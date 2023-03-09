use crate::functions::resolve_internal_functions;
use crate::parser::types::{
    EntrypointFn, FileHeader, Ldr, Relocation, Section, SectionMap, Symbol,
};
use std::alloc::{alloc_zeroed, Layout};
use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::mem::size_of;
use std::ops::Index;
use std::{ptr, slice};
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    LocalFree, VirtualFree, VirtualProtect, MEM_RELEASE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    IMAGE_REL_AMD64_ADDR32NB, IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_REL32,
    IMAGE_REL_AMD64_REL32_5,
};

mod types;

pub fn parse(bytes: &mut [u8]) -> Result<(), String> {
    let mut ldr = Ldr::new(bytes.as_mut_ptr());

    println!("{:?}", ldr);

    println!("[+] PARSE: Loading FileHeader");
    ldr = load_file_header(ldr)?;

    println!("[+] PARSE: Initializing section map");
    ldr = initialize_section_map(ldr)?;

    println!("[+] PARSE: Initializing function map");
    ldr = initialize_function_map(ldr)?;

    println!("[+] PARSE: Loading sections");
    let sections: &mut [Section] = unsafe {
        slice::from_raw_parts_mut(
            ldr.data.offset(
                (*ldr.header).SizeOfOptionalHeader as isize + size_of::<FileHeader>() as isize,
            ) as *mut _ as *mut Section,
            (*ldr.header).NumberOfSections as usize,
        )
    };

    ldr = ldr.with_sections(sections.as_mut_ptr());

    println!("[+] PARSE: Mapping sections to section map");
    for (i, section) in sections.iter().enumerate() {
        map_sections_to_section_map(&mut ldr, i, section);
    }

    println!("[+] PARSE: Loading symbols");
    let symbols_offset = unsafe { ldr.data.offset((*ldr.header).PointerToSymbolTable as isize) };

    let symbols: &mut [Symbol] = unsafe {
        slice::from_raw_parts_mut(
            symbols_offset as *mut _ as *mut Symbol,
            (*ldr.header).NumberOfSymbols as usize,
        )
    };

    ldr = ldr.with_symbols(symbols.as_mut_ptr());

    println!("[+] PARSE: Building symbol name lookup table");
    let symbol_name_lt = build_symbol_name_lookup_table(symbols_offset, unsafe {
        (*ldr.header).NumberOfSymbols as isize
    });

    process_sections(&ldr, symbol_name_lt)?;

    println!("[+] Processed sections!");

    let mut entrypoint_ptr: *mut c_void = ptr::null_mut();

    let mut section_map =
        unsafe { (*ldr.section_map).as_slice((*ldr.header).NumberOfSections as usize) };

    for symbol in symbols.iter() {
        if unsafe { symbol.N.ShortName } == [103, 111, 0, 0, 0, 0, 0, 0] {
            entrypoint_ptr = unsafe {
                section_map[symbol.SectionNumber as usize - 1]
                    .ptr
                    .add(symbol.Value as usize)
            } as *mut c_void;
        }
    }

    if entrypoint_ptr.is_null() {
        println!("[!] Couldn't find the `go` address !");

        return Err("[!] Couldn't find the `go` address !".into());
    }

    println!("[+] Found entrypoint!");

    let mut old = PAGE_READWRITE;

    let hr = unsafe {
        VirtualProtect(
            section_map[0].ptr as *const c_void,
            section_map[0].size,
            PAGE_EXECUTE_READ,
            &mut old,
        )
    };

    if hr.0 == 0 {
        println!("[!] Couldn't mark `.text` section as executable!");
    }

    // EntrypointFn
    let entrypoint_fn: EntrypointFn = unsafe { std::mem::transmute(entrypoint_ptr) };

    println!("[+] Calling entrypoint!");

    entrypoint_fn(ptr::null_mut(), 0);

    println!("[+] Done");

    for (i, section) in section_map.iter_mut().enumerate() {
        if !section.ptr.is_null() {
            let hr = unsafe {
                VirtualProtect(
                    section.ptr as *const c_void,
                    section.size,
                    PAGE_READWRITE,
                    &mut old,
                )
            };

            if hr.0 == 0 {
                println!("[!] Couldn't change protection to RW for Section `{}`", i);
            }

            unsafe {
                section.ptr.write_bytes(0u8, section.size);
            }

            let hr = unsafe { VirtualFree(section.ptr as *mut c_void, 0, MEM_RELEASE) };

            if hr.0 == 0 {
                println!(
                    "[!] Failed to free memory for Section `{}` at ptr `{:p}`",
                    i, section.ptr
                );
            }

            section.ptr = ptr::null_mut();
        }
    }

    if !ldr.section_map.is_null() {
        unsafe {
            ldr.section_map.write_bytes(
                0u8,
                (*ldr.header).NumberOfSections as usize * size_of::<SectionMap>(),
            );
        }

        unsafe {
            LocalFree(ldr.section_map as isize);
        }

        ldr.section_map = ptr::null_mut();
    }

    if !ldr.function_map.is_null() {
        unsafe {
            ldr.function_map.write_bytes(0u8, 2048);
        }

        let hr = unsafe { VirtualFree(ldr.function_map as *mut c_void, 0, MEM_RELEASE) };

        if hr.0 == 0 {
            println!("[!] Failed to free memory for function_map");
        }

        ldr.function_map = ptr::null_mut()
    }

    Ok(())
}

pub fn process_sections(ldr: &Ldr, symbol_name_lt: HashMap<u32, String>) -> Result<(), String> {
    let sections = unsafe { (*ldr.sections).as_slice((*ldr.header).NumberOfSections as usize) };
    let section_map =
        unsafe { (*ldr.section_map).as_slice((*ldr.header).NumberOfSections as usize) };
    let symbols = unsafe { (*ldr.symbols).as_slice((*ldr.header).NumberOfSymbols as usize) };
    let mut relocations_ptr: *mut Relocation = ptr::null_mut();

    let mut offset: u32 = 0;
    let mut offset_long: u64 = 0;
    let mut function_count: usize = 0;

    for (i, section) in sections.iter().enumerate() {
        println!(
            "=> Processing section: `{}`",
            std::str::from_utf8(&section.Name).unwrap().trim()
        );

        relocations_ptr = unsafe {
            ldr.data.offset(section.PointerToRelocations as isize) as *mut _ as *mut Relocation
        };

        let relocations =
            unsafe { (*relocations_ptr).as_slice(section.NumberOfRelocations as usize) };

        for relocation in relocations.iter() {
            if relocation.SymbolTableIndex > symbols.len() as u32 {
                println!("[*] Failed relocation: {:?}", relocation);
                return Err("Cannot continue with relocations".into());
            }

            let symbol: Symbol = symbols[relocation.SymbolTableIndex as usize];

            if unsafe { symbol.N.ShortName[0] } != 0 {
                let value = unsafe { symbol.N.ShortName };
                let name = CStr::from_bytes_with_nul(&value).unwrap_or_default();

                match relocation.Type as u32 {
                    IMAGE_REL_AMD64_ADDR64 => {
                        // Copy the virtual address for the relocation to offset_long.
                        // The actual address is the section pointer we cached in SectionMap plus the virtual address.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                section_map[i].ptr.add(relocation.VirtualAddress as usize)
                                    as *mut u64,
                                &mut offset_long as *mut u64,
                                size_of::<u64>(),
                            )
                        }

                        // Calculate the actual offset needed for relocation.
                        offset_long = unsafe {
                            section_map[(symbol.SectionNumber - 1) as usize]
                                .ptr
                                .add(offset_long as usize) as u64
                        };

                        // Copy the new offset we calculated into the virtual address for the relocation.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                &mut offset_long as *mut u64,
                                section_map[i].ptr.add(relocation.VirtualAddress as usize)
                                    as *mut u64,
                                size_of::<u64>(),
                            )
                        }
                    }
                    IMAGE_REL_AMD64_ADDR32NB => {
                        // Copy the virtual address for the relocation to offset.
                        // The actual address is the section pointer we cached in SectionMap plus the virtual address.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                section_map[i].ptr.add(relocation.VirtualAddress as usize)
                                    as *mut u32,
                                &mut offset as *mut u32,
                                size_of::<u32>(),
                            )
                        }

                        // Calculate the actual offset needed for relocation.
                        let needed_offset: u32 = unsafe {
                            section_map[(symbol.SectionNumber - 1) as usize]
                                .ptr
                                .add(offset as usize)
                                .sub(
                                    section_map[i]
                                        .ptr
                                        .add(relocation.VirtualAddress as usize)
                                        .add(4) as usize,
                                ) as u32
                        };

                        if needed_offset > u32::MAX {
                            println!("[*] Failed relocation: {:?}", relocation);
                            return Err("[!] The relocation is out of bounds, something probably went wrong...".into());
                        }

                        offset = needed_offset;

                        // Copy the new offset we calculated into the virtual address for the relocation.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                &mut offset as *mut u32,
                                section_map[i].ptr.add(relocation.VirtualAddress as usize)
                                    as *mut u32,
                                size_of::<u32>(),
                            )
                        }
                    }
                    IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                        unsafe {
                            ptr::copy_nonoverlapping(
                                section_map[i].ptr.add(relocation.VirtualAddress as usize)
                                    as *mut u32,
                                &mut offset as *mut u32,
                                size_of::<u32>(),
                            )
                        }

                        // Check for overflows
                        unsafe {
                            if section_map[(symbol.SectionNumber - 1) as usize].ptr.sub(
                                section_map[i]
                                    .ptr
                                    .add(relocation.VirtualAddress as usize)
                                    .add(4) as usize,
                            ) as u32
                                > u32::MAX
                            {
                                return Err("[!] The relocation is out of bounds, something probably went wrong...".into());
                            }
                        }

                        // Calculate the actual offset needed for relocation.
                        offset = unsafe {
                            section_map[(symbol.SectionNumber - 1) as usize]
                                .ptr
                                .sub(relocation.Type as usize - 4)
                                .sub(
                                    section_map[i]
                                        .ptr
                                        .add(relocation.VirtualAddress as usize)
                                        .add(4) as usize,
                                ) as u32
                        };

                        // Copy the new offset we calculated into the virtual address for the relocation.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                &mut offset as *mut u32,
                                section_map[i].ptr.add(relocation.VirtualAddress as usize)
                                    as *mut u32,
                                size_of::<u32>(),
                            )
                        }
                    }
                    _ => {
                        println!("[!] Relocation type not found: {}", relocation.Type)
                    }
                }
            } else {
                let value = unsafe { symbol.N.LongName[1] };
                let unknown = "<unknown>".to_string();
                let mut symbol_name: &str = symbol_name_lt.get(&value).unwrap_or(&unknown);

                if symbol_name == &unknown {
                    println!("[*] Failed symbol: {:?}", symbol);
                    println!("[*] Failed relocation: {:?}", relocation);
                    return Err("[!] Unable to resolve symbol".into());
                }

                let func_ptr = get_external_function_ptr(symbol_name)?;

                if relocation.Type as u32 == IMAGE_REL_AMD64_REL32 && func_ptr != 0 {
                    let needed_offset = unsafe {
                        ldr.function_map.add(function_count * size_of::<u64>()).sub(
                            section_map[i]
                                .ptr
                                .add(relocation.VirtualAddress as usize)
                                .add(4) as usize,
                        ) as u32
                    };

                    if needed_offset > u32::MAX {
                        println!("[*] Failed relocation: {:?}", relocation);
                        return Err(
                            "[!] The relocation is out of bounds, something probably went wrong..."
                                .into(),
                        );
                    }

                    unsafe {
                        ptr::copy_nonoverlapping(
                            &func_ptr,
                            ldr.function_map.add(function_count * size_of::<u64>()) as *mut isize,
                            size_of::<u64>(),
                        )
                    }

                    offset = needed_offset;

                    unsafe {
                        ptr::copy_nonoverlapping(
                            &mut offset as *mut u32,
                            section_map[i].ptr.add(relocation.VirtualAddress as usize) as *mut u32,
                            size_of::<u32>(),
                        )
                    }

                    function_count = function_count + 1;
                } else if relocation.Type as u32 == IMAGE_REL_AMD64_REL32 {
                    unsafe {
                        ptr::copy_nonoverlapping(
                            section_map[i].ptr.add(relocation.VirtualAddress as usize) as *mut u32,
                            &mut offset as *mut u32,
                            size_of::<u32>(),
                        )
                    }

                    let needed_offset = unsafe {
                        section_map[(symbol.SectionNumber - 1) as usize].ptr.sub(
                            section_map[i]
                                .ptr
                                .add(relocation.VirtualAddress as usize)
                                .add(4) as usize,
                        ) as u32
                    };

                    if needed_offset > u32::MAX {
                        println!("[*] Failed relocation: {:?}", relocation);
                        return Err(
                            "[!] The relocation is out of bounds, something probably went wrong..."
                                .into(),
                        );
                    }

                    offset = offset + needed_offset;

                    unsafe {
                        ptr::copy_nonoverlapping(
                            &mut offset as *mut u32,
                            section_map[i].ptr.add(relocation.VirtualAddress as usize) as *mut u32,
                            size_of::<u32>(),
                        )
                    }
                } else {
                    println!("[*] Failed relocation: {:?}", relocation);
                    println!("[!] Relocation type not found: {}", relocation.Type)
                }
            }
        }
    }

    Ok(())
}

pub fn load_file_header(ldr: Ldr) -> Result<Ldr, String> {
    let mut file_header_slice: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(ldr.data, size_of::<FileHeader>()) };

    let mut file_header_ptr = file_header_slice as *mut _ as *mut FileHeader;

    if file_header_ptr.is_null() {
        return Err("Unable to load file header".into());
    }

    Ok(ldr.with_header(file_header_ptr))
}

pub fn initialize_section_map(ldr: Ldr) -> Result<Ldr, String> {
    let section_map_size =
        unsafe { size_of::<Section>() * (*ldr.header).NumberOfSections as usize };

    let mut section_map_vec =
        Vec::<SectionMap>::with_capacity(section_map_size / size_of::<SectionMap>());

    let section_map_ptr = section_map_vec.as_mut_ptr();

    std::mem::forget(section_map_vec);

    Ok(ldr.with_section_map(section_map_ptr))
}

pub fn initialize_function_map(ldr: Ldr) -> Result<Ldr, String> {
    let layout = Layout::from_size_align(2048, std::mem::align_of::<i8>()).unwrap();
    let ptr = unsafe { alloc_zeroed(layout) };

    let mut function_map_vec =
        unsafe { Vec::from_raw_parts(ptr as *mut i8, layout.size(), layout.size()) };

    let function_map_ptr = function_map_vec.as_mut_ptr();

    std::mem::forget(function_map_vec);

    Ok(ldr.with_function_map(function_map_ptr))
}

pub fn map_sections_to_section_map(ldr: &mut Ldr, index: usize, section: &Section) {
    println!(
        "           => Working on section: `{}`",
        std::str::from_utf8(&section.Name).unwrap().trim()
    );

    unsafe { (*ldr.section_map.offset(index as isize)).size = section.SizeOfRawData as usize }

    let mut vec =
        Vec::<u8>::with_capacity(unsafe { (*ldr.section_map.offset(index as isize)).size });
    let ptr = vec.as_mut_ptr() as *mut i8;

    unsafe { (*ldr.section_map.offset(index as isize)).ptr = ptr };
    std::mem::forget(vec);

    let src = ldr.data as *const u8;
    let dest = unsafe { (*ldr.section_map.offset(index as isize)).ptr as *mut u8 };

    unsafe {
        ptr::copy_nonoverlapping(
            src.offset(section.PointerToRawData as isize),
            dest,
            section.SizeOfRawData as usize,
        );
    }
}

pub fn build_symbol_name_lookup_table(
    symbols_offset: *mut u8,
    num_of_symbols: isize,
) -> HashMap<u32, String> {
    let offset = unsafe { symbols_offset.offset(size_of::<Symbol>() as isize * num_of_symbols) };

    let length: u32 = unsafe {
        let length_ptr = slice::from_raw_parts(offset as *const u8, size_of::<u32>());

        *(length_ptr.as_ptr() as *const u32)
    };

    let string_table_slice: &[u8] =
        unsafe { slice::from_raw_parts(offset.offset(4) as *const u8, length as usize - 4) };

    let mut string_table: HashMap<u32, String> = HashMap::new();
    let mut buffer: Vec<u8> = vec![];

    for (off, s) in string_table_slice.iter().enumerate() {
        if *s == 0 {
            string_table.insert(
                (off - buffer.len() + 4) as u32,
                String::from_utf8(buffer).unwrap_or("<unknown>".to_string()),
            );
            buffer = vec![];
            continue;
        }

        buffer.push(*s);
    }

    return string_table;
}

pub fn get_external_function_ptr(symbol: &str) -> Result<isize, String> {
    let symbol_prefix = "__imp_";
    let beacon_prefix = "__imp_Beacon";
    let wide_char_prefix = "__imp_toWideChar";

    if symbol == "<unknown>" || symbol.len() < 6 || !symbol.starts_with(symbol_prefix) {
        println!("[!] Function with unknown naming convention! [{}]", symbol);

        return Err(format!(
            "[!] Function with unknown naming convention! [{}]",
            symbol
        ));
    }

    let mut symbol_name = symbol.to_string();

    let _ = symbol_name.drain(0..6);

    if symbol.starts_with(beacon_prefix) || symbol.starts_with(wide_char_prefix) {
        let func_ptr = resolve_internal_functions(&symbol_name)?;
        return Ok(func_ptr);
    }

    let library_function: Vec<_> = symbol_name
        .split(&['$', '@'][..])
        .map(|s| format!("{}\0", s))
        .collect();

    if library_function.len() != 2 {
        println!("[!] Function with unknown naming convention! [{}]", symbol);
        return Err(format!(
            "[!] Function with unknown naming convention! [{}]",
            symbol
        ));
    }

    let mut library_name = library_function.get(0).unwrap().as_bytes();
    let mut function_name = library_function.get(1).unwrap().as_bytes();

    let library_handle =
        unsafe { LoadLibraryA(PCSTR::from_raw(library_name.as_ptr())).unwrap_or_default() };

    if library_handle.is_invalid() {
        println!(
            "[!] Error loading library: [{}]",
            std::str::from_utf8(library_name).unwrap_or_default()
        );

        return Err(format!(
            "[!] Error loading library: [{}]",
            std::str::from_utf8(library_name).unwrap_or_default()
        ));
    }

    return match unsafe { GetProcAddress(library_handle, PCSTR::from_raw(function_name.as_ptr())) }
    {
        None => {
            println!(
                "[!] Error loading function: [{}]",
                std::str::from_utf8(function_name).unwrap_or_default()
            );

            Err(format!(
                "[!] Error loading function: [{}]",
                std::str::from_utf8(function_name).unwrap_or_default()
            ))
        }
        Some(f) => Ok(f as isize),
    };
}
