use std::fmt::{Debug, Formatter};
use std::slice;

pub type EntrypointFn = fn(*mut i8, u32);

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ldr {
    pub data: *mut u8,
    pub header: *mut FileHeader,
    pub sections: *mut Section,
    pub relocations: *mut Relocation,
    pub symbols: *mut Symbol,
    pub section_map: *mut SectionMap,
    pub function_map: *mut i8,
}

impl Ldr {
    pub fn new(data: *mut u8) -> Ldr {
        Ldr {
            data,
            header: std::ptr::null_mut(),
            sections: std::ptr::null_mut(),
            relocations: std::ptr::null_mut(),
            symbols: std::ptr::null_mut(),
            section_map: std::ptr::null_mut(),
            function_map: std::ptr::null_mut(),
        }
    }

    pub fn with_data(&self, data: *mut u8) -> Ldr {
        Ldr {
            data,
            header: self.header,
            sections: self.sections,
            relocations: self.relocations,
            symbols: self.symbols,
            section_map: self.section_map,
            function_map: self.function_map,
        }
    }
    pub fn with_header(&self, header: *mut FileHeader) -> Ldr {
        Ldr {
            data: self.data,
            header,
            sections: self.sections,
            relocations: self.relocations,
            symbols: self.symbols,
            section_map: self.section_map,
            function_map: self.function_map,
        }
    }
    pub fn with_sections(&self, sections: *mut Section) -> Ldr {
        Ldr {
            data: self.data,
            header: self.header,
            sections,
            relocations: self.relocations,
            symbols: self.symbols,
            section_map: self.section_map,
            function_map: self.function_map,
        }
    }
    pub fn with_relocations(&self, relocations: *mut Relocation) -> Ldr {
        Ldr {
            data: self.data,
            header: self.header,
            sections: self.sections,
            relocations,
            symbols: self.symbols,
            section_map: self.section_map,
            function_map: self.function_map,
        }
    }
    pub fn with_symbols(&self, symbols: *mut Symbol) -> Ldr {
        Ldr {
            data: self.data,
            header: self.header,
            sections: self.sections,
            relocations: self.relocations,
            symbols,
            section_map: self.section_map,
            function_map: self.function_map,
        }
    }
    pub fn with_section_map(&self, section_map: *mut SectionMap) -> Ldr {
        Ldr {
            data: self.data,
            header: self.header,
            sections: self.sections,
            relocations: self.relocations,
            symbols: self.symbols,
            section_map,
            function_map: self.function_map,
        }
    }
    pub fn with_function_map(&self, function_map: *mut i8) -> Ldr {
        Ldr {
            data: self.data,
            header: self.header,
            sections: self.sections,
            relocations: self.relocations,
            symbols: self.symbols,
            section_map: self.section_map,
            function_map,
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct FileHeader {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Section {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

impl Section {
    pub fn as_slice<'module>(&mut self, len: usize) -> &'module mut [Section] {
        unsafe { slice::from_raw_parts_mut(self as *mut Section, len) }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed(2))]
pub struct Relocation {
    pub VirtualAddress: u32,
    pub SymbolTableIndex: u32,
    pub Type: u16,
}

impl Relocation {
    pub fn as_slice<'module>(&mut self, len: usize) -> &'module mut [Relocation] {
        unsafe { slice::from_raw_parts_mut(self as *mut Relocation, len) }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed(2))]
pub struct Symbol {
    pub N: ShortOrLongName,
    pub Value: u32,
    pub SectionNumber: i16,
    pub Type: u16,
    pub StorageClass: u8,
    pub NumberOfAuxSymbols: u8,
}

impl Symbol {
    pub fn as_slice<'module>(&mut self, len: usize) -> &'module mut [Symbol] {
        unsafe { slice::from_raw_parts_mut(self as *mut Symbol, len) }
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed(2))]
pub union ShortOrLongName {
    pub ShortName: [u8; 8],
    pub Name: SymbolName,
    pub LongName: [u32; 2],
}

impl Debug for ShortOrLongName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ShortOrLongName {{ ShortName: {:?}, LongName: {:?} }}",
            unsafe { self.ShortName },
            // unsafe { self.Name },
            unsafe { self.LongName }
        )
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed(2))]
pub union SymbolName {
    pub Short: u32,
    pub Long: u32,
}

impl Debug for SymbolName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SymbolName {{ Short: {:?}, Long: {:?} }}",
            unsafe { self.Short },
            unsafe { self.Long }
        )
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SectionMap {
    pub ptr: *mut i8,
    pub size: usize,
}

impl SectionMap {
    pub fn as_slice<'module>(&mut self, len: usize) -> &'module mut [SectionMap] {
        unsafe { slice::from_raw_parts_mut(self as *mut SectionMap, len) }
    }
}
