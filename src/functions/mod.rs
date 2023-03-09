use printf_compat::{format as formatter, output};
use std::alloc::{alloc, dealloc, Layout};
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::{c_char, c_int, c_short};
use std::{ptr, slice};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOA};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DataP {
    pub original: *mut c_char,
    pub buffer: *mut c_char,
    pub length: c_int,
    pub size: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FormatP {
    pub original: *mut c_char,
    pub buffer: *mut c_char,
    pub length: c_int,
    pub size: c_int,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Carrier {
    pub output: Vec<c_char>,
    pub offset: usize,
}

impl Carrier {
    pub const fn new() -> Carrier {
        Carrier {
            output: Vec::new(),
            offset: 0,
        }
    }

    pub fn append_char_array(&mut self, s: *mut c_char, len: c_int) {
        let holder = unsafe { slice::from_raw_parts(s, len as usize) };

        self.output.extend_from_slice(holder);
        self.offset = self.output.len() - holder.len();
    }

    pub fn append_string(&mut self, s: String) {
        let mut mapped = s.bytes().map(|c| c as i8).collect::<Vec<c_char>>();

        self.output.append(&mut mapped);
        self.offset = self.output.len() - s.len() as usize;
    }

    pub fn flush(&mut self) -> String {
        let mut result = String::new();

        for c in self.output.iter() {
            if (*c as u8) == 0 {
                result.push(0x0a as char);
            } else {
                result.push(*c as u8 as char);
            }
        }

        result
    }

    #[allow(dead_code)]
    pub fn get_from_offset(&self, offset: usize) -> &[c_char] {
        if offset >= self.output.len() {
            return &[];
        }

        let (_, tail) = self.output.split_at(offset);

        return tail;
    }

    #[allow(dead_code)]
    pub fn get_from_current_offset(&self) -> &[c_char] {
        let (_, tail) = self.output.split_at(self.offset);

        return tail;
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        return self.output.len();
    }
}

static mut OUTPUT: Carrier = Carrier::new();

pub fn resolve_internal_functions(name: &str) -> Result<isize, String> {
    match name {
        "BeaconDataParse" => Ok((BeaconDataParse as *const ()) as isize),
        "BeaconDataInt" => Ok((BeaconDataInt as *const ()) as isize),
        "BeaconDataShort" => Ok((BeaconDataShort as *const ()) as isize),
        "BeaconDataLength" => Ok((BeaconDataLength as *const ()) as isize),
        "BeaconDataExtract" => Ok((BeaconDataExtract as *const ()) as isize),
        "BeaconFormatAlloc" => Ok((BeaconFormatAlloc as *const ()) as isize),
        "BeaconFormatReset" => Ok((BeaconFormatReset as *const ()) as isize),
        "BeaconFormatFree" => Ok((BeaconFormatFree as *const ()) as isize),
        "BeaconFormatAppend" => Ok((BeaconFormatAppend as *const ()) as isize),
        "BeaconFormatPrintf" => Ok((BeaconFormatPrintf as *const ()) as isize),
        "BeaconFormatToString" => Ok((BeaconFormatToString as *const ()) as isize),
        "BeaconFormatInt" => Ok((BeaconFormatInt as *const ()) as isize),
        "BeaconPrintf" => Ok((BeaconPrintf as *const ()) as isize),
        "BeaconOutput" => Ok((BeaconOutput as *const ()) as isize),
        "BeaconUseToken" => Ok((BeaconUseToken as *const ()) as isize),
        "BeaconRevertToken" => Ok((BeaconRevertToken as *const ()) as isize),
        "BeaconIsAdmin" => Ok((BeaconIsAdmin as *const ()) as isize),
        "BeaconGetSpawnTo" => Ok((BeaconGetSpawnTo as *const ()) as isize),
        "BeaconSpawnTemporaryProcess" => Ok((BeaconSpawnTemporaryProcess as *const ()) as isize),
        "BeaconInjectProcess" => Ok((BeaconInjectProcess as *const ()) as isize),
        "BeaconInjectTemporaryProcess" => Ok((BeaconInjectTemporaryProcess as *const ()) as isize),
        "BeaconCleanupProcess" => Ok((BeaconCleanupProcess as *const ()) as isize),
        "toWideChar" => Ok((to_wide_char as *const ()) as isize),
        &_ => Err("[!] Couldn't find internal function.".into()),
    }
}

#[no_mangle]
pub extern "C" fn BeaconDataParse(parser: *mut DataP, buffer: *mut c_char, size: c_int) {
    if parser.is_null() {
        return;
    }

    let mut pp: DataP = unsafe { *parser };

    pp.original = buffer;
    pp.buffer = buffer;
    pp.length = size - 4;
    pp.size = size - 4;

    unsafe {
        pp.buffer = pp.buffer.add(4);
    }

    unsafe {
        *parser = pp;
    }

    return;
}

#[no_mangle]
pub extern "C" fn BeaconDataInt(parser: *mut DataP) -> c_int {
    if parser.is_null() {
        return 0;
    }

    let mut pp: DataP = unsafe { *parser };

    if pp.length < 4 {
        return 0;
    }

    let result: &[u8] = unsafe { slice::from_raw_parts(pp.buffer as *const u8, 4) };

    let mut dst = [0u8; 4];
    dst.clone_from_slice(&result[0..4]);

    pp.buffer = unsafe { pp.buffer.add(4) };
    pp.length = pp.length - 4;

    unsafe {
        *parser = pp;
    }

    return i32::from_ne_bytes(dst) as c_int;
}

#[no_mangle]
pub extern "C" fn BeaconDataShort(parser: *mut DataP) -> c_short {
    if parser.is_null() {
        return 0;
    }

    let mut pp: DataP = unsafe { *parser };

    if pp.length < 2 {
        return 0;
    }

    let result: &[u8] = unsafe { slice::from_raw_parts(pp.buffer as *const u8, 4) };

    let mut dst = [0u8; 2];
    dst.clone_from_slice(&result[0..2]);

    pp.buffer = unsafe { pp.buffer.add(2) };
    pp.length = pp.length - 2;

    unsafe {
        *parser = pp;
    }

    return i16::from_ne_bytes(dst);
}

#[no_mangle]
pub extern "C" fn BeaconDataLength(parser: *mut DataP) -> c_int {
    if parser.is_null() {
        return 0;
    }

    let pp: DataP = unsafe { *parser };

    return pp.length;
}

#[no_mangle]
pub extern "C" fn BeaconDataExtract(parser: *mut DataP, size: *mut c_int) -> *mut c_char {
    if parser.is_null() {
        return ptr::null_mut();
    }

    let mut pp: DataP = unsafe { *parser };

    if pp.length < 4 {
        return ptr::null_mut();
    }

    let length_parts: &[u8] = unsafe { slice::from_raw_parts(pp.buffer as *const u8, 4) };

    let mut length_holder = [0u8; 4];
    length_holder.clone_from_slice(&length_parts[0..4]);

    let length: u32 = u32::from_ne_bytes(length_holder);

    pp.buffer = unsafe { pp.buffer.add(4) };

    let result = pp.buffer;

    if result.is_null() {
        return ptr::null_mut();
    }

    pp.length = pp.length - 4;

    pp.length = pp.length - length as i32;

    pp.buffer = unsafe { pp.buffer.add(length as usize) };

    if !size.is_null() && !result.is_null() {
        unsafe {
            *size = length as c_int;
        }
    }

    unsafe {
        *parser = pp;
    }

    return result;
}

#[no_mangle]
pub extern "C" fn BeaconFormatAlloc(format: *mut FormatP, max_size: c_int) {
    if format.is_null() {
        return;
    }

    if max_size == 0 {
        return;
    }

    let mut fp: FormatP = unsafe { *format };

    let mut align: usize = 1;

    while align < max_size as usize {
        align = align * 2;
    }

    let layout = Layout::from_size_align(max_size as usize, align).unwrap();
    let ptr = unsafe { alloc(layout) };

    fp.original = ptr as *mut i8;
    fp.buffer = fp.original;
    fp.length = 0;
    fp.size = max_size;

    unsafe {
        *format = fp;
    }

    return;
}

#[no_mangle]
pub extern "C" fn BeaconFormatReset(format: *mut FormatP) {
    if format.is_null() {
        return;
    }

    let mut fp: FormatP = unsafe { *format };

    let size = fp.size;

    // Free format
    BeaconFormatFree(&mut fp);

    // Alloc format
    BeaconFormatAlloc(&mut fp, size);

    unsafe {
        *format = fp;
    }

    return;
}

#[no_mangle]
pub extern "C" fn BeaconFormatFree(format: *mut FormatP) {
    if format.is_null() {
        return;
    }

    let mut fp: FormatP = unsafe { *format };

    if !fp.original.is_null() {
        let mut align: usize = 1;

        while align < fp.size as usize {
            align = align * 2;
        }

        let layout = Layout::from_size_align(fp.size as usize, align).unwrap();

        unsafe { dealloc(fp.original as *mut u8, layout) };
    }

    fp.original = ptr::null_mut();
    fp.buffer = ptr::null_mut();
    fp.length = 0;
    fp.size = 0;

    unsafe {
        *format = fp;
    }

    return;
}

#[no_mangle]
pub extern "C" fn BeaconFormatAppend(format: *mut FormatP, text: *mut c_char, len: c_int) {
    if format.is_null() {
        return;
    }

    let mut fp: FormatP = unsafe { *format };

    if fp.length + len > fp.size {
        return;
    }

    unsafe {
        ptr::copy_nonoverlapping(text, fp.original, len as usize);
    }

    fp.buffer = unsafe { fp.buffer.add(len as usize) };
    fp.length = fp.length + len;

    unsafe {
        *format = fp;
    }

    return;
}

#[no_mangle]
pub unsafe extern "C" fn BeaconFormatPrintf(format: *mut FormatP, fmt: *mut c_char, mut tail: ...) {
    if format.is_null() {
        return;
    }

    let mut fp: FormatP = *format;

    let mut s = String::new();
    let bytes_written = formatter(fmt, tail.as_va_list(), output::fmt_write(&mut s));

    if fp.length + bytes_written + 1 > fp.size {
        return;
    }

    s.push('\0');

    ptr::copy_nonoverlapping(s.as_ptr(), fp.buffer as *mut u8, s.len());

    fp.length = fp.length + s.len() as i32;

    *format = fp;

    return;
}

#[no_mangle]
pub extern "C" fn BeaconFormatToString(format: *mut FormatP, size: *mut c_int) -> *mut c_char {
    if format.is_null() {
        return ptr::null_mut();
    }

    let fp: FormatP = unsafe { *format };

    if fp.length == 0 {
        return ptr::null_mut();
    }

    unsafe {
        *size = fp.length;
    }

    return fp.original;
}

#[no_mangle]
pub extern "C" fn BeaconFormatInt(format: *mut FormatP, value: c_int) {
    if format.is_null() {
        return;
    }

    let mut fp: FormatP = unsafe { *format };

    if fp.length + 4 > fp.size {
        return;
    }

    let swapped = swap_endianness(value as u32);
    let mut result = swapped.to_be_bytes();

    unsafe {
        ptr::copy_nonoverlapping(result.as_mut_ptr(), fp.original as *mut u8, 4);
    }

    fp.buffer = unsafe { fp.buffer.add(4) };
    fp.length = fp.length + 4;

    unsafe {
        *format = fp;
    }

    return;
}

#[no_mangle]
pub unsafe extern "C" fn BeaconPrintf(_: c_int, fmt: *mut c_char, mut tail: ...) {
    let mut s = String::new();

    formatter(fmt, tail.as_va_list(), output::fmt_write(&mut s));

    s.push('\0');

    OUTPUT.append_string(s);

    return;
}

#[no_mangle]
pub extern "C" fn BeaconOutput(_: c_int, data: *mut c_char, len: c_int) {
    unsafe { OUTPUT.append_char_array(data, len) }
}

#[no_mangle]
fn get_output() -> Carrier {
    return unsafe { OUTPUT.clone() };
}

#[no_mangle]
pub extern "C" fn swap_endianness(src: u32) -> u32 {
    let test: u32 = 0x000000ff;

    // if test is 0xff00, then we are little endian, otherwise big endian
    if (((test >> 24) & 0xff) as u8) == 0xff {
        return src.swap_bytes();
    }

    return src;
}

#[no_mangle]
/// Converts the src string to a UTF16-LE wide-character string, using the target's default encoding.
///
/// # Arguments
///
/// * `src` - The source string to convert.
/// * `dst` - The destination string.
/// * `max` - The size (in bytes!) of the destination buffer
///
/// # Safety
/// This function is unsafe because it dereferences the src pointer.
pub extern "C" fn to_wide_char(src: *mut c_char, dst: *mut u16, max: c_int) -> i32 {
    if src.is_null() {
        return 0;
    }

    let c_str: &CStr = unsafe { CStr::from_ptr(src) };

    let str_slice: &str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut size = str_slice.len();

    if size > max as usize {
        size = max as usize - 1;
    }

    let mut v: Vec<u16> = str_slice
        .encode_utf16()
        .take(size)
        .map(|x| x as u16)
        .collect();
    v.push(0);

    unsafe { ptr::copy(v.as_ptr(), dst, size) };

    return 1;
}

#[no_mangle]
pub extern "C" fn BeaconUseToken(token: HANDLE) -> i32 {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconRevertToken() {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconIsAdmin() -> i32 {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconGetSpawnTo(x86: i32, buffer: *mut c_char, length: c_int) {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconSpawnTemporaryProcess(
    x86: i32,
    ignoreToken: i32,
    sInfo: *mut STARTUPINFOA,
    pInfo: *mut PROCESS_INFORMATION,
) -> i32 {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconInjectProcess(
    hProc: HANDLE,
    pid: c_int,
    payload: *mut c_char,
    p_len: c_int,
    p_offset: c_int,
    arg: *mut c_char,
    a_len: c_int,
) {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconInjectTemporaryProcess(
    pInfo: *mut PROCESS_INFORMATION,
    payload: *mut c_char,
    p_len: c_int,
    p_offset: c_int,
    arg: *mut c_char,
    a_len: c_int,
) {
    todo!()
}

#[no_mangle]
pub extern "C" fn BeaconCleanupProcess(pInfo: *mut PROCESS_INFORMATION) {
    todo!()
}

#[cfg(test)]
mod tests {
    use core::ffi::CStr;
    use std::ffi::CString;
    use std::{ptr, slice};

    use crate::functions::*;
    #[cfg(target_os = "windows")]
    use winapi::{shared::minwindef::DWORD, shared::ntdef::c_char};

    #[cfg(not(target_os = "windows"))]
    use super::super::test_types::{c_char, DWORD};

    unsafe fn reset_output() {
        OUTPUT = Carrier::new();
    }

    #[test]
    fn can_parse_beacon_data() {
        let mut buffer: [c_char; 0xff] = [0i8; 0xff];

        let mut parser = super::DataP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        assert_eq!(parser.length, 0);
        assert_eq!(parser.size, 0);
        assert_eq!(parser.buffer, ptr::null_mut());

        BeaconDataParse(&mut parser, buffer.as_mut_ptr(), 0xff);

        assert_ne!(parser.original, ptr::null_mut());
        assert_ne!(parser.buffer, ptr::null_mut());
        assert_eq!(parser.length, 0xff - 4);
        assert_eq!(parser.size, 0xff - 4);

        unsafe {
            assert_eq!(parser.buffer, buffer.as_mut_ptr().add(4));
        }
    }

    #[test]
    fn can_extract_int_from_parser() {
        let mut buffer: [c_char; 0xff] = [0i8; 0xff];

        buffer[4] = 0x1;
        buffer[5] = 0x4;

        let mut parser = super::DataP {
            original: buffer.as_mut_ptr(),
            buffer: buffer.as_mut_ptr(),
            length: 0,
            size: 0,
        };

        BeaconDataParse(&mut parser, buffer.as_mut_ptr(), 0xff);

        let result = BeaconDataInt(&mut parser);

        assert_eq!(1025, result);
    }

    #[test]
    fn can_extract_short_from_parser() {
        let mut buffer: [c_char; 0xff] = [0i8; 0xff];

        buffer[4] = 0x1;
        buffer[5] = 0x4;

        let mut parser = super::DataP {
            original: buffer.as_mut_ptr(),
            buffer: buffer.as_mut_ptr(),
            length: 0,
            size: 0,
        };

        BeaconDataParse(&mut parser, buffer.as_mut_ptr(), 0xff);

        let result = BeaconDataShort(&mut parser);

        assert_eq!(1025, result);
    }

    #[test]
    fn can_extract_data_from_parser() {
        let mut buffer: [c_char; 0xff] = [0i8; 0xff];

        // set our data size
        buffer[4] = 0x5;

        // set our data
        buffer[8] = 104;
        buffer[9] = 101;
        buffer[10] = 108;
        buffer[11] = 108;
        buffer[12] = 111;

        let mut parser = super::DataP {
            original: buffer.as_mut_ptr(),
            buffer: buffer.as_mut_ptr(),
            length: 0,
            size: 0,
        };

        BeaconDataParse(&mut parser, buffer.as_mut_ptr(), 0xff);

        let mut size = 0;

        let result = BeaconDataExtract(&mut parser, &mut size);

        let string: &[u8] = unsafe { slice::from_raw_parts(result as *const u8, size as usize) };

        let result_string = String::from_utf8_lossy(string);

        assert_eq!("hello", result_string);
        assert_eq!(5, size);
    }

    #[test]
    fn can_return_data_length() {
        let mut buffer: [c_char; 0xff] = [0i8; 0xff];
        let expected_length = 0xff - 4;

        let mut parser = super::DataP {
            original: buffer.as_mut_ptr(),
            buffer: buffer.as_mut_ptr(),
            length: 0,
            size: 0,
        };

        BeaconDataParse(&mut parser, buffer.as_mut_ptr(), 0xff);

        let length = BeaconDataLength(&mut parser);

        assert_eq!(length, expected_length);
    }

    #[test]
    fn can_allocate_format_p() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);
    }

    #[test]
    fn can_reset_format_p() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);

        BeaconFormatReset(&mut format);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);
    }

    #[test]
    fn can_deallocate_format_p() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);

        BeaconFormatFree(&mut format);

        assert_eq!(format.original, ptr::null_mut());
        assert_eq!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0);
    }

    #[test]
    fn can_append_text_to_format_p() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);

        let mut buffer: [c_char; 5] = [104, 101, 108, 108, 111];

        BeaconFormatAppend(&mut format, buffer.as_mut_ptr(), 5);

        assert_eq!(format.length, 5);

        let string: &[u8] =
            unsafe { slice::from_raw_parts(format.original as *const u8, format.length as usize) };

        let result_string = String::from_utf8_lossy(string);
        assert_eq!("hello", result_string);
    }

    #[test]
    fn can_printf_to_format_p() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);

        let fmt = CString::new("%.*f %.3s").unwrap();
        let fmt_slice = fmt.to_bytes_with_nul();

        unsafe {
            BeaconFormatPrintf(
                &mut format,
                fmt_slice.as_ptr() as *mut c_char,
                2,
                0.3333,
                "foobar",
            )
        };

        assert_eq!(format.length, 9);

        let string: &[c_char] =
            unsafe { slice::from_raw_parts(format.original, format.length as usize) };

        let result_string = unsafe { CStr::from_ptr(string.as_ptr()) };

        assert_eq!("0.33 foo", result_string.to_str().unwrap());
    }

    #[test]
    fn can_turn_format_p_into_string() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);

        let mut buffer: [c_char; 5] = [104, 101, 108, 108, 111];

        BeaconFormatAppend(&mut format, buffer.as_mut_ptr(), 5);

        assert_eq!(format.length, 5);

        let mut length = 0;

        let string_parts = BeaconFormatToString(&mut format, &mut length);

        let string: &[u8] =
            unsafe { slice::from_raw_parts(string_parts as *const u8, length as usize) };

        let result_string = String::from_utf8_lossy(string);

        assert_eq!("hello", result_string);
    }

    #[test]
    fn can_append_int_to_format_p() {
        let mut format = super::FormatP {
            original: ptr::null_mut(),
            buffer: ptr::null_mut(),
            length: 0,
            size: 0,
        };

        BeaconFormatAlloc(&mut format, 0xff);

        assert_ne!(format.original, ptr::null_mut());
        assert_ne!(format.buffer, ptr::null_mut());
        assert_eq!(format.length, 0);
        assert_eq!(format.size, 0xff);

        BeaconFormatInt(&mut format, 5);

        assert_eq!(format.length, 4);

        let result: &[u8] =
            unsafe { slice::from_raw_parts(format.original as *const u8, format.length as usize) };

        assert_eq!(result, &[0, 0, 0, 5]);
    }

    #[test]
    fn can_printf_to_beacon() {
        let fmt = CString::new("%.*f %.3s").unwrap();
        let fmt_slice = fmt.to_bytes_with_nul();

        unsafe { BeaconPrintf(0, fmt_slice.as_ptr() as *mut c_char, 2, 0.3333, "foobar") };

        let result = unsafe { OUTPUT.get_from_current_offset() };

        let result_string = unsafe { CStr::from_ptr(result.as_ptr()) };

        assert_eq!(unsafe { OUTPUT.len() }, 9);
        assert_eq!(&[48, 46, 51, 51, 32, 102, 111, 111, 0], result);
        assert_eq!("0.33 foo", result_string.to_str().unwrap());

        unsafe { reset_output() };
    }

    #[test]
    fn can_append_beacon_output() {
        let mut buffer: [c_char; 6] = [104, 101, 108, 108, 111, 0];

        BeaconOutput(0, buffer.as_mut_ptr(), 6);

        let result = unsafe { OUTPUT.get_from_current_offset() };

        let result_string = unsafe { CStr::from_ptr(result.as_ptr()) };

        assert_eq!(unsafe { OUTPUT.len() }, 6);
        assert_eq!(&[104, 101, 108, 108, 111, 0], result);
        assert_eq!("hello", result_string.to_str().unwrap());

        unsafe { reset_output() };
    }

    #[test]
    fn can_return_beacon_output() {
        let mut buffer: [c_char; 6] = [104, 101, 108, 108, 111, 0];
        BeaconOutput(0, buffer.as_mut_ptr(), 6);

        let fmt = CString::new("%.*f %.3s").unwrap();
        let fmt_slice = fmt.to_bytes_with_nul();

        unsafe { BeaconPrintf(0, fmt_slice.as_ptr() as *mut c_char, 2, 0.3333, "foobar") };

        let mut data = get_output();

        assert_eq!("hello\n0.33 foo\n", data.flush());
        assert_eq!(15, data.len());
    }

    #[test]
    fn can_swap_endianness() {
        let src = 1025_u32.to_le();

        // This test won't work on big endian machines.
        // So I'll just test the code that actually matters.
        assert_eq!(17039360, src.swap_bytes());
    }

    #[test]
    fn can_convert_string_to_wide_string() {
        let before = CString::new("hello world! ハローワールド！　?!").unwrap();

        let c_ptr: *mut c_char = before.into_raw();

        let mut buffer = [0; 0xff];
        let buffer_length: DWORD = buffer.len() as DWORD;

        let success = crate::beacon::to_wide_char(c_ptr, buffer.as_mut_ptr(), buffer_length as i32);

        let buffer_slice: [u16; 0xff] = buffer.map(|b| b as u16);
        let len = buffer.iter().take_while(|&&c| c != 0).count();

        let result = String::from_utf16_lossy(&buffer_slice[..len]);

        assert_eq!("hello world! ハローワールド！　?!", format!("{}", result));
        assert_eq!(success, 1);
    }

    #[test]
    fn can_limit_characters_when_converting() {
        let before = CString::new("hello world! ハローワールド！　?!").unwrap();

        let c_ptr: *mut c_char = before.into_raw();

        let mut buffer = [0; 0xff];

        let success = crate::beacon::to_wide_char(c_ptr, buffer.as_mut_ptr(), 5 as i32);

        let buffer_slice: [u16; 0xff] = buffer.map(|b| b as u16);
        let len = buffer.iter().take_while(|&&c| c != 0).count();

        let result = String::from_utf16_lossy(&buffer_slice[..len]);

        assert_eq!("hell", format!("{}", result));
        assert_eq!(success, 1);
    }
}
