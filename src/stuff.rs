use core::ffi::CStr;

use alloc::{string::String, vec::Vec};

use crate::{
    print,
    sys::{strlen, strncmp},
};

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print!("{:?}\n", info);
    unsafe {
        crate::sys::exit(1);
    };
}

pub fn own_string_from_ptr(ptr: *mut u8, len: usize) -> String {
    let mut v = Vec::with_capacity(len);
    v.resize(len, 0);
    unsafe { core::ptr::copy(ptr, v.as_mut_ptr(), len) }
    String::from_utf8(v).unwrap()
}

pub fn cstr_eq_str(c: &CStr, s: &str) -> bool {
    unsafe {
        strlen(c.as_ptr() as *mut u8) == s.len()
            && strncmp(c.as_ptr() as *const u8, s.as_ptr(), s.len()) == 0
    }
}
