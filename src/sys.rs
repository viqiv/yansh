use core::ffi::{c_int, c_void, CStr};
use core::{mem, ptr};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dirent64<'a> {
    ino: usize,     /* 64-bit inode number */
    off: usize,     /* Not an offset; see getdents() */
    reclen: u16,    /* Size of this dirent */
    kind: u8,       /* File type */
    name: &'a CStr, /* Filename (null-terminated) */
}

impl<'a> Dirent64<'a> {
    pub fn ino(&self) -> usize {
        self.ino
    }

    pub fn off(&self) -> usize {
        self.off
    }

    pub fn rec_len(&self) -> u16 {
        self.reclen
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn get_name(&self) -> &CStr {
        self.name
    }

    pub fn set_name(&mut self, ptr: *const u8) {
        self.name = unsafe { CStr::from_ptr(ptr as *const i8) };
    }
}

extern "C" {
    pub fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    pub fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    pub fn exit(status: i32) -> !;
    pub fn fork() -> c_int;
    pub fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> c_int;
    pub fn waitid(idtype: c_int, id: c_int, infop: *const c_void, options: c_int) -> c_int;
    pub fn dup2(oldfd: i32, newfd: i32) -> i32;
    pub fn open(path: *const u8, flags: i32, mode: i32) -> i32;
    pub fn close(fd: i32) -> i32;
    pub fn pipe(fds: *mut i32) -> i32;
    pub fn chdir(path: *const u8) -> i32;
    pub fn strncmp(a: *const u8, b: *const u8, c: usize) -> i32;
    pub fn strlen(a: *const u8) -> usize;
    pub fn getdents64(fd: u32, buf: *mut u8, n: usize) -> isize;
}
