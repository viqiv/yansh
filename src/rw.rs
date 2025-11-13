use core::{ffi::CStr, marker::PhantomData, mem};

use alloc::string::String;

use crate::sys::{self, getdents64, open, Dirent64};

#[derive(Debug)]
pub enum IOError {
    Unknown,
    Other(&'static str),
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IOError>;
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IOError>;
}

pub struct Stdout;
pub struct Stdin;

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IOError> {
        let n = unsafe { sys::read(0, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            Err(IOError::Other("Read failure."))
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IOError> {
        let n = unsafe { sys::write(1, buf.as_ptr(), buf.len()) };
        if n < 0 {
            Err(IOError::Other("Write failure."))
        } else {
            Ok(n as usize)
        }
    }
}

impl core::fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe {
            sys::write(1, s.as_bytes().as_ptr(), s.len());
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let mut stdout = $crate::rw::Stdout;
        core::fmt::write(&mut stdout, format_args!($($arg)*)).unwrap();
    }};
}

pub struct ShellReader<T: Read> {
    r: T,
}

impl<T: Read> ShellReader<T> {
    pub fn new(reader: T) -> Self {
        Self { r: reader }
    }

    pub fn read_line(&mut self) -> Result<String, IOError> {
        let mut str = String::new();
        let mut buf = [0u8; 256];
        loop {
            let n = self.r.read(&mut buf)?;
            assert!(buf[n - 1] as char == '\n');
            if n > 1 && buf[n - 2] as char != '\\' {
                str.push_str(core::str::from_utf8(&buf[0..n - 1]).unwrap());
                break;
            }

            if n > 1 {
                str.push_str(core::str::from_utf8(&buf[0..n - 2]).unwrap());
            } else {
                break;
            }
            print!("> ");
        }
        Ok(str)
    }
}

pub fn open_dir(path: &CStr) -> Result<i32, IOError> {
    let fd = unsafe { open(path.as_ptr() as *const u8, 65536, 0) };
    if fd < 0 {
        Err(IOError::Unknown)
    } else {
        Ok(fd)
    }
}

pub struct DirIter<'a> {
    fd: i32,
    offt: usize,
    end_offt: usize,
    buf: [u8; 256],
    _pd: PhantomData<&'a u8>,
}

impl<'a> DirIter<'a> {
    pub fn new(fd: i32) -> DirIter<'a> {
        DirIter {
            fd,
            offt: 0,
            end_offt: 0,
            buf: [0; 256],
            _pd: PhantomData,
        }
    }

    fn read_ents(&mut self) -> Result<usize, IOError> {
        let n = unsafe { getdents64(self.fd as u32, self.buf.as_mut_ptr(), self.buf.len()) };
        if n < 0 {
            Err(IOError::Unknown)
        } else {
            Ok(n as usize)
        }
    }
}

impl<'a> Iterator for DirIter<'a> {
    type Item = Dirent64<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offt == self.end_offt {
            let n = self.read_ents().unwrap();
            if n == 0 {
                return None;
            }
            self.offt = 0;
            self.end_offt = n;
        }
        let ptr = unsafe { self.buf.as_ptr().add(self.offt) } as *const Dirent64;
        let reff = unsafe { ptr.as_ref() }.unwrap();
        self.offt += reff.rec_len() as usize;
        let mut dent = *reff;
        let ptr = ptr as *mut u8;
        dent.set_name(unsafe { ptr.add(2 * mem::size_of::<usize>() + 3) });
        Some(dent)
    }
}

pub struct PathIter<'a> {
    path: &'a str,
}

impl<'a> PathIter<'a> {
    pub fn new(path: &'a str) -> PathIter<'a> {
        PathIter { path }
    }
}

impl<'a> Iterator for PathIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sep) = self.path.find(":") {
            let res = &self.path[0..sep];
            self.path = &self.path[sep + 1..];
            Some(res)
        } else {
            None
        }
    }
}
