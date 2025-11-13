#![no_std]
#![no_main]

extern crate alloc;

use alloc::{collections::BTreeMap, format, string::String};
use core::{mem::forget, str};
use rw::ShellReader;
use sys::strlen;

mod tok {
    use core::{iter::Peekable, str::Bytes};

    use crate::{
        print,
        rw::{open_dir, DirIter, PathIter},
        stuff::cstr_eq_str,
        Env,
    };
    use alloc::{ffi::CString, string::String, vec::Vec};

    #[derive(Debug, PartialEq, Clone, Copy)]
    pub enum TokenKind {
        Ident,
        Redirect,
        RedirectAppend,
        RedirectFrom,
        SemiColon,
        Equals,
        Pipe,
        Eof,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Slice {
        len: usize,
        ptr: *const u8,
    }

    pub enum TokErr {
        Unexpected,
    }

    impl Slice {
        pub fn new(string: &str) -> Slice {
            let cs = CString::new(string).unwrap().into_raw();
            Slice {
                len: string.len(),
                ptr: cs as *mut u8,
            }
        }

        pub fn ptr(&self) -> *const u8 {
            self.ptr
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn replace(&mut self, other: String) {
            let d = *self;
            d.drop();

            self.len = other.len();
            let cs = CString::new(other).unwrap().into_raw();
            self.ptr = cs as *mut u8;
        }

        pub fn drop(&self) {
            if self.ptr as usize > 9 {
                let _ = unsafe { CString::from_raw(self.ptr as *mut i8) };
            }
        }
    }

    #[derive(Debug)]
    pub struct Token {
        pub kind: TokenKind,
        pub slice: Option<Slice>,
    }

    impl Drop for Token {
        fn drop(&mut self) {
            if let Some(s) = self.slice {
                s.drop()
            }
        }
    }

    impl Token {
        pub fn new(kind: TokenKind, slice: Option<&str>) -> Token {
            let mut t = Token {
                kind,
                slice: if let Some(s) = slice {
                    Some(Slice::new(s))
                } else {
                    None
                },
            };
            match kind {
                TokenKind::Redirect | TokenKind::RedirectAppend => {
                    t.slice = Some(Slice {
                        len: 0,
                        ptr: usize::from_str_radix(slice.unwrap_or("1"), 10).unwrap() as *const u8,
                    })
                }
                _ => {}
            }
            t
        }

        pub fn slice_mut(&mut self) -> Option<&mut Slice> {
            if self.slice.is_some() {
                self.slice.as_mut()
            } else {
                None
            }
        }
    }

    fn is_ident(c: char) -> bool {
        c.is_alphanumeric() || c == '/' || c == '.' || c == '_' || c == '-'
    }

    fn is_space(c: char) -> bool {
        c == ' ' || c == '\n' || c == '\t'
    }

    fn ident(bytes: &mut Peekable<Bytes>) -> usize {
        let mut len = 0;
        while let Some(p) = bytes.peek() {
            let c = *p as char;
            if !is_ident(c) {
                break;
            }
            len += 1;
            bytes.next();
        }
        len
    }

    fn ident_alnum(bytes: &mut Peekable<Bytes>) -> usize {
        let mut len = 0;
        while let Some(p) = bytes.peek() {
            let c = *p as char;
            if !(c.is_alphanumeric() || c == '?') {
                break;
            }
            len += 1;
            bytes.next();
        }
        len
    }

    fn ident_alnum2(bytes: &mut Peekable<Bytes>) -> usize {
        let mut len = 0;
        while let Some(p) = bytes.peek() {
            let c = *p as char;
            if !(c.is_alphanumeric() || c == '?' || c == '$') {
                break;
            }
            len += 1;
            bytes.next();
        }
        len
    }

    fn s_quote(bytes: &mut Peekable<Bytes>) -> usize {
        let mut len = 0;
        while let Some(b) = bytes.peek() {
            if *b as char == '\'' {
                break;
            }
            bytes.next();
            len += 1;
        }
        len
    }

    fn d_quote(bytes: &mut Peekable<Bytes>) -> usize {
        let mut len = 0;
        while let Some(b) = bytes.peek() {
            if *b as char == '\"' {
                break;
            }
            bytes.next();
            len += 1;
        }
        len
    }

    pub fn expand_from_path(ident: &str, path: &str) -> Option<String> {
        let path_it = PathIter::new(path);
        for path in path_it {
            let cs = if let Ok(c) = CString::new(path) {
                c
            } else {
                continue;
            };
            let fd = if let Ok(f) = open_dir(&cs) {
                f
            } else {
                continue;
            };

            let dir_it = DirIter::new(fd);

            for file in dir_it {
                if cstr_eq_str(file.get_name(), ident) {
                    let mut s = String::new();
                    s.push_str(path);
                    if !path.ends_with('/') {
                        s.push('/');
                    }
                    s.push_str(ident);
                    return Some(s);
                }
            }
        }
        None
    }

    fn expand_ident(ident: &str, env: &Env) -> String {
        let mut s = String::new();
        let mut bytes = ident.bytes().peekable();
        let mut i = 0;
        while let Some(p) = bytes.peek() {
            let c = *p as char;
            if c == '$' {
                bytes.next();
                i += 1;
                let begin = i;
                let klen = ident_alnum(&mut bytes);
                if klen == 0 {
                    s.push_str("$");
                } else {
                    let key = &ident[begin..][0..klen];
                    let value = env.get_var(key.as_ptr(), key.len());
                    s.push_str(value);
                    i += klen;
                }
            } else {
                s.push(c);
                bytes.next();
                i += 1;
            }
        }
        s
    }

    pub fn tokenize<'a>(input: &'a str, env: &Env) -> Result<Vec<Token>, TokErr> {
        let mut tokens = Vec::new();
        let mut bytes = input.bytes().peekable();
        let mut i = 0usize;
        let input_len = bytes.len();
        assert!(input_len == input.len());

        while i < input_len {
            let c = bytes.next().unwrap() as char;
            if c.is_digit(10) {
                match bytes.peek() {
                    Some(b'>') => {
                        if let Some(p) = bytes.peek() {
                            if *p as char == '>' {
                                tokens.push(Token::new(
                                    TokenKind::RedirectAppend,
                                    Some(&input[i..i + 1]),
                                ));
                                bytes.next();
                                bytes.next();
                                i += 3;
                                continue;
                            }
                        }
                        tokens.push(Token::new(TokenKind::Redirect, Some(&input[i..i + 1])));
                        bytes.next();
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
            }

            if is_ident(c) {
                let begin = i;
                let id_len = ident(&mut bytes) + 1;
                tokens.push(Token::new(
                    TokenKind::Ident,
                    Some(&expand_ident(&input[begin..][0..id_len], env)),
                ));
                i += id_len;
            } else {
                match c {
                    ' ' | '\n' | '\t' => {
                        i += 1;
                    }
                    '>' => {
                        i += 1;
                        if let Some(p) = bytes.peek() {
                            if *p as char == '>' {
                                i += 1;
                                bytes.next();
                                tokens.push(Token::new(TokenKind::RedirectAppend, None));
                                continue;
                            }
                        }

                        tokens.push(Token::new(TokenKind::Redirect, None));
                    }
                    '|' => {
                        i += 1;
                        tokens.push(Token::new(TokenKind::Pipe, None));
                    }
                    ';' => {
                        i += 1;
                        tokens.push(Token::new(TokenKind::SemiColon, None));
                    }
                    '=' => {
                        i += 1;
                        tokens.push(Token::new(TokenKind::Equals, None));
                    }
                    '$' => {
                        let begin = i;
                        let q_len = ident_alnum2(&mut bytes) + 1;
                        tokens.push(Token::new(
                            TokenKind::Ident,
                            Some(&expand_ident(&input[begin..][0..q_len], env)),
                        ));
                        i += q_len;
                    }
                    '<' => {
                        i += 1;
                        tokens.push(Token::new(TokenKind::RedirectFrom, None));
                    }
                    '\'' => {
                        i += 1;
                        let begin = i;
                        let q_len = s_quote(&mut bytes);
                        tokens.push(Token::new(
                            TokenKind::Ident,
                            Some(&input[begin..][0..q_len]),
                        ));
                        i += 1 + q_len;
                        if let Some(n) = bytes.next() {
                            if n as char != '\'' {
                                return Err(TokErr::Unexpected);
                            }
                        } else {
                            return Err(TokErr::Unexpected);
                        }
                    }
                    '\"' => {
                        i += 1;
                        let begin = i;
                        let q_len = d_quote(&mut bytes);
                        tokens.push(Token::new(
                            TokenKind::Ident,
                            Some(&expand_ident(&input[begin..][0..q_len], env)),
                        ));
                        i += 1 + q_len;
                        if let Some(n) = bytes.next() {
                            if n as char != '\"' {
                                return Err(TokErr::Unexpected);
                            }
                        } else {
                            return Err(TokErr::Unexpected);
                        }
                    }
                    _ => {
                        return Err(TokErr::Unexpected);
                    }
                };
            }
        }

        tokens.push(Token::new(TokenKind::Eof, None));
        Ok(tokens)
    }
}

mod parse {
    use core::ffi::c_void;

    use alloc::{
        boxed::Box,
        collections::{BTreeMap, VecDeque},
        string::String,
        vec::Vec,
    };

    use crate::{
        print,
        stuff::own_string_from_ptr,
        sys::{self, chdir, close, dup2, execve, exit, open, pipe, strlen, strncmp, waitid},
        tok::{expand_from_path, Token, TokenKind},
        Env,
    };

    pub struct Parser<'a> {
        current: usize,
        tokens: &'a mut Vec<Token>,
        env: &'a mut Env,
    }

    #[derive(Debug)]
    pub enum ParseError {
        UnexpectedToken(TokenKind),
        UnexpectedEndOfFile,
    }

    pub struct Redir {
        pub to: bool,
        pub append: bool,
        pub path: *const u8,
    }

    pub enum ExcErr {
        NoEnt,
        Other,
    }

    pub struct Cmd {
        argv: Vec<*const u8>,
        redirects: BTreeMap<i32, Redir>,
        pipe: Option<*const Cmd>,
    }

    impl Drop for Cmd {
        fn drop(&mut self) {
            Cmd::drop2(&self);
        }
    }

    impl Cmd {
        pub fn new() -> Cmd {
            Cmd {
                argv: Vec::new(),
                redirects: BTreeMap::new(),
                pipe: None,
            }
        }

        pub fn drop2(cmd: &Cmd) {
            if cmd.pipe.is_none() {
                return;
            }

            let p_ref = unsafe { cmd.pipe.unwrap().cast_mut().as_mut().unwrap() };
            let _ = unsafe { Box::from_raw(p_ref as *mut Cmd) };
        }

        pub fn push_raw_arg(&mut self, arg: *const u8) {
            self.argv.push(arg);
        }

        pub fn argv_null_term(&mut self) {
            self.argv.push(core::ptr::null());
        }

        pub fn name_cstr(&self) -> *const u8 {
            self.argv[0]
        }

        pub fn argv_ptr(&self) -> *const *const u8 {
            self.argv.as_ptr()
        }

        pub fn exec(mut cmd: &Self) -> Result<i32, ExcErr> {
            if unsafe {
                strncmp(cmd.name_cstr(), "exit".as_ptr(), 4) == 0 && strlen(cmd.name_cstr()) == 4
            } {
                unsafe { exit(0) };
            }

            if unsafe {
                strncmp(cmd.name_cstr(), "cd".as_ptr(), 2) == 0 && strlen(cmd.name_cstr()) == 2
            } {
                let dir = if cmd.argv.len() > 2 {
                    cmd.argv[1]
                } else {
                    "/\0".as_ptr()
                };
                let res = unsafe { chdir(dir) };
                return if res == 0 { Ok(0) } else { Err(ExcErr::NoEnt) };
            }
            let mut pids = Vec::new();

            let mut pipe_fdq = VecDeque::<i32>::new();
            let mut first = true;

            loop {
                let mut pipe_fds = [-1, -1i32];

                if cmd.pipe.is_some() {
                    let res = unsafe { pipe(pipe_fds.as_mut_ptr()) };
                    assert!(res == 0);
                    pipe_fdq.push_front(pipe_fds[1]);
                    pipe_fdq.push_front(pipe_fds[0]);
                }

                let (stdin, stdout) = if first {
                    first = false;
                    (None, pipe_fdq.pop_back())
                } else {
                    (pipe_fdq.pop_back(), pipe_fdq.pop_back())
                };

                let pid = unsafe { sys::fork() };
                if pid == 0 {
                    //child
                    let r_iter = cmd.redirects.iter();
                    for (k, v) in r_iter {
                        let r_fd = unsafe {
                            open(
                                v.path,
                                0x40 | if v.append {
                                    0x400
                                } else if !v.to {
                                    0
                                } else {
                                    0x200
                                } | if v.to { 1 } else { 0 },
                                04000 | 07 | 070 | 0700,
                            )
                        };
                        assert!(r_fd >= 0);
                        if v.to {
                            let d_fd = unsafe { dup2(r_fd, *k) };
                            assert!(d_fd == *k);
                        } else {
                            let d_fd = unsafe { dup2(r_fd, 0) };
                            assert!(d_fd == 0);
                        }
                    }

                    if let Some(fd) = stdin {
                        let d_fd = unsafe { dup2(fd, 0) };
                        assert!(d_fd == 0);
                    }
                    if let Some(fd) = stdout {
                        let d_fd = unsafe { dup2(fd, 1) };
                        assert!(d_fd == 1);
                    }

                    let envp = [core::ptr::null()];
                    unsafe { execve(cmd.name_cstr(), cmd.argv_ptr(), envp.as_ptr()) };
                    print!("yansh: Command failed\n");
                    unsafe { exit(1) };
                } else if pid < 0 {
                    return Err(ExcErr::Other);
                } else {
                    if let Some(fd) = stdin {
                        unsafe { close(fd) };
                    }
                    if let Some(fd) = stdout {
                        unsafe { close(fd) };
                    }

                    pids.push(pid);
                }

                match cmd.pipe {
                    Some(p) => cmd = unsafe { p.as_ref().unwrap() },
                    _ => break,
                }
            }

            let mut xs = 0;
            for i in 0..pids.len() {
                let mut siginfo = [0u8; 128];
                unsafe { waitid(1, pids[i], siginfo.as_mut_ptr() as *mut c_void, 4) };
                xs = /* TODO siginfo.status*/ 0;
            }

            Ok(xs)
        }
    }

    impl<'a> Parser<'a> {
        pub fn new(env: &'a mut crate::Env, tokens: &'a mut Vec<Token>) -> Self {
            Self {
                current: 0,
                tokens,
                env,
            }
        }

        fn peek(&self) -> Option<&Token> {
            if self.current < self.tokens.len() {
                return Some(&self.tokens[self.current]);
            }
            None
        }

        fn check(&self, token_type: TokenKind) -> bool {
            if let Some(t) = self.tokens.get(self.current) {
                t.kind == token_type
            } else {
                false
            }
        }

        fn match_tokens(&mut self, tokens: &[TokenKind]) -> bool {
            if let Some(current_token) = self.tokens.get(self.current) {
                for tok in tokens.iter() {
                    if *tok == current_token.kind {
                        self.advance();
                        return true;
                    }
                }
            }
            return false;
        }

        fn advance(&mut self) -> Option<&Token> {
            self.current += 1;
            self.tokens.get(self.current - 1)
        }

        fn previous(&self) -> &Token {
            self.tokens.get(self.current - 1).unwrap()
        }

        fn previous_mut(&mut self) -> &mut Token {
            self.tokens.get_mut(self.current - 1).unwrap()
        }

        fn back(&mut self) {
            self.current -= 1;
        }

        fn expect(&mut self, kind: TokenKind) -> Result<&Token, ParseError> {
            if self.check(kind) {
                self.advance();
                Ok(self.previous())
            } else {
                if let Some(tok) = self.peek() {
                    Err(ParseError::UnexpectedToken(tok.kind))
                } else {
                    Err(ParseError::UnexpectedEndOfFile)
                }
            }
        }

        pub fn cmd(&mut self) -> Result<Cmd, ParseError> {
            let path = self.env.get_path();

            let cmd_name = self.previous();
            let mut cmd = Cmd::new();
            let name_slice = cmd_name.slice.unwrap();

            let k = unsafe {
                String::from_raw_parts(
                    name_slice.ptr() as *mut u8,
                    name_slice.len(),
                    name_slice.len(),
                )
            };

            let x = expand_from_path(&k, path);
            core::mem::forget(k);

            if let Some(x) = x {
                let cmd_name = self.previous_mut();
                cmd_name.slice_mut().unwrap().replace(x);
                cmd.push_raw_arg(cmd_name.slice.unwrap().ptr());
            } else {
                cmd.push_raw_arg(cmd_name.slice.unwrap().ptr());
            }

            while self.match_tokens(&[TokenKind::Ident]) {
                cmd.push_raw_arg(self.previous().slice.unwrap().ptr());
            }
            cmd.argv_null_term();
            Ok(cmd)
        }

        pub fn redir(&mut self) -> Result<Cmd, ParseError> {
            let mut cmd = self.cmd()?;
            while self.match_tokens(&[
                TokenKind::Redirect,
                TokenKind::RedirectAppend,
                TokenKind::RedirectFrom,
            ]) {
                let kind = self.previous().kind;
                let fd = if kind != TokenKind::RedirectFrom {
                    self.previous().slice.unwrap().ptr() as i32
                } else {
                    0
                };
                let prev = self.expect(TokenKind::Ident)?;
                cmd.redirects.insert(
                    fd,
                    Redir {
                        to: kind != TokenKind::RedirectFrom,
                        append: kind == TokenKind::RedirectAppend,
                        path: prev.slice.unwrap().ptr(),
                    },
                );
            }
            Ok(cmd)
        }

        pub fn pipeline(&mut self) -> Result<Cmd, ParseError> {
            let mut parent_cmd = self.redir()?;
            let mut cmd = &mut parent_cmd;
            while self.match_tokens(&[TokenKind::Pipe]) {
                self.expect(TokenKind::Ident)?;
                let cmd_box = Box::new(self.redir()?);
                let cmd_ptr = Box::into_raw(cmd_box);
                let cmd_ref = unsafe { cmd_ptr.as_mut().unwrap() };
                cmd.pipe = Some(cmd_ptr);
                cmd = cmd_ref;
            }
            Ok(parent_cmd)
        }

        pub fn vars(&mut self) -> Result<Option<Cmd>, ParseError> {
            let cmd_name = self.previous();
            let kslice = cmd_name.slice.unwrap();

            if self.match_tokens(&[TokenKind::Equals]) {
                let value = self.expect(TokenKind::Ident)?;
                let vslice = value.slice.unwrap();
                let key = own_string_from_ptr(kslice.ptr() as *mut u8, kslice.len());
                let value = own_string_from_ptr(vslice.ptr() as *mut u8, vslice.len());
                self.env.put_var(key, value);
                return Ok(None);
            }

            Ok(Some(self.pipeline()?))
        }

        pub fn parse(&mut self) -> Result<Vec<Cmd>, ParseError> {
            let mut cmds = Vec::new();
            loop {
                if let Some(tok) = self.peek() {
                    if tok.kind == TokenKind::Eof {
                        break;
                    }
                }
                self.expect(TokenKind::Ident)?;

                if let Some(cmd) = self.vars()? {
                    cmds.push(cmd);
                }
                if self.match_tokens(&[TokenKind::SemiColon, TokenKind::Eof]) {
                    let kind = self.previous().kind;
                    if kind == TokenKind::Eof {
                        break;
                    }
                } else {
                    // unreached
                }
            }
            Ok(cmds)
        }
    }
}

pub struct Env {
    vars: BTreeMap<String, String>,
    env_vars: BTreeMap<String, String>,
}

impl Env {
    pub fn new(envp: *const *const u8) -> Env {
        let mut env = Env {
            vars: BTreeMap::new(),
            env_vars: BTreeMap::new(),
        };

        let mut eptr = envp;
        while !(unsafe { *eptr }).is_null() {
            let len = unsafe { strlen(*eptr) };
            let str1 = unsafe { String::from_raw_parts(*eptr as *mut u8, len, len) };
            let sep = str1.find('=').unwrap();
            env.env_vars
                .insert(String::from(&str1[0..sep]), String::from(&str1[sep + 1..]));
            eptr = unsafe { eptr.add(1) };
            forget(str1);
        }

        env
    }

    pub fn put_var(&mut self, var: String, val: String) {
        self.vars.insert(var, val);
    }

    pub fn get_var(&self, key_ptr: *const u8, len: usize) -> &str {
        let key = unsafe { String::from_raw_parts(key_ptr as *mut u8, len, len) };
        let res = self.vars.get(&key);
        let res = if let Some(s) = res {
            s
        } else {
            if let Some(s) = self.env_vars.get(&key) {
                s
            } else {
                ""
            }
        };
        core::mem::forget(key);
        res
    }

    pub fn get_ex_var(&mut self, key: &str) -> &mut String {
        let k = unsafe { String::from_raw_parts(key.as_ptr() as *mut u8, key.len(), key.len()) };
        let res = self.vars.get_mut(&k).unwrap();
        core::mem::forget(k);
        res
    }

    pub fn get_path(&self) -> &str {
        let k = unsafe { String::from_raw_parts("PATH".as_ptr() as *mut u8, 4, 4) };
        let res = self.env_vars.get(&k);
        core::mem::forget(k);
        if let Some(p) = res {
            p
        } else {
            ""
        }
    }
}

fn main(argc: usize, argv: *const *const u8) {
    let envp = unsafe { argv.add(argc + 1) };
    let mut env = Env::new(envp);
    env.put_var("?".into(), "0".into());
    let stdin = rw::Stdin;
    let mut sr = ShellReader::new(stdin);
    loop {
        print!("$ ");
        let mut tokens = match tok::tokenize(&sr.read_line().unwrap(), &env) {
            Ok(t) => t,
            Err(_) => {
                print!("yansh: unexpected character somewhere\n");
                continue;
            }
        };
        let mut parser = parse::Parser::new(&mut env, &mut tokens);
        let mut cmds = match parser.parse() {
            Ok(c) => c,
            Err(_) => {
                print!("yansh: unexpected token somewhere\n");
                continue;
            }
        };
        for i in 0..cmds.len() {
            if let Ok(xs) = parse::Cmd::exec(&mut cmds[i]) {
                let xs_str = env.get_ex_var("?");
                xs_str.clear();
                xs_str.push_str(&format!("{}", xs));
            };
        }
    }
}

#[no_mangle]
pub extern "C" fn start_rs(argc: usize, argv: usize) {
    heap::init();
    main(argc, argv as *const *const u8);
}

mod heap;
mod rw;
mod stuff;
mod sys;
