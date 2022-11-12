extern crate detours_sys as detours;
//extern crate named_pipe;
extern crate winapi;
//extern crate lazy_static;
// use std::ffi::CString;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetExitCodeProcess, ResumeThread};
use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_DEFAULT_ERROR_MODE, CREATE_SUSPENDED, INFINITE};

pub static S_TRAP_GUID: GUID = GUID {
    Data1: 0x9640b7b0,
    Data2: 0xca4d,
    Data3: 0x4d61,
    Data4: [0x9a, 0x27, 0x79, 0xc7, 0x9, 0xa3, 0x1e, 0xb0],
};

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};

pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    env: Option<HashMap<OsString, OsString>>,
    cwd: Option<OsString>,
    outdir: String,
}

fn mk_key(s: &OsStr) -> OsString {
    s.to_str().unwrap().to_ascii_uppercase().into()
}

struct Payload {
    handle: RawHandle,
}

impl Payload {
    pub fn new(handle: RawHandle) -> Payload {
        Payload { handle }
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl Command {
    pub fn new(program: &OsStr, args: Vec<OsString>) -> Command {
        Command {
            program: program.to_os_string(),
            args,
            env: None,
            cwd: None,
            outdir: ".".to_string(),
        }
    }

    pub fn arg(&mut self, arg: &OsStr) -> &mut Self {
        self.args.push(arg.to_os_string());
        self
    }
    fn init_env_map(&mut self) {
        if self.env.is_none() {
            self.env = Some(
                std::env::vars_os()
                    .map(|(key, val)| (mk_key(&key), val))
                    .collect(),
            );
        }
    }
    pub fn env(&mut self, key: &OsStr, val: &OsStr) -> &mut Self {
        self.init_env_map();
        self.env
            .as_mut()
            .unwrap()
            .insert(mk_key(key), val.to_os_string());
        self
    }
    pub fn env_remove(&mut self, key: &OsStr) -> &mut Self {
        self.init_env_map();
        self.env.as_mut().unwrap().remove(&mk_key(key));
        self
    }
    pub fn env_clear(&mut self) -> &mut Self {
        self.env = Some(HashMap::new());
        self
    }
    pub fn cwd(&mut self, dir: &OsStr) -> &mut Self {
        self.cwd = Some(dir.to_os_string());
        self
    }
    pub fn outdir(&mut self, outdir: &str) -> &mut Self {
        self.outdir = outdir.to_string();
        self
    }

    pub fn spawn(&mut self) -> io::Result<DWORD> {
        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as _;
            let pi: PROCESS_INFORMATION = std::mem::zeroed();
            let cl = make_command_line(&self.program, &self.args)?;
            println!("starting :{:?}", cl);
            use std::env;
            let mut paths = match env::var_os("PATH") {
                Some(path) => env::split_paths(&path).collect::<Vec<_>>(),
                None => vec![],
            };
            paths.push(std::path::PathBuf::from("."));
            paths.push(
                std::path::PathBuf::from(std::env::args().next().unwrap())
                    .parent()
                    .unwrap()
                    .to_path_buf(),
            );
            let dll64path = paths
                .iter()
                .map(|pb| pb.as_path().join("tupinject64.dll"))
                .find(|x| x.is_file())
                .expect("tupinject64.dll not found in path");

            let dllpath = std::ffi::CString::new(dll64path.to_str().unwrap());
            let (envp, _) = make_envp(self.env.as_ref())?;
            let (dirp, _) = make_dirp(self.cwd.as_ref())?;
            let dllpathptr = dllpath.unwrap();
            let dllpaths: [*const i8; 1] = [dllpathptr.as_bytes_with_nul().as_ptr() as _];
            let dwflags: DWORD = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;
            let null = std::ptr::null_mut();
            if detours::DetourCreateProcessWithDllsW(
                null as _,
                cl.as_ptr() as *mut _,
                null as _,
                null as _,
                TRUE,
                dwflags,
                envp,
                dirp,
                (&si as *const _) as _,
                &pi as *const _ as _,
                1,
                dllpaths.as_ptr() as _,
                None,
            ) != TRUE
            {
                eprintln!(
                    "SetupHook: DetourCreateProcessWithDllEx failed with {}\n",
                    winapi::um::errhandlingapi::GetLastError()
                );
                return Err(io::Error::from_raw_os_error(9007));
            }
            // let done = Arc::new(AtomicBool::new(false));
            use std::fs::File;
            use std::fs::OpenOptions;
            let o = std::path::PathBuf::from(&self.outdir).join(format!("evts-{}", pi.dwProcessId));
            let file: File = OpenOptions::new().write(true).create(true).open(o).unwrap();
            use std::os::windows::io::IntoRawHandle;
            let handle = Handle::new(file.into_raw_handle());
            use winapi::um::winnt::DUPLICATE_SAME_ACCESS;
            let dup = handle.duplicate(Handle::new(pi.hProcess), 0, true, DUPLICATE_SAME_ACCESS);
            if dup.is_err() {
                eprintln!(
                    "TRACEBLD: file handle duplication failed: {}\n",
                    winapi::um::errhandlingapi::GetLastError()
                );

                std::process::exit(9007);
            }
            let payload = Payload::new(dup.unwrap().raw());
            if FALSE
                == detours::DetourCopyPayloadToProcess(
                    pi.hProcess as _,
                    &S_TRAP_GUID as *const _ as _,
                    &payload as *const _ as _,
                    std::mem::size_of::<Payload>() as _,
                )
            {
                eprintln!(
                    "TRACEBLD: could not setup payload during dll injection: {}\n",
                    winapi::um::errhandlingapi::GetLastError()
                );

                std::process::exit(9008);
            }

            ResumeThread(pi.hThread);

            WaitForSingleObject(pi.hProcess, INFINITE);
            let mut dw_result: DWORD = 0;
            if FALSE == GetExitCodeProcess(pi.hProcess, &mut dw_result as *mut _ as _) {
                eprintln!(
                    "TRACEBLD: GetExitCodeProcess failed: {}\n",
                    winapi::um::errhandlingapi::GetLastError()
                );
                std::process::exit(9008);
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            Ok(dw_result)
        }
    }
}

use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
// use std::ffi::{OsString};

fn ensure_no_nuls<T: AsRef<OsStr>>(str: T) -> std::io::Result<T> {
    if str.as_ref().encode_wide().any(|b| b == 0) {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "nul byte found in provided data",
        ))
    } else {
        Ok(str)
    }
}

fn make_command_line(prog: &OsStr, args: &[OsString]) -> std::io::Result<Vec<u16>> {
    // Encode the command and arguments in a command line string such
    // that the spawned process may recover them using CommandLineToArgvW.
    let mut cmd: Vec<u16> = Vec::new();
    append_arg(&mut cmd, prog)?;
    for arg in args {
        cmd.push(' ' as u16);
        append_arg(&mut cmd, arg)?;
    }
    cmd.push('\0' as u16);
    return Ok(cmd);

    fn append_arg(cmd: &mut Vec<u16>, arg: &OsStr) -> std::io::Result<()> {
        // If an argument has 0 characters then we need to quote it to ensure
        // that it actually gets passed through on the command line or otherwise
        // it will be dropped entirely when parsed on the other end.
        ensure_no_nuls(arg)?;
        let quote = arg
            .to_str()
            .unwrap_or("")
            .as_bytes()
            .iter()
            .any(|c| *c == b' ' || *c == b'\t')
            || arg.is_empty();
        if quote {
            cmd.push('"' as u16);
        }

        let iter = arg.encode_wide();
        let mut backslashes: usize = 0;
        for x in iter {
            if x == '\\' as u16 {
                backslashes += 1;
            } else {
                if x == '"' as u16 {
                    // Add n+1 backslashes to total 2n+1 before internal '"'.
                    for _ in 0..(backslashes + 1) {
                        cmd.push('\\' as u16);
                    }
                }
                backslashes = 0;
            }
            cmd.push(x);
        }

        if quote {
            // Add n backslashes to total 2n before ending '"'.
            for _ in 0..backslashes {
                cmd.push('\\' as u16);
            }
            cmd.push('"' as u16);
        }
        Ok(())
    }
}

fn make_envp(
    env: Option<&std::collections::HashMap<OsString, OsString>>,
) -> std::io::Result<(*mut c_void, Vec<u16>)> {
    // On Windows we pass an "environment block" which is not a char**, but
    // rather a concatenation of null-terminated k=v\0 sequences, with a final
    // \0 to terminate.
    match env {
        Some(env) => {
            let mut blk = Vec::new();

            for pair in env {
                blk.extend(ensure_no_nuls(pair.0)?.encode_wide());
                blk.push('=' as u16);
                blk.extend(ensure_no_nuls(pair.1)?.encode_wide());
                blk.push(0);
            }
            blk.push(0);
            Ok((blk.as_mut_ptr() as *mut c_void, blk))
        }
        _ => Ok((std::ptr::null_mut(), Vec::new())),
    }
}

fn make_dirp(d: Option<&OsString>) -> std::io::Result<(*const u16, Vec<u16>)> {
    match d {
        Some(dir) => {
            let mut dir_str: Vec<u16> = ensure_no_nuls(dir)?.encode_wide().collect();
            dir_str.push(0);
            Ok((dir_str.as_ptr(), dir_str))
        }
        None => Ok((std::ptr::null(), Vec::new())),
    }
}

////////////////////////////////////////////////////////////////////////////////
// Processes
////////////////////////////////////////////////////////////////////////////////

/// An owned container for `HANDLE` object, closing them on Drop.
///
/// All methods are inherited through a `Deref` impl to `RawHandle`
pub use std::os::windows::io::RawHandle;

pub struct Handle(RawHandle);

/// A wrapper type for `HANDLE` objects to give them proper Send/Sync inference
/// as well as Rust-y methods.
///
/// This does **not** drop the handle when it goes out of scope, use `Handle`
/// instead for that.
use winapi::um::winnt::HANDLE;

unsafe impl Send for Handle {}

unsafe impl Sync for Handle {}

/// A value representing a child process.
///
/// The lifetime of this value is linked to the lifetime of the actual
/// process - the Process destructor calls self.finish() which waits
/// for the process to terminate.
pub struct Process {
    handle: Handle,
}

pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }
use std::io;

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

use winapi::um::handleapi::DuplicateHandle;

impl Handle {
    fn raw(&self) -> HANDLE {
        self.0
    }
    fn duplicate(
        &self,
        target_process: Handle,
        access: DWORD,
        inherit: bool,
        options: DWORD,
    ) -> io::Result<Handle> {
        let mut ret = 0 as HANDLE;
        cvt(unsafe {
            let cur_proc = GetCurrentProcess();
            DuplicateHandle(
                cur_proc,
                self.0,
                target_process.raw(),
                &mut ret,
                access,
                inherit as BOOL,
                options,
            )
        })?;
        Ok(Handle::new(ret))
    }
    pub fn new(handle: RawHandle) -> Handle {
        Handle(handle)
    }
}

use winapi::um::processthreadsapi::{GetProcessId, TerminateProcess};
use winapi::um::winbase::WAIT_OBJECT_0;

impl Process {
    pub fn new(handle: Handle) -> Process {
        Process { handle }
    }
    pub fn kill(&mut self) -> io::Result<()> {
        cvt(unsafe { TerminateProcess(self.handle.raw(), 1) })?;
        Ok(())
    }

    pub fn id(&self) -> u32 {
        unsafe { GetProcessId(self.handle.raw()) as u32 }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        unsafe {
            let res = WaitForSingleObject(self.handle.raw(), INFINITE);
            if res != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let mut status = 0;
            cvt(GetExitCodeProcess(self.handle.raw(), &mut status))?;
            Ok(ExitStatus(status))
        }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub fn into_handle(self) -> Handle {
        self.handle
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitStatus(DWORD);

impl ExitStatus {
    pub fn success(&self) -> bool {
        self.0 == 0
    }
    pub fn code(&self) -> Option<i32> {
        Some(self.0 as i32)
    }
}

impl From<DWORD> for ExitStatus {
    fn from(u: DWORD) -> ExitStatus {
        ExitStatus(u)
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "exit code: {}", self.0)
    }
}
