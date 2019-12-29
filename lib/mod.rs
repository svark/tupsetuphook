extern crate named_pipe;
extern crate winapi;
extern crate detours_sys as detours;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{ExitProcess, GetExitCodeProcess, ResumeThread};
use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOA};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_DEFAULT_ERROR_MODE, CREATE_SUSPENDED, INFINITE};
use std::ffi::CString;
pub static S_TRAP_GUID: GUID = GUID {
    Data1: 0x9640b7b0,
    Data2: 0xca4d,
    Data3: 0x4d61,
    Data4: [0x9a, 0x27, 0x79, 0xc7, 0x9, 0xa3, 0x1e, 0xb0],
};

pub fn pipserve(threaddone: Arc<AtomicBool>, pid: u32, out: &std::path::PathBuf) {
    use named_pipe::PipeOptions;
    pub const TBLOG_PIPE_NAME: &'static str = "\\\\.\\pipe\\tracebuild\0";
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    let o = out.clone();
    let o = o.join(format!("evts-{}", pid));
    let mut file: File = OpenOptions::new().write(true).create(true).open(o).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        'outer: while !threaddone.load(Ordering::Acquire) {
            let mut cs = PipeOptions::new(TBLOG_PIPE_NAME)
                .open_mode(named_pipe::OpenMode::Duplex)
                .single()
                .unwrap();
            while let Ok(mut server) = cs.wait() {
                let _ = server.write("s".as_bytes());
                while let Ok(sz) = server.read(&mut buf) {
                    if sz > 0 {
                        let _ = file.write(&buf[..sz]);
                    } else {
                        break;
                    }
                }
                match server.disconnect() {
                    Err(e) => {
                        eprintln!("failed:{}", e);
                        break;
                    }
                    Ok(csnew) => cs = csnew,
                }
                if threaddone.load(Ordering::Acquire) {
                    break 'outer;
                }
            }
        }
    });
}

pub fn spawn(commandline: String, outdir : String )
{
  unsafe {
      let mut si: STARTUPINFOA = std::mem::zeroed();
      si.cb = std::mem::size_of::<STARTUPINFOA>() as _;
      let pi: PROCESS_INFORMATION = std::mem::zeroed();
      let cl = CString::new(commandline.as_str()).unwrap();
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

      let paths = paths
          .iter()
          .map(|pb| pb.as_path().join("tupinject64.dll"))
          .find(|x| x.is_file())
          .expect("tupinjec64.dll not found in path");

      let dllpath = std::ffi::CString::new(paths.to_str().unwrap());
      println!("with dll:{:?}", &dllpath);
      let dllpathptr = dllpath.unwrap();
      let dllpaths: [*const i8; 1] = [dllpathptr.as_bytes_with_nul().as_ptr() as _];
      let dwflags: DWORD = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;
      let null = std::ptr::null_mut();
      if detours::DetourCreateProcessWithDllsA(
          null as _,
            cl.as_ptr() as *mut _,
            null as _,
            null as _,
            TRUE,
            dwflags,
            null as _,
            null as _,
            (&si as *const _) as _,
            &pi as *const _ as _,
            1,
            dllpaths.as_ptr() as _,
            None,
        ) != TRUE
        {
            println!(
                "TRACEBLD: DetourCreateProcessWithDllEx failed with {}\n",
                winapi::um::errhandlingapi::GetLastError()
            );
            ExitProcess(9007);
        }
      let done = Arc::new(AtomicBool::new(false));
      pipserve(
          done.clone(),
          pi.dwProcessId,
          &std::path::PathBuf::from(outdir),
      );
      ResumeThread(pi.hThread);

      WaitForSingleObject(pi.hProcess, INFINITE);
      done.store(true, Ordering::Release);
      let mut dw_result: DWORD = 0;
      if FALSE == GetExitCodeProcess(pi.hProcess, &mut dw_result as *mut _ as _) {
          eprintln!(
              "TRACEBLD: GetExitCodeProcess failed: {}\n",
              winapi::um::errhandlingapi::GetLastError()
          );
          // return 9008;
      }

      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }
}
