use std::ffi::OsString;

pub fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("run using:\ntupspawn outdir application [args]\n");
        return;
    }
    let outdir = args[0].clone();
    let cmd: Vec<_> = std::env::args().skip(2).take(1).collect();
    let cmdargs: Vec<_> = std::env::args()
        .skip(3)
        .map(|x| OsStr::new(&x).to_os_string())
        .collect();

    use std::ffi::OsStr;
    let exit_code = tupexec::Command::new(OsStr::new(cmd[0].as_str()), cmdargs)
        .outdir(OsString::from(outdir.as_str()).as_os_str() )
        .spawn()
        .unwrap().wait();
    std::process::exit(exit_code.code().unwrap());
}
