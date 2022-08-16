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
    let exit_code = spawn::Command::new(OsStr::new(cmd[0].as_str()), cmdargs)
        .outdir(outdir.as_str())
        .spawn()
        .unwrap();
    std::process::exit(exit_code as _);
}
