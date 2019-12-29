pub fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("run using:\ntupspawn outdir application [args]\n");
        return;
    }
    let outdir = args[0].clone();
    let commandlinevec: Vec<_> = std::env::args().skip(2).collect();
    let commandline = commandlinevec.join(" ");
    spawn::spawn(commandline, outdir);
}
