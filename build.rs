use std::io::BufReader;
use std::path::PathBuf;
use std::{env, fs};

// #[cfg(target_arch = "aarch64")]
fn setup_crosscomp() {
    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    compile_error!("only setup to download crosscomp running on x86_64 linux");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    println!("{target_arch}");
    let cross_name = match target_arch.as_str() {
        "aarch64" => "aarch64-linux-musl-cross",
        "armv7" => "armv7-linux-musl-cross",
        "x86_64" => return,
        arch => panic!("unsupported arch: {arch}"),
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    let all_compilers = PathBuf::from(out_dir).join("musl");
    let compiler_dir = all_compilers.join(&cross_name);

    if !all_compilers.is_dir() {
        fs::create_dir(&all_compilers).unwrap();
    }
    if !compiler_dir.join(&cross_name).is_dir() {
        download_compiler(all_compilers, cross_name);
    }
}

fn download_compiler(compiler_dir: PathBuf, cross: &str) {
    use flate2::bufread::GzDecoder;
    use tar::Archive;

    println!("**** downloading musl crosscompiler ****");

    let mut sources = [
        "https://musl.cc/",
        "https://github.com/tsl0922/musl-toolchains/releases/download/2021-11-23/",
    ]
    .into_iter()
    .map(ToString::to_string);

    let bytes = loop {
        let source = sources.next().expect("No more mirrors to try");
        let uri = source + cross + ".tgz";
        match reqwest::blocking::get(&uri) {
            Ok(bytes) => break bytes,
            Err(_) => {
                eprintln!("Error trying to download from {uri:?}, trying another mirror");
            }
        }
    };

    println!("**** done downloading crosscompiler ****");

    let buf = BufReader::new(bytes);
    let tarfile = GzDecoder::new(buf);
    let mut archive = Archive::new(tarfile);
    archive.unpack(compiler_dir).unwrap();
}

fn main() {
    if std::env::consts::ARCH == "x86_64" {
        setup_crosscomp();
    }
}
