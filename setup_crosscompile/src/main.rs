use std::collections::HashMap;
use std::io::BufReader;
use std::path::PathBuf;
use std::{env, fs};

fn download_compiler(dir: PathBuf, cross: &str) {
    use flate2::bufread::GzDecoder;
    use tar::Archive;

    println!("**** downloading musl crosscompiler ****");

    let mut sources = [
        "https://github.com/tsl0922/musl-toolchains/releases/download/2021-11-23/",
        "https://musl.cc/", // be nice to musl cc, dont hammer them from CI
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
    archive.unpack(dir).unwrap();
}

fn main() {
    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    compile_error!("only setup to download crosscomp running on x86_64 linux");
    let mut musl_compilers = HashMap::new();
    musl_compilers.insert("x86_64-unknown-linux-musl", "x86_64-linux-musl-native");
    musl_compilers.insert("aarch64-unknown-linux-musl", "aarch64-linux-musl-cross");
    musl_compilers.insert(
        "armv7-unknown-linux-musleabihf",
        "armv7l-linux-musleabihf-cross",
    );
    musl_compilers.insert("arm-unknown-linux-musleabihf", "arm-linux-musleabihf-cross");

    let target_arch = env::args().nth(1).expect("needs arch as argument");
    let compiler_name = musl_compilers.get(target_arch.as_str()).unwrap_or_else(|| panic!("unsupported arch: {target_arch}\nvalid options are: {:?}",
        musl_compilers.keys().collect::<Vec<_>>()));

    let dir = PathBuf::from("../compilers");
    if !dir.is_dir() {
        fs::create_dir(&dir).unwrap();
    }

    if !dir.join(compiler_name).is_dir() {
        download_compiler(dir, compiler_name);
    }
}
