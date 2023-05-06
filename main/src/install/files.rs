// This followes the linux foundation recommendations:
// https://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html#THEUSRHIERARCHY

use std::io::{ErrorKind, Write};
use std::path::Path;
use std::{env, fs};

use color_eyre::eyre::{bail, Context};
use color_eyre::{eyre, Help};

use crate::config::InstallArgs;
use crate::warn;

pub(crate) fn install_local(stdout: &mut impl Write, args: &InstallArgs) -> eyre::Result<()> {
    todo!()
}

pub(crate) fn install_global(stdout: &mut impl Write, args: &InstallArgs) -> eyre::Result<()> {
    let current = env::current_exe().wrap_err(concat!(
        "Could not get ",
        env!("CARGO_PKG_NAME"),
        "'s binary location"
    ))?;

    let target = match args.dir {
        Some(ref dir) if dir.is_dir() => dir.join(env!("CARGO_PKG_NAME")),
        Some(_) => bail!("--dir argument is not a dir"),
        None => install_path()?.to_path_buf(),
    };

    if target == current {
        warn!(stdout, "Binary is already in install location.");
        return Ok(());
    }

    if let Err(e) = fs::copy(current, target) {
        let perm_denied = e.kind() == ErrorKind::PermissionDenied;
        let mut ret = Err(e).wrap_err("Could not copy binary to install location");
        if perm_denied {
            ret = ret.with_suggestion(|| "Try running using sudo");
        }
        ret?;
    }

    Ok(())
}

fn install_path() -> eyre::Result<&'static Path> {
    let possible_paths: &[&'static Path] =
        &[concat!("/usr/bin/", env!("CARGO_PKG_NAME"))].map(Path::new);

    for path in possible_paths {
        if path.parent().expect("never root").is_dir() {
            return Ok(path);
        }
    }

    Err(eyre::eyre!("No install location exists"))
        .suggestion("Set the location manually using --location <path>")
}

pub(crate) fn remove() -> eyre::Result<()> {
    todo!()
}

pub(crate) fn remove_system() -> _ {
    todo!()
}

pub(crate) fn remove_local() -> _ {
    todo!()
}
