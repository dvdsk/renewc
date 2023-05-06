use std::io::Write;

use color_eyre::eyre::{self, Context};

use crate::config::{InstallArgs, UninstallTarget};
use crate::Config;

mod files;
mod systemd;

// todo global vs local install
// https://wiki.archlinux.org/title/Systemd/User#Automatic_start-up_of_systemd_user_instances
// https://www.freedesktop.org/software/systemd/man/systemd.special.html#Units%20managed%20by%20the%20user%20service%20manager
// https://unix.stackexchange.com/questions/698463/service-in-systemd-user-mode-inactive-dead
// https://www.man7.org/linux/man-pages/man1/loginctl.1.html
// https://www.xf.is/2020/06/27/configuring-systemd-user-timer/

// TODO testing, with docker container or something?

pub fn local(stdout: &mut impl Write, args: InstallArgs) -> eyre::Result<()> {
    files::install_local(stdout, &args).wrap_err("Could not move files")?;
    systemd::local::enable_linger()?;
    systemd::local::write_service().wrap_err("Could not write systemd service")?;
    systemd::local::write_timer(&args).wrap_err("Could not write systemd timer")?;
    systemd::local::enable().wrap_err("Could not enable service and timer")
}

pub fn global(stdout: &mut impl Write, args: InstallArgs) -> eyre::Result<()> {
    files::install_global(stdout, &args).wrap_err("Failed to move files")?;
    systemd::system::write_service().wrap_err("Could not write systemd service")?;
    systemd::system::write_timer(&args).wrap_err("Could not write systemd timer")?;
    systemd::system::enable().wrap_err("Could not enable service and timer")
}

pub fn place(stdout: &mut impl Write, args: InstallArgs) -> eyre::Result<()> {
    let config: Config = args.run.into();
    if config.port > 1024 && !args.global {
        local(stdout, args)
    } else {
        global(stdout, args)
    }
}

pub fn remove(target: UninstallTarget) -> eyre::Result<()> {
    match target {
        UninstallTarget::System => {
            files::remove_system()?;
            systemd::system::disable()?;
            systemd::system::remove_units()?;
        }
        UninstallTarget::Local => {
            files::remove_local()?;
            systemd::local::disable()?;
            systemd::local::remove_units()?;
        }
        UninstallTarget::All => todo!(),
        UninstallTarget::Ask => todo!(),
    }

    Ok(())
}

pub fn reload(service: &str) -> eyre::Result<()> {
    todo!()
    // systemd::global::systemctl(&["reload"], service)
    //     .wrap_err_with(|| "Could not reload ".to_owned() + service)
}
