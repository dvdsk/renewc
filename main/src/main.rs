use clap::{Parser, Subcommand};
use color_eyre::eyre::{self, Context};
use tracing::warn;

use renewc::{
    config::{InstallArgs, RenewArgs},
    run, systemd,
};

#[derive(Subcommand, Debug)]
enum Commands {
    /// Renew certificates now
    Run(RenewArgs),
    /// Create and enable renew-certs system service.
    Install(InstallArgs),
    /// Disable and remove renew-certs system service.
    Uninstall,
}

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about="Certificate renewal, with advanced diagnostics without installing anything",
    long_about = "This as a renewal tool that runs without install and does not need anything installed. If anything goes south during renewal it does not just report an error. It will try and find out what is wrong and give you a detailed report."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    #[clap(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    color_eyre::config::HookBuilder::default()
        .display_env_section(cli.debug)
        .display_location_section(cli.debug);

    setup_tracing(cli.debug);

    match cli.command {
        Commands::Run(args) => run(args, cli.debug).await?,
        Commands::Install(args) => {
            if !args.run.production {
                warn!("Installing service that runs against staging-environment, certificates will not be valid");
            }
            systemd::write_service().wrap_err("Could not write systemd service")?;
            systemd::write_timer(&args).wrap_err("Could not write systemd timer")?;
            systemd::enable().wrap_err("Could not enable service and timer")?;
        }
        Commands::Uninstall => {
            systemd::disable().wrap_err("Could not disable service and timer")?;
            systemd::remove_units().wrap_err("Could not remove service and timer")?;
        }
    }
    Ok(())
}

#[allow(clippy::missing_panics_doc)]
pub fn setup_tracing(debug: bool) {
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter = if debug {
        "renewc=debug,warn"
    } else {
        "renewc=info,warn"
    };

    let filter = filter::EnvFilter::builder().parse(filter).unwrap();

    let fmt = fmt::layer()
        .pretty()
        .with_line_number(true)
        .with_test_writer();

    let _ignore_err = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .try_init();
}
