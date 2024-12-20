use clap::{Parser, Subcommand, ValueHint};
use time::macros::format_description;
use std::path::{PathBuf, Path};
use std::str::FromStr;

use super::Output;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Renew certificates now
    Run(RenewArgs),
    /// Create and enable renew-certs system service.
    Install(InstallArgs),
    /// Disable and remove renew-certs system service.
    Uninstall,
}

impl Commands {
    #[must_use]
    pub fn debug(&self) -> bool {
        match self {
            Commands::Run(args) => args.debug,
            Commands::Install(args) => args.run.debug,
            Commands::Uninstall => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Time(pub time::Time);

impl FromStr for Time {
    type Err = time::error::Parse;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let format = format_description!("[hour]:[minute]");
        Ok(Self(time::Time::parse(s, &format)?))
    }
}

#[derive(Parser, Debug)]
pub struct InstallArgs {
    /// time at which refresh should run
    #[clap(long, default_value = "04:00")]
    pub time: Time,

    #[clap(flatten)]
    pub run: RenewArgs,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
pub struct RenewArgs {
    /// domain(s) request certificates for multiple subdomains
    /// by passing this argument multiple times with various domains
    /// note the base domain must be the same in all
    #[clap(long, short, required = true, value_hint=ValueHint::Other)]
    pub domain: Vec<String>,

    /// Contact info
    #[clap(long, value_hint = ValueHint::EmailAddress)]
    pub email: Vec<String>,

    /// Use Let's Encrypt production environment
    /// (see https://letsencrypt.org/docs/staging-environment/)
    #[clap(long)]
    pub production: bool,

    /// External port 80 should be forwarded to this
    /// internal port
    #[clap(long, short, default_value_t = 80, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,

    /// Systemd service to reload after renewal
    #[clap(long, short, value_hint=ValueHint::Other)]
    pub reload: Option<String>,

    /// Renew a certificate even if its not due yet
    #[clap(long, default_value_t = false)]
    pub renew_early: bool,

    /// Ignore existing certificates and always renew
    #[clap(long, default_value_t = false)]
    pub force: bool,

    /// Request a staging certificate even if that overwrites a
    /// valid production certificate
    #[clap(long, default_value_t = false)]
    pub overwrite_production: bool,

    #[clap(long)]
    pub debug: bool,

    // the options in the Output struct are added at the end
    #[clap(flatten)]
    pub output_config: OutputArgs,
}

#[derive(Parser, Debug, Clone)]
pub struct OutputArgs {
    /// How to store the output, encoding and ways to split
    /// the file between files.
    #[clap(long, short, value_enum, default_value_t = Output::PemSeperateKey)]
    pub output: Output,

    /// Path including file name where to output the signed
    /// certificate possibly with its private key and/or chain
    /// (depending on the selected Output option).
    ///
    /// Note: The correct file extension is added automatically 
    /// if left unspecified. It depends on the chosen output format.
    #[clap(long, short, value_hint=ValueHint::FilePath)]
    pub certificate_path: PathBuf,

    /// Path including file name where to output the certificates
    /// private key. Used when it is stored seperate from the other
    /// output.
    ///
    /// If left unspecified this will default to the
    /// certificate-path's dir and the file name will be the shortest
    /// part of the domain(s).
    ///
    /// Note: The correct file extension is added automatically 
    /// if left unspecified. It depends on the chosen output format.
    #[clap(long, value_hint=ValueHint::FilePath)]
    pub key_path: Option<PathBuf>,

    /// Path including file name where to output the certificates chain.
    /// Used when it is stored seperate from the other output. If left
    /// unspecified it is deduced from the certificate-path.
    ///
    /// If left unspecified this will default to the
    /// certificate-path's dir and the file name will be the shortest
    /// part of the domain(s).
    ///
    /// Note: Can not be used when the format is set to Der.
    /// Note: The correct file extension is added automatically 
    /// if left unspecified
    #[clap(long, value_hint=ValueHint::FilePath)]
    pub chain_path: Option<PathBuf>,
}

impl OutputArgs {
    #[must_use] pub fn test(dir: &Path) -> Self {
        Self {
            output: Output::default(),
            certificate_path: dir.to_owned(),
            key_path: None,
            chain_path: None,
        }
    }
}
