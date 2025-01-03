use std::fmt::Display;
use std::path::Path;

use color_eyre::eyre;
use strum::EnumIter;

use crate::diagnostics;

use self::args::RenewArgs;
use self::paths::{ChainPath, KeyPath};

mod args;
mod paths;
pub use args::{Commands, InstallArgs, OutputArgs};
pub use paths::name;
use paths::CertPath;

#[derive(clap::ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
/// How to store the output.
///
/// After a certificate has been issued we have three outputs.
///  - The signed certificate for our domain(s).
///  - A certificate chain, it contains all the certificates
///    a client needs to check if our signed certificate is authentic.
///  - Our certificates private key.
pub enum Output {
    /// Use PEM encoding. Store the signed certificate, the chain and the private
    /// key in the same file in that order. File extension will be 'pem'.
    /// Note: format expected by: Haproxy
    PemSingleFile,

    /// Use PEM encoding. Store the signed certificate and certificate chain
    /// in the same file in that order. Keep the private key in another file.
    /// File extensions will be 'pem'.
    /// Note: If the file is auto generated the first will start with `chain_` the
    /// second in `key_`.
    /// Note: format expected by: Nginx and Apache
    #[default]
    PemSeperateKey,

    /// Use PEM encoding. Store the signed certificate and private key in the
    /// same file in that order. The chain is stored in another file.
    /// File extensions will be 'pem'.
    /// Note: If the file is auto generated the first will start with `cert_` the
    /// second in `chain_`.
    PemSeperateChain,

    /// Use PEM encoding. Store the signed certificate, private key and chain
    /// all in their own file. File extensions will be 'pem'.
    /// Note: If the file names are auto generated these will start with
    /// `cert_`, `key_` and `chain_`.
    PemAllSeperate,

    /// Use DER encoding. Store each certificate of the chain, the signed certificate
    /// and its private key in their own file. File extensions will be 'der'.
    /// Note: If the file names are auto generated these will start with
    /// `cert_`, `key_` and `chain_`.
    Der,

    // these still need implementing, lets not show them in the help text
    #[clap(skip)]
    PKCS12,
    #[clap(skip)]
    PKCS12SeperateKey,
    #[clap(skip)]
    PKCS12SeperateChain,
    #[clap(skip)]
    PKCS12AllSeperate,
}

impl Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::PemSingleFile => f.write_str("pem-single-file"),
            Output::PemSeperateKey => f.write_str("pem-seperate-key"),
            Output::PemSeperateChain => f.write_str("pem-seperate-chain"),
            Output::PemAllSeperate => f.write_str("pem-all-seperate"),
            Output::Der => f.write_str("der"),
            Output::PKCS12 => f.write_str("pkcs12"),
            Output::PKCS12SeperateKey => f.write_str("pkcs12-seperate-key"),
            Output::PKCS12SeperateChain => f.write_str("pkcs12-seperate-chain"),
            Output::PKCS12AllSeperate => f.write_str("pkcs12-all-seperate"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub enum Encoding {
    PEM,
    DER,
    PKCS12,
}

impl Encoding {
    pub(crate) fn extension(self) -> &'static str {
        match self {
            Encoding::PEM => "pem",
            Encoding::DER => "der",
            Encoding::PKCS12 => "pkcs12",
        }
    }
}

impl From<&Output> for Encoding {
    fn from(output: &Output) -> Self {
        match output {
            Output::PemSingleFile
            | Output::PemSeperateKey
            | Output::PemSeperateChain
            | Output::PemAllSeperate => Encoding::PEM,
            Output::Der => Encoding::DER,
            Output::PKCS12
            | Output::PKCS12SeperateKey
            | Output::PKCS12SeperateChain
            | Output::PKCS12AllSeperate => Encoding::PKCS12,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub output: Output,
    pub cert_path: CertPath,
    pub key_path: KeyPath,
    pub chain_path: ChainPath,
}

impl OutputConfig {
    fn new(args: OutputArgs, name: &str) -> Result<Self, eyre::Report> {
        Ok(OutputConfig {
            cert_path: CertPath::new(&args.output, &args.certificate_path, name)?,
            key_path: KeyPath::new(&args.output, &args.certificate_path, args.key_path, name)?,
            chain_path: ChainPath::new(
                &args.output,
                &args.certificate_path,
                args.chain_path,
                name,
            )?,
            output: args.output,
        })
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Config {
    pub domains: Vec<String>,
    pub(crate) email: Vec<String>,
    pub production: bool,
    pub port: u16,
    pub output_config: OutputConfig,
    /// reload an external systemd service
    pub reload: Option<String>,
    pub(crate) renew_early: bool,
    pub(crate) overwrite_production: bool,
    /// do not ask questions
    pub non_interactive: bool,
    pub force: bool,
    pub diagnostics: diagnostics::Config,
}

impl TryFrom<RenewArgs> for Config {
    type Error = eyre::Report;

    fn try_from(args: RenewArgs) -> Result<Self, Self::Error> {
        let name = name(&args.domain)?;
        let output_config = OutputConfig::new(args.output_config, &name)?;
        Ok(Config {
            domains: args.domain,
            email: args.email,
            production: args.production,
            port: args.port,
            output_config,
            reload: args.reload,
            force: args.force,
            renew_early: args.renew_early,
            overwrite_production: args.overwrite_production,
            non_interactive: false,
            diagnostics: diagnostics::Config::default(),
        })
    }
}

impl Config {
    #[must_use]
    pub fn test(port: u16, dir: &Path) -> Self {
        let domains = vec!["testdomain.org".into()];
        let name = name(&domains).unwrap();
        let output_args = OutputArgs::test(dir);
        let output_config = OutputConfig::new(output_args, &name).unwrap();
        Config {
            domains,
            email: vec!["test@testdomain.org".into()],
            production: false,
            port,
            output_config,
            reload: None,
            renew_early: false,
            force: false,
            overwrite_production: false,
            non_interactive: true,
            diagnostics: diagnostics::Config::test(),
        }
    }
}
