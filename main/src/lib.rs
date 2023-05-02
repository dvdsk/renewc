#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::io::Write;

use cert::format::PemItem;
use cert::info::Info;
use color_eyre::owo_colors::OwoColorize;

use color_eyre::eyre;

pub mod cert;
pub mod config;
pub mod diagnostics;
pub mod renew;
pub mod systemd;
pub mod util;

pub use config::Config;

macro_rules! warn {
    ($stream:expr, $($arg:tt)*) => {
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.red())).unwrap()
        writeln!($stream, "{}", format_args!($($arg)*).red()).unwrap()
    };
}

macro_rules! info {
    ($stream:expr, $($arg:tt)*) => {
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.green())).unwrap()
        writeln!($stream, "{}", format_args!($($arg)*).green()).unwrap()
    };
}

/// during integration testing we do not want to hit lets encrypts backend
/// by passing the ACME implentation we can test other functionality.
#[async_trait::async_trait]
pub trait ACME {
    async fn renew<P: PemItem>(
        &self,
        config: &Config,
        debug: bool,
    ) -> eyre::Result<cert::Signed<P>>;
}

pub async fn run<P: PemItem>(
    acme_impl: impl ACME,
    stdout: &mut impl Write,
    config: &Config,
    debug: bool,
) -> eyre::Result<Option<cert::Signed<P>>> {
    if let Some(cert) = Info::from_disk(config)? {
        match (config.production, cert.staging, cert.should_renew()) {
            (false, true, _) => {
                warn!(
                    stdout,
                    "Requesting Staging cert, certificates will not be valid"
                );
            }
            (false, false, _) if cert.is_expired() => {
                warn!(stdout, "Requesting Staging cert. Overwriting expired production certificate. Certificate will not be valid");
            }
            (false, false, _) => {
                let question = "Found still valid production cert, continuing will overwrite it with a staging certificate";
                if !config.overwrite_production && exit_requested(stdout, config, question) {
                    return Ok(None);
                }
                warn!(
                    stdout,
                    "Requesting Staging cert, certificates will not be valid"
                );
            }
            (true, true, _) => {
                info!(
                    stdout,
                    "Requesting production cert, existing certificate is staging"
                );
            }
            (true, false, true) => {
                if cert.is_expired() {
                    warn!(stdout, "Renewing production cert: existing certificate expired {} days, {} hours ago", cert.since_expired().whole_days(), cert.since_expired().whole_hours());
                } else {
                    warn!(stdout, "Renewing production cert: existing certificate expires soon: {} days, {} hours", 
                      cert.expires_in.whole_days(),
                      cert.expires_in.whole_hours());
                }
            }
            (true, false, false) => {
                info!(
                    stdout,
                    "Production cert not yet due for renewal, expires in: {} days, {} hours",
                    cert.expires_in.whole_days(),
                    cert.expires_in.whole_hours()
                );
                if !config.renew_early {
                    info!(stdout, "Quiting, you can force renewal using --renew-early");
                    return Ok(None);
                }
            }
        }
    }

    let signed = acme_impl.renew(config, debug).await?;
    Ok(Some(signed))
}

#[must_use]
fn exit_requested(w: &mut impl Write, config: &Config, question: &str) -> bool {
    use is_terminal::IsTerminal;

    info!(w, "{}", question);

    if config.non_interactive || !std::io::stdin().is_terminal() {
        warn!(w, "Need user confirmation however no user input possible");
        return true; // user cant confirm
    }

    info!(w, "Continue? y/n");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    if let Some('y') = buf.chars().next() {
        info!(w, "Quiting, user requested exit");
        true
    } else {
        false
    }
}
