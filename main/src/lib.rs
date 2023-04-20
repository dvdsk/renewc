#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use time::Duration;

use color_eyre::eyre::{self, Context};
use tracing::{warn, info};

pub mod cert;
pub mod renew;
pub mod server;
pub mod systemd;
pub mod util;
pub mod diagnostics;
pub mod config;

pub use config::Config;

pub async fn run(config: impl Into<Config>, debug: bool) -> eyre::Result<()> {
    let config = config.into();

    if let Some(existing) = cert::extract_combined(&config.path)? {
        let (expires_in, is_staging) = cert::analyze(&existing)?;
        let expires_soon = expires_in < Duration::days(10);
        match (!config.production, is_staging, expires_soon) {
            (true, true, _) => {
                warn!("Requesting Staging cert, certificates will not be valid");
            }
            (true, false, _) if expires_in < Duration::seconds(0) => {
                warn!("Requesting Staging cert. Overwriting expired production certificate. Certificate will not be valid");
            }
            (true, false, _) => {
                let question = "Found still valid production cert, continuing will overwrite it with a staging certificate";
                if !config.overwrite_production {
                    if exit_requested(&config, question) {
                        return Ok(());
                    }
                }
                warn!("Requesting Staging cert, certificates will not be valid");
            }
            (false, true, _) => {
                info!("Requesting production cert, existing certificate is staging");
            }
            (false, false, true) => {
                info!("Renewing production cert: existing certificate expires soon: {} days, {} hours", 
                      expires_in.whole_days(), 
                      expires_in.whole_hours());
            }
            (false, false, false) => {
                info!("Production cert not yet due for renewal, expires in: {} days, {} hours", 
                      expires_in.whole_days(), 
                      expires_in.whole_hours());
                if !config.renew_early {
                    println!("Quiting, not yet due for renewal, you can force renewal using --renew-early");
                    return Ok(());
                }
            }
        }
    }

    let signed = renew::request(&config, debug).await?;
    cert::write_combined(config.path, signed).wrap_err("Could not write out certificates")?;
    if let Some(service) = config.reload {
        systemd::systemctl(&["reload"], &service)
            .wrap_err_with(|| "Could not reload ".to_owned() + &service)?;
    }
    Ok(())
}

#[must_use]
fn exit_requested(config: &Config, question: &str) -> bool {
    use is_terminal::IsTerminal;
    if config.non_interactive || !std::io::stdin().is_terminal() {
        return true; // user cant confirm 
    }

    println!("{}", question);
    println!("Continue? y/n");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    if let Some('y') = buf.chars().next() {
        info!("Quiting, user requested exit");
        true
    } else {
        false
    }
}
