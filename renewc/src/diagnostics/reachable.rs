use std::time::Duration;

use color_eyre::eyre::Context;
use color_eyre::{eyre, Help};
use reqwest::{Response, StatusCode};
use tracing::{debug, instrument};

use crate::config::Config;
use crate::renew::server::Http01Challenge;

const APP: &str = env!("CARGO_PKG_NAME");

async fn check_response(resp: Response, key_auth: &str, domain: &str) -> eyre::Result<()> {
    match resp.status() {
        StatusCode::OK => {
            let body_bytes = resp.bytes().await.unwrap();
            assert_eq!(body_bytes, key_auth.as_bytes());
            Ok(())
        }
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::NOT_FOUND => {
            Err(eyre::eyre!(
                "Could not reach {APP} via {domain}"
            ))
            .note("Another server is getting traffic for external port 80")
            .suggestion(format!("Check if port 80 is forwarded to a port on this machine. If it is configure {APP} to use that port with the `--port` option. If not forward port 80 to this machine")).with_local_ip_note()
        }
        other => Err(eyre::eyre!(
                "Got StatusCode {other}"
            )).wrap_err_with(|| format!("Could not reach {APP} via {domain}"))
            .note("Another server is getting traffic for external port 80")
            .suggestion(format!("Check if port 80 is forwarded to a port on this machine. If it is configure {APP} to use that port with the `--port` option. If not forward port 80 to this machine")).with_local_ip_note()
    }
}

#[instrument(ret, skip(key_auth, path))]
async fn check(path: &str, domain: &str, key_auth: &str) -> eyre::Result<()> {
    let url = format!("http://{domain}{path}");
    debug!("checking: {url}");
    let client = reqwest::Client::new();
    let get = client.get(&url).timeout(Duration::from_millis(250)).send();
    match get.await {
        Ok(resp) => check_response(resp, key_auth, domain).await,
        Err(e) if e.is_timeout() || e.is_connect() => {
            Err(eyre::eyre!("Could not reach {APP} via {domain}"))
                .suggestion("Forward port 80 to this machine")
                .with_local_ip_note()
        }
        Err(e) => unreachable!("unexpected reqwest error: {e:?}"),
    }
}

pub async fn server(config: &Config, challanges: &[Http01Challenge]) -> eyre::Result<()> {
    let Http01Challenge {
        token, key_auth, ..
    } = challanges
        .first()
        .expect("there is always one domain thus one challange");

    let path = format!("/.well-known/acme-challenge/{token}");
    // TODO: make this run concurrently <02-06-23>
    for domain in &config.domains {
        check(&path, domain, key_auth).await?;
    }

    Ok(())
}

trait WithLocalIp {
    fn with_local_ip_note(self) -> Self;
}

impl<T> WithLocalIp for eyre::Result<T> {
    fn with_local_ip_note(self) -> Self {
        match local_ip_address::local_ip() {
            Ok(ip) => self.with_note(|| format!("This machines local IP adress: {ip:?}")),
            Err(e) => self.with_warning(|| {
                format!("Failed to be helpfull and find this machines local IP error: {e:?}")
            }),
        }
    }
}
