#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::io::Write;

use cert::format::PemItem;
use cert::info::Info as CertInfo;
use color_eyre::eyre;

pub mod advise;
pub mod cert;
pub mod config;
pub mod diagnostics;
pub mod renew;

use advise::CheckResult;
pub use config::Config;
use owo_colors::OwoColorize;

/// during integration testing we do not want to hit lets encrypts backend
/// by passing the ACME implementation we can test other functionality.
pub trait ACME {
    #[allow(async_fn_in_trait)]
    async fn renew<P: PemItem, W: Write + Send>(
        &self,
        config: &Config,
        stdout: &mut W,
        debug: bool,
    ) -> eyre::Result<cert::Signed<P>>;
}

fn warn(stdout: &mut impl Write, s: &str) {
    let s = s.red().to_string() + "\n";
    stdout.write_all(s.as_bytes()).unwrap();
}

fn info(stdout: &mut impl Write, s: &str) {
    let s = s.green().to_string() + "\n";
    stdout.write_all(s.as_bytes()).unwrap();
}

pub async fn run<P: PemItem>(
    acme_impl: &mut impl ACME,
    stdout: &mut (impl Write + Send),
    config: &Config,
    debug: bool,
) -> eyre::Result<Option<cert::Signed<P>>> {
    if config.force {
        let signed = acme_impl.renew(config, stdout, debug).await?;
        return Ok(Some(signed));
    }

    match CertInfo::from_disk(config, stdout)
        .map(|cert| advise::given_existing(config, &cert, stdout))
    {
        Ok(CheckResult::Refuse {
            status: Some(status),
            warning,
        }) => {
            info(stdout, &status);
            warn(stdout, warning);
            return Ok(None);
        }
        Ok(CheckResult::Refuse {
            status: None,
            warning,
        }) => {
            warn(stdout, warning);
            return Ok(None);
        }
        Ok(CheckResult::Accept { status }) => {
            info(stdout, &status);
        }
        Ok(CheckResult::NoCert) => (),
        Ok(CheckResult::Warn { warning }) => warn(stdout, warning),
        Err(e) => {
            writeln!(stdout, "Warning: renew advise impossible").unwrap();
            for (i, err) in e.chain().enumerate() {
                advise::warn!(stdout, "   {i}: {err}");
            }
            writeln!(
                stdout,
                "Note: {}",
                "This might mean the previous certificate is corrupt or broken".blue()
            )
            .unwrap();
        }
    }

    let staging_config = Config {
        production: false,
        ..config.clone()
    };
    if config.production {
        info(
            stdout,
            "first checking if request can succeed by using staging environment",
        );
        let mut stdout = IndentedOut::new(stdout);
        let _: cert::Signed<P> = acme_impl.renew(&staging_config, &mut stdout, debug).await?;
    }
    let signed = acme_impl.renew(config, stdout, debug).await?;
    Ok(Some(signed))
}

struct IndentedOut<'a> {
    out: &'a mut (dyn Write + Send),
}

impl<'a> IndentedOut<'a> {
    fn new(out: &'a mut (dyn Write + Send)) -> Self {
        out.write("\t".as_bytes())
            .expect("out should support normal log amounts of data");
        Self { out }
    }
}

impl<'a> Write for IndentedOut<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf = String::from_utf8_lossy(buf).to_string();
        let indented = buf.replace("\n", "\n\t");
        self.out.write(indented.as_bytes())?;
        // if we return from write(indented) the returned len is larger then
        // what the calling code expects which can make it crash
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}
