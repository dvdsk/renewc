use std::fs;
use std::path::PathBuf;

use itertools::Itertools;
use rcgen::{Certificate, CertificateParams, IsCa};
use renewc::cert::format::{Label, PemItem};
use renewc::cert::Signed;
use tempfile::TempDir;
use time::OffsetDateTime;

fn ca_cert(is_staging: bool) -> Certificate {
    let subject_alt_names = if is_staging {
        vec!["STAGING.letsencrypt.org".to_string()]
    } else {
        vec!["letsencrypt.org".to_string()]
    };
    let mut params = CertificateParams::new(subject_alt_names);
    params.not_after = valid();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    Certificate::from_params(params).unwrap()
}

pub fn client_cert(valid_till: OffsetDateTime, domains: &[String]) -> Certificate {
    let mut params = CertificateParams::new(domains);
    params.not_after = valid_till;
    Certificate::from_params(params).unwrap()
}

/// returns a PEM encoded certificate chain of:
/// root cert, signed intermediate cert and signed client cert
pub fn generate_cert_with_chain<P: PemItem>(
    valid_till: OffsetDateTime,
    is_staging: bool,
    domains: &[String],
) -> Signed<P> {
    let root_ca_cert = ca_cert(is_staging);
    let root_ca = root_ca_cert.serialize_pem().unwrap();

    let intermediate_ca_cert = ca_cert(is_staging);
    let intermediate_ca = intermediate_ca_cert
        .serialize_pem_with_signer(&root_ca_cert)
        .unwrap();

    let client = client_cert(valid_till, domains);
    let client_cert = client
        .serialize_pem_with_signer(&intermediate_ca_cert)
        .unwrap();
    let client_key = client.serialize_private_key_pem();

    let root_ca = PemItem::from_pem(root_ca, Label::Certificate).unwrap();
    let intermediate_ca = PemItem::from_pem(intermediate_ca, Label::Certificate).unwrap();
    let chain = vec![intermediate_ca, root_ca];

    let client_cert = PemItem::from_pem(client_cert, Label::Certificate).unwrap();
    let client_key = PemItem::from_pem(client_key, Label::PrivateKey).unwrap();

    Signed {
        certificate: client_cert,
        private_key: client_key,
        chain,
    }
}

#[allow(dead_code)]
pub fn write_single_chain<P: PemItem>(dir: &TempDir, signed: Signed<P>) -> PathBuf {
    let path = dir.path().join("cert.pem");
    let bytes: Vec<u8> = Itertools::intersperse(
        signed.chain.iter().map(P::as_bytes),
        "\r\n".as_bytes().to_vec(),
    )
    .flatten()
    .collect();
    fs::write(&path, bytes).unwrap();
    path
}

pub fn valid() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(16_734_790_789).unwrap()
}

// not actually dead, modules in integration tests 
// give compile warnings if code is not used in each integration test file
#[allow(dead_code)] 
pub fn expired() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_683_145_489).unwrap()
}

