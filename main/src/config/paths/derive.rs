use color_eyre::eyre;
use std::path::{Path, PathBuf};
use tracing::instrument;

#[instrument(level = "debug", ret)]
pub(crate) fn derive_path(cert_path: &Path, name: &str, ty: &str, extension: &str) -> PathBuf {
    dir(cert_path).join(&format!("{name}_{ty}")).with_extension(extension)
}

pub fn name(domains: &[impl AsRef<str>]) -> eyre::Result<String> {
    let shortest = domains
        .iter()
        .map(AsRef::as_ref)
        .min_by_key(|d| d.len())
        .unwrap();
    let last_dot = shortest
        .rfind('.')
        .ok_or_else(|| eyre::eyre!("shortest domain has no top level domain [org/net/com etc]"))?;
    let (name, _extension) = shortest.split_at(last_dot);
    if let Some(last_dot) = name.rfind('.') {
        let (_subdomains, name) = name.split_at(last_dot + 1);
        Ok(name.to_string())
    } else {
        Ok(name.to_string())
    }
}

pub(super) fn dir(cert_path: &Path) -> PathBuf {
    let dir = if cert_path.is_file() {
        cert_path
            .parent()
            .expect("is never none if parent was a file")
    } else {
        cert_path
    };

    dir.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_name() {
        let domains = [
            "example.org",
            "subdomain.example.org",
            "subsubdomain.subdomain.example.org",
            "another.example.org",
            "even_more.example.org",
            "a.nm.org",
            "subdomain.nm.org",
        ];

        assert_eq!(name(&domains).unwrap(), "nm");
    }
}
