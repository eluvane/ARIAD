use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use ariad_core::{CONFIG_SCHEMA_VERSION, Credential, Destination, EgressDecision, decide_egress};
use serde::Deserialize;

const MAX_CREDENTIAL_LEN: usize = Credential::HEX_LEN + 2;

const MAX_CONFIG_TEXT_LEN: usize = 64 * 1024;
const MAX_ALLOW_ENTRIES: usize = 256;

/// A local configuration read, syntax, or policy failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Invalid,
    EgressDenied,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    schema_version: u16,
    credential_file: PathBuf,
    allow_private: bool,
    #[serde(default = "default_principal")]
    principal: u64,
    allow: Vec<AllowEntry>,
}

fn default_principal() -> u64 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowEntry {
    host: String,
    port: u16,
}

struct CredentialFileBytes {
    bytes: [u8; MAX_CREDENTIAL_LEN],
    len: usize,
}

impl CredentialFileBytes {
    fn read(path: &Path) -> Result<Self, Reject> {
        let mut file = File::open(path).map_err(|_| Reject::Invalid)?;
        let mut contents = Self {
            bytes: [0u8; MAX_CREDENTIAL_LEN],
            len: 0,
        };
        loop {
            if contents.len == MAX_CREDENTIAL_LEN {
                let mut extra = [0u8; 1];
                let read = read_some(&mut file, &mut extra);
                wipe(&mut extra);
                if read? == 0 {
                    break;
                }
                return Err(Reject::Invalid);
            }
            let n = read_some(&mut file, &mut contents.bytes[contents.len..])?;
            if n == 0 {
                break;
            }
            contents.len = match contents.len.checked_add(n) {
                Some(len) if len <= MAX_CREDENTIAL_LEN => len,
                _ => return Err(Reject::Invalid),
            };
        }
        Ok(contents)
    }

    fn as_slice(&self) -> &[u8] {
        let end = self.len.min(self.bytes.len());
        &self.bytes[..end]
    }
}

impl Drop for CredentialFileBytes {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
        self.len = 0;
    }
}

struct WipedSecret {
    bytes: [u8; Credential::BYTE_LEN],
}

impl Drop for WipedSecret {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

/// One file configuration snapshot. `load` checks its fields at load time.
/// Later edits to the public fields do not repeat those checks.
pub struct LoadedConfig {
    secret: [u8; Credential::BYTE_LEN],
    pub principal: u64,
    pub allow_private: bool,
    pub allow: Vec<Destination>,
}

impl LoadedConfig {
    /// Copies the configured secret into an owned credential.
    pub fn credential(&self) -> Credential {
        Credential::from_bytes(self.secret)
    }
}

impl Drop for LoadedConfig {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

/// Validates both files using `load`, then drops the loaded configuration.
/// Domain entries are parsed without DNS resolution or a reachability check.
pub fn validate(config_path: &Path) -> Result<(), Reject> {
    load(config_path).map(|_| ())
}

/// Loads TOML limited to 64 KiB with 1..=256 exact host and port entries.
/// Relative credential paths use the configuration directory. The credential
/// must contain 64 hex digits, with at most one LF or CRLF suffix.
/// Literal IP entries must pass the configured egress policy. Domain entries
/// require address policy checks when resolved for a connection.
pub fn load(config_path: &Path) -> Result<LoadedConfig, Reject> {
    let text = read_config_text(config_path)?;
    let parsed: FileConfig = toml::from_str(&text).map_err(|_| Reject::Invalid)?;
    if parsed.schema_version != CONFIG_SCHEMA_VERSION.0
        || parsed.allow.is_empty()
        || parsed.allow.len() > MAX_ALLOW_ENTRIES
        || parsed.principal == 0
    {
        return Err(Reject::Invalid);
    }
    let mut secret = load_secret(config_path, &parsed.credential_file)?;
    let mut loaded = LoadedConfig {
        secret: secret.bytes,
        principal: parsed.principal,
        allow_private: parsed.allow_private,
        allow: Vec::new(),
    };
    wipe(&mut secret.bytes);
    loaded
        .allow
        .try_reserve_exact(parsed.allow.len())
        .map_err(|_| Reject::Invalid)?;
    for entry in &parsed.allow {
        loaded
            .allow
            .push(validate_allow_entry(parsed.allow_private, entry)?);
    }
    Ok(loaded)
}

fn read_config_text(path: &Path) -> Result<String, Reject> {
    let bytes = read_capped(path, MAX_CONFIG_TEXT_LEN)?;
    String::from_utf8(bytes).map_err(|_| Reject::Invalid)
}

fn read_capped(path: &Path, max_len: usize) -> Result<Vec<u8>, Reject> {
    let mut file = File::open(path).map_err(|_| Reject::Invalid)?;
    let mut data = Vec::new();
    data.try_reserve(max_len).map_err(|_| Reject::Invalid)?;
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let n = read_some(&mut file, &mut chunk)?;
        if n == 0 {
            return Ok(data);
        }
        if data.len().saturating_add(n) > max_len {
            return Err(Reject::Invalid);
        }
        data.extend_from_slice(&chunk[..n]);
    }
}

fn read_some(file: &mut File, buf: &mut [u8]) -> Result<usize, Reject> {
    loop {
        match file.read(buf) {
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(Reject::Invalid),
        }
    }
}

fn load_secret(config_path: &Path, credential_file: &Path) -> Result<WipedSecret, Reject> {
    let parent = config_path.parent().ok_or(Reject::Invalid)?;
    let path = parent.join(credential_file);
    let file_bytes = CredentialFileBytes::read(&path)?;
    let trimmed = trim_one_newline(file_bytes.as_slice());
    let mut secret = WipedSecret {
        bytes: [0u8; Credential::BYTE_LEN],
    };
    Credential::decode_hex(trimmed, &mut secret.bytes).map_err(|_| Reject::Invalid)?;
    Ok(secret)
}

fn validate_allow_entry(allow_private: bool, entry: &AllowEntry) -> Result<Destination, Reject> {
    let host = &entry.host;
    let port = entry.port;
    let rendered = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let destination = Destination::parse(&rendered).map_err(|_| Reject::Invalid)?;
    if let Some(ip) = destination.as_ip()
        && decide_egress(allow_private, ip) != EgressDecision::Allow
    {
        return Err(Reject::EgressDenied);
    }
    Ok(destination)
}

fn trim_one_newline(bytes: &[u8]) -> &[u8] {
    if let Some(without) = bytes.strip_suffix(b"\r\n") {
        without
    } else if let Some(without) = bytes.strip_suffix(b"\n") {
        without
    } else {
        bytes
    }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = 0;
    }
    std::hint::black_box(bytes);
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(prefix: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn credential_hex() -> String {
        "ab".repeat(Credential::BYTE_LEN)
    }

    pub(crate) fn config_text(allow_private: bool, entries: &str, extra: &str) -> String {
        let schema_version = CONFIG_SCHEMA_VERSION.0;
        format!(
            "schema_version = {schema_version}\ncredential_file = \"cred.hex\"\nallow_private = {allow_private}\nallow = [{entries}]\n{extra}"
        )
    }

    pub(crate) fn write_config(dir: &TempDir, text: &str, credential: &[u8]) -> PathBuf {
        std::fs::write(dir.path().join("cred.hex"), credential).unwrap();
        let config = dir.path().join("server.toml");
        std::fs::write(&config, text).unwrap();
        config
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{TempDir, credential_hex, write_config};
    use super::*;

    fn config_text(allow_private: bool, host: &str, extra: &str) -> String {
        test_support::config_text(
            allow_private,
            &format!("{{ host = \"{host}\", port = 443 }}"),
            extra,
        )
    }

    #[test]
    fn rejects_config_over_local_validate_limit() {
        let dir = TempDir::new("ariad-server-config");
        let mut text = config_text(false, "1.1.1.1", "");
        text.push_str(&" ".repeat(MAX_CONFIG_TEXT_LEN + 1 - text.len()));
        assert_eq!(text.len(), MAX_CONFIG_TEXT_LEN + 1);
        let config = write_config(&dir, &text, credential_hex().as_bytes());
        assert_eq!(validate(&config), Err(Reject::Invalid));
    }

    #[test]
    fn accepts_config_at_local_validate_limit() {
        let dir = TempDir::new("ariad-server-config");
        let mut text = config_text(false, "1.1.1.1", "");
        text.push_str(&" ".repeat(MAX_CONFIG_TEXT_LEN - text.len()));
        assert_eq!(text.len(), MAX_CONFIG_TEXT_LEN);
        let mut credential = credential_hex();
        credential.push('\n');
        let config = write_config(&dir, &text, credential.as_bytes());
        assert_eq!(validate(&config), Ok(()));
    }

    #[test]
    fn accepts_credential_hex_with_crlf_and_rejects_one_extra_byte() {
        let dir = TempDir::new("ariad-server-config");
        let text = config_text(false, "1.1.1.1", "");
        let mut credential = credential_hex();
        credential.push_str("\r\n");
        assert_eq!(credential.len(), MAX_CREDENTIAL_LEN);
        let config = write_config(&dir, &text, credential.as_bytes());
        assert_eq!(validate(&config), Ok(()));

        credential.push('\n');
        let config = write_config(&dir, &text, credential.as_bytes());
        assert_eq!(validate(&config), Err(Reject::Invalid));
    }

    #[test]
    fn credential_hex_keeps_case_and_single_newline_rules() {
        let dir = TempDir::new("ariad-server-credential");
        let text = config_text(false, "1.1.1.1", "");
        let hex = "aB".repeat(Credential::BYTE_LEN);
        for suffix in ["", "\n", "\r\n"] {
            let config = write_config(&dir, &text, format!("{hex}{suffix}").as_bytes());
            let loaded = load(&config).expect("mixed-case credential");
            assert!(
                loaded
                    .credential()
                    .verify(&Credential::from_bytes([0xab; Credential::BYTE_LEN]))
            );
        }
        for suffix in ["\r", "\n\n", " "] {
            let config = write_config(&dir, &text, format!("{hex}{suffix}").as_bytes());
            assert_eq!(validate(&config), Err(Reject::Invalid));
        }
    }

    #[test]
    fn empty_allow_bad_schema_unknown_field_and_bad_credential_are_invalid() {
        let dir = TempDir::new("ariad-server-config");
        let credential = credential_hex();
        let empty_allow = test_support::config_text(false, "", "");
        let config = write_config(&dir, &empty_allow, credential.as_bytes());
        assert_eq!(validate(&config), Err(Reject::Invalid));

        let bad_schema = config_text(false, "1.1.1.1", "").replacen(
            &format!("schema_version = {}", CONFIG_SCHEMA_VERSION.0),
            &format!(
                "schema_version = {}",
                CONFIG_SCHEMA_VERSION.0.wrapping_add(1)
            ),
            1,
        );
        let config = write_config(&dir, &bad_schema, credential.as_bytes());
        assert_eq!(validate(&config), Err(Reject::Invalid));

        let unknown = config_text(false, "1.1.1.1", "allow_all = true\n");
        let config = write_config(&dir, &unknown, credential.as_bytes());
        assert_eq!(validate(&config), Err(Reject::Invalid));

        let config = write_config(&dir, &config_text(false, "1.1.1.1", ""), b"zz\n");
        assert_eq!(validate(&config), Err(Reject::Invalid));
    }

    #[test]
    fn ip_outside_decide_egress_is_denied() {
        let dir = TempDir::new("ariad-server-config");
        let config = write_config(
            &dir,
            &config_text(false, "127.0.0.1", ""),
            credential_hex().as_bytes(),
        );
        assert_eq!(validate(&config), Err(Reject::EgressDenied));
    }

    #[test]
    fn principal_defaults_and_zero_principal_are_validated() {
        let dir = TempDir::new("ariad-server-config");
        let text = config_text(false, "1.1.1.1", "");
        let config = write_config(&dir, &text, credential_hex().as_bytes());
        assert_eq!(load(&config).expect("default principal").principal, 1);
        for (principal, valid) in [(0, false), (7, true)] {
            let text = config_text(false, "1.1.1.1", &format!("principal = {principal}\n"));
            let config = write_config(&dir, &text, credential_hex().as_bytes());
            assert_eq!(validate(&config).is_ok(), valid);
        }
    }

    #[test]
    fn domain_allow_is_exact_and_allow_entries_are_bounded() {
        let dir = TempDir::new("ariad-server-config");
        let text = config_text(false, "Example.COM", "");
        let config = write_config(&dir, &text, credential_hex().as_bytes());
        let loaded = load(&config).expect("domain");
        assert_eq!(
            loaded.allow,
            [Destination::parse("example.com:443").expect("target")]
        );
        let entries =
            std::iter::repeat_n("{ host = \"1.1.1.1\", port = 443 }", MAX_ALLOW_ENTRIES + 1)
                .collect::<Vec<_>>()
                .join(",");
        let text = test_support::config_text(false, &entries, "");
        let config = write_config(&dir, &text, credential_hex().as_bytes());
        assert_eq!(validate(&config), Err(Reject::Invalid));
    }

    #[test]
    fn non_utf8_config_is_invalid() {
        let dir = TempDir::new("ariad-server-config");
        let config = dir.path().join("server.toml");
        std::fs::write(&config, [0xff, 0xfe]).unwrap();
        assert_eq!(validate(&config), Err(Reject::Invalid));
    }
}
