use ariad_core::Credential;

pub fn credential() -> Credential {
    Credential::from_bytes([0x11; 32])
}
