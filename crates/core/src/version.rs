#![forbid(unsafe_code)]

/// Wire protocol version, independent of the crate's package version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingVersion(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileRevision(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSchemaVersion(pub u16);

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(0);

pub const H2_BINDING_VERSION: BindingVersion = BindingVersion(0);

pub const DEFAULT_PROFILE_REVISION: ProfileRevision = ProfileRevision(0);

pub const CONFIG_SCHEMA_VERSION: ConfigSchemaVersion = ConfigSchemaVersion(0);
