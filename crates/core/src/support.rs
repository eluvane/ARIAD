#![forbid(unsafe_code)]

use crate::version::{H2_BINDING_VERSION, PROTOCOL_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    TestedLocal,
    DeclaredCi,
    Unsupported,
}

/// Return declared support status for an exact Rust target triple.
///
/// This lookup does not inspect the host environment or run a compatibility test.
pub fn target_class(name: &str) -> TargetClass {
    match name {
        "x86_64-pc-windows-msvc" => TargetClass::TestedLocal,
        "x86_64-unknown-linux-gnu" => TargetClass::DeclaredCi,
        _ => TargetClass::Unsupported,
    }
}

/// Compare protocol and H2-binding versions with this build's values.
///
/// Target support and profile or configuration revisions are independent of
/// this result.
pub fn wire_compatible(protocol: u16, h2_binding: u16) -> bool {
    protocol == PROTOCOL_VERSION.0 && h2_binding == H2_BINDING_VERSION.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_version_zero_is_compatible() {
        assert!(wire_compatible(0, 0));
        assert!(!wire_compatible(1, 0));
        assert!(!wire_compatible(0, 1));
    }

    #[test]
    fn mobile_targets_are_unsupported() {
        assert_eq!(
            target_class("x86_64-pc-windows-msvc"),
            TargetClass::TestedLocal
        );
        assert_eq!(
            target_class("x86_64-unknown-linux-gnu"),
            TargetClass::DeclaredCi
        );
        assert_eq!(target_class("aarch64-apple-ios"), TargetClass::Unsupported);
        assert_eq!(
            target_class("aarch64-linux-android"),
            TargetClass::Unsupported
        );
    }
}
