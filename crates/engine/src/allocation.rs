use std::alloc::Layout;
use std::sync::atomic::AtomicUsize;

use ariad_core::EngineError;

/// Charge retained payload capacity plus the boxed owner used by `Bytes::from_owner`.
pub(crate) fn retained_bytes_charge<T>(capacity_bytes: usize) -> Result<usize, EngineError> {
    // bytes 1.12.1 uses repr(C) Owned<T> { AtomicUsize, T }, even for empty payloads.
    // Recheck this allocation layout when updating bytes.
    let (owner_layout, _) = Layout::new::<AtomicUsize>()
        .extend(Layout::new::<T>())
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    capacity_bytes
        .checked_add(owner_layout.pad_to_align().size())
        .ok_or(EngineError::ResourceLimitExceeded)
}
