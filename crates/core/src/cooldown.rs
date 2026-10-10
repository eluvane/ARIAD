#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;

use crate::capability::BindingId;
use crate::epoch::NetworkEpoch;
use crate::error::EngineError;
use crate::failure::{FailureClass, FailureScope};

pub const MAX_COOLDOWN_MS: u64 = 60_000;
pub const MAX_COOLDOWN_ENTRIES: usize = 64;

/// An unscoped key, separate from every [`ScopedCooldownKey`] entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CooldownKey {
    pub scope: FailureScope,
    pub id: u64,
}

/// Every field participates in equality. Absent binding or address fields do
/// not act as wildcards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedCooldownKey {
    pub scope: FailureScope,
    pub id: u64,
    pub endpoint_generation: u64,
    pub binding: Option<BindingId>,
    pub address: Option<SocketAddr>,
    pub failure: FailureClass,
    pub network_epoch: NetworkEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableKey {
    Legacy(CooldownKey),
    Scoped(ScopedCooldownKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    key: TableKey,
    expires_at_ms: u64,
}

/// Bounded cooldowns in a caller-supplied millisecond clock domain.
/// Scoped and unscoped entries share capacity. Queries keep expired entries.
pub struct CooldownTable {
    entries: VecDeque<Entry>,
}

impl CooldownTable {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_COOLDOWN_ENTRIES),
        }
    }

    /// Counts stored entries, including expired entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes scoped entries from other epochs and keeps all unscoped entries.
    pub fn retain_epoch(&mut self, current: NetworkEpoch) {
        self.entries.retain(|entry| match entry.key {
            TableKey::Legacy(_) => true,
            TableKey::Scoped(key) => key.network_epoch == current,
        });
    }

    /// Sets or replaces the expiry at `now_ms + cooldown_ms`.
    /// Use the same clock domain for recording and lookup. Durations outside
    /// `1..=MAX_COOLDOWN_MS` return `InvalidConfig`. Expiry overflow returns
    /// `ResourceLimitExceeded`. At capacity, a new key replaces an expired
    /// entry or returns `ResourceLimitExceeded` if none is expired.
    /// Errors leave the table unchanged.
    pub fn record(
        &mut self,
        key: CooldownKey,
        now_ms: u64,
        cooldown_ms: u64,
    ) -> Result<(), EngineError> {
        self.record_key(TableKey::Legacy(key), now_ms, cooldown_ms)
    }

    /// Records a scoped key under [`Self::record`]'s rules.
    pub fn record_scoped(
        &mut self,
        key: ScopedCooldownKey,
        now_ms: u64,
        cooldown_ms: u64,
    ) -> Result<(), EngineError> {
        self.record_key(TableKey::Scoped(key), now_ms, cooldown_ms)
    }

    fn record_key(
        &mut self,
        key: TableKey,
        now_ms: u64,
        cooldown_ms: u64,
    ) -> Result<(), EngineError> {
        if cooldown_ms == 0 || cooldown_ms > MAX_COOLDOWN_MS {
            return Err(EngineError::InvalidConfig);
        }
        let expires_at_ms = now_ms
            .checked_add(cooldown_ms)
            .ok_or(EngineError::ResourceLimitExceeded)?;
        if let Some(existing) = self.entries.iter_mut().find(|entry| entry.key == key) {
            existing.expires_at_ms = expires_at_ms;
            return Ok(());
        }
        if self.entries.len() == MAX_COOLDOWN_ENTRIES {
            let Some(expired_index) = self
                .entries
                .iter()
                .position(|entry| now_ms >= entry.expires_at_ms)
            else {
                return Err(EngineError::ResourceLimitExceeded);
            };
            self.entries.remove(expired_index);
        }
        self.entries.push_back(Entry { key, expires_at_ms });
        Ok(())
    }

    /// Returns true while the unscoped key is under cooldown, excluding its expiry.
    pub fn cooled(&self, key: CooldownKey, now_ms: u64) -> bool {
        self.cooled_key(TableKey::Legacy(key), now_ms)
    }

    /// Uses [`Self::cooled`]'s expiry rule for an exact scoped key.
    pub fn cooled_scoped(&self, key: ScopedCooldownKey, now_ms: u64) -> bool {
        self.cooled_key(TableKey::Scoped(key), now_ms)
    }

    fn cooled_key(&self, key: TableKey, now_ms: u64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.key == key && now_ms < entry.expires_at_ms)
    }
}

impl Default for CooldownTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_expires_and_stays_bounded() {
        let mut table = CooldownTable::new();
        let key = CooldownKey {
            scope: FailureScope::Candidate,
            id: 7,
        };
        table.record(key, 1_000, 50).unwrap();
        assert!(table.cooled(key, 1_049));
        assert!(!table.cooled(key, 1_050));
        for id in 0..MAX_COOLDOWN_ENTRIES {
            table
                .record(
                    CooldownKey {
                        scope: FailureScope::Candidate,
                        id: u64::try_from(id).unwrap(),
                    },
                    0,
                    10,
                )
                .unwrap();
        }
        assert_eq!(table.len(), MAX_COOLDOWN_ENTRIES);
        assert_eq!(
            table.record(
                CooldownKey {
                    scope: FailureScope::Candidate,
                    id: 10_000,
                },
                0,
                10,
            ),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert!(table.cooled(
            CooldownKey {
                scope: FailureScope::Candidate,
                id: 0,
            },
            0,
        ));
        assert_eq!(
            table.record(
                CooldownKey {
                    scope: FailureScope::Candidate,
                    id: 10_000,
                },
                10,
                10,
            ),
            Ok(())
        );
        assert!(!table.cooled(
            CooldownKey {
                scope: FailureScope::Candidate,
                id: 0,
            },
            10,
        ));
    }

    #[test]
    fn zero_or_huge_cooldown_is_rejected() {
        let mut table = CooldownTable::new();
        let key = CooldownKey {
            scope: FailureScope::Endpoint,
            id: 1,
        };
        assert_eq!(table.record(key, 0, 0), Err(EngineError::InvalidConfig));
        assert_eq!(
            table.record(key, 0, MAX_COOLDOWN_MS + 1),
            Err(EngineError::InvalidConfig)
        );
        assert!(table.is_empty());
    }

    #[test]
    fn scoped_cooldown_separates_binding_failure_address_and_epoch() {
        let mut table = CooldownTable::new();
        let key = ScopedCooldownKey {
            scope: FailureScope::Candidate,
            id: 1,
            endpoint_generation: 1,
            binding: Some(BindingId::H2),
            address: Some("127.0.0.1:443".parse().unwrap()),
            failure: FailureClass::CandidateTransport,
            network_epoch: NetworkEpoch::start(),
        };
        table.record_scoped(key, 0, 1_000).unwrap();
        assert!(table.cooled_scoped(key, 1));
        for different in [
            ScopedCooldownKey {
                binding: Some(BindingId::H3),
                ..key
            },
            ScopedCooldownKey {
                failure: FailureClass::PeerTrust,
                ..key
            },
            ScopedCooldownKey {
                address: Some("127.0.0.2:443".parse().unwrap()),
                ..key
            },
            ScopedCooldownKey {
                endpoint_generation: 2,
                ..key
            },
            ScopedCooldownKey {
                network_epoch: key.network_epoch.advance().unwrap(),
                ..key
            },
        ] {
            assert!(!table.cooled_scoped(different, 1));
        }
        assert!(!table.cooled(
            CooldownKey {
                scope: key.scope,
                id: key.id
            },
            1
        ));
        assert!(!table.cooled_scoped(key, 1_000));
    }

    #[test]
    fn legacy_and_scoped_entries_share_one_capacity() {
        let mut table = CooldownTable::new();
        for id in 0..MAX_COOLDOWN_ENTRIES {
            table
                .record(
                    CooldownKey {
                        scope: FailureScope::Endpoint,
                        id: u64::try_from(id).unwrap(),
                    },
                    0,
                    10,
                )
                .unwrap();
        }
        let key = ScopedCooldownKey {
            scope: FailureScope::Endpoint,
            id: 100,
            endpoint_generation: 1,
            binding: None,
            address: None,
            failure: FailureClass::EndpointDns,
            network_epoch: NetworkEpoch::start(),
        };
        assert_eq!(
            table.record_scoped(key, 0, 10),
            Err(EngineError::ResourceLimitExceeded)
        );
        table.record_scoped(key, 10, 10).unwrap();
        assert_eq!(table.len(), MAX_COOLDOWN_ENTRIES);
    }
}
