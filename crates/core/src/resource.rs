use crate::budget::{MemoryBudget, MemoryReservation, ScopedMemoryReservation};
use crate::error::EngineError;

/// Shared quota for admitted objects, independent of payload or allocation size.
/// Keep each reservation until its object is released. Clones share the count.
#[derive(Debug, Clone)]
pub struct ResourceBudget {
    count_budget: MemoryBudget,
}

/// Releases one admitted object count when dropped.
#[derive(Debug)]
#[must_use = "hold the reservation while the admitted resource is alive"]
pub struct ResourceReservation {
    reservation: MemoryReservation,
}

/// Releases one object count from each admitted quota when dropped.
#[derive(Debug)]
#[must_use = "hold the reservation while the admitted resource is alive"]
pub struct ScopedResourceReservation {
    reservation: ScopedMemoryReservation,
}

impl ResourceBudget {
    /// Sets the object count limit using [`MemoryBudget::new`] validation.
    pub fn new(limit: usize) -> Result<Self, EngineError> {
        Ok(Self {
            count_budget: MemoryBudget::new(limit)?,
        })
    }

    /// Admits one object under [`MemoryBudget::try_acquire`]'s quota rules.
    pub fn try_acquire(&self) -> Result<ResourceReservation, EngineError> {
        Ok(ResourceReservation {
            reservation: self.count_budget.try_acquire(1)?,
        })
    }

    /// Admits one object in both quotas under [`MemoryBudget::try_acquire_scoped`]'s rules.
    pub fn try_acquire_scoped(
        &self,
        session: &Self,
    ) -> Result<ScopedResourceReservation, EngineError> {
        Ok(ScopedResourceReservation {
            reservation: self
                .count_budget
                .try_acquire_scoped(&session.count_budget, 1)?,
        })
    }

    /// Returns a snapshot of admitted object count across all clones.
    pub fn used(&self) -> usize {
        self.count_budget.used()
    }

    pub fn limit(&self) -> usize {
        self.count_budget.limit()
    }
}

impl ResourceReservation {
    pub fn release(self) {
        self.reservation.release();
    }
}

impl ScopedResourceReservation {
    pub fn release(self) {
        self.reservation.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_object_limit_is_rejected() {
        assert_eq!(
            ResourceBudget::new(0).unwrap_err(),
            EngineError::InvalidConfig
        );
    }

    #[test]
    fn object_limit_is_shared_and_each_permit_releases_once() {
        let budget = ResourceBudget::new(2).unwrap();
        let clone = budget.clone();
        let first = budget.try_acquire().unwrap();
        let second = clone.try_acquire().unwrap();
        assert_eq!(budget.used(), 2);
        assert_eq!(budget.limit(), 2);
        assert_eq!(
            clone.try_acquire().unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        first.release();
        assert_eq!(clone.used(), 1);
        let replacement = clone.try_acquire().unwrap();
        drop(second);
        assert_eq!(budget.used(), 1);
        drop(replacement);
        assert_eq!(clone.used(), 0);
    }

    #[test]
    fn session_object_denial_does_not_leak_a_process_permit() {
        let process = ResourceBudget::new(2).unwrap();
        let session = ResourceBudget::new(1).unwrap();
        let retained = session.try_acquire().unwrap();
        assert_eq!(
            process.try_acquire_scoped(&session).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 1);
        drop(retained);
        let admitted = process.try_acquire_scoped(&session).unwrap();
        assert_eq!(process.used(), 1);
        assert_eq!(session.used(), 1);
        admitted.release();
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
    }

    #[test]
    fn dropping_scoped_object_permit_releases_both_scopes() {
        let process = ResourceBudget::new(1).unwrap();
        let session = ResourceBudget::new(1).unwrap();
        let admitted = process.try_acquire_scoped(&session).unwrap();
        drop(admitted);
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
        let process_only = process.try_acquire().unwrap();
        assert_eq!(
            process.try_acquire_scoped(&session).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        assert_eq!(session.used(), 0);
        drop(process_only);
    }

    #[test]
    fn scoped_object_aliases_charge_only_once() {
        let process = ResourceBudget::new(1).unwrap();
        let session = process.clone();
        let admitted = process.try_acquire_scoped(&session).unwrap();
        assert_eq!(process.used(), 1);
        assert_eq!(
            process.try_acquire().unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        drop(admitted);
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
    }
}
