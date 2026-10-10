#![forbid(unsafe_code)]

//! Sans-I/O state machines, protocol codecs and admission policies.
//!
//! Transport and host adapters perform network I/O and report its results to
//! these policies and state machines.

mod address;
mod association;
mod auth;
mod budget;
mod capability;
mod capsule;
mod cooldown;
mod core;
mod deadline;
mod egress;
mod endpoint;
mod epoch;
mod error;
mod event;
mod failure;
mod measure;
mod network;
mod path_select;
mod resource;
mod retry;
mod session;
mod stream;
mod support;
mod udp;
mod version;

pub use address::{Destination, normalize_ip};
pub use association::{AssociationEffect, AssociationInput, AssociationMachine, AssociationPhase};
pub use auth::{AuthzDecision, Credential};
pub use budget::{BudgetLimits, MemoryBudget, MemoryReservation, ScopedMemoryReservation};
pub use capability::{BindingId, CapabilitySet, DeliveryMode};
pub use capsule::{
    CapsuleDecoder, CapsuleRef, DATAGRAM_CAPSULE, OwnedCapsule, VarInt, datagram_max_payload,
    decode_capsule, decode_varint, encode_datagram_capsule, encode_http_datagram,
    split_http_datagram, wire_overhead,
};
pub use cooldown::{CooldownKey, CooldownTable, ScopedCooldownKey};
pub use core::{Core, CoreConfig};
pub use deadline::{DeadlineKind, child_deadline, lab_cap};
pub use egress::{EgressDecision, EgressDenyReason, decide_egress, validate_ip_target};
pub use endpoint::{EndpointAddressHints, EndpointDescriptor, MAX_ENDPOINT_ADDRESS_HINTS};
pub use epoch::NetworkEpoch;
pub use error::{EngineError, PublicFailure, RetryScope};
pub use event::{CoreInput, CoreOutput, FlowGeneration, FlowId};
pub use failure::{
    FailureClass, FailureScope, connect_failure_class, failure_scope, may_retry_other_endpoint,
    preferred_connect_error,
};
pub use measure::{FIELD_OBSERVATIONS, MeasureLog, MeasureOutcome, OBSERVED_ON, Sample, Scenario};
pub use network::{
    CandidateContext, candidate_cooled_in_epoch, cooled_flags, scoped_cooldown_key,
    select_attempts_for_epoch, select_for_epoch,
};
pub use path_select::{
    Candidate, MAX_CANDIDATE_ATTEMPTS, MAX_PARALLEL_CANDIDATES, SelectRequest, select_attempts,
    select_candidates,
};
pub use resource::{ResourceBudget, ResourceReservation, ScopedResourceReservation};
pub use retry::{RetryPolicy, RetryQuota, RetryQuotaPolicy, backoff_delay_ms};
pub use session::{SessionInput, SessionMachine, SessionPhase};
pub use stream::{StreamInput, StreamMachine, StreamPhase};
pub use support::{TargetClass, target_class, wire_compatible};
pub use udp::{DatagramAdmit, DatagramOutcome, PathChange, UdpAssociation, admit_datagram};
pub use version::{
    BindingVersion, CONFIG_SCHEMA_VERSION, ConfigSchemaVersion, DEFAULT_PROFILE_REVISION,
    H2_BINDING_VERSION, PROTOCOL_VERSION, ProfileRevision, ProtocolVersion,
};
