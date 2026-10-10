use ariad_core::{BindingId, Destination, EndpointDescriptor};
use ariad_engine::{SpkiPin, TrustPolicy};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const HOSTNAME: &str = "endpoint.test";
pub const TRUST_GROUP: u64 = 7;

pub fn tcp_destination() -> Destination {
    Destination::parse("1.1.1.1:443").expect("TCP destination")
}

pub fn endpoint(identity_hostname: &str, binding: BindingId) -> EndpointDescriptor {
    EndpointDescriptor {
        id: 1,
        generation: 1,
        identity_hostname: identity_hostname.to_owned(),
        trust_group: TRUST_GROUP,
        bindings: vec![binding],
        ech_required: false,
    }
}

pub struct CertificateFixture {
    root: CertificateDer<'static>,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    pub pin: SpkiPin,
}

impl CertificateFixture {
    /// Generates a new CA for each fixture. `expired` backdates only the leaf
    /// certificate; the CA retains its default validity period.
    pub fn new(expired: bool) -> Self {
        Self::with_subject_alt_name(
            expired,
            SanType::DnsName(HOSTNAME.try_into().expect("DNS name")),
        )
    }

    pub fn with_subject_alt_name(expired: bool, subject_alt_name: SanType) -> Self {
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_parameters =
            CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
        ca_parameters
            .distinguished_name
            .push(DnType::CommonName, "ARIAD test CA");
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_parameters.self_signed(&ca_key).expect("CA certificate");
        let key = KeyPair::generate().expect("server key");
        let mut parameters =
            CertificateParams::new(Vec::<String>::new()).expect("server parameters");
        parameters.subject_alt_names = vec![subject_alt_name];
        if expired {
            parameters.not_before = date_time_ymd(1975, 1, 1);
            parameters.not_after = date_time_ymd(2000, 1, 1);
        }
        let certificate = parameters
            .signed_by(&key, &ca, &ca_key)
            .expect("server certificate");
        let certificate = certificate.der().clone();
        let pin = SpkiPin::from_spki_der(&key.public_key_der()).expect("SPKI pin");
        Self {
            root: ca.der().clone(),
            certificate,
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            pin,
        }
    }

    pub fn policy(&self) -> TrustPolicy {
        TrustPolicy::from_der_roots(TRUST_GROUP, vec![self.root.as_ref().to_vec()])
            .expect("trust policy")
    }

    pub fn pinned_policy(&self) -> TrustPolicy {
        self.policy()
            .with_spki_pins(vec![self.pin])
            .expect("pin policy")
    }

    pub fn identity(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![self.certificate.clone(), self.root.clone()],
            self.key.clone_key(),
        )
    }
}
