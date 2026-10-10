#![forbid(unsafe_code)]

use ariad_core::{
    DATAGRAM_CAPSULE, EngineError, decode_capsule, encode_datagram_capsule, encode_http_datagram,
    split_http_datagram,
};

const HTTP_DATAGRAMS: &str = include_str!("../../../tests/vectors/http-datagram-v0.txt");
const DATAGRAM_CAPSULES: &str = include_str!("../../../tests/vectors/datagram-capsule-v0.txt");

struct Vector<'a> {
    name: &'a str,
    context_id: u64,
    payload: Vec<u8>,
    wire: Vec<u8>,
}

fn vectors(input: &str) -> impl Iterator<Item = Vector<'_>> {
    input.lines().map(|line| {
        let mut fields = line.split('|');
        let name = fields.next().expect("vector name");
        let context_id = fields
            .next()
            .expect("context")
            .parse()
            .expect("context number");
        let payload = decode_hex(fields.next().expect("payload"));
        let wire = decode_hex(fields.next().expect("wire"));
        assert!(fields.next().is_none(), "extra vector field: {name}");
        Vector {
            name,
            context_id,
            payload,
            wire,
        }
    })
}

fn decode_hex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    assert_eq!(value.len() % 2, 0, "odd hex length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex text");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}

#[test]
fn http_datagrams_match_literal_wire_vectors() {
    for vector in vectors(HTTP_DATAGRAMS) {
        assert_eq!(
            encode_http_datagram(vector.context_id, &vector.payload).expect("encode"),
            vector.wire,
            "{}",
            vector.name
        );
        let (context_id, payload) = split_http_datagram(&vector.wire).expect("decode");
        assert_eq!(context_id, vector.context_id, "{}", vector.name);
        assert_eq!(payload, vector.payload, "{}", vector.name);
    }
}

#[test]
fn datagram_capsules_match_literal_wire_vectors() {
    for vector in vectors(DATAGRAM_CAPSULES) {
        assert_eq!(
            encode_datagram_capsule(vector.context_id, &vector.payload).expect("encode"),
            vector.wire,
            "{}",
            vector.name
        );
        let (capsule, consumed_bytes) = decode_capsule(&vector.wire, 128).expect("decode");
        assert_eq!(capsule.kind, DATAGRAM_CAPSULE, "{}", vector.name);
        assert_eq!(consumed_bytes, vector.wire.len(), "{}", vector.name);
        let (context_id, payload) = split_http_datagram(capsule.value).expect("datagram");
        assert_eq!(context_id, vector.context_id, "{}", vector.name);
        assert_eq!(payload, vector.payload, "{}", vector.name);
    }
}

#[test]
fn every_truncated_capsule_vector_is_rejected() {
    for vector in vectors(DATAGRAM_CAPSULES) {
        for end in 0..vector.wire.len() {
            assert_eq!(
                decode_capsule(&vector.wire[..end], 128),
                Err(EngineError::ProtocolViolation),
                "{} truncated at {end}",
                vector.name
            );
        }
        let (capsule, _) = decode_capsule(&vector.wire, 128).expect("complete");
        let header_bytes = vector.wire.len() - capsule.value.len();
        assert_eq!(
            decode_capsule(&vector.wire[..header_bytes], capsule.value.len() - 1),
            Err(EngineError::MessageTooLarge),
            "{} oversized claim",
            vector.name
        );
    }
}

#[test]
fn consecutive_capsules_preserve_message_boundaries() {
    let expected: Vec<_> = vectors(DATAGRAM_CAPSULES).collect();
    let wire: Vec<_> = expected
        .iter()
        .flat_map(|vector| vector.wire.iter().copied())
        .collect();
    let mut wire_offset = 0;
    for vector in expected {
        let (capsule, consumed_bytes) = decode_capsule(&wire[wire_offset..], 128).expect("capsule");
        assert_eq!(consumed_bytes, vector.wire.len(), "{}", vector.name);
        let (context_id, payload) = split_http_datagram(capsule.value).expect("datagram");
        assert_eq!(context_id, vector.context_id, "{}", vector.name);
        assert_eq!(payload, vector.payload, "{}", vector.name);
        wire_offset += consumed_bytes;
    }
    assert_eq!(wire_offset, wire.len());
}

#[test]
fn short_varint_corpus_has_exact_payload_boundaries() {
    assert_eq!(
        split_http_datagram(&[]),
        Err(EngineError::ProtocolViolation)
    );
    for first in 0u8..=255 {
        for second in 0u8..=255 {
            let input = [first, second];
            match first {
                0..=63 => {
                    assert_eq!(
                        split_http_datagram(&input),
                        Ok((u64::from(first), &input[1..]))
                    );
                }
                64..=127 => {
                    let expected = (u64::from(first - 64) << 8) | u64::from(second);
                    assert_eq!(split_http_datagram(&input), Ok((expected, &input[2..])));
                    assert_eq!(
                        split_http_datagram(&input[..1]),
                        Err(EngineError::ProtocolViolation)
                    );
                }
                128..=255 => {
                    assert_eq!(
                        split_http_datagram(&input),
                        Err(EngineError::ProtocolViolation)
                    );
                }
            }
        }
    }
}

#[test]
fn nonminimal_varints_remain_valid_without_consuming_payload() {
    for prefix in [
        vec![0],
        vec![0x40, 0],
        vec![0x80, 0, 0, 0],
        vec![0xc0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        let mut input = prefix;
        input.extend_from_slice(b"payload");
        assert_eq!(split_http_datagram(&input), Ok((0, b"payload".as_slice())));
    }
}

#[test]
fn maximum_claimed_length_and_truncated_context_fail_explicitly() {
    assert_eq!(
        decode_capsule(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 128),
        Err(EngineError::MessageTooLarge)
    );
    let (capsule, consumed) = decode_capsule(&[0, 1, 0x40], 128).expect("outer capsule");
    assert_eq!(consumed, 3);
    assert_eq!(
        split_http_datagram(capsule.value),
        Err(EngineError::ProtocolViolation)
    );
    for context in [1u64 << 62, u64::MAX] {
        assert_eq!(
            encode_http_datagram(context, b"x"),
            Err(EngineError::MessageTooLarge)
        );
        assert_eq!(
            encode_datagram_capsule(context, b"x"),
            Err(EngineError::MessageTooLarge)
        );
    }
}
