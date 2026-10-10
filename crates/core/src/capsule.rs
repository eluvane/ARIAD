#![forbid(unsafe_code)]

use crate::error::EngineError;

pub const DATAGRAM_CAPSULE: u64 = 0;

const MAX_VARINT: u64 = (1 << 62) - 1;

/// A QUIC variable-length integer encoded in 1, 2, 4, or 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt {
    bytes: [u8; VarInt::MAX_ENCODED_LEN],
    encoded_len: u8,
}

impl VarInt {
    /// Maximum encoding length in bytes, including nonminimal encodings.
    pub const MAX_ENCODED_LEN: usize = 8;

    /// Uses the shortest encoding. Values above `2^62 - 1` return `MessageTooLarge`.
    pub fn encode(value: u64) -> Result<Self, EngineError> {
        if value > MAX_VARINT {
            return Err(EngineError::MessageTooLarge);
        }
        let length_prefix = if value < 1 << 6 {
            0u8
        } else if value < 1 << 14 {
            0x40
        } else if value < 1 << 30 {
            0x80
        } else {
            0xc0
        };
        let encoded_len = varint_encoded_len(length_prefix);
        let value_bytes = value.to_be_bytes();
        let mut bytes = [0u8; Self::MAX_ENCODED_LEN];
        bytes[..encoded_len].copy_from_slice(&value_bytes[value_bytes.len() - encoded_len..]);
        bytes[0] |= length_prefix;
        Ok(Self {
            bytes,
            encoded_len: u8::try_from(encoded_len).map_err(|_| EngineError::MessageTooLarge)?,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.encoded_len)]
    }
}

fn varint_encoded_len(first: u8) -> usize {
    1usize << (first >> 6)
}

/// Returns the leading QUIC varint and the unconsumed input suffix.
/// Nonminimal encodings are accepted. Empty or truncated input returns `ProtocolViolation`.
pub fn decode_varint(input: &[u8]) -> Result<(u64, &[u8]), EngineError> {
    let Some((first, _)) = input.split_first() else {
        return Err(EngineError::ProtocolViolation);
    };
    let encoded_len = varint_encoded_len(*first);
    if input.len() < encoded_len {
        return Err(EngineError::ProtocolViolation);
    }
    let mut value_bytes = [0u8; std::mem::size_of::<u64>()];
    let value_offset = value_bytes.len() - encoded_len;
    value_bytes[value_offset..].copy_from_slice(&input[..encoded_len]);
    value_bytes[value_offset] &= 0x3f;
    let value = u64::from_be_bytes(value_bytes);
    Ok((value, &input[encoded_len..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleRef<'a> {
    pub kind: u64,
    pub value: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct OwnedCapsule {
    pub kind: u64,
    /// `CapsuleDecoder` skips unknown capsule values and returns an empty buffer.
    pub value: Vec<u8>,
}

/// Incremental capsule framing with a bounded value length.
/// Only DATAGRAM values are retained; unknown capsule values are skipped.
pub struct CapsuleDecoder {
    max_value_bytes: usize,
    varint_bytes: [u8; VarInt::MAX_ENCODED_LEN],
    buffered_varint_bytes: usize,
    kind: Option<u64>,
    length_read: bool,
    remaining_value_bytes: usize,
    buffered_value: Vec<u8>,
    failed: bool,
}

impl CapsuleDecoder {
    /// Sets the maximum capsule value length in bytes. Zero returns `InvalidConfig`.
    pub fn new(max_value: usize) -> Result<Self, EngineError> {
        if max_value == 0 {
            return Err(EngineError::InvalidConfig);
        }
        Ok(Self {
            max_value_bytes: max_value,
            varint_bytes: [0; VarInt::MAX_ENCODED_LEN],
            buffered_varint_bytes: 0,
            kind: None,
            length_read: false,
            remaining_value_bytes: 0,
            buffered_value: Vec::new(),
            failed: false,
        })
    }

    /// Consumes at most one capsule and returns the consumed byte count.
    /// Incomplete headers and values are retained for the next call.
    ///
    /// Calls `before_allocate` once for each nonempty DATAGRAM value, after
    /// checking its claimed length and before reserving storage. The argument
    /// is the claimed byte length; the resulting capacity may be larger.
    /// The caller retains its reservation through decoding and the returned
    /// value's lifetime, and accounts for the actual capacity.
    ///
    /// Any returned error releases the buffered value and poisons the decoder.
    /// Later `feed` and `finish` calls return `ProtocolViolation` until `clear`.
    /// Callback effects remain the caller's responsibility after failure.
    pub fn feed<F>(
        &mut self,
        input: &[u8],
        mut before_allocate: F,
    ) -> Result<(usize, Option<OwnedCapsule>), EngineError>
    where
        F: FnMut(usize) -> Result<(), EngineError>,
    {
        if self.failed {
            return Err(EngineError::ProtocolViolation);
        }
        let result = self.feed_inner(input, &mut before_allocate);
        if result.is_err() {
            self.failed = true;
            self.buffered_value = Vec::new();
        }
        result
    }

    /// Checks for a complete capsule boundary without changing state.
    /// Incomplete input returns `TruncatedStream`; a poisoned decoder returns
    /// `ProtocolViolation`.
    pub fn finish(&self) -> Result<(), EngineError> {
        if self.failed {
            Err(EngineError::ProtocolViolation)
        } else if self.kind.is_some() || self.length_read || self.buffered_varint_bytes != 0 {
            Err(EngineError::TruncatedStream)
        } else {
            Ok(())
        }
    }

    /// Discards partial input and its value allocation, and clears the failed state.
    pub fn clear(&mut self) {
        self.buffered_varint_bytes = 0;
        self.kind = None;
        self.length_read = false;
        self.remaining_value_bytes = 0;
        self.buffered_value = Vec::new();
        self.failed = false;
    }

    fn feed_inner<F>(
        &mut self,
        input: &[u8],
        before_allocate: &mut F,
    ) -> Result<(usize, Option<OwnedCapsule>), EngineError>
    where
        F: FnMut(usize) -> Result<(), EngineError>,
    {
        let mut consumed_bytes = 0;
        if self.kind.is_none() {
            let Some(kind) = self.read_varint(input, &mut consumed_bytes)? else {
                return Ok((consumed_bytes, None));
            };
            self.kind = Some(kind);
        }
        if !self.length_read {
            let Some(claimed_value_len) = self.read_varint(input, &mut consumed_bytes)? else {
                return Ok((consumed_bytes, None));
            };
            let value_len = bounded_value_len(claimed_value_len, self.max_value_bytes)?;
            if self.kind == Some(DATAGRAM_CAPSULE) && value_len != 0 {
                before_allocate(value_len)?;
                self.buffered_value
                    .try_reserve_exact(value_len)
                    .map_err(|_| EngineError::ResourceLimitExceeded)?;
            }
            self.length_read = true;
            self.remaining_value_bytes = value_len;
        }
        let value_chunk_len = input
            .len()
            .saturating_sub(consumed_bytes)
            .min(self.remaining_value_bytes);
        if self.kind == Some(DATAGRAM_CAPSULE) {
            self.buffered_value
                .extend_from_slice(&input[consumed_bytes..consumed_bytes + value_chunk_len]);
        }
        consumed_bytes += value_chunk_len;
        self.remaining_value_bytes -= value_chunk_len;
        if self.remaining_value_bytes != 0 {
            return Ok((consumed_bytes, None));
        }
        let kind = self.kind.take().ok_or(EngineError::ProtocolViolation)?;
        self.length_read = false;
        Ok((
            consumed_bytes,
            Some(OwnedCapsule {
                kind,
                value: std::mem::take(&mut self.buffered_value),
            }),
        ))
    }

    fn read_varint(
        &mut self,
        input: &[u8],
        consumed_bytes: &mut usize,
    ) -> Result<Option<u64>, EngineError> {
        while *consumed_bytes < input.len() {
            self.varint_bytes[self.buffered_varint_bytes] = input[*consumed_bytes];
            self.buffered_varint_bytes += 1;
            *consumed_bytes += 1;
            let encoded_len = varint_encoded_len(self.varint_bytes[0]);
            if self.buffered_varint_bytes == encoded_len {
                let (value, _) = decode_varint(&self.varint_bytes[..encoded_len])?;
                self.buffered_varint_bytes = 0;
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}

/// Returns the largest payload byte length whose encoding fits `wire_limit`.
/// `native` selects HTTP datagram framing; otherwise DATAGRAM capsule framing
/// is included. Unencodable context IDs or framing sizes, size overflow, and
/// limits too small for empty framing return `MessageTooLarge`.
pub fn datagram_max_payload(
    native: bool,
    context_id: u64,
    wire_limit: usize,
) -> Result<usize, EngineError> {
    if wire_overhead(native, context_id, 0)? > wire_limit {
        return Err(EngineError::MessageTooLarge);
    }
    let mut low = 0;
    let mut high = wire_limit;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let encoded_bytes = middle
            .checked_add(wire_overhead(native, context_id, middle)?)
            .ok_or(EngineError::MessageTooLarge)?;
        if encoded_bytes <= wire_limit {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Ok(low)
}

/// Borrows one complete capsule and returns its total consumed byte count.
/// `max_value` bounds the value bytes, excluding the kind and length fields.
/// A zero limit accepts only empty values.
/// An oversized claim returns `MessageTooLarge` before checking value availability.
/// Truncated headers or values return `ProtocolViolation`.
pub fn decode_capsule(
    input: &[u8],
    max_value: usize,
) -> Result<(CapsuleRef<'_>, usize), EngineError> {
    let input_len = input.len();
    let (kind, after_kind) = decode_varint(input)?;
    let (length, after_length) = decode_varint(after_kind)?;
    let length = bounded_value_len(length, max_value)?;
    if after_length.len() < length {
        return Err(EngineError::ProtocolViolation);
    }
    let value = &after_length[..length];
    let consumed_bytes = input_len - after_length.len() + length;
    Ok((CapsuleRef { kind, value }, consumed_bytes))
}

fn bounded_value_len(claimed_len: u64, max_value: usize) -> Result<usize, EngineError> {
    let length = usize::try_from(claimed_len).map_err(|_| EngineError::MessageTooLarge)?;
    if length > max_value {
        return Err(EngineError::MessageTooLarge);
    }
    Ok(length)
}

/// Separates the context ID from the payload with [`decode_varint`].
pub fn split_http_datagram(value: &[u8]) -> Result<(u64, &[u8]), EngineError> {
    decode_varint(value)
}

/// Returns framing bytes excluding the payload: the context ID for native
/// datagrams, plus capsule kind and length fields for capsule framing.
/// Unencodable context IDs or capsule lengths return `MessageTooLarge`.
pub fn wire_overhead(
    native: bool,
    context_id: u64,
    payload_len: usize,
) -> Result<usize, EngineError> {
    let context_bytes = VarInt::encode(context_id)?.as_slice().len();
    if native {
        return Ok(context_bytes);
    }
    let value_len = context_bytes
        .checked_add(payload_len)
        .ok_or(EngineError::MessageTooLarge)?;
    let [kind, length] = datagram_capsule_header(value_len)?;
    let length_bytes = length.as_slice().len();
    let kind_bytes = kind.as_slice().len();
    kind_bytes
        .checked_add(length_bytes)
        .and_then(|header_bytes| header_bytes.checked_add(context_bytes))
        .ok_or(EngineError::MessageTooLarge)
}

/// Allocates a context ID followed by the payload. No path payload limit is checked.
/// Unencodable context IDs or size overflow return `MessageTooLarge`; allocation
/// failure returns `ResourceLimitExceeded`.
pub fn encode_http_datagram(context_id: u64, payload: &[u8]) -> Result<Vec<u8>, EngineError> {
    encode_datagram(context_id, payload, true)
}

/// Allocates a DATAGRAM capsule containing a context ID and the payload.
/// No path payload limit is checked. Unencodable values or size overflow return
/// `MessageTooLarge`; allocation failure returns `ResourceLimitExceeded`.
pub fn encode_datagram_capsule(context_id: u64, payload: &[u8]) -> Result<Vec<u8>, EngineError> {
    encode_datagram(context_id, payload, false)
}

fn encode_datagram(context_id: u64, payload: &[u8], native: bool) -> Result<Vec<u8>, EngineError> {
    let context = VarInt::encode(context_id)?;
    let value_len = context
        .as_slice()
        .len()
        .checked_add(payload.len())
        .ok_or(EngineError::MessageTooLarge)?;
    let capsule_header = if native {
        None
    } else {
        Some(datagram_capsule_header(value_len)?)
    };
    let mut encoded_len = value_len;
    if let Some(header) = &capsule_header {
        for field in header {
            encoded_len = encoded_len
                .checked_add(field.as_slice().len())
                .ok_or(EngineError::MessageTooLarge)?;
        }
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    if let Some(header) = capsule_header {
        for field in header {
            encoded.extend_from_slice(field.as_slice());
        }
    }
    encoded.extend_from_slice(context.as_slice());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn datagram_capsule_header(value_len: usize) -> Result<[VarInt; 2], EngineError> {
    Ok([
        VarInt::encode(DATAGRAM_CAPSULE)?,
        VarInt::encode(u64::try_from(value_len).map_err(|_| EngineError::MessageTooLarge)?)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_boundaries() {
        for value in [0u64, 63, 64, 16_383, 16_384, MAX_VARINT] {
            let encoded = VarInt::encode(value).unwrap();
            let (decoded, rest) = decode_varint(encoded.as_slice()).unwrap();
            assert_eq!(decoded, value);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn huge_claimed_capsule_does_not_need_a_buffer() {
        let mut input = Vec::new();
        input.extend_from_slice(VarInt::encode(0).unwrap().as_slice());
        input.extend_from_slice(VarInt::encode(1_000_000).unwrap().as_slice());
        input.extend_from_slice(&[1, 2, 3]);
        assert!(input.len() < 1_000_000);
        let decoded = decode_capsule(&input, 64);
        let buffer = decoded.as_ref().ok().map(|(capsule, _)| capsule.value);
        assert!(buffer.is_none());
        assert_eq!(decoded, Err(EngineError::MessageTooLarge));
    }

    #[test]
    fn truncated_capsule_is_not_a_short_payload() {
        let mut input = Vec::new();
        input.extend_from_slice(VarInt::encode(0).unwrap().as_slice());
        input.extend_from_slice(VarInt::encode(4).unwrap().as_slice());
        input.extend_from_slice(&[9, 9]);
        assert_eq!(
            decode_capsule(&input, 64),
            Err(EngineError::ProtocolViolation)
        );
    }

    #[test]
    fn zero_value_limit_accepts_only_empty_borrowed_capsules() {
        assert_eq!(
            decode_capsule(&[0, 0], 0),
            Ok((
                CapsuleRef {
                    kind: DATAGRAM_CAPSULE,
                    value: &[],
                },
                2,
            ))
        );
        assert_eq!(
            decode_capsule(&[0, 1], 0),
            Err(EngineError::MessageTooLarge)
        );
        assert_eq!(
            CapsuleDecoder::new(0).err(),
            Some(EngineError::InvalidConfig)
        );
    }

    #[test]
    fn datagram_capsule_round_trips_the_payload() {
        let encoded = encode_datagram_capsule(0, b"ping").unwrap();
        let (capsule, consumed) = decode_capsule(&encoded, 64).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(capsule.kind, DATAGRAM_CAPSULE);
        let (context, payload) = split_http_datagram(capsule.value).unwrap();
        assert_eq!(context, 0);
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn incremental_capsules_preserve_every_chunk_boundary() {
        let first = encode_datagram_capsule(0, b"first").unwrap();
        let second = encode_datagram_capsule(0, &[3; 80]).unwrap();
        let wire: Vec<u8> = first.into_iter().chain(second).collect();
        for chunk_size in 1..=wire.len() {
            let mut decoder = CapsuleDecoder::new(128).unwrap();
            let mut allocation_requests = Vec::new();
            let mut capsule_values = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                let mut offset = 0;
                while offset < chunk.len() {
                    let (consumed_bytes, capsule) = decoder
                        .feed(&chunk[offset..], |value_bytes| {
                            allocation_requests.push(value_bytes);
                            Ok(())
                        })
                        .unwrap();
                    assert!(consumed_bytes > 0);
                    offset += consumed_bytes;
                    if let Some(capsule) = capsule {
                        capsule_values.push(capsule.value);
                    }
                }
            }
            decoder.finish().unwrap();
            assert_eq!(allocation_requests, [6, 81]);
            assert_eq!(capsule_values[0], b"\0first");
            assert_eq!(capsule_values[1], [vec![0], vec![3; 80]].concat());
        }
    }

    #[test]
    fn unknown_capsule_values_are_skipped_without_allocation() {
        let mut decoder = CapsuleDecoder::new(128).unwrap();
        let (used, value) = decoder
            .feed(&[9, 4, 1, 2], |_| panic!("unknown allocation"))
            .unwrap();
        assert_eq!(used, 4);
        assert!(value.is_none());
        assert_eq!(decoder.finish(), Err(EngineError::TruncatedStream));
        let (used, value) = decoder
            .feed(&[3, 4, 0, 1, 0], |_| panic!("unknown allocation"))
            .unwrap();
        assert_eq!(used, 2);
        assert_eq!(
            value,
            Some(OwnedCapsule {
                kind: 9,
                value: Vec::new()
            })
        );
        decoder.finish().unwrap();
    }

    #[test]
    fn empty_capsules_do_not_consume_following_capsules() {
        for kind in [DATAGRAM_CAPSULE, 9] {
            let input = [u8::try_from(kind).unwrap(), 0, 0, 1, 0];
            let mut decoder = CapsuleDecoder::new(8).unwrap();
            let (consumed, capsule) = decoder
                .feed(&input, |_| panic!("empty allocation"))
                .unwrap();
            assert_eq!(consumed, 2);
            assert_eq!(
                capsule,
                Some(OwnedCapsule {
                    kind,
                    value: Vec::new(),
                })
            );
            decoder.finish().unwrap();

            let mut allocation_requests = Vec::new();
            let (consumed, capsule) = decoder
                .feed(&input[consumed..], |value_bytes| {
                    allocation_requests.push(value_bytes);
                    Ok(())
                })
                .unwrap();
            assert_eq!(consumed, 3);
            assert_eq!(allocation_requests, [1]);
            assert_eq!(
                capsule,
                Some(OwnedCapsule {
                    kind: DATAGRAM_CAPSULE,
                    value: vec![0],
                })
            );
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn claimed_length_is_checked_before_allocation_callback() {
        let mut decoder = CapsuleDecoder::new(8).unwrap();
        let mut header = vec![0];
        header.extend_from_slice(VarInt::encode(1_000_000).unwrap().as_slice());
        assert_eq!(
            decoder.feed(&header, |_| panic!("oversize allocation")),
            Err(EngineError::MessageTooLarge)
        );
        assert_eq!(
            decoder.feed(&[0, 1, 0], |_| Ok(())),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(decoder.buffered_value.capacity(), 0);
    }

    #[test]
    fn denied_allocation_poisons_decoder_and_releases_value() {
        let mut decoder = CapsuleDecoder::new(8).unwrap();
        assert_eq!(
            decoder.feed(&[0, 3, 0, 1, 2], |_| Err(
                EngineError::ResourceLimitExceeded
            )),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(decoder.buffered_value.capacity(), 0);
        decoder.clear();
        let (_, capsule) = decoder.feed(&[0, 1, 0], |_| Ok(())).unwrap();
        assert_eq!(capsule.unwrap().value, [0]);
    }

    #[test]
    fn incomplete_varints_and_values_are_truncation_at_eof() {
        for prefix in [&[0x40][..], &[0][..], &[0, 0x40][..], &[0, 3, 0, 1][..]] {
            let mut decoder = CapsuleDecoder::new(8).unwrap();
            decoder.feed(prefix, |_| Ok(())).unwrap();
            assert_eq!(decoder.finish(), Err(EngineError::TruncatedStream));
            decoder.clear();
            decoder.finish().unwrap();
            let (consumed, capsule) = decoder.feed(&[0, 1, 0], |_| Ok(())).unwrap();
            assert_eq!(consumed, 3);
            assert_eq!(capsule.unwrap().value, [0]);
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn advertised_payload_limit_includes_varint_size_changes() {
        for wire_limit in [16, 63, 64, 65, 16_383, 16_384] {
            for context in [0, 63, 64, 16_383] {
                let max = datagram_max_payload(false, context, wire_limit).unwrap();
                assert!(
                    encode_datagram_capsule(context, &vec![0; max])
                        .unwrap()
                        .len()
                        <= wire_limit
                );
                assert!(
                    encode_datagram_capsule(context, &vec![0; max + 1])
                        .unwrap()
                        .len()
                        > wire_limit
                );
            }
        }
    }

    #[test]
    fn native_overhead_is_independent_of_payload_length() {
        assert_eq!(wire_overhead(true, 0, usize::MAX), Ok(1));
        assert_eq!(
            wire_overhead(false, 0, usize::MAX),
            Err(EngineError::MessageTooLarge)
        );
    }
}
