#ifndef ARIAD_H
#define ARIAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t ariad_handle;

/* Experimental H2 ABI. Handles are process-local numbers, not pointers.
 * Each engine has one runtime driver thread. Network tasks advance between
 * calls. Call blocking network functions on native threads outside Tokio tasks.
 * UI and async hosts must dispatch these calls to host worker threads.
 * Stream read/write and association send/recv use independent direction locks.
 * Registry and owner locks cover bookkeeping, never network waits. Overlapping
 * calls can return ARIAD_ERROR_BUSY for an occupied direction or a contended
 * bookkeeping lock. Cancellation does not acquire direction locks.
 * No callbacks exist.
 * No logger, signal handler, or global runtime is installed.
 *
 * All non-null pointers must refer to valid memory for the complete call.
 * Nonempty inputs must stay initialized, readable, and unmodified within one
 * live allocation. Outputs must be writable and exclusively accessible.
 * Every output pointer must be aligned for its declared pointee type.
 * Output ranges must not overlap any other argument range. These conditions
 * are caller obligations. Null/length/handle checks do not validate pointers.
 * Input pointers are never retained; the library can retain owned copies.
 * Output storage belongs to the caller and need not be initialized.
 * Keep memory valid until its own call returns, even if another thread destroys
 * the handle first. Destruction does not end an admitted call's pointer lifetime.
 *
 * Network timeouts are 1..ARIAD_MAX_TIMEOUT_MS milliseconds. Each call uses one
 * operation deadline; transport phase limits can shorten it. Input and output
 * payloads are limited to ARIAD_MAX_COPY bytes per call. A successful write
 * reports the accepted prefix; advance by that count. A failed write can have
 * effects, so do not replay the payload on this or a replacement connection.
 * Stream read returns ARIAD_EOF for a clean end. Non-null handle, count, and
 * metadata outputs are cleared before other validation. Counts remain zero
 * on errors/EOF. A timeout does not establish rollback.
 *
 * Engine shutdown and destroy invalidate all child handles. Session close
 * and destroy invalidate its stream and association handles. Stream cancel/reset
 * keep the stream handle alive until destroy. Close keeps the session handle
 * alive. Association close keeps its handle alive until association destroy.
 * ARIAD_ERROR_BUSY leaves ownership unchanged. An active network call does not
 * hold the owner lock. Engine destroy invalidates handles before network waits,
 * cancels admitted calls, and waits for runtime cleanup under its deadline.
 * ARIAD_FORCED can report deferred cleanup until admitted calls return. Pending,
 * live, and deferred runtimes count toward the 32-engine admission limit.
 * Keep the library loaded until engines, calls, and deferred runtime cleanup end.
 * Some teardown errors still invalidate handles; see the declarations below.
 * Stale or incorrectly typed handles return ARIAD_ERROR_INVALID_HANDLE.
 *
 * Unwinding Rust panics are caught and return ARIAD_ERROR_INTERNAL. The affected
 * engine must be destroyed. Normal calls reject a failed or poisoned engine.
 * A poisoned engine lock is recovered only for teardown.
 * Build with panic=unwind for this behavior. panic=abort, allocation aborts,
 * and invalid native memory cannot be recovered by this ABI.
 */

/* BEGIN GENERATED WIRE VERSIONS */
/* Generated from crates/core/src/version.rs. */
#define ARIAD_PROTOCOL_VERSION 0u
#define ARIAD_H2_BINDING_VERSION 0u
/* END GENERATED WIRE VERSIONS */

/* BEGIN GENERATED CREDENTIAL LIMITS */
/* Generated from crates/core/src/auth.rs. */
#define ARIAD_CREDENTIAL_BYTES 32u
#define ARIAD_CREDENTIAL_HEX_BYTES 64u
/* END GENERATED CREDENTIAL LIMITS */

/* BEGIN GENERATED TRUST ROOT LIMIT */
/* Generated from crates/engine/src/tls_policy.rs. */
#define ARIAD_MAX_TRUST_ROOT_DER_BYTES 16384u
/* END GENERATED TRUST ROOT LIMIT */

#define ARIAD_ABI_VERSION 1u
#define ARIAD_OK 0
#define ARIAD_EOF 1
#define ARIAD_FORCED 2
#define ARIAD_DROPPED 3
#define ARIAD_ERROR_INVALID_ARGUMENT (-1)
#define ARIAD_ERROR_INVALID_HANDLE (-2)
#define ARIAD_ERROR_BUSY (-3)
#define ARIAD_ERROR_INTERNAL (-4)
#define ARIAD_ERROR_INVALID_CONFIG (-10)
#define ARIAD_ERROR_UNSUPPORTED (-11)
#define ARIAD_ERROR_ENDPOINT_RESOLUTION (-12)
#define ARIAD_ERROR_PEER_IDENTITY (-13)
#define ARIAD_ERROR_AUTHENTICATION (-14)
#define ARIAD_ERROR_AUTHORIZATION_UNAVAILABLE (-15)
#define ARIAD_ERROR_EGRESS (-16)
#define ARIAD_ERROR_TARGET_RESOLUTION (-17)
#define ARIAD_ERROR_TARGET_CONNECT (-18)
#define ARIAD_ERROR_TRANSPORT (-19)
#define ARIAD_ERROR_TRANSFER_STALLED (-20)
#define ARIAD_ERROR_RESOURCE_LIMIT (-21)
#define ARIAD_ERROR_MESSAGE_TOO_LARGE (-22)
#define ARIAD_ERROR_CANCELLED (-23)
#define ARIAD_ERROR_DEADLINE (-24)
#define ARIAD_ERROR_REMOTE_RESET (-25)
#define ARIAD_ERROR_PROTOCOL (-26)
#define ARIAD_ERROR_TRUNCATED (-27)
#define ARIAD_ERROR_NO_TRUSTED_PATH (-28)
#define ARIAD_CLOSE_GRACEFUL 0u
#define ARIAD_CLOSE_IMMEDIATE 1u
#define ARIAD_DELIVERY_RELIABLE 1u
#define ARIAD_DELIVERY_UNRELIABLE 2u
#define ARIAD_MAX_COPY 65536u
#define ARIAD_MAX_TIMEOUT_MS 60000u
#define ARIAD_MAX_TEXT 512u

#define ARIAD_FEATURE_H2 1u
#define ARIAD_FEATURE_H3 2u
#define ARIAD_FEATURE_UDP_UNRELIABLE 3u
#define ARIAD_FEATURE_ECH 4u

#define ARIAD_TARGET_WINDOWS_MSVC 1u
#define ARIAD_TARGET_LINUX_GNU 2u
#define ARIAD_TARGET_IOS 3u
#define ARIAD_TARGET_ANDROID 4u

#define ARIAD_TARGET_CLASS_UNSUPPORTED 0
#define ARIAD_TARGET_CLASS_TESTED_LOCAL 1
#define ARIAD_TARGET_CLASS_DECLARED_CI 2

/* C ABI version, independent of protocol and H2 binding versions. Check before
 * other calls. Compatible additions keep this version. Dynamic loaders must
 * also check that each entry point they use is present.
 */
uint32_t ariad_abi_version(void);
/* Constant name for an operation status. Unknown values return
 * "ARIAD_STATUS_UNKNOWN". Always returns a non-null, NUL-terminated ASCII
 * string, owned by the library and valid until the library is unloaded.
 * Do not modify or free it. Needs no engine, allocates no memory, and is safe
 * across threads. Feature and target query results are classifications,
 * not operation statuses.
 */
const char *ariad_status_name(int32_t status);
/* Endpoint is an IP:port literal. Identity is the certificate hostname; its
 * ASCII syntax and 253-byte limit are checked independently of the address.
 * Strings contain 1..ARIAD_MAX_TEXT UTF-8 bytes without a trailing NUL. Root is
 * one nonempty DER certificate, at most ARIAD_MAX_TRUST_ROOT_DER_BYTES bytes. Larger or malformed
 * certificates return ARIAD_ERROR_INVALID_CONFIG; the earlier copy bound
 * rejects inputs above ARIAD_MAX_COPY as ARIAD_ERROR_MESSAGE_TOO_LARGE and
 * empty or null DER input as ARIAD_ERROR_INVALID_ARGUMENT.
 * Success writes out_engine. Creation performs no network I/O. Connections
 * use TLS 1.3 with ALPN h2. Default sockets have no routing-loop protection.
 * Hosts needing a protection hook must use the Rust HostServices API.
 */
int32_t ariad_engine_create(const uint8_t *endpoint, size_t endpoint_len, const uint8_t *identity,
                            size_t identity_len, const uint8_t *trust_root_der,
                            size_t trust_root_len, ariad_handle *out_engine);
/* Credential is exactly ARIAD_CREDENTIAL_BYTES bytes and is copied into the session. Success writes
 * out_session after TLS identity and H2 setup. Authentication and destination
 * authorization occur on each subsequent open. A shut-down engine returns
 * ARIAD_ERROR_CANCELLED.
 */
int32_t ariad_engine_connect(ariad_handle engine, const uint8_t *credential, size_t credential_len,
                             uint32_t timeout_ms, ariad_handle *out_session);
/* Stops new opens and invalidates child handles before network waits, including
 * on ARIAD_ERROR_TRANSPORT. ARIAD_FORCED reports forced sessions, pending
 * connects, or an expired shutdown deadline. Engine and runtime remain until
 * destroy.
 * Argument/lock failures precede shutdown; a caught panic can interrupt cleanup.
 */
int32_t ariad_engine_shutdown(ariad_handle engine, uint32_t timeout_ms);
/* Invalidates engine and child handles before network waits, including on
 * shutdown ARIAD_ERROR_TRANSPORT. Cancellation wakes admitted calls without
 * taking their direction locks. ARIAD_FORCED can report an expired wait for
 * those calls; runtime cleanup continues after they return and retains admission.
 * Failed or poisoned owner teardown returns ARIAD_ERROR_INTERNAL and
 * invalidates handles.
 * ARIAD_ERROR_BUSY, invalid arguments, and invalid handles leave ownership intact.
 * Other internal errors or caught panics can precede or interrupt teardown;
 * they do not establish that a handle can be reused.
 */
int32_t ariad_engine_destroy(ariad_handle engine, uint32_t timeout_ms);
/* Destination is ASCII host:port or [ipv6]:port, in 1..ARIAD_MAX_TEXT bytes without a NUL.
 * Domain hosts are limited to 253 bytes; ports are in 1..65535.
 * Success writes out_stream after an accepted TCP CONNECT response. Opening
 * sends no application payload.
 */
int32_t ariad_session_open_stream(ariad_handle session, const uint8_t *destination,
                                  size_t destination_len, uint32_t timeout_ms,
                                  ariad_handle *out_stream);
/* mode is ARIAD_CLOSE_GRACEFUL or ARIAD_CLOSE_IMMEDIATE. Once close returns,
 * streams and associations are invalidated, including on transport errors.
 * ARIAD_OK reports graceful closure; ARIAD_FORCED reports forced cleanup or an
 * expired closure deadline.
 * The session handle remains valid. Argument/lock failures precede closure;
 * a caught panic can interrupt cleanup.
 */
int32_t ariad_session_close(ariad_handle session, uint32_t mode, uint32_t timeout_ms);
/* Cancels and releases session and children without a graceful network drain. */
int32_t ariad_session_destroy(ariad_handle session);
/* Borrows input until this synchronous call returns. input_len is
 * 1..ARIAD_MAX_COPY. ARIAD_OK reports the accepted prefix in
 * out_written; acceptance does not confirm remote delivery. Errors report
 * zero and can retain transport effects. Do not replay the payload.
 */
int32_t ariad_stream_write(ariad_handle stream, const uint8_t *input, size_t input_len,
                           uint32_t timeout_ms, size_t *out_written);
/* output_capacity is 1..ARIAD_MAX_COPY. ARIAD_OK copies a nonempty prefix and
 * reports its count. EOF reports zero. Reset, cancellation, and truncation are
 * errors. Errors and EOF leave the output buffer unchanged.
 */
int32_t ariad_stream_read(ariad_handle stream, uint8_t *output, size_t output_capacity,
                          uint32_t timeout_ms, size_t *out_read);
/* Ends writes and permits further reads. OK means the local end signal was
 * accepted; it does not confirm peer EOF. The handle remains valid.
 */
int32_t ariad_stream_end_write(ariad_handle stream, uint32_t timeout_ms);
/* Requests cancellation and retains the handle until destroy. */
int32_t ariad_stream_cancel(ariad_handle stream);
/* Resets the stream. On success, further reads report ARIAD_ERROR_REMOTE_RESET.
 * The handle remains valid until destroy.
 */
int32_t ariad_stream_reset(ariad_handle stream);
/* Cancels and releases the stream, invalidating its handle. */
int32_t ariad_stream_destroy(ariad_handle stream);

/* Destination uses the stream-open text format. require_unreliable is 0 or 1.
 * H2 rejects 1 before reading the destination or writing a request. Success
 * writes out_association. Getters report negotiated delivery and payload limit;
 * local feature metadata does not establish them.
 */
int32_t ariad_session_open_datagram(ariad_handle session, const uint8_t *destination,
                                    size_t destination_len, uint32_t require_unreliable,
                                    uint32_t timeout_ms, ariad_handle *out_association);
/* Writes ARIAD_DELIVERY_RELIABLE or ARIAD_DELIVERY_UNRELIABLE. This getter
 * remains available after association close, until handle destruction.
 */
int32_t ariad_association_delivery_mode(ariad_handle association, uint32_t *out_mode);
/* Writes maximum whole-message bytes, capped by ARIAD_MAX_COPY. This getter
 * remains available after association close, until handle destruction.
 */
int32_t ariad_association_max_payload(ariad_handle association, size_t *out_max_payload);
/* Send accepts one complete message, including a zero-length message with
 * input=NULL. OK means locally admitted; it does not assert remote delivery.
 * Nonempty messages must fit ariad_association_max_payload. DROPPED means local
 * resource admission failed. Failed sends can have effects and must not be replayed.
 */
int32_t ariad_association_send(ariad_handle association, const uint8_t *input, size_t input_len,
                               uint32_t timeout_ms);
/* Recv consumes one complete message. Capacity is 0..ARIAD_MAX_COPY. If it does
 * not fit, ARIAD_ERROR_MESSAGE_TOO_LARGE discards the message and reports zero
 * bytes; output stays unchanged. No prefix is copied. Capacity above the ABI
 * limit is rejected before receiving a message.
 * output=NULL/capacity=0 can receive an empty message. A nonempty message is
 * discarded as MessageTooLarge in that case. A zero-byte OK is not stream EOF.
 */
int32_t ariad_association_recv(ariad_handle association, uint8_t *output, size_t output_capacity,
                               uint32_t timeout_ms, size_t *out_read);
/* Closes and discards buffered messages. Handle and getters remain valid, but
 * send/recv cannot continue. H2 closure resets the transport.
 */
int32_t ariad_association_close(ariad_handle association);
/* Cancels and releases the association, invalidating its handle. */
int32_t ariad_association_destroy(ariad_handle association);

/* Version, capability, and target queries need no engine and do no I/O. */
/* Experimental protocol version supported by this library. */
uint16_t ariad_protocol_version(void);
/* Experimental H2 binding version supported by this library. */
uint16_t ariad_h2_binding_version(void);
/* Local H2 ABI feature metadata: 1 supported, 0 unsupported, -1 unknown feature.
 * This result does not describe a peer or establish negotiation.
 */
int32_t ariad_supported(uint32_t feature);
/* 1 if both versions match this library, else 0. Performs no negotiation. */
int32_t ariad_wire_compatible(uint16_t protocol, uint16_t h2_binding);
/* Declared target metadata: ARIAD_TARGET_CLASS_TESTED_LOCAL,
 * ARIAD_TARGET_CLASS_DECLARED_CI, ARIAD_TARGET_CLASS_UNSUPPORTED, or -1 for an unknown target.
 * Classifies the named target, not the current host.
 */
int32_t ariad_target(uint32_t target);

#ifdef __cplusplus
}
#endif

#endif
