// Package ariad owns synchronous C ABI handles for pinned H2 connections.
//
// Timed calls use milliseconds in 1..MaxTimeoutMS and block until C returns.
// Context cancellation does not interrupt them. Hosts bound concurrent calls,
// retain borrowed buffers until return, and destroy every acquired owner.
// Zero-value owners are invalid; copies share the same ownership state.
package ariad

/*
#cgo LDFLAGS: -lariad_ffi
#include <ariad.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

// ExpectedABI and the related constants come from the compiled C header.
// They do not report the linked library's versions or negotiated peer limits.
const (
	ExpectedABI          = uint32(C.ARIAD_ABI_VERSION)
	ExpectedProtocol     = uint16(C.ARIAD_PROTOCOL_VERSION)
	ExpectedH2Binding    = uint16(C.ARIAD_H2_BINDING_VERSION)
	MaxCopy              = int(C.ARIAD_MAX_COPY)
	MaxTimeoutMS         = uint32(C.ARIAD_MAX_TIMEOUT_MS)
	CredentialBytes      = int(C.ARIAD_CREDENTIAL_BYTES)
	CredentialHexBytes   = int(C.ARIAD_CREDENTIAL_HEX_BYTES)
	MaxTrustRootDERBytes = int(C.ARIAD_MAX_TRUST_ROOT_DER_BYTES)
	maxText              = int(C.ARIAD_MAX_TEXT)
)

// Status is a native outcome code. Negative codes are errors that support
// errors.Is comparisons; nonnegative codes describe successful outcomes.
type Status int32

const (
	StatusOK                    Status = C.ARIAD_OK
	StatusEOF                   Status = C.ARIAD_EOF
	StatusForced                Status = C.ARIAD_FORCED
	StatusDropped               Status = C.ARIAD_DROPPED
	ErrInvalidArgument          Status = C.ARIAD_ERROR_INVALID_ARGUMENT
	ErrInvalidHandle            Status = C.ARIAD_ERROR_INVALID_HANDLE
	ErrBusy                     Status = C.ARIAD_ERROR_BUSY
	ErrInternal                 Status = C.ARIAD_ERROR_INTERNAL
	ErrInvalidConfig            Status = C.ARIAD_ERROR_INVALID_CONFIG
	ErrUnsupported              Status = C.ARIAD_ERROR_UNSUPPORTED
	ErrEndpointResolution       Status = C.ARIAD_ERROR_ENDPOINT_RESOLUTION
	ErrPeerIdentity             Status = C.ARIAD_ERROR_PEER_IDENTITY
	ErrAuthentication           Status = C.ARIAD_ERROR_AUTHENTICATION
	ErrAuthorizationUnavailable Status = C.ARIAD_ERROR_AUTHORIZATION_UNAVAILABLE
	ErrEgress                   Status = C.ARIAD_ERROR_EGRESS
	ErrTargetResolution         Status = C.ARIAD_ERROR_TARGET_RESOLUTION
	ErrTargetConnect            Status = C.ARIAD_ERROR_TARGET_CONNECT
	ErrTransport                Status = C.ARIAD_ERROR_TRANSPORT
	ErrTransferStalled          Status = C.ARIAD_ERROR_TRANSFER_STALLED
	ErrResourceLimit            Status = C.ARIAD_ERROR_RESOURCE_LIMIT
	ErrMessageTooLarge          Status = C.ARIAD_ERROR_MESSAGE_TOO_LARGE
	ErrCancelled                Status = C.ARIAD_ERROR_CANCELLED
	ErrDeadline                 Status = C.ARIAD_ERROR_DEADLINE
	ErrRemoteReset              Status = C.ARIAD_ERROR_REMOTE_RESET
	ErrProtocol                 Status = C.ARIAD_ERROR_PROTOCOL
	ErrTruncated                Status = C.ARIAD_ERROR_TRUNCATED
	ErrNoTrustedPath            Status = C.ARIAD_ERROR_NO_TRUSTED_PATH
)

// Error returns diagnostic text. Use the numeric Status for classification.
func (s Status) Error() string {
	return fmt.Sprintf("%s (%d)", C.GoString(C.ariad_status_name(C.int32_t(s))), int32(s))
}

// Feature identifies a local transport capability, not peer support.
type Feature uint32

const (
	FeatureH2            Feature = C.ARIAD_FEATURE_H2
	FeatureH3            Feature = C.ARIAD_FEATURE_H3
	FeatureUDPUnreliable Feature = C.ARIAD_FEATURE_UDP_UNRELIABLE
	FeatureECH           Feature = C.ARIAD_FEATURE_ECH
)

// Versions reports the ABI and wire versions exported by the linked library.
type Versions struct {
	ABI       uint32
	Protocol  uint16
	H2Binding uint16
}

// LibraryVersions queries native metadata without creating a connection.
func LibraryVersions() Versions {
	return Versions{
		ABI:       uint32(C.ariad_abi_version()),
		Protocol:  uint16(C.ariad_protocol_version()),
		H2Binding: uint16(C.ariad_h2_binding_version()),
	}
}

// Supports reports whether the linked library provides feature.
// Unknown feature identifiers return ErrInvalidArgument.
func Supports(feature Feature) (bool, error) {
	switch C.ariad_supported(C.uint32_t(feature)) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, ErrInvalidArgument
	}
}

// CheckLibrary requires the compiled header's ABI and wire versions and local H2
// support. It does not verify the peer, host platform, or native linkage setup.
func CheckLibrary() error {
	abi := uint32(C.ariad_abi_version())
	if abi != ExpectedABI {
		return fmt.Errorf("ariad ABI version %d, want %d", abi, ExpectedABI)
	}
	versions := LibraryVersions()
	if C.ariad_wire_compatible(C.uint16_t(ExpectedProtocol), C.uint16_t(ExpectedH2Binding)) != 1 {
		return fmt.Errorf("ariad wire versions %d/%d, want %d/%d", versions.Protocol, versions.H2Binding, ExpectedProtocol, ExpectedH2Binding)
	}
	h2, err := Supports(FeatureH2)
	if err != nil {
		return err
	}
	if !h2 {
		return ErrUnsupported
	}
	return nil
}

// Target names a Rust build target; it does not identify the current Go host.
type Target uint32

const (
	TargetWindowsMSVC Target = C.ARIAD_TARGET_WINDOWS_MSVC
	TargetLinuxGNU    Target = C.ARIAD_TARGET_LINUX_GNU
	TargetIOS         Target = C.ARIAD_TARGET_IOS
	TargetAndroid     Target = C.ARIAD_TARGET_ANDROID
)

// SupportClass records declared Rust target validation, not Go binding support.
type SupportClass int32

const (
	Unsupported SupportClass = C.ARIAD_TARGET_CLASS_UNSUPPORTED
	TestedLocal SupportClass = C.ARIAD_TARGET_CLASS_TESTED_LOCAL
	DeclaredCI  SupportClass = C.ARIAD_TARGET_CLASS_DECLARED_CI
)

// DeclaredSupport returns target metadata without testing this host.
// Unknown target identifiers return ErrInvalidArgument.
func DeclaredSupport(target Target) (SupportClass, error) {
	class := C.ariad_target(C.uint32_t(target))
	if class < C.ARIAD_TARGET_CLASS_UNSUPPORTED {
		return Unsupported, ErrInvalidArgument
	}
	if class > C.ARIAD_TARGET_CLASS_DECLARED_CI {
		return Unsupported, ErrInternal
	}
	return SupportClass(class), nil
}

// CloseMode selects session drain or immediate cancellation.
type CloseMode uint32

const (
	CloseGraceful  CloseMode = C.ARIAD_CLOSE_GRACEFUL
	CloseImmediate CloseMode = C.ARIAD_CLOSE_IMMEDIATE
)

// DeliveryMode distinguishes reliable capsules from native unreliable datagrams.
type DeliveryMode uint32

const (
	DeliveryReliable   DeliveryMode = C.ARIAD_DELIVERY_RELIABLE
	DeliveryUnreliable DeliveryMode = C.ARIAD_DELIVERY_UNRELIABLE
)

type ownership struct {
	mu     sync.Mutex
	failed bool
}

type resource struct {
	owner  *ownership
	parent *resource
	handle C.ariad_handle
	// Closing a parent invalidates descendants without retaining a child registry.
	closed bool
}

// Engine owns a native runtime and invalidates its descendants on destruction.
// Copies share ownership. Destroy must be called explicitly; there is no finalizer.
type Engine struct{ state *resource }

// Session retains an Engine connection. Closing or destroying it invalidates its
// streams and associations; the Session still needs Destroy after Close.
type Session struct{ state *resource }

// Stream owns one TCP CONNECT flow. Independent reads and writes may overlap;
// calls contending for the same direction can return ErrBusy.
type Stream struct{ state *resource }

// Association owns one destination-bound UDP context. Send and Recv may overlap;
// payload delivery and size limits come from its negotiated getters.
type Association struct{ state *resource }

func (r *resource) validLocked() bool {
	for node := r; node != nil; node = node.parent {
		if node.handle == 0 || (node != r && node.closed) {
			return false
		}
	}
	return true
}

func (r *resource) load(open, teardown bool) (C.ariad_handle, error) {
	if r == nil {
		return 0, ErrInvalidHandle
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if !r.validLocked() {
		return 0, ErrInvalidHandle
	}
	if r.owner.failed && !teardown {
		return 0, ErrInternal
	}
	if open && r.closed {
		return 0, ErrCancelled
	}
	// Release the state lock before C can wait or cancel another admitted call.
	return r.handle, nil
}

func (r *resource) result(code C.int32_t) error {
	if code == C.ARIAD_OK {
		return nil
	}
	if code == C.ARIAD_ERROR_INTERNAL {
		r.owner.mu.Lock()
		r.owner.failed = true
		r.owner.mu.Unlock()
	}
	return Status(code)
}

func (r *resource) countResult(code C.int32_t, count C.size_t, minimum, maximum int) (int, error) {
	if err := r.result(code); err != nil {
		return 0, err
	}
	if count < C.size_t(minimum) || count > C.size_t(maximum) {
		return 0, r.result(C.ARIAD_ERROR_INTERNAL)
	}
	return int(count), nil
}

func (r *resource) child(handle C.ariad_handle, code C.int32_t) (*resource, error) {
	if err := r.result(code); err != nil {
		return nil, err
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if !r.validLocked() {
		return nil, ErrInvalidHandle
	}
	if r.owner.failed || handle == 0 {
		r.owner.failed = true
		return nil, ErrInternal
	}
	if r.closed {
		return nil, ErrCancelled
	}
	return &resource{owner: r.owner, parent: r, handle: handle}, nil
}

func (r *resource) finishClose(code C.int32_t) (bool, error) {
	if code != C.ARIAD_ERROR_BUSY && code != C.ARIAD_ERROR_INVALID_ARGUMENT {
		r.owner.mu.Lock()
		r.closed = true
		if code == C.ARIAD_ERROR_INVALID_HANDLE {
			r.handle = 0
		}
		r.owner.mu.Unlock()
	}
	if code == C.ARIAD_FORCED {
		return true, nil
	}
	return false, r.result(code)
}

func (r *resource) destroy(call func(C.ariad_handle) C.int32_t, engine bool) (bool, error) {
	handle, err := r.load(false, true)
	if errors.Is(err, ErrInvalidHandle) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	code := call(handle)
	if code == C.ARIAD_OK || code == C.ARIAD_ERROR_INVALID_HANDLE ||
		(engine && (code == C.ARIAD_FORCED || code == C.ARIAD_ERROR_TRANSPORT)) {
		r.owner.mu.Lock()
		r.handle = 0
		r.closed = true
		r.owner.mu.Unlock()
	}
	if code == C.ARIAD_ERROR_INVALID_HANDLE {
		return false, nil
	}
	if code == C.ARIAD_FORCED && engine {
		return true, nil
	}
	// INTERNAL can precede native teardown. Keep the handle for an engine destroy retry.
	return false, r.result(code)
}

// C borrows pointer-free Go storage only until its synchronous call returns.
func bytePointer(bytes []byte) *C.uint8_t {
	if len(bytes) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&bytes[0]))
}

func timeoutValid(timeoutMS uint32) bool {
	return timeoutMS > 0 && timeoutMS <= MaxTimeoutMS
}

func copyError(size, minimum int, timeoutMS uint32) error {
	if size < minimum || !timeoutValid(timeoutMS) {
		return ErrInvalidArgument
	}
	if size > MaxCopy {
		return ErrMessageTooLarge
	}
	return nil
}

func textError(text string) error {
	if text == "" {
		return ErrInvalidArgument
	}
	if len(text) > maxText {
		return ErrMessageTooLarge
	}
	return nil
}

// NewEngine validates native compatibility and one pinned H2 endpoint.
// endpoint is an IP:port route; identity is the certificate DNS name. The DER
// input must contain one certificate within MaxTrustRootDERBytes. Construction
// creates a native owner without connecting; the caller must eventually Destroy it.
func NewEngine(endpoint, identity string, trustRootDER []byte) (*Engine, error) {
	if err := CheckLibrary(); err != nil {
		return nil, err
	}
	if err := textError(endpoint); err != nil {
		return nil, err
	}
	if err := textError(identity); err != nil {
		return nil, err
	}
	if len(trustRootDER) == 0 {
		return nil, ErrInvalidArgument
	}
	if len(trustRootDER) > MaxCopy {
		return nil, ErrMessageTooLarge
	}
	endpointBytes, identityBytes := []byte(endpoint), []byte(identity)
	var handle C.ariad_handle
	code := C.ariad_engine_create(bytePointer(endpointBytes), C.size_t(len(endpointBytes)),
		bytePointer(identityBytes), C.size_t(len(identityBytes)),
		bytePointer(trustRootDER), C.size_t(len(trustRootDER)), &handle)
	runtime.KeepAlive(endpointBytes)
	runtime.KeepAlive(identityBytes)
	runtime.KeepAlive(trustRootDER)
	if code != C.ARIAD_OK {
		return nil, Status(code)
	}
	if handle == 0 {
		return nil, ErrInternal
	}
	return &Engine{state: &resource{owner: &ownership{}, handle: handle}}, nil
}

// Connect verifies the proxy and stores exactly CredentialBytes credential bytes
// for later target opens. Keep the input unchanged until return. Failure does not
// permit direct destination fallback.
func (e *Engine) Connect(credential []byte, timeoutMS uint32) (*Session, error) {
	if len(credential) != CredentialBytes || !timeoutValid(timeoutMS) {
		return nil, ErrInvalidArgument
	}
	handle, err := e.state.load(true, false)
	if err != nil {
		return nil, err
	}
	var session C.ariad_handle
	code := C.ariad_engine_connect(handle, bytePointer(credential), C.size_t(len(credential)), C.uint32_t(timeoutMS), &session)
	runtime.KeepAlive(credential)
	state, err := e.state.child(session, code)
	if err != nil {
		return nil, err
	}
	return &Session{state: state}, nil
}

// Shutdown stops admission and invalidates descendants. The Engine remains for
// Destroy. forced reports an unfinished graceful drain separately from err.
func (e *Engine) Shutdown(timeoutMS uint32) (forced bool, err error) {
	if !timeoutValid(timeoutMS) {
		return false, ErrInvalidArgument
	}
	handle, err := e.state.load(false, false)
	if err != nil {
		return false, err
	}
	return e.state.finishClose(C.ariad_engine_shutdown(handle, C.uint32_t(timeoutMS)))
}

// Destroy releases the Engine and descendants. ErrBusy and ErrInternal preserve
// the owner for cleanup retry; ErrTransport invalidates it. A forced result can
// leave native cleanup active until already admitted calls return.
func (e *Engine) Destroy(timeoutMS uint32) (forced bool, err error) {
	if !timeoutValid(timeoutMS) {
		return false, ErrInvalidArgument
	}
	return e.state.destroy(func(handle C.ariad_handle) C.int32_t {
		return C.ariad_engine_destroy(handle, C.uint32_t(timeoutMS))
	}, true)
}

// OpenStream requests one authorized TCP destination. Success owns a Stream;
// proxy verification alone does not establish destination admission.
func (s *Session) OpenStream(destination string, timeoutMS uint32) (*Stream, error) {
	if !timeoutValid(timeoutMS) {
		return nil, ErrInvalidArgument
	}
	if err := textError(destination); err != nil {
		return nil, err
	}
	handle, err := s.state.load(true, false)
	if err != nil {
		return nil, err
	}
	bytes := []byte(destination)
	var stream C.ariad_handle
	code := C.ariad_session_open_stream(handle, bytePointer(bytes), C.size_t(len(bytes)), C.uint32_t(timeoutMS), &stream)
	runtime.KeepAlive(bytes)
	state, err := s.state.child(stream, code)
	if err != nil {
		return nil, err
	}
	return &Stream{state: state}, nil
}

// OpenDatagram binds one UDP destination. H2 rejects requireUnreliable before
// inspecting destination or sending a request. Inspect the returned Association's
// DeliveryMode and MaxPayload before sending data.
func (s *Session) OpenDatagram(destination string, requireUnreliable bool, timeoutMS uint32) (*Association, error) {
	if !timeoutValid(timeoutMS) {
		return nil, ErrInvalidArgument
	}
	handle, err := s.state.load(true, false)
	if err != nil {
		return nil, err
	}
	var bytes []byte
	var requirement C.uint32_t
	if requireUnreliable {
		// H2 rejects this requirement before inspecting the destination.
		requirement = 1
	} else {
		if destinationErr := textError(destination); destinationErr != nil {
			return nil, destinationErr
		}
		bytes = []byte(destination)
	}
	var association C.ariad_handle
	code := C.ariad_session_open_datagram(handle, bytePointer(bytes), C.size_t(len(bytes)), requirement, C.uint32_t(timeoutMS), &association)
	runtime.KeepAlive(bytes)
	state, err := s.state.child(association, code)
	if err != nil {
		return nil, err
	}
	return &Association{state: state}, nil
}

// Close stops new flows and invalidates descendants. The Session remains for
// Destroy. forced reports a drain that did not finish within its budget.
func (s *Session) Close(mode CloseMode, timeoutMS uint32) (forced bool, err error) {
	if (mode != CloseGraceful && mode != CloseImmediate) || !timeoutValid(timeoutMS) {
		return false, ErrInvalidArgument
	}
	handle, err := s.state.load(false, false)
	if err != nil {
		return false, err
	}
	return s.state.finishClose(C.ariad_session_close(handle, C.uint32_t(mode), C.uint32_t(timeoutMS)))
}

// Destroy releases the Session and descendants. An already invalidated owner is
// a no-op; ErrBusy preserves ownership for retry after contention ends.
func (s *Session) Destroy() error {
	_, err := s.state.destroy(func(handle C.ariad_handle) C.int32_t {
		return C.ariad_session_destroy(handle)
	}, false)
	return err
}

// Write accepts one nonempty prefix of input. Advance by the returned count on
// success. An error can retain transport effects; do not replay the payload.
func (s *Stream) Write(input []byte, timeoutMS uint32) (int, error) {
	if err := copyError(len(input), 1, timeoutMS); err != nil {
		return 0, err
	}
	handle, err := s.state.load(false, false)
	if err != nil {
		return 0, err
	}
	var count C.size_t
	code := C.ariad_stream_write(handle, bytePointer(input), C.size_t(len(input)), C.uint32_t(timeoutMS), &count)
	runtime.KeepAlive(input)
	return s.state.countResult(code, count, 1, len(input))
}

// Read copies one nonempty prefix into output. Clean EOF is (0, io.EOF).
// Native errors and EOF leave the supplied output unchanged.
func (s *Stream) Read(output []byte, timeoutMS uint32) (int, error) {
	if err := copyError(len(output), 1, timeoutMS); err != nil {
		return 0, err
	}
	handle, err := s.state.load(false, false)
	if err != nil {
		return 0, err
	}
	var count C.size_t
	code := C.ariad_stream_read(handle, bytePointer(output), C.size_t(len(output)), C.uint32_t(timeoutMS), &count)
	runtime.KeepAlive(output)
	if code == C.ARIAD_EOF {
		if count != 0 {
			return 0, s.state.result(C.ARIAD_ERROR_INTERNAL)
		}
		return 0, io.EOF
	}
	return s.state.countResult(code, count, 1, len(output))
}

// EndWrite half-closes the sending direction. Reads can continue until peer EOF.
// Local completion does not establish remote application processing.
func (s *Stream) EndWrite(timeoutMS uint32) error {
	if !timeoutValid(timeoutMS) {
		return ErrInvalidArgument
	}
	handle, err := s.state.load(false, false)
	if err != nil {
		return err
	}
	return s.state.result(C.ariad_stream_end_write(handle, C.uint32_t(timeoutMS)))
}

// Cancel stops flow work without releasing the Stream owner or undoing accepted
// bytes. A concurrent native call must still return before its buffer is reused.
func (s *Stream) Cancel() error {
	handle, err := s.state.load(false, false)
	if err != nil {
		return err
	}
	return s.state.result(C.ariad_stream_cancel(handle))
}

// Reset sends an abrupt stream reset. The Stream remains for Destroy.
func (s *Stream) Reset() error {
	handle, err := s.state.load(false, false)
	if err != nil {
		return err
	}
	return s.state.result(C.ariad_stream_reset(handle))
}

// Destroy releases the Stream. ErrBusy preserves the owner for cleanup retry.
func (s *Stream) Destroy() error {
	_, err := s.state.destroy(func(handle C.ariad_handle) C.int32_t {
		return C.ariad_stream_destroy(handle)
	}, false)
	return err
}

// DeliveryMode reports negotiated semantics. The getter remains valid after
// Association.Close while the Session and Engine remain open.
func (a *Association) DeliveryMode() (DeliveryMode, error) {
	handle, err := a.state.load(false, false)
	if err != nil {
		return 0, err
	}
	var mode C.uint32_t
	if operationErr := a.state.result(C.ariad_association_delivery_mode(handle, &mode)); operationErr != nil {
		return 0, operationErr
	}
	if mode != C.ARIAD_DELIVERY_RELIABLE && mode != C.ARIAD_DELIVERY_UNRELIABLE {
		return 0, a.state.result(C.ARIAD_ERROR_INTERNAL)
	}
	return DeliveryMode(mode), nil
}

// MaxPayload reports the negotiated whole-message limit, capped by MaxCopy.
// It does not prove that the host network prevents IP fragmentation.
func (a *Association) MaxPayload() (int, error) {
	handle, err := a.state.load(false, false)
	if err != nil {
		return 0, err
	}
	var size C.size_t
	code := C.ariad_association_max_payload(handle, &size)
	return a.state.countResult(code, size, 0, MaxCopy)
}

// Send submits one whole message, including nil for an empty message. dropped
// reports a local drop separately from err. Success does not prove delivery;
// errors can retain transport effects and must not trigger payload replay.
func (a *Association) Send(input []byte, timeoutMS uint32) (dropped bool, err error) {
	if validationErr := copyError(len(input), 0, timeoutMS); validationErr != nil {
		return false, validationErr
	}
	handle, err := a.state.load(true, false)
	if err != nil {
		return false, err
	}
	code := C.ariad_association_send(handle, bytePointer(input), C.size_t(len(input)), C.uint32_t(timeoutMS))
	runtime.KeepAlive(input)
	if code == C.ARIAD_DROPPED {
		return true, nil
	}
	return false, a.state.result(code)
}

// Recv consumes one whole message. (0, nil) denotes an empty message. An oversized
// message is discarded with ErrMessageTooLarge and leaves output unchanged.
func (a *Association) Recv(output []byte, timeoutMS uint32) (int, error) {
	if err := copyError(len(output), 0, timeoutMS); err != nil {
		return 0, err
	}
	handle, err := a.state.load(true, false)
	if err != nil {
		return 0, err
	}
	var count C.size_t
	code := C.ariad_association_recv(handle, bytePointer(output), C.size_t(len(output)), C.uint32_t(timeoutMS), &count)
	runtime.KeepAlive(output)
	return a.state.countResult(code, count, 0, len(output))
}

// Close stops sending and receiving. The negotiated getters remain available;
// the Association still needs Destroy.
func (a *Association) Close() error {
	handle, err := a.state.load(false, false)
	if err != nil {
		return err
	}
	_, err = a.state.finishClose(C.ariad_association_close(handle))
	return err
}

// Destroy releases the Association. ErrBusy preserves ownership for cleanup retry.
func (a *Association) Destroy() error {
	_, err := a.state.destroy(func(handle C.ariad_handle) C.int32_t {
		return C.ariad_association_destroy(handle)
	}, false)
	return err
}
