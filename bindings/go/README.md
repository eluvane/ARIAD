# Go binding

This module wraps the synchronous [ARIAD C ABI](../../crates/ffi/include/ariad.h)
with `Engine`, `Session`, `Stream`, and `Association` objects. The Go version
requirement is declared in [go.mod](go.mod). It uses cgo and the standard library.
There are no Go module dependencies.
The host supplies a C compiler and a matching native ARIAD library.

Go linkage and runtime integration have not been verified on any target.
The Linux/GNU configuration below is an integration recipe. Native Windows/MSVC
target metadata does not establish compatibility with Go's Windows cgo toolchain
or its linker. No Windows, iOS, or Android packaging recipe is provided here;
mobile integration remains unverified.

## Configure native linkage

Use `ariad.h` and the `ariad-ffi` shared library from the same checkout. This
binding requires the additive `ariad_status_name` symbol; an older ABI-1 library
without that symbol will fail to link or load. Native build prerequisites are in
[CONTRIBUTING.md](../../CONTRIBUTING.md).

The Go source supplies `-lariad_ffi`. Configure header and library directories
with `CGO_CPPFLAGS` and `CGO_LDFLAGS`. Configure the native loader separately.
For a Linux/GNU host, after building `libariad_ffi.so` for that host:

```sh
ariad_root=/absolute/path/to/ariad
export CGO_ENABLED=1
export CC=cc
export CGO_CPPFLAGS="-I${ariad_root}/crates/ffi/include"
export CGO_LDFLAGS="-L${ariad_root}/target/release"
export LD_LIBRARY_PATH="${ariad_root}/target/release${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
cd "${ariad_root}/bindings/go"
```

Replace the directories if artifacts live elsewhere. The header, Rust library,
C compiler, and Go target must agree on architecture and ABI. cgo is required;
`CGO_ENABLED=0` does not provide this package.

For a host application in a separate local Go module, use a local replacement:

```go
require github.com/eluvane/ariad/bindings/go v0.5.1

replace github.com/eluvane/ariad/bindings/go => /absolute/path/to/ariad/bindings/go
```

The replacement points to source. It does not build or install the Rust library.

## Blocking calls and ownership

Calls execute synchronously. Run network and teardown work on host goroutines
when the caller must remain responsive. A goroutine can block in native code for
its operation timeout. The host must bound concurrency; this package starts no
goroutines, installs no callbacks or logger, and creates no global runtime. The
native ABI uses one runtime driver thread per engine.

All timed methods take integer milliseconds in `1..MaxTimeoutMS`. Each call has
its own deadline. The wrapper supplies no automatic retry, reconnection, or payload
replay. Cancelling a Go context does not cancel a native call. Use `Stream.Cancel`
or destroy the owning engine from another goroutine, and wait for every admitted
call to return before releasing its buffers.

Obtain objects from `NewEngine`, `Connect`, `OpenStream`, and `OpenDatagram`.
Their zero values are invalid. Copying an object value shares its ownership
state. Raw handles are private and use the exact C `ariad_handle` type. Length
and count parameters use C `size_t` and are bounded before conversion to Go `int`.
The shared state mutex covers bookkeeping only, never a blocking C call.

| Operation | Ownership after completion |
| --- | --- |
| `Engine.Shutdown` | Invalidates sessions and their children. Engine remains for `Destroy`. |
| `Engine.Destroy` | Releases engine and children on normal completion, forced completion, or a teardown transport error. |
| `Session.Close` | Invalidates streams and associations. Session remains for `Destroy`. |
| `Session.Destroy` | Releases session and its children. |
| `Stream.EndWrite`, `Cancel`, `Reset` | Stream handle remains for `Destroy`. |
| `Association.Close` | Send and receive stop. Handle and negotiated getters remain for `Destroy`. |
| `Stream.Destroy`, `Association.Destroy` | Release that handle. |

There are no finalizers. Call `Destroy` explicitly and inspect cleanup errors.
Destroying an already released object, or a child invalidated by its parent,
is a local no-op. `ErrBusy` and invalid arguments preserve ownership; retain
the object and retry cleanup after contention is resolved. A concurrent call
may independently change its state.

`ErrInternal` stops ordinary calls for the affected engine. Keep the engine
object for `Destroy`, including a cleanup retry: native internal errors can
precede or interrupt teardown. The wrapper does not infer release from that
error. A close error can conservatively stop local use of descendants; destroying
the engine remains the cleanup path. `ErrTransport` from engine destroy still
invalidates engine and child handles.

`Engine.Shutdown`, `Engine.Destroy`, and `Session.Close` return `(forced, err)`.
`forced=true, err=nil` represents `ARIAD_FORCED`, separate from ordinary success.
After forced engine destruction, admitted calls can retain native runtime
cleanup until they return. Their memory must remain valid for their entire call.

## Buffers and outcomes

The wrapper passes `[]byte` storage directly to C and keeps it alive until the
call returns. The ABI never retains input pointers. Do not mutate input, access
output, or use overlapping buffers in another call while a call is active.
Only short text inputs are converted to `[]byte`; no `C.CString` or C allocation
is used for credentials, trust roots, or binary payloads.

| Method | Result |
| --- | --- |
| `Stream.Write(input, timeoutMS)` | Accepts one nonempty prefix of a `1..MaxCopy` byte input. Advance by the returned count after success. |
| `Stream.Read(output, timeoutMS)` | Copies a nonempty prefix into `1..MaxCopy` bytes of storage. Clean EOF is `(0, io.EOF)`. |
| `Association.Send(input, timeoutMS)` | Sends one whole message, including `nil` for an empty message. Returns `(dropped, err)`. |
| `Association.Recv(output, timeoutMS)` | Receives one whole message into `0..MaxCopy` bytes. `(0, nil)` is an empty message. |

Accepted data is locally admitted; it does not prove remote delivery. Failed
writes or sends report no accepted count and can retain transport effects.
Stop the exchange after an error. Do not replay that payload on the same or
a replacement connection, including after timeout or `ErrBusy`.

`Send` returns `dropped=true, err=nil` for the local `ARIAD_DROPPED` outcome.
Check `Association.DeliveryMode` and `Association.MaxPayload` after opening.
Those getters describe the negotiated association. Messages must fit that limit.
H2 uses reliable capsules and rejects `requireUnreliable=true` before inspecting
the destination or sending a request.

If a received datagram exceeds the supplied buffer, `ErrMessageTooLarge`
discards the entire message; it copies no prefix and leaves the buffer unchanged.
`Recv(nil, timeoutMS)` can receive an empty message and discards a nonempty
message with that error. Stream errors and EOF also leave the output unchanged.
Native status errors have type `Status`; use `errors.Is(err, ariad.ErrBusy)`
or `errors.As` to inspect them. Status text comes from `ariad_status_name`.

## Check versions and capabilities

`NewEngine` calls `CheckLibrary` before creating an engine. It compares the
library ABI against `ExpectedABI` and checks wire compatibility against
`ExpectedProtocol` and `ExpectedH2Binding`. These constants come from the compiled
C header. It also requires local H2 support.
`LibraryVersions`, `Supports`, and `DeclaredSupport` expose the
native metadata without network I/O. Local feature support does not prove peer
support or negotiated delivery. Declared target classes refer to the named Rust
target and do not inspect the current host or certify this Go binding.

The C ABI exposes H2 only. Rust H3 and host socket-protection hooks are outside
this module. Engine creation needs an IP:port endpoint, a certificate DNS
identity, and one nonempty DER root certificate within `MaxTrustRootDERBytes`.
Connect needs exactly `CredentialBytes` bytes. The native library checks
destination syntax, TLS identity, authentication, and destination authorization.

## Echo example

The [example](examples/echo/main.go) performs one four-byte TCP echo synchronously.
It advances by each accepted prefix, verifies replies, ends writes,
requires clean EOF, and checks explicit cleanup. It never retries payloads.
It needs a configured proxy and an authorized TCP echo destination. The echo
server must close its output after reading the client's EOF.

From the configured module directory:

```sh
export ARIAD_CREDENTIAL_HEX='<credential-hex>'
go run ./examples/echo '<endpoint-ip:port>' '<tls-name>' '<ca.der>' '<echo-destination>'
```

Replace every placeholder. Supply `CredentialHexBytes` hexadecimal digits for
`ARIAD_CREDENTIAL_HEX`. `go_h2_echo=ok bytes=4` is printed only after the
exchange and cleanup return successfully. The example clears its decoded
credential buffer after `Connect`; the environment and Go string are still
owned by the host process.
