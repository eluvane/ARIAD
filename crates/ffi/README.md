# Native embedding

`ariad-ffi` exposes the experimental H2 engine through [ariad.h](include/ariad.h).
The optional [ariad.hpp](include/ariad.hpp) adapter adds C++17 ownership types.
Both use the same C ABI and native library. The C++ adapter uses only the
standard library and leaves stream and datagram I/O in the C API.

## ABI definitions

[ariad.h](include/ariad.h) defines ABI constants and function signatures.
[Core version constants](../core/src/version.rs) define wire versions.
[Credential widths](../core/src/auth.rs) and
[TLS certificate limits](../engine/src/tls_policy.rs) define their native metadata.
[generate_abi.py](../../tools/generate_abi.py) derives Rust declarations, Python
constants and ctypes signatures, and Kotlin constants from these definitions.
Go, C++, and Swift use the C header directly. Keep generated sections unchanged
by hand. After editing a definition, run from the repository root:

```sh
python -B tools/generate_abi.py
python -B tools/generate_abi.py --check
python -B -m unittest discover -s tools -p 'test_*.py'
```

The check fails when an output differs from its source. Rust function-type
assertions also check implementation signatures against the C declarations when
the crate is compiled. The [Lint workflow](../../.github/workflows/lint.yml)
checks generated outputs without building Rust or loading the native library.

## Build and link

From the repository root, with the pinned Rust toolchain and target linker:

```sh
cargo build -p ariad-ffi --locked --release
```

The crate declares `lib`, `cdylib`, and `staticlib` outputs. Native output names
depend on the target toolchain. The expected artifacts are:

| Target family | Shared library | Static archive |
| --- | --- | --- |
| Linux | `libariad_ffi.so` | `libariad_ffi.a` |
| Apple | `libariad_ffi.dylib` where the target permits it | `libariad_ffi.a` |
| Windows MSVC | `ariad_ffi.dll` plus its import library | `ariad_ffi.lib` |

A Windows DLL import library and a static archive are different artifacts;
select the artifact produced for the intended link mode. They must not be
interchanged merely because both can have a `.lib` suffix. Add
`crates/ffi/include` to your include path and link the matching native library.
For shared linkage, keep the library available to the application's loader.
For static linkage, required platform system libraries and link flags depend
on the target and remain unverified. Headers and library must come from the
same checkout. Host release outputs normally live in `target/release`; an
explicit Cargo target adds a `target/<target-triple>/release` directory.

Keep the library loaded until engines, admitted calls, and deferred runtime
cleanup have all ended. `ARIAD_FORCED` does not establish that unloading is safe.
The ABI has no deferred-cleanup completion query; retain the module for the
process lifetime if the host cannot establish completion.

The [Linux C consumer job](../../.github/workflows/ci.yml) declares this debug
build and link procedure:

```sh
cargo build -p ariad-ffi --locked
cc -std=c11 -Wall -Wextra -Wpedantic -Werror -pthread \
  -I crates/ffi/include crates/ffi/tests/consumer.c \
  -L "$PWD/target/debug" -Wl,-rpath,"$PWD/target/debug" -lariad_ffi \
  -o target/debug/ariad-c-consumer
```

This is a repository procedure, not evidence of a successful local build or CI
run. The consumer uses a fixed test credential and the repository's echo fixture.
It is not a configured proxy client. Native C++ linkage, iOS, Android, and mobile
packaging remain unverified. The C ABI has no platform socket-protection hook;
hosts needing routing-loop protection must use the Rust `HostServices` API.

## C flow

Check `ariad_abi_version() == ARIAD_ABI_VERSION` before creating an engine.
ABI version 1 permits additive exports: an older ABI-1 library may lack
`ariad_status_name`. A dynamic loader must also check every required symbol.
The C++ adapter's status-name helper requires the export from the matching build.
The wire protocol and H2 binding versions have separate metadata functions;
checking them does not negotiate with a peer.

Keep numeric handles in caller-owned state. This opening helper leaves every
created handle in `client`, including when a later operation fails:

```c
#include "ariad.h"
#include <string.h>

typedef struct {
    ariad_handle engine;
    ariad_handle session;
    ariad_handle stream;
} native_client;

int32_t client_open(native_client *client, const char *endpoint,
                    const char *identity, const uint8_t *root, size_t root_len,
                    const uint8_t credential[ARIAD_CREDENTIAL_BYTES],
                    const char *destination) {
    if (client == NULL || endpoint == NULL || identity == NULL ||
        credential == NULL || destination == NULL || client->engine != 0 ||
        client->session != 0 || client->stream != 0) {
        return ARIAD_ERROR_INVALID_ARGUMENT;
    }
    int32_t status = ariad_engine_create(
        (const uint8_t *)endpoint, strlen(endpoint),
        (const uint8_t *)identity, strlen(identity), root, root_len, &client->engine);
    if (status != ARIAD_OK) {
        return status;
    }
    status = ariad_engine_connect(client->engine, credential,
                                  ARIAD_CREDENTIAL_BYTES, 10000,
                                  &client->session);
    if (status != ARIAD_OK) {
        return status;
    }
    return ariad_session_open_stream(
        client->session, (const uint8_t *)destination, strlen(destination),
        10000, &client->stream);
}
```

Start with `native_client client = {0};`. The endpoint is an IP address and port;
the identity is the certificate hostname. `root` is one DER trust certificate,
at most `ARIAD_MAX_TRUST_ROOT_DER_BYTES` bytes. The credential contains exactly
`ARIAD_CREDENTIAL_BYTES` bytes. The destination is
`host:port` or `[ipv6]:port`, without a trailing NUL in the transmitted range.
Creation performs no network I/O. Connecting establishes TLS 1.3 and H2;
authentication and destination authorization happen on each open.

Use `ariad_stream_write`, `ariad_stream_read`, and `ariad_stream_end_write` on
`client.stream`. Destroy the stream, close/destroy the session, then
shutdown/destroy the engine. Read the teardown status before changing stored
handles. `ARIAD_ERROR_BUSY` leaves ownership unchanged; retain the handle and
retry cleanup later under a caller-controlled deadline. Engine destroy also
retains ownership on invalid arguments. Other teardown errors can follow
invalidation, so they do not establish that the handle is reusable. Consult the
individual declarations in `ariad.h`.

Engine shutdown/destroy invalidates all child handles. Session close/destroy
invalidates its streams and associations. Shutdown keeps the engine handle;
session close keeps the session handle. Stream cancel/reset and association
close keep their own handles until destroy. The complete
[C consumer](tests/consumer.c) also shows partial stream I/O, association
messages, direction contention, and concurrent teardown.

## C++ ownership

The adapter provides `ariad::engine`, `ariad::session`, `ariad::stream`, and
`ariad::association`. They can be default constructed or move constructed, but
cannot be copied or move assigned. Factories return `ariad::result<T>` containing
the integer `code` and an owned `value`. An unsuccessful factory returns an empty
owner. Factory bookkeeping can throw `std::bad_alloc`; it is allocated before
the native create/connect/open call, so allocation failure cannot orphan a newly
published native handle.

Keep the owners together. Declaring the engine first gives reverse-order
destruction of its children:

```cpp
#include "ariad.hpp"

struct cpp_client {
    ariad::engine engine;
    ariad::session session;
    ariad::stream stream;
};

ariad::result<cpp_client> open_client(
    std::string_view endpoint, std::string_view identity,
    const std::uint8_t* root, std::size_t root_len,
    const std::uint8_t* credential, std::string_view destination) {
    auto engine = ariad::create_engine(endpoint, identity, root, root_len);
    if (engine.code != ARIAD_OK) {
        return {engine.code, cpp_client{}};
    }
    auto session = ariad::connect(engine.value, credential,
                                 ARIAD_CREDENTIAL_BYTES, 10000);
    if (session.code != ARIAD_OK) {
        return {session.code, cpp_client{}};
    }
    auto stream = ariad::open_stream(session.value, destination, 10000);
    if (stream.code != ARIAD_OK) {
        return {stream.code, cpp_client{}};
    }
    return {ARIAD_OK, {std::move(engine.value), std::move(session.value),
                       std::move(stream.value)}};
}
```

Call this helper from a native worker thread after checking the ABI version.
On an opening error, already-created local owners use their best-effort
destructors. The C flow is available when the host must observe and retain every
cleanup handle on such failures. The returned C++ client remains yours until
explicit cleanup or scope exit. I/O uses a borrowed number:

```cpp
std::size_t accepted = 0;
const auto code = ariad_stream_write(client.stream.native_handle(),
                                     payload, payload_size, 10000, &accepted);
```

Here `client` is a live `cpp_client`, and `payload` stays readable and unchanged
until the call returns. On `ARIAD_OK`, advance by `accepted`, which can be smaller
than `payload_size`. On any error, do not replay that payload. Handle the numeric
status before preparing another write.

For observable cleanup, call `client.stream.destroy()`,
`ariad::close(client.session, ARIAD_CLOSE_GRACEFUL, timeout_ms)`,
`client.session.destroy()`, `ariad::shutdown(client.engine, timeout_ms)`, and
`ariad::destroy(client.engine, timeout_ms)` as needed. Calls preserve returned
native statuses; locally invalid owners return `ARIAD_ERROR_INVALID_HANDLE`.
`destroy()` without an argument uses 1000 ms for engines; child destroy
calls have no network-drain timeout in the C ABI.

Explicit destroy retains the owner on `ARIAD_ERROR_BUSY` or
`ARIAD_ERROR_INVALID_ARGUMENT`. Keep the object alive if cleanup needs a later
retry. `ARIAD_OK` and `ARIAD_ERROR_INVALID_HANDLE` clear stored ownership.
Engine destroy also clears it on `ARIAD_FORCED` or `ARIAD_ERROR_TRANSPORT`, which
follow native invalidation. Internal and other uncertain destroy outcomes retain
the raw owned number for explicit teardown, while quarantining ordinary handle
use across the engine family. `native_handle()` then returns zero, and boolean
conversion is false. Explicit `destroy()` still uses the retained number:
call it even when boolean conversion is false after an uncertain cleanup result.
This policy does not prove that native cleanup completed.

Destructors are `noexcept` and make at most one cleanup attempt. They discard the
status and any unresolved ownership; a busy or interrupted cleanup can leave
native resources live. The engine's 1000 ms destructor timeout requests the
native deadline and does not bound all cleanup work.

Wrapper shutdown/close/destroy tracks parent invalidation. Successful parent
teardown and uncertain outcomes invalidate tracked descendants, whose
`native_handle()` then returns zero. Busy and invalid-argument failures leave
tracking unchanged. The shared bookkeeping does not keep the native parent
alive. A wrapper's boolean conversion reports only tracked handle
validity, not connection health. Raw C teardown on a borrowed `native_handle()`
bypasses this bookkeeping; use the wrapper teardown helpers for tracked parents.
The wrapper observes internal errors from its own factory and teardown calls.
It cannot observe an internal error returned by raw C I/O. After such an error,
stop ordinary calls and explicitly destroy the affected engine.
Ownership access and mutation across one wrapper family need external
synchronization. To use the C ABI's concurrent I/O directions, copy the borrowed
handle while synchronized and keep call buffers alive until their own calls
return.

## I/O and status rules

- Calls are synchronous. Run network calls and owner destruction outside GUI or
  event-loop threads and outside Tokio tasks. One runtime thread per engine
  advances transport work between calls.
- Each network timeout is `1..ARIAD_MAX_TIMEOUT_MS` milliseconds. It applies to
  one operation; transport phase limits can shorten it. Repeated operations need
  a separate total budget in the host.
- Stream read/write payloads are `1..ARIAD_MAX_COPY` bytes per call. Writes
  report only the accepted prefix. Reads return a prefix or `ARIAD_EOF` with
  zero bytes. Accepted data does not prove remote delivery. Errors report zero
  counts and can retain transport effects; a timeout does not prove rollback.
- Use `ariad::open_datagram(session, destination, require_unreliable, timeout_ms)`
  for an association. H2 rejects `require_unreliable=true`. Query the negotiated
  mode and payload limit through `ariad_association_delivery_mode` and
  `ariad_association_max_payload`; feature metadata does not establish them.
- Association send/recv operates on whole messages, including empty messages.
  `ARIAD_DROPPED` is an explicit send outcome. A too-small receive buffer discards
  the message and returns `ARIAD_ERROR_MESSAGE_TOO_LARGE`, without copying a
  prefix. A zero-byte successful receive is not stream EOF. Failed sends must
  not be replayed.
- Handle `ARIAD_OK`, `ARIAD_EOF`, `ARIAD_FORCED`, and `ARIAD_DROPPED` according to
  the operation. Preserve unknown integer statuses. `ariad_status_name(code)`
  and `ariad::status_name(code)` return a static C string, or
  `ARIAD_STATUS_UNKNOWN`; log the number as well. The string is read-only and
  remains valid only while the library is loaded.
- `ARIAD_ERROR_INTERNAL` requires teardown of the affected engine. Unwinding
  Rust panics are caught only with `panic=unwind`; aborts and invalid caller
  memory are outside this boundary.

All caller buffers remain valid for the complete synchronous call, even during
concurrent parent destruction. Input is borrowed and never retained as a native
pointer. Outputs must be aligned, writable, exclusive, and disjoint from other
argument ranges. Null/length checks do not validate memory.

This adapter and its snippets have received static inspection only. C++
compilation, native linkage, runtime behavior, and mobile builds are unrun.
