# Python embedding

`ariad.py` is a dependency-free Python 3.10+ binding for the synchronous
[H2 C ABI](../../crates/ffi/include/ariad.h). Copy this module into the host
application, or add this directory to the application's module search path.
Supply an already-built `ariad-ffi` shared library for the host's architecture.
No package installation is required.

`Library(path)` resolves an explicit existing file path and loads it with
`ctypes.CDLL`. Typical library names are `ariad_ffi.dll`, `libariad_ffi.so`, and
`libariad_ffi.dylib`. The selected library must report `ABI_VERSION` and export
the functions in the header. The optional `ariad_status_name` query has a local
fallback for earlier ABI 1 libraries. ABI mismatch raises `AbiVersionError`.
Missing exports and loader failures are reported by `ctypes`.

## Host example

Run the complete native scope in a worker outside the UI or async event-loop
thread. Every native method is synchronous. Connect, open, stream I/O,
datagram I/O, session close, engine shutdown, and engine destroy can wait for
network or runtime work. Each timeout is `1..MAX_TIMEOUT_MS` milliseconds for
that call; transport limits may shorten it. The binding installs no runtime,
logger, signal handler, or process configuration of its own.

This example exchanges a small request with a destination that closes its
response after the client ends writes. The host supplies the endpoint IP and
port, certificate hostname, DER CA certificate, a credential containing
`CREDENTIAL_BYTES` bytes, allowed destination, and response consumer. Keep
credentials in host-managed storage. Do not print them.

```python
from ariad import Library, MAX_COPY, Status


def exchange(library_path, endpoint, identity, ca_der, credential,
             destination, payload, on_data):
    if not 1 <= len(payload) <= MAX_COPY:
        raise ValueError("this example accepts a small nonempty request")
    library = Library(library_path)
    with library.create_engine(endpoint, identity, ca_der,
                               cleanup_timeout_ms=5000) as engine:
        with engine.connect(credential, timeout_ms=5000) as session:
            with session.open_stream(destination, timeout_ms=5000) as stream:
                offset = 0
                while offset < len(payload):
                    offset += stream.write(payload[offset:], timeout_ms=5000)
                stream.end_write(timeout_ms=5000)
                while True:
                    chunk = stream.read(timeout_ms=5000)
                    if chunk == b"":
                        break
                    on_data(chunk)
    return engine.last_teardown_status
```

The returned status can be `Status.FORCED`: native cleanup may continue until
already admitted calls return. If used from `asyncio`, call the complete helper
through `await asyncio.to_thread(exchange, ...)`. The response consumer runs
in that worker; the host must marshal UI updates back to its UI thread.

For full duplex protocols or larger payloads, start a reader worker while a
writer worker submits at most `MAX_COPY` bytes per call. `CDLL` releases the GIL
during native calls. The binding holds only brief lifecycle locks; it permits
one read and one write, or one datagram send and one receive, concurrently.
Direction or native bookkeeping contention can return `ERROR_BUSY`.

## Outcomes and ownership

| Method | Result |
| --- | --- |
| `Library.create_engine(...)` | `Engine`; creation performs no network I/O |
| `Engine.connect(credential, timeout_ms=...)` | `Session` |
| `Session.open_stream(destination, timeout_ms=...)` | `Stream` |
| `Stream.write(data, timeout_ms=...)` | Accepted prefix length, in `1..len(data)` |
| `Stream.read(capacity=MAX_COPY, timeout_ms=...)` | Nonempty prefix, or `b""` for clean EOF |
| `Stream.end_write(timeout_ms=...)` | Local end accepted; further reads remain possible |
| `Session.close(mode=CloseMode.GRACEFUL, timeout_ms=...)` | `Status.OK` or `Status.FORCED`; child handles invalidated |
| `Engine.shutdown(timeout_ms=...)` | `Status.OK` or `Status.FORCED`; child handles invalidated |
| `Engine.destroy(timeout_ms=...)` | `Status.OK` or `Status.FORCED`; runtime released or cleanup deferred |

Construct handles through these factory methods. Engine, session, stream, and
association objects are context managers. Context exit calls `destroy()` once.
Explicit `destroy()` also works; an object already invalidated by a parent
teardown requires no further native call. Session and association `close()`
retain their own native handles until `destroy()`. Stream `cancel()` and
`reset()` retain its handle too. Engine shutdown retains the engine until
destroy. Parent references retain the library while child wrappers exist.
There is no finalizer that waits for the network.

After a native teardown, `last_teardown_status` records its numeric status,
including outcomes during context exit. A teardown `ERROR_BUSY` leaves ownership
intact and raises an exception. Release the contention before explicitly trying
teardown again. Transport errors from session close or engine shutdown still
invalidate children. Transport errors from engine destroy still invalidate the
engine. `ERROR_INTERNAL` disables normal operations on the affected engine;
destroy that engine. If an internal destroy error leaves ownership uncertain,
the wrapper retains its number only for an explicit teardown attempt. A later
native `ERROR_INVALID_HANDLE` confirms it is no longer live and is also reported.

When a context body raises, cleanup keeps that original exception. A cleanup
failure is recorded in `last_cleanup_error` and `last_teardown_status`. Python
3.11+ also adds a note when the body exception supports it. The host must inspect
these fields and finish teardown as needed. If the body succeeded, a cleanup
failure is raised normally. Explicit `destroy()` always reports its own failure.

Native errors raise `AriadError` with `operation`, numeric `status`, and
`status_name`. `HandleClosedError` reports local use after parent teardown or
engine failure. Invalid Python argument types and ranges fail before native
calls. `AbiContractError` reports invalid native counts or metadata.

Advance write offsets only by successful returned counts. Failed writes and
datagram sends can have transport effects. Their exceptions do not establish
rollback. Do not replay that payload on this connection or a replacement
connection. The binding performs no automatic retry or direct-connect fallback.

Cancellation of an `asyncio` await does not stop its worker. Retain the engine
and use explicit native cancellation or engine destruction from another worker
when interruption is required. Let admitted calls return. Their per-call storage
remains owned until their native function returns, even during concurrent teardown.
Do not mutate a source buffer while the binding copies it for a call.

## Datagrams

```python
from ariad import DeliveryMode, Status

with session.open_datagram(destination, timeout_ms=5000) as association:
    delivery = association.delivery_mode()
    limit = association.max_payload()
    outcome = association.send(b"", timeout_ms=5000)
    if outcome == Status.DROPPED:
        handle_local_drop()
    else:
        message = association.recv(capacity=limit, timeout_ms=5000)
        consume_message(message, delivery)
```

`send()` submits exactly one whole message, including `b""`. `Status.OK` means
local admission, not remote delivery. `Status.DROPPED` reports failed local
resource admission; it is returned explicitly. `recv()` returns one complete
message. A `b""` receive is an empty datagram. `recv(capacity=0)` can receive
that empty message. A larger message is discarded and raises
`ERROR_MESSAGE_TOO_LARGE`; no prefix is returned and no receive is retried.
Capacity is bounded by `MAX_COPY`. Use the negotiated `max_payload()` for sends.
The native ABI rejects a message above that negotiated limit before admission.

H2 uses reliable CONNECT-UDP capsules and rejects `require_unreliable=True`.
Local feature metadata does not establish peer negotiation. The reference daemon
requires a host UDP connector that supplies fragmentation protection and a
payload limit. Association `close()` discards buffered messages and prevents
send and receive; its metadata getters remain available until destroy.

`Library.supported(Feature.H2)` and the version methods report local metadata.
`Library.target(Target.IOS)` reports the declared named target classification,
not the current host or proof that this Python binding runs on that platform.
Python/native loading and platform interoperability remain unverified here.
The C ABI provides no host routing protection hook; applications that need one
must use the Rust `HostServices` path.

## Verification

`test_ariad.py` contains standard-library tests using a fake native library.
They cover ABI setup, partial I/O, errors without replay, empty datagrams,
and lifecycle invalidation without loading a native library or using the network.
Mocked tests, source parsing, and signature checks do not establish native
runtime correctness or platform support.
