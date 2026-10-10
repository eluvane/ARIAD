from __future__ import annotations

import ctypes
import tempfile
import unittest
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import ariad

if TYPE_CHECKING:
    from collections.abc import Callable


def set_output(pointer: Any, c_type: Any, value: int) -> None:
    ctypes.cast(pointer, ctypes.POINTER(c_type))[0] = value


class FakeFunction:
    def __init__(self, owner: FakeNative, name: str) -> None:
        self.owner = owner
        self.name = name
        self.calls: list[tuple[Any, ...]] = []
        self.argtypes: list[Any] = []
        self.restype: Any = None

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        self.owner.calls.append(self.name)
        if self.name in self.owner.handlers:
            return self.owner.handlers[self.name](*args)
        if self.name == "ariad_abi_version":
            return self.owner.abi_version
        if self.name == "ariad_status_name":
            try:
                return ("ARIAD_" + ariad.Status(args[0]).name).encode("ascii")
            except ValueError:
                return b"ARIAD_STATUS_UNKNOWN"
        if self.name in (
            "ariad_engine_create",
            "ariad_engine_connect",
            "ariad_session_open_stream",
            "ariad_session_open_datagram",
        ):
            self.owner.next_handle += 1
            set_output(args[-1], ctypes.c_uint64, self.owner.next_handle)
        elif self.name == "ariad_stream_write":
            set_output(args[-1], ctypes.c_size_t, args[2])
        elif self.name == "ariad_stream_read":
            return ariad.Status.EOF
        elif self.name == "ariad_association_delivery_mode":
            set_output(args[-1], ctypes.c_uint32, ariad.DeliveryMode.RELIABLE)
        elif self.name == "ariad_association_max_payload":
            set_output(args[-1], ctypes.c_size_t, 1200)
        elif self.name == "ariad_supported":
            return 1 if args[0] == ariad.Feature.H2 else 0
        elif self.name == "ariad_wire_compatible":
            return int(args == (ariad.PROTOCOL_VERSION, ariad.H2_BINDING_VERSION))
        return ariad.Status.OK


class FakeNative:
    def __init__(self, *, abi_version: int = ariad.ABI_VERSION, status_query: bool = False) -> None:
        self.abi_version = abi_version
        self.status_query = status_query
        self.next_handle = 0
        self.handlers: dict[str, Callable[..., Any]] = {}
        self.functions: dict[str, FakeFunction] = {}
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> FakeFunction:
        if name == "ariad_status_name" and not self.status_query:
            raise AttributeError(name)
        if name not in self.functions:
            self.functions[name] = FakeFunction(self, name)
        return self.functions[name]


class BindingTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "ariad-test-library"
        self.path.touch()
        self.native = FakeNative()
        loader = patch("ariad.ctypes.CDLL", return_value=self.native)
        self.loader = loader.start()
        self.addCleanup(loader.stop)
        self.library = ariad.Library(self.path)

    def handles(self) -> tuple[ariad.Engine, ariad.Session, ariad.Stream]:
        engine = self.library.create_engine("127.0.0.1:443", "localhost", b"fake-der")
        session = engine.connect(bytes(ariad.CREDENTIAL_BYTES))
        stream = session.open_stream("localhost:7")
        return engine, session, stream

    def test_explicit_loader_and_widths(self) -> None:
        self.loader.assert_called_once_with(str(self.path.resolve()))
        self.assertEqual(self.native.ariad_abi_version.restype, ctypes.c_uint32)
        self.assertEqual(
            self.native.ariad_engine_create.argtypes[-1], ctypes.POINTER(ctypes.c_uint64)
        )
        self.assertEqual(
            self.native.ariad_engine_connect.argtypes,
            [
                ctypes.c_uint64,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint64),
            ],
        )
        self.assertEqual(
            self.native.ariad_stream_read.argtypes,
            [
                ctypes.c_uint64,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_size_t),
            ],
        )
        self.assertEqual(self.native.ariad_stream_read.restype, ctypes.c_int32)
        self.assertEqual(self.native.ariad_protocol_version.restype, ctypes.c_uint16)
        self.assertEqual(self.native.ariad_h2_binding_version.restype, ctypes.c_uint16)

    def test_abi_mismatch_precedes_operation_binding(self) -> None:
        wrong = FakeNative(abi_version=ariad.ABI_VERSION + 1)
        self.loader.return_value = wrong
        with self.assertRaises(ariad.AbiVersionError):
            ariad.Library(self.path)
        self.assertEqual(wrong.calls, ["ariad_abi_version"])
        self.assertEqual(list(wrong.functions), ["ariad_abi_version"])

    def test_status_query_and_old_abi_fallback(self) -> None:
        self.assertEqual(self.library.status_name(-24), "ARIAD_ERROR_DEADLINE")
        self.assertEqual(self.library.status_name(-999), "ARIAD_STATUS_UNKNOWN")
        current = FakeNative(status_query=True)
        self.loader.return_value = current
        library = ariad.Library(self.path)
        self.assertEqual(current.ariad_status_name.argtypes, [ctypes.c_int32])
        self.assertEqual(current.ariad_status_name.restype, ctypes.c_char_p)
        self.assertEqual(library.status_name(-3), "ARIAD_ERROR_BUSY")

    def test_partial_write_and_clean_eof(self) -> None:
        engine, _session, stream = self.handles()

        def write(_handle: int, buffer: Any, size: int, _timeout_ms: int, count: Any) -> int:
            self.assertEqual(bytes(buffer), b"hello")
            self.assertEqual(size, 5)
            set_output(count, ctypes.c_size_t, 2)
            return ariad.Status.OK

        def read(_handle: int, buffer: Any, _capacity: int, _timeout_ms: int, count: Any) -> int:
            ctypes.memmove(buffer, b"hi", 2)
            set_output(count, ctypes.c_size_t, 2)
            return ariad.Status.OK

        self.native.handlers["ariad_stream_write"] = write
        self.native.handlers["ariad_stream_read"] = read
        self.assertEqual(stream.write(b"hello"), 2)
        self.assertEqual(len(self.native.ariad_stream_write.calls), 1)
        self.assertEqual(stream.read(8), b"hi")
        stream.end_write()
        self.native.handlers.pop("ariad_stream_read")
        self.assertEqual(stream.read(), b"")
        engine.destroy()

    def test_write_failure_is_reported_without_replay(self) -> None:
        engine, _session, stream = self.handles()
        self.native.handlers["ariad_stream_write"] = lambda *_args: ariad.Status.ERROR_DEADLINE
        with self.assertRaises(ariad.AriadError) as caught:
            stream.write(b"ambiguous")
        self.assertEqual(caught.exception.status, ariad.Status.ERROR_DEADLINE)
        self.assertEqual(caught.exception.operation, "ariad_stream_write")
        self.assertEqual(len(self.native.ariad_stream_write.calls), 1)
        self.assertEqual(len(self.native.ariad_engine_connect.calls), 1)
        engine.destroy()

    def test_read_error_is_not_eof_and_invalid_count_is_rejected(self) -> None:
        engine, _session, stream = self.handles()
        self.native.handlers["ariad_stream_read"] = lambda *_args: ariad.Status.ERROR_TRUNCATED
        with self.assertRaises(ariad.AriadError) as caught:
            stream.read()
        self.assertEqual(caught.exception.status, ariad.Status.ERROR_TRUNCATED)
        self.native.handlers["ariad_stream_read"] = lambda *_args: ariad.Status.OK
        with self.assertRaises(ariad.AbiContractError):
            stream.read()
        engine.destroy()

    def test_datagrams_preserve_empty_messages_and_explicit_drop(self) -> None:
        engine, session, _stream = self.handles()
        association = session.open_datagram("localhost:53")
        self.assertEqual(association.delivery_mode(), ariad.DeliveryMode.RELIABLE)
        self.assertEqual(association.max_payload(), 1200)
        self.assertEqual(association.send(b""), ariad.Status.OK)
        args = self.native.ariad_association_send.calls[-1]
        self.assertIsNone(args[1])
        self.assertEqual(args[2], 0)
        self.assertEqual(association.recv(capacity=0), b"")
        args = self.native.ariad_association_recv.calls[-1]
        self.assertIsNone(args[1])
        self.assertEqual(args[2], 0)
        self.native.handlers["ariad_association_send"] = lambda *_args: ariad.Status.DROPPED
        self.assertEqual(association.send(b"message"), ariad.Status.DROPPED)
        association.close()
        self.assertEqual(association.max_payload(), 1200)
        with self.assertRaises(ariad.HandleClosedError):
            association.send(b"")
        engine.destroy()

    def test_oversize_datagram_receive_is_not_retried(self) -> None:
        engine, session, _stream = self.handles()
        association = session.open_datagram("localhost:53")
        self.native.handlers["ariad_association_recv"] = lambda *_args: (
            ariad.Status.ERROR_MESSAGE_TOO_LARGE
        )
        with self.assertRaises(ariad.AriadError) as caught:
            association.recv(capacity=2)
        self.assertEqual(caught.exception.status, ariad.Status.ERROR_MESSAGE_TOO_LARGE)
        self.assertEqual(len(self.native.ariad_association_recv.calls), 1)
        engine.destroy()

    def test_session_close_invalidates_children_but_retains_session(self) -> None:
        engine, session, stream = self.handles()
        self.native.handlers["ariad_session_close"] = lambda *_args: ariad.Status.FORCED
        self.assertEqual(session.close(), ariad.Status.FORCED)
        self.assertEqual(session.last_teardown_status, ariad.Status.FORCED)
        with self.assertRaises(ariad.HandleClosedError):
            stream.read()
        with self.assertRaises(ariad.HandleClosedError):
            session.open_stream("localhost:7")
        self.assertEqual(stream.destroy(), ariad.Status.OK)
        self.assertEqual(len(self.native.ariad_stream_destroy.calls), 0)
        self.assertEqual(session.destroy(), ariad.Status.OK)
        self.assertEqual(len(self.native.ariad_session_destroy.calls), 1)
        engine.destroy()

    def test_shutdown_transport_error_invalidates_children(self) -> None:
        engine, _session, stream = self.handles()
        self.native.handlers["ariad_engine_shutdown"] = lambda *_args: ariad.Status.ERROR_TRANSPORT
        with self.assertRaises(ariad.AriadError):
            engine.shutdown()
        with self.assertRaises(ariad.HandleClosedError):
            stream.read()
        with self.assertRaises(ariad.HandleClosedError):
            engine.connect(bytes(ariad.CREDENTIAL_BYTES))
        self.assertEqual(engine.destroy(), ariad.Status.OK)

    def test_busy_destroy_retains_ownership(self) -> None:
        engine, _session, stream = self.handles()
        self.native.handlers["ariad_engine_destroy"] = lambda *_args: ariad.Status.ERROR_BUSY
        with self.assertRaises(ariad.AriadError) as caught:
            engine.destroy()
        self.assertEqual(caught.exception.status, ariad.Status.ERROR_BUSY)
        self.assertEqual(stream.write(b"still-owned"), 11)
        self.native.handlers.pop("ariad_engine_destroy")
        self.assertEqual(engine.destroy(), ariad.Status.OK)
        self.assertEqual(len(self.native.ariad_engine_destroy.calls), 2)

    def test_child_destroy_preserves_retry_and_invalidation(self) -> None:
        for kind in ("session", "stream", "association"):
            for status in (
                ariad.Status.ERROR_BUSY,
                ariad.Status.ERROR_INVALID_ARGUMENT,
                ariad.Status.ERROR_INVALID_HANDLE,
            ):
                with self.subTest(kind=kind, status=status):
                    engine, session, stream = self.handles()
                    children = {
                        "session": session,
                        "stream": stream,
                        "association": session.open_datagram("localhost:53"),
                    }
                    child = children[kind]
                    operation = f"ariad_{kind}_destroy"
                    function = getattr(self.native, operation)
                    baseline = len(function.calls)
                    self.native.handlers[operation] = lambda *_args, status=status: status
                    with self.assertRaises(ariad.AriadError) as caught:
                        child.destroy()
                    self.assertEqual(caught.exception.operation, operation)
                    self.assertEqual(caught.exception.status, status)
                    self.assertEqual(child.last_teardown_status, status)
                    self.native.handlers.pop(operation)
                    self.assertEqual(child.destroy(), ariad.Status.OK)
                    self.assertEqual(child.destroy(), ariad.Status.OK)
                    attempts = 1 if status == ariad.Status.ERROR_INVALID_HANDLE else 2
                    self.assertEqual(len(function.calls), baseline + attempts)
                    engine.destroy()

    def test_internal_failure_requires_engine_teardown(self) -> None:
        engine, _session, stream = self.handles()
        self.native.handlers["ariad_stream_read"] = lambda *_args: ariad.Status.ERROR_INTERNAL
        with self.assertRaises(ariad.AriadError):
            stream.read()
        with self.assertRaises(ariad.HandleClosedError):
            stream.write(b"payload")
        with self.assertRaises(ariad.HandleClosedError):
            engine.connect(bytes(ariad.CREDENTIAL_BYTES))
        self.native.handlers["ariad_engine_destroy"] = lambda *_args: ariad.Status.ERROR_INTERNAL
        with self.assertRaises(ariad.AriadError):
            engine.destroy()
        self.native.handlers["ariad_engine_destroy"] = lambda *_args: (
            ariad.Status.ERROR_INVALID_HANDLE
        )
        with self.assertRaises(ariad.AriadError) as caught:
            engine.destroy()
        self.assertEqual(caught.exception.status, ariad.Status.ERROR_INVALID_HANDLE)
        self.assertEqual(engine.destroy(), ariad.Status.OK)
        self.assertEqual(len(self.native.ariad_engine_destroy.calls), 2)

    def test_context_exit_order_and_forced_outcome(self) -> None:
        self.native.handlers["ariad_engine_destroy"] = lambda *_args: ariad.Status.FORCED
        with (
            self.library.create_engine("127.0.0.1:443", "localhost", b"fake-der") as engine,
            engine.connect(bytes(ariad.CREDENTIAL_BYTES)) as session,
            session.open_stream("localhost:7"),
        ):
            pass
        self.assertEqual(
            self.native.calls[-3:],
            ["ariad_stream_destroy", "ariad_session_destroy", "ariad_engine_destroy"],
        )
        self.assertEqual(engine.last_teardown_status, ariad.Status.FORCED)
        self.assertFalse(hasattr(ariad.Engine, "__del__"))

    def test_context_cleanup_failure_preserves_body_error(self) -> None:
        for status in (ariad.Status.ERROR_BUSY, ariad.Status.ERROR_INTERNAL):
            with self.subTest(status=status):
                self.native.handlers["ariad_engine_destroy"] = lambda *_args, status=status: status
                body_error = ValueError("host operation failed")
                with (
                    self.assertRaises(ValueError) as caught,
                    self.library.create_engine("127.0.0.1:443", "localhost", b"fake-der") as engine,
                ):
                    raise body_error
                self.assertIs(caught.exception, body_error)
                self.assertIsInstance(engine.last_cleanup_error, ariad.AriadError)
                cleanup_error = cast("ariad.AriadError", engine.last_cleanup_error)
                self.assertEqual(cleanup_error.status, status)
                self.assertEqual(engine.last_teardown_status, status)
                if hasattr(body_error, "add_note"):
                    self.assertIn("ARIAD context cleanup failed:", vars(body_error)["__notes__"][0])
                self.native.handlers.pop("ariad_engine_destroy")
                engine.destroy()

    def test_context_cleanup_failure_raises_when_body_succeeded(self) -> None:
        self.native.handlers["ariad_engine_destroy"] = lambda *_args: ariad.Status.ERROR_BUSY
        with (
            self.assertRaises(ariad.AriadError) as caught,
            self.library.create_engine("127.0.0.1:443", "localhost", b"fake-der") as engine,
        ):
            pass
        self.assertEqual(caught.exception.status, ariad.Status.ERROR_BUSY)
        self.assertIs(engine.last_cleanup_error, caught.exception)
        self.assertEqual(engine.last_teardown_status, ariad.Status.ERROR_BUSY)
        self.native.handlers.pop("ariad_engine_destroy")
        engine.destroy()

    def test_cleanup_note_failure_does_not_replace_body_error(self) -> None:
        self.native.handlers["ariad_engine_destroy"] = lambda *_args: ariad.Status.ERROR_BUSY
        body_error = ValueError("host operation failed")
        vars(body_error)["__notes__"] = 0
        with (
            self.assertRaises(ValueError) as caught,
            self.library.create_engine("127.0.0.1:443", "localhost", b"fake-der") as engine,
        ):
            raise body_error
        self.assertIs(caught.exception, body_error)
        self.assertIsInstance(engine.last_cleanup_error, ariad.AriadError)
        cleanup_error = cast("ariad.AriadError", engine.last_cleanup_error)
        self.assertEqual(cleanup_error.status, ariad.Status.ERROR_BUSY)
        self.native.handlers.pop("ariad_engine_destroy")
        engine.destroy()

    def test_parent_teardown_during_open_does_not_publish_local_child(self) -> None:
        def open_after_close(close: Callable[[], ariad.Status], *args: Any) -> int:
            close()
            set_output(args[-1], ctypes.c_uint64, 2)
            return ariad.Status.OK

        for operation in (
            "ariad_engine_connect",
            "ariad_session_open_stream",
            "ariad_session_open_datagram",
        ):
            with self.subTest(operation=operation):
                engine = self.library.create_engine("127.0.0.1:443", "localhost", b"fake-der")
                close: Callable[[], ariad.Status]
                opening: Callable[[], ariad._Handle]
                if operation == "ariad_engine_connect":
                    close = engine.shutdown
                    opening = partial(engine.connect, bytes(ariad.CREDENTIAL_BYTES))
                else:
                    session = engine.connect(bytes(ariad.CREDENTIAL_BYTES))
                    close = session.close
                    opening = partial(
                        session.open_stream
                        if operation == "ariad_session_open_stream"
                        else session.open_datagram,
                        "localhost:7",
                    )
                self.native.handlers[operation] = partial(open_after_close, close)
                with self.assertRaises(ariad.HandleClosedError):
                    opening()
                self.native.handlers.pop(operation)
                engine.destroy()

    def test_invalid_arguments_fail_before_native_calls(self) -> None:
        engine, session, stream = self.handles()
        baseline = len(self.native.calls)
        for action, error in (
            (lambda: stream.write(b""), ValueError),
            (lambda: stream.write(b"a" * (ariad.MAX_COPY + 1)), ValueError),
            (lambda: stream.read(0), ValueError),
            (lambda: stream.read(timeout_ms=True), TypeError),
            (lambda: engine.connect(bytes(ariad.CREDENTIAL_BYTES - 1)), ValueError),
            (lambda: session.close(mode=cast("ariad.CloseMode", True)), TypeError),
            (lambda: session.open_stream("localhost:7\x00"), ValueError),
            (
                lambda: session.open_datagram("localhost:53", require_unreliable=cast("bool", 1)),
                TypeError,
            ),
        ):
            with self.assertRaises(error):
                action()
        self.assertEqual(len(self.native.calls), baseline)
        engine.destroy()

    def test_trust_root_limit_retains_python_validation(self) -> None:
        engine = self.library.create_engine(
            "127.0.0.1:443", "localhost", bytes(ariad.MAX_TRUST_ROOT_DER_BYTES)
        )
        self.assertEqual(
            self.native.ariad_engine_create.calls[-1][5], ariad.MAX_TRUST_ROOT_DER_BYTES
        )
        baseline = len(self.native.calls)
        for root in (b"", bytes(ariad.MAX_TRUST_ROOT_DER_BYTES + 1)):
            with self.subTest(length=len(root)), self.assertRaises(ValueError):
                self.library.create_engine("127.0.0.1:443", "localhost", root)
        self.assertEqual(len(self.native.calls), baseline)
        engine.destroy()


if __name__ == "__main__":
    unittest.main()
