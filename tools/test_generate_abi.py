from __future__ import annotations

import ast
import io
import re
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from tools import generate_abi as abi


class GeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (abi.ROOT / abi.HEADER).read_text(encoding="utf-8")

    def test_checked_in_outputs_match_all_sources(self) -> None:
        for path, expected in abi.generate_outputs(abi.ROOT).items():
            with self.subTest(path=path):
                self.assertEqual((abi.ROOT / path).read_text(encoding="utf-8"), expected)

    def test_integer_widths_and_complete_function_signatures(self) -> None:
        header = abi.parse_header(self.source)
        constants = {constant.name: constant for constant in header.constants}
        self.assertEqual(constants["ARIAD_MAX_COPY"].rust_type, "usize")
        self.assertEqual(constants["ARIAD_ABI_VERSION"].rust_type, "u32")
        self.assertEqual(constants["ARIAD_ERROR_INVALID_HANDLE"].rust_type, "i32")
        functions = {function.name: function for function in header.functions}
        self.assertEqual(functions["ariad_status_name"].result, "const char *")
        self.assertEqual(
            functions["ariad_engine_connect"].parameters,
            ("ariad_handle", "const uint8_t *", "size_t", "uint32_t", "ariad_handle *"),
        )
        rust = abi.rust_source(header)
        python = abi.python_signatures(header)
        self.assertEqual(re.findall(r"=\s*(ariad_[a-z0-9_]+);", rust), list(functions))
        for function in header.functions:
            self.assertIn(f'"{function.name}":', python)
        self.assertIn(
            'unsafe extern "C" fn(i32) -> *const std::ffi::c_char = ariad_status_name;', rust
        )
        self.assertIn('"ariad_abi_version": ([], _U32)', python)
        self.assertIn('"ariad_status_name": ([_I32], ctypes.c_char_p)', python)

    def test_new_status_reaches_every_generated_language(self) -> None:
        source = self.source + "\n#define ARIAD_ERROR_SAMPLE (-99)\n"
        header = abi.parse_header(source)
        rust = abi.rust_source(header)
        self.assertIn("pub const ARIAD_ERROR_SAMPLE: i32 = -99;", rust)
        self.assertIn('ARIAD_ERROR_SAMPLE => c"ARIAD_ERROR_SAMPLE".as_ptr()', rust)
        python = ast.parse(abi.python_constants(header))
        status = next(node for node in python.body if isinstance(node, ast.ClassDef))
        self.assertEqual(status.name, "Status")
        self.assertIn("    ERROR_SAMPLE = -99", abi.python_constants(header))
        self.assertIn("const val ERROR_SAMPLE = -99", abi.kotlin_source(header))

    def test_value_and_prototype_changes_update_outputs(self) -> None:
        source = self.source.replace(
            "#define ARIAD_MAX_COPY 65536u", "#define ARIAD_MAX_COPY 1024u"
        )
        source = source.replace("uint32_t timeout_ms", "uint16_t timeout_ms")
        header = abi.parse_header(source)
        self.assertIn("ARIAD_MAX_COPY: usize = 1024;", abi.rust_source(header))
        self.assertIn("MAX_COPY = 1024", abi.python_constants(header))
        self.assertIn(
            '"ariad_engine_connect": ([_HANDLE, _U8P, _SIZE, _U16, _HANDLEP], _I32)',
            abi.python_signatures(header),
        )

    def test_pointer_return_has_a_ctypes_alias(self) -> None:
        header = abi.parse_header(self.source + "\nuint16_t *ariad_sample(void);\n")
        python = abi.python_signatures(header)
        self.assertIn("_U16P = ctypes.POINTER(_U16)", python)
        self.assertIn('"ariad_sample": ([], _U16P)', python)
        self.assertIn('unsafe extern "C" fn() -> *mut u16 = ariad_sample;', abi.rust_source(header))

    def test_unsupported_macro_syntax_is_rejected(self) -> None:
        for value in ("(1 << 10)", "0x10u", "010u", "1UL", "4294967296u", "-1u"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                abi.parse_header(self.source + f"\n#define ARIAD_SAMPLE {value}\n")
        with self.assertRaisesRegex(ValueError, "unsupported C directive"):
            abi.parse_header(self.source + "\n#if SOME_FEATURE\n#endif\n")

    def test_duplicate_definitions_and_status_values_are_rejected(self) -> None:
        for definition in (
            "#define ARIAD_ABI_VERSION 2u",
            "#define ARIAD_ERROR_SAMPLE (-1)",
            "uint32_t ariad_abi_version(void);",
            "typedef uint64_t ariad_handle;",
        ):
            with self.subTest(definition=definition), self.assertRaises(ValueError):
                abi.parse_header(self.source + "\n" + definition + "\n")

    def test_unsupported_declarations_are_rejected(self) -> None:
        for declaration in (
            "int32_t ariad_sample(uint8_t **output);",
            "int32_t ariad_sample(unsigned long input);",
            "int32_t ariad_sample(int32_t (*callback)(void));",
            "int32_t ariad_sample(ariad_handle handle, ...);",
            "int32_t ariad_sample(ariad_handle handle)",
            "int32_t ariad_sample();",
        ):
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                abi.parse_header(self.source + "\n" + declaration + "\n")

    def test_wire_versions_follow_core_and_reject_new_grammar(self) -> None:
        source = (abi.ROOT / abi.WIRE_SOURCE).read_text(encoding="utf-8")
        source = source.replace("ProtocolVersion(0);", "ProtocolVersion(17);")
        self.assertIn("#define ARIAD_PROTOCOL_VERSION 17u", abi.wire_macros(source))
        for changed in (
            source.replace("ProtocolVersion(17);", "ProtocolVersion(65536);"),
            source.replace("ProtocolVersion(17);", "ProtocolVersion(1 + 16);"),
            source + "\npub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(17);\n",
        ):
            with self.subTest(source=changed), self.assertRaises(ValueError):
                abi.wire_macros(changed)

    def test_generated_regions_preserve_handwritten_code(self) -> None:
        source = (
            "retained_before\n# BEGIN GENERATED ABI CONSTANTS\nold\n"
            "# END GENERATED ABI CONSTANTS\nretained_after\n"
        )
        updated = abi.replace_region(source, "ABI CONSTANTS", "new\n")
        self.assertEqual(updated, source.replace("\nold\n", "\nnew\n"))
        for malformed in (
            "",
            source + source,
            "# END GENERATED ABI CONSTANTS\n# BEGIN GENERATED ABI CONSTANTS\n",
        ):
            with self.subTest(source=malformed), self.assertRaises(ValueError):
                abi.replace_region(malformed, "ABI CONSTANTS", "new")

    def test_credential_limits_follow_core_and_reject_new_grammar(self) -> None:
        source = (abi.ROOT / abi.CREDENTIAL_SOURCE).read_text(encoding="utf-8")
        source = source.replace("BYTE_LEN: usize = 32;", "BYTE_LEN: usize = 16;")
        macros = abi.credential_macros(source)
        self.assertIn("#define ARIAD_CREDENTIAL_BYTES 16u", macros)
        self.assertIn("#define ARIAD_CREDENTIAL_HEX_BYTES 32u", macros)
        for changed in (
            source.replace("BYTE_LEN: usize = 16;", "BYTE_LEN: usize = 0;"),
            source.replace("2 * Self::BYTE_LEN;", "Self::BYTE_LEN * 2;"),
            source + "\n    pub const BYTE_LEN: usize = 16;\n",
        ):
            with self.subTest(source=changed), self.assertRaises(ValueError):
                abi.credential_macros(changed)

    def test_trust_root_limit_uses_decimal_or_kib_and_rejects_other_expressions(self) -> None:
        source = (abi.ROOT / abi.TRUST_SOURCE).read_text(encoding="utf-8")
        for literal, expected in (("2048", 2048), ("32 * 1024", 32768)):
            changed = source.replace("16 * 1024;", literal + ";")
            self.assertIn(
                f"#define ARIAD_MAX_TRUST_ROOT_DER_BYTES {expected}u", abi.trust_root_macro(changed)
            )
        for literal in ("16 << 10", "16 * 512", "0", "4294967296", "016"):
            changed = source.replace("16 * 1024;", literal + ";")
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                abi.trust_root_macro(changed)

    def test_check_reports_drift_without_writing(self) -> None:
        error = io.StringIO()
        with (
            patch.object(
                abi,
                "generate_outputs",
                return_value={Path("crates/ffi/include/ariad.h"): "changed"},
            ),
            patch.object(Path, "write_text") as write,
            redirect_stderr(error),
        ):
            self.assertEqual(abi.main(["--check"]), 1)
        write.assert_not_called()
        self.assertIn("ABI output drift: crates/ffi/include/ariad.h", error.getvalue())


if __name__ == "__main__":
    unittest.main()
