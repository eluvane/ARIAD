"""Generate checked-in bindings for the header's numeric macros and C prototypes."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = Path("crates/ffi/include/ariad.h")
WIRE_SOURCE = Path("crates/core/src/version.rs")
CREDENTIAL_SOURCE = Path("crates/core/src/auth.rs")
TRUST_SOURCE = Path("crates/engine/src/tls_policy.rs")
RUST = Path("crates/ffi/src/abi.rs")
PYTHON = Path("bindings/python/ariad.py")
KOTLIN = Path("bindings/mobile/android/AriadConstants.kt")

SCALARS = {
    "uint8_t": ("u8", "_U8", "ctypes.c_uint8"),
    "uint16_t": ("u16", "_U16", "ctypes.c_uint16"),
    "uint32_t": ("u32", "_U32", "ctypes.c_uint32"),
    "uint64_t": ("u64", "_U64", "ctypes.c_uint64"),
    "int32_t": ("i32", "_I32", "ctypes.c_int32"),
    "size_t": ("usize", "_SIZE", "ctypes.c_size_t"),
}
RUST_CONSTANT_TYPES = {
    "ARIAD_MAX_COPY": "usize",
    "ARIAD_PROTOCOL_VERSION": "u16",
    "ARIAD_H2_BINDING_VERSION": "u16",
    "ARIAD_MAX_TEXT": "usize",
    "ARIAD_CREDENTIAL_BYTES": "usize",
    "ARIAD_CREDENTIAL_HEX_BYTES": "usize",
    "ARIAD_MAX_TRUST_ROOT_DER_BYTES": "usize",
}
ENUM_PREFIXES = (
    ("CloseMode", "ARIAD_CLOSE_"),
    ("DeliveryMode", "ARIAD_DELIVERY_"),
    ("Feature", "ARIAD_FEATURE_"),
    ("Target", "ARIAD_TARGET_"),
    ("TargetClass", "ARIAD_TARGET_CLASS_"),
)


@dataclass(frozen=True)
class Constant:
    name: str
    value: int
    unsigned: bool

    @property
    def rust_type(self) -> str:
        return RUST_CONSTANT_TYPES.get(self.name, "u32" if self.unsigned else "i32")

    @property
    def is_status(self) -> bool:
        return self.name.startswith("ARIAD_ERROR_") or self.name in (
            "ARIAD_OK",
            "ARIAD_EOF",
            "ARIAD_FORCED",
            "ARIAD_DROPPED",
        )


@dataclass(frozen=True)
class Function:
    name: str
    result: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class Header:
    handle_type: str
    constants: tuple[Constant, ...]
    functions: tuple[Function, ...]


def base_type(c_type: str) -> str:
    return c_type.removeprefix("const ").removesuffix(" *")


def normalize_type(value: str) -> str:
    value = re.sub(r"\s*\*\s*", " *", value.strip())
    value = " ".join(value.split())
    base = base_type(value)
    if value == "const char *":
        return value
    if base not in (*SCALARS, "ariad_handle"):
        raise ValueError(f"unsupported C type: {value}")
    if value not in (base, f"{base} *", f"const {base} *"):
        raise ValueError(f"unsupported C type: {value}")
    return value


def parse_header(source: str) -> Header:
    """Accept the ABI's fixed-width scalars and single-level named pointers."""
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)
    constants: dict[str, Constant] = {}
    declarations = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#define") and stripped != "#define ARIAD_H":
            match = re.fullmatch(r"#define\s+(ARIAD_[A-Z0-9_]+)\s+(.+)", stripped)
            if match is None:
                raise ValueError(f"unsupported C macro: {stripped}")
            name, value = match.groups()
            if name in constants:
                raise ValueError(f"duplicate C macro: {name}")
            if value.startswith("(") and value.endswith(")"):
                value = value[1:-1].strip()
            literal = re.fullmatch(r"(-?(?:0|[1-9][0-9]*))(u?)", value, flags=re.IGNORECASE)
            if literal is None:
                raise ValueError(f"unsupported C macro value: {name} {value}")
            number, suffix = literal.groups()
            constant = Constant(name, int(number), bool(suffix))
            minimum, maximum = (0, 2**32 - 1) if suffix else (-(2**31), 2**31 - 1)
            if not minimum <= constant.value <= maximum:
                raise ValueError(f"C macro outside its integer range: {name}")
            if constant.rust_type == "u16" and not 0 <= constant.value <= 65535:
                raise ValueError(f"wire version outside uint16_t range: {name}")
            if constant.rust_type == "usize" and constant.value < 0:
                raise ValueError(f"size constant must be nonnegative: {name}")
            constants[name] = constant
        elif stripped.startswith("#"):
            if stripped not in (
                "#ifndef ARIAD_H",
                "#define ARIAD_H",
                "#ifdef __cplusplus",
                "#endif",
                "#include <stddef.h>",
                "#include <stdint.h>",
            ):
                raise ValueError(f"unsupported C directive: {stripped}")
        elif stripped not in ('extern "C" {', "}"):
            declarations.append(line)
    body = "\n".join(declarations).strip()
    if not body.endswith(";"):
        raise ValueError("C declarations must end with a semicolon")
    handle_type = ""
    functions: dict[str, Function] = {}
    for declaration in body[:-1].split(";"):
        declaration = declaration.strip()
        if declaration == "typedef uint64_t ariad_handle":
            if handle_type:
                raise ValueError("duplicate ariad_handle typedef")
            handle_type = "uint64_t"
            continue
        match = re.fullmatch(r"(.+?)\b(ariad_[a-z0-9_]+)\s*\((.*)\)", declaration, re.DOTALL)
        if match is None:
            raise ValueError(f"unsupported C declaration: {declaration}")
        result, name, parameters = match.groups()
        if name in functions:
            raise ValueError(f"duplicate C function: {name}")
        types = []
        if parameters.strip() != "void":
            for parameter in parameters.split(","):
                parameter_match = re.fullmatch(r"(.+[\s*])([A-Za-z_]\w*)", parameter.strip())
                if parameter_match is None:
                    raise ValueError(f"unsupported C parameter: {parameter}")
                types.append(normalize_type(parameter_match[1]))
        functions[name] = Function(name, normalize_type(result), tuple(types))
    if not handle_type or not constants or not functions:
        raise ValueError("header needs ariad_handle, constants, and functions")
    statuses = [constant for constant in constants.values() if constant.is_status]
    if any(constant.unsigned for constant in statuses):
        raise ValueError("operation statuses must be signed int32_t literals")
    if len({constant.value for constant in statuses}) != len(statuses):
        raise ValueError("operation statuses must have distinct values")
    return Header(handle_type, tuple(constants.values()), tuple(functions.values()))


def replace_region(
    source: str, name: str, content: str, *, c_comment: bool = False, blank_lines: int = 0
) -> str:
    begin = f"/* BEGIN GENERATED {name} */" if c_comment else f"# BEGIN GENERATED {name}"
    end = f"/* END GENERATED {name} */" if c_comment else f"# END GENERATED {name}"
    if source.count(begin) != 1 or source.count(end) != 1:
        raise ValueError(f"expected exactly one generated region: {name}")
    start = source.index(begin) + len(begin)
    finish = source.index(end)
    if finish < start:
        raise ValueError(f"reversed generated region: {name}")
    return source[:start] + "\n" + content.rstrip() + "\n" * (blank_lines + 1) + source[finish:]


def wire_macros(source: str) -> str:
    lines = [f"/* Generated from {WIRE_SOURCE.as_posix()}. */"]
    for name, version_type in (
        ("PROTOCOL_VERSION", "ProtocolVersion"),
        ("H2_BINDING_VERSION", "BindingVersion"),
    ):
        matches = re.findall(
            rf"(?m)^pub const {name}: {version_type} = {version_type}\((\d+)\);$", source
        )
        if len(matches) != 1 or not 0 <= int(matches[0]) <= 65535:
            raise ValueError(f"expected one uint16_t tuple declaration for {name}")
        lines.append(f"#define ARIAD_{name} {int(matches[0])}u")
    return "\n".join(lines)


def credential_macros(source: str) -> str:
    byte_lengths = re.findall(r"(?m)^\s+pub const BYTE_LEN: usize = ([0-9]+);$", source)
    hex_factors = re.findall(
        r"(?m)^\s+pub const HEX_LEN: usize = ([0-9]+) \* Self::BYTE_LEN;$", source
    )
    if len(byte_lengths) != 1 or len(hex_factors) != 1:
        raise ValueError("expected one Credential BYTE_LEN and derived HEX_LEN declaration")
    byte_length, hex_factor = int(byte_lengths[0]), int(hex_factors[0])
    if byte_length <= 0 or hex_factor <= 0:
        raise ValueError("credential lengths must be positive")
    return "\n".join(
        [
            f"/* Generated from {CREDENTIAL_SOURCE.as_posix()}. */",
            f"#define ARIAD_CREDENTIAL_BYTES {byte_length}u",
            f"#define ARIAD_CREDENTIAL_HEX_BYTES {byte_length * hex_factor}u",
        ]
    )


def trust_root_macro(source: str) -> str:
    matches = re.findall(
        r"(?m)^pub\(crate\) const MAX_CERTIFICATE_DER_BYTES: usize = "
        r"(0|[1-9][0-9]*)(?: \* (1024))?;$",
        source,
    )
    if len(matches) != 1:
        raise ValueError("expected one decimal or KiB MAX_CERTIFICATE_DER_BYTES declaration")
    number, factor = matches[0]
    length = int(number) * (int(factor) if factor else 1)
    if not 0 < length <= 2**32 - 1:
        raise ValueError("trust root limit must be a positive uint32_t value")
    return "\n".join(
        [
            f"/* Generated from {TRUST_SOURCE.as_posix()}. */",
            f"#define ARIAD_MAX_TRUST_ROOT_DER_BYTES {length}u",
        ]
    )


def rust_type(c_type: str) -> str:
    if c_type == "const char *":
        return "*const std::ffi::c_char"
    base = base_type(c_type)
    result = "AriadHandle" if base == "ariad_handle" else SCALARS[base][0]
    if c_type.endswith(" *"):
        return ("*const " if c_type.startswith("const ") else "*mut ") + result
    return result


def python_type(c_type: str) -> str:
    if c_type == "const char *":
        return "ctypes.c_char_p"
    base = base_type(c_type)
    alias = "_HANDLE" if base == "ariad_handle" else SCALARS[base][1]
    return alias + "P" if c_type.endswith(" *") else alias


def rust_source(header: Header) -> str:
    lines = [
        "// Generated by tools/generate_abi.py from crates/ffi/include/ariad.h. Do not edit.",
        "",
        "/// A process-local object identifier. Zero is invalid.",
        "/// Destroyed identifiers are not reused.",
        f"pub type AriadHandle = {SCALARS[header.handle_type][0]};",
        "",
    ]
    docs = {
        "ARIAD_MAX_COPY": "Maximum input or output payload size per call, in bytes.",
        "ARIAD_MAX_TIMEOUT_MS": (
            "Maximum network operation timeout, in milliseconds. Zero is rejected."
        ),
    }
    for item in header.constants:
        if item.name in docs:
            lines.append(f"/// {docs[item.name]}")
        lines.append(f"pub const {item.name}: {item.rust_type} = {item.value};")
    lines.extend(
        ["", "fn abi_status_name(status: i32) -> *const std::ffi::c_char {", "    match status {"]
    )
    lines.extend(
        f'        {item.name} => c"{item.name}".as_ptr(),'
        for item in header.constants
        if item.is_status
    )
    lines.extend(['        _ => c"ARIAD_STATUS_UNKNOWN".as_ptr(),', "    }", "}", ""])
    lines.append(
        "// Safe exports also coerce to these pointers. The assignments check C ABI types."
    )
    for function in header.functions:
        parameters = ", ".join(rust_type(parameter) for parameter in function.parameters)
        result = rust_type(function.result)
        line = f'const _: unsafe extern "C" fn({parameters}) -> {result} = {function.name};'
        if len(line) <= 100:
            lines.append(line)
        elif len(type_line := f'const _: unsafe extern "C" fn({parameters}) -> {result} =') <= 100:
            lines.extend([type_line, f"    {function.name};"])
        else:
            lines.append('const _: unsafe extern "C" fn(')
            lines.extend(f"    {rust_type(parameter)}," for parameter in function.parameters)
            lines.append(f") -> {result} = {function.name};")
    lines.extend(
        [
            "",
            "const _: [(); ARIAD_CREDENTIAL_BYTES] = [(); ariad_core::Credential::BYTE_LEN];",
            "const _: [(); ARIAD_CREDENTIAL_HEX_BYTES] = [(); ariad_core::Credential::HEX_LEN];",
            "const _: () = assert!(ARIAD_PROTOCOL_VERSION == ariad_core::PROTOCOL_VERSION.0);",
            "const _: () = assert!(ARIAD_H2_BINDING_VERSION == ariad_core::H2_BINDING_VERSION.0);",
            "const _: [(); ARIAD_MAX_TRUST_ROOT_DER_BYTES] =",
            "    [(); ariad_engine::TrustPolicy::MAX_ROOT_CERTIFICATE_BYTES];",
        ]
    )
    return "\n".join(lines) + "\n"


def python_constants(header: Header) -> str:
    groups: dict[str, list[tuple[str, int]]] = {"Status": []}
    groups.update((name, []) for name, _prefix in ENUM_PREFIXES)
    globals_ = []
    for constant in header.constants:
        if constant.is_status:
            groups["Status"].append((constant.name.removeprefix("ARIAD_"), constant.value))
            continue
        for name, prefix in sorted(ENUM_PREFIXES, key=lambda item: len(item[1]), reverse=True):
            if constant.name.startswith(prefix):
                groups[name].append((constant.name.removeprefix(prefix), constant.value))
                break
        else:
            globals_.append(f"{constant.name.removeprefix('ARIAD_')} = {constant.value}")
    lines = ["# Generated by tools/generate_abi.py from crates/ffi/include/ariad.h.", *globals_]
    for name, members in groups.items():
        if not members:
            raise ValueError(f"missing constants for Python enum {name}")
        lines.extend(["", "", f"class {name}(IntEnum):"])
        lines.extend(f"    {member} = {value}" for member, value in members)
    return "\n".join(lines)


def python_signatures(header: Header) -> str:
    lines = ["# Generated by tools/generate_abi.py from crates/ffi/include/ariad.h."]
    c_types = {
        c_type
        for function in header.functions
        for c_type in (*function.parameters, function.result)
    }
    used_types = {base_type(c_type) for c_type in c_types}
    lines.extend(
        f"{alias} = {ctype}"
        for name, (_rust, alias, ctype) in SCALARS.items()
        if name in used_types
    )
    lines.append(f"_HANDLE = {SCALARS[header.handle_type][2]}")
    pointers = {c_type for c_type in c_types if c_type.endswith(" *") and c_type != "const char *"}
    for alias, base in sorted(
        {(python_type(item), python_type(base_type(item))) for item in pointers}
    ):
        lines.append(f"{alias} = ctypes.POINTER({base})")
    lines.append("_SIGNATURES: dict[str, tuple[list[type[Any]], type[Any]]] = {")
    for function in header.functions:
        parameters = ", ".join(python_type(parameter) for parameter in function.parameters)
        lines.append(f'    "{function.name}": ([{parameters}], {python_type(function.result)}),')
    lines.append("}")
    return "\n".join(lines)


def kotlin_source(header: Header) -> str:
    lines = [
        "// Generated by tools/generate_abi.py from crates/ffi/include/ariad.h. Do not edit.",
        "package org.ariad.integration",
        "",
        "internal object AriadConstants {",
    ]
    for constant in header.constants:
        if not -(2**31) <= constant.value <= 2**31 - 1:
            raise ValueError(f"C macro cannot fit a Kotlin Int: {constant.name}")
        lines.append(f"    const val {constant.name.removeprefix('ARIAD_')} = {constant.value}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_outputs(root: Path) -> dict[Path, str]:
    header_source = replace_region(
        (root / HEADER).read_text(encoding="utf-8"),
        "WIRE VERSIONS",
        wire_macros((root / WIRE_SOURCE).read_text(encoding="utf-8")),
        c_comment=True,
    )
    header_source = replace_region(
        header_source,
        "CREDENTIAL LIMITS",
        credential_macros((root / CREDENTIAL_SOURCE).read_text(encoding="utf-8")),
        c_comment=True,
    )
    header_source = replace_region(
        header_source,
        "TRUST ROOT LIMIT",
        trust_root_macro((root / TRUST_SOURCE).read_text(encoding="utf-8")),
        c_comment=True,
    )
    header = parse_header(header_source)
    python_source = (root / PYTHON).read_text(encoding="utf-8")
    python_source = replace_region(
        python_source, "ABI CONSTANTS", python_constants(header), blank_lines=2
    )
    python_source = replace_region(python_source, "ABI SIGNATURES", python_signatures(header))
    return {
        HEADER: header_source,
        RUST: rust_source(header),
        PYTHON: python_source,
        KOTLIN: kotlin_source(header),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        outputs = generate_outputs(ROOT)
        changed = [
            path
            for path, expected in outputs.items()
            if not (ROOT / path).exists() or (ROOT / path).read_text(encoding="utf-8") != expected
        ]
        if args.check:
            if changed:
                print(
                    "ABI output drift: " + ", ".join(path.as_posix() for path in changed),
                    file=sys.stderr,
                )
                print("Run python tools/generate_abi.py", file=sys.stderr)
                return 1
        else:
            for path in changed:
                (ROOT / path).write_text(outputs[path], encoding="utf-8", newline="\n")
        return 0
    except (OSError, ValueError) as error:
        print(f"ABI generation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
