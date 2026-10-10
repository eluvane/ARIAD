"""Plan release versions and package checked native build outputs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


@dataclass(frozen=True)
class Target:
    triple: str
    runner: str
    system: str

    @property
    def archive_suffix(self) -> str:
        return ".zip" if self.system == "windows" else ".tar.gz"

    @property
    def binary(self) -> str:
        return "ariad-server.exe" if self.system == "windows" else "ariad-server"

    @property
    def libraries(self) -> tuple[str, ...]:
        if self.system == "windows":
            return "ariad_ffi.dll", "ariad_ffi.dll.lib", "ariad_ffi.lib"
        shared = "libariad_ffi.dylib" if self.system == "macos" else "libariad_ffi.so"
        return shared, "libariad_ffi.a"


TARGETS = (
    Target("x86_64-unknown-linux-gnu", "ubuntu-22.04", "linux"),
    Target("aarch64-unknown-linux-gnu", "ubuntu-22.04-arm", "linux"),
    Target("x86_64-apple-darwin", "macos-15-intel", "macos"),
    Target("aarch64-apple-darwin", "macos-14", "macos"),
    Target("x86_64-pc-windows-msvc", "windows-2022", "windows"),
    Target("aarch64-pc-windows-msvc", "windows-11-arm", "windows"),
)


def parse_version(value: str) -> tuple[int, int, int]:
    match = VERSION.fullmatch(value)
    if match is None:
        raise ValueError("version must be MAJOR.MINOR.PATCH, with an optional v prefix")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def table_pattern(name: str) -> re.Pattern[str]:
    return re.compile(rf"(^\[{re.escape(name)}\]\n)(.*?)(?=^\[|\Z)", re.MULTILINE | re.DOTALL)


def workspace_version(manifest: str) -> str:
    table = table_pattern("workspace.package").search(manifest)
    versions = [
        match.group(1)
        for match in re.finditer(
            r'^version\s*=\s*"([^"]+)"\s*$', table[2] if table else "", re.MULTILINE
        )
    ]
    if len(versions) != 1:
        raise ValueError("workspace.package must declare exactly one version")
    parse_version(versions[0])
    return versions[0]


def plan_release(
    current: str, releases: list[dict[str, object]], tags: list[str], requested: str
) -> dict[str, str]:
    reserved = {str(item["tag_name"]) for item in releases} | set(tags)
    published = [item for item in releases if not item.get("draft") and item.get("published_at")]
    previous = (
        str(max(published, key=lambda item: str(item["published_at"]))["tag_name"])
        if published
        else ""
    )
    versions = [parse_version(current)]
    versions.extend(parse_version(tag) for tag in reserved if VERSION.fullmatch(tag))
    if requested:
        selected = parse_version(requested)
        if selected <= max(versions):
            raise ValueError("an explicit release version must exceed all existing versions")
    else:
        major, minor, patch = max(versions)
        selected = major, minor, patch + 1
    version = ".".join(str(part) for part in selected)
    tag = "v" + version
    if tag in reserved:
        raise ValueError(f"release tag already exists: {tag}")
    if previous and not VERSION.fullmatch(previous):
        raise ValueError("the previous release must use a vMAJOR.MINOR.PATCH tag")
    matrix = [{"target": target.triple, "runner": target.runner} for target in TARGETS]
    return {"version": version, "tag": tag, "previous_tag": previous, "matrix": json.dumps(matrix)}


def version_outputs(manifest: str, lock: str, names: set[str], version: str) -> tuple[str, str]:
    old = workspace_version(manifest)
    parse_version(version)
    if not names:
        raise ValueError("workspace package list is empty")

    def package_table(match: re.Match[str]) -> str:
        body, count = re.subn(
            r'^version\s*=\s*"[^"]+"\s*$', f'version = "{version}"', match[2], flags=re.MULTILINE
        )
        if count != 1:
            raise ValueError("workspace version is ambiguous")
        return match[1] + body

    manifest = table_pattern("workspace.package").sub(package_table, manifest)
    dependencies = table_pattern("workspace.dependencies").search(manifest)
    if dependencies is None:
        raise ValueError("workspace.dependencies is missing")

    def dependency(match: re.Match[str]) -> str:
        if match[1] not in names:
            return match[0]
        text, count = re.subn(r'\bversion\s*=\s*"([^"]+)"', f'version = "{version}"', match[0])
        declared = re.search(r'\bversion\s*=\s*"([^"]+)"', match[0])
        if count != 1 or declared is None or declared[1] != old or "path" not in match[0]:
            raise ValueError(f"unsupported workspace dependency declaration: {match[1]}")
        return text

    body = re.sub(
        r"^([\w-]+)\s*=\s*\{[^\n]+\}\s*$", dependency, dependencies[2], flags=re.MULTILINE
    )
    manifest = manifest[: dependencies.start(2)] + body + manifest[dependencies.end(2) :]
    seen: set[str] = set()

    def package(match: re.Match[str]) -> str:
        text = match[0]
        name = re.search(r'^name = "([^"]+)"$', text, re.MULTILINE)
        if name is None or name[1] not in names:
            return text
        if name[1] in seen or re.search(r"^source\s*=", text, re.MULTILINE):
            raise ValueError(f"ambiguous locked workspace package: {name[1]}")
        seen.add(name[1])
        updated, count = re.subn(
            rf'^version = "{re.escape(old)}"$', f'version = "{version}"', text, flags=re.MULTILINE
        )
        if count != 1:
            raise ValueError(f"unexpected locked workspace version: {name[1]}")
        return updated

    lock = re.sub(
        r"^\[\[package\]\]\n.*?(?=^\[\[package\]\]|\Z)",
        package,
        lock,
        flags=re.MULTILINE | re.DOTALL,
    )
    if seen != names:
        raise ValueError("Cargo.lock does not contain every workspace package")
    for name in names:
        lock = lock.replace(f'"{name} {old}"', f'"{name} {version}"')
    return manifest, lock


def native_name(tag: str, target: Target) -> str:
    return f"ariad-{tag}-{target.triple}{target.archive_suffix}"


def release_notes(directory: Path, generated: str) -> str:
    changelog = re.search(
        r"(?m)^\*\*Full Changelog\*\*: (https://github\.com/[^\s]+)[ \t]*\r?$", generated
    )
    if changelog is None:
        raise ValueError("generated release notes must contain a full changelog link")
    archives = sorted(path.name for path in directory.iterdir() if path.name != "SHA256SUMS")
    if not archives or not (directory / "SHA256SUMS").is_file():
        raise ValueError("release downloads must contain native archives and SHA256SUMS")
    lines = ["## Downloads", ""]
    lines.extend(
        f"- `{name}`: reference server, C ABI shared/static\n"
        "  libraries, C/C++ headers, license, and build metadata."
        for name in archives
    )
    checksum = (
        "SHA-256 digest of the native archive."
        if len(archives) == 1
        else "SHA-256 digests of the native archives."
    )
    lines.extend([f"- `SHA256SUMS`: {checksum}", "", f"[Full changelog]({changelog[1]})"])
    return "\n".join(lines) + "\n"


def package_native(
    root: Path, target: Target, tag: str, source_sha: str, release_sha: str, output: Path
) -> Path:
    version = tag.removeprefix("v")
    parse_version(version)
    if workspace_version((root / "Cargo.toml").read_text(encoding="utf-8")) != version:
        raise ValueError("release tag does not match the built workspace version")
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (source_sha, release_sha)):
        raise ValueError("source and release commits must be full SHA-1 identifiers")
    build = root / "target" / target.triple / "release"
    files = {f"bin/{target.binary}": build / target.binary}
    files.update({f"lib/{name}": build / name for name in target.libraries})
    files.update(
        {f"include/{name}": root / "crates/ffi/include" / name for name in ("ariad.h", "ariad.hpp")}
    )
    files["LICENSE"] = root / "LICENSE"
    for path in files.values():
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError(f"missing or empty release input: {path}")
    metadata = {
        "version": version,
        "tag": tag,
        "target": target.triple,
        "source_commit": source_sha,
        "release_commit": release_sha,
        "transport": "H2 with Rustls",
    }
    docs = {
        "BUILD-INFO.json": (json.dumps(metadata, indent=2) + "\n").encode(),
        "README.md": (
            f"# ARIAD {tag}\n\n"
            f"Native build for `{target.triple}`.\n\n"
            "`bin/` contains the reference server. `lib/` contains the C ABI shared\n"
            "library and static archive. Windows builds also include the DLL import\n"
            "library. `include/` contains the matching C and C++ headers.\n\n"
            "These builds use H2 with Rustls. H3 and mobile native binaries are not\n"
            "included. Static linkage needs the target's platform libraries; Windows\n"
            "builds use the dynamic MSVC runtime. macOS builds are not notarized.\n\n"
            "See the [native embedding guide]"
            f"(https://github.com/eluvane/ARIAD/blob/{tag}/crates/ffi/README.md).\n"
            "The release page's Source code downloads contain the tagged Rust\n"
            "workspace, Python and Go wrappers, and mobile example sources.\n"
        ).encode(),
    }
    output.mkdir(parents=True, exist_ok=True)
    archive = output / native_name(tag, target)
    prefix = archive.name.removesuffix(target.archive_suffix)
    if target.system == "windows":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for name, path in sorted(files.items()):
                zipped.write(path, f"{prefix}/{name}")
            for name, data in docs.items():
                zipped.writestr(f"{prefix}/{name}", data)
    else:
        with tarfile.open(archive, "w:gz") as packed:
            for name, path in sorted(files.items()):
                packed.add(path, arcname=f"{prefix}/{name}", recursive=False)
            for name, data in docs.items():
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(data)
                info.mode = 0o644
                packed.addfile(info, io.BytesIO(data))
    return archive


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checksums(directory: Path, tag: str) -> dict[str, str]:
    parse_version(tag)
    expected = {native_name(tag, target) for target in TARGETS}
    actual = {path.name for path in directory.iterdir() if path.name != "SHA256SUMS"}
    if actual != expected:
        raise ValueError(
            f"release asset set differs: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    digests: dict[str, str] = {}
    for name in sorted(expected):
        path = directory / name
        if not path.is_file() or path.is_symlink() or not path.stat().st_size:
            raise ValueError(f"invalid release archive: {name}")
        digests[name] = file_digest(path)
    (directory / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in digests.items()), encoding="utf-8"
    )
    return digests


def verify_assets(directory: Path, tag: str, release: dict[str, object]) -> None:
    if release.get("tag_name") != tag:
        raise ValueError("uploaded release tag differs from the plan")
    expected = checksums(directory, tag)
    expected["SHA256SUMS"] = file_digest(directory / "SHA256SUMS")
    assets = cast("list[dict[str, object]]", release["assets"])
    uploaded = {str(asset["name"]): asset for asset in assets}
    if set(uploaded) != set(expected) or len(assets) != len(uploaded):
        raise ValueError("uploaded release asset set differs from the plan")
    for name, digest in expected.items():
        asset = uploaded[name]
        if (
            asset.get("state") != "uploaded"
            or asset.get("digest") != "sha256:" + digest
            or asset.get("size") != (directory / name).stat().st_size
        ):
            raise ValueError(f"uploaded release asset failed verification: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("prepare")
    plan.add_argument("--history", type=Path, required=True)
    plan.add_argument("--metadata", type=Path, required=True)
    plan.add_argument("--tags", type=Path, required=True)
    plan.add_argument("--version", default="")
    notes = commands.add_parser("notes")
    notes.add_argument("--directory", type=Path, required=True)
    notes.add_argument("--generated", type=Path, required=True)
    package = commands.add_parser("package")
    package.add_argument("--target", choices=[target.triple for target in TARGETS], required=True)
    package.add_argument("--tag", required=True)
    package.add_argument("--source-sha", required=True)
    package.add_argument("--release-sha", required=True)
    package.add_argument("--output", type=Path, required=True)
    sums = commands.add_parser("checksums")
    sums.add_argument("--tag", required=True)
    sums.add_argument("--directory", type=Path, required=True)
    verify = commands.add_parser("verify-assets")
    verify.add_argument("--tag", required=True)
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--release", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            history = cast(
                "list[list[dict[str, object]]]",
                json.loads(args.history.read_text(encoding="utf-8")),
            )
            metadata = cast(
                "dict[str, object]", json.loads(args.metadata.read_text(encoding="utf-8"))
            )
            packages = cast("list[dict[str, object]]", metadata["packages"])
            members = cast("list[str]", metadata["workspace_members"])
            names = {str(item["name"]) for item in packages if item["id"] in members}
            manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
            result = plan_release(
                workspace_version(manifest),
                [item for page in history for item in page],
                args.tags.read_text(encoding="utf-8").splitlines(),
                args.version,
            )
            updated, lock = version_outputs(
                manifest,
                (ROOT / "Cargo.lock").read_text(encoding="utf-8"),
                names,
                result["version"],
            )
            readme = (
                (ROOT / "README.md")
                .read_text(encoding="utf-8")
                .replace(
                    f"Version **{workspace_version(manifest)}**", f"Version **{result['version']}**"
                )
            )
            for path, text in (
                ("Cargo.toml", updated),
                ("Cargo.lock", lock),
                ("README.md", readme),
            ):
                (ROOT / path).write_text(text, encoding="utf-8", newline="\n")
            for key, value in result.items():
                print(f"{key}={value}")
        elif args.command == "notes":
            generated = json.loads(args.generated.read_text(encoding="utf-8"))
            body = generated["body"]
            if not isinstance(body, str):
                raise ValueError("generated release notes must contain a text body")
            print(release_notes(args.directory, body), end="")
        elif args.command == "package":
            target = next(target for target in TARGETS if target.triple == args.target)
            print(
                package_native(
                    ROOT, target, args.tag, args.source_sha, args.release_sha, args.output
                )
            )
        elif args.command == "checksums":
            checksums(args.directory, args.tag)
        else:
            remote = cast("dict[str, object]", json.loads(args.release.read_text(encoding="utf-8")))
            verify_assets(args.directory, args.tag, remote)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
