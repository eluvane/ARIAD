from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools import release

MANIFEST = """[workspace]
members = ["crates/core", "crates/engine"]

[workspace.package]
version = "0.0.0"
edition = "2024"

[workspace.dependencies]
ariad-core = { path = "crates/core", version = "0.0.0" }
http = "1"
"""
LOCK = """version = 4

[[package]]
name = "ariad-core"
version = "0.0.0"

[[package]]
name = "ariad-engine"
version = "0.0.0"
dependencies = ["ariad-core 0.0.0", "http"]

[[package]]
name = "http"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "independent-fixture"
"""
NAMES = {"ariad-core", "ariad-engine"}


class ReleasePlanTests(unittest.TestCase):
    def test_first_release_uses_next_patch_without_a_previous_tag(self) -> None:
        plan = release.plan_release("0.0.0", [], [], "")
        self.assertEqual(plan["tag"], "v0.0.1")
        self.assertEqual(plan["previous_tag"], "")
        self.assertEqual(len(json.loads(plan["matrix"])), 6)

    def test_previous_boundary_includes_prereleases_but_excludes_drafts(self) -> None:
        history: list[dict[str, object]] = [
            {"tag_name": "v0.1.0", "draft": False, "published_at": "2026-01-01T00:00:00Z"},
            {
                "tag_name": "v0.2.0",
                "draft": False,
                "prerelease": True,
                "published_at": "2026-02-01T00:00:00Z",
            },
            {"tag_name": "v0.2.1", "draft": True, "published_at": None},
        ]
        plan = release.plan_release("0.0.0", history, ["v0.2.2"], "")
        self.assertEqual(plan["previous_tag"], "v0.2.0")
        self.assertEqual(plan["version"], "0.2.3")

    def test_numeric_version_order_and_explicit_minor_release(self) -> None:
        plan = release.plan_release("0.0.0", [], ["v0.9.9", "v0.10.0"], "")
        self.assertEqual(plan["tag"], "v0.10.1")
        self.assertEqual(
            release.plan_release("0.0.0", [], ["v0.10.0"], "v0.11.0")["version"], "0.11.0"
        )

    def test_invalid_and_reserved_versions_fail_before_output(self) -> None:
        for version in ("0.0.0", "v1.2.3", "01.2.3", "1.2", "1.2.3\ninjected=value", "../1.2.3"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.plan_release("0.0.0", [], ["v1.2.3"], version)

    def test_unrecognized_previous_release_does_not_reset_changelog_range(self) -> None:
        with self.assertRaises(ValueError):
            release.plan_release(
                "0.0.0",
                [
                    {
                        "tag_name": "old-release",
                        "draft": False,
                        "published_at": "2026-01-01T00:00:00Z",
                    }
                ],
                [],
                "",
            )

    def test_versions_change_together_and_registry_packages_stay_identical(self) -> None:
        manifest, lock = release.version_outputs(MANIFEST, LOCK, NAMES, "1.2.3")
        self.assertEqual(release.workspace_version(manifest), "1.2.3")
        self.assertIn('ariad-core = { path = "crates/core", version = "1.2.3" }', manifest)
        self.assertIn('dependencies = ["ariad-core 1.2.3", "http"]', lock)
        self.assertNotIn('version = "0.0.0"', lock)
        self.assertEqual(lock[lock.index('name = "http"') :], LOCK[LOCK.index('name = "http"') :])
        self.assertIn('edition = "2024"', manifest)

    def test_version_sync_rejects_missing_ambiguous_or_stale_workspace_entries(self) -> None:
        cases = (
            (MANIFEST, LOCK, NAMES | {"missing"}),
            (MANIFEST, LOCK + '\n[[package]]\nname = "ariad-core"\nversion = "0.0.0"\n', NAMES),
            (
                MANIFEST,
                LOCK.replace(
                    'name = "ariad-core"\nversion = "0.0.0"',
                    'name = "ariad-core"\nversion = "0.1.0"',
                ),
                NAMES,
            ),
            (
                MANIFEST.replace(
                    'path = "crates/core", version = "0.0.0"',
                    'path = "crates/core", version = "0.1.0"',
                ),
                LOCK,
                NAMES,
            ),
        )
        for manifest, lock, names in cases:
            with self.subTest(names=names), self.assertRaises(ValueError):
                release.version_outputs(manifest, lock, names, "1.2.3")


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.assets = Path(temporary.name)
        (self.assets / "SHA256SUMS").write_text("fixture digest", encoding="utf-8")

    def test_release_body_contains_only_actual_downloads_and_the_comparison_link(self) -> None:
        names = {release.native_name("v0.0.1", target) for target in release.TARGETS}
        for name in names:
            (self.assets / name).write_bytes(b"native archive")
        generated = (
            "<!-- Release notes generated using configuration in .github/release.yml -->\n\n"
            "## Fixes\n\n"
            "- Bound pending requests by @contributor in https://github.com/example/project/pull/1\n\n"
            "**Full Changelog**: https://github.com/example/project/compare/v0.0.0...v0.0.1\n"
        )
        result = release.release_notes(self.assets, generated)
        self.assertTrue(result.startswith("## Downloads\n\n"))
        self.assertEqual(result.count("\n## "), 0)
        for name in names:
            self.assertIn(f"- `{name}`:", result)
        self.assertIn("- `SHA256SUMS`: SHA-256 digests of the native archives.", result)
        self.assertNotIn("Bound pending requests", result)
        self.assertNotIn("<!--", result)
        self.assertTrue(
            result.endswith(
                "[Full changelog](https://github.com/example/project/compare/v0.0.0...v0.0.1)\n"
            )
        )

    def test_single_target_uses_the_actual_archive_and_first_release_history_link(self) -> None:
        name = release.native_name("v0.0.1", release.TARGETS[4])
        (self.assets / name).write_bytes(b"native archive")
        generated = (
            "<!-- Release notes generated using configuration in .github/release.yml -->\n\n\n\n"
            "**Full Changelog**: https://github.com/example/project/commits/v0.0.1\n"
        )
        result = release.release_notes(self.assets, generated.replace("\n", "\r\n"))
        self.assertIn(f"- `{name}`:", result)
        self.assertIn("- `SHA256SUMS`: SHA-256 digest of the native archive.", result)
        self.assertEqual(result.count("- `ariad-"), 1)
        self.assertTrue(
            result.endswith("[Full changelog](https://github.com/example/project/commits/v0.0.1)\n")
        )

    def test_incomplete_downloads_or_missing_changelog_prevent_notes(self) -> None:
        with self.assertRaises(ValueError):
            release.release_notes(self.assets, "## Fixes\n")
        generated = "**Full Changelog**: https://github.com/example/project/commits/v0.0.1\n"
        with self.assertRaises(ValueError):
            release.release_notes(self.assets, generated)
        (self.assets / release.native_name("v0.0.1", release.TARGETS[0])).write_bytes(b"archive")
        (self.assets / "SHA256SUMS").unlink()
        with self.assertRaises(ValueError):
            release.release_notes(self.assets, generated)


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
        (self.root / "LICENSE").write_text("test license", encoding="utf-8")
        headers = self.root / "crates/ffi/include"
        headers.mkdir(parents=True)
        for name in ("ariad.h", "ariad.hpp"):
            (headers / name).write_text(name, encoding="utf-8")

    def native_inputs(self, target: release.Target) -> None:
        build = self.root / "target" / target.triple / "release"
        build.mkdir(parents=True)
        for name in (target.binary, *target.libraries):
            (build / name).write_bytes(name.encode())

    def asset_fixture(self) -> Path:
        directory = self.root / "assets"
        directory.mkdir()
        names = {release.native_name("v0.0.1", target) for target in release.TARGETS}
        for name in names:
            (directory / name).write_bytes(name.encode())
        return directory

    def remote_fixture(self, directory: Path) -> dict[str, object]:
        release.checksums(directory, "v0.0.1")
        return {
            "tag_name": "v0.0.1",
            "assets": [
                {
                    "name": path.name,
                    "state": "uploaded",
                    "size": path.stat().st_size,
                    "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in directory.iterdir()
            ],
        }

    def test_each_platform_archive_contains_server_libraries_headers_and_provenance(self) -> None:
        for target in release.TARGETS:
            with self.subTest(target=target.triple):
                self.native_inputs(target)
                archive = release.package_native(
                    self.root, target, "v0.0.0", "a" * 40, "b" * 40, self.root / "archives"
                )
                prefix = archive.name.removesuffix(target.archive_suffix) + "/"
                if target.system == "windows":
                    with zipfile.ZipFile(archive) as packed:
                        contents = {
                            name.removeprefix(prefix): packed.read(name)
                            for name in packed.namelist()
                        }
                else:
                    with tarfile.open(archive) as packed:
                        contents = {}
                        for entry in packed.getmembers():
                            data = packed.extractfile(entry)
                            if data is None:
                                self.fail(f"unexpected directory entry: {entry.name}")
                            contents[entry.name.removeprefix(prefix)] = data.read()
                self.assertEqual(
                    set(contents),
                    {
                        f"bin/{target.binary}",
                        *(f"lib/{name}" for name in target.libraries),
                        "include/ariad.h",
                        "include/ariad.hpp",
                        "LICENSE",
                        "README.md",
                        "BUILD-INFO.json",
                    },
                )
                metadata = json.loads(contents["BUILD-INFO.json"])
                self.assertEqual(metadata["version"], "0.0.0")
                self.assertEqual(metadata["source_commit"], "a" * 40)
                self.assertEqual(metadata["release_commit"], "b" * 40)

    def test_missing_library_and_version_mismatch_prevent_packaging(self) -> None:
        target = release.TARGETS[0]
        self.native_inputs(target)
        for tag in ("v0.0.1", "../../escape"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.package_native(
                    self.root, target, tag, "a" * 40, "b" * 40, self.root / "archives"
                )
        (self.root / "target" / target.triple / "release" / target.libraries[0]).unlink()
        with self.assertRaises(ValueError):
            release.package_native(
                self.root, target, "v0.0.0", "a" * 40, "b" * 40, self.root / "archives"
            )
        self.assertFalse((self.root / "archives").exists())

    def test_complete_archive_set_has_real_sha256_and_repeatable_manifest(self) -> None:
        directory = self.asset_fixture()
        release.checksums(directory, "v0.0.1")
        first = (directory / "SHA256SUMS").read_bytes()
        lines = first.decode().splitlines()
        self.assertEqual(len(lines), len(release.TARGETS))
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((directory / name).read_bytes()).hexdigest())
        release.checksums(directory, "v0.0.1")
        self.assertEqual((directory / "SHA256SUMS").read_bytes(), first)

    def test_partial_or_unexpected_assets_prevent_manifest_creation(self) -> None:
        directory = self.asset_fixture()
        missing = directory / release.native_name("v0.0.1", release.TARGETS[0])
        missing.unlink()
        with self.assertRaises(ValueError):
            release.checksums(directory, "v0.0.1")
        self.assertFalse((directory / "SHA256SUMS").exists())
        missing.write_bytes(b"native")
        for name in ("unexpected.zip", "ariad-v0.0.1-source.tar.gz"):
            with self.subTest(name=name):
                extra = directory / name
                extra.write_bytes(b"unrelated")
                with self.assertRaises(ValueError):
                    release.checksums(directory, "v0.0.1")
                extra.unlink()

    def test_uploaded_assets_must_match_contents_sizes_and_complete_names(self) -> None:
        directory = self.asset_fixture()
        remote = self.remote_fixture(directory)
        release.verify_assets(directory, "v0.0.1", remote)
        for key, value in (("digest", "sha256:" + "0" * 64), ("size", 0), ("state", "new")):
            broken = json.loads(json.dumps(remote))
            broken["assets"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.verify_assets(directory, "v0.0.1", broken)
        partial = json.loads(json.dumps(remote))
        partial["assets"].pop()
        with self.assertRaises(ValueError):
            release.verify_assets(directory, "v0.0.1", partial)


if __name__ == "__main__":
    unittest.main()
