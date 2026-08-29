#!/usr/bin/env python3
"""Adversarial unit tests for deterministic release packaging."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load test module: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


packager = load_module("diskplan_test_packager", SCRIPT_DIR / "package_bundle.py")
sys.modules["package_bundle"] = packager
source_manifest = load_module(
    "diskplan_test_source_manifest", SCRIPT_DIR / "source_manifest.py"
)
protocol_contract_fixture = load_module(
    "diskplan_test_protocol_contract_fixture",
    SCRIPT_DIR / "rewrite_protocol_contract_fixture.py",
)


def make_test_bundle(parent: Path, reverse: bool = False) -> Path:
    bundle = parent / "diskplan-test"
    bundle.mkdir(parents=True)
    specs = [
        packager.BundleArtifactSpec(
            bundle_path="VERSION",
            compatibility_version="product-v1",
            maximum_bytes=256,
            mode=0o644,
            role="product-version",
            source="@version-file",
        ),
        packager.BundleArtifactSpec(
            bundle_path="rules/builtin-v1.json",
            compatibility_version="diskplan.rules.v1",
            maximum_bytes=1024,
            mode=0o644,
            role="declarative-rules",
            source="rules/builtin-v1.json",
        ),
    ]
    packager.make_bundle_directories(bundle, [item.bundle_path for item in specs])
    payloads = {
        "VERSION": b"0.1.0\n",
        "rules/builtin-v1.json": b'{"rules":[],"schema_version":"diskplan.rules.v1"}\n',
    }
    artifacts = []
    sequence = list(reversed(specs)) if reverse else specs
    for spec in sequence:
        artifacts.append(packager.write_bundle_artifact(bundle, spec, payloads[spec.bundle_path]))
    artifacts.sort(key=lambda item: os.fsencode(item["path"]))
    manifest = {
        "architecture": "arm64",
        "artifacts": artifacts,
        "bundle_format": 1,
        "deployment_target_macos": "14.0",
        "excluded_inputs": [],
        "manifest_schema_version": packager.MANIFEST_SCHEMA_VERSION,
        "optional_capabilities": [],
        "product_version": "0.1.0",
        "protocol_major": 1,
        "protocol_minor": 4,
        "release_gate_macos": "26.0",
        "required_capabilities": ["framing-v1"],
        "source_revision": "0" * 40,
    }
    manifest_data = packager.canonical_json(manifest)
    packager.write_private_file(bundle / "manifest.json", manifest_data, 0o644)
    checksummed = [(item["path"], item["sha256"]) for item in artifacts]
    checksummed.append(("manifest.json", packager.digest(manifest_data)))
    sums = "".join(
        f"{sha256}  {path}\n"
        for path, sha256 in sorted(checksummed, key=lambda item: os.fsencode(item[0]))
    ).encode("ascii")
    packager.write_private_file(bundle / "SHA256SUMS", sums, 0o644)
    packager.verify_bundle_tree(bundle)
    return bundle


class VersionMetadataTests(unittest.TestCase):
    def test_semver_rejects_numeric_prerelease_leading_zeroes(self) -> None:
        self.assertIsNone(packager.SEMVER.fullmatch("1.2.3-01"))
        self.assertIsNotNone(packager.SEMVER.fullmatch("1.2.3-0"))
        self.assertIsNotNone(packager.SEMVER.fullmatch("1.2.3-alpha.01a+001"))

    def test_generated_native_contract_matches_canonical_json(self) -> None:
        repository_root = SCRIPT_DIR.parent.parent
        artifacts, _excluded = packager.load_bundle_contract(
            repository_root / "release/bundle-contract.json"
        )
        self.assertEqual(
            (SCRIPT_DIR / "bundle-contract.generated.h").read_bytes(),
            packager.render_c_bundle_contract(artifacts),
        )

    def test_shell_contract_matches_canonical_json(self) -> None:
        repository_root = SCRIPT_DIR.parent.parent
        artifacts, _excluded = packager.load_bundle_contract(
            repository_root / "release/bundle-contract.json"
        )
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'source "$1"; diskplan_expected_artifact_contract',
                "diskplan-contract-test",
                str(SCRIPT_DIR / "release-common.sh"),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        expected = "".join(
            f"{item.bundle_path}\t{item.mode:04o}\t{item.role}\t{item.compatibility_version}\n"
            for item in artifacts
        ).encode("ascii")
        self.assertEqual(completed.stdout, expected)
        self.assertEqual(completed.stderr, b"")
        files = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'source "$1"; diskplan_expected_files',
                "diskplan-contract-test",
                str(SCRIPT_DIR / "release-common.sh"),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        expected_files = sorted(
            [item.bundle_path for item in artifacts] + ["manifest.json", "SHA256SUMS"],
            key=os.fsencode,
        )
        self.assertEqual(files.stdout.decode("ascii").splitlines(), expected_files)
        directories = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'source "$1"; diskplan_expected_directories',
                "diskplan-contract-test",
                str(SCRIPT_DIR / "release-common.sh"),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(
            directories.stdout.decode("ascii").splitlines(),
            packager.bundle_directories(expected_files),
        )

    def test_protocol_contract_fixture_rewrites_only_exact_bound_assets(self) -> None:
        repository_root = SCRIPT_DIR.parent.parent
        source = repository_root / "release/bundle-contract.json"
        expected_contract = json.loads(source.read_text(encoding="ascii"))
        for artifact in expected_contract["artifacts"]:
            if artifact["bundle_path"] in protocol_contract_fixture.PROTOCOL_ASSETS:
                artifact["compatibility_version"] = "protocol-2.4"
        expected_bytes = packager.canonical_compact_json(expected_contract)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle-contract.json"
            protocol_contract_fixture.rewrite_contract(
                source,
                output,
                "1.4",
                "2.4",
            )
            self.assertEqual(output.read_bytes(), expected_bytes)
            artifacts, _excluded = packager.load_bundle_contract(output)
            rewritten = {
                item.bundle_path
                for item in artifacts
                if item.compatibility_version == "protocol-2.4"
            }
            self.assertEqual(rewritten, set(protocol_contract_fixture.PROTOCOL_ASSETS))

    def test_protocol_contract_fixture_rejects_same_count_path_drift(self) -> None:
        repository_root = SCRIPT_DIR.parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            output = root / "output.json"
            contract = json.loads(
                (repository_root / "release/bundle-contract.json").read_text(
                    encoding="ascii"
                )
            )
            by_path = {item["bundle_path"]: item for item in contract["artifacts"]}
            by_path["protocol.json"]["compatibility_version"] = "local-install-v1"
            by_path["release-common.sh"]["compatibility_version"] = "protocol-1.4"
            source.write_bytes(packager.canonical_compact_json(contract))
            with self.assertRaisesRegex(
                ValueError,
                "protocol-bound bundle asset metadata mismatch: protocol.json",
            ):
                protocol_contract_fixture.rewrite_contract(
                    source,
                    output,
                    "1.4",
                    "2.4",
                )
            self.assertFalse(output.exists())

    def test_protocol_contract_fixture_rejects_noncanonical_numeric_protocol_asset(
        self,
    ) -> None:
        repository_root = SCRIPT_DIR.parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            output = root / "output.json"
            contract = json.loads(
                (repository_root / "release/bundle-contract.json").read_text(
                    encoding="ascii"
                )
            )
            by_path = {item["bundle_path"]: item for item in contract["artifacts"]}
            by_path["release-common.sh"]["compatibility_version"] = "protocol-01.4"
            source.write_bytes(packager.canonical_compact_json(contract))
            with self.assertRaisesRegex(
                ValueError,
                "unexpected protocol-bound bundle asset: release-common.sh",
            ):
                protocol_contract_fixture.rewrite_contract(
                    source,
                    output,
                    "1.4",
                    "2.4",
                )
            self.assertFalse(output.exists())


class SourceManifestTests(unittest.TestCase):
    def test_release_uses_unlinked_trusted_comparator_and_full_record_seal(self) -> None:
        script = (SCRIPT_DIR / "build-release.sh").read_text(encoding="ascii")
        self.assertIn('exec 8<"${TRUSTED_SOURCE_MANIFEST}"', script)
        self.assertIn('exec 9<"${TRUSTED_SOURCE_MANIFEST}"', script)
        self.assertIn(
            '/bin/cp "${SOURCE_ROOT}/scripts/release/source_manifest.py"', script
        )
        self.assertNotIn(
            '/bin/cp "${REPO_ROOT}/scripts/release/source_manifest.py"', script
        )
        self.assertIn('/bin/rm "${TRUSTED_SOURCE_MANIFEST}"', script)
        self.assertIn("exec 8<&-", script)
        self.assertIn("exec 9<&-", script)
        self.assertIn("python3 /dev/fd/9", script)
        self.assertIn('--expected-record-sha256 "${SOURCE_SNAPSHOT_RECORD_SHA256}"', script)
        self.assertNotIn(
            'python3 "${SOURCE_ROOT}/scripts/release/source_manifest.py"', script
        )

    def test_system_bash_holds_trusted_fds_but_closes_them_for_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            comparator = source_root / "scripts/release/source_manifest.py"
            comparator.parent.mkdir(parents=True)
            comparator.write_text("print('trusted')\n", encoding="ascii")
            trusted = root / "trusted-comparator.py"
            release_script = (SCRIPT_DIR / "build-release.sh").read_text(
                encoding="ascii"
            )
            block_start = release_script.index(
                '/bin/cp "${SOURCE_ROOT}/scripts/release/source_manifest.py"'
            )
            block_end = release_script.index(
                'SOURCE_SNAPSHOT_MANIFEST="$(python3 /dev/fd/8', block_start
            )
            production_fd_block = release_script[block_start:block_end]
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    f"""
set -euo pipefail
SOURCE_ROOT="$1"
TRUSTED_SOURCE_MANIFEST="$2"
{production_fd_block}
run_compiler /bin/bash -c 'test ! -e /dev/fd/8; test ! -e /dev/fd/9'
test -e /dev/fd/8
test -e /dev/fd/9
if /bin/bash -c 'printf attack >&8' 2>/dev/null; then exit 1; fi
/usr/bin/cmp /dev/fd/8 "$1/scripts/release/source_manifest.py"
/usr/bin/cmp /dev/fd/9 "$1/scripts/release/source_manifest.py"
test "$(/usr/bin/stat -f '%l' /dev/fd/8)" = 0
test "$(/usr/bin/stat -f '%l' /dev/fd/9)" = 0
test ! -e "$2"
""",
                    "diskplan-fd-test",
                    str(source_root),
                    str(trusted),
                ],
                cwd=temporary,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))

    def test_manifest_changes_for_content_drift_but_not_equivalent_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.txt"
            source.write_text("one\n", encoding="ascii")
            initial = source_manifest.snapshot_manifest(root)

            source.write_text("two\n", encoding="ascii")
            content_changed = source_manifest.snapshot_manifest(root)
            self.assertNotEqual(initial, content_changed)

            replacement = root / "replacement.txt"
            replacement.write_text("two\n", encoding="ascii")
            os.replace(replacement, source)
            replaced = source_manifest.snapshot_manifest(root)
            self.assertEqual(content_changed, replaced)

    def test_timestamp_only_change_preserves_protected_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.txt"
            source.write_text("stable\n", encoding="ascii")
            initial = source_manifest.snapshot_manifest(root)
            metadata = source.stat()
            os.utime(
                source,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
            self.assertEqual(initial, source_manifest.snapshot_manifest(root))

    def test_compilation_content_mutation_is_rejected_by_sealed_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.swift"
            source.write_text("let value = 1\n", encoding="ascii")
            baseline = source_manifest.snapshot(root)
            source.write_text("let value = 2\n", encoding="ascii")
            comparison = source_manifest.compare_snapshots(
                baseline, source_manifest.snapshot(root)
            )
            self.assertEqual(
                [(change.relative, change.fields) for change in comparison.protected],
                [(b"source.swift", ("content",))],
            )

    def test_compilation_generated_entry_is_rejected_by_sealed_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = source_manifest.snapshot(root)
            generated = root / ".swiftpm"
            generated.mkdir()
            (generated / "workspace-state.json").write_text("{}\n", encoding="ascii")
            comparison = source_manifest.compare_snapshots(
                baseline, source_manifest.snapshot(root)
            )
            self.assertEqual(
                [(change.relative, change.fields) for change in comparison.protected],
                [
                    (b".swiftpm", ("added",)),
                    (b".swiftpm/workspace-state.json", ("added",)),
                ],
            )

    def test_mode_kind_removal_and_symlink_target_drift_are_protected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_text("stable\n", encoding="ascii")
            baseline = source_manifest.snapshot(root)
            source.chmod(0o600)
            comparison = source_manifest.compare_snapshots(
                baseline, source_manifest.snapshot(root)
            )
            self.assertEqual(comparison.protected[0].fields, ("mode",))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_text("stable\n", encoding="ascii")
            baseline = source_manifest.snapshot(root)
            source.unlink()
            source.mkdir()
            comparison = source_manifest.compare_snapshots(
                baseline, source_manifest.snapshot(root)
            )
            self.assertEqual(
                comparison.protected[0].fields, ("kind", "mode", "size", "payload")
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_text("stable\n", encoding="ascii")
            baseline = source_manifest.snapshot(root)
            source.unlink()
            comparison = source_manifest.compare_snapshots(
                baseline, source_manifest.snapshot(root)
            )
            self.assertEqual(comparison.protected[0].fields, ("removed",))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link = root / "link"
            link.symlink_to("first")
            baseline = source_manifest.snapshot(root)
            link.unlink()
            link.symlink_to("other")
            comparison = source_manifest.compare_snapshots(
                baseline, source_manifest.snapshot(root)
            )
            self.assertEqual(comparison.protected[0].fields, ("payload",))

    def test_entry_limit_applies_while_directory_is_enumerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(5):
                (root / f"source-{index}").write_text("stable\n", encoding="ascii")
            real_scandir = os.scandir

            class TrackingScandir:
                def __init__(self, path: Path) -> None:
                    self.inner = real_scandir(path)
                    self.yielded = 0

                def __enter__(self) -> "TrackingScandir":
                    self.inner.__enter__()
                    return self

                def __exit__(self, *args: object) -> None:
                    self.inner.__exit__(*args)

                def __iter__(self) -> "TrackingScandir":
                    return self

                def __next__(self) -> os.DirEntry[str]:
                    child = next(self.inner)
                    self.yielded += 1
                    return child

            tracking = TrackingScandir(root)
            with (
                mock.patch.object(source_manifest, "MAX_ENTRIES", 2),
                mock.patch.object(source_manifest.os, "scandir", return_value=tracking),
                self.assertRaisesRegex(ValueError, "exceeds 2 entries"),
            ):
                source_manifest.snapshot(root)
            self.assertEqual(tracking.yielded, 2)

    def test_entry_limit_is_global_across_nested_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(3):
                directory = root / f"directory-{index}"
                directory.mkdir()
                (directory / "source").write_text("stable\n", encoding="ascii")
            real_scandir = os.scandir
            yielded = 0

            class TrackingScandir:
                def __init__(self, path: Path) -> None:
                    self.inner = real_scandir(path)

                def __enter__(self) -> "TrackingScandir":
                    self.inner.__enter__()
                    return self

                def __exit__(self, *args: object) -> None:
                    self.inner.__exit__(*args)

                def __iter__(self) -> "TrackingScandir":
                    return self

                def __next__(self) -> os.DirEntry[str]:
                    nonlocal yielded
                    child = next(self.inner)
                    yielded += 1
                    return child

            with (
                mock.patch.object(source_manifest, "MAX_ENTRIES", 4),
                mock.patch.object(
                    source_manifest.os,
                    "scandir",
                    side_effect=lambda path: TrackingScandir(path),
                ),
                self.assertRaisesRegex(ValueError, "exceeds 4 entries"),
            ):
                source_manifest.snapshot(root)
            self.assertEqual(yielded, 4)

    def test_identical_resolved_rewrite_is_observation_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resolved = root / "Package.resolved"
            resolved.write_text('{"version":2}\n', encoding="ascii")
            baseline = source_manifest.snapshot(root)
            replacement = root / "replacement"
            replacement.write_bytes(resolved.read_bytes())
            os.replace(replacement, resolved)
            current = source_manifest.snapshot(root)
            comparison = source_manifest.compare_snapshots(baseline, current)
            self.assertEqual(baseline.protected_digest, current.protected_digest)
            self.assertEqual(comparison.protected, ())
            self.assertIn(
                b"Package.resolved",
                [change.relative for change in comparison.observations],
            )

    def test_snapshot_record_round_trip_and_tamper_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.txt").write_text("stable\n", encoding="ascii")
            baseline = source_manifest.snapshot(root)
            record = source_manifest.snapshot_record(baseline)
            self.assertEqual(source_manifest.parse_snapshot_record(record), baseline)
            tampered = json.loads(record)
            tampered["entries"][1]["payload_hex"] = "00" * 32
            with self.assertRaisesRegex(ValueError, "protected digest does not match"):
                source_manifest.parse_snapshot_record(
                    json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode(
                        "ascii"
                    )
                )

    def test_snapshot_record_rejects_extra_and_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.txt").write_text("stable\n", encoding="ascii")
            record = json.loads(
                source_manifest.snapshot_record(source_manifest.snapshot(root))
            )
            record["extra"] = True
            with self.assertRaisesRegex(ValueError, "record keys are invalid"):
                source_manifest.parse_snapshot_record(
                    json.dumps(record, separators=(",", ":"), sort_keys=True).encode(
                        "ascii"
                    )
                )
            del record["extra"]
            record["entries"].append(record["entries"][-1])
            with self.assertRaisesRegex(ValueError, "unique and sorted"):
                source_manifest.parse_snapshot_record(
                    json.dumps(record, separators=(",", ":"), sort_keys=True).encode(
                        "ascii"
                    )
                )

    def test_snapshot_record_file_is_owner_private_and_no_follow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.txt").write_text("stable\n", encoding="ascii")
            record_path = root / "snapshot.json"
            baseline = source_manifest.snapshot(source_root)
            source_manifest.write_snapshot_record(record_path, baseline)
            self.assertEqual(stat.S_IMODE(record_path.stat().st_mode), 0o600)
            record_digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            self.assertEqual(
                source_manifest.load_snapshot_record(record_path, record_digest), baseline
            )
            record_path.unlink()
            target = root / "target.json"
            target.write_text("do not replace\n", encoding="ascii")
            record_path.symlink_to(target)
            with self.assertRaises(OSError):
                source_manifest.write_snapshot_record(record_path, baseline)
            self.assertEqual(target.read_text(encoding="ascii"), "do not replace\n")

    def test_snapshot_record_rejects_noncanonical_and_observation_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.txt").write_text("stable\n", encoding="ascii")
            baseline = source_manifest.snapshot(source_root)
            canonical = source_manifest.snapshot_record(baseline)
            noncanonical = json.dumps(json.loads(canonical), indent=2).encode("ascii")
            with self.assertRaisesRegex(ValueError, "not canonical"):
                source_manifest.parse_snapshot_record(noncanonical)
            record_path = root / "snapshot.json"
            source_manifest.write_snapshot_record(record_path, baseline)
            record_digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            record = json.loads(record_path.read_bytes())
            record["entries"][0]["observation"]["mtime_ns"] += 1
            record_path.write_bytes(
                json.dumps(record, separators=(",", ":"), sort_keys=True).encode("ascii")
                + b"\n"
            )
            with self.assertRaisesRegex(ValueError, "sealed baseline"):
                source_manifest.load_snapshot_record(record_path, record_digest)

    def test_snapshot_record_rejects_mode_owner_and_link_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            baseline = source_manifest.snapshot(source_root)
            record_path = root / "snapshot.json"
            source_manifest.write_snapshot_record(record_path, baseline)
            record_digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            record_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner-private"):
                source_manifest.load_snapshot_record(record_path, record_digest)
            record_path.chmod(0o600)
            linked = root / "linked-snapshot.json"
            os.link(record_path, linked)
            with self.assertRaisesRegex(ValueError, "owner-private"):
                source_manifest.load_snapshot_record(record_path, record_digest)
            linked.unlink()

            parent_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with (
                mock.patch.object(
                    source_manifest,
                    "open_private_record_parent",
                    return_value=(parent_descriptor, record_path.name),
                ),
                mock.patch.object(
                    source_manifest.os, "geteuid", return_value=os.geteuid() + 1
                ),
                self.assertRaisesRegex(ValueError, "owner-private"),
            ):
                source_manifest.load_snapshot_record(record_path, record_digest)

    def test_snapshot_record_rejects_name_slot_replacement_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            baseline = source_manifest.snapshot(source_root)
            record_path = root / "snapshot.json"
            source_manifest.write_snapshot_record(record_path, baseline)
            record_digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            replacement = root / "replacement.json"
            replacement.write_bytes(record_path.read_bytes())
            replacement.chmod(0o600)
            real_read = os.read
            replaced = False

            def read_then_replace(descriptor: int, maximum: int) -> bytes:
                nonlocal replaced
                chunk = real_read(descriptor, maximum)
                if not replaced:
                    os.replace(replacement, record_path)
                    replaced = True
                return chunk

            with (
                mock.patch.object(source_manifest.os, "read", side_effect=read_then_replace),
                self.assertRaisesRegex(ValueError, "changed while reading"),
            ):
                source_manifest.load_snapshot_record(record_path, record_digest)

    def test_cli_reports_exact_protected_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            source = source_root / "Package.swift"
            source.write_text("let value = 1\n", encoding="ascii")
            baseline = source_manifest.snapshot(source_root)
            record_path = root / "snapshot.json"
            source_manifest.write_snapshot_record(record_path, baseline)
            record_digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            source.write_text("let value = 2\n", encoding="ascii")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "source_manifest.py"),
                    "--compare-to",
                    str(record_path),
                    "--expected-record-sha256",
                    record_digest,
                    str(source_root),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b"")
            self.assertIn(b"protected source change: Package.swift: content", completed.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "extended ACLs require macOS")
    def test_snapshot_record_rejects_extended_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            baseline = source_manifest.snapshot(source_root)
            record_path = root / "snapshot.json"
            source_manifest.write_snapshot_record(record_path, baseline)
            subprocess.run(
                ["/bin/chmod", "+a", "everyone allow read", str(record_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            record_digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "ACL-free"):
                source_manifest.load_snapshot_record(record_path, record_digest)

    @unittest.skipUnless(sys.platform == "darwin", "extended ACLs require macOS")
    def test_snapshot_record_rejects_parent_directory_extended_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            baseline = source_manifest.snapshot(source_root)
            subprocess.run(
                ["/bin/chmod", "+a", "everyone allow read", str(root)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self.assertRaisesRegex(ValueError, "directory.*ACL-free"):
                source_manifest.write_snapshot_record(root / "snapshot.json", baseline)

    @unittest.skipUnless(sys.platform == "darwin", "extended ACLs require macOS")
    def test_acl_probe_distinguishes_absent_present_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertTrue(source_manifest.fd_acl_free(descriptor))
                self.assertTrue(packager.output_directory_acl_free(descriptor))
                subprocess.run(
                    ["/bin/chmod", "+a", "everyone allow read", str(root)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertFalse(source_manifest.fd_acl_free(descriptor))
                self.assertFalse(packager.output_directory_acl_free(descriptor))
            finally:
                os.close(descriptor)
        with self.assertRaises(OSError):
            source_manifest.fd_acl_free(-1)
        with self.assertRaises(OSError):
            packager.output_directory_acl_free(-1)

    def test_hash_regular_rejects_replacement_after_lstat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.txt"
            source.write_text("same\n", encoding="ascii")
            initial = source.lstat()
            replacement = root / "replacement.txt"
            replacement.write_text("same\n", encoding="ascii")
            os.replace(replacement, source)
            with self.assertRaises(ValueError):
                source_manifest.hash_regular(source, initial)


class StagedFileTests(unittest.TestCase):
    def test_timestamp_only_source_change_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"stable\n")
            staged = packager.stage_source(source, root / "staged", 1024, 0o644)
            try:
                metadata = source.stat()
                os.utime(
                    source,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
                )
                staged.assert_source_stable()
            finally:
                staged.close()

    def test_same_size_source_content_change_is_rejected_even_with_restored_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"first\n")
            original = source.stat()
            staged = packager.stage_source(source, root / "staged", 1024, 0o644)
            try:
                source.write_bytes(b"other\n")
                os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
                with self.assertRaisesRegex(ValueError, "source content changed"):
                    staged.assert_source_stable()
            finally:
                staged.close()

    def test_source_ancestor_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            source = parent / "source"
            source.write_bytes(b"stable\n")
            staged = packager.stage_source(source, root / "staged", 1024, 0o644)
            try:
                parent.rename(root / "original-parent")
                parent.mkdir()
                (parent / "source").write_bytes(b"replacement\n")
                with self.assertRaisesRegex(ValueError, "bound directory slot was replaced"):
                    staged.assert_source_stable()
            finally:
                staged.close()

    def test_hash_regular_rejects_content_drift_after_lstat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.txt"
            source.write_text("one\n", encoding="ascii")
            initial = source.lstat()
            source.write_text("two\n", encoding="ascii")
            with self.assertRaises(ValueError):
                source_manifest.hash_regular(source, initial)


class MachOContractTests(unittest.TestCase):
    def test_all_three_components_are_mandatory(self) -> None:
        staged = {
            "diskplan": object(),
            "diskplan-engine": object(),
            "diskplan-fs-helper": object(),
        }
        with mock.patch.object(packager, "require_macho_contract") as require:
            packager.validate_macho_components(staged, "14.0")
        self.assertEqual(
            require.call_args_list,
            [
                mock.call(staged["diskplan"], "14.0"),
                mock.call(staged["diskplan-engine"], "14.0"),
                mock.call(staged["diskplan-fs-helper"], "14.0"),
            ],
        )

    def test_wrong_minimum_macos_is_rejected(self) -> None:
        file = SimpleNamespace(path=Path("/private/test/diskplan"))
        vtool = b"""diskplan (architecture arm64):
Load command 1
      cmd LC_BUILD_VERSION
 platform MACOS
    minos 13.0
      sdk 26.0
"""
        results = [
            packager.ProbeResult(stdout=b"arm64\n", returncode=0),
            packager.ProbeResult(stdout=vtool, returncode=0),
        ]
        with mock.patch.object(packager, "run_staged", side_effect=results):
            with self.assertRaisesRegex(ValueError, "wrong platform or minimum"):
                packager.require_macho_contract(file, "14.0")


class PublicationTests(unittest.TestCase):
    def make_set(self, directory_fd: int, archive_name: str, payload: bytes):
        archive_temp, archive_fd = packager.create_output_temp(directory_fd, archive_name)
        packager.write_all(archive_fd, payload)
        os.fchmod(archive_fd, 0o644)
        os.fsync(archive_fd)
        archive_digest = packager.digest_fd(archive_fd, packager.MAX_ARCHIVE_BYTES)
        sidecar_temp, sidecar_fd, sidecar_data = packager.create_sidecar(
            directory_fd, archive_name, archive_digest
        )
        return (
            archive_temp,
            archive_fd,
            archive_digest,
            sidecar_temp,
            sidecar_fd,
            sidecar_data,
        )

    def publish(self, directory_fd: int, archive_name: str, values) -> None:
        packager.publish_verified_set(
            directory_fd,
            values[0],
            values[1],
            archive_name,
            values[2],
            values[3],
            values[4],
            values[5],
        )

    def close_set(self, values) -> None:
        os.close(values[1])
        os.close(values[4])

    def test_exact_set_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            values = self.make_set(directory_fd, "release.tar.gz", b"archive")
            try:
                self.publish(directory_fd, "release.tar.gz", values)
                self.publish(directory_fd, "release.tar.gz", values)
            finally:
                self.close_set(values)
                os.close(directory_fd)

    def test_exact_orphan_sidecar_is_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            archive_name = "release.tar.gz"
            values = self.make_set(directory_fd, archive_name, b"archive")
            try:
                os.link(
                    values[3],
                    f"{archive_name}.sha256",
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                self.publish(directory_fd, archive_name, values)
                self.assertTrue((Path(temporary) / archive_name).is_file())
            finally:
                self.close_set(values)
                os.close(directory_fd)

    def test_mismatched_orphan_sidecar_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            archive_name = "release.tar.gz"
            values = self.make_set(directory_fd, archive_name, b"archive")
            checksum = Path(temporary) / f"{archive_name}.sha256"
            checksum.write_text("0" * 64 + f"  {archive_name}\n", encoding="ascii")
            checksum.chmod(0o644)
            try:
                with self.assertRaises(FileExistsError):
                    self.publish(directory_fd, archive_name, values)
                self.assertFalse((Path(temporary) / archive_name).exists())
            finally:
                self.close_set(values)
                os.close(directory_fd)

    def test_hostile_sidecar_symlink_never_touches_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            target = root / "target"
            target.write_text("sentinel\n", encoding="ascii")
            directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
            archive_name = "release.tar.gz"
            values = self.make_set(directory_fd, archive_name, b"archive")
            os.symlink(target, output / f"{archive_name}.sha256")
            try:
                with self.assertRaises(OSError):
                    self.publish(directory_fd, archive_name, values)
                self.assertEqual(target.read_text(encoding="ascii"), "sentinel\n")
            finally:
                self.close_set(values)
                os.close(directory_fd)


class DeterministicGzipTests(unittest.TestCase):
    def test_output_directory_must_be_exclusive_to_current_euid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o777)
            output.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "non-group/world-writable"):
                packager.open_output_directory(output)

    @unittest.skipUnless(sys.platform == "darwin", "extended ACLs require macOS")
    def test_output_directory_rejects_extended_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            subprocess.run(
                ["/bin/chmod", "+a", "everyone allow read", str(output)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self.assertRaisesRegex(ValueError, "ACL-free"):
                packager.open_output_directory(output)

    def test_archive_rejects_ancestor_replacement_after_descriptor_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            bundle = make_test_bundle(root)
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "builtin-v1.json").write_bytes(b"unverified\n")
            real_bind = packager.bind_verified_bundle

            def bind_then_replace(path: Path) -> object:
                verified = real_bind(path)
                (bundle / "rules").rename(bundle / "retired-rules")
                (bundle / "rules").symlink_to(outside, target_is_directory=True)
                return verified

            directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    packager,
                    "bind_verified_bundle",
                    side_effect=bind_then_replace,
                ):
                    with self.assertRaisesRegex(ValueError, "source ancestor was replaced"):
                        packager.build_archive(bundle, directory_fd, "release.tar.gz")
                self.assertEqual(list(output.iterdir()), [])
            finally:
                os.close(directory_fd)

    def test_header_level_and_archive_bytes_are_pinned(self) -> None:
        packager.require_pinned_zlib()
        archives: list[bytes] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(2):
                parent = root / str(index)
                output = parent / "output"
                bundle = make_test_bundle(parent, reverse=index == 1)
                output.mkdir()
                os.utime(bundle / "VERSION", (100 + index, 200 + index))
                directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
                name, descriptor, _digest = packager.build_archive(
                    bundle, directory_fd, "release.tar.gz"
                )
                try:
                    archives.append(
                        packager.read_fd(descriptor, packager.MAX_ARCHIVE_BYTES)
                    )
                finally:
                    os.close(descriptor)
                    os.unlink(name, dir_fd=directory_fd)
                    os.close(directory_fd)
        self.assertEqual(archives[0], archives[1])
        self.assertEqual(
            [packager.digest(archive) for archive in archives],
            [
                "5bce31c2eb91417c4354d3a82d18062a397fe07b5345234c22e741f8e14391c2",
                "5bce31c2eb91417c4354d3a82d18062a397fe07b5345234c22e741f8e14391c2",
            ],
        )
        self.assertEqual(archives[0][:10], packager.GZIP_HEADER)
        self.assertEqual(archives[0][4:8], b"\x00\x00\x00\x00")
        self.assertEqual(archives[0][8], 2)
        self.assertEqual(archives[0][9], 255)
        self.assertTrue(gzip.decompress(archives[0]).startswith(b"diskplan-test/"))

    def test_unpinned_zlib_is_rejected(self) -> None:
        with mock.patch.object(packager.zlib, "ZLIB_RUNTIME_VERSION", "future"):
            with self.assertRaises(RuntimeError):
                packager.require_pinned_zlib()


class BundleManifestTests(unittest.TestCase):
    def test_missing_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_test_bundle(Path(temporary))
            (bundle / "VERSION").unlink()
            with self.assertRaisesRegex(ValueError, "missing or extra"):
                packager.verify_bundle_tree(bundle)

    def test_tampered_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_test_bundle(Path(temporary))
            (bundle / "VERSION").write_text("0.2.0\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                packager.verify_bundle_tree(bundle)

    def test_extra_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_test_bundle(Path(temporary))
            (bundle / "extra").write_text("unexpected\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "missing or extra"):
                packager.verify_bundle_tree(bundle)

    def test_manifest_case_fold_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_test_bundle(Path(temporary))
            manifest_path = bundle / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            duplicate = dict(manifest["artifacts"][1])
            duplicate["path"] = "Rules/Builtin-v1.json"
            manifest["artifacts"].append(duplicate)
            manifest["artifacts"].sort(key=lambda item: os.fsencode(item["path"]))
            manifest_path.write_bytes(packager.canonical_json(manifest))
            with self.assertRaisesRegex(ValueError, "path collision"):
                packager.verify_bundle_tree(bundle)

    def test_manifest_schema_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_test_bundle(Path(temporary))
            manifest_path = bundle / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["manifest_schema_version"] = "diskplan.bundle-manifest.v999"
            manifest_path.write_bytes(packager.canonical_json(manifest))
            with self.assertRaisesRegex(ValueError, "schema version"):
                packager.verify_bundle_tree(bundle)

    def test_contract_rejects_duplicate_case_folded_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract_path = Path(temporary) / "contract.json"
            contract = {
                "artifacts": [
                    {
                        "bundle_path": "rules/value",
                        "compatibility_version": "rules-v1",
                        "maximum_bytes": 10,
                        "mode": "0644",
                        "role": "declarative-rules",
                        "source": "rules/value",
                    },
                    {
                        "bundle_path": "Rules/value",
                        "compatibility_version": "rules-v1",
                        "maximum_bytes": 10,
                        "mode": "0644",
                        "role": "declarative-rules",
                        "source": "Rules/value",
                    },
                ],
                "excluded": [],
                "schema_version": packager.CONTRACT_SCHEMA_VERSION,
            }
            contract_path.write_bytes(packager.canonical_compact_json(contract))
            with self.assertRaisesRegex(ValueError, "case-fold-colliding"):
                packager.load_bundle_contract(contract_path)


class PackagingAssetsTests(unittest.TestCase):
    def test_main_packages_the_exact_runtime_contract(self) -> None:
        repository_root = SCRIPT_DIR.parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            components = root / "components"
            components.mkdir()
            inputs = {}
            for name in ("diskplan", "diskplan-engine", "diskplan-fs-helper"):
                path = components / name
                path.write_bytes(f"fake-{name}\n".encode("ascii"))
                path.chmod(0o755)
                inputs[name] = path
            arguments = SimpleNamespace(
                frontend=inputs["diskplan"],
                engine=inputs["diskplan-engine"],
                fs_helper=inputs["diskplan-fs-helper"],
                installer=SCRIPT_DIR / "install.sh",
                activator=SCRIPT_DIR / "activate.sh",
                uninstaller=SCRIPT_DIR / "uninstall.sh",
                common_library=SCRIPT_DIR / "release-common.sh",
                version_file=repository_root / "release/VERSION",
                protocol_metadata=repository_root / "release/protocol.json",
                asset_root=repository_root,
                bundle_contract=repository_root / "release/bundle-contract.json",
                source_revision="1" * 40,
                output_dir=output,
                require_macho_arm64=False,
            )

            def identity(_file, component):
                return {
                    "component": component,
                    "product_version": "0.1.0",
                    "protocol_major": 1,
                    "protocol_minor": 4,
                }

            helper = {
                "component": "diskplan-fs-helper",
                "product_version": "0.1.0",
                "protocol_major": 1,
                "protocol_minor": 4,
                "helper_abi": 1,
            }
            with (
                mock.patch.object(packager, "parse_args", return_value=arguments),
                mock.patch.object(packager, "validate_macho_components"),
                mock.patch.object(packager, "component_identity", side_effect=identity),
                mock.patch.object(packager, "helper_identity", return_value=helper),
                mock.patch("builtins.print"),
            ):
                self.assertEqual(packager.main(), 0)

            archive = output / "diskplan-0.1.0-macos-arm64.tar.gz"
            with tarfile.open(archive, "r:gz") as bundled:
                names = bundled.getnames()
                manifest_member = bundled.extractfile(
                    "diskplan-0.1.0-macos-arm64/manifest.json"
                )
                self.assertIsNotNone(manifest_member)
                manifest = json.load(manifest_member)
            artifact_paths = [item["path"] for item in manifest["artifacts"]]
            artifact_compatibility = {
                item["path"]: item["compatibility_version"]
                for item in manifest["artifacts"]
            }
            self.assertIn("rules/builtin-v1.json", artifact_paths)
            self.assertIn("rules/user-policy-default-v1.json", artifact_paths)
            self.assertIn("proto/diskplan/v1/ipc.proto", artifact_paths)
            self.assertIn("proto/fixtures/canonical-binary-v1/evidence.bin", artifact_paths)
            runtime_fixture_paths = {
                "proto/fixtures/runtime-v1.4/README.md",
                "proto/fixtures/runtime-v1.4/codex-scope-action.frames.hex",
                "proto/fixtures/runtime-v1.4/empty-batch-dry-run.frames.hex",
                "proto/fixtures/runtime-v1.4/fixtures.json",
                "proto/fixtures/runtime-v1.4/force-action-execution.frames.hex",
                "proto/fixtures/runtime-v1.4/git-evidence-action.frames.hex",
                "proto/fixtures/runtime-v1.4/version-survivor-action.frames.hex",
            }
            self.assertTrue(runtime_fixture_paths.issubset(artifact_paths))
            self.assertEqual(
                {artifact_compatibility[path] for path in runtime_fixture_paths},
                {"runtime-v1.4"},
            )
            self.assertIn("runtime-capabilities.json", artifact_paths)
            self.assertEqual(manifest["protocol_minor"], 4)
            self.assertEqual(
                manifest["optional_capabilities"],
                [
                    "audit-artifact-v1",
                    "execution-record-artifact-v1",
                    "history-artifact-v1",
                    "saved-plan-artifact-v1",
                ],
            )
            self.assertFalse(any("history.json" in name for name in names))
            self.assertFalse(any("execution-record.json" in name for name in names))

    def test_repository_asset_symlink_is_rejected_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("data\n", encoding="ascii")
            (root / "link").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "cannot safely open regular file"):
                packager.require_safe_repository_source(root, "link")

    def test_cleanup_does_not_delete_a_replacement_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            original.write_bytes(b"owned\n")
            held = os.open(original, os.O_RDONLY)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                replacement = root / "replacement"
                replacement.write_bytes(b"keep\n")
                os.replace(replacement, original)
                packager.unlink_if_same(directory, "original", held, 1024)
                self.assertEqual(original.read_bytes(), b"keep\n")
            finally:
                os.close(directory)
                os.close(held)

    def test_cleanup_retains_both_objects_when_quarantine_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            original.write_bytes(b"owned\n")
            held = os.open(original, os.O_RDONLY)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            real_rename = packager.rename_exclusive

            def replace_quarantine(
                source_fd: int,
                source: str,
                destination_fd: int,
                destination: str,
            ) -> None:
                real_rename(source_fd, source, destination_fd, destination)
                os.rename(
                    destination,
                    ".retained-owned",
                    src_dir_fd=destination_fd,
                    dst_dir_fd=destination_fd,
                )
                replacement = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=destination_fd,
                )
                try:
                    os.write(replacement, b"replacement\n")
                finally:
                    os.close(replacement)

            try:
                with mock.patch.object(
                    packager,
                    "rename_exclusive",
                    side_effect=replace_quarantine,
                ):
                    with self.assertRaisesRegex(ValueError, "retained a replaced object"):
                        packager.unlink_if_same(directory, "original", held, 1024)
                self.assertEqual((root / ".retained-owned").read_bytes(), b"owned\n")
                quarantines = list(root.glob(".diskplan-remove-*"))
                self.assertEqual(len(quarantines), 1)
                self.assertEqual(quarantines[0].read_bytes(), b"replacement\n")
                self.assertFalse(original.exists())
            finally:
                os.close(directory)
                os.close(held)


class BoundedProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        source = self.root / "source"
        source.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        source.chmod(0o755)
        self.staged = packager.stage_source(
            source,
            self.root / "staged",
            packager.MAX_METADATA_BYTES,
            0o755,
        )

    def tearDown(self) -> None:
        self.staged.close()
        self.temporary.cleanup()

    def test_output_cap_terminates_whole_group(self) -> None:
        with self.assertRaisesRegex(ValueError, "bounded process-group"):
            packager.run_staged(self.staged, ["/usr/bin/yes"], "output probe")

    def test_timeout_terminates_whole_group(self) -> None:
        with mock.patch.object(packager, "PROBE_TIMEOUT_SECONDS", 1):
            with self.assertRaisesRegex(ValueError, "bounded process-group"):
                packager.run_staged(self.staged, ["/bin/sleep", "30"], "timeout probe")

    def test_background_descendant_is_reaped_before_success(self) -> None:
        result = packager.run_staged(
            self.staged,
            ["/bin/sh", "-c", "sleep 30 & exit 0"],
            "descendant probe",
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_failure_retains_only_a_bounded_supervisor_report_summary(self) -> None:
        report = {
            "cleanup": {
                "attempted": True,
                "term_attempted": True,
                "term_sent": False,
                "kill_attempted": True,
                "kill_sent": False,
                "quiescent": True,
            },
            "command_output": "must-not-leak",
            "elapsed_millis": 3,
            "error_type": "ProcessLookupError",
            "exit_code": 70,
            "leader_exit_code": 0,
            "output_bytes": 27,
            "process_group_verified": False,
            "result": "supervisor_failed",
            "termination_signal": None,
        }
        completed = SimpleNamespace(
            stdout=json.dumps(report).encode("ascii"),
            stderr=b"",
            returncode=70,
        )
        with mock.patch.object(packager.subprocess, "run", return_value=completed):
            with self.assertRaises(ValueError) as raised:
                packager.run_staged(self.staged, ["/usr/bin/true"], "identity probe")

        message = str(raised.exception)
        self.assertIn('"error_type":"ProcessLookupError"', message)
        self.assertIn('"result":"supervisor_failed"', message)
        self.assertIn('"supervisor_returncode":70', message)
        self.assertNotIn("command_output", message)
        self.assertNotIn("must-not-leak", message)


if __name__ == "__main__":
    unittest.main()
