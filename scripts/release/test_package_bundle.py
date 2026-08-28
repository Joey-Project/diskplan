#!/usr/bin/env python3
"""Adversarial unit tests for deterministic release packaging."""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
import stat
import sys
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
source_manifest = load_module(
    "diskplan_test_source_manifest", SCRIPT_DIR / "source_manifest.py"
)


class VersionMetadataTests(unittest.TestCase):
    def test_semver_rejects_numeric_prerelease_leading_zeroes(self) -> None:
        self.assertIsNone(packager.SEMVER.fullmatch("1.2.3-01"))
        self.assertIsNotNone(packager.SEMVER.fullmatch("1.2.3-0"))
        self.assertIsNotNone(packager.SEMVER.fullmatch("1.2.3-alpha.01a+001"))


class SourceManifestTests(unittest.TestCase):
    def test_manifest_changes_for_content_drift_and_replacement(self) -> None:
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
            self.assertNotEqual(content_changed, replaced)

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
    def test_header_level_and_archive_bytes_are_pinned(self) -> None:
        packager.require_pinned_zlib()
        archives: list[bytes] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(2):
                parent = root / str(index)
                bundle = parent / "diskplan-test"
                output = parent / "output"
                bundle.mkdir(parents=True)
                output.mkdir()
                packager.write_private_file(bundle / "VERSION", b"0.1.0\n", 0o644)
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
        self.assertEqual(archives[0][:10], packager.GZIP_HEADER)
        self.assertEqual(archives[0][4:8], b"\x00\x00\x00\x00")
        self.assertEqual(archives[0][8], 2)
        self.assertEqual(archives[0][9], 255)
        self.assertTrue(gzip.decompress(archives[0]).startswith(b"diskplan-test/"))

    def test_unpinned_zlib_is_rejected(self) -> None:
        with mock.patch.object(packager.zlib, "ZLIB_RUNTIME_VERSION", "future"):
            with self.assertRaises(RuntimeError):
                packager.require_pinned_zlib()


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


if __name__ == "__main__":
    unittest.main()
