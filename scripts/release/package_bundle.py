#!/usr/bin/env python3
"""Build a deterministic Diskplan macOS arm64 release archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--activator", type=Path, required=True)
    parser.add_argument("--uninstaller", type=Path, required=True)
    parser.add_argument("--common-library", type=Path, required=True)
    parser.add_argument("--version-file", type=Path, required=True)
    parser.add_argument("--protocol-metadata", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-macho-arm64", action="store_true")
    return parser.parse_args()


def read_regular_file(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"not a non-symlink regular file: {path}")
    if metadata.st_size > maximum:
        raise ValueError(f"file exceeds {maximum} bytes: {path}")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise ValueError(f"file size changed while reading: {path}")
    return data


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(read_regular_file(path, MAX_METADATA_BYTES))
    if type(value) is not dict:
        raise ValueError(f"expected a JSON object: {path}")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def component_identity(path: Path, expected_component: str) -> tuple[dict[str, Any], str]:
    initial_bytes = read_regular_file(path, MAX_BINARY_BYTES)
    initial_digest = digest(initial_bytes)
    completed = subprocess.run(
        [str(path), "--version-json"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if completed.returncode != 0:
        raise ValueError(f"{expected_component} --version-json exited {completed.returncode}")
    if completed.stderr:
        raise ValueError(f"{expected_component} --version-json wrote to stderr")
    if len(completed.stdout) > 4096:
        raise ValueError(f"{expected_component} --version-json exceeded 4096 bytes")
    try:
        identity = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{expected_component} returned malformed version JSON") from error
    if type(identity) is not dict or identity.get("component") != expected_component:
        raise ValueError(f"{expected_component} returned the wrong component identity")
    expected_keys = {
        "component",
        "product_version",
        "protocol_major",
        "protocol_minor",
    }
    if set(identity) != expected_keys:
        raise ValueError(f"{expected_component} returned an unsupported identity shape")
    if (
        type(identity["product_version"]) is not str
        or type(identity["protocol_major"]) is not int
        or type(identity["protocol_minor"]) is not int
    ):
        raise ValueError(f"{expected_component} returned identity fields with wrong types")
    if digest(read_regular_file(path, MAX_BINARY_BYTES)) != initial_digest:
        raise ValueError(f"{expected_component} changed during its identity probe")
    return identity, initial_digest


def require_macho_arm64(path: Path) -> None:
    completed = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    arches = completed.stdout.decode("ascii", errors="strict").split()
    if completed.returncode != 0 or "arm64" not in arches:
        raise ValueError(f"release binary does not contain arm64 Mach-O code: {path}")


def validate_protocol(metadata: dict[str, Any]) -> None:
    expected_types = {
        "architecture": str,
        "bundle_format": int,
        "deployment_target_macos": str,
        "protocol_major": int,
        "protocol_minor": int,
        "release_gate_macos": str,
        "required_capabilities": list,
    }
    if set(metadata) != set(expected_types):
        raise ValueError("protocol metadata has an unsupported shape")
    for key, expected_type in expected_types.items():
        if type(metadata[key]) is not expected_type:
            raise ValueError(f"protocol metadata field has wrong type: {key}")
    if metadata["architecture"] != "arm64" or metadata["bundle_format"] != 1:
        raise ValueError("unsupported release architecture or bundle format")
    if metadata["protocol_major"] < 1 or metadata["protocol_minor"] < 0:
        raise ValueError("invalid protocol version")
    capabilities = metadata["required_capabilities"]
    if (
        any(type(item) is not str or not item for item in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise ValueError("required capabilities must be unique and sorted")


def copy_artifact(
    source: Path,
    destination: Path,
    executable: bool,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    data = read_regular_file(source, MAX_BINARY_BYTES if executable else MAX_METADATA_BYTES)
    actual_digest = digest(data)
    if expected_sha256 is not None and actual_digest != expected_sha256:
        raise ValueError(f"artifact changed before packaging: {source}")
    destination.write_bytes(data)
    mode = 0o755 if executable else 0o644
    destination.chmod(mode)
    return {
        "name": destination.name,
        "mode": f"{mode:04o}",
        "sha256": actual_digest,
        "size": len(data),
    }


def add_tar_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "wheel"
    info.mtime = 0
    archive.addfile(info)


def add_tar_file(archive: tarfile.TarFile, path: Path, name: str) -> None:
    data = path.read_bytes()
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = stat.S_IMODE(path.stat().st_mode)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "wheel"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def digest_file(path: Path, maximum: int) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"not a non-symlink regular file: {path}")
    if metadata.st_size > maximum:
        raise ValueError(f"file exceeds {maximum} bytes: {path}")
    hasher = hashlib.sha256()
    consumed = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > maximum:
                raise ValueError(f"file grew beyond {maximum} bytes: {path}")
            hasher.update(chunk)
    if consumed != metadata.st_size:
        raise ValueError(f"file size changed while hashing: {path}")
    return hasher.hexdigest()


def build_archive(bundle: Path, archive_path: Path) -> None:
    temporary = archive_path.with_name(f".{archive_path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    add_tar_directory(archive, bundle.name)
                    for path in sorted(bundle.iterdir(), key=lambda item: os.fsencode(item.name)):
                        add_tar_file(archive, path, f"{bundle.name}/{path.name}")
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, archive_path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    args = parse_args()
    version = read_regular_file(args.version_file, 256).decode("ascii").strip()
    if not SEMVER.fullmatch(version):
        raise ValueError("VERSION is not a canonical semantic version")
    if not GIT_SHA.fullmatch(args.source_revision):
        raise ValueError("source revision must be an exact lowercase Git SHA")

    protocol = read_json(args.protocol_metadata)
    validate_protocol(protocol)
    frontend, frontend_digest = component_identity(args.frontend, "diskplan")
    engine, engine_digest = component_identity(args.engine, "diskplan-engine")
    expected_identity = {
        "product_version": version,
        "protocol_major": protocol["protocol_major"],
        "protocol_minor": protocol["protocol_minor"],
    }
    for component in (frontend, engine):
        for key, expected in expected_identity.items():
            if component[key] != expected:
                raise ValueError(f"component identity mismatch for {component['component']}: {key}")
    if args.require_macho_arm64:
        require_macho_arm64(args.frontend)
        require_macho_arm64(args.engine)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"diskplan-{version}-macos-arm64"
    with tempfile.TemporaryDirectory(prefix=".diskplan-package-", dir=args.output_dir) as staging:
        bundle = Path(staging) / bundle_name
        bundle.mkdir(mode=0o755)
        artifacts = [
            copy_artifact(args.frontend, bundle / "diskplan", True, frontend_digest),
            copy_artifact(args.engine, bundle / "diskplan-engine", True, engine_digest),
            copy_artifact(args.installer, bundle / "install.sh", True),
            copy_artifact(args.activator, bundle / "activate.sh", True),
            copy_artifact(args.uninstaller, bundle / "uninstall.sh", True),
            copy_artifact(args.common_library, bundle / "release-common.sh", False),
        ]
        version_path = bundle / "VERSION"
        version_path.write_text(f"{version}\n", encoding="ascii")
        version_path.chmod(0o644)
        artifacts.append(
            {
                "name": "VERSION",
                "mode": "0644",
                "sha256": digest(version_path.read_bytes()),
                "size": version_path.stat().st_size,
            }
        )
        protocol_path = bundle / "protocol.json"
        protocol_path.write_bytes(canonical_json(protocol))
        protocol_path.chmod(0o644)
        artifacts.append(
            {
                "name": "protocol.json",
                "mode": "0644",
                "sha256": digest(protocol_path.read_bytes()),
                "size": protocol_path.stat().st_size,
            }
        )
        artifacts.sort(key=lambda item: os.fsencode(item["name"]))

        manifest = {
            "architecture": protocol["architecture"],
            "artifacts": artifacts,
            "bundle_format": protocol["bundle_format"],
            "deployment_target_macos": protocol["deployment_target_macos"],
            "product_version": version,
            "protocol_major": protocol["protocol_major"],
            "protocol_minor": protocol["protocol_minor"],
            "release_gate_macos": protocol["release_gate_macos"],
            "required_capabilities": protocol["required_capabilities"],
            "source_revision": args.source_revision,
        }
        manifest_path = bundle / "manifest.json"
        manifest_path.write_bytes(canonical_json(manifest))
        manifest_path.chmod(0o644)

        checksummed = artifacts + [
            {
                "name": "manifest.json",
                "sha256": digest(manifest_path.read_bytes()),
            }
        ]
        checksummed.sort(key=lambda item: os.fsencode(item["name"]))
        sums_path = bundle / "SHA256SUMS"
        sums_path.write_text(
            "".join(f"{item['sha256']}  {item['name']}\n" for item in checksummed),
            encoding="ascii",
        )
        sums_path.chmod(0o644)

        archive_path = args.output_dir / f"{bundle_name}.tar.gz"
        build_archive(bundle, archive_path)
        checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
        checksum_temporary = checksum_path.with_name(
            f".{checksum_path.name}.{os.getpid()}.tmp"
        )
        try:
            checksum_temporary.write_text(
                f"{digest_file(archive_path, 2 * MAX_BINARY_BYTES + MAX_METADATA_BYTES)}  {archive_path.name}\n",
                encoding="ascii",
            )
            checksum_temporary.chmod(0o644)
            os.replace(checksum_temporary, checksum_path)
        finally:
            checksum_temporary.unlink(missing_ok=True)
        print(archive_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
