#!/usr/bin/env python3
from pathlib import Path
import plistlib
import sys


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "FileProviderAcceptance"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    swift = "\n".join(path.read_text() for path in FIXTURE.rglob("*.swift"))
    lifecycle = (ROOT / "scripts" / "fileprovider-fixture.sh").read_text()
    all_fixture_text = swift + "\n" + lifecycle
    require("removeAllDomains" not in all_fixture_text, "bulk domain removal is forbidden")
    require("CloudStorage" not in lifecycle, "lifecycle must not delete or address CloudStorage")
    require("mode: .removeAll" in swift, "exact-domain teardown must request removeAll mode")
    require("domain.testingModes = []" in swift, "testing modes must remain empty")
    require("domain.isHidden = true" in swift, "fixture domain must be hidden")
    require("Data(contentsOf:" not in swift, "control files must not use pathname-following reads")
    require("O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW" in swift, "oracle append flags changed")
    require("flock(descriptor, LOCK_EX)" in swift, "oracle events must be lock-serialized")
    require("O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK" in swift, "secure control read flags changed")
    require("renameatx_np" in swift and "RENAME_EXCL" in swift, "cleanup must isolate the exact run atomically")
    require("FixtureContract.sentinelContents().write" in swift, "fetchContents must write real bytes")
    require('case "prepare"' in swift, "recovery manifest must be prepared before registration")
    require(
        lifecycle.index('"$host" prepare') < lifecycle.index('pluginkit -a "$appex"'),
        "manifest preparation must precede extension registration",
    )
    require("pluginkit -a \"$appex\"" in lifecycle, "registration must use the exact appex path")
    require("verify_elected_extension" in lifecycle, "registration must verify the elected physical appex")
    require("pluginkit -r \"$manifest_appex\"" in lifecycle, "recovery must unregister the manifest appex")
    require("plutil -extract appPath" not in lifecycle, "recovery must not read executable paths before trusted validation")
    require('"$host" status --manifest' in lifecycle, "recovery must validate with the known host first")
    require("sleep 2" not in lifecycle, "fixed sleeps are not a quiescence oracle")
    require("closeWindowAfterQuiescence" in swift, "oracle close must use bounded event quiescence")
    require('"scanner_acceptance":"not-run"' in lifecycle, "probe-level result must not claim scanner acceptance")
    for path in [FIXTURE / "Host" / "Host.entitlements", FIXTURE / "Extension" / "Extension.entitlements"]:
        with path.open("rb") as stream:
            entitlements = plistlib.load(stream)
        require("com.apple.developer.fileprovider.testing-mode" not in entitlements, f"testing-mode entitlement in {path}")
        require(
            entitlements.get("com.apple.security.application-groups")
            == ["group.com.joeyteng.diskplan.fileprovider-fixture"],
            f"unexpected App Group in {path}",
        )
    print("file-provider-fixture-static: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"file-provider-fixture-static: {error}", file=sys.stderr)
        raise SystemExit(1)
