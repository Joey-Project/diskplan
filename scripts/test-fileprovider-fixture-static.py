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
    accept = lifecycle.index("accept()")
    require(
        lifecycle.index('"$host" prepare', accept)
        < lifecycle.index("\n  register_extension\n", accept),
        "manifest preparation must precede extension registration",
    )
    require("pluginkit -a " not in lifecycle, "registration must not use an unbounded pluginkit command")
    require("pluginkit -r " not in lifecycle, "unregistration must not use an unbounded pluginkit command")
    require("fileprovider-fixture-pluginkit.py" in lifecycle, "pluginkit mutation must use a bounded helper")
    require("verify_elected_extension" in lifecycle, "registration must verify the elected physical appex")
    require("unregister_extension" in lifecycle, "recovery must unregister the exact manifest appex")
    require(lifecycle.count("verify_removed_extension") == 3, "both teardown paths must verify exact-path removal")
    require("--state absent" in lifecycle, "registry removal verification must inspect all exact-bundle entries")
    recover = lifecycle[lifecycle.index("recover()") : lifecycle.index("accept()")]
    require(
        recover.index("unregister_extension")
        < recover.index("verify_removed_extension")
        < recover.index('"$host" cleanup'),
        "recovery cleanup must follow verified registry removal",
    )
    accept_body = lifecycle[lifecycle.index("accept()") : lifecycle.index("command=$1")]
    require(
        accept_body.index("unregister_extension")
        < accept_body.index("verify_removed_extension")
        < accept_body.index('"$host" cleanup'),
        "acceptance cleanup must follow verified registry removal",
    )
    require("plutil -extract appPath" not in lifecycle, "recovery must not read executable paths before trusted validation")
    require('"$host" status --manifest' in lifecycle, "recovery must validate with the known host first")
    require("sleep 2" not in lifecycle, "fixed sleeps are not a quiescence oracle")
    require("closeWindowAfterQuiescence" in swift, "oracle close must use bounded event quiescence")
    require(
        '"$host" oracle-end --manifest "$manifest" --quiet-ms 2000 --timeout-ms 30000' in lifecycle,
        "acceptance must require a two-second quiet window within a 30-second bound",
    )
    first_probe = lifecycle.index('"$host" probe --manifest "$manifest"')
    second_probe = lifecycle.index('"$host" probe --manifest "$manifest"', first_probe + 1)
    oracle_end = lifecycle.index('"$host" oracle-end --manifest "$manifest"')
    assertion = lifecycle.index('"$host" assert --manifest "$manifest"')
    require(second_probe < oracle_end < assertion, "both provider probes must finish before the oracle closes")
    health = lifecycle.index('"$host" oracle-health --manifest "$manifest"')
    require(second_probe < health < oracle_end, "oracle health must be proven inside the open window")
    assert_body = swift[swift.index("private static func assertAcceptance"):]
    assert_body = assert_body[: assert_body.index("\n  }")]
    require("probe(" not in assert_body, "post-window assertion must not touch the provider path")
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
