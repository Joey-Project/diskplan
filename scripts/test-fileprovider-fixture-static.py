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
    lifecycle_lock = (ROOT / "scripts" / "fileprovider-fixture-lifecycle-lock.py").read_text()
    pending_preflight = (ROOT / "scripts" / "fileprovider-fixture-pending-preflight.py").read_text()
    registration = (ROOT / "scripts" / "fileprovider-fixture-registration.py").read_text()
    pluginkit = (ROOT / "scripts" / "fileprovider-fixture-pluginkit.py").read_text()
    all_fixture_text = swift + "\n" + lifecycle
    require("removeAllDomains" not in all_fixture_text, "bulk domain removal is forbidden")
    require("CloudStorage" not in lifecycle, "lifecycle must not delete or address CloudStorage")
    require("mode: .removeAll" in swift, "exact-domain teardown must request removeAll mode")
    require("domain.testingModes = []" in swift, "testing modes must remain empty")
    require("domain.isHidden = true" in swift, "fixture domain must be hidden")
    require("Data(contentsOf:" not in swift, "control files must not use pathname-following reads")
    require("O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW" in swift, "oracle append flags changed")
    require(
        "try acquireBoundedLock(" in swift,
        "oracle session and event locks must use bounded acquisition",
    )
    require(
        "if flock(descriptor, operation | LOCK_NB) == 0" in swift,
        "oracle locks must use nonblocking acquisition",
    )
    require(
        swift.count("try requireLockDeadline(") >= 2,
        "oracle locks must check the absolute deadline before and after acquisition",
    )
    require("flock(descriptor, LOCK_EX)" not in swift, "oracle event lock must not block")
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
    require(
        "subprocess.run" not in registration + pluginkit,
        "PlugInKit helpers must not collect unbounded output before enforcing the cap",
    )
    require(
        "run_bounded_text(" in registration and "run_bounded_text(" in pluginkit,
        "both PlugInKit helpers must use incremental bounded capture",
    )
    require("verify_elected_extension" in lifecycle, "registration must verify the elected physical appex")
    require("unregister_extension" in lifecycle, "recovery must unregister the exact manifest appex")
    require(lifecycle.count("verify_removed_extension") >= 3, "both teardown paths must verify exact-path removal")
    require("--state absent" in lifecycle, "registry removal verification must inspect all exact-bundle entries")
    recover = lifecycle[lifecycle.index("recover()") : lifecycle.index("accept()")]
    recover_unregister = recover.index("unregister_extension")
    require(
        recover_unregister
        < recover.index("verify_removed_extension", recover_unregister)
        < recover.index('"$host" cleanup'),
        "recovery cleanup must follow verified registry removal",
    )
    accept_body = lifecycle[lifecycle.index("accept()") : lifecycle.index("command=$1")]
    require(
        accept_body.index("trap report_recovery EXIT")
        < accept_body.index('"$host" prepare'),
        "prepare recovery trap must be active before the run directory can be created",
    )
    require(
        "recover-unpublished" in lifecycle and 'case "recover-unpublished"' in swift,
        "manifestless prepare artifacts must have a deterministic recovery command",
    )
    require(
        accept_body.index("unregister_extension")
        < accept_body.index("verify_removed_extension")
        < accept_body.index('"$host" cleanup'),
        "acceptance cleanup must follow verified registry removal",
    )
    require("plutil -extract appPath" not in lifecycle, "recovery must not read executable paths before trusted validation")
    require('"$host" status --manifest' in lifecycle, "recovery must validate with the known host first")
    require("sleep 2" not in lifecycle, "fixed sleeps are not a quiescence oracle")
    require(
        "DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_HELD" not in lifecycle
        and "--verify-held-fd" in lifecycle
        and "exec 9>&-" in lifecycle
        and "--verify-lock-busy" in lifecycle
        and "pass_fds=(LOCK_CAPABILITY_FD,)" in lifecycle_lock,
        "lifecycle single-flight must require the inherited locked descriptor capability",
    )
    require(
        'python3 "$repo_root/scripts/fileprovider-fixture-pending-preflight.py"' in lifecycle
        and "os.scandir(descriptor)" in pending_preflight
        and "evidence.append(os.fsencode(entry.name))" in pending_preflight,
        "acceptance must descriptor-scan every prior pending-run mutation before build",
    )
    require(
        "mutation-dispatched" in lifecycle
        and "mutation-complete" in lifecycle
        and "unresolved_external_mutation" in lifecycle
        and "currentBootGeneration" in swift,
        "external adds must retain explicit dispatch/completion and boot-generation evidence",
    )
    require("closeWindowAfterQuiescence" in swift, "oracle close must use bounded event quiescence")
    require("sealRecorder" in swift, "teardown must persistently seal the recorder")
    require(
        'try createRecorderMarker("recorder-sealed", directory: directory)' in swift,
        "oracle close must atomically seal its final snapshot",
    )
    require(
        "let snapshot = try log.sealedSnapshot()" in swift,
        "assertion must require the immutable sealed snapshot",
    )
    require("try? recreateManifest" not in swift, "manifest recovery failures must not be discarded")
    require(
        '".manifest-recovery-\\(runName).json"' in swift,
        "cleanup must retain deterministic recovery evidence outside staging",
    )
    require(
        "try unlink(parent: parent, name: stagingName, flags: AT_REMOVEDIR)\n"
        "      guard fsync(parent.rawValue) == 0" in swift,
        "final staging removal must be durable before recovery evidence is deleted",
    )
    require(
        "SecureFixtureStorage.recoverCleanup(" in swift,
        "the production host must support exact sibling-manifest recovery cleanup",
    )
    require(
        'sibling_manifest=$(dirname "$run_directory")/.manifest-recovery-"$run_name".json'
        in lifecycle,
        "acceptance failure must report the deterministic sibling recovery manifest",
    )
    require(
        "let gate = OneShotCallbackGate(deadline: deadline)" in swift
        and "let source = gate.claimCallback()" in swift
        and "claimCallback(isBeforeDeadline:" not in swift,
        "the callback gate must own and atomically evaluate its deadline",
    )
    require(
        "func materializedItemsDidChange(completionHandler:" in swift
        and "defer { completionHandler() }" in swift,
        "materialized-items callbacks must complete even when oracle recording fails",
    )
    require(
        'try createRecorderMarker("recorder-failed", directory: directory)' in swift
        and 'recorderMarkerExists("recorder-failed"' in swift
        and "try admission.fail(log: log, deadlineNanoseconds: deadline)" in swift
        and '"recorder-admissions.log"' in swift,
        "every production non-sealed recorder failure must leave immutable poison evidence",
    )
    require(
        '"recorder-attempt.lock"' in swift
        and "let admission = try log.makeAdmissionChannel()" in swift
        and "try admission.beginRecordAttempt(" in swift
        and "operation: LOCK_SH" in swift
        and "operation: LOCK_EX" in swift
        and "withSynchronizedRecorder" in swift,
        "record attempts and acceptance snapshots must share the independent in-flight gate",
    )
    require(
        'try createRecorderMarker("recorder-sealing", directory: directory)' in swift
        and 'recorderMarkerExists("recorder-sealing"' in swift
        and "if !admissions.hasCutoff" in swift,
        "acceptance sealing must publish persistent fail-closed transition evidence",
    )
    require(
        "decodeOracleEventStrict" in swift
        and "guard seen.insert(key).inserted" in swift
        and "Set(keys) == oracleEventJSONKeys" in swift
        and "maximumNestingDepth" in swift,
        "sealed event parsing must reject unknown and duplicate top-level keys",
    )
    staging_sync = swift.index('"sync-staged-run-directory-parent"')
    inventory = swift.index("let tree = try inventory", staging_sync)
    deletion = swift.index("try delete(entries: tree", inventory)
    require(staging_sync < inventory < deletion, "staging rename must be parent-durable before deletion")
    require(
        '"recorder-incomplete-attempt-"' in swift
        and "let markerName = try createIncompleteAttemptMarker" in swift
        and "try attempt?.resolve()" in swift
        and "try recorderHasIncompleteAttempts(directory: directory)" in swift,
        "attempts must retain durable incomplete evidence until event or failure publication",
    )
    require(
        "recoveryURL.isFileURL, recoveryURL.path == expectedURL.path" in swift
        and "let parent = try openControlDirectory(at: parentURL, record: .manifest)" in swift
        and "name: expectedURL.lastPathComponent" in swift,
        "sibling recovery must bind an exact basename under the trusted expected parent",
    )
    require(
        '!components.contains(".")' in swift
        and '!components.contains("..")' in swift
        and "guard url.path == value" in swift,
        "host manifest arguments must reject noncanonical path components before loading",
    )
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
