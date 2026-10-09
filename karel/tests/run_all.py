#!/usr/bin/env python3
"""Run every test file and the pyflakes gate; non-zero exit on any failure.

  python3 tests/run_all.py
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
FILES = ["test_regressions.py", "test_logs.py", "test_events.py",
         "test_gpu.py", "test_housekeeping.py", "test_failed_recent.py",
         "test_run_sh.py", "test_acme.py", "test_usage.py", "test_gateway.py",
         "test_ai_contract.py", "test_snapshots.py", "test_prom_pvc.py", "fuzz.py", "consistency.py"]


def main():
    failed = []
    for f in FILES:
        print("=" * 70)
        print("## %s" % f)
        print("=" * 70)
        r = subprocess.run([sys.executable, os.path.join(TESTS, f)],
                           capture_output=False, timeout=900)
        if r.returncode != 0:
            failed.append(f)

    # Replay a freshly generated bundle: an old bundle (no new facts) must
    # still exit 0 with no rule errors.
    print("=" * 70)
    print("## --from-bundle replay")
    print("=" * 70)
    src_out = "/tmp/outs/out"
    if os.path.isdir(src_out):
        import tempfile
        d = tempfile.mkdtemp(prefix="karel-replay.")
        pipe = os.path.join(ROOT, "lib", "pipeline.py")
        prom = "/tmp/outs/out-prom"
        r = subprocess.run(
            [sys.executable, pipe, "--out", src_out, "--prom-out", prom,
             "--prev", "/dev/null", "--suppressions", "/dev/null",
             "--housekeeping-state", "/dev/null",
             "--bundle", os.path.join(d, "bundle.json"),
             "--snapshot", os.path.join(d, "snapshot.json"),
             "--report", os.path.join(d, "report.md")],
            capture_output=True, text=True, timeout=300)
        replay_ok = r.returncode == 0
        if replay_ok:
            r = subprocess.run(
                [sys.executable, pipe, "--from-bundle",
                 os.path.join(d, "bundle.json"),
                 "--out", d, "--prev", "/dev/null",
                 "--suppressions", "/dev/null",
                 "--report", os.path.join(d, "replay.md")],
                capture_output=True, text=True, timeout=300)
            replay_ok = r.returncode == 0 and \
                "KAREL_RULE_ERROR" not in (r.stdout or "")
        print("  %s  old-bundle replay exits 0 with no rule errors"
              % ("PASS" if replay_ok else "FAIL"))
        if not replay_ok:
            failed.append("replay")
            print((r.stderr or "")[-400:])
    else:
        print("  SKIP  (no collector output at %s)" % src_out)

    print("=" * 70)
    print("## pyflakes")
    print("=" * 70)
    try:
        import importlib.util as _ilu
        has = _ilu.find_spec("pyflakes") is not None
    except Exception:
        has = False
    if has:
        r = subprocess.run(
            [sys.executable, "-m", "pyflakes"] +
            [os.path.join(ROOT, d, f)
             for d in ("lib", "bin", "tests")
             for f in sorted(os.listdir(os.path.join(ROOT, d)))
             if f.endswith(".py")],
            capture_output=True, text=True)
        ok = r.returncode == 0
        print("  %s  pyflakes is clean" % ("PASS" if ok else "FAIL"))
        if not ok:
            failed.append("pyflakes")
            print((r.stdout or r.stderr)[:2000])
    else:
        print("  SKIP  (pyflakes not installed)")

    print()
    if failed:
        print("FAILED: %s" % ", ".join(failed))
        return 1
    print("everything green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
