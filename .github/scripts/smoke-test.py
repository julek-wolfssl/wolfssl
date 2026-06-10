#!/usr/bin/env python3
# Build and "make check" every smoke configuration in its own out-of-tree
# (VPATH) build directory, all in parallel (one thread per config).
# Driven by .github/workflows/smoke-test.yml, but also runnable locally:
#
#   .github/scripts/smoke-test.py                  # all configs
#   .github/scripts/smoke-test.py default dtls-suite
#   .github/scripts/smoke-test.py --list
#
# Concurrent "make check" runs are safe because the test scripts re-exec
# themselves under "bwrap --unshare-net" when bubblewrap is installed (one
# network namespace each) and the remaining test outputs land in the build
# directory; see isolate_certs() for the one exception.

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

# cflags/ldflags are applied at make time only (never to ./configure) so
# autoconf feature detection is not poisoned by benign warnings in
# conftest probes.
@dataclass
class Config:
    name: str
    configure: list = field(default_factory=list)
    cflags: str = "-Werror"
    ldflags: str = ""

# Common-failure configs derived from the Jenkins PRB top-10 (last 30 days).
CONFIGS = [
    Config("default"),
    Config("enable-all", ["--enable-all"]),
    Config("opensslextra", ["--enable-opensslextra"]),
    Config("enable-all-smallstack", ["--enable-all", "--enable-smallstack"]),
    Config("cryptonly", ["--enable-cryptonly"]),
    # Below entries target the top Jenkins PRB failure modes
    # (-Werror unused-function / implicit-decl / link errors).
    Config("leantls-extra", ["--enable-leantls", "--enable-session-ticket",
                             "--enable-sni", "--enable-opensslextra"]),
    Config("dtls-suite", ["--enable-psk", "--enable-dtls", "--enable-dtls13",
                          "--enable-dtls-mtu", "--enable-aesccm",
                          "--enable-opensslextra"]),
    Config("integration", ["--enable-openssh", "--enable-lighty",
                           "--enable-stunnel", "--enable-opensslextra"]),
    # AddressSanitizer (UBSAN excluded - current master has known
    # left-shift UB in auto-generated SP math).
    Config("sanitize-asan", ["--enable-all"],
           cflags="-fsanitize=address -fno-omit-frame-pointer -g -O1",
           ldflags="-fsanitize=address"),
]

SRCDIR = Path(__file__).resolve().parents[2]
ON_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"
print_lock = threading.Lock()


def isolate_certs(bdir):
    # scripts/crl-gen-openssl.test writes generated CRLs under certs/crl/.
    # Through the VPATH certs symlink that write would land in the shared
    # source tree and race between the parallel checks, so give every build
    # dir its own copy. wolfssl-test-data.stamp already exists at this
    # point, so make will not recreate the symlink.
    certs = bdir / "certs"
    if certs.is_symlink():
        certs.unlink()
        shutil.copytree(SRCDIR / "certs", certs, symlinks=True)


def dump(title, path):
    print(f"::group::{title}" if ON_GITHUB else f"==== {title} ====")
    try:
        sys.stdout.write(path.read_text(errors="replace"))
    except OSError as e:
        print(e)
    if ON_GITHUB:
        print("::endgroup::")
    sys.stdout.flush()


def run_config(cfg, jobs, cc):
    bdir = SRCDIR / f"build-{cfg.name}"
    if bdir.exists():
        shutil.rmtree(bdir)
    bdir.mkdir()
    configure = [str(SRCDIR / "configure")] + cfg.configure
    if cc:
        configure.append(f"CC={cc}")
    make = ["make", f"-j{jobs}", f"CFLAGS={cfg.cflags}",
            f"LDFLAGS={cfg.ldflags}"]
    steps = [
        ("configure", configure),
        ("make", make),
        # Prebuild the check programs (testsuite, tests/unit.test, ...)
        # without running any tests so "make check" below is pure test
        # execution.
        ("make check TESTS=", make + ["check", "TESTS="]),
        ("isolate certs", isolate_certs),
        ("make check", ["make", f"CFLAGS={cfg.cflags}",
                        f"LDFLAGS={cfg.ldflags}", "check"]),
    ]
    failed = None
    start = time.monotonic()
    log = bdir / "smoke.log"
    with open(log, "w") as logf:
        for step, cmd in steps:
            if callable(cmd):
                cmd(bdir)
                continue
            print(f"+ {' '.join(cmd)}", file=logf, flush=True)
            if subprocess.run(cmd, cwd=bdir, stdout=logf,
                              stderr=subprocess.STDOUT).returncode != 0:
                failed = step
                break
    minutes = (time.monotonic() - start) / 60
    with print_lock:
        verdict = f"FAIL ({failed})" if failed else "pass"
        dump(f"{cfg.name}: {verdict} [{minutes:.1f} min]", log)
        if failed == "configure":
            dump(f"{cfg.name}: config.log", bdir / "config.log")
        elif failed == "make check":
            dump(f"{cfg.name}: test-suite.log", bdir / "test-suite.log")
    return failed


def summarize(results):
    lines = ["| Config | Result |", "|---|---|"]
    for cfg, failed in results:
        ok = ":x: FAIL (%s)" % failed if failed else ":white_check_mark: pass"
        lines.append(f"| {cfg.name} | {ok} |")
    table = "\n".join(lines)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            print(f"### Smoke make check\n\n{table}", file=f)


def main():
    p = argparse.ArgumentParser(
        description="Build and make check every smoke config in its own "
                    "out-of-tree build directory, in parallel.")
    p.add_argument("configs", nargs="*", metavar="NAME",
                   help="configs to run (default: all)")
    p.add_argument("--list", action="store_true", help="list configs")
    p.add_argument("--jobs", type=int, default=2,
                   help="make -j per config (default: 2)")
    p.add_argument("--cc", default="ccache gcc" if shutil.which("ccache")
                   else None, help="compiler passed to configure as CC=")
    opts = p.parse_args()

    if opts.list:
        for cfg in CONFIGS:
            print(f"{cfg.name}: {' '.join(cfg.configure)}")
        return 0
    selected = CONFIGS
    if opts.configs:
        by_name = {cfg.name: cfg for cfg in CONFIGS}
        unknown = [n for n in opts.configs if n not in by_name]
        if unknown:
            p.error(f"unknown config(s): {' '.join(unknown)}")
        selected = [by_name[n] for n in opts.configs]

    if not (SRCDIR / "configure").exists():
        subprocess.run(["./autogen.sh"], cwd=SRCDIR, check=True)

    with ThreadPoolExecutor(max_workers=len(selected)) as pool:
        results = list(zip(selected, pool.map(
            lambda cfg: run_config(cfg, opts.jobs, opts.cc), selected)))
    summarize(results)
    failed = [cfg.name for cfg, failure in results if failure]
    if failed:
        print(f"::error::smoke failed for: {' '.join(failed)}"
              if ON_GITHUB else f"smoke failed for: {' '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
