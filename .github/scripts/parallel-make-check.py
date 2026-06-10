#!/usr/bin/env python3
# Build and "make check" a set of configurations, each in its own out-of-tree
# (VPATH) build directory, on a pool of worker threads (default: one per
# CPU); each thread takes the next pending config as soon as it is free.
# The final summary reports how efficiently the pool used the machine
# (thread occupancy and CPU utilization).
#
# The configurations come from a JSON file ("-" for stdin): a list of
# objects, one per configuration. Recognized keys, all optional except
# "name" (unknown keys are an error, so typos do not pass silently):
#
#   name       unique identifier; the config builds in build-<name>/
#   configure  list of extra ./configure arguments
#   cflags     CFLAGS for make, overriding --cflags
#   ldflags    LDFLAGS for make, overriding --ldflags
#   comment    ignored; JSON has no comment syntax, so notes go here
#
# For example:
#
#   [
#     {"name": "default"},
#     {"name": "all-asan", "configure": ["--enable-all"],
#      "cflags": "-fsanitize=address", "ldflags": "-fsanitize=address"}
#   ]
#
# Driven by CI workflows, which keep their config lists next to the
# invocation (see .github/workflows/smoke-test.yml), but also runnable
# locally - copy the JSON block out of the workflow into a file:
#
#   .github/scripts/parallel-make-check.py configs.json     # all configs
#   .github/scripts/parallel-make-check.py configs.json default all-asan
#   .github/scripts/parallel-make-check.py --list configs.json
#
# Concurrent "make check" runs are safe because the test scripts re-exec
# themselves under "bwrap --unshare-net" when bubblewrap is installed (one
# network namespace each) and the remaining test outputs land in the build
# directory; see --private-dir for the exception.

import argparse
import json
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
# conftest probes. They are omitted entirely when empty so a plain config
# keeps the configure-chosen defaults.
@dataclass
class Config:
    name: str
    configure: list = field(default_factory=list)
    cflags: str = ""
    ldflags: str = ""

SRCDIR = Path(__file__).resolve().parents[2]
ON_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"
print_lock = threading.Lock()


def nproc():
    # Like nproc(1): CPUs usable by this process, falling back to all online.
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def load_configs(opts, error):
    try:
        if opts.json == "-":
            entries = json.load(sys.stdin)
        else:
            entries = json.loads(Path(opts.json).read_text())
    except (OSError, ValueError) as e:
        error(f"{opts.json}: {e}")
    if not isinstance(entries, list):
        error(f"{opts.json}: expected a JSON list of config objects")
    configs = []
    for entry in entries:
        if not isinstance(entry, dict):
            error(f"{opts.json}: config entries must be objects: {entry!r}")
        unknown = set(entry) - {"name", "configure", "cflags", "ldflags",
                                "comment"}
        if unknown:
            error(f"{opts.json}: unknown key(s) in {entry.get('name', entry)!r}: "
                  f"{' '.join(sorted(unknown))}")
        name = entry.get("name")
        if not isinstance(name, str) or not name or "/" in name:
            error(f"{opts.json}: every config needs a \"name\" usable as a "
                  f"directory suffix: {entry!r}")
        if any(cfg.name == name for cfg in configs):
            error(f"{opts.json}: duplicate config name {name!r}")
        configs.append(Config(name, list(entry.get("configure", [])),
                              entry.get("cflags", opts.cflags),
                              entry.get("ldflags", opts.ldflags)))
    if not configs:
        error(f"{opts.json}: no configs")
    return configs


def privatize_dirs(bdir, dirs):
    # Replace build-tree symlinks into the source tree with private
    # per-build-dir copies: tests that write into these directories would
    # otherwise write through the symlink into the shared source tree and
    # race with the other parallel checks. Runs after the build steps so
    # that build rules which (re)create the symlinks have already run.
    for name in dirs:
        d = bdir / name
        if d.is_symlink():
            d.unlink()
            shutil.copytree(SRCDIR / name, d, symlinks=True)


def dump(title, path):
    print(f"::group::{title}" if ON_GITHUB else f"==== {title} ====")
    try:
        sys.stdout.write(path.read_text(errors="replace"))
    except OSError as e:
        print(e)
    if ON_GITHUB:
        print("::endgroup::")
    sys.stdout.flush()


def run_config(cfg, opts):
    bdir = SRCDIR / f"build-{cfg.name}"
    if bdir.exists():
        shutil.rmtree(bdir)
    bdir.mkdir()
    configure = [str(SRCDIR / "configure")] + cfg.configure
    if opts.cc:
        configure.append(f"CC={opts.cc}")
    flags = [f"CFLAGS={cfg.cflags}"] if cfg.cflags else []
    flags += [f"LDFLAGS={cfg.ldflags}"] if cfg.ldflags else []
    make = ["make", f"-j{opts.jobs}"] + flags
    steps = [
        ("configure", configure),
        ("make", make),
        # Prebuild the check programs without running any tests so
        # "make check" below is pure test execution.
        ("make check TESTS=", make + ["check", "TESTS="]),
        ("private dirs", lambda: privatize_dirs(bdir, opts.private_dir)),
        ("make check", ["make"] + flags + ["check"]),
    ]
    failed = None
    start = time.monotonic()
    log = bdir / "make-check.log"
    with open(log, "w") as logf:
        for step, cmd in steps:
            if callable(cmd):
                cmd()
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
    return failed, minutes


def summarize(results, wall_min, cpu_min, nthreads):
    lines = ["| Config | Result | Minutes |", "|---|---|---|"]
    for cfg, failed, minutes in results:
        ok = ":x: FAIL (%s)" % failed if failed else ":white_check_mark: pass"
        lines.append(f"| {cfg.name} | {ok} | {minutes:.1f} |")
    # Two views of how efficiently the pool used the machine: thread
    # occupancy is the time the workers spent running configs out of the
    # thread-minutes available (a long config left for last idles the other
    # workers and drags it down); CPU utilization is the CPU time the build
    # and test children actually consumed out of the CPU-minutes available
    # (too-shallow make -j and serial test phases show up here).
    busy_min = sum(minutes for _, _, minutes in results)
    ncpu = nproc()
    lines += [
        "",
        f"{len(results)} configs in {wall_min:.1f} min on {nthreads} "
        f"threads / {ncpu} CPUs: "
        f"thread occupancy {100 * busy_min / (wall_min * nthreads):.0f}% "
        f"({busy_min:.1f} of {wall_min * nthreads:.1f} thread-min), "
        f"CPU utilization {100 * cpu_min / (wall_min * ncpu):.0f}% "
        f"({cpu_min:.1f} of {wall_min * ncpu:.1f} CPU-min)",
    ]
    table = "\n".join(lines)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            print(f"### make check\n\n{table}", file=f)


def main():
    p = argparse.ArgumentParser(
        description="Build and make check every configuration from a JSON "
                    "file in its own out-of-tree build directory, in "
                    "parallel.")
    p.add_argument("json", metavar="CONFIGS.json",
                   help="JSON list of configs (see the script header for "
                        "the format), or - for stdin")
    p.add_argument("configs", nargs="*", metavar="NAME",
                   help="configs to run (default: all)")
    p.add_argument("--list", action="store_true", help="list configs")
    p.add_argument("--jobs", type=int, default=2,
                   help="make -j per config (default: 2)")
    p.add_argument("--threads", type=int, default=nproc(),
                   help="worker threads; each takes the next pending config "
                        "when it is free (default: nproc)")
    p.add_argument("--cc", default="ccache gcc" if shutil.which("ccache")
                   else None, help="compiler passed to configure as CC=")
    p.add_argument("--cflags", default="",
                   help="CFLAGS for configs that do not set their own")
    p.add_argument("--ldflags", default="",
                   help="LDFLAGS for configs that do not set their own")
    p.add_argument("--private-dir", action="append", default=[],
                   metavar="DIR",
                   help="give each build dir a private copy of this "
                        "symlinked source directory before make check, for "
                        "tests that write into it (repeatable)")
    opts = p.parse_args()

    all_configs = load_configs(opts, p.error)
    if opts.list:
        for cfg in all_configs:
            print(f"{cfg.name}: {' '.join(cfg.configure)}")
        return 0
    selected = all_configs
    if opts.configs:
        by_name = {cfg.name: cfg for cfg in all_configs}
        unknown = [n for n in opts.configs if n not in by_name]
        if unknown:
            p.error(f"unknown config(s): {' '.join(unknown)}")
        selected = [by_name[n] for n in opts.configs]

    if not (SRCDIR / "configure").exists():
        subprocess.run(["./autogen.sh"], cwd=SRCDIR, check=True)

    nthreads = max(1, min(opts.threads, len(selected)))
    wall_start = time.monotonic()
    cpu_start = os.times()
    with ThreadPoolExecutor(max_workers=nthreads) as pool:
        results = [(cfg, failed, minutes) for cfg, (failed, minutes)
                   in zip(selected, pool.map(
                       lambda cfg: run_config(cfg, opts), selected))]
    wall_min = (time.monotonic() - wall_start) / 60
    cpu_end = os.times()
    # os.times() child counters cover the waited-for configure/make
    # subprocesses of every worker thread.
    cpu_min = (cpu_end.children_user - cpu_start.children_user
               + cpu_end.children_system - cpu_start.children_system) / 60
    summarize(results, wall_min, cpu_min, nthreads)
    failed = [cfg.name for cfg, failure, _ in results if failure]
    if failed:
        print(f"::error::make check failed for: {' '.join(failed)}"
              if ON_GITHUB else f"make check failed for: {' '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
