# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run a single fixture-driven munit test."""
import subprocess


def run_reader(command, environment=None, *, echo=True):
    result = subprocess.run([str(arg) for arg in command], env=environment,
                            capture_output=True, text=True)
    summary = "1 of 1 (100%) tests successful, 0 (0%) test skipped."
    if result.returncode or summary not in result.stdout:
        raise AssertionError(f"Reader failed or did not run its test: {command}\n"
                             f"{result.stdout}\n{result.stderr}")
    if echo:
        print(result.stdout, end="", flush=True)
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        raise SystemExit("usage: munit_runner.py READER [ARGUMENT ...]")
    run_reader(sys.argv[1:])
