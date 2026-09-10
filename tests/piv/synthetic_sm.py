# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay deterministic CS2 and CS7 sessions through the C tests."""
import argparse
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from sm_fixtures import session
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from munit_runner import run_reader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--bits", type=int, choices=(256, 384), action="append", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="tiny-crypto-synthetic-sm-") as temporary:
        for bits in args.bits:
            fixture = session(bits)
            suite = "27" if bits == 256 else "2e"
            scalar = (1).to_bytes(bits // 8, "big").hex()
            lines = [f"begin {suite} {scalar} {'00' * 8} {fixture['request'].hex()}",
                     f"finish {fixture['response'].hex()} {fixture['material'].hex()}",
                     f"command 20 00 80 0 - {fixture['command'].hex()}",
                     f"response 9000 {fixture['reply'].hex()} - 9000"]
            path = Path(temporary) / "session.txt"
            path.write_text("\n".join(lines) + "\n")
            result = run_reader([str(args.reader), "--transcript", str(path)], echo=False)
            print(f"P-{bits}: {result.stdout}", end="")


if __name__ == "__main__":
    main()
