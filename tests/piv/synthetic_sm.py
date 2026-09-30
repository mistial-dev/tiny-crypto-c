# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay deterministic CS2 and CS7 sessions through the library link.

The transcript format is described in tests/piv/sm_apdu_replay.c."""
import argparse
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from sm_fixtures import session
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from munit_runner import run_reader

PIV_SELECT = "00a404000ba00000030800001000010000"


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
            apt = ("612a4f0ba00000030800001000010079074f05a000000308500a49442d4f6e6520504956"
                   f"ac068001{suite}0601007f6608020203f802027fff9000")
            lines = [f"select {PIV_SELECT} {apt}",
                     f"begin {suite} {scalar} {'00' * 8} {fixture['request'].hex()}",
                     f"finish {fixture['response'].hex()} {fixture['material'].hex()}",
                     f"state {1:032x} {'00' * 16} {'00' * 16}",
                     "command 20 00 80 0 - - 9000",
                     f"wire 0c2000800a{fixture['command'].hex()}00 {fixture['reply'].hex()}9000",
                     "end"]
            path = Path(temporary) / "session.txt"
            path.write_text("\n".join(lines) + "\n")
            result = run_reader([str(args.reader), "--transcript", str(path)], echo=False)
            print(f"P-{bits}: {result.stdout}", end="")


if __name__ == "__main__":
    main()
