# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build an AVR test program and run it on qemu-system-avr (Arduino Uno).

The program reports on USART0. The test passes when the expected line
appears before the timeout."""
import argparse
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cc", required=True)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--include", required=True)
    # Seconds before a program that never reports is killed.
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("sources", nargs="+")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        elf = Path(directory) / "test.elf"
        command = [args.cc, "-std=c99", "-Os", "-Wall", "-Wextra", "-Werror", "-mmcu=atmega328p",
                   "-I" + args.include, *("-D" + d for d in args.define), *args.sources,
                   "-o", str(elf)]
        subprocess.run(command, check=True)
        # The program reports one line and then spins, so stop QEMU once the
        # line arrives. The timeout bounds a program that never reports.
        process = subprocess.Popen([args.qemu, "-machine", "uno", "-bios", str(elf),
                                    "-nographic", "-serial", "stdio", "-monitor", "none"],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        timer = threading.Timer(args.timeout, process.kill)
        timer.start()
        try:
            output = process.stdout.readline()
        finally:
            timer.cancel()
            process.kill()
            process.wait()
    print(output, end="")
    return 0 if args.expect in output else 1


if __name__ == "__main__":
    sys.exit(main())
