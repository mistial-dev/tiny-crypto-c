"""Run every vendored Wycheproof HKDF case against the public C API."""

import json
import subprocess
import sys
from pathlib import Path


FILES = (
    ("sha1", "hkdf_sha1_test.json"),
    ("sha256", "hkdf_sha256_test.json"),
    ("sha384", "hkdf_sha384_test.json"),
    ("sha512", "hkdf_sha512_test.json"),
)


def main() -> int:
    reader = sys.argv[1]
    directory = Path(sys.argv[2])
    counts = {"valid": 0, "invalid": 0}
    for hash_name, filename in FILES:
        corpus = json.loads((directory / filename).read_text(encoding="utf-8"))
        tests = [test for group in corpus["testGroups"] for test in group["tests"]]
        if len(tests) != corpus["numberOfTests"]:
            raise AssertionError(f"{filename}: declared case count differs")
        for test in tests:
            result = subprocess.run(
                [
                    reader,
                    hash_name,
                    test["ikm"],
                    test["salt"],
                    test["info"],
                    str(test["size"]),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            outcome = test["result"]
            counts[outcome] += 1
            if outcome == "valid":
                if result.returncode != 0 or result.stdout != bytes.fromhex(test["okm"]):
                    raise AssertionError(f"{filename} tcId={test['tcId']}: valid result differs")
            elif result.returncode != 1 or result.stdout:
                raise AssertionError(f"{filename} tcId={test['tcId']}: invalid input accepted")
    if counts != {"valid": 327, "invalid": 12}:
        raise AssertionError(f"unexpected HKDF corpus size: {counts}")
    print(f"Wycheproof HKDF: {counts['valid']} valid, {counts['invalid']} invalid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
