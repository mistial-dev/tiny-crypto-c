# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check EC public keys and ECDH against cryptography or NIST CAVP answers."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import zipfile


def check(readers, bits, scalar, public, peer, shared, label):
    for reader in readers:
        result = subprocess.run([reader, "--capture", str(bits), scalar, public, peer, shared],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(f"{label}, {reader}:\n{result.stdout}\n{result.stderr}")


def cavp(archive, readers):
    # NIST's component-testing page, ECCCDH Primitive Test Vectors (2012).
    # https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
    expected = "5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise AssertionError("Unexpected ECCCDH archive digest")
    with zipfile.ZipFile(archive) as bundle:
        lines = bundle.read("KAS_ECC_CDH_PrimitiveTest.txt").decode("ascii").splitlines()
    curve, record = None, {}
    counts = {"P-256": 0, "P-384": 0}
    for line in lines:
        line = line.strip()
        if line.startswith("["):
            curve = line[1:-1]
            record = {}
        elif curve in counts and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            record[key] = value
            if key == "ZIUT":
                check(readers, curve[2:], record["dIUT"],
                      "04" + record["QIUTx"] + record["QIUTy"],
                      "04" + record["QCAVSx"] + record["QCAVSy"],
                      record["ZIUT"], f"{curve} COUNT={record['COUNT']}")
                counts[curve] += 1
                record = {}
    if counts != {"P-256": 25, "P-384": 25}:
        raise AssertionError(f"Incomplete ECCCDH corpus: {counts}")
    print(f"Checked 50 NIST ECCCDH answers using {len(readers)} builds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", action="append", required=True)
    parser.add_argument("--cases", type=int, default=16)
    parser.add_argument("--cavp-archive", type=Path)
    args = parser.parse_args()
    if args.cases < 1:
        parser.error("--cases must be positive")
    if args.cavp_archive:
        cavp(args.cavp_archive, args.reader)
        return
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    curves = (
        (ec.SECP256R1(), int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)),
        (ec.SECP384R1(), int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
                           "581a0db248b0a77aecec196accc52973", 16)),
    )
    count = 0
    for curve, order in curves:
        width = curve.key_size // 8
        scalars = [1, 2, order - 1, order - 2, 1 << (curve.key_size - 1)]
        for i in range(args.cases):
            seed = hashlib.sha512(f"{curve.name}:{i}".encode()).digest()
            scalars.append(1 + int.from_bytes(seed, "big") % (order - 1))
        # Leading zero coordinates must survive fixed-width serialization.
        for scalar in range(1, 4097):
            point = ec.derive_private_key(scalar, curve).public_key().public_numbers()
            if point.x < 1 << (curve.key_size - 8):
                scalars.append(scalar)
                break
        else:
            raise AssertionError(f"{curve.name}: no leading-zero case")
        for i, scalar in enumerate(scalars):
            private = ec.derive_private_key(scalar, curve)
            peer = ec.derive_private_key(1 if i == len(scalars) - 1 else order - 1 - i,
                                         curve).public_key()
            public = private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            encoded_peer = peer.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            shared = private.exchange(ec.ECDH(), peer)
            check(args.reader, curve.key_size, scalar.to_bytes(width, "big").hex(),
                  public.hex(), encoded_peer.hex(), shared.hex(), f"{curve.name} case {i}")
            count += 1
    print(f"Checked {count} EC cases against cryptography using {len(args.reader)} builds")


if __name__ == "__main__":
    main()
