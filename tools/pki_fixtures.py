# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Original encoding fixtures for parser tests and resource measurements."""


def tlv(tag, value):
    length = len(value)
    width = (length.bit_length() + 7) // 8
    encoded_length = bytes([length]) if length < 128 else bytes([128 + width]) + length.to_bytes(width, "big")
    return tag.to_bytes((tag.bit_length() + 7) // 8 or 1, "big") + encoded_length + value


def seq(*values):
    return tlv(0x30, b"".join(values))


def name(value=b"Example", tag=0x0c):
    return seq(tlv(0x31, seq(tlv(6, bytes.fromhex("550403")), tlv(tag, value))))


def extension(oid, value, critical=None):
    flag = b"" if critical is None else tlv(1, bytes([critical]))
    return seq(tlv(6, bytes.fromhex(oid)), flag, tlv(4, value))


def certificate(issuer=None, subject=None, extensions=None, key_kind="rsa", bits=12, signature_algorithm=None,
                validity=None, public_key_algorithm=None):
    algorithm = signature_algorithm if signature_algorithm is not None else seq(tlv(6, bytes.fromhex("2a864886f70d01010b")), tlv(5, b""))
    if key_kind == "rsa":
        key_algorithm = seq(tlv(6, bytes.fromhex("2a864886f70d010101")), tlv(5, b""))
        modulus = b"\x0c\xa1" if bits == 12 else b"\x00\x80" + b"\x11" * (bits // 8 - 1)
        key = seq(tlv(2, modulus), tlv(2, b"\x01\x00\x01" if bits > 12 else b"\x11"))
    elif key_kind == "ec":
        curve = "2a8648ce3d030107" if bits == 256 else "2b81040022"
        key_algorithm = seq(tlv(6, bytes.fromhex("2a8648ce3d0201")), tlv(6, bytes.fromhex(curve)))
        key = b"\x04" + b"\x11" * (bits // 4)
    else:
        raise ValueError(key_kind)
    spki = seq(key_algorithm if public_key_algorithm is None else public_key_algorithm,
               tlv(3, b"\x00" + key))
    tbs = seq(tlv(0xa0, tlv(2, b"\x02")), tlv(2, b"\x01"), algorithm,
              name() if issuer is None else issuer,
              seq(tlv(0x17, b"240101000000Z"), tlv(0x17, b"300101000000Z")) if validity is None else validity,
              name() if subject is None else subject, spki,
              b"" if extensions is None else tlv(0xa3, seq(*extensions)))
    return seq(tbs, algorithm, tlv(3, b"\x00\x01"))


def benchmark_certificate(key_kind, bits):
    return certificate(key_kind=key_kind, bits=bits, extensions=[
        extension("551d13", seq()), extension("551d0f", tlv(3, b"\x07\x80"), 255)])


def chuid(unsigned=False):
    if unsigned:
        return tlv(0x53, tlv(0x30, bytes(range(25))) + tlv(0x34, bytes(range(16))) +
                   tlv(0x35, b"20301231") + tlv(0xfe, b""))
    return tlv(0x53, tlv(0x30, bytes(range(25))) + tlv(0x34, bytes(range(16))) +
               tlv(0x35, b"20301231") + tlv(0x36, bytes(range(16, 32))) +
               tlv(0x3e, seq()) + tlv(0xfe, b""))


def cvc(bits=256, public_key=None, issuer=None, subject=None, role=0):
    if bits not in (256, 384):
        raise ValueError("PIV SM CVC requires P-256 or P-384")
    if public_key is None:
        public_key = b"\x04" + b"\x11" * (bits // 4)
    if len(public_key) != 1 + bits // 4 or public_key[0] != 4:
        raise ValueError("Expected an uncompressed public key of the selected width")
    issuer = bytes(range(8)) if issuer is None else issuer
    subject = bytes(range(16)) if subject is None else subject
    if len(issuer) != 8 or len(subject) not in (8, 16) or role not in (0, 0x12):
        raise ValueError("Invalid PIV SM CVC identity or role")
    curve = "2a8648ce3d030107" if bits == 256 else "2b81040022"
    signature_oid = "2a864886f70d01010b" if role == 0x12 else (
        "2a8648ce3d040302" if bits == 256 else "2a8648ce3d040303")
    key = tlv(0x7f49, tlv(6, bytes.fromhex(curve)) + tlv(0x86, public_key))
    algorithm = seq(tlv(6, bytes.fromhex(signature_oid)), tlv(5, b"") if role == 0x12 else b"")
    signature_value = b"\x01" if role == 0x12 else seq(tlv(2, b"\x01"), tlv(2, b"\x01"))
    signature = seq(algorithm, tlv(3, b"\x00" + signature_value))
    return tlv(0x7f21, tlv(0x5f29, b"\x80") + tlv(0x42, issuer) +
               tlv(0x5f20, subject) + key + tlv(0x5f4c, bytes([role])) +
               tlv(0x5f37, signature))


def c_array(data, variable="data"):
    return f"const uint8_t {variable}[] = {{" + ",".join(f"0x{byte:02x}" for byte in data) + "}; "


def eac_key(kind="ec", domain=True):
    if kind == "rsa":
        return tlv(0x7f49, tlv(6, bytes.fromhex("04007f00070202020102")) +
                   tlv(0x81, b"\x80" + b"\x11" * 255) + tlv(0x82, b"\x01\x00\x01"))
    parameters = (tlv(0x81, b"\xff" * 32) + tlv(0x82, b"\x01") + tlv(0x83, b"\x01") +
                  tlv(0x84, b"\x04" + b"\x11" * 64) + tlv(0x85, b"\xff" * 32)) if domain else b""
    return tlv(0x7f49, tlv(6, bytes.fromhex("04007f00070202020203")) + parameters +
               tlv(0x86, b"\x04" + b"\x11" * 64))


def eac_certificate(kind="ec", domain=True):
    body = tlv(0x7f4e, tlv(0x5f29, b"\x00") + tlv(0x42, b"DETEST00001") + eac_key(kind, domain) +
               tlv(0x5f20, b"DETEST00001" if domain else b"DETERM00001") +
               tlv(0x7f4c, tlv(6, bytes.fromhex("04007f000703010202")) +
                   tlv(0x53, bytes([0xc0 if domain else 0, 0, 0, 0, 0]))) +
               tlv(0x5f25, bytes([2,6,0,1,0,1])) + tlv(0x5f24, bytes([3,0,0,1,0,1])))
    return tlv(0x7f21, body + tlv(0x5f37, b"\x01" * (256 if kind == "rsa" else 64)))


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixtures = (("TC_ENABLE_PIV_CHUID", "chuid", chuid()),
                ("TC_ENABLE_PIV_CHUID", "twic_unsigned", chuid(unsigned=True)),
                ("TC_ENABLE_EAC_CVC", "eac_rsa", eac_certificate("rsa")),
                ("TC_ENABLE_EAC_CVC", "eac_ec", eac_certificate()),
                ("TC_ENABLE_EAC_CVC", "eac_inherited", eac_certificate(domain=False)),
                ("TC_ENABLE_EAC_CVC", "eac_domain", eac_key()),
                ("TC_ENABLE_PIV_CVC", "cvc", cvc()),
                ("TC_ENABLE_X509", "rsa", benchmark_certificate("rsa", 2048)),
                ("TC_ENABLE_X509", "ec", benchmark_certificate("ec", 256)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("/* Generated parser fixtures. */\n" + "".join(
        f"#if {flag}\nstatic " + c_array(data, "fixture_" + label) + "\n#endif\n"
        for flag, label, data in fixtures), encoding="utf-8")
