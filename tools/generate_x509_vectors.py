#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic X.509 corpus in tests/vectors/x509/synthetic/.

Everything here is produced with the OpenSSL command line (3.5 or newer is
required for ML-DSA / SLH-DSA / ML-KEM) plus a small DER rewriter used to
manufacture malformed encodings that no sane tool will emit.  Every file
lands in a ``manifest.json`` entry with:

  * ``file``       path relative to the synthetic directory
  * ``kind``       cert | crl | csr | p7b | bundle
  * ``expect``     what a conforming implementation should do:
                   ``parse`` (well-formed, verifies where a chain exists),
                   ``parse-only`` (well-formed but semantically bad, e.g.
                   expired, weak or violates a path rule),
                   ``reject`` (must be rejected by a strict DER parser)
  * ``reason``     human-readable description of the case
  * ``chain``      optional list of issuer files, leaf first, root last
  * ``openssl``    what this OpenSSL said about it (verify / parse result)

Private keys are deliberately not written into the corpus; rerunning this
script therefore produces a fresh PKI with different keys and signatures.

Usage: tools/generate_x509_vectors.py [--out DIR] [--openssl PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

OPENSSL = os.environ.get("OPENSSL", "openssl")
OUT = pathlib.Path("tests/vectors/x509/synthetic")
WORK: pathlib.Path
MANIFEST: list[dict] = []

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def run(*args: str, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [OPENSSL, *args]
    r = subprocess.run(cmd, input=input, capture_output=True)
    if check and r.returncode != 0:
        sys.stderr.write(" ".join(cmd) + "\n" + r.stderr.decode(errors="replace") + "\n")
        raise SystemExit(f"openssl failed: {args[0]}")
    return r


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pem_to_der(pem: bytes, label: str = "CERTIFICATE") -> bytes:
    import base64
    import re

    m = re.search(rb"-----BEGIN " + label.encode() + rb"-----(.*?)-----END", pem, re.S)
    return base64.b64decode(b"".join(m.group(1).split()))


def der_to_pem(der: bytes, label: str = "CERTIFICATE") -> bytes:
    import base64

    b = base64.encodebytes(der).replace(b"\n", b"")
    lines = [b[i : i + 64] for i in range(0, len(b), 64)]
    return b"-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label.encode(), b"\n".join(lines), label.encode())


def record(rel: str, kind: str, expect: str, reason: str, **extra) -> None:
    p = OUT / rel
    e = {"file": rel, "kind": kind, "expect": expect, "reason": reason, "sha256": sha256(p), "size": p.stat().st_size}
    e.update({k: v for k, v in extra.items() if v is not None})
    MANIFEST.append(e)


def openssl_parse_result(path: pathlib.Path, kind: str = "cert") -> str:
    inform = "PEM" if b"-----BEGIN" in path.read_bytes() else "DER"
    if kind == "cert":
        r = run("x509", "-inform", inform, "-in", str(path), "-noout", "-text", check=False)
    elif kind == "crl":
        r = run("crl", "-inform", inform, "-in", str(path), "-noout", "-text", check=False)
    elif kind == "csr":
        r = run("req", "-inform", inform, "-in", str(path), "-noout", "-text", check=False)
    else:
        r = run("pkcs7", "-inform", inform, "-in", str(path), "-print_certs", "-noout", check=False)
    if r.returncode == 0:
        return "parsed"
    last = r.stderr.decode(errors="replace").strip().splitlines()
    return "error: " + (last[-1][:160] if last else "?")


def openssl_verify(leaf: pathlib.Path, chain: list[pathlib.Path], root: pathlib.Path, *extra: str) -> str:
    args = ["verify", "-CAfile", str(root)]
    if chain:
        untrusted = WORK / (leaf.stem + ".untrusted.pem")
        untrusted.write_bytes(b"".join(p.read_bytes() for p in chain))
        args += ["-untrusted", str(untrusted)]
    args += list(extra) + [str(leaf)]
    r = run(*args, check=False)
    if r.returncode == 0:
        return "ok"
    err = (r.stderr + r.stdout).decode(errors="replace")
    for line in err.splitlines():
        if line.startswith("error "):
            return line.strip()[:160]
    return "fail: " + err.strip().splitlines()[-1][:160] if err.strip() else "fail"


# --------------------------------------------------------------------------
# key / cert factories
# --------------------------------------------------------------------------


def genkey(name: str, alg: str, *pkeyopts: str) -> pathlib.Path:
    key = WORK / f"{name}.key"
    if key.exists():
        return key
    args = ["genpkey", "-algorithm", alg, "-out", str(key)]
    for o in pkeyopts:
        args += ["-pkeyopt", o]
    run(*args)
    return key


def gen_dsa_key(name: str, bits: int = 2048) -> pathlib.Path:
    key = WORK / f"{name}.key"
    if key.exists():
        return key
    params = WORK / f"{name}.params"
    run("genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", f"pbits:{bits}", "-pkeyopt", "qbits:256", "-out", str(params))
    run("genpkey", "-paramfile", str(params), "-out", str(key))
    return key


def write_cnf(name: str, req_extra: str = "", sections: str = "") -> pathlib.Path:
    cnf = WORK / f"{name}.cnf"
    cnf.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "prompt = no\n"
        f"{req_extra}\n"
        "[dn]\n"
        "CN = placeholder\n"
        f"{sections}\n"
    )
    return cnf


def self_signed(
    name: str,
    key: pathlib.Path,
    subj: str,
    ext: str = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
    days: int = 3650,
    md: str | None = "sha256",
    serial: str | None = None,
    extra: list[str] | None = None,
    req_extra: str = "",
    not_before: str | None = None,
    not_after: str | None = None,
) -> pathlib.Path:
    out = WORK / f"{name}.pem"
    cnf = write_cnf(name, req_extra, "[v3]\n" + ext)
    args = ["req", "-new", "-x509", "-key", str(key), "-subj", subj, "-config", str(cnf), "-extensions", "v3", "-out", str(out)]
    if not_before or not_after:
        args += ["-not_before", not_before or "20200101000000Z", "-not_after", not_after or "20400101000000Z"]
    else:
        args += ["-days", str(days)]
    if md:
        args += [f"-{md}"]
    if serial is not None:
        args += ["-set_serial", serial]
    if extra:
        args += extra
    run(*args)
    return out


def csr(name: str, key: pathlib.Path, subj: str, extra: list[str] | None = None, req_extra: str = "") -> pathlib.Path:
    out = WORK / f"{name}.csr"
    cnf = write_cnf(name + "_csr", req_extra)
    args = ["req", "-new", "-key", str(key), "-subj", subj, "-config", str(cnf), "-out", str(out)]
    if extra:
        args += extra
    run(*args)
    return out


def issue(
    name: str,
    key: pathlib.Path,
    subj: str,
    ca_cert: pathlib.Path,
    ca_key: pathlib.Path,
    ext: str,
    days: int = 825,
    md: str | None = "sha256",
    serial: str | None = None,
    extra: list[str] | None = None,
    req_extra: str = "",
    not_before: str | None = None,
    not_after: str | None = None,
    x509v1: bool = False,
    force_pubkey: pathlib.Path | None = None,
    req_args: list[str] | None = None,
) -> pathlib.Path:
    out = WORK / f"{name}.pem"
    if force_pubkey is not None:
        # openssl x509 -new lets us wrap a public key we cannot sign with (KEM, X25519)
        args = ["x509", "-new", "-force_pubkey", str(force_pubkey), "-subj", subj, "-CA", str(ca_cert), "-CAkey", str(ca_key), "-out", str(out)]
    else:
        req = csr(name, key, subj, extra=req_args, req_extra=req_extra)
        args = ["x509", "-req", "-in", str(req), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-out", str(out)]
    if x509v1:
        args += ["-x509v1"]
    else:
        extf = WORK / f"{name}.ext"
        extf.write_text(ext)
        args += ["-extfile", str(extf)]
    if not_before or not_after:
        args += ["-not_before", not_before or "20200101000000Z", "-not_after", not_after or "20400101000000Z"]
    else:
        args += ["-days", str(days)]
    if md:
        args += [f"-{md}"]
    if serial is not None:
        args += ["-set_serial", serial]
    else:
        args += ["-set_serial", "0x" + os.urandom(8).hex()]
    if extra:
        args += extra
    run(*args)
    return out


def publish(src: pathlib.Path, rel: str, kind: str, expect: str, reason: str, der: bool = False, **extra) -> pathlib.Path:
    dst = OUT / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    if der and data.lstrip().startswith(b"-----"):
        label = {"cert": "CERTIFICATE", "crl": "X509 CRL", "csr": "CERTIFICATE REQUEST"}[kind]
        data = pem_to_der(data, label)
    dst.write_bytes(data)
    res = openssl_parse_result(dst, kind if kind in ("cert", "crl", "csr") else "p7")
    record(rel, kind, expect, reason, openssl=res, **extra)
    return dst


# --------------------------------------------------------------------------
# minimal DER rewriter (enough for surgery on certificates)
# --------------------------------------------------------------------------


class Node:
    def __init__(self, tag: int, value: bytes, children: list["Node"] | None = None, raw_len: bytes | None = None):
        self.tag = tag
        self.value = value  # primitive content (ignored when children is set)
        self.children = children
        self.raw_len = raw_len  # keep original length octets for round-tripping

    @property
    def constructed(self) -> bool:
        return self.children is not None

    def encode(self, force_len: bytes | None = None) -> bytes:
        body = b"".join(c.encode() for c in self.children) if self.constructed else self.value
        return bytes([self.tag]) + (force_len if force_len is not None else enc_len(len(body))) + body

    def __getitem__(self, i: int) -> "Node":
        assert self.children is not None
        return self.children[i]


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def parse(buf: bytes, pos: int = 0) -> tuple[Node, int]:
    tag = buf[pos]
    pos += 1
    l = buf[pos]
    pos += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(buf[pos : pos + n], "big")
        pos += n
    val = buf[pos : pos + l]
    end = pos + l
    if tag & 0x20:
        kids = []
        p = pos
        while p < end:
            k, p = parse(buf, p)
            kids.append(k)
        return Node(tag, b"", kids), end
    return Node(tag, val), end


def cert_parts(der: bytes) -> tuple[Node, Node, Node, Node]:
    """Return (certificate, tbs, sigalg, sigvalue)."""
    root, _ = parse(der)
    return root, root[0], root[1], root[2]


def tbs_index(tbs: Node) -> dict[str, int]:
    """Map TBSCertificate field names to child indexes (handles absent version)."""
    i = 0
    idx = {}
    if tbs[0].tag == 0xA0:
        idx["version"] = 0
        i = 1
    for f in ("serial", "sigalg", "issuer", "validity", "subject", "spki"):
        idx[f] = i
        i += 1
    while i < len(tbs.children):
        t = tbs[i].tag
        idx[{0xA1: "issuerUID", 0xA2: "subjectUID", 0xA3: "extensions"}.get(t, f"unk{i}")] = i
        i += 1
    return idx


def mutate(der: bytes, fn) -> bytes:
    cert, tbs, alg, sig = cert_parts(der)
    fn(cert, tbs, alg, sig)
    return cert.encode()


def resign(der: bytes, fn, ca_key: pathlib.Path, md: str = "sha256") -> bytes:
    """Apply fn to the TBS, then produce a fresh, valid signature with ca_key.

    Only for RSA (PKCS#1 v1.5) and ECDSA issuers: `openssl dgst -sign` emits
    exactly the octets that belong in signatureValue for those algorithms.
    """
    cert, tbs, alg, sig = cert_parts(der)
    fn(cert, tbs, alg, sig)
    tbs_der = tbs.encode()
    r = run("dgst", f"-{md}", "-sign", str(ca_key), input=tbs_der)
    sig.value = b"\x00" + r.stdout
    return cert.encode()


# --------------------------------------------------------------------------
# corpus sections
# --------------------------------------------------------------------------


def section_algorithms() -> dict[str, tuple[pathlib.Path, pathlib.Path]]:
    """Self-signed roots for every signature / key algorithm family."""
    roots = {}
    specs = [
        ("rsa2048_sha256", ("RSA", "rsa_keygen_bits:2048"), "sha256", "RSA-2048, sha256WithRSAEncryption"),
        ("rsa3072_sha384", ("RSA", "rsa_keygen_bits:3072"), "sha384", "RSA-3072, sha384WithRSAEncryption"),
        ("rsa4096_sha512", ("RSA", "rsa_keygen_bits:4096"), "sha512", "RSA-4096, sha512WithRSAEncryption"),
        ("rsa2048_sha1", ("RSA", "rsa_keygen_bits:2048"), "sha1", "RSA-2048 signed with sha1WithRSAEncryption (weak digest)"),
        ("rsa2048_sha224", ("RSA", "rsa_keygen_bits:2048"), "sha224", "RSA-2048, sha224WithRSAEncryption"),
        ("rsa2048_sha512_256", ("RSA", "rsa_keygen_bits:2048"), "sha512-256", "RSA-2048, sha512-256WithRSAEncryption (RFC 8017 truncated SHA-512)"),
        ("rsa2048_sha3_256", ("RSA", "rsa_keygen_bits:2048"), "sha3-256", "RSA-2048, id-rsassa-pkcs1-v1_5-with-sha3-256"),
        ("rsa1024_sha256", ("RSA", "rsa_keygen_bits:1024"), "sha256", "RSA-1024 (legacy, below current minimum)"),
        ("rsa512_sha256", ("RSA", "rsa_keygen_bits:512"), "sha256", "RSA-512 (toy key; signature shorter than digest info + padding minimum edge)"),
        ("rsa8192_sha256", ("RSA", "rsa_keygen_bits:8192"), "sha256", "RSA-8192 (very large modulus)"),
        ("rsa2048_e3_sha256", ("RSA", "rsa_keygen_bits:2048", "rsa_keygen_pubexp:3"), "sha256", "RSA-2048 with public exponent 3"),
        ("ecp256_sha256", ("EC", "ec_paramgen_curve:P-256"), "sha256", "ECDSA P-256, ecdsa-with-SHA256"),
        ("ecp384_sha384", ("EC", "ec_paramgen_curve:P-384"), "sha384", "ECDSA P-384, ecdsa-with-SHA384"),
        ("ecp521_sha512", ("EC", "ec_paramgen_curve:P-521"), "sha512", "ECDSA P-521, ecdsa-with-SHA512"),
        ("ecp256_sha1", ("EC", "ec_paramgen_curve:P-256"), "sha1", "ECDSA P-256 signed with ecdsa-with-SHA1"),
        ("ecp256_sha3_256", ("EC", "ec_paramgen_curve:P-256"), "sha3-256", "ECDSA P-256, id-ecdsa-with-sha3-256"),
        ("ecp224_sha224", ("EC", "ec_paramgen_curve:P-224"), "sha224", "ECDSA P-224, ecdsa-with-SHA224"),
        ("secp256k1_sha256", ("EC", "ec_paramgen_curve:secp256k1"), "sha256", "ECDSA secp256k1 (non-NIST curve)"),
        ("brainpoolp256r1_sha256", ("EC", "ec_paramgen_curve:brainpoolP256r1"), "sha256", "ECDSA brainpoolP256r1 (RFC 5639 curve)"),
        ("brainpoolp384r1_sha384", ("EC", "ec_paramgen_curve:brainpoolP384r1"), "sha384", "ECDSA brainpoolP384r1"),
        ("ecp256_explicit_sha256", ("EC", "ec_paramgen_curve:P-256", "ec_param_enc:explicit"), "sha256", "P-256 key with explicit (specifiedCurve) domain parameters in SPKI - forbidden by RFC 5480 for PKIX but seen in the wild"),
        ("ed25519", ("ED25519",), None, "Ed25519 (RFC 8410), no digest, absent parameters"),
        ("ed448", ("ED448",), None, "Ed448 (RFC 8410)"),
        ("mldsa44", ("ML-DSA-44",), None, "ML-DSA-44 (RFC 9881)"),
        ("mldsa65", ("ML-DSA-65",), None, "ML-DSA-65 (RFC 9881)"),
        ("mldsa87", ("ML-DSA-87",), None, "ML-DSA-87 (RFC 9881)"),
        ("slhdsa_sha2_128s", ("SLH-DSA-SHA2-128s",), None, "SLH-DSA-SHA2-128s (RFC 9909), ~8 KB signature"),
        ("slhdsa_shake_128f", ("SLH-DSA-SHAKE-128f",), None, "SLH-DSA-SHAKE-128f (RFC 9909), ~17 KB signature"),
    ]
    for name, (alg, *opts), md, reason in specs:
        key = genkey(name, alg, *opts)
        cert = self_signed(name, key, f"/C=XX/O=tiny-crypto synthetic/CN=Root {name}", md=md)
        roots[name] = (cert, key)
        publish(cert, f"algorithms/root_{name}.pem", "cert", "parse", reason, self_signed=True)
        publish(cert, f"algorithms/root_{name}.der", "cert", "parse", reason + " (DER)", der=True, self_signed=True)

    # DSA
    dsa_key = gen_dsa_key("dsa2048")
    dsa = self_signed("dsa2048_sha256", dsa_key, "/CN=Root dsa2048", md="sha256")
    roots["dsa2048_sha256"] = (dsa, dsa_key)
    publish(dsa, "algorithms/root_dsa2048_sha256.pem", "cert", "parse", "DSA-2048/256, id-dsa-with-sha256 (RFC 5758)", self_signed=True)
    dsa1 = self_signed("dsa2048_sha1", dsa_key, "/CN=Root dsa2048 sha1", md="sha1")
    publish(dsa1, "algorithms/root_dsa2048_sha1.pem", "cert", "parse", "DSA-2048 signed with dsaWithSHA1 (RFC 3279)", self_signed=True)

    # RSA-PSS: PKCS#1 key with PSS signature, and a restricted RSA-PSS key
    rsa = roots["rsa2048_sha256"][1]
    pss_opts = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"]
    pss = self_signed("rsa_pss_sha256", rsa, "/CN=Root RSA PSS sha256", md="sha256", extra=pss_opts)
    roots["rsa_pss_sha256"] = (pss, rsa)
    publish(pss, "algorithms/root_rsa2048_pss_sha256_salt32.pem", "cert", "parse", "rsaEncryption SPKI, RSASSA-PSS signature (sha256/MGF1-sha256/salt 32) with explicit parameters (RFC 4055)", self_signed=True)
    pss384 = self_signed("rsa_pss_sha384", roots["rsa3072_sha384"][1], "/CN=Root RSA PSS sha384", md="sha384", extra=["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:48", "-sigopt", "rsa_mgf1_md:sha384"])
    publish(pss384, "algorithms/root_rsa3072_pss_sha384_salt48.pem", "cert", "parse", "RSASSA-PSS sha384/MGF1-sha384/salt 48", self_signed=True)
    pss_s20 = self_signed("rsa_pss_sha256_salt20", rsa, "/CN=Root RSA PSS salt20", md="sha256", extra=["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:20", "-sigopt", "rsa_mgf1_md:sha256"])
    publish(pss_s20, "algorithms/root_rsa2048_pss_sha256_salt20.pem", "cert", "parse", "RSASSA-PSS with saltLength 20 (default omitted in DER? no: explicit 20)", self_signed=True)
    pss_mgf_mismatch = self_signed("rsa_pss_mgf_mismatch", rsa, "/CN=Root RSA PSS mgf mismatch", md="sha256", extra=["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha1"])
    publish(pss_mgf_mismatch, "algorithms/root_rsa2048_pss_sha256_mgf1sha1.pem", "cert", "parse-only", "RSASSA-PSS with hashAlgorithm sha256 but MGF1 hash sha1 (legal but forbidden by RFC 4055 §3.1 and RFC 8017 profiles that require equality)", self_signed=True)
    psskey = genkey("rsapss_key", "RSA-PSS", "rsa_keygen_bits:2048", "rsa_pss_keygen_md:sha256", "rsa_pss_keygen_mgf1_md:sha256", "rsa_pss_keygen_saltlen:32")
    pssk = self_signed("rsapss_key_cert", psskey, "/CN=Root id-RSASSA-PSS key", md="sha256")
    roots["rsapss_key"] = (pssk, psskey)
    publish(pssk, "algorithms/root_rsapss_restricted_key.pem", "cert", "parse", "SPKI algorithm id-RSASSA-PSS with parameter restrictions (RFC 4055 §3.3)", self_signed=True)

    # compressed EC point in SPKI
    eckey = roots["ecp256_sha256"][1]
    comp = WORK / "ecp256_compressed.key"
    run("ec", "-in", str(eckey), "-conv_form", "compressed", "-out", str(comp))
    ccert = self_signed("ecp256_compressed", comp, "/CN=Root ecp256 compressed point")
    publish(ccert, "algorithms/root_ecp256_compressed_point.pem", "cert", "parse", "P-256 SPKI with compressed point (02/03 prefix); RFC 5480 says implementations SHOULD support it", self_signed=True)

    # keys that cannot sign: ML-KEM, X25519, X448 - wrapped in certs signed by an ML-DSA / Ed25519 CA
    for kem, signer in (("ML-KEM-512", "mldsa44"), ("ML-KEM-768", "mldsa65"), ("ML-KEM-1024", "mldsa87")):
        k = genkey(kem.lower().replace("-", ""), kem)
        pub = WORK / (k.stem + ".pub")
        run("pkey", "-in", str(k), "-pubout", "-out", str(pub))
        c = issue(f"leaf_{k.stem}", k, f"/CN={kem} key", roots[signer][0], roots[signer][1], "basicConstraints=CA:FALSE\nkeyUsage=critical,keyEncipherment\n", md=None, force_pubkey=pub)
        publish(c, f"algorithms/leaf_{k.stem}_signed_{signer}.pem", "cert", "parse", f"{kem} public key (RFC 9935) in an end-entity certificate signed with {signer}", chain=[f"algorithms/root_{signer}.pem"])
    for xk, signer in (("X25519", "ed25519"), ("X448", "ed448")):
        k = genkey(xk.lower(), xk)
        pub = WORK / (k.stem + ".pub")
        run("pkey", "-in", str(k), "-pubout", "-out", str(pub))
        c = issue(f"leaf_{k.stem}", k, f"/CN={xk} key agreement", roots[signer][0], roots[signer][1], "basicConstraints=CA:FALSE\nkeyUsage=critical,keyAgreement\n", md=None, force_pubkey=pub)
        publish(c, f"algorithms/leaf_{k.stem}_signed_{signer}.pem", "cert", "parse", f"{xk} key agreement public key (RFC 8410 §10.2 style) signed with {signer}", chain=[f"algorithms/root_{signer}.pem"])
    return roots


def section_chains(roots) -> dict:
    """Valid multi-level chains, cross-signing, and a deep path."""
    out = {}
    plan = [
        ("rsa", "rsa4096_sha512", ("RSA", "rsa_keygen_bits:2048"), "sha256", ("EC", "ec_paramgen_curve:P-256"), "sha256", "RSA-4096 root -> RSA-2048 intermediate -> P-256 leaf (mixed algorithms)"),
        ("ec", "ecp384_sha384", ("EC", "ec_paramgen_curve:P-384"), "sha384", ("EC", "ec_paramgen_curve:P-256"), "sha256", "P-384 root -> P-384 intermediate -> P-256 leaf"),
        ("ed25519", "ed25519", ("ED25519",), None, ("ED25519",), None, "Ed25519 root -> Ed25519 intermediate -> Ed25519 leaf"),
        ("mldsa", "mldsa87", ("ML-DSA-65",), None, ("ML-DSA-44",), None, "ML-DSA-87 root -> ML-DSA-65 intermediate -> ML-DSA-44 leaf"),
        ("pss", "rsa_pss_sha256", ("RSA", "rsa_keygen_bits:2048"), "sha256", ("RSA", "rsa_keygen_bits:2048"), "sha256", "RSA-PSS signatures at every level"),
    ]
    for tag, rootname, ialg, imd, lalg, lmd, reason in plan:
        rcert, rkey = roots[rootname]
        ikey = genkey(f"chain_{tag}_int", *ialg)
        lkey = genkey(f"chain_{tag}_leaf", *lalg)
        pss = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"] if tag == "pss" else None
        inter = issue(f"chain_{tag}_int", ikey, f"/C=XX/O=tiny-crypto synthetic/CN=Intermediate {tag}", rcert, rkey,
                      "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n", days=3000, md=imd, extra=pss)
        leaf = issue(f"chain_{tag}_leaf", lkey, f"/C=XX/O=tiny-crypto synthetic/CN=leaf-{tag}.example.com", inter, ikey,
                     "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:leaf-%s.example.com,DNS:www.leaf-%s.example.com\n" % (tag, tag), md=lmd, extra=pss)
        d = f"chains/{tag}"
        publish(rcert, f"{d}/root.pem", "cert", "parse", reason + " [root]", self_signed=True)
        publish(inter, f"{d}/intermediate.pem", "cert", "parse", reason + " [intermediate]", chain=[f"{d}/root.pem"])
        v = openssl_verify(leaf, [inter], rcert)
        publish(leaf, f"{d}/leaf.pem", "cert", "parse", reason + " [leaf]", chain=[f"{d}/intermediate.pem", f"{d}/root.pem"], openssl_verify=v)
        bundle = OUT / d / "chain.pem"
        bundle.write_bytes(leaf.read_bytes() + inter.read_bytes() + rcert.read_bytes())
        record(f"{d}/chain.pem", "bundle", "parse", reason + " [PEM bundle leaf,intermediate,root]")
        p7 = OUT / d / "chain.p7b"
        run("crl2pkcs7", "-nocrl", "-certfile", str(bundle), "-out", str(p7), "-outform", "DER")
        record(f"{d}/chain.p7b", "p7b", "parse", reason + " [PKCS#7 certs-only bundle, DER]", openssl=openssl_parse_result(p7, "p7"))
        out[tag] = {"root": rcert, "root_key": rkey, "int": inter, "int_key": ikey, "leaf": leaf, "leaf_key": lkey}

    # cross-signed intermediate: same intermediate key/subject signed by two roots
    r1c, r1k = roots["rsa2048_sha256"]
    r2c, r2k = roots["ecp256_sha256"]
    xkey = genkey("xsign_int", "RSA", "rsa_keygen_bits:2048")
    xa = issue("xsign_int_a", xkey, "/O=tiny-crypto synthetic/CN=Cross-signed Intermediate", r1c, r1k, "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n", days=3000)
    xb = issue("xsign_int_b", xkey, "/O=tiny-crypto synthetic/CN=Cross-signed Intermediate", r2c, r2k, "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n", days=3000)
    lk = genkey("xsign_leaf", "EC", "ec_paramgen_curve:P-256")
    xl = issue("xsign_leaf", lk, "/CN=cross.example.com", xa, xkey, "basicConstraints=CA:FALSE\nsubjectAltName=DNS:cross.example.com\nauthorityKeyIdentifier=keyid\n")
    publish(r1c, "chains/cross_signed/root_a_rsa.pem", "cert", "parse", "cross-signing: root A (RSA)", self_signed=True)
    publish(r2c, "chains/cross_signed/root_b_ec.pem", "cert", "parse", "cross-signing: root B (EC)", self_signed=True)
    publish(xa, "chains/cross_signed/intermediate_signed_by_a.pem", "cert", "parse", "same intermediate key+subject, issued by root A", chain=["chains/cross_signed/root_a_rsa.pem"])
    publish(xb, "chains/cross_signed/intermediate_signed_by_b.pem", "cert", "parse", "same intermediate key+subject, issued by root B", chain=["chains/cross_signed/root_b_ec.pem"])
    publish(xl, "chains/cross_signed/leaf.pem", "cert", "parse", "leaf validates through either intermediate (AKID is keyid only)",
            chain=["chains/cross_signed/intermediate_signed_by_a.pem", "chains/cross_signed/root_a_rsa.pem"],
            openssl_verify=openssl_verify(xl, [xa], r1c) + " | via B: " + openssl_verify(xl, [xb], r2c))

    # deep chain: root + 6 intermediates + leaf, pathlen decreasing
    rc, rk = roots["ecp256_sha256"]
    prev_c, prev_k = rc, rk
    files = ["chains/deep/root.pem"]
    publish(rc, "chains/deep/root.pem", "cert", "parse", "deep chain root", self_signed=True)
    inters = []
    for i in range(6):
        k = genkey(f"deep_int{i}", "EC", "ec_paramgen_curve:P-256")
        c = issue(f"deep_int{i}", k, f"/CN=Deep Intermediate {i}", prev_c, prev_k, f"basicConstraints=critical,CA:TRUE,pathlen:{5 - i}\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n", days=3000)
        publish(c, f"chains/deep/intermediate_{i}.pem", "cert", "parse", f"deep chain intermediate {i} (pathlen {5 - i})", chain=list(reversed(files)))
        files.append(f"chains/deep/intermediate_{i}.pem")
        inters.append(c)
        prev_c, prev_k = c, k
    lk = genkey("deep_leaf", "EC", "ec_paramgen_curve:P-256")
    leaf = issue("deep_leaf", lk, "/CN=deep.example.com", prev_c, prev_k, "basicConstraints=CA:FALSE\nsubjectAltName=DNS:deep.example.com\n")
    publish(leaf, "chains/deep/leaf.pem", "cert", "parse", "leaf at depth 8 (root + 6 intermediates)", chain=list(reversed(files)), openssl_verify=openssl_verify(leaf, inters, rc))
    out["deep"] = {"root": rc, "root_key": rk, "inters": inters, "leaf": leaf}
    return out


def section_fields(roots, chains) -> None:
    """Names, times, serials, string types, subject variants."""
    ca_c, ca_k = chains["ec"]["int"], chains["ec"]["int_key"]
    ca_chain = ["chains/ec/intermediate.pem", "chains/ec/root.pem"]
    k = genkey("fields_leaf", "EC", "ec_paramgen_curve:P-256")
    base_ext = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n"

    def leaf(name, subj, ext=base_ext, reason="", expect="parse", **kw):
        c = issue("fields_" + name, k, subj, ca_c, ca_k, ext, **kw)
        publish(c, f"fields/{name}.pem", "cert", expect, reason, chain=ca_chain, openssl_verify=openssl_verify(c, [ca_c], chains["ec"]["root"]))
        return c

    # --- serial numbers
    leaf("serial_1", "/CN=serial one", serial="1", reason="serialNumber = 1 (single byte)")
    leaf("serial_20_bytes", "/CN=serial 20 bytes", serial="0x7f" + "ab" * 19, reason="20-octet positive serialNumber (RFC 5280 maximum)")
    leaf("serial_high_bit_20_bytes", "/CN=serial hi bit", serial="0x" + "ff" * 20, reason="serialNumber whose magnitude needs 20 bytes with the high bit set, so DER needs 21 content octets (leading 00) - still legal per RFC 5280 §4.1.2.2 erratum discussions; many parsers cap at 20")
    leaf("serial_21_bytes", "/CN=serial 21 bytes", serial="0x01" + "00" * 20, reason="21-octet serialNumber, exceeds the RFC 5280 20-octet limit (conforming CAs MUST NOT; parsers SHOULD accept gracefully)", expect="parse-only")
    leaf("serial_negative", "/CN=serial negative", serial="-1234567", reason="negative serialNumber (RFC 5280 says CAs MUST use positive; parsers SHOULD handle non-conforming negative values)", expect="parse-only")
    leaf("serial_zero", "/CN=serial zero", serial="0", reason="serialNumber = 0 (non-positive, non-conforming but seen in the wild)", expect="parse-only")

    # --- validity encodings
    leaf("validity_utctime", "/CN=utctime", not_before="20200101000000Z", not_after="20491231235959Z", reason="UTCTime for both dates, notAfter at the 2049 boundary")
    leaf("validity_generalizedtime", "/CN=generalizedtime", not_before="20200101000000Z", not_after="20600101000000Z", reason="notAfter in 2060 must be GeneralizedTime (RFC 5280 §4.1.2.5)")
    leaf("validity_no_well_defined_expiry", "/CN=no expiry", not_before="20200101000000Z", not_after="99991231235959Z", reason="notAfter 99991231235959Z: RFC 5280 'no well-defined expiration date'")
    leaf("validity_before_1950", "/CN=before 1950", not_before="19491231235959Z", not_after="20300101000000Z", reason="notBefore 1949 must be GeneralizedTime; UTCTime cannot express it")
    leaf("validity_expired", "/CN=expired", not_before="20100101000000Z", not_after="20110101000000Z", reason="expired certificate (semantically invalid, structurally fine)", expect="parse-only")
    leaf("validity_not_yet_valid", "/CN=not yet valid", not_before="20500101000000Z", not_after="20600101000000Z", reason="not yet valid (notBefore in 2050 - also exercises GeneralizedTime for notBefore)", expect="parse-only")
    leaf("validity_one_second", "/CN=one second", not_before="20260101000000Z", not_after="20260101000001Z", reason="1-second validity window (2026-01-01 00:00:00 to 00:00:01, so expired)", expect="parse-only")
    inv = issue("fields_validity_inverted_src", k, "/CN=inverted", ca_c, ca_k, base_ext, not_before="20200101000000Z", not_after="20300101000000Z")

    def swap_times(cert, tbs, alg, sig):
        v = tbs[tbs_index(tbs)["validity"]]
        v.children.reverse()

    inv_bad = WORK / "fields_validity_inverted.pem"
    inv_bad.write_bytes(der_to_pem(resign(pem_to_der(inv.read_bytes()), swap_times, ca_k)))
    publish(inv_bad, "fields/validity_inverted.pem", "cert", "parse-only", "notBefore after notAfter (validly re-signed by the issuer)", chain=ca_chain, openssl_verify=openssl_verify(inv_bad, [ca_c], chains["ec"]["root"]))

    # --- DN string types and content
    leaf("dn_printablestring", "/C=XX/ST=State/L=City/O=Org/OU=Unit/CN=printable.example.com", req_extra="string_mask = default\n", reason="DN attributes as PrintableString (string_mask default)")
    leaf("dn_utf8string", "/C=XX/O=Org/CN=utf8.example.com", req_extra="string_mask = utf8only\n", reason="DN attributes as UTF8String")
    leaf("dn_utf8_nonascii", "/C=DE/O=Zürich Straße GmbH/CN=Ünïcödé ✓ 例子", req_extra="string_mask = utf8only\nutf8 = yes\n", req_args=["-utf8"], reason="UTF8String DN with Latin-1, symbol and CJK characters")
    leaf("dn_bmpstring", "/C=XX/O=BMP Örg/CN=bmp.example.com", req_extra="string_mask = default\nutf8 = yes\n", req_args=["-utf8"], reason="non-ASCII with string_mask default -> BMPString / T61String legacy types")
    leaf("dn_t61string", "/C=XX/O=T61 Örg/CN=t61.example.com", req_extra="string_mask = nombstr\nutf8 = yes\n", req_args=["-utf8"], reason="string_mask nombstr forces T61String (TeletexString) for non-ASCII")
    leaf("dn_all_common_attributes", "/C=XX/ST=State/L=Locality/street=1 Main St/postalCode=12345/O=Org/OU=Unit/CN=all.example.com/emailAddress=a@example.com/serialNumber=SN-1/title=Engineer/GN=Given/SN=Sur/initials=GS/pseudonym=nick/generationQualifier=III/dnQualifier=dq/businessCategory=Private Organization/jurisdictionC=XX/organizationIdentifier=NTRXX-123/DC=example/DC=com/UID=uid1/description=desc/name=full name", reason="DN using most attribute types from RFC 4519 / X.520 / CABF EV")
    leaf("dn_multivalued_rdn", "/C=XX/CN=multi.example.com+OU=Unit A+O=Org", req_args=["-multivalue-rdn"], reason="multi-valued RDN (SET with three AttributeTypeAndValue, DER sorted)")
    leaf("dn_unknown_attribute_oid", "/CN=oid.example.com/1.2.840.113549.1.9.2=unstructuredName/2.5.4.97=NTRXX-1/1.3.6.1.4.1.99999.1=custom", reason="DN with attribute types given by OID, including a private-enterprise arc")
    lc = issue("fields_dn_long_cn_src", k, "/CN=long", ca_c, ca_k, base_ext)

    def long_cn(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        subj.children[0].children[0].children[1].value = b"a" * 64 + b".example.com"

    lc_bad = WORK / "fields_dn_long_cn.pem"
    lc_bad.write_bytes(der_to_pem(resign(pem_to_der(lc.read_bytes()), long_cn, ca_k)))
    publish(lc_bad, "fields/dn_long_cn.pem", "cert", "parse-only", "CN of 76 characters (exceeds X.520 ub-common-name 64; OpenSSL refuses to create it, so the value was patched in and the certificate re-signed)", chain=ca_chain, openssl_verify=openssl_verify(lc_bad, [ca_c], chains["ec"]["root"]))
    leaf("dn_duplicate_attributes", "/CN=first/CN=second/OU=x/OU=y", reason="two CN RDNs and two OU RDNs (legal, order significant)")
    leaf("subject_empty_san_critical", "/", "basicConstraints=CA:FALSE\nsubjectAltName=critical,DNS:empty-subject.example.com\nauthorityKeyIdentifier=keyid\n", reason="empty subject SEQUENCE with critical SAN (RFC 5280 §4.1.2.6)")
    leaf("subject_empty_san_not_critical", "/", "basicConstraints=CA:FALSE\nsubjectAltName=DNS:empty-subject.example.com\n", reason="empty subject but SAN not marked critical (violates RFC 5280 MUST)", expect="parse-only")
    leaf("subject_cn_only_no_san", "/CN=cn-only.example.com", "basicConstraints=CA:FALSE\n", reason="hostname only in CN, no SAN (legacy; CABF forbids since 2012)")
    leaf("subject_ip_in_cn", "/CN=192.0.2.1", "basicConstraints=CA:FALSE\nsubjectAltName=IP:192.0.2.1\n", reason="IPv4 address as CN and iPAddress SAN")
    leaf("subject_wildcard", "/CN=*.example.com", "basicConstraints=CA:FALSE\nsubjectAltName=DNS:*.example.com,DNS:example.com\n", reason="wildcard dNSName")
    leaf("subject_idn_punycode", "/CN=xn--bcher-kva.example", "basicConstraints=CA:FALSE\nsubjectAltName=DNS:xn--bcher-kva.example,DNS:xn--80ak6aa92e.com\n", reason="IDN A-labels (punycode) in SAN")
    # subject / issuer unique identifiers cannot be produced by openssl; see malformed/ for DER-injected ones


def section_extensions(roots, chains) -> None:
    ca_c, ca_k = chains["rsa"]["int"], chains["rsa"]["int_key"]
    ca_chain = ["chains/rsa/intermediate.pem", "chains/rsa/root.pem"]
    k = genkey("ext_leaf", "EC", "ec_paramgen_curve:P-256")

    def leaf(name, ext, reason, expect="parse", subj="/CN=ext.example.com", **kw):
        c = issue("ext_" + name, k, subj, ca_c, ca_k, ext, **kw)
        publish(c, f"extensions/{name}.pem", "cert", expect, reason, chain=ca_chain, openssl_verify=openssl_verify(c, [ca_c], chains["rsa"]["root"]))
        return c

    v3src = issue("ext_v1_src", k, "/CN=v1.example.com", ca_c, ca_k, "basicConstraints=CA:FALSE\n")

    def strip_to_v1(cert, tbs, alg, sig):
        idx = tbs_index(tbs)
        tbs.children.pop(idx["extensions"])
        tbs.children.pop(0)

    v1 = WORK / "ext_v1_no_extensions.pem"
    v1.write_bytes(der_to_pem(resign(pem_to_der(v3src.read_bytes()), strip_to_v1, ca_k)))
    publish(v1, "extensions/v1_no_extensions.pem", "cert", "parse", "X.509 v1 certificate (no version field, no extensions) issued and validly signed by a v3 CA", chain=ca_chain, openssl_verify=openssl_verify(v1, [ca_c], chains["rsa"]["root"]))
    v1root = self_signed("ext_v1_root", roots["rsa2048_sha256"][1], "/CN=v1 self-signed root", extra=["-x509v1"], ext="")
    publish(v1root, "extensions/v1_self_signed_root.pem", "cert", "parse", "X.509 v1 self-signed certificate (what 1990s roots look like)", self_signed=True)
    leaf("v3_empty_extensions_none", "basicConstraints=CA:FALSE\n", "minimal v3: only basicConstraints")
    leaf("all_general_name_types",
         "basicConstraints=CA:FALSE\nsubjectAltName=DNS:gn.example.com,IP:192.0.2.7,IP:2001:db8::7,email:user@example.com,URI:https://gn.example.com/path?q=1,RID:1.3.6.1.4.1.99999.2,dirName:dir_sect,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com,otherName:1.3.6.1.5.5.7.8.7;IA5STRING:_smtp.example.com\n"
         "[dir_sect]\nC=XX\nO=Dir Org\nCN=dir name\n",
         "SAN with dNSName, IPv4, IPv6, rfc822Name, URI, registeredID, directoryName, otherName (UPN) and SRVName otherName")
    leaf("san_1000_dns", "basicConstraints=CA:FALSE\nsubjectAltName=@alt\n[alt]\n" + "".join(f"DNS.{i}=host{i}.example.com\n" for i in range(1, 1001)), "1000 dNSName SAN entries (~25 KB certificate)")
    leaf("san_ip_ranges_in_ee", "basicConstraints=CA:FALSE\nsubjectAltName=IP:10.0.0.1,IP:::1,IP:0.0.0.0\n", "iPAddress SANs including loopback IPv6 and 0.0.0.0")
    leaf("san_email_only", "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment\nextendedKeyUsage=emailProtection\nsubjectAltName=email:person@example.com\n", "S/MIME style: rfc822Name SAN, contentCommitment (nonRepudiation) bit, emailProtection EKU", subj="/CN=Person Name/emailAddress=person@example.com")
    leaf("key_usage_all_bits", "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly\n", "all nine KeyUsage bits set (9 bits -> 2 octets, 7 unused bits)", expect="parse-only")
    leaf("key_usage_decipher_only", "basicConstraints=CA:FALSE\nkeyUsage=critical,keyAgreement,decipherOnly\n", "decipherOnly (bit 8) forces a 2-octet BIT STRING")
    leaf("eku_many", "basicConstraints=CA:FALSE\nextendedKeyUsage=critical,serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,OCSPSigning,ipsecIKE,msCodeInd,msCodeCom,msCTLSign,msEFS,1.3.6.1.5.5.7.3.17,2.16.840.1.101.3.6.8,1.3.6.1.4.1.311.20.2.2,anyExtendedKeyUsage\n", "critical EKU with fifteen purposes incl. id-PIV-cardAuth (2.16.840.1.101.3.6.8), MS smartcard logon and anyExtendedKeyUsage")
    leaf("aia_crldp_ocsp", "basicConstraints=CA:FALSE\nauthorityInfoAccess=OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.cer,caIssuers;URI:ldap://ldap.example.com/cn=CA?cACertificate\ncrlDistributionPoints=URI:http://crl.example.com/ca.crl,URI:ldap://ldap.example.com/cn=CA?certificateRevocationList\nsubjectInfoAccess=caRepository;URI:http://ca.example.com/repo\n", "AIA (OCSP + two caIssuers), two CRL DPs and SIA")
    leaf("crldp_full", "basicConstraints=CA:FALSE\ncrlDistributionPoints=crldp1_section\n[crldp1_section]\nfullname=URI:http://crl.example.com/full.crl\nCRLissuer=dirName:issuer_sect\nreasons=keyCompromise,CACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,AACompromise\n[issuer_sect]\nC=XX\nCN=Indirect CRL Issuer\n", "DistributionPoint with fullName, cRLIssuer and a reasons ReasonFlags BIT STRING")
    leaf("freshest_crl", "basicConstraints=CA:FALSE\nfreshestCRL=URI:http://crl.example.com/delta.crl\n", "freshestCRL (delta CRL distribution point) extension")
    leaf("certificate_policies_qualifiers", "basicConstraints=CA:FALSE\ncertificatePolicies=ia5org,2.23.140.1.2.1,1.3.6.1.4.1.99999.1.1,@polsect\n[polsect]\npolicyIdentifier=1.3.6.1.4.1.99999.1.2\nCPS.1=https://example.com/cps\nCPS.2=https://example.com/cps2\nuserNotice.1=@notice\n[notice]\nexplicitText=This is a test certificate policy user notice\norganization=Org Name\nnoticeNumbers=1,2,3\n", "certificatePolicies with CABF DV OID, plain OIDs, CPS URIs and a UserNotice with NoticeReference")
    leaf("certificate_policies_any", "basicConstraints=CA:FALSE\ncertificatePolicies=critical,2.5.29.32.0\n", "critical certificatePolicies containing only anyPolicy (RFC 5280 says anyPolicy in EE is fine; critical is unusual)")
    leaf("ocsp_nocheck", "basicConstraints=CA:FALSE\nextendedKeyUsage=OCSPSigning\nnoCheck=ignored\n", "OCSP responder cert with id-pkix-ocsp-nocheck (NULL value extension)")
    leaf("tls_feature_must_staple", "basicConstraints=CA:FALSE\ntlsfeature=status_request\n", "TLS Feature extension (RFC 7633 must-staple)")
    leaf("unknown_noncritical_extension", "basicConstraints=CA:FALSE\n1.3.6.1.4.1.99999.9.1=ASN1:UTF8String:unknown extension payload\n", "unrecognised non-critical extension (private arc) - must be ignored")
    leaf("unknown_critical_extension", "basicConstraints=CA:FALSE\n1.3.6.1.4.1.99999.9.2=critical,ASN1:UTF8String:unknown critical extension\n", "unrecognised CRITICAL extension - RFC 5280 §4.2 requires rejection during validation", expect="parse-only")
    leaf("ext_value_octet_string_empty", "basicConstraints=CA:FALSE\n1.3.6.1.4.1.99999.9.3=ASN1:SEQUENCE\n", "extension whose extnValue OCTET STRING wraps an empty SEQUENCE")
    leaf("issuer_alt_name", "basicConstraints=CA:FALSE\nissuerAltName=DNS:ca.example.com,email:ca@example.com\n", "issuerAltName extension")
    leaf("subject_key_identifier_manual", "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=00112233445566778899AABBCCDDEEFF00112233\nauthorityKeyIdentifier=keyid,issuer:always\n", "explicit SKID value plus AKID with keyid, issuer name and serial")
    leaf("basic_constraints_ca_true_in_leaf", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n", "end-entity style cert claiming CA:TRUE without keyCertSign (parse; policy mismatch)", expect="parse-only")
    leaf("basic_constraints_pathlen_without_ca", "basicConstraints=CA:FALSE,pathlen:3\n", "pathLenConstraint present although cA is FALSE (RFC 5280 says MUST NOT appear)", expect="parse-only")
    leaf("name_constraints_on_leaf", "basicConstraints=CA:FALSE\nnameConstraints=critical,permitted;DNS:.example.com\n", "nameConstraints in an end-entity certificate (MUST only appear in CA certs)", expect="parse-only")
    leaf("subject_directory_attributes", "basicConstraints=CA:FALSE\n2.5.29.9=ASN1:SEQUENCE:sda\n[sda]\nattr1=SEQUENCE:sda_attr\n[sda_attr]\ntype=OID:1.3.6.1.5.5.7.9.4\nvals=SET:sda_vals\n[sda_vals]\nv1=PRINTABLESTRING:XX\n", "subjectDirectoryAttributes carrying countryOfCitizenship (RFC 3739)")
    leaf("qc_statements", "basicConstraints=CA:FALSE\n1.3.6.1.5.5.7.1.3=ASN1:SEQUENCE:qcs\n[qcs]\nq1=SEQUENCE:qc1\nq2=SEQUENCE:qc2\n[qc1]\nid=OID:0.4.0.1862.1.1\n[qc2]\nid=OID:0.4.0.1862.1.6\ninfo=SEQUENCE:qc2info\n[qc2info]\nt=OID:0.4.0.1862.1.6.1\n", "qcStatements (ETSI EN 319 412-5 QcCompliance + QcType eSign)")
    leaf("precert_poison", "basicConstraints=CA:FALSE\n1.3.6.1.4.1.11129.2.4.3=critical,ASN1:NULL\n", "CT precertificate poison extension (critical NULL) - RFC 6962 §3.1; must not be treated as a valid certificate", expect="parse-only")
    leaf("sct_list_fake", "basicConstraints=CA:FALSE\n1.3.6.1.4.1.11129.2.4.2=ASN1:FORMAT:HEX,OCTETSTRING:0000\n", "signedCertificateTimestampList extension with an empty (zero-length) SCT list")
    leaf("piv_style_fascn_upn", "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth,1.3.6.1.4.1.311.20.2.2\ncertificatePolicies=2.16.840.1.101.3.2.1.3.13\nsubjectAltName=@piv_san\n[piv_san]\notherName.1=2.16.840.1.101.3.6.6;FORMAT:HEX,OCT:D65018582A9DE58360D8210842108421084210842108421086A1\notherName.2=1.3.6.1.4.1.311.20.2.3;UTF8:1234567890@mil\nURI=urn:uuid:12345678-1234-5678-1234-567812345678\n", "PIV Authentication certificate profile: FASC-N otherName, UPN, UUID URI, id-fpki-common-authentication policy, smartcard logon EKU", subj="/C=US/O=U.S. Government/OU=Test Agency/CN=TEST SUBJECT")
    leaf("many_extensions", "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:many.example.com\nissuerAltName=issuer:copy\nauthorityInfoAccess=OCSP;URI:http://ocsp.example.com/\ncrlDistributionPoints=URI:http://crl.example.com/ca.crl\ncertificatePolicies=2.23.140.1.2.2\ntlsfeature=status_request\nnsComment=Netscape comment extension\nnsCertType=server\n1.3.6.1.4.1.99999.9.4=ASN1:INTEGER:42\n", "fourteen extensions including Netscape legacy nsCertType/nsComment")

    # CA-only extensions
    ik = genkey("ext_ca", "EC", "ec_paramgen_curve:P-256")
    rc, rk = roots["ecp256_sha256"]
    for name, ext, reason in (
        ("ca_name_constraints", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nnameConstraints=critical,permitted;DNS:.example.com,permitted;DNS:example.com,permitted;email:example.com,permitted;IP:192.0.2.0/255.255.255.0,permitted;IP:2001:db8::/ffff:ffff:ffff:ffff:0:0:0:0,permitted;dirName:nc_dir,excluded;DNS:.forbidden.example.com,excluded;URI:.example.net\n[nc_dir]\nC=XX\nO=Constrained Org\n", "CA with nameConstraints: permitted DNS/email/IPv4/IPv6/dirName subtrees and excluded DNS/URI"),
        ("ca_policy_constraints", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\ncertificatePolicies=1.3.6.1.4.1.99999.1.1,1.3.6.1.4.1.99999.1.2\npolicyConstraints=critical,requireExplicitPolicy:0,inhibitPolicyMapping:1\npolicyMappings=1.3.6.1.4.1.99999.1.1:1.3.6.1.4.1.99999.2.1,1.3.6.1.4.1.99999.1.2:1.3.6.1.4.1.99999.2.2\ninhibitAnyPolicy=critical,0\n", "CA with policyConstraints, policyMappings and inhibitAnyPolicy"),
        ("ca_pathlen_zero", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n", "CA with pathLenConstraint 0 and keyUsage without cRLSign"),
        ("ca_basic_constraints_not_critical", "basicConstraints=CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n", "CA whose basicConstraints is not marked critical (RFC 5280 says MUST be critical in CA certs)"),
        ("ca_missing_key_usage", "basicConstraints=critical,CA:TRUE\n", "CA without keyUsage extension (allowed by RFC 5280 for CAs, forbidden by CABF)"),
    ):
        c = issue("ext_" + name, ik, f"/CN={name}", rc, rk, ext, days=3000)
        publish(c, f"extensions/{name}.pem", "cert", "parse", reason, chain=["algorithms/root_ecp256_sha256.pem"])


def section_path_violations(roots, chains) -> None:
    """Structurally valid certificates whose chains must fail path validation."""
    rc, rk = roots["rsa2048_sha256"]
    root_rel = "algorithms/root_rsa2048_sha256.pem"
    lk = genkey("pv_leaf", "EC", "ec_paramgen_curve:P-256")
    ik = genkey("pv_int", "EC", "ec_paramgen_curve:P-256")
    ca_ext = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
    ee_ext = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pv.example.com\nauthorityKeyIdentifier=keyid\n"

    def case(name, int_ext, leaf_ext, reason, int_kw=None, leaf_kw=None, int_key=ik, leaf_issuer=None, leaf_issuer_key=None, verify_extra=(), leaf_expect="parse-only"):
        inter = issue(f"pv_{name}_int", int_key, f"/CN=Intermediate {name}", rc, rk, int_ext, days=3000, **(int_kw or {}))
        li, lik = (leaf_issuer or inter), (leaf_issuer_key or int_key)
        leaf = issue(f"pv_{name}_leaf", lk, f"/CN=pv.example.com", li, lik, leaf_ext, **(leaf_kw or {}))
        d = f"path_violations/{name}"
        publish(inter, f"{d}/intermediate.pem", "cert", "parse", reason + " [intermediate]", chain=[root_rel])
        publish(leaf, f"{d}/leaf.pem", "cert", leaf_expect, reason + (" [leaf; chain must fail]" if leaf_expect == "parse-only" else " [leaf]"), chain=[f"{d}/intermediate.pem", root_rel],
                openssl_verify=openssl_verify(leaf, [inter], rc, *verify_extra))

    case("intermediate_not_ca", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\n", ee_ext, "intermediate has basicConstraints cA=FALSE")
    case("intermediate_missing_basic_constraints", "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n", ee_ext, "intermediate lacks basicConstraints entirely (v3)")
    case("intermediate_no_keycertsign", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,cRLSign\nsubjectKeyIdentifier=hash\n", ee_ext, "intermediate keyUsage lacks keyCertSign")
    case("intermediate_expired", ca_ext, ee_ext, "intermediate expired in 2015", int_kw={"not_before": "20140101000000Z", "not_after": "20150101000000Z"})
    case("intermediate_not_yet_valid", ca_ext, ee_ext, "intermediate not valid until 2050", int_kw={"not_before": "20500101000000Z", "not_after": "20600101000000Z"})
    case("leaf_expired", ca_ext, ee_ext, "leaf expired", leaf_kw={"not_before": "20200101000000Z", "not_after": "20210101000000Z"})
    case("leaf_outside_intermediate_validity", ca_ext, ee_ext, "leaf validity extends beyond intermediate's notAfter (fine per RFC 5280 at validation time, flagged by some profiles)", int_kw={"not_before": "20200101000000Z", "not_after": "20300101000000Z"}, leaf_kw={"not_before": "20200101000000Z", "not_after": "20400101000000Z"}, leaf_expect="parse")
    case("pathlen_exceeded", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\nsubjectKeyIdentifier=hash\n", ee_ext, "intermediate with pathlen:0; this leaf directly below it is fine", leaf_expect="parse")
    # build pathlen case properly: need a second CA under the pathlen:0 int
    inter0 = WORK / "pv_pathlen_exceeded_int.pem"
    k2 = genkey("pv_pathlen_int2", "EC", "ec_paramgen_curve:P-256")
    int2 = issue("pv_pathlen_int2", k2, "/CN=Intermediate below pathlen 0", inter0, ik, ca_ext, days=3000)
    leaf2 = issue("pv_pathlen_leaf2", lk, "/CN=pv.example.com", int2, k2, ee_ext)
    publish(int2, "path_violations/pathlen_exceeded/intermediate_2.pem", "cert", "parse", "second intermediate issued under a pathlen:0 CA", chain=["path_violations/pathlen_exceeded/intermediate.pem", root_rel])
    publish(leaf2, "path_violations/pathlen_exceeded/leaf_depth2.pem", "cert", "parse-only", "leaf under two intermediates where the first has pathlen:0 - must fail", chain=["path_violations/pathlen_exceeded/intermediate_2.pem", "path_violations/pathlen_exceeded/intermediate.pem", root_rel], openssl_verify=openssl_verify(leaf2, [int2, inter0], rc))

    case("name_constraints_excluded", ca_ext + "nameConstraints=critical,excluded;DNS:.example.com\n", ee_ext, "leaf dNSName pv.example.com falls in an excluded subtree")
    case("name_constraints_not_permitted", ca_ext + "nameConstraints=critical,permitted;DNS:.allowed.test\n", ee_ext, "leaf dNSName not in permitted subtrees")
    case("name_constraints_cn_fallback", ca_ext + "nameConstraints=critical,permitted;DNS:.allowed.test\n", "basicConstraints=CA:FALSE\n", "no SAN; CN pv.example.com outside permitted DNS subtree (only matters if CN is treated as hostname)")
    case("policy_required_missing", ca_ext + "policyConstraints=critical,requireExplicitPolicy:0\ncertificatePolicies=1.3.6.1.4.1.99999.1.1\n", ee_ext, "requireExplicitPolicy:0 but the leaf has no certificatePolicies", verify_extra=("-policy_check", "-explicit_policy"))
    case("inhibit_any_policy", ca_ext + "inhibitAnyPolicy=critical,0\ncertificatePolicies=1.3.6.1.4.1.99999.1.1\n", ee_ext.replace("basicConstraints=CA:FALSE\n", "basicConstraints=CA:FALSE\ncertificatePolicies=2.5.29.32.0\n"), "inhibitAnyPolicy:0 in CA, leaf asserts only anyPolicy; fails when an explicit policy is required", verify_extra=("-policy_check", "-explicit_policy", "-policy", "1.3.6.1.4.1.99999.1.1"))
    case("eku_ca_restricts", ca_ext + "extendedKeyUsage=emailProtection\n", ee_ext, "CA EKU emailProtection only; leaf serverAuth (RFC 5280 does not chain EKU, CABF/Microsoft/Chrome do)", verify_extra=("-purpose", "sslserver"))
    case("unknown_critical_ext_in_intermediate", ca_ext + "1.3.6.1.4.1.99999.9.5=critical,ASN1:UTF8String:critical unknown in CA\n", ee_ext, "intermediate carries an unrecognised critical extension")
    case("leaf_ca_true", ca_ext, "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n", "leaf is itself a CA certificate presented as end entity (fails -purpose sslserver)", verify_extra=("-purpose", "sslserver"))
    case("leaf_key_usage_no_digital_signature", ca_ext, "basicConstraints=CA:FALSE\nkeyUsage=critical,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pv.example.com\n", "EC leaf with keyUsage keyEncipherment only (incompatible with ECDSA; TLS 1.3 needs digitalSignature)")

    # name chaining broken: leaf issuer name does not match intermediate subject
    inter = issue("pv_namechain_int", ik, "/CN=Real Intermediate", rc, rk, ca_ext, days=3000)
    leaf = issue("pv_namechain_leaf", lk, "/CN=pv.example.com", inter, ik, ee_ext)
    der = pem_to_der(leaf.read_bytes())

    def swap_issuer(cert, tbs, alg, sig):
        idx = tbs_index(tbs)
        tbs.children[idx["issuer"]] = parse(pem_to_der(rc.read_bytes()))[0][0][tbs_index(parse(pem_to_der(rc.read_bytes()))[0][0])["subject"]]

    bad = WORK / "pv_namechain_leaf_bad.pem"
    bad.write_bytes(der_to_pem(mutate(der, swap_issuer)))
    publish(inter, "path_violations/issuer_name_mismatch/intermediate.pem", "cert", "parse", "name chaining: real intermediate", chain=[root_rel])
    publish(bad, "path_violations/issuer_name_mismatch/leaf.pem", "cert", "parse-only", "leaf issuer name replaced by the root's name, so it chains by name to the root but the signature is the intermediate's (signature check fails against root, name check fails against intermediate)", chain=["path_violations/issuer_name_mismatch/intermediate.pem", root_rel], openssl_verify=openssl_verify(bad, [inter], rc))

    # signature made by a different key than the claimed issuer
    other_k = genkey("pv_wrongkey", "EC", "ec_paramgen_curve:P-256")
    imp_src = issue("pv_wrongkey_leaf_src", lk, "/CN=pv.example.com", inter, ik, ee_ext)
    imp = WORK / "pv_wrongkey_leaf.pem"
    imp.write_bytes(der_to_pem(resign(pem_to_der(imp_src.read_bytes()), lambda *a: None, other_k)))  # re-signed with an unrelated key
    publish(imp, "path_violations/signature_wrong_key/leaf.pem", "cert", "parse-only", "issuer name and AKID match the intermediate but the signature was made with an unrelated key", chain=["path_violations/issuer_name_mismatch/intermediate.pem", root_rel], openssl_verify=openssl_verify(imp, [inter], rc))

    # AKID that does not match issuer's SKID
    akid_ext = ee_ext.replace("authorityKeyIdentifier=keyid\n", "") + "authorityKeyIdentifier=none\n"
    akl = issue("pv_akid_leaf", lk, "/CN=pv.example.com", inter, ik, ee_ext)
    der = pem_to_der(akl.read_bytes())

    def flip_akid(cert, tbs, alg, sig):
        idx = tbs_index(tbs)
        for ext in tbs[idx["extensions"]][0].children:
            if ext[0].value == bytes.fromhex("551d23"):  # authorityKeyIdentifier
                v = bytearray(ext.children[-1].value)
                v[-1] ^= 0xFF
                ext.children[-1].value = bytes(v)

    akbad = WORK / "pv_akid_bad.pem"
    akbad.write_bytes(der_to_pem(mutate(der, flip_akid)))
    publish(akbad, "path_violations/akid_mismatch/leaf.pem", "cert", "parse-only", "authorityKeyIdentifier keyIdentifier last byte flipped: does not match issuer SKID (signature is now also invalid since TBS changed)", chain=["path_violations/issuer_name_mismatch/intermediate.pem", root_rel], openssl_verify=openssl_verify(akbad, [inter], rc))

    # self-signed but not self-consistent: issuer==subject, signature by another key
    ss_k = genkey("pv_selfsigned", "EC", "ec_paramgen_curve:P-256")
    ss = self_signed("pv_selfsigned_ok", ss_k, "/CN=Self Signed Test")
    fake = WORK / "pv_selfsigned_fake.pem"
    fake.write_bytes(der_to_pem(resign(pem_to_der(ss.read_bytes()), lambda *a: None, other_k)))  # same TBS, signed with other_k
    publish(ss, "path_violations/self_signed_wrong_key/self_signed_good.pem", "cert", "parse", "genuine self-signed certificate", self_signed=True)
    publish(fake, "path_violations/self_signed_wrong_key/self_signed_bad_signature.pem", "cert", "parse-only", "issuer == subject and SPKI is the subject's key, but the signature was made with a different key (self-signature verification must fail)", self_signed=True, openssl_verify=openssl_verify(fake, [], fake, "-check_ss_sig"))


def section_crls(roots, chains) -> None:
    """CRLs via `openssl ca` against the RSA chain intermediate."""
    ca_c, ca_k = chains["rsa"]["int"], chains["rsa"]["int_key"]
    cadir = WORK / "cadb"
    cadir.mkdir(exist_ok=True)
    (cadir / "index.txt").write_text("")
    (cadir / "index.txt.attr").write_text("unique_subject = no\n")
    (cadir / "crlnumber").write_text("1000\n")
    (cadir / "serial").write_text("01\n")
    cnf = WORK / "ca.cnf"

    def write_ca_cnf(crl_ext: bool, md="sha256"):
        cnf.write_text(
            f"[ca]\ndefault_ca = CA\n[CA]\ndir = {cadir}\ndatabase = $dir/index.txt\nnew_certs_dir = $dir\nserial = $dir/serial\n"
            + ("crlnumber = $dir/crlnumber\n" if crl_ext else "")
            + f"certificate = {ca_c}\nprivate_key = {ca_k}\ndefault_md = {md}\ndefault_crl_days = 30\npolicy = pol\n"
            + ("crl_extensions = crl_ext\n" if crl_ext else "")
            + "[pol]\ncommonName = supplied\n[crl_ext]\nauthorityKeyIdentifier=keyid:always\nissuerAltName=DNS:crl-issuer.example.com\n"
        )

    write_ca_cnf(True)
    empty = WORK / "crl_empty.pem"
    run("ca", "-config", str(cnf), "-gencrl", "-out", str(empty))
    publish(empty, "crls/crl_v2_empty.pem", "crl", "parse", "v2 CRL with no revoked certificates (no revokedCertificates field), crlNumber + AKID + issuerAltName")
    publish(empty, "crls/crl_v2_empty.der", "crl", "parse", "same, DER", der=True)

    # revoke a few leaves with different reasons
    reasons = [("keyCompromise", "20250115120000Z"), ("CACompromise", None), ("affiliationChanged", None), ("superseded", None), ("cessationOfOperation", None), ("certificateHold", None), ("removeFromCRL", None), ("unspecified", None)]
    lk = genkey("crl_leaf", "EC", "ec_paramgen_curve:P-256")
    revoked_leaf = None
    for i, (reason, comp) in enumerate(reasons):
        c = issue(f"crl_victim{i}", lk, f"/CN=victim{i}.example.com", ca_c, ca_k, "basicConstraints=CA:FALSE\n")
        args = ["ca", "-config", str(cnf), "-revoke", str(c), "-crl_reason", reason]
        if comp:
            args += ["-crl_compromise", comp]
        run(*args)
        if i == 0:
            revoked_leaf = c
    c = issue("crl_victim_plain", lk, "/CN=victim-plain.example.com", ca_c, ca_k, "basicConstraints=CA:FALSE\n")
    run("ca", "-config", str(cnf), "-revoke", str(c))  # no reason code
    full = WORK / "crl_full.pem"
    run("ca", "-config", str(cnf), "-gencrl", "-out", str(full))
    publish(full, "crls/crl_v2_ten_entries_all_reasons.pem", "crl", "parse", "v2 CRL with 9 entries: every CRLReason value openssl ca can emit (0-6, 8), one invalidityDate, one entry without extensions")
    publish(full, "crls/crl_v2_ten_entries_all_reasons.der", "crl", "parse", "same, DER", der=True)
    publish(revoked_leaf, "crls/revoked_leaf.pem", "cert", "parse-only", "leaf revoked (keyCompromise) in crl_v2_ten_entries_all_reasons", chain=["chains/rsa/intermediate.pem", "chains/rsa/root.pem"],
            openssl_verify=openssl_verify(revoked_leaf, [ca_c], chains["rsa"]["root"], "-crl_check", "-CRLfile", str(full)))
    # v1 CRL (no extensions at all)
    write_ca_cnf(False)
    v1 = WORK / "crl_v1.pem"
    run("ca", "-config", str(cnf), "-gencrl", "-out", str(v1))
    publish(v1, "crls/crl_v1_no_extensions.pem", "crl", "parse", "v1 CRL: no version field, no CRL extensions, entries still carry reason codes")
    # weak digest / long-lived CRL / GeneralizedTime
    write_ca_cnf(True, md="sha1")
    sha1crl = WORK / "crl_sha1.pem"
    run("ca", "-config", str(cnf), "-gencrl", "-out", str(sha1crl))
    publish(sha1crl, "crls/crl_v2_sha1.pem", "crl", "parse-only", "CRL signed with sha1WithRSAEncryption")
    write_ca_cnf(True)
    long_crl = WORK / "crl_long.pem"
    run("ca", "-config", str(cnf), "-gencrl", "-crldays", "9000", "-out", str(long_crl))
    publish(long_crl, "crls/crl_v2_nextupdate_generalizedtime.pem", "crl", "parse", "nextUpdate ~24 years out, so it is a GeneralizedTime (year >= 2050)")
    # CRLs signed with other algorithms via ad-hoc CA dirs
    for tag, alg_md in (("ec", "sha384"), ("ed25519", None), ("mldsa", None)):
        ic, ik = chains[tag]["int"], chains[tag]["int_key"]
        d = WORK / f"cadb_{tag}"
        d.mkdir(exist_ok=True)
        (d / "index.txt").write_text("")
        (d / "crlnumber").write_text("01\n")
        c2 = WORK / f"ca_{tag}.cnf"
        c2.write_text(f"[ca]\ndefault_ca = CA\n[CA]\ndir = {d}\ndatabase = $dir/index.txt\nnew_certs_dir = $dir\nserial = $dir/serial\ncrlnumber = $dir/crlnumber\ncertificate = {ic}\nprivate_key = {ik}\ndefault_md = {alg_md or 'default'}\ndefault_crl_days = 30\npolicy = pol\ncrl_extensions = crl_ext\n[pol]\ncommonName = supplied\n[crl_ext]\nauthorityKeyIdentifier=keyid:always\n")
        run("ca", "-config", str(c2), "-revoke", str(chains[tag]["leaf"]), "-crl_reason", "superseded")
        p = WORK / f"crl_{tag}.pem"
        run("ca", "-config", str(c2), "-gencrl", "-out", str(p))
        publish(p, f"crls/crl_v2_{tag}.pem", "crl", "parse", f"CRL signed by the {tag} chain intermediate, revoking chains/{tag}/leaf.pem", chain=[f"chains/{tag}/intermediate.pem", f"chains/{tag}/root.pem"])
    # CRL with broken signature
    der = pem_to_der(full.read_bytes(), "X509 CRL")
    b = bytearray(der)
    b[-1] ^= 0x01
    bad = OUT / "crls/crl_v2_bad_signature.der"
    bad.write_bytes(bytes(b))
    record("crls/crl_v2_bad_signature.der", "crl", "parse-only", "last signature byte flipped: parses, signature verification must fail", openssl=openssl_parse_result(bad, "crl"))
    # CRL issued by the wrong CA (name says rsa intermediate, signed by ec intermediate)
    # -> simplest: take the rsa CRL and replace signature with the ec CRL's; mark as parse-only
    ec_der = pem_to_der((WORK / "crl_ec.pem").read_bytes(), "X509 CRL")
    crl_node, _ = parse(der)
    ec_node, _ = parse(ec_der)
    crl_node.children[1] = ec_node[1]
    crl_node.children[2] = ec_node[2]
    wrong = OUT / "crls/crl_v2_signature_from_other_issuer.der"
    wrong.write_bytes(crl_node.encode())
    record("crls/crl_v2_signature_from_other_issuer.der", "crl", "parse-only", "TBSCertList of the RSA CRL with the ECDSA signature (and outer signatureAlgorithm) of another CRL: algorithm mismatch between tbs.signature and outer signatureAlgorithm", openssl=openssl_parse_result(wrong, "crl"))


def section_csrs(roots) -> None:
    k = genkey("csr_key", "EC", "ec_paramgen_curve:P-256")
    c = csr("csr_basic", k, "/C=XX/O=Org/CN=csr.example.com")
    publish(c, "csr/csr_ecp256_basic.pem", "csr", "parse", "PKCS#10 request, P-256, no attributes")
    cnf = WORK / "csr_ext.cnf"
    cnf.write_text("[req]\ndistinguished_name=dn\nprompt=no\nreq_extensions=v3\n[dn]\nCN=csr-ext.example.com\n[v3]\nsubjectAltName=DNS:csr-ext.example.com,DNS:www.csr-ext.example.com\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")
    c2 = WORK / "csr_ext.csr"
    run("req", "-new", "-key", str(k), "-config", str(cnf), "-out", str(c2))
    publish(c2, "csr/csr_ecp256_with_extension_request.pem", "csr", "parse", "PKCS#10 with extensionRequest attribute (SAN, KU, EKU)")
    publish(c2, "csr/csr_ecp256_with_extension_request.der", "csr", "parse", "same, DER", der=True)
    rk = roots["rsa2048_sha256"][1]
    c3 = csr("csr_rsa", rk, "/CN=csr-rsa.example.com", extra=["-sha256"])
    publish(c3, "csr/csr_rsa2048_sha256.pem", "csr", "parse", "PKCS#10 RSA-2048 sha256WithRSAEncryption")
    mk = roots["mldsa44"][1]
    c4 = csr("csr_mldsa", mk, "/CN=csr-mldsa.example.com")
    publish(c4, "csr/csr_mldsa44.pem", "csr", "parse", "PKCS#10 signed with ML-DSA-44")


def section_malformed(roots, chains) -> None:
    """DER-level damage applied to a known-good leaf."""
    good = chains["ec"]["leaf"]
    root_der = pem_to_der(chains["ec"]["root"].read_bytes())
    der = pem_to_der(good.read_bytes())
    shutil.copy(good, OUT / "malformed/../chains/ec/leaf.pem") if False else None
    cases: list[tuple[str, bytes, str, str]] = []

    def add(name, data, reason, expect="reject"):
        cases.append((name, data, reason, expect))

    add("truncated_half", der[: len(der) // 2], "certificate cut in half")
    add("truncated_last_byte", der[:-1], "last byte of signature missing (outer length now exceeds data)")
    add("truncated_after_tbs", der[: 4 + 4 + int.from_bytes(der[6:8], "big")] if der[5] == 0x82 else der[:100], "TBSCertificate only, no signatureAlgorithm/signatureValue")
    add("trailing_garbage", der + b"\x00\x01\x02\x03", "four trailing bytes after the outer SEQUENCE")
    add("trailing_zero", der + b"\x00", "single trailing NUL byte")
    add("empty", b"", "zero-length input")
    add("just_sequence_header", b"\x30\x00", "SEQUENCE with zero length")
    add("only_tag", b"\x30", "a lone SEQUENCE tag with no length")
    add("random_bytes_256", bytes(range(256)), "256 non-DER bytes")

    def outer_len(force):
        return der[:1] + force + der[1 + (1 + (der[1] & 0x7F) if der[1] & 0x80 else 1) :]

    body_len = len(der) - 4
    add("outer_length_too_long", outer_len(bytes([0x82]) + (body_len + 10).to_bytes(2, "big")), "outer SEQUENCE length claims 10 more bytes than present")
    add("outer_length_too_short", outer_len(bytes([0x82]) + (body_len - 10).to_bytes(2, "big")), "outer SEQUENCE length 10 bytes short (leaves trailing data)")
    add("outer_length_indefinite", b"\x30\x80" + der[4:] + b"\x00\x00", "outer SEQUENCE with BER indefinite length (0x80 ... 00 00) - not DER")
    add("outer_length_long_form_non_minimal", b"\x30\x83\x00" + body_len.to_bytes(2, "big") + der[4:], "length encoded in 3 octets where 2 suffice (non-minimal, not DER)")
    add("outer_length_0x80_0xff", b"\x30\x84\xff\xff\xff\xff" + der[4:], "length field 0xFFFFFFFF (integer overflow probe)")
    add("outer_length_5_octets", b"\x30\x85\x00\x00\x00" + body_len.to_bytes(2, "big") + der[4:], "5-octet length field")
    add("outer_tag_set", b"\x31" + der[1:], "outer tag is SET (0x31) instead of SEQUENCE")
    add("outer_tag_primitive_sequence", b"\x10" + der[1:], "SEQUENCE tag without the constructed bit (0x10)")
    add("outer_tag_high_tag_number", b"\x3f\x10" + der[1:], "high-tag-number form 0x3F 0x10 for SEQUENCE")

    def m(fn):
        return mutate(der, fn)

    # version field
    def version_set(v):
        def f(cert, tbs, alg, sig):
            tbs[0].children[0].value = bytes([v])
        return f

    add("version_v2_with_extensions", m(version_set(1)), "version = 1 (v2) although extensions are present (RFC 5280: version MUST be 3)", "parse-only")
    add("version_v1_explicit_with_extensions", m(version_set(0)), "explicit version = 0 (v1) with extensions present; DER also forbids encoding the DEFAULT value", "parse-only")
    add("version_v4", m(version_set(3)), "version = 3 (v4) - undefined")
    add("version_v255", m(version_set(255)), "version INTEGER 255 (encoded 00 FF)")

    def version_negative(cert, tbs, alg, sig):
        tbs[0].children[0].value = b"\xff"

    add("version_negative", m(version_negative), "version = -1")

    def version_two_bytes(cert, tbs, alg, sig):
        tbs[0].children[0].value = b"\x00\x02"

    add("version_non_minimal_integer", m(version_two_bytes), "version INTEGER 2 encoded as 00 02 (non-minimal, not DER)")

    def version_tag_wrong(cert, tbs, alg, sig):
        tbs[0].tag = 0xA1

    add("version_wrong_context_tag", m(version_tag_wrong), "version wrapped in [1] instead of [0]")

    def drop_version(cert, tbs, alg, sig):
        tbs.children.pop(0)

    add("version_absent_with_extensions", m(drop_version), "version field absent (implies v1) but extensions [3] present", "parse-only")

    # serial number
    def serial_set(b):
        def f(cert, tbs, alg, sig):
            tbs[tbs_index(tbs)["serial"]].value = b
        return f

    add("serial_empty", m(serial_set(b"")), "serialNumber INTEGER with zero-length content")
    add("serial_non_minimal_leading_zero", m(serial_set(b"\x00\x7f")), "serialNumber 0x7F encoded as 00 7F (non-minimal, not DER)")
    add("serial_non_minimal_leading_ff", m(serial_set(b"\xff\x80")), "negative serial -128 encoded as FF 80 (non-minimal, not DER)")
    add("serial_1000_bytes", m(serial_set(b"\x01" + b"\x00" * 999)), "1000-octet serialNumber", "parse-only")

    def serial_tag_octet(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["serial"]].tag = 0x04

    add("serial_tag_octet_string", m(serial_tag_octet), "serialNumber encoded as OCTET STRING instead of INTEGER")

    # algorithm identifiers
    def alg_mismatch(cert, tbs, alg, sig):
        # inner tbs.signature says sha384; outer stays sha256
        tbs[tbs_index(tbs)["sigalg"]].children[0].value = bytes.fromhex("2a8648ce3d040303")  # ecdsa-with-SHA384

    add("sigalg_inner_outer_mismatch", m(alg_mismatch), "tbs.signature (ecdsa-with-SHA384) differs from outer signatureAlgorithm (ecdsa-with-SHA256) - RFC 5280 §4.1.1.2 MUST match", "parse-only")

    def alg_outer_null_params(cert, tbs, alg, sig):
        alg.children.append(Node(0x05, b""))

    add("sigalg_ecdsa_with_null_params", m(alg_outer_null_params), "outer ecdsa-with-SHA256 AlgorithmIdentifier with explicit NULL parameters (RFC 5758: MUST be absent)", "parse-only")

    def alg_unknown_oid(cert, tbs, alg, sig):
        alg.children[0].value = bytes.fromhex("2b0601040181e6070101")
        tbs[tbs_index(tbs)["sigalg"]].children[0].value = bytes.fromhex("2b0601040181e6070101")

    add("sigalg_unknown_oid", m(alg_unknown_oid), "signature algorithm OID from a private arc (1.3.6.1.4.1.99999.1.1)", "parse-only")

    def alg_oid_empty(cert, tbs, alg, sig):
        alg.children[0].value = b""

    add("sigalg_oid_empty", m(alg_oid_empty), "OBJECT IDENTIFIER with zero-length content")

    def alg_oid_nonminimal(cert, tbs, alg, sig):
        alg.children[0].value = b"\x80" + alg.children[0].value

    add("sigalg_oid_leading_0x80", m(alg_oid_nonminimal), "OID sub-identifier with a leading 0x80 octet (non-minimal base-128, not DER)")

    def alg_oid_unterminated(cert, tbs, alg, sig):
        alg.children[0].value = alg.children[0].value[:-1] + bytes([alg.children[0].value[-1] | 0x80])

    add("sigalg_oid_unterminated", m(alg_oid_unterminated), "OID whose final sub-identifier octet has the continuation bit set")

    def alg_oid_huge_arc(cert, tbs, alg, sig):
        alg.children[0].value = b"\x2a" + b"\xff" * 12 + b"\x7f"

    add("sigalg_oid_arc_overflow", m(alg_oid_huge_arc), "OID with an 91-bit sub-identifier (overflows 64-bit arcs)", "parse-only")

    def alg_extra_element(cert, tbs, alg, sig):
        alg.children.append(Node(0x02, b"\x01"))

    add("sigalg_extra_integer", m(alg_extra_element), "AlgorithmIdentifier with a trailing INTEGER after parameters")

    def alg_empty(cert, tbs, alg, sig):
        alg.children.clear()

    add("sigalg_empty_sequence", m(alg_empty), "outer signatureAlgorithm is an empty SEQUENCE")

    # names
    def issuer_empty(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["issuer"]].children.clear()

    add("issuer_empty", m(issuer_empty), "issuer Name is an empty SEQUENCE (RFC 5280: issuer MUST be non-empty)", "parse-only")

    def rdn_empty_set(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["subject"]].children.append(Node(0x31, b"", []))

    add("subject_rdn_empty_set", m(rdn_empty_set), "subject contains an RDN that is an empty SET (SIZE (1..MAX) violated)")

    def rdn_not_set(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["subject"]].children[0].tag = 0x30

    add("subject_rdn_sequence_instead_of_set", m(rdn_not_set), "RelativeDistinguishedName encoded as SEQUENCE rather than SET")

    def atv_missing_value(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["subject"]].children[0].children[0].children.pop()

    add("subject_atv_missing_value", m(atv_missing_value), "AttributeTypeAndValue with only the type OID")

    def cn_with_nul(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        for rdn in subj.children:
            atv = rdn.children[0]
            if atv.children[0].value == bytes.fromhex("550403"):
                atv.children[1].value = b"www.good.example\x00.evil.example"

    add("subject_cn_embedded_nul", m(cn_with_nul), "CN contains an embedded NUL byte (classic hostname-truncation attack); signature no longer valid", "parse-only")

    def cn_invalid_utf8(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        for rdn in subj.children:
            atv = rdn.children[0]
            if atv.children[0].value == bytes.fromhex("550403"):
                atv.children[1].tag = 0x0C
                atv.children[1].value = b"bad\xff\xfe utf8"

    add("subject_cn_invalid_utf8", m(cn_invalid_utf8), "UTF8String CN containing invalid UTF-8 sequences")

    def cn_printable_bad_chars(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        for rdn in subj.children:
            atv = rdn.children[0]
            if atv.children[0].value == bytes.fromhex("550403"):
                atv.children[1].tag = 0x13
                atv.children[1].value = b"not@printable_chars!"

    add("subject_cn_printablestring_illegal_chars", m(cn_printable_bad_chars), "PrintableString containing @, _ and ! which are outside the PrintableString repertoire", "parse-only")

    def cn_universal_string(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        for rdn in subj.children:
            atv = rdn.children[0]
            if atv.children[0].value == bytes.fromhex("550403"):
                atv.children[1].tag = 0x1C
                atv.children[1].value = "univ".encode("utf-32-be")

    add("subject_cn_universalstring", m(cn_universal_string), "CN as UniversalString (UTF-32BE) - legal DirectoryString choice rarely supported", "parse-only")

    def cn_bmp_odd_length(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        for rdn in subj.children:
            atv = rdn.children[0]
            if atv.children[0].value == bytes.fromhex("550403"):
                atv.children[1].tag = 0x1E
                atv.children[1].value = b"\x00a\x00b\x00"

    add("subject_cn_bmpstring_odd_length", m(cn_bmp_odd_length), "BMPString with an odd number of octets")

    def cn_ia5_high_bit(cert, tbs, alg, sig):
        subj = tbs[tbs_index(tbs)["subject"]]
        for rdn in subj.children:
            atv = rdn.children[0]
            if atv.children[0].value == bytes.fromhex("550403"):
                atv.children[1].tag = 0x16
                atv.children[1].value = b"ia5\xe9"

    add("subject_cn_ia5string_high_bit", m(cn_ia5_high_bit), "IA5String CN with an octet >= 0x80", "parse-only")

    def rdn_set_unsorted(cert, tbs, alg, sig):
        # build a multi-valued RDN with elements deliberately out of DER order
        a = Node(0x30, b"", [Node(0x06, bytes.fromhex("55040b")), Node(0x0C, b"zzz")])  # OU=zzz (longer OID first)
        b = Node(0x30, b"", [Node(0x06, bytes.fromhex("550403")), Node(0x0C, b"aaa")])  # CN=aaa
        tbs[tbs_index(tbs)["subject"]].children.append(Node(0x31, b"", [a, b]))

    add("subject_multivalued_rdn_unsorted_set", m(rdn_set_unsorted), "multi-valued RDN SET whose elements are not in DER canonical order (BER, not DER)", "parse-only")

    # validity
    def time_set(which, tag, val):
        def f(cert, tbs, alg, sig):
            v = tbs[tbs_index(tbs)["validity"]]
            v.children[which].tag = tag
            v.children[which].value = val
        return f

    add("utctime_no_seconds", m(time_set(0, 0x17, b"2001010000Z")), "UTCTime YYMMDDHHMMZ without seconds (X.680 allows, RFC 5280 requires seconds)", "parse-only")
    add("utctime_with_offset", m(time_set(0, 0x17, b"200101000000+0100")), "UTCTime with +0100 offset instead of Z (RFC 5280 MUST use Z)", "parse-only")
    add("utctime_lowercase_z", m(time_set(0, 0x17, b"200101000000z")), "UTCTime terminated with lowercase z")
    add("utctime_invalid_month", m(time_set(0, 0x17, b"201301000000Z")), "UTCTime month 13")
    add("utctime_feb_30", m(time_set(0, 0x17, b"200230000000Z")), "UTCTime 30 February")
    add("utctime_hour_24", m(time_set(0, 0x17, b"200101240000Z")), "UTCTime hour 24")
    add("utctime_second_60", m(time_set(0, 0x17, b"200101000060Z")), "UTCTime leap second 60 (not permitted)")
    add("utctime_for_2050", m(time_set(1, 0x17, b"500101000000Z")), "notAfter 2050 encoded as UTCTime (must be GeneralizedTime; UTCTime 50 means 1950)", "parse-only")
    add("generalizedtime_for_2030", m(time_set(1, 0x18, b"20300101000000Z")), "notAfter 2030 encoded as GeneralizedTime (RFC 5280: dates before 2050 MUST use UTCTime)", "parse-only")
    add("generalizedtime_fractional_seconds", m(time_set(1, 0x18, b"20300101000000.5Z")), "GeneralizedTime with fractional seconds (RFC 5280 forbids)", "parse-only")
    add("generalizedtime_no_seconds", m(time_set(1, 0x18, b"203001010000Z")), "GeneralizedTime without seconds")
    add("generalizedtime_local_time", m(time_set(1, 0x18, b"20300101000000")), "GeneralizedTime without Z (local time)")
    add("time_wrong_tag_octet_string", m(time_set(0, 0x04, b"200101000000Z")), "notBefore encoded as OCTET STRING")
    add("time_empty", m(time_set(0, 0x17, b"")), "empty UTCTime")
    add("time_non_digit", m(time_set(0, 0x17, b"20010100000AZ")), "UTCTime with a non-digit character")

    def validity_three_elements(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["validity"]].children.append(Node(0x17, b"300101000000Z"))

    add("validity_three_times", m(validity_three_elements), "Validity SEQUENCE with three time elements")

    # SPKI
    def spki_param_null_ec(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[0].children[1] = Node(0x05, b"")

    add("spki_ec_params_null", m(spki_param_null_ec), "id-ecPublicKey with NULL parameters instead of namedCurve")

    def spki_ec_params_absent(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[0].children.pop()

    add("spki_ec_params_absent", m(spki_ec_params_absent), "id-ecPublicKey without parameters (RFC 5480: MUST be present)")

    def spki_ec_unknown_curve(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[0].children[1].value = bytes.fromhex("2b0601040181e60702")

    add("spki_ec_unknown_curve_oid", m(spki_ec_unknown_curve), "namedCurve OID from a private arc", "parse-only")

    def spki_ec_point_flip(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        v = bytearray(spki.children[1].value)
        v[-1] ^= 0x01
        spki.children[1].value = bytes(v)

    add("spki_ec_point_not_on_curve", m(spki_ec_point_flip), "last byte of the P-256 point flipped: point is not on the curve", "parse-only")

    def spki_ec_point_infinity(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = b"\x00\x00"

    add("spki_ec_point_at_infinity", m(spki_ec_point_infinity), "EC public key encoded as the point at infinity (single 0x00)")

    def spki_ec_point_short(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = spki.children[1].value[:-1]

    add("spki_ec_point_truncated", m(spki_ec_point_short), "uncompressed P-256 point one byte short")

    def spki_ec_point_hybrid(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        v = bytearray(spki.children[1].value)
        v[1] = 0x06 if (v[-1] & 1) == 0 else 0x07
        spki.children[1].value = bytes(v)

    add("spki_ec_point_hybrid_form", m(spki_ec_point_hybrid), "EC point in hybrid form (0x06/0x07 prefix) - X9.62 legal, PKIX implementations MUST NOT accept? (RFC 5480 says hybrid SHOULD NOT be used)", "parse-only")

    def spki_bitstring_unused_bits(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = b"\x03" + spki.children[1].value[1:]

    add("spki_bitstring_unused_bits_nonzero", m(spki_bitstring_unused_bits), "subjectPublicKey BIT STRING claims 3 unused bits (must be 0 for a key octet string)")

    def spki_bitstring_unused_bits_8(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = b"\x08" + spki.children[1].value[1:]

    add("spki_bitstring_unused_bits_8", m(spki_bitstring_unused_bits_8), "BIT STRING initial octet 8 (must be 0..7)")

    def spki_bitstring_empty(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = b""

    add("spki_bitstring_empty", m(spki_bitstring_empty), "subjectPublicKey BIT STRING with no content at all (not even the unused-bits octet)")

    def spki_bitstring_constructed(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        inner = spki.children[1]
        spki.children[1] = Node(0x23, b"", [Node(0x03, inner.value)])

    add("spki_bitstring_constructed", m(spki_bitstring_constructed), "subjectPublicKey as a constructed BIT STRING (BER segmented, not DER)")

    def spki_as_octet_string(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].tag = 0x04
        spki.children[1].value = spki.children[1].value[1:]

    add("spki_key_as_octet_string", m(spki_as_octet_string), "subjectPublicKey encoded as OCTET STRING instead of BIT STRING")

    # RSA-specific SPKI cases built from the RSA root
    rsa_der = pem_to_der(roots["rsa2048_sha256"][0].read_bytes())

    def rmut(fn):
        return mutate(rsa_der, fn)

    def rsa_params_absent(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["spki"]].children[0].children.pop()

    add("spki_rsa_params_absent", rmut(rsa_params_absent), "rsaEncryption AlgorithmIdentifier without the mandatory NULL parameters (RFC 3279 §2.3.1)", "parse-only")

    def rsa_params_empty_seq(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["spki"]].children[0].children[1] = Node(0x30, b"", [])

    add("spki_rsa_params_empty_sequence", rmut(rsa_params_empty_seq), "rsaEncryption with an empty SEQUENCE as parameters")

    def rsa_key(fn):
        def f(cert, tbs, alg, sig):
            spki = tbs[tbs_index(tbs)["spki"]]
            bs = spki.children[1].value
            key, _ = parse(bs[1:])
            fn(key)
            spki.children[1].value = b"\x00" + key.encode()
        return f

    def mod_even(k):
        v = bytearray(k[0].value)
        v[-1] &= 0xFE
        k[0].value = bytes(v)

    add("spki_rsa_modulus_even", rmut(rsa_key(mod_even)), "RSA modulus made even (invalid key; signature cannot verify)", "parse-only")

    def mod_negative(k):
        k[0].value = k[0].value[1:] if k[0].value[0] == 0 else k[0].value

    add("spki_rsa_modulus_negative", rmut(rsa_key(mod_negative)), "RSA modulus leading 0x00 stripped so the INTEGER is negative")

    def mod_leading_zeros(k):
        k[0].value = b"\x00\x00" + k[0].value[1:]

    add("spki_rsa_modulus_non_minimal", rmut(rsa_key(mod_leading_zeros)), "RSA modulus INTEGER with two leading zero octets (non-minimal, not DER)")

    def exp_one(k):
        k[1].value = b"\x01"

    add("spki_rsa_exponent_1", rmut(rsa_key(exp_one)), "RSA public exponent e = 1", "parse-only")

    def exp_even(k):
        k[1].value = b"\x01\x00\x00"

    add("spki_rsa_exponent_even", rmut(rsa_key(exp_even)), "RSA public exponent e = 65536 (even)", "parse-only")

    def exp_zero(k):
        k[1].value = b"\x00"

    add("spki_rsa_exponent_0", rmut(rsa_key(exp_zero)), "RSA public exponent e = 0", "parse-only")

    def exp_huge(k):
        k[1].value = b"\x01" + b"\x00" * 300

    add("spki_rsa_exponent_2401_bits", rmut(rsa_key(exp_huge)), "RSA public exponent larger than the modulus", "parse-only")

    def key_extra_int(k):
        k.children.append(Node(0x02, b"\x01"))

    add("spki_rsa_key_three_integers", rmut(rsa_key(key_extra_int)), "RSAPublicKey SEQUENCE with a third INTEGER")

    def key_missing_exp(k):
        k.children.pop()

    add("spki_rsa_key_missing_exponent", rmut(rsa_key(key_missing_exp)), "RSAPublicKey with only the modulus")

    def key_not_seq(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = b"\x00\x02\x01\x01"

    add("spki_rsa_key_bare_integer", rmut(key_not_seq), "subjectPublicKey for rsaEncryption holding a bare INTEGER instead of RSAPublicKey")

    def spki_rsa_modulus_1_bit(k):
        k[0].value = b"\x03"

    add("spki_rsa_modulus_tiny", rmut(rsa_key(spki_rsa_modulus_1_bit)), "RSA modulus n = 3", "parse-only")

    # Ed25519-specific
    ed_der = pem_to_der(roots["ed25519"][0].read_bytes())

    def ed_params_null(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["spki"]].children[0].children.append(Node(0x05, b""))

    add("spki_ed25519_params_null", mutate(ed_der, ed_params_null), "id-Ed25519 AlgorithmIdentifier with NULL parameters (RFC 8410: MUST be absent)", "parse-only")

    def ed_key_31(cert, tbs, alg, sig):
        spki = tbs[tbs_index(tbs)["spki"]]
        spki.children[1].value = spki.children[1].value[:-1]

    add("spki_ed25519_key_31_bytes", mutate(ed_der, ed_key_31), "Ed25519 public key of 31 bytes")

    def ed_sig_63(cert, tbs, alg, sig):
        sig.value = sig.value[:-1]

    add("sig_ed25519_63_bytes", mutate(ed_der, ed_sig_63), "Ed25519 signature of 63 bytes", "parse-only")

    def ed_sig_null_params(cert, tbs, alg, sig):
        alg.children.append(Node(0x05, b""))
        tbs[tbs_index(tbs)["sigalg"]].children.append(Node(0x05, b""))

    add("sigalg_ed25519_null_params", mutate(ed_der, ed_sig_null_params), "Ed25519 signature AlgorithmIdentifier with NULL parameters in both places", "parse-only")

    # extensions
    def ext_dup(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        exts.children.append(exts.children[0])

    add("ext_duplicate", m(ext_dup), "the first extension appears twice (RFC 5280: a certificate MUST NOT include more than one instance of a particular extension)", "parse-only")

    def ext_empty_seq(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["extensions"]][0].children.clear()

    add("ext_empty_sequence", m(ext_empty_seq), "Extensions SEQUENCE present but empty (SIZE (1..MAX) violated)")

    def ext_bool_01(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if len(e.children) == 3:
                e.children[1].value = b"\x01"
                return
        # add a critical flag with bad boolean to the first extension
        e = exts.children[0]
        e.children.insert(1, Node(0x01, b"\x01"))

    add("ext_critical_boolean_0x01", m(ext_bool_01), "critical BOOLEAN TRUE encoded as 0x01 instead of 0xFF (BER, not DER)")

    def ext_bool_false_explicit(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        e = exts.children[0]
        if len(e.children) == 2:
            e.children.insert(1, Node(0x01, b"\x00"))

    add("ext_critical_false_explicit", m(ext_bool_false_explicit), "critical FALSE encoded explicitly (DER forbids encoding DEFAULT values)")

    def ext_value_not_octet(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        exts.children[0].children[-1].tag = 0x30

    add("ext_value_not_octet_string", m(ext_value_not_octet), "extnValue tagged SEQUENCE instead of OCTET STRING")

    def ext_value_garbage(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d13"):  # basicConstraints
                e.children[-1].value = b"\xff\xfe\xfd"

    add("ext_basic_constraints_garbage", m(ext_value_garbage), "basicConstraints extnValue holds non-DER bytes", "parse-only")

    def ext_bc_trailing(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d13"):
                e.children[-1].value = e.children[-1].value + b"\x00"

    add("ext_basic_constraints_trailing_byte", m(ext_bc_trailing), "trailing byte after the BasicConstraints SEQUENCE inside extnValue", "parse-only")

    def ext_bc_ca_true_bool_01(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d13"):
                e.children[-1].value = bytes.fromhex("3003010101")  # SEQUENCE { BOOLEAN 0x01 }

    add("ext_basic_constraints_ca_boolean_0x01", m(ext_bc_ca_true_bool_01), "BasicConstraints cA TRUE encoded as 0x01 (accepted by many, not DER)", "parse-only")

    def ext_bc_pathlen_negative(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d13"):
                e.children[-1].value = bytes.fromhex("30060101ff0201ff")  # cA TRUE, pathLen -1

    add("ext_basic_constraints_pathlen_negative", m(ext_bc_pathlen_negative), "BasicConstraints pathLenConstraint = -1", "parse-only")

    def ext_ku_trailing_zero_bits(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d0f"):  # keyUsage
                e.children[-1].value = bytes.fromhex("03030780" + "00")  # digitalSignature with an extra all-zero octet, unused bits 7
                return
        exts.children.append(Node(0x30, b"", [Node(0x06, bytes.fromhex("551d0f")), Node(0x01, b"\xff"), Node(0x04, bytes.fromhex("0303078000"))]))

    add("ext_key_usage_trailing_zero_octet", m(ext_ku_trailing_zero_bits), "KeyUsage BIT STRING with a trailing all-zero octet (DER requires trailing zero bits be removed)", "parse-only")

    def ext_ku_empty_bitstring(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        exts.children.append(Node(0x30, b"", [Node(0x06, bytes.fromhex("551d0f")), Node(0x01, b"\xff"), Node(0x04, bytes.fromhex("030100"))]))

    add("ext_key_usage_no_bits_set", m(ext_ku_empty_bitstring), "critical KeyUsage with zero bits set (RFC 5280: at least one bit MUST be set)", "parse-only")

    def ext_san_empty(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                e.children[-1].value = bytes.fromhex("3000")

    add("ext_san_empty_sequence", m(ext_san_empty), "subjectAltName with an empty GeneralNames SEQUENCE (SIZE (1..MAX))", "parse-only")

    def ext_san_empty_dns(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                e.children[-1].value = bytes.fromhex("30028200")

    add("ext_san_empty_dnsname", m(ext_san_empty_dns), "dNSName of zero length", "parse-only")

    def ext_san_dns_space(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                e.children[-1].value = bytes.fromhex("3003820120")

    add("ext_san_dnsname_single_space", m(ext_san_dns_space), "dNSName consisting of a single space (RFC 5280 says MUST NOT)", "parse-only")

    def ext_san_ip_5_bytes(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                e.children[-1].value = bytes.fromhex("300787050102030405")

    add("ext_san_ipaddress_5_bytes", m(ext_san_ip_5_bytes), "iPAddress of 5 octets (must be 4 or 16 in a SAN)", "parse-only")

    def ext_san_ip_8_bytes(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                e.children[-1].value = bytes.fromhex("300a8708c0000201ffffff00")

    add("ext_san_ipaddress_8_bytes_cidr_in_ee", m(ext_san_ip_8_bytes), "iPAddress with address+mask (8 octets) in a SAN - only legal in nameConstraints", "parse-only")

    def ext_san_unknown_choice(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                e.children[-1].value = bytes.fromhex("3005890378797a")

    add("ext_san_unknown_generalname_tag", m(ext_san_unknown_choice), "GeneralName with context tag [9], which does not exist", "parse-only")

    def ext_san_dns_nul(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                name = b"www.good.example\x00.evil.example"
                e.children[-1].value = bytes([0x30, len(name) + 2, 0x82, len(name)]) + name

    add("ext_san_dnsname_embedded_nul", m(ext_san_dns_nul), "dNSName with embedded NUL", "parse-only")

    def ext_san_dns_non_ia5(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d11"):
                name = "bücher.example".encode()
                e.children[-1].value = bytes([0x30, len(name) + 2, 0x82, len(name)]) + name

    add("ext_san_dnsname_utf8_not_ia5", m(ext_san_dns_non_ia5), "dNSName containing raw UTF-8 (IA5String required; must be A-label)", "parse-only")

    def ext_aki_keyid_empty(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d23"):
                e.children[-1].value = bytes.fromhex("30028000")

    add("ext_akid_empty_keyid", m(ext_aki_keyid_empty), "authorityKeyIdentifier with zero-length keyIdentifier", "parse-only")

    def ext_aki_critical(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for e in exts.children:
            if e.children[0].value == bytes.fromhex("551d23") and len(e.children) == 2:
                e.children.insert(1, Node(0x01, b"\xff"))

    add("ext_akid_marked_critical", m(ext_aki_critical), "authorityKeyIdentifier marked critical (RFC 5280: MUST be non-critical)", "parse-only")

    def ext_oid_ext_short(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        exts.children[0].children[0].value = b"\x55"

    add("ext_oid_single_octet", m(ext_oid_ext_short), "extension OID with a single octet (2.5)", "parse-only")

    def ext_wrap_wrong_tag(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["extensions"]].tag = 0xA4

    add("ext_wrapper_context_tag_4", m(ext_wrap_wrong_tag), "extensions wrapped in [4] instead of [3]")

    def ext_wrap_implicit(cert, tbs, alg, sig):
        e = tbs[tbs_index(tbs)["extensions"]]
        inner = e[0]
        e.children = inner.children

    add("ext_wrapper_implicit_tagging", m(ext_wrap_implicit), "extensions [3] used as IMPLICIT wrapper (the inner SEQUENCE is missing)")

    def ext_nested_bomb(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        payload = b"\x30\x00"
        for _ in range(500):
            payload = b"\x30" + enc_len(len(payload)) + payload
        exts.children.append(Node(0x30, b"", [Node(0x06, bytes.fromhex("2b0601040181e6070905")), Node(0x04, payload)]))

    add("ext_deeply_nested_500", m(ext_nested_bomb), "unknown extension whose value is a SEQUENCE nested 500 deep (recursion probe)", "parse-only")

    def ext_huge_count(cert, tbs, alg, sig):
        exts = tbs[tbs_index(tbs)["extensions"]][0]
        for i in range(2000):
            oid = bytes.fromhex("2b0601040181e60709") + bytes([0x80 | (i >> 7) & 0x7F, i & 0x7F]) if i >= 128 else bytes.fromhex("2b0601040181e60709") + bytes([i])
            exts.children.append(Node(0x30, b"", [Node(0x06, oid), Node(0x04, b"\x05\x00")]))

    add("ext_2000_extensions", m(ext_huge_count), "2000 distinct unknown non-critical extensions", "parse-only")

    # unique identifiers (openssl cannot emit these)
    def add_uids(cert, tbs, alg, sig):
        idx = tbs_index(tbs)
        pos = idx["extensions"]
        tbs.children.insert(pos, Node(0x82, b"\x00" + b"\xbb" * 8))
        tbs.children.insert(pos, Node(0x81, b"\x00" + b"\xaa" * 8))

    add("uids_issuer_and_subject_unique_id", m(add_uids), "issuerUniqueID [1] and subjectUniqueID [2] present (v3 permits; RFC 5280 says CAs MUST NOT generate)", "parse-only")

    def uid_v1(cert, tbs, alg, sig):
        idx = tbs_index(tbs)
        tbs.children.pop(idx["extensions"])
        tbs.children.append(Node(0x82, b"\x00" + b"\xbb" * 8))
        tbs.children.pop(0)

    add("uids_in_v1_certificate", m(uid_v1), "v1 certificate (no version) that carries a subjectUniqueID (requires v2)", "parse-only")

    # signature value
    def sig_flip(cert, tbs, alg, sig):
        v = bytearray(sig.value)
        v[-1] ^= 0x01
        sig.value = bytes(v)

    add("sig_last_bit_flipped", m(sig_flip), "one bit of the ECDSA signature flipped: well-formed, fails verification", "parse-only")

    def sig_unused_bits(cert, tbs, alg, sig):
        sig.value = b"\x04" + sig.value[1:]

    add("sig_bitstring_unused_bits_4", m(sig_unused_bits), "signatureValue BIT STRING claims 4 unused bits")

    def sig_empty(cert, tbs, alg, sig):
        sig.value = b"\x00"

    add("sig_empty", m(sig_empty), "zero-length signature (BIT STRING with only the unused-bits octet)", "parse-only")

    def sig_missing(cert, tbs, alg, sig):
        cert.children.pop()

    add("sig_missing", m(sig_missing), "Certificate SEQUENCE with only tbsCertificate and signatureAlgorithm (RFC 9925 'unsigned certificates' use a different construction)")

    def sig_r_zero(cert, tbs, alg, sig):
        s, _ = parse(sig.value[1:])
        s[0].value = b"\x00"
        sig.value = b"\x00" + s.encode()

    add("sig_ecdsa_r_zero", m(sig_r_zero), "ECDSA-Sig-Value with r = 0", "parse-only")

    def sig_r_negative(cert, tbs, alg, sig):
        s, _ = parse(sig.value[1:])
        if s[0].value[0] == 0:
            s[0].value = s[0].value[1:]
        else:
            s[0].value = bytes([s[0].value[0] | 0x80]) + s[0].value[1:]
        sig.value = b"\x00" + s.encode()

    add("sig_ecdsa_r_negative", m(sig_r_negative), "ECDSA r INTEGER negative (missing 00 pad / high bit set)", "parse-only")

    def sig_r_non_minimal(cert, tbs, alg, sig):
        s, _ = parse(sig.value[1:])
        s[0].value = b"\x00\x00" + s[0].value.lstrip(b"\x00")
        sig.value = b"\x00" + s.encode()

    add("sig_ecdsa_r_non_minimal", m(sig_r_non_minimal), "ECDSA r INTEGER with superfluous leading zeros (BER, not DER)", "parse-only")

    def sig_ecdsa_three_ints(cert, tbs, alg, sig):
        s, _ = parse(sig.value[1:])
        s.children.append(Node(0x02, b"\x01"))
        sig.value = b"\x00" + s.encode()

    add("sig_ecdsa_three_integers", m(sig_ecdsa_three_ints), "ECDSA-Sig-Value SEQUENCE with three INTEGERs", "parse-only")

    def sig_ecdsa_raw(cert, tbs, alg, sig):
        s, _ = parse(sig.value[1:])
        r = s[0].value.lstrip(b"\x00").rjust(32, b"\x00")
        ss = s[1].value.lstrip(b"\x00").rjust(32, b"\x00")
        sig.value = b"\x00" + r + ss

    add("sig_ecdsa_raw_r_s_concatenated", m(sig_ecdsa_raw), "ECDSA signature as raw r||s (64 bytes) instead of DER SEQUENCE (as used in JWS/COSE, wrong for X.509)", "parse-only")

    def sig_ecdsa_trailing(cert, tbs, alg, sig):
        sig.value = sig.value + b"\x00"

    add("sig_ecdsa_trailing_byte", m(sig_ecdsa_trailing), "trailing byte after ECDSA-Sig-Value inside the BIT STRING", "parse-only")

    def sig_wrong_len_rsa(cert, tbs, alg, sig):
        sig.value = sig.value[:-1]

    add("sig_rsa_one_byte_short", mutate(rsa_der, sig_wrong_len_rsa), "RSA signature 255 bytes instead of 256", "parse-only")

    def sig_rsa_all_zero(cert, tbs, alg, sig):
        sig.value = b"\x00" + b"\x00" * 256

    add("sig_rsa_all_zero", mutate(rsa_der, sig_rsa_all_zero), "RSA signature of all zero bytes", "parse-only")

    def sig_rsa_all_ff(cert, tbs, alg, sig):
        sig.value = b"\x00" + b"\xff" * 256

    add("sig_rsa_all_ff_ge_modulus", mutate(rsa_der, sig_rsa_all_ff), "RSA signature integer >= modulus (all 0xFF)", "parse-only")

    def tbs_modified_serial(cert, tbs, alg, sig):
        tbs[tbs_index(tbs)["serial"]].value = b"\x7f"

    add("tbs_serial_changed_signature_stale", m(tbs_modified_serial), "serialNumber altered after signing: canonical DER, signature verification must fail", "parse-only")

    # whole-structure oddities
    def cert_in_sequence_of_two(cert, tbs, alg, sig):
        pass

    add("two_certificates_concatenated", der + der, "two DER certificates back to back (a stream, not a single certificate)", "parse-only")
    add("pem_missing_end_line", der_to_pem(der).replace(b"-----END CERTIFICATE-----\n", b""), "PEM without the END line", "reject")
    add("pem_wrong_label", der_to_pem(der).replace(b"CERTIFICATE", b"CERTIFIKAT"), "PEM with a non-standard label", "parse-only")
    add("pem_trusted_certificate_label", der_to_pem(der, "TRUSTED CERTIFICATE"), "OpenSSL 'TRUSTED CERTIFICATE' PEM label wrapping a plain certificate (RFC 7468 does not define it)", "parse-only")
    add("pem_x509_certificate_label", der_to_pem(der, "X509 CERTIFICATE"), "legacy 'X509 CERTIFICATE' label (RFC 7468 §5.1 says parsers SHOULD accept)", "parse")
    add("pem_crlf_line_endings", der_to_pem(der).replace(b"\n", b"\r\n"), "PEM with CRLF line endings", "parse")
    add("pem_no_line_breaks", b"-----BEGIN CERTIFICATE-----\n" + __import__("base64").b64encode(der) + b"\n-----END CERTIFICATE-----\n", "PEM body on a single line", "parse")
    add("pem_leading_text_and_bag_attributes", b"Bag Attributes\n    friendlyName: test\nsubject=CN=x\n" + der_to_pem(der), "explanatory text before the PEM block (OpenSSL pkcs12 output style)", "parse")
    add("pem_base64_bad_char", der_to_pem(der).replace(b"MII", b"M!I", 1), "PEM body with an illegal base64 character", "reject")
    add("pem_base64_truncated_line", der_to_pem(der).replace(b"\n-----END", b"AAAAAAAA\n-----END", 1), "PEM body with extra base64 (decodes to trailing garbage)", "reject")
    # BER: whole certificate re-encoded with indefinite lengths for every constructed type
    def to_indefinite(node: Node) -> bytes:
        if node.constructed:
            return bytes([node.tag]) + b"\x80" + b"".join(to_indefinite(c) for c in node.children) + b"\x00\x00"
        return node.encode()

    add("ber_indefinite_lengths_everywhere", to_indefinite(parse(der)[0]), "every constructed element BER indefinite-length (a strict DER parser must reject; the signature is over the DER TBS so a lenient one must re-encode)", "reject")

    def to_long_form(node: Node) -> bytes:
        if node.constructed:
            body = b"".join(to_long_form(c) for c in node.children)
        else:
            body = node.value
        return bytes([node.tag]) + b"\x82" + len(body).to_bytes(2, "big") + body

    add("ber_long_form_lengths_everywhere", to_long_form(parse(der)[0]), "every length encoded in long form 82 xx xx even where one byte suffices (BER, not DER)", "reject")

    # validly re-signed variants of semantic violations (signature checks pass, so only the semantic rule catches them)
    ec_int_key = chains["ec"]["int_key"]
    for name, fn, reason in (
        ("resigned_version_v2_with_extensions", version_set(1), "version = v2 with extensions, validly signed"),
        ("resigned_cn_embedded_nul", cn_with_nul, "CN with embedded NUL, validly signed"),
        ("resigned_san_dnsname_embedded_nul", ext_san_dns_nul, "dNSName with embedded NUL, validly signed"),
        ("resigned_duplicate_extension", ext_dup, "duplicate extension, validly signed"),
        ("resigned_unique_ids", add_uids, "issuerUniqueID and subjectUniqueID present, validly signed"),
        ("resigned_ca_boolean_0x01", ext_bc_ca_true_bool_01, "BasicConstraints cA encoded 0x01, validly signed (over the non-DER TBS)"),
        ("resigned_key_usage_trailing_zero_octet", ext_ku_trailing_zero_bits, "KeyUsage with trailing zero octet, validly signed"),
        ("resigned_serial_negative_nonminimal", serial_set(b"\xff\x80"), "non-minimal negative serial, validly signed"),
        ("resigned_utctime_for_2050", time_set(1, 0x17, b"500101000000Z"), "UTCTime used for 2050 notAfter, validly signed"),
        ("resigned_generalizedtime_for_2030", time_set(1, 0x18, b"20300101000000Z"), "GeneralizedTime used for 2030 notAfter, validly signed"),
        ("resigned_sigalg_inner_outer_mismatch", alg_mismatch, "tbs.signature != signatureAlgorithm, validly signed with the outer algorithm"),
        ("resigned_2000_extensions", ext_huge_count, "2000 extensions, validly signed"),
        ("resigned_deeply_nested_500", ext_nested_bomb, "500-deep nested extension value, validly signed"),
    ):
        data = resign(der, fn, ec_int_key)
        add(name, data, reason, "parse-only")
        (OUT / "malformed").mkdir(parents=True, exist_ok=True)
        tmpp = OUT / "malformed" / f"{name}.der"
        tmpp.write_bytes(data)
        cases[-1] = (name, data, reason + " | openssl verify: " + openssl_verify(tmpp, [chains["ec"]["int"]], chains["ec"]["root"]), "parse-only")

    # write everything
    for name, data, reason, expect in cases:
        ext = ".pem" if data.lstrip().startswith(b"-----") or name.startswith("pem_") else ".der"
        rel = f"malformed/{name}{ext}"
        (OUT / rel).parent.mkdir(parents=True, exist_ok=True)
        (OUT / rel).write_bytes(data)
        record(rel, "cert", expect, reason, openssl=openssl_parse_result(OUT / rel, "cert"), derived_from="chains/ec/leaf.pem" if not (name.startswith("spki_rsa") or name.startswith("sig_rsa")) and "ed25519" not in name else ("algorithms/root_rsa2048_sha256.pem" if "rsa" in name else "algorithms/root_ed25519.pem"))


def main() -> None:
    global OUT, WORK, OPENSSL
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    ap.add_argument("--openssl", default=OPENSSL)
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args()
    OUT = args.out
    OPENSSL = args.openssl
    ver = run("version").stdout.decode().strip()
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    tmp = tempfile.mkdtemp(prefix="x509gen-")
    WORK = pathlib.Path(tmp)
    try:
        roots = section_algorithms()
        chains = section_chains(roots)
        section_fields(roots, chains)
        section_extensions(roots, chains)
        section_path_violations(roots, chains)
        section_crls(roots, chains)
        section_csrs(roots)
        section_malformed(roots, chains)
    finally:
        if args.keep_work:
            print("work dir kept:", WORK)
        else:
            shutil.rmtree(WORK, ignore_errors=True)
    MANIFEST.sort(key=lambda e: e["file"])
    (OUT / "manifest.json").write_text(json.dumps({"generator": "tools/generate_x509_vectors.py", "openssl": ver, "entries": MANIFEST}, indent=1) + "\n")
    from collections import Counter

    print(f"{len(MANIFEST)} files;", dict(Counter(e["expect"] for e in MANIFEST)), "; openssl:", dict(Counter(e.get("openssl", "-").split(":")[0] for e in MANIFEST)))


if __name__ == "__main__":
    main()
