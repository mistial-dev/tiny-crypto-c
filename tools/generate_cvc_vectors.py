#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate EAC (BSI TR-03110) card verifiable certificates for tests/vectors/eac/.

The certificates themselves are produced by secunet's BouncyCertGenerator from
https://github.com/eID-Testbeds/common-testbed-utilities (the same tool that
made the eID-Server testbed's CVCs).  That project ships no licence and needs a
Java 8 era toolchain, so it is not vendored; this script expects it compiled
into a directory of classes plus its BouncyCastle 1.57 / JAXB 2.3 / log4j 2.1
jars, e.g.:

    javac -encoding ISO-8859-1 -cp "jars/*" -d classes \\
        $(find CVC/src/main BouncyCertGenerator/src/main CommonUtilities/src/main \\
               -name '*.java' | grep -v BouncyCastleTlsHelper)
    cp -R BouncyCertGenerator/src/main/resources/* classes/
    CVCGEN_CLASSPATH="classes:jars/*" tools/generate_cvc_vectors.py

One source patch is required for the NIST/SEC curves (BouncyCastle 1.57 uses
custom curve classes that are not ``ECCurve.Fp``): in
``CVC/.../CVPubKeyHolder.java`` change ``(ECCurve.Fp) m_ECDomain.getCurve()``
to ``(ECCurve.AbstractFp) ...`` and ``curve.getQ()`` to
``curve.getField().getCharacteristic()``.

What this script adds: the XML configuration (a wider spread of algorithms,
curves, roles and validity windows than the testbed uses), a fixed reference
date so the output is reproducible apart from the keys, DER-level malformed
variants, and ``manifest.json`` describing every file.  Private keys are not
copied into the corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

OUT = pathlib.Path("tests/vectors/eac/cvc/generated")
REF_DATE = "2026-09-01"
MAIN = "com.secunet.testbedutils.bouncycertgen.StandaloneBouncyCertificateGenerator"

# --------------------------------------------------------------------------
# XML configuration
# --------------------------------------------------------------------------

AT_ALL = """<writeDG17>true</writeDG17><writeDG18>true</writeDG18><writeDG19>true</writeDG19><writeDG20>true</writeDG20><writeDG21>true</writeDG21>
<readDG1>true</readDG1><readDG2>true</readDG2><readDG3>true</readDG3><readDG4>true</readDG4><readDG5>true</readDG5><readDG6>true</readDG6><readDG7>true</readDG7><readDG8>true</readDG8><readDG9>true</readDG9><readDG10>true</readDG10><readDG11>true</readDG11><readDG12>true</readDG12><readDG13>true</readDG13><readDG14>true</readDG14><readDG15>true</readDG15><readDG16>true</readDG16><readDG17>true</readDG17><readDG18>true</readDG18><readDG19>true</readDG19><readDG20>true</readDG20><readDG21>true</readDG21>
<installQualifiedCertificate>true</installQualifiedCertificate><installCertificate>true</installCertificate><pinManagement>true</pinManagement><canAllowed>true</canAllowed><privilegedTerminal>true</privilegedTerminal><restrictedIdentification>true</restrictedIdentification><communityIDVerification>true</communityIDVerification><ageVerification>true</ageVerification>"""
AT_EID_ONLY = """<readDG1>true</readDG1><readDG2>true</readDG2><readDG4>true</readDG4><readDG5>true</readDG5><readDG8>true</readDG8><readDG17>true</readDG17><restrictedIdentification>true</restrictedIdentification><ageVerification>true</ageVerification>"""
AT_NONE = ""
IS_ALL = "<readEPassDG3>true</readEPassDG3><readEPassDG4>true</readEPassDG4>"
IS_DG3 = "<readEPassDG3>true</readEPassDG3>"
ST_ALL = "<generateQualifiedElectronicSignature>true</generateQualifiedElectronicSignature><generateElectronicSignature>true</generateElectronicSignature>"


def key(name, alg, curve=None, rsa_bits=None, pub=False, expo=None):
    files = f"<filePrivateKey>./keys/{name}.pkcs8</filePrivateKey>"
    if pub:
        files += f"<filePublicKey>./keys/{name}.x509</filePublicKey>"
    if curve:
        body = f"<ecdsa>{curve}</ecdsa>"
    else:
        body = "<rsa>" + (f"<publicExpo>{expo}</publicExpo>" if expo else "") + f"<length>{rsa_bits}</length></rsa>"
    return f'<key name="{name}_KEY" create="true">{files}<algorithm>{alg}</algorithm>{body}</key>'


def cert(holder, issuer, keyname, signkey, role, ttype, auth, eff, exp, out, domain=False, ext="", force_oid=None, profile=0):
    dp = ' domainParam="true"' if domain else ""
    fo = f' forceOID="{force_oid}"' if force_oid else ""
    effx = f"<effDate>{eff}</effDate>" if "-" in str(eff) else f"<effDateOffset>{eff}</effDateOffset>"
    expx = f"<expDate>{exp}</expDate>" if "-" in str(exp) else f"<expDateOffset>{exp}</expDateOffset>"
    return f"""<cert><profileId>{profile}</profileId><certAuthRef>{issuer}</certAuthRef><publicKey{dp}>{keyname}_KEY</publicKey><certHolderRef>{holder}</certHolderRef>
<certHolderAuth type="{ttype}"{fo}><role>{role}</role>{auth}</certHolderAuth>{effx}{expx}{ext}<signKey>{signkey}_KEY</signKey><outputFile>./certs/{out}.cvcert</outputFile></cert>"""


def description(subject, url, terms, sector=None, out="desc"):
    s = f"""<extensions><description><issuerName>tiny-crypto test DV</issuerName><issuerURL>https://dv.example.test</issuerURL><subjectName>{subject}</subjectName><subjectURL>{url}</subjectURL><termsOfUsage>{terms}</termsOfUsage><redirectURL>https://redirect.example.test/</redirectURL><fileDescription>./desc/{out}.bin</fileDescription></description>"""
    if sector:
        s += f"<terminalSector><fileSectorPublicKey>./keys/{sector}.x509.cv</fileSectorPublicKey></terminalSector>"
    return s + "</extensions>"


def ref(role2: str, tag: str) -> str:
    """Holder/authority mnemonic: country XX + 2-letter role + tag (<= 9 chars total after XX)."""
    m = f"{role2}{tag}"
    assert len(m) <= 9, m
    return "XX" + m


def build_xml() -> tuple[str, list[dict]]:
    keys = []
    certs = []
    meta = []  # (file stem, description, expect)
    SEQ = "00001"

    def add_chain(tag, alg, curve=None, rsa_bits=None, expo=None, ttype="AT", auth_dv=AT_ALL, auth_term=AT_EID_ONLY, term_ext="", term_force_oid=None):
        cvca, dv, term = ref("CV", tag), ref("DV", tag), ref("TM", tag)
        for n in (cvca, dv, term):
            keys.append(key(n, alg, curve, rsa_bits, pub=(n == cvca), expo=expo))
        certs.append(cert(cvca + SEQ, cvca + SEQ, cvca, cvca, "CVCA", ttype, auth_dv, "2026-01-01", "2036-01-01", f"{tag}_cvca", domain=True))
        certs.append(cert(dv + SEQ, cvca + SEQ, dv, cvca, "DV_DOMESTIC", ttype, auth_dv, "2026-06-01", "2029-06-01", f"{tag}_dv"))
        certs.append(cert(term + SEQ, dv + SEQ, term, dv, "TERMINAL", ttype, auth_term, REF_DATE, 90, f"{tag}_terminal", ext=term_ext, force_oid=term_force_oid))
        desc = f"{alg} " + (curve or f"RSA-{rsa_bits}" + (f" e={expo}" if expo else ""))
        meta.append((f"{tag}_cvca", f"self-signed CVCA root, {desc}, domain parameters included, holder authorization {ttype} with every right", "parse"))
        meta.append((f"{tag}_dv", f"DV_DOMESTIC issued by {tag}_cvca, {desc}, public key without domain parameters", "parse"))
        meta.append((f"{tag}_terminal", f"TERMINAL issued by {tag}_dv, {desc}, 90-day validity from {REF_DATE}" + (", with certificate description and terminal sector extensions" if term_ext else ""), "parse"))
        return cvca, dv, term

    BP256 = ("TA_ECDSA_SHA_256", "BRAINPOOL::p256r1")

    # 1. brainpoolP256r1 / ECDSA-SHA-256: the German eID profile, richest chain
    keys.append(key(ref("SK", "BP256"), *BP256, pub=True))
    cvca, dv, term = add_chain("BP256", *BP256,
                               term_ext=description("Test Service Provider", "https://sp.example.test", "Terms of usage for the tiny-crypto test terminal. No rights granted.", sector=ref("SK", "BP256"), out="BP256_terminal"))
    # foreign DV + terminal without extensions
    dvf, tmf = ref("DF", "BP256"), ref("TF", "BP256")
    keys.append(key(dvf, *BP256))
    keys.append(key(tmf, *BP256))
    certs.append(cert(dvf + SEQ, cvca + SEQ, dvf, cvca, "DV_FOREIGN", "AT", AT_ALL, "2026-06-01", "2029-06-01", "BP256_dv_foreign"))
    certs.append(cert(tmf + SEQ, dvf + SEQ, tmf, dvf, "TERMINAL", "AT", AT_NONE, REF_DATE, 30, "BP256_terminal_foreign_no_rights"))
    meta.append(("BP256_dv_foreign", "DV_FOREIGN issued by BP256_cvca", "parse"))
    meta.append(("BP256_terminal_foreign_no_rights", "TERMINAL under the foreign DV with no authorization bits set and no extensions", "parse"))
    # link certificate: CVCA generation 2 signed by generation 1, then a new chain under it
    cv2, dv2 = ref("C2", "BP256"), ref("D2", "BP256")
    keys.append(key(cv2, *BP256, pub=True))
    keys.append(key(dv2, *BP256))
    certs.append(cert(cv2 + SEQ, cvca + SEQ, cv2, cvca, "CVCA", "AT", AT_ALL, "2030-01-01", "2040-01-01", "BP256_link_cvca1_to_cvca2", domain=True))
    certs.append(cert(cv2 + SEQ, cv2 + SEQ, cv2, cv2, "CVCA", "AT", AT_ALL, "2030-01-01", "2040-01-01", "BP256_cvca2_self_signed", domain=True))
    certs.append(cert(dv2 + SEQ, cv2 + SEQ, dv2, cv2, "DV_DOMESTIC", "AT", AT_ALL, "2030-01-01", "2033-01-01", "BP256_dv_under_cvca2"))
    meta.append(("BP256_link_cvca1_to_cvca2", "link certificate: CVCA generation 2 key signed by generation 1 (CAR != CHR, role CVCA, domain parameters)", "parse"))
    meta.append(("BP256_cvca2_self_signed", "the same generation 2 CVCA key self-signed", "parse"))
    meta.append(("BP256_dv_under_cvca2", "DV issued by CVCA generation 2 (validates only through the link certificate)", "parse"))
    # validity edge cases
    dvo, tmu = ref("DO", "BP256"), ref("TU", "BP256")
    keys.append(key(dvo, *BP256))
    keys.append(key(tmu, *BP256))
    certs.append(cert(dvo + SEQ, cvca + SEQ, dvo, cvca, "DV_DOMESTIC", "AT", AT_ALL, "2015-01-01", "2016-01-01", "BP256_dv_expired"))
    certs.append(cert(tmu + SEQ, dv + SEQ, tmu, dv, "TERMINAL", "AT", AT_EID_ONLY, "2040-01-01", "2040-12-31", "BP256_terminal_not_yet_valid"))
    certs.append(cert(term + "00002", dv + SEQ, term, dv, "TERMINAL", "AT", AT_EID_ONLY, REF_DATE, 0, "BP256_terminal_one_day"))
    certs.append(cert(term + "00003", dv + SEQ, term, dv, "TERMINAL", "AT", AT_EID_ONLY, "2049-12-31", "2050-01-01", "BP256_terminal_2049_2050"))
    meta.append(("BP256_dv_expired", "DV that expired in 2016", "parse-only"))
    meta.append(("BP256_terminal_not_yet_valid", "TERMINAL not valid before 2040", "parse-only"))
    meta.append(("BP256_terminal_one_day", "TERMINAL with expiration date equal to effective date (one day); sequence number 00002 for the same key", "parse"))
    meta.append(("BP256_terminal_2049_2050", "TERMINAL valid 2049-12-31 to 2050-01-01 (BCD date YYMMDD wraps 49 -> 50)", "parse"))
    certs.append(cert(term + "00004", dv + SEQ, term, dv, "TERMINAL", "AT", AT_EID_ONLY, REF_DATE, 90, "BP256_terminal_profile_id_1", profile=1))
    meta.append(("BP256_terminal_profile_id_1", "certificate profile identifier 1 (only 0 is defined by TR-03110)", "parse-only"))
    certs.append(cert(term + "00005", dv + SEQ, term, dv, "TERMINAL", "AT", AT_EID_ONLY, REF_DATE, 90, "BP256_terminal_forced_is_oid_with_at_bits", force_oid="04007F000703010201"))
    meta.append(("BP256_terminal_forced_is_oid_with_at_bits", "authorization template OID says id-IS (0.4.0.127.0.7.3.1.2.1) but the discretionary data is an AT bitmap (5 bytes instead of 1)", "parse-only"))

    # 2. other curves / hashes / terminal types.  NIST/SEC curves need the one-line
    #    ECCurve.Fp -> ECCurve.AbstractFp cast fix in CVPubKeyHolder.java (see README).
    add_chain("P256IS", "TA_ECDSA_SHA_256", "ASN1::secp256r1", ttype="IS", auth_dv=IS_ALL, auth_term=IS_DG3)
    add_chain("P256", "TA_ECDSA_SHA_256", "ASN1::secp256r1")
    add_chain("P384", "TA_ECDSA_SHA_256", "ASN1::secp384r1")
    add_chain("P521", "TA_ECDSA_SHA_256", "ASN1::secp521r1")
    add_chain("P224", "TA_ECDSA_SHA_224", "ASN1::secp224r1")
    add_chain("P192", "TA_ECDSA_SHA_1", "ASN1::secp192r1")
    add_chain("K256", "TA_ECDSA_SHA_256", "ASN1::secp256k1")
    add_chain("BP256IS", *BP256, ttype="IS", auth_dv=IS_ALL, auth_term=IS_DG3)
    add_chain("BP384ST", "TA_ECDSA_SHA_256", "BRAINPOOL::p384r1", ttype="ST", auth_dv=ST_ALL, auth_term=ST_ALL)
    add_chain("BP384", "TA_ECDSA_SHA_256", "BRAINPOOL::p384r1")
    add_chain("BP512", "TA_ECDSA_SHA_256", "BRAINPOOL::p512r1")
    add_chain("BP320", "TA_ECDSA_SHA_256", "BRAINPOOL::p320r1")
    add_chain("BP224", "TA_ECDSA_SHA_224", "BRAINPOOL::p224r1")
    add_chain("BP192", "TA_ECDSA_SHA_1", "BRAINPOOL::p192r1")
    add_chain("BP160", "TA_ECDSA_SHA_1", "BRAINPOOL::p160r1")
    add_chain("P160", "TA_ECDSA_SHA_1", "ASN1::secp160r1")
    add_chain("BP256T", *BP256[:1], "BRAINPOOL::p256t1")
    add_chain("BP512T", "TA_ECDSA_SHA_256", "BRAINPOOL::p512t1")

    # 3. RSA
    add_chain("RPSS256", "TA_RSA_PSS_SHA_256", rsa_bits=2048)
    add_chain("RPSS1", "TA_RSA_PSS_SHA_1", rsa_bits=1536)
    add_chain("RV15256", "TA_RSA_v1_5_SHA_256", rsa_bits=3072)
    add_chain("RV151", "TA_RSA_v1_5_SHA_1", rsa_bits=1024)
    add_chain("RE3", "TA_RSA_v1_5_SHA_256", rsa_bits=2048, expo=3)
    add_chain("R512", "TA_RSA_v1_5_SHA_1", rsa_bits=512)

    xml = ('<?xml version="1.0" encoding="utf-8"?>\n<root xmlns="http://www.secunet.com" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.secunet.com cv_schema.xsd">\n<keys>\n'
           + "\n".join(keys) + "\n</keys>\n" + "\n".join(certs) + "\n</root>\n")
    return xml, [{"stem": s, "reason": r, "expect": e} for s, r, e in meta]


# --------------------------------------------------------------------------
# TLV helpers for malformed variants
# --------------------------------------------------------------------------


def tlv_iter(b: bytes, pos: int = 0, end: int | None = None):
    end = len(b) if end is None else end
    while pos < end:
        tstart = pos
        t = b[pos]
        pos += 1
        if t & 0x1F == 0x1F:
            t = (t << 8) | b[pos]
            pos += 1
        lstart = pos
        l = b[pos]
        pos += 1
        if l & 0x80:
            n = l & 0x7F
            l = int.from_bytes(b[pos : pos + n], "big")
            pos += n
        yield t, tstart, lstart, pos, pos + l
        pos += l


def find(b: bytes, tag: int, start=0, end=None):
    for t, ts, ls, vs, ve in tlv_iter(b, start, end):
        if t == tag:
            return ts, ls, vs, ve
    return None


def deep_find(b: bytes, tag: int):
    """Depth-first search for a tag; returns the element's content."""
    for t, ts, ls, vs, ve in tlv_iter(b):
        if t == tag:
            return b[vs:ve]
        first = b[ts]
        if first & 0x20:
            r = deep_find(b[vs:ve], tag)
            if r is not None:
                return r
    return None


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    r = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(r)]) + r


def rewrap(tag: int, body: bytes) -> bytes:
    tb = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    return tb + enc_len(len(body)) + body


def malformed(good: dict[str, bytes]) -> list[tuple[str, bytes, str, str]]:
    out = []
    der = good["BP256_terminal"]
    cvca = good["BP256_cvca"]
    _, _, body_s, body_e = find(der, 0x7F21)
    body = der[body_s:body_e]
    b_s, _, _, b_e = find(body, 0x7F4E)
    tbs = body[b_s:b_e]  # 7F4E header + content
    sig_t = find(body, 0x5F37)
    sig = body[sig_t[2] : sig_t[3]]

    def add(name, data, reason, expect="reject"):
        out.append((name, data, reason, expect))

    add("truncated_half", der[: len(der) // 2], "certificate cut in half")
    add("truncated_last_byte", der[:-1], "last signature byte missing")
    add("trailing_garbage", der + b"\x00\x01\x02", "three bytes after the 7F21 template")
    add("empty", b"", "zero-length input")
    add("outer_tag_7f22", b"\x7f\x22" + der[2:], "outer tag 7F22 instead of 7F21 (CV certificate)")
    add("outer_tag_7f21_wrong_length_long", der[:2] + b"\x82" + (len(der) - 4 + 20).to_bytes(2, "big") + der[4:], "outer length 20 bytes too long")
    add("outer_tag_7f21_wrong_length_short", der[:2] + b"\x82" + (len(der) - 4 - 20).to_bytes(2, "big") + der[4:], "outer length 20 bytes too short")
    add("outer_length_indefinite", der[:2] + b"\x80" + der[4:] + b"\x00\x00", "BER indefinite length on the outer template")
    add("outer_length_non_minimal", der[:2] + b"\x83\x00" + (len(der) - 4).to_bytes(2, "big") + der[4:], "3-octet length where 2 suffice")
    add("body_missing_signature", rewrap(0x7F21, tbs), "7F21 containing only the 7F4E body, no 5F37 signature")
    add("signature_before_body", rewrap(0x7F21, rewrap(0x5F37, sig) + tbs), "5F37 signature placed before the 7F4E body (order is fixed by TR-03110)", "parse-only")
    add("signature_flipped_bit", rewrap(0x7F21, tbs + rewrap(0x5F37, sig[:-1] + bytes([sig[-1] ^ 1]))), "one bit of the ECDSA signature flipped: well formed, verification must fail", "parse-only")
    add("signature_short", rewrap(0x7F21, tbs + rewrap(0x5F37, sig[:-1])), "signature one byte short (63 bytes for a 256-bit curve r||s)", "parse-only")
    add("signature_empty", rewrap(0x7F21, tbs + rewrap(0x5F37, b"")), "zero-length signature", "parse-only")
    add("signature_all_zero", rewrap(0x7F21, tbs + rewrap(0x5F37, bytes(len(sig)))), "signature r = s = 0", "parse-only")
    add("signature_der_encoded", rewrap(0x7F21, tbs + rewrap(0x5F37, b"\x30" + enc_len(len(sig) + 4) + b"\x02" + enc_len(len(sig) // 2) + sig[: len(sig) // 2] + b"\x02" + enc_len(len(sig) // 2) + sig[len(sig) // 2 :])),
        "signature as X9.62 DER SEQUENCE instead of plain r||s (TR-03110 requires plain format)", "parse-only")
    add("duplicate_signature", rewrap(0x7F21, tbs + rewrap(0x5F37, sig) + rewrap(0x5F37, sig)), "two 5F37 elements")
    add("two_certificates_concatenated", der + der, "two certificates back to back", "parse-only")

    # body-level edits: rebuild body from its elements
    _, _, c_s, c_e = find(tbs, 0x7F4E)
    inner = {t: tbs[vs:ve] for t, ts, ls, vs, ve in tlv_iter(tbs, c_s, c_e)}
    order = [t for t, *_ in tlv_iter(tbs, c_s, c_e)]

    def rebuild(mod: dict[int, bytes | None], extra: list[tuple[int, bytes]] = (), reorder=None):
        parts = []
        for t in (reorder or order):
            v = mod.get(t, inner[t]) if t in mod else inner[t]
            if v is None:
                continue
            parts.append(rewrap(t, v))
        for t, v in extra:
            parts.append(rewrap(t, v))
        new_tbs = rewrap(0x7F4E, b"".join(parts))
        return rewrap(0x7F21, new_tbs + rewrap(0x5F37, sig))

    add("body_missing_profile_identifier", rebuild({0x5F29: None}), "5F29 certificate profile identifier absent")
    add("body_profile_identifier_two_bytes", rebuild({0x5F29: b"\x00\x00"}), "5F29 with two octets", "parse-only")
    add("body_profile_identifier_ff", rebuild({0x5F29: b"\xff"}), "5F29 = 0xFF (undefined profile)", "parse-only")
    add("body_missing_car", rebuild({0x42: None}), "42 certification authority reference absent")
    add("body_car_too_long", rebuild({0x42: b"XXCVCABP2561" + b"0" * 10}), "CAR of 22 characters (maximum is 16)", "parse-only")
    add("body_car_too_short", rebuild({0x42: b"XXCVCA"}), "CAR of 6 characters (minimum is 8: 2 country + 1 mnemonic + 5 sequence)", "parse-only")
    add("body_car_non_ascii", rebuild({0x42: b"XX\xff\xfeCA00001"}), "CAR with bytes outside ISO 8859-1 letters/digits", "parse-only")
    add("body_car_lowercase_country", rebuild({0x42: b"xxCVCABP256100001"}), "CAR country code in lower case", "parse-only")
    add("body_chr_missing", rebuild({0x5F20: None}), "5F20 certificate holder reference absent")
    add("body_chr_equals_car_on_terminal", rebuild({0x5F20: inner[0x42]}), "terminal certificate whose CHR equals its CAR (looks self-issued but role is TERMINAL)", "parse-only")
    add("body_pubkey_missing", rebuild({0x7F49: None}), "7F49 public key absent")
    add("body_pubkey_empty", rebuild({0x7F49: b""}), "7F49 public key with no content")
    add("body_pubkey_only_oid", rebuild({0x7F49: rewrap(0x06, bytes.fromhex("04007f00070202020203"))}), "7F49 with the algorithm OID but no 86 public point")
    add("body_pubkey_point_compressed", rebuild({0x7F49: rewrap(0x06, bytes.fromhex("04007f00070202020203")) + rewrap(0x86, b"\x02" + b"\x11" * 32)}), "86 public point in compressed form (TR-03110 requires uncompressed 04||x||y)", "parse-only")
    add("body_pubkey_point_wrong_length", rebuild({0x7F49: rewrap(0x06, bytes.fromhex("04007f00070202020203")) + rewrap(0x86, b"\x04" + b"\x11" * 63)}), "86 public point one byte short", "parse-only")
    add("body_pubkey_point_not_on_curve", rebuild({0x7F49: rewrap(0x06, bytes.fromhex("04007f00070202020203")) + rewrap(0x86, b"\x04" + b"\x11" * 64)}), "86 public point that is not on brainpoolP256r1", "parse-only")
    add("body_pubkey_unknown_oid", rebuild({0x7F49: rewrap(0x06, bytes.fromhex("2b0601040181e60701")) + inner[0x7F49][12:]}), "7F49 with an unknown algorithm OID", "parse-only")
    add("body_pubkey_rsa_oid_with_ec_point", rebuild({0x7F49: rewrap(0x06, bytes.fromhex("04007f00070202010201")) + inner[0x7F49][12:]}), "7F49 OID id-TA-RSA-v1-5-SHA-1 but the element is an EC point (86)", "parse-only")
    # domain parameters present in a non-CVCA cert (copy the CVCA's 7F49)
    add("body_pubkey_domain_params_in_terminal", rebuild({0x7F49: deep_find(cvca, 0x7F49)}), "terminal certificate carrying full domain parameters (81..85, 87) in 7F49 - only CVCA certificates may", "parse-only")
    add("body_chat_missing", rebuild({0x7F4C: None}), "7F4C certificate holder authorization template absent (mandatory in TR-03110 v2)", "parse-only")
    add("body_chat_empty", rebuild({0x7F4C: b""}), "7F4C with no content")
    add("body_chat_role_cvca_in_terminal", rebuild({0x7F4C: rewrap(0x06, bytes.fromhex("04007f000703010202")) + rewrap(0x53, b"\xc0" + b"\x00" * 4)}), "authorization role bits say CVCA (11) on a certificate issued by a DV", "parse-only")
    add("body_chat_discretionary_data_wrong_length", rebuild({0x7F4C: rewrap(0x06, bytes.fromhex("04007f000703010202")) + rewrap(0x53, b"\x00" * 3)}), "id-AT template with a 3-byte bitmap (must be 5)", "parse-only")
    add("body_chat_reserved_bits_set", rebuild({0x7F4C: rewrap(0x06, bytes.fromhex("04007f000703010202")) + rewrap(0x53, b"\x3f\xff\xff\xff\xff")}), "id-AT template with every bit set including RFU bits", "parse-only")
    add("body_effective_date_missing", rebuild({0x5F25: None}), "5F25 effective date absent")
    add("body_effective_date_bcd_invalid", rebuild({0x5F25: b"\x02\x06\x01\x03\x03\x01"}), "effective date with month 13 (BCD digits 1,3)", "parse-only")
    add("body_effective_date_digit_gt_9", rebuild({0x5F25: b"\x02\x06\x0a\x01\x00\x01"}), "date digit 0x0A (not a decimal digit)", "parse-only")
    add("body_effective_date_5_bytes", rebuild({0x5F25: b"\x02\x06\x01\x00\x01"}), "date with 5 octets instead of 6")
    add("body_expiration_before_effective", rebuild({0x5F24: b"\x02\x00\x01\x00\x01\x00"}), "expiration date 2020-01-01 before effective date", "parse-only")
    add("body_expiration_missing", rebuild({0x5F24: None}), "5F24 expiration date absent")
    add("body_elements_reordered", rebuild({}, reorder=[0x5F29, 0x7F49, 0x42, 0x5F20, 0x7F4C, 0x5F25, 0x5F24] + [t for t in order if t not in (0x5F29, 0x7F49, 0x42, 0x5F20, 0x7F4C, 0x5F25, 0x5F24)]), "7F49 before 42: elements out of the TR-03110 order", "parse-only")
    add("body_unknown_element", rebuild({}, extra=[(0x5F99, b"\x01\x02\x03")]), "unknown 5F99 element appended to the body", "parse-only")
    add("body_duplicate_car", rebuild({}, extra=[(0x42, inner[0x42])]), "second 42 element appended", "parse-only")
    add("body_extensions_empty", rebuild({0x65: b""}) if 0x65 in inner else rebuild({}, extra=[(0x65, b"")]), "65 certificate extensions template present but empty", "parse-only")
    add("body_extension_unknown_oid", rebuild({}, extra=[(0x65, rewrap(0x73, rewrap(0x06, bytes.fromhex("2b0601040181e60702")) + rewrap(0x80, b"\xaa" * 32)))]) if 0x65 not in inner else rebuild({0x65: inner[0x65] + rewrap(0x73, rewrap(0x06, bytes.fromhex("2b0601040181e60702")) + rewrap(0x80, b"\xaa" * 32))}), "extension discretionary data template with an unknown OID", "parse-only")
    hl = 2 + ((1 + (tbs[2] & 0x7F)) if tbs[2] & 0x80 else 1)
    add("body_nested_length_mismatch", rewrap(0x7F21, b"\x7f\x4e" + enc_len(len(tbs) - hl + 5) + tbs[hl:] + rewrap(0x5F37, sig)), "7F4E length claims 5 more bytes than its content")
    return out


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    ap.add_argument("--classpath", default=os.environ.get("CVCGEN_CLASSPATH"), help="classes dir + jars for the secunet generator")
    ap.add_argument("--java", default="java")
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args()
    if not args.classpath:
        raise SystemExit("set CVCGEN_CLASSPATH or --classpath (see module docstring)")

    xml, meta = build_xml()
    work = pathlib.Path(tempfile.mkdtemp(prefix="cvcgen-"))
    for d in ("keys", "certs", "desc"):
        (work / d).mkdir()
    (work / "config.xml").write_text(xml)
    r = subprocess.run([args.java, "-cp", args.classpath, MAIN, "-cv", "-xin", "config.xml", "-date", REF_DATE], cwd=work, capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("WARN") or "generated" in line:
            print(line)
    if r.returncode != 0 or "generated" not in r.stdout:
        print(r.stdout, r.stderr)
        raise SystemExit("generator failed")

    if args.out.exists():
        shutil.rmtree(args.out)
    (args.out / "certs").mkdir(parents=True)
    (args.out / "public_keys").mkdir()
    (args.out / "descriptions").mkdir()
    (args.out / "malformed").mkdir()
    shutil.copy(work / "config.xml", args.out / "config.xml")

    manifest = []
    good: dict[str, bytes] = {}
    for m in meta:
        src = work / "certs" / f"{m['stem']}.cvcert"
        if not src.exists():
            print("MISSING", src)
            continue
        data = src.read_bytes()
        good[m["stem"]] = data
        dst = args.out / "certs" / f"{m['stem']}.cvcert"
        dst.write_bytes(data)
        manifest.append({"file": f"certs/{m['stem']}.cvcert", "kind": "cvc", "expect": m["expect"], "reason": m["reason"], "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    for f in sorted((work / "keys").glob("*.x509.cv")):
        shutil.copy(f, args.out / "public_keys" / f.name)
        manifest.append({"file": f"public_keys/{f.name}", "kind": "cvc-public-key", "expect": "parse", "reason": "7F49 public key template with domain parameters (as exported for CVCA and sector keys)", "sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "size": f.stat().st_size})
    for f in sorted((work / "desc").glob("*.bin")):
        shutil.copy(f, args.out / "descriptions" / f.name)
        manifest.append({"file": f"descriptions/{f.name}", "kind": "certificate-description", "expect": "parse", "reason": "CertificateDescription (TR-03110-4 / TR-03110-3 C.3.1) DER whose SHA-256 is referenced from the terminal certificate's 65 extension", "sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "size": f.stat().st_size})
    for name, data, reason, expect in malformed(good):
        p = args.out / "malformed" / f"{name}.cvcert"
        p.write_bytes(data)
        manifest.append({"file": f"malformed/{name}.cvcert", "kind": "cvc", "expect": expect, "reason": reason, "derived_from": "certs/BP256_terminal.cvcert", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    # independent verification; anything the tool emitted that does not verify
    # (it strips leading zero octets from r, s and coordinates, which TR-03110
    # forbids) is downgraded to parse-only with the finding recorded
    import sys as _sys

    _sys.path.insert(0, str(pathlib.Path(__file__).parent))
    import verify_cvc

    results = {r["file"]: r for r in verify_cvc.check_dir(args.out / "certs")}
    results.update({"malformed/" + r["file"]: r for r in verify_cvc.check_dir(args.out / "malformed", [args.out / "certs"])})
    for e in manifest:
        key_ = e["file"][len("certs/") :] if e["file"].startswith("certs/") else e["file"]
        r = results.get(key_)
        if r is None:
            continue
        e["verify"] = r.get("error") or r.get("verify")
        if e["expect"] == "parse" and e["verify"] != "signature ok":
            e["expect"] = "parse-only"
            e["reason"] += f" | NOTE: {e['verify']} - the generator strips leading zero octets from r/s or coordinates, which TR-03110 D.3.3 forbids; kept as a non-conforming sample"
    manifest.sort(key=lambda e: e["file"])
    (args.out / "manifest.json").write_text(json.dumps({"generator": "tools/generate_cvc_vectors.py + eID-Testbeds/common-testbed-utilities BouncyCertGenerator", "reference_date": REF_DATE, "entries": manifest}, indent=1) + "\n")
    from collections import Counter

    print(len(manifest), "files", dict(Counter(e["expect"] for e in manifest)))
    if args.keep_work:
        print("work:", work)
    else:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
