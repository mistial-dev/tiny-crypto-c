#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent checker for BSI TR-03110 card verifiable certificates.

Pure Python (hashlib only): parses the 7F21 template, resolves the issuer by
CAR within a directory of certificates, inherits domain parameters from the
CVCA as TR-03110 requires, and verifies the signature (ECDSA plain r||s over
the 7F4E body, or RSA PKCS#1 v1.5 / PSS).  Used to confirm what the
BouncyCertGenerator emitted before it went into the corpus.

Usage: tools/verify_cvc.py [--issuers DIR]... [--json] DIR [DIR ...]
       (one line per certificate; --issuers adds directories searched for CARs)
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

OID_TA = {  # id-TA = 0.4.0.127.0.7.2.2.2 ; .1.x RSA, .2.x ECDSA
    "04007f00070202020101": ("rsa", "v15", "sha1"),
    "04007f00070202020102": ("rsa", "v15", "sha256"),
    "04007f00070202020103": ("rsa", "pss", "sha1"),
    "04007f00070202020104": ("rsa", "pss", "sha256"),
    "04007f00070202020105": ("rsa", "v15", "sha512"),
    "04007f00070202020106": ("rsa", "pss", "sha512"),
    "04007f00070202020201": ("ecdsa", "sha1"),
    "04007f00070202020202": ("ecdsa", "sha224"),
    "04007f00070202020203": ("ecdsa", "sha256"),
    "04007f00070202020204": ("ecdsa", "sha384"),
    "04007f00070202020205": ("ecdsa", "sha512"),
}


def tlv_iter(b: bytes, pos: int = 0, end: int | None = None):
    end = len(b) if end is None else end
    while pos < end:
        ts = pos
        t = b[pos]
        pos += 1
        if t & 0x1F == 0x1F:
            t = (t << 8) | b[pos]
            pos += 1
        l = b[pos]
        pos += 1
        if l & 0x80:
            n = l & 0x7F
            l = int.from_bytes(b[pos : pos + n], "big")
            pos += n
        if pos + l > end:
            raise ValueError(f"length overrun at {ts}")
        yield t, ts, pos, pos + l
        pos += l
    if pos != end:
        raise ValueError("length underrun")


def children(b: bytes) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = {}
    for t, ts, vs, ve in tlv_iter(b):
        out.setdefault(t, []).append(b[vs:ve])
    return out


class CVC:
    def __init__(self, data: bytes):
        top = list(tlv_iter(data))
        if len(top) != 1 or top[0][0] != 0x7F21:
            raise ValueError("not a single 7F21 template")
        _, _, vs, ve = top[0]
        parts = list(tlv_iter(data, vs, ve))
        tags = [p[0] for p in parts]
        if tags != [0x7F4E, 0x5F37]:
            raise ValueError(f"7F21 children {['%X' % t for t in tags]} (expected 7F4E, 5F37)")
        self.body = data[parts[0][1] : parts[0][3]]  # with header: what is signed
        self.signature = data[parts[1][2] : parts[1][3]]
        c = children(data[parts[0][2] : parts[0][3]])
        order = [t for t, *_ in tlv_iter(data, parts[0][2], parts[0][3])]
        expected = [0x5F29, 0x42, 0x7F49, 0x5F20, 0x7F4C, 0x5F25, 0x5F24]
        if order[:7] != expected or any(t not in (0x65,) for t in order[7:]):
            raise ValueError(f"body order {['%X' % t for t in order]}")
        one = lambda t: (c[t][0] if len(c.get(t, [])) == 1 else (_ for _ in ()).throw(ValueError(f"tag {t:X} count {len(c.get(t, []))}")))
        self.profile = one(0x5F29)
        self.car = one(0x42).decode("latin1")
        self.chr = one(0x5F20).decode("latin1")
        pk = children(one(0x7F49))
        self.pk_oid = pk[0x06][0].hex()
        self.pk = {t: v[0] for t, v in pk.items()}
        chat = children(one(0x7F4C))
        self.chat_oid = chat[0x06][0].hex()
        self.chat_bits = chat[0x53][0]
        self.eff = one(0x5F25)
        self.exp = one(0x5F24)
        self.extensions = c.get(0x65, [None])[0]
        for d, name in ((self.eff, "effective"), (self.exp, "expiration")):
            if len(d) != 6 or any(x > 9 for x in d):
                raise ValueError(f"{name} date not 6 BCD digits")
        if self.profile != b"\x00":
            raise ValueError(f"profile identifier {self.profile.hex()}")
        if not (8 <= len(self.car) <= 16 and 8 <= len(self.chr) <= 16):
            raise ValueError("CAR/CHR length")

    def date(self, d: bytes) -> str:
        return "20%d%d-%d%d-%d%d" % tuple(d)

    def role(self) -> str:
        return {0xC0: "CVCA", 0x80: "DV_DOMESTIC", 0x40: "DV_FOREIGN", 0x00: "TERMINAL"}[self.chat_bits[0] & 0xC0]


# --- EC arithmetic (affine, short Weierstrass) --------------------------------


def ec_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def ec_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P, p, a)
        P = ec_add(P, P, p, a)
        k >>= 1
    return R


def ecdsa_verify(dom: dict, Q: bytes, msg: bytes, sig: bytes, hname: str) -> bool:
    p, a, b = (int.from_bytes(dom[t], "big") for t in (0x81, 0x82, 0x83))
    G = dom[0x84]
    n = int.from_bytes(dom[0x85], "big")
    if G[0] != 4 or Q[0] != 4:
        return False
    fl = (len(G) - 1) // 2
    Gp = (int.from_bytes(G[1 : 1 + fl], "big"), int.from_bytes(G[1 + fl :], "big"))
    Qp = (int.from_bytes(Q[1 : 1 + fl], "big"), int.from_bytes(Q[1 + fl :], "big"))
    if (Qp[1] * Qp[1] - Qp[0] ** 3 - a * Qp[0] - b) % p:
        return False
    nl = (n.bit_length() + 7) // 8
    if len(sig) != 2 * nl:
        return False
    r, s = int.from_bytes(sig[:nl], "big"), int.from_bytes(sig[nl:], "big")
    if not (0 < r < n and 0 < s < n):
        return False
    e = int.from_bytes(hashlib.new(hname, msg).digest(), "big")
    if n.bit_length() < e.bit_length():
        e >>= e.bit_length() - n.bit_length()
    w = pow(s, -1, n)
    R = ec_add(ec_mul(e * w % n, Gp, p, a), ec_mul(r * w % n, Qp, p, a), p, a)
    return R is not None and R[0] % n == r


# --- RSA --------------------------------------------------------------------

DIGEST_INFO = {"sha1": "3021300906052b0e03021a05000414", "sha256": "3031300d060960864801650304020105000420", "sha512": "3051300d060960864801650304020305000440"}


def mgf1(seed: bytes, length: int, hname: str) -> bytes:
    out = b""
    c = 0
    while len(out) < length:
        out += hashlib.new(hname, seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:length]


def rsa_verify(n: int, e: int, msg: bytes, sig: bytes, scheme: str, hname: str) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    h = hashlib.new(hname, msg).digest()
    if scheme == "v15":
        t = bytes.fromhex(DIGEST_INFO[hname]) + h
        return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    # EMSA-PSS, salt length = hash length (TR-03110 A.2.1.1)
    hl = len(h)
    if em[-1] != 0xBC:
        return False
    masked, H = em[: k - hl - 1], em[k - hl - 1 : -1]
    db = bytes(x ^ y for x, y in zip(masked, mgf1(H, k - hl - 1, hname)))
    db = bytes([db[0] & (0xFF >> (8 * k - n.bit_length() + 1))]) + db[1:]
    if db[: k - 2 * hl - 2] != bytes(k - 2 * hl - 2) or db[k - 2 * hl - 2] != 0x01:
        return False
    salt = db[-hl:]
    return H == hashlib.new(hname, bytes(8) + h + salt).digest()


# --- driver -----------------------------------------------------------------


def load_dir(d: pathlib.Path) -> list[dict]:
    results = []
    for f in sorted(list(d.glob("*.cvcert")) + list(d.glob("*.cvc"))):
        try:
            results.append({"file": f.name, "cvc": CVC(f.read_bytes())})
        except Exception as ex:  # noqa: BLE001
            results.append({"file": f.name, "error": f"parse: {ex}"})
    return results


def check_dir(d: pathlib.Path, issuer_dirs: list[pathlib.Path] = ()) -> list[dict]:
    results = load_dir(d)
    # issuers: this directory plus any extra ones; a link certificate and a
    # self-signed CVCA share a CHR, so keep a list per CHR
    by_chr: dict[str, list[CVC]] = {}
    for src in [results] + [load_dir(x) for x in issuer_dirs]:
        for r in src:
            if "cvc" in r:
                by_chr.setdefault(r["cvc"].chr, []).append(r["cvc"])
    out = []
    for r in results:
        if "error" in r:
            out.append(r)
            continue
        c: CVC = r["cvc"]
        issuers = by_chr.get(c.car, [])
        # domain parameters: walk up (breadth first over every certificate with
        # the issuer's CHR) until a key carrying 0x81..0x85 is found
        def find_dom(chr_: str, depth: int = 0):
            cands = by_chr.get(chr_, [])
            for cand in cands:
                if 0x81 in cand.pk and 0x84 in cand.pk:
                    return cand.pk
            if depth < 8:
                for cand in cands:
                    if cand.car != cand.chr:
                        r = find_dom(cand.car, depth + 1)
                        if r is not None:
                            return r
            return None

        dom = c.pk if 0x81 in c.pk and 0x84 in c.pk else find_dom(c.car)
        verdict = "no issuer in set" if not issuers else None
        for iss in issuers:
            alg = OID_TA.get(iss.pk_oid)
            if alg is None:
                verdict = f"unknown TA OID {iss.pk_oid}"
                continue
            if alg[0] == "ecdsa":
                idom = iss.pk if 0x81 in iss.pk else dom
                if idom is None or 0x86 not in iss.pk:
                    verdict = "no domain parameters reachable"
                    continue
                ok = ecdsa_verify(idom, iss.pk[0x86], c.body, c.signature, alg[1])
            else:
                ok = rsa_verify(int.from_bytes(iss.pk[0x81], "big"), int.from_bytes(iss.pk[0x82], "big"), c.body, c.signature, alg[1], alg[2])
            if ok:
                verdict = "signature ok"
                break
            verdict = "SIGNATURE INVALID"
        out.append({"file": r["file"], "chr": c.chr, "car": c.car, "role": c.role(), "alg": c.pk_oid, "chat": c.chat_oid, "eff": c.date(c.eff), "exp": c.date(c.exp), "ext": c.extensions is not None, "verify": verdict})
    return out


def main() -> None:
    argv = sys.argv[1:]
    issuers = []
    while "--issuers" in argv:
        i = argv.index("--issuers")
        issuers.append(pathlib.Path(argv[i + 1]))
        del argv[i : i + 2]
    args = [a for a in argv if not a.startswith("--")]
    as_json = "--json" in argv
    allres = {}
    for d in args:
        res = check_dir(pathlib.Path(d), issuers)
        allres[d] = res
        if not as_json:
            print(f"== {d}")
            for r in res:
                if "error" in r:
                    print(f"  {r['file']:48s} {r['error']}")
                else:
                    print(f"  {r['file']:48s} {r['role']:11s} {r['chr']:17s} <- {r['car']:17s} {r['eff']}..{r['exp']} {r['verify']}")
    if as_json:
        print(json.dumps(allres, indent=1))


if __name__ == "__main__":
    main()
