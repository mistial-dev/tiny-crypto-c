# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Print fresh public RSA fixtures. Requires Python cryptography; keys stay in memory."""
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

message = b"tiny-crypto-c role verification"
print("/* SPDX-FileCopyrightText: Mistial Dev\n * SPDX-License-Identifier: GPL-2.0-or-later */")
print("/* Synthetic public fixtures from generate_rsa.py. */")
print("static const char rsa_digest[] = \"" + hashlib.sha256(message).hexdigest() + "\";")
print("static const struct { unsigned bits; const char *spki, *v15, *pss; } rsa_vectors[] = {")
for bits in (1024, 2048, 3072):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public = key.public_key()
    encoded = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signatures = []
    for scheme in (padding.PKCS1v15(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)):
        signature = key.sign(message, scheme, hashes.SHA256())
        public.verify(signature, message, scheme, hashes.SHA256())
        signatures.append(signature)
    print("  {" + str(bits) + ",")
    for index, data in enumerate((encoded, *signatures)):
        text = data.hex()
        for offset in range(0, len(text), 96):
            suffix = "," if offset + 96 >= len(text) and index < 2 else ""
            print('    "' + text[offset:offset + 96] + '"' + suffix)
    print("  },")
print("};")
