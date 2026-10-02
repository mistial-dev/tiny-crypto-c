# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Define the Wycheproof documents exercised by tiny-crypto-c tests."""

FIXED_VECTOR_NAMES = frozenset({
    "aead_aes_siv_cmac_test.json", "aes_ccm_test.json", "aes_cmac_test.json",
    "aes_eax_test.json", "aes_gcm_test.json", "aes_gmac_test.json",
    "aes_kwp_test.json", "aes_siv_cmac_test.json", "aes_wrap_test.json",
    "ecdh_secp256r1_ecpoint_test.json", "ecdh_secp256r1_test.json",
    "ecdh_secp384r1_ecpoint_test.json", "ecdh_secp384r1_test.json",
    "hkdf_sha1_test.json", "hkdf_sha256_test.json", "hkdf_sha384_test.json",
    "hkdf_sha512_test.json", "hmac_sha1_test.json", "hmac_sha224_test.json",
    "hmac_sha256_test.json", "hmac_sha384_test.json", "hmac_sha512_test.json",
    "kmac256_no_customization_test.json", "primality_test.json",
})


def supported_vector_names(available_names):
    """Return fixed and algorithm-family documents consumed by the adapters."""
    selected = set(FIXED_VECTOR_NAMES)
    for name in available_names:
        if name.startswith("rsa_pkcs1_") and name.endswith("_sig_gen_test.json"):
            selected.add(name)
        elif name.startswith(("rsa_pss_", "rsa_signature_", "rsa_oaep_", "ecdsa_")) and name.endswith("_test.json"):
            selected.add(name)
    return selected
