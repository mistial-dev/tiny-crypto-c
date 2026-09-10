/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <tiny_crypto/tiny_crypto.hpp>
#if TC_ENABLE_X509
#include <tiny_crypto/key_challenge.h>
#include <tiny_crypto/x509_path.h>
#include <tiny_crypto/x509_crl.h>
#include <tiny_crypto/x509_revocation.h>
#include <tiny_crypto/x509_store.h>
#include <tiny_crypto/rsa.h>
#include <tiny_crypto/rsa.hpp>
#endif

void tiny_crypto_cpp_header_compile(void) {
#if TC_ENABLE_PIV_SM
    tiny_crypto::piv_sm session;
    (void)session;
#endif
#if TC_ENABLE_X509
    TC_RSA_result (*validate)(const TC_RSA_private_key*, const TC_RSA_workspace*,
        TC_RSA_execution*) = TC_RSA_validate_private_key;
    tiny_crypto::rsa_result (*validate_cpp)(const tiny_crypto::rsa_private_key&,
        const tiny_crypto::rsa_workspace&, tiny_crypto::rsa_execution&) =
        tiny_crypto::rsa_validate_private_key;
    (void)validate;
    (void)validate_cpp;
#if defined(__AVR__)
    static_assert(sizeof(size_t) == 2, "AVR size_t must be 16-bit");
    static_assert(sizeof(uint32_t) == 4, "RSA validation work must be 32-bit");
#endif
    TC_X509_public_key key = {};
    TC_key_challenge_options challenge_options = {};
    TC_key_challenge_workspace challenge_workspace = {};
    (void)challenge_options;
    (void)challenge_workspace;
    TC_TLV_frame frames[4];
    TC_bytes oids[4], policies[4];
    uint32_t left[8], right[6];
    uint8_t matched[2];
    TC_X509_policy_node nodes[4];
    TC_X509_policy_edge edges[4];
    TC_X509_policy_expected expected[4];
    TC_X509_policy_mapping mappings[4];
    TC_X509_path_workspace workspace = TC_X509_PATH_WORKSPACE_INIT(
        frames, oids, left, right, matched, nodes, edges, expected, mappings, policies);
    (void)workspace;
#endif
#if TC_ENABLE_TLV
    tiny_crypto::TLVReader reader;
    (void)reader;
#endif
#if TC_ENABLE_KMAC256
    tiny_crypto::KMAC256 kmac;
    (void)kmac;
#endif
#if TC_ENABLE_AES
    tiny_crypto::AES aes;
    (void)aes;
#endif
#if TC_ENABLE_SHA256
    tiny_crypto::SHA256 hash;
    (void)hash;
#endif
}
