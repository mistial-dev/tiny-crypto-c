/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>

#if defined(TC_TEST_HEADER_RSA)
#if !defined(TINY_CRYPTO_RSA_H_) || !defined(TINY_CRYPTO_RSA_HPP_)
#error "The C++ umbrella must expose the enabled C and C++ RSA declarations"
#endif
static tiny_crypto::rsa_public_key tc_header_rsa_key;
#endif

#if defined(TC_TEST_HEADER_X509)
#if !defined(TINY_CRYPTO_X509_H_) || !defined(TINY_CRYPTO_X509_CRYPTO_H_)
#error "The C++ umbrella must expose the X.509 reader C API"
#endif
#if defined(TINY_CRYPTO_KEY_CHALLENGE_H_)
#error "The base X.509 profile must not expose key challenges"
#endif
#endif

#if defined(TC_TEST_HEADER_KEY_CHALLENGE) && !defined(TINY_CRYPTO_KEY_CHALLENGE_H_)
#error "The C++ umbrella must expose the key challenge C API"
#endif

#if defined(TC_TEST_HEADER_PIV_OBJECTS)
#if !defined(TINY_CRYPTO_CMS_H_) || !defined(TINY_CRYPTO_PIV_OID_H_) || \
    !defined(TINY_CRYPTO_PIV_CERTIFICATE_H_) || \
    !defined(TINY_CRYPTO_PIV_CARD_H_) || !defined(TINY_CRYPTO_PIV_CMS_H_) || \
    !defined(TINY_CRYPTO_LDS_H_) || !defined(TINY_CRYPTO_FASCN_H_) || \
    !defined(TINY_CRYPTO_TWIC_UUID_H_) || !defined(TINY_CRYPTO_PIV_SECURITY_H)
#error "The C++ umbrella must expose the PIV object C API"
#endif
static TC_PIV_card_identifiers tc_header_card_identifiers;
#endif

#if defined(TC_TEST_HEADER_TLV)
#if !defined(TINY_CRYPTO_TLV_H_) || !defined(TINY_CRYPTO_TLV_HPP_)
#error "The C++ umbrella must expose the TLV wrapper"
#endif
#endif

#if defined(TC_TEST_HEADER_AAMVA) && !defined(TINY_CRYPTO_AAMVA_H_)
#error "The C++ umbrella must expose the AAMVA C API"
#endif

#if defined(TC_TEST_HEADER_FASCN) && !defined(TINY_CRYPTO_FASCN_H_)
#error "The C++ umbrella must expose the FASC-N C API"
#endif

#if defined(TC_TEST_HEADER_TWIC_UUID) && !defined(TINY_CRYPTO_TWIC_UUID_H_)
#error "The C++ umbrella must expose the TWIC UUID C API"
#endif

#if defined(TC_TEST_HEADER_X509_PATH) && \
    (!defined(TINY_CRYPTO_X509_PATH_H_) || !defined(TINY_CRYPTO_X509_STORE_H_))
#error "The C++ umbrella must expose the X.509 path C API"
#endif

#if defined(TC_TEST_HEADER_X509_REVOCATION) && \
    (!defined(TINY_CRYPTO_X509_CRL_H_) || !defined(TINY_CRYPTO_X509_REVOCATION_H_))
#error "The C++ umbrella must expose the X.509 revocation C API"
#endif

#if defined(TC_TEST_HEADER_CMS) && !defined(TINY_CRYPTO_CMS_H_)
#error "The C++ umbrella must expose the CMS C API"
#endif
#if defined(TC_TEST_HEADER_PIV_OIDS) && !defined(TINY_CRYPTO_PIV_OID_H_)
#error "The C++ umbrella must expose the PIV/TWIC identifier C API"
#endif
#if defined(TC_TEST_HEADER_CMS) && \
    (defined(TINY_CRYPTO_CMS_VALIDATION_H_) || defined(TINY_CRYPTO_X509_PATH_H_) || \
     defined(TINY_CRYPTO_X509_REVOCATION_H_))
#error "The base CMS profile must not expose path or revocation APIs"
#endif
#if defined(TC_TEST_HEADER_CMS_VALIDATION) && \
    !defined(TINY_CRYPTO_CMS_VALIDATION_H_)
#error "The C++ umbrella must expose the CMS validation C API"
#endif

#if defined(TC_TEST_HEADER_CREDENTIAL) && \
    (!defined(TINY_CRYPTO_CREDENTIAL_H_) || !defined(TINY_CRYPTO_VALIDATION_H_))
#error "The C++ umbrella must expose credential validation C APIs"
#endif

#if defined(TC_TEST_HEADER_TWIC_TPK)
#if !defined(TINY_CRYPTO_TWIC_TPK_H_)
#error "The C++ umbrella must expose the TWIC TPK C API"
#endif
static TC_TWIC_tpk tc_header_tpk;
#endif

#if defined(TC_TEST_HEADER_PIV_CVC) && !defined(TINY_CRYPTO_PIV_CVC_H_)
#error "The C++ umbrella must expose the enabled PIV CVC C API"
#endif

#if defined(TC_TEST_HEADER_PIV_CHUID) && !defined(TINY_CRYPTO_PIV_CHUID_H_)
#error "The C++ umbrella must expose the enabled PIV CHUID C API"
#endif

#if defined(TC_TEST_HEADER_PIV_SM) && \
    (!defined(TINY_CRYPTO_PIV_SM_H_) || !defined(TINY_CRYPTO_PIV_SM_HPP_))
#error "The C++ umbrella must expose the standalone PIV secure messaging wrapper"
#endif

#if defined(TC_TEST_HEADER_TWIC_CCL) && !defined(TINY_CRYPTO_TWIC_CCL_H_)
#error "The C++ umbrella must expose the enabled TWIC CCL C API"
#endif

void tiny_crypto_cpp_umbrella_compile()
{
#if defined(TC_TEST_HEADER_RSA)
    (void)tc_header_rsa_key;
#endif
#if defined(TC_TEST_HEADER_PIV_OBJECTS)
  (void)tc_header_card_identifiers;
#endif
#if defined(TC_TEST_HEADER_TWIC_TPK)
  (void)tc_header_tpk;
#endif
}
