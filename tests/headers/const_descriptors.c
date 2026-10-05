/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* Compile-only probe. Every public entry that takes a workspace descriptor
 * receives a const descriptor here. A declaration that drops const fails this
 * object under -Werror in C and as a conversion error in C++, which the
 * const_descriptors.cpp translation unit compiles. Pointers other than the
 * descriptors are NULL because the probe never runs. */
#include <stddef.h>
#include <tiny_crypto/cms.h>
#include <tiny_crypto/cms_validation.h>
#include <tiny_crypto/credential.h>
#include <tiny_crypto/eac_cvc.h>
#include <tiny_crypto/rsa.h>
#include <tiny_crypto/validation.h>
#include <tiny_crypto/x509.h>
#include <tiny_crypto/x509_crl.h>
#include <tiny_crypto/x509_crl_source.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_ocsp.h>
#include <tiny_crypto/x509_path.h>
#include <tiny_crypto/x509_revocation.h>
#include <tiny_crypto/x509_store.h>
#include <tiny_crypto/x509_trust_anchor.h>

typedef struct {
  const TC_X509_workspace* x509;
  const TC_X509_name_workspace* names;
  const TC_X509_constraint_workspace* constraints;
  const TC_X509_path_workspace* path;
  const TC_X509_search_workspace* search;
  const TC_X509_revocation_workspace* revocation;
  const TC_X509_crl_prepare_workspace* crl_prepare;
  const TC_X509_native_workspace* native;
  const TC_CMS_signature_workspace* cms_signature;
  const TC_CMS_path_workspace* cms_path;
  const TC_CMS_credential_workspace* cms_credential;
  const TC_PIV_security_validation_workspace* security;
  const TC_EAC_CVC_workspace* eac_cvc;
  const TC_RSA_workspace* rsa;
} tc_const_descriptors;

int tc_const_descriptor_probe(const tc_const_descriptors* d);

static int x509_probe(const tc_const_descriptors* d, TC_bytes none)
{
  int r = 0;
  r += (int)TC_X509_read(none, NULL, d->x509, NULL);
  r += (int)TC_X509_name_equal(none, none, NULL, d->names, NULL, NULL);
  r += (int)TC_X509_name_within(none, none, NULL, d->names, NULL, NULL);
  r += (int)TC_X509_issuer_check(NULL, none, NULL, NULL, NULL, d->names, NULL);
  r += (int)TC_X509_general_name_within(NULL, NULL, NULL, d->names, NULL, NULL);
  r += (int)TC_X509_name_constraints_check(NULL, NULL, NULL, d->constraints, NULL, NULL);
  r += (int)TC_X509_certificate_names_check(NULL, NULL, NULL, d->constraints, NULL, NULL);
  r += (int)TC_X509_crl_extensions_read(none, NULL, d->x509, NULL, NULL);
  r += (int)TC_X509_crl_index_init(NULL, 0, NULL, d->x509, NULL, NULL, 0, NULL);
  r += (int)TC_X509_crl_prepare_begin(NULL, NULL, 0, NULL, d->crl_prepare, NULL, NULL);
  r += (int)TC_X509_store_anchor_from_certificate(NULL, NULL, d->x509, NULL);
  r += (int)TC_X509_trust_anchor_list_init(NULL, none, NULL, d->x509);
  const TC_X509_signature_provider provider = TC_X509_native_provider(d->native);
  r += provider.context != NULL;
  return r;
}

static int path_probe(const tc_const_descriptors* d, TC_bytes none)
{
  const TC_buffer empty = {NULL, 0};
  int r = 0;
  r += (int)TC_X509_path_build(none, NULL, NULL, d->path, d->search, NULL);
  r += (int)TC_X509_path_validate(NULL, 0, NULL, NULL, d->path, NULL);
  r += (int)TC_X509_path_validate_with_anchor(NULL, 0, NULL, NULL, d->path, NULL);
  r += (int)TC_X509_path_check_revocation(NULL, 0, NULL, d->revocation, NULL, NULL);
  r += (int)TC_X509_ocsp_response_verify(NULL, d->path, NULL, NULL);
  r += (int)TC_X509_ocsp_request_encode(NULL, d->path, NULL, empty, NULL);
  return r;
}

static int cms_probe(const tc_const_descriptors* d, TC_bytes none)
{
  int r = 0;
  r += (int)TC_CMS_signer_verify_digest(NULL, none, d->cms_signature, NULL);
  r += (int)TC_CMS_signer_verify_content(NULL, none, TC_CMS_CONTENT_RAW, d->cms_signature, NULL);
  r += (int)TC_CMS_signer_path_build(NULL, NULL, NULL, d->cms_path, NULL, NULL);
  r += (int)TC_CMS_signed_data_path_build(NULL, NULL, NULL, d->cms_path, NULL, NULL);
  r += (int)TC_CMS_credential_validate(NULL, NULL, NULL, NULL, d->cms_credential, NULL);
  r += (int)TC_validation_context_init(NULL, NULL, d->cms_credential, NULL);
  r += (int)TC_PIV_security_authenticate(NULL, NULL, d->security, NULL, NULL);
  r += (int)TC_PIV_security_validate(NULL, NULL, d->security, NULL, NULL);
  r += (int)TC_EAC_CVC_read(none, NULL, d->eac_cvc, NULL);
  return r;
}

static int rsa_probe(const tc_const_descriptors* d, TC_bytes none)
{
  const TC_buffer empty = {NULL, 0};
  const TC_RSA_keygen_limits limits = {0, 0};
  int r = 0;
  r += (int)TC_RSA_prepare_public_key(NULL, NULL, d->rsa, d->rsa, NULL);
  r += (int)TC_RSA_keygen_init(NULL, 0, TC_APPROVED_ONLY, NULL, limits, d->rsa);
  r += (int)TC_RSA_raw_public(NULL, none, empty, d->rsa, NULL);
  r += (int)TC_RSA_raw_private(NULL, none, none, empty, d->rsa, NULL);
  r += (int)TC_RSA_encrypt_oaep(NULL, NULL, none, empty, d->rsa, NULL);
  r += (int)TC_RSA_decrypt_oaep(NULL, NULL, none, empty, NULL, d->rsa, NULL);
  r += (int)TC_RSA_sign_v15_digest(NULL, NULL, none, empty, d->rsa, NULL);
  r += (int)TC_RSA_sign_pss_digest(NULL, NULL, none, empty, d->rsa, NULL);
  r += (int)TC_RSA_validate_private_key(NULL, TC_RSA_EXPONENT_FIPS, TC_APPROVED_ONLY, d->rsa, NULL);
  r += (int)TC_RSA_validate_crt(NULL, NULL, d->rsa, NULL);
  r += (int)TC_RSA_derive_crt(NULL, NULL, d->rsa, NULL);
  r += (int)TC_RSA_verify_v15_digest(NULL, NULL, none, none, d->rsa, NULL);
  r += (int)TC_RSA_verify_v15_prepared(NULL, NULL, none, none, d->rsa, NULL);
  r += (int)TC_RSA_verify_pss_digest(NULL, NULL, none, none, d->rsa, NULL);
  r += (int)TC_RSA_verify_pss_prepared(NULL, NULL, none, none, d->rsa, NULL);
  return r;
}

int tc_const_descriptor_probe(const tc_const_descriptors* d)
{
  const TC_bytes none = {NULL, 0};
  return x509_probe(d, none) + path_probe(d, none) + cms_probe(d, none) + rsa_probe(d, none);
}
