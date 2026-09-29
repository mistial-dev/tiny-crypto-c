/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * OCSP responses generated with OpenSSL from throwaway P-256 keys. The cases
 * cover CA-signed and delegated responders, delegate rejections, response
 * structure, nonces, work limits and CRL fallback in the composed path check.
 * OCSP_basic_sign stamps producedAt with the wall clock, so every time is
 * relative to the clock read by hierarchy_init. */
#include "ocsp_fixture.h"
#include "test_util.h"
#include "openssl_fixture.h"
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <time.h>

static ocsp_fixture fixture;

enum { DAY = 86400, TARGET_SERIAL = 0x1234, OTHER_SERIAL = 0x4321, DELEGATE_SERIAL = 7 };

typedef struct {
  EVP_PKEY *ca_key, *responder_key, *other_key;
  X509 *ca, *target, *other_ca;
  uint8_t ca_der[OCSP_FILE_CAPACITY], target_der[OCSP_FILE_CAPACITY];
  TC_bytes ca_bytes, target_bytes;
  TC_X509_trust_anchor anchor;
  TC_X509_time at;
} hierarchy;

static hierarchy pki;
static uint8_t response_bytes[OCSP_FILE_CAPACITY], delegate_bytes[OCSP_FILE_CAPACITY];

/* One certificate below issuer, or self-signed when issuer is NULL. signer
 * signs it, normally the issuer key. */
typedef struct {
  EVP_PKEY* key;
  const char* name;
  X509* issuer;
  EVP_PKEY* signer;
  long serial;
  int expired;
  int ca;
  const char* key_usage;
  const char* extended_key_usage;
  int nocheck;
  int unknown_critical;
} certificate_spec;

static X509_EXTENSION* unknown_extension(int critical)
{
  ASN1_OBJECT* oid = OBJ_txt2obj("1.3.6.1.4.1.55555.1", 1);
  ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
  munit_assert_not_null(oid);
  munit_assert_not_null(value);
  munit_assert_int(ASN1_OCTET_STRING_set(value, (const unsigned char*)"\x05\x00", 2), ==, 1);
  X509_EXTENSION* extension = X509_EXTENSION_create_by_OBJ(NULL, oid, critical, value);
  munit_assert_not_null(extension);
  ASN1_OBJECT_free(oid);
  ASN1_OCTET_STRING_free(value);
  return extension;
}

static X509* issue(const certificate_spec* spec)
{
  X509* certificate = make_certificate(spec->key, spec->name, spec->issuer);
  munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(certificate), spec->serial), ==, 1);
  munit_assert_not_null(
      X509_gmtime_adj(X509_getm_notBefore(certificate), spec->expired ? -60L * DAY : -30L * DAY));
  munit_assert_not_null(
      X509_gmtime_adj(X509_getm_notAfter(certificate), spec->expired ? -1L * DAY : 365L * DAY));
  if (spec->ca)
    add_extension(certificate, NID_basic_constraints, "critical,CA:TRUE");
  if (spec->key_usage)
    add_extension(certificate, NID_key_usage, spec->key_usage);
  if (spec->extended_key_usage)
    add_extension(certificate, NID_ext_key_usage, spec->extended_key_usage);
  if (spec->nocheck)
    add_extension(certificate, NID_id_pkix_OCSP_noCheck, "ignored");
  if (spec->unknown_critical) {
    X509_EXTENSION* extension = unknown_extension(1);
    munit_assert_int(X509_add_ext(certificate, extension, -1), ==, 1);
    X509_EXTENSION_free(extension);
  }
  munit_assert_int(X509_sign(certificate, spec->signer, EVP_sha256()), >, 0);
  return certificate;
}

static TC_bytes certificate_der(X509* certificate, uint8_t der[OCSP_FILE_CAPACITY])
{
  unsigned char* cursor = der;
  const int length = i2d_X509(certificate, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_int(length, <=, OCSP_FILE_CAPACITY);
  munit_assert_int(i2d_X509(certificate, &cursor), ==, length);
  return (TC_bytes){der, (size_t)length};
}

static TC_X509_time utc_time(time_t seconds)
{
  struct tm fields;
  munit_assert_not_null(gmtime_r(&seconds, &fields));
  return (TC_X509_time){
      (unsigned)(fields.tm_year + 1900), (uint8_t)(fields.tm_mon + 1), (uint8_t)fields.tm_mday,
      (uint8_t)fields.tm_hour,           (uint8_t)fields.tm_min,       (uint8_t)fields.tm_sec};
}

/* A CA, a target it issued with serial 0x1234 and an unrelated CA. */
static void hierarchy_init(void)
{
  ocsp_fixture_init(&fixture);
  pki.ca_key = EVP_EC_gen("prime256v1");
  pki.responder_key = EVP_EC_gen("prime256v1");
  pki.other_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(pki.ca_key);
  munit_assert_not_null(pki.responder_key);
  munit_assert_not_null(pki.other_key);
  const certificate_spec ca = {.key = pki.ca_key,
                               .name = "tiny-crypto-c OCSP CA",
                               .signer = pki.ca_key,
                               .serial = 1,
                               .ca = 1,
                               .key_usage = "critical,keyCertSign,cRLSign"};
  pki.ca = issue(&ca);
  const certificate_spec other = {.key = pki.other_key,
                                  .name = "tiny-crypto-c other CA",
                                  .signer = pki.other_key,
                                  .serial = 1,
                                  .ca = 1,
                                  .key_usage = "critical,keyCertSign,cRLSign"};
  pki.other_ca = issue(&other);
  EVP_PKEY* target_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(target_key);
  const certificate_spec target = {.key = target_key,
                                   .name = "tiny-crypto-c OCSP target",
                                   .issuer = pki.ca,
                                   .signer = pki.ca_key,
                                   .serial = TARGET_SERIAL,
                                   .key_usage = "critical,digitalSignature"};
  pki.target = issue(&target);
  EVP_PKEY_free(target_key);
  pki.ca_bytes = certificate_der(pki.ca, pki.ca_der);
  pki.target_bytes = certificate_der(pki.target, pki.target_der);
  TC_X509_certificate view;
  munit_assert_int(TC_X509_read(pki.ca_bytes, &fixture.limits, &fixture.parser, &view), ==,
                   TC_TLV_OK);
  pki.anchor = (TC_X509_trust_anchor){view.subject, view.public_key};
  pki.at = utc_time(time(NULL));
}

static void hierarchy_free(void)
{
  X509_free(pki.ca);
  X509_free(pki.target);
  X509_free(pki.other_ca);
  EVP_PKEY_free(pki.ca_key);
  EVP_PKEY_free(pki.responder_key);
  EVP_PKEY_free(pki.other_key);
  memset(&pki, 0, sizeof pki);
}

/* An OCSP delegate for the CA. The default authorizes it (RFC 6960
 * 4.2.2.2). Tests adjust one field per rejection. */
static certificate_spec delegate_spec(void)
{
  const certificate_spec spec = {.key = pki.responder_key,
                                 .name = "tiny-crypto-c OCSP responder",
                                 .issuer = pki.ca,
                                 .signer = pki.ca_key,
                                 .serial = DELEGATE_SERIAL,
                                 .key_usage = "critical,digitalSignature",
                                 .extended_key_usage = "OCSPSigning"};
  return spec;
}

/* The target SingleResponse and its surroundings. The default is a GOOD
 * status with a SHA-1 CertID, thisUpdate one hour ago and nextUpdate a day
 * ahead, signed by signer and key with the signer certificate embedded. */
typedef struct {
  X509* signer;
  EVP_PKEY* key;
  unsigned long flags;
  const EVP_MD* cert_id_hash;
  X509* cert_id_issuer;
  int status, reason;
  int copies, other_first, no_next_update;
  const uint8_t* nonce;
  size_t nonce_length;
  OCSP_REQUEST* request;
  /* Extensions for responseExtensions, the target entry and the entry that
   * other_first adds. */
  int response_extension, single_extension, other_extension;
  int corrupt_signature;
} response_spec;

static response_spec response_by(X509* signer, EVP_PKEY* key)
{
  response_spec spec;
  memset(&spec, 0, sizeof spec);
  spec.signer = signer;
  spec.key = key;
  spec.status = V_OCSP_CERTSTATUS_GOOD;
  spec.reason = OCSP_REVOKED_STATUS_NOSTATUS;
  return spec;
}

/* Extension selectors for response_extension and single_extension. */
enum { NO_EXTENSION, NONCRITICAL_UNKNOWN, CRITICAL_UNKNOWN, CRITICAL_NONCE };

static void add_extensions(int kind, OCSP_BASICRESP* basic, OCSP_SINGLERESP* single)
{
  X509_EXTENSION* extension = NULL;
  if (kind == NONCRITICAL_UNKNOWN || kind == CRITICAL_UNKNOWN)
    extension = unknown_extension(kind == CRITICAL_UNKNOWN);
  if (kind == CRITICAL_NONCE) {
    /* extnValue OCTET STRING { OCTET STRING nonce } (RFC 9654 2.1). */
    static const uint8_t value[] = {4,  32, 1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                    23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    ASN1_OCTET_STRING* octets = ASN1_OCTET_STRING_new();
    munit_assert_not_null(octets);
    munit_assert_int(ASN1_OCTET_STRING_set(octets, value, sizeof value), ==, 1);
    extension = X509_EXTENSION_create_by_NID(NULL, NID_id_pkix_OCSP_Nonce, 1, octets);
    ASN1_OCTET_STRING_free(octets);
  }
  if (!extension)
    return;
  if (single)
    munit_assert_int(OCSP_SINGLERESP_add_ext(single, extension, -1), ==, 1);
  else
    munit_assert_int(OCSP_BASICRESP_add_ext(basic, extension, -1), ==, 1);
  X509_EXTENSION_free(extension);
}

static OCSP_SINGLERESP* add_status(OCSP_BASICRESP* basic, OCSP_CERTID* id,
                                   const response_spec* spec)
{
  ASN1_TIME* this_update = X509_gmtime_adj(NULL, -3600);
  ASN1_TIME* next_update = spec->no_next_update ? NULL : X509_gmtime_adj(NULL, DAY);
  ASN1_TIME* revoked = X509_gmtime_adj(NULL, -7L * DAY);
  munit_assert_not_null(this_update);
  munit_assert_not_null(revoked);
  OCSP_SINGLERESP* single = OCSP_basic_add1_status(basic, id, spec->status, spec->reason, revoked,
                                                   this_update, next_update);
  munit_assert_not_null(single);
  ASN1_TIME_free(this_update);
  ASN1_TIME_free(next_update);
  ASN1_TIME_free(revoked);
  return single;
}

static TC_bytes build_response(const response_spec* spec, uint8_t out[OCSP_FILE_CAPACITY])
{
  const EVP_MD* hash = spec->cert_id_hash ? spec->cert_id_hash : EVP_sha1();
  OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
  munit_assert_not_null(basic);
  if (spec->other_first) {
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    munit_assert_not_null(serial);
    munit_assert_int(ASN1_INTEGER_set(serial, OTHER_SERIAL), ==, 1);
    OCSP_CERTID* other = OCSP_cert_id_new(hash, X509_get_subject_name(pki.ca),
                                          X509_get0_pubkey_bitstr(pki.ca), serial);
    munit_assert_not_null(other);
    add_extensions(spec->other_extension, basic, add_status(basic, other, spec));
    OCSP_CERTID_free(other);
    ASN1_INTEGER_free(serial);
  }
  OCSP_CERTID* id =
      OCSP_cert_to_id(hash, pki.target, spec->cert_id_issuer ? spec->cert_id_issuer : pki.ca);
  munit_assert_not_null(id);
  OCSP_SINGLERESP* single = NULL;
  for (int i = 0; i < (spec->copies ? spec->copies : 1); ++i)
    single = add_status(basic, id, spec);
  OCSP_CERTID_free(id);
  add_extensions(spec->single_extension, basic, single);
  if (spec->nonce_length)
    munit_assert_int(OCSP_basic_add1_nonce(basic, (unsigned char*)(uintptr_t)spec->nonce,
                                           (int)spec->nonce_length),
                     ==, 1);
  if (spec->request)
    munit_assert_int(OCSP_copy_nonce(basic, spec->request), ==, 1);
  add_extensions(spec->response_extension, basic, NULL);
  munit_assert_int(OCSP_basic_sign(basic, spec->signer, spec->key, EVP_sha256(), NULL, spec->flags),
                   ==, 1);
  OCSP_RESPONSE* response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
  munit_assert_not_null(response);
  OCSP_BASICRESP_free(basic);
  unsigned char* cursor = out;
  const int length = i2d_OCSP_RESPONSE(response, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_int(length, <=, OCSP_FILE_CAPACITY);
  munit_assert_int(i2d_OCSP_RESPONSE(response, &cursor), ==, length);
  OCSP_RESPONSE_free(response);
  if (spec->corrupt_signature) {
    /* Without embedded certificates the signature BIT STRING ends the DER. */
    munit_assert_true(spec->flags & OCSP_NOCERTS);
    out[length - 1] ^= 1;
  }
  return (TC_bytes){out, (size_t)length};
}

static TC_X509_ocsp_verify_request target_request(TC_bytes response)
{
  return ocsp_request(&fixture, response, pki.target_bytes, &pki.anchor, pki.at);
}

/* Verify and check the documented output state: a wiped result on failure. */
static TC_TLV_result verify_with(const TC_X509_ocsp_verify_request* request,
                                 TC_X509_ocsp_result* result)
{
  size_t work = 20000000;
  memset(result, 0x5a, sizeof *result);
  const TC_TLV_result status =
      TC_X509_ocsp_response_verify(request, &fixture.workspace, &work, result);
  if (status != TC_TLV_OK)
    ocsp_assert_wiped(result);
  return status;
}

static TC_TLV_result verify(const response_spec* spec, const TC_X509_store_source* store,
                            TC_X509_ocsp_result* result)
{
  TC_X509_ocsp_verify_request request = target_request(build_response(spec, response_bytes));
  request.certificates = store;
  return verify_with(&request, result);
}

/* A response signed by the CA itself, identified byName or byKey (RFC 6960
 * 4.2.1 and 4.2.2.2), reports its status and no delegate. */
TC_TEST(ca_signed)
{
  const unsigned long forms[] = {OCSP_NOCERTS, OCSP_NOCERTS | OCSP_RESPID_KEY, 0};
  TC_X509_ocsp_result result;
  hierarchy_init();
  for (size_t i = 0; i < sizeof forms / sizeof *forms; ++i) {
    response_spec spec = response_by(pki.ca, pki.ca_key);
    spec.flags = forms[i];
    munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
    munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
    munit_assert_true(result.has_next_update);
    munit_assert_false(result.has_reason);
    munit_assert_null(result.responder_certificate.data);
    munit_assert_false(result.responder_nocheck);
  }

  /* revokedInfo with and without a CRLReason (RFC 6960 4.2.1). */
  response_spec spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  spec.status = V_OCSP_CERTSTATUS_REVOKED;
  spec.reason = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_true(result.has_reason);
  munit_assert_uint(result.reason, ==, 1);
  const TC_X509_time week_ago = utc_time(time(NULL) - 7L * DAY);
  munit_assert_uint(result.revocation_time.year, ==, week_ago.year);
  munit_assert_uint(result.revocation_time.month, ==, week_ago.month);
  munit_assert_uint(result.revocation_time.day, ==, week_ago.day);
  spec.reason = OCSP_REVOKED_STATUS_NOSTATUS;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_false(result.has_reason);
  /* removeFromCRL belongs to delta CRLs only (RFC 5280 5.3.1). */
  spec.reason = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  /* An authenticated unknown status gives no decision. */
  spec.status = V_OCSP_CERTSTATUS_UNKNOWN;
  spec.reason = OCSP_REVOKED_STATUS_NOSTATUS;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_UNSUPPORTED);

  /* Without nextUpdate the response needs a max_age_seconds bound. */
  spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  spec.no_next_update = 1;
  TC_X509_ocsp_verify_request request = target_request(build_response(&spec, response_bytes));
  request.time.max_age_seconds = 0;
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);
  request.time.max_age_seconds = 7200;
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_OK);
  munit_assert_false(result.has_next_update);
  request.time.max_age_seconds = 600;
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);
  /* The evaluation time must follow producedAt within the clock skew. */
  request.time.max_age_seconds = 0;
  request.time.at = utc_time(time(NULL) - 2 * 3600);
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);

  /* A bad signature under the matching issuer name finds no signer. */
  spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  spec.corrupt_signature = 1;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  spec.flags = OCSP_NOCERTS | OCSP_RESPID_KEY;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  /* The unrelated CA signs byName with its own name: no authorized signer. */
  spec = response_by(pki.other_ca, pki.other_key);
  spec.flags = OCSP_NOCERTS;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  spec.flags = 0;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  hierarchy_free();
  return MUNIT_OK;
}

/* CertID hashes: SHA-1 and SHA-256 are supported. Any other hash is
 * UNSUPPORTED. A CertID naming another issuer covers no certificate. */
TC_TEST(cert_id)
{
  TC_X509_ocsp_result result;
  hierarchy_init();
  response_spec spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  spec.cert_id_hash = EVP_sha256();
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
  spec.cert_id_hash = EVP_sha384();
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_UNSUPPORTED);
  spec.cert_id_hash = EVP_sha512();
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_UNSUPPORTED);
  spec.cert_id_hash = NULL;
  spec.cert_id_issuer = pki.other_ca;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  hierarchy_free();
  return MUNIT_OK;
}

/* Delegates embedded in the response or supplied through the store, named
 * byName or byKey. The result reports the delegate and id-pkix-ocsp-nocheck
 * (RFC 6960 4.2.2.2 and 4.2.2.2.1). */
TC_TEST(delegates)
{
  const unsigned long forms[] = {0, OCSP_RESPID_KEY};
  TC_X509_ocsp_result result;
  hierarchy_init();
  for (int nocheck = 0; nocheck < 2; ++nocheck) {
    certificate_spec authorized = delegate_spec();
    authorized.nocheck = nocheck;
    X509* delegate = issue(&authorized);
    const TC_bytes delegate_der = certificate_der(delegate, delegate_bytes);
    const TC_X509_store_array array = {&delegate_der, 1, NULL, 0};
    TC_X509_store_source store;
    munit_assert_int(TC_X509_store_array_source(&array, &store), ==, TC_TLV_OK);
    for (size_t i = 0; i < 2; ++i) {
      response_spec spec = response_by(delegate, pki.responder_key);
      spec.flags = forms[i];
      munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
      munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
      munit_assert_true(ocsp_span_within(result.responder_certificate,
                                         (TC_bytes){response_bytes, sizeof response_bytes}));
      munit_assert_size(result.responder_certificate.length, ==, delegate_der.length);
      munit_assert_memory_equal(delegate_der.length, result.responder_certificate.data,
                                delegate_der.data);
      munit_assert_int(result.responder_nocheck, ==, nocheck);

      spec.flags = forms[i] | OCSP_NOCERTS;
      munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
      munit_assert_int(verify(&spec, &store, &result), ==, TC_TLV_OK);
      munit_assert_ptr_equal(result.responder_certificate.data, delegate_der.data);
      munit_assert_int(result.responder_nocheck, ==, nocheck);
      /* A signature by the delegate that does not verify. */
      spec.corrupt_signature = 1;
      munit_assert_int(verify(&spec, &store, &result), ==, TC_TLV_INVALID);
    }
    X509_free(delegate);
  }
  /* A present keyUsage is optional for a delegate. */
  certificate_spec no_key_usage = delegate_spec();
  no_key_usage.key_usage = NULL;
  X509* delegate = issue(&no_key_usage);
  response_spec spec = response_by(delegate, pki.responder_key);
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
  X509_free(delegate);
  hierarchy_free();
  return MUNIT_OK;
}

/* A delegate must be issued by the CA, carry id-kp-OCSPSigning, be valid at
 * the evaluation time, allow digitalSignature when keyUsage is present and
 * have no unknown critical extension (RFC 6960 4.2.2.2, RFC 5280 4.2). Each
 * rejected delegate leaves the response without an authorized signer. */
TC_TEST(delegate_rejections)
{
  enum { CASES = 8 };
  TC_X509_ocsp_result result;
  hierarchy_init();
  for (int i = 0; i < CASES; ++i) {
    certificate_spec rejected = delegate_spec();
    switch (i) {
    case 0:
      rejected.extended_key_usage = NULL;
      break;
    case 1:
      rejected.extended_key_usage = "serverAuth,clientAuth";
      break;
    case 2:
      rejected.extended_key_usage = "anyExtendedKeyUsage";
      break;
    case 3:
      /* Issued by another CA under its own name. */
      rejected.issuer = pki.other_ca;
      rejected.signer = pki.other_key;
      break;
    case 4:
      /* Names the CA as issuer but carries another key's signature. */
      rejected.signer = pki.other_key;
      break;
    case 5:
      rejected.expired = 1;
      break;
    case 6:
      rejected.key_usage = "critical,keyAgreement";
      break;
    default:
      rejected.unknown_critical = 1;
      break;
    }
    X509* delegate = issue(&rejected);
    const TC_bytes delegate_der = certificate_der(delegate, delegate_bytes);
    const TC_X509_store_array array = {&delegate_der, 1, NULL, 0};
    TC_X509_store_source store;
    munit_assert_int(TC_X509_store_array_source(&array, &store), ==, TC_TLV_OK);
    response_spec spec = response_by(delegate, pki.responder_key);
    munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
    spec.flags = OCSP_NOCERTS | OCSP_RESPID_KEY;
    munit_assert_int(verify(&spec, &store, &result), ==, TC_TLV_INVALID);
    X509_free(delegate);
  }
  hierarchy_free();
  return MUNIT_OK;
}

/* responses may hold other certificates' SingleResponses. The target must
 * appear once. max_responses bounds every SingleResponse read. */
TC_TEST(single_responses)
{
  TC_X509_ocsp_result result;
  hierarchy_init();
  response_spec spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  spec.other_first = 1;
  TC_X509_ocsp_verify_request request = target_request(build_response(&spec, response_bytes));
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_OK);
  request.max_responses = 2;
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_OK);
  request.max_responses = 1;
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_LIMIT);

  spec.other_first = 0;
  spec.copies = 2;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  spec.copies = 3;
  spec.status = V_OCSP_CERTSTATUS_REVOKED;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  hierarchy_free();
  return MUNIT_OK;
}

/* Unknown noncritical extensions are ignored. An unknown critical extension
 * in responseExtensions or singleExtensions is UNSUPPORTED (RFC 6960 4.4,
 * RFC 5280 4.2). A nonce is noncritical and only in responseExtensions
 * (RFC 9654 2.1). */
TC_TEST(extensions)
{
  TC_X509_ocsp_result result;
  hierarchy_init();
  response_spec spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  spec.response_extension = NONCRITICAL_UNKNOWN;
  spec.single_extension = NONCRITICAL_UNKNOWN;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
  spec.single_extension = CRITICAL_UNKNOWN;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_UNSUPPORTED);
  spec.single_extension = NO_EXTENSION;
  spec.response_extension = CRITICAL_UNKNOWN;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_UNSUPPORTED);
  /* A critical unknown extension on another certificate's entry. */
  spec.response_extension = NO_EXTENSION;
  spec.other_first = 1;
  spec.other_extension = NONCRITICAL_UNKNOWN;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_OK);
  spec.other_extension = CRITICAL_UNKNOWN;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_UNSUPPORTED);
  spec.other_first = 0;
  spec.single_extension = CRITICAL_NONCE;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  spec.single_extension = NO_EXTENSION;
  spec.response_extension = CRITICAL_NONCE;
  munit_assert_int(verify(&spec, NULL, &result), ==, TC_TLV_INVALID);
  hierarchy_free();
  return MUNIT_OK;
}

/* Encode a request with a nonce, answer it with OpenSSL copying the nonce
 * and verify the echo (RFC 6960 4.1.1, RFC 9654 2.1). Nonces outside
 * 32..128 octets are argument errors, and a missing or different echo is
 * INVALID. */
TC_TEST(nonce)
{
  uint8_t nonce_bytes[130], encoded[512];
  TC_X509_ocsp_result result;
  hierarchy_init();
  for (size_t i = 0; i < sizeof nonce_bytes; ++i)
    nonce_bytes[i] = (uint8_t)(0x40 + i);
  const size_t lengths[] = {32, 33, 128};
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    const TC_bytes sent = {nonce_bytes, lengths[i]};
    const TC_X509_ocsp_encode_request encode = {pki.target_bytes, &pki.anchor, TC_HASH_SHA256, sent,
                                                &fixture.limits};
    size_t work = 20000000, length = 0;
    munit_assert_int(TC_X509_ocsp_request_encode(&encode, &fixture.workspace, &work,
                                                 (TC_buffer){encoded, sizeof encoded}, &length),
                     ==, TC_TLV_OK);
    /* OpenSSL reads the same CertID and nonce. */
    const unsigned char* cursor = encoded;
    OCSP_REQUEST* parsed = d2i_OCSP_REQUEST(NULL, &cursor, (long)length);
    munit_assert_not_null(parsed);
    munit_assert_ptr_equal(cursor, encoded + length);
    munit_assert_int(OCSP_request_onereq_count(parsed), ==, 1);
    OCSP_CERTID* expected = OCSP_cert_to_id(EVP_sha256(), pki.target, pki.ca);
    munit_assert_int(
        OCSP_id_cmp(OCSP_onereq_get0_id(OCSP_request_onereq_get0(parsed, 0)), expected), ==, 0);
    OCSP_CERTID_free(expected);

    response_spec spec = response_by(pki.ca, pki.ca_key);
    spec.flags = OCSP_NOCERTS;
    spec.cert_id_hash = EVP_sha256();
    spec.request = parsed;
    TC_X509_ocsp_verify_request request = target_request(build_response(&spec, response_bytes));
    request.expected_nonce = sent;
    munit_assert_int(verify_with(&request, &result), ==, TC_TLV_OK);
    /* A response nonce is accepted without an expected one. */
    request.expected_nonce = (TC_bytes){NULL, 0};
    munit_assert_int(verify_with(&request, &result), ==, TC_TLV_OK);
    uint8_t changed[128];
    memcpy(changed, nonce_bytes, lengths[i]);
    changed[lengths[i] - 1] ^= 1;
    request.expected_nonce = (TC_bytes){changed, lengths[i]};
    munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);
    OCSP_REQUEST_free(parsed);
  }

  /* No echo, or an echo of another length. */
  response_spec spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  TC_X509_ocsp_verify_request request = target_request(build_response(&spec, response_bytes));
  request.expected_nonce = (TC_bytes){nonce_bytes, 32};
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);
  spec.nonce = nonce_bytes;
  spec.nonce_length = 16;
  request = target_request(build_response(&spec, response_bytes));
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_OK);
  request.expected_nonce = (TC_bytes){nonce_bytes, 32};
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);
  /* RFC 9654 2.1 limits the nonce to 128 octets. */
  spec.nonce_length = 129;
  request = target_request(build_response(&spec, response_bytes));
  munit_assert_int(verify_with(&request, &result), ==, TC_TLV_INVALID);

  /* Expected nonces outside 32..128 octets fail at entry with the result
   * and work unchanged. */
  const size_t bad[] = {1, 31, 129};
  for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
    request.expected_nonce = (TC_bytes){nonce_bytes, bad[i]};
    memset(&result, 0x5a, sizeof result);
    size_t work = 1000;
    munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                     TC_TLV_ARGUMENT);
    ocsp_assert_untouched(&result);
    munit_assert_size(work, ==, 1000);
  }
  hierarchy_free();
  return MUNIT_OK;
}

/* Run request with budget and require LIMIT with a wiped result. */
static void assert_work_limit(const TC_X509_ocsp_verify_request* request, size_t budget)
{
  TC_X509_ocsp_result result;
  memset(&result, 0x5a, sizeof result);
  size_t work = budget;
  munit_assert_int(TC_X509_ocsp_response_verify(request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_LIMIT);
  ocsp_assert_wiped(&result);
}

/* Work is charged in stages: response bytes, the target certificate and
 * issuer Name, CertID hashing, extensions, the ResponderID, the delegate
 * path and its signature, then the response signature. A budget one short of
 * the full cost, and budgets spread across every stage, are LIMIT. Workspace
 * and parsing capacities are LIMIT too. */
TC_TEST(work_limits)
{
  TC_X509_ocsp_result result;
  hierarchy_init();
  X509* delegate;
  {
    const certificate_spec authorized = delegate_spec();
    delegate = issue(&authorized);
  }
  response_spec spec = response_by(delegate, pki.responder_key);
  spec.other_first = 1;
  spec.response_extension = NONCRITICAL_UNKNOWN;
  spec.nonce = (const uint8_t*)"0123456789abcdef0123456789abcdef";
  spec.nonce_length = 32;
  TC_X509_ocsp_verify_request request = target_request(build_response(&spec, response_bytes));
  request.expected_nonce = (TC_bytes){spec.nonce, 32};
  size_t work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  const size_t required = 20000000 - work;
  work = required;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  enum { SAMPLES = 512 };
  for (size_t i = 0; i < SAMPLES; ++i)
    assert_work_limit(&request, required * i / SAMPLES);
  for (size_t budget = required - 32; budget < required; ++budget)
    assert_work_limit(&request, budget);

  /* Frame and OID capacity, and the parsing limits. */
  const TC_X509_path_workspace full = fixture.workspace;
  fixture.workspace.frames.capacity = 4;
  assert_work_limit(&request, 20000000);
  fixture.workspace = full;
  fixture.workspace.oid_capacity = 1;
  assert_work_limit(&request, 20000000);
  fixture.workspace = full;
  TC_TLV_limits limits = fixture.limits;
  limits.max_input = request.response.length - 1;
  request.parsing = &limits;
  assert_work_limit(&request, 20000000);
  limits = fixture.limits;
  limits.max_elements = 40;
  assert_work_limit(&request, 20000000);
  request.parsing = &fixture.limits;
  request.max_certificates = 0;
  assert_work_limit(&request, 20000000);
  X509_free(delegate);
  hierarchy_free();
  return MUNIT_OK;
}

/* Unsuccessful responses carry no status (RFC 6960 4.2.1). malformedRequest
 * reports bad data, the others give no decision, and value 4 is unused. */
TC_TEST(unsuccessful)
{
  const TC_TLV_result expected[] = {TC_TLV_INVALID, TC_TLV_UNSUPPORTED, TC_TLV_UNSUPPORTED,
                                    TC_TLV_INVALID, TC_TLV_UNSUPPORTED, TC_TLV_UNSUPPORTED};
  TC_X509_ocsp_result result;
  hierarchy_init();
  for (int status = 1; status <= 6; ++status) {
    OCSP_RESPONSE* response = OCSP_response_create(status, NULL);
    munit_assert_not_null(response);
    unsigned char* cursor = response_bytes;
    const int length = i2d_OCSP_RESPONSE(response, &cursor);
    munit_assert_int(length, >, 0);
    OCSP_RESPONSE_free(response);
    const TC_X509_ocsp_verify_request request =
        target_request((TC_bytes){response_bytes, (size_t)length});
    munit_assert_int(verify_with(&request, &result), ==, expected[status - 1]);
  }
  hierarchy_free();
  return MUNIT_OK;
}

/* CRL contents for check_path. */
enum { NO_CRL, EMPTY_CRL, CRL_REVOKES_TARGET, CRL_REVOKES_DELEGATE };

/* A CA-signed complete CRL that lists serial, or nothing when serial is 0. */
static TC_bytes crl_der(long serial, uint8_t out[OCSP_FILE_CAPACITY])
{
  X509_CRL* crl = X509_CRL_new();
  munit_assert_not_null(crl);
  munit_assert_int(X509_CRL_set_version(crl, 1), ==, 1);
  munit_assert_int(X509_CRL_set_issuer_name(crl, X509_get_subject_name(pki.ca)), ==, 1);
  ASN1_TIME* last = X509_gmtime_adj(NULL, -3600);
  ASN1_TIME* next = X509_gmtime_adj(NULL, DAY);
  munit_assert_int(X509_CRL_set1_lastUpdate(crl, last), ==, 1);
  munit_assert_int(X509_CRL_set1_nextUpdate(crl, next), ==, 1);
  if (serial) {
    X509_REVOKED* entry = X509_REVOKED_new();
    ASN1_INTEGER* number = ASN1_INTEGER_new();
    munit_assert_not_null(entry);
    munit_assert_not_null(number);
    munit_assert_int(ASN1_INTEGER_set(number, serial), ==, 1);
    munit_assert_int(X509_REVOKED_set_serialNumber(entry, number), ==, 1);
    ASN1_INTEGER_free(number);
    munit_assert_int(X509_REVOKED_set_revocationDate(entry, last), ==, 1);
    munit_assert_int(X509_CRL_add0_revoked(crl, entry), ==, 1);
  }
  ASN1_INTEGER* number = ASN1_INTEGER_new();
  munit_assert_not_null(number);
  munit_assert_int(ASN1_INTEGER_set(number, 1), ==, 1);
  munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_crl_number, number, 0, 0), ==, 1);
  ASN1_INTEGER_free(number);
  ASN1_TIME_free(last);
  ASN1_TIME_free(next);
  munit_assert_int(X509_CRL_sort(crl), ==, 1);
  munit_assert_int(X509_CRL_sign(crl, pki.ca_key, EVP_sha256()), >, 0);
  unsigned char* cursor = out;
  const int length = i2d_X509_CRL(crl, &cursor);
  munit_assert_int(length, >, 0);
  munit_assert_int(length, <=, OCSP_FILE_CAPACITY);
  X509_CRL_free(crl);
  return (TC_bytes){out, (size_t)length};
}

static ocsp_revocation revocation;
static uint8_t crl_bytes[OCSP_FILE_CAPACITY];

/* Check the one-certificate path CA -> target with a CRL selector from the
 * enum above. delegate, when present, is a source candidate. */
static TC_TLV_result check_path(TC_bytes response, int crl, const TC_bytes* delegate,
                                TC_X509_revocation_result* result)
{
  const long serial = crl == CRL_REVOKES_TARGET     ? TARGET_SERIAL
                      : crl == CRL_REVOKES_DELEGATE ? DELEGATE_SERIAL
                                                    : 0;
  const TC_bytes crls[] = {crl != NO_CRL ? crl_der(serial, crl_bytes) : (TC_bytes){NULL, 0}};
  /* The CA signs its CRLs, so it is also a signer candidate. */
  const TC_bytes candidates[] = {pki.ca_bytes, delegate ? *delegate : (TC_bytes){NULL, 0}};
  ocsp_revocation_init(&revocation, &fixture, pki.ca_bytes, candidates, delegate ? 2 : 1, crls,
                       crl != NO_CRL, pki.at);
  const TC_X509_revocation_options options =
      ocsp_revocation_options(&revocation, pki.at, &response, 1);
  size_t work = 20000000;
  memset(result, 0xa5, sizeof *result);
  return TC_X509_path_check_revocation(&pki.target_bytes, 1, &options, &revocation.workspace, &work,
                                       result);
}

/* TC_X509_path_check_revocation settles a member with an accepted OCSP
 * response and falls back to CRLs otherwise. A delegate without
 * id-pkix-ocsp-nocheck needs CRL evidence of its own (RFC 6960 4.2.2.2.1). */
TC_TEST(path_fallback)
{
  TC_X509_revocation_result result;
  hierarchy_init();
  response_spec spec = response_by(pki.ca, pki.ca_key);
  spec.flags = OCSP_NOCERTS;
  const TC_bytes good = build_response(&spec, response_bytes);
  munit_assert_int(check_path(good, NO_CRL, NULL, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  /* OCSP settles the member before the CRL is consulted. */
  munit_assert_int(check_path(good, CRL_REVOKES_TARGET, NULL, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);

  /* An unauthorized responder falls back to the CRL, which decides. */
  certificate_spec unauthorized = delegate_spec();
  unauthorized.extended_key_usage = NULL;
  X509* rejected = issue(&unauthorized);
  spec = response_by(rejected, pki.responder_key);
  const TC_bytes unauthorized_response = build_response(&spec, response_bytes);
  munit_assert_int(check_path(unauthorized_response, CRL_REVOKES_TARGET, NULL, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_size(result.certificate_index, ==, 0);
  munit_assert_int(check_path(unauthorized_response, EMPTY_CRL, NULL, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  munit_assert_int(check_path(unauthorized_response, NO_CRL, NULL, &result), ==,
                   TC_TLV_UNSUPPORTED);
  X509_free(rejected);

  /* A delegate without nocheck, supplied through the source. */
  const certificate_spec authorized = delegate_spec();
  X509* delegate = issue(&authorized);
  const TC_bytes delegate_der = certificate_der(delegate, delegate_bytes);
  spec = response_by(delegate, pki.responder_key);
  spec.flags = OCSP_NOCERTS;
  spec.status = V_OCSP_CERTSTATUS_REVOKED;
  spec.reason = OCSP_REVOKED_STATUS_SUPERSEDED;
  const TC_bytes revoked = build_response(&spec, response_bytes);
  munit_assert_int(check_path(revoked, NO_CRL, &delegate_der, &result), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(check_path(revoked, EMPTY_CRL, &delegate_der, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_uint(result.evidence.revocation.reason, ==, OCSP_REVOKED_STATUS_SUPERSEDED);
  /* A revoked delegate leaves the target to the CRL, which lists nothing
   * for it. Accepting the delegate would report REVOKED. */
  munit_assert_int(check_path(revoked, CRL_REVOKES_DELEGATE, &delegate_der, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  X509_free(delegate);

  /* A nocheck delegate needs no CRL, even one that lists it. */
  certificate_spec exempt = delegate_spec();
  exempt.nocheck = 1;
  delegate = issue(&exempt);
  const TC_bytes exempt_der = certificate_der(delegate, delegate_bytes);
  spec = response_by(delegate, pki.responder_key);
  spec.flags = OCSP_NOCERTS;
  spec.status = V_OCSP_CERTSTATUS_REVOKED;
  spec.reason = OCSP_REVOKED_STATUS_SUPERSEDED;
  const TC_bytes exempt_revoked = build_response(&spec, response_bytes);
  munit_assert_int(check_path(exempt_revoked, NO_CRL, &exempt_der, &result), ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_int(check_path(exempt_revoked, CRL_REVOKES_DELEGATE, &exempt_der, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  X509_free(delegate);
  hierarchy_free();
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/ca-signed", ca_signed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/cert-id", cert_id, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/delegates", delegates, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/delegate-rejections", delegate_rejections, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/single-responses", single_responses, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/extensions", extensions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/nonce", nonce, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/work-limits", work_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/unsuccessful", unsuccessful, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/path-fallback", path_fallback, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/ocsp/openssl", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
