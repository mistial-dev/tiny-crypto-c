/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Key policy (SP 800-78-5 Tables 9 and 10) and key proofs over GENERAL
 * AUTHENTICATE (SP 800-73-5 Part 2 3.2.4 and A.4) on the SD 33 card 2
 * (RSA-2048) and card 4 (P-256) simulators, plain and under secure
 * messaging. The random source returns the digests the cards signed in the
 * captures, so the simulator's recorded answers verify. The PIN and pairing
 * code come from the fixtures. */
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_key_proof.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_vci.h>
#include <tiny_crypto/x509_crypto.h>
#include "card_simulator.h"
#include "munit.h"
#include "scripted_transport.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

#define STEP(command, response) {command, response, {0}, {0}, TC_OK, 0}

enum {
  RESPONSE_BYTES = 1024,
  SM_SCRATCH_BYTES = 1024,
  EXCHANGES = 256,
  CERTIFICATE_BYTES = 4096,
  WORK = 1000000,
  FRAMES = 16,
  EXTENSIONS = 32
};

/* The captured card 2 SHA-256 PKCS #1 v1.5 encoded messages end in these
 * digests. */
static const uint8_t card2_digest_9a[32] = {
    0x1e, 0x7a, 0x86, 0x02, 0x3c, 0x89, 0xbc, 0x32, 0x6c, 0xcf, 0x96, 0x86, 0x9f, 0x61, 0x21, 0x36,
    0x7b, 0x2f, 0x43, 0x6a, 0xd6, 0x19, 0xa9, 0x34, 0x55, 0xd9, 0x8c, 0xe9, 0x81, 0x1a, 0x51, 0xe0};
static const uint8_t card2_digest_9e[32] = {
    0x63, 0x7a, 0xe3, 0x80, 0x2f, 0xbe, 0xd7, 0xef, 0x1f, 0xb1, 0xed, 0xaa, 0x53, 0x66, 0xeb, 0x56,
    0xb7, 0xa8, 0x0c, 0x29, 0x14, 0xa4, 0x86, 0x2d, 0xbf, 0x80, 0xff, 0xb6, 0x86, 0x91, 0x36, 0x37};

static tc_card_fixture fixture;
static tc_card_simulator card;
/* The command scratch, aligned so tests can place inputs inside it. */
static union {
  uint8_t bytes[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  TC_PIV_key_proof_request request;
  TC_X509_signature_provider provider;
} command_scratch;
static uint8_t sm_scratch[SM_SCRATCH_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];
static uint8_t certificate_bytes[CERTIFICATE_BYTES];
static TC_PIV_SM session;
static TC_PIV_SM_workspace sm_workspace;
static TC_PIV_key_proof_workspace workspace;
static TC_ECDSA_workspace ec_workspace;
static TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
static const tc_card_session* recorded;

/* The digest the random source returns, and its requests. */
static struct {
  const uint8_t* digest;
  size_t length, calls;
  int fail;
} entropy;

static TC_status recorded_digest(void* context, uint8_t* output, size_t length)
{
  (void)context;
  ++entropy.calls;
  if (entropy.fail)
    return TC_ERROR;
  munit_assert_size(length, ==, entropy.length);
  memcpy(output, entropy.digest, length);
  return TC_OK;
}

static TC_random_source digest_source(const uint8_t* digest, size_t length)
{
  entropy.digest = digest;
  entropy.length = length;
  entropy.calls = 0;
  entropy.fail = 0;
  return (TC_random_source){recorded_digest, NULL};
}

static TC_X509_signature_provider native_provider(void)
{
  static TC_RSA_workspace rsa;
  static TC_X509_native_workspace native;
  rsa = (TC_RSA_workspace){rsa_words, sizeof rsa_words / sizeof *rsa_words};
  native = (TC_X509_native_workspace){&ec_workspace, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  return TC_X509_native_provider(&native);
}

/* A transport around the simulator that records the first GENERAL
 * AUTHENTICATE fragment and can damage the answer. */
static struct {
  uint8_t first[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  size_t first_length, authenticate_fragments;
  int flip_signature, bad_template;
} wire;

static TC_status wire_transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  const int authenticate = command.length > 1 && command.data[1] == 0x87;
  if (authenticate) {
    if (!wire.authenticate_fragments++) {
      memcpy(wire.first, command.data, command.length);
      wire.first_length = command.length;
    }
  }
  const TC_status status =
      tc_card_simulator_transport(context).transmit(context, command, response, length);
  if (status != TC_OK || *length <= 2)
    return status;
  const uint8_t sw1 = response.data[*length - 2];
  if (wire.bad_template && authenticate)
    response.data[0] ^= 1;
  if (wire.flip_signature && sw1 == 0x90)
    response.data[*length - 3] ^= 1;
  return status;
}

static void load(const char* name)
{
  char path[512];
  snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, name);
  munit_assert_long(tc_card_fixture_load(&fixture, path), ==, 0);
  memset(&wire, 0, sizeof wire);
}

static TC_buffer response_buffer(void)
{
  return (TC_buffer){response_bytes, sizeof response_bytes};
}

static void link_open(TC_PIV_link* link, TC_PIV_interface interface, int select)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_card_simulator_init(&card, &fixture, interface);
  munit_assert_int(
      TC_PIV_link_init(link, (TC_APDU_transport){wire_transmit, &card}, &options,
                       (TC_buffer){command_scratch.bytes, sizeof command_scratch.bytes}),
      ==, TC_PIV_OK);
  if (select)
    munit_assert_int(
        TC_PIV_select(link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application), ==,
        TC_PIV_OK);
}

/* The PIN or pairing code of reference as ASCII digits. */
static TC_bytes secret(uint8_t reference, uint8_t out[8])
{
  const tc_card_reference* data = tc_card_fixture_reference(&fixture, reference);
  munit_assert_not_null(data);
  size_t length = 0;
  while (length < 8 && data->value[length] != 0xff)
    ++length;
  memcpy(out, data->value, length);
  return (TC_bytes){out, length};
}

static void pin_verify(TC_PIV_link* link)
{
  uint8_t pin[8];
  TC_PIV_reference_status status;
  munit_assert_int(TC_PIV_pin_verify(link, 0x80, secret(0x80, pin), 3, &status), ==, TC_PIV_OK);
  munit_assert_uint8(status.submitted, ==, 1);
}

static TC_status recorded_scalar(void* context, uint8_t* output, size_t length)
{
  (void)context;
  munit_assert_size(length, ==, recorded->scalar.length);
  memcpy(output, recorded->scalar.data, length);
  return TC_OK;
}

/* Secure the contactless link with the recorded key establishment and
 * establish the VCI with the pairing code. */
static void link_secure_vci(TC_PIV_link* link)
{
  TC_PIV_SM_peer peer;
  TC_PIV_CVC cvc;
  TC_PIV_discovery discovery;
  TC_PIV_vci_mode mode;
  uint8_t pairing[8];
  recorded = &fixture.sessions[0];
  memset(&session, 0, sizeof session);
  munit_assert_int(TC_PIV_SM_key_request(link, &session, (TC_PIV_SM_suite)recorded->suite,
                                         recorded->host_id.data,
                                         (TC_random_source){recorded_scalar, NULL},
                                         response_buffer(), &peer, &sm_workspace),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_CVC_read(peer.certificate, &cvc), ==, TC_TLV_OK);
  munit_assert_int(TC_PIV_SM_finish(&session, &peer, cvc.public_key, &sm_workspace), ==, TC_OK);
  munit_assert_int(
      TC_PIV_link_secure(link, &sm_workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}), ==,
      TC_PIV_OK);
  munit_assert_int(TC_PIV_discovery_get(link, TC_PIV_DISCOVERY_PIV, response_buffer(), &discovery),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_vci_establish(link, &discovery, secret(0x98, pairing), &mode), ==,
                   TC_PIV_OK);
}

/* Decode and parse the certificate of container tag from the fixture. A
 * plain certificate borrows the fixture, a GZIP one certificate_bytes. */
static void certificate_load(uint32_t tag, TC_X509_certificate* out)
{
  static TC_TLV_frame frames[FRAMES];
  static TC_bytes oids[EXTENSIONS];
  const TC_TLV_limits limits = {CERTIFICATE_BYTES, CERTIFICATE_BYTES, 512, FRAMES};
  TC_X509_workspace parser = {{frames, FRAMES}, oids, EXTENSIONS};
  static TC_GZIP_workspace gzip;
  TC_PIV_certificate container;
  size_t work = WORK;
  const tc_card_object* object = tc_card_fixture_object(&fixture, tag);
  munit_assert_not_null(object);
  munit_assert_int(TC_PIV_certificate_decode(
                       object->data, TC_PIV_CERTIFICATE_SLOT, CERTIFICATE_BYTES, &gzip, &work,
                       (TC_buffer){certificate_bytes, CERTIFICATE_BYTES}, &container),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_read(container.certificate, &limits, &parser, out), ==, TC_TLV_OK);
}

static TC_PIV_key_proof_request proof_request(const TC_X509_certificate* certificate, uint8_t key)
{
  TC_PIV_key_proof_request request;
  memset(&request, 0, sizeof request);
  request.certificate = certificate;
  request.policy.profile = TC_PIV_CARD;
  request.policy.at = (TC_X509_time){2026, 9, 29, 18, 0, 0};
  request.policy.rsa_padding = TC_PIV_RSA_PKCS1_V15;
  request.key_reference = key;
  return request;
}

static TC_PIV_result prove(TC_PIV_link* link, const TC_PIV_key_proof_request* request,
                           TC_random_source random)
{
  const TC_X509_signature_provider provider = native_provider();
  TC_work_budget work = {WORK};
  memset(&workspace, 0xa5, sizeof workspace);
  return TC_PIV_key_prove(link, request, random, &provider, &workspace, &work);
}

/* A certificate view with only the fields the key policy reads. usage is
 * the keyUsage BIT STRING: unused bits and one byte, or 0 for none. */
typedef struct {
  TC_X509_certificate certificate;
  uint8_t extensions[18];
  uint8_t modulus[512], point[97], exponent[4];
} synthetic_key;

static void synthetic_rsa(synthetic_key* out, unsigned bits, const uint8_t* exponent,
                          size_t exponent_length, uint8_t unused, uint8_t usage)
{
  /* Extensions { keyUsage critical BIT STRING } (RFC 5280 4.2.1.3). */
  const uint8_t extensions[] = {0x30, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,   0x0f,
                                0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, unused, usage};
  memset(out, 0, sizeof *out);
  memcpy(out->extensions, extensions, sizeof extensions);
  memset(out->modulus, 0xc3, sizeof out->modulus);
  memcpy(out->exponent, exponent, exponent_length);
  out->certificate.version = 3;
  if (usage)
    out->certificate.extensions = (TC_bytes){out->extensions, sizeof extensions};
  out->certificate.public_key.type = TC_KEY_RSA;
  out->certificate.public_key.bits = bits;
  out->certificate.public_key.modulus = (TC_bytes){out->modulus, bits / 8u};
  out->certificate.public_key.exponent = (TC_bytes){out->exponent, exponent_length};
}

static void synthetic_ec(synthetic_key* out, TC_EC_curve curve, unsigned bits, size_t point)
{
  static const uint8_t f4[] = {1, 0, 1};
  synthetic_rsa(out, 0, f4, sizeof f4, 7, 0x80);
  out->certificate.public_key = (TC_X509_public_key){0};
  out->certificate.public_key.type = TC_KEY_EC;
  out->certificate.public_key.curve = curve;
  out->certificate.public_key.bits = bits;
  out->point[0] = 4;
  out->certificate.public_key.key = (TC_bytes){out->point, point};
}

static TC_PIV_result select_algorithm(const TC_X509_certificate* certificate,
                                      const TC_PIV_key_policy* policy, uint8_t* algorithm)
{
  TC_PIV_key_parameters parameters;
  memset(&parameters, 0x5a, sizeof parameters);
  const TC_PIV_result result = TC_PIV_key_parameters_select(certificate, policy, &parameters);
  *algorithm = result == TC_PIV_OK ? parameters.algorithm : 0;
  if (result != TC_PIV_OK)
    munit_assert_true(tc_test_all_value(&parameters, sizeof parameters, 0x5a));
  return result;
}

/* SP 800-78-5 Table 9 identifiers, the Table 10 end of RSA-2048 and the
 * TWIC profiles. */
TC_TEST(algorithms)
{
  static const uint8_t f4[] = {1, 0, 1}, three[] = {3}, even[] = {1, 0, 0};
  static const uint8_t large[] = {1, 0, 0, 1};
  TC_PIV_key_policy policy = {TC_PIV_CARD, {2026, 9, 29, 18, 0, 0}, TC_PIV_RSA_PKCS1_V15, 0};
  synthetic_key key;
  uint8_t algorithm = 0;
  const struct {
    unsigned bits;
    TC_PIV_card_profile profile;
    uint8_t allow;
    TC_PIV_result result;
    uint8_t algorithm;
  } rsa[] = {
      {2048, TC_PIV_CARD, 0, TC_PIV_OK, TC_PIV_ALGORITHM_RSA_2048},
      {3072, TC_PIV_CARD, 0, TC_PIV_OK, TC_PIV_ALGORITHM_RSA_3072},
      {1024, TC_PIV_CARD, 1, TC_PIV_UNSUPPORTED, 0},
      {1024, TC_TWIC_LEGACY_CARD, 0, TC_PIV_UNSUPPORTED, 0},
      {1024, TC_TWIC_LEGACY_CARD, 1, TC_PIV_OK, TC_PIV_ALGORITHM_RSA_1024},
      {1024, TC_TWIC_NEXGEN_CARD, 1, TC_PIV_UNSUPPORTED, 0},
      {3072, TC_TWIC_NEXGEN_CARD, 0, TC_PIV_UNSUPPORTED, 0},
      {2048, TC_TWIC_NEXGEN_CARD, 0, TC_PIV_OK, TC_PIV_ALGORITHM_RSA_2048},
      {4096, TC_PIV_CARD, 0, TC_PIV_UNSUPPORTED, 0},
  };
  for (size_t i = 0; i < sizeof rsa / sizeof *rsa; ++i) {
    synthetic_rsa(&key, rsa[i].bits, f4, sizeof f4, 7, 0x80);
    policy.profile = rsa[i].profile;
    policy.allow_rsa1024 = rsa[i].allow;
    munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, rsa[i].result);
    munit_assert_uint8(algorithm, ==, rsa[i].algorithm);
  }
  /* Table 10: 07 through 2030 under PIV, and the TWIC reader policy after. */
  synthetic_rsa(&key, 2048, f4, sizeof f4, 7, 0x80);
  policy = (TC_PIV_key_policy){TC_PIV_CARD, {2030, 12, 31, 23, 59, 59}, TC_PIV_RSA_PKCS1_V15, 0};
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_OK);
  policy.at = (TC_X509_time){2031, 1, 1, 0, 0, 0};
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_UNSUPPORTED);
  policy.profile = TC_TWIC_LEGACY_CARD;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_OK);
  policy.profile = TC_TWIC_NEXGEN_CARD;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_OK);
  synthetic_rsa(&key, 3072, f4, sizeof f4, 7, 0x80);
  policy.profile = TC_PIV_CARD;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_OK);

  /* SHA-256 encodings, PSS with MGF1-SHA-256 and a 32-byte salt. */
  TC_PIV_key_parameters parameters;
  policy = (TC_PIV_key_policy){TC_PIV_CARD, {2026, 9, 29, 18, 0, 0}, TC_PIV_RSA_PKCS1_V15, 0};
  munit_assert_int(TC_PIV_key_parameters_select(&key.certificate, &policy, &parameters), ==,
                   TC_PIV_OK);
  munit_assert_int(parameters.challenge.signature.scheme, ==, TC_SIGNATURE_RSA_V15);
  munit_assert_int(parameters.challenge.signature.hash, ==, TC_HASH_SHA256);
  munit_assert_size(parameters.challenge.signature.salt_length, ==, 0);
  policy.rsa_padding = TC_PIV_RSA_PSS;
  munit_assert_int(TC_PIV_key_parameters_select(&key.certificate, &policy, &parameters), ==,
                   TC_PIV_OK);
  munit_assert_int(parameters.challenge.signature.scheme, ==, TC_SIGNATURE_RSA_PSS);
  munit_assert_int(parameters.challenge.signature.mgf_hash, ==, TC_HASH_SHA256);
  munit_assert_size(parameters.challenge.signature.salt_length, ==, 32);
  policy.rsa_padding = TC_PIV_RSA_PKCS1_V15;

  /* Exponents of 65537 to 2^256 - 1 and a modulus of bits / 8 bytes. */
  synthetic_rsa(&key, 2048, three, sizeof three, 7, 0x80);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_INVALID);
  synthetic_rsa(&key, 2048, even, sizeof even, 7, 0x80);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_INVALID);
  synthetic_rsa(&key, 2048, large, sizeof large, 7, 0x80);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_OK);
  key.certificate.public_key.modulus.length = 255;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_INVALID);

  /* keyUsage must assert digitalSignature. */
  synthetic_rsa(&key, 2048, f4, sizeof f4, 2, 0x04);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_INVALID);
  synthetic_rsa(&key, 2048, f4, sizeof f4, 7, 0);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_INVALID);

  /* ECDSA P-256 and P-384 with their hashes. NEXGEN takes RSA-2048 only. */
  synthetic_ec(&key, TC_EC_P256, 256, 65);
  munit_assert_int(TC_PIV_key_parameters_select(&key.certificate, &policy, &parameters), ==,
                   TC_PIV_OK);
  munit_assert_uint8(parameters.algorithm, ==, TC_PIV_ALGORITHM_ECC_P256);
  munit_assert_int(parameters.challenge.signature.scheme, ==, TC_SIGNATURE_ECDSA);
  munit_assert_int(parameters.challenge.signature.hash, ==, TC_HASH_SHA256);
  synthetic_ec(&key, TC_EC_P384, 384, 97);
  munit_assert_int(TC_PIV_key_parameters_select(&key.certificate, &policy, &parameters), ==,
                   TC_PIV_OK);
  munit_assert_uint8(parameters.algorithm, ==, TC_PIV_ALGORITHM_ECC_P384);
  munit_assert_int(parameters.challenge.signature.hash, ==, TC_HASH_SHA384);
  policy.profile = TC_TWIC_NEXGEN_CARD;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_UNSUPPORTED);
  policy.profile = TC_TWIC_LEGACY_CARD;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_OK);
  policy.profile = TC_PIV_CARD;
  synthetic_ec(&key, TC_EC_P384, 384, 49);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_UNSUPPORTED);
  synthetic_ec(&key, TC_EC_P521, 521, 133);
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_UNSUPPORTED);
  key.certificate.public_key.type = TC_KEY_UNKNOWN;
  munit_assert_int(select_algorithm(&key.certificate, &policy, &algorithm), ==, TC_PIV_UNSUPPORTED);

  /* Argument errors leave out unchanged. */
  synthetic_rsa(&key, 2048, f4, sizeof f4, 7, 0x80);
  munit_assert_int(select_algorithm(NULL, &policy, &algorithm), ==, TC_PIV_ARGUMENT);
  munit_assert_int(select_algorithm(&key.certificate, NULL, &algorithm), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_parameters_select(&key.certificate, &policy, NULL), ==,
                   TC_PIV_ARGUMENT);
  const TC_PIV_key_policy invalid[] = {
      {(TC_PIV_card_profile)3, {2026, 9, 29, 0, 0, 0}, TC_PIV_RSA_PKCS1_V15, 0},
      {TC_PIV_CARD, {2026, 9, 29, 0, 0, 0}, (TC_PIV_rsa_padding)2, 0},
      {TC_PIV_CARD, {2026, 9, 29, 0, 0, 0}, TC_PIV_RSA_PKCS1_V15, 2},
      {TC_PIV_CARD, {2026, 13, 29, 0, 0, 0}, TC_PIV_RSA_PKCS1_V15, 0}};
  for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i)
    munit_assert_int(select_algorithm(&key.certificate, &invalid[i], &algorithm), ==,
                     TC_PIV_ARGUMENT);
  return MUNIT_OK;
}

/* Card 2 on contact: 9E is Always, 9A needs the PIN. Both answers verify
 * under the certificates of 5FC101 and 5FC105. The request follows Part 2
 * A.4.1: 7C {82 00, 81 82 01 00 challenge} in two SHORT fragments. */
TC_TEST(card2_contact)
{
  static const uint8_t first[] = {0x10, 0x87, 0x07, 0x9e, 0xff, 0x7c, 0x82, 0x01,
                                  0x06, 0x82, 0x00, 0x81, 0x82, 0x01, 0x00, 0x00};
  TC_PIV_link link;
  TC_X509_certificate card_auth, piv_auth;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT, 1);
  certificate_load(0x5fc101, &card_auth);
  TC_PIV_key_proof_request request = proof_request(&card_auth, TC_PIV_KEY_CARD_AUTHENTICATION);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_OK);
  munit_assert_size(entropy.calls, ==, 1);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  munit_assert_size(wire.first_length, ==, 5 + 255);
  munit_assert_memory_equal(sizeof first, wire.first, first);
  munit_assert_size(wire.authenticate_fragments, ==, 2);
  munit_assert_size(card.get_responses, ==, 1);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);

  /* 9A before the PIN: the card answers 6982. */
  certificate_load(0x5fc105, &piv_auth);
  request = proof_request(&piv_auth, TC_PIV_KEY_PIV_AUTHENTICATION);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9a, sizeof card2_digest_9a)),
                   ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6982);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  pin_verify(&link);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9a, sizeof card2_digest_9a)),
                   ==, TC_PIV_OK);
  /* An unrecorded challenge gets 6A80 from the simulator. */
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6a80);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Card 2 on contactless. 9E is Always and goes plain on an unsecured link.
 * 9A needs the VCI, so it is refused before anything is sent. Under secure
 * messaging both go as 1C chains, and 9A still needs the PIN. */
TC_TEST(card2_contactless)
{
  TC_PIV_link link;
  TC_X509_certificate card_auth, piv_auth;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACTLESS, 1);
  certificate_load(0x5fc101, &card_auth);
  certificate_load(0x5fc105, &piv_auth);
  /* piv_auth reuses certificate_bytes, so parse card_auth again after. */
  TC_PIV_key_proof_request request = proof_request(&piv_auth, TC_PIV_KEY_PIV_AUTHENTICATION);
  const size_t before = card.transmits;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9a, sizeof card2_digest_9a)),
                   ==, TC_PIV_REFUSED);
  munit_assert_size(card.transmits, ==, before);
  munit_assert_size(entropy.calls, ==, 0);
  munit_assert_true(tc_test_all_value(&workspace, sizeof workspace, 0xa5));
  request.key_reference = TC_PIV_KEY_DIGITAL_SIGNATURE;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9a, sizeof card2_digest_9a)),
                   ==, TC_PIV_REFUSED);

  certificate_load(0x5fc101, &card_auth);
  request = proof_request(&card_auth, TC_PIV_KEY_CARD_AUTHENTICATION);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_OK);
  munit_assert_size(card.protected_commands, ==, 0);

  link_secure_vci(&link);
  const size_t fragments = card.fragments, protected_commands = card.protected_commands;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_OK);
  munit_assert_size(card.protected_commands, ==, protected_commands + 1);
  munit_assert_size(card.fragments, ==, fragments + 1);

  certificate_load(0x5fc105, &piv_auth);
  request = proof_request(&piv_auth, TC_PIV_KEY_PIV_AUTHENTICATION);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9a, sizeof card2_digest_9a)),
                   ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6982);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.secured, ==, 1);
  pin_verify(&link);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9a, sizeof card2_digest_9a)),
                   ==, TC_PIV_OK);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* The digest of the recorded card 4 ECDSA input for key, which the card
 * signed directly. */
static TC_random_source card4_digest(uint8_t key)
{
  for (size_t i = 0; i < fixture.authentication_count; ++i) {
    const tc_card_authentication* entry = &fixture.authentications[i];
    if (entry->algorithm == TC_PIV_ALGORITHM_ECC_P256 && entry->key == key && entry->tag == 0x81)
      return digest_source(entry->input.data, entry->input.length);
  }
  munit_error("no recorded input");
  return digest_source(NULL, 0);
}

/* Card 4 (P-256) on contact: 9E, then 9C right after a PIN submission
 * (PIN Always) and 9A with the PIN still verified. A second 9C without a
 * fresh PIN gets 6982. The ECDSA template fits one command. */
TC_TEST(card4_contact)
{
  TC_PIV_link link;
  TC_X509_certificate certificate;
  load("sd33_card4");
  link_open(&link, TC_PIV_CONTACT, 1);
  certificate_load(0x5fc101, &certificate);
  TC_PIV_key_proof_request request = proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  munit_assert_int(prove(&link, &request, card4_digest(0x9e)), ==, TC_PIV_OK);
  munit_assert_size(wire.authenticate_fragments, ==, 1);
  static const uint8_t command[] = {0x00, 0x87, 0x11, 0x9e, 0x26, 0x7c,
                                    0x24, 0x82, 0x00, 0x81, 0x20};
  munit_assert_memory_equal(sizeof command, wire.first, command);
  munit_assert_size(wire.first_length, ==, sizeof command + 32 + 1);

  certificate_load(0x5fc10a, &certificate);
  request = proof_request(&certificate, TC_PIV_KEY_DIGITAL_SIGNATURE);
  pin_verify(&link);
  munit_assert_int(prove(&link, &request, card4_digest(0x9c)), ==, TC_PIV_OK);
  munit_assert_int(prove(&link, &request, card4_digest(0x9c)), ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6982);

  certificate_load(0x5fc105, &certificate);
  request = proof_request(&certificate, TC_PIV_KEY_PIV_AUTHENTICATION);
  munit_assert_int(prove(&link, &request, card4_digest(0x9a)), ==, TC_PIV_OK);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* A damaged answer fails the proof: a flipped signature byte and a
 * template with another tag. */
TC_TEST(invalid_answer)
{
  TC_PIV_link link;
  TC_X509_certificate certificate;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT, 1);
  certificate_load(0x5fc101, &certificate);
  const TC_PIV_key_proof_request request =
      proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  wire.flip_signature = 1;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_INVALID);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  wire.flip_signature = 0;
  wire.bad_template = 1;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_INVALID);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  wire.bad_template = 0;
  load("sd33_card4");
  link_open(&link, TC_PIV_CONTACT, 1);
  certificate_load(0x5fc101, &certificate);
  wire.flip_signature = 1;
  munit_assert_int(prove(&link, &request, card4_digest(0x9e)), ==, TC_PIV_INVALID);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Policy failures send nothing and draw no randomness: keyUsage without
 * digitalSignature, e = 3, RSA-2048 after 2030 under PIV and RSA-1024 under
 * PIV. */
TC_TEST(policy)
{
  static const uint8_t f4[] = {1, 0, 1}, three[] = {3};
  TC_PIV_link link;
  synthetic_key key;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT, 1);
  const struct {
    unsigned bits;
    const uint8_t* exponent;
    size_t exponent_length;
    uint8_t unused, usage;
    uint16_t year;
    TC_PIV_result result;
  } cases[] = {{2048, f4, sizeof f4, 2, 0x04, 2026, TC_PIV_INVALID},
               {2048, three, sizeof three, 7, 0x80, 2026, TC_PIV_INVALID},
               {2048, f4, sizeof f4, 7, 0x80, 2031, TC_PIV_UNSUPPORTED},
               {1024, f4, sizeof f4, 7, 0x80, 2026, TC_PIV_UNSUPPORTED}};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    synthetic_rsa(&key, cases[i].bits, cases[i].exponent, cases[i].exponent_length, cases[i].unused,
                  cases[i].usage);
    TC_PIV_key_proof_request request =
        proof_request(&key.certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
    request.policy.at.year = cases[i].year;
    request.policy.allow_rsa1024 = 1;
    const size_t before = card.transmits;
    munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                     ==, cases[i].result);
    munit_assert_size(card.transmits, ==, before);
    munit_assert_size(entropy.calls, ==, 0);
    munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  }
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* The TWIC application proves with 9E only, on NEXGEN cards and under the
 * profile of its SELECT. */
TC_TEST(twic_application)
{
  static const tc_script_step steps[] = {STEP("00A4040009A0000003672000000100",
                                              "61144F0BA00000036720000001010379054F03A00000"
                                              "7F6608020204000202080090"
                                              "00")};
  tc_script script;
  TC_PIV_link link;
  TC_PIV_application application;
  TC_X509_certificate certificate;
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, 0};
  load("sd33_card2");
  certificate_load(0x5fc101, &certificate);
  tc_script_init(&script, steps, sizeof steps / sizeof *steps);
  munit_assert_int(
      TC_PIV_link_init(&link, tc_script_transport(&script), &options,
                       (TC_buffer){command_scratch.bytes, sizeof command_scratch.bytes}),
      ==, TC_PIV_OK);
  munit_assert_int(
      TC_PIV_select(&link, TC_PIV_APPLICATION_TWIC, 0, response_buffer(), &application), ==,
      TC_PIV_OK);
  munit_assert_int(application.profile, ==, TC_TWIC_NEXGEN_CARD);
  TC_PIV_key_proof_request request = proof_request(&certificate, TC_PIV_KEY_PIV_AUTHENTICATION);
  request.policy.profile = TC_TWIC_NEXGEN_CARD;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_true(tc_test_all_value(&workspace, sizeof workspace, 0xa5));
  request.key_reference = TC_PIV_KEY_DIGITAL_SIGNATURE;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_ARGUMENT);
  request.key_reference = TC_PIV_KEY_CARD_AUTHENTICATION;
  request.policy.profile = TC_TWIC_LEGACY_CARD;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_size(script.next, ==, 1);
  munit_assert_size(entropy.calls, ==, 0);
  TC_PIV_link_clear(&link);

  /* GENERAL AUTHENTICATE is a NEXGEN command of the TWIC application (TWIC
   * Part 2 v5 5.3). A Legacy card proves on its PIV application. */
  static const tc_script_step legacy[] = {STEP("00A4040009A0000003672000000100",
                                               "61164F0BA00000036720000001010179074F05A000"
                                               "0003677F66080202040002020800"
                                               "9000")};
  tc_script_init(&script, legacy, sizeof legacy / sizeof *legacy);
  munit_assert_int(
      TC_PIV_link_init(&link, tc_script_transport(&script), &options,
                       (TC_buffer){command_scratch.bytes, sizeof command_scratch.bytes}),
      ==, TC_PIV_OK);
  munit_assert_int(
      TC_PIV_select(&link, TC_PIV_APPLICATION_TWIC, 0, response_buffer(), &application), ==,
      TC_PIV_OK);
  munit_assert_int(application.profile, ==, TC_TWIC_LEGACY_CARD);
  request = proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  request.policy.profile = TC_TWIC_LEGACY_CARD;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_UNSUPPORTED);
  munit_assert_true(tc_test_all_value(&workspace, sizeof workspace, 0xa5));
  munit_assert_size(script.next, ==, 1);
  munit_assert_size(entropy.calls, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Argument errors leave the workspace and work unchanged and send nothing. */
TC_TEST(arguments)
{
  TC_PIV_link link, cleared;
  TC_X509_certificate certificate;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT, 1);
  certificate_load(0x5fc101, &certificate);
  const TC_X509_signature_provider provider = native_provider();
  const TC_random_source random = digest_source(card2_digest_9e, sizeof card2_digest_9e);
  TC_PIV_key_proof_request request = proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  TC_work_budget work = {WORK};
  memset(&cleared, 0, sizeof cleared);
  memset(&workspace, 0xa5, sizeof workspace);
  munit_assert_int(TC_PIV_key_prove(NULL, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&cleared, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&link, NULL, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&link, &request, (TC_random_source){NULL, NULL}, &provider,
                                    &workspace, &work),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, NULL, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, NULL, &work), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, NULL), ==,
                   TC_PIV_ARGUMENT);
  const uint8_t keys[] = {0x00, 0x9b, 0x9d, 0x82, 0x04};
  for (size_t i = 0; i < sizeof keys; ++i) {
    request.key_reference = keys[i];
    munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, &work), ==,
                     TC_PIV_ARGUMENT);
  }
  request = proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  request.policy.at.hour = 24;
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  request = proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  request.certificate = NULL;
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  /* The workspace overlaps the certificate bytes, the link or the scratch. */
  request = proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  TC_X509_certificate moved = certificate;
  moved.encoded.data = (const uint8_t*)&workspace + 8;
  request.certificate = &moved;
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  request.certificate = &certificate;
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider,
                                    (TC_PIV_key_proof_workspace*)(void*)&link, &work),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider,
                                    (TC_PIV_key_proof_workspace*)(void*)command_scratch.bytes,
                                    &work),
                   ==, TC_PIV_ARGUMENT);
  /* The certificate bytes, its key, the provider or the request inside the
   * link storage, which the exchange rewrites. */
  moved = certificate;
  moved.encoded.data = command_scratch.bytes + 8;
  request.certificate = &moved;
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  moved = certificate;
  moved.public_key.modulus.data = command_scratch.bytes;
  munit_assert_int(TC_PIV_key_prove(&link, &request, random, &provider, &workspace, &work), ==,
                   TC_PIV_ARGUMENT);
  request.certificate = &certificate;
  command_scratch.provider = provider;
  munit_assert_int(
      TC_PIV_key_prove(&link, &request, random, &command_scratch.provider, &workspace, &work), ==,
      TC_PIV_ARGUMENT);
  command_scratch.request = request;
  munit_assert_int(
      TC_PIV_key_prove(&link, &command_scratch.request, random, &provider, &workspace, &work), ==,
      TC_PIV_ARGUMENT);
  munit_assert_true(tc_test_all_value(&workspace, sizeof workspace, 0xa5));
  munit_assert_uint32(work.remaining, ==, WORK);
  munit_assert_size(entropy.calls, ==, 0);
  munit_assert_size(tc_card_simulator_sent(&card, 0x87, 0), ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Refusals before sending, unsupported providers and the failures after
 * the checks, which wipe the workspace. */
TC_TEST(failures)
{
  TC_PIV_link link;
  TC_X509_certificate certificate;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT, 0);
  certificate_load(0x5fc101, &certificate);
  const TC_PIV_key_proof_request request =
      proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  /* No application selected. */
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_REFUSED);
  munit_assert_size(card.transmits, ==, 0);
  TC_PIV_link_clear(&link);

  link_open(&link, TC_PIV_CONTACT, 1);
  TC_X509_signature_provider provider = native_provider();
  TC_work_budget work = {WORK};
  provider.verify_digest = NULL;
  memset(&workspace, 0xa5, sizeof workspace);
  munit_assert_int(TC_PIV_key_prove(&link, &request,
                                    digest_source(card2_digest_9e, sizeof card2_digest_9e),
                                    &provider, &workspace, &work),
                   ==, TC_PIV_UNSUPPORTED);
  munit_assert_size(entropy.calls, ==, 0);

  /* A failing random source, no work and a short exchange budget. */
  TC_random_source random = digest_source(card2_digest_9e, sizeof card2_digest_9e);
  entropy.fail = 1;
  const size_t before = card.transmits;
  munit_assert_int(prove(&link, &request, random), ==, TC_PIV_ERROR);
  munit_assert_size(card.transmits, ==, before);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  provider = native_provider();
  work.remaining = 0;
  memset(&workspace, 0xa5, sizeof workspace);
  munit_assert_int(TC_PIV_key_prove(&link, &request,
                                    digest_source(card2_digest_9e, sizeof card2_digest_9e),
                                    &provider, &workspace, &work),
                   ==, TC_PIV_LIMIT);
  munit_assert_size(entropy.calls, ==, 0);
  munit_assert_size(card.transmits, ==, before);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  TC_PIV_link_clear(&link);

  /* SELECT takes one of two exchanges, and the chain preflight needs one
   * per fragment, so it stops before the first fragment. */
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 2, 0, 0}, TC_PIV_CONTACT, 0};
  TC_PIV_application application;
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  munit_assert_int(
      TC_PIV_link_init(&link, (TC_APDU_transport){wire_transmit, &card}, &options,
                       (TC_buffer){command_scratch.bytes, sizeof command_scratch.bytes}),
      ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_LIMIT);
  munit_assert_size(tc_card_simulator_sent(&card, 0x87, 0), ==, 0);
  munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* A lost secure messaging session refuses the proof until unsecure. */
TC_TEST(session_lost)
{
  TC_PIV_link link;
  TC_X509_certificate certificate;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACTLESS, 1);
  link_secure_vci(&link);
  certificate_load(0x5fc101, &certificate);
  const TC_PIV_key_proof_request request =
      proof_request(&certificate, TC_PIV_KEY_CARD_AUTHENTICATION);
  /* A reset ends the card session. The next protected command gets 6982
   * outside SM, which ends the link session. */
  tc_card_simulator_reset(&card);
  TC_PIV_application application;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_CARD_STATUS);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.sm_lost, ==, 1);
  const size_t before = card.transmits;
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_REFUSED);
  munit_assert_size(card.transmits, ==, before);
  munit_assert_size(entropy.calls, ==, 0);
  TC_PIV_link_unsecure(&link);
  munit_assert_int(prove(&link, &request, digest_source(card2_digest_9e, sizeof card2_digest_9e)),
                   ==, TC_PIV_OK);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/algorithms", algorithms, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/card2-contact", card2_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/card2-contactless", card2_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/card4-contact", card4_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-answer", invalid_answer, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policy", policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/twic-application", twic_application, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/arguments", arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/failures", failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/session-lost", session_lost, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/piv/key-proof", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
