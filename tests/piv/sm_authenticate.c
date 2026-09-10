/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_sm.h>
#include <tiny_crypto/piv_sm_authenticate.h>
#include "../../examples/piv_sm_wire.h"
#include "munit.h"
#include "test_util.h"
#include "sm_fixtures.h"
#include <string.h>

enum { TEST_WORK = 1000000 };

typedef struct { size_t width; } fixed_random_state;

static TC_status fixed_scalar(void* context, uint8_t* output, size_t length)
{
  fixed_random_state* state = (fixed_random_state*)context;
  if (length != state->width) return TC_ERROR;
  memset(output,0,length);
  output[length - 1] = 1;
  return TC_OK;
}

static TC_X509_signature_result accept_signature(void* context,
    const TC_bytes* message, size_t count, const TC_DER_algorithm* algorithm,
    TC_bytes signature, const TC_X509_public_key* key, size_t* work)
{
  (void)context; (void)message; (void)count; (void)algorithm;
  (void)signature; (void)key; (void)work;
  return TC_X509_SIGNATURE_VALID;
}

static TC_X509_signature_result reject_signature(void* context,
    const TC_bytes* message, size_t count, const TC_DER_algorithm* algorithm,
    TC_bytes signature, const TC_X509_public_key* key, size_t* work)
{
  (void)context; (void)message; (void)count; (void)algorithm;
  (void)signature; (void)key; (void)work;
  return TC_X509_SIGNATURE_INVALID;
}

static const uint8_t signer_extensions[] = {
  0x30,0x13,0x30,0x11,0x06,0x03,0x55,0x1d,0x0e,0x04,0x0a,0x04,0x08,
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
};
static const uint8_t ec_public_key_oid[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
static const uint8_t p256_parameters[] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
static const uint8_t p384_parameters[] = {0x06,0x05,0x2b,0x81,0x04,0x00,0x22};
static const uint8_t rsa_public_key_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};
static const uint8_t rsa_null[] = {0x05,0x00};
static const uint8_t rsa_exponent[] = {0x01,0x00,0x01};
static const uint8_t rsa_modulus[256] = {0x80};
static const uint8_t rsa_encoded_key[] = {0x01};

static void signer_key(const struct tc_sm_fixture* fixture, TC_X509_certificate* signer)
{
  const int cs2 = fixture->suite == TC_PIV_SM_CS2;
  if (fixture->intermediate.length) {
    signer->public_key.type = TC_KEY_RSA;
    signer->public_key.bits = 2048;
    signer->public_key.algorithm.oid = (TC_bytes){rsa_public_key_oid,sizeof rsa_public_key_oid};
    signer->public_key.algorithm.parameters = (TC_bytes){rsa_null,sizeof rsa_null};
    signer->public_key.modulus = (TC_bytes){rsa_modulus,sizeof rsa_modulus};
    signer->public_key.exponent = (TC_bytes){rsa_exponent,sizeof rsa_exponent};
    signer->public_key.key = (TC_bytes){rsa_encoded_key,sizeof rsa_encoded_key};
    signer->public_key.curve_oid = (TC_bytes){NULL,0};
    signer->public_key.curve = TC_EC_UNKNOWN;
    return;
  }
  signer->public_key.type = TC_KEY_EC;
  signer->public_key.bits = cs2 ? 256 : 384;
  signer->public_key.curve = cs2 ? TC_EC_P256 : TC_EC_P384;
  signer->public_key.algorithm.oid = (TC_bytes){ec_public_key_oid,sizeof ec_public_key_oid};
  signer->public_key.algorithm.parameters = cs2 ?
    (TC_bytes){p256_parameters,sizeof p256_parameters} :
    (TC_bytes){p384_parameters,sizeof p384_parameters};
  signer->public_key.key = fixture->public_key;
  signer->public_key.curve_oid = cs2 ?
    (TC_bytes){p256_parameters + 2,sizeof p256_parameters - 2} :
    (TC_bytes){p384_parameters + 2,sizeof p384_parameters - 2};
}

static void begin_session(const struct tc_sm_fixture* fixture, TC_PIV_SM* session)
{
  TC_PIV_SM_workspace workspace;
  fixed_random_state random = {fixture->suite == TC_PIV_SM_CS2 ? 32u : 48u};
  uint8_t request[118];
  size_t written = 0;
  static const uint8_t host_id[8] = {0};
  memset(session,0,sizeof *session);
  munit_assert_int(example_piv_sm_begin(session,fixture->suite,host_id,fixed_scalar,&random,
      request,sizeof request,&written,&workspace),==,TC_OK);
  munit_assert_size(written,==,fixture->request.length);
  munit_assert_memory_equal(written,request,fixture->request.data);
}

static TC_PIV_SM_authentication authentication(const struct tc_sm_fixture* fixture,
    const TC_X509_certificate* signer, const TC_TLV_limits* limits,
    const TC_X509_signature_provider* signatures)
{
  ExamplePIVSMResponse response;
  munit_assert_int(example_piv_sm_response_read(fixture->suite,fixture->response,
    &response),==,TC_OK);
  TC_PIV_SM_authentication value = {
    response.peer,fixture->intermediate,{NULL,0},signer,limits,signatures
  };
  return value;
}

static MunitResult authenticate(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const TC_TLV_limits limits = {4096,4096,128,8};
  const TC_X509_signature_provider accepted = {accept_signature,NULL,NULL};
  const TC_X509_signature_provider rejected = {reject_signature,NULL,NULL};
  TC_X509_certificate signer = {0};
  signer.extensions = (TC_bytes){signer_extensions,sizeof signer_extensions};

  for (size_t i = 0; i < sizeof sm_fixtures / sizeof *sm_fixtures; ++i) {
    const struct tc_sm_fixture* fixture = &sm_fixtures[i];
    TC_PIV_SM session;
    TC_PIV_SM_authentication_workspace workspace;
    size_t work = TEST_WORK;
    signer_key(fixture,&signer);
    begin_session(fixture,&session);
    TC_PIV_SM_authentication request = authentication(fixture,&signer,&limits,&accepted);
    if (fixture->intermediate.length) {
      ExamplePIVSMResponse parsed;
      TC_PIV_CVC checked;
      TC_EC_workspace points;
      size_t chain_work = TEST_WORK;
      munit_assert_int(example_piv_sm_response_read(fixture->suite,fixture->response,
          &parsed),==,TC_OK);
      const TC_PIV_CVC_chain_request chain = {parsed.peer.certificate,fixture->intermediate,
          {NULL,0},fixture->suite == TC_PIV_SM_CS2 ? TC_EC_P256 : TC_EC_P384,&signer};
      munit_assert_int(TC_PIV_CVC_chain_verify(&chain,&limits,&accepted,&points,
          &chain_work,&checked),==,TC_X509_SIGNATURE_VALID);
    }
    munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,&work,&workspace),
        ==,TC_CREDENTIAL_VALID);
    munit_assert_uint(session.state,==,TC_PIV_SM_READY);
    munit_assert_true(tc_test_all_zero(&workspace,sizeof workspace));
    const size_t key_bytes = fixture->suite == TC_PIV_SM_CS2 ? 16 : 32;
    munit_assert_memory_equal(key_bytes,session.data.traffic.mac_key,
        fixture->material.data + key_bytes);
    munit_assert_memory_equal(key_bytes,session.data.traffic.enc_key,
        fixture->material.data + 2 * key_bytes);
    munit_assert_memory_equal(key_bytes,session.data.traffic.rmac_key,
        fixture->material.data + 3 * key_bytes);
    const size_t required_work = TEST_WORK - work;
    munit_assert_size(required_work,>,0);

    ExamplePIVSMCommand command = {{NULL,0},0x20,0,0x80,0};
    uint8_t protected_command[16];
    size_t written = 0;
    munit_assert_int(example_piv_sm_protect(&session,&command,protected_command,
        sizeof protected_command,&written,&workspace.session),==,TC_OK);
    munit_assert_size(written,==,fixture->command.length);
    munit_assert_memory_equal(written,protected_command,fixture->command.data);
    ExamplePIVSMResult reply;
    munit_assert_int(example_piv_sm_unprotect(&session,fixture->reply,
        0x9000,NULL,0,&reply,&workspace.session),==,TC_OK);
    munit_assert_size(reply.length,==,0);
    munit_assert_uint(reply.status,==,0x9000);
    munit_assert_uint(session.state,==,TC_PIV_SM_READY);

    begin_session(fixture,&session);
    request = authentication(fixture,&signer,&limits,&accepted);
    work = required_work - 1;
    munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,&work,&workspace),
        ==,TC_CREDENTIAL_LIMIT);
    munit_assert_true(tc_test_all_zero(&session,sizeof session));

    uint8_t changed_response[512];
    munit_assert_size(fixture->response.length,<=,sizeof changed_response);
    memcpy(changed_response,fixture->response.data,fixture->response.length);
    ExamplePIVSMResponse parsed;
    munit_assert_int(example_piv_sm_response_read(fixture->suite,fixture->response,
        &parsed),==,TC_OK);
    const size_t cryptogram_offset = (size_t)(parsed.peer.cryptogram.data - fixture->response.data);
    changed_response[cryptogram_offset] ^= 1;
    begin_session(fixture,&session);
    request = authentication(fixture,&signer,&limits,&accepted);
    request.peer.cryptogram = (TC_bytes){changed_response + cryptogram_offset,16};
    request.peer.certificate = (TC_bytes){changed_response +
      (parsed.peer.certificate.data - fixture->response.data),parsed.peer.certificate.length};
    request.peer.nonce = (TC_bytes){changed_response +
      (parsed.peer.nonce.data - fixture->response.data),parsed.peer.nonce.length};
    work = TEST_WORK;
    munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,&work,&workspace),
        ==,TC_CREDENTIAL_INVALID);
    munit_assert_true(tc_test_all_zero(&session,sizeof session));

    begin_session(fixture,&session);
    request.signatures = &rejected;
    work = TEST_WORK;
    munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,&work,&workspace),
        ==,TC_CREDENTIAL_INVALID);
    munit_assert_true(tc_test_all_zero(&session,sizeof session));
    munit_assert_true(tc_test_all_zero(&workspace,sizeof workspace));

    begin_session(fixture,&session);
    static const uint8_t wrong_uuid[16] = {0xff};
    request = authentication(fixture,&signer,&limits,&accepted);
    request.expected_uuid = (TC_bytes){wrong_uuid,sizeof wrong_uuid};
    work = TEST_WORK;
    munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,&work,&workspace),
        ==,TC_CREDENTIAL_INVALID);
    munit_assert_true(tc_test_all_zero(&session,sizeof session));

    begin_session(fixture,&session);
    request = authentication(fixture,&signer,&limits,&accepted);
    request.peer.nonce.length = 0;
    work = TEST_WORK;
    munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,&work,&workspace),
        ==,TC_CREDENTIAL_INVALID);
    munit_assert_true(tc_test_all_zero(&session,sizeof session));
  }
  return MUNIT_OK;
}

static MunitResult arguments(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const TC_TLV_limits limits = {4096,4096,128,8};
  const TC_X509_signature_provider signatures = {accept_signature,NULL,NULL};
  TC_X509_certificate signer = {0};
  signer.extensions = (TC_bytes){signer_extensions,sizeof signer_extensions};
  TC_PIV_SM session, saved;
  TC_PIV_SM_authentication_workspace workspace;
  size_t work = TEST_WORK;
  begin_session(&sm_fixtures[0],&session);
  saved = session;
  TC_PIV_SM_authentication request = authentication(&sm_fixtures[0],&signer,&limits,&signatures);
  munit_assert_int(TC_PIV_SM_authenticate_response(&session,NULL,&work,&workspace),
      ==,TC_CREDENTIAL_ERROR);
  munit_assert_memory_equal(sizeof session,&session,&saved);
  munit_assert_size(work,==,TEST_WORK);
  munit_assert_int(TC_PIV_SM_authenticate_response(&session,&request,(size_t*)&session,&workspace),
      ==,TC_CREDENTIAL_ERROR);
  munit_assert_memory_equal(sizeof session,&session,&saved);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/response",authenticate,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/arguments",arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
static const MunitSuite suite = {"/piv-sm-authenticate",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
int main(int argc, char** argv) { return munit_suite_main(&suite,NULL,argc,argv); }
