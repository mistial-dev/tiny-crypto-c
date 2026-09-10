/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TEST_TWIC_CARD_FIXTURE_H_
#define TEST_TWIC_CARD_FIXTURE_H_
#include "fascn_fixture.h"
#include "../../examples/credential_auth.h"
#include "../../examples/credential_validate.h"
#include "../../examples/pki_input.h"
#include "../../examples/x509_workspace.h"
#include "../x509/openssl_fixture.h"
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/piv_card.h>
#include <tiny_crypto/twic_ccl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <string.h>

enum { WORK_LIMIT = 1000000, BUFFER_CAPACITY = 1024 };
typedef enum { NORMAL, TAMPERED, REPLAY, WRONG_TAG, TRAILING, SIGN_LENGTH_ERROR,
  TRANSPORT_ERROR, CHAIN_STATUS_ERROR } CardMode;
typedef struct {
  EVP_PKEY* key;
  uint8_t algorithm, reference, pss, request[512], reply[512], saved_reply[512];
  size_t request_length, reply_length, reply_offset, saved_length;
  size_t calls, signatures, fail_at;
  CardMode mode;
  TC_TWIC_CCL_store* replacement_store;
  TC_TWIC_CCL_snapshot* replacement;
} SyntheticCard;
typedef struct { unsigned sequence; int fail; size_t calls; } Entropy;

static TC_status random_digest(void* context, uint8_t* output, size_t length)
{
  Entropy* entropy = context;
  ++entropy->calls;
  for (size_t i = 0; i < length; ++i) output[i] = (uint8_t)(entropy->sequence + i);
  ++entropy->sequence;
  return entropy->fail ? TC_ERROR : TC_OK;
}

static void make_reply(SyntheticCard* card)
{
  /* Compare the transmitted framing against independent, fixed encodings. */
  static const uint8_t rsa1024[] = {0x7c,0x81,0x85,0x82,0,0x81,0x81,0x80};
  static const uint8_t rsa2048[] = {0x7c,0x82,1,6,0x82,0,0x81,0x82,1,0};
  static const uint8_t rsa3072[] = {0x7c,0x82,1,0x86,0x82,0,0x81,0x82,1,0x80};
  static const uint8_t p256[] = {0x7c,36,0x82,0,0x81,32};
  static const uint8_t p384[] = {0x7c,52,0x82,0,0x81,48};
  const uint8_t* header = p256;
  size_t header_length = sizeof p256;
  if (card->algorithm == EXAMPLE_CARD_ALGORITHM_RSA_1024) { header = rsa1024; header_length = sizeof rsa1024; }
  if (card->algorithm == EXAMPLE_CARD_ALGORITHM_RSA_2048) { header = rsa2048; header_length = sizeof rsa2048; }
  if (card->algorithm == EXAMPLE_CARD_ALGORITHM_RSA_3072) { header = rsa3072; header_length = sizeof rsa3072; }
  if (card->algorithm == EXAMPLE_CARD_ALGORITHM_EC_P384) { header = p384; header_length = sizeof p384; }
  munit_assert_size(card->request_length, >, header_length);
  munit_assert_memory_equal(header_length,card->request,header);
  const uint8_t* challenge = card->request + header_length;
  const size_t challenge_length = card->request_length - header_length;
  EVP_PKEY_CTX* signer = EVP_PKEY_CTX_new(card->key,NULL);
  uint8_t signature[384];
  size_t length = sizeof signature;
  munit_assert_not_null(signer);
  munit_assert_int(EVP_PKEY_sign_init(signer), ==, 1);
  if (EVP_PKEY_is_a(card->key,"RSA")) {
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signer,RSA_NO_PADDING), ==, 1);
    munit_assert_size(challenge_length, ==, (size_t)EVP_PKEY_get_size(card->key));
  } else {
    const EVP_MD* hash = card->algorithm == EXAMPLE_CARD_ALGORITHM_EC_P384 ? EVP_sha384() : EVP_sha256();
    munit_assert_int(EVP_PKEY_CTX_set_signature_md(signer,hash), ==, 1);
    munit_assert_size(challenge_length, ==, (size_t)EVP_MD_get_size(hash));
  }
  munit_assert_int(EVP_PKEY_sign(signer,signature,&length,challenge,challenge_length), ==, 1);
  EVP_PKEY_CTX_free(signer);
  if (EVP_PKEY_is_a(card->key,"RSA") && !card->pss) {
    EVP_PKEY_CTX* verifier = EVP_PKEY_CTX_new(card->key,NULL);
    munit_assert_not_null(verifier);
    munit_assert_int(EVP_PKEY_verify_init(verifier), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verifier,RSA_PKCS1_PADDING), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_signature_md(verifier,EVP_sha256()), ==, 1);
    munit_assert_int(EVP_PKEY_verify(verifier,signature,length,challenge + challenge_length - 32,32), ==, 1);
    EVP_PKEY_CTX_free(verifier);
  }
  ++card->signatures;
  card->request_length = 0;
  card->reply_offset = 0;
  size_t used = 0;
  card->reply[used++] = 0x7c;
  if (length < 128) {
    card->reply[used++] = (uint8_t)(length + 2);
    card->reply[used++] = 0x82;
    card->reply[used++] = (uint8_t)length;
  } else {
    card->reply[used++] = 0x82;
    card->reply[used++] = (uint8_t)((length + 4) >> 8);
    card->reply[used++] = (uint8_t)(length + 4);
    card->reply[used++] = 0x82;
    card->reply[used++] = 0x82;
    card->reply[used++] = (uint8_t)(length >> 8);
    card->reply[used++] = (uint8_t)length;
  }
  memcpy(card->reply + used,signature,length);
  card->reply_length = used + length;
  if (card->mode == TAMPERED) card->reply[used + length - 1] ^= 1;
  if (card->mode == WRONG_TAG) card->reply[0] ^= 1;
  if (card->mode == TRAILING) card->reply[card->reply_length++] = 0;
  if (card->mode == REPLAY) {
    munit_assert_size(card->saved_length, >, 0);
    memcpy(card->reply,card->saved_reply,card->saved_length);
    card->reply_length = card->saved_length;
  } else if (card->mode == NORMAL) {
    memcpy(card->saved_reply,card->reply,card->reply_length);
    card->saved_length = card->reply_length;
  }
}

static int transmit(void* context, const uint8_t* command, size_t command_length,
    uint8_t* response, size_t capacity, size_t* length)
{
  SyntheticCard* card = context;
  ++card->calls;
  if (card->replacement && card->calls == 1)
    munit_assert_int(TC_TWIC_CCL_store_publish(card->replacement_store,
        card->replacement_store->revision,card->replacement), ==, TC_TWIC_CCL_OK);
  if (card->mode == TRANSPORT_ERROR || card->calls == card->fail_at) return 0;
  munit_assert_size(command_length, >=, 5);
  if (command[1] == 0x87) {
    munit_assert_uint(command[2], ==, card->algorithm);
    munit_assert_uint(command[3], ==, card->reference ? card->reference : EXAMPLE_CARD_KEY_CARD_AUTHENTICATION);
    const int chained = command[0] == 0x10;
    const size_t chunk = command[4];
    munit_assert_size(command_length, ==, 5 + chunk + (chained ? 0 : 1));
    munit_assert_size(card->request_length + chunk, <=, sizeof card->request);
    memcpy(card->request + card->request_length,command + 5,chunk);
    card->request_length += chunk;
    if (chained) {
      munit_assert_size(chunk, ==, 255);
      munit_assert_size(capacity, >=, 2);
      response[0] = card->mode == CHAIN_STATUS_ERROR ? 0x69 : 0x90;
      response[1] = card->mode == CHAIN_STATUS_ERROR ? 0x82 : 0;
      *length = 2;
      return 1;
    }
    munit_assert_uint(command[0], ==, 0);
    munit_assert_uint(command[command_length - 1], ==, 0);
    if (card->mode == SIGN_LENGTH_ERROR) {
      response[0] = 0x6c;
      response[1] = 0;
      *length = 2;
      return 1;
    }
    make_reply(card);
  } else {
    static const uint8_t get_response[] = {0,0xc0,0,0};
    munit_assert_size(command_length, ==, 5);
    munit_assert_memory_equal(sizeof get_response,command,get_response);
    munit_assert_size(card->reply_offset, >, 0);
  }
  size_t chunk = card->reply_length - card->reply_offset;
  size_t requested = command[command_length - 1];
  if (!requested) requested = 256;
  if (chunk > requested) chunk = requested;
  munit_assert_size(chunk + 2, <=, capacity);
  memcpy(response,card->reply + card->reply_offset,chunk);
  card->reply_offset += chunk;
  const size_t remaining = card->reply_length - card->reply_offset;
  response[chunk] = remaining ? 0x61 : 0x90;
  response[chunk + 1] = (uint8_t)remaining;
  *length = chunk + 2;
  return 1;
}


#endif
