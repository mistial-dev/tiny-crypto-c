/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TEST_TWIC_CARD_FIXTURE_H_
#define TEST_TWIC_CARD_FIXTURE_H_
#include "fascn_fixture.h"
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
typedef enum {
  NORMAL,
  TAMPERED,
  REPLAY,
  WRONG_TAG,
  TRAILING,
  SIGN_LENGTH_ERROR,
  TRANSPORT_ERROR,
  CHAIN_STATUS_ERROR
} CardMode;
typedef struct {
  EVP_PKEY* key;
  /* legacy selects TWIC sub-version 01 (Legacy) in place of 03 (NEXGEN). */
  uint8_t algorithm, reference, pss, legacy, request[512], reply[512], saved_reply[512];
  size_t request_length, reply_length, reply_offset, saved_length;
  size_t calls, signatures, fail_at;
  CardMode mode;
  TC_TWIC_CCL_store* replacement_store;
  TC_TWIC_CCL_snapshot* replacement;
} SyntheticCard;
typedef struct {
  unsigned sequence;
  int fail;
  size_t calls;
} Entropy;

static TC_status random_digest(void* context, uint8_t* output, size_t length)
{
  Entropy* entropy = context;
  ++entropy->calls;
  for (size_t i = 0; i < length; ++i)
    output[i] = (uint8_t)(entropy->sequence + i);
  ++entropy->sequence;
  return entropy->fail ? TC_ERROR : TC_OK;
}

static void make_reply(SyntheticCard* card)
{
  /* Compare the transmitted framing against independent, fixed encodings. */
  static const uint8_t rsa1024[] = {0x7c, 0x81, 0x85, 0x82, 0, 0x81, 0x81, 0x80};
  static const uint8_t rsa2048[] = {0x7c, 0x82, 1, 6, 0x82, 0, 0x81, 0x82, 1, 0};
  static const uint8_t rsa3072[] = {0x7c, 0x82, 1, 0x86, 0x82, 0, 0x81, 0x82, 1, 0x80};
  static const uint8_t p256[] = {0x7c, 36, 0x82, 0, 0x81, 32};
  static const uint8_t p384[] = {0x7c, 52, 0x82, 0, 0x81, 48};
  const uint8_t* header = p256;
  size_t header_length = sizeof p256;
  if (card->algorithm == TC_PIV_ALGORITHM_RSA_1024) {
    header = rsa1024;
    header_length = sizeof rsa1024;
  }
  if (card->algorithm == TC_PIV_ALGORITHM_RSA_2048) {
    header = rsa2048;
    header_length = sizeof rsa2048;
  }
  if (card->algorithm == TC_PIV_ALGORITHM_RSA_3072) {
    header = rsa3072;
    header_length = sizeof rsa3072;
  }
  if (card->algorithm == TC_PIV_ALGORITHM_ECC_P384) {
    header = p384;
    header_length = sizeof p384;
  }
  munit_assert_size(card->request_length, >, header_length);
  munit_assert_memory_equal(header_length, card->request, header);
  const uint8_t* challenge = card->request + header_length;
  const size_t challenge_length = card->request_length - header_length;
  EVP_PKEY_CTX* signer = EVP_PKEY_CTX_new(card->key, NULL);
  uint8_t signature[384];
  size_t length = sizeof signature;
  munit_assert_not_null(signer);
  munit_assert_int(EVP_PKEY_sign_init(signer), ==, 1);
  if (EVP_PKEY_is_a(card->key, "RSA")) {
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signer, RSA_NO_PADDING), ==, 1);
    munit_assert_size(challenge_length, ==, (size_t)EVP_PKEY_get_size(card->key));
  } else {
    const EVP_MD* hash = card->algorithm == TC_PIV_ALGORITHM_ECC_P384 ? EVP_sha384() : EVP_sha256();
    munit_assert_int(EVP_PKEY_CTX_set_signature_md(signer, hash), ==, 1);
    munit_assert_size(challenge_length, ==, (size_t)EVP_MD_get_size(hash));
  }
  munit_assert_int(EVP_PKEY_sign(signer, signature, &length, challenge, challenge_length), ==, 1);
  EVP_PKEY_CTX_free(signer);
  if (EVP_PKEY_is_a(card->key, "RSA") && !card->pss) {
    EVP_PKEY_CTX* verifier = EVP_PKEY_CTX_new(card->key, NULL);
    munit_assert_not_null(verifier);
    munit_assert_int(EVP_PKEY_verify_init(verifier), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verifier, RSA_PKCS1_PADDING), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_signature_md(verifier, EVP_sha256()), ==, 1);
    munit_assert_int(
        EVP_PKEY_verify(verifier, signature, length, challenge + challenge_length - 32, 32), ==, 1);
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
  memcpy(card->reply + used, signature, length);
  card->reply_length = used + length;
  if (card->mode == TAMPERED)
    card->reply[used + length - 1] ^= 1;
  if (card->mode == WRONG_TAG)
    card->reply[0] ^= 1;
  if (card->mode == TRAILING)
    card->reply[card->reply_length++] = 0;
  if (card->mode == REPLAY) {
    munit_assert_size(card->saved_length, >, 0);
    memcpy(card->reply, card->saved_reply, card->saved_length);
    card->reply_length = card->saved_length;
  } else if (card->mode == NORMAL) {
    memcpy(card->saved_reply, card->reply, card->reply_length);
    card->saved_length = card->reply_length;
  }
}

/* SELECT answers the application property template of the PIV AID or of the
 * TWIC AID prefix with its version (SP 800-73-5 Part 2 3.1.1, TWIC Part 2 v5
 * 5.1): 61 {4F AID, 79 {4F RID}}. */
static TC_status select_answer(const SyntheticCard* card, TC_bytes command, TC_buffer response,
                               size_t* length)
{
  munit_assert_size(command.length, >=, 6);
  const size_t aid_length = command.data[4];
  munit_assert_size(command.length, ==, 5 + aid_length + 1);
  const int twic = aid_length == 9;
  munit_assert_true(twic || aid_length == 11);
  uint8_t* out = response.data;
  munit_assert_size(response.capacity, >=, 26);
  size_t used = 0;
  out[used++] = 0x61;
  out[used++] = 22;
  out[used++] = 0x4f;
  out[used++] = 11;
  memcpy(out + used, command.data + 5, aid_length);
  used += aid_length;
  if (twic) {
    out[used++] = 0x01;
    out[used++] = card->legacy ? 0x01 : 0x03;
  }
  out[used++] = 0x79;
  out[used++] = 7;
  out[used++] = 0x4f;
  out[used++] = 5;
  memcpy(out + used, command.data + 5, 5);
  used += 5;
  out[used++] = 0x90;
  out[used++] = 0;
  *length = used;
  return TC_OK;
}

/* GENERAL AUTHENTICATE with 7C {82 00, 81 challenge}, SHORT with CLA 10
 * chaining or one EXTENDED command, and GET RESPONSE of the answer. */
static TC_status transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  SyntheticCard* card = context;
  ++card->calls;
  if (card->replacement && card->calls == 1)
    munit_assert_int(TC_TWIC_CCL_store_publish(card->replacement_store,
                                               card->replacement_store->revision,
                                               card->replacement),
                     ==, TC_TWIC_CCL_OK);
  if (card->mode == TRANSPORT_ERROR || card->calls == card->fail_at)
    return TC_ERROR;
  munit_assert_size(command.length, >=, 5);
  if (command.data[1] == 0xa4)
    return select_answer(card, command, response, length);
  size_t requested = command.data[command.length - 1];
  if (command.data[1] == 0x87) {
    munit_assert_uint(command.data[2], ==, card->algorithm);
    munit_assert_uint(command.data[3], ==,
                      card->reference ? card->reference : TC_PIV_KEY_CARD_AUTHENTICATION);
    const int chained = command.data[0] == 0x10;
    const int extended = command.data[4] == 0 && command.length > 7;
    const size_t chunk =
        extended ? (size_t)command.data[5] << 8 | command.data[6] : command.data[4];
    const uint8_t* data = command.data + (extended ? 7 : 5);
    munit_assert_size(command.length, ==,
                      (extended ? 7 : 5) + chunk +
                          (chained    ? 0
                           : extended ? 2
                                      : 1));
    munit_assert_size(card->request_length + chunk, <=, sizeof card->request);
    const size_t before = card->request_length;
    memcpy(card->request + card->request_length, data, chunk);
    card->request_length += chunk;
    if (chained) {
      munit_assert_false(extended);
      munit_assert_size(chunk, ==, 255);
      munit_assert_size(response.capacity, >=, 2);
      response.data[0] = card->mode == CHAIN_STATUS_ERROR ? 0x69 : 0x90;
      response.data[1] = card->mode == CHAIN_STATUS_ERROR ? 0x82 : 0;
      *length = 2;
      return TC_OK;
    }
    munit_assert_uint(command.data[0], ==, 0);
    /* Le 00 (Part 2 A.4.1), or the link's extended Ne. */
    if (extended) {
      requested = (size_t)command.data[command.length - 2] << 8 | command.data[command.length - 1];
      if (!requested)
        requested = 65536;
    } else
      munit_assert_uint(command.data[command.length - 1], ==, 0);
    if (card->mode == SIGN_LENGTH_ERROR) {
      /* The channel may send this step again with Le = SW2. */
      card->request_length = before;
      response.data[0] = 0x6c;
      response.data[1] = 0;
      *length = 2;
      return TC_OK;
    }
    make_reply(card);
  } else {
    static const uint8_t get_response[] = {0, 0xc0, 0, 0};
    munit_assert_size(command.length, ==, 5);
    munit_assert_memory_equal(sizeof get_response, command.data, get_response);
    munit_assert_size(card->reply_offset, >, 0);
  }
  size_t chunk = card->reply_length - card->reply_offset;
  if (!requested)
    requested = 256;
  if (chunk > requested)
    chunk = requested;
  munit_assert_size(chunk + 2, <=, response.capacity);
  memcpy(response.data, card->reply + card->reply_offset, chunk);
  card->reply_offset += chunk;
  const size_t remaining = card->reply_length - card->reply_offset;
  response.data[chunk] = remaining ? 0x61 : 0x90;
  response.data[chunk + 1] = (uint8_t)remaining;
  *length = chunk + 2;
  return TC_OK;
}

#endif
