/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AES-EAX (Bellare, Rogaway, Wagner) and EAX' (ANSI C12.22) authenticated
 * encryption. */
#include "aes_mac_core_internal.h"

#if (defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)) || \
    (defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1))

#if defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1)
/* C12.22 defines EAX' field values in the reference implementation's
 * little-endian byte order, so its doubling shifts toward higher indexes and
 * applies the reduction constant to byte zero. */
static void tc_aes_eax_prime_double(uint8_t value[TC_AES_BLOCKLEN])
{
  uint8_t carry = 0;
  unsigned i;

  for (i = 0; i < TC_AES_BLOCKLEN; ++i)
  {
    const uint8_t next = (uint8_t)(value[i] >> 7);
    value[i] = (uint8_t)((value[i] << 1) | carry);
    carry = next;
  }
  value[0] ^= (uint8_t)(0x87u & (uint8_t)(0u - carry));
}
#endif

#if (defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)) || \
    (defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1))
static TC_status tc_aes_eax_constants(const struct TC_AES_key_ctx* aes,
                              uint8_t d[TC_AES_BLOCKLEN],
                              uint8_t q[TC_AES_BLOCKLEN],
                              void (*double_subkey)(uint8_t[TC_AES_BLOCKLEN]))
{
  uint8_t l[TC_AES_BLOCKLEN] = { 0 };
  TC_status status = tc_aes_cipher((state_t*)l, aes->round_key);
  if (status != TC_OK) goto done;
  tc_aes_copy_bytes(d, l, TC_AES_BLOCKLEN);
  double_subkey(d);
  tc_aes_copy_bytes(q, d, TC_AES_BLOCKLEN);
  double_subkey(q);
done:
#if TC_ZEROIZE
  TC_secure_zero(l, sizeof(l));
#endif
  return status;
}
#endif

#if defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)
static TC_status tc_aes_eax_key_constants(const struct TC_AES_key_ctx* aes,
                              uint8_t d[TC_AES_BLOCKLEN],
                              uint8_t q[TC_AES_BLOCKLEN])
{
  return tc_aes_eax_constants(aes, d, q, tc_aes_gf128_double);
}
#endif

#if defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1)
static TC_status tc_aes_eax_prime_key_constants(const struct TC_AES_key_ctx* aes,
                                    uint8_t d[TC_AES_BLOCKLEN],
                                    uint8_t q[TC_AES_BLOCKLEN])
{
  return tc_aes_eax_constants(aes, d, q, tc_aes_eax_prime_double);
}
#endif

/* CMAC with an optional EAX domain prefix. Passing domain < 0 implements the
 * C12.22 CMAC' form, whose CBC initial value is D or Q. */
static TC_status tc_aes_eax_cmac(const struct TC_AES_key_ctx* aes,
                     const uint8_t initial[TC_AES_BLOCKLEN], int domain,
                     const uint8_t* data, size_t length,
                     const uint8_t complete_subkey[TC_AES_BLOCKLEN],
                     const uint8_t partial_subkey[TC_AES_BLOCKLEN],
                     uint8_t result[TC_AES_BLOCKLEN])
{
  uint8_t mac[TC_AES_BLOCKLEN];
  uint8_t block[TC_AES_BLOCKLEN] = { 0 };
  size_t used = 0;
  const tc_aes_mac_key mac_key = {aes->round_key,TC_AES_FIXED_ROUNDS};
  const tc_mac_cipher cipher = tc_aes_mac_cipher(&mac_key);
  TC_status status = TC_OK;

  tc_aes_copy_bytes(mac, initial, TC_AES_BLOCKLEN);
  if (domain >= 0) {
    block[TC_AES_BLOCKLEN - 1u] = (uint8_t)domain;
    used = TC_AES_BLOCKLEN;
  }
  status = tc_mac_cbc_update(&cipher,mac,block,&used,data,length,1);
  if (status == TC_OK)
    status = tc_mac_cmac_final(&cipher,mac,block,used,complete_subkey,partial_subkey,result);
#if TC_ZEROIZE
  TC_secure_zero(mac, sizeof(mac));
  TC_secure_zero(block, sizeof(block));
#endif
  return status;
}

#if defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)
static TC_status tc_aes_eax_omac(const struct TC_AES_key_ctx* aes, const uint8_t d[TC_AES_BLOCKLEN],
                     const uint8_t q[TC_AES_BLOCKLEN], uint8_t domain,
                     const uint8_t* data, size_t length,
                     uint8_t result[TC_AES_BLOCKLEN])
{
  uint8_t initial[TC_AES_BLOCKLEN] = { 0 };
  return tc_aes_eax_cmac(aes, initial, domain, data, length, d, q, result);
}
#endif

static TC_status tc_aes_eax_ctr_xor(const struct TC_AES_key_ctx* aes,
                        const uint8_t initial[TC_AES_BLOCKLEN],
                        const uint8_t* input, uint8_t* output, size_t length,
                        int prime)
{
  return tc_aes_mac_ctr_xor(aes->round_key, initial, input, output, length,
                            (tc_aes_mac_ctr_bits){ 1u, 3u, (uint8_t)prime });
}

#if defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)

static TC_status tc_aes_eax_crypt(const uint8_t* key, const uint8_t* nonce,
                     size_t nonce_len, const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, size_t input_len, uint8_t* output,
                     const uint8_t* expected_tag, uint8_t* output_tag,
                     size_t tag_len, int decrypt)
{
  struct {
    struct TC_AES_key_ctx aes;
    uint8_t nonce_mac[TC_AES_BLOCKLEN];
    uint8_t header_mac[TC_AES_BLOCKLEN];
    uint8_t message_mac[TC_AES_BLOCKLEN];
    uint8_t full_tag[TC_AES_BLOCKLEN];
    uint8_t d[TC_AES_BLOCKLEN];
    uint8_t q[TC_AES_BLOCKLEN];
  } st;
  TC_status status = TC_ERROR;
  uint8_t i;
  int output_started = 0;

  if (key == NULL || (nonce_len != 0 && nonce == NULL) ||
      (aad_len != 0 && aad == NULL) ||
      (input_len != 0 && (input == NULL || output == NULL)) ||
      (decrypt ? expected_tag == NULL : output_tag == NULL) ||
      tag_len < TC_AES_EAX_MIN_TAG_LEN || tag_len > TC_AES_BLOCKLEN ||
      !tc_aes_buffers_ok(input, input_len, output, input_len) ||
      !tc_aes_buffers_disjoint(output, input_len,
                               decrypt ? (const void*)expected_tag
                                       : (const void*)output_tag,
                               tag_len))
    return TC_ERROR;

  if (TC_AES_key_init(&st.aes, key) != TC_OK)
    goto done;
  if (tc_aes_eax_key_constants(&st.aes, st.d, st.q) != TC_OK ||
      tc_aes_eax_omac(&st.aes, st.d, st.q, 0, nonce, nonce_len, st.nonce_mac) != TC_OK ||
      tc_aes_eax_omac(&st.aes, st.d, st.q, 1, aad, aad_len, st.header_mac) != TC_OK)
    goto done;

  if (decrypt)
  {
    if (tc_aes_eax_omac(&st.aes, st.d, st.q, 2, input, input_len, st.message_mac) != TC_OK)
      goto done;
    for (i = 0; i < TC_AES_BLOCKLEN; ++i)
      st.full_tag[i] = (uint8_t)(st.nonce_mac[i] ^ st.header_mac[i] ^
                                 st.message_mac[i]);
    status = TC_ct_equal(st.full_tag, expected_tag, tag_len);
    if (status == TC_OK)
    {
      /* EAX verifies before CTR decryption, so unauthenticated plaintext is
       * never written to the caller's buffer. */
      output_started = 1;
      status = tc_aes_eax_ctr_xor(&st.aes, st.nonce_mac, input, output, input_len, 0);
    }
  }
  else
  {
    output_started = 1;
    if (tc_aes_eax_ctr_xor(&st.aes, st.nonce_mac, input, output, input_len, 0) != TC_OK ||
        tc_aes_eax_omac(&st.aes, st.d, st.q, 2, output, input_len, st.message_mac) != TC_OK)
      goto done;
    for (i = 0; i < TC_AES_BLOCKLEN; ++i)
      st.full_tag[i] = (uint8_t)(st.nonce_mac[i] ^ st.header_mac[i] ^
                                 st.message_mac[i]);
    tc_aes_copy_bytes(output_tag, st.full_tag, tag_len);
    status = TC_OK;
  }

done:
  if (status != TC_OK && output_started && input_len != 0)
    TC_secure_zero(output, input_len);
#if TC_ZEROIZE
  TC_secure_zero(&st, sizeof(st));
#endif
  return status;
}

TC_status TC_AES_EAX_encrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len)
{
  return tc_aes_eax_crypt(key, nonce, nonce_len, aad, aad_len, plaintext,
                   plaintext_len, ciphertext, NULL, tag, tag_len, 0);
}

TC_status TC_AES_EAX_decrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* tag, size_t tag_len, uint8_t* plaintext)
{
  return tc_aes_eax_crypt(key, nonce, nonce_len, aad, aad_len, ciphertext,
                   ciphertext_len, plaintext, tag, NULL, tag_len, 1);
}

#endif /* EAX */

#if defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1)

static TC_status tc_aes_eax_prime_crypt(const uint8_t* key, const uint8_t* cleartext,
                           size_t cleartext_len, const uint8_t* input,
                           size_t input_len, uint8_t* output,
                           const uint8_t* expected_tag, uint8_t* output_tag,
                           int decrypt)
{
  struct {
    struct TC_AES_key_ctx aes;
    uint8_t d[TC_AES_BLOCKLEN];
    uint8_t q[TC_AES_BLOCKLEN];
    uint8_t nonce_mac[TC_AES_BLOCKLEN];
    uint8_t message_mac[TC_AES_BLOCKLEN];
    uint8_t full_tag[TC_AES_BLOCKLEN];
  } st;
  uint8_t i;
  TC_status status = TC_ERROR;
  int output_started = 0;

  if (key == NULL || (cleartext_len != 0 && cleartext == NULL) ||
      (input_len != 0 && (input == NULL || output == NULL)) ||
      (decrypt ? expected_tag == NULL : output_tag == NULL) ||
      !tc_aes_buffers_ok(input, input_len, output, input_len) ||
      !tc_aes_buffers_disjoint(output, input_len,
                               decrypt ? (const void*)expected_tag
                                       : (const void*)output_tag,
                               TC_AES_EAX_PRIME_TAG_LEN))
    return TC_ERROR;

  if (TC_AES_key_init(&st.aes, key) != TC_OK)
    goto done;
  if (tc_aes_eax_prime_key_constants(&st.aes, st.d, st.q) != TC_OK ||
      tc_aes_eax_cmac(&st.aes, st.d, -1, cleartext, cleartext_len, st.d, st.q,
                      st.nonce_mac) != TC_OK)
    goto done;

  if (decrypt)
  {
    if (tc_aes_eax_cmac(&st.aes, st.q, -1, input, input_len, st.d, st.q, st.message_mac) != TC_OK)
      goto done;
    for (i = 0; i < TC_AES_BLOCKLEN; ++i)
      st.full_tag[i] = (uint8_t)(st.nonce_mac[i] ^ st.message_mac[i]);
    /* EAX' writes its four-byte tag in reverse order. Reuse message_mac as a
     * small comparison buffer after its full-block value has been consumed. */
    for (i = 0; i < TC_AES_EAX_PRIME_TAG_LEN; ++i)
      st.message_mac[i] = st.full_tag[TC_AES_BLOCKLEN - 1u - i];
    status = TC_ct_equal(st.message_mac, expected_tag,
                         TC_AES_EAX_PRIME_TAG_LEN);
    if (status == TC_OK)
    {
      output_started = 1;
      status = tc_aes_eax_ctr_xor(&st.aes, st.nonce_mac, input, output, input_len, 1);
    }
  }
  else
  {
    output_started = 1;
    if (tc_aes_eax_ctr_xor(&st.aes, st.nonce_mac, input, output, input_len, 1) != TC_OK ||
        tc_aes_eax_cmac(&st.aes, st.q, -1, output, input_len, st.d, st.q, st.message_mac) != TC_OK)
      goto done;
    for (i = 0; i < TC_AES_BLOCKLEN; ++i)
      st.full_tag[i] = (uint8_t)(st.nonce_mac[i] ^ st.message_mac[i]);
    for (i = 0; i < TC_AES_EAX_PRIME_TAG_LEN; ++i)
      output_tag[i] = st.full_tag[TC_AES_BLOCKLEN - 1u - i];
    status = TC_OK;
  }

done:
  if (status != TC_OK && output_started && input_len != 0)
    TC_secure_zero(output, input_len);
#if TC_ZEROIZE
  TC_secure_zero(&st, sizeof(st));
#endif
  return status;
}

TC_status TC_AES_EAX_PRIME_encrypt(const uint8_t* key, const uint8_t* cleartext,
                          size_t cleartext_len, const uint8_t* plaintext,
                          size_t plaintext_len, uint8_t* ciphertext,
                          uint8_t tag[TC_AES_EAX_PRIME_TAG_LEN])
{
  return tc_aes_eax_prime_crypt(key, cleartext, cleartext_len, plaintext,
                         plaintext_len, ciphertext, NULL, tag, 0);
}

TC_status TC_AES_EAX_PRIME_decrypt(const uint8_t* key, const uint8_t* cleartext,
                          size_t cleartext_len, const uint8_t* ciphertext,
                          size_t ciphertext_len,
                          const uint8_t tag[TC_AES_EAX_PRIME_TAG_LEN],
                          uint8_t* plaintext)
{
  return tc_aes_eax_prime_crypt(key, cleartext, cleartext_len, ciphertext,
                         ciphertext_len, plaintext, tag, NULL, 1);
}

#endif /* EAX_PRIME */

#endif /* EAX || EAX_PRIME */
