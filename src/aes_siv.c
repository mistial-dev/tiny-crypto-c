/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AES-SIV deterministic authenticated encryption (RFC 5297). */
#include "aes_mac_core_internal.h"

#if TC_AES_ENABLE_SIV
/* AES-CMAC under the S2V key over one or two concatenated parts. */
static TC_status tc_aes_siv_cmac(const uint8_t* round_key, const uint8_t k1[TC_AES_BLOCKLEN],
                                 const uint8_t k2[TC_AES_BLOCKLEN], const TC_bytes* parts,
                                 size_t count, uint8_t out[TC_AES_BLOCKLEN])
{
  const tc_aes_mac_key key = {round_key, TC_AES_FIXED_ROUNDS};
  const tc_mac_cipher cipher = tc_aes_mac_cipher(&key);
  return tc_mac_cmac_parts(&cipher, NULL, parts, count, k1, k2, out);
}

static TC_status tc_aes_siv_s2v(const uint8_t* k1_round, const uint8_t* const* ad,
                                const size_t* ad_lens, size_t ad_count, const uint8_t* last,
                                size_t last_len, uint8_t v[TC_AES_BLOCKLEN])
{
  uint8_t d[TC_AES_BLOCKLEN];
  uint8_t tmp[TC_AES_BLOCKLEN];
  uint8_t last_block[TC_AES_BLOCKLEN];
  uint8_t k1[TC_AES_BLOCKLEN];
  uint8_t k2[TC_AES_BLOCKLEN];
  size_t i;
  const uint8_t zero[TC_AES_BLOCKLEN] = {0};
  TC_status status;

  /* Every S2V component uses the same CMAC key, so derive its subkeys once. */
  status = tc_aes_cmac_generate_subkeys(k1_round, TC_AES_FIXED_ROUNDS, k1, k2);
  if (status != TC_OK)
    goto done;
  status = tc_aes_siv_cmac(k1_round, k1, k2, &(TC_bytes){zero, TC_AES_BLOCKLEN}, 1, d);
  if (status != TC_OK)
    goto done;
  for (i = 0; i < ad_count; ++i) {
    uint8_t j;
    status = tc_aes_siv_cmac(k1_round, k1, k2,
                             &(TC_bytes){ad[i] != NULL ? ad[i] : zero, ad_lens[i]}, 1, tmp);
    if (status != TC_OK)
      goto done;
    tc_aes_gf128_double(d);
    for (j = 0; j < TC_AES_BLOCKLEN; ++j)
      d[j] ^= tmp[j];
  }

  if (last_len >= TC_AES_BLOCKLEN) {
    /* T = last xorend D = prefix || (suffix xor D); CMAC(T). */
    memcpy(last_block, last + (last_len - TC_AES_BLOCKLEN), TC_AES_BLOCKLEN);
    for (i = 0; i < TC_AES_BLOCKLEN; ++i)
      last_block[i] ^= d[i];
    const TC_bytes parts[] = {{last, last_len - TC_AES_BLOCKLEN}, {last_block, TC_AES_BLOCKLEN}};
    status = tc_aes_siv_cmac(k1_round, k1, k2, parts, 2, v);
  } else {
    /* T = dbl(D) xor pad(last); single-block CMAC input. */
    uint8_t t[TC_AES_BLOCKLEN];
    uint8_t j;
    memcpy(t, d, TC_AES_BLOCKLEN);
    tc_aes_gf128_double(t);
    memset(tmp, 0, TC_AES_BLOCKLEN);
    if (last_len != 0 && last != NULL)
      memcpy(tmp, last, last_len);
    tmp[last_len] = 0x80;
    for (j = 0; j < TC_AES_BLOCKLEN; ++j)
      t[j] ^= tmp[j];
    status = tc_aes_siv_cmac(k1_round, k1, k2, &(TC_bytes){t, TC_AES_BLOCKLEN}, 1, v);
#if TC_ZEROIZE
    TC_secure_zero(t, sizeof(t));
#endif
  }

done:
#if TC_ZEROIZE
  TC_secure_zero(d, sizeof(d));
  TC_secure_zero(tmp, sizeof(tmp));
  TC_secure_zero(last_block, sizeof(last_block));
  TC_secure_zero(k1, sizeof(k1));
  TC_secure_zero(k2, sizeof(k2));
#endif
  return status;
}

static TC_status tc_aes_siv_ctr(const uint8_t* k2_round, const uint8_t v[TC_AES_BLOCKLEN],
                                const uint8_t* input, uint8_t* output, size_t length)
{
  /* RFC 5297 clears bit 63 and bit 31 of the synthetic IV. */
  return tc_aes_mac_ctr_xor(k2_round, v, input, output, length, (tc_aes_mac_ctr_bits){8u, 12u, 1u});
}

static TC_status tc_aes_siv_crypt(const uint8_t* key, const uint8_t* const* ad,
                                  const size_t* ad_lens, size_t ad_count, const uint8_t* input,
                                  size_t input_len, uint8_t* output, uint8_t v[TC_AES_SIV_V_LEN],
                                  int decrypt)
{
  struct {
    struct TC_AES_key_ctx k1;
    struct TC_AES_key_ctx k2;
    uint8_t computed[TC_AES_BLOCKLEN];
  } st;
  size_t i;
  TC_status status = TC_ERROR;

  if (key == NULL || (ad_count != 0 && (ad == NULL || ad_lens == NULL)) ||
      ad_count > TC_AES_SIV_MAX_AD || (input_len != 0 && (input == NULL || output == NULL)) ||
      v == NULL || !tc_aes_buffers_ok(input, input_len, output, input_len))
    return TC_ERROR;

  for (i = 0; i < ad_count; ++i) {
    if (ad_lens[i] != 0 && ad[i] == NULL)
      return TC_ERROR;
  }

  if (TC_AES_key_init(&st.k1, key) != TC_OK ||
      TC_AES_key_init(&st.k2, key + TC_AES_KEYLEN) != TC_OK)
    goto done;

  if (decrypt) {
    status = tc_aes_siv_ctr(st.k2.round_key, v, input, output, input_len);
    if (status == TC_OK)
      status =
          tc_aes_siv_s2v(st.k1.round_key, ad, ad_lens, ad_count, output, input_len, st.computed);
    if (status == TC_OK)
      status = TC_ct_equal(st.computed, v, TC_AES_BLOCKLEN);
    if (status != TC_OK) {
      /* SIV decrypts before authenticating. Any failure discards plaintext. */
      if (output != NULL && input_len != 0)
        TC_secure_zero(output, input_len);
    }
  } else {
    status = tc_aes_siv_s2v(st.k1.round_key, ad, ad_lens, ad_count, input, input_len, v);
    if (status == TC_OK) {
      status = tc_aes_siv_ctr(st.k2.round_key, v, input, output, input_len);
      if (status != TC_OK && output != NULL && input_len != 0)
        TC_secure_zero(output, input_len);
    }
  }

done:
#if TC_ZEROIZE
  TC_secure_zero(&st, sizeof(st));
#endif
  return status;
}

TC_status TC_AES_SIV_encrypt(const uint8_t* key, const uint8_t* const* ad, const size_t* ad_lens,
                             size_t ad_count, const uint8_t* plaintext, size_t plaintext_len,
                             uint8_t v[TC_AES_SIV_V_LEN], uint8_t* ciphertext)
{
  uint8_t local_v[TC_AES_SIV_V_LEN];
  TC_status status;

  if (v == NULL)
    return TC_ERROR;
  /*
   * V is written after ciphertext. If they overlap, the post-encrypt copy
   * would clobber ciphertext (exact or partial). Stage V for pt alias only.
   */
  if (!tc_internal_ranges_disjoint(v, TC_AES_SIV_V_LEN, ciphertext, plaintext_len))
    return TC_ERROR;
  status = tc_aes_siv_crypt(key, ad, ad_lens, ad_count, plaintext, plaintext_len, ciphertext,
                            local_v, 0);
  if (status == TC_OK)
    memcpy(v, local_v, TC_AES_SIV_V_LEN);
#if TC_ZEROIZE
  TC_secure_zero(local_v, sizeof(local_v));
#endif
  return status;
}

TC_status TC_AES_SIV_decrypt(const uint8_t* key, const uint8_t* const* ad, const size_t* ad_lens,
                             size_t ad_count, const uint8_t v[TC_AES_SIV_V_LEN],
                             const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext)
{
  uint8_t local_v[TC_AES_SIV_V_LEN];
  TC_status status;

  if (v == NULL)
    return TC_ERROR;
  if (!tc_internal_ranges_disjoint(v, TC_AES_SIV_V_LEN, plaintext, ciphertext_len))
    return TC_ERROR;
  memcpy(local_v, v, TC_AES_SIV_V_LEN);
  status = tc_aes_siv_crypt(key, ad, ad_lens, ad_count, ciphertext, ciphertext_len, plaintext,
                            local_v, 1);
#if TC_ZEROIZE
  TC_secure_zero(local_v, sizeof(local_v));
#endif
  return status;
}

#endif /* SIV */
