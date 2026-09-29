/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Incremental RSA key generation (FIPS 186-5 appendix A.1.3). */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_private_internal.h"

enum {
  TC_RSA_KEYGEN_EMPTY = 0,
  TC_RSA_KEYGEN_P_NEW,
  TC_RSA_KEYGEN_P_PREPARE,
  TC_RSA_KEYGEN_P_ROUND,
  TC_RSA_KEYGEN_Q_NEW,
  TC_RSA_KEYGEN_Q_PREPARE,
  TC_RSA_KEYGEN_Q_ROUND
};

static inline uint32_t tc_rsa_keygen_mod_u32(const uint8_t* value, size_t length, uint32_t modulus)
{
  uint32_t remainder = 0;
  for (size_t i = 0; i < length; ++i)
    remainder = (uint32_t)(((uint64_t)remainder * 256u + value[i]) % modulus);
  return remainder;
}

static inline uint32_t tc_rsa_keygen_gcd(uint32_t a, uint32_t b)
{
  while (b) {
    uint32_t remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}

/* Cheap public-candidate filtering avoids almost all expensive strong tests. */
static inline int tc_rsa_keygen_candidate_filter(const uint8_t* candidate, size_t length)
{
  static const uint8_t primes[] = {
      3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,  59,  61,  67,
      71,  73,  79,  83,  89,  97,  101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
      163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251};
  for (size_t i = 0; i < sizeof primes; ++i)
    if (tc_rsa_keygen_mod_u32(candidate, length, primes[i]) == 0)
      return 0;
  uint32_t residue = tc_rsa_keygen_mod_u32(candidate, length, TC_RSA_KEYGEN_PUBLIC_EXPONENT);
  residue = residue ? residue - 1 : TC_RSA_KEYGEN_PUBLIC_EXPONENT - 1;
  return tc_rsa_keygen_gcd(residue, TC_RSA_KEYGEN_PUBLIC_EXPONENT) == 1;
}

static inline int tc_rsa_keygen_far_apart(const uint8_t* p, const uint8_t* q, size_t length,
                                          tc_mp_word* scratch)
{
  const size_t n = length / sizeof(tc_mp_word);
  tc_mp_word* left = scratch;
  tc_mp_word* right = left + n;
  tc_mp_word* difference = right + n;
  tc_mp_from_be(left, p, length);
  tc_mp_from_be(right, q, length);
  if (tc_mp_subtract(difference, left, right, n))
    tc_mp_subtract(difference, right, left, n);
  /* FIPS 186-5 B.3.1 requires |p-q| > 2^(prime_bits-100). */
  const size_t threshold_bit = length * 8 - 100;
  const size_t word = threshold_bit / TC_MP_WORD_BITS;
  const unsigned bit = (unsigned)(threshold_bit % TC_MP_WORD_BITS);
  for (size_t i = n; i-- > word + 1;)
    if (difference[i])
      return 1;
  if (difference[word] > ((tc_mp_word)1u << bit))
    return 1;
  if (difference[word] < ((tc_mp_word)1u << bit))
    return 0;
  for (size_t i = 0; i < word; ++i)
    if (difference[i])
      return 1;
  return 0;
}

static inline uint32_t tc_rsa_keygen_inverse_65537(uint32_t value)
{
  uint32_t result = 1;
  /* 65537 is prime. A fixed addition chain computes value^(65537-2). */
  for (unsigned bit = 0; bit < 16; ++bit) {
    result = (uint32_t)((uint64_t)result * result % TC_RSA_KEYGEN_PUBLIC_EXPONENT);
    result = (uint32_t)((uint64_t)result * value % TC_RSA_KEYGEN_PUBLIC_EXPONENT);
  }
  return result;
}

/* Derive n and d from retained prime bytes. Scratch has at least 10h+2 limbs,
 * where h is the prime width. Results remain in scratch until publication. */
static inline void tc_rsa_keygen_derive(const uint8_t* p_bytes, const uint8_t* q_bytes,
                                        size_t prime_length, tc_mp_word* scratch,
                                        tc_mp_word** modulus_out, tc_mp_word** d_out)
{
  const size_t h = prime_length / sizeof(tc_mp_word), n = 2 * h;
  tc_mp_word* p = scratch;
  tc_mp_word* q = p + h;
  tc_mp_word* modulus = q + h;
  tc_mp_word* phi = modulus + n;
  tc_mp_word* numerator = phi + n;
  const size_t extra = (16 + TC_MP_WORD_BITS - 1) / TC_MP_WORD_BITS;
  tc_mp_word* d = numerator + n + extra;
  tc_mp_from_be(p, p_bytes, prime_length);
  tc_mp_from_be(q, q_bytes, prime_length);
  tc_mp_multiply(modulus, p, q, h);
  --p[0];
  --q[0];
  tc_mp_multiply(phi, p, q, h);
  uint32_t residue = 0;
  for (size_t i = n; i; --i)
    residue = (uint32_t)(((uint64_t)residue * ((uint64_t)1u << TC_MP_WORD_BITS) + phi[i - 1]) %
                         TC_RSA_KEYGEN_PUBLIC_EXPONENT);
  const uint32_t inverse = tc_rsa_keygen_inverse_65537(residue);
  const uint32_t multiplier = TC_RSA_KEYGEN_PUBLIC_EXPONENT - inverse;
  uint64_t carry = 0;
  for (size_t i = 0; i < n; ++i) {
    carry += (uint64_t)phi[i] * multiplier;
    numerator[i] = (tc_mp_word)carry;
    carry >>= TC_MP_WORD_BITS;
  }
  for (size_t i = 0; i < extra; ++i) {
    numerator[n + i] = (tc_mp_word)carry;
    carry >>= TC_MP_WORD_BITS;
  }
  carry = 1;
  for (size_t i = 0; i < n + extra; ++i) {
    carry += numerator[i];
    numerator[i] = (tc_mp_word)carry;
    carry >>= TC_MP_WORD_BITS;
  }
  uint32_t remainder = 0;
  for (size_t i = n + extra; i; --i) {
    uint64_t dividend = ((uint64_t)remainder << TC_MP_WORD_BITS) | numerator[i - 1];
    if (i - 1 < n)
      d[i - 1] = (tc_mp_word)(dividend / TC_RSA_KEYGEN_PUBLIC_EXPONENT);
    remainder = (uint32_t)(dividend % TC_RSA_KEYGEN_PUBLIC_EXPONENT);
  }
  *modulus_out = modulus;
  *d_out = d;
}


#define TC_RSA_KEYGEN_MARKER UINT32_C(0x524b4731)

static int tc_rsa_keygen_output_check(const TC_RSA_keygen_state* state,
                                      const TC_RSA_keygen_output* output,
                                      const TC_RSA_workspace* workspace, size_t bits)
{
  const size_t modulus_length = bits / 8, prime_length = bits / 16;
  const TC_buffer buffers[] = {output->modulus, output->exponent, output->d, output->p, output->q};
  const size_t needed[] = {modulus_length, 3, modulus_length, prime_length, prime_length};
  if (!workspace->words || (uintptr_t)workspace->words % sizeof(TC_RSA_word) ||
      workspace->capacity > SIZE_MAX / sizeof *workspace->words ||
      workspace->capacity < TC_RSA_KEYGEN_WORKSPACE_WORDS(bits))
    return 0;
  for (size_t i = 0; i < sizeof buffers / sizeof *buffers; ++i) {
    if (!buffers[i].data || buffers[i].capacity < needed[i])
      return 0;
    if (!tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, state, sizeof *state) ||
        !tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, output,
                                     sizeof *output) ||
        !tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, workspace,
                                     sizeof *workspace) ||
        !tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, workspace->words,
                                     workspace->capacity * sizeof *workspace->words))
      return 0;
    for (size_t j = 0; j < i; ++j)
      if (!tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, buffers[j].data,
                                       buffers[j].capacity))
        return 0;
  }
  return tc_internal_ranges_disjoint(state, sizeof *state, workspace, sizeof *workspace) &&
         tc_internal_ranges_disjoint(state, sizeof *state, workspace->words,
                                     workspace->capacity * sizeof *workspace->words);
}

TC_RSA_result TC_RSA_keygen_init(TC_RSA_keygen_state* state, size_t bits,
                                 const TC_RSA_keygen_output* output, TC_RSA_keygen_limits limits,
                                 const TC_RSA_workspace* workspace)
{
  if (!state || !output || !workspace)
    return TC_RSA_ARGUMENT;
  if (state->marker == TC_RSA_KEYGEN_MARKER)
    return TC_RSA_ARGUMENT;
  if (!TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, bits))
    return TC_RSA_UNSUPPORTED;
  if (!limits.candidate_attempts || !limits.random_requests)
    return TC_RSA_LIMIT;
  const size_t length = bits / 8, prime_length = length / 2;
  if (workspace->capacity < TC_RSA_KEYGEN_WORKSPACE_WORDS(bits) ||
      output->modulus.capacity < length || output->exponent.capacity < 3 ||
      output->d.capacity < length || output->p.capacity < prime_length ||
      output->q.capacity < prime_length)
    return TC_RSA_LIMIT;
  if (!tc_rsa_keygen_output_check(state, output, workspace, bits))
    return TC_RSA_ARGUMENT;
  TC_RSA_keygen_state initialized;
  memset(&initialized, 0, sizeof initialized);
  initialized.workspace = *workspace;
  initialized.output = *output;
  initialized.marker = TC_RSA_KEYGEN_MARKER;
  initialized.bits = (uint32_t)bits;
  initialized.candidate_limit = limits.candidate_attempts;
  initialized.random_limit = limits.random_requests;
  initialized.phase = TC_RSA_KEYGEN_P_NEW;
  TC_secure_zero(workspace->words, TC_RSA_KEYGEN_WORKSPACE_WORDS(bits) * sizeof *workspace->words);
  *state = initialized;
  return TC_RSA_OK;
}

void TC_RSA_keygen_clear(TC_RSA_keygen_state* state)
{
  if (!state)
    return;
  if (state->marker == TC_RSA_KEYGEN_MARKER &&
      TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, state->bits) && state->workspace.words &&
      state->workspace.capacity >= TC_RSA_KEYGEN_WORKSPACE_WORDS(state->bits))
    TC_secure_zero(state->workspace.words,
                   TC_RSA_KEYGEN_WORKSPACE_WORDS(state->bits) * sizeof *state->workspace.words);
  TC_secure_zero(state, sizeof *state);
}

static TC_RSA_result tc_rsa_keygen_stop(TC_RSA_keygen_state* state, TC_RSA_result result)
{
  TC_RSA_keygen_clear(state);
  return result;
}

static TC_RSA_result tc_rsa_keygen_random(TC_RSA_keygen_state* state, TC_random_fn random,
                                          void* context, uint8_t* output, size_t length)
{
  if (state->random_requests == state->random_limit)
    return TC_RSA_LIMIT;
  ++state->random_requests;
  return random(context, output, length) == TC_OK ? TC_RSA_OK : TC_RSA_ERROR;
}

static TC_RSA_result tc_rsa_keygen_step(TC_RSA_keygen_state* state, TC_random_fn random,
                                        void* random_context, TC_RSA_cancel_fn cancel,
                                        void* cancel_context, uint32_t* work)
{
  if (!work)
    return TC_RSA_ARGUMENT;
  uint32_t max_work = *work;
#define TC_RSA_KEYGEN_RETURN(value)                                                                \
  do {                                                                                             \
    TC_RSA_result tc_rsa_keygen_result = (value);                                                  \
    *work = max_work;                                                                              \
    return tc_rsa_keygen_result;                                                                   \
  } while (0)
  if (!state || !random || state->marker != TC_RSA_KEYGEN_MARKER ||
      !TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, state->bits))
    TC_RSA_KEYGEN_RETURN(TC_RSA_ARGUMENT);
  if (state->phase < TC_RSA_KEYGEN_P_NEW || state->phase > TC_RSA_KEYGEN_Q_ROUND)
    TC_RSA_KEYGEN_RETURN(tc_rsa_keygen_stop(state, TC_RSA_ARGUMENT));
  const size_t length = state->bits / 8, prime_length = length / 2;
  const size_t n = length / sizeof(TC_RSA_word), h = n / 2;
  const size_t required = TC_RSA_KEYGEN_WORKSPACE_WORDS(state->bits);
  if (!state->workspace.words || state->workspace.capacity < required)
    TC_RSA_KEYGEN_RETURN(tc_rsa_keygen_stop(state, TC_RSA_ARGUMENT));
  uint8_t* p = (uint8_t*)state->workspace.words;
  uint8_t* q = p + prime_length;
  TC_RSA_word* scratch = state->workspace.words + n;
  const uint32_t candidate_work = (uint32_t)prime_length + 54;
  const uint32_t setup_work = UINT32_C(24) * (uint32_t)prime_length + 3;
  const uint32_t round_work = UINT32_C(24) * (uint32_t)prime_length + 2;
  for (;;) {
    if (cancel && cancel(cancel_context))
      TC_RSA_KEYGEN_RETURN(tc_rsa_keygen_stop(state, TC_RSA_CANCELLED));
    if (state->phase == TC_RSA_KEYGEN_P_NEW || state->phase == TC_RSA_KEYGEN_Q_NEW) {
      if (state->candidates == state->candidate_limit)
        TC_RSA_KEYGEN_RETURN(tc_rsa_keygen_stop(state, TC_RSA_LIMIT));
      if (max_work < candidate_work)
        TC_RSA_KEYGEN_RETURN(TC_RSA_IN_PROGRESS);
      max_work -= candidate_work;
      ++state->candidates;
      uint8_t* candidate = state->phase == TC_RSA_KEYGEN_P_NEW ? p : q;
      TC_RSA_result status =
          tc_rsa_keygen_random(state, random, random_context, candidate, prime_length);
      if (status != TC_RSA_OK)
        TC_RSA_KEYGEN_RETURN(tc_rsa_keygen_stop(state, status));
      candidate[0] |= 0xc0u;
      candidate[prime_length - 1] |= 1u;
      if (!tc_rsa_keygen_candidate_filter(candidate, prime_length))
        continue;
      if (state->phase == TC_RSA_KEYGEN_Q_NEW &&
          !tc_rsa_keygen_far_apart(p, q, prime_length, scratch))
        continue;
      state->phase =
          state->phase == TC_RSA_KEYGEN_P_NEW ? TC_RSA_KEYGEN_P_PREPARE : TC_RSA_KEYGEN_Q_PREPARE;
    }
    if (state->phase == TC_RSA_KEYGEN_P_PREPARE || state->phase == TC_RSA_KEYGEN_Q_PREPARE) {
      if (max_work < setup_work)
        TC_RSA_KEYGEN_RETURN(TC_RSA_IN_PROGRESS);
      max_work -= setup_work;
      const uint8_t* candidate = state->phase == TC_RSA_KEYGEN_P_PREPARE ? p : q;
      tc_mp_from_be(scratch, candidate, prime_length);
      state->twos = (uint16_t)tc_mp_miller_rabin_prepare(scratch, h, scratch + 2 * h);
      state->rounds = 0;
      state->phase =
          state->phase == TC_RSA_KEYGEN_P_PREPARE ? TC_RSA_KEYGEN_P_ROUND : TC_RSA_KEYGEN_Q_ROUND;
    }
    if (state->phase == TC_RSA_KEYGEN_P_ROUND || state->phase == TC_RSA_KEYGEN_Q_ROUND) {
      if (max_work < round_work)
        TC_RSA_KEYGEN_RETURN(TC_RSA_IN_PROGRESS);
      max_work -= round_work;
      TC_RSA_word* base = scratch + h;
      TC_RSA_word* temporary = scratch + 8 * h;
      TC_RSA_result status =
          tc_rsa_keygen_random(state, random, random_context, (uint8_t*)temporary, prime_length);
      if (status != TC_RSA_OK)
        TC_RSA_KEYGEN_RETURN(tc_rsa_keygen_stop(state, status));
      const uint8_t* candidate_bytes = state->phase == TC_RSA_KEYGEN_P_ROUND ? p : q;
      if (!tc_rsa_witness_sample(base, (uint8_t*)temporary, candidate_bytes, prime_length,
                                 prime_length, scratch, scratch + 7 * h, temporary, h))
        continue;
      if (!tc_mp_miller_rabin_round(scratch, base, h, state->twos, scratch + 2 * h)) {
        state->phase =
            state->phase == TC_RSA_KEYGEN_P_ROUND ? TC_RSA_KEYGEN_P_NEW : TC_RSA_KEYGEN_Q_NEW;
        state->rounds = 0;
        TC_secure_zero(scratch, (6 * n + 2) * sizeof *scratch);
        continue;
      }
      if (++state->rounds != TC_RSA_VALIDATION_ROUNDS)
        continue;
      if (state->phase == TC_RSA_KEYGEN_P_ROUND) {
        state->phase = TC_RSA_KEYGEN_Q_NEW;
        state->rounds = 0;
        TC_secure_zero(scratch, (6 * n + 2) * sizeof *scratch);
        continue;
      }
      TC_RSA_word *modulus_words, *d_words;
      tc_rsa_keygen_derive(p, q, prime_length, scratch, &modulus_words, &d_words);
      tc_mp_to_be(state->output.modulus.data, modulus_words, length);
      state->output.exponent.data[0] = 1;
      state->output.exponent.data[1] = 0;
      state->output.exponent.data[2] = 1;
      tc_mp_to_be(state->output.d.data, d_words, length);
      memcpy(state->output.p.data, p, prime_length);
      memcpy(state->output.q.data, q, prime_length);
      TC_RSA_keygen_clear(state);
      TC_RSA_KEYGEN_RETURN(TC_RSA_OK);
    }
  }
#undef TC_RSA_KEYGEN_RETURN
}

TC_RSA_result TC_RSA_keygen_step(TC_RSA_keygen_state* state, TC_random_source random,
                                 TC_RSA_cancel_fn cancel, void* cancel_context,
                                 TC_work_budget* work)
{
  if (!work)
    return TC_RSA_ARGUMENT;
  uint32_t available = work->remaining;
  TC_RSA_result result =
      tc_rsa_keygen_step(state, random.fill, random.context, cancel, cancel_context, &available);
  work->remaining = available;
  return result;
}
#endif
