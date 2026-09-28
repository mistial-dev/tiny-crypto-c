/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Incremental RSA key generation (FIPS 186-5 appendix A.1.3). */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_keygen_internal.h"

#define TC_RSA_KEYGEN_MARKER UINT32_C(0x524b4731)

size_t TC_RSA_keygen_workspace_words(size_t bits)
{
  if (!tc_rsa_supported_modulus_size(bits / 8) || bits % 8)
    return 0;
  return TC_RSA_KEYGEN_WORKSPACE_WORDS(bits);
}

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
  if (!TC_RSA_keygen_workspace_words(bits))
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
  if (state->marker == TC_RSA_KEYGEN_MARKER && TC_RSA_keygen_workspace_words(state->bits) &&
      state->workspace.words &&
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
      !TC_RSA_keygen_workspace_words(state->bits))
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
      uint8_t* bytes = (uint8_t*)temporary;
      tc_rsa_mask_candidate_width(bytes, candidate_bytes, prime_length, prime_length);
      tc_mp_from_be(base, bytes, prime_length);
      TC_RSA_word* last = scratch + 7 * h;
      memcpy(last, scratch, prime_length);
      --last[0];
      const TC_RSA_word below_last = tc_mp_subtract(temporary, base, last, h);
      TC_RSA_word above_one = (TC_RSA_word)(base[0] & ~1u);
      for (size_t i = 1; i < h; ++i)
        above_one |= base[i];
      if (!below_last || !above_one)
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
