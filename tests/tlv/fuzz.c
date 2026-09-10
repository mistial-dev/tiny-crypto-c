/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tlv.h>
#include <tiny_crypto/der.h>
#include <stdlib.h>
#include <string.h>

struct trace { uint32_t hash; size_t opens, closes; };
static void trace(void* user, const TC_TLV_event* e)
{
  struct trace* t = (struct trace*)user;
  size_t i;
  if (e->kind == TC_TLV_BEGIN) ++t->opens;
  if (e->kind == TC_TLV_CLOSE) ++t->closes;
  for (i = 0; i < e->bytes.length; ++i) t->hash = t->hash * 33 + e->bytes.data[i];
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t length)
{
  TC_TLV_limits limits = {32768, 16384, 2048, 16};
  TC_TLV_frame frames[16];
  TC_TLV_element e, saved;
  TC_bytes span;
  int sign;
  unsigned unused;
  uint32_t integer;
  TC_DER_algorithm algorithm;
  TC_DER_signature_pair signature;
  int profile;
  if (length > limits.max_input) return 0;
  for (profile = TC_TLV_DER; profile <= TC_TLV_ISO7816_PAD_ZERO_FF; ++profile) {
    TC_TLV_result r;
    struct trace a = {0,0,0}, b = {0,0,0};
    TC_TLV_stream stream;
    size_t p = 0;
    memset(&e, 0xa5, sizeof e); saved = e;
    r = TC_TLV_read(data, length, (TC_TLV_profile)profile, &limits, &e);
    if (r == TC_TLV_OK) {
      if (e.encoded.data != data || e.encoded.length > length ||
          e.value.data != data + e.header.header_length ||
          e.value.length != e.encoded.length - e.header.header_length) abort();
    } else if (memcmp(&e, &saved, sizeof e)) abort();
    memset(&e,0xa5,sizeof e); saved = e;
    r = TC_TLV_read_tree(data,length,(TC_TLV_profile)profile,&limits,frames,
        sizeof frames / sizeof *frames,&e);
    if (r == TC_TLV_OK) {
      if (e.encoded.data != data || e.encoded.length > length || !e.encoded.length ||
          e.value.data != data + e.header.header_length ||
          e.value.length != e.encoded.length - e.header.header_length -
            (e.header.indefinite ? 2u : 0u)) abort();
      if (TC_TLV_walk(e.encoded.data,e.encoded.length,(TC_TLV_profile)profile,&limits,
          frames,sizeof frames / sizeof *frames,NULL,NULL) != TC_TLV_OK) abort();
    } else if (memcmp(&e,&saved,sizeof e)) abort();
    r = TC_TLV_walk(data, length, (TC_TLV_profile)profile, &limits, frames, 16, trace, &a);
    if (TC_TLV_stream_init(&stream, (TC_TLV_profile)profile, &limits, frames, 16) != TC_TLV_OK) abort();
    while (p < length) {
      size_t n = (data[p] % 17) + 1;
      TC_TLV_result step;
      if (n > length - p) n = length - p;
      step = TC_TLV_stream_feed(&stream, data + p, n, trace, &b);
      if (step < 0) break;
      p += n;
    }
    if ((TC_TLV_stream_finish(&stream) == TC_TLV_OK) != (r == TC_TLV_OK)) abort();
    if (r == TC_TLV_OK && (a.hash != b.hash || a.opens != b.opens ||
                          a.closes != b.closes || a.opens != a.closes)) abort();
  }
  (void)TC_DER_integer(data, length, &span, &sign);
  (void)TC_DER_uint32(data, length, &integer);
  (void)TC_DER_bit_string(data, length, &span, &unused);
  (void)TC_DER_oid(data, length, &span);
  (void)TC_DER_boolean(data, length, &sign);
  (void)TC_DER_null(data, length);
  (void)TC_DER_algorithm_identifier(data, length, &algorithm);
  (void)TC_DER_ecdsa_signature(data, length, &signature);
  return 0;
}
