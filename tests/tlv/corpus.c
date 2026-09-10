/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tlv.h>
#include <stdio.h>
#include <stdlib.h>

/* Request: profile byte, big-endian uint32 length, input bytes. */
static void node(void* user, const TC_TLV_event* e)
{
  size_t i;
  (void)user;
  if (e->kind != TC_TLV_BEGIN) return;
  printf("N %lu %lu %u %lu ", (unsigned long)e->offset, (unsigned long)e->depth,
         (unsigned)e->header.header_length, (unsigned long)e->header.length);
  for (i = 0; i < e->header.tag_length; ++i) printf("%02x", e->header.tag[i]);
  putchar('\n');
}

int main(void)
{
  uint8_t header[5];
  const TC_TLV_limits limits = {65535,65535,8192,32};
  const size_t chunks[] = {1, 17, 257};
  for (;;) {
    size_t got = fread(header, 1, sizeof header, stdin), length, i;
    uint8_t* data;
    TC_TLV_frame frames[32];
    TC_TLV_result result;
    if (!got) return ferror(stdin) ? 1 : 0;
    if (got != sizeof header) return 1;
    length = 0;
    for (i = 1; i < 5; ++i) length = length * 256 + header[i];
    if (length > limits.max_input) return 1;
    data = (uint8_t*)malloc(length ? length : 1);
    if (!data || fread(data, 1, length, stdin) != length) { free(data); return 1; }
    if (header[0] & 128) {
      TC_TLV_header parsed;
      const TC_TLV_limits header_limits = {65535,SIZE_MAX,1,1};
      result = TC_TLV_header_read(data, length, (TC_TLV_profile)(header[0] & 127),
                                  &header_limits, &parsed);
      if (result == TC_TLV_OK)
        printf("N 0 0 %u %lu 04\n", (unsigned)parsed.header_length, (unsigned long)parsed.length);
      printf("R %d\n", (int)result);
      fflush(stdout);
      free(data);
      continue;
    }
    result = TC_TLV_walk(data, length, (TC_TLV_profile)header[0], &limits, frames, 32, node, NULL);
    for (i = 0; i < sizeof chunks / sizeof chunks[0]; ++i) {
      TC_TLV_stream stream;
      size_t p = 0;
      if (TC_TLV_stream_init(&stream, (TC_TLV_profile)header[0], &limits, frames, 32) != TC_TLV_OK)
        return 1;
      while (p < length) {
        size_t n = length - p;
        TC_TLV_result r;
        if (n > chunks[i]) n = chunks[i];
        r = TC_TLV_stream_feed(&stream, data + p, n, NULL, NULL);
        if (r < 0) break;
        p += n;
      }
      if ((TC_TLV_stream_finish(&stream) == TC_TLV_OK) != (result == TC_TLV_OK)) return 1;
    }
    printf("R %d\n", (int)result);
    fflush(stdout);
    free(data);
  }
}
