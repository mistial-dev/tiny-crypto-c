/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static volatile uint8_t sink;

/* Fixed public inputs keep repeated measurements comparable. */
static int measure(void)
{
  /* SHA-384 of 64 zero bytes, checked with Python hashlib. */
  static const uint8_t expected[48] = {0xc5, 0x16, 0xaa, 0x8d, 0x3b, 0x45, 0x7c, 0x63, 0x6c, 0x68,
                                       0x26, 0x93, 0x70, 0x99, 0xc0, 0xd2, 0x3a, 0x13, 0xf2, 0xc3,
                                       0x70, 0x1a, 0x38, 0x8b, 0x3c, 0x8f, 0xe4, 0xbc, 0x20, 0x73,
                                       0x28, 0x1b, 0x0c, 0x44, 0x62, 0x61, 0x03, 0x69, 0x88, 0x4c,
                                       0x4a, 0xba, 0xba, 0x8e, 0x97, 0xb6, 0xde, 0xbe};
  uint8_t data[64] = {0}, digest[TC_SHA384_DIGESTLEN];
  const TC_bytes message = {data, sizeof data};
  int64_t start = esp_timer_get_time();
  for (unsigned i = 0; i < 100; ++i) {
    if (TC_SHA384_digest(message, digest) != TC_OK)
      return 1;
    sink ^= digest[0];
  }
  int64_t elapsed = esp_timer_get_time() - start;
  if (memcmp(digest, expected, sizeof expected) != 0)
    return 1;
  printf("SHA-384 64-byte input: %" PRId64 " us / 100 operations\n", elapsed);
#if TC_ENABLE_EC
  static TC_EC_workspace workspace;
  uint8_t scalar[48] = {0}, point[97];
  for (unsigned width = 32; width <= 48; width += 16) {
    if ((width == 32 && !TC_EC_ENABLE_P256) || (width == 48 && !TC_EC_ENABLE_P384))
      continue;
    memset(scalar, 0, sizeof scalar);
    scalar[width - 1] = 1;
    start = esp_timer_get_time();
    const TC_EC_curve curve = width == 32 ? TC_EC_P256 : TC_EC_P384;
    TC_work_budget work = {TC_EC_operation_work(curve, TC_EC_OPERATION_PUBLIC_KEY)};
    if (TC_EC_public_key(curve, (TC_bytes){scalar, width}, (TC_buffer){point, 1 + 2 * width},
                         &workspace, &work) != TC_EC_OK)
      return 1;
    printf("P-%u public key: %" PRId64 " us\n", width * 8, esp_timer_get_time() - start);
    sink ^= point[1];
    vTaskDelay(1);
  }
#endif
  return 0;
}

void app_main(void)
{
  printf("tiny-crypto-c %s, resource profile %d\n", TC_APPLICATION_TARGET, TC_RESOURCE_PROFILE);
  if (measure()) {
    puts("Benchmark failed");
    abort();
  }
  printf("Internal heap free: %zu bytes; minimum: %zu bytes; task stack unused: %u bytes\n",
         heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
         heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
         (unsigned)uxTaskGetStackHighWaterMark(NULL));
}
