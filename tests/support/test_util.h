/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_TEST_UTIL_H
#define TINY_CRYPTO_TEST_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include "munit.h"

/* Define a munit test that reads neither its parameters nor its user data.
 * The macro expands to a wrapper with the munit signature and opens the
 * definition of a parameterless body that the wrapper calls:
 *
 *   TC_TEST(test_example)
 *   {
 *     munit_assert_int(1, ==, 1);
 *     return MUNIT_OK;
 *   }
 *
 * The wrapper consumes both munit arguments in standard C, so test bodies
 * need no casts to stay clean under -Wall -Wextra and MSVC /W4. Tests that
 * read params or user_data keep the explicit munit signature. TC_TEST gives
 * the test internal linkage. TC_TEST_SHARED gives it external linkage for
 * suites that list tests defined in another file. Declare a shared test with
 * the munit signature before its TC_TEST_SHARED definition. */
#define TC_TEST_DEFINE(linkage, name)                                                              \
  static MunitResult name##_test_body(void);                                                       \
  linkage MunitResult name(const MunitParameter params[], void* user_data)                         \
  {                                                                                                \
    (void)params;                                                                                  \
    (void)user_data;                                                                               \
    return name##_test_body();                                                                     \
  }                                                                                                \
  static MunitResult name##_test_body(void)
#define TC_TEST(name) TC_TEST_DEFINE(static, name)
#define TC_TEST_SHARED(name) TC_TEST_DEFINE(extern, name)

void tc_test_fill_bytes(uint8_t* output, size_t length, uint8_t seed, uint8_t stride);
void tc_test_fill_incrementing(uint8_t* output, size_t length);
void tc_test_fill_stride3(uint8_t* output, size_t length, uint8_t seed);
/* Return 1 when every byte of memory equals value. */
int tc_test_all_value(const void* memory, size_t length, uint8_t value);
int tc_test_all_zero(const void* memory, size_t length);

#endif
