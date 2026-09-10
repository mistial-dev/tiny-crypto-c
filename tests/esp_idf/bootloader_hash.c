/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "bootloader_sha.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

static MunitResult hashes(const MunitParameter params[], void *user)
{
    static const char *answers[] = {
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    };
    unsigned algorithm;
    (void)params; (void)user;
    for (algorithm = 0; algorithm < 3; ++algorithm) {
        size_t split;
        uint8_t expected[64], digest[64];
        size_t length = tc_test_decode_hex(answers[algorithm], expected, sizeof expected);
        for (split = 0; split <= 3; ++split) {
            void *handle = algorithm == 0 ? bootloader_sha256_start() : bootloader_sha512_start(algorithm == 1);
            void *cancel = algorithm == 0 ? bootloader_sha256_start() : bootloader_sha512_start(algorithm == 1);
            munit_assert_not_null(handle);
            munit_assert_not_null(cancel);
            munit_assert_ptr_not_equal(handle, cancel);
            if (algorithm == 0) {
                bootloader_sha256_finish(cancel, NULL);
                bootloader_sha256_data(handle, "abc", split);
                bootloader_sha256_data(handle, NULL, 0);
                bootloader_sha256_data(handle, &"abc"[split], 3 - split);
                bootloader_sha256_finish(handle, digest);
            } else {
                bootloader_sha512_finish(cancel, NULL);
                bootloader_sha512_data(handle, "abc", split);
                bootloader_sha512_data(handle, NULL, 0);
                bootloader_sha512_data(handle, &"abc"[split], 3 - split);
                bootloader_sha512_finish(handle, digest);
            }
            munit_assert_memory_equal(length, digest, expected);
        }
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/hashes", hashes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
int main(int argc, char **argv)
{
    MunitSuite suite = {"/idf-image", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
    return munit_suite_main(&suite, NULL, argc, argv);
}
