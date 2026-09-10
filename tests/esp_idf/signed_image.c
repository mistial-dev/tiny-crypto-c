/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "secure_boot_signature_priv.h"
#include <tiny_crypto/hash.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>
#include "image_fixture.h"

static const char *image_path;
#if defined(TC_TEST_IDF_ECDSA)
#define verify_block verify_ecdsa_signature_block
#define block_signature(block) ((block).ecdsa.signature)
#else
#define verify_block verify_rsa_signature_block
#define block_signature(block) ((block).signature)
#endif

static MunitResult image_signature(const MunitParameter params[], void *user)
{
    ets_secure_boot_signature_t signatures;
    uint8_t digest[32];
    (void)params; (void)user;
    if (!image_path) return MUNIT_SKIP;
    read_image_fixture(image_path, &signatures, digest);
    munit_assert_uint8(signatures.block[0].magic_byte, ==, 0xe7);
    munit_assert_memory_equal(32,digest,signatures.block[0].image_digest);
    munit_assert_int(verify_block(&signatures,digest,&signatures.block[0]), ==, ESP_OK);
    digest[0] ^= 1;
    munit_assert_int(verify_block(&signatures,digest,&signatures.block[0]), ==, ESP_ERR_IMAGE_INVALID);
    digest[0] ^= 1;
    block_signature(signatures.block[0])[0] ^= 1;
    munit_assert_int(verify_block(&signatures,digest,&signatures.block[0]), ==, ESP_ERR_IMAGE_INVALID);
    block_signature(signatures.block[0])[0] ^= 1;
#if defined(TC_TEST_IDF_ECDSA)
    signatures.block[0].ecdsa.key.curve_id = 0xff;
    munit_assert_int(verify_block(&signatures,digest,&signatures.block[0]), ==, ESP_ERR_INVALID_ARG);
#else
    signatures.block[0].key.e = 2;
    munit_assert_int(verify_block(&signatures,digest,&signatures.block[0]), ==, ESP_ERR_IMAGE_INVALID);
#endif
    munit_assert_int(verify_block(NULL,digest,&signatures.block[0]), ==, ESP_ERR_INVALID_ARG);
    return MUNIT_OK;
}
static MunitTest tests[] = {
    {"/image",image_signature,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
int main(int argc, char **argv)
{
    MunitSuite suite = {"/idf-image",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
    if (argc == 3 && strcmp(argv[1],"--image") == 0) { image_path = argv[2]; argc = 1; }
    return munit_suite_main(&suite,NULL,argc,argv);
}
