# SPDX-License-Identifier: GPL-2.0-or-later
"""Small test programs used for both board measurements."""
import shlex

SKETCH = '''#include <tiny_crypto/tiny_crypto.h>
#include <string.h>
static volatile uint8_t sink;
static void consume(const uint8_t* p, size_t n) { size_t i; for (i = 0; i < n; ++i) sink ^= p[i]; }
static uint8_t key[32], buf[64], iv[16], tag[64];
#define CHECK(call) do { if ((call) != TC_OK) return 1; } while (0)
static int feature(void)
{
  memset(key, 0x11, sizeof key); memset(buf, 0x22, sizeof buf); memset(iv, 0x33, sizeof iv);
  %s
  return 0;
}
extern "C" void setup(void) { sink = (uint8_t)feature(); }
extern "C" void loop(void) { }
'''

# Disable the default ciphers; each case enables what it needs.
OFF = ("-DTC_ENABLE_AES=0 -DTC_ENABLE_DES=0 -DTC_AES_ENABLE_CTR=0 "
       "-DTC_DES_ENABLE_CTR=0 -DTC_DES_ENABLE_TDES=0")
AES = OFF + " -DTC_ENABLE_AES=1"
DES = OFF + " -DTC_ENABLE_DES=1"
NO256 = OFF + " -DTC_ENABLE_SHA256=0"

FEATURES = [
    ("Empty firmware", "", OFF),
    ("AES-128 CTR",
     "struct TC_AES_ctx c; CHECK(TC_AES_init_ctx_iv(&c, key, iv)); CHECK(TC_AES_CTR_crypt(&c, buf, 64)); consume(buf, 64);",
     AES + " -DTC_AES_ENABLE_CTR=1"),
    ("AES-128 CBC",
     "struct TC_AES_ctx c; CHECK(TC_AES_init_ctx_iv(&c, key, iv)); CHECK(TC_AES_CBC_encrypt(&c, buf, 64)); CHECK(TC_AES_CBC_decrypt(&c, buf, 64)); consume(buf, 64);",
     AES + " -DTC_AES_ENABLE_CBC=1"),
    ("AES-128 GCM, bitwise GHASH",
     "CHECK(TC_AES_GCM_encrypt(key, iv, 12, buf, 8, buf, 32, buf, tag, 16)); consume(buf, 32); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_GCM=1 -DTC_AES_GCM_GHASH_MODE=1"),
    ("AES-128 CCM",
     "CHECK(TC_AES_CCM_encrypt(key, iv, 12, buf, 8, buf, 32, buf, tag, 16)); consume(buf, 32); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_CCM=1"),
    ("AES-128 EAX",
     "CHECK(TC_AES_EAX_encrypt(key, iv, 16, buf, 8, buf, 32, buf, tag, 16)); consume(buf, 32); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_EAX=1"),
    ("AES-128 CMAC",
     "CHECK(TC_AES_CMAC(key, buf, 40, tag, 16)); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_CMAC=1"),
    ("DES CTR",
     "struct TC_DES_ctx c; CHECK(TC_DES_init_ctx_iv(&c, key, iv)); CHECK(TC_DES_CTR_crypt(&c, buf, 64)); consume(buf, 64);",
     DES + " -DTC_DES_ENABLE_CTR=1"),
    ("3DES CTR",
     "struct TC_DES3_ctx c; CHECK(TC_DES3_init_ctx_iv(&c, key, 24, iv)); CHECK(TC_DES3_CTR_crypt(&c, buf, 64)); consume(buf, 64);",
     DES + " -DTC_DES_ENABLE_CTR=1 -DTC_DES_ENABLE_TDES=1"),
    ("TDEA CMAC",
     "CHECK(TC_DES_CMAC(key, 24, buf, 40, tag, 8)); consume(tag, 8);",
     DES + " -DTC_DES_ENABLE_CMAC=1"),
    ("SHA-1", "CHECK(TC_SHA1_digest(buf, 64, tag)); consume(tag, 20);", NO256 + " -DTC_ENABLE_SHA1=1"),
    ("SHA-224", "CHECK(TC_SHA224_digest(buf, 64, tag)); consume(tag, 28);", NO256 + " -DTC_ENABLE_SHA224=1"),
    ("SHA-256", "CHECK(TC_SHA256_digest(buf, 64, tag)); consume(tag, 32);", OFF),
    ("SHA-384", "uint8_t d[48]; CHECK(TC_SHA384_digest(buf, 64, d)); consume(d, 48);", NO256 + " -DTC_ENABLE_SHA384=1"),
    ("SHA-512", "uint8_t d[64]; CHECK(TC_SHA512_digest(buf, 64, d)); consume(d, 64);", NO256 + " -DTC_ENABLE_SHA512=1"),
    ("HMAC-SHA-1",
     "CHECK(TC_HMAC_SHA1_digest(key, 32, buf, 64, tag, 16)); consume(tag, 16);",
     NO256 + " -DTC_ENABLE_SHA1=1 -DTC_ENABLE_HMAC=1"),
    ("HMAC-SHA-256",
     "CHECK(TC_HMAC_SHA256_digest(key, 32, buf, 64, tag, 16)); consume(tag, 16);",
     OFF + " -DTC_ENABLE_HMAC=1"),
    ("HMAC-SHA-512",
     "uint8_t d[64]; CHECK(TC_HMAC_SHA512_digest(key, 32, buf, 64, d, 64)); consume(d, 64);",
     NO256 + " -DTC_ENABLE_SHA512=1 -DTC_ENABLE_HMAC=1"),
    ("KBKDF counter mode, HMAC-SHA-1",
     "struct TC_KBKDF_params p = { 32, 0, 0 }; CHECK(TC_KBKDF_HMAC_SHA1_counter(key, 32, &p, NULL, 0, buf, 34, tag, 32)); consume(tag, 32);",
     NO256 + " -DTC_ENABLE_SHA1=1 -DTC_ENABLE_HMAC=1 -DTC_ENABLE_KDF=1"),
    ("KBKDF counter mode, HMAC-SHA-256",
     "struct TC_KBKDF_params p = { 32, 0, 0 }; CHECK(TC_KBKDF_HMAC_SHA256_counter(key, 32, &p, NULL, 0, buf, 34, tag, 32)); consume(tag, 32);",
     OFF + " -DTC_ENABLE_HMAC=1 -DTC_ENABLE_KDF=1"),
    ("KBKDF feedback mode, HMAC-SHA-256",
     "struct TC_KBKDF_params p = { 32, 1, 1 }; CHECK(TC_KBKDF_HMAC_SHA256_feedback(key, 32, &p, iv, 16, buf, 34, tag, 32)); consume(tag, 32);",
     OFF + " -DTC_ENABLE_HMAC=1 -DTC_ENABLE_KDF=1"),
    ("KBKDF counter mode, AES-128 CMAC",
     "struct TC_KBKDF_params p = { 32, 0, 0 }; CHECK(TC_KBKDF_AES_CMAC_counter(key, 16, &p, NULL, 0, buf, 34, tag, 32)); consume(tag, 32);",
     AES + " -DTC_AES_ENABLE_CMAC=1 -DTC_ENABLE_KDF=1"),
]


FEATURES += [
    ("KMAC256, 32-byte output",
     "CHECK(TC_KMAC256_digest(key, 32, buf, 64, NULL, 0, tag, 32)); consume(tag, 32);",
     NO256 + " -DTC_ENABLE_KMAC256=1"),
    ("KMAC256, 48-byte output",
     "CHECK(TC_KMAC256_digest(key, 32, buf, 64, NULL, 0, tag, 48)); consume(tag, 48);",
     NO256 + " -DTC_ENABLE_KMAC256=1"),
    ("PIV Auto KMAC256 derivation",
     'uint8_t session[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xA9,0xBA,0xCB,0xDC,0xED,0xFE,0x0F,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00}; uint8_t message[] = {0x4F,0x53,0x44,0x50,0x2D,0x50,0x49,0x56,0x2D,0x41,0x55,0x54,0x4F,0x01,0x07,0x00,0x00,0x00,0x2A,0x00,0x00,0x00,0xD1,0x38,0x10,0xD8,0x28,0xAB,0x6C,0x10,0xC3,0x39,0xE5,0xA1,0x68,0x5A,0x08,0xC9,0x2A,0xDE,0x0A,0x61,0x84,0xE7,0x39,0xC3,0xE7,0x09,0xD4,0x9C,0x7E,0xFD,0xD0,0x43,0x2E,0xAC,0xEA,0x26,0x8A,0xE9,0x05,0x27,0x4C,0x9E,0x07,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xA9,0xBA,0xCB,0xDC,0xED,0xFE,0x0F}; uint8_t kdk[32]; CHECK(TC_KMAC256_digest(session, sizeof session, NULL, 0, (const uint8_t*)"OSDP-PIV-AUTO-KDK-v1", 20, kdk, 32)); CHECK(TC_KMAC256_digest(kdk, 32, message, sizeof message, (const uint8_t*)"OSDP-PIV-AUTO-CHALLENGE-v1", 26, tag, 32)); consume(tag, 32); TC_secure_zero(kdk, sizeof kdk);',
     NO256 + " -DTC_ENABLE_KMAC256=1"),
]


def definitions(flags):
    """Keep the last value when a flag is defined more than once."""
    return dict(flag[2:].split("=", 1) for flag in shlex.split(flags))
