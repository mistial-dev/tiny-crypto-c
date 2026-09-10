# SPDX-License-Identifier: GPL-2.0-or-later
"""Small test programs used for both board measurements."""
import shlex
from pki_fixtures import benchmark_certificate, c_array, chuid, cvc, eac_certificate, eac_key
from sm_fixtures import session as sm_session

SKETCH = '''#include <tiny_crypto/tiny_crypto.h>
#include <string.h>
static volatile uint8_t sink;
static void consume(const uint8_t* p, size_t n) { size_t i; for (i = 0; i < n; ++i) sink ^= p[i]; }
static uint8_t key[32], buf[64], iv[16], tag[64];
#if TC_ENABLE_PIV_SM
#include "piv_sm_wire.h"
static TC_status fixture_random(void* user, uint8_t* output, size_t length) {
  (void)user; memset(output,0,length); output[length-1]=1; return TC_OK;
}
#endif
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


FEATURES += [
    ("TLV definite-length reader",
     'const uint8_t data[] = {0x30,3,2,1,42}; TC_TLV_limits limits = {64,64,8,4}; TC_TLV_reader reader; TC_TLV_element element; CHECK(TC_TLV_reader_init(&reader,data,sizeof data,TC_TLV_DER,&limits)); CHECK(TC_TLV_next(&reader,&element)); consume(element.value.data,element.value.length);',
     NO256 + " -DTC_ENABLE_TLV=1"),
    ("TLV bounded tree walk",
     'const uint8_t data[] = {0x30,3,2,1,42}; TC_TLV_limits limits = {64,64,8,4}; TC_TLV_frame frames[4]; CHECK(TC_TLV_walk(data,sizeof data,TC_TLV_DER,&limits,frames,4,NULL,NULL)); consume(data,sizeof data);',
     NO256 + " -DTC_ENABLE_TLV=1"),
    ("TLV BER incremental reader",
     'const uint8_t data[] = {0x30,0x80,2,1,42,0,0}; TC_TLV_limits limits = {64,64,8,4}; TC_TLV_frame frames[4]; TC_TLV_stream stream; CHECK(TC_TLV_stream_init(&stream,TC_TLV_BER,&limits,frames,4)); if(TC_TLV_stream_feed(&stream,data,1,NULL,NULL)!=TC_TLV_MORE) return 1; CHECK(TC_TLV_stream_feed(&stream,data+1,sizeof data-1,NULL,NULL)); CHECK(TC_TLV_stream_finish(&stream)); consume(data,sizeof data);',
     NO256 + " -DTC_ENABLE_TLV=1 -DTC_TLV_ENABLE_BER=1 -DTC_TLV_ENABLE_STREAM=1"),
    ("DER integer and OID readers",
     'const uint8_t integer[] = {2,1,42}, oid[] = {6,3,0x55,4,3}; uint32_t n; TC_bytes span; CHECK(TC_DER_uint32(integer,sizeof integer,&n)); CHECK(TC_DER_oid(oid,sizeof oid,&span)); if(n!=42) return 1; consume(span.data,span.length);',
     NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1"),
]


PKI = NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1"
FEATURES += [
    ("PIV CHUID reader", c_array(chuid()) +
     "TC_PIV_CHUID c; CHECK(TC_PIV_CHUID_read(data,sizeof data,TC_PIV_CHUID_CONTAINER,&c)); "
     "if(c.card_uuid.length!=16 || c.cardholder_uuid.length!=16) return 1; consume(c.card_uuid.data,16);",
     NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_PIV_CHUID=1"),
    ("PIV secure messaging CVC reader", c_array(cvc()) +
     "TC_PIV_CVC c; CHECK(TC_PIV_CVC_read(data,sizeof data,&c)); "
     "if(c.key_bits!=256 || c.role!=0) return 1; consume(c.signed_data.data,c.signed_data.length);",
     PKI + " -DTC_ENABLE_PIV_CVC=1"),
]
FEATURES.append(("TWIC unsigned CHUID reader", c_array(chuid(unsigned=True)) +
    "TC_PIV_CHUID c; CHECK(TC_PIV_CHUID_read_profile(data,sizeof data,TC_PIV_CHUID_CONTAINER,"
    "TC_CHUID_PROFILE_TWIC_UNSIGNED,&c)); consume(c.card_uuid.data,c.card_uuid.length);",
    NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_PIV_CHUID=1"))
for kind, inherited in (("rsa", False), ("ec", False), ("ec", True)):
    setup = c_array(eac_certificate(kind, not inherited))
    setup += "TC_EAC_CVC c; TC_TLV_limits bounds={4096,4096,128,8}; TC_TLV_frame frames[8]; "
    setup += "TC_EAC_CVC_workspace work={frames,8}; CHECK(TC_EAC_CVC_read(data,sizeof data,&bounds,&work,&c)); "
    if inherited:
        setup += c_array(eac_key(), "domain_data")
        setup += "TC_EAC_CVC_public_key domain; CHECK(TC_EAC_CVC_public_key_read(domain_data,sizeof domain_data,&bounds,&domain)); "
        setup += "CHECK(TC_EAC_CVC_check_encoding(&c,&domain,&domain)); "
    setup += "consume(c.signed_data.data,c.signed_data.length);"
    label = "inherited EC with encoding checks" if inherited else "RSA-2048" if kind == "rsa" else "explicit EC-256"
    FEATURES.append(("EAC CVC " + label, setup, PKI + " -DTC_ENABLE_EAC_CVC=1"))

for key_kind, bits in (("rsa", 2048), ("ec", 256)):
    data = benchmark_certificate(key_kind, bits)
    FEATURES.append((f"X.509 {key_kind.upper()}-{bits} certificate reader", c_array(data) +
        "TC_X509_certificate c; TC_TLV_limits bounds={1024,1024,128,8}; TC_TLV_frame frames[8]; "
        "TC_bytes oids[8]; TC_X509_workspace work={frames,8,oids,8}; "
        "CHECK(TC_X509_read(data,sizeof data,&bounds,&work,&c)); "
        f"if(c.public_key.bits!={bits}) return 1; consume(c.public_key.key.data,c.public_key.key.length);",
        PKI + " -DTC_ENABLE_X509=1"))


RP2350_FEATURES = []
for bits in (256, 384):
    for small in (1, 0):
        width = bits // 8
        body = (f"static TC_EC_workspace work; uint8_t scalar[{width}]={{0}}, point[{2*width+1}], secret[{width}]; "
                f"scalar[{width-1}]=1; CHECK(TC_EC_public_key(TC_EC_P{bits},scalar,sizeof scalar,point,sizeof point,&work)); "
                f"CHECK(TC_ECDH(TC_EC_P{bits},scalar,sizeof scalar,point,sizeof point,secret,sizeof secret,&work)); "
                "if(memcmp(secret,point+1,sizeof secret)) return 1; consume(secret,sizeof secret);")
        flags = (NO256 + f" -DTC_ENABLE_EC=1 -DTC_EC_SMALL={small}"
                 f" -DTC_EC_ENABLE_P256={int(bits == 256)} -DTC_EC_ENABLE_P384={int(bits == 384)}")
        RP2350_FEATURES.append((f"ECDH P-{bits}, {'byte' if small else 'native'} limbs", body, flags))


for bits in (256, 384):
    fixture = sm_session(bits)
    arrays = "".join(c_array(value, name) for name, value in fixture.items())
    suite = "TC_PIV_SM_CS2" if bits == 256 else "TC_PIV_SM_CS7"
    body = (arrays + "static TC_PIV_SM_workspace work; TC_PIV_SM state={0}; uint8_t host[8]={0}, output[256]; "
            "size_t written; ExamplePIVSMResult result; TC_bytes trusted={public_key,sizeof public_key}; "
            "ExamplePIVSMCommand cmd={{NULL,0},0x20,0,0x80,0}; "
            f"CHECK(example_piv_sm_begin(&state,{suite},host,fixture_random,NULL,output,sizeof output,&written,&work)); "
            "if(written!=sizeof request || memcmp(output,request,written)) return 1; "
            "TC_bytes response_bytes={response,sizeof response}, reply_bytes={reply,sizeof reply}; "
            "CHECK(example_piv_sm_finish(&state,response_bytes,0x9000,trusted,&work)); "
            f"if(memcmp(state.data.traffic.mac_key,material+{16 if bits == 256 else 32},{16 if bits == 256 else 32})) return 1; "
            "CHECK(example_piv_sm_protect(&state,&cmd,output,sizeof output,&written,&work)); "
            "if(written!=sizeof command || memcmp(output,command,written)) return 1; "
            "CHECK(example_piv_sm_unprotect(&state,reply_bytes,0x9000,output,sizeof output,&result,&work)); "
            "if(result.length!=0 || result.status!=0x9000) return 1; consume((const uint8_t*)&state,sizeof state); "
            "TC_PIV_SM_clear(&state);")
    flags = (AES + " -DTC_ENABLE_PIV_SM=1 -DTC_AES_ENABLE_DYNAMIC=1 -DTC_ENABLE_EC=1 -DTC_ENABLE_SSKDF=1"
             " -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1 -DTC_ENABLE_PIV_CVC=1"
             f" -DTC_ENABLE_SHA384={int(bits == 384)}"
             f" -DTC_PIV_SM_ENABLE_CS2={int(bits == 256)} -DTC_PIV_SM_ENABLE_CS7={int(bits == 384)}"
             f" -DTC_EC_ENABLE_P256={int(bits == 256)} -DTC_EC_ENABLE_P384={int(bits == 384)}")
    RP2350_FEATURES.append((f"PIV SM CS{2 if bits == 256 else 7} handshake and message", body, flags))


def features_for_board(board):
    return FEATURES + (RP2350_FEATURES if board == "pico2" else [])


def definitions(flags):
    """Keep the last value when a flag is defined more than once."""
    return dict(flag[2:].split("=", 1) for flag in shlex.split(flags))
