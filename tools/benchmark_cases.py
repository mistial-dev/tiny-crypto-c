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
#if TC_ENABLE_PIV_SM_APDU
static TC_status fixture_random(void* user, uint8_t* output, size_t length) {
  (void)user; memset(output,0,length); output[length-1]=1; return TC_OK;
}
/* A card answering SELECT, key establishment and the protected VERIFY query. */
typedef struct { TC_bytes select, key, reply; } fixture_card;
static TC_status fixture_transmit(void* context, TC_bytes command, TC_buffer response,
                                  size_t* length) {
  const fixture_card* card = (const fixture_card*)context;
  const TC_bytes answer = command.data[1] == 0xa4 ? card->select
                          : command.data[1] == 0x87 ? card->key : card->reply;
  if (answer.length + 2 > response.capacity) return TC_ERROR;
  memcpy(response.data, answer.data, answer.length);
  response.data[answer.length] = 0x90; response.data[answer.length + 1] = 0;
  *length = answer.length + 2; return TC_OK;
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
     "struct TC_AES_ctx c; CHECK(TC_AES_init(&c, (TC_bytes){key, 16})); CHECK(TC_AES_set_iv(&c, (TC_bytes){iv, 16})); CHECK(TC_AES_CTR_crypt(&c, (TC_buffer){buf, 64})); consume(buf, 64);",
     AES + " -DTC_AES_ENABLE_CTR=1"),
    ("AES-128 CBC",
     "struct TC_AES_ctx c; CHECK(TC_AES_init(&c, (TC_bytes){key, 16})); CHECK(TC_AES_set_iv(&c, (TC_bytes){iv, 16})); CHECK(TC_AES_CBC_encrypt(&c, (TC_buffer){buf, 64})); CHECK(TC_AES_CBC_decrypt(&c, (TC_buffer){buf, 64})); consume(buf, 64);",
     AES + " -DTC_AES_ENABLE_CBC=1"),
    ("AES-128 GCM, bitwise GHASH",
     "CHECK(TC_AES_GCM_encrypt((TC_bytes){key, 16}, (TC_bytes){iv, 12}, (TC_bytes){buf, 8}, (TC_bytes){buf, 32}, (TC_buffer){buf, 32}, (TC_buffer){tag, 16})); consume(buf, 32); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_GCM=1 -DTC_AES_GCM_GHASH_MODE=1"),
    ("AES-128 CCM",
     "CHECK(TC_AES_CCM_encrypt((TC_bytes){key, 16}, (TC_bytes){iv, 12}, (TC_bytes){buf, 8}, (TC_bytes){buf, 32}, (TC_buffer){buf, 32}, (TC_buffer){tag, 16})); consume(buf, 32); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_CCM=1"),
    ("AES-128 EAX",
     "CHECK(TC_AES_EAX_encrypt((TC_bytes){key, 16}, (TC_bytes){iv, 16}, (TC_bytes){buf, 8}, (TC_bytes){buf, 32}, (TC_buffer){buf, 32}, (TC_buffer){tag, 16})); consume(buf, 32); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_EAX=1"),
    ("AES-128 CMAC",
     "CHECK(TC_AES_CMAC((TC_bytes){key, 16}, (TC_bytes){buf, 40}, (TC_buffer){tag, 16})); consume(tag, 16);",
     AES + " -DTC_AES_ENABLE_CMAC=1"),
    ("DES CTR",
     "struct TC_DES_ctx c; CHECK(TC_DES_init(&c, (TC_bytes){key, 8})); CHECK(TC_DES_set_iv(&c, (TC_bytes){iv, 8})); CHECK(TC_DES_CTR_crypt(&c, (TC_buffer){buf, 64})); consume(buf, 64);",
     DES + " -DTC_DES_ENABLE_CTR=1"),
    ("TDEA CTR",
     "struct TC_DES_ctx c; CHECK(TC_DES_init(&c, (TC_bytes){key, 24})); CHECK(TC_DES_set_iv(&c, (TC_bytes){iv, 8})); CHECK(TC_DES_CTR_crypt(&c, (TC_buffer){buf, 64})); consume(buf, 64);",
     DES + " -DTC_DES_ENABLE_CTR=1 -DTC_DES_ENABLE_TDES=1"),
    ("TDEA CMAC",
     "CHECK(TC_DES_CMAC((TC_bytes){key, 24}, (TC_bytes){buf, 40}, (TC_buffer){tag, 8})); consume(tag, 8);",
     DES + " -DTC_DES_ENABLE_CMAC=1"),
    ("SHA-1", "CHECK(TC_SHA1_digest((TC_bytes){buf, 64}, tag)); consume(tag, 20);", NO256 + " -DTC_ENABLE_SHA1=1"),
    ("SHA-224", "CHECK(TC_SHA224_digest((TC_bytes){buf, 64}, tag)); consume(tag, 28);", NO256 + " -DTC_ENABLE_SHA224=1"),
    ("SHA-256", "CHECK(TC_SHA256_digest((TC_bytes){buf, 64}, tag)); consume(tag, 32);", OFF),
    ("SHA-384", "uint8_t d[48]; CHECK(TC_SHA384_digest((TC_bytes){buf, 64}, d)); consume(d, 48);", NO256 + " -DTC_ENABLE_SHA384=1"),
    ("SHA-512", "uint8_t d[64]; CHECK(TC_SHA512_digest((TC_bytes){buf, 64}, d)); consume(d, 64);", NO256 + " -DTC_ENABLE_SHA512=1"),
    ("HMAC-SHA-1",
     "CHECK(TC_HMAC_SHA1_digest((TC_bytes){key, 32}, (TC_bytes){buf, 64}, (TC_buffer){tag, 16})); consume(tag, 16);",
     NO256 + " -DTC_ENABLE_SHA1=1 -DTC_ENABLE_HMAC=1"),
    ("HMAC-SHA-256",
     "CHECK(TC_HMAC_SHA256_digest((TC_bytes){key, 32}, (TC_bytes){buf, 64}, (TC_buffer){tag, 16})); consume(tag, 16);",
     OFF + " -DTC_ENABLE_HMAC=1"),
    ("HMAC-SHA-512",
     "uint8_t d[64]; CHECK(TC_HMAC_SHA512_digest((TC_bytes){key, 32}, (TC_bytes){buf, 64}, (TC_buffer){d, 64})); consume(d, 64);",
     NO256 + " -DTC_ENABLE_SHA512=1 -DTC_ENABLE_HMAC=1"),
    ("KBKDF counter mode, HMAC-SHA-1",
     "struct TC_KBKDF_params p = { 32, 0, 0 }; CHECK(TC_KBKDF_HMAC_SHA1_counter((TC_bytes){key, 32}, &p, (TC_bytes){NULL, 0}, (TC_bytes){buf, 34}, (TC_buffer){tag, 32})); consume(tag, 32);",
     NO256 + " -DTC_ENABLE_SHA1=1 -DTC_ENABLE_HMAC=1 -DTC_ENABLE_KDF=1"),
    ("KBKDF counter mode, HMAC-SHA-256",
     "struct TC_KBKDF_params p = { 32, 0, 0 }; CHECK(TC_KBKDF_HMAC_SHA256_counter((TC_bytes){key, 32}, &p, (TC_bytes){NULL, 0}, (TC_bytes){buf, 34}, (TC_buffer){tag, 32})); consume(tag, 32);",
     OFF + " -DTC_ENABLE_HMAC=1 -DTC_ENABLE_KDF=1"),
    ("KBKDF feedback mode, HMAC-SHA-256",
     "struct TC_KBKDF_params p = { 32, 1, 1 }; CHECK(TC_KBKDF_HMAC_SHA256_feedback((TC_bytes){key, 32}, &p, (TC_bytes){iv, 16}, (TC_bytes){buf, 34}, (TC_buffer){tag, 32})); consume(tag, 32);",
     OFF + " -DTC_ENABLE_HMAC=1 -DTC_ENABLE_KDF=1"),
    ("KBKDF counter mode, AES-128 CMAC",
     "struct TC_KBKDF_params p = { 32, 0, 0 }; CHECK(TC_KBKDF_AES_CMAC_counter((TC_bytes){key, 16}, &p, (TC_bytes){NULL, 0}, (TC_bytes){buf, 34}, (TC_buffer){tag, 32})); consume(tag, 32);",
     AES + " -DTC_AES_ENABLE_CMAC=1 -DTC_ENABLE_KDF=1"),
]


FEATURES += [
    ("KMAC256, 32-byte output",
     "CHECK(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){buf, 64}, (TC_bytes){NULL, 0}, (TC_buffer){tag, 32})); consume(tag, 32);",
     NO256 + " -DTC_ENABLE_KMAC256=1"),
    ("KMAC256, 48-byte output",
     "CHECK(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){buf, 64}, (TC_bytes){NULL, 0}, (TC_buffer){tag, 48})); consume(tag, 48);",
     NO256 + " -DTC_ENABLE_KMAC256=1"),
    ("PIV Auto KMAC256 derivation",
     'uint8_t session[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xA9,0xBA,0xCB,0xDC,0xED,0xFE,0x0F,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00}; uint8_t message[] = {0x4F,0x53,0x44,0x50,0x2D,0x50,0x49,0x56,0x2D,0x41,0x55,0x54,0x4F,0x01,0x07,0x00,0x00,0x00,0x2A,0x00,0x00,0x00,0xD1,0x38,0x10,0xD8,0x28,0xAB,0x6C,0x10,0xC3,0x39,0xE5,0xA1,0x68,0x5A,0x08,0xC9,0x2A,0xDE,0x0A,0x61,0x84,0xE7,0x39,0xC3,0xE7,0x09,0xD4,0x9C,0x7E,0xFD,0xD0,0x43,0x2E,0xAC,0xEA,0x26,0x8A,0xE9,0x05,0x27,0x4C,0x9E,0x07,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xA9,0xBA,0xCB,0xDC,0xED,0xFE,0x0F}; uint8_t kdk[32]; CHECK(TC_KMAC256_digest((TC_bytes){session, sizeof session}, (TC_bytes){NULL, 0}, (TC_bytes){(const uint8_t*)"OSDP-PIV-AUTO-KDK-v1", 20}, (TC_buffer){kdk, 32})); CHECK(TC_KMAC256_digest((TC_bytes){kdk, 32}, (TC_bytes){message, sizeof message}, (TC_bytes){(const uint8_t*)"OSDP-PIV-AUTO-CHALLENGE-v1", 26}, (TC_buffer){tag, 32})); consume(tag, 32); TC_secure_zero(kdk, sizeof kdk);',
     NO256 + " -DTC_ENABLE_KMAC256=1"),
]


FEATURES += [
    ("TLV definite-length reader",
     'const uint8_t data[] = {0x30,3,2,1,42}; TC_TLV_limits limits = {64,64,8,4}; TC_TLV_reader reader; TC_TLV_element element; CHECK(TC_TLV_reader_init(&reader,(TC_bytes){data,sizeof data},TC_TLV_DER,&limits)); CHECK(TC_TLV_next(&reader,&element)); consume(element.value.data,element.value.length);',
     NO256 + " -DTC_ENABLE_TLV=1"),
    ("TLV bounded tree walk",
     'const uint8_t data[] = {0x30,3,2,1,42}; TC_TLV_limits limits = {64,64,8,4}; TC_TLV_frame frames[4]; CHECK(TC_TLV_walk((TC_bytes){data,sizeof data},TC_TLV_DER,&limits,(TC_TLV_frames){frames,4},NULL,NULL)); consume(data,sizeof data);',
     NO256 + " -DTC_ENABLE_TLV=1"),
    ("TLV BER incremental reader",
     'const uint8_t data[] = {0x30,0x80,2,1,42,0,0}; TC_TLV_limits limits = {64,64,8,4}; TC_TLV_frame frames[4]; TC_TLV_stream stream; CHECK(TC_TLV_stream_init(&stream,TC_TLV_BER,&limits,(TC_TLV_frames){frames,4})); if(TC_TLV_stream_feed(&stream,(TC_bytes){data,1},NULL,NULL)!=TC_TLV_MORE) return 1; CHECK(TC_TLV_stream_feed(&stream,(TC_bytes){data+1,sizeof data-1},NULL,NULL)); CHECK(TC_TLV_stream_finish(&stream)); consume(data,sizeof data);',
     NO256 + " -DTC_ENABLE_TLV=1 -DTC_TLV_ENABLE_BER=1 -DTC_TLV_ENABLE_STREAM=1"),
    ("DER integer and OID readers",
     'const uint8_t integer[] = {2,1,42}, oid[] = {6,3,0x55,4,3}; uint32_t n; TC_bytes span; CHECK(TC_DER_uint32((TC_bytes){integer,sizeof integer},&n)); CHECK(TC_DER_oid((TC_bytes){oid,sizeof oid},&span)); if(n!=42) return 1; consume(span.data,span.length);',
     NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1"),
]


PKI = NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1"
FEATURES += [
    ("PIV CHUID reader", c_array(chuid()) +
     "TC_PIV_CHUID c; CHECK(TC_PIV_CHUID_read((TC_bytes){data,sizeof data},TC_PIV_CHUID_CONTAINER,TC_CHUID_PROFILE_PIV,&c)); "
     "if(c.card_uuid.length!=16 || c.cardholder_uuid.length!=16) return 1; consume(c.card_uuid.data,16);",
     NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_PIV_CHUID=1"),
    ("PIV secure messaging CVC reader", c_array(cvc()) +
     "TC_PIV_CVC c; CHECK(TC_PIV_CVC_read((TC_bytes){data,sizeof data},&c)); "
     "if(c.key_bits!=256 || c.role!=0) return 1; consume(c.signed_data.data,c.signed_data.length);",
     PKI + " -DTC_ENABLE_PIV_CVC=1"),
]
FEATURES.append(("TWIC unsigned CHUID reader", c_array(chuid(unsigned=True)) +
    "TC_PIV_CHUID c; CHECK(TC_PIV_CHUID_read((TC_bytes){data,sizeof data},"
    "TC_PIV_CHUID_CONTAINER,TC_CHUID_PROFILE_TWIC_UNSIGNED,&c)); consume(c.card_uuid.data,c.card_uuid.length);",
    NO256 + " -DTC_ENABLE_TLV=1 -DTC_ENABLE_PIV_CHUID=1"))
for kind, inherited in (("rsa", False), ("ec", False), ("ec", True)):
    setup = c_array(eac_certificate(kind, not inherited))
    setup += "TC_EAC_CVC c; TC_TLV_limits bounds={4096,4096,128,8}; TC_TLV_frame frames[8]; "
    setup += "TC_EAC_CVC_workspace work={{frames,8}}; CHECK(TC_EAC_CVC_read((TC_bytes){data,sizeof data},&bounds,&work,&c)); "
    if inherited:
        setup += c_array(eac_key(), "domain_data")
        setup += "TC_EAC_CVC_public_key domain; CHECK(TC_EAC_CVC_public_key_read((TC_bytes){domain_data,sizeof domain_data},&bounds,&domain)); "
        setup += "CHECK(TC_EAC_CVC_check_encoding(&c,&domain,&domain)); "
    setup += "consume(c.signed_data.data,c.signed_data.length);"
    label = "inherited EC with encoding checks" if inherited else "RSA-2048" if kind == "rsa" else "explicit EC-256"
    FEATURES.append(("EAC CVC " + label, setup, PKI + " -DTC_ENABLE_EAC_CVC=1"))

for key_kind, bits in (("rsa", 2048), ("ec", 256)):
    data = benchmark_certificate(key_kind, bits)
    FEATURES.append((f"X.509 {key_kind.upper()}-{bits} certificate reader", c_array(data) +
        "TC_X509_certificate c; TC_TLV_limits bounds={1024,1024,128,8}; TC_TLV_frame frames[8]; "
        "TC_bytes oids[8]; TC_X509_workspace work={{frames,8},oids,8}; "
        "CHECK(TC_X509_read((TC_bytes){data,sizeof data},&bounds,&work,&c)); "
        f"if(c.public_key.bits!={bits}) return 1; consume(c.public_key.key.data,c.public_key.key.length);",
        PKI + " -DTC_ENABLE_X509=1"))


RP2350_FEATURES = []
for bits in (256, 384):
    for small in (1, 0):
        width = bits // 8
        body = (f"static TC_EC_workspace work; uint8_t scalar[{width}]={{0}}, point[{2*width+1}], secret[{width}]; "
                f"scalar[{width-1}]=1; TC_work_budget budget={{UINT32_MAX}}; "
                f"CHECK(TC_EC_public_key(TC_EC_P{bits},TC_APPROVED_ONLY,(TC_bytes){{scalar,sizeof scalar}},(TC_buffer){{point,sizeof point}},&work,&budget)); "
                f"CHECK(TC_ECDH(TC_EC_P{bits},TC_APPROVED_ONLY,(TC_bytes){{scalar,sizeof scalar}},(TC_bytes){{point,sizeof point}},(TC_buffer){{secret,sizeof secret}},&work,&budget)); "
                "if(memcmp(secret,point+1,sizeof secret)) return 1; consume(secret,sizeof secret);")
        flags = (NO256 + f" -DTC_ENABLE_EC=1 -DTC_EC_SMALL={small}"
                 f" -DTC_EC_ENABLE_P256={int(bits == 256)} -DTC_EC_ENABLE_P384={int(bits == 384)}")
        RP2350_FEATURES.append((f"ECDH P-{bits}, {'byte' if small else 'native'} limbs", body, flags))


# SD 33 card 2 application property template with the suite byte at index 40.
SM_APT = bytes.fromhex("612a4f0ba00000030800001000010079074f05a000000308500a49442d4f6e6520504956"
                       "ac068001270601007f6608020203f802027fff")

for bits in (256, 384):
    fixture = sm_session(bits)
    arrays = "".join(c_array(value, name) for name, value in fixture.items())
    suite = "TC_PIV_SM_CS2" if bits == 256 else "TC_PIV_SM_CS7"
    apt = bytearray(SM_APT)
    apt[40] = 0x27 if bits == 256 else 0x2e
    key_bytes = 16 if bits == 256 else 32
    body = (arrays + c_array(bytes(apt), "apt") +
            "static uint8_t scratch[261], sm_scratch[128], answer[400]; static TC_PIV_SM state; "
            "static TC_PIV_SM_workspace work; TC_PIV_link link; TC_PIV_application app; "
            "TC_PIV_SM_peer peer; TC_PIV_reference_status status; uint8_t host[8]={0}; "
            "TC_bytes trusted={public_key,sizeof public_key}; "
            "fixture_card card={{apt,sizeof apt},{response,sizeof response},{reply,sizeof reply}}; "
            "TC_PIV_link_options options={{TC_APDU_SHORT,0,8,0,0},TC_PIV_CONTACT,0}; "
            "if(TC_PIV_link_init(&link,(TC_APDU_transport){fixture_transmit,&card},&options,"
            "(TC_buffer){scratch,sizeof scratch})!=TC_PIV_OK) return 1; "
            "if(TC_PIV_select(&link,TC_PIV_APPLICATION_PIV,0,(TC_buffer){answer,sizeof answer},&app)"
            "!=TC_PIV_OK) return 1; "
            f"if(TC_PIV_SM_key_request(&link,&state,{suite},host,(TC_random_source){{fixture_random,NULL}},"
            "(TC_buffer){answer,sizeof answer},&peer,&work)!=TC_PIV_OK) return 1; "
            "CHECK(TC_PIV_SM_finish(&state,&peer,trusted,&work)); "
            f"if(memcmp(state.data.traffic.mac_key,material+{key_bytes},{key_bytes})) return 1; "
            "if(TC_PIV_link_secure(&link,&work,(TC_buffer){sm_scratch,sizeof sm_scratch})!=TC_PIV_OK) "
            "return 1; "
            "if(TC_PIV_verify_status(&link,0x80,&status)!=TC_PIV_OK || !status.verified) return 1; "
            "consume((const uint8_t*)&state,sizeof state); TC_PIV_link_clear(&link);")
    flags = (AES + " -DTC_ENABLE_PIV_SM=1 -DTC_AES_ENABLE_DYNAMIC=1 -DTC_ENABLE_EC=1 -DTC_ENABLE_SSKDF=1"
             " -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1 -DTC_ENABLE_PIV_CVC=1"
             " -DTC_ENABLE_APDU=1 -DTC_ENABLE_PIV_COMMAND=1 -DTC_ENABLE_PIV_SM_APDU=1"
             f" -DTC_ENABLE_SHA384={int(bits == 384)}"
             f" -DTC_PIV_SM_ENABLE_CS2={int(bits == 256)} -DTC_PIV_SM_ENABLE_CS7={int(bits == 384)}"
             f" -DTC_EC_ENABLE_P256={int(bits == 256)} -DTC_EC_ENABLE_P384={int(bits == 384)}")
    RP2350_FEATURES.append((f"PIV SM CS{2 if bits == 256 else 7} handshake and message", body, flags))


def features_for_board(board):
    return FEATURES + (RP2350_FEATURES if board == "pico2" else [])


def definitions(flags):
    """Keep the last value when a flag is defined more than once."""
    return dict(flag[2:].split("=", 1) for flag in shlex.split(flags))
