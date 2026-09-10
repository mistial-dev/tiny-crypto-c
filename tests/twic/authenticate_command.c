/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_pcsc.h"
#include "../../examples/credential_validate.h"
#include "../cms/openssl_fixture.h"
#include "card_fixture.h"
#include <sys/resource.h>
#include <zlib.h>

int example_twic_command_main(int argc, char **argv);
enum {
  SUCCESS,
  LEGACY,
  TWIC_PURPOSE,
  CANCELLED,
  STALE,
  FINAL_CCL_SUPERSEDED,
  BAD_ROOT,
  ROOT_DIGEST_MISMATCH,
  BAD_CERTIFICATE,
  BAD_REPLY,
  RNG_FAILURE,
  CLOCK_FAILURE,
  TOO_SLOW,
  BACKWARD_CLOCK,
  OPEN_FAILURE,
  SELECT_FAILURE,
  READ_FAILURE,
  CLOSE_FAILURE,
  LOCK_FAILURE,
  FILE_FAILURE,
  CCL_EXPIRES,
  CCL_FUTURE,
  CCL_NO_TIMESTAMP,
  CCL_AGE_BOUNDARY,
  CERTIFICATE_EXPIRES,
  INTERMEDIATE,
  MISSING_ISSUER,
  GZIP_VALID,
  GZIP_BAD_CRC,
  GZIP_TRUNCATED,
  ROOT_NOT_CA,
  ROOT_WRONG_USAGE,
  ROOT_PATH_LIMIT,
  ROOT_NAME_ALLOWED,
  ROOT_NAME_DENIED,
  ROOT_UNKNOWN_CRITICAL,
  UNRELATED_ROOT,
  WRONG_CARD_KEY,
  CORE_LIMIT_FAILURE,
  UNLOCK_FAILURE,
  INVALID_FASCN,
  UUID_NUMBER_MISMATCH,
  ABSENT_UUID,
  CHUID_VALID,
  CHUID_LEGACY,
  CHUID_TWIC_PURPOSE,
  CHUID_BER,
  CHUID_INTERMEDIATE,
  CHUID_REVOKED,
  CHUID_WRONG_CARD,
  CHUID_WRONG_SIGNER,
  CHUID_TAMPERED,
  CHUID_UNSIGNED,
  CHUID_BAD_CRL,
  CHUID_UNTRUSTED_ROOT,
  CHUID_ROOT_DIGEST_MISMATCH,
  CHUID_DATE_EXPIRES,
  CHUID_READ_FAILURE,
  CHUID_BER_REQUIRED,
  CHUID_BER_TAMPERED,
  CHUID_LARGE_CRL,
  CHUID_LARGE_REVOKED,
  CHUID_CARD_REVOKED,
  CHUID_RSA_ABSENT,
  CHUID_RSA_ABSENT_REQUIRED,
  CHUID_RSA_ABSENT_TAMPERED,
  BIO_VALID,
  BIO_LEGACY,
  BIO_WRONG_KEY,
  BIO_TAMPERED,
  BIO_READ_FAILURE,
  BIO_BAD_KEY,
  BIO_LEGACY_SIGNATURE,
  BIO_LEGACY_SIGNATURE_REQUIRED,
  BIO_RSA_ABSENT,
  BIO_RSA_ABSENT_REQUIRED,
  BIO_RSA_ABSENT_TAMPERED,
  SECURITY_VALID,
  SECURITY_LEGACY,
  SECURITY_CHANGED,
  SECURITY_MISSING,
  SECURITY_OPTIONAL,
  SECURITY_OMITTED_OPTIONAL,
  SECURITY_MAPPING,
  SECURITY_OPTIONAL_DENIED,
  SECURITY_FINAL_DATE,
  SECURITY_FINAL_MAPPING,
  SECURITY_RSA_ABSENT,
  SECURITY_RSA_ABSENT_REQUIRED,
  SECURITY_RSA_ABSENT_TAMPERED,
  SECURITY_PRINTED,
  SECURITY_PRINTED_REQUIRED,
  SECURITY_PRINTED_CHANGED,
  CASES
};
static unsigned scenario, opened, closed, commands, clocks, locked, unlocked,
    selected_twic, ccl_checks;
static unsigned marsec_level;
static int extended_reads, extended_chunks, piv_envelope;
static SyntheticCard card;
static Entropy entropy;
static uint8_t root_der[BUFFER_CAPACITY], issuer_der[BUFFER_CAPACITY],
    leaf_der[BUFFER_CAPACITY], object[2048];
static size_t root_length, issuer_length, leaf_length, object_length,
    object_offset;
static uint8_t compressed[2048];
static TC_bytes wire_certificate;
static void *protected_buffer;
static size_t protected_length;
static uint8_t chuid_bytes[2048], content_root_der[BUFFER_CAPACITY],
    issuer_crl_der[BUFFER_CAPACITY];
static uint8_t crl_der[128 * 1024];
static size_t chuid_length, content_root_length, crl_length, issuer_crl_length;
static uint8_t biometric_bytes[2048], face_bytes[2048];
static size_t biometric_length, face_length, biometric_reads;
static uint8_t security_bytes[2048], unsigned_chuid_bytes[64];
static size_t security_length, unsigned_chuid_length;
static const uint8_t extra_object[] = {0x53, 3, 0xbc, 1, 0x42};
static uint8_t printed_object[96];
static size_t printed_length;
static const uint8_t printed_tlvs[] = {
    0x01, 4,   'T', 'E', 'S', 'T', 0x02, 0,    0x04, 9,   '0',
    '9',  'S', 'E', 'P', '2', '0', '2',  '6',  0x05, 8,   '1',
    '2',  '3', '4', '5', '6', '7', '8',  0x06, 8,    '7', '0',
    '9',  '9', '1', '2', '3', '4', 0x07, 0,    0x08, 0};

static void sha256_hex(const uint8_t *input, size_t length, char out[65]) {
  static const char digits[] = "0123456789abcdef";
  uint8_t digest[32];
  unsigned digest_length;
  munit_assert_int(
      EVP_Digest(input, length, digest, &digest_length, EVP_sha256(), NULL), ==,
      1);
  munit_assert_uint(digest_length, ==, sizeof digest);
  for (size_t i = 0; i < sizeof digest; ++i) {
    out[i * 2] = digits[digest[i] >> 4];
    out[i * 2 + 1] = digits[digest[i] & 15];
  }
  out[64] = 0;
}

ExampleTWICResult example_twic_command_cancellation_check(
    const TC_TWIC_CCL_snapshot *ccl,
    const TC_TWIC_CCL_freshness_policy *freshness, size_t max_reads,
    TC_bytes fascn) {
  ++ccl_checks;
  if (scenario == FINAL_CCL_SUPERSEDED)
    return EXAMPLE_TWIC_STALE;
  return example_twic_cancellation_check(ccl, freshness, max_reads, fascn);
}

static size_t encrypt_biometric(const uint8_t *plaintext,
                                size_t plaintext_length, uint8_t *out,
                                size_t capacity) {
  static const uint8_t key[] = {0, 1, 2,  3,  4,  5,  6,  7,
                                8, 9, 10, 11, 12, 13, 14, 15};
  EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
  munit_assert_not_null(cipher);
  munit_assert_int(
      EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL), ==, 1);
  munit_assert_size(plaintext_length + 24, <=, capacity);
  int written, tail;
  munit_assert_int(EVP_EncryptUpdate(cipher, out + 8, &written, plaintext,
                                     (int)plaintext_length),
                   ==, 1);
  munit_assert_int(EVP_EncryptFinal_ex(cipher, out + 8 + written, &tail), ==,
                   1);
  EVP_CIPHER_CTX_free(cipher);
  const size_t ciphertext_length = (size_t)written + (size_t)tail;
  out[0] = 0x53;
  out[1] = 0x82;
  out[2] = (uint8_t)((ciphertext_length + 4) >> 8);
  out[3] = (uint8_t)(ciphertext_length + 4);
  out[4] = 0xbc;
  out[5] = 0x82;
  out[6] = (uint8_t)(ciphertext_length >> 8);
  out[7] = (uint8_t)ciphertext_length;
  return ciphertext_length + 8;
}

FILE *example_twic_fopen(const char *path, const char *mode) {
  munit_assert_string_equal(mode, "rb");
  const int intermediate = !strcmp(path, "content-issuer-crl");
  munit_assert_true(intermediate || !strcmp(path, "content-crl"));
  const uint8_t *bytes = intermediate ? issuer_crl_der : crl_der;
  const size_t length = intermediate ? issuer_crl_length : crl_length;
  FILE *file = tmpfile();
  munit_assert_not_null(file);
  if (scenario == CHUID_BAD_CRL) {
    const uint8_t invalid = 0;
    munit_assert_size(fwrite(&invalid, 1, 1, file), ==, 1);
  } else
    munit_assert_size(fwrite(bytes, 1, length, file), ==, length);
  rewind(file);
  return file;
}

static int legacy(void) {
  return scenario == LEGACY || scenario == CHUID_LEGACY ||
         scenario == BIO_LEGACY || scenario == BIO_LEGACY_SIGNATURE ||
         scenario == BIO_LEGACY_SIGNATURE_REQUIRED ||
         scenario == SECURITY_LEGACY;
}
static int with_chuid(void) { return scenario >= CHUID_VALID; }
static int with_biometric(void) { return scenario >= BIO_VALID; }
static int with_security(void) { return scenario >= SECURITY_VALID; }
static int optional_objects(void) {
  return scenario == SECURITY_OPTIONAL || scenario == SECURITY_OMITTED_OPTIONAL;
}

int example_twic_setrlimit(int resource, const struct rlimit *limit) {
  munit_assert_int(resource, ==, RLIMIT_CORE);
  munit_assert_uint(limit->rlim_cur, ==, 0);
  munit_assert_uint(limit->rlim_max, ==, 0);
  return scenario == CORE_LIMIT_FAILURE ? -1 : 0;
}

int example_twic_mlock(const void *buffer, size_t length) {
  ++locked;
  protected_buffer = (void *)buffer;
  protected_length = length;
  return scenario == LOCK_FAILURE ? -1 : 0;
}

int example_twic_munlock(const void *buffer, size_t length) {
  ++unlocked;
  munit_assert_ptr_equal(buffer, protected_buffer);
  munit_assert_size(length, ==, protected_length);
  for (size_t i = 0; i < length; ++i)
    munit_assert_uint(((const uint8_t *)buffer)[i], ==, 0);
  return scenario == UNLOCK_FAILURE ? -1 : 0;
}

int example_twic_read_file(const char *path, uint8_t *buffer, size_t capacity,
                           TC_bytes *out);

int example_twic_read_created_file(const char *path, uint8_t *buffer,
                                   size_t capacity, TC_bytes *out,
                                   uint64_t *created) {
  const uint64_t max_age = (marsec_level == 1 ? 7u : 1u) * 24u * 60u * 60u;
  if (scenario == CCL_NO_TIMESTAMP) {
    TC_secure_zero(buffer, capacity);
    return 0;
  }
  *created = scenario == STALE ? 1788912000 - max_age - 1
             : (scenario == CCL_EXPIRES || scenario == CCL_AGE_BOUNDARY)
                 ? 1788912000 - max_age
             : scenario == CCL_FUTURE ? 1788912001
                                      : 1788911950;
  if (scenario == CHUID_DATE_EXPIRES || scenario == SECURITY_FINAL_DATE)
    *created = 1788912000;
  return example_twic_read_file(path, buffer, capacity, out);
}

int example_twic_read_file(const char *path, uint8_t *buffer, size_t capacity,
                           TC_bytes *out) {
  if (scenario == FILE_FAILURE) {
    TC_secure_zero(buffer, capacity);
    return 0;
  }
  size_t length;
  if (!strcmp(path, "tpk")) {
    static const char hex[] =
        "DFC10118C010000102030405060708090A0B0C0D0E0FC10108C20100\n";
    length = sizeof hex - 1;
    munit_assert_size(length, <=, capacity);
    memcpy(buffer, hex, length);
    if (scenario == BIO_WRONG_KEY)
      buffer[12] = 'F';
    if (scenario == BIO_BAD_KEY)
      buffer[0] = 'X';
  } else if (!strcmp(path, "root")) {
    length = root_length;
    munit_assert_size(length, <=, capacity);
    memcpy(buffer, root_der, length);
    if (scenario == BAD_ROOT)
      buffer[0] ^= 1;
  } else if (!strcmp(path, "content-root")) {
    length = content_root_length;
    munit_assert_size(length, <=, capacity);
    memcpy(buffer, content_root_der, length);
  } else if (!strcmp(path, "content-crl") ||
             !strcmp(path, "content-issuer-crl")) {
    const int intermediate = !strcmp(path, "content-issuer-crl");
    length = intermediate ? issuer_crl_length : crl_length;
    munit_assert_size(length, <=, capacity);
    memcpy(buffer, intermediate ? issuer_crl_der : crl_der, length);
    if (scenario == CHUID_BAD_CRL)
      buffer[0] ^= 1;
  } else if (!strcmp(path, "issuer")) {
    length = issuer_length;
    munit_assert_size(length, <=, capacity);
    memcpy(buffer, issuer_der, length);
  } else {
    munit_assert_string_equal(path, "ccl");
    length = TC_TWIC_CCL_FASCN_BYTES;
    munit_assert_size(length, <=, capacity);
    memset(buffer, 0xff, length);
    if (scenario == CANCELLED)
      memcpy(buffer, test_card_fascn, length);
  }
  *out = (TC_bytes){buffer, length};
  return 1;
}

int example_card_now(TC_X509_time *out) {
  ++clocks;
  if (clocks > 1 && with_biometric()) {
    /* The final acceptance check still has the complete encrypted response. */
    munit_assert_size(biometric_length, <=, protected_length);
    const uint8_t *bytes = protected_buffer;
    int retained = 0;
    for (size_t i = 0; i <= protected_length - biometric_length; ++i)
      if (!memcmp(bytes + i, biometric_bytes, biometric_length)) {
        retained = 1;
        break;
      }
    munit_assert_true(retained);
  }
  if (scenario == CLOCK_FAILURE)
    return 0;
  *out = (TC_X509_time){2026, 9, 9, 0, 0, 0};
  if (clocks > 1 && scenario == TOO_SLOW)
    out->second = 31;
  if (clocks > 1 && scenario == BACKWARD_CLOCK)
    out->year = 2025;
  if (clocks > 1 &&
      (scenario == CCL_EXPIRES || scenario == CERTIFICATE_EXPIRES))
    out->second = 1;
  if (scenario == CHUID_DATE_EXPIRES || scenario == SECURITY_FINAL_DATE)
    *out = clocks > 1 ? (TC_X509_time){2026, 9, 10, 0, 0, 0}
                      : (TC_X509_time){2026, 9, 9, 23, 59, 59};
  if (clocks > 1 && scenario == SECURITY_FINAL_MAPPING) {
    uint8_t *bytes = protected_buffer;
    int changed = 0;
    munit_assert_uint(security_bytes[1], ==, 0x82);
    enum { OUTER_HEADER_BYTES = 4, MAPPING_HEADER_BYTES = 2 };
    for (size_t i = 0; i <= protected_length - security_length; ++i) {
      if (memcmp(bytes + i, security_bytes, security_length))
        continue;
      bytes[i + OUTER_HEADER_BYTES + MAPPING_HEADER_BYTES] = 2;
      changed = 1;
      break;
    }
    munit_assert_true(changed);
  }
  return 1;
}

TC_status example_card_random(void *context, uint8_t *out, size_t length) {
  (void)context;
  return random_digest(&entropy, out, length);
}

int example_card_pcsc_open(ExampleCardPCSC *connection, const char *reader) {
  munit_assert_string_equal(reader, "synthetic");
  munit_assert_uint(locked, ==, 1);
  ++opened;
  connection->transaction = scenario != OPEN_FAILURE;
  return connection->transaction;
}

int example_card_pcsc_close(ExampleCardPCSC *connection) {
  ++closed;
  connection->transaction = 0;
  return scenario != CLOSE_FAILURE;
}

static void object_reply(uint8_t *response, size_t capacity, size_t *length) {
  size_t chunk = object_length - object_offset;
  if ((!extended_reads || extended_chunks) && chunk > 200)
    chunk = 200;
  munit_assert_size(chunk + 2, <=, capacity);
  memcpy(response, object + object_offset, chunk);
  object_offset += chunk;
  const size_t remaining = object_length - object_offset;
  response[chunk] = remaining ? 0x61 : 0x90;
  response[chunk + 1] = remaining > 255 ? 0 : (uint8_t)remaining;
  if (extended_reads && !remaining) {
    response[chunk] = 0x62;
    response[chunk + 1] = 0x82;
  }
  *length = chunk + 2;
}

int example_card_pcsc_transmit(void *context, const uint8_t *command,
                               size_t length, uint8_t *response,
                               size_t capacity, size_t *out) {
  munit_assert_int(((ExampleCardPCSC *)context)->transaction, ==, 1);
  ++commands;
  if (command[1] == 0xa4) {
    if (scenario == SELECT_FAILURE)
      return 0;
    munit_assert_size(length, ==, 15);
    munit_assert_size(capacity, >=, 17);
    const int twic = command[9] == 0x67;
    selected_twic = (unsigned)twic;
    response[0] = 0x61;
    response[1] = 13;
    response[2] = 0x4f;
    response[3] = 11;
    memcpy(response + 4, command + 5, 9);
    response[13] = 1;
    response[14] = twic ? (legacy() ? 1 : 3) : 0;
    response[15] = 0x90;
    response[16] = 0;
    *out = 17;
    return 1;
  }
  if (command[1] == 0xcb) {
    if (scenario == READ_FAILURE)
      return 0;
    uint8_t short_command[11];
    if (extended_reads) {
      munit_assert_size(length, ==, 14);
      munit_assert_uint(command[4], ==, 0);
      munit_assert_uint(command[5], ==, 0);
      munit_assert_uint(command[6], ==, 5);
      const size_t requested = (size_t)command[12] << 8 | command[13];
      munit_assert_size(requested + EXAMPLE_CARD_STATUS_BYTES, ==, capacity);
      /* Reuse the object-selection fixture after checking extended framing. */
      memcpy(short_command, command, 4);
      short_command[4] = command[6];
      memcpy(short_command + 5, command + 7, 5);
      short_command[10] = 0;
      command = short_command;
      length = sizeof short_command;
    }
    munit_assert_size(length, ==, 11);
    if (with_security() &&
        (command[9] == 4 || command[9] == 8 || command[9] == 9 ||
         command[9] == 0x0f || command[9] == 0x21 || command[8] == 0xc0)) {
      munit_assert_uint(selected_twic, ==, 1);
      const int optional = command[9] == 0x21 || command[8] == 0xc0;
      if (optional && scenario == SECURITY_OPTIONAL_DENIED) {
        response[0] = 0x69;
        response[1] = 0x82;
        *out = 2;
        return 1;
      }
      if ((optional && !optional_objects()) ||
          (scenario == SECURITY_MISSING && command[9] == 8)) {
        response[0] = 0x6a;
        response[1] = 0x82;
        *out = 2;
        return 1;
      }
      const uint8_t *bytes = command[9] == 4      ? unsigned_chuid_bytes
                             : command[9] == 8    ? face_bytes
                             : command[9] == 0x0f ? security_bytes
                                                  : extra_object;
      object_length = command[9] == 4      ? unsigned_chuid_length
                      : command[9] == 8    ? face_length
                      : command[9] == 0x0f ? security_length
                                           : sizeof extra_object;
      if (command[9] == 9 && scenario >= SECURITY_PRINTED) {
        bytes = printed_object;
        object_length = printed_length;
      }
      munit_assert_size(object_length, <=, sizeof object);
      memcpy(object, bytes, object_length);
      object_offset = 0;
      object_reply(response, capacity, out);
      return 1;
    }
    if (command[9] == 3 || command[9] == 8) {
      munit_assert_true(with_biometric());
      munit_assert_uint(selected_twic, ==, 1);
      const uint8_t biometric_tag[] = {0xdf, 0xc1, command[9]};
      munit_assert_memory_equal(sizeof biometric_tag, command + 7,
                                biometric_tag);
      ++biometric_reads;
      if (scenario == BIO_READ_FAILURE)
        return 0;
      const uint8_t *bytes = command[9] == 3 ? biometric_bytes : face_bytes;
      object_length = command[9] == 3 ? biometric_length : face_length;
      munit_assert_size(object_length, <=, sizeof object);
      memcpy(object, bytes, object_length);
      object_offset = 0;
      object_reply(response, capacity, out);
      return 1;
    }
    if (command[9] == 2) {
      munit_assert_true(with_chuid());
      if (scenario == CHUID_READ_FAILURE)
        return 0;
      static const uint8_t chuid_tag[] = {0x5f, 0xc1, 2};
      munit_assert_memory_equal(sizeof chuid_tag, command + 7, chuid_tag);
      munit_assert_size(chuid_length, <=, sizeof object);
      memcpy(object, chuid_bytes, chuid_length);
      object_length = chuid_length;
      object_offset = 0;
      object_reply(response, capacity, out);
      return 1;
    }
    static const uint8_t tag[] = {0x5f, 0xc1, 1};
    munit_assert_memory_equal(sizeof tag, command + 7, tag);
    const size_t wire_length = wire_certificate.length;
    const size_t payload =
        4 + wire_length + 3 + (legacy() || piv_envelope ? 2 : 0);
    object[0] = 0x53;
    object[1] = 0x82;
    object[2] = (uint8_t)(payload >> 8);
    object[3] = (uint8_t)payload;
    object[4] = 0x70;
    object[5] = 0x82;
    object[6] = (uint8_t)(wire_length >> 8);
    object[7] = (uint8_t)wire_length;
    memcpy(object + 8, wire_certificate.data, wire_length);
    if (scenario == BAD_CERTIFICATE)
      object[8 + wire_length - 1] ^= 1;
    size_t used = 8 + wire_length;
    object[used++] = 0x71;
    object[used++] = 1;
    object[used++] =
        scenario >= GZIP_VALID && scenario <= GZIP_TRUNCATED ? 1 : 0;
    if (legacy() || piv_envelope) {
      object[used++] = 0xfe;
      object[used++] = 0;
    }
    object_length = used;
    object_offset = 0;
    object_reply(response, capacity, out);
    return 1;
  }
  if (command[1] == 0xc0 && object_offset < object_length) {
    object_reply(response, capacity, out);
    return 1;
  }
  return transmit(&card, command, length, response, capacity, out);
}

static void make_chuid(X509 *root, EVP_PKEY *root_key, X509 *issuer,
                       EVP_PKEY *issuer_key, EVP_PKEY *signing_key,
                       X509 *card_certificate) {
  enum { PREFIX_BYTES = 55, OUTER_HEADER = 4, CMS_HEADER = 4 };
  const int intermediate = scenario == CHUID_INTERMEDIATE;
  X509 *signing = make_certificate(signing_key, "Synthetic contents signer",
                                   intermediate ? issuer : root);
  add_extension(signing, NID_key_usage, "critical,digitalSignature");
  add_extension(signing, NID_ext_key_usage,
                scenario == CHUID_TWIC_PURPOSE ? "1.3.6.1.4.1.29138.6.7"
                                               : "2.16.840.1.101.3.6.7");
  munit_assert_int(
      X509_sign(signing, intermediate ? issuer_key : root_key, EVP_sha256()), >,
      0);
  X509 *provisioned = X509_dup(root);
  munit_assert_not_null(provisioned);
  if (scenario == CHUID_UNTRUSTED_ROOT)
    munit_assert_int(X509_set_pubkey(provisioned, issuer_key), ==, 1);
  content_root_length = encode_certificate(
      provisioned, scenario == CHUID_UNTRUSTED_ROOT ? issuer_key : root_key,
      EVP_sha256(), content_root_der, sizeof content_root_der);
  X509_free(provisioned);
  const int large_crl =
      scenario == CHUID_LARGE_CRL || scenario == CHUID_LARGE_REVOKED;
  crl_length = encode_issuer_crl_entries(
      root, root_key,
      scenario == CHUID_CARD_REVOKED ? card_certificate
      : scenario == CHUID_REVOKED || scenario == CHUID_LARGE_REVOKED ? signing
                                                                     : NULL,
      large_crl ? 2048 : 0, crl_der, sizeof crl_der);
  if (large_crl)
    munit_assert_size(crl_length, >, 16 * 1024);
  issuer_crl_length = encode_issuer_crl(issuer, issuer_key, NULL,
                                        issuer_crl_der, sizeof issuer_crl_der);
  uint8_t content[PREFIX_BYTES + 2] = {0x30, 25};
  memcpy(content + 2, test_card_fascn, sizeof test_card_fascn);
  if (scenario == CHUID_WRONG_CARD)
    content[2] ^= 1;
  content[27] = 0x34;
  content[28] = 16;
  static const uint8_t guid[] = {0x91, 0xbe, 0x20, 0x94, 0xf6, 0xdc,
                                 0x53, 0x49, 0x80, 0,    0x40, 0x90,
                                 0xe4, 0x9e, 0x50, 0x5c};
  if (!legacy())
    memcpy(content + 29, guid, sizeof guid);
  content[45] = 0x35;
  content[46] = 8;
  memcpy(content + 47, "20260909", 8);
  content[PREFIX_BYTES] = 0xfe;
  memcpy(chuid_bytes + OUTER_HEADER, content, PREFIX_BYTES);
  size_t used = OUTER_HEADER + PREFIX_BYTES;
  if (scenario != CHUID_UNSIGNED) {
    const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED;
    CMS_ContentInfo *cms =
        CMS_sign(signing, signing_key, NULL, NULL, flags | CMS_PARTIAL);
    BIO *input = BIO_new_mem_buf(content, sizeof content);
    ASN1_OBJECT *type = OBJ_txt2obj("2.16.840.1.101.3.6.1", 1);
    munit_assert_not_null(cms);
    munit_assert_not_null(input);
    munit_assert_not_null(type);
    munit_assert_int(CMS_set1_eContentType(cms, type), ==, 1);
    set_cms_signer_name(
        cms,
        X509_get_subject_name(scenario == CHUID_WRONG_SIGNER ? root : signing));
    munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
    int length = i2d_CMS_ContentInfo(cms, NULL);
    munit_assert_int(length, >, 0);
    munit_assert_size((size_t)length + used + CMS_HEADER + 2, <=,
                      sizeof chuid_bytes);
    chuid_bytes[used++] = 0x3e;
    chuid_bytes[used++] = 0x82;
    chuid_bytes[used++] = (uint8_t)((unsigned)length >> 8);
    chuid_bytes[used++] = (uint8_t)length;
    unsigned char *cursor = chuid_bytes + used;
    munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
    if (scenario >= CHUID_RSA_ABSENT && scenario <= CHUID_RSA_ABSENT_TAMPERED) {
      length = (int)omit_cms_rsa_parameters(
          (TC_bytes){chuid_bytes + used, (size_t)length}, chuid_bytes + used,
          sizeof chuid_bytes - used - 2);
      chuid_bytes[used - 2] = (uint8_t)((unsigned)length >> 8);
      chuid_bytes[used - 1] = (uint8_t)length;
    }
    if (scenario == CHUID_BER || scenario == CHUID_BER_REQUIRED ||
        scenario == CHUID_BER_TAMPERED) {
      length = (int)cms_fixture_reverse_attributes(
          chuid_bytes + used, (size_t)length, sizeof chuid_bytes - used - 2,
          signing_key);
      chuid_bytes[used - 2] = (uint8_t)((unsigned)length >> 8);
      chuid_bytes[used - 1] = (uint8_t)length;
    }
    used += (size_t)length;
    if (scenario == CHUID_TAMPERED || scenario == CHUID_BER_TAMPERED ||
        scenario == CHUID_RSA_ABSENT_TAMPERED)
      chuid_bytes[used - 1] ^= 1;
    CMS_ContentInfo_free(cms);
    BIO_free(input);
    ASN1_OBJECT_free(type);
  }
  chuid_bytes[used++] = 0xfe;
  chuid_bytes[used++] = 0;
  const size_t payload = used - OUTER_HEADER;
  chuid_bytes[0] = 0x53;
  chuid_bytes[1] = 0x82;
  chuid_bytes[2] = (uint8_t)(payload >> 8);
  chuid_bytes[3] = (uint8_t)payload;
  if (payload < 128) {
    memmove(chuid_bytes + 2, chuid_bytes + OUTER_HEADER, payload);
    chuid_bytes[1] = (uint8_t)payload;
    used = payload + 2;
  }
  chuid_length = used;
  if (with_biometric()) {
    uint8_t plaintext[2048];
    const TC_bytes signed_guid =
        scenario == BIO_LEGACY_SIGNATURE ||
                scenario == BIO_LEGACY_SIGNATURE_REQUIRED
            ? (TC_bytes){NULL, 0}
            : (TC_bytes){content + 29, 16};
    const size_t plaintext_length = encode_biometric_parameters(
        signing, signing_key, 0,
        scenario >= BIO_RSA_ABSENT && scenario <= BIO_RSA_ABSENT_TAMPERED,
        (TC_bytes){content + 2, 25}, signed_guid, plaintext, sizeof plaintext);
    if (scenario == BIO_TAMPERED || scenario == BIO_RSA_ABSENT_TAMPERED)
      plaintext[88] ^= 1;
    biometric_length = encrypt_biometric(
        plaintext, plaintext_length, biometric_bytes, sizeof biometric_bytes);
    static const uint8_t piv_face[] = {
        'F',  'A', 'C', 0, '0', '1', '0', 0,    0,    0,    0,   50,   0,
        1,    0,   0,   0, 36,  0,   0,   0,    0,    0,    0,   0,    0,
        0,    1,   0,   0, 0,   0,   0,   0,    1,    0,    1,   0xa5, 2,
        0x58, 1,   2,   0, 0,   0,   0,   0xff, 0xd8, 0xff, 0xd9};
    uint8_t face_record[sizeof piv_face];
    memcpy(face_record, piv_face, sizeof face_record);
    face_record[26] = face_record[27] = 0;
    face_record[34] = 0;
    face_record[36] = 1;
    face_record[37] = 18;
    const size_t face_plaintext_length = encode_biometric_record_parameters(
        signing, signing_key, 0,
        scenario >= BIO_RSA_ABSENT && scenario <= BIO_RSA_ABSENT_TAMPERED,
        (TC_bytes){content + 2, 25}, signed_guid,
        (TC_bytes){face_record, sizeof face_record}, 0x0501, 2, 0x20, plaintext,
        sizeof plaintext);
    face_length = encrypt_biometric(plaintext, face_plaintext_length,
                                    face_bytes, sizeof face_bytes);
  }
  if (with_security()) {
    unsigned_chuid_length =
        cms_fixture_field(unsigned_chuid_bytes, sizeof unsigned_chuid_bytes,
                          0x53, content, sizeof content);
    static const uint16_t containers[] = {0x3000, 0x3002, 0x2003, 0x6030,
                                          0x3001, 0x1015, 0x6011, 0x6012};
    TC_bytes contents[] = {{chuid_bytes + 4, chuid_length - 4},
                           {content, sizeof content},
                           {biometric_bytes + 4, biometric_length - 4},
                           {face_bytes + 4, face_length - 4},
                           {extra_object + 2, sizeof extra_object - 2},
                           {extra_object + 2, sizeof extra_object - 2},
                           {extra_object + 2, sizeof extra_object - 2},
                           {extra_object + 2, sizeof extra_object - 2}};
    if (scenario >= SECURITY_PRINTED) {
      static const uint8_t key[] = {0, 1, 2,  3,  4,  5,  6,  7,
                                    8, 9, 10, 11, 12, 13, 14, 15};
      uint8_t ciphertext[80], field[88];
      EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
      munit_assert_not_null(cipher);
      munit_assert_int(
          EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL), ==,
          1);
      int written, tail;
      munit_assert_int(EVP_EncryptUpdate(cipher, ciphertext, &written,
                                         printed_tlvs, sizeof printed_tlvs),
                       ==, 1);
      munit_assert_int(EVP_EncryptFinal_ex(cipher, ciphertext + written, &tail),
                       ==, 1);
      EVP_CIPHER_CTX_free(cipher);
      const size_t field_length = cms_fixture_field(
          field, sizeof field, 0xbc, ciphertext, (size_t)(written + tail));
      printed_length = cms_fixture_field(printed_object, sizeof printed_object,
                                         0x53, field, field_length);
      contents[4] = (TC_bytes){printed_tlvs, sizeof printed_tlvs};
      if (scenario == SECURITY_PRINTED_CHANGED)
        printed_object[printed_length - 1] ^= 1;
    }
    uint8_t body[2048];
    const size_t length = encode_security_inventory_parameters(
        signing, signing_key,
        scenario >= SECURITY_RSA_ABSENT &&
            scenario <= SECURITY_RSA_ABSENT_TAMPERED,
        containers, contents,
        legacy()             ? 3
        : optional_objects() ? (scenario == SECURITY_OMITTED_OPTIONAL ? 7 : 8)
                             : 5,
        body, sizeof body);
    if (scenario == SECURITY_MAPPING)
      body[2] = 2;
    if (scenario == SECURITY_RSA_ABSENT_TAMPERED)
      body[length - 3] ^= 1;
    security_length = cms_fixture_field(security_bytes, sizeof security_bytes,
                                        0x53, body, length);
    if (scenario == SECURITY_CHANGED)
      unsigned_chuid_bytes[31] ^= 1;
  }
  X509_free(signing);
}

static MunitResult command_workflow(const MunitParameter params[],
                                    void *context) {
  const char *mode = munit_parameters_get(params, "transport");
  extended_reads = strcmp(mode, "short") != 0;
  extended_chunks = !strcmp(mode, "extended-chained");
  piv_envelope = !strcmp(mode, "extended-piv-envelope");
  marsec_level = !extended_reads ? 1 : piv_envelope ? 3 : 2;
  EVP_PKEY *root_key = EVP_EC_gen("prime256v1");
  EVP_PKEY *card_key = EVP_RSA_gen(2048);
  EVP_PKEY *other_card_key = EVP_RSA_gen(2048);
  EVP_PKEY *signing_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(root_key);
  munit_assert_not_null(card_key);
  munit_assert_not_null(other_card_key);
  munit_assert_not_null(signing_key);
  X509 *root = make_certificate(root_key, "Synthetic command root", NULL);
  add_extension(root, NID_basic_constraints, "critical,CA:TRUE");
  add_extension(root, NID_key_usage, "critical,keyCertSign,cRLSign");
  root_length = encode_certificate(root, root_key, EVP_sha256(), root_der,
                                   sizeof root_der);
  EVP_PKEY *issuer_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(issuer_key);
  X509 *issuer = make_certificate(issuer_key, "Synthetic command issuer", root);
  add_extension(issuer, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
  add_extension(issuer, NID_key_usage, "critical,keyCertSign,cRLSign");
  issuer_length = encode_certificate(issuer, root_key, EVP_sha256(), issuer_der,
                                     sizeof issuer_der);
  for (scenario = 0; scenario < CASES; ++scenario) {
    X509 *provisioned = X509_dup(root);
    munit_assert_not_null(provisioned);
    if (scenario == ROOT_NOT_CA || scenario == ROOT_PATH_LIMIT) {
      X509_EXTENSION_free(X509_delete_ext(
          provisioned,
          X509_get_ext_by_NID(provisioned, NID_basic_constraints, -1)));
      add_extension(provisioned, NID_basic_constraints,
                    scenario == ROOT_NOT_CA ? "critical,CA:FALSE"
                                            : "critical,CA:TRUE,pathlen:0");
    }
    if (scenario == ROOT_WRONG_USAGE) {
      X509_EXTENSION_free(X509_delete_ext(
          provisioned, X509_get_ext_by_NID(provisioned, NID_key_usage, -1)));
      add_extension(provisioned, NID_key_usage, "critical,digitalSignature");
    }
    if (scenario == ROOT_NAME_ALLOWED || scenario == ROOT_NAME_DENIED)
      add_extension(provisioned, NID_name_constraints,
                    "critical,permitted;DNS:.allowed.invalid");
    if (scenario == ROOT_UNKNOWN_CRITICAL)
      add_extension(provisioned, NID_ext_key_usage, "critical,clientAuth");
    /* Matching issuer names alone cannot establish a certificate path. */
    if (scenario == UNRELATED_ROOT)
      munit_assert_int(X509_set_pubkey(provisioned, issuer_key), ==, 1);
    root_length = encode_certificate(
        provisioned, scenario == UNRELATED_ROOT ? issuer_key : root_key,
        EVP_sha256(), root_der, sizeof root_der);
    X509_free(provisioned);
    const int issued = scenario == INTERMEDIATE || scenario == MISSING_ISSUER ||
                       scenario == ROOT_PATH_LIMIT;
    X509 *leaf = make_certificate(card_key, "Synthetic command card",
                                  issued ? issuer : root);
    if (scenario == CERTIFICATE_EXPIRES)
      munit_assert_int(
          ASN1_TIME_set_string(X509_getm_notAfter(leaf), "20260909000000Z"), ==,
          1);
    add_extension(leaf, NID_basic_constraints, "critical,CA:FALSE");
    add_extension(leaf, NID_key_usage, "critical,digitalSignature");
    add_extension(leaf, NID_ext_key_usage,
                  scenario == TWIC_PURPOSE ? "1.3.6.1.4.1.29138.6.8"
                                           : "2.16.840.1.101.3.6.8");
    uint8_t fascn[25];
    memcpy(fascn, test_card_fascn, sizeof fascn);
    if (scenario == INVALID_FASCN)
      fascn[0] ^= 1;
    add_card_identifiers(leaf, (TC_bytes){fascn, sizeof fascn},
                         scenario == ABSENT_UUID ? NULL
                         : legacy()
                             ? "urn:uuid:00000000-0000-0000-0000-000000000000"
                         : scenario == UUID_NUMBER_MISMATCH
                             ? "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505d"
                             : "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c");
    if (scenario == ROOT_NAME_ALLOWED || scenario == ROOT_NAME_DENIED) {
      GENERAL_NAMES *names =
          X509_get_ext_d2i(leaf, NID_subject_alt_name, NULL, NULL);
      GENERAL_NAME *name = GENERAL_NAME_new();
      ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
      munit_assert_not_null(names);
      munit_assert_not_null(name);
      munit_assert_not_null(dns);
      const char *text = scenario == ROOT_NAME_ALLOWED ? "card.allowed.invalid"
                                                       : "card.blocked.invalid";
      munit_assert_int(ASN1_STRING_set(dns, text, (int)strlen(text)), ==, 1);
      GENERAL_NAME_set0_value(name, GEN_DNS, dns);
      munit_assert_int(sk_GENERAL_NAME_push(names, name), >, 0);
      munit_assert_int(X509_add1_ext_i2d(leaf, NID_subject_alt_name, names, 0,
                                         X509V3_ADD_REPLACE),
                       ==, 1);
      GENERAL_NAMES_free(names);
    }
    leaf_length = encode_certificate(leaf, issued ? issuer_key : root_key,
                                     EVP_sha256(), leaf_der, sizeof leaf_der);
    if (with_chuid())
      make_chuid(root, root_key, issuer, issuer_key,
                 ((scenario >= CHUID_RSA_ABSENT &&
                   scenario <= CHUID_RSA_ABSENT_TAMPERED) ||
                  (scenario >= BIO_RSA_ABSENT &&
                   scenario <= BIO_RSA_ABSENT_TAMPERED) ||
                  (scenario >= SECURITY_RSA_ABSENT &&
                   scenario <= SECURITY_RSA_ABSENT_TAMPERED))
                     ? other_card_key
                     : signing_key,
                 leaf);
    X509_free(leaf);
    wire_certificate = (TC_bytes){leaf_der, leaf_length};
    if (scenario >= GZIP_VALID && scenario <= GZIP_TRUNCATED) {
      enum { GZIP_WINDOW_BITS = 31, DEFLATE_MEMORY_LEVEL = 8 };
      z_stream stream = {0};
      munit_assert_int(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                                    GZIP_WINDOW_BITS, DEFLATE_MEMORY_LEVEL,
                                    Z_DEFAULT_STRATEGY),
                       ==, Z_OK);
      stream.next_in = leaf_der;
      stream.avail_in = (uInt)leaf_length;
      stream.next_out = compressed;
      stream.avail_out = sizeof compressed;
      munit_assert_int(deflate(&stream, Z_FINISH), ==, Z_STREAM_END);
      wire_certificate = (TC_bytes){compressed, (size_t)stream.total_out};
      munit_assert_int(deflateEnd(&stream), ==, Z_OK);
      if (scenario == GZIP_BAD_CRC)
        compressed[wire_certificate.length - 8] ^= 1;
      if (scenario == GZIP_TRUNCATED)
        --wire_certificate.length;
    }
    memset(&card, 0, sizeof card);
    card.key = scenario == WRONG_CARD_KEY ? other_card_key : card_key;
    card.algorithm = EXAMPLE_CARD_ALGORITHM_RSA_2048;
    card.pss = extended_reads;
    card.mode = scenario == BAD_REPLY ? TAMPERED : NORMAL;
    entropy = (Entropy){1, scenario == RNG_FAILURE, 0};
    opened = closed = commands = clocks = locked = unlocked = ccl_checks = 0;
    object_length = object_offset = 0;
    biometric_reads = 0;
    char root_digest[65], content_root_digest[65];
    sha256_hex(root_der, root_length, root_digest);
    if (scenario == ROOT_DIGEST_MISMATCH)
      root_digest[0] = root_digest[0] == '0' ? '1' : '0';
    if (with_chuid())
      sha256_hex(content_root_der, content_root_length, content_root_digest);
    if (scenario == CHUID_ROOT_DIGEST_MISMATCH)
      content_root_digest[0] = content_root_digest[0] == '0' ? '1' : '0';
    char *argv[40] = {"twic_authenticate",
                      "--reader",
                      "synthetic",
                      "--root",
                      "root",
                      "--root-sha256",
                      root_digest,
                      "--ccl",
                      "ccl",
                      "--issuer",
                      "issuer",
                      NULL};
    int argc = issued && scenario != MISSING_ISSUER ? 11 : 9;
    if (card.pss) {
      argv[argc++] = "--rsa-padding";
      argv[argc++] = "pss";
    }
    if (extended_reads) {
      argv[argc++] = "--marsec-level";
      argv[argc++] = marsec_level == 3 ? "3" : "2";
    }
    if (with_chuid()) {
      argv[argc++] = "--chuid-root";
      argv[argc++] = "content-root";
      argv[argc++] = "--chuid-root-sha256";
      argv[argc++] = content_root_digest;
      argv[argc++] = "--chuid-crl";
      argv[argc++] = "content-crl";
      if (scenario == CHUID_BER || scenario == CHUID_BER_TAMPERED)
        argv[argc++] = "--chuid-ber";
      if (scenario == CHUID_RSA_ABSENT ||
          scenario == CHUID_RSA_ABSENT_TAMPERED || scenario == BIO_RSA_ABSENT ||
          scenario == BIO_RSA_ABSENT_TAMPERED ||
          scenario == SECURITY_RSA_ABSENT ||
          scenario == SECURITY_RSA_ABSENT_TAMPERED) {
        argv[argc++] = "--cms-rsa-parameters";
        argv[argc++] = "allow-absent";
      }
      if (scenario == CHUID_INTERMEDIATE) {
        argv[argc++] = "--chuid-issuer";
        argv[argc++] = "issuer";
        argv[argc++] = "--chuid-crl";
        argv[argc++] = "content-issuer-crl";
      }
    }
    if (with_biometric()) {
      argv[argc++] = "--tpk-hex";
      argv[argc++] = "tpk";
    }
    if (scenario == BIO_LEGACY_SIGNATURE)
      argv[argc++] = "--legacy-biometric-signature";
    if (with_security())
      argv[argc++] = "--security-object";
    if (scenario == SECURITY_PRINTED || scenario == SECURITY_PRINTED_CHANGED)
      argv[argc++] = "--printed-plaintext";
    if (extended_reads)
      argv[argc++] = "--extended-reads";
    if (piv_envelope)
      argv[argc++] = "--piv-certificate-envelope";
    const int expected =
        scenario == SUCCESS || scenario == CCL_AGE_BOUNDARY ||
        scenario == LEGACY || scenario == TWIC_PURPOSE ||
        scenario == ABSENT_UUID || scenario == CHUID_LARGE_CRL ||
        scenario == CHUID_RSA_ABSENT || scenario == INTERMEDIATE ||
        scenario == GZIP_VALID || scenario == ROOT_NAME_ALLOWED ||
        (scenario >= CHUID_VALID && scenario <= CHUID_INTERMEDIATE) ||
        scenario == BIO_VALID || scenario == BIO_LEGACY ||
        scenario == BIO_LEGACY_SIGNATURE || scenario == BIO_RSA_ABSENT ||
        scenario == SECURITY_VALID || scenario == SECURITY_LEGACY ||
        scenario == SECURITY_OPTIONAL || scenario == SECURITY_RSA_ABSENT ||
        scenario == SECURITY_PRINTED;
    munit_assert_int(example_twic_command_main(argc, argv), ==,
                     expected ? 0 : 1);
    if (expected || scenario == FINAL_CCL_SUPERSEDED)
      munit_assert_uint(ccl_checks, ==, 1);
    const int protected =
        scenario != LOCK_FAILURE && scenario != CORE_LIMIT_FAILURE;
    munit_assert_uint(unlocked, ==, protected ? 1 : 0);
    munit_assert_uint(closed, ==, protected ? 1 : 0);
    if (scenario == CORE_LIMIT_FAILURE)
      munit_assert_uint(locked, ==, 0);
    if (scenario == CCL_FUTURE || scenario == CCL_NO_TIMESTAMP) {
      munit_assert_uint(opened, ==, 0);
      munit_assert_uint(commands, ==, 0);
    }
    if (scenario == CANCELLED || scenario == BAD_CERTIFICATE ||
        scenario == STALE || scenario == CCL_FUTURE ||
        scenario == CCL_NO_TIMESTAMP || scenario == INVALID_FASCN ||
        scenario == UUID_NUMBER_MISMATCH || scenario == BAD_ROOT ||
        scenario == ROOT_DIGEST_MISMATCH || scenario == FILE_FAILURE ||
        scenario == CLOCK_FAILURE || scenario == LOCK_FAILURE ||
        scenario == OPEN_FAILURE || scenario == SELECT_FAILURE ||
        scenario == READ_FAILURE || scenario == MISSING_ISSUER ||
        scenario == GZIP_BAD_CRC || scenario == GZIP_TRUNCATED ||
        scenario == ROOT_NOT_CA || scenario == ROOT_WRONG_USAGE ||
        scenario == ROOT_PATH_LIMIT || scenario == ROOT_NAME_DENIED ||
        scenario == ROOT_UNKNOWN_CRITICAL || scenario == UNRELATED_ROOT ||
        scenario == CORE_LIMIT_FAILURE || scenario == BIO_BAD_KEY ||
        scenario == CHUID_ROOT_DIGEST_MISMATCH)
      munit_assert_size(entropy.calls, ==, 0);
    if (scenario == INVALID_FASCN || scenario == UUID_NUMBER_MISMATCH)
      munit_assert_size(card.signatures, ==, 0);
    if (expected || scenario == FINAL_CCL_SUPERSEDED ||
        scenario == WRONG_CARD_KEY || scenario == UNLOCK_FAILURE ||
        (with_chuid() && scenario != BIO_BAD_KEY &&
         scenario != CHUID_ROOT_DIGEST_MISMATCH))
      munit_assert_size(card.signatures, ==, 1);
    if (with_biometric()) {
      if (scenario == BIO_BAD_KEY)
        munit_assert_size(biometric_reads, ==, 0);
      else {
        munit_assert_size(biometric_reads, >=, 1);
        munit_assert_size(biometric_reads, <=, 2);
      }
    }
  }
  X509_free(root);
  X509_free(issuer);
  EVP_PKEY_free(issuer_key);
  EVP_PKEY_free(root_key);
  EVP_PKEY_free(card_key);
  EVP_PKEY_free(other_card_key);
  EVP_PKEY_free(signing_key);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult command_arguments(const MunitParameter params[],
                                     void *context) {
  char *argv[32] = {"twic_authenticate",
                    "--reader",
                    "synthetic",
                    "--root",
                    "root",
                    "--ccl",
                    "ccl",
                    "--marsec-level",
                    "1",
                    NULL};
  static const char *bad_numbers[] = {
      "", "-1", "+1", " 1", "1x", "18446744073709551616", "0", "4"};
  opened = locked = commands = 0;
  for (size_t i = 0; i < sizeof bad_numbers / sizeof *bad_numbers; ++i) {
    argv[8] = (char *)bad_numbers[i];
    munit_assert_int(example_twic_command_main(9, argv), ==, 2);
  }
  argv[8] = "1";
  argv[9] = "--cms-rsa-parameters";
  munit_assert_int(example_twic_command_main(10, argv), ==, 2);
  argv[10] = "unknown";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[10] = "allow-absent";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[11] = "--chuid-root";
  argv[12] = "unused";
  argv[13] = "--chuid-crl";
  argv[14] = "unused";
  argv[15] = "--cms-rsa-parameters";
  argv[16] = "null";
  munit_assert_int(example_twic_command_main(17, argv), ==, 2);
  argv[9] = "--printed-plaintext";
  munit_assert_int(example_twic_command_main(10, argv), ==, 2);
  argv[10] = "--printed-plaintext";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[9] = "--rsa-padding";
  argv[10] = "unknown";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[10] = "pss";
  argv[11] = "--rsa-padding";
  argv[12] = "v15";
  munit_assert_int(example_twic_command_main(13, argv), ==, 2);
  argv[9] = "--marsec-level";
  argv[10] = "2";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[7] = "--published";
  munit_assert_int(example_twic_command_main(9, argv), ==, 2);
  argv[7] = "--unknown";
  munit_assert_int(example_twic_command_main(9, argv), ==, 2);
  argv[7] = "--marsec-level";
  munit_assert_int(example_twic_command_main(8, argv), ==, 2);
  static const char *incomplete[] = {"--chuid-root", "--chuid-crl",
                                     "--chuid-issuer", "--tpk-hex"};
  for (size_t i = 0; i < sizeof incomplete / sizeof *incomplete; ++i) {
    argv[9] = (char *)incomplete[i];
    argv[10] = "unused";
    munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  }
  argv[9] = argv[10] = "--chuid-ber";
  munit_assert_int(example_twic_command_main(10, argv), ==, 2);
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[9] = argv[10] = "--extended-reads";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[9] = argv[10] = "--piv-certificate-envelope";
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[9] = argv[10] = "--legacy-biometric-signature";
  munit_assert_int(example_twic_command_main(10, argv), ==, 2);
  munit_assert_int(example_twic_command_main(11, argv), ==, 2);
  argv[9] = "--chuid-root";
  argv[10] = "unused";
  argv[11] = "--chuid-root";
  argv[12] = "unused";
  munit_assert_int(example_twic_command_main(13, argv), ==, 2);
  for (unsigned kind = 0; kind < 2; ++kind) {
    int argc = 11;
    argv[argc++] = "--chuid-crl";
    argv[argc++] = "unused";
    for (unsigned i = 0; i < 4; ++i) {
      argv[argc++] = kind ? "--chuid-issuer" : "--chuid-crl";
      argv[argc++] = "unused";
    }
    munit_assert_int(example_twic_command_main(argc, argv), ==, 2);
  }
  munit_assert_uint(opened, ==, 0);
  munit_assert_uint(locked, ==, 0);
  munit_assert_uint(commands, ==, 0);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

int main(int argc, char **argv) {
  static char *transports[] = {"short", "extended", "extended-chained",
                               "extended-piv-envelope", NULL};
  static MunitParameterEnum workflow_parameters[] = {{"transport", transports},
                                                     {NULL, NULL}};
  MunitTest tests[] = {{"/workflow", command_workflow, NULL, NULL,
                        MUNIT_TEST_OPTION_NONE, workflow_parameters},
                       {"/arguments", command_arguments, NULL, NULL,
                        MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/twic/command", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
