/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_chuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void field(const char* name, TC_bytes span)
{
  size_t i;
  printf("%s=", name);
  for (i = 0; i < span.length; ++i) printf("%02x", span.data[i]);
  putchar('\n');
}

int main(int argc, char** argv)
{
  uint8_t data[4096];
  size_t length, i;
  FILE* file;
  TC_PIV_CVC cvc, saved;
  TC_TLV_result result;
  if (argc != 2 && argc != 3) return 2;
  file = fopen(argv[argc - 1], "rb");
  if (!file) return 2;
  length = fread(data, 1, sizeof data, file);
  if (ferror(file) || !feof(file)) { fclose(file); return 2; }
  fclose(file);
  if (argc == 3) {
    TC_PIV_CHUID chuid, previous;
    TC_PIV_CHUID_encoding encoding = strcmp(argv[1], "contents") == 0 ?
      TC_PIV_CHUID_CONTENTS : TC_PIV_CHUID_CONTAINER;
    result = TC_PIV_CHUID_read(data, length, encoding, &chuid);
    if (result != TC_TLV_OK) { fprintf(stderr, "%s: %d\n", argv[2], result); return 1; }
    field("fascn", chuid.fascn);
    field("card_uuid", chuid.card_uuid);
    field("cardholder_uuid", chuid.cardholder_uuid);
    field("expiration", chuid.expiration);
    field("signature", chuid.signature);
    previous = chuid;
    for (i = 0; i < length; ++i) {
      if (TC_PIV_CHUID_read(data, i, encoding, &chuid) == TC_TLV_OK ||
          memcmp(&chuid, &previous, sizeof chuid)) return 1;
    }
    return 0;
  }
  result = TC_PIV_CVC_read(data, length, &cvc);
  if (result != TC_TLV_OK) { fprintf(stderr, "%s: %d\n", argv[1], result); return 1; }
  field("iin", cvc.issuer);
  field("subject", cvc.subject);
  field("public_key_oid", cvc.curve_oid);
  field("public_key_raw_hex", cvc.public_key);
  field("signature_oid", cvc.signature_algorithm.oid);
  field("signature_value", cvc.signature);
  field("signed_data", cvc.signed_data);
  printf("role=%02x\nkey_bits=%u\n", cvc.role, cvc.key_bits);
  saved = cvc;
  for (i = 0; i < length; ++i) {
    if (TC_PIV_CVC_read(data, i, &cvc) == TC_TLV_OK || memcmp(&cvc, &saved, sizeof cvc)) return 1;
  }
  data[0] ^= 1;
  if (TC_PIV_CVC_read(data, length, &cvc) == TC_TLV_OK || memcmp(&cvc, &saved, sizeof cvc)) return 1;
  return 0;
}
