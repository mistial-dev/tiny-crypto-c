/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/eac_cvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void field(const char* name, TC_bytes value)
{
  size_t i;
  printf("%s=", name);
  for (i = 0; i < value.length; ++i) printf("%02x", value.data[i]);
  putchar('\n');
}
int main(int argc, char** argv)
{
  static uint8_t data[65536];
  TC_TLV_limits limits = {sizeof data,sizeof data,4096,16};
  TC_TLV_frame frames[16];
  TC_EAC_CVC_workspace workspace = {frames,16};
  TC_EAC_CVC certificate, saved;
  TC_EAC_CVC_public_key key, old_key;
  TC_TLV_result result;
  size_t length, i;
  FILE* file;
  if (argc != 2 && argc != 3 && argc != 5) return 2;
  file = !strcmp(argv[1], "-") ? stdin : fopen(argv[1], "rb");
  if (!file) return 2;
  length = fread(data, 1, sizeof data, file);
  if (ferror(file) || !feof(file)) { fclose(file); return 2; }
  fclose(file);
  if (argc == 3) {
    memset(&key, 0xa5, sizeof key); old_key = key;
    result = TC_EAC_CVC_public_key_read(data, length, &limits, &key);
    printf("result=%d\n", result);
    if (result != TC_TLV_OK) return memcmp(&key, &old_key, sizeof key) ? 1 : 0;
    field("oid", key.oid); field("point", key.point);
    return 0;
  }
  memset(&certificate, 0xa5, sizeof certificate); saved = certificate;
  result = TC_EAC_CVC_read(data, length, &limits, &workspace, &certificate);
  printf("result=%d\n", result);
  if (result != TC_TLV_OK) return memcmp(&certificate, &saved, sizeof certificate) ? 1 : 0;
  field("issuer", certificate.issuer); field("holder", certificate.holder);
  field("signed_data", certificate.signed_data); field("signature", certificate.signature);
  field("oid", certificate.public_key.oid); field("point", certificate.public_key.point);
  printf("role=%u\ntype=%u\ndomain=%d\n", (unsigned)certificate.role,
      (unsigned)certificate.terminal_type, certificate.public_key.has_domain);
  printf("self_encoding=%d\n", TC_EAC_CVC_check_encoding(&certificate, &certificate.public_key, NULL));
  if (argc == 5) {
    static const uint8_t magnitude[8192] = {0x80};
    size_t widths[3];
    TC_EAC_CVC_public_key issuer, domain;
    for (i = 0; i < 3; ++i) {
      char* end;
      unsigned long width = strtoul(argv[i + 2], &end, 10);
      if (!argv[i + 2][0] || *end || width > sizeof magnitude) return 2;
      widths[i] = (size_t)width;
    }
    memset(&issuer, 0, sizeof issuer); memset(&domain, 0, sizeof domain);
    issuer.algorithm = widths[2] ? TC_EAC_RSA_V15 : TC_EAC_ECDSA;
    issuer.has_domain = domain.has_domain = 1; domain.algorithm = TC_EAC_ECDSA;
    domain.p.data = magnitude; domain.p.length = widths[0];
    issuer.order.data = magnitude; issuer.order.length = widths[1];
    issuer.modulus.data = magnitude; issuer.modulus.length = widths[2];
    printf("context_encoding=%d\n", TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain));
  }
  saved = certificate;
  for (i = 0; i < length; ++i) {
    result = TC_EAC_CVC_read(data, i, &limits, &workspace, &certificate);
    if (result == TC_TLV_OK || memcmp(&certificate, &saved, sizeof certificate)) return 1;
  }
  return 0;
}
