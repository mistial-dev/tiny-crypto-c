/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static void field(const char* name, TC_bytes value)
{
  size_t i;
  printf("%s=", name);
  for (i = 0; i < value.length; ++i) printf("%02x", value.data[i]);
  putchar('\n');
}

int main(int argc, char** argv)
{
  uint8_t bytes[65536];
  TC_TLV_frame frames[32];
  TC_bytes oids[256];
  TC_X509_workspace workspace = {frames,32,oids,256};
  TC_TLV_limits limits = {sizeof bytes, sizeof bytes, 8192, 32};
  TC_X509_certificate certificate, saved;
  TC_TLV_result result;
  FILE* file;
  size_t length;
  if (argc != 2 && argc != 6) return 2;
  if (argc == 6) {
    unsigned long values[4];
    int i;
    for (i = 0; i < 4; ++i) {
      char* end;
      values[i] = strtoul(argv[i + 2], &end, 10);
      if (!argv[i + 2][0] || *end || values[i] > sizeof bytes) return 2;
    }
    if (values[2] > 32 || values[3] > 256) return 2;
    limits.max_input = (size_t)values[0];
    limits.max_elements = (size_t)values[1];
    workspace.frame_capacity = (size_t)values[2];
    workspace.extension_capacity = (size_t)values[3];
    if (!workspace.frame_capacity) workspace.frames = NULL;
    if (!workspace.extension_capacity) workspace.extension_oids = NULL;
  }
  file = strcmp(argv[1], "-") == 0 ? stdin : fopen(argv[1], "rb");
  if (!file) return 2;
#ifdef _WIN32
  if (file == stdin && _setmode(_fileno(stdin), _O_BINARY) == -1) return 2;
#endif
  length = fread(bytes, 1, sizeof bytes, file);
  if (ferror(file) || !feof(file)) { fclose(file); return 2; }
  fclose(file);
  memset(&certificate, 0xa5, sizeof certificate); saved = certificate;
  result = TC_X509_read(bytes, length, &limits, &workspace, &certificate);
  printf("result=%d\n", result);
  if (result != TC_TLV_OK) return memcmp(&certificate, &saved, sizeof certificate) ? 1 : 0;
  printf("version=%u\n", certificate.version);
  printf("not_before=%04u%02u%02u%02u%02u%02uZ\n", certificate.not_before.year,
    certificate.not_before.month, certificate.not_before.day, certificate.not_before.hour,
    certificate.not_before.minute, certificate.not_before.second);
  field("serial", certificate.serial);
  field("key_oid", certificate.public_key.algorithm.oid);
  printf("key_type=%u\nkey_bits=%u\ncurve=%u\n", (unsigned)certificate.public_key.type,
    certificate.public_key.bits, (unsigned)certificate.public_key.curve);
  field("key", certificate.public_key.key);
  field("signature_oid", certificate.signature_algorithm.oid);
  return 0;
}
