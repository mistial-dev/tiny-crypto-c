/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "card_config.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* SD 33 card 2: the RSA 3072 issuing CA signs the card certificates and the
 * CHUID signer, the ECC P-384 CA the secure messaging signer. Card 4 uses
 * the ECC P-256 CA for both. The digests pin the vendored files. */
static const tc_piv_card_identity identities[] = {
    {"sd33-card2",
     "sd33_card2",
     {"x509/ocsp/sd33/card01_issuer.der", "x509/ocsp/sd33/card04_issuer.der"},
     {"cf90296da018d851f11a634ddbd6dcdadeed9162cb3b5cfe32d348bba1e73a7b",
      "0bcc856374b0c0508da978cd6b88ccb3d4c0d3b06cb24f139502915a8cd6e9fb"},
     {"x509/crl/sd33/RSA3072IssuingCA.crl", "x509/crl/sd33/ECCP384IssuingCA.crl"},
     2,
     2},
    {"sd33-card4",
     "sd33_card4",
     {"x509/ocsp/sd33/card03_issuer.der", NULL},
     {"c6e30842c65233016a0d8ab8121a85d988a3372589bc473bab18109813bea9a1", NULL},
     {"x509/crl/sd33/ECCP256IssuingCA.crl", NULL},
     1,
     1}};

static TC_bytes secret(const char* name)
{
  const char* value = getenv(name);
  return value && *value ? (TC_bytes){(const uint8_t*)value, strlen(value)} : (TC_bytes){NULL, 0};
}

static int digits(TC_bytes value, size_t minimum, size_t maximum)
{
  if (!value.length)
    return 1;
  if (value.length < minimum || value.length > maximum)
    return 0;
  for (size_t i = 0; i < value.length; ++i)
    if (value.data[i] < '0' || value.data[i] > '9')
      return 0;
  return 1;
}

static int path_join(char* out, const char* directory, const char* name)
{
  const int length = snprintf(out, TC_PIV_CARD_PATH_BYTES, "%s/%s", directory, name);
  return length > 0 && (size_t)length < TC_PIV_CARD_PATH_BYTES;
}

static int name_order(const void* left, const void* right)
{
  return strcmp(left, right);
}

/* Every *.crl of directory, in name order. */
static int crl_directory(tc_piv_card_trust_paths* trust, const char* directory)
{
  char names[TC_PIV_CARD_TRUST_FILES][256];
  size_t count = 0;
  DIR* listing = opendir(directory);
  if (!listing)
    return 0;
  int ok = 1;
  for (const struct dirent* entry = readdir(listing); entry && ok; entry = readdir(listing)) {
    const size_t length = strlen(entry->d_name);
    if (length < 5 || strcmp(entry->d_name + length - 4, ".crl"))
      continue;
    ok = count < TC_PIV_CARD_TRUST_FILES && length < sizeof names[0];
    if (ok)
      memcpy(names[count++], entry->d_name, length + 1);
  }
  ok = !closedir(listing) && ok;
  qsort(names, count, sizeof names[0], name_order);
  trust->crl_count = 0;
  for (size_t i = 0; ok && i < count; ++i)
    ok = path_join(trust->crls[trust->crl_count++], directory, names[i]);
  return ok;
}

static const char* trust_read(tc_piv_card_config* out, const char* vector_dir)
{
  const tc_piv_card_identity* defaults = out->expect ? out->expect : &identities[0];
  tc_piv_card_trust_paths* trust = &out->trust;
  for (size_t i = 0; i < defaults->anchor_count; ++i) {
    if (!path_join(trust->anchors[i], vector_dir, defaults->anchors[i]))
      return "TC_PIV_CARD_EXPECT";
    trust->anchor_sha256[i] = defaults->anchor_sha256[i];
  }
  trust->anchor_count = defaults->anchor_count;
  const char* root = getenv("TC_PIV_CARD_ROOT");
  const char* root_sha256 = getenv("TC_PIV_CARD_ROOT_SHA256");
  if (root && *root) {
    if (!root_sha256 || strlen(root_sha256) != 64 || strlen(root) >= TC_PIV_CARD_PATH_BYTES)
      return "TC_PIV_CARD_ROOT_SHA256";
    memcpy(trust->anchors[trust->anchor_count], root, strlen(root) + 1);
    trust->anchor_sha256[trust->anchor_count++] = root_sha256;
  } else if (root_sha256) {
    return "TC_PIV_CARD_ROOT";
  }
  const char* crl_dir = getenv("TC_PIV_CARD_CRL_DIR");
  if (crl_dir && *crl_dir)
    return crl_directory(trust, crl_dir) ? NULL : "TC_PIV_CARD_CRL_DIR";
  for (size_t i = 0; i < defaults->crl_count; ++i)
    if (!path_join(trust->crls[i], vector_dir, defaults->crls[i]))
      return "TC_PIV_CARD_EXPECT";
  trust->crl_count = defaults->crl_count;
  return NULL;
}

const char* tc_piv_card_config_read(tc_piv_card_config* out, const char* vector_dir)
{
  memset(out, 0, sizeof *out);
  out->reader = getenv("TC_PIV_CARD_READER");
  const char* interface = getenv("TC_PIV_CARD_INTERFACE");
  if (interface && !strcmp(interface, "contact"))
    out->interface = TC_PIV_CARD_CONTACT;
  else if (interface && !strcmp(interface, "contactless"))
    out->interface = TC_PIV_CARD_CONTACTLESS;
  else if (interface && *interface)
    return "TC_PIV_CARD_INTERFACE";
  out->pin = secret("TC_PIV_PIN");
  out->pairing_code = secret("TC_PIV_PAIRING_CODE");
  if (!digits(out->pin, 6, 8))
    return "TC_PIV_PIN";
  if (!digits(out->pairing_code, 8, 8))
    return "TC_PIV_PAIRING_CODE";
  out->minimum_retries = 3;
  const char* retries = getenv("TC_PIV_CARD_MIN_RETRIES");
  if (retries && *retries) {
    char* end;
    const unsigned long value = strtoul(retries, &end, 10);
    if (*end || value < 2 || value > 15)
      return "TC_PIV_CARD_MIN_RETRIES";
    out->minimum_retries = (unsigned)value;
  }
  const char* expect = getenv("TC_PIV_CARD_EXPECT");
  if (expect && *expect) {
    for (size_t i = 0; i < sizeof identities / sizeof *identities; ++i)
      if (!strcmp(expect, identities[i].name))
        out->expect = &identities[i];
    if (!out->expect)
      return "TC_PIV_CARD_EXPECT";
  }
  const char* revocation = getenv("TC_PIV_CARD_REVOCATION");
  out->revocation = TC_VALIDATION_REVOCATION_WHEN_AVAILABLE;
  if (revocation && !strcmp(revocation, "required"))
    out->revocation = TC_VALIDATION_REVOCATION_REQUIRED;
  else if (revocation && *revocation && strcmp(revocation, "when-available"))
    return "TC_PIV_CARD_REVOCATION";
  const char* extended = getenv("TC_PIV_CARD_EXTENDED");
  out->extended = extended && !strcmp(extended, "1");
  out->dump_dir = getenv("TC_PIV_CARD_DUMP_DIR");
  if (out->dump_dir && *out->dump_dir && !tc_piv_card_private_directory(out->dump_dir))
    return "TC_PIV_CARD_DUMP_DIR";
  if (out->dump_dir && !*out->dump_dir)
    out->dump_dir = NULL;
  return trust_read(out, vector_dir);
}

int tc_piv_card_private_directory(const char* path)
{
  struct stat info;
  return !stat(path, &info) && S_ISDIR(info.st_mode) && !(info.st_mode & 077) &&
         info.st_uid == geteuid();
}
