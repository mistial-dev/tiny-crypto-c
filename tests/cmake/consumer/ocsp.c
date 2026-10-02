/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "x509_ocsp.h"
#include <stdio.h>
#include <string.h>
#include <tiny_crypto/x509_crypto.h>

enum { FIXTURE_CAPACITY = 1024 };

/* Read one fixture from OCSP_FIXTURE_DIR. Returns 0 on failure. */
static size_t read_fixture(const char* name, uint8_t bytes[FIXTURE_CAPACITY])
{
  char path[512];
  if (snprintf(path, sizeof path, "%s/%s", OCSP_FIXTURE_DIR, name) >= (int)sizeof path)
    return 0;
  FILE* file = fopen(path, "rb");
  if (!file)
    return 0;
  const size_t length = fread(bytes, 1, FIXTURE_CAPACITY, file);
  const int complete = !ferror(file) && feof(file);
  return fclose(file) == 0 && complete ? length : 0;
}

/* The locally generated P-256 fixtures: a CA-signed REVOKED response with
 * reason keyCompromise, checked with the installed example and provider. */
int main(void)
{
  static ExampleX509Workspace storage;
  static uint8_t ca[FIXTURE_CAPACITY], target[FIXTURE_CAPACITY], response[FIXTURE_CAPACITY];
  const size_t ca_length = read_fixture("ca.der", ca);
  const size_t target_length = read_fixture("target.der", target);
  const size_t response_length = read_fixture("revoked_key_compromise.der", response);
  if (!ca_length || !target_length || !response_length)
    return 1;

  const TC_TLV_limits limits = {FIXTURE_CAPACITY, FIXTURE_CAPACITY, 128, 16};
  const TC_X509_workspace parser = {{storage.frames, 16}, storage.oids, 16};
  TC_X509_certificate issuer;
  if (TC_X509_read((TC_bytes){ca, ca_length}, &limits, &parser, &issuer) != TC_TLV_OK)
    return 2;
  const TC_X509_trust_anchor anchor = {issuer.subject, issuer.public_key};

  static const uint8_t nonce[EXAMPLE_OCSP_NONCE_LENGTH] = {1};
  uint8_t encoded[EXAMPLE_OCSP_REQUEST_CAPACITY];
  size_t length = 0;
  if (example_ocsp_request((TC_bytes){target, target_length}, &anchor, nonce, &storage,
                           (TC_buffer){encoded, sizeof encoded}, &length) != TC_TLV_OK ||
      !length || memcmp(encoded + length - sizeof nonce, nonce, sizeof nonce))
    return 3;

  static TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {&ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider verifier = TC_X509_native_provider(&native);
  ExampleOcspCheck check = {
      {target, target_length}, &anchor,   {NULL, 0}, {response, response_length},
      {2026, 9, 30, 0, 0, 0},  &verifier, NULL};
  TC_X509_ocsp_report result;
  if (example_ocsp_check(&check, &storage, &result) != EXAMPLE_OCSP_REVOKED || !result.has_reason ||
      result.reason != 1)
    return 4;
  /* A changed signature byte leaves no authorized signer. */
  response[response_length - 1] ^= 1;
  if (example_ocsp_check(&check, &storage, &result) != EXAMPLE_OCSP_REJECTED ||
      result.status != TC_X509_REVOCATION_UNDETERMINED)
    return 5;
  return 0;
}
