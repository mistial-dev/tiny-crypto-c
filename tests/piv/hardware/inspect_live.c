/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * test_piv_inspect_live: examples/piv_inspect on the live card in a fresh
 * connection, with the hardware guard installed through the example's
 * TC_PIV_HARDWARE_GUARD hook. The environment is that of piv_card.c
 * (card_config.h). The guard allows one PIN submission and one pairing
 * code, both only for a card that matches TC_PIV_CARD_EXPECT, and no 9C.
 * Without TC_PIV_CARD_EXPECT the example runs with neither. Exit status 0
 * or 1 of the example passes. CTest fails the run on a printed FAILED
 * check. */
#include "../../../examples/credential_pcsc.h"
#include "card_config.h"
#include "card_fixture.h"
#include "guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TC_VECTOR_DIR
#error "TC_VECTOR_DIR must name tests/vectors"
#endif
#ifndef TC_CARD_FIXTURE_DIR
#error "TC_CARD_FIXTURE_DIR must name the capture fixture directory"
#endif

#define SKIP_STATUS 77

/* examples/piv_inspect_main.c, built with main renamed. */
int example_piv_inspect_main(int argc, char** argv);

static tc_piv_card_config config;
static tc_card_fixture expected;
static tc_piv_guard guard;
static ExampleCardPCSCGuard hook;

const ExampleCardPCSCGuard* example_piv_inspect_guard(void)
{
  return hook.check ? &hook : NULL;
}

static const char* guard_start(void)
{
  tc_piv_guard_policy policy;
  memset(&policy, 0, sizeof policy);
  policy.minimum_retries = config.minimum_retries;
  if (config.expect) {
    char path[512];
    if (snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, config.expect->fixture) <=
            0 ||
        tc_card_fixture_load(&expected, path))
      return "unable to load the expected card fixture";
    const tc_card_object* chuid = tc_card_fixture_object(&expected, 0x5fc102);
    const tc_card_object* certificate = tc_card_fixture_object(&expected, 0x5fc101);
    if (!chuid || !certificate)
      return "the expected card fixture lacks the CHUID or 5FC101";
    policy.identity[TC_PIV_GUARD_CHUID] = chuid->data;
    policy.identity[TC_PIV_GUARD_CARD_CERTIFICATE] = certificate->data;
    policy.pin_submissions = config.pin.length ? 1 : 0;
    policy.pairing_submissions = config.pairing_code.length ? 1 : 0;
  } else if (unsetenv("TC_PIV_PIN") || unsetenv("TC_PIV_PAIRING_CODE")) {
    return "unable to clear the PIN variables";
  }
  if (!tc_piv_guard_init(&guard, &policy))
    return "invalid guard policy";
  hook = (ExampleCardPCSCGuard){tc_piv_guard_check, tc_piv_guard_observe, &guard,
                                tc_piv_guard_connected};
  return NULL;
}

int main(void)
{
  enum { ARGUMENTS = 48 };
  static char minimum[8];
  static char* arguments[ARGUMENTS];
  const char* malformed = tc_piv_card_config_read(&config, TC_VECTOR_DIR);
  if (malformed) {
    fprintf(stderr, "inspect_live: %s is malformed\n", malformed);
    return EXIT_FAILURE;
  }
  if (!config.reader || !*config.reader) {
    fputs("inspect_live: skipped, TC_PIV_CARD_READER is unset\n", stderr);
    return SKIP_STATUS;
  }
  const char* failure = guard_start();
  if (failure || setenv("TC_PIV_HARDWARE_GUARD", "1", 1)) {
    fprintf(stderr, "inspect_live: %s\n", failure ? failure : "unable to set the guard variable");
    return EXIT_FAILURE;
  }
  int count = 0;
  arguments[count++] = (char*)"piv_inspect";
  arguments[count++] = (char*)"--reader";
  arguments[count++] = (char*)config.reader;
  if (config.interface != TC_PIV_CARD_DETECT) {
    arguments[count++] = (char*)"--interface";
    arguments[count++] =
        (char*)(config.interface == TC_PIV_CARD_CONTACT ? "contact" : "contactless");
  }
  if (config.extended)
    arguments[count++] = (char*)"--extended";
  arguments[count++] = (char*)"--revocation";
  arguments[count++] =
      (char*)(config.revocation == TC_VALIDATION_REVOCATION_REQUIRED ? "required"
                                                                     : "when-available");
  snprintf(minimum, sizeof minimum, "%u", config.minimum_retries);
  arguments[count++] = (char*)"--min-retries";
  arguments[count++] = minimum;
  for (size_t i = 0; i < config.trust.anchor_count; ++i) {
    arguments[count++] = (char*)"--anchor";
    arguments[count++] = config.trust.anchors[i];
    arguments[count++] = (char*)"--anchor-sha256";
    arguments[count++] = (char*)config.trust.anchor_sha256[i];
  }
  for (size_t i = 0; i < config.trust.crl_count; ++i) {
    arguments[count++] = (char*)"--crl";
    arguments[count++] = config.trust.crls[i];
  }
  if (config.dump_dir) {
    arguments[count++] = (char*)"--dump-dir";
    arguments[count++] = (char*)config.dump_dir;
  }
  arguments[count] = NULL;
  const int status = example_piv_inspect_main(count, arguments);
  fprintf(stderr, "inspect_live: exit status %d, %zu commands, %zu PIN submissions, %zu refused\n",
          status, guard.counts.exchanges, guard.counts.pin_submissions, guard.counts.refusals);
  if (guard.counts.refusals) {
    fprintf(stderr, "inspect_live: the guard refused %s\n", guard.counts.refusal);
    return EXIT_FAILURE;
  }
  return status == 0 || status == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
