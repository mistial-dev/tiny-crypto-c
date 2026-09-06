/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * Opt-in NIST CAVP KBKDFVS (SP 800-108) response-file validation.
 *
 * Runs the six files under tests/vectors/kdf/cavp/ (see its README.md). The
 * AES key size is fixed per build, so each binary runs the CMAC_AES section
 * matching TC_AES_KEY_BITS; the 128-bit binary also runs every non-AES PRF.
 * Each file asserts the exact number of vectors run and skipped.
 *
 * Test-only translation unit; never linked into the library. Enable with
 * TC_KDF_CAVP=1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tiny_crypto/kdf.h>
#include "cavp.h"
#include "munit.h"
#include "test_io.h"

#ifndef KDF_CAVP_DIR
#define KDF_CAVP_DIR "tests/vectors/kdf/cavp"
#endif

#if defined(TC_KDF_CAVP) && (TC_KDF_CAVP == 1) && TC_ENABLE_KDF

typedef TC_status (*kdf_counter_fn)(const uint8_t*, size_t, const struct TC_KBKDF_params*,
                                    const uint8_t*, size_t, const uint8_t*, size_t,
                                    uint8_t*, size_t);
typedef TC_status (*kdf_feedback_fn)(const uint8_t*, size_t, const struct TC_KBKDF_params*,
                                     const uint8_t*, size_t, const uint8_t*, size_t,
                                     uint8_t*, size_t);
typedef TC_status (*kdf_pipeline_fn)(const uint8_t*, size_t, const struct TC_KBKDF_params*,
                                     const uint8_t*, size_t, uint8_t*, size_t);

struct kdf_cavp_prf
{
  const char* name;
  size_t h;
  kdf_counter_fn counter;
  kdf_feedback_fn feedback;
  kdf_pipeline_fn pipeline;
  int aes_bits; /* 0 for non-AES PRFs */
};

static const struct kdf_cavp_prf kdf_cavp_prfs[] = {
#if TC_KBKDF_HAVE_HMAC_SHA1
  { "HMAC_SHA1", TC_SHA1_DIGESTLEN, TC_KBKDF_HMAC_SHA1_counter,
    TC_KBKDF_HMAC_SHA1_feedback, TC_KBKDF_HMAC_SHA1_pipeline, 0 },
#endif
#if TC_KBKDF_HAVE_HMAC_SHA224
  { "HMAC_SHA224", TC_SHA224_DIGESTLEN, TC_KBKDF_HMAC_SHA224_counter,
    TC_KBKDF_HMAC_SHA224_feedback, TC_KBKDF_HMAC_SHA224_pipeline, 0 },
#endif
#if TC_KBKDF_HAVE_HMAC_SHA256
  { "HMAC_SHA256", TC_SHA256_DIGESTLEN, TC_KBKDF_HMAC_SHA256_counter,
    TC_KBKDF_HMAC_SHA256_feedback, TC_KBKDF_HMAC_SHA256_pipeline, 0 },
#endif
#if TC_KBKDF_HAVE_HMAC_SHA384
  { "HMAC_SHA384", TC_SHA384_DIGESTLEN, TC_KBKDF_HMAC_SHA384_counter,
    TC_KBKDF_HMAC_SHA384_feedback, TC_KBKDF_HMAC_SHA384_pipeline, 0 },
#endif
#if TC_KBKDF_HAVE_HMAC_SHA512
  { "HMAC_SHA512", TC_SHA512_DIGESTLEN, TC_KBKDF_HMAC_SHA512_counter,
    TC_KBKDF_HMAC_SHA512_feedback, TC_KBKDF_HMAC_SHA512_pipeline, 0 },
#endif
#if TC_KBKDF_HAVE_AES_CMAC
  { "CMAC_AES128", TC_AES_CMAC_TAG_MAX, TC_KBKDF_AES_CMAC_counter,
    TC_KBKDF_AES_CMAC_feedback, TC_KBKDF_AES_CMAC_pipeline, 128 },
  { "CMAC_AES192", TC_AES_CMAC_TAG_MAX, TC_KBKDF_AES_CMAC_counter,
    TC_KBKDF_AES_CMAC_feedback, TC_KBKDF_AES_CMAC_pipeline, 192 },
  { "CMAC_AES256", TC_AES_CMAC_TAG_MAX, TC_KBKDF_AES_CMAC_counter,
    TC_KBKDF_AES_CMAC_feedback, TC_KBKDF_AES_CMAC_pipeline, 256 },
#endif
#if TC_KBKDF_HAVE_DES_CMAC
  { "CMAC_TDES2", TC_DES_CMAC_TAG_MAX, TC_KBKDF_DES_CMAC_counter,
    TC_KBKDF_DES_CMAC_feedback, TC_KBKDF_DES_CMAC_pipeline, 0 },
  { "CMAC_TDES3", TC_DES_CMAC_TAG_MAX, TC_KBKDF_DES_CMAC_counter,
    TC_KBKDF_DES_CMAC_feedback, TC_KBKDF_DES_CMAC_pipeline, 0 },
#endif
  { NULL, 0, NULL, NULL, NULL, 0 }
};

/* PRF sections this binary runs: 480 (or 40) vectors each. */
#define KDF_CAVP_NON_AES_PRFS \
  (TC_KBKDF_HAVE_HMAC_SHA1 + TC_KBKDF_HAVE_HMAC_SHA224 + TC_KBKDF_HAVE_HMAC_SHA256 + \
   TC_KBKDF_HAVE_HMAC_SHA384 + TC_KBKDF_HAVE_HMAC_SHA512 + 2 * TC_KBKDF_HAVE_DES_CMAC)
#if TC_AES_KEY_BITS == 128
#define KDF_CAVP_ACTIVE_PRFS (KDF_CAVP_NON_AES_PRFS + TC_KBKDF_HAVE_AES_CMAC)
#else
#define KDF_CAVP_ACTIVE_PRFS (TC_KBKDF_HAVE_AES_CMAC)
#endif

/* A PRF section is active when compiled in and, for AES, matching this build. */
static const struct kdf_cavp_prf* kdf_cavp_lookup(const char* name)
{
  const struct kdf_cavp_prf* p;
  for (p = kdf_cavp_prfs; p->name != NULL; ++p)
  {
    if (strcmp(p->name, name) != 0)
      continue;
    if (p->aes_bits == 0)
      return (TC_AES_KEY_BITS == 128) ? p : NULL;
    return (p->aes_bits == TC_AES_KEY_BITS) ? p : NULL;
  }
  return NULL;
}

#define KDF_CAVP_MODE_COUNTER  0
#define KDF_CAVP_MODE_FEEDBACK 1
#define KDF_CAVP_MODE_PIPELINE 2

/* Field maxima in the corpus: KI/IV <= 64, fixed <= 60, KO <= 300 bytes. */
struct kdf_cavp_record
{
  uint8_t ki[64];   long ki_len;
  uint8_t iv[64];   long iv_len;   long iv_bits;
  uint8_t fixed[64]; long fixed_len; long fixed_bytes;
  uint8_t before[64]; long before_len; long before_bytes;
  uint8_t after[64];  long after_len;  long after_bytes;
  long l_bits;
  long count;
};

/* "[NAME=VALUE]" header: copies VALUE (without the bracket) into out. */
static int cavp_header(const char* line, const char* name, char* out, size_t out_len)
{
  size_t n = strlen(name);
  const char* end;
  size_t len;
  if (line[0] != '[' || strncmp(line + 1, name, n) != 0 || line[1 + n] != '=')
    return 0;
  line += 2 + n;
  end = strchr(line, ']');
  if (end == NULL)
    return 0;
  len = (size_t)(end - line);
  if (len + 1 > out_len)
    return 0;
  memcpy(out, line, len);
  out[len] = '\0';
  return 1;
}

static FILE* cavp_open(const char* relative)
{
  char path[512];
  FILE* file;
  snprintf(path, sizeof(path), "%s/%s", KDF_CAVP_DIR, relative);
  file = tc_test_fopen(path, "r");
  if (file == NULL)
    munit_errorf("cannot open CAVP file %s", path);
  return file;
}

struct kdf_cavp_stats
{
  long total;
  long ran;
  long empty_iv;
};

static void cavp_run_file(const char* relative, int mode, int has_counter,
                          struct kdf_cavp_stats* stats)
{
  FILE* file = cavp_open(relative);
  static char line[1024];
  char value[32];
  const struct kdf_cavp_prf* prf = NULL;
  int active = 0;
  char location[16] = "";
  long rlen = 0;
  struct kdf_cavp_record rec;
  uint8_t ko[320];
  uint8_t actual[320];

  memset(stats, 0, sizeof(*stats));
  memset(&rec, 0, sizeof(rec));

  while (fgets(line, sizeof(line), file) != NULL)
  {
    const char* v;

    if (line[0] == '#' || line[0] == '\r' || line[0] == '\n')
      continue;
    if (cavp_header(line, "PRF", value, sizeof(value)))
    {
      prf = kdf_cavp_lookup(value);
      active = (prf != NULL);
      continue;
    }
    if (cavp_header(line, "CTRLOCATION", location, sizeof(location)))
      continue;
    if (cavp_header(line, "RLEN", value, sizeof(value)))
    {
      rlen = strtol(value, NULL, 10);
      continue;
    }
    if (line[0] == '[')
      munit_errorf("%s: unknown section header %s", relative, line);

    if ((v = tc_cavp_field_value(line, "COUNT")) != NULL)
    {
      memset(&rec, 0, sizeof(rec));
      rec.ki_len = rec.iv_len = rec.fixed_len = rec.before_len = rec.after_len = -1;
      rec.iv_bits = rec.fixed_bytes = rec.before_bytes = rec.after_bytes = -1;
      rec.count = strtol(v, NULL, 10);
      stats->total++;
      continue;
    }
    if ((v = tc_cavp_field_value(line, "L")) != NULL)
      rec.l_bits = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(line, "KI")) != NULL)
      rec.ki_len = tc_cavp_parse_hex(v, rec.ki, sizeof(rec.ki));
    else if ((v = tc_cavp_field_value(line, "IVlen")) != NULL)
      rec.iv_bits = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(line, "IV")) != NULL)
      rec.iv_len = tc_cavp_parse_hex(v, rec.iv, sizeof(rec.iv));
    else if ((v = tc_cavp_field_value(line, "FixedInputDataByteLen")) != NULL)
      rec.fixed_bytes = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(line, "FixedInputData")) != NULL)
      rec.fixed_len = tc_cavp_parse_hex(v, rec.fixed, sizeof(rec.fixed));
    else if ((v = tc_cavp_field_value(line, "DataBeforeCtrLen")) != NULL)
      rec.before_bytes = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(line, "DataBeforeCtrData")) != NULL)
      rec.before_len = tc_cavp_parse_hex(v, rec.before, sizeof(rec.before));
    else if ((v = tc_cavp_field_value(line, "DataAfterCtrLen")) != NULL)
      rec.after_bytes = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(line, "DataAfterCtrData")) != NULL)
      rec.after_len = tc_cavp_parse_hex(v, rec.after, sizeof(rec.after));
    else if ((v = tc_cavp_field_value(line, "KO")) != NULL)
    {
      long ko_len = tc_cavp_parse_hex(v, ko, sizeof(ko));
      struct TC_KBKDF_params p;
      TC_status rc;

      munit_assert_long(rec.l_bits % 8, ==, 0);
      munit_assert_long(ko_len, ==, rec.l_bits / 8);
      munit_assert_long(rec.ki_len, >, 0);
      if (rec.iv_bits >= 0)
        munit_assert_long(rec.iv_len, ==, rec.iv_bits / 8);
      if (rec.fixed_bytes >= 0)
        munit_assert_long(rec.fixed_len, ==, rec.fixed_bytes);
      if (rec.before_bytes >= 0)
        munit_assert_long(rec.before_len, ==, rec.before_bytes);
      if (rec.after_bytes >= 0)
        munit_assert_long(rec.after_len, ==, rec.after_bytes);

      if (!active)
        continue;

      if (rec.iv_bits == 0)
        stats->empty_iv++;

      p.counter_bits = (uint8_t)rlen;
      p.counter_location = 0;
      p.use_counter = (uint8_t)has_counter;

      if (mode == KDF_CAVP_MODE_COUNTER)
      {
        const uint8_t* before = NULL;
        const uint8_t* after = NULL;
        size_t before_len = 0, after_len = 0;
        if (strcmp(location, "BEFORE_FIXED") == 0)
        {
          after = rec.fixed;
          after_len = (size_t)rec.fixed_len;
        }
        else if (strcmp(location, "AFTER_FIXED") == 0)
        {
          before = rec.fixed;
          before_len = (size_t)rec.fixed_len;
        }
        else if (strcmp(location, "MIDDLE_FIXED") == 0)
        {
          before = rec.before;
          before_len = (size_t)rec.before_len;
          after = rec.after;
          after_len = (size_t)rec.after_len;
        }
        else
          munit_errorf("%s: unknown CTRLOCATION %s", relative, location);
        rc = prf->counter(rec.ki, (size_t)rec.ki_len, &p, before, before_len,
                          after, after_len, actual, (size_t)ko_len);
      }
      else
      {
        if (has_counter)
        {
          if (strcmp(location, "BEFORE_ITER") == 0)
            p.counter_location = TC_KBKDF_CTR_BEFORE_ITER;
          else if (strcmp(location, "AFTER_ITER") == 0)
            p.counter_location = TC_KBKDF_CTR_AFTER_ITER;
          else if (strcmp(location, "AFTER_FIXED") == 0)
            p.counter_location = TC_KBKDF_CTR_AFTER_FIXED;
          else
            munit_errorf("%s: unknown CTRLOCATION %s", relative, location);
        }
        if (mode == KDF_CAVP_MODE_FEEDBACK)
          rc = prf->feedback(rec.ki, (size_t)rec.ki_len, &p, rec.iv, (size_t)rec.iv_len,
                             rec.fixed, (size_t)rec.fixed_len, actual, (size_t)ko_len);
        else
          rc = prf->pipeline(rec.ki, (size_t)rec.ki_len, &p,
                             rec.fixed, (size_t)rec.fixed_len, actual, (size_t)ko_len);
      }

      if (rc != TC_OK)
        munit_errorf("%s [PRF=%s][CTRLOCATION=%s][RLEN=%ld] COUNT=%ld: derivation failed",
                     relative, prf->name, location, rlen, rec.count);
      if (memcmp(actual, ko, (size_t)ko_len) != 0)
      {
        fprintf(stderr, "KBKDF CAVP mismatch in %s [PRF=%s][CTRLOCATION=%s][RLEN=%ld] COUNT=%ld\n",
                relative, prf->name, location, rlen, rec.count);
        tc_cavp_print_bytes("expected", ko, (size_t)ko_len);
        tc_cavp_print_bytes("actual  ", actual, (size_t)ko_len);
        munit_error("KBKDF CAVP test failed");
      }
      stats->ran++;
    }
  }
  fclose(file);
}

static void cavp_check_counts(const struct kdf_cavp_stats* stats, long total, long per_prf)
{
  munit_assert_long(stats->total, ==, total);
  munit_assert_long(stats->ran, ==, per_prf * KDF_CAVP_ACTIVE_PRFS);
}

MunitResult test_kbkdf_cavp_counter(const MunitParameter params[], void* data)
{
  struct kdf_cavp_stats stats;
  (void) params;
  (void) data;

  cavp_run_file("KDFCTR_gen.rsp", KDF_CAVP_MODE_COUNTER, 1, &stats);
  cavp_check_counts(&stats, 4800, 480);
  return MUNIT_OK;
}

MunitResult test_kbkdf_cavp_feedback(const MunitParameter params[], void* data)
{
  struct kdf_cavp_stats stats;
  (void) params;
  (void) data;

  cavp_run_file("KDFFeedbackWithZeroIV_gen.rsp", KDF_CAVP_MODE_FEEDBACK, 1, &stats);
  cavp_check_counts(&stats, 4800, 480);
  if (stats.ran != 0)
    munit_assert_long(stats.empty_iv, >, 0); /* the zero-length IV path was exercised */

  cavp_run_file("KDFFeedbackNoZeroIV_gen.rsp", KDF_CAVP_MODE_FEEDBACK, 1, &stats);
  cavp_check_counts(&stats, 4800, 480);
  munit_assert_long(stats.empty_iv, ==, 0);

  cavp_run_file("KDFFeedbackNoCtr_gen.rsp", KDF_CAVP_MODE_FEEDBACK, 0, &stats);
  cavp_check_counts(&stats, 400, 40);
  return MUNIT_OK;
}

MunitResult test_kbkdf_cavp_pipeline(const MunitParameter params[], void* data)
{
  struct kdf_cavp_stats stats;
  (void) params;
  (void) data;

  cavp_run_file("KDFDblPipelineWithCtr_gen.rsp", KDF_CAVP_MODE_PIPELINE, 1, &stats);
  cavp_check_counts(&stats, 4800, 480);

  cavp_run_file("KDFDblPipelineWOCtr_gen.rsp", KDF_CAVP_MODE_PIPELINE, 0, &stats);
  cavp_check_counts(&stats, 400, 40);
  return MUNIT_OK;
}

#else /* !TC_KDF_CAVP */

MunitResult test_kbkdf_cavp_counter(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_kbkdf_cavp_feedback(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_kbkdf_cavp_pipeline(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }

#endif /* TC_KDF_CAVP */
