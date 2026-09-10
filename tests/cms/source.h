/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TEST_CMS_SOURCE_H_
#define TEST_CMS_SOURCE_H_
#include <tiny_crypto/x509_store.h>
typedef struct {
  const TC_bytes* records;
  size_t count, calls;
  TC_TLV_result status;
  int increase_work;
} candidate_source;

static inline TC_TLV_result read_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  candidate_source* source = context;
  ++source->calls;
  if (source->increase_work) ++*work;
  if (source->status != TC_TLV_OK) return source->status;
  if (index >= source->count) return TC_TLV_ARGUMENT;
  *out = source->records[index];
  return TC_TLV_OK;
}
#endif
