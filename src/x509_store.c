/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#if TC_ENABLE_X509_PATH
#include <tiny_crypto/x509_store.h>
#include "pki_storage_internal.h"
#include "snapshot_internal.h"
#include <string.h>

static void recycle(TC_X509_store_snapshot* slot)
{
  memset(&slot->source, 0, sizeof slot->source);
  slot->state = TC_X509_SNAPSHOT_FREE;
}

static TC_TLV_result array_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  const TC_X509_store_array* array = (const TC_X509_store_array*)context;
  if (!array || !work || !out || index >= array->candidate_count ||
      !tc_pki_storage_separate(out, sizeof *out, &array->candidates[index],
                               sizeof array->candidates[index]))
    return TC_TLV_ARGUMENT;
  if (!*work)
    return TC_TLV_LIMIT;
  --*work;
  *out = array->candidates[index];
  return TC_TLV_OK;
}

static TC_TLV_result array_anchor(void* context, size_t index, size_t* work,
                                  TC_X509_store_anchor* out)
{
  const TC_X509_store_array* array = (const TC_X509_store_array*)context;
  if (!array || !work || !out || index >= array->anchor_count ||
      !tc_pki_storage_separate(out, sizeof *out, &array->anchors[index],
                               sizeof array->anchors[index]))
    return TC_TLV_ARGUMENT;
  if (!*work)
    return TC_TLV_LIMIT;
  --*work;
  *out = array->anchors[index];
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_store_array_source(const TC_X509_store_array* array,
                                         TC_X509_store_source* out)
{
  TC_X509_store_source source;
  if (!array || !out || (array->candidate_count && !array->candidates) ||
      (array->anchor_count && !array->anchors) ||
      !tc_pki_storage_separate(array, sizeof *array, out, sizeof *out))
    return TC_TLV_ARGUMENT;
  source.context = (void*)array;
  source.candidate_count = array->candidate_count;
  source.anchor_count = array->anchor_count;
  source.candidate = array_candidate;
  source.anchor = array_anchor;
  *out = source;
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_store_prepare(TC_X509_store_snapshot* slot,
                                    const TC_X509_store_source* source)
{
  if (!slot || !source || !tc_pki_storage_separate(slot, sizeof *slot, source, sizeof *source) ||
      (source->candidate_count && !source->candidate) || (source->anchor_count && !source->anchor))
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_snapshot_prepare(&slot->state, slot->readers);
  if (result != TC_TLV_OK)
    return result;
  slot->source = *source;
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_store_discard(TC_X509_store_snapshot* slot)
{
  if (!slot)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_snapshot_discard(&slot->state, slot->readers);
  if (result != TC_TLV_OK)
    return result;
  recycle(slot);
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_store_publish(TC_X509_store* store, size_t revision,
                                    TC_X509_store_snapshot* slot)
{
  TC_X509_store_snapshot* previous;
  if (!store || !slot || !tc_pki_storage_separate(store, sizeof *store, slot, sizeof *slot))
    return TC_TLV_ARGUMENT;
  previous = store->current;
  TC_TLV_result result =
      tc_snapshot_publish(&slot->state, slot->readers, previous ? &previous->state : NULL,
                          previous ? previous->readers : 0, revision, &store->revision);
  if (result != TC_TLV_OK)
    return result;
  store->current = slot;
  if (previous && previous->state == TC_SNAPSHOT_FREE)
    recycle(previous);
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_store_acquire(TC_X509_store* store, TC_X509_store_snapshot** out)
{
  TC_X509_store_snapshot* slot;
  if (!store || !out || !tc_pki_storage_separate(store, sizeof *store, out, sizeof *out))
    return TC_TLV_ARGUMENT;
  slot = store->current;
  if (!slot)
    return TC_TLV_END;
  if (!tc_pki_storage_separate(slot, sizeof *slot, out, sizeof *out))
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_snapshot_acquire(slot->state, &slot->readers);
  if (result != TC_TLV_OK)
    return result;
  *out = slot;
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_store_release(TC_X509_store_snapshot* slot)
{
  if (!slot)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_snapshot_release(&slot->state, &slot->readers);
  if (result != TC_TLV_OK)
    return result;
  if (slot->state == TC_SNAPSHOT_FREE)
    recycle(slot);
  return TC_TLV_OK;
}
#endif
