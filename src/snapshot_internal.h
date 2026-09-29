/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_SNAPSHOT_INTERNAL_H_
#define TC_SNAPSHOT_INTERNAL_H_
#include <tiny_crypto/snapshot.h>
#include <tiny_crypto/tlv.h>
#include "internal.h"

/* Separation checks shared by the snapshot stores. Store and slot objects
 * must not overlap, so a state change through one pointer never rewrites
 * another. current is the store's published slot and may be NULL. */
static inline int tc_snapshot_publish_separate(const void* store, size_t store_size,
                                               const void* slot, size_t slot_size,
                                               const void* current, size_t current_size)
{
  return tc_internal_ranges_disjoint(store, store_size, slot, slot_size) &&
         (!current || (tc_internal_ranges_disjoint(current, current_size, store, store_size) &&
                       tc_internal_ranges_disjoint(current, current_size, slot, slot_size)));
}

/* current is the non-NULL published slot. out receives the acquired slot. */
static inline int tc_snapshot_acquire_separate(const void* store, size_t store_size,
                                               const void* current, size_t current_size,
                                               const void* out, size_t out_size)
{
  return tc_internal_ranges_disjoint(store, store_size, out, out_size) &&
         tc_internal_ranges_disjoint(current, current_size, out, out_size) &&
         tc_internal_ranges_disjoint(current, current_size, store, store_size);
}

/* Callers validate storage and domain-specific payloads before changing state.
 * Reclaim payloads after a successful transition to FREE. */
static inline TC_TLV_result tc_snapshot_prepare(TC_snapshot_state* state, size_t readers)
{
  if (*state != TC_SNAPSHOT_FREE || readers)
    return TC_TLV_LIMIT;
  *state = TC_SNAPSHOT_PREPARED;
  return TC_TLV_OK;
}

static inline TC_TLV_result tc_snapshot_discard(TC_snapshot_state* state, size_t readers)
{
  if (*state != TC_SNAPSHOT_PREPARED || readers)
    return TC_TLV_ARGUMENT;
  *state = TC_SNAPSHOT_FREE;
  return TC_TLV_OK;
}

/* A publish needs a prepared, unread slot and a current previous slot.
 * Callers with domain checks that must follow these run it first. */
static inline TC_TLV_result tc_snapshot_publish_check(TC_snapshot_state next, size_t readers,
                                                      const TC_snapshot_state* previous)
{
  if (next != TC_SNAPSHOT_PREPARED || readers || (previous && *previous != TC_SNAPSHOT_CURRENT))
    return TC_TLV_ARGUMENT;
  return TC_TLV_OK;
}

static inline TC_TLV_result tc_snapshot_publish(TC_snapshot_state* next, size_t readers,
                                                TC_snapshot_state* previous,
                                                size_t previous_readers, size_t expected,
                                                size_t* revision)
{
  const TC_TLV_result state = tc_snapshot_publish_check(*next, readers, previous);
  if (state != TC_TLV_OK)
    return state;
  if (expected != *revision)
    return TC_TLV_INVALID;
  if (*revision == SIZE_MAX)
    return TC_TLV_LIMIT;
  *next = TC_SNAPSHOT_CURRENT;
  ++*revision;
  if (previous)
    *previous = previous_readers ? TC_SNAPSHOT_RETIRED : TC_SNAPSHOT_FREE;
  return TC_TLV_OK;
}

static inline TC_TLV_result tc_snapshot_acquire(TC_snapshot_state state, size_t* readers)
{
  if (state != TC_SNAPSHOT_CURRENT)
    return TC_TLV_ARGUMENT;
  if (*readers == SIZE_MAX)
    return TC_TLV_LIMIT;
  ++*readers;
  return TC_TLV_OK;
}

static inline TC_TLV_result tc_snapshot_release(TC_snapshot_state* state, size_t* readers)
{
  if (!*readers || (*state != TC_SNAPSHOT_CURRENT && *state != TC_SNAPSHOT_RETIRED))
    return TC_TLV_ARGUMENT;
  --*readers;
  if (!*readers && *state == TC_SNAPSHOT_RETIRED)
    *state = TC_SNAPSHOT_FREE;
  return TC_TLV_OK;
}
#endif
