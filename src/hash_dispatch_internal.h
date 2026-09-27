/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_HASH_DISPATCH_INTERNAL_H_
#define TC_HASH_DISPATCH_INTERNAL_H_
#include "hash_info_internal.h"
#include "hash_adapter_internal.h"

static inline int tc_hash_available(TC_hash_algorithm algorithm)
{
#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || TC_ENABLE_SHA384 || TC_ENABLE_SHA512
  return tc_hash_adapter_get(algorithm, NULL);
#else
  (void)algorithm;
  return 0;
#endif
}

typedef enum { TC_HASH_INIT, TC_HASH_UPDATE, TC_HASH_FINAL } tc_hash_operation;

/* Shared dispatch for contiguous, segmented and parser-fed messages. */
static inline TC_status tc_hash_process(TC_hash_algorithm algorithm,
    tc_hash_workspace* workspace, tc_hash_operation operation, TC_bytes bytes, uint8_t* digest)
{
#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || TC_ENABLE_SHA384 || TC_ENABLE_SHA512
  tc_hash_adapter adapter;
  void* ctx;
  if (!tc_hash_adapter_get(algorithm, &adapter) || !workspace ||
      (operation == TC_HASH_UPDATE && bytes.length && !bytes.data) ||
      (operation == TC_HASH_FINAL && !digest)) return TC_ERROR;
  ctx = adapter.workspace_context(workspace);
  switch (operation) {
    case TC_HASH_INIT: return adapter.hash_init(ctx);
    case TC_HASH_UPDATE: return adapter.hash_update(ctx, bytes.data, bytes.length);
    case TC_HASH_FINAL: return adapter.hash_final(ctx, digest);
    default: return TC_ERROR;
  }
#else
  (void)algorithm;
  (void)workspace;
  (void)operation;
  (void)bytes;
  (void)digest;
  return TC_ERROR;
#endif
}

/* Keep the algorithm fixed between init and final. Scratch and input/output
 * storage are disjoint. Callers wipe scratch when a stream is abandoned. */
static inline TC_status tc_hash_init(TC_hash_algorithm algorithm, tc_hash_workspace* workspace)
{
  const TC_bytes empty = {NULL,0};
  return tc_hash_process(algorithm,workspace,TC_HASH_INIT,empty,NULL);
}

static inline TC_status tc_hash_update(TC_hash_algorithm algorithm,
    tc_hash_workspace* workspace, TC_bytes bytes)
{
  return tc_hash_process(algorithm,workspace,TC_HASH_UPDATE,bytes,NULL);
}

static inline TC_status tc_hash_final(TC_hash_algorithm algorithm,
    tc_hash_workspace* workspace, uint8_t* digest)
{
  const TC_bytes empty = {NULL,0};
  TC_status status = tc_hash_process(algorithm,workspace,TC_HASH_FINAL,empty,digest);
  if (workspace) TC_secure_zero(workspace,sizeof *workspace);
  return status;
}

/* Hash borrowed parts in order. Caller bounds count/lengths and validates ranges.
 * Workspace, digest and input storage are disjoint. Digest has the selected
 * hash's full output size. No output is written before all updates succeed. */
static inline TC_status tc_hash_digest_parts(TC_hash_algorithm algorithm,
    const TC_bytes* parts, size_t count, uint8_t* digest, tc_hash_workspace* workspace)
{
  TC_status status;
  if (!workspace || !digest || (count && !parts) || !tc_hash_available(algorithm)) return TC_ERROR;
  for (size_t i = 0; i < count; ++i) if (parts[i].length && !parts[i].data) return TC_ERROR;
  status = tc_hash_init(algorithm,workspace);
  for (size_t i = 0; status == TC_OK && i < count; ++i)
    status = tc_hash_update(algorithm,workspace,parts[i]);
  if (status == TC_OK) return tc_hash_final(algorithm,workspace,digest);
  TC_secure_zero(workspace,sizeof *workspace);
  return status;
}
#endif
