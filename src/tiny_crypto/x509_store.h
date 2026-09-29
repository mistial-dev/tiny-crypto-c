/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Certificate store: published certificate sources, trust anchors with path
 * controls, snapshot lifetimes and anchors built from root certificates.
 * Standards: RFC 5914 section 2.5, RFC 5937.
 * Configuration: TC_ENABLE_X509_PATH.
 * Contracts: docs/api.md. Guide: docs/x509-store.md. */
#ifndef TINY_CRYPTO_X509_STORE_H_
#define TINY_CRYPTO_X509_STORE_H_
#include <tiny_crypto/x509.h>
#include <tiny_crypto/snapshot.h>
#ifdef __cplusplus
extern "C" {
#endif

/* replaced_controls bits. Each marks a TrustAnchorInfo CertPathControls field
 * whose normalized value replaces the corresponding certificate_extensions
 * control (RFC 5914 section 2.5). */
enum {
  /* policySet replaces certificatePolicies in policy_set. */
  TC_X509_ANCHOR_REPLACED_POLICY_SET = 1u << 0,
  /* policyFlags replace policyConstraints and inhibitAnyPolicy in
   * policy_flags. */
  TC_X509_ANCHOR_REPLACED_POLICY_FLAGS = 1u << 1,
  /* nameConstr replaces nameConstraints in names. */
  TC_X509_ANCHOR_REPLACED_NAMES = 1u << 2,
  /* pathLenConstraint replaces the basicConstraints pathLen in path_len. */
  TC_X509_ANCHOR_REPLACED_PATH_LEN = 1u << 3
};

/* One trust anchor with its RFC 5937 path controls. Validation applies the
 * normalized fields names, policy_set, policy_flags and path_len. The
 * extension spans are checked for controls those fields must reflect.
 *
 * Borrowed DER spans. Policy and extension spans contain SEQUENCE contents.
 * extensions holds TrustAnchorInfo exts, which must not contain
 * certificatePolicies, policyConstraints, inhibitAnyPolicy or nameConstraints
 * (RFC 5914 section 2.6). certificate_extensions holds the anchor
 * certificate's own extensions. A path control there whose normalized field
 * is empty makes validation return UNSUPPORTED, unless replaced_controls marks
 * it as replaced. Build records from certificates with
 * TC_X509_store_anchor_from_certificate, or from a TrustAnchorList with
 * TC_X509_trust_anchor_next. */
typedef struct {
  TC_X509_trust_anchor trust;
  TC_X509_name_constraints names;
  TC_bytes key_id, title, title_language;
  TC_bytes policy_set, extensions, certificate_extensions;
  /* TC_X509_PATH_REQUIRE_EXPLICIT_POLICY, _INHIBIT_MAPPING and
   * _INHIBIT_ANY_POLICY only. */
  unsigned policy_flags;
  /* TC_X509_ANCHOR_REPLACED_* bits. TC_X509_trust_anchor_next sets them.
   * Caller-built records set a bit only when the normalized field holds the
   * replacing value. Other bits make validation return ERROR. */
  unsigned replaced_controls;
  /* Non-self-issued intermediates allowed below the anchor. */
  size_t path_len;
  uint8_t has_path_len;
  /* A TrustAnchorInfo without certPath is valid data with no X.509 name. */
  uint8_t x509_unusable;
} TC_X509_store_anchor;

/* Build an anchor record from a parsed anchor certificate with the rules of
 * the RFC 5914 TrustAnchorList certificate choice. certificatePolicies,
 * nameConstraints, policyConstraints, inhibitAnyPolicy and the
 * basicConstraints pathLen fill the normalized fields (RFC 5937 section 2).
 * The record borrows the certificate's DER. Keep that DER unchanged while
 * the record is in use. The certificate view itself may be discarded.
 * workspace supplies frames and extension OID scratch.
 *
 * Returns OK and writes out. NULL arguments, NULL scratch with a nonzero
 * capacity, and out overlapping the certificate view, its DER or the scratch
 * return ARGUMENT with out unchanged. After those checks, failures zero out:
 * INVALID for an empty subject, a reversed validity period, a keyUsage
 * without keyCertSign, or malformed or duplicate extensions and policies.
 * LIMIT for exhausted limits or scratch. The anchor's validity period is not
 * checked against any time. */
TC_TLV_result TC_X509_store_anchor_from_certificate(const TC_X509_certificate* certificate,
                                                    const TC_TLV_limits* limits,
                                                    TC_X509_workspace* workspace,
                                                    TC_X509_store_anchor* out);

/* Array-backed source for a fixed, caller-owned snapshot. All records and
 * their borrowed DER must remain stable until readers release the snapshot. */
typedef struct {
  const TC_bytes* candidates;
  size_t candidate_count;
  const TC_X509_store_anchor* anchors;
  size_t anchor_count;
} TC_X509_store_array;

/* Candidates are untrusted certificates. Anchors carry explicit local trust.
 * Callbacks return borrowed records, consume work without increasing it, and
 * return OK only after writing out. An unavailable record is a read error.
 * Reads propagate LIMIT and UNSUPPORTED. Other failure codes become ARGUMENT.
 * Record bytes and ordering remain stable while the source is in use. */
typedef struct {
  void* context;
  size_t candidate_count, anchor_count;
  TC_TLV_result (*candidate)(void* context, size_t index, size_t* work, TC_bytes* out);
  TC_TLV_result (*anchor)(void* context, size_t index, size_t* work, TC_X509_store_anchor* out);
} TC_X509_store_source;
TC_TLV_result TC_X509_store_array_source(const TC_X509_store_array* array,
                                         TC_X509_store_source* out);

/* Zero-initialize these objects. Fields are managed by the store functions.
 * state follows the TC_snapshot_state lifecycle in snapshot.h. */
typedef struct {
  TC_X509_store_source source;
  size_t readers;
  TC_snapshot_state state;
} TC_X509_store_snapshot;
typedef struct {
  TC_X509_store_snapshot* current;
  size_t revision;
} TC_X509_store;

/* Serialize every call with the application's lock. Store, slots, source and
 * result pointers must occupy disjoint storage. publish and acquire check the
 * store, the published slot and their arguments for overlap and return
 * ARGUMENT unchanged when they overlap. Do not copy live slots.
 * Keep source context and record bytes unchanged until the slot becomes FREE.
 * Certificate validation and trust authorization are caller responsibilities. */

/* Copy the callback configuration into a FREE slot. Retains borrowed context
 * and record storage. A busy slot returns LIMIT unchanged. */
TC_TLV_result TC_X509_store_prepare(TC_X509_store_snapshot* slot,
                                    const TC_X509_store_source* source);
/* Return a PREPARED slot to FREE and clear its source descriptor. Other states
 * return ARGUMENT unchanged. The caller owns the underlying record storage. */
TC_TLV_result TC_X509_store_discard(TC_X509_store_snapshot* slot);
/* Authorize and persist changes before publication. A stale revision returns
 * INVALID. Exhausted revision space returns LIMIT. Neither changes the store.
 * Publishing an empty source removes all anchors for subsequent readers. */
TC_TLV_result TC_X509_store_publish(TC_X509_store* store, size_t revision,
                                    TC_X509_store_snapshot* slot);
/* Acquire returns END without changing out when no snapshot is published.
 * Each successful acquire needs one release, after all borrowed results expire.
 * Old readers retain the old trust configuration across publication. Applications
 * requiring immediate distrust must cancel or revalidate those operations. */
TC_TLV_result TC_X509_store_acquire(TC_X509_store* store, TC_X509_store_snapshot** out);
/* Release one acquired reference. The last reader of a RETIRED slot returns it
 * to FREE, allowing the caller to reclaim its context and record storage. */
TC_TLV_result TC_X509_store_release(TC_X509_store_snapshot* slot);
#ifdef __cplusplus
}
#endif
#endif
