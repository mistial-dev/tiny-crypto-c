/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_X509_CRL_SOURCE_INTERNAL_H_
#define TINY_CRYPTO_X509_CRL_SOURCE_INTERNAL_H_
#include "source_der_internal.h"
#include "source_hash_internal.h"
#include "x509_crl_internal.h"

typedef struct {
  uint64_t offset, length;
} tc_source_span;

typedef struct {
  tc_source_span tbs, algorithm, signature;
  tc_source_span version, inner_algorithm, issuer, this_update, next_update;
  tc_source_span revoked, extensions;
} tc_x509_crl_layout;

/* Locate encoded fields without reading the revoked entries. Optional absent
 * fields have zero length. Typed field checks and authentication follow before
 * this provisional layout can contribute to a revocation result. */
TC_TLV_result tc_x509_crl_source_layout(tc_source_reader* reader, tc_x509_crl_layout* out);

/* Copy bounded metadata into stable caller storage, then apply shared typed
 * checks. Layout comes from this immutable source. All writable storage and
 * inputs are disjoint. Scratch is provisional. out changes only on success.
 * encoded/tbs/revoked remain empty. Their source offsets stay in layout.
 * copies, when present, receives the copied field TLVs in storage. */
TC_TLV_result tc_x509_crl_source_metadata(tc_source_reader* reader,
                                          const tc_x509_crl_layout* layout, TC_buffer storage,
                                          const TC_TLV_limits* limits,
                                          const tc_pki_tree_workspace* tree, TC_X509_crl* out,
                                          tc_x509_crl_fields* copies);

/* Single-pass TBSCertList hash of a prepared CRL. Entry bytes are hashed from
 * the buffer the entry parser reads. Every other TBSCertList byte is hashed
 * from one read and must equal its expected copy: a DER header rebuilt from
 * the layout or a metadata field copied by tc_x509_crl_source_metadata. The
 * signature then authenticates the bytes that were parsed. */
enum { TC_CRL_TBS_SEGMENTS = 9, TC_CRL_TBS_HEADERS = 3, TC_CRL_TBS_HEADER_BYTES = 10 };
typedef struct {
  uint64_t offset, length;
  /* Expected bytes, or NULL for entries that are hashed without a scan. */
  const uint8_t* expected;
} tc_x509_crl_tbs_segment;
typedef struct {
  /* hash.offset is the next TBSCertList byte to hash. */
  tc_source_hash hash;
  tc_x509_crl_tbs_segment segments[TC_CRL_TBS_SEGMENTS];
  uint8_t headers[TC_CRL_TBS_HEADERS][TC_CRL_TBS_HEADER_BYTES];
  /* Offset of the first scanned entry, or of the bytes after the entry list. */
  uint64_t entries_begin;
  size_t count, next;
} tc_x509_crl_tbs_hash;

typedef struct {
  uint64_t cursor, end, remaining;
  unsigned version;
  /* Hash fed with each entry's parsed bytes, or NULL. */
  tc_x509_crl_tbs_hash* tbs;
} tc_x509_crl_source_entries;

TC_TLV_result tc_x509_crl_source_entries_init(tc_source_reader* reader, tc_source_span encoded,
                                              unsigned version, uint64_t max_entries,
                                              tc_x509_crl_source_entries* out);
/* Borrow an entry from the read window when it fits. Copy fragmented entries to
 * scratch. Returned spans last until the next reader/scratch operation. Cursor
 * and out change only on success. Scratch and I/O budgets are provisional.
 * Entry extension policy and indirect issuer inheritance are separate steps.
 * With entries->tbs set, the entry bytes are hashed before parsing, and any
 * failure leaves that hash unusable. */
TC_TLV_result tc_x509_crl_source_entry_next(tc_source_reader* reader,
                                            tc_x509_crl_source_entries* entries, TC_buffer scratch,
                                            const TC_TLV_limits* limits,
                                            const tc_pki_tree_workspace* tree,
                                            tc_x509_crl_entry* out);

typedef struct {
  tc_x509_crl_source_entries entries;
  const TC_X509_crl_extensions* extensions;
  tc_x509_crl_entry_issuer issuer;
  TC_buffer issuer_storage;
} tc_x509_crl_source_revoked;

/* Metadata and extensions stay alive and unchanged during iteration. Separate
 * issuer storage retains GeneralNames across read-window and entry-scratch reuse.
 * All input, state, output and scratch regions are disjoint. */
TC_TLV_result tc_x509_crl_source_revoked_init(tc_source_reader* reader, tc_source_span encoded,
                                              const TC_X509_crl* metadata,
                                              const TC_X509_crl_extensions* extensions,
                                              uint64_t max_entries, TC_buffer issuer_storage,
                                              tc_x509_crl_source_revoked* out);
TC_TLV_result tc_x509_crl_source_revoked_next(tc_source_reader* reader,
                                              tc_x509_crl_source_revoked* revoked,
                                              TC_buffer scratch, const TC_TLV_limits* limits,
                                              const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                              size_t capacity, tc_x509_crl_revoked_entry* out);

/* Prepare the TBSCertList hash over layout. copies holds the metadata TLVs
 * copied from the same source. entries is the iterator the scan consumes, or
 * a zero iterator when the entries are hashed without a scan. INVALID when
 * the copies or the entry list do not tile the TBSCertList. */
TC_TLV_result tc_x509_crl_tbs_hash_init(tc_x509_crl_tbs_hash* out, tc_source_reader* reader,
                                        TC_hash_algorithm algorithm,
                                        const tc_x509_crl_layout* layout,
                                        const tc_x509_crl_fields* copies,
                                        const tc_x509_crl_source_entries* entries);

typedef enum {
  TC_CRL_SCAN_ACTIVE,
  /* Entries are done and the bytes after them are being hashed. */
  TC_CRL_SCAN_TRAILER,
  TC_CRL_SCAN_COMPLETE,
  TC_CRL_SCAN_FAILED
} tc_crl_scan_phase;
typedef struct {
  tc_source_reader* reader;
  tc_x509_crl_source_revoked revoked;
  const TC_X509_crl_target* queries;
  TC_X509_crl_match* matches;
  size_t count;
  tc_x509_crl_tbs_hash* tbs;
  tc_crl_scan_phase phase;
} tc_x509_crl_source_scan;

/* Start from a freshly initialized iterator. Queries and metadata remain stable;
 * matches is provisional caller scratch. All writable/input storage is disjoint.
 * An empty query batch still validates every entry. tbs, when present, is
 * initialized over the same iterator and is fed in the same pass. */
TC_TLV_result tc_x509_crl_source_scan_init(tc_source_reader* reader,
                                           const tc_x509_crl_source_revoked* revoked,
                                           const TC_X509_crl_target* queries, size_t count,
                                           TC_X509_crl_match* matches, size_t capacity,
                                           tc_x509_crl_tbs_hash* tbs, tc_x509_crl_source_scan* out);
/* Process at most max_entries. With a hash, also hash at most max_bytes of
 * the TBSCertList bytes around the entries. Entry bytes are hashed as each
 * entry is read. Work is charged one unit per hashed byte, and work and I/O
 * limits bound each call further. Failure makes the scan terminal. complete
 * changes only on success. */
TC_TLV_result tc_x509_crl_source_scan_step(tc_x509_crl_source_scan* scan, size_t max_entries,
                                           size_t max_bytes, TC_buffer scratch,
                                           const tc_x509_crl_decode* decode, int* complete);
#endif
