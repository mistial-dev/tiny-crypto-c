<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Certificate store

Include `<tiny_crypto/x509_store.h>`. The store publishes caller-owned certificate sources and keeps
retired sources alive while readers use them. Certificate bytes stay in caller storage.

A source has separate callbacks for untrusted candidate certificates and explicit trust anchors.
Each anchor can carry path constraints. Callbacks return borrowed spans and charge reads against the
supplied work budget. `TC_X509_store_array_source` presents a fixed `TC_X509_store_array` of
candidate spans and anchor records as a source and charges one work unit per record read. Anchor
records come from the [trust-anchor reader](x509-trust-anchors.md) or from one parsed root with
`TC_X509_store_anchor_from_certificate`.

## Update a source

Zero-initialize the store and snapshot slots, and serialize store calls with the application's lock.

1. Build an immutable source in unused storage.
1. Call `TC_X509_store_prepare` with a free slot and that source.
1. Validate the proposed records, authorize the trust change and persist it.
1. Call `TC_X509_store_publish` with the revision used to prepare the update.
1. To abandon the update, call `TC_X509_store_discard` on the prepared slot.

Preparation checks callback configuration only. The application parses certificates, makes the
trust decision, writes flash and recovers after power loss. Publication returns `TC_TLV_INVALID`
for a stale revision and `TC_TLV_LIMIT` when the revision counter is exhausted. Both leave the
current source in place.

## Slot states

Each slot follows the `TC_snapshot_state` lifecycle from `<tiny_crypto/snapshot.h>`, which the TWIC
canceled-card-list store shares.

| State                  | Entered by                                                   | Leaves by        |
| ---------------------- | ------------------------------------------------------------ | ---------------- |
| `TC_SNAPSHOT_FREE`     | zero initialization, discard, last release of a retired slot | prepare          |
| `TC_SNAPSHOT_PREPARED` | prepare                                                      | publish, discard |
| `TC_SNAPSHOT_CURRENT`  | publish                                                      | a later publish  |
| `TC_SNAPSHOT_RETIRED`  | a later publish while readers remain                         | last release     |

Only the `TC_SNAPSHOT_CURRENT` slot accepts new readers. A superseded slot without readers goes
straight to `TC_SNAPSHOT_FREE`. Publish and acquire return `TC_TLV_ARGUMENT`, with no changes, when
the store, the published slot and the argument objects overlap.

## Reader lifetimes

`TC_X509_store_acquire` returns the current snapshot, or `TC_TLV_END` when nothing is published.
Hold the reference until every use of its certificate bytes and borrowed validation results ends,
then call `TC_X509_store_release` exactly once. Releasing a slot without readers returns
`TC_TLV_ARGUMENT`. A released reference is invalid.

A retired snapshot's storage becomes reusable when its state reaches `TC_SNAPSHOT_FREE`. Allocate
slots for the current source, a prepared update and every retired source that readers still hold.

Existing readers keep the previous trust configuration, so removing an anchor leaves their
operations running. For immediate distrust, cancel or revalidate those operations before using
their results.

## Build a path

Pass the acquired snapshot's `source` to `TC_X509_path_build` with the target certificate, the
[path options](x509-path.md#inputs) and caller-owned validation and search workspaces. The builder
tries candidate issuers and explicit anchors, validates each complete path and returns the first
valid one. Candidate order affects search cost and which valid path is selected.

Search uses a `TC_bytes` array and a `TC_X509_search_frame` array of equal capacity. The smaller of
that capacity and `options.max_certificates` bounds path depth. `options.max_work` covers failed
branches and storage callbacks as well as the successful path. Exhausted resources return
`TC_X509_PATH_LIMIT`.

The result's `path` points into search storage, anchor-issued certificate first and target last.
`anchor_index` identifies the selected source anchor. Keep the snapshot and both workspaces alive
while using the result, and see [path lifetimes](x509-path.md#lifetimes) before reusing them.

[example_find_client_path](../examples/x509_client.c) searches for a four-certificate path under the
client-authentication policy of the ordered-chain example. Allocate its validation arena and an
`EXAMPLE_CLIENT_PATH_CAPACITY` search workspace outside a small task stack, then pass a signature
verifier, the current time and the snapshot's source. The caller locks and releases the snapshot,
so the returned certificate and policy spans stay usable.

Enrollment record validation and persistent storage adapters belong to the application.
