<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# TWIC canceled card lists

Enable `TINY_CRYPTO_ENABLE_TWIC_CCL=ON` (on in the desktop profile) and include
`<tiny_crypto/twic_ccl.h>`. The reader has no cryptographic dependencies.

The [TSA CCL feed](https://tsaenrollmentbyidemia.tsa.dhs.gov/canceled-card-lists) lists canceled
or suspended credentials by FASC-N. Each CSV row holds 50 hexadecimal digits in either case, a
comma and a `ddMmmYYYY` cancellation date with an English title-case month. Dates must be valid
Gregorian dates with a nonzero year. Rows end with CRLF or LF. Empty lists, an unterminated final
row, quoting, headers and extra fields fail validation.

## Reading and lookup

`TC_TWIC_CCL_read` decodes one row, without its line ending, into a 25-byte FASC-N and the
record's cancellation date. Output stays unchanged on failure.

`TC_TWIC_CCL_contains` validates a complete CSV buffer, then reports whether it lists a FASC-N
such as `chuid.fascn`. It takes a maximum record count and runs in linear time. Duplicate records
count as one.

For chunked input, `TC_TWIC_CCL_stream_init` takes byte and record limits, a callback and its
context, and `stream_update` and `stream_finish` feed it. Zero limits permit zero work. Complete
rows parse straight from the chunks, and a split row retains at most 61 bytes. Each decoded record
is valid for its callback, so copy records to staging storage to build a list. Failures persist
until reinitialization, and earlier callback writes stay in staging storage. A successful `finish`
confirms framing and records only. A download cut at a row boundary is still valid CSV, so check
completeness, provenance and freshness before publishing the staged list.

Input chunks, parser state and outputs need disjoint storage. Keep input stable during a call.
Callbacks must leave the parser alone and avoid reentering it.

## Credential policy

Membership covers the supplied list only. Acceptance also needs list freshness, card
authentication, expiration and access checks. Keep the selected list stable for the whole
decision, and keep the previous list active when an update fails.

The MD5 checksum on the TSA download page detects corruption. Authenticated retrieval or trusted
provisioning establishes origin. Track publication and retrieval times apart from the per-record
cancellation dates.

`TC_TWIC_CCL_check_freshness` checks trusted publication and retrieval timestamps in Unix seconds
against `now`, an inclusive maximum publication age and a persisted `minimum_publication` floor.
A zero age requires publication at `now`. A later download of the same list keeps its original
publication age. A future receipt, or receipt before publication, returns `TC_TWIC_CCL_INVALID`.
An expired or too-old publication returns `TC_TWIC_CCL_STALE`. Store operations perform no age
check, so call the helper at the application's policy boundary.

Deployment rules:

- TSA's *TWIC NEXGEN & Legacy, Part 4, version 4*, §2.6 directs PACS implementations to download
  daily, verify the message digest, keep the previous list and warn after an unavailable or empty
  download, and warn when the list is older than three days.
- For maritime checks,
  [33 CFR 101.525](https://www.ecfr.gov/current/title-33/chapter-I/subchapter-H/part-101/subpart-E/section-101.525)
  limits information age to seven days at MARSEC Level 1 and one day at Levels 2 and 3, requires an
  update within twelve hours of a MARSEC increase, and requires the most recently obtained list.

The application configures these limits, triggers and warnings.

The visual list, VCCL, uses the printed card identification number (CIN). Electronic queries use
the full FASC-N. Certificate revocation and credential cancellation are separate checks, and a
suspended credential can be listed while its certificates remain unrevoked. See the
[TWIC Reader Specification, Part 3, sections 4.4.3 and 4.4.4](https://www.tsa.gov/sites/default/files/5c.-twic-nexgen-legacy-part-3-reader-specification-v4.pdf).

## Indexed storage

For repeated checks, provision a packed array of 25-byte FASC-Ns sorted in unsigned byte order on
the host. Keep every identifier from the validated CSV. Duplicates may be kept or removed. The
image can live in external flash or a file.

`TC_TWIC_CCL_index_prepare` scans a `TC_TWIC_CCL_source` (count, context and indexed read
callback) once to check key sizes and order against a maximum record count, and writes the index
only on success. `TC_TWIC_CCL_index_from_memory` does the same for an image in stable memory,
given a pointer to its `TC_bytes` descriptor. Indexed reads borrow keys from the image, so keep the
descriptor and bytes unchanged until every index and snapshot using them is released. Lookup
output must be separate from both. Bind the index to its completed import and provenance metadata
before credential checks use it.

Host programs can load the file with `example_read_file` from `examples/pki_input.h`, close it, and
index the owned buffer, which stays stable if the file is later replaced. Provision the image and
its publication metadata together through a trusted channel.

`TC_TWIC_CCL_index_contains` runs an exact binary search with the same FASC-N query as the CSV
lookup and a maximum read count. An index of `n` keys needs at most `floor(log2(n)) + 1` reads.
Failures leave the membership output unchanged:

| Cause                 | Result                     |
| --------------------- | -------------------------- |
| Failed source read    | `TC_TWIC_CCL_SOURCE_ERROR` |
| Key of the wrong size | `TC_TWIC_CCL_INVALID`      |
| Exhausted read budget | `TC_TWIC_CCL_LIMIT`        |

The source may reuse one 25-byte read buffer. Keys and their order must stay unchanged for the
index's lifetime. Lock a shared read buffer, or give concurrent readers their own.

[twic_ccl_storage.c](../examples/twic_ccl_storage.c) adapts a byte-addressed storage callback.
Set `context`, `read_at` and the image `length` in a caller-owned `ExampleTwicCclStorage`, which
also holds the read buffer, then call `example_twic_ccl_open` to get an index. Keep the storage
object and image alive while checks use it.

## Snapshots

A `TC_TWIC_CCL_store` publishes lists through two or more zero-initialized `TC_TWIC_CCL_snapshot`
slots. After validating and persisting an index and its metadata, call `TC_TWIC_CCL_store_prepare`
on a free slot, then `TC_TWIC_CCL_store_publish` with the expected store revision. A failed publish
keeps the current list. Discard a prepared slot to abandon an update. A publication older than the
current list fails.

Readers call `TC_TWIC_CCL_store_acquire`, `TC_TWIC_CCL_snapshot_contains` and
`TC_TWIC_CCL_store_release`. A superseded slot stays allocated until released, and its queries
return `TC_TWIC_CCL_STALE`, so acquire the new slot and repeat. A missing list returns
`TC_TWIC_CCL_UNAVAILABLE`. Both leave lookup outputs unchanged.

Serialize these operations and the final validity decision under one application lock, so no
update supersedes a lookup before its result is used. Protect source buffers the same way. Apply
warning and age policy with the held metadata. Persist rollback state and the image before
publishing, and restore both after a restart.

`example_check_twic_cancellation` in the storage example acquires, checks age, looks up and
releases. `listed` is the membership result. `policy.max_age` is an acceptance limit, and
`age_warning` reports a separate caller-chosen warning threshold. Both outputs stay unchanged on
failure, and every acquired snapshot is released.

## Staged import example

[twic_ccl_import.c](../examples/twic_ccl_import.c) parses the CSV and verifies its MD5, so it needs
CCL and MD5 support. `example_twic_ccl_import_init` takes the decoded expected checksum, byte and
record limits, and a callback that appends each key to private staging storage. Feed the exact
download chunks to `example_twic_ccl_import_update`.

After the download, sort the staged keys and expose them as an unchanging `TC_TWIC_CCL_source`. The
example keeps duplicates, because the source count must equal the parsed record count.
`example_twic_ccl_import_finish` verifies framing, checksum, record count and order before
preparing the proposed slot. A wrong checksum, including one from a download truncated at a row
boundary, returns `TC_TWIC_CCL_CHECKSUM_MISMATCH`.

On success, persist the image and metadata, apply update policy, and publish under the store lock.
On failure, keep the active list, discard the staged image and warn with the returned error. Call
`example_twic_ccl_import_clear` before releasing the state. The expected checksum and metadata must
come from trusted retrieval or provisioning.

## Tests

In a configured test build, build `test_twic_ccl` and run
`ctest --test-dir build -R '^test_twic_ccl$'`. Synthetic munit cases cover decoding, membership,
invalid rows, chunk boundaries, truncation, limits, sink failures and the storage example, with no
network access.

To check a downloaded feed:

```sh
TC_TEST_TWIC_CCL=/path/to/CCL.CSV \
TC_TEST_TWIC_CCL_MD5=the_32_hex_digits_from_CCL.CSV.MD5 \
  ./build/test_twic_ccl
```

The case skips when `TC_TEST_TWIC_CCL` is unset and requires the MD5 when it is set. It verifies
the checksum with the library, builds a sorted image, looks up every identifier through the index,
and compares mutated queries with the C library's `bsearch`.
