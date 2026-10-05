/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/common.h>
#if TC_ENABLE_X509_REVOCATION
#include "x509_crl_source_internal.h"
#include "internal.h"
#include "tlv_internal.h"

static int source_tag(const tc_source_der_element* field, uint8_t tag)
{
  return tc_tlv_tag_bytes_is(field->header.tag, field->header.tag_length, tag);
}

static tc_source_span source_span(const tc_source_der_element* field)
{
  const tc_source_span span = {field->offset, field->end - field->offset};
  return span;
}

static TC_TLV_result source_field(tc_source_reader* reader, uint64_t* cursor, uint64_t end,
                                  tc_source_der_element* field)
{
  TC_TLV_result result = tc_source_der_read(reader, *cursor, end, UINT64_MAX, field);
  if (result == TC_TLV_OK)
    *cursor = field->end;
  return result;
}

static TC_TLV_result source_required(tc_source_reader* reader, uint64_t* cursor, uint64_t end,
                                     uint8_t tag, tc_source_der_element* field)
{
  TC_TLV_result result = source_field(reader, cursor, end, field);
  if (result == TC_TLV_END)
    return TC_TLV_INVALID;
  if (result != TC_TLV_OK)
    return result;
  return source_tag(field, tag) ? TC_TLV_OK : TC_TLV_INVALID;
}

TC_TLV_result tc_x509_crl_source_layout(tc_source_reader* reader, tc_x509_crl_layout* out)
{
  tc_source_der_element outer, tbs, field;
  tc_x509_crl_layout parsed = {0};
  uint64_t cursor = 0;
  if (!reader || !out || !tc_internal_ranges_disjoint(out, sizeof *out, reader, sizeof *reader) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, reader->window.data, reader->window.capacity))
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = source_required(reader, &cursor, reader->source.length, 0x30, &outer);
  if (result != TC_TLV_OK)
    return result;
  if (cursor != reader->source.length)
    return TC_TLV_INVALID;
  cursor = outer.value_offset;
  result = source_required(reader, &cursor, outer.end, 0x30, &tbs);
  if (result != TC_TLV_OK)
    return result;
  parsed.tbs = source_span(&tbs);
  result = source_required(reader, &cursor, outer.end, 0x30, &field);
  if (result != TC_TLV_OK)
    return result;
  parsed.algorithm = source_span(&field);
  result = source_required(reader, &cursor, outer.end, 3, &field);
  if (result != TC_TLV_OK)
    return result;
  parsed.signature = source_span(&field);
  if (cursor != outer.end)
    return TC_TLV_INVALID;

  cursor = tbs.value_offset;
  result = source_field(reader, &cursor, tbs.end, &field);
  if (result != TC_TLV_OK)
    return result == TC_TLV_END ? TC_TLV_INVALID : result;
  if (source_tag(&field, 2)) {
    parsed.version = source_span(&field);
    result = source_required(reader, &cursor, tbs.end, 0x30, &field);
    if (result != TC_TLV_OK)
      return result;
  }
  if (!source_tag(&field, 0x30))
    return TC_TLV_INVALID;
  parsed.inner_algorithm = source_span(&field);
  result = source_required(reader, &cursor, tbs.end, 0x30, &field);
  if (result != TC_TLV_OK)
    return result;
  parsed.issuer = source_span(&field);
  result = source_field(reader, &cursor, tbs.end, &field);
  if (result != TC_TLV_OK)
    return result == TC_TLV_END ? TC_TLV_INVALID : result;
  if (!source_tag(&field, 0x17) && !source_tag(&field, 0x18))
    return TC_TLV_INVALID;
  parsed.this_update = source_span(&field);
  result = source_field(reader, &cursor, tbs.end, &field);
  if (result == TC_TLV_OK && (source_tag(&field, 0x17) || source_tag(&field, 0x18))) {
    parsed.next_update = source_span(&field);
    result = source_field(reader, &cursor, tbs.end, &field);
  }
  if (result == TC_TLV_OK && source_tag(&field, 0x30)) {
    parsed.revoked = source_span(&field);
    result = source_field(reader, &cursor, tbs.end, &field);
  }
  if (result == TC_TLV_OK) {
    if (!source_tag(&field, 0xa0) || !parsed.version.length || cursor != tbs.end)
      return TC_TLV_INVALID;
    uint64_t explicit_cursor = field.value_offset;
    const uint64_t explicit_end = field.end;
    result = source_required(reader, &explicit_cursor, explicit_end, 0x30, &field);
    if (result != TC_TLV_OK)
      return result;
    if (explicit_cursor != explicit_end || !field.header.length)
      return TC_TLV_INVALID;
    parsed.extensions = source_span(&field);
  } else if (result != TC_TLV_END)
    return result;
  *out = parsed;
  return TC_TLV_OK;
}

/* Hash bytes read at offset, which must be the next TBSCertList byte. */
static TC_TLV_result tbs_hash_update(tc_x509_crl_tbs_hash* tbs, uint64_t offset, TC_bytes bytes,
                                     size_t* work)
{
  tc_source_hash* hash = &tbs->hash;
  if (!hash->active || offset != hash->offset || bytes.length > hash->end - offset)
    return TC_TLV_INVALID;
  TC_TLV_result result = tc_pki_work_charge(work, bytes.length);
  if (result != TC_TLV_OK)
    return result;
  if (tc_hash_update(hash->algorithm, &hash->hash, bytes) != TC_OK)
    return TC_TLV_ARGUMENT;
  hash->offset += bytes.length;
  return TC_TLV_OK;
}

/* Hash the segments that start before limit, reading each byte once and
 * comparing it with the expected copy. *budget bounds the bytes read. OK
 * when the hash reached limit, MORE when the budget ran out first. */
static TC_TLV_result tbs_hash_segments(tc_x509_crl_tbs_hash* tbs, tc_source_reader* reader,
                                       uint64_t limit, size_t* budget, size_t* work)
{
  while (tbs->next < tbs->count && tbs->segments[tbs->next].offset < limit) {
    const tc_x509_crl_tbs_segment* segment = &tbs->segments[tbs->next];
    const uint64_t end = segment->offset + segment->length;
    while (tbs->hash.offset < end) {
      if (!*budget)
        return TC_TLV_MORE;
      const uint64_t remaining = end - tbs->hash.offset;
      const size_t request = remaining < *budget ? (size_t)remaining : *budget;
      const uint64_t offset = tbs->hash.offset;
      TC_bytes chunk;
      TC_TLV_result result =
          tc_source_status(tc_source_reader_view(reader, offset, request, &chunk));
      if (result != TC_TLV_OK)
        return result;
      if (segment->expected &&
          memcmp(chunk.data, segment->expected + (offset - segment->offset), chunk.length))
        return TC_TLV_INVALID;
      result = tbs_hash_update(tbs, offset, chunk, work);
      if (result != TC_TLV_OK)
        return result;
      *budget -= chunk.length;
    }
    tbs->next++;
  }
  return tbs->hash.offset == limit ? TC_TLV_OK : TC_TLV_INVALID;
}

/* Write the DER header of an element with tag and a value of length bytes
 * (X.690 section 10.1). Returns the header size. */
static size_t der_header(uint8_t out[TC_CRL_TBS_HEADER_BYTES], uint8_t tag, uint64_t length)
{
  size_t size = 0, octets = 0;
  out[size++] = tag;
  if (length < 0x80) {
    out[size++] = (uint8_t)length;
    return size;
  }
  for (uint64_t rest = length; rest; rest >>= 8)
    ++octets;
  out[size++] = (uint8_t)(0x80 | octets);
  while (octets--)
    out[size++] = (uint8_t)(length >> (8 * octets));
  return size;
}

/* Segments are appended in source order from position. */
typedef struct {
  tc_x509_crl_tbs_hash* tbs;
  uint64_t position;
  size_t headers;
  TC_TLV_result result;
} tbs_tiling;

/* Append the segment at the current position. */
static void tbs_segment(tbs_tiling* tiling, uint64_t length, const uint8_t* expected)
{
  tc_x509_crl_tbs_hash* tbs = tiling->tbs;
  if (tiling->result != TC_TLV_OK || !length)
    return;
  if (tbs->count == TC_CRL_TBS_SEGMENTS) {
    tiling->result = TC_TLV_INVALID;
    return;
  }
  tbs->segments[tbs->count++] = (tc_x509_crl_tbs_segment){tiling->position, length, expected};
  tiling->position += length;
}

/* Append a copied field, which must start at the current position. */
static void tbs_field(tbs_tiling* tiling, tc_source_span span, TC_bytes copy)
{
  if (tiling->result == TC_TLV_OK &&
      (span.length != copy.length || (span.length && span.offset != tiling->position)))
    tiling->result = TC_TLV_INVALID;
  tbs_segment(tiling, span.length, copy.data);
}

/* Append the header of the element at the current position whose value
 * starts at value and ends at end. */
static void tbs_header(tbs_tiling* tiling, uint8_t tag, uint64_t value, uint64_t end)
{
  if (tiling->result != TC_TLV_OK)
    return;
  if (tiling->headers == TC_CRL_TBS_HEADERS || value < tiling->position || end < value) {
    tiling->result = TC_TLV_INVALID;
    return;
  }
  uint8_t* header = tiling->tbs->headers[tiling->headers++];
  if (der_header(header, tag, end - value) != value - tiling->position) {
    tiling->result = TC_TLV_INVALID;
    return;
  }
  tbs_segment(tiling, value - tiling->position, header);
}

TC_TLV_result tc_x509_crl_tbs_hash_init(tc_x509_crl_tbs_hash* out, tc_source_reader* reader,
                                        TC_hash_algorithm algorithm,
                                        const tc_x509_crl_layout* layout,
                                        const tc_x509_crl_fields* copies,
                                        const tc_x509_crl_source_entries* entries)
{
  if (!out || !reader || !layout || !copies || !entries)
    return TC_TLV_ARGUMENT;
  memset(out, 0, sizeof *out);
  const tc_source_span* first =
      layout->version.length ? &layout->version : &layout->inner_algorithm;
  const uint64_t tbs_end = layout->tbs.offset + layout->tbs.length;
  tbs_tiling tiling = {out, layout->tbs.offset, 0, TC_TLV_OK};
  tbs_header(&tiling, 0x30, first->offset, tbs_end);
  tbs_field(&tiling, layout->version, copies->version);
  tbs_field(&tiling, layout->inner_algorithm, copies->inner_algorithm);
  tbs_field(&tiling, layout->issuer, copies->issuer);
  tbs_field(&tiling, layout->this_update, copies->this_update);
  tbs_field(&tiling, layout->next_update, copies->next_update);
  if (layout->revoked.length && entries->end) {
    /* The scan reads and hashes [cursor, end). */
    tbs_header(&tiling, 0x30, entries->cursor, entries->end);
    out->entries_begin = tiling.position;
    tiling.position = entries->end;
  } else {
    /* Entries of an unusable CRL are hashed without a scan. */
    tbs_segment(&tiling, layout->revoked.length, NULL);
    out->entries_begin = tiling.position;
  }
  if (layout->extensions.length)
    tbs_header(&tiling, 0xa0, layout->extensions.offset, tbs_end);
  tbs_field(&tiling, layout->extensions, copies->extensions);
  if (tiling.result != TC_TLV_OK)
    return tiling.result;
  if (tiling.position != tbs_end)
    return TC_TLV_INVALID;
  return tc_source_status(
      tc_source_hash_init(&out->hash, reader, algorithm, layout->tbs.offset, layout->tbs.length));
}

TC_TLV_result tc_x509_crl_source_entries_init(tc_source_reader* reader, tc_source_span encoded,
                                              unsigned version, uint64_t max_entries,
                                              tc_x509_crl_source_entries* out)
{
  if (!reader || !out || (version != 1 && version != 2) || encoded.offset > reader->source.length ||
      encoded.length > reader->source.length - encoded.offset)
    return TC_TLV_ARGUMENT;
  tc_x509_crl_source_entries parsed = {0, 0, max_entries, version, NULL};
  if (encoded.length) {
    tc_source_der_element element;
    TC_TLV_result result = tc_source_der_read(
        reader, encoded.offset, encoded.offset + encoded.length, UINT64_MAX, &element);
    if (result != TC_TLV_OK)
      return result;
    if (!source_tag(&element, 0x30) || element.end != encoded.offset + encoded.length)
      return TC_TLV_INVALID;
    parsed.cursor = element.value_offset;
    parsed.end = element.end;
  }
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_source_entry_next(tc_source_reader* reader,
                                            tc_x509_crl_source_entries* entries, TC_buffer scratch,
                                            const TC_TLV_limits* limits,
                                            const tc_pki_tree_workspace* tree,
                                            tc_x509_crl_entry* out)
{
  if (!reader || !entries || !limits || !tree || !tree->work || !out ||
      entries->cursor > entries->end || entries->end > reader->source.length ||
      (!scratch.data && scratch.capacity))
    return TC_TLV_ARGUMENT;
  if (entries->cursor == entries->end)
    return TC_TLV_END;
  if (!entries->remaining)
    return TC_TLV_LIMIT;
  tc_source_der_element element;
  TC_TLV_result result =
      tc_source_der_read(reader, entries->cursor, entries->end, limits->max_value, &element);
  if (result != TC_TLV_OK)
    return result;
  if (!source_tag(&element, 0x30))
    return TC_TLV_INVALID;
  const uint64_t size = element.end - element.offset;
  if (size > limits->max_input || size > SIZE_MAX)
    return TC_TLV_LIMIT;
  /* Borrow the entry when one cache window holds it; otherwise copy it. */
  TC_bytes encoded;
  result = tc_source_status(tc_source_reader_view(reader, element.offset, (size_t)size, &encoded));
  if (result != TC_TLV_OK)
    return result;
  if (encoded.length != size) {
    if (size > scratch.capacity)
      return TC_TLV_LIMIT;
    result = tc_source_reader_copy(reader, element.offset, (size_t)size, scratch.data);
    if (result != TC_TLV_OK)
      return result;
    encoded = (TC_bytes){scratch.data, (size_t)size};
  }
  if (entries->tbs) {
    result = tbs_hash_update(entries->tbs, element.offset, encoded, tree->work);
    if (result != TC_TLV_OK)
      return result;
  }
  TC_TLV_reader bounded;
  result = TC_TLV_reader_init(&bounded, encoded, TC_TLV_DER, limits);
  if (result != TC_TLV_OK)
    return result;
  tc_x509_crl_entry parsed;
  result = tc_x509_crl_entry_next(&bounded, entries->version, tree, &parsed);
  if (result != TC_TLV_OK)
    return result;
  entries->cursor = element.end;
  entries->remaining--;
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_source_revoked_init(tc_source_reader* reader, tc_source_span encoded,
                                              const TC_X509_crl* metadata,
                                              const TC_X509_crl_extensions* extensions,
                                              uint64_t max_entries, TC_buffer issuer_storage,
                                              tc_x509_crl_source_revoked* out)
{
  if (!metadata || !metadata->issuer.data || !metadata->issuer.length || !extensions || !out ||
      (!issuer_storage.data && issuer_storage.capacity))
    return TC_TLV_ARGUMENT;
  tc_x509_crl_source_revoked parsed = {0};
  TC_TLV_result result = tc_x509_crl_extension_policy(extensions);
  if (result != TC_TLV_OK)
    return result;
  result = tc_x509_crl_source_entries_init(reader, encoded, metadata->version, max_entries,
                                           &parsed.entries);
  if (result != TC_TLV_OK)
    return result;
  parsed.extensions = extensions;
  parsed.issuer.name = metadata->issuer;
  parsed.issuer_storage = issuer_storage;
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_source_revoked_next(tc_source_reader* reader,
                                              tc_x509_crl_source_revoked* revoked,
                                              TC_buffer scratch, const TC_TLV_limits* limits,
                                              const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                              size_t capacity, tc_x509_crl_revoked_entry* out)
{
  if (!revoked || !out)
    return TC_TLV_ARGUMENT;
  tc_x509_crl_source_revoked next = *revoked;
  tc_x509_crl_entry entry;
  tc_x509_crl_revoked_entry parsed;
  TC_TLV_result result =
      tc_x509_crl_source_entry_next(reader, &next.entries, scratch, limits, tree, &entry);
  if (result != TC_TLV_OK)
    return result;
  result = tc_x509_crl_entry_resolve(&entry, next.extensions, &next.issuer, limits, tree, oids,
                                     capacity, &parsed);
  if (result != TC_TLV_OK)
    return result;
  if (parsed.extensions.present & TC_CRL_ENTRY_ISSUER) {
    const TC_bytes names = parsed.issuer.names;
    if (names.length > next.issuer_storage.capacity)
      return TC_TLV_LIMIT;
    if (!next.issuer_storage.data)
      return TC_TLV_ARGUMENT;
    memcpy(next.issuer_storage.data, names.data, names.length);
    parsed.issuer.names = (TC_bytes){next.issuer_storage.data, names.length};
  }
  next.issuer = parsed.issuer;
  *revoked = next;
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_source_scan_init(tc_source_reader* reader,
                                           const tc_x509_crl_source_revoked* revoked,
                                           const TC_X509_crl_target* queries, size_t count,
                                           TC_X509_crl_match* matches, size_t capacity,
                                           tc_x509_crl_tbs_hash* tbs, tc_x509_crl_source_scan* out)
{
  if (!reader || !revoked || !out || (count && (!queries || !matches)) ||
      count > SIZE_MAX / sizeof *matches || count > SIZE_MAX / sizeof *queries)
    return TC_TLV_ARGUMENT;
  if (count > capacity)
    return TC_TLV_LIMIT;
  for (size_t i = 0; i < count; ++i)
    if (!queries[i].serial.data || !queries[i].serial.length || !queries[i].issuer.data ||
        !queries[i].issuer.length)
      return TC_TLV_ARGUMENT;
  tc_x509_crl_source_scan parsed = {reader, *revoked, queries,           matches,
                                    count,  tbs,      TC_CRL_SCAN_ACTIVE};
  parsed.revoked.entries.tbs = tbs;
  if (count)
    memset(matches, 0, count * sizeof *matches);
  *out = parsed;
  return TC_TLV_OK;
}

/* Scan at most max_entries entries. OK with *done set after the last one. */
static TC_TLV_result scan_entries(tc_x509_crl_source_scan* scan, size_t max_entries,
                                  TC_buffer scratch, const tc_x509_crl_decode* decode, int* done)
{
  const TC_TLV_limits* limits = decode->limits;
  const tc_pki_tree_workspace* tree = decode->tree;
  for (size_t step = 0; step < max_entries; ++step) {
    tc_x509_crl_revoked_entry entry;
    TC_TLV_result result =
        tc_x509_crl_source_revoked_next(scan->reader, &scan->revoked, scratch, limits, tree,
                                        decode->oids, decode->oid_capacity, &entry);
    if (result == TC_TLV_END) {
      *done = 1;
      return TC_TLV_OK;
    }
    for (size_t i = 0; result == TC_TLV_OK && i < scan->count; ++i)
      result = tc_x509_crl_match_update(&entry, &scan->queries[i], limits, tree, decode->names,
                                        &scan->matches[i]);
    if (result != TC_TLV_OK)
      return result;
  }
  *done = 0;
  return TC_TLV_OK;
}

/* One scan step in phase order: the hashed bytes before the entries, the
 * entries, then the hashed bytes after them. MORE when a budget ends the
 * step early. */
static TC_TLV_result scan_advance(tc_x509_crl_source_scan* scan, size_t max_entries,
                                  size_t max_bytes, TC_buffer scratch,
                                  const tc_x509_crl_decode* decode)
{
  tc_x509_crl_tbs_hash* tbs = scan->tbs;
  size_t* work = decode->tree->work;
  size_t budget = max_bytes;
  TC_TLV_result result = TC_TLV_OK;
  if (scan->phase == TC_CRL_SCAN_ACTIVE) {
    int done = 0;
    if (tbs && tbs->hash.offset < tbs->entries_begin)
      result = tbs_hash_segments(tbs, scan->reader, tbs->entries_begin, &budget, work);
    if (result == TC_TLV_OK)
      result = scan_entries(scan, max_entries, scratch, decode, &done);
    if (result != TC_TLV_OK)
      return result;
    if (!done)
      return TC_TLV_MORE;
    scan->phase = tbs ? TC_CRL_SCAN_TRAILER : TC_CRL_SCAN_COMPLETE;
  }
  if (scan->phase == TC_CRL_SCAN_TRAILER) {
    result = tbs_hash_segments(tbs, scan->reader, tbs->hash.end, &budget, work);
    if (result != TC_TLV_OK)
      return result;
    scan->phase = TC_CRL_SCAN_COMPLETE;
  }
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_source_scan_step(tc_x509_crl_source_scan* scan, size_t max_entries,
                                           size_t max_bytes, TC_buffer scratch,
                                           const tc_x509_crl_decode* decode, int* complete)
{
  if (!scan || !decode || !decode->limits || !decode->tree || !decode->tree->work || !complete ||
      !max_entries || (scan->tbs && !max_bytes) ||
      (scan->phase != TC_CRL_SCAN_ACTIVE && scan->phase != TC_CRL_SCAN_TRAILER))
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = scan_advance(scan, max_entries, max_bytes, scratch, decode);
  if (result == TC_TLV_MORE) {
    *complete = 0;
    return TC_TLV_OK;
  }
  if (result != TC_TLV_OK) {
    scan->phase = TC_CRL_SCAN_FAILED;
    return result;
  }
  *complete = 1;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_source_metadata(tc_source_reader* reader,
                                          const tc_x509_crl_layout* layout, TC_buffer storage,
                                          const TC_TLV_limits* limits,
                                          const tc_pki_tree_workspace* tree, TC_X509_crl* out,
                                          tc_x509_crl_fields* copies)
{
  if (!reader || !layout || !storage.data || !out || !limits || !tree || !tree->work)
    return TC_TLV_ARGUMENT;
  const tc_source_span spans[] = {layout->algorithm,       layout->signature, layout->version,
                                  layout->inner_algorithm, layout->issuer,    layout->this_update,
                                  layout->next_update,     layout->extensions};
  tc_x509_crl_fields fields = {0};
  TC_bytes* views[] = {&fields.algorithm,       &fields.signature, &fields.version,
                       &fields.inner_algorithm, &fields.issuer,    &fields.this_update,
                       &fields.next_update,     &fields.extensions};
  size_t total = 0;
  for (size_t i = 0; i < sizeof spans / sizeof spans[0]; ++i) {
    if (spans[i].offset > reader->source.length ||
        spans[i].length > reader->source.length - spans[i].offset)
      return TC_TLV_ARGUMENT;
    if (spans[i].length > storage.capacity - total || spans[i].length > limits->max_input)
      return TC_TLV_LIMIT;
    total += (size_t)spans[i].length;
  }
  size_t used = 0;
  for (size_t i = 0; i < sizeof spans / sizeof spans[0]; ++i) {
    const size_t length = (size_t)spans[i].length;
    if (!length)
      continue;
    *views[i] = (TC_bytes){storage.data + used, length};
    const TC_TLV_result copied =
        tc_source_reader_copy(reader, spans[i].offset, length, storage.data + used);
    if (copied != TC_TLV_OK)
      return copied;
    used += length;
  }
  TC_TLV_result result = tc_x509_crl_metadata_read(&fields, limits, tree, out);
  if (result == TC_TLV_OK && copies)
    *copies = fields;
  return result;
}
#endif
