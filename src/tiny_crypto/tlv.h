/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_TLV_H_
#define TINY_CRYPTO_TLV_H_

#include <tiny_crypto/common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  TC_TLV_OK = 0,
  TC_TLV_END = 1,
  TC_TLV_MORE = 2,
  TC_TLV_INVALID = -1,
  TC_TLV_LIMIT = -2,
  TC_TLV_UNSUPPORTED = -3,
  TC_TLV_ARGUMENT = -4,
  TC_TLV_IO = -5 /* Backing storage could not supply the requested bytes. */
} TC_TLV_result;

typedef enum {
  TC_TLV_DER = 0,
  TC_TLV_ISO7816 = 1,
  TC_TLV_BER = 2,
  /* ISO/IEC 7816-4 section 8.1.2 padding bytes, accepted only between root
   * objects. Section 6.4 forbids padding inside a constructed template. */
  TC_TLV_ISO7816_PAD_ZERO = 3,
  TC_TLV_ISO7816_PAD_ZERO_FF = 4
} TC_TLV_profile;

typedef struct {
  /* All limits are inclusive. Zero allows no bytes/elements/constructed
   * levels, not unlimited input. Indefinite values exclude their own EOC. */
  size_t max_input, max_value, max_elements, max_depth;
} TC_TLV_limits;

/* Up to a 32-bit ASN.1 tag number. Raw tag bytes retain class and encoding:
 * the on-card tag 7F21 has ASN.1 tag number 0x21.
 * ISO 7816 limits tags to three bytes. ASN.1 can use up to six here. */
#define TC_TLV_TAG_BYTES 6
#define TC_TLV_HEADER_BYTES (TC_TLV_TAG_BYTES + 1 + sizeof(size_t))
typedef struct {
  uint32_t number;
  size_t length;
  uint8_t tag[TC_TLV_TAG_BYTES];
  uint8_t tag_length, header_length, tag_class, constructed, indefinite;
} TC_TLV_header;

typedef struct {
  TC_TLV_header header;
  TC_bytes encoded, value;
} TC_TLV_element;

/* Input must remain alive and unchanged while any returned span is used.
 * Input, parser state, frame storage, and output structs must not overlap.
 * Failure leaves every output unchanged. Header parsing reads only the tag and length.
 * MORE requests additional bytes. At the end of a message, it means truncation.
 * DER here checks framing only. Typed/schema checks are separate. */
TC_TLV_result TC_TLV_header_read(const uint8_t* data, size_t length, TC_TLV_profile profile,
                                 const TC_TLV_limits* limits, TC_TLV_header* out);
/* A shallow, definite-length read. Use walk/stream for indefinite BER. */
TC_TLV_result TC_TLV_read(const uint8_t* data, size_t length, TC_TLV_profile profile,
                          const TC_TLV_limits* limits, TC_TLV_element* out);

/* Sibling cursor over borrowed input. Treat members as read-only and start it
 * with TC_TLV_reader_init or TC_TLV_reader_child. root is set by
 * TC_TLV_reader_init and cleared by TC_TLV_reader_child. Only a root reader
 * skips padding for the padded ISO 7816 profiles. */
typedef struct {
  TC_bytes input;
  TC_TLV_limits limits;
  size_t offset, elements;
  TC_TLV_profile profile;
  uint8_t root;
} TC_TLV_reader;
/* Start a root reader over a complete data field or payload. Limits are copied.
 * Returns ARGUMENT for NULL reader/limits, NULL data with a length or an
 * unknown profile, UNSUPPORTED for BER when disabled and LIMIT when length
 * exceeds max_input. Failure leaves reader unchanged. */
TC_TLV_result TC_TLV_reader_init(TC_TLV_reader* reader, const uint8_t* data, size_t length,
                                 TC_TLV_profile profile, const TC_TLV_limits* limits);
/* Start a reader over the template of an element read from parent. The child
 * inherits the parent's profile and limits, starts its own element count and
 * rejects padding. Its template is complete, so a truncated nested element
 * returns INVALID. The element value must lie inside the parent input.
 * Returns ARGUMENT for NULL pointers or an element outside the parent, and
 * leaves child unchanged on failure. child may reuse the parent's storage. */
TC_TLV_result TC_TLV_reader_child(TC_TLV_reader* child, const TC_TLV_reader* parent,
                                  const TC_TLV_element* element);
/* Read the next sibling. END means no more siblings. MORE means a root
 * reader's next element is truncated. INVALID covers bad framing, and padding
 * or truncation in a child reader. LIMIT means max_elements or max_value was
 * exceeded. Failure leaves reader and out unchanged. Use walk to enforce a
 * shared budget across an entire tree. */
TC_TLV_result TC_TLV_next(TC_TLV_reader* reader, TC_TLV_element* out);

typedef enum { TC_TLV_BEGIN, TC_TLV_VALUE, TC_TLV_CLOSE } TC_TLV_event_kind;
typedef struct {
  TC_TLV_event_kind kind;
  size_t offset, depth;
  /* Header is populated for BEGIN only. bytes contains the exact header.
   * VALUE borrows a chunk of primitive content. CLOSE bytes is empty for
   * definite objects, or the two EOC bytes for indefinite objects.
   * TC_TLV_walk spans borrow its input, with bytes.data at input + offset.
   * A stream span borrows the fed chunk, except a header or EOC split across
   * chunks, which borrows stream storage for the callback's duration only. */
  TC_TLV_header header;
  TC_bytes bytes;
} TC_TLV_event;
typedef void (*TC_TLV_visit)(void* user, const TC_TLV_event* event);

typedef struct {
  size_t end, bound, start;
  uint8_t indefinite, resource_bound;
} TC_TLV_frame;

/* Caller-owned nesting storage for one decode: capacity frames at data. A
 * decode needs one frame per constructed nesting level. The frames are
 * scratch, may change on failure and must not overlap the input. */
typedef struct {
  TC_TLV_frame* data;
  size_t capacity;
} TC_TLV_frames;

/* Treat members as private after init. Frames are caller-owned and must not
 * alias input or the stream. Callbacks must not modify/reenter the parser.
 * Wait for finish to succeed before acting on events. */
typedef struct {
  TC_TLV_limits limits;
  TC_TLV_frame* frames;
  size_t capacity, depth, offset, elements, remaining;
  TC_TLV_profile profile;
  TC_TLV_result error;
  uint8_t header[TC_TLV_HEADER_BYTES];
  uint8_t used, primitive, finished;
} TC_TLV_stream;

#if TC_TLV_ENABLE_STREAM
TC_TLV_result TC_TLV_stream_init(TC_TLV_stream* stream, TC_TLV_profile profile,
                                 const TC_TLV_limits* limits, TC_TLV_frames frames);
/* Consumes a chunk without retaining its address. Callbacks borrow spans only
 * for their duration. After an error, call init before reusing the stream.
 * Events emitted before an error remain emitted.
 * OK/MORE both consume the entire chunk. MORE means an object is unfinished.
 * Discard the message on error. */
TC_TLV_result TC_TLV_stream_feed(TC_TLV_stream* stream, const uint8_t* data, size_t length,
                                 TC_TLV_visit visit, void* user);
TC_TLV_result TC_TLV_stream_finish(TC_TLV_stream* stream);
#endif
/* Walk checks all constructed boundaries with one shared element/depth budget.
 * Event spans borrow data and stay valid while data is alive and unchanged.
 * A sequence of root objects is accepted. A schema needing exactly one root
 * must check that separately. NULL visit validates framing without callbacks. */
TC_TLV_result TC_TLV_walk(const uint8_t* data, size_t length, TC_TLV_profile profile,
                          const TC_TLV_limits* limits, TC_TLV_frames frames, TC_TLV_visit visit,
                          void* user);

/* Read one complete object and validate its constructed boundaries. Supports
 * indefinite BER and leaves following siblings unread. Returned spans borrow
 * input. encoded includes EOC and value excludes it. MORE means truncation.
 * Frames may change on failure. out changes only on OK. Input, limits, frames
 * and out must be disjoint. Root padding after the object is left unread. */
TC_TLV_result TC_TLV_read_tree(const uint8_t* data, size_t length, TC_TLV_profile profile,
                               const TC_TLV_limits* limits, TC_TLV_frames frames,
                               TC_TLV_element* out);

#ifdef __cplusplus
}
#endif
#endif
