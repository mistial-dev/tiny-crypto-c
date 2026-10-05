<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# TLV parsing

Enable `TINY_CRYPTO_ENABLE_TLV=ON` and include `<tiny_crypto/tlv.h>`. Every call names its
encoding: DER, ISO 7816 or BER. BER also needs `TINY_CRYPTO_TLV_ENABLE_BER=ON`.

`TC_TLV_read` reads one definite-length object and leaves its children unchecked.
`TC_TLV_read_tree` also checks constructed boundaries and handles indefinite BER lengths. Both stop
before the next sibling and return spans into the input, which follow the
[borrowed-span rules](api.md#buffers-and-lifetimes). A span with NULL data and a nonzero length
returns `TC_TLV_ARGUMENT`.

```c
#include <tiny_crypto/tlv.h>

TC_TLV_result read_ber_object(TC_bytes input, TC_TLV_element* object)
{
    enum { MAX_BYTES = 4096, MAX_ELEMENTS = 128, MAX_DEPTH = 8 };
    const TC_TLV_limits limits = {MAX_BYTES, MAX_BYTES, MAX_ELEMENTS, MAX_DEPTH};
    TC_TLV_frame frames[MAX_DEPTH];

    return TC_TLV_read_tree(input, TC_TLV_BER, &limits,
                            (TC_TLV_frames){frames, MAX_DEPTH}, object);
}
```

Decoders that validate nesting take caller-owned frame storage as `TC_TLV_frames`, an array and
its capacity. They use one frame per constructed nesting level, so `limits.max_depth` frames
always suffice. Frames are scratch and may change on failure.

| Result            | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| `TC_TLV_OK`       | `object` is written.                                     |
| `TC_TLV_MORE`     | The object is truncated. Supply more input or reject it. |
| `TC_TLV_INVALID`  | Bad framing.                                             |
| `TC_TLV_LIMIT`    | A configured resource bound was exceeded.                |
| `TC_TLV_ARGUMENT` | Invalid arguments.                                       |

Errors leave `object` unchanged. ISO/IEC 7816-4:2020 section 6.3 allows length fields of one to
five bytes, so the ISO 7816 profiles report a first length byte of `85` to `FE` as
`TC_TLV_INVALID`. BER and DER report more length octets than the length type holds as
`TC_TLV_LIMIT` (X.690 section 8.1.3.5).

`object.encoded` spans the whole object, including any end-of-contents bytes. `object.value`
excludes the outer header and end-of-contents bytes, so `value.length` gives the content size of
an indefinite object. `header.length` holds the encoded length field, which the indefinite form
omits. To require exactly one object, check that `encoded.length` equals the input length.

## Sibling readers

`TC_TLV_reader_init` starts a root reader over a complete data field or payload. `TC_TLV_next`
returns one sibling per call and leaves its value unread. `TC_TLV_reader_child` opens a child
reader over a constructed element's template. The child borrows the element value, inherits the
parent's profile and limits, and starts its own element count. Start every reader with one of
these two functions.

The padded ISO 7816 profiles skip `00` (and `FF` for `TC_TLV_ISO7816_PAD_ZERO_FF`) in root readers
only. ISO/IEC 7816-4:2020 sections 8.1.2 and 8.1.3 permit padding between root data objects, and
section 6.4 requires a constructed template to hold nested data objects without padding. A child
reader therefore returns `TC_TLV_INVALID` for a padding byte. A child template is a complete
value, so a truncated nested element also returns `TC_TLV_INVALID`. `TC_TLV_reader_init` on a value
span creates a root reader, so open nested templates with `TC_TLV_reader_child`.

```c
#include <tiny_crypto/tlv.h>

/* Count the data objects inside each template of a padded response. */
TC_TLV_result count_nested(TC_bytes response, size_t* nested)
{
    enum { MAX_BYTES = 1024, MAX_ELEMENTS = 64, MAX_DEPTH = 4 };
    const TC_TLV_limits limits = {MAX_BYTES, MAX_BYTES, MAX_ELEMENTS, MAX_DEPTH};
    TC_TLV_reader root, child;
    TC_TLV_element object, inner;
    TC_TLV_result result;
    size_t count = 0;

    result = TC_TLV_reader_init(&root, response, TC_TLV_ISO7816_PAD_ZERO_FF,
                                &limits);
    while (result == TC_TLV_OK &&
           (result = TC_TLV_next(&root, &object)) == TC_TLV_OK) {
        if (!object.header.constructed)
            continue;
        result = TC_TLV_reader_child(&child, &root, &object);
        while (result == TC_TLV_OK &&
               (result = TC_TLV_next(&child, &inner)) == TC_TLV_OK)
            ++count;
        if (result == TC_TLV_END)
            result = TC_TLV_OK;
    }
    if (result != TC_TLV_END)
        return result; /* MORE here means a truncated response. */
    *nested = count;
    return TC_TLV_OK;
}
```

`TC_TLV_next` returns `TC_TLV_END` when no siblings remain. A root reader returns `TC_TLV_MORE`
when the next element is truncated. Failures leave the reader and element unchanged.

## Whole-tree traversal

`TC_TLV_walk` traverses a whole tree or sequence of roots without heap allocation. It visits
borrowed primitive chunks and applies one element and depth budget across the input. Every event
span points into the walked input at the event offset, so a visitor may keep BEGIN headers, VALUE
chunks and EOC markers while that input stays alive and unchanged.

With `TINY_CRYPTO_TLV_ENABLE_STREAM=ON`, the incremental stream API provides the same traversal
for fragmented input. Stream events borrow the fed chunk. A header or EOC split across two chunks
comes from stream storage and stays valid only during the callback.

These APIs check framing. A well-framed DER object can still hold an invalid INTEGER, an unordered
SET or a missing certificate field. The typed [DER readers](der.md) and object parsers check
those.
