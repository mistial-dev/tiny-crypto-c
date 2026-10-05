<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# X.509 CRL parsing

Include `<tiny_crypto/x509_crl.h>` and enable `TINY_CRYPTO_ENABLE_X509_REVOCATION`.
`TC_X509_crl_read` reads a DER `CertificateList` into borrowed spans and decoded update times. It
parses only. Signature verification, signer trust, freshness, scope and base/delta selection happen
in [path revocation checking](x509-revocation.md).

Pass the encoded CRL, parsing limits, one frame per nesting level, a work budget and a result:

```c
enum { CRL_MAX_BYTES = 65536, CRL_MAX_ELEMENTS = 8192,
       CRL_MAX_DEPTH = 32, CRL_WORK = 1000000 };
TC_TLV_frame frames[CRL_MAX_DEPTH];
const TC_TLV_limits limits = {
    CRL_MAX_BYTES, CRL_MAX_BYTES, CRL_MAX_ELEMENTS, CRL_MAX_DEPTH
};
size_t work = CRL_WORK;
TC_X509_crl crl;
TC_TLV_result result = TC_X509_crl_read(
    encoded, &limits, (TC_TLV_frames){frames, CRL_MAX_DEPTH}, &work, &crl);
if (result != TC_TLV_OK) {
    /* Handle malformed input, exhausted limits or invalid arguments. */
    return result;
}
```

`encoded` is a `TC_bytes` holding one complete CRL. Choose limits for your issuer's CRLs, and keep
the frame array outside a small task stack if needed.

Result fields:

- `encoded` and `tbs`: the complete CRL and the signed TBSCertList.
- `issuer`: the DER Name.
- `signature`: the signature bytes without BIT STRING framing.
- `revoked` and `extensions`: their SEQUENCE encodings, empty when absent.
- `version`: 1 or 2.
- `next_update`: valid only when `has_next_update` is set.

Keep the input unchanged while using the result. Frames are reusable after the call. A failed call
leaves the result untouched and still consumes work. Overlap and failure rules follow
[Working with the API](api.md#input-stability-and-overlap).

## CRL extensions

`TC_X509_crl_extensions_read` decodes `crl.extensions` into a `TC_X509_crl_extensions` view, using a
`TC_X509_workspace`:

```c
enum { CRL_EXTENSION_CAPACITY = 16 };
TC_bytes extension_oids[CRL_EXTENSION_CAPACITY];
const TC_X509_workspace workspace = {
    {frames, CRL_MAX_DEPTH}, extension_oids, CRL_EXTENSION_CAPACITY
};
TC_X509_crl_extensions extensions;
result = TC_X509_crl_extensions_read(
    crl.extensions, &limits, &workspace, &work, &extensions);
if (result != TC_TLV_OK) {
    return result;
}
```

The OID array needs one slot per extension and detects duplicates. It is reusable after the call,
because returned spans borrow the CRL. An absent extension sequence gives an empty view.

- `present` and `critical`: `TC_X509_CRL_EXT_*` masks.
- `number` and `base_number`: DER INTEGER contents.
- `distribution`: the issuing distribution point, including reason and certificate-type limits.
- `freshest`: a CRLDistributionPoints sequence.
- `issuer_alt`: GeneralNames contents without the SEQUENCE wrapper.
- `unknown_critical_oid`: an unrecognized critical extension.

Revocation policy decides whether the decoded criticality and scope are acceptable.

## Indexing a collection

`TC_X509_crl_index_init` parses an array of DER spans into a caller-owned `TC_X509_crl_record`
array and a `TC_X509_crl_index`. Pass the parsing workspace above and one work budget for the
collection. Record capacity must cover every input span, and the parsing limits apply to each CRL.

```c
const TC_bytes inputs[] = {encoded};
TC_X509_crl_record records[1];
TC_X509_crl_index index;
work = CRL_WORK;
result = TC_X509_crl_index_init(inputs, 1, &limits, &workspace, &work,
                                records, 1, &index);
if (result != TC_TLV_OK) {
    return result;
}
```

The index borrows the record array, and each record borrows its CRL bytes. Keep both unchanged while
using the index. Frame and OID scratch are reusable after initialization. An empty collection
accepts NULL/0 input and record arrays.

A malformed CRL stops initialization and leaves the index result unchanged, with record storage
possibly partly written. Extension-policy failures stay in their records, so selection can try
alternatives later.

## File and flash sources

Include `<tiny_crypto/x509_crl_source.h>` for CRLs held outside RAM. A `TC_source` supplies a 64-bit
length and an exact read-at callback. The callback returns `TC_ERROR` for a short read or storage
failure, and preparation then returns `TC_TLV_IO`. Keep the source unchanged throughout preparation.

### Begin and step

`TC_X509_crl_prepare_begin` takes the source, the target serial/issuer pairs, limits and a
caller-owned workspace. `TC_X509_crl_prepare_size` and `TC_X509_crl_prepare_alignment` size its
state buffer, and `TC_X509_crl_storage` gives static storage the right alignment. The rest of the
workspace holds a read window, a metadata buffer, entry scratch, retained issuer storage,
parser/name scratch and one match slot per target.

Call `TC_X509_crl_prepare_step` until `complete` is set, refilling its per-call work budget before
each call. Read-byte and callback limits apply to the whole job. `max_entries` bounds entries
scanned per call and `max_bytes` bounds TBSCertList bytes hashed around them. Metadata and entry
limits are independent of the CRL size.

Preparation hashes the TBSCertList during the entry scan. Each entry is hashed from the bytes its
parser reads. The remaining bytes are read once, hashed and compared with the metadata and
crlExtensions copied by begin, or with the DER headers begin located. A source that returns
different bytes on a later read yields `TC_TLV_INVALID` or a digest that fails signature
verification.

A CRL whose extensions fail policy, such as an unknown critical extension, still prepares. Its
record keeps `TC_TLV_INVALID` or `TC_TLV_UNSUPPORTED` in `policy`, its entries stay unscanned and
every target is unmatched. The resolver skips that record, as it does for the same CRL from
`TC_X509_crl_index_init` (RFC 5280 section 5.2).

### Finish

`TC_X509_crl_prepare_finish` fills a `TC_X509_crl_record` for an index. Its digest and matches stay
in job storage. Include targets for every path member and candidate CRL signer whose revocation may
be checked. A target missing from the batch produces `TC_TLV_UNSUPPORTED`. Equal-number delta CRLs
with different retained hash algorithms produce `TC_TLV_UNSUPPORTED` when their signed contents
must be compared.

The certificate source must include the CRL signer certificates, including a root that signs a
CRL. Trust anchors supply trusted names and keys, and signer certificates supply the extensions used
in signer selection.

Keep job state, metadata, targets and matches unchanged until the last record use. Read-window,
entry, issuer and parser scratch are reusable after preparation. The record holds its evidence in
RAM, so the source can be released. Call `TC_X509_crl_prepare_clear` after releasing every borrowed
record. A preparation failure leaves scratch provisional and requires a new job.
