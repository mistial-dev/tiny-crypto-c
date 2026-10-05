<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# TWIC barcodes and privacy keys

Enable `TINY_CRYPTO_ENABLE_AAMVA` and `TINY_CRYPTO_ENABLE_TWIC_TPK`, then include
`<tiny_crypto/aamva.h>` and `<tiny_crypto/twic_tpk.h>`. TPK container parsing also needs
`TINY_CRYPTO_ENABLE_TLV`. The input is the raw output of the application's PDF417 decoder. The
formats are in AAMVA's DL/ID Card Design Standard, Annex D, and TSA's TWIC NEXGEN & Legacy Part 2
v5, sections 4.6.2 and 4.9.

## Reading the privacy key

Call `TC_AAMVA_subfile_find` with `"ZT"`, then `TC_AAMVA_field_find` with `"ZTA"` on that subfile.
Both return spans that borrow the barcode buffer. `TC_TLV_END` means the subfile or field is
absent. A repeated field is invalid.

The AAMVA reader checks ANSI directory framing and printable-ASCII text fields. It accepts empty
field values and an optional LF after a subfile designator. Dates, names and jurisdiction-specific
fields are left to the caller. Version 00 headers return `TC_TLV_UNSUPPORTED`. Historical versions
and non-ASCII decoding are outside the reader.

`TC_TWIC_tpk_read` decodes the key from one of three inputs:

- `TC_TWIC_TPK_BARCODE_HEX`: the ZTA value, a hexadecimal DFC101 container. The DCF101 prefix of
  TWIC's barcode example is also accepted.
- `TC_TWIC_TPK_CONTENTS`: the `53` value of a card GET DATA response, holding the C0/C1/C2 fields.
- `TC_TWIC_TPK_CARD`: a complete binary `DFC101` TLV.

The container length must equal its C0/C1/C2 fields. The section 4.9 example prints a length of
`28` for 24 content bytes, so it returns `TC_TLV_INVALID`. The decoder checks the C0 key, C1
algorithm and C2 key-index fields before returning an AES-128 key.

The result owns its 16 key bytes. Wipe it with `TC_secure_zero(&key, sizeof key)` after use, along
with any buffers holding the barcode or decoded objects. Errors preserve the output. Output storage
must be separate from the input.

The barcode supplies key material only. Authenticate a decrypted object's signature and signer
path before using its identity or biometric data.

## Object encryption

Enable `TINY_CRYPTO_ENABLE_TWIC_OBJECT_CRYPTO`, AES, ECB mode and 128-bit AES keys. Object
encryption is independent of the TPK reader. With the runtime S-box profile, call
`TC_AES_init_sbox()` once at startup, before any TWIC encryption, decryption or concurrent crypto
operation. An uninitialized S-box produces a processing error.

`TC_TWIC_object_decrypt` decrypts an enciphered object's `BC` value in place. Pass the complete
nonempty, block-aligned ciphertext as a `TC_buffer` and separate output-length storage. It checks
PKCS#7 padding across the final block, wipes the padding, and returns the plaintext length. Invalid
padding or a processing error wipes the whole buffer. Bad arguments leave it unchanged. Treat the
plaintext as untrusted until its signature and credential checks succeed.

`TC_TWIC_object_encrypt` pads and encrypts in place. Pass a `TC_buffer` with up to
`TC_AES_BLOCKLEN` spare bytes, since aligned input gains a full padding block, then the plaintext
length. The output length includes padding. Empty plaintext is supported. Bad arguments leave the
buffer and output length unchanged. Processing failures wipe the padded region.

Build and sign a signed object type before encrypting it. TWIC enciphered printed information
(`DFC109`) has no signature block, so its decrypted fields carry no authenticated identity.
