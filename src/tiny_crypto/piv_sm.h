/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Client-side PIV secure messaging: key establishment, key confirmation and
 * command and response protection for cipher suites 2 and 7.
 * Standards: SP 800-73-5 Part 2 section 4, SP 800-56A Rev. 3, SP 800-38B.
 * Configuration: TC_ENABLE_PIV_SM, TC_PIV_SM_ENABLE_CS2 and
 * TC_PIV_SM_ENABLE_CS7.
 * Limitations: APDU framing, chaining and status words belong to the
 * application. CVC authentication is in piv_sm_authenticate.h.
 * Contracts: docs/api.md. Guide: docs/piv-sm.md. */
#ifndef TINY_CRYPTO_PIV_SM_H_
#define TINY_CRYPTO_PIV_SM_H_
#include <tiny_crypto/aes_dynamic.h>
#include <tiny_crypto/ec.h>

#if TC_PIV_SM_ENABLE_CS7
#define TC_PIV_SM_KEY_BYTES 32
#define TC_PIV_SM_COORDINATE_BYTES 48
#else
#define TC_PIV_SM_KEY_BYTES 16
#define TC_PIV_SM_COORDINATE_BYTES 32
#endif

#define TC_PIV_SM_AUTHENTICATED_SPANS_MAX 8

typedef enum { TC_PIV_SM_CS2 = 0x27, TC_PIV_SM_CS7 = 0x2e } TC_PIV_SM_suite;
/* IDLE holds no session. ESTABLISHING follows begin and awaits finish. READY
 * accepts one protect call. PENDING awaits the response to that command. */
typedef enum {
  TC_PIV_SM_IDLE = 0,
  TC_PIV_SM_ESTABLISHING,
  TC_PIV_SM_READY,
  TC_PIV_SM_PENDING
} TC_PIV_SM_state;

/* Zero-initialize before first use. Treat members as private and read the
 * state with TC_PIV_SM_get_state. Never copy a live session, because the copy
 * would reuse keys and counters. Clear when the card is removed or transport
 * delivery becomes uncertain. */
typedef struct {
  union {
    struct {
      uint8_t scalar[TC_PIV_SM_COORDINATE_BYTES];
      uint8_t public_key[1 + 2 * TC_PIV_SM_COORDINATE_BYTES], host_id[8];
    } handshake;
    struct {
      uint8_t mac_key[TC_PIV_SM_KEY_BYTES], enc_key[TC_PIV_SM_KEY_BYTES],
          rmac_key[TC_PIV_SM_KEY_BYTES];
      uint8_t counter[16], command_mcv[16], response_mcv[16];
    } traffic;
  } data;
  uint8_t suite, state;
} TC_PIV_SM;

typedef struct {
  union {
    TC_EC_workspace ec;
    struct {
      union {
        TC_AES_dynamic_key aes;
        TC_AES_dynamic_CMAC cmac;
      } cipher;
      uint8_t material[4 * TC_PIV_SM_KEY_BYTES], digest[32], block[16];
    } symmetric;
  } operation;
  uint8_t secret[TC_PIV_SM_COORDINATE_BYTES];
} TC_PIV_SM_workspace;

/* Fields emitted by session setup. Spans borrow session storage and remain
 * valid until the session changes or is cleared. Protocol encoders decide how
 * these fields are carried. */
typedef struct {
  TC_bytes host_identifier, public_key;
  TC_PIV_SM_suite suite;
} TC_PIV_SM_handshake;

/* Peer fields decoded from the card's key establishment response
 * (SP 800-73-5 Part 2 section 4.1, step C11). certificate is the exact encoded
 * CVC used by the key-derivation transcript. card_control is the received
 * CB_ICC byte. Pass it unchanged so finish can check it and bind it into
 * OtherInfo. */
typedef struct {
  TC_bytes certificate, nonce, cryptogram;
  uint8_t card_control;
} TC_PIV_SM_peer;

/* authenticated is an ordered list of already-framed bytes. It may include
 * the ciphertext output span so a protocol layer can authenticate its encoded
 * header, ciphertext and trailing fields without copying. */
typedef struct {
  TC_bytes plaintext;
  uint8_t* ciphertext;
  size_t ciphertext_capacity;
  const TC_bytes* authenticated;
  size_t authenticated_count;
} TC_PIV_SM_protect_request;

typedef struct {
  TC_bytes ciphertext, tag;
  const TC_bytes* authenticated;
  size_t authenticated_count;
} TC_PIV_SM_unprotect_request;

#ifdef __cplusplus
extern "C" {
#endif

/* Keep writable objects disjoint from each other and from inputs, except for
 * protect's ciphertext spans. Sessions retain no input pointers.
 *
 * The status-returning functions return TC_ERROR for NULL, overlapping or
 * malformed arguments and for a call made in the wrong state. Those argument
 * errors leave the session, workspace and outputs unchanged. Causes listed
 * under a function as after validation instead end the session. Every other
 * return wipes the used workspace and leaves the session in the state named
 * for that result. */

/* Wipe session keys and counters and return to IDLE. Accepts NULL. */
void TC_PIV_SM_clear(TC_PIV_SM* session);

/* Return the session state. NULL reports TC_PIV_SM_IDLE. Callers use it to
 * tell a retryable unprotect result from one that ended the session. */
TC_PIV_SM_state TC_PIV_SM_get_state(const TC_PIV_SM* session);

/* Start a new session and return the fields needed by a protocol handshake.
 * Any state is accepted. Valid arguments discard any previous session.
 * TC_OK: ESTABLISHING. handshake borrows session storage.
 * TC_ERROR after validation: a failed RNG or 16 rejected scalars leaves the
 * session IDLE and handshake unchanged. */
TC_status TC_PIV_SM_begin(TC_PIV_SM* session, TC_PIV_SM_suite suite, const uint8_t host_id[8],
                          TC_random_source random, TC_PIV_SM_handshake* handshake,
                          TC_PIV_SM_workspace* workspace);

/* Authenticate the peer key through the application's trust workflow, then
 * pass that key and the unchanged decoded peer fields here. Requires
 * ESTABLISHING.
 * TC_OK: READY with fresh session keys.
 * TC_MISMATCH: the key-confirmation cryptogram differs. IDLE.
 * TC_ERROR after validation: IDLE. Causes are a nonzero card_control, missing
 * peer fields, peer field or key lengths that do not match the suite, an
 * invalid peer key and KDF failure. */
TC_status TC_PIV_SM_finish(TC_PIV_SM* session, const TC_PIV_SM_peer* peer,
                           TC_bytes authenticated_key, TC_PIV_SM_workspace* workspace);

/* Store the padded ciphertext size for plaintext_length. Padding always adds
 * 1 to 16 bytes, so a multiple of 16 grows by a full block. Empty plaintext
 * has an empty ciphertext. Returns TC_ERROR for a NULL output or when the size
 * exceeds SIZE_MAX, leaving *ciphertext_length unchanged. */
TC_status TC_PIV_SM_ciphertext_size(size_t plaintext_length, size_t* ciphertext_length);

/* Encrypt plaintext and authenticate the supplied ordered spans. The caller
 * owns all protocol framing and places the ciphertext span in authenticated
 * where its protocol requires it. Ciphertext storage may overlap authenticated
 * spans. Keep plaintext separate. Requires READY, so only one protected request
 * may be pending. A ciphertext_capacity below TC_PIV_SM_ciphertext_size is an
 * argument error.
 * TC_OK: PENDING. Writes ciphertext, *ciphertext_length and tag.
 * TC_ERROR after validation: IDLE with ciphertext wiped. Causes are an
 * exhausted message counter and cipher failure. */
TC_status TC_PIV_SM_protect(TC_PIV_SM* session, const TC_PIV_SM_protect_request* request,
                            size_t* ciphertext_length, uint8_t tag[8],
                            TC_PIV_SM_workspace* workspace);

/* Authenticate ordered response spans, then decrypt and check padding.
 * Plaintext is released only after authentication. Requires PENDING.
 * TC_OK: READY. Writes plaintext and *plaintext_length.
 * TC_MISMATCH: the response tag differs. IDLE.
 * TC_ERROR with state PENDING: an argument error, or capacity below the
 * authenticated plaintext length. The session and outputs are unchanged, so
 * the same response can be retried with corrected arguments or a larger
 * buffer. A capacity of request->ciphertext.length always suffices.
 * TC_ERROR with state IDLE: malformed padding, an exhausted counter or cipher
 * failure. *plaintext_length is unchanged and written plaintext is wiped. */
TC_status TC_PIV_SM_unprotect(TC_PIV_SM* session, const TC_PIV_SM_unprotect_request* request,
                              uint8_t* plaintext, size_t capacity, size_t* plaintext_length,
                              TC_PIV_SM_workspace* workspace);

#ifdef __cplusplus
}
#endif
#endif
