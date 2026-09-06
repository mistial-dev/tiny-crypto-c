/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TINY_CRYPTO_CONFIG_H_
#define TINY_CRYPTO_CONFIG_H_

/* Algorithm selection. Disabled translation units can be omitted entirely by
 * CMake, while these values also gate the umbrella headers. */
#ifndef TC_ENABLE_AES
#define TC_ENABLE_AES 1
#endif
#ifndef TC_ENABLE_DES
#define TC_ENABLE_DES 0
#endif
#ifndef TC_ENABLE_SHA1
#define TC_ENABLE_SHA1 0
#endif
#ifndef TC_ENABLE_SHA224
#define TC_ENABLE_SHA224 0
#endif
#ifndef TC_ENABLE_SHA256
#define TC_ENABLE_SHA256 1
#endif
#ifndef TC_ENABLE_SHA384
#define TC_ENABLE_SHA384 0
#endif
#ifndef TC_ENABLE_SHA512
#define TC_ENABLE_SHA512 0
#endif
#ifndef TC_ENABLE_HMAC
#define TC_ENABLE_HMAC 0
#endif
#ifndef TC_ENABLE_KMAC256
#define TC_ENABLE_KMAC256 0
#endif
/* SP 800-108 KBKDF over the enabled HMAC / CMAC PRFs (kdf.c). */
#ifndef TC_ENABLE_KDF
#define TC_ENABLE_KDF 0
#endif

/* Cross-algorithm security and embedded-storage policy.
 * TC_ZEROIZE: finalization wipes contexts and HMAC key-derived schedules,
 *   pads, and tags. Public-data hash schedules are not wiped on every block.
 *   CPU registers used as round working variables are not wiped.
 * TC_STRICT: streaming APIs reject NULL arguments (compiled out when 0).
 *   One-shot APIs always validate their arguments.
 * TC_AVR_PROGMEM: keep constant tables in AVR flash; 0 copies them into SRAM. */
#ifndef TC_ZEROIZE
#define TC_ZEROIZE 1
#endif
#ifndef TC_STRICT
#define TC_STRICT 1
#endif
#ifndef TC_AVR_PROGMEM
#define TC_AVR_PROGMEM 1
#endif
#if (TC_AVR_PROGMEM != 0) && (TC_AVR_PROGMEM != 1)
#error "TC_AVR_PROGMEM must be 0 or 1"
#endif
#ifndef TC_HMAC_MIN_TAG_LEN
#define TC_HMAC_MIN_TAG_LEN 16
#endif

/* AES defaults favor small constant-time firmware: one key schedule size,
 * CTR only, no authentication-mode workspaces or lookup tables. */
#ifndef TC_AES_KEY_BITS
#define TC_AES_KEY_BITS 128
#endif
#ifndef TC_AES_ENABLE_CBC
#define TC_AES_ENABLE_CBC 0
#endif
#ifndef TC_AES_ENABLE_ECB
#define TC_AES_ENABLE_ECB 0
#endif
#ifndef TC_AES_ENABLE_CTR
#define TC_AES_ENABLE_CTR 1
#endif
#ifndef TC_AES_ENABLE_OFB
#define TC_AES_ENABLE_OFB 0
#endif
#ifndef TC_AES_ENABLE_GCM
#define TC_AES_ENABLE_GCM 0
#endif
#ifndef TC_AES_ENABLE_CCM
#define TC_AES_ENABLE_CCM 0
#endif
#ifndef TC_AES_ENABLE_EAX
#define TC_AES_ENABLE_EAX 0
#endif
#ifndef TC_AES_ENABLE_EAX_PRIME
#define TC_AES_ENABLE_EAX_PRIME 0
#endif
#ifndef TC_AES_ENABLE_SIV
#define TC_AES_ENABLE_SIV 0
#endif
#ifndef TC_AES_ENABLE_CMAC
#define TC_AES_ENABLE_CMAC 0
#endif
#ifndef TC_AES_EAX_MIN_TAG_LEN
#define TC_AES_EAX_MIN_TAG_LEN 8
#endif
#ifndef TC_AES_CMAC_MIN_TAG_LEN
#define TC_AES_CMAC_MIN_TAG_LEN 8
#endif
#ifndef TC_AES_TINY
#define TC_AES_TINY 0
#endif
#ifndef TC_AES_GCM_GHASH_MODE
#define TC_AES_GCM_GHASH_MODE 0
#endif
#ifndef TC_AES_SBOX_MODE
#define TC_AES_SBOX_MODE 1
#endif
#ifndef TC_AES_WIDE_OPS
#define TC_AES_WIDE_OPS 0
#endif

/* DES defaults preserve the imported project's CTR and 3DES behavior. DES has
 * a 56-bit effective key and should only be used for legacy interoperability. */
#ifndef TC_DES_ENABLE_ECB
#define TC_DES_ENABLE_ECB 0
#endif
#ifndef TC_DES_ENABLE_CBC
#define TC_DES_ENABLE_CBC 0
#endif
#ifndef TC_DES_ENABLE_CTR
#define TC_DES_ENABLE_CTR 1
#endif
#ifndef TC_DES_ENABLE_OFB
#define TC_DES_ENABLE_OFB 0
#endif
#ifndef TC_DES_ENABLE_CFB1
#define TC_DES_ENABLE_CFB1 0
#endif
#ifndef TC_DES_ENABLE_CFB8
#define TC_DES_ENABLE_CFB8 0
#endif
#ifndef TC_DES_ENABLE_CFB64
#define TC_DES_ENABLE_CFB64 0
#endif
#ifndef TC_DES_ENABLE_TDES
#define TC_DES_ENABLE_TDES 1
#endif
#ifndef TC_DES_ENABLE_CMAC
#define TC_DES_ENABLE_CMAC 0
#endif
#ifndef TC_DES_REJECT_WEAK_KEYS
#define TC_DES_REJECT_WEAK_KEYS 0
#endif

#endif
