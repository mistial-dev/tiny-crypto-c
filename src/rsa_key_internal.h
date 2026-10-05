/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_RSA_KEY_INTERNAL_H_
#define TC_RSA_KEY_INTERNAL_H_
#include <tiny_crypto/common.h>
#include <string.h>

/* RSA public-key shape over minimal big-endian magnitudes (RFC 8017 section
 * 3.1): n and e odd and 3 <= e < n. Readers of X.509 SubjectPublicKeyInfo,
 * card-verifiable certificates and RSA keys share this rule. The RSA layer
 * adds its modulus size policy. */
static inline int tc_rsa_public_shape_valid(TC_bytes modulus, TC_bytes exponent)
{
  return modulus.length && exponent.length && exponent.length <= modulus.length &&
         (modulus.data[modulus.length - 1] & 1) && (exponent.data[exponent.length - 1] & 1) &&
         !(exponent.length == 1 && exponent.data[0] < 3) &&
         !(exponent.length == modulus.length &&
           memcmp(exponent.data, modulus.data, modulus.length) >= 0);
}
#endif
