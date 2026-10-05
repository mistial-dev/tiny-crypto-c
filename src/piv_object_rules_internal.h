/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Profile rules of the facial image and certificate container readers. */
#ifndef TC_PIV_OBJECT_RULES_INTERNAL_H_
#define TC_PIV_OBJECT_RULES_INTERNAL_H_
#include <tiny_crypto/piv_biometric.h>
#include <tiny_crypto/piv_certificate.h>

#if TC_ENABLE_PIV_OBJECTS
/* Lower bounds for an INCITS 385-2004 image block: expression (1 neutral,
 * at most 1 in every profile), image type (1 Full Frontal, at most 1) and
 * width in pixels. */
typedef struct {
  uint8_t expression_min;
  uint8_t image_type_min;
  uint16_t width_min;
} tc_piv_face_rules;

/* Optional elements of a certificate container after 70 and 71.
 * intermediate_cvc  a 7F21 intermediate CVC may precede FE.
 * mscuid            a 72 MSCUID may precede FE.
 * end_optional      the container may end without FE. */
typedef struct {
  uint8_t intermediate_cvc;
  uint8_t mscuid;
  uint8_t end_optional;
} tc_piv_certificate_rules;

/* Rules of a certificate profile, or NULL for an unknown one. */
const tc_piv_certificate_rules* tc_piv_certificate_rules_get(TC_PIV_certificate_profile profile);
#endif
#endif
