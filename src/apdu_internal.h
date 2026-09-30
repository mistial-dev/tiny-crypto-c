/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Command field layout shared by TC_APDU_command_encode and the channel. */
#ifndef TC_APDU_INTERNAL_H_
#define TC_APDU_INTERNAL_H_
#include <tiny_crypto/apdu.h>

/* CLA bits of the first interindustry values (ISO/IEC 7816-4 5.4.1 Table 2). */
enum {
  TC_APDU_CLA_CLASS_MASK = 0xe0, /* 000x xxxx: first interindustry values */
  TC_APDU_CLA_CHAINING = 0x10,   /* b5: not the last command of a chain */
  TC_APDU_CLA_SM_MASK = 0x0c,    /* b4 b3: secure messaging indication */
  TC_APDU_CLA_CHANNEL_MASK = 0x03
};

/* Encoded form of one command: its size and whether Lc and Le use the
 * extended fields. */
typedef struct {
  size_t size;
  uint8_t extended;
} tc_apdu_form;

/* UNSUPPORTED for a CLA outside the first interindustry values, ARGUMENT for
 * CLA b5, which the channel owns. */
TC_APDU_result tc_apdu_class_check(uint8_t cla);
/* Choose the form for nc data bytes and ne expected bytes (ISO/IEC 7816-4
 * 5.2). ARGUMENT for an unknown format or values outside the format, LIMIT
 * for a size above SIZE_MAX. Ignores CLA. */
TC_APDU_result tc_apdu_form_get(size_t nc, uint32_t ne, TC_APDU_length_format format,
                                tc_apdu_form* out);
/* Write command in form to out, which holds form->size bytes and is
 * disjoint from the command data. */
void tc_apdu_write(const TC_APDU_command* command, const tc_apdu_form* form, uint8_t* out);
#endif
