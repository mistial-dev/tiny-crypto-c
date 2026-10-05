/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC application rules for the PIV card commands (TWIC Part 2 v5). */
#ifndef TC_TWIC_COMMAND_INTERNAL_H_
#define TC_TWIC_COMMAND_INTERNAL_H_
#include <tiny_crypto/piv_command.h>

#if TC_ENABLE_TWIC && TC_ENABLE_PIV_COMMAND
/* Frame a TWIC GET DATA answer: 53 or the requested tag. 53 00, TAG 00 and,
 * for a constructed tag, TAG 02 80 00 are empty (section 3.3.6). A 6282
 * answer may carry padding after the object (section 5.2). An optional
 * object that is not initialized may answer 9000 without data, which gives
 * TC_PIV_FORM_NONE (section 4.5). */
TC_TLV_result tc_twic_object_frame(TC_bytes data, uint16_t sw, TC_bytes tag,
                                   const TC_TLV_limits* limits, TC_PIV_data_object* out);
#endif
#endif
