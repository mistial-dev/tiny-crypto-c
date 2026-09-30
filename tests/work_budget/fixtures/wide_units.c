/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* Negative fixture for the type guard. A budget structure whose counter
 * becomes size_t compiles everywhere once every user changes with it. The
 * TC_EXPECT_MEMBER check on the counter rejects it. TC_FIXTURE_CORRECT
 * selects the accepted form. */
#include <tiny_crypto/common.h>
#include "check.h"

typedef struct {
#ifdef TC_FIXTURE_CORRECT
  uint32_t remaining;
#else
  size_t remaining;
#endif
} tc_fixture_budget;

void tc_fixture_types(tc_fixture_budget* budget);

void tc_fixture_types(tc_fixture_budget* budget)
{
  TC_EXPECT_MEMBER(uint32_t, budget, remaining);
}
