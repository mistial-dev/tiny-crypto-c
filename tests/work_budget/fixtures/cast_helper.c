/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* Negative fixture for the type guard. A pointer cast at the call site hides
 * a helper that takes size_t* from the compiler, so the call compiles. The
 * TC_EXPECT_FUNCTION check on the helper's declaration rejects it.
 * TC_FIXTURE_CORRECT selects the accepted form. */
#include <tiny_crypto/common.h>
#include "check.h"

#ifdef TC_FIXTURE_CORRECT
typedef uint32_t tc_fixture_units;
#else
typedef size_t tc_fixture_units;
#endif

static int consume(tc_fixture_units* work, uint32_t cost)
{
  if (*work < cost)
    return 0;
  *work -= cost;
  return 1;
}

int tc_fixture_charge(TC_work_budget* budget, uint32_t cost);

int tc_fixture_charge(TC_work_budget* budget, uint32_t cost)
{
  TC_EXPECT_FUNCTION(consume, int, (uint32_t*, uint32_t));
  return consume((tc_fixture_units*)&budget->remaining, cost);
}
