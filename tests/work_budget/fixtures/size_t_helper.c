/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* Negative fixture for every -Werror build. A helper that takes size_t* for
 * the budget cannot receive &budget->remaining without an incompatible
 * pointer diagnostic. TC_FIXTURE_CORRECT selects the accepted form. */
#include <tiny_crypto/common.h>

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
  return consume(&budget->remaining, cost);
}
