/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* Negative fixture for the 16-bit narrowing build. A size_t alias copies the
 * 32-bit budget, which truncates it where size_t is 16 bits. -Wconversion
 * rejects the copy. TC_FIXTURE_CORRECT selects the accepted form. */
#include <tiny_crypto/common.h>

#ifdef TC_FIXTURE_CORRECT
typedef uint32_t tc_fixture_units;
#else
typedef size_t tc_fixture_units;
#endif

int tc_fixture_charge(TC_work_budget* budget, uint32_t cost);

int tc_fixture_charge(TC_work_budget* budget, uint32_t cost)
{
  const tc_fixture_units left = budget->remaining;
  if (left < cost)
    return 0;
  budget->remaining = left - cost;
  return 1;
}
