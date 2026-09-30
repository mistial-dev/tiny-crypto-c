/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_WORK_BUDGET_CHECK_H
#define TC_TEST_WORK_BUDGET_CHECK_H

/* Compile-time type checks for work budgets. Each check initializes a pointer
 * of the expected type, so a mismatch is an incompatible-pointer diagnostic
 * and tests/cmake/work_budget_width.cmake compiles with -Werror. Use the
 * checks inside a function body. They generate no code that runs. */

/* function must have exactly the type result(parameters). */
#define TC_EXPECT_FUNCTION(function, result, parameters)                                           \
  do {                                                                                             \
    result(*const tc_expected_function) parameters = (function);                                   \
    (void)tc_expected_function;                                                                    \
  } while (0)

/* object->member must have exactly the type type. */
#define TC_EXPECT_MEMBER(type, object, member)                                                     \
  do {                                                                                             \
    type* const tc_expected_member = &(object)->member;                                            \
    (void)tc_expected_member;                                                                      \
  } while (0)

#endif
