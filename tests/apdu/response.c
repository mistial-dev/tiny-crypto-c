/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Response APDU reading and status classes: ISO/IEC 7816-4:2020 5.6. */
#include <tiny_crypto/apdu.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

TC_TEST(valid_responses)
{
  static const uint8_t success[] = {0x53, 0x00, 0x90, 0x00};
  static const uint8_t more[] = {0xaa, 0xbb, 0x61, 0x10};
  static const uint8_t warning[] = {0x01, 0x62, 0x82};
  static const uint8_t proprietary[] = {0x91, 0x23};
  static const uint8_t status_only[] = {0x6a, 0x82};
  TC_APDU_response response;
  munit_assert_int(TC_APDU_response_read((TC_bytes){success, sizeof success}, &response), ==,
                   TC_APDU_OK);
  munit_assert_ptr_equal(response.data.data, success);
  munit_assert_size(response.data.length, ==, 2);
  munit_assert_uint16(response.sw, ==, 0x9000);
  munit_assert_int(TC_APDU_response_read((TC_bytes){more, sizeof more}, &response), ==, TC_APDU_OK);
  munit_assert_uint16(response.sw, ==, 0x6110);
  /* Warnings may carry data (5.6). */
  munit_assert_int(TC_APDU_response_read((TC_bytes){warning, sizeof warning}, &response), ==,
                   TC_APDU_OK);
  munit_assert_size(response.data.length, ==, 1);
  munit_assert_int(TC_APDU_response_read((TC_bytes){proprietary, sizeof proprietary}, &response),
                   ==, TC_APDU_OK);
  munit_assert_uint16(response.sw, ==, 0x9123);
  munit_assert_int(TC_APDU_response_read((TC_bytes){status_only, sizeof status_only}, &response),
                   ==, TC_APDU_OK);
  munit_assert_size(response.data.length, ==, 0);
  munit_assert_uint16(response.sw, ==, 0x6a82);
  return MUNIT_OK;
}

TC_TEST(invalid_responses)
{
  static const uint8_t short_bytes[] = {0x90};
  static const uint8_t invalid_sw[][2] = {{0x60, 0x00}, {0x60, 0xff}, {0x00, 0x00}, {0x50, 0x00},
                                          {0x70, 0x00}, {0x8f, 0xff}, {0xa0, 0x00}, {0xff, 0xff}};
  static const uint8_t errors_with_data[][3] = {{0x01, 0x64, 0x00}, {0x01, 0x66, 0x00},
                                                {0x01, 0x69, 0x82}, {0x01, 0x6a, 0x82},
                                                {0x01, 0x6c, 0x10}, {0x01, 0x6f, 0x00}};
  TC_APDU_response response = {{short_bytes, 99}, 0x1234};
  munit_assert_int(TC_APDU_response_read((TC_bytes){short_bytes, sizeof short_bytes}, &response),
                   ==, TC_APDU_INVALID);
  munit_assert_int(TC_APDU_response_read((TC_bytes){NULL, 0}, &response), ==, TC_APDU_INVALID);
  for (size_t i = 0; i < sizeof invalid_sw / sizeof *invalid_sw; ++i)
    munit_assert_int(TC_APDU_response_read((TC_bytes){invalid_sw[i], 2}, &response), ==,
                     TC_APDU_INVALID);
  for (size_t i = 0; i < sizeof errors_with_data / sizeof *errors_with_data; ++i)
    munit_assert_int(TC_APDU_response_read((TC_bytes){errors_with_data[i], 3}, &response), ==,
                     TC_APDU_INVALID);
  munit_assert_size(response.data.length, ==, 99);
  munit_assert_uint16(response.sw, ==, 0x1234);
  return MUNIT_OK;
}

TC_TEST(argument_errors)
{
  static const uint8_t bytes[] = {0x90, 0x00};
  TC_APDU_response storage[2];
  memset(storage, 0x90, sizeof storage);
  TC_APDU_response response = {{NULL, 7}, 0x4321};
  munit_assert_int(TC_APDU_response_read((TC_bytes){bytes, 2}, NULL), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_response_read((TC_bytes){NULL, 2}, &response), ==, TC_APDU_ARGUMENT);
  munit_assert_size(response.data.length, ==, 7);
  /* out inside the encoded bytes. */
  munit_assert_int(
      TC_APDU_response_read((TC_bytes){(const uint8_t*)storage, sizeof storage}, &storage[1]), ==,
      TC_APDU_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(status_classes)
{
  static const struct {
    uint16_t sw;
    TC_APDU_status_class expected;
  } cases[] = {{0x9000, TC_APDU_SW_SUCCESS},     {0x6100, TC_APDU_SW_MORE_DATA},
               {0x61ff, TC_APDU_SW_MORE_DATA},   {0x6282, TC_APDU_SW_WARNING},
               {0x63c3, TC_APDU_SW_WARNING},     {0x6400, TC_APDU_SW_EXECUTION},
               {0x6581, TC_APDU_SW_EXECUTION},   {0x6600, TC_APDU_SW_EXECUTION},
               {0x6700, TC_APDU_SW_CHECKING},    {0x6883, TC_APDU_SW_CHECKING},
               {0x6982, TC_APDU_SW_CHECKING},    {0x6a82, TC_APDU_SW_CHECKING},
               {0x6b00, TC_APDU_SW_CHECKING},    {0x6c10, TC_APDU_SW_WRONG_LE},
               {0x6d00, TC_APDU_SW_CHECKING},    {0x6e00, TC_APDU_SW_CHECKING},
               {0x6f00, TC_APDU_SW_CHECKING},    {0x9001, TC_APDU_SW_PROPRIETARY},
               {0x9fff, TC_APDU_SW_PROPRIETARY}, {0x6000, TC_APDU_SW_INVALID},
               {0x60ff, TC_APDU_SW_INVALID},     {0x0000, TC_APDU_SW_INVALID},
               {0x5f00, TC_APDU_SW_INVALID},     {0x7000, TC_APDU_SW_INVALID},
               {0x8000, TC_APDU_SW_INVALID},     {0xa000, TC_APDU_SW_INVALID}};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i)
    munit_assert_int(TC_APDU_status_classify(cases[i].sw), ==, cases[i].expected);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static MunitTest tests[] = {
      {"/valid-responses", valid_responses, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/invalid-responses", invalid_responses, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/argument-errors", argument_errors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/status-classes", status_classes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  static const MunitSuite suite = {"/apdu/response", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
