// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/error.h"
#include "tlsclient/src/error-internal.h"

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class ErrorTest : public ::testing::Test {
};

TEST_F(ErrorTest, Basic) {
  char filename[8];

  const Result r1 = ErrorResult("", 0, ERR_SUCCESS);
  ASSERT_EQ(0u, LineNumberFromResult(r1));
  ASSERT_EQ(ERR_SUCCESS, ErrorCodeFromResult(r1));
  FilenameFromResult(filename, r1);
  ASSERT_EQ(0, filename[0]);

  const Result r2 = ErrorResult("", 1, ERR_SUCCESS);
  ASSERT_EQ(1u, LineNumberFromResult(r2));

  const Result r3 = ErrorResult("", 4094, ERR_SUCCESS);
  ASSERT_EQ(4094u, LineNumberFromResult(r3));

  const Result r4 = ErrorResult("", 4095, ERR_SUCCESS);
  ASSERT_EQ(4095u, LineNumberFromResult(r4));

  const Result r5 = ErrorResult("", 10000, ERR_SUCCESS);
  ASSERT_EQ(4095u, LineNumberFromResult(r5));

  const Result r6 = ErrorResult("test", 0, ERR_SUCCESS);
  FilenameFromResult(filename, r6);
  ASSERT_EQ('t', filename[0]);
  ASSERT_EQ('e', filename[1]);
  ASSERT_EQ('s', filename[2]);
  ASSERT_EQ('t', filename[3]);
  ASSERT_EQ(0, filename[4]);

  const Result r7 = ErrorResult("testing123", 0, ERR_SUCCESS);
  FilenameFromResult(filename, r7);
  ASSERT_EQ('t', filename[0]);
  ASSERT_EQ('e', filename[1]);
  ASSERT_EQ('s', filename[2]);
  ASSERT_EQ('t', filename[3]);
  ASSERT_EQ('i', filename[4]);
  ASSERT_EQ('n', filename[5]);
  ASSERT_EQ('g', filename[6]);
  ASSERT_EQ(0, filename[7]);

  const Result r8 = ErrorResult("TEST.cc", 0, ERR_SUCCESS);
  FilenameFromResult(filename, r8);
  ASSERT_EQ('t', filename[0]);
  ASSERT_EQ('e', filename[1]);
  ASSERT_EQ('s', filename[2]);
  ASSERT_EQ('t', filename[3]);
  ASSERT_EQ('.', filename[4]);
  ASSERT_EQ('c', filename[5]);
  ASSERT_EQ('c', filename[6]);
  ASSERT_EQ(0, filename[7]);

  const Result r9 = ErrorResult("dir/TEST.cc", 0, ERR_SUCCESS);
  FilenameFromResult(filename, r9);
  ASSERT_EQ('t', filename[0]);
  ASSERT_EQ('e', filename[1]);
  ASSERT_EQ('s', filename[2]);
  ASSERT_EQ('t', filename[3]);
  ASSERT_EQ('.', filename[4]);
  ASSERT_EQ('c', filename[5]);
  ASSERT_EQ('c', filename[6]);
  ASSERT_EQ(0, filename[7]);
}

}  // anonymous namespace
