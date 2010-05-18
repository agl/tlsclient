// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// #include "tlsclient/src/crypto/cbc.h"
#include "tlsclient/src/crypto/aes/aes.h"

#include <gtest/gtest.h>

#include "tlsclient/src/base-internal.h"
#include "tlsclient/tests/util.h"

using namespace tlsclient;

namespace {

class CBCTest : public ::testing::Test {
};

struct CBCTestCase {
  const char* key;
  const char* iv;
  // For the decrypt tests, these two are actually the other way around.
  const char* plaintext;
  const char* ciphertext;
};

TEST_F(CBCTest, AES128) {
}

}  // anonymous namespace
