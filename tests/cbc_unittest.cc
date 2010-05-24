// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/cbc.h"

#include "tlsclient/src/crypto/aes/aes.h"

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class CBCTest : public ::testing::Test {
};

static const uint8_t kBase[32] =
  {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,
   5,4,3,2,1,1,2,3,4,5,6,7,8,9,0,1};

TEST_F(CBCTest, Simple) {
  static const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  static const uint8_t iv[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  CBC<AES128> enc(key, iv, ENCRYPT);
  CBC<AES128> dec(key, iv, DECRYPT);

  uint8_t simple[16];
  memcpy(simple, kBase, sizeof(simple));
  const struct iovec iov_simple = {simple, sizeof(simple)};

  enc.Crypt(&iov_simple, 1);
  dec.Crypt(&iov_simple, 1);

  ASSERT_TRUE(memcmp(simple, kBase, sizeof(simple)) == 0);
}

TEST_F(CBCTest, Simple2) {
  static const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  static const uint8_t iv[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  CBC<AES128> enc(key, iv, ENCRYPT);
  CBC<AES128> dec(key, iv, DECRYPT);

  uint8_t simple[32];
  memcpy(simple, kBase, sizeof(simple));
  const struct iovec iov_simple = {simple, sizeof(simple)};

  enc.Crypt(&iov_simple, 1);
  dec.Crypt(&iov_simple, 1);

  ASSERT_TRUE(memcmp(simple, kBase, sizeof(simple)) == 0);
}

TEST_F(CBCTest, Split) {
  static const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  static const uint8_t iv[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  CBC<AES128> enc(key, iv, ENCRYPT);
  CBC<AES128> dec(key, iv, DECRYPT);

  uint8_t simple[32];
  memcpy(simple, kBase, sizeof(simple));
  const struct iovec iovs[2] = {{simple, 16}, {simple+16, 16}};

  enc.Crypt(iovs, 2);
  dec.Crypt(iovs, 2);

  ASSERT_TRUE(memcmp(simple, kBase, sizeof(simple)) == 0);
}

TEST_F(CBCTest, Many) {
  static const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  static const uint8_t iv[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
  CBC<AES128> enc(key, iv, ENCRYPT);
  CBC<AES128> enc2(key, iv, ENCRYPT);
  CBC<AES128> dec(key, iv, DECRYPT);

  uint8_t simple[16];
  uint8_t parts[16];
  memcpy(simple, kBase, sizeof(simple));
  memcpy(parts, kBase, sizeof(parts));
  const struct iovec iov_simple = {simple, sizeof(simple)};
  struct iovec iovs[16];

  for (unsigned i = 0; i < 16; i++) {
    iovs[i].iov_base = &parts[i];
    iovs[i].iov_len = 1;
  }

  enc.Crypt(&iov_simple, 1);
  enc2.Crypt(iovs, 16);
  ASSERT_TRUE(memcmp(simple, parts, sizeof(simple)) == 0);
  dec.Crypt(iovs, 16);
  ASSERT_TRUE(memcmp(parts, kBase, sizeof(simple)) == 0);
}

}  // anonymous namespace
