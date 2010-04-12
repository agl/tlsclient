// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/rc4/rc4.h"

#include <gtest/gtest.h>

#include "tlsclient/src/base-internal.h"
#include "tlsclient/tests/util.h"

using namespace tlsclient;

namespace {

class RC4Test : public ::testing::Test {
};

struct RC4TestCase {
  const char* key;
  const char* keystream;
};

static const RC4TestCase RC4Tests[] = {
  // Test vectors from the original cypherpunk posting of ARC4:
  //   http://groups.google.com/group/sci.crypt/msg/10a300c9d21afca0?pli=1
  { "0123456789abcdef", "7494c2e7104b0879" },
  { "0000000000000000", "de188941a3375d3a" },
  { "ef012345", "d6a141a7ec3c38dfbd61" },

  // Test vectors from the Wikipedia page: http://en.wikipedia.org/wiki/RC4
  { "4b6579", "eb9f7781b734ca72a719" },
  { "57696b69", "6044db6d41b7" },
};

TEST_F(RC4Test, Simple) {
  for (size_t i = 0; i < arraysize(RC4Tests); i++) {
    const RC4TestCase* const test = &RC4Tests[i];

    const size_t key_len = strlen(test->key) / 2;
    uint8_t* key = new uint8_t[key_len];
    FromHex(key, test->key);

    const size_t ks_len = strlen(test->keystream) / 2;
    uint8_t* data = new uint8_t[ks_len];
    memset(data, 0, ks_len);

    RC4 rc4(key, key_len);
    struct iovec iov;
    iov.iov_base = data;
    iov.iov_len = ks_len;
    rc4.Encrypt(&iov, 1);

    char* hex = new char[ks_len*2 + 1];
    HexDump(hex, data, ks_len);

    ASSERT_STREQ(test->keystream, hex);

    delete[] hex;
    delete[] data;
    delete[] key;
  }
}

}  // anonymous namespace
