// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/prf/hmac.h"

#include <gtest/gtest.h>

#include "tlsclient/src/base-internal.h"
#include "tlsclient/src/crypto/sha1/sha1.h"
#include "tlsclient/tests/util.h"

using namespace tlsclient;

namespace {

class HMACTest : public ::testing::Test {
};

struct Test {
  const char* key;
  unsigned keylen;
  const char* input;
  const char* digest;
};

// These tests were taken from the FIPS spec
// http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf
static const Test HMACSHA1Tests[] = {
  {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f", 64, "Sample #1", "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a"},
  {"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43", 20, "Sample #2", "0922d3405faa3d194f82a45830737d5cc6c75d24"},
  {"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3", 100, "Sample #3", "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa"},
};

TEST_F(HMACTest, Simple) {
  uint8_t digest[HMAC<SHA1>::DIGEST_SIZE];
  char hexdigest[HMAC<SHA1>::DIGEST_SIZE * 2 + 1];
  HMAC<SHA1> hmac;

  for (size_t i = 0; i < arraysize(HMACSHA1Tests); i++) {
    hmac.Init(reinterpret_cast<const uint8_t*>(HMACSHA1Tests[i].key), HMACSHA1Tests[i].keylen);
    hmac.Update(HMACSHA1Tests[i].input, strlen(HMACSHA1Tests[i].input));
    hmac.Final(digest);
    HexDump(hexdigest, digest, HMAC<SHA1>::DIGEST_SIZE);
    ASSERT_STREQ(HMACSHA1Tests[i].digest, hexdigest);
  }
}

}  // anonymous namespace
