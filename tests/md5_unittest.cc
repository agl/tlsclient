// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/md5/md5.h"

#include <gtest/gtest.h>

#include "tlsclient/src/base-internal.h"
#include "tlsclient/tests/util.h"

using namespace tlsclient;

namespace {

class MD5Test : public ::testing::Test {
};

// These tests were taken from the Go test suite.
struct MD5TestCase {
  const char* digest;
  const char* input;
};

static const MD5TestCase MD5Tests[] = {
  {"d41d8cd98f00b204e9800998ecf8427e", ""},
  {"0cc175b9c0f1b6a831c399e269772661", "a"},
  {"187ef4436122d1cc2f40dc2b92f0eba0", "ab"},
  {"900150983cd24fb0d6963f7d28e17f72", "abc"},
  {"e2fc714c4727ee9395f324cd2e7f331f", "abcd"},
  {"ab56b4d92b40713acc5af89985d4b786", "abcde"},
  {"e80b5017098950fc58aad83c8c14978e", "abcdef"},
  {"7ac66c0f148de9519b8bd264312c4d64", "abcdefg"},
  {"e8dc4081b13434b45189a720b77b6818", "abcdefgh"},
  {"8aa99b1f439ff71293e95357bac6fd94", "abcdefghi"},
  {"a925576942e94b2ef57a066101b48876", "abcdefghij"},
  {"d747fc1719c7eacb84058196cfe56d57", "Discard medicine more than two years old."},
  {"bff2dcb37ef3a44ba43ab144768ca837", "He who has a shady past knows that nice guys finish last."},
  {"0441015ecb54a7342d017ed1bcfdbea5", "I wouldn't marry him with a ten foot pole."},
  {"9e3cac8e9e9757a60c3ea391130d3689", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
  {"a0f04459b031f916a59a35cc482dc039", "The days of the digital watch are numbered.  -Tom Stoppard"},
  {"e7a48e0fe884faf31475d2a04b1362cc", "Nepal premier won't resign."},
  {"637d2fe925c07c113800509964fb0e06", "For every action there is an equal and opposite government program."},
  {"834a8d18d5c6562119cf4c7f5086cb71", "His money is twice tainted: 'taint yours and 'taint mine."},
  {"de3a4d2fd6c73ec2db2abad23b444281", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
  {"acf203f997e2cf74ea3aff86985aefaf", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
  {"e1c1384cb4d2221dfdd7c795a4222c9a", "size:  a.out:  bad magic"},
  {"c90f3ddecc54f34228c063d7525bf644", "The major problem is with sendmail.  -Mark Horton"},
  {"cdf7ab6c1fd49bd9933c43f3ea5af185", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
  {"83bc85234942fc883c063cbd7f0ad5d0", "If the enemy is within range, then so are you."},
  {"277cbe255686b48dd7e8f389394d9299", "It's well we cannot hear the screams/That we create in others' dreams."},
  {"fd3fb0a7ffb8af16603f3d3af98f8e1f", "You remind me of a TV show, but that's all right: I watch it anyway."},
  {"469b13a78ebf297ecda64d4723655154", "C is as portable as Stonehedge!!"},
  {"63eb3a2f466410104731c4b037600110", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
  {"72c2ed7592debca1c90fc0100f931a2f", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
  {"132f7619d33b523b1d9e5bd8e0928355", "How can you write a big system without C++?  -Paul Glick"},
};

TEST_F(MD5Test, Simple) {
  uint8_t digest[MD5::DIGEST_SIZE];
  char hexdigest[MD5::DIGEST_SIZE * 2 + 1];
  MD5 md5;

  for (size_t i = 0; i < arraysize(MD5Tests); i++) {
    md5.Init();
    md5.Update(MD5Tests[i].input, strlen(MD5Tests[i].input));
    md5.Final(digest);
    HexDump(hexdigest, digest, MD5::DIGEST_SIZE);
    ASSERT_STREQ(MD5Tests[i].digest, hexdigest);
  }
}

TEST_F(MD5Test, ByteByByte) {
  uint8_t digest[MD5::DIGEST_SIZE];
  char hexdigest[MD5::DIGEST_SIZE * 2 + 1];
  MD5 md5;

  for (size_t i = 0; i < arraysize(MD5Tests); i++) {
    md5.Init();
    size_t length = strlen(MD5Tests[i].input);
    for (size_t j = 0; j < length; j++)
      md5.Update(&MD5Tests[i].input[j], 1);
    md5.Final(digest);
    HexDump(hexdigest, digest, MD5::DIGEST_SIZE);
    ASSERT_STREQ(MD5Tests[i].digest, hexdigest);
  }
}

}  // anonymous namespace
