// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/buffer.h"

#include <vector>

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class BufferTest : public ::testing::Test {
};

TEST_F(BufferTest, Leak) {
  struct iovec iov[2];
  Buffer b1(iov, 2);  // we should be able to destruct this without it trying to free the iovec
}

TEST_F(BufferTest, Empty) {
  Buffer b(NULL, 0);
  ASSERT_EQ(0, b.size());
  ASSERT_EQ(0, b.remaining());
  const Buffer::Pos pos = b.Tell();
  ASSERT_TRUE(b.Seek(pos));

  b.Rewind();
  ASSERT_EQ(0, b.size());
  ASSERT_EQ(0, b.remaining());
}

TEST_F(BufferTest, OneBlock) {
  static const char kTestString[] = "testing";
  struct iovec iov = {const_cast<char*>(kTestString), sizeof(kTestString)};

  Buffer b(&iov, 1);
  ASSERT_EQ(sizeof(kTestString), b.size());
  ASSERT_EQ(sizeof(kTestString), b.remaining());
  const Buffer::Pos pos = b.Tell();
  ASSERT_TRUE(b.Seek(pos));

  b.Rewind();
  ASSERT_EQ(sizeof(kTestString), b.size());
  ASSERT_EQ(sizeof(kTestString), b.remaining());

  for (size_t i = 0; i < sizeof(kTestString); i++) {
    char c;
    ASSERT_EQ(sizeof(kTestString) - i, b.remaining());
    ASSERT_TRUE(b.Read(&c, 1));
    ASSERT_EQ(kTestString[i], c);
  }
}

TEST_F(BufferTest, TwoBlock) {
  static const char kTestString1[] = "hello";
  static const char kTestString2[] = "world";
  struct iovec iov[2] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
  };

  Buffer b(iov, 2);
  ASSERT_EQ(sizeof(kTestString1) + sizeof(kTestString2), b.size());
  ASSERT_EQ(sizeof(kTestString1) + sizeof(kTestString2), b.remaining());
  const Buffer::Pos pos = b.Tell();
  ASSERT_TRUE(b.Seek(pos));

  for (size_t i = 0; i < sizeof(kTestString1) + sizeof(kTestString2); i++) {
    char c;
    ASSERT_EQ(sizeof(kTestString1) + sizeof(kTestString2) - i, b.remaining());
    ASSERT_TRUE(b.Read(&c, 1));

    if (i < sizeof(kTestString1)) {
      ASSERT_EQ(kTestString1[i], c);
    } else {
      ASSERT_EQ(kTestString2[i - sizeof(kTestString1)], c);
    }
  }

  b.Rewind();
  char buf[sizeof(kTestString1) + sizeof(kTestString2)];
  ASSERT_TRUE(b.Read(buf, sizeof(buf)));
  ASSERT_TRUE(memcmp(kTestString1, buf, sizeof(kTestString1)) == 0);
  ASSERT_TRUE(memcmp(kTestString2, buf + sizeof(kTestString1), sizeof(kTestString2)) == 0);
}

TEST_F(BufferTest, Advance) {
  static const char kTestString1[] = "hello";
  static const char kTestString2[] = "world";
  struct iovec iov[2] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
  };
  Buffer b(iov, 2);
  char c;

  b.Advance(1);
  ASSERT_TRUE(b.Read(&c, 1));
  ASSERT_EQ('e', c);
  b.Advance(5);
  ASSERT_TRUE(b.Read(&c, 1));
  ASSERT_EQ('o', c);
  b.Advance(4);
  ASSERT_FALSE(b.Read(&c, 1));
}

static void CheckSubstring(const Buffer& in, size_t len, const char* expected) {
  char c;
  Buffer b = in.SubString(len);

  ASSERT_EQ(len, b.size());
  ASSERT_EQ(len, b.remaining());
  for (size_t i = 0; i < len; i++) {
    ASSERT_EQ(i, b.TellBytes());
    ASSERT_EQ(len - i, b.remaining());
    ASSERT_TRUE(b.Read(&c, 1));
    ASSERT_EQ(len, b.size());
    ASSERT_EQ(expected[i], c);
  }
  ASSERT_FALSE(b.Read(&c, 1));
}

TEST_F(BufferTest, SubString1) {
  static const char kTestString[] = "testing";
  struct iovec iov = {const_cast<char*>(kTestString), sizeof(kTestString)};
  Buffer b(&iov, 1);

  CheckSubstring(b, 0, "");
  CheckSubstring(b, 1, "t");
  CheckSubstring(b, 2, "te");
  CheckSubstring(b, sizeof(kTestString), kTestString);
}

TEST_F(BufferTest, SubString2) {
  static const char kTestString1[] = "hello";
  static const char kTestString2[] = "world";
  struct iovec iov[2] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
  };
  Buffer b(iov, 2);

  CheckSubstring(b, 0, "");
  CheckSubstring(b, 1, "h");
  CheckSubstring(b, 2, "he");
  CheckSubstring(b, sizeof(kTestString1), kTestString1);
  CheckSubstring(b, sizeof(kTestString1) + 1, "hello\x00w");
  CheckSubstring(b, sizeof(kTestString1) + 2, "hello\x00wo");
  CheckSubstring(b, sizeof(kTestString1) + sizeof(kTestString2), "hello\x00world");
}

TEST_F(BufferTest, SubString3) {
  static const char kTestString1[] = "hello";
  static const char kTestString2[] = "world";
  struct iovec iov[2] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
  };
  Buffer b(iov, 2);
  char c;

  ASSERT_TRUE(b.Read(&c, 1));
  ASSERT_EQ('h', c);

  CheckSubstring(b, 0, "");
  CheckSubstring(b, 1, "e");
  CheckSubstring(b, 2, "el");
  CheckSubstring(b, sizeof(kTestString1), "ello\x00w");
  CheckSubstring(b, sizeof(kTestString1) + 1, "ello\x00wo");
  CheckSubstring(b, sizeof(kTestString1) + sizeof(kTestString2) - 1, "ello\x00world");
}

TEST_F(BufferTest, SubString4) {
  static const char kTestString1[] = "goodbye";
  static const char kTestString2[] = "cruel";
  static const char kTestString3[] = "world";
  struct iovec iov[3] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
    {const_cast<char*>(kTestString3), sizeof(kTestString3)},
  };
  Buffer b(iov, 3);

  CheckSubstring(b, 0, "");
  CheckSubstring(b, 1, "g");
  CheckSubstring(b, 2, "go");
  CheckSubstring(b, sizeof(kTestString1), kTestString1);
  CheckSubstring(b, sizeof(kTestString1) + 1, "goodbye\000c");
  CheckSubstring(b, sizeof(kTestString1) + sizeof(kTestString2), "goodbye\000cruel\x00");
  CheckSubstring(b, sizeof(kTestString1) + sizeof(kTestString2) + 1, "goodbye\000cruel\x00w");
  CheckSubstring(b, sizeof(kTestString1) + sizeof(kTestString2) + sizeof(kTestString3), "goodbye\000cruel\x00world");
}

TEST_F(BufferTest, SubString5) {
  static const char kTestString1[] = "goodbye";
  static const char kTestString2[] = "cruel";
  static const char kTestString3[] = "world";
  struct iovec iov[3] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
    {const_cast<char*>(kTestString3), sizeof(kTestString3)},
  };
  Buffer b(iov, 3);
  char c[9];

  ASSERT_TRUE(b.Read(c, sizeof(c)));

  CheckSubstring(b, 0, "");
  CheckSubstring(b, 1, "r");
  CheckSubstring(b, 2, "ru");
  CheckSubstring(b, 5, "ruel");
  CheckSubstring(b, 6, "ruel\x00w");
  CheckSubstring(b, 7, "ruel\x00wo");
  CheckSubstring(b, 11, "ruel\x00world");
}

TEST_F(BufferTest, Get) {
  static const char kTestString1[] = "hello";
  static const char kTestString2[] = "world";
  struct iovec iov[2] = {
    {const_cast<char*>(kTestString1), sizeof(kTestString1)},
    {const_cast<char*>(kTestString2), sizeof(kTestString2)},
  };
  Buffer b(iov, 2);
  uint8_t temp[32];

  uint8_t* a = b.Get(temp, 5);
  // We should be able to get a direct pointer here
  ASSERT_NE(temp, a);
  ASSERT_TRUE(memcmp(a, "hello", 5) == 0);

  // This should be a copy because it crosses a boundary
  a = b.Get(temp, 3);
  ASSERT_EQ(a, temp);
  ASSERT_TRUE(memcmp(a, "\x00wo", 3) == 0);

  // This should return NULL because we don't have that much data
  a = b.Get(temp, 30);
  ASSERT_FALSE(a);
}

TEST_F(BufferTest, VariableLength1) {
  static const char kTestString[] = "\x03\x01\x02\x03\x04";
  struct iovec iov = {const_cast<char*>(kTestString), sizeof(kTestString) - 1};
  Buffer b(&iov, 1);
  uint8_t temp[3];
  bool ok;

  Buffer b2(b.VariableLength(&ok, 1));
  ASSERT_TRUE(ok);
  ASSERT_EQ(3, b2.size());
  ASSERT_EQ(b.remaining(), 1);
  ASSERT_TRUE(memcmp(b2.Get(temp, 3), "\x01\x02\x03", 3) == 0);
}

TEST_F(BufferTest, VariableLength2) {
  static const char kTestString[] = "\x00\x03\x01\x02\x03\x04";
  struct iovec iov = {const_cast<char*>(kTestString), sizeof(kTestString) - 1};
  Buffer b(&iov, 1);
  uint8_t temp[3];
  bool ok;

  Buffer b2(b.VariableLength(&ok, 2));
  ASSERT_TRUE(ok);
  ASSERT_EQ(3, b2.size());
  ASSERT_EQ(b.remaining(), 1);
  ASSERT_TRUE(memcmp(b2.Get(temp, 3), "\x01\x02\x03", 3) == 0);
}

}  // anonymous namespace
