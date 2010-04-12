// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/sink.h"

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class SinkTest : public ::testing::Test {
};

TEST_F(SinkTest, Empty) {
  Arena a;
  Sink s(&a);
  ASSERT_EQ(0u, s.size());
}

TEST_F(SinkTest, U8) {
  Arena a;
  Sink s(&a);
  s.U8(42);
  ASSERT_EQ(1u, s.size());
  ASSERT_EQ(42, s.data()[0]);
}

TEST_F(SinkTest, U16) {
  Arena a;
  Sink s(&a);
  s.U16(0x0201);
  ASSERT_EQ(2u, s.size());
  ASSERT_EQ(2, s.data()[0]);
  ASSERT_EQ(1, s.data()[1]);
}

TEST_F(SinkTest, U24) {
  Arena a;
  Sink s(&a);
  s.U24(0x030201);
  ASSERT_EQ(3u, s.size());
  ASSERT_EQ(3, s.data()[0]);
  ASSERT_EQ(2, s.data()[1]);
  ASSERT_EQ(1, s.data()[2]);
}

TEST_F(SinkTest, U32) {
  Arena a;
  Sink s(&a);
  s.U32(0x04030201);
  ASSERT_EQ(4u, s.size());
  ASSERT_EQ(4, s.data()[0]);
  ASSERT_EQ(3, s.data()[1]);
  ASSERT_EQ(2, s.data()[2]);
  ASSERT_EQ(1, s.data()[3]);
}

TEST_F(SinkTest, Append) {
  Arena a;
  Sink s(&a);
  s.Append(reinterpret_cast<const uint8_t*>("testing"), 8);
  ASSERT_EQ(8u, s.size());
  ASSERT_EQ('t', s.data()[0]);
  ASSERT_EQ('e', s.data()[1]);
  ASSERT_EQ('s', s.data()[2]);
  ASSERT_EQ('t', s.data()[3]);
  ASSERT_EQ('i', s.data()[4]);
  ASSERT_EQ('n', s.data()[5]);
  ASSERT_EQ('g', s.data()[6]);
  ASSERT_EQ(0, s.data()[7]);
}

TEST_F(SinkTest, AppendMany) {
  static const unsigned kIterations = 100000;
  uint8_t b = 42;
  Arena a;
  Sink s(&a);

  for (unsigned i = 0; i < kIterations; i++) {
    s.Append(&b, 1);
  }

  ASSERT_EQ(s.size(), kIterations);
}

TEST_F(SinkTest, VariableBlock1) {
  Arena a;
  Sink s(&a);

  s.U8(1);
  {
    Sink s2 = s.VariableLengthBlock(1);
    s2.U8(3);
    s2.U8(4);
  }
  s.U8(5);

  ASSERT_EQ(5u, s.size());
  ASSERT_TRUE(0 == memcmp(s.data(), "\x01\x02\x03\x04\x05", 5));
}

TEST_F(SinkTest, VariableBlock2) {
  Arena a;
  Sink s(&a);

  s.U8(1);
  {
    Sink s2 = s.VariableLengthBlock(2);
    s2.U8(3);
    s2.U8(4);
  }
  s.U8(5);

  ASSERT_EQ(6u, s.size());
  ASSERT_TRUE(0 == memcmp(s.data(), "\x01\x00\x02\x03\x04\x05", 6));
}

TEST_F(SinkTest, VariableBlock4) {
  Arena a;
  Sink s(&a);

  s.U8(1);
  {
    Sink s2 = s.VariableLengthBlock(4);
    s2.U8(3);
    s2.U8(4);
  }
  s.U8(5);

  ASSERT_EQ(8u, s.size());
  ASSERT_TRUE(0 == memcmp(s.data(), "\x01\x00\x00\x00\x02\x03\x04\x05", 8));
}

TEST_F(SinkTest, Record) {
  Arena a;
  Sink sink(&a);

  {
    Sink s = sink.Record(SSLv3, RECORD_HANDSHAKE);
    Sink s2 = s.HandshakeMessage(CERTIFICATE_VERIFY);
    s2.U8(5);
  }

  ASSERT_EQ(10u, sink.size());
  ASSERT_TRUE(0 == memcmp(sink.data(), "\x16\x03\x00\x00\x05\x0f\x00\x00\x01\x05", 10));
}

}  // anonymous namespace
