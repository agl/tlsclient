// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"
#include "tlsclient/public/context.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class HandshakeTest : public ::testing::Test {
};

class ContextBase : public Context {
 public:
  bool RandomBytes(void* addr, size_t len) {
    return false;
  }

  uint64_t EpochSeconds() {
    return 0;
  }

  Certificate* ParseRSACertificate(const uint8_t* bytes, size_t length) {
    return NULL;
  }
};

class ContextWorkingEpochSeconds : public ContextBase {
 public:
  uint64_t EpochSeconds() {
    return 100000;
  }
};

class ContextWorkingRandomBytes : public ContextBase {
 public:
  bool RandomBytes(void* addr, size_t len) {
    memset(addr, 0, len);
    return true;
  }
};

class ContextBothWorking : public ContextBase {
 public:
  uint64_t EpochSeconds() {
    return 100000;
  }

  bool RandomBytes(void* addr, size_t len) {
    memset(addr, 0, len);
    return true;
  }
};

TEST_F(HandshakeTest, EpochSecondsFailure) {
  ContextWorkingRandomBytes ctx;
  Connection conn(&ctx);
  Arena a;
  Sink s(&a);

  const Result r = MarshallClientHello(&s, conn.priv());
  ASSERT_EQ(ERR_EPOCH_SECONDS_FAILED, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, RandomBytesFailure) {
  ContextWorkingEpochSeconds ctx;
  Connection conn(&ctx);
  Arena a;
  Sink s(&a);

  const Result r = MarshallClientHello(&s, conn.priv());
  ASSERT_EQ(ERR_RANDOM_BYTES_FAILED, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, Success) {
  ContextBothWorking ctx;
  Connection conn(&ctx);
  Arena a;
  Sink s(&a);

  conn.EnableDefault();
  const Result r = MarshallClientHello(&s, conn.priv());
  ASSERT_EQ(0, ErrorCodeFromResult(r));
}

}  // anonymous namespace
