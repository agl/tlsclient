// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/arena.h"

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class ArenaTest : public ::testing::Test {
};

TEST_F(ArenaTest, Create) {
  Arena a;
}

TEST_F(ArenaTest, Leak) {
  Arena a;

  a.Allocate(1000);
  a.Allocate(1000);
  a.Allocate(1000);
  a.Allocate(1000);
  a.Allocate(1000);
  a.Allocate(1000);

  ASSERT_LE(6000, a.bytes_allocated());
}

TEST_F(ArenaTest, Free) {
  Arena a;

  a.Allocate(1000);
  a.Allocate(1000);
  void *ptr = a.Allocate(1000);
  a.Allocate(1000);
  a.Allocate(1000);
  a.Allocate(1000);

  a.Free(ptr);
  ASSERT_LE(5000, a.bytes_allocated());
}

TEST_F(ArenaTest, Free2) {
  Arena a;

  for (unsigned i = 0; i < 100; i++) {
    void* const p = a.Allocate(1);
    a.Allocate(1);
    a.Allocate(1);
    a.Free(p);
  }
}

TEST_F(ArenaTest, Realloc) {
  Arena a;

  void* const p = a.Allocate(10);
  a.Realloc(p, 10000);

  ASSERT_GE(10000, a.bytes_allocated());
}

TEST_F(ArenaTest, Realloc2) {
  Arena a;

  for (unsigned i = 0; i < 100; i++) {
    void* const p = a.Allocate(1);
    void* const p2 = a.Allocate(1);
    a.Allocate(1);
    a.Free(p);
    a.Realloc(p2, 1000);
  }
}

}  // anonymous namespace
