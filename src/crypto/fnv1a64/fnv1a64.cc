// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/fnv1a64/fnv1a64.h"

// This is an implementation of the FNV-1a hash as described at
// http://isthe.com/chongo/tech/comp/fnv/

namespace tlsclient {

// http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
static const uint64_t kOffsetBasis = 14695981039346656037ull;
static const uint64_t kPrime = 1099511628211ull;

void FNV1a64::Init() {
  s_ = kOffsetBasis;
}

void FNV1a64::Update(const void* data, size_t length) {
  const uint8_t* d = reinterpret_cast<const uint8_t*>(data);

  for (size_t i = 0; i < length; i++) {
    s_ ^= d[i];
    s_ *= kPrime;
  }
} 

void FNV1a64::Final(uint8_t* out_digest) {
  out_digest[0] = s_ >> 56;
  out_digest[1] = s_ >> 48;
  out_digest[2] = s_ >> 40;
  out_digest[3] = s_ >> 32;
  out_digest[4] = s_ >> 24;
  out_digest[5] = s_ >> 16;
  out_digest[6] = s_ >> 8;
  out_digest[7] = s_;
}

}  // namespace tlsclient
