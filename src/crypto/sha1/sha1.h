// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_SHA1_H_
#define TLSCLIENT_SHA1_H_

#include "tlsclient/public/base.h"

namespace tlsclient {

class SHA1 {
 public:
  SHA1() {
    Init();
  }

  enum {
    DIGEST_SIZE = 20,
    BLOCK_SIZE = 64,
  };

  // Init resets the SHA1 context. The constructor calls this function so you
  // don't need to unless you wish to reuse an SHA1 object.
  void Init();
  void Update(const void* data, size_t length);
  void Final(uint8_t* out_digest);

 private:
  void Process();
  void Pad();

  uint32_t A, B, C, D, E;

  uint32_t H[5];

  union {
    uint32_t W[80];
    uint8_t M[64];
  };

  uint32_t cursor;
  uint32_t l;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_SHA1_H_
