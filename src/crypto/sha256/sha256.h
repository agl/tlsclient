// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_SHA256_H_
#define TLSCLIENT_SHA256_H_

#include "tlsclient/public/base.h"

namespace tlsclient {

class SHA256 {
 public:
  SHA256() {
    Init();
  }

  enum {
    DIGEST_SIZE = 32,
    BLOCK_SIZE = 64,
  };

  // Init resets the SHA256 context. The constructor calls this function so
  // you don't need to unless you wish to reuse an SHA256 object.
  void Init();
  void Update(const void* data, size_t length);
  void Final(uint8_t* out_digest);

 private:
  uint8_t h_[DIGEST_SIZE];
  uint8_t block_[BLOCK_SIZE];
  unsigned block_used_;
  size_t bits_;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_SHA1_H_
