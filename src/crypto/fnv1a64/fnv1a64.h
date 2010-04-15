// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_FNV1A64_H_
#define TLSCLIENT_FNV1A64_H_

#include "tlsclient/public/base.h"

namespace tlsclient {

class FNV1a64 {
 public:
  FNV1a64() {
    Init();
  }

  enum {
    DIGEST_SIZE = 8,
    BLOCK_SIZE = 1,
  };

  // Init resets the context. The constructor calls this function so you
  // don't need to unless you wish to reuse this object.
  void Init();
  void Update(const void* data, size_t length);
  void Final(uint8_t* out_digest);

 private:
  uint64_t s_;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_FNV1A64_H_
