// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_AES_H_
#define TLSCLIENT_AES_H_

#include "tlsclient/public/base.h"
#include "tlsclient/src/crypto/base.h"

namespace tlsclient {

class AES128 {
 public:
  enum {
    ROUNDS = 10,
    BLOCK_SIZE = 16,
  };

  AES128(const uint8_t key[16], Direction dir);
  void Crypt(uint8_t out[16], const uint8_t in[16]);

 private:
  uint32_t c_[44];
  const Direction dir_;
};

class AES256 {
 public:
  enum {
    ROUNDS = 14,
    BLOCK_SIZE = 16,
  };

  AES256(const uint8_t key[16], Direction dir);
  void Crypt(uint8_t out[16], const uint8_t in[16]);

 private:
  uint32_t c_[60];
  const Direction dir_;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_SHA1_H_
