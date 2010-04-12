// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/base.h"

namespace tlsclient {

template<class H>
class HMAC {
 public:
  enum {
    DIGEST_SIZE = H::DIGEST_SIZE,
  };

  HMAC() {
    memset(key_, 0, sizeof(key_));
  }

  HMAC(const uint8_t* key, size_t length) {
    Init(key, length);
  }

  void Init(const uint8_t* key, size_t length) {
    hash_.Init();

    if (length < H::BLOCK_SIZE) {
      // Keys are zero padded on the right if too short.
      memset(key_, 0, sizeof(key_));
      memcpy(key_, key, length);
    } else if (length == H::BLOCK_SIZE) {
      memcpy(key_, key, length);
    } else {
      // Key which are too long are hashed down.
      memset(key_, 0, sizeof(key_));
      hash_.Update(key, length);
      hash_.Final(key_);
      hash_.Init();
    }

    // Apply ipad mask.
    for (size_t i = 0; i < sizeof(key_); i++)
      key_[i] ^= 0x36;

    hash_.Update(key_, sizeof(key_));
  }

  void Update(const void* data, size_t length) {
    hash_.Update(data, length);
  }

  void Final(uint8_t* out_digest) {
    uint8_t intermediate_digest[H::DIGEST_SIZE];
    hash_.Final(intermediate_digest);

    // Convert the ipad mask to the opad mask by XORing with ipad ^ opad.
    for (size_t i = 0; i < sizeof(key_); i++)
      key_[i] ^= 0x6a;

    hash_.Init();
    hash_.Update(key_, sizeof(key_));
    hash_.Update(intermediate_digest, sizeof(intermediate_digest));
    hash_.Final(out_digest);
  }

 private:
  H hash_;
  // The key is stored XORed with the ipad.
  uint8_t key_[H::BLOCK_SIZE];
};

}  // namespace tlsclient
