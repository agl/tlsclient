// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_RC4_H_
#define TLSCLIENT_RC4_H_

#include "tlsclient/public/base.h"

namespace tlsclient {

class RC4 {
 public:
  RC4(const uint8_t* key, unsigned len);
  void Encrypt(const struct iovec* iov, unsigned iov_len);
  void Decrypt(const struct iovec* iov, unsigned iov_len) {
    Encrypt(iov, iov_len);
  }

 private:
  void EncryptSpan(uint8_t* data, size_t len);

  uint8_t s_[256];
  uint8_t i_;
  uint8_t j_;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_SHA1_H_
