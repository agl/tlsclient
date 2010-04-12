// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file implements RC4 encryption, as defined in Bruce Schneier's
// Applied Cryptography.

#include "tlsclient/src/crypto/rc4/rc4.h"

namespace tlsclient {

RC4::RC4(const uint8_t* key, unsigned len) {
  assert(len > 0 && len <= 256);
  for (unsigned i = 0; i < 256; i++)
    s_[i] = i;

  uint8_t j = 0;
  for (unsigned i = 0; i < 256; i++) {
    j += s_[i] + key[i % len];
    const uint8_t t = s_[i];
    s_[i] = s_[j];
    s_[j] = t;
  }

  i_ = j_ = 0;
}

void RC4::Encrypt(const struct iovec* iov, unsigned iov_len) {
  for (unsigned i = 0; i < iov_len; i++)
    EncryptSpan(static_cast<uint8_t*>(iov[i].iov_base), iov[i].iov_len);
}

void RC4::EncryptSpan(uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    i_++;
    j_ += s_[i_];
    const uint8_t t = s_[i_];
    s_[i_] = s_[j_];
    s_[j_] = t;
    data[i] ^= s_[static_cast<uint8_t>(s_[i_] + s_[j_])];
  }
}

}  // namespace tlsclient
