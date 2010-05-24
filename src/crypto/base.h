// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CRYPTO_BASE_H
#define TLSCLIENT_CRYPTO_BASE_H

namespace tlsclient {

enum Direction {
  ENCRYPT = 0,
  DECRYPT = 1,
};

template<unsigned size>
static void XorBytes(uint8_t* dest, const uint8_t* src) {
  for (unsigned i = 0; i < size; i++) {
    dest[i] ^= src[i];
  }
}

template<>
void XorBytes<8>(uint8_t* dest, const uint8_t* src) {
  uint64_t* dest64 = reinterpret_cast<uint64_t*>(dest);
  const uint64_t* src64 = reinterpret_cast<const uint64_t*>(src);

  dest64[0] ^= src64[0];
}

template<>
void XorBytes<16>(uint8_t* dest, const uint8_t* src) {
  uint64_t* dest64 = reinterpret_cast<uint64_t*>(dest);
  const uint64_t* src64 = reinterpret_cast<const uint64_t*>(src);

  dest64[0] ^= src64[0];
  dest64[1] ^= src64[1];
}

}  // namespace tlsclient

#endif  // !TLSCLIENT_CRYPTO_BASE_H
