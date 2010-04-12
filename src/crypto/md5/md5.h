// Copyright (c) 2006-2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_MD5_H_
#define TLSCLIENT_MD5_H_

#include "tlsclient/public/base.h"

namespace tlsclient {

// MD5 stands for Message Digest algorithm 5.
// MD5 is a robust hash function, designed for cyptography, but often used
// for file checksums.  The code is complex and slow, but has few
// collisions.
// See Also:
//   http://en.wikipedia.org/wiki/MD5

// These functions perform MD5 operations. The simplest call is MD5Sum() to
// generate the MD5 sum of the given data.
//
// You can also compute the MD5 sum of data incrementally by making multiple
// calls to MD5Update():
//   MD5Context ctx; // intermediate MD5 data: do not use
//   MD5Init(&ctx);
//   MD5Update(&ctx, data1, length1);
//   MD5Update(&ctx, data2, length2);
//   ...
//
//   MD5Digest digest; // the result of the computation
//   MD5Final(&digest, &ctx);
//
// You can call MD5DigestToBase16() to generate a string of the digest.

class MD5 {
 public:
  MD5() {
    Init();
  }

  enum {
    DIGEST_SIZE = 16,
    BLOCK_SIZE = 64,
  };

  // Init resets the MD5 context. The constructor calls this function so you
  // don't need to unless you wish to reuse an MD5 object.
  void Init();
  void Update(const void* data, size_t length);
  void Final(uint8_t* out_digest);

 private:
  uint32_t buf_[4];
  uint32_t bits_[2];
  uint8_t in_[64];
};

}  // namespace tlsclient

#endif  // TLSCLIENT_MD5_H_
