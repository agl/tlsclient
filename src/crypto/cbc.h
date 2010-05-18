// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CBC_H
#define TLSCLIENT_CBC_H

#include "tlsclient/src/buffer.h"
#include "tlsclient/src/crypto/base.h"

namespace tlsclient {

template<class BlockCipher>
class CBC {
 public:
  CBC(const uint8_t* key, const uint8_t* iv, Direction d)
      : cipher_(key, d),
        direction_(d) {
    memcpy(last_, iv, sizeof(last_));
  }

  void Crypt(struct iovec* in, unsigned in_len) {
    uint8_t blockbuf[BlockCipher::BLOCK_SIZE];
    uint8_t* block;
    uint8_t last[BlockCipher::BLOCK_SIZE];
    Buffer buf(in, in_len);
    size_t len = buf.remaining();

    assert(len % BlockCipher::BLOCK_SIZE == 0);

    while (len >= BlockCipher::BLOCK_SIZE) {
      const Buffer::Pos previous_position(buf.Tell());
      block = buf.Get(blockbuf, BlockCipher::BLOCK_SIZE);

      if (D == ENCRYPT) {
        XorBytes<BlockCipher::BLOCK_SIZE>(block, last_);
      } else {
        memcpy(last, block, sizeof(last));
      }

      cipher_.Cipher(block, block);

      if (D == ENCRYPT) {
        memcpy(last_, block, sizeof(last_));
      } else {
        XorBytes<BlockCipher::BLOCK_SIZE>(block, last_);
        memcpy(last_, last, sizeof(last_));
      }

      len -= BlockCipher::BLOCK_SIZE;

      if (block != blockbuf) {
        // We had to assemble a block which spanned iovecs. Thus we need to
        // write the result back out.
        buf.Seek(previous_position);
        buf.Write(block, BlockCipher::BLOCK_SIZE);
      }
    }
  }

 private:
  BlockCipher cipher_;
  const Direction direction_;
  uint8_t last_[BlockCipher::BLOCK_SIZE];
};


}  // namespace tlsclient

#endif  // !TLSCLIENT_CBC_H
