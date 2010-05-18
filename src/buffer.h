// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_BUFFER_H
#define TLSCLIENT_BUFFER_H

#include "tlsclient/public/base.h"

#include <vector>

#include <gtest/gtest_prod.h>

namespace tlsclient {

class Buffer {
 public:
  struct Pos {
    Pos()
        : i(0),
          offset(0) {
    }

    unsigned i;
    size_t offset;
  };

  Buffer(const struct iovec *iov, unsigned len)
      : iov_(iov),
        len_(len),
        delete_(false) {
  }

  ~Buffer() {
    if (delete_)
      delete[] iov_;
  }

  void Rewind() {
    pos_.i = 0;
    pos_.offset = 0;
  }

  Pos Tell() const {
    return pos_;
  }

  size_t TellBytes() const {
    size_t r = 0;
    for (unsigned i = 0; i < pos_.i; i++) {
      r += iov_[i].iov_len;
    }
    r += pos_.offset;

    return r;
  }

  bool Seek(const Pos& pos) {
    if (pos.i < len_ && pos.offset >= iov_[pos.i].iov_len) {
      return false;
    } else if (pos.i == len_ && pos.offset) {
      return false;
    } else if (pos.i > len_) {
      return false;
    }

    pos_ = pos;
    return true;
  }

  void Advance(size_t nbytes) {
    while (nbytes && pos_.i < len_) {
      size_t n = iov_[pos_.i].iov_len - pos_.offset;
      if (n > nbytes)
        n = nbytes;
      nbytes -= n;

      if (nbytes) {
        pos_.i++;
        pos_.offset = 0;
      } else {
        pos_.offset += n;
        if (pos_.offset == iov_[pos_.i].iov_len) {
          pos_.i++;
          pos_.offset = 0;
        }
      }
    }

    assert(!nbytes);
  }

  size_t size() const {
    size_t r = 0;
    for (unsigned i = 0; i < len_; i++) {
      r += iov_[i].iov_len;
    }

    return r;
  }

  size_t remaining() const {
    size_t r = 0;

    for (unsigned i = pos_.i; i < len_; i++) {
      r += iov_[i].iov_len;
    }
    r -= pos_.offset;

    return r;
  }

  Buffer SubString(size_t len) const {
    std::vector<struct iovec> iovs;
    const bool b = PeekV(&iovs, len);
    assert(b);
    struct iovec *iovs_copy = new struct iovec[iovs.size()];
    memcpy(&iovs_copy[0], &iovs[0], sizeof(struct iovec) * iovs.size());
    return Buffer(&iovs_copy[0], iovs.size(), true);
  }

  bool PeekV(std::vector<struct iovec>* out, size_t len) const {
    Pos pos(pos_);

    if (!len)
      return true;

    while (len && pos.i < len_) {
      size_t n = iov_[pos.i].iov_len - pos.offset;
      if (n > len)
        n = len;
      len -= n;

      if (len) {
        pos.i++;
        pos.offset = 0;
      } else {
        pos.offset += n;
        break;
      }
    }

    if (len)
      return false;

    const unsigned num_iovs = pos.i - pos_.i + 1;
    const size_t old_out_size = out->size();
    out->resize(old_out_size + num_iovs);
    struct iovec *iovs = &((*out)[old_out_size]);
    iovs[0].iov_base = static_cast<uint8_t*>(iov_[pos_.i].iov_base) + pos_.offset;
    if (pos.i == pos_.i) {
      iovs[0].iov_len = pos.offset - pos_.offset;
    } else {
      iovs[0].iov_len = iov_[pos_.i].iov_len - pos_.offset;
    }

    for (unsigned i = pos_.i + 1; i < pos.i; i++)
      iovs[i - pos_.i] = iov_[i];

    if (num_iovs > 1) {
      iovs[num_iovs - 1].iov_base = iov_[pos.i].iov_base;
      iovs[num_iovs - 1].iov_len = pos.offset;
    }

    return true;
  }

  bool Read(void* out, size_t len) {
    uint8_t* o = static_cast<uint8_t*>(out);
    Pos pos(pos_);

    while (len && pos.i < len_) {
      size_t bytes_to_copy = iov_[pos.i].iov_len - pos.offset;
      if (bytes_to_copy > len)
        bytes_to_copy = len;
      memcpy(o, static_cast<uint8_t*>(iov_[pos.i].iov_base) + pos.offset, bytes_to_copy);
      o += bytes_to_copy;
      len -= bytes_to_copy;

      if (len) {
        pos.i++;
        pos.offset = 0;
      } else {
        pos.offset += bytes_to_copy;
        if (pos.offset == iov_[pos.i].iov_len) {
          pos.i++;
          pos.offset = 0;
        }
        break;
      }
    }

    if (len == 0) {
      pos_ = pos;
      return true;
    }

    return false;
  }

  bool Write(void* in, size_t len) {
    uint8_t* i = static_cast<uint8_t*>(in);
    Pos pos(pos_);

    // This is pretty much a duplication of Read().

    while (len && pos.i < len_) {
      size_t bytes_to_write = iov_[pos.i].iov_len - pos.offset;
      if (bytes_to_write > len)
        bytes_to_write = len;
      memcpy(static_cast<uint8_t*>(iov_[pos.i].iov_base) + pos.offset, i, bytes_to_write);
      i += bytes_to_write;
      len -= bytes_to_write;

      if (len) {
        pos.i++;
        pos.offset = 0;
      } else {
        pos.offset += bytes_to_write;
        if (pos.offset == iov_[pos.i].iov_len) {
          pos.i++;
          pos.offset = 0;
        }
        break;
      }
    }

    if (len == 0) {
      pos_ = pos;
      return true;
    }

    return false;
  }

  uint8_t* Get(uint8_t* out, size_t len) {
    if (pos_.i == len_)
      return NULL;

    const size_t remaining_in_current_chunk = iov_[pos_.i].iov_len - pos_.offset;
    if (remaining_in_current_chunk < len) {
      if (Read(out, len))
        return out;
      return NULL;
    }

    uint8_t* const ret = static_cast<uint8_t*>(iov_[pos_.i].iov_base) + pos_.offset;
    pos_.offset += len;
    if (pos_.offset == iov_[pos_.i].iov_len) {
      pos_.i++;
      pos_.offset = 0;
    }

    return ret;
  }

  bool U8(uint8_t* out) {
    return Read(out, 1);
  }

  bool U16(uint16_t* out) {
    uint8_t buf[2], *u16;
    u16 = Get(buf, 2);
    if (!u16)
      return false;
    *out = static_cast<uint16_t>(u16[0]) << 8 | u16[1];
    return true;
  }

  bool U32(uint32_t* out) {
    uint8_t buf[4], *u32;
    u32 = Get(buf, 4);
    if (!u32)
      return false;
    *out = static_cast<uint32_t>(u32[0]) << 24 |
           static_cast<uint32_t>(u32[1]) << 16 |
           static_cast<uint32_t>(u32[2]) << 8 |
           static_cast<uint32_t>(u32[3]);
    return true;
  }

  Buffer VariableLength(bool* ok, unsigned len_size) {
    assert(len_size > 0 && len_size <= 4);
    uint8_t temp[4], *lenbuffer;
    uint32_t len = 0;

    *ok = false;
    lenbuffer = Get(temp, len_size);
    if (!lenbuffer)
      return Buffer();
    for (unsigned i = 0; i < len_size; i++) {
      len <<= 8;
      len |= lenbuffer[i];
    }

    if (remaining() < len)
      return Buffer();
    std::vector<struct iovec> iovs;
    PeekV(&iovs, len);
    Advance(len);
    *ok = true;
    struct iovec *iovs_copy = new struct iovec[iovs.size()];
    memcpy(iovs_copy, &iovs[0], sizeof(struct iovec) * iovs.size());
    return Buffer(iovs_copy, iovs.size(), true);
  }

  const struct iovec* iovec() const {
    return iov_;
  }

  unsigned iovec_len() const {
    return len_;
  }

  static void RemoveTrailingBytes(struct iovec* iov, unsigned* iov_len, size_t bytes_to_remove) {
    while (bytes_to_remove > 0 && *iov_len > 0) {
      struct iovec* last = &iov[(*iov_len) - 1];
      size_t n = last->iov_len;
      if (n > bytes_to_remove) {
        n = bytes_to_remove;
        last->iov_len -= n;
      } else {
        (*iov_len)--;
      }
      bytes_to_remove -= n;
    }
  }

 private:
  Buffer()
      : iov_(NULL),
        len_(0),
        delete_(false) {
  }

  Buffer(const struct iovec *iov, unsigned len, bool del)
      : iov_(iov),
        len_(len),
        delete_(del) {
  }

  const struct iovec *const iov_;
  const unsigned len_;
  const bool delete_;

  Pos pos_;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_BUFFER_H
