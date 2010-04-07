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
    ReadV(&iovs, len);
    struct iovec *iovs_copy = new struct iovec[iovs.size()];
    memcpy(&iovs_copy[0], &iovs[0], sizeof(struct iovec) * iovs.size());
    return Buffer(&iovs_copy[0], iovs.size(), true);
  }

  void ReadV(std::vector<struct iovec>* out, size_t len) const {
    Pos pos(pos_);

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

    assert(!len);

    const unsigned num_iovs = pos.i - pos_.i + 1;
    const size_t old_out_size = out->size();
    out->resize(old_out_size + num_iovs);
    struct iovec *iovs = &(*out)[old_out_size];
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

 private:
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
