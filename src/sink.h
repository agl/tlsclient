// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_SINK_H
#define TLSCLIENT_SINK_H

#include "tlsclient/public/base.h"
#include "tlsclient/src/arena.h"
#include "tlsclient/src/handshake.h"

namespace tlsclient {

class Sink {
 public:
  static const size_t kDefaultSize = 2048;

  struct Buf {
    uint8_t* data;
    size_t length;
    size_t offset;
  };

  Sink(Arena* a)
      : arena_(a),
        buf_(&b_),
        initial_offset_(0),
        length_size_(0),
        length_offset_(0) {
    b_.data = static_cast<uint8_t*>(a->Allocate(kDefaultSize));
    b_.length = kDefaultSize;
    b_.offset = 0;
  }

  ~Sink() {
    WriteLength();

    if (buf_ == &b_ && b_.data) {
      arena_->Free(b_.data);
      b_.data = NULL;
    }
  }

  void WriteLength() {
    const size_t written = buf_->offset - length_offset_ - length_size_;

    for (unsigned i = 0; i < length_size_; i++) {
      buf_->data[length_offset_ + i] = written >> (8 * (length_size_ - i - 1));
    }
  }

  uint8_t* Release() {
    assert(buf_ == &b_);

    uint8_t* const ret = b_.data;
    b_.data = NULL;
    return ret;
  }

  Sink(const Sink& other) :
    arena_(other.arena_),
    buf_(other.buf_),
    initial_offset_(other.initial_offset_),
    length_size_(0),
    length_offset_(0) {
  }

  Sink VariableLengthBlock(unsigned length_prefix_size) {
    Ensure(length_prefix_size);
    buf_->offset += length_prefix_size;
    return Sink(this, length_prefix_size);
  }

  void U8(uint8_t v) {
    Ensure(1);
    buf_->data[buf_->offset++] = v;
  }

  void U16(uint16_t v) {
    Ensure(2);
    buf_->data[buf_->offset++] = v >> 8;
    buf_->data[buf_->offset++] = v;
  }

  void U24(uint32_t v) {
    Ensure(3);
    buf_->data[buf_->offset++] = v >> 16;
    buf_->data[buf_->offset++] = v >> 8;
    buf_->data[buf_->offset++] = v;
  }

  void U32(uint32_t v) {
    Ensure(4);
    buf_->data[buf_->offset++] = v >> 24;
    buf_->data[buf_->offset++] = v >> 16;
    buf_->data[buf_->offset++] = v >> 8;
    buf_->data[buf_->offset++] = v;
  }

  void Append(const uint8_t* data, size_t length) {
    Ensure(length);
    memcpy(buf_->data + buf_->offset, data, length);
    buf_->offset += length;
  }

  uint8_t* Block(size_t length) {
    Ensure(length);
    uint8_t* const ret = buf_->data + buf_->offset;
    buf_->offset += length;
    return ret;
  }

  void Copy(const void* src, size_t length) {
    Ensure(length);
    uint8_t* const ret = buf_->data + buf_->offset;
    buf_->offset += length;
    memcpy(ret, src, length);
  }

  Sink Record(TLSVersion version, RecordType type) {
    U8(static_cast<uint8_t>(type));

    switch (version) {
    case SSLv3:
      U16(0x0300);
      break;
    case TLSv10:
      U16(0x0301);
      break;
    case TLSv11:
      U16(0x0302);
      break;
    case TLSv12:
      U16(0x0303);
      break;
    default:
      abort();
    }

    return VariableLengthBlock(2);
  }

  Sink HandshakeMessage(HandshakeMessage type) {
    U8(static_cast<uint8_t>(type));

    return VariableLengthBlock(3);
  }

  const uint8_t* data() const {
    return buf_->data + initial_offset_;
  }

  size_t size() const {
    return buf_->offset - initial_offset_;
  }

 private:
  Sink(Sink* parent, unsigned length_size)
      : arena_(parent->arena_),
        buf_(parent->buf_),
        initial_offset_(buf_->offset),
        length_size_(length_size),
        length_offset_(parent->buf_->offset - length_size) {
  }

  void Ensure(size_t n) {
    const size_t remaining = buf_->length - buf_->offset;
    if (remaining >= n)
      return;
    buf_->length += n;
    buf_->length *= 2;
    buf_->data = static_cast<uint8_t*>(arena_->Realloc(buf_->data, buf_->length));
  }

  Arena *const arena_;
  Buf *const buf_;
  const size_t initial_offset_;

  const unsigned length_size_;
  const size_t length_offset_;
  Buf b_;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_SINK_H
