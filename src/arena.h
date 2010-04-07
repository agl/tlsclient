// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_ARENA_H
#define TLSCLIENT_ARENA_H

#include "tlsclient/public/base.h"

namespace tlsclient {

class Arena {
 public:
  Arena()
      : head_(NULL),
        allocated_(0) {
  }

  struct Header {
    Header* prev;
    Header* next;
    unsigned len;
  };

  ~Arena() {
    Header* next;

    for (Header* cur = head_; cur; cur = next) {
      next = cur->next;
      free(cur);
    }

    allocated_ = 0;
    head_ = NULL;
  }

  void* Allocate(size_t len) {
    len += sizeof(Header);
    uint8_t* ptr = static_cast<uint8_t*>(malloc(len));
    allocated_ += len;
    Header* elem = reinterpret_cast<Header*>(ptr);
    if (head_)
      head_->prev = elem;
    elem->next = head_;
    elem->prev = NULL;
    elem->len = len;

    head_ = elem;
    return ptr + sizeof(Header);
  }

  void* Realloc(void* inptr, size_t len) {
    uint8_t* ptr = static_cast<uint8_t*>(inptr);
    Header* elem = reinterpret_cast<Header*>(ptr - sizeof(Header));

    len += sizeof(Header);
    Header* const elem_prev = elem->prev;
    Header* const elem_next = elem->next;
    uint8_t* newptr = static_cast<uint8_t*>(realloc(elem, len));
    Header* newelem = reinterpret_cast<Header*>(newptr);

    if (newelem == elem) {
      newelem->len = len;
      return newptr + sizeof(Header);
    }

    if (elem_prev) {
      elem_prev->next = newelem;
    } else {
      head_ = newelem;
    }

    if (elem_next)
      elem_next->prev = newelem;

    return newptr + sizeof(Header);
  }

  void Free(void* inptr) {
    uint8_t* ptr = static_cast<uint8_t*>(inptr);
    Header* elem = reinterpret_cast<Header*>(ptr - sizeof(Header));
    if (elem->prev)
      elem->prev->next = elem->next;
    else
      head_ = elem->next;

    if (elem->next)
      elem->next->prev = elem->prev;

    allocated_ -= elem->len;
    free(elem);
  }

  size_t bytes_allocated() const {
    return allocated_;
  }

 private:
  Header* head_;
  size_t allocated_;
};

}  // namespace tlsclient

#endif
