// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CONTEXT_H
#define TLSCLIENT_CONTEXT_H

#include "tlsclient/public/base.h"

namespace tlsclient {

class Certificate {
 public:
  virtual ~Certificate() { }

  virtual unsigned size() = 0;

  virtual bool EncryptPKCS1(uint8_t* output, uint8_t* bytes, size_t length) = 0;
  virtual unsigned SizeEncryptPKCS1(size_t length) = 0;
};

class Context {
 public:
  virtual bool RandomBytes(void*, size_t) = 0;
  virtual uint64_t EpochSeconds() = 0;
  virtual Certificate* ParseCertificate(const uint8_t* bytes, size_t length) = 0;
};

}  // namespace tlsclient

#endif // TLSCLIENT_CONTEXT_H
