// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_OPENSSL_CONTEXT_H
#define TLSCLIENT_OPENSSL_CONTEXT_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/context.h"

class OpenSSLContext : public tlsclient::Context {
 public:
  virtual bool RandomBytes(void*, size_t);
  virtual uint64_t EpochSeconds();
  virtual tlsclient::Certificate* ParseCertificate(const uint8_t* bytes, size_t length);
};

#endif  // TLSCLIENT_OPENSSL_CONTEXT_H
