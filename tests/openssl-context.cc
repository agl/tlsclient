// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/tests/openssl-context.h"

#include <time.h>
#include <openssl/rand.h>

bool OpenSSLContext::RandomBytes(void* buffer, size_t len) {
  return RAND_bytes(static_cast<unsigned char*>(buffer), len) == 1;
}

uint64_t OpenSSLContext::EpochSeconds() {
  return time(NULL);
}

tlsclient::Certificate* OpenSSLContext::ParseCertificate(const uint8_t* bytes, size_t length) {

}
