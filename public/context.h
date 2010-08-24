// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CONTEXT_H
#define TLSCLIENT_CONTEXT_H

#include "tlsclient/public/base.h"

namespace tlsclient {

// Certificate is an abstract class that the user of Connection needs to
// implement in order to provide libtlsclient with the public-key funtions
// needed to handshake with TLS servers.
class Certificate {
 public:
  virtual ~Certificate() { }

  // EncryptPKCS1 performs RSA encryption with PKCS#1 padding.
  //   output: on return, contains |SizeEncryptPKCS1| bytes of encrypted data.
  //   bytes: the plaintext data to be encrypted.
  //   length: the number of bytes in |bytes|.
  //   returns: true on success.
  virtual bool EncryptPKCS1(uint8_t* output, uint8_t* bytes, size_t length) = 0;
  // SizeEncryptPKCS1 returns the size of the ciphertext resulting from
  // encrypting data with this public key.
  virtual size_t SizeEncryptPKCS1() = 0;
};

// Context is an abstract class that provides callbacks for system
// functionality that libtlsclient needs.
class Context {
 public:
  virtual ~Context() { }
  // RandomBytes fills a buffer with cryptographically strong random data.
  virtual bool RandomBytes(void*, size_t) = 0;
  // EpochSeconds returns the number of seconds since the UNIX epoch.
  virtual uint64_t EpochSeconds() = 0;
  // ParseCertificate returns a Certificate pointer resulting from parsing
  // certificate data from the peer. The data is taken raw from the TLS
  // protocol and will typically be X509 DER encoded.
  virtual Certificate* ParseCertificate(const uint8_t* bytes, size_t length) = 0;
};

}  // namespace tlsclient

#endif // TLSCLIENT_CONTEXT_H
