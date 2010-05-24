// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CIPHERSUITES_H
#define TLSCLIENT_CIPHERSUITES_H

#include "tlsclient/public/base.h"
#include "tlsclient/src/handshake.h"

namespace tlsclient {

struct KeyBlock;

enum {
  CIPHERSUITE_RSA = 1 << 0,
  CIPHERSUITE_RC4 = 1 << 1,
  CIPHERSUITE_SHA = 1 << 2,
  CIPHERSUITE_SHA256 = 1 << 3,
  CIPHERSUITE_MD5 = 1 << 4,
  CIPHERSUITE_AES128 = 1 << 5,
  CIPHERSUITE_AES256 = 1 << 6,
  CIPHERSUITE_CBC = 1 << 7,
};

class CipherSpec {
 public:
  CipherSpec()
      : ref_count_(1) {
  }

  virtual ~CipherSpec() { }

  // ScratchBytesNeeded returns the number of scratch bytes needed to encrypt
  // data with the given total length.
  virtual unsigned ScratchBytesNeeded(size_t length) = 0;
  // WARNING: |in| must have space for an extra element at the end, after
  //   |in_len| elements.
  virtual bool Encrypt(uint8_t* scratch, size_t* scratch_size, const uint8_t* record_header, struct iovec* in, unsigned in_len, uint64_t seq_num) = 0;
  virtual bool Decrypt(unsigned* bytes_stripped, struct iovec* iov, unsigned* iov_len, const uint8_t* record_header, uint64_t seq_num) = 0;
  virtual unsigned StripMACAndPadding(struct iovec* iov, unsigned* iov_len) = 0;

  void AddRef() {
    ref_count_++;
  }

  void DecRef() {
    ref_count_--;
    if (!ref_count_)
      delete this;
  }

 private:
  unsigned ref_count_;
};

struct CipherSuite {
  // A bitmask of CIPHERSUITE_ flags. When considering ciphersuites the
  // Connection has a corresponding bitmask of enabled flags and only those
  // ciphersuites which are a subset are selected.
  unsigned flags;
  // The wire value of this ciphersuite
  uint16_t value;
  // The name as given in the RFCs
  char name[64];
  // The sizes of the pieces of key material needed.
  unsigned key_len, mac_len, iv_len;
  // create is a factory function to create a new CipherSpec for this cipher
  // suite and the given key material. The KeyBlock must already be filled out
  // with the correct amount of key material.
  CipherSpec* (*create) (TLSVersion version, const KeyBlock&);
};

const CipherSuite *AllCipherSuites();

// CompareBytes returns true iff a and b are the same and works in constant
// time.
bool CompareBytes(const uint8_t* a, const uint8_t* b, unsigned len);

}  // namespace tlsclient

#endif // !TLSCLIENT_CIPHERSUITES_H
