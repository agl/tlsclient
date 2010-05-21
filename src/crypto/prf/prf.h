// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_PRF_H
#define TLSCLIENT_PRF_H

#include "tlsclient/public/base.h"
#include "tlsclient/src/handshake.h"

namespace tlsclient {

bool MasterSecretFromPreMasterSecret(uint8_t master[48],
                                     TLSVersion version,
                                     const uint8_t* premaster, size_t premaster_len,
                                     const uint8_t client_random[32],
                                     const uint8_t server_random[32]);

bool KeysFromMasterSecret(KeyBlock* inout, TLSVersion version,
                          const uint8_t master[48],
                          const uint8_t client_random[32],
                          const uint8_t server_random[32]);

class HandshakeHash {
 public:
  virtual ~HandshakeHash() { }

  virtual unsigned Length() const = 0;
  virtual void Update(const void* data, size_t length) = 0;
  virtual const uint8_t* ClientVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) = 0;
  virtual const uint8_t* ServerVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) = 0;
};

HandshakeHash* HandshakeHashForVersion(TLSVersion version);

}  // namespace tlsclient

#endif  // TLSCLIENT_PRF_H
