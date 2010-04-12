// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_PRF_H
#define TLSCLIENT_PRF_H

#include "tlsclient/public/base.h"
#include "tlsclient/src/handshake.h"

namespace tlsclient {

bool KeysFromPreMasterSecret(TLSVersion version,
                             KeyBlock* inout,
                             const uint8_t* premaster, size_t premaster_len,
                             // FIXME: make explicit uint8_t[N] types for clarity.
                             const uint8_t* client_random,
                             const uint8_t* server_random);

class HandshakeHash {
 public:
  virtual ~HandshakeHash() { }

  virtual void Update(const void* data, size_t length) = 0;
  virtual void Final(const uint8_t* master_secret, size_t master_secret_len) = 0;
  virtual const uint8_t* client_verify_data() const = 0;
  virtual const uint8_t* server_verify_data() const = 0;
};

HandshakeHash* HandshakeHashForVersion(TLSVersion version);

}  // namespace tlsclient

#endif  // TLSCLIENT_PRF_H
