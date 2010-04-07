// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CONNECTION_PRIVATE_H
#define TLSCLIENT_CONNECTION_PRIVATE_H

#include "tlsclient/public/base.h"
#include "tlsclient/src/arena.h"
#include "tlsclient/src/handshake.h"

#include <string>

namespace tlsclient {

class Context;

struct ConnectionPrivate {
  ConnectionPrivate(Context* in_ctx)
      : ctx(in_ctx),
        state(SEND_PHASE_ONE),
        sslv3(false),
        ciphersuite_flags(0),
        last_buffer(NULL),
        version_established(false) {
  }

  Arena arena;
  Context* const ctx;
  HandshakeState state;
  std::string host_name;
  bool sslv3;
  // ciphersuite_flags is a bitmask of CIPHERSUITE_ values (see
  // src/handshake.h) which describes the set of ciphersuites that are
  // acceptable to the user.
  unsigned ciphersuite_flags;
  // last_buffer contains a pointer to the last marshall buffer. We assume
  // that, by the time the client calls Connection::Get() again, it has
  // finished with the last buffer and so we can free it. This buffer is
  // allocated via |arena|.
  uint8_t* last_buffer;
  // This is true if we have established a common TLS version in |version|
  bool version_established;
  TLSVersion version;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_CONNECTION_PRIVATE_H
