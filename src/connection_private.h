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
class Certificate;
struct CipherSuite;
class HandshakeHash;

struct ConnectionPrivate {
  ConnectionPrivate(Context* in_ctx)
      : ctx(in_ctx),
        state(SEND_PHASE_ONE),
        sslv3(false),
        cipher_suite_flags_enabled(0),
        last_buffer(NULL),
        version_established(false),
        partial_record_remaining(0),
        application_data_allowed(false),
        cipher_suite(NULL),
        server_supports_renegotiation_info(false),
        server_cert(NULL),
        handshake_hash(NULL),
        read_cipher_spec(NULL),
        write_cipher_spec(NULL),
        pending_read_cipher_spec(NULL),
        pending_write_cipher_spec(NULL) {
  }

  ~ConnectionPrivate();

  Arena arena;
  Context* const ctx;
  HandshakeState state;
  std::string host_name;
  bool sslv3;
  // cipher_suite_flags_enabled is a bitmask of CIPHERSUITE_ values (see
  // src/handshake.h) which describes the set of ciphersuites that are
  // acceptable to the user.
  unsigned cipher_suite_flags_enabled;
  // last_buffer contains a pointer to the last marshall buffer. We assume
  // that, by the time the client calls Connection::Get() again, it has
  // finished with the last buffer and so we can free it. This buffer is
  // allocated via |arena|.
  uint8_t* last_buffer;
  // This is true if we have established a common TLS version in |version|
  bool version_established;
  TLSVersion version;
  // This is the number of bytes of record payload data currently pending. This
  // is non-zero if we parse a handshake message from a record, but there's
  // another handshake message in the same record. In this case, next time
  // GetRecordOrHandshake looks at the pending data it needs to know not to
  // expect a record header at the beginning.
  unsigned partial_record_remaining;
  // When returning vectors of application data, we need somewhere to store the
  // iovecs. We want to avoid allocating and freeing then everytime so we keep
  // this around. It will grow as needed but (hopefully) not shrink.
  std::vector<struct iovec> out_vectors;
  // This is true iff we have completed a handshake and are happy to pass
  // application data records to the client.
  bool application_data_allowed;
  uint8_t client_random[32];
  uint8_t server_random[32];
  const CipherSuite* cipher_suite;
  bool server_supports_renegotiation_info;
  // Each of these vectors contains an element of the server's certificate
  // chain (in the order received from the server). The underlying data is
  // allocated from |arena|.
  std::vector<struct iovec> server_certificates;
  // This is the server's certificate (i.e. the first one in it's certificate
  // chain)
  Certificate* server_cert;
  uint8_t master_secret[48];
  HandshakeHash* handshake_hash;
  CipherSpec* read_cipher_spec;
  CipherSpec* write_cipher_spec;
  CipherSpec* pending_read_cipher_spec;
  CipherSpec* pending_write_cipher_spec;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_CONNECTION_PRIVATE_H
