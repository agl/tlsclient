// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_HANDSHAKE_H
#define TLSCLIENT_HANDSHAKE_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/error.h"

namespace tlsclient {

enum HandshakeState {
  AWAIT_HELLO_REQUEST = 0,
  SEND_PHASE_ONE,
  RECV_SERVER_HELLO,
  RECV_SERVER_CERTIFICATE,
  RECV_SERVER_HELLO_DONE,
  SEND_PHASE_TWO,
  RECV_CHANGE_CIPHER_SPEC,
  RECV_FINISHED,
};

enum HandshakeMessage {
  HELLO_REQUEST = 0,
  CLIENT_HELLO = 1,
  SERVER_HELLO = 2,
  CERTIFICATE = 11,
  SERVER_KEY_EXCHANGE = 12,
  CERTIFICATE_REQUEST = 13,
  SERVER_HELLO_DONE = 14,
  CERTIFICATE_VERIFY = 15,
  CLIENT_KEY_EXCHANGE = 16,
  FINISHED = 20,
  INVALID_MESSAGE = -1,
  CHANGE_CIPHER_SPEC = 0xffff,
  // If you add new entries here, also add them to IsValidHandshakeType
};

enum TLSVersion {
  SSLv3 = 0x0300,
  TLSv10 = 0x0301,
  TLSv11 = 0x0302,
  TLSv12 = 0x0303,
  // If you add new entries here, also add them to IsValidVersion
};

enum RecordType {
  RECORD_CHANGE_CIPHER_SPEC = 20,
  RECORD_ALERT = 21,
  RECORD_HANDSHAKE = 22,
  RECORD_APPLICATION_DATA = 23,
  // If you add new entries here, also add them to IsValidRecordType
};

enum {
  CIPHERSUITE_RSA = 1 << 0,
  CIPHERSUITE_RC4 = 1 << 1,
  CIPHERSUITE_SHA = 1 << 2,
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
};

class Sink;
class ConnectionPrivate;

struct Extension {
 public:
  // Called to see if this extension should be included.
  virtual bool ShouldBeIncluded(ConnectionPrivate* priv) const = 0;
  virtual Result Marshall(Sink* sink, ConnectionPrivate* priv) const = 0;
  // The IANA assigned extension number.
  virtual uint16_t value() const = 0;
};

Result MarshallClientHello(Sink* sink, ConnectionPrivate* priv);
Result MarshallClientHelloExtensions(Sink* sink, ConnectionPrivate* priv);

}  // namespace tlsclient

#endif  // TLSCLIENT_HANDSHAKE_H
