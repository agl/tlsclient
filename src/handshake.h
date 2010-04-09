// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_HANDSHAKE_H
#define TLSCLIENT_HANDSHAKE_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/error.h"

#include <vector>

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
  // Changing something here? Don't forget to update
  // kPermittedHandshakeMessagesPerState!
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

enum AlertLevel {
  ALERT_LEVEL_WARNING = 1,
  ALERT_LEVEL_ERROR = 2,
};

enum AlertType {
  ALERT_CLOSE_NOTIFY = 0,
  ALERT_UNEXPECTED_MESSAGE = 10,
  ALERT_BAD_RECORD_MAC = 20,
  ALERT_DECRYPTION_FAILED = 21,
  ALERT_RECORD_OVERFLOW = 22,
  ALERT_DECOMPRESSION_FAILURE = 30,
  ALERT_HANDSHAKE_FAILURE = 40,
  ALERT_NO_CERTIFICATE = 41,
  ALERT_BAD_CERTIFICATE = 42,
  ALERT_UNSUPPORTED_CERTIFICATE = 43,
  ALERT_CERTIFICATE_REVOKED = 44,
  ALERT_CERTIFICATE_EXPIRED = 45,
  ALERT_CERTIFICATE_UNKNOWN = 46,
  ALERT_ILLEGAL_PARAMETER = 47,
  ALERT_UNKNOWN_CA = 48,
  ALERT_ACCESS_DENIED = 49,
  ALERT_DECODE_ERROR = 50,
  ALERT_DECRYPT_ERROR = 51,
  ALERT_EXPORT_RESTRICTION = 60,
  ALERT_PROTOCOL_VERSION = 70,
  ALERT_INSUFFICIENT_SECURITY = 71,
  ALERT_INTERNAL_ERROR = 80,
  ALERT_USER_CANCELED = 90,
  ALERT_NO_RENEGOTIATION = 100,
  ALERT_UNSUPPORTED_EXTENSION = 110,
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
class Buffer;

bool IsValidAlertLevel(uint8_t wire_level);
Result MarshallClientHello(Sink* sink, ConnectionPrivate* priv);
Result GetHandshakeMessage(bool* found, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in);
Result GetRecordOrHandshake(bool* found, RecordType* type, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in, ConnectionPrivate* priv);
Result AlertTypeToResult(AlertType);

Result ProcessServerHello(ConnectionPrivate* priv, Buffer* in);
Result ProcessHandshakeMessage(ConnectionPrivate* priv, HandshakeMessage type, Buffer* in);
Result ProcessServerCertificate(ConnectionPrivate* priv, Buffer* in);
Result ProcessServerHelloDone(ConnectionPrivate* priv, Buffer* in);

}  // namespace tlsclient

#endif  // TLSCLIENT_HANDSHAKE_H
