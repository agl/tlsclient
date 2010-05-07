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
  SEND_CLIENT_HELLO,
  RECV_SERVER_HELLO,
  RECV_CERTIFICATE,
  RECV_SERVER_HELLO_DONE,
  SEND_CLIENT_KEY_EXCHANGE,
  SEND_CHANGE_CIPHER_SPEC,
  SEND_FINISHED,
  RECV_SESSION_TICKET,
  RECV_CHANGE_CIPHER_SPEC,
  RECV_FINISHED,

  RECV_RESUME_SERVER_HELLO_DONE,
  RECV_RESUME_SESSION_TICKET,
  RECV_RESUME_CHANGE_CIPHER_SPEC,
  RECV_RESUME_FINISHED,
  SEND_RESUME_CHANGE_CIPHER_SPEC,
  SEND_RESUME_FINISHED,

  SEND_SNAP_START_CLIENT_KEY_EXCHANGE,
  SEND_SNAP_START_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_FINISHED,
  RECV_SNAP_START_SERVER_HELLO,
  RECV_SNAP_START_CERTIFICATE,
  RECV_SNAP_START_SERVER_HELLO_DONE,
  RECV_SNAP_START_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_FINISHED,

  RECV_SNAP_START_RECOVERY_CERTIFICATE,
  RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE,
  SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT,
  SEND_SNAP_START_RECOVERY_FINISHED,
  SEND_SNAP_START_RECOVERY_RETRANSMIT,
  RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RECOVERY_FINISHED,

  SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RESUME_FINISHED,
  RECV_SNAP_START_RESUME_SERVER_HELLO,
  RECV_SNAP_START_RESUME_SERVER_HELLO_DONE,
  RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RESUME_FINISHED,

  RECV_SNAP_START_RESUME_RECOVERY_SERVER_HELLO_DONE,
  RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RESUME_RECOVERY_FINISHED,
  SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT,
  SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RESUME_RECOVERY_FINISHED,
  SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT,

  RECV_SNAP_START_RESUME_RECOVERY2_CERTIFICATE,
  RECV_SNAP_START_RESUME_RECOVERY2_SERVER_HELLO_DONE,
  SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT,
  SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE,
  SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RESUME_RECOVERY2_FINISHED,
  SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT,
  RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET,
  RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RESUME_RECOVERY2_FINISHED,

  // Changing something here? Don't forget to update
  // kPermittedHandshakeMessagesPerState!

  STATE_MUST_BRANCH = 0xff,
};

enum HandshakeMessage {
  HELLO_REQUEST = 0,
  CLIENT_HELLO = 1,
  SERVER_HELLO = 2,
  SESSION_TICKET = 4,
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

struct KeyBlock {
  enum {
    MAX_LEN = 32,
  };

  unsigned key_len, mac_len, iv_len;
  uint8_t client_key[MAX_LEN];
  uint8_t server_key[MAX_LEN];
  uint8_t client_mac[MAX_LEN];
  uint8_t server_mac[MAX_LEN];
  uint8_t client_iv[MAX_LEN];
  uint8_t server_iv[MAX_LEN];
};

// ResumptionTypes enumerates the different sorts of resumption data that we'll
// serialise in |GetResumptionData|. These values may be stored on disk so
// should never be changed lightly.
enum ResumptionTypes {
  RESUMPTION_METHOD_SESSION_ID = 0,
  RESUMPTION_METHOD_SESSION_TICKET = 1,
};

class Sink;
struct ConnectionPrivate;
class Buffer;

bool IsValidAlertLevel(uint8_t wire_level);
bool IsValidVersion(uint16_t wire_version);
Result MarshalClientHello(Sink* sink, ConnectionPrivate* priv);
Result MarshalClientKeyExchange(Sink* sink, ConnectionPrivate* priv);
Result MarshalFinished(Sink* sink, ConnectionPrivate* priv);
bool NextIsApplicationData(Buffer* in);
Result GetHandshakeMessage(bool* found, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in);
Result GetRecordOrHandshake(bool* found, RecordType* type, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in, ConnectionPrivate* priv);
Result AlertTypeToResult(AlertType);

Result ProcessServerHello(ConnectionPrivate* priv, Buffer* in);
Result ProcessHandshakeMessage(ConnectionPrivate* priv, HandshakeMessage type, Buffer* in);
Result ProcessServerCertificate(ConnectionPrivate* priv, Buffer* in);
Result ProcessServerHelloDone(ConnectionPrivate* priv, Buffer* in);
Result ProcessServerFinished(ConnectionPrivate* priv, Buffer* in);
Result ProcessSessionTicket(ConnectionPrivate* priv, Buffer* in);
Result GenerateMasterSecret(ConnectionPrivate* priv);
Result SetupCiperSpec(ConnectionPrivate* priv);

}  // namespace tlsclient

#endif  // TLSCLIENT_HANDSHAKE_H
