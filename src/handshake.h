// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_HANDSHAKE_H
#define TLSCLIENT_HANDSHAKE_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/error.h"
#include "tlsclient/src/tls.h"

#include <vector>

namespace tlsclient {

// These are the states that a handshake can be in. Note the comment at the
// bottom that references other places that must be updated when adding a new
// state.
enum HandshakeState {
  // Full handshake
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

  // Resume handshakes (session tickets or otherwise)
  RECV_RESUME_SERVER_HELLO_DONE,
  RECV_RESUME_SESSION_TICKET,
  RECV_RESUME_CHANGE_CIPHER_SPEC,
  RECV_RESUME_FINISHED,
  SEND_RESUME_CHANGE_CIPHER_SPEC,
  SEND_RESUME_FINISHED,

  // Snap start full handshake
  SEND_SNAP_START_CLIENT_KEY_EXCHANGE,
  SEND_SNAP_START_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_FINISHED,
  RECV_SNAP_START_SESSION_TICKET,
  RECV_SNAP_START_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_FINISHED,

  // Snap start full handshake recovery
  RECV_SNAP_START_RECOVERY_CERTIFICATE,
  RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE,
  SEND_SNAP_START_RECOVERY_CLIENT_KEY_EXCHANGE,
  SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RECOVERY_FINISHED,
  SEND_SNAP_START_RECOVERY_RETRANSMIT,
  RECV_SNAP_START_RECOVERY_SESSION_TICKET,
  RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RECOVERY_FINISHED,

  // Snap start resume handshake
  SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RESUME_FINISHED,
  RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RESUME_FINISHED,

  // Snap start resume handshake recovery
  RECV_SNAP_START_RESUME_RECOVERY_SESSION_TICKET,
  RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RESUME_RECOVERY_FINISHED,
  SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RESUME_RECOVERY_FINISHED,
  SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT,

  // Snap start resume handshake double recovery (both the snap start and the
  // resumption were rejected).
  RECV_SNAP_START_RESUME_RECOVERY2_CERTIFICATE,
  RECV_SNAP_START_RESUME_RECOVERY2_SERVER_HELLO_DONE,
  SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE,
  SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC,
  SEND_SNAP_START_RESUME_RECOVERY2_FINISHED,
  SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT,
  RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET,
  RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC,
  RECV_SNAP_START_RESUME_RECOVERY2_FINISHED,

  // Changing something here? Don't forget to update
  // kPermittedHandshakeMessagesPerState and kNextState!

  // Used in kNextState to indicate that this state forks and so
  // cannot be advanced automatically.
  STATE_MUST_BRANCH = 0xff,
};

// A KeyBlock contains the keying material required for a CipherSuite. See RFC
// 5246, section 6.2.
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

Result SendHandshakeMessages(Sink* sink, ConnectionPrivate* priv);
Result EncryptApplicationData(struct iovec* start, struct iovec* end, const struct iovec* iov, unsigned iov_len, size_t len, ConnectionPrivate* priv);

}  // namespace tlsclient

#endif  // TLSCLIENT_HANDSHAKE_H
