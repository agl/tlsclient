// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"

#include "tlsclient/public/error.h"
#include "tlsclient/public/buffer.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"

namespace tlsclient {

Connection::Connection(Context* ctx)
    : priv_(new ConnectionPrivate(ctx)) {
}

Connection::~Connection() {
  delete priv_;
}

void Connection::set_host_name(const char* name) {
  priv_->host_name = name;
}

bool Connection::need_to_write() const {
  switch (priv_->state) {
  case SEND_PHASE_ONE:
  case SEND_PHASE_TWO:
    return true;
  default:
    return false;
  }
}

bool Connection::is_server_cert_available() const {
  return false;
}

bool Connection::is_server_verified() const {
  return false;
}

bool Connection::is_ready_to_send_application_data() const {
  return false;
}

Result Connection::Get(struct iovec* out) {
  if (priv_->last_buffer) {
    priv_->arena.Free(priv_->last_buffer);
    priv_->last_buffer = NULL;
  }

  Sink sink(&priv_->arena);

  assert(need_to_write());

  if (priv_->state == SEND_PHASE_ONE) {
    Sink s(sink.Record(TLSv12, RECORD_HANDSHAKE));
    Sink ss(sink.HandshakeMessage(CLIENT_HELLO));
    const Result r = MarshallClientHello(&ss, priv_);
    if (r)
      return r;
    priv_->state = RECV_SERVER_HELLO;
  } else if (priv_->state == SEND_PHASE_TWO) {
    Sink s(sink.Record(TLSv12, RECORD_HANDSHAKE));
    {
      Sink ss(sink.HandshakeMessage(CLIENT_KEY_EXCHANGE));
      assert(false);
      /*const Result r = MarshallClientKeyExchange(&ss, priv_);
      if (r)
        return r;*/
    }
    priv_->state = RECV_CHANGE_CIPHER_SPEC;
  } else {
    assert(false);
  }

  out->iov_len = sink.size();
  out->iov_base = sink.Release();
  return 0;
}

void Connection::EnableRSA(bool enable) {
  SetEnableBit(CIPHERSUITE_RSA, enable);
}

void Connection::EnableRC4(bool enable) {
  SetEnableBit(CIPHERSUITE_RC4, enable);
}

void Connection::EnableSHA(bool enable) {
  SetEnableBit(CIPHERSUITE_SHA, enable);
}

void Connection::EnableDefault() {
  SetEnableBit(CIPHERSUITE_RSA, true);
  SetEnableBit(CIPHERSUITE_RC4, true);
  SetEnableBit(CIPHERSUITE_SHA, true);
}

void Connection::SetEnableBit(unsigned mask, bool enable) {
  if (enable) {
    priv_->cipher_suite_flags_enabled |= mask;
  } else {
    priv_->cipher_suite_flags_enabled &= ~mask;
  }
}

Result Connection::Process(struct iovec** out, unsigned* out_n, size_t* used,
                           const struct iovec* iov, unsigned n) {
  *out = NULL;
  *out_n = 0;
  *used = 0;

  Buffer buf(iov, n);
  bool found;
  RecordType type;
  HandshakeMessage htype;

  for (;;) {
    // In order to be False Start compatible, if we're waiting to send we stop
    // processing. Otherwise we'll be in the wrong state to process the record.
    if (need_to_write())
      return 0;

    priv_->out_vectors.clear();

    Result r = GetRecordOrHandshake(&found, &type, &htype, &priv_->out_vectors, &buf, priv_);
    if (r)
      return r;

    if (!found)
      return 0;

    if (type == RECORD_APPLICATION_DATA) {
      if (!priv_->application_data_allowed)
        return ERROR_RESULT(ERR_UNEXPECTED_APPLICATION_DATA);
      *out = &priv_->out_vectors[0];
      *out_n = priv_->out_vectors.size();
      *used = buf.TellBytes();
      return 0;
    }

    Buffer in(&priv_->out_vectors[0], priv_->out_vectors.size());

    switch (type) {
      case RECORD_ALERT: {
        if (in.size() != 2)
          return ERROR_RESULT(ERR_INCORRECT_ALERT_LENGTH);
        uint8_t wire_level;
        in.Read(&wire_level, 1);
        if (!IsValidAlertLevel(wire_level))
          return ERROR_RESULT(ERR_INVALID_ALERT_LEVEL);
        const AlertLevel level = static_cast<AlertLevel>(level);
        if (level == ALERT_LEVEL_WARNING)
          continue;  // FIXME: what to do about warnings?
        uint8_t alert_type;
        in.Read(&alert_type, 1);
      *used = buf.TellBytes();
        return AlertTypeToResult(static_cast<AlertType>(alert_type));
      }
      case RECORD_CHANGE_CIPHER_SPEC:
        r = ProcessHandshakeMessage(priv_, CHANGE_CIPHER_SPEC, &in);
        if (r)
          return r;
        *used = buf.TellBytes();
        break;
      case RECORD_HANDSHAKE:
        r = ProcessHandshakeMessage(priv_, htype, &in);
        if (r)
          return r;
        *used = buf.TellBytes();
        break;
      default:
        assert(false);
    }
  }
}

}  // namespace tlsclient
