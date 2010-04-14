// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"

#include "tlsclient/public/context.h"
#include "tlsclient/public/error.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/crypto/cipher_suites.h"
#include "tlsclient/src/crypto/prf/prf.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"

namespace tlsclient {

ConnectionPrivate::~ConnectionPrivate() {
  delete server_cert;
  memset(master_secret, 0, sizeof(master_secret));
  delete handshake_hash;

  if (read_cipher_spec)
    read_cipher_spec->DecRef();
  if (write_cipher_spec)
    write_cipher_spec->DecRef();
  if (pending_read_cipher_spec)
    pending_read_cipher_spec->DecRef();
  if (pending_write_cipher_spec)
    pending_write_cipher_spec->DecRef();
}

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
  return priv_->state == AWAIT_HELLO_REQUEST;
}

static Result EncryptRecord(ConnectionPrivate* priv, Sink* sink) {
  if (!priv->write_cipher_spec)
    return 0;
  sink->WriteLength();

  struct iovec iov[2];
  iov[0].iov_base = const_cast<uint8_t*>(sink->data());
  iov[0].iov_len = sink->size();
  size_t scratch_size = priv->write_cipher_spec->ScratchBytesNeeded(sink->size());
  uint8_t* scratch = sink->Block(scratch_size);
  if (!priv->write_cipher_spec->Encrypt(scratch, &scratch_size, sink->data() - 5, iov, 1, priv->write_seq_num))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  priv->write_seq_num++;
  return 0;
}

Result Connection::Get(struct iovec* out) {
  Result r;

  if (priv_->last_buffer) {
    priv_->arena.Free(priv_->last_buffer);
    priv_->last_buffer = NULL;
  }

  Sink sink(&priv_->arena);

  if (!need_to_write())
    return ERROR_RESULT(ERR_UNNEEDED_GET);

  if (priv_->state == SEND_PHASE_ONE) {
    Sink s(sink.Record(TLSv12, RECORD_HANDSHAKE));
    {
      Sink ss(sink.HandshakeMessage(CLIENT_HELLO));
      if ((r = MarshalClientHello(&ss, priv_)))
        return r;
      // We don't add this handshake message to the handshake hash at this
      // point because we don't know which hash function we'll be using until
      // we get the ServerHello.
    }
    if ((r = EncryptRecord(priv_, &s)))
      return r;
    priv_->state = RECV_SERVER_HELLO;
  } else if (priv_->state == SEND_PHASE_TWO ||
             priv_->state == SEND_RESUME_PHASE_ONE) {
    Result r;
    if (priv_->state == SEND_PHASE_TWO) {
      Sink s(sink.Record(priv_->version, RECORD_HANDSHAKE));
      {
        Sink ss(sink.HandshakeMessage(CLIENT_KEY_EXCHANGE));
        if ((r = MarshalClientKeyExchange(&ss, priv_)))
          return r;
      }
      priv_->handshake_hash->Update(s.data(), s.size());
      if ((r = EncryptRecord(priv_, &s)))
        return r;
    }
    {
      Sink s(sink.Record(priv_->version, RECORD_CHANGE_CIPHER_SPEC));
      s.U8(1);
      if ((r = EncryptRecord(priv_, &s)))
        return r;
    }
    if (priv_->write_cipher_spec)
      priv_->write_cipher_spec->DecRef();
    priv_->write_cipher_spec = priv_->pending_write_cipher_spec;
    priv_->pending_write_cipher_spec = NULL;
    priv_->write_seq_num = 0;
    {
      Sink s(sink.Record(priv_->version, RECORD_HANDSHAKE));
      {
        Sink ss(sink.HandshakeMessage(FINISHED));
        if ((r = MarshalFinished(&ss, priv_)))
          return r;
      }
      priv_->handshake_hash->Update(s.data(), s.size());
      if ((r = EncryptRecord(priv_, &s)))
        return r;
    }

    if (priv_->state == SEND_PHASE_TWO) {
      priv_->state = RECV_CHANGE_CIPHER_SPEC;
    } else {
      priv_->state = AWAIT_HELLO_REQUEST;
    }
  } else {
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  priv_->last_buffer = sink.Release();
  priv_->last_buffer_len = sink.size();
  out->iov_len = sink.size();
  out->iov_base = priv_->last_buffer;
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

Result Connection::Encrypt(struct iovec* start, struct iovec* end, const struct iovec* iov, unsigned iov_len) {
  if (!is_ready_to_send_application_data())
    return ERROR_RESULT(ERR_NOT_READY_TO_SEND_APPLICATION_DATA);

  Buffer buf(iov, iov_len);
  size_t len = buf.size();

  if (len > 16384)
    return ERROR_RESULT(ERR_ENCRYPT_RECORD_TOO_LONG);

  // We need an extra element at the end of the array so we have to make a
  // copy.
  priv_->out_vectors.resize(iov_len + 1);
  memcpy(&priv_->out_vectors[0], iov, iov_len * sizeof(struct iovec));

  uint8_t* const header = priv_->scratch;
  header[0] = RECORD_APPLICATION_DATA;
  uint16_t wire_version = static_cast<uint16_t>(priv_->version);
  header[1] = wire_version >> 8;
  header[2] = wire_version;
  header[3] = len >> 8;
  header[4] = len;

  size_t scratch_size = sizeof(priv_->scratch) - 5;
  if (!priv_->write_cipher_spec->Encrypt(priv_->scratch + 5, &scratch_size, header, &priv_->out_vectors[0], iov_len, priv_->write_seq_num))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  priv_->write_seq_num++;

  len += scratch_size;
  header[3] = len >> 8;
  header[4] = len;

  start->iov_base = header;
  start->iov_len = 5;
  end->iov_base = priv_->scratch + 5;
  end->iov_len = scratch_size;

  return 0;
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
        return ERROR_RESULT(ERR_INTERNAL_ERROR);
    }
  }
}

static const uint8_t kResumptionSerialisationVersion = 0;

bool Connection::is_resumption_data_availible() const {
  return priv_->resumption_data_ready &&
         priv_->session_id_len;
}

Result Connection::GetResumptionData(struct iovec* iov) {
  Sink sink(&priv_->arena);

  if (priv_->state != AWAIT_HELLO_REQUEST ||
      priv_->session_id_len == 0) {
    return ERROR_RESULT(ERR_RESUMPTION_DATA_NOT_READY);
  }

  sink.U8(kResumptionSerialisationVersion);
  sink.U16(priv_->cipher_suite->value);
  uint8_t* master = sink.Block(sizeof(priv_->master_secret));
  memcpy(master, priv_->master_secret, sizeof(priv_->master_secret));
  sink.U8(priv_->session_id_len);
  uint8_t* session_id = sink.Block(sizeof(priv_->session_id));
  memcpy(session_id, priv_->session_id, sizeof(priv_->session_id));

  iov->iov_base = sink.Release();
  iov->iov_len = sink.size();

  return 0;
}

Result Connection::SetResumptionData(const uint8_t* data, size_t len) {
  const struct iovec iov = {const_cast<uint8_t*>(data), len};
  Buffer buf(&iov, 1);

  uint8_t version;
  if (!buf.Read(&version, 1) || version != kResumptionSerialisationVersion)
    return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);

  uint8_t cipher_suite_value_bytes[2];
  uint16_t cipher_suite_value;
  if (!buf.Read(&cipher_suite_value_bytes, 2))
    return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
  cipher_suite_value = static_cast<uint16_t>(cipher_suite_value_bytes[0]) << 8 |
                       cipher_suite_value_bytes[1];

  const CipherSuite* suites = AllCipherSuites();
  const CipherSuite* cipher_suite = NULL;
  for (unsigned i = 0; suites[i].flags; i++) {
    if (suites[i].value == cipher_suite_value) {
      if ((suites[i].flags & priv_->cipher_suite_flags_enabled) == suites[i].flags) {
        cipher_suite = &suites[i];
        break;
      } else {
        return ERROR_RESULT(ERR_RESUME_CIPHER_SUITE_NOT_ENABLED);
      }
    }
  }

  if (!cipher_suite)
    return ERROR_RESULT(ERR_RESUME_CIPHER_SUITE_NOT_FOUND);

  priv_->cipher_suite = cipher_suite;

  if (!buf.Read(priv_->master_secret, sizeof(priv_->master_secret)) ||
      !buf.Read(&priv_->session_id_len, sizeof(priv_->session_id_len)) ||
      priv_->session_id_len == 0 ||
      priv_->session_id_len > 32 ||
      !buf.Read(priv_->session_id, sizeof(priv_->session_id))) {
    priv_->session_id_len = 0;
    return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
  }

  return 0;
}

bool Connection::did_resume() const {
  return priv_->did_resume;
}

}  // namespace tlsclient
