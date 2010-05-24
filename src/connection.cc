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

#include <stdio.h>

#if 0
#include <stdio.h>
static void hexdump(const void* data, size_t length) {
  const uint8_t* in = static_cast<const uint8_t*>(data);

  for (size_t i = 0; i < length; i++) {
    printf("%x", in[i] >> 4);
    printf("%x", in[i] & 15);
  }

  printf("\n");
}
#endif

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

void Connection::set_sslv3(bool use_sslv3) {
  priv_->sslv3 = use_sslv3;
}

void Connection::set_host_name(const char* name) {
  priv_->host_name = name;
}

static bool IsSendState(HandshakeState state) {
  switch (state) {
  case SEND_CLIENT_HELLO:
  case SEND_CLIENT_KEY_EXCHANGE:
  case SEND_CHANGE_CIPHER_SPEC:
  case SEND_FINISHED:
  case SEND_RESUME_CHANGE_CIPHER_SPEC:
  case SEND_RESUME_FINISHED:
  case SEND_SNAP_START_CLIENT_KEY_EXCHANGE:
  case SEND_SNAP_START_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_FINISHED:
  case SEND_SNAP_START_RECOVERY_CLIENT_KEY_EXCHANGE:
  case SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RECOVERY_FINISHED:
  case SEND_SNAP_START_RECOVERY_RETRANSMIT:
  case SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RESUME_FINISHED:
  case SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RESUME_RECOVERY_FINISHED:
  case SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT:
  case SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE:
  case SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RESUME_RECOVERY2_FINISHED:
  case SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT:
    return true;
  default:
    return false;
  }
}

bool Connection::need_to_write() const {
  return IsSendState(priv_->state);
}

bool Connection::is_server_cert_available() const {
  return false;
}

bool Connection::is_server_verified() const {
  return false;
}

bool Connection::is_ready_to_send_application_data() const {
  return priv_->can_send_application_data;
}

Result Connection::server_certificates(const struct iovec** out_iovs, unsigned* out_len) {
  if (priv_->server_certificates.size() == 0 && priv_->predicted_certificates.size()) {
    *out_iovs = &priv_->predicted_certificates[0];
    *out_len = priv_->server_certificates.size();
    return 0;
  }

  *out_iovs = &priv_->server_certificates[0];
  *out_len = priv_->server_certificates.size();
  return 0;
}

const char* Connection::cipher_suite_name() const {
  if (!priv_->cipher_suite)
    return NULL;
  return priv_->cipher_suite->name;
}

Result EncryptApplicationData(struct iovec* start, struct iovec* end, const struct iovec* iov, unsigned iov_len, size_t len, ConnectionPrivate* priv) {
  // We need an extra element at the end of the array so we have to make a
  // copy.
  priv->out_vectors.resize(iov_len + 1);
  memcpy(&priv->out_vectors[0], iov, iov_len * sizeof(struct iovec));

  uint8_t* const header = priv->scratch;
  header[0] = RECORD_APPLICATION_DATA;
  uint16_t wire_version = static_cast<uint16_t>(priv->version);
  if (priv->snap_start_attempt)
    wire_version = static_cast<uint16_t>(priv->predicted_server_version);
  header[1] = wire_version >> 8;
  header[2] = wire_version;
  header[3] = len >> 8;
  header[4] = len;

  size_t scratch_size = sizeof(priv->scratch) - 5;
  if (!priv->write_cipher_spec)
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  if (!priv->write_cipher_spec->Encrypt(priv->scratch + 5, &scratch_size, header, &priv->out_vectors[0], iov_len, priv->write_seq_num))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  priv->write_seq_num++;

  len += scratch_size;
  header[3] = len >> 8;
  header[4] = len;

  start->iov_base = header;
  start->iov_len = 5;
  end->iov_base = priv->scratch + 5;
  end->iov_len = scratch_size;

  return 0;
}

Result Connection::Encrypt(struct iovec* start, struct iovec* end, const struct iovec* iov, unsigned iov_len) {
  if (!is_ready_to_send_application_data())
    return ERROR_RESULT(ERR_NOT_READY_TO_SEND_APPLICATION_DATA);

  Buffer buf(iov, iov_len);
  size_t len = buf.size();

  if (len > 16384)
    return ERROR_RESULT(ERR_ENCRYPT_RECORD_TOO_LONG);

  return EncryptApplicationData(start, end, iov, iov_len, len, priv_);
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

static Result SendClientHello(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  Sink s(sink->Record(TLSv12, RECORD_HANDSHAKE));
  {
    Sink ss(s.HandshakeMessage(CLIENT_HELLO));
    if ((r = MarshalClientHello(&ss, priv)))
      return r;
    // We don't add this handshake message to the handshake hash at this
    // point because we don't know which hash function we'll be using until
    // we get the ServerHello.
  }

  if (!priv->snap_start_attempt)
    priv->state = RECV_SERVER_HELLO;

  priv->sent_client_hello.iov_len = s.size();
  priv->sent_client_hello.iov_base = priv->arena.Allocate(s.size());
  memcpy(priv->sent_client_hello.iov_base, s.data(), s.size());
  if (!priv->snap_start_attempt) {
    if ((r = EncryptRecord(priv, &s)))
      return r;
  }

  return 0;
}

static Result SendClientKeyExchange(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  Sink s(sink->Record(priv->version, RECORD_HANDSHAKE));
  {
    Sink ss(s.HandshakeMessage(CLIENT_KEY_EXCHANGE));
    if ((r = MarshalClientKeyExchange(&ss, priv)))
      return r;
  }

  priv->handshake_hash->Update(s.data(), s.size());
  if ((r = EncryptRecord(priv, &s)))
    return r;
  return 0;
}

static Result SendChangeCipherSpec(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  Sink s(sink->Record(priv->version, RECORD_CHANGE_CIPHER_SPEC));
  s.U8(1);
  if ((r = EncryptRecord(priv, &s)))
    return r;

  return 0;
}

static Result SendFinished(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  Sink s(sink->Record(priv->version, RECORD_HANDSHAKE));
  {
    Sink ss(s.HandshakeMessage(FINISHED));
    if ((r = MarshalFinished(&ss, priv)))
      return r;
  }
  priv->handshake_hash->Update(s.data(), s.size());
  if ((r = EncryptRecord(priv, &s)))
    return r;

  if (priv->false_start)
    priv->can_send_application_data = true;

  if (priv->state == SEND_FINISHED) {
    if (priv->expecting_session_ticket) {
      priv->state = RECV_SESSION_TICKET;
    } else {
      priv->state = RECV_CHANGE_CIPHER_SPEC;
    }
  }

  return 0;
}

extern const HandshakeState kNextState[];
extern const char *kStateNames[];

Result SendHandshakeMessages(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  while (IsSendState(priv->state)) {
    const HandshakeState prev_state = priv->state;
    switch (priv->state) {
    case SEND_CLIENT_HELLO:
      r = SendClientHello(sink, priv);
      break;
    case SEND_CLIENT_KEY_EXCHANGE:
    case SEND_SNAP_START_CLIENT_KEY_EXCHANGE:
    case SEND_SNAP_START_RECOVERY_CLIENT_KEY_EXCHANGE:
    case SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE:
      r = SendClientKeyExchange(sink, priv);
      if ((r = GenerateMasterSecret(priv)))
        return r;
      if ((r = SetupCiperSpec(priv)))
        return r;
      break;
    case SEND_CHANGE_CIPHER_SPEC:
    case SEND_RESUME_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC:
      if (priv->state == SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC) {
        if ((r = GenerateMasterSecret(priv)))
          return r;
      }
      if (priv->state == SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC ||
          priv->state == SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC) {
        if ((r = SetupCiperSpec(priv)))
          return r;
      }
      if ((r = SendChangeCipherSpec(sink, priv)))
        return r;

      if (priv->write_cipher_spec)
        priv->write_cipher_spec->DecRef();
      priv->write_cipher_spec = priv->pending_write_cipher_spec;
      priv->pending_write_cipher_spec = NULL;
      priv->write_seq_num = 0;

      break;
    case SEND_FINISHED:
    case SEND_RESUME_FINISHED:
    case SEND_SNAP_START_FINISHED:
    case SEND_SNAP_START_RESUME_FINISHED:
    case SEND_SNAP_START_RECOVERY_FINISHED:
    case SEND_SNAP_START_RESUME_RECOVERY_FINISHED:
    case SEND_SNAP_START_RESUME_RECOVERY2_FINISHED:
      r = SendFinished(sink, priv);
      break;
    case SEND_SNAP_START_RECOVERY_RETRANSMIT:
    case SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT:
    case SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT:
      priv->snap_start_attempt = false;

      {
        struct iovec start, end;
        if ((r = EncryptApplicationData(&start, &end, &priv->snap_start_application_data, 1, priv->snap_start_application_data.iov_len, priv)))
          return r;
        sink->Copy(start.iov_base, start.iov_len);
        sink->Copy(priv->snap_start_application_data.iov_base, priv->snap_start_application_data.iov_len);
        sink->Copy(end.iov_base, end.iov_len);

        priv->arena.Free(priv->snap_start_application_data.iov_base);
        priv->snap_start_application_data.iov_len = 0;
      }

      if (priv->state == SEND_SNAP_START_RECOVERY_RETRANSMIT) {
        if (priv->expecting_session_ticket) {
          priv->state = RECV_SNAP_START_RECOVERY_SESSION_TICKET;
        } else {
          priv->state = RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC;
        }
      } else if (priv->state == SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT) {
        if (priv->expecting_session_ticket) {
          priv->state = RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET;
        } else {
          priv->state = RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC;
        }
      }

      break;
    default:
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    }

    if (r)
      return r;

    if (priv->state == prev_state) {
      priv->state = kNextState[priv->state];
      if (priv->state == STATE_MUST_BRANCH)
        return ERROR_RESULT(ERR_INTERNAL_ERROR);
    }
  }

  if (sink->size() == 0)
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  return 0;
}

Result Connection::Get(struct iovec* out) {
  Result r;

  if (priv_->last_buffer) {
    priv_->arena.Free(priv_->last_buffer);
    priv_->last_buffer = NULL;
  }

  if (!need_to_write())
    return ERROR_RESULT(ERR_UNNEEDED_GET);

  Sink sink(&priv_->arena);

  if ((r = SendHandshakeMessages(&sink, priv_)))
    return r;

  priv_->last_buffer = sink.Release();
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

void Connection::EnableMD5(bool enable) {
  SetEnableBit(CIPHERSUITE_MD5, enable);
}

void Connection::EnableDefault() {
  SetEnableBit(CIPHERSUITE_RSA, true);
  SetEnableBit(CIPHERSUITE_SHA, true);
  SetEnableBit(CIPHERSUITE_SHA256, true);
  SetEnableBit(CIPHERSUITE_MD5, true);
  SetEnableBit(CIPHERSUITE_RC4, true);
  SetEnableBit(CIPHERSUITE_CBC, true);
  SetEnableBit(CIPHERSUITE_AES128, true);
  SetEnableBit(CIPHERSUITE_AES256, true);
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
  priv_->out_vectors.clear();

  Buffer buf(iov, n);
  bool found;
  RecordType type;
  HandshakeMessage htype;

  for (;;) {
    // In order to be False Start compatible, if we're waiting to send we stop
    // processing. Otherwise we'll be in the wrong state to process the record.
    if (need_to_write())
      return 0;

    if (priv_->out_vectors.size() && !NextIsApplicationData(&buf)) {
      // We had some amount of application data already and now we have another
      // form of record. We'll return the application level data now.
      return 0;
    }
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
      continue;
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
        const AlertLevel level = static_cast<AlertLevel>(wire_level);
        if (false && level == ALERT_LEVEL_WARNING)
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

    priv_->out_vectors.clear();
  }
}

static const uint8_t kResumptionSerialisationVersion = 0;

bool Connection::is_resumption_data_availible() const {
  return priv_->resumption_data_ready &&
         (priv_->session_id_len || priv_->expecting_session_ticket);
}

Result Connection::GetResumptionData(struct iovec* iov) {
  Sink sink(&priv_->arena);

  if (!priv_->resumption_data_ready)
    return ERROR_RESULT(ERR_RESUMPTION_DATA_NOT_READY);

  sink.U8(kResumptionSerialisationVersion);
  sink.U16(priv_->cipher_suite->value);
  uint8_t* master = sink.Block(sizeof(priv_->master_secret));
  memcpy(master, priv_->master_secret, sizeof(priv_->master_secret));

  if (priv_->session_id_len) {
    sink.U8(RESUMPTION_METHOD_SESSION_ID);
    sink.U8(priv_->session_id_len);
    uint8_t* session_id = sink.Block(priv_->session_id_len);
    memcpy(session_id, priv_->session_id, priv_->session_id_len);
  } else {
    sink.U8(RESUMPTION_METHOD_SESSION_TICKET);
    const size_t len = priv_->session_ticket.iov_len;
    sink.U16(len);
    uint8_t* ticket = sink.Block(len);
    memcpy(ticket, priv_->session_ticket.iov_base, len);
  }

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

  uint8_t resumption_type;

  if (!buf.Read(priv_->master_secret, sizeof(priv_->master_secret)) ||
      !buf.Read(&resumption_type, sizeof(resumption_type))) {
    return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
  }

  if (resumption_type == RESUMPTION_METHOD_SESSION_ID) {
    if (!buf.Read(&priv_->session_id_len, sizeof(priv_->session_id_len)) ||
        priv_->session_id_len == 0 ||
        priv_->session_id_len > sizeof(priv_->session_id) ||
        !buf.Read(priv_->session_id, priv_->session_id_len)) {
      priv_->session_id_len = 0;
      return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
    }
  } else if (resumption_type == RESUMPTION_METHOD_SESSION_TICKET) {
    uint16_t len;
    if (!buf.U16(&len))
      return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
    priv_->session_ticket.iov_base = priv_->arena.Allocate(len);
    priv_->session_ticket.iov_len = len;
    if (!buf.Read(priv_->session_ticket.iov_base, len))
      return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
    priv_->session_tickets = true;
    priv_->have_session_ticket_to_present = true;

    // We need to send a session id in order to recognise when the server
    // accepted our ticket.
    priv_->session_id_len = 1;
    priv_->session_id[0] = 0;
  } else {
    return ERROR_RESULT(ERR_CANNOT_PARSE_RESUMPTION_DATA);
  }

  return 0;
}

bool Connection::did_resume() const {
  return priv_->did_resume;
}

void Connection::EnableFalseStart(bool enable) {
  priv_->false_start = enable;
}

void Connection::EnableSessionTickets(bool enable) {
  priv_->session_tickets = enable;
}

void Connection::SetPredictedCertificates(const struct iovec* iovs, unsigned len) {
  priv_->predicted_certificates.resize(len);

  for (unsigned i = 0; i < len; i++) {
    priv_->predicted_certificates[i].iov_base = priv_->arena.Allocate(iovs[i].iov_len);
    priv_->predicted_certificates[i].iov_len = iovs[i].iov_len;
    memcpy(priv_->predicted_certificates[i].iov_base, iovs[i].iov_base, iovs[i].iov_len);
  }
}

void Connection::CollectSnapStartData() {
  priv_->collect_snap_start = true;
  priv_->session_tickets = true;
}

bool Connection::is_snap_start_data_available() const {
  return priv_->snap_start_data_available;
}

static const uint8_t kSnapStartSerialisationVersion = 1;

Result Connection::GetSnapStartData(struct iovec* iov) {
  Sink sink(&priv_->arena);

  if (!is_snap_start_data_available())
    return ERROR_RESULT(ERR_SNAP_START_DATA_NOT_READY);

  sink.U8(kSnapStartSerialisationVersion);

  sink.U16(static_cast<uint16_t>(priv_->version));
  sink.U16(static_cast<uint16_t>(priv_->cipher_suite->value));
  sink.Copy(priv_->server_epoch, sizeof(priv_->server_epoch));

  {
    Sink server_hello_sink(sink.VariableLengthBlock(2));
    uint8_t* server_hello = server_hello_sink.Block(priv_->snap_start_server_hello.iov_len);
    memcpy(server_hello, priv_->snap_start_server_hello.iov_base, priv_->snap_start_server_hello.iov_len);
  }

  iov->iov_base = sink.Release();
  iov->iov_len = sink.size();

  return 0;
}

Result Connection::SetSnapStartData(const uint8_t* data, size_t len, const uint8_t* app_data, size_t app_data_len) {
  const struct iovec iov = {const_cast<uint8_t*>(data), len};
  Buffer buf(&iov, 1);
  bool ok;

  if (priv_->predicted_certificates.size() == 0)
    return ERROR_RESULT(ERR_NEED_PREDICTED_CERTS_FIRST);

  uint8_t version;
  if (!buf.Read(&version, 1) || version != kSnapStartSerialisationVersion)
    return ERROR_RESULT(ERR_CANNOT_PARSE_SNAP_START_DATA);

  uint16_t wire_version;
  if (!buf.U16(&wire_version))
    return ERROR_RESULT(ERR_CANNOT_PARSE_SNAP_START_DATA);
  priv_->predicted_server_version = static_cast<TLSVersion>(wire_version);

  uint16_t cipher_suite_value;
  if (!buf.U16(&cipher_suite_value))
    return ERROR_RESULT(ERR_CANNOT_PARSE_SNAP_START_DATA);

  const CipherSuite* suites = AllCipherSuites();
  const CipherSuite* cipher_suite = NULL;
  for (unsigned i = 0; suites[i].flags; i++) {
    if (suites[i].value == cipher_suite_value) {
      if ((suites[i].flags & priv_->cipher_suite_flags_enabled) == suites[i].flags) {
        cipher_suite = &suites[i];
        break;
      }
    }
  }

  if (!cipher_suite)
    return ERROR_RESULT(ERR_RESUME_CIPHER_SUITE_NOT_FOUND);

  priv_->cipher_suite = cipher_suite;

  if (!buf.Read(priv_->predicted_epoch, sizeof(priv_->predicted_epoch)))
    return ERROR_RESULT(ERR_CANNOT_PARSE_SNAP_START_DATA);

  Buffer server_hello_buf(buf.VariableLength(&ok, 2));
  if (!ok)
    return ERROR_RESULT(ERR_CANNOT_PARSE_SNAP_START_DATA);

  const size_t server_hello_len = server_hello_buf.remaining();
  priv_->predicted_server_hello.iov_base = priv_->arena.Allocate(server_hello_len);
  priv_->predicted_server_hello.iov_len = server_hello_len;

  if (!server_hello_buf.Read(priv_->predicted_server_hello.iov_base, server_hello_len))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  priv_->snap_start_attempt = true;
  priv_->version = priv_->predicted_server_version;
  priv_->session_tickets = true;

  priv_->snap_start_application_data.iov_base = priv_->arena.Allocate(app_data_len);
  memcpy(priv_->snap_start_application_data.iov_base, app_data, app_data_len);
  priv_->snap_start_application_data.iov_len = app_data_len;

  return 0;
}

bool Connection::did_snap_start() const {
  return priv_->did_snap_start;
}

}  // namespace tlsclient
