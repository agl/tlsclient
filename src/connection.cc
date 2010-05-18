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

bool Connection::need_to_write() const {
  switch (priv_->state) {
  case SEND_CLIENT_HELLO:
  case SEND_CLIENT_KEY_EXCHANGE:
  case SEND_CHANGE_CIPHER_SPEC:
  case SEND_FINISHED:
  case SEND_RESUME_CHANGE_CIPHER_SPEC:
  case SEND_RESUME_FINISHED:
  case SEND_SNAP_START_CLIENT_KEY_EXCHANGE:
  case SEND_SNAP_START_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_FINISHED:
  case SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT:
  case SEND_SNAP_START_RECOVERY_CLIENT_KEY_EXCHANGE:
  case SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RECOVERY_FINISHED:
  case SEND_SNAP_START_RECOVERY_RETRANSMIT:
  case SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RESUME_FINISHED:
  case SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT:
  case SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RESUME_RECOVERY_FINISHED:
  case SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT:
  case SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT:
  case SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE:
  case SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC:
  case SEND_SNAP_START_RESUME_RECOVERY2_FINISHED:
  case SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT:
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

Result Connection::SendClientHello(Sink* sink) {
  Result r;

  Sink s(sink->Record(TLSv12, RECORD_HANDSHAKE));
  {
    Sink ss(s.HandshakeMessage(CLIENT_HELLO));
    if ((r = MarshalClientHello(&ss, priv_)))
      return r;
    // We don't add this handshake message to the handshake hash at this
    // point because we don't know which hash function we'll be using until
    // we get the ServerHello.
  }

  priv_->sent_client_hello.iov_len = s.size();
  priv_->sent_client_hello.iov_base = priv_->arena.Allocate(priv_->sent_client_hello.iov_len);
  memcpy(priv_->sent_client_hello.iov_base, s.data(), priv_->sent_client_hello.iov_len);

  if (priv_->snap_start_attempt) {
    priv_->handshake_hash = HandshakeHashForVersion(priv_->predicted_server_version);
    if (!priv_->handshake_hash)
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    priv_->handshake_hash->Update(s.data(), s.size());
    priv_->handshake_hash->Update(priv_->predicted_response.iov_base, priv_->predicted_response.iov_len);
    if (priv_->expecting_session_ticket) {
      priv_->state = SEND_SNAP_START_CLIENT_KEY_EXCHANGE;
    } else {
      // The Finished message, which we are about to send, needs to include
      // the server's Finished message, which doesn't exist yet. None the
      // less, we can predict the server's finished message and feed it into
      // our handshake hash, but we have to remember its value so that we can
      // compare it against the message when we receive it.

      unsigned verify_data_size;
      const uint8_t* verify_data = priv_->handshake_hash->ServerVerifyData(&verify_data_size, priv_->master_secret, sizeof(priv_->master_secret));
      priv_->server_verify.iov_base = priv_->arena.Allocate(verify_data_size);
      memcpy(priv_->server_verify.iov_base, verify_data, verify_data_size);
      priv_->server_verify.iov_len = verify_data_size;

      uint8_t handshake_header[4];
      handshake_header[0] = static_cast<uint8_t>(FINISHED);
      handshake_header[1] = handshake_header[2] = 0;
      handshake_header[3] = verify_data_size;

      priv_->handshake_hash->Update(handshake_header, sizeof(handshake_header));
      priv_->handshake_hash->Update(verify_data, verify_data_size);

      Result r = SetupCiperSpec(priv_);
      if (r)
        return r;
      priv_->state = SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC;
    }
  } else {
    if ((r = EncryptRecord(priv_, &s)))
      return r;
    priv_->state = RECV_SERVER_HELLO;
  }

  return 0;
}

Result Connection::SendClientKeyExchange(Sink* sink) {
  Result r;

  Sink s(sink->Record(priv_->version, RECORD_HANDSHAKE));
  {
    Sink ss(s.HandshakeMessage(CLIENT_KEY_EXCHANGE));
    if ((r = MarshalClientKeyExchange(&ss, priv_)))
      return r;
  }

  priv_->handshake_hash->Update(s.data(), s.size());
  if ((r = EncryptRecord(priv_, &s)))
    return r;
  return 0;
}

Result Connection::SendChangeCipherSpec(Sink* sink) {
  Result r;

  Sink s(sink->Record(priv_->version, RECORD_CHANGE_CIPHER_SPEC));
  s.U8(1);
  if ((r = EncryptRecord(priv_, &s)))
    return r;

  return 0;
}

Result Connection::SendFinished(Sink* sink) {
  Result r;

  Sink s(sink->Record(priv_->version, RECORD_HANDSHAKE));
  {
    Sink ss(s.HandshakeMessage(FINISHED));
    if ((r = MarshalFinished(&ss, priv_)))
      return r;
  }
  priv_->handshake_hash->Update(s.data(), s.size());
  if ((r = EncryptRecord(priv_, &s)))
    return r;

  if (priv_->false_start || priv_->snap_start_attempt) {
    priv_->can_send_application_data = true;
    priv_->recording_application_data = true;
  }

  if (priv_->state == SEND_FINISHED) {
    if (priv_->expecting_session_ticket) {
      priv_->state = RECV_SESSION_TICKET;
    } else {
      priv_->state = RECV_CHANGE_CIPHER_SPEC;
    }
  }

  return 0;
}

extern const HandshakeState kNextState[];
extern const char *kStateNames[];

Result Connection::Get(struct iovec* out) {
  Result r;

  if (priv_->last_buffer) {
    priv_->arena.Free(priv_->last_buffer);
    priv_->last_buffer = NULL;
  }

  if (!need_to_write())
    return ERROR_RESULT(ERR_UNNEEDED_GET);

  Sink sink(&priv_->arena);

  while (need_to_write()) {
    const HandshakeState prev_state = priv_->state;
    switch (priv_->state) {
    case SEND_CLIENT_HELLO:
      r = SendClientHello(&sink);
      break;
    case SEND_CLIENT_KEY_EXCHANGE:
    case SEND_SNAP_START_CLIENT_KEY_EXCHANGE:
    case SEND_SNAP_START_RECOVERY_CLIENT_KEY_EXCHANGE:
    case SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE:
      r = SendClientKeyExchange(&sink);
      if ((r = GenerateMasterSecret(priv_)))
        return r;
      if ((r = SetupCiperSpec(priv_)))
        return r;
      break;
    case SEND_CHANGE_CIPHER_SPEC:
    case SEND_RESUME_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT:
    case SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT:
    case SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC:
    case SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT:
    case SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC:
      if (priv_->state == SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC) {
        if ((r = GenerateMasterSecret(priv_)))
          return r;
      }
      if (priv_->state == SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC ||
          priv_->state == SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC) {
        if ((r = SetupCiperSpec(priv_)))
          return r;
      }
      if ((r = SendChangeCipherSpec(&sink)))
        return r;

      if (priv_->state != SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT &&
          priv_->state != SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT &&
          priv_->state != SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT) {
        if (priv_->write_cipher_spec)
          priv_->write_cipher_spec->DecRef();
        priv_->write_cipher_spec = priv_->pending_write_cipher_spec;
        priv_->pending_write_cipher_spec = NULL;
        priv_->write_seq_num = 0;
      }

      break;
    case SEND_FINISHED:
    case SEND_RESUME_FINISHED:
    case SEND_SNAP_START_FINISHED:
    case SEND_SNAP_START_RESUME_FINISHED:
    case SEND_SNAP_START_RECOVERY_FINISHED:
    case SEND_SNAP_START_RESUME_RECOVERY_FINISHED:
    case SEND_SNAP_START_RESUME_RECOVERY2_FINISHED:
      r = SendFinished(&sink);
      break;
    case SEND_SNAP_START_RECOVERY_RETRANSMIT:
    case SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT:
    case SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT:
      priv_->recording_application_data = false;

      for (std::vector<struct iovec>::const_iterator i = priv_->recorded_application_data.begin(); i != priv_->recorded_application_data.end(); i++) {
        struct iovec start, end;
        Encrypt(&start, &end, &(*i), 1);
        uint8_t* a = sink.Block(start.iov_len);
        memcpy(a, start.iov_base, start.iov_len);
        uint8_t* b = sink.Block(i->iov_len);
        memcpy(b, i->iov_base, i->iov_len);
        uint8_t* c = sink.Block(end.iov_len);
        memcpy(c, end.iov_base, end.iov_len);
        priv_->arena.Free(i->iov_base);
      }
      priv_->recorded_application_data.clear();
      priv_->snap_start_attempt = false;

      if (priv_->state == SEND_SNAP_START_RECOVERY_RETRANSMIT) {
        if (priv_->expecting_session_ticket) {
          priv_->state = RECV_SNAP_START_RECOVERY_SESSION_TICKET;
        } else {
          priv_->state = RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC;
        }
      } else if (priv_->state == SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT) {
        if (priv_->expecting_session_ticket) {
          priv_->state = RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET;
        } else {
          priv_->state = RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC;
        }
      }

      break;
    default:
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    }

    if (r)
      return r;

    if (priv_->state == prev_state) {
      priv_->state = kNextState[priv_->state];
      if (priv_->state == STATE_MUST_BRANCH)
        return ERROR_RESULT(ERR_INTERNAL_ERROR);
    }
  }

  if (sink.size() == 0)
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

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
  SetEnableBit(CIPHERSUITE_RC4, true);
  SetEnableBit(CIPHERSUITE_SHA, true);
  SetEnableBit(CIPHERSUITE_MD5, true);
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

  if (priv_->recording_application_data) {
    uint8_t* data = static_cast<uint8_t*>(priv_->arena.Allocate(len));
    if (!buf.Read(data, len))
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    const struct iovec iov = {data, len};
    priv_->recorded_application_data.push_back(iov);
  }

  // We need an extra element at the end of the array so we have to make a
  // copy.
  priv_->out_vectors.resize(iov_len + 1);
  memcpy(&priv_->out_vectors[0], iov, iov_len * sizeof(struct iovec));

  uint8_t* const header = priv_->scratch;
  header[0] = RECORD_APPLICATION_DATA;
  uint16_t wire_version = static_cast<uint16_t>(priv_->version);
  if (priv_->snap_start_attempt)
    wire_version = static_cast<uint16_t>(priv_->predicted_server_version);
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

Result Connection::SetSnapStartData(const uint8_t* data, size_t len) {
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

  return 0;
}

bool Connection::did_snap_start() const {
  return priv_->did_snap_start;
}

}  // namespace tlsclient
