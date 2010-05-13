// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/handshake.h"

#include <vector>

#include "tlsclient/public/context.h"
#include "tlsclient/public/error.h"
#include "tlsclient/src/base-internal.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/src/crypto/prf/prf.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/extension.h"
#include "tlsclient/src/sink.h"
#include "tlsclient/src/crypto/cipher_suites.h"

#include <stdio.h>

namespace tlsclient {

// RFC 5746, section 3.3
static const uint16_t kSignalingCipherSuiteValue = 0xff00;

bool IsValidHandshakeType(uint8_t type) {
  HandshakeMessage m(static_cast<HandshakeMessage>(type));

  switch (m) {
    case HELLO_REQUEST:
    case CLIENT_HELLO:
    case SERVER_HELLO:
    case CERTIFICATE:
    case SERVER_KEY_EXCHANGE:
    case CERTIFICATE_REQUEST:
    case SERVER_HELLO_DONE:
    case CERTIFICATE_VERIFY:
    case CLIENT_KEY_EXCHANGE:
    case FINISHED:
    case SESSION_TICKET:
      return true;
    default:
      return false;
  }
}

bool IsValidRecordType(uint8_t wire_value) {
  RecordType t = static_cast<RecordType>(wire_value);

  switch (t) {
    case RECORD_CHANGE_CIPHER_SPEC:
    case RECORD_ALERT:
    case RECORD_HANDSHAKE:
    case RECORD_APPLICATION_DATA:
      return true;
    default:
      return false;
  }
}

bool IsValidAlertLevel(uint8_t wire_level) {
  AlertLevel level = static_cast<AlertLevel>(wire_level);

  switch (level) {
    case ALERT_LEVEL_WARNING:
    case ALERT_LEVEL_ERROR:
      return true;
    default:
      return false;
  }
}

bool IsValidVersion(uint16_t wire_version) {
  TLSVersion v = static_cast<TLSVersion>(wire_version);

  switch (v) {
    case SSLv3:
    case TLSv10:
    case TLSv11:
    case TLSv12:
      return true;
    default:
      return false;
  }
}

Result AlertTypeToResult(AlertType type) {
  switch (type) {
    case ALERT_CLOSE_NOTIFY:
      return ERROR_RESULT(ERR_ALERT_CLOSE_NOTIFY);
    case ALERT_UNEXPECTED_MESSAGE:
      return ERROR_RESULT(ERR_ALERT_UNEXPECTED_MESSAGE);
    case ALERT_BAD_RECORD_MAC:
      return ERROR_RESULT(ERR_ALERT_BAD_RECORD_MAC);
    case ALERT_DECRYPTION_FAILED:
      return ERROR_RESULT(ERR_ALERT_DECRYPTION_FAILED);
    case ALERT_HANDSHAKE_FAILURE:
      return ERROR_RESULT(ERR_ALERT_HANDSHAKE_FAILURE);
    case ALERT_NO_CERTIFICATE:
      return ERROR_RESULT(ERR_ALERT_NO_CERTIFICATE);
    case ALERT_BAD_CERTIFICATE:
      return ERROR_RESULT(ERR_ALERT_BAD_CERTIFICATE);
    case ALERT_UNSUPPORTED_CERTIFICATE:
      return ERROR_RESULT(ERR_ALERT_UNSUPPORTED_CERTIFICATE);
    case ALERT_CERTIFICATE_REVOKED:
      return ERROR_RESULT(ERR_ALERT_CERTIFICATE_REVOKED);
    case ALERT_CERTIFICATE_EXPIRED:
      return ERROR_RESULT(ERR_ALERT_CERTIFICATE_EXPIRED);
    case ALERT_CERTIFICATE_UNKNOWN:
      return ERROR_RESULT(ERR_ALERT_CERTIFICATE_UNKNOWN);
    case ALERT_ILLEGAL_PARAMETER:
      return ERROR_RESULT(ERR_ALERT_ILLEGAL_PARAMETER);
    case ALERT_UNKNOWN_CA:
      return ERROR_RESULT(ERR_ALERT_UNKNOWN_CA);
    case ALERT_ACCESS_DENIED:
      return ERROR_RESULT(ERR_ALERT_ACCESS_DENIED);
    case ALERT_DECODE_ERROR:
      return ERROR_RESULT(ERR_ALERT_DECODE_ERROR);
    case ALERT_DECRYPT_ERROR:
      return ERROR_RESULT(ERR_ALERT_DECRYPT_ERROR);
    case ALERT_EXPORT_RESTRICTION:
      return ERROR_RESULT(ERR_ALERT_EXPORT_RESTRICTION);
    case ALERT_PROTOCOL_VERSION:
      return ERROR_RESULT(ERR_ALERT_PROTOCOL_VERSION);
    case ALERT_INSUFFICIENT_SECURITY:
      return ERROR_RESULT(ERR_ALERT_INSUFFICIENT_SECURITY);
    case ALERT_INTERNAL_ERROR:
      return ERROR_RESULT(ERR_ALERT_INTERNAL_ERROR);
    case ALERT_USER_CANCELED:
      return ERROR_RESULT(ERR_ALERT_USER_CANCELED);
    case ALERT_NO_RENEGOTIATION:
      return ERROR_RESULT(ERR_ALERT_NO_RENEGOTIATION);
    case ALERT_UNSUPPORTED_EXTENSION:
      return ERROR_RESULT(ERR_ALERT_UNSUPPORTED_EXTENSION);
    default:
      return ERROR_RESULT(ERR_UNKNOWN_FATAL_ALERT);
  }
}

// NextIsApplicationData returns true if the next record in the given Buffer is
// an application data record. The record need not be complete. If insufficient
// data is in the buffer, it returns false.
bool NextIsApplicationData(Buffer* in) {
  if (!in->remaining())
    return false;

  const Buffer::Pos pos = in->Tell();
  uint8_t type;
  const bool r = in->U8(&type);
  in->Seek(pos);
  if (!r)
    return false;
  return static_cast<RecordType>(type) == RECORD_APPLICATION_DATA;
}

// FIXME: I just made this up --agl
static const unsigned kMaxHandshakeLength = 65536;

Result GetHandshakeMessage(bool* found, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in) {
  uint8_t header[4];
  *found = false;

  if (!in->Read(header, sizeof(header)))
    return 0;

  if (!IsValidHandshakeType(header[0]))
    return ERROR_RESULT(ERR_UNKNOWN_HANDSHAKE_MESSAGE_TYPE);
  *htype = static_cast<HandshakeMessage>(header[0]);

  const uint32_t length = static_cast<uint32_t>(header[1]) << 16 |
                          static_cast<uint32_t>(header[2]) << 8 |
                          header[3];
  if (length > kMaxHandshakeLength)
    return ERROR_RESULT(ERR_HANDSHAKE_MESSAGE_TOO_LONG);
  if (in->remaining() < length)
    return 0;

  in->PeekV(out, length);
  in->Advance(length);
  *found = true;
  return 0;
}

Result GetRecordOrHandshake(bool* found, RecordType* type, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in, ConnectionPrivate* priv) {
  uint8_t header[5];
  *found = false;
  std::vector<struct iovec> handshake_vectors;

  for (unsigned n = 0; ; n++) {
    const bool first_record = n == 0;
    uint16_t length;

    if (priv->partial_record_remaining && first_record) {
      length = priv->partial_record_remaining;
      // We only ever half-process a record if it's a handshake record.
      *type = RECORD_HANDSHAKE;
    } else {
      if (!in->Read(header, sizeof(header)))
        return 0;
      if (!IsValidRecordType(header[0]))
        return ERROR_RESULT(ERR_INVALID_RECORD_TYPE);
      *type = static_cast<RecordType>(header[0]);

      const uint16_t version = static_cast<uint16_t>(header[1]) << 8 | header[2];
      if (priv->version_established) {
        if (priv->version != static_cast<TLSVersion>(version))
          return ERROR_RESULT(ERR_BAD_RECORD_VERSION);
      } else {
        if (!IsValidVersion(version))
          return ERROR_RESULT(ERR_INVALID_RECORD_VERSION);
        priv->version_established = true;
        priv->version = static_cast<TLSVersion>(version);
      }

      length = static_cast<uint16_t>(header[3]) << 8 | header[4];
      if (in->remaining() < length)
        return 0;

      if (*type != RECORD_HANDSHAKE) {
        if (!first_record)
          return ERROR_RESULT(ERR_TRUNCATED_HANDSHAKE_MESSAGE);
        // Records other than handshake records are processed one at a time and
        // we can store the vectors directly into |out|.
        const size_t orig = out->size();
        in->PeekV(out, length);
        if (priv->read_cipher_spec) {
          unsigned iov_len = out->size() - orig;
          unsigned bytes_stripped;
          if (!priv->read_cipher_spec->Decrypt(&bytes_stripped, &(*out)[orig], &iov_len, header, priv->read_seq_num))
            return ERROR_RESULT(ERR_BAD_MAC);
          out->resize(orig + iov_len);
          priv->read_seq_num++;
        }

        in->Advance(length);
        *found = true;
        return 0;
      }
    }

    // Otherwise we append the vectors of the handshake message into
    // |handshake_vectors|
    const size_t orig = handshake_vectors.size();
    in->PeekV(&handshake_vectors, length);
    // This is the number of bytes of padding and MAC removed from the end.
    unsigned bytes_stripped = 0;
    if (priv->read_cipher_spec) {
      unsigned iov_len = handshake_vectors.size() - orig;
      if (n < priv->pending_records_decrypted) {
        bytes_stripped = priv->read_cipher_spec->StripMACAndPadding(&handshake_vectors[orig], &iov_len);
      } else {
        if (!priv->read_cipher_spec->Decrypt(&bytes_stripped, &handshake_vectors[orig], &iov_len, header, priv->read_seq_num))
            return ERROR_RESULT(ERR_BAD_MAC);
        priv->read_seq_num++;
        priv->pending_records_decrypted++;
      }
      handshake_vectors.resize(orig + iov_len);
    }
    Buffer buf(&handshake_vectors[0], handshake_vectors.size());

    const Result r = GetHandshakeMessage(found, htype, out, &buf);
    if (r)
      return r;
    if (*found == false) {
      // If we didn't find a complete handshake message then we consumed the
      // whole record.
      in->Advance(length);
    } else {
      // If we did find a complete handshake message then it might not have
      // taken up the whole record. In this case, we advance the record, less
      // the amount of data left over in the handshake message buffer.
      priv->partial_record_remaining = buf.remaining() + bytes_stripped;
      in->Advance(length - priv->partial_record_remaining);
      // If we have a partial record remaining, then it has been decrypted.
      // Otherwise, we can consumed all the decrypted records.
      priv->pending_records_decrypted = priv->partial_record_remaining > 0;
      return 0;
    }
  }
}

uint16_t TLSVersionToOffer(ConnectionPrivate* priv) {
  if (priv->sslv3)
    return static_cast<uint16_t>(SSLv3);

  return static_cast<uint16_t>(TLSv12);
}

Result MarshalClientHello(Sink* sink, ConnectionPrivate* priv) {
  const uint64_t now = priv->ctx->EpochSeconds();
  if (!now)
    return ERROR_RESULT(ERR_EPOCH_SECONDS_FAILED);

  priv->client_random[0] = now >> 24;
  priv->client_random[1] = now >> 16;
  priv->client_random[2] = now >> 8;
  priv->client_random[3] = now;
  if (!priv->ctx->RandomBytes(priv->client_random + 4, sizeof(priv->client_random) - 4))
    return ERROR_RESULT(ERR_RANDOM_BYTES_FAILED);

  sink->U16(TLSVersionToOffer(priv));
  sink->Append(priv->client_random, sizeof(priv->client_random));

  sink->U8(priv->session_id_len);
  uint8_t* session_id = sink->Block(priv->session_id_len);
  memcpy(session_id, priv->session_id, priv->session_id_len);

  {
    Sink s(sink->VariableLengthBlock(2));

    // For SSLv3 we'll include the SCSV. See RFC 5746.
    if (priv->sslv3)
      sink->U16(kSignalingCipherSuiteValue);

    unsigned written = 0;
    const CipherSuite* suites = AllCipherSuites();
    for (unsigned i = 0; suites[i].flags; i++) {
      if ((suites[i].flags & priv->cipher_suite_flags_enabled) == suites[i].flags) {
        s.U16(suites[i].value);
        written++;
      }
    }

    if (!written)
      return ERROR_RESULT(ERR_NO_POSSIBLE_CIPHERSUITES);
  }

  sink->U8(1);  // number of compression methods
  sink->U8(0);  // no compression.

  if (priv->sslv3) // no extensions in SSLv3
    return 0;

  {
    Sink s(sink->VariableLengthBlock(2));
    const Result r = MarshalClientHelloExtensions(&s, priv);
    if (r)
      return r;
  }

  return 0;
}

Result GenerateMasterSecret(ConnectionPrivate* priv) {
  if (!MasterSecretFromPreMasterSecret(priv->master_secret, priv->version, priv->premaster_secret, sizeof(priv->premaster_secret), priv->client_random, priv->server_random))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  // FIXME: really? Is this true with session tickets?
  priv->resumption_data_ready = true;
  return 0;
}

Result SetupCiperSpec(ConnectionPrivate* priv) {
  KeyBlock kb;
  kb.key_len = priv->cipher_suite->key_len;
  kb.mac_len = priv->cipher_suite->mac_len;
  kb.iv_len = priv->cipher_suite->iv_len;

  if (!KeysFromMasterSecret(&kb, priv->version, priv->master_secret, priv->client_random, priv->server_random))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  if (priv->pending_read_cipher_spec)
    priv->pending_read_cipher_spec->DecRef();
  if (priv->pending_write_cipher_spec)
    priv->pending_write_cipher_spec->DecRef();
  priv->pending_read_cipher_spec = priv->pending_write_cipher_spec = priv->cipher_suite->create(priv->version, kb);
  priv->pending_write_cipher_spec->AddRef();

  return 0;
}

Result MarshalClientKeyExchange(Sink* sink, ConnectionPrivate* priv) {
  if (!priv->cipher_suite || (priv->cipher_suite->flags & CIPHERSUITE_RSA) == 0)
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  const uint16_t offered_version = TLSVersionToOffer(priv);
  priv->premaster_secret[0] = offered_version >> 8;
  priv->premaster_secret[1] = offered_version;
  const bool is_sslv3 = priv->version == SSLv3;

  if (!priv->ctx->RandomBytes(&priv->premaster_secret[2], sizeof(priv->premaster_secret) - 2))
    return ERROR_RESULT(ERR_RANDOM_BYTES_FAILED);

  const size_t encrypted_premaster_size = priv->server_cert->SizeEncryptPKCS1();
  if (!encrypted_premaster_size)
    return ERROR_RESULT(ERR_SIZE_ENCRYPT_PKCS1_FAILED);

  // SSLv3 doesn't prefix the encrypted premaster secret with length bytes.
  Sink s(sink->VariableLengthBlock(is_sslv3 ? 0 : 2));
  uint8_t* encrypted_premaster_secret = s.Block(encrypted_premaster_size);
  if (!priv->server_cert->EncryptPKCS1(encrypted_premaster_secret, priv->premaster_secret, sizeof(priv->premaster_secret)))
    return ERROR_RESULT(ERR_ENCRYPT_PKCS1_FAILED);

  return 0;
}

Result MarshalFinished(Sink* sink, ConnectionPrivate* priv) {
  unsigned verify_data_size;
  const uint8_t* const verify_data = priv->handshake_hash->ClientVerifyData(&verify_data_size, priv->master_secret, sizeof(priv->master_secret));
  uint8_t* b = sink->Block(verify_data_size);
  memcpy(b, verify_data, verify_data_size);

  return 0;
}

static const HandshakeMessage kPermittedHandshakeMessagesPerState[][2] = {
  /* AWAIT_HELLO_REQUEST */ { HELLO_REQUEST, INVALID_MESSAGE },
  /* SEND_CLIENT_HELLO */ { INVALID_MESSAGE },
  /* RECV_SERVER_HELLO */ { SERVER_HELLO, INVALID_MESSAGE },
  /* RECV_CERTIFICATE */ { CERTIFICATE, INVALID_MESSAGE },
  /* RECV_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* SEND_CLIENT_KEY_EXCHANGE */ { INVALID_MESSAGE },
  /* SEND_CHANGE_CIPHER_SPEC */ { INVALID_MESSAGE },
  /* SEND_FINISHED */ { INVALID_MESSAGE },
  /* RECV_SESSION_TICKET */ { SESSION_TICKET, INVALID_MESSAGE },
  /* RECV_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_FINISHED */ { FINISHED, INVALID_MESSAGE },

  /* RECV_RESUME_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* RECV_RESUME_SESSION_TICKET */ { SESSION_TICKET, INVALID_MESSAGE },
  /* RECV_RESUME_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_RESUME_FINISHED */ { FINISHED, INVALID_MESSAGE },
  /* SEND_RESUME_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* SEND_RESUME_FINISHED */ { FINISHED, INVALID_MESSAGE },

  /* SEND_SNAP_START_CLIENT_KEY_EXCHANGE */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_CHANGE_CIPHER_SPEC */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_FINISHED */ { INVALID_MESSAGE },
  /* RECV_SNAP_START_SERVER_HELLO */ { SERVER_HELLO, INVALID_MESSAGE },
  /* RECV_SNAP_START_CERTIFICATE */ { CERTIFICATE, INVALID_MESSAGE },
  /* RECV_SNAP_START_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* RECV_SNAP_START_SESSION_TICKET */ { SESSION_TICKET, INVALID_MESSAGE },
  /* RECV_SNAP_START_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_SNAP_START_FINISHED */ { FINISHED, INVALID_MESSAGE },

  /* RECV_SNAP_START_RECOVERY_CERTIFICATE */ { CERTIFICATE, INVALID_MESSAGE },
  /* RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RECOVERY_FINISHED */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RECOVERY_RETRANSMIT */ { INVALID_MESSAGE },
  /* RECV_SNAP_START_RECOVERY_SESSION_TICKET */ { SESSION_TICKET, INVALID_MESSAGE },
  /* RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_SNAP_START_RECOVERY_FINISHED */ { FINISHED, INVALID_MESSAGE },

  /* SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_FINISHED */ { INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_SERVER_HELLO */ { SERVER_HELLO, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_FINISHED */ { FINISHED, INVALID_MESSAGE },

  /* RECV_SNAP_START_RESUME_RECOVERY_SESSION_TICKET */ { SESSION_TICKET, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_RECOVERY_FINISHED */ { FINISHED, INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY_FINISHED */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT */ { INVALID_MESSAGE },

  /* RECV_SNAP_START_RESUME_RECOVERY2_CERTIFICATE */ { CERTIFICATE, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_RECOVERY2_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY2_FINISHED */ { INVALID_MESSAGE },
  /* SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT */ { INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET */ { SESSION_TICKET, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_SNAP_START_RESUME_RECOVERY2_FINISHED */ { FINISHED, INVALID_MESSAGE },
};

extern const HandshakeState kNextState[] = {
  /* AWAIT_HELLO_REQUEST */ STATE_MUST_BRANCH,  // FIXME: not yet implemented.
  /* SEND_CLIENT_HELLO */ STATE_MUST_BRANCH,
  /* RECV_SERVER_HELLO */ STATE_MUST_BRANCH,
  /* RECV_CERTIFICATE */ RECV_SERVER_HELLO_DONE,
  /* RECV_SERVER_HELLO_DONE */ SEND_CLIENT_KEY_EXCHANGE,
  /* SEND_CLIENT_KEY_EXCHANGE */ SEND_CHANGE_CIPHER_SPEC,
  /* SEND_CHANGE_CIPHER_SPEC */ SEND_FINISHED,
  /* SEND_FINISHED */ STATE_MUST_BRANCH,
  /* RECV_SESSION_TICKET */ RECV_CHANGE_CIPHER_SPEC,
  /* RECV_CHANGE_CIPHER_SPEC */ RECV_FINISHED,
  /* RECV_FINISHED */ AWAIT_HELLO_REQUEST,

  /* RECV_RESUME_SERVER_HELLO_DONE */ STATE_MUST_BRANCH,
  /* RECV_RESUME_SESSION_TICKET */ RECV_RESUME_CHANGE_CIPHER_SPEC,
  /* RECV_RESUME_CHANGE_CIPHER_SPEC */ RECV_RESUME_FINISHED,
  /* RECV_RESUME_FINISHED */ SEND_RESUME_CHANGE_CIPHER_SPEC,
  /* SEND_RESUME_CHANGE_CIPHER_SPEC */ SEND_RESUME_FINISHED,
  /* SEND_RESUME_FINISHED */ AWAIT_HELLO_REQUEST,

  /* SEND_SNAP_START_CLIENT_KEY_EXCHANGE */ SEND_SNAP_START_CHANGE_CIPHER_SPEC,
  /* SEND_SNAP_START_CHANGE_CIPHER_SPEC */ SEND_SNAP_START_FINISHED,
  /* SEND_SNAP_START_FINISHED */ RECV_SNAP_START_SERVER_HELLO,
  /* RECV_SNAP_START_SERVER_HELLO */ STATE_MUST_BRANCH,
  /* RECV_SNAP_START_CERTIFICATE */ RECV_SNAP_START_SERVER_HELLO_DONE,
  /* RECV_SNAP_START_SERVER_HELLO_DONE */ RECV_SNAP_START_SESSION_TICKET,
  /* RECV_SNAP_START_SESSION_TICKET */ RECV_SNAP_START_CHANGE_CIPHER_SPEC,
  /* RECV_SNAP_START_CHANGE_CIPHER_SPEC */ RECV_SNAP_START_FINISHED,
  /* RECV_SNAP_START_FINISHED */ AWAIT_HELLO_REQUEST,

  /* RECV_SNAP_START_RECOVERY_CERTIFICATE */ RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE,
  /* RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE */ SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT,
  /* SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT */ SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC,
  /* SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC */ SEND_SNAP_START_RECOVERY_FINISHED,
  /* SEND_SNAP_START_RECOVERY_FINISHED */ SEND_SNAP_START_RECOVERY_RETRANSMIT,
  /* SEND_SNAP_START_RECOVERY_RETRANSMIT */ STATE_MUST_BRANCH,
  /* RECV_SNAP_START_RECOVERY_SESSION_TICKET */ RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC,
  /* RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC */ RECV_SNAP_START_RECOVERY_FINISHED,
  /* RECV_SNAP_START_RECOVERY_FINISHED */ AWAIT_HELLO_REQUEST,

  /* SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC */ SEND_SNAP_START_RESUME_FINISHED,
  /* SEND_SNAP_START_RESUME_FINISHED */ RECV_SNAP_START_RESUME_SERVER_HELLO,
  /* RECV_SNAP_START_RESUME_SERVER_HELLO */ STATE_MUST_BRANCH,
  /* RECV_SNAP_START_RESUME_SERVER_HELLO_DONE */ RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC,
  /* RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC */ RECV_SNAP_START_RESUME_FINISHED,
  /* RECV_SNAP_START_RESUME_FINISHED */ AWAIT_HELLO_REQUEST,

  /* RECV_SNAP_START_RESUME_RECOVERY_SESSION_TICKET */ RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC,
  /* RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC */ RECV_SNAP_START_RESUME_RECOVERY_FINISHED,
  /* RECV_SNAP_START_RESUME_RECOVERY_FINISHED */ SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT,
  /* SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT */ SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC,
  /* SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC */ SEND_SNAP_START_RESUME_RECOVERY_FINISHED,
  /* SEND_SNAP_START_RESUME_RECOVERY_FINISHED */ SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT,
  /* SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT */ AWAIT_HELLO_REQUEST,

  /* RECV_SNAP_START_RESUME_RECOVERY2_CERTIFICATE */ RECV_SNAP_START_RESUME_RECOVERY2_SERVER_HELLO_DONE,
  /* RECV_SNAP_START_RESUME_RECOVERY2_SERVER_HELLO_DONE */ SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT,
  /* SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT */ SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE,
  /* SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE */ SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC,
  /* SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC */ SEND_SNAP_START_RESUME_RECOVERY2_FINISHED,
  /* SEND_SNAP_START_RESUME_RECOVERY2_FINISHED */ SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT,
  /* SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT */ STATE_MUST_BRANCH,
  /* RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET */ RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC,
  /* RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC */ RECV_SNAP_START_RESUME_RECOVERY2_FINISHED,
  /* RECV_SNAP_START_RESUME_RECOVERY2_FINISHED */ AWAIT_HELLO_REQUEST,
};

const char *kStateNames[] = {
  "AWAIT_HELLO_REQUEST",
  "SEND_CLIENT_HELLO",
  "RECV_SERVER_HELLO",
  "RECV_CERTIFICATE",
  "RECV_SERVER_HELLO_DONE",
  "SEND_CLIENT_KEY_EXCHANGE",
  "SEND_CHANGE_CIPHER_SPEC",
  "SEND_FINISHED",
  "RECV_SESSION_TICKET",
  "RECV_CHANGE_CIPHER_SPEC",
  "RECV_FINISHED",

  "RECV_RESUME_SERVER_HELLO_DONE",
  "RECV_RESUME_SESSION_TICKET",
  "RECV_RESUME_CHANGE_CIPHER_SPEC",
  "RECV_RESUME_FINISHED",
  "SEND_RESUME_CHANGE_CIPHER_SPEC",
  "SEND_RESUME_FINISHED",

  "SEND_SNAP_START_CLIENT_KEY_EXCHANGE",
  "SEND_SNAP_START_CHANGE_CIPHER_SPEC",
  "SEND_SNAP_START_FINISHED",
  "RECV_SNAP_START_SERVER_HELLO",
  "RECV_SNAP_START_CERTIFICATE",
  "RECV_SNAP_START_SERVER_HELLO_DONE",
  "RECV_SNAP_START_SESSION_TICKET",
  "RECV_SNAP_START_CHANGE_CIPHER_SPEC",
  "RECV_SNAP_START_FINISHED",

  "RECV_SNAP_START_RECOVERY_CERTIFICATE",
  "RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE",
  "SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT",
  "SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC",
  "SEND_SNAP_START_RECOVERY_FINISHED",
  "SEND_SNAP_START_RECOVERY_RETRANSMIT",
  "RECV_SNAP_START_RECOVERY_SESSION_TICKET",
  "RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC",
  "RECV_SNAP_START_RECOVERY_FINISHED",

  "SEND_SNAP_START_RESUME_CHANGE_CIPHER_SPEC",
  "SEND_SNAP_START_RESUME_FINISHED",
  "RECV_SNAP_START_RESUME_SERVER_HELLO",
  "RECV_SNAP_START_RESUME_SERVER_HELLO_DONE",
  "RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC",
  "RECV_SNAP_START_RESUME_FINISHED",

  "RECV_SNAP_START_RESUME_RECOVERY_SESSION_TICKET",
  "RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC",
  "RECV_SNAP_START_RESUME_RECOVERY_FINISHED",
  "SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT",
  "SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC",
  "SEND_SNAP_START_RESUME_RECOVERY_FINISHED",
  "SEND_SNAP_START_RESUME_RECOVERY_RETRANSMIT",

  "RECV_SNAP_START_RESUME_RECOVERY2_CERTIFICATE",
  "RECV_SNAP_START_RESUME_RECOVERY2_SERVER_HELLO_DONE",
  "SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC_REVERT",
  "SEND_SNAP_START_RESUME_RECOVERY2_CLIENT_KEY_EXCHANGE",
  "SEND_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC",
  "SEND_SNAP_START_RESUME_RECOVERY2_FINISHED",
  "SEND_SNAP_START_RESUME_RECOVERY2_RETRANSMIT",
  "RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET",
  "RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC",
  "RECV_SNAP_START_RESUME_RECOVERY2_FINISHED",
};

static void AddHandshakeMessageToVerifyHash(HandshakeHash* handshake_hash, HandshakeMessage type, Buffer* in) {
  uint8_t header[4];
  header[0] = static_cast<uint8_t>(type);
  header[1] = in->size() >> 16;
  header[2] = in->size() >> 8;
  header[3] = in->size();
  handshake_hash->Update(header, sizeof(header));
  for (unsigned i = 0; i < in->iovec_len(); i++) {
    const struct iovec& iov = in->iovec()[i];
    handshake_hash->Update(iov.iov_base, iov.iov_len);
  }
}

Result ProcessHandshakeMessage(ConnectionPrivate* priv, HandshakeMessage type, Buffer* in) {
  bool ok = false;
  Result r;

  for (size_t i = 0; i < arraysize(kPermittedHandshakeMessagesPerState[0]); i++) {
    const HandshakeMessage permitted = kPermittedHandshakeMessagesPerState[priv->state][i];
    if (permitted == INVALID_MESSAGE)
      break;
    if (permitted == type) {
      ok = true;
      break;
    }
  }

  if (!ok)
    return ERROR_RESULT(ERR_UNEXPECTED_HANDSHAKE_MESSAGE);

  if (priv->handshake_hash &&
      type != FINISHED &&
      type != SERVER_HELLO &&
      type != CHANGE_CIPHER_SPEC &&
      priv->state != RECV_SNAP_START_SERVER_HELLO &&
      priv->state != RECV_SNAP_START_CERTIFICATE &&
      priv->state != RECV_SNAP_START_SERVER_HELLO_DONE) {
    AddHandshakeMessageToVerifyHash(priv->handshake_hash, type, in);
  }

  const HandshakeState prev_state = priv->state;

  switch (type) {
    case SERVER_HELLO:
      r = ProcessServerHello(priv, in);
      break;
    case CERTIFICATE:
      r = ProcessServerCertificate(priv, in);
      break;
    case SERVER_HELLO_DONE:
      r = ProcessServerHelloDone(priv, in);
      break;
    case CHANGE_CIPHER_SPEC:
      uint8_t b;
      if (!in->Read(&b, 1) || b != 1 || in->remaining() != 0)
        return ERROR_RESULT(ERR_UNEXPECTED_HANDSHAKE_MESSAGE);
      if (priv->read_cipher_spec)
        priv->read_cipher_spec->DecRef();
      priv->read_cipher_spec = priv->pending_read_cipher_spec;
      priv->pending_read_cipher_spec = NULL;
      priv->read_seq_num = 0;
      r = 0;
      break;
    case FINISHED:
      r = ProcessServerFinished(priv, in);
      break;
    case SESSION_TICKET:
      r = ProcessSessionTicket(priv, in);
      break;
    default:
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  if (r)
    return r;

  if (priv->state == prev_state) {
    priv->state = kNextState[prev_state];
    if (priv->state == STATE_MUST_BRANCH)
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  printf("%s -> %s\n", kStateNames[prev_state], kStateNames[priv->state]);

  return 0;
}

Result ProcessServerHello(ConnectionPrivate* priv, Buffer* in) {
  bool ok;

  const Buffer::Pos start_of_server_hello = in->Tell();

  uint16_t server_wire_version;
  if (!in->U16(&server_wire_version))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
  if (!IsValidVersion(server_wire_version))
    return ERROR_RESULT(ERR_UNSUPPORTED_SERVER_VERSION);
  const TLSVersion version = static_cast<TLSVersion>(server_wire_version);
  if (priv->version_established && priv->version != version)
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  uint8_t server_random[sizeof(priv->server_random)];
  if (!in->Read(server_random, sizeof(server_random)))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  if (priv->state == RECV_SNAP_START_SERVER_HELLO ||
      priv->state == RECV_SNAP_START_RESUME_SERVER_HELLO) {
    if (memcmp(priv->server_random, server_random, sizeof(priv->server_random)) == 0) {
      // Snap start accepted.
      priv->recording_application_data = false;
      priv->did_snap_start = true;
      if (priv->state == RECV_SNAP_START_RESUME_SERVER_HELLO) {
        priv->did_resume = true;
        priv->state = RECV_SNAP_START_RESUME_CHANGE_CIPHER_SPEC;
      } else {
        priv->state = RECV_SNAP_START_CERTIFICATE;
      }
      return 0;
    }

    // The server didn't accept our suggested server random which means that
    // we need to perform snap start recovery.
    priv->server_verify.iov_base = NULL;
    priv->server_verify.iov_len = 0;

    if (priv->write_cipher_spec)
      priv->write_cipher_spec->DecRef();
    priv->write_cipher_spec = NULL;
  }
  memcpy(priv->server_random, server_random, sizeof(priv->server_random));

  Buffer session_id_buf(in->VariableLength(&ok, 1));
  if (!ok)
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
  if (session_id_buf.remaining() > sizeof(priv->session_id))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
  uint8_t session_id[sizeof(priv->session_id)];
  bool resumption = false;
  if (priv->session_id_len &&
      session_id_buf.remaining() == priv->session_id_len &&
      session_id_buf.Read(session_id, priv->session_id_len) &&
      memcmp(session_id, priv->session_id, priv->session_id_len) == 0) {
    // Session ids match. We're resuming a session.
    resumption = true;
  } else {
    session_id_buf.Rewind();
    priv->session_id_len = session_id_buf.remaining();
    if (!session_id_buf.Read(priv->session_id, priv->session_id_len))
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  uint16_t cipher_suite;
  if (!in->U16(&cipher_suite))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  if (resumption) {
    // Check that the cipher suite is the same one as from the previous
    // session.
    if (cipher_suite != priv->cipher_suite->value)
      return ERROR_RESULT(ERR_RESUMPTION_CIPHER_SUITE_MISMATCH);
  } else {
    const CipherSuite* suites = AllCipherSuites();
    for (size_t i = 0; suites[i].flags; i++) {
      const CipherSuite* suite = &suites[i];
      if (suite->value == cipher_suite) {
        // Check that the ciphersuite was one that we offered.
        if ((suite->flags & priv->cipher_suite_flags_enabled) == suite->flags)
          priv->cipher_suite = suite;
        break;
      }
    }
  }

  if (!priv->cipher_suite)
    return ERROR_RESULT(ERR_UNSUPPORTED_CIPHER_SUITE);

  uint8_t compression_method;
  if (!in->U8(&compression_method))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  // We don't support compression yet.
  if (compression_method)
    return ERROR_RESULT(ERR_UNSUPPORTED_COMPRESSION_METHOD);

  delete priv->handshake_hash;
  priv->handshake_hash = HandshakeHashForVersion(version);
  if (!priv->handshake_hash)
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  // We didn't know, until now, which TLS version to use. That meant that we
  // didn't know which hash to use for the ClientHello. However, the
  // ClientHello is still hanging around sent_client_hello so we can add it,
  // and this message, now.

  if (priv->sent_client_hello.iov_base)
    priv->handshake_hash->Update(priv->sent_client_hello.iov_base, priv->sent_client_hello.iov_len);
  AddHandshakeMessageToVerifyHash(priv->handshake_hash, SERVER_HELLO, in);

  if (resumption) {
    Result r = SetupCiperSpec(priv);
    if (r)
      return r;
    // We don't know if we're going to get a session ticket until we have
    // processes the extensions so we set the next state below.
    priv->did_resume = true;
    priv->resumption_data_ready = true;
  } else if (priv->state == RECV_SERVER_HELLO) {
    priv->state = RECV_CERTIFICATE;
  } else if (priv->state == RECV_SNAP_START_SERVER_HELLO) {
    priv->state = RECV_SNAP_START_RECOVERY_CERTIFICATE;
  } else if (priv->state == RECV_SNAP_START_RESUME_SERVER_HELLO) {
    priv->state = RECV_SNAP_START_RESUME_RECOVERY2_CERTIFICATE;
  } else {
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  if (in->remaining() == 0)
    return 0;

  Buffer extensions(in->VariableLength(&ok, 2));
  if (!ok)
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  Result r = ProcessServerHelloExtensions(&extensions, priv);
  if (r)
    return r;

  if (in->remaining())
    return ERROR_RESULT(ERR_HANDSHAKE_TRAILING_DATA);

  if (priv->server_supports_snap_start && priv->collect_snap_start) {
    const Buffer::Pos end = in->Tell();
    in->Seek(start_of_server_hello);
    const size_t server_hello_len = in->remaining();
    uint8_t* server_hello = static_cast<uint8_t*>(priv->arena.Allocate(server_hello_len));
    if (!in->Read(server_hello, server_hello_len))
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    priv->snap_start_server_hello.iov_base = server_hello;
    priv->snap_start_server_hello.iov_len = server_hello_len;
    in->Seek(end);
  }

  if (resumption) {
    if (priv->state == RECV_SERVER_HELLO) {
      if (priv->expecting_session_ticket) {
        priv->state = RECV_RESUME_SESSION_TICKET;
      } else {
        priv->state = RECV_RESUME_CHANGE_CIPHER_SPEC;
      }
    } else if (priv->state == RECV_SNAP_START_RESUME_SERVER_HELLO) {
      if (priv->expecting_session_ticket) {
        priv->state = RECV_SNAP_START_RESUME_RECOVERY_SESSION_TICKET;
      } else {
        priv->state = RECV_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC;
      }
    } else {
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    }
  }

  return 0;
}

Result ProcessServerCertificate(ConnectionPrivate* priv, Buffer* in) {
  bool ok;

  if (priv->state == RECV_SNAP_START_CERTIFICATE)
    return 0;

  Buffer certificates(in->VariableLength(&ok, 3));
  if (!ok)
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  while (certificates.remaining()) {
    Buffer certificate(certificates.VariableLength(&ok, 3));
    if (!ok)
      return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
    const size_t size = certificate.size();
    if (!size)
      return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
    void* certbytes = priv->arena.Allocate(size);
    if (!certificate.Read(certbytes, size))
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    struct iovec iov = {certbytes, size};
    priv->server_certificates.push_back(iov);
  }

  if (!priv->server_certificates.size())
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  if (in->remaining())
    return ERROR_RESULT(ERR_HANDSHAKE_TRAILING_DATA);

  priv->server_cert = priv->ctx->ParseCertificate(static_cast<uint8_t*>(priv->server_certificates[0].iov_base), priv->server_certificates[0].iov_len);
  if (!priv->server_cert)
    return ERROR_RESULT(ERR_CANNOT_PARSE_CERTIFICATE);

  return 0;
}

Result ProcessServerHelloDone(ConnectionPrivate* priv, Buffer* in) {
  if (in->remaining())
    return ERROR_RESULT(ERR_HANDSHAKE_TRAILING_DATA);

  if (priv->server_supports_snap_start && priv->collect_snap_start)
    priv->snap_start_data_available = true;

  if (priv->state == RECV_SNAP_START_RECOVERY_SERVER_HELLO_DONE) {
    // We restarted the handshake calculation because we entered recovery. The
    // server still processed the ClientKeyExchange message that we sent,
    // however, so we need to add it to the handshake hash.
    priv->handshake_hash->Update(priv->sent_client_key_exchange.iov_base, priv->sent_client_key_exchange.iov_len);
  }

#if 0
  if (priv->state == RECV_SNAP_START_SERVER_HELLO_DONE) {
    if (priv->expecting_session_ticket) {
      priv->state = RECV_SNAP_START_SESSION_TICKET;
    } else {
      priv->state = RECV_SNAP_START_CHANGE_CIPHER_SPEC;
    }
  } else if (priv->snap_start_recovery) {
    priv->state = SEND_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC_REVERT;
  } else {
    priv->state = SEND_CLIENT_KEY_EXCHANGE;
  }
#endif

  return 0;
}

Result ProcessServerFinished(ConnectionPrivate* priv, Buffer* in) {
  unsigned server_verify_len;
  const uint8_t* server_verify;

  if (priv->server_verify.iov_base) {
    server_verify = static_cast<uint8_t*>(priv->server_verify.iov_base);
    server_verify_len = priv->server_verify.iov_len;
  } else {
    server_verify = priv->handshake_hash->ServerVerifyData(&server_verify_len, priv->master_secret, sizeof(priv->master_secret));
  }

  uint8_t verify_data[36];

  if (in->remaining() != server_verify_len)
    return ERROR_RESULT(ERR_BAD_VERIFY);
  if (server_verify_len > sizeof(verify_data))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  if (!in->Read(verify_data, server_verify_len))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  if (!CompareBytes(server_verify, verify_data, server_verify_len))
    return ERROR_RESULT(ERR_BAD_VERIFY);

  priv->application_data_allowed = true;
  priv->can_send_application_data = true;

  if (priv->state == RECV_FINISHED ||
      priv->state == RECV_SNAP_START_RESUME_FINISHED ||
      priv->state == RECV_SNAP_START_RECOVERY_FINISHED ||
      priv->state == RECV_SNAP_START_RESUME_RECOVERY2_FINISHED) {
    priv->state = AWAIT_HELLO_REQUEST;
  } else if (priv->state == RECV_RESUME_FINISHED) {
    AddHandshakeMessageToVerifyHash(priv->handshake_hash, FINISHED, in);
    priv->state = SEND_RESUME_CHANGE_CIPHER_SPEC;
  } else if (priv->state == RECV_SNAP_START_RESUME_RECOVERY_FINISHED) {
    AddHandshakeMessageToVerifyHash(priv->handshake_hash, FINISHED, in);
    priv->state = SEND_SNAP_START_RESUME_RECOVERY_CHANGE_CIPHER_SPEC_REVERT;
  } else {
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  return 0;
}

Result ProcessSessionTicket(ConnectionPrivate* priv, Buffer* in) {
  uint32_t lifetime_hint;
  if (!in->U32(&lifetime_hint))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  // We ignore the lifetime hint for now. OpenSSL sets it to zero anyway.
  bool ok;
  Buffer ticket(in->VariableLength(&ok, 2));
  const size_t len = ticket.remaining();
  if (!ok || !len)
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  priv->session_ticket.iov_len = len;
  priv->session_ticket.iov_base = priv->arena.Allocate(len);
  if (!ticket.Read(priv->session_ticket.iov_base, len))
    return ERROR_RESULT(ERR_INTERNAL_ERROR);

  priv->resumption_data_ready = true;

  if (priv->state == RECV_SESSION_TICKET) {
    priv->state = RECV_CHANGE_CIPHER_SPEC;
  } else if (priv->state == RECV_RESUME_SESSION_TICKET) {
    priv->state = RECV_RESUME_CHANGE_CIPHER_SPEC;
  } else if (priv->state == RECV_SNAP_START_SESSION_TICKET) {
    priv->state = RECV_CHANGE_CIPHER_SPEC;
  } else if (priv->state == RECV_SNAP_START_RECOVERY_SESSION_TICKET) {
    priv->state = RECV_SNAP_START_RECOVERY_CHANGE_CIPHER_SPEC;
  } else if (priv->state == RECV_SNAP_START_RESUME_RECOVERY2_SESSION_TICKET) {
    priv->state = RECV_SNAP_START_RESUME_RECOVERY2_CHANGE_CIPHER_SPEC;
  } else {
    return ERROR_RESULT(ERR_INTERNAL_ERROR);
  }

  return 0;
}

}  // namespace tlsclient
