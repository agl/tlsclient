// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/handshake.h"

#include <vector>

#include "tlsclient/public/context.h"
#include "tlsclient/public/error.h"
#include "tlsclient/src/base-internal.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/extension.h"
#include "tlsclient/src/sink.h"

namespace tlsclient {

// RFC 5746, section 3.3
static const uint16_t kSignalingCipherSuiteValue = 0xff00;

static const CipherSuite kCipherSuites[] = {
  { CIPHERSUITE_RSA | CIPHERSUITE_RC4 | CIPHERSUITE_SHA,
    0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
};

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
  bool first_record = true;
  std::vector<struct iovec> handshake_vectors;

  for (;;) {
    uint16_t length;

    if (priv->partial_record_remaining) {
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
        in->PeekV(out, length);
        *found = true;
        return 0;
      }

      // Decrypt and verify.
    }

    // Otherwise we append the vectors of the handshake message into
    // |handshake_vectors|
    first_record = false;
    in->PeekV(&handshake_vectors, length);
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
      priv->partial_record_remaining = buf.remaining();
      in->Advance(length - priv->partial_record_remaining);
      return 0;
    }
  }
}

uint16_t TLSVersionToOffer(ConnectionPrivate* priv) {
  if (priv->sslv3)
    return static_cast<uint16_t>(SSLv3);

  return static_cast<uint16_t>(TLSv12);
}

Result MarshallClientHello(Sink* sink, ConnectionPrivate* priv) {
  const uint64_t now = priv->ctx->EpochSeconds();
  if (!now)
    return ERROR_RESULT(ERR_EPOCH_SECONDS_FAILED);

  uint8_t rnd[28];
  if (!priv->ctx->RandomBytes(rnd, sizeof(rnd)))
    return ERROR_RESULT(ERR_RANDOM_BYTES_FAILED);

  sink->U16(TLSVersionToOffer(priv));
  sink->U32(now);
  sink->Append(rnd, sizeof(rnd));

  sink->U8(0);  // no session resumption for the moment.

  {
    Sink s(sink->VariableLengthBlock(2));

    // For SSLv3 we'll include the SCSV. See RFC 5746.
    if (priv->sslv3)
      sink->U16(kSignalingCipherSuiteValue);

    unsigned written = 0;
    for (unsigned i = 0; i < arraysize(kCipherSuites); i++) {
      if ((kCipherSuites[i].flags & priv->cipher_suite_flags_enabled) == kCipherSuites[i].flags) {
        s.U16(kCipherSuites[i].value);
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
    const Result r = MarshallClientHelloExtensions(&s, priv);
    if (r)
      return r;
  }

  return 0;
}

Result MarshallClientKeyExchange(Sink* sink, ConnectionPrivate* priv) {
  assert(priv->cipher_suite);
  assert(priv->cipher_suite->flags & CIPHERSUITE_RSA);

  uint8_t premaster_secret[48];
  const uint16_t offered_version = TLSVersionToOffer(priv);
  premaster_secret[0] = offered_version >> 8;
  premaster_secret[1] = offered_version;
  // const bool is_sslv3 = priv->version == SSLv3;

  if (!priv->ctx->RandomBytes(&premaster_secret[2], sizeof(premaster_secret) - 2))
    return ERROR_RESULT(ERR_RANDOM_BYTES_FAILED);

  // SSLv3 doesn't prefix the encrypted premaster secret with length bytes.
  return 0;
}

static const HandshakeMessage kPermittedHandshakeMessagesPerState[][2] = {
  /* AWAIT_HELLO_REQUEST */ { HELLO_REQUEST, INVALID_MESSAGE },
  /* SEND_PHASE_ONE */ { INVALID_MESSAGE },
  /* RECV_SERVER_HELLO */ { SERVER_HELLO, INVALID_MESSAGE },
  /* RECV_SERVER_CERTIFICATE */ { CERTIFICATE, INVALID_MESSAGE },
  /* RECV_SERVER_HELLO_DONE */ { SERVER_HELLO_DONE, INVALID_MESSAGE },
  /* SEND_PHASE_TWO */ { INVALID_MESSAGE },
  /* RECV_CHANGE_CIPHER_SPEC */ { CHANGE_CIPHER_SPEC, INVALID_MESSAGE },
  /* RECV_FINISHED */ { FINISHED, INVALID_MESSAGE },
};

Result ProcessHandshakeMessage(ConnectionPrivate* priv, HandshakeMessage type, Buffer* in) {
  for (size_t i = 0; i < arraysize(kPermittedHandshakeMessagesPerState[0]); i++) {
    const HandshakeMessage permitted = kPermittedHandshakeMessagesPerState[priv->state][i];
    if (permitted == INVALID_MESSAGE)
      return ERROR_RESULT(ERR_UNEXPECTED_HANDSHAKE_MESSAGE);
    if (permitted == type)
      break;
  }

  switch (type) {
    case SERVER_HELLO:
      return ProcessServerHello(priv, in);
    case CERTIFICATE:
      return ProcessServerCertificate(priv, in);
    case SERVER_HELLO_DONE:
      return ProcessServerHelloDone(priv, in);
    default:
      assert(false);
  }
}

Result ProcessServerHello(ConnectionPrivate* priv, Buffer* in) {
  bool ok;

  uint16_t server_wire_version;
  if (!in->U16(&server_wire_version))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
  if (!IsValidVersion(server_wire_version))
    return ERROR_RESULT(ERR_UNSUPPORTED_SERVER_VERSION);
  if (priv->version_established && priv->version != static_cast<TLSVersion>(server_wire_version))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  if (!in->Read(&priv->server_random, sizeof(priv->server_random)))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  // No session id support yet.
  Buffer session_id(in->VariableLength(&ok, 1));
  if (!ok)
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  uint16_t cipher_suite;
  if (!in->U16(&cipher_suite))
    return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

  for (size_t i = 0; i < arraysize(kCipherSuites); i++) {
    const CipherSuite* suite = &kCipherSuites[i];
    if (suite->value == cipher_suite) {
      // Check that the ciphersuite was one that we offered.
      if ((suite->flags & priv->cipher_suite_flags_enabled) == suite->flags)
        priv->cipher_suite = suite;
      break;
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

  priv->state = RECV_SERVER_CERTIFICATE;

  return 0;
}

Result ProcessServerCertificate(ConnectionPrivate* priv, Buffer* in) {
  bool ok;

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
      assert(false);
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

  priv->state = RECV_SERVER_HELLO_DONE;

  return 0;
}

Result ProcessServerHelloDone(ConnectionPrivate* priv, Buffer* in) {
  if (in->remaining())
    return ERROR_RESULT(ERR_HANDSHAKE_TRAILING_DATA);

  priv->state = SEND_PHASE_TWO;

  return 0;
}

}  // namespace tlsclient
