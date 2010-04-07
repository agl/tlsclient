// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/handshake.h"

#include <vector>

#include "tlsclient/src/base-internal.h"
#include "tlsclient/public/context.h"
#include "tlsclient/public/error.h"
#include "tlsclient/public/buffer.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/sink.h"

namespace tlsclient {

// RFC 5746, section 3.3
static const uint16_t kSignalingCipherSuiteValue = 0xff00;

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

  const uint32_t length = static_cast<uint32_t>(header[1]) |
                          static_cast<uint32_t>(header[2]) |
                          header[3];
  if (length > kMaxHandshakeLength)
    return ERROR_RESULT(ERR_HANDSHAKE_MESSAGE_TOO_LONG);
  if (in->remaining() < length)
    return 0;

  in->ReadV(out, length);
  *found = true;
  return 0;
}

Result GetRecordOrHandshake(bool* found, RecordType* type, HandshakeMessage* htype, std::vector<struct iovec>* out, Buffer* in, ConnectionPrivate* priv) {
  uint8_t header[5];
  *found = false;
  bool first_record = true;
  std::vector<struct iovec> handshake_vectors;

  for (;;) {
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

    const uint16_t length = static_cast<uint16_t>(header[3]) | header[4];
    if (in->remaining() < length)
      return 0;

    if (*type != RECORD_HANDSHAKE) {
      if (!first_record)
        return ERROR_RESULT(ERR_TRUNCATED_HANDSHAKE_MESSAGE);
      // Records other than handshake records are processed one at a time and
      // we can store the vectors directly into |out|.
      in->ReadV(out, length);
      *found = true;
      return 0;
    }

    // Otherwise we append the vectors of the handshake message into |handshake_vectors|
    first_record = false;
    in->ReadV(&handshake_vectors, length);
    Buffer buf(&handshake_vectors[0], handshake_vectors.size());

    const Result r = GetHandshakeMessage(found, htype, out, buf);
    if (*found || r)
      return r;
  }
}

Result MarshallClientHello(Sink* sink, ConnectionPrivate* priv) {
  const uint64_t now = priv->ctx->EpochSeconds();
  if (!now)
    return ERROR_RESULT(ERR_EPOCH_SECONDS_FAILED);

  uint8_t rnd[28];
  if (!priv->ctx->RandomBytes(rnd, sizeof(rnd)))
    return ERROR_RESULT(ERR_RANDOM_BYTES_FAILED);

  if (priv->sslv3) {
    sink->U16(0x0300);
  } else {
    sink->U16(0x0303);
  }

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
      if ((kCipherSuites[i].flags & priv->ciphersuite_flags) == kCipherSuites[i].flags) {
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

}  // namespace tlsclient
