// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/extension.h"

#include "tlsclient/public/context.h"
#include "tlsclient/src/base-internal.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"
#include "tlsclient/src/crypto/fnv1a64/fnv1a64.h"
#include "tlsclient/src/crypto/prf/prf.h"

#if 0
static void hexdump(const void*a, size_t l) {
  const uint8_t* in = (uint8_t*)a;
  for (size_t i = 0; i < l; i++) {
    printf("%x", in[i] >> 4);
    printf("%x", in[i] & 15);
  }
  printf("\n");
}
#endif

namespace tlsclient {

class RenegotiationInfo : public Extension {
 public:
  uint16_t value() const {
    return 65281;
  }

  bool ShouldBeIncluded(ConnectionPrivate* priv) const {
    return true;
  }

  Result Marshal(Sink* sink, ConnectionPrivate* priv) const {
    // No support for renegotiation yet.
    sink->U8(0);
    return 0;
  }

  Result Process(Buffer* extension, ConnectionPrivate* priv) const {
    priv->server_supports_renegotiation_info = true;
    return 0;
  }
};

// ServerNameIndication implements RFC 3546, section 3.1.
class ServerNameIndication : public Extension {
 public:
  enum {
    SNI_NAME_TYPE_HOST_NAME = 0,
    MAX_HOST_NAME = 65535,
  };

  uint16_t value() const {
    return 0;
  }

  bool ShouldBeIncluded(ConnectionPrivate* priv) const {
    const size_t size = priv->host_name.size();
    return size > 0 && size <= MAX_HOST_NAME;
  }

  Result Marshal(Sink* sink, ConnectionPrivate* priv) const {
    Sink server_name_list(sink->VariableLengthBlock(2));
    server_name_list.U8(SNI_NAME_TYPE_HOST_NAME);
    Sink host_name(server_name_list.VariableLengthBlock(2));
    uint8_t* name = host_name.Block(priv->host_name.size());
    memcpy(name, priv->host_name.data(), priv->host_name.size());
    return 0;
  }

  Result Process(Buffer* extension, ConnectionPrivate* priv) const {
    // The server is free to echo an empty extension back to us.
    return 0;
  }
};

class SessionTicket : public Extension {
 public:
  enum {
    EXTENSION_VALUE = 35,
  };

  uint16_t value() const {
    return EXTENSION_VALUE;
  }

  bool ShouldBeIncluded(ConnectionPrivate* priv) const {
    return priv->session_tickets;
  }

  Result Marshal(Sink* sink, ConnectionPrivate* priv) const {
    if (!priv->have_session_ticket_to_present)
      return 0;

    uint8_t* ticket = sink->Block(priv->session_ticket.iov_len);
    memcpy(ticket, priv->session_ticket.iov_base, priv->session_ticket.iov_len);
    return 0;
  }

  Result Process(Buffer* extension, ConnectionPrivate* priv) const {
    if (extension->remaining())
      return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

    priv->expecting_session_ticket = true;
    // If we presented a session ticket then the server may both ack the ticket
    // *and* echo an empty extension. This means that it's going to send us a
    // new ticket.
    priv->resumption_data_ready = false;
    // If we offer session ticket support then GnuTLS will both echo the empty
    // extension and include a session id. We need to ignore the session id
    // otherwise the rest of the resumption code will assume that we're doing
    // session id based resumption in the future.
    priv->session_id_len = 0;
    return 0;
  }
};

class SnapStart : public Extension {
 public:
  uint16_t value() const {
    return 13174;
  }

  bool ShouldBeIncluded(ConnectionPrivate* priv) const {
    return true;
  }

  Result Marshal(Sink* sink, ConnectionPrivate* priv) const {
    if (!priv->snap_start_attempt)
      return 0;

    // The first four bytes of the suggested server random are the same as the
    // first four of our random.
    memcpy(priv->server_random, priv->client_random, 4);
    // The next four bytes are the server's epoch, which we currently take to
    // be zero.
    memset(priv->server_random + 4, 0, 8);
    // And the remainder is random.
    if (!priv->ctx->RandomBytes(priv->server_random + 12, sizeof(priv->server_random) - 12))
      return ERROR_RESULT(ERR_RANDOM_BYTES_FAILED);

    // The first four bytes of the server random are the same as the client
    // random and we don't bother sending them.
    uint8_t* server_random = sink->Block(sizeof(priv->server_random) - 4);
    memcpy(server_random, priv->server_random + 4, sizeof(priv->server_random) - 4);

    Sink predicted_response(&priv->arena);

    {
      const uint8_t* predicted = static_cast<uint8_t*>(priv->predicted_server_hello.iov_base);
      const size_t len = priv->predicted_server_hello.iov_len;

      // A ServerHello is 8 bytes + session id data + extensions.
      if (len < 38)
        return ERROR_RESULT(ERR_INTERNAL_ERROR);

      Sink server_hello_sink(predicted_response.HandshakeMessage(SERVER_HELLO));
      server_hello_sink.Copy(predicted, 2);
      server_hello_sink.Copy(priv->server_random, sizeof(priv->server_random));
      // We need to make sure that the server doesn't include a random session id
      // in its ServerHello because we can't predict that. We do that by using the
      // session tickets extension. If we are attempting a session tickets
      // resumption, then the server will echo our 1 byte session id: {0x00}.
      // Otherwise, the session id will be empty. Either way, we need to omit
      // the session id in |predicted|.
      if (priv->have_session_ticket_to_present) {
        server_hello_sink.U8(1);
        server_hello_sink.U8(0);
        // We assume that the server doesn't renew the session ticket.
        priv->expecting_session_ticket = false;
      } else {
        server_hello_sink.U8(0);
        priv->expecting_session_ticket = true;
      }

      const unsigned session_id_len = predicted[34];
      if (len < 38u + session_id_len)
        return ERROR_RESULT(ERR_INTERNAL_ERROR);

      // After the session id data are 3 bytes: CipherSuite (2) and
      // CompressionMethod (1)
      server_hello_sink.Copy(predicted + 35 + session_id_len, 3);

      struct iovec trailing_iov = {const_cast<uint8_t*>(predicted + 38 + session_id_len), len - 38 - session_id_len};
      if (trailing_iov.iov_len) {
        // The ServerHello has extensions. We need to parse them we remove the
        // empty session tickets extension.
        Sink extensions_sink(server_hello_sink.VariableLengthBlock(2));
        Buffer trailing(&trailing_iov, 1);
        bool ok;
        Buffer extensions(trailing.VariableLength(&ok, 2));
        if (!ok)
          return ERROR_RESULT(ERR_INTERNAL_ERROR);
        while (extensions.remaining()) {
          uint16_t extension_type;
          if (!extensions.U16(&extension_type))
            return ERROR_RESULT(ERR_INTERNAL_ERROR);
          Buffer extension(extensions.VariableLength(&ok, 2));
          if (!ok)
            return ERROR_RESULT(ERR_INTERNAL_ERROR);

          if (priv->have_session_ticket_to_present &&
              extension_type == SessionTicket::EXTENSION_VALUE) {
            continue;
          }
          extensions_sink.U16(extension_type);
          extensions_sink.U16(extension.remaining());
          uint8_t* d = extensions_sink.Block(extension.remaining());
          if (!extension.Read(d, extension.remaining()))
            return ERROR_RESULT(ERR_INTERNAL_ERROR);
        }
      }
    }

    if (!priv->predicted_certificates.size())
      return ERROR_RESULT(ERR_INTERNAL_ERROR);
    priv->server_cert = priv->ctx->ParseCertificate(static_cast<uint8_t*>(priv->predicted_certificates[0].iov_base), priv->predicted_certificates[0].iov_len);

    if (!priv->have_session_ticket_to_present) {
      Sink cert_msg_sink(predicted_response.HandshakeMessage(CERTIFICATE));
      Sink certs_sink(cert_msg_sink.VariableLengthBlock(3));

      for (std::vector<struct iovec>::const_iterator i = priv->predicted_certificates.begin(); i != priv->predicted_certificates.end(); i++) {
        Sink cert_sink(certs_sink.VariableLengthBlock(3));
        const uint8_t* cert = static_cast<uint8_t*>(i->iov_base);
        cert_sink.Copy(cert, i->iov_len);
      }
    }

    if (!priv->have_session_ticket_to_present)
      predicted_response.HandshakeMessage(SERVER_HELLO_DONE);

    FNV1a64 fnv;
    priv->predicted_response.iov_base = predicted_response.Release();
    priv->predicted_response.iov_len = predicted_response.size();
    fnv.Update(priv->predicted_response.iov_base, priv->predicted_response.iov_len);
    uint8_t* predicted_hash = sink->Block(FNV1a64::DIGEST_SIZE);
    fnv.Final(predicted_hash);

    return 0;
  }

  Result Process(Buffer* extension, ConnectionPrivate* priv) const {
    priv->server_supports_snap_start = true;
    return 0;
  }
};

static RenegotiationInfo g_renegotiation_info;
static ServerNameIndication g_sni;
static SessionTicket g_session_ticket;
static SnapStart g_snap_start;

static const Extension* kExtensions[] = {
  &g_renegotiation_info,
  &g_sni,
  &g_session_ticket,
  &g_snap_start,
};

static Result MaybeIncludeExtension(const Extension* ext, Sink *sink, ConnectionPrivate* priv) {
  if (!ext->ShouldBeIncluded(priv))
    return 0;

  sink->U16(ext->value());
  Sink s(sink->VariableLengthBlock(2));
  return ext->Marshal(&s, priv);
}

Result MarshalClientHelloExtensions(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  for (size_t i = 0; i < arraysize(kExtensions); i++) {
    r = MaybeIncludeExtension(kExtensions[i], sink, priv);
    if (r)
      return r;
  }

  return 0;
}

Result ProcessServerHelloExtensions(Buffer* extensions, ConnectionPrivate* priv) {
  bool ok;

  while (extensions->remaining()) {
    uint16_t extension_type;
    if (!extensions->U16(&extension_type))
      return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);
    Buffer extension(extensions->VariableLength(&ok, 2));
    if (!ok)
      return ERROR_RESULT(ERR_INVALID_HANDSHAKE_MESSAGE);

    bool found = false;
    for (size_t i = 0; i < arraysize(kExtensions); i++) {
      if (kExtensions[i]->value() == extension_type) {
        Result r = kExtensions[i]->Process(&extension, priv);
        if (r)
          return r;
        found = true;
        break;
      }
    }

    if (!found)
      return ERROR_RESULT(ERR_UNKNOWN_EXTENSION);
  }

  return 0;
}

}  // namespace tlsclient
