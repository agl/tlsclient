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

class SnapStart : public Extension {
 public:
  uint16_t value() const {
    return 13174;
  }

  bool ShouldBeIncluded(ConnectionPrivate* priv) const {
    return true;
  }

  Result Marshal(Sink* sink, ConnectionPrivate* priv) const {
    if (priv->snap_start_attempt) {
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

      // We poke the suggested server random into our predicted response. The
      // server random starts two bytes from the start of the ServerHello and
      // there's four bytes of handshake protocol header.
      memcpy(static_cast<uint8_t*>(priv->predicted_response.iov_base) + 4 + 2, priv->server_random, sizeof(priv->server_random));

      FNV1a64 fnv;
      fnv.Update(priv->predicted_response.iov_base, priv->predicted_response.iov_len);
      uint8_t* predicted_hash = sink->Block(FNV1a64::DIGEST_SIZE);
      fnv.Final(predicted_hash);
    }
    return 0;
  }

  Result Process(Buffer* extension, ConnectionPrivate* priv) const {
    priv->server_supports_snap_start = true;
    return 0;
  }
};

static RenegotiationInfo g_renegotiation_info;
static ServerNameIndication g_sni;
static SnapStart g_snap_start;

static const Extension* kExtensions[] = {
  &g_renegotiation_info,
  &g_sni,
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

#if 0
class FNV1a64HandshakeHash : public HandshakeHash {
 public:
  virtual void Update(const void* data, size_t length) {
    fnv_.Update(data, length);
  }

  virtual const uint8_t* ClientVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    return NULL;
  }

  virtual const uint8_t* ServerVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    return NULL;
  }

 private:
  FNV1a64 fnv_;
}
#endif

}  // namespace tlsclient
