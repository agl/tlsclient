// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/extension.h"

#include "tlsclient/src/base-internal.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/error-internal.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"

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

RenegotiationInfo g_renegotiation_info;
ServerNameIndication g_sni;

static const Extension* kExtensions[] = {
  &g_renegotiation_info,
  &g_sni,
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
