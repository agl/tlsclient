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

  Result Marshall(Sink* sink, ConnectionPrivate* priv) const {
    // No support for renegotiation yet.
    sink->U8(0);
    return 0;
  }

  Result Process(Buffer* extension, ConnectionPrivate* priv) const {
    priv->server_supports_renegotiation_info = true;
    return 0;
  }
};

RenegotiationInfo g_renegotiation_info;

static const Extension* kExtensions[] = {
  &g_renegotiation_info,
};

static Result MaybeIncludeExtension(const Extension* ext, Sink *sink, ConnectionPrivate* priv) {
  if (!ext->ShouldBeIncluded(priv))
    return 0;

  sink->U16(ext->value());
  Sink s(sink->VariableLengthBlock(2));
  return ext->Marshall(&s, priv);
}

Result MarshallClientHelloExtensions(Sink* sink, ConnectionPrivate* priv) {
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
