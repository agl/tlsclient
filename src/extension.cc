// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/handshake.h"
#include "tlsclient/src/connection_private.h"
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
};

RenegotiationInfo g_renegotiation_info;

static Result MaybeIncludeExtension(Extension* ext, Sink *sink, ConnectionPrivate* priv) {
  if (!ext->ShouldBeIncluded(priv))
    return 0;

  sink->U16(ext->value());
  Sink s(sink->VariableLengthBlock(2));
  return ext->Marshall(&s, priv);
}

Result MarshallClientHelloExtensions(Sink* sink, ConnectionPrivate* priv) {
  Result r;

  r = MaybeIncludeExtension(&g_renegotiation_info, sink, priv);
  if (r)
    return r;

  return 0;
}

}  // namespace tlsclient
