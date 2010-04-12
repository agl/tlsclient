// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_EXTENSION_H
#define TLSCLIENT_EXTENSION_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/error.h"

namespace tlsclient {

struct ConnectionPrivate;
class Buffer;
class Sink;

struct Extension {
 public:
  // Called to see if this extension should be included.
  virtual bool ShouldBeIncluded(ConnectionPrivate* priv) const = 0;
  virtual Result Marshall(Sink* sink, ConnectionPrivate* priv) const = 0;
  virtual Result Process(Buffer* extension, ConnectionPrivate* priv) const = 0;
  // The IANA assigned extension number.
  virtual uint16_t value() const = 0;
};

Result ProcessServerHelloExtensions(Buffer* extension, ConnectionPrivate* priv);
Result MarshallClientHelloExtensions(Sink* sink, ConnectionPrivate* priv);

}  // namespace tlsclient

#endif  // TLSCLIENT_EXTENSION_H
