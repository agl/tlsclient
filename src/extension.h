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

Result ProcessServerHelloExtensions(Buffer* extension, ConnectionPrivate* priv);
Result MarshalClientHelloExtensions(Sink* sink, ConnectionPrivate* priv);

}  // namespace tlsclient

#endif  // TLSCLIENT_EXTENSION_H
