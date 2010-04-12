// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_TESTS_UTIL_H
#define TLSCLIENT_TESTS_UTIL_H

#include "tlsclient/public/base.h"

namespace tlsclient {

void HexDump(char* out, const uint8_t* data, size_t length);
void FromHex(uint8_t* out, const char* in);

}

#endif  // TLSCLIENT_TESTS_UTIL_H
