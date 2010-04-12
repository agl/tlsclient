// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/tests/util.h"

namespace tlsclient {

void HexDump(char* out, const uint8_t* data, size_t length) {
  static const char hextable[] = "0123456789abcdef";
  for (size_t i = 0; i < length; i++) {
    out[i*2]     = hextable[data[i] >> 4];
    out[i*2 + 1] = hextable[data[i] & 15];
  }
  out[length*2] = 0;
}

static uint8_t FromHexChar(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  } else if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  } else {
    return 0;
  }
}

void FromHex(uint8_t* out, const char* in) {
  size_t len = strlen(in);
  for (size_t i = 0; i < len/2; i++)
    out[i] = (FromHexChar(in[i*2]) << 4) | FromHexChar(in[i*2 + 1]);
}

}  // namespace tlsclient
