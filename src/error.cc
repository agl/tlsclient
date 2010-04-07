// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/error.h"

#include <stdint.h>

namespace tlsclient {

static const char kErrorStrings[][70] = {
  "Success",
  "Call to EpochSeconds failed",
  "Call to RandomBytes failed",
  "No ciphersuites have been enabled (try Connection::EnableDefault)",
  "Encountered record with invalid type",
  "Encountered record with incorrect version",
  "Encountered record with invalid version",
  "A incomplete handshake message was followed by a non-handshake record",
  "Encountered a handshake message with an unknown type",
  "Encountered a handshake message which was too long to process",
  ""
};

ErrorCode ErrorCodeFromResult(Result r) {
  return static_cast<ErrorCode>(r & 0x3ff);
}

void FilenameFromResult(char out[8], Result r) {
  for (unsigned i = 0; i < 7; i++) {
    uint8_t c = r >> 58;
    if (c == 0) {
      out[i] = 0;
    } else if (c < 32) {
      out[i] = c + 32;
    } else {
      out[i] = c + 64;
    }

    r <<= 6;
  }

  out[7] = 0;
}

unsigned LineNumberFromResult(Result r) {
  return (r >> 10) & 0xfff;
}

const char *StringFromResult(Result r) {
  return StringFromErrorCode(ErrorCodeFromResult(r));
}

const char *StringFromErrorCode(ErrorCode e) {
  if (e >= ERR_MAX)
    return "Unknown error";
  return kErrorStrings[e];
}

Result ErrorResult(const char* filename, unsigned line_no, ErrorCode e) {
  Result r = 0;

  unsigned i;
  for (i = 0; *filename && i < 7; filename++, i++) {
    uint8_t c = *filename;

    if (i)
      r <<= 6;

    if (c < 32) {
      c = 14;  // '.'
    } else if (c < 96) {
      c -= 32;
    } else if (c < 128) {
      c -= 64;
    } else {
      c = 14;  // '.'
    }

    r |= c;
  }

  r <<= 12 + (6 * (7 - i));
  if (line_no >= 4096)
    line_no = 4095;
  r |= line_no;
  r <<= 10;
  r |= e;

  return r;
}

}  // namespace tlsclient
