// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_ERROR_H
#define TLSCLIENT_ERROR_H

#include <stdint.h>

namespace tlsclient {

// Error codes are returned as 64-bit unsigned integers. Zero is success.
typedef uint64_t Result;

// The 64-bit bits are assigned like this:
//   Bottom 10 bits: error code
//   12 bits: line number
//   top 42 bits: packed filename
//
// The filename is packed with each character taking 6 bits. For each input
// byte the following mapping applies:
//   0..31 -> 14
//   32..95 -> 0..63
//   96..127 -> 32..63

enum ErrorCode {
  ERR_SUCCESS = 0,
  ERR_EPOCH_SECONDS_FAILED = 1,
  ERR_RANDOM_BYTES_FAILED = 2,
  ERR_NO_POSSIBLE_CIPHERSUITES = 3,
  ERR_INVALID_RECORD_TYPE = 4,
  ERR_BAD_RECORD_VERSION = 5,
  ERR_INVALID_RECORD_VERSION = 6,
  ERR_TRUNCATED_HANDSHAKE_MESSAGE = 7,
  ERR_UNKNOWN_HANDSHAKE_MESSAGE_TYPE = 8,
  ERR_HANDSHAKE_MESSAGE_TOO_LONG = 9,
  ERR_MAX,
};

ErrorCode ErrorCodeFromResult(Result);
void FilenameFromResult(char out[8], Result);
unsigned LineNumberFromResult(Result);
const char *StringFromResult(Result);
const char *StringFromErrorCode(ErrorCode);

}  // namespace tlsclient

#endif  // TLSCLIENT_ERROR_H
