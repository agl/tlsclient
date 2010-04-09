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
  ERR_INCORRECT_ALERT_LENGTH = 10,
  ERR_INVALID_ALERT_LEVEL = 11,

  // Alerts
  ERR_ALERT_CLOSE_NOTIFY = 12,
  ERR_ALERT_UNEXPECTED_MESSAGE = 13,
  ERR_ALERT_BAD_RECORD_MAC = 14,
  ERR_ALERT_DECRYPTION_FAILED = 15,
  ERR_ALERT_HANDSHAKE_FAILURE = 16,
  ERR_ALERT_NO_CERTIFICATE = 17,
  ERR_ALERT_BAD_CERTIFICATE = 18,
  ERR_ALERT_UNSUPPORTED_CERTIFICATE = 19,
  ERR_ALERT_CERTIFICATE_REVOKED = 20,
  ERR_ALERT_CERTIFICATE_EXPIRED = 21,
  ERR_ALERT_CERTIFICATE_UNKNOWN = 22,
  ERR_ALERT_ILLEGAL_PARAMETER = 23,
  ERR_ALERT_UNKNOWN_CA = 24,
  ERR_ALERT_ACCESS_DENIED = 25,
  ERR_ALERT_DECODE_ERROR = 26,
  ERR_ALERT_EXPORT_RESTRICTION = 27,
  ERR_ALERT_PROTOCOL_VERSION = 28,
  ERR_ALERT_INSUFFICIENT_SECURITY = 29,
  ERR_ALERT_INTERNAL_ERROR = 30,
  ERR_ALERT_USER_CANCELED = 31,
  ERR_ALERT_NO_RENEGOTIATION = 32,
  ERR_ALERT_UNSUPPORTED_EXTENSION = 33,
  ERR_UNKNOWN_FATAL_ALERT = 34,

  ERR_UNEXPECTED_APPLICATION_DATA = 35,
  ERR_UNEXPECTED_HANDSHAKE_MESSAGE = 36,
  ERR_INVALID_HANDSHAKE_MESSAGE = 37,
  ERR_UNSUPPORTED_SERVER_VERSION = 38,
  ERR_UNSUPPORTED_CIPHER_SUITE = 39,
  ERR_UNSUPPORTED_COMPRESSION_METHOD = 40,
  ERR_UNKNOWN_EXTENSION = 41,
  ERR_HANDSHAKE_TRAILING_DATA = 42,
  ERR_CANNOT_PARSE_CERTIFICATE = 43,

  // Remember to add the string to the array in src/error.cc!

  ERR_MAX,
};

ErrorCode ErrorCodeFromResult(Result);
void FilenameFromResult(char out[8], Result);
unsigned LineNumberFromResult(Result);
const char *StringFromResult(Result);
const char *StringFromErrorCode(ErrorCode);

}  // namespace tlsclient

#endif  // TLSCLIENT_ERROR_H
