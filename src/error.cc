// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/error.h"

#include <stdint.h>
#include <string.h>

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
  "Encountered an alert record with an incorrect length",
  "Encountered an invalid alert level",

  // Alerts
  "Received fatal alert from peer: close_notify",
  "Received fatal alert from peer: unexpected_message",
  "Received fatal alert from peer: bad_record_mac",
  "Received fatal alert from peer: decryption_failed",
  "Received fatal alert from peer: handshake_failure",
  "Received fatal alert from peer: no_certificate",
  "Received fatal alert from peer: bad_certificate",
  "Received fatal alert from peer: unsupported_certificate",
  "Received fatal alert from peer: certificate_revoked",
  "Received fatal alert from peer: certificate_expired",
  "Received fatal alert from peer: certificate_unknown",
  "Received fatal alert from peer: illegal_parameter",
  "Received fatal alert from peer: unknown_ca",
  "Received fatal alert from peer: access_denied",
  "Received fatal alert from peer: decode_error",
  "Received fatal alert from peer: decrypt_error",
  "Received fatal alert from peer: export_restriction",
  "Received fatal alert from peer: protocol_version",
  "Received fatal alert from peer: insufficient_security",
  "Received fatal alert from peer: internal_error",
  "Received fatal alert from peer: user_canceled",
  "Received fatal alert from peer: no_renegotiation",
  "Received fatal alert from peer: unsupported_extension",
  "Received unknown fatal alert from peer",

  "Received an application data record before the server verified itself",
  "Encountered a handshake message that was unexpected in this state",
  "Encountered corruption while processing a handshake message",
  "The server responded with an unsupported protocol version",
  "The server selected an unsupported/disabled cipher suite",
  "The server selected an unsupported/disabled compression method",
  "The server returned an unknown ServerHello extension",
  "Encountered a handshake message with unknown trailing data",
  "Context::ParseCertificate failed to parse the server's certificate",
  "Certificate::SizeEncryptPKCS1 failed",
  "Certificate::EncryptPKCS1 failed",
  "An internal error occured (sorry, my fault!)",
  "Received a record with bad authentication code",
  "Received a Finished record with bad verify data",
  "Connection::Encrypt called before the connection is ready",
  "Connection::Encrypt called with > 2**14 bytes of data",
  "Connection::Get called without need_to_write() being true",
  "GetResumptionData called before session is ready",
  "Connection::SetResumptionData failed to parse the given data",
  "The cipher suite specified by resumption data is not enabled",
  "The cipher suite specified by resumption data is not supported",
  "The server's cipher suite doesn't match the resumption data",
  "GetSnapStartData called before the snap start data is ready",
  "Connection::SetSnapStartData failed to parse the given data",
  "Need to call SetPredictedCertificates before SetSnapStartData",

  // Remember to add an element to the enum in public/error.h!

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

  const char* basename = strrchr(filename, '/');
  if (basename)
    filename = basename + 1;

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
