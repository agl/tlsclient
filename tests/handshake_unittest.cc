// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "tlsclient/public/connection.h"
#include "tlsclient/public/context.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/src/crypto/cipher_suites.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class HandshakeTest : public ::testing::Test {
};

class ContextBase : public Context {
 public:
  bool RandomBytes(void* addr, size_t len) {
    return false;
  }

  uint64_t EpochSeconds() {
    return 0;
  }

  Certificate* ParseCertificate(const uint8_t* bytes, size_t length) {
    return NULL;
  }
};

class ContextWorkingEpochSeconds : public ContextBase {
 public:
  uint64_t EpochSeconds() {
    return 100000;
  }
};

class ContextWorkingRandomBytes : public ContextBase {
 public:
  bool RandomBytes(void* addr, size_t len) {
    memset(addr, 0, len);
    return true;
  }
};

class ContextBothWorking : public ContextBase {
 public:
  uint64_t EpochSeconds() {
    return 100000;
  }

  bool RandomBytes(void* addr, size_t len) {
    memset(addr, 0, len);
    return true;
  }
};

class FakeCertificate : public Certificate {
  virtual bool EncryptPKCS1(uint8_t* output, uint8_t* bytes, size_t length) {
    return false;
  }

  virtual size_t SizeEncryptPKCS1() {
    return 0;
  }
};

class ContextCanParseCertificates : public ContextBase {
 public:
  Certificate* ParseCertificate(const uint8_t* bytes, size_t length) {
    return new FakeCertificate;
  }
};


TEST_F(HandshakeTest, EpochSecondsFailure) {
  ContextWorkingRandomBytes ctx;
  Connection conn(&ctx);
  Arena a;
  Sink s(&a);

  const Result r = MarshalClientHello(&s, conn.priv());
  ASSERT_EQ(ERR_EPOCH_SECONDS_FAILED, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, RandomBytesFailure) {
  ContextWorkingEpochSeconds ctx;
  Connection conn(&ctx);
  Arena a;
  Sink s(&a);

  const Result r = MarshalClientHello(&s, conn.priv());
  ASSERT_EQ(ERR_RANDOM_BYTES_FAILED, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, Success) {
  ContextBothWorking ctx;
  Connection conn(&ctx);
  Arena a;
  Sink s(&a);

  conn.EnableDefault();
  const Result r = MarshalClientHello(&s, conn.priv());
  ASSERT_EQ(0, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, GetHandshakeMessageInvalidType) {
  static const char kData[] = "\x80\x00\x00\x00";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  HandshakeMessage htype;
  std::vector<struct iovec> out;

  const Result r = GetHandshakeMessage(&found, &htype, &out, &in);
  ASSERT_EQ(ERR_UNKNOWN_HANDSHAKE_MESSAGE_TYPE, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, GetHandshakeMessageTooLong) {
  static const char kData[] = "\x01\x80\x00\x00";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  HandshakeMessage htype;
  std::vector<struct iovec> out;

  const Result r = GetHandshakeMessage(&found, &htype, &out, &in);
  ASSERT_EQ(ERR_HANDSHAKE_MESSAGE_TOO_LONG, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, GetHandshakeMessageIncomplete) {
  static const char kData[] = "\x01\x00\x00\x01";
  struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  HandshakeMessage htype;
  std::vector<struct iovec> out;

  const Result r = GetHandshakeMessage(&found, &htype, &out, &in);
  ASSERT_EQ(0u, r);
  ASSERT_FALSE(found);

  iov.iov_len++;
  in.Rewind();
  const Result r2 = GetHandshakeMessage(&found, &htype, &out, &in);
  ASSERT_EQ(0u, r2);
  ASSERT_TRUE(found);
  ASSERT_EQ(CLIENT_HELLO, htype);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(0, static_cast<uint8_t*>(out[0].iov_base)[0]);
}

// A version with an invalid version.
TEST_F(HandshakeTest, GetRecordInvalidVersion) {
  static const char kData[] = "\x16\x01\x00\x00\x01";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(ERR_INVALID_RECORD_VERSION, ErrorCodeFromResult(r));
}

// A record with an invalid type.
TEST_F(HandshakeTest, GetRecordInvalidType) {
  static const char kData[] = "\x01\x03\x00\x00\x01";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(ERR_INVALID_RECORD_TYPE, ErrorCodeFromResult(r));
}

// A record which has a different version than the version which we imprinted to.
TEST_F(HandshakeTest, GetRecordChangingVersion) {
  static const char kData[] = "\x16\x03\x00\x00\x01";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);
  priv.version_established = true;
  priv.version = TLSv12;

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(ERR_BAD_RECORD_VERSION, ErrorCodeFromResult(r));
}

// A complete alert record.
TEST_F(HandshakeTest, GetAlert) {
  static const char kData[] = "\x15\x03\x00\x00\x02\x01\x02";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_ALERT, type);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(2u, out[0].iov_len);
  ASSERT_EQ(1, static_cast<uint8_t*>(out[0].iov_base)[0]);
  ASSERT_EQ(2, static_cast<uint8_t*>(out[0].iov_base)[1]);
  ASSERT_TRUE(priv.version_established);
  ASSERT_EQ(SSLv3, priv.version);
}

// A handshake message contained within a single record.
TEST_F(HandshakeTest, GetSimpleHandshake) {
  static const char kData[] = "\x16\x03\x00\x00\x05\x01\x00\x00\x01\x01";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(1, static_cast<uint8_t*>(out[0].iov_base)[0]);
  ASSERT_TRUE(priv.version_established);
  ASSERT_EQ(SSLv3, priv.version);
}

// The handshake message is incomplete.
TEST_F(HandshakeTest, GetIncompleteHandshake) {
  static const char kData[] = "\x16\x03\x00\x00\x05\x01\x00\x00\x01";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_FALSE(found);
}

// The handshake message is split across two records.
TEST_F(HandshakeTest, GetSplitHandshake) {
  static const char kData[] = "\x16\x03\x00\x00\x04\x01\x00\x00\x01\x16\x03\x00\x00\x01\x05";
  struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);
  Result r;

  for (iov.iov_len = 1; iov.iov_len < sizeof(kData); iov.iov_len++) {
    in.Rewind();
    r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
    ASSERT_EQ(0, ErrorCodeFromResult(r));
    if (iov.iov_len != sizeof(kData) - 1) {
      ASSERT_FALSE(found);
    }
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);

  // It's easier to put the output into a Buffer here.
  Buffer buf(&out[0], out.size());
  ASSERT_EQ(1u, buf.size());
  char c;
  ASSERT_TRUE(buf.Read(&c, 1));
  ASSERT_EQ(5, c);
}

// Two handshake messages are split across three records.
TEST_F(HandshakeTest, GetSplitHandshakes) {
  static const char kData[] = "\x16\x03\x00\x00\x03\x01\x00\x00\x16\x03\x00\x00\x07\x04\x10\x11\x12\x13\x01\x00\x16\x03\x00\x00\x05\x00\x03\x14\x15\x16";
  struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);
  Result r;

  for (iov.iov_len = 1; iov.iov_len < 21; iov.iov_len++) {
    in.Rewind();
    r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
    ASSERT_EQ(0, ErrorCodeFromResult(r));
    if (iov.iov_len != 20) {
      ASSERT_FALSE(found);
    }
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);

  // It's easier to put the output into a Buffer here.
  Buffer buf(&out[0], out.size());
  ASSERT_EQ(4u, buf.size());
  uint8_t contents[4];
  ASSERT_TRUE(buf.Read(contents, 4));
  ASSERT_TRUE(memcmp(contents, "\x10\x11\x12\x13", 4) == 0);

  ASSERT_EQ(18u, in.TellBytes());
  out.clear();
  const Buffer::Pos pos = in.Tell();

  for (iov.iov_len = 20; iov.iov_len < sizeof(kData); iov.iov_len++) {
    in.Seek(pos);
    r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
    ASSERT_EQ(0, ErrorCodeFromResult(r));
    if (iov.iov_len != sizeof(kData) - 1) {
      ASSERT_FALSE(found);
    }
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);

  Buffer buf2(&out[0], out.size());
  ASSERT_EQ(3u, buf2.size());
  ASSERT_TRUE(buf2.Read(contents, 3));
  ASSERT_TRUE(memcmp(contents, "\x14\x15\x16", 3) == 0);
}

// An incomplete handshake message followed by a non-handshake record.
TEST_F(HandshakeTest, GetTruncatedHandshake) {
  static const char kData[] = "\x16\x03\x00\x00\x04\x01\x00\x00\x01\x15\x03\x00\x00\x01\x05";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(ERR_TRUNCATED_HANDSHAKE_MESSAGE, ErrorCodeFromResult(r));
}

// Three handshake messages in a single record followed by an alert
TEST_F(HandshakeTest, GetMultiHandshake) {
  static const char kData[] = "\x16\x03\x00\x00\x0f\x01\x00\x00\x01\x05\x02\x00\x00\x01\x06\x10\x00\x00\x01\x07\x15\x03\x00\x00\x01\x08";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);

  out.clear();
  Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(5, static_cast<uint8_t*>(out[0].iov_base)[0]);

  out.clear();
  r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(SERVER_HELLO, htype);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(6, static_cast<uint8_t*>(out[0].iov_base)[0]);

  out.clear();
  r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_KEY_EXCHANGE, htype);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(7, static_cast<uint8_t*>(out[0].iov_base)[0]);

  out.clear();
  r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_ALERT, type);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(8, static_cast<uint8_t*>(out[0].iov_base)[0]);

  r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_FALSE(found);
}

// TestCipherSpec flips every 'encrypted' bit and puts a four byte 'MAC' at
// the end of the record.
class TestCipherSpec : public CipherSpec {
 public:
  enum {
    MAC_SIZE = 4,
  };

  unsigned ScratchBytesNeeded(size_t length) {
    assert(false);
  }

  virtual bool Encrypt(uint8_t* scratch, size_t* scratch_size, const uint8_t* record_header, struct iovec* in, unsigned in_len, uint64_t seq_num) {
    assert(false);
  }

  virtual bool Decrypt(unsigned* bytes_stripped, struct iovec* iov, unsigned* iov_len, const uint8_t* record_header, uint64_t seq_num) {
    // 'decrypt' the data by flipping all the bits
    for (unsigned i = 0; i < *iov_len; i++) {
      for (size_t j = 0; j < iov[i].iov_len; j++) {
        static_cast<uint8_t*>(iov[i].iov_base)[j] ^= 0xff;
      }
    }

    Buffer::RemoveTrailingBytes(iov, iov_len, MAC_SIZE);
    *bytes_stripped = MAC_SIZE;
    return true;
  }

  virtual unsigned StripMACAndPadding(struct iovec* iov, unsigned* iov_len) {
    Buffer::RemoveTrailingBytes(iov, iov_len, MAC_SIZE);
    return MAC_SIZE;
  }
};

// 'Decrypt' a single record.
TEST_F(HandshakeTest, DecryptRecord) {
  char kData[] = "\x17\x03\x00\x00\x05\xf0\x00\x00\x00\x00";
  static const struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);
  TestCipherSpec* test_cipher_spec = new TestCipherSpec;
  priv.read_cipher_spec = test_cipher_spec;

  const Result r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_APPLICATION_DATA, type);
  ASSERT_EQ(1u, out.size());
  ASSERT_EQ(1u, out[0].iov_len);
  ASSERT_EQ(15, static_cast<uint8_t*>(out[0].iov_base)[0]);
}

// Two handshake messages are split across three encrypted records.
TEST_F(HandshakeTest, GetSplitEncryptedHandshakes) {
  char kData[] = "\x16\x03\x00\x00\x07\xfe\xff\xff\x00\x00\x00\x00\x16\x03\x00\x00\x0b\xfb\xef\xee\xed\xec\xfe\xff\x00\x00\x00\x00\x16\x03\x00\x00\x09\xff\xfc\xeb\xea\xe9\x00\x00\x00\x00";
  struct iovec iov = {const_cast<char*>(kData), sizeof(kData) - 1};
  Buffer in(&iov, 1);
  bool found;
  RecordType type;
  HandshakeMessage htype;
  std::vector<struct iovec> out;
  ConnectionPrivate priv(NULL);
  Result r;
  TestCipherSpec* test_cipher_spec = new TestCipherSpec;
  priv.read_cipher_spec = test_cipher_spec;

  for (iov.iov_len = 1; iov.iov_len < 29; iov.iov_len++) {
    in.Rewind();
    if (iov.iov_len == 28)
      r++;
    r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
    ASSERT_EQ(0, ErrorCodeFromResult(r));
    if (iov.iov_len != 28) {
      ASSERT_FALSE(found);
    }
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);

  // It's easier to put the output into a Buffer here.
  Buffer buf(&out[0], out.size());
  ASSERT_EQ(4u, buf.size());
  uint8_t contents[4];
  ASSERT_TRUE(buf.Read(contents, 4));
  ASSERT_TRUE(memcmp(contents, "\x10\x11\x12\x13", 4) == 0);

  ASSERT_EQ(22u, in.TellBytes());
  out.clear();
  const Buffer::Pos pos = in.Tell();

  for (iov.iov_len = 28; iov.iov_len < sizeof(kData); iov.iov_len++) {
    in.Seek(pos);
    r = GetRecordOrHandshake(&found, &type, &htype, &out, &in, &priv);
    ASSERT_EQ(0, ErrorCodeFromResult(r));
    if (iov.iov_len != sizeof(kData) - 1) {
      ASSERT_FALSE(found);
    }
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(RECORD_HANDSHAKE, type);
  ASSERT_EQ(CLIENT_HELLO, htype);

  Buffer buf2(&out[0], out.size());
  ASSERT_EQ(3u, buf2.size());
  ASSERT_TRUE(buf2.Read(contents, 3));
  ASSERT_TRUE(memcmp(contents, "\x14\x15\x16", 3) == 0);
}

static const uint8_t kServerHelloTempl[] = {
  0x03, 0x02,   // version
  // server random
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x00, // no session id
  0x00, 0x05,  // TLS_RSA_WITH_RC4_128_SHA
  0x00, // no compression
  0x00, 0x00,  // no extension data
};

TEST_F(HandshakeTest, ProcessServerHelloBadVersion) {
  ConnectionPrivate priv(NULL);
  uint8_t kServerHello[sizeof(kServerHelloTempl)];
  memcpy(kServerHello, kServerHelloTempl, sizeof(kServerHelloTempl));
  struct iovec iov = {kServerHello, sizeof(kServerHello)};
  Buffer buf(&iov, 1);
  priv.cipher_suite_flags_enabled = -1;

  kServerHello[0] = 10;

  Result r = ProcessServerHello(&priv, &buf);
  ASSERT_EQ(ERR_UNSUPPORTED_SERVER_VERSION, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessServerHelloBadCipherSuite) {
  ConnectionPrivate priv(NULL);
  uint8_t kServerHello[sizeof(kServerHelloTempl)];
  memcpy(kServerHello, kServerHelloTempl, sizeof(kServerHelloTempl));
  struct iovec iov = {kServerHello, sizeof(kServerHello)};
  Buffer buf(&iov, 1);
  priv.cipher_suite_flags_enabled = -1;

  // Set ciphersuite to 0000
  kServerHello[36] = 0;

  Result r = ProcessServerHello(&priv, &buf);
  ASSERT_EQ(ERR_UNSUPPORTED_CIPHER_SUITE, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessServerHelloBadCompressionMethod) {
  ConnectionPrivate priv(NULL);
  uint8_t kServerHello[sizeof(kServerHelloTempl)];
  memcpy(kServerHello, kServerHelloTempl, sizeof(kServerHelloTempl));
  struct iovec iov = {kServerHello, sizeof(kServerHello)};
  Buffer buf(&iov, 1);
  priv.cipher_suite_flags_enabled = -1;

  // Set compression method to 22
  kServerHello[37] = 22;

  Result r = ProcessServerHello(&priv, &buf);
  ASSERT_EQ(ERR_UNSUPPORTED_COMPRESSION_METHOD, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessServerHello) {
  ConnectionPrivate priv(NULL);
  priv.state = RECV_SERVER_HELLO;
  struct iovec iov = {const_cast<uint8_t*>(kServerHelloTempl), sizeof(kServerHelloTempl)};
  Buffer buf(&iov, 1);
  priv.cipher_suite_flags_enabled = -1;

  Result r = ProcessServerHello(&priv, &buf);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(priv.cipher_suite);
  ASSERT_EQ(0x0005, priv.cipher_suite->value);
  ASSERT_TRUE(memcmp(priv.server_random, &kServerHelloTempl[2], 32) == 0);
}

TEST_F(HandshakeTest, ProcessServerHelloNoExtensions) {
  ConnectionPrivate priv(NULL);
  priv.state = RECV_SERVER_HELLO;
  // The last two bytes are the extensions length. We should be able to parse
  // without them.
  struct iovec iov = {const_cast<uint8_t*>(kServerHelloTempl), sizeof(kServerHelloTempl) - 2};
  Buffer buf(&iov, 1);
  priv.cipher_suite_flags_enabled = -1;

  Result r = ProcessServerHello(&priv, &buf);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_TRUE(priv.cipher_suite);
  ASSERT_EQ(0x0005, priv.cipher_suite->value);
  ASSERT_TRUE(memcmp(priv.server_random, &kServerHelloTempl[2], 32) == 0);
}

TEST_F(HandshakeTest, ProcessServerHelloPartial) {
  ConnectionPrivate priv(NULL);
  struct iovec iov = {const_cast<uint8_t*>(kServerHelloTempl), 0};
  Buffer buf(&iov, 1);
  priv.cipher_suite_flags_enabled = -1;

  // We want to check that all prefixes are invalid, but the prefix which cuts
  // off the two extension length bytes *is* valid, so we only check up to
  // there.
  for (size_t i = 0; i < sizeof(kServerHelloTempl) - 2; i++) {
    iov.iov_len = i;
    Buffer buf(&iov, 1);
    Result r = ProcessServerHello(&priv, &buf);
    ASSERT_EQ(ERR_INVALID_HANDSHAKE_MESSAGE, ErrorCodeFromResult(r));
  }
}

static const uint8_t kCertificateTempl[] = {
  0x00, 0x00, 0x13,  // total length
  0x00, 0x00, 0x03,  // cert 1 length
  0x04, 0x05, 0x06,
  0x00, 0x00, 0x03,  // cert 2 length
  0x04, 0x05, 0x07,
  0x00, 0x00, 0x04,  // cert 3 length
  0x04, 0x05, 0x06, 0x08,
};

TEST_F(HandshakeTest, ProcessCertificateBadLength1) {
  ConnectionPrivate priv(NULL);
  uint8_t kCertificate[sizeof(kCertificateTempl)];
  memcpy(kCertificate, kCertificateTempl, sizeof(kCertificateTempl));
  struct iovec iov = {kCertificate, sizeof(kCertificate)};
  Buffer buf(&iov, 1);

  kCertificate[2] = 40;

  Result r = ProcessServerCertificate(&priv, &buf);
  ASSERT_EQ(ERR_INVALID_HANDSHAKE_MESSAGE, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessCertificateBadLength2) {
  ConnectionPrivate priv(NULL);
  uint8_t kCertificate[sizeof(kCertificateTempl)];
  memcpy(kCertificate, kCertificateTempl, sizeof(kCertificateTempl));
  struct iovec iov = {kCertificate, sizeof(kCertificate)};
  Buffer buf(&iov, 1);

  kCertificate[5] = 5;

  Result r = ProcessServerCertificate(&priv, &buf);
  ASSERT_EQ(ERR_INVALID_HANDSHAKE_MESSAGE, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessCertificateZeroLength1) {
  ConnectionPrivate priv(NULL);
  static const uint8_t kCertificate[] = {0x00, 0x00, 0x00};
  struct iovec iov = {const_cast<uint8_t*>(kCertificate), sizeof(kCertificate)};
  Buffer buf(&iov, 1);

  Result r = ProcessServerCertificate(&priv, &buf);
  ASSERT_EQ(ERR_INVALID_HANDSHAKE_MESSAGE, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessCertificateZeroLength2) {
  ConnectionPrivate priv(NULL);
  static const uint8_t kCertificate[] = {0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
  struct iovec iov = {const_cast<uint8_t*>(kCertificate), sizeof(kCertificate)};
  Buffer buf(&iov, 1);

  Result r = ProcessServerCertificate(&priv, &buf);
  ASSERT_EQ(ERR_INVALID_HANDSHAKE_MESSAGE, ErrorCodeFromResult(r));
}

TEST_F(HandshakeTest, ProcessCertificate) {
  ContextCanParseCertificates ctx;
  ConnectionPrivate priv(&ctx);
  struct iovec iov = {const_cast<uint8_t*>(kCertificateTempl), sizeof(kCertificateTempl)};
  Buffer buf(&iov, 1);

  Result r = ProcessServerCertificate(&priv, &buf);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  ASSERT_EQ(3u, priv.server_certificates.size());
  ASSERT_EQ(3u, priv.server_certificates[0].iov_len);
  ASSERT_EQ(3u, priv.server_certificates[1].iov_len);
  ASSERT_EQ(4u, priv.server_certificates[2].iov_len);
  ASSERT_TRUE(memcmp(priv.server_certificates[0].iov_base, "\x04\x05\x06", 3) == 0);
  ASSERT_TRUE(memcmp(priv.server_certificates[1].iov_base, "\x04\x05\x07", 3) == 0);
  ASSERT_TRUE(memcmp(priv.server_certificates[2].iov_base, "\x04\x05\x06\x08", 4) == 0);
  ASSERT_TRUE(priv.server_cert);
}

}  // anonymous namespace
