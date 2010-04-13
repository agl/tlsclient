// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/cipher_suites.h"

#include "tlsclient/src/buffer.h"
#include "tlsclient/src/crypto/prf/hmac.h"
#include "tlsclient/src/crypto/prf/prf.h"
#include "tlsclient/src/crypto/rc4/rc4.h"
#include "tlsclient/src/crypto/sha1/sha1.h"

namespace tlsclient {

#if 0
static void hexdump(const void* in, size_t length) {
  const uint8_t* const a = reinterpret_cast<const uint8_t*>(in);

  for (size_t i = 0; i < length; i++) {
    printf("%x", a[i] >> 4);
    printf("%x", a[i] & 15);
  }
  printf("\n");
}
#endif

static void MarshalSeqNum(uint8_t* seq, uint64_t seq_num) {
  seq[0] = seq_num >> 56;
  seq[1] = seq_num >> 48;
  seq[2] = seq_num >> 40;
  seq[3] = seq_num >> 32;
  seq[4] = seq_num >> 24;
  seq[5] = seq_num >> 16;
  seq[6] = seq_num >> 8;
  seq[7] = seq_num;
}

class RC4_SHA : public CipherSpec {
 public:
  RC4_SHA(const KeyBlock& kb)
      : rc4_read_(kb.server_key, kb.key_len),
        rc4_write_(kb.client_key, kb.key_len) {
    memcpy(mac_read_, kb.server_mac, sizeof(mac_read_));
    memcpy(mac_write_, kb.client_mac, sizeof(mac_write_));
  }

  virtual unsigned ScratchBytesNeeded(size_t length) {
    return HMAC<SHA1>::DIGEST_SIZE;
  }

  virtual bool Encrypt(uint8_t* scratch, size_t* scratch_size, const uint8_t* record_header, struct iovec* in, unsigned in_len, uint64_t seq_num) {
    if (*scratch_size < HMAC<SHA1>::DIGEST_SIZE)
      return false;

    uint8_t seq[8];
    MarshalSeqNum(seq, seq_num);

    HMAC<SHA1> mac(mac_write_, sizeof(mac_write_));
    mac.Update(seq, sizeof(seq));
    mac.Update(record_header, 5);
    for (unsigned i = 0; i < in_len; i++) {
      mac.Update(in[i].iov_base, in[i].iov_len);
    }
    mac.Final(scratch);
    *scratch_size = HMAC<SHA1>::DIGEST_SIZE;

    in[in_len].iov_base = scratch;
    in[in_len].iov_len = HMAC<SHA1>::DIGEST_SIZE;
    rc4_write_.Encrypt(in, in_len + 1);
    return true;
  }

  virtual bool Decrypt(unsigned* bytes_stripped, struct iovec* iov, unsigned* iov_len, const uint8_t* record_header, uint64_t seq_num) {
    uint8_t seq[8];
    uint8_t scratch1[HMAC<SHA1>::DIGEST_SIZE];
    uint8_t scratch2[HMAC<SHA1>::DIGEST_SIZE];
    MarshalSeqNum(seq, seq_num);

    rc4_read_.Decrypt(iov, *iov_len);

    Buffer buf(iov, *iov_len);
    const size_t len = buf.size();
    if (len < HMAC<SHA1>::DIGEST_SIZE)
      return false;
    buf.Advance(len - HMAC<SHA1>::DIGEST_SIZE);
    if (!buf.Read(scratch2, sizeof(scratch2)))
      return false;

    uint8_t record_header_copy[5];
    memcpy(record_header_copy, record_header, 5);
    uint16_t record_length = static_cast<uint16_t>(record_header[3]) << 8 |
                             record_header[4];
    record_length -= HMAC<SHA1>::DIGEST_SIZE;
    record_header_copy[3] = record_length >> 8;
    record_header_copy[4] = record_length;

    Buffer::RemoveTrailingBytes(iov, iov_len, HMAC<SHA1>::DIGEST_SIZE);

    HMAC<SHA1> mac(mac_read_, sizeof(mac_read_));
    mac.Update(seq, sizeof(seq));
    mac.Update(record_header_copy, 5);
    for (unsigned i = 0; i < *iov_len; i++)
      mac.Update(iov[i].iov_base, iov[i].iov_len);
    mac.Final(scratch1);

    return CompareBytes(scratch1, scratch2, sizeof(scratch1));
  }

  virtual unsigned StripMACAndPadding(struct iovec* iov, unsigned* iov_len) {
    return 0;
  }

 private:
  RC4 rc4_read_;
  RC4 rc4_write_;
  uint8_t mac_read_[20];
  uint8_t mac_write_[20];
};

CipherSpec* CreateRC4_SHA(const KeyBlock& kb) {
  return new RC4_SHA(kb);
}

static const CipherSuite kCipherSuites[] = {
  { CIPHERSUITE_RSA | CIPHERSUITE_RC4 | CIPHERSUITE_SHA,
    0x0005, "TLS_RSA_WITH_RC4_128_SHA", 16, 20, 0, CreateRC4_SHA},
  { 0, 0, "", 0, 0, 0, NULL },
};

const CipherSuite* AllCipherSuites() {
  return kCipherSuites;
}

bool CompareBytes(const uint8_t* a, const uint8_t* b, unsigned len) {
  uint8_t v = 0;

  for (unsigned i = 0; i < len; i++) {
    v |= a[i] ^ b[i];
  }

  return v == 0;
}


}  // namespace tlsclient
