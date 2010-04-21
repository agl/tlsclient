// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/cipher_suites.h"

#include "tlsclient/src/buffer.h"
#include "tlsclient/src/crypto/prf/hmac.h"
#include "tlsclient/src/crypto/prf/prf.h"
#include "tlsclient/src/crypto/rc4/rc4.h"
#include "tlsclient/src/crypto/md5/md5.h"
#include "tlsclient/src/crypto/sha1/sha1.h"

#if 0
#include <stdio.h>
static void hexdump(const void* in, size_t length) {
  const uint8_t* const a = reinterpret_cast<const uint8_t*>(in);

  for (size_t i = 0; i < length; i++) {
    printf("%x", a[i] >> 4);
    printf("%x", a[i] & 15);
  }
  printf("\n");
}
#endif

namespace tlsclient {

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

const uint8_t kSSLv3Pad1[48] =
  { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };

const uint8_t kSSLv3Pad2[48] =
  { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };

template<class H, enum TLSVersion>
class MAC { };

// MAC<SSLv3> implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
template<class H>
class MAC<H, SSLv3> {
 public:
  enum {
    MAC_SIZE = H::DIGEST_SIZE,
  };

  static void Do(uint8_t* out, const uint8_t* record_header, struct iovec* in, unsigned in_len, uint64_t seq_num, const uint8_t* mac_secret) {
    H hash;
    const unsigned pad_length = H::DIGEST_SIZE == 20 ? 40 : 48;

    hash.Update(mac_secret, H::DIGEST_SIZE);
    hash.Update(kSSLv3Pad1, pad_length);

    uint8_t seq[8];
    MarshalSeqNum(seq, seq_num);
    hash.Update(seq, sizeof(seq));

    hash.Update(record_header, 1);
    hash.Update(record_header + 3, 2);
    for (unsigned i = 0; i < in_len; i++)
      hash.Update(in[i].iov_base, in[i].iov_len);
    hash.Final(out);

    hash.Init();
    hash.Update(mac_secret, H::DIGEST_SIZE);
    hash.Update(kSSLv3Pad2, pad_length);
    hash.Update(out, H::DIGEST_SIZE);
    hash.Final(out);
  }
};

// MAC<TLSv10> implements the TLSv10 MAC function, as defined in RFC 2246
// section 6.3.2.1
template<class H>
class MAC<H, TLSv10> {
 public:
  enum {
    MAC_SIZE = HMAC<H>::DIGEST_SIZE,
  };

  static void Do(uint8_t* out, const uint8_t* record_header, struct iovec* in, unsigned in_len, uint64_t seq_num, const uint8_t* mac_secret) {
    uint8_t seq[8];
    MarshalSeqNum(seq, seq_num);

    HMAC<H> mac(mac_secret, H::DIGEST_SIZE);
    mac.Update(seq, sizeof(seq));
    mac.Update(record_header, 5);
    for (unsigned i = 0; i < in_len; i++)
      mac.Update(in[i].iov_base, in[i].iov_len);
    mac.Final(out);
  }
};

template<class Cipher, class H, enum TLSVersion V>
class StreamCipherSpec : public CipherSpec {
 public:
  typedef MAC<H, V> M;

  StreamCipherSpec(const KeyBlock& kb)
      : read_(kb.server_key, kb.key_len),
        write_(kb.client_key, kb.key_len) {
    memcpy(mac_read_, kb.server_mac, sizeof(mac_read_));
    memcpy(mac_write_, kb.client_mac, sizeof(mac_write_));
  }

  virtual unsigned ScratchBytesNeeded(size_t length) {
    return M::MAC_SIZE;
  }

  virtual bool Encrypt(uint8_t* scratch, size_t* scratch_size, const uint8_t* record_header, struct iovec* in, unsigned in_len, uint64_t seq_num) {
    if (*scratch_size < M::MAC_SIZE)
      return false;

    M::Do(scratch, record_header, in, in_len, seq_num, mac_write_);
    *scratch_size = M::MAC_SIZE;

    in[in_len].iov_base = scratch;
    in[in_len].iov_len = M::MAC_SIZE;
    write_.Encrypt(in, in_len + 1);
    return true;
  }

  virtual bool Decrypt(unsigned* bytes_stripped, struct iovec* iov, unsigned* iov_len, const uint8_t* record_header, uint64_t seq_num) {
    uint8_t scratch1[M::MAC_SIZE];
    uint8_t scratch2[M::MAC_SIZE];

    read_.Decrypt(iov, *iov_len);

    Buffer buf(iov, *iov_len);
    const size_t len = buf.size();
    if (len < M::MAC_SIZE)
      return false;
    buf.Advance(len - M::MAC_SIZE);
    if (!buf.Read(scratch2, sizeof(scratch2)))
      return false;

    uint8_t record_header_copy[5];
    memcpy(record_header_copy, record_header, 5);
    uint16_t record_length = static_cast<uint16_t>(record_header[3]) << 8 |
                             record_header[4];
    record_length -= M::MAC_SIZE;
    record_header_copy[3] = record_length >> 8;
    record_header_copy[4] = record_length;

    Buffer::RemoveTrailingBytes(iov, iov_len, M::MAC_SIZE);

    M::Do(scratch1, record_header_copy, iov, *iov_len, seq_num, mac_read_);
    return CompareBytes(scratch1, scratch2, sizeof(scratch1));
  }

  virtual unsigned StripMACAndPadding(struct iovec* iov, unsigned* iov_len) {
    Buffer::RemoveTrailingBytes(iov, iov_len, M::MAC_SIZE);
    return M::MAC_SIZE;
  }

 private:
  Cipher read_;
  Cipher write_;
  uint8_t mac_read_[H::DIGEST_SIZE];
  uint8_t mac_write_[H::DIGEST_SIZE];
};

template<class Cipher, class Hash>
CipherSpec* CreateStreamCipher(TLSVersion version, const KeyBlock& kb) {
  if (version == SSLv3) {
    return new StreamCipherSpec<Cipher, Hash, SSLv3>(kb);
  } else {
    return new StreamCipherSpec<Cipher, Hash, TLSv10>(kb);
  }
}

static const CipherSuite kCipherSuites[] = {
  { CIPHERSUITE_RSA | CIPHERSUITE_RC4 | CIPHERSUITE_SHA,
    0x0005, "TLS_RSA_WITH_RC4_128_SHA", 16, 20, 0, CreateStreamCipher<RC4, SHA1>},
  { CIPHERSUITE_RSA | CIPHERSUITE_RC4 | CIPHERSUITE_MD5,
    0x0004, "TLS_RSA_WITH_RC4_128_MD5", 16, 16, 0, CreateStreamCipher<RC4, MD5>},
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
