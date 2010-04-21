// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/prf/prf.h"

#include "tlsclient/src/crypto/md5/md5.h"
#include "tlsclient/src/crypto/prf/hmac.h"
#include "tlsclient/src/crypto/sha1/sha1.h"
#include "tlsclient/src/crypto/sha256/sha256.h"

#if 0
#include <stdio.h>
static void hexdump(const void* data, size_t len) {
  const unsigned char* in = static_cast<const uint8_t*>(data);
  size_t i ;

  for (i = 0; i < len; i++) {
    printf("%x", in[i] >> 4);
    printf("%x", in[i] & 15);
  }

  printf("\n");
}
#endif

namespace tlsclient {

// PHash calculates P_hash, as defined in RFC 2246, section 5.
template<class H>
static void PHash(uint8_t* out, size_t out_len,
                  const uint8_t* secret, size_t secret_len,
                  const struct iovec* iov, unsigned iov_len) {
  typedef HMAC<H> HMAC;

  size_t done = 0;
  uint8_t digest[HMAC::DIGEST_SIZE];

  HMAC hmac(secret, secret_len);
  for (unsigned i = 0; i < iov_len; i++)
    hmac.Update(iov[i].iov_base, iov[i].iov_len);
  hmac.Final(digest);

  while (done < out_len) {
    uint8_t block[HMAC::DIGEST_SIZE];
    hmac.Init(secret, secret_len);
    hmac.Update(digest, sizeof(digest));
    for (unsigned i = 0; i < iov_len; i++)
      hmac.Update(iov[i].iov_base, iov[i].iov_len);
    hmac.Final(block);

    hmac.Init(secret, secret_len);
    hmac.Update(digest, sizeof(digest));
    hmac.Final(digest);

    size_t todo = out_len - done;
    if (todo > HMAC::DIGEST_SIZE)
      todo = HMAC::DIGEST_SIZE;
    memcpy(out + done, block, todo);
    done += todo;
  }
}

static void PRF10(uint8_t* out, size_t out_len,
                  const uint8_t* secret, size_t secret_len,
                  const uint8_t* label, size_t label_len,
                  const uint8_t* seed, size_t seed_len) {
  uint8_t* temp = new uint8_t[out_len];
  struct iovec iov[2];

  iov[0].iov_base = const_cast<uint8_t*>(label);
  iov[0].iov_len = label_len;
  iov[1].iov_base = const_cast<uint8_t*>(seed);
  iov[1].iov_len = seed_len;

  const size_t half_len = (secret_len+1) / 2;
  const uint8_t* secret2 = secret + secret_len - half_len;

  PHash<MD5>(out, out_len, secret, half_len, iov, 2);
  PHash<SHA1>(temp, out_len, secret2, half_len, iov, 2);
  for (size_t i = 0; i < out_len; i++)
    out[i] ^= temp[i];

  delete[] temp;
}

static void PRF12(uint8_t* out, size_t out_len,
                  const uint8_t* secret, size_t secret_len,
                  const uint8_t* label, size_t label_len,
                  const uint8_t* seed, size_t seed_len) {
  struct iovec iov[2];
  iov[0].iov_base = const_cast<uint8_t*>(label);
  iov[0].iov_len = label_len;
  iov[1].iov_base = const_cast<uint8_t*>(seed);
  iov[1].iov_len = seed_len;
  PHash<SHA256>(out, out_len, secret, secret_len, iov, 2);
}

// PRF30 implements the SSLv3 pseudo-random function as specified in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 6.
// In order to make the rest of the code more generic, this function takes and
// ignores a |label| argument and it assumes that the client and server randoms
// have been concatenated and provided in the |seed| argument.
static void PRF30 (uint8_t* out, size_t out_len,
                   const uint8_t* secret, size_t secret_len,
                   const uint8_t* label, size_t label_len,
                   const uint8_t* seed, size_t seed_len) {
  MD5 md5;
  SHA1 sha1;
  size_t done = 0;
  unsigned i = 0;

  while (done < out_len) {
    uint8_t output[MD5::DIGEST_SIZE];
    uint8_t digest[SHA1::DIGEST_SIZE];
    // RFC5246 section 6.3 says that the largest PRF output needed is 128
    // bytes. Since no more ciphersuites will be added to SSLv3, this will
    // remain true. Each iteration gives us 16 bytes so 10 iterations will be
    // sufficient.
    static const unsigned kMaxIterations = 10;
    uint8_t b[kMaxIterations];

    if (i > kMaxIterations)
      i = kMaxIterations;

    memset(b, 'A' + i, i + 1);
    sha1.Init();
    sha1.Update(b, i + 1);
    sha1.Update(secret, secret_len);
    sha1.Update(seed, seed_len);
    sha1.Final(digest);

    md5.Init();
    md5.Update(secret, secret_len);
    md5.Update(digest, sizeof(digest));
    md5.Final(output);

    size_t todo = out_len - done;
    if (todo > sizeof(output))
      todo = sizeof(output);

    memcpy(out + done, output, todo);
    done += todo;
    i++;
  }
}

typedef void (*PRF) (uint8_t* out, size_t out_len,
                     const uint8_t* secret, size_t secret_len,
                     const uint8_t* label, size_t label_len,
                     const uint8_t* seed, size_t seed_len);

void MasterSecretFromPreMasterSecret(uint8_t master[48], PRF prf,
                                     const uint8_t* premaster, size_t premaster_len,
                                     const uint8_t client_random[32],
                                     const uint8_t server_random[32]) {
  static const char kMasterSecretLabel[] = "master secret";
  uint8_t randoms[32 + 32];

  memcpy(randoms, client_random, 32);
  memcpy(randoms + 32, server_random, 32);

  prf(master, 48, premaster, premaster_len, reinterpret_cast<const uint8_t*>(kMasterSecretLabel), sizeof(kMasterSecretLabel) - 1, randoms, sizeof(randoms));
}

void KeysFromMasterSecret(KeyBlock* kb, PRF prf,
                          const uint8_t master[48],
                          const uint8_t* client_random,
                          const uint8_t* server_random) {
  static const char kKeyLabel[] = "key expansion";
  uint8_t randoms[32 + 32];
  const unsigned key_material_len = kb->key_len * 2 + kb->mac_len * 2 + kb->iv_len * 2;
  uint8_t* const key_material = new uint8_t[key_material_len];

  memcpy(randoms, server_random, 32);
  memcpy(randoms + 32, client_random, 32);

  prf(key_material, key_material_len, master, 48, reinterpret_cast<const uint8_t*>(kKeyLabel), sizeof(kKeyLabel) - 1, randoms, sizeof(randoms));

  const uint8_t* p = key_material;
  memcpy(kb->client_mac, p, kb->mac_len);
  p += kb->mac_len;
  memcpy(kb->server_mac, p, kb->mac_len);
  p += kb->mac_len;
  memcpy(kb->client_key, p, kb->key_len);
  p += kb->key_len;
  memcpy(kb->server_key, p, kb->key_len);
  p += kb->key_len;
  memcpy(kb->client_iv, p, kb->iv_len);
  p += kb->iv_len;
  memcpy(kb->server_iv, p, kb->iv_len);
  p += kb->iv_len;

  delete[] key_material;
}

bool MasterSecretFromPreMasterSecret(uint8_t master[48], TLSVersion version,
                                     const uint8_t* premaster, size_t premaster_len,
                                     const uint8_t client_random[32],
                                     const uint8_t server_random[32]) {
  PRF prf = NULL;

  switch (version) {
    case SSLv3:
      prf = PRF30;
      break;
    case TLSv10:
    case TLSv11:
      prf = PRF10;
      break;
    case TLSv12:
      prf = PRF12;
      break;
    default:
      return false;
  }

  MasterSecretFromPreMasterSecret(master, prf, premaster, premaster_len, client_random, server_random);
  return true;
}

bool KeysFromMasterSecret(KeyBlock* kb, TLSVersion version,
                          const uint8_t master[48],
                          const uint8_t client_random[32],
                          const uint8_t server_random[32]) {
  switch (version) {
    case SSLv3:
      KeysFromMasterSecret(kb, PRF30, master, client_random, server_random);
      return true;
    case TLSv10:
    case TLSv11:
      KeysFromMasterSecret(kb, PRF10, master, client_random, server_random);
      return true;
    case TLSv12:
      KeysFromMasterSecret(kb, PRF12, master, client_random, server_random);
      return true;
    default:
      return false;
  }
}

class HandshakeHash30 : public HandshakeHash {
 public:
  void Update(const void* data, size_t length) {
    sha1_.Update(data, length);
    md5_.Update(data, length);
  }

  virtual const uint8_t* ClientVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    static const uint8_t kMagic[4] = {0x43, 0x4c, 0x4e, 0x54};
    VerifyData(client_verify_, master_secret, master_secret_len, kMagic);
    *out_size = sizeof(client_verify_);
    return client_verify_;
  }

  virtual const uint8_t* ServerVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    static const uint8_t kMagic[4] = {0x53, 0x52, 0x56, 0x52};
    VerifyData(server_verify_, master_secret, master_secret_len, kMagic);
    *out_size = sizeof(server_verify_);
    return server_verify_;
  }

 private:
  void VerifyData(uint8_t* out, const uint8_t* master_secret, size_t master_secret_len, const uint8_t magic[4]) {
    MD5 md5(md5_);
    SHA1 sha1(sha1_);
    uint8_t pad1[48], pad2[48];
    uint8_t digest[SHA1::DIGEST_SIZE];

    // pad_1             The character 0x36 repeated 48 times for MD5
    //                   or 40 times for SHA.
    // pad_2             The character 0x5c repeated 48 times for MD5
    //                   or 40 times for SHA.
    memset(pad1, 0x36, sizeof(pad1));
    memset(pad2, 0x5c, sizeof(pad2));

    md5.Update(magic, 4);
    md5.Update(master_secret, master_secret_len);
    md5.Update(pad1, 48);
    md5.Final(digest);

    md5.Init();
    md5.Update(master_secret, master_secret_len);
    md5.Update(pad2, 48);
    md5.Update(digest, MD5::DIGEST_SIZE);
    md5.Final(out);

    sha1.Update(magic, 4);
    sha1.Update(master_secret, master_secret_len);
    sha1.Update(pad1, 40);
    sha1.Final(digest);

    sha1.Init();
    sha1.Update(master_secret, master_secret_len);
    sha1.Update(pad2, 40);
    sha1.Update(digest, SHA1::DIGEST_SIZE);
    sha1.Final(out + MD5::DIGEST_SIZE);
  }

  SHA1 sha1_;
  MD5 md5_;

  uint8_t client_verify_[MD5::DIGEST_SIZE + SHA1::DIGEST_SIZE];
  uint8_t server_verify_[MD5::DIGEST_SIZE + SHA1::DIGEST_SIZE];
};

class HandshakeHash10 : public HandshakeHash {
 public:
  void Update(const void* data, size_t length) {
    sha1_.Update(data, length);
    md5_.Update(data, length);
  }

  virtual const uint8_t* ClientVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    static const char kLabel[] = "client finished";
    uint8_t digests[MD5::DIGEST_SIZE + SHA1::DIGEST_SIZE];
    MD5 md5(md5_);
    SHA1 sha1(sha1_);

    md5.Final(digests);
    sha1.Final(digests + MD5::DIGEST_SIZE);
    PRF10(client_verify_, sizeof(client_verify_), master_secret, master_secret_len, reinterpret_cast<const uint8_t*>(kLabel), sizeof(kLabel) - 1, digests, sizeof(digests));

    *out_size = sizeof(client_verify_);
    return client_verify_;
  }

  virtual const uint8_t* ServerVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    static const char kLabel[] = "server finished";
    uint8_t digests[MD5::DIGEST_SIZE + SHA1::DIGEST_SIZE];
    MD5 md5(md5_);
    SHA1 sha1(sha1_);

    md5.Final(digests);
    sha1.Final(digests + MD5::DIGEST_SIZE);
    PRF10(server_verify_, sizeof(server_verify_), master_secret, master_secret_len, reinterpret_cast<const uint8_t*>(kLabel), sizeof(kLabel) - 1, digests, sizeof(digests));

    *out_size = sizeof(server_verify_);
    return server_verify_;
  }

 private:
  SHA1 sha1_;
  MD5 md5_;

  uint8_t client_verify_[12];
  uint8_t server_verify_[12];
};

class HandshakeHash12 : public HandshakeHash {
 public:
  void Update(const void* data, size_t length) {
    sha256_.Update(data, length);
  }

  virtual const uint8_t* ClientVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    static const char kLabel[] = "client finished";
    uint8_t digest[SHA256::DIGEST_SIZE];
    SHA256 sha256(sha256_);

    sha256.Final(digest);
    PRF12(client_verify_, sizeof(client_verify_), master_secret, master_secret_len, reinterpret_cast<const uint8_t*>(kLabel), sizeof(kLabel) - 1, digest, sizeof(digest));

    *out_size = sizeof(client_verify_);
    return client_verify_;
  }

  virtual const uint8_t* ServerVerifyData(unsigned* out_size, const uint8_t* master_secret, size_t master_secret_len) {
    static const char kLabel[] = "server finished";
    uint8_t digest[SHA256::DIGEST_SIZE];
    SHA256 sha256(sha256_);

    sha256.Final(digest);
    PRF12(server_verify_, sizeof(server_verify_), master_secret, master_secret_len, reinterpret_cast<const uint8_t*>(kLabel), sizeof(kLabel) - 1, digest, sizeof(digest));

    *out_size = sizeof(server_verify_);
    return server_verify_;
  }

 private:
  SHA256 sha256_;

  uint8_t client_verify_[12];
  uint8_t server_verify_[12];
};

HandshakeHash* HandshakeHashForVersion(TLSVersion version) {
  switch (version) {
    case TLSv10:
    case TLSv11:
      return new HandshakeHash10;
    case TLSv12:
      return new HandshakeHash12;
    case SSLv3:
      return new HandshakeHash30;
    default:
      return NULL;
  }
}

}  // namespace tlsclient
