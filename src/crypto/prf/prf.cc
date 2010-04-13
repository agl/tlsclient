// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/prf/prf.h"

#include "tlsclient/src/crypto/md5/md5.h"
#include "tlsclient/src/crypto/prf/hmac.h"
#include "tlsclient/src/crypto/sha1/sha1.h"

#include <stdio.h>

namespace tlsclient {

// Calculates P_hash, as defined in RFC 2246, section 5.
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

void KeysFromPreMasterSecret10(KeyBlock* kb,
                               const uint8_t* premaster, size_t premaster_len,
                               const uint8_t* client_random,
                               const uint8_t* server_random) {
  static const char kMasterSecretLabel[] = "master secret";
  static const char kKeyLabel[] = "key expansion";
  uint8_t randoms[32 + 32];
  const unsigned key_material_len = kb->key_len * 2 + kb->mac_len * 2 + kb->iv_len * 2;
  uint8_t* const key_material = new uint8_t[key_material_len];

  memcpy(randoms, client_random, 32);
  memcpy(randoms + 32, server_random, 32);

  PRF10(kb->master_secret, sizeof(kb->master_secret), premaster, premaster_len, reinterpret_cast<const uint8_t*>(kMasterSecretLabel), sizeof(kMasterSecretLabel) - 1, randoms, sizeof(randoms));

  memcpy(randoms, server_random, 32);
  memcpy(randoms + 32, client_random, 32);

  PRF10(key_material, key_material_len, kb->master_secret, sizeof(kb->master_secret), reinterpret_cast<const uint8_t*>(kKeyLabel), sizeof(kKeyLabel) - 1, randoms, sizeof(randoms));

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

bool KeysFromPreMasterSecret(TLSVersion version,
                             KeyBlock* kb,
                             const uint8_t* premaster, size_t premaster_len,
                             const uint8_t* client_random,
                             const uint8_t* server_random) {
  switch (version) {
    case TLSv10:
    case TLSv11:
      KeysFromPreMasterSecret10(kb, premaster, premaster_len, client_random, server_random);
      return true;
    case SSLv3:
    case TLSv12:
    default:
      return false;
  }
}

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

HandshakeHash* HandshakeHashForVersion(TLSVersion version) {
  switch (version) {
    case TLSv10:
    case TLSv11:
      return new HandshakeHash10;
    case SSLv3:
    case TLSv12:
    default:
      return NULL;
  }
}

}  // namespace tlsclient
