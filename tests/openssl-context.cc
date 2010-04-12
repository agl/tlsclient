// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/tests/openssl-context.h"

#include <time.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

class OpenSSLCertificate : public tlsclient::Certificate {
 public:
  OpenSSLCertificate(X509* x509, EVP_PKEY* pubkey)
      : x509_(x509),
        pubkey_(pubkey),
        rsa_(pubkey_->pkey.rsa) {
  }

  ~OpenSSLCertificate() {
    EVP_PKEY_free(pubkey_);
    X509_free(x509_);
  }

  virtual size_t SizeEncryptPKCS1() {
    return RSA_size(rsa_);
  }

  virtual bool EncryptPKCS1(uint8_t* output, uint8_t* bytes, size_t length) {
    const unsigned size = RSA_size(rsa_);
    if (size <= RSA_PKCS1_PADDING_SIZE || length >= size - RSA_PKCS1_PADDING_SIZE)
      return false;
    return RSA_public_encrypt(length, bytes, output, rsa_, RSA_PKCS1_PADDING) == RSA_size(rsa_);
  }

 private:
  X509* const x509_;
  EVP_PKEY* const pubkey_;
  RSA* const rsa_;
};

bool OpenSSLContext::RandomBytes(void* buffer, size_t len) {
  return RAND_bytes(static_cast<unsigned char*>(buffer), len) == 1;
}

uint64_t OpenSSLContext::EpochSeconds() {
  return time(NULL);
}

tlsclient::Certificate* OpenSSLContext::ParseCertificate(const uint8_t* bytes, size_t length) {
  BIO* bio = BIO_new_mem_buf(const_cast<uint8_t*>(bytes), length);
  X509* x509 = d2i_X509_bio(bio, NULL);
  BIO_free(bio);
  if (!x509)
    return NULL;
  EVP_PKEY* pkey = X509_get_pubkey(x509);
  if (!pkey) {
    X509_free(x509);
    return NULL;
  }

  if (pkey->type != EVP_PKEY_RSA) {
    // We only support RSA keys for now
    EVP_PKEY_free(pkey);
    X509_free(x509);
    return NULL;
  }

  return new OpenSSLCertificate(x509, pkey);
}
