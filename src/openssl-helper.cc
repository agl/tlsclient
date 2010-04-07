// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

int
main(int argc, char **argv) {
  SSL_library_init();
  ERR_load_crypto_strings();

  BIO* bio = BIO_new_socket(3, 0 /* don't take ownership of fd */);
  SSL_CTX* ctx = SSL_CTX_new(TLSv1_server_method());
  SSL* server = SSL_new(ctx);
  SSL_set_bio(server, bio, bio);

  int err;
  for (;;) {
    const int ret = SSL_accept(server);
    if (ret != 1) {
      err = SSL_get_error(server, ret);
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "SSL_accept failed: %d\n", err);
      return 0;
    }
  }

  SSL_shutdown(server);

  return 0;
}
