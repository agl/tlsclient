// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

static const char kKeyFile[] = "testdata/openssl.key";
static const char kCertFile[] = "testdata/openssl.crt";

int
main(int argc, char **argv) {
  int ret;

  // Don't block on /dev/random
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  gnutls_global_init ();

  gnutls_certificate_credentials_t x509_cred;
  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_key_file(x509_cred, kCertFile, kKeyFile, GNUTLS_X509_FMT_PEM);

  gnutls_session_t session;
  gnutls_init(&session, GNUTLS_SERVER);

  const char* err_pos;
  ret = gnutls_priority_set_direct(session, "NORMAL", &err_pos);
  assert(ret == GNUTLS_E_SUCCESS);

  int protocols[2];
  protocols[0] = gnutls_protocol_get_id("TLS1.2");
  assert(protocols[0] != GNUTLS_VERSION_UNKNOWN);
  protocols[1] = 0;
  ret = gnutls_protocol_set_priority(session, protocols);
  assert(ret == GNUTLS_E_SUCCESS);

  gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) 3);
  ret = gnutls_handshake(session);
  if (ret < 0) {
    gnutls_deinit(session);
    fprintf(stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
    return 1;
  }

  char buffer[6];
  ret = gnutls_record_recv(session, buffer, sizeof(buffer));
  if (ret == 0) {
    return 1;
  } else if (ret < 0) {
    fprintf(stderr, "\n*** Received corrupted data(%d). Closing the connection.\n\n", ret);
    return 1;
  } else {
    if (memcmp(buffer, "hello!", sizeof(buffer)) == 0) {
      gnutls_record_send(session, "goodbye!", 8);
    }
  }

  gnutls_bye(session, GNUTLS_SHUT_WR);
  gnutls_certificate_free_credentials(x509_cred);
  gnutls_global_deinit();

  return 0;
}
