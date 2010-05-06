// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

static const char kKeyFile[] = "testdata/openssl.key";
static const char kCertFile[] = "testdata/openssl.crt";

int db_store(void* ptr, gnutls_datum_t key, gnutls_datum_t value) {
  std::map<std::string, std::string> *db = static_cast<std::map<std::string, std::string>*>(ptr);
  (*db)[std::string((char *)key.data, key.size)] = std::string((char*)value.data, value.size);
  return 0;
}

gnutls_datum_t db_retrieve(void* ptr, gnutls_datum_t key) {
  std::map<std::string, std::string> *db = static_cast<std::map<std::string, std::string>*>(ptr);

  gnutls_datum_t ret;
  memset(&ret, 0, sizeof(ret));
  std::map<std::string, std::string>::const_iterator i = db->find(std::string((char *)key.data, key.size));
  if (i != db->end()) {
    ret.data = (unsigned char *) malloc(i->second.size());
    memcpy(ret.data, i->second.data(), i->second.size());
    ret.size = i->second.size();
  }

  return ret;
}

int db_remove(void* ptr, gnutls_datum_t key) {
  return 0;
}

int
main(int argc, char **argv) {
  int ret;

  bool tls12 = false, resume = false, session_tickets = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "tls1.2") == 0) {
      tls12 = true;
    } else if (strcmp(argv[i], "resume") == 0) {
      resume = true;
    } else if (strcmp(argv[i], "session-tickets") == 0) {
      session_tickets = true;
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 1;
    }
  }

  std::map<std::string, std::string> db;

  // Don't block on /dev/random
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  gnutls_global_init ();

  gnutls_certificate_credentials_t x509_cred;
  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_key_file(x509_cred, kCertFile, kKeyFile, GNUTLS_X509_FMT_PEM);

  gnutls_datum_t session_ticket_key;
  if (session_tickets)
    gnutls_session_ticket_key_generate(&session_ticket_key);

  for (unsigned connections = 0; ; connections++) {
    gnutls_session_t session;
    gnutls_init(&session, GNUTLS_SERVER);

    if (resume) {
      if (session_tickets) {
        gnutls_session_ticket_enable_server(session, &session_ticket_key);
      } else {
        gnutls_db_set_store_function(session, db_store);
        gnutls_db_set_retrieve_function(session, db_retrieve);
        gnutls_db_set_remove_function(session, db_remove);
        gnutls_db_set_ptr(session, &db);
      }
    }

    const char* err_pos;
    ret = gnutls_priority_set_direct(session, "NORMAL", &err_pos);
    assert(ret == GNUTLS_E_SUCCESS);

    if (tls12) {
      int protocols[2];
      protocols[0] = gnutls_protocol_get_id("TLS1.2");
      assert(protocols[0] != GNUTLS_VERSION_UNKNOWN);
      protocols[1] = 0;
      ret = gnutls_protocol_set_priority(session, protocols);
      assert(ret == GNUTLS_E_SUCCESS);
    }

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

    if (!resume || (resume && connections == 1))
      break;
  }

  gnutls_certificate_free_credentials(x509_cred);
  gnutls_global_deinit();

  return 0;
}
