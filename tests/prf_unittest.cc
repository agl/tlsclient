// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/src/crypto/prf/prf.h"

#include <gtest/gtest.h>

#include "tlsclient/src/base-internal.h"
#include "tlsclient/tests/util.h"

using namespace tlsclient;

namespace {

class PRFTest : public ::testing::Test {
};

struct PRFTestCase {
  const char* premaster;
  const char* client_random;
  const char* server_random;
  unsigned mac_len;
  unsigned key_len;
  const char *client_mac;
  const char *server_mac;
  const char *client_key;
  const char *server_key;
};

// These tests were taken from the Go code.
static const PRFTestCase PRFTests[] = {
  {
    "0302cac83ad4b1db3b9ab49ad05957de2a504a634a386fc600889321e1a971f57479466830ac3e6f468e87f5385fa0c5",
    "4ae66303755184a3917fcb44880605fcc53baa01912b22ed94473fc69cebd558",
    "4ae663020ec16e6bb5130be918cfcafd4d765979a3136a5d50c593446e4e44db",
    20,
    16,
    "805aaa19b3d2c0a0759a4b6c9959890e08480119",
    "2d22f9fe519c075c16448305ceee209fc24ad109",
    "d50b5771244f850cd8117a9ccafe2cf1",
    "e076e33206b30507a85c32855acd0919",
  },
  {
    "03023f7527316bc12cbcd69e4b9e8275d62c028f27e65c745cfcddc7ce01bd3570a111378b63848127f1c36e5f9e4890",
    "4ae66364b5ea56b20ce4e25555aed2d7e67f42788dd03f3fee4adae0459ab106",
    "4ae66363ab815cbf6a248b87d6b556184e945e9b97fbdf247858b0bdafacfa1c",
    20,
    16,
    "97742ed60a0554ca13f04f97ee193177b971e3b0",
    "37068751700400e03a8477a5c7eec0813ab9e0dc",
    "207cddbc600d2a200abac6502053ee5c",
    "df3f94f6e1eacc753b815fe16055cd43",
  },
  {
    "832d515f1d61eebb2be56ba0ef79879efb9b527504abb386fb4310ed5d0e3b1f220d3bb6b455033a2773e6d8bdf951d278a187482b400d45deb88a5d5a6bb7d6a7a1decc04eb9ef0642876cd4a82d374d3b6ff35f0351dc5d411104de431375355addc39bfb1f6329fb163b0bc298d658338930d07d313cd980a7e3d9196cac1",
    "4ae663b2ee389c0de147c509d8f18f5052afc4aaf9699efe8cb05ece883d3a5e",
    "4ae664d503fd4cff50cfc1fb8fc606580f87b0fcdac9554ba0e01d785bdf278e",
    20,
    16,
    "3c7647c93c1379a31a609542aa44e7f117a70085",
    "0d73102994be74a575a3ead8532590ca32a526d4",
    "ac7581b0b6c10d85bbd905ffbf36c65e",
    "ff07edde49682b45466bd2e39464b306",
  },
};

TEST_F(PRFTest, Simple) {
  for (size_t i = 0; i < arraysize(PRFTests); i++) {
    const PRFTestCase* test = &PRFTests[i];
    const unsigned premaster_len = strlen(test->premaster) / 2;
    uint8_t* premaster = new uint8_t[premaster_len];
    uint8_t client_random[32];
    uint8_t server_random[32];

    FromHex(premaster, test->premaster);
    FromHex(client_random, test->client_random);
    FromHex(server_random, test->server_random);

    KeyBlock kb;
    kb.key_len = test->key_len;
    kb.mac_len = test->mac_len;
    kb.iv_len = 0;

    KeysFromPreMasterSecret(TLSv10, &kb, premaster, premaster_len, client_random, server_random);

    char* client_key = new char[test->key_len*2 + 1];
    char* server_key = new char[test->key_len*2 + 1];
    char* client_mac = new char[test->mac_len*2 + 1];
    char* server_mac = new char[test->mac_len*2 + 1];

    HexDump(client_key, kb.client_key, kb.key_len);
    ASSERT_STREQ(test->client_key, client_key);
    HexDump(server_key, kb.server_key, kb.key_len);
    ASSERT_STREQ(test->server_key, server_key);
    HexDump(client_mac, kb.client_mac, kb.mac_len);
    ASSERT_STREQ(test->client_mac, client_mac);
    HexDump(server_mac, kb.server_mac, kb.mac_len);
    ASSERT_STREQ(test->server_mac, server_mac);

    delete[] premaster;
    delete[] client_key;
    delete[] server_key;
    delete[] client_mac;
    delete[] server_mac;
  }
}

}  // anonymous namespace
