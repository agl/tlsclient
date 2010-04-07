// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"
#include "tlsclient/public/context.h"

#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <gtest/gtest.h>

using namespace tlsclient;

namespace {

class ConnectionTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    const int server = socket(AF_INET, SOCK_STREAM, 0);
    assert(server >= 0);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = PF_INET;
    assert(bind(server, (struct sockaddr*) &sin, sizeof(sin)) == 0);
    socklen_t socklen = sizeof(sin);
    assert(getsockname(server, (struct sockaddr*) &sin, &socklen) == 0);
    assert(socklen == sizeof(sin));
    assert(listen(server, 1) == 0);

    const int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(server >= 0);
    assert(connect(client, (struct sockaddr*) &sin, sizeof(sin)) == 0);

    child_ = fork();
    if (child_ == 0) {
      if (server == 3) {
        close(client);
      } else {
        close(client);
        dup2(server, 3);
        close(server);
      }
      static const char* const args[] = {"./out/Default/openssl-helper", NULL};
      execv(args[0], const_cast<char**>(args));
      static const char kMsg[] = "Failed to exec openssl helper\n";
      write(2, kMsg, sizeof(kMsg) - 1);
      _exit(0);
    }

    close(server);
    client_ = client;
  }

  virtual void TearDown() {
    close(client_);
    client_ = -1;
    int status;
    waitpid(client_, &status, 0);
  }

  int client_;
  pid_t child_;
};

class TestingContext : public Context {
 public:
  virtual bool RandomBytes(void* addr, size_t len) {
    memset(addr, 0, len);
    return true;
  }

  virtual uint64_t EpochSeconds() {
    return 513;
  }

  Certificate* ParseRSACertificate(const uint8_t* bytes, size_t length) {
    return NULL;
  }
};

TEST_F(ConnectionTest, Basic) {
  TestingContext ctx;
  Connection conn(&ctx);

  conn.EnableDefault();
  ASSERT_TRUE(conn.need_to_write());
  ASSERT_FALSE(conn.is_server_verified());
  ASSERT_FALSE(conn.is_server_cert_available());
  ASSERT_FALSE(conn.is_ready_to_send_application_data());

  struct iovec iov;
  ASSERT_EQ(0, conn.Get(&iov));
  ASSERT_EQ(iov.iov_len, write(client_, iov.iov_base, iov.iov_len));

  std::vector<struct iovec> iovs;

  for (;;) {
    static const size_t kBufferLength = 10;
    uint8_t* buf = new uint8_t[kBufferLength];
    struct iovec iov, *out_iov;
    iov.iov_base = buf;
    unsigned out_n;
    size_t used;

    for (;;) {
      const ssize_t r = read(client_, buf, kBufferLength);
      if (r == -1) {
        if (errno == EINTR)
          continue;
        ASSERT_EQ(errno, EINTR);
        return;
      }
      iov.iov_len = r;

      iovs.push_back(iov);

      ASSERT_EQ(0, conn.Process(&out_iov, &out_n, &used, &iovs[0], iovs.size()));
    }
  }
}

}  // anonymous namespace
