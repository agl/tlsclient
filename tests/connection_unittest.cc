// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>

#include <gtest/gtest.h>

#include "tlsclient/public/context.h"
#include "tlsclient/src/arena.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/tests/openssl-context.h"

using namespace tlsclient;

namespace {

class ConnectionTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = PF_INET;
    assert(bind(listener, (struct sockaddr*) &sin, sizeof(sin)) == 0);
    socklen_t socklen = sizeof(sin);
    assert(getsockname(listener, (struct sockaddr*) &sin, &socklen) == 0);
    assert(socklen == sizeof(sin));
    assert(listen(listener, 1) == 0);

    const int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0);
    assert(connect(client, (struct sockaddr*) &sin, sizeof(sin)) == 0);

    const int server = accept(listener, NULL, NULL);
    assert(server >= 0);
    close(listener);

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

static bool
writea(int fd, const void* idata, size_t len) {
  size_t done = 0;
  const uint8_t* data = static_cast<const uint8_t*>(idata);

  while (done < len) {
    ssize_t r = write(fd, data + done, len - done);
    if (r == -1) {
      if (errno == EINTR)
        continue;
      return false;
    } else if (r == 0) {
      return false;
    } else {
      done += r;
    }
  }

  return true;
}

TEST_F(ConnectionTest, Basic) {
  OpenSSLContext ctx;
  Connection conn(&ctx);
  Result r;

  conn.EnableDefault();
  ASSERT_TRUE(conn.need_to_write());
  ASSERT_FALSE(conn.is_server_verified());
  ASSERT_FALSE(conn.is_server_cert_available());
  ASSERT_FALSE(conn.is_ready_to_send_application_data());

  Arena arena;
  std::vector<struct iovec> iovs;
  bool sent = false;

  for (;;) {
    if (conn.need_to_write()) {
      struct iovec out;
      Result r = conn.Get(&out);
      ASSERT_EQ(0, ErrorCodeFromResult(r));
      ASSERT_TRUE(writea(client_, out.iov_base, out.iov_len));
    }

    if (conn.is_ready_to_send_application_data() && !sent) {
      struct iovec iov[3];
      char kMsg[] = "hello!";
      iov[1].iov_base = kMsg;
      iov[1].iov_len = sizeof(kMsg) - 1;
      r = conn.Encrypt(&iov[0], &iov[2], &iov[1], 1);
      ASSERT_EQ(0, ErrorCodeFromResult(r));
      writev(client_, iov, 3);
      sent = true;
    }

    static const size_t kBufferLength = 1;
    uint8_t* buf = static_cast<uint8_t*>(arena.Allocate(kBufferLength));
    struct iovec iov, *out_iov;
    iov.iov_base = buf;
    unsigned out_n;
    size_t used;

    ssize_t n;
    for (;;) {
      n = read(client_, buf, kBufferLength);
      if (n == -1) {
        if (errno == EINTR)
          continue;
        ASSERT_EQ(errno, EINTR);
        return;
      }
      break;
    }

    if (!n)
      return; // FIXME

    iov.iov_len = n;
    iovs.push_back(iov);

    r = conn.Process(&out_iov, &out_n, &used, &iovs[0], iovs.size());
    if (r) {
      char filename[8];
      FilenameFromResult(filename, r);
      fprintf(stderr, "%s:%d %s\n", filename, LineNumberFromResult(r), StringFromResult(r));
    }
    ASSERT_EQ(0, ErrorCodeFromResult(r));

    if (out_n) {
      char s[9];
      Buffer buf(out_iov, out_n);
      ASSERT_EQ(8u, buf.size());
      ASSERT_TRUE(buf.Read(s, 8));
      s[8] = 0;
      ASSERT_STREQ("goodbye!", s);
      break;
    }

    // Need to remove the consumed bytes from the buffer.
    while (used) {
      assert(iovs.size() > 0);
      if (used >= iovs[0].iov_len) {
        used -= iovs[0].iov_len;
        iovs.erase(iovs.begin());
      } else {
        iovs[0].iov_base = static_cast<uint8_t*>(iovs[0].iov_base) + used;
        iovs[0].iov_len -= used;
        used -= used;
      }
    }
  }
}

}  // anonymous namespace
