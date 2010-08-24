// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <gtest/gtest.h>

#include "tlsclient/public/context.h"
#include "tlsclient/src/arena.h"
#include "tlsclient/src/buffer.h"
#include "tlsclient/tests/openssl-context.h"

using namespace tlsclient;

namespace {

static const char kTestSrcDirAdditional[] =
#if defined(TEST_SRCDIR_ADDITIONAL)
#define xstr(x) str(x)
#define str(x) #x
 "" xstr(TEST_SRCDIR_ADDITIONAL) "";
#undef xstr
#undef str
#else
  "";
#endif

static const char kOpenSSLHelperBase[] = "openssl-helper";

const char *OpenSSLHelper() {
  static char path[256];
  const char *testSrcDir = getenv("TEST_SRCDIR");
  if (!testSrcDir)
    testSrcDir = "./out/Default";
  snprintf(path, sizeof(path), "%s/%s/%s", testSrcDir, kTestSrcDirAdditional, kOpenSSLHelperBase);
  printf("TESTSRCDIR: %s\n", path);
  return path;
}

#if defined(HAVE_GNUTLS)
static const char kGnuTLSHelperBase[] = "gnutls-helper";

const char *GnuTLSHelper() {
  static char path[256];
  const char *testSrcDir = getenv("TEST_SRCDIR");
  if (!testSrcDir)
    testSrcDir = "./out/Default";
  snprintf(path, sizeof(path), "%s/%s/%s", testSrcDir, kTestSrcDirAdditional, kGnuTLSHelperBase);
  return path;
}
#endif


class ConnectionTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    client_ = -1;
    child_ = -1;
  }

  void StartServer(const char* const args[]) {
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

    static const int on = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

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
      execv(args[0], const_cast<char**>(args));
      static const char kMsg[] = "Failed to exec openssl helper\n";
      write(2, kMsg, sizeof(kMsg) - 1);
      _exit(0);
    }

    close(server);
    client_ = client;
  }

  void StopServer() {
    close(client_);
    client_ = -1;
    int status;
    waitpid(child_, &status, 0);
    child_ = -1;
  }

  virtual void TearDown() {
    if (child_ != -1)
      StopServer();
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

static void MaybePrintResult(Result r) {
  if (!r)
    return;
  char filename[8];
  FilenameFromResult(filename, r);
  fprintf(stderr, "%s:%d %s\n", filename, LineNumberFromResult(r), StringFromResult(r));
}

static const uint8_t kMsg[] = {'h', 'e', 'l', 'l', 'o', '!'};

static void PerformConnection(const int fd, Connection* conn, bool is_snap_start = false) {
  Result r;

  ASSERT_TRUE(conn->need_to_write());
  ASSERT_FALSE(conn->is_server_verified());
  ASSERT_FALSE(conn->is_server_cert_available());
  ASSERT_FALSE(conn->is_ready_to_send_application_data());

  Arena arena;
  std::vector<struct iovec> iovs;
  bool sent = is_snap_start;
  bool corked = false;
  int buffer_length = 0;
  bool have_echo = false;

  for (;;) {
    if (conn->need_to_write()) {
      struct iovec out;
      r = conn->Get(&out);
      MaybePrintResult(r);
      ASSERT_EQ(0, ErrorCodeFromResult(r));
      if (conn->is_ready_to_send_application_data() && !sent) {
        static const int on = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
        corked = true;
      }
      ASSERT_TRUE(writea(fd, out.iov_base, out.iov_len));
    }

    if (conn->is_ready_to_send_application_data() && !sent) {
      struct iovec iov[3];
      uint8_t msg[sizeof(kMsg)];
      memcpy(msg, kMsg, sizeof(kMsg));
      iov[1].iov_base = msg;
      iov[1].iov_len = sizeof(msg);
      r = conn->Encrypt(&iov[0], &iov[2], &iov[1], 1);
      ASSERT_EQ(0, ErrorCodeFromResult(r));
      writev(fd, iov, 3);
      sent = true;
      if (corked) {
        static const int off = 0;
        setsockopt(fd, IPPROTO_TCP, TCP_CORK, &off, sizeof(off));
        corked = false;
      }
    }

    buffer_length = 2048;
    uint8_t* buf = static_cast<uint8_t*>(arena.Allocate(buffer_length));
    struct iovec iov, *out_iov;
    iov.iov_base = buf;
    unsigned out_n;
    size_t used;

    ssize_t n;
    for (;;) {
      n = read(fd, buf, buffer_length);
      if (n == -1) {
        if (errno == EINTR)
          continue;
        ASSERT_EQ(EINTR, errno);
        return;
      }
      break;
    }

    ASSERT_LT(0, n);

    iov.iov_len = n;
    iovs.push_back(iov);

    for (;;) {
      r = conn->Process(&out_iov, &out_n, &used, &iovs[0], iovs.size());

      if (out_n) {
        char s[9];
        Buffer buf(out_iov, out_n);
        ASSERT_EQ(8u, buf.size());
        ASSERT_TRUE(buf.Read(s, 8));
        s[8] = 0;
        ASSERT_STREQ("goodbye!", s);
        have_echo = true;
      }

      if (ErrorCodeFromResult(r) == ERR_ALERT_CLOSE_NOTIFY) {
        ASSERT_TRUE(have_echo);
        return;
      }
      MaybePrintResult(r);
      ASSERT_EQ(0, ErrorCodeFromResult(r));

      if (!used)
        break;

      // Need to remove the consumed bytes from the buffer.
      while (used) {
        assert(iovs.size() > 0);
        if (used >= iovs[0].iov_len) {
          used -= iovs[0].iov_len;
          iovs.erase(iovs.begin());
        } else {
          iovs[0].iov_base = static_cast<uint8_t*>(iovs[0].iov_base) + used;
          iovs[0].iov_len -= used;
          used = 0;
        }
      }
    }
  }
}

TEST_F(ConnectionTest, OpenSSLSimple) {
  static const char* const args[] = {OpenSSLHelper(), NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  StartServer(args);
  PerformConnection(client_, &conn);
}

#if defined(HAVE_GNUTLS)
TEST_F(ConnectionTest, GnuTLSSimple) {
  static const char* const args[] = {GnuTLSHelper(), NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  StartServer(args);
  PerformConnection(client_, &conn);
}

TEST_F(ConnectionTest, GnuTLSv12) {
  static const char* const args[] = {GnuTLSHelper(), "tls1.2", NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  StartServer(args);
  PerformConnection(client_, &conn);
}

TEST_F(ConnectionTest, GnuTLSAES) {
  static const char* const args[] = {GnuTLSHelper(), NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableSHA(true);
  conn.EnableAES128(true);
  conn.EnableCBC(true);
  conn.EnableRSA(true);
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_STREQ(conn.cipher_suite_name(), "TLS_RSA_WITH_AES_128_CBC_SHA");
}

TEST_F(ConnectionTest, GnuTLSFalseStart) {
  static const char* const args[] = {GnuTLSHelper(), NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.EnableFalseStart(true);
  StartServer(args);
  PerformConnection(client_, &conn);
}

TEST_F(ConnectionTest, GnuTLSResume) {
  static const char* const args[] = {GnuTLSHelper(), "resume", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2);
  ASSERT_TRUE(conn2.did_resume());
}

TEST_F(ConnectionTest, GnuTLSResume12) {
  static const char* const args[] = {GnuTLSHelper(), "resume", "tls1.2", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2);
  ASSERT_TRUE(conn2.did_resume());
}

TEST_F(ConnectionTest, GnuTLSSessionTickets) {
  static const char* const args[] = {GnuTLSHelper(), "resume", "session-tickets", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.EnableSessionTickets(true);
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2);
  ASSERT_TRUE(conn2.did_resume());
}
#endif

TEST_F(ConnectionTest, OpenSSLv3) {
  static const char* const args[] = {OpenSSLHelper(), "sslv3", NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  StartServer(args);
  PerformConnection(client_, &conn);
}

TEST_F(ConnectionTest, OpenSSLAES) {
  static const char* const args[] = {OpenSSLHelper(), NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableSHA(true);
  conn.EnableAES128(true);
  conn.EnableCBC(true);
  conn.EnableRSA(true);
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_STREQ(conn.cipher_suite_name(), "TLS_RSA_WITH_AES_128_CBC_SHA");
}

TEST_F(ConnectionTest, OpenSSLSNI) {
  static const char* const args[] = {OpenSSLHelper(), "sni", NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.set_host_name("test.example.com");
  StartServer(args);
  PerformConnection(client_, &conn);
}

TEST_F(ConnectionTest, OpenSSLFalseStart) {
  static const char* const args[] = {OpenSSLHelper(), NULL};

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.EnableFalseStart(true);
  StartServer(args);
  PerformConnection(client_, &conn);
}

TEST_F(ConnectionTest, OpenSSLSessionTickets) {
  static const char* const args[] = {OpenSSLHelper(), "session-tickets", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.EnableSessionTickets(true);
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2);
  ASSERT_TRUE(conn2.did_resume());
}

TEST_F(ConnectionTest, OpenSSLSnapStart) {
  static const char* const args[] = {OpenSSLHelper(), "snap-start", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.CollectSnapStartData();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_snap_start_data_available());

  struct iovec snap_start_data;
  r = conn.GetSnapStartData(&snap_start_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  const struct iovec *server_certs;
  unsigned server_certs_len;
  r = conn.server_certificates(&server_certs, &server_certs_len);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  conn2.SetPredictedCertificates(server_certs, server_certs_len);
  r = conn2.SetSnapStartData(static_cast<uint8_t*>(snap_start_data.iov_base), snap_start_data.iov_len, kMsg, sizeof(kMsg));
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2, true /* snap started */);
  ASSERT_TRUE(conn2.did_snap_start());
}

TEST_F(ConnectionTest, OpenSSLSnapStartResume) {
  static const char* const args[] = {OpenSSLHelper(), "snap-start", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.CollectSnapStartData();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_snap_start_data_available());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec snap_start_data;
  r = conn.GetSnapStartData(&snap_start_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  const struct iovec *server_certs;
  unsigned server_certs_len;
  r = conn.server_certificates(&server_certs, &server_certs_len);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  conn2.SetPredictedCertificates(server_certs, server_certs_len);
  r = conn2.SetSnapStartData(static_cast<uint8_t*>(snap_start_data.iov_base), snap_start_data.iov_len, kMsg, sizeof(kMsg));
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2, true);
  ASSERT_TRUE(conn2.did_snap_start());
  ASSERT_TRUE(conn2.did_resume());
}

TEST_F(ConnectionTest, OpenSSLSnapStartRecovery) {
  static const char* const args[] = {OpenSSLHelper(), "snap-start-recovery", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.CollectSnapStartData();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_snap_start_data_available());

  struct iovec snap_start_data;
  r = conn.GetSnapStartData(&snap_start_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  const struct iovec *server_certs;
  unsigned server_certs_len;
  r = conn.server_certificates(&server_certs, &server_certs_len);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  conn2.SetPredictedCertificates(server_certs, server_certs_len);
  r = conn2.SetSnapStartData(static_cast<uint8_t*>(snap_start_data.iov_base), snap_start_data.iov_len, kMsg, sizeof(kMsg));
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2, true);
  ASSERT_FALSE(conn2.did_snap_start());
}

TEST_F(ConnectionTest, OpenSSLSnapStartResumeRecovery) {
  static const char* const args[] = {OpenSSLHelper(), "snap-start-recovery", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.CollectSnapStartData();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_snap_start_data_available());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec snap_start_data;
  r = conn.GetSnapStartData(&snap_start_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  const struct iovec *server_certs;
  unsigned server_certs_len;
  r = conn.server_certificates(&server_certs, &server_certs_len);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  conn2.SetPredictedCertificates(server_certs, server_certs_len);
  r = conn2.SetSnapStartData(static_cast<uint8_t*>(snap_start_data.iov_base), snap_start_data.iov_len, kMsg, sizeof(kMsg));
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2, true);
  ASSERT_FALSE(conn2.did_snap_start());
  ASSERT_TRUE(conn2.did_resume());
}

TEST_F(ConnectionTest, OpenSSLSnapStartResumeRecoveryMispredict) {
  // This test doesn't trigger a recovery by having the helper binary reject
  // the random, but rather by corrupting the Snap Start data so that we
  // mispredict the server's response.
  static const char* const args[] = {OpenSSLHelper(), "snap-start", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.CollectSnapStartData();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_snap_start_data_available());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec snap_start_data;
  r = conn.GetSnapStartData(&snap_start_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  // Force the ServerHello version to SSLv3.
  static_cast<uint8_t*>(snap_start_data.iov_base)[15] = 0;

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  const struct iovec *server_certs;
  unsigned server_certs_len;
  r = conn.server_certificates(&server_certs, &server_certs_len);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  conn2.SetPredictedCertificates(server_certs, server_certs_len);
  r = conn2.SetSnapStartData(static_cast<uint8_t*>(snap_start_data.iov_base), snap_start_data.iov_len, kMsg, sizeof(kMsg));
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2, true);
  ASSERT_FALSE(conn2.did_snap_start());
  ASSERT_TRUE(conn2.did_resume());
}


TEST_F(ConnectionTest, OpenSSLSnapStartResumeRecovery2) {
  static const char* const args[] = {OpenSSLHelper(), "snap-start-recovery", NULL};
  Result r;

  OpenSSLContext ctx;
  Connection conn(&ctx);
  conn.EnableDefault();
  conn.CollectSnapStartData();
  StartServer(args);
  PerformConnection(client_, &conn);
  ASSERT_FALSE(conn.did_resume());
  ASSERT_TRUE(conn.is_snap_start_data_available());
  ASSERT_TRUE(conn.is_resumption_data_availible());

  struct iovec snap_start_data;
  r = conn.GetSnapStartData(&snap_start_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  struct iovec resumption_data;
  r = conn.GetResumptionData(&resumption_data);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  // We deliberately damage the resumption data to cause a double failure.
  static_cast<uint8_t*>(resumption_data.iov_base)[100] ^= 0xff;

  const struct iovec *server_certs;
  unsigned server_certs_len;
  r = conn.server_certificates(&server_certs, &server_certs_len);
  ASSERT_EQ(0, ErrorCodeFromResult(r));

  Connection conn2(&ctx);
  conn2.EnableDefault();
  conn2.SetPredictedCertificates(server_certs, server_certs_len);
  r = conn2.SetSnapStartData(static_cast<uint8_t*>(snap_start_data.iov_base), snap_start_data.iov_len, kMsg, sizeof(kMsg));
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  r = conn2.SetResumptionData(static_cast<uint8_t*>(resumption_data.iov_base), resumption_data.iov_len);
  MaybePrintResult(r);
  ASSERT_EQ(0, ErrorCodeFromResult(r));
  PerformConnection(client_, &conn2, true);
  ASSERT_FALSE(conn2.did_snap_start());
  ASSERT_FALSE(conn2.did_resume());
}

}  // anonymous namespace
