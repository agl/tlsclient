// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CONNECTION_H
#define TLSCLIENT_CONNECTION_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/error.h"

namespace tlsclient {

struct ConnectionPrivate;
class Context;
class Buffer;

class Connection {
 public:
  Connection(Context*);
  ~Connection();

  bool need_to_write() const;
  Result Get(struct iovec* out);
  Result Process(struct iovec** out, unsigned* out_n, size_t* used,
                 const struct iovec* iov, unsigned n);

  Result Encrypt(struct iovec* start, struct iovec* end, const struct iovec* iov, unsigned iov_len);

  bool is_server_cert_available() const;
  bool is_server_verified() const;
  bool is_ready_to_send_application_data() const;

  void set_sslv3(bool use_sslv3);
  void set_host_name(const char* name);

  void EnableRSA(bool enable);
  void EnableRC4(bool enable);
  void EnableSHA(bool enable);

  void EnableDefault();

  // For testing only.
  ConnectionPrivate* priv() const {
    return priv_;
  }

 private:
  void SetEnableBit(unsigned bit, bool onoff);

  ConnectionPrivate* const priv_;
};

}  // namespace tlsclient

#endif
