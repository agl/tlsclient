// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tlsclient/public/connection.h"

#include "tlsclient/public/error.h"
#include "tlsclient/src/connection_private.h"
#include "tlsclient/src/handshake.h"
#include "tlsclient/src/sink.h"

namespace tlsclient {

Connection::Connection(Context* ctx)
    : priv_(new ConnectionPrivate(ctx)) {
}

Connection::~Connection() {
  delete priv_;
}

void Connection::set_host_name(const char* name) {
  priv_->host_name = name;
}

bool Connection::need_to_write() const {
  switch (priv_->state) {
  case SEND_PHASE_ONE:
  case SEND_PHASE_TWO:
    return true;
  default:
    return false;
  }
}

bool Connection::is_server_cert_available() const {
  return false;
}

bool Connection::is_server_verified() const {
  return false;
}

bool Connection::is_ready_to_send_application_data() const {
  return false;
}

Result Connection::Get(struct iovec* out) {
  if (priv_->last_buffer) {
    priv_->arena.Free(priv_->last_buffer);
    priv_->last_buffer = NULL;
  }

  Sink sink(&priv_->arena);

  assert(need_to_write());

  {
    Sink s(sink.Record(TLSv12, RECORD_HANDSHAKE));
    Sink ss(sink.HandshakeMessage(CLIENT_HELLO));
    const Result r = MarshallClientHello(&ss, priv_);
    if (r)
      return r;
  }

  out->iov_len = sink.size();
  out->iov_base = sink.Release();
  return 0;
}

void Connection::EnableRSA(bool enable) {
  SetEnableBit(CIPHERSUITE_RSA, enable);
}

void Connection::EnableRC4(bool enable) {
  SetEnableBit(CIPHERSUITE_RC4, enable);
}

void Connection::EnableSHA(bool enable) {
  SetEnableBit(CIPHERSUITE_SHA, enable);
}

void Connection::EnableDefault() {
  SetEnableBit(CIPHERSUITE_RSA, true);
  SetEnableBit(CIPHERSUITE_RC4, true);
  SetEnableBit(CIPHERSUITE_SHA, true);
}

void Connection::SetEnableBit(unsigned mask, bool enable) {
  if (enable) {
    priv_->ciphersuite_flags |= mask;
  } else {
    priv_->ciphersuite_flags &= ~mask;
  }
}

Result Connection::Process(struct iovec** out, unsigned* out_n, size_t* used,
                           const struct iovec* iov, unsigned n) {
  *out = NULL;
  *out_n = 0;
  *used = 0;

  

  return 0;
}

}  // namespace tlsclient
