// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_CONNECTION_PRIVATE_H
#define TLSCLIENT_CONNECTION_PRIVATE_H

#include "tlsclient/public/base.h"
#include "tlsclient/src/arena.h"
#include "tlsclient/src/handshake.h"

#include <string>

namespace tlsclient {

class Context;
class Certificate;
struct CipherSuite;
class CipherSpec;
class HandshakeHash;

struct ConnectionPrivate {
  ConnectionPrivate(Context* in_ctx)
      : ctx(in_ctx),
        state(SEND_CLIENT_HELLO),
        sslv3(false),
        cipher_suite_flags_enabled(0),
        last_buffer(NULL),
        version_established(false),
        partial_record_remaining(0),
        pending_records_decrypted(0),
        application_data_allowed(false),
        can_send_application_data(false),
        cipher_suite(NULL),
        server_supports_renegotiation_info(false),
        server_cert(NULL),
        handshake_hash(NULL),
        read_cipher_spec(NULL),
        write_cipher_spec(NULL),
        pending_read_cipher_spec(NULL),
        pending_write_cipher_spec(NULL),
        session_id_len(0),
        did_resume(false),
        resumption_data_ready(false),
        false_start(false),
        collect_snap_start(false),
        server_supports_snap_start(false),
        snap_start_data_available(false),
        snap_start_attempt(false),
        snap_start_recovery(false),
        recording_application_data(false),
        did_snap_start(false),
        session_tickets(false),
        have_session_ticket_to_present(false),
        expecting_session_ticket(false) {
    sent_client_hello.iov_base = 0;
    sent_client_key_exchange.iov_base = 0;
    server_verify.iov_base = 0;
    server_verify.iov_len = 0;
  }

  ~ConnectionPrivate();

  Arena arena;
  Context* const ctx;
  HandshakeState state;
  std::string host_name;
  bool sslv3;
  // cipher_suite_flags_enabled is a bitmask of CIPHERSUITE_ values (see
  // src/handshake.h) which describes the set of ciphersuites that are
  // acceptable to the user.
  unsigned cipher_suite_flags_enabled;
  // last_buffer contains a pointer to the last marshall buffer. We assume
  // that, by the time the client calls Connection::Get() again, it has
  // finished with the last buffer and so we can free it. This buffer is
  // allocated via |arena|.
  uint8_t* last_buffer;
  struct iovec sent_client_hello;
  struct iovec sent_client_key_exchange;
  // This is true if we have established a common TLS version in |version|
  bool version_established;
  TLSVersion version;
  // This is the number of bytes of record payload data currently pending.
  // This is non-zero if we parse a handshake message from a record, but
  // there's another handshake message in the same record. In this case, next
  // time GetRecordOrHandshake looks at the pending data it needs to know not
  // to expect a record header at the beginning.
  unsigned partial_record_remaining;
  // This is the number of records which we have decrypted but not processed.
  // This is non-zero if we're looking for a complete handshake message and
  // it spans several encrypted records.
  unsigned pending_records_decrypted;
  // When returning vectors of application data, we need somewhere to store the
  // iovecs. We want to avoid allocating and freeing then everytime so we keep
  // this around. It will grow as needed but (hopefully) not shrink.
  std::vector<struct iovec> out_vectors;
  // This is true iff we have completed a handshake and are happy to pass
  // application data records to the client.
  bool application_data_allowed;
  // This is true iff we are happy to send application data to the peer.
  // Typically this is only true if we have completed the handshake but False
  // Start and Snap Start alter this.
  bool can_send_application_data;
  uint8_t client_random[32];
  uint8_t server_random[32];
  const CipherSuite* cipher_suite;
  bool server_supports_renegotiation_info;
  // Each of these vectors contains an element of the server's certificate
  // chain (in the order received from the server). The underlying data is
  // allocated from |arena|.
  std::vector<struct iovec> server_certificates;
  // This is the server's certificate (i.e. the first one in it's certificate
  // chain)
  Certificate* server_cert;
  uint8_t master_secret[48];
  uint8_t premaster_secret[48];
  HandshakeHash* handshake_hash;
  // A NULL pointer for either of these means the NULL cipher spec.
  CipherSpec* read_cipher_spec;
  CipherSpec* write_cipher_spec;
  // These are the cipher specs which are waiting for a ChangeCipherSpec in
  // order to become current.
  CipherSpec* pending_read_cipher_spec;
  CipherSpec* pending_write_cipher_spec;
  // The sequence numbers. See RFC 2246 section 6.
  uint64_t write_seq_num;
  uint64_t read_seq_num;
  // This is buffer space in which we stuff record headers, MACs and padding
  // bytes for outbound records. We want to encrypt them in place, but we need
  // to add some bytes at the beginning and end. So we return an array of
  // iovecs and the extra space comes from here:
  uint8_t scratch[64];
  // If we are attempting a resume then this contains the offered session id
  // until we receive a ServerHello. Afterwards it contains the server's chosen
  // session id.
  uint8_t session_id[32];
  uint8_t session_id_len;
  // This is set to true when a ServerHello is received which echos our
  // attempted session resumption.
  bool did_resume;
  // This is set to true when |session_id_len| and |master_secret| are ready.
  // (Note that session_id_len may still be zero if the server didn't offer
  // resumption.)
  bool resumption_data_ready;
  bool false_start;

  bool collect_snap_start;
  bool server_supports_snap_start;
  bool snap_start_data_available;
  struct iovec snap_start_server_hello;

  // The peer's expected certificates in wire format and wire order.
  std::vector<struct iovec> predicted_certificates;

  // This is true if we are attempting a snap start handshake.
  bool snap_start_attempt;
  // If we're attempting a snap start, we need to know the version that the
  // server will agree on in order to put it in the record headers.
  TLSVersion predicted_server_version;
  // This is the server's predicted handshake reply at the handshake level
  // (i.e. doesn't include record headers).
  struct iovec predicted_server_hello;
  struct iovec predicted_response;
  // If the server rejected our snap-start then this is true.
  bool snap_start_recovery;
  // If we are sending application data records after a snap-start we have to
  // record them in case we enter recovery and need to retransmit.
  bool recording_application_data;
  std::vector<struct iovec> recorded_application_data;
  // This is true if the handshake successfully managed a snap-start (without
  // entering recovery)
  bool did_snap_start;

  // This is the server's expected Finished data for the snap-start resume
  // case.
  struct iovec server_verify;

  // This is true if session tickets are enabled (i.e. we'll send the extension
  // and such)
  bool session_tickets;
  // If this is true, then |session_ticket| contains a session ticket that
  // we'll attempt to resume with.
  bool have_session_ticket_to_present;
  // If this is true, then the server indicated that it'll send a session
  // ticket in this handshake. Once |resumption_data_ready| is true, then the
  // next session ticket will be stored in |session_ticket|.
  bool expecting_session_ticket;
  struct iovec session_ticket;
};

}  // namespace tlsclient

#endif  // TLSCLIENT_CONNECTION_PRIVATE_H
