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

// Connection represents an association with a TLS peer. Initially the peer is
// unknown and unauthenticated. As the association progresses, by reading and
// writing data, the peer's certificate will become known and application level
// data can be transmitted and received.
//
// This library does no verification of the server. It's up to the user of this
// library to wait until the server's certificate chain is available and to
// validate it before sending or receiving application level data.
//
// The object is not thread-safe.
//
// A Connection generates data to be sent in one of two ways: either the data
// is generated internally and is overhead of the TLS protocol, or the data is
// encrypted application level data. Whenever internally generated data needs
// to be sent, |need_to_write| will return true. There are no external signals
// into this object, so |need_to_write| can only become true after data from
// the peer has been passed to |Process|. Thus the users of this object should
// check |need_to_write| after every chunk of data has been processed.
//
// Application level data is encrypted on request (once
// |is_ready_to_send_application_data| is true) with |Encrypt| and the user of
// this object should immediately send the resulting data onwards. Data from
// |Get| and |Encrypt| must not be reordered.
//
// Don't forget to call EnableDefault (or some set of Enable calls) first.
class Connection {
 public:
  // See the documentation in context.h.
  Connection(Context*);
  ~Connection();

  // need_to_write returns true whenever internally generated data needs to be
  // sent to the peer. Call |Get| to obtain the data.
  bool need_to_write() const;
  // Get generates data that must be sent to the peer.
  //   out: (output) on return, this points to the generated data. This data
  //     only remains valid until the next call to |Get|.
  //   returns: 0 on success.
  Result Get(struct iovec* out);

  // Process processes all data from the peer and splits out any application
  // level data that the user of this object should process furthur.
  //   out: (output) on return, points to an array of iovecs which describe
  //     the application level data (if any) extracted from the input.
  //   out_n: (output) on return, the number of elements in |out|
  //   used: (output) on return, the number of bytes of input consumed.
  //   iov: the data from the peer. *This is mutated by |Process|*.
  //   n: the number of elements in |iov|.
  //   returns:
  //     0: success
  //     ERR_ALERT_CLOSE_NOTIFY: the peer securely signaled the end of the
  //       stream. Application data may still have resulted from this call.
  //
  // Data from the peer cannot be processed if an insufficient amount is
  // availible.  In this case, |used| will be set to 0 and the user of this
  // object should read more data and call |Process| again with the previous
  // and additional data. The input may be mutated by |Process| and, if calling
  // |Process| multiple times with the same data, it's the mutated data which
  // must be given on subsequent calls.
  //
  // Equally, |used| may be less then the amount given. In this case, the used
  // bytes must not be given in subsequent calls.
  //
  // Data from the peer can consist entirely of overhead so |out_n| may be zero
  // on return even if |used| is non-zero.
  Result Process(struct iovec** out, unsigned* out_n, size_t* used,
                 const struct iovec* iov, unsigned n);

  // Encrypt encrypts application level data for transmission to the peer.
  // |is_ready_to_send_application_data| return true otherwise |Encrypt| will
  // result in ERR_NOT_READY_TO_SEND_APPLICATION_DATA. The given data is
  // mutated in place and two additional vectors are returned. The first must
  // be transmitted immediately prior to the encrypted application data and the
  // second immediately after.
  //   start: (output) on return, a vector of data to be transmitted
  //     immediately prior to that in |iov|. This data is valid until the next
  //     call to |Encrypt|
  //   end: (output) on return, a vector of data to be transmitted
  //     immediately after that in |iov|. This data is valid until the next
  //     call to |Encrypt|
  //   iov: an array of vectors of application level data. This data is
  //     encrypted in place.
  //   iov_len: the number of elements in |iov|.
  //   returns: 0 on success.
  Result Encrypt(struct iovec* start, struct iovec* end, const struct iovec* iov, unsigned iov_len);

  // is_resumption_data_availible returns true if |GetResumptionData| can
  // return session resumption information for this connection.
  bool is_resumption_data_availible() const;
  // GetResumptionData returns an opaque block of data which can be give as an
  // argument to |SetResumptionData| on future connections. The returned data
  // is freshly allocated and will be released when the Connection object is
  // deleted.
  Result GetResumptionData(struct iovec* iov);
  // SetResumptionData causes the connection to attempt to resume the session
  // which resulted in the data. (The data must be from a call to
  // GetResumptionData).
  //   data: a block of data from a previous call to GetResumptionData on
  //     another connection.
  //   len: the number of bytes in |data|
  //   returns:
  //     0: success
  //     ERR_CANNOT_PARSE_RESUMPTION_DATA: the data was invalid
  //     ERR_RESUME_CIPHER_SUITE_NOT_FOUND: the data specified a cipher suite
  //       which isn't supported.
  //     ERR_RESUME_CIPHER_SUITE_NOT_ENABLED: the data specified a cipher suite
  //       which hasn't been enabled via calls to Connection::Enable*
  Result SetResumptionData(const uint8_t* data, size_t len);
  // did_resume returns true if the last handshake was a resumption.
  bool did_resume() const;

  // is_server_cert_available returns true iff calling |server_certificates|
  // will return the peer's certificates. This will never be true if the
  // session is resumed. Once true, this is always true.
  bool is_server_cert_available() const;
  // is_server_verified returns true once the peer has proved that they hold
  // the private part of whatever certificate they presented. This will always
  // be true once |Process| returns application level data. Once true, this is
  // always true.
  bool is_server_verified() const;
  // is_ready_to_send_application_data returns true if the handshake has
  // sufficiently progressed that |Encrypt| may be called. Once true, this is
  // always true.
  bool is_ready_to_send_application_data() const;
  // server_certificates returns the server's certificates in the order given
  // by the peer (i.e. most specific first).
  //   out_iovs: (output) on return, points to an array of vectors. Each vector
  //     contains exactly one certificate.
  //   out_len: (output) on return, the number of elements in |out_iovs|.
  Result server_certificates(const struct iovec** out_iovs, unsigned* out_len);

  // cipher_suite_name returns the textual name of the current cipher suite, as
  // defined in the IANA registry of TLS cipher suites. This function can be
  // called any time after is_ready_to_send_application_data returns true.
  // Otherwise it will return NULL.
  const char* cipher_suite_name() const;

  void CollectSnapStartData();
  bool is_snap_start_data_available() const;
  Result GetSnapStartData(struct iovec* iov);
  Result SetSnapStartData(const uint8_t* data, size_t len);
  bool did_snap_start();

  // set_sslv3 sets whether we should use SSLv3 only. This should never need to
  // be called except to work around buggy TLS server that are intolerant of
  // extensions.
  void set_sslv3(bool use_sslv3);
  // set_host_name sets the name which is given the server to aid in its
  // selection of certificates.
  void set_host_name(const char* name);

  void EnableRSA(bool enable);
  void EnableRC4(bool enable);
  void EnableSHA(bool enable);

  void EnableFalseStart();

  // Set sensible defaults.
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
