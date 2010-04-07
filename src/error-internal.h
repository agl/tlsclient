// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TLSCLIENT_ERROR_INTERNAL_H
#define TLSCLIENT_ERROR_INTERNAL_H

#include "tlsclient/public/base.h"
#include "tlsclient/public/error.h"

namespace tlsclient {

#define ERROR_RESULT(e) ErrorResult(__FILE__, __LINE__, e);

Result ErrorResult(const char* filename, unsigned line_no, ErrorCode);

}  // namespace tlsclient

#endif  // TLSCLIENT_ERROR_INTERNAL_H
