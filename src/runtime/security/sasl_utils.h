// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include "kerberos_utils.h"

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <functional>

#include <dsn/utility/errors.h>

namespace dsn {
namespace security {
// before call sasl_init, you must call init_kerberos()
error_s sasl_init(bool is_server);

error_s call_sasl_func(sasl_conn_t *conn, const std::function<int()> &call);

error_s retrive_user_name(sasl_conn_t *sasl_conn, std::string &output);

} // namespace security
} // namespace dsn
