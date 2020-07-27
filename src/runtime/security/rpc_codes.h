// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include <dsn/tool-api/task_code.h>

namespace dsn {
// TODO: version_nego_message
DEFINE_TASK_CODE_RPC(RPC_NEGOTIATION, TASK_PRIORITY_COMMON, dsn::THREAD_POOL_DEFAULT)

inline bool is_auth_nego_message(dsn::task_code code)
{
    return code == RPC_NEGOTIATION || code == RPC_NEGOTIATION_ACK;
}

inline bool is_negotiation_message(dsn::task_code code) { return is_auth_nego_message(code); }
}
