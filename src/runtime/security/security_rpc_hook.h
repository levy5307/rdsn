// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once

#include "runtime/rpc/rpc_session_hook.h"

namespace dsn {
namespace security {
class security_rpc_hook : public rpc_session_hook
{
public:
    security_rpc_hook() = default;
    ~security_rpc_hook() = default;

    bool on_connected(rpc_session *session);
    bool on_receive_message(message_ex *msg);
    bool on_send_message(message_ex *msg);
    bool on_disconnected(message_ex *msg);
};
} // namespace security
} // namespace dsn
