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

#include "rpc_session_hook_manager.h"

namespace dsn {

void rpc_session_hook_manager::add(std::unique_ptr<rpc_session_hook> interceptor)
{
    _hooks.push_back(std::move(interceptor));
}

bool rpc_session_hook_manager::on_connected(rpc_session *session)
{
    bool result = true;
    for (auto &interceptor : _hooks) {
        result &= interceptor->on_connected(session);
    }

    return result;
}

bool rpc_session_hook_manager::on_send_message(message_ex *msg)
{
    bool result = true;
    for (auto &interceptor : _hooks) {
        result &= interceptor->on_send_message(msg);
    }

    return result;
}

bool rpc_session_hook_manager::on_receive_message(message_ex *msg)
{
    bool result = true;
    for (auto &interceptor : _hooks) {
        result &= interceptor->on_receive_message(msg);
    }

    return result;
}

} // namespace dsn
