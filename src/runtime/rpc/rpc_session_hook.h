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

#include <dsn/tool-api/rpc_message.h>

namespace dsn {
class rpc_session_hook
{
public:
    rpc_session_hook() = default;
    virtual ~rpc_session_hook() = 0;

    virtual bool on_connected(message_ex *msg) = 0;
    virtual bool on_receive(message_ex *msg) = 0;
    virtual bool on_send(message_ex *msg) = 0;
};
} // namespace dsn
