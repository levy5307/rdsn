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

#include "security_types.h"
#include "sasl_wrapper.h"

#include <memory>
#include <dsn/utility/errors.h>
#include <dsn/tool-api/rpc_message.h>
#include <dsn/cpp/rpc_holder.h>

namespace dsn {
class rpc_session;

namespace security {
typedef rpc_holder<negotiation_request, negotiation_response> negotiation_rpc;

class negotiation
{
public:
    negotiation(rpc_session *session)
        : _session(session), _status(negotiation_status::type::INVALID)
    {
    }
    virtual ~negotiation() = 0;

    virtual void start() = 0;
    const char *user_name() const { return _user_name.c_str(); }
    bool negotiation_succeed() const { return _status == negotiation_status::type::SASL_SUCC; }
    void fail_negotiation() {
        _status = negotiation_status::type::SASL_AUTH_FAIL;
        _session->on_failure(true);
    }

protected:
    // The ownership of the negotiation instance is held by rpc_session.
    // So negotiation keeps only a raw pointer.
    rpc_session *_session;
    std::string _user_name;
    std::string _name;
    negotiation_status::type _status;
    std::unique_ptr<sasl_wrapper> _sasl;
};

std::unique_ptr<negotiation> create_negotiation(bool is_client, rpc_session *session);
} // namespace security
} // namespace dsn
