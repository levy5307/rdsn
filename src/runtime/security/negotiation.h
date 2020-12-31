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
#include <dsn/cpp/rpc_holder.h>

namespace dsn {
class rpc_session;

namespace security {
typedef rpc_holder<negotiation_request, negotiation_response> negotiation_rpc;

class negotiation
{
public:
    explicit negotiation(rpc_session* session)
        : _session(session), _status(negotiation_status::type::INVALID)
    {
        _sasl = create_sasl_wrapper(_session->is_client());
    }

    virtual ~negotiation() = 0;

    virtual void start() = 0;
    bool succeed() const { return _status == negotiation_status::type::SASL_SUCC; }
    void fail_negotiation();
    // check whether the status is equal to expected_status
    // ret value:
    //   true:  status == expected_status
    //   false: status != expected_status
    bool check_status(negotiation_status::type status, negotiation_status::type expected_status);

    /// ret value:
    ///    true  - pend succeed
    ///    false - pend failed
    bool try_pend_message(message_ex *msg);

protected:
    void set_succeed();

    rpc_session* _session;
    std::string _name;
    negotiation_status::type _status;
    std::string _selected_mechanism;
    std::unique_ptr<sasl_wrapper> _sasl;

private:
    void clear_pending_messages();

    mutable utils::ex_lock_nr _lock; // [
    // when the negotiation doesn't succeed,
    // all messages are queued in _pending_messages.
    // all of them will be resend when it succeed
    std::vector<message_ex *> _pending_messages;
    // ]

};

negotiation* create_negotiation(rpc_session *session);
} // namespace security
} // namespace dsn
