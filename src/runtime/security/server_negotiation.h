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

#include "negotiation.h"
#include "negotiation_utils.h"
#include <dsn/utility/errors.h>

namespace dsn {
namespace security {

class server_negotiation : public negotiation
{
public:
    server_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_message(message_ptr msg);

private:
    void handle_client_response_on_challenge(const message_ptr &req);
    void on_list_mechanisms(const message_ptr &m);
    void on_select_mechanism(const message_ptr &m);

    error_s do_sasl_server_init();
    error_s do_sasl_server_start(const blob &input, blob &output);
    error_s do_sasl_step(const blob &input, blob &output);

    void fail_negotiation(const message_ptr &req, dsn::string_view reason);
    void succ_negotiation(const message_ptr &req);
    void reply(const message_ptr &req, const negotiation_message &response_data);

private:
    // the lifetime of _session should be longer than client_negotiation
    rpc_session *_session;
    // for logging
    std::string _name;
    std::string _selected_mechanism;
    std::unique_ptr<sasl_conn_t, sasl_deleter> _sasl_conn;
};

} // namespace security
} // namespace dsn
