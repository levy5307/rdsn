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
extern const std::set<std::string> supported_mechanisms;

class server_negotiation : public negotiation
{
public:
    server_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_request(message_ptr msg);

private:
    void handle_client_response_on_challenge(const message_ptr &req,
                                             const negotiation_request &request);
    void on_list_mechanisms(const message_ptr &m, const negotiation_request &request);
    void on_select_mechanism(const message_ptr &m, const negotiation_request &request);

    error_s do_sasl_server_init();
    error_s do_sasl_server_start(const std::string &input, std::string &output);
    error_s do_sasl_step(const std::string &input, std::string &output);

    void fail_negotiation(const message_ptr &req, const std::string &reason);
    void succ_negotiation(const message_ptr &req);
    void reply(const message_ptr &req, const negotiation_response &response);

private:
    // for logging
    std::string _name;
    std::string _selected_mechanism;
    std::unique_ptr<sasl_conn_t, sasl_deleter> _sasl_conn;
};

} // namespace security
} // namespace dsn
