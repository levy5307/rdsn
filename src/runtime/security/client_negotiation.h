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

#include <sasl/sasl.h>

namespace dsn {
namespace security {
extern const std::set<std::string> supported_mechanisms;

class client_negotiation : public negotiation
{
public:
    client_negotiation(rpc_session *session);
    void start();

private:
    void handle_response(message_ptr resp);
    void list_mechanisms();
    void recv_mechanisms(const negotiation_response &resp);
    void select_mechanism(const std::string &resp);
    void mechanism_selected(const negotiation_response &resp);
    void initiate_negotiation();
    void handle_challenge(const negotiation_response &resp);

    error_s do_sasl_client_init();
    error_s send_sasl_initiate_msg();
    error_s do_sasl_step(const std::string &input, std::string &output);

    void send(const negotiation_request &request);
    void fail_negotiation();
    void succ_negotiation();

private:
    // for logging
    std::string _selected_mechanism;
    std::unique_ptr<sasl_conn_t, sasl_deleter> _sasl_conn;
};

} // namespace security
} // namespace dsn
