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
    void start_negotiate();
    void handle_message(message_ptr msg);

private:
    void list_mechanisms();
    void recv_mechanisms(const message_ptr &mechs_msg);
    void select_mechanism(const std::string &mechanism);
    void mechanism_selected(const message_ptr &mechs_msg);
    void initiate_negotiation();
    void handle_challenge(const message_ptr &challenge_msg);

    error_s do_sasl_client_init();
    error_s send_sasl_initiate_msg();
    error_s do_sasl_step(const std::string &input, std::string &output);

    void send(const negotiation_message &n);
    void fail_negotiation();
    void succ_negotiation();

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
