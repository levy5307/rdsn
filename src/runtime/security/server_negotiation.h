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
#include <dsn/cpp/rpc_holder.h>

namespace dsn {
namespace security {
extern const std::set<std::string> supported_mechanisms;

class server_negotiation : public negotiation
{
public:
    server_negotiation(rpc_session *session);
    void start();
    void handle_request(negotiation_rpc rpc);

private:
    void handle_client_response_on_challenge(negotiation_rpc rpc);
    void on_list_mechanisms(negotiation_rpc rpc);
    void on_select_mechanism(negotiation_rpc rpc);
    void succ_negotiation(negotiation_rpc rpc);

private:
    // for logging
    std::string _selected_mechanism;
};

} // namespace security
} // namespace dsn
