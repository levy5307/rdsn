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

#include "negotiation_service.h"
#include "negotiation_utils.h"
#include "server_negotiation.h"

namespace dsn {
namespace security {
extern bool FLAGS_enable_auth;

negotiation_service::negotiation_service() : serverlet("negotiation_service") {}

void negotiation_service::open_service()
{
    register_rpc_handler(
        RPC_NEGOTIATION, "Negotiation", &negotiation_service::on_negotiation_request);
}

void negotiation_service::on_negotiation_request(message_ex *req)
{
    dassert(!req->io_session->is_client(), "only server session receive negotiation request");

    // return SASL_NO_AUTH if auth is not enable
    if (!security::FLAGS_enable_auth) {
        reply_no_auth(req);
        return;
    }

    server_negotiation *s_negotiation =
        dynamic_cast<server_negotiation *>(req->io_session->get_negotiation());
    s_negotiation->handle_request(req);
}

void negotiation_service::reply_no_auth(message_ex *req)
{
    auto resp = req->create_response();

    negotiation_response response;
    response.status = negotiation_status::type::SASL_NO_AUTH;
    marshall(resp, response);
    dsn_rpc_reply(resp);
}

} // namespace security
} // namespace dsn
