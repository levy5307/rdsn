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

#include "negotiation_manager.h"
#include "negotiation_utils.h"
#include "server_negotiation.h"

#include <dsn/utility/flags.h>
#include <dsn/tool-api/zlocks.h>
#include <dsn/dist/failure_detector/fd.code.definition.h>
#include <dsn/dist/fmt_logging.h>
#include <dsn/http/http_server.h>

namespace dsn {
namespace security {
DSN_DECLARE_bool(enable_auth);
DSN_DECLARE_bool(mandatory_auth);

inline bool is_negotiation_message(dsn::task_code code)
{
    return code == RPC_NEGOTIATION || code == RPC_NEGOTIATION_ACK;
}

// in_white_list returns if the rpc code can be allowed to bypass negotiation.
inline bool in_white_list(task_code code)
{
    return is_negotiation_message(code) || fd::is_failure_detector_message(code) ||
           is_http_message(code);
}

negotiation* get_negotiation(rpc_session *session) {
    return static_cast<negotiation *>(
            session->get_context(rpc_session_context_code::NEGOTIATION));
}

bool on_rpc_recv_msg(message_ex *msg)
{
    if (!msg->io_session->is_client() && !FLAGS_mandatory_auth) {
        // if this is server_session and mandatory_auth is turned off.
        return true;
    }
    if (in_white_list(msg->rpc_code())) {
        return true;
    }

    return get_negotiation(msg->io_session)->succeed();
}

bool on_rpc_send_msg(message_ex *msg)
{
    if (!msg->io_session->is_client() && !FLAGS_mandatory_auth) {
        // if this is server_session and mandatory_auth is turned off.
        return true;
    }
    if (in_white_list(msg->rpc_code())) {
        return true;
    }

    // if try_pend_message return true, it means the msg is pended to the resend message queue
    return !msg->io_session->try_pend_message(msg);
}

void on_rpc_session_created(rpc_session *session) {
    negotiation *nego = create_negotiation(session);
    session->set_context(rpc_session_context_code::NEGOTIATION, static_cast<void*>(nego));
}

void on_rpc_session_destroyed(rpc_session *session) {
    negotiation *nego = get_negotiation(session);
    if (dsn_likely(nego != nullptr)) {
        delete nego;
        session->delete_context(rpc_session_context_code::NEGOTIATION);
    }
}

void init_join_point()
{
    rpc_session::on_rpc_session_created.put_back(on_rpc_session_created, "security");
    rpc_session::on_rpc_session_destroyed.put_back(on_rpc_session_destroyed, "security");
    rpc_session::on_rpc_recv_message.put_native(on_rpc_recv_msg);
    rpc_session::on_rpc_send_message.put_native(on_rpc_send_msg);
}

negotiation_manager::negotiation_manager() : serverlet("negotiation_manager") {}

void negotiation_manager::open_service()
{
    register_rpc_handler_with_rpc_holder(
        RPC_NEGOTIATION, "Negotiation", &negotiation_manager::on_negotiation_request);
}

void negotiation_manager::on_negotiation_request(negotiation_rpc rpc)
{
    auto session = rpc.dsn_request()->io_session;
    dassert(!session->is_client(), "only server session receives negotiation request");

    // reply SASL_AUTH_DISABLE if auth is not enable
    if (!security::FLAGS_enable_auth) {
        rpc.response().status = negotiation_status::type::SASL_AUTH_DISABLE;
        return;
    }

    auto srv_negotiation = static_cast<server_negotiation *>(
            session->get_context(rpc_session_context_code::NEGOTIATION));
    srv_negotiation->handle_request(rpc);
}

} // namespace security
} // namespace dsn
