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

#include "client_negotiation.h"
#include "sasl_utils.h"
#include "negotiation_utils.h"

#include <dsn/dist/fmt_logging.h>
#include <dsn/tool-api/async_calls.h>

namespace dsn {
namespace security {

client_negotiation::client_negotiation(rpc_session *session) : negotiation(session)
{
    _name = fmt::format("CLIENT_NEGOTIATION(SERVER={})", _session->remote_address().to_string());
}

void client_negotiation::start()
{
    ddebug_f("{}: start negotiation", _name);
    list_mechanisms();
}

void client_negotiation::list_mechanisms()
{
    negotiation_request request;
    _status = request.status = negotiation_status::type::SASL_LIST_MECHANISMS;
    send(request);
}

void client_negotiation::handle_response(error_code err, const negotiation_response &&response)
{
    if (err != ERR_OK) {
        fail_negotiation();
        return;
    }

    // if server doesn't enable auth and the auth is not mandantory, make the negotiation success
    if (negotiation_status::type::SASL_AUTH_DISABLE == response.status &&
        !_session->mandantory_auth()) {
        ddebug_f("{}: treat negotiation succeed as server doesn't enable it, user_name in later "
                 "messages aren't trustable",
                 _name);
        succ_negotiation();
        return;
    }

    if (_status == negotiation_status::type::SASL_LIST_MECHANISMS) {
        recv_mechanisms(response);
        return;
    }
    if (_status == negotiation_status::type::SASL_SELECT_MECHANISMS) {
        mechanism_selected(response);
        return;
    }
    handle_challenge(response);
}

void client_negotiation::recv_mechanisms(const negotiation_response &resp)
{
    if (resp.status != negotiation_status::type::SASL_LIST_MECHANISMS_RESP) {
        dwarn_f("{}: got message({}) while expect({})",
                _name,
                enum_to_string(resp.status),
                enum_to_string(negotiation_status::type::SASL_LIST_MECHANISMS_RESP));
        fail_negotiation();
        return;
    }

    std::string matched_mechanism = "";
    std::vector<std::string> server_supported_mechanisms;
    std::string resp_string = resp.msg;
    dsn::utils::split_args(resp_string.c_str(), server_supported_mechanisms, ',');

    for (const std::string &server_supported_mechanism : server_supported_mechanisms) {
        if (supported_mechanisms.find(server_supported_mechanism) != supported_mechanisms.end()) {
            ddebug_f("{}: found {} mechanism in server, use it", _name, server_supported_mechanism);
            matched_mechanism = server_supported_mechanism;
            break;
        }
    }

    if (matched_mechanism.empty()) {
        dwarn_f("server only support mechanisms of ({}), can't find expected ({})",
                resp_string,
                join(supported_mechanisms.begin(), supported_mechanisms.end(), ","));
        fail_negotiation();
        return;
    }

    select_mechanism(matched_mechanism);
}

void client_negotiation::select_mechanism(const std::string &mechanism)
{
    _selected_mechanism = mechanism;

    negotiation_request req;
    _status = req.status = negotiation_status::type::SASL_SELECT_MECHANISMS;
    req.msg = _selected_mechanism;

    send(req);
}

void client_negotiation::mechanism_selected(const negotiation_response &resp)
{
    if (resp.status == negotiation_status::type::SASL_SELECT_MECHANISMS_OK) {
        initiate_negotiation();
    } else {
        dwarn_f("{}: select mechanism({}) from server failed, type({}), reason({})",
                _name,
                _selected_mechanism,
                enum_to_string(resp.status),
                resp.msg);
        fail_negotiation();
    }
}

void client_negotiation::initiate_negotiation()
{
    error_s err_s = do_sasl_client_init();
    if (!err_s.is_ok()) {
        dassert_f(false,
                  "{}: initiaze sasl client failed, error = {}, reason = {}",
                  _name,
                  err_s.code().to_string(),
                  err_s.description());
        fail_negotiation();
        return;
    }

    err_s = send_sasl_initiate_msg();

    error_code code = err_s.code();
    const std::string &desc = err_s.description();

    if (code == ERR_AUTH_NEGO_FAILED && desc.find("Ticket expired") != std::string::npos) {
        derror_f("{}: start client negotiation with ticket expire, waiting on ticket renew", _name);
        fail_negotiation();
    } else if (code != ERR_OK && code != ERR_INCOMPLETE) {
        dassert_f(false,
                  "{}: client_negotiation: send sasl_client_start failed, error = {}, reason = {}",
                  _name,
                  code.to_string(),
                  desc);
        fail_negotiation();
    }
}

void client_negotiation::handle_challenge(const negotiation_response &challenge)
{
    /// TODO(zlw): delete
    if (challenge.status == negotiation_status::type::SASL_AUTH_FAIL) {
        dwarn_f("{}: auth failed, reason({})", _name, challenge.msg);
        fail_negotiation();
        return;
    }

    if (challenge.status == negotiation_status::type::SASL_CHALLENGE) {
        std::string response_msg;
        error_s err_s = do_sasl_step(challenge.msg, response_msg);
        if (err_s.code() != ERR_OK && err_s.code() != ERR_INCOMPLETE) {
            derror_f("{}: negotiation failed locally, reason = {}", _name, err_s.description());
            fail_negotiation();
            return;
        }

        negotiation_request request;
        _status = request.status = negotiation_status::type::SASL_CHANLLENGE_RESP;
        request.msg = response_msg;
        send(request);
        return;
    }

    if (challenge.status == negotiation_status::type::SASL_SUCC) {
        ddebug_f("{}: negotiation succ", _name);
        error_s err = retrive_user_name(_sasl_conn.get(), _user_name);
        dassert_f(err.is_ok(),
                  "{}: can't get user name for completed connection reason ({})",
                  _name,
                  err.description());
        succ_negotiation();
        return;
    }

    derror_f("{}: recv wrong negotiation msg, type = {}", _name, enum_to_string(challenge.status));
    fail_negotiation();
}

error_s client_negotiation::do_sasl_client_init()
{
    sasl_conn_t *conn = nullptr;
    error_s err_s = call_sasl_func(nullptr, [&]() {
        return sasl_client_new(get_service_name().c_str(),
                               get_service_fqdn().c_str(),
                               nullptr,
                               nullptr,
                               nullptr,
                               0,
                               &conn);
    });

    if (err_s.is_ok()) {
        _sasl_conn.reset(conn);
    }

    return err_s;
}

error_s client_negotiation::send_sasl_initiate_msg()
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    const char *client_mech = nullptr;

    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_client_start(
            _sasl_conn.get(), _selected_mechanism.c_str(), nullptr, &msg, &msg_len, &client_mech);
    });

    error_code code = err_s.code();
    if (code == ERR_OK || code == ERR_INCOMPLETE) {
        negotiation_request req;
        _status = req.status = negotiation_status::type::SASL_INITIATE;
        req.msg.assign(msg, msg_len);
        send(req);
    }

    return err_s;
}

error_s client_negotiation::do_sasl_step(const std::string &input, std::string &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_client_step(
            _sasl_conn.get(), input.c_str(), input.length(), nullptr, &msg, &msg_len);
    });

    output.assign(msg, msg_len);
    return err_s;
}

void client_negotiation::send(const negotiation_request &request)
{
    message_ptr msg = message_ex::create_request(RPC_NEGOTIATION);
    dsn::marshall(msg.get(), request);

    rpc_response_task_ptr t = rpc::create_rpc_response_task(
        msg, nullptr, [this](error_code err, negotiation_response response) {
            handle_response(err, std::move(response));
        });
    dsn_rpc_call(_session->remote_address(), t);
}

void client_negotiation::fail_negotiation()
{
    _status = negotiation_status::type::SASL_AUTH_FAIL;
    _session->complete_negotiation(false);
}

void client_negotiation::succ_negotiation()
{
    _status = negotiation_status::type::SASL_SUCC;
    _session->complete_negotiation(true);
}

} // namespace security
} // namespace dsn
