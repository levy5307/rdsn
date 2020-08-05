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

#include "server_negotiation.h"
#include "sasl_utils.h"

#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace security {
server_negotiation::server_negotiation(rpc_session *session) : negotiation(session) {}

void server_negotiation::start_negotiate()
{
    _status = negotiation_status::type::SASL_LIST_MECHANISMS;
    ddebug_f("{}: start negotiation", _name);
}

void server_negotiation::handle_message(message_ptr msg)
{
    if (_status == negotiation_status::type::SASL_LIST_MECHANISMS) {
        on_list_mechanisms(msg);
        return;
    }
    if (_status == negotiation_status::type::SASL_LIST_MECHANISMS_RESP) {
        on_select_mechanism(msg);
        return;
    }

    handle_client_response_on_challenge(msg);
}

void server_negotiation::reply(const message_ptr &req, const negotiation_message &response_data)
{
    message_ptr resp = req->create_response();
    strncpy(resp->header->server.error_name,
            ERR_OK.to_string(),
            sizeof(resp->header->server.error_name));
    resp->header->server.error_code.local_code = ERR_OK; // rpc is ok
    resp->header->server.error_code.local_hash = message_ex::s_local_hash;
    dsn::marshall(resp, response_data);

    _session->send_message(resp);
}

void server_negotiation::fail_negotiation(const message_ptr &req, const std::string &reason)
{
    negotiation_message response;
    _status = response.status = negotiation_status::type::SASL_AUTH_FAIL;
    response.msg = reason;
    reply(req, response);

    _session->complete_negotiation(false);
}

void server_negotiation::succ_negotiation(const message_ptr &req)
{
    negotiation_message response;
    _status = response.status = negotiation_status::type::SASL_SUCC;
    reply(req, response);

    _session->complete_negotiation(true);
}

void server_negotiation::on_list_mechanisms(const message_ptr &m)
{
    negotiation_message request;
    dsn::unmarshall(m, request);
    if (request.status == negotiation_status::type::SASL_LIST_MECHANISMS) {
        std::string mech_list = join(supported_mechanisms.begin(), supported_mechanisms.end(), ",");
        ddebug_f("{}: reply server mechs({})", _name, mech_list);
        negotiation_message response;
        _status = response.status = negotiation_status::type::SASL_LIST_MECHANISMS_RESP;
        response.msg = std::move(mech_list);
        reply(m, response);
    } else {
        dwarn_f("{}: got message({}) while expect({})",
                _name,
                enum_to_string(request.status),
                negotiation_status::type::SASL_LIST_MECHANISMS);
        fail_negotiation(m, "invalid_client_message_status");
    }
}

void server_negotiation::on_select_mechanism(const message_ptr &m)
{
    negotiation_message request;
    dsn::unmarshall(m, request);
    if (request.status == negotiation_status::type::SASL_SELECT_MECHANISMS) {
        _selected_mechanism = request.msg;
        ddebug_f("{}: client select mechanism({})", _name, _selected_mechanism);

        if (supported_mechanisms.find(_selected_mechanism) == supported_mechanisms.end()) {
            std::string error_msg =
                fmt::format("the mechanism of {} is not supported", _selected_mechanism);
            derror_f("{}", error_msg);
            fail_negotiation(m, error_msg);
        }

        error_s err_s = do_sasl_server_init();
        if (!err_s.is_ok()) {
            dwarn_f("{}: server initialize sasl failed, error = {}, msg = {}",
                    _name,
                    err_s.code().to_string(),
                    err_s.description());
            fail_negotiation(m, err_s.description());
            return;
        }

        negotiation_message response;
        _status = response.status = negotiation_status::type::SASL_SELECT_MECHANISMS_OK;
        reply(m, response);
    } else {
        dwarn_f("{}: got message({}) while expect({})",
                _name,
                enum_to_string(request.status),
                negotiation_status::type::SASL_SELECT_MECHANISMS);
        fail_negotiation(m, "invalid_client_message_status");
    }
}

error_s server_negotiation::do_sasl_server_init()
{
    sasl_conn_t *conn = nullptr;
    error_s err_s = call_sasl_func(nullptr, [&]() {
        return sasl_server_new(get_service_name().c_str(),
                               get_service_fqdn().c_str(),
                               nullptr,
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

error_s server_negotiation::do_sasl_server_start(const std::string &input, std::string &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_server_start(_sasl_conn.get(),
                                 _selected_mechanism.data(),
                                 input.data(),
                                 input.length(),
                                 &msg,
                                 &msg_len);
    });

    output.assign(msg, msg_len);
    return err_s;
}

error_s server_negotiation::do_sasl_step(const std::string &input, std::string &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_server_step(_sasl_conn.get(), input.data(), input.length(), &msg, &msg_len);
    });

    output.assign(msg, msg_len);
    return err_s;
}

void server_negotiation::handle_client_response_on_challenge(const message_ptr &req)
{
    dinfo_f("{}: recv response negotiation message from client", _name);
    negotiation_message client_message;
    dsn::unmarshall(req, client_message);

    if (client_message.status != negotiation_status::type::SASL_INITIATE &&
        client_message.status != negotiation_status::type::SASL_RESPONSE) {
        derror_f("{}: recv wrong negotiation msg, type = {}",
                 _name,
                 enum_to_string(client_message.status));
        fail_negotiation(req, "invalid_client_message_type");
        return;
    }

    std::string output;
    error_s err_s;
    if (client_message.status == negotiation_status::type::SASL_INITIATE) {
        err_s = do_sasl_server_start(client_message.msg, output);
    } else {
        err_s = do_sasl_step(client_message.msg, output);
    }

    if (err_s.code() != ERR_OK && err_s.code() != ERR_INCOMPLETE) {
        dwarn_f("{}: negotiation failed locally, with err = {}, msg = {}",
                _name,
                err_s.code().to_string(),
                err_s.description());
        fail_negotiation(req, err_s.description());
        return;
    }

    if (err_s.code() == ERR_OK) {
        error_s err = retrive_user_name(_sasl_conn.get(), _user_name);
        dassert_f(err.is_ok(), "{}: unexpected result({})", _name, err.description());
        ddebug_f("{}: negotiation succ for user({})", _name, _user_name);
        succ_negotiation(req);
    } else {
        negotiation_message challenge;
        _status = challenge.status = negotiation_status::type::SASL_CHALLENGE;
        challenge.msg = output;
        reply(req, challenge);
    }
}

} // namespace security
} // namespace dsn
