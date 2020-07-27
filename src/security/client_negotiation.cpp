// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#include "rpc_codes.h"
#include <dsn/tool-api/rpc_address.h>
#include <security/init.h>
#include <security/client_negotiation.h>
#include <security/sasl_utils.h>
#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace security {

client_negotiation::client_negotiation(rpc_session *session) : negotiation(), _session(session)
{
    _name = fmt::format("C_NEGO_L({})=>R({})",
                        dsn_primary_address().to_string(),
                        _session->remote_address().to_string());
}

void client_negotiation::start_negotiate()
{
    ddebug_f("{}: start negotiation", _name);
    list_mechanisms();
}

void client_negotiation::handle_message(message_ex *msg)
{
    if (msg->error() == ERR_HANDLER_NOT_FOUND && !_session->mandantory_auth()) {
        dwarn_f("{}: treat negotiation succeed as server doesn't support it, user_name in later "
                "messages aren't trustable",
                _name);
        succ_negotiation();
        return;
    }
    if (msg->error() != ERR_OK) {
        derror_f("{}: negotiation failed, error = {}", _name, msg->error().to_string());
        fail_negotiation();
        return;
    }
    if (_status == negotiation_status::type::SASL_LIST_MECHANISMS) {
        recv_mechanisms(msg);
        return;
    }
    if (_status == negotiation_status::type::SASL_SELECT_MECHANISMS) {
        mechanism_selected(msg);
        return;
    }
    handle_challenge(msg);
}

void client_negotiation::list_mechanisms()
{
    negotiation_message req;
    req.status = negotiation_status::type::SASL_LIST_MECHANISMS;
    send(req);
}

void client_negotiation::recv_mechanisms(message_ex *mechs_msg)
{
    negotiation_message resp;
    dsn::unmarshall(mechs_msg, resp);

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
    std::string resp_string = resp.msg.to_string();
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

void client_negotiation::select_mechanism(dsn::string_view mech)
{
    _selected_mechanism.assign(mech.data(), mech.length());

    negotiation_message req;
    req.status = negotiation_status::type::SASL_SELECT_MECHANISMS;
    req.msg = dsn::blob::create_from_bytes(mech.data(), mech.length());

    send(req);
}

void client_negotiation::mechanism_selected(message_ex *mechs_msg)
{
    negotiation_message resp;
    dsn::unmarshall(mechs_msg, resp);
    if (resp.status == negotiation_status::type::SASL_SELECT_MECHANISMS_OK) {
        initiate_negotiation();
    } else {
        dwarn_f("{}: select mechanism({}) from server failed, type({}), reason({})",
                _name,
                _selected_mechanism,
                enum_to_string(resp.status),
                resp.msg.to_string());
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

void client_negotiation::handle_challenge(message_ex *challenge_msg)
{
    negotiation_message challenge;
    dsn::unmarshall(challenge_msg, challenge);

    if (challenge.status == negotiation_status::type::SASL_AUTH_FAIL) {
        dwarn_f("{}: auth failed, reason({})", _name, challenge.msg.to_string());
        fail_negotiation();
        return;
    }

    if (challenge.status == negotiation_status::type::SASL_CHALLENGE) {
        dsn::blob response_msg;
        error_s err_s = do_sasl_step(challenge.msg, response_msg);
        if (err_s.code() != ERR_OK && err_s.code() != ERR_INCOMPLETE) {
            derror_f("{}: negotiation failed locally, reason = {}", _name, err_s.description());
            fail_negotiation();
            return;
        }

        negotiation_message resp;
        resp.status = negotiation_status::type::SASL_RESPONSE;
        resp.msg = response_msg;
        send(resp);
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
            _sasl_conn.get(), _selected_mechanism.data(), nullptr, &msg, &msg_len, &client_mech);
    });

    error_code code = err_s.code();
    if (code == ERR_OK || code == ERR_INCOMPLETE) {
        negotiation_message req;
        req.status = negotiation_status::type::SASL_INITIATE;
        req.msg = dsn::blob::create_from_bytes(msg, msg_len);
        send(req);
    }

    return err_s;
}

error_s client_negotiation::do_sasl_step(const dsn::blob &input, blob &output)
{
    const char *msg = nullptr;
    unsigned msg_len = 0;
    error_s err_s = call_sasl_func(_sasl_conn.get(), [&]() {
        return sasl_client_step(
            _sasl_conn.get(), input.data(), input.length(), nullptr, &msg, &msg_len);
    });

    output = dsn::blob::create_from_bytes(msg, msg_len);
    return err_s;
}

void client_negotiation::send(const negotiation_message &n)
{
    _status = n.status;
    message_ptr msg = message_ex::create_request(RPC_NEGOTIATION);
    dsn::marshall(msg.get(), n);
    _session->send_message(msg.get());
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
