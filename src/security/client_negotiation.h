// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include <security/negotiation_utils.h>

namespace dsn {
namespace security {

class client_negotiation
{
public:
    client_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_message_from_server(message_ptr msg);
    const char *user_name() const { return _user_name.c_str(); }
    bool negotiation_succeed() const { return negotiation_status::type::SASL_SUCC == _status; }

private:
    void initiate_negotiation();
    error_s do_sasl_client_init();
    error_s send_sasl_initiate_msg();
    error_s do_sasl_step(const blob &input, blob &output);
    error_s retrive_user_name_from_sasl_conn(std::string &output);
    void handle_challenge(const message_ptr &challenge_msg);

    void list_mechanisms();
    void recv_mechanisms(const message_ptr &mechs_msg);

    void select_mechanism(dsn::string_view mech);
    void mechanism_selected(const message_ptr &mechs_msg);

    void send(const negotiation_message &n);
    void fail_negotiation();
    void succ_negotiation();

private:
    // the lifetime of _session should be longer than client_negotiation
    rpc_session *_session;
    // for logging
    std::string _name;

    std::string _user_name;
    std::unique_ptr<sasl_conn_t, sasl_deleter> _sasl_conn;

    negotiation_status::type _status;
    std::string _selected_mechanism;
};

} // namespace security
} // namespace dsn
