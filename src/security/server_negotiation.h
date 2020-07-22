// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include <security/negotiation_utils.h>

namespace dsn {
namespace security {

class server_negotiation
{
public:
    server_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_message_from_client(message_ptr msg);
    const char *user_name() const { return _user_name.c_str(); }
    bool negotiation_succeed() const { return _status == negotiation_status::type::SASL_SUCC; }

private:
    error_s do_sasl_server_init();
    error_s do_sasl_server_start(const blob &input, blob &output);
    error_s do_sasl_step(const blob &input, blob &output);
    error_s retrive_user_name_from_sasl_conn(std::string &output);

    void handle_client_response_on_challenge(const message_ptr &req);

    void on_list_mechanisms(const message_ptr &m);
    void on_select_mechanism(const message_ptr &m);

    void fail_negotiation(const message_ptr &req, dsn::string_view reason);
    void succ_negotiation(const message_ptr &req);

    void reply(const message_ptr &req, const negotiation_message &response_data);

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
