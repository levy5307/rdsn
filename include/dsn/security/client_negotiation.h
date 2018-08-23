/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Microsoft Corporation
 *
 * -=- Robust Distributed System Nucleus (rDSN) -=-
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once

#include <dsn/security/negotiation_utils.h>

namespace dsn {
namespace security {

class client_negotiation
{
public:
    client_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_message_from_server(message_ptr msg);
    const char *user_name() const { return _user_name.c_str(); }
    bool negotiation_succeed() const { return negotiation_status::SASL_SUCC == _status; }

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

} // end namespace security
} // end namespace dsn
