// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include "negotiation.h"
#include <security/negotiation_utils.h>
#include <dsn/utility/errors.h>

namespace dsn {
namespace security {

class server_negotiation : public negotiation
{
public:
    server_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_message(message_ex *msg);

private:
    void handle_client_response_on_challenge(message_ex *req);
    void on_list_mechanisms(message_ex *m);
    void on_select_mechanism(message_ex *m);

    error_s do_sasl_server_init();
    error_s do_sasl_server_start(const blob &input, blob &output);
    error_s do_sasl_step(const blob &input, blob &output);

    void fail_negotiation(message_ex *req, dsn::string_view reason);
    void succ_negotiation(message_ex *req);
    void reply(message_ex *req, const negotiation_message &response_data);

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
