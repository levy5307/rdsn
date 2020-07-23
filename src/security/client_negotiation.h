// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include <security/negotiation_utils.h>
#include <dsn/utility/errors.h>
#include "negotiation.h"

namespace dsn {
namespace security {

class client_negotiation : public negotiation
{
public:
    client_negotiation(rpc_session *session);
    void start_negotiate();
    void handle_message(message_ptr msg);

private:
    void list_mechanisms();
    void recv_mechanisms(const message_ptr &mechs_msg);
    void select_mechanism(dsn::string_view mech);
    void mechanism_selected(const message_ptr &mechs_msg);
    void initiate_negotiation();
    void handle_challenge(const message_ptr &challenge_msg);

    error_s do_sasl_client_init();
    error_s send_sasl_initiate_msg();
    error_s do_sasl_step(const blob &input, blob &output);

    void send(const negotiation_message &n);
    void fail_negotiation();
    void succ_negotiation();

private:
    // for logging
    std::string _name;
    std::string _selected_mechanism;
    std::unique_ptr<sasl_conn_t, sasl_deleter> _sasl_conn;
};

} // namespace security
} // namespace dsn
