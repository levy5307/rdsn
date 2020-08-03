// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include "security_types.h"
#include <dsn/utility/errors.h>
#include <dsn/tool-api/rpc_message.h>

namespace dsn {
namespace security {
extern const std::set<std::string> supported_mechanisms;

class negotiation
{
public:
    negotiation() : _user_name("unknown"), _status(negotiation_status::type::INVALID) {}
    virtual ~negotiation() = 0;

    virtual void start_negotiate() = 0;
    virtual void handle_message(message_ptr msg) = 0;
    const char *user_name() const { return _user_name.c_str(); }
    bool negotiation_succeed() const { return _status == negotiation_status::type::SASL_SUCC; }

protected:
    std::string _user_name;
    negotiation_status::type _status;
};

std::unique_ptr<negotiation> create_negotiation(bool is_client, rpc_session *session);

} // namespace security
} // namespace dsn