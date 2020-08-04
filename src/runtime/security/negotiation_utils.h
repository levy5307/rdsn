// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include "runtime/security/security_types.h"
#include <sasl/sasl.h>

namespace dsn {
namespace security {

struct sasl_deleter
{
    void operator()(sasl_conn_t *conn) { sasl_dispose(&conn); }
};

inline const char *enum_to_string(negotiation_status::type s)
{
    switch (s) {
    case negotiation_status::type::SASL_LIST_MECHANISMS:
        return "negotiation_list_mechanisms";
    case negotiation_status::type::SASL_LIST_MECHANISMS_RESP:
        return "negotiation_list_mechanisms_resp";
    case negotiation_status::type::SASL_SELECT_MECHANISMS:
        return "negotiation_select_mechanisms";
    case negotiation_status::type::SASL_SELECT_MECHANISMS_OK:
        return "negotiation_select_mechanisms_ok";
    case negotiation_status::type::SASL_SUCC:
        return "negotiation_succ";
    case negotiation_status::type::SASL_AUTH_FAIL:
        return "negotiation_auth_fail";
    case negotiation_status::type::SASL_INITIATE:
        return "negotiation_initiate";
    case negotiation_status::type::SASL_CHALLENGE:
        return "negotiation_challenge";
    case negotiation_status::type::SASL_RESPONSE:
        return "negotiation_response";
    case negotiation_status::type::INVALID:
        return "negotiation_invalid";
    }
    return "negotiation-unkown";
}

template <typename ForwardIterator>
std::string join(ForwardIterator begin, ForwardIterator end, const std::string &token)
{
    std::stringstream result;
    if (begin != end) {
        result << std::string(begin->data(), begin->size());
        ++begin;
    }
    while (begin != end) {
        result << token;
        result << std::string(begin->data(), begin->size());
        ++begin;
    }
    return result.str();
}

DEFINE_TASK_CODE_RPC(RPC_NEGOTIATION, TASK_PRIORITY_COMMON, dsn::THREAD_POOL_DEFAULT)

inline bool is_auth_nego_message(dsn::task_code code)
{
    return code == RPC_NEGOTIATION || code == RPC_NEGOTIATION_ACK;
}

inline bool is_negotiation_message(dsn::task_code code) { return is_auth_nego_message(code); }

} // namespace security
} // namespace dsn
