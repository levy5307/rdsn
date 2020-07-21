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

#include <dsn/security/security_types.h>
#include <dsn/security/sasl_utils.h>
#include <dsn/security/rpc_codes.h>
#include <dsn/tool-api/network.h>
#include <dsn/tool-api/rpc_message.h>

namespace dsn {
namespace security {

struct sasl_deleter
{
    void operator()(sasl_conn_t *conn) { sasl_dispose(&conn); }
};

inline const char *enum_to_string(negotiation_status s)
{
    switch (s) {
    case negotiation_status::NS_LIST_MECHANISMS:
        return "negotiation_list_mechanisms";
    case negotiation_status::NS_LIST_MECHANISMS_RESP:
        return "negotiation_list_mechanisms_resp";
    case negotiation_status::NS_SELECT_MECHANISMS:
        return "negotiation_select_mechanisms";
    case negotiation_status::NS_SELECT_MECHANISMS_OK:
        return "negotiation_select_mechanisms_ok";
    case negotiation_status::NS_SUCC:
        return "negotiation_succ";
    case negotiation_status::NS_FAIL:
        return "negotiation_auth_fail";
    case negotiation_status::NS_INITIATE:
        return "negotiation_initiate";
    case negotiation_status::NS_CHALLENGE:
        return "negotiation_challenge";
    case negotiation_status::NS_RESPONSE:
        return "negotiation_response";
    case negotiation_status::NS_INVALID:
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

} // end namespace security
} // end namespace dsn
