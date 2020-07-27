// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include <dsn/cpp/serverlet.h>
#include <dsn/tool-api/zlocks.h>
#include "security_types.h"

namespace dsn {
namespace security {

typedef rpc_holder<negotiation_message, negotiation_message> negotiation_rpc;

class negotiation_manager : public serverlet<negotiation_manager> {
public:
    negotiation_manager();
    void on_negotiation(negotiation_rpc rpc);
    void start_negotiation();
    negotiation* get_negotiation(rpc_session_ptr rpc_session);
    void remove_negotiation(rpc_session_ptr rpc_session);

private:
    void register_rpc_handlers();

    mutable zrwlock_nr _negotiations_lock;
    std::map<rpc_session_ptr, std::unique_ptr<negotiation>> _negotiations;
};

} // namespace security
} // namespace dsn
