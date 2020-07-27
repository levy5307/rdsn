// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#include "negotiation_manager.h"
#include "negotiation.h"
#include "rpc_codes.h"

namespace dsn {
namespace security {

negotiation_manager::negotiation_manager() : serverlet("negotiation_manager")
{
    this->register_rpc_handlers();
}

void negotiation_manager::on_negotiation(message_ex *msg)
{
    negotiation *neg = get_negotiation(msg->io_session);
    assert(neg != nullptr);
    neg->handle_message(msg);
}

void negotiation_manager::start_negotiation() { zauto_read_lock l(_negotiations_lock); }

negotiation *negotiation_manager::get_negotiation(rpc_session_ptr rpc_session)
{
    zauto_read_lock l(_negotiations_lock);
    if (_negotiations.find(rpc_session) != _negotiations.end()) {
        return _negotiations[rpc_session].get();
    }

    return nullptr;
}

void negotiation_manager::remove_negotiation(rpc_session_ptr rpc_session)
{
    zauto_write_lock l(_negotiations_lock);
    _negotiations.erase(rpc_session);
}

void negotiation_manager::register_rpc_handlers()
{
    register_rpc_handler(RPC_NEGOTIATION, "negotiation", &negotiation_manager::on_negotiation);
    register_rpc_handler(
        RPC_NEGOTIATION_ACK, "negotiation_ack", &negotiation_manager::on_negotiation);
}

} // namespace security
} // namespace dsn
