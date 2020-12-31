// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "negotiation.h"
#include "client_negotiation.h"
#include "server_negotiation.h"
#include "negotiation_utils.h"

#include <dsn/utility/flags.h>
#include <dsn/utility/smart_pointers.h>
#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace security {
/// TODO(zlw):we can't get string list from cflags now,
/// so we should get supported mechanisms from config in the later
const std::set<std::string> supported_mechanisms{"GSSAPI"};

DSN_DEFINE_bool("security", enable_auth, false, "whether open auth or not");
DSN_DEFINE_bool("security", mandatory_auth, false, "wheter to do authertication mandatorily");
DSN_TAG_VARIABLE(mandatory_auth, FT_MUTABLE);

negotiation::~negotiation() {
    clear_pending_messages();
}

negotiation *create_negotiation(rpc_session *session)
{
    if (session->is_client()) {
        return new client_negotiation(session);
    } else {
        return new server_negotiation(session);
    }
}

void negotiation::fail_negotiation()
{
    _status = negotiation_status::type::SASL_AUTH_FAIL;
    _session->on_failure(true);
}

bool negotiation::check_status(negotiation_status::type status,
                               negotiation_status::type expected_status)
{
    if (status != expected_status) {
        dwarn_f("{}: get message({}) while expect({})",
                _name,
                enum_to_string(status),
                enum_to_string(expected_status));
        return false;
    }

    return true;
}

bool negotiation::try_pend_message(message_ex *msg)
{
    // we should pend msg if negotiation is not succeed,
    // in order to resend it when the negotiation is succeed
    if (dsn_unlikely(_status != negotiation_status::type::SASL_SUCC)) {
        utils::auto_lock<utils::ex_lock_nr> l(_lock);
        if (_status != negotiation_status::type::SASL_SUCC) {
            msg->add_ref();
            _pending_messages.push_back(msg);
            return true;
        }
    }
    return false;
}

void negotiation::clear_pending_messages()
{
    utils::auto_lock<utils::ex_lock_nr> l(_lock);
    for (auto msg : _pending_messages) {
        msg->release_ref();
    }
    _pending_messages.clear();
}

void negotiation::set_succeed()
{
    std::vector<message_ex *> swapped_pending_msgs;
    {
        utils::auto_lock<utils::ex_lock_nr> l(_lock);
        _status = negotiation_status::type::SASL_SUCC;
        _pending_messages.swap(swapped_pending_msgs);
    }

    // resend the pending messages
    for (auto msg : swapped_pending_msgs) {
        _session->send_message(msg);
        msg->release_ref();
    }
}
} // namespace security
} // namespace dsn
