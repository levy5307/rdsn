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

#include "replica_access_controller.h"

#include <dsn/tool-api/rpc_message.h>
#include <dsn/utility/flags.h>
#include <dsn/dist/fmt_logging.h>
#include <bitset>

namespace dsn {
namespace security {
DSN_DECLARE_bool(mandatory_auth);
DSN_DECLARE_bool(enable_auth);
DSN_DECLARE_string(super_user);

void replica_access_controller::reset(const std::string &acls) {}

bool replica_access_controller::check(message_ex *msg, const acl_bit bit)
{
    const std::string &user_name = msg->user_name;
    if (!FLAGS_enable_auth || !FLAGS_mandatory_auth || user_name == FLAGS_super_user) {
        return true;
    }

    auto acl = _acls_map.find(user_name);
    if (acl == _acls_map.end()) {
        ddebug_f("user_name {} doesn't exist in acls_map", user_name);
    }

    return std::bitset<10>(acl->second)[static_cast<int>(bit)];
}
} // namespace security
} // namespace dsn
