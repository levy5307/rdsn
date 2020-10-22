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
#include <dsn/dist/fmt_logging.h>
#include <bitset>

namespace dsn {
namespace security {
replica_access_controller::replica_access_controller(const std::string &name) { _name = name; }

void replica_access_controller::reset(const std::string &users)
{
    std::istringstream iss(users);
    std::string user_name;
    std::unordered_set<std::string> temp_users;
    while (getline(iss, user_name, ',')) {
        temp_users.insert(user_name);
    }

    {
        // This swap operation is in constant time
        utils::auto_write_lock l(_lock);
        _users.swap(temp_users);
    }
}

bool replica_access_controller::check(message_ex *msg)
{
    const std::string &user_name = msg->user_name;
    if (pre_check(user_name)) {
        return true;
    }

    {
        utils::auto_read_lock l(_lock);
        if (_users.find(user_name) == _users.end()) {
            ddebug_f("{}: user_name {} doesn't exist in acls_map of", _name, user_name);
            return false;
        }
        return true;
    }
}
} // namespace security
} // namespace dsn
