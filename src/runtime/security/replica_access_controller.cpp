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

namespace dsn {
namespace security {
replica_access_controller::replica_access_controller(const std::string &name) { _name = name; }

void replica_access_controller::reset(const std::string &users)
{
    {
        // check to see whether we should update it or not.
        utils::auto_read_lock l(_lock);
        if (_env_users == users) {
            return;
        }
    }

    std::vector<std::string> users_vec;
    utils::split_args(users.c_str(), users_vec, ',');
    std::unordered_set<std::string> users_set(users_vec.begin(), users_vec.end());

    {
        utils::auto_write_lock l(_lock);
        // This swap operation is in constant time
        _users.swap(users_set);
        _env_users = users;
    }
}

bool replica_access_controller::allowed(message_ex *msg)
{
    const std::string &user_name = msg->user_name;
    if (pre_check(user_name)) {
        return true;
    }

    {
        utils::auto_read_lock l(_lock);
        if (_users.find(user_name) == _users.end()) {
            ddebug_f("{}: user_name {} doesn't exist in acls map", _name, user_name);
            return false;
        }
        return true;
    }
}
} // namespace security
} // namespace dsn
