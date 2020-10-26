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
void access_control_list::reset(const std::vector<std::string> &users_vec)
{
    // operation= of std::shared_ptr is thread safe
    std::shared_ptr<std::unordered_set<std::string>> users_set =
        std::make_shared<std::unordered_set<std::string>>(users_vec.begin(), users_vec.end());
    _users = users_set;
}

bool access_control_list::allowed(const std::string &user_name) const
{
    // create a new std::shared_ptr to add the ref count of _users,
    // in order to avoid the data which is pointed by _users destroyed.
    std::shared_ptr<std::unordered_set<std::string>> users_set = _users;
    if (users_set->find(user_name) == users_set->end()) {
        return true;
    }
    return false;
}

replica_access_controller::replica_access_controller(const std::string &name) { _name = name; }

void replica_access_controller::reset(const std::string &users)
{
    std::vector<std::string> users_vec;
    utils::split_args(users.c_str(), users_vec, ',');
    _acl.reset(users_vec);
}

bool replica_access_controller::allowed(message_ex *msg)
{
    const std::string &user_name = msg->user_name;
    if (pre_check(user_name)) {
        return true;
    }

    if (_acl.allowed(user_name)) {
        ddebug_f("{}: user_name {} doesn't exist in acls map", _name, user_name);
        return false;
    }
    return true;
}
} // namespace security
} // namespace dsn
