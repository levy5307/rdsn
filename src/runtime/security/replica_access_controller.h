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

#pragma once

#include <dsn/utility/synchronize.h>
#include "access_controller.h"

namespace dsn {
namespace security {
struct access_controller_data
{
    void reset(const std::vector<std::string> &users_vec)
    {
        // operation= of std::shared_ptr is thread safe
        std::shared_ptr<std::unordered_set<std::string>> users_set =
            std::make_shared<std::unordered_set<std::string>>(users_vec.begin(), users_vec.end());
        _data = users_set;
    }

    bool find(const std::string &user_name) const
    {
        // create a new std::shared_ptr to add the ref count of _data,
        // in order to avoid the data which is pointed by _data destroyed.
        std::shared_ptr<std::unordered_set<std::string>> users_set = _data;
        if (users_set->find(user_name) == users_set->end()) {
            return true;
        }
        return false;
    }

    std::shared_ptr<std::unordered_set<std::string>> _data;
};

class replica_access_controller : public access_controller
{
public:
    replica_access_controller(const std::string &name);
    void reset(const std::string &users);
    bool check(message_ex *msg);

private:
    access_controller_data _users;
    std::string _name;
};
} // namespace security
} // namespace dsn
