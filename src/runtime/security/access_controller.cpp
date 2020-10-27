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

#include "access_controller.h"

#include <dsn/utility/flags.h>
#include <dsn/utility/smart_pointers.h>
#include "meta_access_controller.h"
#include "replica_access_controller.h"

namespace dsn {
namespace security {
DSN_DEFINE_bool("security", enable_access_control, false, "whether enable access control or not");
DSN_DEFINE_string("security", super_user, "", "super user for access controller");

access_controller::~access_controller() {}

bool access_controller::pre_check(const std::string &user_name)
{
    if (!FLAGS_enable_access_control || user_name == FLAGS_super_user) {
        return true;
    }
    return false;
}

std::unique_ptr<access_controller> create_access_controller(bool is_meta, std::string name)
{
    if (is_meta) {
        return make_unique<meta_access_controller>();
    } else {
        return make_unique<replica_access_controller>(name);
    }
}
} // namespace security
} // namespace dsn
