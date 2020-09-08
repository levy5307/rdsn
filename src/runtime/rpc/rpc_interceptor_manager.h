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

#include "rpc_interceptor.h"

#include <vector>
#include <memory>
#include <dsn/utility/singleton.h>

namespace dsn {

class rpc_interceptor_manager : public utils::singleton<rpc_interceptor_manager>
{
public:
    void add(std::unique_ptr<rpc_interceptor> interceptor);
    bool init();
    bool before();
    bool after();

private:
    rpc_interceptor_manager() = default;
    friend class utils::singleton<rpc_interceptor_manager>;

    std::vector<std::unique_ptr<rpc_interceptor>> _interceptors;
};

} // namespace dsn
