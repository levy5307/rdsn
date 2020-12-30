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

#include "server_negotiation.h"

#include <dsn/cpp/serverlet.h>

namespace dsn {
namespace security {

negotiation* get_negotiation(rpc_session *session);

class negotiation_manager : public serverlet<negotiation_manager>,
                            public utils::singleton<negotiation_manager>
{
public:
    void open_service();

private:
    negotiation_manager();
    void on_negotiation_request(negotiation_rpc rpc);

    friend class utils::singleton<negotiation_manager>;
    friend class negotiation_manager_test;
};

void init_join_point();
} // namespace security
} // namespace dsn
