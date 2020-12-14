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

#include <dsn/http/http_server.h>
#include <dsn/utility/flags.h>
#include <dsn/utility/output_utils.h>

namespace dsn {
void update_config(const http_request &req, http_response &resp)
{
    if (req.query_args.size() != 1) {
        resp.status_code = http_status_code::bad_request;
        return;
    }

    auto iter = req.query_args.begin();
    auto res = update_flag(iter->first.c_str(), iter->second.c_str());

    utils::table_printer tp;
    tp.add_row_name_and_data("update_status", res.description());
    std::ostringstream out;
    tp.output(out, dsn::utils::table_printer::output_format::kJsonCompact);
    resp.body = out.str();
    resp.status_code = http_status_code::ok;
}

void list_all_configs(const http_request &req, http_response &resp)
{
    if (req.query_args.size() != 0) {
        resp.status_code = http_status_code::bad_request;
        return;
    }

    /**
    dsn::utils::table_printer tp("all_configs");
    tp.add_title("name");
    tp.add_column("section");
    tp.add_column("type");
    tp.add_column("value");
    tp.add_column("tags");
    tp.add_column("description");
    for (const auto &flag : all_flags) {
        tp.append_data(flag.first);
        tp.append_data(flag.second.section());
        tp.append_data(flag.second.type());
        tp.append_data(flag.second.const_value<int>());

        std::string tags_str;
        const auto &tags = flag.second.tags();
        for (const auto &tag : tags) {
            tags_str += tag;
        }
        tp.append_data(tags_str);
    }

    std::ostringstream out;
    tp.output(out, utils::table_printer::output_format::kJsonCompact);
    resp.body = out.str();
    resp.status_code = http_status_code::ok;
    */
}
} // namespace dsn
