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

#include <dsn/c/api_common.h>
#include "meta_data.h"

namespace dsn {
namespace replication {

class meta_service;

class partition_healer
{
public:
    template <typename T>
    static partition_healer *create(meta_service *svc)
    {
        return new T(svc);
    }
    typedef partition_healer *(*factory)(meta_service *svc);

public:
    explicit partition_healer(meta_service *svc);
    virtual ~partition_healer();

    void reconfig(meta_view view, const configuration_update_request &request);
    virtual pc_status cure(meta_view view, const dsn::gpid &gpid, configuration_proposal_action &action);

    //
    // When replica infos are collected from replica servers, meta-server
    // will use this to check if a replica on a server is useful
    // params:
    //   node: the owner of the replica info
    //   info: the replica info on node
    // ret:
    //   return true if the replica is accepted as an useful replica. Or-else false.
    //   WARNING: if false is returned, the replica on node may be garbage-collected
    //
    virtual bool collect_replica(meta_view view, const rpc_address &node, const replica_info &info);
    //
    // Try to construct a replica-group by current replica-infos of a gpid
    // ret:
    //   if construct the replica successfully, return true.
    //   Notice: as long as we can construct something from current infos, we treat it as a
    //   success
    //
    virtual bool construct_replica(meta_view view, const gpid &pid, int max_replica_count);
    void register_ctrl_commands();
    void unregister_ctrl_commands();

    void get_ddd_partitions(gpid pid, std::vector<ddd_partition_info> &partitions);
    void clear_ddd_partitions();

    bool from_proposals(meta_view &view, const dsn::gpid &gpid, configuration_proposal_action &action);

private:
    // if a proposal is generated by cure, meta will record the POSSIBLE PARTITION COUNT
    // IN FUTURE of a node with module "newly_partitions".
    // the side effect should be eliminated when a proposal is finished, no matter
    // successfully or unsuccessfully
    void finish_cure_proposal(meta_view &view,
                              const dsn::gpid &gpid,
                              const configuration_proposal_action &action);
    pc_status on_missing_primary(meta_view &view, const dsn::gpid &gpid);
    pc_status on_missing_secondary(meta_view &view, const dsn::gpid &gpid);
    pc_status on_redundant_secondary(meta_view &view, const dsn::gpid &gpid);

    bool in_black_list(dsn::rpc_address addr)
    {
        dsn::zauto_read_lock l(_black_list_lock);
        return _assign_secondary_black_list.count(addr) != 0;
    }

    void set_ddd_partition(ddd_partition_info &&partition);

    std::string ctrl_assign_delay_ms(const std::vector<std::string> &args);
    std::string ctrl_assign_secondary_black_list(const std::vector<std::string> &args);

    meta_service *_svc;
    dsn_handle_t _ctrl_assign_delay_ms;
    int32_t _mutation_2pc_min_replica_count;
    uint64_t _replica_assign_delay_ms_for_dropouts;

    perf_counter_wrapper _recent_choose_primary_fail_count;

    dsn_handle_t _ctrl_assign_secondary_black_list;
    // NOTICE: the command handler is called in THREADPOOL_DEFAULT
    // but when adding secondary, the black list is accessed in THREADPOOL_META_STATE
    // so we need a lock to protect it
    dsn::zrwlock_nr _black_list_lock;
    std::set<dsn::rpc_address> _assign_secondary_black_list;

    mutable zlock _ddd_partitions_lock;
    std::map<gpid, ddd_partition_info> _ddd_partitions;
};
} // namespace replication
} // namespace dsn
