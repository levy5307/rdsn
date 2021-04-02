/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Microsoft Corporation
 *
 * -=- Robust Distributed System Nucleus (rDSN) -=-
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * Description:
 *     A greedy load balancer based on Dijkstra & Ford-Fulkerson
 *
 * Revision history:
 *     2016-02-03, Weijie Sun, first version
 */

#pragma once

#include <algorithm>
#include <functional>
#include "server_load_balancer.h"
#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace replication {

class greedy_load_balancer : public simple_load_balancer
{
public:
    explicit greedy_load_balancer(meta_service *svc);
    ~greedy_load_balancer() override;
    bool balance(meta_view view, migration_list &list) override;
    bool check(meta_view view, migration_list &list) override;
    void report(const migration_list &list, bool balance_checker) override;
    void score(meta_view view, double &primary_stddev, double &total_stddev) override;

    void register_ctrl_commands() override;
    void unregister_ctrl_commands() override;

    std::string get_balance_operation_count(const std::vector<std::string> &args) override;

private:
    enum class balance_type
    {
        move_primary,
        copy_primary,
        copy_secondary
    };

    enum operation_counters
    {
        MOVE_PRI_COUNT = 0,
        COPY_PRI_COUNT = 1,
        COPY_SEC_COUNT = 2,
        ALL_COUNT = 3,
        MAX_COUNT = 4
    };

    // these variables are temporarily assigned by interface "balance"
    const meta_view *t_global_view;
    migration_list *t_migration_result;
    int t_total_partitions;
    int t_alive_nodes;
    int t_operation_counters[MAX_COUNT];

    // this is used to assign an integer id for every node
    // and these are generated from the above data, which are tempory too
    std::unordered_map<dsn::rpc_address, int> address_id;
    std::vector<dsn::rpc_address> address_vec;

    // disk_tag -> targets(primaries/partitions)_on_this_disk
    typedef std::map<std::string, int> disk_load;

    // options
    bool _balancer_in_turn;
    bool _only_primary_balancer;
    bool _only_move_primary;
    bool _balance_cluster;

    // the app set which won't be re-balanced
    std::set<app_id> _balancer_ignored_apps;
    dsn::zrwlock_nr _balancer_ignored_apps_lock;

    dsn_handle_t _ctrl_balancer_ignored_apps;
    dsn_handle_t _ctrl_balancer_in_turn;
    dsn_handle_t _ctrl_only_primary_balancer;
    dsn_handle_t _ctrl_only_move_primary;
    dsn_handle_t _get_balance_operation_count;
    dsn_handle_t _ctrl_balance_cluster;

    // perf counters
    perf_counter_wrapper _balance_operation_count;
    perf_counter_wrapper _recent_balance_move_primary_count;
    perf_counter_wrapper _recent_balance_copy_primary_count;
    perf_counter_wrapper _recent_balance_copy_secondary_count;

private:
    void number_nodes(const node_mapper &nodes);
    void shortest_path(std::vector<bool> &visit,
                       std::vector<int> &flow,
                       std::vector<int> &prev,
                       std::vector<std::vector<int>> &network);

    // balance decision generators. All these functions try to make balance decisions
    // and store them to t_migration_result.
    //
    // return true if some decision is made, which means that these generators either put some
    // actions to the migration_list or don't take any action if they think the state is balanced.
    //
    // when return false, it means generators refuse to make decision coz
    // they think they need more informations.
    bool move_primary_based_on_flow_per_app(const std::shared_ptr<app_state> &app,
                                            const std::vector<int> &prev,
                                            const std::vector<int> &flow);
    bool copy_primary_per_app(const std::shared_ptr<app_state> &app,
                              bool still_have_less_than_average,
                              int replicas_low);
    bool primary_balancer_per_app(const std::shared_ptr<app_state> &app);

    bool copy_secondary_per_app(const std::shared_ptr<app_state> &app);

    void greedy_balancer(bool balance_checker);

    bool all_replica_infos_collected(const node_state &ns);
    // using t_global_view to get disk_tag of node's pid
    const std::string &get_disk_tag(const dsn::rpc_address &node, const dsn::gpid &pid);

    // return false if can't get the replica_info for some replicas on this node
    bool calc_disk_load(app_id id,
                        const dsn::rpc_address &node,
                        bool only_primary,
                        /*out*/ disk_load &load);
    void
    dump_disk_load(app_id id, const rpc_address &node, bool only_primary, const disk_load &load);

    std::shared_ptr<configuration_balancer_request>
    generate_balancer_request(const partition_configuration &pc,
                              const balance_type &type,
                              const rpc_address &from,
                              const rpc_address &to);

    std::string remote_command_balancer_ignored_app_ids(const std::vector<std::string> &args);
    std::string set_balancer_ignored_app_ids(const std::vector<std::string> &args);
    std::string get_balancer_ignored_app_ids();
    std::string clear_balancer_ignored_app_ids();

    bool is_ignored_app(app_id app_id);

    // ----------------------------------------------
    // TODO(heyuchen):
    enum class cluster_balance_type
    {
        kTotal = 0,
        kPrimary
    };

    struct AppMigrationInfo
    {
        int32_t app_id;
        std::string app_name;
        std::vector<std::map<rpc_address, partition_status::type>> partitions;
        std::map<rpc_address, int32_t> replicas_count;
        bool operator<(const AppMigrationInfo &another) const
        {
            if (app_id < another.app_id)
                return true;
            return false;
        }
        bool operator==(const AppMigrationInfo &another) const { return app_id == another.app_id; }
        partition_status::type get_partition_status(int32_t pidx, rpc_address addr)
        {
            for (const auto &kv : partitions[pidx]) {
                if (kv.first == addr) {
                    return kv.second;
                }
            }
            return partition_status::PS_INACTIVE;
        }
    };

    struct NodeMigrationInfo
    {
        rpc_address address;
        std::map<std::string, partition_set> partitions;
        partition_set future_partitions;
        bool operator<(const NodeMigrationInfo &another) const
        {
            if (address < another.address)
                return true;
            return false;
        }
        bool operator==(const NodeMigrationInfo &another) const
        {
            return address == another.address;
        }
    };

    struct ClusterMigrationInfo
    {
        cluster_balance_type type;
        std::map<int32_t, int32_t> apps_skew;
        std::map<int32_t, AppMigrationInfo> apps_info;
        std::map<rpc_address, NodeMigrationInfo> nodes_info;
        std::map<rpc_address, int32_t> replicas_count;
    };

    struct MoveInfo
    {
        gpid pid;
        rpc_address source_node;
        std::string source_disk_tag;
        rpc_address target_node;
        balance_type type;
    };

    bool total_replica_balance(const app_mapper &all_apps,
                               const node_mapper &nodes,
                               const cluster_balance_type type,
                               /*out*/ migration_list &list);
    bool get_cluster_migration_info(const app_mapper &all_apps,
                                    const node_mapper &nodes,
                                    const cluster_balance_type type,
                                    /*out*/ ClusterMigrationInfo &cluster_info);
    bool get_next_move(const ClusterMigrationInfo &cluster_info,
                       const partition_set &selected_pid,
                       /*out*/ MoveInfo &next_move);

    inline int32_t get_count(const node_state &ns, cluster_balance_type type, int32_t app_id)
    {
        unsigned count = 0;
        switch (type) {
        case cluster_balance_type::kTotal:
            if (app_id > 0) {
                count = ns.partition_count(app_id);
            } else {
                count = ns.partition_count();
            }
            break;
        case cluster_balance_type::kPrimary:
            if (app_id > 0) {
                count = ns.primary_count(app_id);
            } else {
                count = ns.primary_count();
            }
            break;
        default:
            break;
        }
        return (int32_t)count;
    }

    inline int32_t get_skew(const std::map<rpc_address, int32_t> &count_map)
    {
        int32_t min = INT_MAX, max = 0;
        for (const auto &kv : count_map) {
            if (kv.second < min) {
                min = kv.second;
            }
            if (kv.second > max) {
                max = kv.second;
            }
        }
        return max - min;
    }

    template <typename A, typename B>
    void flip_map(const std::map<A, B> &ori, /*out*/ std::multimap<B, A> &target)
    {
        std::transform(ori.begin(),
                       ori.end(),
                       std::inserter(target, target.begin()),
                       [](const std::pair<A, B> &p) { return std::pair<B, A>(p.second, p.first); });
    }

    void get_min_max_set(const std::map<rpc_address, int32_t> &node_count_map,
                         /*out*/ std::set<rpc_address> &min_set,
                         /*out*/ std::set<rpc_address> &max_set);

    template <typename A, typename B>
    void get_value_set(const std::multimap<A, B> &map_struct,
                       bool get_first,
                       /*out*/ std::set<B> &target_set)
    {
        auto value = get_first ? map_struct.begin()->first : map_struct.rbegin()->first;
        auto range = map_struct.equal_range(value);
        for (auto iter = range.first; iter != range.second; ++iter) {
            target_set.insert(iter->second);
        }
    }

    template <typename A>
    void get_intersection(const std::set<A> &set1,
                          const std::set<A> &set2,
                          /*out*/ std::set<A> &intersection)
    {
        std::set_intersection(set1.begin(),
                              set1.end(),
                              set2.begin(),
                              set2.end(),
                              std::inserter(intersection, intersection.begin()));
    }

    bool pick_up_move(const ClusterMigrationInfo &cluster_info,
                      const std::set<rpc_address> &max_nodes,
                      const std::set<rpc_address> &min_nodes,
                      const int32_t app_id,
                      const partition_set &selected_pid,
                      /*out*/ MoveInfo &move_info);

    bool get_max_load_disk(const ClusterMigrationInfo &cluster_info,
                           const std::set<rpc_address> &max_nodes,
                           const int32_t app_id,
                           /*out*/ rpc_address &picked_node,
                           /*out*/ std::string &picked_disk,
                           /*out*/ partition_set &target_partitions);

    void get_disk_partitions_map(const ClusterMigrationInfo &cluster_info,
                                 const rpc_address &addr,
                                 const int32_t app_id,
                                 /*out*/ std::map<std::string, partition_set> &disk_partitions);

    bool pick_up_partition(const ClusterMigrationInfo &cluster_info,
                           const rpc_address &min_node_addr,
                           const partition_set &max_load_partitions,
                           const partition_set &selected_pid,
                           /*out*/ gpid &picked_pid);

    bool apply_move(const MoveInfo &move,
                    /*out*/ partition_set &selected_pids,
                    /*out*/ migration_list &list,
                    /*out*/ ClusterMigrationInfo &cluster_info);

    bool move_primary_per_app(const std::shared_ptr<app_state> &app, const node_mapper &nodes);
};

inline configuration_proposal_action
new_proposal_action(const rpc_address &target, const rpc_address &node, config_type::type type)
{
    configuration_proposal_action act;
    act.__set_target(target);
    act.__set_node(node);
    act.__set_type(type);
    return act;
}

} // namespace replication
} // namespace dsn
