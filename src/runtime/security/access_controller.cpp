// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#include <runtime/security/access_controller.h>

#include <sstream>
#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace security {

const std::string access_controller::ACL_KEY = "acl";

void decode_and_insert(int app_id,
                       const std::string &acl_entries_str,
                       std::shared_ptr<acls_map> acls)
{
    if (acl_entries_str.empty()) {
        return;
    }

    std::unordered_map<std::string, std::string> app_acl;
    std::istringstream iss(acl_entries_str);
    std::string user_name, permission;
    while (getline(iss, user_name, ':')) {
        getline(iss, permission, ';');
        app_acl[user_name] = permission;
    }

    acls->insert(std::make_pair(app_id, app_acl));
}

access_controller::access_controller()
{
    // initial rpc permission template

    // 1.rpc_rrdb for replica
    register_entries({"RPC_RRDB_RRDB_GET",
                      "RPC_RRDB_RRDB_MULTI_GET",
                      "RPC_RRDB_RRDB_SORTKEY_COUNT",
                      "RPC_RRDB_RRDB_TTL",
                      "RPC_RRDB_RRDB_GET_SCANNER",
                      "RPC_RRDB_RRDB_SCAN",
                      "RPC_RRDB_RRDB_CLEAR_SCANNER"},
                     "10");

    register_entries({"RPC_RRDB_RRDB_PUT",
                      "RPC_RRDB_RRDB_MULTI_PUT",
                      "RPC_RRDB_RRDB_REMOVE",
                      "RPC_RRDB_RRDB_MULTI_REMOVE",
                      "RPC_RRDB_RRDB_INCR",
                      "RPC_RRDB_RRDB_CHECK_AND_SET",
                      "RPC_RRDB_RRDB_CHECK_AND_MUTATE"},
                     "11"); // Based on "writable always readable"

    // 2. meta
    register_allpass_entries({"RPC_CM_LIST_APPS",
                              "RPC_CM_LIST_NODES",
                              "RPC_CM_CLUSTER_INFO",
                              "RPC_CM_QUERY_PARTITION_CONFIG_BY_INDEX"});

    // 3. only superuser -- unregistered rpc_codes require superuser privileges

    // RPC_CM_QUERY_NODE_PARTITIONS
    // RPC_CM_CONFIG_SYNC
    // RPC_CM_UPDATE_PARTITION_CONFIGURATION
    // RPC_CM_CREATE_APP
    // RPC_CM_DROP_APP
    // RPC_CM_RECALL_APP
    // RPC_CM_CONTROL_META
    // RPC_CM_START_RECOVERY // CAUTION: only super user can do start recovery, do not register it
    // RPC_CM_START_RESTORE

    // RPC_CM_PROPOSE_BALANCER
    // RPC_CM_ADD_BACKUP_POLICY
    // RPC_CM_QUERY_BACKUP_POLICY
    // RPC_CM_MODIFY_BACKUP_POLICY

    // RPC_CM_REPORT_RESTORE_STATUS
    // RPC_CM_QUERY_RESTORE_STATUS
    // RPC_CM_ADD_DUPLICATION
    // RPC_CM_CHANGE_DUPLICATION_STATUS
    // RPC_CM_QUERY_DUPLICATION
    // RPC_CM_DUPLICATION_SYNC

    // RPC_CM_UPDATE_APP_ENV // CAUTION: only super user can update app env, if need register,
    // should reject unpermitted requests which want to update acl in app_envs
    // RPC_CM_DDD_DIAGNOSE
}

void access_controller::load_config(const std::string &super_user,
                                    const bool open_auth,
                                    const bool mandatory_auth)
{
    _super_user = super_user;
    _open_auth = open_auth;
    _mandatory_auth = mandatory_auth;
    ddebug_f("load superuser({}), open_auth({}), mandatory_auth({})",
             super_user,
             open_auth,
             mandatory_auth);
}

// for meta
bool access_controller::pre_check(const std::string &rpc_code, const std::string &user_name)
{
    if (!_open_auth || !_mandatory_auth || user_name == _super_user ||
        _all_pass.find(rpc_code) != _all_pass.end())
        return true;

    return false;
}

bool access_controller::cluster_level_check(const std::string &rpc_code,
                                            const std::string &user_name)
{
    // can't do cluster level check when using app_envs' acl
    ddebug("not implemented");
    return false;
}

bool access_controller::app_level_check(const std::string &rpc_code,
                                        const std::string &user_name,
                                        const std::string &acl_entries_str)
{
    auto mask_iter = _acl_masks.find(rpc_code);
    if (mask_iter == _acl_masks.end()) {
        ddebug_f("rpc_code {} is not registered", rpc_code);
        return false;
    }
    const auto &mask = mask_iter->second;

    auto user_pos = std::string::npos;
    if ((user_pos = acl_entries_str.find(user_name)) == std::string::npos) {
        ddebug_f("user_name {} doesn't exist in acl_entries_str", user_name);
        return false;
    }
    auto end = acl_entries_str.find(";", user_pos);
    auto permission_pos = user_pos + user_name.size() + 1;
    std::string permission_str = acl_entries_str.substr(permission_pos, end - permission_pos);
    auto permission =
        std::bitset<10>(permission_str); // CAUTION: only accept binary strings now, no decimal

    if ((permission & mask) == mask)
        return true;

    return false;
}

// for replica
bool access_controller::bit_check(const int app_id, const std::string &user_name, const acl_bit bit)
{
    if (!_open_auth || !_mandatory_auth || user_name == _super_user)
        return true;

    bool ret = false;

    auto app_acl = _cached_app_acls.find(app_id);
    if (app_acl == _cached_app_acls.end()) {
        ddebug_f("app_acl(id {}) is empty, acl deny", app_id);
    } else {
        auto entry = app_acl->second.find(user_name);
        if (entry == app_acl->second.end()) {
            ddebug_f("user_name {} doesn't exist in app_acl(id {})", user_name, app_id);
        } else {
            auto permission = entry->second;
            ret = std::bitset<10>(permission)[static_cast<int>(bit)];
        }
    }

    return ret;
}
} // namespace security
} // namespace dsn