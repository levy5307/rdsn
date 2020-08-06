// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#include "sasl_utils.h"

#include <dsn/c/api_utilities.h>
#include <dsn/utility/config_api.h>
#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace security {

// use anonymous to define client/server callback
namespace {

const char *logger_level_to_string(int level)
{
    switch (level) {
    case SASL_LOG_NONE:
        return "SASL_LOG_NONE";
    case SASL_LOG_ERR:
        return "SASL_LOG_ERR";
    case SASL_LOG_FAIL:
        return "SASL_LOG_FAIL";
    case SASL_LOG_WARN:
        return "SASL_LOG_WARN";
    case SASL_LOG_NOTE:
        return "SASL_LOG_NOTE";
    case SASL_LOG_DEBUG:
        return "SASL_LOG_DEBUG";
    case SASL_LOG_TRACE:
        return "SASL_LOG_TRACE";
    case SASL_LOG_PASS:
        return "SASL_LOG_PASS";
    default:
        return "Unkown SASL log level";
    }
}

static const char *plugins_search_path = nullptr;

int sasl_simple_logger(void *context, int level, const char *msg)
{
    // TODO: we can set a level to print sasl log info
    if (level == SASL_LOG_NONE || nullptr == msg) {
        return SASL_OK;
    }

    ddebug_f("sasl log info: log level = {}, message = {}", logger_level_to_string(level), msg);
    return SASL_OK;
}

int getpath(void *context, char **path)
{
    if (nullptr == path) {
        return SASL_BADPARAM;
    }
    *path = const_cast<char *>(plugins_search_path);
    return SASL_OK;
}

int simple(void *context, int id, const char **result, unsigned *len)
{
    if (nullptr == result) {
        return SASL_BADPARAM;
    }
    static std::string username = get_username();
    switch (id) {
    case SASL_CB_USER:
    case SASL_CB_AUTHNAME:
        *result = username.c_str();
        if (len != nullptr) {
            *len = username.length();
        }
        return SASL_OK;
    case SASL_CB_LANGUAGE:
        derror("could handle SASL callback type SASL_CB_LANGUAGE");
        return SASL_BADPARAM;
    default:
        dassert_f(false, "unexpected SASL callback type: {}", id);
        return SASL_BADPARAM;
    }
}

sasl_callback_t client_callbacks[] = {{SASL_CB_USER, (sasl_callback_ft)&simple, nullptr},
                                      {SASL_CB_GETPATH, (sasl_callback_ft)&getpath, nullptr},
                                      {SASL_CB_AUTHNAME, (sasl_callback_ft)&simple, nullptr},
                                      {SASL_CB_LOG, (sasl_callback_ft)&sasl_simple_logger, nullptr},
                                      {SASL_CB_LIST_END, nullptr, nullptr}};

sasl_callback_t server_callbacks[] = {{SASL_CB_LOG, (sasl_callback_ft)&sasl_simple_logger, nullptr},
                                      {SASL_CB_GETPATH, (sasl_callback_ft)&getpath, nullptr},
                                      {SASL_CB_LIST_END, nullptr, nullptr}};

// provide mutex function for sasl
void *sasl_mutex_alloc_local() { return static_cast<void *>(new utils::ex_lock_nr); }

void sasl_mutex_free_local(void *m) { delete static_cast<utils::ex_lock_nr *>(m); }

int sasl_mutex_lock_local(void *m)
{
    static_cast<utils::ex_lock_nr *>(m)->lock();
    return 0;
}

int sasl_mutex_unlock_local(void *m)
{
    static_cast<utils::ex_lock_nr *>(m)->unlock();
    return 0;
}

void sasl_set_mutex_local()
{
    sasl_set_mutex(&sasl_mutex_alloc_local,
                   &sasl_mutex_lock_local,
                   &sasl_mutex_unlock_local,
                   &sasl_mutex_free_local);
}

const char *sasl_err_desc(int status, sasl_conn_t *conn)
{
    if (conn != nullptr) {
        return sasl_errdetail(conn);
    } else {
        return sasl_errstring(status, nullptr, nullptr);
    }
}

} // end anonymous namespace

error_s call_sasl_func(sasl_conn_t *conn, const std::function<int()> &call)
{
    krb5_cred_lock().lock_read();
    int err = call();
    krb5_cred_lock().unlock_read();
    error_s ret;
    switch (err) {
    case SASL_OK:
        return error_s::make(ERR_OK);
    case SASL_CONTINUE:
        return error_s::make(ERR_INCOMPLETE);
    case SASL_FAIL:      // Generic failure (encompasses missing krb5 credentials).
    case SASL_BADAUTH:   // Authentication failure.
    case SASL_BADMAC:    // Decode failure.
    case SASL_NOAUTHZ:   // Authorization failure.
    case SASL_NOUSER:    // User not found.
    case SASL_WRONGMECH: // Server doesn't support requested mechanism.
    case SASL_BADSERV: { // Server failed mutual authentication.
        ret = error_s::make(ERR_AUTH_NEGO_FAILED);
        ret << "sasl auth failed, error: " << sasl_err_desc(err, conn);
        break;
    }
    default:
        ret = error_s::make(ERR_UNKNOWN);
        break;
    }
    return ret;
}

error_s sasl_init(bool is_server)
{
    plugins_search_path = dsn_config_get_value_string(
        "security", "sasl_plugin_path", "/usr/lib/sasl2", "path to search sasl plugins");
    sasl_set_mutex_local();
    int err = 0;
    err = sasl_client_init(&client_callbacks[0]);
    error_s ret = error_s::make(ERR_OK);
    if (err != SASL_OK) {
        ret = error_s::make(ERR_RUNTIME_ERROR);
        ret << "initialize sasl client failed with error: "
            << sasl_errstring(err, nullptr, nullptr);
        return ret;
    }
    if (is_server) {
        // TODO: find a better saslappname
        err = sasl_server_init(&server_callbacks[0], "pegasus");
        if (err != SASL_OK) {
            ret = error_s::make(ERR_RUNTIME_ERROR);
            ret << "initialize sasl server failed with error: "
                << sasl_errstring(err, nullptr, nullptr);
            return ret;
        }
    }
    return ret;
}

error_s retrive_user_name(sasl_conn_t *sasl_conn, std::string &output)
{
    char *username = nullptr;
    error_s err_s = call_sasl_func(sasl_conn, [&]() {
        return sasl_getprop(sasl_conn, SASL_USERNAME, (const void **)&username);
    });

    if (err_s.is_ok()) {
        output = username;
        output = output.substr(0, output.find_last_of('@'));
        output = output.substr(0, output.find_first_of('/'));
    }
    return err_s;
}
} // namespace security
} // namespace dsn
