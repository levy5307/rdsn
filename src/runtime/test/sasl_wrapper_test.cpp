//
// Created by mi on 2020/9/7.
//

#include "runtime/security/sasl_wrapper.h"

#include <gtest/gtest.h>
#include <dsn/dist/fmt_logging.h>

namespace dsn {
namespace security {
class sasl_wrapper_test : public testing::Test {

};

TEST_F(sasl_wrapper_test, sasl_wrapper_test) {
    std::unique_ptr<sasl_wrapper> wrapper = create_sasl_wrapper(true);
    error_s err_s = wrapper->init();
    dassert(err_s.is_ok(), "error is ok");

    std::string output;
    err_s = wrapper->start("GSSAPI", "", output);
    ddebug_f("output = {}", output);
    dassert(err_s.is_ok() || ERR_SASL_INCOMPLETE == err_s.code(), "error is ok or incomplete");
}
}
}
