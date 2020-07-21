// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#pragma once

#include <vector>
#include <cstdint>

namespace dsn {
namespace utils {

double mean_stddev(const std::vector<uint32_t> &result_set, bool partial_sample);

} // namespace utils
} // namespace dsn
