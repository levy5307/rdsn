// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.

#include "negotiation.h"

namespace dsn {
namespace security {
const std::set<std::string> supported_mechanisms{"GSSAPI"};

negotiation::~negotiation() {}
}
}
