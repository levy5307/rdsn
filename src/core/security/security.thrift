include "../../dsn.thrift"

namespace cpp dsn.security

// negotiation process:
//
//                       client               server
//                          | --- SASL_MECH --> |
//                          | <-- SASL_MECH --- |
//                          | - SASL_SEL_MECH ->|
//                          | <- SASL_SEL_OK ---|
//                          |                   |
//                          | --- SASL_INIT --> |
//                          |                   |
//                          | <-- SASL_CHAL --- |
//                          | --- SASL_RESP --> |
//                          |                   |
//                          |      .....        |
//                          |                   |
//                          | <-- SASL_CHAL --- |
//                          | --- SASL_RESP --> |
//                          |                   | (authentication will succeed
//                          |                   |  if all chanllenges passed)
//                          | <-- NS_SUCC --- |
// (client won't response   |                   |
// if servers says ok)      |                   |
//                          | --- RPC_CALL ---> |
//                          | <-- RPC_RESP ---- |

enum negotiation_status {
    NS_INVALID = 0,
    NS_LIST_MECHANISMS,
    NS_LIST_MECHANISMS_RESP,
    NS_SELECT_MECHANISMS,
    NS_SELECT_MECHANISMS_OK,
    NS_INITIATE,
    NS_CHALLENGE,
    NS_RESPONSE,
    NS_SUCC,
    NS_FAIL
}

struct negotiation_message {
    1: negotiation_status status;
    2: dsn.blob msg;
}
