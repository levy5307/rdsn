/**
 * Autogenerated by Thrift Compiler (0.9.3)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#include "security_types.h"

#include <algorithm>
#include <ostream>

#include <thrift/TToString.h>

namespace dsn {
namespace security {

int _knegotiation_statusValues[] = {negotiation_status::INVALID,
                                    negotiation_status::SASL_LIST_MECHANISMS,
                                    negotiation_status::SASL_LIST_MECHANISMS_RESP,
                                    negotiation_status::SASL_SELECT_MECHANISMS,
                                    negotiation_status::SASL_SELECT_MECHANISMS_OK,
                                    negotiation_status::SASL_INITIATE,
                                    negotiation_status::SASL_CHALLENGE,
                                    negotiation_status::SASL_RESPONSE,
                                    negotiation_status::SASL_SUCC,
                                    negotiation_status::SASL_AUTH_FAIL};
const char *_knegotiation_statusNames[] = {"INVALID",
                                           "SASL_LIST_MECHANISMS",
                                           "SASL_LIST_MECHANISMS_RESP",
                                           "SASL_SELECT_MECHANISMS",
                                           "SASL_SELECT_MECHANISMS_OK",
                                           "SASL_INITIATE",
                                           "SASL_CHALLENGE",
                                           "SASL_RESPONSE",
                                           "SASL_SUCC",
                                           "SASL_AUTH_FAIL"};
const std::map<int, const char *> _negotiation_status_VALUES_TO_NAMES(
    ::apache::thrift::TEnumIterator(10, _knegotiation_statusValues, _knegotiation_statusNames),
    ::apache::thrift::TEnumIterator(-1, NULL, NULL));

negotiation_message::~negotiation_message() throw() {}

void negotiation_message::__set_status(const negotiation_status::type val) { this->status = val; }

void negotiation_message::__set_msg(const ::dsn::blob &val) { this->msg = val; }

uint32_t negotiation_message::read(::apache::thrift::protocol::TProtocol *iprot)
{

    apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
    uint32_t xfer = 0;
    std::string fname;
    ::apache::thrift::protocol::TType ftype;
    int16_t fid;

    xfer += iprot->readStructBegin(fname);

    using ::apache::thrift::protocol::TProtocolException;

    while (true) {
        xfer += iprot->readFieldBegin(fname, ftype, fid);
        if (ftype == ::apache::thrift::protocol::T_STOP) {
            break;
        }
        switch (fid) {
        case 1:
            if (ftype == ::apache::thrift::protocol::T_I32) {
                int32_t ecast0;
                xfer += iprot->readI32(ecast0);
                this->status = (negotiation_status::type)ecast0;
                this->__isset.status = true;
            } else {
                xfer += iprot->skip(ftype);
            }
            break;
        case 2:
            if (ftype == ::apache::thrift::protocol::T_STRUCT) {
                xfer += this->msg.read(iprot);
                this->__isset.msg = true;
            } else {
                xfer += iprot->skip(ftype);
            }
            break;
        default:
            xfer += iprot->skip(ftype);
            break;
        }
        xfer += iprot->readFieldEnd();
    }

    xfer += iprot->readStructEnd();

    return xfer;
}

uint32_t negotiation_message::write(::apache::thrift::protocol::TProtocol *oprot) const
{
    uint32_t xfer = 0;
    apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
    xfer += oprot->writeStructBegin("negotiation_message");

    xfer += oprot->writeFieldBegin("status", ::apache::thrift::protocol::T_I32, 1);
    xfer += oprot->writeI32((int32_t)this->status);
    xfer += oprot->writeFieldEnd();

    xfer += oprot->writeFieldBegin("msg", ::apache::thrift::protocol::T_STRUCT, 2);
    xfer += this->msg.write(oprot);
    xfer += oprot->writeFieldEnd();

    xfer += oprot->writeFieldStop();
    xfer += oprot->writeStructEnd();
    return xfer;
}

void swap(negotiation_message &a, negotiation_message &b)
{
    using ::std::swap;
    swap(a.status, b.status);
    swap(a.msg, b.msg);
    swap(a.__isset, b.__isset);
}

negotiation_message::negotiation_message(const negotiation_message &other1)
{
    status = other1.status;
    msg = other1.msg;
    __isset = other1.__isset;
}
negotiation_message::negotiation_message(negotiation_message &&other2)
{
    status = std::move(other2.status);
    msg = std::move(other2.msg);
    __isset = std::move(other2.__isset);
}
negotiation_message &negotiation_message::operator=(const negotiation_message &other3)
{
    status = other3.status;
    msg = other3.msg;
    __isset = other3.__isset;
    return *this;
}
negotiation_message &negotiation_message::operator=(negotiation_message &&other4)
{
    status = std::move(other4.status);
    msg = std::move(other4.msg);
    __isset = std::move(other4.__isset);
    return *this;
}
void negotiation_message::printTo(std::ostream &out) const
{
    using ::apache::thrift::to_string;
    out << "negotiation_message(";
    out << "status=" << to_string(status);
    out << ", "
        << "msg=" << to_string(msg);
    out << ")";
}

} // namespace security
} // namespace dsn
