// get_message_type_str() is defined in tasks/amf/nas5g_message.cpp, which needs the whole
// AMF application (NGAP asn1c types, ITTI, protobuf state). The 5G codecs only call it to
// name a message type in a log line that mayhem/log_stub.c discards.
#include <cstdint>
#include <string>
namespace magma5g {
std::string get_message_type_str(uint8_t type) { return std::to_string(type); }
}  // namespace magma5g
