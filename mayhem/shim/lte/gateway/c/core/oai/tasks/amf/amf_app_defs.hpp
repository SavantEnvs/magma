/* Stand-in for the AMF application header, searched before the repo root only by
 * mayhem/build.sh. tasks/nas5g/src/AmfMessage.cpp and SmfMessage.cpp include
 * amf_app_defs.hpp for a single declaration, get_message_type_str() (used in log
 * lines); the real header drags in the asn1c-generated NGAP types and the AMF
 * protobuf state. The definition lives in mayhem/nas5g_log_names.cpp. */
#pragma once
#include <cstdint>
#include <string>
namespace magma5g {
std::string get_message_type_str(uint8_t type);
}  // namespace magma5g
