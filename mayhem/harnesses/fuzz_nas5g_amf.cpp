// 5G NAS mobility management decoder (magma5g::AmfMsg::M5gNasMessageDecodeMsg), the
// AMF's entry for every plain 5GMM message from a UE (tasks/amf/nas5g_message.cpp).
// Registration request (UE security capability), UL NAS transport (payload container
// -> 5GSM, DNN) and the other 5GMM messages and IEs in tasks/nas5g/src{,/ies}.
#include <cstdint>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
}
#include "lte/gateway/c/core/oai/tasks/nas5g/include/AmfMessage.hpp"

using magma5g::AmfMsg;

// AmfMsgDecodeHeaderMsg reads the three mandatory 5GMM header octets (extended
// protocol discriminator, security header type, message type; TS 24.501 9.1.1) with no
// length check, so its contract is a buffer of at least that header. A shorter PDU
// crashes in the header read on every such input (an upstream bug, but one shallow
// enough to stop the fuzzer from ever running past it); reject those inputs.
static constexpr size_t kM5gmmHeaderLen = 3;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kM5gmmHeaderLen) return -1;
  uint8_t* buf = static_cast<uint8_t*>(malloc(size ? size : 1));
  if (size) memcpy(buf, data, size);
  {
    AmfMsg msg;
    msg.M5gNasMessageDecodeMsg(&msg, buf, static_cast<uint32_t>(size));
  }
  free(buf);
  return 0;
}
