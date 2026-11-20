// 5G NAS session management decoder (magma5g::SmfMsg::SmfMsgDecodeMsg): PDU session
// establishment/modification/release requests with QoS rules, DNN and extended PCO,
// reached without the UL NAS transport wrapper fuzz_nas5g_amf needs.
#include <cstdint>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
}
#include "lte/gateway/c/core/oai/tasks/nas5g/include/SmfMessage.hpp"

using magma5g::SmfMsg;

// SmfMsgDecodeHeaderMsg reads the four mandatory 5GSM header octets (extended
// protocol discriminator, PDU session ID, PTI, message type; TS 24.501 9.1.1) with no
// length check, so its contract is a buffer of at least that header. A shorter
// payload crashes in the header read on every such input (an upstream bug, but one
// shallow enough to stop the fuzzer from running past it); reject those inputs.
static constexpr size_t k5gsmHeaderLen = 4;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < k5gsmHeaderLen) return -1;
  uint8_t* buf = static_cast<uint8_t*>(malloc(size ? size : 1));
  if (size) memcpy(buf, data, size);
  {
    SmfMsg msg;
    msg.SmfMsgDecodeMsg(&msg, buf, static_cast<uint32_t>(size));
  }
  free(buf);
  return 0;
}
