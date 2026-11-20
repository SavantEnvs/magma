// 4G NAS EPS Mobility Management (EMM) plain-message decoder, as the MME runs it on
// every uplink NAS PDU from a UE (tasks/nas/api/network/nas_message.cpp ->
// emm_msg_decode). The whole input is the plain EMM message.
#include <cstdint>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
}
#include "lte/gateway/c/core/oai/tasks/nas/emm/msg/emm_msg.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Exact-size heap copy so ASan sees reads past the PDU.
  uint8_t* buf = static_cast<uint8_t*>(malloc(size ? size : 1));
  if (size) memcpy(buf, data, size);
  EMM_msg msg;
  memset(&msg, 0, sizeof(msg));
  emm_msg_decode(&msg, buf, static_cast<uint32_t>(size));
  free(buf);
  return 0;
}
