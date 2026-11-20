// 4G NAS EPS Session Management (ESM) decoder: PDN connectivity, bearer resource
// requests, ESM information response — including the UE-supplied Protocol Configuration
// Options, TFT, APN and QoS IEs (lib/3gpp/3gpp_24.008_sm_ies.c). The MME runs it on the
// ESM container of every uplink NAS message.
#include <cstdint>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
}
#include "lte/gateway/c/core/oai/tasks/nas/esm/msg/esm_msg.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  uint8_t* buf = static_cast<uint8_t*>(malloc(size ? size : 1));
  if (size) memcpy(buf, data, size);
  ESM_msg msg;
  memset(&msg, 0, sizeof(msg));
  esm_msg_decode(&msg, buf, static_cast<uint32_t>(size));
  free(buf);
  return 0;
}
