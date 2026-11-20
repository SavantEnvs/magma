// 4G NAS PDU entry of the MME (tasks/nas/api/network/nas_message.cpp,
// nas_message_decode): security header parsing, service-request short MAC, sequence
// number / NAS COUNT handling, MAC check (EIA1/EIA2), deciphering (EEA1/EEA2), then the
// EMM/ESM decoders. The MME calls it on every uplink NAS PDU (emm_as / nas_proc).
//
// Input byte 0 selects the UE's security context, the rest is the NAS PDU:
//   0x80 clear  -> no security context (NULL, as before authentication)
//   0x80 set    -> a context with all-zero keys and counts, EIA = bits 0-1, EEA = bits 2-3
// The context is rebuilt for every input (nas_message_decode updates its counts).
#include <cstdint>
#include <cstdlib>
#include <cstring>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
}
#include "lte/gateway/c/core/oai/tasks/nas/api/network/nas_message.hpp"
#include "lte/gateway/c/core/oai/tasks/nas/emm/emm_data.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  const uint8_t mode = data[0];
  const size_t len = size - 1;
  uint8_t* buf = static_cast<uint8_t*>(malloc(len ? len : 1));
  if (len) memcpy(buf, data + 1, len);

  emm_security_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.selected_algorithms.integrity = mode & 0x3;
  ctx.selected_algorithms.encryption = (mode >> 2) & 0x3;
  void* security = (mode & 0x80) ? &ctx : nullptr;

  nas_message_t msg;
  memset(&msg, 0, sizeof(msg));
  nas_message_decode_status_t status;
  memset(&status, 0, sizeof(status));
  nas_message_decode(buf, &msg, len, security, &status);
  free(buf);
  return 0;
}
