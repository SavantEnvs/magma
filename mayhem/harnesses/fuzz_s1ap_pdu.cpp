// S1AP (TS 36.413 r15) PDU decoder of the MME (tasks/s1ap/s1ap_mme_decoder.cpp,
// s1ap_mme_decode_pdu): the asn1c-generated APER decoder for every S1AP-PDU an eNB
// sends over SCTP (S1 setup, initial UE message, uplink NAS transport, handover, ...).
// The generated code comes from upstream's own s1ap-15.6.0.asn1 with upstream's asn1c
// fork and flags (bazel/asn1c.bzl), built by mayhem/build.sh.
#include <cstdint>
#include <cstring>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
#include "lte/gateway/c/core/oai/lib/bstr/bstrlib.h"
}
#include "lte/gateway/c/core/oai/tasks/s1ap/s1ap_mme_decoder.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // s1ap_mme_receive -> blk2bstr of the SCTP payload, as the MME does.
  // An SCTP DATA chunk carries at least one byte of user data (RFC 4960 3.3.1: a DATA
  // chunk with no user data is a protocol violation answered with ABORT), so the
  // decoder is never handed an empty PDU; ngap_amf_decode_pdu asserts as much.
  if (size == 0) return -1;
  bstring raw = blk2bstr(data, static_cast<int>(size));
  if (raw == NULL) return 0;
  S1ap_S1AP_PDU_t pdu;
  memset(&pdu, 0, sizeof(pdu));
  s1ap_mme_decode_pdu(&pdu, raw);
  ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1ap_S1AP_PDU, &pdu);
  bdestroy(raw);
  return 0;
}
