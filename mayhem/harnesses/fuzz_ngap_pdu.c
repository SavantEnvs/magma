// NGAP (TS 38.413 r16) PDU decoder of the AMF (tasks/ngap/ngap_amf_decoder.c,
// ngap_amf_decode_pdu): the asn1c-generated APER decoder for every NGAP-PDU a gNB sends
// over SCTP. The generated code comes from upstream's own r16.asn1 with upstream's
// asn1c fork and flags (bazel/asn1c.bzl), built by mayhem/build.sh.
#include <stdint.h>
#include <string.h>
#include "lte/gateway/c/core/oai/common/log.h"
#include "lte/gateway/c/core/oai/lib/bstr/bstrlib.h"
#include "lte/gateway/c/core/oai/tasks/ngap/ngap_amf_decoder.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // An SCTP DATA chunk carries at least one byte of user data (RFC 4960 3.3.1: a DATA
  // chunk with no user data is a protocol violation answered with ABORT), so the
  // decoder is never handed an empty PDU; ngap_amf_decode_pdu asserts as much.
  if (size == 0) return -1;
  bstring raw = blk2bstr(data, (int)size);
  if (raw == NULL) return 0;
  Ngap_NGAP_PDU_t pdu;
  memset(&pdu, 0, sizeof(pdu));
  ngap_amf_decode_pdu(&pdu, raw);
  ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Ngap_NGAP_PDU, &pdu);
  bdestroy(raw);
  return 0;
}
