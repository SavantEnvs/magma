// Known-answer suite for magma's NAS codecs (run by mayhem/test.sh).
// Vectors are the captured UE packets in upstream's own unit tests
// (lte/gateway/c/core/oai/test/mme_app_task/test_mme_app_emm_encode_decode.cpp,
//  test/amf/test_amf_encode_decode.cpp, test/amf/test_amf_stateless.cpp); each case
// asserts decoded field values, and the 4G cases also re-encode and compare bytes.
// Prints "PASS <name>" / "FAIL <name>: why" per case and "SUMMARY passed=P failed=F".
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
}
#include "lte/gateway/c/core/oai/tasks/nas/emm/msg/emm_msg.hpp"
#include "lte/gateway/c/core/oai/tasks/nas/esm/msg/esm_msg.hpp"
#include "lte/gateway/c/core/oai/tasks/nas/api/network/nas_message.hpp"
#include "lte/gateway/c/core/oai/tasks/nas5g/include/AmfMessage.hpp"
#include "lte/gateway/c/core/oai/tasks/nas5g/include/SmfMessage.hpp"
extern "C" {
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/include/NwGtpv2c.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/include/NwGtpv2cPrivate.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/include/NwGtpv2cMsgIeParseInfo.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/shared/NwGtpv2cIe.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/shared/NwGtpv2cMsg.h"
}

static int g_pass = 0, g_fail = 0;
#define CHECK(name, cond)                                                   \
  do {                                                                      \
    if (!(cond)) {                                                          \
      printf("FAIL %s: %s\n", name, #cond);                                 \
      ok = false;                                                           \
    }                                                                       \
  } while (0)
static void report(const char* name, bool ok) {
  if (ok) { printf("PASS %s\n", name); g_pass++; } else { g_fail++; }
}

// Combined attach from the s1ap tester, with the 07 41 plain EMM header in front.
static const uint8_t kAttachTester[] = {
    0x07, 0x41, 0x72, 0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x02, 0xe0, 0xe0, 0x00, 0x04, 0x02, 0x01, 0xd0, 0x11, 0x40, 0x08, 0x04,
    0x02, 0x60, 0x04, 0x00, 0x02, 0x1c, 0x00};
// Combined attach from a Pixel 4 (ESM container carries a PDN connectivity request + PCO).
static const uint8_t kAttachPixel[] = {
    0x07, 0x41,
    0x72, 0x08, 0x39, 0x51, 0x10, 0x00, 0x30, 0x09, 0x01, 0x07, 0x07, 0xf0,
    0x70, 0xc0, 0x40, 0x19, 0x00, 0x80, 0x00, 0x34, 0x02, 0x0c, 0xd0, 0x11,
    0xd1, 0x27, 0x2d, 0x80, 0x80, 0x21, 0x10, 0x01, 0x00, 0x00, 0x10, 0x81,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x11, 0x00, 0x00, 0x1a, 0x01, 0x01, 0x00, 0x23, 0x00, 0x00, 0x24, 0x00,
    0x5c, 0x0a, 0x01, 0x31, 0x04, 0x65, 0xe0, 0x3e, 0x00, 0x90, 0x11, 0x03,
    0x57, 0x58, 0xa6, 0x20, 0x0d, 0x60, 0x14, 0x04, 0xef, 0x65, 0x23, 0x3b,
    0x88, 0x00, 0x92, 0xf2, 0x00, 0x00, 0x40, 0x08, 0x04, 0x02, 0x60, 0x04,
    0x00, 0x02, 0x1f, 0x00, 0x5d, 0x01, 0x03, 0xc1};
// 5GMM registration request (test_amf_encode_decode.cpp).
static const uint8_t kRegReq5g[] = {
    0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x09, 0xf1, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x01, 0x00,
    0x2e, 0x08, 0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f,
    0x05, 0x04, 0x01, 0x00, 0x00, 0x01, 0x53, 0x01, 0x00};
// 5GMM UL NAS transport carrying a PDU session establishment request with DNN "internet".
static const uint8_t kUlNas5g[] = {
    0x7e, 0x00, 0x67, 0x01, 0x00, 0x15, 0x2e, 0x01, 0x01, 0xc1, 0xff,
    0xff, 0x91, 0xa1, 0x28, 0x01, 0x00, 0x7b, 0x00, 0x07, 0x80, 0x00,
    0x0a, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x01, 0x81, 0x22, 0x01, 0x01,
    0x25, 0x09, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74};

static void test_emm_attach_roundtrip() {
  const char* name = "emm_attach_request_tester_roundtrip";
  bool ok = true;
  uint8_t in[sizeof(kAttachTester)];
  memcpy(in, kAttachTester, sizeof in);
  EMM_msg m;
  memset(&m, 0, sizeof m);
  int rc = emm_msg_decode(&m, in, sizeof in);
  CHECK(name, rc == (int)sizeof in);
  CHECK(name, m.header.protocol_discriminator == EPS_MOBILITY_MANAGEMENT_MESSAGE);
  CHECK(name, m.header.message_type == ATTACH_REQUEST);
  CHECK(name, m.attach_request.epsattachtype == EPS_ATTACH_TYPE_COMBINED_EPS_IMSI);
  CHECK(name, m.attach_request.esmmessagecontainer != NULL &&
                  blength(m.attach_request.esmmessagecontainer) == 4);
  // Re-encode the attach body (after the 2-byte header), as upstream's
  // TestDecodeEncodeAttachRequest does, and compare byte for byte.
  attach_request_msg body;
  memset(&body, 0, sizeof body);
  uint8_t in2[sizeof(kAttachTester) - 2];
  memcpy(in2, kAttachTester + 2, sizeof in2);
  int dec = decode_attach_request(&body, in2, sizeof in2);
  uint8_t out[256] = {0};
  int enc = encode_attach_request(&body, out, dec > 0 ? dec : 0);
  printf("  %s: decoded=%d body=%d encoded=%d\n", name, rc, dec, enc);
  CHECK(name, dec == (int)sizeof in2);
  CHECK(name, enc == dec);
  CHECK(name, enc > 0 && memcmp(out, kAttachTester + 2, sizeof in2) == 0);
  report(name, ok);
}

// The MME's NAS PDU entry on a plain (security header type 0) attach request,
// before any security context exists.
static void test_nas_message_plain_attach() {
  const char* name = "nas_message_decode_plain_attach";
  bool ok = true;
  nas_message_t msg;
  memset(&msg, 0, sizeof msg);
  nas_message_decode_status_t st;
  memset(&st, 0, sizeof st);
  int rc = nas_message_decode(kAttachTester, &msg, sizeof(kAttachTester), NULL, &st);
  printf("  %s: rc=%d\n", name, rc);
  CHECK(name, rc == (int)sizeof(kAttachTester));
  CHECK(name, msg.plain.emm.header.message_type == ATTACH_REQUEST);
  CHECK(name, msg.plain.emm.attach_request.epsattachtype == EPS_ATTACH_TYPE_COMBINED_EPS_IMSI);
  CHECK(name, st.integrity_protected_message == 0 && st.ciphered_message == 0);
  report(name, ok);
}

static void test_emm_attach_pixel_and_esm() {
  const char* name = "emm_attach_request_pixel";
  bool ok = true;
  uint8_t in[sizeof(kAttachPixel)];
  memcpy(in, kAttachPixel, sizeof in);
  EMM_msg m;
  memset(&m, 0, sizeof m);
  int rc = emm_msg_decode(&m, in, sizeof in);
  CHECK(name, rc == (int)sizeof in);
  CHECK(name, m.attach_request.epsattachtype == EPS_ATTACH_TYPE_COMBINED_EPS_IMSI);
  CHECK(name, m.attach_request.naskeysetidentifier.naskeysetidentifier ==
                  NAS_KEY_SET_IDENTIFIER_NOT_AVAILABLE);
  bstring esm = m.attach_request.esmmessagecontainer;
  CHECK(name, esm != NULL && blength(esm) == 0x34);
  report(name, ok);
  if (esm == NULL) return;

  const char* name2 = "esm_pdn_connectivity_request_pco";
  ok = true;
  ESM_msg e;
  memset(&e, 0, sizeof e);
  rc = esm_msg_decode(&e, (uint8_t*)bdata(esm), blength(esm));
  CHECK(name2, rc == 0x34);
  CHECK(name2, e.header.message_type == PDN_CONNECTIVITY_REQUEST);
  CHECK(name2, e.header.procedure_transaction_identity == 0x0c);
  const protocol_configuration_options_t& pco =
      e.pdn_connectivity_request.protocolconfigurationoptions;
  CHECK(name2, pco.num_protocol_or_container_id == 9);
  CHECK(name2, pco.protocol_or_container_ids[0].id == 0x8021);
  CHECK(name2, pco.protocol_or_container_ids[1].id == 0x000d);
  CHECK(name2, pco.protocol_or_container_ids[8].id == 0x0024);
  report(name2, ok);
}

static void test_5g_registration_request() {
  const char* name = "nas5g_registration_request";
  bool ok = true;
  uint8_t in[sizeof(kRegReq5g)];
  memcpy(in, kRegReq5g, sizeof in);
  magma5g::AmfMsg m;
  int rc = m.M5gNasMessageDecodeMsg(&m, in, sizeof in);
  printf("  %s: decoded=%d of %zu\n", name, rc, sizeof in);
  // M5gNasMessageDecodeMsg returns header bytes (3) + the message decoder's
  // count, which itself includes the 3 header bytes.
  CHECK(name, rc == (int)sizeof in + 3);
  CHECK(name, m.header.extended_protocol_discriminator == 0x7e);
  CHECK(name, m.header.message_type == 0x41);
  CHECK(name, m.msg.reg_request.m5gs_reg_type.type_val == 1);
  CHECK(name, m.msg.reg_request.m5gs_reg_type.FOR == 1);
  CHECK(name, m.msg.reg_request.ue_sec_capability.iei == 0x2e);
  CHECK(name, m.msg.reg_request.ue_sec_capability.ea == 0x80);
  report(name, ok);
}

static void test_5g_ul_nas_transport() {
  const char* name = "nas5g_ul_nas_transport";
  bool ok = true;
  uint8_t in[sizeof(kUlNas5g)];
  memcpy(in, kUlNas5g, sizeof in);
  magma5g::AmfMsg m;
  int rc = m.M5gNasMessageDecodeMsg(&m, in, sizeof in);
  printf("  %s: decoded=%d of %zu\n", name, rc, sizeof in);
  CHECK(name, rc == (int)sizeof in + 3);
  CHECK(name, m.header.message_type == 0x67);
  CHECK(name, m.msg.ul_nas_transport.dnn.len == 9);
  CHECK(name, m.msg.ul_nas_transport.dnn.iei == 0x25);
  CHECK(name, memcmp(m.msg.ul_nas_transport.dnn.dnn, "internet", 8) == 0);
  report(name, ok);

  // The payload container (offset 6, 0x15 bytes) is a 5GSM PDU session establishment request.
  const char* name2 = "nas5g_smf_pdu_session_establishment_request";
  ok = true;
  magma5g::SmfMsg s;
  uint8_t pl[0x15];
  memcpy(pl, kUlNas5g + 6, sizeof pl);
  rc = s.SmfMsgDecodeMsg(&s, pl, sizeof pl);
  printf("  %s: decoded=%d of %zu\n", name2, rc, sizeof pl);
  CHECK(name2, rc > 0);
  CHECK(name2, s.header.extended_protocol_discriminator == 0x2e);
  CHECK(name2, s.header.pdu_session_id == 0x01);
  CHECK(name2, s.header.procedure_transaction_id == 0x01);
  CHECK(name2, s.header.message_type == 0xc1);
  report(name2, ok);
}

// GTPv2-C create session response (TS 29.274 7.2.2) as an SGW sends it on S11:
// TEID 0x11223344, seq 1, Cause 16 (request accepted), S11 SGW F-TEID 0x1234 @10.0.0.1,
// S5/S8 PGW F-TEID (instance 1), PAA 192.168.128.10, APN-AMBR, bearer context (EBI 5).
static const uint8_t kCreateSessionRsp[] = {
    0x48, 0x21, 0x00, 0x59, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x8b, 0x00,
    0x00, 0x12, 0x34, 0x0a, 0x00, 0x00, 0x01, 0x57, 0x00, 0x09, 0x01, 0x87,
    0x00, 0x00, 0x56, 0x78, 0x0a, 0x00, 0x00, 0x02, 0x4f, 0x00, 0x05, 0x00,
    0x01, 0xc0, 0xa8, 0x80, 0x0a, 0x48, 0x00, 0x08, 0x00, 0x00, 0x01, 0x86,
    0xa0, 0x00, 0x03, 0x0d, 0x40, 0x5d, 0x00, 0x18, 0x00, 0x49, 0x00, 0x01,
    0x00, 0x05, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00,
    0x81, 0x00, 0x00, 0x9a, 0xbc, 0x0a, 0x00, 0x00, 0x01};

static void test_gtpv2c_create_session_response() {
  const char* name = "gtpv2c_create_session_response";
  bool ok = true;
  nw_gtpv2c_stack_t* stack =
      static_cast<nw_gtpv2c_stack_t*>(calloc(1, sizeof(nw_gtpv2c_stack_t)));
  nw_gtpv2c_msg_ie_parse_info_t* info = nwGtpv2cMsgIeParseInfoNew(
      (nw_gtpv2c_stack_handle_t)stack, NW_GTP_CREATE_SESSION_RSP);
  uint8_t in[sizeof(kCreateSessionRsp)];
  memcpy(in, kCreateSessionRsp, sizeof in);
  nw_gtpv2c_msg_handle_t h = 0;
  CHECK(name, nwGtpv2cMsgFromBufferNew((nw_gtpv2c_stack_handle_t)stack, in,
                                       sizeof in, &h) == NW_OK);
  nw_gtpv2c_error_t err;
  memset(&err, 0, sizeof err);
  nw_rc_t rc = nwGtpv2cMsgIeParse(info, h, &err);
  printf("  %s: parse rc=%d\n", name, (int)rc);
  CHECK(name, rc == NW_OK);
  CHECK(name, nwGtpv2cMsgGetTeid(h) == 0x11223344u);
  CHECK(name, nwGtpv2cMsgGetSeqNumber(h) == 1u);
  uint8_t* ie = NULL;
  uint16_t ielen = 0;
  CHECK(name, nwGtpv2cMsgGetIeTlvP(h, NW_GTPV2C_IE_CAUSE, NW_GTPV2C_IE_INSTANCE_ZERO,
                                   &ie, &ielen) == NW_OK);
  CHECK(name, ielen == 2 && ie != NULL && ie[0] == 16);
  CHECK(name, nwGtpv2cMsgGetIeTlvP(h, NW_GTPV2C_IE_FTEID, NW_GTPV2C_IE_INSTANCE_ONE,
                                   &ie, &ielen) == NW_OK);
  CHECK(name, ielen == 9 && ie != NULL && ie[0] == 0x87 && ie[4] == 0x78);
  // A mandatory IE (Cause) missing must be reported, not accepted.
  const char* name2 = "gtpv2c_missing_mandatory_ie";
  bool ok2 = true;
  {
    bool& ok = ok2;
    uint8_t bad[] = {0x48, 0x21, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x02, 0x00};
    nw_gtpv2c_msg_handle_t h2 = 0;
    CHECK(name2, nwGtpv2cMsgFromBufferNew((nw_gtpv2c_stack_handle_t)stack, bad,
                                          sizeof bad, &h2) == NW_OK);
    memset(&err, 0, sizeof err);
    rc = nwGtpv2cMsgIeParse(info, h2, &err);
    CHECK(name2, rc != NW_OK);
    CHECK(name2, err.cause == NW_GTPV2C_CAUSE_MANDATORY_IE_MISSING);
    nwGtpv2cMsgDelete((nw_gtpv2c_stack_handle_t)stack, h2);
  }
  nwGtpv2cMsgDelete((nw_gtpv2c_stack_handle_t)stack, h);
  report(name, ok);
  report(name2, ok2);
}

int main() {
  test_emm_attach_roundtrip();
  test_emm_attach_pixel_and_esm();
  test_nas_message_plain_attach();
  test_5g_registration_request();
  test_5g_ul_nas_transport();
  test_gtpv2c_create_session_response();
  printf("SUMMARY passed=%d failed=%d\n", g_pass, g_fail);
  return g_fail ? 1 : 0;
}
