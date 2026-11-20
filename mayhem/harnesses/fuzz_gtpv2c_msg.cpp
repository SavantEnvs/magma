// GTPv2-C message parsing as the MME/SGW stack runs it on every UDP datagram from an
// S11/S5/S10 peer (lib/gtpv2-c/nwgtpv2c-0.11/src/NwGtpv2c.c, nwGtpv2cProcessUdpReq and
// its per-message handlers): header checks, nwGtpv2cMsgFromBufferNew, then
// nwGtpv2cMsgIeParse against the stack's per-message-type IE table
// (NwGtpv2cMsgIeParseInfo.c: mandatory/conditional IEs, grouped bearer contexts), and
// then, for the five messages the MME's S11 task decodes (tasks/s11/s11_mme_session_manager.cpp
// and s11_mme_bearer_manager.cpp), the same nwGtpv2cMsgParser with the same per-IE
// callbacks those handlers register: the gtpv2c_*_ie_get decoders in
// lib/gtpv2-c/gtpv2c_ie_formatter and tasks/s11/s11_ie_formatter.cpp (cause, F-TEID, PAA,
// AMBR, PCO, EBI, PTI, APN restriction, and the grouped bearer contexts with their QoS/TFT).
//
// The stack object is built as nwGtpv2cInitialize builds the part these functions read:
// calloc'd, no custom memory manager, and the same IE parse tables. Those are created
// once and only read while parsing.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern "C" {
#include "lte/gateway/c/core/oai/common/log.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/include/NwGtpv2c.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/include/NwGtpv2cPrivate.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/include/NwGtpv2cMsgIeParseInfo.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/shared/NwGtpv2cIe.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/shared/NwGtpv2cMsg.h"
#include "lte/gateway/c/core/oai/lib/gtpv2-c/nwgtpv2c-0.11/shared/NwGtpv2cMsgParser.h"
}
#include "lte/gateway/c/core/oai/include/s11_messages_types.hpp"
#include "lte/gateway/c/core/oai/tasks/s11/s11_ie_formatter.hpp"

static nw_gtpv2c_stack_t* g_stack;

// s11_common.cpp's s11_ie_indication_generic: unexpected IEs are only logged.
static nw_rc_t ie_generic(uint8_t, uint16_t, uint8_t, uint8_t*, void*) { return NW_OK; }

#define ADD(p, t, i, pr, cb, arg) \
  nwGtpv2cMsgParserAddIe(p, NW_GTPV2C_IE_##t, NW_GTPV2C_IE_INSTANCE_##i, \
                         NW_GTPV2C_IE_PRESENCE_##pr, cb, arg)

// The s11_mme_handle_* body for msgType: parser, the same IEs/callbacks, run, delete.
static void s11_decode(nw_gtpv2c_msg_handle_t hMsg, uint8_t msgType) {
  nw_gtpv2c_stack_handle_t st = (nw_gtpv2c_stack_handle_t)g_stack;
  nw_gtpv2c_msg_parser_t* p = NULL;
  switch (msgType) {
    case NW_GTP_CREATE_SESSION_RSP: case NW_GTP_DELETE_SESSION_RSP:
    case NW_GTP_RELEASE_ACCESS_BEARERS_RSP: case NW_GTP_MODIFY_BEARER_RSP:
    case NW_GTP_CREATE_BEARER_REQ: break;
    default: return;
  }
  if (nwGtpv2cMsgParserNew(st, msgType, ie_generic, NULL, &p) != NW_OK) return;
  // The handlers keep these in an ITTI message; heap-allocate them the same way.
  protocol_configuration_options_t* pco = NULL;
  void* msg = NULL;
  switch (msgType) {
    case NW_GTP_CREATE_SESSION_RSP: {  // s11_mme_handle_create_session_response
      auto* r = (itti_s11_create_session_response_t*)calloc(1, sizeof(itti_s11_create_session_response_t));
      msg = r; pco = &r->pco;
      ADD(p, CAUSE, ZERO, MANDATORY, gtpv2c_cause_ie_get, &r->cause);
      ADD(p, FTEID, ZERO, CONDITIONAL, gtpv2c_fteid_ie_get, &r->s11_sgw_fteid);
      ADD(p, FTEID, ONE, CONDITIONAL, gtpv2c_fteid_ie_get, &r->s5_s8_pgw_fteid);
      ADD(p, PAA, ZERO, CONDITIONAL, gtpv2c_paa_ie_get, &r->paa);
      ADD(p, APN_RESTRICTION, ZERO, CONDITIONAL, gtpv2c_apn_restriction_ie_get,
          &r->apn_restriction);
      ADD(p, AMBR, ZERO, CONDITIONAL, gtpv2c_ambr_ie_get, &r->ambr);
      ADD(p, PCO, ZERO, CONDITIONAL, gtpv2c_pco_ie_get, &r->pco);
      ADD(p, BEARER_CONTEXT, ZERO, CONDITIONAL, gtpv2c_bearer_context_created_ie_get,
          &r->bearer_contexts_created);
      ADD(p, BEARER_CONTEXT, ONE, CONDITIONAL,
          gtpv2c_bearer_context_marked_for_removal_ie_get,
          &r->bearer_contexts_marked_for_removal);
      break;
    }
    case NW_GTP_DELETE_SESSION_RSP: {  // s11_mme_handle_delete_session_response
      auto* r = (itti_s11_delete_session_response_t*)calloc(1, sizeof(itti_s11_delete_session_response_t));
      msg = r; pco = &r->pco;
      ADD(p, CAUSE, ZERO, MANDATORY, gtpv2c_cause_ie_get, &r->cause);
      ADD(p, PCO, ZERO, CONDITIONAL, gtpv2c_pco_ie_get, &r->pco);
      break;
    }
    case NW_GTP_RELEASE_ACCESS_BEARERS_RSP: {  // s11_mme_handle_release_access_bearer_response
      auto* r = (itti_s11_release_access_bearers_response_t*)calloc(1, sizeof(itti_s11_release_access_bearers_response_t));
      msg = r;
      ADD(p, CAUSE, ZERO, MANDATORY, gtpv2c_cause_ie_get, &r->cause);
      break;
    }
    case NW_GTP_MODIFY_BEARER_RSP: {  // s11_mme_handle_modify_bearer_response
      auto* r = (itti_s11_modify_bearer_response_t*)calloc(1, sizeof(itti_s11_modify_bearer_response_t));
      msg = r;
      ADD(p, CAUSE, ZERO, MANDATORY, gtpv2c_cause_ie_get, &r->cause);
      ADD(p, BEARER_CONTEXT, ZERO, CONDITIONAL, gtpv2c_bearer_context_modified_ie_get,
          &r->bearer_contexts_modified);
      ADD(p, BEARER_CONTEXT, ONE, CONDITIONAL,
          gtpv2c_bearer_context_marked_for_removal_ie_get,
          &r->bearer_contexts_marked_for_removal);
      break;
    }
    case NW_GTP_CREATE_BEARER_REQ: {  // s11_mme_handle_create_bearer_request
      auto* r = (itti_s11_create_bearer_request_t*)calloc(1, sizeof(itti_s11_create_bearer_request_t));
      msg = r; pco = &r->pco;
      ADD(p, EBI, ZERO, MANDATORY, gtpv2c_ebi_ie_get, &r->linked_eps_bearer_id);
      ADD(p, PCO, ZERO, OPTIONAL, gtpv2c_pco_ie_get, &r->pco);
      ADD(p, BEARER_CONTEXT, ZERO, MANDATORY,
          gtpv2c_bearer_context_to_be_created_within_create_bearer_request_ie_get,
          &r->bearer_contexts);
      ADD(p, PROCEDURE_TRANSACTION_ID, ZERO, CONDITIONAL, gtpv2c_pti_ie_get, &r->pti);
      break;
    }
  }
  uint8_t offType = 0, offInst = 0;
  uint16_t offLen = 0;
  (void)nwGtpv2cMsgParserRun(p, hMsg, &offType, &offInst, &offLen);
  nwGtpv2cMsgParserDelete(st, p);
  if (pco) clear_protocol_configuration_options(pco);
  free(msg);
}

// The message types nwGtpv2cInitialize registers an IE parse table for.
static const uint8_t kTypes[] = {
    NW_GTP_ECHO_RSP, NW_GTP_CREATE_SESSION_REQ, NW_GTP_CREATE_SESSION_RSP,
    NW_GTP_DELETE_SESSION_REQ, NW_GTP_DELETE_SESSION_RSP, NW_GTP_MODIFY_BEARER_REQ,
    NW_GTP_MODIFY_BEARER_RSP, NW_GTP_CREATE_BEARER_REQ, NW_GTP_CREATE_BEARER_RSP,
    NW_GTP_UPDATE_BEARER_REQ, NW_GTP_UPDATE_BEARER_RSP, NW_GTP_DELETE_BEARER_REQ,
    NW_GTP_DELETE_BEARER_RSP, NW_GTP_DELETE_BEARER_CMD,
    NW_GTP_DELETE_BEARER_FAILURE_IND, NW_GTP_BEARER_RESOURCE_CMD,
    NW_GTP_BEARER_RESOURCE_FAILURE_IND, NW_GTP_RELEASE_ACCESS_BEARERS_REQ,
    NW_GTP_RELEASE_ACCESS_BEARERS_RSP, NW_GTP_DOWNLINK_DATA_NOTIFICATION,
    NW_GTP_FORWARD_RELOCATION_REQ, NW_GTP_FORWARD_RELOCATION_RSP,
    NW_GTP_FORWARD_ACCESS_CONTEXT_NTF, NW_GTP_FORWARD_ACCESS_CONTEXT_ACK,
    NW_GTP_FORWARD_RELOCATION_COMPLETE_NTF, NW_GTP_FORWARD_RELOCATION_COMPLETE_ACK,
    NW_GTP_CONTEXT_REQ, NW_GTP_CONTEXT_RSP, NW_GTP_CONTEXT_ACK,
    NW_GTP_RELOCATION_CANCEL_REQ, NW_GTP_RELOCATION_CANCEL_RSP,
    NW_GTP_IDENTIFICATION_REQ, NW_GTP_IDENTIFICATION_RSP};

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  (void)argc; (void)argv;
  g_stack = (nw_gtpv2c_stack_t*)calloc(1, sizeof(nw_gtpv2c_stack_t));
  for (size_t i = 0; i < sizeof(kTypes); i++)
    g_stack->pGtpv2cMsgIeParseInfo[kTypes[i]] =
        nwGtpv2cMsgIeParseInfoNew((nw_gtpv2c_stack_handle_t)g_stack, kTypes[i]);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // The UDP task receives into a 4096-byte buffer (tasks/udp/udp_primitives_server.c,
  // udp_socket_desc_s.buffer), which is NW_GTPV2C_MAX_MSG_LEN: no datagram is longer.
  if (size > NW_GTPV2C_MAX_MSG_LEN) return -1;
  uint8_t* buf = (uint8_t*)malloc(size ? size : 1);
  if (size) memcpy(buf, data, size);

  // nwGtpv2cProcessUdpReq's own checks, in its order.
  if (size < NW_GTPV2C_MINIMUM_HEADER_SIZE) goto out;
  if ((uint32_t)(ntohs(*(uint16_t*)(buf + 2)) + ((buf[0] & 0x08) ? 4 : 0)) > size)
    goto out;
  if (((buf[0] & 0xE0) >> 5) != NW_GTP_VERSION) goto out;
  {
    uint8_t msgType = buf[1];
    if (msgType >= NW_GTP_MSG_END || !g_stack->pGtpv2cMsgIeParseInfo[msgType]) goto out;
    nw_gtpv2c_msg_handle_t hMsg = 0;
    if (nwGtpv2cMsgFromBufferNew((nw_gtpv2c_stack_handle_t)g_stack, buf,
                                 (uint32_t)size, &hMsg) != NW_OK)
      goto out;
    nw_gtpv2c_error_t error;
    memset(&error, 0, sizeof(error));
    nw_rc_t rc = nwGtpv2cMsgIeParse(g_stack->pGtpv2cMsgIeParseInfo[msgType], hMsg, &error);
    if (rc == NW_OK) {
      // What the s11 handlers read next.
      (void)nwGtpv2cMsgGetTeid(hMsg);
      (void)nwGtpv2cMsgGetSeqNumber(hMsg);
      uint8_t cause = 0;
      (void)nwGtpv2cMsgGetIeTV1(hMsg, NW_GTPV2C_IE_CAUSE, NW_GTPV2C_IE_INSTANCE_ZERO, &cause);
      uint8_t* ie = NULL;
      uint16_t ielen = 0;
      (void)nwGtpv2cMsgGetIeTlvP(hMsg, NW_GTPV2C_IE_FTEID, NW_GTPV2C_IE_INSTANCE_ZERO, &ie, &ielen);
      // nwGtpv2cHandleUlpTrigger/s11_mme_ulp_process_stack_req_cb hand the parsed
      // message to the s11 handler for its type.
      s11_decode(hMsg, msgType);
    }
    nwGtpv2cMsgDelete((nw_gtpv2c_stack_handle_t)g_stack, hMsg);
  }
out:
  free(buf);
  return 0;
}
