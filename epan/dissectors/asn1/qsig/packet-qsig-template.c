/* packet-qsig.c
 * Routines for QSIG packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <wsutil/strtoi.h>

#include "packet-ber.h"
#include "packet-qsig.h"

#define PNAME  "QSIG"
#define PSNAME "QSIG"
#define PFNAME "qsig"

/* Shifted codeset values */
#define CS0 0x000
#define CS1 0x100
#define CS2 0x200
#define CS3 0x300
#define CS4 0x400
#define CS5 0x500
#define CS6 0x600
#define CS7 0x700

#define	QSIG_IE_TRANSIT_COUNTER 0x31
#define	QSIG_IE_PARTY_CATEGORY  0x32

void proto_register_qsig(void);
void proto_reg_handoff_qsig(void);

static dissector_handle_t qsig_arg_handle;
static dissector_handle_t qsig_res_handle;
static dissector_handle_t qsig_err_handle;
static dissector_handle_t qsig_ie4_handle;
static dissector_handle_t qsig_ie5_handle;

static const value_string qsig_str_ie_type_cs4[] = {
  { QSIG_IE_TRANSIT_COUNTER , "Transit counter" },
  { 0, NULL}
};
static const value_string qsig_str_ie_type_cs5[] = {
  { QSIG_IE_PARTY_CATEGORY  , "Party category" },
  { 0, NULL}
};
/* Codeset array */
static const value_string *qsig_str_ie_type[] = {
  NULL,
  NULL,
  NULL,
  NULL,
  qsig_str_ie_type_cs4,
  qsig_str_ie_type_cs5,
  NULL,
  NULL,
};


static const value_string qsig_str_pc[] = {
  { 0x00 , "unknown" },
  { 0x01 , "extension" },
  { 0x02 , "operator" },
  { 0x03 , "emergency extension" },
  { 0, NULL}
};

static const value_string qsig_str_service[] = {
  { 13868, "QSIG-NA" },
  { 13873, "QSIG-CF" },
  { 13874, "QSIG-PR" },
  { 13869, "QSIG-CT" },
  { 13870, "QSIG-CC" },
  { 14843, "QSIG-CO" },
  { 14844, "QSIG-DND(O)" },
  { 14846, "QSIG-CI" },
  { 15050, "QSIG-AOC" },
  { 15052, "QSIG-RE" },
  { 15054, "QSIG-CINT" },
  { 15506, "QSIG-MWI" },
  { 15507, "SYNC-SIG" },
  { 15772, "QSIG-CMN" },
  { 15992, "QSIG-CPI(P)" },
  { 17876, "QSIG-PUMR" },
  { 17878, "QSIG-PUMCH" },
  { 19460, "QSIG-SSCT" },
  { 15429, "QSIG-WTMLR" },
  { 15431, "QSIG-WTMCH" },
  { 15433, "QSIG-WTMAU" },
  { 21407, "QSIG-SD" },
  { 21889, "QSIG-CIDL" },
  {   325, "QSIG-SMS" },
  {   344, "QSIG-MCR" },
  {  3471, "QSIG-MCM" },
  {  3472, "QSIG-MID" },
  {   0, NULL}
};

static const value_string qsig_str_service_name[] = {
  { 13868, "Name-Operations" },
  { 13873, "Call-Diversion-Operations" },
  { 13874, "Path-Replacement-Operations" },
  { 13869, "Call-Transfer-Operations" },
  { 13870, "SS-CC-Operations" },
  { 14843, "Call-Offer-Operations" },
  { 14844, "Do-Not-Disturb-Operations" },
  { 14846, "Call-Intrusion-Operations" },
  { 15050, "SS-AOC-Operation" },
  { 15052, "Recall-Operation" },
  { 15054, "Call-Interception-Operations" },
  { 15506, "SS-MWI-Operations" },
  { 15507, "Synchronization-Operations" },
  { 15772, "Common-Information-Operations" },
  { 15992, "Call-Interruption-Operation" },
  { 17876, "PUM-Registration-Operation" },
  { 17878, "Private-User-Mobility-Call-Handling-Operations" },
  { 19460, "Single-Step-Call-Transfer-Operations" },
  { 15429, "WTM-Location-Registration-Operations" },
  { 15431, "Wireless-Terminal-Call-Handling-Operations" },
  { 15433, "WTM-Authentication-Operations" },
  { 21407, "SS-SD-Operations" },
  { 21889, "Call-Identification-and-Call-Linkage-Operations" },
  {   325, "Short-Message-Service-Operations" },
  {   344, "SS-MCR-Operations" },
  {  3471, "SS-MCM-Operations" },
  {  3472, "SS-MID-Operations" },
  {   0, NULL}
};

#define NO_SRV (-1)
static const int32_t op2srv_tab[] = {
  /*   0 */ 13868,
  /*   1 */ 13868,
  /*   2 */ 13868,
  /*   3 */ 13868,
  /*   4 */ 13874,
  /*   5 */ 13874,
  /*   6 */ 13874,
  /*   7 */ 13869,
  /*   8 */ 13869,
  /*   9 */ 13869,
  /*  10 */ 13869,
  /*  11 */ 13869,
  /*  12 */ 13869,
  /*  13 */ 13869,
  /*  14 */ 13869,
  /*  15 */ 13873,
  /*  16 */ 13873,
  /*  17 */ 13873,
  /*  18 */ 13873,
  /*  19 */ 13873,
  /*  20 */ 13873,
  /*  21 */ 13873,
  /*  22 */ 13873,
  /*  23 */ 13873,
  /*  24 */ NO_SRV,
  /*  25 */ NO_SRV,
  /*  26 */ NO_SRV,
  /*  27 */ 13870,
  /*  28 */ 13870,
  /*  29 */ 13870,
  /*  30 */ 13870,
  /*  31 */ 13870,
  /*  32 */ 13870,
  /*  33 */ 13870,
  /*  34 */ 14843,
  /*  35 */ 14844,
  /*  36 */ 14844,
  /*  37 */ 14844,
  /*  38 */ 14844,
  /*  39 */ 14844,
  /*  40 */ 13870,
  /*  41 */ 90001,
  /*  42 */ 90001,
  /*  43 */ 14846,
  /*  44 */ 14846,
  /*  45 */ 14846,
  /*  46 */ 14846,
  /*  47 */ 14846,
  /*  48 */ 14846,
  /*  49 */ 90001,
  /*  50 */ 15429,
  /*  51 */ 15429,
  /*  52 */ 15429,
  /*  53 */ 15429,
  /*  54 */ 15431,
  /*  55 */ 15431,
  /*  56 */ 15431,
  /*  57 */ 15052,
  /*  58 */ 15052,
  /*  59 */ 15050,
  /*  60 */ 15050,
  /*  61 */ 15050,
  /*  62 */ 15050,
  /*  63 */ 15050,
  /*  64 */ 15050,
  /*  65 */ 15050,
  /*  66 */ 15054,
  /*  67 */ 15054,
  /*  68 */ 15054,
  /*  69 */ 15054,
  /*  70 */ 15054,
  /*  71 */ 15431,
  /*  72 */ 15433,
  /*  73 */ 15433,
  /*  74 */ 15433,
  /*  75 */ 15433,
  /*  76 */ 15433,
  /*  77 */ 15433,
  /*  78 */ 15507,
  /*  79 */ 15507,
  /*  80 */  3471,
  /*  81 */  3471,
  /*  82 */  3471,
  /*  83 */ NO_SRV,
  /*  84 */ 15772,
  /*  85 */ 15772,
  /*  86 */ 13874,
  /*  87 */ 15992,
  /*  88 */ 15992,
  /*  89 */ 17876,
  /*  90 */ 17876,
  /*  91 */ 17876,
  /*  92 */ 17876,
  /*  93 */ 17878,
  /*  94 */ 17878,
  /*  95 */ 17878,
  /*  96 */ 17878,
  /*  97 */ 15429,
  /*  98 */ 15429,
  /*  99 */ 19460,
  /* 100 */ 19460,
  /* 101 */ 19460,
  /* 102 */ 19460,
  /* 103 */ 21407,
  /* 104 */ 21407,
  /* 105 */ 21889,
  /* 106 */ 21889,
  /* 107 */   325,
  /* 108 */   325,
  /* 109 */   325,
  /* 110 */   325,
  /* 111 */   325,
  /* 112 */   344,
  /* 113 */   344,
  /* 114 */   344,
  /* 115 */  3471,
  /* 116 */  3471,
  /* 117 */  3471,
  /* 118 */  3471,
  /* 119 */  3472,
  /* 120 */  3472,
};

static const value_string qsig_str_operation[] = {
#include "packet-qsig-table10.c"
  {   0, NULL}
};

static const value_string qsig_str_error[] = {
#include "packet-qsig-table20.c"
  {   0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_qsig;
static int hf_qsig_operation;
static int hf_qsig_service;
static int hf_qsig_error;
static int hf_qsig_ie_type;
static int hf_qsig_ie_type_cs4;
static int hf_qsig_ie_type_cs5;
static int hf_qsig_ie_len;
static int hf_qsig_ie_data;
static int hf_qsig_tc;
static int hf_qsig_pc;
#include "packet-qsig-hf.c"

static int *hf_qsig_ie_type_arr[] = {
  NULL,
  NULL,
  NULL,
  NULL,
  &hf_qsig_ie_type_cs4,
  &hf_qsig_ie_type_cs5,
  NULL,
  NULL,
};

/* Initialize the subtree pointers */
static int ett_qsig;
static int ett_qsig_ie;
static int ett_qsig_unknown_extension;
#include "packet-qsig-ett.c"
static int ett_cnq_PSS1InformationElement;

/* static expert_field ei_qsig_unsupported_arg_type; */
static expert_field ei_qsig_unsupported_result_type;
static expert_field ei_qsig_unsupported_error_type;

/* Preferences */

/* Subdissectors */
static dissector_handle_t q931_ie_handle;

/* Global variables */
static const char *extension_oid;

/* Dissector tables */
static dissector_table_t extension_dissector_table;

#include "packet-qsig-fn.c"

typedef struct _qsig_op_t {
  int32_t opcode;
  dissector_t arg_pdu;
  dissector_t res_pdu;
} qsig_op_t;

static const qsig_op_t qsig_op_tab[] = {
#include "packet-qsig-table11.c"
};

typedef struct _qsig_err_t {
  int32_t errcode;
  dissector_t err_pdu;
} qsig_err_t;

static const qsig_err_t qsig_err_tab[] = {
#include "packet-qsig-table21.c"
};

static const qsig_op_t *get_op(int32_t opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_op_tab) - 1; i >= 0; i--)
    if (qsig_op_tab[i].opcode == opcode)
      return &qsig_op_tab[i];
  return NULL;
}

static int32_t get_service(int32_t opcode) {
  if ((opcode < 0) || (opcode >= (int)array_length(op2srv_tab)))
    return NO_SRV;
  return op2srv_tab[opcode];
}

static const qsig_err_t *get_err(int32_t errcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_err_tab) - 1; i >= 0; i--)
    if (qsig_err_tab[i].errcode == errcode)
      return &qsig_err_tab[i];
  return NULL;
}

/*--- dissect_qsig_arg ------------------------------------------------------*/
static int
dissect_qsig_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  int32_t opcode = 0, service, oid_num;
  const qsig_op_t *op_ptr = NULL;
  const char *p, *oid;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code == 0) {  /* local */
    opcode = rctx->d.code_local;
    op_ptr = get_op(opcode);
  } else if (rctx->d.code == 1) {  /* global */
    oid = g_strrstr(rctx->d.code_global, ".");
    if (oid != NULL) {
     if (ws_strtou32(oid+1, NULL, &oid_num))
        op_ptr = get_op(oid_num);
    }
    if (op_ptr)
        opcode = op_ptr->opcode;
  } else {
    return offset;
  }
  if (!op_ptr)
    return offset;
  service = get_service(opcode);

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_captured_length(tvb), ENC_NA);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = try_val_to_str(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, qsig_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_expert(tree, pinfo, &ei_qsig_unsupported_error_type, tvb, offset, -1);
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_res -------------------------------------------------------*/
static int
dissect_qsig_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  int32_t opcode, service;
  const qsig_op_t *op_ptr;
  const char *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 2)  /* returnResult */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;
  service = get_service(opcode);

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_captured_length(tvb), ENC_NA);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = try_val_to_str(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, qsig_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_expert(tree, pinfo, &ei_qsig_unsupported_result_type, tvb, offset, -1);
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_err ------------------------------------------------------*/
static int
dissect_qsig_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  int32_t errcode;
  const qsig_err_t *err_ptr;
  const char *p;
  proto_item *ti;
  proto_tree *qsig_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 3)  /* returnError */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  errcode = rctx->d.code_local;
  err_ptr = get_err(errcode);
  if (!err_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_captured_length(tvb), ENC_NA);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_error, tvb, 0, 0, errcode);
  p = try_val_to_str(errcode, VALS(qsig_str_error));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu)
    offset = err_ptr->err_pdu(tvb, pinfo, qsig_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_expert(tree, pinfo, &ei_qsig_unsupported_error_type, tvb, offset, -1);
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_transit_counter_ie ---------------------------------------*/
static int
dissect_qsig_transit_counter_ie(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_tc, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  return offset;
}
/*--- dissect_qsig_party_category_ie ----------------------------------------*/
static int
dissect_qsig_party_category_ie(tvbuff_t *tvb, int offset, packet_info *pinfo  _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_pc, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  return offset;
}

/*--- dissect_qsig_ie -------------------------------------------------------*/
static void
dissect_qsig_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int codeset) {
  int offset;
  proto_item *ti, *hidden_item;
  proto_tree *ie_tree;
  uint8_t ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, -1, ENC_NA);
  proto_item_set_hidden(ti);

  ie_type = tvb_get_uint8(tvb, offset);
  ie_len = tvb_get_uint8(tvb, offset + 1);

  ie_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_qsig_ie, NULL,
            val_to_str(ie_type, VALS(qsig_str_ie_type[codeset]), "unknown (0x%02X)"));

  proto_tree_add_item(ie_tree, *hf_qsig_ie_type_arr[codeset], tvb, offset, 1, ENC_BIG_ENDIAN);
  hidden_item = proto_tree_add_item(ie_tree, hf_qsig_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_set_hidden(hidden_item);
  proto_tree_add_item(ie_tree, hf_qsig_ie_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  if (tvb_reported_length_remaining(tvb, offset) <= 0)
    return;
  switch ((codeset << 8) | ie_type) {
    case CS4 | QSIG_IE_TRANSIT_COUNTER :
      dissect_qsig_transit_counter_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    case CS5 | QSIG_IE_PARTY_CATEGORY :
      dissect_qsig_party_category_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    default:
      if (ie_len > 0) {
        if (tree) proto_tree_add_item(ie_tree, hf_qsig_ie_data, tvb, offset, ie_len, ENC_NA);
      }
  }
}
/*--- dissect_qsig_ie_cs4 ---------------------------------------------------*/
static int
dissect_qsig_ie_cs4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  dissect_qsig_ie(tvb, pinfo, tree, 4);
  return tvb_captured_length(tvb);
}
/*--- dissect_qsig_ie_cs5 ---------------------------------------------------*/
static int
dissect_qsig_ie_cs5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  dissect_qsig_ie(tvb, pinfo, tree, 5);
  return tvb_captured_length(tvb);
}

/*--- proto_register_qsig ---------------------------------------------------*/
void proto_register_qsig(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_qsig_operation, { "Operation", "qsig.operation",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_operation), 0x0,
                           NULL, HFILL }},
    { &hf_qsig_service,   { "Service", "qsig.service",
                           FT_UINT16, BASE_DEC, VALS(qsig_str_service), 0x0,
                           "Supplementary Service", HFILL }},
    { &hf_qsig_error,     { "Error", "qsig.error",
                           FT_UINT16, BASE_DEC, VALS(qsig_str_error), 0x0,
                           NULL, HFILL }},
    { &hf_qsig_ie_type, { "Type", "qsig.ie.type",
                          FT_UINT8, BASE_HEX, NULL, 0x0,
                          "Information Element Type", HFILL }},
    { &hf_qsig_ie_type_cs4, { "Type", "qsig.ie.type.cs4",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_ie_type_cs4), 0x0,
                          "Information Element Type (Codeset 4)", HFILL }},
    { &hf_qsig_ie_type_cs5, { "Type", "qsig.ie.type.cs5",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_ie_type_cs5), 0x0,
                          "Information Element Type (Codeset 5)", HFILL }},
    { &hf_qsig_ie_len,  { "Length", "qsig.ie.len",
                          FT_UINT8, BASE_DEC, NULL, 0x0,
                          "Information Element Length", HFILL }},
    { &hf_qsig_ie_data, { "Data", "qsig.ie.data",
                          FT_BYTES, BASE_NONE, NULL, 0x0,
                          NULL, HFILL }},
    { &hf_qsig_tc,      { "Transit count", "qsig.tc",
                          FT_UINT8, BASE_DEC, NULL, 0x1F,
                          NULL, HFILL }},
    { &hf_qsig_pc,      { "Party category", "qsig.pc",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_pc), 0x07,
                          NULL, HFILL }},
#include "packet-qsig-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_qsig,
    &ett_qsig_ie,
    &ett_qsig_unknown_extension,
#include "packet-qsig-ettarr.c"
    &ett_cnq_PSS1InformationElement,
  };

  static ei_register_info ei[] = {
#if 0
    { &ei_qsig_unsupported_arg_type, { "qsig.unsupported.arg_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED ARGUMENT TYPE (QSIG)", EXPFILL }},
#endif
    { &ei_qsig_unsupported_result_type, { "qsig.unsupported.result_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED RESULT TYPE (QSIG)", EXPFILL }},
    { &ei_qsig_unsupported_error_type, { "qsig.unsupported.error_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED ERROR TYPE (QSIG)", EXPFILL }},
  };

  expert_module_t* expert_qsig;

  /* Register protocol and dissector */
  proto_qsig = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_qsig, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_qsig = expert_register_protocol(proto_qsig);
  expert_register_field_array(expert_qsig, ei, array_length(ei));

  /* Register dissectors */
  qsig_arg_handle = register_dissector(PFNAME "_arg", dissect_qsig_arg, proto_qsig);
  qsig_res_handle = register_dissector(PFNAME "_res", dissect_qsig_res, proto_qsig);
  qsig_err_handle = register_dissector(PFNAME "_err", dissect_qsig_err, proto_qsig);
  qsig_ie4_handle = register_dissector(PFNAME "_ie_cs4", dissect_qsig_ie_cs4, proto_qsig);
  qsig_ie5_handle = register_dissector(PFNAME "_ie_cs5", dissect_qsig_ie_cs5, proto_qsig);

  /* Register dissector tables */
  extension_dissector_table = register_dissector_table("qsig.ext", "QSIG Extension", proto_qsig, FT_STRING, STRING_CASE_SENSITIVE);
}


/*--- proto_reg_handoff_qsig ------------------------------------------------*/
void proto_reg_handoff_qsig(void) {
  int i;
  char *oid;
  dissector_handle_t q931_handle;

  q931_handle = find_dissector_add_dependency("q931", proto_qsig);
  q931_ie_handle = find_dissector_add_dependency("q931.ie", proto_qsig);

  for (i=0; i<(int)array_length(qsig_op_tab); i++) {
    dissector_add_uint("q932.ros.local.arg", qsig_op_tab[i].opcode, qsig_arg_handle);
    dissector_add_uint("q932.ros.local.res", qsig_op_tab[i].opcode, qsig_res_handle);

    oid = wmem_strdup_printf(NULL, "1.3.12.9.%d", qsig_op_tab[i].opcode);
    dissector_add_string("q932.ros.global.arg", oid, qsig_arg_handle);
    dissector_add_string("q932.ros.global.res", oid, qsig_res_handle);
    wmem_free(NULL, oid);
  }
  for (i=0; i<(int)array_length(qsig_err_tab); i++) {
    dissector_add_uint("q932.ros.local.err", qsig_err_tab[i].errcode, qsig_err_handle);
  }

  /* QSIG-TC - Transit counter */
  dissector_add_uint("q931.ie", CS4 | QSIG_IE_TRANSIT_COUNTER, qsig_ie4_handle);

  /* SSIG-BC - Party category */
  dissector_add_uint("q931.ie", CS5 | QSIG_IE_PARTY_CATEGORY, qsig_ie5_handle);

  /* RFC 3204, 3.2 QSIG Media Type */
  dissector_add_string("media_type", "application/qsig", q931_handle);

}

/*---------------------------------------------------------------------------*/
