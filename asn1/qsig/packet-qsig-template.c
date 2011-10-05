/* packet-qsig.c
 * Routines for QSIG packet dissection
 * 2007  Tomas Kukosa
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>

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
static const gint32 op2srv_tab[] = {
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
static int proto_qsig = -1;
static int hf_qsig_operation = -1;
static int hf_qsig_service = -1;
static int hf_qsig_error = -1;
static int hf_qsig_ie_type = -1;
static int hf_qsig_ie_type_cs4 = -1;
static int hf_qsig_ie_type_cs5 = -1;
static int hf_qsig_ie_len = -1;
static int hf_qsig_ie_data = -1;
static int hf_qsig_tc = -1;
static int hf_qsig_pc = -1;
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
static gint ett_qsig = -1;
static gint ett_qsig_ie = -1;
static gint ett_qsig_unknown_extension = -1;
#include "packet-qsig-ett.c"
static gint ett_cnq_PSS1InformationElement = -1;

/* Preferences */

/* Subdissectors */
static dissector_handle_t q931_ie_handle = NULL;

/* Global variables */
static const char *extension_oid = NULL;
static GHashTable *qsig_opcode2oid_hashtable = NULL;
static GHashTable *qsig_oid2op_hashtable = NULL;

/* Dissector tables */
static dissector_table_t extension_dissector_table;

#include "packet-qsig-fn.c"

typedef struct _qsig_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} qsig_op_t;

static const qsig_op_t qsig_op_tab[] = {
#include "packet-qsig-table11.c"
};

typedef struct _qsig_err_t {
  gint32 errcode;
  new_dissector_t err_pdu;
} qsig_err_t;

static const qsig_err_t qsig_err_tab[] = {
#include "packet-qsig-table21.c"
};

static const qsig_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_op_tab) - 1; i >= 0; i--)
    if (qsig_op_tab[i].opcode == opcode)
      return &qsig_op_tab[i];
  return NULL;
}

static gint32 get_service(gint32 opcode) {
  if ((opcode < 0) || (opcode >= (int)array_length(op2srv_tab)))
    return NO_SRV;
  return op2srv_tab[opcode];
}

static const qsig_err_t *get_err(gint32 errcode) {
  int i;

  /* search from the end to get the last occurence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_err_tab) - 1; i >= 0; i--)
    if (qsig_err_tab[i].errcode == errcode)
      return &qsig_err_tab[i];
  return NULL;
}

/*--- dissect_qsig_arg ------------------------------------------------------*/
static int
dissect_qsig_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset;
  rose_ctx_t *rctx;
  gint32 opcode = 0, service;
  const qsig_op_t *op_ptr;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code == 0) {  /* local */
    opcode = rctx->d.code_local;
    op_ptr = get_op(opcode);
  } else if (rctx->d.code == 1) {  /* global */
    op_ptr = g_hash_table_lookup(qsig_oid2op_hashtable, rctx->d.code_global);
    if (op_ptr) opcode = op_ptr->opcode;
  } else {
    return offset;
  }
  if (!op_ptr)
    return offset;
  service = get_service(opcode);

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = match_strval(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, qsig_tree);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (QSIG)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_res -------------------------------------------------------*/
static int
dissect_qsig_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset;
  rose_ctx_t *rctx;
  gint32 opcode, service;
  const qsig_op_t *op_ptr;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
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

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = match_strval(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, qsig_tree);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (QSIG)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_err ------------------------------------------------------*/
static int
dissect_qsig_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset;
  rose_ctx_t *rctx;
  gint32 errcode;
  const qsig_err_t *err_ptr;
  const gchar *p;
  proto_item *ti;
  proto_tree *qsig_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 3)  /* returnError */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  errcode = rctx->d.code_local;
  err_ptr = get_err(errcode);
  if (!err_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_error, tvb, 0, 0, errcode);
  p = match_strval(errcode, VALS(qsig_str_error));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu)
    offset = err_ptr->err_pdu(tvb, pinfo, qsig_tree);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED ERROR TYPE (QSIG)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_transit_counter_ie ---------------------------------------*/
static int
dissect_qsig_transit_counter_ie(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_tc, tvb, offset, 1, FALSE);
  offset++;
  return offset;
}
/*--- dissect_qsig_party_category_ie ----------------------------------------*/
static int
dissect_qsig_party_category_ie(tvbuff_t *tvb, int offset, packet_info *pinfo  _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_pc, tvb, offset, 1, FALSE);
  offset++;
  return offset;
}

/*--- dissect_qsig_ie -------------------------------------------------------*/
static void
dissect_qsig_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int codeset) {
  gint offset;
  proto_item *ti, *ti_ie, *hidden_item;
  proto_tree *ie_tree;
  guint8 ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, -1, FALSE);
  PROTO_ITEM_SET_HIDDEN(ti);

  ie_type = tvb_get_guint8(tvb, offset);
  ie_len = tvb_get_guint8(tvb, offset + 1);

  ti_ie = proto_tree_add_text(tree, tvb, offset, -1, "%s",
            val_to_str(ie_type, VALS(qsig_str_ie_type[codeset]), "unknown (0x%02X)"));
  ie_tree = proto_item_add_subtree(ti_ie, ett_qsig_ie);
  proto_tree_add_item(ie_tree, *hf_qsig_ie_type_arr[codeset], tvb, offset, 1, FALSE);
  hidden_item = proto_tree_add_item(ie_tree, hf_qsig_ie_type, tvb, offset, 1, FALSE);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  proto_tree_add_item(ie_tree, hf_qsig_ie_len, tvb, offset + 1, 1, FALSE);
  offset += 2;
  if (tvb_length_remaining(tvb, offset) <= 0)
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
static void
dissect_qsig_ie_cs4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_qsig_ie(tvb, pinfo, tree, 4);
}
/*--- dissect_qsig_ie_cs5 ---------------------------------------------------*/
static void
dissect_qsig_ie_cs5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_qsig_ie(tvb, pinfo, tree, 5);
}

/*--- qsig_init_tables ---------------------------------------------------------*/
static void qsig_init_tables(void) {
  guint i;
  gint opcode, *key;
  gchar *oid;

  if (qsig_opcode2oid_hashtable)
    g_hash_table_destroy(qsig_opcode2oid_hashtable);
  qsig_opcode2oid_hashtable = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);

  if (qsig_oid2op_hashtable)
    g_hash_table_destroy(qsig_oid2op_hashtable);
  qsig_oid2op_hashtable = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  /* fill-in global OIDs */
  for (i=0; i<array_length(qsig_op_tab); i++) {
    opcode = qsig_op_tab[i].opcode;
    oid = g_strdup_printf("1.3.12.9.%d", opcode);
    key = g_malloc(sizeof(gint));
    *key = opcode;
    g_hash_table_insert(qsig_opcode2oid_hashtable, key, oid);
    g_hash_table_insert(qsig_oid2op_hashtable, g_strdup(oid), (gpointer)&qsig_op_tab[i]);
  }

}

/*--- proto_register_qsig ---------------------------------------------------*/
void proto_register_qsig(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_qsig_operation, { "Operation", "qsig.operation",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_operation), 0x0,
                           NULL, HFILL }},
    { &hf_qsig_service,   { "Service", "qsig.service",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_service), 0x0,
                           "Supplementary Service", HFILL }},
    { &hf_qsig_error,     { "Error", "qsig.error",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_error), 0x0,
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
  static gint *ett[] = {
    &ett_qsig,
    &ett_qsig_ie,
    &ett_qsig_unknown_extension,
#include "packet-qsig-ettarr.c"
    &ett_cnq_PSS1InformationElement,
  };

  /* Register protocol and dissector */
  proto_qsig = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_qsig, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector tables */
  extension_dissector_table = register_dissector_table("qsig.ext", "QSIG Extension", FT_STRING, BASE_NONE);

  qsig_init_tables();
}


/*--- proto_reg_handoff_qsig ------------------------------------------------*/
void proto_reg_handoff_qsig(void) {
  int i;
  gint key;
  const gchar *oid;
  dissector_handle_t q931_handle;
  dissector_handle_t qsig_arg_handle;
  dissector_handle_t qsig_res_handle;
  dissector_handle_t qsig_err_handle;
  dissector_handle_t qsig_ie_handle;

  q931_handle = find_dissector("q931");
  q931_ie_handle = find_dissector("q931.ie");

  qsig_arg_handle = new_create_dissector_handle(dissect_qsig_arg, proto_qsig);
  qsig_res_handle = new_create_dissector_handle(dissect_qsig_res, proto_qsig);
  for (i=0; i<(int)array_length(qsig_op_tab); i++) {
    dissector_add_uint("q932.ros.local.arg", qsig_op_tab[i].opcode, qsig_arg_handle);
    dissector_add_uint("q932.ros.local.res", qsig_op_tab[i].opcode, qsig_res_handle);
    key = qsig_op_tab[i].opcode;
    oid = g_hash_table_lookup(qsig_opcode2oid_hashtable, &key);
    if (oid) {
      dissector_add_string("q932.ros.global.arg", oid, qsig_arg_handle);
      dissector_add_string("q932.ros.global.res", oid, qsig_res_handle);
    }
  }
  qsig_err_handle = new_create_dissector_handle(dissect_qsig_err, proto_qsig);
  for (i=0; i<(int)array_length(qsig_err_tab); i++) {
    dissector_add_uint("q932.ros.local.err", qsig_err_tab[i].errcode, qsig_err_handle);
  }

  qsig_ie_handle = create_dissector_handle(dissect_qsig_ie_cs4, proto_qsig);
  /* QSIG-TC - Transit counter */
  dissector_add_uint("q931.ie", CS4 | QSIG_IE_TRANSIT_COUNTER, qsig_ie_handle);

  qsig_ie_handle = create_dissector_handle(dissect_qsig_ie_cs5, proto_qsig);
  /* SSIG-BC - Party category */
  dissector_add_uint("q931.ie", CS5 | QSIG_IE_PARTY_CATEGORY, qsig_ie_handle);

  /* RFC 3204, 3.2 QSIG Media Type */
  dissector_add_string("media_type", "application/qsig", q931_handle);

}

/*---------------------------------------------------------------------------*/
