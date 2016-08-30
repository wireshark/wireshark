/* packet-q932.c
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-ber.h"
#include "packet-q932.h"

#define PNAME  "Q.932"
#define PSNAME "Q932"
#define PFNAME "q932"

void proto_register_q932(void);

/* Initialize the protocol and registered fields */
static int proto_q932 = -1;
static int hf_q932_ie_type = -1;
static int hf_q932_ie_len = -1;
static int hf_q932_ie_data = -1;
static int hf_q932_pp = -1;
static int hf_q932_nd = -1;
#include "packet-q932-hf.c"

/* Initialize the subtree pointers */
static gint ett_q932 = -1;
static gint ett_q932_ie = -1;
#include "packet-q932-ett.c"

static expert_field ei_q932_dse_not_supported = EI_INIT;
static expert_field ei_q932_acse_not_supported = EI_INIT;
static expert_field ei_q932_unknown_component = EI_INIT;
static expert_field ei_q932_asn1_encoded = EI_INIT;


/* Preferences */

/* ROSE context */
static rose_ctx_t q932_rose_ctx;

dissector_table_t qsig_arg_local_dissector_table;
dissector_table_t qsig_res_local_dissector_table;
dissector_table_t qsig_err_local_dissector_table;

dissector_table_t etsi_arg_local_dissector_table;
dissector_table_t etsi_res_local_dissector_table;
dissector_table_t etsi_err_local_dissector_table;

#define FACILITY_QSIG	0
#define FACILITY_ETSI	1
static gint g_facility_encoding = FACILITY_QSIG;

void proto_reg_handoff_q932(void);
/* Subdissectors */
static dissector_handle_t q932_ros_handle;

#define	Q932_IE_EXTENDED_FACILITY   0x0D
#define	Q932_IE_FACILITY            0x1C
#define	Q932_IE_NOTIFICATION_INDICATOR  0x27
#define	Q932_IE_INFORMATION_REQUEST 0x32
#define	Q932_IE_FEATURE_ACTIVATION  0x38
#define	Q932_IE_FEATURE_INDICATION  0x39
#define	Q932_IE_SERVICE_PROFILE_ID  0x3A
#define	Q932_IE_ENDPOINT_IDENTIFIER 0x3B
static const value_string q932_str_ie_type[] = {
  { Q932_IE_EXTENDED_FACILITY  , "Extended facility" },
  { Q932_IE_FACILITY           , "Facility" },
  { Q932_IE_NOTIFICATION_INDICATOR, "Notification indicator" },
  { Q932_IE_INFORMATION_REQUEST, "Information request" },
  { Q932_IE_FEATURE_ACTIVATION , "Feature activation" },
  { Q932_IE_FEATURE_INDICATION , "Feature indication" },
  { Q932_IE_SERVICE_PROFILE_ID , "Service profile identification" },
  { Q932_IE_ENDPOINT_IDENTIFIER, "Endpoint identifier" },
  { 0, NULL}
};

static const value_string str_pp[] = {
  { 0x11  , "Remote Operations Protocol" },
  { 0x12  , "CMIP Protocol" },
  { 0x13  , "ACSE Protocol" },
  { 0x1F  , "Networking extensions" },
  { 0, NULL}
};

static const value_string str_nd[] = {
  { 0x00  , "User suspended" },
  { 0x01  , "User resume" },
  { 0x02  , "Bearer service change" },
  { 0x04  , "Call completion delay" },
  { 0x03  , "Discriminator for extension to ASN.1 encoded component" },
  { 0x40  , "Discriminator for extension to ASN.1 encoded component for ISO" },
  { 0x42  , "Conference established" },
  { 0x43  , "Conference disconnected" },
  { 0x44  , "Other party added" },
  { 0x45  , "Isolated" },
  { 0x46  , "Reattached" },
  { 0x47  , "Other party isolated" },
  { 0x48  , "Other party reattached" },
  { 0x49  , "Other party split" },
  { 0x4A  , "Other party disconnected" },
  { 0x4B  , "Conference floating" },
  { 0x4C  , "Conference disconnected, pre-emption" },
  { 0x4F  , "Conference floating, served user pre-empted" },
  { 0x60  , "Call is a waiting call" },
  { 0x68  , "Diversion activated" },
  { 0x69  , "call transferred, alerting" },
  { 0x6A  , "call transferred, answered" },
  { 0x6E  , "reverse charging (whole call)" },
  { 0x6F  , "reverse charging (for the rest of the call)" },
  { 0x74  , "service profile update" },
  { 0x79  , "Remote hold" },
  { 0x7A  , "Remote retrieval" },
  { 0x7B  , "Call is diverting" },
  { 0, NULL}
};

#include "packet-q932-fn.c"

/*--- dissect_q932_facility_ie -------------------------------------------------------*/
static void
dissect_q932_facility_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length) {
  gint8 appclass;
  gboolean pc;
  gint32 tag;
  guint32 len;
  int hoffset, eoffset;
  int ie_end;
  tvbuff_t *next_tvb;

  ie_end = offset + length;
  proto_tree_add_item(tree, hf_q932_pp, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  while (offset < ie_end) {
    hoffset = offset;
    offset = get_ber_identifier(tvb, offset, &appclass, &pc, &tag);
    offset = get_ber_length(tvb, offset, &len, NULL);
    eoffset = offset + len;
    next_tvb =  tvb_new_subset_length(tvb, hoffset, eoffset - hoffset);
    switch (appclass) {
      case BER_CLASS_CON:
        switch (tag) {
          case 10 :  /* Network Facility Extension */
            dissect_NetworkFacilityExtension_PDU(next_tvb, pinfo, tree, NULL);
            break;
          case 18 :  /* Network Protocol Profile */
            dissect_NetworkProtocolProfile_PDU(next_tvb, pinfo, tree, NULL);
            break;
          case 11 :  /* Interpretation Component */
            dissect_InterpretationComponent_PDU(next_tvb, pinfo, tree, NULL);
            break;
          /* ROSE APDU */
          case  1 :  /* invoke */
          case  2 :  /* returnResult */
          case  3 :  /* returnError */
          case  4 :  /* reject */
            q932_rose_ctx.apdu_depth = 1;
            call_dissector_with_data(q932_ros_handle, next_tvb, pinfo, tree, &q932_rose_ctx);
            break;
          /* DSE APDU */
          case 12 :  /* begin */
          case 14 :  /* end */
          case 15 :  /* continue */
          case 17 :  /* abort */
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_expert(tree, pinfo, &ei_q932_dse_not_supported, tvb, offset, len);
            break;
          default:
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_expert(tree, pinfo, &ei_q932_unknown_component, tvb, offset, len);
        }
        break;
      case BER_CLASS_APP:
        switch (tag) {
          /* ACSE APDU */
          case  0 :  /* aarq */
          case  1 :  /* aare */
          case  2 :  /* rlrq */
          case  3 :  /* rlre */
          case  4 :  /* abrt */
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_expert(tree, pinfo, &ei_q932_acse_not_supported, tvb, offset, len);
            break;
          default:
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_expert(tree, pinfo, &ei_q932_unknown_component, tvb, offset, len);
        }
        break;
      default:
        offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
        offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
        proto_tree_add_expert(tree, pinfo, &ei_q932_unknown_component, tvb, offset, len);
    }
    offset = eoffset;
  }
}

/*--- dissect_q932_ni_ie -------------------------------------------------------*/
static void
dissect_q932_ni_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length) {
  int remain = length;
  guint8 octet = 0;
  guint32 value = 0;
  proto_item* ti;

  while ((remain > 0) && !(octet & 0x80)) {
    octet = tvb_get_guint8(tvb, offset++);
    remain--;
    value <<= 7;
    value |= octet & 0x7F;
  }
  ti = proto_tree_add_uint(tree, hf_q932_nd, tvb, offset - (length - remain), length - remain, value);

  if (remain > 0) {
    expert_add_info(pinfo, ti, &ei_q932_asn1_encoded);
  }
}

/*--- dissect_q932_ie -------------------------------------------------------*/
static int
dissect_q932_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  gint offset;
  proto_item *ti;
  proto_tree *ie_tree;
  guint8 ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_q932, tvb, offset, -1, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(ti);

  ie_type = tvb_get_guint8(tvb, offset);
  ie_len = tvb_get_guint8(tvb, offset + 1);

  ie_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_q932_ie, NULL,
            val_to_str(ie_type, VALS(q932_str_ie_type), "unknown (0x%02X)"));

  proto_tree_add_item(ie_tree, hf_q932_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ie_tree, hf_q932_ie_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  if (tvb_reported_length_remaining(tvb, offset) <= 0)
    return offset;
  switch (ie_type) {
    case Q932_IE_FACILITY :
      dissect_q932_facility_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    case Q932_IE_NOTIFICATION_INDICATOR :
      dissect_q932_ni_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    default:
      if (ie_len > 0) {
        proto_tree_add_item(ie_tree, hf_q932_ie_data, tvb, offset, ie_len, ENC_NA);
      }
  }
  return tvb_captured_length(tvb);
}

/*--- dissect_q932_apdu -----------------------------------------------------*/
static int
dissect_q932_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  return call_dissector(q932_ros_handle, tvb, pinfo, tree);
}

/*--- proto_register_q932 ---------------------------------------------------*/
void proto_register_q932(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_q932_ie_type, { "Type", "q932.ie.type",
                          FT_UINT8, BASE_HEX, VALS(q932_str_ie_type), 0x0,
                          "Information Element Type", HFILL }},
    { &hf_q932_ie_len,  { "Length", "q932.ie.len",
                          FT_UINT8, BASE_DEC, NULL, 0x0,
                          "Information Element Length", HFILL }},
    { &hf_q932_ie_data, { "Data", "q932.ie.data",
                          FT_BYTES, BASE_NONE, NULL, 0x0,
                          NULL, HFILL }},
    { &hf_q932_pp,      { "Protocol profile", "q932.pp",
                          FT_UINT8, BASE_HEX, VALS(str_pp), 0x1F,
                          NULL, HFILL }},
    { &hf_q932_nd,      { "Notification description", "q932.nd",
                          FT_UINT8, BASE_HEX, VALS(str_nd), 0x0,
                          NULL, HFILL }},
#include "packet-q932-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_q932,
    &ett_q932_ie,
#include "packet-q932-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_q932_dse_not_supported, { "q932.dse_not_supported", PI_UNDECODED, PI_WARN, "DSE APDU (not supported)", EXPFILL }},
    { &ei_q932_acse_not_supported, { "q932.acse_not_supported", PI_UNDECODED, PI_WARN, "ACSE APDU (not supported)", EXPFILL }},
    { &ei_q932_unknown_component, { "q932.unknown_component", PI_UNDECODED, PI_WARN, "Unknown Component", EXPFILL }},
    { &ei_q932_asn1_encoded, { "q932.asn1_encoded", PI_UNDECODED, PI_WARN, "ASN.1 Encoded Data Structure(NOT IMPLEMENTED)", EXPFILL }},
  };

  module_t *q932_module;
  expert_module_t* expert_q932;

  static const enum_val_t facility_encoding[] = {
    {"Facility as QSIG", "Dissect facility as QSIG", FACILITY_QSIG},
    {"Facility as ETSI", "Dissect facility as ETSI", FACILITY_ETSI},
    {NULL, NULL, -1}
  };

  /* Register protocol and dissector */
  proto_q932 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("q932.apdu", dissect_q932_apdu, proto_q932);

  /* Register fields and subtrees */
  proto_register_field_array(proto_q932, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_q932 = expert_register_protocol(proto_q932);
  expert_register_field_array(expert_q932, ei, array_length(ei));

  rose_ctx_init(&q932_rose_ctx);

  /* Register dissector tables */
  q932_rose_ctx.arg_global_dissector_table = register_dissector_table("q932.ros.global.arg", "Q.932 Operation Argument (global opcode)", proto_q932, FT_STRING, BASE_NONE);
  q932_rose_ctx.res_global_dissector_table = register_dissector_table("q932.ros.global.res", "Q.932 Operation Result (global opcode)", proto_q932, FT_STRING, BASE_NONE);
  q932_rose_ctx.err_global_dissector_table = register_dissector_table("q932.ros.global.err", "Q.932 Error (global opcode)", proto_q932, FT_STRING, BASE_NONE);

  qsig_arg_local_dissector_table = register_dissector_table("q932.ros.local.arg", "Q.932 Operation Argument (local opcode)", proto_q932, FT_UINT32, BASE_HEX);
  qsig_res_local_dissector_table = register_dissector_table("q932.ros.local.res", "Q.932 Operation Result (local opcode)", proto_q932, FT_UINT32, BASE_HEX);
  qsig_err_local_dissector_table = register_dissector_table("q932.ros.local.err", "Q.932 Error (local opcode)", proto_q932, FT_UINT32, BASE_HEX);

  etsi_arg_local_dissector_table = register_dissector_table("q932.ros.etsi.local.arg", "Q.932 ETSI Operation Argument (local opcode)", proto_q932, FT_UINT32, BASE_HEX);
  etsi_res_local_dissector_table = register_dissector_table("q932.ros.etsi.local.res", "Q.932 ETSI Operation Result (local opcode)", proto_q932, FT_UINT32, BASE_HEX);
  etsi_err_local_dissector_table = register_dissector_table("q932.ros.etsi.local.err", "Q.932 ETSI Error (local opcode)", proto_q932, FT_UINT32, BASE_HEX);

  q932_module = prefs_register_protocol(proto_q932, proto_reg_handoff_q932);

  prefs_register_enum_preference(q932_module, "facility_encoding",
                       "Type of Facility encoding",
                       "Type of Facility encoding",
                       &g_facility_encoding, facility_encoding, FALSE);
}

/*--- proto_reg_handoff_q932 ------------------------------------------------*/
void proto_reg_handoff_q932(void) {
  dissector_handle_t q932_ie_handle;

  static gboolean q931_prefs_initialized = FALSE;

  if (!q931_prefs_initialized) {
    q932_ie_handle = create_dissector_handle(dissect_q932_ie, proto_q932);
    /* Facility */
    dissector_add_uint("q931.ie", (0x00 << 8) | Q932_IE_FACILITY, q932_ie_handle);
    /* Notification indicator */
    dissector_add_uint("q931.ie", (0x00 << 8) | Q932_IE_NOTIFICATION_INDICATOR, q932_ie_handle);
    q932_ros_handle = find_dissector_add_dependency("q932.ros", proto_q932);
  }

  if(g_facility_encoding == FACILITY_QSIG){
    q932_rose_ctx.arg_local_dissector_table = qsig_arg_local_dissector_table;
    q932_rose_ctx.res_local_dissector_table = qsig_res_local_dissector_table;
    q932_rose_ctx.err_local_dissector_table = qsig_err_local_dissector_table;
  }else{
    q932_rose_ctx.arg_local_dissector_table = etsi_arg_local_dissector_table;
    q932_rose_ctx.res_local_dissector_table = etsi_res_local_dissector_table;
    q932_rose_ctx.err_local_dissector_table = etsi_err_local_dissector_table;
  }

}

/*---------------------------------------------------------------------------*/
