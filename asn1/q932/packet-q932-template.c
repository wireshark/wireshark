/* packet-q932.c
 * Routines for Q.932 packet dissection
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
#include "packet-q932.h"

#define PNAME  "Q.932"
#define PSNAME "Q932"
#define PFNAME "q932"

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

/* Preferences */

/* ROSE context */
static rose_ctx_t q932_rose_ctx;

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
/*static*/ void
dissect_q932_facility_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length) {
  gint8 class;
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
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
    offset = get_ber_length(tvb, offset, &len, NULL);
    eoffset = offset + len;
    next_tvb =  tvb_new_subset(tvb, hoffset, eoffset - hoffset, eoffset - hoffset);
    switch (class) {
      case BER_CLASS_CON:
        switch (tag) {
          case 10 :  /* Network Facility Extension */
            dissect_NetworkFacilityExtension_PDU(next_tvb, pinfo, tree);
            break;
          case 18 :  /* Network Protocol Profile */
            dissect_NetworkProtocolProfile_PDU(next_tvb, pinfo, tree);
            break;
          case 11 :  /* Interpretation Component */
            dissect_InterpretationComponent_PDU(next_tvb, pinfo, tree);
            break;
          /* ROSE APDU */
          case  1 :  /* invoke */
          case  2 :  /* returnResult */
          case  3 :  /* returnError */
          case  4 :  /* reject */
            q932_rose_ctx.apdu_depth = 1;
            pinfo->private_data = &q932_rose_ctx;
            call_dissector(q932_ros_handle, next_tvb, pinfo, tree);
            break;
          /* DSE APDU */
          case 12 :  /* begin */
          case 14 :  /* end */
          case 15 :  /* continue */
          case 17 :  /* abort */
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "DSE APDU (not supported)");
            break;
          default:
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "Unknown Component");
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
            proto_tree_add_text(tree, tvb, offset, len, "ACSE APDU (not supported)");
            break;
          default:
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "Unknown Component");
        }
        break;
      default:
        offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
        offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
        proto_tree_add_text(tree, tvb, offset, len, "Unknown Component");
    }
    offset = eoffset;
  }
}

/*--- dissect_q932_ni_ie -------------------------------------------------------*/
static void
dissect_q932_ni_ie(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length) {
  int remain = length;
  guint8 octet = 0;
  guint32 value = 0;

  while ((remain > 0) && !(octet & 0x80)) {
    octet = tvb_get_guint8(tvb, offset++);
    remain--;
    value <<= 7;
    value |= octet & 0x7F;
  }
  proto_tree_add_uint(tree, hf_q932_nd, tvb, offset - (length - remain), length - remain, value);

  if (remain > 0) {
    proto_tree_add_text(tree, tvb, offset - remain, remain, "ASN.1 Encoded Data Structure(NOT IMPLEMENTED): %s", tvb_bytes_to_str(tvb, offset - remain, remain));
  }
}

/*--- dissect_q932_ie -------------------------------------------------------*/
static void
dissect_q932_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset;
  proto_item *ti, *ti_ie;
  proto_tree *ie_tree;
  guint8 ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_q932, tvb, offset, -1, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(ti);

  ie_type = tvb_get_guint8(tvb, offset);
  ie_len = tvb_get_guint8(tvb, offset + 1);

  ti_ie = proto_tree_add_text(tree, tvb, offset, -1, "%s",
            val_to_str(ie_type, VALS(q932_str_ie_type), "unknown (0x%02X)"));
  ie_tree = proto_item_add_subtree(ti_ie, ett_q932_ie); 
  proto_tree_add_item(ie_tree, hf_q932_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ie_tree, hf_q932_ie_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  if (tvb_length_remaining(tvb, offset) <= 0)
    return;
  switch (ie_type) {
    case Q932_IE_FACILITY :
      dissect_q932_facility_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    case Q932_IE_NOTIFICATION_INDICATOR :
      dissect_q932_ni_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    default:
      if (ie_len > 0) {
        if (tree) proto_tree_add_item(ie_tree, hf_q932_ie_data, tvb, offset, ie_len, ENC_NA);
      }
  }
}

/*--- dissect_q932_apdu -----------------------------------------------------*/
static void
dissect_q932_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  call_dissector(q932_ros_handle, tvb, pinfo, tree);
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

  /* Register protocol and dissector */
  proto_q932 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("q932.apdu", dissect_q932_apdu, proto_q932);

  /* Register fields and subtrees */
  proto_register_field_array(proto_q932, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rose_ctx_init(&q932_rose_ctx);

  /* Register dissector tables */
  q932_rose_ctx.arg_global_dissector_table = register_dissector_table("q932.ros.global.arg", "Q.932 Operation Argument (global opcode)", FT_STRING, BASE_NONE);
  q932_rose_ctx.res_global_dissector_table = register_dissector_table("q932.ros.global.res", "Q.932 Operation Result (global opcode)", FT_STRING, BASE_NONE);
  q932_rose_ctx.arg_local_dissector_table = register_dissector_table("q932.ros.local.arg", "Q.932 Operation Argument (local opcode)", FT_UINT32, BASE_HEX); 
  q932_rose_ctx.res_local_dissector_table = register_dissector_table("q932.ros.local.res", "Q.932 Operation Result (local opcode)", FT_UINT32, BASE_HEX); 
  q932_rose_ctx.err_global_dissector_table = register_dissector_table("q932.ros.global.err", "Q.932 Error (global opcode)", FT_STRING, BASE_NONE);
  q932_rose_ctx.err_local_dissector_table = register_dissector_table("q932.ros.local.err", "Q.932 Error (local opcode)", FT_UINT32, BASE_HEX); 
}

/*--- proto_reg_handoff_q932 ------------------------------------------------*/
void proto_reg_handoff_q932(void) {
  dissector_handle_t q932_ie_handle;

  q932_ie_handle = create_dissector_handle(dissect_q932_ie, proto_q932);
  /* Facility */
  dissector_add_uint("q931.ie", (0x00 << 8) | Q932_IE_FACILITY, q932_ie_handle); 
  /* Notification indicator */
  dissector_add_uint("q931.ie", (0x00 << 8) | Q932_IE_NOTIFICATION_INDICATOR, q932_ie_handle); 

  q932_ros_handle = find_dissector("q932.ros");
}

/*---------------------------------------------------------------------------*/
