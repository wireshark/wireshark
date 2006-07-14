/* packet-pana.c
 * Routines for Protocol for carrying Authentication for Network Access dissection
 * Copyright 2006, Peter Racz <racz@ifi.unizh.ch>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/value_string.h>

#define PANA_UDP_PORT 3001
#define PANA_VERSION 1

#define MIN_AVP_SIZE 8

#define PANA_FLAG_R 0x8000
#define PANA_FLAG_S 0x4000
#define PANA_FLAG_N 0x2000
#define PANA_FLAG_L 0x1000
#define PANA_FLAG_RES4 0x0800
#define PANA_FLAG_RES5 0x0400
#define PANA_FLAG_RES6 0x0200
#define PANA_FLAG_RES7 0x0100
#define PANA_FLAG_RES8 0x0080
#define PANA_FLAG_RES9 0x0040
#define PANA_FLAG_RES10 0x0020
#define PANA_FLAG_RES11 0x0010
#define PANA_FLAG_RES12 0x0008
#define PANA_FLAG_RES13 0x0004
#define PANA_FLAG_RES14 0x0002
#define PANA_FLAG_RES15 0x0001
#define PANA_FLAG_RES 0x0fff

#define PANA_AVP_FLAG_V 0x8000
#define PANA_AVP_FLAG_M 0x4000
#define PANA_AVP_FLAG_RES2 0x2000
#define PANA_AVP_FLAG_RES3 0x1000
#define PANA_AVP_FLAG_RES4 0x0800
#define PANA_AVP_FLAG_RES5 0x0400
#define PANA_AVP_FLAG_RES6 0x0200
#define PANA_AVP_FLAG_RES7 0x0100
#define PANA_AVP_FLAG_RES8 0x0080
#define PANA_AVP_FLAG_RES9 0x0040
#define PANA_AVP_FLAG_RES10 0x0020
#define PANA_AVP_FLAG_RES11 0x0010
#define PANA_AVP_FLAG_RES12 0x0008
#define PANA_AVP_FLAG_RES13 0x0004
#define PANA_AVP_FLAG_RES14 0x0002
#define PANA_AVP_FLAG_RES15 0x0001
#define PANA_AVP_FLAG_RES 0x3fff


/* Initialize the protocol and registered fields */
static int proto_pana = -1;
static int hf_pana_version_type = -1;
static int hf_pana_reserved_type = -1;
static int hf_pana_length_type = -1;
static int hf_pana_msg_type = -1;
static int hf_pana_seqnumber = -1;

static dissector_handle_t pana_handle = NULL;
static dissector_handle_t eap_handle = NULL;

static int hf_pana_flags = -1;
static int hf_pana_flag_r = -1;
static int hf_pana_flag_s = -1;
static int hf_pana_flag_n = -1;
static int hf_pana_flag_l = -1;
static int hf_pana_flag_res4 = -1;
static int hf_pana_flag_res5 = -1;
static int hf_pana_flag_res6 = -1;
static int hf_pana_flag_res7 = -1;
static int hf_pana_flag_res8 = -1;
static int hf_pana_flag_res9 = -1;
static int hf_pana_flag_res10 = -1;
static int hf_pana_flag_res11 = -1;
static int hf_pana_flag_res12 = -1;
static int hf_pana_flag_res13 = -1;
static int hf_pana_flag_res14 = -1;
static int hf_pana_flag_res15 = -1;

static int hf_pana_avp_code = -1;
static int hf_pana_avp_length = -1;
static int hf_pana_avp_flags = -1;
static int hf_pana_avp_flag_v = -1;
static int hf_pana_avp_flag_m = -1;
static int hf_pana_avp_flag_res2 = -1;
static int hf_pana_avp_flag_res3 = -1;
static int hf_pana_avp_flag_res4 = -1;
static int hf_pana_avp_flag_res5 = -1;
static int hf_pana_avp_flag_res6 = -1;
static int hf_pana_avp_flag_res7 = -1;
static int hf_pana_avp_flag_res8 = -1;
static int hf_pana_avp_flag_res9 = -1;
static int hf_pana_avp_flag_res10 = -1;
static int hf_pana_avp_flag_res11 = -1;
static int hf_pana_avp_flag_res12 = -1;
static int hf_pana_avp_flag_res13 = -1;
static int hf_pana_avp_flag_res14 = -1;
static int hf_pana_avp_flag_res15 = -1;
static int hf_pana_avp_reserved = -1;
static int hf_pana_avp_vendorid = -1;

static int hf_pana_avp_data_uint64 = -1;
static int hf_pana_avp_data_int64 = -1;
static int hf_pana_avp_data_uint32 = -1;
static int hf_pana_avp_data_int32 = -1;
static int hf_pana_avp_data_bytes = -1;
static int hf_pana_avp_data_string = -1;
static int hf_pana_avp_data_enumerated = -1;
static int hf_pana_avp_data_addrfamily = -1;
static int hf_pana_avp_data_ipv4 = -1;
static int hf_pana_avp_data_ipv6 = -1;

static const value_string msg_type_names[] = {
       { 1, "PANA-PAA-Discover" },
       { 2, "PANA-Start" },
       { 3, "PANA-Auth" },
       { 4, "PANA-Reauth" },
       { 5, "PANA-Bind" },
       { 6, "PANA-Ping" },
       { 7, "PANA-Termination" },
       { 8, "PANA-Error" },
       { 9, "PANA-FirstAuth-End" },
       { 10, "PANA-Update" },
       { 0, NULL }
};

static const value_string msg_subtype_names[] = {
       { 0x0000, "Answer" },
       { 0x8000, "Request" },
       { 0, NULL }
};

static const value_string avp_code_names[] = {
       { 1, "Algorithm AVP" },
       { 2, "AUTH AVP" },
       { 3, "Cookie AVP" },
       { 4, "Device-Id AVP" },
       { 5, "EAP-Payload AVP" },
       { 6, "Failed-AVP AVP" },
       { 7, "ISP-Information AVP" },
       { 8, "Key-Id AVP" },
       { 9, "NAP-Information AVP" },
       { 10, "Nonce AVP" },
       { 11, "Notification AVP" },
       { 12, "PPAC AVP" },
       { 13, "Protection-Capability AVP" },
       { 14, "Provider-Identifier AVP" },
       { 15, "Provider-Name AVP" },
       { 16, "Result-Code" },
       { 17, "Session-Id" },
       { 18, "Session-Lifetime" },
       { 19, "Termination-Cause" },
       { 0, NULL }
};

static const value_string avp_resultcode_names[] = {
       { 2001, "PANA_SUCCESS" },
       { 3001, "PANA_MESSAGE_UNSUPPORTED" },
       { 3002, "PANA_UNABLE_TO_DELIVER" },
       { 3008, "PANA_INVALID_HDR_BITS" },
       { 3009, "PANA_INVALID_AVP_FLAGS" },
       { 4001, "PANA_AUTHENTICATION_REJECTED" },
       { 5001, "PANA_AVP_UNSUPPORTED" },
       { 5002, "PANA_UNKNOWN_SESSION_ID" },
       { 5003, "PANA_AUTHORIZATION_REJECTED" },
       { 5004, "PANA_INVALID_AVP_DATA" },
       { 5005, "PANA_MISSING_AVP" },
       { 5006, "PANA_RESOURCES_EXCEEDED" },
       { 5007, "PANA_CONTRADICTING_AVPS" },
       { 5008, "PANA_AVP_NOT_ALLOWED" },
       { 5009, "PANA_AVP_OCCURS_TOO_MANY_TIMES" },
       { 5011, "PANA_UNSUPPORTED_VERSION" },
       { 5012, "PANA_UNABLE_TO_COMPLY" },
       { 5014, "PANA_INVALID_AVP_LENGTH" },
       { 5015, "PANA_INVALID_MESSAGE_LENGTH" },
       { 5016, "PANA_PROTECTION_CAPABILITY_UNSUPPORTED" },
       { 5017, "PANA_PPAC_CAPABILITY_UNSUPPORTED" },
       { 0, NULL }
};

typedef enum {
  PANA_OCTET_STRING = 1,
  PANA_INTEGER32,
  PANA_INTEGER64,
  PANA_UNSIGNED32,
  PANA_UNSIGNED64,
  PANA_FLOAT32,
  PANA_FLOAT64,
  PANA_FLOAT128,
  PANA_GROUPED,
  PANA_ENUMERATED,
  PANA_UTF8STRING,
  PANA_IP_ADDRESS,
  PANA_EAP,
  PANA_RESULT_CODE
} pana_avp_types;

static const value_string avp_type_names[]={
       { PANA_OCTET_STRING,"OctetString" },
       { PANA_INTEGER32,       "Integer32" },
       { PANA_INTEGER64,       "Integer64" },
       { PANA_UNSIGNED32,      "Unsigned32" },
       { PANA_UNSIGNED64,      "Unsigned64" },
       { PANA_FLOAT32,         "Float32" },
       { PANA_FLOAT64,         "Float64" },
       { PANA_FLOAT128,        "Float128" },
       { PANA_GROUPED,         "Grouped" },
       { PANA_ENUMERATED,      "Enumerated" },
       { PANA_UTF8STRING,      "UTF8String" },
       { PANA_IP_ADDRESS,      "IPAddress" },
       { PANA_EAP,             "OctetString" },
       { PANA_RESULT_CODE,     "Unsigned32" },
       { 0, NULL }
};


/* Initialize the subtree pointers */
static gint ett_pana = -1;
static gint ett_pana_flags = -1;
static gint ett_pana_avp = -1;
static gint ett_pana_avp_info = -1;
static gint ett_pana_avp_flags = -1;



/*
 * Function for the PANA flags dissector.
 */
static void
dissect_pana_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags)
{
       proto_item *flags_item=NULL;
       proto_tree *flags_tree=NULL;

       if(!parent_tree) return;

       flags_item = proto_tree_add_uint(parent_tree, hf_pana_flags, tvb,
                                             offset, 2, flags);
       flags_tree = proto_item_add_subtree(flags_item, ett_pana_flags);

       proto_tree_add_boolean(flags_tree, hf_pana_flag_r, tvb, offset, 2, flags);
       if (flags & PANA_FLAG_R)
               proto_item_append_text(flags_item, ", Request");
       else
               proto_item_append_text(flags_item, ", Answer");
       proto_tree_add_boolean(flags_tree, hf_pana_flag_s, tvb, offset, 2, flags);
       if (flags & PANA_FLAG_S)
               proto_item_append_text(flags_item, ", S flag set");
       proto_tree_add_boolean(flags_tree, hf_pana_flag_n, tvb, offset, 2, flags);
       if (flags & PANA_FLAG_N)
               proto_item_append_text(flags_item, ", N flag set");
       proto_tree_add_boolean(flags_tree, hf_pana_flag_l, tvb, offset, 2, flags);
       if (flags & PANA_FLAG_L)
               proto_item_append_text(flags_item, ", L flag set");
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res4, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res5, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res6, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res7, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res8, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res9, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res10, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res11, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res12, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res13, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res14, tvb, offset, 2, flags);
       proto_tree_add_boolean(flags_tree, hf_pana_flag_res15, tvb, offset, 2, flags);

}


/*
 * Function for AVP flags dissector.
 */
static void
dissect_pana_avp_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags)
{
       proto_item *avp_flags_item=NULL;
       proto_tree *avp_flags_tree=NULL;

       if(!parent_tree) return;

       avp_flags_item = proto_tree_add_uint(parent_tree, hf_pana_avp_flags, tvb,
                                                       offset, 2, flags);
       avp_flags_tree = proto_item_add_subtree(avp_flags_item, ett_pana_avp_flags);

       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_v, tvb, offset, 2, flags);
       if (flags & PANA_AVP_FLAG_V)
               proto_item_append_text(avp_flags_item, ", Vendor");
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_m, tvb, offset, 2, flags);
       if (flags & PANA_AVP_FLAG_M)
               proto_item_append_text(avp_flags_item, ", Mandatory");
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res2, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res3, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res4, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res5, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res6, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res7, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res8, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res9, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res10, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res11, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res12, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res13, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res14, tvb, offset, 2, flags);
       proto_tree_add_boolean(avp_flags_tree, hf_pana_avp_flag_res15, tvb, offset, 2, flags);

}


/*
 * Map AVP code to AVP type
 */
static pana_avp_types
pana_avp_get_type(guint16 avp_code, guint32 vendor_id)
{

       if(vendor_id == 0) {
               switch(avp_code) {
                       case 1: return PANA_UNSIGNED32;         /* Algorithm AVP */
                       case 2: return PANA_OCTET_STRING;       /* AUTH AVP */
                       case 3: return PANA_OCTET_STRING;       /* Cookie AVP */
                       case 4: return PANA_UNSIGNED64;         /* Device-Id AVP, it should be PANA_IP_ADDRESS*/
                       case 5: return PANA_EAP;                        /* EAP-Payload AVP */
                       case 6: return PANA_GROUPED;            /* Failed-AVP AVP */
                       case 7: return PANA_GROUPED;            /* ISP-Information AVP */
                       case 8: return PANA_INTEGER32;          /* Key-Id AVP */
                       case 9: return PANA_GROUPED;            /* NAP-Information AVP */
                       case 10: return PANA_OCTET_STRING;      /* Nonce AVP */
                       case 11: return PANA_OCTET_STRING;      /* Notification AVP */
                       case 12: return PANA_UNSIGNED32;        /* Post-PANA-Address-Configuration (PPAC) AVP */
                       case 13: return PANA_UNSIGNED32;        /* Protection-Capability AVP */
                       case 14: return PANA_UNSIGNED32;        /* Provider-Identifier AVP */
                       case 15: return PANA_UTF8STRING;        /* Provider-Name AVP */
                       case 16: return PANA_RESULT_CODE;       /* Result-Code AVP */
                       case 17: return PANA_UTF8STRING;        /* Session-Id AVP */
                       case 18: return PANA_UNSIGNED32;        /* Session-Lifetime AVP */
                       case 19: return PANA_ENUMERATED;        /* Termination-Cause AVP */
                       default: return PANA_OCTET_STRING;
               }
       } else {
               return PANA_OCTET_STRING;
       }
}




/*
 * Function for AVP dissector.
 */
static void
dissect_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *avp_tree)
{

       gint offset;
       guint16 avp_code;
       guint16 avp_flags;
       guint16 avp_length;
       guint16 avp_type;
       guint32 vendor_id;
       guint16 avp_hdr_length;
       guint16 avp_data_length;
       guint16 padding;

       guint16 buffer_length;
       int bad_avp = FALSE;

       tvbuff_t *group_tvb;
       tvbuff_t *eap_tvb;
       proto_item *single_avp_item;
       proto_tree *single_avp_tree;
       proto_item *avp_group_item;
       proto_tree *avp_group_tree;
       proto_item *avp_eap_item;
       proto_tree *avp_eap_tree;

       offset = 0;
       buffer_length = 0;
       buffer_length = tvb_length(tvb);

       if (buffer_length <= 0) {
               proto_tree_add_text(avp_tree, tvb, offset, tvb_length(tvb),     "No Attribute Value Pairs Found");
               return;
       }

       /* Go through all AVPs */
       while (buffer_length > 0 ) {
               /* Check buffer length */
               if (buffer_length < MIN_AVP_SIZE) return;

               avp_code = tvb_get_ntohs(tvb, offset);
               avp_flags = tvb_get_ntohs(tvb, offset + 2);
               avp_length = tvb_get_ntohs(tvb, offset + 4);

               /* Check AVP flags for vendor specific AVP */
               if (avp_flags & PANA_AVP_FLAG_V) {
                       vendor_id = tvb_get_ntohl(tvb, 8);
                       avp_hdr_length = 12;
               } else {
                       vendor_id = 0;
                       avp_hdr_length = 8;
               }

               /* Check AVP type */
               avp_type = pana_avp_get_type(avp_code, vendor_id);

               /* AVP data length */
               avp_data_length = avp_length - avp_hdr_length;

               /* Check AVP length */
               if ((avp_length < MIN_AVP_SIZE) || (avp_length > buffer_length)) bad_avp = TRUE;
               /* Check AVP flags */
               if (avp_flags & PANA_AVP_FLAG_RES) bad_avp = TRUE;

               /* Check padding */
               padding = (4 - (avp_length % 4)) % 4;

               single_avp_item = proto_tree_add_text(avp_tree, tvb, offset, avp_length + padding,
                                                               "%s (%s) length: %d bytes (%d padded bytes)",
                                                               val_to_str(avp_code, avp_code_names, "Unknown (%d)"),
                                                               val_to_str(avp_type, avp_type_names, "Unknown (%d)"),
                                                               avp_length,
                                                               avp_length + padding);

               single_avp_tree = proto_item_add_subtree(single_avp_item, ett_pana_avp_info);

               if (single_avp_tree != NULL) {
                       /* AVP Code */
                       proto_tree_add_uint_format_value(single_avp_tree, hf_pana_avp_code, tvb,
                                                       offset, 2, avp_code, "%s (%u)",
                                                       val_to_str(avp_code, avp_code_names, "Unknown (%d)"),
                                                       avp_code);
                       offset += 2;
                       /* AVP Flags */
                       dissect_pana_avp_flags(single_avp_tree, tvb, offset, avp_flags);
                       offset += 2;
                       /* AVP Length */
                       proto_tree_add_item(single_avp_tree, hf_pana_avp_length, tvb, offset, 2, FALSE);
                       offset += 2;
                       /* Reserved */
                       proto_tree_add_item(single_avp_tree, hf_pana_avp_reserved, tvb, offset, 2, FALSE);
                       offset += 2;
                       /* Vendor ID */
                       if (avp_flags & PANA_AVP_FLAG_V) {
                               proto_tree_add_item(single_avp_tree, hf_pana_avp_vendorid, tvb, offset, 4, FALSE);
                               offset += 4;
                       }
                       /* AVP Value */
                       switch(avp_type) {
                               case PANA_GROUPED: {
                                       avp_group_item = proto_tree_add_text(single_avp_tree,
                                                                         tvb, offset, avp_data_length,
                                                                         "Grouped AVP");
                                       avp_group_tree = proto_item_add_subtree(avp_group_item, ett_pana_avp);
                                       group_tvb = tvb_new_subset(tvb, offset,
                                                                       MIN(avp_data_length, tvb_length(tvb)-offset), avp_data_length);
                                       if (avp_group_tree != NULL) {
                                               dissect_avps(group_tvb, pinfo, avp_group_tree);
                                       }
                                       break;
                               }
                               case PANA_UTF8STRING: {
                                       const guint8 *data;
                                       data = tvb_get_ptr(tvb, offset, avp_data_length);
                                       proto_tree_add_string_format(single_avp_tree, hf_pana_avp_data_string, tvb,
                                                       offset, avp_data_length, data,
                                                       "UTF8String: %*.*s",
                                                       avp_data_length, avp_data_length, data);
                                       break;
                               }
                               case PANA_OCTET_STRING: {
                                       proto_tree_add_bytes_format(single_avp_tree, hf_pana_avp_data_bytes, tvb,
                                                       offset, avp_data_length,
                                                   tvb_get_ptr(tvb, offset, avp_data_length),
                                                       "Hex Data Highlighted Below");
                                       break;
                               }
                               case PANA_INTEGER32: {
                                       proto_tree_add_item(single_avp_tree, hf_pana_avp_data_int32, tvb,
                                                       offset, 4, FALSE);
                                       break;
                               }
                               case PANA_UNSIGNED32: {
                                       proto_tree_add_item(single_avp_tree, hf_pana_avp_data_uint32, tvb,
                                                       offset, 4, FALSE);
                                       break;
                               }
                               case PANA_INTEGER64: {
                                       proto_tree_add_item(single_avp_tree, hf_pana_avp_data_int64, tvb,
                                                       offset, 8, FALSE);
                                       break;
                               }
                               case PANA_UNSIGNED64: {
                                       proto_tree_add_item(single_avp_tree, hf_pana_avp_data_uint64, tvb,
                                                       offset, 8, FALSE);
                                       break;
                               }
                               case PANA_ENUMERATED: {
                                       proto_tree_add_item(single_avp_tree, hf_pana_avp_data_enumerated, tvb,
                                                       offset, 4, FALSE);
                                       break;
                               }
                               case PANA_IP_ADDRESS: {
                                       proto_tree_add_item(single_avp_tree, hf_pana_avp_data_addrfamily, tvb,
                                                       offset, 2, FALSE);
                                       if (tvb_get_ntohs(tvb, offset) == 0x0001) {
                                               proto_tree_add_item(single_avp_tree, hf_pana_avp_data_ipv4, tvb,
                                                               offset+2, avp_data_length-2, FALSE);
                                       } else if (tvb_get_ntohs(tvb, offset) == 0x0002) {
                                               proto_tree_add_item(single_avp_tree, hf_pana_avp_data_ipv6, tvb,
                                                               offset+2, avp_data_length-2, FALSE);
                                       } else {
                                               proto_tree_add_bytes_format(single_avp_tree, hf_pana_avp_data_bytes, tvb,
                                                               offset, avp_data_length,
                                                               tvb_get_ptr(tvb, offset, avp_data_length),
                                                               "Error! Cannot Parse Address Family %d",
                                                               tvb_get_ntohs(tvb, offset));
                                       }
                                       break;
                               }
                               case PANA_RESULT_CODE: {
                                       proto_tree_add_text(single_avp_tree, tvb, offset, avp_data_length,
                                                               "Value: %d (%s)",
                                                               tvb_get_ntohl(tvb, offset),
                                                               val_to_str(tvb_get_ntohs(tvb, offset), avp_code_names, "Unknown"));
                                       break;
                               }
                               case PANA_EAP: {
                                       avp_eap_item = proto_tree_add_text(single_avp_tree,
                                                                         tvb, offset, avp_data_length,
                                                                         "AVP Value (EAP packet)");
                                       avp_eap_tree = proto_item_add_subtree(avp_eap_item, ett_pana_avp);
                                       eap_tvb = tvb_new_subset(tvb, offset, avp_data_length, avp_data_length);
                                       if (avp_eap_tree != NULL && eap_handle != NULL) {
                                               call_dissector(eap_handle, eap_tvb, pinfo, avp_eap_tree);
                                       }
                                       break;
                               }
                       }
                       /* Just check that offset will advance */
                       g_assert((avp_length+padding)!=0);

                       offset += avp_data_length + padding;
               }

               /* Update the buffer length */
               buffer_length -=  avp_length + padding;
       }

}



/*
 * Function for the PANA PDU dissector.
 */
static void
dissect_pana_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

       proto_tree *pana_tree;
       proto_tree *avp_tree;
       proto_item *ti;
       proto_item *avp_item;

       tvbuff_t *avp_tvb;

       guint16 flags = 0;
       guint16 msg_type;
       gint16 msg_length;
       gint16 avp_length;

       /* Get message length, type and flags */
       msg_length = tvb_get_ntohs(tvb, 2);
       flags = tvb_get_ntohs(tvb, 4);
       msg_type = tvb_get_ntohs(tvb, 6);
       avp_length = msg_length-12;

       /* Make entries in Protocol column and Info column on summary display */
       if (check_col(pinfo->cinfo, COL_PROTOCOL))
               col_set_str(pinfo->cinfo, COL_PROTOCOL, "PANA");

       if (check_col(pinfo->cinfo, COL_INFO)) {
               col_clear(pinfo->cinfo, COL_INFO);
               col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s-%s",
               val_to_str(msg_type, msg_type_names, "Unknown (%d)"),
               match_strval(flags & PANA_FLAG_R, msg_subtype_names));
       }

       /* Make the protocol tree */
       if (tree) {

               gint offset = 0;

               /* create display subtree for the protocol */
               ti = proto_tree_add_item(tree, proto_pana, tvb, 0, -1, FALSE);
               pana_tree = proto_item_add_subtree(ti, ett_pana);

               /* Version */
               proto_tree_add_item(pana_tree, hf_pana_version_type, tvb, offset, 1, FALSE);
               offset += 1;
               /* Reserved field */
               proto_tree_add_item(pana_tree, hf_pana_reserved_type, tvb, offset, 1, FALSE);
               offset += 1;
               /* Length */
               proto_tree_add_item(pana_tree, hf_pana_length_type, tvb, offset, 2, FALSE);
               offset += 2;
               /* Flags */
               dissect_pana_flags(pana_tree, tvb, offset, flags);
               offset += 2;

               /* Message Type */
               proto_tree_add_uint_format_value(pana_tree, hf_pana_msg_type, tvb,
                                                       offset, 2, msg_type, "%s-%s (%d)",
                            val_to_str(msg_type, msg_type_names, "Unknown (%d)"),
                            match_strval(flags & PANA_FLAG_R, msg_subtype_names),
                            msg_type);
               offset += 2;

               proto_tree_add_item(pana_tree,
                       hf_pana_seqnumber, tvb, offset, 4, FALSE);
               offset += 4;

               /* AVPs */
               if(avp_length>0){
                   avp_tvb = tvb_new_subset(tvb, offset, avp_length, avp_length);
                   avp_item = proto_tree_add_text(pana_tree, tvb, offset, avp_length, "Attribute Value Pairs");
                   avp_tree = proto_item_add_subtree(avp_item, ett_pana_avp);

                   if (avp_tree != NULL) {
                           dissect_avps(avp_tvb, pinfo, avp_tree);
                   }
               }
       }

}



/*
 * Function for the PANA dissector.
 */
static gboolean
dissect_pana(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

       guint8 pana_version;
       guint8 pana_res;
       guint16 msg_length;
       guint16 flags;
       guint32 buffer_length;
       guint16 msg_type;

       /* Get buffer length */
       buffer_length = tvb_length(tvb);

       /* Check minimum buffer length */
       if(buffer_length < 12) {
               return FALSE;
       }

       /* Get header fields */
       pana_version = tvb_get_guint8(tvb, 0);
       pana_res = tvb_get_guint8(tvb, 1);
       msg_length = tvb_get_ntohs(tvb, 2);
       flags = tvb_get_ntohs(tvb, 4);
       msg_type = tvb_get_ntohs(tvb, 6);

       /* Check version */
       if(pana_version != PANA_VERSION) {
               return FALSE;
       }

       /* Check minimum packet length */
       if(msg_length < 12) {
               return FALSE;
       }

       /* Check the packet length and buffer length matching */
       if(msg_length != buffer_length) {
               return FALSE;
       }

       /* check that the reserved byte is zero */
       if(pana_res!=0){
               return FALSE;
       }

       /* verify that none of the reserved bits are set */
       if(flags&0x0fff){
               return FALSE;
       }

       /* verify that we recognize the message type */
       if(msg_type>10 || msg_type==0){
               return FALSE;
       }


       dissect_pana_pdu(tvb, pinfo, tree);

       return TRUE;
}


/*
 * Register the protocol with Wireshark
 */
void
proto_register_pana(void)
{
  module_t *pana_module;

       static hf_register_info hf[] = {
               { &hf_pana_version_type,
                       { "PANA Version", "pana.version",
                       FT_UINT8, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_reserved_type,
                       { "PANA Reserved", "pana.reserved",
                       FT_UINT8, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_length_type,
                       { "PANA Message Length", "pana.length",
                       FT_UINT16, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },


               { &hf_pana_flags,
                       { "Flags", "pana.flags",
                       FT_UINT8, BASE_HEX, NULL, 0x0,
                   "", HFILL }
               },
               { &hf_pana_flag_r,
                       { "Request", "pana.flags.r",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_R,
                       "", HFILL }
               },
               { &hf_pana_flag_s,
                       { "Separate", "pana.flags.s",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_S,
                       "", HFILL }
               },
               { &hf_pana_flag_n,
                       { "NAP Auth","pana.flags.n",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_N,
                       "", HFILL }
               },
               { &hf_pana_flag_l,
                       { "Stateless Discovery","pana.flags.l",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_L,
                       "", HFILL }
               },
               { &hf_pana_flag_res4,
                       { "Reserved","pana.flags.res4",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES4,
                       "", HFILL }
               },
               { &hf_pana_flag_res5,
                       { "Reserved","pana.flags.res5",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES5,
                       "", HFILL }
               },
               { &hf_pana_flag_res6,
                       { "Reserved","pana.flags.res6",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES6,
                       "", HFILL }
               },
               { &hf_pana_flag_res7,
                       { "Reserved","pana.flags.res7",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES7,
                       "", HFILL }
               },
               { &hf_pana_flag_res8,
                       { "Reserved","pana.flags.res8",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES8,
                       "", HFILL }
               },
               { &hf_pana_flag_res9,
                       { "Reserved","pana.flags.res9",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES9,
                       "", HFILL }
               },
               { &hf_pana_flag_res10,
                       { "Reserved","pana.flags.res10",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES10,
                       "", HFILL }
               },
               { &hf_pana_flag_res11,
                       { "Reserved","pana.flags.res11",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES11,
                       "", HFILL }
               },
               { &hf_pana_flag_res12,
                       { "Reserved","pana.flags.res12",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES12,
                       "", HFILL }
               },
               { &hf_pana_flag_res13,
                       { "Reserved","pana.flags.res13",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES13,
                       "", HFILL }
               },
               { &hf_pana_flag_res14,
                       { "Reserved","pana.flags.res14",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES14,
                       "", HFILL }
               },
               { &hf_pana_flag_res15,
                       { "Reserved","pana.flags.res15",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_FLAG_RES15,
                       "", HFILL }
               },


               { &hf_pana_msg_type,
                       { "PANA Message Type", "pana.type",
                       FT_UINT16, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_seqnumber,
                       { "PANA Sequence Number", "pana.seq",
                       FT_UINT32, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },


               { &hf_pana_avp_code,
                       { "AVP Code", "pana.avp.code",
                       FT_UINT16, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_length,
                       { "AVP Length", "pana.avp.length",
                       FT_UINT16, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_flags,
                       { "AVP Flags", "pana.avp.flags",
                       FT_UINT16, BASE_HEX, NULL, 0x0,
                   "", HFILL }
               },
               { &hf_pana_avp_flag_v,
                       { "Vendor", "pana.avp.flags.v",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_V,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_m,
                       { "Mandatory", "pana.avp.flags.m",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_M,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res2,
                       { "Reserved","pana.avp.flags.res2",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES2,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res3,
                       { "Reserved","pana.avp.flags.res3",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES3,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res4,
                       { "Reserved","pana.avp.flags.res4",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES4,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res5,
                       { "Reserved","pana.avp.flags.res5",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES5,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res6,
                       { "Reserved","pana.avp.flags.res6",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES6,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res7,
                       { "Reserved","pana.avp.flags.res7",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES7,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res8,
                       { "Reserved","pana.avp.flags.res8",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES8,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res9,
                       { "Reserved","pana.avp.flags.res9",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES9,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res10,
                       { "Reserved","pana.avp.flags.res10",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES10,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res11,
                       { "Reserved","pana.avp.flags.res11",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES11,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res12,
                       { "Reserved","pana.avp.flags.res12",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES12,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res13,
                       { "Reserved","pana.avp.flags.res13",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES13,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res14,
                       { "Reserved","pana.avp.flags.res14",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES14,
                       "", HFILL }
               },
               { &hf_pana_avp_flag_res15,
                       { "Reserved","pana.avp.flags.res15",
                       FT_BOOLEAN, 16, TFS(&flags_set_truth), PANA_AVP_FLAG_RES15,
                       "", HFILL }
               },
               { &hf_pana_avp_reserved,
                       { "AVP Reserved", "pana.avp.reserved",
                       FT_UINT16, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_vendorid,
                       { "AVP Vendor ID", "pana.avp.vendorid",
                       FT_UINT32, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },


               { &hf_pana_avp_data_uint64,
                       { "Value", "pana.avp.data.uint64",
                       FT_UINT64, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_int64,
                       { "Value", "pana.avp.data.int64",
                       FT_INT64, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_uint32,
                       { "Value", "pana.avp.data.uint32",
                       FT_UINT32, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_int32,
                       { "Value", "pana.avp.data.int32",
                       FT_INT32, BASE_HEX, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_bytes,
                       { "Value", "pana.avp.data.bytes",
                       FT_BYTES, BASE_NONE, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_string,
                       { "Value", "pana.avp.data.string",
                       FT_STRING, BASE_NONE, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_enumerated,
                       { "Value", "pana.avp.data.enum",
                       FT_INT32, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_addrfamily,
                       { "Address Family", "pana.avp.data.addrfamily",
                       FT_UINT16, BASE_DEC, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_ipv4,
                       { "IPv4 Address", "pana.avp.data.ipv4",
                       FT_IPv4, BASE_NONE, NULL, 0x0,
                       "", HFILL }
               },
               { &hf_pana_avp_data_ipv6,
                       { "IPv6 Address", "pana.avp.data.ipv6",
                       FT_IPv6, BASE_NONE, NULL, 0x0,
                       "", HFILL }
               },

       };

       /* Setup protocol subtree array */
       static gint *ett[] = {
               &ett_pana,
               &ett_pana_flags,
               &ett_pana_avp,
               &ett_pana_avp_info,
               &ett_pana_avp_flags,
       };

       /* Register the protocol name and description */
       proto_pana = proto_register_protocol("Protocol for carrying Authentication for Network Access",
           "PANA", "pana");

       /* Required function calls to register the header fields and subtrees used */
       proto_register_field_array(proto_pana, hf, array_length(hf));
       proto_register_subtree_array(ett, array_length(ett));

       /* Register preferences module */
       pana_module = prefs_register_protocol(proto_pana, NULL);

}


void
proto_reg_handoff_pana(void)
{
    heur_dissector_add("udp", dissect_pana, proto_pana);

    pana_handle = new_create_dissector_handle(dissect_pana, proto_pana);
    dissector_add_handle("udp.port", pana_handle);

    eap_handle = find_dissector("eap");
    if(!eap_handle) fprintf(stderr,"PANA warning: EAP dissector not found\n");

}
