/* packet-fcgi.c
 * Routines for FastCGI dissection
 * Copyright 2010, Tom Hughes <tom@compton.nu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

static int proto_fcgi = -1;

static guint tcp_port = 0;

static int hf_fcgi_version = -1;
static int hf_fcgi_type = -1;
static int hf_fcgi_id = -1;
static int hf_fcgi_content_length = -1;
static int hf_fcgi_padding_length = -1;
static int hf_fcgi_content_data = -1;
static int hf_fcgi_padding_data = -1;
static int hf_fcgi_begin_request_role = -1;
static int hf_fcgi_begin_request_flags = -1;
static int hf_fcgi_begin_request_keep_conn = -1;
static int hf_fcgi_end_request_app_status = -1;
static int hf_fcgi_end_request_protocol_status = -1;

static int ett_fcgi = -1;
static int ett_fcgi_begin_request = -1;
static int ett_fcgi_end_request = -1;
static int ett_fcgi_params = -1;

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11

static const value_string record_types[] = {
   { 1, "FCGI_BEGIN_REQUEST" },
   { 2, "FCGI_ABORT_REQUEST" },
   { 3, "FCGI_END_REQUEST" },
   { 4, "FCGI_PARAMS" },
   { 5, "FCGI_STDIN" },
   { 6, "FCGI_STDOUT" },
   { 7, "FCGI_STDERR" },
   { 8, "FCGI_DATA" },
   { 9, "FCGI_GET_VALUES" },
   { 10, "FCGI_GET_VALUES_RESULT" },
   { 11, "FCGI_UNKNOWN_TYPE" },
   { 0, NULL }
};

static const value_string application_roles[] = {
   { 1, "FCGI_RESPONDER" },
   { 2, "FCGI_AUTHORIZER" },
   { 3, "FCGI_FILTER" },
   { 0, NULL }
};

#define FCGI_KEEP_CONN  1

static const value_string protocol_statuses[] = {
   { 0, "FCGI_REQUEST_COMPLETE" },
   { 1, "FCGI_CANT_MPX_CONN" },
   { 2, "FCGI_OVERLOADED" },
   { 3, "FCGI_UNKNOWN_ROLE" },
   { 0, NULL }
};

void proto_reg_handoff_fcgi(void);

static void
dissect_nv_pairs(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   gint end_offset = offset + len;

   while (offset < end_offset) {
      gint start_offset = offset;
      guint32 namelen;
      guint32 valuelen;
      char *name;
      char *value;

      namelen = tvb_get_guint8(tvb, offset);
      if ((namelen & 0x80) == 0) {
         offset += 1;
      } else {
         namelen = tvb_get_ntohl(tvb, offset) & 0x7FFFFFFF;
         offset += 4;
      }

      valuelen = tvb_get_guint8(tvb, offset);
      if ((valuelen & 0x80) == 0) {
         offset += 1;
      } else {
         valuelen = tvb_get_ntohl(tvb, offset) & 0x7FFFFFFF;
         offset += 4;
      }

      name = tvb_get_ephemeral_string(tvb, offset, namelen);
      offset += namelen;

      if (valuelen > 0) {
         value = tvb_get_ephemeral_string(tvb, offset, valuelen);
         offset += valuelen;

         proto_tree_add_text(fcgi_tree, tvb, start_offset, offset - start_offset, "%s = %s", name, value);
      } else {
         proto_tree_add_text(fcgi_tree, tvb, start_offset, offset - start_offset, "%s", name);
      }
   }
}

static void
dissect_begin_request(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   proto_item *br;
   proto_tree *br_tree;

   br = proto_tree_add_text(fcgi_tree, tvb, offset, len, "Begin Request:");
   br_tree = proto_item_add_subtree(br, ett_fcgi_begin_request);

   proto_tree_add_item(br_tree, hf_fcgi_begin_request_role, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(br_tree, hf_fcgi_begin_request_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(br_tree, hf_fcgi_begin_request_keep_conn, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset += 1;

   offset += 5;

   return;
}

static void
dissect_abort_request(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   proto_tree_add_text(fcgi_tree, tvb, offset, len, "Abort Request:");

   return;
}

static void
dissect_end_request(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   proto_item *er;
   proto_tree *er_tree;

   er = proto_tree_add_text(fcgi_tree, tvb, offset, len, "End Request:");
   er_tree = proto_item_add_subtree(er, ett_fcgi_end_request);

   proto_tree_add_item(er_tree, hf_fcgi_end_request_app_status, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(er_tree, hf_fcgi_end_request_protocol_status, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset += 1;

   offset += 3;

   return;
}

static void
dissect_params(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   proto_item *p;
   proto_tree *p_tree;

   p = proto_tree_add_text(fcgi_tree, tvb, offset, len, "Params:");
   p_tree = proto_item_add_subtree(p, ett_fcgi_params);

   dissect_nv_pairs(tvb, p_tree, offset, len);

   return;
}

static void
dissect_get_values(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   proto_item *gv;
   proto_tree *gv_tree;

   gv = proto_tree_add_text(fcgi_tree, tvb, offset, len, "Get Values:");
   gv_tree = proto_item_add_subtree(gv, ett_fcgi_params);

   dissect_nv_pairs(tvb, gv_tree, offset, len);

   return;
}

static void
dissect_get_values_result(tvbuff_t *tvb, proto_tree *fcgi_tree, gint offset, guint16 len)
{
   proto_item *gvr;
   proto_tree *gvr_tree;

   gvr = proto_tree_add_text(fcgi_tree, tvb, offset, len, "Get Values:");
   gvr_tree = proto_item_add_subtree(gvr, ett_fcgi_params);

   dissect_nv_pairs(tvb, gvr_tree, offset, len);

   return;
}

static void
dissect_fcgi_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;
   guint8 type;

   type = tvb_get_guint8(tvb, 1);

   /* When there are multiple FCGI records in a TCP frame the following code */
   /* will append the type for each record to COL_INFO.                      */
   /* XXX: Unfortunately, something in the tcp_dissect_pdus() code is broken */
   /*      such that only the type for the first FCGI record appears in the  */
   /*      INFO column. (All write attempts to COL_INFO after the first fail */
   /*      because pinfo->cinfo->writable is FALSE).                         */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "FCGI");
   col_clear(pinfo->cinfo, COL_INFO);
   col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                      val_to_str(type, record_types, "Unknown (%u)"));
   col_set_fence(pinfo->cinfo, COL_INFO);

   if (tree) { /* we are being asked for details */
      proto_item *ti;
      proto_tree *fcgi_tree;
      guint16 clen;
      guint8 plen;

      ti = proto_tree_add_item(tree, proto_fcgi, tvb, 0, -1, ENC_NA);
      proto_item_append_text(ti, " (%s)",
                             val_to_str(type, record_types, "Unknown (%u)"));
      fcgi_tree = proto_item_add_subtree(ti, ett_fcgi);

      proto_tree_add_item(fcgi_tree, hf_fcgi_version, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;

      proto_tree_add_item(fcgi_tree, hf_fcgi_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;

      proto_tree_add_item(fcgi_tree, hf_fcgi_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      clen = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(fcgi_tree, hf_fcgi_content_length, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      plen = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(fcgi_tree, hf_fcgi_padding_length, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;

      offset += 1;

      switch (type)
      {
      case FCGI_BEGIN_REQUEST:
         dissect_begin_request(tvb, fcgi_tree, offset, clen);
         offset += clen;
         break;
      case FCGI_ABORT_REQUEST:
         dissect_abort_request(tvb, fcgi_tree, offset, clen);
         offset += clen;
         break;
      case FCGI_END_REQUEST:
         dissect_end_request(tvb, fcgi_tree, offset, clen);
         offset += clen;
         break;
      case FCGI_PARAMS:
         dissect_params(tvb, fcgi_tree, offset, clen);
         offset += clen;
         break;
      case FCGI_GET_VALUES:
         dissect_get_values(tvb, fcgi_tree, offset, clen);
         offset += clen;
         break;
      case FCGI_GET_VALUES_RESULT:
         dissect_get_values_result(tvb, fcgi_tree, offset, clen);
         offset += clen;
         break;
      default:
         if (clen > 0) {
            proto_tree_add_item(fcgi_tree, hf_fcgi_content_data, tvb, offset, clen, ENC_NA);
            offset += clen;
         }
         break;
      }

      if (plen > 0) {
         proto_tree_add_item(fcgi_tree, hf_fcgi_padding_data, tvb, offset, plen, ENC_NA);
         offset += plen;
      }
   }
}

static guint
get_fcgi_record_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   return 8 + tvb_get_ntohs(tvb, offset + 4) + tvb_get_guint8(tvb, offset + 6);
}

static void
dissect_fcgi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 8, get_fcgi_record_len, dissect_fcgi_record);
}

void
proto_register_fcgi(void)
{
   static hf_register_info hf[] = {
      { &hf_fcgi_version,
        { "Version", "fcgi.version",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_type,
        { "Type", "fcgi.type",
          FT_UINT8, BASE_DEC, VALS(record_types), 0x0, NULL, HFILL } },
      { &hf_fcgi_id,
        { "Request ID", "fcgi.id",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_content_length,
        { "Content Length", "fcgi.content.length",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_padding_length,
        { "Padding Length", "fcgi.padding.length",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_content_data,
        { "Content Data", "fcgi.content.data",
          FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_padding_data,
        { "Padding Data", "fcgi.padding.data",
          FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_begin_request_role,
        { "Role", "fcgi.begin_request.role",
          FT_UINT16, BASE_DEC, VALS(application_roles), 0x0, NULL, HFILL } },
      { &hf_fcgi_begin_request_flags,
        { "Flags", "fcgi.begin_request.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_begin_request_keep_conn,
        { "FCGI_KEEP_CONN", "fcgi.begin_request.keep_conn",
          FT_BOOLEAN, 8, NULL, FCGI_KEEP_CONN, NULL, HFILL } },
      { &hf_fcgi_end_request_app_status,
        { "Application Status", "fcgi.end_request.app_status",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_fcgi_end_request_protocol_status,
        { "Protocol Status", "fcgi.end_request.protocol_status",
          FT_UINT32, BASE_DEC, VALS(protocol_statuses), 0x0, NULL, HFILL } }
   };
   static gint *ett[] = {
      &ett_fcgi,
      &ett_fcgi_begin_request,
      &ett_fcgi_end_request,
      &ett_fcgi_params
   };
   module_t *fcgi_module;

   proto_fcgi = proto_register_protocol("FastCGI", "FCGI", "fcgi");

   proto_register_field_array(proto_fcgi, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   fcgi_module = prefs_register_protocol(proto_fcgi, proto_reg_handoff_fcgi);

   prefs_register_uint_preference(fcgi_module,
                                  "tcp.port",
                                  "TCP port for FCGI",
                                  "Set the TCP port for FastCGI traffic",
                                  10,
                                  &tcp_port);

   register_dissector("fcgi", dissect_fcgi, proto_fcgi);
}

void
proto_reg_handoff_fcgi(void)
{
   static gboolean initialized = FALSE;
   static dissector_handle_t fcgi_handle;
   static guint saved_tcp_port;

   if (!initialized) {
      fcgi_handle = create_dissector_handle(dissect_fcgi, proto_fcgi);
      dissector_add_handle("tcp.port", fcgi_handle);  /* for "decode as" */
      initialized = TRUE;
   } else if (saved_tcp_port != 0) {
      dissector_delete_uint("tcp.port", saved_tcp_port, fcgi_handle);
   }

   if (tcp_port != 0) {
      dissector_add_uint("tcp.port", tcp_port, fcgi_handle);
   }

   saved_tcp_port = tcp_port;
}
