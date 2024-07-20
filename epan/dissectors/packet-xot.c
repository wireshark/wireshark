/* packet-xot.c
 * Routines for X.25 over TCP dissection (RFC 1613)
 *
 * Copyright 2000, Paul Ionescu <paul@acorp.ro>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

#include "packet-tcp.h"

#define TCP_PORT_XOT 1998
#define XOT_HEADER_LENGTH 4
#define XOT_VERSION 0
#define XOT_PVC_SETUP 0xF5

/* Some X25 macros from packet-x25.c - some adapted code as well below */
#define X25_MIN_HEADER_LENGTH 3
#define X25_MIN_M128_HEADER_LENGTH 4
#define X25_NONDATA_BIT                 0x01
#define PACKET_IS_DATA(type)            (!(type & X25_NONDATA_BIT))
#define X25_MBIT_MOD8                   0x10
#define X25_MBIT_MOD128                 0x01

void proto_register_xot(void);
void proto_reg_handoff_xot(void);

static const value_string vals_x25_type[] = {
   { XOT_PVC_SETUP, "PVC Setup" },
   { 0,   NULL}
};

static const value_string xot_pvc_status_vals[] = {
   { 0x00, "Waiting to connect" },

   { 0x08, "Destination disconnected" },
   { 0x09, "PVC/TCP connection refused" },
   { 0x0A, "PVC/TCP routing error" },
   { 0x0B, "PVC/TCP connect timed out" },

   { 0x10, "Trying to connect via TCP" },
   { 0x11, "Awaiting PVC-SETUP reply" },
   { 0x12, "Connected" },
   { 0x13, "No such destination interface" },
   { 0x14, "Destination interface is not up" },
   { 0x15, "Non-X.25 destination interface" },
   { 0x16, "No such destination PVC" },
   { 0x17, "Destination PVC configuration mismatch" },
   { 0x18, "Mismatched flow control values" },
   { 0x19, "Can't support flow control values" },
   { 0x1A, "PVC setup protocol error" },

   { 0,   NULL}
};

static int proto_xot;
static int ett_xot;
static int hf_xot_version;
static int hf_xot_length;

static int hf_x25_gfi;
static int hf_x25_lcn;
static int hf_x25_type;

static int hf_xot_pvc_version;
static int hf_xot_pvc_status;
static int hf_xot_pvc_init_itf_name_len;
static int hf_xot_pvc_init_lcn;
static int hf_xot_pvc_resp_itf_name_len;
static int hf_xot_pvc_resp_lcn;
static int hf_xot_pvc_send_inc_window;
static int hf_xot_pvc_send_out_window;
static int hf_xot_pvc_send_inc_pkt_size;
static int hf_xot_pvc_send_out_pkt_size;
static int hf_xot_pvc_init_itf_name;
static int hf_xot_pvc_resp_itf_name;

static dissector_handle_t xot_handle;
static dissector_handle_t xot_tcp_handle;

static dissector_handle_t x25_handle;

/* desegmentation of X.25 over multiple TCP */
static bool xot_desegment = true;
/* desegmentation of X.25 packet sequences */
static bool x25_desegment;

static unsigned get_xot_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                             int offset, void *data _U_)
{
   uint16_t plen;
   int remain = tvb_captured_length_remaining(tvb, offset);
   if ( remain < XOT_HEADER_LENGTH){
      /* We did not get the data we asked for, use up what we can */
      return remain;
   }

   /*
    * Get the length of the X.25-over-TCP packet.
    */
   plen = tvb_get_ntohs(tvb, offset + 2);
   return XOT_HEADER_LENGTH + plen;
}

static unsigned get_xot_pdu_len_mult(packet_info *pinfo _U_, tvbuff_t *tvb,
                                  int offset, void *data _U_)
{
   int offset_before = offset; /* offset where we start this test */
   int offset_next = offset + XOT_HEADER_LENGTH + X25_MIN_HEADER_LENGTH;
   int tvb_len;

   while ((tvb_len = tvb_captured_length_remaining(tvb, offset)) > 0){
      uint16_t plen = 0;
      int modulo;
      uint16_t bytes0_1;
      uint8_t pkt_type;
      bool m_bit_set;
      int offset_x25 = offset + XOT_HEADER_LENGTH;

      /* Minimum where next starts */
      offset_next = offset_x25 + X25_MIN_HEADER_LENGTH;

      if (tvb_len < XOT_HEADER_LENGTH) {
         return offset_next-offset_before;
      }

      /*
       * Get the length of the current X.25-over-TCP packet.
       */
      plen = get_xot_pdu_len(pinfo, tvb, offset, NULL);
      offset_next = offset + plen;

      /* Make sure we have enough data */
      if (tvb_len < plen){
         return offset_next-offset_before;
      }

      /*Some minor code copied from packet-x25.c */
      bytes0_1 = tvb_get_ntohs(tvb,  offset_x25+0);
      pkt_type = tvb_get_uint8(tvb, offset_x25+2);

      /* If this is the first packet and it is not data, no sequence needed */
      if (offset == offset_before && !PACKET_IS_DATA(pkt_type)) {
          return offset_next-offset_before;
      }

      /* Check for data, there can be X25 control packets in the X25 data */
      if (PACKET_IS_DATA(pkt_type)){
         modulo = ((bytes0_1 & 0x2000) ? 128 : 8);
         if (modulo == 8) {
            m_bit_set = pkt_type & X25_MBIT_MOD8;
         } else {
            m_bit_set = tvb_get_uint8(tvb, offset_x25+3) & X25_MBIT_MOD128;
         }

         if (!m_bit_set){
            /* We are done with this sequence when the mbit is no longer set */
            return offset_next-offset_before;
         }
      }
      offset = offset_next;
      offset_next += XOT_HEADER_LENGTH + X25_MIN_HEADER_LENGTH;
  }

  /* not enough data */
  pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
  return offset_next - offset_before;
}

static int dissect_xot_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   int offset = 0;
   uint16_t version;
   uint16_t plen;
   uint8_t pkt_type;
   proto_item *ti = NULL;
   proto_tree *xot_tree = NULL;
   tvbuff_t   *next_tvb;

   /*
    * Dissect the X.25-over-TCP packet.
    */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "XOT");
   version = tvb_get_ntohs(tvb, offset + 0);
   plen = tvb_get_ntohs(tvb, offset + 2);
   col_add_fstr(pinfo->cinfo, COL_INFO, "XOT Version = %u, size = %u",
                version, plen);
   if (offset == 0 &&
       tvb_reported_length_remaining(tvb, offset) > XOT_HEADER_LENGTH + plen )
      col_append_fstr(pinfo->cinfo, COL_INFO, " TotX25: %d",
                      tvb_reported_length_remaining(tvb, offset));

   if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_xot, tvb, offset, XOT_HEADER_LENGTH,
                                          "X.25 over TCP");
      xot_tree = proto_item_add_subtree(ti, ett_xot);

      proto_tree_add_uint(xot_tree, hf_xot_version, tvb, offset, 2, version);
      proto_tree_add_uint(xot_tree, hf_xot_length, tvb, offset + 2, 2, plen);
   }

   offset += XOT_HEADER_LENGTH;
   /*
    * Construct a tvbuff containing the amount of the payload we have
    * available.  Make its reported length the amount of data in the
    * X.25-over-TCP packet.
    */
   if (plen >= X25_MIN_HEADER_LENGTH) {
      pkt_type = tvb_get_uint8(tvb, offset + 2);
      if (pkt_type == XOT_PVC_SETUP) {
         unsigned init_itf_name_len, resp_itf_name_len, pkt_size;
         int hdr_offset = offset;

         col_set_str(pinfo->cinfo, COL_INFO, "XOT PVC Setup");
         proto_item_set_len(ti, XOT_HEADER_LENGTH + plen);

         /* These fields are in overlay with packet-x25.c */
         proto_tree_add_item(xot_tree, hf_x25_gfi, tvb, hdr_offset, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(xot_tree, hf_x25_lcn, tvb, hdr_offset, 2, ENC_BIG_ENDIAN);
         hdr_offset += 2;
         proto_tree_add_item(xot_tree, hf_x25_type, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         hdr_offset += 1;

         proto_tree_add_item(xot_tree, hf_xot_pvc_version, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         hdr_offset += 1;
         proto_tree_add_item(xot_tree, hf_xot_pvc_status, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         hdr_offset += 1;
         proto_tree_add_item(xot_tree, hf_xot_pvc_init_itf_name_len, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         init_itf_name_len = tvb_get_uint8(tvb, hdr_offset);
         hdr_offset += 1;
         proto_tree_add_item(xot_tree, hf_xot_pvc_init_lcn, tvb, hdr_offset, 2, ENC_BIG_ENDIAN);
         hdr_offset += 2;
         proto_tree_add_item(xot_tree, hf_xot_pvc_resp_itf_name_len, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         resp_itf_name_len = tvb_get_uint8(tvb, hdr_offset);
         hdr_offset += 1;
         proto_tree_add_item(xot_tree, hf_xot_pvc_resp_lcn, tvb, hdr_offset, 2, ENC_BIG_ENDIAN);
         hdr_offset += 2;
         proto_tree_add_item(xot_tree, hf_xot_pvc_send_inc_window, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         hdr_offset += 1;
         proto_tree_add_item(xot_tree, hf_xot_pvc_send_out_window, tvb, hdr_offset, 1, ENC_BIG_ENDIAN);
         hdr_offset += 1;
         pkt_size = tvb_get_uint8(tvb, hdr_offset);
         proto_tree_add_uint_format_value(xot_tree, hf_xot_pvc_send_inc_pkt_size, tvb, hdr_offset, 1, pkt_size, "2^%u", pkt_size);
         hdr_offset += 1;
         pkt_size = tvb_get_uint8(tvb, hdr_offset);
         proto_tree_add_uint_format_value(xot_tree, hf_xot_pvc_send_out_pkt_size, tvb, hdr_offset, 1, pkt_size, "2^%u", pkt_size);
         hdr_offset += 1;
         proto_tree_add_item(xot_tree, hf_xot_pvc_init_itf_name, tvb, hdr_offset, init_itf_name_len, ENC_ASCII);
         hdr_offset += init_itf_name_len;
         proto_tree_add_item(xot_tree, hf_xot_pvc_resp_itf_name, tvb, hdr_offset, resp_itf_name_len, ENC_ASCII);
      } else {
         next_tvb = tvb_new_subset_length(tvb, offset, plen);
         call_dissector(x25_handle, next_tvb, pinfo, tree);
      }
   }

   return tvb_captured_length(tvb);
}

static int dissect_xot_mult(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
   int offset = 0;
   int len = get_xot_pdu_len_mult(pinfo, tvb, offset, NULL);
   tvbuff_t   *next_tvb;
   int offset_max = offset+MIN(len,tvb_captured_length_remaining(tvb, offset));
   proto_item *ti;
   proto_tree *xot_tree;

   if (tree) {
      /* Special header to show segments */
      ti = proto_tree_add_protocol_format(tree, proto_xot, tvb, offset, offset_max-offset,
                                          "X.25 over TCP - X.25 Sequence");
      xot_tree = proto_item_add_subtree(ti, ett_xot);
      proto_tree_add_uint(xot_tree, hf_xot_length, tvb, offset, offset_max, len);
   }

   while (offset <= offset_max - XOT_HEADER_LENGTH){
      int plen = get_xot_pdu_len(pinfo, tvb, offset, NULL);
      next_tvb = tvb_new_subset_length(tvb, offset, plen);

      dissect_xot_pdu(next_tvb, pinfo, tree, data);
      offset += plen;
   }
   return tvb_captured_length(tvb);
}

static int
dissect_xot_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
   if (!x25_desegment || !xot_desegment){
      tcp_dissect_pdus(tvb, pinfo, tree, xot_desegment,
                       XOT_HEADER_LENGTH,
                       get_xot_pdu_len,
                       dissect_xot_pdu, data);
   } else {
      /* Use length version that "peeks" into X25, possibly several XOT packets */
      tcp_dissect_pdus(tvb, pinfo, tree, xot_desegment,
                       XOT_HEADER_LENGTH,
                       get_xot_pdu_len_mult,
                       dissect_xot_mult, data);
   }
   return tvb_reported_length(tvb);
}

static int dissect_xot_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
   int tvb_len = tvb_captured_length(tvb);
   conversation_t *conversation;

   if (tvb_len < 2 || tvb_get_ntohs(tvb, 0) != XOT_VERSION) {
      return 0;
   }

   conversation = find_or_create_conversation(pinfo);
   conversation_set_dissector(conversation, xot_tcp_handle);

   return dissect_xot_tcp(tvb, pinfo, tree, data);
}

/* Register the protocol with Wireshark */
void
proto_register_xot(void)
{
   static hf_register_info hf[] = {
      { &hf_xot_version,
        { "Version", "xot.version", FT_UINT16, BASE_DEC,
          NULL, 0, "Version of X.25 over TCP protocol", HFILL }},

      { &hf_xot_length,
        { "Length", "xot.length", FT_UINT16, BASE_DEC,
          NULL, 0, "Length of X.25 over TCP packet", HFILL }},
      /* These fields are in overlay with packet-x25.c */
      { &hf_x25_gfi,
        { "GFI", "x25.gfi", FT_UINT16, BASE_DEC,
          NULL, 0xF000, "General Format Identifier", HFILL }},

      { &hf_x25_lcn,
        { "Logical Channel", "x25.lcn", FT_UINT16, BASE_DEC,
          NULL, 0x0FFF, "Logical Channel Number", HFILL }},

      { &hf_x25_type,
        { "Packet Type", "x25.type", FT_UINT8, BASE_HEX,
          VALS(vals_x25_type), 0x0, NULL, HFILL }},

      { &hf_xot_pvc_version,
        { "Version", "xot.pvc.version", FT_UINT8, BASE_HEX,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_status,
        { "Status", "xot.pvc.status", FT_UINT8, BASE_HEX,
          VALS(xot_pvc_status_vals), 0, NULL, HFILL }},

      { &hf_xot_pvc_init_itf_name_len,
        { "Initiator interface name length", "xot.pvc.init_itf_name_len", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_init_lcn,
        { "Initiator LCN", "xot.pvc.init_lcn", FT_UINT16, BASE_DEC,
          NULL, 0, "Initiator Logical Channel Number", HFILL }},

      { &hf_xot_pvc_resp_itf_name_len,
        { "Responder interface name length", "xot.pvc.resp_itf_name_len", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_resp_lcn,
        { "Responder LCN", "xot.pvc.resp_lcn", FT_UINT16, BASE_DEC,
          NULL, 0, "Responder Logical Channel Number", HFILL }},

      { &hf_xot_pvc_send_inc_window,
        { "Sender incoming window", "xot.pvc.send_inc_window", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_send_out_window,
        { "Sender outgoing window", "xot.pvc.send_out_window", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_send_inc_pkt_size,
        { "Sender incoming packet size", "xot.pvc.send_inc_pkt_size", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_send_out_pkt_size,
        { "Sender outgoing packet size", "xot.pvc.send_out_pkt_size", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_init_itf_name,
        { "Initiator interface name", "xot.pvc.init_itf_name", FT_STRING, BASE_NONE,
          NULL, 0, NULL, HFILL }},

      { &hf_xot_pvc_resp_itf_name,
        { "Responder interface name", "xot.pvc.resp_itf_name", FT_STRING, BASE_NONE,
          NULL, 0, NULL, HFILL }}
   };

   static int *ett[] = {
      &ett_xot
   };
   module_t *xot_module;

   proto_xot = proto_register_protocol("X.25 over TCP", "XOT", "xot");
   proto_register_field_array(proto_xot, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   xot_handle = register_dissector("xot", dissect_xot_tcp_heur, proto_xot);
   xot_tcp_handle = create_dissector_handle(dissect_xot_tcp, proto_xot);
   xot_module = prefs_register_protocol(proto_xot, NULL);

   prefs_register_bool_preference(xot_module, "desegment",
      "Reassemble X.25-over-TCP messages spanning multiple TCP segments",
      "Whether the X.25-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
      "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings",
      &xot_desegment);
   prefs_register_bool_preference(xot_module, "x25_desegment",
      "Reassemble X.25 packets with More flag to enable safe X.25 reassembly",
      "Whether the X.25-over-TCP dissector should reassemble all X.25 packets before calling the X25 dissector. "
      "If the TCP packets arrive out-of-order, the X.25 reassembly can otherwise fail. "
      "To use this option, you should also enable \"Reassemble X.25-over-TCP messages spanning multiple TCP segments\", \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings and \"Reassemble fragmented X.25 packets\" in the X.25 protocol settings.",
      &x25_desegment);

}

void
proto_reg_handoff_xot(void)
{
   dissector_add_uint_with_preference("tcp.port", TCP_PORT_XOT, xot_handle);

   x25_handle = find_dissector_add_dependency("x.25", proto_xot);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
