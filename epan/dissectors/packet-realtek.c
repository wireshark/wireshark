/* packet-realtek.c
 * Routines for Realtek layer 2 protocols dissection
 *
 * Based on code from a 2004 submission
 * Copyright 2004, Horst Kronstorfer <hkronsto@frequentis.com>
 * but significantly modernized.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <epan/packet.h>
#include <etypes.h>

void proto_register_realtek(void);
void proto_reg_handoff_realtek(void);

#define RTL_PROTOCOL_RRCP    0x01    /* RRCP */
#define RTL_PROTOCOL_REP     0x02    /* REP */
#define RTL_PROTOCOL_RLDP    0x03    /* RLDP */
#define RTL_PROTOCOL_RLDP2   0x23    /* also RLDP */
#define RTL_PROTOCOL_XXX_DSA 0x04    /* DSA protocol for some chip(s) */

/*
 * Values for the upper 4 bits of the protocol field, for
 * protocols where the lower 4 bits contain protocol data.
 *
 * See section 8.10 "CPU Tag Function" of
 *
 *    http://realtek.info/pdf/rtl8306sd%28m%29_datasheet_1.1.pdf
 *
 * for the RTL8306 DSA protocol tag format.
 */
#define RTL_PROTOCOL_8306_DSA   0x9    /* RTL8306 DSA protocol */
#define RTL_PROTOCOL_8366RB_DSA 0xA    /* RTL8366RB DSA protocol */

enum {
  RRCP_OPCODE_HELLO = 0,
  RRCP_OPCODE_GET = 1,
  RRCP_OPCODE_SET = 2
};

/* HELLO, HELLO_REPLY, GET, GET_REPLY, SET */
#define RRCP_OPCODE_FIELD_LENGTH 1
#define RRCP_REPLY_FIELD_LENGTH RRCP_OPCODE_FIELD_LENGTH
#define RRCP_REPLY_MASK 0x80
#define RRCP_REPLY_BIT_POS 7
#define RRCP_OPCODE_MASK 0x7f
#define RRCP_AUTHKEY_FIELD_LENGTH 2
/* GET, GET_REPLY, SET */
#define RRCP_REGADDR_FIELD_LENGTH 2
/* GET_REPLY, SET */
#define RRCP_REGDATA_FIELD_LENGTH 2
/* HELLO_REPLY */
#define RRCP_DLPORT_FIELD_LENGTH 1
#define RRCP_ULPORT_FIELD_LENGTH 1
#define RRCP_ULMAC_FIELD_LENGTH 6
#define RRCP_CHIPID_FIELD_LENGTH 2
#define RRCP_VENDID_FIELD_LENGTH 4

#define RRCP_HELLO_PACKET_LENGTH 4
#define RRCP_HELLO_REPLY_PACKET_LENGTH 18
#define RRCP_GET_SET_PACKET_LENGTH 8

static const value_string rrcp_opcode_names[] = {
   { RRCP_OPCODE_HELLO, "Hello" },
   { RRCP_OPCODE_GET,   "Get" },
   { RRCP_OPCODE_SET,   "Set" },
   {0, NULL}
};

static int proto_realtek = -1;

static int hf_realtek_packet = -1;

static int proto_rrcp = -1;

static int hf_rrcp_protocol = -1;
static int hf_rrcp_reply = -1;
static int hf_rrcp_opcode = -1;
static int hf_rrcp_authkey = -1;
static int hf_rrcp_regaddr = -1;
static int hf_rrcp_regdata = -1;
static int hf_rrcp_hello_reply_dl_port = -1;
static int hf_rrcp_hello_reply_ul_port = -1;
static int hf_rrcp_hello_reply_ul_mac = -1;
static int hf_rrcp_hello_reply_chip_id = -1;
static int hf_rrcp_hello_reply_vendor_id = -1;

static int proto_rep = -1;
static int hf_rep_protocol = -1;

static int proto_rldp = -1;
static int hf_rldp_protocol = -1;

static int ett_realtek = -1;
static int ett_rrcp = -1;
static int ett_rep = -1;
static int ett_rldp = -1;

static heur_dissector_list_t realtek_heur_subdissector_list;

static const guint8 ether_mac_bcast[] = {
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/* Code to actually dissect the Realtek protocols */
static int
dissect_realtek(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *realtek_tree;
  heur_dtbl_entry_t *hdtbl_entry;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Realtek");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_realtek, tvb, 0, -1, ENC_NA);
  realtek_tree = proto_item_add_subtree(ti, ett_realtek);

  if (!dissector_try_heuristic(realtek_heur_subdissector_list, tvb, pinfo,
                               tree, &hdtbl_entry, NULL)) {
    proto_tree_add_item(realtek_tree, hf_realtek_packet, tvb, 0, -1, ENC_NA);
  }
  return tvb_captured_length(tvb);
}

/*
 * See section 8.20 "Realtek Remote Control Protocol" of
 *
 *    http://realtek.info/pdf/rtl8324.pdf
 *
 * and section 7.22 "Realtek Remote Control Protocol" of
 *
 *    http://realtek.info/pdf/rtl8326.pdf
 *
 * and this page on the OpenRRCP Wiki:
 *
 *    http://openrrcp.org.ru/wiki/rrcp_protocol
 *
 * for information on RRCP.
 */
static gboolean
dissect_rrcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *rrcp_tree;
  guint8 proto;
  int offset = 0;
  guint32 reply, opcode;

  if (!tvb_bytes_exist(tvb, 0, 1))
    return FALSE;
  proto = tvb_get_guint8(tvb, 0);
  if (proto != RTL_PROTOCOL_RRCP)
    return FALSE;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RRCP");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_rrcp, tvb, 0, -1, ENC_NA);
  rrcp_tree = proto_item_add_subtree(ti, ett_rrcp);

  proto_tree_add_uint(rrcp_tree, hf_rrcp_protocol, tvb, offset, 1,
                      proto);
  offset += 1;
  proto_tree_add_item_ret_boolean(rrcp_tree, hf_rrcp_reply, tvb,
                                  offset, RRCP_REPLY_FIELD_LENGTH,
                                  ENC_NA, &reply);
  proto_tree_add_item_ret_uint(rrcp_tree, hf_rrcp_opcode, tvb,
                               offset, RRCP_OPCODE_FIELD_LENGTH,
                               ENC_NA, &opcode);
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
               val_to_str(opcode, rrcp_opcode_names, "Unknown (%u)"),
               (reply) ? "Reply" : "Request");
  offset += RRCP_OPCODE_FIELD_LENGTH;

  proto_tree_add_item(rrcp_tree, hf_rrcp_authkey, tvb, offset,
                      RRCP_AUTHKEY_FIELD_LENGTH, ENC_BIG_ENDIAN);
  offset += RRCP_AUTHKEY_FIELD_LENGTH;

  if ((RRCP_OPCODE_GET == opcode) || (RRCP_OPCODE_SET == opcode)) {
    proto_tree_add_item(rrcp_tree, hf_rrcp_regaddr, tvb, offset,
                        RRCP_REGADDR_FIELD_LENGTH, ENC_BIG_ENDIAN);
    offset += RRCP_REGADDR_FIELD_LENGTH;
    proto_tree_add_item(rrcp_tree, hf_rrcp_regdata, tvb, offset,
                        RRCP_REGDATA_FIELD_LENGTH, ENC_BIG_ENDIAN);
    offset += RRCP_REGDATA_FIELD_LENGTH;
  }
  else if (RRCP_OPCODE_HELLO == opcode) {
    if (reply) {
      proto_tree_add_item(rrcp_tree, hf_rrcp_hello_reply_dl_port, tvb,
                          offset, RRCP_DLPORT_FIELD_LENGTH, ENC_NA);
      offset += RRCP_DLPORT_FIELD_LENGTH;
      proto_tree_add_item(rrcp_tree, hf_rrcp_hello_reply_ul_port, tvb,
                          offset, RRCP_ULPORT_FIELD_LENGTH, ENC_NA);
      offset += RRCP_ULPORT_FIELD_LENGTH;
      proto_tree_add_item(rrcp_tree, hf_rrcp_hello_reply_ul_mac, tvb,
                          offset, RRCP_ULMAC_FIELD_LENGTH, ENC_NA);
      offset += RRCP_ULMAC_FIELD_LENGTH;
      proto_tree_add_item(rrcp_tree, hf_rrcp_hello_reply_chip_id, tvb,
                          offset, RRCP_CHIPID_FIELD_LENGTH, ENC_BIG_ENDIAN);
      offset += RRCP_CHIPID_FIELD_LENGTH;
      proto_tree_add_item(rrcp_tree, hf_rrcp_hello_reply_vendor_id, tvb,
                          offset, RRCP_VENDID_FIELD_LENGTH, ENC_BIG_ENDIAN);
      offset += RRCP_VENDID_FIELD_LENGTH;
    }
  }
  proto_item_set_end(ti, tvb, offset);
  /* Let 'packet-eth' provide trailer/pad-bytes info */
  tvb_set_reported_length(tvb, offset);
  return TRUE;
}

/*
 * See section 8.22 "Realtek Echo Protocol" of
 *
 *    http://realtek.info/pdf/rtl8324.pdf
 *
 * and section 7.24 "Realtek Echo Protocol" of
 *
 *    http://realtek.info/pdf/rtl8326.pdf
 *
 * for information on REP.
 */
static gboolean
dissect_rep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *rep_tree;
  guint8 proto;
  int offset = 0;
  gboolean bcast;

  if (!tvb_bytes_exist(tvb, 0, 1))
    return FALSE;
  proto = tvb_get_guint8(tvb, 0);
  if (proto != RTL_PROTOCOL_REP)
    return FALSE;

  ti = proto_tree_add_item(tree, proto_rep, tvb, 0, -1, ENC_NA);
  rep_tree = proto_item_add_subtree(ti, ett_rep);

  bcast = (pinfo->dst.type == AT_ETHER &&
           memcmp(pinfo->dst.data, ether_mac_bcast, 6) == 0);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "REP");
  col_add_fstr(pinfo->cinfo, COL_INFO,
               "Echo %s", (bcast) ? "Request" : "Reply");

  proto_tree_add_uint(rep_tree, hf_rep_protocol, tvb, offset, 1,
                      proto);
  offset += 1;

  proto_item_set_end(ti, tvb, offset);
  /* Let 'packet-eth' provide trailer/pad-bytes info */
  tvb_set_reported_length(tvb, offset);
  return TRUE;
}

/*
 * See section 8.21 "Network Loop Connection Fault Detection" of
 *
 *    http://realtek.info/pdf/rtl8324.pdf
 *
 * and section 7.23 "Network Loop Connection Fault Detection" of
 *
 *    http://realtek.info/pdf/rtl8326.pdf
 *
 * for information on RLDP.
 *
 * See also section 7.3.8 "Loop Detection" of
 *
 *    http://www.ibselectronics.com/ibsstore/datasheet/RTL8306E-CG.pdf
 *
 * (revision 1.1 of the RTL8306E-CG datasheet), which describes a loop
 * detection protocol for which the payload has a 16-bit (presumably
 * big-endian) field containing the value 0x0300, followed by what is
 * presumably a 16-bit big-endian field the upper 12 bits of which are 0
 * and the lower 4 bits of which are a TTL value, followed by zeroes to
 * pad the packet out to the minimum Ethernet packet size.
 *
 * See also section 7.3.13 "Loop Detection" of
 *
 *    http://realtek.info/pdf/rtl8305sb.pdf
 *
 * (revision 1.3 of the RTL8305SB datasheet), which describes a similar
 * loop detection protocol that lacks the TTL field - all the bytes
 * after 0x0300 are zero.
 *
 * See also section 7.3.7 "Loop Detection" of
 *
 *    https://datasheet.lcsc.com/lcsc/1810221720_Realtek-Semicon-RTL8305NB-CG_C52146.pdf
 *
 * (revision 1.0 of the RTL8305NB-CT datasheet), which describes a loop
 * detection protocol similar to the one from the RTL8306E-CG datasheet,
 * except that the first value is 0x2300, not 0x0300.
 *
 * And, on top of all that, I've seen packets where the first octet of
 * the packet is 0x23, and that's followed by 6 unknown octets (a MAC
 * address of some sort?  It differs from packet to packet in a capture),
 * followed by the MAC address that appears in the source address in the
 * Ethernet header (possibly the originator, in case the packet is forwarded,
 * in which case the forwarded packets won't have the source address from
 * the Ethernet header there), followed by unknown stuff (0x0d followed by
 * zeroes for all such packets in one capture, 0x01 followed by zeroes for
 * all such packets in another capture, 0x07 followed by 0x20's for all
 * such packets in yet another capture).  The OpenRRCP issue at
 * https://github.com/illarionov/OpenRRCP/issues/3 shows a capture
 * similar to the last of those, but with 0x02 instead of 0x07.  Or is that
 * just crap in the buffer in which the chip constructed the packet, left
 * over from something else?
 */
static int
dissect_rldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *rldp_tree;
  guint8 proto;
  int offset = 0;

  if (!tvb_bytes_exist(tvb, 0, 1))
    return FALSE;
  proto = tvb_get_guint8(tvb, 0);
  if (proto != RTL_PROTOCOL_RLDP && proto != RTL_PROTOCOL_RLDP2)
    return FALSE;

  ti = proto_tree_add_item(tree, proto_rldp, tvb, 0, -1, ENC_NA);
  rldp_tree = proto_item_add_subtree(ti, ett_rep);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLDP");
  col_set_str(pinfo->cinfo, COL_INFO, "Network Loop Detection");

  proto_tree_add_uint(rldp_tree, hf_rldp_protocol, tvb, offset, 1,
                      proto);
  offset += 1;

  proto_item_set_end(ti, tvb, offset);
  /* Let 'packet-eth' provide trailer/pad-bytes info */
  tvb_set_reported_length(tvb, offset);
  return TRUE;
}

/* Register the protocol with Ethereal */
void
proto_register_realtek(void)
{
  static hf_register_info hf_realtek[] = {
    { &hf_realtek_packet, {
       "Unknown packet", "realtek.packet", FT_BYTES, BASE_NONE,
       NULL, 0x0, NULL, HFILL }},
  };

  static hf_register_info hf_rrcp[] = {
    { &hf_rrcp_protocol, {
       "Protocol", "rrcp.protocol", FT_UINT8, BASE_HEX,
       NULL, 0x0, NULL, HFILL }},
    { &hf_rrcp_reply, {
       "Reply", "rrcp.reply", FT_BOOLEAN, 8,
       NULL, RRCP_REPLY_MASK, "RRCP reply flag", HFILL}},
    { &hf_rrcp_opcode, {
       "Opcode", "rrcp.opcode", FT_UINT8, BASE_HEX,
       VALS(rrcp_opcode_names), RRCP_OPCODE_MASK, "RRCP operation code",
       HFILL }},
    { &hf_rrcp_authkey, {
       "Authentication key", "rrcp.authkey", FT_UINT16, BASE_HEX,
       NULL, 0, "RRCP authentication key", HFILL }},
    { &hf_rrcp_regaddr, {
       "Register address", "rrcp.regaddr", FT_UINT16, BASE_HEX,
       NULL, 0, "RRCP register address", HFILL }},
    { &hf_rrcp_regdata, {
       "Register data", "rrcp.regdata", FT_UINT16, BASE_HEX,
       NULL, 0, "RRCP register data", HFILL }},
    { &hf_rrcp_hello_reply_dl_port, {
       "Downlink port number", "rrcp.hello_reply.downlink_port",
       FT_UINT8, BASE_DEC, NULL, 0, "RRCP hello reply downlink port", HFILL }},
    { &hf_rrcp_hello_reply_ul_port, {
       "Uplink port number", "rrcp.hello_reply.uplink_port", FT_UINT8,
       BASE_DEC, NULL, 0, "RRCP hello reply uplink port", HFILL }},
    { &hf_rrcp_hello_reply_ul_mac, {
       "Uplink MAC address", "rrcp.hello_reply.uplink_mac", FT_ETHER,
       BASE_NONE, NULL, 0, "RRCP hello reply uplink MAC address", HFILL }},
    { &hf_rrcp_hello_reply_chip_id, {
       "Chip ID", "rrcp.hello_reply.chip_id", FT_UINT16,
       BASE_HEX, NULL, 0, "RRCP hello reply chip ID", HFILL }},
    { &hf_rrcp_hello_reply_vendor_id, {
       "Vendor ID", "rrcp.hello_reply.vendor_id", FT_UINT32, BASE_HEX,
       NULL, 0, "RRCP hello reply vendor ID", HFILL }}
  };

  static hf_register_info hf_rep[] = {
    { &hf_rep_protocol, {
       "Protocol", "rep.protocol", FT_UINT8, BASE_HEX,
       NULL, 0x0, NULL, HFILL }},
  };

  static hf_register_info hf_rldp[] = {
    { &hf_rldp_protocol, {
       "Protocol", "rldp.protocol", FT_UINT8, BASE_HEX,
       NULL, 0x0, NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_realtek,
    &ett_rrcp,
    &ett_rep,
    &ett_rldp
  };

  proto_realtek = proto_register_protocol("Realtek Layer 2 Protocols",
                                          "Realtek", "realtek");
  proto_register_field_array(proto_realtek, hf_realtek, array_length(hf_realtek));
  realtek_heur_subdissector_list = register_heur_dissector_list("realtek",
                                                                proto_realtek);

  proto_rrcp = proto_register_protocol("Realtek Remote Control Protocol",
                                       "RRCP", "rrcp");
  proto_register_field_array(proto_rrcp, hf_rrcp, array_length(hf_rrcp));

  proto_rep = proto_register_protocol("Realtek Echo Protocol",
                                      "REP", "rep");
  proto_register_field_array(proto_rrcp, hf_rep, array_length(hf_rep));

  proto_rldp = proto_register_protocol("Realtek Loop Detection Protocol",
                                       "RLDP", "rldp");
  proto_register_field_array(proto_rrcp, hf_rldp, array_length(hf_rldp));

  proto_register_subtree_array(ett, array_length(ett));
}

/* Sub-dissector registration */
void
proto_reg_handoff_realtek(void)
{
  dissector_handle_t realtek_handle;

  realtek_handle = create_dissector_handle(dissect_realtek, proto_realtek);
  dissector_add_uint("ethertype", ETHERTYPE_REALTEK, realtek_handle);

  heur_dissector_add("realtek", dissect_rrcp, "Realtek Remote Control Protocol",
                     "rrcp", proto_rrcp, HEURISTIC_ENABLE);

  heur_dissector_add("realtek", dissect_rep, "Realtek Echo Protocol",
                     "rep", proto_rep, HEURISTIC_ENABLE);

  heur_dissector_add("realtek", dissect_rldp, "Realtek Loop Detection Protocol",
                     "rldp", proto_rldp, HEURISTIC_ENABLE);
}
