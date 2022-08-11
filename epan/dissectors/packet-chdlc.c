/* packet-chdlc.c
 * Routines for Cisco HDLC packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/chdlctypes.h>
#include <epan/nlpid.h>
#include <epan/addr_resolv.h>
#include "packet-chdlc.h"
#include "packet-ppp.h"
#include "packet-ip.h"
#include "packet-juniper.h"
#include "packet-l2tp.h"
#include <epan/expert.h>

/*
 * See section 4.3.1 of RFC 1547, and
 *
 *    http://www.nethelp.no/net/cisco-hdlc.txt
 */

void proto_register_chdlc(void);
void proto_reg_handoff_chdlc(void);
void proto_register_slarp(void);
void proto_reg_handoff_slarp(void);

static int proto_chdlc = -1;
static int hf_chdlc_addr = -1;
static int hf_chdlc_control = -1;
static int hf_chdlc_proto = -1;
static int hf_chdlc_clns_padding = -1;

static gint ett_chdlc = -1;

static int proto_slarp = -1;
static int hf_slarp_ptype = -1;
static int hf_slarp_address = -1;
static int hf_slarp_netmask = -1;
static int hf_slarp_mysequence = -1;
static int hf_slarp_yoursequence = -1;
static int hf_slarp_reliability = -1;

static expert_field ei_slarp_reliability = EI_INIT;
static gint ett_slarp = -1;

/*
 * Protocol types for the Cisco HDLC format.
 *
 * As per the above, according to RFC 1547, these are "standard 16 bit
 * Ethernet protocol type code[s]", but 0x8035 is Reverse ARP, and
 * that is (at least according to the Linux ISDN code) not the
 * same as Cisco SLARP.
 *
 * In addition, 0x2000 is apparently the Cisco Discovery Protocol, but
 * on Ethernet those are encapsulated inside SNAP with an OUI of
 * OUI_CISCO, not OUI_ENCAP_ETHER.
 *
 * We thus have a separate dissector table for Cisco HDLC types.
 * We could perhaps have that table hold only type values that
 * wouldn't be in the Ethernet dissector table, and check that
 * table first and the Ethernet dissector table if that fails.
 */
#define CISCO_SLARP     0x8035  /* Cisco SLARP protocol */

static dissector_table_t subdissector_table;

static dissector_handle_t chdlc_handle;

static capture_dissector_handle_t ip_cap_handle;

static const value_string chdlc_address_vals[] = {
  {CHDLC_ADDR_UNICAST,   "Unicast"},
  {CHDLC_ADDR_MULTICAST, "Multicast"},
  {0,                    NULL}
};

const value_string chdlc_vals[] = {
  {0x2000,               "Cisco Discovery Protocol"},
  {ETHERTYPE_IP,         "IP"},
  {ETHERTYPE_IPv6,       "IPv6"},
  {CISCO_SLARP,          "SLARP"},
  {ETHERTYPE_DEC_LB,     "DEC LanBridge"},
  {CHDLCTYPE_BPDU,       "Spanning Tree BPDU"},
  {ETHERTYPE_ATALK,      "Appletalk"},
  {ETHERTYPE_AARP,       "AARP"},
  {ETHERTYPE_IPX,        "Netware IPX/SPX"},
  {ETHERTYPE_ETHBRIDGE,  "Transparent Ethernet bridging" },
  {CHDLCTYPE_OSI,        "OSI" },
  {ETHERTYPE_MPLS,       "MPLS unicast"},
  {ETHERTYPE_MPLS_MULTI, "MPLS multicast"},
  {0,                     NULL}
};

static gboolean
capture_chdlc( const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header) {
  if (!BYTES_ARE_IN_FRAME(offset, len, 4))
    return FALSE;

  switch (pntoh16(&pd[offset + 2])) {
    case ETHERTYPE_IP:
      return call_capture_dissector(ip_cap_handle, pd, offset + 4, len, cpinfo, pseudo_header);
  }

  return FALSE;
}

void
chdlctype(dissector_handle_t sub_dissector, guint16 chdlc_type,
          tvbuff_t *tvb, int offset_after_chdlctype,
          packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
          int chdlctype_id)
{
  tvbuff_t *next_tvb;
  int       padbyte;

  proto_tree_add_uint(fh_tree, chdlctype_id, tvb,
                        offset_after_chdlctype - 2, 2, chdlc_type);

  padbyte = tvb_get_guint8(tvb, offset_after_chdlctype);
  if (chdlc_type == CHDLCTYPE_OSI &&
    !( padbyte == NLPID_ISO8473_CLNP || /* older Juniper SW does not send a padbyte */
       padbyte == NLPID_ISO9542_ESIS ||
       padbyte == NLPID_ISO10589_ISIS)) {
    /* There is a Padding Byte for CLNS protocols over Cisco HDLC */
    proto_tree_add_item(fh_tree, hf_chdlc_clns_padding, tvb, offset_after_chdlctype, 1, ENC_BIG_ENDIAN);
    next_tvb = tvb_new_subset_remaining(tvb, offset_after_chdlctype + 1);
  } else {
    next_tvb = tvb_new_subset_remaining(tvb, offset_after_chdlctype);
  }

  /* dissect with the handle; if there's no handle, it's just data */
  if (sub_dissector != NULL) {
    call_dissector(sub_dissector, next_tvb, pinfo, tree);
  } else {
    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", chdlc_type);
    call_data_dissector(next_tvb, pinfo, tree);
  }
}

static gint chdlc_fcs_decode = 0; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */

static int
dissect_chdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  guint16     proto;
  dissector_handle_t sub_dissector;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CHDLC");
  col_clear(pinfo->cinfo, COL_INFO);

  switch (pinfo->p2p_dir) {

  case P2P_DIR_SENT:
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
    break;

  case P2P_DIR_RECV:
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
    break;

  default:
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
    break;
  }

  proto = tvb_get_ntohs(tvb, 2);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_chdlc, tvb, 0, 4, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_chdlc);

    proto_tree_add_item(fh_tree, hf_chdlc_addr, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(fh_tree, hf_chdlc_control, tvb, 1, 1, ENC_NA);
  }

  decode_fcs(tvb, pinfo, fh_tree, chdlc_fcs_decode, 2);

  sub_dissector = dissector_get_uint_handle(subdissector_table, proto);
  chdlctype(sub_dissector, proto, tvb, 4, pinfo, tree, fh_tree, hf_chdlc_proto);
  return tvb_captured_length(tvb);
}

void
proto_register_chdlc(void)
{
  static hf_register_info hf[] = {
    { &hf_chdlc_addr,
      { "Address", "chdlc.address", FT_UINT8, BASE_HEX,
        VALS(chdlc_address_vals), 0x0, NULL, HFILL }},
    { &hf_chdlc_control,
      { "Control", "chdlc.control", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_chdlc_proto,
      { "Protocol", "chdlc.protocol", FT_UINT16, BASE_HEX,
        VALS(chdlc_vals), 0x0, NULL, HFILL }},
    { &hf_chdlc_clns_padding,
      { "CLNS Padding", "chdlc.clns_padding", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_chdlc,
  };

  module_t *chdlc_module;

  proto_chdlc = proto_register_protocol("Cisco HDLC", "CHDLC", "chdlc");
  proto_register_field_array(proto_chdlc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  subdissector_table = register_dissector_table("chdlc.protocol",
                                                "Cisco HDLC protocol", proto_chdlc,
                                                FT_UINT16, BASE_HEX);

  chdlc_handle = register_dissector("chdlc", dissect_chdlc, proto_chdlc);

  /* Register the preferences for the chdlc protocol */
  chdlc_module = prefs_register_protocol(proto_chdlc, NULL);

  prefs_register_enum_preference(chdlc_module,
        "fcs_type",
        "CHDLC Frame Checksum Type",
        "The type of CHDLC frame checksum (none, 16-bit, 32-bit)",
        &chdlc_fcs_decode,
        fcs_options, ENC_BIG_ENDIAN);

  register_capture_dissector("chdlc", capture_chdlc, proto_chdlc);

}

void
proto_reg_handoff_chdlc(void)
{
  capture_dissector_handle_t chdlc_cap_handle;

  dissector_add_uint("wtap_encap", WTAP_ENCAP_CHDLC, chdlc_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_CHDLC_WITH_PHDR, chdlc_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_CHDLC, chdlc_handle);
  dissector_add_uint("l2tp.pw_type", L2TPv3_PW_CHDLC, chdlc_handle);

  chdlc_cap_handle = find_capture_dissector("chdlc");
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_CHDLC, chdlc_cap_handle);

  ip_cap_handle = find_capture_dissector("ip");
}




#define SLARP_REQUEST   0
#define SLARP_REPLY     1
#define SLARP_LINECHECK 2

static const value_string slarp_ptype_vals[] = {
  {SLARP_REQUEST,   "Request"},
  {SLARP_REPLY,     "Reply"},
  {SLARP_LINECHECK, "Line keepalive"},
  {0,               NULL}
};

static int
dissect_slarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *slarp_tree;
  guint32     code;
  guint32     addr;
  guint32     mysequence;
  guint32     yoursequence;
  proto_item* reliability_item;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SLARP");
  col_clear(pinfo->cinfo, COL_INFO);

  code = tvb_get_ntohl(tvb, 0);

  ti = proto_tree_add_item(tree, proto_slarp, tvb, 0, 14, ENC_NA);
  slarp_tree = proto_item_add_subtree(ti, ett_slarp);

  switch (code) {

  case SLARP_REQUEST:
  case SLARP_REPLY:
    addr = tvb_get_ipv4(tvb, 4);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, from %s, mask %s",
                     val_to_str(code, slarp_ptype_vals, "Unknown (%d)"),
                     get_hostname(addr), tvb_ip_to_str(pinfo->pool, tvb, 8));
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      proto_tree_add_item(slarp_tree, hf_slarp_address, tvb, 4, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(slarp_tree, hf_slarp_netmask, tvb, 8, 4, ENC_BIG_ENDIAN);
    }
    break;

  case SLARP_LINECHECK:
    mysequence = tvb_get_ntohl(tvb, 4);
    yoursequence = tvb_get_ntohl(tvb, 8);
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s, outgoing sequence %u, returned sequence %u",
                     val_to_str(code, slarp_ptype_vals, "Unknown (%d)"),
                     mysequence, yoursequence);

    proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
    proto_tree_add_uint(slarp_tree, hf_slarp_mysequence, tvb, 4, 4,
                          mysequence);
    proto_tree_add_uint(slarp_tree, hf_slarp_yoursequence, tvb, 8, 4,
                          yoursequence);
    reliability_item = proto_tree_add_item(slarp_tree, hf_slarp_reliability, tvb,
        12, 2, ENC_BIG_ENDIAN);
    if (tvb_get_ntohs(tvb, 12) != 0xFFFF) {
        expert_add_info(pinfo, reliability_item, &ei_slarp_reliability);
    }
    break;

  default:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown packet type 0x%08X", code);

    proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
    call_data_dissector(tvb_new_subset_remaining(tvb, 4), pinfo, slarp_tree);
    break;
  }
  return tvb_captured_length(tvb);
}

void
proto_register_slarp(void)
{
  expert_module_t* expert_slarp;

  static hf_register_info hf[] = {
    { &hf_slarp_ptype,
      { "Packet type", "slarp.ptype", FT_UINT32, BASE_DEC,
        VALS(slarp_ptype_vals), 0x0, NULL, HFILL }},
    { &hf_slarp_address,
      { "Address", "slarp.address", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    /* XXX - need an FT_ for netmasks, which is like FT_IPV4 but doesn't
       get translated to a host name. */
    { &hf_slarp_netmask,
      { "Netmask", "slarp.netmask", FT_IPv4, BASE_NETMASK,
        NULL, 0x0, NULL, HFILL }},
    { &hf_slarp_mysequence,
      { "Outgoing sequence number", "slarp.mysequence", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_slarp_yoursequence,
      { "Returned sequence number", "slarp.yoursequence", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_slarp_reliability,
      { "Reliability", "slarp.reliability", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_slarp,
  };

  static ei_register_info ei[] = {
    { &ei_slarp_reliability, { "slarp.reliability.invalid", PI_MALFORMED, PI_ERROR,
      "Reliability must be 0xFFFF", EXPFILL }}
  };

  proto_slarp = proto_register_protocol("Cisco SLARP", "SLARP", "slarp");
  proto_register_field_array(proto_slarp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_slarp = expert_register_protocol(proto_slarp);
  expert_register_field_array(expert_slarp, ei, array_length(ei));
}

void
proto_reg_handoff_slarp(void)
{
  dissector_handle_t slarp_handle;

  slarp_handle = create_dissector_handle(dissect_slarp, proto_slarp);
  dissector_add_uint("chdlc.protocol", CISCO_SLARP, slarp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
