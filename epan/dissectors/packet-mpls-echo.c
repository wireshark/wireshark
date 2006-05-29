/* packet-mpls-echo.c
 * Routines for Multiprotocol Label Switching Echo dissection
 * Copyright 2004, Carlos Pignataro <cpignata@cisco.com>
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
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include "packet-ntp.h"
#include "packet-ldp.h"
#include "packet-mpls.h"

#define UDP_PORT_MPLS_ECHO 3503

void proto_reg_handoff_mpls_echo(void);

static int proto_mpls_echo = -1;
static int hf_mpls_echo_version = -1;
static int hf_mpls_echo_mbz = -1;
static int hf_mpls_echo_gflags = -1;
static int hf_mpls_echo_flag_sbz = -1;
static int hf_mpls_echo_flag_v = -1;
static int hf_mpls_echo_msgtype = -1;
static int hf_mpls_echo_replymode = -1;
static int hf_mpls_echo_returncode = -1;
static int hf_mpls_echo_returnsubcode = -1;
static int hf_mpls_echo_handle = -1;
static int hf_mpls_echo_sequence = -1;
static int hf_mpls_echo_ts_sent = -1;
static int hf_mpls_echo_ts_rec = -1;
static int hf_mpls_echo_tlv_type = -1;
static int hf_mpls_echo_tlv_len = -1;
static int hf_mpls_echo_tlv_value = -1;
static int hf_mpls_echo_tlv_fec_type = -1;
static int hf_mpls_echo_tlv_fec_len = -1;
static int hf_mpls_echo_tlv_fec_value = -1;
static int hf_mpls_echo_tlv_fec_ldp_ipv4 = -1;
static int hf_mpls_echo_tlv_fec_ldp_ipv4_mask = -1;
static int hf_mpls_echo_tlv_fec_ldp_ipv6 = -1;
static int hf_mpls_echo_tlv_fec_ldp_ipv6_mask = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ipv4_ipv4_endpoint = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ipv6_ipv6_endpoint = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ip_mbz1 = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ip_tunnel_id = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ipv4_ext_tunnel_id = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ipv4_ipv4_sender = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ipv6_ext_tunnel_id = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ipv6_ipv6_sender = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ip_mbz2 = -1;
static int hf_mpls_echo_tlv_fec_rsvp_ip_lsp_id = -1;
static int hf_mpls_echo_tlv_fec_l2cid_sender = -1;
static int hf_mpls_echo_tlv_fec_l2cid_remote = -1;
static int hf_mpls_echo_tlv_fec_l2cid_vcid = -1;
static int hf_mpls_echo_tlv_fec_l2cid_encap = -1;
static int hf_mpls_echo_tlv_fec_l2cid_mbz = -1;
static int hf_mpls_echo_tlv_fec_bgp_nh = -1;
static int hf_mpls_echo_tlv_fec_bgp_ipv4 = -1;
static int hf_mpls_echo_tlv_fec_bgp_len = -1;
static int hf_mpls_echo_tlv_fec_gen_ipv4 = -1;
static int hf_mpls_echo_tlv_fec_gen_ipv4_mask = -1;
static int hf_mpls_echo_tlv_fec_gen_ipv6 = -1;
static int hf_mpls_echo_tlv_fec_gen_ipv6_mask = -1;
static int hf_mpls_echo_tlv_fec_nil_label = -1;
static int hf_mpls_echo_tlv_ds_map_mtu = -1;
static int hf_mpls_echo_tlv_ds_map_addr_type = -1;
static int hf_mpls_echo_tlv_ds_map_res = -1;
static int hf_mpls_echo_tlv_ds_map_flag_res = -1;
static int hf_mpls_echo_tlv_ds_map_flag_i = -1;
static int hf_mpls_echo_tlv_ds_map_flag_n = -1;
static int hf_mpls_echo_tlv_ds_map_ds_ip = -1;
static int hf_mpls_echo_tlv_ds_map_int_ip = -1;
static int hf_mpls_echo_tlv_ds_map_if_index = -1;
static int hf_mpls_echo_tlv_ds_map_ds_ipv6 = -1;
static int hf_mpls_echo_tlv_ds_map_int_ipv6 = -1;
static int hf_mpls_echo_tlv_ds_map_hash_type = -1;
static int hf_mpls_echo_tlv_ds_map_depth = -1;
static int hf_mpls_echo_tlv_ds_map_muti_len = -1;
static int hf_mpls_echo_tlv_ds_map_mp_ip = -1;
static int hf_mpls_echo_tlv_ds_map_mp_mask = -1;
static int hf_mpls_echo_tlv_ds_map_mp_ip_low = -1;
static int hf_mpls_echo_tlv_ds_map_mp_ip_high = -1;
static int hf_mpls_echo_tlv_ds_map_mp_value = -1;
static int hf_mpls_echo_tlv_ds_map_mp_label = -1;
static int hf_mpls_echo_tlv_ds_map_mp_exp = -1;
static int hf_mpls_echo_tlv_ds_map_mp_bos = -1;
static int hf_mpls_echo_tlv_ds_map_mp_proto = -1;
static int hf_mpls_echo_tlv_padaction = -1;
static int hf_mpls_echo_tlv_padding = -1;
static int hf_mpls_echo_tlv_vendor = -1;
static int hf_mpls_echo_tlv_ilso_ipv4_addr = -1;
static int hf_mpls_echo_tlv_ilso_ipv4_int_addr = -1;
static int hf_mpls_echo_tlv_ilso_ipv6_addr = -1;
static int hf_mpls_echo_tlv_ilso_ipv6_int_addr = -1;
static int hf_mpls_echo_tlv_ilso_label = -1;
static int hf_mpls_echo_tlv_ilso_exp = -1;
static int hf_mpls_echo_tlv_ilso_bos = -1;
static int hf_mpls_echo_tlv_ilso_ttl = -1;
static int hf_mpls_echo_tlv_rto_ipv4 = -1;
static int hf_mpls_echo_tlv_rto_ipv6 = -1;
static int hf_mpls_echo_tlv_reply_tos = -1;
static int hf_mpls_echo_tlv_reply_tos_mbz = -1;
static int hf_mpls_echo_tlv_errored_type = -1;

static gint ett_mpls_echo = -1;
static gint ett_mpls_echo_gflags = -1;
static gint ett_mpls_echo_tlv = -1;
static gint ett_mpls_echo_tlv_fec = -1;
static gint ett_mpls_echo_tlv_ds_map = -1;
static gint ett_mpls_echo_tlv_ilso = -1;

static int mpls_echo_udp_port = 0;

static guint32 global_mpls_echo_udp_port = UDP_PORT_MPLS_ECHO;

static const value_string mpls_echo_msgtype[] = {
  {1, "MPLS Echo Request"},
  {2, "MPLS Echo Reply"},
  {3, "MPLS Data Plane Verification Request"},
  {4, "MPLS Data Plane Verification Reply"},
  {0, NULL}
};

static const value_string mpls_echo_replymode[] = {
  {1, "Do not reply"},
  {2, "Reply via an IPv4/IPv6 UDP packet"},
  {3, "Reply via an IPv4/IPv6 UDP packet with Router Alert"},
  {4, "Reply via application level control channel"},
  {0, NULL}
};

static const value_string mpls_echo_returncode[] = {
  {0, "No return code"},
  {1, "Malformed echo request received"},
  {2, "One or more of the TLVs was not understood"},
  {3, "Replying router is an egress for the FEC at stack depth RSC"},
  {4, "Replying router has no mapping for the FEC at stack depth RSC"},
  {5, "Reserved"},
  {6, "Reserved"},
  {7, "Reserved"},
  {8, "Label switched at stack-depth RSC"},
  {9, "Label switched but no MPLS forwarding at stack-depth RSC"},
  {10, "Mapping for this FEC is not the given label at stack depth RSC"},
  {11, "No label entry at stack-depth RSC"},
  {12, "Protocol not associated with interface at FEC stack depth RSC"},
  {13, "Premature termination, label stack shrinking to a single label"},
  {0, NULL}
};

#define TLV_TARGET_FEC_STACK       0x0001
#define TLV_DOWNSTREAM_MAPPING     0x0002
#define TLV_PAD                    0x0003
#define TLV_ERROR_CODE             0x0004
#define TLV_VENDOR_CODE            0x0005
#define TLV_TBD                    0x0006
#define TLV_ILSO_IPv4              0x0007
#define TLV_ILSO_IPv6              0x0008
#define TLV_ERRORED_TLV            0x0009
#define TLV_REPLY_TOS              0x000A
#define TLV_RTO_IPv4               0x000B
#define TLV_RTO_IPv6               0x000C
#define TLV_VENDOR_PRIVATE_START   0xFC00
#define TLV_VENDOR_PRIVATE_END     0xFFFF

/* MPLS Echo TLV Type names */
static const value_string mpls_echo_tlv_type_names[] = {
  { TLV_TARGET_FEC_STACK,          "Target FEC Stack" },
  { TLV_DOWNSTREAM_MAPPING,        "Downstream Mapping" },
  { TLV_PAD,                       "Pad" },
  { TLV_ERROR_CODE,                "Error Code" },
  { TLV_VENDOR_CODE,               "Vendor Enterprise Code" },
  { TLV_TBD,                       "TDB" },
  { TLV_ILSO_IPv4,                 "IPv4 Interface and Label Stack Object" },
  { TLV_ILSO_IPv6,                 "IPv6 Interface and Label Stack Object" },
  { TLV_ERRORED_TLV,               "Errored TLVs" },
  { TLV_REPLY_TOS,                 "Reply TOS Byte" },
  { TLV_RTO_IPv4,                  "IPv4 Reply-to Object" },
  { TLV_RTO_IPv6,                  "IPv6 Reply-to Object" },
  { TLV_VENDOR_PRIVATE_START,      "Vendor Private" },
  { 0, NULL}
};

#define TLV_FEC_STACK_LDP_IPv4     1
#define TLV_FEC_STACK_LDP_IPv6     2
#define TLV_FEC_STACK_RSVP_IPv4    3
#define TLV_FEC_STACK_RSVP_IPv6    4
#define TLV_FEC_STACK_RES          5
#define TLV_FEC_STACK_VPN_IPv4     6
#define TLV_FEC_STACK_VPN_IPv6     7
#define TLV_FEC_STACK_L2_VPN       8
#define TLV_FEC_STACK_L2_CID_OLD   9
#define TLV_FEC_STACK_L2_CID_NEW  10
#define TLV_FEC_STACK_L2_FEC_129  11
#define TLV_FEC_STACK_BGP_LAB_v4  12
#define TLV_FEC_STACK_BGP_LAB_v6  13
#define TLV_FEC_STACK_GEN_IPv4    14
#define TLV_FEC_STACK_GEN_IPv6    15
#define TLV_FEC_STACK_NIL         16
#define TLV_FEC_VENDOR_PRIVATE_START   0xFC00
#define TLV_FEC_VENDOR_PRIVATE_END     0xFFFF

/* FEC sub-TLV Type names */
static const value_string mpls_echo_tlv_fec_names[] = {
  { TLV_FEC_STACK_LDP_IPv4,    "LDP IPv4 prefix"},
  { TLV_FEC_STACK_LDP_IPv6,    "LDP IPv6 prefix"},
  { TLV_FEC_STACK_RSVP_IPv4,   "RSVP IPv4 Session Query"},
  { TLV_FEC_STACK_RSVP_IPv6,   "RSVP IPv6 Session Query"},
  { TLV_FEC_STACK_RES,         "Reserved"},
  { TLV_FEC_STACK_VPN_IPv4,    "VPN IPv4 prefix"},
  { TLV_FEC_STACK_VPN_IPv6,    "VPN IPv6 prefix"},
  { TLV_FEC_STACK_L2_VPN,      "L2 VPN endpoint"},
  { TLV_FEC_STACK_L2_CID_OLD,  "FEC 128 Pseudowire (old)"},
  { TLV_FEC_STACK_L2_CID_NEW,  "FEC 128 Pseudowire (new)"},
  { TLV_FEC_STACK_L2_FEC_129,  "FEC 129 Pseudowire"},
  { TLV_FEC_STACK_BGP_LAB_v4,  "BGP labeled IPv4 prefix"},
  { TLV_FEC_STACK_BGP_LAB_v6,  "BGP labeled IPv6 prefix"},
  { TLV_FEC_STACK_GEN_IPv4,    "Generic IPv4 prefix"},
  { TLV_FEC_STACK_GEN_IPv6,    "Generic IPv6 prefix"},
  { TLV_FEC_STACK_NIL,         "Nil FEC"},
  { TLV_FEC_VENDOR_PRIVATE_START, "Vendor Private"},
  { 0, NULL}
};

static const value_string mpls_echo_tlv_pad[] = {
  { 1, "Drop Pad TLV from reply" },
  { 2, "Copy Pad TLV to reply" },
  { 0, NULL}
};

#define TLV_DS_MAP_ADDR_IPv4		1
#define TLV_DS_MAP_ADDR_UNNUM_IPv4	2
#define TLV_DS_MAP_ADDR_IPv6		3
#define TLV_DS_MAP_ADDR_UNNUM_IPv6	4

static const value_string mpls_echo_tlv_ds_map_addr_type[] = {
  {TLV_DS_MAP_ADDR_IPv4,	"IPv4 Numbered"},
  {TLV_DS_MAP_ADDR_UNNUM_IPv4,	"IPv4 Unnumbered"},
  {TLV_DS_MAP_ADDR_IPv6,	"IPv6 Numbered"},
  {TLV_DS_MAP_ADDR_UNNUM_IPv6,	"IPv6 Unnumbered"},
  {0, NULL}
};

#define TLV_DS_MAP_HASH_NO_MP		0
#define TLV_DS_MAP_HASH_LABEL		1
#define TLV_DS_MAP_HASH_IP		2
#define TLV_DS_MAP_HASH_LABEL_RANGE	3
#define TLV_DS_MAP_HASH_IP_RANGE	4
#define TLV_DS_MAP_HASH_NO_LABEL	5
#define TLV_DS_MAP_HASH_ALL_IP		6
#define TLV_DS_MAP_HASH_NO_MATCH	7
#define TLV_DS_MAP_HASH_BITMASK_IP	8
#define TLV_DS_MAP_HASH_BITMASK_LABEL	9

static const value_string mpls_echo_tlv_ds_map_hash_type[] = {
  {TLV_DS_MAP_HASH_NO_MP,		"no multipath"},
  {TLV_DS_MAP_HASH_LABEL,		"label"},
  {TLV_DS_MAP_HASH_IP,			"IP address"},
  {TLV_DS_MAP_HASH_LABEL_RANGE,		"label range"},
  {TLV_DS_MAP_HASH_IP_RANGE,		"IP address range"},
  {TLV_DS_MAP_HASH_NO_LABEL,		"no more labels"},
  {TLV_DS_MAP_HASH_ALL_IP,		"All IP addresses"},
  {TLV_DS_MAP_HASH_NO_MATCH,		"no match"},
  {TLV_DS_MAP_HASH_BITMASK_IP,		"Bit-masked IPv4 address set"},
  {TLV_DS_MAP_HASH_BITMASK_LABEL,	"Bit-masked label set"},
  {0, NULL}
};

static const value_string mpls_echo_tlv_ds_map_mp_proto[] = {
  {0, "Unknown"},
  {1, "Static"},
  {2, "BGP"},
  {3, "LDP"},
  {4, "RSVP-TE"},
  {5, "Reserved"},
  {0, NULL}
};

/*
 * Dissector for FEC sub-TLVs
 */
static void
dissect_mpls_echo_tlv_fec(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
        proto_tree *ti = NULL, *tlv_fec_tree = NULL;
        guint16 index = 1, nil_index = 1, type, saved_type;
        int length, nil_length, pad;
        guint32 label;
        guint8  exp, bos, ttl;

        if (tree){
          while (rem >= 4){ /* Type, Length */
            type = tvb_get_ntohs(tvb, offset);
	    saved_type = type;
	    /* Check for Vendor Private sub-TLVs */
	    if(type >= TLV_FEC_VENDOR_PRIVATE_START) /* && <= TLV_FEC_VENDOR_PRIVATE_END always true */
		type = TLV_FEC_VENDOR_PRIVATE_START;

            length = tvb_get_ntohs(tvb, offset + 2);
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "FEC Element %u: %s",
                     index, val_to_str(type, mpls_echo_tlv_fec_names, 
                     "Unknown FEC type (0x%04X)"));
            tlv_fec_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv_fec);
            if(tlv_fec_tree == NULL) return;

            /* FEC sub-TLV Type and Length */
	    proto_tree_add_uint_format(tlv_fec_tree, hf_mpls_echo_tlv_fec_type, tvb,
		offset, 2, saved_type, "Type: %s (%u)",
		val_to_str(type, mpls_echo_tlv_fec_names, "Unknown sub-TLV type"), saved_type);

            proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_len, tvb, offset + 2,
                2, FALSE);

	    if (length + 4 > rem){
		proto_tree_add_text(tlv_fec_tree, tvb, offset, rem,
			"Error processing FEC sub-TLV: length is %u and reminder is %u",
			length, rem - 4);
		return;
	    }

            /* FEC sub-TLV Value */
            switch (type) {
            case TLV_FEC_STACK_LDP_IPv4:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_ldp_ipv4, 
                    tvb, offset + 4, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_ldp_ipv4_mask, 
                    tvb, offset + 8, 1, FALSE);
                if (length == 8)
                    proto_tree_add_text(tlv_fec_tree, tvb, offset + 9, 3, "Padding");
                break;
	    case TLV_FEC_STACK_LDP_IPv6:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_ldp_ipv6,
                    tvb, offset + 4, 16, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_ldp_ipv6_mask,
                    tvb, offset + 20, 1, FALSE);
                if (length == 20)
                    proto_tree_add_text(tlv_fec_tree, tvb, offset + 21, 3, "Padding");
                break;
	    case TLV_FEC_STACK_RSVP_IPv4:
		if (length != 20){
		    proto_tree_add_text(tlv_fec_tree, tvb, offset, rem,
		        "Error processing sub-TLV: length is %d, should be 20", length);
		    return;
		}
		proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ipv4_ipv4_endpoint,
		    tvb, offset + 4, 4, FALSE);
		proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_mbz1,
		    tvb, offset + 8, 2, FALSE);
		proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_tunnel_id,
		    tvb, offset + 10, 2, FALSE);
		proto_tree_add_text(tlv_fec_tree, tvb, offset + 12, 4,
		    "Extended Tunnel ID: 0x%08X (%s)", tvb_get_ntohl(tvb, offset + 12),
		    ip_to_str(tvb_get_ptr(tvb, offset + 12, 4)));
		proto_tree_add_item_hidden(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ipv4_ext_tunnel_id,
		    tvb, offset + 12, 4, FALSE);
		proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ipv4_ipv4_sender,
		    tvb, offset + 16, 4, FALSE);
		proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_mbz2,
		    tvb, offset + 20, 2, FALSE);
		proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_lsp_id,
		    tvb, offset + 22, 2, FALSE);
		break;
            case TLV_FEC_STACK_RSVP_IPv6:
                if (length != 56){
                    proto_tree_add_text(tlv_fec_tree, tvb, offset, rem,
                        "Error processing sub-TLV: length is %d, should be 56", length);
                    return;
                }
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ipv6_ipv6_endpoint,
                    tvb, offset + 4, 16, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_mbz1,
                    tvb, offset + 20, 2, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_tunnel_id,
                    tvb, offset + 22, 2, FALSE);
                proto_tree_add_text(tlv_fec_tree, tvb, offset + 24, 16,
                    "Extended Tunnel ID: 0x%s (%s)",
		    tvb_bytes_to_str(tvb, offset + 24, 16),
                    ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset + 24, 16)));
                proto_tree_add_item_hidden(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ipv6_ext_tunnel_id,
                    tvb, offset + 24, 16, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ipv6_ipv6_sender,
                    tvb, offset + 40, 16, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_mbz2,
                    tvb, offset + 56, 2, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_rsvp_ip_lsp_id,
                    tvb, offset + 58, 2, FALSE);
                break;
            case TLV_FEC_STACK_L2_CID_OLD:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_remote,
                    tvb, offset + 4, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_vcid,
                    tvb, offset + 8, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_encap,
                    tvb, offset + 12, 2, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_mbz,
                    tvb, offset + 14, 2, FALSE);
                break;
	    case TLV_FEC_STACK_L2_CID_NEW:
                if (length < 14){
                    proto_tree_add_text(tlv_fec_tree, tvb, offset, rem,
                        "Error processing sub-TLV: length is %d, should be 14", length);
                    return;
                }
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_sender,
                    tvb, offset + 4, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_remote,
                    tvb, offset + 8, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_vcid,
                    tvb, offset + 12, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_encap,
                    tvb, offset + 16, 2, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_l2cid_mbz,
                    tvb, offset + 18, 2, FALSE);
                break;
	    case TLV_FEC_VENDOR_PRIVATE_START:
		if (length < 4) { /* SMI Enterprise code */
			proto_tree_add_text(tlv_fec_tree, tvb, offset + 4, length,
				"Error processing Vendor Private sub-TLV: length is %d, should be >= 4",
				length);
		} else {
			proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_vendor, tvb,
				offset + 4, 4, FALSE);
			proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_value, tvb,
				offset + 8, length - 4, FALSE);
		}
		break;
	    case TLV_FEC_STACK_BGP_LAB_v4:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_bgp_nh,
                    tvb, offset + 4, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_bgp_ipv4,
                    tvb, offset + 8, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_bgp_len,
                    tvb, offset + 12, 1, FALSE);
                if (length == 12)
                    proto_tree_add_text(tlv_fec_tree, tvb, offset + 13, 3, "Padding");
		break;
	    case TLV_FEC_STACK_GEN_IPv4:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_gen_ipv4,
                    tvb, offset + 4, 4, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_gen_ipv4_mask,
                    tvb, offset + 8, 1, FALSE);
                if (length == 8)
                    proto_tree_add_text(tlv_fec_tree, tvb, offset + 9, 3, "Padding");
		break;
	    case TLV_FEC_STACK_GEN_IPv6:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_gen_ipv6,
                    tvb, offset + 4, 16, FALSE);
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_gen_ipv6_mask,
                    tvb, offset + 20, 1, FALSE);
                if (length == 20)
                    proto_tree_add_text(tlv_fec_tree, tvb, offset + 21, 3, "Padding");
		break;
	    case TLV_FEC_STACK_NIL:
                nil_length = length;
	        while (nil_length >= 4){
	                decode_mpls_label(tvb, offset + 4, &label, &exp, &bos, &ttl);
	                if (label <= LABEL_MAX_RESERVED){
	                        proto_tree_add_uint_format(tlv_fec_tree, hf_mpls_echo_tlv_fec_nil_label,
	                                tvb, offset + 4, 3, label, "Label %u: %u (%s)", nil_index, label,
	                                val_to_str(label, special_labels, "Reserved - Unknown"));
	                } else {
	                        proto_tree_add_uint_format(tlv_fec_tree, hf_mpls_echo_tlv_fec_nil_label,
	                                tvb, offset + 4, 3, label, "Label %u: %u", nil_index, label);
	                }
	                nil_length -= 4;
	                offset += 4;
	                nil_index++;
	        }
		break;

            case TLV_FEC_STACK_RES:
            case TLV_FEC_STACK_VPN_IPv4:
            case TLV_FEC_STACK_VPN_IPv6:
            case TLV_FEC_STACK_L2_VPN:
            default:
		if(length)
                	proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_value,
					    tvb, offset + 4, length, FALSE);
                break;
            }

	    /*
	     * Check for padding based on sub-TLV length alignment;
	     * FEC sub-TLVs is zero-padded to align to four-octet boundary.
	     */
	    if (length  % 4){
		pad = 4 - (length % 4);
		if (length + 4 + pad > rem){
		    proto_tree_add_text(tlv_fec_tree, tvb, offset, rem,
			"Error processing FEC sub-TLV: padded length is %u and reminder is %u",
			length + pad, rem - 4);
		    return;
		} else {
		    proto_tree_add_text(tlv_fec_tree, tvb, offset + 4 + length, pad, "Padding");
		}
		length += pad;
	    }

            rem -= 4 + length;
            offset += 4 + length;
            index++;
          }
        }
}

/*
 * Dissector for Downstream Mapping TLV
 */
static void
dissect_mpls_echo_tlv_ds_map(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *tlv_ds_map_tree = NULL;
	guint16 mplen, index = 1;
	guint32 label;
	guint8	exp, bos, proto;
	guint8	hash_type, addr_type;

        proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_mtu, tvb,
                            offset, 2, FALSE);
        proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_addr_type, tvb,
                            offset + 2, 1, FALSE);
        ti = proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_res, tvb,
                            offset + 3, 1, FALSE);
        tlv_ds_map_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv_ds_map);

        proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_flag_res, tvb,
                            offset + 3, 1, FALSE);
        proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_flag_i, tvb,
                            offset + 3, 1, FALSE);
        proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_flag_n, tvb,
                            offset + 3, 1, FALSE);

	addr_type = tvb_get_guint8(tvb, offset + 2);
	switch(addr_type){
	case TLV_DS_MAP_ADDR_IPv4:
        	proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_ds_ip, tvb,
				offset + 4, 4, FALSE);
        	proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_int_ip, tvb,
				offset + 8, 4, FALSE);
		break;
	case TLV_DS_MAP_ADDR_UNNUM_IPv4:
	case TLV_DS_MAP_ADDR_UNNUM_IPv6:
                proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_ds_ip, tvb,
                                offset + 4, 4, FALSE);
                proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_if_index, tvb,
                                offset + 8, 4, FALSE);
		break;
	case TLV_DS_MAP_ADDR_IPv6:
                proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_ds_ipv6, tvb,
                                offset + 4, 16, FALSE);
                proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_int_ipv6, tvb,
                                offset + 20, 16, FALSE);
		rem -= 24;
		offset += 24;
                break;
	default:
                proto_tree_add_text(tree, tvb, offset + 4, 8,
                        "Error processing TLV: Unknown Address Type of %u",
                        addr_type);
		break;
	}
        proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_hash_type, tvb,
                            offset + 12, 1, FALSE);
        proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_depth, tvb,
                            offset + 13, 1, FALSE);
        proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_muti_len, tvb,
                            offset + 14, 2, FALSE);

	/* Get the Multipath Length and Hash Type */
	mplen = tvb_get_ntohs(tvb, offset + 14);
	hash_type = tvb_get_guint8(tvb, offset + 12);

	rem -= 16;
	offset += 16;
	if (rem < mplen){
		proto_tree_add_text(tree, tvb, offset, rem,
			"Error processing TLV: Multi Path length is %d and reminder is %u",
			mplen, rem);
		return;
	}
	rem -= mplen;
	if(mplen){
	    switch(hash_type){
	    case TLV_DS_MAP_HASH_IP:
		if(mplen != 4){
			proto_tree_add_text(tree, tvb, offset, mplen,
				"Multi Path length is %u and should be 4", mplen);
			break;
		}
		ti = proto_tree_add_text(tree, tvb, offset, 4,
			"Multipath Information");
		tlv_ds_map_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv_ds_map);
		proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_ip, tvb,
			offset, 4, FALSE);
		break;
	    case TLV_DS_MAP_HASH_IP_RANGE:
		if(mplen != 8){
			proto_tree_add_text(tree, tvb, offset, mplen,
				"Multi Path length is %u and should be 8", mplen);
			break;
		}
		ti = proto_tree_add_text(tree, tvb, offset, 8,
			"Multipath Information");
		tlv_ds_map_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv_ds_map);
		proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_ip_low, tvb,
			offset, 4, FALSE);
		proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_ip_high, tvb,
			offset + 4, 4, FALSE);
		break;
            case TLV_DS_MAP_HASH_NO_MP:
            case TLV_DS_MAP_HASH_NO_LABEL:
            case TLV_DS_MAP_HASH_ALL_IP:
            case TLV_DS_MAP_HASH_NO_MATCH:
		proto_tree_add_text(tree, tvb, offset, mplen,
			"No Multipath Information");
		break;
	    case TLV_DS_MAP_HASH_BITMASK_IP:
		if(mplen < 4){
			proto_tree_add_text(tree, tvb, offset, mplen,
				"Multi Path length is %u and should be >= 4", mplen);
			break;
		}
		ti = proto_tree_add_text(tree, tvb, offset, mplen,
			"Multipath Information");
		tlv_ds_map_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv_ds_map);
		proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_ip, tvb,
			offset, 4, FALSE);
		if(mplen > 4)
			proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_mask, tvb,
				offset + 4, mplen - 4, FALSE);
		break;
	    default:
		proto_tree_add_item(tree, hf_mpls_echo_tlv_ds_map_mp_value, tvb,
			offset, mplen, FALSE);
		break;
	    }
	}

	offset += mplen;

	while (rem >= 4){
		decode_mpls_label(tvb, offset, &label, &exp, &bos, &proto);
		ti = proto_tree_add_text(tree, tvb, offset, 4, "Downstream Label Element %u",
			index);
		tlv_ds_map_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv_ds_map);
		proto_item_append_text(ti, ", Label: %u", label);
		if (label <= LABEL_MAX_RESERVED){
			proto_tree_add_uint_format(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_label,
				tvb, offset, 3, label, "Downstream Label: %u (%s)", label,
				val_to_str(label, special_labels, "Reserved - Unknown"));
			proto_item_append_text(ti, " (%s)", val_to_str(label, special_labels,
				"Reserved - Unknown"));
		} else {
			proto_tree_add_uint_format(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_label,
				tvb, offset, 3, label, "Downstream Label: %u", label);
		}
		proto_item_append_text(ti, ", Exp: %u, BOS: %u", exp, bos);
		proto_tree_add_uint_format(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_exp,
			tvb, offset + 2, 1, exp, "Downstream Exp: %u", exp);
		proto_tree_add_uint_format(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_bos,
			tvb, offset + 2, 1, bos, "Downstream BOS: %u", bos);
		proto_tree_add_item(tlv_ds_map_tree, hf_mpls_echo_tlv_ds_map_mp_proto,
			tvb, offset + 3, 1, FALSE);
		proto_item_append_text(ti, ", Protocol: %u (%s)", proto, val_to_str(proto,
			mpls_echo_tlv_ds_map_mp_proto, "Unknown"));
		rem -= 4;
		offset += 4;
		index++;
	}
}

/*
 * Dissector for IPv4 and IPv6 Interface and Label Stack Object
 */
static void
dissect_mpls_echo_tlv_ilso(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem, gboolean is_ipv6)
{
	proto_tree *ti = NULL, *tlv_ilso = NULL;
	guint16	index = 1;
	guint32 label;
	guint8  exp, bos, ttl;

	if (is_ipv6){
		proto_tree_add_item(tree, hf_mpls_echo_tlv_ilso_ipv6_addr, tvb,
			offset, 16, FALSE);
		proto_tree_add_item(tree, hf_mpls_echo_tlv_ilso_ipv6_int_addr, tvb,
			offset + 16, 16, FALSE);

		offset += 32;
		rem -= 32;
	} else {
		proto_tree_add_item(tree, hf_mpls_echo_tlv_ilso_ipv4_addr, tvb,
			offset, 4, FALSE);
		proto_tree_add_item(tree, hf_mpls_echo_tlv_ilso_ipv4_int_addr, tvb,
			offset + 4, 4, FALSE);

		offset += 8;
		rem -= 8;
	}


        while (rem >= 4){
		decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);
                ti = proto_tree_add_text(tree, tvb, offset, 4, "Label Stack Element %u",
                        index);
                tlv_ilso = proto_item_add_subtree(ti, ett_mpls_echo_tlv_ilso);
                proto_item_append_text(ti, ", Label: %u", label);
		if (label <= LABEL_MAX_RESERVED){
                	proto_tree_add_uint_format(tlv_ilso, hf_mpls_echo_tlv_ilso_label,
	                        tvb, offset, 3, label, "Label: %u (%s)", label,
				val_to_str(label, special_labels, "Reserved - Unknown"));
			proto_item_append_text(ti, " (%s)", val_to_str(label, special_labels,
				"Reserved - Unknown"));
		} else {
			proto_tree_add_uint_format(tlv_ilso, hf_mpls_echo_tlv_ilso_label,
				tvb, offset, 3, label, "Label: %u", label);
		}
		proto_item_append_text(ti, ", Exp: %u, BOS: %u, TTL: %u",
			exp, bos, ttl);
		proto_tree_add_uint_format(tlv_ilso, hf_mpls_echo_tlv_ilso_exp,
			tvb, offset + 2, 1, exp, "Exp: %u", exp);
		proto_tree_add_uint_format(tlv_ilso, hf_mpls_echo_tlv_ilso_bos,
			tvb, offset + 2, 1, bos, "BOS: %u", bos);
		proto_tree_add_item(tlv_ilso, hf_mpls_echo_tlv_ilso_ttl,
			tvb, offset + 3, 1, FALSE);
                rem -= 4;
                offset += 4;
                index++;
        }
}

static int
dissect_mpls_echo_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem, gboolean in_errored);

/*
 * Dissector for Errored TLVs
 */
static void
dissect_mpls_echo_tlv_errored(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	int errored_tlv_length;

	while(rem >= 4){
		errored_tlv_length = dissect_mpls_echo_tlv(tvb, offset, tree, rem, TRUE);
		rem -= errored_tlv_length;
		offset += errored_tlv_length;
	}
}

/*
 * Dissector for MPLS Echo TLVs and return bytes consumed
 */
static int
dissect_mpls_echo_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem, gboolean in_errored)
{
        guint16 type, saved_type;
        int length;
        proto_tree *ti = NULL, *mpls_echo_tlv_tree = NULL;

        length = tvb_reported_length_remaining(tvb, offset);
        rem = MIN(rem, length);

        if( rem < 4 ) { /* Type Length */
                if(tree)
                    proto_tree_add_text(tree, tvb, offset, rem,
                        "Error processing TLV: length is %d, should be >= 4",
                        rem);
                return rem;
        }
        type = tvb_get_ntohs(tvb, offset);
        length = tvb_get_ntohs(tvb, offset + 2),
        rem -= 4; /* do not count Type Length */
        length = MIN(length, rem);

        if (tree) {
		/* Check for Vendor Private TLVs */
		saved_type = type;
		if(type >= TLV_VENDOR_PRIVATE_START) /* && <= TLV_VENDOR_PRIVATE_END always true */
			type = TLV_VENDOR_PRIVATE_START;

                ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s%s",
			in_errored ? "Errored TLV Type: " : "",
                        val_to_str(type, mpls_echo_tlv_type_names, "Unknown TLV type (0x%04X)"));
                mpls_echo_tlv_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv);
                if(mpls_echo_tlv_tree == NULL) return length+4;

                /* MPLS Echo TLV Type and Length */
		if (in_errored){
			proto_tree_add_uint_format(mpls_echo_tlv_tree, hf_mpls_echo_tlv_errored_type, tvb,
			    offset, 2, saved_type, "Errored TLV Type: %s (%u)",
			    val_to_str(type, mpls_echo_tlv_type_names, "Unknown TLV type"), saved_type);
		} else {
			proto_tree_add_uint_format(mpls_echo_tlv_tree, hf_mpls_echo_tlv_type, tvb,
			    offset, 2, saved_type, "Type: %s (%u)", 
			    val_to_str(type, mpls_echo_tlv_type_names, "Unknown TLV type"), saved_type);
		}
                proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_len, tvb, offset + 2, 2, FALSE);

                /* MPLS Echo TLV Value */
                if (length == 0)
                        return 4; /* Empty TLV, return Type and Length consumed. */

                switch (type) {
                case TLV_TARGET_FEC_STACK:
                        dissect_mpls_echo_tlv_fec(tvb, offset + 4, mpls_echo_tlv_tree, length);
                        break;
                case TLV_PAD:
                        proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_padaction, tvb,
                            offset + 4, 1, FALSE);
			if (length > 1)
				proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_padding, tvb,
					offset + 5, length - 1, FALSE);
                        break;
		case TLV_VENDOR_CODE:
			proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_vendor, tvb,
			offset + 4, 4, FALSE);
			break;
		case TLV_ILSO_IPv4:
                        if(length < 8) {
                                proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
                                        "Error processing TLV: length is %d, should be >= 8",
                                        length);
                                break;
                        }
                        dissect_mpls_echo_tlv_ilso(tvb, offset + 4, mpls_echo_tlv_tree, length, FALSE);
                        break;
		case TLV_ILSO_IPv6:
			if(length < 32) {
				proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
					"Error processing TLV: length is %d, should be >= 32",
					length);
				break;
			}
			dissect_mpls_echo_tlv_ilso(tvb, offset + 4, mpls_echo_tlv_tree, length, TRUE);
			break;
		case TLV_RTO_IPv4:
                        if(length != 4) {
                                proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
                                        "Error processing TLV: length is %d, should be 4",
                                        length);
                                break;
                        }
                        proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_rto_ipv4, 
                            tvb, offset + 4, 4, FALSE);
			break;
		case TLV_RTO_IPv6:
                        if(length != 16) {
                                proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
                                        "Error processing TLV: length is %d, should be 16",
                                        length);
                                break;
                        }
                        proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_rto_ipv6,    
                            tvb, offset + 4, 16, FALSE);
			break;
		case TLV_VENDOR_PRIVATE_START:
			if (length < 4) { /* SMI Enterprise code */
				proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
					"Error processing Vendor Private TLV: length is %d, should be >= 4",
					length);
			} else {
				proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_vendor, tvb,
					offset + 4, 4, FALSE);
				proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_value, tvb,
					offset + 8, length - 4, FALSE);
			}
			break;
                case TLV_DOWNSTREAM_MAPPING:
			if(length < 16) {
				proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
                        		"Error processing TLV: length is %d, should be >= 16",
                        		length);
                		break;
        		}
			dissect_mpls_echo_tlv_ds_map(tvb, offset + 4, mpls_echo_tlv_tree, length);
			break;
		case TLV_ERRORED_TLV:
			if (in_errored)
				proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_value, tvb,
					offset + 4, length, FALSE);
			else
				dissect_mpls_echo_tlv_errored(tvb, offset + 4, mpls_echo_tlv_tree, length);
			break;
		case TLV_REPLY_TOS:
			if(length != 4) {
				proto_tree_add_text(mpls_echo_tlv_tree, tvb, offset + 4, length,
					"Error processing TLV: length is %d, should be 4",
					length);
				break;
			}
			proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_reply_tos, tvb,
				offset + 4, 1, FALSE);
			proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_reply_tos_mbz, tvb,
				offset + 5, 3, FALSE);
			break;
                case TLV_ERROR_CODE:
                default:
                        proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_value, tvb,
                            offset + 4, length, FALSE);
                        break;
                }
        }
        return length + 4;  /* Length of the Value field + Type Length */
}

#define MSGTYPE_MPLS_ECHO(msgtype)	((msgtype == 1) || (msgtype == 2))
#define MSGTYPE_DATAPLANE(msgtype)	((msgtype == 3) || (msgtype == 4))

/*
 * Dissector for MPLS Echo (LSP PING) packets
 */
static void
dissect_mpls_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0, rem = 0, len;
        proto_item *ti = NULL;
        proto_tree *mpls_echo_tree = NULL, *mpls_echo_gflags = NULL;
        guint8 msgtype;
        const guint8 *ts_sent, *ts_rec;

        /* If version != 1 we assume it's not an mpls ping packet */
        if (!tvb_bytes_exist(tvb, 0, 5)) {
                return; /* Not enough information to tell version and message type. */
        }
        if (tvb_get_ntohs(tvb, 0) != 1) {
                return; /* Not version 1. */
        }

        if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS ECHO");
    
        rem = tvb_reported_length_remaining(tvb, offset);

        /* Get the message type and fill in the Column info */
        msgtype = tvb_get_guint8(tvb, offset + 4);

	/* The minimum fixed part of the packet is 16 Bytes or 32 Bytes depending on Msg Type */
        if( ((!MSGTYPE_MPLS_ECHO(msgtype)) && (rem < 16)) ||
		((MSGTYPE_MPLS_ECHO(msgtype)) && (rem < 32)) ) {
                if( check_col(pinfo->cinfo, COL_INFO) )
                        col_set_str(pinfo->cinfo, COL_INFO, "Malformed Message");
                if(tree) {
			ti = proto_tree_add_item(tree, proto_mpls_echo, tvb, 0, -1, FALSE);
			mpls_echo_tree = proto_item_add_subtree(ti, ett_mpls_echo);
                        proto_tree_add_text(mpls_echo_tree, tvb, offset, rem,
                            "Error processing Message: length is %d, should be >= %u",
                            rem, (MSGTYPE_MPLS_ECHO(msgtype)) ? 32 : 16);
		}
                return;
        }

        if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO,
                val_to_str(msgtype, mpls_echo_msgtype, "Unknown Message Type (0x%02X)"));


        if (tree) {

                /* Add subtree and dissect the fixed part of the message */
                ti = proto_tree_add_item(tree, proto_mpls_echo, tvb, 0, -1, FALSE);
                mpls_echo_tree = proto_item_add_subtree(ti, ett_mpls_echo);

                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_version, tvb, offset, 2, FALSE);

		if(MSGTYPE_MPLS_ECHO(msgtype)){
		    ti = proto_tree_add_item(mpls_echo_tree,
				hf_mpls_echo_gflags, tvb, offset + 2, 2, FALSE);
		    mpls_echo_gflags = proto_item_add_subtree(ti, ett_mpls_echo_gflags);
		    proto_tree_add_item(mpls_echo_gflags,
			hf_mpls_echo_flag_sbz, tvb, offset + 2, 2, FALSE);
		    proto_tree_add_item(mpls_echo_gflags,
			hf_mpls_echo_flag_v, tvb, offset + 2, 2, FALSE);
		} else {
		    proto_tree_add_item(mpls_echo_tree,
			hf_mpls_echo_mbz, tvb, offset + 2, 2, FALSE);
		}

                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_msgtype, tvb, offset + 4, 1, FALSE);
                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_replymode, tvb, offset + 5, 1, FALSE);
                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_returncode, tvb, offset + 6, 1, FALSE);
                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_returnsubcode, tvb, offset + 7, 1, FALSE);
                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_handle, tvb, offset + 8, 4, FALSE);
                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_sequence, tvb, offset + 12, 4, FALSE);

		if(MSGTYPE_MPLS_ECHO(msgtype)){
                	/* Using NTP routine to calculate the timestamp */
                	ts_sent = tvb_get_ptr(tvb, 16, 8);
                	proto_tree_add_bytes_format(mpls_echo_tree, hf_mpls_echo_ts_sent, tvb,
                	    offset + 16, 8, ts_sent, "Timestamp Sent: %s", ntp_fmt_ts(ts_sent));
                	ts_rec = tvb_get_ptr(tvb, 24, 8);
                	proto_tree_add_bytes_format(mpls_echo_tree, hf_mpls_echo_ts_rec, tvb,
                	    offset + 24, 8, ts_rec, "Timestamp Received: %s", ntp_fmt_ts(ts_rec));
		}

        }

	if(MSGTYPE_MPLS_ECHO(msgtype)){
            offset += 32;
            rem -= 32;
	} else {
            offset += 16;
            rem -= 16;
	}

        /* Dissect all TLVs */
        while(tvb_reported_length_remaining(tvb, offset) > 0 ) {
                len = dissect_mpls_echo_tlv(tvb, offset, mpls_echo_tree, rem, FALSE);
                offset += len;
                rem -= len;
        }

}


/* Register the protocol with Wireshark */

void
proto_register_mpls_echo(void)
{                 

        static hf_register_info hf[] = {
                { &hf_mpls_echo_version,
                        { "Version", "mpls_echo.version",
                        FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO Version Number", HFILL}
                },
                { &hf_mpls_echo_mbz,
                        { "MBZ", "mpls_echo.mbz",
                        FT_UINT16, BASE_HEX, NULL, 0x0, "MPLS ECHO Must be Zero", HFILL}
                },
                { &hf_mpls_echo_gflags,
                        { "Global Flags", "mpls_echo.flags",
                        FT_UINT16, BASE_HEX, NULL, 0x0, "MPLS ECHO Global Flags", HFILL}
                },
                { &hf_mpls_echo_flag_sbz,
                        { "Reserved", "mpls_echo.flag_sbz",
                        FT_UINT16, BASE_HEX, NULL, 0xFFFE, "MPLS ECHO Reserved Flags", HFILL}
                },
                { &hf_mpls_echo_flag_v,
                        { "Validate FEC Stack", "mpls_echo.flag_v",
                        FT_BOOLEAN, 16, NULL, 0x0001, "MPLS ECHO Validate FEC Stack Flag", HFILL}
                },
                { &hf_mpls_echo_msgtype,
                        { "Message Type", "mpls_echo.msg_type",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_msgtype), 0x0, "MPLS ECHO Message Type", HFILL}
                },
                { &hf_mpls_echo_replymode,
                        { "Reply Mode", "mpls_echo.reply_mode",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_replymode), 0x0, "MPLS ECHO Reply Mode", HFILL}
                },
                { &hf_mpls_echo_returncode,
                        { "Return Code", "mpls_echo.return_code",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_returncode), 0x0, "MPLS ECHO Return Code", HFILL}
                },
                { &hf_mpls_echo_returnsubcode,
                        { "Return Subcode", "mpls_echo.return_subcode",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO Return Subcode", HFILL}
                },
                { &hf_mpls_echo_handle,
                        { "Sender's Handle", "mpls_echo.sender_handle",
                        FT_UINT32, BASE_HEX, NULL, 0x0, "MPLS ECHO Sender's Handle", HFILL}
                },
                { &hf_mpls_echo_sequence,
                        { "Sequence Number", "mpls_echo.sequence",
                        FT_UINT32, BASE_DEC, NULL, 0x0, "MPLS ECHO Sequence Number", HFILL}
                },
                { &hf_mpls_echo_ts_sent,
                        { "Timestamp Sent", "mpls_echo.timestamp_sent",
                        FT_BYTES, BASE_NONE, NULL, 0x0, "MPLS ECHO Timestamp Sent", HFILL}
                },
                { &hf_mpls_echo_ts_rec,
                        { "Timestamp Received", "mpls_echo.timestamp_rec",
                        FT_BYTES, BASE_NONE, NULL, 0x0, "MPLS ECHO Timestamp Received", HFILL}
                },
                { &hf_mpls_echo_tlv_type,
                        { "Type", "mpls_echo.tlv.type",
                        FT_UINT16, BASE_DEC, VALS(mpls_echo_tlv_type_names), 0x0,
                        "MPLS ECHO TLV Type", HFILL}
                },
                { &hf_mpls_echo_tlv_len,
                        { "Length", "mpls_echo.tlv.len",
                        FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Length", HFILL}
                },
                { &hf_mpls_echo_tlv_value,
                        { "Value", "mpls_echo.tlv.value",
                        FT_BYTES, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Value", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_type,
                        { "Type", "mpls_echo.tlv.fec.type",
                        FT_UINT16, BASE_DEC, VALS(mpls_echo_tlv_fec_names), 0x0,
                        "MPLS ECHO TLV FEC Stack Type", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_len,
                        { "Length", "mpls_echo.tlv.fec.len",
                        FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack Length", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_value,
                        { "Value", "mpls_echo.tlv.fec.value",
                        FT_BYTES, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack Value", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_ldp_ipv4,
                        { "IPv4 Prefix", "mpls_echo.tlv.fec.ldp_ipv4",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack LDP IPv4", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_ldp_ipv4_mask,
                        { "Prefix Length", "mpls_echo.tlv.fec.ldp_ipv4_mask",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack LDP IPv4 Prefix Length", HFILL}
                },
		{ &hf_mpls_echo_tlv_fec_ldp_ipv6,
			{ "IPv6 Prefix", "mpls_echo.tlv.fec.ldp_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack LDP IPv6", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_ldp_ipv6_mask,
			{ "Prefix Length", "mpls_echo.tlv.fec.ldp_ipv6_mask",
			FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack LDP IPv6 Prefix Length", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_rsvp_ipv4_ipv4_endpoint,
			{ "IPv4 Tunnel endpoint address", "mpls_echo.tlv.fec.rsvp_ipv4_ep",
			FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP IPv4 Tunnel Endpoint Address", HFILL}
		},
                { &hf_mpls_echo_tlv_fec_rsvp_ipv6_ipv6_endpoint,
                        { "IPv6 Tunnel endpoint address", "mpls_echo.tlv.fec.rsvp_ipv6_ep",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP IPv6 Tunnel Endpoint Address", HFILL}
                },
		{ &hf_mpls_echo_tlv_fec_rsvp_ip_mbz1,
			{ "Must Be Zero", "mpls_echo.tlv.fec.rsvp_ip_mbz1",
			FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP MBZ", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_rsvp_ip_tunnel_id,
			{ "Tunnel ID", "mpls_echo.tlv.fec.rsvp_ip_tun_id",
			FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP Tunnel ID", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_rsvp_ipv4_ext_tunnel_id,
			{ "Extended Tunnel ID", "mpls_echo.tlv.fec.rsvp_ipv4_ext_tun_id",
			FT_UINT32, BASE_HEX, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP IPv4 Extended Tunnel ID", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_rsvp_ipv4_ipv4_sender,
			{ "IPv4 Tunnel sender address", "mpls_echo.tlv.fec.rsvp_ipv4_sender",
			FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP IPv4 Sender", HFILL}
		},
                { &hf_mpls_echo_tlv_fec_rsvp_ipv6_ext_tunnel_id,
                        { "Extended Tunnel ID", "mpls_echo.tlv.fec.rsvp_ipv6_ext_tun_id",
                        FT_BYTES, BASE_HEX, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP IPv6 Extended Tunnel ID", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_rsvp_ipv6_ipv6_sender,
                        { "IPv6 Tunnel sender address", "mpls_echo.tlv.fec.rsvp_ipv6_sender",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP IPv4 Sender", HFILL}
                },
		{ &hf_mpls_echo_tlv_fec_rsvp_ip_mbz2,
			{ "Must Be Zero", "mpls_echo.tlv.fec.rsvp_ip_mbz2",
			FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP MBZ", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_rsvp_ip_lsp_id,
			{ "LSP ID", "mpls_echo.tlv.fec.rsvp_ip_lsp_id",
			FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack RSVP LSP ID", HFILL}
		},
                { &hf_mpls_echo_tlv_fec_l2cid_sender,
                        { "Sender's PE Address", "mpls_echo.tlv.fec.l2cid_sender",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack L2CID Sender", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_l2cid_remote,
                        { "Remote PE Address", "mpls_echo.tlv.fec.l2cid_remote",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack L2CID Remote", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_l2cid_vcid,
                        { "VC ID", "mpls_echo.tlv.fec.l2cid_vcid",
                        FT_UINT32, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack L2CID VCID", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_l2cid_encap,
                        { "Encapsulation", "mpls_echo.tlv.fec.l2cid_encap",
                        FT_UINT16, BASE_DEC, VALS(fec_vc_types_vals), 0x0, "MPLS ECHO TLV FEC Stack L2CID Encapsulation", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_l2cid_mbz,
                        { "MBZ", "mpls_echo.tlv.fec.l2cid_mbz",
                        FT_UINT16, BASE_HEX, NULL, 0x0, "MPLS ECHO TLV FEC Stack L2CID MBZ", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_bgp_nh,
                        { "BGP Next Hop", "mpls_echo.tlv.fec.bgp_nh",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack BGP Next Hop", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_bgp_ipv4,
                        { "IPv4 Prefix", "mpls_echo.tlv.fec.bgp_ipv4",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack BGP IPv4", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_bgp_len,
                        { "Prefix Length", "mpls_echo.tlv.fec.bgp_len",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack BGP Prefix Length", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_gen_ipv4,
                        { "IPv4 Prefix", "mpls_echo.tlv.fec.gen_ipv4",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack Generic IPv4", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_gen_ipv4_mask,
                        { "Prefix Length", "mpls_echo.tlv.fec.gen_ipv4_mask",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack Generic IPv4 Prefix Length", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_gen_ipv6,
                        { "IPv6 Prefix", "mpls_echo.tlv.fec.gen_ipv6",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack Generic IPv6", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_gen_ipv6_mask,
                        { "Prefix Length", "mpls_echo.tlv.fec.gen_ipv6_mask",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack Generic IPv6 Prefix Length", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_nil_label,
                        { "Label", "mpls_echo.tlv.fec.nil_label",
                        FT_UINT24, BASE_DEC, VALS(special_labels), 0x0, "MPLS ECHO TLV FEC Stack NIL Label", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mtu,
                        { "MTU", "mpls_echo.tlv.ds_map.mtu",
                        FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Downstream Map MTU", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_addr_type,
                        { "Address Type", "mpls_echo.tlv.ds_map.addr_type",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_tlv_ds_map_addr_type), 0x0,
			"MPLS ECHO TLV Downstream Map Address Type", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_res,
                        { "DS Flags", "mpls_echo.tlv.ds_map.res",
                        FT_UINT8, BASE_HEX, NULL, 0x0, "MPLS ECHO TLV Downstream Map DS Flags", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_flag_res,
                        { "MBZ", "mpls_echo.tlv.ds_map.flag_res",
                        FT_UINT8, BASE_HEX, NULL, 0xFC, "MPLS ECHO TLV Downstream Map Reserved Flags", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_flag_i,
                        { "Interface and Label Stack Request", "mpls_echo.tlv.ds_map.flag_i",
                        FT_BOOLEAN, 8, NULL, 0x02, "MPLS ECHO TLV Downstream Map I-Flag", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_flag_n,
                        { "Treat as Non-IP Packet", "mpls_echo.tlv.ds_map.flag_n",
                        FT_BOOLEAN, 8, NULL, 0x01, "MPLS ECHO TLV Downstream Map N-Flag", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_ds_ip,
                        { "Downstream IP Address", "mpls_echo.tlv.ds_map.ds_ip",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map IP Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_int_ip,
                        { "Downstream Interface Address", "mpls_echo.tlv.ds_map.int_ip",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map Interface Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_if_index,
                        { "Upstream Interface Index", "mpls_echo.tlv.ds_map.if_index",
                        FT_UINT32, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Downstream Map Interface Index", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_ds_ipv6,
                        { "Downstream IPv6 Address", "mpls_echo.tlv.ds_map.ds_ipv6",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map IPv6 Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_int_ipv6,
                        { "Downstream Interface IPv6 Address", "mpls_echo.tlv.ds_map.int_ipv6",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map Interface IPv6 Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_hash_type,
                        { "Multipath Type", "mpls_echo.tlv.ds_map.hash_type",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_tlv_ds_map_hash_type), 0x0,
			"MPLS ECHO TLV Downstream Map Multipath Type", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_depth,
                        { "Depth Limit", "mpls_echo.tlv.ds_map.depth",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Downstream Map Depth Limit", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_muti_len,
                        { "Multipath Length", "mpls_echo.tlv.ds_map.multi_len",
                        FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Downstream Map Multipath Length", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_ip,
                        { "IP Address", "mpls_echo.tlv.ds_map_mp.ip",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map Multipath IP Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_mask,
                        { "Mask", "mpls_echo.tlv.ds_map_mp.mask",
                        FT_BYTES, BASE_HEX, NULL, 0x0, "MPLS ECHO TLV Downstream Map Multipath Mask", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_ip_low,
                        { "IP Address Low", "mpls_echo.tlv.ds_map_mp.ip_low",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map Multipath Low IP Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_ip_high,
                        { "IP Address High", "mpls_echo.tlv.ds_map_mp.ip_high",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Downstream Map Multipath High IP Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_value,
                        { "Multipath Value", "mpls_echo.tlv.ds_map_mp.value",
                        FT_BYTES, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Multipath Value", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_label,
                        { "Downstream Label", "mpls_echo.tlv.ds_map.mp_label",
                        FT_UINT24, BASE_DEC, VALS(special_labels), 0x0, "MPLS ECHO TLV Downstream Map Downstream Label", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_exp,
                        { "Downstream Experimental", "mpls_echo.tlv.ds_map.mp_exp",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Downstream Map Downstream Experimental", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_bos,
                        { "Downstream BOS", "mpls_echo.tlv.ds_map.mp_bos",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Downstream Map Downstream BOS", HFILL}
                },
                { &hf_mpls_echo_tlv_ds_map_mp_proto,
                        { "Downstream Protocol", "mpls_echo.tlv.ds_map.mp_proto",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_tlv_ds_map_mp_proto), 0x0,
			"MPLS ECHO TLV Downstream Map Downstream Protocol", HFILL}
                },
                { &hf_mpls_echo_tlv_padaction,
                        { "Pad Action", "mpls_echo.tlv.pad_action",
                        FT_UINT8, BASE_DEC, VALS(mpls_echo_tlv_pad), 0x0, "MPLS ECHO Pad TLV Action", HFILL}
                },
                { &hf_mpls_echo_tlv_padding,
                        { "Padding", "mpls_echo.tlv.pad_padding",
                        FT_BYTES, BASE_NONE, NULL, 0x0, "MPLS ECHO Pad TLV Padding", HFILL}
                },
		{ &hf_mpls_echo_tlv_vendor,
			{ "Vendor Id", "mpls_echo.tlv.vendor_id",
			FT_UINT32, BASE_DEC, VALS(sminmpec_values), 0x0, "MPLS ECHO Vendor Id", HFILL}
		},
                { &hf_mpls_echo_tlv_ilso_ipv4_addr,
                        { "Downstream IPv4 Address", "mpls_echo.tlv.ilso_ipv4.addr",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_ipv4_int_addr,
                        { "Downstream Interface Address", "mpls_echo.tlv.ilso_ipv4.int_addr",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_ipv6_addr,
                        { "Downstream IPv6 Address", "mpls_echo.tlv.ilso_ipv6.addr",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_ipv6_int_addr,
                        { "Downstream Interface Address", "mpls_echo.tlv.ilso_ipv6.int_addr",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack Address", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_label,
                        { "Label", "mpls_echo.tlv.ilso_ipv4.label",
                        FT_UINT24, BASE_DEC, VALS(special_labels), 0x0, "MPLS ECHO TLV Interface and Label Stack Label", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_exp,
                        { "Exp", "mpls_echo.tlv.ilso_ipv4.exp",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack Exp", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_bos,
                        { "BOS", "mpls_echo.tlv.ilso_ipv4.bos",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack BOS", HFILL}
                },
                { &hf_mpls_echo_tlv_ilso_ttl,
                        { "TTL", "mpls_echo.tlv.ilso_ipv4.ttl",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Interface and Label Stack TTL", HFILL}
                },
                { &hf_mpls_echo_tlv_rto_ipv4,
                        { "Reply-to IPv4 Address", "mpls_echo.tlv.rto.ipv4",
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV IPv4 Reply-To Object", HFILL}
                },
                { &hf_mpls_echo_tlv_rto_ipv6,
                        { "Reply-to IPv6 Address", "mpls_echo.tlv.rto.ipv6",
                        FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV IPv6 Reply-To Object", HFILL}
                },
                { &hf_mpls_echo_tlv_reply_tos,
                        { "Reply-TOS Byte", "mpls_echo.tlv.reply.tos",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV Reply-TOS Byte", HFILL}
                },
                { &hf_mpls_echo_tlv_reply_tos_mbz,
                        { "MBZ", "mpls_echo.tlv.reply.tos.mbz",
                        FT_UINT24, BASE_HEX, NULL, 0x0, "MPLS ECHO TLV Reply-TOS MBZ", HFILL}
                },
                { &hf_mpls_echo_tlv_errored_type,
                        { "Errored TLV Type", "mpls_echo.tlv.errored.type",
                        FT_UINT16, BASE_DEC, VALS(mpls_echo_tlv_type_names), 0x0,
                        "MPLS ECHO TLV Errored TLV Type", HFILL}
                }
        };

        static gint *ett[] = {
                &ett_mpls_echo,
		&ett_mpls_echo_gflags,
                &ett_mpls_echo_tlv,
                &ett_mpls_echo_tlv_fec,
		&ett_mpls_echo_tlv_ds_map,
		&ett_mpls_echo_tlv_ilso,
        };

        module_t *mpls_echo_module;

        proto_mpls_echo = proto_register_protocol("Multiprotocol Label Switching Echo",
            "MPLS Echo", "mpls-echo");

        proto_register_field_array(proto_mpls_echo, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        mpls_echo_module = prefs_register_protocol(proto_mpls_echo, proto_reg_handoff_mpls_echo);
        prefs_register_uint_preference(mpls_echo_module, "udp.port", "MPLS Echo UDP Port",
            "Set the UDP port for messages (if other"
            " than the default of 3503)",
            10, &global_mpls_echo_udp_port);
}


void
proto_reg_handoff_mpls_echo(void)
{
        static gboolean mpls_echo_prefs_initialized = FALSE;
        static dissector_handle_t mpls_echo_handle;

        if(!mpls_echo_prefs_initialized) {
            mpls_echo_handle = create_dissector_handle(dissect_mpls_echo,
                proto_mpls_echo);
            mpls_echo_prefs_initialized = TRUE;
        } else {
            dissector_delete("udp.port", mpls_echo_udp_port, mpls_echo_handle);
        }

        mpls_echo_udp_port = global_mpls_echo_udp_port;
        dissector_add("udp.port", global_mpls_echo_udp_port, mpls_echo_handle);
}
