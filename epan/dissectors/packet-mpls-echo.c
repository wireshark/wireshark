/* packet-mpls-echo.c
 * Routines for Multiprotocol Label Switching Echo dissection
 * Copyright 2004, Carlos Pignataro <cpignata@cisco.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#define UDP_PORT_MPLS_ECHO 3503

void proto_reg_handoff_mpls_echo(void);

static int proto_mpls_echo = -1;
static int hf_mpls_echo_version = -1;
static int hf_mpls_echo_mbz = -1;
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
static int hf_mpls_echo_tlv_padaction = -1;
static int hf_mpls_echo_tlv_padding = -1;
static int hf_mpls_echo_tlv_vendor = -1;

static gint ett_mpls_echo = -1;
static gint ett_mpls_echo_tlv = -1;
static gint ett_mpls_echo_tlv_fec = -1;

static int mpls_echo_udp_port = 0;

static guint32 global_mpls_echo_udp_port = UDP_PORT_MPLS_ECHO;

static const value_string mpls_echo_msgtype[] = {
  {1, "MPLS Echo Request"},
  {2, "MPLS Echo Reply"},
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
  {0, NULL}
};

#define TLV_TARGET_FEC_STACK       0x0001
#define TLV_DOWNSTREAM_MAPPING     0x0002
#define TLV_PAD                    0x0003
#define TLV_ERROR_CODE             0x0004
#define TLV_VENDOR_CODE            0x0005
#define TLV_VENDOR_PRIVATE_START   0xFC00
#define TLV_VENDOR_PRIVATE_END     0xFFFF

/* MPLS Echo TLV Type names */
static const value_string mpls_echo_tlv_type_names[] = {
  { TLV_TARGET_FEC_STACK,          "Target FEC Stack" },
  { TLV_DOWNSTREAM_MAPPING,        "Downstream Mapping" },
  { TLV_PAD,                       "Pad" },
  { TLV_ERROR_CODE,                "Error Code" },
  { TLV_VENDOR_CODE,               "Vendor Enterprise Code" },
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
  { TLV_FEC_STACK_L2_CID_OLD,  "L2 cirtuit ID (deprecated)"},
  { TLV_FEC_STACK_L2_CID_NEW,  "L2 cirtuit ID (current)"},
  { TLV_FEC_VENDOR_PRIVATE_START, "Vendor Private"},
  { 0, NULL}
};

static const value_string mpls_echo_tlv_pad[] = {
  { 1, "Drop Pad TLV from reply" },
  { 2, "Copy Pad TLV to reply" },
  { 0, NULL}
};

/*
 * Dissector for FEC sub-TLVs
 */
static void
dissect_mpls_echo_tlv_fec(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
        proto_tree *ti = NULL, *tlv_fec_tree = NULL;
        guint16 index = 1, type;
        int length;

        if (tree){
          while (rem >= 4){ /* Type, Length */
            type = tvb_get_ntohs(tvb, offset);
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
            proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_type, tvb, offset,
                2, FALSE);
            proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_len, tvb, offset + 2,
                2, FALSE);

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
            case TLV_FEC_STACK_RES:
            case TLV_FEC_STACK_VPN_IPv4:
            case TLV_FEC_STACK_VPN_IPv6:
            case TLV_FEC_STACK_L2_VPN:
            default:
                proto_tree_add_item(tlv_fec_tree, hf_mpls_echo_tlv_fec_value, tvb, offset + 4,
                    length, FALSE);
                break;
            }
            rem -= 4 + length;
            offset += 4 + length;
            index++;
          }
        }
}

/*
 * Dissector for MPLS Echo TLVs and return bytes consumed
 */
static int
dissect_mpls_echo_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
        guint16 type;
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
		if(type >= TLV_VENDOR_PRIVATE_START) /* && <= TLV_VENDOR_PRIVATE_END always true */
			type = TLV_VENDOR_PRIVATE_START;

                ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
                        val_to_str(type, mpls_echo_tlv_type_names, "Unknown TLV type (0x%04X)"));
                mpls_echo_tlv_tree = proto_item_add_subtree(ti, ett_mpls_echo_tlv);
                if(mpls_echo_tlv_tree == NULL) return length+4;

                /* MPLS Echo TLV Type and Length */
                proto_tree_add_uint_format(mpls_echo_tlv_tree, hf_mpls_echo_tlv_type, tvb,
                    offset, 2, type, "Type: %s (%u)", 
                    val_to_str(type, mpls_echo_tlv_type_names, "Unknown TLV type"), type );
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
                        proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_padding, tvb,
                            offset + 5, length - 1, FALSE);
                        break;
		case TLV_VENDOR_CODE:
			proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_vendor, tvb,
			offset + 4, 4, FALSE);
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
                case TLV_ERROR_CODE:
                default:
                        proto_tree_add_item(mpls_echo_tlv_tree, hf_mpls_echo_tlv_value, tvb,
                            offset + 4, length, FALSE);
                        break;
                }
        }
        return length + 4;  /* Length of the Value field + Type Length */
}

/*
 * Dissector for MPLS Echo (LSP PING) packets
 */
static void
dissect_mpls_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0, rem = 0, len;
        proto_item *ti = NULL;
        proto_tree *mpls_echo_tree = NULL;
        guint8 msgtype;
        const guint8 *ts_sent, *ts_rec;
        gchar buff[NTP_TS_SIZE];

        /* If version != 1 we assume it's not an mpls ping packet */
        if (!tvb_bytes_exist(tvb, 0, 2)) {
                return; /* Not enough information to tell. */
        }
        if (tvb_get_ntohs(tvb, 0) != 1) {
                return; /* Not version 1. */
        }

        if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS ECHO");
    
        rem = tvb_reported_length_remaining(tvb, offset);

        if( rem < 32 ) { /* The fixed part of the packet is 32 Bytes */
                if( check_col(pinfo->cinfo, COL_INFO) )
                        col_set_str(pinfo->cinfo, COL_INFO, "Malformed Message");
                if(tree)
                        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Message: length is %d, should be >= 32",
                            rem);
                return;
        }

        /* Get the message type and fill in the Column info */
        msgtype = tvb_get_guint8(tvb, offset + 4);
        if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO,
                val_to_str(msgtype, mpls_echo_msgtype, "Unknown Message Type (0x%02X)"));


        if (tree) {

                /* Add subtree and dissect the fixed part of the message */
                ti = proto_tree_add_item(tree, proto_mpls_echo, tvb, 0, -1, FALSE);
                mpls_echo_tree = proto_item_add_subtree(ti, ett_mpls_echo);

                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_version, tvb, offset, 2, FALSE);
                proto_tree_add_item(mpls_echo_tree,
                    hf_mpls_echo_mbz, tvb, offset + 2, 2, FALSE);
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

                /* Using NTP routine to calculate the timestamp */
                ts_sent = tvb_get_ptr(tvb, 16, 8);
                proto_tree_add_bytes_format(mpls_echo_tree, hf_mpls_echo_ts_sent, tvb,
                    offset + 16, 8, ts_sent, "Timestamp Sent: %s", ntp_fmt_ts(ts_sent, buff));
                ts_rec = tvb_get_ptr(tvb, 24, 8);
                proto_tree_add_bytes_format(mpls_echo_tree, hf_mpls_echo_ts_rec, tvb,
                    offset + 24, 8, ts_rec, "Timestamp Received: %s", ntp_fmt_ts(ts_rec, buff));

        }

        offset += 32;
        rem -= 32;

        /* Dissect all TLVs */
        while(tvb_reported_length_remaining(tvb, offset) > 0 ) {
                len = dissect_mpls_echo_tlv(tvb, offset, mpls_echo_tree, rem);
                offset += len;
                rem -= len;
        }

}


/* Register the protocol with Ethereal */

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
                        FT_UINT16, BASE_DEC, NULL, 0x0, "MPLS ECHO Must Be Zero", HFILL}
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
                        FT_IPv4, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack IPv4", HFILL}
                },
                { &hf_mpls_echo_tlv_fec_ldp_ipv4_mask,
                        { "Prefix Length", "mpls_echo.tlv.fec.ldp_ipv4_mask",
                        FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack IPv4 Prefix Length", HFILL}
                },
		{ &hf_mpls_echo_tlv_fec_ldp_ipv6,
			{ "IPv6 Prefix", "mpls_echo.tlv.fec.ldp_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0, "MPLS ECHO TLV FEC Stack IPv6", HFILL}
		},
		{ &hf_mpls_echo_tlv_fec_ldp_ipv6_mask,
			{ "Prefix Length", "mpls_echo.tlv.fec.ldp_ipv6_mask",
			FT_UINT8, BASE_DEC, NULL, 0x0, "MPLS ECHO TLV FEC Stack IPv6 Prefix Length", HFILL}
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
		}
        };

        static gint *ett[] = {
                &ett_mpls_echo,
                &ett_mpls_echo_tlv,
                &ett_mpls_echo_tlv_fec,
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
