/* packet-ldp.c
 * Routines for LDP (RFC 3036) packet disassembly
 *
 * $Id: packet-ldp.c,v 1.27 2002/01/21 22:15:17 guy Exp $
 * 
 * Copyright (c) November 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "prefs.h"
#include "afn.h"

#define TCP_PORT_LDP 646
#define UDP_PORT_LDP 646

void proto_reg_handoff_ldp(void);

static int proto_ldp = -1;

/* Delete the following if you do not use it, or add to it if you need */
static int hf_ldp_req = -1;
static int hf_ldp_rsp = -1;
static int hf_ldp_version = -1;
static int hf_ldp_pdu_len = -1;
static int hf_ldp_lsr = -1;
static int hf_ldp_ls_id = -1;
static int hf_ldp_msg_ubit = -1;
static int hf_ldp_msg_type = -1;
static int hf_ldp_msg_len = -1;
static int hf_ldp_msg_id = -1;
static int hf_ldp_msg_vendor_id = -1;
static int hf_ldp_msg_experiment_id = -1;
static int hf_ldp_tlv_value = -1;
static int hf_ldp_tlv_type = -1;
static int hf_ldp_tlv_unknown = -1;
static int hf_ldp_tlv_len = -1;
static int hf_ldp_tlv_val_hold = -1;
static int hf_ldp_tlv_val_target = -1;
static int hf_ldp_tlv_val_request = -1;
static int hf_ldp_tlv_val_res = -1;
static int hf_ldp_tlv_ipv4_taddr = -1;
static int hf_ldp_tlv_config_seqno = -1;
static int hf_ldp_tlv_ipv6_taddr = -1;
static int hf_ldp_tlv_fec_wc = -1;
static int hf_ldp_tlv_fec_af = -1;
static int hf_ldp_tlv_fec_len = -1;
static int hf_ldp_tlv_fec_pfval = -1;
static int hf_ldp_tlv_fec_hoval = -1;
static int hf_ldp_tlv_addrl_addr_family = -1;
static int hf_ldp_tlv_addrl_addr = -1;
static int hf_ldp_tlv_hc_value = -1;
static int hf_ldp_tlv_pv_lsrid = -1;
static int hf_ldp_tlv_generic_label = -1;
static int hf_ldp_tlv_atm_label_vbits = -1;
static int hf_ldp_tlv_atm_label_vpi = -1;
static int hf_ldp_tlv_atm_label_vci = -1;
static int hf_ldp_tlv_fr_label_len = -1;
static int hf_ldp_tlv_fr_label_dlci = -1;
static int hf_ldp_tlv_status_ebit = -1;
static int hf_ldp_tlv_status_fbit = -1;
static int hf_ldp_tlv_status_data = -1;
static int hf_ldp_tlv_status_msg_id = -1;
static int hf_ldp_tlv_status_msg_type = -1;
static int hf_ldp_tlv_extstatus_data = -1;
static int hf_ldp_tlv_returned_version = -1;
static int hf_ldp_tlv_returned_pdu_len = -1;
static int hf_ldp_tlv_returned_lsr = -1;
static int hf_ldp_tlv_returned_ls_id = -1;
static int hf_ldp_tlv_returned_msg_ubit = -1;
static int hf_ldp_tlv_returned_msg_type = -1;
static int hf_ldp_tlv_returned_msg_len = -1;
static int hf_ldp_tlv_returned_msg_id = -1;
static int hf_ldp_tlv_sess_ver = -1;
static int hf_ldp_tlv_sess_ka = -1;
static int hf_ldp_tlv_sess_advbit = -1;
static int hf_ldp_tlv_sess_ldetbit = -1;
static int hf_ldp_tlv_sess_pvlim = -1;
static int hf_ldp_tlv_sess_mxpdu = -1;
static int hf_ldp_tlv_sess_rxlsr = -1;
static int hf_ldp_tlv_sess_rxls = -1;
static int hf_ldp_tlv_sess_atm_merge = -1;
static int hf_ldp_tlv_sess_atm_lr = -1;
static int hf_ldp_tlv_sess_atm_dir = -1;
static int hf_ldp_tlv_sess_atm_minvpi = -1;
static int hf_ldp_tlv_sess_atm_maxvpi = -1;
static int hf_ldp_tlv_sess_atm_minvci = -1;
static int hf_ldp_tlv_sess_atm_maxvci = -1;
static int hf_ldp_tlv_sess_fr_merge = -1;
static int hf_ldp_tlv_sess_fr_lr = -1;
static int hf_ldp_tlv_sess_fr_dir = -1;
static int hf_ldp_tlv_sess_fr_len = -1;
static int hf_ldp_tlv_sess_fr_mindlci = -1;
static int hf_ldp_tlv_sess_fr_maxdlci = -1;
static int hf_ldp_tlv_lbl_req_msg_id = -1;
static int hf_ldp_tlv_vendor_id = -1;
static int hf_ldp_tlv_experiment_id = -1;

static int ett_ldp = -1;
static int ett_ldp_header = -1;
static int ett_ldp_ldpid = -1;
static int ett_ldp_message = -1;
static int ett_ldp_tlv = -1;
static int ett_ldp_tlv_val = -1;
static int ett_ldp_fec = -1;

static int tcp_port = 0;
static int udp_port = 0;

/* desegmentation of LDP over TCP */
static gboolean ldp_desegment = FALSE;

/* Add your functions here */

static int global_ldp_tcp_port = TCP_PORT_LDP;
static int global_ldp_udp_port = UDP_PORT_LDP;

/*
 * The following define all the TLV types I know about
 */

#define TLV_FEC                    0x0100
#define TLV_ADDRESS_LIST           0x0101
#define TLV_HOP_COUNT              0x0103
#define TLV_PATH_VECTOR            0x0104
#define TLV_GENERIC_LABEL          0x0200
#define TLV_ATM_LABEL              0x0201
#define TLV_FRAME_LABEL            0x0202
#define TLV_STATUS                 0x0300
#define TLV_EXTENDED_STATUS        0x0301
#define TLV_RETURNED_PDU           0x0302
#define TLV_RETURNED_MESSAGE       0x0303
#define TLV_COMMON_HELLO_PARMS     0x0400
#define TLV_IPV4_TRANSPORT_ADDRESS 0x0401
#define TLV_CONFIGURATION_SEQNO    0x0402
#define TLV_IPV6_TRANSPORT_ADDRESS 0x0403
#define TLV_COMMON_SESSION_PARMS   0x0500
#define TLV_ATM_SESSION_PARMS      0x0501
#define TLV_FRAME_RELAY_SESSION_PARMS 0x0502
#define TLV_LABEL_REQUEST_MESSAGE_ID 0x0600

#define TLV_VENDOR_PRIVATE_START   0x3E00
#define TLV_VENDOR_PRIVATE_END     0x3EFF
#define TLV_EXPERIMENTAL_START     0x3F00
#define TLV_EXPERIMENTAL_END       0x3FFF

static const value_string tlv_type_names[] = { 
  { TLV_FEC,                       "Forwarding Equivalence Classes TLV" },
  { TLV_ADDRESS_LIST,              "Address List TLV"},
  { TLV_HOP_COUNT,                 "Hop Count TLV"},
  { TLV_PATH_VECTOR,               "Path Vector TLV"},
  { TLV_GENERIC_LABEL,             "Generic Label TLV"},
  { TLV_ATM_LABEL,                 "ATM Label TLV"},
  { TLV_FRAME_LABEL,               "Frame Label TLV"},
  { TLV_STATUS,                    "Status TLV"},
  { TLV_EXTENDED_STATUS,           "Extended Status TLV"},
  { TLV_RETURNED_PDU,              "Returned PDU TLV"},
  { TLV_RETURNED_MESSAGE,          "Returned Message TLV"},
  { TLV_COMMON_HELLO_PARMS,        "Common Hello Parameters TLV"},
  { TLV_IPV4_TRANSPORT_ADDRESS,    "IPv4 Transport Address TLV"},
  { TLV_CONFIGURATION_SEQNO,       "Configuration Sequence Number TLV"},
  { TLV_IPV6_TRANSPORT_ADDRESS,    "IPv6 Transport Address TLV"},
  { TLV_COMMON_SESSION_PARMS,      "Common Session Parameters TLV"},
  { TLV_ATM_SESSION_PARMS,         "ATM Session Parameters TLV"},
  { TLV_FRAME_RELAY_SESSION_PARMS, "Frame Relay Session Parameters TLV"},
  { TLV_LABEL_REQUEST_MESSAGE_ID,  "Label Request Message ID TLV"},
  { TLV_VENDOR_PRIVATE_START,	"Vendor Private TLV"},
  { TLV_EXPERIMENTAL_START,	"Experimental TLV"},
  { 0, NULL}
};

/*
 * The following define all the message types I know about
 */

#define LDP_NOTIFICATION       0x0001
#define LDP_HELLO              0x0100
#define LDP_INITIALIZATION     0x0200
#define LDP_KEEPALIVE          0x0201
#define LDP_ADDRESS            0x0300
#define LDP_ADDRESS_WITHDRAWAL 0x0301
#define LDP_LABEL_MAPPING      0x0400
#define LDP_LABEL_REQUEST      0x0401
#define LDP_LABEL_WITHDRAWAL   0x0402
#define LDP_LABEL_RELEASE      0x0403
#define LDP_LABEL_ABORT_REQUEST 0x0404
#define LDP_VENDOR_PRIVATE_START 0x3E00
#define LDP_VENDOR_PRIVATE_END   0x3EFF
#define LDP_EXPERIMENTAL_MESSAGE_START 0x3F00
#define LDP_EXPERIMENTAL_MESSAGE_END   0x3FFF

static const value_string ldp_message_types[] = {
  {LDP_NOTIFICATION,             "Notification Message"},
  {LDP_HELLO,                    "Hello Message"},
  {LDP_INITIALIZATION,           "Initialization Message"},
  {LDP_KEEPALIVE,                "Keep Alive Message"},
  {LDP_ADDRESS,                  "Address Message"},
  {LDP_ADDRESS_WITHDRAWAL,       "Address Withdrawal Message"},
  {LDP_LABEL_MAPPING,            "Label Mapping Message"},
  {LDP_LABEL_REQUEST,            "Label Request Message"},
  {LDP_LABEL_WITHDRAWAL,         "Label Withdrawal Message"},
  {LDP_LABEL_RELEASE,            "Label Release Message"},
  {LDP_LABEL_ABORT_REQUEST,      "Label Abort Request Message"},
  {LDP_VENDOR_PRIVATE_START,     "Vendor-Private Message"},
  {LDP_EXPERIMENTAL_MESSAGE_START,     "Experimental Message"},
  {0, NULL}
};

static const true_false_string ldp_message_ubit = {
  "Unknown bit set",
  "Unknown bit not set"
};

static const true_false_string hello_targeted_vals = {
  "Targeted Hello",
  "Link Hello"
};

static const value_string tlv_unknown_vals[] = {
  {0, "Known TLV"},
  {1, "Known TLV"},
  {2, "Unknown TLV, do not Forward"},
  {3, "Unknown TLV, do Forward"},
  {0, NULL}
};

#define	WILDCARD_FEC	1
#define	PREFIX_FEC	2
#define	HOST_FEC	3

static const value_string fec_types[] = {
  {WILDCARD_FEC, "Wildcard FEC"},
  {PREFIX_FEC, "Prefix FEC"},
  {HOST_FEC, "Host Address FEC"},
  {0, NULL}
};

static const value_string tlv_atm_merge_vals[] = {
  {0, "Merge not supported"},
  {1, "VP merge supported"},
  {2, "VC merge supported"},
  {3, "VP & VC merge supported"},
  {0, NULL}
};

static const value_string tlv_atm_vbits_vals[] = {
  {0, "VPI & VCI Significant"},
  {1, "Only VPI Significant"},
  {2, "Only VCI Significant"},
  {3, "VPI & VCI not Significant, nonsense"},
  {0, NULL}
};

static const value_string tlv_fr_merge_vals[] = {
  {0, "Merge not supported"},
  {1, "Merge supported"},
  {2, "Unspecified"},
  {3, "Unspecified"},
  {0, NULL}
};

static const value_string tlv_fr_len_vals[] = {
  {0, "10 bits"},
  {1, "Reserved"},
  {2, "23 bits"},
  {3, "Reserved"},
  {0, NULL}
};

static const true_false_string tlv_atm_dirbit = {
  "Bidirectional capability",
  "Unidirectional capability"
};

static const true_false_string hello_requested_vals = {
  "Source requests periodic hellos",
  "Source does not request periodic hellos"
};

static const true_false_string tlv_sess_advbit_vals = {
  "Downstream On Demand proposed",
  "Downstream Unsolicited proposed"
};

static const true_false_string tlv_sess_ldetbit_vals = {
  "Loop Detection Enabled",
  "Loop Detection Disabled"
};

static const true_false_string tlv_status_ebit = {
  "Fatal Error Notification",
  "Advisory Notification"
};

static const true_false_string tlv_status_fbit = {
  "Notification should be Forwarded",
  "Notification should NOT be Forwarded"
};

static const value_string tlv_status_data[] = {
  {0, "Success"},
  {1, "Bad LDP Identifier"},
  {2, "Bad Protocol Version"},
  {3, "Bad PDU Length"},
  {4, "Unknown Message Type"},
  {5, "Bad Message Length"},
  {6, "Unknown TLV"},
  {7, "Bad TLV Length"},
  {8, "Malformed TLV Value"},
  {9, "Hold Timer Expired"},
  {10, "Shutdown"},
  {11, "Loop Detected"},
  {12, "Unknown FEC"},
  {13, "No Route"},
  {14, "No Label Resources"},
  {15, "Label Resources / Available"},
  {16, "Session Rejected / No Hello"},
  {17, "Session Rejected / Parameters Advertisement Mode"},
  {18, "Session Rejected / Parameters Max PDU Length"},
  {19, "Session Rejected / Parameters Label Range"},
  {20, "KeepAlive Timer Expired"},
  {21, "Label Request Aborted"},
  {22, "Missing Message Parameters"},
  {23, "Unsoported Address Family"},
  {24, "Session Rejected / Bad KeepAlive Time"},
  {25, "Internal Error"},
  {0, NULL}
};

/* Dissect FEC TLV */

void
dissect_tlv_fec(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti=NULL, *val_tree=NULL, *fec_tree=NULL;
	guint16	family, ix=1, ax;
	guint8	addr_size=0, *addr, implemented, prefix_len_octets, prefix_len, host_len;
	void *str_handler=NULL;
	char *str;

	if (tree) {

		if( rem < 4 ) {
			proto_tree_add_text(tree, tvb, offset, rem, "Error processing TLV");
			return;
		}

		ti=proto_tree_add_text(tree, tvb, offset, rem, "FEC Elements");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;

		while (rem > 0){
			switch (tvb_get_guint8(tvb, offset)) {
			case WILDCARD_FEC:
	  			ti = proto_tree_add_text(val_tree, tvb, offset, 4, "FEC Element %u", ix);
	  			fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
				if(fec_tree == NULL) return;
	  			proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc,tvb, offset, 4, FALSE);
	  			rem -= 1;
	  			offset += 1;
	  			break;

			case PREFIX_FEC:
				if( rem < 4 ){/*not enough*/
					proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
					return;
				}
				family=tvb_get_ntohs(tvb, offset+1);
				prefix_len=tvb_get_guint8(tvb, offset+3);
				prefix_len_octets=(prefix_len+7)/8;
				
				implemented=1;
				switch(family) {
					case AFNUM_INET: /*IPv4*/
						addr_size=4;
						str_handler=ip_to_str;
						break;
					case AFNUM_INET6: /*IPv6*/
						addr_size=16;
						str_handler=ip6_to_str;
						break;
					default:
						implemented=0;
						break;
				}

				if( !implemented ) {
					guint16 noctets;
					
					noctets= rem>4+prefix_len_octets?4+prefix_len_octets:rem;
					proto_tree_add_text(val_tree, tvb, offset, noctets,"Support for Address Family not implemented");
					offset+=noctets;
					rem-=noctets;
					break;
				}

				if( rem < 4+MIN(addr_size, prefix_len_octets) ){
					proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
					return;
				}

	  			/*Add a subtree for this*/
	  			ti = proto_tree_add_text(val_tree, tvb, offset, 4+MIN(addr_size, prefix_len_octets), "FEC Element %u", ix);
	  			fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
				if(fec_tree == NULL) return;
	  			proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, FALSE);
	  			offset += 1;

				proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, FALSE);
	  			offset += 2;

	  			proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, FALSE);
	  			offset += 1;
				
				
				if( addr_size < prefix_len_octets) {
					offset+=addr_size;
					rem-=addr_size;
	    				proto_tree_add_text(fec_tree, tvb, offset-1, 1, "Invalid prefix %u length for family %s", prefix_len, val_to_str(family, afn_vals, "Unknown Family"));
					break;
				}

				if( (addr=g_malloc0(addr_size)) == NULL ){
					/*big big trouble, no mem or bad addr_size*/
					fprintf(stderr, "packet-ldp: dissect_tlv_fec() malloc failed\n");
					return;
				}
				
				for(ax=0; ax+1 <= prefix_len_octets; ax++)
					addr[ax]=tvb_get_guint8(tvb, offset+ax);
				if( prefix_len % 8 )
					addr[ax-1] = addr[ax-1]&(0xFF<<(8-prefix_len%8));

				str = (* (char* (*)(guint8 *))str_handler)(addr);
				proto_tree_add_string_format(fec_tree, hf_ldp_tlv_fec_pfval, tvb, offset, prefix_len_octets, str, "Prefix: %s", str);
				
				offset += prefix_len_octets;
				rem -= 4+prefix_len_octets;
				g_free(addr);
				break;

			case HOST_FEC:
				if( rem < 4 ){/*not enough*/
					proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
					return;
				}
				family=tvb_get_ntohs(tvb, offset+1);
				host_len=tvb_get_guint8(tvb, offset+3);

				implemented=1;
				switch(family) {
					case AFNUM_INET: /*IPv4*/
						addr_size=4;
						str_handler=ip_to_str;
						break;
					case AFNUM_INET6: /*IPv6*/
						addr_size=16;
						str_handler=ip6_to_str;
						break;
					default:
						implemented=0;
						break;
				}

				if( !implemented ) {
					guint16 noctets;
					
					noctets= rem>4+host_len?4+host_len:rem;
					proto_tree_add_text(val_tree, tvb, offset, noctets,"Support for Address Family not implemented");
					offset+=noctets;
					rem-=noctets;
					break;
				}

				if( rem < 4+addr_size ){
					proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
					return;
				}

	  			/*Add a subtree for this*/
	  			ti = proto_tree_add_text(val_tree, tvb, offset, 4+addr_size, "FEC Element %u", ix);
	  			fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
				if(fec_tree == NULL) return;
	  			proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, FALSE);
	  			offset += 1;

				proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, FALSE);
	  			offset += 2;

	  			proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, FALSE);
	  			offset += 1;
				
				
				if( addr_size != host_len) {
					offset+=addr_size;
					rem-=addr_size;
	    				proto_tree_add_text(fec_tree, tvb, offset-1, 1, "Invalid address length %u length for family %s", host_len, val_to_str(family, afn_vals, "Unknown Family"));
					break;
				}

				if( (addr=g_malloc0(addr_size)) == NULL ){
					/*big big xtrouble, no mem or bad addr_size*/
					fprintf(stderr, "packet-ldp: dissect_tlv_fec() malloc failed\n");
					return;
				}
				
				for(ax=0; ax+1 <= host_len; ax++)
					addr[ax]=tvb_get_guint8(tvb, offset+ax);

				str = (* (char* (*)(guint8 *))str_handler)(addr);
				proto_tree_add_string_format(fec_tree, hf_ldp_tlv_fec_hoval, tvb, offset, host_len, str, "Address: %s", str);
				
				offset += host_len;
				rem -= 4+host_len;
				g_free(addr);
				break;

			default:  /* Unknown */
			/* XXX - do all FEC's have a length that's a multiple of 4? */
			/* Hmmm, don't think so. Will check. RJS. */
			/* If we don't know its structure, we have to exit */
	  			ti = proto_tree_add_text(val_tree, tvb, offset, 4, "FEC Element %u", ix);
	  			fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
				if(fec_tree == NULL) return;
	  			proto_tree_add_text(fec_tree, tvb, offset, rem, "Unknown FEC TLV type");
				return;
			}
			ix++;
		}
	}
}

/* Dissect Address List TLV */

void
dissect_tlv_address_list(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;
	guint16	family, ix;
	guint8	addr_size, *addr;
	void *str_handler;
	char *str;

	if (tree) {
		if( rem < 2 ) {
			proto_tree_add_text(tree, tvb, offset, rem,
					 "Error processing TLV");
			return;
		}

		family=tvb_get_ntohs(tvb, offset);
    		proto_tree_add_item(tree, hf_ldp_tlv_addrl_addr_family, tvb,
					 offset, 2, FALSE);
		switch(family) {
			case AFNUM_INET: /*IPv4*/
				addr_size=4;
				str_handler=ip_to_str;
				break;
			case AFNUM_INET6: /*IPv6*/
				addr_size=16;
				str_handler=ip6_to_str;
				break;
			default:
				proto_tree_add_text(tree, tvb, offset+2, rem-2,
				 "Support for Address Family not implemented");
				return;
		}

		offset+=2; rem-=2;
		ti=proto_tree_add_text(tree, tvb, offset, rem, "Addresses");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

		if(val_tree == NULL) return;
		if( (addr=g_malloc(addr_size)) == NULL ){
			/*big big trouble*/
			fprintf(stderr, "packet-ldp: dissect_tlv_address_list() malloc failed\n");
			return;
		}

		for(ix=1; rem >= addr_size; ix++, offset += addr_size,
							 rem -= addr_size) {
			if( (tvb_memcpy(tvb, addr, offset, addr_size))
							 == NULL)
				break;

			str = (* (char* (*)(guint8 *))str_handler)(addr);
			proto_tree_add_string_format(val_tree,
			hf_ldp_tlv_addrl_addr, tvb, offset, addr_size, str,
			"Address %u : %s", ix, str);
		}
		if(rem)
			proto_tree_add_text(val_tree, tvb, offset, rem,
					 "Error processing TLV");
		g_free(addr);
	}
}

/* Dissect Path Vector TLV */

void
dissect_tlv_path_vector(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;
	guint8	ix, *addr;

	if (tree) {
		ti=proto_tree_add_text(tree, tvb, offset, rem, "LSR IDs");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

		if(val_tree == NULL) return;

		for(ix=1; rem >= 4; ix++, offset += 4, rem -= 4) {
			if( (addr=(guint8 *)tvb_get_ptr(tvb, offset, 4))
							 == NULL)
				break;
			proto_tree_add_ipv4_format(val_tree, hf_ldp_tlv_pv_lsrid, tvb,
			offset, 4, tvb_get_ntohl(tvb, offset), "LSR Id %u : %s", ix,
			ip_to_str(addr));
		}
		if(rem)
			proto_tree_add_text(val_tree, tvb, offset, rem,
					 "Error processing TLV");
	}
}

/* Dissect ATM Label TLV */

void
dissect_tlv_atm_label(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;
	guint16	id;

	if(tree) {
		if(rem != 4){
			proto_tree_add_text(tree, tvb, offset, rem, "Error processing TLV");
			return;
		}
		ti=proto_tree_add_text(tree, tvb, offset, rem, "ATM Label");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;

		proto_tree_add_item(val_tree, hf_ldp_tlv_atm_label_vbits, tvb, offset, 1, FALSE);

		id=tvb_get_ntohs(tvb, offset)&0x0FFF;
		proto_tree_add_uint_format(val_tree, hf_ldp_tlv_atm_label_vpi, tvb, offset, 2, id, "VPI: %u", id); 
			
		id=tvb_get_ntohs(tvb, offset+2);
		proto_tree_add_uint_format(val_tree, hf_ldp_tlv_atm_label_vci, tvb, offset+2, 2, id, "VCI: %u", id); 
	}
}

/* Dissect FRAME RELAY Label TLV */

void
dissect_tlv_frame_label(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;
	guint8	len;
	guint32	id;

	if(tree) {
		if(rem != 4){
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing TLV");
			return;
		}
		ti=proto_tree_add_text(tree, tvb, offset, rem, "Frame Relay Label");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;

		len=(guint8)(tvb_get_ntohs(tvb, offset)>>7) & 0x03;
		proto_tree_add_uint_format(val_tree, hf_ldp_tlv_fr_label_len, tvb, offset, 2, len, "Number of DLCI bits: %s (%u)", val_to_str(len, tlv_fr_len_vals, "Unknown Length"), len); 

		id=tvb_get_ntoh24(tvb, offset+1)&0x7FFFFF;
		proto_tree_add_uint_format(val_tree, 
		hf_ldp_tlv_fr_label_dlci, tvb, offset+1, 3, id, "DLCI: %u", id); 
	}
}

/* Dissect STATUS TLV */

void
dissect_tlv_status(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;
	guint32	data;

	if(tree) {
		if(rem != 10){
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing TLV");
			return;
		}

		ti=proto_tree_add_text(tree, tvb, offset, rem, "Status");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;

		proto_tree_add_item(val_tree, hf_ldp_tlv_status_ebit, tvb, offset, 1, FALSE); 
		proto_tree_add_item(val_tree, hf_ldp_tlv_status_fbit, tvb, offset, 1, FALSE); 

		data=tvb_get_ntohl(tvb, offset)&0x3FFFFFFF;
		proto_tree_add_uint_format(val_tree, hf_ldp_tlv_status_data, tvb, offset, 4, data, "Status Data: %s (0x%X)", val_to_str(data, tlv_status_data, "Unknown Status Data"), data); 

		proto_tree_add_item(val_tree, hf_ldp_tlv_status_msg_id, tvb, offset+4, 4, FALSE); 
		proto_tree_add_item(val_tree, hf_ldp_tlv_status_msg_type, tvb, offset+8, 2, FALSE); 
	}
}

/* Dissect Returned PDU TLV */

void
dissect_tlv_returned_pdu(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;

	if(tree) {
		if(rem < 10){
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing TLV");
			return;
		}
		ti=proto_tree_add_text(tree, tvb, offset, rem, "Returned PDU");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;

		proto_tree_add_item(val_tree, hf_ldp_tlv_returned_version, tvb, offset, 2, FALSE); 
		proto_tree_add_item(val_tree, hf_ldp_tlv_returned_pdu_len, tvb, offset+2, 2, FALSE); 
		proto_tree_add_item(val_tree, hf_ldp_tlv_returned_lsr, tvb, offset+4, 4, FALSE); 
		proto_tree_add_item(val_tree, hf_ldp_tlv_returned_ls_id, tvb, offset+8, 2, FALSE); 
		offset += 10;
		rem -= 10;

		if( rem > 0 ) {
		/*XXX - dissect returned pdu data*/
			proto_tree_add_text(val_tree, tvb, offset, rem, "Returned PDU Data");
		}
	}
}

/* Dissect Returned MESSAGE TLV */

void
dissect_tlv_returned_message(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;
	guint16	type;

	if(tree) {
		if(rem < 4){
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing TLV");
			return;
		}
		ti=proto_tree_add_text(tree, tvb, offset, rem, "Returned Message");
		val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;

		proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_ubit, tvb, offset, 1, FALSE); 

		type=tvb_get_ntohs(tvb, offset)&0x7FFF;
		proto_tree_add_uint_format(val_tree, hf_ldp_tlv_returned_msg_type, tvb, offset, 2, type, "Message Type: %s (0x%X)", val_to_str(type, ldp_message_types,"Unknown Message Type"), type); 

		proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_len, tvb, offset+2, 2, FALSE); 
		offset += 4;
		rem -= 4;

		if( rem >= 4  ) { /*have msg_id*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_id, tvb, offset, 4, FALSE); 
			offset += 4;
			rem -= 4;
		}

		if( rem > 0 ) {
		/*XXX - dissect returned msg parameters*/
			proto_tree_add_text(val_tree, tvb, offset, rem, "Returned Message Parameters");
		}
	}
}

/* Dissect the common hello params */

void 
dissect_tlv_common_hello_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;

	if (tree) {
#if 0
		ti = proto_tree_add_item(tree, hf_ldp_tlv_value, tvb, offset, rem, FALSE);
		val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);
		if(val_tree == NULL) return;
#else
		val_tree=tree;
#endif
		proto_tree_add_item(val_tree, hf_ldp_tlv_val_hold, tvb, offset, 2, FALSE);
		proto_tree_add_boolean(val_tree, hf_ldp_tlv_val_target, tvb, offset + 2, 2, FALSE);
		proto_tree_add_boolean(val_tree, hf_ldp_tlv_val_request, tvb, offset + 2, 2, FALSE);
		proto_tree_add_item(val_tree, hf_ldp_tlv_val_res, tvb, offset + 2, 2, FALSE);
	}
}

/* Dissect the common session params */

void 
dissect_tlv_common_session_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL;

	if (tree != NULL) {
		ti = proto_tree_add_text(tree, tvb, offset, rem, "Parameters");
		if( rem != 14) { /*length of Comm Sess Parms tlv*/
			proto_tree_add_text(tree, tvb, offset, rem, "Error processing TLV");
			return ;
		}
    		val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

		if(val_tree != NULL) {
			/*Protocol Version*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ver, tvb,offset, 2, FALSE); 

			/*KeepAlive Time*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ka, tvb,offset + 2, 2, FALSE);

			/*A bit*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_advbit,tvb, offset + 4, 1, FALSE);
					 
			/*D bit*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ldetbit,tvb, offset + 4, 1, FALSE);
					 
			/*Path Vector Limit*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_pvlim,tvb, offset + 5, 1, FALSE);
					 
			/*Max PDU Length*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_mxpdu,tvb, offset + 6, 2, FALSE);
					 
			/*Rx LSR*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_rxlsr,tvb, offset + 8, 4, FALSE);
					 
			/*Rx LS*/
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_rxls,tvb, offset + 12, 2, FALSE);
		}
	}
}

/* Dissect the atm session params */

void 
dissect_tlv_atm_session_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL, *lbl_tree = NULL;
	guint8 numlr, ix;
	guint16 id;

	if (tree != NULL) {
		if(rem < 4) {
			proto_tree_add_text(tree, tvb, offset, rem,
						 "Error processing TLV");
			return;
		}

    		ti = proto_tree_add_text(tree, tvb, offset, rem,"ATM Parameters");
		val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

		if(val_tree != NULL) {
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_atm_merge,tvb, offset, 1, FALSE); 

			/*get the number of label ranges*/	
			numlr=(tvb_get_guint8(tvb, offset)>>2) & 0x0F;
			proto_tree_add_uint_format(val_tree, hf_ldp_tlv_sess_atm_lr,
			tvb, offset, 1, numlr, "Number of Label Range components: %u",
			numlr); 

			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_atm_dir,tvb, offset, 1, FALSE); 

			/*move into range components*/
			offset += 4;
			rem -= 4;
			ti = proto_tree_add_text(val_tree, tvb, offset, rem,"ATM Label Range Components");
				 
			if(numlr) {
				val_tree=proto_item_add_subtree(ti,ett_ldp_tlv_val);
				if( ! val_tree ) return;
			}
			/*now dissect ranges*/
			for(ix=1; numlr > 0 && rem >= 8; ix++, rem-=8, numlr--) {
				ti=proto_tree_add_text(val_tree, tvb, offset, 8,
				 "ATM Label Range Component %u", ix);
				lbl_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

				if( lbl_tree == NULL ) break;

				id=tvb_get_ntohs(tvb, offset)&0x0FFF;
				proto_tree_add_uint_format(lbl_tree, 
			hf_ldp_tlv_sess_atm_minvpi,tvb, offset, 2, id, "Minimum VPI: %u", id); 
				id=tvb_get_ntohs(tvb, offset+4)&0x0FFF;
				proto_tree_add_uint_format(lbl_tree, 
			hf_ldp_tlv_sess_atm_maxvpi,tvb, (offset+4), 2, id, "Maximum VPI: %u", id); 
				 
				id=tvb_get_ntohs(tvb, offset+2);
				proto_tree_add_uint_format(lbl_tree, 
			hf_ldp_tlv_sess_atm_minvci,tvb, offset+2, 2, id, "Minimum VCI: %u", id); 
				id=tvb_get_ntohs(tvb, offset+6);
				proto_tree_add_uint_format(lbl_tree, 
			hf_ldp_tlv_sess_atm_maxvci,tvb, offset+6, 2, id, "Maximum VCI: %u", id); 

				offset += 8;
			}
			if( rem || numlr)
				proto_tree_add_text(val_tree, tvb, offset, rem,"Error processing TLV");
		}
	}
}

/* Dissect the frame relay session params */

void 
dissect_tlv_frame_relay_session_parms(tvbuff_t *tvb, guint offset,proto_tree *tree, int rem)
{
	proto_tree *ti = NULL, *val_tree = NULL, *lbl_tree = NULL;
	guint8 numlr, ix, len;
	guint32	id;

	if (tree != NULL) {
		if(rem < 4) {
			proto_tree_add_text(tree, tvb, offset, rem,
						 "Error processing TLV");
			return;
		}

    		ti = proto_tree_add_text(tree, tvb, offset, rem,
						 "Frame Relay Parameters");
		val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

		if(val_tree != NULL) {
			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_fr_merge,
				tvb, offset, 1, FALSE); 

			/*get the number of label ranges*/	
			numlr=(tvb_get_guint8(tvb, offset)>>2) & 0x0F;
			proto_tree_add_uint_format(val_tree, hf_ldp_tlv_sess_fr_lr,
			tvb, offset, 1, numlr, "Number of Label Range components: %u",
			numlr); 

			proto_tree_add_item(val_tree, hf_ldp_tlv_sess_fr_dir,
				 tvb, offset, 1, FALSE); 

			/*move into range components*/
			offset += 4;
			rem -= 4;
			ti = proto_tree_add_text(val_tree, tvb, offset, rem,
				 "Frame Relay Label Range Components");

			if(numlr) {
				val_tree=proto_item_add_subtree(ti,
							 ett_ldp_tlv_val);
				if( ! val_tree ) return;
			}

			/*now dissect ranges*/
			for(ix=1; numlr > 0 && rem >= 8; ix++, rem-=8, numlr--) {
				ti=proto_tree_add_text(val_tree, tvb, offset, 8,
				"Frame Relay Label Range Component %u", ix);
				lbl_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

				if( lbl_tree == NULL ) break;

				len=(guint8)(tvb_get_ntohs(tvb, offset)>>7) & 0x03;
				proto_tree_add_uint_format(lbl_tree, hf_ldp_tlv_sess_fr_len, tvb, offset, 2, len, "Number of DLCI bits: %s (%u)", val_to_str(len, tlv_fr_len_vals, "Unknown Length"), len); 

				id=tvb_get_ntoh24(tvb, offset+1)&0x7FFFFF;
				proto_tree_add_uint_format(lbl_tree, 
			hf_ldp_tlv_sess_fr_mindlci, tvb, offset+1, 3, id, "Minimum DLCI %u", id); 
				id=tvb_get_ntoh24(tvb, offset+5)&0x7FFFFF;
				proto_tree_add_uint_format(lbl_tree, 
			hf_ldp_tlv_sess_fr_maxdlci, tvb, offset+5, 3, id, "Maximum DLCI %u", id); 

				offset += 8;
			}

			if( rem || numlr)
				proto_tree_add_text(val_tree, tvb, offset, rem,
				 "Error processing TLV");
		}
	}
}


/* Dissect a TLV and return the number of bytes consumed ... */

int
dissect_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
	guint16 type, typebak;
	int length;
	proto_tree *ti = NULL, *tlv_tree = NULL;

	length=tvb_reported_length_remaining(tvb, offset);
	rem=MIN(rem, length);

	if( rem < 4 ) {/*chk for minimum header*/
		if(tree)
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing TLV");
		return rem;
	}
	type = tvb_get_ntohs(tvb, offset) & 0x3FFF;

	length = tvb_get_ntohs(tvb, offset + 2),
	rem -= 4; /*do not count header*/
	length = MIN(length, rem);  /* Don't go haywire if a problem ... */

	if (tree != NULL) {
		/*chk for vendor-private*/
		if(type>=TLV_VENDOR_PRIVATE_START && type<=TLV_VENDOR_PRIVATE_END){
			typebak=type;		/*keep type*/	
			type=TLV_VENDOR_PRIVATE_START;

		/*chk for experimental*/
		} else if(type>=TLV_EXPERIMENTAL_START && type<=TLV_EXPERIMENTAL_END){
			typebak=type;		/*keep type*/	
			type=TLV_EXPERIMENTAL_START;
		}

		ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
	     		val_to_str(type, tlv_type_names, "Unknown TLV type (0x%04X)"));
		tlv_tree = proto_item_add_subtree(ti, ett_ldp_tlv);
		if(tlv_tree == NULL) return length+4;

		proto_tree_add_item(tlv_tree, hf_ldp_tlv_unknown, tvb, offset, 1, FALSE);

		proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2, type, "TLV Type: %s (0x%X)", val_to_str(type, tlv_type_names, "Unknown TLV type"), type ); 

		proto_tree_add_item(tlv_tree, hf_ldp_tlv_len, tvb, offset + 2, 2, FALSE);

		switch (type) {

		case TLV_FEC:
			dissect_tlv_fec(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_ADDRESS_LIST:
			dissect_tlv_address_list(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_HOP_COUNT:
			if( length != 1 ) /*error, only one byte*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4,length,"Error processing TLV");
			else
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_hc_value, tvb,offset + 4, length, FALSE); 
			break;

		case TLV_PATH_VECTOR:
			dissect_tlv_path_vector(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_GENERIC_LABEL:
			if( length != 4 ) /*error, need only label*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				guint32 label=tvb_get_ntohl(tvb, offset+4) & 0x000FFFFF;

				proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_generic_label,
					tvb, offset+4, length, label, "Generic Label: %u", label); 
			}
			break;

		case TLV_ATM_LABEL:
			dissect_tlv_atm_label(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_FRAME_LABEL:
			dissect_tlv_frame_label(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_STATUS:
			dissect_tlv_status(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_EXTENDED_STATUS:
			if( length != 4 ) /*error, need only status_code(guint32)*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_extstatus_data, tvb, offset + 4, length, FALSE); 
			}
			break;

		case TLV_RETURNED_PDU:
			dissect_tlv_returned_pdu(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_RETURNED_MESSAGE:
			dissect_tlv_returned_message(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_COMMON_HELLO_PARMS:
			dissect_tlv_common_hello_parms(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_IPV4_TRANSPORT_ADDRESS:
			if( length != 4 ) /*error, need only ipv4*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv4_taddr, tvb, offset + 4, 4, FALSE);
			}
			break;

		case TLV_CONFIGURATION_SEQNO:
			if( length != 4 ) /*error, need only seq_num(guint32)*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_config_seqno, tvb, offset + 4, 4, FALSE);
			}
			break;

		case TLV_IPV6_TRANSPORT_ADDRESS:
			if( length != 16 ) /*error, need only ipv6*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv6_taddr, tvb, offset + 4, 16, FALSE);
			}
			break;

		case TLV_COMMON_SESSION_PARMS:
			dissect_tlv_common_session_parms(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_ATM_SESSION_PARMS:
			dissect_tlv_atm_session_parms(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_FRAME_RELAY_SESSION_PARMS:
			dissect_tlv_frame_relay_session_parms(tvb, offset + 4, tlv_tree, length);
			break;

		case TLV_LABEL_REQUEST_MESSAGE_ID:
			if( length != 4 ) /*error, need only one msgid*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_lbl_req_msg_id, tvb,offset + 4,length, FALSE); 
			break;

		case TLV_VENDOR_PRIVATE_START:
			if( length < 4 ) /*error, at least Vendor ID*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_vendor_id, tvb,offset + 4, 4, FALSE); 
				if( length > 4 )  /*have data*/ 
					proto_tree_add_text(tlv_tree, tvb, offset + 8, length-4,"Data");
			}
			break;

		case TLV_EXPERIMENTAL_START:
			if( length < 4 ) /*error, at least Experiment ID*/
				proto_tree_add_text(tlv_tree, tvb, offset + 4, length,"Error processing TLV");
			else {
				proto_tree_add_item(tlv_tree, hf_ldp_tlv_experiment_id, tvb,offset + 4, 4, FALSE); 
				if( length > 4 )  /*have data*/ 
					proto_tree_add_text(tlv_tree, tvb, offset + 8, length-4,"Data");
			}
			break;

		default:
			proto_tree_add_item(tlv_tree, hf_ldp_tlv_value, tvb, offset + 4, length, FALSE);
			break;
    		}
	}

	return length + 4;  /* Length of the value field + header */
}


/* Dissect a Message and return the number of bytes consumed ... */

int
dissect_msg(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, int rem)
{
	guint16 type, typebak;
	guint8	extra=0;
	int length, ao=0, co;
	proto_tree *ti = NULL, *msg_tree = NULL;

	length=tvb_reported_length_remaining(tvb, offset);
	rem=MIN(rem, length);

	if( rem < 8 ) {/*chk for minimum header = type + length + msg_id*/
		if( check_col(pinfo->cinfo, COL_INFO) )
			col_append_fstr(pinfo->cinfo, COL_INFO, "Bad Message");
		if(tree)
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing Message");
		return rem;
	}
	type = tvb_get_ntohs(tvb, offset) & 0x7FFF;

	/*chk for vendor-private*/
	if(type>=LDP_VENDOR_PRIVATE_START && type<=LDP_VENDOR_PRIVATE_END){
		typebak=type;		/*keep type*/	
		type=LDP_VENDOR_PRIVATE_START;
		extra=4;
	/*chk for experimental*/
	} else if(type>=LDP_EXPERIMENTAL_MESSAGE_START && type<=LDP_EXPERIMENTAL_MESSAGE_END){
		typebak=type;		/*keep type*/	
		type=LDP_EXPERIMENTAL_MESSAGE_START;
		extra=4;
	}

	if( (length = tvb_get_ntohs(tvb, offset + 2)) < (4+extra) ) {/*not enough data for type*/
		if( check_col(pinfo->cinfo, COL_INFO) )
			col_append_fstr(pinfo->cinfo, COL_INFO, "Bad Message Length ");
		if(tree)
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing Message Length");
		return rem;
	}
	rem -= 4; 
	length = MIN(length, rem);  /* Don't go haywire if a problem ... */

	if( check_col(pinfo->cinfo, COL_INFO) ){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, ldp_message_types, "Unknown Message (0x%04X)"));
	}

	if( tree ){
		ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
	     		val_to_str(type, ldp_message_types, "Unknown Message type (0x%04X)"));
		msg_tree = proto_item_add_subtree(ti, ett_ldp_message);
		if(msg_tree == NULL) return length+4;

		proto_tree_add_item(msg_tree, hf_ldp_msg_ubit, tvb, offset, 1, FALSE);

		type=tvb_get_ntohs(tvb, offset)&0x7FFF;
		proto_tree_add_uint_format(msg_tree, hf_ldp_msg_type, tvb, offset, 2, type, "Message Type: %s (0x%X)", val_to_str(type, ldp_message_types,"Unknown Message Type"), type); 

		proto_tree_add_item(msg_tree, hf_ldp_msg_len, tvb, offset+2, 2, FALSE);
		proto_tree_add_item(msg_tree, hf_ldp_msg_id, tvb, offset+4, 4, FALSE);
		if(extra){
			int hf_tmp=0;

			switch(type){
				case LDP_VENDOR_PRIVATE_START:
					hf_tmp=hf_ldp_msg_vendor_id;
					break;
				case LDP_EXPERIMENTAL_MESSAGE_START:
					hf_tmp=hf_ldp_msg_experiment_id;
					break;
			}
			proto_tree_add_item(msg_tree, hf_tmp, tvb, offset+8, extra, FALSE);
		}
	}
		
	offset += (8+extra);
	length -= (4+extra);
	
	if( tree )	
		while( (length-ao) > 0 ) {
			co=dissect_tlv(tvb, offset, msg_tree, length-ao);
		 	offset += co;
			ao += co;
		}
	
	return length+8+extra;
}

/* Dissect a PDU and return the number of bytes consumed ... */

int
dissect_ldp_pdu(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, int rem, guint ix)
{
	int length, ao=0, co;
	proto_tree *ti=NULL, *pdu_tree = NULL;
	
	length=tvb_reported_length_remaining(tvb, offset);
	rem=MIN(rem, length);
	
	if( rem < 10 ){/*don't even have a PDU header*/
/*XXX Need changes in desegment_tcp to handle multiple requests*/
#if 0
		if( pinfo->can_desegment && (pinfo->ptype==PT_TCP) && ldp_desegment ){
			pinfo->desegment_offset=offset;
			pinfo->desegment_len=10-rem;
		}
#else
		if(tree)
			proto_tree_add_text(tree, tvb, offset, rem,"Not enough bytes for PDU Hdr in TCP segment");
#endif
		return rem;
	}

	if( (length = tvb_get_ntohs(tvb, offset + 2)) < 6 ) {/*not enough*/
		if( check_col(pinfo->cinfo, COL_INFO) && ix )
			col_append_fstr(pinfo->cinfo, COL_INFO, "PDU %u: ", ix);
		if( check_col(pinfo->cinfo, COL_INFO) ){
			col_append_fstr(pinfo->cinfo, COL_INFO, "Bad PDU Length ");
		}
		if(tree)
			proto_tree_add_text(tree, tvb, offset, rem,"Error processing PDU Length");
		return rem;
	}

	rem -=4;
	if( length>rem ){
		if( pinfo->can_desegment && (pinfo->ptype==PT_TCP) && ldp_desegment ){/*ask for more*/
			pinfo->desegment_offset=offset;
			pinfo->desegment_len=length-rem;
		}else {
			if( check_col(pinfo->cinfo, COL_INFO) && ix )
				col_append_fstr(pinfo->cinfo, COL_INFO, "PDU %u: ", ix);
			if( check_col(pinfo->cinfo, COL_INFO) )
				col_append_fstr(pinfo->cinfo, COL_INFO, "Bad PDU Length ");
			if(tree)
				proto_tree_add_text(tree, tvb, offset, rem+4,"Error processing PDU Length");
		}
		return rem+4;
	}
	
	if( check_col(pinfo->cinfo, COL_INFO) && ix )
		col_append_fstr(pinfo->cinfo, COL_INFO, "PDU %u: ", ix);

	if( tree ){
		ti=proto_tree_add_protocol_format(tree, proto_ldp, tvb, offset,
		    length+4, "LDP PDU %u", ix);
		pdu_tree = proto_item_add_subtree(ti, ett_ldp);
	}

	if(pdu_tree){
		proto_tree_add_item(pdu_tree, hf_ldp_version, tvb, offset, 2, FALSE);
		proto_tree_add_item(pdu_tree, hf_ldp_pdu_len, tvb, offset+2, 2, FALSE);
		proto_tree_add_item(pdu_tree, hf_ldp_lsr, tvb, offset+4, 4, FALSE);
		proto_tree_add_item(pdu_tree, hf_ldp_ls_id, tvb, offset+8, 2, FALSE);
	}
	offset += 10;
	length -= 6;

	while( (length-ao) > 0 ) {
		co=dissect_msg(tvb, offset, pinfo, pdu_tree, length-ao);
		offset += co;
		ao += co;
	}
	
	return length+10;
}

static void
dissect_ldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDP");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	dissect_ldp_pdu(tvb, 0, pinfo, tree, tvb_reported_length(tvb), 0);
}

static void
dissect_ldp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{ 
	int offset=0, length, rtn;
	guint ix=1;
  

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDP");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	length=tvb_reported_length(tvb);
	while (length > 0){
		rtn = dissect_ldp_pdu(tvb, offset, pinfo, tree, length, ix++);
		offset += rtn;
		length -= rtn;
	}
}

/* Register all the bits needed with the filtering engine */

void 
proto_register_ldp(void)
{
  static hf_register_info hf[] = {
    { &hf_ldp_req,
      /* Change the following to the type you need */
      { "Request", "ldp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_ldp_rsp,
      { "Response", "ldp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_ldp_version,
      { "Version", "ldp.hdr.version", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP Version Number", HFILL }},

    { &hf_ldp_pdu_len,
      { "PDU Length", "ldp.hdr.pdu_len", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP PDU Length", HFILL }},

    { &hf_ldp_lsr,
      { "LSR ID", "ldp.hdr.ldpid.lsr", FT_IPv4, BASE_HEX, NULL, 0x0, "LDP Label Space Router ID", HFILL }},

    { &hf_ldp_ls_id,
      { "Label Space ID", "ldp.hdr.ldpid.lsid", FT_UINT16, BASE_DEC, NULL, 0, "LDP Label Space ID", HFILL }},

    { &hf_ldp_msg_ubit,
      { "U bit", "ldp.msg.ubit", FT_BOOLEAN, 8, TFS(&ldp_message_ubit), 0x80, "Unknown Message Bit", HFILL }},

    { &hf_ldp_msg_type,
      { "Message Type", "ldp.msg.type", FT_UINT16, BASE_HEX, VALS(ldp_message_types), 0x7FFF, "LDP message type", HFILL }},

    { &hf_ldp_msg_len,
      { "Message Length", "ldp.msg.len", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP Message Length (excluding message type and len)", HFILL }},

    { &hf_ldp_msg_id, 
      { "Message ID", "ldp.msg.id", FT_UINT32, BASE_HEX, NULL, 0x0, "LDP Message ID", HFILL }},

    { &hf_ldp_msg_vendor_id, 
      { "Vendor ID", "ldp.msg.vendor.id", FT_UINT32, BASE_HEX, NULL, 0x0, "LDP Vendor-private Message ID", HFILL }},

    { &hf_ldp_msg_experiment_id, 
      { "Experiment ID", "ldp.msg.experiment.id", FT_UINT32, BASE_HEX, NULL, 0x0, "LDP Experimental Message ID", HFILL }},

    { &hf_ldp_tlv_unknown, 
      { "TLV Unknown bits", "ldp.msg.tlv.unknown", FT_UINT8, BASE_HEX, VALS(tlv_unknown_vals), 0xC0, "TLV Unknown bits Field", HFILL }},

    { &hf_ldp_tlv_type, 
      { "TLV Type", "ldp.msg.tlv.type", FT_UINT16, BASE_HEX, VALS(tlv_type_names), 0x3FFF, "TLV Type Field", HFILL }},

    { &hf_ldp_tlv_len,
      {"TLV Length", "ldp.msg.tlv.len", FT_UINT16, BASE_DEC, NULL, 0x0, "TLV Length Field", HFILL }},

    { &hf_ldp_tlv_value,
      { "TLV Value", "ldp.msg.tlv.value", FT_BYTES, BASE_NONE, NULL, 0x0, "TLV Value Bytes", HFILL }},

    { &hf_ldp_tlv_val_hold,
      { "Hold Time", "ldp.msg.tlv.hello.hold", FT_UINT16, BASE_DEC, NULL, 0x0, "Hello Common Parameters Hold Time", HFILL }},

    { &hf_ldp_tlv_val_target,
      { "Targeted Hello", "ldp.msg.tlv.hello.targeted", FT_BOOLEAN, 8, TFS(&hello_targeted_vals), 0x80, "Hello Common Parameters Targeted Bit", HFILL }},

    { &hf_ldp_tlv_val_request,
      { "Hello Requested", "ldp,msg.tlv.hello.requested", FT_BOOLEAN, 8, TFS(&hello_requested_vals), 0x40, "Hello Common Parameters Hello Requested Bit", HFILL }},
 
    { &hf_ldp_tlv_val_res,
      { "Reserved", "ldp.msg.tlv.hello.res", FT_UINT16, BASE_HEX, NULL, 0x3FFF, "Hello Common Parameters Reserved Field", HFILL }},

    { &hf_ldp_tlv_ipv4_taddr,
      { "IPv4 Transport Address", "ldp.msg.tlv.ipv4.taddr", FT_IPv4, BASE_DEC, NULL, 0x0, "IPv4 Transport Address", HFILL }},

    { &hf_ldp_tlv_config_seqno,
      { "Configuration Sequence Number", "ldp.msg.tlv.hello.cnf_seqno", FT_UINT32, BASE_DEC, NULL, 0x0, "Hello Configuration Sequence Number", HFILL }},

    { &hf_ldp_tlv_ipv6_taddr,
      { "IPv6 Transport Address", "ldp.msg.tlv.ipv6.taddr", FT_IPv6, BASE_DEC, NULL, 0x0, "IPv6 Transport Address", HFILL }},

    { &hf_ldp_tlv_fec_wc,
      { "FEC Element Type", "ldp.msg.tlv.fec.type", FT_UINT8, BASE_DEC, VALS(fec_types), 0x0, "Forwarding Equivalence Class Element Types", HFILL }},

    { &hf_ldp_tlv_fec_af,
      { "FEC Element Address Type", "ldp.msg.tlv.fec.af", FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Forwarding Equivalence Class Element Address Family", HFILL }},

    { &hf_ldp_tlv_fec_len,
      { "FEC Element Length", "ldp.msg.tlv.fec.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Forwarding Equivalence Class Element Length", HFILL }},

    { &hf_ldp_tlv_fec_pfval,
      { "FEC Element Prefix Value", "ldp.msg.tlv.fec.pfval", FT_STRING, BASE_NONE, NULL, 0x0, "Forwarding Equivalence Class Element Prefix", HFILL }},

    { &hf_ldp_tlv_fec_hoval,
      { "FEC Element Host Address Value", "ldp.msg.tlv.fec.hoval", FT_STRING, BASE_NONE, NULL, 0x0, "Forwarding Equivalence Class Element Address", HFILL }},

    { &hf_ldp_tlv_addrl_addr_family,
      { "Address Family", "ldp.msg.tlv.addrl.addr_family", FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Address Family List", HFILL }},

    { &hf_ldp_tlv_addrl_addr,
      { "Address", "ldp.msg.tlv.addrl.addr", FT_STRING, BASE_NONE, NULL, 0x0, "Address", HFILL }},

    { &hf_ldp_tlv_hc_value,
      { "Hop Count Value", "ldp.msg.tlv.hc.value", FT_UINT8, BASE_DEC, NULL, 0x0, "Hop Count", HFILL }},

    { &hf_ldp_tlv_pv_lsrid,
      { "LSR Id", "ldp.msg.tlv.pv.lsrid", FT_IPv4, BASE_DEC, NULL, 0x0, "Path Vector LSR Id", HFILL }},

    { &hf_ldp_tlv_sess_ver,
      { "Session Protocol Version", "ldp.msg.tlv.sess.ver", FT_UINT16, BASE_DEC, NULL, 0x0, "Common Session Parameters Protocol Version", HFILL }},

    { &hf_ldp_tlv_sess_ka,
      { "Session KeepAlive Time", "ldp.msg.tlv.sess.ka", FT_UINT16, BASE_DEC, NULL, 0x0, "Common Session Parameters KeepAlive Time", HFILL }},

    { &hf_ldp_tlv_sess_advbit,
      { "Session Label Advertisement Discipline", "ldp.msg.tlv.sess.advbit",
 FT_BOOLEAN, 8, TFS(&tlv_sess_advbit_vals), 0x80, 
	"Common Session Parameters Label Advertisement Discipline", HFILL }},

    { &hf_ldp_tlv_sess_ldetbit,
      { "Session Loop Detection", "ldp.msg.tlv.sess.ldetbit", FT_BOOLEAN, 8, TFS(&tlv_sess_ldetbit_vals), 0x40, "Common Session Parameters Loop Detection", HFILL }},

    { &hf_ldp_tlv_sess_pvlim,
      { "Session Path Vector Limit", "ldp.msg.tlv.sess.pvlim", FT_UINT8, BASE_DEC, NULL, 0x0, "Common Session Parameters Path Vector Limit", HFILL }},

    { &hf_ldp_tlv_sess_mxpdu,
      { "Session Max PDU Length", "ldp.msg.tlv.sess.mxpdu", FT_UINT16, BASE_DEC, NULL, 0x0, "Common Session Parameters Max PDU Length", HFILL }},

    { &hf_ldp_tlv_sess_rxlsr,
      { "Session Receiver LSR Identifier", "ldp.msg.tlv.sess.rxlsr", FT_IPv4, BASE_DEC, NULL, 0x0, "Common Session Parameters LSR Identifier", HFILL }},

    { &hf_ldp_tlv_sess_rxls,
      { "Session Receiver Label Space Identifier", "ldp.msg.tlv.sess.rxlsr", FT_UINT16, BASE_DEC, NULL, 0x0, "Common Session Parameters Receiver Label Space Identifier", HFILL }},

    { &hf_ldp_tlv_sess_atm_merge,
      { "Session ATM Merge Parameter", "ldp.msg.tlv.sess.atm.merge", FT_UINT8, BASE_DEC, VALS(tlv_atm_merge_vals), 0xC0, "Merge ATM Session Parameters", HFILL }},

    { &hf_ldp_tlv_sess_atm_lr,
      { "Number of ATM Label Ranges", "ldp.msg.tlv.sess.atm.lr", FT_UINT8, BASE_DEC, NULL, 0x3C, "Number of Label Ranges", HFILL }},

    { &hf_ldp_tlv_sess_atm_dir,
      { "Directionality", "ldp.msg.tlv.sess.atm.dir", FT_BOOLEAN, 8, TFS(&tlv_atm_dirbit), 0x02, "Lablel Directionality", HFILL }},

    { &hf_ldp_tlv_sess_atm_minvpi,
      { "Minimum VPI", "ldp.msg.tlv.sess.atm.minvpi", FT_UINT16, BASE_DEC, NULL, 0x0FFF, "Minimum VPI", HFILL }},

    { &hf_ldp_tlv_sess_atm_minvci,
      { "Minimum VCI", "ldp.msg.tlv.sess.atm.minvci", FT_UINT16, BASE_DEC, NULL, 0x0, "Minimum VCI", HFILL }},

    { &hf_ldp_tlv_sess_atm_maxvpi,
      { "Maximum VPI", "ldp.msg.tlv.sess.atm.maxvpi", FT_UINT16, BASE_DEC, NULL, 0x0FFF, "Maximum VPI", HFILL }},

    { &hf_ldp_tlv_sess_atm_maxvci,
      { "Maximum VCI", "ldp.msg.tlv.sess.atm.maxvci", FT_UINT16, BASE_DEC, NULL, 0x0, "Maximum VCI", HFILL }},

    { &hf_ldp_tlv_sess_fr_merge,
      { "Session Frame Relay Merge Parameter", "ldp.msg.tlv.sess.fr.merge", FT_UINT8, BASE_DEC, VALS(tlv_fr_merge_vals), 0xC0, "Merge Frame Relay Session Parameters", HFILL }},

    { &hf_ldp_tlv_sess_fr_lr,
      { "Number of Frame Relay Label Ranges", "ldp.msg.tlv.sess.fr.lr", FT_UINT8, BASE_DEC, NULL, 0x3C, "Number of Label Ranges", HFILL }},

    { &hf_ldp_tlv_sess_fr_dir,
      { "Directionality", "ldp.msg.tlv.sess.fr.dir", FT_BOOLEAN, 8, TFS(&tlv_atm_dirbit), 0x02, "Lablel Directionality", HFILL }},

    { &hf_ldp_tlv_sess_fr_len,
      { "Number of DLCI bits", "ldp.msg.tlv.sess.fr.len", FT_UINT16, BASE_DEC, VALS(tlv_fr_len_vals), 0x0180, "DLCI Number of bits", HFILL }},

    { &hf_ldp_tlv_sess_fr_mindlci,
      { "Minimum DLCI", "ldp.msg.tlv.sess.fr.mindlci", FT_UINT24, BASE_DEC, NULL, 0x7FFFFF, "Minimum DLCI", HFILL }},

    { &hf_ldp_tlv_sess_fr_maxdlci,
      { "Maximum DLCI", "ldp.msg.tlv.sess.fr.maxdlci", FT_UINT24, BASE_DEC, NULL, 0x7FFFFF, "Maximum DLCI", HFILL }},

    { &hf_ldp_tlv_lbl_req_msg_id, 
      { "Label Request Message ID", "ldp.tlv.lbl_req_msg_id", FT_UINT32, BASE_HEX, NULL, 0x0, "Label Request Message to be aborted", HFILL }},

    { &hf_ldp_tlv_vendor_id,
      { "Vendor ID", "ldp.msg.tlv.vendor_id", FT_UINT32, BASE_HEX, NULL, 0, "IEEE 802 Assigned Vendor ID", HFILL }},

    { &hf_ldp_tlv_experiment_id,
      { "Experiment ID", "ldp.msg.tlv.experiment_id", FT_UINT32, BASE_HEX, NULL, 0, "Experiment ID", HFILL }},

    { &hf_ldp_tlv_generic_label,
      { "Generic Label", "ldp.msg.tlv.generic.label", FT_UINT32, BASE_HEX, NULL, 0x000FFFFF, "Generic Label", HFILL }},

    { &hf_ldp_tlv_atm_label_vbits,
      { "V-bits", "ldp.msg.tlv.atm.label.vbits", FT_UINT8, BASE_HEX, VALS(tlv_atm_vbits_vals), 0x30, "ATM Label V Bits", HFILL }},

    { &hf_ldp_tlv_atm_label_vpi,
      { "VPI", "ldp.msg.tlv.atm.label.vpi", FT_UINT16, BASE_DEC, NULL, 0x0FFF, "ATM Label VPI", HFILL }},

    { &hf_ldp_tlv_atm_label_vci,
      { "VCI", "ldp.msg.tlv.atm.label.vci", FT_UINT16, BASE_DEC, NULL, 0, "ATM Label VCI", HFILL }},

    { &hf_ldp_tlv_fr_label_len,
      { "Number of DLCI bits", "ldp.msg.tlv.fr.label.len", FT_UINT16, BASE_DEC, VALS(tlv_fr_len_vals), 0x0180, "DLCI Number of bits", HFILL }},

    { &hf_ldp_tlv_fr_label_dlci,
      { "DLCI", "ldp.msg.tlv.fr.label.dlci", FT_UINT24, BASE_DEC, NULL, 0x7FFFFF, "FRAME RELAY Label DLCI", HFILL }},

    { &hf_ldp_tlv_status_ebit,
      { "E Bit", "ldp.msg.tlv.status.ebit", FT_BOOLEAN, 8, TFS(&tlv_status_ebit), 0x80, "Fatal Error Bit", HFILL }},

    { &hf_ldp_tlv_status_fbit,
      { "F Bit", "ldp.msg.tlv.status.fbit", FT_BOOLEAN, 8, TFS(&tlv_status_fbit), 0x40, "Forward Bit", HFILL }},

    { &hf_ldp_tlv_status_data,
      { "Status Data", "ldp.msg.tlv.status.data", FT_UINT32, BASE_HEX, VALS(tlv_status_data), 0x3FFFFFFF, "Status Data", HFILL }},

    { &hf_ldp_tlv_status_msg_id, 
      { "Message ID", "ldp.msg.tlv.status.msg.id", FT_UINT32, BASE_HEX, NULL, 0x0, "Identifies peer message to which Status TLV refers", HFILL }},

    { &hf_ldp_tlv_status_msg_type,
      { "Message Type", "ldp.msg.tlv.status.msg.type", FT_UINT16, BASE_HEX, VALS(ldp_message_types), 0x0, "Type of peer message to which Status TLV refers", HFILL }},

    { &hf_ldp_tlv_extstatus_data,
      { "Extended Status Data", "ldp.msg.tlv.extstatus.data", FT_UINT32, BASE_HEX, NULL, 0x0, "Extended Status Data", HFILL }},

    { &hf_ldp_tlv_returned_version,
      { "Returned PDU Version", "ldp.msg.tlv.returned.version", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP Version Number", HFILL }},

    { &hf_ldp_tlv_returned_pdu_len,
      { "Returned PDU Length", "ldp.msg.tlv.returned.pdu_len", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP PDU Length", HFILL }},

    { &hf_ldp_tlv_returned_lsr,
      { "Returned PDU LSR ID", "ldp.msg.tlv.returned.ldpid.lsr", FT_IPv4, BASE_DEC, NULL, 0x0, "LDP Label Space Router ID", HFILL }},

    { &hf_ldp_tlv_returned_ls_id,
      { "Returned PDU Label Space ID", "ldp.msg.tlv.returned.ldpid.lsid", FT_UINT16, BASE_HEX, NULL, 0x0, "LDP Label Space ID", HFILL }},

    { &hf_ldp_tlv_returned_msg_ubit, 
      { "Returned Message Unknown bit", "ldp.msg.tlv.returned.msg.ubit", FT_UINT8, BASE_HEX, TFS(&ldp_message_ubit), 0x80, "Message Unknown bit", HFILL }},

    { &hf_ldp_tlv_returned_msg_type,
      { "Returned Message Type", "ldp.msg.tlv.returned.msg.type", FT_UINT16, BASE_HEX, VALS(ldp_message_types), 0x7FFF, "LDP message type", HFILL }},

    { &hf_ldp_tlv_returned_msg_len,
      { "Returned Message Length", "ldp.msg.tlv.returned.msg.len", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP Message Length (excluding message type and len)", HFILL }},

    { &hf_ldp_tlv_returned_msg_id, 
      { "Returned Message ID", "ldp.msg.tlv.returned.msg.id", FT_UINT32, BASE_HEX, NULL, 0x0, "LDP Message ID", HFILL }}

  };

  static gint *ett[] = {
    &ett_ldp,
    &ett_ldp_header,
    &ett_ldp_ldpid,
    &ett_ldp_message,
    &ett_ldp_tlv,
    &ett_ldp_tlv_val,
    &ett_ldp_fec,
  };
  module_t *ldp_module; 

  proto_ldp = proto_register_protocol("Label Distribution Protocol",
				       "LDP", "ldp");

  proto_register_field_array(proto_ldp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for , particularly our port */

  ldp_module = prefs_register_protocol(proto_ldp, proto_reg_handoff_ldp);

  prefs_register_uint_preference(ldp_module, "tcp.port", "LDP TCP Port",
				 "Set the TCP port for messages (if other"
				 " than the default of 646)",
				 10, &global_ldp_tcp_port);

  prefs_register_uint_preference(ldp_module, "udp.port", "LDP UDP Port",
				 "Set the UDP port for messages (if other"
				 " than the default of 646)",
				 10, &global_ldp_udp_port);

  prefs_register_bool_preference(ldp_module, "desegment_ldp_messages",
    "Desegment all LDP messages spanning multiple TCP segments",
    "Whether the LDP dissector should desegment all messages spanning multiple TCP segments",
    &ldp_desegment);
}

/* The registration hand-off routine */
void
proto_reg_handoff_ldp(void)
{
  static int ldp_prefs_initialized = FALSE;
  static dissector_handle_t ldp_tcp_handle, ldp_handle;

  if (!ldp_prefs_initialized) {

    ldp_tcp_handle = create_dissector_handle(dissect_ldp_tcp, proto_ldp);
    ldp_handle = create_dissector_handle(dissect_ldp, proto_ldp);

    ldp_prefs_initialized = TRUE;

  }
  else {

    dissector_delete("tcp.port", tcp_port, ldp_tcp_handle);
    dissector_delete("udp.port", udp_port, ldp_handle);

  }

  /* Set our port number for future use */

  tcp_port = global_ldp_tcp_port;
  udp_port = global_ldp_udp_port;

  dissector_add("tcp.port", global_ldp_tcp_port, ldp_tcp_handle);
  dissector_add("udp.port", global_ldp_udp_port, ldp_handle);

}
