/* packet-icmp.c
 * Routines for ICMP - Internet Control Message Protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Monday, June 27, 2005
 * Support for the ICMP extensions for MPLS
 * (https://tools.ietf.org/html/draft-ietf-mpls-icmp-02
 *  which has been replaced by rfcs 4884 and 4950)
 * by   Maria-Luiza Crivat <luizacri@gmail.com>
 * &    Brice Augustin <bricecotte@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Added support for ICMP extensions RFC 4884 and RFC 5837
 * (c) 2011 Gaurav Tungatkar <gstungat@ncsu.edu>
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/in_cksum.h>
#include <epan/sequence_analysis.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/ipproto.h>
#include <epan/capture_dissectors.h>
#include <epan/proto_data.h>
#include <epan/afn.h>

#include <wsutil/pint.h>

#include "packet-ip.h"
#include "packet-icmp.h"

void proto_register_icmp(void);
void proto_reg_handoff_icmp(void);

static heur_dissector_list_t icmp_heur_subdissector_list;
static int icmp_tap;

/* Conversation related data */
static int hf_icmp_resp_in;
static int hf_icmp_resp_to;
static int hf_icmp_no_resp;
static int hf_icmp_resptime;
static int hf_icmp_data_time;
static int hf_icmp_data_time_relative;

typedef struct _icmp_conv_info_t {
	wmem_tree_t *unmatched_pdus;
	wmem_tree_t *matched_pdus;
} icmp_conv_info_t;

static icmp_transaction_t *transaction_start(packet_info * pinfo,
					     proto_tree * tree,
					     uint32_t * key);
static icmp_transaction_t *transaction_end(packet_info * pinfo,
					   proto_tree * tree,
					   uint32_t * key);

/* Decode the end of the ICMP payload as ICMP MPLS extensions
if the packet in the payload has more than 128 bytes */
static bool favor_icmp_mpls_ext;

static int proto_icmp;

static int hf_icmp_type;
static int hf_icmp_code;
static int hf_icmp_checksum;
static int hf_icmp_checksum_status;
static int hf_icmp_unused;
static int hf_icmp_reserved;
static int hf_icmp_ident;
static int hf_icmp_ident_le;
static int hf_icmp_seq_num;
static int hf_icmp_seq_num_le;
static int hf_icmp_mtu;
static int hf_icmp_num_addrs;
static int hf_icmp_addr_entry_size;
static int hf_icmp_lifetime;
static int hf_icmp_pointer;
static int hf_icmp_router_address;
static int hf_icmp_pref_level;
static int hf_icmp_redir_gw;
static int hf_icmp_originate_timestamp;
static int hf_icmp_receive_timestamp;
static int hf_icmp_transmit_timestamp;
static int hf_icmp_address_mask;
static int hf_icmp_length;
static int hf_icmp_length_original_datagram;

/* Mobile ip */
static int hf_icmp_mip_type;
static int hf_icmp_mip_length;
static int hf_icmp_mip_prefix_length;
static int hf_icmp_mip_seq;
static int hf_icmp_mip_life;
static int hf_icmp_mip_flags;
static int hf_icmp_mip_r;
static int hf_icmp_mip_b;
static int hf_icmp_mip_h;
static int hf_icmp_mip_f;
static int hf_icmp_mip_m;
static int hf_icmp_mip_g;
static int hf_icmp_mip_v;
static int hf_icmp_mip_rt;
static int hf_icmp_mip_u;
static int hf_icmp_mip_x;
static int hf_icmp_mip_reserved;
static int hf_icmp_mip_coa;
static int hf_icmp_mip_challenge;
static int hf_icmp_mip_content;

/* extensions RFC 4884*/
static int hf_icmp_ext;
static int hf_icmp_ext_version;
static int hf_icmp_ext_reserved;
static int hf_icmp_ext_checksum;
static int hf_icmp_ext_checksum_status;
static int hf_icmp_ext_length;
static int hf_icmp_ext_class;
static int hf_icmp_ext_c_type;
static int hf_icmp_ext_data;

/* Interface information extension RFC 5837 */
static int hf_icmp_int_info_ifindex;
static int hf_icmp_int_info_ipaddr;
static int hf_icmp_int_info_name;
static int hf_icmp_int_info_mtu_present;
static int hf_icmp_int_info_mtu;
static int hf_icmp_int_info_index;
static int hf_icmp_int_info_afi;
static int hf_icmp_int_info_ipv4;
static int hf_icmp_int_info_ipv6;
static int hf_icmp_int_info_ipunknown;
static int hf_icmp_int_info_name_length;
static int hf_icmp_int_info_name_string;
static int hf_icmp_int_info_role;
static int hf_icmp_int_info_reserved;
static int ett_icmp_interface_info_object;
static int ett_icmp_interface_ipaddr;
static int ett_icmp_interface_name;
/* MPLS extension object*/
static int hf_icmp_mpls_label;
static int hf_icmp_mpls_exp;
static int hf_icmp_mpls_s;
static int hf_icmp_mpls_ttl;
static int hf_icmp_mpls_data;

static int ett_icmp;
static int ett_icmp_mip;
static int ett_icmp_mip_flags;

/* extensions */
static int ett_icmp_ext;
static int ett_icmp_ext_object;

/* MPLS extensions */
static int ett_icmp_mpls_stack_object;

static expert_field ei_icmp_type_deprecated;
static expert_field ei_icmp_resp_not_found;
static expert_field ei_icmp_checksum;
static expert_field ei_icmp_ext_checksum;

/* Extended Echo - Probe */
static int hf_icmp_ext_echo_seq_num;
static int hf_icmp_ext_echo_req_reserved;
static int hf_icmp_ext_echo_req_local;
static int hf_icmp_ext_echo_rsp_state;
static int hf_icmp_ext_echo_rsp_reserved;
static int hf_icmp_ext_echo_rsp_active;
static int hf_icmp_ext_echo_rsp_ipv4;
static int hf_icmp_ext_echo_rsp_ipv6;
static int hf_icmp_int_ident_name_string;
static int hf_icmp_int_ident_index;
static int hf_icmp_int_ident_afi;
static int hf_icmp_int_ident_addr_length;
static int hf_icmp_int_ident_reserved;
static int hf_icmp_int_ident_ipv4;
static int hf_icmp_int_ident_ipv6;
static int hf_icmp_int_ident_address;

static dissector_handle_t icmp_handle;


/* ICMP definitions */
#define ICMP_ECHOREPLY     0
#define ICMP_UNREACH       3
#define ICMP_SOURCEQUENCH  4
#define ICMP_REDIRECT      5
#define ICMP_ALTHOST       6
#define ICMP_ECHO          8
#define ICMP_RTRADVERT     9
#define ICMP_RTRSOLICIT   10
#define ICMP_TIMXCEED     11
#define ICMP_PARAMPROB    12
#define ICMP_TSTAMP       13
#define ICMP_TSTAMPREPLY  14
#define ICMP_IREQ         15
#define ICMP_IREQREPLY    16
#define ICMP_MASKREQ      17
#define ICMP_MASKREPLY    18
#define ICMP_PHOTURIS     40
#define ICMP_EXTECHO      42
#define ICMP_EXTECHOREPLY 43

/* ICMP UNREACHABLE */
#define ICMP_NET_UNREACH         0	/* Network Unreachable */
#define ICMP_HOST_UNREACH        1	/* Host Unreachable */
#define ICMP_PROT_UNREACH        2	/* Protocol Unreachable */
#define ICMP_PORT_UNREACH        3	/* Port Unreachable */
#define ICMP_FRAG_NEEDED         4	/* Fragmentation Needed/DF set */
#define ICMP_SR_FAILED           5	/* Source Route failed */
#define ICMP_NET_UNKNOWN         6
#define ICMP_HOST_UNKNOWN        7
#define ICMP_HOST_ISOLATED       8
#define ICMP_NET_ANO             9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13	/* Packet filtered */
#define ICMP_PREC_VIOLATION     14	/* Precedence violation */
#define ICMP_PREC_CUTOFF        15	/* Precedence cut off */

#define ICMP_MIP_EXTENSION_PAD	 0
#define ICMP_MIP_MOB_AGENT_ADV	16
#define ICMP_MIP_PREFIX_LENGTHS	19
#define ICMP_MIP_CHALLENGE	24

static dissector_handle_t ip_handle;

/* RFC 6633 and 6918 formally deprecated a number of types, including
 * those never widely implemented nor deployed (in Wireshark or elsewhere.)
 */
static const value_string icmp_type_str[] = {
	{ICMP_ECHOREPLY,    "Echo (ping) reply"},
	{1,		    "Reserved"},
	{2,		    "Reserved"},
	{ICMP_UNREACH,	    "Destination unreachable"},
	{ICMP_SOURCEQUENCH, "Source quench (flow control)"}, /* Deprecated */
	{ICMP_REDIRECT,	    "Redirect"},
	{ICMP_ALTHOST,	    "Alternate host address"}, /* Deprecated */
	{ICMP_ECHO,	    "Echo (ping) request"},
	{ICMP_RTRADVERT,    "Router advertisement"},
	{ICMP_RTRSOLICIT,   "Router solicitation"},
	{ICMP_TIMXCEED,	    "Time-to-live exceeded"},
	{ICMP_PARAMPROB,    "Parameter problem"},
	{ICMP_TSTAMP,	    "Timestamp request"},
	{ICMP_TSTAMPREPLY,  "Timestamp reply"},
	{ICMP_IREQ,	    "Information request"}, /* Deprecated */
	{ICMP_IREQREPLY,    "Information reply"}, /* Deprecated */
	{ICMP_MASKREQ,	    "Address mask request"}, /* Deprecated */
	{ICMP_MASKREPLY,    "Address mask reply"}, /* Deprecated */
	{19,		    "Reserved (for security)"},
	{30,		    "Traceroute"}, /* Deprecated */
	{31,		    "Datagram Conversion Error"}, /* Deprecated */
	{32,		    "Mobile Host Redirect"}, /* Deprecated */
	{33,		    "IPv6 Where-Are-You"}, /* Deprecated */
	{34,		    "IPv6 I-Am-Here"}, /* Deprecated */
	{35,		    "Mobile Registration Request"}, /* Deprecated */
	{36,		    "Mobile Registration Reply"}, /* Deprecated */
	{37,		    "Domain Name Request"}, /* Deprecated */
	{38,		    "Domain Name Reply"}, /* Deprecated */
	{39,		    "SKIP"}, /* Deprecated */
	{ICMP_PHOTURIS,	    "Photuris"},
	{41,		    "Experimental mobility protocols"},
	{ICMP_EXTECHO,	    "Extended Echo request"},
	{ICMP_EXTECHOREPLY, "Extended Echo reply"},
	{0, NULL}
};

static const value_string unreach_code_str[] = {
	{ICMP_NET_UNREACH,    "Network unreachable"},
	{ICMP_HOST_UNREACH,   "Host unreachable"},
	{ICMP_PROT_UNREACH,   "Protocol unreachable"},
	{ICMP_PORT_UNREACH,   "Port unreachable"},
	{ICMP_FRAG_NEEDED,    "Fragmentation needed"},
	{ICMP_SR_FAILED,      "Source route failed"},
	{ICMP_NET_UNKNOWN,    "Destination network unknown"},
	{ICMP_HOST_UNKNOWN,   "Destination host unknown"},
	{ICMP_HOST_ISOLATED,  "Source host isolated"},
	{ICMP_NET_ANO,	      "Network administratively prohibited"},
	{ICMP_HOST_ANO,	      "Host administratively prohibited"},
	{ICMP_NET_UNR_TOS,    "Network unreachable for TOS"},
	{ICMP_HOST_UNR_TOS,   "Host unreachable for TOS"},
	{ICMP_PKT_FILTERED,   "Communication administratively filtered"},
	{ICMP_PREC_VIOLATION, "Host precedence violation"},
	{ICMP_PREC_CUTOFF,    "Precedence cutoff in effect"},
	{0, NULL}
};

static const value_string redir_code_str[] = {
	{0, "Redirect for network"},
	{1, "Redirect for host"},
	{2, "Redirect for TOS and network"},
	{3, "Redirect for TOS and host"},
	{0, NULL}
};

static const value_string alt_host_code_str[] = {
	{0, "Alternate address for host"},
	{0, NULL}
};

static const value_string rtradvert_code_str[] = {
	{ 0, "Normal router advertisement"},
	{16, "Does not route common traffic"},
	{0, NULL}
};

static const value_string ttl_code_str[] = {
	{0, "Time to live exceeded in transit"},
	{1, "Fragment reassembly time exceeded"},
	{0, NULL}
};

static const value_string par_code_str[] = {
	{0, "Pointer indicates the error"},
	{1, "Required option missing"},
	{2, "Bad length"},
	{0, NULL}
};

static const value_string photuris_code_str[] = {
	{0, "Bad SPI"},
	{1, "Authentication Failed"},
	{2, "Decompression Failed"},
	{3, "Decryption Failed"},
	{4, "Need Authentication"},
	{5, "Need Authorization"},
	{0, NULL}
};

static const value_string ext_echo_req_code_str[] = {
	{0, "No error"},
	{0, NULL}
};

static const value_string ext_echo_reply_code_str[] = {
	{0, "No error"},
	{1, "Malformed Query"},
	{2, "No Such Interface"},
	{3, "No Such Table Entry"},
	{4, "Multiple Interfaces Satisfy Query"},
	{0, NULL}
};

static const value_string ext_echo_reply_state_str[] = {
	{0, "Reserved"},
	{1, "Incomplete"},
	{2, "Reachable"},
	{3, "Stale"},
	{4, "Delay"},
	{5, "Probe"},
	{6, "Failed"},
	{0, NULL}
};

#define ICMP_EXT_ECHO_IDENT_NAME	1
#define ICMP_EXT_ECHO_IDENT_INDEX	2
#define ICMP_EXT_ECHO_IDENT_ADDRESS	3

static const value_string ext_echo_ident_str[] = {
	{ICMP_EXT_ECHO_IDENT_NAME,    "Identifies Interface By Name"},
	{ICMP_EXT_ECHO_IDENT_INDEX,   "Identifies Interface By Index"},
	{ICMP_EXT_ECHO_IDENT_ADDRESS, "Identifies Interface By Address"},
	{0, NULL}
};

static const value_string mip_extensions[] = {
	{ICMP_MIP_EXTENSION_PAD,  "One byte padding extension"}, /* RFC 2002 */
	{ICMP_MIP_MOB_AGENT_ADV,  "Mobility Agent Advertisement Extension"},
	/* RFC 2002 */
	{ICMP_MIP_PREFIX_LENGTHS, "Prefix Lengths Extension"},	 /* RFC 2002 */
	{ICMP_MIP_CHALLENGE,	  "Challenge Extension"},	 /* RFC 3012 */
	{0, NULL}
};

static const value_string icmp_ext_class_str[] = {
	{1, "MPLS Label Stack Class"},
	{2, "Interface Information Object"},
	{3, "Interface Identification Object"},
	{0, NULL}
};

/* RFC 5837 ICMP extension - Interface Information Object
 * Interface Role
 */
static const value_string interface_role_str[] = {
	{0, "IP interface upon which datagram arrived"},
	{1, "Sub-IP component of an IP interface upon which datagram arrived"},
	{2, "IP interface through which datagram would be forwarded"},
	{3, "IP next-hop to which datagram would be forwarded"},
	{0, NULL}
};

#define INT_INFO_INTERFACE_ROLE                 0xc0
#define INT_INFO_RESERVED                       0x30
#define INT_INFO_IFINDEX                        0x08
#define INT_INFO_IPADDR                         0x04
#define INT_INFO_NAME                           0x02
#define INT_INFO_MTU                            0x01

#define INTERFACE_INFORMATION_OBJECT_CLASS       2

#define INTERFACE_IDENTIFICATION_OBJECT_CLASS    3

#define MPLS_STACK_ENTRY_OBJECT_CLASS            1
#define MPLS_EXTENDED_PAYLOAD_OBJECT_CLASS       0

#define MPLS_STACK_ENTRY_C_TYPE                  1
#define MPLS_EXTENDED_PAYLOAD_C_TYPE             1

/* Return true if the address is in the 224.0.0.0/4 network block */
#define is_a_multicast_addr(a)	in4_addr_is_multicast(a)

/* Return true if the address is the 255.255.255.255 broadcast address */
#define is_a_broadcast_addr(a)	((a) == 0xffffffffU)

/*
 * We check the address type in case some bogus IPv6 packet specifies ICMP
 * rather than ICMP6 in the next header field.
 */
#define ADDR_IS_MULTICAST(addr) \
	(((addr)->type == AT_IPv4) && is_a_multicast_addr(pntoh32((addr)->data)))

#define ADDR_IS_BROADCAST(addr) \
	(((addr)->type == AT_IPv4) && is_a_broadcast_addr(pntoh32((addr)->data)))

#define ADDR_IS_NOT_UNICAST(addr) \
	(ADDR_IS_MULTICAST(addr) || ADDR_IS_BROADCAST(addr))


/* whenever a ICMP packet is seen by the tap listener */
/* Add a new frame into the graph */
static tap_packet_status
icmp_seq_analysis_packet( void *ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *dummy _U_, tap_flags_t flags _U_)
{
	seq_analysis_info_t *sainfo = (seq_analysis_info_t *) ptr;
	seq_analysis_item_t *sai = sequence_analysis_create_sai_with_addresses(pinfo, sainfo);

	if (!sai)
		return TAP_PACKET_DONT_REDRAW;

	sai->frame_number = pinfo->num;

	sequence_analysis_use_color_filter(pinfo, sai);

	sai->port_src=pinfo->srcport;
	sai->port_dst=pinfo->destport;

	sequence_analysis_use_col_info_as_label_comment(pinfo, sai);

	if (pinfo->ptype == PT_NONE) {
		icmp_info_t *p_icmp_info = (icmp_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_icmp, 0);

		if (p_icmp_info != NULL) {
			sai->port_src = 0;
			sai->port_dst = p_icmp_info->type * 256 + p_icmp_info->code;
		}
	}

	sai->line_style = 1;
	sai->conv_num = 0;
	sai->display = true;

	g_queue_push_tail(sainfo->items, sai);

	return TAP_PACKET_REDRAW;
}

static conversation_t *_find_or_create_conversation(packet_info * pinfo)
{
	conversation_t *conv = NULL;

	/* Have we seen this conversation before? */
	conv =
	    find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
			      0, 0, 0);
	if (conv == NULL) {
		/* No, this is a new conversation. */
		conv =
		    conversation_new(pinfo->num, &pinfo->src,
				     &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype), 0, 0, 0);
	}
	return conv;
}

/*
 * Dissect the mobile ip advertisement extensions.
 */
static void
dissect_mip_extensions(tvbuff_t * tvb, int offset, proto_tree * tree)
{
	uint8_t type;
	uint8_t length;
	proto_item *ti;
	proto_tree *mip_tree = NULL;
	int numCOAs;
	int i;
	static int * const flags[] = {
		&hf_icmp_mip_r,
		&hf_icmp_mip_b,
		&hf_icmp_mip_h,
		&hf_icmp_mip_f,
		&hf_icmp_mip_m,
		&hf_icmp_mip_g,
		&hf_icmp_mip_v,
		&hf_icmp_mip_rt,
		&hf_icmp_mip_u,
		&hf_icmp_mip_x,
		&hf_icmp_mip_reserved,
		NULL
	};

	/* Not much to do if we're not parsing everything */
	if (!tree)
		return;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		type = tvb_get_uint8(tvb, offset + 0);
		if (type) {
			length = tvb_get_uint8(tvb, offset + 1);
		} else {
			length = 0;
		}

		mip_tree = proto_tree_add_subtree_format(tree, tvb, offset,
								1, ett_icmp_mip, &ti,
								"Ext: %s", val_to_str(type,
								mip_extensions,
								"Unknown ext %u"));
		proto_tree_add_item(mip_tree, hf_icmp_mip_type,
					tvb, offset, 1,
					ENC_BIG_ENDIAN);
		offset++;
		if (type != ICMP_MIP_EXTENSION_PAD)
		{
			proto_item_set_len(ti, length + 2);

			/* length */
			proto_tree_add_item(mip_tree, hf_icmp_mip_length,
						tvb, offset, 1,
						ENC_BIG_ENDIAN);
			offset++;
		}

		switch (type) {
		case ICMP_MIP_EXTENSION_PAD:
			/* One byte padding extension */
			break;
		case ICMP_MIP_MOB_AGENT_ADV:
			/* Mobility Agent Advertisement Extension (RFC 2002) */
			/* Add our fields */
			/* sequence number */
			proto_tree_add_item(mip_tree, hf_icmp_mip_seq, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			/* Registration Lifetime */
			proto_tree_add_item(mip_tree, hf_icmp_mip_life,
					    tvb, offset, 2,
					    ENC_BIG_ENDIAN);
			offset += 2;
			/* flags */
			proto_tree_add_bitmask(mip_tree, tvb, offset, hf_icmp_mip_flags, ett_icmp_mip_flags, flags, ENC_BIG_ENDIAN);
			offset += 2;

			/* COAs */
			numCOAs = (length - 6) / 4;
			for (i = 0; i < numCOAs; i++) {
				proto_tree_add_item(mip_tree,
						    hf_icmp_mip_coa, tvb,
						    offset, 4,
						    ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;
		case ICMP_MIP_PREFIX_LENGTHS:
			/* Prefix-Lengths Extension  (RFC 2002) */
			/* Add our fields */

			/* prefix lengths */
			for (i = 0; i < length; i++) {
				proto_tree_add_item(mip_tree,
						    hf_icmp_mip_prefix_length,
						    tvb, offset, 1,
						    ENC_BIG_ENDIAN);
				offset++;
			}
			break;
		case ICMP_MIP_CHALLENGE:
			/* Challenge Extension  (RFC 3012) */
			/* challenge */
			proto_tree_add_item(mip_tree,
					    hf_icmp_mip_challenge, tvb,
					    offset, length, ENC_NA);
			offset += length;

			break;
		default:
			/* data, if any */
			if (length != 0) {
				proto_tree_add_item(mip_tree, hf_icmp_mip_content, tvb, offset, length - 4, ENC_NA);
				offset += length;
			}

			break;
		}
	}

}				/* dissect_mip_extensions */

static bool
dissect_mpls_extended_payload_object(tvbuff_t * tvb, int offset,
				     proto_tree * ext_object_tree,
				     proto_item * tf_object)
{

	uint16_t obj_length, obj_trunc_length;
	bool unknown_object;
	uint8_t c_type;
	unknown_object = false;
	/* Object length */
	obj_length = tvb_get_ntohs(tvb, offset);

	obj_trunc_length =
	    MIN(obj_length, tvb_reported_length_remaining(tvb, offset));

	/* C-Type */
	c_type = tvb_get_uint8(tvb, offset + 3);
	proto_tree_add_uint(ext_object_tree, hf_icmp_ext_c_type, tvb,
			    offset + 3, 1, c_type);

	/* skip the object header */
	offset += 4;

	switch (c_type) {
	case MPLS_EXTENDED_PAYLOAD_C_TYPE:
		proto_item_set_text(tf_object, "Extended Payload");

		/* This object contains some portion of the original packet
		   that could not fit in the 128 bytes of the ICMP payload */
		if (obj_trunc_length > 4) {
			proto_tree_add_item(ext_object_tree, hf_icmp_ext_data, tvb, offset, obj_trunc_length - 4, ENC_NA);
		}
		break;
	default:
		unknown_object = true;
	}			/* end switch c_type */
	return unknown_object;
}

static bool
dissect_mpls_stack_entry_object(tvbuff_t * tvb, int offset,
				proto_tree * ext_object_tree,
				proto_item * tf_object)
{

	proto_item *tf_entry;
	proto_tree *mpls_stack_object_tree;
	uint16_t obj_length, obj_trunc_length;
	int obj_end_offset;
	unsigned label;
	uint8_t ttl;
	uint8_t tmp;
	bool unknown_object;
	uint8_t c_type;
	unknown_object = false;
	/* Object length */
	obj_length = tvb_get_ntohs(tvb, offset);

	obj_trunc_length =
	    MIN(obj_length, tvb_reported_length_remaining(tvb, offset));
	obj_end_offset = offset + obj_trunc_length;
	/* C-Type */
	c_type = tvb_get_uint8(tvb, offset + 3);
	proto_tree_add_uint(ext_object_tree, hf_icmp_ext_c_type, tvb,
			    offset + 3, 1, c_type);

	/* skip the object header */
	offset += 4;

	switch (c_type) {
	case MPLS_STACK_ENTRY_C_TYPE:
		proto_item_set_text(tf_object, "MPLS Stack Entry");
		/* For each entry */
		while (offset + 4 <= obj_end_offset) {
			if (tvb_reported_length_remaining(tvb, offset) < 4) {
				/* Not enough room in the packet ! */
				break;
			}
			/* Create a subtree for each entry (the text will be set later) */
			mpls_stack_object_tree = proto_tree_add_subtree(ext_object_tree,
								tvb, offset, 4,
								ett_icmp_mpls_stack_object, &tf_entry, " ");

			/* Label */
			label = (unsigned) tvb_get_ntohs(tvb, offset);
			tmp = tvb_get_uint8(tvb, offset + 2);
			label = (label << 4) + (tmp >> 4);

			proto_tree_add_uint(mpls_stack_object_tree,
					    hf_icmp_mpls_label, tvb,
					    offset, 3, label << 4);

			proto_item_set_text(tf_entry, "Label: %u", label);

			/* Experimental field (also called "CoS") */
			proto_tree_add_uint(mpls_stack_object_tree,
					    hf_icmp_mpls_exp, tvb,
					    offset + 2, 1, tmp);

			proto_item_append_text(tf_entry, ", Exp: %u",
					       (tmp >> 1) & 0x07);

			/* Stack bit */
			proto_tree_add_boolean(mpls_stack_object_tree,
					       hf_icmp_mpls_s, tvb,
					       offset + 2, 1, tmp);

			proto_item_append_text(tf_entry, ", S: %u",
					       tmp & 0x01);

			/* TTL */
			ttl = tvb_get_uint8(tvb, offset + 3);

			proto_tree_add_item(mpls_stack_object_tree,
					    hf_icmp_mpls_ttl, tvb,
					    offset + 3, 1, ENC_BIG_ENDIAN);

			proto_item_append_text(tf_entry, ", TTL: %u", ttl);

			/* Skip the entry */
			offset += 4;
		}

		if (offset < obj_end_offset) {
			proto_tree_add_item(ext_object_tree, hf_icmp_mpls_data, tvb, offset, obj_end_offset - offset, ENC_NA);
		}
		break;

	default:

		unknown_object = true;

		break;
	}			/* end switch c_type */
	return unknown_object;

}				/* end dissect_mpls_stack_entry_object */

/* Dissect Interface Information Object RFC 5837*/
static bool
dissect_interface_information_object(tvbuff_t * tvb, int offset,
				     proto_tree * ext_object_tree,
				     proto_item * tf_object)
{
	proto_tree *int_name_object_tree = NULL;
	proto_tree *int_ipaddr_object_tree;
	uint16_t obj_length, obj_trunc_length;
	int obj_end_offset;
	uint8_t c_type;
	bool unknown_object;
	uint8_t if_index_flag;
	uint8_t ipaddr_flag;
	uint8_t name_flag;
	uint8_t mtu_flag;
	uint16_t afi;
	uint8_t int_name_length = 0;

	unknown_object = false;
	/* Object length */
	obj_length = tvb_get_ntohs(tvb, offset);

	obj_trunc_length =
	    MIN(obj_length, tvb_reported_length_remaining(tvb, offset));
	obj_end_offset = offset + obj_trunc_length;

	/* C-Type */
	c_type = tvb_get_uint8(tvb, offset + 3);

	proto_item_set_text(tf_object, "Interface Information Object");
	if (tvb_reported_length_remaining(tvb, offset) < 4) {
		/* Not enough room in the packet ! return unknown_object = true */
		return true;
	}

	if_index_flag = (c_type & INT_INFO_IFINDEX) >> 3;
	ipaddr_flag = (c_type & INT_INFO_IPADDR) >> 2;
	name_flag = (c_type & INT_INFO_NAME) >> 1;
	mtu_flag = (c_type & INT_INFO_MTU) >> 0;

	{
		static int * const c_type_fields[] = {
			&hf_icmp_int_info_role,
			&hf_icmp_int_info_reserved,
			&hf_icmp_int_info_ifindex,
			&hf_icmp_int_info_ipaddr,
			&hf_icmp_int_info_name,
			&hf_icmp_int_info_mtu_present,
			NULL
		};
		proto_tree_add_bitmask(ext_object_tree, tvb, offset + 3,
				       hf_icmp_ext_c_type,
				       ett_icmp_interface_info_object,
				       c_type_fields, ENC_BIG_ENDIAN);
	}

	/* skip header */
	offset += 4;

	/*if ifIndex is set, next 32 bits are ifIndex */
	if (if_index_flag) {
		proto_tree_add_item(ext_object_tree, hf_icmp_int_info_index, tvb, offset, 4, ENC_NA);
		offset += 4;
	}

	/* IP Address Sub Object */
	if (ipaddr_flag && (obj_end_offset >= offset + 2)) {
		/* Address Family Identifier */
		afi = tvb_get_ntohs(tvb, offset);

		/*
		 * if afi = 1, IPv4 address, 2 bytes afi, 2 bytes rsvd, 4 bytes IP addr
		 * if afi = 2, IPv6 address, 2 bytes afi, 2 bytes rsvd, 16 bytes IP addr
		 */
		int_ipaddr_object_tree = proto_tree_add_subtree(ext_object_tree, tvb, offset,
					 afi == 1 ? 8 : 20, ett_icmp_interface_ipaddr, NULL,
					 "IP Address Sub-Object");

		proto_tree_add_uint(int_ipaddr_object_tree,
				    hf_icmp_int_info_afi, tvb, offset, 2,
				    afi);
		offset += 2;

		proto_tree_add_item(int_ipaddr_object_tree, hf_icmp_reserved, tvb, offset, 2, ENC_NA);
		offset += 2;

		switch(afi){
			case 1: /* IPv4 */
			proto_tree_add_item(int_ipaddr_object_tree, hf_icmp_int_info_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
			case 2: /* IPv6 */
			proto_tree_add_item(int_ipaddr_object_tree, hf_icmp_int_info_ipv6, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;
			default: /* Unknown ?! */
			proto_tree_add_item(int_ipaddr_object_tree, hf_icmp_int_info_ipunknown, tvb, offset, offset - obj_end_offset, ENC_NA);
			return false;
		}

	}

	/* Interface Name Sub Object */
	if (name_flag) {
		if (obj_end_offset >= offset + 1) {
			int_name_length = tvb_get_uint8(tvb, offset);
			int_name_object_tree = proto_tree_add_subtree(ext_object_tree, tvb,
						 offset, int_name_length, ett_icmp_interface_name, NULL,
						 "Interface Name Sub-Object");

			proto_tree_add_item(int_name_object_tree, hf_icmp_int_info_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
		if (obj_end_offset >= offset + int_name_length) {
			proto_tree_add_item(int_name_object_tree, hf_icmp_int_info_name_string, tvb, offset, int_name_length - 1, ENC_ASCII);
			offset += int_name_length - 1;
		}
	}
	/* MTU Sub Object */
	if (mtu_flag) {
		proto_tree_add_item(ext_object_tree, hf_icmp_int_info_mtu, tvb, offset, 4, ENC_NA);
	}


	return unknown_object;

}				/*end dissect_interface_information_object */

/* Dissect Interface Identification Object RFC 8335*/
static bool
dissect_interface_identification_object(tvbuff_t * tvb, int offset,
				     proto_tree * ext_object_tree,
				     proto_item * tf_object)
{
	proto_item *ti;
	uint16_t obj_length;
	uint8_t c_type;
	bool unknown_object;
	uint32_t afi;
	uint32_t addr_length;

	unknown_object = false;
	/* Object length */
	obj_length = tvb_get_ntohs(tvb, offset);

	/* C-Type */
	c_type = tvb_get_uint8(tvb, offset + 3);

	proto_item_set_text(tf_object, "Interface Identification Object");
	if (tvb_reported_length_remaining(tvb, offset) < 5) {
		/* Not enough room in the packet ! return unknown_object = true */
		return true;
	}

	ti = proto_tree_add_uint(ext_object_tree, hf_icmp_ext_c_type, tvb, offset + 3, 1, c_type);
	proto_item_append_text(ti, " (%s)", val_to_str(c_type, ext_echo_ident_str, "Unknown C-Type %u"));
	offset += 4;

	switch(c_type) {
		case ICMP_EXT_ECHO_IDENT_NAME:
			proto_tree_add_item(ext_object_tree, hf_icmp_int_ident_name_string, tvb, offset, obj_length - 4, ENC_ASCII);
			break;
		case ICMP_EXT_ECHO_IDENT_INDEX:
			proto_tree_add_item(ext_object_tree, hf_icmp_int_ident_index, tvb, offset, 4, ENC_NA);
			break;
		case ICMP_EXT_ECHO_IDENT_ADDRESS:
			proto_tree_add_item_ret_uint(ext_object_tree, hf_icmp_int_ident_afi, tvb, offset, 2, ENC_BIG_ENDIAN, &afi);
			offset += 2;
			proto_tree_add_item_ret_uint(ext_object_tree, hf_icmp_int_ident_addr_length, tvb, offset, 1, ENC_BIG_ENDIAN, &addr_length);
			offset += 1;
			proto_tree_add_item(ext_object_tree, hf_icmp_int_ident_reserved, tvb, offset, 1, ENC_NA);
			offset += 1;
			switch(afi){
				case AFNUM_INET: /* IPv4 */
					while(addr_length >= 4 && tvb_reported_length_remaining(tvb, offset) >= 4) {
						proto_tree_add_item(ext_object_tree, hf_icmp_int_ident_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
						addr_length -= 4;
					}
					break;
				case AFNUM_INET6: /* IPv6 */
					while(addr_length >= 16 && tvb_reported_length_remaining(tvb, offset) >= 16) {
						proto_tree_add_item(ext_object_tree, hf_icmp_int_ident_ipv6, tvb, offset, 16, ENC_NA);
						offset += 16;
						addr_length -= 16;
					}
					break;
				default: /* Unknown ?! */
					proto_tree_add_item(ext_object_tree, hf_icmp_int_ident_address, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
			}
	}

	return unknown_object;

}				/*end dissect_interface_identification_object */

static int
dissect_icmp_extension(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
	int offset = 0;
	uint8_t version;
	uint8_t class_num;
	uint8_t c_type;
	uint16_t obj_length, obj_trunc_length, checksum;
	proto_item *ti, *tf_object;
	proto_tree *ext_tree, *ext_object_tree;
	int obj_end_offset;
	unsigned reported_length;
	bool unknown_object;
	uint8_t int_info_obj_count;

	int_info_obj_count = 0;

	reported_length = tvb_reported_length_remaining(tvb, offset);

	/* Add a tree for multi-part extensions RFC 4884 */
	ti = proto_tree_add_none_format(tree, hf_icmp_ext, tvb,
					offset, reported_length,
					"ICMP Multi-Part Extensions");

	if (reported_length < 4 /* Common header */ ) {
		return offset;
	}

	ext_tree = proto_item_add_subtree(ti, ett_icmp_ext);

	/* Version */
	version = hi_nibble(tvb_get_uint8(tvb, offset));
	proto_tree_add_uint(ext_tree, hf_icmp_ext_version, tvb, offset, 1,
			    version);

	/* Reserved */
	proto_tree_add_item(ext_tree, hf_icmp_ext_reserved,
				   tvb, offset, 2, ENC_BIG_ENDIAN);

	/* Checksum */
	checksum = tvb_get_ntohs(tvb, offset + 2);
	if (checksum == 0) {
		proto_tree_add_checksum(ext_tree, tvb, offset + 2, hf_icmp_ext_checksum, hf_icmp_ext_checksum_status, &ei_icmp_ext_checksum,
							pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);

	} else {
		proto_tree_add_checksum(ext_tree, tvb, offset + 2, hf_icmp_ext_checksum, hf_icmp_ext_checksum_status, &ei_icmp_ext_checksum,
							pinfo, ip_checksum_tvb(tvb, offset, reported_length), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
	}

	if (version != 1 && version != 2) {
		/* Unsupported version */
		proto_item_append_text(ti, " (unsupported version)");
		return offset;
	}

	/* Skip the common header */
	offset += 4;

	/* While there is enough room to read an object */
	while (tvb_reported_length_remaining(tvb, offset) >=
	       4 /* Object header */ ) {
		/* Object length */
		obj_length = tvb_get_ntohs(tvb, offset);

		obj_trunc_length =
		    MIN(obj_length,
			tvb_reported_length_remaining(tvb, offset));

		obj_end_offset = offset + obj_trunc_length;

		/* Add a subtree for this object (the text will be reset later) */
		ext_object_tree = proto_tree_add_subtree(ext_tree, tvb, offset,
						MAX(obj_trunc_length, 4),
						ett_icmp_ext_object, &tf_object, "Unknown object");

		proto_tree_add_uint(ext_object_tree, hf_icmp_ext_length,
				    tvb, offset, 2, obj_length);

		/* Class */
		class_num = tvb_get_uint8(tvb, offset + 2);
		proto_tree_add_item(ext_object_tree, hf_icmp_ext_class,
				    tvb, offset + 2, 1, ENC_BIG_ENDIAN);

		/* C-Type */
		c_type = tvb_get_uint8(tvb, offset + 3);

		if (obj_length < 4 /* Object header */ ) {
			/* Thanks doc/README.developer :)) */
			proto_item_set_text(tf_object,
					    "Object with bad length");
			break;
		}


		switch (class_num) {
		case MPLS_STACK_ENTRY_OBJECT_CLASS:
			unknown_object =
			    dissect_mpls_stack_entry_object(tvb, offset,
							    ext_object_tree,
							    tf_object);
			break;
		case INTERFACE_INFORMATION_OBJECT_CLASS:
			unknown_object =
			    dissect_interface_information_object(tvb,
								 offset,
								 ext_object_tree,
								 tf_object);
			int_info_obj_count++;
			if (int_info_obj_count > 4) {
				proto_item_set_text(tf_object,
						    "More than 4 Interface Information Objects");
			}
			break;
		case MPLS_EXTENDED_PAYLOAD_OBJECT_CLASS:
			unknown_object =
			    dissect_mpls_extended_payload_object(tvb,
								 offset,
								 ext_object_tree,
								 tf_object);
			break;
		case INTERFACE_IDENTIFICATION_OBJECT_CLASS:
			unknown_object =
			    dissect_interface_identification_object(tvb,
								 offset,
								 ext_object_tree,
								 tf_object);
			break;
		default:

			unknown_object = true;

			break;
		}		/* end switch class_num */

		/* The switches couldn't decode the object */
		if (unknown_object == true) {
			proto_tree_add_item(ext_object_tree, hf_icmp_ext_c_type, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

			/* Skip the object header */
			offset += 4;

			proto_item_set_text(tf_object,
					    "Unknown object (%d/%d)",
					    class_num, c_type);

			if (obj_trunc_length > 4) {
				proto_tree_add_item(ext_object_tree, hf_icmp_ext_data, tvb, offset, obj_trunc_length - 4, ENC_NA);
			}
		}

		/* */
		if (obj_trunc_length < obj_length) {
			proto_item_append_text(tf_object, " (truncated)");
		}

		/* Go to the end of the object */
		offset = obj_end_offset;

	}
	return offset;
}

/* ======================================================================= */
/*
	Note: We are tracking conversations via these keys:

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             |G|            Checksum           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Identifier          |        Sequence Number        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            VLAN ID                            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static icmp_transaction_t *transaction_start(packet_info * pinfo,
					     proto_tree * tree,
					     uint32_t * key)
{
	conversation_t *conversation;
	icmp_conv_info_t *icmp_info;
	icmp_transaction_t *icmp_trans;
	wmem_tree_key_t icmp_key[3];
	proto_item *it;

	/* Handle the conversation tracking */
	conversation = _find_or_create_conversation(pinfo);
	icmp_info = (icmp_conv_info_t *)conversation_get_proto_data(conversation, proto_icmp);
	if (icmp_info == NULL) {
		icmp_info = wmem_new(wmem_file_scope(), icmp_conv_info_t);
		icmp_info->unmatched_pdus = wmem_tree_new(wmem_file_scope());
		icmp_info->matched_pdus   = wmem_tree_new(wmem_file_scope());
		conversation_add_proto_data(conversation, proto_icmp,
					    icmp_info);
	}

	if (!PINFO_FD_VISITED(pinfo)) {
		/* this is a new request, create a new transaction structure and map it to the
		   unmatched table
		 */
		icmp_key[0].length = 3;
		icmp_key[0].key = key;
		icmp_key[1].length = 0;
		icmp_key[1].key = NULL;

		icmp_trans = wmem_new(wmem_file_scope(), icmp_transaction_t);
		icmp_trans->rqst_frame = pinfo->num;
		icmp_trans->resp_frame = 0;
		icmp_trans->rqst_time = pinfo->abs_ts;
		nstime_set_zero(&icmp_trans->resp_time);
		wmem_tree_insert32_array(icmp_info->unmatched_pdus, icmp_key,
				       (void *) icmp_trans);
	} else {
		/* Already visited this frame */
		uint32_t frame_num = pinfo->num;

		icmp_key[0].length = 3;
		icmp_key[0].key = key;
		icmp_key[1].length = 1;
		icmp_key[1].key = &frame_num;
		icmp_key[2].length = 0;
		icmp_key[2].key = NULL;

		icmp_trans =
		    (icmp_transaction_t *)wmem_tree_lookup32_array(icmp_info->matched_pdus,
					   icmp_key);
	}
	if (icmp_trans == NULL) {
		if (ADDR_IS_NOT_UNICAST(&pinfo->dst)) {
			/* Note the non-unicast destination and skip transaction tracking */
			col_append_str(pinfo->cinfo, COL_INFO, ADDR_IS_BROADCAST(&pinfo->dst) ? " (broadcast)" : " (multicast)");
		} else if (PINFO_FD_VISITED(pinfo)) {
			/* No response found - add field and expert info */
			it = proto_tree_add_item(tree, hf_icmp_no_resp, NULL, 0, 0,
						 ENC_NA);
			proto_item_set_generated(it);

			col_append_fstr(pinfo->cinfo, COL_INFO, " (no response found!)");

			/* Expert info.  TODO: add to _icmp_transaction_t type and sequence number
			   so can report here (and in taps) */
			expert_add_info_format(pinfo, it, &ei_icmp_resp_not_found,
					       "No response seen to ICMP request");
		}

		return NULL;
	}

	/* Print state tracking in the tree */
	if (icmp_trans->resp_frame) {
		it = proto_tree_add_uint(tree, hf_icmp_resp_in, NULL, 0, 0,
					 icmp_trans->resp_frame);
		proto_item_set_generated(it);

		col_append_frame_number(pinfo, COL_INFO, " (reply in %u)",
				icmp_trans->resp_frame);
	}

	return icmp_trans;

}				/* transaction_start() */

/* ======================================================================= */
static icmp_transaction_t *transaction_end(packet_info * pinfo,
					   proto_tree * tree,
					   uint32_t * key)
{
	conversation_t *conversation;
	icmp_conv_info_t *icmp_info;
	icmp_transaction_t *icmp_trans;
	wmem_tree_key_t icmp_key[3];
	proto_item *it;
	nstime_t ns;
	double resp_time;

	conversation =
	    find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
			      conversation_pt_to_conversation_type(pinfo->ptype), 0, 0, 0);
	if (conversation == NULL) {
		return NULL;
	}

	icmp_info = (icmp_conv_info_t *)conversation_get_proto_data(conversation, proto_icmp);
	if (icmp_info == NULL) {
		return NULL;
	}

	if (!PINFO_FD_VISITED(pinfo)) {
		uint32_t frame_num;

		icmp_key[0].length = 3;
		icmp_key[0].key = key;
		icmp_key[1].length = 0;
		icmp_key[1].key = NULL;
		icmp_trans =
		    (icmp_transaction_t *)wmem_tree_lookup32_array(icmp_info->unmatched_pdus,
					   icmp_key);
		if (icmp_trans == NULL) {
			return NULL;
		}

		/* we have already seen this response, or an identical one */
		if (icmp_trans->resp_frame != 0) {
			return NULL;
		}

		icmp_trans->resp_frame = pinfo->num;

		/* we found a match. Add entries to the matched table for both request and reply frames
		 */
		icmp_key[0].length = 3;
		icmp_key[0].key = key;
		icmp_key[1].length = 1;
		icmp_key[1].key = &frame_num;
		icmp_key[2].length = 0;
		icmp_key[2].key = NULL;

		frame_num = icmp_trans->rqst_frame;
		wmem_tree_insert32_array(icmp_info->matched_pdus, icmp_key,
				       (void *) icmp_trans);

		frame_num = icmp_trans->resp_frame;
		wmem_tree_insert32_array(icmp_info->matched_pdus, icmp_key,
				       (void *) icmp_trans);
	} else {
		/* Already visited this frame */
		uint32_t frame_num = pinfo->num;

		icmp_key[0].length = 3;
		icmp_key[0].key = key;
		icmp_key[1].length = 1;
		icmp_key[1].key = &frame_num;
		icmp_key[2].length = 0;
		icmp_key[2].key = NULL;

		icmp_trans =
		    (icmp_transaction_t *)wmem_tree_lookup32_array(icmp_info->matched_pdus,
					   icmp_key);

		if (icmp_trans == NULL) {
			return NULL;
		}
	}


	it = proto_tree_add_uint(tree, hf_icmp_resp_to, NULL, 0, 0,
				 icmp_trans->rqst_frame);
	proto_item_set_generated(it);

	nstime_delta(&ns, &pinfo->abs_ts, &icmp_trans->rqst_time);
	icmp_trans->resp_time = ns;
	resp_time = nstime_to_msec(&ns);
	it = proto_tree_add_double_format_value(tree, hf_icmp_resptime,
						NULL, 0, 0, resp_time,
						"%.3f ms", resp_time);
	proto_item_set_generated(it);

	col_append_frame_number(pinfo, COL_INFO, " (request in %d)",
			icmp_trans->rqst_frame);

	return icmp_trans;

}				/* transaction_end() */

static bool
update_best_guess_timestamp(time_t secs, int64_t usecs, const nstime_t *comp_ts, nstime_t *out_ts, nstime_t *best_diff)
{
	nstime_t ts, delta;
	if (usecs < 1000000 && usecs >= 0) {
		/* suseconds_t allows -1 but we'll reject it */
		ts.secs = secs;
		ts.nsecs = (int)(1000 * usecs);
		(nstime_cmp(comp_ts, &ts) > 0) ? nstime_delta(&delta, comp_ts, &ts) : nstime_delta(&delta, &ts, comp_ts);
		if (nstime_cmp(&delta, best_diff) < 0) {
			nstime_copy(best_diff, &delta);
			nstime_copy(out_ts, &ts);
			return true;
		}
	}
	return false;
}

int
get_best_guess_timestamp(tvbuff_t *tvb, int offset, nstime_t *comp_ts, nstime_t *out_ts)
{
	/* Mike Muuss's original ping program put a timeval in the first
	 * 8 bytes. Many (most?) implementations follow this, but as it's
	 * not in the RFCs, it's usually just sent in native byte order.
	 * Modern systems have 64 bit time_t, so we'll check that too.
	 * The heuristic is to assume the value that has the smallest
	 * absolute difference with the given time (the frame timestamp),
	 * so long as it's less than a maximum value.
	 *
	 * XXX: There are other possibilities. A system could use a 32 bit
	 * suseconds_t even with a 64 bit time_t (as our nstime_t does with
	 * nsecs on platforms with a 32 bit int, and as NetBSD and OpenBSD
	 * apparently do) and other implementations of ping could do whatever
	 * they want (e.g., send a timespec with with nanosecond fractional
	 * time.)
	 */

	if (!tvb_bytes_exist(tvb, offset, 8)) {
		return 0;
	}

	/* Maximum delta we'll accept. We've been using one day for well over
	 * a decade; it could be tighter, but I suppose this helps for captures
	 * made on machines that didn't have their timezones set correctly?
	 */
	nstime_t best_delta = NSTIME_INIT_SECS(3600 * 24);
	int64_t secs, usecs;
	int len = 0;

	if (tvb_bytes_exist(tvb, offset, 16)) {
		/* LE timeval, 64 bit time_t */
		secs = (time_t)tvb_get_letoh64(tvb, offset);
		usecs = tvb_get_letoh64(tvb, offset + 8);
		if (update_best_guess_timestamp(secs, usecs, comp_ts, out_ts, &best_delta)) {
			len = 16;
		}
	}

	/* LE timeval, 32 bit time_t */
	secs = tvb_get_letohl(tvb, offset);
	usecs = tvb_get_letohl(tvb, offset + 4);
	/* Pre-Y2038, a timeval with 64 bit time_t looks like a LE timeval with
	 * 32 bit time_t and 0 fractional seconds. Assume that (with legal
	 * value for the following 64 bit usecs) is less likely than clock skew
	 * that makes the ping timestamp in the future, and avoid the wrong
	 * decision in the latter case. */
	if (len == 0 || usecs != 0) {
		if (update_best_guess_timestamp(secs, usecs, comp_ts, out_ts, &best_delta)) {
			len = 8;
		}
	}

	/* BE timeval, 32 bit time_t */
	secs = tvb_get_ntohl(tvb, offset);
	usecs = tvb_get_ntohl(tvb, offset + 4);
	if (update_best_guess_timestamp(secs, usecs, comp_ts, out_ts, &best_delta)) {
		len = 8;
	}

	if (tvb_bytes_exist(tvb, offset, 16)) {
		/* BE timeval, 64 bit time_t */
		secs = (time_t)tvb_get_ntoh64(tvb, offset);
		usecs = tvb_get_ntoh64(tvb, offset + 8);
		if (update_best_guess_timestamp(secs, usecs, comp_ts, out_ts, &best_delta)) {
			len = 16;
		}
	}

	return len;
}

#define MSPERDAY            86400000

/* ======================================================================= */
static uint32_t
get_best_guess_mstimeofday(tvbuff_t * tvb, int offset, uint32_t comp_ts)
{
	uint32_t be_ts, le_ts;

	/* Account for the special case from RFC 792 as best we can by clearing
	 * the msb.  Ref: [Page 16] of https://tools.ietf.org/html/rfc792:

	 If the time is not available in milliseconds or cannot be provided
	 with respect to midnight UT then any time can be inserted in a
	 timestamp provided the high order bit of the timestamp is also set
	 to indicate this non-standard value.
	 */
	be_ts = tvb_get_ntohl(tvb, offset) & 0x7fffffff;
	le_ts = tvb_get_letohl(tvb, offset) & 0x7fffffff;

	if (be_ts < MSPERDAY && le_ts >= MSPERDAY) {
		return be_ts;
	}

	if (le_ts < MSPERDAY && be_ts >= MSPERDAY) {
		return le_ts;
	}

	if (be_ts < MSPERDAY && le_ts < MSPERDAY) {
		uint32_t saved_be_ts = be_ts;
		uint32_t saved_le_ts = le_ts;

		/* Is this a rollover to a new day, clocks not synchronized, different
		 * timezones between originate and receive/transmit, .. what??? */
		if (be_ts < comp_ts && be_ts <= (MSPERDAY / 4)
		    && comp_ts >= (MSPERDAY - (MSPERDAY / 4)))
			be_ts += MSPERDAY;	/* Assume a rollover to a new day */
		if (le_ts < comp_ts && le_ts <= (MSPERDAY / 4)
		    && comp_ts >= (MSPERDAY - (MSPERDAY / 4)))
			le_ts += MSPERDAY;	/* Assume a rollover to a new day */
		if ((be_ts - comp_ts) < (le_ts - comp_ts))
			return saved_be_ts;
		return saved_le_ts;
	}

	/* Both are bigger than MSPERDAY, but neither one's msb's are set.  This
	 * is clearly invalid, but now what TODO?  For now, take the one closest to
	 * the comparative timestamp, which is another way of saying, "let's
	 * return a deterministic wild guess. */
	if ((be_ts - comp_ts) < (le_ts - comp_ts)) {
		return be_ts;
	}
	return le_ts;
}				/* get_best_guess_mstimeofday() */

static bool
capture_icmp(const unsigned char *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	capture_dissector_increment_count(cpinfo, proto_icmp);
	return true;
}

/*
 * RFC 792 for basic ICMP.
 * RFC 1191 for ICMP_FRAG_NEEDED (with MTU of next hop).
 * RFC 1256 for router discovery messages.
 * RFC 2002 and 3012 for Mobile IP stuff.
 */
static int
dissect_icmp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data)
{
	proto_tree *icmp_tree = NULL;
	proto_item *ti, *checksum_item;
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint8_t icmp_original_dgram_length;
	unsigned captured_length, reported_length;
	const char *type_str, *code_str;
	uint32_t num_addrs = 0;
	uint32_t addr_entry_size = 0;
	uint32_t i;
	bool save_in_error_pkt;
	tvbuff_t *next_tvb;
	uint32_t conv_key[3];
	icmp_transaction_t *trans = NULL;
	nstime_t ts, time_relative;
	ws_ip4 *iph = WS_IP4_PTR(data);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICMP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* To do: check for runts, errs, etc. */
	icmp_type = tvb_get_uint8(tvb, 0);
	icmp_code = tvb_get_uint8(tvb, 1);
	/* RFC 4884: Length of original datagram carried in the ICMP payload,
	 * or 0 otherwise. Length in terms of 32 bit words.*/
	icmp_original_dgram_length = tvb_get_uint8(tvb, 5);

	type_str =
	    val_to_str_const(icmp_type, icmp_type_str,
			     "Unknown ICMP (obsolete or malformed?)");

	switch (icmp_type) {
	case ICMP_UNREACH:
		code_str =
		    val_to_str(icmp_code, unreach_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_REDIRECT:
		code_str =
		    val_to_str(icmp_code, redir_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_ALTHOST:
		code_str =
		    val_to_str(icmp_code, alt_host_code_str,
			       "Unknown code: %u");
		icmp_original_dgram_length = 0;
		break;
	case ICMP_RTRADVERT:
		switch (icmp_code) {
		case 0:	/* Mobile-Ip */
		case 16:	/* Mobile-Ip */
			type_str = "Mobile IP Advertisement";
			break;
		}		/* switch icmp_code */
		code_str =
		    val_to_str(icmp_code, rtradvert_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_TIMXCEED:
		code_str =
		    val_to_str(icmp_code, ttl_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_PARAMPROB:
		code_str =
		    val_to_str(icmp_code, par_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_PHOTURIS:
		code_str =
		    val_to_str(icmp_code, photuris_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_EXTECHO:
		code_str =
		    val_to_str(icmp_code, ext_echo_req_code_str,
			       "Unknown code: %u");
		break;
	case ICMP_EXTECHOREPLY:
		code_str =
		    val_to_str(icmp_code, ext_echo_reply_code_str,
			       "Unknown code: %u");
		break;
	default:
		code_str = NULL;
		break;
	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "%-20s", type_str);
	if (code_str) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", code_str);
	}

	captured_length = tvb_captured_length(tvb);
	reported_length = tvb_reported_length(tvb);

	ti = proto_tree_add_item(tree, proto_icmp, tvb, 0, captured_length, ENC_NA);
	icmp_tree = proto_item_add_subtree(ti, ett_icmp);

	ti = proto_tree_add_item(icmp_tree, hf_icmp_type, tvb, 0, 1,
				 ENC_BIG_ENDIAN);
	proto_item_append_text(ti, " (%s)", type_str);
        switch (icmp_type) {
	case ICMP_SOURCEQUENCH:
	case ICMP_ALTHOST:
	case ICMP_IREQ:
	case ICMP_IREQREPLY:
	case ICMP_MASKREQ:
	case ICMP_MASKREPLY:
	case 30:
	case 31:
	case 32:
	case 33:
	case 34:
	case 35:
	case 36:
	case 37:
	case 38:
	case 39:
		expert_add_info(pinfo, ti, &ei_icmp_type_deprecated);
		break;
	default:
		break;
	}

	ti = proto_tree_add_item(icmp_tree, hf_icmp_code, tvb, 1, 1,
				 ENC_BIG_ENDIAN);
	if (code_str) {
		proto_item_append_text(ti, " (%s)", code_str);
	}

	if (!pinfo->fragmented && captured_length >= reported_length
	    && !pinfo->flags.in_error_pkt) {
		/* The packet isn't part of a fragmented datagram, isn't
		   truncated, and isn't the payload of an error packet, so we can checksum
		   it. */
		proto_tree_add_checksum(icmp_tree, tvb, 2, hf_icmp_checksum, hf_icmp_checksum_status, &ei_icmp_checksum, pinfo, ip_checksum_tvb(tvb, 0, reported_length),
								ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
	} else {
		checksum_item = proto_tree_add_checksum(icmp_tree, tvb, 2, hf_icmp_checksum, hf_icmp_checksum_status, &ei_icmp_checksum, pinfo, 0,
								ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		proto_item_append_text(checksum_item, " [%s]",
					pinfo->flags.in_error_pkt ? "in ICMP error packet" : "fragmented datagram");
	}

	/* Decode the second 4 bytes of the packet. */
	switch (icmp_type) {
	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	case ICMP_TSTAMP:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQ:
	case ICMP_IREQREPLY:
	case ICMP_MASKREQ:
	case ICMP_MASKREPLY:
		proto_tree_add_item(icmp_tree, hf_icmp_ident, tvb, 4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ident_le, tvb, 4, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_seq_num, tvb, 6, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_seq_num_le, tvb, 6, 2, ENC_LITTLE_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, " id=0x%04x, seq=%u/%u",
				tvb_get_ntohs(tvb, 4), tvb_get_ntohs(tvb, 6), tvb_get_letohs(tvb, 6));
		if (iph != NULL) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", ttl=%u", iph->ip_ttl);
		}
		break;

	case ICMP_UNREACH:
		if (icmp_original_dgram_length > 0) {
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 4, 1, ENC_NA);
			proto_tree_add_item(icmp_tree, hf_icmp_length, tvb, 5, 1, ENC_BIG_ENDIAN);
			ti = proto_tree_add_uint(icmp_tree, hf_icmp_length_original_datagram,
						 tvb, 5, 1, icmp_original_dgram_length * 4);
			proto_item_set_generated(ti);
			if (icmp_code == ICMP_FRAG_NEEDED) {
				proto_tree_add_item(icmp_tree, hf_icmp_mtu, tvb, 6, 2, ENC_BIG_ENDIAN);
			} else {
				proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 6, 2, ENC_NA);
			}
		} else if (icmp_code == ICMP_FRAG_NEEDED) {
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 4, 2, ENC_NA);
			proto_tree_add_item(icmp_tree, hf_icmp_mtu, tvb, 6, 2, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 4, 4, ENC_NA);
		}
		break;

	case ICMP_RTRADVERT:
		proto_tree_add_item_ret_uint(icmp_tree, hf_icmp_num_addrs, tvb, 4, 1, ENC_BIG_ENDIAN, &num_addrs);
		proto_tree_add_item_ret_uint(icmp_tree, hf_icmp_addr_entry_size, tvb, 5, 1, ENC_BIG_ENDIAN, &addr_entry_size);
		ti = proto_tree_add_item(icmp_tree, hf_icmp_lifetime, tvb, 6, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(ti, " (%s)", signed_time_secs_to_str(pinfo->pool, tvb_get_ntohs(tvb, 6)));
		break;

	case ICMP_PARAMPROB:
		proto_tree_add_item(icmp_tree, hf_icmp_pointer, tvb, 4, 1, ENC_BIG_ENDIAN);
		if (icmp_original_dgram_length > 0) {
			proto_tree_add_item(icmp_tree, hf_icmp_length, tvb, 5, 1, ENC_BIG_ENDIAN);
			ti = proto_tree_add_uint(icmp_tree, hf_icmp_length_original_datagram,
						 tvb, 5, 1, icmp_original_dgram_length * 4);
			proto_item_set_generated(ti);
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 6, 2, ENC_NA);
		} else {
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 5, 3, ENC_NA);
		}
		break;

	case ICMP_REDIRECT:
		proto_tree_add_item(icmp_tree, hf_icmp_redir_gw, tvb, 4, 4, ENC_BIG_ENDIAN);
		break;

	case ICMP_TIMXCEED:
		if (icmp_original_dgram_length > 0) {
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 4, 1, ENC_NA);
			proto_tree_add_item(icmp_tree, hf_icmp_length, tvb, 5, 1, ENC_BIG_ENDIAN);
			ti = proto_tree_add_uint(icmp_tree, hf_icmp_length_original_datagram,
						 tvb, 5, 1, icmp_original_dgram_length * 4);
			proto_item_set_generated(ti);
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 6, 2, ENC_NA);
		} else {
			proto_tree_add_item(icmp_tree, hf_icmp_unused, tvb, 4, 4, ENC_NA);
		}
		break;

	case ICMP_EXTECHO:
		proto_tree_add_item(icmp_tree, hf_icmp_ident, tvb, 4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ident_le, tvb, 4, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_seq_num, tvb, 6, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_req_reserved, tvb, 7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_req_local, tvb, 7, 1, ENC_BIG_ENDIAN);
		break;

	case ICMP_EXTECHOREPLY:
		proto_tree_add_item(icmp_tree, hf_icmp_ident, tvb, 4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ident_le, tvb, 4, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_seq_num, tvb, 6, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_rsp_state, tvb, 7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_rsp_reserved, tvb, 7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_rsp_active, tvb, 7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_rsp_ipv4, tvb, 7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(icmp_tree, hf_icmp_ext_echo_rsp_ipv6, tvb, 7, 1, ENC_BIG_ENDIAN);
		break;
	}


	/* Decode the additional information in the packet.  */
	switch (icmp_type) {
	case ICMP_UNREACH:
	case ICMP_TIMXCEED:
	case ICMP_PARAMPROB:
	case ICMP_SOURCEQUENCH:
	case ICMP_REDIRECT:
		/* Save the current value of the "we're inside an error packet"
		   flag, and set that flag; subdissectors may treat packets
		   that are the payload of error packets differently from
		   "real" packets. */
		save_in_error_pkt = pinfo->flags.in_error_pkt;
		pinfo->flags.in_error_pkt = true;

		/* Decode the IP header and first 64 bits of data from the
		   original datagram. */
		next_tvb = tvb_new_subset_remaining(tvb, 8);

		/* If the packet is compliant with RFC 4884, then it has
		 * icmp_original_dgram_length*4 bytes of original IP packet that needs
		 * to be decoded, followed by extension objects.
		 */

		if (icmp_type == ICMP_REDIRECT) {
			/* No icmp_original_dgram_length is available for redirect message,
			 * we expect a max of Internet Header + 64 bits of Original Data Datagram */
			set_actual_length(next_tvb, ((tvb_get_uint8(tvb, 8) & 0x0f) * 4) + 8);
		} else if (icmp_original_dgram_length
		    && (tvb_reported_length(tvb) >
			(unsigned) (8 + icmp_original_dgram_length * 4))
		    && (tvb_get_ntohs(tvb, 8 + 2) >
			(unsigned) icmp_original_dgram_length * 4)) {
			set_actual_length(next_tvb,
					  ((tvb_get_uint8(tvb, 8) & 0x0f) + icmp_original_dgram_length) * 4);
		} else {
			/* There is a collision between RFC 1812 and draft-ietf-mpls-icmp-02.
			   We don't know how to decode the 128th and following bytes of the ICMP payload.
			   According to draft-ietf-mpls-icmp-02, these bytes should be decoded as MPLS extensions
			   whereas RFC 1812 tells us to decode them as a portion of the original packet.
			   Let the user decide.

			   Here the user decided to favor MPLS extensions.
			   Force the IP dissector to decode only the first 128 bytes. */
			if ((tvb_reported_length(tvb) > 8 + 128) &&
			    favor_icmp_mpls_ext
			    && (tvb_get_ntohs(tvb, 8 + 2) > 128)) {
				set_actual_length(next_tvb, 128);
			}
		}

		call_dissector(ip_handle, next_tvb, pinfo, icmp_tree);

		/* Restore the "we're inside an error packet" flag. */
		pinfo->flags.in_error_pkt = save_in_error_pkt;

		/* Decode MPLS extensions if the payload has at least 128 bytes, and
		   - the original packet in the ICMP payload has less than 128 bytes, or
		   - the user favors the MPLS extensions analysis */
		if ((tvb_reported_length(tvb) > 8 + 128)
		    && (tvb_get_ntohs(tvb, 8 + 2) <= 128
			|| favor_icmp_mpls_ext)) {
			int ext_offset = MAX(icmp_original_dgram_length * 4, 128) + 8;
			tvbuff_t * extension_tvb = tvb_new_subset_remaining(tvb, ext_offset);
			dissect_icmp_extension(extension_tvb, pinfo, icmp_tree, NULL);
		}
		break;
	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
		if (icmp_type == ICMP_ECHOREPLY) {
			if (!pinfo->flags.in_error_pkt) {
				conv_key[0] =
				    (uint32_t) tvb_get_ntohs(tvb, 2);
				if (conv_key[0] == 0xffff) {
					conv_key[0] = 0;
				}
				if (pinfo->flags.in_gre_pkt && prefs.strict_conversation_tracking_heuristics)
					conv_key[0] |= 0x00010000;	/* set a bit for "in GRE" */
				conv_key[1] =
				    ((uint32_t) tvb_get_ntohs(tvb, 4) << 16) |
				     tvb_get_ntohs(tvb, 6);
				conv_key[2] = prefs.strict_conversation_tracking_heuristics ? pinfo->vlan_id : 0;
				trans =
				    transaction_end(pinfo, icmp_tree,
						    conv_key);
			}
		} else {
			if (!pinfo->flags.in_error_pkt) {
				uint16_t tmp[2];

				tmp[0] = ~tvb_get_ntohs(tvb, 2);
				tmp[1] = ~0x0800;	/* The difference between echo request & reply */
				conv_key[0] =
				    ip_checksum((uint8_t *) & tmp,
						sizeof(tmp));
				if (pinfo->flags.in_gre_pkt && prefs.strict_conversation_tracking_heuristics) {
					conv_key[0] |= 0x00010000;	/* set a bit for "in GRE" */
				}
				conv_key[1] =
				    ((uint32_t) tvb_get_ntohs(tvb, 4) << 16) |
				     tvb_get_ntohs(tvb, 6);
				conv_key[2] = prefs.strict_conversation_tracking_heuristics ? pinfo->vlan_id : 0;
				trans =
				    transaction_start(pinfo, icmp_tree,
						      conv_key);
			}
		}

		/* Make sure we have enough bytes in the payload before trying to
		 * see if the data looks like a timestamp; otherwise we'll get
		 * malformed packets as we try to access data that isn't there. */
		if (tvb_captured_length_remaining(tvb, 8) < 8) {
			if (tvb_captured_length_remaining(tvb, 8) > 0) {
				call_data_dissector(tvb_new_subset_remaining
					       (tvb, 8), pinfo, icmp_tree);
			}
			break;
		}

		/* Interpret the first 8 or 16 bytes of the icmp data as a timestamp
		 * But only if it does look like it's a timestamp.
		 *
		 */
		int len = get_best_guess_timestamp(tvb, 8, &pinfo->abs_ts, &ts);
		if (len) {
			proto_tree_add_time(icmp_tree, hf_icmp_data_time,
					    tvb, 8, len, &ts);
			nstime_delta(&time_relative, &pinfo->abs_ts,
				     &ts);
			ti = proto_tree_add_time(icmp_tree,
						 hf_icmp_data_time_relative,
						 tvb, 8, len,
						 &time_relative);
			proto_item_set_generated(ti);
			call_data_dissector(tvb_new_subset_remaining(tvb,
								8 + len),
				       pinfo, icmp_tree);
		} else {
			heur_dtbl_entry_t *hdtbl_entry;
			next_tvb = tvb_new_subset_remaining(tvb, 8);
			if (!dissector_try_heuristic(icmp_heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
				call_data_dissector(next_tvb, pinfo, icmp_tree);
			}
		}
		break;

	case ICMP_RTRADVERT:
		if (addr_entry_size == 2) {
			for (i = 0; i < num_addrs; i++) {
				proto_tree_add_item(icmp_tree, hf_icmp_router_address, tvb, 8 + (i * 8), 4, ENC_NA);
				proto_tree_add_item(icmp_tree, hf_icmp_pref_level, tvb, 12 + (i * 8), 4, ENC_NA);
			}
			if ((icmp_code == 0) || (icmp_code == 16)) {
				/* Mobile-Ip */
				dissect_mip_extensions(tvb, 8 + i * 8,
						       icmp_tree);
			}
		} else {
			call_data_dissector(tvb_new_subset_remaining(tvb, 8),
				       pinfo, icmp_tree);
		}
		break;

	case ICMP_TSTAMP:
	case ICMP_TSTAMPREPLY:
		{
			uint32_t frame_ts, orig_ts;

			frame_ts = (uint32_t)(((pinfo->abs_ts.secs * 1000) +
				    (pinfo->abs_ts.nsecs / 1000000)) %
			    86400000);

			orig_ts = get_best_guess_mstimeofday(tvb, 8, frame_ts);
			ti = proto_tree_add_item(icmp_tree, hf_icmp_originate_timestamp, tvb, 8, 4, ENC_BIG_ENDIAN);
			proto_item_append_text(ti, " (%s after midnight UTC)", signed_time_msecs_to_str(pinfo->pool, orig_ts));

			ti = proto_tree_add_item(icmp_tree, hf_icmp_receive_timestamp, tvb, 12, 4, ENC_BIG_ENDIAN);
			proto_item_append_text(ti, " (%s after midnight UTC)", signed_time_msecs_to_str(pinfo->pool, get_best_guess_mstimeofday(tvb, 12, frame_ts)));

			ti = proto_tree_add_item(icmp_tree, hf_icmp_transmit_timestamp, tvb, 16, 4, ENC_BIG_ENDIAN);
			proto_item_append_text(ti, " (%s after midnight UTC)", signed_time_msecs_to_str(pinfo->pool, get_best_guess_mstimeofday(tvb, 16, frame_ts)));

		}
		break;

	case ICMP_MASKREQ:
	case ICMP_MASKREPLY:
		proto_tree_add_item(icmp_tree, hf_icmp_address_mask, tvb, 8, 4, ENC_BIG_ENDIAN);
		break;

	case ICMP_EXTECHO:
		if (tvb_reported_length(tvb) > 8) {
			tvbuff_t * extension_tvb = tvb_new_subset_remaining(tvb, 8);
			dissect_icmp_extension(extension_tvb, pinfo, icmp_tree, NULL);
		}
		break;
	}

	if (!PINFO_FD_VISITED(pinfo)) {
		icmp_info_t *p_icmp_info = wmem_new(wmem_file_scope(), icmp_info_t);
		p_icmp_info->type = icmp_type;
		p_icmp_info->code = icmp_code;
		p_add_proto_data(wmem_file_scope(), pinfo, proto_icmp, 0, p_icmp_info);
	}

	if (trans) {
		tap_queue_packet(icmp_tap, pinfo, trans);
	}

	return tvb_reported_length(tvb);
}

void proto_register_icmp(void)
{
	static hf_register_info hf[] = {
		{&hf_icmp_type,
		 {"Type", "icmp.type", FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_code,
		 {"Code", "icmp.code", FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_checksum,
		 {"Checksum", "icmp.checksum", FT_UINT16, BASE_HEX, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_checksum_status,
		 {"Checksum Status", "icmp.checksum.status", FT_UINT8, BASE_NONE,
		  VALS(proto_checksum_vals), 0x0,
		  NULL, HFILL}},

		{&hf_icmp_unused,
		 {"Unused", "icmp.unused", FT_BYTES,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_reserved,
		 {"Reserved", "icmp.reserved", FT_BYTES,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_ident,
		 {"Identifier (BE)", "icmp.ident", FT_UINT16, BASE_DEC_HEX,
		  NULL, 0x0,
		  "Identifier (big endian representation)", HFILL}},

		{&hf_icmp_ident_le,
		 {"Identifier (LE)", "icmp.ident_le", FT_UINT16, BASE_DEC_HEX,
		  NULL, 0x0,
		  "Identifier (little endian representation)", HFILL}},

		{&hf_icmp_seq_num,
		 {"Sequence Number (BE)", "icmp.seq", FT_UINT16,
		  BASE_DEC_HEX, NULL, 0x0,
		  "Sequence Number (big endian representation)", HFILL}},

		{&hf_icmp_seq_num_le,
		 {"Sequence Number (LE)", "icmp.seq_le", FT_UINT16,
		  BASE_DEC_HEX, NULL,
		  0x0, "Sequence Number (little endian representation)",
		  HFILL}},

		{&hf_icmp_mtu,
		 {"MTU of next hop", "icmp.mtu", FT_UINT16, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_num_addrs,
		 {"Number of addresses", "icmp.num_addrs", FT_UINT8, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_addr_entry_size,
		 {"Address entry size", "icmp.addr_entry_size", FT_UINT8, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_lifetime,
		 {"Lifetime", "icmp.lifetime", FT_UINT16, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_pointer,
		 {"Pointer", "icmp.pointer", FT_UINT32, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_router_address,
		 {"Router address", "icmp.router_address", FT_IPv4, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_pref_level,
		 {"Preference level", "icmp.pref_level", FT_INT32, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_originate_timestamp,
		 {"Originate Timestamp", "icmp.originate_timestamp", FT_UINT32, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_receive_timestamp,
		 {"Receive Timestamp", "icmp.receive_timestamp", FT_UINT32, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_transmit_timestamp,
		 {"Transmit Timestamp", "icmp.transmit_timestamp", FT_UINT32, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_address_mask,
		 {"Address Mask", "icmp.address_mask", FT_IPv4, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_redir_gw,
		 {"Gateway Address", "icmp.redir_gw", FT_IPv4, BASE_NONE,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_type,
		 {"Extension Type", "icmp.mip.type", FT_UINT8, BASE_DEC,
		  VALS(mip_extensions), 0x0, NULL, HFILL}},

		{&hf_icmp_mip_length,
		 {"Length", "icmp.mip.length", FT_UINT8, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_prefix_length,
		 {"Prefix Length", "icmp.mip.prefixlength", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_seq,
		 {"Sequence Number", "icmp.mip.seq", FT_UINT16, BASE_DEC,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_life,
		 {"Registration Lifetime", "icmp.mip.life", FT_UINT16,
		  BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_flags,
		 {"Flags", "icmp.mip.flags", FT_UINT16, BASE_HEX, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_r,
		 {"Registration Required", "icmp.mip.r", FT_BOOLEAN, 16,
		  NULL, 0x8000,
		  "Registration with this FA is required", HFILL}},

		{&hf_icmp_mip_b,
		 {"Busy", "icmp.mip.b", FT_BOOLEAN, 16, NULL, 0x4000,
		  "This FA will not accept requests at this time", HFILL}},

		{&hf_icmp_mip_h,
		 {"Home Agent", "icmp.mip.h", FT_BOOLEAN, 16, NULL, 0x2000,
		  "Home Agent Services Offered", HFILL}},

		{&hf_icmp_mip_f,
		 {"Foreign Agent", "icmp.mip.f", FT_BOOLEAN, 16, NULL,
		  0x1000,
		  "Foreign Agent Services Offered", HFILL}},

		{&hf_icmp_mip_m,
		 {"Minimal Encapsulation", "icmp.mip.m", FT_BOOLEAN, 16,
		  NULL, 0x0800,
		  "Minimal encapsulation tunneled datagram support",
		  HFILL}},

		{&hf_icmp_mip_g,
		 {"GRE", "icmp.mip.g", FT_BOOLEAN, 16, NULL, 0x0400,
		  "GRE encapsulated tunneled datagram support", HFILL}},

		{&hf_icmp_mip_v,
		 {"VJ Comp", "icmp.mip.v", FT_BOOLEAN, 16, NULL, 0x0200,
		  "Van Jacobson Header Compression Support", HFILL}},

		{&hf_icmp_mip_rt,
		 {"Reverse tunneling", "icmp.mip.rt", FT_BOOLEAN, 16, NULL,
		  0x0100,
		  "Reverse tunneling support", HFILL}},

		{&hf_icmp_mip_u,
		 {"UDP tunneling", "icmp.mip.u", FT_BOOLEAN, 16, NULL,
		  0x0080,
		  "UDP tunneling support", HFILL}},

		{&hf_icmp_mip_x,
		 {"Revocation support", "icmp.mip.x", FT_BOOLEAN, 16, NULL,
		  0x0040,
		  "Registration revocation support", HFILL}},

		{&hf_icmp_mip_reserved,
		 {"Reserved", "icmp.mip.reserved", FT_UINT16, BASE_HEX,
		  NULL, 0x003f,
		  NULL, HFILL}},

		{&hf_icmp_mip_coa,
		 {"Care-Of-Address", "icmp.mip.coa", FT_IPv4, BASE_NONE,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_challenge,
		 {"Challenge", "icmp.mip.challenge", FT_BYTES, BASE_NONE,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mip_content,
		 {"Content", "icmp.mip.content", FT_BYTES, BASE_NONE,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext,
		 {"ICMP Extensions", "icmp.ext", FT_NONE, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext_version,
		 {"Version", "icmp.ext.version", FT_UINT8, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext_reserved,
		 {"Reserved", "icmp.ext.res", FT_UINT16, BASE_HEX, NULL,
		  0x0fff,
		  NULL, HFILL}},

		{&hf_icmp_ext_checksum,
		 {"Checksum", "icmp.ext.checksum", FT_UINT16, BASE_HEX,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext_checksum_status,
		 {"Checksum Status", "icmp.ext.checksum.status", FT_UINT8, BASE_NONE,
		  VALS(proto_checksum_vals),
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext_length,
		 {"Length", "icmp.ext.length", FT_UINT16, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext_class,
		 {"Class", "icmp.ext.class", FT_UINT8, BASE_DEC,
		 VALS(icmp_ext_class_str), 0x0, NULL, HFILL}},

		{&hf_icmp_ext_c_type,
		 {"C-Type", "icmp.ext.ctype", FT_UINT8, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},

		{&hf_icmp_ext_data,
		 {"Data", "icmp.ext.data", FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mpls_label,
		 {"Label", "icmp.mpls.label", FT_UINT24, BASE_DEC, NULL,
		  0xfffff0,
		  NULL, HFILL}},

		{&hf_icmp_mpls_exp,
		 {"Experimental", "icmp.mpls.exp", FT_UINT24, BASE_DEC,
		  NULL, 0x0e,
		  NULL, HFILL}},

		{&hf_icmp_mpls_s,
		 {"Stack bit", "icmp.mpls.s", FT_BOOLEAN, 8,
		  TFS(&tfs_set_notset), 0x01,
		  NULL, HFILL}},

		{&hf_icmp_mpls_ttl,
		 {"Time to live", "icmp.mpls.ttl", FT_UINT8, BASE_DEC,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_mpls_data,
		 {"Data", "icmp.mpls.data", FT_BYTES, BASE_NONE ,
		  NULL, 0x0,
		  NULL, HFILL}},

		{&hf_icmp_resp_in,
		 {"Response frame", "icmp.resp_in", FT_FRAMENUM, BASE_NONE,
		  FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
		  "The frame number of the corresponding response",
		  HFILL}},

		{&hf_icmp_no_resp,
		 {"No response seen", "icmp.no_resp", FT_NONE, BASE_NONE,
		  NULL, 0x0,
		  "No corresponding response frame was seen",
		  HFILL}},

		{&hf_icmp_resp_to,
		 {"Request frame", "icmp.resp_to", FT_FRAMENUM, BASE_NONE,
		  FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
		  "The frame number of the corresponding request", HFILL}},

		{&hf_icmp_resptime,
		 {"Response time", "icmp.resptime", FT_DOUBLE, BASE_NONE,
		  NULL, 0x0,
		  "The time between the request and the response, in ms.",
		  HFILL}},

		{&hf_icmp_data_time,
		 {"Timestamp from icmp data", "icmp.data_time",
		  FT_ABSOLUTE_TIME,
		  ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "The timestamp in the first 8 or 16 bytes of the icmp data",
		  HFILL}},

		{&hf_icmp_data_time_relative,
		 {"Timestamp from icmp data (relative)",
		  "icmp.data_time_relative",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		  "The timestamp of the packet, relative to the timestamp in the first 8 or 16 bytes of the icmp data",
		  HFILL}},

		{&hf_icmp_length,
		 {"Length", "icmp.length", FT_UINT8,
		  BASE_DEC, NULL,
		  0x0,
		  "The length of the original datagram", HFILL}},
		{&hf_icmp_length_original_datagram,
		 {"Length of original datagram", "icmp.length.original_datagram", FT_UINT8,
		  BASE_DEC, NULL,
		  0x0,
		  "The length of the original datagram (length * 4)", HFILL}},
		{&hf_icmp_int_info_role,
		 {"Interface Role", "icmp.int_info.role",
		  FT_UINT8, BASE_DEC, VALS(interface_role_str),
		  INT_INFO_INTERFACE_ROLE,
		  NULL, HFILL}},
		{&hf_icmp_int_info_reserved,
		 {"Reserved", "icmp.int_info.reserved",
		  FT_UINT8, BASE_DEC, NULL, INT_INFO_RESERVED,
		  NULL, HFILL}},
		{&hf_icmp_int_info_ifindex,
		 {"ifIndex", "icmp.int_info.ifindex", FT_BOOLEAN, 8, NULL,
		  INT_INFO_IFINDEX,
		  "True: ifIndex of the interface included; False: ifIndex of the interface not included",
		  HFILL}},
		{&hf_icmp_int_info_ipaddr,
		 {"IP Address", "icmp.int_info.ipaddr", FT_BOOLEAN, 8,
		  TFS(&tfs_present_not_present),
		  INT_INFO_IPADDR,
		  NULL, HFILL}},
		{&hf_icmp_int_info_name,
		 {"Interface Name", "icmp.int_info.name_present", FT_BOOLEAN, 8,
		  TFS(&tfs_present_not_present),
		  INT_INFO_NAME,
		  NULL,
		  HFILL}},
		{&hf_icmp_int_info_mtu_present,
		 {"MTU", "icmp.int_info.mtu_present", FT_BOOLEAN, 8, TFS(&tfs_present_not_present),
		  INT_INFO_MTU,
		  NULL, HFILL}},
		{&hf_icmp_int_info_index,
		 {"Interface Index", "icmp.int_info.index",
		  FT_UINT32, BASE_DEC,
		  NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_info_afi,
		 {"Address Family Identifier", "icmp.int_info.afi",
		  FT_UINT16, BASE_DEC,
		  NULL, 0x0,
		  "Address Family of the interface address", HFILL}},
		{&hf_icmp_int_info_ipv4,
		 {"Source", "icmp.int_info.ipv4", FT_IPv4, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_info_ipv6,
		 {"Source", "icmp.int_info.ipv6", FT_IPv6, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_info_ipunknown,
		 {"Source", "icmp.int_info.ipunknown", FT_BYTES, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_info_name_length,
		 {"Name Length", "icmp.int_info.name_length", FT_UINT8, BASE_DEC, NULL,
		  0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_info_name_string,
		 {"Name", "icmp.int_info.name", FT_STRING, BASE_NONE, NULL,
		  0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_info_mtu,
		 {"Maximum Transmission Unit", "icmp.int_info.mtu",
		  FT_UINT32, BASE_DEC,
		  NULL, 0x0,
		  NULL, HFILL}},


		{&hf_icmp_ext_echo_seq_num,
		 {"Sequence Number", "icmp.ext.echo.seq", FT_UINT8,
		  BASE_DEC_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_req_reserved,
		 {"Reserved", "icmp.ext.echo.req.res", FT_UINT8,
		  BASE_HEX, NULL, 0xFE,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_req_local,
		 {"Local bit", "icmp.ext.echo.req.local", FT_BOOLEAN,
		  8, TFS(&tfs_set_notset), 0x01,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_rsp_state,
		 {"State", "icmp.ext.echo.rsp.state", FT_UINT8,
		  BASE_DEC, VALS(ext_echo_reply_state_str), 0xE0,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_rsp_reserved,
		 {"Reserved", "icmp.ext.echo.rsp.res", FT_UINT8,
		  BASE_HEX, NULL, 0x18,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_rsp_active,
		 {"Active bit", "icmp.ext.echo.rsp.active", FT_BOOLEAN,
		  8, TFS(&tfs_set_notset), 0x04,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_rsp_ipv4,
		 {"IPv4 bit", "icmp.ext.echo.rsp.ipv4", FT_BOOLEAN,
		  8, TFS(&tfs_set_notset), 0x02,
		  NULL, HFILL}},
		{&hf_icmp_ext_echo_rsp_ipv6,
		 {"IPv6 bit", "icmp.ext.echo.rsp.ipv6", FT_BOOLEAN,
		  8, TFS(&tfs_set_notset), 0x01,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_name_string,
		 {"Name", "icmp.int_ident.name", FT_STRING,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_index,
		 {"Interface Index", "icmp.int_ident.index", FT_UINT32,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_afi,
		 {"Address Family Identifier", "icmp.int_ident.afi", FT_UINT16,
		  BASE_DEC, VALS(afn_vals), 0x0,
		  "Address Family of the interface address", HFILL}},
		{&hf_icmp_int_ident_addr_length,
		 {"Address Length", "icmp.int_ident.addr_length", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_reserved,
		 {"Reserved", "icmp.int_ident.reserved", FT_BYTES,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_ipv4,
		 {"Address", "icmp.int_ident.ipv4", FT_IPv4,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_ipv6,
		 {"Address", "icmp.int_ident.ipv6", FT_IPv6,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_icmp_int_ident_address,
		 {"Address", "icmp.int_ident.address", FT_BYTES,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

	};

	static int *ett[] = {
		&ett_icmp,
		&ett_icmp_mip,
		&ett_icmp_mip_flags,
		/* MPLS extensions */
		&ett_icmp_ext,
		&ett_icmp_ext_object,
		&ett_icmp_mpls_stack_object,
		/* Interface Information Object RFC 5837 */
		&ett_icmp_interface_info_object,
		&ett_icmp_interface_ipaddr,
		&ett_icmp_interface_name
	};

	static ei_register_info ei[] = {
		{ &ei_icmp_type_deprecated, { "icmp.type.deprecated", PI_DEPRECATED, PI_NOTE, "Type is deprecated", EXPFILL }},
		{ &ei_icmp_resp_not_found, { "icmp.resp_not_found", PI_SEQUENCE, PI_WARN, "Response not found", EXPFILL }},
		{ &ei_icmp_checksum, { "icmp.checksum_bad", PI_CHECKSUM, PI_WARN, "Bad checksum", EXPFILL }},
		{ &ei_icmp_ext_checksum, { "icmp.ext.checksum_bad", PI_CHECKSUM, PI_WARN, "Bad checksum", EXPFILL }},
	};

	module_t *icmp_module;
	expert_module_t* expert_icmp;

	proto_icmp =
	    proto_register_protocol("Internet Control Message Protocol",
				    "ICMP", "icmp");
	proto_register_field_array(proto_icmp, hf, array_length(hf));
	expert_icmp = expert_register_protocol(proto_icmp);
	expert_register_field_array(expert_icmp, ei, array_length(ei));
	proto_register_subtree_array(ett, array_length(ett));

	icmp_module = prefs_register_protocol(proto_icmp, NULL);

	prefs_register_bool_preference(icmp_module, "favor_icmp_mpls",
				       "Favor ICMP extensions for MPLS",
				       "Whether the 128th and following bytes of the ICMP payload should be decoded as MPLS extensions or as a portion of the original packet",
				       &favor_icmp_mpls_ext);

	register_seq_analysis("icmp", "ICMP Flows", proto_icmp, NULL, TL_REQUIRES_COLUMNS, icmp_seq_analysis_packet);
	icmp_handle = register_dissector("icmp", dissect_icmp, proto_icmp);
	icmp_heur_subdissector_list = register_heur_dissector_list_with_description("icmp", "ICMP Echo payload", proto_icmp);
	register_dissector("icmp_extension", dissect_icmp_extension, proto_icmp);
	icmp_tap = register_tap("icmp");
}

void proto_reg_handoff_icmp(void)
{
	capture_dissector_handle_t icmp_cap_handle;

	/*
	 * Get handle for the IP dissector.
	 */
	ip_handle = find_dissector_add_dependency("ip", proto_icmp);

	dissector_add_uint("ip.proto", IP_PROTO_ICMP, icmp_handle);
	icmp_cap_handle = create_capture_dissector_handle(capture_icmp, proto_icmp);
	capture_dissector_add_uint("ip.proto", IP_PROTO_ICMP, icmp_cap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
