/* packet-igmp.c   2001 Ronnie Sahlberg <rsahlber@bigpond.net.au>
 * Routines for IGMP packet disassembly
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
/*
	IGMP is defined in the following RFCs
	RFC988	Version 0	Obsolete
	RFC1054	Version 1
	RFC1112	Version 1	(same as RFC1054 as far as we are concerned)
	RFC2236	Version 2
	draft-ietf-idmr-igmp-v3-07	Version 3

	Size in bytes for each packet
	type	RFC988	RFC1054	RFC2236 RFC????
	        v0      v1      v2      v3
	0x01      20
	0x02      20
	0x03      20
	0x04      20
	0x05      20
	0x06      20
	0x07      20
	0x08      20
	0x11               8*     8*     >=12
        0x12               8*     8* 
	0x16                      8
	0x17                      8
	0x22                            >=8

   * Differs in second byte of protocol. Always 0 in V1
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "packet.h"
#include "ipproto.h"
#include "in_cksum.h"

static int proto_igmp = -1;
static int hf_type = -1;
static int hf_version = -1;
static int hf_group_type = -1;
static int hf_reply_code = -1;
static int hf_reply_pending = -1;
static int hf_checksum = -1;
static int hf_checksum_bad = -1;
static int hf_identifier = -1;
static int hf_access_key = -1;
static int hf_max_resp = -1;
static int hf_max_resp_exp = -1;
static int hf_max_resp_mant = -1;
static int hf_supress = -1;
static int hf_qrv = -1;
static int hf_qqic = -1;
static int hf_num_src = -1;
static int hf_saddr = -1;
static int hf_num_grp_recs = -1;
static int hf_record_type = -1;
static int hf_aux_data_len = -1;
static int hf_maddr = -1;
static int hf_aux_data = -1;

static int ett_igmp = -1;
static int ett_group_record = -1;
static int ett_sqrv_bits = -1;
static int ett_max_resp = -1;


#define IGMP_V0_CREATE_GROUP_REQUEST	0x01
#define IGMP_V0_CREATE_GROUP_REPLY	0x02
#define IGMP_V0_JOIN_GROUP_REQUEST	0x03
#define IGMP_V0_JOIN_GROUP_REPLY	0x04
#define IGMP_V0_LEAVE_GROUP_REQUEST	0x05
#define IGMP_V0_LEAVE_GROUP_REPLY	0x06
#define IGMP_V0_CONFIRM_GROUP_REQUEST	0x07
#define IGMP_V0_CONFIRM_GROUP_REPLY	0x08
#define IGMP_V1_HOST_MEMBERSHIP_QUERY	0x11
#define IGMP_V1_HOST_MEMBERSHIP_REPORT	0x12
#define IGMP_V1_DVMRP_MESSAGE		0x13
#define IGMP_V1_PIM_ROUTING_MESSAGE	0x14
#define IGMP_V2_MEMBERSHIP_REPORT	0x16
#define IGMP_V2_LEAVE_GROUP		0x17
#define IGMP_V1_TRACEROUTE_RESPONSE	0x1e	/* XXX */
#define IGMP_V1_TRACEROUTE_MESSAGE	0x1f	/* XXX */
#define IGMP_V3_MEMBERSHIP_REPORT	0x22
	
static const value_string commands[] = {
	{IGMP_V0_CREATE_GROUP_REQUEST,	"Create Group Request"		},
	{IGMP_V0_CREATE_GROUP_REPLY,	"Create Group Reply"		},
	{IGMP_V0_JOIN_GROUP_REQUEST,	"Join Group Request"		},
	{IGMP_V0_JOIN_GROUP_REPLY,	"Join Group Reply"		},
	{IGMP_V0_LEAVE_GROUP_REQUEST,	"Leave Group Request"		},
	{IGMP_V0_LEAVE_GROUP_REPLY,	"Leave Group Reply"		},
	{IGMP_V0_CONFIRM_GROUP_REQUEST,	"Confirm Group Request"		},
	{IGMP_V0_CONFIRM_GROUP_REPLY,	"Confirm Group Reply"		},
	{IGMP_V1_HOST_MEMBERSHIP_QUERY,	"Membership Query"		},
	{IGMP_V1_HOST_MEMBERSHIP_REPORT,"Membership Report"		},
	{IGMP_V1_DVMRP_MESSAGE,		"DVMRP Message"			},
	{IGMP_V1_PIM_ROUTING_MESSAGE,	"PIM Routing Message"		},
	{IGMP_V2_MEMBERSHIP_REPORT,	"Membership Report"		},
	{IGMP_V2_LEAVE_GROUP,		"Leave Group"			},
	{IGMP_V1_TRACEROUTE_RESPONSE,	"Traceroute Response"		},
	{IGMP_V1_TRACEROUTE_MESSAGE,	"Traceroute Message"		},
	{IGMP_V3_MEMBERSHIP_REPORT,	"Membership Report"		},
	{0,		NULL}
};

#define IGMP_V3_S		0x08
#define IGMP_V3_QRV_MASK	0x07

#define IGMP_MAX_RESP_EXP	0x70
#define IGMP_MAX_RESP_MANT	0x0f

#define IGMP_V0_GROUP_PUBLIC	0x00
#define IGMP_V0_GROUP_PRIVATE	0x01

static const value_string vs_group_type[] = {
	{IGMP_V0_GROUP_PUBLIC,		"Public Group"			},
	{IGMP_V0_GROUP_PRIVATE,		"Private Group"			},
	{0,		NULL}
};

#define IGMP_V0_REPLY_GRANTED	0x00
#define IGMP_V0_REPLY_NO_RESOURCES	0x01
#define IGMP_V0_REPLY_INVALID_CODE	0x02
#define IGMP_V0_REPLY_INVALID_GROUP	0x03
#define IGMP_V0_REPLY_INVALID_KEY	0x04

static const value_string vs_reply_code[] = {
	{IGMP_V0_REPLY_GRANTED,	"Request Granted"	},
	{IGMP_V0_REPLY_NO_RESOURCES,	"Request Denied, No Resources"	},
	{IGMP_V0_REPLY_INVALID_CODE,	"Request Denied, Invalid Code"	},
	{IGMP_V0_REPLY_INVALID_GROUP,	"Request Denied, Invalid Group"	},
	{IGMP_V0_REPLY_INVALID_KEY,	"Request Denied, Invalid Key"	},
	{0,		NULL}
};

static const true_false_string tfs_s = {
	"SUPRESS router side processing",
	"Do not supress router side processing"
};

#define IGMP_V3_MODE_IS_INCLUDE		1
#define IGMP_V3_MODE_IS_EXCLUDE		2
#define IGMP_V3_CHANGE_TO_INCLUDE_MODE	3
#define IGMP_V3_CHANGE_TO_EXCLUDE_MODE	4
#define IGMP_V3_ALLOW_NEW_SOURCES	5
#define IGMP_V3_BLOCK_OLD_SOURCES	6

static const value_string vs_record_type[] = {
	{IGMP_V3_MODE_IS_INCLUDE, 	"Mode Is Include"		},
	{IGMP_V3_MODE_IS_EXCLUDE, 	"Mode Is Exclude"		},
	{IGMP_V3_CHANGE_TO_INCLUDE_MODE,"Change To Include Mode"	},
	{IGMP_V3_CHANGE_TO_EXCLUDE_MODE,"Change To Exclude Mode"	},
	{IGMP_V3_ALLOW_NEW_SOURCES, 	"Allow New Sources"		},
	{IGMP_V3_BLOCK_OLD_SOURCES, 	"Block Old Sources"		},
	{ 0,	NULL}
};

#define PRINT_VERSION(version) 						\
	if (check_col(pinfo->fd, COL_INFO)) {				\
		char str[256];						\
		sprintf(str,"V%d %s",version,val_to_str(type, commands, \
				"Unknown Type:0x%02x"));		\
		col_add_str(pinfo->fd, COL_INFO,str); 			\
	}								\
	/* version of IGMP protocol */					\
	proto_tree_add_uint(tree, hf_version, tvb, 0, 0, version);	\
	/* type of command */						\
	proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);	\
	offset += 1;


static void igmp_checksum(proto_tree *tree,tvbuff_t *tvb, int len)
{
	guint16 cksum,hdrcksum;
	vec_t cksum_vec[1];

	cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, len);
	cksum_vec[0].len = len;

	hdrcksum = tvb_get_ntohs(tvb, 2);
	cksum = in_cksum(&cksum_vec[0],1);

	if (cksum==0) {
		proto_tree_add_uint_format(tree, hf_checksum, tvb, 2, 2, hdrcksum, "Header checksum: 0x%04x (correct)", hdrcksum);
	} else {
		proto_tree_add_item_hidden(tree, hf_checksum_bad, tvb, 2, 2, TRUE);
		proto_tree_add_uint_format(tree, hf_checksum, tvb, 2, 2, hdrcksum, "Header checksum: 0x%04x (incorrect, should be 0x%04x)", hdrcksum,in_cksum_shouldbe(hdrcksum,cksum));
	}

	return;
}


static int
dissect_v3_max_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	proto_tree *tree;
	proto_item *item;
	guint8 bits;
	guint32 tsecs;

	bits = tvb_get_guint8(tvb, offset);
	if (bits&0x80) {
		tsecs = ((bits&IGMP_MAX_RESP_MANT)|0x10);
		tsecs = tsecs << ( ((bits&IGMP_MAX_RESP_EXP)>>4) + 3);
	} else {
		tsecs = bits;
	}		

	item = proto_tree_add_uint_format(parent_tree, hf_max_resp, tvb,
			offset, 1, tsecs, "Max Response Time: %.1f sec (0x%02x)",tsecs*0.1,bits);

	if (bits&0x80) {
		tree = proto_item_add_subtree(item, ett_max_resp);

		proto_tree_add_uint(tree, hf_max_resp_exp, tvb, offset, 1,
			bits);
		proto_tree_add_uint(tree, hf_max_resp_mant, tvb, offset, 1,
			bits);
	}

	offset += 1;

	return offset;
}

static int
dissect_v3_sqrv_bits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	proto_tree *tree;
	proto_item *item;
	guint8 bits;

	bits = tvb_get_guint8(tvb, offset);

	item = proto_tree_add_text(parent_tree, tvb, offset, 1, 
		"QRV=%d S=%s", bits&IGMP_V3_QRV_MASK,
			(bits&IGMP_V3_S)?tfs_s.true_string:tfs_s.false_string);
	tree = proto_item_add_subtree(item, ett_sqrv_bits);

	/* S flag */
	proto_tree_add_boolean(tree, hf_supress, tvb, offset, 1, bits);
	/* QRV */
	proto_tree_add_uint(tree, hf_qrv, tvb, offset, 1, bits);
	offset += 1;

	return offset;
}

static int
dissect_v3_group_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	proto_tree *tree;
	proto_item *item;
	int old_offset = offset;
	guint8	adl;
	guint16 num;
	guint32 ip;

	ip = tvb_get_letohl(tvb, offset+4);
	item = proto_tree_add_text(parent_tree, tvb, offset, 0, 
		"Group Record : %s  %s", 
			ip_to_str((gchar*)&ip), 
			val_to_str(tvb_get_guint8(tvb, offset), vs_record_type,"")
		);
	tree = proto_item_add_subtree(item, ett_group_record);

	/* record type */
	proto_tree_add_uint(tree, hf_record_type, tvb, offset, 1, tvb_get_guint8(tvb, offset));
	offset += 1;

	/* aux data len */
	adl = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_aux_data_len, tvb, offset, 1, adl);
	offset += 1;

	/*number of sources*/
	num = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, hf_num_src, tvb, offset, 2, num);
	offset += 2;

	/* multicast address */
	proto_tree_add_ipv4(tree, hf_maddr, tvb, 
		offset, 4, tvb_get_letohl(tvb, offset));
	offset += 4;

	/* source addresses */
	while(num--){
		proto_tree_add_ipv4(tree, hf_saddr, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;
	}

	/* aux data */
	if(adl){
		proto_tree_add_bytes(tree, hf_aux_data, tvb, offset, adl*4, tvb_get_ptr(tvb, offset, adl*4));
		offset += adl*4;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/* dissectors for version 3, rfc???? */
static int
dissect_igmp_v3_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int type, int offset)
{
	guint16 num;

	PRINT_VERSION(3);

	/* skip reserved field*/
	offset += 1;

	/* checksum */
	igmp_checksum(tree, tvb, pinfo->iplen-pinfo->iphdrlen*4);
	offset +=2;

	/* skip reserved field */
	offset += 2;

	/* number of group records */
	num = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, hf_num_grp_recs, tvb, offset, 2, num);
	offset += 2;
	
	while (num--) {
		offset = dissect_v3_group_record(tvb,pinfo,tree,offset);
	}

	return offset;
}

static int
dissect_igmp_v3_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int type, int offset)
{
	guint16 num;

	PRINT_VERSION(3);

	num = tvb_get_ntohs(tvb, offset+9);
	/* max resp code */
	offset = dissect_v3_max_resp(tvb, pinfo, tree, offset);

	/* checksum */
	igmp_checksum(tree, tvb, pinfo->iplen-pinfo->iphdrlen*4);
	offset += 2;

	/* group address */
	proto_tree_add_ipv4(tree, hf_maddr, tvb, offset, 4, tvb_get_letohl(tvb, offset));
	offset +=4;

	/* bitmask for S and QRV */
	offset = dissect_v3_sqrv_bits(tvb, pinfo, tree, offset);

	/* qqic */
	proto_tree_add_uint(tree, hf_qqic, tvb, offset, 1, tvb_get_guint8(tvb, offset));
	offset += 1;

	/*number of sources*/
	proto_tree_add_uint(tree, hf_num_src, tvb, offset, 2, num);
	offset += 2;

	while(num--){
		proto_tree_add_ipv4(tree, hf_saddr, tvb, 
			offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;
	}

	return offset;
}

/* dissector for version 2, rfc2236 */
static int
dissect_igmp_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int type, int offset)
{
	guint8 tsecs;

	PRINT_VERSION(2);

	/* max resp time */
	tsecs = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(tree, hf_max_resp, tvb,
		offset, 1, tsecs, "Max Response Time: %.1f sec (0x%02x)", tsecs*0.1,tsecs);
	offset += 1;

	/* checksum */
	igmp_checksum(tree, tvb, 8);
	offset += 2;

	/* group address */
	proto_tree_add_ipv4(tree, hf_maddr, tvb, offset, 4, tvb_get_letohl(tvb, offset));
	offset +=4;

	return offset;
}

/* dissector for version 1, rfc1054 */
static int
dissect_igmp_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int type, int offset)
{
	PRINT_VERSION(1);

	/* skip unused byte */
	offset += 1;

	/* checksum */
	igmp_checksum(tree, tvb, 8);
	offset += 2;

	/* group address */
	proto_tree_add_ipv4(tree, hf_maddr, tvb, offset, 4, tvb_get_letohl(tvb, offset));
	offset +=4;

	return offset;
}

/*
 * Dissector for V1 PIM messages.
 *
 * XXX - are these just PIM V1 messages (which we don't dissect in the PIM
 * dissector)?  Where is PIM V1 documented?  I'm inferring some of this
 * from the tcpdump IGMP dissector.
 */
#define PIMV1_QUERY		0
#define PIMV1_REGISTER		1
#define PIMV1_REGISTER_STOP	2
#define PIMV1_JOIN_PRUNE	3
#define PIMV1_RP_REACHABLE	4
#define PIMV1_ASSERT		5
#define PIMV1_GRAFT		6
#define PIMV1_GRAFT_ACK		7
#define PIMV1_MODE		8

static const value_string pim_routing_type[] = {
	{ PIMV1_QUERY,		"Query" },
	{ PIMV1_REGISTER,	"Register" },
	{ PIMV1_REGISTER_STOP,	"Register-Stop" },
	{ PIMV1_JOIN_PRUNE,	"Join/Prune" },
	{ PIMV1_RP_REACHABLE,	"RP-reachable" },
	{ PIMV1_ASSERT,		"Assert" },
	{ PIMV1_GRAFT,		"Graft" },
	{ PIMV1_GRAFT_ACK,	"Graft-ACK" },
	{ PIMV1_MODE,		"Mode" },
	{ 0,			NULL }
};

static int
dissect_igmp_v1_pim_routing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int type, int offset)
{
	guint8 pimv1_type;

	PRINT_VERSION(1);

	pimv1_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Message type: %s",
	    val_to_str(pimv1_type, pim_routing_type, "Unknown (%u)"));

	/* XXX - dissect the rest of it */
	return offset;
}

/* dissector for version 0, rfc988 */
static int
dissect_igmp_v0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int type, int offset)
{
	unsigned char code;

	PRINT_VERSION(0);

	/* Code */
	code = tvb_get_guint8(tvb, offset);
	if (type==IGMP_V0_CREATE_GROUP_REQUEST) {
		proto_tree_add_uint(tree, hf_group_type, tvb, offset, 1, code);
	} else if (!(type&0x01)) {
		if (code <5) {
			proto_tree_add_uint(tree, hf_reply_code, tvb, offset, 1, code);
		} else {
			proto_tree_add_uint(tree, hf_reply_pending, tvb, offset, 1, code);
		}
	}
	offset += 1;

	/* checksum */
	igmp_checksum(tree, tvb, 20);
	offset += 2;

	/* identifier */
	proto_tree_add_uint(tree, hf_identifier, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
	offset += 4;

	/* group address */
	proto_tree_add_ipv4(tree, hf_maddr, tvb, offset, 4, tvb_get_letohl(tvb, offset));
	offset +=4;

	/* access key */
	proto_tree_add_bytes(tree, hf_access_key, tvb, offset, 8, tvb_get_ptr(tvb, offset, 8));
	offset +=8;

	return offset;		
} 

static void
dissect_igmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree;
	proto_item *item;
	int offset = 0;
	unsigned char type;

	item = proto_tree_add_item(parent_tree, proto_igmp, tvb, offset, 0, FALSE);
	tree = proto_item_add_subtree(item, ett_igmp);


	if (check_col(pinfo->fd, COL_PROTOCOL)) {
		col_set_str(pinfo->fd, COL_PROTOCOL, "IGMP");
	}
	if (check_col(pinfo->fd, COL_INFO)) {
		col_clear(pinfo->fd, COL_INFO);
	}


	type = tvb_get_guint8(tvb, offset);


	/* version 0 */
	if ((type&0xf0)==0){
		offset = dissect_igmp_v0(tvb, pinfo, tree, type, offset);
	}


	switch (type) {

	case IGMP_V1_HOST_MEMBERSHIP_QUERY:	/* 0x11 v1/v2/v3 */
		if ( (pinfo->iplen-pinfo->iphdrlen*4)>=12 ) {
			/* version 3 */
			offset = dissect_igmp_v3_query(tvb, pinfo, tree, type, offset);
		} else {
			/* v1 and v2 differs in second byte of header */
			if (tvb_get_guint8(tvb, offset)) {
				offset = dissect_igmp_v2(tvb, pinfo, tree, type, offset);
			} else {
				offset = dissect_igmp_v1(tvb, pinfo, tree, type, offset);
			}
		}
		break;

	case IGMP_V1_HOST_MEMBERSHIP_REPORT:	/* 0x12  v1/v2 */
		/* v1 and v2 differs in second byte of header */
		if (tvb_get_guint8(tvb, offset)) {
			offset = dissect_igmp_v2(tvb, pinfo, tree, type, offset);
		} else {
			offset = dissect_igmp_v1(tvb, pinfo, tree, type, offset);
		}
		break;

	case IGMP_V1_DVMRP_MESSAGE:
		offset = dissect_igmp_v1(tvb, pinfo, tree, type, offset);
		/*
		 * XXX - dissect the rest as DVMRP; see the tcpdump IGMP
		 * and DVMRP dissectors.
		 */
		break;

	case IGMP_V1_PIM_ROUTING_MESSAGE:
		offset = dissect_igmp_v1_pim_routing(tvb, pinfo, tree, type, offset);
		break;

	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V2_LEAVE_GROUP:
		offset = dissect_igmp_v2(tvb, pinfo, tree, type, offset);
		break;

	case IGMP_V1_TRACEROUTE_RESPONSE:
		/* XXX - V1 or V2? */
		offset = dissect_igmp_v1(tvb, pinfo, tree, type, offset);
		/*
		 * XXX - dissect the rest as traceroute response; see the
		 * tcpdump IGMP dissector.
		 */
		break;

	case IGMP_V1_TRACEROUTE_MESSAGE:
		/* XXX - V1 or V2? */
		offset = dissect_igmp_v1(tvb, pinfo, tree, type, offset);
		/*
		 * XXX - dissect the rest as traceroute message; see the
		 * tcpdump IGMP dissector.
		 */
		break;

	case IGMP_V3_MEMBERSHIP_REPORT:
		offset = dissect_igmp_v3_response(tvb, pinfo, tree, type, offset);
		break;
	}


	proto_item_set_len(item, offset);
}

void
proto_register_igmp(void)
{
	static hf_register_info hf[] = {
		{ &hf_type,
			{ "Type", "igmp.type", FT_UINT8, BASE_HEX,
			  VALS(commands), 0, "IGMP Packet Type" }},

		{ &hf_version,
			{ "IGMP Version", "igmp.version", FT_UINT8, BASE_DEC,
			  NULL, 0, "IGMP Version" }},

		{ &hf_group_type,
			{ "Type Of Group", "igmp.group_type", FT_UINT8, BASE_DEC,
			  VALS(vs_group_type), 0, "IGMP V0 Type Of Group" }},

		{ &hf_reply_code,
			{ "Reply", "igmp.reply", FT_UINT8, BASE_DEC,
			  VALS(vs_reply_code), 0, "IGMP V0 Reply" }},

		{ &hf_reply_pending,
			{ "Reply Pending", "igmp.reply.pending", FT_UINT8, BASE_DEC,
			  NULL, 0, "IGMP V0 Reply Pending, Retry in this many seconds" }},

		{ &hf_checksum,
			{ "Checksum", "igmp.checksum", FT_UINT16, BASE_HEX,
			  NULL, 0, "IGMP Checksum" }},

		{ &hf_checksum_bad,
			{ "Bad Checksum", "igmp.checksum_bad", FT_BOOLEAN, BASE_NONE,
			  NULL, 0, "Bad IGMP Checksum" }},

		{ &hf_identifier,
			{ "Identifier", "igmp.identifier", FT_UINT32, BASE_DEC,
			  NULL, 0, "IGMP V0 Identifier" }},

		{ &hf_access_key,
			{ "Access Key", "igmp.access_key", FT_BYTES, BASE_HEX,
			  NULL, 0, "IGMP V0 Access Key" }},

		{ &hf_max_resp,
			{ "Max Resp Time", "igmp.max_resp", FT_UINT8, BASE_DEC,
			  NULL, 0, "Max Response Time" }},

		{ &hf_supress,
			{ "S", "igmp.s", FT_BOOLEAN, 8,
			  TFS(&tfs_s), IGMP_V3_S, "Supress Router Side Processing" }},

		{ &hf_qrv,
			{ "QRV", "igmp.qrv", FT_UINT8, BASE_DEC,
			NULL, IGMP_V3_QRV_MASK, "Querier's Robustness Value"}},

		{ &hf_qqic,
			{ "QQIC", "igmp.qqic", FT_UINT8, BASE_DEC,
			  NULL, 0, "Querier's Query Interval Code" }},

		{ &hf_num_src,
			{ "Num Src", "igmp.num_src", FT_UINT16, BASE_DEC,
			  NULL, 0, "Number Of Sources" }},

		{ &hf_saddr,
			{ "Source Address", "igmp.saddr", FT_IPv4, BASE_NONE,
			  NULL, 0, "Source Address" }},

		{ &hf_num_grp_recs,
			{ "Num Group Records", "igmp.num_grp_recs", FT_UINT16, BASE_DEC,
			  NULL, 0, "Number Of Group Records" }},

		{ &hf_record_type,
			{ "Record Type", "igmp.record_type", FT_UINT8, BASE_DEC,
			VALS(vs_record_type), 0, "Record Type"}},

		{ &hf_aux_data_len,
			{ "Aux Data Len", "igmp.aux_data_len", FT_UINT8, BASE_DEC,
			NULL, 0, "Aux Data Len, In units of 32bit words"}},

		{ &hf_maddr,
			{ "Multicast Address", "igmp.maddr", FT_IPv4, BASE_NONE,
			  NULL, 0, "Multicast Address" }},

		{ &hf_aux_data,
			{ "Aux Data", "igmp.aux_data", FT_BYTES, BASE_HEX,
			  NULL, 0, "IGMP V3 Auxiliary Data" }},

		{ &hf_max_resp_exp,
			{ "Exponent", "igmp.max_resp.exp", FT_UINT8, BASE_HEX,
			NULL, IGMP_MAX_RESP_EXP, "Maxmimum Response Time, Exponent"}},

		{ &hf_max_resp_mant,
			{ "Mantissa", "igmp.max_resp.mant", FT_UINT8, BASE_HEX,
			NULL, IGMP_MAX_RESP_MANT, "Maxmimum Response Time, Mantissa"}},

	};
	static gint *ett[] = {
		&ett_igmp,
		&ett_group_record,
		&ett_sqrv_bits,
		&ett_max_resp,
	};

	proto_igmp = proto_register_protocol("Internet Group Management Protocol",
	    "IGMP", "igmp");
	proto_register_field_array(proto_igmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_igmp(void)
{
	dissector_add("ip.proto", IP_PROTO_IGMP, dissect_igmp, proto_igmp);
}
