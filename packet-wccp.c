/* packet-wccp.c
 * Routines for Web Cache Coordination Protocol dissection
 * Jerry Talkington <jerryt@netapp.com>
 *
 * $Id: packet-wccp.c,v 1.11 2000/11/17 21:00:36 gram Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_wccp = -1;
static int hf_wccp_message_type = -1;	/* the message type */
static int hf_wccp_version = -1;	/* protocol version */
static int hf_hash_revision = -1;	/* the version of the hash */
static int hf_change_num = -1;		/* change number */
static int hf_recvd_id = -1;			
static int hf_cache_ip = -1;

static gint ett_wccp = -1;
static gint ett_cache_count = -1;
static gint ett_buckets = -1;
static gint ett_flags = -1;
static gint ett_cache_info = -1;

/*
 * See
 *
 *	http://search.ietf.org/internet-drafts/draft-ietf-wrec-web-pro-00.txt
 *
 * if it hasn't expired yet.
 */

#define UDP_PORT_WCCP	2048

#define WCCPv1			0x0004
#define WCCP_HERE_I_AM		7
#define WCCP_I_SEE_YOU		8
#define WCCP_ASSIGN_BUCKET	9

static const value_string wccp_type_vals[] = {
    { WCCP_HERE_I_AM,     "Here I am" },
    { WCCP_I_SEE_YOU,     "I see you" },
    { WCCP_ASSIGN_BUCKET, "Assign bucket" },
    { 0,                  NULL }
};

static const value_string wccp_version_val[] = {
	{ WCCPv1, "1"},
	{ 0, NULL}
};

#define HASH_INFO_SIZE	(4*(1+8+1))

#define	WCCP_U_FLAG	0x80000000

static void dissect_hash_data(const u_char *pd, int offset,
    proto_tree *wccp_tree);
static void dissect_web_cache_list_entry(const u_char *pd, int offset,
    int index, proto_tree *wccp_tree);
static int wccp_bucket_info(guint8 bucket_info, proto_tree *bucket_tree,
    guint32 start, int offset);
static gchar *bucket_name(guint8 bucket);

static void 
dissect_wccp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree *wccp_tree = NULL;
	proto_item *wccp_tree_item;
	guint32 wccp_message_type;
	guint32 wccp_version;
	guint32 cache_count;
	int i;

	OLD_CHECK_DISPLAY_AS_DATA(proto_wccp, pd, offset, fd, tree);

	if(check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd, COL_PROTOCOL, "WCCP");
	}

	wccp_message_type = pntohl(&pd[offset]);

	if(check_col(fd, COL_INFO)) {
		col_add_str(fd, COL_INFO, val_to_str(wccp_message_type,
		    wccp_type_vals, "Unknown WCCP message (%u)"));
	}

	if(tree != NULL) {
		wccp_tree_item = proto_tree_add_item(tree, proto_wccp, NullTVB, offset,
		    END_OF_FRAME, FALSE);
		wccp_tree = proto_item_add_subtree(wccp_tree_item, ett_wccp);

		proto_tree_add_uint(wccp_tree, hf_wccp_message_type, NullTVB, offset,
		    sizeof(wccp_message_type), wccp_message_type);
		offset += sizeof(wccp_message_type);

		switch (wccp_message_type) {

		case WCCP_HERE_I_AM:
			wccp_version = pntohl(&pd[offset]);
			proto_tree_add_uint(wccp_tree, hf_wccp_version, NullTVB,
			    offset, 4, wccp_version);
			offset += 4;
			dissect_hash_data(pd, offset, wccp_tree);
			offset += HASH_INFO_SIZE;
			proto_tree_add_uint(wccp_tree, hf_recvd_id, NullTVB, offset,
			    4, pntohl(&pd[offset]));
			offset += 4;
			break;

		case WCCP_I_SEE_YOU:
			wccp_version = pntohl(&pd[offset]);
			proto_tree_add_uint(wccp_tree, hf_wccp_version, NullTVB,
			    offset, 4, wccp_version);
			offset += 4;
			proto_tree_add_uint(wccp_tree, hf_change_num, NullTVB, offset,
			    4, pntohl(&pd[offset]));
			offset += 4;
			proto_tree_add_uint(wccp_tree, hf_recvd_id, NullTVB, offset,
			    4, pntohl(&pd[offset]));
			offset += 4;
			cache_count = pntohl(&pd[offset]);
			proto_tree_add_text(wccp_tree, NullTVB, offset, 4,
			    "Number of Web Caches: %u", cache_count);
			offset += 4;
			for (i = 0; i < cache_count; i++) {
				dissect_web_cache_list_entry(pd, offset, i,
				    wccp_tree);
				offset += 4 + HASH_INFO_SIZE;
			}
			break;

		case WCCP_ASSIGN_BUCKET:
			/*
			 * This hasn't been tested, since I don't have any
			 * traces with this in it.
			 */
			proto_tree_add_uint(wccp_tree, hf_recvd_id, NullTVB, offset,
			    4, pntohl(&pd[offset]));
			offset += 4;
			cache_count = pntohl(&pd[offset]);
			proto_tree_add_text(wccp_tree, NullTVB, offset, 4,
			    "Number of Web Caches: %u", cache_count);
			offset += 4;
			for (i = 0; i < cache_count; i++) {
				proto_tree_add_ipv4_format(wccp_tree,
				    hf_cache_ip, NullTVB, offset, 4,
				    pntohl(&pd[offset]),
				    "Web Cache %d IP Address: %s", i,
				    ip_to_str((guint8 *) &pd[offset]));
				offset += 4;
			}
			for (i = 0; i < 256; i += 4) {
				proto_tree_add_text(wccp_tree, NullTVB, offset, 4,
				    "Buckets %d - %d: %10s %10s %10s %10s",
				    i, i + 3,
				    bucket_name(pd[offset]),
				    bucket_name(pd[offset+1]),
				    bucket_name(pd[offset+2]),
				    bucket_name(pd[offset+3]));
				offset += 4;
			}
			break;

		default:
			wccp_version = pntohl(&pd[offset]);
			proto_tree_add_uint(wccp_tree, hf_wccp_version, NullTVB,
			    offset, 4, wccp_version);
			offset += 4;
			old_dissect_data(pd, offset, fd, wccp_tree);
			break;
		}
	}
}

static void
dissect_hash_data(const u_char *pd, int offset, proto_tree *wccp_tree)
{
	proto_item *bucket_item;
	proto_tree *bucket_tree;
	proto_item *tf;
	proto_tree *field_tree;
	int i;
	guint8 bucket_info;
	int n;
	guint32 flags;

	proto_tree_add_uint(wccp_tree, hf_hash_revision, NullTVB, offset, 4,
	    pntohl(&pd[offset]));
	offset += 4;

	bucket_item = proto_tree_add_text(wccp_tree, NullTVB, offset, 32,
	    "Hash information");
	bucket_tree = proto_item_add_subtree(bucket_item, ett_buckets);

	for (i = 0, n = 0; i < 32; i++) {
		bucket_info = pd[offset];
		n = wccp_bucket_info(bucket_info, bucket_tree, n, offset);
		offset += 1;
	}
	flags = pntohl(&pd[offset]);
	tf = proto_tree_add_text(wccp_tree, NullTVB, offset, 4,
	    "Flags: 0x%08X (%s)", flags,
	    ((flags & WCCP_U_FLAG) ?
	      "Hash information is historical" :
	      "Hash information is current"));
	field_tree = proto_item_add_subtree(tf, ett_flags);
	proto_tree_add_text(field_tree, NullTVB, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP_U_FLAG,
	      sizeof (flags)*8,
	      "Hash information is historical",
	      "Hash information is current"));
}

static void
dissect_web_cache_list_entry(const u_char *pd, int offset, int index,
    proto_tree *wccp_tree)
{
	proto_item *tl;
	proto_tree *list_entry_tree;

	tl = proto_tree_add_text(wccp_tree, NullTVB, offset, 4 + HASH_INFO_SIZE,
	    "Web-Cache List Entry(%d)", index);
	list_entry_tree = proto_item_add_subtree(tl,
	    ett_cache_info);
	proto_tree_add_ipv4(list_entry_tree, hf_cache_ip, NullTVB, offset, 4,
	    pntohl(&pd[offset]));
	dissect_hash_data(pd, offset + 4, list_entry_tree);
}

/*
 * wccp_bucket_info()
 * takes an integer representing a "Hash Information" bitmap, and spits out
 * the corresponding proto_tree entries, returning the next bucket number.
 */
static int
wccp_bucket_info(guint8 bucket_info, proto_tree *bucket_tree, guint32 start,
    int offset)
{
	guint32 i;

	for(i = 0; i < 8; i++) {
		proto_tree_add_text(bucket_tree, NullTVB, offset, sizeof(bucket_info), "Bucket %3d: %s", start, (bucket_info & 1<<i ? "Assigned" : "Not Assigned") );
		start++;
	}
	return(start);
}

static gchar *
bucket_name(guint8 bucket)
{
	static gchar str[4][10+1];
	static gchar *cur;

	if (cur == &str[0][0])
		cur = &str[1][0];
	else if (cur == &str[1][0])
		cur = &str[2][0];
	else if (cur == &str[2][0])
		cur = &str[3][0];
	else
		cur = &str[0][0];
	if (bucket == 0xff)
		strcpy(cur, "Unassigned");
	else
		sprintf(cur, "%u", bucket);
	return cur;
}

void
proto_register_wccp(void)
{
	static hf_register_info hf[] = {
		{ &hf_wccp_message_type,
			{ "WCCP Message Type", "wccp.message", FT_UINT32, BASE_DEC, VALS(wccp_type_vals), 0x0,
				"The WCCP message that was sent"}
		},
		{ &hf_wccp_version, 
			{ "WCCP Version", "wccp.version", FT_UINT32, BASE_DEC, VALS(wccp_version_val), 0x0,
				"The WCCP version"}
		},
		{ &hf_hash_revision,
			{ "Hash Revision", "wccp.hash_revision", FT_UINT32, BASE_DEC, 0x0, 0x0,
				"The cache hash revision"}
		},
		{ &hf_change_num,
			{ "Change Number", "wccp.change_num", FT_UINT32, BASE_DEC, 0x0, 0x0,
				"The Web-Cache list entry change number"}
		},
		{ &hf_recvd_id,
			{ "Received ID", "wccp.recvd_id", FT_UINT32, BASE_DEC, 0x0, 0x0,
				"The number of I_SEE_YOU's that have been sent"}
		},
		{ &hf_cache_ip,
			{ "Web Cache IP address", "wccp.cache_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
				"The IP address of a Web cache"}
		},
	};
	static gint *ett[] = {
		&ett_wccp,
		&ett_cache_count,
		&ett_buckets,
		&ett_flags,
		&ett_cache_info,
	};

	proto_wccp = proto_register_protocol("Web Cache Coordination Protocol",
	    "wccp");
	proto_register_field_array(proto_wccp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wccp(void)
{
	old_dissector_add("udp.port", UDP_PORT_WCCP, dissect_wccp);
}
