/* packet-wccp.c
 * Routines for Web Cache Coordination Protocol dissection
 * Jerry Talkington <jerryt@netapp.com>
 *
 * $Id: packet-wccp.c,v 1.1 1999/12/12 03:05:56 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include <glib.h>
#include "packet.h"

#define WCCPv1			0x0004
#define WCCP_HERE_I_AM		0x0007
#define WCCP_I_SEE_YOU		0x0008
#define WCCP_ASSIGN_BUCKET	0x0009

static const value_string wccp_types[] = {
	{ WCCP_HERE_I_AM, "WCCP_HERE_I_AM" }, 
	{ WCCP_I_SEE_YOU, "WCCP_I_SEE_YOU" },
	{ WCCP_ASSIGN_BUCKET, "WCCP_ASSIGN_BUCKET" },
	{ 0, NULL}
};

static const value_string wccp_version_val[] = {
	{ WCCPv1, "1"},
	{ 0, NULL}
};

typedef struct _wccp_cache_info {
	guint32 ip_addr;
	guint32 hash_rev;
	guint32 hash_info[8];
	guint32 reserved;
} wccp_cache_info;

static guint32 proto_wccp = -1;
static guint32 ett_wccp = -1;
static guint32 ett_cache_count = -1;
static guint32 ett_cache_info = -1;
static guint32 ett_buckets = -1;
static guint32 hf_wccp_message_type = -1;	/* the message type */
static guint32 hf_wccp_version = -1;		/* protocol version */
static guint32 hf_hash_version = -1;		/* the version of the hash */
static guint32 hf_change_num = -1;		/* change number */
static guint32 hf_recvd_id = -1;			
static guint32 hf_cache_ip = -1;

int wccp_bucket_info(guint8 bucket_info, proto_tree *bucket_tree, guint32 start, int offset);

void
dissect_wccp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	const u_char *data, *data_end;
	proto_tree *wccp_tree = NULL;
	proto_item *wccp_tree_item = NULL;
	guint32 wccp_message_type = 0;
	
	data = &pd[offset];
	data_end = data + END_OF_FRAME;

	if(check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd, COL_PROTOCOL, "WCCP");
	}
	
	wccp_message_type = pntohl(&pd[offset]);

	if(check_col(fd, COL_INFO)) {
		col_add_str(fd, COL_INFO, val_to_str(wccp_message_type, wccp_types, "Unknown WCCP message"));
	}

	if(tree != NULL) {
		guint32 wccp_version = 0;

		wccp_tree_item = proto_tree_add_item_format(tree, proto_wccp, offset, (data_end - data),
			NULL, "Web Cache Coordination Protocol");

		wccp_tree = proto_item_add_subtree(wccp_tree_item, ett_wccp);
		proto_tree_add_item(wccp_tree, hf_wccp_message_type , offset, sizeof(wccp_message_type), wccp_message_type);
		offset += sizeof(wccp_message_type);

		wccp_version = pntohl(&pd[offset]);
		proto_tree_add_item(wccp_tree, hf_wccp_version, offset, sizeof(wccp_version), wccp_version);
		offset += sizeof(wccp_version);

		if (wccp_message_type == WCCP_HERE_I_AM) {
			guint32 *rsvd;
			guint32 hash_version;
			guint32 recvd_id;
			guint32 i = 0;
			guint32 n = 0;
			guint8  bucket_info;
			proto_tree *bucket_tree = NULL;
			proto_item *bucket_item = NULL;
			
			hash_version = pntohl(&pd[offset]);
			proto_tree_add_item(wccp_tree, hf_hash_version, offset, sizeof(hash_version), hash_version);
			offset += sizeof(hash_version);

			bucket_item = proto_tree_add_text(wccp_tree, offset, 32, "Hash Information");
			bucket_tree = proto_item_add_subtree(bucket_item, ett_buckets);
			for(i = 0, n = 0; i < 32; i++) {
				bucket_info = (guint32)pd[offset];
				n = wccp_bucket_info(bucket_info, bucket_tree, n, offset);
				offset += sizeof(bucket_info);
			}

			/* we only care about the first bit, the rest is just pad */
			rsvd = (guint32 *)&pd[offset];
			proto_tree_add_text(wccp_tree, offset, sizeof(rsvd), ( (*rsvd & (1<<31) ) ? "U: Historical" : "U: Current" ) );
			offset += sizeof(rsvd);

			recvd_id = pntohl(&pd[offset]);
			proto_tree_add_item(wccp_tree, hf_recvd_id, offset, sizeof(recvd_id), recvd_id);
			offset += sizeof(recvd_id); /* copy and paste is fun */

		} else if (wccp_message_type == WCCP_I_SEE_YOU) {
			guint32 change_num = 0;
			guint32 recvd_id = 0;
			guint32 cache_count = 0;
			guint32 i = 0;
			guint32 n = 0;
			guint32 ccount = 0;
			guint8  bucket_info;
			wccp_cache_info *cache_info;
			proto_item *cache_count_item = NULL;
			proto_item *cache_info_item = NULL;
			proto_item *bucket_item = NULL;
			proto_tree *cache_count_tree = NULL;
			proto_tree *cache_info_tree = NULL;
			proto_tree *bucket_tree = NULL;
			
			
			change_num = pntohl(&pd[offset]);
			proto_tree_add_item(wccp_tree, hf_change_num, offset, sizeof(change_num), change_num);
			offset += sizeof(change_num);

			recvd_id = pntohl(&pd[offset]);
			proto_tree_add_item(wccp_tree, hf_recvd_id, offset, sizeof(recvd_id), recvd_id);
			offset += sizeof(recvd_id);

			cache_count = pntohl(&pd[offset]);
			cache_count_item = proto_tree_add_text(wccp_tree, offset, sizeof(cache_count), "Number of caches: %i", cache_count); 
			offset += sizeof(cache_count);
			
			cache_count_tree = proto_item_add_subtree(cache_count_item, ett_cache_count);
			for(ccount = 0; ccount < cache_count; ccount++) { 
				cache_info = (wccp_cache_info *)&pd[offset];
				cache_info_item = proto_tree_add_item(cache_count_tree, hf_cache_ip, offset, sizeof(cache_info->ip_addr), cache_info->ip_addr);
				offset += sizeof(cache_info->ip_addr);
				
				cache_info_tree = proto_item_add_subtree(cache_info_item, ett_cache_info);
				
				proto_tree_add_text(cache_info_tree, offset, sizeof(cache_info->hash_rev), "Hash Revision: %i", cache_info->hash_rev);
				offset += sizeof(cache_info->hash_rev);
				bucket_item = proto_tree_add_text(cache_info_tree, offset, 32, "Hash Information");
				bucket_tree = proto_item_add_subtree(bucket_item, ett_buckets);


				for(i = 0, n = 0; i < 32; i++) {
					bucket_info = (guint32)pd[offset];
					n = wccp_bucket_info(bucket_info, bucket_tree, n, offset);
					offset += sizeof(bucket_info);
				}
				proto_tree_add_text(cache_info_tree, offset, sizeof(cache_info->reserved), ( (cache_info->reserved & (1<<31) ) ? "U: Historical" : "U: Current" ) );
				offset += sizeof(cache_info->reserved);
			}
			

		} else if (wccp_message_type == WCCP_ASSIGN_BUCKET) {
		/* this hasn't been tested, since I don't have any traces with this in it. */
			guint32 recvd_id = 0;
			guint32 wc_count = 0;
			guint32 ip_addr = 0;
			guint16 cache_index;
			guint8  i = 0;
			guint8  bucket_info;
			proto_item *ip_item;
			proto_item *bucket_item;
			proto_tree *ip_tree;
			proto_tree *bucket_tree;

			recvd_id = pd[offset];
			proto_tree_add_item(wccp_tree, hf_recvd_id, offset, sizeof(recvd_id), recvd_id);
			offset += sizeof(recvd_id);

			wc_count = pntohl(&pd[offset]);
			ip_item = proto_tree_add_text(wccp_tree, offset, sizeof(wc_count), "Number of caches: %i", wc_count); 
			offset += sizeof(wc_count);

			ip_tree = proto_item_add_subtree(ip_item, ett_cache_count);
			for(i = 0; i < wc_count; i++) {
				ip_addr = pd[offset];
				proto_tree_add_item(ip_tree, hf_cache_ip, offset, sizeof(ip_addr), ip_addr);
				offset += sizeof(ip_addr);
			}

			bucket_item = proto_tree_add_text(wccp_tree, offset, 32, "Bucket Assignments");
			bucket_tree = proto_item_add_subtree(bucket_item, ett_buckets);
			
			for(i = 0; i < 256; i++) {
				bucket_info = pd[offset];
				if(bucket_info != 0xff) {
					cache_index = g_ntohs((guint16)bucket_info);
					proto_tree_add_text(bucket_tree, offset, sizeof(bucket_info), "Bucket %i: Cache %i", i, bucket_info);
				} else {
					proto_tree_add_text(bucket_tree, offset, sizeof(bucket_info), "Bucket %i: Unassigned", i);
				}
				offset += sizeof(bucket_info);
			}
		}
		
		
	}
}

/*
 * wccp_bucket_info()
 * takes an integer representing a "Hash Information" bitmap, and spits out
 * the corresponding proto_tree entries, returning the next bucket number.
 */
int
wccp_bucket_info(guint8 bucket_info, proto_tree *bucket_tree, guint32 start, int offset)
{
	guint32 i;

	for(i = 0; i < 8; i++) {
		proto_tree_add_text(bucket_tree, offset, sizeof(bucket_info), "Bucket %3d: %s", start, (bucket_info & 1<<i ? "Assigned" : "Not Assigned") );
		start++;
	}
	return(start);
}

/* register */
void
proto_register_wccp(void)
{
	static gint *ett[] = {
		&ett_wccp,
		&ett_cache_count,
		&ett_cache_info,
		&ett_buckets,
	};
	static hf_register_info hf[] = {
		{ &hf_wccp_message_type,
			{ "WCCP Message Type", "wccp.message", FT_UINT32, BASE_DEC, VALS(wccp_types), 0x0,
				"The WCCP message that was sent"}
		},
		{ &hf_wccp_version, 
			{ "WCCP Version", "wccp.version", FT_UINT32, BASE_DEC, VALS(wccp_version_val), 0x0,
				"The WCCP version"}
		},
		{ &hf_hash_version,
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
			{ "Cache IP address", "wccp.cache.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
				"The IP address of a cache"}
		},
		
	};

	
	proto_wccp = proto_register_protocol("Web Cache Coordination Protocol", "wccp");
	proto_register_field_array(proto_wccp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett)); 
}
