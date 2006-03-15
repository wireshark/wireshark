/* packet-ncp-int.h
 * Structures and functions for NetWare Core Protocol.
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified for NDS support by Greg Morris (gmorris@novell.com)
 *
 * Portions Copyright (c) Gilbert Ramirez 2000-2002
 * Portions Copyright (c) Novell, Inc. 2000-2003
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2000 Gerald Combs
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

#ifndef __PACKET_NCP_INT_H__
#define __PACKET_NCP_INT_H__

#include <epan/expert.h>

typedef struct _ptvc_record ptvc_record;
typedef struct _sub_ptvc_record sub_ptvc_record;

struct _ptvc_record {
	int			*hf_ptr;
	gint			length;
	const sub_ptvc_record	*sub_ptvc_rec;
	unsigned int	endianness	: 1; /* 0=BE, 1=LE */
	unsigned int	var_index	: 2;
	unsigned int	repeat_index	: 2;
	unsigned int	req_cond_index	: 8;
	unsigned int	special_fmt	: 2;
};

/*
 * Every NCP packet has this common header (except for burst packets).
 */
struct ncp_common_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high; /* type=0x5555 doesn't have this */
};

#define NCP_FMT_NONE			0
#define NCP_FMT_NW_DATE			1
#define NCP_FMT_NW_TIME			2
#define NCP_FMT_UNICODE         3

extern gboolean nds_defragment;
extern gboolean nds_echo_eid;
extern gboolean ncp_echo_err;
extern gboolean ncp_echo_conn;
extern gboolean ncp_echo_server;
extern gboolean ncp_echo_file;

struct _sub_ptvc_record {
	gint			*ett;
	const char		*descr;
	const ptvc_record	*ptvc_rec;
};

typedef struct {
	const char		*dfilter_text;
	dfilter_t		*dfilter;
} conditional_record;

typedef struct {
	int			*hf_ptr;
	const char		*first_string;
	const char		*repeat_string;
} info_string_t;


struct novell_tap {
    int stat;
    int hdr;
};

typedef struct novell_tap _novell_tap;

typedef struct {
	guint8		error_in_packet;
	gint		ncp_error_index;
} error_equivalency;

typedef struct {
	guint8			func;
	guint8			subfunc;
	guint8			has_subfunc;
	const gchar*		name;
	gint			group;
	const ptvc_record	*request_ptvc;
	const ptvc_record	*reply_ptvc;
	const error_equivalency	*errors;
	const int		*req_cond_indexes;
	unsigned int		req_cond_size_type;
	const info_string_t	*req_info_str;
} ncp_record;

typedef struct {
	const ncp_record	*ncp_rec;
	gboolean		*req_cond_results;
	guint32			req_frame_num;
	nstime_t		req_frame_time;
	guint32			req_nds_flags;
	guint8			nds_request_verb;
	guint8			nds_version;
	char			object_name[256];
	gboolean		nds_frag;
	guint32			nds_end_frag;
    guint32         nds_frag_num;
} ncp_req_hash_value;

void dissect_ncp_request(tvbuff_t*, packet_info*, guint32,
		guint8, guint16, proto_tree *volatile);

void dissect_ncp_reply(tvbuff_t *, packet_info*, guint32, guint8,
		guint16, proto_tree*, struct novell_tap*);

void dissect_ping_req(tvbuff_t *, packet_info*, guint32, guint8,
		guint16, proto_tree*);

void dissect_nds_request(tvbuff_t*, packet_info*, guint32,
		guint8, guint16, proto_tree*);

void nds_defrag(tvbuff_t*, packet_info*, guint32,
		guint8, guint16, proto_tree*, struct novell_tap*);

extern int proto_ncp;
extern gint ett_ncp;
extern gint ett_nds;
extern gint ett_nds_segments;
extern gint ett_nds_segment;

/*extern dissector_handle_t nds_data_handle;*/
extern GHashTable *nds_fragment_table;
extern GHashTable *nds_reassembled_table;

/*
 * NCP packet types.
 */
#define NCP_ALLOCATE_SLOT	0x1111
#define NCP_SERVICE_REQUEST	0x2222
#define NCP_SERVICE_REPLY	0x3333
#define NCP_WATCHDOG		0x3e3e
#define NCP_DEALLOCATE_SLOT	0x5555
#define NCP_BURST_MODE_XFER	0x7777
#define NCP_POSITIVE_ACK	0x9999
#define NCP_BROADCAST_SLOT	0xbbbb
#define NCP_LIP_ECHO		0x4c69

#endif
