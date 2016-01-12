/* packet-ncp-int.h
 * Structures and functions for NetWare Core Protocol.
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified for NDS support by Greg Morris (gmorris@novell.com)
 *
 * Portions Copyright (c) Gilbert Ramirez 2000-2002
 * Portions Copyright (c) Novell, Inc. 2000-2003
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_NCP_INT_H__
#define __PACKET_NCP_INT_H__

#include <epan/expert.h>
#include <epan/ptvcursor.h>

typedef struct _ptvc_record ptvc_record;
typedef struct _sub_ptvc_record sub_ptvc_record;

typedef struct {
	int			*hf_ptr;
	const char		*first_string;
	const char		*repeat_string;
} info_string_t;

struct _ptvc_record {
	int			*hf_ptr;
	gint			length;
	const sub_ptvc_record	*sub_ptvc_rec;
	const info_string_t	*req_info_str;
	unsigned int	endianness;
	unsigned int	var_index	: 2;
	unsigned int	repeat_index	: 2;
	unsigned int	req_cond_index	: 8;
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

extern gboolean nds_defragment;
extern gboolean nds_echo_eid;
extern gboolean ncp_echo_err;
extern gboolean ncp_echo_conn;
extern gboolean ncp_echo_server;
extern gboolean ncp_echo_file;
extern gboolean ncp_newstyle;

struct _sub_ptvc_record {
	gint			*ett;
	const char		*descr;
	const ptvc_record	*ptvc_rec;
};

typedef struct {
	const char		*dfilter_text;
	struct epan_dfilter	*dfilter;
} conditional_record;

struct novell_tap {
	int stat;
	int hdr;
};

typedef struct novell_tap _novell_tap;

typedef struct {
	guint8			error_in_packet;
	gint			ncp_error_index;
} error_equivalency;

struct _ncp_record;
typedef void (ncp_expert_handler)(ptvcursor_t *ptvc, packet_info *pinfo, const struct _ncp_record *ncp_rec, gboolean request);

typedef struct _ncp_record {
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
	ncp_expert_handler  *expert_handler_func;
} ncp_record;

typedef struct {
	const ncp_record	*ncp_rec;
	gboolean		*req_cond_results;
	guint32			req_frame_num;
	nstime_t		req_frame_time;
	guint16			length;
	guint32			req_nds_flags;
	guint32			req_nds_prot_flags;
	guint8			nds_request_verb;
	guint8			nds_version;
	char			object_name[256];
	gboolean		nds_frag;
	guint32			nds_end_frag;
	guint32			nds_frag_num;
	guint16			req_mask;
	guint16			req_mask_ext;
	guint32			nds_frag_flags;
} ncp_req_hash_value;

WS_DLL_PUBLIC const value_string sss_verb_enum[];
WS_DLL_PUBLIC const value_string nmas_subverb_enum[];
WS_DLL_PUBLIC const value_string ncp_nds_verb_vals[];

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
