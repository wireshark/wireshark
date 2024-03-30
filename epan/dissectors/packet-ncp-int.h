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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
	int			length;
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
	uint16_t	type;
	uint8_t	sequence;
	uint8_t	conn_low;
	uint8_t	task;
	uint8_t	conn_high; /* type=0x5555 doesn't have this */
};

extern bool nds_defragment;
extern bool nds_echo_eid;
extern bool ncp_echo_err;
extern bool ncp_echo_conn;
extern bool ncp_echo_server;
extern bool ncp_echo_file;
extern bool ncp_newstyle;

struct _sub_ptvc_record {
	int			*ett;
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
	uint8_t			error_in_packet;
	int			ncp_error_index;
} error_equivalency;

struct _ncp_record;
typedef void (ncp_expert_handler)(ptvcursor_t *ptvc, packet_info *pinfo, const struct _ncp_record *ncp_rec, bool request);

typedef struct _ncp_record {
	uint8_t			func;
	uint8_t			subfunc;
	uint8_t			has_subfunc;
	const char*		name;
	int			group;
	const ptvc_record	*request_ptvc;
	const ptvc_record	*reply_ptvc;
	const error_equivalency	*errors;
	const int		*req_cond_indexes;
	unsigned int		req_cond_size_type;
	ncp_expert_handler  *expert_handler_func;
} ncp_record;

/*
 * XXX - should the object_name be a pointer, initialized to null,
 * and set to a wmem-allocated copy of the full string?
 */
typedef struct {
	const ncp_record	*ncp_rec;
	bool		*req_cond_results;
	uint32_t			req_frame_num;
	nstime_t		req_frame_time;
	uint16_t			length;
	uint32_t			req_nds_flags;
	uint32_t			req_nds_prot_flags;
	uint8_t			nds_request_verb;
	uint8_t			nds_version;
	char			object_name[256];
	bool		nds_frag;
	uint32_t			nds_end_frag;
	uint32_t			nds_frag_num;
	uint16_t			req_mask;
	uint16_t			req_mask_ext;
	uint32_t			nds_frag_flags;
} ncp_req_hash_value;

WS_DLL_PUBLIC const value_string sss_verb_enum[];
WS_DLL_PUBLIC const value_string nmas_subverb_enum[];
WS_DLL_PUBLIC const value_string ncp_nds_verb_vals[];

void dissect_ncp_request(tvbuff_t*, packet_info*, uint32_t,
		uint8_t, uint16_t, bool, proto_tree *volatile);

void dissect_ncp_reply(tvbuff_t *, packet_info*, uint32_t, uint8_t,
		uint16_t, proto_tree*, struct novell_tap*);

void dissect_ping_req(tvbuff_t *, packet_info*, uint32_t, uint8_t,
		uint16_t, proto_tree*);

void dissect_nds_request(tvbuff_t*, packet_info*, uint32_t,
		uint8_t, uint16_t, proto_tree*);

void nds_defrag(tvbuff_t*, packet_info*, uint32_t,
		uint8_t, uint16_t, proto_tree*, struct novell_tap*);

extern int proto_ncp;
extern int ett_ncp;
extern int ett_nds;
extern int ett_nds_segments;
extern int ett_nds_segment;

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
