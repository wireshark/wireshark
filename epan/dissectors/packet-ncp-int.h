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


static const value_string ncp_group_vals[] = {
    { 0, "Synchronization" },
    { 1, "Print" },
    { 2, "File System" },
    { 3, "Connection" },
    { 4, "File Server Environment" },
    { 5, "Message" },
    { 6, "Bindery" },
    { 7, "Queue Management System (QMS)" },
    { 8, "Accounting" },
    { 9, "Transaction Tracking" },
    { 10, "AFP" },
    { 11, "NCP Extension" },
    { 12, "Extended Attribute" },
    { 13, "Auditing" },
    { 14, "Enhanced File System" },
    { 15, "Migration" },
    { 16, "Novell Modular Authentication Services (NMAS)" },
    { 17, "Secret Store Services (SSS)" },
    { 18, "Packet Burst" },
    { 19, "Novell Directory Services (NDS)" },
    { 20, "Time Synchronization" },
    { 21, "Server Statistics" },
    { 22, "Remote" },
    { 0,  NULL}
};

static const value_string sss_verb_enum[] = {
    { 0x00000000, "Query Server" },
    { 0x00000001, "Read App Secrets" },
    { 0x00000002, "Write App Secrets" },
    { 0x00000003, "Add Secret ID" },
    { 0x00000004, "Remove Secret ID" },
    { 0x00000005, "Remove SecretStore" },
    { 0x00000006, "Enumerate Secret IDs" },
    { 0x00000007, "Unlock Store" },
    { 0x00000008, "Set Master Password" },
    { 0x00000009, "Get Service Information" },
    { 0x000000ff, "Fragment"},
    { 0x00000000, NULL}
};

static const value_string nmas_subverb_enum[] = {
    { 0, "Fragmented Ping" },
    { 2, "Client Put Data" },
    { 4, "Client Get Data" },
    { 6, "Client Get User NDS Credentials" },
    { 8, "Login Store Management" },
    { 10, "Writable Object Check" },
    { 1242, "Message Handler" },
    { 0,  NULL}
};

static const value_string ncp_nds_verb_vals[] = {
    { 1, "Resolve Name" },
    { 2, "Read Entry Information" },
    { 3, "Read" },
    { 4, "Compare" },
    { 5, "List" },
    { 6, "Search Entries" },
    { 7, "Add Entry" },
    { 8, "Remove Entry" },
    { 9, "Modify Entry" },
    { 10, "Modify RDN" },
    { 11, "Create Attribute" },
    { 12, "Read Attribute Definition" },
    { 13, "Remove Attribute Definition" },
    { 14, "Define Class" },
    { 15, "Read Class Definition" },
    { 16, "Modify Class Definition" },
    { 17, "Remove Class Definition" },
    { 18, "List Containable Classes" },
    { 19, "Get Effective Rights" },
    { 20, "Add Partition" },
    { 21, "Remove Partition" },
    { 22, "List Partitions" },
    { 23, "Split Partition" },
    { 24, "Join Partitions" },
    { 25, "Add Replica" },
    { 26, "Remove Replica" },
    { 27, "Open Stream" },
    { 28, "Search Filter" },
    { 29, "Create Subordinate Reference" },
    { 30, "Link Replica" },
    { 31, "Change Replica Type" },
    { 32, "Start Update Schema" },
    { 33, "End Update Schema" },
    { 34, "Update Schema" },
    { 35, "Start Update Replica" },
    { 36, "End Update Replica" },
    { 37, "Update Replica" },
    { 38, "Synchronize Partition" },
    { 39, "Synchronize Schema" },
    { 40, "Read Syntaxes" },
    { 41, "Get Replica Root ID" },
    { 42, "Begin Move Entry" },
    { 43, "Finish Move Entry" },
    { 44, "Release Moved Entry" },
    { 45, "Backup Entry" },
    { 46, "Restore Entry" },
    { 47, "Save DIB (Obsolete)" },
    { 48, "Control" },
    { 49, "Remove Backlink" },
    { 50, "Close Iteration" },
    { 51, "Mutate Entry" },
    { 52, "Audit Skulking" },
    { 53, "Get Server Address" },
    { 54, "Set Keys" },
    { 55, "Change Password" },
    { 56, "Verify Password" },
    { 57, "Begin Login" },
    { 58, "Finish Login" },
    { 59, "Begin Authentication" },
    { 60, "Finish Authentication" },
    { 61, "Logout" },
    { 62, "Repair Ring (Obsolete)" },
    { 63, "Repair Timestamps" },
    { 64, "Create Back Link" },
    { 65, "Delete External Reference" },
    { 66, "Rename External Reference" },
    { 67, "Create Queue Entry Directory" },
    { 68, "Remove Queue Entry Directory" },
    { 69, "Merge Entries" },
    { 70, "Change Tree Name" },
    { 71, "Partition Entry Count" },
    { 72, "Check Login Restrictions" },
    { 73, "Start Join" },
    { 74, "Low Level Split" },
    { 75, "Low Level Join" },
    { 76, "Abort Partition Operation" },
    { 77, "Get All Servers" },
    { 78, "Partition Function" },
    { 79, "Read References" },
    { 80, "Inspect Entry" },
    { 81, "Get Remote Entry ID" },
    { 82, "Change Security" },
    { 83, "Check Console Operator" },
    { 84, "Start Move Tree" },
    { 85, "Move Tree" },
    { 86, "End Move Tree" },
    { 87, "Low Level Abort Join" },
    { 88, "Check Security Equivalence" },
    { 89, "Merge Tree" },
    { 90, "Sync External Reference" },
    { 91, "Resend Entry" },
    { 92, "New Schema Epoch" },
    { 93, "Statistics" },
    { 94, "Ping" },
    { 95, "Get Bindery Contexts" },
    { 96, "Monitor Connection" },
    { 97, "Get DS Statistics" },
    { 98, "Reset DS Counters" },
    { 99, "Console" },
    { 100, "Read Stream" },
    { 101, "Write Stream" },
    { 102, "Create Orphan Partition" },
    { 103, "Remove Orphan Partition" },
    { 104, "Link Orphan Partition" },
    { 105, "Set Distributed Reference Link (DRL)" },
    { 106, "Available" },
    { 107, "Available" },
    { 108, "Verify Distributed Reference Link (DRL)" },
    { 109, "Verify Partition" },
    { 110, "Iterator" },
    { 111, "Available" },
    { 112, "Close Stream" },
    { 113, "Available" },
    { 114, "Read Status" },
    { 115, "Partition Sync Status" },
    { 116, "Read Reference Data" },
    { 117, "Write Reference Data" },
    { 118, "Resource Event" },
    { 119, "DIB Request (obsolete)" },
    { 120, "Set Replication Filter" },
    { 121, "Get Replication Filter" },
    { 122, "Change Attribute Definition" },
    { 123, "Schema in Use" },
    { 124, "Remove Keys" },
    { 125, "Clone" },
    { 126, "Multiple Operations Transaction" },
    { 240, "Ping" },
    { 255, "EDirectory Call" },
    { 0,  NULL }
};

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
