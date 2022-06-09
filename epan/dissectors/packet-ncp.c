/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified to allow NCP over TCP/IP decodes by James Coe <jammer@cin.net>
 * Modified to decode server op-lock, packet signature,
 * & NDS packets by Greg Morris <gmorris@novell.com>
 *
 * Portions Copyright (c) by Gilbert Ramirez 2000-2002
 * Portions Copyright (c) by James Coe 2000-2002
 * Portions Copyright (c) Novell, Inc. 2000-2003
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* XXX:
   ToDo: Find and fix possible memory leak(s):

   Example:

   A 40M capture file with mostly NCP frames results
   in a 400K-800K memory usage increase each time the file is reloaded.

   (If the NCP dissection is disabled, there is minimal memory usage
   increase each time the file is reloaded).
*/

/*
 * On page 86 of
 *
 *   https://www.novell.com/documentation/developer/smscomp/pdfdoc/sms_docs/sms_docs.pdf
 *
 * it says:
 *
 * The following table lists the wild cards options that can be used in
 * the terminal path node.
 *
 *    Value  Option     Description
 *    0x2A   ASTERISK   Regular asterisk
 *    0x3F   QUESTION   Regular question mark
 *    0xAE   SPERIOD    Special Period-the most significant bit set
 *    0xAA   SASTERISK. Special Asterisk-the most significant bit set.
 *    0xBF   SQUESTION  Special Question-with the most significant bit set.
 *
 * ASTERISK is '*', and QUESTION is '?'; the "special" versions correspond
 * to the corresponding ASCII character, but with the upper bit set.
 *
 * They do not indicate what "special" means here.  During the painful
 * process at NetApp of reverse-engineering SMB server wildcard matching;
 * it turned out that "traditional 8.3 name" matching and "long name"
 * matching behave differently, and there were separate code points for
 * "traditional 8.3 name" wildcards and period and "long name" wildcards
 * and period, so that might be what's involved here.
 *
 * How should we display them?  Show the character in question plus a
 * Unicode COMBINING OVERLINE (U+0305), so they show up as {period,
 * asterisk, question mark} with an overline, for example?
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/srt_table.h>
#include "packet-ipx.h"
#include "packet-tcp.h"
#include "packet-ncp-int.h"
#include <epan/conversation_table.h>

void proto_register_ncp(void);
void proto_reg_handoff_ncp(void);

int proto_ncp = -1;
static int hf_ncp_ip_ver = -1;
static int hf_ncp_ip_length = -1;
static int hf_ncp_ip_rplybufsize = -1;
static int hf_ncp_ip_sig = -1;
static int hf_ncp_ip_packetsig = -1;
static int hf_ncp_type = -1;
static int hf_ncp_seq = -1;
static int hf_ncp_connection = -1;
static int hf_ncp_task = -1;
static int hf_ncp_stream_type = -1;
static int hf_ncp_system_flags = -1;
static int hf_ncp_system_flags_abt = -1;
static int hf_ncp_system_flags_eob = -1;
static int hf_ncp_system_flags_sys = -1;
static int hf_ncp_system_flags_bsy = -1;
static int hf_ncp_system_flags_lst = -1;
static int hf_ncp_src_connection = -1;
static int hf_ncp_dst_connection = -1;
static int hf_ncp_packet_seqno = -1;
static int hf_ncp_delay_time = -1;
static int hf_ncp_burst_seqno = -1;
static int hf_ncp_ack_seqno = -1;
static int hf_ncp_burst_len = -1;
static int hf_ncp_burst_offset = -1;
static int hf_ncp_data_offset = -1;
static int hf_ncp_data_bytes = -1;
static int hf_ncp_missing_fraglist_count = -1;
static int hf_ncp_missing_data_offset = -1;
static int hf_ncp_missing_data_count = -1;
static int hf_ncp_oplock_flag = -1;
static int hf_ncp_oplock_handle = -1;
static int hf_ncp_completion_code = -1;
static int hf_ncp_connection_status = -1;
static int hf_ncp_slot = -1;
static int hf_ncp_signature_character = -1;
/* static int hf_ncp_fragment_handle = -1; */
static int hf_lip_echo_magic = -1;
static int hf_lip_echo_payload = -1;
static int hf_ncp_burst_command = -1;
static int hf_ncp_burst_file_handle = -1;
static int hf_ncp_burst_reserved = -1;

gint ett_ncp = -1;
gint ett_nds = -1;
gint ett_nds_segments = -1;
gint ett_nds_segment = -1;
static gint ett_ncp_system_flags = -1;

static expert_field ei_ncp_oplock_handle = EI_INIT;
static expert_field ei_ncp_new_server_session = EI_INIT;
static expert_field ei_ncp_type = EI_INIT;

static struct novell_tap ncp_tap;
static struct ncp_common_header     header;
static struct ncp_common_header    *ncp_hdr;

dissector_handle_t nds_data_handle;

/* desegmentation of NCP over TCP */
static gboolean ncp_desegment = TRUE;

#define TCP_PORT_NCP            524
#define UDP_PORT_NCP            524

#define NCP_RQST_HDR_LENGTH     7
#define NCP_RPLY_HDR_LENGTH     8

/* These are the header structures to handle NCP over IP */
#define NCPIP_RQST      0x446d6454      /* "DmdT" */
#define NCPIP_RPLY      0x744e6350      /* "tNcP" */

struct ncp_ip_header {
    guint32 signature;
    guint32 length;
};

/* This header only appears on NCP over IP request packets */
struct ncp_ip_rqhdr {
    guint32 version;
    guint32 rplybufsize;
};

static const value_string ncp_sigchar_vals[] = {
	{ '?', "Poll inactive station" },
	{ 'Y', "Station is still using the connection" },
	{ '!', "Broadcast message waiting" },
	{ 0, NULL }
};

static const value_string ncp_ip_signature[] = {
    { NCPIP_RQST, "Demand Transport (Request)" },
    { NCPIP_RPLY, "Transport is NCP (Reply)" },
    { 0, NULL }
};

static const value_string burst_command[] = {
    { 0x01000000, "Burst Read" },
    { 0x02000000, "Burst Write" },
    { 0, NULL }
};

/* The information in this module comes from:
   NetWare LAN Analysis, Second Edition
   Laura A. Chappell and Dan E. Hakes
   (c) 1994 Novell, Inc.
   Novell Press, San Jose.
   ISBN: 0-7821-1362-1

   And from the ncpfs source code by Volker Lendecke

   And:
   Programmer's Guide to the NetWare Core Protocol
   Steve Conner & Diane Conner
   (c) 1996 by Steve Conner & Diane Conner
   Published by Annabooks, San Diego, California
   ISBN: 0-929392-31-0

   And:

   https://www.novell.com/developer/ndk/netware_core_protocols.html

   NCP documentation

   (formerly http:developer.novell.com)

*/

static const value_string ncp_type_vals[] = {
    { NCP_ALLOCATE_SLOT,    "Create a service connection" },
    { NCP_SERVICE_REQUEST,  "Service request" },
    { NCP_SERVICE_REPLY,    "Service reply" },
    { NCP_WATCHDOG,         "Watchdog" },
    { NCP_DEALLOCATE_SLOT,  "Destroy service connection" },
    { NCP_BROADCAST_SLOT,   "Server Broadcast" },
    { NCP_BURST_MODE_XFER,  "Burst mode transfer" },
    { NCP_POSITIVE_ACK,     "Request being processed" },
    { NCP_LIP_ECHO,         "Large Internet Packet Echo" },
    { 0,                    NULL }
};

static const value_string ncp_oplock_vals[] = {
    { 0x21, "Message Waiting" },
    { 0x24, "Clear Op-lock" },
    { 0, NULL }
};

enum ncp_table_values
{
    NCP_NCP_SRT_TABLE_INDEX = 0,
    NCP_NDS_SRT_TABLE_INDEX,
    NCP_FUNC_SRT_TABLE_INDEX,
    NCP_SSS_SRT_TABLE_INDEX,
    NCP_NMAS_SRT_TABLE_INDEX,
    NCP_SUB17_SRT_TABLE_INDEX,
    NCP_SUB21_SRT_TABLE_INDEX,
    NCP_SUB22_SRT_TABLE_INDEX,
    NCP_SUB23_SRT_TABLE_INDEX,
    NCP_SUB32_SRT_TABLE_INDEX,
    NCP_SUB34_SRT_TABLE_INDEX,
    NCP_SUB35_SRT_TABLE_INDEX,
    NCP_SUB36_SRT_TABLE_INDEX,
    NCP_SUB86_SRT_TABLE_INDEX,
    NCP_SUB87_SRT_TABLE_INDEX,
    NCP_SUB89_SRT_TABLE_INDEX,
    NCP_SUB90_SRT_TABLE_INDEX,
    NCP_SUB92_SRT_TABLE_INDEX,
    NCP_SUB94_SRT_TABLE_INDEX,
    NCP_SUB104_SRT_TABLE_INDEX,
    NCP_SUB111_SRT_TABLE_INDEX,
    NCP_SUB114_SRT_TABLE_INDEX,
    NCP_SUB123_SRT_TABLE_INDEX,
    NCP_SUB131_SRT_TABLE_INDEX

};

#define NCP_NUM_PROCEDURES     0

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

WS_DLL_PUBLIC_DEF const value_string sss_verb_enum[] = {
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

WS_DLL_PUBLIC_DEF const value_string nmas_subverb_enum[] = {
    { 0, "Fragmented Ping" },
    { 2, "Client Put Data" },
    { 4, "Client Get Data" },
    { 6, "Client Get User NDS Credentials" },
    { 8, "Login Store Management" },
    { 10, "Writable Object Check" },
    { 1242, "Message Handler" },
    { 0,  NULL}
};

WS_DLL_PUBLIC_DEF const value_string ncp_nds_verb_vals[] = {
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

static void
ncpstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
    /* Initialize all of the SRT tables with 0 rows.  That way we can "filter" the drawing
       function to only output tables with rows > 0 */

    init_srt_table("NCP", "Groups", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.group", NULL);

    /* NDS Verbs */
    init_srt_table("NDS Verbs", "NDS", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.ndsverb", NULL);

    /* NCP Functions */
    init_srt_table("NCP Functions without Subfunctions", "Functions", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func", NULL);

    /* Secret Store Verbs */
    init_srt_table("Secret Store Verbs", "SSS", srt_array, NCP_NUM_PROCEDURES, NULL, "sss.subverb", NULL);

    /* NMAS Verbs */
    init_srt_table("NMAS Verbs", "NMAS", srt_array, NCP_NUM_PROCEDURES, NULL, "nmas.subverb", NULL);

    /* NCP Subfunctions */
    init_srt_table("Subfunctions for NCP 17", "17", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==17 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 21", "21", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==21 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 22", "22", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==22 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 23", "23", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==23 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 32", "32", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==32 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 34", "34", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==34 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 35", "35", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==35 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 36", "36", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==36 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 86", "86", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==86 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 87", "87", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==87 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 89 (Extended NCP's with UTF8 Support)", "89", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==89 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 90", "90", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==90 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 92 (Secret Store Services)", "92", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==92 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 94 (Novell Modular Authentication Services)", "94", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==94 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 104", "104", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==104 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 111", "111", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==111 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 114", "114", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==114 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 123", "123", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==123 && ncp.subfunc", NULL);
    init_srt_table("Subfunctions for NCP 131", "131", srt_array, NCP_NUM_PROCEDURES, NULL, "ncp.func==131 && ncp.subfunc", NULL);
}

static tap_packet_status
ncpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
    guint i = 0;
    srt_stat_table *ncp_srt_table;
    srt_data_t *data = (srt_data_t *)pss;
    const ncp_req_hash_value *request_val=(const ncp_req_hash_value *)prv;
    gchar* tmp_str;

    /* if we haven't seen the request, just ignore it */
    if(!request_val || request_val->ncp_rec==0){
        return TAP_PACKET_DONT_REDRAW;
    }

    /* By Group */
    tmp_str = val_to_str_wmem(NULL, request_val->ncp_rec->group, ncp_group_vals, "Unknown(%u)");
    i = NCP_NCP_SRT_TABLE_INDEX;
    ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
    init_srt_table_row(ncp_srt_table, request_val->ncp_rec->group, tmp_str);
    wmem_free(NULL, tmp_str);
    add_srt_table_data(ncp_srt_table, request_val->ncp_rec->group, &request_val->req_frame_time, pinfo);
    /* By NCP number without subfunction*/
    if (request_val->ncp_rec->subfunc==0) {
        i = NCP_FUNC_SRT_TABLE_INDEX;
        ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
        init_srt_table_row(ncp_srt_table, request_val->ncp_rec->func, request_val->ncp_rec->name);
        add_srt_table_data(ncp_srt_table, request_val->ncp_rec->func, &request_val->req_frame_time, pinfo);
    }
    /* By Subfunction number */
    if(request_val->ncp_rec->subfunc!=0){
        if (request_val->ncp_rec->func==17) {
            i = NCP_SUB17_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==21) {
            i = NCP_SUB21_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==22) {
            i = NCP_SUB22_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==23) {
            i = NCP_SUB23_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==32) {
            i = NCP_SUB32_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==34) {
            i = NCP_SUB34_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==35) {
            i = NCP_SUB35_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==36) {
            i = NCP_SUB36_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==86) {
            i = NCP_SUB86_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==87) {
            i = NCP_SUB87_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==89) {
            i = NCP_SUB89_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==90) {
            i = NCP_SUB90_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==92) {
            i = NCP_SUB92_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==94) {
            i = NCP_SUB94_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==104) {
            i = NCP_SUB104_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==111) {
            i = NCP_SUB111_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==114) {
            i = NCP_SUB114_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==123) {
            i = NCP_SUB123_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==131) {
            i = NCP_SUB131_SRT_TABLE_INDEX;
            ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
            init_srt_table_row(ncp_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(ncp_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
    }
    /* By NDS verb */
    if (request_val->ncp_rec->func==0x68) {
        tmp_str = val_to_str_wmem(NULL, request_val->nds_request_verb, ncp_nds_verb_vals, "Unknown(%u)");
        i = NCP_NDS_SRT_TABLE_INDEX;
        ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
        init_srt_table_row(ncp_srt_table, (request_val->nds_request_verb), tmp_str);
        add_srt_table_data(ncp_srt_table, (request_val->nds_request_verb), &request_val->req_frame_time, pinfo);
        wmem_free(NULL, tmp_str);
    }
    if (request_val->ncp_rec->func==0x5c) {
        tmp_str = val_to_str_wmem(NULL, request_val->req_nds_flags, sss_verb_enum, "Unknown(%u)");
        i = NCP_SSS_SRT_TABLE_INDEX;
        ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
        init_srt_table_row(ncp_srt_table, (request_val->req_nds_flags), tmp_str);
        add_srt_table_data(ncp_srt_table, (request_val->req_nds_flags), &request_val->req_frame_time, pinfo);
        wmem_free(NULL, tmp_str);
    }
    if (request_val->ncp_rec->func==0x5e) {
        tmp_str = val_to_str_wmem(NULL, request_val->req_nds_flags, nmas_subverb_enum, "Unknown(%u)");
        i = NCP_NMAS_SRT_TABLE_INDEX;
        ncp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
        init_srt_table_row(ncp_srt_table, (request_val->req_nds_flags), tmp_str);
        add_srt_table_data(ncp_srt_table, (request_val->req_nds_flags), &request_val->req_frame_time, pinfo);
        wmem_free(NULL, tmp_str);
    }
    return TAP_PACKET_REDRAW;
}


/* Conversation Struct so we can detect NCP server sessions */

typedef struct {
    conversation_t *conversation;
    guint32         nwconnection;
    guint8          nwtask;
} mncp_rhash_key;

/* Store the packet number for the start of the NCP session.
 * Note sessions are defined as
 * NCP Connection + NCP Task == Unique NCP server session
 * It is normal for multiple sessions per connection to exist
 * These are normally different applications running on multi-tasking
 * Operating Systems.
 */
typedef struct {
    guint32  session_start_packet_num;
} mncp_rhash_value;

static GHashTable *mncp_rhash = NULL;

/* Hash Functions */
static gint
mncp_equal(gconstpointer v, gconstpointer v2)
{
    const mncp_rhash_key *val1 = (const mncp_rhash_key*)v;
    const mncp_rhash_key *val2 = (const mncp_rhash_key*)v2;

    if (val1->conversation == val2->conversation && val1->nwconnection == val2->nwconnection && val1->nwtask == val2->nwtask) {
        return 1;
    }
    return 0;
}

static guint
mncp_hash(gconstpointer v)
{
    const mncp_rhash_key *mncp_key = (const mncp_rhash_key*)v;
    return GPOINTER_TO_UINT(mncp_key->conversation)+mncp_key->nwconnection+mncp_key->nwtask;
}

/* Initializes the hash table each time a new
 * file is loaded or re-loaded in wireshark */
static void
mncp_init_protocol(void)
{
    mncp_rhash = g_hash_table_new(mncp_hash, mncp_equal);
}

static void
mncp_cleanup_protocol(void)
{
    g_hash_table_destroy(mncp_rhash);
}

static mncp_rhash_value*
mncp_hash_insert(conversation_t *conversation, guint32 nwconnection, guint8 nwtask, packet_info *pinfo)
{
    mncp_rhash_key      *key;
    mncp_rhash_value    *value;

    /* Now remember the request, so we can find it if we later
       a reply to it. Track by conversation, connection, and task number.
       in NetWare these values determine each unique session */
    key = wmem_new(wmem_file_scope(), mncp_rhash_key);
    key->conversation = conversation;
    key->nwconnection = nwconnection;
    key->nwtask = nwtask;

    value = wmem_new(wmem_file_scope(), mncp_rhash_value);

    g_hash_table_insert(mncp_rhash, key, value);

    if (ncp_echo_conn && nwconnection != 65535) {
        expert_add_info_format(pinfo, NULL, &ei_ncp_new_server_session, "Detected New Server Session. Connection %d, Task %d", nwconnection, nwtask);
        value->session_start_packet_num = pinfo->num;
    }

    return value;
}

/* Returns the ncp_rec*, or NULL if not found. */
static mncp_rhash_value*
mncp_hash_lookup(conversation_t *conversation, guint32 nwconnection, guint8 nwtask)
{
    mncp_rhash_key        key;

    key.conversation = conversation;
    key.nwconnection = nwconnection;
    key.nwtask = nwtask;

    return (mncp_rhash_value *)g_hash_table_lookup(mncp_rhash, &key);
}

static const char* ncp_conv_get_filter_type(conv_item_t* conv _U_, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_PORT) || (filter == CONV_FT_DST_PORT) || (filter == CONV_FT_ANY_PORT))
        return "ncp.connection";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ncp_ct_dissector_info = {&ncp_conv_get_filter_type};

static tap_packet_status
ncp_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const struct ncp_common_header *ncph=(const struct ncp_common_header *)vip;
    guint32 connection;

    connection = (ncph->conn_high * 256)+ncph->conn_low;
    if (connection < 65535) {
        add_conversation_table_data(hash, &pinfo->src, &pinfo->dst, connection, connection, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &ncp_ct_dissector_info, ENDPOINT_NCP);
    }

    return TAP_PACKET_REDRAW;
}

static const char* ncp_host_get_filter_type(hostlist_talker_t* host _U_, conv_filter_type_e filter)
{
    return ncp_conv_get_filter_type(NULL, filter);
}

static hostlist_dissector_info_t ncp_host_dissector_info = {&ncp_host_get_filter_type};

static tap_packet_status
ncp_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    /*const ncp_common_header *ncphdr=vip;*/

    /* Take two "add" passes per packet, adding for each direction, ensures that all
    packets are counted properly (even if address is sending to itself)
    XXX - this could probably be done more efficiently inside hostlist_table */
    add_hostlist_table_data(hash, &pinfo->src, 0, TRUE, 1, pinfo->fd->pkt_len, &ncp_host_dissector_info, ENDPOINT_NCP);
    add_hostlist_table_data(hash, &pinfo->dst, 0, FALSE, 1, pinfo->fd->pkt_len, &ncp_host_dissector_info, ENDPOINT_NCP);

    return TAP_PACKET_REDRAW;
}

/*
 * Burst packet system flags.
 */
#define ABT 0x04        /* Abort request */
#define BSY 0x08        /* Server Busy */
#define EOB 0x10        /* End of burst */
#define LST 0x40        /* Include Fragment List */
#define SYS 0x80        /* System packet */

#define LIP_ECHO_MAGIC_LEN 16
static char lip_echo_magic[LIP_ECHO_MAGIC_LEN] = {
    'L', 'I', 'P', ' ', 'E', 'c', 'h', 'o', ' ', 'D', 'a', 't', 'a', ' ', ' ', ' '
};

static void
dissect_ncp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_tcp)
{
    proto_tree            *ncp_tree = NULL;
    proto_item            *ti;
    struct ncp_ip_header  ncpiph;
    struct ncp_ip_rqhdr   ncpiphrq;
    gboolean              is_lip_echo_allocate_slot = FALSE;
    guint16               ncp_burst_seqno, ncp_ack_seqno;
    guint16               flags = 0;
    proto_tree            *flags_tree = NULL;
    int                   hdr_offset = 0;
    int                   commhdr = 0;
    int                   offset = 0;
    gint                  length_remaining;
    tvbuff_t              *next_tvb;
    guint32               ncp_burst_command, burst_len, burst_off, burst_file;
    guint8                subfunction;
    guint32               nw_connection = 0, data_offset;
    guint16               data_len = 0;
    guint16               missing_fraglist_count = 0;
    mncp_rhash_value      *request_value = NULL;
    conversation_t        *conversation;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCP");
    col_clear(pinfo->cinfo, COL_INFO);

    ncp_hdr = &header;

    ti = proto_tree_add_item(tree, proto_ncp, tvb, 0, -1, ENC_NA);
    ncp_tree = proto_item_add_subtree(ti, ett_ncp);
    if (is_tcp) {
        if (tvb_get_ntohl(tvb, hdr_offset) != NCPIP_RQST && tvb_get_ntohl(tvb, hdr_offset) != NCPIP_RPLY)
            commhdr += 1;
        /* Get NCPIP Header data */
        ncpiph.signature = tvb_get_ntohl(tvb, commhdr);
        proto_tree_add_uint(ncp_tree, hf_ncp_ip_sig, tvb, commhdr, 4, ncpiph.signature);
        ncpiph.length = (0x7fffffff & tvb_get_ntohl(tvb, commhdr+4));
        proto_tree_add_uint(ncp_tree, hf_ncp_ip_length, tvb, commhdr+4, 4, ncpiph.length);
        commhdr += 8;
        if (ncpiph.signature == NCPIP_RQST) {
            ncpiphrq.version = tvb_get_ntohl(tvb, commhdr);
            proto_tree_add_uint(ncp_tree, hf_ncp_ip_ver, tvb, commhdr, 4, ncpiphrq.version);
            commhdr += 4;
            ncpiphrq.rplybufsize = tvb_get_ntohl(tvb, commhdr);
            proto_tree_add_uint(ncp_tree, hf_ncp_ip_rplybufsize, tvb, commhdr, 4, ncpiphrq.rplybufsize);
            commhdr += 4;
        }
        /* Check to see if this is a valid offset, otherwise increment for packet signature */
        if (try_val_to_str(tvb_get_ntohs(tvb, commhdr), ncp_type_vals)==NULL) {
            /* Check to see if we have a valid type after packet signature length */
            if (try_val_to_str(tvb_get_ntohs(tvb, commhdr+8), ncp_type_vals)!=NULL) {
                proto_tree_add_item(ncp_tree, hf_ncp_ip_packetsig, tvb, commhdr, 8, ENC_NA);
                commhdr += 8;
            }
        }
    } else {
        /* Initialize this structure, we use it below */
        memset(&ncpiph, 0, sizeof(ncpiph));
    }

    header.type         = tvb_get_ntohs(tvb, commhdr);
    header.sequence     = tvb_get_guint8(tvb, commhdr+2);
    header.conn_low     = tvb_get_guint8(tvb, commhdr+3);
    header.task         = tvb_get_guint8(tvb, commhdr+4);
    header.conn_high    = tvb_get_guint8(tvb, commhdr+5);
    proto_tree_add_uint(ncp_tree, hf_ncp_type, tvb, commhdr, 2, header.type);
    nw_connection = (header.conn_high*256)+header.conn_low;

    /* Ok, we need to track the conversation so that we can
     * determine if a new server session is occurring for this
     * connection.
     */
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
        ENDPOINT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->destport,
        0);
    if ((ncpiph.length & 0x80000000) || ncpiph.signature == NCPIP_RPLY) {
        /* First time through we will record the initial connection and task
         * values
         */
        if (!pinfo->fd->visited) {
            if (conversation != NULL) {
                /* find the record telling us the
                 * request made that caused this
                 * reply
                 */
                request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
                /* if for some reason we have no
                 * conversation in our hash, create
                 * one */
                if (request_value == NULL) {
                    mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
                }
            } else {
                /* It's not part of any conversation
                 * - create a new one.
                 */
                conversation = conversation_new(pinfo->num, &pinfo->src,
                    &pinfo->dst, ENDPOINT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->destport, 0);
                mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
            }
            /* If this is a request packet then we
             * might have a new task
             */
            if (ncpiph.signature == NCPIP_RPLY) {
                /* Now on reply packets we have to
                 * use the state of the original
                 * request packet, so look up the
                 * request value and check the task number
                 */
                /*request_value = mncp_hash_lookup(conversation, nw_connection, header.task);*/
            }
        } else {
            /* Get request value data */
            request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
            if (request_value) {
                if ((request_value->session_start_packet_num == pinfo->num) && ncp_echo_conn) {
                    expert_add_info_format(pinfo, NULL, &ei_ncp_new_server_session, "Detected New Server Session. Connection %d, Task %d", nw_connection, header.task);
                }
            }
        }
    } else {
        if (!pinfo->fd->visited) {
            if (conversation != NULL) {
                /* find the record telling us the
                 * request made that caused this
                 * reply
                 */
                request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
                /* if for some reason we have no
                 * conversation in our hash, create
                 * one */
                if (request_value == NULL) {
                    mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
                }
            } else {
                /* It's not part of any conversation
                 * - create a new one.
                 */
                conversation = conversation_new(pinfo->num, &pinfo->src,
                    &pinfo->dst, ENDPOINT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->destport, 0);
                mncp_hash_insert(conversation, nw_connection, header.task, pinfo);
            }
            /* find the record telling us the request
             * made that caused this reply
             */
        } else {
            request_value = mncp_hash_lookup(conversation, nw_connection, header.task);
            if (request_value) {
                if ((request_value->session_start_packet_num == pinfo->num) && ncp_echo_conn) {
                    expert_add_info_format(pinfo, NULL, &ei_ncp_new_server_session, "Detected New Server Session. Connection %d, Task %d", nw_connection, header.task);
                }
            }
        }
    }

    tap_queue_packet(ncp_tap.hdr, pinfo, ncp_hdr);

    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(header.type, ncp_type_vals, "Unknown type (0x%04x)"));

    /*
     * Process the packet-type-specific header.
     */
    switch (header.type) {

    case NCP_BROADCAST_SLOT:    /* Server Broadcast */
        proto_tree_add_uint(ncp_tree, hf_ncp_seq, tvb, commhdr + 2, 1, header.sequence);
        proto_tree_add_uint(ncp_tree, hf_ncp_connection,tvb, commhdr + 3, 3, nw_connection);
        proto_tree_add_item(ncp_tree, hf_ncp_task, tvb, commhdr + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_oplock_flag, tvb, commhdr + 9, 1, tvb_get_guint8(tvb, commhdr+9));
        proto_tree_add_item(ncp_tree, hf_ncp_oplock_handle, tvb, commhdr + 10, 4, ENC_BIG_ENDIAN);
        if ((tvb_get_guint8(tvb, commhdr+9)==0x24) && ncp_echo_file) {
            expert_add_info_format(pinfo, NULL, &ei_ncp_oplock_handle, "Server requesting station to clear oplock on handle - %08x", tvb_get_ntohl(tvb, commhdr+10));
        }
        break;

    case NCP_LIP_ECHO:    /* Lip Echo Packet */
        /* Unlike the ones with a packet type of 0x1111, in this one, the
           packet type field is the first two bytes of "Lip Echo Data"
           (with "Lip" not capitalized, and with "Echo Data" not followed
           by blanks) */
        proto_tree_add_item(ncp_tree, hf_lip_echo_magic, tvb, commhdr, 13, ENC_ASCII);
        break;

    case NCP_BURST_MODE_XFER:    /* Packet Burst Packet */
        /*
         * XXX - we should keep track of whether there's a burst
         * outstanding on a connection and, if not, treat the
         * beginning of the data as a burst header.
         *
         * The burst header contains:
         *
         *    4 bytes of little-endian function number:
         *        1 = read, 2 = write;
         *
         *    4 bytes of file handle;
         *
         *    8 reserved bytes;
         *
         *    4 bytes of big-endian file offset;
         *
         *    4 bytes of big-endian byte count.
         *
         * The data follows for a burst write operation.
         *
         * The first packet of a burst read reply contains:
         *
         *    4 bytes of little-endian result code:
         *       0: No error
         *       1: Initial error
         *       2: I/O error
         *       3: No data read;
         *
         *    4 bytes of returned byte count (big-endian?).
         *
         * The data follows.
         *
         * Each burst of a write request is responded to with a
         * burst packet with a 2-byte little-endian result code:
         *
         *    0: Write successful
         *    4: Write error
         */
        flags = tvb_get_guint8(tvb, commhdr + 2);

        ti = proto_tree_add_uint(ncp_tree, hf_ncp_system_flags,
            tvb, commhdr + 2, 1, flags);
        flags_tree = proto_item_add_subtree(ti, ett_ncp_system_flags);

        proto_tree_add_item(flags_tree, hf_ncp_system_flags_abt,
            tvb, commhdr + 2, 1, ENC_BIG_ENDIAN);
        if (flags & ABT) {
            proto_item_append_text(ti, "  ABT");
        }
        flags&=(~( ABT ));

        proto_tree_add_item(flags_tree, hf_ncp_system_flags_bsy,
            tvb, commhdr + 2, 1, ENC_BIG_ENDIAN);
        if (flags & BSY) {
            proto_item_append_text(ti, "  BSY");
        }
        flags&=(~( BSY ));

        proto_tree_add_item(flags_tree, hf_ncp_system_flags_eob,
            tvb, commhdr + 2, 1, ENC_BIG_ENDIAN);
        if (flags & EOB) {
            proto_item_append_text(ti, "  EOB");
        }
        flags&=(~( EOB ));

        proto_tree_add_item(flags_tree, hf_ncp_system_flags_lst,
            tvb, commhdr + 2, 1, ENC_BIG_ENDIAN);
        if (flags & LST) {
            proto_item_append_text(ti, "  LST");
        }
        flags&=(~( LST ));

        proto_tree_add_item(flags_tree, hf_ncp_system_flags_sys,
            tvb, commhdr + 2, 1, ENC_BIG_ENDIAN);
        if (flags & SYS) {
            proto_item_append_text(ti, "  SYS");
        }
        flags&=(~( SYS ));


        proto_tree_add_item(ncp_tree, hf_ncp_stream_type,
            tvb, commhdr + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_src_connection,
            tvb, commhdr + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_dst_connection,
            tvb, commhdr + 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_packet_seqno,
            tvb, commhdr + 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_delay_time,
            tvb, commhdr + 16, 4, ENC_BIG_ENDIAN);
        ncp_burst_seqno = tvb_get_ntohs(tvb, commhdr+20);
        proto_tree_add_item(ncp_tree, hf_ncp_burst_seqno,
            tvb, commhdr + 20, 2, ENC_BIG_ENDIAN);
        ncp_ack_seqno = tvb_get_ntohs(tvb, commhdr+22);
        proto_tree_add_item(ncp_tree, hf_ncp_ack_seqno,
            tvb, commhdr + 22, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_burst_len,
            tvb, commhdr + 24, 4, ENC_BIG_ENDIAN);
        data_offset = tvb_get_ntohl(tvb, commhdr + 28);
        proto_tree_add_uint(ncp_tree, hf_ncp_data_offset,
            tvb, commhdr + 28, 4, data_offset);
        data_len = tvb_get_ntohs(tvb, commhdr + 32);
        proto_tree_add_uint(ncp_tree, hf_ncp_data_bytes,
            tvb, commhdr + 32, 2, data_len);
        missing_fraglist_count = tvb_get_ntohs(tvb, commhdr + 34);
        proto_tree_add_item(ncp_tree, hf_ncp_missing_fraglist_count,
            tvb, commhdr + 34, 2, ENC_BIG_ENDIAN);
        offset = commhdr + 36;
        if (!(flags & SYS) && ncp_burst_seqno == ncp_ack_seqno &&
            data_offset == 0) {
            /*
             * This is either a Burst Read or Burst Write
             * command.  The data length includes the burst
             * mode header, plus any data in the command
             * (there shouldn't be any in a read, but there
             * might be some in a write).
             */
            if (data_len < 4)
                return;
            ncp_burst_command = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(ncp_tree, hf_ncp_burst_command,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            data_len -= 4;

            if (data_len < 4)
                return;
            burst_file = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(ncp_tree, hf_ncp_burst_file_handle,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            data_len -= 4;

            if (data_len < 8)
                return;
            proto_tree_add_item(ncp_tree, hf_ncp_burst_reserved,
                tvb, offset, 8, ENC_NA);
            offset += 8;
            data_len -= 8;

            if (data_len < 4)
                return;
            burst_off = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(ncp_tree, hf_ncp_burst_offset,
                tvb, offset, 4, burst_off);
            offset += 4;
            data_len -= 4;

            if (data_len < 4)
                return;
            burst_len = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(ncp_tree, hf_ncp_burst_len,
                tvb, offset, 4, burst_len);
            offset += 4;
            data_len -= 4;

            col_add_fstr(pinfo->cinfo, COL_INFO,
                "%s %d bytes starting at offset %d in file 0x%08x",
                val_to_str(ncp_burst_command,
                    burst_command, "Unknown (0x%08x)"),
                    burst_len, burst_off, burst_file);
            break;
        } else {
            if (tvb_get_guint8(tvb, commhdr + 2) & 0x10) {
                col_set_str(pinfo->cinfo, COL_INFO, "End of Burst");
            }
        }
        break;

    case NCP_ALLOCATE_SLOT:        /* Allocate Slot Request */
        length_remaining = tvb_reported_length_remaining(tvb, commhdr + 4);
        if (length_remaining >= LIP_ECHO_MAGIC_LEN &&
            tvb_memeql(tvb, commhdr+4, lip_echo_magic, LIP_ECHO_MAGIC_LEN) == 0) {
            /* This is a LIP Echo. */
            is_lip_echo_allocate_slot = TRUE;
            col_set_str(pinfo->cinfo, COL_INFO, "LIP Echo");
        }
        /* fall through */

    case NCP_POSITIVE_ACK:        /* Positive Acknowledgement */
    case NCP_SERVICE_REQUEST:    /* Server NCP Request */
    case NCP_SERVICE_REPLY:        /* Server NCP Reply */
    case NCP_WATCHDOG:        /* Watchdog Packet */
    case NCP_DEALLOCATE_SLOT:    /* Deallocate Slot Request */
    default:
        proto_tree_add_uint(ncp_tree, hf_ncp_seq, tvb, commhdr + 2, 1, header.sequence);
        /* XXX - what's at commhdr + 3 in a LIP Echo packet?
           commhdr + 4 on is the LIP echo magic number and data. */
        if (!is_lip_echo_allocate_slot) {
            proto_tree_add_uint(ncp_tree, hf_ncp_connection,tvb, commhdr + 3, 3, nw_connection);
            proto_tree_add_item(ncp_tree, hf_ncp_task, tvb, commhdr + 4, 1, ENC_BIG_ENDIAN);
        }
        break;
    }

    /*
     * Process the packet body.
     */
    switch (header.type) {

    case NCP_ALLOCATE_SLOT:        /* Allocate Slot Request */
        if (is_lip_echo_allocate_slot) {
            length_remaining = tvb_reported_length_remaining(tvb, commhdr + 4);
            proto_tree_add_item(ncp_tree, hf_lip_echo_magic, tvb, commhdr + 4, LIP_ECHO_MAGIC_LEN, ENC_ASCII);
            if (length_remaining > LIP_ECHO_MAGIC_LEN)
                proto_tree_add_item(ncp_tree, hf_lip_echo_payload, tvb, commhdr+4+LIP_ECHO_MAGIC_LEN, length_remaining - LIP_ECHO_MAGIC_LEN, ENC_NA);
        }
        next_tvb = tvb_new_subset_remaining(tvb, commhdr);
        dissect_ncp_request(next_tvb, pinfo, nw_connection,
            header.sequence, header.type, is_lip_echo_allocate_slot, ncp_tree);
        break;

    case NCP_DEALLOCATE_SLOT:    /* Deallocate Slot Request */
        next_tvb = tvb_new_subset_remaining(tvb, commhdr);
        dissect_ncp_request(next_tvb, pinfo, nw_connection,
            header.sequence, header.type, FALSE, ncp_tree);
        break;

    case NCP_SERVICE_REQUEST:    /* Server NCP Request */
    case NCP_BROADCAST_SLOT:    /* Server Broadcast Packet */
        next_tvb = tvb_new_subset_remaining(tvb, commhdr);
        if (tvb_get_guint8(tvb, commhdr+6) == 0x68) {
            subfunction = tvb_get_guint8(tvb, commhdr+7);
            switch (subfunction) {

            case 0x02:    /* NDS Frag Packet to decode */
                dissect_nds_request(next_tvb, pinfo,
                    nw_connection, header.sequence,
                    header.type, ncp_tree);
                break;

            case 0x01:    /* NDS Ping */
                dissect_ping_req(next_tvb, pinfo,
                    nw_connection, header.sequence,
                    header.type, ncp_tree);
                break;

            default:
                dissect_ncp_request(next_tvb, pinfo,
                    nw_connection, header.sequence,
                    header.type, FALSE, ncp_tree);
                break;
             }
        } else {
            dissect_ncp_request(next_tvb, pinfo, nw_connection,
                header.sequence, header.type, FALSE, ncp_tree);
        }
        break;

    case NCP_SERVICE_REPLY:        /* Server NCP Reply */
        next_tvb = tvb_new_subset_remaining(tvb, commhdr);
        nds_defrag(next_tvb, pinfo, nw_connection, header.sequence,
            header.type, ncp_tree, &ncp_tap);
        break;

    case NCP_POSITIVE_ACK:        /* Positive Acknowledgement */
        /*
         * XXX - this used to call "nds_defrag()", which would
         * clear out "frags".  Was that the right thing to
         * do?
         */
        next_tvb = tvb_new_subset_remaining(tvb, commhdr);
        dissect_ncp_reply(next_tvb, pinfo, nw_connection,
            header.sequence, header.type, ncp_tree, &ncp_tap);
        break;

    case NCP_WATCHDOG:        /* Watchdog Packet */
        /*
         * XXX - should the completion code be interpreted as
         * it is in "packet-ncp2222.inc"?  If so, this
         * packet should be handled by "dissect_ncp_reply()".
         */
        proto_tree_add_item(ncp_tree, hf_ncp_completion_code,
            tvb, commhdr + 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_connection_status,
            tvb, commhdr + 7, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_slot,
            tvb, commhdr + 8, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_ncp_signature_character,
            tvb, commhdr + 9, 1, ENC_LITTLE_ENDIAN);
        /*
         * Display the rest of the packet as data.
         */
        if (tvb_offset_exists(tvb, commhdr + 10)) {
            call_data_dissector(tvb_new_subset_remaining(tvb, commhdr + 10),
                pinfo, ncp_tree);
        }
        break;

    case NCP_BURST_MODE_XFER:    /* Packet Burst Packet */
        if (flags & SYS) {
            /*
             * System packet; show missing fragments if there
             * are any.
             */
            while (missing_fraglist_count != 0) {
                proto_tree_add_item(ncp_tree, hf_ncp_missing_data_offset,
                    tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(ncp_tree, hf_ncp_missing_data_count,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                missing_fraglist_count--;
            }
        } else {
            /*
             * XXX - do this by using -1 and -1 as the length
             * arguments to "tvb_new_subset_length_caplen()" and then calling
             * "tvb_set_reported_length()"?  That'll throw an
             * exception if "data_len" goes past the reported
             * length of the packet, but that's arguably a
             * feature in this case.
             */
            length_remaining = tvb_captured_length_remaining(tvb, offset);
            if (length_remaining > data_len)
                length_remaining = data_len;
            if (data_len != 0) {
                call_data_dissector(tvb_new_subset_length_caplen(tvb, offset,
                    length_remaining, data_len),
                    pinfo, ncp_tree);
            }
        }
        break;

    case NCP_LIP_ECHO:        /* LIP Echo Packet */
        proto_tree_add_item(ncp_tree, hf_lip_echo_payload, tvb, commhdr + 13, -1, ENC_NA);
        break;

    default:
        proto_tree_add_expert_format(ncp_tree, pinfo, &ei_ncp_type, tvb, commhdr + 6, -1,
            "%s packets not supported yet",
            val_to_str(header.type, ncp_type_vals,
                "Unknown type (0x%04x)"));
        break;
    }
}

static int
dissect_ncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_ncp_common(tvb, pinfo, tree, FALSE);
    return tvb_captured_length(tvb);
}

static guint
get_ncp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint32 signature;

    /*
     * Check the NCP-over-TCP header signature, to make sure it's there.
     * If it's not there, we cannot trust the next 4 bytes to be a
     * packet length+"has signature" flag, so we just say the length is
     * "what remains in the packet".
     */
    signature = tvb_get_ntohl(tvb, offset);
    if (signature != NCPIP_RQST && signature != NCPIP_RPLY)
        return tvb_captured_length_remaining(tvb, offset);

    /*
     * Get the length of the NCP-over-TCP packet.  Strip off the "has
     * signature" flag.
     */

    return tvb_get_ntohl(tvb, offset + 4) & 0x7fffffff;
}

static int
dissect_ncp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_ncp_common(tvb, pinfo, tree, TRUE);
    return tvb_captured_length(tvb);
}

static int
dissect_ncp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, ncp_desegment, 8, get_ncp_pdu_len,
                     dissect_ncp_tcp_pdu, data);
    return tvb_captured_length(tvb);
}

void
proto_register_ncp(void)
{
    static hf_register_info hf[] = {
        { &hf_ncp_ip_sig,
          { "NCP over IP signature",            "ncp.ip.signature",
            FT_UINT32, BASE_HEX, VALS(ncp_ip_signature), 0x0,
            NULL, HFILL }},
        { &hf_ncp_ip_length,
          { "NCP over IP length",               "ncp.ip.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_ip_ver,
          { "NCP over IP Version",              "ncp.ip.version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_ip_rplybufsize,
          { "NCP over IP Reply Buffer Size",    "ncp.ip.replybufsize",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_ip_packetsig,
          { "NCP over IP Packet Signature",     "ncp.ip.packetsig",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_type,
          { "Type",                             "ncp.type",
            FT_UINT16, BASE_HEX, VALS(ncp_type_vals), 0x0,
            "NCP message type", HFILL }},
        { &hf_ncp_seq,
          { "Sequence Number",                  "ncp.seq",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_connection,
          { "Connection Number",                "ncp.connection",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_task,
          { "Task Number",                      "ncp.task",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_oplock_flag,
          { "Broadcast Message Flag",           "ncp.msg_flag",
            FT_UINT8, BASE_HEX, VALS(ncp_oplock_vals), 0x0,
            NULL, HFILL }},
        { &hf_ncp_oplock_handle,
          { "File Handle",                      "ncp.oplock_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_stream_type,
          { "Stream Type",                      "ncp.stream_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Type of burst", HFILL }},
        { &hf_ncp_system_flags,
          { "System Flags",                     "ncp.system_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_system_flags_abt,
          { "ABT",                              "ncp.system_flags.abt",
            FT_BOOLEAN, 8, NULL, ABT,
            "Is this an abort request?", HFILL }},
        { &hf_ncp_system_flags_eob,
          { "EOB",                              "ncp.system_flags.eob",
            FT_BOOLEAN, 8, NULL, EOB,
            "Is this the last packet of the burst?", HFILL }},
        { &hf_ncp_system_flags_sys,
          { "SYS",                              "ncp.system_flags.sys",
            FT_BOOLEAN, 8, NULL, SYS,
            "Is this a system packet?", HFILL }},
        { &hf_ncp_system_flags_bsy,
          { "BSY",                              "ncp.system_flags.bsy",
            FT_BOOLEAN, 8, NULL, BSY,
            "Is the server busy?", HFILL }},
        { &hf_ncp_system_flags_lst,
          { "LST",                              "ncp.system_flags.lst",
            FT_BOOLEAN, 8, NULL, LST,
            "Return Fragment List?", HFILL }},
        { &hf_ncp_src_connection,
          { "Source Connection ID",             "ncp.src_connection",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The workstation's connection identification number", HFILL }},
        { &hf_ncp_dst_connection,
          { "Destination Connection ID",        "ncp.dst_connection",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The server's connection identification number", HFILL }},
        { &hf_ncp_packet_seqno,
          { "Packet Sequence Number",           "ncp.packet_seqno",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Sequence number of this packet in a burst", HFILL }},
        { &hf_ncp_delay_time,
          { "Delay Time",                       "ncp.delay_time",       /* in 100 us increments */
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Delay time between consecutive packet sends (100 us increments)", HFILL }},
        { &hf_ncp_burst_seqno,
          { "Burst Sequence Number",            "ncp.burst_seqno",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Sequence number of this packet in the burst", HFILL }},
        { &hf_ncp_ack_seqno,
          { "ACK Sequence Number",              "ncp.ack_seqno",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Next expected burst sequence number", HFILL }},
        { &hf_ncp_burst_len,
          { "Burst Length",                     "ncp.burst_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Total length of data in this burst", HFILL }},
        { &hf_ncp_burst_offset,
          { "Burst Offset",                     "ncp.burst_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Offset of data in the burst", HFILL }},
        { &hf_ncp_data_offset,
          { "Data Offset",                      "ncp.data_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Offset of this packet", HFILL }},
        { &hf_ncp_data_bytes,
          { "Data Bytes",                       "ncp.data_bytes",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of data bytes in this packet", HFILL }},
        { &hf_ncp_missing_fraglist_count,
          { "Missing Fragment List Count",      "ncp.missing_fraglist_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of missing fragments reported", HFILL }},
        { &hf_ncp_missing_data_offset,
          { "Missing Data Offset",              "ncp.missing_data_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Offset of beginning of missing data", HFILL }},
        { &hf_ncp_missing_data_count,
          { "Missing Data Count",               "ncp.missing_data_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of bytes of missing data", HFILL }},
        { &hf_ncp_completion_code,
          { "Completion Code",                  "ncp.completion_code",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_connection_status,
          { "Connection Status",                "ncp.connection_status",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_slot,
          { "Slot",                             "ncp.slot",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_signature_character,
          { "Signature Character",              "ncp.signature_character",
            FT_CHAR, BASE_HEX, VALS(ncp_sigchar_vals), 0x0,
            NULL, HFILL }},
#if 0
        { &hf_ncp_fragment_handle,
          { "Fragment Handle",                  "ncp.fragger_hndl",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
#endif
        { &hf_lip_echo_magic,
          { "Large Internet Packet Echo Magic String",  "ncp.lip_echo.magic_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_lip_echo_payload,
          { "Large Internet Packet Echo Payload",  "ncp.lip_echo.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ncp_burst_command,
          { "Burst Command",                    "ncp.burst_command",
            FT_UINT32, BASE_HEX, VALS(burst_command), 0x0,
            "Packet Burst Command", HFILL }},
        { &hf_ncp_burst_file_handle,
          { "Burst File Handle",                "ncp.burst_file_handle",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Packet Burst File Handle", HFILL }},
        { &hf_ncp_burst_reserved,
          { "Reserved",                         "ncp.burst_reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };
    static gint *ett[] = {
        &ett_ncp,
        &ett_ncp_system_flags,
        &ett_nds,
        &ett_nds_segments,
        &ett_nds_segment
    };
    static ei_register_info ei[] = {
        { &ei_ncp_new_server_session, { "ncp.new_server_session", PI_RESPONSE_CODE, PI_CHAT, "Detected New Server Session", EXPFILL }},
        { &ei_ncp_oplock_handle, { "ncp.oplock_handle.clear", PI_RESPONSE_CODE, PI_CHAT, "Server requesting station to clear oplock", EXPFILL }},
        { &ei_ncp_type, { "ncp.type.unsupported", PI_UNDECODED, PI_NOTE, "Packet type not supported yet", EXPFILL }},
    };
    module_t *ncp_module;
    expert_module_t* expert_ncp;

    proto_ncp = proto_register_protocol("NetWare Core Protocol", "NCP", "ncp");

    proto_register_field_array(proto_ncp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ncp = expert_register_protocol(proto_ncp);
    expert_register_field_array(expert_ncp, ei, array_length(ei));

    ncp_module = prefs_register_protocol(proto_ncp, NULL);
    prefs_register_obsolete_preference(ncp_module, "initial_hash_size");
    prefs_register_bool_preference(ncp_module, "desegment",
                                   "Reassemble NCP-over-TCP messages spanning multiple TCP segments",
                                   "Whether the NCP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &ncp_desegment);
    prefs_register_bool_preference(ncp_module, "defragment_nds",
                                   "Reassemble fragmented NDS messages spanning multiple reply packets",
                                   "Whether the NCP dissector should defragment NDS messages spanning multiple reply packets.",
                                   &nds_defragment);
    prefs_register_bool_preference(ncp_module, "newstyle",
                                   "Dissect New Netware Information Structure",
                                   "Dissect the NetWare Information Structure as NetWare 5.x or higher or as older NetWare 3.x.",
                                   &ncp_newstyle);
    prefs_register_bool_preference(ncp_module, "eid_2_expert",
                                   "Expert: EID to Name lookups?",
                                   "Whether the NCP dissector should echo the NDS Entry ID to name resolves to the expert table.",
                                   &nds_echo_eid);
    prefs_register_bool_preference(ncp_module, "connection_2_expert",
                                   "Expert: NCP Connections?",
                                   "Whether the NCP dissector should echo NCP connection information to the expert table.",
                                   &ncp_echo_conn);
    prefs_register_bool_preference(ncp_module, "error_2_expert",
                                   "Expert: NCP Errors?",
                                   "Whether the NCP dissector should echo protocol errors to the expert table.",
                                   &ncp_echo_err);
    prefs_register_bool_preference(ncp_module, "server_2_expert",
                                   "Expert: Server Information?",
                                   "Whether the NCP dissector should echo server information to the expert table.",
                                   &ncp_echo_server);
    prefs_register_bool_preference(ncp_module, "file_2_expert",
                                   "Expert: File Information?",
                                   "Whether the NCP dissector should echo file open/close/oplock information to the expert table.",
                                   &ncp_echo_file);
    register_init_routine(&mncp_init_protocol);
    register_cleanup_routine(&mncp_cleanup_protocol);
    ncp_tap.stat=register_tap("ncp_srt");
    ncp_tap.hdr=register_tap("ncp");

    register_conversation_table(proto_ncp, FALSE, ncp_conversation_packet, ncp_hostlist_packet);
    register_srt_table(proto_ncp, "ncp_srt", 24, ncpstat_packet, ncpstat_init, NULL);
}

void
proto_reg_handoff_ncp(void)
{
    dissector_handle_t ncp_handle;
    dissector_handle_t ncp_tcp_handle;

    ncp_handle = create_dissector_handle(dissect_ncp, proto_ncp);
    ncp_tcp_handle = create_dissector_handle(dissect_ncp_tcp, proto_ncp);
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_NCP, ncp_tcp_handle);
    dissector_add_uint("udp.port", UDP_PORT_NCP, ncp_handle);
    dissector_add_uint("ipx.packet_type", IPX_PACKET_TYPE_NCP, ncp_handle);
    dissector_add_uint("ipx.socket", IPX_SOCKET_NCP, ncp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

