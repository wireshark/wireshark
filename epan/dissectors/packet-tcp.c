/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/in_cksum.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/ip_opts.h>
#include <epan/follow.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-tcp.h"
#include "packet-frame.h"
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/slab.h>
#include <epan/expert.h>

static int tcp_tap = -1;

/* Place TCP summary in proto tree */
static gboolean tcp_summary_in_tree = TRUE;

/*
 * Flag to control whether to check the TCP checksum.
 *
 * In at least some Solaris network traces, there are packets with bad
 * TCP checksums, but the traffic appears to indicate that the packets
 * *were* received; the packets were probably sent by the host on which
 * the capture was being done, on a network interface to which
 * checksumming was offloaded, so that DLPI supplied an un-checksummed
 * packet to the capture program but a checksummed packet got put onto
 * the wire.
 */
static gboolean tcp_check_checksum = FALSE;

/*
 * Window scaling values to be used when not known (set as a preference) */
 enum scaling_window_value {
  WindowScaling_NotKnown=-1,
  WindowScaling_0=0,
  WindowScaling_1,
  WindowScaling_2,
  WindowScaling_3,
  WindowScaling_4,
  WindowScaling_5,
  WindowScaling_6,
  WindowScaling_7,
  WindowScaling_8,
  WindowScaling_9,
  WindowScaling_10,
  WindowScaling_11,
  WindowScaling_12,
  WindowScaling_13,
  WindowScaling_14
};
static gint tcp_default_window_scaling = (gint)WindowScaling_NotKnown;


extern FILE* data_out_file;

static int proto_tcp = -1;
static int hf_tcp_srcport = -1;
static int hf_tcp_dstport = -1;
static int hf_tcp_port = -1;
static int hf_tcp_stream = -1;
static int hf_tcp_seq = -1;
static int hf_tcp_nxtseq = -1;
static int hf_tcp_ack = -1;
static int hf_tcp_hdr_len = -1;
static int hf_tcp_flags = -1;
static int hf_tcp_flags_res = -1;
static int hf_tcp_flags_ns = -1;
static int hf_tcp_flags_cwr = -1;
static int hf_tcp_flags_ecn = -1;
static int hf_tcp_flags_urg = -1;
static int hf_tcp_flags_ack = -1;
static int hf_tcp_flags_push = -1;
static int hf_tcp_flags_reset = -1;
static int hf_tcp_flags_syn = -1;
static int hf_tcp_flags_fin = -1;
static int hf_tcp_window_size_value = -1;
static int hf_tcp_window_size = -1;
static int hf_tcp_window_size_scalefactor = -1;
static int hf_tcp_checksum = -1;
static int hf_tcp_checksum_bad = -1;
static int hf_tcp_checksum_good = -1;
static int hf_tcp_len = -1;
static int hf_tcp_urgent_pointer = -1;
static int hf_tcp_analysis = -1;
static int hf_tcp_analysis_flags = -1;
static int hf_tcp_analysis_bytes_in_flight = -1;
static int hf_tcp_analysis_acks_frame = -1;
static int hf_tcp_analysis_ack_rtt = -1;
static int hf_tcp_analysis_rto = -1;
static int hf_tcp_analysis_rto_frame = -1;
static int hf_tcp_analysis_retransmission = -1;
static int hf_tcp_analysis_fast_retransmission = -1;
static int hf_tcp_analysis_out_of_order = -1;
static int hf_tcp_analysis_reused_ports = -1;
static int hf_tcp_analysis_lost_packet = -1;
static int hf_tcp_analysis_ack_lost_packet = -1;
static int hf_tcp_analysis_window_update = -1;
static int hf_tcp_analysis_window_full = -1;
static int hf_tcp_analysis_keep_alive = -1;
static int hf_tcp_analysis_keep_alive_ack = -1;
static int hf_tcp_analysis_duplicate_ack = -1;
static int hf_tcp_analysis_duplicate_ack_num = -1;
static int hf_tcp_analysis_duplicate_ack_frame = -1;
static int hf_tcp_analysis_zero_window = -1;
static int hf_tcp_analysis_zero_window_probe = -1;
static int hf_tcp_analysis_zero_window_probe_ack = -1;
static int hf_tcp_continuation_to = -1;
static int hf_tcp_pdu_time = -1;
static int hf_tcp_pdu_size = -1;
static int hf_tcp_pdu_last_frame = -1;
static int hf_tcp_reassembled_in = -1;
static int hf_tcp_reassembled_length = -1;
static int hf_tcp_reassembled_data = -1;
static int hf_tcp_segments = -1;
static int hf_tcp_segment = -1;
static int hf_tcp_segment_overlap = -1;
static int hf_tcp_segment_overlap_conflict = -1;
static int hf_tcp_segment_multiple_tails = -1;
static int hf_tcp_segment_too_long_fragment = -1;
static int hf_tcp_segment_error = -1;
static int hf_tcp_segment_count = -1;
static int hf_tcp_options = -1;
static int hf_tcp_option_kind = -1;
static int hf_tcp_option_len = -1;
static int hf_tcp_option_mss = -1;
static int hf_tcp_option_mss_val = -1;
static int hf_tcp_option_wscale_shift = -1;
static int hf_tcp_option_wscale_multiplier = -1;
static int hf_tcp_option_sack_perm = -1;
static int hf_tcp_option_sack = -1;
static int hf_tcp_option_sack_sle = -1;
static int hf_tcp_option_sack_sre = -1;
static int hf_tcp_option_sack_range_count = -1;
static int hf_tcp_option_echo = -1;
static int hf_tcp_option_echo_reply = -1;
static int hf_tcp_option_timestamp_tsval = -1;
static int hf_tcp_option_timestamp_tsecr = -1;
static int hf_tcp_option_cc = -1;
static int hf_tcp_option_ccnew = -1;
static int hf_tcp_option_ccecho = -1;
static int hf_tcp_option_md5 = -1;
static int hf_tcp_option_qs = -1;
static int hf_tcp_option_exp = -1;
static int hf_tcp_option_exp_data = -1;

static int hf_tcp_option_rvbd_probe = -1;
static int hf_tcp_option_rvbd_probe_version1 = -1;
static int hf_tcp_option_rvbd_probe_version2 = -1;
static int hf_tcp_option_rvbd_probe_type1 = -1;
static int hf_tcp_option_rvbd_probe_type2 = -1;
static int hf_tcp_option_rvbd_probe_optlen = -1;
static int hf_tcp_option_rvbd_probe_prober = -1;
static int hf_tcp_option_rvbd_probe_proxy = -1;
static int hf_tcp_option_rvbd_probe_client = -1;
static int hf_tcp_option_rvbd_probe_proxy_port = -1;
static int hf_tcp_option_rvbd_probe_appli_ver = -1;
static int hf_tcp_option_rvbd_probe_storeid = -1;
static int hf_tcp_option_rvbd_probe_flags = -1;
static int hf_tcp_option_rvbd_probe_flag_last_notify = -1;
static int hf_tcp_option_rvbd_probe_flag_server_connected = -1;
static int hf_tcp_option_rvbd_probe_flag_not_cfe = -1;
static int hf_tcp_option_rvbd_probe_flag_sslcert = -1;
static int hf_tcp_option_rvbd_probe_flag_probe_cache = -1;

static int hf_tcp_option_rvbd_trpy = -1;
static int hf_tcp_option_rvbd_trpy_flags = -1;
static int hf_tcp_option_rvbd_trpy_flag_mode = -1;
static int hf_tcp_option_rvbd_trpy_flag_oob = -1;
static int hf_tcp_option_rvbd_trpy_flag_chksum = -1;
static int hf_tcp_option_rvbd_trpy_flag_fw_rst = -1;
static int hf_tcp_option_rvbd_trpy_flag_fw_rst_inner = -1;
static int hf_tcp_option_rvbd_trpy_flag_fw_rst_probe = -1;
static int hf_tcp_option_rvbd_trpy_src = -1;
static int hf_tcp_option_rvbd_trpy_dst = -1;
static int hf_tcp_option_rvbd_trpy_src_port = -1;
static int hf_tcp_option_rvbd_trpy_dst_port = -1;
static int hf_tcp_option_rvbd_trpy_client_port = -1;

static int hf_tcp_option_mptcp_flags = -1;
static int hf_tcp_option_mptcp_B_flag = -1;
static int hf_tcp_option_mptcp_C_flag = -1;
static int hf_tcp_option_mptcp_S_flag = -1;
static int hf_tcp_option_mptcp_F_flag = -1;
static int hf_tcp_option_mptcp_m_flag = -1;
static int hf_tcp_option_mptcp_M_flag = -1;
static int hf_tcp_option_mptcp_a_flag = -1;
static int hf_tcp_option_mptcp_A_flag = -1;
static int hf_tcp_option_mptcp_subtype = -1;
static int hf_tcp_option_mptcp_version = -1;
static int hf_tcp_option_mptcp_address_id = -1;
static int hf_tcp_option_mptcp_recv_token = -1;
static int hf_tcp_option_mptcp_sender_key = -1;
static int hf_tcp_option_mptcp_recv_key = -1;
static int hf_tcp_option_mptcp_sender_rand = -1;
static int hf_tcp_option_mptcp_sender_trunc_mac = -1;
static int hf_tcp_option_mptcp_sender_mac = -1;
static int hf_tcp_option_mptcp_data_ack = -1;
static int hf_tcp_option_mptcp_data_seq_no = -1;
static int hf_tcp_option_mptcp_subflow_seq_no = -1;
static int hf_tcp_option_mptcp_data_lvl_len = -1;
static int hf_tcp_option_mptcp_checksum = -1;
static int hf_tcp_option_mptcp_ipver = -1;
static int hf_tcp_option_mptcp_ipv4 = -1;
static int hf_tcp_option_mptcp_ipv6 = -1;
static int hf_tcp_option_mptcp_port = -1;

static int hf_tcp_ts_relative = -1;
static int hf_tcp_ts_delta = -1;
static int hf_tcp_option_scps = -1;
static int hf_tcp_option_scps_vector = -1;
static int hf_tcp_option_scps_binding = -1;
static int hf_tcp_option_scps_binding_len = -1;
static int hf_tcp_scpsoption_flags_bets = -1;
static int hf_tcp_scpsoption_flags_snack1 = -1;
static int hf_tcp_scpsoption_flags_snack2 = -1;
static int hf_tcp_scpsoption_flags_compress = -1;
static int hf_tcp_scpsoption_flags_nlts = -1;
static int hf_tcp_scpsoption_flags_reserved = -1;
static int hf_tcp_scpsoption_connection_id = -1;
static int hf_tcp_option_snack = -1;
static int hf_tcp_option_snack_offset = -1;
static int hf_tcp_option_snack_size = -1;
static int hf_tcp_option_snack_le = -1;
static int hf_tcp_option_snack_re = -1;
static int hf_tcp_option_user_to = -1;
static int hf_tcp_option_user_to_granularity = -1;
static int hf_tcp_option_user_to_val = -1;
static int hf_tcp_proc_src_uid = -1;
static int hf_tcp_proc_src_pid = -1;
static int hf_tcp_proc_src_uname = -1;
static int hf_tcp_proc_src_cmd = -1;
static int hf_tcp_proc_dst_uid = -1;
static int hf_tcp_proc_dst_pid = -1;
static int hf_tcp_proc_dst_uname = -1;
static int hf_tcp_proc_dst_cmd = -1;
static int hf_tcp_data = -1;

static gint ett_tcp = -1;
static gint ett_tcp_flags = -1;
static gint ett_tcp_options = -1;
static gint ett_tcp_option_timestamp = -1;
static gint ett_tcp_option_mss = -1;
static gint ett_tcp_option_wscale = -1;
static gint ett_tcp_option_sack = -1;
static gint ett_tcp_option_scps = -1;
static gint ett_tcp_option_scps_extended = -1;
static gint ett_tcp_option_user_to = -1;
static gint ett_tcp_option_exp = -1;
static gint ett_tcp_option_sack_perm = -1;
static gint ett_tcp_analysis = -1;
static gint ett_tcp_analysis_faults = -1;
static gint ett_tcp_timestamps = -1;
static gint ett_tcp_segments = -1;
static gint ett_tcp_segment  = -1;
static gint ett_tcp_checksum = -1;
static gint ett_tcp_process_info = -1;
static gint ett_tcp_option_mptcp = -1;

static gint ett_tcp_opt_rvbd_probe = -1;
static gint ett_tcp_opt_rvbd_probe_flags = -1;
static gint ett_tcp_opt_rvbd_trpy = -1;
static gint ett_tcp_opt_rvbd_trpy_flags = -1;

/* Some protocols such as encrypted DCE/RPCoverHTTP have dependencies
 * from one PDU to the next PDU and require that they are called in sequence.
 * These protocols would not be able to handle PDUs coming out of order
 * or for example when a PDU is seen twice, like for retransmissions.
 * This preference can be set for such protocols to make sure that we dont invoke
 * the subdissectors for retransmitted or out-of-order segments.
 */
static gboolean tcp_no_subdissector_on_error = FALSE;

/*
 *  TCP option
 */

#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_MSS              2       /* Segment size negotiating */
#define TCPOPT_WINDOW           3       /* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_ECHO             6
#define TCPOPT_ECHOREPLY        7
#define TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define TCPOPT_CC               11
#define TCPOPT_CCNEW            12
#define TCPOPT_CCECHO           13
#define TCPOPT_MD5              19      /* RFC2385 */
#define TCPOPT_MPTCP            0x1e    /* Multipath TCP */
#define TCPOPT_SCPS             20      /* SCPS Capabilities */
#define TCPOPT_SNACK            21      /* SCPS SNACK */
#define TCPOPT_RECBOUND         22      /* SCPS Record Boundary */
#define TCPOPT_CORREXP          23      /* SCPS Corruption Experienced */
#define TCPOPT_QS               27      /* RFC4782 */
#define TCPOPT_USER_TO          28      /* RFC5482 */
#define TCPOPT_EXP_FD           0xfd    /* Experimental, reserved */
#define TCPOPT_EXP_FE           0xfe    /* Experimental, reserved */
/* Non IANA registered option numbers */
#define TCPOPT_RVBD_PROBE       76      /* Riverbed probe option */
#define TCPOPT_RVBD_TRPY        78      /* Riverbed transparency option */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_SACK_MIN       2
#define TCPOLEN_ECHO           6
#define TCPOLEN_ECHOREPLY      6
#define TCPOLEN_TIMESTAMP     10
#define TCPOLEN_CC             6
#define TCPOLEN_CCNEW          6
#define TCPOLEN_CCECHO         6
#define TCPOLEN_MD5           18
#define TCPOLEN_MPTCP_MIN      8
#define TCPOLEN_SCPS           4
#define TCPOLEN_SNACK          6
#define TCPOLEN_RECBOUND       2
#define TCPOLEN_CORREXP        2
#define TCPOLEN_QS             8
#define TCPOLEN_USER_TO        4
#define TCPOLEN_RVBD_PROBE_MIN 3
#define TCPOLEN_RVBD_TRPY_MIN 16
#define TCPOLEN_EXP_MIN        2

/*
 *     Multipath TCP subtypes
 */
#define TCPOPT_MPTCP_MP_CAPABLE    0x0    /* Multipath TCP Multipath Capable */
#define TCPOPT_MPTCP_MP_JOIN       0x1    /* Multipath TCP Join Connection */
#define TCPOPT_MPTCP_DSS           0x2    /* Multipath TCP Data Sequence Signal */
#define TCPOPT_MPTCP_ADD_ADDR      0x3    /* Multipath TCP Add Address */
#define TCPOPT_MPTCP_REMOVE_ADDR   0x4    /* Multipath TCP Remove Address */
#define TCPOPT_MPTCP_MP_PRIO       0x5    /* Multipath TCP Change Subflow Priority */
#define TCPOPT_MPTCP_MP_FAIL       0x6    /* Multipath TCP Fallback */

static const true_false_string tcp_option_user_to_granularity = {
  "Minutes", "Seconds"
};

static const value_string tcp_option_kind_vs[] = {
    { TCPOPT_EXP_FD, "Experimental 0xFD" },
    { TCPOPT_EXP_FE, "Experimental 0xFE" },
    { TCPOPT_WINDOW, "Window Scale" },
    { TCPOPT_SACK_PERM, "SACK Permission" },
    { TCPOPT_MSS, "MSS size" },
    { TCPOPT_TIMESTAMP, "Timestamp" },
    { TCPOPT_MPTCP, "Multipath TCP" },
    { 0, NULL }
};

/* not all of the hf_fields below make sense for TCP but we have to provide
   them anyways to comply with the api (which was aimed for ip fragment
   reassembly) */
static const fragment_items tcp_segment_items = {
    &ett_tcp_segment,
    &ett_tcp_segments,
    &hf_tcp_segments,
    &hf_tcp_segment,
    &hf_tcp_segment_overlap,
    &hf_tcp_segment_overlap_conflict,
    &hf_tcp_segment_multiple_tails,
    &hf_tcp_segment_too_long_fragment,
    &hf_tcp_segment_error,
    &hf_tcp_segment_count,
    &hf_tcp_reassembled_in,
    &hf_tcp_reassembled_length,
    &hf_tcp_reassembled_data,
    "Segments"
};

static const value_string mptcp_subtype_vs[] = {
    { TCPOPT_MPTCP_MP_CAPABLE, "Multipath Capable" },
    { TCPOPT_MPTCP_MP_JOIN, "Join Connection" },
    { TCPOPT_MPTCP_DSS, "Data Sequence Signal" },
    { TCPOPT_MPTCP_ADD_ADDR, "Add Address"},
    { TCPOPT_MPTCP_REMOVE_ADDR, "Remove Address" },
    { TCPOPT_MPTCP_MP_PRIO, "Change Subflow Priority" },
    { TCPOPT_MPTCP_MP_FAIL, "TCP Fallback" },
    { 0, NULL }
};

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;
static guint32 tcp_stream_index;

/* TCP structs and definitions */

/* **************************************************************************
 * RTT, relative sequence numbers, window scaling & etc.
 * **************************************************************************/
static gboolean tcp_analyze_seq           = TRUE;
static gboolean tcp_relative_seq          = TRUE;
static gboolean tcp_track_bytes_in_flight = TRUE;
static gboolean tcp_calculate_ts          = FALSE;

/* SLAB allocator for tcp_unacked structures
 */
SLAB_ITEM_TYPE_DEFINE(tcp_unacked_t)
static SLAB_FREE_LIST_DEFINE(tcp_unacked_t)
#define TCP_UNACKED_NEW(fi)                 \
    SLAB_ALLOC(fi, tcp_unacked_t)
#define TCP_UNACKED_FREE(fi)                    \
    SLAB_FREE(fi, tcp_unacked_t)


#define TCP_A_RETRANSMISSION        0x0001
#define TCP_A_LOST_PACKET           0x0002
#define TCP_A_ACK_LOST_PACKET       0x0004
#define TCP_A_KEEP_ALIVE            0x0008
#define TCP_A_DUPLICATE_ACK         0x0010
#define TCP_A_ZERO_WINDOW           0x0020
#define TCP_A_ZERO_WINDOW_PROBE     0x0040
#define TCP_A_ZERO_WINDOW_PROBE_ACK 0x0080
#define TCP_A_KEEP_ALIVE_ACK        0x0100
#define TCP_A_OUT_OF_ORDER          0x0200
#define TCP_A_FAST_RETRANSMISSION   0x0400
#define TCP_A_WINDOW_UPDATE         0x0800
#define TCP_A_WINDOW_FULL           0x1000
#define TCP_A_REUSED_PORTS          0x2000


static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
    guint32 seq, guint32 nxtseq, gboolean is_tcp_segment,
    struct tcp_analysis *tcpd);


struct tcp_analysis *
init_tcp_conversation_data(packet_info *pinfo)
{
    struct tcp_analysis *tcpd;

    /* Initialize the tcp protocol data structure to add to the tcp conversation */
    tcpd=se_alloc0(sizeof(struct tcp_analysis));
    tcpd->flow1.win_scale=-1;
    tcpd->flow1.window = G_MAXUINT32;
    tcpd->flow1.multisegment_pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_multisegment_pdus");
    /*
    tcpd->flow1.username = NULL;
    tcpd->flow1.command = NULL;
    */
    tcpd->flow2.window = G_MAXUINT32;
    tcpd->flow2.win_scale=-1;
    tcpd->flow2.multisegment_pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_multisegment_pdus");
    /*
    tcpd->flow2.username = NULL;
    tcpd->flow2.command = NULL;
    */
    tcpd->acked_table=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_analyze_acked_table");
    tcpd->ts_first.secs=pinfo->fd->abs_ts.secs;
    tcpd->ts_first.nsecs=pinfo->fd->abs_ts.nsecs;
    tcpd->ts_prev.secs=pinfo->fd->abs_ts.secs;
    tcpd->ts_prev.nsecs=pinfo->fd->abs_ts.nsecs;
    tcpd->flow1.valid_bif = 1;
    tcpd->flow2.valid_bif = 1;
    tcpd->stream = tcp_stream_index++;
    tcpd->server_port = 0;

    return tcpd;
}

struct tcp_analysis *
get_tcp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    int direction;
    struct tcp_analysis *tcpd;

    /* Did the caller supply the conversation pointer? */
    if( conv==NULL )
            conv = find_or_create_conversation(pinfo);

    /* Get the data for this conversation */
    tcpd=conversation_get_proto_data(conv, proto_tcp);

    /* If the conversation was just created or it matched a
     * conversation with template options, tcpd will not
     * have been initialized. So, initialize
     * a new tcpd structure for the conversation.
     */
    if (!tcpd) {
        tcpd = init_tcp_conversation_data(pinfo);
        conversation_add_proto_data(conv, proto_tcp, tcpd);
    }

    if (!tcpd) {
      return NULL;
    }

    /* check direction and get ua lists */
    direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if(direction==0) {
        direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    if(direction>=0) {
        tcpd->fwd=&(tcpd->flow1);
        tcpd->rev=&(tcpd->flow2);
    } else {
        tcpd->fwd=&(tcpd->flow2);
        tcpd->rev=&(tcpd->flow1);
    }

    tcpd->ta=NULL;
    return tcpd;
}

/* Attach process info to a flow */
/* XXX - We depend on the TCP dissector finding the conversation first */
void
add_tcp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command) {
    conversation_t *conv;
    struct tcp_analysis *tcpd;
    tcp_flow_t *flow = NULL;

    conv = find_conversation(frame_num, local_addr, remote_addr, PT_TCP, local_port, remote_port, 0);
    if (!conv) {
        return;
    }

    tcpd = conversation_get_proto_data(conv, proto_tcp);
    if (!tcpd) {
        return;
    }

    if (CMP_ADDRESS(local_addr, &conv->key_ptr->addr1) == 0 && local_port == conv->key_ptr->port1) {
        flow = &tcpd->flow1;
    } else if (CMP_ADDRESS(remote_addr, &conv->key_ptr->addr1) == 0 && remote_port == conv->key_ptr->port1) {
        flow = &tcpd->flow2;
    }
    if (!flow || flow->command) {
        return;
    }

    flow->process_uid = uid;
    flow->process_pid = pid;
    flow->username = se_strdup(username);
    flow->command = se_strdup(command);
}


/* Calculate the timestamps relative to this conversation */
static void
tcp_calculate_timestamps(packet_info *pinfo, struct tcp_analysis *tcpd,
            struct tcp_per_packet_data_t *tcppd)
{
    if( !tcppd ) {
        tcppd = se_alloc(sizeof(struct tcp_per_packet_data_t));
        p_add_proto_data(pinfo->fd, proto_tcp, tcppd);
    }

    if (!tcpd)
        return;

    nstime_delta(&tcppd->ts_del, &pinfo->fd->abs_ts, &tcpd->ts_prev);

    tcpd->ts_prev.secs=pinfo->fd->abs_ts.secs;
    tcpd->ts_prev.nsecs=pinfo->fd->abs_ts.nsecs;
}

/* Add a subtree with the timestamps relative to this conversation */
static void
tcp_print_timestamps(packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree, struct tcp_analysis *tcpd, struct tcp_per_packet_data_t *tcppd)
{
    proto_item  *item;
    proto_tree  *tree;
    nstime_t    ts;

    if (!tcpd)
        return;

    item=proto_tree_add_text(parent_tree, tvb, 0, 0, "Timestamps");
    PROTO_ITEM_SET_GENERATED(item);
    tree=proto_item_add_subtree(item, ett_tcp_timestamps);

    nstime_delta(&ts, &pinfo->fd->abs_ts, &tcpd->ts_first);
    item = proto_tree_add_time(tree, hf_tcp_ts_relative, tvb, 0, 0, &ts);
    PROTO_ITEM_SET_GENERATED(item);

    if( !tcppd )
        tcppd = p_get_proto_data(pinfo->fd, proto_tcp);

    if( tcppd ) {
        item = proto_tree_add_time(tree, hf_tcp_ts_delta, tvb, 0, 0,
            &tcppd->ts_del);
        PROTO_ITEM_SET_GENERATED(item);
    }
}

static void
print_pdu_tracking_data(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tcp_tree, struct tcp_multisegment_pdu *msp)
{
    proto_item *item;

    col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Continuation to #%u] ", msp->first_frame);
    item=proto_tree_add_uint(tcp_tree, hf_tcp_continuation_to,
        tvb, 0, 0, msp->first_frame);
    PROTO_ITEM_SET_GENERATED(item);
}

/* if we know that a PDU starts inside this segment, return the adjusted
   offset to where that PDU starts or just return offset back
   and let TCP try to find out what it can about this segment
*/
static int
scan_for_next_pdu(tvbuff_t *tvb, proto_tree *tcp_tree, packet_info *pinfo, int offset, guint32 seq, guint32 nxtseq, emem_tree_t *multisegment_pdus)
{
    struct tcp_multisegment_pdu *msp=NULL;

    if(!pinfo->fd->flags.visited) {
        msp=se_tree_lookup32_le(multisegment_pdus, seq-1);
        if(msp) {
            /* If this is a continuation of a PDU started in a
             * previous segment we need to update the last_frame
             * variables.
            */
            if(seq>msp->seq && seq<msp->nxtpdu) {
                msp->last_frame=pinfo->fd->num;
                msp->last_frame_time=pinfo->fd->abs_ts;
                print_pdu_tracking_data(pinfo, tvb, tcp_tree, msp);
            }

            /* If this segment is completely within a previous PDU
             * then we just skip this packet
             */
            if(seq>msp->seq && nxtseq<=msp->nxtpdu) {
                return -1;
            }
            if(seq<msp->nxtpdu && nxtseq>msp->nxtpdu) {
                offset+=msp->nxtpdu-seq;
                return offset;
            }

        }
    } else {
        /* First we try to find the start and transfer time for a PDU.
         * We only print this for the very first segment of a PDU
         * and only for PDUs spanning multiple segments.
         * Se we look for if there was any multisegment PDU started
         * just BEFORE the end of this segment. I.e. either inside this
         * segment or in a previous segment.
         * Since this might also match PDUs that are completely within
         * this segment we also verify that the found PDU does span
         * beyond the end of this segment.
         */
        msp=se_tree_lookup32_le(multisegment_pdus, nxtseq-1);
        if(msp) {
            if(pinfo->fd->num==msp->first_frame) {
                proto_item *item;
                nstime_t ns;

                item=proto_tree_add_uint(tcp_tree, hf_tcp_pdu_last_frame, tvb, 0, 0, msp->last_frame);
                PROTO_ITEM_SET_GENERATED(item);

                nstime_delta(&ns, &msp->last_frame_time, &pinfo->fd->abs_ts);
                item = proto_tree_add_time(tcp_tree, hf_tcp_pdu_time,
                        tvb, 0, 0, &ns);
                PROTO_ITEM_SET_GENERATED(item);
            }
        }

        /* Second we check if this segment is part of a PDU started
         * prior to the segment (seq-1)
         */
        msp=se_tree_lookup32_le(multisegment_pdus, seq-1);
        if(msp) {
            /* If this segment is completely within a previous PDU
             * then we just skip this packet
             */
            if(seq>msp->seq && nxtseq<=msp->nxtpdu) {
                print_pdu_tracking_data(pinfo, tvb, tcp_tree, msp);
                return -1;
            }

            if(seq<msp->nxtpdu && nxtseq>msp->nxtpdu) {
                offset+=msp->nxtpdu-seq;
                return offset;
            }
        }

    }
    return offset;
}

/* if we saw a PDU that extended beyond the end of the segment,
   use this function to remember where the next pdu starts
*/
struct tcp_multisegment_pdu *
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint32 seq, guint32 nxtpdu, emem_tree_t *multisegment_pdus)
{
    struct tcp_multisegment_pdu *msp;

    msp=se_alloc(sizeof(struct tcp_multisegment_pdu));
    msp->nxtpdu=nxtpdu;
    msp->seq=seq;
    msp->first_frame=pinfo->fd->num;
    msp->last_frame=pinfo->fd->num;
    msp->last_frame_time=pinfo->fd->abs_ts;
    msp->flags=0;
    se_tree_insert32(multisegment_pdus, seq, (void *)msp);
    return msp;
}

/* This is called for SYN and SYN+ACK packets and the purpose is to verify
 * that we have seen window scaling in both directions.
 * If we cant find window scaling being set in both directions
 * that means it was present in the SYN but not in the SYN+ACK
 * (or the SYN was missing) and then we disable the window scaling
 * for this tcp session.
 */
static void
verify_tcp_window_scaling(gboolean is_synack, struct tcp_analysis *tcpd)
{
    if( tcpd->fwd->win_scale==-1 ) {
        /* We know window scaling will not be used as:
         * a) this is the SYN and it does not have the WS option
         *    (we set the reverse win_scale also in case we miss
         *    the SYN/ACK)
         * b) this is the SYN/ACK and either the SYN packet has not
         *    been seen or it did have the WS option. As the SYN/ACK
         *    does not have the WS option, window scaling will not be used.
         *
         * Setting win_scale to -2 to indicate that we can
         * trust the window_size value in the TCP header.
         */
        tcpd->fwd->win_scale = -2;
        tcpd->rev->win_scale = -2;

    } else if( is_synack && tcpd->rev->win_scale==-2 ) {
        /* The SYN/ACK has the WS option, while the SYN did not,
         * this should not happen, but the endpoints will not
         * have used window scaling, so we will neither
         */
        tcpd->fwd->win_scale = -2;
    }
}

/* if we saw a window scaling option, store it for future reference
*/
static void
pdu_store_window_scale_option(guint8 ws, struct tcp_analysis *tcpd)
{
    if (tcpd)
        tcpd->fwd->win_scale=ws;
}

/* when this function returns, it will (if createflag) populate the ta pointer.
 */
static void
tcp_analyze_get_acked_struct(guint32 frame, guint32 seq, guint32 ack, gboolean createflag, struct tcp_analysis *tcpd)
{
    emem_tree_key_t key[] = {{1, &frame}, {1, &seq}, {1, &ack}, {0, NULL}};

    if (!tcpd) {
        return;
    }

    tcpd->ta = se_tree_lookup32_array(tcpd->acked_table, key);
    if((!tcpd->ta) && createflag) {
        tcpd->ta = se_alloc0(sizeof(struct tcp_acked));
        se_tree_insert32_array(tcpd->acked_table, key, (void *)tcpd->ta);
    }
}


/* fwd contains a list of all segments processed but not yet ACKed in the
 *     same direction as the current segment.
 * rev contains a list of all segments received but not yet ACKed in the
 *     opposite direction to the current segment.
 *
 * New segments are always added to the head of the fwd/rev lists.
 *
 */
static void
tcp_analyze_sequence_number(packet_info *pinfo, guint32 seq, guint32 ack, guint32 seglen, guint16 flags, guint32 window, struct tcp_analysis *tcpd)
{
    tcp_unacked_t *ual=NULL;
    tcp_unacked_t *prevual=NULL;
    guint32 nextseq;
    int ackcount;

#if 0
    printf("\nanalyze_sequence numbers   frame:%u\n",pinfo->fd->num);
    printf("FWD list lastflags:0x%04x base_seq:%u:\n",tcpd->fwd->lastsegmentflags,tcpd->fwd->base_seq);
    for(ual=tcpd->fwd->segments; ual; ual=ual->next)
            printf("Frame:%d Seq:%u Nextseq:%u\n",ual->frame,ual->seq,ual->nextseq);
    printf("REV list lastflags:0x%04x base_seq:%u:\n",tcpd->rev->lastsegmentflags,tcpd->rev->base_seq);
    for(ual=tcpd->rev->segments; ual; ual=ual->next)
            printf("Frame:%d Seq:%u Nextseq:%u\n",ual->frame,ual->seq,ual->nextseq);
#endif

    if (!tcpd) {
        return;
    }

    /* if this is the first segment for this list we need to store the
     * base_seq
     *
     * Start relative seq and ack numbers at 1 if this
     * is not a SYN packet. This makes the relative
     * seq/ack numbers to be displayed correctly in the
     * event that the SYN or SYN/ACK packet is not seen
     * (this solves bug 1542)
     */
    if(tcpd->fwd->base_seq==0) {
        tcpd->fwd->base_seq = (flags & TH_SYN) ? seq : seq-1;
    }

    /* Only store reverse sequence if this isn't the SYN
     * There's no guarantee that the ACK field of a SYN
     * contains zeros; get the ISN from the first segment
     * with the ACK bit set instead (usually the SYN/ACK).
     */
    if( (tcpd->rev->base_seq==0) && (flags & TH_ACK) ) {
        tcpd->rev->base_seq = (flags & TH_SYN) ? ack : ack-1;
    }

    if( flags & TH_ACK ) {
        tcpd->rev->valid_bif = 1;
    }

    /* ZERO WINDOW PROBE
     * it is a zero window probe if
     *  the sequence number is the next expected one
     *  the window in the other direction is 0
     *  the segment is exactly 1 byte
     */
/*QQQ tested*/
    if( seglen==1
    &&  seq==tcpd->fwd->nextseq
    &&  tcpd->rev->window==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_ZERO_WINDOW_PROBE;
        goto finished_fwd;
    }


    /* ZERO WINDOW
     * a zero window packet has window == 0   but none of the SYN/FIN/RST set
     */
/*QQQ tested*/
    if( window==0
    && (flags&(TH_RST|TH_FIN|TH_SYN))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_ZERO_WINDOW;
    }


    /* LOST PACKET
     * If this segment is beyond the last seen nextseq we must
     * have missed some previous segment
     *
     * We only check for this if we have actually seen segments prior to this
     * one.
     * RST packets are not checked for this.
     */
    if( tcpd->fwd->nextseq
    &&  GT_SEQ(seq, tcpd->fwd->nextseq)
    &&  (flags&(TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_LOST_PACKET;

        /* Disable BiF until an ACK is seen in the other direction */
        tcpd->fwd->valid_bif = 0;
    }


    /* KEEP ALIVE
     * a keepalive contains 0 or 1 bytes of data and starts one byte prior
     * to what should be the next sequence number.
     * SYN/FIN/RST segments are never keepalives
     */
/*QQQ tested */
    if( (seglen==0||seglen==1)
    &&  seq==(tcpd->fwd->nextseq-1)
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_KEEP_ALIVE;
    }

    /* WINDOW UPDATE
     * A window update is a 0 byte segment with the same SEQ/ACK numbers as
     * the previous seen segment and with a new window value
     */
    if( seglen==0
    &&  window
    &&  window!=tcpd->fwd->window
    &&  seq==tcpd->fwd->nextseq
    &&  ack==tcpd->fwd->lastack
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_WINDOW_UPDATE;
    }


    /* WINDOW FULL
     * If we know the window scaling
     * and if this segment contains data and goes all the way to the
     * edge of the advertised window
     * then we mark it as WINDOW FULL
     * SYN/RST/FIN packets are never WINDOW FULL
     */
/*QQQ tested*/
    if( seglen>0
    &&  tcpd->rev->win_scale!=-1
    &&  (seq+seglen)==(tcpd->rev->lastack+(tcpd->rev->window<<(tcpd->rev->win_scale==-2?0:tcpd->rev->win_scale)))
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_WINDOW_FULL;
    }


    /* KEEP ALIVE ACK
     * It is a keepalive ack if it repeats the previous ACK and if
     * the last segment in the reverse direction was a keepalive
     */
/*QQQ tested*/
    if( seglen==0
    &&  window
    &&  window==tcpd->fwd->window
    &&  seq==tcpd->fwd->nextseq
    &&  ack==tcpd->fwd->lastack
    && (tcpd->rev->lastsegmentflags&TCP_A_KEEP_ALIVE)
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_KEEP_ALIVE_ACK;
        goto finished_fwd;
    }


    /* ZERO WINDOW PROBE ACK
     * It is a zerowindowprobe ack if it repeats the previous ACK and if
     * the last segment in the reverse direction was a zerowindowprobe
     * It also repeats the previous zero window indication
     */
/*QQQ tested*/
    if( seglen==0
    &&  window==0
    &&  window==tcpd->fwd->window
    &&  seq==tcpd->fwd->nextseq
    &&  ack==tcpd->fwd->lastack
    && (tcpd->rev->lastsegmentflags&TCP_A_ZERO_WINDOW_PROBE)
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_ZERO_WINDOW_PROBE_ACK;
        goto finished_fwd;
    }


    /* DUPLICATE ACK
     * It is a duplicate ack if window/seq/ack is the same as the previous
     * segment and if the segment length is 0
     */
    if( seglen==0
    &&  window
    &&  window==tcpd->fwd->window
    &&  seq==tcpd->fwd->nextseq
    &&  ack==tcpd->fwd->lastack
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        tcpd->fwd->dupacknum++;
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_DUPLICATE_ACK;
        tcpd->ta->dupack_num=tcpd->fwd->dupacknum;
        tcpd->ta->dupack_frame=tcpd->fwd->lastnondupack;
    }



finished_fwd:
    /* If this was NOT a dupack we must reset the dupack counters */
    if( (!tcpd->ta) || !(tcpd->ta->flags&TCP_A_DUPLICATE_ACK) ) {
        tcpd->fwd->lastnondupack=pinfo->fd->num;
        tcpd->fwd->dupacknum=0;
    }


    /* ACKED LOST PACKET
     * If this segment acks beyond the 'max seq to be acked' in the other direction
     * then that means we have missed packets going in the
     * other direction
     *
     * We only check this if we have actually seen some seq numbers
     * in the other direction.
     */
    if( tcpd->rev->maxseqtobeacked
    &&  GT_SEQ(ack, tcpd->rev->maxseqtobeacked )
    &&  (flags&(TH_ACK))!=0 ) {
/*QQQ tested*/
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_ACK_LOST_PACKET;
        /* update 'max seq to be acked' in the other direction so we don't get
         * this indication again.
         */
        tcpd->rev->maxseqtobeacked=tcpd->rev->nextseq;
    }


    /* RETRANSMISSION/FAST RETRANSMISSION/OUT-OF-ORDER
     * If the segments contains data and if it does not advance
     * sequence number it must be either of these three.
     * Only test for this if we know what the seq number should be
     * (tcpd->fwd->nextseq)
     *
     * Note that a simple KeepAlive is not a retransmission
     */
    if( seglen>0
    &&  tcpd->fwd->nextseq
    &&  (LT_SEQ(seq, tcpd->fwd->nextseq)) ) {
        guint64 t;

        if(tcpd->ta && (tcpd->ta->flags&TCP_A_KEEP_ALIVE) ) {
            goto finished_checking_retransmission_type;
        }

        /* If there were >=2 duplicate ACKs in the reverse direction
         * (there might be duplicate acks missing from the trace)
         * and if this sequence number matches those ACKs
         * and if the packet occurs within 20ms of the last
         * duplicate ack
         * then this is a fast retransmission
         */
        t=(pinfo->fd->abs_ts.secs-tcpd->rev->lastacktime.secs)*1000000000;
        t=t+(pinfo->fd->abs_ts.nsecs)-tcpd->rev->lastacktime.nsecs;
        if( tcpd->rev->dupacknum>=2
        &&  tcpd->rev->lastack==seq
        &&  t<20000000 ) {
            if(!tcpd->ta) {
                tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->flags|=TCP_A_FAST_RETRANSMISSION;
            goto finished_checking_retransmission_type;
        }

        /* If the segment came <3ms since the segment with the highest
         * seen sequence number and it doesn't look like a retransmission
         * then it is an OUT-OF-ORDER segment.
         *   (3ms is an arbitrary number)
         */
        t=(pinfo->fd->abs_ts.secs-tcpd->fwd->nextseqtime.secs)*1000000000;
        t=t+(pinfo->fd->abs_ts.nsecs)-tcpd->fwd->nextseqtime.nsecs;
        if( t<3000000
        && tcpd->fwd->nextseq != seq + seglen ) {
            if(!tcpd->ta) {
                tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->flags|=TCP_A_OUT_OF_ORDER;
            goto finished_checking_retransmission_type;
        }

        /* Then it has to be a generic retransmission */
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_RETRANSMISSION;
        nstime_delta(&tcpd->ta->rto_ts, &pinfo->fd->abs_ts, &tcpd->fwd->nextseqtime);
        tcpd->ta->rto_frame=tcpd->fwd->nextseqframe;
    }

finished_checking_retransmission_type:

    nextseq = seq+seglen;
    if (seglen || flags&(TH_SYN|TH_FIN)) {
        /* add this new sequence number to the fwd list */
        TCP_UNACKED_NEW(ual);
        ual->next=tcpd->fwd->segments;
        tcpd->fwd->segments=ual;
        ual->frame=pinfo->fd->num;
        ual->seq=seq;
        ual->ts=pinfo->fd->abs_ts;

        /* next sequence number is seglen bytes away, plus SYN/FIN which counts as one byte */
        if( (flags&(TH_SYN|TH_FIN)) ) {
            nextseq+=1;
        }
        ual->nextseq=nextseq;
    }

    /* Store the highest number seen so far for nextseq so we can detect
     * when we receive segments that arrive with a "hole"
     * If we don't have anything since before, just store what we got.
     * ZeroWindowProbes are special and don't really advance the nextseq
     */
    if(GT_SEQ(nextseq, tcpd->fwd->nextseq) || !tcpd->fwd->nextseq) {
        if( !tcpd->ta || !(tcpd->ta->flags&TCP_A_ZERO_WINDOW_PROBE) ) {
            tcpd->fwd->nextseq=nextseq;
            tcpd->fwd->nextseqframe=pinfo->fd->num;
            tcpd->fwd->nextseqtime.secs=pinfo->fd->abs_ts.secs;
            tcpd->fwd->nextseqtime.nsecs=pinfo->fd->abs_ts.nsecs;
        }
    }

    /* Store the highest continuous seq number seen so far for 'max seq to be acked',
     so we can detect TCP_A_ACK_LOST_PACKET condition
     */
    if(EQ_SEQ(seq, tcpd->fwd->maxseqtobeacked) || !tcpd->fwd->maxseqtobeacked) {
        if( !tcpd->ta || !(tcpd->ta->flags&TCP_A_ZERO_WINDOW_PROBE) ) {
            tcpd->fwd->maxseqtobeacked=tcpd->fwd->nextseq;
        }
    }


    /* remember what the ack/window is so we can track window updates and retransmissions */
    tcpd->fwd->window=window;
    tcpd->fwd->lastack=ack;
    tcpd->fwd->lastacktime.secs=pinfo->fd->abs_ts.secs;
    tcpd->fwd->lastacktime.nsecs=pinfo->fd->abs_ts.nsecs;


    /* if there were any flags set for this segment we need to remember them
     * we only remember the flags for the very last segment though.
     */
    if(tcpd->ta) {
        tcpd->fwd->lastsegmentflags=tcpd->ta->flags;
    } else {
        tcpd->fwd->lastsegmentflags=0;
    }


    /* remove all segments this ACKs and we don't need to keep around any more
     */
    ackcount=0;
    prevual = NULL;
    ual = tcpd->rev->segments;
    while(ual) {
        tcp_unacked_t *tmpual;

        /* If this ack matches the segment, process accordingly */
        if(ack==ual->nextseq) {
            tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
            tcpd->ta->frame_acked=ual->frame;
            nstime_delta(&tcpd->ta->ts, &pinfo->fd->abs_ts, &ual->ts);
        }
        /* If this acknowledges part of the segment, adjust the segment info for the acked part */
        else if (GT_SEQ(ack, ual->seq) && LE_SEQ(ack, ual->nextseq)) {
            ual->seq = ack;
            continue;
        }
        /* If this acknowledges a segment prior to this one, leave this segment alone and move on */
        else if (GT_SEQ(ual->nextseq,ack)) {
            prevual = ual;
            ual = ual->next;
            continue;
        }

        /* This segment is old, or an exact match.  Delete the segment from the list */
        ackcount++;
        tmpual=ual->next;

        if (tcpd->rev->scps_capable) {
          /* Track largest segment successfully sent for SNACK analysis*/
          if ((ual->nextseq - ual->seq) > tcpd->fwd->maxsizeacked) {
            tcpd->fwd->maxsizeacked = (ual->nextseq - ual->seq);
          }
        }

        if (!prevual) {
            tcpd->rev->segments = tmpual;
            TCP_UNACKED_FREE(ual);
            ual = tmpual;
        }
        else{
            prevual->next = tmpual;
            TCP_UNACKED_FREE(ual);
            ual = tmpual;
        }
    }

    /* how many bytes of data are there in flight after this frame
     * was sent
     */
    ual=tcpd->fwd->segments;
    if (tcp_track_bytes_in_flight && seglen!=0 && ual && tcpd->fwd->valid_bif) {
        guint32 first_seq, last_seq, in_flight;

        first_seq = ual->seq - tcpd->fwd->base_seq;
        last_seq = ual->nextseq - tcpd->fwd->base_seq;
        while (ual) {
            if ((ual->nextseq-tcpd->fwd->base_seq)>last_seq) {
                last_seq = ual->nextseq-tcpd->fwd->base_seq;
            }
            if ((ual->seq-tcpd->fwd->base_seq)<first_seq) {
                first_seq = ual->seq-tcpd->fwd->base_seq;
            }
            ual = ual->next;
        }
        in_flight = last_seq-first_seq;

        if (in_flight>0 && in_flight<2000000000) {
            if(!tcpd->ta) {
                tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->bytes_in_flight = in_flight;
        }
    }

}

/*
 * Prints results of the sequence number analysis concerning tcp segments
 * retransmitted or out-of-order
 */
static void
tcp_sequence_number_analysis_print_retransmission(packet_info * pinfo,
                          tvbuff_t * tvb,
                          proto_tree * flags_tree,
                          struct tcp_acked *ta
                          )
{
    proto_item * flags_item;

    /* TCP Retransmission */
    if (ta->flags & TCP_A_RETRANSMISSION) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_retransmission,
                                              tvb, 0, 0,
                                              "This frame is a (suspected) "
                                              "retransmission"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Retransmission (suspected)");

        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Retransmission] ");

        if (ta->rto_ts.secs || ta->rto_ts.nsecs) {
            flags_item = proto_tree_add_time(flags_tree, hf_tcp_analysis_rto,
                                             tvb, 0, 0, &ta->rto_ts);
            PROTO_ITEM_SET_GENERATED(flags_item);
            flags_item=proto_tree_add_uint(flags_tree, hf_tcp_analysis_rto_frame,
                                           tvb, 0, 0, ta->rto_frame);
            PROTO_ITEM_SET_GENERATED(flags_item);
        }
    }
    /* TCP Fast Retransmission */
    if (ta->flags & TCP_A_FAST_RETRANSMISSION) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_fast_retransmission,
                                              tvb, 0, 0,
                                              "This frame is a (suspected) fast"
                                              " retransmission"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Fast retransmission (suspected)");
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_retransmission,
                                              tvb, 0, 0,
                                              "This frame is a (suspected) "
                                              "retransmission"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Fast Retransmission] ");
    }
    /* TCP Out-Of-Order */
    if (ta->flags & TCP_A_OUT_OF_ORDER) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_out_of_order,
                                              tvb, 0, 0,
                                              "This frame is a (suspected) "
                                              "out-of-order segment"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN,
                               "Out-Of-Order segment");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Out-Of-Order] ");
    }
}

/* Prints results of the sequence number analysis concerning reused ports */
static void
tcp_sequence_number_analysis_print_reused(packet_info * pinfo,
                      tvbuff_t * tvb,
                      proto_tree * flags_tree,
                      struct tcp_acked *ta
                      )
{
    proto_item * flags_item;

    /* TCP Ports Reused */
    if (ta->flags & TCP_A_REUSED_PORTS) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_reused_ports,
                                              tvb, 0, 0,
                                              "A new tcp session is started with the same "
                                              "ports as an earlier session in this trace"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "TCP Port numbers reused for new session");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Port numbers reused] ");
    }
}

/* Prints results of the sequence number analysis concerning lost tcp segments */
static void
tcp_sequence_number_analysis_print_lost(packet_info * pinfo,
                    tvbuff_t * tvb,
                    proto_tree * flags_tree,
                    struct tcp_acked *ta
                    )
{
    proto_item * flags_item;

    /* TCP Lost Segment */
    if (ta->flags & TCP_A_LOST_PACKET) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_lost_packet,
                                              tvb, 0, 0,
                                              "A segment before this frame "
                                              "wasn't captured"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN,
                               "Previous segment not captured (common at capture start)");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Previous segment not captured] ");
    }
    /* TCP Ack lost segment */
    if (ta->flags & TCP_A_ACK_LOST_PACKET) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_ack_lost_packet,
                                              tvb, 0, 0,
                                              "This frame ACKs a segment we have "
                                              "not seen"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN,
                               "ACKed segment that wasn't captured (common at capture start)");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP ACKed unseen segment] ");
    }
}

/* Prints results of the sequence number analysis concerning tcp window */
static void
tcp_sequence_number_analysis_print_window(packet_info * pinfo,
                      tvbuff_t * tvb,
                      proto_tree * flags_tree,
                      struct tcp_acked *ta
                      )
{
    proto_item * flags_item;

    /* TCP Window Update */
    if (ta->flags & TCP_A_WINDOW_UPDATE) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_window_update,
                                              tvb, 0, 0,
                                              "This is a tcp window update"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_CHAT,
                               "Window update");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Window Update] ");
    }
    /* TCP Full Window */
    if (ta->flags & TCP_A_WINDOW_FULL) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_window_full,
                                              tvb, 0, 0,
                                              "The transmission window is now "
                                              "completely full"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN,
                               "Window is full");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Window Full] ");
    }
}

/* Prints results of the sequence number analysis concerning tcp keepalive */
static void
tcp_sequence_number_analysis_print_keepalive(packet_info * pinfo,
                      tvbuff_t * tvb,
                      proto_tree * flags_tree,
                      struct tcp_acked *ta
                      )
{
    proto_item * flags_item;

    /*TCP Keep Alive */
    if (ta->flags & TCP_A_KEEP_ALIVE) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_keep_alive,
                                              tvb, 0, 0,
                                              "This is a TCP keep-alive segment"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Keep-Alive");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Keep-Alive] ");
    }
    /* TCP Ack Keep Alive */
    if (ta->flags & TCP_A_KEEP_ALIVE_ACK) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_keep_alive_ack,
                                              tvb, 0, 0,
                                              "This is an ACK to a TCP keep-alive "
                                              "segment"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Keep-Alive ACK");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Keep-Alive ACK] ");
    }
}

/* Prints results of the sequence number analysis concerning tcp duplicate ack */
static void
tcp_sequence_number_analysis_print_duplicate(packet_info * pinfo,
                          tvbuff_t * tvb,
                          proto_tree * flags_tree,
                          struct tcp_acked *ta,
                          proto_tree * tree
                        )
{
    proto_item * flags_item;

    /* TCP Duplicate ACK */
    if (ta->dupack_num) {
        if (ta->flags & TCP_A_DUPLICATE_ACK ) {
            flags_item=proto_tree_add_none_format(flags_tree,
                                                  hf_tcp_analysis_duplicate_ack,
                                                  tvb, 0, 0,
                                                  "This is a TCP duplicate ack"
                );
            PROTO_ITEM_SET_GENERATED(flags_item);
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                                   "[TCP Dup ACK %u#%u] ",
                                   ta->dupack_frame,
                                   ta->dupack_num
                );

        }
        flags_item=proto_tree_add_uint(tree, hf_tcp_analysis_duplicate_ack_num,
                                       tvb, 0, 0, ta->dupack_num);
        PROTO_ITEM_SET_GENERATED(flags_item);
        flags_item=proto_tree_add_uint(tree, hf_tcp_analysis_duplicate_ack_frame,
                                       tvb, 0, 0, ta->dupack_frame);
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Duplicate ACK (#%u)",
                               ta->dupack_num
            );
    }
}

/* Prints results of the sequence number analysis concerning tcp zero window */
static void
tcp_sequence_number_analysis_print_zero_window(packet_info * pinfo,
                          tvbuff_t * tvb,
                          proto_tree * flags_tree,
                          struct tcp_acked *ta
                        )
{
    proto_item * flags_item;

    /* TCP Zero Window Probe */
    if (ta->flags & TCP_A_ZERO_WINDOW_PROBE) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_zero_window_probe,
                                              tvb, 0, 0,
                                              "This is a TCP zero-window-probe"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Zero window probe");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindowProbe] ");
    }
    /* TCP Zero Window */
    if (ta->flags&TCP_A_ZERO_WINDOW) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_zero_window,
                                              tvb, 0, 0,
                                              "This is a ZeroWindow segment"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN,
                               "Zero window");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindow] ");
    }
    /* TCP Zero Window Probe Ack */
    if (ta->flags & TCP_A_ZERO_WINDOW_PROBE_ACK) {
        flags_item=proto_tree_add_none_format(flags_tree,
                                              hf_tcp_analysis_zero_window_probe_ack,
                                              tvb, 0, 0,
                                              "This is an ACK to a TCP zero-window-probe"
            );
        PROTO_ITEM_SET_GENERATED(flags_item);
        expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE,
                               "Zero window probe ACK");
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP ZeroWindowProbeAck] ");
    }
}


/* Prints results of the sequence number analysis concerning how many bytes of data are in flight */
static void
tcp_sequence_number_analysis_print_bytes_in_flight(packet_info * pinfo _U_,
                          tvbuff_t * tvb _U_,
                          proto_tree * flags_tree _U_,
                          struct tcp_acked *ta
                        )
{
    proto_item * flags_item;

    if (tcp_track_bytes_in_flight) {
        flags_item=proto_tree_add_uint(flags_tree,
                                       hf_tcp_analysis_bytes_in_flight,
                                       tvb, 0, 0, ta->bytes_in_flight);

        PROTO_ITEM_SET_GENERATED(flags_item);
    }
}

static void
tcp_print_sequence_number_analysis(packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree,
                          struct tcp_analysis *tcpd, guint32 seq, guint32 ack)
{
    struct tcp_acked *ta = NULL;
    proto_item *item;
    proto_tree *tree;
    proto_tree *flags_tree=NULL;

    if (!tcpd) {
        return;
    }
    if(!tcpd->ta) {
        tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, FALSE, tcpd);
    }
    ta=tcpd->ta;
    if(!ta) {
        return;
    }

    item=proto_tree_add_item(parent_tree, hf_tcp_analysis, tvb, 0, 0, ENC_NA);
    PROTO_ITEM_SET_GENERATED(item);
    tree=proto_item_add_subtree(item, ett_tcp_analysis);

    /* encapsulate all proto_tree_add_xxx in ifs so we only print what
       data we actually have */
    if(ta->frame_acked) {
        item = proto_tree_add_uint(tree, hf_tcp_analysis_acks_frame,
            tvb, 0, 0, ta->frame_acked);
            PROTO_ITEM_SET_GENERATED(item);

        /* only display RTT if we actually have something we are acking */
        if( ta->ts.secs || ta->ts.nsecs ) {
            item = proto_tree_add_time(tree, hf_tcp_analysis_ack_rtt,
            tvb, 0, 0, &ta->ts);
                PROTO_ITEM_SET_GENERATED(item);
        }
    }

    if(ta->bytes_in_flight) {
        /* print results for amount of data in flight */
        tcp_sequence_number_analysis_print_bytes_in_flight(pinfo, tvb, tree, ta);
    }

    if(ta->flags) {
        item = proto_tree_add_item(tree, hf_tcp_analysis_flags, tvb, 0, 0, ENC_NA);
        PROTO_ITEM_SET_GENERATED(item);
        flags_tree=proto_item_add_subtree(item, ett_tcp_analysis);

        /* print results for reused tcp ports */
        tcp_sequence_number_analysis_print_reused(pinfo, tvb, flags_tree, ta);

        /* print results for retransmission and out-of-order segments */
        tcp_sequence_number_analysis_print_retransmission(pinfo, tvb, flags_tree, ta);

        /* print results for lost tcp segments */
        tcp_sequence_number_analysis_print_lost(pinfo, tvb, flags_tree, ta);

        /* print results for tcp window information */
        tcp_sequence_number_analysis_print_window(pinfo, tvb, flags_tree, ta);

        /* print results for tcp keep alive information */
        tcp_sequence_number_analysis_print_keepalive(pinfo, tvb, flags_tree, ta);

        /* print results for tcp duplicate acks */
        tcp_sequence_number_analysis_print_duplicate(pinfo, tvb, flags_tree, ta, tree);

        /* print results for tcp zero window  */
        tcp_sequence_number_analysis_print_zero_window(pinfo, tvb, flags_tree, ta);

    }

}

static void
print_tcp_fragment_tree(fragment_data *ipfd_head, proto_tree *tree, proto_tree *tcp_tree, packet_info *pinfo, tvbuff_t *next_tvb)
{
    proto_item *tcp_tree_item, *frag_tree_item;

    /*
     * The subdissector thought it was completely
     * desegmented (although the stuff at the
     * end may, in turn, require desegmentation),
     * so we show a tree with all segments.
     */
    show_fragment_tree(ipfd_head, &tcp_segment_items,
        tree, pinfo, next_tvb, &frag_tree_item);
    /*
     * The toplevel fragment subtree is now
     * behind all desegmented data; move it
     * right behind the TCP tree.
     */
    tcp_tree_item = proto_tree_get_parent(tcp_tree);
    if(frag_tree_item && tcp_tree_item) {
        proto_tree_move_item(tree, tcp_tree_item, frag_tree_item);
    }
}

/* **************************************************************************
 * End of tcp sequence number analysis
 * **************************************************************************/


/* Minimum TCP header length. */
#define TCPH_MIN_LEN            20

/* Desegmentation of TCP streams */
/* table to hold defragmented TCP streams */
static GHashTable *tcp_fragment_table = NULL;

/* functions to trace tcp segments */
/* Enable desegmenting of TCP streams */
static gboolean tcp_desegment = TRUE;

static void
desegment_tcp(tvbuff_t *tvb, packet_info *pinfo, int offset,
              guint32 seq, guint32 nxtseq,
              guint32 sport, guint32 dport,
              proto_tree *tree, proto_tree *tcp_tree,
              struct tcp_analysis *tcpd)
{
    struct tcpinfo *tcpinfo = pinfo->private_data;
    fragment_data *ipfd_head;
    int last_fragment_len;
    gboolean must_desegment;
    gboolean called_dissector;
    int another_pdu_follows;
    int deseg_offset;
    guint32 deseg_seq;
    gint nbytes;
    proto_item *item;
    struct tcp_multisegment_pdu *msp;
    gboolean cleared_writable = col_get_writable(pinfo->cinfo);

again:
    ipfd_head = NULL;
    last_fragment_len = 0;
    must_desegment = FALSE;
    called_dissector = FALSE;
    another_pdu_follows = 0;
    msp = NULL;

    /*
     * Initialize these to assume no desegmentation.
     * If that's not the case, these will be set appropriately
     * by the subdissector.
     */
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    /*
     * Initialize this to assume that this segment will just be
     * added to the middle of a desegmented chunk of data, so
     * that we should show it all as data.
     * If that's not the case, it will be set appropriately.
     */
    deseg_offset = offset;

    if (tcpd) {
        /* Have we seen this PDU before (and is it the start of a multi-
         * segment PDU)?
         */
        if ((msp = se_tree_lookup32(tcpd->fwd->multisegment_pdus, seq))) {
            const char* str;

            /* Yes.  This could be because we've dissected this frame before
             * or because this is a retransmission of a previously-seen
             * segment.  Either way, we don't need to hand it off to the
             * subdissector and we certainly don't want to re-add it to the
             * multisegment_pdus list: if we did, subsequent lookups would
             * find this retransmission instead of the original transmission
             * (breaking desegmentation if we'd already linked other segments
             * to the original transmission's entry).
             */

            if (msp->first_frame == PINFO_FD_NUM(pinfo)) {
                str = "";
                col_set_str(pinfo->cinfo, COL_INFO, "[TCP segment of a reassembled PDU]");
            } else {
                str = "Retransmitted ";
                /* TCP analysis already flags this (in COL_INFO) as a retransmission--if it's enabled */
            }

            nbytes = tvb_reported_length_remaining(tvb, offset);
            proto_tree_add_bytes_format(tcp_tree, hf_tcp_data, tvb, offset,
                nbytes, NULL, "%sTCP segment data (%u byte%s)", str, nbytes,
                plurality(nbytes, "", "s"));
            return;
        }

        /* Else, find the most previous PDU starting before this sequence number */
        msp = se_tree_lookup32_le(tcpd->fwd->multisegment_pdus, seq-1);
    }

    if (msp && msp->seq <= seq && msp->nxtpdu > seq) {
        int len;

        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame=pinfo->fd->num;
            msp->last_frame_time=pinfo->fd->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        if (msp->flags&MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /* The dissector asked for the entire segment */
            len = tvb_length_remaining(tvb, offset);
        } else {
            len = MIN(nxtseq, msp->nxtpdu) - seq;
        }
        last_fragment_len = len;

        ipfd_head = fragment_add(tvb, offset, pinfo, msp->first_frame,
                                 tcp_fragment_table, seq - msp->seq, len,
                                 (LT_SEQ (nxtseq,msp->nxtpdu)) );

        if (!PINFO_FD_VISITED(pinfo)
        && msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            msp->flags &= (~MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT);

            /* If we consumed the entire segment there is no
             * other pdu starting anywhere inside this segment.
             * So update nxtpdu to point at least to the start
             * of the next segment.
             * (If the subdissector asks for even more data we
             * will advance nxtpdu even further later down in
             * the code.)
             */
            msp->nxtpdu = nxtseq;
        }

        if( (msp->nxtpdu < nxtseq)
        &&  (msp->nxtpdu >= seq)
        &&  (len > 0)) {
            another_pdu_follows=msp->nxtpdu - seq;
        }
    } else {
        /* This segment was not found in our table, so it doesn't
         * contain a continuation of a higher-level PDU.
         * Call the normal subdissector.
         */

        /*
         * Supply the sequence number of this segment. We set this here
         * because this segment could be after another in the same packet,
         * in which case seq was incremented at the end of the loop.
         */
        tcpinfo->seq = seq;

        process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree,
                            sport, dport, 0, 0, FALSE, tcpd);
        called_dissector = TRUE;

        /* Did the subdissector ask us to desegment some more data
         * before it could handle the packet?
         * If so we have to create some structures in our table but
         * this is something we only do the first time we see this
         * packet.
         */
        if(pinfo->desegment_len) {
            if (!PINFO_FD_VISITED(pinfo))
                must_desegment = TRUE;

            /*
             * Set "deseg_offset" to the offset in "tvb"
             * of the first byte of data that the
             * subdissector didn't process.
             */
            deseg_offset = offset + pinfo->desegment_offset;
        }

        /* Either no desegmentation is necessary, or this is
         * segment contains the beginning but not the end of
         * a higher-level PDU and thus isn't completely
         * desegmented.
         */
        ipfd_head = NULL;
    }


    /* is it completely desegmented? */
    if (ipfd_head) {
        /*
         * Yes, we think it is.
         * We only call subdissector for the last segment.
         * Note that the last segment may include more than what
         * we needed.
         */
        if(ipfd_head->reassembled_in == pinfo->fd->num) {
            /*
             * OK, this is the last segment.
             * Let's call the subdissector with the desegmented
             * data.
             */
            tvbuff_t *next_tvb;
            int old_len;

            /* create a new TVB structure for desegmented data */
            next_tvb = tvb_new_child_real_data(tvb, ipfd_head->data,
                                               ipfd_head->datalen,
                                               ipfd_head->datalen);

            /* add desegmented data to the data source list */
            add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

            /*
             * Supply the sequence number of the first of the
             * reassembled bytes.
             */
            tcpinfo->seq = msp->seq;

            /* indicate that this is reassembled data */
            tcpinfo->is_reassembled = TRUE;

            /* call subdissector */
            process_tcp_payload(next_tvb, 0, pinfo, tree, tcp_tree, sport,
                                dport, 0, 0, FALSE, tcpd);
            called_dissector = TRUE;

            /*
             * OK, did the subdissector think it was completely
             * desegmented, or does it think we need even more
             * data?
             */
            old_len = (int)(tvb_reported_length(next_tvb) - last_fragment_len);
            if (pinfo->desegment_len &&
                pinfo->desegment_offset<=old_len) {
                /*
                 * "desegment_len" isn't 0, so it needs more
                 * data for something - and "desegment_offset"
                 * is before "old_len", so it needs more data
                 * to dissect the stuff we thought was
                 * completely desegmented (as opposed to the
                 * stuff at the beginning being completely
                 * desegmented, but the stuff at the end
                 * being a new higher-level PDU that also
                 * needs desegmentation).
                 */
                fragment_set_partial_reassembly(pinfo,msp->first_frame, tcp_fragment_table);

                /* Update msp->nxtpdu to point to the new next
                 * pdu boundary.
                 */
                if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                    /* We want reassembly of at least one
                     * more segment so set the nxtpdu
                     * boundary to one byte into the next
                     * segment.
                     * This means that the next segment
                     * will complete reassembly even if it
                     * is only one single byte in length.
                     */
                    msp->nxtpdu = seq + tvb_reported_length_remaining(tvb, offset) + 1;
                    msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
                } else if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                    tcpd->fwd->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
                } else {
                    msp->nxtpdu=seq + last_fragment_len + pinfo->desegment_len;
                }

                /* Since we need at least some more data
                 * there can be no pdu following in the
                 * tail of this segment.
                 */
                another_pdu_follows = 0;
                offset += last_fragment_len;
                seq += last_fragment_len;
                if (tvb_length_remaining(tvb, offset) > 0)
                    goto again;
            } else {
                /*
                 * Show the stuff in this TCP segment as
                 * just raw TCP segment data.
                 */
                nbytes = another_pdu_follows > 0
                    ? another_pdu_follows
                    : tvb_reported_length_remaining(tvb, offset);
                proto_tree_add_bytes_format(tcp_tree, hf_tcp_data, tvb, offset,
                    nbytes, NULL, "TCP segment data (%u byte%s)", nbytes,
                    plurality(nbytes, "", "s"));

                print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);

                /* Did the subdissector ask us to desegment
                 * some more data?  This means that the data
                 * at the beginning of this segment completed
                 * a higher-level PDU, but the data at the
                 * end of this segment started a higher-level
                 * PDU but didn't complete it.
                 *
                 * If so, we have to create some structures
                 * in our table, but this is something we
                 * only do the first time we see this packet.
                 */
                if(pinfo->desegment_len) {
                    if (!PINFO_FD_VISITED(pinfo))
                        must_desegment = TRUE;

                    /* The stuff we couldn't dissect
                     * must have come from this segment,
                     * so it's all in "tvb".
                     *
                     * "pinfo->desegment_offset" is
                     * relative to the beginning of
                     * "next_tvb"; we want an offset
                     * relative to the beginning of "tvb".
                     *
                     * First, compute the offset relative
                     * to the *end* of "next_tvb" - i.e.,
                     * the number of bytes before the end
                     * of "next_tvb" at which the
                     * subdissector stopped.  That's the
                     * length of "next_tvb" minus the
                     * offset, relative to the beginning
                     * of "next_tvb, at which the
                     * subdissector stopped.
                     */
                    deseg_offset = ipfd_head->datalen - pinfo->desegment_offset;

                    /* "tvb" and "next_tvb" end at the
                     * same byte of data, so the offset
                     * relative to the end of "next_tvb"
                     * of the byte at which we stopped
                     * is also the offset relative to
                     * the end of "tvb" of the byte at
                     * which we stopped.
                     *
                     * Convert that back into an offset
                     * relative to the beginning of
                     * "tvb", by taking the length of
                     * "tvb" and subtracting the offset
                     * relative to the end.
                     */
                    deseg_offset = tvb_reported_length(tvb) - deseg_offset;
                }
            }
        }
    }

    if (must_desegment) {
        /* If the dissector requested "reassemble until FIN"
         * just set this flag for the flow and let reassembly
         * proceed at normal.  We will check/pick up these
         * reassembled PDUs later down in dissect_tcp() when checking
         * for the FIN flag.
         */
        if (tcpd && pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
            tcpd->fwd->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
        }
        /*
         * The sequence number at which the stuff to be desegmented
         * starts is the sequence number of the byte at an offset
         * of "deseg_offset" into "tvb".
         *
         * The sequence number of the byte at an offset of "offset"
         * is "seq", i.e. the starting sequence number of this
         * segment, so the sequence number of the byte at
         * "deseg_offset" is "seq + (deseg_offset - offset)".
         */
        deseg_seq = seq + (deseg_offset - offset);

        if (tcpd && ((nxtseq - deseg_seq) <= 1024*1024)
            && (!PINFO_FD_VISITED(pinfo))) {
            if(pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                /* The subdissector asked to reassemble using the
                 * entire next segment.
                 * Just ask reassembly for one more byte
                 * but set this msp flag so we can pick it up
                 * above.
                 */
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo, deseg_seq,
                    nxtseq+1, tcpd->fwd->multisegment_pdus);
                msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
            } else {
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+pinfo->desegment_len, tcpd->fwd->multisegment_pdus);
            }

            /* add this segment as the first one for this new pdu */
            fragment_add(tvb, deseg_offset, pinfo, msp->first_frame,
                         tcp_fragment_table, 0, nxtseq - deseg_seq,
                         LT_SEQ(nxtseq, msp->nxtpdu));
        }
    }

    if (!called_dissector || pinfo->desegment_len != 0) {
        if (ipfd_head != NULL && ipfd_head->reassembled_in != 0 &&
            !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
            /*
             * We know what frame this PDU is reassembled in;
             * let the user know.
             */
            item = proto_tree_add_uint(tcp_tree, hf_tcp_reassembled_in, tvb, 0,
                                       0, ipfd_head->reassembled_in);
            PROTO_ITEM_SET_GENERATED(item);
        }

        /*
         * Either we didn't call the subdissector at all (i.e.,
         * this is a segment that contains the middle of a
         * higher-level PDU, but contains neither the beginning
         * nor the end), or the subdissector couldn't dissect it
         * all, as some data was missing (i.e., it set
         * "pinfo->desegment_len" to the amount of additional
         * data it needs).
         */
        if (pinfo->desegment_offset == 0) {
            /*
             * It couldn't, in fact, dissect any of it (the
             * first byte it couldn't dissect is at an offset
             * of "pinfo->desegment_offset" from the beginning
             * of the payload, and that's 0).
             * Just mark this as TCP.
             */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");
            col_set_str(pinfo->cinfo, COL_INFO, "[TCP segment of a reassembled PDU]");
        }

        /*
         * Show what's left in the packet as just raw TCP segment
         * data.
         * XXX - remember what protocol the last subdissector
         * was, and report it as a continuation of that, instead?
         */
        nbytes = tvb_reported_length_remaining(tvb, deseg_offset);
        proto_tree_add_bytes_format(tcp_tree, hf_tcp_data, tvb, deseg_offset,
            -1, NULL, "TCP segment data (%u byte%s)", nbytes,
            plurality(nbytes, "", "s"));
    }
    pinfo->can_desegment = 0;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    if(another_pdu_follows) {
        /* there was another pdu following this one. */
        pinfo->can_desegment = 2;
        /* we also have to prevent the dissector from changing the
         * PROTOCOL and INFO columns since what follows may be an
         * incomplete PDU and we don't want it be changed back from
         *  <Protocol>   to <TCP>
         * XXX There is no good way to block the PROTOCOL column
         * from being changed yet so we set the entire row unwritable.
         * The flag cleared_writable stores the initial state.
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
        cleared_writable |= col_get_writable(pinfo->cinfo);
        col_set_writable(pinfo->cinfo, FALSE);
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    } else {
        /* remove any blocking set above otherwise the
         * proto,colinfo tap will break
         */
        if(cleared_writable) {
            col_set_writable(pinfo->cinfo, TRUE);
        }
    }
}

/*
 * Loop for dissecting PDUs within a TCP stream; assumes that a PDU
 * consists of a fixed-length chunk of data that contains enough information
 * to determine the length of the PDU, followed by rest of the PDU.
 *
 * The first three arguments are the arguments passed to the dissector
 * that calls this routine.
 *
 * "proto_desegment" is the dissector's flag controlling whether it should
 * desegment PDUs that cross TCP segment boundaries.
 *
 * "fixed_len" is the length of the fixed-length part of the PDU.
 *
 * "get_pdu_len()" is a routine called to get the length of the PDU from
 * the fixed-length part of the PDU; it's passed "pinfo", "tvb" and "offset".
 *
 * "dissect_pdu()" is the routine to dissect a PDU.
 */
void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 gboolean proto_desegment, guint fixed_len,
                 guint (*get_pdu_len)(packet_info *, tvbuff_t *, int),
                 dissector_t dissect_pdu)
{
    volatile int offset = 0;
    int offset_before;
    guint length_remaining;
    guint plen;
    guint length;
    tvbuff_t *next_tvb;
    proto_item *item=NULL;
    void *pd_save;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        /*
         * We use "tvb_ensure_length_remaining()" to make sure there actually
         * *is* data remaining.  The protocol we're handling could conceivably
         * consists of a sequence of fixed-length PDUs, and therefore the
         * "get_pdu_len" routine might not actually fetch anything from
         * the tvbuff, and thus might not cause an exception to be thrown if
         * we've run past the end of the tvbuff.
         *
         * This means we're guaranteed that "length_remaining" is positive.
         */
        length_remaining = tvb_ensure_length_remaining(tvb, offset);

        /*
         * Can we do reassembly?
         */
        if (proto_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the fixed-length part of the PDU split across segment
             * boundaries?
             */
            if (length_remaining < fixed_len) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us and that we need "some more
                 * data."  Don't tell it exactly how many bytes we need because
                 * if/when we ask for even more (after the header) that will
                 * break reassembly.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return;
            }
        }

        /*
         * Get the length of the PDU.
         */
        plen = (*get_pdu_len)(pinfo, tvb, offset);
        if (plen < fixed_len) {
            /*
             * Either:
             *
             *  1) the length value extracted from the fixed-length portion
             *     doesn't include the fixed-length portion's length, and
             *     was so large that, when the fixed-length portion's
             *     length was added to it, the total length overflowed;
             *
             *  2) the length value extracted from the fixed-length portion
             *     includes the fixed-length portion's length, and the value
             *     was less than the fixed-length portion's length, i.e. it
             *     was bogus.
             *
             * Report this as a bounds error.
             */
            show_reported_bounds_error(tvb, pinfo, tree);
            return;
        }

        /*
         * Do not display the the PDU length if it crosses the boundary of the
         * packet and no more packets are available.
         *
         * XXX - we don't necessarily know whether more packets are
         * available; we might be doing a one-pass read through the
         * capture in TShark, or we might be doing a live capture in
         * Wireshark.
         */
#if 0
        if (length_remaining >= plen || there are more packets)
        {
#endif
                /*
                 * Display the PDU length as a field
                 */
                item=proto_tree_add_uint(pinfo->tcp_tree, hf_tcp_pdu_size,
                                         tvb, offset, plen, plen);
                PROTO_ITEM_SET_GENERATED(item);
#if 0
        } else {
                item = proto_tree_add_text(pinfo->tcp_tree, tvb, offset, -1,
                    "PDU Size: %u cut short at %u",plen,length_remaining);
                PROTO_ITEM_SET_GENERATED(item);
        }
#endif


        /* give a hint to TCP where the next PDU starts
         * so that it can attempt to find it in case it starts
         * somewhere in the middle of a segment.
         */
        if(!pinfo->fd->flags.visited && tcp_analyze_seq) {
            guint remaining_bytes;
            remaining_bytes=tvb_reported_length_remaining(tvb, offset);
            if(plen>remaining_bytes) {
                pinfo->want_pdu_tracking=2;
                pinfo->bytes_until_next_pdu=plen-remaining_bytes;
            }
        }

        /*
         * Can we do reassembly?
         */
        if (proto_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the PDU split across segment boundaries?
             */
            if (length_remaining < plen) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us, and how many more bytes we
                 * need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = plen - length_remaining;
                return;
            }
        }

        /*
         * Construct a tvbuff containing the amount of the payload we have
         * available.  Make its reported length the amount of data in the PDU.
         *
         * XXX - if reassembly isn't enabled. the subdissector will throw a
         * BoundsError exception, rather than a ReportedBoundsError exception.
         * We really want a tvbuff where the length is "length", the reported
         * length is "plen", and the "if the snapshot length were infinite"
         * length is the minimum of the reported length of the tvbuff handed
         * to us and "plen", with a new type of exception thrown if the offset
         * is within the reported length but beyond that third length, with
         * that exception getting the "Unreassembled Packet" error.
         */
        length = length_remaining;
        if (length > plen)
            length = plen;
        next_tvb = tvb_new_subset(tvb, offset, length, plen);

        /*
         * Dissect the PDU.
         *
         * Catch the ReportedBoundsError exception; if this particular message
         * happens to get a ReportedBoundsError exception, that doesn't mean
         * that we should stop dissecting PDUs within this frame or chunk of
         * reassembled data.
         *
         * If it gets a BoundsError, we can stop, as there's nothing more to
         * see, so we just re-throw it.
         */
        pd_save = pinfo->private_data;
        TRY {
            (*dissect_pdu)(next_tvb, pinfo, tree);
        }
        CATCH(BoundsError) {
            RETHROW;
        }
        CATCH(ReportedBoundsError) {
            /*  Restore the private_data structure in case one of the
             *  called dissectors modified it (and, due to the exception,
             *  was unable to restore it).
             */
            pinfo->private_data = pd_save;
            show_reported_bounds_error(tvb, pinfo, tree);
        }
        ENDTRY;

        /*
         * Step to the next PDU.
         * Make sure we don't overflow.
         */
        offset_before = offset;
        offset += plen;
        if (offset <= offset_before)
            break;
    }
}

static void
tcp_info_append_uint(packet_info *pinfo, const char *abbrev, guint32 val)
{
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%u", abbrev, val);
}

static void
dissect_tcpopt_exp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;

    item = proto_tree_add_item(opt_tree, hf_tcp_option_exp, tvb,
        offset, optlen, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_exp);
    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_exp_data, tvb,
        offset + 2, optlen - 2, ENC_NA);
    tcp_info_append_uint(pinfo, "Expxx", TRUE);
}


static void
dissect_tcpopt_sack_perm(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;

    item = proto_tree_add_boolean(opt_tree, hf_tcp_option_sack_perm, tvb, offset,
                           optlen, TRUE);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_sack_perm);
    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    tcp_info_append_uint(pinfo, "SACK_PERM", TRUE);
}

static void
dissect_tcpopt_mss(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;
    guint16 mss;

    mss = tvb_get_ntohs(tvb, offset + 2);
    item = proto_tree_add_none_format(opt_tree, hf_tcp_option_mss, tvb, offset,
        optlen, "%s: %u bytes", optp->name, mss);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_mss);
    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_mss_val, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    tcp_info_append_uint(pinfo, "MSS", mss);
}

/* The window scale extension is defined in RFC 1323 */
static void
dissect_tcpopt_wscale(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    guint8 val, shift;
    proto_item *wscale_pi, *gen_pi;
    proto_tree *wscale_tree;
    struct tcp_analysis *tcpd=NULL;

    tcpd=get_tcp_conversation_data(NULL,pinfo);

    wscale_pi = proto_tree_add_text(opt_tree, tvb, offset, 3, "Window scale: ");
    wscale_tree = proto_item_add_subtree(wscale_pi, ett_tcp_option_wscale);

    proto_tree_add_item(wscale_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(wscale_tree, hf_tcp_option_len, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(wscale_tree, hf_tcp_option_wscale_shift, tvb, offset, 1,
                        ENC_NA);
    shift = tvb_get_guint8(tvb, offset);

    gen_pi = proto_tree_add_uint(wscale_tree, hf_tcp_option_wscale_multiplier, tvb,
                                 offset, 1, 1 << shift);
    PROTO_ITEM_SET_GENERATED(gen_pi);
    val = tvb_get_guint8(tvb, offset);

    proto_item_append_text(wscale_pi, "%u (multiply by %u)", val, 1 << shift);

    tcp_info_append_uint(pinfo, "WS", 1 << shift);

    if(!pinfo->fd->flags.visited) {
        pdu_store_window_scale_option(shift, tcpd);
    }
}

static void
dissect_tcpopt_sack(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data)
{
    proto_tree *field_tree = NULL;
    proto_item *tf=NULL;
    proto_item *hidden_item;
    guint32 leftedge, rightedge;
    struct tcp_analysis *tcpd=NULL;
    struct tcpheader *tcph = (struct tcpheader *)data;
    guint32 base_ack=0;
    guint  num_sack_ranges = 0;

    if(tcp_analyze_seq && tcp_relative_seq) {
        /* find(or create if needed) the conversation for this tcp session */
        tcpd=get_tcp_conversation_data(NULL,pinfo);

        if (tcpd) {
            base_ack=tcpd->rev->base_seq;
        }
    }

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s:", optp->name);
    offset += 2;    /* skip past type and length */
    optlen -= 2;    /* subtract size of type and length */
    while (optlen > 0) {
        if (field_tree == NULL) {
            /* Haven't yet made a subtree out of this option.  Do so. */
            field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
            hidden_item = proto_tree_add_boolean(field_tree, hf_tcp_option_sack, tvb,
                                                 offset, optlen, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        if (optlen < 4) {
            proto_tree_add_text(field_tree, tvb, offset,      optlen,
                                "(suboption would go past end of option)");
            break;
        }
        leftedge = tvb_get_ntohl(tvb, offset)-base_ack;
        proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_sle, tvb,
                                   offset, 4, leftedge,
                                   "left edge = %u%s", leftedge,
                                   tcp_relative_seq ? " (relative)" : "");

        optlen -= 4;
        if (optlen < 4) {
            proto_tree_add_text(field_tree, tvb, offset,      optlen,
                                "(suboption would go past end of option)");
            break;
        }
        /* XXX - check whether it goes past end of packet */
        rightedge = tvb_get_ntohl(tvb, offset + 4)-base_ack;
        optlen -= 4;
        proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_sre, tvb,
                                   offset+4, 4, rightedge,
                                   "right edge = %u%s", rightedge,
                                   tcp_relative_seq ? " (relative)" : "");
        tcp_info_append_uint(pinfo, "SLE", leftedge);
        tcp_info_append_uint(pinfo, "SRE", rightedge);
        num_sack_ranges++;

        /* Update tap info */
        if (tcph != NULL && (tcph->num_sack_ranges < MAX_TCP_SACK_RANGES)) {
            tcph->sack_left_edge[tcph->num_sack_ranges] = leftedge;
            tcph->sack_right_edge[tcph->num_sack_ranges] = rightedge;
            tcph->num_sack_ranges++;
        }

        proto_item_append_text(field_tree, " %u-%u", leftedge, rightedge);
        offset += 8;
    }

    /* Show number of SACK ranges in this option as a generated field */
    tf = proto_tree_add_uint(field_tree, hf_tcp_option_sack_range_count,
                             tvb, 0, 0, num_sack_ranges);
    PROTO_ITEM_SET_GENERATED(tf);
}

static void
dissect_tcpopt_echo(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *hidden_item;
    guint32 echo;

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    echo = tvb_get_ntohl(tvb, offset + 2);
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_echo, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset,      optlen,
                        "%s: %u", optp->name, echo);
    tcp_info_append_uint(pinfo, "ECHO", echo);
}

/* If set, do not put the TCP timestamp information on the summary line */
static gboolean tcp_ignore_timestamps = FALSE;

static void
dissect_tcpopt_timestamp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *ts_tree;
    guint32 ts_val, ts_ecr;

    ti = proto_tree_add_text(opt_tree, tvb, offset, 10, "Timestamps: ");
    ts_tree = proto_item_add_subtree(ti, ett_tcp_option_timestamp);

    proto_tree_add_item(ts_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(ts_tree, hf_tcp_option_len, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(ts_tree,  hf_tcp_option_timestamp_tsval, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    ts_val = tvb_get_ntohl(tvb, offset);
    offset += 4;

    proto_tree_add_item(ts_tree,  hf_tcp_option_timestamp_tsecr, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    ts_ecr = tvb_get_ntohl(tvb, offset);
    /* offset += 4; */

    proto_item_append_text(ti, "TSval %u, TSecr %u", ts_val, ts_ecr);
    if (tcp_ignore_timestamps == FALSE) {
        tcp_info_append_uint(pinfo, "TSval", ts_val);
        tcp_info_append_uint(pinfo, "TSecr", ts_ecr);
    }
}

/*
 * The TCP Extensions for Multipath Operation with Multiple Addresses
 * are defined in draft-ietf-mptcp-multiaddressed-04
 *
 * <http://tools.ietf.org/html/draft-ief-mptcp-multiaddressed-04>
 *
 * Author: Andrei Maruseac <andrei.maruseac@intel.com>
 */
static void
dissect_tcpopt_mptcp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *mptcp_tree;

    proto_tree *mptcp_flags_tree;
    guint8 subtype;
    guint8 index;
    guint8 flags;
    guint8 ipver;

    ti = proto_tree_add_text(opt_tree, tvb, offset, optlen, "Multipath TCP");
    mptcp_tree = proto_item_add_subtree(ti, ett_tcp_option_mptcp);

    proto_tree_add_item(mptcp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mptcp_tree, hf_tcp_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_subtype, tvb,
                        offset, 1, ENC_BIG_ENDIAN);

    subtype = tvb_get_guint8(tvb, offset) >> 4;
    proto_item_append_text(ti, ": %s", val_to_str(subtype, mptcp_subtype_vs, "Unknown (%d)"));
    switch (subtype) {
        case TCPOPT_MPTCP_MP_CAPABLE:
            proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_version, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            flags = tvb_get_guint8(tvb, offset);
            ti = proto_tree_add_uint(mptcp_tree, hf_tcp_option_mptcp_flags, tvb,
                        offset, 1, flags);
            mptcp_flags_tree = proto_item_add_subtree(ti, ett_tcp_option_mptcp);

            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_C_flag,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_S_flag,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if (optlen == 12 || optlen == 20) {
                proto_tree_add_item(mptcp_tree,
                        hf_tcp_option_mptcp_sender_key, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
            }

            if (optlen == 20) {
                proto_tree_add_item(mptcp_tree,
                        hf_tcp_option_mptcp_recv_key, tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            break;

        case TCPOPT_MPTCP_MP_JOIN:
            switch (optlen) {
                case 12:
                    flags = tvb_get_guint8(tvb, offset) & 0x01;
                    ti = proto_tree_add_uint(mptcp_tree,
                            hf_tcp_option_mptcp_flags, tvb,
                            offset, 1, flags);
                    mptcp_flags_tree = proto_item_add_subtree(ti,
                            ett_tcp_option_mptcp);

                    proto_tree_add_item(mptcp_flags_tree,
                            hf_tcp_option_mptcp_B_flag, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_address_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_recv_token, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                    offset += 4;

                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_sender_rand, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                    break;

                case 16:
                    flags = tvb_get_guint8(tvb, offset) & 0x01;
                    ti = proto_tree_add_uint(mptcp_tree,
                            hf_tcp_option_mptcp_flags, tvb,
                            offset, 1, flags);
                    mptcp_flags_tree = proto_item_add_subtree(ti,
                            ett_tcp_option_mptcp);

                    proto_tree_add_item(mptcp_flags_tree,
                            hf_tcp_option_mptcp_B_flag, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_address_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_sender_trunc_mac, tvb, offset,
                            8, ENC_BIG_ENDIAN);
                    offset += 8;

                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_sender_rand, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                    break;

                case 24:
                    offset += 2;
                    for (index = 0; index < 5; index++) {
                        proto_tree_add_item(mptcp_tree,
                                hf_tcp_option_mptcp_sender_mac, tvb, offset,
                                4, ENC_BIG_ENDIAN);
                        offset += 4;
                    }
                    break;

                default:
                    break;
            }
            break;

        case TCPOPT_MPTCP_DSS:
            offset += 1;
            flags = tvb_get_guint8(tvb, offset) & 0x1F;
            ti = proto_tree_add_uint(mptcp_tree, hf_tcp_option_mptcp_flags, tvb,
                            offset, 1, flags);
            mptcp_flags_tree = proto_item_add_subtree(ti, ett_tcp_option_mptcp);

            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_F_flag,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_m_flag,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_M_flag,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_a_flag,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_A_flag,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if (flags & 1) {
                if (flags & 2) {
                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_data_ack, tvb, offset,
                            8, ENC_BIG_ENDIAN);
                    offset += 8;
                } else {
                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_data_ack, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                    offset += 4;
                }
            }

            if (flags & 4) {
                if (flags & 8) {
                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_data_seq_no, tvb, offset,
                            8, ENC_BIG_ENDIAN);
                    offset += 8;
                } else {
                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_data_seq_no, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                    offset += 4;
                }

                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_subflow_seq_no, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_data_lvl_len, tvb, offset,
                            2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_checksum, tvb, offset,
                            2, ENC_BIG_ENDIAN);
            }
            break;

        case TCPOPT_MPTCP_ADD_ADDR:
            proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_ipver, tvb, offset, 1, ENC_BIG_ENDIAN);
            ipver = tvb_get_guint8(tvb, offset) & 0x0F;
            offset += 1;

            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_address_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            switch (ipver) {
                case 4:
                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    break;

                case 6:
                    proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_ipv6, tvb, offset, 16, ENC_NA);
                    offset += 16;
                    break;

                default:
                    break;
            }

            if (optlen % 4 == 2) {
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            }
            break;

        case TCPOPT_MPTCP_REMOVE_ADDR:
            offset += 1;
            proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_address_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
            break;

        case TCPOPT_MPTCP_MP_PRIO:
            flags = tvb_get_guint8(tvb, offset) & 0x01;
            ti = proto_tree_add_uint(mptcp_tree, hf_tcp_option_mptcp_flags, tvb,
                            offset, 1, flags);
            mptcp_flags_tree = proto_item_add_subtree(ti, ett_tcp_option_mptcp);

            proto_tree_add_item(mptcp_flags_tree, hf_tcp_option_mptcp_B_flag,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if (optlen == 4) {
                proto_tree_add_item(mptcp_tree,
                        hf_tcp_option_mptcp_address_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            break;

        case TCPOPT_MPTCP_MP_FAIL:
            offset += 1;
            offset += 1;
            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_data_seq_no, tvb, offset, 8, ENC_BIG_ENDIAN);
            break;

        default:
            break;
    }
}

static void
dissect_tcpopt_cc(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *hidden_item;
    guint32 cc;

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    cc = tvb_get_ntohl(tvb, offset + 2);
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_cc, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset,      optlen,
                        "%s: %u", optp->name, cc);
    tcp_info_append_uint(pinfo, "CC", cc);
}

static void
dissect_tcpopt_qs(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{

    proto_item *hidden_item;

    guint8 rate = tvb_get_guint8(tvb, offset + 2) & 0x0f;

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_qs, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset,      optlen,
                        "%s: Rate response, %s, TTL diff %u ", optp->name,
                        val_to_str_ext_const(rate, &qs_rate_vals_ext, "Unknown"),
                        tvb_get_guint8(tvb, offset + 3));
    col_append_fstr(pinfo->cinfo, COL_INFO, " QSresp=%s", val_to_str_ext_const(rate, &qs_rate_vals_ext, "Unknown"));
}


static void
dissect_tcpopt_scps(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
            int offset, guint optlen, packet_info *pinfo,
            proto_tree *opt_tree, void *data _U_)
{
    struct tcp_analysis *tcpd;
    proto_tree *field_tree = NULL;
    tcp_flow_t *flow;
    int         direction;
    proto_item *tf = NULL, *hidden_item;
    guint8      capvector;
    guint8      connid;

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tcpd = get_tcp_conversation_data(NULL,pinfo);

    /* check direction and get ua lists */
    direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);

    /* if the addresses are equal, match the ports instead */
    if(direction==0) {
        direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }

    if(direction>=0)
        flow =&(tcpd->flow1);
    else
        flow =&(tcpd->flow2);

    /* If the option length == 4, this is a real SCPS capability option
     * See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS Transport Protocol
     * (SCPS-TP)" Section 3.2.3 for definition.
     */
    if (optlen == 4) {
        hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_scps,
                                             tvb, offset, optlen, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        capvector = tvb_get_guint8(tvb, offset + 2);
        connid = tvb_get_guint8(tvb, offset + 3);

        tf = proto_tree_add_item(opt_tree, hf_tcp_option_scps_vector, tvb,
                                 offset + 2, 1, ENC_BIG_ENDIAN);
        field_tree = proto_item_add_subtree(tf, ett_tcp_option_scps);
        proto_tree_add_item(field_tree, hf_tcp_scpsoption_flags_bets, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_scpsoption_flags_snack1, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_scpsoption_flags_snack2, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_scpsoption_flags_compress, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_scpsoption_flags_nlts, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_scpsoption_flags_reserved, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);

        if (capvector) {
            struct capvec
            {
                guint8 mask;
                const gchar *str;
            } capvecs[] = {
                {0x80, "BETS"},
                {0x40, "SNACK1"},
                {0x20, "SNACK2"},
                {0x10, "COMP"},
                {0x08, "NLTS"},
                {0x07, "RESERVED"}
            };
            gboolean anyflag = FALSE;
            guint i;

            col_append_str(pinfo->cinfo, COL_INFO, " SCPS[");
            for (i = 0; i < sizeof(capvecs)/sizeof(struct capvec); i++) {
                if (capvector & capvecs[i].mask) {
                    proto_item_append_text(tf, "%s%s", anyflag ? ", " : " (",
                                           capvecs[i].str);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s",
                                    anyflag ? ", " : "", capvecs[i].str);
                    anyflag = TRUE;
                }
            }
            col_append_str(pinfo->cinfo, COL_INFO, "]");
            proto_item_append_text(tf, ")");
        }

        proto_tree_add_item(field_tree, hf_tcp_scpsoption_connection_id, tvb,
                            offset + 3, 1, ENC_BIG_ENDIAN);
        flow->scps_capable = 1;

        if (connid)
            tcp_info_append_uint(pinfo, "Connection ID", connid);
    } else {
        /* The option length != 4, so this is an infamous "extended capabilities
         * option. See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS
         * Transport Protocol (SCPS-TP)" Section 3.2.5 for definition.
         *
         *  As the format of this option is only partially defined (it is
         * a community (or more likely vendor) defined format beyond that, so
         * at least for now, we only parse the standardized portion of the option.
         */
        guint8 local_offset = 2;
        guint8 binding_space;
        guint8 extended_cap_length;

        if (flow->scps_capable != 1) {
            /* There was no SCPS capabilities option preceding this */
            proto_tree_add_uint_format(opt_tree, hf_tcp_option_scps_vector,
                                       tvb, offset, optlen, 0,
                                       "Illegal SCPS Extended Capabilities (%d bytes)",
                                       optlen);
        } else {
            tf = proto_tree_add_uint_format(opt_tree, hf_tcp_option_scps_vector,
                                            tvb, offset, optlen, 0,
                                            "SCPS Extended Capabilities (%d bytes)",
                                            optlen);
            field_tree=proto_item_add_subtree(tf, ett_tcp_option_scps_extended);

            /* There may be multiple binding spaces included in a single option,
             * so we will semi-parse each of the stacked binding spaces - skipping
             * over the octets following the binding space identifier and length.
             */
            while (optlen > local_offset) {

                /* 1st octet is Extended Capability Binding Space */
                binding_space = tvb_get_guint8(tvb, (offset + local_offset));

                /* 2nd octet (upper 4-bits) has binding space length in 16-bit words.
                 * As defined by the specification, this length is exclusive of the
                 * octets containing the extended capability type and length
                 */
                extended_cap_length =
                    (tvb_get_guint8(tvb, (offset + local_offset + 1)) >> 4);

                /* Convert the extended capabilities length into bytes for display */
                extended_cap_length = (extended_cap_length << 1);

                proto_tree_add_item(field_tree, hf_tcp_option_scps_binding, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_uint(field_tree, hf_tcp_option_scps_binding_len, tvb, offset + local_offset + 1, 1, extended_cap_length);

                /* Step past the binding space and length octets */
                local_offset += 2;

                proto_tree_add_text(field_tree, tvb, offset + local_offset,
                                    extended_cap_length,
                                    "Binding Space Data (%u bytes)",
                                    extended_cap_length);

                tcp_info_append_uint(pinfo, "EXCAP", binding_space);

                /* Step past the Extended capability data
                 * Treat the extended capability data area as opaque;
                 * If one desires to parse the extended capability data
                 * (say, in a vendor aware build of wireshark), it would
                 * be triggered here.
                 */
                local_offset += extended_cap_length;
            }
        }
    }
}

static void
dissect_tcpopt_user_to(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *hidden_item, *tf;
    proto_tree *field_tree;
    gboolean g;
    guint16 to;

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    g = tvb_get_ntohs(tvb, offset + 2) & 0x8000;
    to = tvb_get_ntohs(tvb, offset + 2) & 0x7FFF;
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_user_to, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tf = proto_tree_add_uint_format(opt_tree, hf_tcp_option_user_to_val, tvb, offset,
                               optlen, to, "%s: %u %s", optp->name, to, g ? "minutes" : "seconds");
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    proto_tree_add_item(field_tree, hf_tcp_option_user_to_granularity, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_tcp_option_user_to_val, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    tcp_info_append_uint(pinfo, "USER_TO", to);
}

/* This is called for SYN+ACK packets and the purpose is to verify that
 * the SCPS capabilities option has been successfully negotiated for the flow.
 * If the SCPS capabilities option was offered by only one party, the
 * proactively set scps_capable attribute of the flow (set upon seeing
 * the first instance of the SCPS option) is revoked.
 */
static void
verify_scps(packet_info *pinfo,  proto_item *tf_syn, struct tcp_analysis *tcpd)
{
    tf_syn = 0x0;

    if(tcpd) {
        if ((!(tcpd->flow1.scps_capable)) || (!(tcpd->flow2.scps_capable))) {
            tcpd->flow1.scps_capable = 0;
            tcpd->flow2.scps_capable = 0;
        } else {
            expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_NOTE,
                                   "Connection establish request (SYN-ACK): SCPS Capabilities Negotiated");
        }
    }
}

/* See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS
 * Transport Protocol (SCPS-TP)" Section 3.5 for definition of the SNACK option
 */
static void
dissect_tcpopt_snack(const ip_tcp_opt *optp, tvbuff_t *tvb,
            int offset, guint optlen, packet_info *pinfo,
            proto_tree *opt_tree, void *data _U_)
{
    struct tcp_analysis *tcpd=NULL;
    guint16 relative_hole_offset;
    guint16 relative_hole_size;
    guint16 base_mss = 0;
    guint32 ack;
    guint32 hole_start;
    guint32 hole_end;
    char    null_modifier[] = "\0";
    char    relative_modifier[] = "(relative)";
    char   *modifier = null_modifier;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(opt_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tcpd = get_tcp_conversation_data(NULL,pinfo);

    /* The SNACK option reports missing data with a granularity of segments. */
    relative_hole_offset = tvb_get_ntohs(tvb, offset + 2);
    relative_hole_size = tvb_get_ntohs(tvb, offset + 4);

    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_snack, tvb,
                                         offset, optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_offset,
                                      tvb, offset, optlen, relative_hole_offset);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_size,
                                      tvb, offset, optlen, relative_hole_size);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset, optlen,
                        "%s: Offset %u, Size %u", optp->name,
                        relative_hole_offset, relative_hole_size);

    ack   = tvb_get_ntohl(tvb, 8);

    if (tcp_relative_seq) {
        ack -= tcpd->rev->base_seq;
        modifier = relative_modifier;
    }

    /* To aid analysis, we can use a simple but generally effective heuristic
     * to report the most likely boundaries of the missing data.  If the
     * flow is scps_capable, we track the maximum sized segment that was
     * acknowledged by the receiver and use that as the reporting granularity.
     * This may be different from the negotiated MTU due to PMTUD or flows
     * that do not send max-sized segments.
     */
    base_mss = tcpd->fwd->maxsizeacked;

    if (base_mss) {
        /* Scale the reported offset and hole size by the largest segment acked */
        hole_start = ack + (base_mss * relative_hole_offset);
        hole_end   = hole_start + (base_mss * relative_hole_size);

        hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_le,
                                          tvb, offset, optlen, hole_start);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_re,
                                          tvb, offset, optlen, hole_end);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_text(opt_tree, tvb, offset, optlen,
                            "\tMissing Sequence %u - %u %s",
                            hole_start, hole_end, modifier);

        tcp_info_append_uint(pinfo, "SNLE", hole_start);
        tcp_info_append_uint(pinfo, "SNRE", hole_end);

        expert_add_info_format(pinfo, NULL, PI_SEQUENCE, PI_NOTE,
                               "SNACK Sequence %u - %u %s",
                               hole_start, hole_end, modifier);
    }
}

enum
{
    PROBE_VERSION_UNSPEC = 0,
    PROBE_VERSION_1      = 1,
    PROBE_VERSION_2      = 2,
    PROBE_VERSION_MAX
};

/* Probe type definition. */
enum
{
    PROBE_QUERY          = 0,
    PROBE_RESPONSE       = 1,
    PROBE_INTERNAL       = 2,
    PROBE_TRACE          = 3,
    PROBE_QUERY_SH       = 4,
    PROBE_RESPONSE_SH    = 5,
    PROBE_QUERY_INFO     = 6,
    PROBE_RESPONSE_INFO  = 7,
    PROBE_QUERY_INFO_SH  = 8,
    PROBE_QUERY_INFO_SID = 9,
    PROBE_RST            = 10,
    PROBE_TYPE_MAX
};

static const value_string rvbd_probe_type_vs[] = {
    { PROBE_QUERY,          "Probe Query" },
    { PROBE_RESPONSE,       "Probe Response" },
    { PROBE_INTERNAL,       "Probe Internal" },
    { PROBE_TRACE,          "Probe Trace" },
    { PROBE_QUERY_SH,       "Probe Query SH" },
    { PROBE_RESPONSE_SH,    "Probe Response SH" },
    { PROBE_QUERY_INFO,     "Probe Query Info" },
    { PROBE_RESPONSE_INFO,  "Probe Response Info" },
    { PROBE_QUERY_INFO_SH,  "Probe Query Info SH" },
    { PROBE_QUERY_INFO_SID, "Probe Query Info Store ID" },
    { PROBE_RST,            "Probe Reset" },
    { 0, NULL }
};


#define PROBE_OPTLEN_OFFSET            1

#define PROBE_VERSION_TYPE_OFFSET      2
#define PROBE_V1_RESERVED_OFFSET       3
#define PROBE_V1_PROBER_OFFSET         4
#define PROBE_V1_APPLI_VERSION_OFFSET  8
#define PROBE_V1_PROXY_ADDR_OFFSET     8
#define PROBE_V1_PROXY_PORT_OFFSET    12
#define PROBE_V1_SH_CLIENT_ADDR_OFFSET 8
#define PROBE_V1_SH_PROXY_ADDR_OFFSET 12
#define PROBE_V1_SH_PROXY_PORT_OFFSET 16

#define PROBE_V2_INFO_OFFSET           3

#define PROBE_V2_INFO_CLIENT_ADDR_OFFSET 4
#define PROBE_V2_INFO_STOREID_OFFSET   4

#define PROBE_VERSION_MASK          0x01

/* Probe Query Extra Info flags */
#define RVBD_FLAGS_PROBE_LAST       0x01
#define RVBD_FLAGS_PROBE_NCFE       0x04

/* Probe Response Extra Info flags */
#define RVBD_FLAGS_PROBE_SERVER     0x01
#define RVBD_FLAGS_PROBE_SSLCERT    0x02
#define RVBD_FLAGS_PROBE            0x10

static void
rvbd_probe_decode_version_type(const guint8 vt, guint8 *ver, guint8 *type)
{
    if (vt & PROBE_VERSION_MASK) {
        *ver = PROBE_VERSION_1;
        *type = vt >> 4;
    } else {
        *ver = PROBE_VERSION_2;
        *type = vt >> 1;
    }
}

static void
rvbd_probe_resp_add_info(proto_item *pitem, packet_info *pinfo, guint32 ip, guint16 port)
{
    proto_item_append_text(pitem, ", Server Steelhead: %s:%u", ip_to_str((guint8 *)&ip), port);

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "SA+, ");
}

static void
dissect_tcpopt_rvbd_probe(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                          guint optlen, packet_info *pinfo, proto_tree *opt_tree,
                          void *data _U_)
{
    guint8 ver, type;
    proto_tree *field_tree;
    proto_item *pitem;

    rvbd_probe_decode_version_type(
        tvb_get_guint8(tvb, offset + PROBE_VERSION_TYPE_OFFSET),
        &ver, &type);

    pitem = proto_tree_add_boolean_format_value(
        opt_tree, hf_tcp_option_rvbd_probe, tvb, offset, optlen, 1,
        "%s", val_to_str_const(type, rvbd_probe_type_vs, "Probe Unknown"));

    if (type >= PROBE_TYPE_MAX)
        return;

    /* optlen, type, ver are common for all probes */
    field_tree = proto_item_add_subtree(pitem, ett_tcp_opt_rvbd_probe);
    pitem = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                        offset + PROBE_OPTLEN_OFFSET, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(pitem);
    pitem = proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(pitem);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_optlen, tvb,
                        offset + PROBE_OPTLEN_OFFSET, 1, ENC_BIG_ENDIAN);

    if (ver == PROBE_VERSION_1) {
        guint32 ip;
        guint16 port;

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_type1, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_version1, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);

        if (type == PROBE_INTERNAL)
            return;

        proto_tree_add_text(field_tree, tvb, offset + PROBE_V1_RESERVED_OFFSET,
                            1, "Reserved");

        ip = tvb_get_ipv4(tvb, offset + PROBE_V1_PROBER_OFFSET);
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_prober, tvb,
                            offset + PROBE_V1_PROBER_OFFSET, 4, ENC_BIG_ENDIAN);

        switch (type) {

        case PROBE_QUERY:
        case PROBE_QUERY_SH:
        case PROBE_TRACE:
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_appli_ver, tvb,
                                offset + PROBE_V1_APPLI_VERSION_OFFSET, 2,
                                ENC_BIG_ENDIAN);

            proto_item_append_text(pitem, ", CSH IP: %s", ip_to_str((guint8 *)&ip));

            if (check_col(pinfo->cinfo, COL_INFO)) {
                /* Small look-ahead hack to distinguish S+ from S+* */
#define PROBE_V1_QUERY_LEN    10
                const guint8 qinfo_hdr[] = { 0x4c, 0x04, 0x0c };
                int not_cfe = 0;
                /* tvb_memeql seems to be the only API that doesn't throw
                   an exception in case of an error */
                if (tvb_memeql(tvb, offset + PROBE_V1_QUERY_LEN,
                               qinfo_hdr, sizeof(qinfo_hdr)) == 0) {
                        not_cfe = tvb_get_guint8(tvb, offset + PROBE_V1_QUERY_LEN +
                                                 sizeof(qinfo_hdr)) & RVBD_FLAGS_PROBE_NCFE;
                }
                col_prepend_fstr(pinfo->cinfo, COL_INFO, "S%s, ",
                                 type == PROBE_TRACE ? "#" :
                                 not_cfe ? "+*" : "+");
           }
           break;

        case PROBE_RESPONSE:
            ip = tvb_get_ipv4(tvb, offset + PROBE_V1_PROXY_ADDR_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy, tvb,
                                offset + PROBE_V1_PROXY_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

            port = tvb_get_ntohs(tvb, offset + PROBE_V1_PROXY_PORT_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy_port, tvb,
                                offset + PROBE_V1_PROXY_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

            rvbd_probe_resp_add_info(pitem, pinfo, ip, port);
            break;

        case PROBE_RESPONSE_SH:
            proto_tree_add_item(field_tree,
                                hf_tcp_option_rvbd_probe_client, tvb,
                                offset + PROBE_V1_SH_CLIENT_ADDR_OFFSET, 4,
                                ENC_BIG_ENDIAN);

            ip = tvb_get_ipv4(tvb, offset + PROBE_V1_SH_PROXY_ADDR_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy, tvb,
                                offset + PROBE_V1_SH_PROXY_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

            port = tvb_get_ntohs(tvb, offset + PROBE_V1_SH_PROXY_PORT_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy_port, tvb,
                                offset + PROBE_V1_SH_PROXY_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

            rvbd_probe_resp_add_info(pitem, pinfo, ip, port);
            break;
        }
    }
    else if (ver == PROBE_VERSION_2) {
        proto_item *ver_pi;
        proto_item *flag_pi;
        proto_tree *flag_tree;
        guint8 flags;

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_type2, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_uint_format_value(
            field_tree, hf_tcp_option_rvbd_probe_version2, tvb,
            offset + PROBE_VERSION_TYPE_OFFSET, 1, ver, "%u", ver);
        /* Use version1 for filtering purposes because version2 packet
           value is 0, but filtering is usually done for value 2 */
        ver_pi = proto_tree_add_uint(field_tree, hf_tcp_option_rvbd_probe_version1, tvb,
                                     offset + PROBE_VERSION_TYPE_OFFSET, 1, ver);
        PROTO_ITEM_SET_HIDDEN(ver_pi);

        switch (type) {

        case PROBE_QUERY_INFO:
        case PROBE_QUERY_INFO_SH:
        case PROBE_QUERY_INFO_SID:
            flags = tvb_get_guint8(tvb, offset + PROBE_V2_INFO_OFFSET);
            flag_pi = proto_tree_add_uint(field_tree, hf_tcp_option_rvbd_probe_flags,
                                          tvb, offset + PROBE_V2_INFO_OFFSET,
                                          1, flags);

            flag_tree = proto_item_add_subtree(flag_pi, ett_tcp_opt_rvbd_probe_flags);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_not_cfe,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_last_notify,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, ENC_BIG_ENDIAN);

            if (type == PROBE_QUERY_INFO_SH)
                proto_tree_add_item(flag_tree,
                                    hf_tcp_option_rvbd_probe_client, tvb,
                                    offset + PROBE_V2_INFO_CLIENT_ADDR_OFFSET,
                                    4, ENC_BIG_ENDIAN);
            else if (type == PROBE_QUERY_INFO_SID)
                proto_tree_add_item(flag_tree,
                                    hf_tcp_option_rvbd_probe_storeid, tvb,
                                    offset + PROBE_V2_INFO_STOREID_OFFSET,
                                    4, ENC_BIG_ENDIAN);

            if (type != PROBE_QUERY_INFO_SID &&
                check_col(pinfo->cinfo, COL_INFO) &&
                (tvb_get_guint8(tvb, 13) & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) &&
                (flags & RVBD_FLAGS_PROBE_LAST)) {
                col_prepend_fstr(pinfo->cinfo, COL_INFO, "SA++, ");
            }

            break;

        case PROBE_RESPONSE_INFO:
            flag_pi = proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_flags,
                                          tvb, offset + PROBE_V2_INFO_OFFSET,
                                          1, ENC_BIG_ENDIAN);

            flag_tree = proto_item_add_subtree(flag_pi, ett_tcp_opt_rvbd_probe_flags);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_probe_cache,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_sslcert,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_server_connected,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, ENC_BIG_ENDIAN);
            break;

        case PROBE_RST:
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_flags,
                                  tvb, offset + PROBE_V2_INFO_OFFSET,
                                  1, ENC_BIG_ENDIAN);
            break;
        }
    }
}

enum {
    TRPY_OPTNUM_OFFSET        = 0,
    TRPY_OPTLEN_OFFSET        = 1,

    TRPY_OPTIONS_OFFSET       = 2,
    TRPY_SRC_ADDR_OFFSET      = 4,
    TRPY_DST_ADDR_OFFSET      = 8,
    TRPY_SRC_PORT_OFFSET      = 12,
    TRPY_DST_PORT_OFFSET      = 14,
    TRPY_CLIENT_PORT_OFFSET   = 16
};

/* Trpy Flags */
#define RVBD_FLAGS_TRPY_MODE         0x0001
#define RVBD_FLAGS_TRPY_OOB          0x0002
#define RVBD_FLAGS_TRPY_CHKSUM       0x0004
#define RVBD_FLAGS_TRPY_FW_RST       0x0100
#define RVBD_FLAGS_TRPY_FW_RST_INNER 0x0200
#define RVBD_FLAGS_TRPY_FW_RST_PROBE 0x0400

static const true_false_string trpy_mode_str = {
    "Port Transparency",
    "Full Transparency"
};

static void
dissect_tcpopt_rvbd_trpy(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
                        int offset, guint optlen, packet_info *pinfo,
                        proto_tree *opt_tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_tree *flag_tree;
    proto_item *pitem;
    proto_item *flag_pi;
    guint32 src, dst;
    guint16 sport, dport, flags;
    static dissector_handle_t sport_handle = NULL;

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "TRPY, ");

    pitem = proto_tree_add_boolean_format_value(
        opt_tree, hf_tcp_option_rvbd_trpy, tvb, offset, optlen, 1,
        "%s", "");

    field_tree = proto_item_add_subtree(pitem, ett_tcp_opt_rvbd_trpy);
    pitem = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                        offset + PROBE_OPTLEN_OFFSET, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(pitem);
    pitem = proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(pitem);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_optlen, tvb,
                        offset + PROBE_OPTLEN_OFFSET, 1, ENC_BIG_ENDIAN);

    flags = tvb_get_ntohs(tvb, offset + TRPY_OPTIONS_OFFSET);
    flag_pi = proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_flags,
                                  tvb, offset + TRPY_OPTIONS_OFFSET,
                                  2, ENC_BIG_ENDIAN);

    flag_tree = proto_item_add_subtree(flag_pi, ett_tcp_opt_rvbd_trpy_flags);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_fw_rst_probe,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_fw_rst_inner,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_fw_rst,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_chksum,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_oob,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_mode,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, ENC_BIG_ENDIAN);

    src = tvb_get_ipv4(tvb, offset + TRPY_SRC_ADDR_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_src,
                        tvb, offset + TRPY_SRC_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

    dst = tvb_get_ipv4(tvb, offset + TRPY_DST_ADDR_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_dst,
                        tvb, offset + TRPY_DST_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

    sport = tvb_get_ntohs(tvb, offset + TRPY_SRC_PORT_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_src_port,
                        tvb, offset + TRPY_SRC_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

    dport = tvb_get_ntohs(tvb, offset + TRPY_DST_PORT_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_dst_port,
                        tvb, offset + TRPY_DST_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(pitem, "%s:%u -> %s:%u",
                           ip_to_str((guint8 *)&src), sport,
                           ip_to_str((guint8 *)&dst), dport);

    /* Client port only set on SYN: optlen == 18 */
    if ((flags & RVBD_FLAGS_TRPY_OOB) && (optlen > TCPOLEN_RVBD_TRPY_MIN))
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_client_port,
                            tvb, offset + TRPY_CLIENT_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

    /* We need to map this TCP session on our own dissector instead of what
       Wireshark thinks runs on these ports */
    if (sport_handle == NULL) {
        sport_handle = find_dissector("sport");
    }
    if (sport_handle != NULL) {
        conversation_t *conversation;
        conversation = find_conversation(pinfo->fd->num,
            &pinfo->src, &pinfo->dst, pinfo->ptype,
            pinfo->srcport, pinfo->destport, 0);
        if (conversation == NULL) {
            conversation = conversation_new(pinfo->fd->num,
                &pinfo->src, &pinfo->dst, pinfo->ptype,
                pinfo->srcport, pinfo->destport, 0);
        }
        if (conversation->dissector_handle != sport_handle) {
            conversation_set_dissector(conversation, sport_handle);
        }
    }
}

static const ip_tcp_opt tcpopts[] = {
    {
        TCPOPT_EOL,
        "End of Option List (EOL)",
        NULL,
        OPT_LEN_NO_LENGTH,
        0,
        NULL,
    },
    {
        TCPOPT_NOP,
        "No-Operation (NOP)",
        NULL,
        OPT_LEN_NO_LENGTH,
        0,
        NULL,
    },
    {
        TCPOPT_MSS,
        "Maximum segment size",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_MSS,
        dissect_tcpopt_mss
    },
    {
        TCPOPT_WINDOW,
        "Window scale",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_WINDOW,
        dissect_tcpopt_wscale
    },
    {
        TCPOPT_SACK_PERM,
        "SACK permitted",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_SACK_PERM,
        dissect_tcpopt_sack_perm,
    },
    {
        TCPOPT_SACK,
        "SACK",
        &ett_tcp_option_sack,
        OPT_LEN_VARIABLE_LENGTH,
        TCPOLEN_SACK_MIN,
        dissect_tcpopt_sack
    },
    {
        TCPOPT_ECHO,
        "Echo",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_ECHO,
        dissect_tcpopt_echo
    },
    {
        TCPOPT_ECHOREPLY,
        "Echo reply",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_ECHOREPLY,
        dissect_tcpopt_echo
    },
    {
        TCPOPT_TIMESTAMP,
        "Timestamps",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_TIMESTAMP,
        dissect_tcpopt_timestamp
    },
    {
        TCPOPT_MPTCP,
        "Multipath TCP",
        NULL,
        OPT_LEN_VARIABLE_LENGTH,
        TCPOLEN_MPTCP_MIN,
        dissect_tcpopt_mptcp
    },
    {
        TCPOPT_CC,
        "CC",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_CC,
        dissect_tcpopt_cc
    },
    {
        TCPOPT_CCNEW,
        "CC.NEW",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_CCNEW,
        dissect_tcpopt_cc
    },
    {
        TCPOPT_CCECHO,
        "CC.ECHO",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_CCECHO,
        dissect_tcpopt_cc
    },
    {
        TCPOPT_MD5,
        "TCP MD5 signature",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_MD5,
        NULL
    },
    {
        TCPOPT_SCPS,
        "SCPS capabilities",
        &ett_tcp_option_scps,
        OPT_LEN_VARIABLE_LENGTH,
        TCPOLEN_SCPS,
        dissect_tcpopt_scps
    },
    {
        TCPOPT_SNACK,
        "Selective Negative Acknowledgment",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_SNACK,
        dissect_tcpopt_snack
    },
    {
        TCPOPT_RECBOUND,
        "SCPS record boundary",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_RECBOUND,
        NULL
    },
    {
        TCPOPT_CORREXP,
        "SCPS corruption experienced",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_CORREXP,
        NULL
    },
    {
        TCPOPT_QS,
        "Quick-Start",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_QS,
        dissect_tcpopt_qs
    },
    {
        TCPOPT_USER_TO,
        "User Timeout",
        &ett_tcp_option_user_to,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_USER_TO,
        dissect_tcpopt_user_to
  },
  {
        TCPOPT_RVBD_PROBE,
        "Riverbed Probe",
        NULL,
        OPT_LEN_VARIABLE_LENGTH,
        TCPOLEN_RVBD_PROBE_MIN,
        dissect_tcpopt_rvbd_probe
  },
  {
        TCPOPT_RVBD_TRPY,
        "Riverbed Transparency",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        TCPOLEN_RVBD_TRPY_MIN,
        dissect_tcpopt_rvbd_trpy
  },
  {
        TCPOPT_EXP_FD,
        "Experimental",
        NULL,
        OPT_LEN_VARIABLE_LENGTH,
        TCPOLEN_EXP_MIN,
        dissect_tcpopt_exp
  },
  {
        TCPOPT_EXP_FE,
        "Experimental",
        NULL,
        OPT_LEN_VARIABLE_LENGTH,
        TCPOLEN_EXP_MIN,
        dissect_tcpopt_exp
  }
};

#define N_TCP_OPTS  array_length(tcpopts)

/* Determine if there is a sub-dissector and call it; return TRUE
   if there was a sub-dissector, FALSE otherwise.

   This has been separated into a stand alone routine to other protocol
   dissectors can call to it, e.g., SOCKS. */

static gboolean try_heuristic_first = FALSE;


/* this function can be called with tcpd==NULL as from the msproxy dissector */
gboolean
decode_tcp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, int src_port, int dst_port,
    struct tcp_analysis *tcpd)
{
    tvbuff_t *next_tvb;
    int low_port, high_port;
    int save_desegment_offset;
    guint32 save_desegment_len;

    /* Don't call subdissectors for keepalives.  Even though they do contain
     * payload "data", it's just garbage.  Display any data the keepalive
     * packet might contain though.
     */
    if(tcpd && tcpd->ta) {
        if(tcpd->ta->flags&TCP_A_KEEP_ALIVE) {
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(data_handle, next_tvb, pinfo, tree);
            return TRUE;
        }
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if (tcp_no_subdissector_on_error && tcpd && tcpd->ta && tcpd->ta->flags & (TCP_A_RETRANSMISSION | TCP_A_OUT_OF_ORDER)) {
        /* Don't try to dissect a retransmission high chance that it will mess
         * subdissectors for protocols that require in-order delivery of the
         * PDUs. (i.e. DCE/RPCoverHTTP and encryption)
         */
        return FALSE;
    }
/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

    if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_TCP,
                                   src_port, dst_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }

    if (try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        save_desegment_offset = pinfo->desegment_offset;
        save_desegment_len = pinfo->desegment_len;
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, NULL)) {
            pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
            return TRUE;
        }
        /*
         * They rejected the packet; make sure they didn't also request
         * desegmentation (we could just override the request, but
         * rejecting a packet *and* requesting desegmentation is a sign
         * of the dissector's code needing clearer thought, so we fail
         * so that the problem is made more obvious).
         */
        DISSECTOR_ASSERT(save_desegment_offset == pinfo->desegment_offset &&
                         save_desegment_len == pinfo->desegment_len);
    }

    /* Do lookups with the subdissector table.
       Try the server port captured on the SYN or SYN|ACK packet.  After that
       try the port number with the lower value first, followed by the
       port number with the higher value.  This means that, for packets
       where a dissector is registered for *both* port numbers:

       1) we pick the same dissector for traffic going in both directions;

       2) we prefer the port number that's more likely to be the right
       one (as that prefers well-known ports to reserved ports);

       although there is, of course, no guarantee that any such strategy
       will always pick the right port number.

       XXX - we ignore port numbers of 0, as some dissectors use a port
       number of 0 to disable the port. */

    if (tcpd && tcpd->server_port != 0 &&
        dissector_try_uint(subdissector_table, tcpd->server_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }

    if (src_port > dst_port) {
        low_port = dst_port;
        high_port = src_port;
    } else {
        low_port = src_port;
        high_port = dst_port;
    }
    if (tcp_no_subdissector_on_error && tcpd && tcpd->ta && tcpd->ta->flags & (TCP_A_RETRANSMISSION | TCP_A_OUT_OF_ORDER)) {
        /* Don't try to dissect a retransmission high chance that it will mess
         * subdissectors for protocols that require in-order delivery of the
         * PDUs. (i.e. DCE/RPCoverHTTP and encryption)
         */
        return FALSE;
    }
    if (low_port != 0 &&
        dissector_try_uint(subdissector_table, low_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }
    if (high_port != 0 &&
        dissector_try_uint(subdissector_table, high_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }

    if (!try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        save_desegment_offset = pinfo->desegment_offset;
        save_desegment_len = pinfo->desegment_len;
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, NULL)) {
            pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
            return TRUE;
        }
        /*
         * They rejected the packet; make sure they didn't also request
         * desegmentation (we could just override the request, but
         * rejecting a packet *and* requesting desegmentation is a sign
         * of the dissector's code needing clearer thought, so we fail
         * so that the problem is made more obvious).
         */
        DISSECTOR_ASSERT(save_desegment_offset == pinfo->desegment_offset &&
                         save_desegment_len == pinfo->desegment_len);
    }

    /* Oh, well, we don't know this; dissect it as data. */
    call_dissector(data_handle,next_tvb, pinfo, tree);

    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    return FALSE;
}

static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
    guint32 seq, guint32 nxtseq, gboolean is_tcp_segment,
    struct tcp_analysis *tcpd)
{
    pinfo->want_pdu_tracking=0;

    TRY {
        if(is_tcp_segment) {
            /*qqq   see if it is an unaligned PDU */
            if(tcpd && tcp_analyze_seq && (!tcp_desegment)) {
                if(seq || nxtseq) {
                    offset=scan_for_next_pdu(tvb, tcp_tree, pinfo, offset,
                        seq, nxtseq, tcpd->fwd->multisegment_pdus);
                }
            }
        }
        /* if offset is -1 this means that this segment is known
         * to be fully inside a previously detected pdu
         * so we don't even need to try to dissect it either.
         */
        if( (offset!=-1) &&
            decode_tcp_ports(tvb, offset, pinfo, tree, src_port,
                dst_port, tcpd) ) {
            /*
             * We succeeded in handing off to a subdissector.
             *
             * Is this a TCP segment or a reassembled chunk of
             * TCP payload?
             */
            if(is_tcp_segment) {
                /* if !visited, check want_pdu_tracking and
                   store it in table */
                if(tcpd && (!pinfo->fd->flags.visited) &&
                    tcp_analyze_seq && pinfo->want_pdu_tracking) {
                    if(seq || nxtseq) {
                        pdu_store_sequencenumber_of_next_pdu(
                            pinfo,
                            seq,
                            nxtseq+pinfo->bytes_until_next_pdu,
                            tcpd->fwd->multisegment_pdus);
                    }
                }
            }
        }
    }
    CATCH_ALL {
        /* We got an exception. At this point the dissection is
         * completely aborted and execution will be transferred back
         * to (probably) the frame dissector.
         * Here we have to place whatever we want the dissector
         * to do before aborting the tcp dissection.
         */
        /*
         * Is this a TCP segment or a reassembled chunk of TCP
         * payload?
         */
        if(is_tcp_segment) {
            /*
             * It's from a TCP segment.
             *
             * if !visited, check want_pdu_tracking and store it
             * in table
             */
            if(tcpd && (!pinfo->fd->flags.visited) && tcp_analyze_seq && pinfo->want_pdu_tracking) {
                if(seq || nxtseq) {
                    pdu_store_sequencenumber_of_next_pdu(pinfo,
                        seq,
                        nxtseq+pinfo->bytes_until_next_pdu,
                        tcpd->fwd->multisegment_pdus);
                }
            }
        }
        RETHROW;
    }
    ENDTRY;
}

void
dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset, guint32 seq,
            guint32 nxtseq, guint32 sport, guint32 dport,
            proto_tree *tree, proto_tree *tcp_tree,
            struct tcp_analysis *tcpd)
{
    gboolean save_fragmented;

    /* Can we desegment this segment? */
    if (pinfo->can_desegment) {
        /* Yes. */
        desegment_tcp(tvb, pinfo, offset, seq, nxtseq, sport, dport, tree,
                      tcp_tree, tcpd);
    } else {
        /* No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame. */
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree, sport, dport,
                            seq, nxtseq, TRUE, tcpd);
        pinfo->fragmented = save_fragmented;
    }
}

static void
dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8  th_off_x2; /* combines th_off and th_x2 */
    guint16 th_sum;
    guint32 ack;
    guint16 th_urp;
    proto_tree *tcp_tree = NULL, *field_tree = NULL;
    proto_item *ti = NULL, *tf, *hidden_item;
    int        offset = 0;
    emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("<None>");
    const gchar *flags[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR", "NS"};
    gint       i;
    guint      bpos;
    guint      optlen;
    guint32    nxtseq = 0;
    guint      reported_len;
    vec_t      cksum_vec[4];
    guint32    phdr[2];
    guint16    computed_cksum;
    guint16    real_window;
    guint      length_remaining;
    gboolean   desegment_ok;
    struct tcpinfo tcpinfo;
    struct tcpheader *tcph;
    proto_item *tf_syn = NULL, *tf_fin = NULL, *tf_rst = NULL, *scaled_pi;
    conversation_t *conv=NULL;
    struct tcp_analysis *tcpd=NULL;
    struct tcp_per_packet_data_t *tcppd=NULL;
    proto_item *item;
    proto_tree *checksum_tree;

    tcph=ep_alloc(sizeof(struct tcpheader));
    SET_ADDRESS(&tcph->ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
    SET_ADDRESS(&tcph->ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");

    /* Clear out the Info column. */
    col_clear(pinfo->cinfo, COL_INFO);

    tcph->th_sport = tvb_get_ntohs(tvb, offset);
    tcph->th_dport = tvb_get_ntohs(tvb, offset + 2);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s > %s",
                    get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));
    if (tree) {
        if (tcp_summary_in_tree) {
            ti = proto_tree_add_protocol_format(tree, proto_tcp, tvb, 0, -1,
                                                "Transmission Control Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
                                                get_tcp_port(tcph->th_sport), tcph->th_sport,
                                                get_tcp_port(tcph->th_dport), tcph->th_dport);
        }
        else {
            ti = proto_tree_add_item(tree, proto_tcp, tvb, 0, -1, ENC_NA);
        }
        tcp_tree = proto_item_add_subtree(ti, ett_tcp);
        pinfo->tcp_tree=tcp_tree;

        proto_tree_add_uint_format(tcp_tree, hf_tcp_srcport, tvb, offset, 2, tcph->th_sport,
                                   "Source port: %s (%u)", get_tcp_port(tcph->th_sport), tcph->th_sport);
        proto_tree_add_uint_format(tcp_tree, hf_tcp_dstport, tvb, offset + 2, 2, tcph->th_dport,
                                   "Destination port: %s (%u)", get_tcp_port(tcph->th_dport), tcph->th_dport);
        hidden_item = proto_tree_add_uint(tcp_tree, hf_tcp_port, tvb, offset, 2, tcph->th_sport);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        hidden_item = proto_tree_add_uint(tcp_tree, hf_tcp_port, tvb, offset + 2, 2, tcph->th_dport);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /*  If we're dissecting the headers of a TCP packet in an ICMP packet
         *  then go ahead and put the sequence numbers in the tree now (because
         *  they won't be put in later because the ICMP packet only contains up
         *  to the sequence number).
         *  We should only need to do this for IPv4 since IPv6 will hopefully
         *  carry enough TCP payload for this dissector to put the sequence
         *  numbers in via the regular code path.
         */
        if (pinfo->layer_names != NULL && pinfo->layer_names->str != NULL) {
            /*  use strstr because g_strrstr is only present in glib2.0 and
             *  g_str_has_suffix in glib2.2
             */
            if (strstr(pinfo->layer_names->str, "icmp:ip") != NULL)
                proto_tree_add_item(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        }
    }

    /* Set the source and destination port numbers as soon as we get them,
       so that they're available to the "Follow TCP Stream" code even if
       we throw an exception dissecting the rest of the TCP header. */
    pinfo->ptype = PT_TCP;
    pinfo->srcport = tcph->th_sport;
    pinfo->destport = tcph->th_dport;

    tcph->th_seq = tvb_get_ntohl(tvb, offset + 4);
    tcph->th_ack = tvb_get_ntohl(tvb, offset + 8);
    th_off_x2 = tvb_get_guint8(tvb, offset + 12);
    tcph->th_flags = tvb_get_ntohs(tvb, offset + 12) & 0x0FFF;
    tcph->th_win = tvb_get_ntohs(tvb, offset + 14);
    real_window = tcph->th_win;
    tcph->th_hlen = hi_nibble(th_off_x2) * 4;  /* TCP header length, in bytes */

    /* find(or create if needed) the conversation for this tcp session */
    conv=find_or_create_conversation(pinfo);
    tcpd=get_tcp_conversation_data(conv,pinfo);

    /* If this is a SYN packet, then check if it's seq-nr is different
     * from the base_seq of the retrieved conversation. If this is the
     * case, create a new conversation with the same addresses and ports
     * and set the TA_PORTS_REUSED flag. If the seq-nr is the same as
     * the base_seq, then do nothing so it will be marked as a retrans-
     * mission later.
     */
    if(tcpd && ((tcph->th_flags&(TH_SYN|TH_ACK))==TH_SYN) &&
       (tcpd->fwd->base_seq!=0) &&
       (tcph->th_seq!=tcpd->fwd->base_seq) ) {
        if (!(pinfo->fd->flags.visited)) {
            conv=conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
            tcpd=get_tcp_conversation_data(conv,pinfo);
        }
        if(!tcpd->ta)
            tcp_analyze_get_acked_struct(pinfo->fd->num, tcph->th_seq, tcph->th_ack, TRUE, tcpd);
        tcpd->ta->flags|=TCP_A_REUSED_PORTS;
    }

    if (tcpd) {
        item = proto_tree_add_uint(tcp_tree, hf_tcp_stream, tvb, offset, 0, tcpd->stream);
        PROTO_ITEM_SET_GENERATED(item);

        /* Copy the stream index into the header as well to make it available
         * to tap listeners.
         */
        tcph->th_stream = tcpd->stream;
    }

    /* Do we need to calculate timestamps relative to the tcp-stream? */
    if (tcp_calculate_ts) {
        tcppd = p_get_proto_data(pinfo->fd, proto_tcp);

        /*
         * Calculate the timestamps relative to this conversation (but only on the
         * first run when frames are accessed sequentially)
         */
        if (!(pinfo->fd->flags.visited))
            tcp_calculate_timestamps(pinfo, tcpd, tcppd);
    }

    /*
     * If we've been handed an IP fragment, we don't know how big the TCP
     * segment is, so don't do anything that requires that we know that.
     *
     * The same applies if we're part of an error packet.  (XXX - if the
     * ICMP and ICMPv6 dissectors could set a "this is how big the IP
     * header says it is" length in the tvbuff, we could use that; such
     * a length might also be useful for handling packets where the IP
     * length is bigger than the actual data available in the frame; the
     * dissectors should trust that length, and then throw a
     * ReportedBoundsError exception when they go past the end of the frame.)
     *
     * We also can't determine the segment length if the reported length
     * of the TCP packet is less than the TCP header length.
     */
    reported_len = tvb_reported_length(tvb);

    if (!pinfo->fragmented && !pinfo->flags.in_error_pkt) {
        if (reported_len < tcph->th_hlen) {
            proto_item *pi;
            pi = proto_tree_add_text(tcp_tree, tvb, offset, 0,
                                     "Short segment. Segment/fragment does not contain a full TCP header"
                                     " (might be NMAP or someone else deliberately sending unusual packets)");
            PROTO_ITEM_SET_GENERATED(pi);
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_WARN, "Short segment");
            tcph->th_have_seglen = FALSE;
        } else {
            /* Compute the length of data in this segment. */
            tcph->th_seglen = reported_len - tcph->th_hlen;
            tcph->th_have_seglen = TRUE;

            if (tree) { /* Add the seglen as an invisible field */

                hidden_item = proto_tree_add_uint(ti, hf_tcp_len, tvb, offset+12, 1, tcph->th_seglen);
                PROTO_ITEM_SET_HIDDEN(hidden_item);

            }


            /* handle TCP seq# analysis parse all new segments we see */
            if(tcp_analyze_seq) {
                if(!(pinfo->fd->flags.visited)) {
                    tcp_analyze_sequence_number(pinfo, tcph->th_seq, tcph->th_ack, tcph->th_seglen, tcph->th_flags, tcph->th_win, tcpd);
                }
                if(tcpd && tcp_relative_seq) {
                    (tcph->th_seq) -= tcpd->fwd->base_seq;
                    (tcph->th_ack) -= tcpd->rev->base_seq;
                }
            }

            /* re-calculate window size, based on scaling factor */
            if (!(tcph->th_flags&TH_SYN)) {   /* SYNs are never scaled */
                if (tcpd && (tcpd->fwd->win_scale>=0)) {
                    (tcph->th_win)<<=tcpd->fwd->win_scale;
                }
                else {
                    /* Don't have it stored, so use preference setting instead! */
                    if (tcp_default_window_scaling>=0) {
                        (tcph->th_win)<<=tcp_default_window_scaling;
                    }
                }
            }

            /* Compute the sequence number of next octet after this segment. */
            nxtseq = tcph->th_seq + tcph->th_seglen;
        }
    } else
        tcph->th_have_seglen = FALSE;

    if (check_col(pinfo->cinfo, COL_INFO) || tree) {
        gboolean first_flag = TRUE;
        for (i = 0; i < 9; i++) {
            bpos = 1 << i;
            if (tcph->th_flags & bpos) {
                if (first_flag) {
                    ep_strbuf_truncate(flags_strbuf, 0);
                }
                ep_strbuf_append_printf(flags_strbuf, "%s%s", first_flag ? "" : ", ", flags[i]);
                first_flag = FALSE;
            }
        }
        if (tcph->th_flags & 0x0E00) {
            if (first_flag) {
                ep_strbuf_truncate(flags_strbuf, 0);
            }
            ep_strbuf_append_printf(flags_strbuf, "%sReserved", first_flag ? "" : ", ");
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " [%s] Seq=%u", flags_strbuf->str, tcph->th_seq);
    if (tcph->th_flags&TH_ACK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Ack=%u", tcph->th_ack);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, " Win=%u", tcph->th_win);

    if (tree) {
        if (tcp_summary_in_tree) {
            proto_item_append_text(ti, ", Seq: %u", tcph->th_seq);
        }
        if(tcp_relative_seq) {
            proto_tree_add_uint_format(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq, "Sequence number: %u    (relative sequence number)", tcph->th_seq);
        } else {
            proto_tree_add_uint(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq);
        }
    }

    if (tcph->th_hlen < TCPH_MIN_LEN) {
        /* Give up at this point; we put the source and destination port in
           the tree, before fetching the header length, so that they'll
           show up if this is in the failing packet in an ICMP error packet,
           but it's now time to give up if the header length is bogus. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", bogus TCP header length (%u, must be at least %u)",
                        tcph->th_hlen, TCPH_MIN_LEN);
        if (tree) {
            proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, tcph->th_hlen,
                                       "Header length: %u bytes (bogus, must be at least %u)", tcph->th_hlen,
                                       TCPH_MIN_LEN);
        }
        return;
    }

    if (tree) {
        if (tcp_summary_in_tree) {
            if(tcph->th_flags&TH_ACK) {
                proto_item_append_text(ti, ", Ack: %u", tcph->th_ack);
            }
            if (tcph->th_have_seglen)
                proto_item_append_text(ti, ", Len: %u", tcph->th_seglen);
        }
        proto_item_set_len(ti, tcph->th_hlen);
        if (tcph->th_have_seglen) {
            if (nxtseq != tcph->th_seq) {
                if(tcp_relative_seq) {
                    tf=proto_tree_add_uint_format(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq, "Next sequence number: %u    (relative sequence number)", nxtseq);
                } else {
                    tf=proto_tree_add_uint(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq);
                }
                PROTO_ITEM_SET_GENERATED(tf);
            }
        }
    }

    if (tcph->th_flags & TH_ACK) {
        if (tree) {
            if (tcp_relative_seq) {
                proto_tree_add_uint_format(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, tcph->th_ack, "Acknowledgment number: %u    (relative ack number)", tcph->th_ack);
            } else {
                proto_tree_add_uint(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, tcph->th_ack);
            }
        }
    } else {
        /* Verify that the ACK field is zero */
        ack = tvb_get_ntohl(tvb, offset+8);
        if (ack != 0) {
            item = proto_tree_add_uint_format(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, ack,
                       "Acknowledgment Number: 0x%08x [should be 0x00000000 because ACK flag is not set]",
                       ack);
            expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                "Acknowledgment number: Broken TCP. The acknowledge field is nonzero while the ACK flag is not set");
        }
    }

    if (tree) {
        proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, tcph->th_hlen,
                                   "Header length: %u bytes", tcph->th_hlen);
        tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, tvb, offset + 12, 2,
                                        tcph->th_flags, "Flags: 0x%03x (%s)", tcph->th_flags, flags_strbuf->str);
        field_tree = proto_item_add_subtree(tf, ett_tcp_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_res, tvb, offset + 12, 1, tcph->th_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_ns, tvb, offset + 12, 1, tcph->th_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_cwr, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_ecn, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_urg, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_ack, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(field_tree, hf_tcp_flags_push, tvb, offset + 13, 1, tcph->th_flags);
        tf_rst = proto_tree_add_boolean(field_tree, hf_tcp_flags_reset, tvb, offset + 13, 1, tcph->th_flags);
        tf_syn = proto_tree_add_boolean(field_tree, hf_tcp_flags_syn, tvb, offset + 13, 1, tcph->th_flags);
        tf_fin = proto_tree_add_boolean(field_tree, hf_tcp_flags_fin, tvb, offset + 13, 1, tcph->th_flags);

        /* As discussed in bug 5541, it is better to use two separate
         * fields for the real and calculated window size.
         */
        proto_tree_add_uint(tcp_tree, hf_tcp_window_size_value, tvb, offset + 14, 2, real_window);
        scaled_pi = proto_tree_add_uint(tcp_tree, hf_tcp_window_size, tvb, offset + 14, 2, tcph->th_win);
        PROTO_ITEM_SET_GENERATED(scaled_pi);

        if( !(tcph->th_flags&TH_SYN) && tcpd ) {
            switch (tcpd->fwd->win_scale) {

            case -1:
                {
                    gint16 win_scale = tcpd->fwd->win_scale;
                    gboolean override_with_pref = FALSE;

                    /* Use preference setting (if set) */
                    if (tcp_default_window_scaling != WindowScaling_NotKnown) {
                        win_scale = tcp_default_window_scaling;
                        override_with_pref = TRUE;
                    }

                    scaled_pi = proto_tree_add_int_format(tcp_tree, hf_tcp_window_size_scalefactor, tvb, offset + 14, 2,
                                                          win_scale, "Window size scaling factor: %d (%s)",
                                                          win_scale,
                                                          (override_with_pref) ? "missing - taken from preference" : "unkown");
                    PROTO_ITEM_SET_GENERATED(scaled_pi);
                }
                break;

            case -2:
                scaled_pi = proto_tree_add_int_format(tcp_tree, hf_tcp_window_size_scalefactor, tvb, offset + 14, 2, tcpd->fwd->win_scale, "Window size scaling factor: %d (no window scaling used)", tcpd->fwd->win_scale);
                PROTO_ITEM_SET_GENERATED(scaled_pi);
                break;

            default:
                scaled_pi = proto_tree_add_int_format(tcp_tree, hf_tcp_window_size_scalefactor, tvb, offset + 14, 2, 1<<tcpd->fwd->win_scale, "Window size scaling factor: %d", 1<<tcpd->fwd->win_scale);
                PROTO_ITEM_SET_GENERATED(scaled_pi);
            }
        }
    }

    if(tcph->th_flags & TH_SYN) {
        if(tcph->th_flags & TH_ACK) {
           expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_CHAT, "Connection establish acknowledge (SYN+ACK): server port %s",
                                   get_tcp_port(tcph->th_sport));
           /* Save the server port to help determine dissector used */
           tcpd->server_port = tcph->th_sport;
        }
        else {
           expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_CHAT, "Connection establish request (SYN): server port %s",
                                   get_tcp_port(tcph->th_dport));
           /* Save the server port to help determine dissector used */
           tcpd->server_port = tcph->th_dport;
        }
    }
    if(tcph->th_flags & TH_FIN)
        /* XXX - find a way to know the server port and output only that one */
        expert_add_info_format(pinfo, tf_fin, PI_SEQUENCE, PI_CHAT, "Connection finish (FIN)");
    if(tcph->th_flags & TH_RST)
        /* XXX - find a way to know the server port and output only that one */
        expert_add_info_format(pinfo, tf_rst, PI_SEQUENCE, PI_CHAT, "Connection reset (RST)");

    /* Supply the sequence number of the first byte and of the first byte
       after the segment. */
    tcpinfo.seq = tcph->th_seq;
    tcpinfo.nxtseq = nxtseq;
    tcpinfo.lastackseq = tcph->th_ack;

    /* Assume we'll pass un-reassembled data to subdissectors. */
    tcpinfo.is_reassembled = FALSE;

    pinfo->private_data = &tcpinfo;

    /*
     * Assume, initially, that we can't desegment.
     */
    pinfo->can_desegment = 0;
    th_sum = tvb_get_ntohs(tvb, offset + 16);
    if (!pinfo->fragmented && tvb_bytes_exist(tvb, 0, reported_len)) {
        /* The packet isn't part of an un-reassembled fragmented datagram
           and isn't truncated.  This means we have all the data, and thus
           can checksum it and, unless it's being returned in an error
           packet, are willing to allow subdissectors to request reassembly
           on it. */

        if (tcp_check_checksum) {
            /* We haven't turned checksum checking off; checksum it. */

            /* Set up the fields of the pseudo-header. */
            cksum_vec[0].ptr = pinfo->src.data;
            cksum_vec[0].len = pinfo->src.len;
            cksum_vec[1].ptr = pinfo->dst.data;
            cksum_vec[1].len = pinfo->dst.len;
            cksum_vec[2].ptr = (const guint8 *)phdr;
            switch (pinfo->src.type) {

            case AT_IPv4:
                phdr[0] = g_htonl((IP_PROTO_TCP<<16) + reported_len);
                cksum_vec[2].len = 4;
                break;

            case AT_IPv6:
                phdr[0] = g_htonl(reported_len);
                phdr[1] = g_htonl(IP_PROTO_TCP);
                cksum_vec[2].len = 8;
                break;

            default:
                /* TCP runs only atop IPv4 and IPv6.... */
                DISSECTOR_ASSERT_NOT_REACHED();
                break;
            }
            cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, reported_len);
            cksum_vec[3].len = reported_len;
            computed_cksum = in_cksum(cksum_vec, 4);
            if (computed_cksum == 0 && th_sum == 0xffff) {
                item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                                  offset + 16, 2, th_sum,
                                                  "Checksum: 0x%04x [should be 0x0000 (see RFC 1624)]", th_sum);

                checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(item);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(item);
                expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_WARN, "TCP Checksum 0xffff instead of 0x0000 (see RFC 1624)");

                col_append_str(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM 0xFFFF]");

                /* Checksum is treated as valid on most systems, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else if (computed_cksum == 0) {
                item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                                  offset + 16, 2, th_sum, "Checksum: 0x%04x [correct]", th_sum);

                checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                              offset + 16, 2, TRUE);
                PROTO_ITEM_SET_GENERATED(item);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(item);

                /* Checksum is valid, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else if (th_sum == 0) {
                /* checksum is probably fine but checksum offload is used */
                item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                                  offset + 16, 2, th_sum, "Checksum: 0x%04x [Checksum Offloaded]", th_sum);

                checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(item);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(item);

                /* Checksum is (probably) valid, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else {
                item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                                  offset + 16, 2, th_sum,
                                                  "Checksum: 0x%04x [incorrect, should be 0x%04x (maybe caused by \"TCP checksum offload\"?)]", th_sum,
                                                  in_cksum_shouldbe(th_sum, computed_cksum));

                checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(item);
                item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                              offset + 16, 2, TRUE);
                PROTO_ITEM_SET_GENERATED(item);
                expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR, "Bad checksum");

                col_append_str(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM INCORRECT]");

                /* Checksum is invalid, so we're not willing to desegment it. */
                desegment_ok = FALSE;
                pinfo->noreassembly_reason = " [incorrect TCP checksum]";
            }
        } else {
            item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                              offset + 16, 2, th_sum, "Checksum: 0x%04x [validation disabled]", th_sum);

            checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
            item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                          offset + 16, 2, FALSE);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                          offset + 16, 2, FALSE);
            PROTO_ITEM_SET_GENERATED(item);

            /* We didn't check the checksum, and don't care if it's valid,
               so we're willing to desegment it. */
            desegment_ok = TRUE;
        }
    } else {
        /* We don't have all the packet data, so we can't checksum it... */
        item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                          offset + 16, 2, th_sum, "Checksum: 0x%04x [unchecked, not all data available]", th_sum);

        checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
        item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                      offset + 16, 2, FALSE);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                      offset + 16, 2, FALSE);
        PROTO_ITEM_SET_GENERATED(item);

        /* ...and aren't willing to desegment it. */
        desegment_ok = FALSE;
    }

    if (desegment_ok) {
        /* We're willing to desegment this.  Is desegmentation enabled? */
        if (tcp_desegment) {
            /* Yes - is this segment being returned in an error packet? */
            if (!pinfo->flags.in_error_pkt) {
                /* No - indicate that we will desegment.
                   We do NOT want to desegment segments returned in error
                   packets, as they're not part of a TCP connection. */
                pinfo->can_desegment = 2;
            }
        }
    }

    th_urp = tvb_get_ntohs(tvb, offset + 18);
    if (tcph->th_flags & TH_URG) {
        /* Export the urgent pointer, for the benefit of protocols such as
           rlogin. */
        tcpinfo.urgent = TRUE;
        tcpinfo.urgent_pointer = th_urp;
        col_append_fstr(pinfo->cinfo, COL_INFO, " Urg=%u", th_urp);
        if (tcp_tree != NULL)
            proto_tree_add_uint(tcp_tree, hf_tcp_urgent_pointer, tvb, offset + 18, 2, th_urp);
    } else {
        tcpinfo.urgent = FALSE;
        if (th_urp) {
            item = proto_tree_add_uint_format(tcp_tree, hf_tcp_urgent_pointer, tvb, offset + 18, 2, th_urp,
                                              "Urgent Pointer: 0x%04x [should be 0x0000 because URG flag is not set]",
                                              th_urp);
            expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                "Urgent Pointer: Broken TCP. The urgent pointer field is nonzero while the URG flag is not set");
        }
    }


    if (tcph->th_have_seglen) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Len=%u", tcph->th_seglen);
    }

    /* Decode TCP options, if any. */
    tcph->num_sack_ranges = 0;
    if (tcph->th_hlen > TCPH_MIN_LEN) {
        /* There's more than just the fixed-length header.  Decode the
           options. */
        optlen = tcph->th_hlen - TCPH_MIN_LEN; /* length of options, in bytes */
        tvb_ensure_bytes_exist(tvb, offset +  20, optlen);
        if (tcp_tree != NULL) {
            guint8 *p_options = ep_tvb_memdup(tvb, offset + 20, optlen);
            tf = proto_tree_add_bytes_format(tcp_tree, hf_tcp_options, tvb, offset +  20,
                                             optlen, p_options, "Options: (%u bytes)", optlen);
            field_tree = proto_item_add_subtree(tf, ett_tcp_options);
        } else {
            tf = NULL;
            field_tree = NULL;
        }
        dissect_ip_tcp_options(tvb, offset + 20, optlen,
                               tcpopts, N_TCP_OPTS, TCPOPT_EOL, pinfo, field_tree, tf, tcph);
    }

    if(!pinfo->fd->flags.visited) {
        if((tcph->th_flags & TH_SYN)==TH_SYN) {
            /* Check the validity of the window scale value
             */
            verify_tcp_window_scaling((tcph->th_flags&TH_ACK)==TH_ACK,tcpd);
        }

        if((tcph->th_flags & (TH_SYN|TH_ACK))==(TH_SYN|TH_ACK)) {
            /* If the SYN or the SYN+ACK offered SCPS capabilities,
             * validate the flow's bidirectional scps capabilities.
             * The or protects against broken implementations offering
             * SCPS capabilities on SYN+ACK even if it wasn't offered with the SYN
             */
            if(tcpd && ((tcpd->rev->scps_capable) || (tcpd->fwd->scps_capable))) {
                verify_scps(pinfo, tf_syn, tcpd);
            }
        }
    }

    /* Skip over header + options */
    offset += tcph->th_hlen;

    /* Check the packet length to see if there's more data
       (it could be an ACK-only packet) */
    length_remaining = tvb_length_remaining(tvb, offset);

    if (tcph->th_have_seglen) {
        if( data_out_file ) {
            reassemble_tcp( tcpd->stream,                         /* tcp stream index */
                            tcph->th_seq,                         /* sequence number */
                            tcph->th_ack,                         /* acknowledgment number */
                            tcph->th_seglen,                      /* data length */
                            (gchar*)tvb_get_ptr(tvb, offset, length_remaining), /* data */
                            length_remaining,                     /* captured data length */
                            ( tcph->th_flags & TH_SYN ),          /* is syn set? */
                            &pinfo->net_src,
                            &pinfo->net_dst,
                            pinfo->srcport,
                            pinfo->destport);
        }
    }

    /* handle TCP seq# analysis, print any extra SEQ/ACK data for this segment*/
    if(tcp_analyze_seq) {
        guint32 use_seq = tcph->th_seq;
        guint32 use_ack = tcph->th_ack;
        /* May need to recover absolute values here... */
        if (tcp_relative_seq) {
            use_seq += tcpd->fwd->base_seq;
            use_ack += tcpd->rev->base_seq;
        }
        tcp_print_sequence_number_analysis(pinfo, tvb, tcp_tree, tcpd, use_seq, use_ack);
    }

    /* handle conversation timestamps */
    if(tcp_calculate_ts) {
        tcp_print_timestamps(pinfo, tvb, tcp_tree, tcpd, tcppd);
    }

    tap_queue_packet(tcp_tap, pinfo, tcph);


    /* A FIN packet might complete reassembly so we need to explicitly
     * check for this here.
     */
    if(tcph->th_have_seglen && tcpd && (tcph->th_flags & TH_FIN)
       && (tcpd->fwd->flags&TCP_FLOW_REASSEMBLE_UNTIL_FIN) ) {
        struct tcp_multisegment_pdu *msp;

        /* find the most previous PDU starting before this sequence number */
        msp=se_tree_lookup32_le(tcpd->fwd->multisegment_pdus, tcph->th_seq-1);
        if(msp) {
            fragment_data *ipfd_head;

            ipfd_head = fragment_add(tvb, offset, pinfo, msp->first_frame,
                                     tcp_fragment_table,
                                     tcph->th_seq - msp->seq,
                                     tcph->th_seglen,
                                     FALSE );
            if(ipfd_head) {
                tvbuff_t *next_tvb;

                /* create a new TVB structure for desegmented data
                 * datalen-1 to strip the dummy FIN byte off
                 */
                next_tvb = tvb_new_child_real_data(tvb, ipfd_head->data, ipfd_head->datalen, ipfd_head->datalen);

                /* add desegmented data to the data source list */
                add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

                /* call the payload dissector
                 * but make sure we don't offer desegmentation any more
                 */
                pinfo->can_desegment = 0;

                process_tcp_payload(next_tvb, 0, pinfo, tree, tcp_tree, tcph->th_sport, tcph->th_dport, tcph->th_seq, nxtseq, FALSE, tcpd);

                print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);

                return;
            }
        }
    }

    if (tcpd && ((tcpd->fwd && tcpd->fwd->command) || (tcpd->rev && tcpd->rev->command))) {
        ti = proto_tree_add_text(tcp_tree, tvb, offset, 0, "Process Information");
        PROTO_ITEM_SET_GENERATED(ti);
        field_tree = proto_item_add_subtree(ti, ett_tcp_process_info);
        if (tcpd->fwd && tcpd->fwd->command) {
            proto_tree_add_uint_format_value(field_tree, hf_tcp_proc_dst_uid, tvb, 0, 0,
                                             tcpd->fwd->process_uid, "%u", tcpd->fwd->process_uid);
            proto_tree_add_uint_format_value(field_tree, hf_tcp_proc_dst_pid, tvb, 0, 0,
                                             tcpd->fwd->process_pid, "%u", tcpd->fwd->process_pid);
            proto_tree_add_string_format_value(field_tree, hf_tcp_proc_dst_uname, tvb, 0, 0,
                                               tcpd->fwd->username, "%s", tcpd->fwd->username);
            proto_tree_add_string_format_value(field_tree, hf_tcp_proc_dst_cmd, tvb, 0, 0,
                                               tcpd->fwd->command, "%s", tcpd->fwd->command);
        }
        if (tcpd->rev && tcpd->rev->command) {
            proto_tree_add_uint_format_value(field_tree, hf_tcp_proc_src_uid, tvb, 0, 0,
                                             tcpd->rev->process_uid, "%u", tcpd->rev->process_uid);
            proto_tree_add_uint_format_value(field_tree, hf_tcp_proc_src_pid, tvb, 0, 0,
                                             tcpd->rev->process_pid, "%u", tcpd->rev->process_pid);
            proto_tree_add_string_format_value(field_tree, hf_tcp_proc_src_uname, tvb, 0, 0,
                                               tcpd->rev->username, "%s", tcpd->rev->username);
            proto_tree_add_string_format_value(field_tree, hf_tcp_proc_src_cmd, tvb, 0, 0,
                                               tcpd->rev->command, "%s", tcpd->rev->command);
        }
    }

    /*
     * XXX - what, if any, of this should we do if this is included in an
     * error packet?  It might be nice to see the details of the packet
     * that caused the ICMP error, but it might not be nice to have the
     * dissector update state based on it.
     * Also, we probably don't want to run TCP taps on those packets.
     */
    if (length_remaining != 0) {
        if (tcph->th_flags & TH_RST) {
            /*
             * RFC1122 says:
             *
             *  4.2.2.12  RST Segment: RFC-793 Section 3.4
             *
             *    A TCP SHOULD allow a received RST segment to include data.
             *
             *    DISCUSSION
             *         It has been suggested that a RST segment could contain
             *         ASCII text that encoded and explained the cause of the
             *         RST.  No standard has yet been established for such
             *         data.
             *
             * so for segments with RST we just display the data as text.
             */
            proto_tree_add_text(tcp_tree, tvb, offset, length_remaining,
                                "Reset cause: %s",
                                tvb_format_text(tvb, offset, length_remaining));
        } else {
            dissect_tcp_payload(tvb, pinfo, offset, tcph->th_seq, nxtseq,
                                tcph->th_sport, tcph->th_dport, tree, tcp_tree, tcpd);
        }
    }
}

static void
tcp_init(void)
{
    tcp_stream_index = 0;
    fragment_table_init(&tcp_fragment_table);
}

void
proto_register_tcp(void)
{
    static hf_register_info hf[] = {

        { &hf_tcp_srcport,
        { "Source Port",        "tcp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_dstport,
        { "Destination Port",       "tcp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_port,
        { "Source or Destination Port", "tcp.port", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_stream,
        { "Stream index",       "tcp.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_seq,
        { "Sequence number",        "tcp.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_nxtseq,
        { "Next sequence number",   "tcp.nxtseq", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_ack,
        { "Acknowledgment number", "tcp.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_hdr_len,
        { "Header Length",      "tcp.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_flags,
        { "Flags",          "tcp.flags", FT_UINT16, BASE_HEX, NULL, TH_MASK,
            NULL, HFILL }},

        { &hf_tcp_flags_res,
        { "Reserved",            "tcp.flags.res", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_RES,
            "Three reserved bits (must be zero)", HFILL }},

        { &hf_tcp_flags_ns,
        { "Nonce", "tcp.flags.ns", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_NS,
            "ECN concealment protection (RFC 3540)", HFILL }},

        { &hf_tcp_flags_cwr,
        { "Congestion Window Reduced (CWR)",            "tcp.flags.cwr", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_CWR,
            NULL, HFILL }},

        { &hf_tcp_flags_ecn,
        { "ECN-Echo",           "tcp.flags.ecn", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_ECN,
            NULL, HFILL }},

        { &hf_tcp_flags_urg,
        { "Urgent",         "tcp.flags.urg", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_URG,
            NULL, HFILL }},

        { &hf_tcp_flags_ack,
        { "Acknowledgment",        "tcp.flags.ack", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_ACK,
            NULL, HFILL }},

        { &hf_tcp_flags_push,
        { "Push",           "tcp.flags.push", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_PUSH,
            NULL, HFILL }},

        { &hf_tcp_flags_reset,
        { "Reset",          "tcp.flags.reset", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_RST,
            NULL, HFILL }},

        { &hf_tcp_flags_syn,
        { "Syn",            "tcp.flags.syn", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_SYN,
            NULL, HFILL }},

        { &hf_tcp_flags_fin,
        { "Fin",            "tcp.flags.fin", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_FIN,
            NULL, HFILL }},

        { &hf_tcp_window_size_value,
        { "Window size value",        "tcp.window_size_value", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The window size value from the TCP header", HFILL }},

        /* 32 bits so we can present some values adjusted to window scaling */
        { &hf_tcp_window_size,
        { "Calculated window size",        "tcp.window_size", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The scaled window size (if scaling has been used)", HFILL }},

        { &hf_tcp_window_size_scalefactor,
        { "Window size scaling factor", "tcp.window_size_scalefactor", FT_INT32, BASE_DEC, NULL, 0x0,
            "The window size scaling factor (-1 when unknown, -2 when no scaling is used)", HFILL }},

        { &hf_tcp_checksum,
        { "Checksum",           "tcp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

        { &hf_tcp_checksum_good,
        { "Good Checksum",      "tcp.checksum_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

        { &hf_tcp_checksum_bad,
        { "Bad Checksum",       "tcp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum doesn't match packet content; False: matches content or not checked", HFILL }},

        { &hf_tcp_analysis,
        { "SEQ/ACK analysis",   "tcp.analysis", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the TCP analysis shown", HFILL }},

        { &hf_tcp_analysis_flags,
        { "TCP Analysis Flags",     "tcp.analysis.flags", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the TCP analysis flags set", HFILL }},

        { &hf_tcp_analysis_retransmission,
        { "Retransmission",     "tcp.analysis.retransmission", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame is a suspected TCP retransmission", HFILL }},

        { &hf_tcp_analysis_fast_retransmission,
        { "Fast Retransmission",        "tcp.analysis.fast_retransmission", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame is a suspected TCP fast retransmission", HFILL }},

        { &hf_tcp_analysis_out_of_order,
        { "Out Of Order",       "tcp.analysis.out_of_order", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame is a suspected Out-Of-Order segment", HFILL }},

        { &hf_tcp_analysis_reused_ports,
        { "TCP Port numbers reused",        "tcp.analysis.reused_ports", FT_NONE, BASE_NONE, NULL, 0x0,
            "A new tcp session has started with previously used port numbers", HFILL }},

        { &hf_tcp_analysis_lost_packet,
        { "Previous Segment Unseen",      "tcp.analysis.lost_segment", FT_NONE, BASE_NONE, NULL, 0x0,
            "We may not have captured a segment before this one", HFILL }},

        { &hf_tcp_analysis_ack_lost_packet,
        { "ACKed Unseen Packet",      "tcp.analysis.ack_lost_segment", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame ACKs a segment that may not have been captured", HFILL }},

        { &hf_tcp_analysis_window_update,
        { "Window update",      "tcp.analysis.window_update", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame is a tcp window update", HFILL }},

        { &hf_tcp_analysis_window_full,
        { "Window full",        "tcp.analysis.window_full", FT_NONE, BASE_NONE, NULL, 0x0,
            "This segment has caused the allowed window to become 100% full", HFILL }},

        { &hf_tcp_analysis_keep_alive,
        { "Keep Alive",     "tcp.analysis.keep_alive", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a keep-alive segment", HFILL }},

        { &hf_tcp_analysis_keep_alive_ack,
        { "Keep Alive ACK",     "tcp.analysis.keep_alive_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is an ACK to a keep-alive segment", HFILL }},

        { &hf_tcp_analysis_duplicate_ack,
        { "Duplicate ACK",      "tcp.analysis.duplicate_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a duplicate ACK", HFILL }},

        { &hf_tcp_analysis_duplicate_ack_num,
        { "Duplicate ACK #",        "tcp.analysis.duplicate_ack_num", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This is duplicate ACK number #", HFILL }},

        { &hf_tcp_analysis_duplicate_ack_frame,
        { "Duplicate to the ACK in frame",      "tcp.analysis.duplicate_ack_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is a duplicate to the ACK in frame #", HFILL }},

        { &hf_tcp_continuation_to,
        { "This is a continuation to the PDU in frame",     "tcp.continuation_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is a continuation to the PDU in frame #", HFILL }},

        { &hf_tcp_analysis_zero_window_probe,
        { "Zero Window Probe",      "tcp.analysis.zero_window_probe", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a zero-window-probe", HFILL }},

        { &hf_tcp_analysis_zero_window_probe_ack,
        { "Zero Window Probe Ack",      "tcp.analysis.zero_window_probe_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is an ACK to a zero-window-probe", HFILL }},

        { &hf_tcp_analysis_zero_window,
        { "Zero Window",        "tcp.analysis.zero_window", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a zero-window", HFILL }},

        { &hf_tcp_len,
          { "TCP Segment Len",            "tcp.len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_analysis_acks_frame,
          { "This is an ACK to the segment in frame",            "tcp.analysis.acks_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which previous segment is this an ACK for", HFILL}},

        { &hf_tcp_analysis_bytes_in_flight,
          { "Bytes in flight",            "tcp.analysis.bytes_in_flight", FT_UINT32, BASE_DEC, NULL, 0x0,
            "How many bytes are now in flight for this connection", HFILL}},

        { &hf_tcp_analysis_ack_rtt,
          { "The RTT to ACK the segment was",            "tcp.analysis.ack_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long time it took to ACK the segment (RTT)", HFILL}},

        { &hf_tcp_analysis_rto,
          { "The RTO for this segment was",            "tcp.analysis.rto", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long transmission was delayed before this segment was retransmitted (RTO)", HFILL}},

        { &hf_tcp_analysis_rto_frame,
          { "RTO based on delta from frame", "tcp.analysis.rto_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is the frame we measure the RTO from", HFILL }},

        { &hf_tcp_urgent_pointer,
        { "Urgent pointer",     "tcp.urgent_pointer", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_segment_overlap,
        { "Segment overlap",    "tcp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }},

        { &hf_tcp_segment_overlap_conflict,
        { "Conflicting data in segment overlap",    "tcp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL }},

        { &hf_tcp_segment_multiple_tails,
        { "Multiple tail segments found",   "tcp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the pdu", HFILL }},

        { &hf_tcp_segment_too_long_fragment,
        { "Segment too long",   "tcp.segment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of the pdu", HFILL }},

        { &hf_tcp_segment_error,
        { "Reassembling error", "tcp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembling error due to illegal segments", HFILL }},

        { &hf_tcp_segment_count,
        { "Segment count", "tcp.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_segment,
        { "TCP Segment", "tcp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_segments,
        { "Reassembled TCP Segments", "tcp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
            "TCP Segments", HFILL }},

        { &hf_tcp_reassembled_in,
        { "Reassembled PDU in frame", "tcp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

        { &hf_tcp_reassembled_length,
        { "Reassembled TCP length", "tcp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        { &hf_tcp_reassembled_data,
        { "Reassembled TCP Data", "tcp.reassembled.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The reassembled payload", HFILL }},

        { &hf_tcp_option_kind,
          { "Kind", "tcp.option_kind", FT_UINT8,
            BASE_DEC, VALS(tcp_option_kind_vs), 0x0, "This TCP option's kind", HFILL }},

        { &hf_tcp_option_len,
          { "Length", "tcp.option_len", FT_UINT8,
            BASE_DEC, NULL, 0x0, "Length of this TCP option in bytes (including kind and length fields)", HFILL }},

        { &hf_tcp_options,
          { "TCP Options", "tcp.options", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_mss,
          { "TCP MSS Option", "tcp.options.mss", FT_NONE,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_mss_val,
          { "MSS Value", "tcp.options.mss_val", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_wscale_shift,
          { "Shift count", "tcp.options.wscale.shift", FT_UINT8,
            BASE_DEC, NULL, 0x0, "Logarithmically encoded power of 2 scale factor", HFILL}},

        { &hf_tcp_option_wscale_multiplier,
          { "Multiplier", "tcp.options.wscale.multiplier",  FT_UINT8,
            BASE_DEC, NULL, 0x0, "Multiply segment window size by this for scaled window size", HFILL}},

        { &hf_tcp_option_exp,
          { "TCP Option - Experimental", "tcp.options.experimental", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_exp_data,
          { "Data", "tcp.options.experimental.data", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack_perm,
          { "TCP SACK Permitted Option", "tcp.options.sack_perm",
            FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack,
          { "TCP SACK Option", "tcp.options.sack", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack_sle,
          {"TCP SACK Left Edge", "tcp.options.sack_le", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack_sre,
          {"TCP SACK Right Edge", "tcp.options.sack_re", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack_range_count,
          { "TCP SACK Count", "tcp.options.sack.count", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_echo,
          { "TCP Echo Option", "tcp.options.echo", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, "TCP Sack Echo", HFILL}},

        { &hf_tcp_option_echo_reply,
          { "TCP Echo Reply Option", "tcp.options.echo_reply",
            FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_timestamp_tsval,
          { "Timestamp value", "tcp.options.timestamp.tsval", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Value of sending machine's timestamp clock", HFILL}},

        { &hf_tcp_option_timestamp_tsecr,
          { "Timestamp echo reply", "tcp.options.timestamp.tsecr", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Echoed timestamp from remote machine", HFILL}},

        { &hf_tcp_option_mptcp_subtype,
          { "Multipath TCP subtype", "tcp.options.mptcp.subtype", FT_UINT8,
            BASE_DEC, VALS(mptcp_subtype_vs), 0xF0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_version,
          { "Multipath TCP version", "tcp.options.mptcp.version", FT_UINT8,
            BASE_DEC, NULL, 0x0F, NULL, HFILL}},

        { &hf_tcp_option_mptcp_flags,
          { "Multipath TCP flags", "tcp.options.mptcp.flags", FT_UINT8,
            BASE_HEX, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_B_flag,
          { "Backup flag", "tcp.options.mptcp.backup.flag", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_C_flag,
          { "Checksum required", "tcp.options.mptcp.checksumreq.flags", FT_UINT8,
            BASE_DEC, NULL, 0x80, NULL, HFILL}},

        { &hf_tcp_option_mptcp_S_flag,
          { "Use HMAC-SHA1", "tcp.options.mptcp.sha1.flag", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_F_flag,
          { "DATA_FIN", "tcp.options.mptcp.datafin.flag", FT_UINT8,
            BASE_DEC, NULL, 0x10, NULL, HFILL}},

        { &hf_tcp_option_mptcp_m_flag,
          { "Data Sequence Number is 8 octets", "tcp.options.mptcp.dseqn8.flag", FT_UINT8,
            BASE_DEC, NULL, 0x08, NULL, HFILL}},

        { &hf_tcp_option_mptcp_M_flag,
          { "Data Sequence Number, Subflow Sequence Number, Data-level Length, Checksum present", "tcp.options.mptcp.dseqnpresent.flag", FT_UINT8,
            BASE_DEC, NULL, 0x04, NULL, HFILL}},

        { &hf_tcp_option_mptcp_a_flag,
          { "Data ACK is 8 octets", "tcp.options.mptcp.dataack8.flag", FT_UINT8,
            BASE_DEC, NULL, 0x02, NULL, HFILL}},

        { &hf_tcp_option_mptcp_A_flag,
          { "Data ACK is present", "tcp.options.mptcp.dataackpresent.flag", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_address_id,
          { "Multipath TCP Address ID", "tcp.options.mptcp.addrid", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_key,
          { "Multipath TCP Sender's Key", "tcp.options.mptcp.sendkey", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_recv_key,
          { "Multipath TCP Receiver's Key", "tcp.options.mptcp.recvkey", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_recv_token,
          { "Multipath TCP Receiver's Token", "tcp.options.mptcp.recvtok", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_rand,
          { "Multipath TCP Sender's Random Number", "tcp.options.mptcp.sendrand", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_trunc_mac,
          { "Multipath TCP Sender's Truncated MAC", "tcp.options.mptcp.sendtruncmac", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_mac,
          { "Multipath TCP Sender's MAC", "tcp.options.mptcp.sendmac", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_data_ack,
          { "Multipath TCP Data ACK", "tcp.options.mptcp.dataack", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_data_seq_no,
          { "Multipath TCP Data Sequence Number", "tcp.options.mptcp.dataseqno", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_subflow_seq_no,
          { "Multipath TCP Subflow Sequence Number", "tcp.options.mptcp.subflowseqno", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_data_lvl_len,
          { "Multipath TCP Data-level Length", "tcp.options.mptcp.datalvllen", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_checksum,
          { "Multipath TCP Checksum", "tcp.options.mptcp.checksum", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_ipver,
          { "Multipath TCP IPVer", "tcp.options.mptcp.ipver", FT_UINT8,
            BASE_DEC, NULL, 0x0F, NULL, HFILL}},

        { &hf_tcp_option_mptcp_ipv4,
          { "Multipath TCP Address", "tcp.options.mptcp.ipv4", FT_IPv4,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_ipv6,
          { "Multipath TCP Address", "tcp.options.mptcp.ipv6", FT_IPv6,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_port,
          { "Multipath TCP Port", "tcp.options.mptcp.port", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_cc,
          { "TCP CC Option", "tcp.options.cc", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ccnew,
          { "TCP CC New Option", "tcp.options.ccnew", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ccecho,
          { "TCP CC Echo Option", "tcp.options.ccecho", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_md5,
          { "TCP MD5 Option", "tcp.options.md5", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_qs,
          { "TCP QS Option", "tcp.options.qs", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_scps,
          { "TCP SCPS Capabilities Option", "tcp.options.scps",
            FT_BOOLEAN, BASE_NONE, NULL,  0x0,
            NULL, HFILL}},

        { &hf_tcp_option_scps_vector,
          { "TCP SCPS Capabilities Vector", "tcp.options.scps.vector",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_scps_binding,
          { "Binding Space (Community) ID",
            "tcp.options.scps.binding.id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "TCP SCPS Extended Binding Space (Community) ID", HFILL}},

        { &hf_tcp_option_scps_binding_len,
          { "Extended Capability Length",
            "tcp.options.scps.binding.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "TCP SCPS Extended Capability Length in bytes", HFILL}},

        { &hf_tcp_option_snack,
          { "TCP Selective Negative Acknowledgment Option",
            "tcp.options.snack",
            FT_BOOLEAN, BASE_NONE, NULL,  0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_offset,
          { "TCP SNACK Offset", "tcp.options.snack.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_size,
          { "TCP SNACK Size", "tcp.options.snack.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_le,
          { "TCP SNACK Left Edge", "tcp.options.snack.le",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_re,
          { "TCP SNACK Right Edge", "tcp.options.snack.re",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_scpsoption_flags_bets,
          { "Partial Reliability Capable (BETS)",
            "tcp.options.scpsflags.bets", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x80, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_snack1,
          { "Short Form SNACK Capable (SNACK1)",
            "tcp.options.scpsflags.snack1", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x40, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_snack2,
          { "Long Form SNACK Capable (SNACK2)",
            "tcp.options.scpsflags.snack2", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x20, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_compress,
          { "Lossless Header Compression (COMP)",
            "tcp.options.scpsflags.compress", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x10, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_nlts,
          { "Network Layer Timestamp (NLTS)",
            "tcp.options.scpsflags.nlts", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x8, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_reserved,
          { "Reserved",
            "tcp.options.scpsflags.reserved", FT_UINT8, BASE_DEC,
            NULL, 0x7, NULL, HFILL }},

        { &hf_tcp_scpsoption_connection_id,
          { "Connection ID",
            "tcp.options.scps.binding",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "TCP SCPS Connection ID", HFILL}},

        { &hf_tcp_option_user_to,
          { "TCP User Timeout", "tcp.options.user_to", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_user_to_granularity,
          { "Granularity", "tcp.options.user_to_granularity", FT_BOOLEAN,
            16, TFS(&tcp_option_user_to_granularity), 0x8000, "TCP User Timeout Granularity", HFILL}},

        { &hf_tcp_option_user_to_val,
          { "User Timeout", "tcp.options.user_to_val", FT_UINT16,
            BASE_DEC, NULL, 0x7FFF, "TCP User Timeout Value", HFILL}},

        { &hf_tcp_option_rvbd_probe,
          { "Riverbed Probe", "tcp.options.rvbd.probe", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, "RVBD TCP Probe Option", HFILL }},

        { &hf_tcp_option_rvbd_probe_type1,
          { "Type", "tcp.options.rvbd.probe.type1",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_type2,
          { "Type", "tcp.options.rvbd.probe.type2",
            FT_UINT8, BASE_DEC, NULL, 0xFE, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_version1,
          { "Version", "tcp.options.rvbd.probe.version",
            FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_version2,
          { "Version", "tcp.options.rvbd.probe.version_raw",
            FT_UINT8, BASE_DEC, NULL, 0x01, "Version 2 Raw Value", HFILL }},

        { &hf_tcp_option_rvbd_probe_optlen,
          { "Length", "tcp.options.rvbd.probe.len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_prober,
          { "CSH IP", "tcp.options.rvbd.probe.prober",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_proxy,
          { "SSH IP", "tcp.options.rvbd.probe.proxy.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_proxy_port,
          { "SSH Port", "tcp.options.rvbd.probe.proxy.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_appli_ver,
          { "Application Version", "tcp.options.rvbd.probe.appli_ver",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_client,
          { "Client IP", "tcp.options.rvbd.probe.client.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_storeid,
          { "CFE Store ID", "tcp.options.rvbd.probe.storeid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flags,
          { "Probe Flags", "tcp.options.rvbd.probe.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_not_cfe,
          { "Not CFE", "tcp.options.rvbd.probe.flags.notcfe",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_NCFE,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_last_notify,
          { "Last Notify", "tcp.options.rvbd.probe.flags.last",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_LAST,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_probe_cache,
          { "Disable Probe Cache on CSH", "tcp.options.rvbd.probe.flags.probe",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_sslcert,
          { "SSL Enabled", "tcp.options.rvbd.probe.flags.ssl",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_SSLCERT,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_server_connected,
          { "SSH outer to server established", "tcp.options.rvbd.probe.flags.server",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_SERVER,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy,
          { "Riverbed Transparency", "tcp.options.rvbd.trpy",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "RVBD TCP Transparency Option", HFILL }},

        { &hf_tcp_option_rvbd_trpy_flags,
          { "Transparency Options", "tcp.options.rvbd.trpy.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_fw_rst_probe,
          { "Enable FW traversal feature", "tcp.options.rvbd.trpy.flags.fw_rst_probe",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_FW_RST_PROBE,
            "Reset state created by probe on the nexthop firewall",
            HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_fw_rst_inner,
          { "Enable Inner FW feature on All FWs", "tcp.options.rvbd.trpy.flags.fw_rst_inner",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_FW_RST_INNER,
            "Reset state created by transparent inner on all firewalls"
            " before passing connection through",
            HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_fw_rst,
          { "Enable Transparency FW feature on All FWs", "tcp.options.rvbd.trpy.flags.fw_rst",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_FW_RST,
            "Reset state created by probe on all firewalls before "
            "establishing transparent inner connection", HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_chksum,
          { "Reserved", "tcp.options.rvbd.trpy.flags.chksum",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_CHKSUM, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_oob,
          { "Out of band connection", "tcp.options.rvbd.trpy.flags.oob",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_OOB, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_mode,
          { "Transparency Mode", "tcp.options.rvbd.trpy.flags.mode",
            FT_BOOLEAN, 16, TFS(&trpy_mode_str),
            RVBD_FLAGS_TRPY_MODE, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_src,
          { "Src SH IP Addr", "tcp.options.rvbd.trpy.src.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_dst,
          { "Dst SH IP Addr", "tcp.options.rvbd.trpy.dst.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_src_port,
          { "Src SH Inner Port", "tcp.options.rvbd.trpy.src.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_dst_port,
          { "Dst SH Inner Port", "tcp.options.rvbd.trpy.dst.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_client_port,
          { "Out of band connection Client Port", "tcp.options.rvbd.trpy.client.port",
            FT_UINT16, BASE_DEC, NULL , 0x0, NULL, HFILL }},

        { &hf_tcp_pdu_time,
          { "Time until the last segment of this PDU", "tcp.pdu.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long time has passed until the last frame of this PDU", HFILL}},

        { &hf_tcp_pdu_size,
          { "PDU Size", "tcp.pdu.size", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The size of this PDU", HFILL}},

        { &hf_tcp_pdu_last_frame,
          { "Last frame of this PDU", "tcp.pdu.last_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is the last frame of the PDU starting in this segment", HFILL }},

        { &hf_tcp_ts_relative,
          { "Time since first frame in this TCP stream", "tcp.time_relative", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time relative to first frame in this TCP stream", HFILL}},

        { &hf_tcp_ts_delta,
          { "Time since previous frame in this TCP stream", "tcp.time_delta", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time delta from previous frame in this TCP stream", HFILL}},

        { &hf_tcp_proc_src_uid,
          { "Source process user ID", "tcp.proc.srcuid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_src_pid,
          { "Source process ID", "tcp.proc.srcpid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_src_uname,
          { "Source process user name", "tcp.proc.srcuname", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_src_cmd,
          { "Source process name", "tcp.proc.srccmd", FT_STRING, BASE_NONE, NULL, 0x0,
            "Source process command name", HFILL}},

        { &hf_tcp_proc_dst_uid,
          { "Destination process user ID", "tcp.proc.dstuid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_dst_pid,
          { "Destination process ID", "tcp.proc.dstpid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_dst_uname,
          { "Destination process user name", "tcp.proc.dstuname", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_dst_cmd,
          { "Destination process name", "tcp.proc.dstcmd", FT_STRING, BASE_NONE, NULL, 0x0,
            "Destination process command name", HFILL}},

        { &hf_tcp_data,
          { "TCP segment data", "tcp.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}}
    };

    static gint *ett[] = {
        &ett_tcp,
        &ett_tcp_flags,
        &ett_tcp_options,
        &ett_tcp_option_timestamp,
        &ett_tcp_option_mptcp,
        &ett_tcp_option_wscale,
        &ett_tcp_option_sack,
        &ett_tcp_option_scps,
        &ett_tcp_option_scps_extended,
        &ett_tcp_option_user_to,
        &ett_tcp_option_exp,
        &ett_tcp_option_sack_perm,
        &ett_tcp_option_mss,
        &ett_tcp_opt_rvbd_probe,
        &ett_tcp_opt_rvbd_probe_flags,
        &ett_tcp_opt_rvbd_trpy,
        &ett_tcp_opt_rvbd_trpy_flags,
        &ett_tcp_analysis_faults,
        &ett_tcp_analysis,
        &ett_tcp_timestamps,
        &ett_tcp_segments,
        &ett_tcp_segment,
        &ett_tcp_checksum,
        &ett_tcp_process_info
    };

    static enum_val_t window_scaling_vals[] = {
        {"not-known",  "Not known",                  WindowScaling_NotKnown},
        {"0",          "0 (no scaling)",             WindowScaling_0},
        {"1",          "1 (multiply by 2)",          WindowScaling_1},
        {"2",          "2 (multiply by 4)",          WindowScaling_2},
        {"3",          "3 (multiply by 8)",          WindowScaling_3},
        {"4",          "4 (multiply by 16)",         WindowScaling_4},
        {"5",          "5 (multiply by 32)",         WindowScaling_5},
        {"6",          "6 (multiply by 64)",         WindowScaling_6},
        {"7",          "7 (multiply by 128)",        WindowScaling_7},
        {"8",          "8 (multiply by 256)",        WindowScaling_8},
        {"9",          "9 (multiply by 512)",        WindowScaling_9},
        {"10",         "10 (multiply by 1024)",      WindowScaling_10},
        {"11",         "11 (multiply by 2048)",      WindowScaling_11},
        {"12",         "12 (multiply by 4096)",      WindowScaling_12},
        {"13",         "13 (multiply by 8192)",      WindowScaling_13},
        {"14",         "14 (multiply by 16384)",     WindowScaling_14},
        {NULL, NULL, -1}
    };


    module_t *tcp_module;

    proto_tcp = proto_register_protocol("Transmission Control Protocol",
        "TCP", "tcp");
    register_dissector("tcp", dissect_tcp, proto_tcp);
    proto_register_field_array(proto_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* subdissector code */
    subdissector_table = register_dissector_table("tcp.port",
        "TCP port", FT_UINT16, BASE_DEC);
    register_heur_dissector_list("tcp", &heur_subdissector_list);

    /* Register configuration preferences */
    tcp_module = prefs_register_protocol(proto_tcp, NULL);
    prefs_register_bool_preference(tcp_module, "summary_in_tree",
        "Show TCP summary in protocol tree",
        "Whether the TCP summary line should be shown in the protocol tree",
        &tcp_summary_in_tree);
    prefs_register_bool_preference(tcp_module, "check_checksum",
        "Validate the TCP checksum if possible",
        "Whether to validate the TCP checksum",
        &tcp_check_checksum);
    prefs_register_bool_preference(tcp_module, "desegment_tcp_streams",
        "Allow subdissector to reassemble TCP streams",
        "Whether subdissector can request TCP streams to be reassembled",
        &tcp_desegment);
    prefs_register_bool_preference(tcp_module, "analyze_sequence_numbers",
        "Analyze TCP sequence numbers",
        "Make the TCP dissector analyze TCP sequence numbers to find and flag segment retransmissions, missing segments and RTT",
        &tcp_analyze_seq);
    prefs_register_bool_preference(tcp_module, "relative_sequence_numbers",
        "Relative sequence numbers",
        "Make the TCP dissector use relative sequence numbers instead of absolute ones. "
        "To use this option you must also enable \"Analyze TCP sequence numbers\". ",
        &tcp_relative_seq);
    prefs_register_enum_preference(tcp_module, "default_window_scaling",
        "Scaling factor to use when not available from capture",
        "Make the TCP dissector use this scaling factor for streams where the signalled scaling factor "
        "is not visible in the capture",
        &tcp_default_window_scaling, window_scaling_vals, FALSE);

    /* Presumably a retired, unconditional version of what has been added back with the preference above... */
    prefs_register_obsolete_preference(tcp_module, "window_scaling");

    prefs_register_bool_preference(tcp_module, "track_bytes_in_flight",
        "Track number of bytes in flight",
        "Make the TCP dissector track the number on un-ACKed bytes of data are in flight per packet. "
        "To use this option you must also enable \"Analyze TCP sequence numbers\". "
        "This takes a lot of memory but allows you to track how much data are in flight at a time and graphing it in io-graphs",
        &tcp_track_bytes_in_flight);
    prefs_register_bool_preference(tcp_module, "calculate_timestamps",
        "Calculate conversation timestamps",
        "Calculate timestamps relative to the first frame and the previous frame in the tcp conversation",
        &tcp_calculate_ts);
    prefs_register_bool_preference(tcp_module, "try_heuristic_first",
        "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
        &try_heuristic_first);
    prefs_register_bool_preference(tcp_module, "ignore_tcp_timestamps",
        "Ignore TCP Timestamps in summary",
        "Do not place the TCP Timestamps in the summary line",
        &tcp_ignore_timestamps);

    prefs_register_bool_preference(tcp_module, "no_subdissector_on_error",
        "Do not call subdissectors for error packets",
        "Do not call any subdissectors for Retransmitted or OutOfOrder segments",
        &tcp_no_subdissector_on_error);

    register_init_routine(tcp_init);
}

void
proto_reg_handoff_tcp(void)
{
    dissector_handle_t tcp_handle;

    tcp_handle = find_dissector("tcp");
    dissector_add_uint("ip.proto", IP_PROTO_TCP, tcp_handle);
    data_handle = find_dissector("data");
    tcp_tap = register_tap("tcp");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
