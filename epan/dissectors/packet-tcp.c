/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/exceptions.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/ip_opts.h>
#include <epan/follow.h>
#include <epan/prefs.h>
#include <epan/show_exception.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/sequence_analysis.h>
#include <epan/reassemble.h>
#include <epan/decode_as.h>
#include <epan/exported_pdu.h>
#include <epan/in_cksum.h>
#include <epan/proto_data.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/str_util.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/pint.h>
#include <wsutil/ws_assert.h>

#include "packet-tcp.h"
#include "packet-ip.h"
#include "packet-icmp.h"

void proto_register_tcp(void);
void proto_reg_handoff_tcp(void);
static void conversation_completeness_fill(gchar*, guint32);

static int tcp_tap = -1;
static int tcp_follow_tap = -1;
static int mptcp_tap = -1;
static int exported_pdu_tap = -1;

/* Place TCP summary in proto tree */
static gboolean tcp_summary_in_tree = TRUE;

static inline guint64 KEEP_32MSB_OF_GUINT64(guint64 nb) {
    return (nb >> 32) << 32;
}

#define MPTCP_DSS_FLAG_DATA_ACK_PRESENT     0x01
#define MPTCP_DSS_FLAG_DATA_ACK_8BYTES      0x02
#define MPTCP_DSS_FLAG_MAPPING_PRESENT      0x04
#define MPTCP_DSS_FLAG_DSN_8BYTES           0x08
#define MPTCP_DSS_FLAG_DATA_FIN_PRESENT     0x10

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

/*
 * Using enum instead of boolean make API easier
 */
enum mptcp_dsn_conversion {
    DSN_CONV_64_TO_32,
    DSN_CONV_32_TO_64,
    DSN_CONV_NONE
} ;

#define MPTCP_TCPRST_FLAG_T_PRESENT     0x1
#define MPTCP_TCPRST_FLAG_W_PRESENT     0x2
#define MPTCP_TCPRST_FLAG_V_PRESENT     0x4
#define MPTCP_TCPRST_FLAG_U_PRESENT     0x8

static const value_string mp_tcprst_reasons[] = {
        { 0x0, "Unspecified error" },
        { 0x1, "MPTCP-specific error" },
        { 0x2, "Lack of resources" },
        { 0x3, "Administratively prohibited" },
        { 0x4, "Too much outstanding data" },
        { 0x5, "Unacceptable performance" },
        { 0x6, "Middlebox interference" },
        { 0, NULL },
};

static gint tcp_default_window_scaling = (gint)WindowScaling_NotKnown;

static int proto_tcp = -1;
static int proto_ip = -1;
static int proto_icmp = -1;

static int proto_tcp_option_nop = -1;
static int proto_tcp_option_eol = -1;
static int proto_tcp_option_timestamp = -1;
static int proto_tcp_option_mss = -1;
static int proto_tcp_option_wscale = -1;
static int proto_tcp_option_sack_perm = -1;
static int proto_tcp_option_sack = -1;
static int proto_tcp_option_echo = -1;
static int proto_tcp_option_echoreply = -1;
static int proto_tcp_option_cc = -1;
static int proto_tcp_option_cc_new = -1;
static int proto_tcp_option_cc_echo = -1;
static int proto_tcp_option_md5 = -1;
static int proto_tcp_option_ao = -1;
static int proto_tcp_option_scps = -1;
static int proto_tcp_option_snack = -1;
static int proto_tcp_option_scpsrec = -1;
static int proto_tcp_option_scpscor = -1;
static int proto_tcp_option_qs = -1;
static int proto_tcp_option_user_to = -1;
static int proto_tcp_option_tfo = -1;
static int proto_tcp_option_rvbd_probe = -1;
static int proto_tcp_option_rvbd_trpy = -1;
static int proto_tcp_option_exp = -1;
static int proto_tcp_option_unknown = -1;
static int proto_mptcp = -1;

static int hf_tcp_srcport = -1;
static int hf_tcp_dstport = -1;
static int hf_tcp_port = -1;
static int hf_tcp_stream = -1;
static int hf_tcp_completeness = -1;
static int hf_tcp_seq = -1;
static int hf_tcp_seq_abs = -1;
static int hf_tcp_nxtseq = -1;
static int hf_tcp_ack = -1;
static int hf_tcp_ack_abs = -1;
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
static int hf_tcp_flags_str = -1;
static int hf_tcp_window_size_value = -1;
static int hf_tcp_window_size = -1;
static int hf_tcp_window_size_scalefactor = -1;
static int hf_tcp_checksum = -1;
static int hf_tcp_checksum_status = -1;
static int hf_tcp_checksum_calculated = -1;
static int hf_tcp_len = -1;
static int hf_tcp_urgent_pointer = -1;
static int hf_tcp_analysis = -1;
static int hf_tcp_analysis_flags = -1;
static int hf_tcp_analysis_bytes_in_flight = -1;
static int hf_tcp_analysis_push_bytes_sent = -1;
static int hf_tcp_analysis_acks_frame = -1;
static int hf_tcp_analysis_ack_rtt = -1;
static int hf_tcp_analysis_first_rtt = -1;
static int hf_tcp_analysis_rto = -1;
static int hf_tcp_analysis_rto_frame = -1;
static int hf_tcp_analysis_duplicate_ack = -1;
static int hf_tcp_analysis_duplicate_ack_num = -1;
static int hf_tcp_analysis_duplicate_ack_frame = -1;
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
static int hf_tcp_option_mss_val = -1;
static int hf_tcp_option_wscale_shift = -1;
static int hf_tcp_option_wscale_multiplier = -1;
static int hf_tcp_option_sack_sle = -1;
static int hf_tcp_option_sack_sre = -1;
static int hf_tcp_option_sack_range_count = -1;
static int hf_tcp_option_sack_dsack_le = -1;
static int hf_tcp_option_sack_dsack_re = -1;
static int hf_tcp_option_echo = -1;
static int hf_tcp_option_timestamp_tsval = -1;
static int hf_tcp_option_timestamp_tsecr = -1;
static int hf_tcp_option_cc = -1;
static int hf_tcp_option_md5_digest = -1;
static int hf_tcp_option_ao_keyid = -1;
static int hf_tcp_option_ao_rnextkeyid = -1;
static int hf_tcp_option_ao_mac = -1;
static int hf_tcp_option_qs_rate = -1;
static int hf_tcp_option_qs_ttl_diff = -1;
static int hf_tcp_option_exp_data = -1;
static int hf_tcp_option_exp_magic_number = -1;
static int hf_tcp_option_unknown_payload = -1;

static int hf_tcp_option_rvbd_probe_version1 = -1;
static int hf_tcp_option_rvbd_probe_version2 = -1;
static int hf_tcp_option_rvbd_probe_type1 = -1;
static int hf_tcp_option_rvbd_probe_type2 = -1;
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
static int hf_tcp_option_mptcp_backup_flag = -1;
static int hf_tcp_option_mptcp_checksum_flag = -1;
static int hf_tcp_option_mptcp_B_flag = -1;
static int hf_tcp_option_mptcp_C_flag = -1;
static int hf_tcp_option_mptcp_H_v0_flag = -1;
static int hf_tcp_option_mptcp_H_v1_flag = -1;
static int hf_tcp_option_mptcp_F_flag = -1;
static int hf_tcp_option_mptcp_m_flag = -1;
static int hf_tcp_option_mptcp_M_flag = -1;
static int hf_tcp_option_mptcp_a_flag = -1;
static int hf_tcp_option_mptcp_A_flag = -1;
static int hf_tcp_option_mptcp_U_flag = -1;
static int hf_tcp_option_mptcp_V_flag = -1;
static int hf_tcp_option_mptcp_W_flag = -1;
static int hf_tcp_option_mptcp_T_flag = -1;
static int hf_tcp_option_mptcp_tcprst_reason = -1;
static int hf_tcp_option_mptcp_reserved_v0_flag = -1;
static int hf_tcp_option_mptcp_reserved_v1_flag = -1;
static int hf_tcp_option_mptcp_subtype = -1;
static int hf_tcp_option_mptcp_version = -1;
static int hf_tcp_option_mptcp_reserved = -1;
static int hf_tcp_option_mptcp_address_id = -1;
static int hf_tcp_option_mptcp_recv_token = -1;
static int hf_tcp_option_mptcp_sender_key = -1;
static int hf_tcp_option_mptcp_recv_key = -1;
static int hf_tcp_option_mptcp_sender_rand = -1;
static int hf_tcp_option_mptcp_sender_trunc_hmac = -1;
static int hf_tcp_option_mptcp_sender_hmac = -1;
static int hf_tcp_option_mptcp_addaddr_trunc_hmac = -1;
static int hf_tcp_option_mptcp_data_ack_raw = -1;
static int hf_tcp_option_mptcp_data_seq_no_raw = -1;
static int hf_tcp_option_mptcp_subflow_seq_no = -1;
static int hf_tcp_option_mptcp_data_lvl_len = -1;
static int hf_tcp_option_mptcp_checksum = -1;
static int hf_tcp_option_mptcp_ipver = -1;
static int hf_tcp_option_mptcp_echo = -1;
static int hf_tcp_option_mptcp_ipv4 = -1;
static int hf_tcp_option_mptcp_ipv6 = -1;
static int hf_tcp_option_mptcp_port = -1;
static int hf_mptcp_expected_idsn = -1;

static int hf_mptcp_dsn = -1;
static int hf_mptcp_rawdsn64 = -1;
static int hf_mptcp_dss_dsn = -1;
static int hf_mptcp_ack = -1;
static int hf_mptcp_stream = -1;
static int hf_mptcp_expected_token = -1;
static int hf_mptcp_analysis = -1;
static int hf_mptcp_analysis_master = -1;
static int hf_mptcp_analysis_subflows = -1;
static int hf_mptcp_number_of_removed_addresses = -1;
static int hf_mptcp_related_mapping = -1;
static int hf_mptcp_reinjection_of = -1;
static int hf_mptcp_reinjected_in = -1;


static int hf_tcp_option_fast_open_cookie_request = -1;
static int hf_tcp_option_fast_open_cookie = -1;

static int hf_tcp_ts_relative = -1;
static int hf_tcp_ts_delta = -1;
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
static int hf_tcp_option_snack_offset = -1;
static int hf_tcp_option_snack_size = -1;
static int hf_tcp_option_snack_le = -1;
static int hf_tcp_option_snack_re = -1;
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
static int hf_tcp_segment_data = -1;
static int hf_tcp_payload = -1;
static int hf_tcp_reset_cause = -1;
static int hf_tcp_fin_retransmission = -1;
static int hf_tcp_option_rvbd_probe_reserved = -1;
static int hf_tcp_option_scps_binding_data = -1;
static int hf_tcp_syncookie_time = -1;
static int hf_tcp_syncookie_mss = -1;
static int hf_tcp_syncookie_hash = -1;
static int hf_tcp_syncookie_option_timestamp = -1;
static int hf_tcp_syncookie_option_ecn = -1;
static int hf_tcp_syncookie_option_sack = -1;
static int hf_tcp_syncookie_option_wscale = -1;

static gint ett_tcp = -1;
static gint ett_tcp_flags = -1;
static gint ett_tcp_options = -1;
static gint ett_tcp_option_timestamp = -1;
static gint ett_tcp_option_mss = -1;
static gint ett_tcp_option_wscale = -1;
static gint ett_tcp_option_sack = -1;
static gint ett_tcp_option_snack = -1;
static gint ett_tcp_option_scps = -1;
static gint ett_tcp_scpsoption_flags = -1;
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
static gint ett_tcp_opt_echo = -1;
static gint ett_tcp_opt_cc = -1;
static gint ett_tcp_opt_md5 = -1;
static gint ett_tcp_opt_ao = -1;
static gint ett_tcp_opt_qs = -1;
static gint ett_tcp_opt_recbound = -1;
static gint ett_tcp_opt_scpscor = -1;
static gint ett_tcp_unknown_opt = -1;
static gint ett_tcp_option_other = -1;
static gint ett_tcp_syncookie = -1;
static gint ett_tcp_syncookie_option = -1;
static gint ett_mptcp_analysis = -1;
static gint ett_mptcp_analysis_subflows = -1;

static expert_field ei_tcp_opt_len_invalid = EI_INIT;
static expert_field ei_tcp_analysis_retransmission = EI_INIT;
static expert_field ei_tcp_analysis_fast_retransmission = EI_INIT;
static expert_field ei_tcp_analysis_spurious_retransmission = EI_INIT;
static expert_field ei_tcp_analysis_out_of_order = EI_INIT;
static expert_field ei_tcp_analysis_reused_ports = EI_INIT;
static expert_field ei_tcp_analysis_lost_packet = EI_INIT;
static expert_field ei_tcp_analysis_ack_lost_packet = EI_INIT;
static expert_field ei_tcp_analysis_window_update = EI_INIT;
static expert_field ei_tcp_analysis_window_full = EI_INIT;
static expert_field ei_tcp_analysis_keep_alive = EI_INIT;
static expert_field ei_tcp_analysis_keep_alive_ack = EI_INIT;
static expert_field ei_tcp_analysis_duplicate_ack = EI_INIT;
static expert_field ei_tcp_analysis_zero_window_probe = EI_INIT;
static expert_field ei_tcp_analysis_zero_window = EI_INIT;
static expert_field ei_tcp_analysis_zero_window_probe_ack = EI_INIT;
static expert_field ei_tcp_analysis_tfo_syn = EI_INIT;
static expert_field ei_tcp_analysis_tfo_ack = EI_INIT;
static expert_field ei_tcp_analysis_tfo_ignored = EI_INIT;
static expert_field ei_tcp_scps_capable = EI_INIT;
static expert_field ei_tcp_option_sack_dsack = EI_INIT;
static expert_field ei_tcp_option_snack_sequence = EI_INIT;
static expert_field ei_tcp_option_wscale_shift_invalid = EI_INIT;
static expert_field ei_tcp_option_mss_absent = EI_INIT;
static expert_field ei_tcp_option_mss_present = EI_INIT;
static expert_field ei_tcp_short_segment = EI_INIT;
static expert_field ei_tcp_ack_nonzero = EI_INIT;
static expert_field ei_tcp_connection_synack = EI_INIT;
static expert_field ei_tcp_connection_syn = EI_INIT;
static expert_field ei_tcp_connection_fin = EI_INIT;
static expert_field ei_tcp_connection_rst = EI_INIT;
static expert_field ei_tcp_connection_fin_active = EI_INIT;
static expert_field ei_tcp_connection_fin_passive = EI_INIT;
static expert_field ei_tcp_checksum_ffff = EI_INIT;
static expert_field ei_tcp_checksum_bad = EI_INIT;
static expert_field ei_tcp_urgent_pointer_non_zero = EI_INIT;
static expert_field ei_tcp_suboption_malformed = EI_INIT;
static expert_field ei_tcp_nop = EI_INIT;
static expert_field ei_tcp_bogus_header_length = EI_INIT;

/* static expert_field ei_mptcp_analysis_unexpected_idsn = EI_INIT; */
static expert_field ei_mptcp_analysis_echoed_key_mismatch = EI_INIT;
static expert_field ei_mptcp_analysis_missing_algorithm = EI_INIT;
static expert_field ei_mptcp_analysis_unsupported_algorithm = EI_INIT;
static expert_field ei_mptcp_infinite_mapping= EI_INIT;
static expert_field ei_mptcp_mapping_missing = EI_INIT;
/* static expert_field ei_mptcp_stream_incomplete = EI_INIT; */
/* static expert_field ei_mptcp_analysis_dsn_out_of_order = EI_INIT; */

/* Some protocols such as encrypted DCE/RPCoverHTTP have dependencies
 * from one PDU to the next PDU and require that they are called in sequence.
 * These protocols would not be able to handle PDUs coming out of order
 * or for example when a PDU is seen twice, like for retransmissions.
 * This preference can be set for such protocols to make sure that we don't
 * invoke the subdissectors for retransmitted or out-of-order segments.
 */
static gboolean tcp_no_subdissector_on_error = TRUE;

/* Enable buffering of out-of-order TCP segments before passing it to a
 * subdissector (depends on "tcp_desegment"). */
static gboolean tcp_reassemble_out_of_order = FALSE;

/*
 * FF: (draft-ietf-tcpm-experimental-options-03)
 * With this flag set we assume the option structure for experimental
 * codepoints (253, 254) has a magic number field (first field after the
 * Kind and Length).  The magic number is used to differentiate different
 * experiments and thus will be used in data dissection.
 */
static gboolean tcp_exp_options_with_magic = TRUE;

/*
 * This flag indicates which of Fast Retransmission or Out-of-Order
 * interpretation should supersede when analyzing an ambiguous packet as
 * things are not always clear. The user is authorized to change this
 * behavior.
 * When set, we keep the historical interpretation (Fast RT > OOO)
 */
static gboolean tcp_fastrt_precedence = TRUE;

/* Process info, currently discovered via IPFIX */
static gboolean tcp_display_process_info = FALSE;

/* Read the sequence number as syn cookie */
static gboolean read_seq_as_syn_cookie = FALSE;

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
#define TCPOPT_SCPS             20      /* SCPS Capabilities */
#define TCPOPT_SNACK            21      /* SCPS SNACK */
#define TCPOPT_RECBOUND         22      /* SCPS Record Boundary */
#define TCPOPT_CORREXP          23      /* SCPS Corruption Experienced */
#define TCPOPT_QS               27      /* RFC4782 Quick-Start Response */
#define TCPOPT_USER_TO          28      /* RFC5482 User Timeout Option */
#define TCPOPT_AO               29      /* RFC5925 The TCP Authentication Option */
#define TCPOPT_MPTCP            30      /* RFC6824 Multipath TCP */
#define TCPOPT_TFO              34      /* RFC7413 TCP Fast Open Cookie */
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
#define TCPOLEN_SCPS           4
#define TCPOLEN_SNACK          6
#define TCPOLEN_RECBOUND       2
#define TCPOLEN_CORREXP        2
#define TCPOLEN_QS             8
#define TCPOLEN_USER_TO        4
#define TCPOLEN_MPTCP_MIN      3
#define TCPOLEN_TFO_MIN        2
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
#define TCPOPT_MPTCP_MP_FASTCLOSE  0x7    /* Multipath TCP Fast Close */
#define TCPOPT_MPTCP_MP_TCPRST     0x8    /* Multipath TCP Reset */

/*
 *     Conversation Completeness values
 */
#define TCP_COMPLETENESS_SYNSENT    0x01  /* TCP SYN SENT */
#define TCP_COMPLETENESS_SYNACK     0x02  /* TCP SYN ACK  */
#define TCP_COMPLETENESS_ACK        0x04  /* TCP ACK      */
#define TCP_COMPLETENESS_DATA       0x08  /* TCP data     */
#define TCP_COMPLETENESS_FIN        0x10  /* TCP FIN      */
#define TCP_COMPLETENESS_RST        0x20  /* TCP RST      */

static const true_false_string tcp_option_user_to_granularity = {
  "Minutes", "Seconds"
};

static const value_string tcp_option_kind_vs[] = {
    { TCPOPT_EOL, "End of Option List" },
    { TCPOPT_NOP, "No-Operation" },
    { TCPOPT_MSS, "Maximum Segment Size" },
    { TCPOPT_WINDOW, "Window Scale" },
    { TCPOPT_SACK_PERM, "SACK Permitted" },
    { TCPOPT_SACK, "SACK" },
    { TCPOPT_ECHO, "Echo" },
    { TCPOPT_ECHOREPLY, "Echo Reply" },
    { TCPOPT_TIMESTAMP, "Time Stamp Option" },
    { 9, "Partial Order Connection Permitted" },
    { 10, "Partial Order Service Profile" },
    { TCPOPT_CC, "CC" },
    { TCPOPT_CCNEW, "CC.NEW" },
    { TCPOPT_CCECHO, "CC.ECHO" },
    { 14, "TCP Alternate Checksum Request" },
    { 15, "TCP Alternate Checksum Data" },
    { 16, "Skeeter" },
    { 17, "Bubba" },
    { 18, "Trailer Checksum Option" },
    { TCPOPT_MD5, "MD5 Signature Option" },
    { TCPOPT_SCPS, "SCPS Capabilities" },
    { TCPOPT_SNACK, "Selective Negative Acknowledgements" },
    { TCPOPT_RECBOUND, "Record Boundaries" },
    { TCPOPT_CORREXP, "Corruption experienced" },
    { 24, "SNAP" },
    { 25, "Unassigned" },
    { 26, "TCP Compression Filter" },
    { TCPOPT_QS, "Quick-Start Response" },
    { TCPOPT_USER_TO, "User Timeout Option" },
    { TCPOPT_AO, "The TCP Authentication Option" },
    { TCPOPT_MPTCP, "Multipath TCP" },
    { TCPOPT_TFO, "TCP Fast Open Cookie" },
    { TCPOPT_RVBD_PROBE, "Riverbed Probe" },
    { TCPOPT_RVBD_TRPY, "Riverbed Transparency" },
    { TCPOPT_EXP_FD, "RFC3692-style Experiment 1" },
    { TCPOPT_EXP_FE, "RFC3692-style Experiment 2" },
    { 0, NULL }
};
static value_string_ext tcp_option_kind_vs_ext = VALUE_STRING_EXT_INIT(tcp_option_kind_vs);

/* not all of the hf_fields below make sense for TCP but we have to provide
   them anyways to comply with the API (which was aimed for IP fragment
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
    { TCPOPT_MPTCP_MP_FASTCLOSE, "Fast Close" },
    { TCPOPT_MPTCP_MP_TCPRST, "TCP Reset" },
    { 0, NULL }
};

static dissector_table_t subdissector_table;
static dissector_table_t tcp_option_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;
static dissector_handle_t tcp_handle;
static dissector_handle_t sport_handle;
static dissector_handle_t tcp_opt_unknown_handle;
static guint32 tcp_stream_count;
static guint32 mptcp_stream_count;



/*
 * Maps an MPTCP token to a mptcp_analysis structure
 * Collisions are not handled
 */
static wmem_tree_t *mptcp_tokens = NULL;

static int * const tcp_option_mptcp_capable_v0_flags[] = {
  &hf_tcp_option_mptcp_checksum_flag,
  &hf_tcp_option_mptcp_B_flag,
  &hf_tcp_option_mptcp_H_v0_flag,
  &hf_tcp_option_mptcp_reserved_v0_flag,
  NULL
};

static int * const tcp_option_mptcp_capable_v1_flags[] = {
  &hf_tcp_option_mptcp_checksum_flag,
  &hf_tcp_option_mptcp_B_flag,
  &hf_tcp_option_mptcp_C_flag,
  &hf_tcp_option_mptcp_H_v1_flag,
  &hf_tcp_option_mptcp_reserved_v1_flag,
  NULL
};

static int * const tcp_option_mptcp_join_flags[] = {
  &hf_tcp_option_mptcp_backup_flag,
  NULL
};

static int * const tcp_option_mptcp_dss_flags[] = {
  &hf_tcp_option_mptcp_F_flag,
  &hf_tcp_option_mptcp_m_flag,
  &hf_tcp_option_mptcp_M_flag,
  &hf_tcp_option_mptcp_a_flag,
  &hf_tcp_option_mptcp_A_flag,
  NULL
};

static int * const tcp_option_mptcp_tcprst_flags[] = {
  &hf_tcp_option_mptcp_U_flag,
  &hf_tcp_option_mptcp_V_flag,
  &hf_tcp_option_mptcp_W_flag,
  &hf_tcp_option_mptcp_T_flag,
  NULL
};

static const unit_name_string units_64bit_version = { " (64bits version)", NULL };


static char *
tcp_flags_to_str(wmem_allocator_t *scope, const struct tcpheader *tcph)
{
    static const char flags[][4] = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR", "NS" };
    const int maxlength = 64; /* upper bounds, max 53B: 8 * 3 + 2 + strlen("Reserved") + 9 * 2 + 1 */

    char *pbuf;
    char *buf;

    int i;

    buf = pbuf = (char *) wmem_alloc(scope, maxlength);
    *pbuf = '\0';

    for (i = 0; i < 9; i++) {
        if (tcph->th_flags & (1 << i)) {
            if (buf[0])
                pbuf = g_stpcpy(pbuf, ", ");
            pbuf = g_stpcpy(pbuf, flags[i]);
        }
    }

    if (tcph->th_flags & TH_RES) {
        if (buf[0])
            pbuf = g_stpcpy(pbuf, ", ");
        g_stpcpy(pbuf, "Reserved");
    }

    if (buf[0] == '\0')
        g_stpcpy(pbuf, "<None>");

    return buf;
}
static char *
tcp_flags_to_str_first_letter(wmem_allocator_t *scope, const struct tcpheader *tcph)
{
    wmem_strbuf_t *buf = wmem_strbuf_new(scope, "");
    unsigned i;
    const unsigned flags_count = 12;
    const char first_letters[] = "RRRNCEUAPRSF";

    /* upper three bytes are marked as reserved ('R'). */
    for (i = 0; i < flags_count; i++) {
        if (((tcph->th_flags >> (flags_count - 1 - i)) & 1)) {
            wmem_strbuf_append_c(buf, first_letters[i]);
        } else {
            wmem_strbuf_append(buf, UTF8_MIDDLE_DOT);
        }
    }

    return wmem_strbuf_finalize(buf);
}

static void
tcp_src_prompt(packet_info *pinfo, gchar *result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_tcp_srcport, pinfo->curr_layer_num));

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", port, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
tcp_src_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_tcp_srcport, pinfo->curr_layer_num);
}

static void
tcp_dst_prompt(packet_info *pinfo, gchar *result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_tcp_dstport, pinfo->curr_layer_num));

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, port);
}

static gpointer
tcp_dst_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_tcp_dstport, pinfo->curr_layer_num);
}

static void
tcp_both_prompt(packet_info *pinfo, gchar *result)
{
    guint32 srcport = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_tcp_srcport, pinfo->curr_layer_num)),
            destport = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_tcp_dstport, pinfo->curr_layer_num));
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "both (%u%s%u)", srcport, UTF8_LEFT_RIGHT_ARROW, destport);
}

static const char* tcp_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{

    if (filter == CONV_FT_SRC_PORT)
        return "tcp.srcport";

    if (filter == CONV_FT_DST_PORT)
        return "tcp.dstport";

    if (filter == CONV_FT_ANY_PORT)
        return "tcp.port";

    if(!conv) {
        return CONV_FILTER_INVALID;
    }

    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_IPv4)
            return "ip.src";
        if (conv->src_address.type == AT_IPv6)
            return "ipv6.src";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_IPv4)
            return "ip.dst";
        if (conv->dst_address.type == AT_IPv6)
            return "ipv6.dst";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_IPv4)
            return "ip.addr";
        if (conv->src_address.type == AT_IPv6)
            return "ipv6.addr";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t tcp_ct_dissector_info = {&tcp_conv_get_filter_type};

static tap_packet_status
tcpip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const struct tcpheader *tcphdr=(const struct tcpheader *)vip;

    add_conversation_table_data_with_conv_id(hash, &tcphdr->ip_src, &tcphdr->ip_dst, tcphdr->th_sport, tcphdr->th_dport, (conv_id_t) tcphdr->th_stream, 1, pinfo->fd->pkt_len,
                                              &pinfo->rel_ts, &pinfo->abs_ts, &tcp_ct_dissector_info, ENDPOINT_TCP);

    return TAP_PACKET_REDRAW;
}

static tap_packet_status
mptcpip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const struct tcp_analysis *tcpd=(const struct tcp_analysis *)vip;
    const mptcp_meta_flow_t *meta=(const mptcp_meta_flow_t *)tcpd->fwd->mptcp_subflow->meta;

    add_conversation_table_data_with_conv_id(hash, &meta->ip_src, &meta->ip_dst,
        meta->sport, meta->dport, (conv_id_t) tcpd->mptcp_analysis->stream, 1, pinfo->fd->pkt_len,
                                              &pinfo->rel_ts, &pinfo->abs_ts, &tcp_ct_dissector_info, ENDPOINT_TCP);

    return TAP_PACKET_REDRAW;
}

static const char* tcp_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_PORT)
        return "tcp.srcport";

    if (filter == CONV_FT_DST_PORT)
        return "tcp.dstport";

    if (filter == CONV_FT_ANY_PORT)
        return "tcp.port";

    if(!host) {
        return CONV_FILTER_INVALID;
    }

    if (filter == CONV_FT_SRC_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.src";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.src";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.dst";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.dst";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.addr";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.addr";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t tcp_host_dissector_info = {&tcp_host_get_filter_type};

static tap_packet_status
tcpip_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    const struct tcpheader *tcphdr=(const struct tcpheader *)vip;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
    packets are counted properly (even if address is sending to itself)
    XXX - this could probably be done more efficiently inside hostlist_table */
    add_hostlist_table_data(hash, &tcphdr->ip_src, tcphdr->th_sport, TRUE, 1, pinfo->fd->pkt_len, &tcp_host_dissector_info, ENDPOINT_TCP);
    add_hostlist_table_data(hash, &tcphdr->ip_dst, tcphdr->th_dport, FALSE, 1, pinfo->fd->pkt_len, &tcp_host_dissector_info, ENDPOINT_TCP);

    return TAP_PACKET_REDRAW;
}

static gboolean
tcp_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "tcp");
}

static gchar*
tcp_build_filter(packet_info *pinfo)
{
    if( pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4 ) {
        /* TCP over IPv4 */
        return ws_strdup_printf("(ip.addr eq %s and ip.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
            address_to_str(pinfo->pool, &pinfo->net_src),
            address_to_str(pinfo->pool, &pinfo->net_dst),
            pinfo->srcport, pinfo->destport );
    }

    if( pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6 ) {
        /* TCP over IPv6 */
        return ws_strdup_printf("(ipv6.addr eq %s and ipv6.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
            address_to_str(pinfo->pool, &pinfo->net_src),
            address_to_str(pinfo->pool, &pinfo->net_dst),
            pinfo->srcport, pinfo->destport );
    }

    return NULL;
}

/****************************************************************************/
/* whenever a TCP packet is seen by the tap listener */
/* Add a new tcp frame into the graph */
static tap_packet_status
tcp_seq_analysis_packet( void *ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *tcp_info, tap_flags_t tapflags _U_)
{
    seq_analysis_info_t *sainfo = (seq_analysis_info_t *) ptr;
    const struct tcpheader *tcph = (const struct tcpheader *)tcp_info;
    char* flags;
    seq_analysis_item_t *sai = sequence_analysis_create_sai_with_addresses(pinfo, sainfo);

    if (!sai)
        return TAP_PACKET_DONT_REDRAW;

    sai->frame_number = pinfo->num;

    sai->port_src=pinfo->srcport;
    sai->port_dst=pinfo->destport;

    flags = tcp_flags_to_str(NULL, tcph);

    if ((tcph->th_have_seglen)&&(tcph->th_seglen!=0)){
        sai->frame_label = ws_strdup_printf("%s - Len: %u",flags, tcph->th_seglen);
    }
    else{
        sai->frame_label = g_strdup(flags);
    }

    wmem_free(NULL, flags);

    if (tcph->th_flags & TH_ACK)
        sai->comment = ws_strdup_printf("Seq = %u Ack = %u",tcph->th_seq, tcph->th_ack);
    else
        sai->comment = ws_strdup_printf("Seq = %u",tcph->th_seq);

    sai->line_style = 1;
    sai->conv_num = (guint16) tcph->th_stream;
    sai->display = TRUE;

    g_queue_push_tail(sainfo->items, sai);

    return TAP_PACKET_REDRAW;
}


gchar *tcp_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo, guint *stream, guint *sub_stream _U_)
{
    conversation_t *conv;
    struct tcp_analysis *tcpd;

    if (((pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) ||
        (pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6))
        && (conv=find_conversation_pinfo(pinfo, 0)) != NULL )
    {
        /* TCP over IPv4/6 */
        tcpd=get_tcp_conversation_data(conv, pinfo);
        if (tcpd == NULL)
            return NULL;

        *stream = tcpd->stream;
        return ws_strdup_printf("tcp.stream eq %u", tcpd->stream);
    }

    return NULL;
}

gchar *tcp_follow_index_filter(guint stream, guint sub_stream _U_)
{
    return ws_strdup_printf("tcp.stream eq %u", stream);
}

gchar *tcp_follow_address_filter(address *src_addr, address *dst_addr, int src_port, int dst_port)
{
    const gchar  *ip_version = src_addr->type == AT_IPv6 ? "v6" : "";
    gchar         src_addr_str[WS_INET6_ADDRSTRLEN];
    gchar         dst_addr_str[WS_INET6_ADDRSTRLEN];

    address_to_str_buf(src_addr, src_addr_str, sizeof(src_addr_str));
    address_to_str_buf(dst_addr, dst_addr_str, sizeof(dst_addr_str));

    return ws_strdup_printf("((ip%s.src eq %s and tcp.srcport eq %d) and "
                     "(ip%s.dst eq %s and tcp.dstport eq %d))"
                     " or "
                     "((ip%s.src eq %s and tcp.srcport eq %d) and "
                     "(ip%s.dst eq %s and tcp.dstport eq %d))",
                     ip_version, src_addr_str, src_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, src_addr_str, src_port);

}

typedef struct tcp_follow_tap_data
{
    tvbuff_t *tvb;
    struct tcpheader* tcph;
    struct tcp_analysis *tcpd;

} tcp_follow_tap_data_t;

/*
 * Tries to apply segments from fragments list to the reconstructed payload.
 * Fragments that can be appended to the end of the payload will be applied (and
 * removed from the list). Fragments that should have been received (according
 * to the ack number) will also be appended to the payload (preceded by some
 * dummy data to mark packet loss if any).
 *
 * Returns TRUE if one fragment has been applied or FALSE if no more fragments
 * can be added to the payload (there might still be unacked fragments with
 * missing segments before them).
 */
static gboolean
check_follow_fragments(follow_info_t *follow_info, gboolean is_server, guint32 acknowledged, guint32 packet_num, gboolean use_ack)
{
    GList *fragment_entry;
    follow_record_t *fragment, *follow_record;
    guint32 lowest_seq = 0;
    gchar *dummy_str;

    fragment_entry = g_list_first(follow_info->fragments[is_server]);
    if (fragment_entry == NULL)
        return FALSE;

    fragment = (follow_record_t*)fragment_entry->data;
    lowest_seq = fragment->seq;

    for (; fragment_entry != NULL; fragment_entry = g_list_next(fragment_entry))
    {
        fragment = (follow_record_t*)fragment_entry->data;

        if( GT_SEQ(lowest_seq, fragment->seq) ) {
            lowest_seq = fragment->seq;
        }

        if( LT_SEQ(fragment->seq, follow_info->seq[is_server]) ) {
            guint32 newseq;
            /* this sequence number seems dated, but
               check the end to make sure it has no more
               info than we have already seen */
            newseq = fragment->seq + fragment->data->len;
            if( GT_SEQ(newseq, follow_info->seq[is_server]) ) {
                guint32 new_pos;

                /* this one has more than we have seen. let's get the
                   payload that we have not seen. This happens when
                   part of this frame has been retransmitted */

                new_pos = follow_info->seq[is_server] - fragment->seq;

                if ( fragment->data->len > new_pos ) {
                    guint32 new_frag_size = fragment->data->len - new_pos;

                    follow_record = g_new0(follow_record_t,1);

                    follow_record->is_server = is_server;
                    follow_record->packet_num = fragment->packet_num;
                    follow_record->abs_ts = fragment->abs_ts;
                    follow_record->seq = follow_info->seq[is_server] + new_frag_size;

                    follow_record->data = g_byte_array_append(g_byte_array_new(),
                                                              fragment->data->data + new_pos,
                                                              new_frag_size);

                    follow_info->payload = g_list_prepend(follow_info->payload, follow_record);
                }

                follow_info->seq[is_server] += (fragment->data->len - new_pos);
            }

            /* Remove the fragment from the list as the "new" part of it
             * has been processed or its data has been seen already in
             * another packet. */
            g_byte_array_free(fragment->data, TRUE);
            g_free(fragment);
            follow_info->fragments[is_server] = g_list_delete_link(follow_info->fragments[is_server], fragment_entry);
            return TRUE;
        }

        if( EQ_SEQ(fragment->seq, follow_info->seq[is_server]) ) {
            /* this fragment fits the stream */
            if( fragment->data->len > 0 ) {
                follow_info->payload = g_list_prepend(follow_info->payload, fragment);
            }

            follow_info->seq[is_server] += fragment->data->len;
            follow_info->fragments[is_server] = g_list_delete_link(follow_info->fragments[is_server], fragment_entry);
            return TRUE;
        }
    }

    if( use_ack && GT_SEQ(acknowledged, lowest_seq) ) {
        /* There are frames missing in the capture file that were seen
         * by the receiving host. Add dummy stream chunk with the data
         * "[xxx bytes missing in capture file]".
         */
        dummy_str = ws_strdup_printf("[%d bytes missing in capture file]",
                        (int)(lowest_seq - follow_info->seq[is_server]) );
        // XXX the dummy replacement could be larger than the actual missing bytes.

        follow_record = g_new0(follow_record_t,1);

        follow_record->data = g_byte_array_append(g_byte_array_new(),
                                                  (guchar*)dummy_str,
                                                  (guint)strlen(dummy_str)+1);
        g_free(dummy_str);
        follow_record->is_server = is_server;
        follow_record->packet_num = packet_num;
        follow_record->seq = lowest_seq;

        follow_info->seq[is_server] = lowest_seq;
        follow_info->payload = g_list_prepend(follow_info->payload, follow_record);
        return TRUE;
    }

    return FALSE;
}

static tap_packet_status
follow_tcp_tap_listener(void *tapdata, packet_info *pinfo,
                      epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    follow_record_t *follow_record;
    follow_info_t *follow_info = (follow_info_t *)tapdata;
    const tcp_follow_tap_data_t *follow_data = (const tcp_follow_tap_data_t *)data;
    gboolean is_server;
    guint32 sequence = follow_data->tcph->th_seq;
    guint32 length = follow_data->tcph->th_seglen;
    guint32 data_offset = 0;
    guint32 data_length = tvb_captured_length(follow_data->tvb);

    if (follow_data->tcph->th_flags & TH_SYN) {
        sequence++;
    }

    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        copy_address(&follow_info->client_ip, &pinfo->src);
        follow_info->server_port = pinfo->destport;
        copy_address(&follow_info->server_ip, &pinfo->dst);
    }

    is_server = !(addresses_equal(&follow_info->client_ip, &pinfo->src) && follow_info->client_port == pinfo->srcport);

   /* Check whether this frame ACKs fragments in flow from the other direction.
    * This happens when frames are not in the capture file, but were actually
    * seen by the receiving host (Fixes bug 592).
    */
    if (follow_info->fragments[!is_server] != NULL) {
        while (check_follow_fragments(follow_info, !is_server, follow_data->tcph->th_ack, pinfo->fd->num, TRUE));
    }

    /*
     * If this is the first segment of this stream, initialize the next expected
     * sequence number. If there is any data, it will be added below.
     */
    if (follow_info->bytes_written[is_server] == 0 && follow_info->seq[is_server] == 0) {
        follow_info->seq[is_server] = sequence;
    }

    /* We have already seen this src (and received some segments), let's figure
     * out whether this segment extends the stream or overlaps a previous gap. */
    if (LT_SEQ(sequence, follow_info->seq[is_server])) {
        /* This sequence number seems dated, but check the end in case it was a
         * retransmission with more data. */
        guint32 nextseq = sequence + length;
        if (GT_SEQ(nextseq, follow_info->seq[is_server])) {
            /* The begin of the segment was already seen, try to add the
             * remaining data that we have not seen to the payload. */
            data_offset = follow_info->seq[is_server] - sequence;
            if (data_length <= data_offset) {
                data_length = 0;
            } else {
                data_length -= data_offset;
            }

            sequence = follow_info->seq[is_server];
            length = nextseq - follow_info->seq[is_server];
        }
    }
    /*
     * Ignore segments that have no new data (either because it was empty, or
     * because it was fully overlapping with previously received data).
     */
    if (data_length == 0 || LT_SEQ(sequence, follow_info->seq[is_server])) {
        return TAP_PACKET_DONT_REDRAW;
    }

    follow_record = g_new0(follow_record_t, 1);
    follow_record->is_server = is_server;
    follow_record->packet_num = pinfo->fd->num;
    follow_record->abs_ts = pinfo->fd->abs_ts;
    follow_record->seq = sequence;  /* start of fragment, used by check_follow_fragments. */
    follow_record->data = g_byte_array_append(g_byte_array_new(),
                                              tvb_get_ptr(follow_data->tvb, data_offset, data_length),
                                              data_length);

    if (EQ_SEQ(sequence, follow_info->seq[is_server])) {
        /* The segment overlaps or extends the previous end of stream. */
        follow_info->seq[is_server] += length;
        follow_info->bytes_written[is_server] += follow_record->data->len;
        follow_info->payload = g_list_prepend(follow_info->payload, follow_record);

        /* done with the packet, see if it caused a fragment to fit */
        while(check_follow_fragments(follow_info, is_server, 0, pinfo->fd->num, FALSE));
    } else {
        /* Out of order packet (more preceding segments are expected). */
        follow_info->fragments[is_server] = g_list_append(follow_info->fragments[is_server], follow_record);
    }
    return TAP_PACKET_DONT_REDRAW;
}

#define EXP_PDU_TCP_INFO_DATA_LEN   19
#define EXP_PDU_TCP_INFO_VERSION    1

static int exp_pdu_tcp_dissector_data_size(packet_info *pinfo _U_, void* data _U_)
{
    return EXP_PDU_TCP_INFO_DATA_LEN+4;
}

static int exp_pdu_tcp_dissector_data_populate_data(packet_info *pinfo _U_, void* data, guint8 *tlv_buffer, guint32 buffer_size _U_)
{
    struct tcpinfo* dissector_data = (struct tcpinfo*)data;

    phton16(&tlv_buffer[0], EXP_PDU_TAG_TCP_INFO_DATA);
    phton16(&tlv_buffer[2], EXP_PDU_TCP_INFO_DATA_LEN); /* tag length */
    phton16(&tlv_buffer[4], EXP_PDU_TCP_INFO_VERSION);
    phton32(&tlv_buffer[6], dissector_data->seq);
    phton32(&tlv_buffer[10], dissector_data->nxtseq);
    phton32(&tlv_buffer[14], dissector_data->lastackseq);
    tlv_buffer[18] = dissector_data->is_reassembled;
    phton16(&tlv_buffer[19], dissector_data->flags);
    phton16(&tlv_buffer[21], dissector_data->urgent_pointer);

    return exp_pdu_tcp_dissector_data_size(pinfo, data);
}

static void
handle_export_pdu_dissection_table(packet_info *pinfo, tvbuff_t *tvb, guint32 port, struct tcpinfo *tcpinfo)
{
    if (have_tap_listener(exported_pdu_tap)) {
        exp_pdu_data_item_t exp_pdu_data_table_value = {exp_pdu_data_dissector_table_num_value_size, exp_pdu_data_dissector_table_num_value_populate_data, NULL};
        exp_pdu_data_item_t exp_pdu_data_dissector_data = {exp_pdu_tcp_dissector_data_size, exp_pdu_tcp_dissector_data_populate_data, NULL};
        const exp_pdu_data_item_t *tcp_exp_pdu_items[] = {
            &exp_pdu_data_src_ip,
            &exp_pdu_data_dst_ip,
            &exp_pdu_data_port_type,
            &exp_pdu_data_src_port,
            &exp_pdu_data_dst_port,
            &exp_pdu_data_orig_frame_num,
            &exp_pdu_data_table_value,
            &exp_pdu_data_dissector_data,
            NULL
        };

        exp_pdu_data_t *exp_pdu_data;

        exp_pdu_data_table_value.data = GUINT_TO_POINTER(port);
        exp_pdu_data_dissector_data.data = tcpinfo;

        exp_pdu_data = export_pdu_create_tags(pinfo, "tcp.port", EXP_PDU_TAG_DISSECTOR_TABLE_NAME, tcp_exp_pdu_items);
        exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
        exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
        exp_pdu_data->pdu_tvb = tvb;

        tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
    }
}

static void
handle_export_pdu_heuristic(packet_info *pinfo, tvbuff_t *tvb, heur_dtbl_entry_t *hdtbl_entry, struct tcpinfo *tcpinfo)
{
    exp_pdu_data_t *exp_pdu_data = NULL;

    if (have_tap_listener(exported_pdu_tap)) {
        if ((!hdtbl_entry->enabled) ||
            (hdtbl_entry->protocol != NULL && !proto_is_protocol_enabled(hdtbl_entry->protocol))) {
            exp_pdu_data = export_pdu_create_common_tags(pinfo, "data", EXP_PDU_TAG_PROTO_NAME);
        } else if (hdtbl_entry->protocol != NULL) {
            exp_pdu_data_item_t exp_pdu_data_dissector_data = {exp_pdu_tcp_dissector_data_size, exp_pdu_tcp_dissector_data_populate_data, NULL};
            const exp_pdu_data_item_t *tcp_exp_pdu_items[] = {
                &exp_pdu_data_src_ip,
                &exp_pdu_data_dst_ip,
                &exp_pdu_data_port_type,
                &exp_pdu_data_src_port,
                &exp_pdu_data_dst_port,
                &exp_pdu_data_orig_frame_num,
                &exp_pdu_data_dissector_data,
                NULL
            };

            exp_pdu_data_dissector_data.data = tcpinfo;

            exp_pdu_data = export_pdu_create_tags(pinfo, hdtbl_entry->short_name, EXP_PDU_TAG_HEUR_PROTO_NAME, tcp_exp_pdu_items);
        }

        if (exp_pdu_data != NULL) {
            exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
            exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
            exp_pdu_data->pdu_tvb = tvb;

            tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
        }
    }
}

static void
handle_export_pdu_conversation(packet_info *pinfo, tvbuff_t *tvb, int src_port, int dst_port, struct tcpinfo *tcpinfo)
{
    if (have_tap_listener(exported_pdu_tap)) {
        conversation_t *conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_TCP, src_port, dst_port, 0);
        if (conversation != NULL)
        {
            dissector_handle_t handle = (dissector_handle_t)wmem_tree_lookup32_le(conversation->dissector_tree, pinfo->num);
            if (handle != NULL)
            {
                exp_pdu_data_item_t exp_pdu_data_dissector_data = {exp_pdu_tcp_dissector_data_size, exp_pdu_tcp_dissector_data_populate_data, NULL};
                const exp_pdu_data_item_t *tcp_exp_pdu_items[] = {
                    &exp_pdu_data_src_ip,
                    &exp_pdu_data_dst_ip,
                    &exp_pdu_data_port_type,
                    &exp_pdu_data_src_port,
                    &exp_pdu_data_dst_port,
                    &exp_pdu_data_orig_frame_num,
                    &exp_pdu_data_dissector_data,
                    NULL
                };

                exp_pdu_data_t *exp_pdu_data;

                exp_pdu_data_dissector_data.data = tcpinfo;

                exp_pdu_data = export_pdu_create_tags(pinfo, dissector_handle_get_dissector_name(handle), EXP_PDU_TAG_PROTO_NAME, tcp_exp_pdu_items);
                exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
                exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
                exp_pdu_data->pdu_tvb = tvb;

                tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
            }
        }
    }
}

/*
 * display the TCP Conversation Completeness
 * we of course pay much attention on complete conversations but also incomplete ones which
 * have a regular start, as in practice we are often looking for such thing
 */
static void conversation_completeness_fill(gchar *buf, guint32 value)
{
    switch(value) {
        case TCP_COMPLETENESS_SYNSENT:
            snprintf(buf, ITEM_LABEL_LENGTH, "Incomplete, SYN_SENT (%u)", value);
            break;
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK):
            snprintf(buf, ITEM_LABEL_LENGTH, "Incomplete, CLIENT_ESTABLISHED (%u)", value);
            break;
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK):
            snprintf(buf, ITEM_LABEL_LENGTH, "Incomplete, ESTABLISHED (%u)", value);
            break;
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_DATA):
            snprintf(buf, ITEM_LABEL_LENGTH, "Incomplete, DATA (%u)", value);
            break;
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_DATA|
              TCP_COMPLETENESS_FIN):
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_DATA|
              TCP_COMPLETENESS_RST):
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_DATA|
              TCP_COMPLETENESS_FIN|
              TCP_COMPLETENESS_RST):
            snprintf(buf, ITEM_LABEL_LENGTH, "Complete, WITH_DATA (%u)", value);
            break;
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_FIN):
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_RST):
        case (TCP_COMPLETENESS_SYNSENT|
              TCP_COMPLETENESS_SYNACK|
              TCP_COMPLETENESS_ACK|
              TCP_COMPLETENESS_FIN|
              TCP_COMPLETENESS_RST):
            snprintf(buf, ITEM_LABEL_LENGTH, "Complete, NO_DATA (%u)", value);
            break;
        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "Incomplete (%u)", value);
            break;
    }
}

/* TCP structs and definitions */

/* **************************************************************************
 * RTT, relative sequence numbers, window scaling & etc.
 * **************************************************************************/
static gboolean tcp_analyze_seq           = TRUE;
static gboolean tcp_relative_seq          = TRUE;
static gboolean tcp_track_bytes_in_flight = TRUE;
static gboolean tcp_bif_seq_based         = FALSE;
static gboolean tcp_calculate_ts          = TRUE;

static gboolean tcp_analyze_mptcp                   = TRUE;
static gboolean mptcp_relative_seq                  = TRUE;
static gboolean mptcp_analyze_mappings              = FALSE;
static gboolean mptcp_intersubflows_retransmission  = FALSE;


#define TCP_A_RETRANSMISSION          0x0001
#define TCP_A_LOST_PACKET             0x0002
#define TCP_A_ACK_LOST_PACKET         0x0004
#define TCP_A_KEEP_ALIVE              0x0008
#define TCP_A_DUPLICATE_ACK           0x0010
#define TCP_A_ZERO_WINDOW             0x0020
#define TCP_A_ZERO_WINDOW_PROBE       0x0040
#define TCP_A_ZERO_WINDOW_PROBE_ACK   0x0080
#define TCP_A_KEEP_ALIVE_ACK          0x0100
#define TCP_A_OUT_OF_ORDER            0x0200
#define TCP_A_FAST_RETRANSMISSION     0x0400
#define TCP_A_WINDOW_UPDATE           0x0800
#define TCP_A_WINDOW_FULL             0x1000
#define TCP_A_REUSED_PORTS            0x2000
#define TCP_A_SPURIOUS_RETRANSMISSION 0x4000

/* Static TCP flags. Set in tcp_flow_t:static_flags */
#define TCP_S_BASE_SEQ_SET 0x01
#define TCP_S_SAW_SYN      0x03
#define TCP_S_SAW_SYNACK   0x05


/* Describe the fields sniffed and set in mptcp_meta_flow_t:static_flags */
#define MPTCP_META_HAS_BASE_DSN_MSB  0x01
#define MPTCP_META_HAS_KEY  0x03
#define MPTCP_META_HAS_TOKEN  0x04
#define MPTCP_META_HAS_ADDRESSES  0x08

/* Describe the fields sniffed and set in mptcp_meta_flow_t:static_flags */
#define MPTCP_SUBFLOW_HAS_NONCE 0x01
#define MPTCP_SUBFLOW_HAS_ADDRESS_ID 0x02

/* MPTCP meta analysis related */
#define MPTCP_META_CHECKSUM_REQUIRED   0x0002

/* if we have no key for this connection, some conversion become impossible,
 * thus return false
 */
static
gboolean
mptcp_convert_dsn(guint64 dsn, mptcp_meta_flow_t *meta, enum mptcp_dsn_conversion conv, gboolean relative, guint64 *result ) {

    *result = dsn;

    /* if relative is set then we need the 64 bits version anyway
     * we assume no wrapping was done on the 32 lsb so this may be wrong for elphant flows
     */
    if(conv == DSN_CONV_32_TO_64 || relative) {

        if(!(meta->static_flags & MPTCP_META_HAS_BASE_DSN_MSB)) {
            /* can't do those without the expected_idsn based on the key */
            return FALSE;
        }
    }

    if(conv == DSN_CONV_32_TO_64) {
        *result = KEEP_32MSB_OF_GUINT64(meta->base_dsn) | dsn;
    }

    if(relative) {
        *result -= meta->base_dsn;
    }

    if(conv == DSN_CONV_64_TO_32) {
        *result = (guint32) *result;
    }

    return TRUE;
}


static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
    guint32 seq, guint32 nxtseq, gboolean is_tcp_segment,
    struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo);


static struct tcp_analysis *
init_tcp_conversation_data(packet_info *pinfo, int direction)
{
    struct tcp_analysis *tcpd;

    /* Initialize the tcp protocol data structure to add to the tcp conversation */
    tcpd=wmem_new0(wmem_file_scope(), struct tcp_analysis);
    tcpd->flow1.win_scale = (direction >= 0) ? pinfo->src_win_scale : pinfo->dst_win_scale;
    tcpd->flow1.window = G_MAXUINT32;
    tcpd->flow1.multisegment_pdus=wmem_tree_new(wmem_file_scope());

    tcpd->flow2.window = G_MAXUINT32;
    tcpd->flow2.win_scale = (direction >= 0) ? pinfo->dst_win_scale : pinfo->src_win_scale;
    tcpd->flow2.multisegment_pdus=wmem_tree_new(wmem_file_scope());

    if (tcp_reassemble_out_of_order) {
        tcpd->flow1.ooo_segments=wmem_list_new(wmem_file_scope());
        tcpd->flow2.ooo_segments=wmem_list_new(wmem_file_scope());
    }

    /* Only allocate the data if its actually going to be analyzed */
    if (tcp_analyze_seq)
    {
        tcpd->flow1.tcp_analyze_seq_info = wmem_new0(wmem_file_scope(), struct tcp_analyze_seq_flow_info_t);
        tcpd->flow2.tcp_analyze_seq_info = wmem_new0(wmem_file_scope(), struct tcp_analyze_seq_flow_info_t);
    }
    /* Only allocate the data if its actually going to be displayed */
    if (tcp_display_process_info)
    {
        tcpd->flow1.process_info = wmem_new0(wmem_file_scope(), struct tcp_process_info_t);
        tcpd->flow2.process_info = wmem_new0(wmem_file_scope(), struct tcp_process_info_t);
    }

    tcpd->acked_table=wmem_tree_new(wmem_file_scope());
    tcpd->ts_first.secs=pinfo->abs_ts.secs;
    tcpd->ts_first.nsecs=pinfo->abs_ts.nsecs;
    nstime_set_zero(&tcpd->ts_mru_syn);
    nstime_set_zero(&tcpd->ts_first_rtt);
    tcpd->ts_prev.secs=pinfo->abs_ts.secs;
    tcpd->ts_prev.nsecs=pinfo->abs_ts.nsecs;
    tcpd->flow1.valid_bif = 1;
    tcpd->flow2.valid_bif = 1;
    tcpd->flow1.push_bytes_sent = 0;
    tcpd->flow2.push_bytes_sent = 0;
    tcpd->flow1.push_set_last = FALSE;
    tcpd->flow2.push_set_last = FALSE;
    tcpd->flow1.closing_initiator = FALSE;
    tcpd->flow2.closing_initiator = FALSE;
    tcpd->stream = tcp_stream_count++;
    tcpd->server_port = 0;

    return tcpd;
}

/* setup meta as well */
static void
mptcp_init_subflow(tcp_flow_t *flow)
{
    struct mptcp_subflow *sf = wmem_new0(wmem_file_scope(), struct mptcp_subflow);

    DISSECTOR_ASSERT(flow->mptcp_subflow == 0);
    flow->mptcp_subflow = sf;
    sf->ssn2dsn_mappings        = wmem_itree_new(wmem_file_scope());
    sf->dsn2packet_map         = wmem_itree_new(wmem_file_scope());
}


/* add a new subflow to an mptcp connection */
static void
mptcp_attach_subflow(struct mptcp_analysis* mptcpd, struct tcp_analysis* tcpd) {

    if(!wmem_list_find(mptcpd->subflows, tcpd)) {
        wmem_list_prepend(mptcpd->subflows, tcpd);
    }

    /* in case we merge 2 mptcp connections */
    tcpd->mptcp_analysis = mptcpd;
}


struct tcp_analysis *
get_tcp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    int direction;
    struct tcp_analysis *tcpd;
    gboolean clear_ta = TRUE;

    /* Did the caller supply the conversation pointer? */
    if( conv==NULL ) {
        /* If the caller didn't supply a conversation, don't
         * clear the analysis, it may be needed */
        clear_ta = FALSE;
        conv = find_or_create_conversation(pinfo);
    }

    /* Get the data for this conversation */
    tcpd=(struct tcp_analysis *)conversation_get_proto_data(conv, proto_tcp);

    direction = cmp_address(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if (direction == 0) {
        direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    /* If the conversation was just created or it matched a
     * conversation with template options, tcpd will not
     * have been initialized. So, initialize
     * a new tcpd structure for the conversation.
     */
    if (!tcpd) {
        tcpd = init_tcp_conversation_data(pinfo, direction);
        conversation_add_proto_data(conv, proto_tcp, tcpd);
    }

    if (!tcpd) {
      return NULL;
    }

    /* check direction and get ua lists */
    if(direction>=0) {
        tcpd->fwd=&(tcpd->flow1);
        tcpd->rev=&(tcpd->flow2);
    } else {
        tcpd->fwd=&(tcpd->flow2);
        tcpd->rev=&(tcpd->flow1);
    }

    if (clear_ta) {
        tcpd->ta=NULL;
    }
    return tcpd;
}

/* Attach process info to a flow */
/* XXX - We depend on the TCP dissector finding the conversation first */
void
add_tcp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command) {
    conversation_t *conv;
    struct tcp_analysis *tcpd;
    tcp_flow_t *flow = NULL;

    if (!tcp_display_process_info)
        return;

    conv = find_conversation(frame_num, local_addr, remote_addr, ENDPOINT_TCP, local_port, remote_port, 0);
    if (!conv) {
        return;
    }

    tcpd = (struct tcp_analysis *)conversation_get_proto_data(conv, proto_tcp);
    if (!tcpd) {
        return;
    }

    if (cmp_address(local_addr, conversation_key_addr1(conv->key_ptr)) == 0 && local_port == conversation_key_port1(conv->key_ptr)) {
        flow = &tcpd->flow1;
    } else if (cmp_address(remote_addr, conversation_key_addr1(conv->key_ptr)) == 0 && remote_port == conversation_key_port1(conv->key_ptr)) {
        flow = &tcpd->flow2;
    }
    if (!flow || (flow->process_info && flow->process_info->command)) {
        return;
    }

    if (flow->process_info == NULL)
        flow->process_info = wmem_new0(wmem_file_scope(), struct tcp_process_info_t);

    flow->process_info->process_uid = uid;
    flow->process_info->process_pid = pid;
    flow->process_info->username = wmem_strdup(wmem_file_scope(), username);
    flow->process_info->command = wmem_strdup(wmem_file_scope(), command);
}

/* Return the current stream count */
guint32 get_tcp_stream_count(void)
{
    return tcp_stream_count;
}

/* Return the mptcp current stream count */
guint32 get_mptcp_stream_count(void)
{
    return mptcp_stream_count;
}

/* Calculate the timestamps relative to this conversation */
static void
tcp_calculate_timestamps(packet_info *pinfo, struct tcp_analysis *tcpd,
            struct tcp_per_packet_data_t *tcppd)
{
    if( !tcppd ) {
        tcppd = wmem_new(wmem_file_scope(), struct tcp_per_packet_data_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_tcp, pinfo->curr_layer_num, tcppd);
    }

    if (!tcpd)
        return;

    nstime_delta(&tcppd->ts_del, &pinfo->abs_ts, &tcpd->ts_prev);

    tcpd->ts_prev.secs=pinfo->abs_ts.secs;
    tcpd->ts_prev.nsecs=pinfo->abs_ts.nsecs;
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

    tree=proto_tree_add_subtree(parent_tree, tvb, 0, 0, ett_tcp_timestamps, &item, "Timestamps");
    proto_item_set_generated(item);

    nstime_delta(&ts, &pinfo->abs_ts, &tcpd->ts_first);
    item = proto_tree_add_time(tree, hf_tcp_ts_relative, tvb, 0, 0, &ts);
    proto_item_set_generated(item);

    if( !tcppd )
        tcppd = (struct tcp_per_packet_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tcp, pinfo->curr_layer_num);

    if( tcppd ) {
        item = proto_tree_add_time(tree, hf_tcp_ts_delta, tvb, 0, 0,
            &tcppd->ts_del);
        proto_item_set_generated(item);
    }
}

static void
print_pdu_tracking_data(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tcp_tree, struct tcp_multisegment_pdu *msp)
{
    proto_item *item;

    col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Continuation to #%u] ", msp->first_frame);
    item=proto_tree_add_uint(tcp_tree, hf_tcp_continuation_to,
        tvb, 0, 0, msp->first_frame);
    proto_item_set_generated(item);
}

/* if we know that a PDU starts inside this segment, return the adjusted
   offset to where that PDU starts or just return offset back
   and let TCP try to find out what it can about this segment
*/
static int
scan_for_next_pdu(tvbuff_t *tvb, proto_tree *tcp_tree, packet_info *pinfo, int offset, guint32 seq, guint32 nxtseq, wmem_tree_t *multisegment_pdus)
{
    struct tcp_multisegment_pdu *msp=NULL;

    if(!pinfo->fd->visited) {
        msp=(struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(multisegment_pdus, seq-1);
        if(msp) {
            /* If this is a continuation of a PDU started in a
             * previous segment we need to update the last_frame
             * variables.
            */
            if(seq>msp->seq && seq<msp->nxtpdu) {
                msp->last_frame=pinfo->num;
                msp->last_frame_time=pinfo->abs_ts;
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
        msp=(struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(multisegment_pdus, nxtseq-1);
        if(msp) {
            if(pinfo->num==msp->first_frame) {
                proto_item *item;
                nstime_t ns;

                item=proto_tree_add_uint(tcp_tree, hf_tcp_pdu_last_frame, tvb, 0, 0, msp->last_frame);
                proto_item_set_generated(item);

                nstime_delta(&ns, &msp->last_frame_time, &pinfo->abs_ts);
                item = proto_tree_add_time(tcp_tree, hf_tcp_pdu_time,
                        tvb, 0, 0, &ns);
                proto_item_set_generated(item);
            }
        }

        /* Second we check if this segment is part of a PDU started
         * prior to the segment (seq-1)
         */
        msp=(struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(multisegment_pdus, seq-1);
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
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint32 seq, guint32 nxtpdu, wmem_tree_t *multisegment_pdus)
{
    struct tcp_multisegment_pdu *msp;

    msp=wmem_new(wmem_file_scope(), struct tcp_multisegment_pdu);
    msp->nxtpdu=nxtpdu;
    msp->seq=seq;
    msp->first_frame=pinfo->num;
    msp->first_frame_with_seq=pinfo->num;
    msp->last_frame=pinfo->num;
    msp->last_frame_time=pinfo->abs_ts;
    msp->flags=0;
    wmem_tree_insert32(multisegment_pdus, seq, (void *)msp);
    /*ws_warning("pdu_store_sequencenumber_of_next_pdu: seq %u", seq);*/
    return msp;
}

/* This is called for SYN and SYN+ACK packets and the purpose is to verify
 * that we have seen window scaling in both directions.
 * If we can't find window scaling being set in both directions
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

/* given a tcpd, returns the mptcp_subflow that sides with meta */
static struct mptcp_subflow *
mptcp_select_subflow_from_meta(const struct tcp_analysis *tcpd, const mptcp_meta_flow_t *meta)
{
    /* select the tcp_flow with appropriate direction */
    if( tcpd->flow1.mptcp_subflow->meta == meta) {
        return tcpd->flow1.mptcp_subflow;
    }
    else {
        return tcpd->flow2.mptcp_subflow;
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

    wmem_tree_key_t key[4];

    key[0].length = 1;
    key[0].key = &frame;

    key[1].length = 1;
    key[1].key = &seq;

    key[2].length = 1;
    key[2].key = &ack;

    key[3].length = 0;
    key[3].key = NULL;

    if (!tcpd) {
        return;
    }

    tcpd->ta = (struct tcp_acked *)wmem_tree_lookup32_array(tcpd->acked_table, key);
    if((!tcpd->ta) && createflag) {
        tcpd->ta = wmem_new0(wmem_file_scope(), struct tcp_acked);
        wmem_tree_insert32_array(tcpd->acked_table, key, (void *)tcpd->ta);
    }
}


/* fwd contains a list of all segments processed but not yet ACKed in the
 *     same direction as the current segment.
 * rev contains a list of all segments received but not yet ACKed in the
 *     opposite direction to the current segment.
 *
 * New segments are always added to the head of the fwd/rev lists.
 *
 * Changes below should be synced with ChAdvTCPAnalysis in the User's
 * Guide: docbook/wsug_src/WSUG_chapter_advanced.adoc
 */
static void
tcp_analyze_sequence_number(packet_info *pinfo, guint32 seq, guint32 ack, guint32 seglen, guint16 flags, guint32 window, struct tcp_analysis *tcpd)
{
    tcp_unacked_t *ual=NULL;
    tcp_unacked_t *prevual=NULL;
    guint32 nextseq;
    int ackcount;

#if 0
    printf("\nanalyze_sequence numbers   frame:%u\n",pinfo->num);
    printf("FWD list lastflags:0x%04x base_seq:%u: nextseq:%u lastack:%u\n",tcpd->fwd->lastsegmentflags,tcpd->fwd->base_seq,tcpd->fwd->tcp_analyze_seq_info->nextseq,tcpd->rev->tcp_analyze_seq_info->lastack);
    for(ual=tcpd->fwd->tcp_analyze_seq_info->segments; ual; ual=ual->next)
            printf("Frame:%d Seq:%u Nextseq:%u\n",ual->frame,ual->seq,ual->nextseq);
    printf("REV list lastflags:0x%04x base_seq:%u nextseq:%u lastack:%u\n",tcpd->rev->lastsegmentflags,tcpd->rev->base_seq,tcpd->rev->tcp_analyze_seq_info->nextseq,tcpd->fwd->tcp_analyze_seq_info->lastack);
    for(ual=tcpd->rev->tcp_analyze_seq_info->segments; ual; ual=ual->next)
            printf("Frame:%d Seq:%u Nextseq:%u\n",ual->frame,ual->seq,ual->nextseq);
#endif

    if (!tcpd) {
        return;
    }

    /* if this is the first segment for this list we need to store the
     * base_seq
     * We use TCP_S_SAW_SYN/SYNACK to distinguish between client and server
     *
     * Start relative seq and ack numbers at 1 if this
     * is not a SYN packet. This makes the relative
     * seq/ack numbers to be displayed correctly in the
     * event that the SYN or SYN/ACK packet is not seen
     * (this solves bug 1542)
     */
    if( !(tcpd->fwd->static_flags & TCP_S_BASE_SEQ_SET)) {
        if(flags & TH_SYN) {
            tcpd->fwd->base_seq = seq;
            tcpd->fwd->static_flags |= (flags & TH_ACK) ? TCP_S_SAW_SYNACK : TCP_S_SAW_SYN;
        }
        else {
            tcpd->fwd->base_seq = seq-1;
        }
        tcpd->fwd->static_flags |= TCP_S_BASE_SEQ_SET;
    }

    /* Only store reverse sequence if this isn't the SYN
     * There's no guarantee that the ACK field of a SYN
     * contains zeros; get the ISN from the first segment
     * with the ACK bit set instead (usually the SYN/ACK).
     *
     * If the SYN and SYN/ACK were received out-of-order,
     * the ISN is ack-1. If we missed the SYN/ACK, but got
     * the last ACK of the 3WHS, the ISN is ack-1. For all
     * other packets the ISN is unknown, so ack-1 is
     * as good a guess as ack.
     */
    if( !(tcpd->rev->static_flags & TCP_S_BASE_SEQ_SET) && (flags & TH_ACK) ) {
        tcpd->rev->base_seq = ack-1;
        tcpd->rev->static_flags |= TCP_S_BASE_SEQ_SET;
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
    if( seglen==1
    &&  seq==tcpd->fwd->tcp_analyze_seq_info->nextseq
    &&  tcpd->rev->window==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_ZERO_WINDOW_PROBE;
        goto finished_fwd;
    }


    /* ZERO WINDOW
     * a zero window packet has window == 0   but none of the SYN/FIN/RST set
     */
    if( window==0
    && (flags&(TH_RST|TH_FIN|TH_SYN))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
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
    if( tcpd->fwd->tcp_analyze_seq_info->nextseq
    &&  GT_SEQ(seq, tcpd->fwd->tcp_analyze_seq_info->nextseq)
    &&  (flags&(TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
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
    if( (seglen==0||seglen==1)
    &&  seq==(tcpd->fwd->tcp_analyze_seq_info->nextseq-1)
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
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
    &&  seq==tcpd->fwd->tcp_analyze_seq_info->nextseq
    &&  ack==tcpd->fwd->tcp_analyze_seq_info->lastack
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
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
    if( seglen>0
    &&  tcpd->rev->win_scale!=-1
    &&  (seq+seglen)==(tcpd->rev->tcp_analyze_seq_info->lastack+(tcpd->rev->window<<(tcpd->rev->is_first_ack?0:(tcpd->rev->win_scale==-2?0:tcpd->rev->win_scale))))
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_WINDOW_FULL;
    }


    /* KEEP ALIVE ACK
     * It is a keepalive ack if it repeats the previous ACK and if
     * the last segment in the reverse direction was a keepalive
     */
    if( seglen==0
    &&  window
    &&  window==tcpd->fwd->window
    &&  seq==tcpd->fwd->tcp_analyze_seq_info->nextseq
    &&  ack==tcpd->fwd->tcp_analyze_seq_info->lastack
    && (tcpd->rev->lastsegmentflags&TCP_A_KEEP_ALIVE)
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
        }
        tcpd->ta->flags|=TCP_A_KEEP_ALIVE_ACK;
        goto finished_fwd;
    }


    /* ZERO WINDOW PROBE ACK
     * It is a zerowindowprobe ack if it repeats the previous ACK and if
     * the last segment in the reverse direction was a zerowindowprobe
     * It also repeats the previous zero window indication
     */
    if( seglen==0
    &&  window==0
    &&  window==tcpd->fwd->window
    &&  seq==tcpd->fwd->tcp_analyze_seq_info->nextseq
    &&  ack==tcpd->fwd->tcp_analyze_seq_info->lastack
    && (tcpd->rev->lastsegmentflags&TCP_A_ZERO_WINDOW_PROBE)
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
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
    &&  seq==tcpd->fwd->tcp_analyze_seq_info->nextseq
    &&  ack==tcpd->fwd->tcp_analyze_seq_info->lastack
    &&  (flags&(TH_SYN|TH_FIN|TH_RST))==0 ) {

        /* MPTCP tolerates duplicate acks in some circumstances, see RFC 8684 4. */
        if(tcpd->mptcp_analysis && (tcpd->mptcp_analysis->mp_operations!=tcpd->fwd->mp_operations)) {
            /* just ignore this DUPLICATE ACK */
        } else {
            switch(tcpd->fwd->tcp_analyze_seq_info->dupacknum) {
                /* neutralize any 'TCP ACK unseen segment' */
                case -1:
                    tcpd->fwd->tcp_analyze_seq_info->dupacknum = 1;
                    break;
                /* in normal circumstances, just increment the counter */
                default:
                    tcpd->fwd->tcp_analyze_seq_info->dupacknum++;
                    break;
            }
            if(!tcpd->ta) {
                tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->flags|=TCP_A_DUPLICATE_ACK;
            tcpd->ta->dupack_num=tcpd->fwd->tcp_analyze_seq_info->dupacknum;
            tcpd->ta->dupack_frame=tcpd->fwd->tcp_analyze_seq_info->lastnondupack;
       }
    }



finished_fwd:
    /* If the ack number changed we must reset the dupack counters */
    if( ack != tcpd->fwd->tcp_analyze_seq_info->lastack ) {
        tcpd->fwd->tcp_analyze_seq_info->lastnondupack=pinfo->num;
        tcpd->fwd->tcp_analyze_seq_info->dupacknum=0;
    }


    /* ACKED LOST PACKET
     * If this segment acks beyond the 'max seq to be acked' in the other direction
     * then that means we have missed packets going in the
     * other direction
     *
     * We only check this if we have actually seen some seq numbers
     * in the other direction.
     */
    if( tcpd->rev->tcp_analyze_seq_info->maxseqtobeacked
    &&  GT_SEQ(ack, tcpd->rev->tcp_analyze_seq_info->maxseqtobeacked )
    &&  (flags&(TH_ACK))!=0 ) {
        if(!tcpd->ta) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
        }
        /* update 'max seq to be acked' in the other direction so we don't get
         * this indication again.
         */
        if( tcpd->rev->tcp_analyze_seq_info->maxseqtobeacked > tcpd->rev->tcp_analyze_seq_info->nextseq ) {
          tcpd->rev->tcp_analyze_seq_info->maxseqtobeacked=tcpd->rev->tcp_analyze_seq_info->nextseq;
          tcpd->ta->flags|=TCP_A_ACK_LOST_PACKET;
        }
        /* sometimes the other direction is stalled with pure ACKs, but we still
         * want to avoid multiple messages related to the very same lost packet.
         * For this, we need to count at least one ACK seen in this direction,
         * and decrementation is not necessary.
         */
        else {
          if(tcpd->rev->tcp_analyze_seq_info->dupacknum == 0)
            tcpd->ta->flags|=TCP_A_ACK_LOST_PACKET;
          tcpd->rev->tcp_analyze_seq_info->dupacknum = -1;
        }
    }


    /* RETRANSMISSION/FAST RETRANSMISSION/OUT-OF-ORDER
     * If the segment contains data (or is a SYN or a FIN) and
     * if it does not advance the sequence number, it must be one
     * of these three.
     * Only test for this if we know what the seq number should be
     * (tcpd->fwd->nextseq)
     *
     * Note that a simple KeepAlive is not a retransmission
     */
    if (seglen>0 || flags&(TH_SYN|TH_FIN)) {
        gboolean seq_not_advanced = tcpd->fwd->tcp_analyze_seq_info->nextseq
                && (LT_SEQ(seq, tcpd->fwd->tcp_analyze_seq_info->nextseq));

        guint64 t;
        guint64 ooo_thres;

        if(tcpd->ta && (tcpd->ta->flags&TCP_A_KEEP_ALIVE) ) {
            goto finished_checking_retransmission_type;
        }

        /* This segment is *not* considered a retransmission/out-of-order if
         *  the segment length is larger than one (it really adds new data)
         *  the sequence number is one less than the previous nextseq and
         *      (the previous segment is possibly a zero window probe)
         *
         * We should still try to flag Spurious Retransmissions though.
         */
        if (seglen > 1 && tcpd->fwd->tcp_analyze_seq_info->nextseq - 1 == seq) {
            seq_not_advanced = FALSE;
        }

        /* Check for spurious retransmission. If the current seq + segment length
         * is less than or equal to the current lastack, the packet contains
         * duplicate data and may be considered spurious.
         */
        if ( seglen > 0
        && tcpd->rev->tcp_analyze_seq_info->lastack
        && LE_SEQ(seq + seglen, tcpd->rev->tcp_analyze_seq_info->lastack) ) {
            if(!tcpd->ta){
                tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->flags|=TCP_A_SPURIOUS_RETRANSMISSION;
            goto finished_checking_retransmission_type;
        }

        gboolean precedence_count = tcp_fastrt_precedence;
        do {
            switch(precedence_count) {
                case TRUE:
                    /* If there were >=2 duplicate ACKs in the reverse direction
                     * (there might be duplicate acks missing from the trace)
                     * and if this sequence number matches those ACKs
                     * and if the packet occurs within 20ms of the last
                     * duplicate ack
                     * then this is a fast retransmission
                     */
                    t=(pinfo->abs_ts.secs-tcpd->rev->tcp_analyze_seq_info->lastacktime.secs)*1000000000;
                    t=t+(pinfo->abs_ts.nsecs)-tcpd->rev->tcp_analyze_seq_info->lastacktime.nsecs;
                    if( seq_not_advanced
                    &&  tcpd->rev->tcp_analyze_seq_info->dupacknum>=2
                    &&  tcpd->rev->tcp_analyze_seq_info->lastack==seq
                    &&  t<20000000 ) {
                        if(!tcpd->ta) {
                            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
                        }
                        tcpd->ta->flags|=TCP_A_FAST_RETRANSMISSION;
                        goto finished_checking_retransmission_type;
                    }
                    precedence_count=!precedence_count;
                    break;

                case FALSE:
                    /* If the segment came relatively close since the segment with the highest
                     * seen sequence number and it doesn't look like a retransmission
                     * then it is an OUT-OF-ORDER segment.
                     */
                    t=(pinfo->abs_ts.secs-tcpd->fwd->tcp_analyze_seq_info->nextseqtime.secs)*1000000000;
                    t=t+(pinfo->abs_ts.nsecs)-tcpd->fwd->tcp_analyze_seq_info->nextseqtime.nsecs;
                    if (tcpd->ts_first_rtt.nsecs == 0 && tcpd->ts_first_rtt.secs == 0) {
                        ooo_thres = 3000000;
                    } else {
                        ooo_thres = tcpd->ts_first_rtt.nsecs + tcpd->ts_first_rtt.secs*1000000000;
                    }

                    if( seq_not_advanced // XXX is this neccessary?
                    && t < ooo_thres
                    && tcpd->fwd->tcp_analyze_seq_info->nextseq != (seq + seglen + (flags&(TH_SYN|TH_FIN) ? 1 : 0))) {
                        if(!tcpd->ta) {
                            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
                        }
                        tcpd->ta->flags|=TCP_A_OUT_OF_ORDER;
                        goto finished_checking_retransmission_type;
                    }
                    precedence_count=!precedence_count;
                    break;
            }
        } while (precedence_count!=tcp_fastrt_precedence) ;

        if (seq_not_advanced) {
            /* Then it has to be a generic retransmission */
            if(!tcpd->ta) {
                tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->flags|=TCP_A_RETRANSMISSION;

            /*
             * worst case scenario: if we don't have better than a recent packet,
             * use it as the reference for RTO
             */
            nstime_delta(&tcpd->ta->rto_ts, &pinfo->abs_ts, &tcpd->fwd->tcp_analyze_seq_info->nextseqtime);
            tcpd->ta->rto_frame=tcpd->fwd->tcp_analyze_seq_info->nextseqframe;

            /*
             * better case scenario: if we have a list of the previous unacked packets,
             * go back to the eldest one, which in theory is likely to be the one retransmitted here.
             * It's not always the perfect match, particularly when original captured packet used LSO
             */
            ual = tcpd->fwd->tcp_analyze_seq_info->segments;
            while(ual) {
                nstime_delta(&tcpd->ta->rto_ts, &pinfo->abs_ts, &ual->ts );
                tcpd->ta->rto_frame=ual->frame;
                ual=ual->next;
            }
        }
    }

finished_checking_retransmission_type:

    nextseq = seq+seglen;
    if ((seglen || flags&(TH_SYN|TH_FIN)) && tcpd->fwd->tcp_analyze_seq_info->segment_count < TCP_MAX_UNACKED_SEGMENTS) {
        /* Add this new sequence number to the fwd list.  But only if there
         * aren't "too many" unacked segments (e.g., we're not seeing the ACKs).
         */
        ual = wmem_new(wmem_file_scope(), tcp_unacked_t);
        ual->next=tcpd->fwd->tcp_analyze_seq_info->segments;
        tcpd->fwd->tcp_analyze_seq_info->segments=ual;
        tcpd->fwd->tcp_analyze_seq_info->segment_count++;
        ual->frame=pinfo->num;
        ual->seq=seq;
        ual->ts=pinfo->abs_ts;

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
    if(GT_SEQ(nextseq, tcpd->fwd->tcp_analyze_seq_info->nextseq) || !tcpd->fwd->tcp_analyze_seq_info->nextseq) {
        if( !tcpd->ta || !(tcpd->ta->flags&TCP_A_ZERO_WINDOW_PROBE) ) {
            tcpd->fwd->tcp_analyze_seq_info->nextseq=nextseq;
            tcpd->fwd->tcp_analyze_seq_info->nextseqframe=pinfo->num;
            tcpd->fwd->tcp_analyze_seq_info->nextseqtime.secs=pinfo->abs_ts.secs;
            tcpd->fwd->tcp_analyze_seq_info->nextseqtime.nsecs=pinfo->abs_ts.nsecs;
        }
    }

    /* Store the highest continuous seq number seen so far for 'max seq to be acked',
     * so we can detect TCP_A_ACK_LOST_PACKET condition.
     * If this ever happens, this boundary value can "jump" further in order to
     * avoid duplicating multiple messages for the very same lost packet. See later
     * how ACKED LOST PACKET are handled.
     */
    if(EQ_SEQ(seq, tcpd->fwd->tcp_analyze_seq_info->maxseqtobeacked) || !tcpd->fwd->tcp_analyze_seq_info->maxseqtobeacked) {
        if( !tcpd->ta || !(tcpd->ta->flags&TCP_A_ZERO_WINDOW_PROBE) ) {
            tcpd->fwd->tcp_analyze_seq_info->maxseqtobeacked=tcpd->fwd->tcp_analyze_seq_info->nextseq;
        }
    }


    /* remember what the ack/window is so we can track window updates and retransmissions */
    tcpd->fwd->window=window;
    tcpd->fwd->tcp_analyze_seq_info->lastack=ack;
    tcpd->fwd->tcp_analyze_seq_info->lastacktime.secs=pinfo->abs_ts.secs;
    tcpd->fwd->tcp_analyze_seq_info->lastacktime.nsecs=pinfo->abs_ts.nsecs;

    /* remember the MPTCP operations if any */
    if( tcpd->mptcp_analysis ) {
        tcpd->fwd->mp_operations=tcpd->mptcp_analysis->mp_operations;
    }

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
    ual = tcpd->rev->tcp_analyze_seq_info->segments;
    while(ual) {
        tcp_unacked_t *tmpual;

        /* If this ack matches the segment, process accordingly */
        if(ack==ual->nextseq) {
            tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
            tcpd->ta->frame_acked=ual->frame;
            nstime_delta(&tcpd->ta->ts, &pinfo->abs_ts, &ual->ts);
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
            tcpd->rev->tcp_analyze_seq_info->segments = tmpual;
        }
        else{
            prevual->next = tmpual;
        }
        wmem_free(wmem_file_scope(), ual);
        ual = tmpual;
        tcpd->rev->tcp_analyze_seq_info->segment_count--;
    }

    /* how many bytes of data are there in flight after this frame
     * was sent
     * The historical evaluation is done from the payload seen in the
     * segments captured. Another method deduced from the SEQ numbers
     * is introduced with issue 7703, but not used by default now. The
     * method is chosen by the user preference tcp_bif_seq_based.
     */
    if(tcp_track_bytes_in_flight) {
        guint32 in_flight, delivered = 0;
        /*
         * "don't repeat yourself" boolean, for the shared part
         * between both methods
         */
        gboolean dry_bif_handling = FALSE;

        /*
         * historical calculation method based on payloads, which is
         * by now still the default.
         */
        if(!tcp_bif_seq_based) {
            ual=tcpd->fwd->tcp_analyze_seq_info->segments;

            if (seglen!=0 && ual && tcpd->fwd->valid_bif) {
                guint32 first_seq, last_seq;

                dry_bif_handling = TRUE;

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
            }
        } else { /* calculation based on SEQ numbers (see issue 7703) */
            if (seglen!=0 && tcpd->fwd->tcp_analyze_seq_info && tcpd->fwd->valid_bif) {

                dry_bif_handling = TRUE;

                in_flight = tcpd->fwd->tcp_analyze_seq_info->nextseq
                          - tcpd->rev->tcp_analyze_seq_info->lastack;
            }
        }
        if(dry_bif_handling) {
            /* subtract any SACK block */
            if(tcpd->rev->tcp_analyze_seq_info->num_sack_ranges > 0) {
                int i;
                for(i = 0; i<tcpd->rev->tcp_analyze_seq_info->num_sack_ranges; i++) {
                    delivered += (tcpd->rev->tcp_analyze_seq_info->sack_right_edge[i+1] -
                                  tcpd->rev->tcp_analyze_seq_info->sack_left_edge[i+1]);
                }
                in_flight -= delivered;
            }

            if (in_flight>0 && in_flight<2000000000) {
                if(!tcpd->ta) {
                    tcp_analyze_get_acked_struct(pinfo->num, seq, ack, TRUE, tcpd);
                }
                tcpd->ta->bytes_in_flight = in_flight;
                /* Decrement in_flight bytes by one when we have a SYN or FIN bit
                 * flag set as it is only virtual.
                 */
                if (flags&(TH_SYN|TH_FIN))  {
                    tcpd->ta->bytes_in_flight -= 1;
		    }
            }

            if((flags & TH_PUSH) && !tcpd->fwd->push_set_last) {
              tcpd->fwd->push_bytes_sent += seglen;
              tcpd->fwd->push_set_last = TRUE;
            } else if ((flags & TH_PUSH) && tcpd->fwd->push_set_last) {
              tcpd->fwd->push_bytes_sent = seglen;
              tcpd->fwd->push_set_last = TRUE;
            } else if (tcpd->fwd->push_set_last) {
              tcpd->fwd->push_bytes_sent = seglen;
              tcpd->fwd->push_set_last = FALSE;
            } else {
              tcpd->fwd->push_bytes_sent += seglen;
            }
            if(!tcpd->ta) {
              tcp_analyze_get_acked_struct(pinfo->fd->num, seq, ack, TRUE, tcpd);
            }
            tcpd->ta->push_bytes_sent = tcpd->fwd->push_bytes_sent;
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
                          proto_tree * flags_tree, proto_item * flags_item,
                          struct tcp_acked *ta
                          )
{
    /* TCP Retransmission */
    if (ta->flags & TCP_A_RETRANSMISSION) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_retransmission);

        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Retransmission] ");

        if (ta->rto_ts.secs || ta->rto_ts.nsecs) {
            flags_item = proto_tree_add_time(flags_tree, hf_tcp_analysis_rto,
                                             tvb, 0, 0, &ta->rto_ts);
            proto_item_set_generated(flags_item);
            flags_item=proto_tree_add_uint(flags_tree, hf_tcp_analysis_rto_frame,
                                           tvb, 0, 0, ta->rto_frame);
            proto_item_set_generated(flags_item);
        }
    }
    /* TCP Fast Retransmission */
    if (ta->flags & TCP_A_FAST_RETRANSMISSION) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_fast_retransmission);
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_retransmission);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Fast Retransmission] ");
    }
    /* TCP Spurious Retransmission */
    if (ta->flags & TCP_A_SPURIOUS_RETRANSMISSION) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_spurious_retransmission);
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_retransmission);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Spurious Retransmission] ");
    }

    /* TCP Out-Of-Order */
    if (ta->flags & TCP_A_OUT_OF_ORDER) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_out_of_order);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Out-Of-Order] ");
    }
}

/* Prints results of the sequence number analysis concerning reused ports */
static void
tcp_sequence_number_analysis_print_reused(packet_info * pinfo,
                      proto_item * flags_item,
                      struct tcp_acked *ta
                      )
{
    /* TCP Ports Reused */
    if (ta->flags & TCP_A_REUSED_PORTS) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_reused_ports);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Port numbers reused] ");
    }
}

/* Prints results of the sequence number analysis concerning lost tcp segments */
static void
tcp_sequence_number_analysis_print_lost(packet_info * pinfo,
                    proto_item * flags_item,
                    struct tcp_acked *ta
                    )
{
    /* TCP Lost Segment */
    if (ta->flags & TCP_A_LOST_PACKET) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_lost_packet);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP Previous segment not captured] ");
    }
    /* TCP Ack lost segment */
    if (ta->flags & TCP_A_ACK_LOST_PACKET) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_ack_lost_packet);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP ACKed unseen segment] ");
    }
}

/* Prints results of the sequence number analysis concerning tcp window */
static void
tcp_sequence_number_analysis_print_window(packet_info * pinfo,
                      proto_item * flags_item,
                      struct tcp_acked *ta
                      )
{
    /* TCP Window Update */
    if (ta->flags & TCP_A_WINDOW_UPDATE) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_window_update);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Window Update] ");
    }
    /* TCP Full Window */
    if (ta->flags & TCP_A_WINDOW_FULL) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_window_full);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Window Full] ");
    }
}

/* Prints results of the sequence number analysis concerning tcp keepalive */
static void
tcp_sequence_number_analysis_print_keepalive(packet_info * pinfo,
                      proto_item * flags_item,
                      struct tcp_acked *ta
                      )
{
    /*TCP Keep Alive */
    if (ta->flags & TCP_A_KEEP_ALIVE) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_keep_alive);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Keep-Alive] ");
    }
    /* TCP Ack Keep Alive */
    if (ta->flags & TCP_A_KEEP_ALIVE_ACK) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_keep_alive_ack);
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
            proto_item_set_generated(flags_item);
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                                   "[TCP Dup ACK %u#%u] ",
                                   ta->dupack_frame,
                                   ta->dupack_num
                );

        }
        flags_item=proto_tree_add_uint(tree, hf_tcp_analysis_duplicate_ack_num,
                                       tvb, 0, 0, ta->dupack_num);
        proto_item_set_generated(flags_item);
        flags_item=proto_tree_add_uint(tree, hf_tcp_analysis_duplicate_ack_frame,
                                       tvb, 0, 0, ta->dupack_frame);
        proto_item_set_generated(flags_item);
        expert_add_info_format(pinfo, flags_item, &ei_tcp_analysis_duplicate_ack, "Duplicate ACK (#%u)", ta->dupack_num);
    }
}

/* Prints results of the sequence number analysis concerning tcp zero window */
static void
tcp_sequence_number_analysis_print_zero_window(packet_info * pinfo,
                          proto_item * flags_item,
                          struct tcp_acked *ta
                        )
{
    /* TCP Zero Window Probe */
    if (ta->flags & TCP_A_ZERO_WINDOW_PROBE) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_zero_window_probe);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindowProbe] ");
    }
    /* TCP Zero Window */
    if (ta->flags&TCP_A_ZERO_WINDOW) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_zero_window);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindow] ");
    }
    /* TCP Zero Window Probe Ack */
    if (ta->flags & TCP_A_ZERO_WINDOW_PROBE_ACK) {
        expert_add_info(pinfo, flags_item, &ei_tcp_analysis_zero_window_probe_ack);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO,
                               "[TCP ZeroWindowProbeAck] ");
    }
}


/* Prints results of the sequence number analysis concerning how many bytes of data are in flight */
static void
tcp_sequence_number_analysis_print_bytes_in_flight(packet_info * pinfo _U_,
                          tvbuff_t * tvb,
                          proto_tree * flags_tree,
                          struct tcp_acked *ta
                        )
{
    proto_item * flags_item;

    if (tcp_track_bytes_in_flight) {
        flags_item=proto_tree_add_uint(flags_tree,
                                       hf_tcp_analysis_bytes_in_flight,
                                       tvb, 0, 0, ta->bytes_in_flight);

        proto_item_set_generated(flags_item);
    }
}

/* Generate the initial data sequence number and MPTCP connection token from the key. */
static void
mptcp_cryptodata_sha1(const guint64 key, guint32 *token, guint64 *idsn)
{
    guint8 digest_buf[HASH_SHA1_LENGTH];
    guint64 pseudokey = GUINT64_TO_BE(key);
    guint32 _token;
    guint64 _isdn;

    gcry_md_hash_buffer(GCRY_MD_SHA1, digest_buf, (const guint8 *)&pseudokey, 8);

    /* memcpy to prevent -Wstrict-aliasing errors with GCC 4 */
    memcpy(&_token, digest_buf, sizeof(_token));
    *token = GUINT32_FROM_BE(_token);
    memcpy(&_isdn, digest_buf + HASH_SHA1_LENGTH - sizeof(_isdn), sizeof(_isdn));
    *idsn = GUINT64_FROM_BE(_isdn);
}

/* Generate the initial data sequence number and MPTCP connection token from the key. */
static void
mptcp_cryptodata_sha256(const guint64 key, guint32 *token, guint64 *idsn)
{
    guint8 digest_buf[HASH_SHA2_256_LENGTH];
    guint64 pseudokey = GUINT64_TO_BE(key);
    guint32 _token;
    guint64 _isdn;

    gcry_md_hash_buffer(GCRY_MD_SHA256, digest_buf, (const guint8 *)&pseudokey, 8);

    /* memcpy to prevent -Wstrict-aliasing errors with GCC 4 */
    memcpy(&_token, digest_buf, sizeof(_token));
    *token = GUINT32_FROM_BE(_token);
    memcpy(&_isdn, digest_buf + HASH_SHA2_256_LENGTH - sizeof(_isdn), sizeof(_isdn));
    *idsn = GUINT64_FROM_BE(_isdn);
}


/* Print formatted list of tcp stream ids that are part of the connection */
static void
mptcp_analysis_add_subflows(packet_info *pinfo,  tvbuff_t *tvb,
    proto_tree *parent_tree, struct mptcp_analysis* mptcpd)
{
    wmem_list_frame_t *it;
    proto_item *item;

    wmem_strbuf_t *val = wmem_strbuf_new(pinfo->pool, "");

    /* for the analysis, we set each subflow tcp stream id */
    for(it = wmem_list_head(mptcpd->subflows); it != NULL; it = wmem_list_frame_next(it)) {
        struct tcp_analysis *sf = (struct tcp_analysis *)wmem_list_frame_data(it);
        wmem_strbuf_append_printf(val, "%u ", sf->stream);
    }

    item = proto_tree_add_string(parent_tree, hf_mptcp_analysis_subflows, tvb, 0, 0, wmem_strbuf_get_str(val));
    proto_item_set_generated(item);
}

/* Compute raw dsn if relative tcp seq covered by DSS mapping */
static gboolean
mptcp_map_relssn_to_rawdsn(mptcp_dss_mapping_t *mapping, guint32 relssn, guint64 *dsn)
{
    if( (relssn < mapping->ssn_low) || (relssn > mapping->ssn_high)) {
        return FALSE;
    }

    *dsn = mapping->rawdsn + (relssn - mapping->ssn_low);
    return TRUE;
}


/* Add duplicated data */
static mptcp_dsn2packet_mapping_t *
mptcp_add_duplicated_dsn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, struct mptcp_subflow *subflow,
guint64 rawdsn64low, guint64 rawdsn64high
)
{
    wmem_list_t *results = NULL;
    wmem_list_frame_t *packet_it = NULL;
    mptcp_dsn2packet_mapping_t *packet = NULL;
    proto_item *item = NULL;

    results = wmem_itree_find_intervals(subflow->dsn2packet_map,
                    pinfo->pool,
                    rawdsn64low,
                    rawdsn64high
                    );

    for(packet_it = wmem_list_head(results);
        packet_it != NULL;
        packet_it = wmem_list_frame_next(packet_it))
    {

        packet = (mptcp_dsn2packet_mapping_t *) wmem_list_frame_data(packet_it);
        DISSECTOR_ASSERT(packet);

        if(pinfo->num > packet->frame) {
            item = proto_tree_add_uint(tree, hf_mptcp_reinjection_of, tvb, 0, 0, packet->frame);
        }
        else {
            item = proto_tree_add_uint(tree, hf_mptcp_reinjected_in, tvb, 0, 0, packet->frame);
        }
        proto_item_set_generated(item);
    }

    return packet;
}


/* Lookup mappings that describe the packet and then converts the tcp seq number
 * into the MPTCP Data Sequence Number (DSN)
 */
static void
mptcp_analysis_dsn_lookup(packet_info *pinfo , tvbuff_t *tvb,
    proto_tree *parent_tree, struct tcp_analysis* tcpd, struct tcpheader * tcph, mptcp_per_packet_data_t *mptcppd)
{
    struct mptcp_analysis* mptcpd = tcpd->mptcp_analysis;
    proto_item *item = NULL;
    mptcp_dss_mapping_t *mapping = NULL;
    guint32 relseq;
    guint64 rawdsn = 0;
    enum mptcp_dsn_conversion convert;

    if(!mptcp_analyze_mappings)
    {
        /* abort analysis */
        return;
    }

    /* for this to work, we need to know the original seq number from the SYN, not from a subsequent packet
    * hence, we abort if we didn't capture the SYN
    */
    if(!(tcpd->fwd->static_flags & ~TCP_S_BASE_SEQ_SET & (TCP_S_SAW_SYN | TCP_S_SAW_SYNACK))) {
        return;
    }

    /* if seq not relative yet, we compute it */
    relseq = (tcp_relative_seq) ? tcph->th_seq : tcph->th_seq - tcpd->fwd->base_seq;

    DISSECTOR_ASSERT(mptcpd);
    DISSECTOR_ASSERT(mptcppd);

    /* in case of a SYN, there is no mapping covering the DSN */
    if(tcph->th_flags & TH_SYN) {

        rawdsn = tcpd->fwd->mptcp_subflow->meta->base_dsn;
        convert = DSN_CONV_NONE;
    }
    /* if it's a non-syn packet without data (just used to convey TCP options)
     * then there would be no mappings */
    else if(relseq == 1 && tcph->th_seglen == 0) {
        rawdsn = tcpd->fwd->mptcp_subflow->meta->base_dsn + 1;
        convert = DSN_CONV_NONE;
    }
    else {

        wmem_list_frame_t *dss_it = NULL;
        wmem_list_t *results = NULL;
        guint32 ssn_low = relseq;
        guint32 seglen = tcph->th_seglen;

        results = wmem_itree_find_intervals(tcpd->fwd->mptcp_subflow->ssn2dsn_mappings,
                    pinfo->pool,
                    ssn_low,
                    (seglen) ? ssn_low + seglen - 1 : ssn_low
                    );
        dss_it = wmem_list_head(results); /* assume it's always ok */
        if(dss_it) {
            mapping = (mptcp_dss_mapping_t *) wmem_list_frame_data(dss_it);
        }
        if(dss_it == NULL || mapping == NULL) {
            expert_add_info(pinfo, parent_tree, &ei_mptcp_mapping_missing);
            return;
        }
        else {
            mptcppd->mapping = mapping;
        }

        DISSECTOR_ASSERT(mapping);
        if(seglen) {
            /* Finds mappings that cover the sent data and adds them to the dissection tree */
            for(dss_it = wmem_list_head(results);
                dss_it != NULL;
                dss_it = wmem_list_frame_next(dss_it))
            {
                mapping = (mptcp_dss_mapping_t *) wmem_list_frame_data(dss_it);
                DISSECTOR_ASSERT(mapping);

                item = proto_tree_add_uint(parent_tree, hf_mptcp_related_mapping, tvb, 0, 0, mapping->frame);
                proto_item_set_generated(item);
            }
        }

        convert = (mapping->extended_dsn) ? DSN_CONV_NONE : DSN_CONV_32_TO_64;
        DISSECTOR_ASSERT(mptcp_map_relssn_to_rawdsn(mapping, relseq, &rawdsn));
    }

    /* Make sure we have the 64bit raw DSN */
    if(mptcp_convert_dsn(rawdsn, tcpd->fwd->mptcp_subflow->meta,
        convert, FALSE, &tcph->th_mptcp->mh_rawdsn64)) {

        /* always display the rawdsn64 (helpful for debug) */
        item = proto_tree_add_uint64(parent_tree, hf_mptcp_rawdsn64, tvb, 0, 0, tcph->th_mptcp->mh_rawdsn64);

        /* converts to relative if required */
        if (mptcp_relative_seq
            && mptcp_convert_dsn(tcph->th_mptcp->mh_rawdsn64, tcpd->fwd->mptcp_subflow->meta, DSN_CONV_NONE, TRUE, &tcph->th_mptcp->mh_dsn)) {
            item = proto_tree_add_uint64(parent_tree, hf_mptcp_dsn, tvb, 0, 0, tcph->th_mptcp->mh_dsn);
            proto_item_append_text(item, " (Relative)");
        }

        /* register dsn->packet mapping */
        if(mptcp_intersubflows_retransmission
            && !PINFO_FD_VISITED(pinfo)
            && tcph->th_seglen > 0
          ) {
                mptcp_dsn2packet_mapping_t *packet = 0;
                packet = wmem_new0(wmem_file_scope(), mptcp_dsn2packet_mapping_t);
                packet->frame = pinfo->fd->num;
                packet->subflow = tcpd;

                wmem_itree_insert(tcpd->fwd->mptcp_subflow->dsn2packet_map,
                        tcph->th_mptcp->mh_rawdsn64,
                        tcph->th_mptcp->mh_rawdsn64 + (tcph->th_seglen - 1 ),
                        packet
                        );
        }
        proto_item_set_generated(item);

        /* We can do this only if rawdsn64 is valid !
        if enabled, look for overlapping mappings on other subflows */
        if(mptcp_intersubflows_retransmission
            && tcph->th_have_seglen
            && tcph->th_seglen) {

            wmem_list_frame_t *subflow_it = NULL;

            /* results should be some kind of list in case 2 DSS are needed to cover this packet */
            for(subflow_it = wmem_list_head(mptcpd->subflows); subflow_it != NULL; subflow_it = wmem_list_frame_next(subflow_it)) {
                struct tcp_analysis *sf_tcpd = (struct tcp_analysis *)wmem_list_frame_data(subflow_it);
                struct mptcp_subflow *sf = mptcp_select_subflow_from_meta(sf_tcpd, tcpd->fwd->mptcp_subflow->meta);

                /* for current subflow */
                if (sf == tcpd->fwd->mptcp_subflow) {
                    /* skip, this is the current subflow */
                }
                /* in case there were retransmissions on other subflows */
                else  {
                    mptcp_add_duplicated_dsn(pinfo, parent_tree, tvb, sf,
                                             tcph->th_mptcp->mh_rawdsn64,
                                             tcph->th_mptcp->mh_rawdsn64 + tcph->th_seglen-1);
                }
            }
        }
    }
    else {
        /* could not get the rawdsn64, ignore and continue */
    }

}


/* Print subflow list */
static void
mptcp_add_analysis_subtree(packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree,
                          struct tcp_analysis *tcpd, struct mptcp_analysis *mptcpd, struct tcpheader * tcph)
{

    proto_item *item = NULL;
    proto_tree *tree = NULL;
    mptcp_per_packet_data_t *mptcppd = NULL;

    if(mptcpd == NULL) {
        return;
    }

    item=proto_tree_add_item(parent_tree, hf_mptcp_analysis, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    tree=proto_item_add_subtree(item, ett_mptcp_analysis);
    proto_item_set_generated(tree);

    /* set field with mptcp stream */
    if(mptcpd->master) {

        item = proto_tree_add_boolean_format_value(tree, hf_mptcp_analysis_master, tvb, 0,
                                     0, (mptcpd->master->stream == tcpd->stream) ? TRUE : FALSE
                                     , "Master is tcp stream %u", mptcpd->master->stream
                                     );

    }
    else {
          item = proto_tree_add_boolean(tree, hf_mptcp_analysis_master, tvb, 0,
                                     0, FALSE);
    }

    proto_item_set_generated(item);

    /* store the TCP Options related to MPTCP then we will avoid false DUP ACKs later */
    guint8 nbOptionsChanged = 0;
    if((tcpd->mptcp_analysis->mp_operations&(0x01))!=tcph->th_mptcp->mh_mpc) {
        tcpd->mptcp_analysis->mp_operations |= 0x01;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x02))!=tcph->th_mptcp->mh_join) {
        tcpd->mptcp_analysis->mp_operations |= 0x02;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x04))!=tcph->th_mptcp->mh_dss) {
        tcpd->mptcp_analysis->mp_operations |= 0x04;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x08))!=tcph->th_mptcp->mh_add) {
        tcpd->mptcp_analysis->mp_operations |= 0x08;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x10))!=tcph->th_mptcp->mh_remove) {
        tcpd->mptcp_analysis->mp_operations |= 0x10;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x20))!=tcph->th_mptcp->mh_prio) {
        tcpd->mptcp_analysis->mp_operations |= 0x20;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x40))!=tcph->th_mptcp->mh_fail) {
        tcpd->mptcp_analysis->mp_operations |= 0x40;
        nbOptionsChanged++;
    }
    if((tcpd->mptcp_analysis->mp_operations&(0x80))!=tcph->th_mptcp->mh_fastclose) {
        tcpd->mptcp_analysis->mp_operations |= 0x80;
        nbOptionsChanged++;
    }
    /* we could track MPTCP option changes here, with nbOptionsChanged */

    item = proto_tree_add_uint(tree, hf_mptcp_stream, tvb, 0, 0, mptcpd->stream);
    proto_item_set_generated(item);

    /* retrieve saved analysis of packets, else create it */
    mptcppd = (mptcp_per_packet_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mptcp, pinfo->curr_layer_num);
    if(!mptcppd) {
        mptcppd = (mptcp_per_packet_data_t *)wmem_new0(wmem_file_scope(), mptcp_per_packet_data_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mptcp, pinfo->curr_layer_num, mptcppd);
    }

    /* Print formatted list of tcp stream ids that are part of the connection */
    mptcp_analysis_add_subflows(pinfo, tvb, tree, mptcpd);

    /* Converts TCP seq number into its MPTCP DSN */
    mptcp_analysis_dsn_lookup(pinfo, tvb, tree, tcpd, tcph, mptcppd);

}


static void
tcp_sequence_number_analysis_print_push_bytes_sent(packet_info * pinfo _U_,
                          tvbuff_t * tvb,
                          proto_tree * flags_tree,
                          struct tcp_acked *ta
                        )
{
    proto_item * flags_item;

    if (tcp_track_bytes_in_flight) {
        flags_item=proto_tree_add_uint(flags_tree,
                                       hf_tcp_analysis_push_bytes_sent,
                                       tvb, 0, 0, ta->push_bytes_sent);

        proto_item_set_generated(flags_item);
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
        tcp_analyze_get_acked_struct(pinfo->num, seq, ack, FALSE, tcpd);
    }
    ta=tcpd->ta;
    if(!ta) {
        return;
    }

    item=proto_tree_add_item(parent_tree, hf_tcp_analysis, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    tree=proto_item_add_subtree(item, ett_tcp_analysis);

    /* encapsulate all proto_tree_add_xxx in ifs so we only print what
       data we actually have */
    if(ta->frame_acked) {
        item = proto_tree_add_uint(tree, hf_tcp_analysis_acks_frame,
            tvb, 0, 0, ta->frame_acked);
            proto_item_set_generated(item);

        /* only display RTT if we actually have something we are acking */
        if( ta->ts.secs || ta->ts.nsecs ) {
            item = proto_tree_add_time(tree, hf_tcp_analysis_ack_rtt,
            tvb, 0, 0, &ta->ts);
                proto_item_set_generated(item);
        }
    }
    if (!nstime_is_zero(&tcpd->ts_first_rtt)) {
        item = proto_tree_add_time(tree, hf_tcp_analysis_first_rtt,
                tvb, 0, 0, &(tcpd->ts_first_rtt));
        proto_item_set_generated(item);
    }

    if(ta->bytes_in_flight) {
        /* print results for amount of data in flight */
        tcp_sequence_number_analysis_print_bytes_in_flight(pinfo, tvb, tree, ta);
        tcp_sequence_number_analysis_print_push_bytes_sent(pinfo, tvb, tree, ta);
    }

    if(ta->flags) {
        item = proto_tree_add_item(tree, hf_tcp_analysis_flags, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(item);
        flags_tree=proto_item_add_subtree(item, ett_tcp_analysis);

        /* print results for reused tcp ports */
        tcp_sequence_number_analysis_print_reused(pinfo, item, ta);

        /* print results for retransmission and out-of-order segments */
        tcp_sequence_number_analysis_print_retransmission(pinfo, tvb, flags_tree, item, ta);

        /* print results for lost tcp segments */
        tcp_sequence_number_analysis_print_lost(pinfo, item, ta);

        /* print results for tcp window information */
        tcp_sequence_number_analysis_print_window(pinfo, item, ta);

        /* print results for tcp keep alive information */
        tcp_sequence_number_analysis_print_keepalive(pinfo, item, ta);

        /* print results for tcp duplicate acks */
        tcp_sequence_number_analysis_print_duplicate(pinfo, tvb, flags_tree, ta, tree);

        /* print results for tcp zero window  */
        tcp_sequence_number_analysis_print_zero_window(pinfo, item, ta);

    }

}

static void
print_tcp_fragment_tree(fragment_head *ipfd_head, proto_tree *tree, proto_tree *tcp_tree, packet_info *pinfo, tvbuff_t *next_tvb)
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

/* The primary ID is the first frame of a multisegment PDU, which is
 * most likely unique in the capture (unlike sequence numbers which
 * can be re-used, especially when relative sequence numbers are enabled).
 * However, frames can have multiple PDUs with certain encapsulations like
 * GSE or MPE over DVB BaseBand Frames.
 */

typedef struct _tcp_endpoint {

    address src_addr;
    address dst_addr;
    port_type ptype;
    guint32 src_port;
    guint32 dst_port;
} tcp_endpoint_t;

static void
save_endpoint(packet_info *pinfo, tcp_endpoint_t *a)
{
    copy_address_shallow(&a->src_addr, &pinfo->src);
    copy_address_shallow(&a->dst_addr, &pinfo->dst);
    a->ptype = pinfo->ptype;
    a->src_port = pinfo->srcport;
    a->dst_port = pinfo->destport;
}

static void
restore_endpoint(packet_info *pinfo, tcp_endpoint_t *a)
{
    copy_address_shallow(&pinfo->src, &a->src_addr);
    copy_address_shallow(&pinfo->dst, &a->dst_addr);
    pinfo->ptype = a->ptype;
    pinfo->srcport = a->src_port;
    pinfo->destport = a->dst_port;
}

typedef struct _tcp_segment_key {
        address src_addr;
        address dst_addr;
        guint32 src_port;
        guint32 dst_port;
        guint32 id;  /* msp->first_frame */
        guint32 seq; /* msp->seq */
} tcp_segment_key;

static guint
tcp_segment_hash(gconstpointer k)
{
        const tcp_segment_key* key = (const tcp_segment_key*) k;
        guint hash_val;

        hash_val = key->id;

/*      In most captures there is only one fragment per id / first_frame,
        so we only use it in the hash as an optimization.

        int i;
        for (i = 0; i < key->src.len; i++)
                hash_val += key->src_addr.data[i];
        for (i = 0; i < key->dst.len; i++)
                hash_val += key->dst_addr.data[i];
        hash_val += key->src_port;
        hash_val += key->dst_port;
        hash_val += key->seq;
*/

        return hash_val;
}

static gint
tcp_segment_equal(gconstpointer k1, gconstpointer k2)
{
        const tcp_segment_key* key1 = (const tcp_segment_key*) k1;
        const tcp_segment_key* key2 = (const tcp_segment_key*) k2;

        /*
         * key.id is the first item to compare since it's the item most
         * likely to differ between sessions, thus short-circuiting
         * the comparison of addresses and ports.
         */
        return (key1->id == key2->id) &&
               (addresses_equal(&key1->src_addr, &key2->src_addr)) &&
               (addresses_equal(&key1->dst_addr, &key2->dst_addr)) &&
               (key1->src_port == key2->src_port) &&
               (key1->dst_port == key2->dst_port) &&
               (key1->seq == key2->seq);
}

/*
 * Create a fragment key for temporary use; it can point to non-
 * persistent data, and so must only be used to look up and
 * delete entries, not to add them.
 */
static gpointer
tcp_segment_temporary_key(const packet_info *pinfo, const guint32 id,
                          const void *data)
{
        struct tcp_multisegment_pdu *msp = (struct tcp_multisegment_pdu*)data;
        DISSECTOR_ASSERT(msp);
        tcp_segment_key *key = g_slice_new(tcp_segment_key);

        /*
         * Do a shallow copy of the addresses.
         */
        copy_address_shallow(&key->src_addr, &pinfo->src);
        copy_address_shallow(&key->dst_addr, &pinfo->dst);
        key->src_port = pinfo->srcport;
        key->dst_port = pinfo->destport;
        key->id = id;
        key->seq = msp->seq;

        return (gpointer)key;
}

/*
 * Create a fragment key for permanent use; it must point to persistent
 * data, so that it can be used to add entries.
 */
static gpointer
tcp_segment_persistent_key(const packet_info *pinfo,
                           const guint32 id, const void *data)
{
        struct tcp_multisegment_pdu *msp = (struct tcp_multisegment_pdu*)data;
        DISSECTOR_ASSERT(msp);
        tcp_segment_key *key = g_slice_new(tcp_segment_key);

        /*
         * Do a deep copy of the addresses.
         */
        copy_address(&key->src_addr, &pinfo->src);
        copy_address(&key->dst_addr, &pinfo->dst);
        key->src_port = pinfo->srcport;
        key->dst_port = pinfo->destport;
        key->id = id;
        key->seq = msp->seq;

        return (gpointer)key;
}

static void
tcp_segment_free_temporary_key(gpointer ptr)
{
        tcp_segment_key *key = (tcp_segment_key *)ptr;
        g_slice_free(tcp_segment_key, key);
}

static void
tcp_segment_free_persistent_key(gpointer ptr)
{
        tcp_segment_key *key = (tcp_segment_key *)ptr;

        if(key){
                /*
                 * Free up the copies of the addresses from the old key.
                 */
                free_address(&key->src_addr);
                free_address(&key->dst_addr);

                g_slice_free(tcp_segment_key, key);
        }
}

const reassembly_table_functions
tcp_reassembly_table_functions = {
        tcp_segment_hash,
        tcp_segment_equal,
        tcp_segment_temporary_key,
        tcp_segment_persistent_key,
        tcp_segment_free_temporary_key,
        tcp_segment_free_persistent_key
};

static reassembly_table tcp_reassembly_table;

/* functions to trace tcp segments */
/* Enable desegmenting of TCP streams */
static gboolean tcp_desegment = TRUE;

#if 0
/* Returns true iff any gap exists in the segments associated with msp up to the
 * given sequence number (it ignores any gaps after the sequence number). */
static gboolean
missing_segments(packet_info *pinfo, struct tcp_multisegment_pdu *msp, guint32 seq)
{
    fragment_head *fd_head;
    guint32 frag_offset = seq - msp->seq;

    if ((gint32)frag_offset <= 0) {
        return FALSE;
    }

    fd_head = fragment_get(&tcp_reassembly_table, pinfo, msp->first_frame, msp);
    /* msp implies existence of fragments, this should never be NULL. */
    DISSECTOR_ASSERT(fd_head);

    /* Find length of contiguous fragments. */
    guint32 max = 0;
    for (fragment_item *frag = fd_head; frag; frag = frag->next) {
        guint32 frag_end = frag->offset + frag->len;
        if (frag->offset <= max && max < frag_end) {
            max = frag_end;
        }
    }
    return max < frag_offset;
}
#endif

static struct tcp_multisegment_pdu*
split_msp(packet_info *pinfo, struct tcp_multisegment_pdu *msp, struct tcp_analysis *tcpd)
{
    fragment_head *fd_head;
    guint32 first_frame = 0;
    guint32 last_frame = 0;
    const guint32 split_offset = pinfo->desegment_offset;

    fd_head = fragment_get(&tcp_reassembly_table, pinfo, msp->first_frame, msp);
    /* This is for splitting defragmented MSPs, so fd_head should exist
     * and be defragmented. This also ensures that fd_i->tvb_data exists.
     */
    DISSECTOR_ASSERT(fd_head && fd_head->flags & FD_DEFRAGMENTED);

    fragment_item *fd_i, *first_frag = NULL;

    /* The fragment list is sorted in offset order, but not nec. frame order
     * or end offset order due to out of order reassembly and possible overlap.
     * fd_i->offset < split_offset - some bytes are before the split
     * fd_i->offset + fd_i->len >= split_offset - some bytes are after split
     * Look through all the fragments that have some data before the split point.
     */
    for (fd_i = fd_head->next; fd_i && (fd_i->offset < split_offset); fd_i = fd_i->next) {
        if (last_frame < fd_i->frame) {
            last_frame = fd_i->frame;
        }
        if (fd_i->offset + fd_i->len >= split_offset) {
            if (first_frag == NULL) {
                first_frag = fd_i;
                first_frame = fd_i->frame;
            } else if (fd_i->frame < first_frame) {
                first_frame = fd_i->frame;
            }
        }
    };

    /* Now look through all the remaining fragments that only have bytes after
     * the split.
     */
    for (; fd_i; fd_i = fd_i->next) {
        guint32 frag_end = fd_i->offset + fd_i->len;
        if (split_offset <= frag_end && fd_i->frame < first_frame) {
            first_frame = fd_i->frame;
        }
    }

    /* We only call this when the frame the fragments were reassembled in
     * (which is the current frame) includes some data before the split
     * point, so that it won't change and we can be consistent dissecting
     * between passes. We also should have at least some data after the
     * split point (because the subdissector claimed there was undissected
     * data.)
     */
    DISSECTOR_ASSERT(fd_head->reassembled_in == last_frame);
    DISSECTOR_ASSERT(first_frag != NULL);

    guint32 new_seq = msp->seq + pinfo->desegment_offset;
    struct tcp_multisegment_pdu *newmsp;
    newmsp = pdu_store_sequencenumber_of_next_pdu(pinfo, new_seq,
        new_seq+1, tcpd->fwd->multisegment_pdus);
    newmsp->first_frame = first_frame;
    newmsp->nxtpdu = msp->nxtpdu;

    /* XXX: Could do the adding the new fragments in fragment_truncate */
    for (fd_i = first_frag; fd_i; fd_i = fd_i->next) {
        guint32 frag_offset = fd_i->offset;
        guint32 frag_len = fd_i->len;
        /* Check for some unusual out of order overlapping segment situations. */
        if (split_offset <= frag_offset + frag_len) {
            if (fd_i->offset < split_offset) {
                frag_offset = split_offset;
                frag_len -= (split_offset - fd_i->offset);
            }
            fragment_add_out_of_order(&tcp_reassembly_table, fd_head->tvb_data,
                         frag_offset, pinfo, first_frame, newmsp,
                         frag_offset - split_offset, frag_len, TRUE, fd_i->frame);
        }
    }

    fragment_truncate(&tcp_reassembly_table, pinfo, msp->first_frame, msp, split_offset);
    msp->nxtpdu = msp->seq + split_offset;

    /* The newmsp nxtpdu will be adjusted after leaving this function. */
    return newmsp;
}

typedef struct _ooo_segment_item {
    guint32 frame;
    guint32 seq;
    guint32 len;
    guint8 *data;
} ooo_segment_item;

static gint
compare_ooo_segment_item(gconstpointer a, gconstpointer b)
{
    const ooo_segment_item *fd_a = a;
    const ooo_segment_item *fd_b = b;

    /* We only insert segments into this list that satisfy
     * LT_SEQ(tcpd->fwd->maxnextseq, seq), for the current value
     * of maxnextseq (removing segments when maxnextseq is advanced)
     * so these rollover-aware comparisons are transitive over the
     * domain (never greater than 2^31).
     */
    if (LT_SEQ(fd_a->seq, fd_b->seq))
        return -1;

    if (GT_SEQ(fd_a->seq, fd_b->seq))
        return 1;

    if (fd_a->frame < fd_b->frame)
        return -1;

    if (fd_a->frame > fd_b->frame)
        return 1;

    return 0;
}

/* Search through our list of out of order segments and add the ones that are
 * now contiguous onto a MSP until we use them all or reach another gap.
 *
 * If the MSP parameter is a incomplete, returns it with any OOO segments added.
 * If the MSP parameter is NULL or complete, returns a newly created MSP with
 * OOO segments added, or NULL if there were no segments to add.
 */
static struct tcp_multisegment_pdu *
msp_add_out_of_order(packet_info *pinfo, struct tcp_multisegment_pdu *msp, struct tcp_analysis *tcpd, guint32 seq)
{

    /* Whether a previous MSP exists with missing segments. */
    gboolean has_unfinished_msp = msp && !(msp->flags & MSP_FLAGS_GOT_ALL_SEGMENTS);

    wmem_list_frame_t *curr_entry;
    curr_entry = wmem_list_head(tcpd->fwd->ooo_segments);
    ooo_segment_item *fd;
    tvbuff_t         *tvb_data;
    while (curr_entry) {
        fd = (ooo_segment_item *)wmem_list_frame_data(curr_entry);
        if (LT_SEQ(tcpd->fwd->maxnextseq, fd->seq)) {
            break;
        }
        /* We have filled in the gap, so this out of order
         * segment is now contiguous and can be processed along
         * with the segment we just received.
         */
        tcpd->fwd->maxnextseq = fd->seq + fd->len;
        tvb_data = tvb_new_real_data(fd->data, fd->len, fd->len);
        if (has_unfinished_msp) {

            /* Increase the expected MSP size if necessary. */
            if (LT_SEQ(msp->nxtpdu, fd->seq + fd->len)) {
                msp->nxtpdu = fd->seq + fd->len;
            }
            /* Add this OOO segment to the unfinished MSP */
            fragment_add_out_of_order(&tcp_reassembly_table,
                tvb_data, 0,
                pinfo, msp->first_frame, msp,
                fd->seq - msp->seq, fd->len,
                msp->nxtpdu, fd->frame);
        } else {
            /* No MSP in progress, so create one starting
             * at the sequence number of segment received
             * in this frame. Note that we will be adding
             * the first segment below, and this is the frame
             * of the first segment, so first_frame_with_seq
             * is already correct (and unnecessary) and
             * we don't need MSP_FLAGS_MISSING_FIRST_SEGMENT. */
            msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                seq, fd->seq + fd->len,
                tcpd->fwd->multisegment_pdus);
            fragment_add_out_of_order(&tcp_reassembly_table,
                        tvb_data, 0, pinfo, msp->first_frame,
                        msp, fd->seq - msp->seq, fd->len,
                        msp->nxtpdu, fd->frame);
            has_unfinished_msp = TRUE;
        }
        tvb_free(tvb_data);
        wmem_list_remove_frame(tcpd->fwd->ooo_segments, curr_entry);
        curr_entry = wmem_list_head(tcpd->fwd->ooo_segments);

    }
    return msp;
}

static void
desegment_tcp(tvbuff_t *tvb, packet_info *pinfo, int offset,
              guint32 seq, guint32 nxtseq,
              guint32 sport, guint32 dport,
              proto_tree *tree, proto_tree *tcp_tree,
              struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo)
{
    fragment_head *ipfd_head;
    int last_fragment_len;
    gboolean must_desegment;
    gboolean called_dissector;
    gboolean has_gap;
    int another_pdu_follows;
    int deseg_offset;
    guint32 deseg_seq;
    gint nbytes;
    proto_item *item;
    struct tcp_multisegment_pdu *msp;
    gboolean cleared_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
    gboolean first_pdu = TRUE;
    const gboolean reassemble_ooo = tcp_analyze_seq && tcp_desegment && tcp_reassemble_out_of_order;

    tcp_endpoint_t orig_endpoint, new_endpoint;

    save_endpoint(pinfo, &orig_endpoint);
    save_endpoint(pinfo, &new_endpoint);

again:
    ipfd_head = NULL;
    last_fragment_len = 0;
    must_desegment = FALSE;
    called_dissector = FALSE;
    has_gap = FALSE;
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

    /*
     * TODO: Some notes on current limitations with TCP desegmentation:
     *
     * This function can be called with either relative or absolute sequence
     * numbers; the ??_SEQ macros are called for comparisons to deal with
     * with sequence number rollover. (With relative sequence numbers, if
     * early TCP segments are received out of order before the SYN it can be
     * possible for rollover to occur at the very beginning of a connection.)
     *
     * However, multi-segment PDU lookup does not work for MSPs that span
     * TCP sequence number rollover, and desegmentation fails.
     *
     * When there is a single TCP connection that is longer than 4 GiB and
     * thus sequence numbers are reused, multi-segment PDU lookup and
     * retransmission identification does not work. (Bug 10503).
     *
     * Distinguishing between sequence number reuse on a very long connection
     * and sequence number reuse due to retransmission is difficult. Right
     * now very long connections are just not handled as the rarer case.
     * Perhaps retransmission identification could be entirely left up to TCP
     * analysis (if enabled, not done at all if disabled), instead of TCP
     * analysis results only used to supplement work here?
     *
     * TCP sequence analysis can set TCP_A_RETRANSMISSION in cases where
     * we still need to process the segment anyway because something other
     * than the sequence number is different from the prior segment. That
     * includes "retransmitted but with additional data" (Bug 13523) and
     * "retransmitted due to bad checksum" (especially if checksum verification
     * is enabled.)
     *
     * If multiple TCP/IP packets are encapsulated in the same frame (such
     * as with GSE, which has very long Baseband Frames) this causes issues:
     *
     * If a subdissector reports that it can handle a payload, but needs
     * more data (pinfo->desegment_len > 0) and did not actually dissect
     * any of it (pinfo->desegment_offset == 0), on the first pass it
     * still adds layers to the frame. On subsequent passes, the MSP created
     * (or extended) in the first pass means that the subdissector won't be
     * called at all. If there are other protocols contained in the frame
     * that are dissected on the second pass they will have different
     * layer numbers than in the first pass, which can disturb proto_data
     * lookup, reassembly, etc. (Bug 16109 describes this for TLS.)
     */

    if (tcpd) {
        /* Have we seen this PDU before (and is it the start of a multi-
         * segment PDU)?
         *
         * If the sequence number was seen before, it is part of a
         * retransmission if the whole segment fits within the MSP.
         * (But if this is this frame was already visited and the first frame of
         * the MSP matches the current frame, then it is not a retransmission,
         * but the start of a new MSP.)
         *
         * If only part of the segment fits in the MSP, then either:
         * - The previous segment included with the MSP was a Zero Window Probe
         *   with one byte of data and the subdissector just asked for one more
         *   byte. Do not mark it as retransmission (Bug 15427).
         * - Data was actually being retransmitted, but with additional data
         *   (Bug 13523). Do not mark it as retransmission to handle the extra
         *   bytes. (NOTE Due to the TCP_A_RETRANSMISSION check below, such
         *   extra data will still be ignored.)
         * - The MSP contains multiple segments, but the subdissector finished
         *   reassembly using a subset of the final segment (thus "msp->nxtpdu"
         *   is smaller than the nxtseq of the previous segment). If that final
         *   segment was retransmitted, then "nxtseq > msp->nxtpdu".
         *   Unfortunately that will *not* be marked as retransmission here.
         *   The next TCP_A_RETRANSMISSION hopefully takes care of it though.
         *
         * Only shortcircuit here when the first segment of the MSP is known,
         * and when this first segment is not one to complete the MSP.
         */
        if ((msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32(tcpd->fwd->multisegment_pdus, seq)) &&
                nxtseq <= msp->nxtpdu &&
                !(msp->flags & MSP_FLAGS_MISSING_FIRST_SEGMENT) && msp->last_frame != pinfo->num) {
            const char* str;
            gboolean is_retransmission = FALSE;

            /* Yes.  This could be because we've dissected this frame before
             * or because this is a retransmission of a previously-seen
             * segment.  Either way, we don't need to hand it off to the
             * subdissector and we certainly don't want to re-add it to the
             * multisegment_pdus list: if we did, subsequent lookups would
             * find this retransmission instead of the original transmission
             * (breaking desegmentation if we'd already linked other segments
             * to the original transmission's entry).
             *
             * Cases to handle here:
             * - In-order stream, pinfo->num matches begin of MSP.
             * - In-order stream, but pinfo->num does not match the begin of the
             *   MSP. Must be a retransmission.
             * - OoO stream where this segment fills the gap in the begin of the
             *   MSP. msp->first_frame is the start where the gap was detected
             *   (and does NOT match pinfo->num).
             */

            if (msp->first_frame == pinfo->num || msp->first_frame_with_seq == pinfo->num) {
                str = "";
                if (first_pdu) {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[TCP segment of a reassembled PDU]");
                }
            } else {
                str = "Retransmitted ";
                is_retransmission = TRUE;
                /* TCP analysis already flags this (in COL_INFO) as a retransmission--if it's enabled */
            }

            /* Fix for bug 3264: look up ipfd for this (first) segment,
               so can add tcp.reassembled_in generated field on this code path. */
            if (!is_retransmission) {
                ipfd_head = fragment_get(&tcp_reassembly_table, pinfo, msp->first_frame, msp);
                if (ipfd_head) {
                    if (ipfd_head->reassembled_in != 0) {
                        item = proto_tree_add_uint(tcp_tree, hf_tcp_reassembled_in, tvb, 0,
                                           0, ipfd_head->reassembled_in);
                        proto_item_set_generated(item);
                    }
                }
            }

            nbytes = tvb_reported_length_remaining(tvb, offset);

            proto_tree_add_bytes_format(tcp_tree, hf_tcp_segment_data, tvb, offset,
                nbytes, NULL, "%sTCP segment data (%u byte%s)", str, nbytes,
                plurality(nbytes, "", "s"));
            goto clean_exit;
        }

        /* The above code only finds retransmission if the PDU boundaries and the seq coincide I think
         * If we have sequence analysis active use the TCP_A_RETRANSMISSION flag.
         * XXXX Could the above code be improved?
         * XXX the following check works great for filtering duplicate
         * retransmissions, but could there be a case where it prevents
         * "tcp_reassemble_out_of_order" from functioning due to skipping
         * retransmission of a lost segment?
         * If the latter is enabled, it could use "maxnextseq" for ignoring
         * retransmitted single-segment PDUs (that would require storing
         * per-packet state (tcp_per_packet_data_t) to make it work for two-pass
         * and random access dissection). Retransmitted segments that are part
         * of a MSP should already be passed only once to subdissectors due to
         * the "reassembled_in" check below.
         */
        if(tcpd->ta) {
            /* Spurious Retransmission is the most obvious case to handle, just ignore it.
             * See issue 10289
             */
            if((tcpd->ta->flags&TCP_A_SPURIOUS_RETRANSMISSION) == TCP_A_SPURIOUS_RETRANSMISSION) {
                goto clean_exit;
            }
            if((tcpd->ta->flags&TCP_A_RETRANSMISSION) == TCP_A_RETRANSMISSION) {
                const char* str = "Retransmitted ";
                nbytes = tvb_reported_length_remaining(tvb, offset);
                proto_tree_add_bytes_format(tcp_tree, hf_tcp_segment_data, tvb, offset,
                    nbytes, NULL, "%sTCP segment data (%u byte%s)", str, nbytes,
                    plurality(nbytes, "", "s"));
                goto clean_exit;
            }
        }
        /* Else, find the most previous PDU starting before this sequence number */
        if (!msp) {
            msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(tcpd->fwd->multisegment_pdus, seq-1);
        }
    }

    if (reassemble_ooo && tcpd && !(tcpd->fwd->flags & TCP_FLOW_REASSEMBLE_UNTIL_FIN)) {
        if (!PINFO_FD_VISITED(pinfo)) {
            /* If there is a gap between this segment and any previous ones
             * (that is, seqno is larger than the maximum expected seqno), then
             * it is possibly an out-of-order segment. The very first segment
             * is expected to be in-order though (otherwise captures starting
             * in midst of a connection would never be reassembled).
             * (maxnextseq is 0 if we have not seen a SYN packet, even with
             * absolute sequence numbers.)
             *
             * Do not bother checking for OoO segments for streams that are
             * reassembled at FIN, the order of segments before FIN does not
             * matter as reordering and reassembly occurs at FIN.
             */

            if (tcpd->fwd->maxnextseq) {
                /* Segments may be missing due to packet loss (assume later
                 * retransmission) or out-of-order (assume it appears later).
                 *
                 * XXX: It would be nice to handle captures that have both
                 * out-of-order packets and some lost packets that are
                 * never retransmitted.
                 * follow_tcp_tap_listener uses the reverse flow's ACK to
                 * decide that missing packets will not be appearing later.
                 * Could we use that idea here too, getting the ack from
                 * tcpinfo, and using that to advance maxnextseq?
                 */

                /* Whether the new segment has a gap from our latest contiguous
                 * sequence number. */
                has_gap = LT_SEQ(tcpd->fwd->maxnextseq, seq);
            }

            if (!has_gap) {
                /* Update the maximum expected seqno if no SYN packet was seen
                 * before, or if the new segment succeeds previous segments. */
                tcpd->fwd->maxnextseq = nxtseq;

                /* If there is no gap, look for any OOO packets that are now
                 * contiguous. */
                msp = msp_add_out_of_order(pinfo, msp, tcpd, seq);
            }
        } else {
            /* If we have visited this frame before, look for the frame in the
             * list of unused out of order segments. Since we know the gap will
             * never be filled, we could pass it to the subdissector, but
             * we want to be consistent between passes.
             */
            ooo_segment_item *fd;
            fd = wmem_new0(pinfo->pool, ooo_segment_item);
            fd->frame = pinfo->num;
            fd->seq = seq;
            fd->len = nxtseq - seq;
            if (wmem_list_find_custom(tcpd->fwd->ooo_segments, fd, compare_ooo_segment_item)) {
                has_gap = TRUE;
            }
        }
    }

    if (msp && LE_SEQ(msp->seq, seq) && GT_SEQ(msp->nxtpdu, seq)) {
        int len;

        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame=pinfo->num;
            msp->last_frame_time=pinfo->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        if (msp->flags&MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /* The dissector asked for the entire segment */
            len = tvb_captured_length_remaining(tvb, offset);
        } else {
            /* Wraparound is possible, so subtraction does not
             * distribute across MIN(x, y)
             */
            len = MIN(nxtseq - seq, msp->nxtpdu - seq);
        }
        last_fragment_len = len;


        if (reassemble_ooo && tcpd && !(tcpd->fwd->flags & TCP_FLOW_REASSEMBLE_UNTIL_FIN)) {
            /*
             * If the previous segment requested more data (setting
             * FD_PARTIAL_REASSEMBLY as the next segment length is unknown), but
             * subsequently an OoO segment was received (for an earlier hole),
             * then "fragment_add" would truncate the reassembled PDU to the end
             * of this OoO segment. To prevent that, explicitly specify the MSP
             * length before calling "fragment_add".
             *
             * When a subdissector requests reassembly at the end of the
             * connection (DESEGMENT_UNTIL_FIN), then it is not
             * possible for an earlier segment to complete reassembly
             * (more_frags for fragment_add is always TRUE). Thus we do not
             * have to worry about increasing the fragment length here.
             */
            fragment_reset_tot_len(&tcp_reassembly_table, pinfo,
                                   msp->first_frame, msp,
                                   MAX(seq + len, msp->nxtpdu) - msp->seq);
        }

        ipfd_head = fragment_add(&tcp_reassembly_table, tvb, offset,
                                 pinfo, msp->first_frame, msp,
                                 seq - msp->seq, len,
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
            if (LT_SEQ(msp->nxtpdu, nxtseq)) {
                msp->nxtpdu = nxtseq;
            }
        }

        if (reassemble_ooo && !PINFO_FD_VISITED(pinfo)) {
            /* Remember when all segments are ready to avoid subsequent
             * out-of-order packets from extending this MSP. If a subsdissector
             * needs more segments, the flag will be cleared below. */
            if (ipfd_head) {
                msp->flags |= MSP_FLAGS_GOT_ALL_SEGMENTS;
            }
        }

        if( (msp->nxtpdu < nxtseq)
        &&  (msp->nxtpdu >= seq)
        &&  (len > 0)) {
            another_pdu_follows=msp->nxtpdu - seq;
        }
    } else if (has_gap) {
        /* This is an OOO segment with a gap and past the known end of
         * the current MSP, if any. We don't know for certain which MSP
         * it belongs to, and the reassembly functions don't let us remove
         * fragment items added by mistake. Keep it around in a separate
         * structure, and add it later.
         *
         * On the second and later passes, we know that this gap will
         * never be filled in, so we could hand the segment to the
         * subdissector anyway. However, we want dissection to be
         * consistent between passes.
         */
        if (!PINFO_FD_VISITED(pinfo)) {
            ooo_segment_item *fd;
            fd = wmem_new0(wmem_file_scope(), ooo_segment_item);
            fd->frame = pinfo->num;
            fd->seq = seq;
            fd->len = nxtseq - seq;
            /* We only enter here if dissect_tcp set can_desegment,
             * which means that these bytes exist. */
            fd->data = tvb_memdup(wmem_file_scope(), tvb, offset, fd->len);
            wmem_list_insert_sorted(tcpd->fwd->ooo_segments, fd, compare_ooo_segment_item);
        }
        ipfd_head = NULL;
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
                            sport, dport, 0, 0, FALSE, tcpd, tcpinfo);

        /* Unless it failed to dissect any data at all, the subdissector
         * might have changed the addresses and/or ports. Save them, and
         * set them back to the original values temporarily so that the
         * fragment functions work correctly (including in any later PDU.)
         *
         * (If we didn't dissect any data, the subdissector *shouldn't*
         * have changed the addresses or ports, so don't save them, but
         * restore them just in case.)
         */
        if (!(pinfo->desegment_len && pinfo->desegment_offset == 0)) {
            save_endpoint(pinfo, &new_endpoint);
        }
        restore_endpoint(pinfo, &orig_endpoint);
        called_dissector = TRUE;

        /* Did the subdissector ask us to desegment some more data
         * before it could handle the packet?
         * If so we'll have to handle that later.
         */
        if(pinfo->desegment_len) {
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
        if (ipfd_head->reassembled_in == pinfo->num && ipfd_head->reas_in_layer_num == pinfo->curr_layer_num) {
            /*
             * OK, this is the last segment.
             * Let's call the subdissector with the desegmented
             * data.
             */
            tvbuff_t *next_tvb;

            /* create a new TVB structure for desegmented data */
            next_tvb = tvb_new_chain(tvb, ipfd_head->tvb_data);

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
                                dport, 0, 0, FALSE, tcpd, tcpinfo);

            /* Unless it failed to dissect any data at all, the subdissector
             * might have changed the addresses and/or ports. Save them, and
             * set them back to the original values temporarily so that the
             * fragment functions work correctly (including in any later PDU.)
             *
             * (If we didn't dissect any data, the subdissector *shouldn't*
             * have changed the addresses or ports, so don't save them, but
             * restore them just in case.)
             */
            if (!(pinfo->desegment_len && pinfo->desegment_offset == 0)) {
                save_endpoint(pinfo, &new_endpoint);
            }
            restore_endpoint(pinfo, &orig_endpoint);
            called_dissector = TRUE;

            /*
             * OK, did the subdissector think it was completely
             * desegmented, or does it think we need even more
             * data?
             */
            if (reassemble_ooo && !PINFO_FD_VISITED(pinfo) && pinfo->desegment_len) {
                /* "desegment_len" isn't 0, so it needs more data to extend the MSP. */
                msp->flags &= ~MSP_FLAGS_GOT_ALL_SEGMENTS;
            }
            if (pinfo->desegment_len) {
                /*
                 * "desegment_len" isn't 0, so it needs more data
                 * to fully dissect the current MSP. msp->nxtpdu was
                 * not accurate and needs to be updated.
                 *
                 * This can happen if a dissector asked for one
                 * more segment (but didn't know exactly how much data)
                 * or if segments were added out of order.
                 *
                 * This is opposed to the current MSP being completely
                 * desegmented, but the stuff at the end of the
                 * current frame past last_fragment_len starting a new
                 * higher-level PDU that may also need desegmentation.
                 * That case is handled on the next loop.
                 *
                 * We want to keep the same dissection and protocol layer
                 * numbers on subsequent passes.
                 *
                 * If "desegment_offset" is 0, then nothing in the reassembled
                 * TCP segments was dissected, so remove the data source.
                 * XXX: We should also remove any layers that were added to
                 * keep things consistent, because we won't call the
                 * subdissector here on subsequent passes.
                 */
                if (pinfo->desegment_offset == 0) {
                    remove_last_data_source(pinfo);
                    fragment_set_partial_reassembly(&tcp_reassembly_table,
                                                    pinfo, msp->first_frame,
                                                    msp);
                } else {
                    /* If "desegment_offset" is not 0, then a PDU in the
                     * reassembled segments was dissected, but some stuff
                     * that was added previously is part of a later PDU.
                     */
                    if (LE_SEQ(msp->seq + pinfo->desegment_offset, seq)) {
                        /* If we don't use anything from the current frame's
                         * segment, then we can't split the msp. The frames of
                         * the earlier PDU weren't reassembled until now, so
                         * they need to point to a reassembled_in frame here
                         * or later.
                         *
                         * Since this segment is the first of newly contiguous
                         * segments, this means the subdissector is asking for
                         * fewer bytes than it did before.
                         * XXX: Report this as a dissector bug?
                         */
                        fragment_set_partial_reassembly(&tcp_reassembly_table,
                                                        pinfo, msp->first_frame,
                                                        msp);
                    } else {
                        /* If we did use bytes from the current segment, then
                         * we want to split the MSP; the earlier part is
                         * dissected in this frame on the first pass, so for
                         * consistency we want to do so on future passes, but
                         * the latter part we cannot dissect until later.
                         * We only need to do this on the first pass; split_msp
                         * truncates the msp so we don't get here a second
                         * time.
                         */
                        /* nxtpdu adjustment for the new msp is the same. */
                        if (!PINFO_FD_VISITED(pinfo)) {
                            msp = split_msp(pinfo, msp, tcpd);
                        }
                        print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);
                    }
                }

                if (!PINFO_FD_VISITED(pinfo)) {
                    /* Update msp->nxtpdu to point to the new next
                     * pdu boundary.
                     * We only do this on the first pass, though we shouldn't
                     * get here on a second pass (since we truncated the msp.)
                     */
                    if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                        /* We want reassembly of at least one
                         * more segment so set the nxtpdu
                         * boundary to one byte into the next
                         * segment.
                         * This means that the next segment
                         * will complete reassembly even if it
                         * is only one single byte in length.
                         * If this is an OoO segment, then increment
                         * the MSP end.
                         */
                        msp->nxtpdu = MAX(seq + tvb_reported_length_remaining(tvb, offset), msp->nxtpdu) + 1;
                        msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
                    } else if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                        tcpd->fwd->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
                        /* This is not the first segment, and we thought the
                         * reassembly would be done now, but now know we must
                         * desgment until FIN. (E.g., HTTP Response with headers
                         * split across segments, and no Content-Length or
                         * Transfer-Encoding (RFC 7230, Section 3.3.3, case 7.)
                         * For the same reasons as below when we encounter
                         * DESEGMENT_UNTIL_FIN on the first segment, give
                         * msp->nxtpdu a big (but not too big) offset so
                         * reassembly will pick up the segments later.
                         */
                        msp->nxtpdu = msp->seq + 0x40000000;
                    } else {
                        if (seq + last_fragment_len >= msp->nxtpdu) {
                            /* This is the segment (overlapping) the end of
                             * the MSP.
                             */
                            msp->nxtpdu = seq + last_fragment_len + pinfo->desegment_len;
                        } else {
                            /* This is a segment before the end of the MSP, so
                             * it must be an out-of-order segment that completed
                             * the MSP. The requested additional data is
                             * relative to that end.
                             */
                            msp->nxtpdu += pinfo->desegment_len;
                        }
                    }
                }

                /* Since we need at least some more data
                 * there can be no pdu following in the
                 * tail of this segment.
                 */
                another_pdu_follows = 0;
                offset += last_fragment_len;
                seq += last_fragment_len;
                if (tvb_captured_length_remaining(tvb, offset) > 0)
                    goto again;
            } else {
                /*
                 * Show the stuff in this TCP segment as
                 * just raw TCP segment data.
                 */
                nbytes = another_pdu_follows > 0
                    ? another_pdu_follows
                    : tvb_reported_length_remaining(tvb, offset);
                proto_tree_add_bytes_format(tcp_tree, hf_tcp_segment_data, tvb, offset,
                    nbytes, NULL, "TCP segment data (%u byte%s)", nbytes,
                    plurality(nbytes, "", "s"));

                print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);
            }
        }
    }

    if (must_desegment) {
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

        /* We have to create some structures in our table but
         * this is something we only do the first time we see this
         * packet. */
        if (!PINFO_FD_VISITED(pinfo)) {
            /* If the dissector requested "reassemble until FIN"
             * just set this flag for the flow and let reassembly
             * proceed at normal.  We will check/pick up these
             * reassembled PDUs later down in dissect_tcp() when checking
             * for the FIN flag.
             */
            if (tcpd && pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                tcpd->fwd->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
            }
            if (tcpd && ((nxtseq - deseg_seq) <= 1024*1024)) {
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
                } else if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                    /*
                     * The subdissector asked to reassemble at the end of the
                     * connection. That will be done in dissect_tcp, but here we
                     * have to ask reassembly to collect all future segments.
                     * Note that TCP_FLOW_REASSEMBLE_UNTIL_FIN was set before,
                     * this ensures that OoO detection is skipped.
                     * The exact nxtpdu offset does not matter, but it should be
                     * smaller than half of the maximum 32-bit unsigned integer
                     * to allow detection of sequence number wraparound, and
                     * larger than the largest possible stream size. Hopefully
                     * 1GiB (0x40000000 bytes) should be enough.
                     */
                    msp = pdu_store_sequencenumber_of_next_pdu(pinfo, deseg_seq,
                        nxtseq+0x40000000, tcpd->fwd->multisegment_pdus);
                } else {
                    msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                        deseg_seq, nxtseq+pinfo->desegment_len, tcpd->fwd->multisegment_pdus);
                }

                /* add this segment as the first one for this new pdu */
                fragment_add(&tcp_reassembly_table, tvb, deseg_offset,
                             pinfo, msp->first_frame, msp,
                             0, nxtseq - deseg_seq,
                             LT_SEQ(nxtseq, msp->nxtpdu));
            }
        } else {
            /* If this is not the first time we have seen the packet, then
             * the MSP should already be created. Retrieve it to see if we
             * know what later frame the PDU is reassembled in.
             */
            if (tcpd && (msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32(tcpd->fwd->multisegment_pdus, deseg_seq))) {
                    ipfd_head = fragment_get(&tcp_reassembly_table, pinfo, msp->first_frame, msp);
            }
        }
    }

    if (!called_dissector || pinfo->desegment_len != 0) {
        if (ipfd_head != NULL && ipfd_head->reassembled_in != 0 &&
            ipfd_head->reassembled_in != pinfo->num &&
            !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
            /*
             * We know what other frame this PDU is reassembled in;
             * let the user know.
             */
            item = proto_tree_add_uint(tcp_tree, hf_tcp_reassembled_in, tvb, 0,
                                       0, ipfd_head->reassembled_in);
            proto_item_set_generated(item);
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
            if (first_pdu) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[TCP segment of a reassembled PDU]");
            }
        }

        /*
         * Show what's left in the packet as just raw TCP segment
         * data. (It's possible that another PDU follows in the case
         * of an out of order frame that is part of two MSPs.)
         * XXX - remember what protocol the last subdissector
         * was, and report it as a continuation of that, instead?
         */
        nbytes = another_pdu_follows ? another_pdu_follows : tvb_reported_length_remaining(tvb, deseg_offset);

        proto_tree_add_bytes_format(tcp_tree, hf_tcp_segment_data, tvb, deseg_offset,
            nbytes, NULL, "TCP segment data (%u byte%s)", nbytes,
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
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
        cleared_writable |= col_get_writable(pinfo->cinfo, COL_PROTOCOL);
        col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);
        first_pdu = FALSE;
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    } else {
        /* remove any blocking set above otherwise the
         * proto,colinfo tap will break
         */
        if(cleared_writable) {
            col_set_writable(pinfo->cinfo, COL_PROTOCOL, TRUE);
        }
    }

clean_exit:
    /* Restore the addresses and ports to whatever they were after
     * the last segment that successfully dissected some data, if any.
     */
    restore_endpoint(pinfo, &new_endpoint);
}

void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 gboolean proto_desegment, guint fixed_len,
                 guint (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
                 dissector_t dissect_pdu, void* dissector_data)
{
    volatile int offset = 0;
    int offset_before;
    guint captured_length_remaining;
    volatile guint plen;
    guint length;
    tvbuff_t *next_tvb;
    proto_item *item=NULL;
    const char *saved_proto;
    guint8 curr_layer_num;
    wmem_list_frame_t *frame;

    tcp_endpoint_t orig_endpoint;

    save_endpoint(pinfo, &orig_endpoint);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /*
         * We use "tvb_ensure_captured_length_remaining()" to make
         * sure there actually *is* data remaining.  The protocol
         * we're handling could conceivably consists of a sequence of
         * fixed-length PDUs, and therefore the "get_pdu_len" routine
         * might not actually fetch anything from the tvbuff, and thus
         * might not cause an exception to be thrown if we've run past
         * the end of the tvbuff.
         *
         * This means we're guaranteed that "captured_length_remaining" is positive.
         */
        captured_length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

        /*
         * Can we do reassembly?
         */
        if (proto_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the fixed-length part of the PDU split across segment
             * boundaries?
             */
            if (captured_length_remaining < fixed_len) {
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
        plen = (*get_pdu_len)(pinfo, tvb, offset, dissector_data);
        if (plen == 0) {
            /*
             * Support protocols which have a variable length which cannot
             * always be determined within the given fixed_len.
             */
            /*
             * If another segment was requested but we can't do reassembly,
             * abort and warn about the unreassembled packet.
             */
            THROW_ON(!(proto_desegment && pinfo->can_desegment), FragmentBoundsError);
            /*
             * Tell the TCP dissector where the data for this message
             * starts in the data it handed us, and that we need one
             * more segment, and return.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return;
        }
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

        /* give a hint to TCP where the next PDU starts
         * so that it can attempt to find it in case it starts
         * somewhere in the middle of a segment.
         */
        if(!pinfo->fd->visited && tcp_analyze_seq) {
            guint remaining_bytes;
            remaining_bytes = tvb_reported_length_remaining(tvb, offset);
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
            if (captured_length_remaining < plen) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us, and how many more bytes we
                 * need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = plen - captured_length_remaining;
                return;
            }
        }

        curr_layer_num = pinfo->curr_layer_num-1;
        frame = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
        while (frame && (proto_tcp != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame)))) {
            frame = wmem_list_frame_prev(frame);
            curr_layer_num--;
        }
#if 0
        if (captured_length_remaining >= plen || there are more packets)
        {
#endif
                /*
                 * Display the PDU length as a field
                 */
                item=proto_tree_add_uint((proto_tree *)p_get_proto_data(pinfo->pool, pinfo, proto_tcp, curr_layer_num),
                                         hf_tcp_pdu_size,
                                         tvb, offset, plen, plen);
                proto_item_set_generated(item);
#if 0
        } else {
                item = proto_tree_add_expert_format((proto_tree *)p_get_proto_data(pinfo->pool, pinfo, proto_tcp, curr_layer_num),
                                        tvb, offset, -1,
                    "PDU Size: %u cut short at %u",plen,captured_length_remaining);
                proto_item_set_generated(item);
        }
#endif

        /*
         * Construct a tvbuff containing the amount of the payload we have
         * available.  Make its reported length the amount of data in the PDU.
         */
        length = captured_length_remaining;
        if (length > plen)
            length = plen;
        next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, plen);
        if (!(proto_desegment && pinfo->can_desegment)) {
            if (plen > length) {
                /* If we can't do reassembly but the PDU is split across
                 * segment boundaries, mark the tvbuff as a fragment so
                 * we throw FragmentBoundsError instead of malformed
                 * errors.
                 */
                tvb_set_fragment(next_tvb);
            }
        }


        /*
         * Dissect the PDU.
         *
         * If it gets an error that means there's no point in
         * dissecting any more PDUs, rethrow the exception in
         * question.
         *
         * If it gets any other error, report it and continue, as that
         * means that PDU got an error, but that doesn't mean we should
         * stop dissecting PDUs within this frame or chunk of reassembled
         * data.
         */
        saved_proto = pinfo->current_proto;
        restore_endpoint(pinfo, &orig_endpoint);
        TRY {
            (*dissect_pdu)(next_tvb, pinfo, tree, dissector_data);
        }
        CATCH_NONFATAL_ERRORS {
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);

            /*
             * Restore the saved protocol as well; we do this after
             * show_exception(), so that the "Malformed packet" indication
             * shows the protocol for which dissection failed.
             */
            pinfo->current_proto = saved_proto;
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
    /* fstr(" %s=%u", abbrev, val) */
    col_append_str_uint(pinfo->cinfo, COL_INFO, abbrev, val, " ");
}

static gboolean
tcp_option_len_check(proto_item* length_item, packet_info *pinfo, guint len, guint optlen)
{
    if (len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        expert_add_info_format(pinfo, length_item, &ei_tcp_opt_len_invalid,
                               "option length should be %u", optlen);
        return FALSE;
    }

    return TRUE;
}

static int
dissect_tcpopt_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;
    int offset = 0, optlen = tvb_reported_length(tvb);

    item = proto_tree_add_item(tree, proto_tcp_option_unknown, tvb, offset, -1, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett_tcp_unknown_opt);

    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    if (optlen > 2)
        proto_tree_add_item(exp_tree, hf_tcp_option_unknown_payload, tvb, offset + 2, optlen - 2, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_default_option(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto, int ett)
{
    proto_item *item;
    proto_tree *exp_tree;
    proto_item *length_item;
    int offset = 0;

    item = proto_tree_add_item(tree, proto, tvb, offset, -1, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett);

    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), 2))
        return tvb_captured_length(tvb);

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_recbound(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_tcpopt_default_option(tvb, pinfo, tree, proto_tcp_option_scpsrec, ett_tcp_opt_recbound);
}

static int
dissect_tcpopt_correxp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_tcpopt_default_option(tvb, pinfo, tree, proto_tcp_option_scpscor, ett_tcp_opt_scpscor);
}

static void
dissect_tcpopt_tfo_payload(tvbuff_t *tvb, int offset, guint optlen,
    packet_info *pinfo, proto_tree *exp_tree, void *data)
{
    proto_item *ti;
    struct tcpheader *tcph = (struct tcpheader*)data;
    struct tcp_analysis *tcpd;

    if (optlen == 2) {
        /* Fast Open Cookie Request */
        proto_tree_add_item(exp_tree, hf_tcp_option_fast_open_cookie_request,
                            tvb, offset, 2, ENC_NA);
        col_append_str(pinfo->cinfo, COL_INFO, " TFO=R");
    } else if (optlen > 2) {
        /* Fast Open Cookie */
        ti = proto_tree_add_item(exp_tree, hf_tcp_option_fast_open_cookie,
                            tvb, offset + 2, optlen - 2, ENC_NA);
        col_append_str(pinfo->cinfo, COL_INFO, " TFO=C");
        if ((tcph->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) {
            expert_add_info(pinfo, ti, &ei_tcp_analysis_tfo_syn);

            /* Is this a SYN with data and the cookie? */
            if (tcph->th_have_seglen && tcph->th_seglen) {
                tcpd = get_tcp_conversation_data(NULL, pinfo);
                if (tcpd) {
                    tcpd->tfo_syn_data = 1;
                }
            }
        }
    }
}

static int
dissect_tcpopt_tfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;
    int offset = 0;

    item = proto_tree_add_item(tree, proto_tcp_option_tfo, tvb, offset, -1, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_exp);
    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    dissect_tcpopt_tfo_payload(tvb, offset, tvb_reported_length(tvb), pinfo, exp_tree, data);
    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_exp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;
    guint16 magic;
    gint offset = 0, optlen = tvb_reported_length(tvb);

    item = proto_tree_add_item(tree, proto_tcp_option_exp, tvb, offset, -1, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_exp);

    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    if (tcp_exp_options_with_magic && ((optlen - 2) > 0)) {
        magic = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_item(exp_tree, hf_tcp_option_exp_magic_number, tvb,
                            offset + 2, 2, ENC_BIG_ENDIAN);
        switch (magic) {
        case 0xf989:  /* RFC7413, TCP Fast Open */
            dissect_tcpopt_tfo_payload(tvb, offset+2, optlen-2, pinfo, exp_tree, data);
            break;
        default:
            /* Unknown magic number */
            break;
        }
    } else {
        proto_tree_add_item(exp_tree, hf_tcp_option_exp_data, tvb,
                            offset + 2, optlen - 2, ENC_NA);
        tcp_info_append_uint(pinfo, "Expxx", TRUE);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_sack_perm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;
    proto_item *length_item;
    int offset = 0;

    item = proto_tree_add_item(tree, proto_tcp_option_sack_perm, tvb, offset, -1, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_sack_perm);

    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    tcp_info_append_uint(pinfo, "SACK_PERM", TRUE);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_SACK_PERM))
        return tvb_captured_length(tvb);

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_mss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *item;
    proto_tree *exp_tree;
    proto_item *length_item;
    int offset = 0;
    struct tcpheader *tcph = (struct tcpheader *)data;
    guint32 mss;

    item = proto_tree_add_item(tree, proto_tcp_option_mss, tvb, offset, -1, ENC_NA);
    exp_tree = proto_item_add_subtree(item, ett_tcp_option_mss);

    if (!(tcph->th_flags & TH_SYN))
    {
        expert_add_info(pinfo, item, &ei_tcp_option_mss_present);
    }

    proto_tree_add_item(exp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(exp_tree, hf_tcp_option_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_MSS))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(exp_tree, hf_tcp_option_mss_val, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &mss);
    proto_item_append_text(item, ": %u bytes", mss);
    tcp_info_append_uint(pinfo, "MSS", mss);

    return tvb_captured_length(tvb);
}

/* The window scale extension is defined in RFC 1323 */
static int
dissect_tcpopt_wscale(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8 val;
    guint32 shift;
    proto_item *wscale_pi, *shift_pi, *gen_pi;
    proto_tree *wscale_tree;
    proto_item *length_item;
    int offset = 0;
    struct tcp_analysis *tcpd;

    tcpd=get_tcp_conversation_data(NULL,pinfo);

    wscale_pi = proto_tree_add_item(tree, proto_tcp_option_wscale, tvb, offset, -1, ENC_NA);
    wscale_tree = proto_item_add_subtree(wscale_pi, ett_tcp_option_wscale);

    proto_tree_add_item(wscale_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    length_item = proto_tree_add_item(wscale_tree, hf_tcp_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_WINDOW))
        return tvb_captured_length(tvb);

    shift_pi = proto_tree_add_item_ret_uint(wscale_tree, hf_tcp_option_wscale_shift, tvb, offset, 1, ENC_BIG_ENDIAN, &shift);
    if (shift > 14) {
        /* RFC 1323: "If a Window Scale option is received with a shift.cnt
         * value exceeding 14, the TCP should log the error but use 14 instead
         * of the specified value." */
        shift = 14;
        expert_add_info(pinfo, shift_pi, &ei_tcp_option_wscale_shift_invalid);
    }

    gen_pi = proto_tree_add_uint(wscale_tree, hf_tcp_option_wscale_multiplier, tvb,
                                 offset, 1, 1 << shift);
    proto_item_set_generated(gen_pi);
    val = tvb_get_guint8(tvb, offset);

    proto_item_append_text(wscale_pi, ": %u (multiply by %u)", val, 1 << shift);

    tcp_info_append_uint(pinfo, "WS", 1 << shift);

    if(!pinfo->fd->visited) {
        pdu_store_window_scale_option(shift, tcpd);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_sack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree *field_tree = NULL;
    proto_item *tf, *ti;
    guint32 leftedge, rightedge;
    struct tcp_analysis *tcpd=NULL;
    struct tcpheader *tcph = (struct tcpheader *)data;
    guint32 base_ack=0;
    guint  num_sack_ranges = 0;
    int offset = 0;
    int sackoffset;
    int optlen = tvb_reported_length(tvb);

    /*
     * SEQ analysis is the condition for both relative analysis obviously,
     * and SACK handling for the in-flight update
     */
    if(tcp_analyze_seq) {
        /* find(or create if needed) the conversation for this tcp session */
        tcpd=get_tcp_conversation_data(NULL,pinfo);

        if (tcpd) {
            if (tcp_relative_seq) {
                base_ack=tcpd->rev->base_seq;
            }

            /*
             * initialize the number of SACK blocks to 0, it will be
             * updated some lines later
             */
            if (tcp_track_bytes_in_flight && tcpd->fwd->tcp_analyze_seq_info) {
                tcpd->fwd->tcp_analyze_seq_info->num_sack_ranges = 0;
            }
        }
    }

    ti = proto_tree_add_item(tree, proto_tcp_option_sack, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(ti, ett_tcp_option_sack);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);

    offset += 2;    /* skip past type and length */
    optlen -= 2;    /* subtract size of type and length */

    sackoffset = offset;
    while (optlen > 0) {
        if (optlen < 4) {
            proto_tree_add_expert(field_tree, pinfo, &ei_tcp_suboption_malformed, tvb, offset, optlen);
            break;
        }
        leftedge = tvb_get_ntohl(tvb, offset)-base_ack;
        proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_sle, tvb,
                                   offset, 4, leftedge,
                                   "left edge = %u%s", leftedge,
                                   (tcp_analyze_seq && tcp_relative_seq) ? " (relative)" : "");
        optlen -= 4;
        if (optlen < 4) {
            proto_tree_add_expert(field_tree, pinfo, &ei_tcp_suboption_malformed, tvb, offset, optlen);
            break;
        }
        /* XXX - check whether it goes past end of packet */
        rightedge = tvb_get_ntohl(tvb, offset + 4)-base_ack;
        optlen -= 4;
        proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_sre, tvb,
                                   offset+4, 4, rightedge,
                                   "right edge = %u%s", rightedge,
                                   (tcp_analyze_seq && tcp_relative_seq) ? " (relative)" : "");
        tcp_info_append_uint(pinfo, "SLE", leftedge);
        tcp_info_append_uint(pinfo, "SRE", rightedge);
        num_sack_ranges++;

        /* Store blocks for BiF analysis */
        if (tcp_analyze_seq && tcpd->fwd->tcp_analyze_seq_info && tcp_track_bytes_in_flight && num_sack_ranges < MAX_TCP_SACK_RANGES) {
            tcpd->fwd->tcp_analyze_seq_info->num_sack_ranges = num_sack_ranges;
            tcpd->fwd->tcp_analyze_seq_info->sack_left_edge[num_sack_ranges] = leftedge;
            tcpd->fwd->tcp_analyze_seq_info->sack_right_edge[num_sack_ranges] = rightedge;
        }

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
    proto_item_set_generated(tf);

    /* RFC 2883 "An Extension to the Selective Acknowledgement (SACK) Option for TCP" aka "D-SACK"
     * Section 4
     *   Conditions: Either the first sack-block is inside the already acknowledged range or
     *               the first sack block is inside the second sack block.
     *
     * Maybe add later:
     * (1) A D-SACK block is only used to report a duplicate contiguous sequence of data received by
     *     the receiver in the most recent packet.
     */
    if (LE_SEQ(tcph->sack_right_edge[0], tcph->th_ack) ||
         (tcph->num_sack_ranges > 1 &&
          LT_SEQ(tcph->sack_left_edge[1], tcph->sack_right_edge[0]) &&
          GE_SEQ(tcph->sack_right_edge[1], tcph->sack_right_edge[0]))
    ) {
        leftedge = tvb_get_ntohl(tvb, sackoffset)-base_ack;
        tf = proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_dsack_le, tvb, sackoffset, 4, leftedge,
            "D-SACK Left Edge = %u%s", leftedge, (tcp_analyze_seq && tcp_relative_seq) ? " (relative)" : "");
        proto_item_set_generated(tf);
        rightedge = tvb_get_ntohl(tvb, sackoffset+4)-base_ack;
        tf = proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_dsack_re, tvb, sackoffset+4, 4, rightedge,
            "D-SACK Right Edge = %u%s", rightedge, (tcp_analyze_seq && tcp_relative_seq) ? " (relative)" : "");
        proto_item_set_generated(tf);
        proto_tree_add_expert(field_tree, pinfo, &ei_tcp_option_sack_dsack, tvb, sackoffset, 8);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *item;
    proto_item *length_item;
    guint32 echo;
    int offset = 0;

    item = proto_tree_add_item(tree, proto_tcp_option_echo, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(item, ett_tcp_opt_echo);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_ECHO))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_tcp_option_echo, tvb,
                        offset + 2, 4, ENC_BIG_ENDIAN, &echo);

    proto_item_append_text(item, ": %u", echo);
    tcp_info_append_uint(pinfo, "ECHO", echo);

    return tvb_captured_length(tvb);
}

/* If set, do not put the TCP timestamp information on the summary line */
static gboolean tcp_ignore_timestamps = FALSE;

static int
dissect_tcpopt_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ts_tree;
    proto_item *length_item;
    int offset = 0;
    guint32 ts_val, ts_ecr;
    int len = tvb_reported_length(tvb);

    ti = proto_tree_add_item(tree, proto_tcp_option_timestamp, tvb, offset, -1, ENC_NA);
    ts_tree = proto_item_add_subtree(ti, ett_tcp_option_timestamp);

    proto_tree_add_item(ts_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    length_item = proto_tree_add_item(ts_tree, hf_tcp_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (!tcp_option_len_check(length_item, pinfo, len, TCPOLEN_TIMESTAMP))
        return tvb_captured_length(tvb);

    ti = proto_tree_add_item_ret_uint(ts_tree, hf_tcp_option_timestamp_tsval, tvb, offset,
                        4, ENC_BIG_ENDIAN, &ts_val);

    proto_tree_add_item_ret_uint(ts_tree, hf_tcp_option_timestamp_tsecr, tvb, offset + 4,
                        4, ENC_BIG_ENDIAN, &ts_ecr);

    proto_item_append_text(ti, ": TSval %u, TSecr %u", ts_val, ts_ecr);
    if (tcp_ignore_timestamps == FALSE) {
        tcp_info_append_uint(pinfo, "TSval", ts_val);
        tcp_info_append_uint(pinfo, "TSecr", ts_ecr);
    }

    if (read_seq_as_syn_cookie) {
      proto_item_append_text(ti, " (syn cookie)");
      proto_item* syncookie_ti = proto_item_add_subtree(ti, ett_tcp_syncookie_option);
      guint32 timestamp = tvb_get_bits32(tvb, offset * 8, 26, ENC_NA) << 6;
      proto_tree_add_uint_bits_format_value(syncookie_ti, hf_tcp_syncookie_option_timestamp, tvb, offset * 8,
        26, timestamp, ENC_TIME_SECS, "%s", abs_time_secs_to_str(wmem_packet_scope(), timestamp, ABSOLUTE_TIME_LOCAL, TRUE));
      proto_tree_add_bits_item(syncookie_ti, hf_tcp_syncookie_option_ecn, tvb, offset * 8 + 26, 1, ENC_NA);
      proto_tree_add_bits_item(syncookie_ti, hf_tcp_syncookie_option_sack, tvb, offset * 8 + 27, 1, ENC_NA);
      proto_tree_add_bits_item(syncookie_ti, hf_tcp_syncookie_option_wscale, tvb, offset * 8 + 28, 4, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static struct mptcp_analysis*
mptcp_alloc_analysis(struct tcp_analysis* tcpd) {

    struct mptcp_analysis* mptcpd;

    DISSECTOR_ASSERT(tcpd->mptcp_analysis == 0);

    mptcpd = (struct mptcp_analysis*)wmem_new0(wmem_file_scope(), struct mptcp_analysis);
    mptcpd->subflows = wmem_list_new(wmem_file_scope());

    mptcpd->stream = mptcp_stream_count++;
    tcpd->mptcp_analysis = mptcpd;

    memset(&mptcpd->meta_flow, 0, 2*sizeof(mptcp_meta_flow_t));

    /* arbitrary assignment. Callers may override this */
    tcpd->fwd->mptcp_subflow->meta = &mptcpd->meta_flow[0];
    tcpd->rev->mptcp_subflow->meta = &mptcpd->meta_flow[1];

    return mptcpd;
}


/* will create necessary structure if fails to find a match on the token */
static struct mptcp_analysis*
mptcp_get_meta_from_token(struct tcp_analysis* tcpd, tcp_flow_t *tcp_flow, guint32 token) {

    struct mptcp_analysis* result = NULL;
    struct mptcp_analysis* mptcpd = tcpd->mptcp_analysis;
    guint8 assignedMetaId = 0;  /* array id < 2 */

    DISSECTOR_ASSERT(tcp_flow == tcpd->fwd || tcp_flow == tcpd->rev);



    /* if token already set for this meta */
    if( tcp_flow->mptcp_subflow->meta  && (tcp_flow->mptcp_subflow->meta->static_flags & MPTCP_META_HAS_TOKEN)) {
        return mptcpd;
    }

    /* else look for a registered meta with this token */
    result = (struct mptcp_analysis*)wmem_tree_lookup32(mptcp_tokens, token);

    /* if token already registered than just share it across TCP connections */
    if(result) {
        mptcpd = result;
        mptcp_attach_subflow(mptcpd, tcpd);
    }
    else {
        /* we create it if this connection */
        if(!mptcpd) {
            /* don't care which meta to choose assign each meta to a direction */
            mptcpd = mptcp_alloc_analysis(tcpd);
            mptcp_attach_subflow(mptcpd, tcpd);
        }
        else {

            /* already exists, thus some meta may already have been configured */
            if(mptcpd->meta_flow[0].static_flags & MPTCP_META_HAS_TOKEN) {
                assignedMetaId = 1;
            }
            else if(mptcpd->meta_flow[1].static_flags & MPTCP_META_HAS_TOKEN) {
                assignedMetaId = 0;
            }
            else {
                DISSECTOR_ASSERT_NOT_REACHED();
            }
            tcp_flow->mptcp_subflow->meta = &mptcpd->meta_flow[assignedMetaId];
        }
        DISSECTOR_ASSERT(tcp_flow->mptcp_subflow->meta);

        tcp_flow->mptcp_subflow->meta->token = token;
        tcp_flow->mptcp_subflow->meta->static_flags |= MPTCP_META_HAS_TOKEN;

        wmem_tree_insert32(mptcp_tokens, token, mptcpd);
    }

    DISSECTOR_ASSERT(mptcpd);


    /* compute the meta id assigned to tcp_flow */
    assignedMetaId = (tcp_flow->mptcp_subflow->meta == &mptcpd->meta_flow[0]) ? 0 : 1;

    /* computes the metaId tcpd->fwd should be assigned to */
    assignedMetaId = (tcp_flow == tcpd->fwd) ? assignedMetaId : (assignedMetaId +1) %2;

    tcpd->fwd->mptcp_subflow->meta = &mptcpd->meta_flow[ (assignedMetaId) ];
    tcpd->rev->mptcp_subflow->meta = &mptcpd->meta_flow[ (assignedMetaId +1) %2];

    return mptcpd;
}

/* setup from_key */
static
struct mptcp_analysis*
get_or_create_mptcpd_from_key(struct tcp_analysis* tcpd, tcp_flow_t *fwd, guint8 version, guint64 key, guint8 hmac_algo _U_) {

    guint32 token = 0;
    guint64 expected_idsn= 0;
    struct mptcp_analysis* mptcpd = tcpd->mptcp_analysis;

    if(fwd->mptcp_subflow->meta && (fwd->mptcp_subflow->meta->static_flags & MPTCP_META_HAS_KEY)) {
        return mptcpd;
    }

    /* MPTCP v0 only standardizes SHA1, and v1 SHA256. */
    if (version == 0)
        mptcp_cryptodata_sha1(key, &token, &expected_idsn);
    else if (version == 1)
        mptcp_cryptodata_sha256(key, &token, &expected_idsn);

    mptcpd = mptcp_get_meta_from_token(tcpd, fwd, token);

    DISSECTOR_ASSERT(fwd->mptcp_subflow->meta);

    fwd->mptcp_subflow->meta->version = version;
    fwd->mptcp_subflow->meta->key = key;
    fwd->mptcp_subflow->meta->static_flags |= MPTCP_META_HAS_KEY;
    fwd->mptcp_subflow->meta->base_dsn = expected_idsn;
    return mptcpd;
}

/* record this mapping */
static
void analyze_mapping(struct tcp_analysis *tcpd, packet_info *pinfo, guint16 len, guint64 dsn, gboolean extended, guint32 ssn) {

    /* store mapping only if analysis is enabled and mapping is not unlimited */
    if (!mptcp_analyze_mappings || !len) {
        return;
    }

    if (PINFO_FD_VISITED(pinfo)) {
        return;
    }

    /* register SSN range described by the mapping into a subflow interval_tree */
    mptcp_dss_mapping_t *mapping = NULL;
    mapping = wmem_new0(wmem_file_scope(), mptcp_dss_mapping_t);

    mapping->rawdsn  = dsn;
    mapping->extended_dsn = extended;
    mapping->frame = pinfo->fd->num;
    mapping->ssn_low = ssn;
    mapping->ssn_high = ssn + len - 1;

    wmem_itree_insert(tcpd->fwd->mptcp_subflow->ssn2dsn_mappings,
        mapping->ssn_low,
        mapping->ssn_high,
        mapping
        );
}

/*
 * The TCP Extensions for Multipath Operation with Multiple Addresses
 * are defined in RFC 6824
 *
 * https://tools.ietf.org/html/rfc6824
 *
 * Author: Andrei Maruseac <andrei.maruseac@intel.com>
 *         Matthieu Coudron <matthieu.coudron@lip6.fr>
 *
 * This function just generates the mptcpheader, i.e. the generation of
 * datastructures is delayed/delegated to mptcp_analyze
 */
static int
dissect_tcpopt_mptcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *item,*main_item;
    proto_tree *mptcp_tree;

    guint32 version;
    guint8 subtype;
    guint8 ipver;
    int offset = 0;
    int optlen = tvb_reported_length(tvb);
    int start_offset = offset;
    struct tcp_analysis *tcpd = NULL;
    struct mptcp_analysis* mptcpd = NULL;
    struct tcpheader *tcph = (struct tcpheader *)data;

    /* There may be several MPTCP options per packet, don't duplicate the structure */
    struct mptcpheader* mph = tcph->th_mptcp;

    if(!mph) {
        mph = wmem_new0(pinfo->pool, struct mptcpheader);
        tcph->th_mptcp = mph;
    }

    tcpd=get_tcp_conversation_data(NULL,pinfo);
    mptcpd=tcpd->mptcp_analysis;

    /* seeing an MPTCP packet on the subflow automatically qualifies it as an mptcp subflow */
    if(!tcpd->fwd->mptcp_subflow) {
         mptcp_init_subflow(tcpd->fwd);
    }
    if(!tcpd->rev->mptcp_subflow) {
         mptcp_init_subflow(tcpd->rev);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPTCP");
    main_item = proto_tree_add_item(tree, proto_mptcp, tvb, offset, -1, ENC_NA);
    mptcp_tree = proto_item_add_subtree(main_item, ett_tcp_option_mptcp);

    proto_tree_add_item(mptcp_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mptcp_tree, hf_tcp_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_subtype, tvb,
                        offset, 1, ENC_BIG_ENDIAN);

    subtype = tvb_get_guint8(tvb, offset) >> 4;
    proto_item_append_text(main_item, ": %s", val_to_str(subtype, mptcp_subtype_vs, "Unknown (%d)"));

    /** preemptively allocate mptcpd when subtype won't allow to find a meta */
    if(!mptcpd && (subtype > TCPOPT_MPTCP_MP_JOIN)) {
        mptcpd = mptcp_alloc_analysis(tcpd);
    }

    switch (subtype) {
        case TCPOPT_MPTCP_MP_CAPABLE:
            mph->mh_mpc = TRUE;

            proto_tree_add_item_ret_uint(mptcp_tree, hf_tcp_option_mptcp_version, tvb,
                        offset, 1, ENC_BIG_ENDIAN, &version);
            offset += 1;

            item = proto_tree_add_bitmask(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_flags,
                         ett_tcp_option_mptcp,
                         version == 1 ? tcp_option_mptcp_capable_v1_flags : tcp_option_mptcp_capable_v0_flags,
                         ENC_BIG_ENDIAN);
            mph->mh_capable_flags = tvb_get_guint8(tvb, offset);
            if ((mph->mh_capable_flags & MPTCP_CAPABLE_CRYPTO_MASK) == 0) {
                expert_add_info(pinfo, item, &ei_mptcp_analysis_missing_algorithm);
            }
            if ((mph->mh_capable_flags & MPTCP_CAPABLE_CRYPTO_MASK) != MPTCP_HMAC_SHA) {
                expert_add_info(pinfo, item, &ei_mptcp_analysis_unsupported_algorithm);
            }
            offset += 1;

            /* optlen == 12 => SYN or SYN/ACK; optlen == 20 => ACK;
             * optlen == 22 => ACK + data (v1 only);
             * optlen == 24 => ACK + data + csum (v1 only)
             */
            if (optlen == 12 || optlen == 20 || optlen == 22 || optlen == 24) {

                mph->mh_key = tvb_get_ntoh64(tvb,offset);
                proto_tree_add_uint64(mptcp_tree, hf_tcp_option_mptcp_sender_key, tvb, offset, 8, mph->mh_key);
                offset += 8;

                mptcpd = get_or_create_mptcpd_from_key(tcpd, tcpd->fwd, version, mph->mh_key, mph->mh_capable_flags & MPTCP_CAPABLE_CRYPTO_MASK);
                mptcpd->master = tcpd;

                item = proto_tree_add_uint(mptcp_tree,
                      hf_mptcp_expected_token, tvb, offset, 0, tcpd->fwd->mptcp_subflow->meta->token);
                proto_item_set_generated(item);

                item = proto_tree_add_uint64(mptcp_tree,
                      hf_mptcp_expected_idsn, tvb, offset, 0, tcpd->fwd->mptcp_subflow->meta->base_dsn);
                proto_item_set_generated(item);

                /* last ACK of 3WHS, repeats both keys */
                if (optlen >= 20) {
                    guint64 recv_key = tvb_get_ntoh64(tvb,offset);
                    proto_tree_add_uint64(mptcp_tree, hf_tcp_option_mptcp_recv_key, tvb, offset, 8, recv_key);
                    offset += 8;

                    if(tcpd->rev->mptcp_subflow->meta
                        && (tcpd->rev->mptcp_subflow->meta->static_flags & MPTCP_META_HAS_KEY)) {

                        /* compare the echoed key with the server key */
                        if(tcpd->rev->mptcp_subflow->meta->key != recv_key) {
                            expert_add_info(pinfo, item, &ei_mptcp_analysis_echoed_key_mismatch);
                        }
                    }
                    else {
                        mptcpd = get_or_create_mptcpd_from_key(tcpd, tcpd->rev, version, recv_key, mph->mh_capable_flags & MPTCP_CAPABLE_CRYPTO_MASK);
                    }
                }

                /* MPTCP v1 ACK + data, contains data_len and optional checksum */
                if (optlen >= 22) {
                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_data_lvl_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    mph->mh_dss_length = tvb_get_ntohs(tvb,offset);
                    offset += 2;

                    if (mph->mh_dss_length == 0) {
                        expert_add_info(pinfo, mptcp_tree, &ei_mptcp_infinite_mapping);
                    }

                    /* when data len is present, this MP_CAPABLE also carries an implicit mapping ... */
                    analyze_mapping(tcpd, pinfo, mph->mh_dss_length, tcpd->fwd->mptcp_subflow->meta->base_dsn + 1, TRUE, tcph->th_seq);

                    /* ... with optional checksum */
                    if (optlen == 24)
                    {
                        proto_tree_add_checksum(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
                    }
                }
            }
            break;

        case TCPOPT_MPTCP_MP_JOIN:
            mph->mh_join = TRUE;
            if(optlen != 12 && !mptcpd) {
                mptcpd = mptcp_alloc_analysis(tcpd);
            }
            switch (optlen) {
                /* Syn */
                case 12:
                    {
                    proto_tree_add_bitmask(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_flags,
                         ett_tcp_option_mptcp, tcp_option_mptcp_join_flags,
                         ENC_BIG_ENDIAN);
                    offset += 1;
                    tcpd->fwd->mptcp_subflow->address_id = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_address_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item_ret_uint(mptcp_tree, hf_tcp_option_mptcp_recv_token, tvb, offset,
                            4, ENC_BIG_ENDIAN, &mph->mh_token);
                    offset += 4;

                    mptcpd = mptcp_get_meta_from_token(tcpd, tcpd->rev, mph->mh_token);
                    if (tcpd->fwd->mptcp_subflow->meta->version == 1) {
                        mptcp_meta_flow_t *tmp = tcpd->fwd->mptcp_subflow->meta;

                        /* if the negotiated version is v1 the first key was exchanged on SYN/ACK packet: we must swap the meta */
                        tcpd->fwd->mptcp_subflow->meta = tcpd->rev->mptcp_subflow->meta;
                        tcpd->rev->mptcp_subflow->meta = tmp;
                    }

                    proto_tree_add_item_ret_uint(mptcp_tree, hf_tcp_option_mptcp_sender_rand, tvb, offset,
                            4, ENC_BIG_ENDIAN, &tcpd->fwd->mptcp_subflow->nonce);

                    }
                    break;


                case 16:    /* Syn/Ack */
                    proto_tree_add_bitmask(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_flags,
                         ett_tcp_option_mptcp, tcp_option_mptcp_join_flags,
                         ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_address_id, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_sender_trunc_hmac, tvb, offset,
                            8, ENC_BIG_ENDIAN);
                    offset += 8;

                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_sender_rand, tvb, offset,
                            4, ENC_BIG_ENDIAN);
                    break;

                case 24:    /* Ack */
                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_reserved, tvb, offset,
                            2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_sender_hmac, tvb, offset,
                                20, ENC_NA);
                    break;

                default:
                    break;
            }
            break;

        /* display only *raw* values since it is harder to guess a correct value than for TCP.
        One needs to enable mptcp_analysis to get more interesting data
         */
        case TCPOPT_MPTCP_DSS:
            mph->mh_dss = TRUE;

            offset += 1;
            mph->mh_dss_flags = tvb_get_guint8(tvb, offset) & 0x1F;

            proto_tree_add_bitmask(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_flags,
                         ett_tcp_option_mptcp, tcp_option_mptcp_dss_flags,
                         ENC_BIG_ENDIAN);
            offset += 1;

            /* displays "raw" DataAck , ie does not convert it to its 64 bits form
            to do so you need to enable
            */
            if (mph->mh_dss_flags & MPTCP_DSS_FLAG_DATA_ACK_PRESENT) {

                guint64 dack64;

                /* 64bits ack */
                if (mph->mh_dss_flags & MPTCP_DSS_FLAG_DATA_ACK_8BYTES) {

                    mph->mh_dss_rawack = tvb_get_ntoh64(tvb,offset);
                    proto_tree_add_uint64_format_value(mptcp_tree, hf_tcp_option_mptcp_data_ack_raw, tvb, offset, 8, mph->mh_dss_rawack, "%" PRIu64 " (64bits)", mph->mh_dss_rawack);
                    offset += 8;
                }
                /* 32bits ack */
                else {
                    mph->mh_dss_rawack = tvb_get_ntohl(tvb,offset);
                    proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_data_ack_raw, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                }

                if(mptcp_convert_dsn(mph->mh_dss_rawack, tcpd->rev->mptcp_subflow->meta,
                    (mph->mh_dss_flags & MPTCP_DSS_FLAG_DATA_ACK_8BYTES) ? DSN_CONV_NONE : DSN_CONV_32_TO_64, mptcp_relative_seq, &dack64)) {
                    item = proto_tree_add_uint64(mptcp_tree, hf_mptcp_ack, tvb, 0, 0, dack64);
                    if (mptcp_relative_seq) {
                        proto_item_append_text(item, " (Relative)");
                    }

                    proto_item_set_generated(item);
                }
                else {
                    /* ignore and continue */
                }

            }

            /* Mapping present */
            if (mph->mh_dss_flags & MPTCP_DSS_FLAG_MAPPING_PRESENT) {

                guint64 dsn;

                if (mph->mh_dss_flags & MPTCP_DSS_FLAG_DSN_8BYTES) {

                    dsn = tvb_get_ntoh64(tvb,offset);
                    proto_tree_add_uint64_format_value(mptcp_tree, hf_tcp_option_mptcp_data_seq_no_raw, tvb, offset, 8, dsn,  "%" PRIu64 "  (64bits version)", dsn);

                    /* if we have the opportunity to complete the 32 Most Significant Bits of the
                     *
                     */
                    if(!(tcpd->fwd->mptcp_subflow->meta->static_flags & MPTCP_META_HAS_BASE_DSN_MSB)) {
                        tcpd->fwd->mptcp_subflow->meta->static_flags |= MPTCP_META_HAS_BASE_DSN_MSB;
                        tcpd->fwd->mptcp_subflow->meta->base_dsn |= (dsn & (guint32) 0);
                    }
                    offset += 8;
                } else {
                    dsn = tvb_get_ntohl(tvb,offset);
                    proto_tree_add_uint64_format_value(mptcp_tree, hf_tcp_option_mptcp_data_seq_no_raw, tvb, offset, 4, dsn,  "%" PRIu64 "  (32bits version)", dsn);
                    offset += 4;
                }
                mph->mh_dss_rawdsn = dsn;

                proto_tree_add_item_ret_uint(mptcp_tree, hf_tcp_option_mptcp_subflow_seq_no, tvb, offset, 4, ENC_BIG_ENDIAN, &mph->mh_dss_ssn);
                offset += 4;

                proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_data_lvl_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                mph->mh_dss_length = tvb_get_ntohs(tvb,offset);
                offset += 2;

                if(mph->mh_dss_length == 0) {
                    expert_add_info(pinfo, mptcp_tree, &ei_mptcp_infinite_mapping);
                }

                /* print head & tail dsn */
                if(mptcp_convert_dsn(mph->mh_dss_rawdsn, tcpd->fwd->mptcp_subflow->meta,
                    (mph->mh_dss_flags & MPTCP_DSS_FLAG_DATA_ACK_8BYTES) ? DSN_CONV_NONE : DSN_CONV_32_TO_64, mptcp_relative_seq, &dsn)) {
                    item = proto_tree_add_uint64(mptcp_tree, hf_mptcp_dss_dsn, tvb, 0, 0, dsn);
                    if (mptcp_relative_seq) {
                            proto_item_append_text(item, " (Relative)");
                    }

                    proto_item_set_generated(item);
                }
                else {
                    /* ignore and continue */
                }

                analyze_mapping(tcpd, pinfo, mph->mh_dss_length, mph->mh_dss_rawdsn, mph->mh_dss_flags & MPTCP_DSS_FLAG_DATA_ACK_8BYTES, mph->mh_dss_ssn);

                if ((int)optlen >= offset-start_offset+4)
                {
                    proto_tree_add_checksum(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
                }
            }
            break;

        case TCPOPT_MPTCP_ADD_ADDR:
            mph->mh_add = TRUE;
            ipver = tvb_get_guint8(tvb, offset) & 0x0F;
            if (ipver == 4 || ipver == 6)
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_ipver, tvb, offset, 1, ENC_BIG_ENDIAN);
            else
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_echo, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_address_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if (optlen == 8 || optlen == 10 || optlen == 16 || optlen == 18) {
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            if (optlen == 20 || optlen == 22 || optlen == 28 || optlen == 30) {
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_ipv6, tvb, offset, 16, ENC_NA);
                offset += 16;
            }

            if (optlen == 10 || optlen == 18 || optlen == 22 || optlen == 30) {
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }

            if (optlen == 16 || optlen == 18 || optlen == 28 || optlen == 30) {
                proto_tree_add_item(mptcp_tree,
                            hf_tcp_option_mptcp_addaddr_trunc_hmac, tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            break;

        case TCPOPT_MPTCP_REMOVE_ADDR:
            mph->mh_remove = TRUE;
            item = proto_tree_add_uint(mptcp_tree, hf_mptcp_number_of_removed_addresses, tvb, start_offset+2,
                1, optlen - 3);
            proto_item_set_generated(item);
            offset += 1;
            while(offset < start_offset + (int)optlen) {
                proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_address_id, tvb, offset,
                                1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;

        case TCPOPT_MPTCP_MP_PRIO:
            mph->mh_prio = TRUE;
            proto_tree_add_bitmask(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_flags,
                         ett_tcp_option_mptcp, tcp_option_mptcp_join_flags,
                         ENC_BIG_ENDIAN);
            offset += 1;

            if (optlen == 4) {
                proto_tree_add_item(mptcp_tree,
                        hf_tcp_option_mptcp_address_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            break;

        case TCPOPT_MPTCP_MP_FAIL:
            mph->mh_fail = TRUE;
            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_reserved, tvb, offset,2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_data_seq_no_raw, tvb, offset, 8, ENC_BIG_ENDIAN);
            break;

        case TCPOPT_MPTCP_MP_FASTCLOSE:
            mph->mh_fastclose = TRUE;
            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(mptcp_tree,
                    hf_tcp_option_mptcp_recv_key, tvb, offset, 8, ENC_BIG_ENDIAN);
            mph->mh_key = tvb_get_ntoh64(tvb,offset);
            break;

        case TCPOPT_MPTCP_MP_TCPRST:
            mph->mh_tcprst = TRUE;
            proto_tree_add_bitmask(mptcp_tree, tvb, offset, hf_tcp_option_mptcp_flags,
                                   ett_tcp_option_mptcp, tcp_option_mptcp_tcprst_flags,
                                   ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(mptcp_tree, hf_tcp_option_mptcp_tcprst_reason, tvb,  offset, 1,
                                ENC_BIG_ENDIAN);
            break;

        default:
            break;
    }

    if ((mptcpd != NULL) && (tcpd->mptcp_analysis != NULL)) {

        /* if mptcpd just got allocated, remember the initial addresses
         * which will serve as identifiers for the conversation filter
         */
        if(tcpd->fwd->mptcp_subflow->meta->ip_src.len == 0) {

            copy_address_wmem(wmem_file_scope(), &tcpd->fwd->mptcp_subflow->meta->ip_src, &tcph->ip_src);
            copy_address_wmem(wmem_file_scope(), &tcpd->fwd->mptcp_subflow->meta->ip_dst, &tcph->ip_dst);

            copy_address_shallow(&tcpd->rev->mptcp_subflow->meta->ip_src, &tcpd->fwd->mptcp_subflow->meta->ip_dst);
            copy_address_shallow(&tcpd->rev->mptcp_subflow->meta->ip_dst, &tcpd->fwd->mptcp_subflow->meta->ip_src);

            tcpd->fwd->mptcp_subflow->meta->sport = tcph->th_sport;
            tcpd->fwd->mptcp_subflow->meta->dport = tcph->th_dport;
        }

        mph->mh_stream = tcpd->mptcp_analysis->stream;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_cc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *item;
    proto_item *length_item;
    int offset = 0;
    guint32 cc;

    item = proto_tree_add_item(tree, proto_tcp_option_cc, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(item, ett_tcp_opt_cc);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_CC))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_tcp_option_cc, tvb,
                        offset + 2, 4, ENC_BIG_ENDIAN, &cc);

    tcp_info_append_uint(pinfo, "CC", cc);
    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_md5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *item;
    proto_item *length_item;
    int offset = 0, optlen = tvb_reported_length(tvb);

    item = proto_tree_add_item(tree, proto_tcp_option_md5, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(item, ett_tcp_opt_md5);

    col_append_lstr(pinfo->cinfo, COL_INFO, " MD5", COL_ADD_LSTR_TERMINATOR);
    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, optlen, TCPOLEN_MD5))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_tcp_option_md5_digest, tvb,
                        offset + 2, optlen - 2, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_ao(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *item;
    proto_item *length_item;
    int offset = 0, optlen = tvb_reported_length(tvb);

    item = proto_tree_add_item(tree, proto_tcp_option_ao, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(item, ett_tcp_opt_ao);

    col_append_lstr(pinfo->cinfo, COL_INFO, "TCP AO", COL_ADD_LSTR_TERMINATOR);
    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (optlen < 4) {
        expert_add_info_format(pinfo, length_item, &ei_tcp_opt_len_invalid,
                               "option length should be >= than 4");
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item(field_tree, hf_tcp_option_ao_keyid, tvb,
                        offset + 2, 1, ENC_NA);

    proto_tree_add_item(field_tree, hf_tcp_option_ao_rnextkeyid, tvb,
                        offset + 3, 1, ENC_NA);

    if (optlen > 4)
        proto_tree_add_item(field_tree, hf_tcp_option_ao_mac, tvb,
                            offset + 4, optlen - 4, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_qs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *item;
    proto_item *length_item;
    guint8 rate;
    int offset = 0;

    item = proto_tree_add_item(tree, proto_tcp_option_qs, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(item, ett_tcp_opt_qs);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_QS))
        return tvb_captured_length(tvb);

    rate = tvb_get_guint8(tvb, offset + 2) & 0x0f;
    col_append_lstr(pinfo->cinfo, COL_INFO,
        " QSresp=", val_to_str_ext_const(rate, &qs_rate_vals_ext, "Unknown"),
        COL_ADD_LSTR_TERMINATOR);
    proto_tree_add_item(field_tree, hf_tcp_option_qs_rate, tvb,
                        offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_tcp_option_qs_ttl_diff, tvb,
                        offset + 3, 1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_scps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    struct tcp_analysis *tcpd;
    proto_tree *field_tree = NULL;
    tcp_flow_t *flow;
    int         direction;
    proto_item *tf = NULL, *item;
    proto_tree *flags_tree = NULL;
    guint8      capvector;
    guint8      connid;
    int         offset = 0, optlen = tvb_reported_length(tvb);

    tcpd = get_tcp_conversation_data(NULL,pinfo);

    /* check direction and get ua lists */
    direction=cmp_address(&pinfo->src, &pinfo->dst);

    /* if the addresses are equal, match the ports instead */
    if(direction==0) {
        direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }

    if(direction>=0)
        flow =&(tcpd->flow1);
    else
        flow =&(tcpd->flow2);

    item = proto_tree_add_item(tree, proto_tcp_option_scps,
                               tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(item, ett_tcp_option_scps);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);

    /* If the option length == 4, this is a real SCPS capability option
     * See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS Transport Protocol
     * (SCPS-TP)" Section 3.2.3 for definition.
     */
    if (optlen == 4) {
        tf = proto_tree_add_item(field_tree, hf_tcp_option_scps_vector, tvb,
                                 offset + 2, 1, ENC_BIG_ENDIAN);
        flags_tree = proto_item_add_subtree(tf, ett_tcp_scpsoption_flags);
        proto_tree_add_item(flags_tree, hf_tcp_scpsoption_flags_bets, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_tcp_scpsoption_flags_snack1, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_tcp_scpsoption_flags_snack2, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_tcp_scpsoption_flags_compress, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_tcp_scpsoption_flags_nlts, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_tcp_scpsoption_flags_reserved, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        capvector = tvb_get_guint8(tvb, offset + 2);

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
                    col_append_lstr(pinfo->cinfo, COL_INFO,
                                    anyflag ? ", " : "",
                                    capvecs[i].str,
                                    COL_ADD_LSTR_TERMINATOR);
                    anyflag = TRUE;
                }
            }
            col_append_str(pinfo->cinfo, COL_INFO, "]");
            proto_item_append_text(tf, ")");
        }

        proto_tree_add_item(field_tree, hf_tcp_scpsoption_connection_id, tvb,
                            offset + 3, 1, ENC_BIG_ENDIAN);
        connid = tvb_get_guint8(tvb, offset + 3);
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
            proto_item_set_text(item,
                                "Illegal SCPS Extended Capabilities (%u bytes)",
                                optlen);
        } else {
            proto_item_set_text(item,
                                "SCPS Extended Capabilities (%u bytes)",
                                optlen);

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

                proto_tree_add_item(field_tree, hf_tcp_option_scps_binding_data, tvb, offset + local_offset, extended_cap_length, ENC_NA);

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

    return tvb_captured_length(tvb);
}

static int
dissect_tcpopt_user_to(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    proto_item *length_item;
    guint16 to;
    int offset = 0;

    tf = proto_tree_add_item(tree, proto_tcp_option_user_to, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_tcp_option_user_to);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_USER_TO))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_tcp_option_user_to_granularity, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    to = tvb_get_ntohs(tvb, offset + 2) & 0x7FFF;
    proto_tree_add_item(field_tree, hf_tcp_option_user_to_val, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    tcp_info_append_uint(pinfo, "USER_TO", to);
    return tvb_captured_length(tvb);
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
            expert_add_info(pinfo, tf_syn, &ei_tcp_scps_capable);
        }
    }
}

/* See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS
 * Transport Protocol (SCPS-TP)" Section 3.5 for definition of the SNACK option
 */
static int
dissect_tcpopt_snack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    struct tcp_analysis *tcpd=NULL;
    guint32 relative_hole_offset;
    guint32 relative_hole_size;
    guint16 base_mss = 0;
    guint32 ack;
    guint32 hole_start;
    guint32 hole_end;
    int     offset = 0;
    proto_item *hidden_item, *tf;
    proto_tree *field_tree;
    proto_item *length_item;

    tf = proto_tree_add_item(tree, proto_tcp_option_snack, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_tcp_option_snack);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, tvb_reported_length(tvb), TCPOLEN_SNACK))
        return tvb_captured_length(tvb);

    tcpd = get_tcp_conversation_data(NULL,pinfo);

    /* The SNACK option reports missing data with a granularity of segments. */
    proto_tree_add_item_ret_uint(field_tree, hf_tcp_option_snack_offset,
                                      tvb, offset + 2, 2, ENC_BIG_ENDIAN, &relative_hole_offset);

    proto_tree_add_item_ret_uint(field_tree, hf_tcp_option_snack_size,
                                      tvb, offset + 4, 2, ENC_BIG_ENDIAN, &relative_hole_size);

    ack   = tvb_get_ntohl(tvb, 8);

    if (tcp_analyze_seq && tcp_relative_seq) {
        ack -= tcpd->rev->base_seq;
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

        hidden_item = proto_tree_add_uint(field_tree, hf_tcp_option_snack_le,
                                          tvb, offset + 2, 2, hole_start);
        proto_item_set_hidden(hidden_item);

        hidden_item = proto_tree_add_uint(field_tree, hf_tcp_option_snack_re,
                                          tvb, offset + 4, 2, hole_end);
        proto_item_set_hidden(hidden_item);

        proto_tree_add_expert_format(field_tree, pinfo, &ei_tcp_option_snack_sequence, tvb, offset+2, 4,
                            "SNACK Sequence %u - %u%s", hole_start, hole_end, ((tcp_analyze_seq && tcp_relative_seq) ? " (relative)" : ""));

        tcp_info_append_uint(pinfo, "SNLE", hole_start);
        tcp_info_append_uint(pinfo, "SNRE", hole_end);
    }

    return tvb_captured_length(tvb);
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

typedef struct rvbd_option_data
{
    gboolean valid;
    guint8 type;
    guint8 probe_flags;

} rvbd_option_data;

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
rvbd_probe_resp_add_info(proto_item *pitem, packet_info *pinfo, tvbuff_t *tvb, int ip_offset, guint16 port)
{
    proto_item_append_text(pitem, ", Server Steelhead: %s:%u", tvb_ip_to_str(pinfo->pool, tvb, ip_offset), port);

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "SA+, ");
}

static int
dissect_tcpopt_rvbd_probe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint8 ver, type;
    proto_tree *field_tree;
    proto_item *pitem;
    proto_item *length_item;
    int offset = 0,
        optlen = tvb_reported_length(tvb);
    struct tcpheader *tcph = (struct tcpheader*)data;

    pitem = proto_tree_add_item(tree, proto_tcp_option_rvbd_probe, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(pitem, ett_tcp_opt_rvbd_probe);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (optlen < TCPOLEN_RVBD_PROBE_MIN) {
        /* Bogus - option length is less than what it's supposed to be for
           this option. */
        expert_add_info_format(pinfo, length_item, &ei_tcp_opt_len_invalid,
                            "option length should be >= %u)",
                            TCPOLEN_RVBD_PROBE_MIN);
        return tvb_captured_length(tvb);
    }

    rvbd_probe_decode_version_type(
        tvb_get_guint8(tvb, offset + PROBE_VERSION_TYPE_OFFSET),
        &ver, &type);

    proto_item_append_text(pitem, ": %s", val_to_str_const(type, rvbd_probe_type_vs, "Probe Unknown"));

    if (type >= PROBE_TYPE_MAX)
        return tvb_captured_length(tvb);

    if (ver == PROBE_VERSION_1) {
        guint16 port;

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_type1, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_version1, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);

        if (type == PROBE_INTERNAL)
            return offset + PROBE_VERSION_TYPE_OFFSET;

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_reserved, tvb, offset + PROBE_V1_RESERVED_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_prober, tvb,
                            offset + PROBE_V1_PROBER_OFFSET, 4, ENC_BIG_ENDIAN);

        switch (type) {

        case PROBE_QUERY:
        case PROBE_QUERY_SH:
        case PROBE_TRACE:
            {
            rvbd_option_data* option_data;
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_appli_ver, tvb,
                                offset + PROBE_V1_APPLI_VERSION_OFFSET, 2,
                                ENC_BIG_ENDIAN);

            proto_item_append_text(pitem, ", CSH IP: %s", tvb_ip_to_str(pinfo->pool, tvb, offset + PROBE_V1_PROBER_OFFSET));

            option_data = (rvbd_option_data*)p_get_proto_data(pinfo->pool, pinfo, proto_tcp_option_rvbd_probe, pinfo->curr_layer_num);
            if (option_data == NULL)
            {
                option_data = wmem_new0(pinfo->pool, rvbd_option_data);
                p_add_proto_data(pinfo->pool, pinfo, proto_tcp_option_rvbd_probe, pinfo->curr_layer_num, option_data);
            }

            option_data->valid = TRUE;
            option_data->type = type;

            }
            break;

        case PROBE_RESPONSE:
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy, tvb,
                                offset + PROBE_V1_PROXY_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

            port = tvb_get_ntohs(tvb, offset + PROBE_V1_PROXY_PORT_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy_port, tvb,
                                offset + PROBE_V1_PROXY_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

            rvbd_probe_resp_add_info(pitem, pinfo, tvb, offset + PROBE_V1_PROXY_ADDR_OFFSET, port);
            break;

        case PROBE_RESPONSE_SH:
            proto_tree_add_item(field_tree,
                                hf_tcp_option_rvbd_probe_client, tvb,
                                offset + PROBE_V1_SH_CLIENT_ADDR_OFFSET, 4,
                                ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy, tvb,
                                offset + PROBE_V1_SH_PROXY_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

            port = tvb_get_ntohs(tvb, offset + PROBE_V1_SH_PROXY_PORT_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy_port, tvb,
                                offset + PROBE_V1_SH_PROXY_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

            rvbd_probe_resp_add_info(pitem, pinfo, tvb, offset + PROBE_V1_SH_PROXY_ADDR_OFFSET, port);
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
        proto_item_set_hidden(ver_pi);

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

            switch (type)
            {
            case PROBE_QUERY_INFO:
                {
                    rvbd_option_data* option_data = (rvbd_option_data*)p_get_proto_data(pinfo->pool, pinfo, proto_tcp_option_rvbd_probe, pinfo->curr_layer_num);
                    if (option_data == NULL)
                    {
                        option_data = wmem_new0(pinfo->pool, rvbd_option_data);
                        p_add_proto_data(pinfo->pool, pinfo, proto_tcp_option_rvbd_probe, pinfo->curr_layer_num, option_data);
                    }

                    option_data->probe_flags = flags;
                }
                break;
            case PROBE_QUERY_INFO_SH:
                proto_tree_add_item(flag_tree,
                                    hf_tcp_option_rvbd_probe_client, tvb,
                                    offset + PROBE_V2_INFO_CLIENT_ADDR_OFFSET,
                                    4, ENC_BIG_ENDIAN);
                break;
            case PROBE_QUERY_INFO_SID:
                proto_tree_add_item(flag_tree,
                                    hf_tcp_option_rvbd_probe_storeid, tvb,
                                    offset + PROBE_V2_INFO_STOREID_OFFSET,
                                    4, ENC_BIG_ENDIAN);
                break;
            }

            if (type != PROBE_QUERY_INFO_SID &&
                tcph != NULL &&
                (tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) &&
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

    return tvb_captured_length(tvb);
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

static int
dissect_tcpopt_rvbd_trpy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *pitem;
    proto_item *length_item;
    guint16 sport, dport, flags;
    int offset = 0,
        optlen = tvb_reported_length(tvb);
    static int * const rvbd_trpy_flags[] = {
        &hf_tcp_option_rvbd_trpy_flag_fw_rst_probe,
        &hf_tcp_option_rvbd_trpy_flag_fw_rst_inner,
        &hf_tcp_option_rvbd_trpy_flag_fw_rst,
        &hf_tcp_option_rvbd_trpy_flag_chksum,
        &hf_tcp_option_rvbd_trpy_flag_oob,
        &hf_tcp_option_rvbd_trpy_flag_mode,
        NULL
    };

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "TRPY, ");

    pitem = proto_tree_add_item(tree, proto_tcp_option_rvbd_trpy, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(pitem, ett_tcp_opt_rvbd_trpy);

    proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    length_item = proto_tree_add_item(field_tree, hf_tcp_option_len, tvb,
                                      offset + 1, 1, ENC_BIG_ENDIAN);

    if (!tcp_option_len_check(length_item, pinfo, optlen, TCPOLEN_RVBD_TRPY_MIN))
        return tvb_captured_length(tvb);

    flags = tvb_get_ntohs(tvb, offset + TRPY_OPTIONS_OFFSET);
    proto_tree_add_bitmask_with_flags(field_tree, tvb, offset + TRPY_OPTIONS_OFFSET, hf_tcp_option_rvbd_trpy_flags,
                        ett_tcp_opt_rvbd_trpy_flags, rvbd_trpy_flags, ENC_NA, BMT_NO_APPEND);

    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_src,
                        tvb, offset + TRPY_SRC_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_dst,
                        tvb, offset + TRPY_DST_ADDR_OFFSET, 4, ENC_BIG_ENDIAN);

    sport = tvb_get_ntohs(tvb, offset + TRPY_SRC_PORT_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_src_port,
                        tvb, offset + TRPY_SRC_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

    dport = tvb_get_ntohs(tvb, offset + TRPY_DST_PORT_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_dst_port,
                        tvb, offset + TRPY_DST_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(pitem, " %s:%u -> %s:%u",
                           tvb_ip_to_str(pinfo->pool, tvb, offset + TRPY_SRC_ADDR_OFFSET), sport,
                           tvb_ip_to_str(pinfo->pool, tvb, offset + TRPY_DST_ADDR_OFFSET), dport);

    /* Client port only set on SYN: optlen == 18 */
    if ((flags & RVBD_FLAGS_TRPY_OOB) && (optlen > TCPOLEN_RVBD_TRPY_MIN))
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_client_port,
                            tvb, offset + TRPY_CLIENT_PORT_OFFSET, 2, ENC_BIG_ENDIAN);

    /* Despite that we have the right TCP ports for other protocols,
     * the data is related to the Riverbed Optimization Protocol and
     * not understandable by normal protocol dissectors. If the sport
     * protocol is available then use that, otherwise just output it
     * as a hex-dump.
     */
    if (sport_handle != NULL) {
        conversation_t *conversation;
        conversation = find_or_create_conversation(pinfo);
        if (conversation_get_dissector(conversation, pinfo->num) != sport_handle) {
            conversation_set_dissector(conversation, sport_handle);
        }
    } else if (data_handle != NULL) {
        conversation_t *conversation;
        conversation = find_or_create_conversation(pinfo);
        if (conversation_get_dissector(conversation, pinfo->num) != data_handle) {
            conversation_set_dissector(conversation, data_handle);
        }
    }

    return tvb_captured_length(tvb);
}

 /* Started as a copy of dissect_ip_tcp_options(), but was changed to support
    options as a dissector table */
static void
tcp_dissect_options(tvbuff_t *tvb, int offset, guint length, int eol,
                       packet_info *pinfo, proto_tree *opt_tree,
                       proto_item *opt_item, void * data)
{
    guchar            opt;
    guint             optlen, nop_count = 0;
    proto_tree       *field_tree;
    const char       *name;
    dissector_handle_t option_dissector;
    tvbuff_t         *next_tvb;
    struct tcpheader *tcph = (struct tcpheader *)data;
    gboolean          mss_seen = FALSE;

    while (length > 0) {
        opt = tvb_get_guint8(tvb, offset);
        --length;      /* account for type byte */
        if ((opt == TCPOPT_EOL) || (opt == TCPOPT_NOP)) {
            int local_proto;
            proto_item* field_item;

            /* We assume that the only options with no length are EOL and
               NOP options, so that we can treat unknown options as having
               a minimum length of 2, and at least be able to move on to
               the next option by using the length in the option. */
            if (opt == TCPOPT_EOL) {
                local_proto = proto_tcp_option_eol;
            } else if (opt == TCPOPT_NOP) {
                local_proto = proto_tcp_option_nop;

                if (opt_item && (nop_count == 0 || offset % 4)) {
                    /* Count number of NOP in a row within a uint32 */
                    nop_count++;

                    if (nop_count == 4) {
                        expert_add_info(pinfo, opt_item, &ei_tcp_nop);
                    }
                } else {
                    nop_count = 0;
                }
            } else {
                DISSECTOR_ASSERT_NOT_REACHED();
            }

            field_item = proto_tree_add_item(opt_tree, local_proto, tvb, offset, 1, ENC_NA);
            field_tree = proto_item_add_subtree(field_item, ett_tcp_option_other);
            proto_tree_add_item(field_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s", proto_get_protocol_short_name(find_protocol_by_id(local_proto)));
            offset += 1;
        } else {
            option_dissector = dissector_get_uint_handle(tcp_option_table, opt);
            if (option_dissector == NULL) {
                name = wmem_strdup_printf(pinfo->pool, "Unknown (0x%02x)", opt);
                option_dissector = tcp_opt_unknown_handle;
            } else {
                name = dissector_handle_get_short_name(option_dissector);
            }

            /* Option has a length. Is it in the packet? */
            if (length == 0) {
                /* Bogus - packet must at least include option code byte and
                    length byte! */
                proto_tree_add_expert_format(opt_tree, pinfo, &ei_tcp_opt_len_invalid, tvb, offset, 1,
                                                "%s (length byte past end of options)", name);
                return;
            }

            optlen = tvb_get_guint8(tvb, offset + 1);  /* total including type, len */
            --length;    /* account for length byte */

            if (optlen < 2) {
                /* Bogus - option length is too short to include option code and
                    option length. */
                proto_tree_add_expert_format(opt_tree, pinfo, &ei_tcp_opt_len_invalid, tvb, offset, 2,
                                    "%s (with too-short option length = %u byte%s)",
                                    name, optlen, plurality(optlen, "", "s"));
                return;
            } else if (optlen - 2 > length) {
                /* Bogus - option goes past the end of the header. */
                proto_tree_add_expert_format(opt_tree, pinfo, &ei_tcp_opt_len_invalid, tvb, offset, length,
                                    "%s (option length = %u byte%s says option goes past end of options)",
                                    name, optlen, plurality(optlen, "", "s"));
                return;
            }

            if (opt == TCPOPT_MSS)
            {
                mss_seen = TRUE;
            }

            next_tvb = tvb_new_subset_length(tvb, offset, optlen);
            call_dissector_with_data(option_dissector, next_tvb, pinfo, opt_tree/* tree */, data);
            proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s", name);

            offset += optlen;
            length -= (optlen-2); //already accounted for type and len bytes
        }

        if (opt == eol)
            break;
    }

    if ((tcph->th_flags & TH_SYN) && (mss_seen != TRUE))
    {
        expert_add_info(pinfo, opt_item, &ei_tcp_option_mss_absent);
    }
}

/* Determine if there is a sub-dissector and call it; return TRUE
   if there was a sub-dissector, FALSE otherwise.

   This has been separated into a stand alone routine to other protocol
   dissectors can call to it, e.g., SOCKS. */

static gboolean try_heuristic_first = FALSE;


/* this function can be called with tcpd==NULL as from the msproxy dissector */
gboolean
decode_tcp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, int src_port, int dst_port,
    struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo)
{
    tvbuff_t *next_tvb;
    int low_port, high_port;
    int save_desegment_offset;
    gboolean try_low_port, try_high_port, try_server_port;
    guint32 save_desegment_len;
    heur_dtbl_entry_t *hdtbl_entry;
    exp_pdu_data_t *exp_pdu_data;

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

    if (tcp_no_subdissector_on_error && !(tcp_desegment && tcp_reassemble_out_of_order) &&
        tcpd && tcpd->ta && tcpd->ta->flags & (TCP_A_RETRANSMISSION | TCP_A_OUT_OF_ORDER)) {
        /* Don't try to dissect a retransmission high chance that it will mess
         * subdissectors for protocols that require in-order delivery of the
         * PDUs. (i.e. DCE/RPCoverHTTP and encryption)
         * If OoO reassembly is enabled and if this segment was previously lost,
         * then this retransmission could have finished reassembly, so continue.
         * XXX should this option be removed? "tcp_reassemble_out_of_order"
         * should have addressed the above in-order requirement.
         */
        return FALSE;
    }
    next_tvb = tvb_new_subset_remaining(tvb, offset);

    save_desegment_offset = pinfo->desegment_offset;
    save_desegment_len = pinfo->desegment_len;

/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

    if (try_conversation_dissector(&pinfo->src, &pinfo->dst, ENDPOINT_TCP,
                                   src_port, dst_port, next_tvb, pinfo, tree, tcpinfo, 0)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        handle_export_pdu_conversation(pinfo, next_tvb, src_port, dst_port, tcpinfo);
        return TRUE;
    }

    /* If the user has manually configured one of the server, low, or high
     * ports to a dissector other than the default (via Decode As or the
     * preferences associated with Decode As), try those first, in that order.
     */
    try_server_port = FALSE;
    if (tcpd && tcpd->server_port != 0) {
        if (dissector_is_uint_changed(subdissector_table, tcpd->server_port)) {
            if (dissector_try_uint_new(subdissector_table, tcpd->server_port, next_tvb, pinfo, tree, TRUE, tcpinfo)) {
                pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
                handle_export_pdu_dissection_table(pinfo, next_tvb, tcpd->server_port, tcpinfo);
                return TRUE;
            }
        } else {
            /* The default; try it later */
            try_server_port = TRUE;
        }
    }

    if (src_port > dst_port) {
        low_port = dst_port;
        high_port = src_port;
    } else {
        low_port = src_port;
        high_port = dst_port;
    }

    try_low_port = FALSE;
    if (low_port != 0) {
        if (dissector_is_uint_changed(subdissector_table, low_port)) {
            if (dissector_try_uint_new(subdissector_table, low_port, next_tvb, pinfo, tree, TRUE, tcpinfo)) {
                pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
                handle_export_pdu_dissection_table(pinfo, next_tvb, low_port, tcpinfo);
                return TRUE;
            }
        } else {
            /* The default; try it later */
            try_low_port = TRUE;
        }
    }

    try_high_port = FALSE;
    if (high_port != 0) {
        if (dissector_is_uint_changed(subdissector_table, high_port)) {
            if (dissector_try_uint_new(subdissector_table, high_port, next_tvb, pinfo, tree, TRUE, tcpinfo)) {
                pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
                handle_export_pdu_dissection_table(pinfo, next_tvb, high_port, tcpinfo);
                return TRUE;
            }
        } else {
            /* The default; try it later */
            try_high_port = TRUE;
        }
    }

    if (try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, tcpinfo)) {
            pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
            handle_export_pdu_heuristic(pinfo, next_tvb, hdtbl_entry, tcpinfo);
            return TRUE;
        }
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

    if (try_server_port &&
        dissector_try_uint_new(subdissector_table, tcpd->server_port, next_tvb, pinfo, tree, TRUE, tcpinfo)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        handle_export_pdu_dissection_table(pinfo, next_tvb, tcpd->server_port, tcpinfo);
        return TRUE;
    }

    if (try_low_port &&
        dissector_try_uint_new(subdissector_table, low_port, next_tvb, pinfo, tree, TRUE, tcpinfo)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        handle_export_pdu_dissection_table(pinfo, next_tvb, low_port, tcpinfo);
        return TRUE;
    }
    if (try_high_port &&
        dissector_try_uint_new(subdissector_table, high_port, next_tvb, pinfo, tree, TRUE, tcpinfo)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        handle_export_pdu_dissection_table(pinfo, next_tvb, high_port, tcpinfo);
        return TRUE;
    }

    if (!try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, tcpinfo)) {
            pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
            handle_export_pdu_heuristic(pinfo, next_tvb, hdtbl_entry, tcpinfo);
            return TRUE;
        }
    }

    /*
     * heuristic / conversation / port registered dissectors rejected the packet;
     * make sure they didn't also request desegmentation (we could just override
     * the request, but rejecting a packet *and* requesting desegmentation is a sign
     * of the dissector's code needing clearer thought, so we fail so that the
     * problem is made more obvious).
     */
    DISSECTOR_ASSERT(save_desegment_offset == pinfo->desegment_offset &&
                     save_desegment_len == pinfo->desegment_len);

    /* Oh, well, we don't know this; dissect it as data. */
    call_dissector(data_handle,next_tvb, pinfo, tree);

    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    if (have_tap_listener(exported_pdu_tap)) {
        exp_pdu_data = export_pdu_create_common_tags(pinfo, "data", EXP_PDU_TAG_PROTO_NAME);
        exp_pdu_data->tvb_captured_length = tvb_captured_length(next_tvb);
        exp_pdu_data->tvb_reported_length = tvb_reported_length(next_tvb);
        exp_pdu_data->pdu_tvb = next_tvb;

        tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
    }
    return FALSE;
}

static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
    guint32 seq, guint32 nxtseq, gboolean is_tcp_segment,
    struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo)
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
                dst_port, tcpd, tcpinfo) ) {
            /*
             * We succeeded in handing off to a subdissector.
             *
             * Is this a TCP segment or a reassembled chunk of
             * TCP payload?
             */
            if(is_tcp_segment) {
                /* if !visited, check want_pdu_tracking and
                   store it in table */
                if(tcpd && (!pinfo->fd->visited) &&
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
            if(tcpd && (!pinfo->fd->visited) && tcp_analyze_seq && pinfo->want_pdu_tracking) {
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
            struct tcp_analysis *tcpd, struct tcpinfo *tcpinfo)
{
    gint nbytes;
    gboolean save_fragmented;

    nbytes = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_bytes_format(tcp_tree, hf_tcp_payload, tvb, offset,
        -1, NULL, "TCP payload (%u byte%s)", nbytes,
        plurality(nbytes, "", "s"));

    /* Can we desegment this segment? */
    if (pinfo->can_desegment) {
        /* Yes. */
        desegment_tcp(tvb, pinfo, offset, seq, nxtseq, sport, dport, tree,
                      tcp_tree, tcpd, tcpinfo);
    } else {
        /* No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame. */
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree, sport, dport,
                            seq, nxtseq, TRUE, tcpd, tcpinfo);
        pinfo->fragmented = save_fragmented;
    }
}

static gboolean
capture_tcp(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
    guint16 src_port, dst_port, low_port, high_port;

    if (!BYTES_ARE_IN_FRAME(offset, len, 4))
        return FALSE;

    capture_dissector_increment_count(cpinfo, proto_tcp);

    src_port = pntoh16(&pd[offset]);
    dst_port = pntoh16(&pd[offset+2]);

    if (src_port > dst_port) {
        low_port = dst_port;
        high_port = src_port;
    } else {
        low_port = src_port;
        high_port = dst_port;
    }

    if (low_port != 0 &&
        try_capture_dissector("tcp.port", low_port, pd, offset+20, len, cpinfo, pseudo_header))
        return TRUE;

    if (high_port != 0 &&
        try_capture_dissector("tcp.port", high_port, pd, offset+20, len, cpinfo, pseudo_header))
        return TRUE;

    /* We've at least identified one type of packet, so this shouldn't be "other" */
    return TRUE;
}

static int
dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8  th_off_x2; /* combines th_off and th_x2 */
    guint16 th_sum;
    guint32 th_urp;
    proto_tree *tcp_tree = NULL, *field_tree = NULL;
    proto_item *ti = NULL, *tf, *hidden_item;
    proto_item *options_item, *hide_seqack_abs_item;
    proto_tree *options_tree;
    int        offset = 0;
    char       *flags_str, *flags_str_first_letter;
    guint      optlen;
    guint32    nxtseq = 0;
    guint      reported_len;
    vec_t      cksum_vec[4];
    guint32    phdr[2];
    guint16    computed_cksum;
    guint16    real_window;
    guint      captured_length_remaining;
    gboolean   desegment_ok;
    struct tcpinfo tcpinfo;
    struct tcpheader *tcph;
    proto_item *tf_syn = NULL, *tf_fin = NULL, *tf_rst = NULL, *scaled_pi;
    conversation_t *conv=NULL, *other_conv;
    guint32 save_last_frame = 0;
    struct tcp_analysis *tcpd=NULL;
    struct tcp_per_packet_data_t *tcppd=NULL;
    proto_item *item;
    proto_tree *checksum_tree;
    gboolean    icmp_ip = FALSE;
    guint8     conversation_completeness = 0;
    gboolean   conversation_is_new = FALSE;

    tcph = wmem_new0(pinfo->pool, struct tcpheader);
    tcph->th_sport = tvb_get_ntohs(tvb, offset);
    tcph->th_dport = tvb_get_ntohs(tvb, offset + 2);
    copy_address_shallow(&tcph->ip_src, &pinfo->src);
    copy_address_shallow(&tcph->ip_dst, &pinfo->dst);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, tcph->th_sport, tcph->th_dport);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_tcp, tvb, 0, -1, ENC_NA);
        if (tcp_summary_in_tree) {
            proto_item_append_text(ti, ", Src Port: %s, Dst Port: %s",
                    port_with_resolution_to_str(pinfo->pool, PT_TCP, tcph->th_sport),
                    port_with_resolution_to_str(pinfo->pool, PT_TCP, tcph->th_dport));
        }
        tcp_tree = proto_item_add_subtree(ti, ett_tcp);
        p_add_proto_data(pinfo->pool, pinfo, proto_tcp, pinfo->curr_layer_num, tcp_tree);

        proto_tree_add_item(tcp_tree, hf_tcp_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tcp_tree, hf_tcp_dstport, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_item(tcp_tree, hf_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(hidden_item);
        hidden_item = proto_tree_add_item(tcp_tree, hf_tcp_port, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(hidden_item);

        /*  If we're dissecting the headers of a TCP packet in an ICMP packet
         *  then go ahead and put the sequence numbers in the tree now (because
         *  they won't be put in later because the ICMP packet only contains up
         *  to the sequence number).
         *  We should only need to do this for IPv4 since IPv6 will hopefully
         *  carry enough TCP payload for this dissector to put the sequence
         *  numbers in via the regular code path.
         */
        {
            wmem_list_frame_t *frame;
            frame = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
            if (proto_ip == (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame))) {
                frame = wmem_list_frame_prev(frame);
                if (proto_icmp == (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame))) {
                    proto_tree_add_item(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                    icmp_ip = TRUE;
                }
            }
        }
    }

    /* Set the source and destination port numbers as soon as we get them,
       so that they're available to the "Follow TCP Stream" code even if
       we throw an exception dissecting the rest of the TCP header. */
    pinfo->ptype = PT_TCP;
    pinfo->srcport = tcph->th_sport;
    pinfo->destport = tcph->th_dport;

    p_add_proto_data(pinfo->pool, pinfo, hf_tcp_srcport, pinfo->curr_layer_num, GUINT_TO_POINTER(tcph->th_sport));
    p_add_proto_data(pinfo->pool, pinfo, hf_tcp_dstport, pinfo->curr_layer_num, GUINT_TO_POINTER(tcph->th_dport));

    tcph->th_rawseq = tvb_get_ntohl(tvb, offset + 4);
    tcph->th_seq = tcph->th_rawseq;
    tcph->th_rawack = tvb_get_ntohl(tvb, offset + 8);
    tcph->th_ack = tcph->th_rawack;
    th_off_x2 = tvb_get_guint8(tvb, offset + 12);
    tcpinfo.flags = tcph->th_flags = tvb_get_ntohs(tvb, offset + 12) & TH_MASK;
    tcph->th_win = tvb_get_ntohs(tvb, offset + 14);
    real_window = tcph->th_win;
    tcph->th_hlen = hi_nibble(th_off_x2) * 4;  /* TCP header length, in bytes */

    /* find(or create if needed) the conversation for this tcp session
     * This is a slight deviation from find_or_create_conversation so it's
     * done manually.  This is done to save the last frame of the conversation
     * in case a new conversation is found and the previous conversation needs
     * to be adjusted,
     */
    if((conv = find_conversation_pinfo(pinfo, 0)) != NULL) {
        /* Update how far the conversation reaches */
        if (pinfo->num > conv->last_frame) {
            save_last_frame = conv->last_frame;
            conv->last_frame = pinfo->num;
        }
    }
    else {
        conv = conversation_new(pinfo->num, &pinfo->src,
                     &pinfo->dst, ENDPOINT_TCP,
                     pinfo->srcport, pinfo->destport, 0);
        /* we need to know when a conversation is new then we initialize the completeness correctly */
        conversation_is_new = TRUE;
    }
    tcpd=get_tcp_conversation_data(conv,pinfo);

    /* If this is a SYN packet, then check if its seq-nr is different
     * from the base_seq of the retrieved conversation. If this is the
     * case, create a new conversation with the same addresses and ports
     * and set the TA_PORTS_REUSED flag. If the seq-nr is the same as
     * the base_seq, then restore some flow values to avoid buggy
     * analysis. In the latter case, it will also be marked as a
     * retransmission later.
     * XXX - Is this affected by MPTCP which can use multiple SYNs?
     */
    if(tcpd && ((tcph->th_flags&(TH_SYN|TH_ACK))==TH_SYN) &&
       (tcpd->fwd->static_flags & TCP_S_BASE_SEQ_SET)) {
        if(tcph->th_seq!=tcpd->fwd->base_seq) {
            if (!(pinfo->fd->visited)) {
                /* Reset the last frame seen in the conversation */
                if (save_last_frame > 0)
                    conv->last_frame = save_last_frame;

                conv=conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_TCP, pinfo->srcport, pinfo->destport, 0);
                tcpd=get_tcp_conversation_data(conv,pinfo);

                if(!tcpd->ta)
                    tcp_analyze_get_acked_struct(pinfo->num, tcph->th_seq, tcph->th_ack, TRUE, tcpd);
                tcpd->ta->flags|=TCP_A_REUSED_PORTS;

                /* As above, a new conversation starting with a SYN implies conversation completeness value 1 */
                tcpd->conversation_completeness = 1;
            }
        }
        else {
            if (!(pinfo->fd->visited)) {
                /*
                 * Sometimes we need to restore the nextseq value.
                 * As stated in RFC 793 3.4 a RST packet might be
                 * sent with SEQ being equal to the ACK received,
                 * thus breaking our flow monitoring. (issue 17616)
                 */
                tcpd->fwd->tcp_analyze_seq_info->nextseq = tcpd->fwd->tcp_analyze_seq_info->maxseqtobeacked;

                if(!tcpd->ta)
                    tcp_analyze_get_acked_struct(pinfo->num, tcph->th_seq, tcph->th_ack, TRUE, tcpd);
                tcpd->ta->flags|=TCP_A_REUSED_PORTS;
            }
        }
    }

    /* If this is a SYN/ACK packet, then check if its seq-nr is different
     * from the base_seq of the retrieved conversation. If this is the
     * case, try to find a conversation with the same addresses and ports
     * and set the TA_PORTS_REUSED flag. If the seq-nr is the same as
     * the base_seq, then do nothing so it will be marked as a retrans-
     * mission later.
     * XXX - Is this affected by MPTCP which can use multiple SYNs?
     */
    if(tcpd && ((tcph->th_flags&(TH_SYN|TH_ACK))==(TH_SYN|TH_ACK)) &&
        (tcpd->fwd->static_flags & TCP_S_BASE_SEQ_SET) &&
        (tcph->th_seq!=tcpd->fwd->base_seq) ) {
        if (!(pinfo->fd->visited)) {
            /* Reset the last frame seen in the conversation */
            if (save_last_frame > 0)
                conv->last_frame = save_last_frame;
        }

        other_conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->src, ENDPOINT_TCP, pinfo->destport, pinfo->srcport, 0);
        if (other_conv != NULL)
        {
            conv = other_conv;
            tcpd=get_tcp_conversation_data(conv,pinfo);

            /* the retrieved conversation might have a different base_seq (issue 16944) */
            tcpd->fwd->base_seq = tcph->th_seq;
        }

        if(!tcpd->ta)
            tcp_analyze_get_acked_struct(pinfo->num, tcph->th_seq, tcph->th_ack, TRUE, tcpd);
        tcpd->ta->flags|=TCP_A_REUSED_PORTS;
    }

    if (tcpd) {
        item = proto_tree_add_uint(tcp_tree, hf_tcp_stream, tvb, offset, 0, tcpd->stream);
        proto_item_set_generated(item);

        /* Display the completeness of this TCP conversation */
        item = proto_tree_add_uint(tcp_tree, hf_tcp_completeness, NULL, 0, 0, tcpd->conversation_completeness);
        proto_item_set_generated(item);

        /* Copy the stream index into the header as well to make it available
         * to tap listeners.
         */
        tcph->th_stream = tcpd->stream;

        /* initialize the SACK blocks seen to 0 */
        if(tcp_analyze_seq && tcpd->fwd->tcp_analyze_seq_info) {
            tcpd->fwd->tcp_analyze_seq_info->num_sack_ranges = 0;
        }
    }

    /* Do we need to calculate timestamps relative to the tcp-stream? */
    if (tcp_calculate_ts) {
        tcppd = (struct tcp_per_packet_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tcp, pinfo->curr_layer_num);

        /*
         * Calculate the timestamps relative to this conversation (but only on the
         * first run when frames are accessed sequentially)
         */
        if (!(pinfo->fd->visited))
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
            proto_tree_add_expert_format(tcp_tree, pinfo, &ei_tcp_short_segment, tvb, offset, 0,
                                     "Short segment. Segment/fragment does not contain a full TCP header"
                                     " (might be NMAP or someone else deliberately sending unusual packets)");
            tcph->th_have_seglen = FALSE;
        } else {
            proto_item *pi;

            /* Compute the length of data in this segment. */
            tcph->th_seglen = reported_len - tcph->th_hlen;
            tcph->th_have_seglen = TRUE;

            pi = proto_tree_add_uint(ti, hf_tcp_len, tvb, offset+12, 1, tcph->th_seglen);
            proto_item_set_generated(pi);

            /* handle TCP seq# analysis parse all new segments we see */
            if(tcp_analyze_seq) {
                if(!(pinfo->fd->visited)) {
                    tcp_analyze_sequence_number(pinfo, tcph->th_seq, tcph->th_ack, tcph->th_seglen, tcph->th_flags, tcph->th_win, tcpd);
                }
                if(tcpd && tcp_relative_seq) {
                    (tcph->th_seq) -= tcpd->fwd->base_seq;
                    if (tcph->th_flags & TH_ACK) {
                        (tcph->th_ack) -= tcpd->rev->base_seq;
                    }
                }
            }

            /* re-calculate window size, based on scaling factor */
            if (!(tcph->th_flags&TH_SYN)) {   /* SYNs are never scaled */
                if (tcpd && (tcpd->fwd->win_scale>=0)) {
                    (tcph->th_win)<<=tcpd->fwd->win_scale;
                }
                else if (tcpd && (tcpd->fwd->win_scale == -1)) {
                    /* i.e. Unknown, but wasn't signalled with no scaling, so use preference setting instead! */
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

    flags_str = tcp_flags_to_str(pinfo->pool, tcph);
    flags_str_first_letter = tcp_flags_to_str_first_letter(pinfo->pool, tcph);

    col_append_lstr(pinfo->cinfo, COL_INFO,
        " [", flags_str, "]",
        COL_ADD_LSTR_TERMINATOR);
    tcp_info_append_uint(pinfo, "Seq", tcph->th_seq);
    if (tcph->th_flags&TH_ACK)
        tcp_info_append_uint(pinfo, "Ack", tcph->th_ack);

    tcp_info_append_uint(pinfo, "Win", tcph->th_win);

    if (tcp_summary_in_tree) {
        proto_item_append_text(ti, ", Seq: %u", tcph->th_seq);
    }

    if (!icmp_ip) {
        if(tcp_relative_seq && tcp_analyze_seq) {
            proto_tree_add_uint_format_value(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq, "%u    (relative sequence number)", tcph->th_seq);
            item = proto_tree_add_uint(tcp_tree, hf_tcp_seq_abs, tvb, offset + 4, 4, tcph->th_rawseq);
            if (read_seq_as_syn_cookie) {
              proto_item* syncookie_ti = NULL;
              proto_item_append_text(item, " (syn cookie)");
              syncookie_ti = proto_item_add_subtree(item, ett_tcp_syncookie);
              proto_tree_add_bits_item(syncookie_ti, hf_tcp_syncookie_time, tvb, (offset + 4) * 8, 5, ENC_NA);
              proto_tree_add_bits_item(syncookie_ti, hf_tcp_syncookie_mss, tvb, (offset + 4) * 8 + 5, 3, ENC_NA);
              proto_tree_add_item(syncookie_ti, hf_tcp_syncookie_hash, tvb, offset + 4 + 1, 3, ENC_NA);
            }

        } else {
            proto_tree_add_uint(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq);
            hide_seqack_abs_item = proto_tree_add_uint(tcp_tree, hf_tcp_seq_abs, tvb, offset + 4, 4, tcph->th_rawseq);
            proto_item_set_hidden(hide_seqack_abs_item);
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
            tf = proto_tree_add_uint_bits_format_value(tcp_tree, hf_tcp_hdr_len, tvb, (offset + 12) << 3, 4, tcph->th_hlen,
                                                       ENC_BIG_ENDIAN, "%u bytes (%u)", tcph->th_hlen, tcph->th_hlen >> 2);
            expert_add_info_format(pinfo, tf, &ei_tcp_bogus_header_length,
                                   "Bogus TCP header length (%u, must be at least %u)", tcph->th_hlen, TCPH_MIN_LEN);
        }
        return offset+12;
    }

    /* initialize or move forward the conversation completeness */
    if(tcpd) {
      if(conversation_is_new) { /* pure SYN must be sought in new conversations only */
        if((tcph->th_flags&(TH_SYN|TH_ACK))==TH_SYN) {
          conversation_completeness |= TCP_COMPLETENESS_SYNSENT;
          if(tcph->th_seglen > 0) { /* TCP Fast Open */
            conversation_completeness |= TCP_COMPLETENESS_DATA;
          }
        }
      }
      else {
          conversation_completeness  = tcpd->conversation_completeness ;

          /* SYN-ACK */
          if((tcph->th_flags&(TH_SYN|TH_ACK))==(TH_SYN|TH_ACK)) {
              conversation_completeness |= TCP_COMPLETENESS_SYNACK;
          }

          /* ACKs */
          if((tcph->th_flags&(TH_SYN|TH_ACK))==(TH_ACK)) {
              if(tcph->th_seglen>0) { /* transporting some data */
                  conversation_completeness |= TCP_COMPLETENESS_DATA;
              }
              else { /* pure ACK */
                  conversation_completeness |= TCP_COMPLETENESS_ACK;
              }
          }

          /* FIN-ACK */
          if((tcph->th_flags&(TH_FIN|TH_ACK))==(TH_FIN|TH_ACK)) {
              conversation_completeness |= TCP_COMPLETENESS_FIN;
          }

          /* RST */
          if(tcph->th_flags&(TH_RST)) {
              conversation_completeness |= TCP_COMPLETENESS_RST;
          }
      }
    }
    tcpd->conversation_completeness = conversation_completeness;

    if (tcp_summary_in_tree) {
        if(tcph->th_flags&TH_ACK) {
            proto_item_append_text(ti, ", Ack: %u", tcph->th_ack);
        }
        if (tcph->th_have_seglen)
            proto_item_append_text(ti, ", Len: %u", tcph->th_seglen);
    }
    proto_item_set_len(ti, tcph->th_hlen);
    if (tcph->th_have_seglen) {
        if(tcp_relative_seq && tcp_analyze_seq) {
            if (tcph->th_flags&(TH_SYN|TH_FIN))  {
                tf=proto_tree_add_uint_format_value(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq + 1, "%u    (relative sequence number)", nxtseq + 1);
            } else  {
                tf=proto_tree_add_uint_format_value(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq, "%u    (relative sequence number)", nxtseq);
            }
        } else {
            if (tcph->th_flags&(TH_SYN|TH_FIN))  {
                tf=proto_tree_add_uint(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq + 1);
            } else  {
                tf=proto_tree_add_uint(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq);
            }
        }
        proto_item_set_generated(tf);
    }

    tf = proto_tree_add_uint(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, tcph->th_ack);
    hide_seqack_abs_item = proto_tree_add_uint(tcp_tree, hf_tcp_ack_abs, tvb, offset + 8, 4, tcph->th_rawack);
    if (tcph->th_flags & TH_ACK) {
        if (tcp_relative_seq && tcp_analyze_seq) {
            proto_item_append_text(tf, "    (relative ack number)");
        } else {
            proto_item_set_hidden(hide_seqack_abs_item);
        }
        if ((tcph->th_flags & TH_SYN) && tcp_analyze_seq) {
            if ((tcp_relative_seq && tcph->th_ack > 1) ||
               (!tcp_relative_seq && tcpd && (tcph->th_ack - tcpd->rev->base_seq) > 1)) {
                expert_add_info(pinfo, tf, &ei_tcp_analysis_tfo_ack);
            } else if (tcpd && tcpd->tfo_syn_data) {
                expert_add_info(pinfo, tf, &ei_tcp_analysis_tfo_ignored);
            }
        }
    } else {
        /* Note if the ACK field is non-zero */
        if (tvb_get_ntohl(tvb, offset+8) != 0) {
            expert_add_info(pinfo, tf, &ei_tcp_ack_nonzero);
        }
    }

    if (tree) {
        // This should be consistent with ip.hdr_len.
        proto_tree_add_uint_bits_format_value(tcp_tree, hf_tcp_hdr_len, tvb, (offset + 12) << 3, 4, tcph->th_hlen,
            ENC_BIG_ENDIAN, "%u bytes (%u)", tcph->th_hlen, tcph->th_hlen>>2);
        tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, tvb, offset + 12, 2,
                                        tcph->th_flags, "Flags: 0x%03x (%s)", tcph->th_flags, flags_str);
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

        tf = proto_tree_add_string(field_tree, hf_tcp_flags_str, tvb, offset + 12, 2, flags_str_first_letter);
        proto_item_set_generated(tf);
        /* As discussed in bug 5541, it is better to use two separate
         * fields for the real and calculated window size.
         */
        proto_tree_add_uint(tcp_tree, hf_tcp_window_size_value, tvb, offset + 14, 2, real_window);
        scaled_pi = proto_tree_add_uint(tcp_tree, hf_tcp_window_size, tvb, offset + 14, 2, tcph->th_win);
        proto_item_set_generated(scaled_pi);

        if( !(tcph->th_flags&TH_SYN) && tcpd ) {
            switch (tcpd->fwd->win_scale) {

            case -1:
                /* Unknown */
                {
                    gint16 win_scale = tcpd->fwd->win_scale;
                    gboolean override_with_pref = FALSE;

                    /* Use preference setting (if set) */
                    if (tcp_default_window_scaling != WindowScaling_NotKnown) {
                        win_scale = (1 << tcp_default_window_scaling);
                        override_with_pref = TRUE;
                    }

                    scaled_pi = proto_tree_add_int_format_value(tcp_tree, hf_tcp_window_size_scalefactor, tvb, offset + 14, 2,
                                                          win_scale, "%d (%s)",
                                                          win_scale,
                                                          (override_with_pref) ? "missing - taken from preference" : "unknown");
                    proto_item_set_generated(scaled_pi);
                }
                break;

            case -2:
                /* No window scaling used */
                scaled_pi = proto_tree_add_int_format_value(tcp_tree, hf_tcp_window_size_scalefactor, tvb, offset + 14, 2, tcpd->fwd->win_scale, "%d (no window scaling used)", tcpd->fwd->win_scale);
                proto_item_set_generated(scaled_pi);
                break;

            default:
                /* Scaling from signalled value */
                scaled_pi = proto_tree_add_int_format_value(tcp_tree, hf_tcp_window_size_scalefactor, tvb, offset + 14, 2, 1<<tcpd->fwd->win_scale, "%d", 1<<tcpd->fwd->win_scale);
                proto_item_set_generated(scaled_pi);
            }
        }
    }

    if(tcph->th_flags & TH_SYN) {
        if(tcph->th_flags & TH_ACK) {
           expert_add_info_format(pinfo, tf_syn, &ei_tcp_connection_synack,
                                  "Connection establish acknowledge (SYN+ACK): server port %u", tcph->th_sport);
           /* Save the server port to help determine dissector used */
           tcpd->server_port = tcph->th_sport;
        }
        else {
           expert_add_info_format(pinfo, tf_syn, &ei_tcp_connection_syn,
                                  "Connection establish request (SYN): server port %u", tcph->th_dport);
           /* Save the server port to help determine dissector used */
           tcpd->server_port = tcph->th_dport;
           tcpd->ts_mru_syn = pinfo->abs_ts;
        }
        /* Remember where the next segment will start. */
        if (tcp_desegment && tcp_reassemble_out_of_order && tcpd && !PINFO_FD_VISITED(pinfo)) {
            if (tcpd->fwd->maxnextseq == 0) {
                tcpd->fwd->maxnextseq = tcph->th_seq + 1;
            }
        }
        /* Initiliaze the is_first_ack */
        tcpd->fwd->is_first_ack = TRUE;
    }
    if(tcph->th_flags & TH_FIN) {
        /* XXX - find a way to know the server port and output only that one */
        expert_add_info(pinfo, tf_fin, &ei_tcp_connection_fin);

        /* Track closing initiator.
           If it was not already closed by the reverse flow, it means we are the first */
        if(!tcpd->rev->closing_initiator) {
            tcpd->fwd->closing_initiator = TRUE;
            expert_add_info(pinfo, tf, &ei_tcp_connection_fin_active);
        } else {
            expert_add_info(pinfo, tf, &ei_tcp_connection_fin_passive);
        }
    }
    if(tcph->th_flags & TH_RST)
        /* XXX - find a way to know the server port and output only that one */
        expert_add_info(pinfo, tf_rst, &ei_tcp_connection_rst);

    if(tcp_analyze_seq
            && (tcph->th_flags & (TH_SYN|TH_ACK)) == TH_ACK
            && !nstime_is_zero(&tcpd->ts_mru_syn)
            &&  nstime_is_zero(&tcpd->ts_first_rtt)) {
        /* If all of the following:
         * - we care (the pref is set)
         * - this is a pure ACK
         * - we have a timestamp for the most-recently-transmitted SYN
         * - we haven't seen a pure ACK yet (no ts_first_rtt stored)
         * then assume it's the last part of the handshake and store the initial
         * RTT time
         */
        nstime_delta(&(tcpd->ts_first_rtt), &(pinfo->abs_ts), &(tcpd->ts_mru_syn));
    }

    /*
     * Remember if we have already seen at least one ACK,
     * then we can neutralize the Window Scale side-effect at the beginning (issue 14690)
     */
    if(tcp_analyze_seq
            && (tcph->th_flags & (TH_SYN|TH_ACK)) == TH_ACK) {
        if(tcpd->fwd->is_first_ack) {
            tcpd->fwd->is_first_ack = FALSE;
        }
    }

    /* Supply the sequence number of the first byte and of the first byte
       after the segment. */
    tcpinfo.seq = tcph->th_seq;
    tcpinfo.nxtseq = nxtseq;
    tcpinfo.lastackseq = tcph->th_ack;

    /* Assume we'll pass un-reassembled data to subdissectors. */
    tcpinfo.is_reassembled = FALSE;

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
            SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data, pinfo->src.len);
            SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data, pinfo->dst.len);
            switch (pinfo->src.type) {

            case AT_IPv4:
                phdr[0] = g_htonl((IP_PROTO_TCP<<16) + reported_len);
                SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)phdr, 4);
                break;

            case AT_IPv6:
                phdr[0] = g_htonl(reported_len);
                phdr[1] = g_htonl(IP_PROTO_TCP);
                SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)phdr, 8);
                break;

            default:
                /* TCP runs only atop IPv4 and IPv6.... */
                DISSECTOR_ASSERT_NOT_REACHED();
                break;
            }
            SET_CKSUM_VEC_TVB(cksum_vec[3], tvb, offset, reported_len);
            computed_cksum = in_cksum(cksum_vec, 4);
            if (computed_cksum == 0 && th_sum == 0xffff) {
                item = proto_tree_add_uint_format_value(tcp_tree, hf_tcp_checksum, tvb,
                                                  offset + 16, 2, th_sum,
                                                  "0x%04x [should be 0x0000 (see RFC 1624)]", th_sum);

                checksum_tree = proto_item_add_subtree(item, ett_tcp_checksum);
                item = proto_tree_add_uint(checksum_tree, hf_tcp_checksum_calculated, tvb,
                                              offset + 16, 2, 0x0000);
                proto_item_set_generated(item);
                /* XXX - What should this special status be? */
                item = proto_tree_add_uint(checksum_tree, hf_tcp_checksum_status, tvb,
                                              offset + 16, 0, PROTO_CHECKSUM_E_BAD);
                proto_item_set_generated(item);
                expert_add_info(pinfo, item, &ei_tcp_checksum_ffff);

                col_append_str(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM 0xFFFF]");

                /* Checksum is treated as valid on most systems, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else {
                proto_item* calc_item;
                item = proto_tree_add_checksum(tcp_tree, tvb, offset+16, hf_tcp_checksum, hf_tcp_checksum_status, &ei_tcp_checksum_bad, pinfo, computed_cksum,
                                               ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);

                calc_item = proto_tree_add_uint(tcp_tree, hf_tcp_checksum_calculated, tvb,
                                              offset + 16, 2, in_cksum_shouldbe(th_sum, computed_cksum));
                proto_item_set_generated(calc_item);

                /* Checksum is valid, so we're willing to desegment it. */
                if (computed_cksum == 0) {
                    desegment_ok = TRUE;
                } else {
                    proto_item_append_text(item, "(maybe caused by \"TCP checksum offload\"?)");

                    /* Checksum is invalid, so we're not willing to desegment it. */
                    desegment_ok = FALSE;
                    pinfo->noreassembly_reason = " [incorrect TCP checksum]";
                    col_append_str(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM INCORRECT]");
                }
            }
        } else {
            proto_tree_add_checksum(tcp_tree, tvb, offset+16, hf_tcp_checksum, hf_tcp_checksum_status, &ei_tcp_checksum_bad, pinfo, 0,
                                    ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

            /* We didn't check the checksum, and don't care if it's valid,
               so we're willing to desegment it. */
            desegment_ok = TRUE;
        }
    } else {
        /* We don't have all the packet data, so we can't checksum it... */
        proto_tree_add_checksum(tcp_tree, tvb, offset+16, hf_tcp_checksum, hf_tcp_checksum_status, &ei_tcp_checksum_bad, pinfo, 0,
                                    ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

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

    item = proto_tree_add_item_ret_uint(tcp_tree, hf_tcp_urgent_pointer, tvb, offset + 18, 2, ENC_BIG_ENDIAN, &th_urp);

    if (IS_TH_URG(tcph->th_flags)) {
        /* Export the urgent pointer, for the benefit of protocols such as
           rlogin. */
        tcpinfo.urgent_pointer = (guint16)th_urp;
        tcp_info_append_uint(pinfo, "Urg", th_urp);
    } else {
         if (th_urp) {
            /* Note if the urgent pointer field is non-zero */
            expert_add_info(pinfo, item, &ei_tcp_urgent_pointer_non_zero);
         }
    }

    if (tcph->th_have_seglen)
        tcp_info_append_uint(pinfo, "Len", tcph->th_seglen);

    /* If there's more than just the fixed-length header (20 bytes), create
       a protocol tree item for the options.  (We already know there's
       not less than the fixed-length header - we checked that above.)

       We ensure that we don't throw an exception here, so that we can
       do some analysis before we dissect the options and possibly
       throw an exception.  (Trying to avoid throwing an exception when
       dissecting options is not something we should do.) */
    optlen = tcph->th_hlen - TCPH_MIN_LEN; /* length of options, in bytes */
    options_item = NULL;
    options_tree = NULL;
    if (optlen != 0) {
        guint bc = (guint)tvb_captured_length_remaining(tvb, offset + 20);

        if (tcp_tree != NULL) {
            options_item = proto_tree_add_item(tcp_tree, hf_tcp_options, tvb, offset + 20,
                                               bc < optlen ? bc : optlen, ENC_NA);
            proto_item_set_text(options_item, "Options: (%u bytes)", optlen);
            options_tree = proto_item_add_subtree(options_item, ett_tcp_options);
        }
    }

    tcph->num_sack_ranges = 0;

    /* handle conversation timestamps */
    if(tcp_calculate_ts) {
        tcp_print_timestamps(pinfo, tvb, tcp_tree, tcpd, tcppd);
    }

    /* Now dissect the options. */
    if (optlen) {
        rvbd_option_data* option_data;

        tcp_dissect_options(tvb, offset + 20, optlen,
                               TCPOPT_EOL, pinfo, options_tree,
                               options_item, tcph);

        /* Do some post evaluation of some Riverbed probe options in the list */
        option_data = (rvbd_option_data*)p_get_proto_data(pinfo->pool, pinfo, proto_tcp_option_rvbd_probe, pinfo->curr_layer_num);
        if (option_data != NULL)
        {
            if (option_data->valid)
            {
                /* Distinguish S+ from S+* */
                col_prepend_fstr(pinfo->cinfo, COL_INFO, "S%s, ",
                                     option_data->type == PROBE_TRACE ? "#" :
                                     (option_data->probe_flags & RVBD_FLAGS_PROBE_NCFE) ? "+*" : "+");
            }
        }

    }

    /* handle TCP seq# analysis, print any extra SEQ/ACK data for this segment*/
    if(tcp_analyze_seq) {
        guint32 use_seq = tcph->th_seq;
        guint32 use_ack = tcph->th_ack;
        /* May need to recover absolute values here... */
        if (tcp_relative_seq) {
            use_seq += tcpd->fwd->base_seq;
            if (tcph->th_flags & TH_ACK) {
                use_ack += tcpd->rev->base_seq;
            }
        }
        tcp_print_sequence_number_analysis(pinfo, tvb, tcp_tree, tcpd, use_seq, use_ack);
    }

    if(!pinfo->fd->visited) {
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

    if (tcph->th_mptcp) {

        if (tcp_analyze_mptcp) {
            mptcp_add_analysis_subtree(pinfo, tvb, tcp_tree, tcpd, tcpd->mptcp_analysis, tcph );
        }
    }

    /* Skip over header + options */
    offset += tcph->th_hlen;

    /* Check the packet length to see if there's more data
       (it could be an ACK-only packet) */
    captured_length_remaining = tvb_captured_length_remaining(tvb, offset);

    if (tcph->th_have_seglen) {
        if(have_tap_listener(tcp_follow_tap)) {
            tcp_follow_tap_data_t* follow_data = wmem_new0(pinfo->pool, tcp_follow_tap_data_t);

            follow_data->tvb = tvb_new_subset_remaining(tvb, offset);
            follow_data->tcph = tcph;
            follow_data->tcpd = tcpd;

            tap_queue_packet(tcp_follow_tap, pinfo, follow_data);
        }
    }

    tap_queue_packet(tcp_tap, pinfo, tcph);

    /* if it is an MPTCP packet */
    if(tcpd->mptcp_analysis) {
        tap_queue_packet(mptcp_tap, pinfo, tcpd);
    }

    /* If we're reassembling something whose length isn't known
     * beforehand, and that runs all the way to the end of
     * the data stream, a FIN indicates the end of the data
     * stream and thus the completion of reassembly, so we
     * need to explicitly check for that here.
     */
    if(tcph->th_have_seglen && tcpd && (tcph->th_flags & TH_FIN)
       && (tcpd->fwd->flags&TCP_FLOW_REASSEMBLE_UNTIL_FIN) ) {
        struct tcp_multisegment_pdu *msp;

        /* Is this the FIN that ended the data stream or is it a
         * retransmission of that FIN?
         */
        if (tcpd->fwd->fin == 0 || tcpd->fwd->fin == pinfo->num) {
            /* Either we haven't seen a FIN for this flow or we
             * have and it's this frame. Note that this is the FIN
             * for this flow, terminate reassembly and dissect the
             * results. */
            tcpd->fwd->fin = pinfo->num;
            msp=(struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(tcpd->fwd->multisegment_pdus, tcph->th_seq-1);
            if(msp) {
                fragment_head *ipfd_head;

                ipfd_head = fragment_add(&tcp_reassembly_table, tvb, offset,
                                         pinfo, msp->first_frame, msp,
                                         tcph->th_seq - msp->seq,
                                         tcph->th_seglen,
                                         FALSE );
                if(ipfd_head && ipfd_head->reassembled_in == pinfo->num && ipfd_head->reas_in_layer_num == pinfo->curr_layer_num) {
                    tvbuff_t *next_tvb;

                    /* create a new TVB structure for desegmented data
                     * datalen-1 to strip the dummy FIN byte off
                     */
                    next_tvb = tvb_new_chain(tvb, ipfd_head->tvb_data);

                    /* add desegmented data to the data source list */
                    add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

                    /* Show details of the reassembly */
                    print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);

                    /* call the payload dissector
                     * but make sure we don't offer desegmentation any more
                     */
                    pinfo->can_desegment = 0;

                    process_tcp_payload(next_tvb, 0, pinfo, tree, tcp_tree, tcph->th_sport, tcph->th_dport, tcph->th_seq,
                                        nxtseq, FALSE, tcpd, &tcpinfo);

                    return tvb_captured_length(tvb);
                }
            }
        } else {
            /* Yes.  This is a retransmission of the final FIN (or it's
             * the final FIN transmitted via a different path).
             * XXX - we need to flag retransmissions a bit better.
             */
            proto_tree_add_uint(tcp_tree, hf_tcp_fin_retransmission, tvb, 0, 0, tcpd->fwd->fin);
        }
    }

    if (tcp_display_process_info && tcpd && ((tcpd->fwd && tcpd->fwd->process_info && tcpd->fwd->process_info->command) ||
                 (tcpd->rev && tcpd->rev->process_info && tcpd->rev->process_info->command))) {
        field_tree = proto_tree_add_subtree(tcp_tree, tvb, offset, 0, ett_tcp_process_info, &ti, "Process Information");
        proto_item_set_generated(ti);
        if (tcpd->fwd && tcpd->fwd->process_info && tcpd->fwd->process_info->command) {
            proto_tree_add_uint(field_tree, hf_tcp_proc_dst_uid, tvb, 0, 0, tcpd->fwd->process_info->process_uid);
            proto_tree_add_uint(field_tree, hf_tcp_proc_dst_pid, tvb, 0, 0, tcpd->fwd->process_info->process_pid);
            proto_tree_add_string(field_tree, hf_tcp_proc_dst_uname, tvb, 0, 0, tcpd->fwd->process_info->username);
            proto_tree_add_string(field_tree, hf_tcp_proc_dst_cmd, tvb, 0, 0, tcpd->fwd->process_info->command);
        }
        if (tcpd->rev && tcpd->rev->process_info && tcpd->rev->process_info->command) {
            proto_tree_add_uint(field_tree, hf_tcp_proc_src_uid, tvb, 0, 0, tcpd->rev->process_info->process_uid);
            proto_tree_add_uint(field_tree, hf_tcp_proc_src_pid, tvb, 0, 0, tcpd->rev->process_info->process_pid);
            proto_tree_add_string(field_tree, hf_tcp_proc_src_uname, tvb, 0, 0, tcpd->rev->process_info->username);
            proto_tree_add_string(field_tree, hf_tcp_proc_src_cmd, tvb, 0, 0, tcpd->rev->process_info->command);
        }
    }

    /*
     * XXX - what, if any, of this should we do if this is included in an
     * error packet?  It might be nice to see the details of the packet
     * that caused the ICMP error, but it might not be nice to have the
     * dissector update state based on it.
     * Also, we probably don't want to run TCP taps on those packets.
     */
    if (captured_length_remaining != 0) {
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
            proto_tree_add_item(tcp_tree, hf_tcp_reset_cause, tvb, offset, captured_length_remaining, ENC_NA|ENC_ASCII);
        } else {
        /* When we have a frame with TCP SYN bit set and segmented TCP payload we need
         * to increment seq and nxtseq to detect the overlapping byte(s). This is to fix Bug 9882.
         */
            if(tcph->th_flags & TH_SYN) {
                dissect_tcp_payload(tvb, pinfo, offset, tcph->th_seq + 1, nxtseq + 1,
                                    tcph->th_sport, tcph->th_dport, tree, tcp_tree, tcpd, &tcpinfo);
            } else {
                dissect_tcp_payload(tvb, pinfo, offset, tcph->th_seq, nxtseq,
                                    tcph->th_sport, tcph->th_dport, tree, tcp_tree, tcpd, &tcpinfo);
            }
        }
    }
    return tvb_captured_length(tvb);
}

static void
tcp_init(void)
{
    tcp_stream_count = 0;

    /* MPTCP init */
    mptcp_stream_count = 0;
    mptcp_tokens = wmem_tree_new(wmem_file_scope());
}

void
proto_register_tcp(void)
{
    static hf_register_info hf[] = {

        { &hf_tcp_srcport,
        { "Source Port",        "tcp.srcport", FT_UINT16, BASE_PT_TCP, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_dstport,
        { "Destination Port",       "tcp.dstport", FT_UINT16, BASE_PT_TCP, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_port,
        { "Source or Destination Port", "tcp.port", FT_UINT16, BASE_PT_TCP, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_stream,
        { "Stream index",       "tcp.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_completeness,
        { "Conversation completeness",       "tcp.completeness", FT_UINT8,
            BASE_CUSTOM, CF_FUNC(conversation_completeness_fill), 0x0,
            "The completeness of the conversation capture", HFILL }},

        { &hf_tcp_seq,
        { "Sequence Number",        "tcp.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_seq_abs,
        { "Sequence Number (raw)",        "tcp.seq_raw", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This shows the raw value of the sequence number", HFILL }},

        { &hf_tcp_nxtseq,
        { "Next Sequence Number",   "tcp.nxtseq", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_ack,
        { "Acknowledgment Number", "tcp.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_ack_abs,
        { "Acknowledgment number (raw)", "tcp.ack_raw", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This shows the raw value of the acknowledgment number", HFILL } },

        // "Data Offset" in https://tools.ietf.org/html/rfc793#section-3.1 and
        // "Data offset" in https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
        { &hf_tcp_hdr_len,
        { "Header Length",    "tcp.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Data offset in 32-bit words", HFILL }},

        { &hf_tcp_flags,
        { "Flags",          "tcp.flags", FT_UINT16, BASE_HEX, NULL, TH_MASK,
            "Flags (12 bits)", HFILL }},

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

        { &hf_tcp_flags_str,
        { "TCP Flags",          "tcp.flags.str", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_window_size_value,
        { "Window",        "tcp.window_size_value", FT_UINT16, BASE_DEC, NULL, 0x0,
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
            "Details at: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

        { &hf_tcp_checksum_status,
        { "Checksum Status",      "tcp.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }},

        { &hf_tcp_checksum_calculated,
        { "Calculated Checksum", "tcp.checksum_calculated", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The expected TCP checksum field as calculated from the TCP segment", HFILL }},

        { &hf_tcp_analysis,
        { "SEQ/ACK analysis",   "tcp.analysis", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the TCP analysis shown", HFILL }},

        { &hf_tcp_analysis_flags,
        { "TCP Analysis Flags",     "tcp.analysis.flags", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the TCP analysis flags set", HFILL }},

        { &hf_tcp_analysis_duplicate_ack,
        { "Duplicate ACK",      "tcp.analysis.duplicate_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a duplicate ACK", HFILL }},

        { &hf_tcp_analysis_duplicate_ack_num,
        { "Duplicate ACK #",        "tcp.analysis.duplicate_ack_num", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This is duplicate ACK number #", HFILL }},

        { &hf_tcp_analysis_duplicate_ack_frame,
        { "Duplicate to the ACK in frame",      "tcp.analysis.duplicate_ack_frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_DUP_ACK), 0x0,
            "This is a duplicate to the ACK in frame #", HFILL }},

        { &hf_tcp_continuation_to,
        { "This is a continuation to the PDU in frame",     "tcp.continuation_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is a continuation to the PDU in frame #", HFILL }},

        { &hf_tcp_len,
          { "TCP Segment Len",            "tcp.len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_analysis_acks_frame,
          { "This is an ACK to the segment in frame",            "tcp.analysis.acks_frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0,
            "Which previous segment is this an ACK for", HFILL}},

        { &hf_tcp_analysis_bytes_in_flight,
          { "Bytes in flight",            "tcp.analysis.bytes_in_flight", FT_UINT32, BASE_DEC, NULL, 0x0,
            "How many bytes are now in flight for this connection", HFILL}},

        { &hf_tcp_analysis_push_bytes_sent,
          { "Bytes sent since last PSH flag",            "tcp.analysis.push_bytes_sent", FT_UINT32, BASE_DEC, NULL, 0x0,
            "How many bytes have been sent since the last PSH flag", HFILL}},

        { &hf_tcp_analysis_ack_rtt,
          { "The RTT to ACK the segment was",            "tcp.analysis.ack_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long time it took to ACK the segment (RTT)", HFILL}},

        { &hf_tcp_analysis_first_rtt,
          { "iRTT",            "tcp.analysis.initial_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long it took for the SYN to ACK handshake (iRTT)", HFILL}},

        { &hf_tcp_analysis_rto,
          { "The RTO for this segment was",            "tcp.analysis.rto", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long transmission was delayed before this segment was retransmitted (RTO)", HFILL}},

        { &hf_tcp_analysis_rto_frame,
          { "RTO based on delta from frame", "tcp.analysis.rto_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is the frame we measure the RTO from", HFILL }},

        { &hf_tcp_urgent_pointer,
        { "Urgent Pointer",     "tcp.urgent_pointer", FT_UINT16, BASE_DEC, NULL, 0x0,
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
            BASE_DEC|BASE_EXT_STRING, &tcp_option_kind_vs_ext, 0x0, "This TCP option's kind", HFILL }},

        { &hf_tcp_option_len,
          { "Length", "tcp.option_len", FT_UINT8,
            BASE_DEC, NULL, 0x0, "Length of this TCP option in bytes (including kind and length fields)", HFILL }},

        { &hf_tcp_options,
          { "TCP Options", "tcp.options", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_mss_val,
          { "MSS Value", "tcp.options.mss_val", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_wscale_shift,
          { "Shift count", "tcp.options.wscale.shift", FT_UINT8,
            BASE_DEC, NULL, 0x0, "Logarithmically encoded power of 2 scale factor", HFILL}},

        { &hf_tcp_option_wscale_multiplier,
          { "Multiplier", "tcp.options.wscale.multiplier",  FT_UINT16,
            BASE_DEC, NULL, 0x0, "Multiply segment window size by this for scaled window size", HFILL}},

        { &hf_tcp_option_exp_data,
          { "Data", "tcp.options.experimental.data", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_exp_magic_number,
          { "Magic Number", "tcp.options.experimental.magic_number", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_unknown_payload,
          { "Payload", "tcp.options.unknown.payload", FT_BYTES,
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

        { &hf_tcp_option_sack_dsack_le,
          {"TCP D-SACK Left Edge", "tcp.options.sack.dsack_le", FT_UINT32,
           BASE_DEC, NULL, 0x0, "Duplicate SACK Left Edge", HFILL}},

        { &hf_tcp_option_sack_dsack_re,
          {"TCP D-SACK Right Edge", "tcp.options.sack.dsack_re", FT_UINT32,
           BASE_DEC, NULL, 0x0, "Duplicate SACK Right Edge", HFILL}},

        { &hf_tcp_option_echo,
          { "TCP Echo Option", "tcp.options.echo_value", FT_UINT32,
            BASE_DEC, NULL, 0x0, "TCP Sack Echo", HFILL}},

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

        { &hf_tcp_option_mptcp_reserved,
          { "Reserved", "tcp.options.mptcp.reserved", FT_UINT16,
            BASE_HEX, NULL, 0x0FFF, NULL, HFILL}},

        { &hf_tcp_option_mptcp_flags,
          { "Multipath TCP flags", "tcp.options.mptcp.flags", FT_UINT8,
            BASE_HEX, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_backup_flag,
          { "Backup flag", "tcp.options.mptcp.backup.flag", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_checksum_flag,
          { "Checksum required", "tcp.options.mptcp.checksumreq.flags", FT_UINT8,
            BASE_DEC, NULL, MPTCP_CHECKSUM_MASK, NULL, HFILL}},

        { &hf_tcp_option_mptcp_B_flag,
          { "Extensibility", "tcp.options.mptcp.extensibility.flag", FT_UINT8,
            BASE_DEC, NULL, 0x40, NULL, HFILL}},

        { &hf_tcp_option_mptcp_C_flag,
          { "Do not attempt to establish new subflows to this address and port", "tcp.options.mptcp.nomoresubflows.flag", FT_UINT8,
            BASE_DEC, NULL, 0x20, NULL, HFILL}},

        { &hf_tcp_option_mptcp_H_v0_flag,
          { "Use HMAC-SHA1", "tcp.options.mptcp.sha1.flag", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_H_v1_flag,
          { "Use HMAC-SHA256", "tcp.options.mptcp.sha256.flag", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_F_flag,
          { "DATA_FIN", "tcp.options.mptcp.datafin.flag", FT_UINT8,
            BASE_DEC, NULL, MPTCP_DSS_FLAG_DATA_FIN_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_m_flag,
          { "Data Sequence Number is 8 octets", "tcp.options.mptcp.dseqn8.flag", FT_UINT8,
            BASE_DEC, NULL, MPTCP_DSS_FLAG_DSN_8BYTES, NULL, HFILL}},

        { &hf_tcp_option_mptcp_M_flag,
          { "Data Sequence Number, Subflow Sequence Number, Data-level Length, Checksum present", "tcp.options.mptcp.dseqnpresent.flag", FT_UINT8,
            BASE_DEC, NULL, MPTCP_DSS_FLAG_MAPPING_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_a_flag,
          { "Data ACK is 8 octets", "tcp.options.mptcp.dataack8.flag", FT_UINT8,
            BASE_DEC, NULL, MPTCP_DSS_FLAG_DATA_ACK_8BYTES, NULL, HFILL}},

        { &hf_tcp_option_mptcp_A_flag,
          { "Data ACK is present", "tcp.options.mptcp.dataackpresent.flag", FT_UINT8,
            BASE_DEC, NULL, MPTCP_DSS_FLAG_DATA_ACK_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_reserved_v0_flag,
          { "Reserved", "tcp.options.mptcp.reserved.flag", FT_UINT8,
            BASE_HEX, NULL, 0x3E, NULL, HFILL}},

        { &hf_tcp_option_mptcp_reserved_v1_flag,
          { "Reserved", "tcp.options.mptcp.reserved.flag", FT_UINT8,
            BASE_HEX, NULL, 0x1E, NULL, HFILL}},

        { &hf_tcp_option_mptcp_U_flag,
          { "Flag U", "tcp.options.mptcp.flag_U.flag", FT_BOOLEAN,
            4, TFS(&tfs_set_notset), MPTCP_TCPRST_FLAG_U_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_V_flag,
          { "Flag V", "tcp.options.mptcp.flag_V.flag", FT_BOOLEAN,
            4, TFS(&tfs_set_notset), MPTCP_TCPRST_FLAG_V_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_W_flag,
          { "Flag W", "tcp.options.mptcp.flag_W.flag", FT_BOOLEAN,
            4, TFS(&tfs_set_notset), MPTCP_TCPRST_FLAG_W_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_T_flag,
          { "Transient", "tcp.options.mptcp.flag_T.flag", FT_BOOLEAN,
            4, TFS(&tfs_set_notset), MPTCP_TCPRST_FLAG_T_PRESENT, NULL, HFILL}},

        { &hf_tcp_option_mptcp_tcprst_reason,
          { "TCPRST Reason", "tcp.options.mptcp.rst_reason", FT_UINT8,
            BASE_HEX, VALS(mp_tcprst_reasons), 0x0, "Multipath TCPRST Reason Code", HFILL}},

        { &hf_tcp_option_mptcp_address_id,
          { "Address ID", "tcp.options.mptcp.addrid", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_key,
          { "Sender's Key", "tcp.options.mptcp.sendkey", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_recv_key,
          { "Receiver's Key", "tcp.options.mptcp.recvkey", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_recv_token,
          { "Receiver's Token", "tcp.options.mptcp.recvtok", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_rand,
          { "Sender's Random Number", "tcp.options.mptcp.sendrand", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_trunc_hmac,
          { "Sender's Truncated HMAC", "tcp.options.mptcp.sendtrunchmac", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_sender_hmac,
          { "Sender's HMAC", "tcp.options.mptcp.sendhmac", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_addaddr_trunc_hmac,
          { "Truncated HMAC", "tcp.options.mptcp.addaddrtrunchmac", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_data_ack_raw,
          { "Original MPTCP Data ACK", "tcp.options.mptcp.rawdataack", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_data_seq_no_raw,
          { "Data Sequence Number", "tcp.options.mptcp.rawdataseqno", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_subflow_seq_no,
          { "Subflow Sequence Number", "tcp.options.mptcp.subflowseqno", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_data_lvl_len,
          { "Data-level Length", "tcp.options.mptcp.datalvllen", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_checksum,
          { "Checksum", "tcp.options.mptcp.checksum", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_ipver,
          { "IP version", "tcp.options.mptcp.ipver", FT_UINT8,
            BASE_DEC, NULL, 0x0F, NULL, HFILL}},

        { &hf_tcp_option_mptcp_echo,
          { "Echo", "tcp.options.mptcp.echo", FT_UINT8,
            BASE_DEC, NULL, 0x01, NULL, HFILL}},

        { &hf_tcp_option_mptcp_ipv4,
          { "Advertised IPv4 Address", "tcp.options.mptcp.ipv4", FT_IPv4,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_ipv6,
          { "Advertised IPv6 Address", "tcp.options.mptcp.ipv6", FT_IPv6,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_mptcp_port,
          { "Advertised port", "tcp.options.mptcp.port", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_cc,
          { "TCP CC Option", "tcp.options.cc_value", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_md5_digest,
          { "MD5 digest", "tcp.options.md5.digest", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ao_keyid,
          { "AO KeyID", "tcp.options.ao.keyid", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ao_rnextkeyid,
          { "AO RNextKeyID", "tcp.options.ao.rnextkeyid", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ao_mac,
          { "AO MAC", "tcp.options.ao.mac", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_qs_rate,
          { "QS Rate", "tcp.options.qs.rate", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &qs_rate_vals_ext, 0x0F, NULL, HFILL}},

        { &hf_tcp_option_qs_ttl_diff,
          { "QS Rate", "tcp.options.qs.ttl_diff", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

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

        { &hf_tcp_option_user_to_granularity,
          { "Granularity", "tcp.options.user_to_granularity", FT_BOOLEAN,
            16, TFS(&tcp_option_user_to_granularity), 0x8000, "TCP User Timeout Granularity", HFILL}},

        { &hf_tcp_option_user_to_val,
          { "User Timeout", "tcp.options.user_to_val", FT_UINT16,
            BASE_DEC, NULL, 0x7FFF, "TCP User Timeout Value", HFILL}},

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

        { &hf_tcp_option_fast_open_cookie_request,
          { "Fast Open Cookie Request", "tcp.options.tfo.request", FT_NONE,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_fast_open_cookie,
          { "Fast Open Cookie", "tcp.options.tfo.cookie", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

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

        { &hf_tcp_segment_data,
          { "TCP segment data", "tcp.segment_data", FT_BYTES, BASE_NONE, NULL, 0x0,
            "A data segment used in reassembly of a lower-level protocol", HFILL}},

        { &hf_tcp_payload,
          { "TCP payload", "tcp.payload", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The TCP payload of this packet", HFILL}},

        { &hf_tcp_option_scps_binding_data,
          { "Binding Space Data", "tcp.options.scps.binding.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_reserved,
          { "Reserved", "tcp.options.rvbd.probe.reserved", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_fin_retransmission,
          { "Retransmission of FIN from frame", "tcp.fin_retransmission", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_reset_cause,
          { "Reset cause", "tcp.reset_cause", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_time,
          { "SYN Cookie Time", "tcp.syncookie.time", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_mss,
          { "SYN Cookie Maximum Segment Size", "tcp.syncookie.mss", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_hash,
          { "SYN Cookie hash", "tcp.syncookie.hash", FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_option_timestamp,
          { "SYN Cookie Timestamp", "tcp.options.timestamp.tsval.syncookie.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_option_ecn,
          { "SYN Cookie ECN", "tcp.options.timestamp.tsval.syncookie.ecn", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_option_sack,
          { "SYN Cookie SACK", "tcp.options.timestamp.tsval.syncookie.sack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_syncookie_option_wscale,
          { "SYN Cookie WScale", "tcp.options.timestamp.tsval.syncookie.wscale", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_tcp,
        &ett_tcp_flags,
        &ett_tcp_options,
        &ett_tcp_option_timestamp,
        &ett_tcp_option_mptcp,
        &ett_tcp_option_wscale,
        &ett_tcp_option_sack,
        &ett_tcp_option_snack,
        &ett_tcp_option_scps,
        &ett_tcp_scpsoption_flags,
        &ett_tcp_option_scps_extended,
        &ett_tcp_option_user_to,
        &ett_tcp_option_exp,
        &ett_tcp_option_sack_perm,
        &ett_tcp_option_mss,
        &ett_tcp_opt_rvbd_probe,
        &ett_tcp_opt_rvbd_probe_flags,
        &ett_tcp_opt_rvbd_trpy,
        &ett_tcp_opt_rvbd_trpy_flags,
        &ett_tcp_opt_echo,
        &ett_tcp_opt_cc,
        &ett_tcp_opt_md5,
        &ett_tcp_opt_ao,
        &ett_tcp_opt_qs,
        &ett_tcp_analysis_faults,
        &ett_tcp_analysis,
        &ett_tcp_timestamps,
        &ett_tcp_segments,
        &ett_tcp_segment,
        &ett_tcp_checksum,
        &ett_tcp_process_info,
        &ett_tcp_unknown_opt,
        &ett_tcp_opt_recbound,
        &ett_tcp_opt_scpscor,
        &ett_tcp_option_other,
        &ett_tcp_syncookie,
        &ett_tcp_syncookie_option
    };

    static gint *mptcp_ett[] = {
        &ett_mptcp_analysis,
        &ett_mptcp_analysis_subflows
    };

    static const enum_val_t window_scaling_vals[] = {
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

    static ei_register_info ei[] = {
        { &ei_tcp_opt_len_invalid, { "tcp.option.len.invalid", PI_SEQUENCE, PI_NOTE, "Invalid length for option", EXPFILL }},
        { &ei_tcp_analysis_retransmission, { "tcp.analysis.retransmission", PI_SEQUENCE, PI_NOTE, "This frame is a (suspected) retransmission", EXPFILL }},
        { &ei_tcp_analysis_fast_retransmission, { "tcp.analysis.fast_retransmission", PI_SEQUENCE, PI_NOTE, "This frame is a (suspected) fast retransmission", EXPFILL }},
        { &ei_tcp_analysis_spurious_retransmission, { "tcp.analysis.spurious_retransmission", PI_SEQUENCE, PI_NOTE, "This frame is a (suspected) spurious retransmission", EXPFILL }},
        { &ei_tcp_analysis_out_of_order, { "tcp.analysis.out_of_order", PI_SEQUENCE, PI_WARN, "This frame is a (suspected) out-of-order segment", EXPFILL }},
        { &ei_tcp_analysis_reused_ports, { "tcp.analysis.reused_ports", PI_SEQUENCE, PI_NOTE, "A new tcp session is started with the same ports as an earlier session in this trace", EXPFILL }},
        { &ei_tcp_analysis_lost_packet, { "tcp.analysis.lost_segment", PI_SEQUENCE, PI_WARN, "Previous segment(s) not captured (common at capture start)", EXPFILL }},
        { &ei_tcp_analysis_ack_lost_packet, { "tcp.analysis.ack_lost_segment", PI_SEQUENCE, PI_WARN, "ACKed segment that wasn't captured (common at capture start)", EXPFILL }},
        { &ei_tcp_analysis_window_update, { "tcp.analysis.window_update", PI_SEQUENCE, PI_CHAT, "TCP window update", EXPFILL }},
        { &ei_tcp_analysis_window_full, { "tcp.analysis.window_full", PI_SEQUENCE, PI_WARN, "TCP window specified by the receiver is now completely full", EXPFILL }},
        { &ei_tcp_analysis_keep_alive, { "tcp.analysis.keep_alive", PI_SEQUENCE, PI_NOTE, "TCP keep-alive segment", EXPFILL }},
        { &ei_tcp_analysis_keep_alive_ack, { "tcp.analysis.keep_alive_ack", PI_SEQUENCE, PI_NOTE, "ACK to a TCP keep-alive segment", EXPFILL }},
        { &ei_tcp_analysis_duplicate_ack, { "tcp.analysis.duplicate_ack", PI_SEQUENCE, PI_NOTE, "Duplicate ACK", EXPFILL }},
        { &ei_tcp_analysis_zero_window_probe, { "tcp.analysis.zero_window_probe", PI_SEQUENCE, PI_NOTE, "TCP Zero Window Probe", EXPFILL }},
        { &ei_tcp_analysis_zero_window, { "tcp.analysis.zero_window", PI_SEQUENCE, PI_WARN, "TCP Zero Window segment", EXPFILL }},
        { &ei_tcp_analysis_zero_window_probe_ack, { "tcp.analysis.zero_window_probe_ack", PI_SEQUENCE, PI_NOTE, "ACK to a TCP Zero Window Probe", EXPFILL }},
        { &ei_tcp_analysis_tfo_syn, { "tcp.analysis.tfo_syn", PI_SEQUENCE, PI_NOTE, "TCP SYN with TFO Cookie", EXPFILL }},
        { &ei_tcp_analysis_tfo_ack, { "tcp.analysis.tfo_ack", PI_SEQUENCE, PI_NOTE, "TCP SYN-ACK accepting TFO data", EXPFILL }},
        { &ei_tcp_analysis_tfo_ignored, { "tcp.analysis.tfo_ignored", PI_SEQUENCE, PI_NOTE, "TCP SYN-ACK ignoring TFO data", EXPFILL }},
        { &ei_tcp_connection_fin_active, { "tcp.connection.fin_active", PI_SEQUENCE, PI_NOTE, "This frame initiates the connection closing", EXPFILL }},
        { &ei_tcp_connection_fin_passive, { "tcp.connection.fin_passive", PI_SEQUENCE, PI_NOTE, "This frame undergoes the connection closing", EXPFILL }},
        { &ei_tcp_scps_capable, { "tcp.analysis.zero_window_probe_ack", PI_SEQUENCE, PI_NOTE, "Connection establish request (SYN-ACK): SCPS Capabilities Negotiated", EXPFILL }},
        { &ei_tcp_option_sack_dsack, { "tcp.options.sack.dsack", PI_SEQUENCE, PI_WARN, "D-SACK Sequence", EXPFILL }},
        { &ei_tcp_option_snack_sequence, { "tcp.options.snack.sequence", PI_SEQUENCE, PI_NOTE, "SNACK Sequence", EXPFILL }},
        { &ei_tcp_option_wscale_shift_invalid, { "tcp.options.wscale.shift.invalid", PI_PROTOCOL, PI_WARN, "Window scale shift exceeds 14", EXPFILL }},
        { &ei_tcp_option_mss_absent, { "tcp.options.mss.absent", PI_PROTOCOL, PI_NOTE, "The SYN packet does not contain a MSS option", EXPFILL }},
        { &ei_tcp_option_mss_present, { "tcp.options.mss.present", PI_PROTOCOL, PI_WARN, "The non-SYN packet does contain a MSS option", EXPFILL }},
        { &ei_tcp_short_segment, { "tcp.short_segment", PI_MALFORMED, PI_WARN, "Short segment", EXPFILL }},
        { &ei_tcp_ack_nonzero, { "tcp.ack.nonzero", PI_PROTOCOL, PI_NOTE, "The acknowledgment number field is nonzero while the ACK flag is not set", EXPFILL }},
        { &ei_tcp_connection_synack, { "tcp.connection.synack", PI_SEQUENCE, PI_CHAT, "Connection establish acknowledge (SYN+ACK)", EXPFILL }},
        { &ei_tcp_connection_syn, { "tcp.connection.syn", PI_SEQUENCE, PI_CHAT, "Connection establish request (SYN)", EXPFILL }},
        { &ei_tcp_connection_fin, { "tcp.connection.fin", PI_SEQUENCE, PI_CHAT, "Connection finish (FIN)", EXPFILL }},
        /* According to RFCs, RST is an indication of an error. Some applications use it
         * to terminate a connection as well, which is a misbehavior (see e.g. rfc3360)
         */
        { &ei_tcp_connection_rst, { "tcp.connection.rst", PI_SEQUENCE, PI_WARN, "Connection reset (RST)", EXPFILL }},
        { &ei_tcp_checksum_ffff, { "tcp.checksum.ffff", PI_CHECKSUM, PI_WARN, "TCP Checksum 0xffff instead of 0x0000 (see RFC 1624)", EXPFILL }},
        { &ei_tcp_checksum_bad, { "tcp.checksum_bad.expert", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_tcp_urgent_pointer_non_zero, { "tcp.urgent_pointer.non_zero", PI_PROTOCOL, PI_NOTE, "The urgent pointer field is nonzero while the URG flag is not set", EXPFILL }},
        { &ei_tcp_suboption_malformed, { "tcp.suboption_malformed", PI_MALFORMED, PI_ERROR, "suboption would go past end of option", EXPFILL }},
        { &ei_tcp_nop, { "tcp.nop", PI_PROTOCOL, PI_WARN, "4 NOP in a row - a router may have removed some options", EXPFILL }},
        { &ei_tcp_bogus_header_length, { "tcp.bogus_header_length", PI_PROTOCOL, PI_ERROR, "Bogus TCP Header length", EXPFILL }},
    };

    static ei_register_info mptcp_ei[] = {
#if 0
        { &ei_mptcp_analysis_unexpected_idsn, { "mptcp.connection.unexpected_idsn", PI_PROTOCOL, PI_NOTE, "Unexpected initial sequence number", EXPFILL }},
#endif
        { &ei_mptcp_analysis_echoed_key_mismatch, { "mptcp.connection.echoed_key_mismatch", PI_PROTOCOL, PI_WARN, "The echoed key in the ACK of the MPTCP handshake does not match the key of the SYN/ACK", EXPFILL }},
        { &ei_mptcp_analysis_missing_algorithm, { "mptcp.connection.missing_algorithm", PI_PROTOCOL, PI_WARN, "No crypto algorithm specified", EXPFILL }},
        { &ei_mptcp_analysis_unsupported_algorithm, { "mptcp.connection.unsupported_algorithm", PI_PROTOCOL, PI_WARN, "Unsupported algorithm", EXPFILL }},
        { &ei_mptcp_infinite_mapping, { "mptcp.dss.infinite_mapping", PI_PROTOCOL, PI_WARN, "Fallback to infinite mapping", EXPFILL }},
        { &ei_mptcp_mapping_missing, { "mptcp.dss.missing_mapping", PI_PROTOCOL, PI_WARN, "No mapping available", EXPFILL }},
#if 0
        { &ei_mptcp_stream_incomplete, { "mptcp.incomplete", PI_PROTOCOL, PI_WARN, "Everything was not captured", EXPFILL }},
        { &ei_mptcp_analysis_dsn_out_of_order, { "mptcp.analysis.dsn.out_of_order", PI_PROTOCOL, PI_WARN, "Out of order dsn", EXPFILL }},
#endif
    };

    static hf_register_info mptcp_hf[] = {
        { &hf_mptcp_ack,
          { "Multipath TCP Data ACK", "mptcp.ack", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_mptcp_dsn,
          { "Data Sequence Number", "mptcp.dsn", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Data Sequence Number mapped to this TCP sequence number", HFILL}},

        { &hf_mptcp_rawdsn64,
          { "Raw Data Sequence Number", "mptcp.rawdsn64", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Data Sequence Number mapped to this TCP sequence number", HFILL}},

        { &hf_mptcp_dss_dsn,
          { "DSS Data Sequence Number", "mptcp.dss.dsn", FT_UINT64,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_mptcp_expected_idsn,
          { "Subflow expected IDSN", "mptcp.expected_idsn", FT_UINT64,
            BASE_DEC|BASE_UNIT_STRING, &units_64bit_version, 0x0, NULL, HFILL}},

        { &hf_mptcp_analysis,
          { "MPTCP analysis",   "mptcp.analysis", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the MPTCP analysis shown", HFILL }},

        { &hf_mptcp_related_mapping,
          { "Related mapping", "mptcp.related_mapping", FT_FRAMENUM , BASE_NONE, NULL, 0x0,
            "Packet in which current packet DSS mapping was sent", HFILL }},

        { &hf_mptcp_reinjection_of,
          { "Reinjection of", "mptcp.reinjection_of", FT_FRAMENUM , BASE_NONE, NULL, 0x0,
            "This is a retransmission of data sent on another subflow", HFILL }},

        { &hf_mptcp_reinjected_in,
          { "Data reinjected in", "mptcp.reinjected_in", FT_FRAMENUM , BASE_NONE, NULL, 0x0,
            "This was retransmitted on another subflow", HFILL }},

        { &hf_mptcp_analysis_subflows,
          { "TCP subflow stream id(s)", "mptcp.analysis.subflows", FT_STRING, BASE_NONE, NULL, 0x0,
            "List all TCP connections mapped to this MPTCP connection", HFILL }},

        { &hf_mptcp_stream,
          { "Stream index", "mptcp.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_mptcp_number_of_removed_addresses,
          { "Number of removed addresses", "mptcp.rm_addr.count", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_mptcp_expected_token,
          { "Subflow token generated from key", "mptcp.expected_token", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_mptcp_analysis_master,
          { "Master flow", "mptcp.master", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL}}

    };

    static build_valid_func tcp_da_src_values[1] = {tcp_src_value};
    static build_valid_func tcp_da_dst_values[1] = {tcp_dst_value};
    static build_valid_func tcp_da_both_values[2] = {tcp_src_value, tcp_dst_value};
    static decode_as_value_t tcp_da_values[3] = {{tcp_src_prompt, 1, tcp_da_src_values}, {tcp_dst_prompt, 1, tcp_da_dst_values}, {tcp_both_prompt, 2, tcp_da_both_values}};
    static decode_as_t tcp_da = {"tcp", "tcp.port", 3, 2, tcp_da_values, "TCP", "port(s) as",
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    module_t *tcp_module;
    module_t *mptcp_module;
    expert_module_t* expert_tcp;
    expert_module_t* expert_mptcp;

    proto_tcp = proto_register_protocol("Transmission Control Protocol", "TCP", "tcp");
    tcp_handle = register_dissector("tcp", dissect_tcp, proto_tcp);
    proto_register_field_array(proto_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_tcp = expert_register_protocol(proto_tcp);
    expert_register_field_array(expert_tcp, ei, array_length(ei));

    /* subdissector code */
    subdissector_table = register_dissector_table("tcp.port",
        "TCP port", proto_tcp, FT_UINT16, BASE_DEC);
    heur_subdissector_list = register_heur_dissector_list("tcp", proto_tcp);
    tcp_option_table = register_dissector_table("tcp.option",
        "TCP Options", proto_tcp, FT_UINT8, BASE_DEC);

    /* Register TCP options as their own protocols so we can get the name of the option */
    proto_tcp_option_nop = proto_register_protocol_in_name_only("TCP Option - No-Operation (NOP)", "No-Operation (NOP)", "tcp.options.nop", proto_tcp, FT_BYTES);
    proto_tcp_option_eol = proto_register_protocol_in_name_only("TCP Option - End of Option List (EOL)", "End of Option List (EOL)", "tcp.options.eol", proto_tcp, FT_BYTES);
    proto_tcp_option_timestamp = proto_register_protocol_in_name_only("TCP Option - Timestamps", "Timestamps", "tcp.options.timestamp", proto_tcp, FT_BYTES);
    proto_tcp_option_mss = proto_register_protocol_in_name_only("TCP Option - Maximum segment size", "Maximum segment size", "tcp.options.mss", proto_tcp, FT_BYTES);
    proto_tcp_option_wscale = proto_register_protocol_in_name_only("TCP Option - Window scale", "Window scale", "tcp.options.wscale", proto_tcp, FT_BYTES);
    proto_tcp_option_sack_perm = proto_register_protocol_in_name_only("TCP Option - SACK permitted", "SACK permitted", "tcp.options.sack_perm", proto_tcp, FT_BYTES);
    proto_tcp_option_sack = proto_register_protocol_in_name_only("TCP Option - SACK", "SACK", "tcp.options.sack", proto_tcp, FT_BYTES);
    proto_tcp_option_echo = proto_register_protocol_in_name_only("TCP Option - Echo", "Echo", "tcp.options.echo", proto_tcp, FT_BYTES);
    proto_tcp_option_echoreply = proto_register_protocol_in_name_only("TCP Option - Echo reply", "Echo reply", "tcp.options.echoreply", proto_tcp, FT_BYTES);
    proto_tcp_option_cc = proto_register_protocol_in_name_only("TCP Option - CC", "CC", "tcp.options.cc", proto_tcp, FT_BYTES);
    proto_tcp_option_cc_new = proto_register_protocol_in_name_only("TCP Option - CC.NEW", "CC.NEW", "tcp.options.ccnew", proto_tcp, FT_BYTES);
    proto_tcp_option_cc_echo = proto_register_protocol_in_name_only("TCP Option - CC.ECHO", "CC.ECHO", "tcp.options.ccecho", proto_tcp, FT_BYTES);
    proto_tcp_option_ao = proto_register_protocol_in_name_only("TCP Option - TCP AO", "TCP AO", "tcp.options.ao", proto_tcp, FT_BYTES);
    proto_tcp_option_md5 = proto_register_protocol_in_name_only("TCP Option - TCP MD5 signature", "TCP MD5 signature", "tcp.options.md5", proto_tcp, FT_BYTES);
    proto_tcp_option_scps = proto_register_protocol_in_name_only("TCP Option - SCPS capabilities", "SCPS capabilities", "tcp.options.scps", proto_tcp, FT_BYTES);
    proto_tcp_option_snack = proto_register_protocol_in_name_only("TCP Option - Selective Negative Acknowledgment", "Selective Negative Acknowledgment", "tcp.options.snack", proto_tcp, FT_BYTES);
    proto_tcp_option_scpsrec = proto_register_protocol_in_name_only("TCP Option - SCPS record boundary", "SCPS record boundary", "tcp.options.scpsrec", proto_tcp, FT_BYTES);
    proto_tcp_option_scpscor = proto_register_protocol_in_name_only("TCP Option - SCPS corruption experienced", "SCPS corruption experienced", "tcp.options.scpscor", proto_tcp, FT_BYTES);
    proto_tcp_option_qs = proto_register_protocol_in_name_only("TCP Option - Quick-Start", "Quick-Start", "tcp.options.qs", proto_tcp, FT_BYTES);
    proto_tcp_option_user_to = proto_register_protocol_in_name_only("TCP Option - User Timeout", "User Timeout", "tcp.options.user_to", proto_tcp, FT_BYTES);
    proto_tcp_option_tfo = proto_register_protocol_in_name_only("TCP Option - TCP Fast Open", "TCP Fast Open", "tcp.options.tfo", proto_tcp, FT_BYTES);
    proto_tcp_option_rvbd_probe = proto_register_protocol_in_name_only("TCP Option - Riverbed Probe", "Riverbed Probe", "tcp.options.rvbd.probe", proto_tcp, FT_BYTES);
    proto_tcp_option_rvbd_trpy = proto_register_protocol_in_name_only("TCP Option - Riverbed Transparency", "Riverbed Transparency", "tcp.options.rvbd.trpy", proto_tcp, FT_BYTES);
    proto_tcp_option_exp = proto_register_protocol_in_name_only("TCP Option - Experimental", "Experimental", "tcp.options.experimental", proto_tcp, FT_BYTES);
    proto_tcp_option_unknown = proto_register_protocol_in_name_only("TCP Option - Unknown", "Unknown", "tcp.options.unknown", proto_tcp, FT_BYTES);

    register_capture_dissector_table("tcp.port", "TCP");

    /* Register configuration preferences */
    tcp_module = prefs_register_protocol(proto_tcp, NULL);
    prefs_register_bool_preference(tcp_module, "summary_in_tree",
        "Show TCP summary in protocol tree",
        "Whether the TCP summary line should be shown in the protocol tree",
        &tcp_summary_in_tree);
    prefs_register_bool_preference(tcp_module, "check_checksum",
        "Validate the TCP checksum if possible",
        "Whether to validate the TCP checksum or not.  "
        "(Invalid checksums will cause reassembly, if enabled, to fail.)",
        &tcp_check_checksum);
    prefs_register_bool_preference(tcp_module, "desegment_tcp_streams",
        "Allow subdissector to reassemble TCP streams",
        "Whether subdissector can request TCP streams to be reassembled",
        &tcp_desegment);
    prefs_register_bool_preference(tcp_module, "reassemble_out_of_order",
        "Reassemble out-of-order segments",
        "Whether out-of-order segments should be buffered and reordered before passing it to a subdissector. "
        "To use this option you must also enable \"Allow subdissector to reassemble TCP streams\".",
        &tcp_reassemble_out_of_order);
    prefs_register_bool_preference(tcp_module, "analyze_sequence_numbers",
        "Analyze TCP sequence numbers",
        "Make the TCP dissector analyze TCP sequence numbers to find and flag segment retransmissions, missing segments and RTT",
        &tcp_analyze_seq);
    prefs_register_bool_preference(tcp_module, "relative_sequence_numbers",
        "Relative sequence numbers (Requires \"Analyze TCP sequence numbers\")",
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
    prefs_register_bool_preference(tcp_module, "bif_seq_based",
        "Evaluate bytes in flight based on sequence numbers",
        "Evaluate BiF on actual sequence numbers or use the historical method based on payloads (default). "
        "This option has no effect if not used with \"Track number of bytes in flight\". ",
        &tcp_bif_seq_based);
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
    prefs_register_bool_preference(tcp_module, "fastrt_supersedes_ooo",
        "Fast Retransmission supersedes Out-of-Order interpretation",
        "When interpreting ambiguous packets, give precedence to Fast Retransmission or OOO ",
        &tcp_fastrt_precedence);

    prefs_register_bool_preference(tcp_module, "no_subdissector_on_error",
        "Do not call subdissectors for error packets",
        "Do not call any subdissectors for Retransmitted or OutOfOrder segments",
        &tcp_no_subdissector_on_error);

    prefs_register_bool_preference(tcp_module, "dissect_experimental_options_with_magic",
        "TCP Experimental Options with a Magic Number",
        "Assume TCP Experimental Options (253, 254) have a Magic Number and use it for dissection",
        &tcp_exp_options_with_magic);

    prefs_register_bool_preference(tcp_module, "display_process_info_from_ipfix",
        "Display process information via IPFIX",
        "Collect and store process information retrieved from IPFIX dissector",
        &tcp_display_process_info);

    prefs_register_bool_preference(tcp_module, "read_seq_as_syn_cookie",
        "Read the seq no. as syn cookie",
        "Read the sequence number as it was a syn cookie",
        &read_seq_as_syn_cookie);

    register_init_routine(tcp_init);
    reassembly_table_register(&tcp_reassembly_table,
                          &tcp_reassembly_table_functions);

    register_decode_as(&tcp_da);

    register_conversation_table(proto_tcp, FALSE, tcpip_conversation_packet, tcpip_hostlist_packet);
    register_conversation_filter("tcp", "TCP", tcp_filter_valid, tcp_build_filter);

    register_seq_analysis("tcp", "TCP Flows", proto_tcp, NULL, 0, tcp_seq_analysis_packet);

    /* considers MPTCP as a distinct protocol (even if it's a TCP option) */
    proto_mptcp = proto_register_protocol("Multipath Transmission Control Protocol", "MPTCP", "mptcp");

    proto_register_field_array(proto_mptcp, mptcp_hf, array_length(mptcp_hf));
    proto_register_subtree_array(mptcp_ett, array_length(mptcp_ett));

    /* Register configuration preferences */
    mptcp_module = prefs_register_protocol(proto_mptcp, NULL);
    expert_mptcp = expert_register_protocol(proto_tcp);
    expert_register_field_array(expert_mptcp, mptcp_ei, array_length(mptcp_ei));

    prefs_register_bool_preference(mptcp_module, "analyze_mptcp",
        "Map TCP subflows to their respective MPTCP connections",
        "To use this option you must also enable \"Analyze TCP sequence numbers\". ",
        &tcp_analyze_mptcp);

    prefs_register_bool_preference(mptcp_module, "relative_sequence_numbers",
        "Display relative MPTCP sequence numbers.",
        "In case you don't capture the key, it will use the first DSN seen",
        &mptcp_relative_seq);

    prefs_register_bool_preference(mptcp_module, "analyze_mappings",
        "Deeper analysis of Data Sequence Signal (DSS)",
        "Scales logarithmically with the number of packets"
        "You need to capture the handshake for this to work."
        "\"Map TCP subflows to their respective MPTCP connections\"",
        &mptcp_analyze_mappings);

    prefs_register_bool_preference(mptcp_module, "intersubflows_retransmission",
        "Check for data duplication across subflows",
        "(Greedy algorithm: Scales linearly with number of subflows and"
        " logarithmic scaling with number of packets)"
        "You need to enable DSS mapping analysis for this option to work",
        &mptcp_intersubflows_retransmission);

    register_conversation_table(proto_mptcp, FALSE, mptcpip_conversation_packet, tcpip_hostlist_packet);
    register_follow_stream(proto_tcp, "tcp_follow", tcp_follow_conv_filter, tcp_follow_index_filter, tcp_follow_address_filter,
                            tcp_port_to_display, follow_tcp_tap_listener);
}

void
proto_reg_handoff_tcp(void)
{
    capture_dissector_handle_t tcp_cap_handle;

    dissector_add_uint("ip.proto", IP_PROTO_TCP, tcp_handle);
    dissector_add_for_decode_as_with_preference("udp.port", tcp_handle);
    data_handle = find_dissector("data");
    sport_handle = find_dissector("sport");
    tcp_tap = register_tap("tcp");
    tcp_follow_tap = register_tap("tcp_follow");

    tcp_cap_handle = create_capture_dissector_handle(capture_tcp, proto_tcp);
    capture_dissector_add_uint("ip.proto", IP_PROTO_TCP, tcp_cap_handle);

    /* Create dissection function handles for all TCP options */
    dissector_add_uint("tcp.option", TCPOPT_TIMESTAMP, create_dissector_handle( dissect_tcpopt_timestamp, proto_tcp_option_timestamp ));
    dissector_add_uint("tcp.option", TCPOPT_MSS, create_dissector_handle( dissect_tcpopt_mss, proto_tcp_option_mss ));
    dissector_add_uint("tcp.option", TCPOPT_WINDOW, create_dissector_handle( dissect_tcpopt_wscale, proto_tcp_option_wscale ));
    dissector_add_uint("tcp.option", TCPOPT_SACK_PERM, create_dissector_handle( dissect_tcpopt_sack_perm, proto_tcp_option_sack_perm ));
    dissector_add_uint("tcp.option", TCPOPT_SACK, create_dissector_handle( dissect_tcpopt_sack, proto_tcp_option_sack ));
    dissector_add_uint("tcp.option", TCPOPT_ECHO, create_dissector_handle( dissect_tcpopt_echo, proto_tcp_option_echo ));
    dissector_add_uint("tcp.option", TCPOPT_ECHOREPLY, create_dissector_handle( dissect_tcpopt_echo, proto_tcp_option_echoreply ));
    dissector_add_uint("tcp.option", TCPOPT_CC, create_dissector_handle( dissect_tcpopt_cc, proto_tcp_option_cc ));
    dissector_add_uint("tcp.option", TCPOPT_CCNEW, create_dissector_handle( dissect_tcpopt_cc, proto_tcp_option_cc_new ));
    dissector_add_uint("tcp.option", TCPOPT_CCECHO, create_dissector_handle( dissect_tcpopt_cc, proto_tcp_option_cc_echo ));
    dissector_add_uint("tcp.option", TCPOPT_MD5, create_dissector_handle( dissect_tcpopt_md5, proto_tcp_option_md5 ));
    dissector_add_uint("tcp.option", TCPOPT_AO, create_dissector_handle( dissect_tcpopt_ao, proto_tcp_option_ao ));
    dissector_add_uint("tcp.option", TCPOPT_SCPS, create_dissector_handle( dissect_tcpopt_scps, proto_tcp_option_scps ));
    dissector_add_uint("tcp.option", TCPOPT_SNACK, create_dissector_handle( dissect_tcpopt_snack, proto_tcp_option_snack ));
    dissector_add_uint("tcp.option", TCPOPT_RECBOUND, create_dissector_handle( dissect_tcpopt_recbound, proto_tcp_option_scpsrec ));
    dissector_add_uint("tcp.option", TCPOPT_CORREXP, create_dissector_handle( dissect_tcpopt_correxp, proto_tcp_option_scpscor ));
    dissector_add_uint("tcp.option", TCPOPT_QS, create_dissector_handle( dissect_tcpopt_qs, proto_tcp_option_qs ));
    dissector_add_uint("tcp.option", TCPOPT_USER_TO, create_dissector_handle( dissect_tcpopt_user_to, proto_tcp_option_user_to ));
    dissector_add_uint("tcp.option", TCPOPT_TFO, create_dissector_handle( dissect_tcpopt_tfo, proto_tcp_option_tfo ));
    dissector_add_uint("tcp.option", TCPOPT_RVBD_PROBE, create_dissector_handle( dissect_tcpopt_rvbd_probe, proto_tcp_option_rvbd_probe ));
    dissector_add_uint("tcp.option", TCPOPT_RVBD_TRPY, create_dissector_handle( dissect_tcpopt_rvbd_trpy, proto_tcp_option_rvbd_trpy ));
    dissector_add_uint("tcp.option", TCPOPT_EXP_FD, create_dissector_handle( dissect_tcpopt_exp, proto_tcp_option_exp ));
    dissector_add_uint("tcp.option", TCPOPT_EXP_FE, create_dissector_handle( dissect_tcpopt_exp, proto_tcp_option_exp ));
    dissector_add_uint("tcp.option", TCPOPT_MPTCP, create_dissector_handle( dissect_tcpopt_mptcp, proto_mptcp ));
    /* Common handle for all the unknown/unsupported TCP options */
    tcp_opt_unknown_handle = create_dissector_handle( dissect_tcpopt_unknown, proto_tcp_option_unknown );

    mptcp_tap = register_tap("mptcp");
    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_4);

    proto_ip = proto_get_id_by_filter_name("ip");
    proto_icmp = proto_get_id_by_filter_name("icmp");
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
