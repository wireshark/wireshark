#!/usr/bin/env python3
# Generates test/captures/lbmc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for lbmc-coverage.pcapng and lbmc-coverage-malformed.pcapng
# Usage: mklbmc.py <outdir>
import struct
import sys
import os

# Header layouts of packet-lbmc.c (field name, size in bytes).
LAYOUT = {
    'lbmc_hdr_t': [('ver_type', 1), ('next_hdr', 1), ('msglen', 2), ('tidx', 4), ('sqn', 4)],
    'lbmc_cntl_hdr_t': [('ver_type', 1), ('next_hdr', 1), ('msglen', 2)],
    'lbmc_minimal_hdr_t': [('ver_type', 1), ('next_hdr', 1), ('msglen', 2)],
    'lbmc_basic_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('res', 2)],
    'lbmc_frag_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('first_sqn', 4), ('offset', 4), ('len', 4)],
    'lbmc_batch_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2)],
    'lbmc_tcp_request_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('res', 1), ('transport', 1), ('qidx', 4), ('port', 2), ('reserved', 2), ('ipaddr', 4)],
    'lbmc_apphdr_chain_element_t': [('next_hdr', 1), ('hdr_len', 1), ('res', 2)],
    'lbmc_apphdr_chain_msgprop_element_t': [('next_hdr', 1), ('hdr_len', 1), ('res', 2), ('len', 4)],
    'lbmc_apphdr_chain_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('res', 1), ('first_chain_hdr', 1)],
    'lbmc_umq_msgid_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('msgid_regid', 8), ('msgid_stamp', 8)],
    'lbmc_umq_sqd_rcv_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('queue_id', 4), ('queue_ver', 4), ('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_umq_resub_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('rcr_idx', 4), ('resp_ip', 4), ('resp_port', 2), ('appset_idx', 2)],
    'lbmc_otid_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('otid', 32)],
    'lbmc_ctxinst_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('ctxinst', 8)],
    'lbmc_srcidx_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('srcidx', 8)],
    'lbmc_umq_ulb_msg_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('queue_id', 4), ('ulb_src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('num_ras', 2)],
    'lbmc_cntl_ssf_init_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('transport', 1), ('transport_idx', 4), ('client_idx', 4), ('ssf_port', 2), ('res', 2), ('ssf_ip', 4)],
    'lbmc_cntl_ssf_creq_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('res', 1), ('mode', 1), ('transport_idx', 4), ('topic_idx', 4), ('client_idx', 4)],
    'lbmc_cntl_ume_preg_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('marker', 1), ('reg_id', 4), ('transport_idx', 4), ('topic_idx', 4), ('src_reg_id', 4), ('resp_port', 2), ('res2', 2), ('resp_ip', 4)],
    'lbmc_cntl_ume_preg_resp_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('code', 1), ('marker', 1), ('reg_id', 4), ('transport_idx', 4), ('topic_idx', 4), ('low_seqnum', 4), ('high_seqnum', 4)],
    'lbmc_cntl_ume_ack_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('type', 1), ('transport_idx', 4), ('id_2', 4), ('rcv_reg_id', 4), ('seqnum', 4)],
    'lbmc_cntl_ume_ranged_ack_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('first_seqnum', 4), ('last_seqnum', 4)],
    'lbmc_cntl_ume_ack_id_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('id', 4)],
    'lbmc_cntl_ume_rxreq_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('request_idx', 4), ('transport_idx', 4), ('id_2', 4), ('seqnum', 4), ('rx_port', 2), ('res', 2), ('rx_ip', 4)],
    'lbmc_cntl_ume_ranged_rxreq_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('first_seqnum', 4), ('last_seqnum', 4)],
    'lbmc_cntl_lji_req_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('request_idx', 4), ('transport_idx', 4), ('topic_idx', 4), ('req_ip', 4), ('req_port', 2), ('res', 2), ('tx_low_sqn', 4), ('rx_req_max', 4), ('rx_req_outstanding_max', 4)],
    'lbmc_cntl_ume_keepalive_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('type', 1), ('transport_idx', 4), ('topic_idx', 4), ('reg_id', 4)],
    'lbmc_cntl_ume_storeid_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('store_id', 2)],
    'lbmc_cntl_ume_capability_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2)],
    'lbmc_cntl_ume_proxy_src_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2)],
    'lbmc_cntl_ume_store_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('grp_idx', 1), ('store_tcp_port', 2), ('store_idx', 2), ('store_ip_addr', 4), ('src_reg_id', 4)],
    'lbmc_cntl_ume_store_ext_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('grp_idx', 1), ('store_tcp_port', 2), ('store_idx', 2), ('store_ip_addr', 4), ('src_reg_id', 4), ('domain_id', 4), ('version', 4)],
    'lbmc_cntl_ume_lj_info_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('low_seqnum', 4), ('high_seqnum', 4), ('qidx', 4)],
    'lbmc_cntl_ume_store_group_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('grp_idx', 1), ('grp_sz', 2), ('res1', 2)],
    'lbmc_cntl_tsni_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('num_recs', 2)],
    'lbmc_cntl_tsni_rec_hdr_t': [('tidx', 4), ('sqn', 4)],
    'lbmc_cntl_umq_reg_ctx_hdr_t': [('port', 2), ('reserved', 2), ('ip', 4), ('capabilities', 4)],
    'lbmc_cntl_umq_reg_src_hdr_t': [('transport_idx', 4), ('topic_idx', 4)],
    'lbmc_cntl_umq_reg_rcv_hdr_t': [('assign_id', 4), ('rcv_type_id', 4), ('last_topic_rcr_tsp', 4)],
    'lbmc_cntl_umq_rcv_dereg_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_reg_ulb_rcv_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('rcv_type_id', 4), ('port', 2), ('reserved', 2), ('ip', 4), ('capabilities', 4)],
    'lbmc_cntl_umq_ulb_rcv_dereg_hdr_t': [('ulb_src_id', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_reg_observer_rcv_hdr_t': [('assign_id', 4), ('rcv_type_id', 4), ('last_topic_rcr_tsp', 4)],
    'lbmc_cntl_umq_observer_rcv_dereg_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_reg_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('reg_type', 1), ('queue_id', 4), ('cmd_id', 2), ('inst_idx', 2), ('regid', 8)],
    'lbmc_cntl_umq_reg_resp_ctx_hdr_t': [('capabilities', 4)],
    'lbmc_cntl_umq_reg_resp_ctx_ex_hdr_t': [('capabilities', 4), ('reserved', 2), ('flags', 2), ('stamp', 8)],
    'lbmc_cntl_umq_reg_resp_err_hdr_t': [('reserved', 2), ('code', 2)],
    'lbmc_cntl_umq_reg_resp_src_hdr_t': [('rcr_idx', 4)],
    'lbmc_cntl_umq_reg_resp_rcv_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_rcv_dereg_resp_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_reg_resp_ulb_rcv_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2), ('capabilities', 4)],
    'lbmc_cntl_umq_ulb_rcv_dereg_resp_hdr_t': [('ulb_src_id', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_reg_resp_observer_rcv_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_observer_rcv_dereg_resp_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_reg_resp_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('resp_type', 1), ('queue_id', 4), ('cmd_id', 2), ('inst_idx', 2), ('regid', 8)],
    'lbmc_cntl_umq_ack_msgid_hdr_t': [('regid', 8), ('stamp', 8)],
    'lbmc_cntl_umq_ack_stable_hdr_t': [('queue_id', 4), ('inst_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_ack_cr_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_ack_ulb_cr_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_ack_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('msgs', 1), ('ack_type', 1)],
    'lbmc_cntl_umq_rcr_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('queue_id', 4), ('rcr_idx', 4), ('msgid_regid', 8), ('msgid_stamp', 8), ('topic_tsp', 4), ('q_tsp', 4), ('assign_id', 4), ('appset_idx', 2), ('num_ras', 2), ('queue_ver', 4)],
    'lbmc_cntl_umq_ka_src_hdr_t': [('transport_idx', 4), ('topic_idx', 4)],
    'lbmc_cntl_umq_ka_rcv_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_ka_ulb_rcv_hdr_t': [('ulb_src_id', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_ka_ulb_rcv_resp_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_ka_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('ka_type', 1), ('queue_id', 4), ('regid', 8), ('inst_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_rxreq_regid_resp_hdr_t': [('regid', 8)],
    'lbmc_cntl_umq_rxreq_addr_resp_hdr_t': [('ip', 4), ('port', 2), ('reserved', 2)],
    'lbmc_cntl_umq_rxreq_mr_hdr_t': [('assign_id', 4), ('msgid_regid', 8), ('msgid_stamp', 8)],
    'lbmc_cntl_umq_rxreq_ulb_mr_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2), ('msgid_regid', 8), ('msgid_stamp', 8)],
    'lbmc_cntl_umq_rxreq_ulb_mr_abort_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('msgid_regid', 8), ('msgid_stamp', 8)],
    'lbmc_cntl_umq_rxreq_qrcrr_hdr_t': [('tsp', 4)],
    'lbmc_cntl_umq_rxreq_trcrr_hdr_t': [('rcr_idx', 4), ('tsp', 4)],
    'lbmc_cntl_umq_rxreq_ulb_trcrr_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('tsp', 4)],
    'lbmc_cntl_umq_rxreq_ulb_trcrr_abort_hdr_t': [('ulb_src_id', 4), ('assign_id', 4), ('tsp', 4)],
    'lbmc_cntl_umq_rxreq_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('rxreq_type', 1)],
    'lbmc_cntl_umq_qmgmt_hdr_t': [('next_hdr', 1), ('hdr_len', 1)],
    'lbmc_cntl_umq_resub_req_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('msgid_regid', 8), ('msgid_stamp', 8), ('rcr_idx', 4), ('resp_ip', 4), ('resp_port', 2), ('appset_idx', 2)],
    'lbmc_cntl_umq_resub_resp_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('code', 1), ('msgid_regid', 8), ('msgid_stamp', 8), ('rcr_idx', 4), ('reserved', 2), ('appset_idx', 2)],
    'lbmc_cntl_topic_interest_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('domain_id', 4)],
    'lbmc_cntl_pattern_interest_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('type', 1), ('domain_id', 4), ('idx', 8)],
    'lbmc_cntl_advertisement_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('hop_count', 1), ('ad_flags', 4), ('cost', 4), ('transport_idx', 4), ('topic_idx', 4), ('low_seqno', 4), ('high_seqno', 4), ('domain_id', 4), ('pat_idx', 8), ('ctxinst', 8)],
    'lbmc_cntl_umq_ulb_rcr_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('queue_id', 4), ('ulb_src_id', 4), ('msgid_regid', 8), ('msgid_stamp', 8), ('topic_tsp', 4), ('assign_id', 4), ('appset_idx', 2), ('num_ras', 2)],
    'lbmc_cntl_umq_lf_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('type', 1), ('num_srcs', 2), ('lf', 2)],
    'lbmc_cntl_ctxinfo_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('reserved', 1), ('hop_count', 1), ('port', 2), ('addr', 4), ('domain_id', 4), ('ctxinst', 8)],
    'lbmc_cntl_ume_pser_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('source_ip', 4), ('store_ip', 4), ('transport_idx', 4), ('topic_idx', 4), ('source_port', 2), ('store_port', 2), ('source_ctxinst', 8), ('store_ctxinst', 8)],
    'lbmc_domain_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('domain', 4)],
    'lbmc_cntl_tnwg_capabilities_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('capabilities1', 4), ('capabilities2', 4), ('capabilities3', 4), ('capabilities4', 4)],
    'lbmc_patidx_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('patidx', 8)],
    'lbmc_cntl_ume_client_lifetime_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('activity_tmo', 4), ('lifetime', 4), ('ttl', 4)],
    'lbmc_cntl_ume_sid_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('sid', 8)],
    'lbmc_cntl_umq_idx_cmd_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('cmd_type', 1), ('queue_id', 4), ('cmd_id', 2), ('inst_idx', 2), ('regid', 8)],
    'lbmc_cntl_umq_rcv_stop_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_rcv_start_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_idx_cmd_rcv_release_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('flags', 4), ('index_len', 1), ('reserved', 3)],
    'lbmc_cntl_umq_ulb_rcv_stop_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_ulb_rcv_start_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('flags', 4), ('appset_idx', 2), ('index_len', 1), ('reserved', 1)],
    'lbmc_cntl_umq_idx_cmd_rcv_reserve_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('flags', 4), ('index_len', 1), ('reserved', 3)],
    'lbmc_cntl_umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('flags', 4), ('appset_idx', 2), ('index_len', 1), ('reserved', 1)],
    'lbmc_cntl_umq_idx_cmd_resp_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('resp_type', 1), ('queue_id', 4), ('cmd_id', 2), ('inst_idx', 2), ('regid', 8)],
    'lbmc_cntl_umq_idx_cmd_resp_err_hdr_t': [('reserved', 2), ('code', 2)],
    'lbmc_cntl_umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('appset_idx', 2), ('reserved', 2)],
    'lbmc_cntl_umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('flags', 4), ('appset_idx', 2), ('index_len', 1), ('reserved', 1)],
    'lbmc_cntl_umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t': [('src_id', 4), ('assign_id', 4), ('flags', 4), ('appset_idx', 2), ('index_len', 1), ('reserved', 1)],
    'lbmc_stream_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('stream_id', 4), ('sqn', 4), ('ctxinst', 8)],
    'lbmc_cntl_topic_md_interest_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('domain_count', 2), ('res1', 2)],
    'lbmc_cntl_pattern_md_interest_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('type', 1), ('domain_count', 2), ('res1', 2), ('idx', 8)],
    'lbmc_cntl_tnwg_ka_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('idx', 4), ('ts_seconds', 8), ('ts_microseconds', 4), ('reserved_1', 4), ('reserved_2', 8), ('reserved_3', 8), ('reserved_4', 8), ('reserved_5', 8), ('reserved_6', 8)],
    'lbmc_cntl_ume_receiver_keepalive_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('rcv_regid', 4), ('session_id', 8), ('ctxinst', 8)],
    'lbmc_cntl_umq_cmd_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('cmd_type', 1), ('queue_id', 4), ('cmd_id', 2), ('inst_idx', 2), ('regid', 8)],
    'lbmc_cntl_umq_ctx_queue_topic_list_hdr_t': [('serial_num', 8)],
    'lbmc_cntl_umq_rcv_msg_retrieve_hdr_t': [('rcr_idx', 4), ('assign_id', 4), ('info_only', 2), ('num_msgids', 1), ('flags', 1)],
    'lbmc_cntl_umq_rcv_msg_retrieve_entry_hdr_t': [('regid', 8), ('stamp', 8)],
    'lbmc_cntl_umq_rcv_msg_list_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_cntl_umq_cmd_resp_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('resp_type', 1), ('queue_id', 4), ('cmd_id', 2), ('inst_idx', 2), ('regid', 8)],
    'lbmc_cntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t': [('num_msgs', 1), ('flags', 1), ('reserved', 2)],
    'lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t': [('regid', 8), ('stamp', 8), ('assign_id', 4), ('num_ras', 2), ('status', 1), ('reserved', 1)],
    'lbmc_cntl_umq_cmd_resp_rcv_msg_list_hdr_t': [('rcr_idx', 4), ('assign_id', 4)],
    'lbmc_xcntl_umq_cmd_resp_rcv_msg_list_hdr_t': [('num_msgs', 8)],
    'lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t': [('regid', 8), ('stamp', 8)],
    'lbmc_cntl_umq_cmd_resp_ctx_topic_list_hdr_t': [('num_topics', 4)],
    'lbmc_cntl_umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t': [('num_receiver_type_ids', 2), ('appset_idx', 2), ('appset_name_len', 1), ('reserved', 3)],
    'lbmc_cntl_umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t': [('rcr_idx', 4), ('num_appsets', 2), ('topic_len', 1), ('reserved', 1)],
    'lbmc_cntl_umq_cmd_resp_err_hdr_t': [('reserved', 2), ('code', 2)],
    'lbmc_cntl_sri_req_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('transport_idx', 4), ('topic_idx', 4)],
    'lbmc_cntl_ume_store_domain_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('domain', 4)],
    'lbmc_cntl_sri_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('version', 4), ('low_sqn', 4), ('high_sqn', 4)],
    'lbmc_cntl_route_info_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('gateway_version', 4), ('configuration_signature', 4), ('node_id', 8), ('topology', 4), ('vers', 2), ('sqn', 2), ('ttl', 1), ('reserved1', 1), ('reserved2', 2)],
    'lbmc_cntl_route_info_neighbor_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('node_id', 8), ('ingress_cost', 4), ('egress_cost', 4)],
    'lbmc_cntl_route_info_nbr_ext_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('node_id', 4)],
    'lbmc_cntl_auth_generic_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('opid', 1)],
    'lbmc_cntl_auth_request_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('opid', 1), ('user_len', 1)],
    'lbmc_cntl_auth_challenge_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('opid', 1), ('mod_len', 1), ('gen_len', 1), ('salt_len', 1), ('pubkey_len', 1)],
    'lbmc_cntl_auth_challenge_rsp_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('opid', 1), ('pubkey_len', 1), ('evidence_len', 1)],
    'lbmc_cntl_auth_result_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('opid', 1), ('result', 1)],
    'lbmc_cntl_hmac_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('padding', 1), ('data', 20)],
    'lbmc_cntl_umq_sid_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('key', 4), ('sid', 8)],
    'lbmc_destination_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('domain_id', 4), ('ipaddr', 4), ('port', 2), ('hops_taken', 2), ('orig_domain_id', 4), ('orig_ipaddr', 4), ('orig_port', 2), ('reserved', 2)],
    'lbmc_topic_idx_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('tidx', 4)],
    'lbmc_cntl_topic_source_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('domain_id', 4)],
    'lbmc_cntl_topic_source_exfunc_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('src_ip', 4), ('src_port', 2), ('unused', 2), ('functionality_flags', 4)],
    'lbmc_cntl_ume_psrc_election_token_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('store_index', 1), ('token', 4)],
    'lbmc_cntl_tcp_sid_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('sid', 4)],
    'lbmc_cntl_transport_security_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 2), ('state', 1), ('protocol_proposed', 1), ('reserved1', 2), ('protocols_accepted', 4), ('reserved2', 4), ('session_id', 8)],
    'lbmc_extopt_cfgopt_hdr_t': [('scope', 1), ('parent', 1)],
    'lbmc_extopt_hdr_t': [('next_hdr', 1), ('hdr_len', 1), ('flags', 1), ('id', 1), ('subtype', 2), ('fragment_offset', 2)],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def fieldval(sname, i, n, sz):
    if any(k in n for k in ('flags', 'res', 'len', 'num', 'count', 'padding', 'unused')):
        return 0
    return int.from_bytes(bytes(((i * 37 + j * 11 + 0x21) & 0x7f) for j in range(sz)), 'big')

def pk(sname, **kw):
    out = b''
    for i, (n, sz) in enumerate(LAYOUT[sname]):
        v = kw.get(n, 0 if n in ('next_hdr', 'hdr_len') else fieldval(sname, i, n, sz))
        if isinstance(v, (bytes, bytearray)):
            out += bytes(v).ljust(sz, b'\0')[:sz] if sz else bytes(v)
        else:
            out += int(v).to_bytes(sz, 'big')
    return out

def hdr(sname, body=b'', trail=b'', **kw):
    b = bytearray(pk(sname, **kw) + body + trail)
    b[1] = len(b)
    return b

def basic(extra, flags=0):
    b = bytearray(struct.pack('!BBH', 0, 0, flags) + extra)
    b[1] = len(b)
    return b

def link(items, end):
    """items: list of (nhdr id, bytearray). Sets each next_hdr; returns
    (first id, bytes)."""
    if not items:
        return end, b''
    out = b''
    for k, (nid, b) in enumerate(items):
        b[0] = items[k + 1][0] if k + 1 < len(items) else end
        out += bytes(b)
    return items[0][0], out

DATA, NONE = 0x00, 0xFF
T_MSG, T_EOT, T_PRORX, T_CNTL, T_RETRANS = 0x0, 0x1, 0x2, 0x8, 0xA

def msg(typ, items, data=b'', tidx=1, sqn=1, ver=0):
    data_type = typ in (T_MSG, T_PRORX, T_RETRANS)
    first, blob = link(items, DATA if data_type else NONE)
    if data_type:
        body = blob + data
        return struct.pack('!BBHII', (ver << 4) | typ, first, 12 + len(body), tidx, sqn) + body
    return struct.pack('!BBH', (ver << 4) | typ, first, 4 + len(blob)) + blob

def ctl(items):
    return msg(T_CNTL, items)

def frag_hdr(first_sqn, offset, total, flags=0):
    return hdr('lbmc_frag_hdr_t', flags=flags, first_sqn=first_sqn, offset=offset, len=total)

def msgprop_chain(plen, extra_elems=False):
    """APPHDR_CHAIN with (optionally) the generic elements and a properties
    length element, as in the review reproducers."""
    elems = b''
    ids = []
    if extra_elems:
        for e in (1, 2, 3, 4, 5):
            ids.append(e)
            elems += bytes([0, 8, 0, 0]) + struct.pack('!I', 0x1000 + e)
    ids.append(6)
    elems += bytes([0, 8, 0, 0]) + struct.pack('!I', plen)
    elems = bytearray(elems)
    # packet-lbmc.c takes the type of every element but the first from the
    # element's own next_hdr byte (see README), so each element carries its own type
    pos = 0
    for k in range(len(ids)):
        elems[pos] = ids[k] if k > 0 else ids[k + 1] if k + 1 < len(ids) else 0
        pos += 8
    b = bytearray(struct.pack('!BBBB', 0, 4 + len(elems), 0, ids[0]) + bytes(elems))
    return b

def props(fields, big=False):
    """Message properties block. fields: list of (key, type, value)."""
    E = '>' if big else '<'
    n = len(fields)
    tbl_end = 8 + 16 * n
    keys = b''
    vals = b''
    koff = []
    voff = []
    for k, t, v in fields:
        koff.append(len(keys))
        keys += k.encode() + b'\0'
    kbase = tbl_end
    vbase = kbase + len(keys)
    for k, t, v in fields:
        voff.append(len(vals))
        if t == 1: vals += struct.pack('B', v)
        elif t == 2: vals += struct.pack('b', v)
        elif t == 3: vals += struct.pack(E + 'h', v)
        elif t == 4: vals += struct.pack(E + 'i', v)
        elif t == 5: vals += struct.pack(E + 'q', v)
        elif t == 6: vals += struct.pack(E + 'f', v)
        elif t == 7: vals += struct.pack(E + 'd', v)
        elif t == 8: vals += v.encode() + b'\0'
        else: vals += struct.pack(E + 'I', v)
    out = (b'\xab\xac\xda\xba' if big else b'\xba\xda\xac\xab') + struct.pack(E + 'HBB', n, 0, 0)
    for i, (k, t, v) in enumerate(fields):
        out += struct.pack(E + 'IIII', kbase + koff[i], vbase + voff[i], 0x1234 + i, t)
    return out + keys + vals

PROPS = [('flag', 1, 1), ('b', 2, -5), ('s', 3, 1234), ('i', 4, 70000), ('l', 5, 1 << 40),
         ('f', 6, 1.5), ('d', 7, 2.25), ('name', 8, 'value')]

# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipaddr(a):
    return bytes(int(x) for x in a.split('.'))

def eth_ip(proto, l4, src, dst, ident):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, ipaddr(src), ipaddr(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    if dst.startswith('224.'):
        dmac = b'\x01\x00\x5e' + bytes([int(dst.split('.')[1]) & 0x7f]) + bytes(int(x) for x in dst.split('.')[2:])
    else:
        dmac = b'\x02\x00\x00\x00\x00\x02'
    return dmac + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + l4

class Net:
    ident = 0

def udp(payload, src, dst, sport, dport):
    Net.ident += 1
    l4 = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(17, l4, src, dst, Net.ident)

class Conn:
    """Minimal TCP connection state: handshake on first use, then data with
    consistent sequence and acknowledgement numbers."""
    conns = {}

    @staticmethod
    def seg(src, sport, dst, dport, payload, flags, seq, ack):
        Net.ident += 1
        opt = struct.pack('!BBH', 2, 4, 1460) if flags & 2 else b''
        h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        pseudo = ipaddr(src) + ipaddr(dst) + struct.pack('!BBH', 0, 6, len(h) + len(payload))
        h = h[:16] + struct.pack('!H', csum(pseudo + h + payload)) + h[18:]
        return eth_ip(6, h + payload, src, dst, Net.ident)

def tcp(payload, src, dst, sport, dport):
    """Returns a list of frames: (handshake if new) + the data segment."""
    key = frozenset(((src, sport), (dst, dport)))
    out = []
    st = Conn.conns.get(key)
    if st is None:
        st = {(src, sport): 1000, (dst, dport): 5000}
        Conn.conns[key] = st
        out.append(Conn.seg(src, sport, dst, dport, b'', 0x02, st[(src, sport)], 0))
        st[(src, sport)] += 1
        out.append(Conn.seg(dst, dport, src, sport, b'', 0x12, st[(dst, dport)], st[(src, sport)]))
        st[(dst, dport)] += 1
        out.append(Conn.seg(src, sport, dst, dport, b'', 0x10, st[(src, sport)], st[(dst, dport)]))
    out.append(Conn.seg(src, sport, dst, dport, payload, 0x18, st[(src, sport)], st[(dst, dport)]))
    st[(src, sport)] += len(payload)
    return out

SRC, MC = '10.0.0.1', '224.10.10.10'
RM = dict(sqn=0)

def lbtrm_pdu(lbmc, session=0x11223344, sport=14390):
    RM['sqn'] += 1
    hdr_ = struct.pack('!BBHI', 0x00, 0x00, sport, session)
    data = struct.pack('!IIBBH', RM['sqn'], 0, 0, 0, 0)
    return hdr_ + data + lbmc

def lbtrm(lbmc, session=0x11223344, sport=14390):
    return udp(lbtrm_pdu(lbmc, session, sport), SRC, MC, sport, 14400)

def tir(name, transport, idx, body, ttl=16):
    return name.encode() + b'\0' + struct.pack('!BBHI', transport, len(body), ttl, idx) + body

def lbmr_tirs(tirs):
    return struct.pack('!BBH', 0x00, 0, len(tirs)) + b''.join(tirs)

def lbmr_frame(tirs, src=SRC):
    return udp(lbmr_tirs(tirs), src, '224.9.10.11', 50100, 12965)

def tir_lbtrm(name, idx, session=0x11223344, mcast='224.10.10.10', dport=14400, sport=14390, src=SRC):
    return tir(name, 0x10, idx, ipaddr(src) + ipaddr(mcast) + struct.pack('!IHH', session, dport, sport))

def tir_tcp(name, idx, port, sid=None, ip=SRC):
    if sid is None:
        return tir(name, 0x00, idx, ipaddr(ip) + struct.pack('!H', port))
    return tir(name, 0x00, idx, ipaddr(ip) + struct.pack('!IH', sid, port))

def tlv(tag, val):
    pad = (-len(val)) % 4
    return struct.pack('!HH', tag, len(val) + pad) + val + b'\0' * pad

def exported(name, payload, extra=b''):
    return tlv(12, name.encode()) + extra + struct.pack('!HH', 0, 0) + payload

def pcapng(path, frames):
    """frames: list of (linktype, bytes)."""
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    lts = sorted(set(l for l, _ in frames))
    for l in lts:
        out += blk(1, struct.pack('<HHI', l, 0, 262144))
    for i, (l, f) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', lts.index(l), ts >> 32, ts & 0xffffffff, len(f), len(f)) + f)
    open(path, 'wb').write(out)

def pcap_classic(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, (l, fr) in enumerate(frames):
            assert l == 1
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---------------------------------------------------------------------------
# Header factories (valid headers, one per NHDR id)
# ---------------------------------------------------------------------------
S = 'lbmc_'
C = 'lbmc_cntl_'
def H_frag(first, off, total, flags=0): return (0x01, frag_hdr(first, off, total, flags))
def H_batch(flags=0xe000): return (0x02, hdr(S + 'batch_hdr_t', flags=flags))
def H_request(): return (0x04, hdr(S + 'tcp_request_hdr_t', res=0x80, transport=0x10, qidx=7, port=14391, ipaddr=ipaddr('10.0.0.9')))
def H_topicname(name='topic.one'): return (0x05, basic(name.encode() + b'\0'))
def H_apphdr(code=0x8123, data=b'appdata!'): return (0x06, basic(data, flags=code))
def H_chain(plen=0, extra=False): return (0x07, msgprop_chain(plen, extra))
def H_umq_msgid(): return (0x08, hdr(S + 'umq_msgid_hdr_t', flags=0x8000))
def H_sqd_rcv(rcr=5, flags=0xe900): return (0x09, hdr(S + 'umq_sqd_rcv_hdr_t', flags=flags, rcr_idx=rcr))
def H_resub(): return (0x0A, hdr(S + 'umq_resub_hdr_t', flags=0xc000, resp_ip=ipaddr('10.0.0.8')))
def H_otid(): return (0x0B, hdr(S + 'otid_hdr_t', flags=0x8000, otid=bytes(range(32))))
def H_ctxinstd(ci=b'\x01' * 8): return (0x0C, hdr(S + 'ctxinst_hdr_t', flags=0x8000, ctxinst=ci))
def H_ctxinstr(ci=b'\x02' * 8): return (0x0D, hdr(S + 'ctxinst_hdr_t', flags=0x8000, ctxinst=ci))
def H_srcidx(): return (0x0E, hdr(S + 'srcidx_hdr_t', flags=0x8000, srcidx=b'srcidx01'))
def H_ulb_msg(): return (0x0F, hdr(S + 'umq_ulb_msg_hdr_t', flags=0xe000))
def H_ssf_init(): return (0x10, hdr(C + 'ssf_init_hdr_t', flags=0xe0, transport=0))
def H_ssf_creq(): return (0x11, hdr(C + 'ssf_creq_hdr_t', mode=1))
def H_preg(): return (0x12, hdr(C + 'ume_preg_hdr_t', flags=0xff, marker=0xff))
def H_preg_resp(code=0x0f): return (0x13, hdr(C + 'ume_preg_resp_hdr_t', code=code, marker=0x81))
def H_ack(): return (0x14, hdr(C + 'ume_ack_hdr_t', flags=0xf0, type=1))
def H_rxreq(flags=0xffff): return (0x15, hdr(C + 'ume_rxreq_hdr_t', flags=flags))
def H_keepalive(): return (0x16, hdr(C + 'ume_keepalive_hdr_t', flags=0xff, type=2))
def H_storeid(): return (0x17, hdr(C + 'ume_storeid_hdr_t', store_id=0x8002))
def H_ranged_ack(): return (0x18, hdr(C + 'ume_ranged_ack_hdr_t', flags=0x8000))
def H_ack_id(): return (0x19, hdr(C + 'ume_ack_id_hdr_t', flags=0x8000))
def H_capability(): return (0x1A, hdr(C + 'ume_capability_hdr_t', flags=0xf000))
def H_proxy_src(): return (0x1B, hdr(C + 'ume_proxy_src_hdr_t', flags=0xe000))
def H_store_group(): return (0x1C, hdr(C + 'ume_store_group_hdr_t', flags=0x80))
def H_store(): return (0x1D, hdr(C + 'ume_store_hdr_t', flags=0xff))
def H_lj_info(): return (0x1E, hdr(C + 'ume_lj_info_hdr_t', flags=0x8000))
def H_ranged_rxreq(): return (0x1F, hdr(C + 'ume_ranged_rxreq_hdr_t', flags=0x8000))
def H_tsni(n=3):
    recs = b''.join(struct.pack('!II', 10 + i, 100 + i) for i in range(n))
    return (0x20, hdr(C + 'tsni_hdr_t', trail=recs, num_recs=n | 0x8000))

UMQ_REG_BODIES = {
    1: ('umq_reg_ctx_hdr_t', {}), 2: ('umq_reg_src_hdr_t', {}), 3: ('umq_reg_rcv_hdr_t', {}),
    4: ('umq_rcv_dereg_hdr_t', {}), 5: ('umq_reg_ulb_rcv_hdr_t', {}), 6: ('umq_ulb_rcv_dereg_hdr_t', {}),
    7: ('umq_reg_observer_rcv_hdr_t', {}), 8: ('umq_observer_rcv_dereg_hdr_t', {})}
def H_umq_reg(t, flags=0xf8):
    n, kw = UMQ_REG_BODIES[t]
    return (0x30, hdr(C + 'umq_reg_hdr_t', body=pk(C + n, **kw), flags=flags, reg_type=t))
UMQ_RESP_BODIES = {
    1: 'umq_reg_resp_ctx_hdr_t', 9: 'umq_reg_resp_ctx_ex_hdr_t', 0xFF: 'umq_reg_resp_err_hdr_t',
    2: 'umq_reg_resp_src_hdr_t', 3: 'umq_reg_resp_rcv_hdr_t', 4: 'umq_rcv_dereg_resp_hdr_t',
    5: 'umq_reg_resp_ulb_rcv_hdr_t', 6: 'umq_ulb_rcv_dereg_resp_hdr_t',
    7: 'umq_reg_resp_observer_rcv_hdr_t', 8: 'umq_observer_rcv_dereg_resp_hdr_t'}
def H_umq_reg_resp(t, flags=0x70):
    return (0x31, hdr(C + 'umq_reg_resp_hdr_t', body=pk(C + UMQ_RESP_BODIES[t], flags=1), flags=flags, resp_type=t))
def H_umq_ack(t, msgs=2):
    body = b''.join(pk(C + 'umq_ack_msgid_hdr_t') for _ in range(msgs))
    sub = {1: 'umq_ack_stable_hdr_t', 2: 'umq_ack_cr_hdr_t', 3: 'umq_ack_ulb_cr_hdr_t'}[t]
    return (0x32, hdr(C + 'umq_ack_hdr_t', body=body + pk(C + sub), msgs=0x60 | msgs, ack_type=t))
def H_umq_rcr(): return (0x33, hdr(C + 'umq_rcr_hdr_t', flags=0x7300))
def H_umq_ka(t):
    sub = {1: 'umq_ka_src_hdr_t', 0x11: 'umq_ka_src_hdr_t', 2: 'umq_ka_rcv_hdr_t', 0x12: 'umq_ka_rcv_hdr_t',
           3: 'umq_ka_ulb_rcv_hdr_t', 0x13: 'umq_ka_ulb_rcv_resp_hdr_t'}.get(t)
    return (0x34, hdr(C + 'umq_ka_hdr_t', body=pk(C + sub) if sub else b'', flags=0x40, ka_type=t))
def H_umq_rxreq(t, rflag=False):
    sub = {1: 'umq_rxreq_mr_hdr_t', 2: 'umq_rxreq_qrcrr_hdr_t', 3: 'umq_rxreq_trcrr_hdr_t', 4: 'umq_rxreq_ulb_mr_hdr_t',
           5: 'umq_rxreq_ulb_trcrr_hdr_t', 6: 'umq_rxreq_ulb_mr_abort_hdr_t', 7: 'umq_rxreq_ulb_trcrr_abort_hdr_t'}.get(t)
    first = pk(C + ('umq_rxreq_regid_resp_hdr_t' if rflag else 'umq_rxreq_addr_resp_hdr_t'))
    return (0x35, hdr(C + 'umq_rxreq_hdr_t', body=first + (pk(C + sub) if sub else b''),
                      flags=0x40 if rflag else 0, rxreq_type=t))
def H_umq_resub_req(): return (0x37, hdr(C + 'umq_resub_req_hdr_t', flags=0x8000))
def H_umq_resub_resp(code=1): return (0x38, hdr(C + 'umq_resub_resp_hdr_t', flags=0x80, code=code))
def H_topic_interest(): return (0x39, hdr(C + 'topic_interest_hdr_t', flags=0x8000))
def H_pattern_interest(): return (0x3A, hdr(C + 'pattern_interest_hdr_t', flags=0xe0, type=1))
def H_advert(flags=0xf8): return (0x3B, hdr(C + 'advertisement_hdr_t', flags=flags, ad_flags=0xf8000000, ctxinst=b'adctxins'))
def H_ctxinsts(): return (0x3C, hdr(S + 'ctxinst_hdr_t', flags=0x8000, ctxinst=b'\x05' * 8))
def H_storename(n='store-a'): return (0x3D, basic(n.encode() + b'\0', flags=0x8000))
def H_ulb_rcr(): return (0x3E, hdr(C + 'umq_ulb_rcr_hdr_t', flags=0x6300))
def H_umq_lf(): return (0x3F, hdr(C + 'umq_lf_hdr_t', flags=0x40, type=1))
def H_ctxinfo(flags=0xfd00, name=b''): return (0x40, hdr(C + 'ctxinfo_hdr_t', flags=flags, trail=name))
def H_pser(): return (0x41, hdr(C + 'ume_pser_hdr_t', flags=0x8000, source_ctxinst=b'srcctx01', store_ctxinst=b'strctx01'))
def H_ctxinst(): return (0x42, hdr(S + 'ctxinst_hdr_t', flags=0x8000, ctxinst=b'\x06' * 8))
def H_domain(): return (0x43, hdr(S + 'domain_hdr_t', flags=0x8000, domain=12))
def H_tnwg_cap(): return (0x44, hdr(C + 'tnwg_capabilities_hdr_t', flags=0x8001, capabilities1=0xc0000000, capabilities3=0xc0000000))
def H_patidx(): return (0x45, hdr(S + 'patidx_hdr_t', flags=0x8000, patidx=b'patidx01'))
def H_client_lifetime(): return (0x46, hdr(C + 'ume_client_lifetime_hdr_t', flags=0x8000))
def H_ume_sid(): return (0x47, hdr(C + 'ume_sid_hdr_t', flags=0x8000))

IDX = {1: 'umq_rcv_stop_idx_assign_hdr_t', 2: 'umq_rcv_start_idx_assign_hdr_t',
       3: 'umq_ulb_rcv_stop_idx_assign_hdr_t', 4: 'umq_ulb_rcv_start_idx_assign_hdr_t',
       5: 'umq_idx_cmd_rcv_release_idx_assign_hdr_t', 6: 'umq_ulb_idx_cmd_rcv_release_idx_assign_hdr_t',
       7: 'umq_idx_cmd_rcv_reserve_idx_assign_hdr_t', 8: 'umq_ulb_idx_cmd_rcv_reserve_idx_assign_hdr_t'}
def H_idx_cmd(t, idx=b'', numeric=False):
    kw = {}
    if t >= 5:
        kw = dict(flags=1 if numeric else 0, index_len=len(idx))
    return (0x48, hdr(C + 'umq_idx_cmd_hdr_t', body=pk(C + IDX[t], **kw), trail=idx, flags=0x80, cmd_type=t))
IDXR = {1: 'umq_idx_cmd_resp_rcv_stop_idx_assign_hdr_t', 2: 'umq_idx_cmd_resp_rcv_start_idx_assign_hdr_t',
        3: 'umq_idx_cmd_resp_ulb_rcv_stop_idx_assign_hdr_t', 4: 'umq_idx_cmd_resp_ulb_rcv_start_idx_assign_hdr_t',
        5: 'umq_idx_cmd_resp_rcv_release_idx_assign_hdr_t', 6: 'umq_idx_cmd_resp_ulb_rcv_release_idx_assign_hdr_t',
        7: 'umq_idx_cmd_resp_rcv_reserve_idx_assign_hdr_t', 8: 'umq_idx_cmd_resp_ulb_rcv_reserve_idx_assign_hdr_t',
        0xFF: 'umq_idx_cmd_resp_err_hdr_t'}
def H_idx_cmd_resp(t, idx=b'', numeric=False, flags=0x80):
    kw = {}
    if t in (7, 8):
        kw = dict(flags=1 if numeric else 0, index_len=len(idx))
    return (0x49, hdr(C + 'umq_idx_cmd_resp_hdr_t', body=pk(C + IDXR[t], **kw), trail=idx, flags=flags, resp_type=t))
def H_odomain(): return (0x4a, hdr(S + 'domain_hdr_t', flags=0x8000, domain=13))
def H_stream(sid=7, sqn=1, ci=b'\x11' * 8): return (0x4b, hdr(S + 'stream_hdr_t', flags=0x8000, stream_id=sid, sqn=sqn, ctxinst=ci))
def H_topic_md(n=2): return (0x4c, hdr(C + 'topic_md_interest_hdr_t', flags=0x8000, trail=b''.join(struct.pack('!I', 100 + i) for i in range(n)), domain_count=n))
def H_pattern_md(n=2): return (0x4d, hdr(C + 'pattern_md_interest_hdr_t', flags=0xe0, type=2, trail=b''.join(struct.pack('!I', 200 + i) for i in range(n)), domain_count=n))
def H_lji_req(): return (0x4e, hdr(C + 'lji_req_hdr_t', flags=0x8000))
def H_tnwg_ka(): return (0x4f, hdr(C + 'tnwg_ka_hdr_t', flags=0xe000))
def H_rcv_ka(): return (0x50, hdr(C + 'ume_receiver_keepalive_hdr_t', flags=0x8000, ctxinst=b'\x07' * 8))

def H_umq_cmd(t, body=b''):
    return (0x51, hdr(C + 'umq_cmd_hdr_t', body=body, flags=0x80, cmd_type=t))
def cmd_body(t):
    if t == 1: return pk(C + 'umq_ctx_queue_topic_list_hdr_t')
    if t == 2:
        return pk(C + 'umq_rcv_msg_retrieve_hdr_t', num_msgids=3, flags=0x80) + pk(C + 'umq_rcv_msg_retrieve_entry_hdr_t') * 3
    if t == 3: return pk(C + 'umq_rcv_msg_list_hdr_t')
def H_umq_cmd_resp(t, body=b''):
    return (0x52, hdr(C + 'umq_cmd_resp_hdr_t', body=body, flags=0x80, resp_type=t))
def cmd_resp_body(t, data=False):
    if t == 1:
        topics = b''
        for k in range(2):
            ts = ('topic%d' % k).encode()
            appsets = b''
            for a in range(k + 1):
                nm = ('appset%d' % a).encode()
                appsets += pk(C + 'umq_cmd_resp_ctx_topic_list_appset_entry_hdr_t', num_receiver_type_ids=a + 1, appset_name_len=len(nm)) \
                           + nm + b''.join(struct.pack('!I', 50 + i) for i in range(a + 1))
            topics += pk(C + 'umq_cmd_resp_ctx_topic_list_topic_entry_hdr_t', num_appsets=k + 1, topic_len=len(ts)) + ts + appsets
        return pk(C + 'umq_cmd_resp_ctx_topic_list_hdr_t', num_topics=2) + topics
    if t == 2:
        if data:
            return pk("lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_hdr_t", num_msgs=2, flags=0) \
                   + pk('lbmc_xcntl_umq_cmd_resp_rcv_msg_retrieve_entry_hdr_t', num_ras=1, status=2) * 2
        return pk(C + 'umq_cmd_resp_rcv_msg_retrieve_hdr_t')
    if t == 3:
        if data:
            return pk('lbmc_xcntl_umq_cmd_resp_rcv_msg_list_hdr_t', num_msgs=2) + pk('lbmc_xcntl_umq_cmd_resp_rcv_msg_list_msg_entry_hdr_t') * 2
        return pk(C + 'umq_cmd_resp_rcv_msg_list_hdr_t')
    if t == 4:
        return pk(C + 'umq_cmd_resp_err_hdr_t', code=3) + b'queue not found\0'
def H_sri_req(): return (0x53, hdr(C + 'sri_req_hdr_t', flags=0x8000))
def H_store_domain(): return (0x54, hdr(C + 'ume_store_domain_hdr_t', flags=0x8000))
def H_sri(): return (0x55, hdr(C + 'sri_hdr_t', flags=0x8000))
def H_route_info(): return (0x56, hdr(C + 'route_info_hdr_t', flags=0x8000))
def H_route_nbr(): return (0x57, hdr(C + 'route_info_neighbor_hdr_t', flags=0x8000))
def H_route_nbr_ext(groups=3): return (0x6E, hdr(C + 'route_info_nbr_ext_hdr_t', flags=0x8000, trail=b''.join(struct.pack('!H', 40 + i) for i in range(groups))))
def H_gateway_name(n='gw-one'): return (0x58, basic(n.encode() + b'\0', flags=0x8000))
# Authentication: opaque placeholder bytes only, no key or crypto handling.
def H_auth(op):
    if op == 1: return (0x60, hdr(C + 'auth_request_hdr_t', flags=0x80, opid=1, user_len=5, trail=b'alice'))
    if op == 2: return (0x60, hdr(C + 'auth_challenge_hdr_t', flags=0x80, opid=2, mod_len=4, gen_len=2, salt_len=3, pubkey_len=5, trail=b'M' * 4 + b'G' * 2 + b'S' * 3 + b'P' * 5))
    if op == 3: return (0x60, hdr(C + 'auth_challenge_rsp_hdr_t', flags=0x80, opid=3, pubkey_len=4, evidence_len=6, trail=b'P' * 4 + b'E' * 6))
    if op == 4: return (0x60, hdr(C + 'auth_result_hdr_t', flags=0x80, opid=4, result=1))
    return (0x60, hdr(C + 'auth_generic_hdr_t', flags=0x80, opid=op, trail=b'xyz'))
def H_hmac(): return (0x62, hdr(C + 'hmac_hdr_t', flags=0x80, data=b'\xaa' * 20))
def H_umq_sid(): return (0x63, hdr(C + 'umq_sid_hdr_t', flags=0x8000))
def H_destination(d=1, o=2, dip='10.1.1.1', oip='10.2.2.2', dp=5000, op_=6000):
    return (0x64, hdr(S + 'destination_hdr_t', flags=0x8000, domain_id=d, ipaddr=ipaddr(dip), port=dp, orig_domain_id=o, orig_ipaddr=ipaddr(oip), orig_port=op_))
def H_topic_idx(): return (0x65, hdr(S + 'topic_idx_hdr_t', flags=0x8000, tidx=99))
def H_topic_source(): return (0x67, hdr(C + 'topic_source_hdr_t', flags=0x8000))
def H_exfunc(): return (0x68, hdr(C + 'topic_source_exfunc_hdr_t', flags=0x8000, functionality_flags=0xf))
def H_store_ext(): return (0x69, hdr(C + 'ume_store_ext_hdr_t', flags=0xff))
def H_election_token(): return (0x6A, hdr(C + 'ume_psrc_election_token_hdr_t', flags=0x80))
def H_tcp_sid(sid=0x1234): return (0x6B, hdr(C + 'tcp_sid_hdr_t', flags=0x8000, sid=sid))
def H_transport_security(proto=3): return (0x6C, hdr(C + 'transport_security_hdr_t', flags=0x8000, state=1, protocol_proposed=proto, protocols_accepted=0x1c))
def H_extopt(flags, subtype, off, data, i=1):
    return (0xFE, hdr(S + 'extopt_hdr_t', flags=flags, id=i, subtype=subtype, fragment_offset=off, trail=data))
def cfgopt(scope, parent, name, value):
    return bytes([scope, parent]) + name.encode() + b'\0' + value.encode() + b'\0'

# ---------------------------------------------------------------------------
# Frame list
# ---------------------------------------------------------------------------
def qmgmt(ptype, flags, qname=b''):
    b = bytearray(struct.pack('!BBBB', 0, 0, flags, ptype) + b'\x5a' * 20 +
                  struct.pack('!IIIHHHH', 3, 4, 0x0a000007, 7777, 2, 3, 4 if ptype == 1 else 9))
    body = {1: struct.pack('!I', 77) + struct.pack('!IHHHH', 0x0a000008, 7778, 1, 2, 0x7) * 4,
            5: struct.pack('!I', 5), 6: struct.pack('!II', 6, 7), 8: struct.pack('!I', 8)}.get(ptype, b'')
    b = b + body + qname
    b[1] = len(b)
    return (0x36, b)

def build_main():
    F = []
    def add(label, data, lt=1):
        F.append((label, lt, data))
    def rm(label, m, **kw):
        add(label, lbtrm(m, **kw))

    # ---- topic resolution: gives the transports and topic names ----
    add('LBMR TIR: topic.one on LBT-RM, topic.two on the same transport',
        lbmr_frame([tir_lbtrm('topic.one', 1), tir_lbtrm('topic.two', 2)]))
    add('LBMR TIR: topic.tcp on LBT-TCP (14380), topic.tcpsid on LBT-TCP with session id (14381)',
        lbmr_frame([tir_tcp('topic.tcp', 5, 14380), tir_tcp('topic.tcpsid', 6, 14381, sid=0x4242)]))

    # ---- data messages ----
    rm('data: plain', msg(T_MSG, [], b'Hello, LBM!', tidx=1, sqn=1))
    rm('data: REQUEST BATCH TOPICNAME APPHDR', msg(T_MSG, [H_request(), H_batch(), H_topicname(), H_apphdr()], b'payload-two', tidx=1, sqn=2))
    rm('data: SRCIDX OTID CTXINSTD CTXINSTR CTXINST', msg(T_MSG, [H_srcidx(), H_otid(), H_ctxinstd(), H_ctxinstr(), H_ctxinst(), H_ctxinsts()], b'payload-three', sqn=3))
    pr = props(PROPS)
    rm('data: APPHDR_CHAIN + LE message properties (all types)', msg(T_MSG, [H_chain(len(pr))], b'with props' + pr, sqn=4))
    pr_be = props(PROPS[:4] + PROPS[7:8], big=True)
    rm('data: APPHDR_CHAIN generic elements + BE message properties', msg(T_MSG, [H_chain(len(pr_be), extra=True)], b'with big-endian props' + pr_be, sqn=5))
    rm('data: UMQ_MSGID SQD_RCV RESUB ULB_MSG UMQ_SID', msg(T_MSG, [H_umq_msgid(), H_sqd_rcv(5), H_resub(), H_ulb_msg(), H_umq_sid()], b'umq data', sqn=6))
    rm('data: retransmission type, TOPIC_IDX TOPIC_SOURCE EXFUNC', msg(T_RETRANS, [H_topic_idx(), H_topic_source(), H_exfunc()], b'rx data', sqn=7))
    rm('data: PRORX type with HMAC TSNI-less', msg(T_PRORX, [H_hmac()], b'prorx data', sqn=8))
    for t, name in ((1, 'ctx_topic_list'), (2, 'rcv_msg_retrieve'), (3, 'rcv_msg_list'), (4, 'error')):
        rm('data: UMQ command response data (%s)' % name,
           msg(T_MSG, [H_sqd_rcv(0)], bytes(H_umq_cmd_resp(t, cmd_resp_body(t, True))[1]), sqn=9 + t))
    # EXTOPT
    cfg = cfgopt(1, 0, 'transport_lbtrm_mc', 'on') + cfgopt(3, 1, 'x', 'y')
    rm('data: EXTOPT cfgopt', msg(T_MSG, [H_extopt(0x80, 0x0100, 0, cfg)], b'xo1', sqn=14))
    rm('data: EXTOPT msgsel', msg(T_MSG, [H_extopt(0x40, 0x0101, 0, b'a > 5\0')], b'xo2', sqn=15))
    rm('data: EXTOPT unknown subtype', msg(T_MSG, [H_extopt(0x00, 0x0999, 0, b'\x01\x02\x03\x04')], b'xo3', sqn=16))
    rm('data: EXTOPT fragmented cfgopt (2 headers)', msg(T_MSG, [
        H_extopt(0x20, 0x0100, 0, cfg[:6]), H_extopt(0x00, 0x0100, 6, cfg[6:])], b'xo4', sqn=17))
    rm('data: EXTOPT fragmented msgsel', msg(T_MSG, [
        H_extopt(0x20, 0x0101, 0, b'abc'), H_extopt(0x00, 0x0101, 3, b'def\0')], b'xo5', sqn=18))
    rm('data: EXTOPT fragmented unknown', msg(T_MSG, [
        H_extopt(0x20, 0x0777, 0, b'\x01\x02'), H_extopt(0x00, 0x0777, 2, b'\x03\x04')], b'xo6', sqn=19))
    rm('data: DESTINATION STREAM-less, TCP_SID, TRANSPORT_SECURITY', msg(T_MSG, [H_destination(), H_tcp_sid(), H_transport_security(3), H_domain(), H_odomain()], b'dest', sqn=20))
    rm('data: TRANSPORT_SECURITY blackhole', msg(T_MSG, [H_transport_security(1)], b'bh', sqn=21))
    # Review reproducer: many tiny messages in one packet (extopt alloc)
    rm('review: 600 minimal LBMC messages in one packet', struct.pack('!BBH', 0x08, 0xFF, 4) * 600)

    # ---- fragments (unfragmented view by default, reassembled with the preference) ----
    def fragset(first, total_parts, order, plen=0, label='', chain=False, umq=False):
        parts = total_parts
        sizes = [len(p) for p in parts]
        total = sum(sizes)
        offs = [sum(sizes[:i]) for i in range(len(parts))]
        for k in order:
            hs = [H_frag(first, offs[k], total)]
            if k == 0 and chain:
                hs = [H_chain(plen)] + hs
            if k == 0 and umq:
                hs = [H_sqd_rcv(0)] + hs
            rm('fragment %s part %d' % (label, k), msg(T_MSG, hs, parts[k], sqn=first + k))
    fragset(100, [b'A' * 8, b'B' * 8, b'C' * 8], [0, 1, 2], label='in order (first_sqn 100)')
    fragset(110, [b'D' * 8, b'E' * 8, b'F' * 8, b'G' * 4], [3, 1, 0, 1, 2], label='out of order + duplicate (first_sqn 110)')
    pr = props([('k1', 4, 11), ('k2', 8, 'str')])
    body = b'fragmented message data' + pr
    cut = [body[:10], body[10:20], body[20:]]
    fragset(120, cut, [0, 1, 2], plen=len(pr), label='with msgprop (first_sqn 120)', chain=True)
    resp = bytes(H_umq_cmd_resp(1, cmd_resp_body(1, True))[1])
    fragset(130, [resp[:20], resp[20:]], [0, 1], label='UMQ cmd resp (first_sqn 130)', umq=True)
    fragset(140, [b'H' * 8, b'I' * 8], [0, 1], label='two part, review twopass (first_sqn 140)')
    fragset(150, [b'J' * 8, b'K' * 8], [1], label='incomplete (only last, first_sqn 150)')
    pdm = struct.pack('!4sBBBBII', b'\xa7\x1c\xca\xfe', 0, 0xFF, 1, 0, 77, 16)
    rm('data: LBMPDM header only payload (dissected with lbmc.dissect_lbmpdm)', msg(T_MSG, [], pdm, sqn=40))
    pdm_le = struct.pack('<4sBBBBII', b'\xfe\xca\x1c\xa7', 0, 0xFF, 1, 0, 78, 16)
    fragset(170, [pdm_le[:8], pdm_le[8:]], [0, 1], label='LBMPDM payload (first_sqn 170)')

    # ---- control messages (LBT-RM carries them as type CNTL) ----
    def c(label, *items):
        rm('control: ' + label, ctl(list(items)))
    c('SSF_INIT', H_ssf_init())
    c('SSF_CREQ', H_ssf_creq())
    c('UME_PREG', H_preg())
    c('UME_PREG_RESP (no E flag)', H_preg_resp(0x0f))
    c('UME_PREG_RESP (E flag)', H_preg_resp(0x2f))
    c('UME_ACK', H_ack())
    c('UME_RXREQ', H_rxreq(0x8000))
    c('UME_RXREQ with TSNI request flag', H_rxreq(0x4000))
    c('UME_KEEPALIVE', H_keepalive())
    c('UME_STOREID', H_storeid())
    c('UME_RANGED_ACK ACK_ID CAPABILITY PROXY_SRC', H_ranged_ack(), H_ack_id(), H_capability(), H_proxy_src())
    c('UME_STORE_GROUP STORE_INFO STORE_INFO_EXT LJ_INFO', H_store_group(), H_store(), H_store_ext(), H_lj_info())
    c('UME_RANGED_RXREQ', H_ranged_rxreq())
    c('PSRC_ELECTION_TOKEN', H_election_token())
    c('PSER', H_pser())
    c('TSNI (3 records)', H_tsni(3))
    for t in range(1, 9):
        c('UMQ_REG type %d' % t, H_umq_reg(t))
    for t in (1, 9, 0xFF, 2, 3, 4, 5, 6, 7, 8):
        c('UMQ_REG_RESP type 0x%02x' % t, H_umq_reg_resp(t))
    for t in (1, 2, 3):
        c('UMQ_ACK type %d' % t, H_umq_ack(t))
    c('UMQ_RCR', H_umq_rcr())
    c('UMQ_ULB_RCR', H_ulb_rcr())
    c('UMQ_LF', H_umq_lf())
    for t in (0, 1, 2, 3, 0x10, 0x11, 0x12, 0x13):
        c('UMQ_KA type 0x%02x' % t, H_umq_ka(t))
    for t in range(1, 8):
        c('UMQ_RXREQ type %d (addr resp)' % t, H_umq_rxreq(t, False))
    c('UMQ_RXREQ type 1 (regid resp)', H_umq_rxreq(1, True))
    for ptype in range(1, 9):
        for fl in (0x00, 0x7f) if ptype in (1, 3) else (0x7f,):
            rm('control: UMQ_QMGMT type %d flags 0x%02x' % (ptype, fl), msg(T_CNTL, [qmgmt(ptype, fl, b'queue-1\0' if fl else b'')]))
    c('UMQ_RESUB_REQ', H_umq_resub_req())
    c('UMQ_RESUB_RESP', H_umq_resub_resp())
    c('TOPIC_INTEREST', H_topic_interest())
    c('PATTERN_INTEREST', H_pattern_interest())
    c('ADVERTISEMENT', H_advert())
    c('STORENAME STORE_DOMAIN', H_storename(), H_store_domain())
    c('CTXINFO without name', H_ctxinfo(0xf400))
    c('CTXINFO with name', H_ctxinfo(0xfc00, b'my-context\0'))
    c('TNWG_CAPABILITIES', H_tnwg_cap())
    c('PATIDX', H_patidx())
    c('UME_CLIENT_LIFETIME UME_SID', H_client_lifetime(), H_ume_sid())
    c('IDX_CMD type 1', H_idx_cmd(1))
    for t in (2, 3, 4):
        c('IDX_CMD type %d' % t, H_idx_cmd(t))
    for t in (1, 2, 3, 4, 5, 6, 0xFF):
        c('IDX_CMD_RESP type 0x%02x' % t, H_idx_cmd_resp(t, flags=0xa0 if t == 0xFF else 0x80))
    for t in (7, 8):
        c('IDX_CMD_RESP type %d string index' % t, H_idx_cmd_resp(t, b'index-two\0'))
        c('IDX_CMD_RESP type %d numeric index' % t, H_idx_cmd_resp(t, struct.pack('!I', 5), numeric=True))
    c('STREAM', H_stream())
    c('TOPIC_MD_INTEREST', H_topic_md(2))
    c('PATTERN_MD_INTEREST', H_pattern_md(3))
    c('LJI_REQ', H_lji_req())
    c('TNWG_KA', H_tnwg_ka())
    c('UME_RCV_KEEPALIVE', H_rcv_ka())
    for t in (1, 2, 3):
        c('UMQ_CMD type %d' % t, H_umq_cmd(t, cmd_body(t)))
    for t in (1, 2, 3, 4):
        c('UMQ_CMD_RESP type %d' % t, H_umq_cmd_resp(t, cmd_resp_body(t, False)))
    c('UMQ_CMD_RESP without body', H_umq_cmd_resp(1, b''))
    c('SRI_REQ', H_sri_req())
    c('SRI', H_sri())
    c('ROUTE_INFO ROUTE_INFO_NEIGHBOR', H_route_info(), H_route_nbr())
    c('ROUTE_INFO_NBR_EXT (3 groups)', H_route_nbr_ext(3))
    c('ROUTE_INFO_NBR_EXT (no groups)', H_route_nbr_ext(0))
    c('GATEWAY_NAME DOMAIN', H_gateway_name(), H_domain())
    for op in (1, 2, 3, 4):
        c('AUTHENTICATION opid %d (placeholder bytes)' % op, H_auth(op))
    c('UMQ_SID', H_umq_sid())
    c('TCP_SID', H_tcp_sid())
    c('TRANSPORT_SECURITY', H_transport_security(5))
    c('TOPIC_SOURCE', H_topic_source())
    c('HMAC', H_hmac())
    c('EXTOPT cfgopt', H_extopt(0x80, 0x0100, 0, cfgopt(2, 0, 'a', 'b')))
    c('TNWG KA with CTXINFO', H_tnwg_ka(), H_ctxinfo(0x0400))
    # EOT and several messages in one LBT-RM packet
    rm('EOT message', msg(T_EOT, []))
    rm('three messages in one packet (data, control, EOT)',
       msg(T_MSG, [], b'first', sqn=30) + ctl([H_ack()]) + msg(T_EOT, []) + msg(T_MSG, [H_frag(160, 0, 4)], b'ABCD', sqn=31))
    return F

def build_tcp():
    """LBMC over TCP (UIM streams). Source/client ports in the LBT-TCP ranges."""
    F = []
    def add(label, data):
        for k, d in enumerate(data):
            F.append((label if k == len(data) - 1 else 'tcp handshake for: ' + label, 1, d))
    SRCI, CLI = '10.0.0.1', '10.0.0.2'
    def cs(label, m):    # client -> source, source port 14380
        add(label, tcp(m, CLI, SRCI, 50000, 14380))
    def sc(label, m):
        add(label, tcp(m, SRCI, CLI, 14380, 50000))
    cs('tcp: client -> source control', ctl([H_ack()]))
    sc('tcp: source -> client data', msg(T_MSG, [], b'tcp data', tidx=5, sqn=1))
    sc('tcp: source -> client data 2', msg(T_MSG, [], b'tcp data 2', tidx=5, sqn=2))
    cs('tcp: client -> source request data', msg(T_MSG, [H_request()], b'req', tidx=5, sqn=3))
    add('tcp: client -> source (14381) control',  tcp(ctl([H_ack()]), CLI, SRCI, 50002, 14381))
    add('tcp: source (14381) -> client data with TCP_SID', tcp(msg(T_MSG, [H_tcp_sid(0x4242)], b'sid data', tidx=6, sqn=1), SRCI, CLI, 14381, 50002))
    add('tcp: source (14381) -> client data', tcp(msg(T_MSG, [], b'sid data 2', tidx=6, sqn=2), SRCI, CLI, 14381, 50002))
    # UIM stream messages on a non-transport connection (ports in the request range)
    def uim(label, m, a=SRCI, b=CLI, ap=14391, bp=50001):
        add(label, tcp(m, a, b, ap, bp))
    uim('uim: reverse direction first', msg(T_MSG, [H_stream(8, 1, b'\x22' * 8), H_ctxinstd(b'\x11' * 8)], b'uim back', tidx=0, sqn=1), a=CLI, b=SRCI, ap=50001, bp=14391)
    uim('uim: instance stream data (STREAM + CTXINSTD)', msg(T_MSG, [H_stream(7, 1, b'\x11' * 8), H_ctxinstd(b'\x22' * 8)], b'uim one', tidx=0, sqn=1))
    uim('uim: instance stream data second message', msg(T_MSG, [H_stream(7, 2, b'\x11' * 8), H_ctxinstd(b'\x22' * 8)], b'uim two', tidx=0, sqn=2))
    uim('uim: instance stream, ctxinst order swapped', msg(T_MSG, [H_stream(9, 1, b'\x33' * 8), H_ctxinstd(b'\x02' * 8)], b'uim three', tidx=0, sqn=1))
    uim('uim: domain stream data (STREAM + DESTINATION)', msg(T_MSG, [H_stream(10, 1), H_destination(1, 2, '10.1.1.1', '10.2.2.2', 5000, 6000)], b'dom one', tidx=0, sqn=1))
    uim('uim: domain stream data, other order of endpoints', msg(T_MSG, [H_stream(10, 2), H_destination(3, 1, '10.1.1.1', '10.2.2.2', 5001, 6000)], b'dom two', tidx=0, sqn=2))
    uim('uim: domain stream data, same port', msg(T_MSG, [H_stream(11, 1), H_destination(4, 4, '10.1.1.1', '10.2.2.2', 5000, 5000)], b'dom three', tidx=0, sqn=1))
    uim('uim: domain stream, same domain, addresses ordered', msg(T_MSG, [H_stream(12, 1), H_destination(5, 5, '10.1.1.1', '10.2.2.2', 5000, 5000)], b'dom four', tidx=0, sqn=1))
    uim('uim: domain stream, same domain, addresses reversed', msg(T_MSG, [H_stream(13, 1), H_destination(6, 6, '10.2.2.2', '10.1.1.1', 5000, 5000)], b'dom five', tidx=0, sqn=1))
    uim('uim: domain stream, same address, ports ordered', msg(T_MSG, [H_stream(14, 1), H_destination(7, 7, '10.1.1.1', '10.1.1.1', 5000, 6000)], b'dom six', tidx=0, sqn=1))
    uim('uim: domain stream, same address, ports reversed', msg(T_MSG, [H_stream(15, 1), H_destination(8, 8, '10.1.1.1', '10.1.1.1', 7000, 6000)], b'dom seven', tidx=0, sqn=1))
    uim('uim: UMQ command response on a stream (no message type)', msg(T_MSG, [H_stream(7, 4), H_ctxinstd(b'\x22' * 8), H_sqd_rcv(0)], bytes(H_umq_cmd_resp(4, cmd_resp_body(4, True))[1]), tidx=0, sqn=4))
    uim('uim: retransmission style data (no source index)', msg(T_RETRANS, [H_request()], b'rx req', tidx=0, sqn=3))
    uim('uim: control message (ACK) with stream', ctl([H_stream(7, 3), H_ctxinstd(b'\x22' * 8), H_ack()]))
    uim('uim: control message ADVERTISEMENT with DESTINATION', ctl([H_stream(10, 3), H_destination(), H_advert()]))
    # Payloads that the LBT-TCP heuristic refuses (lbmc_test_lbmc_header() is false):
    # the frames stay TCP, none of them is an error
    bad = [('shorter than the minimal header', b'\x08\x14'),
           ('version 1', struct.pack('!BBH', 0x18, 0x14, 8) + b'\0' * 4),
           ('unknown type 3', struct.pack('!BBH', 0x03, 0x14, 8) + b'\0' * 4),
           ('unknown first header 0x70', struct.pack('!BBH', 0x08, 0x70, 8) + b'\0' * 4),
           ('message length zero', struct.pack('!BBH', 0x08, 0x14, 0) + b'\0' * 4)]
    for k, (label, payload) in enumerate(bad):
        uim('tcp: not LBMC, ' + label, payload, a=CLI, b=SRCI, ap=51000 + k, bp=14385)
    return F

def build_malformed():
    F = []
    def rm(label, m):
        F.append((label, 1, lbtrm(m, session=0x55667788, sport=14391)))
    def raw(label, b):
        rm(label, b)
    # invalid type / zero lengths
    raw('invalid LBMC type 0x05', struct.pack('!BBH', 0x05, 0xFF, 8) + b'\0' * 4)
    raw('zero message length', struct.pack('!BBH', 0x08, 0xFF, 0) + b'\0' * 8)
    raw('zero header length', struct.pack('!BBH', 0x08, 0x11, 8) + bytes([0xFF, 0, 0, 0]))
    rm('unhandled header TGIDX (0x03)', msg(T_CNTL, [(0x03, basic(b'tgidx-data'))]))
    rm('unhandled header 0x70', msg(T_CNTL, [(0x70, basic(b'unknown'))]))
    rm('unhandled header with hdr_len 4', msg(T_CNTL, [(0x70, bytearray(struct.pack('!BBH', 0, 4, 0)))]))
    rm('TOPICNAME without name', msg(T_MSG, [(0x05, bytearray(struct.pack('!BBH', 0, 4, 0)))], b'x'))
    rm('APPHDR without data', msg(T_MSG, [(0x06, bytearray(struct.pack('!BBH', 0, 4, 0)))], b'x'))
    rm('STORENAME without name', msg(T_CNTL, [(0x3D, bytearray(struct.pack('!BBH', 0, 4, 0)))]))
    rm('GATEWAY_NAME without name', msg(T_CNTL, [(0x58, bytearray(struct.pack('!BBH', 0, 4, 0)))]))
    rm('CTXINFO name flag without name', msg(T_CNTL, [H_ctxinfo(0x0800)]))
    rm('ROUTE_INFO_NBR_EXT odd group length', msg(T_CNTL, [(0x6E, hdr(C + 'route_info_nbr_ext_hdr_t', flags=0, trail=b'\x01')) ]))
    # chain elements
    ch = bytearray(struct.pack('!BBBB', 0, 4 + 4, 0, 0x01) + bytes([0, 0, 0, 0]))
    rm('APPHDR_CHAIN element with zero length', msg(T_MSG, [(0x07, ch)], b'x'))
    ch = bytearray(struct.pack('!BBBB', 0, 4 + 4, 0, 0x06) + bytes([0, 0, 0, 0]))
    rm('APPHDR_CHAIN msgprop element with zero length', msg(T_MSG, [(0x07, ch)], b'x'))
    ch = bytearray(struct.pack('!BBBB', 0, 4 + 4, 0, 0x01) + bytes([0, 4, 0, 0]))
    rm('APPHDR_CHAIN element with length 4 (no data)', msg(T_MSG, [(0x07, ch)], b'x'))
    ch = bytearray(struct.pack('!BBBB', 0, 4 + 4, 0, 0x01) + bytes([0, 40, 0, 0]))
    rm('APPHDR_CHAIN element longer than chain', msg(T_MSG, [(0x07, ch)], b'x'))
    # invalid subtypes
    b = H_umq_reg(1)
    b[1][3] = 0x66
    rm('UMQ_REG invalid type', msg(T_CNTL, [b]))
    b = H_umq_reg_resp(1)
    b[1][3] = 0x66
    rm('UMQ_REG_RESP invalid type', msg(T_CNTL, [b]))
    b = H_umq_ack(1)
    b[1][3] = 0x66
    rm('UMQ_ACK invalid type', msg(T_CNTL, [b]))
    b = H_umq_ka(1)
    b[1][3] = 0x66
    rm('UMQ_KA invalid type', msg(T_CNTL, [b]))
    b = H_umq_rxreq(1)
    b[1][3] = 0x66
    rm('UMQ_RXREQ invalid type', msg(T_CNTL, [b]))
    b = H_idx_cmd(1)
    b[1][3] = 0x66
    rm('IDX_CMD invalid type', msg(T_CNTL, [b]))
    b = H_idx_cmd_resp(1)
    b[1][3] = 0x66
    rm('IDX_CMD_RESP invalid type', msg(T_CNTL, [b]))
    rm('UMQ_CMD invalid type', msg(T_CNTL, [H_umq_cmd(9, b'\0' * 8)]))
    rm('UMQ_CMD_RESP invalid type', msg(T_CNTL, [H_umq_cmd_resp(9, b'\0' * 8)]))
    rm('AUTHENTICATION unknown opid', msg(T_CNTL, [H_auth(9)]))
    rm('AUTHENTICATION unknown opid without data', msg(T_CNTL, [(0x60, hdr(C + 'auth_generic_hdr_t', flags=0, opid=9))]))
    # IDX_CMD release/reserve: index_len is computed from hdr_len without
    # the base header, so the index item reads past the header (README)
    for t in (5, 6, 7, 8):
        rm('IDX_CMD type %d string index (item runs past the header)' % t, msg(T_CNTL, [H_idx_cmd(t, b'index-one\0')]))
        rm('IDX_CMD type %d numeric index (item runs past the header)' % t, msg(T_CNTL, [H_idx_cmd(t, struct.pack('!Q', 77), numeric=True)]))
    # three-part fragmented EXTOPT: the continuation item uses offset + len_dissected
    cfg = cfgopt(1, 0, 'transport_lbtrm_mc', 'on') + cfgopt(3, 1, 'x', 'y')
    rm('EXTOPT fragmented cfgopt (3 headers, middle part reads past the header)', msg(T_MSG, [
        H_extopt(0x20, 0x0100, 0, cfg[:6]), H_extopt(0x20, 0x0100, 6, cfg[6:12]), H_extopt(0x00, 0x0100, 12, cfg[12:])], b'xo4'))
    # APPHDR_CHAIN in the order the protocol describes (each element's next_hdr
    # names the following element): the dissector reads the type from the wrong byte
    ch = bytearray(struct.pack('!BBBB', 0, 4 + 16, 0, 0x01) + bytes([6, 8, 0, 0]) + struct.pack('!I', 4) + bytes([0, 8, 0, 0]) + struct.pack('!I', 12))
    rm('observation: APPHDR_CHAIN, next_hdr names the following element', msg(T_MSG, [(0x07, ch)], b'x' + b'\0' * 12))
    rm('message properties with invalid property type 9', msg(T_MSG, [H_chain(len(props([('odd', 9, 7)])))], b'x' + props([('odd', 9, 7)])))
    # message properties
    rm('message properties with bad magic', msg(T_MSG, [H_chain(24)], b'x' + b'\x00' * 24))
    pr = props([('a', 8, 'v')])
    bad = pr[:8] + struct.pack('<IIII', 24, 26, 0, 0x55) + pr[24:]
    rm('message properties with invalid type', msg(T_MSG, [H_chain(len(bad))], b'x' + bad))
    # review reproducer (scaled down): every field points at the same string
    N = 40
    start = 8 + N * 16
    pb = struct.pack('<IHBB', 0xABACDABA, N, 0, 0) + struct.pack('<IIII', start, start, 0, 8) * N + b'A' * 3000 + b'\0'
    rm('review: message properties with all fields at one string', msg(T_MSG, [H_chain(len(pb))], b'x' + pb))
    rm('message properties with offsets beyond the data', msg(T_MSG, [H_chain(8 + 16)], b'x' + struct.pack('<IHBB', 0xABACDABA, 1, 0, 0) + struct.pack('<IIII', 1000, 1000, 0, 8)))
    # EXTOPT
    rm('EXTOPT continuation without start', msg(T_MSG, [H_extopt(0x20, 0x0100, 5, b'\x01\x02\x03\x04')], b'x'))
    rm('EXTOPT fragment too large', msg(T_MSG, [H_extopt(0x20, 0x0100, 0, b'ab'), H_extopt(0x20, 0x0100, 0xfff0, b'cd'), H_extopt(0x20, 0x0100, 0xfff0, b'ef')][:1] + [H_extopt(0x20, 0x0100, 65535, b'cd')], b'x'))
    rm('EXTOPT end fragment too large', msg(T_MSG, [H_extopt(0x20, 0x0100, 0, b'ab'), H_extopt(0x00, 0x0100, 65535, b'cd')], b'x'))
    rm('EXTOPT unfragmented start too large', msg(T_MSG, [H_extopt(0x20, 0x0100, 0, b'a'), H_extopt(0x20, 0x0100, 65535, b'b')], b'x'))
    # fragments (offsets checked with the preference on)
    def fr(label, first, off, total, data, sqn):
        rm(label, msg(T_MSG, [H_frag(first, off, total)], data, sqn=sqn))
    fr('fragment overlap: first', 200, 0, 16, b'A' * 8, 200)
    fr('fragment overlap: second overlaps first (review uninit)', 200, 4, 16, b'B' * 8, 201)
    fr('fragment beyond total length', 210, 8, 12, b'C' * 8, 210)
    fr('fragment first of message with total 12', 220, 0, 12, b'D' * 8, 220)
    fr('fragment exceeding accumulated total', 220, 8, 12, b'E' * 8, 221)
    # truncated header
    rm('header longer than the message', msg(T_CNTL, [(0x14, bytearray(struct.pack('!BBH', 0, 100, 0) + b'\0' * 8))]))
    rm('TSNI shorter than its records', msg(T_CNTL, [(0x20, bytearray(struct.pack('!BBH', 0, 12, 5) + b'\0' * 8))]))
    rm('truncated LBMC header after type', struct.pack('!BBHII', 0x00, 0x00, 24, 1, 1) + b'')
    rm('unhandled header with hdr_len 2', msg(T_CNTL, [(0x70, bytearray(struct.pack('!BBBBBB', 0, 2, 0, 0, 0, 0)))]))
    return F

def build_tcp_unknown_transport():
    """LBT-TCP frames for a source port without topic resolution: the
    channel is only known on the second pass, the output differs between one
    and two passes, so they are not part of the main capture."""
    F = []
    SRCI, CLI = '10.0.0.1', '10.0.0.2'
    def add(label, data):
        for k, d in enumerate(data):
            F.append((label if k == len(data) - 1 else 'tcp handshake for: ' + label, 1, d))
    sid = lambda s: (0x6B, hdr(C + 'tcp_sid_hdr_t', flags=0x8000, sid=s))
    # from the source (source port 14386, no TIR)
    add('tcp without TIR: client -> source', tcp(ctl([H_ack()]), CLI, SRCI, 52000, 14386))
    add('tcp without TIR: source -> client with TCP_SID', tcp(msg(T_MSG, [sid(0x7001)], b'sid data', tidx=9, sqn=1), SRCI, CLI, 14386, 52000))
    add('tcp without TIR: source -> client', tcp(msg(T_MSG, [], b'sid data 2', tidx=9, sqn=2), SRCI, CLI, 14386, 52000))
    # from the client of a second source (14387): the client side of the connection sends the TCP_SID
    add('tcp without TIR: client -> source with TCP_SID', tcp(msg(T_MSG, [sid(0x7002)], b'client sid data', tidx=9, sqn=1), CLI, SRCI, 52001, 14387))
    add('tcp without TIR: client -> source', tcp(msg(T_MSG, [], b'client data', tidx=9, sqn=2), CLI, SRCI, 52001, 14387))
    add('tcp without TIR: source -> client', tcp(msg(T_MSG, [], b'source data', tidx=9, sqn=3), SRCI, CLI, 14387, 52001))
    return F

def build_exported():
    """Exported PDU frames without address tags (review reproducers of the
    NULL address fixes)."""
    F = []
    tcp_tags = tlv(24, struct.pack('!I', 2)) + tlv(25, struct.pack('!I', 14390)) + tlv(26, struct.pack('!I', 14400))
    stream = H_stream(7, 1, b'\x11' * 8)
    ctxd = H_ctxinstd(b'\x22' * 8)
    F.append(('review: Exported PDU without addresses, STREAM + CTXINSTD',
              252, exported('lbtrm', lbtrm_pdu(msg(T_MSG, [stream, ctxd], b'stream data', tidx=0, sqn=1)), tcp_tags)))
    F.append(('review: Exported PDU without addresses, fragment',
              252, exported('lbtrm', lbtrm_pdu(msg(T_MSG, [H_frag(300, 0, 32)], b'C' * 8, sqn=300)), tcp_tags)))
    F.append(('review: Exported PDU without addresses, fragment (second)',
              252, exported('lbtrm', lbtrm_pdu(msg(T_MSG, [H_frag(300, 8, 32)], b'D' * 24, sqn=301)), tcp_tags)))
    return F

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    Net.ident = 0
    main_frames = build_main()
    main_frames += build_tcp()
    main_frames += build_exported()
    pcapng(os.path.join(out, 'lbmc-coverage.pcapng'), [(l, d) for _, l, d in main_frames])
    mal = build_malformed() + build_tcp_unknown_transport()
    pcapng(os.path.join(out, 'lbmc-coverage-malformed.pcapng'), [(l, d) for _, l, d in mal])
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for i, (lab, _, d) in enumerate(main_frames, 1):
            f.write('main %d %s\n' % (i, lab))
        for i, (lab, _, d) in enumerate(mal, 1):
            f.write('malformed %d %s\n' % (i, lab))
    print(len(main_frames), len(mal))

main()
