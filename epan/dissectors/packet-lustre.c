/* packet-lustre.c
 * Routines for lustre dissection
 * Copyright (c) 2011, 2016, 2017 Intel Corporation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is accurate for Lustre dissection as of Lustre 2.10.2 - November 2017
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-tcp.h"
#include "packet-lnet.h"

void proto_reg_handoff_lustre(void);
void proto_register_lustre(void);

/* Initialize the protocol and registered fields */
static int proto_lustre = -1;

static int hf_lustre_lustre_msg_v1_lm_magic = -1;
static int hf_lustre_lustre_msg_v1_lm_handle = -1;
static int hf_lustre_lustre_msg_v1_lm_last_xid = -1;
static int hf_lustre_lustre_msg_v1_lm_status = -1;
static int hf_lustre_lustre_msg_v1_lm_type = -1;
static int hf_lustre_lustre_msg_v1_lm_flags = -1;
static int hf_lustre_lustre_msg_v1_lm_last_committed = -1;
static int hf_lustre_lustre_msg_v1_lm_buflens = -1;
static int hf_lustre_lustre_msg_v1_lm_conn_cnt = -1;
static int hf_lustre_lustre_msg_v1_lm_transno = -1;
static int hf_lustre_lustre_msg_v1_lm_opc = -1;
static int hf_lustre_lustre_msg_v1_lm_version = -1;
static int hf_lustre_lustre_msg_v1_lm_bufcount = -1;
static int hf_lustre_lustre_msg_v2_lm_magic = -1;
static int hf_lustre_lustre_msg_v2_lm_bufcount = -1;
static int hf_lustre_lustre_msg_v2_lm_repsize = -1;
static int hf_lustre_lustre_msg_v2_lm_cksum = -1;
static int hf_lustre_lustre_msg_v2_lm_buflens = -1;
static int hf_lustre_lustre_msg_v2_lm_flags = -1;
static int hf_lustre_lustre_msg_v2_lm_secflvr = -1;
static int hf_lustre_lustre_msg_v2_lm_padding_2 = -1;
static int hf_lustre_lustre_msg_v2_lm_padding_3 = -1;
static int hf_lustre_extra_padding = -1;
static int hf_lustre_target_uuid = -1;
static int hf_lustre_client_uuid = -1;
static int hf_lustre_mdt_body = -1;
static int hf_lustre_mdt_body_fid1 = -1;
static int hf_lustre_mdt_body_fid2 = -1;
static int hf_lustre_mdt_body_handle = -1;
static int hf_lustre_mdt_body_valid = -1;
static int hf_lustre_mdt_body_size = -1;
static int hf_lustre_mdt_body_mtime = -1;
static int hf_lustre_mdt_body_atime = -1;
static int hf_lustre_mdt_body_ctime = -1;
static int hf_lustre_mdt_body_blocks = -1;
static int hf_lustre_mdt_body_ioepoch = -1;
static int hf_lustre_mdt_body_ino = -1;
static int hf_lustre_mdt_body_fsuid = -1;
static int hf_lustre_mdt_body_fsgid = -1;
static int hf_lustre_mdt_body_capability = -1;
static int hf_lustre_mdt_body_mode = -1;
static int hf_lustre_mdt_body_uid = -1;
static int hf_lustre_mdt_body_gid = -1;
static int hf_lustre_mdt_body_flags = -1;
static int hf_lustre_mdt_body_rdev = -1;
static int hf_lustre_mdt_body_nlink = -1;
static int hf_lustre_mdt_body_generation = -1;
static int hf_lustre_mdt_body_suppgid = -1;
static int hf_lustre_mdt_body_eadatasize = -1;
static int hf_lustre_mdt_body_aclsize = -1;
static int hf_lustre_mdt_body_max_mdsize = -1;
static int hf_lustre_mdt_body_max_cookiesize = -1;
static int hf_lustre_mdt_body_uid_h = -1;
static int hf_lustre_mdt_body_gid_h = -1;
static int hf_lustre_mdt_body_padding_5 = -1;
static int hf_lustre_mdt_body_padding_6 = -1;
static int hf_lustre_mdt_body_padding_7 = -1;
static int hf_lustre_mdt_body_padding_8 = -1;
static int hf_lustre_mdt_body_padding_9 = -1;
static int hf_lustre_mdt_body_padding_10 = -1;
static int hf_lustre_close_data = -1;
static int hf_lustre_close_fid = -1;
static int hf_lustre_close_handle = -1;
static int hf_lustre_close_data_ver = -1;
static int hf_lustre_close_reserved = -1;
static int hf_lustre_mdt_key = -1;
static int hf_lustre_mdt_val = -1;
static int hf_lustre_mdt_vallen = -1;
static int hf_lustre_mdt_rec_reint = -1;
static int hf_lustre_mdt_rec_reint_opcode = -1;
static int hf_lustre_mdt_rec_reint_cap = -1;
static int hf_lustre_mdt_rec_reint_fsuid = -1;
static int hf_lustre_mdt_rec_reint_fsuid_h = -1;
static int hf_lustre_mdt_rec_reint_fsgid = -1;
static int hf_lustre_mdt_rec_reint_fsgid_h = -1;
static int hf_lustre_mdt_rec_reint_suppgid1 = -1;
static int hf_lustre_mdt_rec_reint_suppgid1_h = -1;
static int hf_lustre_mdt_rec_reint_suppgid2 = -1;
static int hf_lustre_mdt_rec_reint_suppgid2_h = -1;
static int hf_lustre_mdt_rec_reint_mtime = -1;
static int hf_lustre_mdt_rec_reint_atime = -1;
static int hf_lustre_mdt_rec_reint_ctime = -1;
static int hf_lustre_mdt_rec_reint_time = -1;
static int hf_lustre_mdt_rec_reint_size32 = -1;
static int hf_lustre_mdt_rec_reint_size64 = -1;
static int hf_lustre_mdt_rec_reint_blocks = -1;
static int hf_lustre_mdt_rec_reint_bias = -1;
static int hf_lustre_mdt_rec_reint_mode = -1;
static int hf_lustre_mdt_rec_reint_flags = -1;
static int hf_lustre_mdt_rec_reint_flags_h = -1;
static int hf_lustre_mdt_rec_reint_attr_flags = -1;
static int hf_lustre_mdt_rec_reint_umask = -1;
static int hf_lustre_mdt_rec_reint_padding = -1;
static int hf_lustre_mdt_rec_reint_fid1 = -1;
static int hf_lustre_mdt_rec_reint_fid2 = -1;
static int hf_lustre_mdt_rec_reint_old_handle = -1;
static int hf_lustre_mdt_rec_reint_rdev = -1;
static int hf_lustre_mdt_rec_reint_valid = -1;
static int hf_lustre_mdt_rec_reint_ioepoch = -1;
static int hf_lustre_mdt_rec_reint_uid = -1;
static int hf_lustre_mdt_rec_reint_gid = -1;
static int hf_lustre_mdt_rec_reint_projid = -1;
static int hf_lustre_mdt_ioepoch = -1;
static int hf_lustre_mdt_ioepoch_ioepoch = -1;
static int hf_lustre_mdt_ioepoch_handle = -1;
static int hf_lustre_mdt_ioepoch_flags = -1;
static int hf_lustre_mdt_ioepoch_padding = -1;
static int hf_lustre_ptlrpc_body_pb = -1;
static int hf_lustre_ptlrpc_body_pb_last_committed = -1;
static int hf_lustre_ptlrpc_body_pb_version = -1;
static int hf_lustre_ptlrpc_body_pb_slv = -1;
static int hf_lustre_ptlrpc_body_pb_pre_version = -1;
static int hf_lustre_ptlrpc_body_pb_padding = -1;
static int hf_lustre_ptlrpc_body_pb_jobid = -1;
static int hf_lustre_ptlrpc_body_pb_timeout = -1;
static int hf_lustre_ptlrpc_body_pb_op_flags = -1;
static int hf_lustre_ptlrpc_body_pb_type = -1;
static int hf_lustre_ptlrpc_body_pb_flags = -1;
static int hf_lustre_ptlrpc_body_pb_limit = -1;
static int hf_lustre_ptlrpc_body_pb_transno = -1;
static int hf_lustre_ptlrpc_body_pb_service_time = -1;
static int hf_lustre_ptlrpc_body_pb_conn_cnt = -1;
static int hf_lustre_ptlrpc_body_pb_opc = -1;
static int hf_lustre_ptlrpc_body_pb_last_seen = -1;
static int hf_lustre_ptlrpc_body_pb_last_xid = -1;
static int hf_lustre_ptlrpc_body_pb_status = -1;
static int hf_lustre_ptlrpc_body_pb_handle = -1;
static int hf_lustre_mdc_swap_layouts = -1;
static int hf_lustre_mdc_swap_layouts_flags = -1;
static int hf_lustre_hsm_current_action = -1;
static int hf_lustre_hsm_current_action_state = -1;
static int hf_lustre_hsm_current_action_action = -1;
static int hf_lustre_hsm_archive = -1;
static int hf_lustre_hsm_archive_id = -1;
static int hf_lustre_hsm_req = -1;
static int hf_lustre_hsm_req_action = -1;
static int hf_lustre_hsm_req_archive_id = -1;
static int hf_lustre_hsm_req_flags = -1;
static int hf_lustre_hsm_req_itemcount = -1;
static int hf_lustre_hsm_req_data_len = -1;
static int hf_lustre_hsm_extent = -1;
static int hf_lustre_hsm_extent_offset = -1;
static int hf_lustre_hsm_extent_length = -1;
static int hf_lustre_hsm_prog = -1;
static int hf_lustre_hsm_prog_fid = -1;
static int hf_lustre_hsm_prog_cookie = -1;
static int hf_lustre_hsm_prog_flags = -1;
static int hf_lustre_hsm_prog_errval = -1;
static int hf_lustre_hsm_prog_data_ver = -1;
static int hf_lustre_hsm_prog_padding1 = -1;
static int hf_lustre_hsm_prog_padding2 = -1;
static int hf_lustre_hsm_user_state = -1;
static int hf_lustre_hsm_us_states = -1;
static int hf_lustre_hsm_us_archive_id = -1;
static int hf_lustre_hsm_us_in_prog_state = -1;
static int hf_lustre_hsm_us_in_prog_action = -1;
static int hf_lustre_hsm_us_ext_info = -1;
static int hf_lustre_hsm_state_set = -1;
static int hf_lustre_hsm_hss_valid = -1;
static int hf_lustre_hsm_hss_archive_id = -1;
static int hf_lustre_hsm_hss_setmask = -1;
static int hf_lustre_hsm_hss_clearmask = -1;
static int hf_lustre_obd_ioobj = -1;
static int hf_lustre_obd_ioobj_ioo_bufcnt = -1;
static int hf_lustre_obd_ioobj_ioo_id = -1;
static int hf_lustre_obd_ioobj_ioo_max_brw = -1;
static int hf_lustre_obd_ioobj_ioo_seq = -1;
static int hf_lustre_obd_statfs = -1;
static int hf_lustre_obd_statfs_os_type = -1;
static int hf_lustre_obd_statfs_os_bavail = -1;
static int hf_lustre_obd_statfs_os_bsize = -1;
static int hf_lustre_obd_statfs_os_maxbytes = -1;
static int hf_lustre_obd_statfs_os_ffree = -1;
static int hf_lustre_obd_statfs_os_files = -1;
static int hf_lustre_obd_statfs_os_bfree = -1;
static int hf_lustre_obd_statfs_os_namelen = -1;
static int hf_lustre_obd_statfs_os_blocks = -1;
static int hf_lustre_obd_statfs_os_fsid = -1;
static int hf_lustre_obd_statfs_os_state = -1;
static int hf_lustre_obd_statfs_os_fprecreated = -1;
static int hf_lustre_obd_statfs_os_spare = -1;
static int hf_lustre_obd_connect_data = -1;
static int hf_lustre_obd_connect_data_ocd_version = -1;
static int hf_lustre_obd_connect_data_ocd_grant = -1;
static int hf_lustre_obd_connect_data_ocd_nllg = -1;
static int hf_lustre_obd_connect_data_ocd_nllu = -1;
static int hf_lustre_obd_connect_data_ocd_grant_blkbits = -1;
static int hf_lustre_obd_connect_data_ocd_grant_inobits = -1;
static int hf_lustre_obd_connect_data_ocd_grant_tax_kb = -1;
static int hf_lustre_obd_connect_data_ocd_grant_max_blks = -1;
static int hf_lustre_obd_connect_data_ocd_padding = -1;
static int hf_lustre_obd_connect_data_ocd_ibits_known = -1;
static int hf_lustre_obd_connect_data_ocd_group = -1;
static int hf_lustre_obd_connect_data_ocd_brw_size = -1;
static int hf_lustre_obd_connect_data_ocd_index = -1;
static int hf_lustre_obd_connect_data_ocd_connect_flags = -1;
static int hf_lustre_obd_connect_data_ocd_connect_flags2 = -1;
static int hf_lustre_obd_connect_data_ocd_cksum_types = -1;
static int hf_lustre_obd_connect_data_ocd_max_easize = -1;
static int hf_lustre_obd_connect_data_ocd_instance = -1;
static int hf_lustre_obd_connect_data_ocd_maxbytes = -1;
static int hf_lustre_obd_connect_data_ocd_maxmodrpcs = -1;
static int hf_lustre_obd_connect_data_ocd_transno = -1;
static int hf_lustre_obd_uuid = -1;
static int hf_lustre_obd_quotactl = -1;
static int hf_lustre_obd_quotactl_qc_stat = -1;
static int hf_lustre_obd_quotactl_qc_cmd = -1;
static int hf_lustre_obd_quotactl_qc_id = -1;
static int hf_lustre_obd_quotactl_qc_type = -1;
static int hf_lustre_obd_dqinfo = -1;
static int hf_lustre_obd_dqinfo_dqi_valid = -1;
static int hf_lustre_obd_dqinfo_dqi_igrace = -1;
static int hf_lustre_obd_dqinfo_dqi_bgrace = -1;
static int hf_lustre_obd_dqinfo_dqi_flags = -1;
static int hf_lustre_obd_dqblk = -1;
static int hf_lustre_obd_dqblk_dqb_isoftlimit = -1;
static int hf_lustre_obd_dqblk_dqb_bhardlimit = -1;
static int hf_lustre_obd_dqblk_dqb_curspace = -1;
static int hf_lustre_obd_dqblk_dqb_itime = -1;
static int hf_lustre_obd_dqblk_dqb_valid = -1;
static int hf_lustre_obd_dqblk_padding = -1;
static int hf_lustre_obd_dqblk_dqb_curinodes = -1;
static int hf_lustre_obd_dqblk_dqb_bsoftlimit = -1;
static int hf_lustre_obd_dqblk_dqb_btime = -1;
static int hf_lustre_obd_dqblk_dqb_ihardlimit = -1;
static int hf_lustre_ost_body = -1;
static int hf_lustre_ost_key = -1;
static int hf_lustre_ost_val = -1;
static int hf_lustre_ost_lvb = -1;
static int hf_lustre_ost_lvb_atime = -1;
static int hf_lustre_ost_lvb_ctime = -1;
static int hf_lustre_ost_lvb_mtime = -1;
static int hf_lustre_ost_lvb_mtime_ns = -1;
static int hf_lustre_ost_lvb_atime_ns = -1;
static int hf_lustre_ost_lvb_ctime_ns = -1;
static int hf_lustre_ost_lvb_padding = -1;
static int hf_lustre_ost_lvb_size = -1;
static int hf_lustre_ost_lvb_blocks = -1;
static int hf_lustre_ost_id = -1;
static int hf_lustre_ost_id_fid = -1;
static int hf_lustre_ost_id_oi = -1;
static int hf_lustre_ost_layout = -1;
static int hf_lustre_ost_layout_stripe_size = -1;
static int hf_lustre_ost_layout_stripe_count = -1;
static int hf_lustre_ost_layout_comp_start = -1;
static int hf_lustre_ost_layout_comp_end = -1;
static int hf_lustre_ost_layout_comp_id = -1;
static int hf_lustre_lu_ladvise_hdr = -1;
static int hf_lustre_lu_ladvise_hdr_magic = -1;
static int hf_lustre_lu_ladvise_hdr_count = -1;
static int hf_lustre_lu_ladvise_hdr_flags = -1;
static int hf_lustre_lu_ladvise_hdr_value1 = -1;
static int hf_lustre_lu_ladvise_hdr_value2 = -1;
static int hf_lustre_lu_ladvise_hdr_value3 = -1;
static int hf_lustre_lu_ladvise = -1;
static int hf_lustre_lu_ladvise_advice = -1;
static int hf_lustre_lu_ladvise_value1 = -1;
static int hf_lustre_lu_ladvise_value2 = -1;
static int hf_lustre_lu_ladvise_start = -1;
static int hf_lustre_lu_ladvise_end = -1;
static int hf_lustre_lu_ladvise_value3 = -1;
static int hf_lustre_lu_ladvise_value4 = -1;
static int hf_lustre_llogd_body = -1;
static int hf_lustre_llogd_body_lgd_len = -1;
static int hf_lustre_llogd_body_lgd_logid = -1;
static int hf_lustre_llogd_body_lgd_index = -1;
static int hf_lustre_llogd_body_lgd_saved_index = -1;
static int hf_lustre_llogd_body_lgd_llh_flags = -1;
static int hf_lustre_llogd_body_lgd_cur_offset = -1;
static int hf_lustre_llogd_body_lgd_ctxt_idx = -1;
static int hf_lustre_llogd_conn_body = -1;
static int hf_lustre_llogd_conn_body_lgdc_gen = -1;
static int hf_lustre_llogd_conn_body_lgdc_logid = -1;
static int hf_lustre_llogd_conn_body_lgdc_ctxt_idx = -1;
static int hf_lustre_llog_rec = -1;
static int hf_lustre_llog_rec_hdr = -1;
static int hf_lustre_llog_rec_tail = -1;
static int hf_lustre_llog_rec_hdr_lrh_type = -1;
static int hf_lustre_llog_rec_hdr_lrh_len = -1;
static int hf_lustre_llog_rec_hdr_lrh_index = -1;
static int hf_lustre_llog_rec_hdr_lrh_id = -1;
static int hf_lustre_llog_rec_tail_lrt_index = -1;
static int hf_lustre_llog_rec_tail_lrt_len = -1;
static int hf_lustre_llog_log_hdr = -1;
static int hf_lustre_llog_log_hdr_tgtuuid = -1;
static int hf_lustre_llog_log_hdr_cat_idx = -1;
static int hf_lustre_llog_log_hdr_bitmap_offset = -1;
static int hf_lustre_llog_log_hdr_flags = -1;
static int hf_lustre_llog_log_hdr_size = -1;
static int hf_lustre_llog_log_hdr_tail = -1;
static int hf_lustre_llog_log_hdr_bitmap = -1;
static int hf_lustre_llog_log_hdr_count = -1;
static int hf_lustre_llog_log_hdr_timestamp = -1;
static int hf_lustre_llog_log_hdr_hdr = -1;
static int hf_lustre_llog_log_hdr_reserved = -1;
static int hf_lustre_llog_hdr_flag_zap_when_empty = -1;
static int hf_lustre_llog_hdr_flag_is_cat = -1;
static int hf_lustre_llog_hdr_flag_is_plain = -1;
static int hf_lustre_llog_hdr_flag_ext_jobid = -1;
static int hf_lustre_llog_hdr_flag_is_fixsize = -1;
static int hf_lustre_llog_gen_rec = -1;
static int hf_lustre_llog_gen_rec_hdr = -1;
static int hf_lustre_llog_gen_rec_tail = -1;
static int hf_lustre_llog_gen_rec_gen = -1;
static int hf_lustre_llog_gen_rec_padding = -1;
static int hf_lustre_llog_logid_rec = -1;
static int hf_lustre_llog_logid_rec_hdr = -1;
static int hf_lustre_llog_logid_rec_tail = -1;
static int hf_lustre_llog_logid_rec_id = -1;
static int hf_lustre_llog_logid_rec_padding = -1;
static int hf_lustre_llog_logid_lgl_ogen = -1;
static int hf_lustre_llog_unlink_rec = -1;
static int hf_lustre_llog_unlink_rec_hdr = -1;
static int hf_lustre_llog_unlink_rec_tail = -1;
static int hf_lustre_llog_unlink_rec_oseq = -1;
static int hf_lustre_llog_unlink_rec_oid = -1;
static int hf_lustre_llog_unlink_rec_count = -1;
static int hf_lustre_llog_unlink64_rec = -1;
static int hf_lustre_llog_unlink64_rec_hdr = -1;
static int hf_lustre_llog_unlink64_rec_fid = -1;
static int hf_lustre_llog_unlink64_rec_count = -1;
static int hf_lustre_llog_unlink64_rec_padding = -1;
static int hf_lustre_llog_unlink64_rec_tail = -1;
static int hf_lustre_llog_setattr64_rec = -1;
static int hf_lustre_llog_setattr64_rec_hdr = -1;
static int hf_lustre_llog_setattr64_rec_uid = -1;
static int hf_lustre_llog_setattr64_rec_uid_h = -1;
static int hf_lustre_llog_setattr64_rec_gid = -1;
static int hf_lustre_llog_setattr64_rec_gid_h = -1;
static int hf_lustre_llog_setattr64_rec_valid = -1;
static int hf_lustre_llog_setattr64_rec_tail = -1;
static int hf_lustre_llog_size_change_rec = -1;
static int hf_lustre_llog_size_change_rec_hdr = -1;
static int hf_lustre_llog_size_change_rec_io_epoch = -1;
static int hf_lustre_llog_size_change_rec_fid = -1;
static int hf_lustre_llog_size_change_rec_tail = -1;
static int hf_lustre_llog_size_change_rec_padding = -1;
static int hf_lustre_llog_cookie = -1;
static int hf_lustre_llog_cookie_lgc_lgl = -1;
static int hf_lustre_llog_cookie_lgc_padding = -1;
static int hf_lustre_llog_cookie_lgc_index = -1;
static int hf_lustre_llog_cookie_lgc_subsys = -1;
static int hf_lustre_llog_gen_conn_cnt = -1;
static int hf_lustre_llog_gen_mnt_cnt = -1;
static int hf_lustre_llog_setattr_rec = -1;
static int hf_lustre_llog_setattr_rec_hdr = -1;
static int hf_lustre_llog_setattr_rec_oseq = -1;
static int hf_lustre_llog_setattr_rec_padding = -1;
static int hf_lustre_llog_setattr_rec_uid = -1;
static int hf_lustre_llog_setattr_rec_oid = -1;
static int hf_lustre_llog_setattr_rec_gid = -1;
static int hf_lustre_llog_setattr_rec_tail = -1;
static int hf_lustre_llog_changelog_rec = -1;
static int hf_lustre_llog_changelog_rec_hdr = -1;
static int hf_lustre_llog_changelog_rec_tail = -1;
static int hf_lustre_changelog_rec = -1;
static int hf_lustre_changelog_rec_namelen = -1;
static int hf_lustre_changelog_rec_flags = -1;
static int hf_lustre_changelog_rec_type = -1;
static int hf_lustre_changelog_rec_index = -1;
static int hf_lustre_changelog_rec_prev = -1;
static int hf_lustre_changelog_rec_time = -1;
static int hf_lustre_changelog_rec_tfid = -1;
static int hf_lustre_changelog_rec_markerflags = -1;
static int hf_lustre_changelog_rec_padding = -1;
static int hf_lustre_changelog_rec_pfid = -1;
static int hf_lustre_changelog_ext_rename_sfid = -1;
static int hf_lustre_changelog_ext_rename_spfid = -1;
static int hf_lustre_changelog_ext_jobid_jobid = -1;
static int hf_lustre_changelog_extra_flags_extra_flags = -1;
static int hf_lustre_changelog_ext_name = -1;
static int hf_lustre_lustre_cfg = -1;
static int hf_lustre_lustre_cfg_version = -1;
static int hf_lustre_lustre_cfg_command = -1;
static int hf_lustre_lustre_cfg_num = -1;
static int hf_lustre_lustre_cfg_flags = -1;
static int hf_lustre_lustre_cfg_nid = -1;
static int hf_lustre_lustre_cfg_padding = -1;
static int hf_lustre_lustre_cfg_bufcount = -1;
static int hf_lustre_lustre_cfg_buflen = -1;
static int hf_lustre_lustre_cfg_buffer = -1;
static int hf_lustre_cfg_marker = -1;
static int hf_lustre_cfg_marker_step = -1;
static int hf_lustre_cfg_marker_flags = -1;
static int hf_lustre_cfg_marker_vers = -1;
static int hf_lustre_cfg_marker_padding = -1;
static int hf_lustre_cfg_marker_createtime = -1;
static int hf_lustre_cfg_marker_canceltime = -1;
static int hf_lustre_cfg_marker_tgtname = -1;
static int hf_lustre_cfg_marker_comment = -1;
static int hf_lustre_rcs = -1;
static int hf_lustre_rcs_rc = -1;
static int hf_lustre_fid_array = -1;
static int hf_lustre_fid_array_fid = -1;
static int hf_lustre_niobuf_remote = -1;
static int hf_lustre_niobuf_remote_len = -1;
static int hf_lustre_niobuf_remote_flags = -1;
static int hf_lustre_niobuf_remote_offset = -1;
static int hf_lustre_lov_ost_data_v1 = -1;
static int hf_lustre_lov_ost_data_v1_l_ost_gen = -1;
static int hf_lustre_lov_ost_data_v1_l_ost_idx = -1;
static int hf_lustre_lmv_mds_md = -1;
static int hf_lustre_lmv_mds_md_magic = -1;
static int hf_lustre_lmv_mds_md_stripe_count = -1;
static int hf_lustre_lmv_mds_md_master_mdt_index = -1;
static int hf_lustre_lmv_mds_md_hash_type = -1;
static int hf_lustre_lmv_mds_md_status = -1;
static int hf_lustre_lmv_mds_md_layout_version = -1;
static int hf_lustre_lmv_mds_md_padding = -1;
static int hf_lustre_lmv_mds_md_pool_name = -1;
static int hf_lustre_lmv_mds_md_stripe_fid = -1;
static int hf_lustre_lov_mds_md = -1;
static int hf_lustre_lov_mds_md_lmm_magic = -1;
static int hf_lustre_lov_mds_md_lmm_stripe_size = -1;
static int hf_lustre_lov_mds_md_lmm_object_id = -1;
static int hf_lustre_lov_mds_md_lmm_object_seq = -1;
static int hf_lustre_lov_mds_md_lmm_stripe_count = -1;
static int hf_lustre_lov_mds_md_lmm_pattern = -1;
static int hf_lustre_lov_mds_md_lmm_layout_gen = -1;
static int hf_lustre_lov_mds_md_lmm_pool_name = -1;
static int hf_lustre_lov_desc = -1;
static int hf_lustre_lov_desc_padding = -1;
static int hf_lustre_lov_desc_pattern = -1;
static int hf_lustre_lov_desc_default_stripe_count = -1;
static int hf_lustre_lov_desc_magic = -1;
static int hf_lustre_lov_desc_uuid = -1;
static int hf_lustre_lov_desc_tgt_count = -1;
static int hf_lustre_lov_desc_default_stripe_size = -1;
static int hf_lustre_lov_desc_default_stripe_offset = -1;
static int hf_lustre_lov_desc_qos_maxage = -1;
static int hf_lustre_quota_body = -1;
static int hf_lustre_qb_flags = -1;
static int hf_lustre_qb_fid = -1;
static int hf_lustre_qb_padding = -1;
static int hf_lustre_qb_lockh = -1;
static int hf_lustre_qb_glb_lockh = -1;
static int hf_lustre_qb_count = -1;
static int hf_lustre_qb_usage = -1;
static int hf_lustre_qb_slv_ver = -1;
static int hf_lustre_quota_adjust_qunit = -1;
static int hf_lustre_quota_adjust_qunit_qaq_id = -1;
static int hf_lustre_quota_adjust_qunit_qaq_flags = -1;
static int hf_lustre_quota_adjust_qunit_qaq_iunit_sz = -1;
static int hf_lustre_quota_adjust_qunit_qaq_bunit_sz = -1;
static int hf_lustre_quota_adjust_qunit_padding1 = -1;
static int hf_lustre_lquota_id = -1;
static int hf_lustre_qid_fid = -1;
static int hf_lustre_qid_uid = -1;
static int hf_lustre_qid_gid = -1;
static int hf_lustre_ldlm_extent_gid = -1;
static int hf_lustre_ldlm_extent_start = -1;
static int hf_lustre_ldlm_extent_end = -1;
static int hf_lustre_ldlm_flock_owner = -1;
static int hf_lustre_ldlm_flock_pid = -1;
static int hf_lustre_ldlm_flock_start = -1;
static int hf_lustre_ldlm_flock_end = -1;
static int hf_lustre_ldlm_flock_padding = -1;
static int hf_lustre_ldlm_request = -1;
static int hf_lustre_ldlm_request_lock_handle = -1;
static int hf_lustre_ldlm_request_lock_flags = -1;
static int hf_lustre_ldlm_request_lock_count = -1;
static int hf_lustre_ldlm_reply = -1;
static int hf_lustre_ldlm_reply_lock_flags = -1;
static int hf_lustre_ldlm_reply_lock_policy_res1 = -1;
static int hf_lustre_ldlm_reply_lock_policy_res2 = -1;
static int hf_lustre_ldlm_reply_lock_handle = -1;
static int hf_lustre_ldlm_reply_lock_padding = -1;
static int hf_lustre_ldlm_inodebits_bits = -1;
static int hf_lustre_ldlm_inodebits_try_bits = -1;
static int hf_lustre_ldlm_lock_desc = -1;
static int hf_lustre_ldlm_lock_desc_l_policy_data = -1;
static int hf_lustre_ldlm_lock_desc_l_granted_mode = -1;
static int hf_lustre_ldlm_lock_desc_l_req_mode = -1;
static int hf_lustre_ldlm_res_id = -1;
static int hf_lustre_ldlm_res_id_name = -1;
static int hf_lustre_ldlm_res_id_bits = -1;
static int hf_lustre_ldlm_res_id_string = -1;
static int hf_lustre_ldlm_res_id_type = -1;
static int hf_lustre_ldlm_resource_desc = -1;
static int hf_lustre_ldlm_resource_desc_lr_type = -1;
static int hf_lustre_ldlm_resource_desc_lr_padding = -1;
static int hf_lustre_ldlm_intent_opc = -1;
static int hf_lustre_ldlm_intent_opc_open = -1;
static int hf_lustre_ldlm_intent_opc_creat = -1;
static int hf_lustre_ldlm_intent_opc_readdir = -1;
static int hf_lustre_ldlm_intent_opc_getattr = -1;
static int hf_lustre_ldlm_intent_opc_lookup = -1;
static int hf_lustre_ldlm_intent_opc_unlink = -1;
static int hf_lustre_ldlm_intent_opc_trunc = -1;
static int hf_lustre_ldlm_intent_opc_getxattr = -1;
static int hf_lustre_ldlm_intent_opc_exec = -1;
static int hf_lustre_ldlm_intent_opc_pin = -1;
static int hf_lustre_ldlm_intent_opc_layout = -1;
static int hf_lustre_ldlm_intent_opc_q_dqacq = -1;
static int hf_lustre_ldlm_intent_opc_q_conn = -1;
static int hf_lustre_ldlm_intent_opc_setxattr = -1;
static int hf_lustre_ldlm_gl_barrier_desc = -1;
static int hf_lustre_ldlm_gl_barrier_desc_status = -1;
static int hf_lustre_ldlm_gl_barrier_desc_timeout = -1;
static int hf_lustre_ldlm_gl_barrier_desc_padding = -1;
static int hf_lustre_ldlm_gl_lquota_desc = -1;
static int hf_lustre_ldlm_gl_lquota_desc_flags = -1;
static int hf_lustre_ldlm_gl_lquota_desc_ver = -1;
static int hf_lustre_ldlm_gl_lquota_desc_hardlimit = -1;
static int hf_lustre_ldlm_gl_lquota_desc_softlimit = -1;
static int hf_lustre_ldlm_gl_lquota_desc_time = -1;
static int hf_lustre_ldlm_gl_lquota_desc_pad2 = -1;
static int hf_lustre_ldlm_key = -1;
static int hf_lustre_ldlm_val = -1;
static int hf_lustre_barrier_lvb = -1;
static int hf_lustre_barrier_lvb_status = -1;
static int hf_lustre_barrier_lvb_index = -1;
static int hf_lustre_barrier_lvb_padding = -1;
static int hf_lustre_mgs_target_info = -1;
static int hf_lustre_mgs_target_info_mti_flags = -1;
static int hf_lustre_mgs_target_info_mti_fsname = -1;
static int hf_lustre_mgs_target_info_mti_svname = -1;
static int hf_lustre_mgs_target_info_mti_config_ver = -1;
static int hf_lustre_mgs_target_info_mti_uuid = -1;
static int hf_lustre_mgs_target_info_mti_stripe_index = -1;
static int hf_lustre_mgs_target_info_mti_params = -1;
static int hf_lustre_mgs_target_info_mti_nids = -1;
static int hf_lustre_mgs_target_info_mti_lustre_ver = -1;
static int hf_lustre_mgs_target_info_mti_nid_count = -1;
static int hf_lustre_mgs_target_info_mti_instance = -1;
static int hf_lustre_mgs_target_info_padding = -1;
static int hf_lustre_mgs_send_param = -1;
static int hf_lustre_mgs_config_body = -1;
static int hf_lustre_mgs_config_body_name = -1;
static int hf_lustre_mgs_config_body_offset = -1;
static int hf_lustre_mgs_config_body_type = -1;
static int hf_lustre_mgs_config_body_nm_cur_pass = -1;
static int hf_lustre_mgs_config_body_bits = -1;
static int hf_lustre_mgs_config_body_units = -1;
static int hf_lustre_mgs_config_res = -1;
static int hf_lustre_mgs_config_res_offset = -1;
static int hf_lustre_mgs_config_res_size = -1;
static int hf_lustre_mgs_config_res_nm_cur_pass = -1;
static int hf_lustre_lustre_handle = -1;
static int hf_lustre_lustre_handle_cookie = -1;
static int hf_lustre_lu_fid_f_seq = -1;
static int hf_lustre_lu_fid_f_oid = -1;
static int hf_lustre_lu_fid_f_ver = -1;
static int hf_lustre_ost_oi_id = -1;
static int hf_lustre_ost_oi_seq = -1;
static int hf_lustre_obdo = -1;
static int hf_lustre_obdo_o_nlink = -1;
static int hf_lustre_obdo_o_uid = -1;
static int hf_lustre_obdo_o_valid = -1;
static int hf_lustre_obdo_o_misc = -1;
static int hf_lustre_obdo_o_padding_4 = -1;
static int hf_lustre_obdo_o_size = -1;
static int hf_lustre_obdo_o_mode = -1;
static int hf_lustre_obdo_o_handle = -1;
static int hf_lustre_obdo_o_atime = -1;
static int hf_lustre_obdo_o_gid = -1;
static int hf_lustre_obdo_o_ioepoch = -1;
static int hf_lustre_obdo_o_data_version = -1;
static int hf_lustre_obdo_o_projid = -1;
//static int hf_lustre_obdo_o_lcookie = -1;
static int hf_lustre_obdo_o_padding_6 = -1;
static int hf_lustre_obdo_o_padding_3 = -1;
static int hf_lustre_obdo_o_flags = -1;
static int hf_lustre_obdo_o_mtime = -1;
static int hf_lustre_obdo_o_blksize = -1;
static int hf_lustre_obdo_o_blocks = -1;
static int hf_lustre_obdo_o_grant = -1;
static int hf_lustre_obdo_o_uid_h = -1;
static int hf_lustre_obdo_o_gid_h = -1;
static int hf_lustre_obdo_o_stripe_idx = -1;
static int hf_lustre_obdo_o_parent_ver = -1;
static int hf_lustre_obdo_o_parent_oid = -1;
static int hf_lustre_obdo_o_padding_5 = -1;
static int hf_lustre_obdo_o_parent_seq = -1;
static int hf_lustre_obdo_o_ctime = -1;
static int hf_lustre_xattr_list = -1;
static int hf_lustre_xattr = -1;
static int hf_lustre_xattr_name = -1;
static int hf_lustre_xattr_data = -1;
static int hf_lustre_xattr_size = -1;
static int hf_lustre_seq_opc = -1;
static int hf_lustre_seq_range = -1;
static int hf_lustre_seq_range_start = -1;
static int hf_lustre_seq_range_end = -1;
static int hf_lustre_seq_range_index = -1;
static int hf_lustre_seq_range_flags = -1;
static int hf_lustre_fld_opc = -1;
static int hf_lustre_capa = -1;
static int hf_lustre_capa_fid = -1;
static int hf_lustre_capa_opc = -1;
static int hf_lustre_capa_uid = -1;
static int hf_lustre_capa_gid = -1;
static int hf_lustre_capa_flags = -1;
static int hf_lustre_capa_keyid = -1;
static int hf_lustre_capa_timeout = -1;
static int hf_lustre_capa_expiry = -1;
static int hf_lustre_capa_hmac = -1;
static int hf_lustre_acl = -1;
static int hf_lustre_hsm_user_item = -1;
static int hf_lustre_hsm_user_item_fid = -1;
static int hf_lustre_layout_intent = -1;
static int hf_lustre_layout_intent_opc = -1;
static int hf_lustre_layout_intent_flags = -1;
static int hf_lustre_layout_intent_start = -1;
static int hf_lustre_layout_intent_end = -1;
static int hf_lustre_data = -1;
static int hf_lustre_name = -1;
static int hf_lustre_filename = -1;
static int hf_lustre_secctx_name = -1;
static int hf_lustre_selinux_pol = -1;
static int hf_lustre_target = -1;
static int hf_lustre_eadata = -1;
static int hf_lustre_idx_info = -1;
static int hf_lustre_idx_info_magic = -1;
static int hf_lustre_idx_info_flags = -1;
static int hf_lustre_idx_info_count = -1;
static int hf_lustre_idx_info_attrs = -1;
static int hf_lustre_idx_info_fid = -1;
static int hf_lustre_idx_info_hash_start = -1;
static int hf_lustre_idx_info_hash_end = -1;
static int hf_lustre_idx_info_keysize = -1;
static int hf_lustre_idx_info_recsize = -1;
static int hf_lustre_idx_info_padding = -1;
static int hf_lustre_out_update_header = -1;
static int hf_lustre_out_update_header_magic = -1;
static int hf_lustre_out_update_header_count = -1;
static int hf_lustre_out_update_header_inline_length = -1;
static int hf_lustre_out_update_header_reply_size = -1;
static int hf_lustre_out_update_header_inline_data = -1;
static int hf_lustre_out_update_buffer = -1;
static int hf_lustre_out_update_buffer_size = -1;
static int hf_lustre_out_update_buffer_padding = -1;
static int hf_lustre_obj_update_reply = -1;
static int hf_lustre_obj_update_reply_magic = -1;
static int hf_lustre_obj_update_reply_count = -1;
static int hf_lustre_obj_update_reply_padding = -1;
static int hf_lustre_obj_update_reply_lens = -1;
static int hf_lustre_obj_update_request = -1;
static int hf_lustre_obj_update_request_magic = -1;
static int hf_lustre_obj_update_request_count = -1;
static int hf_lustre_obj_update_request_padding = -1;
static int hf_lustre_obj_update = -1;
static int hf_lustre_obj_update_type = -1;
static int hf_lustre_obj_update_params_count = -1;
static int hf_lustre_obj_update_result_size = -1;
static int hf_lustre_obj_update_flags = -1;
static int hf_lustre_obj_update_padding = -1;
static int hf_lustre_obj_update_batchid = -1;
static int hf_lustre_obj_update_fid = -1;
static int hf_lustre_obj_update_param = -1;
static int hf_lustre_obj_update_param_len = -1;
static int hf_lustre_obj_update_param_padding = -1;
static int hf_lustre_obj_update_param_buf = -1;
static int hf_lustre_lfsck_request = -1;
static int hf_lustre_lfsck_request_event = -1;
static int hf_lustre_lfsck_request_index = -1;
static int hf_lustre_lfsck_request_flags = -1;
static int hf_lustre_lfsck_request_valid = -1;
static int hf_lustre_lfsck_request_speed = -1;
static int hf_lustre_lfsck_request_status = -1;
static int hf_lustre_lfsck_request_version = -1;
static int hf_lustre_lfsck_request_active = -1;
static int hf_lustre_lfsck_request_param = -1;
static int hf_lustre_lfsck_request_async_windows = -1;
static int hf_lustre_lfsck_request_flags2 = -1;
static int hf_lustre_lfsck_request_fid = -1;
static int hf_lustre_lfsck_request_fid2 = -1;
static int hf_lustre_lfsck_request_comp_id = -1;
static int hf_lustre_lfsck_request_padding = -1;
static int hf_lustre_lfsck_reply = -1;
static int hf_lustre_lfsck_reply_status = -1;
static int hf_lustre_lfsck_reply_padding = -1;
static int hf_lustre_lfsck_reply_repaired = -1;

/* Ett declarations */
static gint ett_lustre = -1;
static gint ett_lustre_lustre_handle_cookie = -1;
static gint ett_lustre_lustre_msg_v1 = -1;
static gint ett_lustre_lustre_handle_v1 = -1;
static gint ett_lustre_lustre_msg_v2 = -1;
static gint ett_lustre_ptlrpc_body = -1;
static gint ett_lustre_lustre_handle_v2 = -1;
static gint ett_lustre_obd_connect_data = -1;
static gint ett_lustre_lov_ost_data_v1 = -1;
static gint ett_lustre_obd_statfs = -1;
static gint ett_lustre_obd_ioobj = -1;
static gint ett_lustre_niobuf_remote = -1;
static gint ett_lustre_rcs = -1;
static gint ett_lustre_fid_array = -1;
static gint ett_lustre_ost_lvb = -1;
static gint ett_lustre_lu_fid = -1;
static gint ett_lustre_mdc_swap_layouts = -1;
static gint ett_lustre_mdt_body = -1;
static gint ett_lustre_mdt_rec_reint = -1;
static gint ett_lustre_obd_quotactl = -1;
static gint ett_lustre_obd_dqinfo = -1;
static gint ett_lustre_obd_dqblk = -1;
static gint ett_lustre_quota_adjust_qunit = -1;
static gint ett_lustre_lov_desc = -1;
static gint ett_lustre_obd_uuid = -1;
static gint ett_lustre_ldlm_res_id = -1;
static gint ett_lustre_ldlm_extent = -1;
static gint ett_lustre_ldlm_inodebits = -1;
static gint ett_lustre_ldlm_flock = -1;
static gint ett_lustre_ldlm_intent_opc = -1;
static gint ett_lustre_ldlm_resource_desc = -1;
static gint ett_lustre_ldlm_lock_desc = -1;
static gint ett_lustre_ldlm_request = -1;
static gint ett_lustre_lustre_handle = -1;
static gint ett_lustre_ldlm_reply = -1;
static gint ett_lustre_ldlm_gl_barrier_desc = -1;
static gint ett_lustre_ldlm_gl_lquota_desc = -1;
static gint ett_lustre_mgs_target_info = -1;
static gint ett_lustre_mgs_config_body = -1;
static gint ett_lustre_mgs_config_res = -1;
static gint ett_lustre_llog_rec = -1;
static gint ett_lustre_llog_rec_hdr = -1;
static gint ett_lustre_llog_rec_tail = -1;
static gint ett_lustre_llog_logid_rec = -1;
static gint ett_lustre_llog_logid = -1;
static gint ett_lustre_lmv_mds_md = -1;
static gint ett_lustre_lov_mds_md = -1;
static gint ett_lustre_llog_unlink_rec = -1;
static gint ett_lustre_llog_unlink64_rec = -1;
static gint ett_lustre_llog_setattr_rec = -1;
static gint ett_lustre_llog_setattr64_rec = -1;
static gint ett_lustre_llog_size_change_rec = -1;
static gint ett_lustre_llog_gen_rec = -1;
static gint ett_lustre_llog_changelog_rec = -1;
static gint ett_lustre_llog_log_hdr = -1;
static gint ett_lustre_llog_hdr_flags = -1;
static gint ett_lustre_llog_cookie = -1;
static gint ett_lustre_llogd_body = -1;
static gint ett_lustre_llogd_conn_body = -1;
static gint ett_lustre_llog_gen = -1;
static gint ett_lustre_changelog_rec = -1;
static gint ett_lustre_lustre_cfg = -1;
static gint ett_lustre_cfg_marker = -1;
static gint ett_lustre_obdo = -1;
static gint ett_lustre_ost_body = -1;
static gint ett_lustre_ldlm_lock_flags = -1;
static gint ett_lustre_seq_range = -1;
static gint ett_lustre_mdt_ioepoch = -1;
static gint ett_lustre_capa = -1;
static gint ett_lustre_idx_info = -1;
static gint ett_lustre_close_data = -1;
static gint ett_lustre_acl = -1;
static gint ett_lustre_ladvise_hdr = -1;
static gint ett_lustre_ladvise = -1;
static gint ett_lustre_hsm_request = -1;
static gint ett_lustre_hsm_archive = -1;
static gint ett_lustre_hsm_current_action = -1;
static gint ett_lustre_hsm_user_item = -1;
static gint ett_lustre_hsm_extent = -1;
static gint ett_lustre_hsm_state_set = -1;
static gint ett_lustre_hsm_progress = -1;
static gint ett_lustre_hsm_user_state = -1;
static gint ett_lustre_quota_body = -1;
static gint ett_lustre_lquota_id = -1;
static gint ett_lustre_layout_intent = -1;
static gint ett_lustre_xattrs = -1;
static gint ett_lustre_xattr_item = -1;
static gint ett_lustre_ost_id = -1;
static gint ett_lustre_ost_id_oi = -1;
static gint ett_lustre_ost_layout = -1;
static gint ett_lustre_eadata = -1;
static gint ett_lustre_out_update_header = -1;
static gint ett_lustre_out_update_header_data = -1;
static gint ett_lustre_out_update_buffer = -1;
static gint ett_lustre_obj_update_reply = -1;
static gint ett_lustre_object_update_request = -1;
static gint ett_lustre_object_update = -1;
static gint ett_lustre_object_update_param = -1;
static gint ett_lustre_lfsck_request = -1;
static gint ett_lustre_lfsck_reply = -1;
static gint ett_lustre_barrier_lvb = -1;

static expert_field ei_lustre_buflen = EI_INIT;
static expert_field ei_lustre_badopc = EI_INIT;
static expert_field ei_lustre_badmagic = EI_INIT;
static expert_field ei_lustre_obsopc = EI_INIT;

/* --------------------------------------------------------------------------------------- */
/* def and macro to know where we are the the lustre payload */
#define LUSTRE_MAGIC_OFFSET 8

#define LUSTRE_BUFCOUNT_OFF ((tvb_get_letohl(tvb, LUSTRE_MAGIC_OFFSET)== MSG_MAGIC_V2) ? 0 : 60)
#define LUSTRE_BUFCOUNT ((tvb_get_letohl(tvb, LUSTRE_MAGIC_OFFSET)== MSG_MAGIC_V2) \
                         ? (tvb_get_letohl(tvb, LUSTRE_BUFCOUNT_OFF)) : ((tvb_get_letohl(tvb, LUSTRE_BUFCOUNT_OFF))) )
/* remark : BUFLENOFF don't have the same meaning if it's for v1 or v2
 * v1 : LUSTRE_BUFLEN_OFF = offset buflen[0] - 4 bytes.
 * v2 : LUSTRE_BUFLEN_OFF = offset buflen[0]
 */
#define LUSTRE_BUFLEN_OFF ((tvb_get_letohl(tvb, LUSTRE_MAGIC_OFFSET)== MSG_MAGIC_V2) ? 32 : 60)

/* LUSTRE_BUFFER_LEN(buffnum) */
#define LUSTRE_BUFFER_LEN(_n) (LUSTRE_BUFCOUNT <= (_n) ? 0              \
                               : tvb_get_letohl(tvb, LUSTRE_BUFLEN_OFF+ \
                                                4*(_n)))

#define LUSTRE_REC_OFF  1 /* normal request/reply record offset */

/* --------------------------------------------------------------------------------------- */

#define LUSTRE_PTLRPC_MSG_VERSION  0x00000003
#define LUSTRE_VERSION_MASK 0xffff0000
#if 0 /* @@ NOT USED */
#define LUSTRE_OBD_VERSION  0x00010000
#define LUSTRE_MDS_VERSION  0x00020000
#define LUSTRE_OST_VERSION  0x00030000
#define LUSTRE_DLM_VERSION  0x00040000
#define LUSTRE_LOG_VERSION  0x00050000
#define LUSTRE_MGS_VERSION  0x00060000
#endif
#define LMV_HASH_TYPE_MASK 0x0000ffff

#define lustre_magic_VALUE_STRING_LIST(XXX) \
    XXX(MSG_MAGIC_V1,           0x0BD00BD0) \
    XXX(MSG_MAGIC_V2,           0x0BD00BD3) \
    XXX(LOV_MAGIC_V1,           0x0BD10BD0) \
    XXX(LOV_MAGIC_V3,           0x0BD30BD0) \
    XXX(LMV_MAGIC_V1,           0x0CD20CD0) \
    XXX(LMV_MAGIC_STRIPE,       0x0CD40CD0) \
    XXX(LADVISE_MAGIC,          0x1ADF1CE0) \
    XXX(IDX_INFO_MAGIC,         0x3D37CC37)
VALUE_STRING_ENUM2(lustre_magic);
VALUE_STRING_ARRAY2(lustre_magic);

#define lov_pattern_vals_VALUE_STRING_LIST(XXX)  \
    XXX(LOV_PATTERN_NONE,       0x000,  "NONE")  \
    XXX(LOV_PATTERN_RAID0,      0x001,  "RAID0") \
    XXX(LOV_PATTERN_RAID1,      0x002,  "RAID1") \
    XXX(LOV_PATTERN_MDT,        0x100,  "MDT") \
    XXX(LOV_PATTERN_CMOBD,      0x200,  "CMOBD")
//VALUE_STRING_ENUM2(lov_pattern_vals);
VALUE_STRING_ARRAY(lov_pattern_vals);

#define lmv_hash_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(LMV_HASH_TYPE_ALL_CHARS, 1, "all_char")   \
    XXX(LMV_HASH_TYPE_FNV_1A_64, 2, "fnv_1a_64")
//VALUE_STRING_ENUM2(lmv_hash_type_vals);
VALUE_STRING_ARRAY(lmv_hash_type_vals);

#define capa_flags_vals_VALUE_STRING_LIST(XXX) \
    XXX(CAPA_OPC_BODY_WRITE, 1<<0)                      \
    XXX(CAPA_OPC_BODY_READ, 1<<1)                       \
    XXX(CAPA_OPC_INDEX_LOOKUP, 1<<2)                    \
    XXX(CAPA_OPC_INDEX_INSERT, 1<<3)                    \
    XXX(CAPA_OPC_INDEX_DELETE, 1<<4)                    \
    XXX(CAPA_OPC_OSS_WRITE, 1<<5)                       \
    XXX(CAPA_OPC_OSS_READ, 1<<6)                        \
    XXX(CAPA_OPC_OSS_TRUNC, 1<<7)                       \
    XXX(CAPA_OPC_OSS_DESTROY, 1<<8)                     \
    XXX(CAPA_OPC_META_WRITE, 1<<9)                      \
    XXX(CAPA_OPC_META_READ, 1<<10)
//VALUE_STRING_ENUM2(capa_flags_vals);
VALUE_STRING_ARRAY2(capa_flags_vals);

#define lustre_op_codes_VALUE_STRING_LIST(XXX) \
    XXX(OST_REPLY,  0)                         \
    XXX(OST_GETATTR,  1)                       \
    XXX(OST_SETATTR,  2)                       \
    XXX(OST_READ,  3)                          \
    XXX(OST_WRITE,  4)                         \
    XXX(OST_CREATE,  5)                        \
    XXX(OST_DESTROY,  6)                       \
    XXX(OST_GET_INFO,  7)                      \
    XXX(OST_CONNECT,  8)                       \
    XXX(OST_DISCONNECT,  9)                    \
    XXX(OST_PUNCH, 10)                         \
    XXX(OST_OPEN, 11)                          \
    XXX(OST_CLOSE, 12)                         \
    XXX(OST_STATFS, 13)                        \
    XXX(OST_SYNC, 16)                          \
    XXX(OST_SET_INFO, 17)                      \
    XXX(OST_QUOTACHECK, 18)                    \
    XXX(OST_QUOTACTL, 19)                      \
    XXX(OST_QUOTA_ADJUST_QUNIT, 20)            \
    XXX(OST_LADVISE, 21)                       \
    XXX(OST_LAST_OPC, 22)                      \
    XXX(MDS_GETATTR, 33)                       \
    XXX(MDS_GETATTR_NAME, 34)                  \
    XXX(MDS_CLOSE, 35)                         \
    XXX(MDS_REINT, 36)                         \
    XXX(MDS_READPAGE, 37)                      \
    XXX(MDS_CONNECT, 38)                       \
    XXX(MDS_DISCONNECT, 39)                    \
    XXX(MDS_GET_ROOT, 40)                      \
    XXX(MDS_STATFS, 41)                        \
    XXX(MDS_PIN, 42)                           \
    XXX(MDS_UNPIN, 43)                         \
    XXX(MDS_SYNC, 44)                          \
    XXX(MDS_DONE_WRITING, 45)                  \
    XXX(MDS_SET_INFO, 46)                      \
    XXX(MDS_QUOTACHECK, 47)                    \
    XXX(MDS_QUOTACTL, 48)                      \
    XXX(MDS_GETXATTR, 49)                      \
    XXX(MDS_SETXATTR, 50)                      \
    XXX(MDS_WRITEPAGE, 51)                     \
    XXX(MDS_IS_SUBDIR, 52)                     \
    XXX(MDS_GET_INFO, 53)                      \
    XXX(MDS_HSM_STATE_GET, 54)                 \
    XXX(MDS_HSM_STATE_SET, 55)                 \
    XXX(MDS_HSM_ACTION, 56)                    \
    XXX(MDS_HSM_PROGRESS, 57)                  \
    XXX(MDS_HSM_REQUEST, 58)                   \
    XXX(MDS_HSM_CT_REGISTER, 59)               \
    XXX(MDS_HSM_CT_UNREGISTER, 60)             \
    XXX(MDS_SWAP_LAYOUTS, 61)                  \
    XXX(MDS_RMFID, 62)                         \
    XXX(MDS_LAST_OPC, 63)                      \
    XXX(LDLM_ENQUEUE, 101)                     \
    XXX(LDLM_CONVERT, 102)                     \
    XXX(LDLM_CANCEL, 103)                      \
    XXX(LDLM_BL_CALLBACK, 104)                 \
    XXX(LDLM_CP_CALLBACK, 105)                 \
    XXX(LDLM_GL_CALLBACK, 106)                 \
    XXX(LDLM_SET_INFO, 107)                    \
    XXX(LDLM_LAST_OPC, 108)                    \
    XXX(MGS_CONNECT, 250)                      \
    XXX(MGS_DISCONNECT, 251)                   \
    XXX(MGS_EXCEPTION, 252)                    \
    XXX(MGS_TARGET_REG, 253)                   \
    XXX(MGS_TARGET_DEL, 254)                   \
    XXX(MGS_SET_INFO, 255)                     \
    XXX(MGS_CONFIG_READ, 256)                  \
    XXX(MGS_LAST_OPC, 257)                     \
    XXX(OBD_PING, 400)                         \
    XXX(OBD_LOG_CANCEL, 401)                   \
    XXX(OBD_QC_CALLBACK, 402)                  \
    XXX(OBD_IDX_READ, 403)                     \
    XXX(OBD_LAST_OPC, 404)                     \
    XXX(LLOG_ORIGIN_HANDLE_CREATE,      501)   \
    XXX(LLOG_ORIGIN_HANDLE_NEXT_BLOCK,  502)   \
    XXX(LLOG_ORIGIN_HANDLE_READ_HEADER, 503)   \
    XXX(LLOG_ORIGIN_HANDLE_WRITE_REC,   504)   \
    XXX(LLOG_ORIGIN_HANDLE_CLOSE,       505)   \
    XXX(LLOG_ORIGIN_CONNECT,            506)   \
    XXX(LLOG_CATINFO,                   507)   \
    XXX(LLOG_ORIGIN_HANDLE_PREV_BLOCK,  508)   \
    XXX(LLOG_ORIGIN_HANDLE_DESTROY,     509)   \
    XXX(LLOG_LAST_OPC,                  510)   \
    XXX(QUOTA_DQACQ,                    601)   \
    XXX(QUOTA_DQREL,                    602)   \
    XXX(QUOTA_LAST_OPC,                 603)   \
    XXX(SEQ_QUERY,                      700)   \
    XXX(SEQ_LAST_OPC,                   701)   \
    XXX(SEC_CTX_INIT,                   801)   \
    XXX(SEC_CTX_INIT_CONT,              802)   \
    XXX(SEC_CTX_FINI,                   803)   \
    XXX(SEC_LAST_OPC,                   804)   \
    XXX(FLD_QUERY,                      900)   \
    XXX(FLD_READ,                       901)   \
    XXX(FLD_LAST_OPC,                   902)   \
    XXX(OUT_UPDATE,                     1000)  \
    XXX(OUT_UPDATE_LAST_OPC,            1001)  \
    XXX(LFSCK_NOTIFY,                   1101)  \
    XXX(LFSCK_QUERY,                    1102)  \
    XXX(LFSCK_LAST_OPC,                 1103)

VALUE_STRING_ENUM2(lustre_op_codes);
VALUE_STRING_ARRAY2(lustre_op_codes);

#define OST_FIRST_OPC   OST_REPLY
#define QUOTA_FIRST_OPC QUOTA_DQACQ
#define MDS_FIRST_OPC   MDS_GETATTR
#define OUT_UPDATE_FIRST_OPC OUT_UPDATE
#define FLD_FIRST_OPC   FLD_QUERY
#define SEQ_FIRST_OPC   SEQ_QUERY
#define LFSCK_FIRST_OPC LFSCK_NOTIFY
#define LDLM_FIRST_OPC  LDLM_ENQUEUE
#define MGS_FIRST_OPC   MGS_CONNECT
#define OBD_FIRST_OPC   OBD_PING
#define LLOG_FIRST_OPC  LLOG_ORIGIN_HANDLE_CREATE
#define SEC_FIRST_OPC   SEC_CTX_INIT


#define lustre_LMTypes_VALUE_STRING_LIST(XXX) \
    XXX(PTL_RPC_MSG_REQUEST, 4711, "request") \
    XXX(PTL_RPC_MSG_ERR,     4712, "error")   \
    XXX(PTL_RPC_MSG_REPLY,   4713, "reply")

VALUE_STRING_ENUM(lustre_LMTypes);
VALUE_STRING_ARRAY(lustre_LMTypes);

static const true_false_string lnet_flags_set_truth = { "Set", "Unset" };

#define lustre_layout_intent_opc_vals_VALUE_STRING_LIST(XXX)    \
    XXX(LAYOUT_INTENT_ACCESS,     0, "ACCESS")                  \
    XXX(LAYOUT_INTENT_READ,       1, "READ")                    \
    XXX(LAYOUT_INTENT_WRITE,      2, "WRITE")                   \
    XXX(LAYOUT_INTENT_GLIMPSE,    3, "GLIMPSE")                 \
    XXX(LAYOUT_INTENT_TRUNC,      4, "TRUNCATE")                \
    XXX(LAYOUT_INTENT_RELEASE,    5, "RELEASE")                 \
    XXX(LAYOUT_INTENT_RESTORE,    6, "RESTORE")
//VALUE_STRING_ENUM(lustre_layout_intent_opc_vals);
VALUE_STRING_ARRAY(lustre_layout_intent_opc_vals);

#define obd_statfs_state_VALUE_STRING_LIST(XXX)                 \
    XXX(OS_STATE_DEGRADED,       0x00000001, "Degraded")        \
    XXX(OS_STATE_READONLY,       0x00000002, "ReadOnly")        \
    XXX(OS_STATE_ENOSPC,         0x00000020, "No Space")        \
    XXX(OS_STATE_ENOINO,         0x00000040, "No Indoes")
//VALUE_STRING_ENUM(obd_statfs_state);
VALUE_STRING_ARRAY(obd_statfs_state);
/********************************************************************
 *
 * OST Definitions
 *
 */

#define lu_ladvise_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(LU_LADVISE_WILLREAD,     1, "willread")     \
    XXX(LU_LADVISE_DONTNEED,     2, "dontneed")
//VALUE_STRING_ENUM2(lu_ladvise_type_vals);
VALUE_STRING_ARRAY(lu_ladvise_type_vals);


/********************************************************************
 *
 * MDS Definitions
 *
 */

#define mds_reint_vals_VALUE_STRING_LIST(XXX)    \
    XXX(REINT_SETATTR,   1, "SETATTR")                  \
    XXX(REINT_CREATE,    2, "CREATE")                   \
    XXX(REINT_LINK,      3, "LINK")                     \
    XXX(REINT_UNLINK,    4, "UNLINK")                   \
    XXX(REINT_RENAME,    5, "RENAME")                   \
    XXX(REINT_OPEN,      6, "OPEN")                     \
    XXX(REINT_SETXATTR,  7, "SETXATTR")                 \
    XXX(REINT_RMENTRY,   8, "RMENTRY")                  \
    XXX(REINT_MIGRATE,   9, "MIGRATE")
VALUE_STRING_ENUM(mds_reint_vals);
VALUE_STRING_ARRAY(mds_reint_vals);

#define lustre_mds_flags_vals_VALUE_STRING_LIST(XXX) \
    XXX(LUSTRE_SYNC_FL,          0x00000008)         \
    XXX(LUSTRE_IMMUTABLE_FL,     0x00000010)         \
    XXX(LUSTRE_APPEND_FL,        0x00000020)         \
    XXX(LUSTRE_NODUMP_FL,        0x00000040)         \
    XXX(LUSTRE_NOATIME_FL,       0x00000080)         \
    XXX(LUSTRE_INDEX_FL,         0x00001000)         \
    XXX(LUSTRE_DIRSYNC_FL,       0x00010000)         \
    XXX(LUSTRE_TOPDIR_FL,        0x00020000)         \
    XXX(LUSTRE_DIRECTIO_FL,      0x00100000)         \
    XXX(LUSTRE_INLINE_DATA_FL,   0x10000000)         \
    XXX(LUSTRE_PROJINHERIT_FL,   0x20000000)         \
    XXX(LUSTRE_ORPHAN_FL,        0x00002000)
//VALUE_STRING_ENUM2(lustre_mds_flags_vals);
VALUE_STRING_ARRAY2(lustre_mds_flags_vals);

/********************************************************************
 *
 * MGS Definitions
 *
 */

#define mgs_config_body_type_vals_VALUE_STRING_LIST(XXX)    \
    XXX(CONFIG_T_CONFIG,         0, "CONFIG")               \
    XXX(CONFIG_T_SPTLRPC,        1, "SPTLRPC")              \
    XXX(CONFIG_T_RECOVER,        2, "RECOVER")              \
    XXX(CONFIG_T_PARAMS,         3, "PARAMS")               \
    XXX(CONFIG_T_NODEMAP,        4, "NODEMAP")              \
    XXX(CONFIG_T_BARRIER,        5, "BARRIER")
VALUE_STRING_ENUM(mgs_config_body_type_vals);
VALUE_STRING_ARRAY(mgs_config_body_type_vals);


/********************************************************************
 *
 * LDLM Definitions
 *
 */

#define lustre_ldlm_mode_vals_VALUE_STRING_LIST(XXX) \
    XXX(LCK_MINMODE, 0,   "MINMODE")                 \
    XXX(LCK_EX,      1,   "Exclusive")               \
    XXX(LCK_PW,      2,   "Protected Write")         \
    XXX(LCK_PR,      4,   "Protected Read")          \
    XXX(LCK_CW,      8,   "Concurrent Write")        \
    XXX(LCK_CR,      16,  "Concurrent Read")         \
    XXX(LCK_NL,      32,  "Null")                    \
    XXX(LCK_GROUP,   64,  "Group")                   \
    XXX(LCK_COS,     128, "Commit on Sharing")

VALUE_STRING_ENUM(lustre_ldlm_mode_vals);
VALUE_STRING_ARRAY(lustre_ldlm_mode_vals);

#define lustre_ldlm_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(LDLM_PLAIN,  10)                         \
    XXX(LDLM_EXTENT, 11)                         \
    XXX(LDLM_FLOCK,  12)                         \
    XXX(LDLM_IBITS,  13)
VALUE_STRING_ENUM2(lustre_ldlm_type_vals);
VALUE_STRING_ARRAY2(lustre_ldlm_type_vals);

#define lustre_ldlm_intent_flags_VALUE_STRING_LIST(XXX) \
    XXX(IT_OPEN,        0x00000001)                     \
    XXX(IT_CREAT,       0x00000002)                     \
    XXX(IT_OPEN_CREAT,  0x00000003)                     \
    XXX(IT_READDIR,     0x00000004)                     \
    XXX(IT_GETATTR,     0x00000008)                     \
    XXX(IT_LOOKUP,      0x00000010)                     \
    XXX(IT_UNLINK,      0x00000020)                     \
    XXX(IT_TRUNC,       0x00000040)                     \
    XXX(IT_GETXATTR,    0x00000080)                     \
    XXX(IT_EXEC,        0x00000100)                     \
    XXX(IT_PIN,         0x00000200)                     \
    XXX(IT_LAYOUT,      0x00000400)                     \
    XXX(IT_QUOTA_DQACQ, 0x00000800)                     \
    XXX(IT_QUOTA_CONN,  0x00001000)                     \
    XXX(IT_SETXATTR,    0x00002000)
VALUE_STRING_ENUM2(lustre_ldlm_intent_flags);
//VALUE_STRING_ARRAY2(lustre_ldlm_intent_flags);

#define lustre_barrier_status_vals_VALUE_STRING_LIST(XXX) \
    XXX(BS_INIT,        0)                                \
    XXX(BS_FREEZING_P1, 1)                                \
    XXX(BS_FREEZING_P2, 2)                                \
    XXX(BS_FROZEN,      3)                                \
    XXX(BS_THAWING,     4)                                \
    XXX(BS_THAWED,      5)                                \
    XXX(BS_FAILED,      6)                                \
    XXX(BS_EXPIRED,     7)                                \
    XXX(BS_RESCAN,      8)
VALUE_STRING_ENUM2(lustre_barrier_status_vals);
VALUE_STRING_ARRAY2(lustre_barrier_status_vals);

#define LDLM_FL_LOCK_CHANGED            0x0000000000000001ULL
#define LDLM_FL_BLOCK_GRANTED           0x0000000000000002ULL
#define LDLM_FL_BLOCK_CONV              0x0000000000000004ULL
#define LDLM_FL_BLOCK_WAIT              0x0000000000000008ULL
#define LDLM_FL_AST_SENT                0x0000000000000020ULL
#define LDLM_FL_REPLAY                  0x0000000000000100ULL
#define LDLM_FL_INTENT_ONLY             0x0000000000000200ULL
#define LDLM_FL_HAS_INTENT              0x0000000000001000ULL
#define LDLM_FL_FLOCK_DEADLOCK          0x0000000000008000ULL
#define LDLM_FL_DISCARD_DATA            0x0000000000010000ULL
#define LDLM_FL_NO_TIMEOUT              0x0000000000020000ULL
#define LDLM_FL_BLOCK_NOWAIT            0x0000000000040000ULL
#define LDLM_FL_TEST_LOCK               0x0000000000080000ULL
#define LDLM_FL_MATCH_LOCK              0x0000000000100000ULL
#define LDLM_FL_CANCEL_ON_BLOCK         0x0000000000800000ULL
#define LDLM_FL_COS_INCOMPAT		0x0000000001000000ULL
#define LDLM_FL_DENY_ON_CONTENTION      0x0000000040000000ULL
#define LDLM_FL_AST_DISCARD_DATA        0x0000000080000000ULL
/* ---- 32 Bits ---- */
#define LDLM_FL_FAIL_LOC                0x0000000100000000ULL
#define LDLM_FL_SKIPPED                 0x0000000200000000ULL
#define LDLM_FL_CBPENDING               0x0000000400000000ULL
#define LDLM_FL_WAIT_NOREPROC           0x0000000800000000ULL
#define LDLM_FL_CANCEL                  0x0000001000000000ULL
#define LDLM_FL_LOCAL_ONLY              0x0000002000000000ULL
#define LDLM_FL_FAILED                  0x0000004000000000ULL
#define LDLM_FL_CANCELING               0x0000008000000000ULL
#define LDLM_FL_LOCAL                   0x0000010000000000ULL
#define LDLM_FL_LVB_READY               0x0000020000000000ULL
#define LDLM_FL_KMS_IGNORE              0x0000040000000000ULL
#define LDLM_FL_CP_REQD                 0x0000080000000000ULL
#define LDLM_FL_CLEANED                 0x0000100000000000ULL
#define LDLM_FL_ATOMIC_CB               0x0000200000000000ULL
#define LDLM_FL_BL_AST                  0x0000400000000000ULL
#define LDLM_FL_BL_DONE                 0x0000800000000000ULL
#define LDLM_FL_NO_LRU                  0x0001000000000000ULL
#define LDLM_FL_FAIL_NOTIFIED           0x0002000000000000ULL
#define LDLM_FL_DESTROYED               0x0004000000000000ULL
#define LDLM_FL_SERVER_LOCK             0x0008000000000000ULL
#define LDLM_FL_RES_LOCKED              0x0010000000000000ULL
#define LDLM_FL_WAITED                  0x0020000000000000ULL
#define LDLM_FL_NS_SRV                  0x0040000000000000ULL
#define LDLM_FL_EXCL                    0x0080000000000000ULL
#define LDLM_FL_RESENT                  0x0100000000000000ULL
#define LDLM_FL_COS_ENABLED             0x0200000000000000ULL

#if 0
static const value_string lustre_ldlm_flags_vals[] = {
  {LDLM_FL_LOCK_CHANGED,        "LDLM_FL_LOCK_CHANGED"},
  {LDLM_FL_BLOCK_GRANTED,       "LDLM_FL_BLOCK_GRANTED"},
  {LDLM_FL_BLOCK_CONV,          "LDLM_FL_BLOCK_CONV"},
  {LDLM_FL_BLOCK_WAIT,          "LDLM_FL_BLOCK_WAIT"},
  {LDLM_FL_AST_SENT,            "LDLM_FL_AST_SENT"},
  {LDLM_FL_REPLAY,              "LDLM_FL_REPLAY"},
  {LDLM_FL_INTENT_ONLY,         "LDLM_FL_INTENT_ONLY"},
  {LDLM_FL_HAS_INTENT,          "LDLM_FL_HAS_INTENT"},
  {LDLM_FL_FLOCK_DEADLOCK,      "LDLM_FL_FLOCK_DEADLOCK"},
  {LDLM_FL_DISCARD_DATA,        "LDLM_FL_DISCARD_DATA"},
  {LDLM_FL_NO_TIMEOUT,          "LDLM_FL_NO_TIMEOUT"},
  {LDLM_FL_BLOCK_NOWAIT,        "LDLM_FL_BLOCK_NOWAIT"},
  {LDLM_FL_TEST_LOCK,           "LDLM_FL_TEST_LOCK"},
  {LDLM_FL_CANCEL_ON_BLOCK,     "LDLM_FL_CANCEL_ON_BLOCK"},
  {LDLM_FL_COS_INCOMPAT,        "LDLM_FL_COS_INCOMPAT"},
  {LDLM_FL_DENY_ON_CONTENTION,  "LDLM_FL_DENY_ON_CONTENTION"},
  {LDLM_FL_AST_DISCARD_DATA,    "LDLM_FL_AST_DISCARD_DATA"},
  { 0, NULL }
};
#endif

/********************************************************************
 *
 * LLOG Definitions
 *
 */

#define LLOG_OP_MAGIC 0x10600000
//#define LLOG_OP_MASK  0xfff00000
#define llog_op_types_VALUE_STRING_LIST(XXX)                            \
    XXX(LLOG_PAD_MAGIC,          LLOG_OP_MAGIC | 0x00000)               \
    XXX(OST_SZ_REC,              LLOG_OP_MAGIC | 0x00f00)               \
    XXX(OST_RAID1_REC,           LLOG_OP_MAGIC | 0x01000)               \
    XXX(MDS_UNLINK_REC,          LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_UNLINK) \
    XXX(MDS_UNLINK64_REC,        LLOG_OP_MAGIC | 0x90000 | (MDS_REINT << 8) | REINT_UNLINK) \
    XXX(MDS_SETATTR_REC,         LLOG_OP_MAGIC | 0x10000 | (MDS_REINT << 8) | REINT_SETATTR) \
    XXX(MDS_SETATTR64_REC,       LLOG_OP_MAGIC | 0x90000 | (MDS_REINT << 8) | REINT_SETATTR) \
    XXX(OBD_CFG_REC,             LLOG_OP_MAGIC | 0x20000)               \
    XXX(PTL_CFG_REC,             LLOG_OP_MAGIC | 0x30000)               \
    XXX(LLOG_GEN_REC,            LLOG_OP_MAGIC | 0x40000)               \
    XXX(LLOG_JOIN_REC,           LLOG_OP_MAGIC | 0x50000)               \
    XXX(CHANGELOG_REC,           LLOG_OP_MAGIC | 0x60000)               \
    XXX(CHANGELOG_USER_REC,      LLOG_OP_MAGIC | 0x70000)               \
    XXX(HSM_AGENT_REC,           LLOG_OP_MAGIC | 0x80000)               \
    XXX(UPDATE_REC,              LLOG_OP_MAGIC | 0xa0000)               \
    XXX(LLOG_HDR_MAGIC,          LLOG_OP_MAGIC | 0x45539)               \
    XXX(LLOG_LOGID_MAGIC,        LLOG_OP_MAGIC | 0x4553b)
VALUE_STRING_ENUM2(llog_op_types);
VALUE_STRING_ARRAY2(llog_op_types);

#define llog_hdr_llh_flags_VALUE_STRING_LIST(XXX)                \
    XXX(LLOG_F_ZAP_WHEN_EMPTY,  0x01, "LLOhdr_llh_G_F_ZAP_WHEN_EMPTY")  \
    XXX(LLOG_F_IS_CAT,          0x02, "LLOhdr_llh_G_F_IS_CAT")          \
    XXX(LLOG_F_IS_PLAIN,        0x04, "LLOG_F_IS_PLAIN")                \
    XXX(LLOG_F_EXT_JOBID,       0x08, "LLOG_F_EXT_JOBID")               \
    XXX(LLOG_F_IS_FIXSIZE,      0x10, "LLOG_F_IS_FIXSIZE")
VALUE_STRING_ENUM(llog_hdr_llh_flags);
//VALUE_STRING_ARRAY(llog_hdr_llh_flags);

#define llog_ctxt_id_vals_VALUE_STRING_LIST(XXX) \
    XXX(LLOG_CONFIG_ORIG_CTXT,   0) \
    XXX(LLOG_CONFIG_REPL_CTXT,   1) \
    XXX(LLOG_MDS_OST_ORIG_CTXT,  2) \
    XXX(LLOG_MDS_OST_REPL_CTXT,  3) \
    XXX(LLOG_SIZE_ORIG_CTXT,     4) \
    XXX(LLOG_SIZE_REPL_CTXT,     5) \
    XXX(LLOG_TEST_ORIG_CTXT,     8) \
    XXX(LLOG_TEST_REPL_CTXT,     9) \
    XXX(LLOG_CHANGELOG_ORIG_CTXT, 12) \
    XXX(LLOG_CHANGELOG_REPL_CTXT, 13) \
    XXX(LLOG_CHANGELOG_USER_ORIG_CTXT, 14) \
    XXX(LLOG_AGENT_ORIG_CTXT,    15) \
    XXX(LLOG_UPDATELOG_ORIG_CTXT, 16) \
    XXX(LLOG_UPDATELOG_REPL_CTXT, 17)
//VALUE_STRING_ENUM2(llog_ctxt_id_vals);
VALUE_STRING_ARRAY2(llog_ctxt_id_vals);

#define changelog_rec_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(CL_MARK,                 0) \
    XXX(CL_CREATE,               1) \
    XXX(CL_MKDIR,                2) \
    XXX(CL_HARDLINK,             3) \
    XXX(CL_SOFTLINK,             4) \
    XXX(CL_MKNOD,                5) \
    XXX(CL_UNLINK,               6) \
    XXX(CL_RMDIR,                7) \
    XXX(CL_RENAME,               8) \
    XXX(CL_EXT,                  9) \
    XXX(CL_OPEN,                 10) \
    XXX(CL_CLOSE,                11) \
    XXX(CL_LAYOUT,               12) \
    XXX(CL_TRUNC,                13) \
    XXX(CL_SETATTR,              14) \
    XXX(CL_XATTR,                15) \
    XXX(CL_HSM,                  16) \
    XXX(CL_MTIME,                17) \
    XXX(CL_CTIME,                18) \
    XXX(CL_ATIME,                19) \
    XXX(CL_MIGRATE,              20) \
    XXX(CL_FLRW,                 21) \
    XXX(CL_RESYNC,               22)
VALUE_STRING_ENUM2(changelog_rec_type_vals);
VALUE_STRING_ARRAY2(changelog_rec_type_vals);

#define changelog_rec_flags_vals_VALUE_STRING_LIST(XXX) \
    XXX(CLF_VERSION,             0x1000) \
    XXX(CLF_RENAME,              0x2000) \
    XXX(CLF_JOBID,               0x4000) \
    XXX(CLF_EXTRA_FLAGS,         0x8000)
VALUE_STRING_ENUM2(changelog_rec_flags_vals);
//VALUE_STRING_ARRAY2(changelog_rec_flags_vals);

#define lcfg_command_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(LCFG_ATTACH,             0x00cf001) \
    XXX(LCFG_DETACH,             0x00cf002) \
    XXX(LCFG_SETUP,              0x00cf003) \
    XXX(LCFG_CLEANUP,            0x00cf004) \
    XXX(LCFG_ADD_UUID,           0x00cf005) \
    XXX(LCFG_DEL_UUID,           0x00cf006) \
    XXX(LCFG_MOUNTOPT,           0x00cf007) \
    XXX(LCFG_DEL_MOUNTOPT,       0x00cf008) \
    XXX(LCFG_SET_TIMEOUT,        0x00cf009) \
    XXX(LCFG_SET_UPCALL,         0x00cf00a) \
    XXX(LCFG_ADD_CONN,           0x00cf00b) \
    XXX(LCFG_DEL_CONN,           0x00cf00c) \
    XXX(LCFG_LOV_ADD_OBD,        0x00cf00d) \
    XXX(LCFG_LOV_DEL_OBD,        0x00cf00e) \
    XXX(LCFG_PARAM,              0x00cf00f) \
    XXX(LCFG_MARKER,             0x00cf010) \
    XXX(LCFG_LOG_START,          0x00ce011) \
    XXX(LCFG_LOG_END,            0x00ce012) \
    XXX(LCFG_LOV_ADD_INA,        0x00ce013) \
    XXX(LCFG_ADD_MDC,            0x00cf014) \
    XXX(LCFG_DEL_MDC,            0x00cf015) \
    XXX(LCFG_SPTLRPC_CONF,       0x00ce016) \
    XXX(LCFG_POOL_NEW,           0x00ce020) \
    XXX(LCFG_POOL_ADD,           0x00ce021) \
    XXX(LCFG_POOL_REM,           0x00ce022) \
    XXX(LCFG_POOL_DEL,           0x00ce023) \
    XXX(LCFG_SET_LDLM_TIMEOUT,   0x00ce030) \
    XXX(LCFG_PRE_CLEANUP,        0x00cf031) \
    XXX(LCFG_SET_PARAM,          0x00ce032) \
    XXX(LCFG_NODEMAP_ADD,        0x00ce040) \
    XXX(LCFG_NODEMAP_DEL,        0x00ce041) \
    XXX(LCFG_NODEMAP_ADD_RANGE,  0x00ce042) \
    XXX(LCFG_NODEMAP_DEL_RANGE,  0x00ce043) \
    XXX(LCFG_NODEMAP_ADD_UIDMAP, 0x00ce044) \
    XXX(LCFG_NODEMAP_DEL_UIDMAP, 0x00ce045) \
    XXX(LCFG_NODEMAP_ADD_GIDMAP, 0x00ce046) \
    XXX(LCFG_NODEMAP_DEL_GIDMAP, 0x00ce047) \
    XXX(LCFG_NODEMAP_ACTIVATE,   0x00ce048) \
    XXX(LCFG_NODEMAP_ADMIN,      0x00ce049) \
    XXX(LCFG_NODEMAP_TRUSTED,    0x00ce050) \
    XXX(LCFG_NODEMAP_SQUASH_UID, 0x00ce051) \
    XXX(LCFG_NODEMAP_SQUASH_GID, 0x00ce052) \
    XXX(LCFG_NODEMAP_ADD_SHKEY,  0x00ce053) \
    XXX(LCFG_NODEMAP_DEL_SHKEY,  0x00ce054) \
    XXX(LCFG_NODEMAP_TEST_NID,   0x00ce055) \
    XXX(LCFG_NODEMAP_TEST_ID,    0x00ce056) \
    XXX(LCFG_NODEMAP_SET_FILESET, 0x00ce057) \
    XXX(LCFG_NODEMAP_DENY_UNKNOWN, 0x00ce058) \
    XXX(LCFG_NODEMAP_MAP_MODE,   0x00ce059)
VALUE_STRING_ENUM2(lcfg_command_type_vals);
VALUE_STRING_ARRAY2(lcfg_command_type_vals);

/********************************************************************
 *
 * HSM Definitions
 *
 */

#define hsm_state_vals_VALUE_STRING_LIST(XXX)   \
    XXX(HS_NONE,                 0x00000000)    \
    XXX(HS_EXISTS,               0x00000001)    \
    XXX(HS_DIRTY,                0x00000002)    \
    XXX(HS_RELEASED,             0x00000004)    \
    XXX(HS_ARCHIVED,             0x00000008)    \
    XXX(HS_NORELEASE,            0x00000010)    \
    XXX(HS_NOARCHIVE,            0x00000020)    \
    XXX(HS_LOST,                 0x00000040)
VALUE_STRING_ARRAY2(hsm_state_vals);

#define hsm_user_action_vals_VALUE_STRING_LIST(XXX)    \
    XXX(HUA_NONE,      1, "NONE")                             \
    XXX(HUA_ARCHIVE,  10, "ARCHIVE")                          \
    XXX(HUA_RESTORE,  11, "RESTORE")                          \
    XXX(HUA_RELEASE,  12, "RELEASE")                          \
    XXX(HUA_REMOVE,   13, "REMOVE")                           \
    XXX(HUA_CANCEL,   14, "CANCEL")
//VALUE_STRING_ENUM(hsm_user_action_vals);
VALUE_STRING_ARRAY(hsm_user_action_vals);

#define hsm_progress_state_vals_VALUE_STRING_LIST(XXX) \
    XXX(HPS_WAITING,  1, "Waiting")                           \
    XXX(HPS_RUNNING,  2, "Running")                           \
    XXX(HPS_DONE,     3, "Done")
//VALUE_STRING_ENUM(hsm_progress_state_vals);
VALUE_STRING_ARRAY(hsm_progress_state_vals);

#define hss_valid_VALUE_STRING_LIST(XXX)        \
    XXX(HSS_SETMASK, 0x01)                      \
        XXX(HSS_CLEARMASK, 0x02)                \
    XXX(HSS_ARCHIVE_ID, 0x04)
VALUE_STRING_ARRAY2(hss_valid);

/********************************************************************
 *
 * Quota Definitions
 *
 */

#define quota_cmd_vals_VALUE_STRING_LIST(XXX)   \
    XXX(Q_SYNC,     0x800001)                   \
    XXX(Q_QUOTAON,  0x800002)                   \
    XXX(Q_QUOTAOFF, 0x800003)                   \
    XXX(Q_GETFMT,   0x800004)                   \
    XXX(Q_GETINFO,  0x800005)                   \
    XXX(Q_SETINFO,  0x800006)                   \
    XXX(Q_GETQUOTA, 0x800007)                   \
    XXX(Q_SETQUOTA, 0x800008)                   \
    XXX(Q_GETNEXTQUOTA, 0x800009)               \
    XXX(LUSTRE_Q_INVALIDATE, 0x80000b)          \
    XXX(LUSTRE_Q_FINVALIDATE, 0x80000c)         \
    XXX(Q_QUOTACHECK,   0x800100)               \
    XXX(Q_INITQUOTA,    0x800101)               \
    XXX(Q_GETOINFO,    0x800102)               \
    XXX(Q_GETOQUOTA,    0x800103)               \
    XXX(Q_FINVALIDATE,    0x800104)
VALUE_STRING_ARRAY2(quota_cmd_vals);

#define quota_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(USRQUOTA, 0)                           \
    XXX(GRPQUOTA, 1)                           \
    XXX(PRJQUOTA, 2)
VALUE_STRING_ARRAY2(quota_type_vals);

/********************************************************************
 *
 * SEQ Definitions
 *
 */

#define seq_op_vals_VALUE_STRING_LIST(XXX) \
    XXX(SEQ_ALLOC_SUPER,         0)        \
    XXX(SEQ_ALLOC_META,          1)
//VALUE_STRING_ENUM2(seq_op_vals);
VALUE_STRING_ARRAY2(seq_op_vals);

#define seq_range_flag_vals_VALUE_STRING_LIST(XXX) \
    XXX(LU_SEQ_RANGE_MDT,         0x0, "MDT")      \
    XXX(LU_SEQ_RANGE_OST,         0x1, "OST")      \
    XXX(LU_SEQ_RANGE_ANY,         0x3, "ANY")
//VALUE_STRING_ENUM(seq_range_flag_vals);
VALUE_STRING_ARRAY(seq_range_flag_vals);

/********************************************************************
 *
 * FLD Definitions
 *
 */

#define fld_op_vals_VALUE_STRING_LIST(XXX) \
    XXX(FLD_CREATE,     0, "Create")       \
    XXX(FLD_DELETE,     1, "Delete")       \
    XXX(FLD_LOOKUP,     2, "Lookup")
//VALUE_STRING_ENUM(fld_op_vals);
VALUE_STRING_ARRAY(fld_op_vals);

/********************************************************************
 *
 * Out Update Definitions
 *
 */
// These can't be in enum because they are bigger than MAXINT
#define OUT_UPDATE_HEADER_MAGIC    0xBDDF0001
#define UPDATE_REQUEST_MAGIC_V1 0xBDDE0001
#define UPDATE_REQUEST_MAGIC_V2 0xBDDE0002

static const value_string update_request_magic_vals[] = {
    {UPDATE_REQUEST_MAGIC_V1, "UPDATE_REQUEST_MAGIC_V1"},
    {UPDATE_REQUEST_MAGIC_V2, "UPDATE_REQUEST_MAGIC_V2"},
    {0, NULL}
};

#define update_reply_magic_vals_VALUE_STRING_LIST(XXX) \
    XXX(UPDATE_REPLY_MAGIC_V1,  0x00BD0001)            \
    XXX(UPDATE_REPLY_MAGIC_V2,  0x00BD0002)
VALUE_STRING_ENUM2(update_reply_magic_vals);
VALUE_STRING_ARRAY2(update_reply_magic_vals);

#define update_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(OUT_START,               0) \
    XXX(OUT_CREATE,              1) \
    XXX(OUT_DESTROY,             2) \
    XXX(OUT_REF_ADD,             3) \
    XXX(OUT_REF_DEL,             4) \
    XXX(OUT_ATTR_SET,            5) \
    XXX(OUT_ATTR_GET,            6) \
    XXX(OUT_XATTR_SET,           7) \
    XXX(OUT_XATTR_GET,           8) \
    XXX(OUT_INDEX_LOOKUP,        9) \
    XXX(OUT_INDEX_INSERT,        10) \
    XXX(OUT_INDEX_DELETE,        11) \
    XXX(OUT_WRITE,               12) \
    XXX(OUT_XATTR_DEL,           13) \
    XXX(OUT_PUNCH,               14) \
    XXX(OUT_READ,                15) \
    XXX(OUT_NOOP,                16)
VALUE_STRING_ENUM2(update_type_vals);
VALUE_STRING_ARRAY2(update_type_vals);

/********************************************************************
 * LFSCK Definitions
 */

#define lfsck_events_vals_VALUE_STRING_LIST(XXX) \
    XXX(LE_LASTID_REBUILDING,    1) \
    XXX(LE_LASTID_REBUILT,       2) \
    XXX(LE_PHASE1_DONE,          3) \
    XXX(LE_PHASE2_DONE,          4) \
    XXX(LE_START,                5) \
    XXX(LE_STOP,                 6) \
    XXX(LE_QUERY,                7) \
    XXX(LE_FID_ACCESSED,         8) \
    XXX(LE_PEER_EXIT,            9) \
    XXX(LE_CONDITIONAL_DESTROY,  10) \
    XXX(LE_PAIRS_VERIFY,         11) \
    XXX(LE_SET_LMV_MASTER,       15) \
    XXX(LE_SET_LMV_SLAVE,        16)
//VALUE_STRING_ENUM2(lfsck_events_vals);
VALUE_STRING_ARRAY2(lfsck_events_vals);

#define lfsck_start_valid_vals_VALUE_STRING_LIST(XXX) \
    XXX(LSV_SPEED_LIMIT,         0x00000001)          \
    XXX(LSV_ERROR_HANDLE,        0x00000002)          \
    XXX(LSV_DRYRUN,              0x00000004)          \
    XXX(LSV_ASYNC_WINDOWS,       0x00000008)          \
    XXX(LSV_CREATE_OSTOBJ,       0x00000010)          \
    XXX(LSV_CREATE_MDTOBJ,       0x00000020)          \
    XXX(LSV_DELAY_CREATE_OSTOBJ, 0x00000040)
VALUE_STRING_ENUM2(lfsck_start_valid_vals);
//VALUE_STRING_ARRAY2(lfsck_start_valid_vals);

#define lfsck_status_vals_VALUE_STRING_LIST(XXX) \
    XXX(LS_INIT,                 0)              \
    XXX(LS_SCANNING_PHASE1,      1)              \
    XXX(LS_SCANNING_PHASE2,      2)              \
    XXX(LS_COMPLETED,            3)              \
    XXX(LS_FAILED,               4)              \
    XXX(LS_STOPPED,              5)              \
    XXX(LS_PAUSED,               6)              \
    XXX(LS_CRASHED,              7)              \
    XXX(LS_PARTIAL,              8)              \
    XXX(LS_CO_FAILED,            9)              \
    XXX(LS_CO_STOPPED,           10)             \
    XXX(LS_CO_PAUSED,            11)
//VALUE_STRING_ENUM2(lfsck_status_vals);
VALUE_STRING_ARRAY2(lfsck_status_vals);

#define lfsck_type_vals_VALUE_STRING_LIST(XXX) \
    XXX(LFSCK_TYPE_SCRUB,        0x0000)       \
    XXX(LFSCK_TYPE_LAYOUT,       0x0001)       \
    XXX(LFSCK_TYPE_NAMESPACE,    0x0004)       \
    XXX(LFSCK_TYPES_SUPPORTED,   0x0005)       \
    XXX(LFSCK_TYPES_ALL,         0xFFFF)
/* LFSCK_TYPES_SUPPORTED = (LFSCK_TYPE_SCRUB | LFSCK_TYPE_LAYOUT | LFSCK_TYPE_NAMESPACE) */
//VALUE_STRING_ENUM2(lfsck_type_vals);
VALUE_STRING_ARRAY2(lfsck_type_vals);

/********************************************************************   \
 *
 * Helper Functions
 *
\********************************************************************/
#define buffer_padding_length(_o) ((8 - ((_o) % 8)) % 8)

static int
add_extra_padding(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree * tree)
{
    guint32 padding_len;

    padding_len = buffer_padding_length(offset);
    if (padding_len) {
        proto_tree_add_item(tree, hf_lustre_extra_padding, tvb, offset, padding_len, ENC_NA);
        offset+=padding_len;
    }
    return offset;
}


/********************************************************************\
 *
 * Conversation
 *
\********************************************************************/

typedef struct _lustre_conv_info_t {
    wmem_map_t *pdus;
} lustre_conv_info_t;

typedef struct lustre_trans {
    guint32 opcode;
    guint64 sub_opcode; /* i.e. intent, reint */
    guint64 match_bits;
} lustre_trans_t;

static lustre_trans_t *
lustre_get_trans(packet_info *pinfo, struct lnet_trans_info *info)
{
    conversation_t *conversation;
    lustre_conv_info_t *conv_info;
    lustre_trans_t *trans;

    // Ignore ports because this is kernel level and there can only be one Lustre instance per server
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
                                     0, 0, 0);
    if (conversation == NULL)
        conversation = conversation_new(pinfo->num, &pinfo->src,
                                        &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype), 0, 0, 0);

    conv_info = (lustre_conv_info_t *)conversation_get_proto_data(conversation, proto_lustre);
    if (!conv_info) {
        conv_info = wmem_new0(wmem_file_scope(), lustre_conv_info_t);
        conv_info->pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, proto_lustre, conv_info);
    }

    trans = (lustre_trans_t *)wmem_map_lookup(conv_info->pdus, GUINT_TO_POINTER(info->match_bits));
    if (trans == NULL) {
        void *ptr;
        trans = wmem_new0(wmem_file_scope(),lustre_trans_t);
        trans->match_bits = info->match_bits;

        ptr = wmem_map_insert(conv_info->pdus, GUINT_TO_POINTER(trans->match_bits), trans);
        if (ptr != NULL) {
            /* XXX - Is this even possible? ?*/
            trans = (lustre_trans_t *)ptr;
            REPORT_DISSECTOR_BUG("ERROR: packet-lustre: conversation replaced: "
                                 "trans:{opcode:%u sub_opcode:%" PRIu64 " match_bits:%" PRIx64 "} "
                                 "with match_bits:%" PRIx64,
                                 trans->opcode, trans->sub_opcode, trans->match_bits, info->match_bits);
        }
    }

    return trans;
}

/********************************************************************\
 *
 * Generic Buffer Dumps
 *
\********************************************************************/

static int
display_buffer_data(tvbuff_t *tvb, packet_info *pinfo, gint offset, proto_tree *parent_tree, guint32 buf_num, const gchar *msg)
{
    proto_item *item;
    guint32 data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_data, tvb, offset, data_len, ENC_NA);
    offset += data_len;

    if (msg != NULL)
        proto_item_append_text(item, ": %s", msg);

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);

    return offset;
}

static int
display_buffer_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gint offset, int hf_index, guint32 buf_num)
{
    guint32 string_len;

    string_len = LUSTRE_BUFFER_LEN(buf_num);
    if (string_len == 0)
        return offset;

    proto_tree_add_item(parent_tree, hf_index, tvb, offset, string_len, ENC_NA);

    offset += string_len;
    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);

    return offset;
}

/********************************************************************\
 *
 * Sub Structures
 *
\********************************************************************/

static void
lustre_fmt_ver( gchar *result, guint32 version )
{
   guint32 major, minor, patch, fix;

    fix = version & 0xff;
    version >>= 8;
    patch = version & 0xff;
    version >>= 8;
    minor = version & 0xff;
    version >>= 8;
    major = version & 0xff;
    snprintf( result, ITEM_LABEL_LENGTH, "%d.%d.%d.%d", major, minor, patch, fix);
}

static int
dissect_struct_lustre_handle(tvbuff_t *tvb, gint offset, proto_tree *parent_tree, int hf_index)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lustre_handle_cookie);

    proto_tree_add_item(tree, hf_lustre_lustre_handle_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_lu_fid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, int hf_index)
{
    proto_tree *tree;
    proto_item *item;
    guint64 seq;
    guint32 val;

    /* struct lu_fid { */
    /*     __u64 f_seq; */
    /*     __u32 f_oid; */
    /*     __u32 f_ver; */
    /* }; */


    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lu_fid);

    proto_tree_add_item_ret_uint64(tree, hf_lustre_lu_fid_f_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN, &seq);
    proto_item_append_text(item, ": [%#" PRIx64 ":", seq);
    offset += 8;

    proto_tree_add_item_ret_uint(tree, hf_lustre_lu_fid_f_oid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(item, "%#x:", val);
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_lustre_lu_fid_f_ver, tvb, offset, 4, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(item, "%#x]", val);
    offset += 4;

    return offset;
}

static int
dissect_struct_obd_uuid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, int hf_index)
{
     proto_tree *tree;
     proto_item *item;

     item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 40, ENC_NA);
     tree = proto_item_add_subtree(item, ett_lustre_obd_uuid);
     /* #define UUID_MAX        40 */
     /* struct obd_uuid { */
     /*     char uuid[UUID_MAX]; */
     /* }; */
     proto_tree_add_item(tree, hf_lustre_obd_uuid, tvb, offset, 40, ENC_ASCII);
     offset += 40;

     return offset;
}

static int
dissect_struct_ost_id(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree, *oi_tree;
    proto_item *item;

    /* struct ost_id { */
    /*     union { */
    /*         struct { */
    /*             __u64    oi_id; */
    /*             __u64    oi_seq; */
    /*         } oi; */
    /*         struct lu_fid oi_fid; */
    /*     }; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_ost_id, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ost_id);

    /* FID */
    dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_ost_id_fid);

    /* !OR! OI */
    item = proto_tree_add_item(tree, hf_lustre_ost_id_oi, tvb, offset, 16, ENC_NA);
    oi_tree = proto_item_add_subtree(item, ett_lustre_ost_id_oi);
    proto_tree_add_item(oi_tree, hf_lustre_ost_oi_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(oi_tree, hf_lustre_ost_oi_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_ost_layout(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_ost_layout, tvb, offset, 28, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ost_layout);

    /* struct ost_layout { */
    /*     __u32    ol_stripe_size; */
    /*     __u32    ol_stripe_count; */
    /*     __u64    ol_comp_start; */
    /*     __u64    ol_comp_end; */
    /*     __u32    ol_comp_id; */
    /* } __attribute__((packed)); */

    proto_tree_add_item(tree, hf_lustre_ost_layout_stripe_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ost_layout_stripe_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ost_layout_comp_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_layout_comp_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_layout_comp_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_struct_obdo(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    gint old_offset;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_obdo, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_obdo);

    /* struct obdo { */
    /*     __u64            o_valid;    /\* hot fields in this obdo *\/ */
    /*     struct ost_id        o_oi; */
    /*     __u64            o_parent_seq; */
    /*     __u64            o_size;        /\* o_size-o_blocks == ost_lvb *\/ */
    /*     __s64            o_mtime; */
    /*     __s64            o_atime; */
    /*     __s64            o_ctime; */
    /*     __u64            o_blocks;    /\* brw: cli sent cached bytes *\/ */
    /*     __u64            o_grant; */
    /*     __u32            o_blksize;    /\* optimal IO blocksize *\/ */
    /*     __u32            o_mode;        /\* brw: cli sent cache remain *\/ */
    /*     __u32            o_uid; */
    /*     __u32            o_gid; */
    /*     __u32            o_flags; */
    /*     __u32            o_nlink;    /\* brw: checksum *\/ */
    /*     __u32            o_parent_oid; */
    /*     __u32            o_misc;        /\* brw: o_dropped *\/ */

    /*     __u64            o_ioepoch;    /\* epoch in ost writes *\/ */
    /*     __u32            o_stripe_idx;    /\* holds stripe idx *\/ */
    /*     __u32            o_parent_ver; */
    /*     struct lustre_handle     o_handle;    /\* brw: lock handle to prolong * locks *\/ */
    /*     /\* Originally, the field is llog_cookie for destroy with unlink cookie */
    /*      * from MDS, it is obsolete in 2.8. Then reuse it by client to transfer */
    /*      * layout and PFL information in IO, setattr RPCs. Since llog_cookie is */
    /*      * not used on wire any longer, remove it from the obdo, then it can be */
    /*      * enlarged freely in the further without affect related RPCs. */
    /*      * */
    /*      * sizeof(ost_layout) + sieof(__u32) == sizeof(llog_cookie). *\/ */
    /* #if VERSION < 2.8.0  */
    /*     struct llog_cookie           o_lcookie; */
    /* #else // VERSION >= 2.10 */
    /*     struct ost_layout            o_layout; */
    /*     __u32            o_padding_3; */
    /* #endif */
    /*     __u32            o_uid_h; */
    /*     __u32            o_gid_h; */

    /*     __u64            o_data_version; */
    /*     __u32            o_projid; */
    /*     __u32            o_padding_4;    /\* also fix */
    /*                          * lustre_swab_obdo() *\/ */
    /*     __u64            o_padding_5; */
    /*     __u64            o_padding_6; */
    /* }; */

    // @@ make into bitmap of OBD_MD_FL*
    proto_tree_add_item(tree, hf_lustre_obdo_o_valid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    offset = dissect_struct_ost_id(tvb, offset, tree);
    proto_tree_add_item(tree, hf_lustre_obdo_o_parent_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_mtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_atime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_ctime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_grant, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_blksize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_nlink, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_parent_oid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_misc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_ioepoch, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_stripe_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_parent_ver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_obdo_o_handle);
    /* pre-2.8 llog_cookie o_lcookie - o_valid & OBD_MD_FLCOOKIE */

    /* 2.10 and later */
    offset = dissect_struct_ost_layout(tvb, offset, tree);
    proto_tree_add_item(tree, hf_lustre_obdo_o_padding_3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_obdo_o_uid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_gid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_data_version, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_projid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_padding_4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obdo_o_padding_5, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obdo_o_padding_6, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_item_set_len(tree, offset-old_offset);
    return offset;
}

static int
dissect_struct_llog_logid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, int hf_index)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 20, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llog_logid);

    offset = dissect_struct_ost_id(tvb, offset, tree);
    proto_tree_add_item(tree, hf_lustre_llog_logid_lgl_ogen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_struct_llog_gen(tvbuff_t *tvb, int offset, proto_tree *parent_tree, int hf_index)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llog_gen);

    proto_tree_add_item(tree, hf_lustre_llog_gen_conn_cnt, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_llog_gen_mnt_cnt, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_llog_rec_hdr(tvbuff_t *tvb, int offset, proto_tree *parent_tree, int hf_index)
{
    proto_tree *tree;
    proto_item *item;
    guint32 ind, type;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llog_rec_hdr);

    /* struct llog_rec_hdr { */
    /*     __u32    lrh_len; */
    /*     __u32    lrh_index; */
    /*     __u32    lrh_type; */
    /*     __u32    lrh_id; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_llog_rec_hdr_lrh_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_llog_rec_hdr_lrh_index, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ind);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_llog_rec_hdr_lrh_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &type);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llog_rec_hdr_lrh_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_append_text(parent_tree, " [%02d]: %s", ind, val_to_str(type, llog_op_types, "Unknown(%x)"));

    return offset;
}

static int
dissect_struct_llog_rec_tail(tvbuff_t *tvb, int offset, proto_tree *parent_tree, int hf_index)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llog_rec_tail);

    proto_tree_add_item(tree, hf_lustre_llog_rec_tail_lrt_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llog_rec_tail_lrt_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_struct_lquota_id(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_lquota_id, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lquota_id);

    /* union lquota_id { */
    /*     struct lu_fid    qid_fid; /\* FID for per-directory quota *\/ */
    /*     __u64        qid_uid; /\* user identifier *\/ */
    /*     __u64        qid_gid; /\* group identifier *\/ */
    /* }; */

    dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_qid_fid);
    proto_tree_add_item(tree, hf_lustre_qid_uid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_lustre_qid_gid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset+=16;

    return offset;
}
static int
dissect_struct_object_update(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree)
{
    proto_tree *tree, *ptree;
    proto_item *item;
    guint count, i, len;
    gint old_offset;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_obj_update, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_object_update);

    /* struct object_update { */
    /*     __u16        ou_type;        /\* enum update_type *\/ */
    /*     __u16        ou_params_count;    /\* update parameters count *\/ */
    /*     __u32        ou_result_size;        /\* how many bytes can return *\/ */
    /*     __u32        ou_flags;        /\* enum update_flag *\/ */
    /*     __u32        ou_padding1;        /\* padding 1 *\/ */
    /*     __u64        ou_batchid;        /\* op transno on master *\/ */
    /*     struct lu_fid    ou_fid;            /\* object to be updated *\/ */
    /*     struct object_update_param ou_params[0]; /\* update params *\/ */
    /* }; */
    /* struct object_update_param { */
    /*     __u16    oup_len;    /\* length of this parameter *\/ */
    /*     __u16    oup_padding; */
    /*     __u32    oup_padding2; */
    /*     char    oup_buf[0]; */
    /* }; */
    proto_tree_add_item(tree, hf_lustre_obj_update_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_lustre_obj_update_params_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_obj_update_result_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obj_update_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obj_update_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obj_update_batchid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_obj_update_fid);

    for (i = 0; i < count; ++i) {
        item = proto_tree_add_item(parent_tree, hf_lustre_obj_update_param, tvb, offset, -1, ENC_NA);
        proto_item_append_text(item, ": [%d]", i);
        ptree = proto_item_add_subtree(item, ett_lustre_object_update_param);

        proto_tree_add_item_ret_uint(ptree, hf_lustre_obj_update_param_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &len);
        offset += 2;
        proto_tree_add_item(ptree, hf_lustre_obj_update_param_padding, tvb, offset, 6, ENC_NA);
        offset += 6;
        proto_tree_add_item(parent_tree, hf_lustre_obj_update_param_buf, tvb, offset, len, ENC_NA);
        offset += len;
    }

    proto_item_set_len(tree, offset-old_offset);
    return offset;
}

static int
dissect_struct_object_update_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    guint count, i, magic;
    int old_offset;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_obj_update_request, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_object_update_request);

    /* struct object_update_request { */
    /*     __u32            ourq_magic; */
    /*     __u16            ourq_count;    /\* number of ourq_updates[] *\/ */
    /*     __u16            ourq_padding; */
    /*     struct object_update    ourq_updates[0]; */
    /* }; */

    proto_tree_add_item_ret_uint(tree, hf_lustre_obj_update_request_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN, &magic);
    if (magic != UPDATE_REQUEST_MAGIC_V2)
        expert_add_info(pinfo, tree, &ei_lustre_badmagic);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_obj_update_request_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_obj_update_request_padding, tvb, offset, 2, ENC_NA);
    offset += 2;

    for (i = 0; i < count; ++i)
        offset = dissect_struct_object_update(tvb, offset, pinfo, tree);

    proto_item_set_len(tree, offset-old_offset);

    return offset;
}

static int
dissect_struct_lov_desc(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    /* struct lov_desc { */
    /*     __u32 ld_tgt_count;        /\* how many OBD's *\/ */
    /*     __u32 ld_active_tgt_count;    /\* how many active *\/ -- MAGIC on wire */
    /*     __s32 ld_default_stripe_count;    /\* how many objects are used *\/ */
    /*     __u32 ld_pattern;        /\* default PATTERN_RAID0 *\/ */
    /*     __u64 ld_default_stripe_size;    /\* in bytes *\/ */
    /*     __s64 ld_default_stripe_offset;    /\* starting OST index *\/ */
    /*     __u32 ld_padding_0;        /\* unused *\/ */
    /*     __u32 ld_qos_maxage;        /\* in second *\/ */
    /*     __u32 ld_padding_1;        /\* also fix lustre_swab_lov_desc *\/ */
    /*     __u32 ld_padding_2;        /\* also fix lustre_swab_lov_desc *\/ */
    /*     struct obd_uuid ld_uuid; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_lov_desc, tvb, offset, 88, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lov_desc);

    proto_tree_add_item(tree, hf_lustre_lov_desc_tgt_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_desc_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_desc_default_stripe_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_desc_pattern, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_desc_default_stripe_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lov_desc_default_stripe_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lov_desc_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_desc_qos_maxage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_desc_padding, tvb, offset, 8, ENC_NA);
    offset += 8;
    offset = dissect_struct_obd_uuid(tvb, offset, tree, hf_lustre_lov_desc_uuid);

    return offset;
}
/********************************************************************
 *
 * LLOG Sub Structures
 *
 */

static int
dissect_struct_changelog_rec(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    guint namelen, flags, type;
    int old_offset = offset;

    /* struct changelog_rec { */
    /*     __u16            cr_namelen; */
    /*     __u16            cr_flags; /\**< \a changelog_rec_flags *\/ */
    /*     __u32            cr_type;  /\**< \a changelog_rec_type *\/ */
    /*     __u64            cr_index; /\**< changelog record number *\/ */
    /*     __u64            cr_prev;  /\**< last index for this target fid *\/ */
    /*     __u64            cr_time; */
    /*     union { */
    /*     struct lu_fid    cr_tfid;        /\**< target fid *\/ */
    /*     __u32        cr_markerflags; /\**< CL_MARK flags *\/ */
    /*     }; */
    /*     struct lu_fid        cr_pfid;        /\**< parent fid *\/ */
    /* }; 32+16+16+extras */
    /* after changelog_rec, there are optional fields based on cr_flags
     * CLF_RENAME :: struct changelog_ext_rename { struct lu_fid    cr_sfid, cr_spfid; }
     * CLF_JOBID  :: struct changelog_ext_jobid  { char             cr_jobid[LUSTRE_JOBID_SIZE==32]; }
     * CLF_EXTRA_FLAGS :: struct changelog_ext_extra_flags { __u64  cr_extra_flags; }
     * cr_namelen>0 :: char name[cr_namelen+'\0']
     */
    item = proto_tree_add_item(parent_tree, hf_lustre_changelog_rec, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_changelog_rec);

    proto_tree_add_item_ret_uint(tree, hf_lustre_changelog_rec_namelen, tvb, offset, 2, ENC_LITTLE_ENDIAN, &namelen);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_lustre_changelog_rec_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN, &flags);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_lustre_changelog_rec_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &type);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_changelog_rec_index, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_changelog_rec_prev, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_changelog_rec_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    if (type == CL_MARK) {
        proto_tree_add_item(tree, hf_lustre_changelog_rec_markerflags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_changelog_rec_padding, tvb, offset, 12, ENC_NA);
        offset += 12;
    } else
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_changelog_rec_tfid);
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_changelog_rec_pfid);
    /* end of struct changelog_rec */
    if (flags & CLF_RENAME) {
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_changelog_ext_rename_sfid);
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_changelog_ext_rename_spfid);
    }
    if (flags & CLF_JOBID) {
        proto_tree_add_item(tree, hf_lustre_changelog_ext_jobid_jobid, tvb, offset, 32, ENC_ASCII);
        offset += 32;
    }
    if (flags & CLF_EXTRA_FLAGS) {
        proto_tree_add_item(tree, hf_lustre_changelog_extra_flags_extra_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }
    if (namelen > 0) {
        proto_tree_add_item(tree, hf_lustre_changelog_ext_name, tvb, offset, namelen, ENC_ASCII);
        offset += namelen;
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
dissect_struct_cfg_marker(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_cfg_marker, tvb, offset, 160, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_cfg_marker);

    /* struct cfg_marker { */
    /*     __u32    cm_step;       /\* aka config version *\/ */
    /*     __u32    cm_flags; */
    /*     __u32    cm_vers;       /\* lustre release version number *\/ */
    /*     __u32    cm_padding;    /\* 64 bit align *\/ */
    /*     __s64    cm_createtime; /\*when this record was first created *\/ */
    /*     __s64    cm_canceltime; /\*when this record is no longer valid*\/ */
    /*     char    cm_tgtname[MTI_NAME_MAXLEN]; */
    /*     char    cm_comment[MTI_NAME_MAXLEN]; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_cfg_marker_step, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_vers, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_createtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_canceltime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_tgtname, tvb, offset, 64, ENC_ASCII);
    offset += 64;
    proto_tree_add_item(tree, hf_lustre_cfg_marker_comment, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    return offset;
}

static int
dissect_struct_lustre_cfg(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    int old_offset, buf_offset;
    guint count, i, cmd, len;

    old_offset = offset;

    /* struct lustre_cfg {
     *    __u32 lcfg_version;
     *    __u32 lcfg_command;
     *    __u32 lcfg_num;
     *    __u32 lcfg_flags;
     *    __u64 lcfg_nid;
     *    __u32 lcfg_nal;        // not used any more
     *    __u32 lcfg_bufcount;
     *    __u32 lcfg_buflens[];
     * };
     */

    item = proto_tree_add_item(parent_tree, hf_lustre_lustre_cfg, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lustre_cfg);

    proto_tree_add_item(tree, hf_lustre_lustre_cfg_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_lustre_cfg_command, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cmd);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_cfg_num, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_cfg_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = lnet_dissect_struct_nid(tvb, tree, offset, hf_lustre_lustre_cfg_nid);
    proto_tree_add_item(tree, hf_lustre_lustre_cfg_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_lustre_cfg_bufcount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;

    buf_offset = offset;
    for (i = 0; i < count; ++i) {
        proto_tree_add_item(tree, hf_lustre_lustre_cfg_buflen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    offset = add_extra_padding(tvb, offset, NULL, tree);
    proto_item_append_text(item, ": %s", val_to_str(cmd, lcfg_command_type_vals, "Unknown(%x)"));
    switch (cmd) {
    case LCFG_MARKER:
        offset = dissect_struct_cfg_marker(tvb, offset, tree);
        break;
    case LCFG_SETUP:
        if (count == 2) {
            len = tvb_get_letohl(tvb, buf_offset);
            len += buffer_padding_length(len+offset);
            proto_tree_add_item(tree, hf_lustre_lustre_cfg_buffer, tvb, offset, len, ENC_ASCII);
            offset += len;
            offset = dissect_struct_lov_desc(tvb, offset, tree);
            break;
        }
        // ELSE FALL THROUGH
    default:
        for (i = 0; i < count; ++i) {
            len = tvb_get_letohl(tvb, buf_offset+(4*i));
            len += buffer_padding_length(len+offset);
            proto_tree_add_item(tree, hf_lustre_lustre_cfg_buffer, tvb, offset, len, ENC_ASCII);
            offset += len;
        }
        break;
    }
    proto_item_set_len(item, offset-old_offset);
    return offset;
}

/********************************************************************
 *
 * LDLM Sub Structures
 *
 */
static int
dissect_struct_ldlm_lock_desc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint64 *ltype)
{
    proto_tree *tree, *res_tree, *id_tree, *l_tree;
    proto_item *item;
    gint i;
    guint32 type;

    /* struct ldlm_lock_desc { */
    /*     struct ldlm_resource_desc l_resource; */
    /*     enum ldlm_mode l_req_mode; */
    /*     enum ldlm_mode l_granted_mode; */
    /*     union ldlm_wire_policy_data l_policy_data; */
    /* }; */
    /* struct ldlm_resource_desc { */
    /*     enum ldlm_type       lr_type; */
    /*     __u32           lr_pad; /\* also fix lustre_swab_ldlm_resource_desc *\/ */
    /*     struct ldlm_res_id lr_name; */
    /* }; */
    /* struct ldlm_res_id { */
    /*     __u64 name[RES_NAME_SIZE]; */
    /* }; */
    /* RES_NAME_SIZE == 4 */
    /* SIZE == (4+4+32)+4+4+(32)*/

    item = proto_tree_add_item(parent_tree, hf_lustre_ldlm_lock_desc, tvb, offset, 80, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ldlm_lock_desc);

    item = proto_tree_add_item(tree, hf_lustre_ldlm_resource_desc, tvb, offset, 40, ENC_NA);
    res_tree = proto_item_add_subtree(item, ett_lustre_ldlm_resource_desc);
    proto_tree_add_item_ret_uint(res_tree, hf_lustre_ldlm_resource_desc_lr_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &type);
    offset += 4;
    proto_tree_add_item(res_tree, hf_lustre_ldlm_resource_desc_lr_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    for (i = 0; i < 4; ++i) {
        item = proto_tree_add_item(res_tree, hf_lustre_ldlm_res_id, tvb, offset, 8, ENC_NA);
        id_tree = proto_item_add_subtree(item, ett_lustre_ldlm_res_id);
        proto_item_append_text(item, " [%d]", i);
        switch (type) {
        case LDLM_IBITS:
            proto_tree_add_item(id_tree, hf_lustre_ldlm_res_id_bits, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case LDLM_PLAIN:
            if (i == 1) {
                if (ltype)
                    *ltype = tvb_get_letoh64(tvb, offset);
                proto_tree_add_item(id_tree, hf_lustre_ldlm_res_id_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            } else
                proto_tree_add_item(id_tree, hf_lustre_ldlm_res_id_string, tvb, offset, 8, ENC_ASCII);
            break;
        default:
            proto_tree_add_item(id_tree, hf_lustre_ldlm_res_id_name, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        }
        offset += 8;
    }

    proto_tree_add_item(tree, hf_lustre_ldlm_lock_desc_l_req_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ldlm_lock_desc_l_granted_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* union ldlm_wire_policy_data { */
    /*     struct ldlm_extent      l_extent; */
    /*     struct ldlm_flock_wire  l_flock; */
    /*     struct ldlm_inodebits   l_inodebits; */
    /* } */
    /* sizeof(ldlm_wire_policy_data) == 32 */
    switch (type) {
    case LDLM_EXTENT:
        item = proto_tree_add_item(tree, hf_lustre_ldlm_lock_desc_l_policy_data, tvb, offset, 24, ENC_NA);
        l_tree = proto_item_add_subtree(item, ett_lustre_ldlm_extent);
        /*     struct ldlm_extent { */
        /*         __u64 start; */
        /*         __u64 end; */
        /*         __u64 gid; */
        /*     }; */
        proto_tree_add_item(l_tree, hf_lustre_ldlm_extent_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_extent_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_extent_gid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_extra_padding, tvb, offset, 8, ENC_NA);
        offset += 8;
        break;
    case LDLM_PLAIN:
    case LDLM_FLOCK:
        item = proto_tree_add_item(tree, hf_lustre_ldlm_lock_desc_l_policy_data, tvb, offset, 32, ENC_NA);
        l_tree = proto_item_add_subtree(item, ett_lustre_ldlm_flock);
        /*     struct ldlm_flock_wire { */
        /*         __u64 lfw_start; */
        /*         __u64 lfw_end; */
        /*         __u64 lfw_owner; */
        /*         __u32 lfw_padding; */
        /*         __u32 lfw_pid; */
        /*     }; */
        proto_tree_add_item(l_tree, hf_lustre_ldlm_flock_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_flock_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_flock_owner, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_flock_padding, tvb, offset, 4, ENC_NA);
        offset += 4;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_flock_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
    case LDLM_IBITS:
        item = proto_tree_add_item(tree, hf_lustre_ldlm_lock_desc_l_policy_data, tvb, offset, 8, ENC_NA);
        l_tree = proto_item_add_subtree(item, ett_lustre_ldlm_flock);
        /*     struct ldlm_inodebits { */
        /*         __u64 bits; */
        /*         __u64 try_bits; */
        /*     }; */
        proto_tree_add_item(l_tree, hf_lustre_ldlm_inodebits_bits, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_ldlm_inodebits_try_bits, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(l_tree, hf_lustre_extra_padding, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    case 0: /* no actual locking */
        proto_tree_add_item(tree, hf_lustre_extra_padding, tvb, offset, 32, ENC_NA);
        offset += 32;
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "Unknown Lock Type: %d", type);
        break;
    }

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);
    return offset;
}

static int
dissect_struct_seq_range(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    gint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct lu_seq_range { */
    /*     __u64 lsr_start; */
    /*     __u64 lsr_end; */
    /*     __u32 lsr_index; */
    /*     __u32 lsr_flags; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_seq_range, tvb, offset, 24, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_seq_range);

    proto_tree_add_item(tree, hf_lustre_seq_range_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_seq_range_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_seq_range_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_seq_range_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_struct_ldlm_gl_barrier_desc(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct ldlm_gl_barrier_desc { */
    /*     __u32        lgbd_status; */
    /*     __u32        lgbd_timeout; */
    /*     __u64        lgbd_padding; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_ldlm_gl_barrier_desc, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ldlm_gl_barrier_desc);

    proto_tree_add_item(tree, hf_lustre_ldlm_gl_barrier_desc_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_barrier_desc_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_barrier_desc_padding, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int
dissect_struct_ldlm_gl_lquota_desc(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct ldlm_gl_lquota_desc { */
    /*     union lquota_id	gl_id;    /\* quota ID subject to the glimpse *\/ */
    /*     __u64        gl_flags; /\* see LQUOTA_FL* below *\/ */
    /*     __u64        gl_ver;   /\* new index version *\/ */
    /*     __u64        gl_hardlimit; /\* new hardlimit or qunit value *\/ */
    /*     __u64        gl_softlimit; /\* new softlimit *\/ */
    /*     __u64        gl_time; */
    /*     __u64        gl_pad2; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_ldlm_gl_lquota_desc, tvb, offset, 64, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ldlm_gl_lquota_desc);

    offset = dissect_struct_lquota_id(tvb, offset, tree);
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_lquota_desc_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_lquota_desc_ver, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_lquota_desc_hardlimit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_lquota_desc_softlimit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_lquota_desc_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ldlm_gl_lquota_desc_pad2, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int
dissect_struct_ldlm_gl_desc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, lustre_trans_t *trans, guint buf_num)
{
    guint data_len;
    int old_offset;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    old_offset = offset;

    /* union ldlm_gl_desc { */
    /*     struct ldlm_gl_lquota_desc	lquota_desc; */
    /*     struct ldlm_gl_barrier_desc	barrier_desc; */
    /* }; SIZE == 64 */

    switch (trans->sub_opcode) {
    case CONFIG_T_BARRIER:
        /* Size == 16 */
        offset = dissect_struct_ldlm_gl_barrier_desc(tvb, offset, parent_tree, buf_num);
        data_len = old_offset+64-offset;
        proto_tree_add_item(parent_tree, hf_lustre_extra_padding, tvb, offset, data_len, ENC_NA);
        offset += data_len;
        break;
    case CONFIG_T_CONFIG:
        /* Size == 64 */
        offset = dissect_struct_ldlm_gl_lquota_desc(tvb, offset, parent_tree, buf_num);
        break;
    default:
        offset = display_buffer_data(tvb, pinfo, offset, parent_tree, buf_num, "GLIMPSE DESC");
        break;
    }

    return offset;
}

static int
dissect_struct_ldlm_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint64 *type, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint old_offset, data_len, count, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    old_offset = offset;

    /* struct ldlm_request { */
    /*     __u32 lock_flags; */
    /*     __u32 lock_count; */
    /*     struct ldlm_lock_desc lock_desc; */
    /*     struct lustre_handle lock_handle[LDLM_LOCKREQ_HANDLES]; */
    /* }; */
    /* LDLM_LOCKREQ_HANDLES == 2 */
    /* sizeof(ldlm_request) == 8+72+ 8*MAX(2,lock_count) */

    item = proto_tree_add_item(parent_tree, hf_lustre_ldlm_request, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ldlm_request);

    /* @@ change to bitmask on LDLM_FL_* */
    proto_tree_add_item(tree, hf_lustre_ldlm_request_lock_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* There are always at least 2 buffers */
    proto_tree_add_item_ret_uint(tree, hf_lustre_ldlm_request_lock_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    if (count < 2)
        count = 2;
    offset += 4;
    offset = dissect_struct_ldlm_lock_desc(tvb, offset, pinfo, tree, type);
    for (i = 0; i < count; ++i)
        offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_ldlm_request_lock_handle);

    proto_item_set_len(tree, offset-old_offset);
    return offset;
}

static int
dissect_struct_ldlm_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint64 *type, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    gint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct ldlm_reply { */
    /*     __u32 lock_flags; */
    /*     __u32 lock_padding;     /\* also fix lustre_swab_ldlm_reply *\/ */
    /*     struct ldlm_lock_desc lock_desc; */
    /*     struct lustre_handle lock_handle; */
    /*     __u64  lock_policy_res1; */
    /*     __u64  lock_policy_res2; */
    /* }; */
    /* SIZE == 24+80+8 */

    item = proto_tree_add_item(parent_tree, hf_lustre_ldlm_reply, tvb, offset, 112, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ldlm_reply);

    proto_tree_add_item(tree, hf_lustre_ldlm_reply_lock_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ldlm_reply_lock_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    offset = dissect_struct_ldlm_lock_desc(tvb, offset, pinfo, tree, type);
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_ldlm_reply_lock_handle);
    proto_tree_add_item(tree, hf_lustre_ldlm_reply_lock_policy_res1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ldlm_reply_lock_policy_res2, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

/********************************************************************\
 *
 * MGS Buffer Structures
 *
\********************************************************************/
static int
dissect_struct_mgs_config_body(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree, lustre_trans_t *trans)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_mgs_config_body, tvb, offset, 80, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mgs_config_body);

    /* struct mgs_config_body { */
    /*     char     mcb_name[MTI_NAME_MAXLEN]; /\* logname *\/ */
    /*     __u64    mcb_offset;    /\* next index of config log to request *\/ */
    /*     __u16    mcb_type;      /\* type of log: CONFIG_T_[CONFIG|RECOVER] *\/ */
    /*     __u8     mcb_nm_cur_pass; */
    /*     __u8     mcb_bits;      /\* bits unit size of config log *\/ */
    /*     __u32    mcb_units;     /\* # of units for bulk transfer *\/ */
    /* }; */
    /* MTI_NAME_MAXLEN == 64 */

    proto_tree_add_item(tree, hf_lustre_mgs_config_body_name, tvb, offset, 64, ENC_ASCII);
    offset += 64;
    proto_tree_add_item(tree, hf_lustre_mgs_config_body_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    trans->sub_opcode = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_lustre_mgs_config_body_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_mgs_config_body_nm_cur_pass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_lustre_mgs_config_body_bits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_lustre_mgs_config_body_units, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;


    return offset;
}

static int
dissect_struct_mgs_config_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree, lustre_trans_t *trans)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_mgs_config_res, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mgs_config_res);

    /* struct mgs_config_res { */
    /*     __u64    mcr_offset;    /\* index of last config log *\/ */
    /*     union { */
    /*         __u64    mcr_size;          /\* size of the log *\/ */
    /*         __u64    mcr_nm_cur_pass;   /\* current nodemap config pass *\/ */
    /*     }; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_mgs_config_res_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    if (trans->sub_opcode == CONFIG_T_NODEMAP)
        proto_tree_add_item(tree, hf_lustre_mgs_config_res_nm_cur_pass, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    else
        proto_tree_add_item(tree, hf_lustre_mgs_config_res_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_mgs_target_info(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint32 data_len, old_offset, i, count;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_mgs_target_info, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mgs_config_res);

    /* #define MTI_NAME_MAXLEN  64 */
    /* #define MTI_PARAM_MAXLEN 4096 */
    /* #define MTI_NIDS_MAX     32 */
    /*     struct mgs_target_info { */
    /*         __u32            mti_lustre_ver; */
    /*         __u32            mti_stripe_index; */
    /*         __u32            mti_config_ver; */
    /*         __u32            mti_flags; */
    /*         __u32            mti_nid_count; */
    /*         __u32            mti_instance; /\* Running instance of target *\/ */
    /*         char             mti_fsname[MTI_NAME_MAXLEN]; */
    /*         char             mti_svname[MTI_NAME_MAXLEN]; */
    /*         char             mti_uuid[sizeof(struct obd_uuid)]; */
    /*         __u64            mti_nids[MTI_NIDS_MAX];     /\* host nids (lnet_nid_t)*\/ */
    /*         char             mti_params[MTI_PARAM_MAXLEN]; */
    /*     }; */

    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_lustre_ver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_stripe_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_config_ver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_mgs_target_info_mti_nid_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_instance, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_fsname, tvb, offset, 64, ENC_NA);
    offset += 64;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_svname, tvb, offset, 64, ENC_NA);
    offset += 64;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_uuid, tvb, offset, 40, ENC_ASCII);
    offset += 40;
    for (i = 0; i < count; ++i)
        offset = lnet_dissect_struct_nid(tvb, tree, offset, hf_lustre_mgs_target_info_mti_nids);
    i = (32-count) * 8;
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_padding, tvb, offset, i, ENC_NA);
    offset += i;
    i = MIN(4096, data_len-(offset-old_offset));
    proto_tree_add_item(tree, hf_lustre_mgs_target_info_mti_params, tvb, offset, i, ENC_NA);
    offset += i;

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

/********************************************************************\
 *
 * MDS Buffer Structures
 *
\********************************************************************/

static int
dissect_struct_acl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_acl, tvb, offset, data_len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_acl);

    proto_tree_add_item(tree, hf_lustre_data, tvb, offset, data_len, ENC_NA);
    offset += data_len;

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);

    return offset;
}

static int
dissect_struct_mdt_ioepoch(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_mdt_ioepoch, tvb, offset, 24, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mdt_ioepoch);

    /* struct mdt_ioepoch { */
    /*     struct lustre_handle mio_handle; */
    /*     __u64 mio_unused1; /\* was ioepoch *\/ */
    /*     __u32 mio_unused2; /\* was flags *\/ */
    /*     __u32 mio_padding; */
    /* } */
    /* sizeof(mdt_ioepoch) == 24 */

    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_mdt_ioepoch_handle);
    proto_tree_add_item(tree, hf_lustre_mdt_ioepoch_ioepoch, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_ioepoch_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_ioepoch_padding, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

static int
dissect_struct_close_data(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_close_data, tvb, offset, 96, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_close_data);

    /* struct close_data { */
    /*     struct lustre_handle    cd_handle; */
    /*     struct lu_fid    cd_fid; */
    /*     __u64        cd_data_version; */
    /*     __u64        cd_reserved[8]; */
    /* }; */
    /* sizeof(mdt_ioepoch) == 8+16+8+64 */

    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_close_handle);
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_close_fid);
    proto_tree_add_item(tree, hf_lustre_close_data_ver, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_close_reserved, tvb, offset, 64, ENC_NA);
    offset += 64;

    return offset;
}

static int
dissect_struct_mdt_rec_reint(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_tree *item;
    guint data_len, opcode;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct mdt_rec_reint {    LINK   CREATE  RENAME  SETXATTR        SETATTR
     *   0 __u32  rr_opcode;                    UNLINK
     *   4 __u32  rr_cap;
     *   8 __u32  rr_fsuid;
     *  12 __u32  rr_fsuid_h;
     *  16 __u32  rr_fsgid;
     *  20 __u32  rr_fsgid_h;
     *  24 __u32  rr_suppgid1;
     *  28 __u32  rr_suppgid1_h;
     *  32 __u32  rr_suppgid2;                                          pad
     *  36 __u32  rr_suppgid2_h;                                        pad
     *  40 lu_fid rr_fid1;
     * -- All above is the same
     *  56 lu_fid rr_fid2;                              pad,pad,pad     valid,uid,gid
     *  72 __s64  rr_mtime;     time    COOKIE  time    valid           size
     *  80 __s64  rr_atime;     pad     time    pad     time            blocks
     *  88 __s64  rr_ctime;     pad     rdev    pad     pad             mtime
     *  96 __u64  rr_size;      pad     ioepoch pad     pad             atime
     * 104 __u64  rr_blocks;    pad     pad     pad     pad             ctime
     * 112 __u32  rr_bias;              mode            size            attr_flags
     * 116 __u32  rr_mode;      pad     bias            flags
     * 120 __u32  rr_flags;     pad             pad     pad             bias
     * 124 __u32  rr_flags_h;   pad             pad     pad             projid
     * 128 __u32  rr_umask;     pad             pad     pad             pad
     * 132 __u32  rr_padding_4;
     * }; */
    /* sizeof(mdt_rec_reint) == 136 */

    item = proto_tree_add_item(parent_tree, hf_lustre_mdt_rec_reint, tvb, offset, 136, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mdt_rec_reint);

    if (data_len != 136)
        expert_add_info_format(pinfo, tree, &ei_lustre_buflen,
                               "Buffer Length mismatch: expected:136 !== length:%u", data_len);

    proto_tree_add_item_ret_uint(tree, hf_lustre_mdt_rec_reint_opcode, tvb, offset, 4, ENC_LITTLE_ENDIAN, &opcode);
    proto_item_append_text(tree, " %s", val_to_str(opcode, mds_reint_vals, "BAD(%d)"));
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_cap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_fsuid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_fsuid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_fsgid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_fsgid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_suppgid1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_suppgid1_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Byte:  32 */
    if (opcode == REINT_SETATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 8, ENC_NA);
        offset += 8;
    } else {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_suppgid2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_suppgid2_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    /* Byte:  40 */
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_mdt_rec_reint_fid1);
    if (opcode == REINT_SETXATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 16, ENC_NA);
        offset += 16;
    } else if (opcode == REINT_SETATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_valid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    } else { /* DEFAULT */
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_mdt_rec_reint_fid2);
    }
    /* Byte:  72 */
    if (opcode == REINT_CREATE) {
        offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_mdt_rec_reint_old_handle);
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_rdev, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_ioepoch, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 8, ENC_NA);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_bias, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

    } else if (opcode == REINT_SETXATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_valid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 24, ENC_NA);
        offset += 24;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_size32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

    } else if (opcode == REINT_SETATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_size64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_mtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_atime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_ctime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_attr_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

    } else {
        if (opcode == REINT_LINK || opcode == REINT_RENAME || opcode == REINT_UNLINK) {
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 32, ENC_NA);
            offset += 32;

        } else { /* DEFAULT */
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_mtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_atime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_ctime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_size64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_bias, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    /* Byte: 120 */
    if (opcode == REINT_LINK || opcode == REINT_RENAME || opcode == REINT_UNLINK || opcode == REINT_SETXATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 12, ENC_NA);
        offset += 12;

    } else if (opcode == REINT_SETATTR) {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_bias, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_projid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

    } else {
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_flags_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_umask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    /* Byte: 132 */
    proto_tree_add_item(tree, hf_lustre_mdt_rec_reint_padding, tvb, offset, 4, ENC_NA);
    offset += 4;

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);

    return offset;
}

static int
dissect_struct_lmv_mds_md_v1(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint old_offset, count, i, magic;

    count = LUSTRE_BUFFER_LEN(buf_num);

    if (count == 0)
        return offset;

    old_offset = offset;
    /* /\* LMV layout EA, and it will be stored both in master and slave object *\/ */
    /* struct lmv_mds_md_v1 { */
    /*     __u32 lmv_magic; */
    /*     __u32 lmv_stripe_count; */
    /*     __u32 lmv_master_mdt_index;    /\* On master object, it is master */
    /*                      * MDT index, on slave object, it */
    /*                      * is stripe index of the slave obj *\/ */
    /*     __u32 lmv_hash_type;        /\* dir stripe policy, i.e. indicate */
    /*                      * which hash function to be used, */
    /*                      * Note: only lower 16 bits is being */
    /*                      * used for now. Higher 16 bits will */
    /*                      * be used to mark the object status, */
    /*                      * for example migrating or dead. *\/ */
    /*     __u32 lmv_layout_version;    /\* Used for directory restriping *\/ */
    /*     __u32 lmv_padding1; */
    /*     __u64 lmv_padding2; */
    /*     __u64 lmv_padding3; */
    /*     char lmv_pool_name[16];    /\* pool name *\/ */
    /*     struct lu_fid lmv_stripe_fids[0];    /\* FIDs for each stripe *\/ */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_lmv_mds_md, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lmv_mds_md);

    proto_tree_add_item_ret_uint(tree, hf_lustre_lmv_mds_md_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN, &magic);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_lmv_mds_md_stripe_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lmv_mds_md_master_mdt_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lmv_mds_md_hash_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_lustre_lmv_mds_md_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lmv_mds_md_layout_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lmv_mds_md_padding, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_item(tree, hf_lustre_lmv_mds_md_pool_name, tvb, offset, 16, ENC_ASCII);
    offset += 16;

    for (i = 0; i < count && magic == LMV_MAGIC_V1; ++i)
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_lmv_mds_md_stripe_fid);

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

static int
dissect_struct_lov_mds_md(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree, *ost_tree;
    proto_item *item;
    guint data_len, old_offset, stripe_count, i;
    guint32 magic;

    old_offset = offset;
    data_len = LUSTRE_BUFFER_LEN(buf_num);

    if (data_len == 0)
        return offset;

    magic = tvb_get_letohl(tvb, offset);

    switch (magic) {
    case LOV_MAGIC_V1:
        item = proto_tree_add_item(parent_tree, hf_lustre_lov_mds_md, tvb, offset, -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_lustre_lov_mds_md);
        proto_item_append_text(item, " V1");
        break;
    case LOV_MAGIC_V3:
        item = proto_tree_add_item(parent_tree, hf_lustre_lov_mds_md, tvb, offset, -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_lustre_lov_mds_md);
        proto_item_append_text(item, " V3");
        break;
    case LMV_MAGIC_V1:
    case LMV_MAGIC_STRIPE: /* this uses struct lmv_mds_md, but without fids */
        return dissect_struct_lmv_mds_md_v1(tvb, pinfo, offset, parent_tree, buf_num);
        break;
    default:
        // This is for speculative processing of LDLM Intent Reply
        // IT_LAYOUT, and thus not an error
        return display_buffer_data(tvb, pinfo, offset, parent_tree, buf_num, "DLM LVB");
    }

    /* struct lov_mds_md_v1 { */
    /*     uint32 lmm_magic; */
    /*     uint32 lmm_pattern; */
    /*     uint64 lmm_object_id; */
    /*     uint64 lmm_object_seq; */
    /*     uint32 lmm_stripe_size; */
    /*     uint16 lmm_stripe_count; */
    /*     uint16 lmm_layout_gen; */
    /*     struct lov_ost_data_v1 lmm_objects[0]; <-- en fait on en a lmm_stripe_count */
    /* } */
    /* struct lov_mds_md_v3 {            /\* LOV EA mds/wire data (little-endian) *\/ */
    /*     __u32 lmm_magic;          /\* magic number = LOV_MAGIC_V3 *\/ */
    /*     __u32 lmm_pattern;        /\* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 *\/ */
    /*     struct ost_id    lmm_oi;      /\* LOV object ID *\/ */
    /*     __u32 lmm_stripe_size;    /\* size of stripe in bytes *\/ */
    /*     /\* lmm_stripe_count used to be __u32 *\/ */
    /*     __u16 lmm_stripe_count;   /\* num stripes in use for this object *\/ */
    /*     __u16 lmm_layout_gen;     /\* layout generation number *\/ */
    /*     char  lmm_pool_name[LOV_MAXPOOLNAME + 1]; /\* must be 32bit aligned *\/ */
    /*     struct lov_ost_data_v1 lmm_objects[0]; /\* per-stripe data *\/ */
    /* }; LOV_MAXPOOLNAME == 15 */

    proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_pattern, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    switch (magic) {
    case LOV_MAGIC_V1:
        proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_object_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_object_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
    case LOV_MAGIC_V3:
        offset = dissect_struct_ost_id(tvb, offset, tree);
        break;
    }
    proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_stripe_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_lov_mds_md_lmm_stripe_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &stripe_count);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_layout_gen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (magic == LOV_MAGIC_V3) {
        proto_tree_add_item(tree, hf_lustre_lov_mds_md_lmm_pool_name, tvb, offset, 16, ENC_ASCII);
        offset += 16;
    }

    /* This may happend when, server is just returning the stripe
       count, but not the stripe data (ie default stripe_count on a
       directory) */
    if (data_len-(offset-old_offset) != stripe_count*24)
        stripe_count = (data_len-(offset-old_offset))/24;

    for (i = 0; i < stripe_count; ++i) {
        item = proto_tree_add_item(tree, hf_lustre_lov_ost_data_v1, tvb, offset, 24, ENC_NA);
        ost_tree = proto_item_add_subtree(item, ett_lustre_lov_ost_data_v1);
        proto_item_append_text(item, " [%u]", i);
        offset = dissect_struct_ost_id(tvb, offset, ost_tree);
        proto_tree_add_item(ost_tree, hf_lustre_lov_ost_data_v1_l_ost_gen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(ost_tree, hf_lustre_lov_ost_data_v1_l_ost_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
dissect_struct_llog_cookie_array(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);

    for (i = 0; i < data_len/24; ++i) {
        item = proto_tree_add_item(parent_tree, hf_lustre_llog_cookie, tvb, offset, 24, ENC_NA);
        tree = proto_item_add_subtree(item, ett_lustre_llog_cookie);
        proto_item_append_text(item, " [%d]", i);

        /* struct llog_cookie { */
        /*     struct llog_logid       lgc_lgl; */
        /*     __u32                   lgc_subsys; */
        /*     __u32                   lgc_index; */
        /*     __u32                   lgc_padding; */
        /* } */
        /* sizeof(llog_cookie) == 12 + 20 */
        offset = dissect_struct_llog_logid(tvb, offset, tree, hf_lustre_llog_cookie_lgc_lgl);
        proto_tree_add_item(tree, hf_lustre_llog_cookie_lgc_subsys, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_llog_cookie_lgc_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_llog_cookie_lgc_padding, tvb, offset, 4, ENC_NA);
        offset += 4;
    }

    return offset;
}

static int
dissect_struct_mdc_swap_layouts(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);

    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_mdc_swap_layouts, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mdc_swap_layouts);
    /* struct mdc_swap_layouts { */
    /*     __u64           msl_flags; */
    /* }   */

    proto_tree_add_item(tree, hf_lustre_mdc_swap_layouts_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_hsm_request(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_req, tvb, offset, 24, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_request);

    /* struct hsm_request { */
    /*     __u32 hr_action;    /\* enum hsm_user_action *\/ */
    /*     __u32 hr_archive_id;    /\* archive id, used only with HUA_ARCHIVE *\/ */
    /*     __u64 hr_flags;        /\* request flags *\/ */
    /*     __u32 hr_itemcount;    /\* item count in hur_user_item vector *\/ */
    /*     __u32 hr_data_len; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_hsm_req_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_req_archive_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_req_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_hsm_req_itemcount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_req_data_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_struct_hsm_extent(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_extent, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_extent);

    proto_tree_add_item(tree, hf_lustre_hsm_extent_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_hsm_extent_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_hsm_progress(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_prog, tvb, offset, 64, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_progress);
    /* struct hsm_progress_kernel { */
    /*     /\* Field taken from struct hsm_progress *\/ */
    /*     lustre_fid        hpk_fid; */
    /*     __u64            hpk_cookie; */
    /*     struct hsm_extent    hpk_extent; */
    /*     __u16            hpk_flags; */
    /*     __u16            hpk_errval; /\* positive val *\/ */
    /*     __u32            hpk_padding1; */
    /*     /\* Additional fields *\/ */
    /*     __u64            hpk_data_version; */
    /*     __u64            hpk_padding2; */
    /* } */

    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_hsm_prog_fid);
    proto_tree_add_item(tree, hf_lustre_hsm_prog_cookie, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    offset = dissect_struct_hsm_extent(tvb, offset, tree);
    proto_tree_add_item(tree, hf_lustre_hsm_prog_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_hsm_prog_errval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_hsm_prog_padding1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_prog_data_ver, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_hsm_prog_padding2, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_hsm_user_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    if (data_len < 32)
        expert_add_info_format(pinfo, parent_tree, &ei_lustre_buflen, "Buffer Length expected >= 32 length:%u", data_len);

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_user_state, tvb, offset, data_len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_user_state);
    /* struct hsm_user_state { */
    /*     /\** Current HSM states, from enum hsm_states. *\/ */
    /*     __u32            hus_states; */
    /*     __u32            hus_archive_id; */
    /*     /\**  The current undergoing action, if there is one *\/ */
    /*     __u32            hus_in_progress_state; */
    /*     __u32            hus_in_progress_action; */
    /*     struct hsm_extent    hus_in_progress_location; */
    /*     char            hus_extended_info[]; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_hsm_us_states, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_us_archive_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_us_in_prog_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_us_in_prog_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_struct_hsm_extent(tvb, offset, tree);

    data_len -= 32;
    if (data_len > 0) {
        proto_tree_add_item(tree, hf_lustre_hsm_us_ext_info, tvb, offset, data_len, ENC_NA);
        offset += data_len;
    }

    return offset;
}

static int
dissect_struct_hsm_state_set(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    if (data_len < 24)
        expert_add_info_format(pinfo, parent_tree, &ei_lustre_buflen,
                               "Buffer Length expected >= 24 length:%u", data_len);

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_state_set, tvb, offset, data_len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_state_set);
    /* struct hsm_state_set { */
    /* 	__u32	hss_valid; */
    /* 	__u32	hss_archive_id; */
    /* 	__u64	hss_setmask; */
    /* 	__u64	hss_clearmask; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_hsm_hss_valid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_hss_archive_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // both of the following are 64-bit ints, but hold a mask that is used with 32-bit ints
    // elsewhere
    proto_tree_add_item(tree, hf_lustre_hsm_hss_setmask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_hsm_hss_clearmask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_hsm_user_item_array(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct hsm_user_item { */
    /*     lustre_fid        hui_fid; */
    /*     struct hsm_extent hui_extent; */
    /* } */
    /* sizeof(hsm_user_item) == 16+16 */

    for (i = 0; i < data_len/32; ++i) {
        item = proto_tree_add_item(parent_tree, hf_lustre_hsm_user_item, tvb, offset, 32, ENC_NA);
        proto_item_append_text(item, " [%d]", i);
        tree = proto_item_add_subtree(item, ett_lustre_hsm_user_item);
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_hsm_user_item_fid);
        offset = dissect_struct_hsm_extent(tvb, offset, tree);
    }
    return offset;
}

static int
dissect_struct_hsm_current_action(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* 4+4+16 */
    /* struct hsm_current_action { */
    /*     /\**  The current undergoing action, if there is one *\/ */
    /*     /\* state is one of hsm_progress_states *\/ */
    /*     __u32			hca_state; */
    /*     /\* action is one of hsm_user_action *\/ */
    /*     __u32			hca_action; */
    /*     struct hsm_extent	hca_location; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_current_action, tvb, offset, 24, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_current_action);
    proto_tree_add_item(tree, hf_lustre_hsm_current_action_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_hsm_current_action_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_struct_hsm_extent(tvb, offset, tree);

    return offset;
}

static int
dissect_hsm_archive(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);

    item = proto_tree_add_item(parent_tree, hf_lustre_hsm_archive, tvb, offset, data_len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_hsm_archive);
    // @@ First item may be count for older clients c.f. lustre/mdt/mdt_hsm.c::mdt_hsm_ct_register()
    for (i = 0; i < data_len/4; ++i) {
        proto_tree_add_item(tree, hf_lustre_hsm_archive_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    offset = add_extra_padding(tvb, offset, NULL, tree);
    return offset;
}


/********************************************************************
 *
 * Out Buffer Structures
 *
 */

static int
dissect_struct_out_update_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree, *data_tree;
    proto_item *item;
    guint i, count, magic;
    gint old_offset, data_len;

    old_offset = offset;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct out_update_header { */
    /*     __u32        ouh_magic; */
    /*     __u32        ouh_count; */
    /*     __u32        ouh_inline_length; */
    /*     __u32        ouh_reply_size; */
    /*     __u32        ouh_inline_data[0]; */
    /* }; */
    /* SIZE = 20 + inline_length */

    item = proto_tree_add_item(parent_tree, hf_lustre_out_update_header, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_out_update_header);

    proto_tree_add_item_ret_uint(tree, hf_lustre_out_update_header_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN, &magic);
    offset += 4;
    if (magic != OUT_UPDATE_HEADER_MAGIC)
        expert_add_info(pinfo, tree, &ei_lustre_badmagic);
    proto_tree_add_item_ret_uint(tree, hf_lustre_out_update_header_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_out_update_header_inline_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_out_update_header_reply_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    item = proto_tree_add_item(tree, hf_lustre_out_update_header_inline_data, tvb, offset, -1, ENC_NA);
    data_tree = proto_item_add_subtree(item, ett_lustre_out_update_header_data);
    if (magic == OUT_UPDATE_HEADER_MAGIC) {
        /* ouh_inline_data -> array[ouh_count] of struct object_update_request */
        for (i = 0; i < count; ++i)
            offset = dissect_struct_object_update_request(tvb, offset, pinfo, tree);

        if (offset-old_offset != data_len)
            expert_add_info(pinfo, tree, &ei_lustre_buflen);
        proto_item_set_len(tree, offset-old_offset);

    } else {
        proto_item_set_len(data_tree, data_len-20);
        proto_item_set_len(tree, data_len);
    }

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);

    return offset;
}


static int
dissect_struct_out_update_buffer(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct out_update_buffer { */
    /*     __u32    oub_size; */
    /*     __u32    oub_padding; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_out_update_buffer, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_out_update_buffer);

    proto_tree_add_item(tree, hf_lustre_out_update_buffer_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_out_update_buffer_padding, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

static int
dissect_struct_obj_update_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i, magic, count;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* struct object_update_reply { */
    /*     __u32    ourp_magic; */
    /*     __u16    ourp_count; */
    /*     __u16    ourp_padding; */
    /*     __u16    ourp_lens[0]; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_obj_update_reply, tvb, offset, 8, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_obj_update_reply);

    /* @@ Check V1? */
    proto_tree_add_item_ret_uint(tree, hf_lustre_obj_update_reply_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN, &magic);
    if (magic != UPDATE_REPLY_MAGIC_V2) /* Currently (Lustre 2.10.2) the default */
        expert_add_info(pinfo, tree, &ei_lustre_badmagic);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_obj_update_reply_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &count);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_obj_update_reply_padding, tvb, offset, 2, ENC_NA);
    offset += 2;

    for (i = 0; i < count; ++i) {
        item = proto_tree_add_item(tree, hf_lustre_obj_update_reply_lens, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_append_text(item, " [%d]", i);
        offset += 2;
    }

    return offset;
}


/********************************************************************
 *
 * I/O Buffer Structures
 *
 */

static int
dissect_struct_obd_ioobj(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);

    /* struct obd_ioobj { */
    /*     uint64 ioo_id; */
    /*     uint64 ioo_seq; */
    /*     uint32 ioo_max_brw; */
    /*     uint32 ioo_bufcnt; */
    /* } */
    /* sizeof(struct obd_ioobj) == 24 */

    for (i = 0; i < data_len/24; ++i) {
        item = proto_tree_add_item(parent_tree, hf_lustre_obd_ioobj,  tvb, offset, 24, ENC_NA);
        proto_item_append_text(item, " [%d]", i);
        tree = proto_item_add_subtree(item, ett_lustre_obd_ioobj);
        proto_tree_add_item(tree, hf_lustre_obd_ioobj_ioo_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_obd_ioobj_ioo_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_obd_ioobj_ioo_max_brw, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_obd_ioobj_ioo_bufcnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    return offset;
}

static int
dissect_struct_niobuf_remote(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);

    /* struct niobuf_remote { */
    /*     __u64    rnb_offset; */
    /*     __u32    rnb_len; */
    /*     __u32    rnb_flags; */
    /* }; */
    /* sizeof(struct niobuf_remote) == 16 */

    for (i = 0; i < data_len/16; ++i) {
        item = proto_tree_add_item(parent_tree, hf_lustre_niobuf_remote, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, " [%d]", i);
        tree = proto_item_add_subtree(item, ett_lustre_niobuf_remote);
        proto_tree_add_item(tree, hf_lustre_niobuf_remote_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(tree, hf_lustre_niobuf_remote_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_niobuf_remote_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);
    return offset;
}

static int
dissect_rc_array(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i;

    data_len = LUSTRE_BUFFER_LEN(buf_num);

    item = proto_tree_add_item(parent_tree, hf_lustre_rcs, tvb, offset, data_len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_rcs);
    for (i = 0; i < data_len/4; ++i) {
        proto_tree_add_item(tree, hf_lustre_rcs_rc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    offset = add_extra_padding(tvb, offset, pinfo, tree);
    return offset;
}

static int
dissect_struct_fid_array(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len, i, num;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_fid_array, tvb, offset, data_len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_fid_array);

    num = data_len/16;
    for (i = 0; i < num; ++i) {
        offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_fid_array_fid);
    }

    offset = add_extra_padding(tvb, offset, pinfo, tree);
    return offset;
}

static int
dissect_struct_quota_body(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_quota_body, tvb, offset, 104, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_quota_body);

    /* struct quota_body { */
    /*     struct lu_fid    qb_fid;     /\* FID of global index packing the pool ID */
    /*                                  * and type (data or metadata) as well as */
    /*                                  * the quota type (user or group). *\/ */
    /*     union lquota_id    qb_id;      /\* uid or gid or directory FID *\/ */
    /*     __u32        qb_flags;   /\* see below *\/ */
    /*     __u32        qb_padding; */
    /*     __u64        qb_count;   /\* acquire/release count (kbytes/inodes) *\/ */
    /*     __u64        qb_usage;   /\* current slave usage (kbytes/inodes) *\/ */
    /*     __u64        qb_slv_ver; /\* slave index file version *\/ */
    /*     struct lustre_handle    qb_lockh;     /\* per-ID lock handle *\/ */
    /*     struct lustre_handle    qb_glb_lockh; /\* global lock handle *\/ */
    /*     __u64        qb_padding1[4]; */
    /* }; */

    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_qb_fid);
    offset = dissect_struct_lquota_id(tvb, offset, tree);
    // @@ Add parsing QUOTA_DQACQ_FL_*
    proto_tree_add_item(tree, hf_lustre_qb_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_qb_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_qb_count, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_qb_usage, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_qb_slv_ver, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_qb_lockh);
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_qb_glb_lockh);
    proto_tree_add_item(tree, hf_lustre_qb_padding, tvb, offset, 32, ENC_NA);
    offset += 32;

    return offset;
}

static int
dissect_struct_obd_quotactl(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree, *sub_tree;
    proto_item *item;

    item = proto_tree_add_item(parent_tree, hf_lustre_obd_quotactl, tvb, offset, 112, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_obd_quotactl);

    /* struct obd_quotactl { */
    /*     __u32            qc_cmd; */
    /*     __u32            qc_type; /\* see Q_* flag below *\/ */
    /*     __u32            qc_id; */
    /*     __u32            qc_stat; */
    /*     struct obd_dqinfo    qc_dqinfo; */
    /*     struct obd_dqblk    qc_dqblk; */
    /* sizeof(obd_quotactl) == 16 + 24 + 72 */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_obd_quotactl_qc_cmd, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_quotactl_qc_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_quotactl_qc_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_quotactl_qc_stat, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    item = proto_tree_add_item(parent_tree, hf_lustre_obd_dqinfo, tvb, offset, 24, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_lustre_obd_dqinfo);
    /* struct obd_dqinfo { */
    /*     __u64 dqi_bgrace; */
    /*     __u64 dqi_igrace; */
    /*     __u32 dqi_flags; */
    /*     __u32 dqi_valid; */
    /* }; */

    proto_tree_add_item(sub_tree, hf_lustre_obd_dqinfo_dqi_bgrace, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqinfo_dqi_igrace, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqinfo_dqi_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqinfo_dqi_valid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    item = proto_tree_add_item(parent_tree, hf_lustre_obd_dqblk, tvb, offset, 72, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_lustre_obd_dqblk);
    /* struct obd_dqblk { */
    /*     __u64 dqb_bhardlimit; */
    /*     __u64 dqb_bsoftlimit; */
    /*     __u64 dqb_curspace; */
    /*     __u64 dqb_ihardlimit; */
    /*     __u64 dqb_isoftlimit; */
    /*     __u64 dqb_curinodes; */
    /*     __u64 dqb_btime; */
    /*     __u64 dqb_itime; */
    /*     __u32 dqb_valid; */
    /*     __u32 dqb_padding; */
    /* }; */
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_bhardlimit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_bsoftlimit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_curspace, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_ihardlimit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_isoftlimit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_curinodes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_btime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_itime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_dqb_valid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(sub_tree, hf_lustre_obd_dqblk_padding, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

static int
dissect_struct_lu_ladvise_hdr(tvbuff_t *tvb, int offset,  packet_info *pinfo, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    guint32 val;

    /* struct ladvise_hdr { */
    /*     __u32            lah_magic;    /\* LADVISE_MAGIC *\/ */
    /*     __u32            lah_count;    /\* number of advices *\/ */
    /*     __u64            lah_flags;    /\* from enum ladvise_flag *\/ */
    /*     __u32            lah_value1;    /\* unused *\/ */
    /*     __u32            lah_value2;    /\* unused *\/ */
    /*     __u64            lah_value3;    /\* unused *\/ */
    /*     struct lu_ladvise    lah_advise[0];    /\* advices in this header *\/ */
    /* sizeof(ladvise_hdr) == 32 */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_lu_ladvise_hdr, tvb, offset, 32, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ladvise_hdr);

    proto_tree_add_item_ret_uint(tree, hf_lustre_lu_ladvise_hdr_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN, &val);
    offset += 4;
    if (val != LADVISE_MAGIC)
        expert_add_info(pinfo, tree, &ei_lustre_badmagic);
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_hdr_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_hdr_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_hdr_value1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_hdr_value2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_hdr_value3, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_lu_ladvise(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;

    /* struct ladvise { */
    /* __u16 lla_advice;    /\* advice type *\/ */
    /* __u16 lla_value1;    /\* values for different advice types *\/ */
    /* __u32 lla_value2; */
    /* __u64 lla_start;    /\* first byte of extent for advice *\/ */
    /* __u64 lla_end;        /\* last byte of extent for advice *\/ */
    /* __u32 lla_value3; */
    /* __u32 lla_value4; */
    /* sizeof(ladvise) == 32 */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_lu_ladvise, tvb, offset, 32, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ladvise);

    proto_tree_add_item(tree, hf_lustre_lu_ladvise_advice, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_value1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_value2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_value3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lu_ladvise_value4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}



/********************************************************************   \
 *
 * Main Buffer Structures
 *
\********************************************************************/

/**
 * Decode struct ptlrpc and return opcode and pb_type to caller,
 * because they're needed to dissect further buffers.
 */
static int
dissect_struct_ptlrpc_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gint offset, guint buf_len,
                           lustre_trans_t *trans, guint32 *pb_type)
{
    proto_tree *tree;
    proto_item *item;
    guint32 pb_version, opcode, i, old_offset;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_ptlrpc_body_pb, tvb, offset,  -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ptlrpc_body);

    /* struct ptlrpc_body { */
    /*   struct lustre_handle { */
    /* } pb_handle; */
    /*   uint32 pb_type; */
    /*   uint32 pb_version; */
    /*   uint32 pb_opc; */
    /*   uint32 pb_status; */
    /*   uint64 pb_last_xid; */
    /*   uint64 pb_last_seen; */
    /*   uint64 pb_last_committed; */
    /*   uint64 pb_transno; */
    /*   uint32 pb_flags; */
    /*   uint32 pb_op_flags; */
    /*   uint32 pb_conn_cnt; */
    /*   uint32 pb_timeout; */
    /*   uint32 pb_service_time; */
    /*   uint32 pb_limit; */
    /*   uint64 pb_slv; */
    /* } */
    /* SIZE == 8+80 */

    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_ptlrpc_body_pb_handle);

    proto_tree_add_item_ret_uint(tree, hf_lustre_ptlrpc_body_pb_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, pb_type);
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_lustre_ptlrpc_body_pb_version, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pb_version);
    pb_version &= ~LUSTRE_VERSION_MASK;
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_lustre_ptlrpc_body_pb_opc, tvb, offset, 4, ENC_LITTLE_ENDIAN, &opcode);
    offset += 4;
    if (*pb_type == PTL_RPC_MSG_REQUEST)
        trans->opcode = opcode;
    else if (trans->opcode != opcode) {
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "Mismatched: PTLRPC:%s != Conversation:%s (match_bits:%" PRIx64 ")",
                               val_to_str(opcode, lustre_op_codes, "Unknown(%d)"),
                               val_to_str(trans->opcode, lustre_op_codes, "Unknown(%d)"), trans->match_bits);
        trans->opcode = opcode;
    }

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_last_xid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_last_seen, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_last_committed, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_transno, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_op_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_conn_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_service_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_limit, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_slv, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* pb_pre_versions */
    for(i = 0; i < 4; ++i) {
        proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_pre_version, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_padding, tvb, offset, 32, ENC_NA);
    offset += 32;

    if (pb_version == LUSTRE_PTLRPC_MSG_VERSION && offset-old_offset < buf_len) {
        /* the length of the string is 32 bytes max, with \0 inside */
        proto_tree_add_item(tree, hf_lustre_ptlrpc_body_pb_jobid, tvb, offset, 32, ENC_ASCII);
        offset+=32;
    }

    /*
    if (offset-old_offset != buf_len)
        expert_add_info(pinfo, , &ei_lustre_buflen);
    */
    proto_item_set_len(item, offset-old_offset);

    /* Add Opcode and PB Type to info lines */
    proto_item_append_text(parent_tree, "%s %s ", val_to_str(opcode, lustre_op_codes, "Unknown(%d)"),
                      val_to_str(*pb_type, lustre_LMTypes, "Unknown(%d)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s ", val_to_str(opcode, lustre_op_codes, "Unknown(%d)"),
                      val_to_str(*pb_type, lustre_LMTypes, "Unknown(%d)"));

    //sanity_check(tvb, pinfo, offset-old_offset);
    return offset;
}

static int
dissect_struct_ost_lvb(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_ost_lvb, tvb, offset, 56, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ost_lvb);

    /* struct ost_lvb { */
    /*     __u64    lvb_size; */
    /*     __s64    lvb_mtime; */
    /*     __s64    lvb_atime; */
    /*     __s64    lvb_ctime; */
    /*     __u64    lvb_blocks; */
    /*     __u32    lvb_mtime_ns; */
    /*     __u32    lvb_atime_ns; */
    /*     __u32    lvb_ctime_ns; */
    /*     __u32    lvb_padding; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_ost_lvb_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_mtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_atime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_ctime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_mtime_ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_atime_ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_ctime_ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_ost_lvb_padding, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

static int
dissect_struct_capa(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    /* struct lustre_capa { */
    /*     struct lu_fid   lc_fid;         /\** fid *\/ */
    /*     __u64           lc_opc;         /\** operations allowed *\/ */
    /*     __u64           lc_uid;         /\** file owner *\/ */
    /*     __u64           lc_gid;         /\** file group *\/ */
    /*     __u32           lc_flags;       /\** HMAC algorithm & flags *\/ */
    /*     __u32           lc_keyid;       /\** key# used for the capability *\/ */
    /*     __u32           lc_timeout;     /\** capa timeout value (sec) *\/ */
    /*     __u32           lc_expiry;      /\** expiry time (sec) *\/ */
    /*     __u8            lc_hmac[CAPA_HMAC_MAX_LEN];   /\** HMAC *\/ */
    /* }    old_offset = offset; */

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_capa, tvb, offset, 120, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_capa);

    offset = dissect_struct_lu_fid(tvb, offset,tree, hf_lustre_capa_fid);
    proto_tree_add_item(tree, hf_lustre_capa_opc, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_capa_uid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_capa_gid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_capa_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_capa_keyid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_capa_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_capa_expiry, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* CAPA_HMAC_MAX_LEN == 64 */
    proto_tree_add_item(tree, hf_lustre_capa_hmac, tvb, offset, 64, ENC_NA);
    offset += 64;

    return offset;
}

static int
dissect_struct_llogd_body(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;
    static int * const flags[] = {
        &hf_lustre_llog_hdr_flag_zap_when_empty,
        &hf_lustre_llog_hdr_flag_is_cat,
        &hf_lustre_llog_hdr_flag_is_plain,
        &hf_lustre_llog_hdr_flag_ext_jobid,
        &hf_lustre_llog_hdr_flag_is_fixsize,
        NULL
    };

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_llogd_body, tvb, offset, 48, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llogd_body);

    /* struct llogd_body { */
    /*     struct llog_logid  lgd_logid; */
    /*     __u32 lgd_ctxt_idx; */
    /*     __u32 lgd_llh_flags; */
    /*     __u32 lgd_index; */
    /*     __u32 lgd_saved_index; */
    /*     __u32 lgd_len; */
    /*     __u64 lgd_cur_offset; */
    /* } */
    /* SIZE = 20+28 */

    offset = dissect_struct_llog_logid(tvb, offset, tree, hf_lustre_llogd_body_lgd_logid);
    proto_tree_add_item(tree, hf_lustre_llogd_body_lgd_ctxt_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_lustre_llogd_body_lgd_llh_flags, ett_lustre_llog_hdr_flags, flags, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llogd_body_lgd_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llogd_body_lgd_saved_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llogd_body_lgd_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llogd_body_lgd_cur_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_llogd_conn_body(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_llogd_conn_body, tvb, offset, 40, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llogd_conn_body);

    /* struct llogd_conn_body { */
    /*         struct llog_gen         lgdc_gen; */
    /*         struct llog_logid       lgdc_logid; */
    /*         __u32                   lgdc_ctxt_idx; */
    /* } */
    /* SIZE == 16+20+4 */

    offset = dissect_struct_llog_gen(tvb, offset, tree, hf_lustre_llogd_conn_body_lgdc_gen);
    offset = dissect_struct_llog_logid(tvb, offset, tree, hf_lustre_llogd_conn_body_lgdc_logid);
    proto_tree_add_item(tree, hf_lustre_llogd_conn_body_lgdc_ctxt_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_struct_llog_log_hdr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint32 len, data_len, old_offset, i;

    static int * const flags[] = {
        &hf_lustre_llog_hdr_flag_zap_when_empty,
        &hf_lustre_llog_hdr_flag_is_cat,
        &hf_lustre_llog_hdr_flag_is_plain,
        &hf_lustre_llog_hdr_flag_ext_jobid,
        &hf_lustre_llog_hdr_flag_is_fixsize,
        NULL
    };

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_llog_log_hdr, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_llog_log_hdr);

    /* struct llog_log_hdr { */
    /*     struct llog_rec_hdr    llh_hdr; */
    /*     __s64            llh_timestamp; */
    /*     __u32            llh_count; */
    /*     __u32            llh_bitmap_offset; */
    /*     __u32            llh_size; */
    /*     __u32            llh_flags; */
    /*     /\* for a catalog the first/oldest and still in-use plain slot is just */
    /*      * next to it. It will serve as the upper limit after Catalog has */
    /*      * wrapped around *\/ */
    /*     __u32            llh_cat_idx; */
    /*     struct obd_uuid        llh_tgtuuid; */
    /*     __u32            llh_reserved[LLOG_HEADER_SIZE/sizeof(__u32)-23]; */
    /*     /\* These fields must always be at the end of the llog_log_hdr. */
    /*      * Note: llh_bitmap size is variable because llog chunk size could be */
    /*      * bigger than LLOG_MIN_CHUNK_SIZE, i.e. sizeof(llog_log_hdr) > 8192 */
    /*      * bytes, and the real size is stored in llh_hdr.lrh_len, which means */
    /*      * llh_tail should only be refered by LLOG_HDR_TAIL(). */
    /*      * But this structure is also used by client/server llog interface */
    /*      * (see llog_client.c), it will be kept in its original way to avoid */
    /*      * compatiblity issue. *\/ */
    /*     __u32            llh_bitmap[LLOG_BITMAP_BYTES / sizeof(__u32)]; */
    /*     struct llog_rec_tail    llh_tail; */
    /* } */
    /* sizeof(llh_reserved) == 1*sizeof(uint32) */
    /* Size = 16+28+40+1+?+8 */

    /* llog_rec_hdr.lrh_len is first */
    len = tvb_get_letohl(tvb, offset);
    if (data_len != len)
        expert_add_info_format(pinfo, tree, &ei_lustre_buflen,
                               "Buffer Length mismatch: buffer:%u !== internal length:%u", data_len, len);

    offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_log_hdr_hdr);
    proto_tree_add_item(tree, hf_lustre_llog_log_hdr_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_llog_log_hdr_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llog_log_hdr_bitmap_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llog_log_hdr_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_lustre_llog_log_hdr_flags, ett_lustre_llog_hdr_flags, flags, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_llog_log_hdr_cat_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_struct_obd_uuid(tvb, offset, tree, hf_lustre_llog_log_hdr_tgtuuid);
    proto_tree_add_item(tree, hf_lustre_llog_log_hdr_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    /* bitmap size is llh_hdr.lrh_len - current offset - sizeof(llog_rec_tail) */
    len -= (offset - old_offset) + 8;
    for (i = 0; i < len/4; ++i) {
        proto_tree_add_item(tree, hf_lustre_llog_log_hdr_bitmap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_log_hdr_tail);
    proto_item_set_len(tree, offset-old_offset);
    return offset;
}

static int
dissect_struct_idx_info(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_idx_info, tvb, offset, 80, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_idx_info);

    /* struct idx_info { */
    /*     __u32        ii_magic; */
    /*     /\* reply: see idx_info_flags below *\/ */
    /*     __u32        ii_flags; */
    /*     __u16        ii_count; */
    /*     __u16        ii_pad0; */
    /*     __u32        ii_attrs; */
    /*     /\* request & reply: index file identifier (FID) *\/ */
    /*     struct lu_fid    ii_fid; */
    /*     /\* reply: version of the index file before starting to walk the index. */
    /*      * Please note that the version can be modified at any time during the */
    /*      * transfer *\/ */
    /*     __u64        ii_version; */
    /*     /\* request: hash to start with: */
    /*      * reply: hash of the first entry of the first lu_idxpage and hash */
    /*      *        of the entry to read next if any *\/ */
    /*     __u64        ii_hash_start; */
    /*     __u64        ii_hash_end; */
    /*     /\* reply: size of keys in lu_idxpages, minimal one if II_FL_VARKEY is */
    /*      * set *\/ */
    /*     __u16        ii_keysize; */
    /*     /\* reply: size of records in lu_idxpages, minimal one if II_FL_VARREC */
    /*      * is set *\/ */
    /*     __u16        ii_recsize; */
    /*     __u32        ii_pad1; */
    /*     __u64        ii_pad2; */
    /*     __u64        ii_pad3; */
    /* }; */
    /* SIZE = 64+16 */

    proto_tree_add_item(tree, hf_lustre_idx_info_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_idx_info_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_idx_info_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_idx_info_padding, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_idx_info_attrs, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_struct_lu_fid(tvb, offset,tree, hf_lustre_idx_info_fid);
    proto_tree_add_item(tree, hf_lustre_idx_info_hash_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_idx_info_hash_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_idx_info_keysize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_idx_info_recsize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_idx_info_padding, tvb, offset, 12, ENC_NA);
    offset += 12;

    return offset;
}

static int
dissect_struct_ldlm_intent(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *parent_tree, lustre_trans_t *trans, guint32 buf_num)
{
    //proto_tree *tree;
    guint32 data_len;

    static int * const flags[] = {
         &hf_lustre_ldlm_intent_opc_open,
         &hf_lustre_ldlm_intent_opc_creat,
         &hf_lustre_ldlm_intent_opc_readdir,
         &hf_lustre_ldlm_intent_opc_getattr,
         &hf_lustre_ldlm_intent_opc_lookup,
         &hf_lustre_ldlm_intent_opc_unlink,
         &hf_lustre_ldlm_intent_opc_trunc,
         &hf_lustre_ldlm_intent_opc_getxattr,
         &hf_lustre_ldlm_intent_opc_exec,
         &hf_lustre_ldlm_intent_opc_pin,
         &hf_lustre_ldlm_intent_opc_layout,
         &hf_lustre_ldlm_intent_opc_q_dqacq,
         &hf_lustre_ldlm_intent_opc_q_conn,
         &hf_lustre_ldlm_intent_opc_setxattr,
         NULL
    };

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    if (data_len != 8)
        expert_add_info(pinfo, parent_tree, &ei_lustre_buflen);

    trans->sub_opcode = tvb_get_letoh64(tvb, offset);
    proto_tree_add_bitmask(parent_tree, tvb, offset, hf_lustre_ldlm_intent_opc, ett_lustre_ldlm_intent_opc, flags, ENC_LITTLE_ENDIAN);
    offset += 8;

    col_append_fstr(pinfo->cinfo, COL_INFO, "[ intent:");
    if (trans->sub_opcode & IT_OPEN    )
        col_append_fstr(pinfo->cinfo, COL_INFO, " open");
    if (trans->sub_opcode & IT_CREAT   )
        col_append_fstr(pinfo->cinfo, COL_INFO, " create");
    if (trans->sub_opcode & IT_READDIR )
        col_append_fstr(pinfo->cinfo, COL_INFO, " readdir");
    if (trans->sub_opcode & IT_GETATTR )
        col_append_fstr(pinfo->cinfo, COL_INFO, " getattr");
    if (trans->sub_opcode & IT_LOOKUP  )
        col_append_fstr(pinfo->cinfo, COL_INFO, " lookup");
    if (trans->sub_opcode & IT_UNLINK  )
        col_append_fstr(pinfo->cinfo, COL_INFO, " unlink");
    if (trans->sub_opcode & IT_TRUNC   )
        col_append_fstr(pinfo->cinfo, COL_INFO, " trunc");
    if (trans->sub_opcode & IT_GETXATTR)
        col_append_fstr(pinfo->cinfo, COL_INFO, " getxattr");
    if (trans->sub_opcode & IT_EXEC    )
        col_append_fstr(pinfo->cinfo, COL_INFO, " exec");
    if (trans->sub_opcode & IT_PIN     )
        col_append_fstr(pinfo->cinfo, COL_INFO, " pin");
    if (trans->sub_opcode & IT_LAYOUT  )
        col_append_fstr(pinfo->cinfo, COL_INFO, " layout");
    if (trans->sub_opcode & IT_QUOTA_DQACQ)
        col_append_fstr(pinfo->cinfo, COL_INFO, " quota_dqacq");
    if (trans->sub_opcode & IT_QUOTA_CONN )
        col_append_fstr(pinfo->cinfo, COL_INFO, " quota_conn");
    if (trans->sub_opcode & IT_SETXATTR   )
        col_append_fstr(pinfo->cinfo, COL_INFO, " setxattr");
    col_append_fstr(pinfo->cinfo, COL_INFO, " ] ");

    return offset;
}

static int
dissect_struct_quota_adjust_qunit(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_quota_adjust_qunit, tvb, offset, 32, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_quota_adjust_qunit);

    /* struct quota_adjust_qunit { */
    /*     __u32 qaq_flags; */
    /*     __u32 qaq_id; */
    /*     __u64 qaq_bunit_sz; */
    /*     __u64 qaq_iunit_sz; */
    /*     __u64 padding1; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_quota_adjust_qunit_qaq_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_quota_adjust_qunit_qaq_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_quota_adjust_qunit_qaq_bunit_sz, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_quota_adjust_qunit_qaq_iunit_sz, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_quota_adjust_qunit_padding1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_xattr_buffers(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree, guint32 buff_num)
{
    /* ldlm_intent_getxattr_server : [eadata][eavals][eavals_lens] *
     * array length == sizeof(eavals_lens)/sizeof(uint32)
     * Buff 1: NAME - array of strings (name of xattr)
     * Buff 2: DATA - array of data (data of xattr)
     * Buff 3: LEN  - array of data lengths (in buff 2)
     */
    int count, i;
    int namestart, namelen, datastart, datalen, lenstart, lenlen;
    int nameoffset, dataoffset, lenoffset;
    proto_tree *tree, *xattr_tree;
    proto_item *item;

    namelen = LUSTRE_BUFFER_LEN(buff_num);
    datalen = LUSTRE_BUFFER_LEN(buff_num+1);
    lenlen = LUSTRE_BUFFER_LEN(buff_num+2);

    count = lenlen / 4;

    namestart = nameoffset = offset;
    datastart = namestart + namelen;
    datastart += buffer_padding_length(datastart);
    dataoffset = datastart;
    lenstart = datastart + datalen;
    lenstart += buffer_padding_length(lenstart);
    lenoffset = lenstart;

    item = proto_tree_add_item(parent_tree, hf_lustre_xattr_list, tvb, offset, -1, ENC_NA);
    xattr_tree = proto_item_add_subtree(item, ett_lustre_xattrs);

    offset = display_buffer_data(tvb, pinfo, offset, xattr_tree, buff_num, "NAMES");
    offset = display_buffer_data(tvb, pinfo, offset, xattr_tree, buff_num+1, "DATA");
    offset = display_buffer_data(tvb, pinfo, offset, xattr_tree, buff_num+2, "LENS");

    for (i = 0; i < count; ++i) {
        int namesize;
        int datasize;

        datasize = tvb_get_letohl(tvb, lenoffset);

        namesize = tvb_strnlen(tvb, nameoffset, namelen - (nameoffset - namestart))+1;

        item = proto_tree_add_item(xattr_tree, hf_lustre_xattr, tvb, nameoffset, namesize, ENC_NA);
        tree = proto_item_add_subtree(item, ett_lustre_xattr_item);

        //@@ Add name to text
        proto_item_append_text(item, " [%d]", i);
        proto_tree_add_item(tree, hf_lustre_xattr_name, tvb, nameoffset, namesize, ENC_ASCII);
        nameoffset += namesize;

        proto_tree_add_item(tree, hf_lustre_xattr_data, tvb, dataoffset, datasize, ENC_NA);
        dataoffset += datasize;

        proto_tree_add_item(tree, hf_lustre_xattr_size, tvb, lenoffset, 4, ENC_LITTLE_ENDIAN);
        lenoffset += 4;
    }

    offset += buffer_padding_length(offset);
    proto_item_set_len(xattr_tree, offset-namestart);
    return offset;
}

static int
dissect_struct_barrier_lvb(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_barrier_lvb, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_barrier_lvb);

    /* struct barrier_lvb { */
    /*     __u32        lvb_status; */
    /*     __u32        lvb_index; */
    /*     __u64        lvb_padding; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_barrier_lvb_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_barrier_lvb_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_barrier_lvb_padding, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int
dissect_struct_eadata(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *parent_tree, guint32 buf_num)
{
    guint32 data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    proto_tree_add_item(parent_tree, hf_lustre_eadata, tvb, offset, data_len, ENC_NA);
    offset += data_len;

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);

    return offset;
}

static int
dissect_struct_layout_intent(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint32 data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_layout_intent, tvb, offset, 24, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_layout_intent);

    if (data_len != 24)
        expert_add_info_format(pinfo, tree, &ei_lustre_buflen,
                               "Buffer Length mismatch: expected:24 !== length:%u", data_len);

    /* struct layout_intent { */
    /*     __u32 li_opc;    /\* intent operation for enqueue, read, write etc *\/ */
    /*     __u32 li_flags; */
    /*     __u64 li_start; */
    /*     __u64 li_end; */
    /* } */
    proto_tree_add_item(tree, hf_lustre_layout_intent_opc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_layout_intent_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_layout_intent_start, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_layout_intent_end, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_ost_body(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    gint old_offset;

    old_offset = offset;

    /* struct ost_body { */
    /*     struct obdo oa; */
    /* }; */

    item = proto_tree_add_item(parent_tree, hf_lustre_ost_body, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_ost_body);

    offset = dissect_struct_obdo(tvb, offset, tree);

    proto_item_set_len(tree, offset-old_offset);
    return offset;
}

static int
dissect_struct_mdt_body(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint32 data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_mdt_body, tvb, offset, 216, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_mdt_body);
    /* struct mdt_body { */
    /*     struct lu_fid { */
    /* } fid1; */
    /*     struct lu_fid { */
    /* } fid2; */
    /*     struct lustre_handle { */
    /* } handle; */
    /*     uint64 valid; */
    /*     uint64 size; */
    /*     uint64 mtime; */
    /*     uint64 atime; */
    /*     uint64 ctime; */
    /*     uint64 blocks; */
    /*     uint64 ioepoch; */
    /*     uint64 ino; */
    /*     uint32 fsuid; */
    /*     uint32 fsgid; */
    /*     uint32 capability; */
    /*     uint32 mode; */
    /*     uint32 uid; */
    /*     uint32 gid; */
    /*     uint32 flags; */
    /*     uint32 rdev; */
    /*     uint32 nlink; */
    /*     uint32 generation; */
    /*     uint32 suppgid; */
    /*     uint32 eadatasize; */
    /*     uint32 aclsize; */
    /*     uint32 max_mdsize; */
    /*     uint32 max_cookiesize; */
    /*     uint32 uid_h; */
    /*     uint32 gid_h; */
    /*     uint32 padding_5; */
    /*     uint64 padding_6; */
    /*     uint64 padding_7; */
    /*     uint64 padding_8; */
    /*     uint64 padding_9; */
    /*     uint64 padding_10; */
    /* } */

    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_mdt_body_fid1);
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_mdt_body_fid2);
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_mdt_body_handle);
    // @@ make into bitmap of OBD_MD_FL*
    proto_tree_add_item(tree, hf_lustre_mdt_body_valid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_mtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_atime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_ctime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_ioepoch, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_ino, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_fsuid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_fsgid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_capability, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_rdev, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_nlink, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_generation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_suppgid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_eadatasize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_aclsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_max_mdsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_max_cookiesize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_uid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_gid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_padding_5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_mdt_body_padding_6, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_padding_7, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_padding_8, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_padding_9, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_mdt_body_padding_10, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_struct_obd_statfs(tvbuff_t *tvb, gint offset, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    guint32 i;

    item = proto_tree_add_item(parent_tree, hf_lustre_obd_statfs, tvb, offset, 144, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_obd_statfs);

    /* struct obd_statfs { */
    /*     __u64           os_type; */
    /*     __u64           os_blocks; */
    /*     __u64           os_bfree; */
    /*     __u64           os_bavail; */
    /*     __u64           os_files; */
    /*     __u64           os_ffree; */
    /*     __u8            os_fsid[40]; */
    /*     __u32           os_bsize; */
    /*     __u32           os_namelen; */
    /*     __u64           os_maxbytes; */
    /*     __u32           os_state;       /\**< obd_statfs_state OS_STATE_* flag *\/ */
    /*     __u32           os_fprecreated;     */
    /*     __u32           os_spare2; */
    /*     __u32           os_spare3; */
    /*     __u32           os_spare4; */
    /*     __u32           os_spare5; */
    /*     __u32           os_spare6; */
    /*     __u32           os_spare7; */
    /*     __u32           os_spare8; */
    /*     __u32           os_spare9; */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_type, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_blocks, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_bfree, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_bavail, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_files, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_ffree, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_fsid, tvb, offset, 40, ENC_ASCII);
    offset += 40;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_bsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_namelen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_maxbytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_statfs_os_fprecreated, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    for (i = 2; i <= 9; ++i) {
        proto_tree_add_item(tree, hf_lustre_obd_statfs_os_spare, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    return offset;
}

static int
dissect_struct_obd_connect_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *item;
    guint32 version;
    gint old_offset, len;

    old_offset = offset;
    item = proto_tree_add_item(parent_tree, hf_lustre_obd_connect_data, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_obd_connect_data);

    /* struct obd_connect_data { */
    /*     __u64 ocd_connect_flags; /\* OBD_CONNECT_* per above *\/ */
    /*     __u32 ocd_version;     /\* lustre release version number *\/ */
    /*     __u32 ocd_grant;     /\* initial cache grant amount (bytes) *\/ */
    /*     __u32 ocd_index;     /\* LOV index to connect to *\/ */
    /*     __u32 ocd_brw_size;     /\* Maximum BRW size in bytes *\/ */
    /*     __u64 ocd_ibits_known;   /\* inode bits this client understands *\/ */
    /*     __u8  ocd_grant_blkbits; /\* log2 of the backend filesystem blocksize *\/ */
    /*     __u8  ocd_grant_inobits; /\* log2 of the per-inode space consumption *\/ */
    /*     __u16 ocd_grant_tax_kb;  /\* extent insertion overhead, in 1K blocks *\/ */
    /*     __u32 ocd_grant_max_blks;/\* maximum number of blocks per extent *\/ */
    /*     __u64 ocd_transno;       /\* first transno from client to be replayed *\/ */
    /*     __u32 ocd_group;         /\* MDS group on OST *\/ */
    /*     __u32 ocd_cksum_types;   /\* supported checksum algorithms *\/ */
    /*     __u32 ocd_max_easize;    /\* How big LOV EA can be on MDS *\/ */
    /*     __u32 ocd_instance;      /\* instance # of this target *\/ */
    /*     __u64 ocd_maxbytes;      /\* Maximum stripe size in bytes *\/ */
    /*     /\* Fields after ocd_maxbytes are only accessible by the receiver */
    /*      * if the corresponding flag in ocd_connect_flags is set. Accessing */
    /*      * any field after ocd_maxbytes on the receiver without a valid flag */
    /*      * may result in out-of-bound memory access and kernel oops. *\/ */
    /*     __u16 ocd_maxmodrpcs;    /\* Maximum modify RPCs in parallel *\/ */
    /*     __u16 padding0;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u32 padding1;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 ocd_connect_flags2; */
    /*     __u64 padding3;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 padding4;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 padding5;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 padding6;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 padding7;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 padding8;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 padding9;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 paddingA;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 paddingB;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 paddingC;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 paddingD;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 paddingE;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /*     __u64 paddingF;          /\* added 2.1.0. also fix lustre_swab_connect *\/ */
    /* }; */

    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_connect_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item_ret_uint(tree, hf_lustre_obd_connect_data_ocd_version, tvb, offset, 4, ENC_LITTLE_ENDIAN, &version);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_brw_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_ibits_known, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    if (version < 0x02013900) { /* changed between 2.1.56 and 2.1.57 (a pre 2.2 tag) */
        /* uint32 ocd_nllu; */
        /* uint32 ocd_nllg; */
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_nllu, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_nllg, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    } else if (version < 0x02083300) { /* changed for 2.8.51 */
        /* __u8  ocd_blocksize;     /\* log2 of the backend filesystem blocksize *\/ */
        /* __u8  ocd_inodespace;    /\* log2 of the per-inode space consumption *\/ */
        /* __u16 ocd_grant_extent;  /\* per-extent grant overhead, in 1K blocks *\/ */
        /* __u32 ocd_unused;        /\* also fix lustre_swab_connect *\/ */
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_blkbits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_inobits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_tax_kb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_padding, tvb, offset, 4, ENC_NA);
        offset += 4;

    } else {
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_blkbits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_inobits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_tax_kb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_grant_max_blks, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_transno, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_group, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_cksum_types, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* the following show up in 2.1.0, 2.2.0, and 2.1.0 respectively */
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_max_easize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_instance, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_maxbytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    /* Rest of fields were added in 2.1.0 */
    if (version >= 0x02010000) {
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_maxmodrpcs, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_padding, tvb, offset, 6, ENC_NA);
        offset += 6;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_connect_flags2, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        // Padding runs padding3 through paddingF
        len = (0x10-3)*8;
        proto_tree_add_item(tree, hf_lustre_obd_connect_data_ocd_padding, tvb, offset, len, ENC_NA);
        offset += len;
    }

     proto_item_set_len(item, offset-old_offset);
     return offset;
}

static int
dissect_struct_lfsck_request(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;
    guint32 valid;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_lfsck_request, tvb, offset, 96, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lfsck_request);

    /* struct lfsck_request { */
    /*     __u32        lr_event; */
    /*     __u32        lr_index; */
    /*     __u32        lr_flags; */
    /*     __u32        lr_valid; */
    /*     union { */
    /*         __u32    lr_speed; */
    /*         __u32    lr_status; */
    /*     }; */
    /*     __u16        lr_version; */
    /*     __u16        lr_active; */
    /*     __u16        lr_param; */
    /*     __u16        lr_async_windows; */
    /*     __u32        lr_flags2; */
    /*     struct lu_fid    lr_fid; */
    /*     struct lu_fid    lr_fid2; */
    /*     __u32        lr_comp_id; */
    /*     __u32        lr_padding_0; */
    /*     __u64        lr_padding_1; */
    /*     __u64        lr_padding_2; */
    /*     __u64        lr_padding_3; */
    /* }; */
    /* SIZE = 64+2*16 */

    proto_tree_add_item(tree, hf_lustre_lfsck_request_event, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lfsck_request_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* @@ bitmap of lfsck_event_flags */
    proto_tree_add_item(tree, hf_lustre_lfsck_request_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* @@ bitmap of lfsk_start_valid */
    proto_tree_add_item_ret_uint(tree, hf_lustre_lfsck_request_valid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &valid);
    offset += 4;
    /* determine union based on lr_valid */
    if (valid & LSV_SPEED_LIMIT)
        proto_tree_add_item(tree, hf_lustre_lfsck_request_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    else
        proto_tree_add_item(tree, hf_lustre_lfsck_request_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lfsck_request_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_lfsck_request_active, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_lfsck_request_param, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lustre_lfsck_request_async_windows, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* @@ bitmap of lfsck_flags */
    proto_tree_add_item(tree, hf_lustre_lfsck_request_flags2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_lfsck_request_fid);
    offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_lfsck_request_fid2);
    proto_tree_add_item(tree, hf_lustre_lfsck_request_comp_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lfsck_request_padding, tvb, offset, 28, ENC_NA);
    offset += 28;

    return offset;
}

static int
dissect_struct_lfsck_reply(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    int data_len;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    item = proto_tree_add_item(parent_tree, hf_lustre_lfsck_reply, tvb, offset, 16, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lustre_lfsck_reply);

    proto_tree_add_item(tree, hf_lustre_lfsck_reply_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lfsck_reply_padding, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lfsck_reply_repaired, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_llog_eadata(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint32 buf_num)
{
    proto_tree *tree;
    proto_item *item;
    guint32 data_len, opcode, len, old_offset;

    data_len = LUSTRE_BUFFER_LEN(buf_num);
    if (data_len == 0)
        return offset;

    /* EADATA in question is an llog record (see lustre/utils/llog_reader.c::print_records()),
    * and lustre/obdclass/llog_swab.c::lustre_swab_llog_rec() */
    /* All llog_*_rec structs start with llog_rec_hdr */

    // First element of llog_rec_hdr is record length
    while ((len = tvb_get_letohl(tvb, offset)) > 0) {
        opcode = tvb_get_letohl(tvb, offset+8);

        old_offset = offset;
        switch (opcode) {
        case LLOG_PAD_MAGIC:
            len = tvb_get_letohl(tvb, offset);
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_rec, tvb, offset, len, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_rec);
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_rec_hdr);
            offset = add_extra_padding(tvb, offset, pinfo, tree);
            /* no internal data */
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_rec_tail);
            break;
        case OST_SZ_REC:
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_size_change_rec, tvb, offset, 64, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_size_change_rec);
            /* struct llog_size_change_rec { */
            /*     struct llog_rec_hdr    lsc_hdr; */
            /*     struct ll_fid        lsc_fid; */
            /*     __u32            lsc_ioepoch; */
            /*     __u32            lsc_padding1; */
            /*     __u64            lsc_padding2; */
            /*     __u64            lsc_padding3; */
            /*     struct llog_rec_tail    lsc_tail; */
            /* } SIZE = 16+16+24+8 */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_size_change_rec_hdr);
            offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_llog_size_change_rec_fid);
            proto_tree_add_item(tree, hf_lustre_llog_size_change_rec_io_epoch, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_size_change_rec_padding, tvb, offset, 20, ENC_NA);
            offset += 20;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_size_change_rec_tail);
            break;
        case OST_RAID1_REC:
            /* Obsolete, never used */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_rec_hdr);
            expert_add_info(pinfo, parent_tree, &ei_lustre_badopc);
            expert_add_info(pinfo, parent_tree, &ei_lustre_obsopc);
            break;
        case MDS_UNLINK_REC:
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_unlink_rec, tvb, offset, 40, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_unlink_rec);
            /* struct llog_unlink_rec { */
            /*     struct llog_rec_hdr    lur_hdr; */
            /*     __u64            lur_oid; */
            /*     __u32            lur_oseq; */
            /*     __u32            lur_count; */
            /*     struct llog_rec_tail    lur_tail; */
            /* } SIZE = 16+16+8 */
            /* Obsolete after 2.5.0 */
            expert_add_info(pinfo, tree, &ei_lustre_obsopc);
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_unlink_rec_hdr);
            proto_tree_add_item(tree, hf_lustre_llog_unlink_rec_oid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_llog_unlink_rec_oseq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_unlink_rec_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_unlink_rec_tail);
            break;
        case MDS_UNLINK64_REC:
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_unlink64_rec, tvb, offset, 60, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_unlink64_rec);
            /* struct llog_unlink64_rec { */
            /*     struct llog_rec_hdr    lur_hdr; */
            /*     struct lu_fid        lur_fid; */
            /*     __u32            lur_count; /\* to destroy the lost precreated *\/ */
            /*     __u32            lur_padding1; */
            /*     __u64            lur_padding2; */
            /*     __u64            lur_padding3; */
            /*     struct llog_rec_tail    lur_tail; */
            /* } SIZE = 16+16+20+8 */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_unlink64_rec_hdr);
            offset = dissect_struct_lu_fid(tvb, offset, tree, hf_lustre_llog_unlink64_rec_fid);
            proto_tree_add_item(tree, hf_lustre_llog_unlink64_rec_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_unlink64_rec_padding, tvb, offset, 20, ENC_NA);
            offset += 20;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_unlink64_rec_tail);
            break;
        case MDS_SETATTR_REC:
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_setattr_rec, tvb, offset, 40, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_setattr_rec);
            /* Obsolete since 1.8.0 */
            expert_add_info(pinfo, tree, &ei_lustre_obsopc);
            /* struct llog_setattr_rec { */
            /*     struct llog_rec_hdr     lsr_hdr; */
            /*     __u64                   lsr_oid; */
            /*     __u32                   lsr_oseq; */
            /*     __u32                   lsr_uid; */
            /*     __u32                   lsr_gid; */
            /*     __u32                   lsr_padding; */
            /*     struct llog_rec_tail    lsr_tail; */
            /* } SIZE = 16+16+8 */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_setattr_rec_hdr);
            proto_tree_add_item(tree, hf_lustre_llog_setattr_rec_oid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_lustre_llog_setattr_rec_oseq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr_rec_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr_rec_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr_rec_padding, tvb, offset, 4, ENC_NA);
            offset += 4;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_setattr_rec_tail);
            break;
        case MDS_SETATTR64_REC:
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_setattr64_rec, tvb, offset, 60, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_setattr64_rec);
            /* struct llog_setattr64_rec { */
            /*     struct llog_rec_hdr    lsr_hdr; */
            /*     struct ost_id        lsr_oi; */
            /*     __u32            lsr_uid; */
            /*     __u32            lsr_uid_h; */
            /*     __u32            lsr_gid; */
            /*     __u32            lsr_gid_h; */
            /*     __u64            lsr_valid; */
            /*     struct llog_rec_tail     lsr_tail; */
            /* } */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_setattr64_rec_hdr);
            offset = dissect_struct_ost_id(tvb, offset, tree);
            proto_tree_add_item(tree, hf_lustre_llog_setattr64_rec_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr64_rec_uid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr64_rec_gid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr64_rec_gid_h, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_lustre_llog_setattr64_rec_valid, tvb, offset, 4, ENC_NA);
            offset += 4;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_setattr64_rec_tail);
            break;
        case OBD_CFG_REC:
            /* struct llog_rec_hdr
             * struct lustre_cfg
             * struct llog_rec_tail
             */
            len = tvb_get_letohl(tvb, offset);
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_rec, tvb, offset, len, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_rec);
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_rec_hdr);
            offset = dissect_struct_lustre_cfg(tvb, offset, tree);
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_rec_tail);
            break;
        case PTL_CFG_REC:
            /* Obsolete in 1.4.0 */
            dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_rec_hdr);
            expert_add_info(pinfo, parent_tree, &ei_lustre_obsopc);
            offset = dissect_struct_eadata(tvb, offset, pinfo, parent_tree, buf_num);
            break;
        case LLOG_GEN_REC:
            /* struct llog_gen_rec { */
            /*     struct llog_rec_hdr    lgr_hdr; */
            /*     struct llog_gen        lgr_gen; */
            /*     __u64            padding1; */
            /*     __u64            padding2; */
            /*     __u64            padding3; */
            /*     struct llog_rec_tail    lgr_tail; */
            /* }; 16+16+24+8 */
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_gen_rec, tvb, offset, 64, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_gen_rec);
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_gen_rec_hdr);
            offset = dissect_struct_llog_gen(tvb, offset, tree, hf_lustre_llog_gen_rec_gen);
            proto_tree_add_item(tree, hf_lustre_llog_gen_rec_padding, tvb, offset, 24, ENC_NA);
            offset += 24;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_gen_rec_tail);
            break;
        case LLOG_JOIN_REC:
            /* Obsolete in 1.8.0 */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_rec_hdr);
            expert_add_info(pinfo, parent_tree, &ei_lustre_obsopc);
            offset = dissect_struct_eadata(tvb, offset, pinfo, parent_tree, buf_num);
            break;
        case CHANGELOG_REC:
            len = tvb_get_letohl(tvb, offset);
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_changelog_rec, tvb, offset, len, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_changelog_rec);
            /* struct llog_changelog_rec { */
            /*     struct llog_rec_hdr  cr_hdr; */
            /*     struct changelog_rec cr; /\**< Variable length field *\/ */
            /*     struct llog_rec_tail cr_do_not_use; /\**< for_sizeof_only *\/ */
            /* } 16+cr+8 */
            offset = dissect_struct_llog_rec_hdr(tvb, offset, tree, hf_lustre_llog_changelog_rec_hdr);
            offset = dissect_struct_changelog_rec(tvb, offset, tree);
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_changelog_rec_tail);
            break;
        case CHANGELOG_USER_REC:
            /* struct llog_changelog_user_rec { */
            /*     struct llog_rec_hdr   cur_hdr; */
            /*     __u32                 cur_id; */
            /*     __u32                 cur_padding; */
            /*     __u64                 cur_endrec; */
            /*     struct llog_rec_tail  cur_tail; */
            /* } */
            //@@ HERE
            dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_rec_hdr);
            offset = dissect_struct_eadata(tvb, offset, pinfo, parent_tree, buf_num);
            break;
        case HSM_AGENT_REC:
            /* struct llog_agent_req_rec { */
            /*     struct llog_rec_hdr    arr_hdr;    /\**< record header *\/ */
            /*     __u32        arr_status;    /\**< status of the request *\/ */
            /*     /\* must match enum */
            /*      * agent_req_status *\/ */
            /*     __u32        arr_archive_id;    /\**< backend archive number *\/ */
            /*     __u64        arr_flags;    /\**< req flags *\/ */
            /*     __u64        arr_compound_id;    /\**< compound cookie *\/ */
            /*     __u64        arr_req_create;    /\**< req. creation time *\/ */
            /*     __u64        arr_req_change;    /\**< req. status change time *\/ */
            /*     struct hsm_action_item    arr_hai;    /\**< req. to the agent *\/ */
            /*     struct llog_rec_tail    arr_tail; /\**< record tail for_sizezof_only *\/ */
            /* } */
            dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_rec_hdr);
            offset = dissect_struct_eadata(tvb, offset, pinfo, parent_tree, buf_num);
            //@@ HERE
            break;
        case UPDATE_REC:
            /* struct llog_update_record { */
            /*     struct llog_rec_hdr     lur_hdr; */
            /*     struct update_records   lur_update_rec; */
            /*     /\* Note ur_update_rec has a variable size, so comment out */
            /*      * the following ur_tail, in case someone use it directly */
            /*      * */
            /*      * struct llog_rec_tail lur_tail; */
            /*      *\/ */
            /* }; */
            dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_rec_hdr);
            offset = dissect_struct_eadata(tvb, offset, pinfo, parent_tree, buf_num);
            //@@ HERE
            break;
        case LLOG_HDR_MAGIC:
            offset = dissect_struct_llog_log_hdr(tvb, offset, pinfo, parent_tree, buf_num);
            break;
        case LLOG_LOGID_MAGIC:
            /* struct llog_logid_rec { */
            /*     struct llog_rec_hdr    lid_hdr; */
            /*     struct llog_logid    lid_id; */
            /*     __u32            lid_padding1; */
            /*     __u64            lid_padding2; */
            /*     __u64            lid_padding3; */
            /*     struct llog_rec_tail    lid_tail; */
            /* } */
            item = proto_tree_add_item(parent_tree, hf_lustre_llog_logid_rec, tvb, offset, len, ENC_NA);
            tree = proto_item_add_subtree(item, ett_lustre_llog_logid_rec);
            offset = dissect_struct_llog_rec_hdr(tvb, offset, parent_tree, hf_lustre_llog_logid_rec_hdr);
            offset = dissect_struct_llog_logid(tvb, offset, tree, hf_lustre_llog_logid_rec_id);
            proto_tree_add_item(tree, hf_lustre_llog_logid_rec_padding, tvb, offset, 12, ENC_NA);
            offset += 12;
            offset = dissect_struct_llog_rec_tail(tvb, offset, tree, hf_lustre_llog_logid_rec_tail);
            break;
        default:
            expert_add_info_format(pinfo, parent_tree, &ei_lustre_badopc, "UNKNOWN LLOG REC Type: %u", opcode);
            break;
        }

        if (offset-old_offset != len) {
            expert_add_info_format(pinfo, parent_tree, &ei_lustre_buflen,
                                   "LLOG REC: Bad Parse Length (opc:%u len:%u parsed:%d)", opcode, len, (offset-old_offset));
            offset = old_offset + len;
            break;
        }
    }

    offset = add_extra_padding(tvb, offset, pinfo, parent_tree);
    return offset;
}

static int
dissect_generic_connect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    /* [targetuuid][clientuuid][lustre_handle][obd_connect_data] */
    offset = dissect_struct_obd_uuid(tvb, offset, tree, hf_lustre_target_uuid);
    offset = dissect_struct_obd_uuid(tvb, offset, tree, hf_lustre_client_uuid);
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_lustre_handle);
    offset = dissect_struct_obd_connect_data(tvb, offset, pinfo, tree);

    return offset;
}

/********************************************************************   \
 *
 * OPCODE Processing
 *
 * decode these via lustre/ptlrpc/layout.c
 *
\********************************************************************/

static int
process_opcode_ost(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    switch (trans->opcode){
    case OST_REPLY: /* obsolete so nothing */
        break;
    case OST_GETATTR:
    case OST_SETATTR:
    case OST_PUNCH:
    case OST_SYNC:
       /* REQ: [OST_BODY][CAPA]
        * REP: [OST_BODY]  */
        offset = dissect_struct_ost_body(tvb, offset, tree);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
        break;

    case OST_READ: /* OST_BRW_READ */
        /* REQ: [OST_BODY][[obd_ioobj]][[niobuf_remote]][capa]
         * REP: [OST_BODY]  */
        offset = dissect_struct_ost_body(tvb, offset, tree);
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_obd_ioobj(tvb, offset, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_niobuf_remote(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        }
        break;

    case OST_WRITE: /* OST_BRW_WRITE */
        /* REQ: [OST_BODY][[obd_ioobj]][[niobuf_remote]][capa]
         * REP: [OST_BODY][RCS]  */
        offset = dissect_struct_ost_body(tvb, offset, tree);
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            // @@ iooobj.buf_count determins number of niobufs
            // niobuf have BUFFERS after them
            offset = dissect_struct_obd_ioobj(tvb, offset, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_niobuf_remote(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        }
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_rc_array(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        break;

    case OST_CREATE:
        offset = dissect_struct_ost_body(tvb, offset, tree);
        break;

    case OST_DESTROY:
        /* REQ: [OST_BODY][DLM_REQ][CAPA]
         * REP: [OST_BODY]  */
        offset = dissect_struct_ost_body(tvb, offset, tree);
        if (pb_type == PTL_RPC_MSG_REPLY)
            break;

        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+1);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
        break;

    case OST_GET_INFO:
        /* REQ: [GETINFO_KEY]
         * REP: [GENERIC_DATA] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_ost_key, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_ost_val, LUSTRE_REC_OFF);
        break;

    case OST_CONNECT:
        /* REQ: CONNECT CLIENT CHAIN == [targetuuid][clientuuid][lustre_handle][obd_connect_data]
         * REP: [OBD_CONNECT_DATA] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_generic_connect(tvb, offset, pinfo, tree);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_obd_connect_data(tvb, offset, pinfo, tree);
        break;

    case OST_DISCONNECT:
        /* no data */
        break;

    case OST_OPEN:
    case OST_CLOSE:
        /* no data - code is obsolete */
        break;

    case OST_STATFS:
        /* REQ: no data
           PRE: [obd_statfs] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            break;
        offset = dissect_struct_obd_statfs(tvb, offset, tree);
        break;

    case OST_SET_INFO:
        /* REQ: [KEY][VAL]
           REP: no data */
        if (pb_type == PTL_RPC_MSG_REPLY)
            break;
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_ost_key, LUSTRE_REC_OFF);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_ost_val, LUSTRE_REC_OFF+1);
        break;

    case OST_QUOTACHECK: /* OBSOLETED after 2.4 */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_obd_quotactl(tvb, offset, tree);
        /* nothing in reply */
        break;

    case OST_QUOTACTL:
        /* REQ: [QUOTACTL]
         * REP: [QUOTACTL] */
        offset = dissect_struct_obd_quotactl(tvb, offset, tree);
        break;

    case OST_QUOTA_ADJUST_QUNIT: /* OBSOLETED after 2.4 */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        /* [quota_adjust_qunit]  */
        offset = dissect_struct_quota_adjust_qunit(tvb, offset, tree, LUSTRE_REC_OFF);
        break;

    case OST_LADVISE:
        /* REQ: [OST_BODY][LADVISE_HDR][LADVISE]
         * REP: [OST_BODY] */
        /*[ost_body] in both case */
        offset = dissect_struct_ost_body(tvb, offset, tree);
        if (pb_type == PTL_RPC_MSG_REPLY)
            break;

        offset = dissect_struct_lu_ladvise_hdr(tvb, offset, pinfo, tree);
        offset = dissect_struct_lu_ladvise(tvb, offset, tree);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN OST OPCODE: %d (type: %d)", trans->opcode, pb_type);
        break;
    };
    return offset;
}

static int
process_opcode_reint_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans)
{
    trans->sub_opcode = tvb_get_letohl(tvb, offset);

    offset = dissect_struct_mdt_rec_reint(tvb, offset, pinfo, tree, LUSTRE_REC_OFF);
    if (trans->sub_opcode == REINT_RMENTRY)
        return offset;
    offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);

    switch(trans->sub_opcode) {
    case REINT_SETATTR:
        /* [REC REINT][CAPA1][MDT EPOCH][EADATA][LOGCOOKIES][DLM REQ] */
        offset = dissect_struct_mdt_ioepoch(tvb, offset, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_llog_cookie_array(tvb, offset, tree, LUSTRE_REC_OFF+4);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+5);
        break;
    case REINT_CREATE:
        /* Create Types:
         * [REC REINT][CAPA1][NAME]
         * ACL:                    [EADATA][DLM REQ][FILE SECCTX NAME][FILE SECCTX]
         * SLAVE:                  [EADATA][DLM REQ]
         * SYM:                    [SYMTGT][DLM REQ][FILE SECCTX NAME][FILE SECCTX]
         */
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+2);
        // This could also be string for symlink
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+4);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_secctx_name, LUSTRE_REC_OFF+5);
        offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF+6, "Security Context");
        break;
    case REINT_LINK:
        /* [REC REINT][CAPA1][CAPA2][NAME][DLM REQ] */
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+3);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+4);
        break;
    case REINT_UNLINK:
        /* [REC REINT][CAPA1][NAME][DLM REQ] */
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+2);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+3);
        break;
    case REINT_RENAME:
        /* [REC REINT][CAPA1][CAPA2][NAME][SYMTGT][DLM REQ] */
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+3);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_target, LUSTRE_REC_OFF+4);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+5);
        break;
    case REINT_OPEN:
        /* [REC REINT][CAPA1][CAPA2][NAME][EADATA][FILE SECCTX NAME][FILE SECCTX] */
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+3);
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+4);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_secctx_name, LUSTRE_REC_OFF+5);
        offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF+6, "Security Context");
        break;
    case REINT_SETXATTR:
        /* [REC REINT][CAPA1][NAME][EADATA][DLM REQ] */
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+2);
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+4);
        break;
    case REINT_RMENTRY:
        /* nothing further - and will never get here */
        break;
    case REINT_MIGRATE:
        /* [REC REINT][CAPA1][CAPA2][NAME][SYMTGT][DLM REQ][MDT EPOCH][CLOSE DATA] */
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+3);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_secctx_name, LUSTRE_REC_OFF+4);
        offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+5);
        offset = dissect_struct_mdt_ioepoch(tvb, offset, tree, LUSTRE_REC_OFF+6);
        offset = dissect_struct_close_data(tvb, offset, tree, LUSTRE_REC_OFF+7);
        break;
    }

    return offset;
}

static int
process_opcode_reint_rep(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans)
{
    offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);

    /* trans->sub_opcode is set during REQUEST */
    switch(trans->sub_opcode) {
    case REINT_SETATTR:
    case REINT_OPEN:
        /* [MDT BODY][MDT MD][ACL][CAPA1][CAPA2] */
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_acl(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_capa(tvb, offset ,tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_capa(tvb, offset ,tree, LUSTRE_REC_OFF+4);
       break;
    case REINT_CREATE:
        /* [MDT BODY][CAPA] */
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
        break;
    case REINT_LINK:
    case REINT_SETXATTR:
    case REINT_RMENTRY:
        /* [MDT BODY] */
        break;
    case REINT_UNLINK:
    case REINT_RENAME:
    case REINT_MIGRATE:
        /* [MDT BODY][MDT MD][LOGCOOKIES][CAPA1][CAPA2] */
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_llog_cookie_array(tvb, offset, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_capa(tvb, offset ,tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_capa(tvb, offset ,tree, LUSTRE_REC_OFF+4);
       break;
    }

    return offset;
}

static int
process_opcode_mds(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans, guint32 pb_type)
{
    switch (trans->opcode) {
    case MDS_GETATTR_NAME:
        /* REQ: [MDT BODY][CAPA][NAME]
         * REP: [MDT BODY][mdt_md][acl][capa1][capa2] */
    case MDS_GETATTR:
        /* REQ: [MDT BODY][CAPA]
         * REP: [MDT BODY][mdt_md][acl][capa1][capa2] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
            if (trans->opcode == MDS_GETATTR_NAME)
                offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_name, LUSTRE_REC_OFF+2);
        }
        if (pb_type == PTL_RPC_MSG_REPLY) {
            offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_acl(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+4);
        }
        break;

    case MDS_CLOSE:
        /* REQ: [MDT IOEPOCH][REINT][CAPA]
         * REP: [MDT BODY][MDT MD][LOGCOOKIES][CAPA1][CAPA2] */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_mdt_ioepoch(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_struct_mdt_rec_reint(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_close_data(tvb, offset, tree, LUSTRE_REC_OFF+3);
        }
        if (pb_type == PTL_RPC_MSG_REPLY) {
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_llog_cookie_array(tvb, offset, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_capa(tvb, offset ,tree, LUSTRE_REC_OFF+3);
            offset = dissect_struct_capa(tvb, offset ,tree, LUSTRE_REC_OFF+4);
        }
        break;

    case MDS_REINT:
        /* the structure depend on the intent_opcode */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = process_opcode_reint_req(tvb, offset, pinfo, tree, trans);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = process_opcode_reint_rep(tvb, offset, pinfo, tree, trans);

        break;

    case MDS_CONNECT:
        /* REQ: generic connect chain ([targetuuid][clientuuid][lustre_handle][obd_connect_data])
         * REP: [CONNECT DATA] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_generic_connect(tvb, offset, pinfo, tree);
        if (pb_type == PTL_RPC_MSG_REPLY || pb_type == PTL_RPC_MSG_ERR) /*[obd_connect_data]*/
            offset = dissect_struct_obd_connect_data(tvb, offset, pinfo, tree);
        break;

    case MDS_DISCONNECT:
        /* no data */
        break;

    case MDS_GET_ROOT:
        /* REQ: [mdt body][NAME] */
        /* REP: [mdt body][capa] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_name, LUSTRE_REC_OFF+1);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
        break;

    case MDS_STATFS:
        /* REQ: no data
         * REP: [OBD STATFS] */
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_obd_statfs(tvb, offset, tree);
        break;

        /* case MDS_PIN: NEVER USED In a release */
        /* case MDS_UNPIN: NEVER USED In a release */

    case MDS_READPAGE: // OUT OF ORDER
        /* page transport: MDS BULK PORTAL */
    case MDS_SYNC:
        /* REQ: [MDT BODY][CAPA]
         * REP: [MDT BODY] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
        break;

    case MDS_DONE_WRITING:
         /* Obsolete since 2.8.0 */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        /* [mdt_body] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        break;

    case MDS_SET_INFO:
        /* Missing from lustre/ptlrpc/layout.c */
        /* REQ: [KEY][VAL]
         * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF);
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_mdt_val, LUSTRE_REC_OFF+1);
        }
        break;

    case MDS_QUOTACHECK:
        /* Obsolete since 2.8.0 */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        /* REQ: [obd_quotactl]
         * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_obd_quotactl(tvb, offset, tree);
        break;

    case MDS_QUOTACTL:
        /* REQ: [obd_quotactl]
         * REP: [obd_quotactl] */
        offset = dissect_struct_obd_quotactl(tvb, offset, tree);
        break;

    case MDS_GETXATTR:
        /* REQ: [MDT BODY][CAPA][NAME][EADATA]
         * REP: [MDT BODY][EADATA] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_name, LUSTRE_REC_OFF+2);
            offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        }
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        break;

    case MDS_SETXATTR:
        /* Obsolete since 2.0.0, should use MDS_REINT.REINT_SETXATTR */
        /* REQ: [mdt_body]
         * REP: no data */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        if(pb_type==PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        break;

    case MDS_WRITEPAGE:
        /* Not used, apparently */
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "MDS WRITEPAGE: Unknown decoding");
        break;

        /* case MDS_IS_SUBDIR: obsolete, never used in a release */

    case MDS_GET_INFO:
        /* REQ: [KEY][LENGTH]
         * REP: [VAL] */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            // @@TODO this is actually a string + fill + optional struct : lustre/include/obd.h KEY_*
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_mdt_key, LUSTRE_REC_OFF);
            // "fid2path" -> [getinfo_fid2path][lu_fid]

            // BUFFER: LUSTRE_REC_OFF+1
            proto_tree_add_item(tree, hf_lustre_mdt_vallen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF, NULL);
        break;

    case MDS_HSM_STATE_GET:
        /* REQ: [mdt_body][capa]
         * REP: [MDT BODY][][HSM USER STATE] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_hsm_user_state(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        break;

    case MDS_HSM_STATE_SET:
        /* REQ: [mdt_body][capa][hsm_state_set]
         * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_hsm_state_set(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        }
        break;

    case MDS_HSM_ACTION:
        /* REQ: [mdt_body][capa]
         * REP: [mdt_body][hsm_current_action] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+1);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_hsm_current_action(tvb, offset, tree, LUSTRE_REC_OFF+1);
        break;

    case MDS_HSM_PROGRESS:
        /* REQ: [mdt_body][hsm_progress]
         * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_struct_hsm_progress(tvb, offset, tree);
        }
        break;

    case MDS_HSM_REQUEST:
        /* REQ: [mdt_body][hsm_request][array of hsm_user_item][generic_data]
         * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_struct_hsm_request(tvb, offset, tree);
            offset = dissect_struct_hsm_user_item_array(tvb, offset, tree, LUSTRE_REC_OFF+2);
            offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF+3, NULL);
        }
        break;

    case MDS_HSM_CT_REGISTER:
       /* REQ: [mdt_body][hsm_archive]
        * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_hsm_archive(tvb, offset, tree, LUSTRE_REC_OFF+1);
        }
        break;

    case MDS_HSM_CT_UNREGISTER:
       /* REQ: [mdt_body]
        * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        break;

    case MDS_SWAP_LAYOUTS:
       /* REQ: [mdt_body][swap_layouts][capa1][capa2][dlm_req]
        * REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
            offset = dissect_struct_mdc_swap_layouts(tvb, offset, tree, LUSTRE_REC_OFF+1);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
            offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF+4);
        }
        break;

    case MDS_RMFID:
       /* REQ: [mdt_body][fid_array][capa1][capa2]
        * REP: [mdt_body][fid_array][rcs] */
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        offset = dissect_struct_fid_array(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+2);
            offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        } else if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_rc_array(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        break;

    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN MDS OPCODE: %d (type: %d)", trans->opcode, pb_type);
        break;
    };

    return offset;
}

static int
process_ldlm_intent_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans)
{
    /* > 2 buffers means LDLM_INTENT */
    if (LUSTRE_BUFCOUNT <= 2)
        return offset;

    /* REQ: [DLM REQ][INTENT]
     * Basic:           --
     * Default:         [REC REINT]
     * OPEN:            [REC REINT][CAPA1][CAPA2][NAME][EADATA][SECCTX NAME][SECCTX]
     * CREATE:          [REC REINT][CAPA1][NAME][EADATA][SECCTX NAME][SECCTX]([SELINUX])
     * GETATTR:         [MDT BODY][CAPA1][NAME]
     * UNLINK:          [REC REINT][CAPA1][NAME]
     * LAYOUT:          [LAYOUT INTENT][EADATA]
     * GETXATTR:        [MDT BODY][CAPA1]
     * QUOTA*:          [QUOTA BODY]
     */
    /* could also sanity check: ldlm_request.lock_flags & LDLM_FL_HAS_INTENT */
    offset = dissect_struct_ldlm_intent(tvb, offset, pinfo, tree, trans, LUSTRE_REC_OFF+1);

    switch (trans->sub_opcode) {
    case IT_OPEN_CREAT:
    case IT_OPEN:
        offset = dissect_struct_mdt_rec_reint(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+4);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+5);
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+6);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_secctx_name, LUSTRE_REC_OFF+7);
        offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF+8, "Security Context");
        break;
    case IT_CREAT:
        offset = dissect_struct_mdt_rec_reint(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+4);
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+5);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_secctx_name, LUSTRE_REC_OFF+6);
        offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF+7, "Security Context");
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_selinux_pol, LUSTRE_REC_OFF+8);
        break;
    case IT_LOOKUP: /* lustre/lmv/lmv_intent.c::lmv_intent_remote() */
    case IT_GETATTR:
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+4);
        break;
    case IT_UNLINK:
        offset = dissect_struct_mdt_rec_reint(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_filename, LUSTRE_REC_OFF+4);
        break;
    case IT_LAYOUT:
        offset = dissect_struct_layout_intent(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        break;
    case IT_GETXATTR:
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+3);
        break;
    case IT_QUOTA_DQACQ:
    case IT_QUOTA_CONN:
        offset = dissect_struct_quota_body(tvb, offset, tree, LUSTRE_REC_OFF+2);
        break;
    default:
        offset = dissect_struct_mdt_rec_reint(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        break;
    }

    return offset;
}

static int
process_ldlm_intent_rep(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans)
{
    /* LDLM_ENQUEUE:
     * REP: [DLM REP][DLM LVB]
     * INTENT:
     * REP: [DLM REP]...
     * Default:      [MDT BODY][MDT MD][ACL]
     * LAYOUT:       [DLM LVB]
     * GETATTR:      [MDT BODY][MDT MD][ACL][CAPA1]([SECCTX])([DEFAULT MDT MD])
     * CREATE:       same as GETATTR
     * OPEN:         [MDT BODY][MDT MD][ACL][CAPA1][CAPA2]([NIOBUF])([SECCTX])
     * QUOTA:        [DLM LVB][QUOTA BODY]
     * GETXATTR:     [MDT BODY][MDT MD][ACL][EADATA][EAVALS][EAVALS LENS]
     */
    offset = dissect_struct_ldlm_reply(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF);
    switch (trans->sub_opcode) {
    case 0: /* LDLM_ENQUEUE - no INTENT */
    case IT_LAYOUT:
        /* if tvb_get_letohl(tvb, offset) == LOV_MAGIC_V1 then DLMLVB :: lov_mds_md_v1 */
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        break;
    case IT_GETATTR:
    case IT_CREAT:
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_acl(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+4);
        break;
    case IT_OPEN:
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_acl(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+4);
        offset = dissect_struct_capa(tvb, offset, tree, LUSTRE_REC_OFF+5);
        offset = dissect_struct_niobuf_remote(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+6);
        offset = display_buffer_data(tvb, pinfo, offset, tree, LUSTRE_REC_OFF+7, "Security Context");
        break;
    case IT_QUOTA_DQACQ:
    case IT_QUOTA_CONN:
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_quota_body(tvb, offset, tree, LUSTRE_REC_OFF+2);
        break;
    case IT_GETXATTR:
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_acl(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        /* this sucks up [EADATA][EAVALS][EAVALS LENS] */
        offset = dissect_xattr_buffers(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+4);
        break;
    default:
        offset = dissect_struct_mdt_body(tvb, offset, tree, LUSTRE_REC_OFF+1);
        offset = dissect_struct_lov_mds_md(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+2);
        offset = dissect_struct_acl(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+3);
        break;
    }
    return offset;
}

static int
process_opcode_ldlm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans, guint32 pb_type)
{
    if (pb_type == PTL_RPC_MSG_REQUEST)
        switch (trans->opcode) {
        case LDLM_ENQUEUE:
            /* REQ: [DLM REQ]{[INTENT]...} */
            offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF);
            offset = process_ldlm_intent_req(tvb, offset, pinfo, tree, trans);
            break;
        case LDLM_GL_CALLBACK:
            /* REQ: [DLM REQ][[GL DESC]]
             * LDLM_GL_CALLBACK_DESC has gl_desc as tertiary buffer
             */
            offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, &trans->sub_opcode, LUSTRE_REC_OFF);
            offset = dissect_struct_ldlm_gl_desc(tvb, offset, pinfo, tree, trans, LUSTRE_REC_OFF+1);
            break;
        case LDLM_CONVERT:
        case LDLM_CANCEL:
        case LDLM_BL_CALLBACK:
            /* REQ: [DLM REQ] */
            offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF);
            break;
        case LDLM_CP_CALLBACK:
            /* REQ: [DLM REQ][DLM LVB] */
            offset = dissect_struct_ldlm_request(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF);
            /* lustre/ldlm/ldlm_lockd.c::ldlm_handle_cp_callback()
             * if extent lock, lvb data is ost_lvb struct, no other
             * options seem to exist */
            offset = dissect_struct_ost_lvb(tvb, offset, tree, LUSTRE_REC_OFF+1);
            break;
        case LDLM_SET_INFO:
            /* not in lustreptlrpc/layout.c
             * in lustre/ldlm/ldlm_lockd.c::ldlm_handle_setinfo() treat like RQF_OBD_SET_INFO */
            /* REQ: [KEY][VAL] */
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_ldlm_key, LUSTRE_REC_OFF);
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_ldlm_val, LUSTRE_REC_OFF+1);
            break;
        default:
            expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN LDLM OPCODE: %d (type: %d)", trans->opcode, pb_type);
            break;
        }

    if (pb_type == PTL_RPC_MSG_REPLY)
        switch (trans->opcode) {
        case LDLM_ENQUEUE:
            offset = process_ldlm_intent_rep(tvb, offset, pinfo, tree, trans);
            break;
        case LDLM_CONVERT:
            /* REP: [DLM REP] */
            offset = dissect_struct_ldlm_reply(tvb, offset, pinfo, tree, NULL, LUSTRE_REC_OFF);
            break;
        case LDLM_CANCEL:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
            /* no data */
            break;
        case LDLM_GL_CALLBACK:
            /* REP: [DLM LVB] */
            offset = dissect_struct_barrier_lvb(tvb, offset, tree, LUSTRE_REC_OFF);
            break;
        case LDLM_SET_INFO:
            /* no data - c.f. Request reasoning, this prossesed as RFQ_OBD_SET_INFO */
            break;
        default:
            expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN LDLM OPCODE: %d (type: %d)", trans->opcode, pb_type);
            break;
        }
    return offset;
}

static int
process_opcode_mgs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    switch (trans->opcode){
    case MGS_CONNECT:
        /* REQ: generic connect chain ([targetuuid][clientuuid][lustre_handle][obd_connect_data])
         * REP: [CONNECT DATA] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_generic_connect(tvb, offset, pinfo, tree);
        if (pb_type == PTL_RPC_MSG_REPLY || pb_type == PTL_RPC_MSG_ERR)
            offset = dissect_struct_obd_connect_data(tvb, offset, pinfo, tree);
        break;
    case MGS_DISCONNECT:
        /* no data */
        break;
    case MGS_EXCEPTION:
        /* no data */
        break;
    case MGS_TARGET_REG:
        /* REQ: [mgs_target_info]
         * REP: [mgs_target_info] */
        offset = dissect_struct_mgs_target_info(tvb, offset, pinfo, tree, LUSTRE_REC_OFF);
        break;
    case MGS_TARGET_DEL:
        /* no data */
        break;
    case MGS_SET_INFO:
        /* REQ: [mgs_send_param]
         * REP: [mgs_send_param] */
        offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_mgs_send_param, LUSTRE_REC_OFF);
        break;
    case MGS_CONFIG_READ:
        /* REQ: [mgs_config_body]
         * REP: [mgs_config_res] */
        if (pb_type==PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_mgs_config_body(tvb, offset, pinfo, tree, trans);
        if (pb_type==PTL_RPC_MSG_REPLY)
            offset = dissect_struct_mgs_config_res(tvb, offset, pinfo, tree, trans);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN MGS OPCODE: %d (type: %d)", trans->opcode, pb_type);
        break;
    };
    return offset;
}


static int
process_opcode_obd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    switch (trans->opcode) {
    case OBD_PING:
        /* no data */
        break;
    case OBD_LOG_CANCEL:
        /* REQ: [LOGCOOKIES]
           REP: no data */
        if (pb_type==PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_llog_cookie_array(tvb, offset, tree, LUSTRE_REC_OFF);
        break;
    case OBD_QC_CALLBACK: /* not used since 2.4 */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        break;
    case OBD_IDX_READ:
        /* REQ: [idx_info]
           REP: [idx_info] */
        offset = dissect_struct_idx_info(tvb, offset, tree, LUSTRE_REC_OFF);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN OBD OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

static int
process_opcode_llog(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    switch (trans->opcode) {
    case LLOG_ORIGIN_HANDLE_CREATE:
        /* REQ: [LLOG BODY][NAME]
           REP: [LLOG BODY] */
        offset = dissect_struct_llogd_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = display_buffer_string(tvb, pinfo, tree, offset, hf_lustre_name, LUSTRE_REC_OFF+1);
        break;
    case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
    case LLOG_ORIGIN_HANDLE_PREV_BLOCK:
        /* REQ: [LLOG BODY]
           REP: [LLOG BODY][EADATA] */
        offset = dissect_struct_llogd_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_llog_eadata(tvb, offset, pinfo, tree, LUSTRE_REC_OFF+1);
        break;
    case LLOG_ORIGIN_HANDLE_READ_HEADER:
        /* REQ: [LLOG BODY]
           REP: [LLOG LOG HDR] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_llogd_body(tvb, offset, tree, LUSTRE_REC_OFF);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_llog_log_hdr(tvb, offset, pinfo, tree, LUSTRE_REC_OFF);
        break;
    case LLOG_ORIGIN_CONNECT:
        /* REQ: [LLOG CONN BODY]
           REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_llogd_conn_body(tvb, offset, tree, LUSTRE_REC_OFF);
        break;
    case LLOG_ORIGIN_HANDLE_DESTROY:
        /* REQ: [LLOG BODY]
           REP: [LLOG BODY] */
        offset = dissect_struct_llogd_body(tvb, offset, tree, LUSTRE_REC_OFF);
        break;
    case LLOG_CATINFO:
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        /* @@ data? */
        break;
    case LLOG_ORIGIN_HANDLE_WRITE_REC:
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        /* @@ obsolete since AT LEAST 2.0 */
        break;
    case LLOG_ORIGIN_HANDLE_CLOSE:
        /* no data */
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN LLOG OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

static int
process_opcode_quota(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    switch (trans->opcode) {
    case QUOTA_DQACQ:
        /* REQ: [QUOTA BODY]
           REP: [QUOTA BODY] */
        offset = dissect_struct_quota_body(tvb, offset, tree, LUSTRE_REC_OFF);
        break;
    case QUOTA_DQREL:
        /* no data */
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN QUOTA OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

static int
process_opcode_seq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    int buffer = LUSTRE_REC_OFF;
    switch (trans->opcode) {
    case SEQ_QUERY:
        /* REQ: [SEQ OPC][SEQ RANGE]
           REP: [SEQ RANGE] */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            trans->sub_opcode = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(tree, hf_lustre_seq_opc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = add_extra_padding(tvb, offset, pinfo, tree);
            ++buffer;
        }
        offset = dissect_struct_seq_range(tvb, offset, tree, buffer);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN SEQ OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

static int
process_opcode_fld(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    int buffer = LUSTRE_REC_OFF;
    switch (trans->opcode) {
    case FLD_QUERY:
        /* REQ: [FLD OPC][FLD MDFLD]
           REP: [FLD MDFLD] */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            trans->sub_opcode = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(tree, hf_lustre_fld_opc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = add_extra_padding(tvb, offset, pinfo, tree);
            ++buffer;
        }
        offset = dissect_struct_seq_range(tvb, offset, tree, buffer);
        break;
    case FLD_READ:
        /* REQ: [FLD MDFLD]
           REP: [GENERIC DATA] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_seq_range(tvb, offset, tree, buffer);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = display_buffer_data(tvb, pinfo, offset, tree, buffer, NULL);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN FLD OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

static int
process_opcode_out_update(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    int buffer = LUSTRE_REC_OFF;
    switch (trans->opcode) {
    case OUT_UPDATE:
        /* REQ: [OUT UDPATE HEADER][OUT UPDATE BUFFER]
           REP: [OUT UPDATE REPLY] */
        if (pb_type == PTL_RPC_MSG_REQUEST) {
            offset = dissect_struct_out_update_header(tvb, offset, pinfo, tree, buffer++);
            offset = dissect_struct_out_update_buffer(tvb, offset, tree, buffer);
        }
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_obj_update_reply(tvb, offset, pinfo, tree, buffer);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN OUT OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

static int
process_opcode_lfsck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans, guint32 pb_type)
{
    int buffer = LUSTRE_REC_OFF;
    switch (trans->opcode) {
    case LFSCK_NOTIFY:
        /* REQ: [LFSCK REQ]
           REP: no data */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_lfsck_request(tvb, offset, tree, buffer);
        break;
    case LFSCK_QUERY:
        /* REQ: [LFSCK REQ]
           REP: [LFSCK REP] */
        if (pb_type == PTL_RPC_MSG_REQUEST)
            offset = dissect_struct_lfsck_request(tvb, offset, tree, buffer);
        if (pb_type == PTL_RPC_MSG_REPLY)
            offset = dissect_struct_lfsck_reply(tvb, offset, tree, buffer);
        break;
    default:
        expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "UNKNOWN LFSCK OPCODE: %d (type: %d)", trans->opcode, pb_type);
    };
    return offset;
}

/********************************************************************   \
 *
 * Message Dissectors and Helpers
 *
\********************************************************************/
/* process lustre opcode :
   check if opcode is in range_opcode, and call the corresponding opcode process function */
static int
lustre_opcode_process(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree * tree, lustre_trans_t *trans, guint32 pb_type)
{
    /* No more buffers to process */
    if (LUSTRE_BUFCOUNT == 1)
        return offset;

    /* OST opcodes */
    if (trans->opcode <= OST_LAST_OPC)
        return process_opcode_ost(tvb, offset, pinfo, tree, trans, pb_type);

    /* MDS opcodes */
    if ((trans->opcode >= MDS_FIRST_OPC) &&  (trans->opcode < MDS_LAST_OPC))
        return process_opcode_mds(tvb, offset, pinfo, tree, trans, pb_type);

    /*LDLM Opcodes*/
    if ((trans->opcode >= LDLM_FIRST_OPC) && (trans->opcode < LDLM_LAST_OPC))
        return process_opcode_ldlm(tvb, offset, pinfo, tree, trans, pb_type);

    /* MGS Opcodes */
    if ((trans->opcode >= MGS_FIRST_OPC) && (trans->opcode < MGS_LAST_OPC))
        return process_opcode_mgs(tvb, offset, pinfo, tree, trans, pb_type);

    /* ODB Opcodes */
    if ((trans->opcode >= OBD_FIRST_OPC) && (trans->opcode < OBD_LAST_OPC))
       return process_opcode_obd(tvb, offset, pinfo, tree, trans, pb_type);

    /* LLOG Opcodes */
    if ((trans->opcode >= LLOG_FIRST_OPC) && (trans->opcode < LLOG_LAST_OPC))
       return process_opcode_llog(tvb, offset, pinfo, tree, trans, pb_type);

    /* QUOTA Opcodes */
    if ((trans->opcode >= QUOTA_FIRST_OPC) && (trans->opcode < QUOTA_LAST_OPC))
       return process_opcode_quota(tvb, offset, pinfo, tree, trans, pb_type);

    /* SEQ Opcodes */
    if ((trans->opcode >= SEQ_FIRST_OPC) && (trans->opcode < SEQ_LAST_OPC))
        return process_opcode_seq(tvb, offset, pinfo, tree, trans, pb_type);

    /* SEC Opcodes */
    if ((trans->opcode >= SEC_FIRST_OPC) && (trans->opcode < SEC_LAST_OPC))
        /* Currently not implemented */
        return offset;

    /* FLD Opcodes */
    if ((trans->opcode >= FLD_FIRST_OPC) && (trans->opcode < FLD_LAST_OPC))
        return process_opcode_fld(tvb, offset, pinfo, tree, trans, pb_type);

    /* OUT Opcodes */
    if ((trans->opcode >= OUT_UPDATE_FIRST_OPC) && (trans->opcode < OUT_UPDATE_LAST_OPC))
        return process_opcode_out_update(tvb, offset, pinfo, tree, trans, pb_type);

    /* LFSCK Opcodes */
    if ((trans->opcode >= LFSCK_FIRST_OPC) && (trans->opcode < LFSCK_LAST_OPC))
        return process_opcode_lfsck(tvb, offset, pinfo, tree, trans, pb_type);

    /* Unrecognized OPCODE */
    expert_add_info_format(pinfo, tree, &ei_lustre_badopc, "BAD OPCODE: %d (type: %d)", trans->opcode, pb_type);

    return offset;
}

static int
dissect_struct_msg_v1(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, lustre_trans_t *trans)
{
    //proto_item *item = NULL;
    guint32 bufcount, i;
    int old_offset;

    old_offset = offset;

    /* struct lustre_msg_v1 { */
    /*     struct lustre_handle lm_handle; */
    /*     __u32 lm_magic; */
    /*     __u32 lm_type; */
    /*     __u32 lm_version; */
    /*     __u32 lm_opc; */
    /*     __u64 lm_last_xid; */
    /*     __u64 lm_last_committed; */
    /*     __u64 lm_transno; */
    /*     __u32 lm_status; */
    /*     __u32 lm_flags; */
    /*     __u32 lm_conn_cnt; */
    /*     __u32 lm_bufcount; */
    /*     __u32 lm_buflens[0]; */
    /* }; */
    offset = dissect_struct_lustre_handle(tvb, offset, tree, hf_lustre_lustre_msg_v1_lm_handle);
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_lustre_msg_v1_lm_opc, tvb, offset, 4, ENC_LITTLE_ENDIAN, &trans->opcode);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_last_xid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_last_committed, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_transno, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_conn_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_lustre_lustre_msg_v1_lm_bufcount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &bufcount);
    offset += 4;

    for (i = 0; i < bufcount; ++i) {
        proto_tree_add_item(tree, hf_lustre_lustre_msg_v1_lm_buflens, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    // add padding if bufcount is odd
    if (bufcount & 1) {
        proto_tree_add_item(tree, hf_lustre_extra_padding, tvb, offset, 4, ENC_NA);
        offset += 4;
    }

    /* @@ HERE - Something, something, something ... */

    proto_item_set_len(tree, offset-old_offset);

    return offset;
}

static int
dissect_struct_msg_v2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, lustre_trans_t *trans)
{
    guint32 bufcount;
    int old_offset;
    guint32 i;
    guint32 buf_len_offset;
    guint32 current_buf_len;
    guint32 pb_type;

    old_offset = offset;

    /* struct lustre_msg_v2 { */
    /*   uint32 lm_bufcount; */
    /*   uint32 lm_secflvr; */
    /*   uint32 lm_magic; */
    /*   uint32 lm_repsize; */
    /*   uint32 lm_cksum; */
    /*   uint32 lm_flags; */
    /*   uint32 lm_padding_2; */
    /*   uint32 lm_padding_3; */
    /*   uint32 lm_buflens[0]; */
    /* } */
    proto_tree_add_item_ret_uint(tree, hf_lustre_lustre_msg_v2_lm_bufcount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &bufcount);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_secflvr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_repsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_cksum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_padding_2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_padding_3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    buf_len_offset=offset;
    for (i = 0; i < bufcount; ++i) {
        proto_tree_add_item(tree, hf_lustre_lustre_msg_v2_lm_buflens, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    /* we add an extra padding if bufcount is odd */
    if (bufcount & 1) {
        proto_tree_add_item(tree, hf_lustre_extra_padding, tvb, offset, 4, ENC_NA);
        offset += 4;
    }

    current_buf_len = tvb_get_letohl(tvb, buf_len_offset);
    offset = dissect_struct_ptlrpc_body(tvb, pinfo, tree, offset, current_buf_len, trans, &pb_type);

    offset = lustre_opcode_process(tvb, offset, pinfo, tree, trans, pb_type);

    proto_item_set_len(tree, offset-old_offset);

    return offset;
}


/********************************************************************\
 *
 * Core Functions
 *
\********************************************************************/

/* Code to actually dissect the packets */
static int
dissect_lustre(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint32 magic_number;
    guint offset = 0;
    proto_item *ti  = NULL;
    proto_tree *lustre_tree = NULL;
    struct lnet_trans_info *info = (struct lnet_trans_info *)data;
    lustre_trans_t *trans = lustre_get_trans(pinfo, info);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lustre");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_lustre, tvb, 0, -1, ENC_NA);
    lustre_tree = proto_item_add_subtree(ti, ett_lustre);

    magic_number = tvb_get_letohl(tvb, 8);

    switch (magic_number) {
      case MSG_MAGIC_V1:
        /* This hasn't been used since before Lustre 1.8.0 */
        expert_add_info(pinfo, tree, &ei_lustre_obsopc);
        proto_item_append_text(lustre_tree, " V1 ");
        offset = dissect_struct_msg_v1(tvb, offset, pinfo, lustre_tree, trans);
        break;

    case MSG_MAGIC_V2:
        /* put some nice info */
        proto_item_append_text(lustre_tree, " V2 ");
        offset = dissect_struct_msg_v2(tvb, offset, pinfo, lustre_tree, trans);
        break;

    default:
        expert_add_info(pinfo, lustre_tree, &ei_lustre_badmagic);
        break;
    }

    return offset;
}

void
proto_reg_handoff_lustre(void)
{
    dissector_handle_t lustre_handle;
    lustre_handle = create_dissector_handle(dissect_lustre, proto_lustre);
    /* we use Lustre only if we get ptl_index = One of this code (we have removed the bulk code) */
    /* in LNET we test if the message is a put or not before adding an lnet.ptl_index value */
    dissector_add_uint("lnet.ptl_index", MDC_REPLY_PORTAL,              lustre_handle);
    dissector_add_uint("lnet.ptl_index", CONNMGR_REQUEST_PORTAL,        lustre_handle);
    dissector_add_uint("lnet.ptl_index", CONNMGR_REPLY_PORTAL,          lustre_handle);
    dissector_add_uint("lnet.ptl_index", OSC_REPLY_PORTAL,              lustre_handle);
    dissector_add_uint("lnet.ptl_index", OST_IO_PORTAL,                 lustre_handle);
    dissector_add_uint("lnet.ptl_index", OST_CREATE_PORTAL,             lustre_handle);
    dissector_add_uint("lnet.ptl_index", MDC_REPLY_PORTAL,              lustre_handle);
    dissector_add_uint("lnet.ptl_index", MDS_REQUEST_PORTAL,            lustre_handle);
    dissector_add_uint("lnet.ptl_index", LDLM_CB_REQUEST_PORTAL,        lustre_handle);
    dissector_add_uint("lnet.ptl_index", LDLM_CB_REPLY_PORTAL,          lustre_handle);
    dissector_add_uint("lnet.ptl_index", LDLM_CANCEL_REQUEST_PORTAL,    lustre_handle);
    dissector_add_uint("lnet.ptl_index", LDLM_CANCEL_REPLY_PORTAL,      lustre_handle);
    dissector_add_uint("lnet.ptl_index", MDS_SETATTR_PORTAL,            lustre_handle);
    dissector_add_uint("lnet.ptl_index", MDS_READPAGE_PORTAL,           lustre_handle);
    dissector_add_uint("lnet.ptl_index", MGC_REPLY_PORTAL,              lustre_handle);
    dissector_add_uint("lnet.ptl_index", MGS_REQUEST_PORTAL,            lustre_handle);
    dissector_add_uint("lnet.ptl_index", MGS_REPLY_PORTAL,              lustre_handle);
    dissector_add_uint("lnet.ptl_index", OST_REQUEST_PORTAL,            lustre_handle);
    dissector_add_uint("lnet.ptl_index", FLD_REQUEST_PORTAL,            lustre_handle);
    dissector_add_uint("lnet.ptl_index", SEQ_METADATA_PORTAL,           lustre_handle);
    dissector_add_uint("lnet.ptl_index", SEQ_DATA_PORTAL,               lustre_handle);
    dissector_add_uint("lnet.ptl_index", SEQ_CONTROLLER_PORTAL,         lustre_handle);
}


/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_lustre(void)
{
    static hf_register_info hf[] = {
        /* Message V1 */
        { &hf_lustre_lustre_msg_v1_lm_magic,
          { "Lm Magic", "lustre.lustre_msg_v1.lm_magic", FT_UINT32, BASE_HEX, VALS(lustre_magic), 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_handle,
          { "Lm Handle", "lustre.lustre_msg_v1.lm_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_msg_v1_lm_last_xid,
          { "Lm Last Xid", "lustre.lustre_msg_v1.lm_last_xid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_status,
          { "Lm Status", "lustre.lustre_msg_v1.lm_status", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_type,
          { "Lm Type", "lustre.lustre_msg_v1.lm_type", FT_UINT32, BASE_DEC, VALS(lustre_LMTypes), 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_flags,
          { "Lm Flags", "lustre.lustre_msg_v1.lm_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_last_committed,
          { "Lm Last Committed", "lustre.lustre_msg_v1.lm_last_committed", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_buflens,
          { "Lm Buflens", "lustre.lustre_msg_v1.lm_buflens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_conn_cnt,
          { "Lm Conn Cnt", "lustre.lustre_msg_v1.lm_conn_cnt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_transno,
          { "Lm Transno", "lustre.lustre_msg_v1.lm_transno", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_opc,
          { "Lm Opc", "lustre.lustre_msg_v1.lm_opc", FT_UINT32, BASE_DEC, VALS(lustre_op_codes), 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_version,
          { "Lm Version", "lustre.lustre_msg_v1.lm_version", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v1_lm_bufcount,
          { "Lm Bufcount", "lustre.lustre_msg_v1.lm_bufcount", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* Message V2 */
        { &hf_lustre_lustre_msg_v2_lm_magic,
          { "Lm Magic", "lustre.lustre_msg_v2.lm_magic", FT_UINT32, BASE_HEX, VALS(lustre_magic), 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_bufcount,
          { "Lm Bufcount", "lustre.lustre_msg_v2.lm_bufcount", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_repsize,
          { "Lm Repsize", "lustre.lustre_msg_v2.lm_repsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_cksum,
          { "Lm Cksum", "lustre.lustre_msg_v2.lm_cksum", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_buflens,
          { "Lm Buflens", "lustre.lustre_msg_v2.lm_buflens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_flags,
          { "Lm Flags", "lustre.lustre_msg_v2.lm_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_secflvr,
          { "Lm Secflvr", "lustre.lustre_msg_v2.lm_secflvr", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_padding_2,
          { "Lm Padding 2", "lustre.lustre_msg_v2.lm_padding_2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lustre_msg_v2_lm_padding_3,
          { "Lm Padding 3", "lustre.lustre_msg_v2.lm_padding_3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /************************************************************
         * PTRL RPC
         */

        /* PTRL RPC BODY */
        { &hf_lustre_ptlrpc_body_pb,
          { "PTL RPC Body", "lustre.ptlrpc_body", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_last_committed,
          { "Pb Last Committed", "lustre.ptlrpc_body.pb_last_committed", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_version,
          { "Pb Version", "lustre.ptlrpc_body.pb_version", FT_UINT32, BASE_DEC, NULL, ~LUSTRE_VERSION_MASK, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_slv,
          { "Pb Slv", "lustre.ptlrpc_body.pb_slv", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_pre_version,
          { "Pb Pre-Version", "lustre.ptlrpc_body.pb_pre_version", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_padding,
          { "Pb Padding", "lustre.ptlrpc_body.pb_padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_jobid,
          { "Pb JobId", "lustre.ptlrpc_body.pb_jobid", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_timeout,
          { "Pb Timeout", "lustre.ptlrpc_body.pb_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_op_flags,
          { "Pb Op Flags", "lustre.ptlrpc_body.pb_op_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_type,
          { "Pb Type", "lustre.ptlrpc_body.pb_type", FT_UINT32, BASE_DEC, VALS(lustre_LMTypes), 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_flags,
          { "Pb Flags", "lustre.ptlrpc_body.pb_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_limit,
          { "Pb Limit", "lustre.ptlrpc_body.pb_limit", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_transno,
          { "Pb Transno", "lustre.ptlrpc_body.pb_transno", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_service_time,
          { "Pb Service Time", "lustre.ptlrpc_body.pb_service_time",FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_conn_cnt,
          { "Pb Conn Cnt", "lustre.ptlrpc_body.pb_conn_cnt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_opc,
          { "Pb Opc", "lustre.ptlrpc_body.pb_opc", FT_UINT32, BASE_DEC, VALS(lustre_op_codes), 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_last_seen,
          { "Pb Last Seen", "lustre.ptlrpc_body.pb_last_seen", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_last_xid,
          { "Pb Last Xid", "lustre.ptlrpc_body.pb_last_xid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_status,
          { "Pb Status", "lustre.ptlrpc_body.pb_status", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ptlrpc_body_pb_handle,
          { "Pb Handle", "lustre.ptlrpc_body.pb_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /************************************************************
         * MDT
         */

        { &hf_lustre_mdt_key,
          { "MDT key", "lustre.mdt_key", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_mdt_val,
          { "MDT val", "lustre.mdt_val", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},

        /* MDT Getinfo */
        { &hf_lustre_mdt_vallen,
          { "MDT Val Len", "lustre.vallen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

        /* MDT BODY */
        { &hf_lustre_mdt_body,
          { "MDT Body", "lustre.mdt_body", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL }},
        { &hf_lustre_mdt_body_fid1,
          { "Fid1", "lustre.mdt_body.fid1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_body_fid2,
          { "Fid2", "lustre.mdt_body.fid2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_body_handle,
          { "Handle", "lustre.mdt_body.handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_body_valid,
          { "Valid", "lustre.mdt_body.valid", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_size,
          { "Size", "lustre.mdt_body.size", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_mtime,
          { "Mtime", "lustre.mdt_body.mtime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_body_atime,
          { "Atime", "lustre.mdt_body.atime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_body_ctime,
          { "Ctime", "lustre.mdt_body.ctime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_body_blocks,
          { "Blocks", "lustre.mdt_body.blocks", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_ioepoch,
          { "Ioepoch", "lustre.mdt_body.ioepoch", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_ino,
          { "Ino", "lustre.mdt_body.ino", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_fsuid,
          { "Fsuid", "lustre.mdt_body.fsuid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_fsgid,
          { "Fsgid", "lustre.mdt_body.fsgid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_capability,
          { "Capability", "lustre.mdt_body.capability", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_mode,
          { "Mode", "lustre.mdt_body.mode", FT_UINT32, BASE_OCT, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_uid,
          { "Uid", "lustre.mdt_body.uid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_gid,
          { "Gid", "lustre.mdt_body.gid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_flags,
          { "Flags", "lustre.mdt_body.flags", FT_UINT32, BASE_HEX, VALS(lustre_mds_flags_vals) , 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_rdev,
          { "Rdev", "lustre.mdt_body.rdev", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_nlink,
          { "Nlink", "lustre.mdt_body.nlink", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_generation,
          { "Generation", "lustre.mdt_body.generation", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_suppgid,
          { "Suppgid", "lustre.mdt_body.suppgid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_eadatasize,
          { "Eadatasize", "lustre.mdt_body.eadatasize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_aclsize,
          { "Aclsize", "lustre.mdt_body.aclsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_max_mdsize,
          { "Max Mdsize", "lustre.mdt_body.max_mdsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_max_cookiesize,
          { "Max Cookiesize", "lustre.mdt_body.max_cookiesize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_uid_h,
          { "Uid H", "lustre.mdt_body.uid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_gid_h,
          { "Gid H", "lustre.mdt_body.gid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_padding_5,
          { "Padding 5", "lustre.mdt_body.padding_5", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_padding_6,
          { "Padding 6", "lustre.mdt_body.padding_6", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_padding_7,
          { "Padding 7", "lustre.mdt_body.padding_7", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_padding_8,
          { "Padding 8", "lustre.mdt_body.padding_8", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_padding_9,
          { "Padding 9", "lustre.mdt_body.padding_9", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_body_padding_10,
          { "Padding 10", "lustre.mdt_body.padding_10", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* Close Data */
        { &hf_lustre_close_data,
          { "MDT Close", "lustre.mdt_close", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_close_fid,
          { "Close FID", "lustre.mdt_close.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_close_handle,
          { "Close Handle", "lustre.mdt_close.handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_close_data_ver,
          { "Close Data Ver", "lustre.mdt_close.data_ver", FT_UINT64, BASE_HEX, NULL, 0, "Data version", HFILL } },
        { &hf_lustre_close_reserved,
          { "Close Reserved Space", "lustre.mdt_close.reserved", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* MDT REC REINT */
        { &hf_lustre_mdt_rec_reint,
          { "MDT ReInt", "lustre.mdt_rec_reint", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_opcode,
          { "Opcode", "lustre.mdt_rec_reint.opcode", FT_UINT32, BASE_DEC, VALS(mds_reint_vals), 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_cap,
          { "Cap", "lustre.mdt_rec_reint.cap", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_fsuid,
          { "Fsuid", "lustre.mdt_rec_reint.fsuid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_fsuid_h,
          { "Fsuid H", "lustre.mdt_rec_reint.fsuid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_fsgid,
          { "Fsgid", "lustre.mdt_rec_reint.fsgid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_fsgid_h,
          { "Fsgid H", "lustre.mdt_rec_reint.fsgid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_suppgid1,
          { "Suppgid1", "lustre.mdt_rec_reint.suppgid1", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_suppgid1_h,
          { "Suppgid1 H", "lustre.mdt_rec_reint.suppgid1_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_suppgid2,
          { "Suppgid2", "lustre.mdt_rec_reint.suppgid2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_suppgid2_h,
          { "Suppgid2 H", "lustre.mdt_rec_reint.suppgid2_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_fid1,
          { "Fid1", "lustre.mdt_rec_reint.fid1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_fid2,
          { "Fid2", "lustre.mdt_rec_reint.fid2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_old_handle,
          { "Old Handle", "lustre.mdt_rec_reint.old_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_lustre_mdt_rec_reint_mtime,
          { "Mod Time", "lustre.mdt_rec_reint.mtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_rec_reint_atime,
          { "Acc Time", "lustre.mdt_rec_reint.atime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_rec_reint_ctime,
          { "Cr  Time", "lustre.mdt_rec_reint.ctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_rec_reint_size64,
          { "Size", "lustre.mdt_rec_reint.size64", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_blocks,
          { "Blocks", "lustre.mdt_rec_reint.blocks", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_bias,
          { "Bias", "lustre.mdt_rec_reint.bias", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_mode,
          { "Mode", "lustre.mdt_rec_reint.mode", FT_UINT32, BASE_OCT, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_flags,
          { "Flags(L)", "lustre.mdt_rec_reint.flags", FT_UINT32, BASE_OCT, NULL, 0, "Low order flags", HFILL }},
        { &hf_lustre_mdt_rec_reint_flags_h,
          { "Flags(H)", "lustre.mdt_rec_reint.flags_h", FT_UINT32, BASE_OCT, NULL, 0, "High order flags", HFILL }},
        { &hf_lustre_mdt_rec_reint_attr_flags,
          { "Attr Flags", "lustre.mdt_rec_reint.attr_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_umask,
          { "Umask", "lustre.mdt_rec_reint.umask", FT_UINT32, BASE_OCT, NULL, 0, NULL, HFILL }},

        { &hf_lustre_mdt_rec_reint_time,
          { "Time", "lustre.mdt_rec_reint.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_rec_reint_size32,
          { "Size", "lustre.mdt_rec_reint.size32", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_rdev,
          { "RDev", "lustre.mdt_rec_reint.rdev", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_ioepoch,
          { "Ioepoch", "lustre.mdt_rec_reint.ioepoch", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_rec_reint_valid,
          { "Valid", "lustre.mdt_rec_reint.valid", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_uid,
          { "Uid", "lustre.mdt_rec_reint.uid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_gid,
          { "Gid", "lustre.mdt_rec_reint.gid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mdt_rec_reint_projid,
          { "ProjID", "lustre.mdt_rec_reint.projid", FT_UINT32, BASE_DEC, NULL, 0, "Project ID", HFILL }},
        { &hf_lustre_mdt_rec_reint_padding,
          { "Padding", "lustre.mdt_rec_reint.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* struct mdt_ioepoch */
        { &hf_lustre_mdt_ioepoch,
          { "MDT ioepoch", "lustre.mdt_ioepoch", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_ioepoch_ioepoch,
          { "Ioepoch", "lustre.mdt_ioepoch.ioepoch", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_ioepoch_flags,
          { "Flags", "lustre.mdt_ioepoch.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_ioepoch_padding,
          { "Padding", "lustre.mdt_ioepoch.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdt_ioepoch_handle,
          { "Handle", "lustre.mdt_ioepoch.handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* struct mdc_swap_layouts */
        { &hf_lustre_mdc_swap_layouts,
          { "MDC Swap Layouts", "lustre.mdc_swap_layouts", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_mdc_swap_layouts_flags,
          { "Flags", "lustre.mdc_swap_layouts.flags", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },


        /************************************************************
         * HSM
         */

        /* HSM Request */
        { &hf_lustre_hsm_req,
          { "HSM Request", "lustre.hsm_req", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_req_action,
          { "HR Action", "lustre.hsm_req.action", FT_UINT32, BASE_HEX, VALS(hsm_user_action_vals), 0, NULL, HFILL } },
        { &hf_lustre_hsm_req_archive_id,
          { "HR Archive ID", "lustre.hsm_req.archive_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_req_flags,
          { "HR Flags", "lustre.hsm_req.flags", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_req_itemcount,
          { "HR Itemcount", "lustre.hsm_req.itemcount", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_req_data_len,
          { "HR Data Length", "lustre.hsm_req.data_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

        /* HSM EXTENT */
        { &hf_lustre_hsm_extent,
          { "HSM Extent", "lustre.hsm_extent", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_extent_offset,
          { "Offset", "lustre.hsm_extent.offset", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_extent_length,
          { "Length", "lustre.hsm_extent.len", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },

        /* HSM PROGRESS */
        { &hf_lustre_hsm_prog,
          { "HSM Progress", "lustre.hsm_progress", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_fid,
          { "HSM Prog FID", "lustre.hsm_progress.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_cookie,
          { "HSM Prog Cookie", "lustre.hsm_progress.cookie", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_flags,
          { "HSM Prog Flags", "lustre.hsm_progress.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_errval,
          { "HSM Prog Error Val", "lustre.hsm_progress.errval", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_data_ver,
          { "HSM Prog Data Version", "lustre.hsm_progress.data_ver", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_padding1,
          { "HSM Padding1", "lustre.hsm_progress.padding1", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_prog_padding2,
          { "HSM Padding2", "lustre.hsm_progress.padding2", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },

        /* HSM STATE GET */
        { &hf_lustre_hsm_user_state,
          { "HSM User State", "lustre.hsm_state_get", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_us_states,
          { "States", "lustre.hsm_state_get.states", FT_UINT32, BASE_HEX, VALS(hsm_state_vals), 0, NULL, HFILL } },
        { &hf_lustre_hsm_us_archive_id,
          { "Archive ID", "lustre.hsm_state_get.archive_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_us_in_prog_state,
          { "In Progress State", "lustre.hsm_state_get.in_prog.state",
            FT_UINT32, BASE_HEX, VALS(hsm_progress_state_vals), 0, NULL, HFILL } },
        { &hf_lustre_hsm_us_in_prog_action,
          { "In Progress Action", "lustre.hsm_state_get.in_prog.action",
            FT_UINT32, BASE_HEX, VALS(hsm_user_action_vals), 0, NULL, HFILL } },
        { &hf_lustre_hsm_us_ext_info,
          { "Extended Info", "lustre.hsm_state_get.ext_info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

       /* HSM STATE SET */
        { &hf_lustre_hsm_state_set,
          { "HSM State Set", "lustre.hsm_state_set", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_hss_valid,
          { "Valid", "lustre.hsm_state_set.valid", FT_UINT32, BASE_HEX, VALS(hss_valid), 0, NULL, HFILL } },
        { &hf_lustre_hsm_hss_archive_id,
          { "Archive Id", "lustre.hsm_state_set.archive_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_hss_setmask,
          { "Set Mask", "lustre.hsm_state_set.setmask",
            FT_UINT32, BASE_HEX, VALS(hsm_state_vals), 0, NULL, HFILL } },
        { &hf_lustre_hsm_hss_clearmask,
          { "Clear Mask", "lustre.hsm_state_set.clearmask",
            FT_UINT32, BASE_HEX, VALS(hsm_state_vals), 0, NULL, HFILL } },

       /* HSM CURRENT ACTION */
        { &hf_lustre_hsm_current_action,
          { "HSM Current Action", "lustre.hsm_current_action", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_current_action_state,
          { "State", "lustre.hsm_current_action.state", FT_UINT32, BASE_HEX, VALS(hsm_progress_state_vals), 0, NULL, HFILL } },
        { &hf_lustre_hsm_current_action_action,
          { "Action", "lustre.hsm_current_action.action", FT_UINT32, BASE_HEX, VALS(hsm_user_action_vals), 0, NULL, HFILL } },

        /* HSM ARCHIVE */
        { &hf_lustre_hsm_archive,
          { "HSM Archive", "lustre.hsm_archive", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_hsm_archive_id,
          { "ID", "lustre.hsm_archive.id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},


        /************************************************************
         * OBD
         */

        /* OBD IO Object */
        { &hf_lustre_obd_ioobj,
          { "OBD IO OBJ", "lustre.obd_ioobj", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_ioobj_ioo_id,
          { "Ioo Id", "lustre.obd_ioobj.ioo_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_ioobj_ioo_seq,
          { "Ioo Gr", "lustre.obd_ioobj.ioo_seq", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_ioobj_ioo_max_brw,
          { "Ioo Max BRW Size", "lustre.obd_ioobj.ioo_max_brw", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_ioobj_ioo_bufcnt,
          { "Ioo Bufcnt", "lustre.obd_ioobj.ioo_bufcnt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* OBD STATFS */
         { &hf_lustre_obd_statfs,
          { "OBD Statfs", "lustre.obd_statfs", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
       { &hf_lustre_obd_statfs_os_type,
          { "Os Type", "lustre.obd_statfs.os_type", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_bavail,
          { "Os Bavail", "lustre.obd_statfs.os_bavail", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_bsize,
          { "Os Bsize", "lustre.obd_statfs.os_bsize", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_maxbytes,
          { "Os Maxbytes", "lustre.obd_statfs.os_maxbytes", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_ffree,
          { "Os Ffree", "lustre.obd_statfs.os_ffree", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_files,
          { "Os Files", "lustre.obd_statfs.os_files", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_bfree,
          { "Os Bfree", "lustre.obd_statfs.os_bfree", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_namelen,
          { "Os Namelen", "lustre.obd_statfs.os_namelen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_blocks,
          { "Os Blocks", "lustre.obd_statfs.os_blocks", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_fsid,
          { "Os Fsid", "lustre.obd_statfs.os_fsid", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_state,
          { "Os State", "lustre.obd_statfs.os_state", FT_UINT32, BASE_HEX, VALS(obd_statfs_state), 0, NULL, HFILL }},
        { &hf_lustre_obd_statfs_os_fprecreated,
          { "Os F Precreate", "lustre.obd_statfs.os_fprecreated", FT_UINT32, BASE_DEC, NULL, 0, "objs available now to the caller", HFILL }},
        { &hf_lustre_obd_statfs_os_spare,
          { "Os Spare", "lustre.obd_statfs.os_spare", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* OBD Connect Data */
        { &hf_lustre_obd_connect_data,
          { "OBD Connect Data", "lustre.obd_connect_data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_connect_flags,
          { "Ocd Connect Flags", "lustre.obd_connect_data.ocd_connect_flags", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_version,
          { "Ocd Version", "lustre.obd_connect_data.ocd_version", FT_UINT32, BASE_CUSTOM, CF_FUNC(lustre_fmt_ver), 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_grant,
          { "Ocd Grant", "lustre.obd_connect_data.ocd_grant", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_index,
          { "Ocd Index", "lustre.obd_connect_data.ocd_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_brw_size,
          { "Ocd Brw Size", "lustre.obd_connect_data.ocd_brw_size", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_ibits_known,
          { "Ocd Ibits Known", "lustre.obd_connect_data.ocd_ibits_known", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        /* reversioned elements */
        { &hf_lustre_obd_connect_data_ocd_nllg,
          { "Ocd Nllg", "lustre.obd_connect_data.ocd_nllg", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_nllu,
          { "Ocd Nllu", "lustre.obd_connect_data.ocd_nllu", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_grant_blkbits,
          { "Ocd Grant blkbits", "lustre.obd_connect_data.grant_blkbits", FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_grant_inobits,
          { "Ocd Grant inobits", "lustre.obd_connect_data.grant_inobits", FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_grant_tax_kb,
          { "Ocd Grant tax kb", "lustre.obd_connect_data.grant_tax_kb", FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_grant_max_blks,
          { "Ocd Grant max blks", "lustre.obd_connect_data.grant_max_blks", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        /* end */
        { &hf_lustre_obd_connect_data_ocd_transno,
          { "Ocd Transno", "lustre.obd_connect_data.ocd_transno", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_group,
          { "Ocd Group", "lustre.obd_connect_data.ocd_group", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_connect_data_ocd_cksum_types,
          { "Ocd Cksum Types", "lustre.obd_connect_data.ocd_cksum_types", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_max_easize,
            { "Ocd Max LOV EA Size", "lustre.obd_connect_data.ocd_max_easize", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_instance,
            { "Ocd Instance", "lustre.obd_connect_data.ocd_instance", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_maxbytes,
            { "Ocd Max Stripe Size (Bytes)", "lustre.obd_connect_data.ocd_maxbytes", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_maxmodrpcs,
            { "Ocd Max Parallel Modify RPCs", "lustre.obd_connect_data.ocd_maxmodrpcs", FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_connect_flags2,
          { "Ocd Connect Flags", "lustre.obd_connect_data.ocd_connect_flags2", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_connect_data_ocd_padding,
          { "Ocd Padding", "lustre.obd_connect_data.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* OBD UID */
        { &hf_lustre_obd_uuid,
          { "obd uuid name", "lustre.obd_uuid", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},

        /* OBD Quota Control */
        { &hf_lustre_obd_quotactl,
          { "OBD QuotaCtl", "lustre.obd_quotactl", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_quotactl_qc_stat,
          { "Qc Stat", "lustre.obd_quotactl.qc_stat", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_quotactl_qc_cmd,
          { "Qc Cmd", "lustre.obd_quotactl.qc_cmd", FT_UINT32, BASE_HEX, VALS(quota_cmd_vals), 0, NULL, HFILL }},
        { &hf_lustre_obd_quotactl_qc_id,
          { "Qc Id", "lustre.obd_quotactl.qc_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_quotactl_qc_type,
          { "Qc Type", "lustre.obd_quotactl.qc_type", FT_UINT32, BASE_DEC, VALS(quota_type_vals), 0, NULL, HFILL }},

        /* Data Quota Info */
        { &hf_lustre_obd_dqblk,
          { "OBD DQ BLK", "lustre.obd_dqblk", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_isoftlimit,
          { "Dqb Isoftlimit", "lustre.obd_dqblk.dqb_isoftlimit", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_bhardlimit,
          { "Dqb Bhardlimit", "lustre.obd_dqblk.dqb_bhardlimit", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_curspace,
          { "Dqb Curspace", "lustre.obd_dqblk.dqb_curspace", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_itime,
          { "Dqb Itime", "lustre.obd_dqblk.dqb_itime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_dqblk_dqb_valid,
          { "Dqb Valid", "lustre.obd_dqblk.dqb_valid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_padding,
          { "Padding", "lustre.obd_dqblk.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_curinodes,
          { "Dqb Curinodes", "lustre.obd_dqblk.dqb_curinodes", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_bsoftlimit,
          { "Dqb Bsoftlimit", "lustre.obd_dqblk.dqb_bsoftlimit", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqblk_dqb_btime,
          { "Dqb Btime", "lustre.obd_dqblk.dqb_btime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obd_dqblk_dqb_ihardlimit,
          { "Dqb Ihardlimit", "lustre.obd_dqblk.dqb_ihardlimit", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },

        /* Data Quota BLK */
        { &hf_lustre_obd_dqinfo,
          { "OBD DQ Info", "lustre.obd_dqinfo", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqinfo_dqi_valid,
          { "Dqi Valid", "lustre.obd_dqinfo.dqi_valid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqinfo_dqi_igrace,
          { "Dqi Igrace", "lustre.obd_dqinfo.dqi_igrace", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqinfo_dqi_bgrace,
          { "Dqi Bgrace", "lustre.obd_dqinfo.dqi_bgrace", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obd_dqinfo_dqi_flags,
          { "Dqi Flags", "lustre.obd_dqinfo.dqi_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

        /************************************************************
         * OST
         */

        { &hf_lustre_ost_body,
          { "OST Body", "lustre.ost_body", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_ost_key,
          { "lustre ost key", "lustre.ost_key", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_ost_val,
          { "lustre ost val", "lustre.ost_val", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},

        /* OST LVB */
        { &hf_lustre_ost_lvb,
          { "OST LVB", "lustre.ost_lvb", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_lvb_atime,
          { "Lvb Atime", "lustre.ost_lvb.lvb_atime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ost_lvb_ctime,
          { "Lvb Ctime", "lustre.ost_lvb.lvb_ctime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ost_lvb_mtime,
          { "Lvb Mtime", "lustre.ost_lvb.lvb_mtime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ost_lvb_mtime_ns,
          { "Lvb Mtime NS", "lustre.ost_lvb.lvb_mtime_ns", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_lvb_atime_ns,
          { "Lvb Atime NS", "lustre.ost_lvb.lvb_atime_ns", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_lvb_ctime_ns,
          { "Lvb Ctime NS", "lustre.ost_lvb.lvb_ctime_ns", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_lvb_size,
          { "Lvb Size", "lustre.ost_lvb.lvb_size", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_lvb_blocks,
          { "Lvb Blocks", "lustre.ost_lvb.lvb_blocks", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_lvb_padding,
          { "padding", "lustre.ost_lvb.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* OST ID */
        { &hf_lustre_ost_id,
          { "OST ID [UNION]", "lustre.ost_id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_id_fid,
          { "FID", "lustre.ost_id.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_id_oi,
          { "OI", "lustre.ost_id.oi", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* OST Layout */
        { &hf_lustre_ost_layout,
          { "OST Layout", "lustre.ost_layout", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_layout_stripe_size,
          { "OL Strip Size", "lustre.ost_layout.stripe_size", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_layout_stripe_count,
          { "OL Strip Count", "lustre.ost_layout.stripe_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_layout_comp_start,
          { "OL Comp Start", "lustre.ost_layout.comp_start", FT_UINT64, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_layout_comp_end,
          { "OL Comp End", "lustre.ost_layout.comp_end", FT_UINT64, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_layout_comp_id,
          { "OL Comp ID", "lustre.ost_layout.comp_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_lustre_lu_ladvise_hdr,
          { "LAdvise Hdr", "lustre.lu_ladvise_hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_hdr_magic,
          { "LAH Magic", "lustre.lu_ladvise_hdr.lah_magic", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_hdr_count,
          { "LAH Count", "lustre.lu_ladvise_hdr.lah_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_hdr_flags,
          { "LAH Flags", "lustre.lu_ladvise_hdr.lah_flags", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_hdr_value1,
          { "LAH Value1", "lustre.lu_ladvise_hdr.lah_value1", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_hdr_value2,
          { "LAH Value2", "lustre.lu_ladvise_hdr.lah_value2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_hdr_value3,
          { "LAH Value3", "lustre.lu_ladvise_hdr.lah_value3", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_lustre_lu_ladvise,
          { "LAdvise", "lustre.lu_ladvise", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_advice,
          { "LAH Advice", "lustre.lu_ladvise.lla_advice", FT_UINT16, BASE_HEX, VALS(lu_ladvise_type_vals), 0, "advice type", HFILL }},
        { &hf_lustre_lu_ladvise_value1,
          { "LAH Value1", "lustre.lu_ladvise.lla_value1", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_value2,
          { "LAH Value2", "lustre.lu_ladvise.lla_value2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_start,
          { "LAH Flags", "lustre.lu_ladvise.lla_start", FT_UINT64, BASE_HEX, NULL, 0, "first byte of extent for advice", HFILL }},
        { &hf_lustre_lu_ladvise_end,
          { "LAH Flags", "lustre.lu_ladvise.lla_end", FT_UINT64, BASE_HEX, NULL, 0, "last byte of extent for advice", HFILL }},
        { &hf_lustre_lu_ladvise_value3,
          { "LAH Value3", "lustre.lu_ladvise.lla_value3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_ladvise_value4,
          { "LAH Value4", "lustre.lu_ladvise.lla_value4", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /************************************************************
         * LLOG
         */

        /* llogd */

        { &hf_lustre_llogd_body,
          { "llogd body", "lustre.llogd_body", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_llogd_body_lgd_len,
          { "Lgd Len", "lustre.llogd_body.lgd_len", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llogd_body_lgd_logid,
          { "Lgd Logid", "lustre.llogd_body.lgd_logid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llogd_body_lgd_index,
          { "Lgd Index", "lustre.llogd_body.lgd_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llogd_body_lgd_saved_index,
          { "Lgd Saved Index", "lustre.llogd_body.lgd_saved_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llogd_body_lgd_llh_flags,
          { "Lgd Llh Flags", "lustre.llogd_body.lgd_llh_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llogd_body_lgd_cur_offset,
          { "Lgd Cur Offset", "lustre.llogd_body.lgd_cur_offset", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llogd_body_lgd_ctxt_idx,
          { "Lgd Ctxt Idx", "lustre.llogd_body.lgd_ctxt_idx", FT_UINT32, BASE_DEC, VALS(llog_ctxt_id_vals), 0, NULL, HFILL }},

        { &hf_lustre_llogd_conn_body,
          { "LLOGd Conn Body", "lustre.llogd_conn_body", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llogd_conn_body_lgdc_gen,
          { "Lgdc Gen", "lustre.llogd_conn_body.lgdc_gen", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llogd_conn_body_lgdc_logid,
          { "Lgdc Logid", "lustre.llogd_conn_body.lgdc_logid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llogd_conn_body_lgdc_ctxt_idx,
          { "Lgdc Ctxt Idx", "lustre.llogd_conn_body.lgdc_ctxt_idx", FT_UINT32, BASE_DEC, VALS(llog_ctxt_id_vals), 0, NULL, HFILL }},

        /* llog */

        /* Generic LLOG Record Entry */
        { &hf_lustre_llog_rec,
          { "LLOG Record", "lustre.llog_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_rec_hdr,
          { "LLOG REC Hdr", "lustre.llog_rec_hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_rec_tail,
          { "LLOG REC Tail", "lustre.llog_rec_tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* LLOG REC Header */
        { &hf_lustre_llog_rec_hdr_lrh_type,
          { "Lrh Type", "lustre.llog_rec_hdr.lrh_type", FT_UINT32, BASE_HEX, VALS(llog_op_types), 0, NULL, HFILL }},
        { &hf_lustre_llog_rec_hdr_lrh_len,
          { "Lrh Len", "lustre.llog_rec_hdr.lrh_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_rec_hdr_lrh_index,
          { "Lrh Index", "lustre.llog_rec_hdr.lrh_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_rec_hdr_lrh_id,
          { "Lrh Id", "lustre.llog_rec_hdr.lrh_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LLOG REC Tail */
        { &hf_lustre_llog_rec_tail_lrt_index,
          { "Lrt Index", "lustre.llog_rec_tail.lrt_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_rec_tail_lrt_len,
          { "Lrt Len", "lustre.llog_rec_tail.lrt_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LLOG Log Header */
        { &hf_lustre_llog_log_hdr,
          { "LLOG Log Hdr", "lustre.llogd_log_hdr", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_llog_log_hdr_tgtuuid,
          { "Llh Tgtuuid", "lustre.llog_log_hdr.llh_tgtuuid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_log_hdr_cat_idx,
          { "Llh Cat Idx", "lustre.llog_log_hdr.llh_cat_idx", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_log_hdr_bitmap_offset,
          { "Llh Bitmap Offset", "lustre.llog_log_hdr.llh_bitmap_offset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_log_hdr_flags,
          { "Llh Flags", "lustre.llog_log_hdr.llh_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_log_hdr_size,
          { "Llh Size", "lustre.llog_log_hdr.llh_size", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_log_hdr_tail,
          { "Llh Tail", "lustre.llog_log_hdr.llh_tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_log_hdr_bitmap,
          { "Llh Bitmap", "lustre.llog_log_hdr.llh_bitmap", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_log_hdr_count,
          { "Llh Count", "lustre.llog_log_hdr.llh_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_log_hdr_timestamp,
          { "Llh Timestamp", "lustre.llog_log_hdr.llh_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_log_hdr_hdr,
          { "Llh Hdr", "lustre.llog_log_hdr.llh_hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_log_hdr_reserved,
          { "Llh Reserved", "lustre.llog_log_hdr.llh_reserved", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        /* LLOG log header flags */
        { &hf_lustre_llog_hdr_flag_zap_when_empty,
          {"LLOG_F_ZAP_WHEN_EMPTY", "lustre.llog_log_hdr.llh_flags.zap_when_empty", FT_BOOLEAN, 32,
           TFS(&lnet_flags_set_truth), LLOG_F_ZAP_WHEN_EMPTY, NULL, HFILL } },
        { &hf_lustre_llog_hdr_flag_is_cat,
          { "LLOG_F_IS_CAT", "lustre.llog_log_hdr.llh_flags.is_cat", FT_BOOLEAN, 32,
            TFS(&lnet_flags_set_truth), LLOG_F_IS_CAT, NULL, HFILL } },
        { &hf_lustre_llog_hdr_flag_is_plain,
          { "LLOG_F_IS_PLAIN", "lustre.llog_log_hdr.llh_flags.is_plain", FT_BOOLEAN, 32,
            TFS(&lnet_flags_set_truth), LLOG_F_IS_PLAIN, NULL, HFILL } },
        { &hf_lustre_llog_hdr_flag_ext_jobid,
          { "LLOG_F_EXT_JOBID", "lustre.llog_log_hdr.llh_flags.ext_jobid", FT_BOOLEAN, 32,
            TFS(&lnet_flags_set_truth), LLOG_F_EXT_JOBID, NULL, HFILL } },
        { &hf_lustre_llog_hdr_flag_is_fixsize,
          { "LLOG_F_IS_FIXSIZE", "lustre.llog_log_hdr.llh_flags.is_fixsize", FT_BOOLEAN, 32,
            TFS(&lnet_flags_set_truth), LLOG_F_IS_FIXSIZE, NULL, HFILL } },

        /* LLOG LOGID REC */
        { &hf_lustre_llog_logid_rec,
          { "LLOG LogID Rec", "lustre.llog_logid_rec", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_llog_logid_rec_hdr,
          { "Lid Hdr", "lustre.llog_logid_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_logid_rec_tail,
          { "Lid Tail", "lustre.llog_logid_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_logid_rec_id,
          { "Lid Id", "lustre.llog_logid_rec.id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_logid_rec_padding,
          { "Padding", "lustre.llog_logid_rec.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LLOG LOGID */
        { &hf_lustre_llog_logid_lgl_ogen,
          { "Lgl Ogen", "lustre.llog_logid.lgl_ogen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LLOG GEN REC */
        { &hf_lustre_llog_gen_rec,
          { "LLOG Gen Rec", "lustre.llog_gen_rec", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_llog_gen_rec_hdr,
          { "Lgr Hdr", "lustre.llog_gen_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_gen_rec_tail,
          { "Lgr Tail", "lustre.llog_gen_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_gen_rec_gen,
          { "Lgr Gen", "lustre.llog_gen_rec.gen", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_gen_rec_padding,
          { "padding", "lustre.llog_gen_rec.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LLOG UNLINK REC */
        { &hf_lustre_llog_unlink_rec,
          { "LLOG Unlink", "lustre.llog_unlink_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink_rec_hdr,
          { "Lur Hdr", "lustre.llog_unlink_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink_rec_tail,
          { "Lur Tail", "lustre.llog_unlink_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink_rec_oseq,
          { "Lur Oseq", "lustre.llog_unlink_rec.oseq", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_unlink_rec_oid,
          { "Lur Oid", "lustre.llog_unlink_rec.oid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_unlink_rec_count,
          { "Padding", "lustre.llog_unlink_rec.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LLOG Size Change */
        { &hf_lustre_llog_unlink64_rec,
          { "LLOG Unlink64", "lustre.llog_unlink64_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink64_rec_hdr,
          { "Lsc Hdr", "lustre.llog_unlink64_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink64_rec_count,
          { "Lsc Count", "lustre.llog_unlink64_rec.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_unlink64_rec_fid,
          { "Lsc Fid", "lustre.llog_unlink64_rec.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink64_rec_tail,
          { "Lsc Tail", "lustre.llog_unlink64_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_unlink64_rec_padding,
          { "Padding", "lustre.llog_unlink64_rec.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},


        /* LLOG Size Change */
        { &hf_lustre_llog_size_change_rec,
          { "LLOG Size Chg", "lustre.llog_size_change_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_size_change_rec_hdr,
          { "Lsc Hdr", "lustre.llog_size_change_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_size_change_rec_io_epoch,
          { "Lsc Io Epoch", "lustre.llog_size_change_rec.io_epoch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_size_change_rec_fid,
          { "Lsc Fid", "lustre.llog_size_change_rec.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_size_change_rec_tail,
          { "Lsc Tail", "lustre.llog_size_change_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_size_change_rec_padding,
          { "Padding", "lustre.llog_size_change_rec.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LLOG Cookie */
        { &hf_lustre_llog_cookie,
          { "LLOG Cookie", "lustre.llog_cookie", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_cookie_lgc_lgl,
          { "Lgc lgl", "lustre.llog_cookie.lgc_lgl", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_cookie_lgc_padding,
          { "Lgc Padding", "lustre.llog_cookie.lgc_padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_cookie_lgc_index,
          { "Lgc Index", "lustre.llog_cookie.lgc_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_cookie_lgc_subsys,
          { "Lgc Subsys", "lustre.llog_cookie.lgc_subsys", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LLOG CHANGELOG REC */
        { &hf_lustre_llog_changelog_rec,
          { "LLOG ChangeLog", "lustre.llog_changelog_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_changelog_rec_hdr,
          { "Cr Hdr", "lustre.llog_changelog_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_changelog_rec_tail,
          { "Cr Tail", "lustre.llog_changelog_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_lustre_changelog_rec,
          { "ChangeLog", "lustre.changelog_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_changelog_rec_namelen,
          { "Cr Name Len", "lustre.changelog_rec.namelen", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_changelog_rec_flags,
          { "Cr Flags", "lustre.changelog_rec.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_changelog_rec_type,
          { "Cr Type", "lustre.changelog_rec.type", FT_UINT32, BASE_DEC, VALS(changelog_rec_type_vals), 0, NULL, HFILL }},
        { &hf_lustre_changelog_rec_index,
          { "Cr Index", "lustre.changelog_rec.index", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_changelog_rec_prev,
          { "Cr Prev", "lustre.changelog_rec.prev", FT_UINT64, BASE_DEC, NULL, 0, "Previous Index", HFILL }},
        { &hf_lustre_changelog_rec_time,
          { "Cr Time", "lustre.changelog_rec.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
        { &hf_lustre_changelog_rec_tfid,
          { "Cr TFid", "lustre.changelog_rec.tfid", FT_NONE, BASE_NONE, NULL, 0, "Target FID", HFILL } },
        { &hf_lustre_changelog_rec_markerflags,
          { "Cr Mrk Flags", "lustre.changelog_rec.markerflags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_changelog_rec_padding,
          { "padding", "lustre.changelog_rec.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_changelog_rec_pfid,
          { "Cr PFid", "lustre.changelog_rec.tfid", FT_NONE, BASE_NONE, NULL, 0, "Parent FID", HFILL } },

        { &hf_lustre_changelog_ext_rename_sfid,
          { "Cr sFid", "lustre.changelog_ext_rename.sfid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_changelog_ext_rename_spfid,
          { "Cr spFid", "lustre.changelog_ext_rename.spfid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_lustre_changelog_ext_jobid_jobid,
          { "Cr JobID", "lustre.changelog_ext_jobid.jobid", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_lustre_changelog_extra_flags_extra_flags,
          { "Cr Extra Flags", "lustre.changelog_extra_flags.extra_flags", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_lustre_changelog_ext_name,
          { "Cr Name", "lustre.changelog_ext_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* LLOG GEN */
        { &hf_lustre_llog_gen_conn_cnt,
          { "Conn Cnt", "lustre.llog_gen.conn_cnt", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_gen_mnt_cnt,
          { "Mnt Cnt", "lustre.llog_gen.mnt_cnt", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LLOG SETATTR REC */
        { &hf_lustre_llog_setattr_rec,
          { "LLOG SetAttr", "lustre.llog_setattr_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_setattr_rec_hdr,
          { "Lsr Hdr", "lustre.llog_setattr_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_setattr_rec_oseq,
          { "Lsr Oseq", "lustre.llog_setattr_rec.oseq", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr_rec_padding,
          { "Padding", "lustre.llog_setattr_rec.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr_rec_uid,
          { "Lsr Uid", "lustre.llog_setattr_rec.uid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr_rec_oid,
          { "Lsr Oid", "lustre.llog_setattr_rec.oid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr_rec_gid,
          { "Lsr Gid", "lustre.llog_setattr_rec.gid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr_rec_tail,
          { "Lsr Tail", "lustre.llog_setattr_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Lustre CFG */
        { &hf_lustre_lustre_cfg,
          { "Lustre CFG", "lustre.lustre_cfg", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_version,
          { "Lcfg Version", "lustre.lustre_cfg.version", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_command,
          { "Lcfg Cmd", "lustre.lustre_cfg.command", FT_UINT32, BASE_HEX, VALS(lcfg_command_type_vals), 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_num,
          { "Lcfg Num", "lustre.lustre_cfg.num", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_flags,
          { "Lcfg Flags", "lustre.lustre_cfg.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_nid,
          { "Lcfg Nid", "lustre.lustre_cfg.nid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_padding,
          { "padding", "lustre.lustre_cfg.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_bufcount,
          { "Lcfg Buf Cnt", "lustre.lustre_cfg.bufcount", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_buflen,
          { "Lcfg Buf Len", "lustre.lustre_cfg.buflen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_cfg_buffer,
          { "Lcfg Buffer", "lustre.lustre_cfg.buffer", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* CFG MARKER */
        { &hf_lustre_cfg_marker,
          { "CFG Marker", "lustre.cfg_marker", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_step,
          { "CM Step", "lustre.cfg_maker.step", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_flags,
          { "CM Flags", "lustre.cfg_maker.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_vers,
          { "CM Vers", "lustre.cfg_maker.vers", FT_UINT32, BASE_CUSTOM, CF_FUNC(lustre_fmt_ver), 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_padding,
          { "padding", "lustre.cfg_maker.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_createtime,
          { "CM Create Time", "lustre.cfg_maker.createtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_canceltime,
          { "CM Cancel Time", "lustre.cfg_maker.canceltime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_tgtname,
          { "CM Tgt Name", "lustre.cfg_maker.tgtname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_cfg_marker_comment,
          { "CM Comment", "lustre.cfg_maker.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* LLOG SETATTR64 REC */
        { &hf_lustre_llog_setattr64_rec,
          { "LLOG SetAttr", "lustre.llog_setattr64_rec", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_setattr64_rec_hdr,
          { "Lsr Hdr", "lustre.llog_setattr64_rec.hdr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_llog_setattr64_rec_uid,
          { "Lsr Uid", "lustre.llog_setattr64_rec.uid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr64_rec_uid_h,
          { "Lsr Uid", "lustre.llog_setattr64_rec.uid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr64_rec_gid,
          { "Lsr Gid", "lustre.llog_setattr64_rec.gid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr64_rec_gid_h,
          { "Lsr Gid", "lustre.llog_setattr64_rec.gid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr64_rec_valid,
          { "Lsr Oid", "lustre.llog_setattr64_rec.valid", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_llog_setattr64_rec_tail,
          { "Lsr Tail", "lustre.llog_setattr64_rec.tail", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /************************************************************
         * NIO
         */

        /* NIO Remote Buffer */
        { &hf_lustre_niobuf_remote,
          { "NIO Buffer", "lustre.niobuf_remote", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_niobuf_remote_offset,
          { "Offset", "lustre.niobuf_remote.offset", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_niobuf_remote_len,
          { "Length", "lustre.niobuf_remote.len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_niobuf_remote_flags,
          { "Flags", "lustre.niobuf_remote.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_lustre_rcs,
          { "RCs", "lustre.rcs", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_rcs_rc,
          { "RC", "lustre.rcs.rc", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* FID Array */
        { &hf_lustre_fid_array,
          { "Fid Array", "lustre.fid_array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_fid_array_fid,
          { "FID", "lustre.fid_array.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /************************************************************
         * LOV
         */

        /* LOV OST Data */
        { &hf_lustre_lov_ost_data_v1,
          { "LOV OST Data V1", "lustre.lov_ost_data_v1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_ost_data_v1_l_ost_gen,
          { "L Ost Gen", "lustre.lov_ost_data_v1.l_ost_gen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_ost_data_v1_l_ost_idx,
          { "L Ost Idx", "lustre.lov_ost_data_v1.l_ost_idx", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LOV MDS MD */
        { &hf_lustre_lmv_mds_md,
          { "LMV MDS MD", "lustre.lmv_mds_md", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_magic,
          { "Lmv Magic", "lustre.lmv_mds_md.magic", FT_UINT32, BASE_HEX, VALS(lustre_magic), 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_stripe_count,
          { "Lmv Stripe Count", "lustre.lmv_mds_md.stripe_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_master_mdt_index,
          { "Lmv Mast MDT Ind", "lustre.lmv_mds_md.master_mdt_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_hash_type,
          { "Lmv Hash Type", "lustre.lmv_mds_md.hash_type", FT_UINT32, BASE_DEC, VALS(lmv_hash_type_vals), LMV_HASH_TYPE_MASK, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_status,
          { "Lmv Status", "lustre.lmv_mds_md.status", FT_UINT32, BASE_HEX, NULL, ~LMV_HASH_TYPE_MASK, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_layout_version,
          { "Lmv Layout Ver", "lustre.lmv_mds_md.layout_version", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_padding,
          { "Lmv padding", "lustre.lmv_mds_md.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_pool_name,
          { "Lmv Pool Name", "lustre.lmv_mds_md.pool_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lmv_mds_md_stripe_fid,
          { "Lmv Stripe FID", "lustre.lmv_mds_md.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LOV MDS MD */
        { &hf_lustre_lov_mds_md,
          { "LOV MDS MD", "lustre.lov_mds_md", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_magic,
          { "Lmm Magic", "lustre.lov_mds_md.lmm_magic", FT_UINT32, BASE_HEX, VALS(lustre_magic), 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_pattern,
          { "Lmm Pattern", "lustre.lov_mds_md.lmm_pattern", FT_UINT32, BASE_HEX, VALS(lov_pattern_vals), 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_object_id,
          { "Lmm Object Id", "lustre.lov_mds_md.lmm_object_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_object_seq,
          { "Lmm Object SEQ", "lustre.lov_mds_md.lmm_object_seq", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_stripe_size,
          { "Lmm Stripe Size", "lustre.lov_mds_md.lmm_stripe_size", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_stripe_count,
          { "Lmm Stripe Count", "lustre.lov_mds_md.lmm_stripe_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_layout_gen,
          { "Lmm Layout Generation", "lustre.lov_mds_md.lmm_layout_gen", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_mds_md_lmm_pool_name,
          { "Lmm Poolname", "lustre.lov_mds_md.lmm_poolname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* LOV Desc */
        { &hf_lustre_lov_desc,
          { "LOV Desc", "lustre.lov_desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_pattern,
          { "Ld Pattern", "lustre.lov_desc.pattern", FT_UINT32, BASE_HEX, VALS(lov_pattern_vals), 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_default_stripe_count,
          { "Ld Default Stripe Count", "lustre.lov_desc.default_stripe_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_magic,
          { "Ld Magic", "lustre.lov_desc.magic", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_tgt_count,
          { "Ld Tgt Count", "lustre.lov_desc.tgt_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_default_stripe_size,
          { "Ld Default Stripe Size", "lustre.lov_desc.default_stripe_size", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_default_stripe_offset,
          { "Ld Default Stripe Offset", "lustre.lov_desc.default_stripe_offset", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_qos_maxage,
          { "Ld Qos Maxage", "lustre.lov_desc.qos_maxage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_padding,
          { "Ld Padding", "lustre.lov_desc.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lov_desc_uuid,
          { "Ld Uuid", "lustre.lov_desc.uuid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /************************************************************
         * QUOTA
         */

        /* QUOTA BODY */
        { &hf_lustre_quota_body,
          { "Quota Body", "lustre.quota_body", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_qb_fid,
          { "FID", "lustre.quota_body.fid", FT_NONE, BASE_NONE, NULL, 0, "FID of global index packing the pool ID", HFILL } },
        { &hf_lustre_qb_lockh,
          { "Lock H", "lustre.quota_body.lockh", FT_NONE, BASE_NONE, NULL, 0, "Per-ID lock handle", HFILL } },
        { &hf_lustre_qb_glb_lockh,
          { "Glb Lock H", "lustre.quota_body.gbl_lockh", FT_NONE, BASE_NONE, NULL, 0, "Global lock handle", HFILL } },
        { &hf_lustre_qb_padding,
          { "padding", "lustre.quota_body.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_qb_flags, /* @@ add VALS(QUOTA_DQACQ_FL_vals) */
          { "Flags", "lustre.quota_body.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_qb_count,
          { "Count", "lustre.quota_body.count", FT_UINT64, BASE_DEC, NULL, 0, "acquire/release count (kbytes/inodes)", HFILL } },
        { &hf_lustre_qb_usage,
          { "Usage", "lustre.quota_body.usage", FT_UINT64, BASE_DEC, NULL, 0, "current slave usage (kbytes/inodes)", HFILL } },
        { &hf_lustre_qb_slv_ver,
          { "Slave Ver", "lustre.quota_body.slv_ver", FT_UINT64, BASE_DEC, NULL, 0, "slave index file version", HFILL } },

        /* Quota Adjust */
        { &hf_lustre_quota_adjust_qunit,
          { "obd quota adjust qunit", "lustre.quota_adjust_qunit", FT_NONE, BASE_NONE, NULL , 0 , NULL, HFILL }},
        { &hf_lustre_quota_adjust_qunit_qaq_id,
          { "Qaq Id", "lustre.quota_adjust_qunit.qaq_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_quota_adjust_qunit_qaq_flags,
          { "Qaq Flags", "lustre.quota_adjust_qunit.qaq_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_quota_adjust_qunit_qaq_iunit_sz,
          { "Qaq Iunit Sz", "lustre.quota_adjust_qunit.qaq_iunit_sz", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_quota_adjust_qunit_qaq_bunit_sz,
          { "Qaq Bunit Sz", "lustre.quota_adjust_qunit.qaq_bunit_sz", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_quota_adjust_qunit_padding1,
          { "Padding1", "lustre.quota_adjust_qunit.padding1", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LQUOTA ID */
        { &hf_lustre_lquota_id,
          { "LQuota ID [UNION]", "lustre.lquota_id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_qid_fid,
          { "FID", "lustre.lquota_id.fid", FT_NONE, BASE_NONE, NULL, 0, "Directory FID", HFILL } },
        { &hf_lustre_qid_uid,
          { "UID", "lustre.lquota_id.uid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_qid_gid,
          { "GID", "lustre.lquota_id.gid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },

        /************************************************************
         * LDLM
         */

        /* LDLM EXTENT */
        { &hf_lustre_ldlm_extent_gid,
          { "Gid", "lustre.ldlm_extent.gid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_extent_start,
          { "Start", "lustre.ldlm_extent.start", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_extent_end,
          { "End", "lustre.ldlm_extent.end", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LDLM FLOCK */
        { &hf_lustre_ldlm_flock_start,
          { "Start", "lustre.ldlm_flock.start", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_flock_end,
          { "End", "lustre.ldlm_flock.end", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_flock_owner,
          { "Owner", "lustre.ldlm_flock.owner", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_flock_padding,
          { "Pid", "lustre.ldlm_flock.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_flock_pid,
          { "Pid", "lustre.ldlm_flock.pid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* LDLM Request */
        { &hf_lustre_ldlm_request,
          { "ldlm request", "lustre.ldlm_request", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_lustre_ldlm_request_lock_handle,
          { "Lock Handle", "lustre.ldlm_request.lock_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_request_lock_flags,
          { "Lock Flags", "lustre.ldlm_request.lock_flags", FT_UINT32, BASE_HEX, NULL, 0 , NULL, HFILL }},
        { &hf_lustre_ldlm_request_lock_count,
          { "Lock Count", "lustre.ldlm_request.lock_count", FT_UINT32, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},

        /* LDLM Reply */
        { &hf_lustre_ldlm_reply,
          { "LDLM Reply", "lustre.ldlm_reply", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_lustre_ldlm_reply_lock_flags,
          { "Lock Flags", "lustre.ldlm_reply.lock_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_reply_lock_policy_res1,
          { "Lock Policy Res1", "lustre.ldlm_reply.lock_policy_res1", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_reply_lock_policy_res2,
          { "Lock Policy Res2", "lustre.ldlm_reply.lock_policy_res2", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_reply_lock_handle,
          { "Lock Handle", "lustre.ldlm_reply.lock_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_reply_lock_padding,
          { "Lock Padding", "lustre.ldlm_reply.lock_padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LDLM INODE */
        { &hf_lustre_ldlm_inodebits_bits,
          { "Bits", "lustre.ldlm_inodebits.bits", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_inodebits_try_bits,
          { "Try Bits", "lustre.ldlm_inodebits.try_bits", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},

        /* LDLM Lock Desc */
        { &hf_lustre_ldlm_lock_desc,
          { "LDLM Desc", "lustre.ldlm_lock_desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_lock_desc_l_policy_data,
          { "L Policy Data", "lustre.ldlm_lock_desc.l_policy_data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_lock_desc_l_granted_mode,
          { "L Granted Mode", "lustre.ldlm_lock_desc.l_granted_mode", FT_UINT32, BASE_DEC, VALS(lustre_ldlm_mode_vals), 0, NULL, HFILL }},
        { &hf_lustre_ldlm_lock_desc_l_req_mode,
          { "L Req Mode", "lustre.ldlm_lock_desc.l_req_mode", FT_UINT32, BASE_DEC, VALS(lustre_ldlm_mode_vals), 0, NULL, HFILL }},

        /* LDLM Resource ID */
        { &hf_lustre_ldlm_res_id,
          { "LDLM Res ID", "lustre.ldlm_res_id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_res_id_name,
          { "Name", "lustre.ldlm_res_id.name", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_res_id_bits,
          { "Bits", "lustre.ldlm_res_id.bits", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_res_id_string,
          { "String", "lustre.ldlm_res_id.string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_res_id_type,
          { "Type", "lustre.ldlm_res_id.type", FT_UINT32, BASE_HEX, VALS(mgs_config_body_type_vals), 0, NULL, HFILL }},

        /* LDLM Resource Desc */
        { &hf_lustre_ldlm_resource_desc,
          { "LDLM Resc Desc", "lustre.ldlm_resource_desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_resource_desc_lr_type,
          { "Lr Type", "lustre.ldlm_resource_desc.lr_type", FT_UINT16, BASE_DEC, VALS(lustre_ldlm_type_vals), 0, NULL, HFILL }},
        { &hf_lustre_ldlm_resource_desc_lr_padding,
          { "Lr Padding", "lustre.ldlm_resource_desc.lr_padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

         /* LDLM GL Barrier Desc */
        { &hf_lustre_ldlm_gl_barrier_desc,
          { "LDLM GL Barrier Desc", "lustre.ldlm_gl_barrier_desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_gl_barrier_desc_status,
          { "Status", "lustre.ldlm_gl_barrier_desc.status", FT_UINT32, BASE_HEX, VALS(lustre_barrier_status_vals), 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_barrier_desc_timeout,
          { "Timeout", "lustre.ldlm_gl_barrier_desc.timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_barrier_desc_padding,
          { "Padding", "lustre.ldlm_gl_barrier_desc.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LDLM GL LQuota Desc */
        { &hf_lustre_ldlm_gl_lquota_desc,
          { "LDLM GL lQuota Desc", "lustre.ldlm_gl_lquota_desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_ldlm_gl_lquota_desc_flags,
          { "Flags", "lustre.ldlm_gl_lquota_desc.flags", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_lquota_desc_ver,
          { "Ver", "lustre.ldlm_gl_lquota_desc.ver", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_lquota_desc_hardlimit,
          { "Hardlimit", "lustre.ldlm_gl_lquota_desc.hardlimit", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_lquota_desc_softlimit,
          { "Softlimit", "lustre.ldlm_gl_lquota_desc.softlimit", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_lquota_desc_time,
          { "Time", "lustre.ldlm_gl_lquota_desc.time", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_gl_lquota_desc_pad2,
          { "padding", "lustre.ldlm_gl_lquota_desc.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* LDLM Intent */
        /*all this flags are uint64, but I don't find the way to use something like TFS() with a Uint64*/
        /*like TFS() with a Uint64 */
        { &hf_lustre_ldlm_intent_opc,
          { "intent opcode", "lustre.ldlm_intent.opc", FT_UINT64, BASE_HEX, NULL, 0,  NULL, HFILL}},
        { &hf_lustre_ldlm_intent_opc_open,
          { "open", "lustre.ldlm_intent.opc_open", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_OPEN,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_creat,
          { "create", "lustre.ldlm_intent.opc_create", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_CREAT  ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_readdir,
          { "readdir", "lustre.ldlm_intent.opc_readdir", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_READDIR  ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_getattr,
          { "getattr", "lustre.ldlm_intent.opc_getattr", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_GETATTR,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_lookup,
          { "lookup", "lustre.ldlm_intent.opc_lookup", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_LOOKUP ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_unlink,
          { "unlink", "lustre.ldlm_intent.opc_unlink", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_UNLINK ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_trunc,
          { "trunc", "lustre.ldlm_intent.opc_trunc", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_TRUNC ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_getxattr,
          { "getxattr", "lustre.ldlm_intent.opc_getxattr", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_GETXATTR ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_exec,
          { "exec", "lustre.ldlm_intent.opc_exec", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_EXEC ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_pin,
          { "pin", "lustre.ldlm_intent.opc_pin", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_PIN ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_layout,
          { "layout", "lustre.ldlm_intent.opc_layout", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_LAYOUT ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_q_dqacq,
          { "quota dqacq", "lustre.ldlm_intent.opc_quota_dqacq", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_QUOTA_DQACQ ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_q_conn,
          { "quota conn", "lustre.ldlm_intent.opc_quota_conn", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_QUOTA_CONN ,  NULL, HFILL } },
        { &hf_lustre_ldlm_intent_opc_setxattr,
          { "setxattr", "lustre.ldlm_intent.opc_setxattr", FT_BOOLEAN, 32, TFS(&lnet_flags_set_truth), IT_SETXATTR ,  NULL, HFILL } },

        /* LDLM SET INFO */
        { &hf_lustre_ldlm_key,
          { "LDLM Set Info Key", "lustre.ldlm.key", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ldlm_val,
          { "LDLM Set Info Value", "lustre.ldlm.value", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Barrier LVB */
        { &hf_lustre_barrier_lvb,
          { "Barrier LVB", "lustre.barrier_lvb", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_barrier_lvb_status,
          { "Lvb Status", "lustre.barrier_lvb.status", FT_UINT32, BASE_HEX, VALS(lustre_barrier_status_vals), 0, NULL, HFILL }},
        { &hf_lustre_barrier_lvb_index,
          { "Lvb Index", "lustre.barrier_lvb.index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_barrier_lvb_padding,
          { "Lvb Padding", "lustre.barrier_lvb.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /************************************************************
         * MGS
         */

        /* MGS Target Info */
        { &hf_lustre_mgs_target_info,
          { "MGS Target Info", "lustre.mgs_target_info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_flags,
          { "Mti Flags", "lustre.mgs_target_info.mti_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_fsname,
          { "Mti Fsname", "lustre.mgs_target_info.mti_fsname", FT_STRINGZPAD, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_svname,
          { "Mti Svname", "lustre.mgs_target_info.mti_svname", FT_STRINGZPAD, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_config_ver,
          { "Mti Config Ver", "lustre.mgs_target_info.mti_config_ver", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_uuid,
          { "Mti Uuid", "lustre.mgs_target_info.mti_uuid", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_stripe_index,
          { "Mti Stripe Index", "lustre.mgs_target_info.mti_stripe_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_params,
          { "Mti Params", "lustre.mgs_target_info.mti_params", FT_STRINGZPAD, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_nids,
          { "Mti Nids", "lustre.mgs_target_info.mti_nids", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_lustre_ver,
          { "Mti Lustre Ver", "lustre.mgs_target_info.mti_lustre_ver", FT_UINT32, BASE_CUSTOM, CF_FUNC(lustre_fmt_ver), 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_nid_count,
          { "Mti Nid Count", "lustre.mgs_target_info.mti_nid_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_mti_instance,
          { "Mti Instance", "lustre.mgs_target_info.mti_instance", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_target_info_padding,
          { "Padding", "lustre.mgs_target_info.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* MGS Send Params */
        { &hf_lustre_mgs_send_param,
          { "Mgs Param", "lustre.mgs_send_param", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* MGS Config Body */
        { &hf_lustre_mgs_config_body,
          { "MGS Config Body", "lustre.mgs_config_body", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_body_name,
          { "mcb name", "lustre.mgs_config_body.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_body_offset,
          { "mcb offset", "lustre.mgs_config_body.offset", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_body_type,
          { "mcb type", "lustre.mgs_config_body.type", FT_UINT16, BASE_DEC, VALS(mgs_config_body_type_vals), 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_body_nm_cur_pass,
          { "mcb # cur pass", "lustre.mgs_config_body.nm_cur_pass", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_body_bits,
          { "mcb bit shift", "lustre.mgs_config_body.bits", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_body_units,
          { "mcb units", "lustre.mgs_config_body.type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* MGS Config Response */
        { &hf_lustre_mgs_config_res,
          { "mgs config res", "lustre.mgs_config_res", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_mgs_config_res_offset,
          { "mcr offset", "lustre.mgs_config_res.offset", FT_UINT64, BASE_DEC, NULL, 0, "Index of Last config log", HFILL }},
        { &hf_lustre_mgs_config_res_size,
          { "mcr size", "lustre.mgs_config_res.size", FT_UINT64, BASE_DEC_HEX, NULL, 0, "Size of Log", HFILL }},
        { &hf_lustre_mgs_config_res_nm_cur_pass,
          { "mcr # cur pass", "lustre.mgs_config_res.nm_cur_pass", FT_UINT64, BASE_DEC, NULL, 0, "Current NODEMAP config pass", HFILL }},

        /************************************************************
         * OUT Update
         */

        /* Out Update Header */
        { &hf_lustre_out_update_header,
          { "Out Update Header", "lustre.out_update_header", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_out_update_header_magic, /* @@ VALS(out_update_magic_header_vals) */
          { "Ouh Magic", "lustre.out_update_header.magic", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_out_update_header_count,
          { "Ouh Count", "lustre.out_update_header.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_out_update_header_inline_length,
          { "Ouh Inline Len", "lustre.out_update_header.inline_length", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_out_update_header_reply_size,
          { "Ouh Reply Sz", "lustre.out_update_header.reply_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_out_update_header_inline_data,
          { "Ouh Inline Data", "lustre.out_update_header.inline_data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* Out Update Buffer */
        { &hf_lustre_out_update_buffer,
          { "Out Update Buffer", "lustre.out_update_buffer", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_out_update_buffer_size,
          { "Oub Size", "lustre.out_update_buffer.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_out_update_buffer_padding,
          { "Oub padding", "lustre.out_update_buffer.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /* Object Update Reply */
        { &hf_lustre_obj_update_reply,
          { "Object Update Rep", "lustre.obj_update_reply", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obj_update_reply_magic,
          { "Ourp Magic", "lustre.obj_update_reply.magic", FT_UINT32, BASE_HEX, VALS(update_reply_magic_vals), 0, NULL, HFILL }},
        { &hf_lustre_obj_update_reply_count,
          { "Ourp Count", "lustre.obj_update_reply.count", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_reply_padding,
          { "Ourp padding", "lustre.obj_update_reply.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_reply_lens,
          { "Ourp Lens", "lustre.obj_update_reply.lens", FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},

        /* Object Update Request */
        { &hf_lustre_obj_update_request,
          { "Object Update Req", "lustre.obj_update_request", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obj_update_request_magic,
          { "Ourq Magic", "lustre.obj_update_request.magic", FT_UINT32, BASE_HEX, VALS(update_request_magic_vals), 0, NULL, HFILL }},
        { &hf_lustre_obj_update_request_count,
          { "Ourq Count", "lustre.obj_update_request.count", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_request_padding,
          { "Ourq padding", "lustre.obj_update_request.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

       /* Object Update */
        { &hf_lustre_obj_update,
          { "Object Update", "lustre.obj_update", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obj_update_type,
          { "Ou Type", "lustre.obj_update.type", FT_UINT16, BASE_HEX, VALS(update_type_vals), 0, NULL, HFILL }},
        { &hf_lustre_obj_update_params_count,
          { "Ou Param Count", "lustre.obj_update.params_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_result_size,
          { "Ou Result Sz", "lustre.obj_update.result_size", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_flags,
          { "Ou Flags", "lustre.obj_update.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_padding,
          { "Ou padding", "lustre.obj_update.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_batchid,
          { "Ou Batch ID", "lustre.obj_update.batchid", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_fid,
          { "Ou Fid", "lustre.obj_update.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

       /* Object Update Param */
        { &hf_lustre_obj_update_param,
          { "Object Update Param", "lustre.obj_update_param", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obj_update_param_len,
          { "Oup Len", "lustre.obj_update_params.len", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_param_padding,
          { "Oup padding", "lustre.obj_update_params.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obj_update_param_buf,
          { "Oup Buf", "lustre.obj_update_params.buf", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

        /************************************************************
         * LFSCK
         */

        /* Request */
        { &hf_lustre_lfsck_request,
          { "LFSCK Request", "lustre.lfsck_request", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_event,
          { "LR Event", "lustre.lfsck_request.event", FT_UINT32, BASE_DEC, VALS(lfsck_events_vals), 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_index,
          { "LR Index", "lustre.lfsck_request.index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_flags,
          { "LR Flags", "lustre.lfsck_request.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_valid,
          { "LR Valid", "lustre.lfsck_request.valid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_speed,
          { "LR Speed", "lustre.lfsck_request.speed", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_status,
          { "LR Status", "lustre.lfsck_request.status", FT_UINT32, BASE_DEC, VALS(lfsck_status_vals), 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_version,
          { "LR Version", "lustre.lfsck_request.version", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_active,
          { "LR Active", "lustre.lfsck_request.active", FT_UINT16, BASE_HEX, VALS(lfsck_type_vals), 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_param,
          { "LR Param", "lustre.lfsck_request.param", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_async_windows,
          { "LR Async Win", "lustre.lfsck_request.async_windows", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_flags2,
          { "LR Flags2", "lustre.lfsck_request.flags2", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_fid,
          { "LR Fid", "lustre.lfsck_request.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_fid2,
          { "LR Fid2", "lustre.lfsck_request.fid2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_comp_id,
          { "LR Comp ID", "lustre.lfsck_request.comp_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_request_padding,
          { "LR padding", "lustre.lfsck_request.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Reply */
        { &hf_lustre_lfsck_reply,
          { "LFSCK Reply", "lustre.lfsck_reply", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_reply_status,
          { "LP Status", "lustre.lfsck_reply.status", FT_UINT32, BASE_DEC, VALS(lfsck_status_vals), 0, NULL, HFILL } },
        { &hf_lustre_lfsck_reply_padding,
          { "LP padding", "lustre.lfsck_reply.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lfsck_reply_repaired,
          { "LP Repaired", "lustre.lfsck_reply.repaired", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },


        /************************************************************
         * OTHER
         */

        /* Cookie */
        { &hf_lustre_lustre_handle,
          { "Handle", "lustre.lustre_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_lustre_handle_cookie,
          { "Cookie", "lustre.lustre_handle.cookie", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },

        /* LU FID */
        { &hf_lustre_lu_fid_f_seq,
          { "Seq", "lustre.lu_fid.f_seq", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_fid_f_oid,
          { "OID", "lustre.ll_fid.f_oid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_lu_fid_f_ver,
          { "Version", "lustre.ll_fid.f_ver", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_lustre_ost_oi_id,
          { "O Id", "lustre.ost_io.id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_ost_oi_seq,
          { "O SEQ", "lustre.ost_oi.seq", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* OBDO */
        { &hf_lustre_obdo,
          { "OBDO", "lustre.obdo", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_valid,
          { "O Valid", "lustre.obdo.o_valid", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        /* .o_oi here */
        { &hf_lustre_obdo_o_parent_seq,
          { "O Parent SEQ", "lustre.obdo.o_parent_seq", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_size,
          { "O Size", "lustre.obdo.o_size", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_mtime,
          { "O Mtime", "lustre.obdo.o_mtime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obdo_o_atime,
          { "O Atime", "lustre.obdo.o_atime",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obdo_o_ctime,
          { "O Ctime", "lustre.obdo.o_ctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL } },
        { &hf_lustre_obdo_o_blocks,
          { "O Blocks", "lustre.obdo.o_blocks", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_grant,
          { "O Grant", "lustre.obdo.o_grant", FT_UINT64, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_blksize,
          { "O Blksize", "lustre.obdo.o_blksize", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_mode,
          { "O Mode", "lustre.obdo.o_mode", FT_UINT32, BASE_OCT, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_uid,
          { "O Uid", "lustre.obdo.o_uid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_gid,
          { "O Gid", "lustre.obdo.o_gid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_flags,
          { "O Flags", "lustre.obdo.o_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_nlink,
          { "O Nlink", "lustre.obdo.o_nlink", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_parent_oid,
          { "O Parent OID", "lustre.obdo.o_parent_oid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_misc,
          { "O Misc", "lustre.obdo.o_misc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_ioepoch,
          { "O IOEpoch", "lustre.obdo.o_ioepoch", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_stripe_idx,
          { "O Stripe Idx", "lustre.obdo.o_stripe_idx", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_parent_ver,
          { "O Parent VER", "lustre.obdo.o_parent_ver", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_handle,
          { "O Handle", "lustre.obdo.o_handle", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        /* .o_handle / .o_lcookie here */
        { &hf_lustre_obdo_o_padding_3,
          { "O Padding 3", "lustre.obdo.o_padding_3", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_uid_h,
          { "O Uid H", "lustre.obdo.o_uid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_gid_h,
          { "O Gid H", "lustre.obdo.o_gid_h", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_data_version,
          { "O Data Version", "lustre.obdo.o_data_version", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_projid,
          { "O Proj ID", "lustre.obdo.o_projid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_padding_4,
          { "O Padding 4", "lustre.obdo.o_padding_4", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_padding_5,
          { "O Padding 5", "lustre.obdo.o_padding_5", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lustre_obdo_o_padding_6,
          { "O Padding 6", "lustre.obdo.o_padding_6", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* XATTR */
        { &hf_lustre_xattr_list,
          { "XATTR List", "lustre.xattr_list", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_xattr,
          { "XATTR", "lustre.xattr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_xattr_name,
          { "xattr name", "lustre.xattr.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_xattr_data,
          { "xattr data", "lustre.xattr.data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lustre_xattr_size,
          { "xattr size", "lustre.xattr.size", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},

        /* SEQ */
        { &hf_lustre_seq_opc,
          { "Seq OPC", "lustre.seq_opc", FT_UINT32, BASE_DEC, VALS(seq_op_vals), 0, NULL, HFILL } },
        { &hf_lustre_seq_range,
          { "Seq Range", "lustre.seq_range", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_seq_range_start,
          { "Seq Range Start", "lustre.seq_range.start", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_seq_range_end,
          { "Seq Range End", "lustre.seq_range.end", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_seq_range_index,
          { "Seq Range Index", "lustre.seq_range.index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_seq_range_flags,
          { "Seq Range Flags", "lustre.seq_range.flags", FT_UINT32, BASE_HEX, VALS(seq_range_flag_vals), 0, NULL, HFILL } },

        /* FLD */
        { &hf_lustre_fld_opc,
          { "FLD OPC", "lustre.fld_opc", FT_UINT32, BASE_DEC, VALS(fld_op_vals), 0, NULL, HFILL } },

        /* struct lustre_capa */
        { &hf_lustre_capa,
          { "Capability", "lustre.capa", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_fid,
          { "Capa fid", "lustre.capa.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_opc,
          { "Capa opc", "lustre.capa.opc", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_uid,
          { "Capa uid", "lustre.capa.uid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_gid,
          { "Capa gid", "lustre.capa.gid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_flags,
          { "Capa flags", "lustre.capa.flags", FT_UINT32, BASE_HEX, VALS(capa_flags_vals), 0, NULL, HFILL } },
        { &hf_lustre_capa_keyid,
          { "Capa keyid", "lustre.capa.keyid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_timeout,
          { "Capa timeout", "lustre.capa.timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_expiry,
          { "Capa expiry", "lustre.capa.expiry", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_capa_hmac,
          { "Capa hmac", "lustre.capa.hmac", FT_BYTES, SEP_COLON, NULL, 0, NULL, HFILL } },

        /* struct idx_info */
        { &hf_lustre_idx_info,
          { "Index Info", "lustre.idx_info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_idx_info_magic,
          { "II Magic", "lustre.idx_info.magic", FT_UINT32, BASE_HEX, VALS(lustre_magic), 0, NULL, HFILL } },
        { &hf_lustre_idx_info_flags,
          { "II Flags", "lustre.idx_info.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_idx_info_count,
          { "II Count", "lustre.idx_info.count", FT_UINT16, BASE_DEC, NULL, 0, "number of lu_idxpage (to be) transferred", HFILL } },
        { &hf_lustre_idx_info_attrs,
          { "II Attrs", "lustre.idx_info.attrs", FT_UINT32, BASE_HEX, NULL, 0, "requested attributes passed down to the iterator API", HFILL } },
        { &hf_lustre_idx_info_fid,
          { "II fid", "lustre.idx_info.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_idx_info_hash_start,
          { "II Hash Start", "lustre.idx_info.hash_start", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_idx_info_hash_end,
          { "II Hash End", "lustre.idx_info.hash_end", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_idx_info_keysize,
          { "II Key size", "lustre.idx_info.keysize", FT_UINT16, BASE_DEC, NULL, 0, "size of keys in lu_idxpages", HFILL } },
        { &hf_lustre_idx_info_recsize,
          { "II Rec size", "lustre.idx_info.recsize", FT_UINT16, BASE_DEC, NULL, 0, "size of records in lu_idxpages", HFILL } },
        { &hf_lustre_idx_info_padding,
          { "padding", "lustre.idx_info.padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* ACL */
        { &hf_lustre_acl,
          { "ACL", "lustre.acl", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* USER ITEM */
        { &hf_lustre_hsm_user_item,
          { "HSM User Item", "lustre.user_item", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_hsm_user_item_fid,
          { "HSM User Item FID", "lustre.user_item.fid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Intent Layout */
        { &hf_lustre_layout_intent,
          { "Layout Intent", "lustre.layout_intent", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_lustre_layout_intent_opc,
          { "Op Code", "lustre.layout_intent.opc", FT_UINT32, BASE_HEX, VALS(lustre_layout_intent_opc_vals), 0, NULL, HFILL } },
        { &hf_lustre_layout_intent_flags,
          { "Flags", "lustre.layout_intent.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_lustre_layout_intent_start,
          { "Start", "lustre.layout_intent.start", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_lustre_layout_intent_end,
          { "End", "lustre.layout_intent.end", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_lustre_eadata,
          { "EA Data", "lustre.eadata", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},

        { &hf_lustre_extra_padding,
          { "extra padding", "lustre.extra_padding", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},

        { &hf_lustre_target_uuid,
          { "Target UUID", "lustre.target_uuid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_lustre_client_uuid,
          { "Client UUID", "lustre.client_uuid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},

        { &hf_lustre_filename,
          { "filename", "lustre.filename", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_selinux_pol,
          { "SELinux Policy", "lustre.selinux_pol", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_target,
          { "target", "lustre.target", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_secctx_name,
          { "Sec Ctx Name", "lustre.secctx_name", FT_STRING, BASE_NONE, NULL , 0 , NULL, HFILL}},
        { &hf_lustre_data,
          { "data", "lustre.data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_lustre_name,
          { "name", "lustre.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}},
    };

    static gint *ett[] = {
        &ett_lustre,
        &ett_lustre_lustre_handle_cookie,
        &ett_lustre_lustre_msg_v1,
        &ett_lustre_lustre_handle_v1,
        &ett_lustre_lustre_msg_v2,
        &ett_lustre_ptlrpc_body,
        &ett_lustre_lustre_handle_v2,
        &ett_lustre_obd_connect_data,
        &ett_lustre_lov_ost_data_v1,
        &ett_lustre_obd_statfs,
        &ett_lustre_obd_ioobj,
        &ett_lustre_niobuf_remote,
        &ett_lustre_rcs,
        &ett_lustre_fid_array,
        &ett_lustre_ost_lvb,
        &ett_lustre_lu_fid,
        &ett_lustre_obd_quotactl,
        &ett_lustre_obd_dqinfo,
        &ett_lustre_obd_dqblk,
        &ett_lustre_quota_adjust_qunit,
        &ett_lustre_mdc_swap_layouts,
        &ett_lustre_mdt_body,
        &ett_lustre_mdt_rec_reint,
        &ett_lustre_lov_desc,
        &ett_lustre_obd_uuid,
        &ett_lustre_ldlm_res_id,
        &ett_lustre_ldlm_extent,
        &ett_lustre_ldlm_inodebits,
        &ett_lustre_ldlm_flock,
        &ett_lustre_ldlm_intent_opc,
        &ett_lustre_ldlm_resource_desc,
        &ett_lustre_ldlm_lock_desc,
        &ett_lustre_ldlm_request,
        &ett_lustre_lustre_handle,
        &ett_lustre_ldlm_reply,
        &ett_lustre_ldlm_gl_barrier_desc,
        &ett_lustre_ldlm_gl_lquota_desc,
        &ett_lustre_mgs_target_info,
        &ett_lustre_mgs_config_body,
        &ett_lustre_mgs_config_res,
        &ett_lustre_cfg_marker,
        &ett_lustre_llog_logid,
        &ett_lustre_lmv_mds_md,
        &ett_lustre_lov_mds_md,
        &ett_lustre_llog_rec,
        &ett_lustre_llog_rec_hdr,
        &ett_lustre_llog_rec_tail,
        &ett_lustre_llog_logid_rec,
        &ett_lustre_llog_unlink_rec,
        &ett_lustre_llog_setattr_rec,
        &ett_lustre_llog_unlink64_rec,
        &ett_lustre_llog_setattr64_rec,
        &ett_lustre_llog_size_change_rec,
        &ett_lustre_llog_gen,
        &ett_lustre_llog_gen_rec,
        &ett_lustre_llog_changelog_rec,
        &ett_lustre_changelog_rec,
        &ett_lustre_lustre_cfg,
        &ett_lustre_llog_log_hdr,
        &ett_lustre_llog_cookie,
        &ett_lustre_llogd_body,
        &ett_lustre_llogd_conn_body,
        &ett_lustre_obdo,
        &ett_lustre_ost_body,
        &ett_lustre_ldlm_lock_flags,
        &ett_lustre_llog_hdr_flags,
        &ett_lustre_seq_range,
        &ett_lustre_mdt_ioepoch,
        &ett_lustre_capa,
        &ett_lustre_idx_info,
        &ett_lustre_eadata,
        &ett_lustre_close_data,
        &ett_lustre_acl,
        &ett_lustre_ladvise_hdr,
        &ett_lustre_ladvise,
        &ett_lustre_hsm_current_action,
        &ett_lustre_hsm_request,
        &ett_lustre_hsm_archive,
        &ett_lustre_hsm_user_item,
        &ett_lustre_hsm_extent,
        &ett_lustre_hsm_state_set,
        &ett_lustre_hsm_progress,
        &ett_lustre_hsm_user_state,
        &ett_lustre_quota_body,
        &ett_lustre_lquota_id,
        &ett_lustre_layout_intent,
        &ett_lustre_xattrs,
        &ett_lustre_xattr_item,
        &ett_lustre_ost_id,
        &ett_lustre_ost_id_oi,
        &ett_lustre_ost_layout,
        &ett_lustre_out_update_header,
        &ett_lustre_out_update_header_data,
        &ett_lustre_out_update_buffer,
        &ett_lustre_obj_update_reply,
        &ett_lustre_object_update_request,
        &ett_lustre_object_update,
        &ett_lustre_object_update_param,
        &ett_lustre_lfsck_request,
        &ett_lustre_lfsck_reply,
        &ett_lustre_barrier_lvb,
    };

    /* Setup protocol expert items */
    expert_module_t *expert_lustre;
    static ei_register_info ei[] = {
        { &ei_lustre_buflen,
          { "lustre.bad_buflen", PI_MALFORMED, PI_ERROR, "Buffer length mis-match", EXPFILL } },
        { &ei_lustre_badopc,
          { "lustre.bad_opcode", PI_PROTOCOL, PI_WARN, "BAD OPCODE", EXPFILL } },
        { &ei_lustre_badmagic,
          { "lustre.bad_magic", PI_PROTOCOL, PI_WARN, "BAD Magic Value", EXPFILL } },
        { &ei_lustre_obsopc,
          { "lustre.old_opcode", PI_DEPRECATED, PI_NOTE, "Deprecated Opcode", EXPFILL } },
    };

    proto_lustre = proto_register_protocol("Lustre", "lustre", "lustre");

    proto_register_field_array(proto_lustre, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_lustre = expert_register_protocol(proto_lustre);
    expert_register_field_array(expert_lustre, ei, array_length(ei));
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
