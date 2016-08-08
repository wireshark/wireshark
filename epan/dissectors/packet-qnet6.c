/* packet-qnet6.c Routines for qnet6 LwL4 dissection Copyright 2009,
 * dragonlinux <dragonlinux@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

#include <epan/etypes.h>
#include <epan/crc32-tvb.h>
#include <wsutil/crc32.h>
#include <epan/ipproto.h>

void proto_reg_handoff_qnet6(void);
void proto_register_qnet6(void);

static int proto_qnet6_l4 = -1;
static int proto_qnet6_qos = -1;
static int proto_qnet6_lr = -1;
static int proto_qnet6_kif = -1;
static int proto_qnet6_nr = -1;

static int hf_qnet6_l4_padding = -1;
static int hf_qnet6_l4_ver = -1;
static int hf_qnet6_l4_type = -1;
static int hf_qnet6_l4_flags = -1;
static int hf_qnet6_l4_flags_first = -1;
static int hf_qnet6_l4_flags_last = -1;
static int hf_qnet6_l4_flags_crc = -1;
static int hf_qnet6_l4_qos_info = -1;
static int hf_qnet6_l4_qos_src_nd_for_dst = -1;
static int hf_qnet6_l4_qos_dst_nd_for_src = -1;
static int hf_qnet6_l4_qos_src_conn_id = -1;
static int hf_qnet6_l4_qos_dst_conn_id = -1;
static int hf_qnet6_l4_qos_src_seq_num = -1;
static int hf_qnet6_l4_qos_qos_type = -1;
static int hf_qnet6_l4_qos_src_qos_idx = -1;
static int hf_qnet6_l4_layer = -1;
static int hf_qnet6_l4_offset = -1;
static int hf_qnet6_l4_length = -1;
static int hf_qnet6_l4_crc = -1;

static int hf_qnet6_qos_tcs_src_name_off = -1;
static int hf_qnet6_qos_tcs_src_name_generated = -1;
static int hf_qnet6_qos_tcs_src_domain_off = -1;
static int hf_qnet6_qos_tcs_src_domain_generated = -1;
static int hf_qnet6_qos_tcs_dst_name_off = -1;
static int hf_qnet6_qos_tcs_dst_name_generated = -1;
static int hf_qnet6_qos_tcs_dst_domain_off = -1;
static int hf_qnet6_qos_tcs_dst_domain_generated = -1;

static int hf_qnet6_lr_ver = -1;
static int hf_qnet6_lr_type = -1;
static int hf_qnet6_lr_total_len = -1;
static int hf_qnet6_lr_src = -1;
static int hf_qnet6_lr_src_name_off = -1;
static int hf_qnet6_lr_src_name_len = -1;
static int hf_qnet6_lr_src_name_generated = -1;
static int hf_qnet6_lr_src_domain_off = -1;
static int hf_qnet6_lr_src_domain_len = -1;
static int hf_qnet6_lr_src_domain_generated = -1;
static int hf_qnet6_lr_src_addr_off = -1;
static int hf_qnet6_lr_src_addr_len = -1;
static int hf_qnet6_lr_src_addr_generated = -1;
static int hf_qnet6_lr_dst = -1;
static int hf_qnet6_lr_dst_name_off = -1;
static int hf_qnet6_lr_dst_name_len = -1;
static int hf_qnet6_lr_dst_name_generated = -1;
static int hf_qnet6_lr_dst_domain_off = -1;
static int hf_qnet6_lr_dst_domain_len = -1;
static int hf_qnet6_lr_dst_domain_generated = -1;
static int hf_qnet6_lr_dst_addr_off = -1;
static int hf_qnet6_lr_dst_addr_len = -1;
static int hf_qnet6_lr_dst_addr_generated = -1;

static int hf_qnet6_kif_msgtype = -1;
static int hf_qnet6_kif_size = -1;

static int hf_qnet6_kif_version = -1;
static int hf_qnet6_kif_client_info = -1;
static int hf_qnet6_kif_zero = -1;

/*
 * client_info
 */
static int hf_qnet6_kif_client_info_nd = -1;
static int hf_qnet6_kif_client_info_pid = -1;
static int hf_qnet6_kif_client_info_sid = -1;
static int hf_qnet6_kif_client_info_flags = -1;
static int hf_qnet6_kif_client_info_cred = -1;
static int hf_qnet6_kif_client_info_cred_ruid = -1;
static int hf_qnet6_kif_client_info_cred_euid = -1;
static int hf_qnet6_kif_client_info_cred_suid = -1;
static int hf_qnet6_kif_client_info_cred_rgid = -1;
static int hf_qnet6_kif_client_info_cred_egid = -1;
static int hf_qnet6_kif_client_info_cred_sgid = -1;
static int hf_qnet6_kif_client_info_cred_ngroups = -1;
static int hf_qnet6_kif_client_info_cred_grouplist = -1;

/*
 * connect message
 */
static int hf_qnet6_kif_connect = -1;
static int hf_qnet6_kif_connect_server_pid = -1;
static int hf_qnet6_kif_connect_server_chid = -1;
static int hf_qnet6_kif_connect_client_id = -1;
static int hf_qnet6_kif_connect_client_pid = -1;
/*
 * connect success message
 */
static int hf_qnet6_kif_connects_client_id = -1;
static int hf_qnet6_kif_connects_server_id = -1;
static int hf_qnet6_kif_connects_scoid = -1;
static int hf_qnet6_kif_connects_nbytes = -1;
/*
 * connect fail message
 */
static int hf_qnet6_kif_connectf_client_id = -1;
static int hf_qnet6_kif_connectf_status = -1;
/*
 * connect death message
 */
static int hf_qnet6_kif_connectd_client_id = -1;
/*
 * msgsend message
 */
static int hf_qnet6_kif_msgsend = -1;
static int hf_qnet6_kif_msgsend_server_id = -1;
static int hf_qnet6_kif_msgsend_client_handle = -1;
static int hf_qnet6_kif_msgsend_vinfo = -1;
static int hf_qnet6_kif_msgsend_nbytes = -1;
/*
 * msgread message
 */
static int hf_qnet6_kif_msgread_msgread_handle = -1;
static int hf_qnet6_kif_msgread_client_handle = -1;
static int hf_qnet6_kif_msgread_offset = -1;
static int hf_qnet6_kif_msgread_nbytes = -1;
/*
 * msgwrite message
 */
static int hf_qnet6_kif_msgwrite_status = -1;
static int hf_qnet6_kif_msgwrite_handle = -1;
static int hf_qnet6_kif_msgwrite_offset = -1;
static int hf_qnet6_kif_msgwrite_nbytes = -1;
static int hf_qnet6_kif_msgwrite_data = -1;
/*
 * unblock message
 */
static int hf_qnet6_kif_unblock_server_id = -1;
static int hf_qnet6_kif_unblock_client_handle = -1;
static int hf_qnet6_kif_unblock_tid = -1;
/*
 * event message
 */
static int hf_qnet6_kif_event_client_handle = -1;
static int hf_qnet6_kif_event_event = -1;
static int hf_qnet6_kif_event_notify = -1;
static int hf_qnet6_kif_event_union1 = -1;
static int hf_qnet6_kif_event_value = -1;
static int hf_qnet6_kif_event_union2 = -1;

/*
 * pulse message
 */
#if 0
static int hf_qnet6_kif_pulse_server_id = -1;
static int hf_qnet6_kif_pulse_client_handle = -1;
static int hf_qnet6_kif_pulse_vinfo = -1;
#endif
static int hf_qnet6_kif_pulse_pulse = -1;
static int hf_qnet6_kif_pulse_priority = -1;
/*
 * signal message
 */
static int hf_qnet6_kif_signal_client_handle = -1;
static int hf_qnet6_kif_signal_pid = -1;
static int hf_qnet6_kif_signal_tid = -1;
static int hf_qnet6_kif_signal_signo = -1;
static int hf_qnet6_kif_signal_code = -1;
static int hf_qnet6_kif_signal_value = -1;
/*
 * disconnect message
 */
static int hf_qnet6_kif_disconnect_server_id = -1;

/*
 * vinfo
 */
static int hf_qnet6_kif_vtid_info_tid = -1;
static int hf_qnet6_kif_vtid_info_coid = -1;
static int hf_qnet6_kif_vtid_info_priority = -1;
static int hf_qnet6_kif_vtid_info_srcmsglen = -1;
static int hf_qnet6_kif_vtid_info_keydata = -1;
static int hf_qnet6_kif_vtid_info_srcnd = -1;
static int hf_qnet6_kif_vtid_info_dstmsglen = -1;
static int hf_qnet6_kif_vtid_info_zero = -1;
/*
 * pulse
 */
static int hf_qnet6_kif_pulse_pulse_type = -1;
static int hf_qnet6_kif_pulse_pulse_subtype = -1;
static int hf_qnet6_kif_pulse_pulse_code = -1;
static int hf_qnet6_kif_pulse_pulse_reserved = -1;
static int hf_qnet6_kif_pulse_pulse_value = -1;
static int hf_qnet6_kif_pulse_pulse_scoid = -1;
/*
 * message
 */
static int hf_qnet6_kif_msg = -1;
static int hf_qnet6_kif_msg_type = -1;
static int hf_qnet6_kif_msg_connect_subtype = -1;
static int hf_qnet6_kif_msg_connect_filetype = -1;
static int hf_qnet6_kif_msg_connect_replymax = -1;
static int hf_qnet6_kif_msg_connect_entrymax = -1;
static int hf_qnet6_kif_msg_connect_key = -1;
static int hf_qnet6_kif_msg_connect_handle = -1;

static int hf_qnet6_kif_msg_connect_ioflag = -1;

static int hf_qnet6_kif_msg_connect_ioflag_access = -1;
static int hf_qnet6_kif_msg_connect_ioflag_append = -1;
static int hf_qnet6_kif_msg_connect_ioflag_dsync = -1;
static int hf_qnet6_kif_msg_connect_ioflag_sync = -1;
static int hf_qnet6_kif_msg_connect_ioflag_rsync = -1;
static int hf_qnet6_kif_msg_connect_ioflag_nonblock = -1;
static int hf_qnet6_kif_msg_connect_ioflag_creat = -1;
static int hf_qnet6_kif_msg_connect_ioflag_truncate = -1;
static int hf_qnet6_kif_msg_connect_ioflag_exclusive = -1;
static int hf_qnet6_kif_msg_connect_ioflag_noctrltty = -1;
static int hf_qnet6_kif_msg_connect_ioflag_closexec = -1;
static int hf_qnet6_kif_msg_connect_ioflag_realids = -1;
static int hf_qnet6_kif_msg_connect_ioflag_largefile = -1;
static int hf_qnet6_kif_msg_connect_ioflag_async = -1;

static int hf_qnet6_kif_msg_connect_mode = -1;
static int hf_qnet6_kif_msg_connect_mode_other_exe = -1;
static int hf_qnet6_kif_msg_connect_mode_other_read = -1;
static int hf_qnet6_kif_msg_connect_mode_other_write = -1;
static int hf_qnet6_kif_msg_connect_mode_group_read = -1;
static int hf_qnet6_kif_msg_connect_mode_group_write = -1;
static int hf_qnet6_kif_msg_connect_mode_group_exe = -1;
static int hf_qnet6_kif_msg_connect_mode_owner_read = -1;
static int hf_qnet6_kif_msg_connect_mode_owner_write = -1;
static int hf_qnet6_kif_msg_connect_mode_owner_exe = -1;
static int hf_qnet6_kif_msg_connect_mode_setuid = -1;
static int hf_qnet6_kif_msg_connect_mode_setgid = -1;
static int hf_qnet6_kif_msg_connect_mode_sticky = -1;
static int hf_qnet6_kif_msg_connect_mode_format = -1;

static int hf_qnet6_kif_msg_connect_sflag = -1;
static int hf_qnet6_kif_msg_connect_access = -1;
static int hf_qnet6_kif_msg_connect_zero = -1;
static int hf_qnet6_kif_msg_connect_pathlen = -1;
static int hf_qnet6_kif_msg_connect_eflag = -1;
static int hf_qnet6_kif_msg_connect_eflag_dir = -1;
static int hf_qnet6_kif_msg_connect_eflag_dot = -1;
static int hf_qnet6_kif_msg_connect_eflag_dotdot = -1;
static int hf_qnet6_kif_msg_connect_extratype = -1;
static int hf_qnet6_kif_msg_connect_extralen = -1;
static int hf_qnet6_kif_msg_connect_path = -1;
static int hf_qnet6_kif_msg_connect_pad_data = -1;
static int hf_qnet6_kif_msg_connect_extra_symlink_path = -1;
static int hf_qnet6_kif_msg_connect_extra_rename_path = -1;
static int hf_qnet6_kif_msg_connect_extra_mount = -1;
static int hf_qnet6_kif_msg_connect_extra_data = -1;
static int hf_qnet6_kif_msg_connect_extra_link_ocb = -1;
/*
 * devctl
 */
static int hf_qnet6_kif_msg_io_combine_len = -1;
static int hf_qnet6_kif_msg_devctl_dcmd = -1;
static int hf_qnet6_kif_msg_devctl_dcmd_cmd = -1;
static int hf_qnet6_kif_msg_devctl_dcmd_ccmd = -1;
static int hf_qnet6_kif_msg_devctl_dcmd_size = -1;
static int hf_qnet6_kif_msg_devctl_dcmd_class = -1;
static int hf_qnet6_kif_msg_devctl_dcmd_from = -1;
static int hf_qnet6_kif_msg_devctl_dcmd_to = -1;

static int hf_qnet6_kif_msg_devctl_nbytes = -1;
static int hf_qnet6_kif_msg_devctl_zero = -1;
/*
 * stat
 */
/*
 * read
 */
static int hf_qnet6_kif_msg_io_read_nbytes = -1;
static int hf_qnet6_kif_msg_io_read_xtypes = -1;
static int hf_qnet6_kif_msg_io_read_xtypes_0_7 = -1;
static int hf_qnet6_kif_msg_io_read_xtypes_8 = -1;
static int hf_qnet6_kif_msg_io_read_xtypes_14 = -1;
static int hf_qnet6_kif_msg_io_read_xtypes_15 = -1;
static int hf_qnet6_kif_msg_io_read_xoffset = -1;
static int hf_qnet6_kif_msg_io_read_cond_min = -1;
static int hf_qnet6_kif_msg_io_read_cond_time = -1;
static int hf_qnet6_kif_msg_io_read_cond_timeout = -1;
/*
 * write
 */
static int hf_qnet6_kif_msg_io_write_data = -1;
static int hf_qnet6_kif_msg_io_write_nbytes = -1;
static int hf_qnet6_kif_msg_io_write_xtypes = -1;
static int hf_qnet6_kif_msg_io_write_xtypes_0_7 = -1;
static int hf_qnet6_kif_msg_io_write_xtypes_8 = -1;
static int hf_qnet6_kif_msg_io_write_xtypes_14 = -1;
static int hf_qnet6_kif_msg_io_write_xtypes_15 = -1;
static int hf_qnet6_kif_msg_io_write_xoffset = -1;

/*
 * seek
 */
static int hf_qnet6_kif_msg_seek_whence = -1;
static int hf_qnet6_kif_msg_seek_offset = -1;
/*
 * pathconf
 */
static int hf_qnet6_kif_msg_pathconf_name = -1;
/*
 * chmod
 */
static int hf_qnet6_kif_msg_io_chmod = -1;
static int hf_qnet6_kif_msg_io_chmod_other_exe = -1;
static int hf_qnet6_kif_msg_io_chmod_other_read = -1;
static int hf_qnet6_kif_msg_io_chmod_other_write = -1;
static int hf_qnet6_kif_msg_io_chmod_group_read = -1;
static int hf_qnet6_kif_msg_io_chmod_group_write = -1;
static int hf_qnet6_kif_msg_io_chmod_group_exe = -1;
static int hf_qnet6_kif_msg_io_chmod_owner_read = -1;
static int hf_qnet6_kif_msg_io_chmod_owner_write = -1;
static int hf_qnet6_kif_msg_io_chmod_owner_exe = -1;
static int hf_qnet6_kif_msg_io_chmod_setuid = -1;
static int hf_qnet6_kif_msg_io_chmod_setgid = -1;
static int hf_qnet6_kif_msg_io_chmod_sticky = -1;
/*
 * chown
 */
static int hf_qnet6_kif_msg_io_chown_gid = -1;
static int hf_qnet6_kif_msg_io_chown_uid = -1;
/*
 * sync
 */
static int hf_qnet6_kif_msg_io_sync = -1;
static int hf_qnet6_kif_msg_syncflag_dsync = -1;
static int hf_qnet6_kif_msg_syncflag_sync = -1;
static int hf_qnet6_kif_msg_syncflag_rsync = -1;
/*
 * utime
 */
static int hf_qnet6_kif_msg_io_utime_curflag = -1;
static int hf_qnet6_kif_msg_io_utime_actime = -1;
static int hf_qnet6_kif_msg_io_utime_modtime = -1;
/*
 * fdinfo
 */
static int hf_qnet6_kif_msg_io_fdinfo_flags = -1;
static int hf_qnet6_kif_msg_io_fdinfo_path_len = -1;
static int hf_qnet6_kif_msg_io_fdinfo_reserved = -1;
/*
 * lock
 */
static int hf_qnet6_kif_msg_io_lock_subtype = -1;
static int hf_qnet6_kif_msg_io_lock_nbytes = -1;
/*
 * space
 */
static int hf_qnet6_kif_msg_io_space_subtype = -1;
static int hf_qnet6_kif_msg_io_space_whence = -1;
static int hf_qnet6_kif_msg_io_space_start = -1;
static int hf_qnet6_kif_msg_io_space_len = -1;

static int hf_qnet6_kif_msgsend_extra = -1;
/*
 * msginfo
 */
static int hf_qnet6_kif_msg_msginfo_nd = -1;
static int hf_qnet6_kif_msg_msginfo_srcnd = -1;
static int hf_qnet6_kif_msg_msginfo_pid = -1;
static int hf_qnet6_kif_msg_msginfo_tid = -1;
static int hf_qnet6_kif_msg_msginfo_chid = -1;
static int hf_qnet6_kif_msg_msginfo_scoid = -1;
static int hf_qnet6_kif_msg_msginfo_coid = -1;
static int hf_qnet6_kif_msg_msginfo_msglen = -1;
static int hf_qnet6_kif_msg_msginfo_srcmsglen = -1;
static int hf_qnet6_kif_msg_msginfo_dstmsglen = -1;
static int hf_qnet6_kif_msg_msginfo_priority = -1;
static int hf_qnet6_kif_msg_msginfo_flags = -1;
static int hf_qnet6_kif_msg_msginfo_reserved = -1;
/*
 * openfd
 */
static int hf_qnet6_kif_msg_openfd_reserved = -1;
static int hf_qnet6_kif_msg_openfd_key = -1;
static int hf_qnet6_kif_msg_openfd_ioflag = -1;

static int hf_qnet6_kif_msg_openfd_ioflag_access = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_append = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_dsync = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_sync = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_rsync = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_nonblock = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_creat = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_truncate = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_exclusive = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_noctrltty = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_closexec = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_realids = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_largefile = -1;
static int hf_qnet6_kif_msg_openfd_ioflag_async = -1;
static int hf_qnet6_kif_msg_openfd_xtype = -1;
static int hf_qnet6_kif_msg_openfd_sflag = -1;
/*
 * dup
 */
static int hf_qnet6_kif_msg_io_dup_reserved = -1;
static int hf_qnet6_kif_msg_io_dup_key = -1;
/*
 * msg
 */
static int hf_qnet6_kif_msg_io_msg_mgrid = -1;
static int hf_qnet6_kif_msg_io_msg_subtype = -1;
/*
 * mmap
 */
static int hf_qnet6_kif_msg_io_mmap_prot = -1;
static int hf_qnet6_kif_msg_io_mmap_prot_read = -1;
static int hf_qnet6_kif_msg_io_mmap_prot_write = -1;
static int hf_qnet6_kif_msg_io_mmap_prot_exec = -1;
static int hf_qnet6_kif_msg_io_mmap_offset = -1;
/*
 * notify
 */
static int hf_qnet6_kif_msg_io_notify_action = -1;
static int hf_qnet6_kif_msg_io_notify_flags = -1;
static int hf_qnet6_kif_msg_io_notify_flags_31 = -1;
static int hf_qnet6_kif_msg_io_notify_flags_30 = -1;
static int hf_qnet6_kif_msg_io_notify_flags_29 = -1;
static int hf_qnet6_kif_msg_io_notify_flags_28 = -1;
static int hf_qnet6_kif_msg_io_notify_mgr = -1;
static int hf_qnet6_kif_msg_io_notify_flags_extra_mask = -1;
static int hf_qnet6_kif_msg_io_notify_flags_exten = -1;
static int hf_qnet6_kif_msg_io_notify_nfds = -1;
static int hf_qnet6_kif_msg_io_notify_fd_first = -1;
static int hf_qnet6_kif_msg_io_notify_nfds_ready = -1;
static int hf_qnet6_kif_msg_io_notify_timo = -1;
static int hf_qnet6_kif_msg_io_notify_fds = -1;
/*
 * NR
 */
/*
 * sys/lsm/qnet/nr_msg.h
 */
static int hf_qnet6_nr_type = -1;
static int hf_qnet6_nr_remote_req_len = -1;
static int hf_qnet6_nr_remote_req_id = -1;
static int hf_qnet6_nr_remote_req_name = -1;
static int hf_qnet6_nr_remote_rep_spare = -1;
static int hf_qnet6_nr_remote_rep_id = -1;      /* remote_answer id */
static int hf_qnet6_nr_remote_rep_nd = -1;      /* remote_answer nd */
static int hf_qnet6_nr_remote_rep_status = -1;  /* remote_error * status */

/*
 * Initialize the subtree pointers
 */
static gint ett_qnet6_l4 = -1;
static gint ett_qnet6_qos = -1;
static gint ett_qnet6_flags = -1;
static gint ett_qnet6_qos_info = -1;

static gint ett_qnet6_lr = -1;
static gint ett_qnet6_lr_src = -1;
static gint ett_qnet6_lr_src_name_subtree = -1;
static gint ett_qnet6_lr_src_domain_subtree = -1;
static gint ett_qnet6_lr_src_addr_subtree = -1;
static gint ett_qnet6_lr_dst_name_subtree = -1;
static gint ett_qnet6_lr_dst_domain_subtree = -1;
static gint ett_qnet6_lr_dst_addr_subtree = -1;
static gint ett_qnet6_lr_dst = -1;

static gint ett_qnet6_kif = -1;
static gint ett_qnet6_kif_vinfo = -1;
static gint ett_qnet6_kif_pulse = -1;
static gint ett_qnet6_kif_event = -1;
static gint ett_qnet6_kif_msg = -1;
static gint ett_qnet6_kif_msg_ioflag = -1;
static gint ett_qnet6_kif_msg_mode = -1;
static gint ett_qnet6_kif_msg_eflag = -1;
static gint ett_qnet6_kif_connect = -1;
static gint ett_qnet6_kif_chmod_mode = -1;
static gint ett_qnet6_kif_msgsend = -1;
static gint ett_qnet6_kif_client_info = -1;
static gint ett_qnet6_kif_client_info_cred = -1;
static gint ett_qnet6_kif_client_info_cred_group = -1;
static gint ett_qnet6_kif_msg_devctl_dcmd = -1;
static gint ett_qnet6_kif_msg_read_xtypes = -1;
static gint ett_qnet6_kif_msg_write_xtypes = -1;
static gint ett_qnet6_kif_msg_sync = -1;
static gint ett_qnet6_kif_msg_openfd_ioflag = -1;
static gint ett_qnet6_kif_msg_msginfo = -1;
static gint ett_qnet6_kif_msg_prot = -1;
static gint ett_qnet6_kif_msg_notify_flags = -1;
static gint ett_qnet6_kif_msg_notify_fds = -1;
static gint ett_qnet6_nr = -1;

/*
 * struct qnet6_lr_pkt { guint8 version; guint8 pad0; guint8 type; guint8
 * pad1;
 *
 * guint32 total_len;
 *
 * guint32 src_name_off; guint32 src_name_len; guint32 src_domain_off;
 * guint32 src_domain_len; guint32 src_addr_off; guint32 src_addr_len;
 *
 * guint32 dst_name_off; guint32 dst_name_len; guint32 dst_domain_off;
 * guint32 dst_domain_len; guint32 dst_addr_off; guint32 dst_addr_len; };
 */
#define QNX_QNET6_LR_PKT_SIZE 56
/*
 * 56 bytes in header, name, domain, addr data are behind
 */

struct qnet6_kif_hdr
{
  guint16 msgtype;
  guint16 size;
};

enum _msg_bases_qnx
{
  QNX_IO_BASE = 0x100,
  QNX_IO_MAX  = 0x1FF
};

enum _io__Uint16types
{
  QNX_IO_CONNECT = QNX_IO_BASE,
  QNX_IO_READ,
  QNX_IO_WRITE,
  QNX_IO_RSVD_CLOSE_OCB,  /* Place holder in jump table */
  QNX_IO_STAT,
  QNX_IO_NOTIFY,
  QNX_IO_DEVCTL,
  QNX_IO_RSVD_UNBLOCK,    /* Place holder in jump table */
  QNX_IO_PATHCONF,
  QNX_IO_LSEEK,
  QNX_IO_CHMOD,
  QNX_IO_CHOWN,
  QNX_IO_UTIME,
  QNX_IO_OPENFD,
  QNX_IO_FDINFO,
  QNX_IO_LOCK,
  QNX_IO_SPACE,
  QNX_IO_SHUTDOWN,
  QNX_IO_MMAP,
  QNX_IO_MSG,
  QNX_IO_RSVD,
  QNX_IO_DUP,
  QNX_IO_CLOSE,
  QNX_IO_RSVD_LOCK_OCB,   /* Place holder in jump table */
  QNX_IO_RSVD_UNLOCK_OCB, /* Place holder in jump table */
  QNX_IO_SYNC,
  QNX_IO_POWER
};
/*
 * struct _io_connect subtype
 */
enum _io_connect_subtypes
{
  QNX_IO_CONNECT_COMBINE,       /* Combine with IO msg */
  QNX_IO_CONNECT_COMBINE_CLOSE, /* Combine with IO msg and always close */
  QNX_IO_CONNECT_OPEN,
  QNX_IO_CONNECT_UNLINK,
  QNX_IO_CONNECT_RENAME,
  QNX_IO_CONNECT_MKNOD,
  QNX_IO_CONNECT_READLINK,
  QNX_IO_CONNECT_LINK,
  QNX_IO_CONNECT_RSVD_UNBLOCK,  /* Place holder in jump table */
  QNX_IO_CONNECT_MOUNT
};

/*
 * struct _io_connect extra_type
 */
enum _io_connect_extra_type
{
  QNX_IO_CONNECT_EXTRA_NONE,
  QNX_IO_CONNECT_EXTRA_LINK,
  QNX_IO_CONNECT_EXTRA_SYMLINK,
  QNX_IO_CONNECT_EXTRA_MQUEUE,
  QNX_IO_CONNECT_EXTRA_PHOTON,
  QNX_IO_CONNECT_EXTRA_SOCKET,
  QNX_IO_CONNECT_EXTRA_SEM,
  QNX_IO_CONNECT_EXTRA_RESMGR_LINK,
  QNX_IO_CONNECT_EXTRA_PROC_SYMLINK,
  QNX_IO_CONNECT_EXTRA_RENAME,
  QNX_IO_CONNECT_EXTRA_MOUNT,
  QNX_IO_CONNECT_EXTRA_MOUNT_OCB,
  QNX_IO_CONNECT_EXTRA_TYMEM
};
#define QNET_LWL4_VER_LITTLE 0x2a /* 42 */
#define QNET_LWL4_VER_BIG    0xaa /* 42|0x80, msb is set */

static const value_string qnet6_ver_vals[] = {
  {QNET_LWL4_VER_LITTLE, "LWL4 little endian"},
  {QNET_LWL4_VER_BIG, "LWL4 big endian"},
  {0, NULL}
};

#define QNET_L4_TYPE_USER_DATA    0x0
#define QNET_L4_TYPE_TCS_INIT     0x1
#define QNET_L4_TYPE_TCS_REM_UP   0x2
#define QNET_L4_TYPE_TCS_UP       0x3
#define QNET_L4_TYPE_TCS_DOWN     0x4
#define QNET_L4_TYPE_TCS_REM_DOWN 0x5

#define QNET_L4_TYPE_USER 0x8
#define QNET_L4_TYPE_ACK  0x9
#define QNET_L4_TYPE_NACK 0xa
#define QNET_L4_TYPE_LRES 0xb
static const value_string qnet6_type_vals[] = {
  {QNET_L4_TYPE_USER_DATA,    "LWL4 user data packet"},
  {QNET_L4_TYPE_TCS_INIT,     "LWL4 TX establishing connection"},
  {QNET_L4_TYPE_TCS_REM_UP,   "LWL4 RX node UP"},
  {QNET_L4_TYPE_TCS_UP,       "LWL4 TX node UP"},
  {QNET_L4_TYPE_TCS_DOWN,     "LWL4 RX tears connection down"},
  {QNET_L4_TYPE_TCS_REM_DOWN, "LWL4 RX tears connection down"},
  {QNET_L4_TYPE_USER,         "LWL4 Data packet"},
  {QNET_L4_TYPE_ACK,          "LWL4 Ack packet"},
  {QNET_L4_TYPE_NACK,         "LWL4 Nack packet"},
  {QNET_L4_TYPE_LRES,         "LWL4 Lan Resolver packets"},
  {0, NULL}
};

#define QNET_L4_FLAGS_FIRST  0x01
#define QNET_L4_FLAGS_LAST   0x02
#define QNET_L4_FLAGS_CRC    0x04

#define QNET_L4_LAYER_KIF   0
#define QNET_L4_LAYER_NR    1
#define QNET_L4_LAYER_LR    2
#define QNET_L4_LAYER_SEQ   3
static const value_string qnet6_layer_vals[] = {
  {QNET_L4_LAYER_KIF, "Kernel Interface"},
  {QNET_L4_LAYER_NR,  "Node Resolver"},
  {QNET_L4_LAYER_LR,  "Lan Resolver"},
  {QNET_L4_LAYER_SEQ, "Sequence"},
  {0, NULL}
};

#define QNET_L4_QOS_TYPE_LOADBALANCE  0
#define QNET_L4_QOS_TYPE_REDUDANT     1
#define QNET_L4_QOS_TYPE_EXCLUSIVE    2
#define QNET_L4_QOS_TYPE_PREFERRED    3
static const value_string qnet6_qos_type_vals[] = {
  {QNET_L4_QOS_TYPE_LOADBALANCE, "Load balance"},
  {QNET_L4_QOS_TYPE_REDUDANT,    "Redudant"},
  {QNET_L4_QOS_TYPE_EXCLUSIVE,   "Exclusive or Sequential"},
  {QNET_L4_QOS_TYPE_PREFERRED,   "Preferred link"},
  {0, NULL}
};

static const value_string qnet6_lr_ver_vals[] = {
  {1, "1"},
  {0, NULL}
};

#define QNET_LR_TYPE_REQUEST 0x1
#define QNET_LR_TYPE_REPLY   0x2
static const value_string qnet6_lr_type_vals[] = {
  {QNET_LR_TYPE_REQUEST, "Request"},
  {QNET_LR_TYPE_REPLY,   "Reply"},
  {0, NULL}
};

#define QNET_KIF_MSGTYPE_MASK   0x007f
#define QNET_KIF_CRED           0x0100
#define QNET_KIF_ENDIAN_MASK    0x8080
#define QNET_KIF_ENDIAN_LITTLE  0x0000
#define QNET_KIF_ENDIAN_BIG     0x8080

enum QNET_KIF_MSGTYPE
{
  QNET_KIF_MSGTYPE_CONNECT,
  QNET_KIF_MSGTYPE_CONNECT_MSGSEND,
  QNET_KIF_MSGTYPE_CONNECT_SUCCESS,
  QNET_KIF_MSGTYPE_CONNECT_FAIL,
  QNET_KIF_MSGTYPE_UNBLOCK,
  QNET_KIF_MSGTYPE_MSGSEND,
  QNET_KIF_MSGTYPE_MSGREAD,
  QNET_KIF_MSGTYPE_MSGREAD_XFER,
  QNET_KIF_MSGTYPE_MSGWRITE,
  QNET_KIF_MSGTYPE_MSGREPLY,
  QNET_KIF_MSGTYPE_MSGERROR,
  QNET_KIF_MSGTYPE_EVENT,
  QNET_KIF_MSGTYPE_PULSE,
  QNET_KIF_MSGTYPE_SIGNAL,
  QNET_KIF_MSGTYPE_DISCONNECT,
  QNET_KIF_MSGTYPE_CONNECT_DEATH,
  QNET_KIF_MSGTYPE_MSGREAD_ERROR,
  QNET_KIF_MSGTYPE_CONNECT_PULSE

};
/*
 * from lib/c/public/devctl.h
 */
enum QNX_DCMD_DEF
{
  QNX_DCMD_ALL       = 0x01,
  QNX_DCMD_FSYS      = 0x02,
  QNX_DCMD_BLK       = QNX_DCMD_FSYS,
  QNX_DCMD_CHR       = 0x03,
  QNX_DCMD_NET       = 0x04,
  QNX_DCMD_MISC      = 0x05,
  QNX_DCMD_IP        = 0x06,
  QNX_DCMD_MIXER     = 0x07,
  QNX_DCMD_PROC      = 0x08,
  QNX_DCMD_MEM       = 0x09,
  QNX_DCMD_INPUT     = 0x0A,
  QNX_DCMD_PHOTON    = 0x0B,
  QNX_DCMD_CAM       = 0x0C,
  QNX_DCMD_USB       = 0x0D,
  QNX_DCMD_MEDIA     = 0x0E,
  QNX_DCMD_CAM_SIM   = 0x0F,
  QNX_DCMD_MEMCLASS  = 0x10,
  QNX_DCMD_PARTITION = 0x11,
  QNX_DCMD_IOCTL_TTY = 't',
  QNX_DCMD_CTTY      = 'T',
  QNX_DCMD_FCTL      = 'f'
};
enum qnx_mgr_types
{
  _IOMGR_FSYS     = 0x02,
  _IOMGR_TCPIP    = 0x06,
  _IOMGR_PHOTON   = 0x0B,
  _IOMGR_CAM      = 0x0C,
  _IOMGR_PCI      = 0x0d,
  _IOMGR_NETMGR   = 0x0e,
  _IOMGR_REGISTRY = 0x10,
  _IOMGR_PCCARD   = 0x11,
  _IOMGR_USB      = 0x12,
  _IOMGR_MEDIA    = 0x13,
  _IOMGR_PMM      = 0x14,
  _IOMGR_DISPLAY  = 0x15,
  _IOMGR_INPUT    = 0x16
};
static const value_string qnet6_kif_mgr_types_vals[] = {
  {_IOMGR_FSYS,     "_IOMGR_FSYS"},
  {_IOMGR_TCPIP,    "_IOMGR_TCPIP"},
  {_IOMGR_PHOTON,   "_IOMGR_PHOTON"},
  {_IOMGR_CAM,      "_IOMGR_CAM"},
  {_IOMGR_PCI,      "_IOMGR_PCI"},
  {_IOMGR_NETMGR,   "_IOMGR_NETMGR "},
  {_IOMGR_REGISTRY, "_IOMGR_REGISTRY"},
  {_IOMGR_PCCARD,   "_IOMGR_PCCARD"},
  {_IOMGR_USB,      "_IOMGR_USB"},
  {_IOMGR_MEDIA,    "_IOMGR_MEDIA"},
  {_IOMGR_PMM,      "_IOMGR_PMM"},
  {_IOMGR_DISPLAY,  "_IOMGR_DISPLAY"},
  {_IOMGR_INPUT,    "_IOMGR_INPUT"},
  {0, NULL}
};

static const value_string qnet6_kif_msgtype_vals[] = {
  {QNET_KIF_MSGTYPE_CONNECT,         "Connect"},
  {QNET_KIF_MSGTYPE_CONNECT_MSGSEND, "Connect MsgSend"},
  {QNET_KIF_MSGTYPE_CONNECT_SUCCESS, "Connect Success"},
  {QNET_KIF_MSGTYPE_CONNECT_FAIL,    "Connect Fail"},
  {QNET_KIF_MSGTYPE_UNBLOCK,         "Unblock"},
  {QNET_KIF_MSGTYPE_MSGSEND,         "MsgSend"},
  {QNET_KIF_MSGTYPE_MSGREAD,         "MsgRead"},
  {QNET_KIF_MSGTYPE_MSGREAD_XFER,    "MsgRead_Xfer"},
  {QNET_KIF_MSGTYPE_MSGWRITE,        "MsgWrite"},
  {QNET_KIF_MSGTYPE_MSGREPLY,        "MsgReply"},
  {QNET_KIF_MSGTYPE_MSGERROR,        "MsgError"},
  {QNET_KIF_MSGTYPE_EVENT,           "Event"},
  {QNET_KIF_MSGTYPE_PULSE,           "Pulse"},
  {QNET_KIF_MSGTYPE_SIGNAL,          "Signal"},
  {QNET_KIF_MSGTYPE_DISCONNECT,      "Disconnect"},
  {QNET_KIF_MSGTYPE_CONNECT_DEATH,   "Connect Death"},
  {QNET_KIF_MSGTYPE_MSGREAD_ERROR,   "MsgRead Error"},
  {QNET_KIF_MSGTYPE_CONNECT_PULSE,   "Connect Pulse"},
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msgtype_vals[] = {
  {QNX_IO_CONNECT,         "_IO_CONNECT"},
  {QNX_IO_READ,            "_IO_READ"},
  {QNX_IO_WRITE,           "_IO_WRITE"},
  {QNX_IO_RSVD_CLOSE_OCB,  "_IO_CLOSE_OCB"},
  {QNX_IO_STAT,            "_IO_STAT"},
  {QNX_IO_NOTIFY,          "_IO_NOTIFY"},
  {QNX_IO_DEVCTL,          "_IO_DEVCTL"},
  {QNX_IO_RSVD_UNBLOCK,    "_IO_UNBLOCK"},
  {QNX_IO_PATHCONF,        "_IO_PATHCONF"},
  {QNX_IO_LSEEK,           "_IO_LSEEK"},
  {QNX_IO_CHMOD,           "_IO_CHMOD"},
  {QNX_IO_CHOWN,           "_IO_CHOWN"},
  {QNX_IO_UTIME,           "_IO_UTIME"},
  {QNX_IO_OPENFD,          "_IO_OPENFD"},
  {QNX_IO_FDINFO,          "_IO_FDINFO"},
  {QNX_IO_LOCK,            "_IO_LOCK"},
  {QNX_IO_SPACE,           "_IO_SPACE"},
  {QNX_IO_SHUTDOWN,        "_IO_SHUTDOWN"},
  {QNX_IO_MMAP,            "_IO_MMAP"},
  {QNX_IO_MSG,             "_IO_MSG"},
  {QNX_IO_RSVD,            "_IO_RESERVED"},
  {QNX_IO_DUP,             "_IO_DUP"},
  {QNX_IO_CLOSE,           "_IO_CLOSE"},
  {QNX_IO_RSVD_LOCK_OCB,   "_IO_LOCK_OCB"},
  {QNX_IO_RSVD_UNLOCK_OCB, "_IO_UNLOCK_OCB"},
  {QNX_IO_SYNC,            "_IO_SYNC"},
  {QNX_IO_POWER,           "_IO_POWER"},
  {0, NULL}
};

static value_string_ext qnet6_kif_msgsend_msgtype_vals_ext = VALUE_STRING_EXT_INIT(qnet6_kif_msgsend_msgtype_vals);


static const value_string qnet6_kif_msgsend_msg_connect_subtype_vals[] = {
  {QNX_IO_CONNECT_COMBINE,       "_IO_CONNECT_COMBINE"},
  {QNX_IO_CONNECT_COMBINE_CLOSE, "_IO_CONNECT_COMBINE_CLOSE"},
  {QNX_IO_CONNECT_OPEN,          "_IO_CONNECT_OPEN"},
  {QNX_IO_CONNECT_UNLINK,        "_IO_CONNECT_UNLINK"},
  {QNX_IO_CONNECT_RENAME,        "_IO_CONNECT_RENAME"},
  {QNX_IO_CONNECT_MKNOD,         "_IO_CONNECT_MKNOD"},
  {QNX_IO_CONNECT_READLINK,      "_IO_CONNECT_READLINK"},
  {QNX_IO_CONNECT_LINK,          "_IO_CONNECT_LINK"},
  {QNX_IO_CONNECT_RSVD_UNBLOCK,  "_IO_CONNECT_UNBLOCK"},
  {QNX_IO_CONNECT_MOUNT,         "_IO_CONNECT_MOUNT"},
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_connect_extratype_vals[] = {
  {QNX_IO_CONNECT_EXTRA_NONE,         "_IO_CONNECT_EXTRA_NONE"},
  {QNX_IO_CONNECT_EXTRA_LINK,         "_IO_CONNECT_EXTRA_LINK"},
  {QNX_IO_CONNECT_EXTRA_SYMLINK,      "_IO_CONNECT_EXTRA_SYMLINK"},
  {QNX_IO_CONNECT_EXTRA_MQUEUE,       "_IO_CONNECT_EXTRA_MQUEUE"},
  {QNX_IO_CONNECT_EXTRA_PHOTON,       "_IO_CONNECT_EXTRA_PHOTON"},
  {QNX_IO_CONNECT_EXTRA_SOCKET,       "_IO_CONNECT_EXTRA_SOCKET"},
  {QNX_IO_CONNECT_EXTRA_SEM,          "_IO_CONNECT_EXTRA_SEM"},
  {QNX_IO_CONNECT_EXTRA_RESMGR_LINK,  "_IO_CONNECT_EXTRA_RESMGR_LINK"},
  {QNX_IO_CONNECT_EXTRA_PROC_SYMLINK, "_IO_CONNECT_EXTRA_PROC_SYMLINK"},
  {QNX_IO_CONNECT_EXTRA_RENAME,       "_IO_CONNECT_EXTRA_RENAME"},
  {QNX_IO_CONNECT_EXTRA_MOUNT,        "_IO_CONNECT_EXTRA_MOUNT"},
  {QNX_IO_CONNECT_EXTRA_MOUNT_OCB,    "_IO_CONNECT_EXTRA_MOUNT_OCB"},
  {QNX_IO_CONNECT_EXTRA_TYMEM,        "_IO_CONNECT_EXTRA_TYMEM"},
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_devctl_cmd_class_vals[] = {
  {0,                  "QNX Reserved"},
  {QNX_DCMD_ALL,       "All io servers"},
  {QNX_DCMD_FSYS,      "Filesystem or io-blk"},
  {QNX_DCMD_CHR,       "Character"},
  {QNX_DCMD_NET,       "Network driver"},
  {QNX_DCMD_MISC,      "Misc"},
  {QNX_DCMD_IP,        "IP"},
  {QNX_DCMD_MIXER,     "Mixer"},
  {QNX_DCMD_PROC,      "Proc"},
  {QNX_DCMD_MEM,       "Mem"},
  {QNX_DCMD_INPUT,     "Input"},
  {QNX_DCMD_PHOTON,    "Photon"},
  {QNX_DCMD_CAM,       "Cam"},
  {QNX_DCMD_USB,       "Usb"},
  {QNX_DCMD_MEDIA,     "Media"},
  {QNX_DCMD_CAM_SIM,   "CamSim"},
  {QNX_DCMD_MEMCLASS,  "Memory Partition"},
  {QNX_DCMD_PARTITION, "Adaptive Parition"},
  {QNX_DCMD_CTTY,      "T"},
  {QNX_DCMD_FCTL,      "f"},
  {QNX_DCMD_IOCTL_TTY, "IOCTL_TTY"},
  {0, NULL}
};

static value_string_ext qnet6_kif_msgsend_msg_devctl_cmd_class_vals_ext = VALUE_STRING_EXT_INIT(qnet6_kif_msgsend_msg_devctl_cmd_class_vals);

enum QNX_DCMD_CC_DEF
{
  QNX_CCMD_DCMD_ALL_GETFLAGS        = 0x101,
  QNX_CCMD_DCMD_ALL_SETFLAGS        = 0x102,
  QNX_CCMD_DCMD_ALL_GETMOUNTFLAGS   = 0x103,
  QNX_CCMD_DCMD_ALL_GETOWN          = 0x104,
  QNX_CCMD_DCMD_ALL_SETOWN          = 0x105,
  QNX_CCMD_DCMD_ALL_FADVISE         = 0x106,

  QNX_CCMD_DCMD_PROC_SYSINFO        = 0x800,
  QNX_CCMD_DCMD_PROC_INFO           = 0x801,
  QNX_CCMD_DCMD_PROC_MAPINFO        = 0x802,
  QNX_CCMD_DCMD_PROC_MAPDEBUG       = 0x803,
  QNX_CCMD_DCMD_PROC_MAPDEBUG_BASE,
  QNX_CCMD_DCMD_PROC_SIGNAL,
  QNX_CCMD_DCMD_PROC_STOP,
  QNX_CCMD_DCMD_PROC_WAITSTOP,
  QNX_CCMD_DCMD_PROC_STATUS,
  QNX_CCMD_DCMD_PROC_TIDSTATUS      = QNX_CCMD_DCMD_PROC_STATUS,
  QNX_CCMD_DCMD_PROC_CURTHREAD,
  QNX_CCMD_DCMD_PROC_RUN,
  QNX_CCMD_DCMD_PROC_GETGREG,
  QNX_CCMD_DCMD_PROC_SETGREG,
  QNX_CCMD_DCMD_PROC_GETFPREG,
  QNX_CCMD_DCMD_PROC_SETFPREG,
  QNX_CCMD_DCMD_PROC_BREAK,
  QNX_CCMD_DCMD_PROC_FREEZETHREAD,
  QNX_CCMD_DCMD_PROC_THAWTHREAD,
  QNX_CCMD_DCMD_PROC_EVENT,
  QNX_CCMD_DCMD_PROC_SET_FLAG,
  QNX_CCMD_DCMD_PROC_CLEAR_FLAG,
  QNX_CCMD_DCMD_PROC_PAGEDATA,
  QNX_CCMD_DCMD_PROC_GETALTREG,        /* 21 */
  QNX_CCMD_DCMD_PROC_SETALTREG,
  QNX_CCMD_DCMD_PROC_TIMERS,
  QNX_CCMD_DCMD_PROC_IRQS,
  QNX_CCMD_DCMD_PROC_GETREGSET,
  QNX_CCMD_DCMD_PROC_SETREGSET,
  QNX_CCMD_DCMD_PROC_THREADCTL,
  QNX_CCMD_DCMD_PROC_GET_BREAKLIST,
  QNX_CCMD_DCMD_PROC_CHANNELS,
  QNX_CCMD_DCMD_PROC_GET_MEMPART_LIST, /* 30 */
  QNX_CCMD_DCMD_PROC_ADD_MEMPARTID,
  QNX_CCMD_DCMD_PROC_DEL_MEMPARTID,
  QNX_CCMD_DCMD_PROC_CHG_MEMPARTID,    /* 33 */

  QNX_CCMD_DCMD_BLK_PARTENTRY       = 0x201,
  QNX_CCMD_DCMD_BLK_FORCE_RELEARN   = 0x202,

  /*
   * lib/io-char/public/sys/dcmd_chr.h
   */
  QNX_CCMD_DCMD_CHR_TTYINFO         = 0x300 + 10,
  QNX_CCMD_DCMD_CHR_SERCTL          = 0x300 + 20,
  QNX_CCMD_DCMD_CHR_TCINJECTC       = 0x300 + 22,
  QNX_CCMD_DCMD_CHR_TCINJECTR       = 0x300 + 23,
  QNX_CCMD_DCMD_CHR_ISATTY          = 0x300 + 24,
  QNX_CCMD_DCMD_CHR_GETOBAND        = 0x300 + 25,
  QNX_CCMD_DCMD_CHR_ISSIZE          = 0x300 + 27,
  QNX_CCMD_DCMD_CHR_OSSIZE          = 0x300 + 28,
  QNX_CCMD_DCMD_CHR_PARCTL          = 0x300 + 98,
  QNX_CCMD_DCMD_CHR_PNPTEXT         = 0x300 + 99,

  QNX_CCMD_DCMD_CHR_ISCHARS         = ('f' << 0x8) + 127,

  QNX_CCMD_DCMD_CHR_TCFLOW          = ('T' << 0x8) + 6,

  QNX_CCMD_DCMD_CHR_TCGETSID        = ('t' << 0x8) + 7,
  QNX_CCMD_DCMD_CHR_TCSETSID        = ('t' << 0x8) + 8,
  QNX_CCMD_DCMD_CHR_TCFLUSH         = ('t' << 0x8) + 16,
  QNX_CCMD_DCMD_CHR_TCSETATTR       = ('t' << 0x8) + 20,
  QNX_CCMD_DCMD_CHR_TCSETATTRD      = ('t' << 0x8) + 21,
  QNX_CCMD_DCMD_CHR_TCSETATTRF      = ('t' << 0x8) + 22,
  QNX_CCMD_DCMD_CHR_TCGETATTR       = ('t' << 0x8) + 19,
  QNX_CCMD_DCMD_CHR_PUTOBAND        = ('t' << 0x8) + 26,
  QNX_CCMD_DCMD_CHR_TCDRAIN         = ('t' << 0x8) + 94,
  QNX_CCMD_DCMD_CHR_SETSIZE         = ('t' << 0x8) + 103,
  QNX_CCMD_DCMD_CHR_GETSIZE         = ('t' << 0x8) + 104,
  QNX_CCMD_DCMD_CHR_LINESTATUS      = ('t' << 0x8) + 106,
  QNX_CCMD_DCMD_CHR_OSCHARS         = ('t' << 0x8) + 115,
  QNX_CCMD_DCMD_CHR_TCSETPGRP       = ('t' << 0x8) + 118,
  QNX_CCMD_DCMD_CHR_TCGETPGRP       = ('t' << 0x8) + 119,

  /*
   * lib/malloc/public/malloc_g/malloc-lib.h
   */
  QNX_CCMD_DCMD_DBGMEM_ADDSYM       = 0x500 + 0,
  QNX_CCMD_DCMD_DBGMEM_REGISTER     = 0x500 + 1,

  /*
   * services/io-fs/lib/public/sys/dmd_dio.h
   */
  QNX_CCMD_DCMD_DIO_DEVICE          = 0xf00 + 1,
  QNX_CCMD_DCMD_DIO_ALLOC           = 0xf00 + 2,
  QNX_CCMD_DCMD_DIO_IO              = 0xf00 + 3,

  /*
   * services/dumper/public/sys/dcmd_dumper.h
   */
  QNX_CCMD_DCMD_DUMPER_NOTIFYEVENT  = 0x500 + 1,
  QNX_CCMD_DCMD_DUMPER_REMOVEALL    = 0x500 + 3,
  QNX_CCMD_DCMD_DUMPER_REMOVEEVENT  = 0x500 + 2,

  QNX_CCMD_DCMD_FSYS_FORCE_RELEARN  = 0x200 + 2,
  QNX_CCMD_DCMD_FSYS_STATISTICS     = 0x200 + 11,
  QNX_CCMD_DCMD_FSYS_STATISTICS_CLR = 0x200 + 12,
  QNX_CCMD_DCMD_FSYS_STATVFS        = 0x200 + 13,
  QNX_CCMD_DCMD_FSYS_PREGROW_FILE,
  QNX_CCMD_DCMD_FSYS_DIRECT_IO,
  QNX_CCMD_DCMD_FSYS_MOUNTED_ON,
  QNX_CCMD_DCMD_FSYS_MOUNTED_AT,
  QNX_CCMD_DCMD_FSYS_MOUNTED_BY,
  QNX_CCMD_DCMD_FSYS_OPTIONS,
  QNX_CCMD_DCMD_FSYS_FILE_FLAGS,
  QNX_CCMD_DCMD_FSYS_MAP_OFFSET     = 0x200 + 21,

  /*
   * services/io-fs/lib/public/sys/dcmd_fsys.h
   */
  QNX_CCMD_DCMD_FSYS_UUID           = 0x200 + 21, /* same with the MAP_OFFSET */
  QNX_CCMD_DCMD_FSYS_DIR_NFILES,
  QNX_CCMD_DCMD_FSYS_PASS_USE,
  QNX_CCMD_DCMD_FSYS_PASS_CHG,
  QNX_CCMD_DCMD_FSYS_PASS_NEW,
  QNX_CCMD_DCMD_FSYS_CACHE_SET      = 0x200 + 26,

  /*
   * services/io-fs/lib/public/sys/dcmd_media.h
   */
  QNX_CCMD_DCMD_MEDIA_SONG          = 0xe00 + 100,
  QNX_CCMD_DCMD_MEDIA_ALBUM         = 0xe00 + 101,
  QNX_CCMD_DCMD_MEDIA_ARTIST,
  QNX_CCMD_DCMD_MEDIA_GENRE,
  QNX_CCMD_DCMD_MEDIA_COMPOSER,
  QNX_CCMD_DCMD_MEDIA_RELEASE_DATE,
  QNX_CCMD_DCMD_MEDIA_TRACK_NUM,

  QNX_CCMD_DCMD_MEDIA_PUBLISHER     = 0xe00 + 107, /* from */
  QNX_CCMD_DCMD_MEDIA_DURATION      = 0xe00 + 107, /* no direction */

  QNX_CCMD_DCMD_MEDIA_NAME, /* 108 */

  QNX_CCMD_DCMD_MEDIA_INFO_STREAM   = 0xe00 + 114, /* 114 */
  QNX_CCMD_DCMD_MEDIA_OPEN_STREAM,
  QNX_CCMD_DCMD_MEDIA_CLOSE_STREAM,
  QNX_CCMD_DCMD_MEDIA_SET_STREAM,
  QNX_CCMD_DCMD_MEDIA_READ_STREAM,
  QNX_CCMD_DCMD_MEDIA_GET_DEVINFO,
  QNX_CCMD_DCMD_MEDIA_UPNP_CDS_BROWSE,
  QNX_CCMD_DCMD_MEDIA_DRM_IS_AUTH,
  QNX_CCMD_DCMD_MEDIA_DRM_REGISTER,
  QNX_CCMD_DCMD_MEDIA_DRM_PROXIMTY,
  QNX_CCMD_DCMD_MEDIA_DRM_LICENSE,
  QNX_CCMD_DCMD_MEDIA_DRM_CHALLENGE, /* 125 */

  QNX_CCMD_DCMD_MEDIA_PLAY          = 0xe00 + 10,
  QNX_CCMD_DCMD_MEDIA_PLAY_AT,
  QNX_CCMD_DCMD_MEDIA_PAUSE,
  QNX_CCMD_DCMD_MEDIA_RESUME,
  QNX_CCMD_DCMD_MEDIA_NEXT_TRACK,
  QNX_CCMD_DCMD_MEDIA_PREV_TRACK,
  QNX_CCMD_DCMD_MEDIA_FASTFWD,
  QNX_CCMD_DCMD_MEDIA_FASTRWD,
  QNX_CCMD_DCMD_MEDIA_PLAYBACK_INFO,
  QNX_CCMD_DCMD_MEDIA_GET_SHUFFLE,
  QNX_CCMD_DCMD_MEDIA_SET_SHUFFLE,
  QNX_CCMD_DCMD_MEDIA_GET_REPEAT,
  QNX_CCMD_DCMD_MEDIA_SET_REPEAT,

  QNX_CCMD_DCMD_MEDIA_DEBUG0        = 0xe00 + 200,
  QNX_CCMD_DCMD_MEDIA_DEBUG1,
  QNX_CCMD_DCMD_MEDIA_DEBUG2,
  QNX_CCMD_DCMD_MEDIA_DEBUG3,
  QNX_CCMD_DCMD_MEDIA_DEBUG4,
  QNX_CCMD_DCMD_MEDIA_DEBUG5,

  QNX_CCMD_DCMD_IO_NET_MAX_QUEUE    = 0x400 + 10,
  QNX_CCMD_DCMD_IO_NET_PROMISCUOUS  = 0x400 + 12,
  QNX_CCMD_DCMD_IO_NET_WIFI         = 0x400 + 14,
  QNX_CCMD_DCMD_IO_NET_REDIRECT_BELOW,
  QNX_CCMD_DCMD_IO_NET_VERSION,
  QNX_CCMD_DCMD_IO_NET_CHANGE_MCAST,
  QNX_CCMD_DCMD_IO_NET_INSTANCE,
  QNX_CCMD_DCMD_IO_NET_TX_FLUSH,
  QNX_CCMD_DCMD_IO_NET_MIIPHY,
  QNX_CCMD_DCMD_IO_NET_GET_CONFIG

};

/*
 * from services/system/public/sys/procfs.h
 */
static const value_string qnet6_kif_msg_devctl_cmd_class_vals[] = {
  {QNX_CCMD_DCMD_BLK_PARTENTRY,         "DCMD_BLK_PARTENTRY"},
  {QNX_CCMD_DCMD_BLK_FORCE_RELEARN,     "DCMD_BLK_FORCE_RELEARN"},
  {QNX_CCMD_DCMD_FSYS_FORCE_RELEARN,    "DCMD_FSYS_FORCE_RELEARN"},
  {QNX_CCMD_DCMD_FSYS_STATISTICS,       "DCMD_FSYS_STATISTICS"},
  {QNX_CCMD_DCMD_FSYS_STATISTICS_CLR,   "DCMD_FSYS_STATISTICS_CLR"},
  {QNX_CCMD_DCMD_FSYS_STATVFS,          "DCMD_FSYS_STATVFS"},
  {QNX_CCMD_DCMD_FSYS_PREGROW_FILE,     "DCMD_FSYS_PREGROW_FILE"},
  {QNX_CCMD_DCMD_FSYS_DIRECT_IO,        "DCMD_FSYS_DIRECT_IO"},
  {QNX_CCMD_DCMD_FSYS_MOUNTED_ON,       "DCMD_FSYS_MOUNTED_ON"},
  {QNX_CCMD_DCMD_FSYS_MOUNTED_AT,       "DCMD_FSYS_MOUNTED_AT"},
  {QNX_CCMD_DCMD_FSYS_MOUNTED_BY,       "DCMD_FSYS_MOUNTED_BY"},
  {QNX_CCMD_DCMD_FSYS_OPTIONS,          "DCMD_FSYS_OPTIONS"},
  {QNX_CCMD_DCMD_FSYS_FILE_FLAGS,       "DCMD_FSYS_FILE_FLAGS"},
  {QNX_CCMD_DCMD_FSYS_MAP_OFFSET,       "DCMD_FSYS_MAP_OFFSET"},
  {QNX_CCMD_DCMD_FSYS_UUID,             "DCMD_FSYS_UUID"},
  {QNX_CCMD_DCMD_FSYS_DIR_NFILES,       "DCMD_FSYS_DIR_NFILES"},
  {QNX_CCMD_DCMD_FSYS_PASS_USE,         "DCMD_FSYS_PASS_USE"},
  {QNX_CCMD_DCMD_FSYS_PASS_CHG,         "DCMD_FSYS_PASS_CHG"},
  {QNX_CCMD_DCMD_FSYS_PASS_NEW,         "DCMD_FSYS_PASS_NEW"},
  {QNX_CCMD_DCMD_FSYS_CACHE_SET,        "DCMD_FSYS_CACHE_SET"},
  {QNX_CCMD_DCMD_CHR_TTYINFO,           "DCMD_CHR_TTYINFO"},
  {QNX_CCMD_DCMD_CHR_SERCTL,            "DCMD_CHR_SERCTL"},
  {QNX_CCMD_DCMD_CHR_TCINJECTC,         "DCMD_CHR_TCINJECTC"},
  {QNX_CCMD_DCMD_CHR_TCINJECTR,         "DCMD_CHR_TCINJECTR"},
  {QNX_CCMD_DCMD_CHR_ISATTY,            "DCMD_CHR_ISATTY"},
  {QNX_CCMD_DCMD_CHR_GETOBAND,          "DCMD_CHR_GETOBAND"},
  {QNX_CCMD_DCMD_CHR_ISSIZE,            "DCMD_CHR_ISSIZE"},
  {QNX_CCMD_DCMD_CHR_OSSIZE,            "DCMD_CHR_OSSIZE"},
  {QNX_CCMD_DCMD_CHR_PARCTL,            "DCMD_CHR_PARCTL"},
  {QNX_CCMD_DCMD_CHR_PNPTEXT,           "DCMD_CHR_PNPTEXT"},
  {QNX_CCMD_DCMD_IO_NET_MAX_QUEUE,      "DCMD_IO_NET_MAX_QUEUE"},
  {QNX_CCMD_DCMD_IO_NET_PROMISCUOUS,    "DCMD_IO_NET_PROMISCUOUS"},
  {QNX_CCMD_DCMD_IO_NET_WIFI,           "DCMD_IO_NET_WIFI"},
  {QNX_CCMD_DCMD_IO_NET_REDIRECT_BELOW, "DCMD_IO_NET_REDIRECT_BELOW"},
  {QNX_CCMD_DCMD_IO_NET_VERSION,        "DCMD_IO_NET_VERSION"},
  {QNX_CCMD_DCMD_IO_NET_CHANGE_MCAST,   "DCMD_IO_NET_CHANGE_MCAST"},
  {QNX_CCMD_DCMD_IO_NET_INSTANCE,       "DCMD_IO_NET_INSTANCE"},
  {QNX_CCMD_DCMD_IO_NET_TX_FLUSH,       "DCMD_IO_NET_TX_FLUSH"},
  {QNX_CCMD_DCMD_IO_NET_MIIPHY,         "DCMD_IO_NET_MIIPHY"},
  {QNX_CCMD_DCMD_IO_NET_GET_CONFIG,     "DCMD_IO_NET_GET_CONFIG"},
  {QNX_CCMD_DCMD_DBGMEM_ADDSYM,         "DCMD_DBGMEM_ADDSYM"},
  {QNX_CCMD_DCMD_DBGMEM_REGISTER,       "DCMD_DBGMEM_REGISTER"},
  {QNX_CCMD_DCMD_DUMPER_NOTIFYEVENT,    "DCMD_DUMPER_NOTIFYEVENT"},
  {QNX_CCMD_DCMD_DUMPER_REMOVEEVENT,    "DCMD_DUMPER_REMOVEEVENT"},
  {QNX_CCMD_DCMD_DUMPER_REMOVEALL,      "DCMD_DUMPER_REMOVEALL"},
  {QNX_CCMD_DCMD_PROC_SYSINFO,          "DCMD_PROC_SYSINFO:obtain information stored in the system page"},
  {QNX_CCMD_DCMD_PROC_INFO,             "DCMD_PROC_INFO:obtain information about a specific process"},
  {QNX_CCMD_DCMD_PROC_MAPINFO,
   "DCMD_PROC_MAPINFO:obtain segment specific information about mapped memory segments in the specific process "},
  {QNX_CCMD_DCMD_PROC_MAPDEBUG,
   "DCMD_PROC_MAPDEBUG:used by debuggers to find the object that contains the symbol information"},
  {QNX_CCMD_DCMD_PROC_MAPDEBUG_BASE,    "PROC_MAPDEBUG_BASE:obtain information pertaining to the path"},
  {QNX_CCMD_DCMD_PROC_SIGNAL,           "DCMD_PROC_SIGNAL"},
  {QNX_CCMD_DCMD_PROC_STOP,             "DCMD_PROC_STOP"},
  {QNX_CCMD_DCMD_PROC_WAITSTOP,         "DCMD_PROC_WAITSTOP"},
  {QNX_CCMD_DCMD_PROC_STATUS,           "DCMD_PROC_STATUS or TIDSTATUS"},
  {QNX_CCMD_DCMD_PROC_CURTHREAD,        "DCMD_PROC_CURTHREAD"},
  {QNX_CCMD_DCMD_PROC_RUN,              "DCMD_PROC_RUN"},
  {QNX_CCMD_DCMD_PROC_GETGREG,          "DCMD_PROC_GETGREG"},
  {QNX_CCMD_DCMD_PROC_SETGREG,          "DCMD_PROC_SETGREG"},
  {QNX_CCMD_DCMD_PROC_GETFPREG,         ""},
  {QNX_CCMD_DCMD_PROC_SETFPREG,         "DCMD_PROC_SETFPREG"},
  {QNX_CCMD_DCMD_PROC_BREAK,            "DCMD_PROC_BREAK"},
  {QNX_CCMD_DCMD_PROC_FREEZETHREAD,     "DCMD_PROC_FREEZETHREAD"},
  {QNX_CCMD_DCMD_PROC_THAWTHREAD,       "DCMD_PROC_THAWTHREAD"},
  {QNX_CCMD_DCMD_PROC_EVENT,            "DCMD_PROC_EVENT"},
  {QNX_CCMD_DCMD_PROC_SET_FLAG,         "DCMD_PROC_SET_FLAG"},
  {QNX_CCMD_DCMD_PROC_CLEAR_FLAG,       "DCMD_PROC_CLEAR_FLAG"},
  {QNX_CCMD_DCMD_PROC_PAGEDATA,         "DCMD_PROC_PAGEDATA"},
  {QNX_CCMD_DCMD_PROC_GETALTREG,        "DCMD_PROC_GETALTREG"}, /* 21 */
  {QNX_CCMD_DCMD_PROC_SETALTREG,        "DCMD_PROC_SETALTREG"},
  {QNX_CCMD_DCMD_PROC_TIMERS,           "DCMD_PROC_TIMERS"},
  {QNX_CCMD_DCMD_PROC_IRQS,             "DCMD_PROC_IRQS"},
  {QNX_CCMD_DCMD_PROC_GETREGSET,        "DCMD_PROC_GETREGSET"},
  {QNX_CCMD_DCMD_PROC_SETREGSET,        "DCMD_PROC_SETREGSET"},
  {QNX_CCMD_DCMD_PROC_THREADCTL,        "DCMD_PROC_THREADCTL"},
  {QNX_CCMD_DCMD_PROC_GET_BREAKLIST,    "DCMD_PROC_GET_BREAKLIST"},
  {QNX_CCMD_DCMD_PROC_CHANNELS,         "DCMD_PROC_CHANNELS"},
  {QNX_CCMD_DCMD_PROC_GET_MEMPART_LIST, "DCMD_PROC_GET_MEMPART_LIST"}, /* 30 */
  {QNX_CCMD_DCMD_PROC_ADD_MEMPARTID,    "DCMD_PROC_ADD_MEMPARTID"},
  {QNX_CCMD_DCMD_PROC_DEL_MEMPARTID,    "DCMD_PROC_DEL_MEMPARTID"},
  {QNX_CCMD_DCMD_PROC_CHG_MEMPARTID,    "DCMD_PROC_CHG_MEMPARTID"}, /* 33 */
  {QNX_CCMD_DCMD_DIO_DEVICE,            "DCMD_DIO_DEVICE"},
  {QNX_CCMD_DCMD_DIO_ALLOC,             "DCMD_DIO_ALLOC"},
  {QNX_CCMD_DCMD_DIO_IO,                "DCMD_DIO_IO"},
  {QNX_CCMD_DCMD_CHR_TCFLOW,            "DCMD_CHR_TCFLOW"},
  {QNX_CCMD_DCMD_CHR_ISCHARS,           "DCMD_CHR_ISCHARS"},
  {QNX_CCMD_DCMD_CHR_TCGETSID,          "DCMD_CHR_TCGETSID"},
  {QNX_CCMD_DCMD_CHR_TCSETSID,          "DCMD_CHR_TCSETSID"},
  {QNX_CCMD_DCMD_CHR_TCFLUSH,           "DCMD_CHR_TCFLUSH"},
  {QNX_CCMD_DCMD_CHR_TCGETATTR,         "DCMD_CHR_TCGETATTR"},
  {QNX_CCMD_DCMD_CHR_TCSETATTR,         "DCMD_CHR_TCSETATTR"},
  {QNX_CCMD_DCMD_CHR_TCSETATTRD,        "DCMD_CHR_TCSETATTRD"},
  {QNX_CCMD_DCMD_CHR_TCSETATTRF,        "DCMD_CHR_TCSETATTRF"},
  {QNX_CCMD_DCMD_CHR_PUTOBAND,          "DCMD_CHR_PUTOBAND"},
  {QNX_CCMD_DCMD_CHR_TCDRAIN,           "DCMD_CHR_TCDRAIN"},
  {QNX_CCMD_DCMD_CHR_SETSIZE,           "DCMD_CHR_SETSIZE"},
  {QNX_CCMD_DCMD_CHR_GETSIZE,           "DCMD_CHR_GETSIZE"},
  {QNX_CCMD_DCMD_CHR_LINESTATUS,        "DCMD_CHR_LINESTATUS"},
  {QNX_CCMD_DCMD_CHR_OSCHARS,           "DCMD_CHR_OSCHARS"},
  {QNX_CCMD_DCMD_CHR_TCSETPGRP,         "DCMD_CHR_TCSETPGRP"},
  {QNX_CCMD_DCMD_CHR_TCGETPGRP,         "DCMD_CHR_TCGETPGRP"},
  {0, NULL}
};

static value_string_ext qnet6_kif_msg_devctl_cmd_class_vals_ext = VALUE_STRING_EXT_INIT(qnet6_kif_msg_devctl_cmd_class_vals);

enum qnx_io_msg_xtypes
{
  QNX_IO_XTYPE_NONE,
  QNX_IO_XTYPE_READCOND,
  QNX_IO_XTYPE_MQUEUE,
  QNX_IO_XTYPE_TCPIP,
  QNX_IO_XTYPE_TCPIP_MSG,
  QNX_IO_XTYPE_OFFSET,
  QNX_IO_XTYPE_REGISTRY
};
static const value_string qnet6_kif_msgsend_msg_io_read_xtypes_vals[] = {
  {QNX_IO_XTYPE_NONE,      "_IO_XTYPE_NONE"},
  {QNX_IO_XTYPE_READCOND,  "_IO_XTYPE_READCOND"},
  {QNX_IO_XTYPE_MQUEUE,    "_IO_XTYPE_MQUEUE"},
  {QNX_IO_XTYPE_TCPIP,     "_IO_XTYPE_TCPIP"},
  {QNX_IO_XTYPE_TCPIP_MSG, "_IO_XTYPE_TCPIP_MSG"},
  {QNX_IO_XTYPE_OFFSET,    "_IO_XTYPE_OFFSET"},
  {QNX_IO_XTYPE_REGISTRY,  "_IO_XTYPE_REGISTRY"},
  {0, NULL}
};

enum _file_type
{
  QNX_FTYPE_MATCHED = -1,
  QNX_FTYPE_ALL     = -1,
  QNX_FTYPE_ANY     =  0,
  QNX_FTYPE_FILE,
  QNX_FTYPE_LINK,
  QNX_FTYPE_SYMLINK,
  QNX_FTYPE_PIPE,
  QNX_FTYPE_SHMEM,
  QNX_FTYPE_MQUEUE,
  QNX_FTYPE_SOCKET,
  QNX_FTYPE_SEM,
  QNX_FTYPE_PHOTON,
  QNX_FTYPE_DUMPER,
  QNX_FTYPE_MOUNT,
  QNX_FTYPE_NAME,
  QNX_FTYPE_TYMEM
};
static const value_string qnet6_kif_msgsend_msg_connect_filetype_vals[] = {
  {QNX_FTYPE_ALL,     "_FTYPE_ALL"},
  {QNX_FTYPE_ANY,     "_FTYPE_ANY"},
  {QNX_FTYPE_FILE,    "_FTYPE_FILE"},
  {QNX_FTYPE_LINK,    "_FTYPE_LINK"},
  {QNX_FTYPE_SYMLINK, "_FTYPE_SYMLINK"},
  {QNX_FTYPE_PIPE,    "_FTYPE_PIPE"},
  {QNX_FTYPE_SHMEM,   "_FTYPE_SHMEM"},
  {QNX_FTYPE_MQUEUE,  "_FTYPE_MQUEUE"},
  {QNX_FTYPE_SOCKET,  "_FTYPE_SOCKET"},
  {QNX_FTYPE_SEM,     "_FTYPE_SEM"},
  {QNX_FTYPE_PHOTON,  "_FTYPE_PHOTON"},
  {QNX_FTYPE_DUMPER,  "_FTYPE_DUMPER"},
  {QNX_FTYPE_MOUNT,   "_FTYPE_MOUNT"},
  {QNX_FTYPE_NAME,    "_FTYPE_NAME"},
  {QNX_FTYPE_TYMEM,   "_FTYPE_TYMEM"},
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_connect_ioflag_vals[] = {
  {0x0, "readonly"},            /* O_RDONLY 0 */
  {0x1, "writeonly"},           /* O_WRONLY 1 */
  {0x2, "readwrite"},           /* O_RDWR 2 */
#if 0
  {0x4, "append"},              /* O_APPEND 010 */
  {0x5, "datasync"},            /* O_DSYNC 020 */
  {0x6, "sync"},                /* O_SYNC 040 */

  {0x9, "rsync"},               /* O_RSYNC 0100 */
  {0xa, "nonblock"},            /* O_NONBLOCK 0200 */
  {0xb, "creat"},               /* O_CREAT 0400 */

  {0xd, "truncate"},            /* O_TRUNC 01000 */
  {0xe, "exclusive"},           /* O_EXCL 02000 */
  {0xf, "noctrltty"},           /* O_NOCTTY 04000 */
  /*
   * below is QNX extension
   */
  /*
   * O_CLOEXEC 020000
   */
  /*
   * O_REALIDS 040000
   */
  /*
   * O_LARGEFILE 0100000
   */
  /*
   * O_ASYNC 0200000
   */
#endif
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_connect_mode_vals[] = {
#if 0
#define S_IRWXU     000700  /* Read, write, execute/search */
#define S_IRUSR     000400  /* Read permission */
#define S_IWUSR     000200  /* Write permission */
#define S_IXUSR     000100  /* Execute/search permission */

  /*
   *  Group permissions
   */
#define S_IRWXG     000070  /* Read, write, execute/search */
#define S_IRGRP     000040  /* Read permission */
#define S_IWGRP     000020  /* Write permission */
#define S_IXGRP     000010  /* Execute/search permission */

  /*
   *  Other permissions
   */
#define S_IRWXO     000007  /* Read, write, execute/search */
#define S_IROTH     000004  /* Read permission */
#define S_IWOTH     000002  /* Write permission */
#define S_IXOTH     000001  /* Execute/search permission */
#define S_ISUID     004000  /* set user id on execution */
#define S_ISGID     002000  /* set group id on execution */
#define S_ISVTX     001000  /* sticky bit */

#define _S_IFIFO    0x1000  /* FIFO */
#define _S_IFCHR    0x2000  /* Character special */
#define _S_IFDIR    0x4000  /* Directory */
#define _S_IFNAM    0x5000  /* Special named file */
#define _S_IFBLK    0x6000  /* Block special */
#define _S_IFREG    0x8000  /* Regular */
#define _S_IFLNK    0xA000  /* Symbolic link */
#define _S_IFSOCK   0xC000  /* Socket */
#endif
  /*
   * yzhao the value should be the value after bitshift
   */
  {0x1, "FIFO"},
  {0x2, "Character special"},
  {0x4, "Directory"},
  {0x5, "Special named file"},
  {0x6, "Block special"},
  {0x8, "Regular"},
  {0xa, "Symbolic link"},
  {0xc, "Socket"},
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_connect_sflag_vals[] = {
  {0x00, "compatibility mode"},
  {0x01, "DOS-like interpretation of open, locks, etc"},
  {0x10, "deny read/write mode"},
  {0x20, "deny write mode"},
  {0x30, "deny read mode"},
  {0x40, "deny none mode"},
  {0x70, "mask for standard share modes"},
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_connect_access_vals[] = {
  {0x0, "not set"},
  {0x1, "read"}, /* IO_FLAG_RD 1 */
  {0x2, "write"}, /* IO_FLAG_WR 2 */
  {0, NULL}
};

static const value_string qnet6_kif_msgsend_msg_io_seek_whence_vals[] = {
  {0x0, "SEEK_SET"},
  {0x1, "SEEK_CUR"},
  {0x2, "SEEK_END"},
  {0, NULL}
};

enum qnx_io_space_subtype_enum
{
  QNX_F_ALLOCSP64 = 110,
  QNX_F_FREESP64  = 111
};

static const value_string qnet6_kif_msgsend_msg_io_space_subtype_vals[] = {
  {QNX_F_ALLOCSP64, "F_ALLOCSP64"},
  {QNX_F_FREESP64,  "F_FREESP64"},
  {0, NULL}
};

enum pathconf_value
{
  QNX_PC_LINK_MAX           =  1,
  QNX_PC_MAX_CANON,
  QNX_PC_MAX_INPUT,
  QNX_PC_NAME_MAX,
  QNX_PC_PATH_MAX,
  QNX_PC_PIPE_BUF,
  QNX_PC_NO_TRUNC,
  QNX_PC_VDISABLE,
  QNX_PC_CHOWN_RESTRICTED,
  QNX_PC_DOS_SHARE          = 10,
  QNX_PC_IMAGE_VADDR        = 11,
  QNX_PC_ASYNC_IO           = 12,
  QNX_PC_PRIO_IO            = 13,
  QNX_PC_SYNC_IO            = 14,
  QNX_PC_SOCK_MAXBUF        = 15,
  QNX_PC_FILESIZEBITS       = 16,
  QNX_PC_SYMLINK_MAX        = 17,
  QNX_PC_SYMLOOP_MAX        = 18,
  QNX_PC_LINK_DIR           = 19,
  QNX_PC_2_SYMLINKS         = 20,
  QNX_PC_ALLOC_SIZE_MIN     = 21,
  QNX_PC_REC_INCR_XFER_SIZE = 22,
  QNX_PC_REC_MAX_XFER_SIZE  = 23,
  QNX_PC_REC_MIN_XFER_SIZE  = 24,
  QNX_PC_REC_XFER_ALIGN     = 25
};

static const value_string qnet6_kif_msgsend_msg_io_pathconf_name_vals[] = {
  {QNX_PC_LINK_MAX,           "_PC_LINK_MAX"},
  {QNX_PC_MAX_CANON,          "_PC_MAX_CANON"},
  {QNX_PC_MAX_INPUT,          "_PC_MAX_INPUT"},
  {QNX_PC_NAME_MAX,           "_PC_NAME_MAX"},
  {QNX_PC_PATH_MAX,           "_PC_PATH_MAX"},
  {QNX_PC_PIPE_BUF,           "_PC_PIPE_BUF"},
  {QNX_PC_NO_TRUNC,           "_PC_NO_TRUNC"},
  {QNX_PC_VDISABLE,           "_PC_VDISABLE"},
  {QNX_PC_CHOWN_RESTRICTED,   "_PC_CHOWN_RESTRICTED"},
  {QNX_PC_DOS_SHARE,          "_PC_DOS_SHARE"},
  {QNX_PC_IMAGE_VADDR,        "_PC_IMAGE_VADDR"},
  {QNX_PC_ASYNC_IO,           "_PC_ASYNC_IO"},
  {QNX_PC_PRIO_IO,            "_PC_PRIO_IO"},
  {QNX_PC_SYNC_IO,            "_PC_SYNC_IO"},
  {QNX_PC_SOCK_MAXBUF,        "_PC_SOCK_MAXBUF"},
  {QNX_PC_FILESIZEBITS,       "_PC_FILESIZEBITS"},
  {QNX_PC_SYMLINK_MAX,        "_PC_SYMLINK_MAX"},
  {QNX_PC_SYMLOOP_MAX,        "_PC_SYMLOOP_MAX"},
  {QNX_PC_LINK_DIR,           "_PC_LINK_DIR"},
  {QNX_PC_2_SYMLINKS,         "_PC_2_SYMLINKS"},
  {QNX_PC_ALLOC_SIZE_MIN,     "_PC_ALLOC_SIZE_MIN"},
  {QNX_PC_REC_INCR_XFER_SIZE, "_PC_REC_INCR_XFER_SIZE"},
  {QNX_PC_REC_MAX_XFER_SIZE,  "_PC_REC_MAX_XFER_SIZE"},
  {QNX_PC_REC_MIN_XFER_SIZE,  "_PC_REC_MIN_XFER_SIZE"},
  {QNX_PC_REC_XFER_ALIGN,     "_PC_REC_XFER_ALIGN"},
  {0, NULL}
};

static value_string_ext qnet6_kif_msgsend_msg_io_pathconf_name_vals_ext = VALUE_STRING_EXT_INIT(qnet6_kif_msgsend_msg_io_pathconf_name_vals);

enum QNX_IO_OPENFD_XTYPES
{
  _IO_OPENFD_NONE,
  _IO_OPENFD_PIPE,
  _IO_OPENFD_KQUEUE,
  _IO_OPENFD_ACCEPT,
  _IO_OPENFD_SCTP_PEELOFF
};

static const value_string qnet6_kif_msgsend_msg_openfd_xtypes_vals[] = {
  {_IO_OPENFD_NONE,         "_IO_OPENFD_NONE"},
  {_IO_OPENFD_PIPE,         "_IO_OPENFD_PIPE"},
  {_IO_OPENFD_KQUEUE,       "_IO_OPENFD_KQUEUE"},
  {_IO_OPENFD_ACCEPT,       "_IO_OPENFD_ACCEPT"},
  {_IO_OPENFD_SCTP_PEELOFF, "_IO_OPENFD_SCTP_PEELOFF"},
  {0, NULL}
};

#define QNX_NTO_SIDE_CHANNEL 0x40000000
#define QNX_NTO_GLOBAL_CHANNEL QNX_NTO_SIDE_CHANNEL

/*
 * Perform LWL4 crc check
 */
static gboolean qnet6_lwl4_check_crc = TRUE;

/*
 * in sys/lsm/qnet/qos.h LR is using sockaddr as addr Family:1 means mac
 * :2 means interface name
 */
#define QNET_LR_SA_FAMILY_MAC 1

/*
 * when dissect_qnet6_lr is called in dissect_qnet6, it has already
 * checked whether left length > sizeof(struct qnet6_lr_pkt) so here we
 * have to check whether off, len > left length proto_tree_add_subtree and
 * proto_tree_add_string's difference are text doesn't need the hf_... so
 * it can't be searched.
 */
static int
dissect_qnet6_lr(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
#define QNET6_LR_PAIRS 6
  proto_item   *ti;
  proto_tree   *stree, *srctree, *dstree, *sstree = NULL;
  guint32       total_len, off, len, rlen;
  gint          lr_start, i, hf_index_off = -1, hf_index_len = -1, hf_index = -1;
  guint8        type;
  guint8 const *p, *name[QNET6_LR_PAIRS];

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "QNET_LR");

  /*
   * now rlen is the length of data behind qnet6_lr_pkt + qnet6_lr_pkt
   */
  rlen = tvb_reported_length_remaining(tvb, *poffset + QNX_QNET6_LR_PKT_SIZE);

  lr_start = *poffset;
  ti = proto_tree_add_item(tree, proto_qnet6_lr, tvb, *poffset, -1, ENC_NA);
  stree = proto_item_add_subtree(ti, ett_qnet6_lr);

  /*
   * version
   */
  proto_tree_add_item(stree, hf_qnet6_lr_ver, tvb, (*poffset)++, 1, ENC_BIG_ENDIAN);
  (*poffset)++; /* skip spare byte */
  /*
   * type
   */
  type = tvb_get_guint8(tvb, *poffset);
  proto_tree_add_item(stree, hf_qnet6_lr_type, tvb, (*poffset)++, 1, ENC_BIG_ENDIAN);
  (*poffset)++; /* skip another spare byte */

  /*
   * total length which includes this header and name payload
   */
  total_len = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_uint(stree, hf_qnet6_lr_total_len, tvb, *poffset, 4, total_len);
  *poffset += 4;

  ti = proto_tree_add_string(stree, hf_qnet6_lr_src, tvb, *poffset, 4 * 6, "source node information");
  srctree = proto_item_add_subtree(ti, ett_qnet6_lr_src);
  ti = proto_tree_add_string(stree, hf_qnet6_lr_dst, tvb, *poffset + 4 * 6, 4 * 6, "destination node information");
  dstree = proto_item_add_subtree(ti, ett_qnet6_lr_dst);
  rlen = MIN(rlen, total_len);

  for (i = 0; i < QNET6_LR_PAIRS; i++)
    {
      if (i < 3)
        stree = srctree;
      else
        stree = dstree;

      switch (i)
        {
        case 0:
          hf_index_off = hf_qnet6_lr_src_name_off;
          hf_index_len = hf_qnet6_lr_src_name_len;
          hf_index = hf_qnet6_lr_src_name_generated;
          sstree = proto_tree_add_subtree(stree, tvb, *poffset, 4 * 2,
              ett_qnet6_lr_src_name_subtree, NULL, "name");
          break;
        case 1:
          hf_index_off = hf_qnet6_lr_src_domain_off;
          hf_index_len = hf_qnet6_lr_src_domain_len;
          hf_index = hf_qnet6_lr_src_domain_generated;
          sstree = proto_tree_add_subtree(stree, tvb, *poffset, 4 * 2,
              ett_qnet6_lr_src_name_subtree, NULL, "domain");
          break;
        case 2:
          hf_index_off = hf_qnet6_lr_src_addr_off;
          hf_index_len = hf_qnet6_lr_src_addr_len;
          hf_index = hf_qnet6_lr_src_addr_generated;
          sstree = proto_tree_add_subtree(stree, tvb, *poffset, 4 * 2,
              ett_qnet6_lr_src_name_subtree, NULL, "address");
          break;
        case 3:
          hf_index_off = hf_qnet6_lr_dst_name_off;
          hf_index_len = hf_qnet6_lr_dst_name_len;
          hf_index = hf_qnet6_lr_dst_name_generated;
          sstree = proto_tree_add_subtree(stree, tvb, *poffset, 4 * 2,
              ett_qnet6_lr_src_name_subtree, NULL, "name");
          break;
        case 4:
          hf_index_off = hf_qnet6_lr_dst_domain_off;
          hf_index_len = hf_qnet6_lr_dst_domain_len;
          hf_index = hf_qnet6_lr_dst_domain_generated;
          sstree = proto_tree_add_subtree(stree, tvb, *poffset, 4 * 2,
              ett_qnet6_lr_src_name_subtree, NULL, "domain");
          break;
        case 5:
          hf_index_off = hf_qnet6_lr_dst_addr_off;
          hf_index_len = hf_qnet6_lr_dst_addr_len;
          hf_index = hf_qnet6_lr_dst_addr_generated;
          sstree = proto_tree_add_subtree(stree, tvb, *poffset, 4 * 2,
              ett_qnet6_lr_src_name_subtree, NULL, "address");
          break;
        }

      off = tvb_get_guint32(tvb, *poffset, encoding);
      proto_tree_add_item(sstree, hf_index_off, tvb, *poffset, 4, encoding);
      *poffset += 4;

      len = tvb_get_guint32(tvb, *poffset, encoding);
      proto_tree_add_item(sstree, hf_index_len, tvb, *poffset, 4, encoding);
      *poffset += 4;

      if ((off <= rlen) && (len <= rlen))
        {
          guint addr_data_offset = lr_start + off + QNX_QNET6_LR_PKT_SIZE /* sizeof(struct qnet6_lr_pkt) */;
          /*
           * struct qnet6_lr_pkt is 64 bit aligned
           */
          if (i != 2 && i != 5)
            {
            name[i] = tvb_get_string_enc(wmem_packet_scope(),
                                         tvb,
                                         addr_data_offset,
                                         len,
                                         ENC_ASCII|ENC_NA);
                ti = proto_tree_add_string(sstree, hf_index, tvb, addr_data_offset, len, name[i]);
                PROTO_ITEM_SET_GENERATED(ti);
            }
          else
            {
              if (tvb_get_guint8(tvb, addr_data_offset + 1) == QNET_LR_SA_FAMILY_MAC && len >= 2 + 6)
                {
                  name[i] = tvb_ether_to_str(tvb, addr_data_offset + 2);
                  ti = proto_tree_add_item(sstree, hf_index, tvb, addr_data_offset + 2, 6, ENC_NA);
                  PROTO_ITEM_SET_GENERATED(ti);
                }
              else
                {
                  /* The comment above suggests that value '2' means interface
                   * name, but this was not observed in the provided pcap, so
                   * let's ignore that possibility for now. */
                  name[i] = NULL;
                }
            }
        }
      else
        {
          name[i] = NULL;
        }
    }

  switch (type)
    {
    case QNET_LR_TYPE_REQUEST:
      p = name[2];
      if (p)
        {
          col_add_fstr(pinfo->cinfo, COL_INFO,
                        "Who is \"%s.%s\"? Tell \"%s.%s\"@%s",
                        name[3] ? (const char*)name[3] : "?", name[4] ? (const char*)name[4] : "?",
                        name[0] ? (const char*)name[0] : "?", name[1] ? (const char*)name[1] : "?",
                        p);
        }
      break;
    case QNET_LR_TYPE_REPLY:
      p = name[2];
      if (p)
        {
          col_add_fstr(pinfo->cinfo, COL_INFO,
                        "To \"%s.%s\", \"%s.%s\" is at %s",
                        name[3] ? (const char*)name[3] : "?", name[4] ? (const char*)name[4] : "?",
                        name[0] ? (const char*)name[0] : "?", name[1] ? (const char*)name[1] : "?",
                        p);
        }
      break;
    default:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown LR Type");
    }

  return *poffset - lr_start;
}

#define QNX_NR_PING_REQ     0
#define QNX_NR_PING_ANS     1
#define QNX_NR_REMOTE_REQ   2
#define QNX_NR_REMOTE_ANS   3
#define QNX_NR_REMOTE_ERROR 4

static const value_string qnet6_nr_type_vals[] = {
  {QNX_NR_PING_REQ,     "Network Resolver Ping Request"},
  {QNX_NR_PING_ANS,     "Network Resolver Ping Reply"},
  {QNX_NR_REMOTE_REQ,   "Network Resolver Remote Request"},
  {QNX_NR_REMOTE_ANS,   "Network Resolver Remote Reply"},
  {QNX_NR_REMOTE_ERROR, "Network Resolver Remote Error"},
  {0, NULL}
};

#define QNX_NOTIFY_ACTION_TRANARM 0x0
#define QNX_NOTIFY_ACTION_CONDARM 0x1
#define QNX_NOTIFY_ACTION_POLL    0x2
#define QNX_NOTIFY_ACTION_POLLARM 0x3
static const value_string qnet6_kif_msgsend_msg_io_notify_action_vals[] = {
  {QNX_NOTIFY_ACTION_TRANARM, "_NOTIFY_ACTION_TRANARM"},
  {QNX_NOTIFY_ACTION_CONDARM, "_NOTIFY_ACTION_CONDARM"},
  {QNX_NOTIFY_ACTION_POLL,    "_NOTIFY_ACTION_POLL"},
  {QNX_NOTIFY_ACTION_POLLARM, "_NOTIFY_ACTION_POLLARM"},
  {0, NULL}
};

/*
 * NR related header files are in sys/lsm/qnet/nr_msg.h yzhao
 */
static int
dissect_qnet6_nr(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
  proto_item *ti;
  proto_tree *stree;
  guint8      name_len, rlen, type;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "QNET_NR");

  ti = proto_tree_add_item(tree, proto_qnet6_nr, tvb, *poffset, -1, ENC_NA);
  stree = proto_item_add_subtree(ti, ett_qnet6_nr);

  /*
   * type
   */
  type = tvb_get_guint8(tvb, *poffset);
  proto_tree_add_item(stree, hf_qnet6_nr_type, tvb, (*poffset)++, 1, ENC_NA);
  switch (type)
    {
    case QNX_NR_PING_REQ:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Network Resolver Ping Request");
      break;
    case QNX_NR_PING_ANS:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Network Resolver Ping Reply");
      /*
       * ping request/reply there is no further data
       */
      break;
    case QNX_NR_REMOTE_REQ:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Network Resolver Remote Request");
      name_len = tvb_get_guint8(tvb, *poffset);
      proto_tree_add_item(stree, hf_qnet6_nr_remote_req_len, tvb, (*poffset)++, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(stree, hf_qnet6_nr_remote_req_id, tvb, *poffset, 2, encoding);
      *poffset += 2;
      rlen = MIN(name_len, tvb_reported_length_remaining(tvb, *poffset));
      proto_tree_add_item(stree, hf_qnet6_nr_remote_req_name, tvb, *poffset, rlen, encoding);
      *poffset += rlen;
      break;
    case QNX_NR_REMOTE_ANS:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Network Resolver Remote Reply");
      proto_tree_add_item(stree, hf_qnet6_nr_remote_rep_spare, tvb, (*poffset)++, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(stree, hf_qnet6_nr_remote_rep_id, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_item(stree, hf_qnet6_nr_remote_rep_nd, tvb, *poffset, 4, encoding);
      *poffset += 4;
      break;
    case QNX_NR_REMOTE_ERROR:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Network Resolver Remote Error");
      proto_tree_add_item(stree, hf_qnet6_nr_remote_rep_spare, tvb, (*poffset)++, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(stree, hf_qnet6_nr_remote_rep_id, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_item(stree, hf_qnet6_nr_remote_rep_status, tvb, *poffset, 4, encoding);
      *poffset += 4;
      break;
    default:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown type");
      break;
    }

  return 0;
}

/*
 * in Neutrino pid_t is _INT32
 */
/*
 * all definitions below are based on QNX Neutrino only supports 32 bits
 * now struct qnet6_kif_connect { guint16 msgtype; guint16 size; // Size
 * of message with cred if sent guint32 version; // Version of local
 * protocol gint32 server_pid; // target process on remote node gint32
 * server_chid; // target channel on remote node gint32 client_id; //
 * handle for remote node to use for this connection gint32 client_pid;
 * // local process id for remote node to verify }; struct
 * qnet6_kif_connect_success { guint16 msgtype; //
 * qnet6_kif_CONNECT_SUCCESS guint16 size; // Size of message guint32
 * version; // Version of remote protocol gint32 client_id; // Handle
 * passed in qnet6_kif_connect gint32 server_id; // A handle on remote
 * node to target messages gint32 scoid; // Remote server's server
 * connect id for local information guint32 nbytes; // Number of bytes to
 * limit qnet6_kif_msgsend to };
 *
 * struct qnet6_kif_connect_fail { guint16 msgtype; //
 * qnet6_kif_CONNECT_FAIL guint16 size; // Size of message guint32
 * version; // Version of remote protocol gint32 client_id; // Handle
 * passed in qnet6_kif_connect gint32 status; // errno reason for failure
 * };
 *
 * struct qnet6_kif_connect_death { guint16 msgtype; //
 * qnet6_kif_CONNECT_DEATH guint16 size; // Size of message gint32
 * client_id; // Handle passed in qnet6_kif_connect };
 */
/*
 * _vtid_info is in sys/neutrino.h
 */
/*
 * struct _vtid_info { gint32 tid; gint32 coid; gint32 priority; gint32
 * srcmsglen; gint32 keydata; gint32 srcnd; gint32 dstmsglen; gint32 zero;
 * }; struct qnet6_kif_msgsend { guint16 msgtype; // qnet6_kif_MSGSEND
 * guint16 size; // Size of message without message gint32 server_id; //
 * Handle returned in qnet6_kif_connect_success gint32 client_handle; //
 * Local handle for this transaction struct _vtid_info vinfo; // Info that
 * changes frequently guint32 nbytes; // number of bytes limited by what
 * remote node requested // unsigned char message[]; // Data to be sent
 * };
 *
 * struct qnet6_kif_msgread { guint16 msgtype; // qnet6_kif_MSGREAD
 * guint16 size; // Size of message gint32 msgread_handle; // Remote
 * handle to msgxfer to gint32 client_handle; // Local handle for this
 * transaction guint32 offset; // Requested offset to read from guint32
 * nbytes; // Requested size to read };
 *
 * struct qnet6_kif_msgwrite { guint16 msgtype; // MSGWRITE, MSGREPLY,
 * MSGERROR, MSGREAD_XFER, MSGREAD_ERROR guint16 size; // Size of message
 * without message gint32 status; // MSGWRITE/MSGREAD_XFER=not used,
 * MSGREPLY=status, MSGERROR,MSGREAD_ERROR=errno gint32 handle; // xfer
 * handle (msgread_handle or client_handle) guint32 offset; // Requested
 * offset to xfer to guint32 nbytes; // Requested size to xfer //
 * unsigned char message[]; // Data to be sent };
 *
 * struct qnet6_kif_unblock { guint16 msgtype; // qnet6_kif_UNBLOCK
 * guint16 size; // Size of message gint32 server_id; // Handle returned
 * in qnet6_kif_connect_success gint32 client_handle; // Local handle to
 * match for unblock int tid; // Local threadid to unblock (match to
 * vinfo.tid) };
 */
/*
 * _pulse is in sys/neutrino.h too
 */
/*
 * QNX6 doesn't support 64 bits yet so void* will be 32 bits, and I assume
 * the int as 32 bits too(I haven't see int is not 32 bits yet on
 * Windows64 and Linux64 so change it to gint32 sizeof(union sigval) will
 * change when QNX6 supports 64 bits and you may see 32, 64 bits OSes
 * running on different machines with QNX even preference may not help as
 * these are application level data.
 */
/*
 * union sigval_qnx { gint32 sival_int; void *sival_ptr; }; struct
 * sigevent_qnx { int sigev_notify; union { int __sigev_signo; int
 * __sigev_coid; int __sigev_id; void (*__sigev_notify_function) (union
 * sigval); } __sigev_un1; union sigval_qnx sigev_value; union { struct {
 * short __sigev_code; short __sigev_priority; } __st; pthread_attr_t
 * *__sigev_notify_attributes; } __sigev_un2;
 *
 * };
 *
 * struct qnet6_kif_event { guint16 msgtype; // qnet6_kif_EVENT guint16
 * size; // Size of message gint32 client_handle; // Local handle to
 * deliver event to struct sigevent_qnx event; // Event to be delivered
 * };
 *
 * struct _pulse { guint16 type; guint16 subtype; gint8 code; guint8
 * reserved[3]; // zero must be union sigval_qnx value; gint32 scoid; };
 * struct qnet6_kif_pulse { guint16 msgtype; // qnet6_kif_PULSE guint16
 * size; // Size of message gint32 server_id; // Handle returned in
 * qnet6_kif_connect_success gint32 client_handle; // Local handle for
 * this transaction struct _vtid_info vinfo; // Info that changes
 * frequently struct _pulse pulse; // Pulse to deliver to remote gint32
 * priority; // Priority in MsgSendPulse() };
 *
 * struct qnet6_kif_signal { guint16 msgtype; // qnet6_kif_SIGNAL guint16
 * size; // Size of message gint32 client_handle; // Local handle for
 * this transaction gint32 pid; // Signal from this pid (local) gint32
 * tid; // Signal from this tid (local) gint32 signo; // Signal to
 * deliver to remote gint32 code; gint32 value; };
 *
 * struct qnet6_kif_disconnect { guint16 msgtype; // qnet6_kif_DISCONNECT
 * guint16 size; // Size of message gint32 server_id; // Handle returned
 * in qnet6_kif_connect_success };
 */

static void
display_channel_id(guint32 chid, proto_item * ti)
{
  if (chid & QNX_NTO_GLOBAL_CHANNEL)
    {
      proto_item_append_text(ti, " _NTO_GLOBAL_CHANNEL|%" G_GUINT32_FORMAT, chid & ~QNX_NTO_GLOBAL_CHANNEL);
    }
}

static void
display_coid(guint32 coid, proto_item * ti)
{
  if (coid & QNX_NTO_SIDE_CHANNEL)
    { /* side channel */
      if ((coid & ~QNX_NTO_SIDE_CHANNEL) == 0)
        proto_item_append_text(ti, " SYSMGR_COID)");
      else
        proto_item_append_text(ti," (_NTO_SIDE_CHANNEL|%" G_GUINT32_FORMAT ")", coid & ~QNX_NTO_SIDE_CHANNEL);
    }
}

/*
 * struct qnx_io_devctl { _Uint16t type; _Uint16t combine_len; _Int32t
 * dcmd; _Int32t nbytes; _Int32t zero; };
 *
 * struct qnx_io_devctl_reply { _Uint32t zero; _Int32t ret_val; _Int32t
 * nbytes; _Int32t zero2; }; #define _POSIX_DEVDIR_NONE 0 #define
 * _POSIX_DEVDIR_TO 0x80000000 #define _POSIX_DEVDIR_FROM 0x40000000
 * #define _POSIX_DEVDIR_TOFROM (_POSIX_DEVDIR_TO | _POSIX_DEVDIR_FROM)
 * #define _POSIX_DEVDIR_CMD_MASK 0x0000FFFF
 */
/*
 * direction is encoded in command's highest 2 bits and command only uses
 * 16 bits please reference QNX' lib/c/public/devctl.h
 */

static int
dissect_qnet6_kif_msgsend_msg(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding);

static void
dissect_qnet6_kif_msgsend_msg_extra(tvbuff_t * tvb, proto_tree * tree, gint * poffset, gint combine_len, gint * left, gint clen, const char *data)
{
  gint nlen;

  nlen = combine_len & ~0x8000;
  /*
   * combine_len includes the type as well
   */
  if (nlen > clen)
    { /* there are data behind _io_msg */
      nlen -= clen;
      if (nlen > *left)
        nlen = *left;
      if (nlen > 0)
        {
          proto_tree_add_string(tree, hf_qnet6_kif_msgsend_extra, tvb, *poffset, nlen, data);
          *poffset += nlen;
          *left -= nlen;
        }
    }
}

/*
 * struct _msg_info { // _msg_info _server_info _Uint32t nd; // client
 * server _Uint32t srcnd; // server n/a pid_t pid; // client server
 * _Int32t tid; // thread n/a _Int32t chid; // server server _Int32t
 * scoid; // server server _Int32t coid; // client client _Int32t
 * msglen; // msg n/a _Int32t srcmsglen; // thread n/a _Int32t
 * dstmsglen; // thread n/a _Int16t priority; // thread n/a _Int16t
 * flags; // n/a client _Uint32t reserved; };
 */
#define QNX_MSG_INFO_SIZE (12*4)
static int
dissect_qnet6_kif_msgsend_msg_msginfo(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int         ret = -1;
  guint32     chid, coid;
  proto_item *ti;

  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_nd, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_srcnd, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_pid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_tid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  chid = tvb_get_guint32(tvb, *poffset, encoding);
  ti = proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_chid, tvb, *poffset, 4, encoding);
  display_channel_id(chid, ti);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_scoid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  coid = tvb_get_guint32(tvb, *poffset, encoding);
  ti = proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_coid, tvb, *poffset, 4, encoding);
  display_coid(coid, ti);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_msglen, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_srcmsglen, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_dstmsglen, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_priority, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_flags, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_msginfo_reserved, tvb, *poffset, 4, encoding);
  *poffset += 4;

  return ret;

}

/*
 * in dissect_qnet6_kif_msgsend_msg already passed the first 2 bytes
 * msg->type and when dissect_qnet6_kif_msgsend_msg_devctl is called, it
 * is guaranteed that at least there 2+4+4+4 data left
 */

static int
dissect_qnet6_kif_msgsend_msg_devctl(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
  int         ret = -1;
  gint        combine_len, left;
  const char *p;
  guint32     dcmd;
  static const int *dcmd_fields[] = {
    &hf_qnet6_kif_msg_devctl_dcmd_cmd,
    &hf_qnet6_kif_msg_devctl_dcmd_class,
    &hf_qnet6_kif_msg_devctl_dcmd_ccmd,
    &hf_qnet6_kif_msg_devctl_dcmd_size,
    &hf_qnet6_kif_msg_devctl_dcmd_from,
    &hf_qnet6_kif_msg_devctl_dcmd_to,
    NULL
  };

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  dcmd = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_devctl_dcmd, ett_qnet6_kif_msg_devctl_dcmd, dcmd_fields, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_devctl_nbytes, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_devctl_zero, tvb, *poffset, 4, encoding);
  *poffset += 4;
  left = tvb_reported_length_remaining(tvb, *poffset);

  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3, "devctl's extra data");
  p = try_val_to_str_ext((dcmd & 0x0000ffff), &qnet6_kif_msg_devctl_cmd_class_vals_ext);
  if (p)
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", p);

  ret = 0;
  /*
   * how combine_len works? message header1
   * (combine_len=COMBINE_LEN_FLAG| sizeof(header1)+ its data size
   * message header1's data(optional) message header2
   * combine_len=COMBINE_FLAG|sizeof(message header2)+its data size so
   * combine_len is the size of its own header+data|COMBINE_FLAG
   */
  /*
   * if combine_len > sizeof(qnx_io_devctl) then there are other
   * messages behind
   */
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (0 < left)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;
}

/*
 * struct qnx_io_read { _Uint16t type; _Uint16t combine_len; _Int32t
 * nbytes; _Uint32t xtype; _Uint32t zero; };
 *
 * typedef union { struct qnx_io_read i; } io_read_t;
 */

static int
dissect_qnet6_kif_msgsend_msg_read(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int     ret = -1;
  guint32 xtypes;
  gint    combine_len, left;
  static const int *xtypes_fields[] = {
    &hf_qnet6_kif_msg_io_read_xtypes_0_7,
    &hf_qnet6_kif_msg_io_read_xtypes_8,
    &hf_qnet6_kif_msg_io_read_xtypes_14,
    &hf_qnet6_kif_msg_io_read_xtypes_15,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_nbytes, tvb,  *poffset, 4, encoding);
  *poffset += 4;
  xtypes = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_io_read_xtypes, ett_qnet6_kif_msg_read_xtypes, xtypes_fields, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_zero, tvb, *poffset, 4, ENC_NA);
  *poffset += 4;

  /*
   * if xtypes is not _IO_XTYPE_NONE then after io_read_t it is another
   * structure according the xtype&0xff
   */
  left -= 2 + 4 * 3;
  switch (xtypes & 0xff)
    {
    case QNX_IO_XTYPE_OFFSET:
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_xoffset, tvb, *poffset, 8, encoding);
      *poffset += 8;
      left -= 8;
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3 + 8, "read's extra data");
      break;
    case QNX_IO_XTYPE_READCOND:
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_cond_min, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_cond_time,tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_cond_timeout, tvb, *poffset, 4, encoding);
      *poffset += 4;
      left -= 12;
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3 + 12, "read's extra data");
      break;
    default:
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3, "read's extra data");
      break;
    }
  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_write(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int     ret = -1;
  guint32 xtypes;
  gint    combine_len, left;
  static const int *xtypes_fields[] = {
    &hf_qnet6_kif_msg_io_write_xtypes_0_7,
    &hf_qnet6_kif_msg_io_write_xtypes_8,
    &hf_qnet6_kif_msg_io_write_xtypes_14,
    &hf_qnet6_kif_msg_io_write_xtypes_15,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_write_nbytes, tvb, *poffset, 4, encoding);
  *poffset += 4;
  xtypes = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_io_write_xtypes, ett_qnet6_kif_msg_write_xtypes, xtypes_fields, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_zero, tvb, *poffset, 4, ENC_NA);
  *poffset += 4;

  /*
   * if xtypes is not _IO_XTYPE_NONE then after io_read_t it is another
   * structure according the xtype&0xff
   */
  left -= 2 + 4 * 3;
  switch (xtypes & 0xff)
    {
    case QNX_IO_XTYPE_OFFSET:
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_write_xoffset, tvb, *poffset, 8, encoding);
      *poffset += 8;
      left -= 8;
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3 + 8, "write's extra data");
      break;
    case QNX_IO_XTYPE_READCOND:
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_cond_min, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_cond_time, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(tree, hf_qnet6_kif_msg_io_read_cond_timeout, tvb, *poffset, 4, encoding);
      *poffset += 4;
      left -= 12;
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3 + 12, "write's extra data");
      break;
    default:
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3, "write's extra data");
      break;
    }

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }
  else
    {
      if (left > 0)
        proto_tree_add_item(tree, hf_qnet6_kif_msg_io_write_data, tvb, *poffset, left, ENC_NA);
    }

  return ret;

}

/*
 *struct qnx_io_lseek {
 _Uint16t type;
 _Uint16t combine_len;
 short whence;
 _Uint16t zero;
 _Uint64t offset;
 };

 typedef union {
 struct qnx_io_lseek i;
 _Uint64t o;
 } io_lseek_t;
 */
static int
dissect_qnet6_kif_msgsend_msg_seek(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_seek_whence, tvb, *poffset, 2, encoding);
  *poffset += 2;

  proto_tree_add_item(tree, hf_qnet6_kif_zero, tvb, *poffset, 2, ENC_NA);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_seek_offset, tvb, *poffset, 8, encoding);
  *poffset += 8;
  left -= 2 + 2 + 2 + 8;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 2 + 2 + 8, "seek's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

/*
 *struct qnx_io_pathconf {
 _Uint16t type;
 _Uint16t combine_len;
 short name;
 _Uint16t zero;
 };

 typedef union {
 struct qnx_io_pathconf i;
 } io_pathconf_t;
 */
static int
dissect_qnet6_kif_msgsend_msg_pathconf(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_pathconf_name, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_zero, tvb, *poffset, 2, ENC_NA);
  *poffset += 2;

  left -= 2 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4, "pathconf's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

/*
 *struct _io_chmod {
 *      _Uint16t type;
 *      _Uint16t combine_len;
 *      mode_t  mode;
 *};
 *
 *typedef union {
 *      struct _io_chmod i;
 *} io_chmod_t;
 */

static int
dissect_qnet6_kif_msgsend_msg_chmod(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;
  static const int *chmod_fields[] = {
    &hf_qnet6_kif_msg_io_chmod_other_exe,
    &hf_qnet6_kif_msg_io_chmod_other_write,
    &hf_qnet6_kif_msg_io_chmod_other_read,
    &hf_qnet6_kif_msg_io_chmod_group_exe,
    &hf_qnet6_kif_msg_io_chmod_group_write,
    &hf_qnet6_kif_msg_io_chmod_group_read,
    &hf_qnet6_kif_msg_io_chmod_owner_exe,
    &hf_qnet6_kif_msg_io_chmod_owner_write,
    &hf_qnet6_kif_msg_io_chmod_owner_read,
    &hf_qnet6_kif_msg_io_chmod_sticky,
    &hf_qnet6_kif_msg_io_chmod_setgid,
    &hf_qnet6_kif_msg_io_chmod_setuid,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_io_chmod, ett_qnet6_kif_chmod_mode, chmod_fields, encoding);
  *poffset += 4;

  left -= 2 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4, "chmod's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

/*
 * struct qnx_io_fdinfo { _Uint16t type; _Uint16t combine_len; _Uint32t
 * flags; _Int32t path_len; _Uint32t reserved; };
 *
 * struct _io_fdinfo_reply { _Uint32t zero[2]; struct _fdinfo info; //char
 * path[path_len + 1]; }; according to lib/c/qnx/iofdinfo.c: client ->
 * server a io_fdinfo message is sent out, if client requests path then
 * path_len !=0 server -> client a fdinfo_reply replied. client is using 3
 * iov to receive reply: 1.msg.o.zero 2.msg.o.info 3.path buffer in
 * iofunc_fdinfo_default it will memset the first 2 uint32. How do I know
 * it is a corresponding reply?
 */
static int
dissect_qnet6_kif_msgsend_msg_fdinfo(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);
  if (left < 2 + 4 + 4 + 4)
    return ret;

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_fdinfo_flags, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_fdinfo_path_len, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_fdinfo_reserved, tvb, *poffset, 4, encoding);
  *poffset += 4;

  left -= 2 + 4 * 3;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3, "fdinfo's extra data");
  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

/*
 * struct _io_lock { _Uint16t type; _Uint16t combine_len; _Uint32t
 * subtype; _Int32t nbytes; //char data[1]; };
 *
 * struct _io_lock_reply { _Uint32t zero[3];
 *
 * };
 */

static int
dissect_qnet6_kif_msgsend_msg_lock(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_lock_subtype, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_lock_nbytes, tvb, *poffset, 4, encoding);
  *poffset += 4;

  left -= 2 + 4 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 + 4, "lock's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_space(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_space_subtype, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_space_whence, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_space_start, tvb, *poffset, 8, encoding);
  *poffset += 8;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_space_len, tvb, *poffset, 8, encoding);
  *poffset += 8;

  left -= 2 * 3 + 8 * 2;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 * 4 + 8 * 2, "space's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_chown(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_chown_gid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_chown_uid, tvb, *poffset, 4, encoding);
  *poffset += 4;

  left -= 2 + 4 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 + 4, "chown's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

/*
 * struct qnx_io_utime { _Uint16t type; _Uint16t combine_len; _Int32t
 * cur_flag; If set, ignore times and set to "now" struct utimbuf times;
 * };
 *
 * in lib/c/public/utime.h struct utimbuf { time_t actime; time_t modtime;
 * };
 */
static int
dissect_qnet6_kif_msgsend_msg_utime(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int      ret = -1;
  gint     combine_len, left;
  nstime_t nt;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_utime_curflag, tvb, *poffset, 4, encoding);
  *poffset += 4;
  nt.nsecs = 0;
  nt.secs = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_time(tree, hf_qnet6_kif_msg_io_utime_actime, tvb, *poffset, 4, &nt);
  *poffset += 4;
  nt.secs = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_time(tree, hf_qnet6_kif_msg_io_utime_modtime, tvb, *poffset, 4, &nt);
  *poffset += 4;

  left -= 2 + 4 + 4 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 3, "utime's data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_sync(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;
  static const int *sync_fields[] = {
    &hf_qnet6_kif_msg_syncflag_dsync,
    &hf_qnet6_kif_msg_syncflag_sync,
    &hf_qnet6_kif_msg_syncflag_rsync,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_io_sync, ett_qnet6_kif_msg_sync, sync_fields, encoding);
  *poffset += 4;

  left -= 2 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4, "sync's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_close(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;

  left -= 2;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2, "close's extra data");
  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_stat(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_zero, tvb, *poffset, 4, ENC_NA);
  *poffset += 4;

  left -= 2 + 4;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4, "stat's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_shutdown(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;

  left -= 2;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2, "shutdown's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_openfd(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int         ret = -1;
  gint        combine_len, left;
  proto_tree *stree;
  static const int *openfd_ioflag_fields[] = {
    &hf_qnet6_kif_msg_openfd_ioflag_access,
    &hf_qnet6_kif_msg_openfd_ioflag_append,
    &hf_qnet6_kif_msg_openfd_ioflag_dsync,
    &hf_qnet6_kif_msg_openfd_ioflag_sync,
    &hf_qnet6_kif_msg_openfd_ioflag_rsync,
    &hf_qnet6_kif_msg_openfd_ioflag_nonblock,
    &hf_qnet6_kif_msg_openfd_ioflag_creat,
    &hf_qnet6_kif_msg_openfd_ioflag_truncate,
    &hf_qnet6_kif_msg_openfd_ioflag_exclusive,
    &hf_qnet6_kif_msg_openfd_ioflag_noctrltty,
    &hf_qnet6_kif_msg_openfd_ioflag_closexec,
    &hf_qnet6_kif_msg_openfd_ioflag_realids,
    &hf_qnet6_kif_msg_openfd_ioflag_largefile,
    &hf_qnet6_kif_msg_openfd_ioflag_async,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_openfd_ioflag, ett_qnet6_kif_msg_openfd_ioflag, openfd_ioflag_fields, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_openfd_sflag, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_openfd_xtype, tvb, *poffset, 2, encoding);
  *poffset += 2;


  stree = proto_tree_add_subtree(tree, tvb, *poffset, QNX_MSG_INFO_SIZE, ett_qnet6_kif_msg_msginfo, NULL, "MsgInfo");

  /*
   * dissect msg_info
   */
  dissect_qnet6_kif_msgsend_msg_msginfo(tvb, pinfo, stree, poffset, encoding);

  proto_tree_add_item(tree, hf_qnet6_kif_msg_openfd_reserved, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_openfd_key, tvb, *poffset, 4, encoding);
  *poffset += 4;

  left -= 2 + 4 + 2 * 2 + QNX_MSG_INFO_SIZE + 4 * 2;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 + 2 * 2 + QNX_MSG_INFO_SIZE + 4 * 2, "openfd's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_mmap(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int         ret = -1;
  gint        combine_len, left;
  proto_tree *stree;
  static const int *prot_fields[] = {
    &hf_qnet6_kif_msg_io_mmap_prot_read,
    &hf_qnet6_kif_msg_io_mmap_prot_write,
    &hf_qnet6_kif_msg_io_mmap_prot_exec,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_io_mmap_prot, ett_qnet6_kif_msg_prot, prot_fields, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_mmap_offset, tvb, *poffset, 8, encoding);
  *poffset += 8;
  stree = proto_tree_add_subtree(tree, tvb, *poffset, QNX_MSG_INFO_SIZE, ett_qnet6_kif_msg_msginfo, NULL, "MsgInfo");
  /*
   * dissect msg_info
   */
  dissect_qnet6_kif_msgsend_msg_msginfo(tvb, pinfo, stree, poffset, encoding);

  proto_tree_add_item(tree, hf_qnet6_kif_zero, tvb, *poffset, 4 * 6, ENC_NA);
  *poffset += 4 * 6;

  left -= 2 + 4 + 8 + 4 * 6 + QNX_MSG_INFO_SIZE;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 + 8 + 4 * 6 + QNX_MSG_INFO_SIZE, "mmap's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_iomsg(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int  ret = -1;
  gint combine_len, left;

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_msg_mgrid, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_msg_subtype, tvb, *poffset, 2, encoding);
  *poffset += 2;

  left -= 2 * 3;

  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len,  &left, 2 + 2 * 3, "io_msg's data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

/*
 * struct qnx_io_notify { _Uint16t type; _Uint16t combine_len; _Int32t
 * action; _Int32t flags; struct sigevent_qnx event;
 *
 * // Following fields only valid if (flags & _NOTIFY_COND_EXTEN) _Int32t
 * mgr[2]; // For use by manager _Int32t flags_extra_mask; _Int32t
 * flags_exten; _Int32t nfds; _Int32t fd_first; _Int32t nfds_ready;
 * _Int64t timo; // struct pollfd fds[nfds]; }; struct pollfd { int fd;
 * //file descriptor short events; //events to look for short revents; //
 * events returned };
 *
 */
static const guint8 *qnet6_kif_msg_io_notify_event_str[] = {
  "read ", "write ", "rdband "
};

static int
dissect_qnet6_kif_msgsend_msg_notify(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int         ret = -1;
  gint        combine_len, left, fd;
  guint16     event, revent;
  proto_tree *stree;
  nstime_t    nt;
  guint64     timo;
  guint32     nfds, i, j, n, m;
  guint8      sevent[20], srevent[20]; /* enough to fit "read,write,rdband" */
  static const int *notify_flags_fields[] = {
    &hf_qnet6_kif_msg_io_notify_flags_28,
    &hf_qnet6_kif_msg_io_notify_flags_29,
    &hf_qnet6_kif_msg_io_notify_flags_30,
    &hf_qnet6_kif_msg_io_notify_flags_31,
    NULL
  };

  left = tvb_reported_length_remaining(tvb, *poffset);

  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_action, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_bitmask(tree, tvb, *poffset, hf_qnet6_kif_msg_io_notify_flags, ett_qnet6_kif_msg_notify_flags, notify_flags_fields, encoding);
  *poffset += 4;
  /*
   * sigevent
   */
  stree = proto_tree_add_subtree(tree, tvb, *poffset, 4 * 4, ett_qnet6_kif_event, NULL, "sigevent");
  /*
   *poffset += sizeof(struct sigevent_qnx); */

  proto_tree_add_item(stree, hf_qnet6_kif_event_notify, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(stree, hf_qnet6_kif_event_union1, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(stree, hf_qnet6_kif_event_value, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(stree, hf_qnet6_kif_event_union2, tvb, *poffset, 4, encoding);
  *poffset += 4;

  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_mgr, tvb, *poffset, 8, encoding);
  *poffset += 8;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_flags_extra_mask, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_flags_exten, tvb, *poffset, 4, encoding);
  *poffset += 4;
  nfds = tvb_get_guint32(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_nfds, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_fd_first, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_notify_nfds_ready, tvb, *poffset, 4, encoding);
  *poffset += 4;

  timo = tvb_get_guint64(tvb, *poffset, encoding);
  if (timo != 0)
    {
      if (timo > 1000000000)
        {
          nt.secs = (int)(timo / 1000000000);
          nt.nsecs = (int)(timo - nt.secs * 1000000000);
        }
      else
        {
          nt.secs = 0;
          nt.nsecs = (int)timo;
        }
    }
  else
    {
      nt.nsecs = 0;
      nt.secs = 0;
    }
  proto_tree_add_time(tree, hf_qnet6_kif_msg_io_notify_timo, tvb, *poffset, 8, &nt);
  *poffset += 8;

  left -= 2 + 4 * 2 + 4 * 4 + 4 * 7 + 8;
  /*
   * handle pollfd fds[nfds]
   */
  if ((guint32) left >= nfds * 8)
    { /* each pollfd size is 8 */
      stree = proto_tree_add_subtree(tree, tvb, *poffset, nfds * 8, ett_qnet6_kif_msg_notify_fds, NULL, "Poll file descriptors array");
      for (i = 0; i < nfds; i++)
        {
          fd = tvb_get_guint32(tvb, *poffset, encoding);
          event = tvb_get_guint16(tvb, *poffset + 4, encoding);
          revent = tvb_get_guint16(tvb, *poffset + 4 + 2, encoding);
          sevent[0] = srevent[0] = 0;
          for (j = 1, n = 0, m = 0; j < 8; j = j << 1)
            {
              if (event & j)
                n += g_snprintf(sevent + n, sizeof(sevent) - n, "%s", qnet6_kif_msg_io_notify_event_str[j >> 1]);
              if (revent & j)
                m += g_snprintf(srevent + m, sizeof(srevent) - m, "%s", qnet6_kif_msg_io_notify_event_str[j >> 1]);
            }
          proto_tree_add_string_format_value(stree, hf_qnet6_kif_msg_io_notify_fds, tvb, *poffset, 8, NULL, "fd:%" G_GINT32_FORMAT " " "event:0x%x %s" "revent:0x%x %s", fd, event, sevent, revent, srevent);
          *poffset += 8;
        }
      left -= nfds * 8;
      dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + 4 * 2 + 4 * 4 + 4 * 7 + 8 + nfds * 8, "notify's extra data");

    }
  else
    return ret;

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          /*
           * there is io_notify's data behind _io_notify_t in
           * lib/c/xopen/poll.c msg.i.combine_len = sizeof(msg.i) so in
           * theory we should not see combine_len > sizeof(msg.i) fds
           * array should be behind _io_notify_t for example: fds[100]
           * nfds=100, fd_first=0, fd_ to server1: server1 may cut it
           * from the end to server2: fds[98] nfds=98, fd_first=xxx any
           * server can only cut from the end as iov[1].base is always
           * fds it didn't set these length to combine_len:(
           */
          ret = dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg_dup(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  int         ret = -1;
  gint        combine_len, left;
  proto_tree *stree;

  left = tvb_reported_length_remaining(tvb, *poffset);
  combine_len = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_combine_len, tvb, *poffset, 2, encoding);
  *poffset += 2;
  stree = proto_tree_add_subtree(tree, tvb, *poffset, QNX_MSG_INFO_SIZE, ett_qnet6_kif_msg_msginfo, NULL, "MsgInfo");

  dissect_qnet6_kif_msgsend_msg_msginfo(tvb, pinfo, stree, poffset, encoding);

  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_dup_reserved, tvb, *poffset, 4, encoding);
  *poffset += 4;
  proto_tree_add_item(tree, hf_qnet6_kif_msg_io_dup_key, tvb, *poffset, 4, encoding);
  *poffset += 4;

  left -= 2 + QNX_MSG_INFO_SIZE + 4 * 2;
  dissect_qnet6_kif_msgsend_msg_extra(tvb, tree, poffset, combine_len, &left, 2 + 2 + QNX_MSG_INFO_SIZE + 4 * 2, "dup's extra data");

  ret = 0;
  if (combine_len & 0x8000)
    { /* _IO_COMBINE_FLAG is 0x8000 */
      if (left > 0)
        {
          ret =
            dissect_qnet6_kif_msgsend_msg(tvb, pinfo, tree, poffset, encoding);
        }
    }

  return ret;

}

static int
dissect_qnet6_kif_msgsend_msg(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
  proto_item  *ti;
  proto_tree  *stree;
  guint16      msgtype, subtype, path_len, extra_len, extra_pad;
  const gchar *msgstr;
  guint8       extra_type;
  gint         rlen, head_len;
  int          ret = -1;
  static const int *ioflag_fields[] = {
    &hf_qnet6_kif_msg_connect_ioflag_access,
    &hf_qnet6_kif_msg_connect_ioflag_append,
    &hf_qnet6_kif_msg_connect_ioflag_dsync,
    &hf_qnet6_kif_msg_connect_ioflag_sync,
    &hf_qnet6_kif_msg_connect_ioflag_rsync,
    &hf_qnet6_kif_msg_connect_ioflag_nonblock,
    &hf_qnet6_kif_msg_connect_ioflag_creat,
    &hf_qnet6_kif_msg_connect_ioflag_truncate,
    &hf_qnet6_kif_msg_connect_ioflag_exclusive,
    &hf_qnet6_kif_msg_connect_ioflag_noctrltty,
    &hf_qnet6_kif_msg_connect_ioflag_closexec,
    &hf_qnet6_kif_msg_connect_ioflag_realids,
    &hf_qnet6_kif_msg_connect_ioflag_largefile,
    &hf_qnet6_kif_msg_connect_ioflag_async,
    NULL
  };
  static const int *mode_fields[] = {
    &hf_qnet6_kif_msg_connect_mode_other_exe,
    &hf_qnet6_kif_msg_connect_mode_other_write,
    &hf_qnet6_kif_msg_connect_mode_other_read,
    &hf_qnet6_kif_msg_connect_mode_group_exe,
    &hf_qnet6_kif_msg_connect_mode_group_write,
    &hf_qnet6_kif_msg_connect_mode_group_read,
    &hf_qnet6_kif_msg_connect_mode_owner_exe,
    &hf_qnet6_kif_msg_connect_mode_owner_write,
    &hf_qnet6_kif_msg_connect_mode_owner_read,
    &hf_qnet6_kif_msg_connect_mode_sticky,
    &hf_qnet6_kif_msg_connect_mode_setgid,
    &hf_qnet6_kif_msg_connect_mode_setuid,
    &hf_qnet6_kif_msg_connect_mode_format,
    NULL
  };
  static const int *eflag_fields[] = {
    &hf_qnet6_kif_msg_connect_eflag_dir,
    &hf_qnet6_kif_msg_connect_eflag_dot,
    &hf_qnet6_kif_msg_connect_eflag_dotdot,
    NULL
  };

  rlen = tvb_reported_length_remaining(tvb, *poffset);

  ti = proto_tree_add_string(tree, hf_qnet6_kif_msg, tvb, *poffset, -1, "upper layer message(QNX6 message passing)");
  stree = proto_item_add_subtree(ti, ett_qnet6_kif_msg);

  msgtype = tvb_get_guint16(tvb, *poffset, encoding);
  proto_tree_add_item(stree, hf_qnet6_kif_msg_type, tvb, *poffset, 2, encoding);
  *poffset += 2;
  msgstr = try_val_to_str_ext(msgtype, &qnet6_kif_msgsend_msgtype_vals_ext);
  if (msgstr != NULL)
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", msgstr);
      proto_item_set_text(ti, "%s", msgstr);
    }
  rlen -= 2;

  switch (msgtype)
    {
    case QNX_IO_CONNECT:
      if (rlen < 2) /* there is no subtype */
        return ret;

      head_len = 2 + 2 + 4 + 2 * 2 + 4 * 4 + 2 * 4 + 1 * 2 + 2;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_subtype,tvb, *poffset, 2, encoding);
      subtype = tvb_get_guint16(tvb, *poffset, encoding);
      *poffset += 2;
      rlen -= 2;
      if (head_len - 2 - 2 > rlen) /* there is no rest of io_connect */
        return ret;
      rlen -=(head_len - 2 - 2);
      /*
       * file type is 1, 2, 3, 4,.... so it is value_strings
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_filetype,tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_replymax, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_entrymax, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_key, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;

      proto_tree_add_bitmask(stree, tvb, *poffset, hf_qnet6_kif_msg_connect_ioflag, ett_qnet6_kif_msg_ioflag, ioflag_fields, encoding);

      *poffset += 4;
      proto_tree_add_bitmask(stree, tvb, *poffset, hf_qnet6_kif_msg_connect_mode, ett_qnet6_kif_msg_mode, mode_fields, encoding);
      *poffset += 4;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_sflag, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_access, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_zero, tvb, *poffset, 2, encoding);
      *poffset += 2;
      path_len = tvb_get_guint16(tvb, *poffset, encoding);
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_pathlen, tvb, *poffset, 2, encoding);
      *poffset += 2;
      proto_tree_add_bitmask(stree, tvb, *poffset, hf_qnet6_kif_msg_connect_eflag, ett_qnet6_kif_msg_eflag, eflag_fields, encoding);
      *poffset += 1;
      extra_type = tvb_get_guint8(tvb, *poffset);
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extratype, tvb, *poffset, 1, encoding);
      *poffset += 1;
      extra_len = tvb_get_guint16(tvb, *poffset, encoding);
      proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extralen, tvb, *poffset, 2, encoding);
      *poffset += 2;
      if (path_len > rlen)
        path_len = rlen;
      /*
       * after extra_len is path_len=strlen(path)+1(path,null),
       * extra_len
       */
      if (path_len > 0)
        {
          proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_path, tvb, *poffset, path_len, ENC_ASCII|ENC_NA);
          *poffset += path_len;
          rlen -= path_len;
        }
      col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(subtype,
            qnet6_kif_msgsend_msg_connect_subtype_vals, "Unknown"));

      if (extra_len > 0 && rlen > 0)
        {
          /*
           * extra data is QNX_MSG_ALIGN which is 8 default is there

           */
          if ((path_len + head_len) &(8 - 1))
            {
              extra_pad =(8 -((path_len + head_len) &(8 - 1)));
              if (extra_pad > rlen)
                extra_pad = rlen;
              if (extra_pad > 0)
                {
                  proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_pad_data, tvb, *poffset, extra_pad, ENC_NA);
                  *poffset += extra_pad;
                  rlen -= extra_pad;
                }
            }
          /*
           * COMBINE_CLOSE and COMBINE are used when it is _IO_CONNECT
           * it will have an additional io message in extra difference
           * in COMBINE_CLOSE and COMBINE is resource manager will call
           * close handler if it is COMBINE_CLOSE for use there is no
           * difference. yzhao I haven't see any app supports COMBINE
           * and support !EXTRA_NONE
           */
          if (extra_len > rlen)
            extra_len = rlen;

          switch (subtype)
            {
            case QNX_IO_CONNECT_COMBINE_CLOSE:
            case QNX_IO_CONNECT_COMBINE:
              if (extra_len >= 4 /* type+combine_len in io message */
                  && rlen >= 4)
                ret = dissect_qnet6_kif_msgsend_msg(tvb, pinfo, stree, poffset, encoding);
              return ret;
              break;
            default:
              switch (extra_type)
                {
                case QNX_IO_CONNECT_EXTRA_LINK: /* 1 */
                  proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extra_link_ocb, tvb, *poffset, extra_len, encoding);
                  break;
                case QNX_IO_CONNECT_EXTRA_SYMLINK: /* 2 */
                  /*
                   * extra data is the symlink new path name
                   */
                  proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extra_symlink_path, tvb, *poffset, extra_len, ENC_ASCII|ENC_NA);
                  break;
                case QNX_IO_CONNECT_EXTRA_RENAME:
                  /*
                   * extra data is the mv old new ,extra is old path
                   * name path is the new name
                   */
                  proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extra_rename_path, tvb, *poffset, extra_len, ENC_ASCII|ENC_NA);
                  break;
                case QNX_IO_CONNECT_EXTRA_MOUNT:
                case QNX_IO_CONNECT_EXTRA_MOUNT_OCB:
                  proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extra_mount, tvb, *poffset, extra_len, ENC_ASCII|ENC_NA);
                  break;
                case QNX_IO_CONNECT_EXTRA_NONE: /* 0 */
                default:
                  proto_tree_add_item(stree, hf_qnet6_kif_msg_connect_extra_data, tvb, *poffset, extra_len, ENC_NA);
                  break;
                }
              break;
            }

          *poffset += extra_len;
        }

      ret = 0;
      break;
    case QNX_IO_DEVCTL:
      ret = dissect_qnet6_kif_msgsend_msg_devctl(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_READ:
      ret = dissect_qnet6_kif_msgsend_msg_read(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_WRITE:
      ret = dissect_qnet6_kif_msgsend_msg_write(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_PATHCONF:
      ret = dissect_qnet6_kif_msgsend_msg_pathconf(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_STAT:
      ret = dissect_qnet6_kif_msgsend_msg_stat(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_LSEEK:
      ret = dissect_qnet6_kif_msgsend_msg_seek(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_CHMOD:
      ret = dissect_qnet6_kif_msgsend_msg_chmod(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_CHOWN:
      ret = dissect_qnet6_kif_msgsend_msg_chown(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_UTIME:
      ret = dissect_qnet6_kif_msgsend_msg_utime(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_FDINFO:
      ret = dissect_qnet6_kif_msgsend_msg_fdinfo(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_LOCK:
      ret = dissect_qnet6_kif_msgsend_msg_lock(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_SPACE:
      ret = dissect_qnet6_kif_msgsend_msg_space(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_CLOSE:
      /*
       * io_close there is no data but only combine_len
       */
      ret = dissect_qnet6_kif_msgsend_msg_close(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_SYNC:
      ret = dissect_qnet6_kif_msgsend_msg_sync(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_OPENFD:
      ret = dissect_qnet6_kif_msgsend_msg_openfd(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_SHUTDOWN:
      ret = dissect_qnet6_kif_msgsend_msg_shutdown(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_MMAP:
      ret = dissect_qnet6_kif_msgsend_msg_mmap(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_MSG:
      ret = dissect_qnet6_kif_msgsend_msg_iomsg(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_NOTIFY:
      ret = dissect_qnet6_kif_msgsend_msg_notify(tvb, pinfo, stree, poffset, encoding);
      break;
    case QNX_IO_DUP:
      ret = dissect_qnet6_kif_msgsend_msg_dup(tvb, pinfo, stree, poffset, encoding);
      break;

    default:
      break;
    }

  return ret;
}

static void
qos_tcs_init_addtree(tvbuff_t * tvb, proto_tree * tree, gint * poffset, guint encoding, int hf_off, int hf_generated, gint rlen, gint name_start)
{
  guint16     off;
  proto_item *ti;
  gint        i;

  proto_tree_add_item(tree, hf_off, tvb, *poffset, 2, encoding);
  off = tvb_get_guint16(tvb, *poffset, encoding);
  if ((gint) off < rlen)
    {
      i = off;
      while(i <= rlen)
        {
          if (tvb_get_guint8(tvb, name_start + i)== 0)
            break;
          i++;
        }
      if (i <= rlen)
        {
          ti = proto_tree_add_item(tree, hf_generated, tvb, name_start + off, i - off, ENC_ASCII|ENC_NA);
          PROTO_ITEM_SET_GENERATED(ti);
        }

    }
  *poffset += 2;

}

static int
dissect_qnet6_qos(guint8 qtype, tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
  proto_item *ti;
  proto_tree *stree;
  gint        rlen, name_start;

  col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "QNET_QOS");

  switch (qtype)
    {
    case QNET_L4_TYPE_TCS_INIT:
      ti = proto_tree_add_item(tree, proto_qnet6_qos, tvb, *poffset, -1, ENC_NA);
      stree = proto_item_add_subtree(ti, ett_qnet6_qos);
      /*
       * after l4_pkt header is the tcs_init_strings guint16
       * src_name_off, src_domain_off, dst_name_off, dst_domain_off
       */

      rlen = tvb_reported_length_remaining(tvb, *poffset);
      if (rlen <(gint) 2 * 4) /* at least we have tcs_init_strings */
        return -1;
      /*
       * after tcs_init_strings how much left
       */
      rlen -= 2 * 4;
      name_start = *poffset + 2 * 4;

      qos_tcs_init_addtree(tvb, stree, poffset, encoding, hf_qnet6_qos_tcs_src_name_off, hf_qnet6_qos_tcs_src_name_generated, rlen, name_start);
      qos_tcs_init_addtree(tvb, stree, poffset, encoding, hf_qnet6_qos_tcs_src_domain_off, hf_qnet6_qos_tcs_src_domain_generated, rlen, name_start);
      qos_tcs_init_addtree(tvb, stree, poffset, encoding, hf_qnet6_qos_tcs_dst_name_off, hf_qnet6_qos_tcs_dst_name_generated, rlen, name_start);
      qos_tcs_init_addtree(tvb, stree, poffset, encoding, hf_qnet6_qos_tcs_dst_domain_off, hf_qnet6_qos_tcs_dst_domain_generated, rlen, name_start);

      col_add_fstr(pinfo->cinfo, COL_INFO, "Qos TCS_INIT Message");

      break;
    case QNET_L4_TYPE_TCS_REM_UP:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Qos TCS_REM_UP Message");
      break;
    case QNET_L4_TYPE_TCS_UP:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Qos TCS_UP Message");
      break;
    case QNET_L4_TYPE_TCS_DOWN:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Qos TCS_DOWN Message");
      break;
    case QNET_L4_TYPE_TCS_REM_DOWN:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Qos TCS_REM_DOWN Message");
      break;
    default:
      break;

    }

  return 0;
}

/*
 * _client_info is defined in sys / neutrino.h and uid_t, gid_t are _INT32
 */
#if defined(__NGROUPS_MAX)
#define O__NGROUPS_MAX __NGROUPS_MAX
#undef __NGROUPS_MAX
#define __NGROUPS_MAX 8
#else
#define __NGROUPS_MAX 8
#endif
/*
 * struct _cred_info { gint32 ruid; gint32 euid; gint32 suid; gint32 rgid;
 * gint32 egid; gint32 sgid; guint32 ngroups; gint32
 * grouplist[__NGROUPS_MAX]; };
 *
 * struct _client_info { guint32 nd; gint32 pid; gint32 sid; guint32 flags;
 * struct _cred_info cred; };
 */
/*
 * dissect_qnet6_kif_cred will return -1 if there are some data there. and
 * it is supposed to be part of cred but not enough or 0 if cred is fully
 * parsed
 */
static int
dissect_qnet6_kif_cred(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint * poffset, guint encoding)
{
  proto_item *ti, *ti1, *ti2;
  proto_tree *stree, *sstree;
  guint32 ngroups;
  gint nleft, ret = -1, length;

  ti = NULL; /* for compiler warning */
  nleft = tvb_reported_length_remaining(tvb, *poffset);
  length =((4 * 4 /* nd,pid,sid,flags */ ) +
           (4 * 3 * 2 + 4) /* ruid,euid,suid,rgid,egid,sgid,ngroups */ );
  /*
   * at least we need everything before the array
   * grouplist[__NGROUPS_MAX]
   */
  if (nleft < length)
    return ret;
  ti1 = proto_tree_add_string(tree, hf_qnet6_kif_client_info, tvb, *poffset, MIN(length, nleft), "client information");
  stree = proto_item_add_subtree(ti1, ett_qnet6_kif_client_info);
  /*
   * nd
   */
  proto_tree_add_item(stree, hf_qnet6_kif_client_info_nd, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * pid
   */
  proto_tree_add_item(stree, hf_qnet6_kif_client_info_pid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * sid
   */
  proto_tree_add_item(stree, hf_qnet6_kif_client_info_sid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * flags
   */
  proto_tree_add_item(stree, hf_qnet6_kif_client_info_flags, tvb, *poffset, 4, encoding);
  *poffset += 4;
  ti2 = proto_tree_add_string(stree, hf_qnet6_kif_client_info_cred, tvb, *poffset, MIN(4 * 6 + 4, nleft - 4 * 4), "client information");
  sstree = proto_item_add_subtree(ti2, ett_qnet6_kif_client_info_cred);

  /*
   * ruid
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_ruid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * euid
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_euid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * suid
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_suid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * rgid
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_rgid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * egid
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_egid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  /*
   * sgid
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_sgid, tvb, *poffset, 4, encoding);
  *poffset += 4;
  ngroups = tvb_get_guint32(tvb, *poffset, encoding);
  /*
   * ngroups
   */
  proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_ngroups, tvb, *poffset, 4, encoding);
  *poffset += 4;
  if (ngroups > __NGROUPS_MAX) /* ngroups is wrong */
    return ret;
  nleft -= length;
  nleft = MIN(nleft, __NGROUPS_MAX * 4);
  if (nleft < (gint) ngroups * 4)
    return ret;
  /*
   * nleft at least >=0
   */
  nleft = MIN(ngroups * 4,(guint32) nleft);
  /*
   * nleft is possible 0,4,...
   */
  if (nleft >= 4)
    {
      ti = proto_tree_add_item(sstree, hf_qnet6_kif_client_info_cred_grouplist, tvb, *poffset, 4, encoding);
      *poffset += 4;
      nleft -= 4;
      length += 4;
    }

  for (; nleft > 0; nleft -= 4)
    {
      proto_item_append_text(ti, " %" G_GUINT32_FORMAT, tvb_get_guint32(tvb, *poffset, encoding));
      *poffset += 4;
      length += 4;
    }
  proto_item_set_len(ti1, length);
  proto_item_set_len(ti2, length - 4 * 4); /* except nd,pid,sid,flags */
  if (ti)
    proto_item_set_len(ti, length - 4 * 4 - 4 * 6 - 4);
  ret = 0;

  return ret;
}

static int
dissect_qnet6_kif(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint * poffset, guint encoding)
{
  proto_item           *ti;
  proto_tree           *stree, *stree1, *sstree;
  gint                  rlen;
  struct qnet6_kif_hdr  khdr;
  const value_string   *p;
  int                   ret = -1;
  guint32               nleft, coid, chid;

  ti = proto_tree_add_item(tree, proto_qnet6_kif, tvb, *poffset, -1, ENC_NA);
  stree = proto_item_add_subtree(ti, ett_qnet6_kif);

  /*
   * when dissect_qnet6_kif is called it is guaranteed that at least msgtype
   * and size are in packet
   */
  khdr.msgtype = tvb_get_guint16(tvb, *poffset, encoding);
  khdr.size = tvb_get_guint16(tvb, *poffset + 2, encoding);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "QNET_KIF");
  for (p = qnet6_kif_msgtype_vals;
       p < qnet6_kif_msgtype_vals +
       sizeof(qnet6_kif_msgtype_vals) / sizeof(value_string); p++)
    {
      if (p->value ==(khdr.msgtype & QNET_KIF_MSGTYPE_MASK))
        {
          if (p->strptr)
            col_set_str(pinfo->cinfo, COL_INFO, p->strptr);
        }
    }

  if ((khdr.msgtype & QNET_KIF_MSGTYPE_MASK) !=
      QNET_KIF_MSGTYPE_CONNECT_MSGSEND)
    {
      /*
       * msgtype
       */
      ti = proto_tree_add_item(stree, hf_qnet6_kif_msgtype, tvb, *poffset, 2, encoding);
      if (khdr.msgtype & QNET_KIF_CRED)
        proto_item_append_text(ti, " CRED");
      if ((khdr.msgtype & QNET_KIF_ENDIAN_MASK) == QNET_KIF_ENDIAN_BIG)
        proto_item_append_text(ti, " BIG_ENDIAN");
      else if ((khdr.msgtype & QNET_KIF_ENDIAN_MASK) == QNET_KIF_ENDIAN_LITTLE)
        proto_item_append_text(ti, " LITTLE_ENDIAN");
      *poffset += 2;
      /*
       * size
       */
      proto_tree_add_item(stree, hf_qnet6_kif_size, tvb, *poffset, 2, encoding);
      *poffset += 2;
    }
  /*
   * how much data left and not parsed yet
   */
  rlen = tvb_reported_length_remaining(tvb, *poffset);

  switch (khdr.msgtype & QNET_KIF_MSGTYPE_MASK)
    {
    case QNET_KIF_MSGTYPE_CONNECT:
      /*
       * version
       */
      proto_tree_add_item(stree, hf_qnet6_kif_version, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * server pid
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connect_server_pid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * server chid
       */
      chid = tvb_get_guint32(tvb, *poffset, encoding);
      ti = proto_tree_add_item(stree,hf_qnet6_kif_connect_server_chid, tvb,*poffset, 4, encoding);
      display_channel_id(chid, ti);
      *poffset += 4;
      /*
       * client id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connect_client_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client pid
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connect_client_pid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * dissect_qnet6_kif_cred will check whether no more data
       */
      if (khdr.msgtype & QNET_KIF_CRED)
        {
          ret = dissect_qnet6_kif_cred(tvb, pinfo, stree, poffset, encoding);
          if (ret != 0)
            return ret;
        }
      break;
    case QNET_KIF_MSGTYPE_CONNECT_MSGSEND:
      /*
       * still don't know how many ngroups in cred_info so needs to
       * modify its size later proto_item_set_len should be called later
       * when we know ngroups.
       */
      /*
       * connect_msgsend format: connect cred (optional, msgtype
       * indicates it size=sizeof(connect)+optinal sizeof(cred)) msgsend
       * cred (optional)
       */
      /*
       * if no struct qnet6_kif_connect
       */
      if (rlen < 4 + 4 + 4 + 4 + 4 + 4)
        return ret;
      ti = proto_tree_add_string(stree, hf_qnet6_kif_connect, tvb, *poffset,
                                 2 * 2 + 4 * 5 + ((khdr.msgtype & QNET_KIF_CRED) ? (4 * 4 + 4 * 7) : 0),
                                 "qnet connect message");
      stree1 = proto_item_add_subtree(ti, ett_qnet6_kif_connect);
      /*
       * msgtype
       */
      ti = proto_tree_add_item(stree1, hf_qnet6_kif_msgtype, tvb, *poffset, 2, encoding);
      if (khdr.msgtype & QNET_KIF_CRED)
        proto_item_append_text(ti, " CRED");
      if ((khdr.msgtype & QNET_KIF_ENDIAN_MASK) == QNET_KIF_ENDIAN_BIG)
        proto_item_append_text(ti, " BIG_ENDIAN");
      else if ((khdr.msgtype & QNET_KIF_ENDIAN_MASK) == QNET_KIF_ENDIAN_LITTLE)
        proto_item_append_text(ti, " LITTLE_ENDIAN");
      *poffset += 2;
      /*
       * size
       */
      proto_tree_add_item(stree1, hf_qnet6_kif_size, tvb, *poffset, 2, encoding);
      *poffset += 2;
      /*
       * version
       */
      proto_tree_add_item(stree1, hf_qnet6_kif_version, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * server pid
       */
      proto_tree_add_item(stree1, hf_qnet6_kif_connect_server_pid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * server chid
       */
      chid = tvb_get_guint32(tvb, *poffset, encoding);
      ti = proto_tree_add_item(stree1, hf_qnet6_kif_connect_server_chid, tvb, *poffset, 4, encoding);
      display_channel_id(chid, ti);
      *poffset += 4;
      /*
       * client id
       */
      proto_tree_add_item(stree1, hf_qnet6_kif_connect_client_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client pid
       */
      proto_tree_add_item(stree1, hf_qnet6_kif_connect_client_pid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      if (khdr.msgtype & QNET_KIF_CRED)
        {
          ret = dissect_qnet6_kif_cred(tvb, pinfo, stree1, poffset, encoding);
          if (ret != 0)
            return ret;
        }

      rlen = tvb_reported_length_remaining(tvb, *poffset);
      if (rlen < 4 /* type+size */ )
        return ret;
      /*
       * msgsend msgtype, size part
       */
      ti = proto_tree_add_string(stree, hf_qnet6_kif_msgsend, tvb, *poffset, -1, "qnet msgsend message");
      stree = proto_item_add_subtree(ti, ett_qnet6_kif_msgsend);

      khdr.msgtype = tvb_get_guint16(tvb, *poffset, encoding);
      khdr.size = tvb_get_guint16(tvb, *poffset + 2, encoding);
      /*
       * msgtype
       */
      ti = proto_tree_add_item(stree, hf_qnet6_kif_msgtype, tvb, *poffset, 2, encoding);
      if (khdr.msgtype & QNET_KIF_CRED)
        proto_item_append_text(ti, " CRED");
      if ((khdr.msgtype & QNET_KIF_ENDIAN_MASK) == QNET_KIF_ENDIAN_BIG)
        proto_item_append_text(ti, " BIG_ENDIAN");
      else if ((khdr.msgtype & QNET_KIF_ENDIAN_MASK) == QNET_KIF_ENDIAN_LITTLE)
        proto_item_append_text(ti, " LITTLE_ENDIAN");
      *poffset += 2;
      /*
       * size
       */
      proto_tree_add_item(stree, hf_qnet6_kif_size, tvb, *poffset, 2, encoding);
      *poffset += 2;
      rlen -= 4;
      goto lmsgsend;
      break;
    case QNET_KIF_MSGTYPE_CONNECT_SUCCESS:
      if (rlen < 4 + 4 + 4 + 4 + 4) /* ver, sid,cid,scoid,nbytes */
        return ret;
      /*
       * version
       */
      proto_tree_add_item(stree, hf_qnet6_kif_version, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * server id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connects_server_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connects_client_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * scoid
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connects_scoid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * nbytes
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connects_nbytes, tvb, *poffset, 4, encoding);
      *poffset += 4;
      if (khdr.msgtype & QNET_KIF_CRED)
        {
          ret = dissect_qnet6_kif_cred(tvb, pinfo, stree, poffset, encoding);
          if (ret != 0)
            return ret;
        }
      break;
    case QNET_KIF_MSGTYPE_CONNECT_FAIL:
      if (rlen < 4 + 4 + 4) /* ver, cid, status */
        return ret;
      /*
       * version
       */
      proto_tree_add_item(stree, hf_qnet6_kif_version, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connectf_client_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * status
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connectf_status, tvb, *poffset, 4, encoding);
      *poffset += 4;
      break;
    case QNET_KIF_MSGTYPE_CONNECT_DEATH:
      if (rlen < 4)
        return ret;
      /*
       * client id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_connectd_client_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      break;
    case QNET_KIF_MSGTYPE_MSGSEND:

    case QNET_KIF_MSGTYPE_PULSE:
    lmsgsend:
      if (rlen < 4 * 10) /* sid,client_handle, tid, coid,priority, srcmsglen,keydata,srcnd,dstmsglen */
        return ret;
      /*
       * server id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgsend_server_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgsend_client_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * vinfo, it is packed as 64 bits aligned so sizeof should work
       * well on 32, 64 bits platforms
       */
      ti = proto_tree_add_string(stree, hf_qnet6_kif_msgsend_vinfo, tvb, *poffset, 4 * 8, "virtual thread information");
      sstree = proto_item_add_subtree(ti, ett_qnet6_kif_vinfo);
      /*
       * tid
       */
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_tid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      coid = tvb_get_guint32(tvb, *poffset, encoding);
      ti = proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_coid, tvb, *poffset, 4, encoding);
      display_coid(coid, ti);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_priority, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_srcmsglen, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_keydata, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_srcnd, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_dstmsglen, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_vtid_info_zero, tvb, *poffset, 4, encoding);
      *poffset += 4;

      rlen -= 40;
      if ((khdr.msgtype & QNET_KIF_MSGTYPE_MASK) ==
          QNET_KIF_MSGTYPE_MSGSEND
          || (khdr.msgtype & QNET_KIF_MSGTYPE_MASK) ==
          QNET_KIF_MSGTYPE_CONNECT_MSGSEND)
        {
          /*
           * nbytes
           */
          proto_tree_add_item(stree, hf_qnet6_kif_msgsend_nbytes, tvb, *poffset, 4, encoding);
          *poffset += 4;

          /*
           * start to dissect resmgr_iomsgs which starts with guint16
           * type
           */
          ret = dissect_qnet6_kif_msgsend_msg(tvb, pinfo, stree, poffset, encoding);
          if (ret != 0)
            return ret;
        }
      else
        {
          if (rlen < 2 * 2 + 1 + 3 + 4 * 3)
            return ret;
          /*
           * pulse is done
           */
          ti = proto_tree_add_string(stree, hf_qnet6_kif_pulse_pulse, tvb, *poffset, 4 * 4 , "pulse information");
          sstree = proto_item_add_subtree(ti, ett_qnet6_kif_pulse);
          proto_tree_add_item(sstree, hf_qnet6_kif_pulse_pulse_type, tvb, *poffset, 2, encoding);
          *poffset += 2;
          proto_tree_add_item(sstree, hf_qnet6_kif_pulse_pulse_subtype, tvb, *poffset, 2, encoding);
          *poffset += 2;
          proto_tree_add_item(sstree, hf_qnet6_kif_pulse_pulse_code, tvb, *poffset, 1, encoding);
          *poffset += 1;
          proto_tree_add_item(sstree, hf_qnet6_kif_pulse_pulse_reserved, tvb, *poffset, 3, encoding);
          *poffset += 3;
          proto_tree_add_item(sstree, hf_qnet6_kif_pulse_pulse_value, tvb, *poffset, 4, encoding);
          *poffset += 4;
          proto_tree_add_item(sstree, hf_qnet6_kif_pulse_pulse_scoid, tvb, *poffset, 4, encoding);
          *poffset += 4;
          /*
           * priority
           */
          proto_tree_add_item(stree, hf_qnet6_kif_pulse_priority, tvb, *poffset, 4, encoding);
          *poffset += 4;
        }
      if (khdr.msgtype & QNET_KIF_CRED)
        {
          ret = dissect_qnet6_kif_cred(tvb, pinfo, stree, poffset, encoding);
          if (ret != 0)
            return ret;
        }
      break;
    case QNET_KIF_MSGTYPE_MSGREAD:
      if (rlen < 4 * 4)
        return ret;
      /*
       * msgread handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgread_msgread_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgread_client_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * offset
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgread_offset, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * nbytes
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgread_nbytes, tvb, *poffset, 4, encoding);
      *poffset += 4;
      break;
    case QNET_KIF_MSGTYPE_MSGWRITE:
    case QNET_KIF_MSGTYPE_MSGREPLY:
    case QNET_KIF_MSGTYPE_MSGERROR:
    case QNET_KIF_MSGTYPE_MSGREAD_XFER:
    case QNET_KIF_MSGTYPE_MSGREAD_ERROR:
      if (rlen < 4 * 4)
        return ret;

      /*
       * status
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgwrite_status, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgwrite_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * offset
       */
      proto_tree_add_item(stree, hf_qnet6_kif_msgwrite_offset, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * nbytes
       */
      nleft = tvb_get_guint32(tvb, *poffset, encoding);
      proto_tree_add_item(stree, hf_qnet6_kif_msgwrite_nbytes, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * else data
       */
      if (rlen - 4 * 4 > 0)
        proto_tree_add_item(stree, hf_qnet6_kif_msgwrite_data, tvb, *poffset, MIN(nleft, (guint32) rlen - 4 * 4), ENC_NA);

      break;
    case QNET_KIF_MSGTYPE_UNBLOCK:
      if (rlen < 4 * 3)
        return ret;
      /*
       * server id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_unblock_server_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * client handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_unblock_client_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * tid
       */
      proto_tree_add_item(stree, hf_qnet6_kif_unblock_tid, tvb, *poffset, 4, encoding);
      *poffset += 4;

      break;
    case QNET_KIF_MSGTYPE_EVENT:
      if (rlen < 4)
        return ret;
      /*
       * client handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_event_client_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      if (rlen < 4 * 4)
        return ret;
      /*
       * sigevent
       */
      ti = proto_tree_add_item(stree, hf_qnet6_kif_event_event, tvb, *poffset, 4 * 4, ENC_NA);
      /*
       *poffset += sizeof(struct sigevent_qnx); */
      sstree = proto_item_add_subtree(ti, ett_qnet6_kif_event);

      proto_tree_add_item(sstree, hf_qnet6_kif_event_notify, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_event_union1, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_event_value, tvb, *poffset, 4, encoding);
      *poffset += 4;
      proto_tree_add_item(sstree, hf_qnet6_kif_event_union2, tvb, *poffset, 4, encoding);
      *poffset += 4;

      break;
    case QNET_KIF_MSGTYPE_SIGNAL:
      if (rlen < 4 * 6)
        return ret;
      /*
       * client handle
       */
      proto_tree_add_item(stree, hf_qnet6_kif_signal_client_handle, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * pid
       */
      proto_tree_add_item(stree, hf_qnet6_kif_signal_pid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * tid
       */
      proto_tree_add_item(stree, hf_qnet6_kif_signal_tid, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * signo
       */
      proto_tree_add_item(stree, hf_qnet6_kif_signal_signo, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * code
       */
      proto_tree_add_item(stree, hf_qnet6_kif_signal_code, tvb, *poffset, 4, encoding);
      *poffset += 4;
      /*
       * value
       */
      proto_tree_add_item(stree, hf_qnet6_kif_signal_value, tvb, *poffset, 4, encoding);
      *poffset += 4;
      if (khdr.msgtype & QNET_KIF_CRED)
        {
          ret = dissect_qnet6_kif_cred(tvb, pinfo, stree, poffset, encoding);
          if (ret != 0)
            return ret;
        }
      break;
    case QNET_KIF_MSGTYPE_DISCONNECT:
      if (rlen < 4)
        return ret;
      /*
       * server id
       */
      proto_tree_add_item(stree, hf_qnet6_kif_disconnect_server_id, tvb, *poffset, 4, encoding);
      *poffset += 4;
    default:
      break;
    }
  ret = 0;

  return ret;
}

#ifdef O__NGROUPS_MAX
#define __NGROUPS_MAX O__NGROUPS_MAX
#else
#undef __NGROUPS_MAX
#endif

static int
dissect_qnet6(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{

  proto_item *ti;
  proto_tree *qnet6_tree, *stree;
  guint8      qflags, qlayer, qtype, crcbuf[4];
  guint       encoding;
  gint        offset = 0;
  gint        len, plen, cklen;
  guint32     crc, crcp;
  static const int * flags[] = {
    &hf_qnet6_l4_flags_first,
    &hf_qnet6_l4_flags_last,
    &hf_qnet6_l4_flags_crc,
    NULL
  };

  memset(crcbuf, 0, sizeof(crcbuf));
  /*
   * Check that there's enough data
   */
  len = (gint) tvb_reported_length(tvb);
  if (len < 36 + 2) /* sizeof (l4_pkt) + 2 bytes pad after 0x8204 */
    return 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "QNET_LWL4");

  /*
   * write to Info column
   */
  col_set_str(pinfo->cinfo, COL_INFO, "Qnet6");

  ti = proto_tree_add_item(tree, proto_qnet6_l4, tvb, 0, 36 + 2, ENC_NA);
  qnet6_tree = proto_item_add_subtree(ti, ett_qnet6_l4);

  proto_tree_add_item(qnet6_tree, hf_qnet6_l4_padding, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /*
   * version
   */
  encoding =(tvb_get_guint8(tvb, offset) & 0x80) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;
  proto_tree_add_item(qnet6_tree, hf_qnet6_l4_ver, tvb, offset++, 1, ENC_BIG_ENDIAN);

  /*
   * type
   */
  qtype = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(qnet6_tree, hf_qnet6_l4_type, tvb, offset++, 1, ENC_BIG_ENDIAN);

  col_add_str(pinfo->cinfo, COL_INFO, val_to_str(qtype, qnet6_type_vals, "Unknown LWL4 Type %u packets"));
  /*
   * flags
   */
  proto_tree_add_bitmask_with_flags(qnet6_tree, tvb, offset,
                hf_qnet6_l4_flags, ett_qnet6_flags, flags, ENC_NA, BMT_NO_APPEND|BMT_NO_FALSE);
  qflags = tvb_get_guint8(tvb, offset);
  offset++;
  /*
   * layer
   */
  qlayer = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(qnet6_tree, hf_qnet6_l4_layer, tvb, offset++, 1, encoding);
  /*
   * qos_info
   */
  /*
   * src_nd_for_dst
   */
  ti = proto_tree_add_item(qnet6_tree, hf_qnet6_l4_qos_info, tvb, offset, 20, ENC_NA);
  stree = proto_item_add_subtree(ti, ett_qnet6_qos_info);
  proto_tree_add_item(stree, hf_qnet6_l4_qos_src_nd_for_dst, tvb, offset, 2, encoding);
  offset += 2;
  /*
   * dst_nd_for_src
   */
  proto_tree_add_item(stree, hf_qnet6_l4_qos_dst_nd_for_src, tvb, offset, 2, encoding);
  offset += 2;
  /*
   * src connection id
   */
  proto_tree_add_item(stree, hf_qnet6_l4_qos_src_conn_id, tvb, offset, 4, encoding);
  offset += 4;
  /*
   * dst connection id
   */
  proto_tree_add_item(stree, hf_qnet6_l4_qos_dst_conn_id, tvb, offset, 4, encoding);
  offset += 4;
  /*
   * sequence number
   */
  proto_tree_add_item(stree, hf_qnet6_l4_qos_src_seq_num, tvb, offset, 4, encoding);
  offset += 4;
  /*
   * qos type
   */
  proto_tree_add_item(stree, hf_qnet6_l4_qos_qos_type, tvb, offset, 2, encoding);
  offset += 2;
  /*
   * qos index
   */
  proto_tree_add_item(stree, hf_qnet6_l4_qos_src_qos_idx, tvb, offset, 2, encoding);
  offset += 2;
  /*
   * end of qos_info
   */
  /*
   * offset in this stream
   */
  proto_tree_add_item(qnet6_tree, hf_qnet6_l4_offset, tvb, offset, 4, encoding);
  offset += 4;
  /*
   * length of its payload
   */
  plen = tvb_get_guint32(tvb, offset, encoding);
  proto_tree_add_uint(qnet6_tree, hf_qnet6_l4_length, tvb, offset, 4, plen);
  offset += 4;
  /*
   * crc value
   */
  crcp = tvb_get_guint32(tvb, offset, encoding);
  /*
   * crc value is l4_pkt header + data behind with original crc is 0
   */
  if ((qflags & (QNET_L4_FLAGS_FIRST)) &&
      (qflags & QNET_L4_FLAGS_LAST) && ((qnet6_lwl4_check_crc) || (qflags & QNET_L4_FLAGS_CRC)))
    {
      /*
       * only do crc when first|last|crc are all set
       */
      /*
       * 1.cksum header of l4_pkt except crc field
       */
      /*
       * qnet is using initial seed 0 not 0xffffffff
       */
      crc = crc32_mpeg2_tvb_offset_seed(tvb, 2, 36 - 4, 0);
      crc = ~crc;
      /*
       * 2. cksum crc field with 4 bytes 0
       */
      crc = crc32_mpeg2_seed(crcbuf, 4, ~crc);
      crc = ~crc;
      cklen = len - 36 - 2;
      if (plen < cklen)
        cklen = plen;
      /*
       * data after header
       */
      if (cklen > 0)
        {
          crc = crc32_mpeg2_tvb_offset_seed(tvb, 36 + 2, cklen, ~crc);
          crc = ~crc;
        }
      /*
       * qnet l4's crc didn't xor itself at last so we have to
       * workaround it
       */
      crc = ~crc;
      if (crcp == crc)
        proto_tree_add_uint_format(qnet6_tree, hf_qnet6_l4_crc, tvb, offset, 4, crcp, "crc32:0x%x [correct]", crcp);
      else
        proto_tree_add_uint_format(qnet6_tree, hf_qnet6_l4_crc, tvb, offset, 4, crcp, "crc32:0x%x [incorrect, should be 0x%x]", crcp, crc);
    }
  else
    {
      proto_tree_add_item(qnet6_tree, hf_qnet6_l4_crc, tvb, offset, 4, encoding);
    }
  offset += 4;
  /*
   * Continue adding tree items to process the packet here
   */
  /*
   * there is no data behind l4_pkt header in this packet
   */
  if (len == offset)
    return offset;
  /*
   * don't support fragment yet
   */
  if (!((qflags & QNET_L4_FLAGS_FIRST) && (qflags & QNET_L4_FLAGS_LAST)))
    {
      if (!(qflags & QNET_L4_FLAGS_FIRST))
        {
          if (qflags & QNET_L4_FLAGS_LAST)
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Last Fragmented ");
          else
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Fragmented ");
          return offset;
        }
    }

  /*
   * if (plen == 0 ) there is no payload indicated by the length in
   * l4_pkt header but we need to go through upper protocol layer to
   * show protocol and info. so upper layer should be careful of
   * the length
   */

  /*
   * qtype < QNET_L4_TYPE_USER is qos packet so qlayer is useless
   */
  if (qtype < QNET_L4_TYPE_USER && qtype > QNET_L4_TYPE_USER_DATA)
    {
      dissect_qnet6_qos(qtype, tvb, pinfo, tree, &offset, encoding);
    }
  else
    {
      switch (qtype)
        {
        case QNET_L4_TYPE_ACK:
          col_set_str(pinfo->cinfo, COL_INFO, "Ack");
          break;
        case QNET_L4_TYPE_NACK:
          col_set_str(pinfo->cinfo, COL_INFO, "Nack");
          break;
        case QNET_L4_TYPE_LRES:
          col_set_str(pinfo->cinfo, COL_INFO, "Lan Resolver Packets");
          break;
        default:
          break;
        }
      switch (qlayer)
        {
        case QNET_L4_LAYER_KIF:
          if (plen >= 4 /* sizeof(struct qnet6_kif_hdr) */ )
            {
              dissect_qnet6_kif (tvb, pinfo, tree, &offset, encoding);
            }
          break;
        case QNET_L4_LAYER_NR:
          /*
           * at least a type in payload
           */
          if (plen >= (gint) 1)
            dissect_qnet6_nr(tvb, pinfo, tree, &offset, encoding);
          break;
        case QNET_L4_LAYER_LR:
          if (plen >= QNX_QNET6_LR_PKT_SIZE
              /*
               * sizeof(struct qnet6_lr_pkt)
               */ )
            {
              dissect_qnet6_lr(tvb, pinfo, tree, &offset, encoding);
            }
          break;
        case QNET_L4_LAYER_SEQ:
          col_set_str(pinfo->cinfo, COL_INFO, "Qos Sequence hole filler Packets");
          break;
        }
    }
  if (!((qflags & QNET_L4_FLAGS_FIRST) && (qflags & QNET_L4_FLAGS_LAST)))
    {
      if (qflags & QNET_L4_FLAGS_FIRST)
        {
          /*
           * do as much as we can
           */
          col_prepend_fstr(pinfo->cinfo, COL_INFO, "First fragmented ");
        }
    }
  return offset;
}

/*
 * Register the protocol with Wireshark
 */

void
proto_register_qnet6(void)
{
  static hf_register_info hf[] = {
    {&hf_qnet6_l4_padding,
     {"Padding", "qnet6.l4.padding",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL
     }
    },
    {&hf_qnet6_l4_ver,
     {"Version", "qnet6.l4.ver",
      FT_UINT8, BASE_DEC, VALS(qnet6_ver_vals), 0,
      "QNET6 L4 Packet Version", HFILL
     }
    },
    {&hf_qnet6_l4_type,
     {"Type", "qnet6.l4.type",
      FT_UINT8, BASE_HEX, VALS(qnet6_type_vals), 0,
      "QNET6 L4 Upper layer protocol type", HFILL}
    },
    {&hf_qnet6_l4_flags,
     {"Flag", "qnet6.l4.flags",
      FT_UINT8, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_l4_flags_first,
     {"First Fragment", "qnet6.l4.flags.first",
      FT_BOOLEAN, 8, TFS(&tfs_yes_no), QNET_L4_FLAGS_FIRST,
      "QNET6 L4 Packet first fragment", HFILL}
    },
    {&hf_qnet6_l4_flags_last,
     {"Last Fragment", "qnet6.l4.flags.last",
      FT_BOOLEAN, 8, TFS(&tfs_yes_no), QNET_L4_FLAGS_LAST,
      "QNET6 L4 Packet last fragment", HFILL}
    },
    {&hf_qnet6_l4_flags_crc,
     {"CRC", "qnet6.l4.flags.crc",
      FT_BOOLEAN, 8, TFS(&tfs_used_notused), QNET_L4_FLAGS_CRC,
      "QNET6 L4 Packet crc used", HFILL}
    },

    {&hf_qnet6_l4_layer,
     {"Layer", "qnet6.l4.layer",
      FT_UINT8, BASE_DEC, VALS(qnet6_layer_vals), 0,
      "QNET6 L4 Packet layer", HFILL}
    },
    /* start from here is for qos_info  */
    /* in qos_info, node id is like ip address
     * but node id is not global like ip address
     * node id is unique on any node only. dragonlinux
     */
    {&hf_qnet6_l4_qos_info,
     {"Qos info", "qnet6.qos.qos_info",
      FT_NONE, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_l4_qos_src_nd_for_dst,
     {"Src_nd_for_dst", "qnet6.qos.src_nd_for_dst",
      FT_UINT16, BASE_DEC, NULL, 0,
      "QNET6 source node id for destination node", HFILL}
    },
    {&hf_qnet6_l4_qos_dst_nd_for_src,
     {"Dst_nd_for_src", "qnet6.qos.dst_nd_for_src",
      FT_UINT16, BASE_DEC, NULL, 0,
      "QNET6 destination node id for source node", HFILL}
    },
    /* in qos_info, connection id is like port number */
    {&hf_qnet6_l4_qos_src_conn_id,
     {"Sconn", "qnet6.qos.sconn",
      FT_UINT32, BASE_HEX, NULL, 0,
      "QNET6 source node's connection id", HFILL}
    },
    {&hf_qnet6_l4_qos_dst_conn_id,
     {"Dconn", "qnet6.qos.dconn",
      FT_UINT32, BASE_HEX, NULL, 0,
      "QNET6 destination node's connection id", HFILL}
    },
    {&hf_qnet6_l4_qos_src_seq_num,
     {"Seq", "qnet6.qos.seq",
      FT_UINT32, BASE_DEC, NULL, 0,
      "QNET6 connection sequence number", HFILL}
    },
    {&hf_qnet6_l4_qos_qos_type,
     {"Sos_type", "qnet6.qos.qos_type",
      FT_UINT16, BASE_DEC, VALS(qnet6_qos_type_vals), 0,
      "QNET6 qos type", HFILL}
    },
    {&hf_qnet6_l4_qos_src_qos_idx,
     {"Src_qos_idx", "qnet6.qos.src_qos_idx",
      FT_UINT16, BASE_DEC, NULL, 0,
      "QNET6 source node qos index", HFILL}
    },

    /* end of qos_info in l4_pkt */
    {&hf_qnet6_l4_offset,
     {"Offset", "qnet6.l4.offset",
      FT_UINT32, BASE_DEC, NULL, 0,
      "QNET6 Packet offset in stream", HFILL}
    },
    {&hf_qnet6_l4_length,
     {"Length", "qnet6.l4.length",
      FT_UINT32, BASE_DEC, NULL, 0,
      "QNET6 Packet payload length", HFILL}
    },
    {&hf_qnet6_l4_crc,
     {"Crc", "qnet6.l4.crc",
      FT_UINT32, BASE_HEX, NULL, 0,
      "QNET6 Packet cksum of header and payload", HFILL}
    }

  };
  static hf_register_info hf_qos[] = {
    {&hf_qnet6_qos_tcs_src_name_off,
     {"Src_name_off", "qnet6.qos.src_name_off",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Source name offset", HFILL}
    },
    {&hf_qnet6_qos_tcs_src_name_generated,
     {"Src_name", "qnet6.qos.src_name",
      FT_STRING, BASE_NONE, NULL, 0,
      "Source name", HFILL}
    },
    {&hf_qnet6_qos_tcs_src_domain_off,
     {"Src_domain_off", "qnet6.qos.src_domain_off",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Source domain name offset", HFILL}
    },
    {&hf_qnet6_qos_tcs_src_domain_generated,
     {"Src_domain", "qnet6.qos.src_domain",
      FT_STRING, BASE_NONE, NULL, 0,
      "Source domain name", HFILL}
    },
    {&hf_qnet6_qos_tcs_dst_name_off,
     {"Dst_name_off", "qnet6.qos.dst_name_off",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Destination name offset", HFILL}
    },
    {&hf_qnet6_qos_tcs_dst_name_generated,
     {"Dst_name", "qnet6.qos.dst_name",
      FT_STRING, BASE_NONE, NULL, 0,
      "Destination name", HFILL}
    },
    {&hf_qnet6_qos_tcs_dst_domain_off,
     {"Dst_domain_off", "qnet6.qos.dst_domain_off",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Destination domain name offset", HFILL}
    },
    {&hf_qnet6_qos_tcs_dst_domain_generated,
     {"Dst_domain", "qnet6.qos.dst_domain",
      FT_STRING, BASE_NONE, NULL, 0,
      "Destination domain name", HFILL}
    }
  };
  static hf_register_info hf_nr[] = {
    /* type, size are the first guint8 in all nr messages */
    {&hf_qnet6_nr_type,
     {"Type", "qnet6.nr.type",
      FT_UINT8, BASE_DEC, VALS(qnet6_nr_type_vals), 0,
      "Network Resolver Message Type", HFILL}
    },
    {&hf_qnet6_nr_remote_req_len,
     {"Req_len", "qnet6.nr.req_len",
      FT_UINT8, BASE_DEC, NULL, 0,
      "Network Resolver remote request length", HFILL}
    },
    {&hf_qnet6_nr_remote_req_id,
     {"Req_id", "qnet6.nr.req_id",
      FT_UINT16, BASE_HEX_DEC, NULL, 0,
      "Network Resolver remote request id", HFILL}
    },
    {&hf_qnet6_nr_remote_req_name,
     {"Req_name", "qnet6.nr.req_name",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "Network Resolver remote request name", HFILL}
    },
    {&hf_qnet6_nr_remote_rep_spare,
     {"Rep_spare", "qnet6.nr.rep_spare",
      FT_UINT8, BASE_HEX, NULL, 0,
      "Network Resolver remote answer pad byte", HFILL}
    },
    {&hf_qnet6_nr_remote_rep_id,
     {"Rep_id", "qnet6.nr.rep_id",
      FT_UINT16, BASE_HEX, NULL, 0,
      "Network Resolver remote answer id", HFILL}
    },
    {&hf_qnet6_nr_remote_rep_nd,
     {"Rep_nd", "qnet6.nr.rep_nd",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Network Resolver remote answer node id", HFILL}
    },
    {&hf_qnet6_nr_remote_rep_status,
     {"Rep_status", "qnet6.nr.rep_status",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Network Resolver remote answer error status", HFILL}
    }
  };

  static hf_register_info hf_lr[] = {
    /* start of qnet6_lr_pkt */
    {&hf_qnet6_lr_ver,
     {"Version", "qnet6.lr.ver",
      FT_UINT8, BASE_DEC, VALS(qnet6_lr_ver_vals), 0,
      "Lan Resolver Version", HFILL}
    },
    {&hf_qnet6_lr_type,
     {"Type", "qnet6.lr.type",
      FT_UINT8, BASE_HEX, VALS(qnet6_lr_type_vals), 0,
      "Lan Resolver Message Type", HFILL}
    },
    {&hf_qnet6_lr_total_len,
     {"Length", "qnet6.lr.length",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message total length(include header + payload)", HFILL}
    },
    {&hf_qnet6_lr_src,
     {"Source", "qnet6.lr.src",
      FT_STRING, BASE_NONE, NULL, 0,
      "LR Message source node", HFILL}
    },

    {&hf_qnet6_lr_src_name_off,
     {"Offset", "qnet6.lr.src.name.off",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message source name offset", HFILL}
    },
    {&hf_qnet6_lr_src_name_len,
     {"Length", "qnet6.lr.src.name.len",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message source name length", HFILL}
    },
    {&hf_qnet6_lr_src_name_generated,
     {"Name", "qnet6.lr.src.name.name",
      FT_STRING, BASE_NONE, NULL, 0,
      "LR Message source name", HFILL}
    },
    {&hf_qnet6_lr_src_domain_off,
     {"Offset", "qnet6.lr.src.domain.off",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message source domain name offset", HFILL}
    },
    {&hf_qnet6_lr_src_domain_len,
     {"Length", "qnet6.lr.src.domain.len",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message source domain name length", HFILL}
    },
    {&hf_qnet6_lr_src_domain_generated,
     {"Domain", "qnet6.lr.src.domain",
      FT_STRING, BASE_NONE, NULL, 0,
      "LR Message source domain name", HFILL}
    },
    {&hf_qnet6_lr_src_addr_off,
     {"Offset", "qnet6.lr.src.addr.off",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message source address offset", HFILL}
    },
    {&hf_qnet6_lr_src_addr_len,
     {"Length", "qnet6.lr.src.addr.len",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message source address length", HFILL}
    },
    {&hf_qnet6_lr_src_addr_generated,
     {"Address", "qnet6.lr.src.addr",
      FT_ETHER, BASE_NONE, NULL, 0,
      "LR Message source address", HFILL}
    },
    {&hf_qnet6_lr_dst,
     {"Destination", "qnet6.lr.dst",
      FT_STRING, BASE_NONE, NULL, 0,
      "LR Message destination node", HFILL}
    },
    {&hf_qnet6_lr_dst_name_off,
     {"Offset", "qnet6.lr.dst.name.off",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message destination name offset", HFILL}
    },
    {&hf_qnet6_lr_dst_name_len,
     {"Length", "qnet6.lr.dst.name.len",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message destination name length", HFILL}
    },
    {&hf_qnet6_lr_dst_name_generated,
     {"Name", "qnet6.lr.dst.name",
      FT_STRING, BASE_NONE, NULL, 0,
      "LR Message destination name", HFILL}
    },
    {&hf_qnet6_lr_dst_domain_off,
     {"Offset", "qnet6.lr.dst.domain.off",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message destination domain name offset", HFILL}
    },
    {&hf_qnet6_lr_dst_domain_len,
     {"Length", "qnet6.lr.dst_domain_len",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message destination domain name length", HFILL}
    },
    {&hf_qnet6_lr_dst_domain_generated,
     {"Domain", "qnet6.lr.dst.domain",
      FT_STRING, BASE_NONE, NULL, 0,
      "LR Message destination domain name", HFILL}
    },
    {&hf_qnet6_lr_dst_addr_off,
     {"Offset", "qnet6.lr.dst.addr.off",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message destination address offset", HFILL}
    },
    {&hf_qnet6_lr_dst_addr_len,
     {"Length", "qnet6.lr.dst.addr.len",
      FT_UINT32, BASE_DEC, NULL, 0,
      "LR Message destination address length", HFILL}
    },
    {&hf_qnet6_lr_dst_addr_generated,
     {"Address", "qnet6.lr.dst.addr",
      FT_ETHER, BASE_NONE, NULL, 0,
      "LR Message destination address", HFILL}
    }

  };

  static hf_register_info hf_kif[] = {
    /* msgtype, size are the first 2 in all kif messages */
    {&hf_qnet6_kif_msgtype,
     {"Type", "qnet6.kif.type",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgtype_vals), QNET_KIF_MSGTYPE_MASK,
      "Kernel Interface Message Type", HFILL}
    },
    {&hf_qnet6_kif_size,
     {"Size", "qnet6.kif.size",
      FT_UINT16, BASE_HEX, NULL, 0,
      "Kernel Interface Message header size", HFILL}
    },
    /* some kif messages will include version as well */
    {&hf_qnet6_kif_version,
     {"Version", "qnet6.kif.version",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Kernel Interface Message version", HFILL}
    },
    /* connect message after msghdr */
    {&hf_qnet6_kif_connect,
     {"Connect", "qnet6.kif.connect",
      FT_STRING, BASE_NONE, NULL, 0,
      "Connect Message", HFILL}
    },
    {&hf_qnet6_kif_msgsend,
     {"Msgsend", "qnet6.kif.msgsend",
      FT_STRING, BASE_NONE, NULL, 0,
      "Msgsend Message", HFILL}
    },
    {&hf_qnet6_kif_connect_server_pid,
     {"Server_pid", "qnet6.kif.connect.server_pid",
      FT_UINT32, BASE_DEC, NULL, 0,
      "Kernel Interface Message Server Pid", HFILL}
    },
    {&hf_qnet6_kif_connect_server_chid,
     {"Server_chid", "qnet6.kif.connect.server_chid",
      FT_UINT32, BASE_HEX_DEC, NULL, 0,
      "Kernel Interface Message Server channel id", HFILL}
    },
    {&hf_qnet6_kif_connect_client_id,
     {"Client_id", "qnet6.kif.connect.client_id",
      FT_UINT32, BASE_HEX_DEC, NULL, 0,
      "Kernel Interface Message client id", HFILL}
    },
    {&hf_qnet6_kif_connect_client_pid,
     {"Client_pid", "qnet6.kif.connect.client_pid",
      FT_UINT32, BASE_DEC, NULL, 0,
      "Kernel Interface Message Client Pid", HFILL}
    },
    /* connect success message after msghdr */
    {&hf_qnet6_kif_connects_client_id,
     {"Client_id", "qnet6.kif.connect_success.client_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface Message client id", HFILL}
    },
    {&hf_qnet6_kif_connects_server_id,
     {"Server_id", "qnet6.kif.connect_success.server_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface Message Server id", HFILL}
    },
    {&hf_qnet6_kif_connects_scoid,
     {"Scoid", "qnet6.kif.connect_success.scoid",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface Message server connection id", HFILL}
    },
    {&hf_qnet6_kif_connects_nbytes,
     {"Nbytes", "qnet6.kif.connect_success.nbytes",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "Kernel Interface Message limit for msgsend", HFILL}
    },
    /* connect fail after msghdr and version */
    {&hf_qnet6_kif_connectf_client_id,
     {"Client_id", "qnet6.kif.connect_fail.client_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface Connect Fail Message client id", HFILL}
    },
    {&hf_qnet6_kif_connectf_status,
     {"Status", "qnet6.kif.connect_fail.status",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface Connect Fail Message Status", HFILL}
    },
    /* connect death after msghdr */
    {&hf_qnet6_kif_connectd_client_id,
     {"Client_id", "qnet6.kif.connect_death.client_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface Connect Death Message client id", HFILL}
    },

    /* msgsend message after msghdr */
    {&hf_qnet6_kif_msgsend_server_id,
     {"Server_id", "qnet6.kif.msgsend.server_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface MsgSend Message Server id", HFILL}
    },
    {&hf_qnet6_kif_msgsend_client_handle,
     {"Client_handle", "qnet6.kif.msgsend.client_handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message client handle", HFILL}
    },
    /* msgsend vtid_info here */
    {&hf_qnet6_kif_msgsend_vinfo,
     {"Vinfo", "qnet6.kif.msgsend.vinfo",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "Kernel Interface MsgSend Message virtual thread information", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_tid,
     {"Vtid", "qnet6.kif.msgsend.vtid_info.tid",
      FT_INT32, BASE_DEC, NULL, 0,
      "essage virtual thread information thread id", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_coid,
     {"Coid", "qnet6.kif.msgsend.vtid_info.coid",
      FT_INT32, BASE_DEC, NULL, 0,
      "Kernel Interface MsgSend Message virtual thread connection id", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_priority,
     {"Priority", "qnet6.kif.msgsend.vtid_info.priority",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message virtual thread priority", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_srcmsglen,
     {"Srcmsglen", "qnet6.kif.msgsend.vtid_info.srcmsglen",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message virtual thread source message length", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_keydata,
     {"Keydata", "qnet6.kif.msgsend.vtid_info.keydata",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message virtual thread keydata", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_srcnd,
     {"Srcnd", "qnet6.kif.msgsend.vtid_info.srcnd",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message virtual thread source node id", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_dstmsglen,
     {"Dstmsglen", "qnet6.kif.msgsend.vtid_info.dstmsglen",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message virtual thread destination message length", HFILL}
    },
    {&hf_qnet6_kif_vtid_info_zero,
     {"Zero", "qnet6.kif.msgsend.vtid_info.zero",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgSend Message virtual thread reserved part", HFILL}
    },
    {&hf_qnet6_kif_msgsend_nbytes,
     {"Nbytes", "qnet6.kif.msgsend.nbytes",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "Kernel Interface MsgSend Message limit for msgsend", HFILL}
    },
    {&hf_qnet6_kif_msgread_msgread_handle,
     {"Msgread_handle", "qnet6.kif.msgread.msgread_handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgRead Message handle", HFILL}
    },
    {&hf_qnet6_kif_msgread_client_handle,
     {"Client_handle", "qnet6.kif.msgread.client_handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "MsgRead Message client handle", HFILL}
    },
    {&hf_qnet6_kif_msgread_offset,
     {"Offset", "qnet6.kif.msgread.offset",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "MsgRead Message limit for msgread", HFILL}
    },
    {&hf_qnet6_kif_msgread_nbytes,
     {"Nbytes", "qnet6.kif.msgread.nbytes",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "MsgRead Message limit for msgread", HFILL}
    },
    /* msgwrite */
    {&hf_qnet6_kif_msgwrite_status,
     {"Status", "qnet6.kif.msgwrite.status",
      FT_INT32, BASE_DEC, NULL, 0,
      "Msgwrite Message client handle", HFILL}
    },
    {&hf_qnet6_kif_msgwrite_handle,
     {"Handle", "qnet6.kif.msgwrite.handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "Msgwrite Message client handle", HFILL}
    },
    {&hf_qnet6_kif_msgwrite_offset,
     {"Offset", "qnet6.kif.msgwrite.offset",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "Msgwrite Message limit for msgwrite", HFILL}
    },
    {&hf_qnet6_kif_msgwrite_nbytes,
     {"Nbytes", "qnet6.kif.msgwrite.nbytes",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "Msgwrite Message limit for msgwrite", HFILL}
    },
    {&hf_qnet6_kif_msgwrite_data,
     {"Data", "qnet6.kif.msgwrite.data",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    /* unblock */
    {&hf_qnet6_kif_unblock_server_id,
     {"Server_id", "qnet6.kif.unblock.server_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "Unblock Message Server id", HFILL}
    },
    {&hf_qnet6_kif_unblock_client_handle,
     {"Client_handle", "qnet6.kif.unblock.client_handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "Unblock Message client handle", HFILL}
    },
    {&hf_qnet6_kif_unblock_tid,
     {"Tid", "qnet6.kif.unblock.tid",
      FT_INT32, BASE_DEC, NULL, 0,
      "thread information thread id", HFILL}
    },
    /* event */
    {&hf_qnet6_kif_event_client_handle,
     {"Client_handle", "qnet6.kif.event.client_handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "Event Message client handle", HFILL}
    },
    /* event */
    {&hf_qnet6_kif_event_event,
     {"Sigevent", "qnet6.kif.event.event",
      FT_NONE, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_event_notify,
     {"Sigevent_notify", "qnet6.kif.event.sigevent_notify",
      FT_INT32, BASE_DEC, NULL, 0,
      "Event Message sigevent notify", HFILL}
    },
    {&hf_qnet6_kif_event_union1,
     {"Sigevent_union1", "qnet6.kif.event.sigevent_union1",
      FT_INT32, BASE_DEC, NULL, 0,
      "Event Message sigevent union1", HFILL}
    },
    {&hf_qnet6_kif_event_value,
     {"Sigevent_sigvalue", "qnet6.kif.event.sigevent_sigvalue",
      FT_INT32, BASE_DEC, NULL, 0,
      "Event Message sigevent sigvalue", HFILL}
    },
    {&hf_qnet6_kif_event_union2,
     {"Sigevent_union2", "qnet6.kif.event.sigevent_union2",
      FT_INT32, BASE_DEC, NULL, 0,
      "Event Message sigevent union2", HFILL}
    },
    /* pulse */
    /* will use msgsend */
    {&hf_qnet6_kif_pulse_pulse,
     {"Pulse", "qnet6.kif.pulse",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_pulse_type,
     {"Type", "qnet6.kif.pulse.pulse.type",
      FT_UINT16, BASE_HEX_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_pulse_subtype,
     {"Subtype", "qnet6.kif.pulse.pulse.subtype",
      FT_UINT16, BASE_HEX_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_pulse_code,
     {"Code", "qnet6.kif.pulse.pulse.code",
      FT_INT8, BASE_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_pulse_reserved,
     {"Reserved", "qnet6.kif.pulse.pulse.reserved",
      FT_UINT24, BASE_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_pulse_value,
     {"Value", "qnet6.kif.pulse.pulse.value",
      FT_UINT32, BASE_HEX_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_pulse_scoid,
     {"Scoid", "qnet6.kif.pulse.pulse.scoid",
      FT_INT32, BASE_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_pulse_priority,
     {"Priority", "qnet6.kif.pulse.priority",
      FT_INT32, BASE_DEC, NULL, 0,
      NULL, HFILL}
    },
    /* signal */
    {&hf_qnet6_kif_signal_client_handle,
     {"Client_handle", "qnet6.kif.signal.client_handle",
      FT_INT32, BASE_DEC, NULL, 0,
      "Signal Message client handle", HFILL}
    },
    {&hf_qnet6_kif_signal_pid,
     {"Pid", "qnet6.kif.signal.pid",
      FT_INT32, BASE_DEC, NULL, 0,
      "Signal Message from this pid", HFILL}
    },
    {&hf_qnet6_kif_signal_tid,
     {"Tid", "qnet6.kif.signal.tid",
      FT_INT32, BASE_DEC, NULL, 0,
      "Signal Message from this tid", HFILL}
    },
    {&hf_qnet6_kif_signal_signo,
     {"Signo", "qnet6.kif.signal.signo",
      FT_INT32, BASE_DEC, NULL, 0,
      "Signal number delivered to remote", HFILL}
    },
    {&hf_qnet6_kif_signal_code,
     {"Code", "qnet6.kif.signal.code",
      FT_INT32, BASE_DEC, NULL, 0,
      "Signal code delivered to remote", HFILL}
    },
    {&hf_qnet6_kif_signal_value,
     {"Value", "qnet6.kif.signal.value",
      FT_INT32, BASE_DEC, NULL, 0,
      "Signal value delivered to remote", HFILL}
    },
    /* disconnect */
    {&hf_qnet6_kif_disconnect_server_id,
     {"Server_id", "qnet6.kif.disconnect.server_id",
      FT_INT32, BASE_DEC, NULL, 0,
      "disconnect message server id from connect success message", HFILL}
    },
    /* msg info */
    {&hf_qnet6_kif_msg,
     {"Message", "qnet6.kif.msgsend.msg",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_type,
     {"Type", "qnet6.kif.msgsend.msg.type",
      FT_UINT16, BASE_HEX|BASE_EXT_STRING, &qnet6_kif_msgsend_msgtype_vals_ext, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_subtype,
     {"Subtype", "qnet6.kif.msgsend.msg.connect.subtype",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_subtype_vals), 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_filetype,
     {"File_type", "qnet6.kif.msgsend.msg.connect.file_type",
      FT_UINT32, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_filetype_vals), 0,
      "file type", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_replymax,
     {"Reply_max", "qnet6.kif.msgsend.msg.connect.reply_max",
      FT_UINT16, BASE_HEX_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_entrymax,
     {"Entry_max", "qnet6.kif.msgsend.msg.connect.entry_max",
      FT_UINT16, BASE_HEX_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_key,
     {"Key", "qnet6.kif.msgsend.msg.connect.key",
      FT_UINT32, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_handle,
     {"Handle", "qnet6.kif.msgsend.msg.connect.handle",
      FT_UINT32, BASE_HEX_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag,
     {"Ioflag", "qnet6.kif.msgsend.msg.connect.ioflag",
      FT_UINT32, BASE_OCT, NULL, 0,
      "file io flag", HFILL}
    },
    /* for FT_BOOLEAN, its display field must be parent bit width */

    {&hf_qnet6_kif_msg_connect_ioflag_access,
     {"access", "qnet6.kif.msgsend.msg.connect.ioflag.access",
      FT_UINT32, BASE_DEC, VALS(qnet6_kif_msgsend_msg_connect_ioflag_vals), 03,
      "access mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_append,
     {"append", "qnet6.kif.msgsend.msg.connect.ioflag.append",
      FT_BOOLEAN, 32, NULL, 010,
      "append mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_dsync,
     {"dsync", "qnet6.kif.msgsend.msg.connect.ioflag.dsync",
      FT_BOOLEAN, 32, NULL, 020,
      "data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_sync,
     {"sync", "qnet6.kif.msgsend.msg.connect.ioflag.sync",
      FT_BOOLEAN, 32, NULL, 040,
      "file sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_rsync,
     {"rsync", "qnet6.kif.msgsend.msg.connect.ioflag.rsync",
      FT_BOOLEAN, 32, NULL, 0100,
      "alias for data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_nonblock,
     {"nonblock", "qnet6.kif.msgsend.msg.connect.ioflag.nonblock",
      FT_BOOLEAN, 32, NULL, 0200,
      "alias for data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_creat,
     {"creat", "qnet6.kif.msgsend.msg.connect.ioflag.creat",
      FT_BOOLEAN, 32, NULL, 0400,
      "creat mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_truncate,
     {"truncate", "qnet6.kif.msgsend.msg.connect.ioflag.truncate",
      FT_BOOLEAN, 32, NULL, 01000,
      "truncate mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_exclusive,
     {"exclusive", "qnet6.kif.msgsend.msg.connect.ioflag.exclusive",
      FT_BOOLEAN, 32, NULL, 02000,
      "exclusive mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_noctrltty,
     {"noctrltty", "qnet6.kif.msgsend.msg.connect.ioflag.noctrltty",
      FT_BOOLEAN, 32, NULL, 04000,
      "noctrltty mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_closexec,
     {"closexec", "qnet6.kif.msgsend.msg.connect.ioflag.closexec",
      FT_BOOLEAN, 32, NULL, 010000,
      "closexec mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_realids,
     {"realids", "qnet6.kif.msgsend.msg.connect.ioflag.realids",
      FT_BOOLEAN, 32, NULL, 020000,
      "realids mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_largefile,
     {"largefile", "qnet6.kif.msgsend.msg.connect.ioflag.largefile",
      FT_BOOLEAN, 32, NULL, 0100000,
      "largefile mode", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_ioflag_async,
     {"async", "qnet6.kif.msgsend.msg.connect.ioflag.async",
      FT_BOOLEAN, 32, NULL, 0200000,
      "async mode", HFILL}
    },

    {&hf_qnet6_kif_msg_connect_mode,
     {"Mode", "qnet6.kif.msgsend.msg.connect.mode",
      FT_UINT32, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_other_exe,
     {"Oexec", "qnet6.kif.msgsend.msg.connect.mode.other.exec",
      FT_BOOLEAN, 32, NULL, 01,
      "others exec permission", HFILL}
    },

    {&hf_qnet6_kif_msg_connect_mode_other_write,
     {"Owrite", "qnet6.kif.msgsend.msg.connect.mode.other.write",
      FT_BOOLEAN, 32, NULL, 02,
      "others write permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_other_read,
     {"Oread", "qnet6.kif.msgsend.msg.connect.mode.other.read",
      FT_BOOLEAN, 32, NULL, 04,
      "others read permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_group_exe,
     {"Gexec", "qnet6.kif.msgsend.msg.connect.mode.group.exec",
      FT_BOOLEAN, 32, NULL, 010,
      "group exec permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_group_write,
     {"Gwrite", "qnet6.kif.msgsend.msg.connect.mode.group.write",
      FT_BOOLEAN, 32, NULL, 020,
      "group write permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_group_read,
     {"Gread", "qnet6.kif.msgsend.msg.connect.mode.group.read",
      FT_BOOLEAN, 32, NULL, 040,
      "group read permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_owner_exe,
     {"Uexec", "qnet6.kif.msgsend.msg.connect.mode.owner.exec",
      FT_BOOLEAN, 32, NULL, 0100,
      "owner exec permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_owner_write,
     {"Uwrite", "qnet6.kif.msgsend.msg.connect.mode.owner.write",
      FT_BOOLEAN, 32, NULL, 0200,
      "owner write permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_owner_read,
     {"Uread", "qnet6.kif.msgsend.msg.connect.mode.owner.read",
      FT_BOOLEAN, 32, NULL, 0400,
      "owner read permission", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_sticky,
     {"sticky", "qnet6.kif.msgsend.msg.connect.mode.sticky",
      FT_BOOLEAN, 32, NULL, 01000,
      "sticky bit", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_setgid,
     {"setgid", "qnet6.kif.msgsend.msg.connect.mode.setgid",
      FT_BOOLEAN, 32, NULL, 02000,
      "set gid when execution", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_mode_setuid,
     {"setuid", "qnet6.kif.msgsend.msg.connect.mode.setuid",
      FT_BOOLEAN, 32, NULL, 04000,
      "set uid when execution", HFILL}
    },

    {&hf_qnet6_kif_msg_connect_mode_format,
     {"format", "qnet6.kif.msgsend.msg.connect.mode.format",
      FT_UINT32, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_mode_vals), 0xf000,
      "file format", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_sflag,
     {"Sflag", "qnet6.kif.msgsend.msg.connect.sflag",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_sflag_vals), 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_access,
     {"Access", "qnet6.kif.msgsend.msg.connect.access",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_access_vals), 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_zero,
     {"Zero", "qnet6.kif.msgsend.msg.connect.zero",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_pathlen,
     {"Path_len", "qnet6.kif.msgsend.msg.connect.path_len",
      FT_UINT16, BASE_HEX, NULL, 0,
      "path length", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_eflag,
     {"Eflag", "qnet6.kif.msgsend.msg.connect.eflag",
      FT_UINT8, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_eflag_dir,
     {"dir", "qnet6.kif.msgsend.msg.connect.eflag.dir",
      FT_BOOLEAN, 8, NULL, 1,
      "path referenced a directory", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_eflag_dot,
     {"dot", "qnet6.kif.msgsend.msg.connect.eflag.dot",
      FT_BOOLEAN, 8, NULL, 2,
      "Last component was . or ..", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_eflag_dotdot,
     {"dotdot", "qnet6.kif.msgsend.msg.connect.eflag.dotdot",
      FT_BOOLEAN, 8, NULL, 4,
      "Last component was ..", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extratype,
     {"Extra_type", "qnet6.kif.msgsend.msg.connect.extra_type",
      FT_UINT8, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_extratype_vals), 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extralen,
     {"Extra_len", "qnet6.kif.msgsend.msg.connect.extra_len",
      FT_UINT16, BASE_HEX_DEC, NULL, 0,
      "extra data length", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_path,
     {"Path", "qnet6.kif.msgsend.msg.connect.path",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "path name", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_pad_data,
     {"Pad data", "qnet6.kif.msgsend.msg.pad_data",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extra_link_ocb,
     {"Ocb", "qnet6.kif.msgsend.msg.connect.extra.link.ocb",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Ocb pointer value", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extra_symlink_path,
     {"Path", "qnet6.kif.msgsend.msg.connect.extra.symlink.path",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "Symlink new path name", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extra_rename_path,
     {"Path", "qnet6.kif.msgsend.msg.connect.extra.rename.path",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "Rename old path name", HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extra_mount,
     {"Mount", "qnet6.kif.msgsend.msg.connect.extra.mount",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_connect_extra_data,
     {"Extra Data", "qnet6.kif.msgsend.msg.connect.extra.data",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },

    /* _IO_DEVCTL */
    {&hf_qnet6_kif_msg_io_combine_len,
     {"Combine_len", "qnet6.kif.msgsend.msg.combine_len",
      FT_UINT16, BASE_HEX, NULL, 0,
      "combine length", HFILL}
    },
    /* when it is in this field is dcmd,
     *            out              ret_val
     */
    {&hf_qnet6_kif_msg_devctl_dcmd,
     {"Dcmd", "qnet6.kif.msgsend.msg.dcmd",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Devctl Command and Direction", HFILL}
    },
    /* if use FT_INT32 then can't use bitmask !!! */
    {&hf_qnet6_kif_msg_devctl_dcmd_ccmd,
     {"Ccmd", "qnet6.kif.msgsend.msg.dcmd.ccmd",
      FT_UINT32, BASE_HEX_DEC|BASE_EXT_STRING, &qnet6_kif_msg_devctl_cmd_class_vals_ext, 0xffff,
      "Devctl Class+Command", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_dcmd_cmd,
     {"Cmd", "qnet6.kif.msgsend.msg.dcmd.cmd",
      FT_UINT32, BASE_HEX_DEC, NULL, 0xff,
      "Devctl Command", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_dcmd_class,
     {"Class", "qnet6.kif.msgsend.msg.dcmd.class",
      FT_UINT32, BASE_HEX|BASE_EXT_STRING, &qnet6_kif_msgsend_msg_devctl_cmd_class_vals_ext, 0xff00,
      "Devctl Command", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_dcmd_size,
     {"Size", "qnet6.kif.msgsend.msg.dcmd.size",
      FT_UINT32, BASE_HEX, NULL, 0x3fff0000,
      "Devctl Command", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_dcmd_from,
     {"From", "qnet6.kif.msgsend.msg.dcmd.from",
      FT_UINT32, BASE_HEX, NULL, 0x40000000,
      "Devctl Direction has from", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_dcmd_to,
     {"To", "qnet6.kif.msgsend.msg.dcmd.to",
      FT_UINT32, BASE_HEX, NULL, 0x80000000,
      "Devctl Direction has to", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_nbytes,
     {"Nbytes", "qnet6.kif.msgsend.msg.nbytes",
      FT_INT32, BASE_DEC, NULL, 0,
      "payload length", HFILL}
    },
    {&hf_qnet6_kif_msg_devctl_zero,
     {"Zero", "qnet6.kif.msgsend.msg.zero",
      FT_INT32, BASE_DEC, NULL, 0,
      "pad", HFILL}
    },
    /* io_read */
    {&hf_qnet6_kif_msg_io_read_nbytes,
     {"Nbytes", "qnet6.kif.msgsend.msg.read.nbytes",
      FT_INT32, BASE_DEC, NULL, 0,
      "read buffer size", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_xtypes,
     {"Xtypes", "qnet6.kif.msgsend.msg.read.xtypes",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Extended types for io message", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_xtypes_0_7,
     {"Xtype", "qnet6.kif.msgsend.msg.read.xtypes0-7",
      FT_UINT32, BASE_HEX, VALS(qnet6_kif_msgsend_msg_io_read_xtypes_vals), 0xff,
      "Extended types 0-7 bits", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_xtypes_8,
     {"DirExtraHint", "qnet6.kif.msgsend.msg.read.xtypes8",
      FT_UINT32, BASE_HEX, NULL, 0x100,
      "_IO_XFLAG_DIR_EXTRA_HINT", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_xtypes_14,
     {"Nonblock", "qnet6.kif.msgsend.msg.read.xtypes0-7",
      FT_UINT32, BASE_HEX, NULL, 0x4000,
      "_IO_XFLAG_NONBLOCK", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_xtypes_15,
     {"Block", "qnet6.kif.msgsend.msg.read.xtypes0-7",
      FT_UINT32, BASE_HEX, NULL, 0x8000,
      "_IO_XFLAG_BLOCK", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_xoffset,
     {"Xoffset", "qnet6.kif.msgsend.msg.read.xoffset",
      FT_INT64, BASE_DEC, NULL, 0,
      "Extended offset in io message", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_cond_min,
     {"Min", "qnet6.kif.msgsend.msg.read.readcond.min",
      FT_INT32, BASE_DEC, NULL, 0,
      "Extended attribute minimum characters for readcond", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_cond_time,
     {"Time", "qnet6.kif.msgsend.msg.read.readcond.time",
      FT_INT32, BASE_DEC, NULL, 0,
      "Extended attribute for readcond in 1/10 second", HFILL}
    },
    {&hf_qnet6_kif_msg_io_read_cond_timeout,
     {"Timeout", "qnet6.kif.msgsend.msg.read.readcond.timeout",
      FT_INT32, BASE_DEC, NULL, 0,
      "Extended attribute timeout for readcond in 1/10 second", HFILL}
    },
    /* io_write */
    {&hf_qnet6_kif_msg_io_write_data,
     {"Write Data", "qnet6.kif.msgsend.msg.write.data",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_nbytes,
     {"Nbytes", "qnet6.kif.msgsend.msg.write.nbytes",
      FT_INT32, BASE_DEC, NULL, 0,
      "write buffer size", HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_xtypes,
     {"Xtypes", "qnet6.kif.msgsend.msg.write.xtypes",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Extended types for io message", HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_xtypes_0_7,
     {"Xtype", "qnet6.kif.msgsend.msg.write.xtypes0-7",
      FT_UINT32, BASE_HEX, VALS(qnet6_kif_msgsend_msg_io_read_xtypes_vals), 0xff,
      "Extended types 0-7 bits", HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_xtypes_8,
     {"DirExtraHint", "qnet6.kif.msgsend.msg.write.xtypes8",
      FT_UINT32, BASE_HEX, NULL, 0x100,
      "_IO_XFLAG_DIR_EXTRA_HINT", HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_xtypes_14,
     {"Nonblock", "qnet6.kif.msgsend.msg.write.xtypes0-7",
      FT_UINT32, BASE_HEX, NULL, 0x4000,
      "_IO_XFLAG_NONBLOCK", HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_xtypes_15,
     {"Block", "qnet6.kif.msgsend.msg.write.xtypes0-7",
      FT_UINT32, BASE_HEX, NULL, 0x8000,
      "_IO_XFLAG_BLOCK", HFILL}
    },
    {&hf_qnet6_kif_msg_io_write_xoffset,
     {"Xoffset", "qnet6.kif.msgsend.msg.write.xoffset",
      FT_INT64, BASE_DEC, NULL, 0,
      "Extended offset in io message", HFILL}
    },
    /* io_seek */
    {&hf_qnet6_kif_msg_seek_whence,
     {"Whence", "qnet6.kif.msgsend.msg.lseek.whence",
      FT_INT16, BASE_DEC, VALS(qnet6_kif_msgsend_msg_io_seek_whence_vals), 0,
      "whence in file", HFILL}
    },
    {&hf_qnet6_kif_msg_seek_offset,
     {"Offset", "qnet6.kif.msgsend.msg.lseek.offset",
      FT_UINT64, BASE_DEC_HEX, NULL, 0,
      "offset according to whence in file", HFILL}
    },
    /* io_pathconf */
    {&hf_qnet6_kif_msg_pathconf_name,
     {"name", "qnet6.kif.msgsend.msg.pathconf.name",
      FT_INT16, BASE_DEC|BASE_EXT_STRING, &qnet6_kif_msgsend_msg_io_pathconf_name_vals_ext, 0,
      "pathconf(name)", HFILL}
    },
    /* io_chmod */
    {&hf_qnet6_kif_msg_io_chmod,
     {"mode", "qnet6.kif.msgsend.msg.chmod.mode",
      FT_UINT32, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_other_exe,
     {"Oexec", "qnet6.kif.msgsend.msg.chmod.other.exec",
      FT_BOOLEAN, 32, NULL, 01,
      "others exec permission", HFILL}
    },

    {&hf_qnet6_kif_msg_io_chmod_other_write,
     {"Owrite", "qnet6.kif.msgsend.msg.chmod.other.write",
      FT_BOOLEAN, 32, NULL, 02,
      "others write permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_other_read,
     {"Oread", "qnet6.kif.msgsend.msg.chmod.other.read",
      FT_BOOLEAN, 32, NULL, 04,
      "others read permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_group_exe,
     {"Gexec", "qnet6.kif.msgsend.msg.chmod.group.exec",
      FT_BOOLEAN, 32, NULL, 010,
      "group exec permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_group_write,
     {"Gwrite", "qnet6.kif.msgsend.msg.chmod.group.write",
      FT_BOOLEAN, 32, NULL, 020,
      "group write permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_group_read,
     {"Gread", "qnet6.kif.msgsend.msg.chmod.group.read",
      FT_BOOLEAN, 32, NULL, 040,
      "group read permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_owner_exe,
     {"Uexec", "qnet6.kif.msgsend.msg.chmod.owner.exec",
      FT_BOOLEAN, 32, NULL, 0100,
      "owner exec permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_owner_write,
     {"Uwrite", "qnet6.kif.msgsend.msg.chmod.owner.write",
      FT_BOOLEAN, 32, NULL, 0200,
      "owner write permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_owner_read,
     {"Uread", "qnet6.kif.msgsend.msg.chmod.owner.read",
      FT_BOOLEAN, 32, NULL, 0400,
      "owner read permission", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_sticky,
     {"sticky", "qnet6.kif.msgsend.msg.chmod.sticky",
      FT_BOOLEAN, 32, NULL, 01000,
      "sticky bit", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_setgid,
     {"setgid", "qnet6.kif.msgsend.msg.chmod.setgid",
      FT_BOOLEAN, 32, NULL, 02000,
      "set gid when execution", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chmod_setuid,
     {"setuid", "qnet6.kif.msgsend.msg.chmod.setuid",
      FT_BOOLEAN, 32, NULL, 04000,
      "set uid when execution", HFILL}
    },
    /* io_chown */
    {&hf_qnet6_kif_msg_io_chown_gid,
     {"gid", "qnet6.kif.msgsend.msg.chown.gid",
      FT_UINT32, BASE_HEX, NULL, 0,
      "chown gid", HFILL}
    },
    {&hf_qnet6_kif_msg_io_chown_uid,
     {"uid", "qnet6.kif.msgsend.msg.chown.uid",
      FT_UINT32, BASE_HEX, NULL, 0,
      "chown uid", HFILL}
    },
    /* io_sync */
    {&hf_qnet6_kif_msg_io_sync,
     {"sync", "qnet6.kif.msgsend.msg.sync",
      FT_UINT32, BASE_HEX, NULL, 0,
      "io sync command", HFILL}
    },
    {&hf_qnet6_kif_msg_syncflag_dsync,
     {"dsync", "qnet6.kif.msgsend.msg.sync.flag.dsync",
      FT_BOOLEAN, 32, NULL, 020,
      "data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_syncflag_sync,
     {"sync", "qnet6.kif.msgsend.msg.sync.flag.sync",
      FT_BOOLEAN, 32, NULL, 040,
      "file sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_syncflag_rsync,
     {"rsync", "qnet6.kif.msgsend.msg.sync.flag.rsync",
      FT_BOOLEAN, 32, NULL, 0100,
      "alias for data sync mode", HFILL}
    },
    /* utime */
    {&hf_qnet6_kif_msg_io_utime_curflag,
     {"curflag", "qnet6.kif.msgsend.msg.utime.curflag",
      FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0,
      "whether use current time", HFILL}
    },
    {&hf_qnet6_kif_msg_io_utime_actime,
     {"actime", "qnet6.kif.msgsend.msg.utime.actime",
      FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
      "access time in seconds since the Epoch", HFILL}
    },
    {&hf_qnet6_kif_msg_io_utime_modtime,
     {"modtime", "qnet6.kif.msgsend.msg.utime.modtime",
      FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
      "modification time in seconds since the Epoch", HFILL}
    },
    /* fdinfo */
    {&hf_qnet6_kif_msg_io_fdinfo_flags,
     {"flags", "qnet6.kif.msgsend.msg.fdinfo.flags",
      FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0,
      "_FDINFO_FLAG_LOCALPATH", HFILL}
    },
    {&hf_qnet6_kif_msg_io_fdinfo_path_len,
     {"pathlen", "qnet6.kif.msgsend.msg.fdinfo.pathlen",
      FT_UINT32, BASE_HEX, NULL, 0,
      "returned path buffer's length", HFILL}
    },
    {&hf_qnet6_kif_msg_io_fdinfo_reserved,
     {"reserved", "qnet6.kif.msgsend.msg.fdinfo.reserved",
      FT_UINT32, BASE_HEX, NULL, 0,
      "reserved fields", HFILL}
    },
    /* lock */
    {&hf_qnet6_kif_msg_io_lock_subtype,
     {"subtype", "qnet6.kif.msgsend.msg.lock.subtype",
      FT_UINT32, BASE_HEX, NULL, 0,
      "io lock subytpe", HFILL}
    },
    {&hf_qnet6_kif_msg_io_lock_nbytes,
     {"nbytes", "qnet6.kif.msgsend.msg.lock.nbytes",
      FT_UINT32, BASE_HEX, NULL, 0,
      "io lock nbytes", HFILL}
    },
    /* space */
    {&hf_qnet6_kif_msg_io_space_subtype,
     {"subtype", "qnet6.kif.msgsend.msg.space.subtype",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_io_space_subtype_vals), 0,
      "io space subytpe", HFILL}
    },
    {&hf_qnet6_kif_msg_io_space_whence,
     {"whence", "qnet6.kif.msgsend.msg.space.whence",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_io_seek_whence_vals), 0,
      "io space whence", HFILL}
    },
    {&hf_qnet6_kif_msg_io_space_start,
     {"start", "qnet6.kif.msgsend.msg.space.start",
      FT_UINT64, BASE_HEX, NULL, 0,
      "io space start", HFILL}
    },
    {&hf_qnet6_kif_msg_io_space_len,
     {"len", "qnet6.kif.msgsend.msg.space.len",
      FT_UINT64, BASE_HEX, NULL, 0,
      "io space len", HFILL}
    },
    {&hf_qnet6_kif_msgsend_extra,
     {"Extra", "qnet6.kif.msgsend.extra",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },

    /* msg_info */
    {&hf_qnet6_kif_msg_msginfo_nd,
     {"Node", "qnet6.kif.msgsend.msg_info.nd",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "node id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_srcnd,
     {"Srcnode", "qnet6.kif.msgsend.msg_info.srcnd",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "source node id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_pid,
     {"Pid", "qnet6.kif.msgsend.msg_info.pid",
      FT_INT32, BASE_DEC, NULL, 0,
      "process id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_tid,
     {"Tid", "qnet6.kif.msgsend.msg_info.tid",
      FT_INT32, BASE_DEC, NULL, 0,
      "thread id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_chid,
     {"Chid", "qnet6.kif.msgsend.msg_info.chid",
      FT_INT32, BASE_DEC, NULL, 0,
      "channel id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_scoid,
     {"Scoid", "qnet6.kif.msgsend.msg_info.scoid",
      FT_INT32, BASE_DEC, NULL, 0,
      "server connection id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_coid,
     {"Coid", "qnet6.kif.msgsend.msg_info.coid",
      FT_INT32, BASE_DEC, NULL, 0,
      "connection id", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_msglen,
     {"Msglen", "qnet6.kif.msgsend.msg_info.msglen",
      FT_INT32, BASE_DEC, NULL, 0,
      "message length", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_srcmsglen,
     {"Srcmsglen", "qnet6.kif.msgsend.msg_info.srcmsglen",
      FT_INT32, BASE_DEC, NULL, 0,
      "source message length", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_dstmsglen,
     {"Dstmsglen", "qnet6.kif.msgsend.msg_info.dstmsglen",
      FT_INT32, BASE_DEC, NULL, 0,
      "destination message length", HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_priority,
     {"Priority", "qnet6.kif.msgsend.msg_info.priority",
      FT_INT16, BASE_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_flags,
     {"Flags", "qnet6.kif.msgsend.msg_info.flags",
      FT_INT16, BASE_DEC, NULL, 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_msginfo_reserved,
     {"Reserved", "qnet6.kif.msgsend.msg_info.reserved",
      FT_UINT32, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    /* openfd */

    {&hf_qnet6_kif_msg_openfd_ioflag,
     {"Ioflag", "qnet6.kif.msgsend.msg.openfd.ioflag",
      FT_UINT32, BASE_OCT, NULL, 0,
      "file io flag", HFILL}
    },
    /* for FT_BOOLEAN, its display field must be parent bit width */

    {&hf_qnet6_kif_msg_openfd_ioflag_access,
     {"access", "qnet6.kif.msgsend.msg.openfd.ioflag.access",
      FT_UINT32, BASE_DEC, VALS(qnet6_kif_msgsend_msg_connect_ioflag_vals), 03,
      "access mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_append,
     {"append", "qnet6.kif.msgsend.msg.openfd.ioflag.append",
      FT_BOOLEAN, 32, NULL, 010,
      "append mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_dsync,
     {"dsync", "qnet6.kif.msgsend.msg.openfd.ioflag.dsync",
      FT_BOOLEAN, 32, NULL, 020,
      "data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_sync,
     {"sync", "qnet6.kif.msgsend.msg.openfd.ioflag.sync",
      FT_BOOLEAN, 32, NULL, 040,
      "file sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_rsync,
     {"rsync", "qnet6.kif.msgsend.msg.openfd.ioflag.rsync",
      FT_BOOLEAN, 32, NULL, 0100,
      "alias for data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_nonblock,
     {"nonblock", "qnet6.kif.msgsend.msg.openfd.ioflag.nonblock",
      FT_BOOLEAN, 32, NULL, 0200,
      "alias for data sync mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_creat,
     {"creat", "qnet6.kif.msgsend.msg.openfd.ioflag.creat",
      FT_BOOLEAN, 32, NULL, 0400,
      "creat mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_truncate,
     {"truncate", "qnet6.kif.msgsend.msg.openfd.ioflag.truncate",
      FT_BOOLEAN, 32, NULL, 01000,
      "truncate mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_exclusive,
     {"exclusive", "qnet6.kif.msgsend.msg.openfd.ioflag.exclusive",
      FT_BOOLEAN, 32, NULL, 02000,
      "exclusive mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_noctrltty,
     {"noctrltty", "qnet6.kif.msgsend.msg.openfd.ioflag.noctrltty",
      FT_BOOLEAN, 32, NULL, 04000,
      "noctrltty mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_closexec,
     {"closexec", "qnet6.kif.msgsend.msg.openfd.ioflag.closexec",
      FT_BOOLEAN, 32, NULL, 010000,
      "closexec mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_realids,
     {"realids", "qnet6.kif.msgsend.msg.openfd.ioflag.realids",
      FT_BOOLEAN, 32, NULL, 020000,
      "realids mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_largefile,
     {"largefile", "qnet6.kif.msgsend.msg.openfd.ioflag.largefile",
      FT_BOOLEAN, 32, NULL, 0100000,
      "largefile mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_ioflag_async,
     {"async", "qnet6.kif.msgsend.msg.openfd.ioflag.async",
      FT_BOOLEAN, 32, NULL, 0200000,
      "async mode", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_sflag,
     {"Sflag", "qnet6.kif.msgsend.msg.openfd.sflag",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_connect_sflag_vals), 0,
      NULL, HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_xtype,
     {"Xtype", "qnet6.kif.msgsend.msg.openfd.xtype",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_msgsend_msg_openfd_xtypes_vals), 0,
      "openfd xtype", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_reserved,
     {"Reserved", "qnet6.kif.msgsend.msg.openfd.reserved",
      FT_UINT32, BASE_HEX, NULL, 0,
      "openfd reserved fields", HFILL}
    },
    {&hf_qnet6_kif_msg_openfd_key,
     {"Key", "qnet6.kif.msgsend.msg.openfd.key",
      FT_UINT32, BASE_HEX, NULL, 0,
      "openfd key", HFILL}
    },
    /* mmap */
    {&hf_qnet6_kif_msg_io_mmap_prot,
     {"Prot", "qnet6.kif.msgsend.msg.mmap.prot",
      FT_UINT32, BASE_HEX, NULL, 0,
      "protection field of mmap", HFILL}
    },
    {&hf_qnet6_kif_msg_io_mmap_prot_read,
     {"Read", "qnet6.kif.msgsend.msg.mmap.prot.read",
      FT_BOOLEAN, 32, NULL, 0x100,
      "protection field of mmap", HFILL}
    },
    {&hf_qnet6_kif_msg_io_mmap_prot_write,
     {"Write", "qnet6.kif.msgsend.msg.mmap.prot.write",
      FT_BOOLEAN, 32, NULL, 0x200,
      "protection field of mmap", HFILL}
    },
    {&hf_qnet6_kif_msg_io_mmap_prot_exec,
     {"Exec", "qnet6.kif.msgsend.msg.mmap.prot.exec",
      FT_BOOLEAN, 32, NULL, 0x400,
      "protection field of mmap", HFILL}
    },
    {&hf_qnet6_kif_msg_io_mmap_offset,
     {"Offset", "qnet6.kif.msgsend.msg.mmap.offset",
      FT_UINT64, BASE_HEX, NULL, 0,
      "offset of object", HFILL}
    },
    /* notify */
    {&hf_qnet6_kif_msg_io_notify_action,
     {"Action", "qnet6.kif.msgsend.msg.notify.action",
      FT_UINT32, BASE_HEX, VALS(qnet6_kif_msgsend_msg_io_notify_action_vals), 0,
      "action of notify", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags,
     {"Action", "qnet6.kif.msgsend.msg.notify.action",
      FT_UINT32, BASE_HEX, NULL, 0,
      "flags of notify", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags_31,
     {"Exten", "qnet6.kif.msgsend.msg.notify.flags.exten",
      FT_BOOLEAN, 32, NULL, 0x80000000,
      "exten flag of notify", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags_30,
     {"Oband", "qnet6.kif.msgsend.msg.notify.flags.oband",
      FT_BOOLEAN, 32, NULL, 0x40000000,
      "outband flag of notify", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags_29,
     {"Output", "qnet6.kif.msgsend.msg.notify.flags.output",
      FT_BOOLEAN, 32, NULL, 0x20000000,
      "output flag of notify", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags_28,
     {"Input", "qnet6.kif.msgsend.msg.notify.flags.input",
      FT_BOOLEAN, 32, NULL, 0x10000000,
      "input flag of notify", HFILL}
    },

    {&hf_qnet6_kif_msg_io_notify_mgr,
     {"Manager", "qnet6.kif.msgsend.msg.notify.mgr",
      FT_UINT64, BASE_HEX, NULL, 0,
      "managers of notify", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags_extra_mask,
     {"FlagsExtraMask", "qnet6.kif.msgsend.msg.notify.flags_extra_mask",
      FT_UINT32, BASE_HEX, NULL, 0,
      "extra mask of flags", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_flags_exten,
     {"FlagsExten", "qnet6.kif.msgsend.msg.notify.flags_exten",
      FT_UINT32, BASE_HEX, NULL, 0,
      "glags exten", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_nfds,
     {"Nfds", "qnet6.kif.msgsend.msg.notify.nfds",
      FT_UINT32, BASE_HEX, NULL, 0,
      "number of fds", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_fd_first,
     {"Firstfd", "qnet6.kif.msgsend.msg.notify.fd_first",
      FT_UINT32, BASE_HEX, NULL, 0,
      "first fd in nfds array", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_nfds_ready,
     {"Ready", "qnet6.kif.msgsend.msg.notify.nfds_ready",
      FT_UINT32, BASE_HEX, NULL, 0,
      "number of ready fds", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_timo,
     {"Timeout", "qnet6.kif.msgsend.msg.notify.timeo",
      FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
      "notify timeout", HFILL}
    },
    {&hf_qnet6_kif_msg_io_notify_fds,
     {"FDS", "qnet6.kif.msgsend.msg.notify.fds",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL}
    },

    /* iomsg*/
    {&hf_qnet6_kif_msg_io_msg_mgrid,
     {"Mgrid", "qnet6.kif.msgsend.msg.iomsg.mgrid",
      FT_UINT16, BASE_HEX, VALS(qnet6_kif_mgr_types_vals), 0,
      "manager id", HFILL}
    },
    {&hf_qnet6_kif_msg_io_msg_subtype,
     {"subtype", "qnet6.kif.msgsend.msg.iomsg.subtype",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL}
    },
    /* dup */
    {&hf_qnet6_kif_msg_io_dup_reserved,
     {"Reserved", "qnet6.kif.msgsend.msg.dup.reserved",
      FT_UINT32, BASE_HEX, NULL, 0,
      "dup message reserved fields", HFILL}
    },
    {&hf_qnet6_kif_msg_io_dup_key,
     {"Key", "qnet6.kif.msgsend.msg.dup.key",
      FT_UINT32, BASE_HEX, NULL, 0,
      "dup message key", HFILL}
    },

    /* _client_info */
    {&hf_qnet6_kif_client_info,
     {"Client_info", "qnet6.kif.client_info",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "client information", HFILL}
    },
    {&hf_qnet6_kif_zero,
     {"Zero", "qnet6.kif.zero",
      FT_BYTES, BASE_NONE, NULL, 0,
      "All bytes should be zero", HFILL}
    },
    {&hf_qnet6_kif_client_info_nd,
     {"Nd", "qnet6.kif.client_info.nd",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "node id", HFILL}
    },
    {&hf_qnet6_kif_client_info_pid,
     {"Pid", "qnet6.kif.client_info.pid",
      FT_INT32, BASE_DEC, NULL, 0,
      "process id", HFILL}
    },
    {&hf_qnet6_kif_client_info_sid,
     {"Sid", "qnet6.kif.client_info.sid",
      FT_INT32, BASE_DEC, NULL, 0,
      "server connection id", HFILL}
    },
    {&hf_qnet6_kif_client_info_flags,
     {"Flags", "qnet6.kif.client_info.flags",
      FT_UINT32, BASE_HEX, NULL, 0,
      "connection flags", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred,
     {"Cred", "qnet6.kif.client_info.cred",
      FT_STRINGZ, BASE_NONE, NULL, 0,
      "client credential information", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_ruid,
     {"Ruid", "qnet6.kif.client_info.cred.ruid",
      FT_INT32, BASE_DEC, NULL, 0,
      "client real uid", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_euid,
     {"Euid", "qnet6.kif.client_info.cred.euid",
      FT_INT32, BASE_DEC, NULL, 0,
      "client effective uid", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_suid,
     {"Suid", "qnet6.kif.client_info.cred.suid",
      FT_INT32, BASE_DEC, NULL, 0,
      "client saved uid", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_rgid,
     {"Rgid", "qnet6.kif.client_info.cred.rgid",
      FT_INT32, BASE_DEC, NULL, 0,
      "client real gid", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_egid,
     {"Egid", "qnet6.kif.client_info.cred.egid",
      FT_INT32, BASE_DEC, NULL, 0,
      "client effective gid", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_sgid,
     {"Sgid", "qnet6.kif.client_info.cred.sgid",
      FT_INT32, BASE_DEC, NULL, 0,
      "client saved gid", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_ngroups,
     {"Ngroups", "qnet6.kif.client_info.cred.ngroups",
      FT_UINT32, BASE_DEC_HEX, NULL, 0,
      "number of groups client belongs to", HFILL}
    },
    {&hf_qnet6_kif_client_info_cred_grouplist,
     {"Grouplist", "qnet6.kif.client_info.cred.grouplist",
      FT_UINT32, BASE_DEC, NULL, 0,
      "groups client belongs to", HFILL}
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_qnet6_l4,
    &ett_qnet6_flags,
    &ett_qnet6_qos_info
  };
  static gint *ett_lr[] = {
    &ett_qnet6_lr,
    &ett_qnet6_lr_src,
    &ett_qnet6_lr_src_name_subtree,
    &ett_qnet6_lr_src_domain_subtree,
    &ett_qnet6_lr_src_addr_subtree,
    &ett_qnet6_lr_dst,
    &ett_qnet6_lr_dst_name_subtree,
    &ett_qnet6_lr_dst_domain_subtree,
    &ett_qnet6_lr_dst_addr_subtree
  };

  static gint *ett_kif[] = {
    &ett_qnet6_kif,
    &ett_qnet6_kif_vinfo,
    &ett_qnet6_kif_pulse,
    &ett_qnet6_kif_event,
    &ett_qnet6_kif_msg,
    &ett_qnet6_kif_msg_ioflag,
    &ett_qnet6_kif_msg_mode,
    &ett_qnet6_kif_msg_eflag,
    &ett_qnet6_kif_connect,
    &ett_qnet6_kif_msgsend,
    &ett_qnet6_kif_client_info,
    &ett_qnet6_kif_client_info_cred,
    &ett_qnet6_kif_client_info_cred_group,
    &ett_qnet6_kif_msg_devctl_dcmd,
    &ett_qnet6_kif_msg_read_xtypes,
    &ett_qnet6_kif_msg_write_xtypes,
    &ett_qnet6_kif_chmod_mode,
    &ett_qnet6_kif_msg_sync,
    &ett_qnet6_kif_msg_msginfo,
    &ett_qnet6_kif_msg_openfd_ioflag,
    &ett_qnet6_kif_msg_prot,
    &ett_qnet6_kif_msg_notify_flags,
    &ett_qnet6_kif_msg_notify_fds
  };
  static gint *ett_nr[] = {
    &ett_qnet6_nr
  };
  static gint *ett_qos[] = {
    &ett_qnet6_qos
  };
  module_t *qnet6_module;

  /* Register the protocol name and description */
  proto_qnet6_l4 = proto_register_protocol("QNX6 QNET LWL4 protocol", "LWL4", "lwl4");

  proto_qnet6_qos = proto_register_protocol("QNX6 QNET QOS protocol", "QOS", "qos");

  proto_qnet6_lr = proto_register_protocol("QNX6 QNET LR protocol", "LR", "lr");

  proto_qnet6_kif = proto_register_protocol("QNX6 QNET KIF protocol", "KIF", "kif");

  proto_qnet6_nr =  proto_register_protocol("QNX6 QNET Network Resolver protocol", "NR", "nr");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_qnet6_l4, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  proto_register_field_array(proto_qnet6_qos, hf_qos, array_length(hf_qos));
  proto_register_subtree_array(ett_qos, array_length(ett_qos));

  proto_register_field_array(proto_qnet6_lr, hf_lr, array_length(hf_lr));
  proto_register_subtree_array(ett_lr, array_length(ett_lr));

  proto_register_field_array(proto_qnet6_kif, hf_kif, array_length(hf_kif));
  proto_register_subtree_array(ett_kif, array_length(ett_kif));

  proto_register_field_array(proto_qnet6_nr, hf_nr, array_length(hf_nr));
  proto_register_subtree_array(ett_nr, array_length(ett_nr));

  qnet6_module = prefs_register_protocol(proto_qnet6_l4, NULL);
  prefs_register_bool_preference(qnet6_module, "check_crc",
                                  "Validate the LWL4 crc even crc bit is not set",
                                  "Whether to validate the LWL4 crc when crc bit is not set",
                                  &qnet6_lwl4_check_crc);

}


void
proto_reg_handoff_qnet6(void)
{
  dissector_handle_t qnet6_handle;

  qnet6_handle = create_dissector_handle(dissect_qnet6, proto_qnet6_l4);
  dissector_add_uint("ethertype", ETHERTYPE_QNX_QNET6, qnet6_handle);
  dissector_add_uint("ip.proto", IP_PROTO_QNX, qnet6_handle);
}


/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
