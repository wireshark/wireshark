/* packet-ff.c
 * Routines for FF-HSE packet disassembly
 *
 * FF-588-1.3: HSE Field Device Access Agent
 * 6. Field Device Access Agent Interface
 *
 * (c) Copyright 2008, Yukiyo Akisada <Yukiyo.Akisada@jp.yokogawa.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * /etc/services
 * ---------------------------------------------------------------------
 * ff-annunc	1089/tcp	# FF Annunciation
 * ff-annunc	1089/udp	# FF Annunciation
 * ff-fms		1090/tcp	# FF Fieldbus Message Specification
 * ff-fms		1090/udp	# FF Fieldbus Message Specification
 * ff-sm		1091/tcp	# FF System Management
 * ff-sm		1091/udp	# FF System Management
 * ff-lr-port	3622/tcp	# FF LAN Redundancy Port
 * ff-lr-port	3622/udp	# FF LAN Redundancy Port
 * ---------------------------------------------------------------------
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include "packet-ff.h"
#include "packet-tcp.h"



static int proto_ff	= -1;
static gint ett_ff	= -1;

static gboolean ff_desegment	= TRUE;	/* desegmentation of FF over TCP */

static dissector_handle_t ff_udp_handle;
static dissector_handle_t ff_tcp_handle;



/*
 * 6.3. Message Header
 */
static int hf_ff_fda_msg_hdr	= -1;

static int hf_ff_fda_msg_hdr_ver	= -1;
static int hf_ff_fda_msg_hdr_fda_addr	= -1;
static int hf_ff_fda_msg_hdr_len	= -1;

static gint ett_ff_fda_msg_hdr	= -1;
static gint ett_ff_fda_msg_hdr_proto_and_type	= -1;
static gint ett_ff_fda_msg_hdr_opts	= -1;
static gint ett_ff_fda_msg_hdr_srv	= -1;



/*
 * 6.4. Message Trailer
 */
static int hf_ff_fda_msg_trailer	= -1;

static int hf_ff_fda_msg_trailer_msg_num	= -1;
static int hf_ff_fda_msg_trailer_invoke_id	= -1;
static int hf_ff_fda_msg_trailer_time_stamp	= -1;
static int hf_ff_fda_msg_trailer_extended_control_field	= -1;

static gint ett_ff_fda_msg_trailer	= -1;



/*
 * 6.5.1 FDA Session Management Services
 */
static int hf_ff_fda	= -1;



/*
 * 6.5.1.1. FDA Open Session (Confirmed Service Id = 1)
 */
static int hf_ff_fda_open_sess	= -1;

static int hf_ff_fda_open_sess_req	= -1;
static int hf_ff_fda_open_sess_req_sess_idx	= -1;
static int hf_ff_fda_open_sess_req_max_buf_siz	= -1;
static int hf_ff_fda_open_sess_req_max_msg_len	= -1;
static int hf_ff_fda_open_sess_req_reserved	= -1;
static int hf_ff_fda_open_sess_req_nma_conf_use	= -1;
static int hf_ff_fda_open_sess_req_inactivity_close_time	= -1;
static int hf_ff_fda_open_sess_req_transmit_delay_time	= -1;
static int hf_ff_fda_open_sess_req_pd_tag	= -1;

static int hf_ff_fda_open_sess_rsp	= -1;
static int hf_ff_fda_open_sess_rsp_sess_idx	= -1;
static int hf_ff_fda_open_sess_rsp_max_buf_siz	= -1;
static int hf_ff_fda_open_sess_rsp_max_msg_len	= -1;
static int hf_ff_fda_open_sess_rsp_reserved	= -1;
static int hf_ff_fda_open_sess_rsp_nma_conf_use	= -1;
static int hf_ff_fda_open_sess_rsp_inactivity_close_time	= -1;
static int hf_ff_fda_open_sess_rsp_transmit_delay_time	= -1;
static int hf_ff_fda_open_sess_rsp_pd_tag	= -1;

static int hf_ff_fda_open_sess_err	= -1;
static int hf_ff_fda_open_sess_err_err_class	= -1;
static int hf_ff_fda_open_sess_err_err_code	= -1;
static int hf_ff_fda_open_sess_err_additional_code	= -1;
static int hf_ff_fda_open_sess_err_additional_desc	= -1;

static gint ett_ff_fda_open_sess_req	= -1;
static gint ett_ff_fda_open_sess_rsp	= -1;
static gint ett_ff_fda_open_sess_err	= -1;



/*
 * 6.5.1.2. FDA Idle (Confirmed Service Id = 3)
 */
static int hf_ff_fda_idle	= -1;

static int hf_ff_fda_idle_req	= -1;

static int hf_ff_fda_idle_rsp	= -1;

static int hf_ff_fda_idle_err	= -1;
static int hf_ff_fda_idle_err_err_class	= -1;
static int hf_ff_fda_idle_err_err_code	= -1;
static int hf_ff_fda_idle_err_additional_code	= -1;
static int hf_ff_fda_idle_err_additional_desc	= -1;

static gint ett_ff_fda_idle_req	= -1;
static gint ett_ff_fda_idle_rsp	= -1;
static gint ett_ff_fda_idle_err	= -1;



/*
 * 6.5.2. SM Services
 */
static int hf_ff_sm	= -1;



/*
 * 6.5.2.1. SM Find Tag Query (Unconfirmed Service Id = 1)
 */
static int hf_ff_sm_find_tag_query	= -1;

static int hf_ff_sm_find_tag_query_req	= -1;
static int hf_ff_sm_find_tag_query_req_query_type	= -1;
static int hf_ff_sm_find_tag_query_req_idx	= -1;
static int hf_ff_sm_find_tag_query_req_tag	= -1;
static int hf_ff_sm_find_tag_query_req_vfd_tag	= -1;

static gint ett_ff_sm_find_tag_query_req	= -1;



/*
 * 6.5.2.2. SM Find Tag Reply (Unconfirmed Service Id = 2)
 */
static int hf_ff_sm_find_tag_reply	= -1;

static int hf_ff_sm_find_tag_reply_req	= -1;
static int hf_ff_sm_find_tag_reply_req_query_type	= -1;
static int hf_ff_sm_find_tag_reply_req_h1_node_addr	= -1;
static int hf_ff_sm_find_tag_reply_req_fda_addr_link_id	= -1;
static int hf_ff_sm_find_tag_reply_req_vfd_ref	= -1;
static int hf_ff_sm_find_tag_reply_req_od_idx	= -1;
static int hf_ff_sm_find_tag_reply_req_ip_addr	= -1;
static int hf_ff_sm_find_tag_reply_req_od_ver	= -1;
static int hf_ff_sm_find_tag_reply_req_dev_id	= -1;
static int hf_ff_sm_find_tag_reply_req_pd_tag	= -1;
static int hf_ff_sm_find_tag_reply_req_reserved	= -1;
static int hf_ff_sm_find_tag_reply_req_num_of_fda_addr_selectors	= -1;
static int hf_ff_sm_find_tag_reply_req_fda_addr_selector	= -1;

static gint ett_ff_sm_find_tag_reply_req	= -1;
static gint ett_ff_sm_find_tag_reply_req_dup_detection_state	= -1;
static gint ett_ff_sm_find_tag_reply_req_list_of_fda_addr_selectors	= -1;



/*
 * 6.5.2.3. SM Identify (Confirmed Service Id = 3)
 */
static int hf_ff_sm_id	= -1;

static int hf_ff_sm_id_req	= -1;

static int hf_ff_sm_id_rsp	= -1;
static int hf_ff_sm_id_rsp_dev_idx	= -1;
static int hf_ff_sm_id_rsp_max_dev_idx	= -1;
static int hf_ff_sm_id_rsp_operational_ip_addr	= -1;
static int hf_ff_sm_id_rsp_dev_id	= -1;
static int hf_ff_sm_id_rsp_pd_tag	= -1;
static int hf_ff_sm_id_rsp_hse_repeat_time	= -1;
static int hf_ff_sm_id_rsp_lr_port	= -1;
static int hf_ff_sm_id_rsp_reserved	= -1;
static int hf_ff_sm_id_rsp_annunc_ver_num	= -1;
static int hf_ff_sm_id_rsp_hse_dev_ver_num	= -1;
static int hf_ff_sm_id_rsp_num_of_entries	= -1;
static int hf_ff_sm_id_rsp_h1_live_list_h1_link_id	= -1;
static int hf_ff_sm_id_rsp_h1_live_list_reserved	= -1;
static int hf_ff_sm_id_rsp_h1_live_list_ver_num	= -1;
static int hf_ff_sm_id_rsp_h1_node_addr_ver_num_h1_node_addr	= -1;
static int hf_ff_sm_id_rsp_h1_node_addr_ver_num_ver_num	= -1;

static int hf_ff_sm_id_err	= -1;
static int hf_ff_sm_id_err_err_class	= -1;
static int hf_ff_sm_id_err_err_code	= -1;
static int hf_ff_sm_id_err_additional_code	= -1;
static int hf_ff_sm_id_err_additional_desc	= -1;

static gint ett_ff_sm_id_req	= -1;
static gint ett_ff_sm_id_rsp	= -1;
static gint ett_ff_sm_id_rsp_smk_state	= -1;
static gint ett_ff_sm_id_rsp_dev_type	= -1;
static gint ett_ff_sm_id_rsp_dev_redundancy_state	= -1;
static gint ett_ff_sm_id_rsp_dup_detection_state	= -1;
static gint ett_ff_sm_id_rsp_entries_h1_live_list	= -1;
static gint ett_ff_sm_id_rsp_h1_live_list	= -1;
static gint ett_ff_sm_id_rsp_entries_node_addr	= -1;
static gint ett_ff_sm_id_rsp_h1_node_addr	= -1;
static gint ett_ff_sm_id_err	= -1;



/*
 * 6.5.2.4. SM Clear Address (Confirmed Service Id = 12)
 */
static int hf_ff_sm_clear_addr	= -1;

static int hf_ff_sm_clear_addr_req	= -1;
static int hf_ff_sm_clear_addr_req_dev_id	= -1;
static int hf_ff_sm_clear_addr_req_pd_tag	= -1;
static int hf_ff_sm_clear_addr_req_interface_to_clear	= -1;

static int hf_ff_sm_clear_addr_rsp	= -1;

static int hf_ff_sm_clear_addr_err	= -1;
static int hf_ff_sm_clear_addr_err_err_class	= -1;
static int hf_ff_sm_clear_addr_err_err_code	= -1;
static int hf_ff_sm_clear_addr_err_additional_code	= -1;
static int hf_ff_sm_clear_addr_err_additional_desc	= -1;

static gint ett_ff_sm_clear_addr_req	= -1;
static gint ett_ff_sm_clear_addr_rsp	= -1;
static gint ett_ff_sm_clear_addr_err	= -1;



/*
 * 6.5.2.5. SM Set Assignment Info (Confirmed Service Id = 14)
 */
static int hf_ff_sm_set_assign_info	= -1;

static int hf_ff_sm_set_assign_info_req	= -1;
static int hf_ff_sm_set_assign_info_req_dev_id	= -1;
static int hf_ff_sm_set_assign_info_req_pd_tag	= -1;
static int hf_ff_sm_set_assign_info_req_h1_new_addr	= -1;
static int hf_ff_sm_set_assign_info_req_lr_port	= -1;
static int hf_ff_sm_set_assign_info_req_hse_repeat_time	= -1;
static int hf_ff_sm_set_assign_info_req_dev_idx	= -1;
static int hf_ff_sm_set_assign_info_req_max_dev_idx	= -1;
static int hf_ff_sm_set_assign_info_req_operational_ip_addr	= -1;

static int hf_ff_sm_set_assign_info_rsp	= -1;
static int hf_ff_sm_set_assign_info_rsp_reserved	= -1;
static int hf_ff_sm_set_assign_info_rsp_max_dev_idx	= -1;
static int hf_ff_sm_set_assign_info_rsp_hse_repeat_time	= -1;

static int hf_ff_sm_set_assign_info_err	= -1;
static int hf_ff_sm_set_assign_info_err_err_class	= -1;
static int hf_ff_sm_set_assign_info_err_err_code	= -1;
static int hf_ff_sm_set_assign_info_err_additional_code	= -1;
static int hf_ff_sm_set_assign_info_err_additional_desc	= -1;

static gint ett_ff_sm_set_assign_info_req	= -1;
static gint ett_ff_sm_set_assign_info_req_dev_redundancy_state	= -1;
static gint ett_ff_sm_set_assign_info_req_clear_dup_detection_state	= -1;
static gint ett_ff_sm_set_assign_info_rsp	= -1;
static gint ett_ff_sm_set_assign_info_err	= -1;



/*
 * 6.5.2.6. SM Clear Assignment Info (Confirmed Service Id = 15)
 */
static int hf_ff_sm_clear_assign_info	= -1;

static int hf_ff_sm_clear_assign_info_req	= -1;
static int hf_ff_sm_clear_assign_info_req_dev_id	= -1;
static int hf_ff_sm_clear_assign_info_req_pd_tag	= -1;

static int hf_ff_sm_clear_assign_info_rsp	= -1;

static int hf_ff_sm_clear_assign_info_err	= -1;
static int hf_ff_sm_clear_assign_info_err_err_class	= -1;
static int hf_ff_sm_clear_assign_info_err_err_code	= -1;
static int hf_ff_sm_clear_assign_info_err_additional_code	= -1;
static int hf_ff_sm_clear_assign_info_err_additional_desc	= -1;

static gint ett_ff_sm_clear_assign_info_req	= -1;
static gint ett_ff_sm_clear_assign_info_rsp	= -1;
static gint ett_ff_sm_clear_assign_info_err	= -1;



/*
 * 6.5.2.7. SM Device Annunciation (Unconfirmed Service Id = 16)
 */
static int hf_ff_sm_dev_annunc	= -1;

static int hf_ff_sm_dev_annunc_req	= -1;
static int hf_ff_sm_dev_annunc_req_dev_idx	= -1;
static int hf_ff_sm_dev_annunc_req_max_dev_idx	= -1;
static int hf_ff_sm_dev_annunc_req_operational_ip_addr	= -1;
static int hf_ff_sm_dev_annunc_req_dev_id	= -1;
static int hf_ff_sm_dev_annunc_req_pd_tag	= -1;
static int hf_ff_sm_dev_annunc_req_hse_repeat_time	= -1;
static int hf_ff_sm_dev_annunc_req_lr_port	= -1;
static int hf_ff_sm_dev_annunc_req_reserved	= -1;
static int hf_ff_sm_dev_annunc_req_annunc_ver_num	= -1;
static int hf_ff_sm_dev_annunc_req_hse_dev_ver_num	= -1;
static int hf_ff_sm_dev_annunc_req_num_of_entries	= -1;
static int hf_ff_sm_dev_annunc_req_h1_live_list_h1_link_id	= -1;
static int hf_ff_sm_dev_annunc_req_h1_live_list_reserved	= -1;
static int hf_ff_sm_dev_annunc_req_h1_live_list_ver_num	= -1;
static int hf_ff_sm_dev_annunc_req_h1_node_addr_ver_num_h1_node_addr	= -1;
static int hf_ff_sm_dev_annunc_req_h1_node_addr_ver_num_ver_num	= -1;

static gint ett_ff_sm_dev_annunc_req	= -1;
static gint ett_ff_sm_dev_annunc_req_smk_state	= -1;
static gint ett_ff_sm_dev_annunc_req_dev_type	= -1;
static gint ett_ff_sm_dev_annunc_req_dev_redundancy_state	= -1;
static gint ett_ff_sm_dev_annunc_req_dup_detection_state	= -1;
static gint ett_ff_sm_dev_annunc_req_entries_h1_live_list	= -1;
static gint ett_ff_sm_dev_annunc_req_h1_live_list	= -1;
static gint ett_ff_sm_dev_annunc_req_entries_node_addr	= -1;
static gint ett_ff_sm_dev_annunc_req_h1_node_addr	= -1;



/*
 * 6.5.3. FMS Services
 */
static int hf_ff_fms	= -1;



/*
 * 6.5.3.2. FMS Initiate (Confirmed Service Id = 96)
 */
static int hf_ff_fms_init	= -1;

static int hf_ff_fms_init_req	= -1;
static int hf_ff_fms_init_req_conn_opt	= -1;
static int hf_ff_fms_init_req_access_protection_supported_calling	= -1;
static int hf_ff_fms_init_req_passwd_and_access_grps_calling	= -1;
static int hf_ff_fms_init_req_ver_od_calling	= -1;
static int hf_ff_fms_init_req_prof_num_calling	= -1;
static int hf_ff_fms_init_req_pd_tag	= -1;

static int hf_ff_fms_init_rsp	= -1;
static int hf_ff_fms_init_rsp_ver_od_called	= -1;
static int hf_ff_fms_init_rsp_prof_num_called	= -1;

static int hf_ff_fms_init_err	= -1;
static int hf_ff_fms_init_err_err_class	= -1;
static int hf_ff_fms_init_err_err_code	= -1;
static int hf_ff_fms_init_err_additional_code	= -1;
static int hf_ff_fms_init_err_additional_desc	= -1;

static gint ett_ff_fms_init_req	= -1;
static gint ett_ff_fms_init_rep	= -1;
static gint ett_ff_fms_init_err	= -1;



/*
 * 6.5.3.3. FMS Abort (Unconfirmed Service Id = 112)
 */
static int hf_ff_fms_abort	= -1;

static int hf_ff_fms_abort_req	= -1;
static int hf_ff_fms_abort_req_abort_id	= -1;
static int hf_ff_fms_abort_req_reason_code	= -1;
static int hf_ff_fms_abort_req_reserved	= -1;

static gint ett_ff_fms_abort_req	= -1;



/*
 * 6.5.3.4. FMS Status (Confirmed Service Id = 0)
 */
static int hf_ff_fms_status	= -1;

static int hf_ff_fms_status_req	= -1;

static int hf_ff_fms_status_rsp	= -1;
static int hf_ff_fms_status_rsp_logical_status	= -1;
static int hf_ff_fms_status_rsp_physical_status	= -1;
static int hf_ff_fms_status_rsp_reserved	= -1;

static int hf_ff_fms_status_err	= -1;
static int hf_ff_fms_status_err_err_class	= -1;
static int hf_ff_fms_status_err_err_code	= -1;
static int hf_ff_fms_status_err_additional_code	= -1;
static int hf_ff_fms_status_err_additional_desc	= -1;

static gint ett_ff_fms_status_req	= -1;
static gint ett_ff_fms_status_rsp	= -1;
static gint ett_ff_fms_status_err	= -1;



/*
 * 6.5.3.5. FMS Unsolicited Status (Unconfirmed Service Id = 1)
 */
static int hf_ff_fms_unsolicited_status	= -1;

static int hf_ff_fms_unsolicited_status_req	= -1;
static int hf_ff_fms_unsolicited_status_req_logical_status	= -1;
static int hf_ff_fms_unsolicited_status_req_physical_status	= -1;
static int hf_ff_fms_unsolicited_status_req_reserved	= -1;

static gint ett_ff_fms_unsolicited_status_req	= -1;



/*
 * 6.5.3.6. FMS Identify (Confirmed Service Id = 1)
 */
static int hf_ff_fms_id	= -1;

static int hf_ff_fms_id_req	= -1;

static int hf_ff_fms_id_rsp	= -1;
static int hf_ff_fms_id_rsp_vendor_name	= -1;
static int hf_ff_fms_id_rsp_model_name	= -1;
static int hf_ff_fms_id_rsp_revision	= -1;

static int hf_ff_fms_id_err	= -1;
static int hf_ff_fms_id_err_err_class	= -1;
static int hf_ff_fms_id_err_err_code	= -1;
static int hf_ff_fms_id_err_additional_code	= -1;
static int hf_ff_fms_id_err_additional_desc	= -1;

static gint ett_ff_fms_id_req	= -1;
static gint ett_ff_fms_id_rsp	= -1;
static gint ett_ff_fms_id_err	= -1;



/*
 * 6.5.3.7. FMS Get OD (Confirmed Service Id = 4)
 */
static int hf_ff_fms_get_od	= -1;

static int hf_ff_fms_get_od_req	= -1;
static int hf_ff_fms_get_od_req_all_attrs	= -1;
static int hf_ff_fms_get_od_req_start_idx_flag	= -1;
static int hf_ff_fms_get_od_req_reserved	= -1;
static int hf_ff_fms_get_od_req_idx	= -1;

static int hf_ff_fms_get_od_rsp	= -1;
static int hf_ff_fms_get_od_rsp_more_follows	= -1;
static int hf_ff_fms_get_od_rsp_num_of_obj_desc	= -1;
static int hf_ff_fms_get_od_rsp_reserved	= -1;

static int hf_ff_fms_get_od_err	= -1;
static int hf_ff_fms_get_od_err_err_class	= -1;
static int hf_ff_fms_get_od_err_err_code	= -1;
static int hf_ff_fms_get_od_err_additional_code	= -1;
static int hf_ff_fms_get_od_err_additional_desc	= -1;

static gint ett_ff_fms_get_od_req	= -1;
static gint ett_ff_fms_get_od_rsp	= -1;
static gint ett_ff_fms_get_od_err	= -1;



/*
 * 6.5.3.8. FMS Initiate Put OD (Confirmed Service Id = 28)
 */
static int hf_ff_fms_init_put_od	= -1;

static int hf_ff_fms_init_put_od_req	= -1;
static int hf_ff_fms_init_put_od_req_reserved	= -1;
static int hf_ff_fms_init_put_od_req_consequence	= -1;

static int hf_ff_fms_init_put_od_rsp	= -1;

static int hf_ff_fms_init_put_od_err	= -1;
static int hf_ff_fms_init_put_od_err_err_class	= -1;
static int hf_ff_fms_init_put_od_err_err_code	= -1;
static int hf_ff_fms_init_put_od_err_additional_code	= -1;
static int hf_ff_fms_init_put_od_err_additional_desc	= -1;

static gint ett_ff_fms_init_put_od_req	= -1;
static gint ett_ff_fms_init_put_od_rsp	= -1;
static gint ett_ff_fms_init_put_od_err	= -1;



/*
 * 6.5.3.9. FMS Put OD (Confirmed Service Id = 29)
 */
static int hf_ff_fms_put_od	= -1;

static int hf_ff_fms_put_od_req	= -1;
static int hf_ff_fms_put_od_req_num_of_obj_desc	= -1;

static int hf_ff_fms_put_od_rsp	= -1;

static int hf_ff_fms_put_od_err	= -1;
static int hf_ff_fms_put_od_err_err_class	= -1;
static int hf_ff_fms_put_od_err_err_code	= -1;
static int hf_ff_fms_put_od_err_additional_code	= -1;
static int hf_ff_fms_put_od_err_additional_desc	= -1;

static gint ett_ff_fms_put_od_req	= -1;
static gint ett_ff_fms_put_od_rsp	= -1;
static gint ett_ff_fms_put_od_err	= -1;



/*
 * 6.5.3.10. FMS Terminate Put OD (Confirmed Service Id = 30)
 */
static int hf_ff_fms_terminate_put_od	= -1;

static int hf_ff_fms_terminate_put_od_req	= -1;

static int hf_ff_fms_terminate_put_od_rsp	= -1;

static int hf_ff_fms_terminate_put_od_err	= -1;
static int hf_ff_fms_terminate_put_od_err_index	= -1;
static int hf_ff_fms_terminate_put_od_err_err_class	= -1;
static int hf_ff_fms_terminate_put_od_err_err_code	= -1;
static int hf_ff_fms_terminate_put_od_err_additional_code	= -1;
static int hf_ff_fms_terminate_put_od_err_additional_desc	= -1;

static gint ett_ff_fms_terminate_put_od_req	= -1;
static gint ett_ff_fms_terminate_put_od_rsp	= -1;
static gint ett_ff_fms_terminate_put_od_err	= -1;



/*
 * 6.5.3.11. FMS Generic Initiate Download Sequence (Confirmed Service Id = 31)
 */
static int hf_ff_fms_gen_init_download_seq	= -1;

static int hf_ff_fms_gen_init_download_seq_req	= -1;
static int hf_ff_fms_gen_init_download_seq_req_idx	= -1;

static int hf_ff_fms_gen_init_download_seq_rsp	= -1;

static int hf_ff_fms_gen_init_download_seq_err	= -1;
static int hf_ff_fms_gen_init_download_seq_err_err_class	= -1;
static int hf_ff_fms_gen_init_download_seq_err_err_code	= -1;
static int hf_ff_fms_gen_init_download_seq_err_additional_code	= -1;
static int hf_ff_fms_gen_init_download_seq_err_additional_desc	= -1;

static gint ett_ff_fms_gen_init_download_seq_req	= -1;
static gint ett_ff_fms_gen_init_download_seq_rep	= -1;
static gint ett_ff_fms_gen_init_download_seq_err	= -1;



/*
 * 6.5.3.12. FMS Generic Download Segment (Confirmed Service Id = 32)
 */
static int hf_ff_fms_gen_download_seg	= -1;

static int hf_ff_fms_gen_download_seg_req	= -1;
static int hf_ff_fms_gen_download_seg_req_idx	= -1;
static int hf_ff_fms_gen_download_seg_req_more_follows	= -1;

static int hf_ff_fms_gen_download_seg_rsp	= -1;

static int hf_ff_fms_gen_download_seg_err	= -1;
static int hf_ff_fms_gen_download_seg_err_err_class	= -1;
static int hf_ff_fms_gen_download_seg_err_err_code	= -1;
static int hf_ff_fms_gen_download_seg_err_additional_code	= -1;
static int hf_ff_fms_gen_download_seg_err_additional_desc	= -1;

static gint ett_ff_fms_gen_download_seg_req	= -1;
static gint ett_ff_fms_gen_download_seg_rsp	= -1;
static gint ett_ff_fms_gen_download_seg_err	= -1;



/*
 * 6.5.3.13. FMS Generic Terminate Download Sequence (Confirmed Service Id = 33)
 */
static int hf_ff_fms_gen_terminate_download_seq	= -1;

static int hf_ff_fms_gen_terminate_download_seq_req	= -1;
static int hf_ff_fms_gen_terminate_download_seq_req_idx	= -1;

static int hf_ff_fms_gen_terminate_download_seq_rsp	= -1;
static int hf_ff_fms_gen_terminate_download_seq_rsp_final_result	= -1;

static int hf_ff_fms_gen_terminate_download_seq_err	= -1;
static int hf_ff_fms_gen_terminate_download_seq_err_err_class	= -1;
static int hf_ff_fms_gen_terminate_download_seq_err_err_code	= -1;
static int hf_ff_fms_gen_terminate_download_seq_err_additional_code	= -1;
static int hf_ff_fms_gen_terminate_download_seq_err_additional_desc	= -1;

static gint ett_ff_fms_gen_terminate_download_seq_req	= -1;
static gint ett_ff_fms_gen_terminate_download_seq_rsp	= -1;
static gint ett_ff_fms_gen_terminate_download_seq_err	= -1;



/*
 * 6.5.3.14. FMS Initiate Download Sequence (Confirmed Service Id = 9)
 */
static int hf_ff_fms_init_download_seq	= -1;

static int hf_ff_fms_init_download_seq_req	= -1;
static int hf_ff_fms_init_download_seq_req_idx	= -1;

static int hf_ff_fms_init_download_seq_rsp	= -1;

static int hf_ff_fms_init_download_seq_err	= -1;
static int hf_ff_fms_init_download_seq_err_err_class	= -1;
static int hf_ff_fms_init_download_seq_err_err_code	= -1;
static int hf_ff_fms_init_download_seq_err_additional_code	= -1;
static int hf_ff_fms_init_download_seq_err_additional_desc	= -1;

static gint ett_ff_fms_init_download_seq_req	= -1;
static gint ett_ff_fms_init_download_seq_rsp	= -1;
static gint ett_ff_fms_init_download_seq_err	= -1;



/*
 * 6.5.3.15. FMS Download Segment (Confirmed Service Id = 10)
 */
static int hf_ff_fms_download_seg	= -1;
static int hf_ff_fms_download_seg_req	= -1;
static int hf_ff_fms_download_seg_req_idx	= -1;

static int hf_ff_fms_download_seg_rsp	= -1;
static int hf_ff_fms_download_seg_rsp_more_follows	= -1;

static int hf_ff_fms_download_seg_err	= -1;
static int hf_ff_fms_download_seg_err_err_class	= -1;
static int hf_ff_fms_download_seg_err_err_code	= -1;
static int hf_ff_fms_download_seg_err_additional_code	= -1;
static int hf_ff_fms_download_seg_err_additional_desc	= -1;

static gint ett_ff_fms_download_seg_req	= -1;
static gint ett_ff_fms_download_seg_rsp	= -1;
static gint ett_ff_fms_download_seg_err	= -1;



/*
 * 6.5.3.16. FMS Terminate Download Sequence (Confirmed Service Id = 11)
 */
static int hf_ff_fms_terminate_download_seq	= -1;

static int hf_ff_fms_terminate_download_seq_req	= -1;
static int hf_ff_fms_terminate_download_seq_req_idx	= -1;
static int hf_ff_fms_terminate_download_seq_req_final_result	= -1;

static int hf_ff_fms_terminate_download_seq_rsp	= -1;

static int hf_ff_fms_terminate_download_seq_err	= -1;
static int hf_ff_fms_terminate_download_seq_err_err_class	= -1;
static int hf_ff_fms_terminate_download_seq_err_err_code	= -1;
static int hf_ff_fms_terminate_download_seq_err_additional_code	= -1;
static int hf_ff_fms_terminate_download_seq_err_additional_desc	= -1;

static gint ett_ff_fms_terminate_download_seq_req	= -1;
static gint ett_ff_fms_terminate_download_seq_rsp	= -1;
static gint ett_ff_fms_terminate_download_seq_err	= -1;



/*
 * 6.5.3.17. FMS Initiate Upload Sequence (Confirmed Service Id = 12)
 */
static int hf_ff_fms_init_upload_seq	= -1;

static int hf_ff_fms_init_upload_seq_req	= -1;
static int hf_ff_fms_init_upload_seq_req_idx	= -1;

static int hf_ff_fms_init_upload_seq_rsp	= -1;

static int hf_ff_fms_init_upload_seq_err	= -1;
static int hf_ff_fms_init_upload_seq_err_err_class	= -1;
static int hf_ff_fms_init_upload_seq_err_err_code	= -1;
static int hf_ff_fms_init_upload_seq_err_additional_code	= -1;
static int hf_ff_fms_init_upload_seq_err_additional_desc	= -1;

static gint ett_ff_fms_init_upload_seq_req	= -1;
static gint ett_ff_fms_init_upload_seq_rsp	= -1;
static gint ett_ff_fms_init_upload_seq_err	= -1;



/*
 * 6.5.3.18. FMS Upload Segment (Confirmed Service Id = 13)
 */
static int hf_ff_fms_upload_seg	= -1;

static int hf_ff_fms_upload_seg_req	= -1;
static int hf_ff_fms_upload_seg_req_idx	= -1;

static int hf_ff_fms_upload_seg_rsp	= -1;
static int hf_ff_fms_upload_seg_rsp_more_follows	= -1;

static int hf_ff_fms_upload_seg_err	= -1;
static int hf_ff_fms_upload_seg_err_err_class	= -1;
static int hf_ff_fms_upload_seg_err_err_code	= -1;
static int hf_ff_fms_upload_seg_err_additional_code	= -1;
static int hf_ff_fms_upload_seg_err_additional_desc	= -1;

static gint ett_ff_fms_upload_seg_req	= -1;
static gint ett_ff_fms_upload_seg_rsp	= -1;
static gint ett_ff_fms_upload_seg_err	= -1;



/*
 * 6.5.3.19. FMS Terminate Upload Sequence (Confirmed Service Id = 14)
 */
static int hf_ff_fms_terminate_upload_seq	= -1;

static int hf_ff_fms_terminate_upload_seq_req	= -1;
static int hf_ff_fms_terminate_upload_seq_req_idx	= -1;

static int hf_ff_fms_terminate_upload_seq_rsp	= -1;

static int hf_ff_fms_terminate_upload_seq_err	= -1;
static int hf_ff_fms_terminate_upload_seq_err_err_class	= -1;
static int hf_ff_fms_terminate_upload_seq_err_err_code	= -1;
static int hf_ff_fms_terminate_upload_seq_err_additional_code	= -1;
static int hf_ff_fms_terminate_upload_seq_err_additional_desc	= -1;

static gint ett_ff_fms_terminate_upload_seq_req	= -1;
static gint ett_ff_fms_terminate_upload_seq_rsp	= -1;
static gint ett_ff_fms_terminate_upload_seq_err	= -1;



/*
 * 6.5.3.20. FMS Request Domain Download (Confirmed Service Id = 15)
 */
static int hf_ff_fms_req_dom_download	= -1;

static int hf_ff_fms_req_dom_download_req	= -1;
static int hf_ff_fms_req_dom_download_req_idx	= -1;
static int hf_ff_fms_req_dom_download_req_additional_info	= -1;

static int hf_ff_fms_req_dom_download_rsp	= -1;

static int hf_ff_fms_req_dom_download_err	= -1;
static int hf_ff_fms_req_dom_download_err_err_class	= -1;
static int hf_ff_fms_req_dom_download_err_err_code	= -1;
static int hf_ff_fms_req_dom_download_err_additional_code	= -1;
static int hf_ff_fms_req_dom_download_err_additional_desc	= -1;

static gint ett_ff_fms_req_dom_download_req	= -1;
static gint ett_ff_fms_req_dom_download_rsp	= -1;
static gint ett_ff_fms_req_dom_download_err	= -1;



/*
 * 6.5.3.21. FMS Request Domain Upload (Confirmed Service Id = 16)
 */
static int hf_ff_fms_req_dom_upload	= -1;

static int hf_ff_fms_req_dom_upload_req	= -1;
static int hf_ff_fms_req_dom_upload_req_idx	= -1;
static int hf_ff_fms_req_dom_upload_req_additional_info	= -1;

static int hf_ff_fms_req_dom_upload_rsp	= -1;

static int hf_ff_fms_req_dom_upload_err	= -1;
static int hf_ff_fms_req_dom_upload_err_err_class	= -1;
static int hf_ff_fms_req_dom_upload_err_err_code	= -1;
static int hf_ff_fms_req_dom_upload_err_additional_code	= -1;
static int hf_ff_fms_req_dom_upload_err_additional_desc	= -1;

static gint ett_ff_fms_req_dom_upload_req	= -1;
static gint ett_ff_fms_req_dom_upload_rsp	= -1;
static gint ett_ff_fms_req_dom_upload_err	= -1;



/*
 * 6.5.3.22. FMS Create Program Invocation (Confirmed Service Id = 17)
 */
static int hf_ff_fms_create_pi	= -1;

static int hf_ff_fms_create_pi_req	= -1;
static int hf_ff_fms_create_pi_req_reusable	= -1;
static int hf_ff_fms_create_pi_req_reserved	= -1;
static int hf_ff_fms_create_pi_req_num_of_dom_idxes	= -1;
static int hf_ff_fms_create_pi_req_dom_idx	= -1;

static int hf_ff_fms_create_pi_rsp	= -1;
static int hf_ff_fms_create_pi_rsp_idx	= -1;

static int hf_ff_fms_create_pi_err	= -1;
static int hf_ff_fms_create_pi_err_err_class	= -1;
static int hf_ff_fms_create_pi_err_err_code	= -1;
static int hf_ff_fms_create_pi_err_additional_code	= -1;
static int hf_ff_fms_create_pi_err_additional_desc	= -1;

static gint ett_ff_fms_create_pi_req	= -1;
static gint ett_ff_fms_create_pi_req_list_of_dom_idxes	= -1;
static gint ett_ff_fms_create_pi_rsp	= -1;
static gint ett_ff_fms_create_pi_err	= -1;



/*
 * 6.5.3.23. FMS Delete Program Invocation (Confirmed Service Id = 18)
 */
static int hf_ff_fms_del_pi	= -1;
static int hf_ff_fms_del_pi_req	= -1;
static int hf_ff_fms_del_pi_req_idx	= -1;

static int hf_ff_fms_del_pi_rsp	= -1;

static int hf_ff_fms_del_pi_err	= -1;
static int hf_ff_fms_del_pi_err_err_class	= -1;
static int hf_ff_fms_del_pi_err_err_code	= -1;
static int hf_ff_fms_del_pi_err_additional_code	= -1;
static int hf_ff_fms_del_pi_err_additional_desc	= -1;

static gint ett_ff_fms_del_pi_req	= -1;
static gint ett_ff_fms_del_pi_rsp	= -1;
static gint ett_ff_fms_del_pi_err	= -1;



/*
 * 6.5.3.24. FMS Start (Confirmed Service Id = 19)
 */
static int hf_ff_fms_start	= -1;
static int hf_ff_fms_start_req	= -1;
static int hf_ff_fms_start_req_idx	= -1;

static int hf_ff_fms_start_rsp	= -1;

static int hf_ff_fms_start_err	= -1;
static int hf_ff_fms_start_err_pi_state	= -1;
static int hf_ff_fms_start_err_err_class	= -1;
static int hf_ff_fms_start_err_err_code	= -1;
static int hf_ff_fms_start_err_additional_code	= -1;
static int hf_ff_fms_start_err_additional_desc	= -1;

static gint ett_ff_fms_start_req	= -1;
static gint ett_ff_fms_start_rsp	= -1;
static gint ett_ff_fms_start_err	= -1;



/*
 * 6.5.3.25. FMS Stop (Confirmed Service Id = 20)
 */
static int hf_ff_fms_stop	= -1;

static int hf_ff_fms_stop_req	= -1;
static int hf_ff_fms_stop_req_idx	= -1;

static int hf_ff_fms_stop_rsp	= -1;

static int hf_ff_fms_stop_err	= -1;
static int hf_ff_fms_stop_err_pi_state	= -1;
static int hf_ff_fms_stop_err_err_class	= -1;
static int hf_ff_fms_stop_err_err_code	= -1;
static int hf_ff_fms_stop_err_additional_code	= -1;
static int hf_ff_fms_stop_err_additional_desc	= -1;

static gint ett_ff_fms_stop_req	= -1;
static gint ett_ff_fms_stop_rsp	= -1;
static gint ett_ff_fms_stop_err	= -1;



/*
 * 6.5.3.26. FMS Resume (Confirmed Service Id = 21)
 */
static int hf_ff_fms_resume	= -1;
static int hf_ff_fms_resume_req	= -1;
static int hf_ff_fms_resume_req_idx	= -1;

static int hf_ff_fms_resume_rsp	= -1;

static int hf_ff_fms_resume_err	= -1;
static int hf_ff_fms_resume_err_pi_state	= -1;
static int hf_ff_fms_resume_err_err_class	= -1;
static int hf_ff_fms_resume_err_err_code	= -1;
static int hf_ff_fms_resume_err_additional_code	= -1;
static int hf_ff_fms_resume_err_additional_desc	= -1;

static gint ett_ff_fms_resume_req	= -1;
static gint ett_ff_fms_resume_rsp	= -1;
static gint ett_ff_fms_resume_err	= -1;



/*
 * 6.5.3.27. FMS Reset (Confirmed Service Id = 22)
 */
static int hf_ff_fms_reset	= -1;
static int hf_ff_fms_reset_req	= -1;
static int hf_ff_fms_reset_req_idx	= -1;

static int hf_ff_fms_reset_rsp	= -1;

static int hf_ff_fms_reset_err	= -1;
static int hf_ff_fms_reset_err_pi_state	= -1;
static int hf_ff_fms_reset_err_err_class	= -1;
static int hf_ff_fms_reset_err_err_code	= -1;
static int hf_ff_fms_reset_err_additional_code	= -1;
static int hf_ff_fms_reset_err_additional_desc	= -1;

static gint ett_ff_fms_reset_req	= -1;
static gint ett_ff_fms_reset_rsp	= -1;
static gint ett_ff_fms_reset_err	= -1;



/*
 * 6.5.3.28. FMS Kill (Confirmed Service Id = 23)
 */
static int hf_ff_fms_kill	= -1;
static int hf_ff_fms_kill_req	= -1;
static int hf_ff_fms_kill_req_idx	= -1;

static int hf_ff_fms_kill_rsp	= -1;

static int hf_ff_fms_kill_err	= -1;
static int hf_ff_fms_kill_err_err_class	= -1;
static int hf_ff_fms_kill_err_err_code	= -1;
static int hf_ff_fms_kill_err_additional_code	= -1;
static int hf_ff_fms_kill_err_additional_desc	= -1;

static gint ett_ff_fms_kill_req	= -1;
static gint ett_ff_fms_kill_rsp	= -1;
static gint ett_ff_fms_kill_err	= -1;



/*
 * 6.5.3.29. FMS Read (Confirmed Service Id = 2)
 */
static int hf_ff_fms_read	= -1;

static int hf_ff_fms_read_req	= -1;
static int hf_ff_fms_read_req_idx	= -1;

static int hf_ff_fms_read_rsp	= -1;

static int hf_ff_fms_read_err	= -1;
static int hf_ff_fms_read_err_err_class	= -1;
static int hf_ff_fms_read_err_err_code	= -1;
static int hf_ff_fms_read_err_additional_code	= -1;
static int hf_ff_fms_read_err_additional_desc	= -1;

static gint ett_ff_fms_read_req	= -1;
static gint ett_ff_fms_read_rsp	= -1;
static gint ett_ff_fms_read_err	= -1;



/*
 * 6.5.3.30. FMS Read with Subindex (Confirmed Service Id = 82)
 */
static int hf_ff_fms_read_with_subidx	= -1;

static int hf_ff_fms_read_with_subidx_req	= -1;
static int hf_ff_fms_read_with_subidx_req_idx	= -1;
static int hf_ff_fms_read_with_subidx_req_subidx	= -1;

static int hf_ff_fms_read_with_subidx_rsp	= -1;

static int hf_ff_fms_read_with_subidx_err	= -1;
static int hf_ff_fms_read_with_subidx_err_err_class	= -1;
static int hf_ff_fms_read_with_subidx_err_err_code	= -1;
static int hf_ff_fms_read_with_subidx_err_additional_code	= -1;
static int hf_ff_fms_read_with_subidx_err_additional_desc	= -1;

static gint ett_ff_fms_read_with_subidx_req	= -1;
static gint ett_ff_fms_read_with_subidx_rsp	= -1;
static gint ett_ff_fms_read_with_subidx_err	= -1;



/*
 * 6.5.3.31. FMS Write (Confirmed Service Id = 3)
 */
static int hf_ff_fms_write	= -1;
static int hf_ff_fms_write_req	= -1;
static int hf_ff_fms_write_req_idx	= -1;

static int hf_ff_fms_write_rsp	= -1;

static int hf_ff_fms_write_err	= -1;
static int hf_ff_fms_write_err_err_class	= -1;
static int hf_ff_fms_write_err_err_code	= -1;
static int hf_ff_fms_write_err_additional_code	= -1;
static int hf_ff_fms_write_err_additional_desc	= -1;

static gint ett_ff_fms_write_req	= -1;
static gint ett_ff_fms_write_rsp	= -1;
static gint ett_ff_fms_write_err	= -1;



/*
 * 6.5.3.32. FMS Write with Subindex (Confirmed Service Id = 83)
 */
static int hf_ff_fms_write_with_subidx	= -1;

static int hf_ff_fms_write_with_subidx_req	= -1;
static int hf_ff_fms_write_with_subidx_req_idx	= -1;
static int hf_ff_fms_write_with_subidx_req_subidx	= -1;

static int hf_ff_fms_write_with_subidx_rsp	= -1;

static int hf_ff_fms_write_with_subidx_err	= -1;
static int hf_ff_fms_write_with_subidx_err_err_class	= -1;
static int hf_ff_fms_write_with_subidx_err_err_code	= -1;
static int hf_ff_fms_write_with_subidx_err_additional_code	= -1;
static int hf_ff_fms_write_with_subidx_err_additional_desc	= -1;

static gint ett_ff_fms_write_with_subidx_req	= -1;
static gint ett_ff_fms_write_with_subidx_rsp	= -1;
static gint ett_ff_fms_write_with_subidx_err	= -1;



/*
 * 6.5.3.33. FMS Define Variable List (Confirmed Service Id = 7)
 */
static int hf_ff_fms_def_variable_list	= -1;

static int hf_ff_fms_def_variable_list_req	= -1;
static int hf_ff_fms_def_variable_list_req_num_of_idxes	= -1;
static int hf_ff_fms_def_variable_list_req_idx	= -1;

static int hf_ff_fms_def_variable_list_rsp	= -1;
static int hf_ff_fms_def_variable_list_rsp_idx	= -1;

static int hf_ff_fms_def_variable_list_err	= -1;
static int hf_ff_fms_def_variable_list_err_err_class	= -1;
static int hf_ff_fms_def_variable_list_err_err_code	= -1;
static int hf_ff_fms_def_variable_list_err_additional_code	= -1;
static int hf_ff_fms_def_variable_list_err_additional_desc	= -1;

static gint ett_ff_fms_def_variable_list_req	= -1;
static gint ett_ff_fms_def_variable_list_req_list_of_idxes	= -1;
static gint ett_ff_fms_def_variable_list_rsp	= -1;
static gint ett_ff_fms_def_variable_list_err	= -1;



/*
 * 6.5.3.34. FMS Delete Variable List (Confirmed Service Id = 8)
 */
static int hf_ff_fms_del_variable_list	= -1;

static int hf_ff_fms_del_variable_list_req	= -1;
static int hf_ff_fms_del_variable_list_req_idx	= -1;

static int hf_ff_fms_del_variable_list_rsp	= -1;

static int hf_ff_fms_del_variable_list_err	= -1;
static int hf_ff_fms_del_variable_list_err_err_class	= -1;
static int hf_ff_fms_del_variable_list_err_err_code	= -1;
static int hf_ff_fms_del_variable_list_err_additional_code	= -1;
static int hf_ff_fms_del_variable_list_err_additional_desc	= -1;

static gint ett_ff_fms_del_variable_list_req	= -1;
static gint ett_ff_fms_del_variable_list_rsp	= -1;
static gint ett_ff_fms_del_variable_list_err	= -1;



/*
 * 6.5.3.35. FMS Information Report (Unconfirmed Service Id = 0)
 */
static int hf_ff_fms_info_report	= -1;

static int hf_ff_fms_info_report_req	= -1;
static int hf_ff_fms_info_report_req_idx	= -1;

static gint ett_ff_fms_info_report_req	= -1;



/*
 * 6.5.3.36. FMS Information Report with Subindex (Unconfirmed Service Id = 16)
 */
static int hf_ff_fms_info_report_with_subidx	= -1;

static int hf_ff_fms_info_report_with_subidx_req	= -1;
static int hf_ff_fms_info_report_with_subidx_req_idx	= -1;
static int hf_ff_fms_info_report_with_subidx_req_subidx	= -1;

static gint ett_ff_fms_info_report_with_subidx_req	= -1;



/*
 * 6.5.3.37. FMS Information Report On Change (Unconfirmed Service Id = 17)
 */
static int hf_ff_fms_info_report_on_change	= -1;

static int hf_ff_fms_info_report_on_change_req	= -1;
static int hf_ff_fms_info_report_on_change_req_idx	= -1;

static gint ett_ff_fms_info_report_on_change_req	= -1;



/*
 * 6.5.3.38. FMS Information Report On Change with Subindex
 *           (Unconfirmed Service Id = 18)
 */
static int hf_ff_fms_info_report_on_change_with_subidx	= -1;

static int hf_ff_fms_info_report_on_change_with_subidx_req	= -1;
static int hf_ff_fms_info_report_on_change_with_subidx_req_idx	= -1;
static int hf_ff_fms_info_report_on_change_with_subidx_req_subidx	= -1;

static gint ett_ff_fms_info_report_on_change_with_subidx_req	= -1;



/*
 * 6.5.3.39. FMS Event Notification (Unconfirmed Service Id = 2)
 */
static int hf_ff_fms_ev_notification	= -1;

static int hf_ff_fms_ev_notification_req	= -1;
static int hf_ff_fms_ev_notification_req_idx	= -1;
static int hf_ff_fms_ev_notification_req_ev_num	= -1;

static gint ett_ff_fms_ev_notification_req	= -1;



/*
 * 6.5.3.40. FMS Alter Event Condition Monitoring (Confirmed Service Id = 24)
 */
static int hf_ff_fms_alter_ev_condition_monitoring	= -1;

static int hf_ff_fms_alter_ev_condition_monitoring_req	= -1;
static int hf_ff_fms_alter_ev_condition_monitoring_req_idx	= -1;
static int hf_ff_fms_alter_ev_condition_monitoring_req_enabled	= -1;

static int hf_ff_fms_alter_ev_condition_monitoring_rsp	= -1;

static int hf_ff_fms_alter_ev_condition_monitoring_err	= -1;
static int hf_ff_fms_alter_ev_condition_monitoring_err_err_class	= -1;
static int hf_ff_fms_alter_ev_condition_monitoring_err_err_code	= -1;
static int hf_ff_fms_alter_ev_condition_monitoring_err_additional_code	= -1;
static int hf_ff_fms_alter_ev_condition_monitoring_err_additional_desc	= -1;

static gint ett_ff_fms_alter_ev_condition_monitoring_req	= -1;
static gint ett_ff_fms_alter_ev_condition_monitoring_rsp	= -1;
static gint ett_ff_fms_alter_ev_condition_monitoring_err	= -1;



/*
 * 6.5.3.41. FMS Acknowledge Event Notification (Confirmed Service Id = 25)
 */
static int hf_ff_fms_ack_ev_notification	= -1;

static int hf_ff_fms_ack_ev_notification_req	= -1;
static int hf_ff_fms_ack_ev_notification_req_idx	= -1;
static int hf_ff_fms_ack_ev_notification_req_ev_num	= -1;

static int hf_ff_fms_ack_ev_notification_rsp	= -1;

static int hf_ff_fms_ack_ev_notification_err	= -1;
static int hf_ff_fms_ack_ev_notification_err_err_class	= -1;
static int hf_ff_fms_ack_ev_notification_err_err_code	= -1;
static int hf_ff_fms_ack_ev_notification_err_additional_code	= -1;
static int hf_ff_fms_ack_ev_notification_err_additional_desc	= -1;

static gint ett_ff_fms_ack_ev_notification_req	= -1;
static gint ett_ff_fms_ack_ev_notification_rsp	= -1;
static gint ett_ff_fms_ack_ev_notification_err	= -1;



/*
 * 6.5.4. LAN Redundancy Services
 */
static int hf_ff_lr	= -1;



/*
 * 6.5.4.1. LAN Redundancy Get Information (Confirmed Service Id = 1)
 */
static int hf_ff_lr_get_info	= -1;

static int hf_ff_lr_get_info_req	= -1;

static int hf_ff_lr_get_info_rsp	= -1;
static int hf_ff_lr_get_info_rsp_lr_attrs_ver	= -1;
static int hf_ff_lr_get_info_rsp_lr_max_msg_num_diff	= -1;
static int hf_ff_lr_get_info_rsp_reserved	= -1;
static int hf_ff_lr_get_info_rsp_diagnostic_msg_intvl	= -1;
static int hf_ff_lr_get_info_rsp_aging_time	= -1;
static int hf_ff_lr_get_info_rsp_diagnostic_msg_if_a_send_addr	= -1;
static int hf_ff_lr_get_info_rsp_diagnostic_msg_if_a_recv_addr	= -1;
static int hf_ff_lr_get_info_rsp_diagnostic_msg_if_b_send_addr	= -1;
static int hf_ff_lr_get_info_rsp_diagnostic_msg_if_b_recv_addr	= -1;

static int hf_ff_lr_get_info_err	= -1;
static int hf_ff_lr_get_info_err_err_class	= -1;
static int hf_ff_lr_get_info_err_err_code	= -1;
static int hf_ff_lr_get_info_err_additional_code	= -1;
static int hf_ff_lr_get_info_err_additional_desc	= -1;

static gint ett_ff_lr_get_info_req	= -1;
static gint ett_ff_lr_get_info_rsp	= -1;
static gint ett_ff_lr_get_info_rsp_lr_flags	= -1;
static gint ett_ff_lr_get_info_err	= -1;



/*
 * 6.5.4.2. LAN Redundancy Put Information (Confirmed Service Id = 2)
 */
static int hf_ff_lr_put_info	= -1;

static int hf_ff_lr_put_info_req	= -1;
static int hf_ff_lr_put_info_req_lr_attrs_ver	= -1;
static int hf_ff_lr_put_info_req_lr_max_msg_num_diff	= -1;
static int hf_ff_lr_put_info_req_reserved	= -1;
static int hf_ff_lr_put_info_req_diagnostic_msg_intvl	= -1;
static int hf_ff_lr_put_info_req_aging_time	= -1;
static int hf_ff_lr_put_info_req_diagnostic_msg_if_a_send_addr	= -1;
static int hf_ff_lr_put_info_req_diagnostic_msg_if_a_recv_addr	= -1;
static int hf_ff_lr_put_info_req_diagnostic_msg_if_b_send_addr	= -1;
static int hf_ff_lr_put_info_req_diagnostic_msg_if_b_recv_addr	= -1;

static int hf_ff_lr_put_info_rsp	= -1;
static int hf_ff_lr_put_info_rsp_lr_attrs_ver	= -1;
static int hf_ff_lr_put_info_rsp_lr_max_msg_num_diff	= -1;
static int hf_ff_lr_put_info_rsp_reserved	= -1;
static int hf_ff_lr_put_info_rsp_diagnostic_msg_intvl	= -1;
static int hf_ff_lr_put_info_rsp_aging_time	= -1;
static int hf_ff_lr_put_info_rsp_diagnostic_msg_if_a_send_addr	= -1;
static int hf_ff_lr_put_info_rsp_diagnostic_msg_if_a_recv_addr	= -1;
static int hf_ff_lr_put_info_rsp_diagnostic_msg_if_b_send_addr	= -1;
static int hf_ff_lr_put_info_rsp_diagnostic_msg_if_b_recv_addr	= -1;

static int hf_ff_lr_put_info_err	= -1;
static int hf_ff_lr_put_info_err_err_class	= -1;
static int hf_ff_lr_put_info_err_err_code	= -1;
static int hf_ff_lr_put_info_err_additional_code	= -1;
static int hf_ff_lr_put_info_err_additional_desc	= -1;

static gint ett_ff_lr_put_info_req	= -1;
static gint ett_ff_lr_put_info_req_lr_flags	= -1;
static gint ett_ff_lr_put_info_rsp	= -1;
static gint ett_ff_lr_put_info_rsp_lr_flags	= -1;
static gint ett_ff_lr_put_info_err	= -1;



/*
 * 6.5.4.3. LAN Redundancy Get Statistics (Confirmed Service Id = 3)
 */
static int hf_ff_lr_get_statistics	= -1;

static int hf_ff_lr_get_statistics_req	= -1;

static int hf_ff_lr_get_statistics_rsp	= -1;
static int hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_recv_a	= -1;
static int hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_miss_a	= -1;
static int hf_ff_lr_get_statistics_rsp_num_rem_dev_diag_recv_fault_a	= -1;
static int hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_recv_b	= -1;
static int hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_miss_b	= -1;
static int hf_ff_lr_get_statistics_rsp_num_rem_dev_diag_recv_fault_b	= -1;
static int hf_ff_lr_get_statistics_rsp_num_x_cable_stat	= -1;
static int hf_ff_lr_get_statistics_rsp_x_cable_stat	= -1;

static int hf_ff_lr_get_statistics_err	= -1;
static int hf_ff_lr_get_statistics_err_err_class	= -1;
static int hf_ff_lr_get_statistics_err_err_code	= -1;
static int hf_ff_lr_get_statistics_err_additional_code	= -1;
static int hf_ff_lr_get_statistics_err_additional_desc	= -1;

static gint ett_ff_lr_get_statistics_req	= -1;
static gint ett_ff_lr_get_statistics_rsp	= -1;
static gint ett_ff_lr_get_statistics_rsp_list_of_x_cable_stat	= -1;
static gint ett_ff_lr_get_statistics_err	= -1;



/*
 * 6.5.4.4. Diagnostic Message (Unconfirmed Service Id = 1)
 */
static int hf_ff_lr_diagnostic_msg	= -1;

static int hf_ff_lr_diagnostic_msg_req	= -1;
static int hf_ff_lr_diagnostic_msg_req_dev_idx	= -1;
static int hf_ff_lr_diagnostic_msg_req_num_of_network_ifs	= -1;
static int hf_ff_lr_diagnostic_msg_req_transmission_if	= -1;
static int hf_ff_lr_diagnostic_msg_req_diagnostic_msg_intvl	= -1;
static int hf_ff_lr_diagnostic_msg_req_pd_tag	= -1;
static int hf_ff_lr_diagnostic_msg_req_reserved	= -1;
static int hf_ff_lr_diagnostic_msg_req_num_of_if_statuses	= -1;
static int hf_ff_lr_diagnostic_msg_req_if_a_to_a_status	= -1;
static int hf_ff_lr_diagnostic_msg_req_if_b_to_a_status	= -1;
static int hf_ff_lr_diagnostic_msg_req_if_a_to_b_status	= -1;
static int hf_ff_lr_diagnostic_msg_req_if_b_to_b_status	= -1;

static gint ett_ff_lr_diagnostic_msg_req	= -1;
static gint ett_ff_lr_diagnostic_msg_req_dup_detection_stat	= -1;
static gint ett_ff_lr_diagnostic_msg_req_a_to_a_status	= -1;
static gint ett_ff_lr_diagnostic_msg_req_b_to_a_status	= -1;
static gint ett_ff_lr_diagnostic_msg_req_a_to_b_status	= -1;
static gint ett_ff_lr_diagnostic_msg_req_b_to_b_status	= -1;



static const value_string names_pad_len[] = {
	{ 0x00, 			"No padding" },
	{ OPTION_PAD_4BYTE, "pad to 4 byte boundary" },
	{ OPTION_PAD_8BYTE, "pad to 8 byte boundary" },
	{ 0, NULL }
};



static const value_string names_proto[] = {
	{ 0x00, "Unused"},
	{ PROTOCOL_FDA, "FDA Session Management" },
	{ PROTOCOL_SM, "SM" },
	{ PROTOCOL_FMS, "FMS" },
	{ PROTOCOL_LAN, "LAN Redundancy" },
	{ 0, NULL }
};



static const value_string names_type[] = {
	{ TYPE_REQUEST, "Request Message" },
	{ TYPE_RESPONSE, "Response Message" },
	{ TYPE_ERROR, "Error Message" },
	{ 0, NULL }
};



static const value_string names_nma_conf_use[] = {
	{ 0, "NMA Configuration Not Permitted" },
	{ 1, "NMA Configuration Permitted" },
	{ 0, NULL }
};



static const value_string names_query_type[] = {
	{ 0, "PD Tag query for primary device" },
	{ 1, "VFD tag query" },
	{ 2, "Function-Block tag query" },
	{ 3, "Element Id query" },
	{ 4, "PD Tag/VFD Reference query" },
	{ 5, "Device Index query" },
	{ 6, "PD Tag query for secondary or member of redundant set" },
	{ 0, NULL }
};



static const value_string names_smk_state[] = {
	{ 0x02, "NO_TAG" }, 		/* 0000 0010 */
	{ 0x04, "OPERATIONAL" }, /* 0000 0100 */
	{ 0, NULL }
};



static const value_string names_dev_type[] = {
	{ 0x00, "Type D-1 Device" }, 					/* 0000 0000 */
	{ 0x01, "Type D-2 Device" }, 					/* 0000 0001 */
	{ 0x02, "Type D-3 Device" }, 					/* 0000 0010 */
	{ 0x03, "Type D-3 and Type D-2 Device" }, 		/* 0000 0011 */
	{ 0x04, "Not used" }, 							/* 0000 0100 */
	{ 0x05, "Type D-2 and Type D-1 Device" }, 		/* 0000 0101 */
	{ 0x06, "Type D-3 and Type D-1 Device" }, 		/* 0000 0110 */
	{ 0x07, "Type D-3 and D-2 and Type D-1 Device" }, /* 0000 0111 */
	{ 0, NULL }
};



static const value_string names_dev_redundancy_role[] = {
	{ 0x04, "Primary" }, /* 0000 0100 */
	{ 0x08, "Secondary" }, /* 0000 1000 */
	{ 0, NULL }
};



static const value_string names_assigned_redundant_dev_type[] = {
	{ 0x00, "Type D-1 Device" }, /* 0000 0000 */
	{ 0x01, "Type D-2 Device" }, /* 0000 0001 */
	{ 0x02, "Type D-3 Device" }, /* 0000 0010 */
	{ 0, NULL }
};



static const value_string names_type_d2_dev_redundancy_role[] = {
	{ 0x00, "Not used" }, 				/* 0000 0000 */
	{ 0x04, "Type D-2 Device Primary" }, /* 0000 0100 */
	{ 0x08, "Type D-2 Device Secondary" }, /* 0000 1000 */
	{ 0, NULL }
};



static const value_string names_conn_opt[] = {
	{ 1, "VCR Selector" },
	{ 2, "NMA Access" },
	{ 3, "FBAP Access" },
	{ 0, NULL }
};



static const value_string names_fda_unconfirmed[] = {
	{ 0,	NULL }
};



static const value_string names_fda_confirmed[] = {
	{ FDA_OPEN_SESSION,	"FDA Open Session" },
	{ FDA_IDLE,	"FDA Idle" },
	{ 0,	NULL }
};



static const value_string names_sm_unconfirmed[] = {
	{ HSE_SM_FIND_TAG_QUERY,	"SM Find Tag Query" },
	{ HSE_SM_FIND_TAG_REPLY,	"SM Find Tag Reply" },
	{ HSE_SM_DEVICE_ANNUNCIATION,	"SM Device Annunciation" },
	{ 0,	NULL }
};



static const value_string names_sm_confirmed[] = {
	{ HSE_SM_IDENTIFY,	"SM Identify" },
	{ HSE_SM_CLEAR_ADDRESS,	"SM Clear Address" },
	{ HSE_SM_SET_ASSIGNMENT,	"SM Set Assignment Info" },
	{ HSE_SM_CLEAR_ASSIGNMENT,	"SM Clear Assignment Info" },
	{ 0,	NULL }
};



static const value_string names_fms_unconfirmed[] = {
	{ HSE_FMS_INFORMATION_REPORT,	"FMS Information Report" },
	{ HSE_FMS_UNSOLICITED_STATUS,	"FMS Unsolicited Status" },
	{ HSE_FMS_EVENT_NOTIFICATION,	"FMS Event Notification" },
	{ HSE_FMS_INFORMATION_REPORT_WITH_SUBINDEX,
		"FMS Information Report with Subindex" },
	{ HSE_FMS_INFORMATION_REPORT_ON_CHANGE,
		"FMS Information Report On Change" },
	{ HSE_FMS_INFORMATION_REPORT_ON_CHANGE_WITH_SUBINDEX,
		"FMS Information Report On Change with Subindex" },
	{ HSE_FMS_ABORT,	"FMS Abort" },
	{ 0,	NULL }
};



static const value_string names_fms_confirmed[] = {
	{ HSE_FMS_STATUS,	"FMS Status" },
	{ HSE_FMS_IDENTIFY,	"FMS Identify" },
	{ HSE_FMS_READ,	"FMS Read" },
	{ HSE_FMS_WRITE,	"FMS Write" },
	{ HSE_FMS_GET_OD,	"FMS Get OD" },
	{ HSE_FMS_DEFINE_VARIABLE_LIST,	"FMS Define Variable List" },
	{ HSE_FMS_DELETE_VARIABLE_LIST,	"FMS Delete Variable List" },
	{ HSE_FMS_INITIATE_DOWNLOAD_SEQUENCE,	"FMS Initiate Download Sequence" },
	{ HSE_FMS_DOWNLOAD_SEGMENT,	"FMS Download Segment" },
	{ HSE_FMS_TERMINATE_DOWNLOAD_SEQUENCE,	"FMS Terminate Download Sequence" },
	{ HSE_FMS_INITIATE_UPLOAD_SEQUENCE,	"FMS Initiate Upload Sequence" },
	{ HSE_FMS_UPLOAD_SEGMENT,	"FMS Upload Segment" },
	{ HSE_FMS_TERMINATE_UPLOAD_SEQUENCE,	"FMS Terminate Upload Sequence" },
	{ HSE_FMS_REQUEST_DOMAIN_DOWNLOAD,	"FMS Request Domain Download" },
	{ HSE_FMS_REQUEST_DOMAIN_UPLOAD,	"FMS Request Domain Upload" },
	{ HSE_FMS_CREATE_PROGRAM_INVOCATION,	"FMS Create Program Invocation" },
	{ HSE_FMS_DELETE_PROGRAM_INVOCATION,	"FMS Delete Program Invocation" },
	{ HSE_FMS_START,	"FMS Start" },
	{ HSE_FMS_STOP,	"FMS Stop" },
	{ HSE_FMS_RESUME,	"FMS Resume" },
	{ HSE_FMS_RESET,	"FMS Reset" },
	{ HSE_FMS_KILL,	"FMS Kill" },
	{ HSE_FMS_ALTER_EVENT_CONDITION_MONITORING,
		"FMS Alter Event Condition Monitoring" },
	{ HSE_FMS_ACKNOWLEDGE_EVENT_NOTIFICATION,
		"FMS Acknowledge Event Notification" },
	{ HSE_FMS_INITIATE_PUT_OD,	"FMS Initiate Put OD" },
	{ HSE_FMS_PUT_OD,	"FMS Put OD" },
	{ HSE_FMS_TERMINATE_PUT_OD,	"FMS Terminate Put OD" },
	{ HSE_FMS_GENERIC_INITIATE_DOWNLOAD_SEQUENCE,
		"FMS Generic Initiate Download Sequence" },
	{ HSE_FMS_GENERIC_DOWNLOAD_SEGMENT,	"FMS Generic Download Segment" },
	{ HSE_FMS_GENERIC_TERMINATE_DOWNLOAD_SEQUENCE,
		"FMS Generic Terminate Download Sequence" },
	{ HSE_FMS_READ_WITH_SUBINDEX,	"FMS Read with Subindex" },
	{ HSE_FMS_WRITE_WITH_SUBINDEX,	"FMS Write with Subindex" },
	{ HSE_FMS_INITIATE,	"FMS Initiate" },
	{ 0,	NULL }
};



static const value_string names_lan_unconfirmed[] = {
	{ LAN_DIAG,	"Diagnostic Message" },
	{ 0,	NULL }
};



static const value_string names_lan_confirmed[] = {
	{ LAN_GET_INFO,	"LAN Redundancy Get Information" },
	{ LAN_PUT_INFO,	"LAN Redundancy Put Information" },
	{ LAN_GET_STATISTICS,	"LAN Redundancy Get Statistics" },
	{ 0,	NULL }
};



static const value_string names_transmission_interface[] = {
	{ 0,	"Interface A" },
	{ 1,	"Interface B" },
	{ 0,	NULL }
};



static const value_string names_err_class[] = {
	{ 1,	"vfd state" },
	{ 2,	"application reference" },
	{ 3,	"definition" },
	{ 4,	"resource" },
	{ 5,	"service" },
	{ 6,	"access" },
	{ 7,	"od" },
	{ 8,	"other" },
	{ 9,	"reject" },
	{ 10,	"h1 sm reason code" },
	{ 11,	"fms initiate" },
	{ 0,	NULL }
};



static const value_string names_err_code_vfd_state[] = {
	{ 0,	"other" },
	{ 0,	NULL }
};



static const value_string names_err_code_appl_ref[] = {
	{ 0,	"other" },
	{ 1,	"object undefined" },
	{ 2,	"object attributes inconsistent" },
	{ 3,	"name already exists" },
	{ 0,	NULL }
};



static const value_string names_err_code_def[] = {
	{ 0,	"other" },
	{ 1,	"application unreachable" },
	{ 0,	NULL }
};



static const value_string names_err_code_res[] = {
	{ 0,	"other" },
	{ 1,	"memory unavailable" },
	{ 2,	"max outstanding requests per session exceeded" },
	{ 3,	"max sessions exceeded" },
	{ 4,	"object creation failure" },
	{ 0,	NULL }
};



static const value_string names_err_code_srv[] = {
	{ 0,	"other" },
	{ 1,	"object state conflict" },
	{ 2,	"pdu size" },
	{ 3,	"object constraint conflict" },
	{ 4,	"parameter inconsistent" },
	{ 5,	"illegal parameter" },
	{ 6,	"unsupported service" },
	{ 7,	"unsupported version" },
	{ 8,	"invalid options" },
	{ 9,	"unsupported protocol" },
	{ 10,	"reserved" },
	{ 11,	"key parameter mismatch" },
	{ 12,	"assignments already made" },
	{ 13,	"unsupported device redundancy state" },
	{ 14,	"response time-out" },
	{ 15,	"duplicate PD Tag detected" },
	{ 0,	NULL }
};



static const value_string names_err_code_access[] = {
	{ 0,	"other" },
	{ 1,	"object invalidated" },
	{ 2,	"hardware fault" },
	{ 3,	"object access denied" },
	{ 4,	"invalid address" },
	{ 5,	"object attribute inconsistent" },
	{ 6,	"object access unsupported" },
	{ 7,	"object non existent" },
	{ 8,	"type conflict" },
	{ 9,	"named access unsupported" },
	{ 10,	"access to element unsupported" },
	{ 11,	"config access already open" },
	{ 12,	"reserved" },
	{ 13,	"unrecognized FDA Address" },
	{ 0,	NULL }
};



static const value_string names_err_code_od[] = {
	{ 0,	"other" },
	{ 1,	"name length overflow" },
	{ 2,	"od overflow" },
	{ 3,	"od write protected" },
	{ 4,	"extension length overflow" },
	{ 5,	"od description length overflow" },
	{ 6,	"operational problem" },
	{ 7,	"hse to h1 format conversion not supported" },
	{ 0,	NULL }
};



static const value_string names_err_code_other[] = {
	{ 0,	"other" },
	{ 0,	NULL }
};



static const value_string names_err_code_reject[] = {
	{ 5,	"pdu size" },
	{ 0,	NULL }
};



static const value_string names_err_code_h1_sm_reason_code[] = {
	{ 0,	"other" },
	{ 1,	"DLL Error - insufficient resources" },
	{ 2,	"DLL Error - sending queue full" },
	{ 3,	"DLL Error - time-out before transmission" },
	{ 4,	"DLL Error - reason unspecified" },
	{ 5,	"Device failed to respond to SET_PD_TAG" },
	{ 6,	"Device failed to respond to WHO_HAS_PD_TAG" },
	{ 7,	"Device failed to respond to SET_ADDR" },
	{ 8,	"Device failed to respond to IDENTIFY" },
	{ 9,	"Device failed to respond to ENABLE_SM_OP" },
	{ 10,	"Device failed to respond to CLEAR_ADDRESS" },
	{ 11,	"Multiple Response from WHO_HAS_PD_TAG" },
	{ 12,	"Non-Matching PD_TAG from WHO_HAS_PD_TAG" },
	{ 13,	"Non-Matching PD_TAG from IDENTIFY" },
	{ 14,	"Non-Matching DEV_ID from IDENTIFY" },
	{ 15,	"Remote Error Invalid State" },
	{ 16,	"Remote Error PD-Tag doesn't match" },
	{ 17,	"Remote Error Dev-ID doesn't match" },
	{ 18,	"Remote Error SMIB object write failed" },
	{ 19,	"Remote Error Starting SM Operational" },
	{ 0,	NULL }
};



static const value_string names_err_code_fms_init[] = {
	{ 0,	"other" },
	{ 1,	"max-fms-pdu-size-insufficient" },
	{ 2,	"feature-not-supported" },
	{ 3,	"version-od-incompatible" },
	{ 4,	"user-initiate-denied" },
	{ 5,	"password-error" },
	{ 6,	"profile-number-incompatible" },
	{ 0,	NULL }
};



static const char *
val_to_str_err_code(guint8 class, guint8 code)
{
	switch(class) {
		case 1:
			return(val_to_str(code, names_err_code_vfd_state, "Unknown"));

		case 2:
			return(val_to_str(code, names_err_code_appl_ref, "Unknown"));

		case 3:
			return(val_to_str(code, names_err_code_def, "Unknown"));

		case 4:
			return(val_to_str(code, names_err_code_res, "Unknown"));

		case 5:
			return(val_to_str(code, names_err_code_srv, "Unknown"));

		case 6:
			return(val_to_str(code, names_err_code_access, "Unknown"));

		case 7:
			return(val_to_str(code, names_err_code_od, "Unknown"));

		case 8:
			return(val_to_str(code, names_err_code_other, "Unknown"));

		case 9:
			return(val_to_str(code, names_err_code_reject, "Unknown"));

		case 10:
			return(val_to_str(code,
				names_err_code_h1_sm_reason_code, "Unknown"));

		case 11:
			return(val_to_str(code, names_err_code_fms_init, "Unknown"));

		default:
			return("Unknown");
	}
}



/*
 * 6.5.1.1.   FDA Open Session (Confirmed Service Id = 1)
 * 6.5.1.1.1. Request Message Parameters
 */
static void
dissect_ff_msg_fda_open_sess_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FDA Open Session Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FDA Open Session Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_open_sess_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_sess_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_max_buf_siz, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_max_msg_len, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_nma_conf_use, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_inactivity_close_time, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_transmit_delay_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.1.1.2. Response Message Parameters
 */
static void
dissect_ff_msg_fda_open_sess_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FDA Open Session Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FDA Open Session Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_open_sess_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_sess_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_max_buf_siz, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_max_msg_len, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_nma_conf_use, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_inactivity_close_time, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_transmit_delay_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_rsp_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.1.1.3. Error Message Parameters
 */
static void
dissect_ff_msg_fda_open_sess_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FDA Open Session Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FDA Open Session Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_open_sess_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fda_open_sess_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_open_sess_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.1.2.   FDA Idle (Confirmed Service Id = 3)
 * 6.5.1.2.1. Request Message Parameters
 */
static void
dissect_ff_msg_fda_idle_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FDA Idle Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FDA Idle Request");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fda_idle_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.1.2.2. Response Message Parameters
 */
static void
dissect_ff_msg_fda_idle_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FDA Idle Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FDA Idle Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fda_idle_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.1.2.3. Error Message Parameters
 */
static void
dissect_ff_msg_fda_idle_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FDA Idle Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FDA Idle Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_idle_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fda_idle_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fda_idle_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_idle_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fda_idle_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.1.   SM Find Tag Query (Unconfirmed Service Id = 1)
 * 6.5.2.1.1. Request Message Parameters
 */
static void
dissect_ff_msg_sm_find_tag_query_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Find Tag Query Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Find Tag Query Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_sm_find_tag_query_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_query_req_query_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_query_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_query_req_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_query_req_vfd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.2.   SM Find Tag Reply (Unconfirmed Service Id = 2)
 * 6.5.2.2.1. Request Message Parameters
 */
static void
dissect_ff_msg_sm_find_tag_reply_req_dup_detection_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Duplicate Detection State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_find_tag_reply_req_dup_detection_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 3-8: Reserved, set to 0.
	 * Bit 2:    1 = Duplicate PD Tag Detected
	 *           0 = Duplicate PD Tag Not Detected
	 * Bit 1:    1 = Duplicate Device Index Detected
	 *           0 = Duplicate Device Index Not Detected
	 */

	/* Bits 3-8: 1111 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xfc, 8, "Reserved: %u"));

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Duplicate PD Tag Detected",
			"Duplicate PD Tag Not Detected"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Duplicate Device Index Detected",
			"Duplicate Device Index Not Detected"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_sm_find_tag_reply_req_list_of_fda_addr_selectors(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint16 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 2 * value,
		"List of FDA Address Selectors (%u bytes)", 2 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_find_tag_reply_req_list_of_fda_addr_selectors);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_sm_find_tag_reply_req_fda_addr_selector,
			tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;
	}

	return;
}



static void
dissect_ff_msg_sm_find_tag_reply_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 DuplicateDetectionState	= 0;
	guint16 NumOfFDAAddrSelectors	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Find Tag Reply Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Find Tag Reply Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_sm_find_tag_reply_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_query_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_h1_node_addr, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_fda_addr_link_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_vfd_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_od_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_ip_addr, tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_od_ver, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_dev_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	DuplicateDetectionState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_find_tag_reply_req_dup_detection_state(tvb,
		offset, sub_tree, DuplicateDetectionState);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	NumOfFDAAddrSelectors = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_find_tag_reply_req_num_of_fda_addr_selectors,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(NumOfFDAAddrSelectors) {
		dissect_ff_msg_sm_find_tag_reply_req_list_of_fda_addr_selectors(tvb,
			offset, sub_tree, NumOfFDAAddrSelectors);
		offset += 2 * NumOfFDAAddrSelectors;
		length -= 2 * NumOfFDAAddrSelectors;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.3.   SM Identify (Confirmed Service Id = 3)
 * 6.5.2.3.1. Request Message Parameters
 */
static void
dissect_ff_msg_sm_id_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Identify Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"SM Identify Request");
		sub_tree = proto_item_add_subtree(ti, ett_ff_sm_id_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.3.2. Response Message Parameters
 */
static int
dissect_ff_msg_sm_id_rsp_h1_node_addr(tvbuff_t *tvb,
	gint offset, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return 0;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 2,
		"H1 Node Address Version Number (%u bytes)", 2);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_h1_node_addr);

	if(!sub_tree) {
		return 0;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_h1_node_addr_ver_num_h1_node_addr,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_h1_node_addr_ver_num_ver_num, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}



static void
dissect_ff_msg_sm_id_rsp_entries_node_addr(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"Version Number List (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_entries_node_addr);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value * 2; d ++) {
		dissect_ff_msg_sm_id_rsp_h1_node_addr(tvb, offset, sub_tree);
		offset += 2;
	}

	return;
}



static int
dissect_ff_msg_sm_id_rsp_h1_live_list(tvbuff_t *tvb,
	gint offset, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return 0;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4,
		"H1 Live-list Version Number (%u bytes)", 4);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_h1_live_list);

	if(!sub_tree) {
		return 0;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_h1_live_list_h1_link_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_h1_live_list_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_h1_live_list_ver_num, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}



static void
dissect_ff_msg_sm_id_rsp_entries_link_id(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"Version Number List (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_entries_h1_live_list);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		dissect_ff_msg_sm_id_rsp_h1_live_list(tvb, offset, sub_tree);
		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_sm_id_rsp_smk_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"SMK State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_smk_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 2-8:
	 *    0 = Reserved
	 *    1 = NO_TAG
	 *    2 = OPERATIONAL
	 *    3  127 = Reserved
	 * Bit 1:
	 *    0 = Not Synchronized with SNTP Time Server
	 *    1 = Synchronized with SNTP Time Server
	 */

	/* Bits 2-8: 1111 1110 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0xfe, 8,
			names_smk_state, "%s"), (value & 0xfe) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Synchronized with SNTP Time Server",
			"Not Synchronized with SNTP Time Server"),
			value & 0x01);

	return;
}



static void
dissect_ff_msg_sm_id_rsp_dev_type(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Device Type: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_dev_type);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bit 8 = Linking Device
	 * Bit 7 = I/O Gateway
	 * Bit 6 = HSE Field Device
	 * Bit 5 = H1 Device
	 * Bit 4 = Reserved
	 * Bits 1 - 3  Redundant Device Type Capability*
	 *    0 = Type D-1 Device
	 *    1 = Type D-2 Device
	 *    2 = Type D-3 Device
	 *    3 = Type D-3 and Type D-2 Device
	 *    4 = Not used
	 *    5 = Type D-2 and Type D-1 Device
	 *    6 = Type D-3 and Type D-1 Device
	 *    7 = Type D-3 and D-2 and Type D-1 Device
	 */

	/* Bits 8: 1000 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x80, 8,
			"Linking Device",
			"Not Linking Device"),
			(value & 0x80) >> 7);

	/* Bits 7: 0100 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x40, 8,
			"I/O Gateway",
			"Not I/O Gateway"),
			(value & 0x40) >> 6);

	/* Bits 6: 0010 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x20, 8,
			"HSE Field Device",
			"Not HSE Field Device"),
			(value & 0x20) >> 5);

	/* Bits 5: 0001 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x10, 8,
			"H1 Device",
			"Not H1 Device"),
			(value & 0x10) >> 4);

	/* Bits 4: 0000 1000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0x08, 8, "Reserved: %u"));

	/* Bits 1-3: 0000 0111 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x07, 8,
			names_dev_type, "Redundant Device Type Capability: %s"),
			value & 0x07);

	return;
}



static void
dissect_ff_msg_sm_id_rsp_dev_redundancy_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Device Redundancy State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_dev_redundancy_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 5-8 = Reserved, set to 0
	 * Bits 3 & 4  Device Redundancy Role
	 *    0 = Reserved
	 *    1 = Primary
	 *    2 = Secondary
	 * Bits 1 & 2  Assigned Redundant Device Type*
	 *    0 = Type D-1 Device
	 *    1 = Type D-2 Device
	 *    2 = Type D-3 Device
	 */

	/* Bits 5-8: 1111 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xf0, 8, "Reserved: %u"));

	/* Bits 3-4: 0000 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x0c, 8,
			names_dev_redundancy_role, "Device Redundancy Role: %s"),
			(value & 0x0c) >> 2);

	/* Bits 1-2: 0000 0011 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x03, 8,
			names_assigned_redundant_dev_type,
			"Assigned Redundant Device Type: %s"), value & 0x03);

	return;
}



static void
dissect_ff_msg_sm_id_rsp_dup_detection_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Duplicate Detection State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp_dup_detection_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 3-8: Reserved, set to 0.
	 * Bit 2:    1 = Duplicate PD Tag Detected
	 *           0 = Duplicate PD Tag Not Detected
	 * Bit 1:    1 = Duplicate Device Index Detected
	 *           0 = Duplicate Device Index Not Detected
	 */

	/* Bits 3-8: 1111 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xfc, 8, "Reserved: %u"));

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Duplicate PD Tag Detected",
			"Duplicate PD Tag Not Detected"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Duplicate Device Index Detected",
			"Duplicate Device Index Not Detected"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_sm_id_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree, guint32 FDAAddress)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti			= NULL;

	guint8 SMKState	= 0;
	guint8 DeviceType	= 0;
	guint8 DeviceRedundancyState	= 0;
	guint8 DuplicateDetectionState	= 0;
	guint32 NumOfEntriesInVerNumList	= 0;

	guint16 LinkId	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Identify Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "SM Identify Response");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_id_rsp);

	if(!sub_tree) {
		return;
	}

	SMKState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_id_rsp_smk_state(tvb, offset, sub_tree, SMKState);
	offset += 1;
	length -= 1;

	DeviceType = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_id_rsp_dev_type(tvb, offset, sub_tree, DeviceType);
	offset += 1;
	length -= 1;

	DeviceRedundancyState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_id_rsp_dev_redundancy_state(tvb,
		offset, sub_tree, DeviceRedundancyState);
	offset += 1;
	length -= 1;

	DuplicateDetectionState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_id_rsp_dup_detection_state(tvb,
		offset, sub_tree, DuplicateDetectionState);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_max_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_operational_ip_addr, tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_dev_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_hse_repeat_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_lr_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_annunc_ver_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_hse_dev_ver_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	NumOfEntriesInVerNumList = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_rsp_num_of_entries, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(NumOfEntriesInVerNumList) {
		/* 11111111 11111111 00000000 00000000 */
		LinkId = (guint16)(FDAAddress >> 16);
		if(LinkId) {
			dissect_ff_msg_sm_id_rsp_entries_node_addr(tvb,
				offset, sub_tree, NumOfEntriesInVerNumList);
		} else {
			dissect_ff_msg_sm_id_rsp_entries_link_id(tvb,
				offset, sub_tree, NumOfEntriesInVerNumList);
		}

		offset += 4 * NumOfEntriesInVerNumList;
		length -= 4 * NumOfEntriesInVerNumList;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.3.3. Error Message Parameters
 */
static void
dissect_ff_msg_sm_id_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Identify Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "SM Identify Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_sm_id_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_sm_id_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_id_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.4.   SM Clear Address (Confirmed Service Id = 12)
 * 6.5.2.4.1. Request Message Parameters
 */
static void
dissect_ff_msg_sm_clear_addr_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Clear Address Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Clear Address Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_sm_id_err);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_addr_req_dev_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_addr_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_addr_req_interface_to_clear, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.4.2. Response Message Parameters
 */
static void
dissect_ff_msg_sm_clear_addr_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Clear Address Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"SM Clear Address Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_sm_clear_addr_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.4.3. Error Message Parameters
 */
static void
dissect_ff_msg_sm_clear_addr_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Clear Address Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Clear Address Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_sm_clear_addr_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_addr_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_sm_clear_addr_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_addr_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_addr_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.5.   SM Set Assignment Info (Confirmed Service Id = 14)
 * 6.5.2.5.1. Request Message Parameters
 */
static void
dissect_ff_msg_sm_set_assign_info_req_dev_redundancy_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Device Redundancy State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_set_assign_info_req_dev_redundancy_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 5-8 = Reserved, set to 0
	 * Bits 3 & 4  Type D-2 Device Redundancy Role
	 *    0 = Not used
	 *    1 = Type D-2 Device Primary
	 *    2 = Type D-2 Device Secondary
	 * Bits 1 & 2  Assigned Device Redundancy Type
	 *    0 = Type D-1 Device
	 *    1 = Type D-2 Device
	 *    2 = Type D-3 Device
	 */

	/* Bits 5-8: 1111 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xf0, 8, "Reserved: %u"));

	/* Bits 3-4: 0000 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x0c, 8,
			names_type_d2_dev_redundancy_role,
			"Type D-2 Device Redundancy Role: %s"),
			(value & 0x0c) >> 2);

	/* Bits 1-2: 0000 0011 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x03, 8,
			names_assigned_redundant_dev_type,
			"Assigned Device Redundancy Type: %s"),
			value & 0x03);

	return;
}



static void
dissect_ff_msg_sm_set_assign_info_req_clear_dup_detection_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Clear Duplicate Detection State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_set_assign_info_req_clear_dup_detection_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 3-8: Reserved, set to 0.
	 * Bit 2:    1 = Do not clear Duplicate PD Tag Detected
	 *           0 = Clear Duplicate PD Tag Detected
	 * Bit 1:    1 = Do not clear Duplicate Device Index Detected
	 *           0 = Clear Duplicate Device Index Detected
	 */

	/* Bits 3-8: 1111 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xfc, 8, "Reserved: %u"));

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Do not clear Duplicate PD Tag Detected",
			"Clear Duplicate PD Tag Detected"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Do not clear Duplicate Device Index Detected",
			"Clear Duplicate Device Index Detected"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_sm_set_assign_info_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 DeviceRedundancyState	= 0;
	guint8 ClearDuplicateDetectionState	= 0;

	col_set_str(pinfo->cinfo, COL_INFO,"SM Set Assignment Info Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Set Assignment Info Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_set_assign_info_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_dev_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_h1_new_addr, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	DeviceRedundancyState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_set_assign_info_req_dev_redundancy_state(tvb,
		offset, sub_tree, DeviceRedundancyState);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_lr_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_hse_repeat_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_max_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_req_operational_ip_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	ClearDuplicateDetectionState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_set_assign_info_req_clear_dup_detection_state(tvb,
		offset, sub_tree, ClearDuplicateDetectionState);
	offset += 1;
	length -= 1;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.5.2. Response Message Parameters
 */
static void
dissect_ff_msg_sm_set_assign_info_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Set Assignment Info Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Set Assignment Info Response");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_set_assign_info_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_rsp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_rsp_max_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_rsp_hse_repeat_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.5.3. Error Message Parameters
 */
static void
dissect_ff_msg_sm_set_assign_info_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Set Assignment Info Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Set Assignment Info Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_sm_set_assign_info_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_sm_set_assign_info_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_set_assign_info_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.6.   SM Clear Assignment Info (Confirmed Service Id = 15)
 * 6.5.2.6.1. Request Message Parameters
 */
static void
dissect_ff_msg_sm_clear_assign_info_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Clear Assignment Info Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Clear Assignment Info Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_clear_assign_info_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_assign_info_req_dev_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_assign_info_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.6.2. Response Message Parameters
 */
static void
dissect_ff_msg_sm_clear_assign_info_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO,"SM Clear Assignment Info Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"SM Clear Assignment Info Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_sm_clear_assign_info_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.6.3. Error Message Parameters
 */
static void
dissect_ff_msg_sm_clear_assign_info_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Clear Assignment Info Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Clear Assignment Info Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_clear_assign_info_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_assign_info_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_sm_clear_assign_info_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_assign_info_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_clear_assign_info_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.2.7.   SM Device Annunciation (Unconfirmed Service Id = 16)
 * 6.5.2.7.1. Request Message Parameters
 */
static int
dissect_ff_msg_sm_dev_annunc_req_h1_node_addr(tvbuff_t *tvb,
	gint offset, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return 0;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 2,
		"H1 Node Address Version Number (%u bytes)", 2);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_h1_node_addr);

	if(!sub_tree) {
		return 0;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_h1_node_addr_ver_num_h1_node_addr,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_h1_node_addr_ver_num_ver_num,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}



static void
dissect_ff_msg_sm_dev_annunc_req_entries_node_addr(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"Version Number List (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_entries_node_addr);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value * 2; d ++) {
		dissect_ff_msg_sm_dev_annunc_req_h1_node_addr(tvb, offset, sub_tree);
		offset += 2;
	}

	return;
}



static int
dissect_ff_msg_sm_dev_annunc_req_h1_live_list(tvbuff_t *tvb,
	gint offset, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return 0;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4,
		"H1 Live-list Version Number (%u bytes)", 4);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_h1_live_list);

	if(!sub_tree) {
		return 0;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_h1_live_list_h1_link_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_h1_live_list_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_h1_live_list_ver_num, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}



static void
dissect_ff_msg_sm_dev_annunc_req_entries_link_id(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"Version Number List (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_entries_h1_live_list);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		dissect_ff_msg_sm_dev_annunc_req_h1_live_list(tvb, offset, sub_tree);
		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_sm_dev_annunc_req_smk_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"SMK State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_smk_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 2-8:
	 *    0 = Reserved
	 *    1 = NO_TAG
	 *    2 = OPERATIONAL
	 *    3  127 = Reserved
	 * Bit 1:
	 *    0 = Not Synchronized with SNTP Time Server
	 *    1 = Synchronized with SNTP Time Server
	 */

	/* Bits 2-8: 1111 1110 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0xfe, 8,
			names_smk_state, "%s"), (value & 0xfe) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Synchronized with SNTP Time Server",
			"Not Synchronized with SNTP Time Server"),
			value & 0x01);

	return;
}



static void
dissect_ff_msg_sm_dev_annunc_req_dev_type(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Device Type: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_dev_type);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bit 8 = Linking Device
	 * Bit 7 = I/O Gateway
	 * Bit 6 = HSE Field Device
	 * Bit 5 = H1 Device
	 * Bit 4 = Reserved
	 * Bits 1 - 3  Redundant Device Type Capability*
	 *    0 = Type D-1 Device
	 *    1 = Type D-2 Device
	 *    2 = Type D-3 Device
	 *    3 = Type D-3 and Type D-2 Device
	 *    4 = Not used
	 *    5 = Type D-2 and Type D-1 Device
	 *    6 = Type D-3 and Type D-1 Device
	 *    7 = Type D-3 and D-2 and Type D-1 Device
	 */

	/* Bits 8: 1000 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x80, 8,
			"Linking Device",
			"Not Linking Device"),
			(value & 0x80) >> 7);

	/* Bits 7: 0100 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x40, 8,
			"I/O Gateway",
			"Not I/O Gateway"),
			(value & 0x40) >> 6);

	/* Bits 6: 0010 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x20, 8,
			"HSE Field Device",
			"Not HSE Field Device"),
			(value & 0x20) >> 5);

	/* Bits 5: 0001 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x10, 8,
			"H1 Device",
			"Not H1 Device"),
			(value & 0x10) >> 4);

	/* Bits 4: 0000 1000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0x08, 8, "Reserved: %u"));

	/* Bits 1-3: 0000 0111 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x07, 8,
			names_dev_type, "Redundant Device Type Capability: %s"),
			value & 0x07);

	return;
}



static void
dissect_ff_msg_sm_dev_annunc_req_dev_redundancy_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Device Redundancy State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_dev_redundancy_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 5-8 = Reserved, set to 0
	 * Bits 3 & 4  Device Redundancy Role
	 *    0 = Reserved
	 *    1 = Primary
	 *    2 = Secondary
	 * Bits 1 & 2  Assigned Redundant Device Type*
	 *    0 = Type D-1 Device
	 *    1 = Type D-2 Device
	 *    2 = Type D-3 Device
	 */

	/* Bits 5-8: 1111 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xf0, 8, "Reserved: %u"));

	/* Bits 3-4: 0000 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x0c, 8,
			names_dev_redundancy_role, "Device Redundancy Role: %s"),
			(value & 0x0c) >> 2);

	/* Bits 1-2: 0000 0011 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, 0x03, 8,
			names_assigned_redundant_dev_type,
			"Assigned Redundant Device Type: %s"), value & 0x03);

	return;
}



static void
dissect_ff_msg_sm_dev_annunc_req_dup_detection_state(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Duplicate Detection State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req_dup_detection_state);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 3-8: Reserved, set to 0.
	 * Bit 2:    1 = Duplicate PD Tag Detected
	 *           0 = Duplicate PD Tag Not Detected
	 * Bit 1:    1 = Duplicate Device Index Detected
	 *           0 = Duplicate Device Index Not Detected
	 */

	/* Bits 3-8: 1111 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xfc, 8, "Reserved: %u"));

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Duplicate PD Tag Detected",
			"Duplicate PD Tag Not Detected"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Duplicate Device Index Detected",
			"Duplicate Device Index Not Detected"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_sm_dev_annunc_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree, guint32 FDAAddress)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti			= NULL;

	guint8 SMKState	= 0;
	guint8 DeviceType	= 0;
	guint8 DeviceRedundancyState	= 0;
	guint8 DuplicateDetectionState	= 0;
	guint32 NumOfEntriesInVerNumList	= 0;

	guint16 LinkId = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "SM Device Annunciation Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"SM Device Annunciation Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_sm_dev_annunc_req);

	if(!sub_tree) {
		return;
	}

	SMKState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_dev_annunc_req_smk_state(tvb, offset, sub_tree, SMKState);
	offset += 1;
	length -= 1;

	DeviceType = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_dev_annunc_req_dev_type(tvb,
		offset, sub_tree, DeviceType);
	offset += 1;
	length -= 1;

	DeviceRedundancyState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_dev_annunc_req_dev_redundancy_state(tvb,
		offset, sub_tree, DeviceRedundancyState);
	offset += 1;
	length -= 1;

	DuplicateDetectionState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_sm_dev_annunc_req_dup_detection_state(tvb,
		offset, sub_tree, DuplicateDetectionState);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_max_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_operational_ip_addr, tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_dev_id, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_hse_repeat_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_lr_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_annunc_ver_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_hse_dev_ver_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	NumOfEntriesInVerNumList = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_sm_dev_annunc_req_num_of_entries, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(NumOfEntriesInVerNumList) {
		/* 11111111 11111111 00000000 00000000 */
		LinkId = (guint16)(FDAAddress >> 16);
		if(LinkId) {
			dissect_ff_msg_sm_dev_annunc_req_entries_node_addr(tvb,
				offset, sub_tree, NumOfEntriesInVerNumList);
		} else {
			dissect_ff_msg_sm_dev_annunc_req_entries_link_id(tvb,
				offset, sub_tree, NumOfEntriesInVerNumList);
		}

		offset += 4 * NumOfEntriesInVerNumList;
		length -= 4 * NumOfEntriesInVerNumList;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.2.   FMS Initiate (Confirmed Service Id = 96)
 * 6.5.3.2.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_init_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti			= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Initiate Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_req_conn_opt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_req_access_protection_supported_calling,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_req_passwd_and_access_grps_calling,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_req_ver_od_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_req_prof_num_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.2.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_init_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti			= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_rep);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_rsp_ver_od_called, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_rsp_prof_num_called, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.2.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_init_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Initiate Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_init_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.3.   FMS Abort (Unconfirmed Service Id = 112)
 * 6.5.3.3.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_abort_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Abort Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Abort Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_abort_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_text(sub_tree, tvb, offset, 16,
		"Abort Detail (%u bytes)", 16);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_abort_req_abort_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_abort_req_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_abort_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.4.   FMS Status (Confirmed Service Id = 0)
 * 6.5.3.4.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_status_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Status Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Status Request");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_status_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.4.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_status_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Status Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Status Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_status_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_status_rsp_logical_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_status_rsp_physical_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_status_rsp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_text(sub_tree, tvb, offset, 4,
		"Local Detail (%u bytes)", 4);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.4.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_status_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Status Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Status Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_status_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_status_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_status_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_status_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_status_err_additional_desc, tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.5.   FMS Unsolicited Status (Unconfirmed Service Id = 1)
 * 6.5.3.5.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_unsolicited_status_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Unsolicited Status Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Unsolicited Status Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_unsolicited_status_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_unsolicited_status_req_logical_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_unsolicited_status_req_physical_status,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_unsolicited_status_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_text(sub_tree, tvb, offset, 4,
		"Local Detail (%u bytes)", 4);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.6.   FMS Identify (Confirmed Service Id = 1)
 * 6.5.3.6.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_id_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Identify Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Identify Request");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_id_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.6.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_id_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti			= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Identify Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Identify Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_id_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_id_rsp_vendor_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_id_rsp_model_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_id_rsp_revision, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.6.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_id_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Identify Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Identify Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_id_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_id_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_id_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_id_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_id_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.7.   FMS Get OD (Confirmed Service Id = 4)
 * 6.5.3.7.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_get_od_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Get OD Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Get OD Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_get_od_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_req_all_attrs, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_req_start_idx_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.7.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_get_od_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Get OD Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Get OD Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_get_od_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_rsp_more_follows, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_rsp_num_of_obj_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_rsp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"List of Object Descriptions (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.7.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_get_od_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Get OD Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Get OD Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_get_od_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_get_od_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_get_od_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_get_od_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.8.   FMS Initiate Put OD (Confirmed Service Id = 28)
 * 6.5.3.8.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_init_put_od_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Put OD Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Put OD Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_put_od_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_put_od_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_put_od_req_consequence, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.8.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_init_put_od_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Put OD Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Initiate Put OD Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_put_od_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.8.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_init_put_od_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Put OD Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Put OD Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_put_od_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_put_od_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_init_put_od_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_put_od_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_init_put_od_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.9.   FMS Put OD (Confirmed Service Id = 29)
 * 6.5.3.9.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_put_od_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Put OD Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Put OD Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_put_od_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_put_od_req_num_of_obj_desc, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	proto_tree_add_text(sub_tree, tvb, offset, length,
		"List of Object Descriptions (%u bytes)", length);

	return;
}



/*
 * 6.5.3.9.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_put_od_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Put OD Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Put OD Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_put_od_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.9.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_put_od_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Put OD Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Put OD Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_put_od_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_put_od_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_put_od_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_put_od_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_put_od_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.10.   FMS Terminate Put OD (Confirmed Service Id = 30)
 * 6.5.3.10.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_put_od_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Put OD Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Terminate Put OD Request");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_terminate_put_od_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.10.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_put_od_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Put OD Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Terminate Put OD Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_terminate_put_od_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.10.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_put_od_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Put OD Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Terminate Put OD Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_terminate_put_od_err);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_put_od_err_index, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_put_od_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_terminate_put_od_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_put_od_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_put_od_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.11.   FMS Generic Initiate Download Sequence
 *             (Confirmed Service Id = 31)
 * 6.5.3.11.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_generic_init_download_sequence_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Initiate Download Sequence Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Initiate Download Sequence Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_gen_init_download_seq_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_init_download_seq_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.11.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_generic_init_download_sequence_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Initiate Download Sequence Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Generic Initiate Download Sequence Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_gen_init_download_seq_rep);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.11.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_generic_init_download_sequence_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Initiate Download Sequence Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Initiate Download Sequence Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_gen_init_download_seq_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_init_download_seq_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_gen_init_download_seq_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_init_download_seq_err_additional_code,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_init_download_seq_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.12.   FMS Generic Download Segment (Confirmed Service Id = 32)
 * 6.5.3.12.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_generic_download_segment_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Download Segment Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Download Segment Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_gen_download_seg_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_download_seg_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_download_seg_req_more_follows, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Load Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.12.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_generic_download_segment_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Download Segment Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Generic Download Segment Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_gen_download_seg_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.12.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_generic_download_segment_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Download Segment Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Download Segment Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_gen_download_seg_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_download_seg_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_gen_download_seg_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_download_seg_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_download_seg_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.13.   FMS Generic Terminate Download Sequence
 *             (Confirmed Service Id = 33)
 * 6.5.3.13.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_generic_terminate_download_sequence_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO,"FMS Generic Terminate Download Sequence Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Terminate Download Sequence Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_gen_terminate_download_seq_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_terminate_download_seq_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.13.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_generic_terminate_download_sequence_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Terminate Download Sequence Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Terminate Download Sequence Response");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_gen_terminate_download_seq_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_terminate_download_seq_rsp_final_result,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.13.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_generic_terminate_download_sequence_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Generic Terminate Download Sequence Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Generic Terminate Download Sequence Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_gen_terminate_download_seq_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_terminate_download_seq_err_err_class,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_gen_terminate_download_seq_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_terminate_download_seq_err_additional_code,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_gen_terminate_download_seq_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.14.   FMS Initiate Download Sequence (Confirmed Service Id = 9)
 * 6.5.3.14.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_init_download_sequence_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Download Sequence Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Download Sequence Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_init_download_seq_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_download_seq_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.14.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_init_download_sequence_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Download Sequence Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Initiate Download Sequence Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_init_download_seq_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.14.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_init_download_sequence_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Download Sequence Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Download Sequence Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_download_seq_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_download_seq_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_init_download_seq_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_download_seq_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_download_seq_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.15.   FMS Download Segment (Confirmed Service Id = 10)
 * 6.5.3.15.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_download_segment_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Download Segment Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Download Segment Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_download_seg_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_download_seg_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.15.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_download_segment_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Download Segment Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Download Segment Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_download_seg_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_download_seg_rsp_more_follows, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Load Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.15.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_download_segment_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Download Segment Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Download Segment Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_download_seg_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_download_seg_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_download_seg_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_download_seg_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_download_seg_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.16.   FMS Terminate Download Sequence (Confirmed Service Id = 11)
 * 6.5.3.16.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_download_sequence_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Download Sequence Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Terminate Download Sequence Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_terminate_download_seq_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_download_seq_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_download_seq_req_final_result,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.16.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_download_sequence_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Download Sequence Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Terminate Download Sequence Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_terminate_download_seq_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.16.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_download_sequence_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Download Sequence Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Terminate Download Sequence Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_terminate_download_seq_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_download_seq_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_terminate_download_seq_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_download_seq_err_additional_code,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_download_seq_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.17.   FMS Initiate Upload Sequence (Confirmed Service Id = 12)
 * 6.5.3.17.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_init_upload_seq_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Upload Sequence Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Upload Sequence Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_upload_seq_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_upload_seq_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.17.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_init_upload_seq_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Upload Sequence Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Initiate Upload Sequence Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_upload_seq_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.17.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_init_upload_seq_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Initiate Upload Sequence Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Initiate Upload Sequence Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_init_upload_seq_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_upload_seq_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_init_upload_seq_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_init_upload_seq_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_init_upload_seq_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.18.   FMS Upload Segment (Confirmed Service Id = 13)
 * 6.5.3.18.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_upload_segment_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Upload Segment Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Upload Segment Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_upload_seg_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_upload_seg_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.18.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_upload_segment_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Upload Segment Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Upload Segment Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_upload_seg_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_upload_seg_rsp_more_follows, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Final Result (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.18.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_upload_segment_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Upload Segment Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Upload Segment Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_upload_seg_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_upload_seg_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_upload_seg_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_upload_seg_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_upload_seg_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.19.   FMS Terminate Upload Sequence (Confirmed Service Id = 14)
 * 6.5.3.19.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_upload_seq_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Upload Sequence Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Terminate Upload Sequence Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_terminate_upload_seq_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_upload_seq_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.19.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_upload_seq_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Upload Sequence Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Terminate Upload Sequence Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_terminate_upload_seq_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.19.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_terminate_upload_seq_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Terminate Upload Sequence Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Terminate Upload Sequence Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_terminate_upload_seq_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_upload_seq_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_terminate_upload_seq_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_upload_seq_err_additional_code,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_terminate_upload_seq_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.20.   FMS Request Domain Download (Confirmed Service Id = 15)
 * 6.5.3.20.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_req_dom_download_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO,"FMS Request Domain Download Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Request Domain Download Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_req_dom_download_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_download_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_item(sub_tree,
			hf_ff_fms_req_dom_download_req_additional_info,
			tvb, offset, length, ENC_ASCII|ENC_NA);
	}

	return;
}



/*
 * 6.5.3.20.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_req_dom_download_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO,"FMS Request Domain Download Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Request Domain Download Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_req_dom_download_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.20.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_req_dom_download_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Request Domain Download Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Request Domain Download Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_req_dom_download_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_download_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_req_dom_download_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_download_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_download_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.21.   FMS Request Domain Upload (Confirmed Service Id = 16)
 * 6.5.3.21.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_req_dom_upload_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Request Domain Upload Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Request Domain Upload Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_req_dom_upload_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_upload_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_item(sub_tree,
			hf_ff_fms_req_dom_upload_req_additional_info,
			tvb, offset, length, ENC_ASCII|ENC_NA);
	}

	return;
}



/*
 * 6.5.3.21.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_req_dom_upload_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Request Domain Upload Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Request Domain Upload Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_req_dom_upload_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.21.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_req_dom_upload_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Request Domain Upload Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Request Domain Upload Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_req_dom_upload_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_upload_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_req_dom_upload_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_upload_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_req_dom_upload_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.22.   FMS Create Program Invocation (Confirmed Service Id = 17)
 * 6.5.3.22.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_create_pi_req_dom_idxes(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint16 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List Of Domain Indexes (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_create_pi_req_list_of_dom_idxes);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_fms_create_pi_req_dom_idx, tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_fms_create_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint16 NumOfDomIdxes	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Create Program Invocation Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Create Program Invocation Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_create_pi_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_req_reusable, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_req_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	NumOfDomIdxes = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_req_num_of_dom_idxes, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(NumOfDomIdxes) {
		dissect_ff_msg_fms_create_pi_req_dom_idxes(tvb,
			offset, sub_tree, NumOfDomIdxes);

		offset += 4 * NumOfDomIdxes;
		length -= 4 * NumOfDomIdxes;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.22.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_create_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Create Program Invocation Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Create Program Invocation Response");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_create_pi_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_rsp_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.22.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_create_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Create Program Invocation Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Create Program Invocation Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_create_pi_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_create_pi_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_create_pi_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.23.   FMS Delete Program Invocation (Confirmed Service Id = 18)
 * 6.5.3.23.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_del_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO,"FMS Delete Program Invocation Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Delete Program Invocation Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_del_pi_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_pi_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.23.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_del_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Delete Program Invocation Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Delete Program Invocation Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_del_pi_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.23.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_del_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Delete Program Invocation Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Delete Program Invocation Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_del_pi_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_pi_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_del_pi_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_pi_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_pi_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.24.   FMS Start (Confirmed Service Id = 19)
 * 6.5.3.24.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_start_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Start Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Start Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_start_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_start_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Execution Argument (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.24.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_start_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Start Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Start Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_start_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.24.3. PI Error Message Parameters
 */
static void
dissect_ff_msg_fms_start_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Start Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Start Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_start_err);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_start_err_pi_state, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_start_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_start_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_start_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_start_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.25.   FMS Stop (Confirmed Service Id = 20)
 * 6.5.3.25.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_stop_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Stop Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Stop Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_stop_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_stop_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.25.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_stop_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Stop Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Stop Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_stop_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.25.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_stop_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Stop Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Stop Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_stop_err);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_stop_err_pi_state, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_stop_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_stop_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_stop_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_stop_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.26.   FMS Resume (Confirmed Service Id = 21)
 * 6.5.3.26.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_resume_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Resume Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Resume Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_resume_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_resume_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Execution Argument (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.26.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_resume_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Resume Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Resume Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_resume_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.26.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_resume_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Resume Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Resume Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_resume_err);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_resume_err_pi_state, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_resume_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_resume_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_resume_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_resume_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.27.   FMS Reset (Confirmed Service Id = 22)
 * 6.5.3.27.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_reset_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Reset Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Reset Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_reset_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_reset_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.27.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_reset_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Reset Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Reset Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_reset_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.27.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_reset_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Reset Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Reset Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_reset_err);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_reset_err_pi_state, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_reset_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_reset_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_reset_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_reset_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.28.   FMS Kill (Confirmed Service Id = 23)
 * 6.5.3.28.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_kill_pi_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Kill Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Kill Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_kill_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_kill_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.28.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_kill_pi_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Kill Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Kill Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_kill_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.28.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_kill_pi_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Kill Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Kill Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_kill_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_kill_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_kill_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_kill_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_kill_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.29.   FMS Read (Confirmed Service Id = 2)
 * 6.5.3.29.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_read_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Read Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Read Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_read_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.29.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_read_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Read Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Read Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_read_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_text(sub_tree, tvb, offset, length,
		"Data (%u bytes)", length);

	return;
}



/*
 * 6.5.3.29.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_read_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Read Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Read Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_read_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_read_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_read_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.30.   FMS Read with Subindex (Confirmed Service Id = 82)
 * 6.5.3.30.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_read_subindex_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Read with Subindex Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Read with Subindex Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_read_with_subidx_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_with_subidx_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_with_subidx_req_subidx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.30.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_read_subindex_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Read with Subindex Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Read with Subindex Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_read_with_subidx_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_text(sub_tree, tvb, offset, length,
		"Data (%u bytes)", length);

	return;
}



/*
 * 6.5.3.30.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_read_subindex_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Read with Subindex Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Read with Subindex Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_read_with_subidx_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_with_subidx_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_read_with_subidx_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_with_subidx_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_read_with_subidx_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.31.   FMS Write (Confirmed Service Id = 3)
 * 6.5.3.31.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_write_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Write Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Write Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_write_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.31.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_write_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Write Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Write Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_write_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.31.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_write_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Write Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length, "FMS Write Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_write_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_fms_write_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree, hf_ff_fms_write_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.32.   FMS Write with Subindex (Confirmed Service Id = 83)
 * 6.5.3.32.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_write_subindex_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Write with Subindex Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Write with Subindex Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_write_with_subidx_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_with_subidx_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_with_subidx_req_subidx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.32.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_write_subindex_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Write with Subindex Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Write with Subindex Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_write_with_subidx_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.32.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_write_subindex_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Write with Subindex Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Write with Subindex Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_write_with_subidx_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_with_subidx_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_write_with_subidx_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_with_subidx_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_write_with_subidx_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.33.   FMS Define Variable List (Confirmed Service Id = 7)
 * 6.5.3.33.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_def_variable_list_req_list_of_idxes(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List Of Indexes (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_def_variable_list_req_list_of_idxes);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_fms_def_variable_list_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_fms_def_variable_list_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint32 NumOfIndexes	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Define Variable List Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Define Variable List Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_def_variable_list_req);

	if(!sub_tree) {
		return;
	}

	NumOfIndexes = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_def_variable_list_req_num_of_idxes, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(NumOfIndexes) {
		dissect_ff_msg_fms_def_variable_list_req_list_of_idxes(tvb,
			offset, sub_tree, NumOfIndexes);
		offset += 4 * NumOfIndexes;
		length -= 4 * NumOfIndexes;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.33.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_def_variable_list_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Define Variable List Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Define Variable List Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_def_variable_list_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_def_variable_list_rsp_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.33.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_def_variable_list_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Define Variable List Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Define Variable List Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_def_variable_list_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_def_variable_list_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_def_variable_list_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_def_variable_list_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_def_variable_list_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.34.   FMS Delete Variable List (Confirmed Service Id = 8)
 * 6.5.3.34.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_del_variable_list_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Delete Variable List Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Delete Variable List Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_del_variable_list_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_variable_list_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.34.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_del_variable_list_rsp(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Delete Variable List Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Delete Variable List Response");
		sub_tree = proto_item_add_subtree(ti, ett_ff_fms_del_variable_list_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.34.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_del_variable_list_err(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Delete Variable List Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Delete Variable List Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_del_variable_list_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_variable_list_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_del_variable_list_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_variable_list_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_del_variable_list_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.35.   FMS Information Report (Unconfirmed Service Id = 0)
 * 6.5.3.35.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_info_report_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Information Report Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Information Report Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_info_report_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_info_report_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.36.   FMS Information Report with Subindex
 *             (Unconfirmed Service Id = 16)
 * 6.5.3.36.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_info_report_subindex_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Information Report with Subindex Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Information Report with Subindex Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_info_report_with_subidx_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_info_report_with_subidx_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_info_report_with_subidx_req_subidx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.37.   FMS Information Report On Change (Unconfirmed Service Id = 17)
 * 6.5.3.37.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_info_report_change_req(tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Information Report On Change Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Information Report On Change Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_info_report_on_change_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_info_report_on_change_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.38. FMS Information Report On Change with Subindex
 *           (Unconfirmed Service Id = 18)
 * 6.5.3.38.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_info_report_change_subindex_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Information Report On Change with Subindex Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Information Report On Change with Subindex Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_info_report_on_change_with_subidx_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_info_report_on_change_with_subidx_req_idx,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_info_report_on_change_with_subidx_req_subidx,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.39. FMS Event Notification (Unconfirmed Service Id = 2)
 * 6.5.3.39.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_ev_notification_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Event Notification Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Event Notification Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_ev_notification_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_ev_notification_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_ev_notification_req_ev_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"Data (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.40.   FMS Alter Event Condition Monitoring (Confirmed Service Id = 24)
 * 6.5.3.40.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_alter_alter_ev_condition_monitoring_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Alter Event Condition Monitoring Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Alter Event Condition Monitoring Request");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_alter_ev_condition_monitoring_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_alter_ev_condition_monitoring_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_text(sub_tree, tvb, offset, 3, "Reserved (%u bytes)", 3);
	offset += 3;
	length -= 3;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_alter_ev_condition_monitoring_req_enabled,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.40.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_alter_alter_ev_condition_monitoring_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Alter Event Condition Monitoring Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Alter Event Condition Monitoring Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_alter_ev_condition_monitoring_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.40.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_alter_alter_ev_condition_monitoring_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Alter Event Condition Monitoring Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Alter Event Condition Monitoring Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fms_alter_ev_condition_monitoring_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_alter_ev_condition_monitoring_err_err_class,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_alter_ev_condition_monitoring_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_alter_ev_condition_monitoring_err_additional_code,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_alter_ev_condition_monitoring_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.41.   FMS Acknowledge Event Notification (Confirmed Service Id = 25)
 * 6.5.3.41.1. Request Message Parameters
 */
static void
dissect_ff_msg_fms_ack_ev_notification_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Acknowledge Event Notification Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Acknowledge Event Notification Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_ack_ev_notification_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_fms_ack_ev_notification_req_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_ack_ev_notification_req_ev_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.41.2. Response Message Parameters
 */
static void
dissect_ff_msg_fms_ack_ev_notification_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Acknowledge Event Notification Response");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"FMS Acknowledge Event Notification Response");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_fms_ack_ev_notification_rsp);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.3.41.3. Error Message Parameters
 */
static void
dissect_ff_msg_fms_ack_ev_notification_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "FMS Acknowledge Event Notification Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"FMS Acknowledge Event Notification Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fms_ack_ev_notification_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_fms_ack_ev_notification_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_fms_ack_ev_notification_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_ack_ev_notification_err_additional_code,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_fms_ack_ev_notification_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.1. LAN Redundancy Get Information (Confirmed Service Id = 1)
 * 6.5.4.1.1. Request Message Parameters
 */
static void
dissect_ff_msg_lr_get_info_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Get Information Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"LAN Redundancy Get Information Request");
		sub_tree = proto_item_add_subtree(ti,
			ett_ff_lr_get_info_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.1.2. Response Message Parameters
 */
static void
dissect_ff_msg_lr_get_info_rsp_lr_flags(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"LAN Redundancy Flags: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_get_info_rsp_lr_flags);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 6-8: Reserved (not used) = 0
	 * Bit 5:    Load Balancing Enabled
	 *             0 = False Do not do load balancing
	 *             1 = True  Do load balancing
	 * Bit 4:    Diagnosis Using Own Messages Enabled
	 *             0 = False Do not use own diagnostic messages for diagnosis
	 *             1 = True  Use own diagnostic messages for diagnosis
	 * Bit 3:    Single Multicast Message Reception Interface Enabled
	 *             0 = False Listen for multicast addresses
	 *                       on both interfaces
	 *             1 = True  Listen for multicast addresses
	 *                       on one interface
	 *                       if zero or one fault detected
	 *                       in network status table
	 * Bit 2:    Crossed Cable Detection Enabled
	 *             0 = False Do not detect crossed cables
	 *             1 = True  Detect crossed cables
	 * B1 (lsb): Single Multicast Message Transmission Interface Enabled
	 *             0 = False Transmit on both interfaces
	 *             1 = True  Transmit on one interface
	 */

	/* Bits 6-8: 1110 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xe0, 8, "Reserved: %u"));

	/* Bits 5: 0001 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x10, 8,
			"Load Balancing Enabled: True",
			"Load Balancing Enabled: False"),
		(value & 0x10) >> 4);

	/* Bits 4: 0000 1000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x08, 8,
			"Diagnosis Using Own Messages Enabled: True",
			"Diagnosis Using Own Messages Enabled: False"),
		(value & 0x08) >> 3);

	/* Bits 3: 0000 0100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x04, 8,
			"Single Multicast Message Reception Interface Enabled: True",
			"Single Multicast Message Reception Interface Enabled: False"),
		(value & 0x04) >> 2);

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Crossed Cable Detection Enabled: True",
			"Crossed Cable Detection Enabled: False"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Single Multicast Message Transmission Interface Enabled: True",
			"Single Multicast Message Transmission Interface Enabled: False"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_lr_get_info_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 MaxMsgNumDiff	= 0;
	guint8 LRFlags	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Get Information Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Get Information Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_get_info_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_lr_attrs_ver, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	MaxMsgNumDiff = tvb_get_guint8(tvb, offset);
	switch(MaxMsgNumDiff) {
		case 0:
		case 1:
			proto_tree_add_uint_format(sub_tree,
				hf_ff_lr_get_info_rsp_lr_max_msg_num_diff,
				tvb, offset, 1, MaxMsgNumDiff,
				"Max Message Number Difference: Do not detect a fault (%u)",
				MaxMsgNumDiff);
			break;

		default:
			proto_tree_add_item(sub_tree,
				hf_ff_lr_get_info_rsp_lr_max_msg_num_diff,
				tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;
	length -= 1;

	LRFlags = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_lr_get_info_rsp_lr_flags(tvb, offset, sub_tree, LRFlags);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_diagnostic_msg_intvl, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_aging_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_diagnostic_msg_if_a_send_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_diagnostic_msg_if_a_recv_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_diagnostic_msg_if_b_send_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_rsp_diagnostic_msg_if_b_recv_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.1.3. Error Message Parameters
 */
static void
dissect_ff_msg_lr_get_info_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Get Information Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Get Information Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_get_info_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_lr_get_info_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_info_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.2. LAN Redundancy Put Information (Confirmed Service Id = 2)
 * 6.5.4.2.1. Request Message Parameters
 */
static void
dissect_ff_msg_lr_put_info_req_lr_flags(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"LAN Redundancy Flags: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_put_info_req_lr_flags);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 6-8: Reserved (not used) = 0
	 * Bit 5:    Load Balancing Enabled
	 *             0 = False Do not do load balancing
	 *             1 = True  Do load balancing
	 * Bit 4:    Diagnosis Using Own Messages Enabled
	 *             0 = False Do not use own diagnostic messages for diagnosis
	 *             1 = True  Use own diagnostic messages for diagnosis
	 * Bit 3:    Single Multicast Message Reception Interface Enabled
	 *             0 = False Listen for multicast addresses
	 *                       on both interfaces
	 *             1 = True  Listen for multicast addresses
	 *                       on one interface
	 *                       if zero or one fault detected
	 *                       in network status table
	 * Bit 2:    Crossed Cable Detection Enabled
	 *             0 = False Do not detect crossed cables
	 *             1 = True  Detect crossed cables
	 * B1 (lsb): Single Multicast Message Transmission Interface Enabled
	 *             0 = False Transmit on both interfaces
	 *             1 = True  Transmit on one interface
	 */

	/* Bits 6-8: 1110 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xe0, 8, "Reserved: %u"));

	/* Bits 5: 0001 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x10, 8,
			"Load Balancing Enabled: True",
			"Load Balancing Enabled: False"),
		(value & 0x10) >> 4);

	/* Bits 4: 0000 1000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x08, 8,
			"Diagnosis Using Own Messages Enabled: True",
			"Diagnosis Using Own Messages Enabled: False"),
		(value & 0x08) >> 3);

	/* Bits 3: 0000 0100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x04, 8,
			"Single Multicast Message Reception Interface Enabled: True",
			"Single Multicast Message Reception Interface Enabled: False"),
		(value & 0x04) >> 2);

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Crossed Cable Detection Enabled: True",
			"Crossed Cable Detection Enabled: False"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Single Multicast Message Transmission Interface Enabled: True",
			"Single Multicast Message Transmission Interface Enabled: False"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_lr_put_info_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 MaxMsgNumDiff	= 0;
	guint8 LRFlags	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Put Information Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Put Information Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_put_info_req);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_lr_attrs_ver, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	MaxMsgNumDiff = tvb_get_guint8(tvb, offset);
	switch(MaxMsgNumDiff) {
		case 0:
		case 1:
			proto_tree_add_uint_format(sub_tree,
				hf_ff_lr_put_info_req_lr_max_msg_num_diff,
				tvb, offset, 1, MaxMsgNumDiff,
				"Max Message Number Difference: Do not detect a fault (%u)",
				MaxMsgNumDiff);
			break;

		default:
			proto_tree_add_item(sub_tree,
				hf_ff_lr_put_info_req_lr_max_msg_num_diff,
				tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;
	length -= 1;

	LRFlags = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_lr_put_info_req_lr_flags(tvb, offset, sub_tree, LRFlags);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_diagnostic_msg_intvl, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_aging_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_diagnostic_msg_if_a_send_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_diagnostic_msg_if_a_recv_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_diagnostic_msg_if_b_send_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_req_diagnostic_msg_if_b_recv_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.2.2. Response Message Parameters
 */
static void
dissect_ff_msg_lr_put_info_rsp_lr_flags(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"LAN Redundancy Flags: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_put_info_rsp_lr_flags);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 6-8: Reserved (not used) = 0
	 * Bit 5:    Load Balancing Enabled
	 *             0 = False Do not do load balancing
	 *             1 = True  Do load balancing
	 * Bit 4:    Diagnosis Using Own Messages Enabled
	 *             0 = False Do not use own diagnostic messages for diagnosis
	 *             1 = True  Use own diagnostic messages for diagnosis
	 * Bit 3:    Single Multicast Message Reception Interface Enabled
	 *             0 = False Listen for multicast addresses
	 *                       on both interfaces
	 *             1 = True  Listen for multicast addresses
	 *                       on one interface
	 *                       if zero or one fault detected
	 *                       in network status table
	 * Bit 2:    Crossed Cable Detection Enabled
	 *             0 = False Do not detect crossed cables
	 *             1 = True  Detect crossed cables
	 * B1 (lsb): Single Multicast Message Transmission Interface Enabled
	 *             0 = False Transmit on both interfaces
	 *             1 = True  Transmit on one interface
	 */

	/* Bits 6-8: 1110 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xe0, 8, "Reserved: %u"));

	/* Bits 5: 0001 0000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x10, 8,
			"Load Balancing Enabled: True",
			"Load Balancing Enabled: False"),
		(value & 0x10) >> 4);

	/* Bits 4: 0000 1000 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x08, 8,
			"Diagnosis Using Own Messages Enabled: True",
			"Diagnosis Using Own Messages Enabled: False"),
		(value & 0x08) >> 3);

	/* Bits 3: 0000 0100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x04, 8,
			"Single Multicast Message Reception Interface Enabled: True",
			"Single Multicast Message Reception Interface Enabled: False"),
		(value & 0x04) >> 2);

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Crossed Cable Detection Enabled: True",
			"Crossed Cable Detection Enabled: False"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Single Multicast Message Transmission Interface Enabled: True",
			"Single Multicast Message Transmission Interface Enabled: False"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_lr_put_info_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 MaxMsgNumDiff	= 0;
	guint8 LRFlags	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Put Information Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Put Information Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_put_info_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_lr_attrs_ver, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	MaxMsgNumDiff = tvb_get_guint8(tvb, offset);
	switch(MaxMsgNumDiff) {
		case 0:
		case 1:
			proto_tree_add_uint_format(sub_tree,
				hf_ff_lr_put_info_rsp_lr_max_msg_num_diff,
				tvb, offset, 1, MaxMsgNumDiff,
				"Max Message Number Difference: Do not detect a fault (%u)",
				MaxMsgNumDiff);
			break;

		default:
			proto_tree_add_item(sub_tree,
				hf_ff_lr_put_info_rsp_lr_max_msg_num_diff,
				tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;
	length -= 1;

	LRFlags = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_lr_put_info_rsp_lr_flags(tvb, offset, sub_tree, LRFlags);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_diagnostic_msg_intvl, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_aging_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_diagnostic_msg_if_a_send_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_diagnostic_msg_if_a_recv_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_diagnostic_msg_if_b_send_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_rsp_diagnostic_msg_if_b_recv_addr,
		tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.2.3. Error Message Parameters
 */
static void
dissect_ff_msg_lr_put_info_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Put Information Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Put Information Error");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_put_info_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree, hf_ff_lr_put_info_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_put_info_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.3. LAN Redundancy Get Statistics (Confirmed Service Id = 3)
 * 6.5.4.3.1. Request Message Parameters
 */
static void
dissect_ff_msg_lr_get_statistics_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Get Statistics Request");

	if(!tree) {
		return;
	}

	if(length) {
		ti = proto_tree_add_text(tree, tvb, offset, length,
			"LAN Redundancy Get Statistics Request");
		sub_tree = proto_item_add_subtree(ti, ett_ff_lr_get_statistics_req);

		if(!sub_tree) {
			return;
		}

		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.3.2. Response Message Parameters
 */
static void
dissect_ff_msg_lr_get_statistics_rsp_x_cable_stat(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List of Crossed Cable Status (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_get_statistics_rsp_list_of_x_cable_stat);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_lr_get_statistics_rsp_x_cable_stat, tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_lr_get_statistics_rsp(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint32 NumXcableStat;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Get Statistics Response");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Get Statistics Response");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_get_statistics_rsp);

	if(!sub_tree) {
		return;
	}

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_recv_a,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_miss_a,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_rem_dev_diag_recv_fault_a,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_recv_b,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_miss_b,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_rem_dev_diag_recv_fault_b,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	NumXcableStat = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_rsp_num_x_cable_stat, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	if(NumXcableStat) {
		dissect_ff_msg_lr_get_statistics_rsp_x_cable_stat(tvb,
			offset, sub_tree, NumXcableStat);
		offset += 4 * NumXcableStat;
		length -= 4 * NumXcableStat;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.3.3. Error Message Parameters
 */
static void
dissect_ff_msg_lr_get_statistics_err(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint8 ErrorClass	= 0;
	guint8 ErrorCode	= 0;
	const char *error_code	= NULL;

	col_set_str(pinfo->cinfo, COL_INFO, "LAN Redundancy Get Statistics Error");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"LAN Redundancy Get Statistics Error");
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_get_statistics_err);

	if(!sub_tree) {
		return;
	}

	ErrorClass = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_err_err_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	ErrorCode = tvb_get_guint8(tvb, offset);
	error_code = val_to_str_err_code(ErrorClass, ErrorCode);
	proto_tree_add_uint_format(sub_tree,
		hf_ff_lr_get_statistics_err_err_code,
		tvb, offset, 1, ErrorCode,
		"Error Code: %s (%u)", error_code, ErrorCode);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_err_additional_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_get_statistics_err_additional_desc,
		tvb, offset, 16, ENC_ASCII|ENC_NA);
	offset += 16;
	length -= 16;

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5.4.4.   Diagnostic Message (Unconfirmed Service Id = 1)
 * 6.5.4.4.1. Request Message Parameters
 */
static void
dissect_ff_msg_diagnostic_msg_req_dup_detection_stat(tvbuff_t *tvb,
        gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Duplicate Detection State: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_diagnostic_msg_req_dup_detection_stat);

	if(!sub_tree) {
		return;
	}

	/*
	 * Bits 3-8: Reserved, set to 0.
	 * Bit 2:    1 = Duplicate PD Tag Detected
	 *           0 = Duplicate PD Tag Not Detected
	 * Bit 18:   1 = Duplicate Device Index Detected
	 *           0 = Duplicate Device Index Not Detected
	 */

	/* Bits 3-8: 1111 1100 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, 0xfc, 8, "Reserved: %u"));

	/* Bits 2: 0000 0010 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x02, 8,
			"Duplicate PD Tag Detected",
			"Duplicate PD Tag Not Detected"),
		(value & 0x02) >> 1);

	/* Bits 1: 0000 0001 */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, 0x01, 8,
			"Duplicate Device Index Detected",
			"Duplicate Device Index Not Detected"),
		value & 0x01);

	return;
}



static void
dissect_ff_msg_diagnostic_msg_req_if_a_to_a_status(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List of Interface AtoA Statuses (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_diagnostic_msg_req_a_to_a_status);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_lr_diagnostic_msg_req_if_a_to_a_status,
			tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_diagnostic_msg_req_if_b_to_a_status(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List of Interface BtoA Statuses (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_diagnostic_msg_req_b_to_a_status);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_lr_diagnostic_msg_req_if_b_to_a_status,
			tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_diagnostic_msg_req_if_a_to_b_status(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List of Interface AtoB Statuses (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_diagnostic_msg_req_a_to_b_status);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_lr_diagnostic_msg_req_if_a_to_b_status,
			tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_diagnostic_msg_req_if_b_to_b_status(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint32 value)
{
	proto_tree *sub_tree    = NULL;
	proto_item *ti  = NULL;
	guint d = 0;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 4 * value,
		"List of Interface BtoB Statuses (%u bytes)", 4 * value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_lr_diagnostic_msg_req_b_to_b_status);

	if(!sub_tree) {
		return;
	}

	for(d = 0; d < value; d ++) {
		proto_tree_add_item(sub_tree,
			hf_ff_lr_diagnostic_msg_req_if_b_to_b_status,
			tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return;
}



static void
dissect_ff_msg_diagnostic_msg_req(
	tvbuff_t *tvb, gint offset,
	guint32 length, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	guint16 DeviceIndex	= 0;
	guint8 DuplicateDetectionState	= 0;
	guint16 NumOfInterfaceStatuses	= 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Diagnostic Message Request");

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, length,
		"Diagnostic Message Request");
	sub_tree = proto_item_add_subtree(ti, ett_ff_lr_diagnostic_msg_req);

	if(!sub_tree) {
		return;
	}

	DeviceIndex = tvb_get_ntohs(tvb, offset);
	if(DeviceIndex) {
		proto_tree_add_item(sub_tree,
			hf_ff_lr_diagnostic_msg_req_dev_idx, tvb, offset, 2, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_uint_format(sub_tree,
			hf_ff_lr_diagnostic_msg_req_dev_idx,
			tvb, offset, 2, DeviceIndex,
			"Device Index: Index not assigned (%u)", DeviceIndex);
	}
	offset += 2;
	length -= 2;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_diagnostic_msg_req_num_of_network_ifs,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_diagnostic_msg_req_transmission_if, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_diagnostic_msg_req_diagnostic_msg_intvl,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_diagnostic_msg_req_pd_tag, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;
	length -= 32;

	proto_tree_add_item(sub_tree,
		hf_ff_lr_diagnostic_msg_req_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	DuplicateDetectionState = tvb_get_guint8(tvb, offset);
	dissect_ff_msg_diagnostic_msg_req_dup_detection_stat(tvb,
		offset, sub_tree, DuplicateDetectionState);
	offset += 1;
	length -= 1;

	NumOfInterfaceStatuses = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(sub_tree,
		hf_ff_lr_diagnostic_msg_req_num_of_if_statuses, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	if(NumOfInterfaceStatuses) {
		dissect_ff_msg_diagnostic_msg_req_if_a_to_a_status(tvb,
			offset, sub_tree, NumOfInterfaceStatuses);
		offset += 4 * NumOfInterfaceStatuses;
		length -= 4 * NumOfInterfaceStatuses;

		dissect_ff_msg_diagnostic_msg_req_if_b_to_a_status(tvb,
			offset, sub_tree, NumOfInterfaceStatuses);
		offset += 4 * NumOfInterfaceStatuses;
		length -= 4 * NumOfInterfaceStatuses;

		dissect_ff_msg_diagnostic_msg_req_if_a_to_b_status(tvb,
			offset, sub_tree, NumOfInterfaceStatuses);
		offset += 4 * NumOfInterfaceStatuses;
		length -= 4 * NumOfInterfaceStatuses;

		dissect_ff_msg_diagnostic_msg_req_if_b_to_b_status(tvb,
			offset, sub_tree, NumOfInterfaceStatuses);
		offset += 4 * NumOfInterfaceStatuses;
		length -= 4 * NumOfInterfaceStatuses;
	}

	if(length) {
		proto_tree_add_text(sub_tree, tvb, offset, length,
			"[Unknown] (%u bytes)", length);
	}

	return;
}



/*
 * 6.5. Service-Specific Parameters
 */
static void
dissect_ff_msg_body(tvbuff_t *tvb, gint offset, guint32 length,
	packet_info *pinfo, proto_tree *tree,
	guint8 ProtocolAndType, guint8 Service, guint32 FDAAddress)
{
	proto_item *hidden_item;
	guint16 message = 0;

	message = ((guint16)ProtocolAndType) << 8;
	message |= (guint16)Service;

	switch(message) {
		case FDA_MSG_SESSION_OPEN_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_open_sess, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_open_sess_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fda_open_sess_req(tvb, offset, length,
				pinfo, tree);
			break;

		case FDA_MSG_SESSION_OPEN_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_open_sess, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_open_sess_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fda_open_sess_rsp(tvb, offset, length,
				pinfo, tree);
			break;

		case FDA_MSG_SESSION_OPEN_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_open_sess, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_open_sess_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fda_open_sess_err(tvb, offset, length,
				pinfo, tree);
			break;

		case FDA_MSG_SESSION_IDLE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_idle, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_idle_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fda_idle_req(tvb, offset, length,
				pinfo, tree);
			break;

		case FDA_MSG_SESSION_IDLE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_idle, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_idle_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fda_idle_rsp(tvb, offset, length,
				pinfo, tree);
			break;

		case FDA_MSG_SESSION_IDLE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_idle, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fda_idle_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fda_idle_err(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_FIND_TAG_QUERY_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_find_tag_query, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_find_tag_query_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_find_tag_query_req(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_FIND_TAG_REPLY_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_find_tag_reply, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_find_tag_reply_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_find_tag_reply_req(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_IDENTIFY_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_id, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_id_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_id_req(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_IDENTIFY_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_id, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_id_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_id_rsp(tvb, offset, length,
				pinfo, tree, FDAAddress);
			break;

		case SM_MSG_IDENTIFY_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_id, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_id_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_id_err(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_CLEAR_ADDRESS_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_addr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_addr_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_clear_addr_req(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_CLEAR_ADDRESS_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_addr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_addr_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_clear_addr_rsp(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_CLEAR_ADDRESS_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_addr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_addr_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_clear_addr_err(tvb, offset, length,
				pinfo, tree);
			break;

		case SM_MSG_SET_ASSIGNMENT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_set_assign_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_set_assign_info_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_set_assign_info_req(tvb, offset,
				length, pinfo, tree);
			break;

		case SM_MSG_SET_ASSIGNMENT_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_set_assign_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_set_assign_info_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_set_assign_info_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case SM_MSG_SET_ASSIGNMENT_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_set_assign_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_set_assign_info_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_set_assign_info_err(tvb, offset,
				length, pinfo, tree);
			break;

		case SM_MSG_CLEAR_ASSIGNMENT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_assign_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_assign_info_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_clear_assign_info_req(tvb, offset,
				length, pinfo, tree);
			break;

		case SM_MSG_CLEAR_ASSIGNMENT_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_assign_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_assign_info_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_clear_assign_info_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case SM_MSG_CLEAR_ASSIGNMENT_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_assign_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_clear_assign_info_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_clear_assign_info_err(tvb, offset,
				length, pinfo, tree);
			break;

		case SM_MSG_DEVICE_ANNUNCIATION_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_dev_annunc, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_sm_dev_annunc_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_sm_dev_annunc_req(tvb, offset,
				length, pinfo, tree, FDAAddress);
			break;

		case FMS_MSG_INITIATE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_ABORT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_abort, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_abort_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_abort_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_STATUS_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_status, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_status_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_status_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_STATUS_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_status, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_status_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_status_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_STATUS_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_status, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_status_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_status_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_UNSOLICITED_STATUS_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_unsolicited_status, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_unsolicited_status_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_unsolicited_status_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_IDENTIFY_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_id, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_id_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_id_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_IDENTIFY_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_id, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_id_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_id_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_IDENTIFY_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_id, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_id_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_id_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_GET_OD_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_get_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_get_od_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_get_od_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_GET_OD_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_get_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_get_od_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_get_od_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_GET_OD_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_get_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_get_od_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_get_od_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_PUT_OD_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_put_od_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_put_od_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_PUT_OD_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_put_od_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_put_od_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_PUT_OD_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_put_od_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_put_od_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_PUT_OD_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_put_od_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_put_od_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_PUT_OD_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_put_od_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_put_od_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_PUT_OD_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_put_od_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_put_od_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_PUT_OD_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_put_od_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_put_od_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_PUT_OD_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_put_od_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_put_od_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_PUT_OD_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_put_od, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_put_od_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_put_od_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_INITIATE_DOWNLOAD_SEQUENCE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_init_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_init_download_seq_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_init_download_sequence_req(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_INITIATE_DOWNLOAD_SEQUENCE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_init_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_init_download_seq_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_init_download_sequence_rsp(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_INITIATE_DOWNLOAD_SEQUENCE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_init_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_init_download_seq_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_init_download_sequence_err(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_DOWNLOAD_SEGMENT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_download_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_download_seg_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_download_segment_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_DOWNLOAD_SEGMENT_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_download_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_download_seg_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_download_segment_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_DOWNLOAD_SEGMENT_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_download_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_download_seg_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_download_segment_err(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_TERMINATE_DOWNLOAD_SEQUENCE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_terminate_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_terminate_download_seq_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_terminate_download_sequence_req(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_TERMINATE_DOWNLOAD_SEQUENCE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_terminate_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_terminate_download_seq_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_terminate_download_sequence_rsp(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_GENERIC_TERMINATE_DOWNLOAD_SEQUENCE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_terminate_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_gen_terminate_download_seq_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_generic_terminate_download_sequence_err(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_DOWNLOAD_SEQUENCE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_download_seq_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_download_sequence_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_DOWNLOAD_SEQUENCE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_download_seq_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_download_sequence_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_DOWNLOAD_SEQUENCE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_download_seq_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_download_sequence_err(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_DOWNLOAD_SEGMENT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_download_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_download_seg_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_download_segment_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DOWNLOAD_SEGMENT_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_download_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_download_seg_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_download_segment_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DOWNLOAD_SEGMENT_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_download_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_download_seg_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_download_segment_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_DOWNLOAD_SEQUENCE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_download_seq_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_download_sequence_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_DOWNLOAD_SEQUENCE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_download_seq_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_download_sequence_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_DOWNLOAD_SEQUENCE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_download_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_download_seq_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_download_sequence_err(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_UPLOAD_SEQUENCE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_upload_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_upload_seq_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_upload_seq_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_UPLOAD_SEQUENCE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_upload_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_upload_seq_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_upload_seq_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_INITIATE_UPLOAD_SEQUENCE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_upload_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_init_upload_seq_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_init_upload_seq_err(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_UPLOAD_SEGMENT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_upload_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_upload_seg_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_upload_segment_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_UPLOAD_SEGMENT_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_upload_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_upload_seg_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_upload_segment_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_UPLOAD_SEGMENT_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_upload_seg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_upload_seg_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_upload_segment_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_UPLOAD_SEQUENCE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_upload_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_upload_seq_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_upload_seq_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_UPLOAD_SEQUENCE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_upload_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_upload_seq_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_upload_seq_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_TERMINATE_UPLOAD_SEQUENCE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_upload_seq, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_terminate_upload_seq_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_terminate_upload_seq_err(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_REQUEST_DOMAIN_DOWNLOAD_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_download, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_download_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_req_dom_download_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_REQUEST_DOMAIN_DOWNLOAD_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_download, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_download_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_req_dom_download_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_REQUEST_DOMAIN_DOWNLOAD_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_download, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_download_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_req_dom_download_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_REQUEST_DOMAIN_UPLOAD_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_upload, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_upload_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_req_dom_upload_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_REQUEST_DOMAIN_UPLOAD_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_upload, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_upload_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_req_dom_upload_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_REQUEST_DOMAIN_UPLOAD_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_upload, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_req_dom_upload_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_req_dom_upload_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_CREATE_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_create_pi, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_create_pi_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_create_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_CREATE_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_create_pi, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_create_pi_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_create_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_CREATE_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_create_pi, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_create_pi_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_create_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DELETE_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_pi, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_pi_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_del_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DELETE_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_pi, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_pi_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_del_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DELETE_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_pi, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_pi_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_del_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_START_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_start, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_start_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_start_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_START_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_start, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_start_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_start_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_START_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_start, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_start_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_start_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_STOP_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_stop, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_stop_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_stop_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_STOP_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_stop, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_stop_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_stop_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_STOP_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_stop, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_stop_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_stop_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_RESUME_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_resume, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_resume_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_resume_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_RESUME_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_resume, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_resume_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_resume_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_RESUME_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_resume, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_resume_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_resume_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_RESET_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_reset, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_reset_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_reset_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_RESET_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_reset, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_reset_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_reset_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_RESET_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_reset, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_reset_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_reset_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_KILL_PI_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_kill, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_kill_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_kill_pi_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_KILL_PI_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_kill, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_kill_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_kill_pi_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_KILL_PI_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_kill, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_kill_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_kill_pi_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_READ_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_read_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_READ_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_read_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_READ_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_read_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_READ_SUBINDEX_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_with_subidx_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_read_subindex_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_READ_SUBINDEX_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_with_subidx_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_read_subindex_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_READ_SUBINDEX_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_read_with_subidx_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_read_subindex_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_WRITE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_write_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_WRITE_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_write_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_WRITE_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_write_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_WRITE_SUBINDEX_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_with_subidx_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_write_subindex_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_WRITE_SUBINDEX_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_with_subidx_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_write_subindex_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_WRITE_SUBINDEX_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_write_with_subidx_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_write_subindex_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DEFINE_VARIABLE_LIST_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_def_variable_list, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_def_variable_list_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_def_variable_list_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DEFINE_VARIABLE_LIST_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_def_variable_list, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_def_variable_list_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_def_variable_list_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DEFINE_VARIABLE_LIST_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_def_variable_list, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_def_variable_list_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_def_variable_list_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DELETE_VARIABLE_LIST_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_variable_list, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_variable_list_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_del_variable_list_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DELETE_VARIABLE_LIST_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_variable_list, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_variable_list_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_del_variable_list_rsp(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_DELETE_VARIABLE_LIST_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_variable_list, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_del_variable_list_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_del_variable_list_err(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INFO_REPORT_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_info_report_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INFO_REPORT_SUBINDEX_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_with_subidx_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_info_report_subindex_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INFO_REPORT_CHANGE_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_on_change, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_on_change_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_info_report_change_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_INFO_REPORT_CHANGE_SUBINDEX_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_on_change_with_subidx, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_info_report_on_change_with_subidx_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_info_report_change_subindex_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_EVENT_NOTIFICATION_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ev_notification, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ev_notification_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_ev_notification_req(tvb, offset,
				length, pinfo, tree);
			break;

		case FMS_MSG_ALTER_EVENT_CONDITION_MONITORING_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_alter_ev_condition_monitoring, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_alter_ev_condition_monitoring_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_alter_alter_ev_condition_monitoring_req(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_ALTER_EVENT_CONDITION_MONITORING_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_alter_ev_condition_monitoring, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_alter_ev_condition_monitoring_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_alter_alter_ev_condition_monitoring_rsp(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_ALTER_EVENT_CONDITION_MONITORING_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_alter_ev_condition_monitoring, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_alter_ev_condition_monitoring_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_alter_alter_ev_condition_monitoring_err(
				tvb, offset, length, pinfo, tree);
			break;

		case FMS_MSG_ACKNOWLEDGE_EVENT_NOTIFICATION_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ack_ev_notification, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ack_ev_notification_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_ack_ev_notification_req(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_ACKNOWLEDGE_EVENT_NOTIFICATION_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ack_ev_notification, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ack_ev_notification_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_ack_ev_notification_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case FMS_MSG_ACKNOWLEDGE_EVENT_NOTIFICATION_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ack_ev_notification, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_fms_ack_ev_notification_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_fms_ack_ev_notification_err(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_GET_INFO_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_info_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_get_info_req(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_GET_INFO_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_info_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_get_info_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_GET_INFO_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_info_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_get_info_err(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_PUT_INFO_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_put_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_put_info_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_put_info_req(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_PUT_INFO_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_put_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_put_info_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_put_info_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_PUT_INFO_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_put_info, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_put_info_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_put_info_err(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_GET_STATISTICS_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_statistics, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_statistics_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_get_statistics_req(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_GET_STATISTICS_RSP:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_statistics, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_statistics_rsp, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_get_statistics_rsp(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_GET_STATISTICS_ERR:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_statistics, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_get_statistics_err, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_lr_get_statistics_err(tvb,
				offset, length, pinfo, tree);
			break;

		case LAN_MSG_DIAG_REQ:
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_diagnostic_msg, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			hidden_item = proto_tree_add_boolean(tree,
					hf_ff_lr_diagnostic_msg_req, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			dissect_ff_msg_diagnostic_msg_req(tvb,
				offset, length, pinfo, tree);
			break;

		default:
			if(check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO,
				"Unknown Service (Protocol Id: %u, Confirmed Msg Type: %u) "
				"(%s Service Id = %u)",
				(ProtocolAndType & PROTOCOL_MASK) >> 2,
				ProtocolAndType & TYPE_MASK,
				(Service & SERVICE_CONFIRMED_FLAG_MASK)?
					"Confirmed": "Unconfirmed",
				Service & SERVICE_SERVICE_ID_MASK);
			}

			if(length) {
				proto_tree_add_text(tree, tvb, offset, length,
					"[Unknown Service] (%u bytes)", length);
			}
	}

	return;
}



/*
 * 6.4. Message Trailer
 */
static int
dissect_ff_msg_trailer(tvbuff_t *tvb,
	gint offset, guint32 length, proto_tree *tree, guint8 Options)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	proto_item *hidden_item;

	if(!tree) {
		return 0;
	}

	hidden_item = proto_tree_add_boolean(tree, hf_ff_fda_msg_trailer, tvb, 0, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	ti = proto_tree_add_text(tree,
		tvb, offset, length, "FDA Message Trailer");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_msg_trailer);

	if(!sub_tree) {
		return 0;
	}

	if(Options & OPTION_MESSAGE_NUMBER_MASK) {
		proto_tree_add_item(sub_tree,
			hf_ff_fda_msg_trailer_msg_num, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if(Options & OPTION_INVOKE_ID_MASK) {
		proto_tree_add_item(sub_tree,
			hf_ff_fda_msg_trailer_invoke_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if(Options & OPTION_TIME_STAMP_MASK) {
		proto_tree_add_item(sub_tree,
			hf_ff_fda_msg_trailer_time_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}

	if(Options & OPTION_EXTENDED_CNTRL_MASK) {
		proto_tree_add_item(sub_tree,
			hf_ff_fda_msg_trailer_extended_control_field,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	return offset;
}



/*
 * Service
 */

static void
dissect_ff_msg_hdr_srv(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 proto_and_type, guint8 service)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1, "Service: 0x%02x", service);
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_msg_hdr_srv);

	if(!sub_tree) {
		return;
	}

	/* Bit 8: Confirmed Flag */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(service, SERVICE_CONFIRMED_FLAG_MASK, 8,
			"Confirmed Flag: Confirmed",
			"Confirmed Flag: Unconfirmed"),
		(service & SERVICE_CONFIRMED_FLAG_MASK) >> 7);

	/* Bits 1-7 Service Id of the service */
	switch(proto_and_type & PROTOCOL_MASK) {
		case PROTOCOL_FDA:
			if(service & SERVICE_CONFIRMED_FLAG_MASK) {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_fda_confirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			} else {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_fda_unconfirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			}

			break;

		case PROTOCOL_SM:
			if(service & SERVICE_CONFIRMED_FLAG_MASK) {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_sm_confirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			} else {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_sm_unconfirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			}

			break;

		case PROTOCOL_FMS:
			if(service & SERVICE_CONFIRMED_FLAG_MASK) {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_fms_confirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			} else {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_fms_unconfirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			}

			break;

		case PROTOCOL_LAN:
			if(service & SERVICE_CONFIRMED_FLAG_MASK) {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_lan_confirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			} else {
				proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
					decode_enumerated_bitfield(service,
						SERVICE_SERVICE_ID_MASK, 8,
						names_lan_unconfirmed, "Service Id: %s"),
					service & SERVICE_SERVICE_ID_MASK);
			}

			break;

		default:
			proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
				decode_numeric_bitfield(service, SERVICE_SERVICE_ID_MASK, 8,
					"Service Id: Unknown (%u)"));
	}

	return;
}



/*
 * Protocol Id And Confirmed Msg Type
 */

static void
dissect_ff_msg_hdr_proto_and_type(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1,
		"Protocol Id And Confirmed Msg Type: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti,
		ett_ff_fda_msg_hdr_proto_and_type);

	if(!sub_tree) {
		return;
	}

	/* Bits 3 - 8: Protocol Id */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, PROTOCOL_MASK, 8,
			names_proto, "Protocol Id: %s"), (value & PROTOCOL_MASK) >> 2);

	/* Bits 1, 2: Confirmed Msg Type */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, TYPE_MASK, 8,
			names_type, "Confirmed Msg Type: %s"), value & TYPE_MASK);

	return;
}



/*
 * Options
 */

static void
dissect_ff_msg_hdr_opts(tvbuff_t *tvb,
	gint offset, proto_tree *tree, guint8 value)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;

	if(!tree) {
		return;
	}

	ti = proto_tree_add_text(tree, tvb, offset, 1, "Options: 0x%02x", value);
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_msg_hdr_opts);

	if(!sub_tree) {
		return;
	}

	/* Bit 8:   1 = Message Number present in the Trailer */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, OPTION_MESSAGE_NUMBER_MASK, 8,
			"Message Number present in the Trailer",
			"Message Number not present in the Trailer"),
		(value & OPTION_MESSAGE_NUMBER_MASK) >> 7);

	/* Bit 7:   1 = Invoke Id present in the Trailer */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, OPTION_INVOKE_ID_MASK, 8,
			"Invoke Id present in the Trailer",
			"Invoke Id not present in the Trailer"),
		(value & OPTION_INVOKE_ID_MASK) >> 6);

	/* Bit 6:   1 = Time Stamp present in the Trailer */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, OPTION_TIME_STAMP_MASK, 8,
			"Time Stamp present in the Trailer",
			"Time Stamp not present in the Trailer"),
		(value & OPTION_TIME_STAMP_MASK) >> 5);

	/* Bit 5:   Reserved */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s",
		decode_numeric_bitfield(value, OPTION_RESERVED_MASK, 8,
			"Reserved: %u"));

	/* Bit 4:   1 = Extended Control Field present in the Trailer */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_boolean_bitfield(value, OPTION_EXTENDED_CNTRL_MASK, 8,
			"Extended Control Field present in the Trailer",
			"Extended Control Field not present in the Trailer"),
		(value & OPTION_EXTENDED_CNTRL_MASK) >> 3);

	/*  Bits1-3: Pad Length */
	proto_tree_add_text(sub_tree, tvb, offset, 1, "%s (%u)",
		decode_enumerated_bitfield(value, OPTION_PAD_LENGTH_MASK, 8,
			names_pad_len, "Pad Length: %s"),
			value & OPTION_PAD_LENGTH_MASK);

	return;
}



/*
 * 6.3. Message Header
 */
static int
dissect_ff_msg_hdr(tvbuff_t *tvb,
	proto_tree *tree, guint8 Options, guint8 ProtocolAndType, guint8 Service)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	proto_item *hidden_item;
	gint offset	= 0;

	if(!tree) {
		return 0;
	}

	hidden_item = proto_tree_add_boolean(tree, hf_ff_fda_msg_hdr, tvb, 0, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	ti = proto_tree_add_text(tree,
		tvb, offset, 12, "FDA Message Header");
	sub_tree = proto_item_add_subtree(ti, ett_ff_fda_msg_hdr);

	if(!sub_tree) {
		return 0;
	}

	/* FDA Message Version */
	proto_tree_add_item(sub_tree,
		hf_ff_fda_msg_hdr_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Options */
	dissect_ff_msg_hdr_opts(tvb, offset, sub_tree, Options);
	offset += 1;

	/* Protocol Id And Confirmed Msg Type */
	dissect_ff_msg_hdr_proto_and_type(tvb,
		offset, sub_tree, ProtocolAndType);
	offset += 1;

	/* Service */
	dissect_ff_msg_hdr_srv(tvb,
		offset, sub_tree, ProtocolAndType, Service);
	offset += 1;

	/* FDA Address */
	proto_tree_add_item(sub_tree,
		hf_ff_fda_msg_hdr_fda_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Message Length */
	proto_tree_add_item(sub_tree,
		hf_ff_fda_msg_hdr_len, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}



static void
dissect_ff(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree	= NULL;
	proto_item *ti	= NULL;
	gint offset	= 0;

	guint8 Options	= 0;	/* Options */
	guint8 ProtocolAndType	= 0;	/* Protocol Id And Confirmed Msg Type */
	guint8 Service	= 0;	/* Service */
	guint32 FDAAddress	= 0;	/* FDA Address */
	guint32 length	= 0;	/* Message Length */

	guint32 trailer_len = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FF");

	Options	= tvb_get_guint8(tvb, 1);
	ProtocolAndType	= tvb_get_guint8(tvb, 2);
	Service	= tvb_get_guint8(tvb, 3);
	FDAAddress	= tvb_get_ntohl(tvb, 4);
	length = tvb_get_ntohl(tvb, 8);

	if(tree) {
		ti = proto_tree_add_item(tree, proto_ff, tvb, offset, length, ENC_NA);
		sub_tree = proto_item_add_subtree(ti, ett_ff);
	}

	if(Options & OPTION_MESSAGE_NUMBER_MASK) {
		length -= 4;
		trailer_len += 4;
	}

	if(Options & OPTION_INVOKE_ID_MASK) {
		length -= 4;
		trailer_len += 4;
	}

	if(Options & OPTION_TIME_STAMP_MASK) {
		length -= 8;
		trailer_len += 8;
	}

	if(Options & OPTION_EXTENDED_CNTRL_MASK) {
		length -= 4;
		trailer_len += 4;
	}

	/*
	 * Header
	 */
	dissect_ff_msg_hdr(tvb, sub_tree, Options, ProtocolAndType, Service);
	offset += 12;
	length -= 12;

	/*
	 * Service-Specific Parameters + User Data (optional)
	 */
	dissect_ff_msg_body(tvb, offset, length, pinfo, sub_tree,
		ProtocolAndType, Service, FDAAddress);
	offset += length;

	/*
	 * Trailer (optional)
	 */
	if(trailer_len) {
		dissect_ff_msg_trailer(tvb,
			offset, trailer_len, sub_tree, Options);
		/*offset += trailer_len;*/
	}

	return;
}



static guint
get_ff_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	return(tvb_get_ntohl(tvb, offset + 8));
}



static void
dissect_ff_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/*
 *
 * 6.3. Message Header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Version    |    Options    | Protocol/Type |    Service    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          FDA Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Message Length                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

	tcp_dissect_pdus(tvb, pinfo, tree, ff_desegment,
		12, get_ff_pdu_len, dissect_ff);

	return;
}



static void
dissect_ff_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	conversation_t *conversation	= NULL;

	if(pinfo->destport == UDP_PORT_FF_FMS) {
		conversation =
			find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				PT_UDP, pinfo->srcport, 0, NO_PORT_B);

		if(!conversation ||
			(conversation->dissector_handle != ff_udp_handle)) {

			conversation =
				conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					PT_UDP, pinfo->srcport, 0, NO_PORT2);

			conversation_set_dissector(conversation, ff_udp_handle);
		}
	}

	dissect_ff(tvb, pinfo, tree);
}



void
proto_register_ff(void)
{
	static hf_register_info hf[] = {
		/*
		 * 6.3. Message Header
		 */
		{ &hf_ff_fda_msg_hdr,
			{ "Message Header", "ff.hdr",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_hdr_ver,
			{ "FDA Message Version", "ff.hdr.ver",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_hdr_fda_addr,
			{ "FDA Address", "ff.hdr.fda_addr",
				FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_hdr_len,
			{ "Message Length", "ff.hdr.len",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.4. Message Trailer
		 */
		{ &hf_ff_fda_msg_trailer,
			{ "Message Trailer", "ff.trailer",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_trailer_msg_num,
			{ "Message Number", "ff.trailer.msg_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_trailer_invoke_id,
			{ "Invoke Id", "ff.trailer.invoke_id",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_trailer_time_stamp,
			{ "Time Stamp", "ff.trailer.time_stamp",
				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_msg_trailer_extended_control_field,
			{ "Extended Control Field", "ff.trailer.extended_control_field",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1. FDA Session Management Services
		 */
		{ &hf_ff_fda,
			{ "FDA Session Management Service", "ff.fda",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.1. FDA Open Session (Confirmed Service Id = 1)
		 */
		{ &hf_ff_fda_open_sess,
			{ "FDA Open Session", "ff.fda.open_sess",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.1.1. Request Message Parameters
		 */
		{ &hf_ff_fda_open_sess_req,
			{ "FDA Open Session Request", "ff.fda.open_sess.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_sess_idx,
			{ "Session Index", "ff.fda.open_sess.req.sess_idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_max_buf_siz,
			{ "Max Buffer Size", "ff.fda.open_sess.req.max_buf_siz",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_max_msg_len,
			{ "Max Message Length", "ff.fda.open_sess.req.max_msg_len",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_reserved,
			{ "Reserved", "ff.fda.open_sess.req.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_nma_conf_use,
			{ "NMA Configuration Use", "ff.fda.open_sess.req.nma_conf_use",
				FT_UINT8, BASE_DEC, VALS(names_nma_conf_use), 0x0,
				NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_inactivity_close_time,
			{ "Inactivity Close Time",
				"ff.fda.open_sess.req.inactivity_close_time",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_transmit_delay_time,
			{ "Transmit Delay Time", "ff.fda.open_sess.req.transmit_delay_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_req_pd_tag,
			{ "PD Tag", "ff.fda.open_sess.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.1.2. Response Message Parameters
		 */
		{ &hf_ff_fda_open_sess_rsp,
			{ "FDA Open Session Response", "ff.fda.open_sess.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_sess_idx,
			{ "Session Index", "ff.fda.open_sess.rsp.sess_idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_max_buf_siz,
			{ "Max Buffer Size", "ff.fda.open_sess.rsp.max_buf_siz",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_max_msg_len,
			{ "Max Message Length", "ff.fda.open_sess.rsp.max_msg_len",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_reserved,
			{ "Reserved", "ff.fda.open_sess.rsp.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_nma_conf_use,
			{ "NMA Configuration Use", "ff.fda.open_sess.rsp.nma_conf_use",
				FT_UINT8, BASE_DEC, VALS(names_nma_conf_use), 0x0,
				NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_inactivity_close_time,
			{ "Inactivity Close Time",
				"ff.fda.open_sess.rsp.inactivity_close_time",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_transmit_delay_time,
			{ "Transmit Delay Time", "ff.fda.open_sess.rsp.transmit_delay_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_rsp_pd_tag,
			{ "PD Tag", "ff.fda.open_sess.rsp.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.1.3. Error Message Parameters
		 */
		{ &hf_ff_fda_open_sess_err,
			{ "FDA Open Session Error", "ff.fda.open_sess.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_err_err_class,
			{ "Error Class", "ff.fda.open_sess.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_err_err_code,
			{ "Error Code", "ff.fda.open_sess.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_err_additional_code,
			{ "Additional Code", "ff.fda.open_sess.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_open_sess_err_additional_desc,
			{ "Additional Description", "ff.fda.open_sess.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.2. FDA Idle (Confirmed Service Id = 3)
		 */
		{ &hf_ff_fda_idle,
			{ "FDA Idle", "ff.fda.idle",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.2.1. Request Message Parameters
		 */
		{ &hf_ff_fda_idle_req,
			{ "FDA Idle Request", "ff.fda.idle.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.2.2. Response Message Parameters
		 */
		{ &hf_ff_fda_idle_rsp,
			{ "FDA Idle Response", "ff.fda.idle.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.1.2.3. Error Message Parameters
		 */
		{ &hf_ff_fda_idle_err,
			{ "FDA Idle Error", "ff.fda.idle.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_idle_err_err_class,
			{ "Error Class", "ff.fda.idle.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fda_idle_err_err_code,
			{ "Error Code", "ff.fda.idle.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_idle_err_additional_code,
			{ "Additional Code", "ff.fda.idle.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fda_idle_err_additional_desc,
			{ "Additional Description", "ff.fda.idle.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2. SM Services
		 */
		{ &hf_ff_sm,
			{ "SM Service", "ff.sm",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.1. SM Find Tag Query (Unconfirmed Service Id = 1)
		 */
		{ &hf_ff_sm_find_tag_query,
			{ "SM Find Tag Query", "ff.sm.find_tag_query",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.1.1. Request Message Parameters
		 */
		{ &hf_ff_sm_find_tag_query_req,
			{ "SM Find Tag Query Request", "ff.sm.find_tag_query.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_query_req_query_type,
			{ "Query Type", "ff.sm.find_tag_query.req.query_type",
				FT_UINT8, BASE_DEC, VALS(names_query_type), 0x0,
				NULL, HFILL } },

		{ &hf_ff_sm_find_tag_query_req_idx,
			{ "Element Id or VFD Reference or Device Index",
				"ff.sm.find_tag_query.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_query_req_tag,
			{ "PD Tag or Function Block Tag", "ff.sm.find_tag_query.req.tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_query_req_vfd_tag,
			{ "VFD Tag", "ff.sm.find_tag_query.req.vfd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.2. SM Find Tag Reply (Unconfirmed Service Id = 2)
		 */
		{ &hf_ff_sm_find_tag_reply,
			{ "SM Find Tag Reply", "ff.sm.find_tag_reply",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.2.1. Request Message Parameters
		 */
		{ &hf_ff_sm_find_tag_reply_req,
			{ "SM Find Tag Reply Request", "ff.sm.find_tag_reply.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_query_type,
			{ "Query Type", "ff.sm.find_tag_reply.req.query_type",
				FT_UINT8, BASE_DEC, VALS(names_query_type), 0x0,
				NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_h1_node_addr,
			{ "Queried Object H1 Node Address",
				"ff.sm.find_tag_reply.req.h1_node_addr",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_fda_addr_link_id,
			{ "Queried Object FDA Address Link Id",
				"ff.sm.find_tag_reply.req.fda_addr_link_id",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_vfd_ref,
			{ "Queried Object VFD Reference",
				"ff.sm.find_tag_reply.req.vfd_ref",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_od_idx,
			{ "Queried Object OD Index", "ff.sm.find_tag_reply.req.od_idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_ip_addr,
			{ "Queried Object IP Address", "ff.sm.find_tag_reply.req.ip_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_od_ver,
			{ "Queried Object OD Version", "ff.sm.find_tag_reply.req.od_ver",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_dev_id,
			{ "Queried Object Device ID", "ff.sm.find_tag_reply.req.dev_id",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_pd_tag,
			{ "Queried Object PD Tag", "ff.sm.find_tag_reply.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_reserved,
			{ "Reserved", "ff.sm.find_tag_reply.req.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_num_of_fda_addr_selectors,
			{ "Number Of FDA Address Selectors",
				"ff.sm.find_tag_reply.req.num_of_fda_addr_selectors",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_find_tag_reply_req_fda_addr_selector,
			{ "FDA Address Selector",
				"ff.sm.find_tag_reply.req.fda_addr_selector.fda_addr_selector",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.7. SM Identify (Unconfirmed Service Id = 16)
		 */
		{ &hf_ff_sm_id,
			{ "SM Identify", "ff.sm.id",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },


		/*
		 * 6.5.2.3.1. Request Message Parameters
		 */
		{ &hf_ff_sm_id_req,
			{ "SM Identify Request", "ff.sm.id.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.3.2. Response Message Parameters
		 */
		{ &hf_ff_sm_id_rsp,
			{ "SM Identify Response", "ff.sm.id.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_dev_idx,
			{ "Device Index", "ff.sm.id.rsp.dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_max_dev_idx,
			{ "Max Device Index", "ff.sm.id.rsp.max_dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_operational_ip_addr,
			{ "Operational IP Address", "ff.sm.id.rsp.operational_ip_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_dev_id,
			{ "Device ID", "ff.sm.id.rsp.dev_id",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_pd_tag,
			{ "PD Tag", "ff.sm.id.rsp.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_hse_repeat_time,
			{ "HSE Repeat Time", "ff.sm.id.rsp.hse_repeat_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_lr_port,
			{ "LAN Redundancy Port", "ff.sm.id.rsp.lr_port",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_reserved,
			{ "Reserved", "ff.sm.id.rsp.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_annunc_ver_num,
			{ "Annunciation Version Number", "ff.sm.id.rsp.annunc_ver_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_hse_dev_ver_num,
			{ "HSE Device Version Number", "ff.sm.id.rsp.hse_dev_ver_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_num_of_entries,
			{ "Number of Entries in Version Number List",
				"ff.sm.id.rsp.num_of_entries",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_h1_live_list_h1_link_id,
			{ "H1 Link Id", "ff.sm.id.rsp.h1_live_list.h1_link_id",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_h1_live_list_reserved,
			{ "Reserved", "ff.sm.id.rsp.h1_live_list.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_h1_live_list_ver_num,
			{ "Version Number", "ff.sm.id.rsp.h1_live_list.ver_num",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_h1_node_addr_ver_num_h1_node_addr,
			{ "H1 Node Address",
				"ff.sm.id.rsp.h1_node_addr_ver_num.h1_node_addr",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_rsp_h1_node_addr_ver_num_ver_num,
			{ "Version Number", "ff.sm.id.rsp.h1_node_addr_ver_num.ver_num",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.3.3. Error Message Parameters
		 */
		{ &hf_ff_sm_id_err,
			{ "SM Identify Error", "ff.sm.id.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_err_err_class,
			{ "Error Class", "ff.sm.id.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_err_err_code,
			{ "Error Code", "ff.sm.id.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_err_additional_code,
			{ "Additional Code", "ff.sm.id.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_id_err_additional_desc,
			{ "Additional Description", "ff.sm.id.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.4. SM Clear Address (Confirmed Service Id = 12)
		 */
		{ &hf_ff_sm_clear_addr,
			{ "SM Clear Address", "ff.sm.clear_addr",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.4.1. Request Message Parameters
		 */
		{ &hf_ff_sm_clear_addr_req,
			{ "SM Clear Address Request", "ff.sm.clear_addr.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_req_dev_id,
			{ "Device ID", "ff.sm.clear_addr.req.dev_id",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_req_pd_tag,
			{ "PD Tag", "ff.sm.clear_addr.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_req_interface_to_clear,
			{ "Interface to Clear", "ff.sm.clear_addr.req.interface_to_clear",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.4.2. Response Message Parameters
		 */
		{ &hf_ff_sm_clear_addr_rsp,
			{ "SM Clear Address Response", "ff.sm.clear_addr.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.4.3. Error Message Parameters
		 */
		{ &hf_ff_sm_clear_addr_err,
			{ "SM Clear Address Error", "ff.sm.clear_addr.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_err_err_class,
			{ "Error Class", "ff.sm.clear_addr.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_err_err_code,
			{ "Error Code", "ff.sm.clear_addr.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_err_additional_code,
			{ "Additional Code", "ff.sm.clear_addr.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_addr_err_additional_desc,
			{ "Additional Description", "ff.sm.clear_addr.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.5. SM Set Assignment Info (Confirmed Service Id = 14)
		 */
		{ &hf_ff_sm_set_assign_info,
			{ "SM Set Assignment Info", "ff.sm.set_assign_info",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.5.1. Request Message Parameters
		 */
		{ &hf_ff_sm_set_assign_info_req,
			{ "SM Set Assignment Info Request", "ff.sm.set_assign_info.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_dev_id,
			{ "Device ID", "ff.sm.set_assign_info.req.dev_id",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_pd_tag,
			{ "PD Tag", "ff.sm.set_assign_info.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_h1_new_addr,
			{ "H1 New Address", "ff.sm.set_assign_info.req.h1_new_addr",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_lr_port,
			{ "LAN Redundancy Port",
				"ff.sm.set_assign_info.req.lr_port",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_hse_repeat_time,
			{ "HSE Repeat Time", "ff.sm.set_assign_info.req.hse_repeat_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_dev_idx,
			{ "Device Index", "ff.sm.set_assign_info.req.dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_max_dev_idx,
			{ "Max Device Index", "ff.sm.set_assign_info.req.max_dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_req_operational_ip_addr,
			{ "Operational IP Address",
				"ff.sm.set_assign_info.req.operational_ip_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.5.2. Response Message Parameters
		 */
		{ &hf_ff_sm_set_assign_info_rsp,
			{ "SM Set Assignment Info Response", "ff.sm.set_assign_info.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_rsp_reserved,
			{ "Reserved", "ff.sm.set_assign_info.rsp.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_rsp_max_dev_idx,
			{ "Max Device Index", "ff.sm.set_assign_info.rsp.max_dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_rsp_hse_repeat_time,
			{ "HSE Repeat Time", "ff.sm.set_assign_info.rsp.hse_repeat_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.5.3. Error Message Parameters
		 */
		{ &hf_ff_sm_set_assign_info_err,
			{ "SM Set Assignment Info Error", "ff.sm.set_assign_info.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_err_err_class,
			{ "Error Class", "ff.sm.set_assign_info.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_err_err_code,
			{ "Error Code", "ff.sm.set_assign_info.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_err_additional_code,
			{ "Additional Code", "ff.sm.set_assign_info.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_set_assign_info_err_additional_desc,
			{ "Additional Description",
				"ff.sm.set_assign_info.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.6. SM Clear Assignment Info (Confirmed Service Id = 15)
		 */
		{ &hf_ff_sm_clear_assign_info,
			{ "SM Clear Assignment Info", "ff.sm.clear_assign_info",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.6.1. Request Message Parameters
		 */
		{ &hf_ff_sm_clear_assign_info_req,
			{ "SM Clear Assignment Info Request", "ff.sm.clear_assign_info.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_assign_info_req_dev_id,
			{ "Device ID", "ff.sm.clear_assign_info.req.dev_id",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_assign_info_req_pd_tag,
			{ "PD Tag", "ff.sm.clear_assign_info.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.6.2. Response Message Parameters
		 */
		{ &hf_ff_sm_clear_assign_info_rsp,
			{ "SM Clear Assignment Info Response",
				"ff.sm.clear_assign_info.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.6.3. Error Message Parameters
		 */
		{ &hf_ff_sm_clear_assign_info_err,
			{ "SM Clear Assignment Info Error", "ff.sm.clear_assign_info.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_assign_info_err_err_class,
			{ "Error Class", "ff.sm.clear_assign_info.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_assign_info_err_err_code,
			{ "Error Code", "ff.sm.clear_assign_info.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_assign_info_err_additional_code,
			{ "Additional Code", "ff.sm.clear_assign_info.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_clear_assign_info_err_additional_desc,
			{ "Additional Description",
				"ff.sm.clear_assign_info.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.7. SM Device Annunciation (Unconfirmed Service Id = 16)
		 */
		{ &hf_ff_sm_dev_annunc,
			{ "SM Device Annunciation", "ff.sm.dev_annunc",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.2.7.1. Request Message Parameters
		 */
		{ &hf_ff_sm_dev_annunc_req,
			{ "SM Device Annunciation Request", "ff.sm.dev_annunc.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_dev_idx,
			{ "Device Index", "ff.sm.dev_annunc.req.dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_max_dev_idx,
			{ "Max Device Index", "ff.sm.dev_annunc.req.max_dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_operational_ip_addr,
			{ "Operational IP Address",
				"ff.sm.dev_annunc.req.operational_ip_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_dev_id,
			{ "Device ID", "ff.sm.dev_annunc.req.dev_id",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_pd_tag,
			{ "PD Tag", "ff.sm.dev_annunc.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_hse_repeat_time,
			{ "HSE Repeat Time", "ff.sm.dev_annunc.req.hse_repeat_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_lr_port,
			{ "LAN Redundancy Port", "ff.sm.dev_annunc.req.lr_port",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_reserved,
			{ "Reserved", "ff.sm.dev_annunc.req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_annunc_ver_num,
			{ "Annunciation Version Number",
				"ff.sm.dev_annunc.req.annunc_ver_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_hse_dev_ver_num,
			{ "HSE Device Version Number",
				"ff.sm.dev_annunc.req.hse_dev_ver_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_num_of_entries,
			{ "Number of Entries in Version Number List",
				"ff.sm.dev_annunc.req.num_of_entries",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_h1_live_list_h1_link_id,
			{ "H1 Link Id", "ff.sm.dev_annunc.req.h1_live_list.h1_link_id",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_h1_live_list_reserved,
			{ "Reserved", "ff.sm.dev_annunc.req.h1_live_list.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_h1_live_list_ver_num,
			{ "Version Number", "ff.sm.dev_annunc.req.h1_live_list.ver_num",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_h1_node_addr_ver_num_h1_node_addr,
			{ "H1 Node Address",
				"ff.sm.dev_annunc.req.h1_node_addr_ver_num.h1_node_addr",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_sm_dev_annunc_req_h1_node_addr_ver_num_ver_num,
			{ "Version Number",
				"ff.sm.dev_annunc.req.h1_node_addr_ver_num.ver_num",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3. FMS Services
		 */
		{ &hf_ff_fms,
			{ "FMS Service", "ff.fms",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.2. FMS Initiate (Confirmed Service Id = 96)
		 */
		{ &hf_ff_fms_init,
			{ "FMS Initiate", "ff.fms.init",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.2.1. Request Message Parameters
		 */
		{ &hf_ff_fms_init_req,
			{ "FMS Initiate Request", "ff.fms.init.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_req_conn_opt,
			{ "Connect Option", "ff.fms.init.req.conn_opt",
				FT_UINT8, BASE_DEC, VALS(names_conn_opt), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_req_access_protection_supported_calling,
			{ "Access Protection Supported Calling",
				"ff.fms.init.req.access_protection_supported_calling",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_req_passwd_and_access_grps_calling,
			{ "Password and Access Groups Calling",
				"ff.fms.init.req.passwd_and_access_grps_calling",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_req_ver_od_calling,
			{ "Version OD Calling", "ff.fms.init.req.ver_od_calling",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_req_prof_num_calling,
			{ "Profile Number Calling", "ff.fms.init.req.prof_num_calling",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_req_pd_tag,
			{ "PD Tag", "ff.fms.init.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.2.2. Response Message Parameters
		 */
		{ &hf_ff_fms_init_rsp,
			{ "FMS Initiate Response", "ff.fms.init.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_rsp_ver_od_called,
			{ "Version OD Called", "ff.fms.init.rsp.ver_od_called",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_rsp_prof_num_called,
			{ "Profile Number Called", "ff.fms.init.rsp.prof_num_called",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.2.3. Error Message Parameters
		 */
		{ &hf_ff_fms_init_err,
			{ "FMS Initiate Error", "ff.fms.init.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_err_err_class,
			{ "Error Class", "ff.fms.init.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_err_err_code,
			{ "Error Code", "ff.fms.init.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_err_additional_code,
			{ "Additional Code", "ff.fms.init.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_err_additional_desc,
			{ "Additional Description", "ff.fms.init.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.3. FMS Abort (Unconfirmed Service Id = 112)
		 */
		{ &hf_ff_fms_abort,
			{ "FMS Abort", "ff.fms.abort",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.3.1. Request Message Parameters
		 */
		{ &hf_ff_fms_abort_req,
			{ "FMS Abort Request", "ff.fms.abort.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_abort_req_abort_id,
			{ "Abort Identifier", "ff.fms.abort.req.abort_id",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_abort_req_reason_code,
			{ "Reason Code", "ff.fms.abort.req.reason_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_abort_req_reserved,
			{ "Reserved", "ff.fms.abort.req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.4. FMS Status (Confirmed Service Id = 0)
		 */
		{ &hf_ff_fms_status,
			{ "FMS Status", "ff.fms.status",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.4.1. Request Message Parameters
		 */
		{ &hf_ff_fms_status_req,
			{ "FMS Status Request", "ff.fms.status.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.4.2. Response Message Parameters
		 */
		{ &hf_ff_fms_status_rsp,
			{ "FMS Status Response", "ff.fms.status.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_rsp_logical_status,
			{ "Logical Status", "ff.fms.status.rsp.logical_status",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_rsp_physical_status,
			{ "Physical Status", "ff.fms.status.rsp.physical_status",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_rsp_reserved,
			{ "Reserved", "ff.fms.status.rsp.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.4.3. Error Message Parameters
		 */
		{ &hf_ff_fms_status_err,
			{ "FMS Status Error", "ff.fms.status.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_err_err_class,
			{ "Error Class", "ff.fms.status.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_err_err_code,
			{ "Error Code", "ff.fms.status.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_err_additional_code,
			{ "Additional Code", "ff.fms.status.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_status_err_additional_desc,
			{ "Additional Description", "ff.fms.status.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.5. FMS Unsolicited Status (Unconfirmed Service Id = 1)
		 */
		{ &hf_ff_fms_unsolicited_status,
			{ "FMS Unsolicited Status", "ff.fms.unsolicited_status",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.5.1. Request Message Parameters
		 */
		{ &hf_ff_fms_unsolicited_status_req,
			{ "FMS Unsolicited Status Request", "ff.fms.unsolicited_status.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_unsolicited_status_req_logical_status,
			{ "Logical Status", "ff.fms.unsolicited_status.req.logical_status",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_unsolicited_status_req_physical_status,
			{ "Physical Status",
				"ff.fms.unsolicited_status.req.physical_status",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_unsolicited_status_req_reserved,
			{ "Reserved", "ff.fms.unsolicited_status.req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.6. FMS Identify (Confirmed Service Id = 1)
		 */
		{ &hf_ff_fms_id,
			{ "FMS Identify", "ff.fms.id",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.6.1. Request Message Parameters
		 */
		{ &hf_ff_fms_id_req,
			{ "FMS Identify Request", "ff.fms.id.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.6.2. Response Message Parameters
		 */
		{ &hf_ff_fms_id_rsp,
			{ "FMS Identify Response", "ff.fms.id.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_rsp_vendor_name,
			{ "Vendor Name", "ff.fms.id.rsp.vendor_name",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_rsp_model_name,
			{ "Model Name", "ff.fms.id.rsp.model_name",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_rsp_revision,
			{ "Revision", "ff.fms.id.rsp.revision",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.6.3. Error Message Parameters
		 */
		{ &hf_ff_fms_id_err,
			{ "FMS Identify Error", "ff.fms.id.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_err_err_class,
			{ "Error Class", "ff.fms.id.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_err_err_code,
			{ "Error Code", "ff.fms.id.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_err_additional_code,
			{ "Additional Code", "ff.fms.id.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_id_err_additional_desc,
			{ "Additional Description", "ff.fms.id.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.7. FMS Get OD (Confirmed Service Id = 4)
		 */
		{ &hf_ff_fms_get_od,
			{ "FMS Get OD", "ff.fms.get_od",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.7.1. Request Message Parameters
		 */
		{ &hf_ff_fms_get_od_req,
			{ "FMS Get OD Request", "ff.fms.get_od.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_req_all_attrs,
			{ "All Attributes", "ff.fms.get_od.req.all_attrs",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_req_start_idx_flag,
			{ "Start Index Flag", "ff.fms.get_od.req.start_idx_flag",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_req_reserved,
			{ "Reserved", "ff.fms.get_od.req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_req_idx,
			{ "Index", "ff.fms.get_od.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.7.2. Response Message Parameters
		 */
		{ &hf_ff_fms_get_od_rsp,
			{ "FMS Get OD Response", "ff.fms.get_od.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_rsp_more_follows,
			{ "More Follows", "ff.fms.get_od.rsp.more_follows",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_rsp_num_of_obj_desc,
			{ "Number of Object Descriptions",
				"ff.fms.get_od.rsp.num_of_obj_desc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_rsp_reserved,
			{ "Reserved", "ff.fms.get_od.rsp.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.7.3. Error Message Parameters
		 */
		{ &hf_ff_fms_get_od_err,
			{ "FMS Get OD Error", "ff.fms.get_od.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_err_err_class,
			{ "Error Class", "ff.fms.get_od.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_err_err_code,
			{ "Error Code", "ff.fms.get_od.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_err_additional_code,
			{ "Additional Code", "ff.fms.get_od.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_get_od_err_additional_desc,
			{ "Additional Description", "ff.fms.get_od.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.8. FMS Initiate Put OD (Confirmed Service Id = 28)
		 */
		{ &hf_ff_fms_init_put_od,
			{ "FMS Initiate Put OD", "ff.fms.init_put_od",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.8.1. Request Message Parameters
		 */
		{ &hf_ff_fms_init_put_od_req,
			{ "FMS Initiate Put OD Request", "ff.fms.init_put_od.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_put_od_req_reserved,
			{ "Reserved", "ff.fms.init_put_od.req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_put_od_req_consequence,
			{ "Consequence", "ff.fms.init_put_od.req.consequence",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.8.2. Response Message Parameters
		 */
		{ &hf_ff_fms_init_put_od_rsp,
			{ "FMS Initiate Put OD Response", "ff.fms.init_put_od.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.8.3. Error Message Parameters
		 */
		{ &hf_ff_fms_init_put_od_err,
			{ "FMS Initiate Put OD Error", "ff.fms.init_put_od.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_put_od_err_err_class,
			{ "Error Class", "ff.fms.init_put_od.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_put_od_err_err_code,
			{ "Error Code", "ff.fms.init_put_od.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_put_od_err_additional_code,
			{ "Additional Code", "ff.fms.init_put_od.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_put_od_err_additional_desc,
			{ "Additional Description",
				"ff.fms.init_put_od.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.9. FMS Put OD (Confirmed Service Id = 29)
		 */
		{ &hf_ff_fms_put_od,
			{ "FMS Put OD", "ff.fms.put_od",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.9.1. Request Message Parameters
		 */
		{ &hf_ff_fms_put_od_req,
			{ "FMS Put OD Request", "ff.fms.put_od.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_put_od_req_num_of_obj_desc,
			{ "Number of Object Descriptions",
				"ff.fms.put_od.req.num_of_obj_desc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.9.2. Response Message Parameters
		 */
		{ &hf_ff_fms_put_od_rsp,
			{ "FMS Put OD Response", "ff.fms.put_od.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.9.3. Error Message Parameters
		 */
		{ &hf_ff_fms_put_od_err,
			{ "FMS Put OD Error", "ff.fms.put_od.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_put_od_err_err_class,
			{ "Error Class", "ff.fms.put_od.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_put_od_err_err_code,
			{ "Error Code", "ff.fms.put_od.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_put_od_err_additional_code,
			{ "Additional Code", "ff.fms.put_od.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_put_od_err_additional_desc,
			{ "Additional Description", "ff.fms.put_od.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.10. FMS Terminate Put OD (Confirmed Service Id = 30)
		 */
		{ &hf_ff_fms_terminate_put_od,
			{ "FMS Terminate Put OD", "ff.fms.terminate_put_od",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.10.1. Request Message Parameters
		 */
		{ &hf_ff_fms_terminate_put_od_req,
			{ "FMS Terminate Put OD Request", "ff.fms.terminate_put_od.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.10.2. Response Message Parameters
		 */
		{ &hf_ff_fms_terminate_put_od_rsp,
			{ "FMS Terminate Put OD Response", "ff.fms.terminate_put_od.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.10.3. Error Message Parameters
		 */
		{ &hf_ff_fms_terminate_put_od_err,
			{ "FMS Terminate Put OD Error", "ff.fms.terminate_put_od.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_put_od_err_index,
			{ "Index", "ff.fms.terminate_put_od.err.index",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_put_od_err_err_class,
			{ "Error Class", "ff.fms.terminate_put_od.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_put_od_err_err_code,
			{ "Error Code", "ff.fms.terminate_put_od.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_put_od_err_additional_code,
			{ "Additional Code", "ff.fms.terminate_put_od.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_put_od_err_additional_desc,
			{ "Additional Description",
				"ff.fms.terminate_put_od.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.11. FMS Generic Initiate Download Sequence
		 *           (Confirmed Service Id = 31)
		 */
		{ &hf_ff_fms_gen_init_download_seq,
			{ "FMS Generic Initiate Download Sequence",
				"ff.fms.gen_init_download_seq",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.11.1. Request Message Parameters
		 */
		{ &hf_ff_fms_gen_init_download_seq_req,
			{ "FMS Generic Initiate Download Sequence Request",
				"ff.fms.gen_init_download_seq.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_init_download_seq_req_idx,
			{ "Index",
				"ff.fms.gen_init_download_seq.req.idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.11.2. Response Message Parameters
		 */
		{ &hf_ff_fms_gen_init_download_seq_rsp,
			{ "FMS Generic Initiate Download Sequence Response",
				"ff.fms.gen_init_download_seq.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.11.3. Error Message Parameters
		 */
		{ &hf_ff_fms_gen_init_download_seq_err,
			{ "FMS Generic Initiate Download Sequence Error",
				"ff.fms.gen_init_download_seq.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_init_download_seq_err_err_class,
			{ "Error Class", "ff.fms.gen_init_download_seq.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_init_download_seq_err_err_code,
			{ "Error Code", "ff.fms.gen_init_download_seq.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_init_download_seq_err_additional_code,
			{ "Additional Code",
				"ff.fms.gen_init_download_seq.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_init_download_seq_err_additional_desc,
			{ "Additional Description",
				"ff.fms.gen_init_download_seq.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.12. FMS Generic Download Segment (Confirmed Service Id = 32)
		 */
		{ &hf_ff_fms_gen_download_seg,
			{ "FMS Generic Download Segment", "ff.fms.gen_download_seg",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.12.1. Request Message Parameters
		 */
		{ &hf_ff_fms_gen_download_seg_req,
			{ "FMS Generic Download Segment Request",
				"ff.fms.gen_download_seg.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_download_seg_req_idx,
			{ "Index", "ff.fms.gen_download_seg.req.idx",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_download_seg_req_more_follows,
			{ "More Follows", "ff.fms.gen_download_seg.req.more_follows",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.12.2. Response Message Parameters
		 */
		{ &hf_ff_fms_gen_download_seg_rsp,
			{ "FMS Generic Download Segment Response",
				"ff.fms.gen_download_seg.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.12.3. Error Message Parameters
		 */
		{ &hf_ff_fms_gen_download_seg_err,
			{ "FMS Generic Download Segment Error",
				"ff.fms.gen_download_seg.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_download_seg_err_err_class,
			{ "Error Class", "ff.fms.gen_download_seg.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_download_seg_err_err_code,
			{ "Error Code", "ff.fms.gen_download_seg.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_download_seg_err_additional_code,
			{ "Additional Code", "ff.fms.gen_download_seg.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_download_seg_err_additional_desc,
			{ "Additional Description",
				"ff.fms.gen_download_seg.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.13. FMS Generic Terminate Download Sequence
		 *           (Confirmed Service Id = 33)
		 */
		{ &hf_ff_fms_gen_terminate_download_seq,
			{ "FMS Generic Terminate Download Sequence",
				"ff.fms.gen_terminate_download_seq",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.13.1. Request Message Parameters
		 */
		{ &hf_ff_fms_gen_terminate_download_seq_req,
			{ "FMS Generic Terminate Download Sequence Request",
				"ff.fms.gen_terminate_download_seq.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_terminate_download_seq_req_idx,
			{ "Index", "ff.fms.gen_terminate_download_seq.req.idx",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.13.2. Response Message Parameters
		 */
		{ &hf_ff_fms_gen_terminate_download_seq_rsp,
			{ "FMS Generic Terminate Download Sequence Response",
				"ff.fms.gen_terminate_download_seq.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_terminate_download_seq_rsp_final_result,
			{ "Final Result",
				"ff.fms.gen_terminate_download_seq.rsp.final_result",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.13.3. Error Message Parameters
		 */
		{ &hf_ff_fms_gen_terminate_download_seq_err,
			{ "FMS Generic Terminate Download Sequence Error",
				"ff.fms.gen_terminate_download_seq.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_terminate_download_seq_err_err_class,
			{ "Error Class", "ff.fms.gen_terminate_download_seq.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_terminate_download_seq_err_err_code,
			{ "Error Code", "ff.fms.gen_terminate_download_seq.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_terminate_download_seq_err_additional_code,
			{ "Additional Code",
				"ff.fms.gen_terminate_download_seq.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_gen_terminate_download_seq_err_additional_desc,
			{ "Additional Description",
				"ff.fms.gen_terminate_download_seq.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.14. FMS Initiate Download Sequence (Confirmed Service Id = 9)
		 */
		{ &hf_ff_fms_init_download_seq,
			{ "FMS Initiate Download Sequence",
				"ff.fms.init_download_seq",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.14.1. Request Message Parameters
		 */
		{ &hf_ff_fms_init_download_seq_req,
			{ "FMS Initiate Download Sequence Request",
				"ff.fms.init_download_seq.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_download_seq_req_idx,
			{ "Index", "ff.fms.init_download_seq.req.idx",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.14.2. Response Message Parameters
		 */
		{ &hf_ff_fms_init_download_seq_rsp,
			{ "FMS Initiate Download Sequence Response",
				"ff.fms.init_download_seq.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.14.3. Error Message Parameters
		 */
		{ &hf_ff_fms_init_download_seq_err,
			{ "FMS Initiate Download Sequence Error",
				"ff.fms.init_download_seq.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_download_seq_err_err_class,
			{ "Error Class", "ff.fms.init_download_seq.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_download_seq_err_err_code,
			{ "Error Code", "ff.fms.init_download_seq.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_download_seq_err_additional_code,
			{ "Additional Code", "ff.fms.init_download_seq.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_download_seq_err_additional_desc,
			{ "Additional Description",
				"ff.fms.init_download_seq.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.15. FMS Download Segment (Confirmed Service Id = 10)
		 */
		{ &hf_ff_fms_download_seg,
			{ "FMS Download Segment", "ff.fms.download_seg",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.15.1. Request Message Parameters
		 */
		{ &hf_ff_fms_download_seg_req,
			{ "FMS Download Segment Request", "ff.fms.download_seg.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_download_seg_req_idx,
			{ "Index", "ff.fms.download_seg.req.idx",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.15.2. Response Message Parameters
		 */
		{ &hf_ff_fms_download_seg_rsp,
			{ "FMS Download Segment Response", "ff.fms.download_seg.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_download_seg_rsp_more_follows,
			{ "Final Result", "ff.fms.download_seg.rsp.more_follows",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.15.3. Error Message Parameters
		 */
		{ &hf_ff_fms_download_seg_err,
			{ "FMS Download Segment Error", "ff.fms.download_seg.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_download_seg_err_err_class,
			{ "Error Class", "ff.fms.download_seg.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_download_seg_err_err_code,
			{ "Error Code", "ff.fms.download_seg.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_download_seg_err_additional_code,
			{ "Additional Code", "ff.fms.download_seg.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_download_seg_err_additional_desc,
			{ "Additional Description",
				"ff.fms.download_seg.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.16. FMS Terminate Download Sequence (Confirmed Service Id = 11)
		 */
		{ &hf_ff_fms_terminate_download_seq,
			{ "FMS Terminate Download Sequence",
				"ff.fms.terminate_download_seq",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.16.1. Request Message Parameters
		 */
		{ &hf_ff_fms_terminate_download_seq_req,
			{ "FMS Terminate Download Sequence Request",
				"ff.fms.terminate_download_seq.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_download_seq_req_idx,
			{ "Index", "ff.fms.terminate_download_seq.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_download_seq_req_final_result,
			{ "Final Result", "ff.fms.terminate_download_seq.req.final_result",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.16.2. Response Message Parameters
		 */
		{ &hf_ff_fms_terminate_download_seq_rsp,
			{ "FMS Terminate Download Sequence Response",
				"ff.fms.terminate_download_seq.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.16.3. Error Message Parameters
		 */
		{ &hf_ff_fms_terminate_download_seq_err,
			{ "FMS Terminate Download Sequence Error",
				"ff.fms.terminate_download_seq.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_download_seq_err_err_class,
			{ "Error Class", "ff.fms.terminate_download_seq.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_download_seq_err_err_code,
			{ "Error Code", "ff.fms.terminate_download_seq.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_download_seq_err_additional_code,
			{ "Additional Code",
				"ff.fms.terminate_download_seq.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_download_seq_err_additional_desc,
			{ "Additional Description",
				"ff.fms.terminate_download_seq.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.17. FMS Initiate Upload Sequence (Confirmed Service Id = 12)
		 */
		{ &hf_ff_fms_init_upload_seq,
			{ "FMS Initiate Upload Sequence", "ff.fms.init_upload_seq",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.17.1. Request Message Parameters
		 */
		{ &hf_ff_fms_init_upload_seq_req,
			{ "FMS Initiate Upload Sequence Request",
				"ff.fms.init_upload_seq.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_upload_seq_req_idx,
			{ "Index", "ff.fms.init_upload_seq.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.17.2. Response Message Parameters
		 */
		{ &hf_ff_fms_init_upload_seq_rsp,
			{ "FMS Initiate Upload Sequence Response",
				"ff.fms.init_upload_seq.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.17.3. Error Message Parameters
		 */
		{ &hf_ff_fms_init_upload_seq_err,
			{ "FMS Initiate Upload Sequence Error",
				"ff.fms.init_upload_seq.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_upload_seq_err_err_class,
			{ "Error Class", "ff.fms.init_upload_seq.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_upload_seq_err_err_code,
			{ "Error Code", "ff.fms.init_upload_seq.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_upload_seq_err_additional_code,
			{ "Additional Code", "ff.fms.init_upload_seq.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_init_upload_seq_err_additional_desc,
			{ "Additional Description",
				"ff.fms.init_upload_seq.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.18. FMS Upload Segment (Confirmed Service Id = 13)
		 */
		{ &hf_ff_fms_upload_seg,
			{ "FMS Upload Segment", "ff.fms.upload_seg",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.18.1. Request Message Parameters
		 */
		{ &hf_ff_fms_upload_seg_req,
			{ "FMS Upload Segment Request", "ff.fms.upload_seg.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_upload_seg_req_idx,
			{ "Index", "ff.fms.upload_seg.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.18.2. Response Message Parameters
		 */
		{ &hf_ff_fms_upload_seg_rsp,
			{ "FMS Upload Segment Response", "ff.fms.upload_seg.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_upload_seg_rsp_more_follows,
			{ "More Follows", "ff.fms.upload_seg.rsp.more_follows",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.18.3. Error Message Parameters
		 */
		{ &hf_ff_fms_upload_seg_err,
			{ "FMS Upload Segment Error", "ff.fms.upload_seg.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_upload_seg_err_err_class,
			{ "Error Class", "ff.fms.upload_seg.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_upload_seg_err_err_code,
			{ "Error Code", "ff.fms.upload_seg.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_upload_seg_err_additional_code,
			{ "Additional Code", "ff.fms.upload_seg.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_upload_seg_err_additional_desc,
			{ "Additional Description", "ff.fms.upload_seg.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.19. FMS Terminate Upload Sequence (Confirmed Service Id = 14)
		 */
		{ &hf_ff_fms_terminate_upload_seq,
			{ "FMS Terminate Upload Sequence",
				"ff.fms.terminate_upload_seq",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.19.1. Request Message Parameters
		 */
		{ &hf_ff_fms_terminate_upload_seq_req,
			{ "FMS Terminate Upload Sequence Request",
				"ff.fms.terminate_upload_seq.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_upload_seq_req_idx,
			{ "Index", "ff.fms.terminate_upload_seq.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.19.2. Response Message Parameters
		 */
		{ &hf_ff_fms_terminate_upload_seq_rsp,
			{ "FMS Terminate Upload Sequence Response",
				"ff.fms.terminate_upload_seq.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.19.3. Error Message Parameters
		 */
		{ &hf_ff_fms_terminate_upload_seq_err,
			{ "FMS Terminate Upload Sequence Error",
				"ff.fms.terminate_upload_seq.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_upload_seq_err_err_class,
			{ "Error Class", "ff.fms.terminate_upload_seq.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_upload_seq_err_err_code,
			{ "Error Code", "ff.fms.terminate_upload_seq.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_upload_seq_err_additional_code,
			{ "Additional Code",
				"ff.fms.terminate_upload_seq.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_terminate_upload_seq_err_additional_desc,
			{ "Additional Description",
				"ff.fms.terminate_upload_seq.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.20. FMS Request Domain Download (Confirmed Service Id = 15)
		 */
		{ &hf_ff_fms_req_dom_download,
			{ "FMS Request Domain Download", "ff.fms.req_dom_download",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.20.1. Request Message Parameters
		 */
		{ &hf_ff_fms_req_dom_download_req,
			{ "FMS Request Domain Download Request",
				"ff.fms.req_dom_download.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_download_req_idx,
			{ "Index", "ff.fms.req_dom_download.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_download_req_additional_info,
			{ "Additional Description",
				"ff.fms.req_dom_download.req.additional_info",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.20.2. Response Message Parameters
		 */
		{ &hf_ff_fms_req_dom_download_rsp,
			{ "FMS Request Domain Download Response",
				"ff.fms.req_dom_download.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		/*
		 * 6.5.3.20.3. Error Message Parameters
		 */
		{ &hf_ff_fms_req_dom_download_err,
			{ "FMS Request Domain Download Error",
				"ff.fms.req_dom_download.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_download_err_err_class,
			{ "Error Class", "ff.fms.req_dom_download.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_download_err_err_code,
			{ "Error Code", "ff.fms.req_dom_download.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_download_err_additional_code,
			{ "Additional Code", "ff.fms.req_dom_download.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_download_err_additional_desc,
			{ "Additional Description",
				"ff.fms.req_dom_download.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.21. FMS Request Domain Upload (Confirmed Service Id = 16)
		 */
		{ &hf_ff_fms_req_dom_upload,
			{ "FMS Request Domain Upload", "ff.fms.req_dom_upload",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.21.1. Request Message Parameters
		 */
		{ &hf_ff_fms_req_dom_upload_req,
			{ "FMS Request Domain Upload Request", "ff.fms.req_dom_upload.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_upload_req_idx,
			{ "Index", "ff.fms.req_dom_upload.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_upload_req_additional_info,
			{ "Additional Description",
				"ff.fms.req_dom_upload.req.additional_info",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.21.2. Response Message Parameters
		 */
		{ &hf_ff_fms_req_dom_upload_rsp,
			{ "FMS Request Domain Upload Response", "ff.fms.req_dom_upload.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.21.3. Error Message Parameters
		 */
		{ &hf_ff_fms_req_dom_upload_err,
			{ "FMS Request Domain Upload Error", "ff.fms.req_dom_upload.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_upload_err_err_class,
			{ "Error Class", "ff.fms.req_dom_upload.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_upload_err_err_code,
			{ "Error Code", "ff.fms.req_dom_upload.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_upload_err_additional_code,
			{ "Additional Code", "ff.fms.req_dom_upload.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_req_dom_upload_err_additional_desc,
			{ "Additional Description",
				"ff.fms.req_dom_upload.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.22. FMS Create Program Invocation (Confirmed Service Id = 17)
		 */
		{ &hf_ff_fms_create_pi,
			{ "FMS Create Program Invocation", "ff.fms.create_pi",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.22.1. Request Message Parameters
		 */
		{ &hf_ff_fms_create_pi_req,
			{ "FMS Create Program Invocation Request", "ff.fms.create_pi.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_req_reusable,
			{ "Reusable", "ff.fms.create_pi.req.reusable",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_req_reserved,
			{ "Reserved", "ff.fms.create_pi.req.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_req_num_of_dom_idxes,
			{ "Number of Domain Indexes",
				"ff.fms.create_pi.req.num_of_dom_idxes",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_req_dom_idx,
			{ "Domain Index", "ff.fms.create_pi.req.list_of_dom_idxes.dom_idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.22.2. Response Message Parameters
		 */
		{ &hf_ff_fms_create_pi_rsp,
			{ "FMS Create Program Invocation Response", "ff.fms.create_pi.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_rsp_idx,
			{ "Index", "ff.fms.create_pi.rsp.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.22.3. Error Message Parameters
		 */
		{ &hf_ff_fms_create_pi_err,
			{ "FMS Create Program Invocation Error", "ff.fms.create_pi.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_err_err_class,
			{ "Error Class", "ff.fms.create_pi.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_err_err_code,
			{ "Error Code", "ff.fms.create_pi.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_err_additional_code,
			{ "Additional Code",
				"ff.fms.create_pi.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_create_pi_err_additional_desc,
			{ "Additional Description",
				"ff.fms.create_pi.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.23. FMS Delete Program Invocation (Confirmed Service Id = 18)
		 */
		{ &hf_ff_fms_del_pi ,
			{ "FMS Delete Program Invocation", "ff.fms.del_pi",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.23.1. Request Message Parameters
		 */
		{ &hf_ff_fms_del_pi_req,
			{ "FMS Delete Program Invocation Request", "ff.fms.del_pi.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_pi_req_idx,
			{ "Index", "ff.fms.del_pi.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.23.2. Response Message Parameters
		 */
		{ &hf_ff_fms_del_pi_rsp,
			{ "FMS Delete Program Invocation Response", "ff.fms.del_pi.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.23.3. Error Message Parameters
		 */
		{ &hf_ff_fms_del_pi_err,
			{ "FMS Delete Program Invocation Error", "ff.fms.del_pi.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_pi_err_err_class,
			{ "Error Class", "ff.fms.del_pi.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_pi_err_err_code,
			{ "Error Code", "ff.fms.del_pi.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_pi_err_additional_code,
			{ "Additional Code",
				"ff.fms.del_pi.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_pi_err_additional_desc,
			{ "Additional Description",
				"ff.fms.del_pi.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.24. FMS Start (Confirmed Service Id = 19)
		 */
		{ &hf_ff_fms_start,
			{ "FMS Start", "ff.fms.start",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.24.1. Request Message Parameters
		 */
		{ &hf_ff_fms_start_req,
			{ "FMS Start Request", "ff.fms.start.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_start_req_idx,
			{ "Index", "ff.fms.start.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.24.2. Response Message Parameters
		 */
		{ &hf_ff_fms_start_rsp,
			{ "FMS Start Response", "ff.fms.start.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.24.3. PI Error Message Parameters
		 */
		{ &hf_ff_fms_start_err,
			{ "FMS Start Error", "ff.fms.start.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_start_err_pi_state,
			{ "Pi State", "ff.fms.start.err.pi_state",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_start_err_err_class,
			{ "Error Class", "ff.fms.start.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_start_err_err_code,
			{ "Error Code", "ff.fms.start.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_start_err_additional_code,
			{ "Additional Code", "ff.fms.start.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_start_err_additional_desc,
			{ "Additional Description", "ff.fms.start.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.25. FMS Stop (Confirmed Service Id = 20)
		 */
		{ &hf_ff_fms_stop,
			{ "FMS Stop", "ff.fms.stop",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.25.1. Request Message Parameters
		 */
		{ &hf_ff_fms_stop_req,
			{ "FMS Stop Request", "ff.fms.stop.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_stop_req_idx,
			{ "Index", "ff.fms.stop.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.25.2. Response Message Parameters
		 */
		{ &hf_ff_fms_stop_rsp,
			{ "FMS Stop Response", "ff.fms.stop.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.25.3. Error Message Parameters
		 */
		{ &hf_ff_fms_stop_err,
			{ "FMS Stop Error", "ff.fms.stop.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_stop_err_pi_state,
			{ "Pi State", "ff.fms.stop.err.pi_state",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_stop_err_err_class,
			{ "Error Class", "ff.fms.stop.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_stop_err_err_code,
			{ "Error Code", "ff.fms.stop.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_stop_err_additional_code,
			{ "Additional Code", "ff.fms.stop.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_stop_err_additional_desc,
			{ "Additional Description", "ff.fms.stop.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.26. FMS Resume (Confirmed Service Id = 21)
		 */
		{ &hf_ff_fms_resume,
			{ "FMS Resume", "ff.fms.resume",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.26.1. Request Message Parameters
		 */
		{ &hf_ff_fms_resume_req,
			{ "FMS Resume Request", "ff.fms.resume.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_resume_req_idx,
			{ "Index", "ff.fms.resume.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.26.2. Response Message Parameters
		 */
		{ &hf_ff_fms_resume_rsp,
			{ "FMS Resume Response", "ff.fms.resume.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.26.3. Error Message Parameters
		 */
		{ &hf_ff_fms_resume_err,
			{ "FMS Resume Error", "ff.fms.resume.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_resume_err_pi_state,
			{ "Pi State", "ff.fms.resume.err.pi_state",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_resume_err_err_class,
			{ "Error Class", "ff.fms.resume.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_resume_err_err_code,
			{ "Error Code", "ff.fms.resume.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_resume_err_additional_code,
			{ "Additional Code", "ff.fms.resume.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_resume_err_additional_desc,
			{ "Additional Description", "ff.fms.resume.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.27. FMS Reset (Confirmed Service Id = 22)
		 */
		{ &hf_ff_fms_reset,
			{ "FMS Reset", "ff.fms.reset",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.27.1. Request Message Parameters
		 */
		{ &hf_ff_fms_reset_req,
			{ "FMS Reset Request", "ff.fms.reset.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_reset_req_idx,
			{ "Index", "ff.fms.reset.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.27.2. Response Message Parameters
		 */
		{ &hf_ff_fms_reset_rsp,
			{ "FMS Reset Response", "ff.fms.reset.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.27.3. Error Message Parameters
		 */
		{ &hf_ff_fms_reset_err,
			{ "FMS Reset Error", "ff.fms.reset.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_reset_err_pi_state,
			{ "Pi State", "ff.fms.reset.err.pi_state",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_reset_err_err_class,
			{ "Error Class", "ff.fms.reset.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_reset_err_err_code,
			{ "Error Code", "ff.fms.reset.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_reset_err_additional_code,
			{ "Additional Code", "ff.fms.reset.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_reset_err_additional_desc,
			{ "Additional Description", "ff.fms.reset.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.28. FMS Kill (Confirmed Service Id = 23)
		 */
		{ &hf_ff_fms_kill,
			{ "FMS Kill", "ff.fms.kill",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.28.1. Request Message Parameters
		 */
		{ &hf_ff_fms_kill_req,
			{ "FMS Kill Request", "ff.fms.kill.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.28.2. Response Message Parameters
		 */
		{ &hf_ff_fms_kill_rsp,
			{ "FMS Kill Response", "ff.fms.kill.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.28.3. Error Message Parameters
		 */
		{ &hf_ff_fms_kill_err,
			{ "FMS Kill Error", "ff.fms.kill.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_kill_req_idx,
			{ "Index", "ff.fms.kill.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_kill_err_err_class,
			{ "Error Class", "ff.fms.kill.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_kill_err_err_code,
			{ "Error Code", "ff.fms.kill.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_kill_err_additional_code,
			{ "Additional Code", "ff.fms.kill.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_kill_err_additional_desc,
			{ "Additional Description", "ff.fms.kill.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.29. FMS Read (Confirmed Service Id = 2)
		 */
		{ &hf_ff_fms_read,
			{ "FMS Read", "ff.fms.read",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.29.1. Request Message Parameters
		 */
		{ &hf_ff_fms_read_req,
			{ "FMS Read Request", "ff.fms.read.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_req_idx,
			{ "Index", "ff.fms.read.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.29.2. Response Message Parameters
		 */
		{ &hf_ff_fms_read_rsp,
			{ "FMS Read Response", "ff.fms.read.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.29.3. Error Message Parameters
		 */
		{ &hf_ff_fms_read_err,
			{ "FMS Read Error", "ff.fms.read.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_err_err_class,
			{ "Error Class", "ff.fms.read.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_err_err_code,
			{ "Error Code", "ff.fms.read.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_err_additional_code,
			{ "Additional Code", "ff.fms.read.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_err_additional_desc,
			{ "Additional Description", "ff.fms.read.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.30. FMS Read with Subindex (Confirmed Service Id = 82)
		 */
		{ &hf_ff_fms_read_with_subidx,
			{ "FMS Read with Subindex", "ff.fms.read_with_subidx",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.30.1. Request Message Parameters
		 */
		{ &hf_ff_fms_read_with_subidx_req,
			{ "FMS Read with Subindex Request", "ff.fms.read_with_subidx.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_with_subidx_req_idx,
			{ "Index", "ff.fms.read_with_subidx.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_with_subidx_req_subidx,
			{ "Index", "ff.fms.read_with_subidx.req.subidx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.30.2. Response Message Parameters
		 */
		{ &hf_ff_fms_read_with_subidx_rsp,
			{ "FMS Read with Subindex Response", "ff.fms.read_with_subidx.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.30.3. Error Message Parameters
		 */
		{ &hf_ff_fms_read_with_subidx_err,
			{ "FMS Read with Subindex Error", "ff.fms.read_with_subidx.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_with_subidx_err_err_class,
			{ "Error Class", "ff.fms.read_with_subidx.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_with_subidx_err_err_code,
			{ "Error Code", "ff.fms.read_with_subidx.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_with_subidx_err_additional_code,
			{ "Additional Code", "ff.fms.read_with_subidx.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_read_with_subidx_err_additional_desc,
			{ "Additional Description",
				"ff.fms.read_with_subidx.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.31. FMS Write (Confirmed Service Id = 3)
		 */
		{ &hf_ff_fms_write,
			{ "FMS Write", "ff.fms.write",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.31.1. Request Message Parameters
		 */
		{ &hf_ff_fms_write_req,
			{ "FMS Write Request", "ff.fms.write.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_req_idx,
			{ "Index", "ff.fms.write.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.31.2. Response Message Parameters
		 */
		{ &hf_ff_fms_write_rsp,
			{ "FMS Write Response", "ff.fms.write.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.31.3. Error Message Parameters
		 */
		{ &hf_ff_fms_write_err,
			{ "FMS Write Error", "ff.fms.write.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_err_err_class,
			{ "Error Class", "ff.fms.write.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_err_err_code,
			{ "Error Code", "ff.fms.write.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_err_additional_code,
			{ "Additional Code", "ff.fms.write.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_err_additional_desc,
			{ "Additional Description", "ff.fms.write.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.32. FMS Write with Subindex (Confirmed Service Id = 83)
		 */
		{ &hf_ff_fms_write_with_subidx,
			{ "FMS Write with Subindex", "ff.fms.write_with_subidx",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.32.1. Request Message Parameters
		 */
		{ &hf_ff_fms_write_with_subidx_req,
			{ "FMS Write with Subindex Request", "ff.fms.write_with_subidx.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_with_subidx_req_idx,
			{ "Index", "ff.fms.write_with_subidx.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_with_subidx_req_subidx,
			{ "Index", "ff.fms.write_with_subidx.req.subidx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.32.2. Response Message Parameters
		 */
		{ &hf_ff_fms_write_with_subidx_rsp,
			{ "FMS Write with Subindex Response",
				"ff.fms.write_with_subidx.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.32.3. Error Message Parameters
		 */
		{ &hf_ff_fms_write_with_subidx_err,
			{ "FMS Write with Subindex Error", "ff.fms.write_with_subidx.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_with_subidx_err_err_class,
			{ "Error Class", "ff.fms.write_with_subidx.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_with_subidx_err_err_code,
			{ "Error Code", "ff.fms.write_with_subidx.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_with_subidx_err_additional_code,
			{ "Additional Code", "ff.fms.write_with_subidx.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_write_with_subidx_err_additional_desc,
			{ "Additional Description",
				"ff.fms.write_with_subidx.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.33. FMS Define Variable List (Confirmed Service Id = 7)
		 */
		{ &hf_ff_fms_def_variable_list,
			{ "FMS Define Variable List", "ff.fms.def_variable_list",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.33.1. Request Message Parameters
		 */
		{ &hf_ff_fms_def_variable_list_req,
			{ "FMS Define Variable List Request",
				"ff.fms.def_variable_list.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_req_num_of_idxes,
			{ "Number of Indexes", "ff.fms.def_variable_list.req.num_of_idxes",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_req_idx,
			{ "Index", "ff.fms.def_variable_list.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.33.2. Response Message Parameters
		 */
		{ &hf_ff_fms_def_variable_list_rsp,
			{ "FMS Define Variable List Response",
				"ff.fms.def_variable_list.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_rsp_idx,
			{ "Index", "ff.fms.def_variable_list.rsp.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.33.3. Error Message Parameters
		 */
		{ &hf_ff_fms_def_variable_list_err,
			{ "FMS Define Variable List Error", "ff.fms.def_variable_list.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_err_err_class,
			{ "Error Class", "ff.fms.def_variable_list.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_err_err_code,
			{ "Error Code", "ff.fms.def_variable_list.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_err_additional_code,
			{ "Additional Code", "ff.fms.def_variable_list.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_def_variable_list_err_additional_desc,
			{ "Additional Description",
				"ff.fms.def_variable_list.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.34. FMS Delete Variable List (Confirmed Service Id = 8)
		 */
		{ &hf_ff_fms_del_variable_list,
			{ "FMS Delete Variable List", "ff.fms.del_variable_list",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.34.1. Request Message Parameters
		 */
		{ &hf_ff_fms_del_variable_list_req,
			{ "FMS Delete Variable List Request",
				"ff.fms.del_variable_list.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_variable_list_req_idx,
			{ "Index", "ff.fms.del_variable_list.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.34.2. Response Message Parameters
		 */
		{ &hf_ff_fms_del_variable_list_rsp,
			{ "FMS Delete Variable List Response",
				"ff.fms.del_variable_list.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.34.3. Error Message Parameters
		 */
		{ &hf_ff_fms_del_variable_list_err,
			{ "FMS Delete Variable List Error", "ff.fms.del_variable_list.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_variable_list_err_err_class,
			{ "Error Class", "ff.fms.del_variable_list.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_variable_list_err_err_code,
			{ "Error Code", "ff.fms.del_variable_list.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_variable_list_err_additional_code,
			{ "Additional Code", "ff.fms.del_variable_list.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_del_variable_list_err_additional_desc,
			{ "Additional Description",
				"ff.fms.del_variable_list.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.35. FMS Information Report (Unconfirmed Service Id = 0)
		 */
		{ &hf_ff_fms_info_report,
			{ "FMS Information Report", "ff.fms.info_report",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.35.1. Request Message Parameters
		 */
		{ &hf_ff_fms_info_report_req,
			{ "FMS Information Report Request", "ff.fms.info_report.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_info_report_req_idx,
			{ "Index", "ff.fms.info_report.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.36. FMS Information Report with Subindex
		 *           (Unconfirmed Service Id = 16)
		 */
		{ &hf_ff_fms_info_report_with_subidx,
			{ "FMS Information Report with Subindex",
				"ff.fms.info_report_with_subidx",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.36.1. Request Message Parameters
		 */
		{ &hf_ff_fms_info_report_with_subidx_req,
			{ "FMS Information Report with Subindex Request",
				"ff.fms.info_report_with_subidx.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_info_report_with_subidx_req_idx,
			{ "Index", "ff.fms.info_report_with_subidx.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_info_report_with_subidx_req_subidx,
			{ "Subindex", "ff.fms.info_report_with_subidx.req.subidx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.37. FMS Information Report On Change
		 *           (Unconfirmed Service Id = 17)
		 */
		{ &hf_ff_fms_info_report_on_change,
			{ "FMS Information Report On Change with Subindex",
				"ff.fms.info_report_on_change",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.37.1. Request Message Parameters
		 */
		{ &hf_ff_fms_info_report_on_change_req,
			{ "FMS Information Report On Change with Subindex Request",
				"ff.fms.info_report_on_change.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_info_report_on_change_req_idx,
			{ "Index", "ff.fms.info_report_on_change.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.38. FMS Information Report On Change with Subindex
		 *           (Unconfirmed Service Id = 18)
		 */
		{ &hf_ff_fms_info_report_on_change_with_subidx,
			{ "FMS Information Report On Change",
				"ff.fms.info_report_on_change_with_subidx",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.38.1. Request Message Parameters
		 */
		{ &hf_ff_fms_info_report_on_change_with_subidx_req,
			{ "FMS Information Report On Change Request",
				"ff.fms.info_report_on_change_with_subidx.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_info_report_on_change_with_subidx_req_idx,
			{ "Index", "ff.fms.info_report_on_change_with_subidx.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_info_report_on_change_with_subidx_req_subidx,
			{ "Subindex", "ff.fms.info_report_on_change_with_subidx.req.subidx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.39. FMS Event Notification (Unconfirmed Service Id = 2)
		 */
		{ &hf_ff_fms_ev_notification,
			{ "FMS Event Notification", "ff.fms.ev_notification",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.39.1. Request Message Parameters
		 */
		{ &hf_ff_fms_ev_notification_req,
			{ "FMS Event Notification Request", "ff.fms.ev_notification.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ev_notification_req_idx,
			{ "Index", "ff.fms.ev_notification.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ev_notification_req_ev_num,
			{ "Event Number", "ff.fms.ev_notification.req.ev_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.40. FMS Alter Event Condition Monitoring
		 *           (Confirmed Service Id = 24)
		 */
		{ &hf_ff_fms_alter_ev_condition_monitoring,
			{ "FMS Alter Event Condition Monitoring",
				"ff.fms.alter_ev_condition_monitoring",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.40.1. Request Message Parameters
		 */
		{ &hf_ff_fms_alter_ev_condition_monitoring_req,
			{ "FMS Alter Event Condition Monitoring Request",
				"ff.fms.alter_ev_condition_monitoring.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_alter_ev_condition_monitoring_req_idx,
			{ "Index", "ff.fms.alter_ev_condition_monitoring.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_alter_ev_condition_monitoring_req_enabled,
			{ "Enabled", "ff.fms.alter_ev_condition_monitoring.req.enabled",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.40.2. Response Message Parameters
		 */
		{ &hf_ff_fms_alter_ev_condition_monitoring_rsp,
			{ "FMS Alter Event Condition Monitoring Response",
				"ff.fms.alter_ev_condition_monitoring.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.40.3. Error Message Parameters
		 */
		{ &hf_ff_fms_alter_ev_condition_monitoring_err,
			{ "FMS Alter Event Condition Monitoring Error",
				"ff.fms.alter_ev_condition_monitoring.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_alter_ev_condition_monitoring_err_err_class,
			{ "Error Class",
				"ff.fms.alter_ev_condition_monitoring.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_alter_ev_condition_monitoring_err_err_code,
			{ "Error Code", "ff.fms.alter_ev_condition_monitoring.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_alter_ev_condition_monitoring_err_additional_code,
			{ "Additional Code",
				"ff.fms.alter_ev_condition_monitoring.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_alter_ev_condition_monitoring_err_additional_desc,
			{ "Additional Description",
				"ff.fms.alter_ev_condition_monitoring.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.41. FMS Acknowledge Event Notification
		 *           (Confirmed Service Id = 25)
		 */
		{ &hf_ff_fms_ack_ev_notification,
			{ "FMS Acknowledge Event Notification",
				"ff.fms.ack_ev_notification",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.41.1. Request Message Parameters
		 */
		{ &hf_ff_fms_ack_ev_notification_req,
			{ "FMS Acknowledge Event Notification Request",
				"ff.fms.ack_ev_notification.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ack_ev_notification_req_idx,
			{ "Index", "ff.fms.ack_ev_notification.req.idx",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ack_ev_notification_req_ev_num,
			{ "Event Number", "ff.fms.ack_ev_notification.req.ev_num",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.41.2. Response Message Parameters
		 */
		{ &hf_ff_fms_ack_ev_notification_rsp,
			{ "FMS Acknowledge Event Notification Response",
				"ff.fms.ack_ev_notification.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.3.41.3. Error Message Parameters
		 */
		{ &hf_ff_fms_ack_ev_notification_err,
			{ "FMS Acknowledge Event Notification Error",
				"ff.fms.ack_ev_notification.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ack_ev_notification_err_err_class,
			{ "Error Class", "ff.fms.ack_ev_notification.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ack_ev_notification_err_err_code,
			{ "Error Code", "ff.fms.ack_ev_notification.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ack_ev_notification_err_additional_code,
			{ "Additional Code",
				"ff.fms.ack_ev_notification.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_fms_ack_ev_notification_err_additional_desc,
			{ "Additional Description",
				"ff.fms.ack_ev_notification.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4. LAN Redundancy Services
		 */
		{ &hf_ff_lr,
			{ "LAN Redundancy Service", "ff.lr",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.1. LAN Redundancy Get Information (Confirmed Service Id = 1)
		 */
		{ &hf_ff_lr_get_info,
			{ "LAN Redundancy Get Information",
				"ff.lr.get_info",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.1.1. Request Message Parameters
		 */
		{ &hf_ff_lr_get_info_req,
			{ "LAN Redundancy Get Information Request",
				"ff.lr.get_info.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.1.2. Response Message Parameters
		 */
		{ &hf_ff_lr_get_info_rsp,
			{ "LAN Redundancy Get Information Response",
				"ff.lr.get_info.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_lr_attrs_ver,
			{ "LAN Redundancy Attributes Version",
				"ff.lr.get_info.rsp.lr_attrs_ver",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_lr_max_msg_num_diff,
			{ "Max Message Number Difference",
				"ff.lr.get_info.rsp.max_msg_num_diff",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_reserved,
			{ "Reserved",
				"ff.lr.get_info.rsp.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_diagnostic_msg_intvl,
			{ "Diagnostic Message Interval",
				"ff.lr.get_info.rsp.diagnostic_msg_intvl",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_aging_time,
			{ "Aging Time",
				"ff.lr.get_info.rsp.aging_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_diagnostic_msg_if_a_send_addr,
			{ "Diagnostic Message Interface A Send Address",
				"ff.lr.get_info.rsp.diagnostic_msg_if_a_send_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_diagnostic_msg_if_a_recv_addr,
			{ "Diagnostic Message Interface A Receive Address",
				"ff.lr.get_info.rsp.diagnostic_msg_if_a_recv_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_diagnostic_msg_if_b_send_addr,
			{ "Diagnostic Message Interface B Send Address",
				"ff.lr.get_info.rsp.diagnostic_msg_if_b_send_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_rsp_diagnostic_msg_if_b_recv_addr,
			{ "Diagnostic Message Interface B Receive Address",
				"ff.lr.get_info.rsp.diagnostic_msg_if_b_recv_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.1.3. Error Message Parameters
		 */
		{ &hf_ff_lr_get_info_err,
			{ "LAN Redundancy Get Information Error",
				"ff.lr.get_info.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_err_err_class,
			{ "Error Class", "ff.lr.get_info.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_err_err_code,
			{ "Error Code", "ff.lr.get_info.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_err_additional_code,
			{ "Additional Code",
				"ff.lr.get_info.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_info_err_additional_desc,
			{ "Additional Description",
				"ff.lr.get_info.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.2. LAN Redundancy Put Information (Confirmed Service Id = 2)
		 */
		{ &hf_ff_lr_put_info,
			{ "LAN Redundancy Put Information", "ff.lr.put_info",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.2.1. Request Message Parameters
		 */
		{ &hf_ff_lr_put_info_req,
			{ "LAN Redundancy Put Information Request", "ff.lr.put_info.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_lr_attrs_ver,
			{ "LAN Redundancy Attributes Version",
				"ff.lr.put_info.req.lr_attrs_ver",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_lr_max_msg_num_diff,
			{ "Max Message Number Difference",
				"ff.lr.put_info.req.max_msg_num_diff",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_reserved,
			{ "Reserved",
				"ff.lr.put_info.req.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_diagnostic_msg_intvl,
			{ "Diagnostic Message Interval",
				"ff.lr.put_info.req.diagnostic_msg_intvl",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_aging_time,
			{ "Aging Time",
				"ff.lr.put_info.req.aging_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_diagnostic_msg_if_a_send_addr,
			{ "Diagnostic Message Interface A Send Address",
				"ff.lr.put_info.req.diagnostic_msg_if_a_send_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_diagnostic_msg_if_a_recv_addr,
			{ "Diagnostic Message Interface A Receive Address",
				"ff.lr.put_info.req.diagnostic_msg_if_a_recv_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_diagnostic_msg_if_b_send_addr,
			{ "Diagnostic Message Interface B Send Address",
				"ff.lr.put_info.req.diagnostic_msg_if_b_send_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_req_diagnostic_msg_if_b_recv_addr,
			{ "Diagnostic Message Interface B Receive Address",
				"ff.lr.put_info.req.diagnostic_msg_if_b_recv_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.2.2. Response Message Parameters
		 */
		{ &hf_ff_lr_put_info_rsp,
			{ "LAN Redundancy Put Information Response",
				"ff.lr.put_info.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_lr_attrs_ver,
			{ "LAN Redundancy Attributes Version",
				"ff.lr.put_info.rsp.lr_attrs_ver",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_lr_max_msg_num_diff,
			{ "Max Message Number Difference",
				"ff.lr.put_info.rsp.max_msg_num_diff",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_reserved,
			{ "Reserved",
				"ff.lr.put_info.rsp.reserved",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_diagnostic_msg_intvl,
			{ "Diagnostic Message Interval",
				"ff.lr.put_info.rsp.diagnostic_msg_intvl",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_aging_time,
			{ "Aging Time",
				"ff.lr.put_info.rsp.aging_time",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_diagnostic_msg_if_a_send_addr,
			{ "Diagnostic Message Interface A Send Address",
				"ff.lr.put_info.rsp.diagnostic_msg_if_a_send_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_diagnostic_msg_if_a_recv_addr,
			{ "Diagnostic Message Interface A Receive Address",
				"ff.lr.put_info.rsp.diagnostic_msg_if_a_recv_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_diagnostic_msg_if_b_send_addr,
			{ "Diagnostic Message Interface B Send Address",
				"ff.lr.put_info.rsp.diagnostic_msg_if_b_send_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_rsp_diagnostic_msg_if_b_recv_addr,
			{ "Diagnostic Message Interface B Receive Address",
				"ff.lr.put_info.rsp.diagnostic_msg_if_b_recv_addr",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.2.3. Error Message Parameters
		 */
		{ &hf_ff_lr_put_info_err,
			{ "LAN Redundancy Put Information Error", "ff.lr.put_info.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_err_err_class,
			{ "Error Class", "ff.lr.put_info.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_err_err_code,
			{ "Error Code", "ff.lr.put_info.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_err_additional_code,
			{ "Additional Code",
				"ff.lr.put_info.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_put_info_err_additional_desc,
			{ "Additional Description",
				"ff.lr.put_info.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.3. LAN Redundancy Get Statistics (Confirmed Service Id = 3)
		 */
		{ &hf_ff_lr_get_statistics,
			{ "LAN Redundancy Get Statistics",
				"ff.lr.get_statistics",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.3.1. Request Message Parameters
		 */
		{ &hf_ff_lr_get_statistics_req,
			{ "LAN Redundancy Get Statistics Request",
				"ff.lr.get_statistics.req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.3.2. Response Message Parameters
		 */
		{ &hf_ff_lr_get_statistics_rsp,
			{ "LAN Redundancy Get Statistics Response",
				"ff.lr.get_statistics.rsp",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_recv_a,
			{ "Error Code", "ff.lr.get_statistics.rsp.num_diag_svr_ind_recv_a",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_miss_a,
			{ "Error Code", "ff.lr.get_statistics.rsp.num_diag_svr_ind_miss_a",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_rem_dev_diag_recv_fault_a,
			{ "Error Code",
				"ff.lr.get_statistics.rsp.num_rem_dev_diag_recv_fault_a",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_recv_b,
			{ "Error Code", "ff.lr.get_statistics.rsp.num_diag_svr_ind_recv_b",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_diag_svr_ind_miss_b,
			{ "Error Code", "ff.lr.get_statistics.rsp.num_diag_svr_ind_miss_b",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_rem_dev_diag_recv_fault_b,
			{ "Error Code",
				"ff.lr.get_statistics.rsp.num_rem_dev_diag_recv_fault_b",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_num_x_cable_stat,
			{ "Error Code", "ff.lr.get_statistics.rsp.num_x_cable_stat",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_rsp_x_cable_stat,
			{ "Error Code", "ff.lr.get_statistics.rsp.x_cable_stat",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.3.3. Error Message Parameters
		 */
		{ &hf_ff_lr_get_statistics_err,
			{ "LAN Redundancy Get Statistics Error",
				"ff.lr.get_statistics.err",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_err_err_class,
			{ "Error Class", "ff.lr.get_statistics.err.err_class",
				FT_UINT8, BASE_DEC, VALS(names_err_class), 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_err_err_code,
			{ "Error Code", "ff.lr.get_statistics.err.err_code",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_err_additional_code,
			{ "Additional Code",
				"ff.lr.get_statistics.err.additional_code",
				FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_get_statistics_err_additional_desc,
			{ "Additional Description",
				"ff.lr.get_statistics.err.additional_desc",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.4 Diagnostic Message (Unconfirmed Service Id = 1)
		 */
		{ &hf_ff_lr_diagnostic_msg,
			{ "Diagnostic Message", "ff.lr.diagnostic_msg",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },



		/*
		 * 6.5.4.4.1. Request Message Parameters
		 */
		{ &hf_ff_lr_diagnostic_msg_req,
			{ "Diagnostic Message Request", "ff.lr.diagnostic_msg_req",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_dev_idx,
			{ "Device Index", "ff.lr.diagnostic_msg.req.dev_idx",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_num_of_network_ifs,
			{ "Number of Network Interfaces",
				"ff.lr.diagnostic_msg.req.num_of_network_ifs",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_transmission_if,
			{ "Transmission Interface",
				"ff.lr.diagnostic_msg.req.transmission_if",
				FT_UINT8, BASE_DEC, VALS(names_transmission_interface), 0x0,
				NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_diagnostic_msg_intvl,
			{ "Diagnostic Message Interval",
				"ff.lr.diagnostic_msg.req.diagnostic_msg_intvl",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_pd_tag,
			{ "PD Tag", "ff.lr.diagnostic_msg.req.pd_tag",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_reserved,
			{ "Reserved", "ff.lr.diagnostic_msg.req.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_num_of_if_statuses,
			{ "Number of Interface Statuses",
				"ff.lr.diagnostic_msg.req.num_of_if_statuses",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_if_a_to_a_status,
			{ "Interface AtoA Status",
				"ff.lr.diagnostic_msg.req.if_a_to_a_status",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_if_b_to_a_status,
			{ "Interface BtoA Status",
				"ff.lr.diagnostic_msg.req.if_b_to_a_status",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_if_a_to_b_status,
			{ "Interface AtoB Status",
				"ff.lr.diagnostic_msg.req.if_a_to_b_status",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_ff_lr_diagnostic_msg_req_if_b_to_b_status,
			{ "Interface BtoB Status",
				"ff.lr.diagnostic_msg.req.if_b_to_b_status",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	};



	static gint *ett[] = {
		&ett_ff,
		&ett_ff_fda_msg_hdr,
		&ett_ff_fda_msg_hdr_proto_and_type,
		&ett_ff_fda_msg_hdr_opts,
		&ett_ff_fda_msg_hdr_srv,

		&ett_ff_fda_msg_trailer,

		&ett_ff_fda_open_sess_req,
		&ett_ff_fda_open_sess_rsp,
		&ett_ff_fda_open_sess_err,

		&ett_ff_fda_idle_req,
		&ett_ff_fda_idle_rsp,
		&ett_ff_fda_idle_err,

		&ett_ff_sm_find_tag_query_req,
		&ett_ff_sm_find_tag_reply_req,
		&ett_ff_sm_find_tag_reply_req_dup_detection_state,
		&ett_ff_sm_find_tag_reply_req_list_of_fda_addr_selectors,

		&ett_ff_sm_id_req,
		&ett_ff_sm_id_rsp,
		&ett_ff_sm_id_rsp_smk_state,
		&ett_ff_sm_id_rsp_dev_type,
		&ett_ff_sm_id_rsp_dev_redundancy_state,
		&ett_ff_sm_id_rsp_dup_detection_state,
		&ett_ff_sm_id_rsp_entries_h1_live_list,
		&ett_ff_sm_id_rsp_h1_live_list,
		&ett_ff_sm_id_rsp_entries_node_addr,
		&ett_ff_sm_id_rsp_h1_node_addr,
		&ett_ff_sm_id_err,

		&ett_ff_sm_clear_addr_req,
		&ett_ff_sm_clear_addr_rsp,
		&ett_ff_sm_clear_addr_err,

		&ett_ff_sm_set_assign_info_req,
		&ett_ff_sm_set_assign_info_req_dev_redundancy_state,
		&ett_ff_sm_set_assign_info_req_clear_dup_detection_state,
		&ett_ff_sm_set_assign_info_rsp,
		&ett_ff_sm_set_assign_info_err,

		&ett_ff_sm_clear_assign_info_req,
		&ett_ff_sm_clear_assign_info_rsp,
		&ett_ff_sm_clear_assign_info_err,

		&ett_ff_sm_dev_annunc_req,
		&ett_ff_sm_dev_annunc_req_smk_state,
		&ett_ff_sm_dev_annunc_req_dev_type,
		&ett_ff_sm_dev_annunc_req_dev_redundancy_state,
		&ett_ff_sm_dev_annunc_req_dup_detection_state,
		&ett_ff_sm_dev_annunc_req_entries_h1_live_list,
		&ett_ff_sm_dev_annunc_req_h1_live_list,
		&ett_ff_sm_dev_annunc_req_entries_node_addr,
		&ett_ff_sm_dev_annunc_req_h1_node_addr,

		&ett_ff_fms_init_req,
		&ett_ff_fms_init_rep,
		&ett_ff_fms_init_err,

		&ett_ff_fms_abort_req,

		&ett_ff_fms_status_req,
		&ett_ff_fms_status_rsp,
		&ett_ff_fms_status_err,

		&ett_ff_fms_unsolicited_status_req,

		&ett_ff_fms_id_req,
		&ett_ff_fms_id_rsp,
		&ett_ff_fms_id_err,

		&ett_ff_fms_get_od_req,
		&ett_ff_fms_get_od_rsp,
		&ett_ff_fms_get_od_err,

		&ett_ff_fms_init_put_od_req,
		&ett_ff_fms_init_put_od_rsp,
		&ett_ff_fms_init_put_od_err,

		&ett_ff_fms_put_od_req,
		&ett_ff_fms_put_od_rsp,
		&ett_ff_fms_put_od_err,

		&ett_ff_fms_terminate_put_od_req,
		&ett_ff_fms_terminate_put_od_rsp,
		&ett_ff_fms_terminate_put_od_err,

		&ett_ff_fms_gen_init_download_seq_req,
		&ett_ff_fms_gen_init_download_seq_rep,
		&ett_ff_fms_gen_init_download_seq_err,

		&ett_ff_fms_gen_download_seg_req,
		&ett_ff_fms_gen_download_seg_rsp,
		&ett_ff_fms_gen_download_seg_err,

		&ett_ff_fms_gen_terminate_download_seq_req,
		&ett_ff_fms_gen_terminate_download_seq_rsp,
		&ett_ff_fms_gen_terminate_download_seq_err,

		&ett_ff_fms_init_download_seq_req,
		&ett_ff_fms_init_download_seq_rsp,
		&ett_ff_fms_init_download_seq_err,

		&ett_ff_fms_download_seg_req,
		&ett_ff_fms_download_seg_rsp,
		&ett_ff_fms_download_seg_err,

		&ett_ff_fms_terminate_download_seq_req,
		&ett_ff_fms_terminate_download_seq_rsp,
		&ett_ff_fms_terminate_download_seq_err,

		&ett_ff_fms_init_upload_seq_req,
		&ett_ff_fms_init_upload_seq_rsp,
		&ett_ff_fms_init_upload_seq_err,

		&ett_ff_fms_upload_seg_req,
		&ett_ff_fms_upload_seg_rsp,
		&ett_ff_fms_upload_seg_err,

		&ett_ff_fms_terminate_upload_seq_req,
		&ett_ff_fms_terminate_upload_seq_rsp,
		&ett_ff_fms_terminate_upload_seq_err,

		&ett_ff_fms_req_dom_download_req,
		&ett_ff_fms_req_dom_download_rsp,
		&ett_ff_fms_req_dom_download_err,

		&ett_ff_fms_req_dom_upload_req,
		&ett_ff_fms_req_dom_upload_rsp,
		&ett_ff_fms_req_dom_upload_err,

		&ett_ff_fms_create_pi_req,
		&ett_ff_fms_create_pi_req_list_of_dom_idxes,
		&ett_ff_fms_create_pi_rsp,
		&ett_ff_fms_create_pi_err,

		&ett_ff_fms_del_pi_req,
		&ett_ff_fms_del_pi_rsp,
		&ett_ff_fms_del_pi_err,

		&ett_ff_fms_start_req,
		&ett_ff_fms_start_rsp,
		&ett_ff_fms_start_err,

		&ett_ff_fms_stop_req,
		&ett_ff_fms_stop_rsp,
		&ett_ff_fms_stop_err,

		&ett_ff_fms_resume_req,
		&ett_ff_fms_resume_rsp,
		&ett_ff_fms_resume_err,

		&ett_ff_fms_reset_req,
		&ett_ff_fms_reset_rsp,
		&ett_ff_fms_reset_err,

		&ett_ff_fms_kill_req,
		&ett_ff_fms_kill_rsp,
		&ett_ff_fms_kill_err,

		&ett_ff_fms_read_req,
		&ett_ff_fms_read_rsp,
		&ett_ff_fms_read_err,

		&ett_ff_fms_read_with_subidx_req,
		&ett_ff_fms_read_with_subidx_rsp,
		&ett_ff_fms_read_with_subidx_err,

		&ett_ff_fms_write_req,
		&ett_ff_fms_write_rsp,
		&ett_ff_fms_write_err,

		&ett_ff_fms_write_with_subidx_req,
		&ett_ff_fms_write_with_subidx_rsp,
		&ett_ff_fms_write_with_subidx_err,

		&ett_ff_fms_def_variable_list_req,
		&ett_ff_fms_def_variable_list_req_list_of_idxes,
		&ett_ff_fms_def_variable_list_rsp,
		&ett_ff_fms_def_variable_list_err,

		&ett_ff_fms_del_variable_list_req,
		&ett_ff_fms_del_variable_list_rsp,
		&ett_ff_fms_del_variable_list_err,

		&ett_ff_fms_info_report_req,

		&ett_ff_fms_info_report_with_subidx_req,

		&ett_ff_fms_info_report_on_change_req,

		&ett_ff_fms_info_report_on_change_with_subidx_req,

		&ett_ff_fms_ev_notification_req,

		&ett_ff_fms_alter_ev_condition_monitoring_req,
		&ett_ff_fms_alter_ev_condition_monitoring_rsp,
		&ett_ff_fms_alter_ev_condition_monitoring_err,

		&ett_ff_fms_ack_ev_notification_req,
		&ett_ff_fms_ack_ev_notification_rsp,
		&ett_ff_fms_ack_ev_notification_err,

		&ett_ff_lr_get_info_req,
		&ett_ff_lr_get_info_rsp,
		&ett_ff_lr_get_info_rsp_lr_flags,
		&ett_ff_lr_get_info_err,

		&ett_ff_lr_put_info_req,
		&ett_ff_lr_put_info_req_lr_flags,
		&ett_ff_lr_put_info_rsp,
		&ett_ff_lr_put_info_rsp_lr_flags,
		&ett_ff_lr_put_info_err,

		&ett_ff_lr_get_statistics_req,
		&ett_ff_lr_get_statistics_rsp,
		&ett_ff_lr_get_statistics_rsp_list_of_x_cable_stat,
		&ett_ff_lr_get_statistics_err,

		&ett_ff_lr_diagnostic_msg_req,
		&ett_ff_lr_diagnostic_msg_req_dup_detection_stat,
		&ett_ff_lr_diagnostic_msg_req_a_to_a_status,
		&ett_ff_lr_diagnostic_msg_req_b_to_a_status,
		&ett_ff_lr_diagnostic_msg_req_a_to_b_status,
		&ett_ff_lr_diagnostic_msg_req_b_to_b_status,
	};

	proto_ff = proto_register_protocol("FOUNDATION Fieldbus", "FF", "ff");
	proto_register_field_array(proto_ff, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	return;
}



void
proto_reg_handoff_ff(void)
{
	/*
	 * 4.8. Using UDP and TCP
	 */
	ff_udp_handle = create_dissector_handle(dissect_ff_udp, proto_ff);
	ff_tcp_handle = create_dissector_handle(dissect_ff_tcp, proto_ff);

	/*
	 * 4.8.4.2. Use
	 *
	 * - Device Annunciation
	 */
	dissector_add_uint("udp.port", UDP_PORT_FF_ANNUNC, ff_udp_handle);

	/*
	 * 4.8.4.2. Use
	 *
	 * - Client / Server
	 */
	dissector_add_uint("udp.port", UDP_PORT_FF_FMS, ff_udp_handle);
	dissector_add_uint("tcp.port", TCP_PORT_FF_FMS, ff_tcp_handle);

	/*
	 * 4.8.4.2. Use
	 *
	 * - Set/Clear Assignment Info and Clear Address
	 * - SM Identify
	 * - SM Find Tag
	 */
	dissector_add_uint("udp.port", UDP_PORT_FF_SM, ff_udp_handle);

	/*
	 * 4.8.4.2. Use
	 *
	 * - LAN Redundancy Get and Put Information
	 */
	dissector_add_uint("udp.port", UDP_PORT_FF_LR_PORT, ff_udp_handle);

	return;
}
