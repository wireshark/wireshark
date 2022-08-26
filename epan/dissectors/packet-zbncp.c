/* packet-zbncp.c
 * Dissector routines for the ZBOSS Network Co-Processor (NCP)
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>

#include "packet-ieee802154.h"
#include "packet-zbncp.h"
#include "conversation.h"

void proto_reg_handoff_zbncp(void);
void proto_register_zbncp(void);
extern void dissect_zbee_nwk_status_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
extern void dissect_zbee_aps_status_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);

#define ZBNCP_PROTOABBREV "zbncp"

#define ZBNCP_SIGN_FST_BYTE                                                                0xDEU
#define ZBNCP_SIGN_SEC_BYTE                                                                0xADU
#define ZBNCP_HDR_SIZE                                                                     7

#define ZBNCP_HDR_FLAGS_ISACK_MASK                                                         0x01
#define ZBNCP_HDR_FLAGS_RETRANS_MASK                                                       0x02
#define ZBNCP_HDR_FLAGS_PKT_SEQ_MASK                                                       0x0C
#define ZBNCP_HDR_FLAGS_ACK_SEQ_MASK                                                       0x30
#define ZBNCP_HDR_FLAGS_ISFIRST_MASK                                                       0x40
#define ZBNCP_HDR_FLAGS_ISLAST_MASK                                                        0x80

#define ZBNCP_DUMP_INFO_SIGN                                                               "ZBNCP"
#define ZBNCP_DUMP_INFO_SIGN_SIZE                                                          (sizeof(ZBNCP_DUMP_INFO_SIGN) - 1)
#define ZBNCP_DUMP_INFO_PAYLOAD_SIZE                                                       3
#define ZBNCP_DUMP_INFO_NCP_TYPE                                                           0x06U
#define ZBNCP_DUMP_INFO_SIZE                                                               (ZBNCP_DUMP_INFO_SIGN_SIZE + ZBNCP_DUMP_INFO_PAYLOAD_SIZE)
#define ZBNCP_DUMP_DIR_MASK                                                                0x01U
#define ZBNCP_DUMP_HOST_INT_DUMP_MASK                                                      0x02U
#define ZBNCP_DUMP_POTENTIAL_TX_RX_ERROR_MASK                                              0x04U

/* decryption helpers */
static guint dissect_zbncp_ll_hdr(tvbuff_t *, packet_info *, proto_tree *, guint, guint8 *);
static void dissect_zbncp_body(tvbuff_t *, packet_info *, proto_tree *, guint, guint16 *);
static void dissect_zbncp_high_level(tvbuff_t *, packet_info *, proto_tree *, guint, guint16 *);
static guint dissect_zbncp_high_level_hdr(tvbuff_t *, packet_info *, proto_tree *, guint, guint8 *, guint16 *);
static void dissect_zbncp_high_level_body(tvbuff_t *, packet_info *, proto_tree *, guint, guint8, guint16);
static void dissect_zbncp_fragmentation_body(tvbuff_t *, packet_info *, proto_tree *, guint);
static guint dissect_zbncp_packet(tvbuff_t *, packet_info *, proto_tree *, guint);
static guint dissect_zbncp_status(tvbuff_t *, packet_info *, proto_tree *, guint);

static tvbuff_t *dissect_zbncp_dump_info(tvbuff_t *, packet_info *, proto_tree *);

/*-------------------------------------
 * Dissector Function Prototypes
 *-------------------------------------
 */
/* Dissection Routines. */

/* Initialize Protocol and Registered fields */

/* ZBNCP hdr */
static int zbncp_frame = -1;
static int proto_zbncp = -1;

static int hf_zbncp_hdr_sign = -1;
static int hf_zbncp_packet_len = -1;
static int hf_zbncp_hdr_type = -1;
static int hf_zbncp_hdr_flags = -1;
static int hf_zbncp_hdr_flags_isack = -1;
static int hf_zbncp_hdr_flags_retrans = -1;
static int hf_zbncp_hdr_flags_packetseq = -1;
static int hf_zbncp_hdr_flags_ackseq = -1;
static int hf_zbncp_hdr_flags_first_frag = -1;
static int hf_zbncp_hdr_flags_last_frag = -1;
static int hf_zbncp_hdr_crc8 = -1;

static int hf_zbncp_body_data_crc16 = -1;
static int hf_zbncp_data_hl_version = -1;
static int hf_zbncp_data_hl_packet_type = -1;
static int hf_zbncp_data_hl_call_id = -1;
static int hf_zbncp_data_hl_tsn = -1;
static int hf_zbncp_data_hl_status_cat = -1;
static int hf_zbncp_data_hl_status = -1;
static int hf_zbncp_data_hl_status_generic = -1;
static int hf_zbncp_data_hl_status_mac = -1;
static int hf_zbncp_data_hl_status_nwk = -1;
static int hf_zbncp_data_hl_status_cbke = -1;
static int hf_zbncp_data_fw_vers = -1;
static int hf_zbncp_data_stack_vers = -1;
static int hf_zbncp_data_proto_vers = -1;
static int hf_zbncp_data_reset_opt = -1;
static int hf_zbncp_data_zb_role = -1;
static int hf_zbncp_data_ch_list_len = -1;
static int hf_zbncp_data_page = -1;
static int hf_zbncp_data_ch_mask = -1;
static int hf_zbncp_data_channel = -1;
static int hf_zbncp_data_channel4 = -1;
static int hf_zbncp_data_pan_id = -1;
static int hf_zbncp_data_mac_int_num = -1;
static int hf_zbncp_data_index = -1;
static int hf_zbncp_data_enable = -1;
static int hf_zbncp_data_bind_type = -1;
static int hf_zbncp_data_ieee_addr = -1;
static int hf_zbncp_data_ext_pan_id = -1;
static int hf_zbncp_data_coordinator_version = -1;
static int hf_zbncp_data_trust_center_addres = -1;
static int hf_zbncp_data_remote_ieee_addr = -1;
static int hf_zbncp_data_src_ieee_addr = -1;
static int hf_zbncp_data_dst_ieee_addr = -1;
static int hf_zbncp_data_partner_ieee_addr = -1;
static int hf_zbncp_data_trace_mask = -1;
static int hf_zbncp_data_trace_wireless_traf = -1;
static int hf_zbncp_data_trace_reserved = -1;
static int hf_zbncp_data_trace_ncp_ll_proto = -1;
static int hf_zbncp_data_trace_host_int_line = -1;
static int hf_zbncp_data_trace_sleep_awake = -1;
static int hf_zbncp_data_keepalive = -1;
static int hf_zbncp_data_rx_on_idle = -1;
static int hf_zbncp_data_res_tx_power = -1;
static int hf_zbncp_data_req_tx_power = -1;
static int hf_zbncp_data_joined = -1;
static int hf_zbncp_data_joined_bit = -1;
static int hf_zbncp_data_parent_bit = -1;
static int hf_zbncp_data_authenticated = -1;
static int hf_zbncp_data_timeout = -1;
static int hf_zbncp_data_keepalive_mode = -1;
static int hf_zbncp_force_route_record_sending = -1;
static int hf_zbncp_data_nwk_addr = -1;
static int hf_zbncp_data_nwk_parent_addr = -1;
static int hf_zbncp_data_src_nwk_addr = -1;
static int hf_zbncp_data_dst_nwk_addr = -1;
static int hf_zbncp_data_remote_nwk_addr = -1;
static int hf_zbncp_data_group_nwk_addr = -1;
static int hf_zbncp_data_src_mac_addr = -1;
static int hf_zbncp_data_dst_mac_addr = -1;
static int hf_zbncp_data_nwk_key = -1;
static int hf_zbncp_data_key_num = -1;
static int hf_zbncp_data_serial_num = -1;
static int hf_zbncp_data_size = -1;
static int hf_zbncp_data_vendor_data = -1;
static int hf_zbncp_data_dump_type = -1;
static int hf_zbncp_data_dump_text = -1;
static int hf_zbncp_data_dump_bin = -1;
static int hf_zbncp_data_parameter_id = -1;
static int hf_zbncp_data_value8_dec = -1;
static int hf_zbncp_data_value16_dec = -1;
static int hf_zbncp_data_aps_ack_to_non_sleepy = -1;
static int hf_zbncp_data_aps_ack_to_sleepy = -1;
static int hf_zbncp_data_min16 = -1;
static int hf_zbncp_data_max16 = -1;
static int hf_zbncp_data_default8_sign = -1;
static int hf_zbncp_data_current8_sign = -1;
static int hf_zbncp_data_is_concentrator = -1;
static int hf_zbncp_data_concentrator_radius = -1;
static int hf_zbncp_data_time16 = -1;
static int hf_zbncp_data_lock_status = -1;
static int hf_zbncp_data_reset_source = -1;
static int hf_zbncp_nwk_leave_allowed = -1;
static int hf_zbncp_data_nvram_dataset_quantity = -1;
static int hf_zbncp_data_nvram_dataset_type = -1;
static int hf_zbncp_data_nvram_version = -1;
static int hf_zbncp_data_dataset_version = -1;
static int hf_zbncp_data_dataset_length = -1;
static int hf_zbncp_data_nvram_dataset_data = -1;
static int hf_zbncp_data_tc_policy_type = -1;
static int hf_zbncp_data_tc_policy_value = -1;
static int hf_zbncp_max_children = -1;
static int hf_zbncp_zdo_leave_allowed = -1;
static int hf_zbncp_zdo_leave_wo_rejoin_allowed = -1;
static int hf_zbncp_data_aps_key = -1;
static int hf_zbncp_data_endpoint = -1;
static int hf_zbncp_data_aps_group_num = -1;
static int hf_zbncp_data_aps_group = -1;
static int hf_zbncp_data_src_endpoint = -1;
static int hf_zbncp_data_dst_endpoint = -1;
static int hf_zbncp_data_poll_pkt_cnt = -1;
static int hf_zbncp_data_poll_timeout = -1;
static int hf_zbncp_data_poll_permit_flag = -1;
static int hf_zbncp_data_profile_id = -1;
static int hf_zbncp_data_device_id = -1;
static int hf_zbncp_data_dev_version = -1;
static int hf_zbncp_data_in_cl_cnt = -1;
static int hf_zbncp_data_out_cl_cnt = -1;
static int hf_zbncp_data_cluster_id = -1;
static int hf_zbncp_data_mac_cap = -1;
static int hf_zbncp_data_manuf_id = -1;
static int hf_zbncp_data_cur_pwr_mode = -1;
static int hf_zbncp_data_cur_pwr_lvl = -1;
static int hf_zbncp_data_susp_period = -1;
static int hf_zbncp_data_av_pwr_src = -1;
static int hf_zbncp_data_cur_pwr_src = -1;
static int hf_zbncp_data_pwr_src_const = -1;
static int hf_zbncp_data_pwr_src_recharge = -1;
static int hf_zbncp_data_pwr_src_disposable = -1;
static int hf_zbncp_data_req_type = -1;
static int hf_zbncp_data_start_idx = -1;
static int hf_zbncp_data_start_idx_16b = -1;
static int hf_zbncp_data_upd_idx = -1;
static int hf_zbncp_data_entry_idx = -1;
static int hf_zbncp_data_num_asoc_dec = -1;
static int hf_zbncp_data_pwr_desc = -1;
static int hf_zbncp_data_pwr_desc_cur_power_mode = -1;
static int hf_zbncp_data_pwr_desc_av_pwr_src = -1;
static int hf_zbncp_data_pwr_desc_cur_pwr_src = -1;
static int hf_zbncp_data_pwr_desc_cur_pwr_lvl = -1;
static int hf_zbncp_data_max_buf_size = -1;
static int hf_zbncp_data_max_inc_trans_size = -1;
static int hf_zbncp_data_max_out_trans_size = -1;
static int hf_zbncp_data_desc_cap = -1;
static int hf_zbncp_data_desc_cap_ext_act_ep_list_av = -1;
static int hf_zbncp_data_desc_cap_ext_simple_desc_list_av = -1;
static int hf_zbncp_data_flags8 = -1;
static int hf_zbncp_data_flags_permit_join = -1;
static int hf_zbncp_data_flags_router_cap = -1;
static int hf_zbncp_data_flags_ed_cap = -1;
static int hf_zbncp_data_flags_stack_profile = -1;
static int hf_zbncp_data_flags16 = -1;
static int hf_zbncp_data_flags_zb_role = -1;
static int hf_zbncp_data_flags_comp_desc_av = -1;
static int hf_zbncp_data_flags_user_desc_av = -1;
static int hf_zbncp_data_flags_freq_868 = -1;
static int hf_zbncp_data_flags_freq_902 = -1;
static int hf_zbncp_data_flags_freq_2400 = -1;
static int hf_zbncp_data_flags_freq_eu_sub_ghz = -1;
static int hf_zbncp_data_srv_msk = -1;
static int hf_zbncp_data_srv_msk_prim_tc = -1;
static int hf_zbncp_data_srv_msk_backup_tc = -1;
static int hf_zbncp_data_srv_msk_prim_bind_tbl_cache = -1;
static int hf_zbncp_data_srv_msk_backup_bind_tbl_cache = -1;
static int hf_zbncp_data_remote_bind_offset = -1;
static int hf_zbncp_data_srv_msk_prim_disc_cache = -1;
static int hf_zbncp_data_srv_msk_backup_disc_cache = -1;
static int hf_zbncp_data_srv_msk_nwk_manager = -1;
static int hf_zbncp_data_srv_msk_stack_compl_rev = -1;
static int hf_zbncp_data_ep_cnt = -1;
static int hf_zbncp_data_dst_addr_mode = -1;
static int hf_zbncp_data_leave_flags = -1;
static int hf_zbncp_data_leave_flags_remove_chil = -1;
static int hf_zbncp_data_leave_flags_rejoin = -1;
static int hf_zbncp_data_permit_dur = -1;
static int hf_zbncp_data_tc_sign = -1;
static int hf_zbncp_data_secur_rejoin = -1;
static int hf_zbncp_data_zdo_rejoin_flags = -1;
static int hf_zbncp_data_zdo_rejoin_flags_tcsw_happened = -1;
static int hf_zbncp_data_dlen8 = -1;
static int hf_zbncp_data_dlen16 = -1;
static int hf_zbncp_data_param_len = -1;
static int hf_zbncp_data_radius = -1;
static int hf_zbncp_data_time_between_disc = -1;
static int hf_zbncp_data_enable_flag = -1;
static int hf_zbncp_data_array = -1;
static int hf_zbncp_data_use_alias = -1;
static int hf_zbncp_data_alias_src = -1;
static int hf_zbncp_data_alias_seq = -1;
static int hf_zbncp_data_tx_opt = -1;
static int hf_zbncp_data_tx_opt_secur = -1;
static int hf_zbncp_data_tx_opt_obsolete = -1;
static int hf_zbncp_data_tx_opt_ack = -1;
static int hf_zbncp_data_tx_opt_frag = -1;
static int hf_zbncp_data_tx_opt_inc_ext_nonce = -1;
static int hf_zbncp_data_tx_opt_force_mesh_route = -1;
static int hf_zbncp_data_tx_opt_send_route_record = -1;
static int hf_zbncp_data_lqi = -1;
static int hf_zbncp_data_rssi = -1;
static int hf_zbncp_data_do_cleanup = -1;
static int hf_zbncp_data_max_rx_bcast = -1;
static int hf_zbncp_data_mac_tx_bcast = -1;
static int hf_zbncp_data_mac_rx_ucast = -1;
static int hf_zbncp_data_mac_tx_ucast_total_zcl = -1;
static int hf_zbncp_data_mac_tx_ucast_failures_zcl = -1;
static int hf_zbncp_data_mac_tx_ucast_retries_zcl = -1;
static int hf_zbncp_data_mac_tx_ucast_total = -1;
static int hf_zbncp_data_mac_tx_ucast_failures = -1;
static int hf_zbncp_data_mac_tx_ucast_retries = -1;
static int hf_zbncp_data_mac_validate_drop_cnt = -1;
static int hf_zbncp_data_mac_phy_cca_fail_count = -1;
static int hf_zbncp_data_phy_to_mac_que_lim_reached = -1;
static int hf_zbncp_data_period_of_time = -1;
static int hf_zbncp_data_last_msg_lqi = -1;
static int hf_zbncp_data_last_msg_rssi = -1;
static int hf_zbncp_data_number_of_resets = -1;
static int hf_zbncp_data_aps_tx_bcast = -1;
static int hf_zbncp_data_aps_tx_ucast_success = -1;
static int hf_zbncp_data_aps_tx_ucast_retry = -1;
static int hf_zbncp_data_aps_tx_ucast_fail = -1;
static int hf_zbncp_data_route_disc_initiated = -1;
static int hf_zbncp_data_nwk_neighbor_added = -1;
static int hf_zbncp_data_nwk_neighbor_removed = -1;
static int hf_zbncp_data_nwk_neighbor_stale = -1;
static int hf_zbncp_upd_status_code = -1;
static int hf_zbncp_data_join_indication = -1;
static int hf_zbncp_data_childs_removed = -1;
static int hf_zbncp_data_aps_decrypt_failure = -1;
static int hf_zbncp_data_packet_buffer_allocate_failures = -1;
static int hf_zbncp_data_aps_unauthorized_key = -1;
static int hf_zbncp_data_nwk_decrypt_failure = -1;
static int hf_zbncp_data_average_mac_retry_per_aps_message_sent = -1;
static int hf_zbncp_data_nwk_fc_failure = -1;
static int hf_zbncp_data_aps_fc_failure = -1;
static int hf_zbncp_data_nwk_retry_overflow = -1;
static int hf_zbncp_data_nwk_bcast_table_full = -1;
static int hf_zbncp_data_status = -1;
static int hf_zbncp_zdo_auth_type = -1;
static int hf_zbncp_zdo_leg_auth_status_code = -1;
static int hf_zbncp_zdo_tclk_auth_status_code = -1;
static int hf_zbncp_zdo_server_mask = -1;
static int hf_zbncp_zdo_start_entry_idx = -1;
static int hf_zbncp_zdo_scan_duration = -1;
static int hf_zbncp_zdo_scan_cnt = -1;
static int hf_zbncp_zdo_scan_mgr_addr = -1;
static int hf_zbncp_data_aps_cnt = -1;
static int hf_zbncp_data_aps_fc = -1;
static int hf_zbncp_data_aps_fc_deliv_mode = -1;
static int hf_zbncp_data_aps_fc_secur = -1;
static int hf_zbncp_data_aps_fc_ack_retrans = -1;
static int hf_zbncp_data_aps_key_attr = -1;
static int hf_zbncp_data_aps_key_attr_key_src = -1;
static int hf_zbncp_data_aps_key_attr_key_used = -1;
static int hf_zbncp_data_pkt_len = -1;
static int hf_zbncp_data_pkt = -1;
static int hf_zbncp_data_scan_dur = -1;
static int hf_zbncp_data_distr_nwk_flag = -1;
static int hf_zbncp_data_nwk_count = -1;
static int hf_zbncp_data_nwk_upd_id = -1;
static int hf_zbncp_data_rejoin = -1;
static int hf_zbncp_data_rejoin_nwk = -1;
static int hf_zbncp_data_secur_en = -1;
static int hf_zbncp_data_beacon_type = -1;
static int hf_zbncp_data_beacon_order = -1;
static int hf_zbncp_data_superframe_order = -1;
static int hf_zbncp_data_battery_life_ext = -1;
static int hf_zbncp_data_enh_beacon = -1;
static int hf_zbncp_data_mac_if = -1;
static int hf_zbncp_data_mac_if_idx = -1;
static int hf_zbncp_data_ed_config = -1;
static int hf_zbncp_data_timeout_cnt = -1;
static int hf_zbncp_data_dev_timeout = -1;
static int hf_zbncp_data_relationship = -1;
static int hf_zbncp_data_tx_fail_cnt = -1;
static int hf_zbncp_data_out_cost = -1;
static int hf_zbncp_data_age = -1;
static int hf_zbncp_data_keepalive_rec = -1;
static int hf_zbncp_data_fast_poll_int = -1;
static int hf_zbncp_data_long_poll_int = -1;
static int hf_zbncp_data_fast_poll_flag = -1;
static int hf_zbncp_data_stop_fast_poll_result = -1;
static int hf_zbncp_data_time = -1;
static int hf_zbncp_data_pan_id_cnt = -1;
static int hf_zbncp_data_ic = -1;
static int hf_zbncp_data_ic_table_size = -1;
static int hf_zbncp_data_ic_ent_cnt = -1;
static int hf_zbncp_data_cs = -1;
static int hf_zbncp_data_ca_pub_key = -1;
static int hf_zbncp_data_ca_priv_key = -1;
static int hf_zbncp_data_cert = -1;
static int hf_zbncp_data_ic_en = -1;
static int hf_zbncp_data_key_type = -1;
static int hf_zbncp_data_issuer = -1;
static int hf_zbncp_data_tx_power = -1;
static int hf_zbncp_data_seed = -1;
static int hf_zbncp_data_tx_time = -1;
static int hf_zbncp_data_link_key = -1;
static int hf_zbncp_data_aps_link_key_type = -1;
static int hf_zbncp_data_key_src = -1;
static int hf_zbncp_data_key_attr = -1;
static int hf_zbncp_data_out_frame_cnt = -1;
static int hf_zbncp_data_inc_frame_cnt = -1;
static int hf_zbncp_data_offset = -1;
static int hf_zbncp_data_do_erase = -1;
static int hf_zbncp_data_calibration_status = -1;
static int hf_zbncp_data_calibration_value = -1;
static int hf_zbncp_data_zgp_key_type = -1;
static int hf_zbncp_data_zgp_link_key = -1;
static int hf_zbncp_data_prod_conf_hdr_crc = -1;
static int hf_zbncp_data_prod_conf_hdr_len = -1;
static int hf_zbncp_data_prod_conf_hdr_version = -1;
static int hf_zbncp_data_prod_conf_body = -1;

/* IEEE802.15.4 capability info (copied from IEEE802.15.4 95e212e6c7 commit)*/
static int hf_ieee802154_cinfo_alt_coord = -1;
static int hf_ieee802154_cinfo_device_type = -1;
static int hf_ieee802154_cinfo_power_src = -1;
static int hf_ieee802154_cinfo_idle_rx = -1;
static int hf_ieee802154_cinfo_sec_capable = -1;
static int hf_ieee802154_cinfo_alloc_addr = -1;

/* ZBNCP traffic dump */
static int hf_zbncp_dump_preambule = -1;
static int hf_zbncp_dump_version = -1;
static int hf_zbncp_dump_type = -1;
static int hf_zbncp_dump_options = -1;
static int hf_zbncp_dump_options_dir = -1;
static int hf_zbncp_dump_options_int_state = -1;
static int hf_zbncp_dump_options_tx_conflict = -1;

/* Initialize subtree pointers */
static gint ett_zbncp_hdr = -1;
static gint ett_zbncp_hdr_flags = -1;
static gint ett_zbncp_ll_body = -1;
static gint ett_zbncp_hl_hdr = -1;
static gint ett_zbncp_hl_body = -1;
static gint ett_zbncp_data_in_cl_list = -1;
static gint ett_zbncp_data_out_cl_list = -1;
static gint ett_zbncp_data_mac_cap = -1;
static gint ett_zbncp_data_pwr_src = -1;
static gint ett_zbncp_data_cur_pwr_src = -1;
static gint ett_zbncp_data_asoc_nwk_list = -1;
static gint ett_zbncp_data_pwr_desc = -1;
static gint ett_zbncp_data_desc_cap = -1;
static gint ett_zbncp_data_flags = -1;
static gint ett_zbncp_data_server_mask = -1;
static gint ett_zbncp_data_ep_list = -1;
static gint ett_zbncp_data_leave_flags = -1;
static gint ett_zbncp_data_tx_opt = -1;
static gint ett_zbncp_data_zdo_rejoin_flags = -1;
static gint ett_zbncp_data_apc_fc = -1;
static gint ett_zbncp_data_prod_conf_hdr = -1;
static gint ett_zbncp_data_aps_key_attr = -1;
static gint ett_zbncp_data_ch_list = -1;
static gint ett_zbncp_data_channel = -1;
static gint ett_zbncp_data_nwk_descr = -1;
static gint ett_zbncp_data_cmd_opt = -1;
static gint ett_zbncp_data_joind_bitmask = -1;
static gint ett_zbncp_data_trace_bitmask = -1;

static gint ett_zbncp_dump = -1;
static gint ett_zbncp_dump_opt = -1;

static dissector_handle_t zbncp_handle;

static const value_string zbncp_hl_type[] =
{
    {ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST, "Request"},
    {ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE, "Response"},
    {ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION, "Indication"},
    {0, NULL}
};

static const value_string zbncp_hl_status_cat[] =
{
    {ZBNCP_HIGH_LVL_STAT_CAT_GENERIC, "Generic"},
    {ZBNCP_HIGH_LVL_STAT_CAT_SYSTEM, "System"},
    {ZBNCP_HIGH_LVL_STAT_CAT_MAC, "MAC"},
    {ZBNCP_HIGH_LVL_STAT_CAT_NWK, "NWK"},
    {ZBNCP_HIGH_LVL_STAT_CAT_APS, "APS"},
    {ZBNCP_HIGH_LVL_STAT_CAT_ZDO, "ZDO"},
    {ZBNCP_HIGH_LVL_STAT_CAT_CBKE, "CBKE"},
    {0, NULL}
};

static const value_string zbncp_reset_opt[] =
{
    {0, "No options"},
    {1, "Erase NVRAM"},
    {2, "Factory Reset"},
    {3, "Locking reading keys"},
    {0, NULL}
};

static const value_string zbncp_zb_role[] =
{
    {0, "ZC"},
    {1, "ZR"},
    {2, "ZED"},
    {0, NULL}
};

static const value_string zbncp_bind_type_vals[] =
{
    {0, "NCP_HL_UNUSED_BINDING"},
    {1, "NCP_HL_UNICAST_BINDING"},
    {0, NULL}
};

static const value_string zbncp_tc_policy_types[] =
{
    {0, "TC Link Keys Required"},
    {1, "IC Required"},
    {2, "TC Rejoin Enabled"},
    {3, "Ignore TC Rejoin"},
    {4, "APS Insecure Join"},
    {5, "Disable NWK MGMT Channel Update"},
    {0, NULL}
};

static const value_string zbncp_dev_update_status_code[] =
{
    {0, "Standard Device Secured Rejoin"},
    {1, "Standard Device Unsecured Join"},
    {2, "Device Left"},
    {3, "Standard Device Trust Center Rejoin"},
    {0, NULL}
};

static const value_string zbncp_hl_call_id[] =
{
    {ZBNCP_CMD_GET_MODULE_VERSION, "GET_MODULE_VERSION"},
    {ZBNCP_CMD_NCP_RESET, "NCP_RESET"},
    {ZBNCP_CMD_GET_ZIGBEE_ROLE, "GET_ZIGBEE_ROLE"},
    {ZBNCP_CMD_SET_ZIGBEE_ROLE, "SET_ZIGBEE_ROLE"},
    {ZBNCP_CMD_GET_ZIGBEE_CHANNEL_MASK, "GET_ZIGBEE_CHANNEL_MASK"},
    {ZBNCP_CMD_SET_ZIGBEE_CHANNEL_MASK, "SET_ZIGBEE_CHANNEL_MASK"},
    {ZBNCP_CMD_GET_ZIGBEE_CHANNEL, "GET_ZIGBEE_CHANNEL"},
    {ZBNCP_CMD_GET_PAN_ID, "GET_PAN_ID"},
    {ZBNCP_CMD_SET_PAN_ID, "SET_PAN_ID"},
    {ZBNCP_CMD_GET_LOCAL_IEEE_ADDR, "GET_LOCAL_IEEE_ADDR"},
    {ZBNCP_CMD_SET_LOCAL_IEEE_ADDR, "SET_LOCAL_IEEE_ADDR"},
    {ZBNCP_CMD_SET_TRACE, "SET_TRACE"},
    {ZBNCP_CMD_GET_KEEPALIVE_TIMEOUT, "GET_KEEPALIVE_TIMEOUT"},
    {ZBNCP_CMD_SET_KEEPALIVE_TIMEOUT, "SET_KEEPALIVE_TIMEOUT"},
    {ZBNCP_CMD_GET_TX_POWER, "GET_TX_POWER"},
    {ZBNCP_CMD_SET_TX_POWER, "SET_TX_POWER"},
    {ZBNCP_CMD_GET_RX_ON_WHEN_IDLE, "GET_RX_ON_WHEN_IDLE"},
    {ZBNCP_CMD_SET_RX_ON_WHEN_IDLE, "SET_RX_ON_WHEN_IDLE"},
    {ZBNCP_CMD_GET_JOINED, "GET_JOINED"},
    {ZBNCP_CMD_GET_AUTHENTICATED, "GET_AUTHENTICATED"},
    {ZBNCP_CMD_GET_ED_TIMEOUT, "GET_ED_TIMEOUT"},
    {ZBNCP_CMD_SET_ED_TIMEOUT, "SET_ED_TIMEOUT"},
    {ZBNCP_CMD_ADD_VISIBLE_DEV, "ADD_VISIBLE_DEV"},
    {ZBNCP_CMD_ADD_INVISIBLE_SHORT, "ADD_INVISIBLE_SHORT"},
    {ZBNCP_CMD_RM_INVISIBLE_SHORT, "RM_INVISIBLE_SHORT"},
    {ZBNCP_CMD_SET_NWK_KEY, "SET_NWK_KEY"},
    {ZBNCP_CMD_GET_SERIAL_NUMBER, "GET_SERIAL_NUMBER"},
    {ZBNCP_CMD_GET_VENDOR_DATA, "GET_VENDOR_DATA"},
    {ZBNCP_CMD_GET_NWK_KEYS, "GET_NWK_KEYS"},
    {ZBNCP_CMD_GET_APS_KEY_BY_IEEE, "GET_APS_KEY_BY_IEEE"},
    {ZBNCP_CMD_BIG_PKT_TO_NCP, "BIG_PKT_TO_NCP"},
    {ZBNCP_CMD_GET_PARENT_ADDR, "GET_PARENT_ADDR"},
    {ZBNCP_CMD_GET_EXT_PAN_ID, "GET_EXT_PAN_ID"},
    {ZBNCP_CMD_GET_COORDINATOR_VERSION, "GET_COORDINATOR_VERSION"},
    {ZBNCP_CMD_GET_SHORT_ADDRESS, "GET_SHORT_ADDRESS"},
    {ZBNCP_CMD_GET_TRUST_CENTER_ADDRESS, "GET_TRUST_CENTER_ADDRESS"},
    {ZBNCP_CMD_DEBUG_WRITE, "DEBUG_WRITE"},
    {ZBNCP_CMD_GET_CONFIG_PARAMETER, "GET_CONFIG_PARAMETER"},
    {ZBNCP_CMD_GET_LOCK_STATUS, "GET_LOCK_STATUS"},
    {ZBNCP_CMD_GET_TRACE, "GET_TRACE"},
    {ZBNCP_CMD_NCP_RESET_IND, "NCP_RESET_IND"},
    {ZBNCP_CMD_SET_NWK_LEAVE_ALLOWED, "SET_NWK_LEAVE_ALLOWED"},
    {ZBNCP_CMD_GET_NWK_LEAVE_ALLOWED, "GET_NWK_LEAVE_ALLOWED"},
    {ZBNCP_CMD_NVRAM_WRITE, "NVRAM_WRITE"},
    {ZBNCP_CMD_NVRAM_READ, "NVRAM_READ"},
    {ZBCNP_CMD_NVRAM_CLEAR, "NVRAM_CLEAR"},
    {ZBNCP_CMD_NVRAM_ERASE, "NVRAM_ERASE"},
    {ZBNCP_CMD_SET_TC_POLICY, "SET_TC_POLICY"},
    {ZBNCP_CMD_SET_EXTENDED_PAN_ID, "SET_EXTENDED_PAN_ID"},
    {ZBNCP_CMD_SET_MAX_CHILDREN, "SET_MAX_CHILDREN"},
    {ZBNCP_CMD_GET_MAX_CHILDREN, "GET_MAX_CHILDREN"},
    {ZBNCP_CMD_SET_ZDO_LEAVE_ALLOWED, "SET_ZDO_LEAVE_ALLOWED"},
    {ZBNCP_CMD_GET_ZDO_LEAVE_ALLOWED, "GET_ZDO_LEAVE_ALLOWED"},
    {ZBNCP_CMD_SET_LEAVE_WO_REJOIN_ALLOWED, "SET_LEAVE_WO_REJOIN_ALLOWED"},
    {ZBNCP_CMD_GET_LEAVE_WO_REJOIN_ALLOWED, "GET_LEAVE_WO_REJOIN_ALLOWED"},
    {ZBNCP_CMD_DISABLE_GPPB, "DISABLE_GPPB"},
    {ZBNCP_CMD_GP_SET_SHARED_KEY_TYPE, "GP_SET_SHARED_KEY_TYPE"},
    {ZBNCP_CMD_GP_SET_DEFAULT_LINK_KEY, "GP_SET_DEFAULT_LINK_KEY"},
    {ZBNCP_CMD_PRODUCTION_CONFIG_READ, "PRODUCTION_CONFIG_READ"},
    {ZBNCP_CMD_AF_SET_SIMPLE_DESC, "AF_SET_SIMPLE_DESC"},
    {ZBNCP_CMD_AF_DEL_EP, "AF_DEL_EP"},
    {ZBNCP_CMD_AF_SET_NODE_DESC, "AF_SET_NODE_DESC"},
    {ZBNCP_CMD_AF_SET_POWER_DESC, "AF_SET_POWER_DESC"},
    {ZBNCP_CMD_AF_SUBGHZ_SUSPEND_IND, "AF_SUBGHZ_SUSPEND_IND"},
    {ZBNCP_CMD_AF_SUBGHZ_RESUME_IND, "AF_SUBGHZ_RESUME_IND"},
    {ZBNCP_CMD_ZDO_NWK_ADDR_REQ, "ZDO_NWK_ADDR_REQ"},
    {ZBNCP_CMD_ZDO_IEEE_ADDR_REQ, "ZDO_IEEE_ADDR_REQ"},
    {ZBNCP_CMD_ZDO_POWER_DESC_REQ, "ZDO_POWER_DESC_REQ"},
    {ZBNCP_CMD_ZDO_NODE_DESC_REQ, "ZDO_NODE_DESC_REQ"},
    {ZBNCP_CMD_ZDO_SIMPLE_DESC_REQ, "ZDO_SIMPLE_DESC_REQ"},
    {ZBNCP_CMD_ZDO_ACTIVE_EP_REQ, "ZDO_ACTIVE_EP_REQ"},
    {ZBNCP_CMD_ZDO_MATCH_DESC_REQ, "ZDO_MATCH_DESC_REQ"},
    {ZBNCP_CMD_ZDO_BIND_REQ, "ZDO_BIND_REQ"},
    {ZBNCP_CMD_ZDO_UNBIND_REQ, "ZDO_UNBIND_REQ"},
    {ZBNCP_CMD_ZDO_MGMT_LEAVE_REQ, "ZDO_MGMT_LEAVE_REQ"},
    {ZBNCP_CMD_ZDO_PERMIT_JOINING_REQ, "ZDO_PERMIT_JOINING_REQ"},
    {ZBNCP_CMD_ZDO_DEV_ANNCE_IND, "ZDO_DEV_ANNCE_IND"},
    {ZBNCP_CMD_ZDO_REJOIN, "ZDO_REJOIN"},
    {ZBNCP_CMD_ZDO_SYSTEM_SRV_DISCOVERY_REQ, "ZDO_SYSTEM_SRV_DISCOVERY_REQ"},
    {ZBNCP_CMD_ZDO_MGMT_BIND_REQ, "ZDO_MGMT_BIND_REQ"},
    {ZBNCP_CMD_ZDO_MGMT_LQI_REQ, "ZDO_MGMT_LQI_REQ"},
    {ZBNCP_CMD_ZDO_MGMT_NWK_UPDATE_REQ, "ZDO_MGMT_NWK_UPDATE_REQ"},
    {ZBNCP_CMD_ZDO_REMOTE_CMD_IND, "ZDO_REMOTE_CMD_IND"},
    {ZBNCP_CMD_ZDO_GET_STATS, "ZDO_GET_STATS"},
    {ZBNCP_CMD_ZDO_DEV_AUTHORIZED_IND, "ZDO_DEV_AUTHORIZED_IND"},
    {ZBNCP_CMD_ZDO_DEV_UPDATE_IND, "ZDO_DEV_UPDATE_IND"},
    {ZBNCP_CMD_ZDO_SET_NODE_DESC_MANUF_CODE, "ZDO_SET_NODE_DESC_MANUF_CODE"},
    {ZBNCP_CMD_HL_ZDO_GET_DIAG_DATA_REQ, "ZDO_GET_DIAG_DATA_REQ"},
    {ZBNCP_CMD_APSDE_DATA_REQ, "APSDE_DATA_REQ"},
    {ZBNCP_CMD_APSME_BIND, "APSME_BIND"},
    {ZBNCP_CMD_APSME_UNBIND, "APSME_UNBIND"},
    {ZBNCP_CMD_APSME_ADD_GROUP, "APSME_ADD_GROUP"},
    {ZBNCP_CMD_APSME_RM_GROUP, "APSME_RM_GROUP"},
    {ZBNCP_CMD_APSDE_DATA_IND, "APSDE_DATA_IND"},
    {ZBNCP_CMD_APSME_RM_ALL_GROUPS, "APSME_RM_ALL_GROUPS"},
    {ZBNCP_CMD_APS_GET_GROUP_TABLE, "APS_GET_GROUP_TABLE"},
    {ZBNCP_CMD_APSME_UNBIND_ALL, "APSME_UNBIND_ALL"},
    {ZBNCP_CMD_APSME_RM_BIND_ENTRY_BY_ID, "APSME_RM_BIND_ENTRY_BY_ID"},
    {ZBNCP_CMD_APSME_CLEAR_BIND_TABLE, "APSME_CLEAR_BIND_TABLE"},
    {ZBNCP_CMD_APSME_REMOTE_BIND_IND, "APSME_REMOTE_BIND_IND"},
    {ZBNCP_CMD_APSME_REMOTE_UNBIND_IND, "APSME_REMOTE_UNBIND_IND"},
    {ZBNCP_CMD_APSME_SET_REMOTE_BIND_OFFSET, "APSME_SET_REMOTE_BIND_OFFSET"},
    {ZBNCP_CMD_APSME_GET_REMOTE_BIND_OFFSET, "APSME_GET_REMOTE_BIND_OFFSET"},
    {ZBNCP_CMD_APSME_GET_BIND_ENTRY_BY_ID, "APSME_GET_BIND_ENTRY_BY_ID"},
    {ZBNCP_CMD_NWK_FORMATION, "NWK_FORMATION"},
    {ZBNCP_CMD_NWK_DISCOVERY, "NWK_DISCOVERY"},
    {ZBNCP_CMD_NWK_NLME_JOIN, "NWK_NLME_JOIN"},
    {ZBNCP_CMD_NWK_PERMIT_JOINING, "NWK_PERMIT_JOINING"},
    {ZBNCP_CMD_NWK_GET_IEEE_BY_SHORT, "NWK_GET_IEEE_BY_SHORT"},
    {ZBNCP_CMD_NWK_GET_SHORT_BY_IEEE, "NWK_GET_SHORT_BY_IEEE"},
    {ZBNCP_CMD_NWK_GET_NEIGHBOR_BY_IEEE, "NWK_GET_NEIGHBOR_BY_IEEE"},
    {ZBNCP_CMD_NWK_STARTED_IND, "NWK_STARTED_IND"},
    {ZBNCP_CMD_NWK_REJOINED_IND, "NWK_REJOINED_IND"},
    {ZBNCP_CMD_NWK_REJOIN_FAILED_IND, "NWK_REJOIN_FAILED_IND"},
    {ZBNCP_CMD_NWK_LEAVE_IND, "NWK_LEAVE_IND"},
    {ZBNCP_CMD_PIM_SET_FAST_POLL_INTERVAL, "PIM_SET_FAST_POLL_INTERVAL"},
    {ZBNCP_CMD_PIM_SET_LONG_POLL_INTERVAL, "PIM_SET_LONG_POLL_INTERVAL"},
    {ZBNCP_CMD_PIM_START_FAST_POLL, "PIM_START_FAST_POLL"},
    {ZBNCP_CMD_PIM_START_POLL, "PIM_START_POLL"},
    {ZBNCP_CMD_PIM_SET_ADAPTIVE_POLL, "PIM_SET_ADAPTIVE_POLL"},
    {ZBNCP_CMD_PIM_STOP_FAST_POLL, "PIM_STOP_FAST_POLL"},
    {ZBNCP_CMD_PIM_STOP_POLL, "PIM_STOP_POLL"},
    {ZBNCP_CMD_PIM_ENABLE_TURBO_POLL, "PIM_ENABLE_TURBO_POLL"},
    {ZBNCP_CMD_PIM_DISABLE_TURBO_POLL, "PIM_DISABLE_TURBO_POLL"},
    {ZBNCP_CMD_NWK_GET_FIRST_NBT_ENTRY, "NWK_GET_FIRST_NBT_ENTRY"},
    {ZBNCP_CMD_NWK_GET_NEXT_NBT_ENTRY, "NWK_GET_NEXT_NBT_ENTRY"},
    {ZBNCP_CMD_NWK_PAN_ID_CONFLICT_RESOLVE, "NWK_PAN_ID_CONFLICT_RESOLVE"},
    {ZBNCP_CMD_NWK_PAN_ID_CONFLICT_IND, "NWK_PAN_ID_CONFLICT_IND"},
    {ZBNCP_CMD_NWK_ADDRESS_UPDATE_IND, "NWK_ADDRESS_UPDATE_IND"},
    {ZBNCP_CMD_NWK_START_WITHOUT_FORMATION, "NWK_START_WITHOUT_FORMATION"},
    {ZBNCP_CMD_NWK_NLME_ROUTER_START, "NWK_NLME_ROUTER_START"},
    {ZBNCP_CMD_PIM_SINGLE_POLL, "PIM_SINGLE_POLL"},
    {ZBNCP_CMD_PARENT_LOST_IND, "PARENT_LOST_IND"},
    {ZBNCP_CMD_PIM_START_TURBO_POLL_PACKETS, "PIM_START_TURBO_POLL_PACKETS"},
    {ZBNCP_CMD_PIM_START_TURBO_POLL_CONTINUOUS, "PIM_START_TURBO_POLL_CONTINUOUS"},
    {ZBNCP_CMD_PIM_TURBO_POLL_CONTINUOUS_LEAVE, "PIM_TURBO_POLL_CONTINUOUS_LEAVE"},
    {ZBNCP_CMD_PIM_TURBO_POLL_PACKETS_LEAVE, "PIM_TURBO_POLL_PACKETS_LEAVE"},
    {ZBNCP_CMD_PIM_PERMIT_TURBO_POLL, "PIM_PERMIT_TURBO_POLL"},
    {ZBNCP_CMD_PIM_SET_FAST_POLL_TIMEOUT, "PIM_SET_FAST_POLL_TIMEOUT"},
    {ZBNCP_CMD_PIM_GET_LONG_POLL_INTERVAL, "PIM_GET_LONG_POLL_INTERVAL"},
    {ZBNCP_CMD_PIM_GET_IN_FAST_POLL_FLAG, "PIM_GET_IN_FAST_POLL_FLAG"},
    {ZBNCP_CMD_SET_KEEPALIVE_MODE, "SET_KEEPALIVE_MODE"},
    {ZBNCP_CMD_START_CONCENTRATOR_MODE, "START_CONCENTRATOR_MODE"},
    {ZBNCP_CMD_STOP_CONCENTRATOR_MODE, "STOP_CONCENTRATOR_MODE"},
    {ZBNCP_CMD_NWK_ENABLE_PAN_ID_CONFLICT_RESOLUTION, "NWK_ENABLE_PAN_ID_CONFLICT_RESOLUTION"},
    {ZBNCP_CMD_NWK_ENABLE_AUTO_PAN_ID_CONFLICT_RESOLUTION, "NWK_ENABLE_AUTO_PAN_ID_CONFLICT_RESOLUTION"},
    {ZBNCP_CMD_PIM_TURBO_POLL_CANCEL_PACKET, "PIM_TURBO_POLL_CANCEL_PACKET"},
    {ZBNCP_CMD_SET_FORCE_ROUTE_RECORD, "SET_FORCE_ROUTE_RECORD"},
    {ZBNCP_CMD_GET_FORCE_ROUTE_RECORD, "GET_FORCE_ROUTE_RECORD"},
    {ZBNCP_CMD_NWK_NBR_ITERATOR_NEXT, "NWK_NBR_ITERATOR_NEXT"},
    {ZBNCP_CMD_SECUR_SET_LOCAL_IC, "SECUR_SET_LOCAL_IC"},
    {ZBNCP_CMD_SECUR_ADD_IC, "SECUR_ADD_IC"},
    {ZBNCP_CMD_SECUR_DEL_IC, "SECUR_DEL_IC"},
    {ZBNCP_CMD_SECUR_ADD_CERT, "SECUR_ADD_CERT"},
    {ZBNCP_CMD_SECUR_DEL_CERT, "SECUR_DEL_CERT"},
    {ZBNCP_CMD_SECUR_START_KE, "SECUR_START_KE"},
    {ZBNCP_CMD_SECUR_START_PARTNER_LK, "SECUR_START_PARTNER_LK"},
    {ZBNCP_CMD_SECUR_CBKE_SRV_FINISHED_IND, "SECUR_CBKE_SRV_FINISHED_IND"},
    {ZBNCP_CMD_SECUR_PARTNER_LK_FINISHED_IND, "SECUR_PARTNER_LK_FINISHED_IND"},
    {ZBNCP_CMD_SECUR_KE_WHITELIST_ADD, "SECUR_KE_WHITELIST_ADD"},
    {ZBNCP_CMD_SECUR_KE_WHITELIST_DEL, "SECUR_KE_WHITELIST_DEL"},
    {ZBNCP_CMD_SECUR_KE_WHITELIST_DEL_ALL, "SECUR_KE_WHITELIST_DEL_ALL"},
    {ZBNCP_CMD_SECUR_JOIN_USES_IC, "SECUR_JOIN_USES_IC"},
    {ZBNCP_CMD_SECUR_GET_IC_BY_IEEE, "SECUR_GET_IC_BY_IEEE"},
    {ZBNCP_CMD_SECUR_GET_CERT, "SECUR_GET_CERT"},
    {ZBNCP_CMD_SECUR_GET_LOCAL_IC, "SECUR_GET_LOCAL_IC"},
    {ZBNCP_CMD_SECUR_TCLK_IND, "SECUR_TCLK_IND"},
    {ZBNCP_CMD_SECUR_TCLK_EXCHANGE_FAILED_IND, "SECUR_TCLK_EXCHANGE_FAILED_IND"},
    {ZBNCP_CMD_SECUR_GET_KEY_IDX, "SECUR_GET_KEY_IDX"},
    {ZBNCP_CMD_SECUR_GET_KEY, "SECUR_GET_KEY"},
    {ZBNCP_CMD_SECUR_ERASE_KEY, "SECUR_ERASE_KEY"},
    {ZBNCP_CMD_SECUR_CLEAR_KEY_TABLE, "SECUR_CLEAR_KEY_TABLE"},
    {ZBNCP_CMD_SECUR_NWK_INITIATE_KEY_SWITCH_PROCEDURE, "SECUR_NWK_INITIATE_KEY_SWITCH_PROCEDURE"},
    {ZBNCP_CMD_SECUR_GET_IC_LIST, "SECUR_GET_IC_LIST"},
    {ZBNCP_CMD_SECUR_GET_IC_BY_IDX, "SECUR_GET_IC_BY_IDX"},
    {ZBNCP_CMD_SECUR_REMOVE_ALL_IC, "SECUR_REMOVE_ALL_IC"},
    {ZBNCP_CMD_SECUR_PARTNER_LK_ENABLE, "SECUR_PARTNER_LK_ENABLE"},
    {ZBNCP_CMD_MANUF_MODE_START, "MANUF_MODE_START"},
    {ZBNCP_CMD_MANUF_MODE_END, "MANUF_MODE_END"},
    {ZBNCP_CMD_MANUF_SET_CHANNEL, "MANUF_SET_CHANNEL"},
    {ZBNCP_CMD_MANUF_GET_CHANNEL, "MANUF_GET_CHANNEL"},
    {ZBNCP_CMD_MANUF_SET_POWER, "MANUF_SET_POWER"},
    {ZBNCP_CMD_MANUF_GET_POWER, "MANUF_GET_POWER"},
    {ZBNCP_CMD_MANUF_START_TONE, "MANUF_START_TONE"},
    {ZBNCP_CMD_MANUF_STOP_TONE, "MANUF_STOP_TONE"},
    {ZBNCP_CMD_MANUF_START_STREAM_RANDOM, "MANUF_START_STREAM_RANDOM"},
    {ZBNCP_CMD_MANUF_STOP_STREAM_RANDOM, "MANUF_STOP_STREAM_RANDOM"},
    {ZBNCP_CMD_NCP_HL_MANUF_SEND_SINGLE_PACKET, "MANUF_SEND_SINGLE_PACKET"},
    {ZBNCP_CMD_MANUF_START_TEST_RX, "MANUF_START_TEST_RX"},
    {ZBNCP_CMD_MANUF_STOP_TEST_RX, "MANUF_STOP_TEST_RX"},
    {ZBNCP_CMD_MANUF_RX_PACKET_IND, "MANUF_RX_PACKET_IND"},
    {ZBNCP_CMD_OTA_RUN_BOOTLOADER, "OTA_RUN_BOOTLOADER"},
    {ZBNCP_CMD_OTA_START_UPGRADE_IND, "OTA_START_UPGRADE_IND"},
    {ZBNCP_CMD_OTA_SEND_PORTION_FW, "OTA_SEND_PORTION_FW"},
    {ZBNCP_CMD_READ_NVRAM_RESERVED, "READ_NVRAM_RESERVED"},
    {ZBNCP_CMD_WRITE_NVRAM_RESERVED, "WRITE_NVRAM_RESERVED"},
    {ZBNCP_CMD_GET_CALIBRATION_INFO, "GET_CALIBRATION_INFO"},
    {0, NULL}
};

static const value_string zbncp_parameter_id_list[] =
{
    {ZBNCP_PARAMETER_ID_IEEE_ADDR_TABLE_SIZE, "IEEE_ADDR_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_NEIGHBOR_TABLE_SIZE, "NEIGHBOR_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_APS_SRC_BINDING_TABLE_SIZE, "APS_SRC_BINDING_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_APS_GROUP_TABLE_SIZE, "APS_GROUP_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_NWK_ROUTING_TABLE_SIZE, "NWK_ROUTING_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_NWK_ROUTE_DISCOVERY_TABLE_SIZE, "NWK_ROUTE_DISCOVERY_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_IOBUF_POOL_SIZE, "IOBUF_POOL_SIZE"},
    {ZBNCP_PARAMETER_ID_PANID_TABLE_SIZE, "PANID_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_APS_DUPS_TABLE_SIZE, "APS_DUPS_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_APS_BIND_TRANS_TABLE_SIZE, "APS_BIND_TRANS_TABLE_SIZE"},
    {ZBNCP_PARAMETER_ID_N_APS_RETRANS_ENTRIES, "N_APS_RETRANS_ENTRIES"},
    {ZBNCP_PARAMETER_ID_NWK_MAX_HOPS, "NWK_MAX_HOPS"},
    {ZBNCP_PARAMETER_ID_NIB_MAX_CHILDREN, "NIB_MAX_CHILDREN"},
    {ZBNCP_PARAMETER_ID_N_APS_KEY_PAIR_ARR_MAX_SIZE, "N_APS_KEY_PAIR_ARR_MAX_SIZE"},
    {ZBNCP_PARAMETER_ID_NWK_MAX_SRC_ROUTES, "NWK_MAX_SRC_ROUTES"},
    {ZBNCP_PARAMETER_ID_APS_MAX_WINDOW_SIZE, "APS_MAX_WINDOW_SIZE"},
    {ZBNCP_PARAMETER_ID_APS_INTERFRAME_DELAY, "APS_INTERFRAME_DELAY"},
    {ZBNCP_PARAMETER_ID_ZDO_ED_BIND_TIMEOUT, "ZDO_ED_BIND_TIMEOUT"},
    {ZBNCP_PARAMETER_ID_NIB_PASSIVE_ASK_TIMEOUT, "NIB_PASSIVE_ASK_TIMEOUT"},
    {ZBNCP_PARAMETER_ID_APS_ACK_TIMEOUTS, "APS_ACK_TIMEOUTS"},
    {ZBNCP_PARAMETER_ID_MAC_BEACON_JITTER, "MAC_BEACON_JITTER"},
    {ZBNCP_PARAMETER_ID_TX_POWER, "TX_POWER"},
    {ZBNCP_PARAMETER_ID_ZLL_DEFAULT_RSSI_THRESHOLD, "ZLL_DEFAULT_RSSI_THRESHOLD"},
    {ZBNCP_PARAMETER_ID_NIB_MTORR, "NIB_MTORR"},
    {0, NULL}
};

static const value_string zbncp_rst_src_list[] =
{
    {0, "ZB_RESET_SRC_POWER_ON"},
    {1, "ZB_RESET_SRC_SW_RESET"},
    {2, "ZB_RESET_SRC_RESET_PIN"},
    {3, "ZB_RESET_SRC_BROWN_OUT"},
    {4, "ZB_RESET_SRC_CLOCK_LOSS"},
    {5, "ZB_RESET_SRC_OTHER"},
    {0, NULL}
};

static const value_string zbncp_power_level[] =
{
    {0, "Critical"},
    {4, "33%"},
    {8, "66%"},
    {12, "100%"},
    {0, NULL}
};

static const value_string zbncp_nwk_req_type[] =
{
    {0, "Single device response"},
    {1, "Extended response"},
    {0, NULL}
};

static const value_string zbncp_hl_status_generic[] =
{
    {0, "OK"},
    {1, "ERROR"},
    {2, "BLOCKED"},
    {3, "EXIT"},
    {4, "BUSY"},
    {5, "EOF"},
    {6, "OUT_OF_RANGE"},
    {7, "EMPTY"},
    {8, "CANCELLED"},
    {10, "INVALID_PARAMETER_1"},
    {11, "INVALID_PARAMETER_2"},
    {12, "INVALID_PARAMETER_3"},
    {13, "INVALID_PARAMETER_4"},
    {14, "INVALID_PARAMETER_5"},
    {15, "INVALID_PARAMETER_6"},
    {16, "INVALID_PARAMETER_7"},
    {17, "INVALID_PARAMETER_8"},
    {18, "INVALID_PARAMETER_9"},
    {19, "INVALID_PARAMETER_10"},
    {20, "INVALID_PARAMETER_11_OR_MORE"},
    {21, "PENDING"},
    {22, "NO_MEMORY"},
    {23, "INVALID_PARAMETER"},
    {24, "OPERATION_FAILED"},
    {25, "BUFFER_TOO_SMALL"},
    {26, "END_OF_LIST"},
    {27, "ALREADY_EXISTS"},
    {28, "NOT_FOUND"},
    {29, "OVERFLOW"},
    {30, "TIMEOUT"},
    {31, "NOT_IMPLEMENTED"},
    {32, "NO_RESOURCES"},
    {33, "UNINITIALIZED"},
    {34, "NO_SERVER"},
    {35, "INVALID_STATE"},
    {37, "CONNECTION_FAILED"},
    {38, "CONNECTION_LOST"},
    {40, "UNAUTHORIZED"},
    {41, "CONFLICT"},
    {42, "INVALID_FORMAT"},
    {43, "NO_MATCH"},
    {44, "PROTOCOL_ERROR"},
    {45, "VERSION"},
    {46, "MALFORMED_ADDRESS"},
    {47, "COULD_NOT_READ_FILE"},
    {48, "FILE_NOT_FOUND"},
    {49, "DIRECTORY_NOT_FOUND"},
    {50, "CONVERSION_ERROR"},
    {51, "INCOMPATIBLE_TYPES"},
    {56, "FILE_CORRUPTED"},
    {57, "PAGE_NOT_FOUND"},
    {62, "ILLEGAL_REQUEST"},
    {64, "INVALID_GROUP"},
    {65, "TABLE_FULL"},
    {69, "IGNORE"},
    {70, "AGAIN"},
    {71, "DEVICE_NOT_FOUND"},
    {72, "OBSOLETE"},
    {0, NULL}
};

static const value_string zb_mac_state[] =
{
    {MAC_ENUM_SUCCESS, "SUCCESS"},
    {MAC_ENUM_BEACON_LOSS, "BEACON_LOSS"},
    {MAC_ENUM_CHANNEL_ACCESS_FAILURE, "CHANNEL_ACCESS_FAILURE"},
    {MAC_ENUM_COUNTER_ERROR, "COUNTER_ERROR"},
    {MAC_ENUM_DENIED, "DENIED"},
    {MAC_ENUM_DISABLE_TRX_FAILURE, "DISABLE_TRX_FAILURE"},
    {MAC_ENUM_FRAME_TOO_LONG, "FRAME_TOO_LONG"},
    {MAC_ENUM_IMPROPER_KEY_TYPE, "IMPROPER_KEY_TYPE"},
    {MAC_ENUM_IMPROPER_SECURITY_LEVEL, "IMPROPER_SECURITY_LEVEL"},
    {MAC_ENUM_INVALID_ADDRESS, "INVALID_ADDRESS"},
    {MAC_ENUM_INVALID_GTS, "INVALID_GTS"},
    {MAC_ENUM_INVALID_HANDLE, "INVALID_HANDLE"},
    {MAC_ENUM_INVALID_INDEX, "INVALID_INDEX"},
    {MAC_ENUM_INVALID_PARAMETER, "INVALID_PARAMETER"},
    {MAC_ENUM_LIMIT_REACHED, "LIMIT_REACHED"},
    {MAC_ENUM_NO_ACK, "NO_ACK"},
    {MAC_ENUM_NO_BEACON, "NO_BEACON"},
    {MAC_ENUM_NO_DATA, "NO_DATA"},
    {MAC_ENUM_NO_SHORT_ADDRESS, "NO_SHORT_ADDRESS"},
    {MAC_ENUM_ON_TIME_TOO_LONG, "ON_TIME_TOO_LONG"},
    {MAC_ENUM_OUT_OF_CAP, "OUT_OF_CAP"},
    {MAC_ENUM_PAN_ID_CONFLICT, "PAN_ID_CONFLICT"},
    {MAC_ENUM_PAST_TIME, "PAST_TIME"},
    {MAC_ENUM_READ_ONLY, "READ_ONLY"},
    {MAC_ENUM_REALIGNMENT, "REALIGNMENT"},
    {MAC_ENUM_SCAN_IN_PROGRESS, "SCAN_IN_PROGRESS"},
    {MAC_ENUM_SECURITY_ERROR, "SECURITY_ERROR"},
    {MAC_ENUM_SUPERFRAME_OVERLAP, "SUPERFRAME_OVERLAP"},
    {MAC_ENUM_TRACKING_OFF, "TRACKING_OFF"},
    {MAC_ENUM_TRANSACTION_EXPIRED, "TRANSACTION_EXPIRED"},
    {MAC_ENUM_TRANSACTION_OVERFLOW, "TRANSACTION_OVERFLOW"},
    {MAC_ENUM_TX_ACTIVE, "TX_ACTIVE"},
    {MAC_ENUM_UNAVAILABLE_KEY, "UNAVAILABLE_KEY"},
    {MAC_ENUM_UNSUPPORTED_LEGACY, "UNSUPPORTED_LEGACY"},
    {MAC_ENUM_UNSUPPORTED_SECURITY, "UNSUPPORTED_SECURITY"},
    {0, NULL}
};

static const value_string zb_nwk_state[] =
{
    {ZBNCP_NWK_STATUS_SUCCESS, "SUCCESS"},
    {ZBNCP_NWK_STATUS_INVALID_PARAMETER, "INVALID_PARAMETER"},
    {ZBNCP_NWK_STATUS_INVALID_REQUEST, "INVALID_REQUEST"},
    {ZBNCP_NWK_STATUS_NOT_PERMITTED, "NOT_PERMITTED, "},
    {ZBNCP_NWK_STATUS_ALREADY_PRESENT, "ALREADY_PRESENT"},
    {ZBNCP_NWK_STATUS_SYNC_FAILURE, "SYNC_FAILURE"},
    {ZBNCP_NWK_STATUS_NEIGHBOR_TABLE_FULL, "NEIGHBOR_TABLE_FULL"},
    {ZBNCP_NWK_STATUS_UNKNOWN_DEVICE, "UNKNOWN_DEVICE"},
    {ZBNCP_NWK_STATUS_UNSUPPORTED_ATTRIBUTE, "UNSUPPORTED_ATTRIBUTE"},
    {ZBNCP_NWK_STATUS_NO_NETWORKS, "NO_NETWORKS"},
    {ZBNCP_NWK_STATUS_MAX_FRM_COUNTER, "MAX_FRM_COUNTER"},
    {ZBNCP_NWK_STATUS_NO_KEY, "NO_KEY"},
    {ZBNCP_NWK_STATUS_ROUTE_DISCOVERY_FAILED, "ROUTE_DISCOVERY_FAILED"},
    {ZBNCP_NWK_STATUS_ROUTE_ERROR, "ROUTE_ERROR"},
    {ZBNCP_NWK_STATUS_BT_TABLE_FULL, "BT_TABLE_FULL"},
    {ZBNCP_NWK_STATUS_FRAME_NOT_BUFFERED, "FRAME_NOT_BUFFERE"},
    {ZBNCP_NWK_STATUS_INVALID_INTERFACE, "INVALID_INTERFACE"},
    {0, NULL}
};

static const value_string zb_cbke_state[] =
{
    {ZBNCP_CBKE_STATUS_OK, "OK"},
    {ZBNCP_CBKE_STATUS_UNKNOWN_ISSUER, "UNKNOWN_ISSUER"},
    {ZBNCP_CBKE_STATUS_BAD_KEY_CONFIRM, "BAD_KEY_CONFIRM"},
    {ZBNCP_CBKE_STATUS_BAD_MESSAGE, "BAD_MESSAGE"},
    {ZBNCP_CBKE_STATUS_NO_RESOURCES, "NO_RESOURCES"},
    {ZBNCP_CBKE_STATUS_UNSUPPORTED_SUITE, "UNSUPPORTED_SUITE"},
    {ZBNCP_CBKE_STATUS_INVALID_CERTIFICATE, "INVALID_CERTIFICATE"},
    {ZBNCP_CBKE_STATUS_NO_KE_EP, "NO_KE_EP"},
    {0, NULL}
};

static const value_string zb_nvram_database_types[] =
{
    {ZB_NVRAM_RESERVED, "ZB_NVRAM_RESERVED"},
    {ZB_NVRAM_COMMON_DATA, "ZB_NVRAM_COMMON_DATA"},
    {ZB_NVRAM_HA_DATA, "ZB_NVRAM_HA_DATA"},
    {ZB_NVRAM_ZCL_REPORTING_DATA, "ZB_NVRAM_ZCL_REPORTING_DATA"},
    {ZB_NVRAM_APS_SECURE_DATA_GAP, "ZB_NVRAM_APS_SECURE_DATA_GAP"},
    {ZB_NVRAM_APS_BINDING_DATA_GAP, "ZB_NVRAM_APS_BINDING_DATA_GAP"},
    {ZB_NVRAM_HA_POLL_CONTROL_DATA, "ZB_NVRAM_HA_POLL_CONTROL_DATA"},
    {ZB_IB_COUNTERS, "ZB_IB_COUNTERS"},
    {ZB_NVRAM_DATASET_GRPW_DATA, "ZB_NVRAM_DATASET_GRPW_DATA"},
    {ZB_NVRAM_APP_DATA1, "ZB_NVRAM_APP_DATA1"},
    {ZB_NVRAM_APP_DATA2, "ZB_NVRAM_APP_DATA2"},
    {ZB_NVRAM_ADDR_MAP, "ZB_NVRAM_ADDR_MAP"},
    {ZB_NVRAM_NEIGHBOUR_TBL, "ZB_NVRAM_NEIGHBOUR_TBL"},
    {ZB_NVRAM_INSTALLCODES, "ZB_NVRAM_INSTALLCODES"},
    {ZB_NVRAM_APS_SECURE_DATA, "ZB_NVRAM_APS_SECURE_DATA"},
    {ZB_NVRAM_APS_BINDING_DATA, "ZB_NVRAM_APS_BINDING_DATA"},
    {ZB_NVRAM_DATASET_GP_PRPOXYT, "ZB_NVRAM_DATASET_GP_PRPOXYT"},
    {ZB_NVRAM_DATASET_GP_SINKT, "ZB_NVRAM_DATASET_GP_SINKT"},
    {ZB_NVRAM_DATASET_GP_CLUSTER, "ZB_NVRAM_DATASET_GP_CLUSTER"},
    {ZB_NVRAM_APS_GROUPS_DATA, "ZB_NVRAM_APS_GROUPS_DATA"},
    {ZB_NVRAM_DATASET_SE_CERTDB, "ZB_NVRAM_DATASET_SE_CERTDB"},
    {ZB_NVRAM_DATASET_GP_APP_TBL, "ZB_NVRAM_DATASET_GP_APP_TBL"},
    {ZB_NVRAM_APP_DATA3, "ZB_NVRAM_APP_DATA3"},
    {ZB_NVRAM_APP_DATA4, "ZB_NVRAM_APP_DATA4"},
    {ZB_NVRAM_KE_WHITELIST, "ZB_NVRAM_KE_WHITELIST"},
    {ZB_NVRAM_ZDO_DIAGNOSTICS_DATA, "ZB_NVRAM_ZDO_DIAGNOSTICS_DATA"},
    {ZB_NVRAM_DATASET_NUMBER, "ZB_NVRAM_DATASET_NUMBER"},
    {ZB_NVRAM_DATA_SET_TYPE_PAGE_HDR, "ZB_NVRAM_DATA_SET_TYPE_PAGE_HDR"},
    {0, NULL}
};

static const value_string zbncp_zgp_key_types[] =
{
    {0, "No key"},
    {1, "Zigbee NWK key"},
    {2, "ZGPD group key"},
    {3, "NWK-key derived ZGPD group key"},
    {4, "(Individual) out-of-the-box ZGPD key"},
    {7, "Derived individual ZGPD key"},
    {0, NULL}
};

static const value_string zbncp_deliv_mode[] =
{
    {0, "Unicast"},
    {2, "Broadcast"},
    {3, "Group"},
    {0, NULL}
};

static const value_string zbncp_aps_key_src[] =
{
    {0, "Unknown"},
    {1, "CBKE"},
    {0, NULL}
};

static const value_string zbncp_aps_key_used[] =
{
    {0, "Provisional TCLK"},
    {1, "Unverified TCLK"},
    {2, "Verified TCLK"},
    {3, "Application LK"},
    {0, NULL}
};

static const value_string zbncp_rejoin_nwk[] =
{
    {0, "Associate"},
    {2, "Rejoin"},
    {0, NULL}
};

static const value_string zbncp_beacon_type[] =
{
    {0, "Non-enhanced beacon"},
    {1, "Enhanced Beacon"},
    {0, NULL}
};

static const value_string zbncp_relationship[] =
{
    {0x00, "neighbor is the parent"},
    {0x01, "neighbor is a child"},
    {0x02, "neighbor is a sibling"},
    {0x03, "none of the above"},
    {0x04, "previous child"},
    {0x05, "unauthenticated child"},
    {0, NULL}
};

static const value_string zbncp_keepalive_mode[] =
{
    {0, "ED_KEEPALIVE_DISABLED"},
    {1, "MAC_DATA_POLL_KEEPALIVE"},
    {2, "ED_TIMEOUT_REQUEST_KEEPALIVE"},
    {3, "BOTH_KEEPALIVE_METHODS"},
    {0, NULL}
};

static const value_string zbncp_stop_fast_poll_result[] =
{
    {0, "Not started"},
    {1, "Not stopped"},
    {2, "Stopped"},
    {0, NULL}
};

static const value_string zbncp_aps_addr_modes[] =
{
    {ZB_APSDE_DST_ADDR_MODE_DST_ADDR_ENDP_NOT_PRESENT, "No addr, no EP"},
    {ZB_APSDE_DST_ADDR_MODE_16_GROUP_ENDP_NOT_PRESENT, "16-bit group addr, no EP"},
    {ZB_APSDE_DST_ADDR_MODE_16_ENDP_PRESENT, "16-bit short addr and EP"},
    {ZB_APSDE_DST_ADDR_MODE_64_ENDP_PRESENT, "64-bit ext addr and EP"},
    {ZB_APSDE_DST_ADDR_MODE_BIND_TBL_ID, "From the dst binding table"},
    {0, NULL}
};

static const value_string zbncp_cs[] =
{
    {1, "KEC Crypto-suite #1"},
    {2, "KEC Crypto-suite #2"},
    {0, NULL}
};

static const value_string zbncp_key_src[] =
{
    {0, "Unknown"},
    {1, "CBKE"},
    {0, NULL}
};

static const value_string zbncp_key_attr[] =
{
    {0, "Provisional key"},
    {1, "Unverified key"},
    {2, "Verified key"},
    {3, "Application key"},
    {0, NULL}
};

static const value_string zbncp_zdo_auth_types[] =
{
    {ZB_ZDO_AUTH_LEGACY_TYPE, "legacy"},
    {ZB_ZDO_AUTH_TCLK_TYPE, "TCLK"},
    {0, NULL}
};

static const value_string zbncp_zdo_leg_auth_status_codes[] =
{
    {0, "Authorization Success"},
    {1, "Authorization Failure"},
    {0, NULL}
};

static const value_string zbncp_zdo_tclk_auth_status_codes[] =
{
    {0, "Authorization Success"},
    {1, "Authorization Timeout"},
    {2, "Authorization Failure"},
    {0, NULL}
};

static const value_string zbncp_dump_type[] =
{
    {0, "Text"},
    {1, "Binary"},
    {0, NULL}
};

static const value_string zbncp_calibration_status[] =
{
    {0x00, "Customer value"},
    {0x01, "Default value"},
    {0x02, "Error"},
    {0, NULL}
};

static const value_string zbncp_force_route_record_sending_modes[] =
{
    {0x00, "Disabled"},
    {0x01, "Enabled"},
    {0, NULL}
};

static const true_false_string tfs_cinfo_device_type = {"FFD", "RFD"};
static const true_false_string tfs_cinfo_power_src = {"AC/Mains Power", "Battery"};

/* Returns changed offset */
static guint
dissect_zbncp_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint status_category = tvb_get_guint8(tvb, offset);
    guint status;

    proto_tree_add_item(tree, hf_zbncp_data_hl_status_cat, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Add status */
    status = tvb_get_guint8(tvb, offset);
    switch (status_category)
    {
    case ZBNCP_HIGH_LVL_STAT_CAT_GENERIC:
        proto_tree_add_item(tree, hf_zbncp_data_hl_status_generic, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zbncp_hl_status_generic, "Unknown Status"));
        break;

    case ZBNCP_HIGH_LVL_STAT_CAT_MAC:
        proto_tree_add_item(tree, hf_zbncp_data_hl_status_mac, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_mac_state, "Unknown Status"));
        break;

    case ZBNCP_HIGH_LVL_STAT_CAT_NWK:
        proto_tree_add_item(tree, hf_zbncp_data_hl_status_nwk, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_nwk_state, "Unknown Status"));
        break;

    case ZBNCP_HIGH_LVL_STAT_CAT_APS:
        dissect_zbee_aps_status_code(tvb, pinfo, tree, offset);
        break;

    case ZBNCP_HIGH_LVL_STAT_CAT_CBKE:
        proto_tree_add_item(tree, hf_zbncp_data_hl_status_cbke, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_cbke_state, "Unknown Status"));
        break;

    default:
        proto_tree_add_item(tree, hf_zbncp_data_hl_status, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: 0x%x", status);
    }
    offset += 1;

    return offset;
}

static tvbuff_t *
dissect_zbncp_dump_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *zbncp_dump_info_tree;
    guint idx, offset;
    guint8 options;

    static int *const options_field[] = {
        &hf_zbncp_dump_options_dir,
        &hf_zbncp_dump_options_int_state,
        &hf_zbncp_dump_options_tx_conflict,
        NULL};

    /* check is it ZBNCP dump sign or not */
    for (idx = 0; idx < ZBNCP_DUMP_INFO_SIGN_SIZE; idx++)
    {
        if (tvb_get_guint8(tvb, idx) != ZBNCP_DUMP_INFO_SIGN[idx])
        {
            return tvb;
        }
    }

    /* Check type */
    if (tvb_get_guint8(tvb, ZBNCP_DUMP_INFO_SIGN_SIZE + 1) != ZBNCP_DUMP_INFO_NCP_TYPE)
    {
        return tvb;
    }

    zbncp_dump_info_tree = proto_tree_add_subtree(tree, tvb, 0, ZBNCP_DUMP_INFO_SIZE, ett_zbncp_dump, NULL, "ZBNCP Dump");

    proto_tree_add_item(zbncp_dump_info_tree, hf_zbncp_dump_preambule, tvb, 0, ZBNCP_DUMP_INFO_SIGN_SIZE, (ENC_ASCII | ENC_NA));
    offset = ZBNCP_DUMP_INFO_SIGN_SIZE;

    proto_tree_add_item(zbncp_dump_info_tree, hf_zbncp_dump_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(zbncp_dump_info_tree, hf_zbncp_dump_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* options subtree */
    options = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(zbncp_dump_info_tree, tvb, offset, hf_zbncp_dump_options, ett_zbncp_dump_opt, options_field, ENC_NA);
    offset += 1;

    if (options & ZBNCP_DUMP_DIR_MASK)
    {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "NCP");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "HOST");
    }
    else
    {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "HOST");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "NCP");
    }

    if (options & ZBNCP_DUMP_POTENTIAL_TX_RX_ERROR_MASK)
    {
        col_append_str(pinfo->cinfo, COL_INFO, ", Potential RX/TX Conflict");
    }

    return tvb_new_subset_remaining(tvb, offset);
}

static guint
dissect_zbncp_high_level_hdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint8 *ptype, guint16 *call_id)
{
    proto_tree *zbncp_comm_hdr_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_zbncp_hl_hdr, NULL, "High Level Header");

    /* Dissect common header */

    proto_tree_add_item(zbncp_comm_hdr_tree, hf_zbncp_data_hl_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    *ptype = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(zbncp_comm_hdr_tree, hf_zbncp_data_hl_packet_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    *call_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(zbncp_comm_hdr_tree, hf_zbncp_data_hl_call_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Update col */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(*ptype, zbncp_hl_type, "Unknown Type"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(*call_id, zbncp_hl_call_id, "Unknown Call ID"));

    /* Dissect additional values */

    if (*ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST ||
        *ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
    {
        /* add TSN */
        proto_tree_add_item(zbncp_comm_hdr_tree, hf_zbncp_data_hl_tsn, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (*ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
    {
        offset = dissect_zbncp_status(tvb, pinfo, zbncp_comm_hdr_tree, offset);
    }

    return offset;
}

static void
dissect_zbncp_high_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint16 *cmd_id)
{
    guint8 packet_type;

    offset = dissect_zbncp_high_level_hdr(tvb, pinfo, tree, offset, &packet_type, cmd_id);

    dissect_zbncp_high_level_body(tvb, pinfo, tree, offset, packet_type, *cmd_id);
}

static void
dissect_zbncp_dst_addrs(proto_tree *zbncp_hl_body_tree, tvbuff_t *tvb, guint dst_addr_mode_offset, guint *offset)
{
    guint8 dst_addr_mode = tvb_get_guint8(tvb, dst_addr_mode_offset);

    if (dst_addr_mode == ZB_APSDE_DST_ADDR_MODE_DST_ADDR_ENDP_NOT_PRESENT || dst_addr_mode == ZB_APSDE_DST_ADDR_MODE_64_ENDP_PRESENT || dst_addr_mode == ZB_APSDE_DST_ADDR_MODE_BIND_TBL_ID)
    {
        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_ieee_addr, tvb, *offset, 8, ENC_NA);
        *offset += 8;
    }
    else if (dst_addr_mode == ZB_APSDE_DST_ADDR_MODE_16_GROUP_ENDP_NOT_PRESENT || dst_addr_mode == ZB_APSDE_DST_ADDR_MODE_16_ENDP_PRESENT)
    {
        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 8;
    }
}

static void
dissect_zbncp_high_level_body(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint8 ptype _U_, guint16 cmd_id)
{
    proto_tree *zbncp_hl_body_tree;

    if (offset >= tvb_reported_length(tvb))
    {
        return;
    }

    zbncp_hl_body_tree = proto_tree_add_subtree_format(tree, tvb, offset, tvb_reported_length(tvb) - offset, ett_zbncp_hl_body, NULL, "Data");

    switch (cmd_id)
    {
    /* NCP Configuration API */
    case ZBNCP_CMD_GET_MODULE_VERSION:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_fw_vers, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_stack_vers, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_proto_vers, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_NCP_RESET:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_reset_opt, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_ZIGBEE_ROLE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zb_role, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_ZIGBEE_ROLE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zb_role, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_ZIGBEE_CHANNEL_MASK:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint i;
            guint8 ch_list_len = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_list_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ch_list_len)
            {
                proto_tree *zbncp_hl_body_data_ch_list = proto_tree_add_subtree_format(
                    zbncp_hl_body_tree, tvb, offset, ch_list_len * 5, ett_zbncp_data_ch_list, NULL, "Channel List");
                for (i = 0; i < ch_list_len; i++)
                {
                    proto_tree *zbncp_hl_body_data_channel_tree = proto_tree_add_subtree_format(
                        zbncp_hl_body_data_ch_list, tvb, offset, 5, ett_zbncp_data_channel, NULL, "Channel");

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
            }
        }
        break;

    case ZBNCP_CMD_SET_ZIGBEE_CHANNEL_MASK:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_GET_ZIGBEE_CHANNEL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_channel, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_PAN_ID:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_SET_PAN_ID:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_GET_LOCAL_IEEE_ADDR:
        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_int_num, tvb, offset, 1, ENC_NA);
        offset += 1;
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SET_LOCAL_IEEE_ADDR:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_int_num, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SET_TRACE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            static int *const trace_bitmask[] = {
                &hf_zbncp_data_trace_wireless_traf,
                &hf_zbncp_data_trace_reserved,
                &hf_zbncp_data_trace_ncp_ll_proto,
                &hf_zbncp_data_trace_host_int_line,
                &hf_zbncp_data_trace_sleep_awake,
                NULL};

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_trace_mask, ett_zbncp_data_trace_bitmask, trace_bitmask, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_GET_KEEPALIVE_TIMEOUT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_keepalive, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_SET_KEEPALIVE_TIMEOUT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_keepalive, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_GET_TX_POWER:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_res_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_TX_POWER:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_req_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_res_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_RX_ON_WHEN_IDLE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rx_on_idle, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_RX_ON_WHEN_IDLE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rx_on_idle, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_JOINED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            static int *const join_bitmask[] = {
                &hf_zbncp_data_joined_bit,
                &hf_zbncp_data_parent_bit,
                NULL};

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_joined, ett_zbncp_data_joind_bitmask, join_bitmask, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_AUTHENTICATED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_authenticated, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_ED_TIMEOUT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_timeout, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_ED_TIMEOUT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_timeout, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ADD_VISIBLE_DEV:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_ADD_INVISIBLE_SHORT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_RM_INVISIBLE_SHORT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_SET_NWK_KEY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_key, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_num, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_SERIAL_NUMBER:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_serial_num, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        break;

    case ZBNCP_CMD_GET_VENDOR_DATA:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint8 size = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_size, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_vendor_data, tvb, offset, size, ENC_NA);
            offset += size;
        }
        break;

    case ZBNCP_CMD_GET_NWK_KEYS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_key, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_num, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_key, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_num, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_key, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_num, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_APS_KEY_BY_IEEE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_key, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        break;

    case ZBNCP_CMD_BIG_PKT_TO_NCP:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint16 pkt_len;

            pkt_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pkt_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pkt, tvb, offset, pkt_len, ENC_NA);
            offset += pkt_len;
        }
        break;

    case ZBNCP_CMD_GET_PARENT_ADDR:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_parent_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_GET_EXT_PAN_ID:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_GET_COORDINATOR_VERSION:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_coordinator_version, tvb, offset++, 1, ENC_NA);
        }
        break;

    case ZBNCP_CMD_GET_SHORT_ADDRESS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_GET_TRUST_CENTER_ADDRESS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_trust_center_addres, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_DEBUG_WRITE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            gint dump_len;

            guint8 dump_type = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dump_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            dump_len = tvb_reported_length(tvb) - offset;
            if (dump_type == 0)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dump_text, tvb, offset, dump_len, ENC_ASCII | ENC_NA);
                offset += dump_len;
            }
            else if (dump_type == 1)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dump_bin, tvb, offset, dump_len, ENC_NA);
                offset += dump_len;
            }
        }
        break;

    case ZBNCP_CMD_GET_CONFIG_PARAMETER:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_parameter_id, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint8 param_id;

            param_id = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_parameter_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (param_id)
            {
            case ZBNCP_PARAMETER_ID_IEEE_ADDR_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_NEIGHBOR_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_APS_SRC_BINDING_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_APS_GROUP_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_NWK_ROUTE_DISCOVERY_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_IOBUF_POOL_SIZE:
            case ZBNCP_PARAMETER_ID_PANID_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_APS_DUPS_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_APS_BIND_TRANS_TABLE_SIZE:
            case ZBNCP_PARAMETER_ID_N_APS_RETRANS_ENTRIES:
            case ZBNCP_PARAMETER_ID_NWK_MAX_HOPS:
            case ZBNCP_PARAMETER_ID_NIB_MAX_CHILDREN:
            case ZBNCP_PARAMETER_ID_N_APS_KEY_PAIR_ARR_MAX_SIZE:
            case ZBNCP_PARAMETER_ID_NWK_MAX_SRC_ROUTES:
            case ZBNCP_PARAMETER_ID_APS_MAX_WINDOW_SIZE:
            case ZBNCP_PARAMETER_ID_APS_INTERFRAME_DELAY:
            case ZBNCP_PARAMETER_ID_ZDO_ED_BIND_TIMEOUT:
            case ZBNCP_PARAMETER_ID_ZLL_DEFAULT_RSSI_THRESHOLD:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_value8_dec, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;

            case ZBNCP_PARAMETER_ID_NIB_PASSIVE_ASK_TIMEOUT:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_value16_dec, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                break;

            case ZBNCP_PARAMETER_ID_APS_ACK_TIMEOUTS:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_ack_to_non_sleepy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_ack_to_sleepy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                break;

            case ZBNCP_PARAMETER_ID_MAC_BEACON_JITTER:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_min16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_max16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                break;

            case ZBNCP_PARAMETER_ID_TX_POWER:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_default8_sign, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_current8_sign, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;

            case ZBNCP_PARAMETER_ID_NIB_MTORR:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_is_concentrator, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_concentrator_radius, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_time16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                break;
            }
        }
        break;

    case ZBNCP_CMD_GET_LOCK_STATUS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lock_status, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_TRACE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            static int *const trace_bitmask[] = {
                &hf_zbncp_data_trace_wireless_traf,
                &hf_zbncp_data_trace_ncp_ll_proto,
                &hf_zbncp_data_trace_host_int_line,
                &hf_zbncp_data_trace_sleep_awake,
                NULL};

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_trace_mask, ett_zbncp_data_trace_bitmask, trace_bitmask, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_NCP_RESET_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_reset_source, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_NWK_LEAVE_ALLOWED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_nwk_leave_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_NWK_LEAVE_ALLOWED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_nwk_leave_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NVRAM_WRITE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint dataset_count, idx;
            guint16 dataset_len;

            dataset_count = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_dataset_quantity, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* multiple datasets */
            for (idx = 0; idx < dataset_count; idx++)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_dataset_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dataset_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                dataset_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dataset_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_dataset_data, tvb, offset, dataset_len, ENC_NA);
                offset += dataset_len;
            }
        }
        break;

    case ZBNCP_CMD_NVRAM_READ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_dataset_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint16 dataset_len;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_dataset_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dataset_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            dataset_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dataset_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nvram_dataset_data, tvb, offset, dataset_len, ENC_NA);
            offset += dataset_len;
        }
        break;

    case ZBNCP_CMD_SET_TC_POLICY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tc_policy_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tc_policy_value, tvb, offset + 2, 1, ENC_NA);
            offset += 3;
        }
        break;

    case ZBNCP_CMD_SET_EXTENDED_PAN_ID:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SET_MAX_CHILDREN:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_max_children, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_MAX_CHILDREN:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_max_children, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_ZDO_LEAVE_ALLOWED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_leave_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_ZDO_LEAVE_ALLOWED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_leave_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_LEAVE_WO_REJOIN_ALLOWED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_leave_wo_rejoin_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_LEAVE_WO_REJOIN_ALLOWED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_leave_wo_rejoin_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GP_SET_SHARED_KEY_TYPE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zgp_key_type, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GP_SET_DEFAULT_LINK_KEY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zgp_link_key, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_PRODUCTION_CONFIG_READ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree *prod_conf_hdr_subtree;
            prod_conf_hdr_subtree = proto_tree_add_subtree(zbncp_hl_body_tree, tvb, offset, 8, ett_zbncp_data_prod_conf_hdr, NULL, "Production config header");

            proto_tree_add_item(prod_conf_hdr_subtree, hf_zbncp_data_prod_conf_hdr_crc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(prod_conf_hdr_subtree, hf_zbncp_data_prod_conf_hdr_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(prod_conf_hdr_subtree, hf_zbncp_data_prod_conf_hdr_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_prod_conf_body, tvb, offset, tvb_captured_length(tvb) - offset, ENC_NA);
            offset = tvb_captured_length(tvb);
        }
        break;

    /* AF API */
    case ZBNCP_CMD_AF_SET_SIMPLE_DESC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint8 in_cl_cnt;
            guint8 out_cl_cnt;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_profile_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_device_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dev_version, tvb, offset, 1, ENC_NA);
            offset += 1;

            in_cl_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_in_cl_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            out_cl_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_cl_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (in_cl_cnt)
            {
                proto_tree *zbncp_hl_body_in_cl_list_tree =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * in_cl_cnt, ett_zbncp_data_in_cl_list, NULL, "Input Cluster List");
                for (i = 0; i < in_cl_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_in_cl_list_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }

            if (out_cl_cnt)
            {
                proto_tree *zbncp_hl_body_out_cl_list_tree =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * out_cl_cnt, ett_zbncp_data_out_cl_list, NULL, "Output Cluster List");
                for (i = 0; i < out_cl_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_out_cl_list_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }
        }
        break;

    case ZBNCP_CMD_AF_DEL_EP:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_AF_SET_NODE_DESC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            /* copy-pasted from packet-ieee802154.c */
            static int *const capability[] = {
                &hf_ieee802154_cinfo_alt_coord,
                &hf_ieee802154_cinfo_device_type,
                &hf_ieee802154_cinfo_power_src,
                &hf_ieee802154_cinfo_idle_rx,
                &hf_ieee802154_cinfo_sec_capable,
                &hf_ieee802154_cinfo_alloc_addr,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zb_role, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_mac_cap, ett_zbncp_data_mac_cap, capability, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_manuf_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_AF_SET_POWER_DESC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            static int *const pwr_sources[] = {
                &hf_zbncp_data_pwr_src_const,
                &hf_zbncp_data_pwr_src_recharge,
                &hf_zbncp_data_pwr_src_disposable,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cur_pwr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_av_pwr_src, ett_zbncp_data_pwr_src, pwr_sources, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_cur_pwr_src, ett_zbncp_data_cur_pwr_src, pwr_sources, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cur_pwr_lvl, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_AF_SUBGHZ_SUSPEND_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_susp_period, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_AF_SUBGHZ_RESUME_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_susp_period, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    /* ZDO API */
    case ZBNCP_CMD_ZDO_NWK_ADDR_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_req_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_remote_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_remote_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (offset < tvb_reported_length(tvb))
            {
                guint8 num_assoc_dev = tvb_get_guint8(tvb, offset);

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_num_asoc_dec, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (num_assoc_dev)
                {
                    guint i;
                    proto_tree *zbncp_hl_body_asoc_nwk_list;

                    proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    zbncp_hl_body_asoc_nwk_list =
                        proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * num_assoc_dev, ett_zbncp_data_asoc_nwk_list, NULL, "Assoc Dev NWK Addr List");

                    for (i = 0; i < num_assoc_dev; i++)
                    {
                        proto_tree_add_item(zbncp_hl_body_asoc_nwk_list, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                    }
                }
            }
        }
        break;

    case ZBNCP_CMD_ZDO_IEEE_ADDR_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_req_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_remote_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_remote_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (offset < tvb_reported_length(tvb))
            {
                guint8 num_assoc_dev = tvb_get_guint8(tvb, offset);

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_num_asoc_dec, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (num_assoc_dev)
                {
                    guint i;
                    proto_tree *zbncp_hl_body_asoc_nwk_list;

                    proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    zbncp_hl_body_asoc_nwk_list =
                        proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * num_assoc_dev, ett_zbncp_data_asoc_nwk_list, NULL, "Assoc Dev NWK Addr List");

                    for (i = 0; i < num_assoc_dev; i++)
                    {
                        proto_tree_add_item(zbncp_hl_body_asoc_nwk_list, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                    }
                }
            }
        }
        break;

    case ZBNCP_CMD_ZDO_POWER_DESC_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            static int *const pwr_desc[] = {
                &hf_zbncp_data_pwr_desc_cur_power_mode,
                &hf_zbncp_data_pwr_desc_av_pwr_src,
                &hf_zbncp_data_pwr_desc_cur_pwr_src,
                &hf_zbncp_data_pwr_desc_cur_pwr_lvl,
                NULL};

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_pwr_desc, ett_zbncp_data_pwr_desc, pwr_desc, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_NODE_DESC_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            static int *const flags[] = {
                &hf_zbncp_data_flags_zb_role,
                &hf_zbncp_data_flags_comp_desc_av,
                &hf_zbncp_data_flags_user_desc_av,
                &hf_zbncp_data_flags_freq_868,
                &hf_zbncp_data_flags_freq_902,
                &hf_zbncp_data_flags_freq_2400,
                &hf_zbncp_data_flags_freq_eu_sub_ghz,
                NULL};

            static int *const mac_capability[] = {
                &hf_ieee802154_cinfo_alt_coord,
                &hf_ieee802154_cinfo_device_type,
                &hf_ieee802154_cinfo_power_src,
                &hf_ieee802154_cinfo_idle_rx,
                &hf_ieee802154_cinfo_sec_capable,
                &hf_ieee802154_cinfo_alloc_addr,
                NULL};

            static int *const server_mask[] = {
                &hf_zbncp_data_srv_msk_prim_tc,
                &hf_zbncp_data_srv_msk_backup_tc,
                &hf_zbncp_data_srv_msk_prim_bind_tbl_cache,
                &hf_zbncp_data_srv_msk_backup_bind_tbl_cache,
                &hf_zbncp_data_srv_msk_prim_disc_cache,
                &hf_zbncp_data_srv_msk_backup_disc_cache,
                &hf_zbncp_data_srv_msk_nwk_manager,
                &hf_zbncp_data_srv_msk_stack_compl_rev,
                NULL};

            static int *const desc_capability[] = {
                &hf_zbncp_data_desc_cap_ext_act_ep_list_av,
                &hf_zbncp_data_desc_cap_ext_simple_desc_list_av,
                NULL};

            proto_tree_add_bitmask_with_flags(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_flags16, ett_zbncp_data_flags, flags, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
            offset += 2;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_mac_cap, ett_zbncp_data_mac_cap, mac_capability, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_manuf_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_max_buf_size, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_max_inc_trans_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask_with_flags(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_srv_msk, ett_zbncp_data_server_mask, server_mask, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_max_out_trans_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_desc_cap, ett_zbncp_data_desc_cap, desc_capability, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_SIMPLE_DESC_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint i;
            guint8 in_cl_cnt;
            guint8 out_cl_cnt;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_profile_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_device_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dev_version, tvb, offset, 1, ENC_NA);
            offset += 1;

            in_cl_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_in_cl_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            out_cl_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_cl_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (in_cl_cnt)
            {
                proto_tree *zbncp_hl_body_in_cl_list_tree =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * in_cl_cnt, ett_zbncp_data_in_cl_list, NULL, "Input Cluster List");
                for (i = 0; i < in_cl_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_in_cl_list_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }

            if (out_cl_cnt)
            {
                proto_tree *zbncp_hl_body_out_cl_list_tree =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * out_cl_cnt, ett_zbncp_data_out_cl_list, NULL, "Output Cluster List");
                for (i = 0; i < out_cl_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_out_cl_list_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_ACTIVE_EP_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint i;
            guint8 ep_cnt = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ep_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ep_cnt)
            {
                proto_tree *zbncp_hl_body_tree_ep_list =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, ep_cnt, ett_zbncp_data_ep_list, NULL, "Endpoint List");
                for (i = 0; i < ep_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_tree_ep_list, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_MATCH_DESC_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint8 in_cl_cnt;
            guint8 out_cl_cnt;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_profile_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            in_cl_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_in_cl_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            out_cl_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_cl_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (in_cl_cnt)
            {
                proto_tree *zbncp_hl_body_in_cl_list_tree =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * in_cl_cnt, ett_zbncp_data_in_cl_list, NULL, "Input Cluster List");
                for (i = 0; i < in_cl_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_in_cl_list_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }

            if (out_cl_cnt)
            {
                proto_tree *zbncp_hl_body_out_cl_list_tree =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, 2 * out_cl_cnt, ett_zbncp_data_out_cl_list, NULL, "Output Cluster List");
                for (i = 0; i < out_cl_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_out_cl_list_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint i;
            guint8 ep_cnt = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ep_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ep_cnt)
            {
                proto_tree *zbncp_hl_body_tree_ep_list =
                    proto_tree_add_subtree_format(zbncp_hl_body_tree, tvb, offset, ep_cnt, ett_zbncp_data_ep_list, NULL, "Endpoint List");
                for (i = 0; i < ep_cnt; i++)
                {
                    proto_tree_add_item(zbncp_hl_body_tree_ep_list, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_BIND_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_UNBIND_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_ieee_addr, tvb, offset, 8, ENC_NA);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_MGMT_LEAVE_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            static int *const leave_flags[] = {
                &hf_zbncp_data_leave_flags_remove_chil,
                &hf_zbncp_data_leave_flags_rejoin,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_leave_flags, ett_zbncp_data_leave_flags, leave_flags, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_PERMIT_JOINING_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_permit_dur, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tc_sign, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_DEV_ANNCE_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            static int *const mac_capability[] = {
                &hf_ieee802154_cinfo_alt_coord,
                &hf_ieee802154_cinfo_device_type,
                &hf_ieee802154_cinfo_power_src,
                &hf_ieee802154_cinfo_idle_rx,
                &hf_ieee802154_cinfo_sec_capable,
                &hf_ieee802154_cinfo_alloc_addr,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_mac_cap, ett_zbncp_data_mac_cap, mac_capability, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_REJOIN:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint8 ch_list_len;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            ch_list_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_list_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ch_list_len)
            {
                proto_tree *zbncp_hl_body_data_ch_list = proto_tree_add_subtree_format(
                    zbncp_hl_body_tree, tvb, offset, ch_list_len * 5, ett_zbncp_data_ch_list, NULL, "Channel List");
                for (i = 0; i < ch_list_len; i++)
                {
                    proto_tree *zbncp_hl_body_data_channel_tree = proto_tree_add_subtree_format(
                        zbncp_hl_body_data_ch_list, tvb, offset, 5, ett_zbncp_data_channel, NULL, "Channel");

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_secur_rejoin, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            static int *const zdo_rejoin_flags[] = {
                &hf_zbncp_data_zdo_rejoin_flags_tcsw_happened,
                NULL};
            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_zdo_rejoin_flags, ett_zbncp_data_zdo_rejoin_flags, zdo_rejoin_flags, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_SYSTEM_SRV_DISCOVERY_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_server_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_MGMT_BIND_REQ:
    case ZBNCP_CMD_ZDO_MGMT_LQI_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_start_entry_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_MGMT_NWK_UPDATE_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_scan_duration, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_scan_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_scan_mgr_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_ZDO_REMOTE_CMD_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint16 data_len;
            static int *const aps_fc[] = {
                &hf_zbncp_data_aps_fc_deliv_mode,
                &hf_zbncp_data_aps_fc_secur,
                &hf_zbncp_data_aps_fc_ack_retrans,
                NULL};

            static int *const aps_key_attr[] = {
                &hf_zbncp_data_aps_key_attr_key_src,
                &hf_zbncp_data_aps_key_attr_key_used,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_param_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            data_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_aps_fc, ett_zbncp_data_apc_fc, aps_fc, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_group_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_profile_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_mac_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_mac_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_aps_key_attr, ett_zbncp_data_aps_key_attr, aps_key_attr, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    case ZBNCP_CMD_ZDO_GET_STATS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_do_cleanup, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_max_rx_bcast, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_bcast, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_rx_ucast, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_ucast_total_zcl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_ucast_failures_zcl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_ucast_retries_zcl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_ucast_total, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_ucast_failures, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_tx_ucast_retries, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_phy_to_mac_que_lim_reached, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_validate_drop_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_phy_cca_fail_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_period_of_time, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_last_msg_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_last_msg_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_number_of_resets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_tx_bcast, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_tx_ucast_success, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_tx_ucast_retry, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_tx_ucast_fail, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_route_disc_initiated, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_neighbor_added, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_neighbor_removed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_neighbor_stale, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_join_indication, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_childs_removed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_fc_failure, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_fc_failure, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_unauthorized_key, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_decrypt_failure, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_decrypt_failure, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_packet_buffer_allocate_failures, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_average_mac_retry_per_aps_message_sent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_retry_overflow, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_bcast_table_full, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_status, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_DEV_AUTHORIZED_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint8 auth_type;
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            auth_type = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_auth_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (auth_type == ZB_ZDO_AUTH_LEGACY_TYPE)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_leg_auth_status_code, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            else if (auth_type == ZB_ZDO_AUTH_TCLK_TYPE)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_zdo_tclk_auth_status_code, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;

    case ZBNCP_CMD_ZDO_DEV_UPDATE_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_upd_status_code, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_ZDO_SET_NODE_DESC_MANUF_CODE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_manuf_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_HL_ZDO_GET_DIAG_DATA_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    /* APS API */
    case ZBNCP_CMD_APSDE_DATA_REQ:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint16 data_len;
            static int *const tx_options[] = {
                &hf_zbncp_data_tx_opt_secur,
                &hf_zbncp_data_tx_opt_obsolete,
                &hf_zbncp_data_tx_opt_ack,
                &hf_zbncp_data_tx_opt_frag,
                &hf_zbncp_data_tx_opt_inc_ext_nonce,
                &hf_zbncp_data_tx_opt_force_mesh_route,
                &hf_zbncp_data_tx_opt_send_route_record,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_param_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            data_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset + ZBNCP_CMD_APSDE_DATA_REQ_DST_ADDR_MODE_OFFSET, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_profile_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_radius, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_tx_opt, ett_zbncp_data_tx_opt, tx_options, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_use_alias, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_alias_src, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_alias_seq, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset + ZBNCP_CMD_APSDE_DATA_REQ_RSP_DST_ADDR_MODE_OFFSET, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tx_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APSME_BIND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST || ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint16 data_len;
            /* Binding table ID - it's an additional field for SNCP only */
            data_len = tvb_reported_length(tvb) - offset;
            if (data_len == 1)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;

    case ZBNCP_CMD_APSME_UNBIND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST || ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint16 data_len;
            /* Binding table ID - it's an additional field for SNCP only */
            data_len = tvb_reported_length(tvb) - offset;
            if (data_len == 1)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;

    case ZBNCP_CMD_APSME_ADD_GROUP:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_group_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APSME_RM_GROUP:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_group_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APSDE_DATA_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint16 data_len;
            static int *const aps_fc[] = {
                &hf_zbncp_data_aps_fc_deliv_mode,
                &hf_zbncp_data_aps_fc_secur,
                &hf_zbncp_data_aps_fc_ack_retrans,
                NULL};

            static int *const aps_key_attr[] = {
                &hf_zbncp_data_aps_key_attr_key_src,
                &hf_zbncp_data_aps_key_attr_key_used,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_param_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            data_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_aps_fc, ett_zbncp_data_apc_fc, aps_fc, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_group_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_profile_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_mac_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_mac_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_aps_key_attr, ett_zbncp_data_aps_key_attr, aps_key_attr, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    case ZBNCP_CMD_APSME_RM_ALL_GROUPS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APS_GET_GROUP_TABLE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint8 group_num;
            group_num = tvb_get_gint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_group_num, tvb, offset++, 1, ENC_NA);

            if (group_num)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_group, tvb, offset, group_num * 2, ENC_LITTLE_ENDIAN);
                offset += group_num * 2;
            }
        }
        break;

    case ZBNCP_CMD_APSME_RM_BIND_ENTRY_BY_ID:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APSME_CLEAR_BIND_TABLE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_APSME_GET_BIND_ENTRY_BY_ID:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_bind_type, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APSME_REMOTE_BIND_IND:
        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
        offset += 1;

        dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_bind_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case ZBNCP_CMD_APSME_REMOTE_UNBIND_IND:
        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_src_endpoint, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_addr_mode, tvb, offset, 1, ENC_NA);
        offset += 1;

        dissect_zbncp_dst_addrs(zbncp_hl_body_tree, tvb, offset - 1, &offset);

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dst_endpoint, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_bind_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case ZBNCP_CMD_APSME_SET_REMOTE_BIND_OFFSET:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_remote_bind_offset, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_APSME_GET_REMOTE_BIND_OFFSET:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_remote_bind_offset, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    /* NWK Management API*/
    case ZBNCP_CMD_NWK_FORMATION:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint8 ch_list_len = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_list_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ch_list_len)
            {
                proto_tree *zbncp_hl_body_data_ch_list = proto_tree_add_subtree_format(
                    zbncp_hl_body_tree, tvb, offset, ch_list_len * 5, ett_zbncp_data_ch_list, NULL, "Channel List");
                for (i = 0; i < ch_list_len; i++)
                {
                    proto_tree *zbncp_hl_body_data_channel_tree = proto_tree_add_subtree_format(
                        zbncp_hl_body_data_ch_list, tvb, offset, 5, ett_zbncp_data_channel, NULL, "Channel");

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_scan_dur, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_distr_nwk_flag, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_NWK_DISCOVERY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint8 ch_list_len = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_list_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ch_list_len)
            {
                proto_tree *zbncp_hl_body_data_ch_list = proto_tree_add_subtree_format(
                    zbncp_hl_body_tree, tvb, offset, ch_list_len * 5, ett_zbncp_data_ch_list, NULL, "Channel List");
                for (i = 0; i < ch_list_len; i++)
                {
                    proto_tree *zbncp_hl_body_data_channel_tree = proto_tree_add_subtree_format(
                        zbncp_hl_body_data_ch_list, tvb, offset, 5, ett_zbncp_data_channel, NULL, "Channel");

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_scan_dur, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint i;
            guint8 nwk_count = tvb_get_guint8(tvb, offset);
            static int *flags[] = {
                &hf_zbncp_data_flags_permit_join,
                &hf_zbncp_data_flags_router_cap,
                &hf_zbncp_data_flags_ed_cap,
                &hf_zbncp_data_flags_stack_profile,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_count, tvb, offset, 1, ENC_NA);
            offset += 1;

            for (i = 0; i < nwk_count; i++)
            {
                proto_tree *zbncp_hl_body_data_nwk_descr = proto_tree_add_subtree_format(
                    zbncp_hl_body_tree, tvb, offset, 14, ett_zbncp_data_nwk_descr, NULL, "Network Descriptor");

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_nwk_upd_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_channel, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_bitmask(zbncp_hl_body_data_nwk_descr, tvb, offset, hf_zbncp_data_flags8, ett_zbncp_data_flags, flags, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(zbncp_hl_body_data_nwk_descr, hf_zbncp_data_rssi, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;

    case ZBNCP_CMD_NWK_NLME_JOIN:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint8 ch_list_len;
            static int *const mac_capability[] = {
                &hf_ieee802154_cinfo_alt_coord,
                &hf_ieee802154_cinfo_device_type,
                &hf_ieee802154_cinfo_power_src,
                &hf_ieee802154_cinfo_idle_rx,
                &hf_ieee802154_cinfo_sec_capable,
                &hf_ieee802154_cinfo_alloc_addr,
                NULL};

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rejoin_nwk, tvb, offset, 1, ENC_NA);
            offset += 1;

            ch_list_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ch_list_len, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (ch_list_len)
            {
                proto_tree *zbncp_hl_body_data_ch_list = proto_tree_add_subtree_format(
                    zbncp_hl_body_tree, tvb, offset, ch_list_len * 5, ett_zbncp_data_ch_list, NULL, "Channel List");
                for (i = 0; i < ch_list_len; i++)
                {
                    proto_tree *zbncp_hl_body_data_channel_tree = proto_tree_add_subtree_format(
                        zbncp_hl_body_data_ch_list, tvb, offset, 5, ett_zbncp_data_channel, NULL, "Channel");

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(zbncp_hl_body_data_channel_tree, hf_zbncp_data_ch_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_scan_dur, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(zbncp_hl_body_tree, tvb, offset, hf_zbncp_data_mac_cap, ett_zbncp_data_mac_cap, mac_capability, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_secur_en, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_channel, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_enh_beacon, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_if, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_PERMIT_JOINING:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_permit_dur, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_GET_IEEE_BY_SHORT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_NWK_GET_SHORT_BY_IEEE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_NWK_GET_NEIGHBOR_BY_IEEE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zb_role, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rx_on_idle, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ed_config, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_timeout_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dev_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_relationship, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tx_fail_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_cost, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_age, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_keepalive_rec, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_if_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_REJOINED_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ext_pan_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_channel, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_beacon_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_if, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_REJOIN_FAILED_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint status_category = tvb_get_guint8(tvb, offset);
            guint status;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_cat, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Add status */
            status = tvb_get_guint8(tvb, offset);
            switch (status_category)
            {
            case ZBNCP_HIGH_LVL_STAT_CAT_GENERIC:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_generic, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zbncp_hl_status_generic, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_MAC:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_mac, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_mac_state, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_NWK:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_nwk, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_nwk_state, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_APS:
                dissect_zbee_aps_status_code(tvb, pinfo, zbncp_hl_body_tree, offset);
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_CBKE:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_cbke, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_cbke_state, "Unknown Status"));
                break;

            default:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: 0x%x", status);
            }
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_LEAVE_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rejoin, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_PIM_SET_FAST_POLL_INTERVAL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_fast_poll_int, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_PIM_SET_LONG_POLL_INTERVAL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_long_poll_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_PIM_START_FAST_POLL:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_PIM_START_POLL:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_PIM_SET_ADAPTIVE_POLL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_PIM_STOP_FAST_POLL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_stop_fast_poll_result, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_PIM_STOP_POLL:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_PIM_ENABLE_TURBO_POLL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_PIM_DISABLE_TURBO_POLL:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_NWK_GET_FIRST_NBT_ENTRY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zb_role, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rx_on_idle, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ed_config, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_timeout_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dev_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_relationship, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tx_fail_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_cost, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_age, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_keepalive_rec, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_if_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_GET_NEXT_NBT_ENTRY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_zb_role, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rx_on_idle, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ed_config, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_timeout_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dev_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_relationship, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tx_fail_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_cost, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_age, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_keepalive_rec, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_mac_if_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_PAN_ID_CONFLICT_RESOLVE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint i;
            guint16 pan_id_cnt = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pan_id_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            for (i = 0; i < pan_id_cnt; i++)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
        }
        break;

    case ZBNCP_CMD_NWK_PAN_ID_CONFLICT_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint i;
            guint16 pan_id_cnt = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pan_id_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            for (i = 0; i < pan_id_cnt; i++)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
        }
        break;

    case ZBNCP_CMD_NWK_ADDRESS_UPDATE_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_NWK_START_WITHOUT_FORMATION:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_NWK_NLME_ROUTER_START:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_beacon_order, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_superframe_order, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_battery_life_ext, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_PIM_SINGLE_POLL:
        /* Empty: only common headers  */
        break;

    case ZBNCP_CMD_PARENT_LOST_IND:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_PIM_START_TURBO_POLL_PACKETS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_poll_pkt_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_PIM_START_TURBO_POLL_CONTINUOUS:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_poll_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_PIM_TURBO_POLL_CONTINUOUS_LEAVE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_PIM_TURBO_POLL_PACKETS_LEAVE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_PIM_PERMIT_TURBO_POLL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_poll_permit_flag, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_PIM_SET_FAST_POLL_TIMEOUT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_poll_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_PIM_GET_LONG_POLL_INTERVAL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_long_poll_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_PIM_GET_IN_FAST_POLL_FLAG:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_fast_poll_flag, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SET_KEEPALIVE_MODE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_keepalive_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_START_CONCENTRATOR_MODE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_radius, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_time_between_disc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_STOP_CONCENTRATOR_MODE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_NWK_ENABLE_PAN_ID_CONFLICT_RESOLUTION:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_enable_flag, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_ENABLE_AUTO_PAN_ID_CONFLICT_RESOLUTION:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_enable_flag, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_PIM_TURBO_POLL_CANCEL_PACKET:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_SET_FORCE_ROUTE_RECORD:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_force_route_record_sending, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_GET_FORCE_ROUTE_RECORD:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_force_route_record_sending, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_NWK_NBR_ITERATOR_NEXT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx_16b, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_upd_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    /* Security API */
    case ZBNCP_CMD_SECUR_SET_LOCAL_IC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
            offset = tvb_reported_length(tvb);
        }
        break;

    case ZBNCP_CMD_SECUR_ADD_IC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
            offset = tvb_reported_length(tvb);
        }
        break;

    case ZBNCP_CMD_SECUR_DEL_IC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_ADD_CERT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint8 crypto_suite = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cs, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (crypto_suite == 1)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ca_pub_key, tvb, offset, 22, ENC_NA);
                offset += 22;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cert, tvb, offset, 48, ENC_NA);
                offset += 48;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ca_priv_key, tvb, offset, 21, ENC_NA);
                offset += 21;
            }
            else if (crypto_suite == 2)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ca_pub_key, tvb, offset, 37, ENC_NA);
                offset += 37;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cert, tvb, offset, 74, ENC_NA);
                offset += 74;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ca_priv_key, tvb, offset, 36, ENC_NA);
                offset += 36;
            }
        }
        break;

    case ZBNCP_CMD_SECUR_DEL_CERT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cs, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_issuer, tvb, offset, 8, ENC_NA);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_START_KE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cs, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint status_category = tvb_get_guint8(tvb, offset);
            guint status;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_cat, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Add status */
            status = tvb_get_guint8(tvb, offset);
            switch (status_category)
            {
            case ZBNCP_HIGH_LVL_STAT_CAT_GENERIC:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_generic, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zbncp_hl_status_generic, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_MAC:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_mac, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_mac_state, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_NWK:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_nwk, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_nwk_state, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_APS:
                dissect_zbee_aps_status_code(tvb, pinfo, zbncp_hl_body_tree, offset);
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_CBKE:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_cbke, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_cbke_state, "Unknown Status"));
                break;

            default:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: 0x%x", status);
            }
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SECUR_START_PARTNER_LK:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_SECUR_CBKE_SRV_FINISHED_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint status_category = tvb_get_guint8(tvb, offset);
            guint status;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_cat, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Add status */
            status = tvb_get_guint8(tvb, offset);
            switch (status_category)
            {
            case ZBNCP_HIGH_LVL_STAT_CAT_GENERIC:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_generic, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zbncp_hl_status_generic, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_MAC:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_mac, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_mac_state, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_NWK:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_nwk, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_nwk_state, "Unknown Status"));
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_APS:
                dissect_zbee_aps_status_code(tvb, pinfo, zbncp_hl_body_tree, offset);
                break;

            case ZBNCP_HIGH_LVL_STAT_CAT_CBKE:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status_cbke, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s", val_to_str_const(status, zb_cbke_state, "Unknown Status"));
                break;

            default:
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_hl_status, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: 0x%x", status);
            }
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_nwk_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_PARTNER_LK_FINISHED_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_KE_WHITELIST_ADD:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_KE_WHITELIST_DEL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_KE_WHITELIST_DEL_ALL:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_SECUR_JOIN_USES_IC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic_en, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SECUR_GET_IC_BY_IEEE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
            offset = tvb_reported_length(tvb);
        }
        break;

    case ZBNCP_CMD_SECUR_GET_CERT:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cs, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint8 crypto_suite = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cs, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (crypto_suite == 1)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ca_pub_key, tvb, offset, 22, ENC_NA);
                offset += 22;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cert, tvb, offset, 48, ENC_NA);
                offset += 48;
            }
            else if (crypto_suite == 2)
            {
                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ca_pub_key, tvb, offset, 37, ENC_NA);
                offset += 37;

                proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_cert, tvb, offset, 74, ENC_NA);
                offset += 74;
            }
        }
        break;

    case ZBNCP_CMD_SECUR_GET_LOCAL_IC:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
            offset = tvb_reported_length(tvb);
        }
        break;

    case ZBNCP_CMD_SECUR_TCLK_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_type, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_SECUR_TCLK_EXCHANGE_FAILED_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            offset = dissect_zbncp_status(tvb, pinfo, zbncp_hl_body_tree, offset);
        }
        break;

    case ZBNCP_CMD_SECUR_GET_KEY_IDX:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_SECUR_GET_KEY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_link_key, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_aps_link_key_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_src, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_key_attr, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_out_frame_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_inc_frame_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_partner_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        break;

    case ZBNCP_CMD_SECUR_ERASE_KEY:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_SECUR_CLEAR_KEY_TABLE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_SECUR_NWK_INITIATE_KEY_SWITCH_PROCEDURE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_SECUR_GET_IC_LIST:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic_table_size, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_start_idx, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic_ent_cnt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic, tvb, offset, tvb_captured_length(tvb) - offset, ENC_NA);
            offset += tvb_captured_length(tvb) - offset;
        }
        break;

    case ZBNCP_CMD_SECUR_GET_IC_BY_IDX:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_entry_idx, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_ic, tvb, offset, tvb_captured_length(tvb) - offset, ENC_NA);
            offset += tvb_captured_length(tvb) - offset;
        }
        break;

    case ZBNCP_CMD_SECUR_REMOVE_ALL_IC:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_SECUR_PARTNER_LK_ENABLE:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_enable, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    /* Manufacturing Test API */
    case ZBNCP_CMD_MANUF_MODE_START:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_channel4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_MANUF_MODE_END:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_MANUF_SET_CHANNEL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_channel4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_MANUF_GET_CHANNEL:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_page, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_channel4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        break;

    case ZBNCP_CMD_MANUF_SET_POWER:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_MANUF_GET_POWER:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    case ZBNCP_CMD_MANUF_START_TONE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_MANUF_STOP_TONE:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_MANUF_START_STREAM_RANDOM:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_seed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case ZBNCP_CMD_MANUF_STOP_STREAM_RANDOM:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_NCP_HL_MANUF_SEND_SINGLE_PACKET:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint8 data_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen8, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    case ZBNCP_CMD_MANUF_START_TEST_RX:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_MANUF_STOP_TEST_RX:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_MANUF_RX_PACKET_IND:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION)
        {
            guint16 data_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_lqi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    /*  NCP FW upgrade API */
    case ZBNCP_CMD_OTA_RUN_BOOTLOADER:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_OTA_START_UPGRADE_IND:
        /* Empty: only common headers */
        break;

    case ZBNCP_CMD_OTA_SEND_PORTION_FW:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint16 data_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    case ZBNCP_CMD_READ_NVRAM_RESERVED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen8, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        else if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            guint8 data_len;

            data_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen8, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    case ZBNCP_CMD_WRITE_NVRAM_RESERVED:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST)
        {
            guint8 data_len;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_do_erase, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            data_len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_dlen8, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (data_len > (tvb_reported_length(tvb) - offset))
            {
                data_len = tvb_reported_length(tvb) - offset;
            }
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_array, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        break;

    case ZBNCP_CMD_GET_CALIBRATION_INFO:
        if (ptype == ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE)
        {
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_calibration_status, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(zbncp_hl_body_tree, hf_zbncp_data_calibration_value, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
        break;

    default:;
    }

    /* Dump the tail. */
    if (offset < tvb_reported_length(tvb))
    {
        tvbuff_t *leftover_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(leftover_tvb, pinfo, tree);
    }
}

static void
dissect_zbncp_fragmentation_body(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree *zbncp_body_tree = proto_tree_add_subtree_format(tree, tvb, offset, tvb_reported_length(tvb) - offset, ett_zbncp_ll_body, NULL, "ZBNCP Packet Body");

    /* CRC */
    proto_tree_add_item(zbncp_body_tree, hf_zbncp_body_data_crc16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Dump the tail. */
    if (offset < tvb_reported_length(tvb))
    {
        tvbuff_t *leftover_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(leftover_tvb, pinfo, zbncp_body_tree);
    }
}

static void
dissect_zbncp_body(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint16 *cmd_id)
{
    proto_tree *zbncp_body_tree = proto_tree_add_subtree_format(tree, tvb, offset, tvb_reported_length(tvb) - offset, ett_zbncp_ll_body, NULL, "ZBNCP Packet Body");

    /* CRC */
    proto_tree_add_item(zbncp_body_tree, hf_zbncp_body_data_crc16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    dissect_zbncp_high_level(tvb, pinfo, zbncp_body_tree, offset, cmd_id);
}

static guint
dissect_zbncp_ll_hdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 *hdr_flags)
{
    proto_tree *ncp_ll_hdr_tree;
    proto_item *proto_root;

    static int *const packet_flags[] = {
        &hf_zbncp_hdr_flags_isack,
        &hf_zbncp_hdr_flags_retrans,
        &hf_zbncp_hdr_flags_packetseq,
        &hf_zbncp_hdr_flags_ackseq,
        &hf_zbncp_hdr_flags_first_frag,
        &hf_zbncp_hdr_flags_last_frag,
        NULL};

    if (tvb_get_guint8(tvb, 0) != ZBNCP_SIGN_FST_BYTE ||
        tvb_get_guint8(tvb, 1) != ZBNCP_SIGN_SEC_BYTE)
    {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZB NCP");

    proto_root = proto_tree_add_protocol_format(tree, zbncp_frame, tvb, 0, tvb_captured_length(tvb), "ZBNCP Low Level Header");
    ncp_ll_hdr_tree = proto_item_add_subtree(proto_root, ett_zbncp_hdr);

    /* hdr */
    proto_tree_add_item(ncp_ll_hdr_tree, hf_zbncp_hdr_sign, tvb, offset, 2, ENC_ASCII);
    offset += 2;

    /* pkt lenght without sign */
    proto_tree_add_item(ncp_ll_hdr_tree, hf_zbncp_packet_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* hl packet type */
    proto_tree_add_item(ncp_ll_hdr_tree, hf_zbncp_hdr_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* hdr flags */
    *hdr_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(ncp_ll_hdr_tree, tvb, offset, hf_zbncp_hdr_flags, ett_zbncp_hdr_flags, packet_flags, ENC_NA);
    offset += 1;

    /* check is ack */
    if (*hdr_flags & ZBNCP_HDR_FLAGS_ISACK_MASK)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "ACK");
    }

    /* crc 8 */
    proto_tree_add_item(ncp_ll_hdr_tree, hf_zbncp_hdr_crc8, tvb, offset++, 1, ENC_NA);

    return offset;
}

static guint
dissect_zbncp_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8 flags;
    guint16 cmd_id;

    conversation_t *conversation;
    gchar *zbncp_ctx_str;

    flags = 0;
    offset = dissect_zbncp_ll_hdr(tvb, pinfo, tree, offset, &flags);

    if (!offset)
    {
        return 0;
    }

    if (offset < tvb_reported_length(tvb))
    {
        if (ZBNCP_GET_PACKET_FLAGS_FIRST_FRAG_BIT(flags))
        {
            /* No fragmentation or first fragment */
            dissect_zbncp_body(tvb, pinfo, tree, offset, &cmd_id);

            /* First fragment */
            if (!ZBNCP_GET_PACKET_FLAGS_LAST_FRAG_BIT(flags))
            {
                const gchar *tmp = val_to_str_const(cmd_id, zbncp_hl_call_id, "Unknown Call ID");
                zbncp_ctx_str = wmem_alloc(wmem_file_scope(), 64);

                if(zbncp_ctx_str != NULL)
                {
                    memcpy(zbncp_ctx_str, tmp, strlen(tmp) + 1);

                    conversation = conversation_new(pinfo->num,  &pinfo->src, &pinfo->dst,
                        conversation_pt_to_conversation_type(pinfo->ptype),
                        pinfo->srcport, pinfo->destport, 0);

                    conversation_add_proto_data(conversation, zbncp_frame, (void *)zbncp_ctx_str);
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, ", first fragment");
            }
        }
        else /* It's fragmentation frame */
        {
            /* Fragmentation frame */
            dissect_zbncp_fragmentation_body(tvb, pinfo, tree, offset);

            conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                conversation_pt_to_conversation_type(pinfo->ptype),
                pinfo->srcport, pinfo->destport, 0);

            if (conversation != NULL)
            {
                zbncp_ctx_str = (gchar *) conversation_get_proto_data(conversation, zbncp_frame);

                if (zbncp_ctx_str != NULL)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", zbncp_ctx_str);
                    conversation_delete_proto_data(conversation, zbncp_frame);
                }
            }

            if (ZBNCP_GET_PACKET_FLAGS_LAST_FRAG_BIT(flags))
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", last fragment");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", fragment");
            }
        }
    }

    return tvb_captured_length(tvb);
}

/**
 * Dissector for ZBOSS NCP packet with an additional dump info.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_zbncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    tvbuff_t *new_tvb;
    new_tvb = dissect_zbncp_dump_info(tvb, pinfo, tree);

    dissect_zbncp_packet(new_tvb, pinfo, tree, 0);

    return tvb_captured_length(tvb);
}

/**
 * Proto ZBOSS Network Coprocessor product registration routine
 */
void proto_register_zbncp(void)
{
    /* NCP protocol headers */
    static hf_register_info hf_zbncp_phy[] = {
        {&hf_zbncp_hdr_sign,
         {"Signature", "zbncp.hdr.sign", FT_UINT16, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_packet_len,
         {"Packet length", "zbncp.hdr.plen", FT_UINT16, BASE_DEC, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_hdr_type,
         {"Packet type", "zbncp.hdr.ptype", FT_UINT8, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_hdr_flags,
         {"Packet flags", "zbncp.hdr.flags", FT_UINT8, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_hdr_flags_isack,
         {"isACK", "zbncp.hdr.flags.isack", FT_BOOLEAN, 8, NULL,
          ZBNCP_HDR_FLAGS_ISACK_MASK, NULL, HFILL}},

        {&hf_zbncp_hdr_flags_retrans,
         {"Should retransmit", "zbncp.hdr.flags.retrans", FT_BOOLEAN, 8, NULL,
          ZBNCP_HDR_FLAGS_RETRANS_MASK, NULL, HFILL}},

        {&hf_zbncp_hdr_flags_packetseq,
         {"Packet#", "zbncp.hdr.flags.packet_seq", FT_UINT8, BASE_DEC, NULL,
          ZBNCP_HDR_FLAGS_PKT_SEQ_MASK, NULL, HFILL}},

        {&hf_zbncp_hdr_flags_ackseq,
         {"ACK#", "zbncp.hdr.flags.ack_seq", FT_UINT8, BASE_DEC, NULL,
          ZBNCP_HDR_FLAGS_ACK_SEQ_MASK, NULL, HFILL}},

        {&hf_zbncp_hdr_flags_first_frag,
         {"First fragment", "zbncp.hdr.flags.first_frag", FT_BOOLEAN, 8, NULL,
          ZBNCP_HDR_FLAGS_ISFIRST_MASK, NULL, HFILL}},

        {&hf_zbncp_hdr_flags_last_frag,
         {"Last fragment", "zbncp.hdr.flags.last_frag", FT_BOOLEAN, 8, NULL,
          ZBNCP_HDR_FLAGS_ISLAST_MASK, NULL, HFILL}},

        {&hf_zbncp_hdr_crc8,
         {"CRC8", "zbncp.hdr.crc8", FT_UINT8, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_body_data_crc16,
         {"CRC16", "zbncp.data.crc16", FT_UINT16, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_version,
         {"Version", "zbncp.data.hl.vers", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_packet_type,
         {"Packet type", "zbncp.data.hl.ptype", FT_UINT8, BASE_HEX, VALS(zbncp_hl_type), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_call_id,
         {"Call/evt id", "zbncp.data.hl.id", FT_UINT16, BASE_HEX, VALS(zbncp_hl_call_id), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_tsn,
         {"TSN", "zbncp.data.hl.tsn", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_status_cat,
         {"Status category", "zbncp.data.hl.status_cat", FT_UINT8, BASE_HEX, VALS(zbncp_hl_status_cat), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_status,
         {"Status", "zbncp.data.hl.status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_status_generic,
         {"Status", "zbncp.data.hl.status", FT_UINT8, BASE_HEX, VALS(zbncp_hl_status_generic), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_status_mac,
         {"Status", "zbncp.data.hl.status", FT_UINT8, BASE_HEX, VALS(zb_mac_state), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_status_nwk,
         {"Status", "zbncp.data.hl.status", FT_UINT8, BASE_HEX, VALS(zb_nwk_state), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_hl_status_cbke,
         {"Status", "zbncp.data.hl.status", FT_UINT8, BASE_HEX, VALS(zb_cbke_state), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_fw_vers,
         {"FW Version", "zbncp.data.fw_vers", FT_UINT32, BASE_HEX, NULL, 0x0, "NCP module firmware version", HFILL}},

        {&hf_zbncp_data_stack_vers,
         {"Stack Version", "zbncp.data.stack_vers", FT_UINT32, BASE_HEX, NULL, 0x0, "NCP module stack version", HFILL}},

        {&hf_zbncp_data_proto_vers,
         {"Protocol Version", "zbncp.data.proto_vers", FT_UINT32, BASE_HEX, NULL, 0x0, "NCP module protocol version", HFILL}},

        {&hf_zbncp_data_reset_opt,
         {"Options", "zbncp.data.rst_opt", FT_UINT8, BASE_HEX, VALS(zbncp_reset_opt), 0x0, "Force NCP module reboot", HFILL}},

        {&hf_zbncp_data_zb_role,
         {"Zigbee role", "zbncp.data.zb_role", FT_UINT8, BASE_HEX, VALS(zbncp_zb_role), 0x0, "Zigbee role code", HFILL}},

        {&hf_zbncp_data_ch_list_len,
         {"Channel list length", "zbncp.data.ch_list_len", FT_UINT8, BASE_HEX, NULL, 0x0, "Number of entries in the following Channel List array", HFILL}},

        {&hf_zbncp_data_page,
         {"Channel page", "zbncp.data.page", FT_UINT8, BASE_DEC_HEX, VALS(zboss_page_names), 0x0,
          "IEEE802.15.4 page number", HFILL}},

        {&hf_zbncp_data_ch_mask,
         {"Channel mask", "zbncp.data.ch_mask", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_channel,
         {"Channel", "zbncp.data.mask", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Channel number", HFILL}},

        {&hf_zbncp_data_channel4,
         {"Channel", "zbncp.data.mask", FT_UINT32, BASE_DEC, NULL, 0x0,
          "Channel number", HFILL}},

        {&hf_zbncp_data_pan_id,
         {"PAN ID", "zbncp.data.pan_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_index,
         {"Index", "zbncp.data.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_enable,
         {"Enable", "zbncp.data.enable", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_bind_type,
         {"Bind Type", "zbncp.data.bind_type", FT_UINT8, BASE_DEC, VALS(zbncp_bind_type_vals), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_int_num,
         {"MAC Interface Num", "zbncp.data.mac_int_num", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_ext_pan_id,
         {"Ext PAN ID", "zbncp.data.ext_pan_id", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_coordinator_version,
         {"Coordinator version", "zbncp.data.coord_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_trust_center_addres,
         {"IEEE trust center address", "zbncp.data.ieee_trust_center_addr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_ieee_addr,
         {"IEEE address", "zbncp.data.ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_remote_ieee_addr,
         {"Remote IEEE address", "zbncp.data.rmt_ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_src_ieee_addr,
         {"Source IEEE address", "zbncp.data.src_ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dst_ieee_addr,
         {"Destination IEEE address", "zbncp.data.dst_ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_partner_ieee_addr,
         {"Partner IEEE address", "zbncp.data.partner_ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_keepalive,
         {"Keepalive Timeout", "zbncp.data.keepalive", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_force_route_record_sending,
         {"Force route record sending mode", "zbncp.data.force_route_rec_mode", FT_UINT8, BASE_DEC, VALS(zbncp_force_route_record_sending_modes), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_rx_on_idle,
         {"Rx On When Idle", "zbncp.data.rx_on_idle", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_res_tx_power,
         {"Resultant TX power", "zbncp.data.tx_power", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_req_tx_power,
         {"Required TX power", "zbncp.data.tx_power", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_joined,
         {"Joined", "zbncp.data.joined", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_joined_bit,
         {"Device is joined", "zbncp.data.device_is_joined", FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}},

        {&hf_zbncp_data_parent_bit,
         {"Parent is lost", "zbncp.data.parent_is_lost", FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}},

        {&hf_zbncp_data_authenticated,
         {"Authenticated", "zbncp.data.auth", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_timeout,
         {"Timeout", "zbncp.data.timeout", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_addr,
         {"NWK address", "zbncp.data.nwk_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_parent_addr,
         {"NWK parent address", "zbncp.data.nwk_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dst_nwk_addr,
         {"Destination NWK address", "zbncp.data.dst_nwk_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_src_nwk_addr,
         {"Source NWK address", "zbncp.data.src_nwk_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_remote_nwk_addr,
         {"Remote NWK address", "zbncp.data.rmt_nwk_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_group_nwk_addr,
         {"Group NWK address", "zbncp.data.group_nwk_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_src_mac_addr,
         {"Source MAC address", "zbncp.data.src_mac_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dst_mac_addr,
         {"Destination MAC address", "zbncp.data.dst_mac_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_key,
         {"NWK Key", "zbncp.data.nwk_key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_key_num,
         {"Key number", "zbncp.data.key_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_serial_num,
         {"Serial number", "zbncp.data.serial_num", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_size,
         {"Size", "zbncp.data.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_parameter_id,
         {"Parameter ID", "zbncp.data.param_id", FT_UINT8, BASE_DEC, VALS(zbncp_parameter_id_list), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_value8_dec,
         {"Value", "zbncp.data.value", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_value16_dec,
         {"Value", "zbncp.data.value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_ack_to_non_sleepy,
         {"Value (for non-sleepy dev)", "zbncp.data.non_sleepy_value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_ack_to_sleepy,
         {"Value (for sleepy dev)", "zbncp.data.sleepy_value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_min16,
         {"Min", "zbncp.data.min_value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_max16,
         {"Max", "zbncp.data.max_value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_default8_sign,
         {"Default", "zbncp.data.default_val", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_current8_sign,
         {"Current", "zbncp.data.current_val", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_is_concentrator,
         {"Is concentrator", "zbncp.data.is_conc", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_concentrator_radius,
         {"Concentrator radius", "zbncp.data.conc_rad", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_time16,
         {"Time", "zbncp.data.conc_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_lock_status,
         {"Locking status", "zbncp.data.lock_status", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_nwk_leave_allowed,
         {"NWK Leave Allowed", "zbncp.data.nwk_leave_allow", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nvram_dataset_quantity,
         {"Dataset quantity", "zbncp.data.nvram_dataset_quantity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nvram_dataset_type,
         {"NVRAM Database type", "zbncp.data.nvram_database_type", FT_UINT16, BASE_HEX, VALS(zb_nvram_database_types), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nvram_version,
         {"NVRAM Version", "zbncp.data.nvram_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dataset_version,
         {"NVRAM Dataset Version", "zbncp.data.dataset_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dataset_length,
         {"NVRAM Dataset size", "zbncp.data.dataset_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nvram_dataset_data,
         {"NVRAM Dataset data", "zbncp.data.dataset_data", FT_UINT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tc_policy_type,
         {"Trust center policy type", "zbncp.data.tc_policy_type", FT_UINT16, BASE_HEX, VALS(zbncp_tc_policy_types), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tc_policy_value,
         {"Trust center policy value", "zbncp.data.tc_policy_value", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_max_children,
         {"Number of children", "zbncp.data.num_children", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_leave_allowed,
         {"ZDO Leave Allowed", "zbncp.data.zdo_leave_allow", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_leave_wo_rejoin_allowed,
         {"ZDO Leave Without Rejoin Allowed", "zbncp.data.zdo_leave_wo_rejoin_allow", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_reset_source,
         {"Reset source", "zbncp.data.rst_src", FT_UINT8, BASE_DEC, VALS(zbncp_rst_src_list), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_vendor_data,
         {"Vendor data", "zbncp.data.vendor_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_aps_key,
         {"APS Key", "zbncp.data.aps_key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_endpoint,
         {"Endpoint", "zbncp.data.endpoint", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_group_num,
         {"APS group number", "zbncp.data.aps_group_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_group,
         {"APS group", "zbncp.data.aps_group", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_src_endpoint,
         {"Source Endpoint", "zbncp.data.src_endpoint", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dst_endpoint,
         {"Destination Endpoint", "zbncp.data.dst_endpoint", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_poll_pkt_cnt,
         {"Packet count", "zbncp.data.poll_pkt_cnt", FT_UINT8, BASE_DEC, NULL, 0x0, "The number of packets to poll", HFILL}},

        {&hf_zbncp_data_poll_timeout,
         {"Poll Timeout", "zbncp.data.poll_timeout", FT_UINT32, BASE_DEC, NULL, 0x0, "The duration of poll in ms", HFILL}},

        {&hf_zbncp_data_poll_permit_flag,
         {"Permit flag", "zbncp.data.poll_permit_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_profile_id,
         {"Profile ID", "zbncp.data.profile_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_device_id,
         {"Device ID", "zbncp.data.device_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dev_version,
         {"Device Version", "zbncp.data.dev_vers", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_in_cl_cnt,
         {"Input Cluster Count", "zbncp.data.in_cl_cnt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_out_cl_cnt,
         {"Output Cluster Count", "zbncp.data.out_cl_cnt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_cluster_id,
         {"Cluster ID", "zbncp.data.cluster_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_cap,
         {"MAC capability", "zbncp.data.mac_cap", FT_UINT8, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_data_manuf_id,
         {"Manufacturer ID", "zbncp.data.manuf_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_cur_pwr_mode,
         {"Current Power Mode", "zbncp.data.pwr_mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_cur_pwr_lvl,
         {"Current Power Level", "zbncp.data.pwr_lvl", FT_UINT8, BASE_DEC, VALS(zbncp_power_level), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_susp_period,
         {"Suspension Period", "zbncp.data.susp_period", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_av_pwr_src,
         {"Available Power Sources", "zbncp.data.av_pwr_src", FT_UINT8, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_data_cur_pwr_src,
         {"Current Power Source", "zbncp.data.cur_pwr_src", FT_UINT8, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_data_pwr_src_const,
         {"Constant (mains) power", "zbncp.data.pwr_src_const", FT_BOOLEAN, 8, NULL,
          0x01, NULL, HFILL}},

        {&hf_zbncp_data_pwr_src_recharge,
         {"Rechargeable battery", "zbncp.data.pwr_src_recharge", FT_BOOLEAN, 8, NULL,
          0x02, NULL, HFILL}},

        {&hf_zbncp_data_pwr_src_disposable,
         {"Disposable battery", "zbncp.data.pwr_src_disp", FT_BOOLEAN, 8, NULL,
          0x04, NULL, HFILL}},

        {&hf_zbncp_data_req_type,
         {"Request Type", "zbncp.data.nwk_req_type", FT_UINT8, BASE_DEC, VALS(zbncp_nwk_req_type), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_start_idx,
         {"Start Index", "zbncp.data.start_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_start_idx_16b,
         {"Start Index", "zbncp.data.start_idx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_upd_idx,
         {"Update Index", "zbncp.data.update_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_entry_idx,
         {"Entry Index", "zbncp.data.entry_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_num_asoc_dec,
         {"Num Assoc Dev", "zbncp.data.num_asoc_dev", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_pwr_desc,
         {"Power Descriptor", "zbncp.data.pwr_desc", FT_UINT16, BASE_HEX, NULL,
          0x0, NULL, HFILL}},

        {&hf_zbncp_data_pwr_desc_cur_power_mode,
         {"Current Power Mode", "zbncp.data.pwr_desc.pwr_mode", FT_UINT16, BASE_DEC, NULL,
          0x000F, NULL, HFILL}},

        {&hf_zbncp_data_pwr_desc_av_pwr_src,
         {"Available Power Sources", "zbncp.data.pwr_desc.av_pwr_src", FT_UINT16, BASE_DEC, NULL,
          0x00F0, NULL, HFILL}}, /* todo */

        {&hf_zbncp_data_pwr_desc_cur_pwr_src,
         {"Current Power Sources", "zbncp.data.pwr_desc.cur_pwr_src", FT_UINT16, BASE_DEC, NULL,
          0x0F00, NULL, HFILL}}, /* todo */

        {&hf_zbncp_data_pwr_desc_cur_pwr_lvl,
         {"Current Power Level", "zbncp.data.cur_pwr_lvl", FT_UINT16, BASE_DEC, VALS(zbncp_power_level),
          0xF000, NULL, HFILL}},

        {&hf_zbncp_data_max_buf_size,
         {"Max buffer size", "zbncp.data.max_buf_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_max_inc_trans_size,
         {"Max Incoming transfer size", "zbncp.data.max_inc_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_max_out_trans_size,
         {"Max Outgoing transfer size", "zbncp.data.max_out_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_desc_cap,
         {"Descriptor Capabilities", "zbncp.data.desc_cap", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_desc_cap_ext_act_ep_list_av,
         {"Extended Active Endpoint List Available", "zbncp.data.desc_cap.active_ep_list", FT_BOOLEAN, 8, NULL,
          0x1, NULL, HFILL}},

        {&hf_zbncp_data_desc_cap_ext_simple_desc_list_av,
         {"Extended Simple Descriptor List Available", "zbncp.data.desc_cap.simple_desc_list", FT_BOOLEAN, 8, NULL,
          0x2, NULL, HFILL}},

        {&hf_zbncp_data_flags8,
         {"Flags", "zbncp.data.flags8", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_flags_permit_join,
         {"Permit Joining", "zbncp.data.flags.perm_join", FT_BOOLEAN, 8, NULL,
          0x1, NULL, HFILL}},

        {&hf_zbncp_data_flags_router_cap,
         {"Router capacity", "zbncp.data.flags.router_cap", FT_BOOLEAN, 8, NULL,
          0x2, NULL, HFILL}},

        {&hf_zbncp_data_flags_ed_cap,
         {"ED capacity", "zbncp.data.flags.ed_cap", FT_BOOLEAN, 8, NULL,
          0x4, NULL, HFILL}},

        {&hf_zbncp_data_flags_stack_profile,
         {"Stack profile", "zbncp.data.flags.stack_profile", FT_UINT8, BASE_DEC, NULL,
          0xF0, NULL, HFILL}},

        {&hf_zbncp_data_flags16,
         {"Flags", "zbncp.data.flags16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_flags_zb_role,
         {"Zigbee role", "zbncp.data.flags.zb_role", FT_UINT16, BASE_HEX, VALS(zbncp_zb_role),
          0x7, NULL, HFILL}},

        {&hf_zbncp_data_flags_comp_desc_av,
         {"Complex desc available", "zbncp.data.flags.comp_desc_av", FT_BOOLEAN, 16, NULL,
          0x8, NULL, HFILL}},

        {&hf_zbncp_data_flags_user_desc_av,
         {"User desc available", "zbncp.data.flags.user_desc_av", FT_BOOLEAN, 16, NULL,
          0x10, NULL, HFILL}},

        {&hf_zbncp_data_flags_freq_868,
         {"868MHz BPSK Band", "zbncp.data.flags.freq.868mhz", FT_BOOLEAN, 16, NULL,
          0x800, NULL, HFILL}},

        {&hf_zbncp_data_flags_freq_902,
         {"902MHz BPSK Band", "zbncp.data.flags.freq.902mhz", FT_BOOLEAN, 16, NULL,
          0x2000, NULL, HFILL}},

        {&hf_zbncp_data_flags_freq_2400,
         {"2.4GHz OQPSK Band", "zbncp.data.flags.freq.2400mhz", FT_BOOLEAN, 16, NULL,
          0x4000, NULL, HFILL}},

        {&hf_zbncp_data_flags_freq_eu_sub_ghz,
         {"EU Sub-GHz FSK Band", "zbncp.data.flags.freq.eu_sub_ghz", FT_BOOLEAN, 16, NULL,
          0x8000, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk,
         {"Server mask", "zbncp.data.srv_msk", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_prim_tc,
         {"Primary Trust Center", "zbncp.data.srv_msk.prim_tc", FT_BOOLEAN, 16, NULL,
          0x1, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_backup_tc,
         {"Backup Trust Center", "zbncp.data.srv_msk.backup_tc", FT_BOOLEAN, 16, NULL,
          0x2, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_prim_bind_tbl_cache,
         {"Primary Binding Table Cache", "zbncp.data.srv_msk.prim_bind_tbl_cache", FT_BOOLEAN, 16, NULL,
          0x4, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_backup_bind_tbl_cache,
         {"Backup Binding Table Cache", "zbncp.data.srv_msk.backup_bind_tbl_cache", FT_BOOLEAN, 16, NULL,
          0x8, NULL, HFILL}},

        {&hf_zbncp_data_remote_bind_offset,
         {"Remote Bind Offset", "zbncp.data.remote_bind_access", FT_UINT8, BASE_HEX, NULL,
          0x0,
          "Remote bind offset, divides the bind table in two parts [0:remote_bind_offset) are for localbindings and "
          "[remote_bind_offset:tbl_size) to remote bindings",
          HFILL}},

        {&hf_zbncp_data_srv_msk_prim_disc_cache,
         {"Primary Discovery Cache", "zbncp.data.srv_msk.prim_disc_cache", FT_BOOLEAN, 16, NULL,
          0x10, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_backup_disc_cache,
         {"Backup Discovery Cache", "zbncp.data.srv_msk.backup_disc_cache", FT_BOOLEAN, 16, NULL,
          0x20, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_nwk_manager,
         {"Network Manager", "zbncp.data.srv_msk.nwk_manager", FT_BOOLEAN, 16, NULL,
          0x40, NULL, HFILL}},

        {&hf_zbncp_data_srv_msk_stack_compl_rev,
         {"Stack Compliance Revision", "zbncp.data.srv_msk.stack_compl_rev", FT_UINT16, BASE_DEC, NULL,
          0xFE00, NULL, HFILL}},

        {&hf_zbncp_data_ep_cnt,
         {"Endpoint Count", "zbncp.data.endpoint_cnt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dst_addr_mode,
         {"Dst Address Mode", "zbncp.data.dst_addr_mode", FT_UINT8, BASE_HEX, VALS(zbncp_aps_addr_modes), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_leave_flags,
         {"Leave flags", "zbncp.data.leave_flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_leave_flags_remove_chil,
         {"Remove children", "zbncp.data.leave_flags.remove_chil", FT_BOOLEAN, 8, NULL,
          0x40, NULL, HFILL}},

        {&hf_zbncp_data_leave_flags_rejoin,
         {"Rejoin", "zbncp.data.leave_flags.rejoin", FT_BOOLEAN, 8, NULL,
          0x80, NULL, HFILL}},

        {&hf_zbncp_data_permit_dur,
         {"Permit Duration", "zbncp.data.permit_dur", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tc_sign,
         {"TC Significance", "zbncp.data.tc_sign", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_secur_rejoin,
         {"Secure Rejoin", "zbncp.data.secure_rejoin", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_zdo_rejoin_flags,
         {"Flags", "zbncp.data.zdo_rejoin.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_zdo_rejoin_flags_tcsw_happened,
         {"Trust Center Swap-out happened", "zbncp.data.zdo_rejoin.flags.tcsw_happened", FT_BOOLEAN, 8, NULL,
          0x01, NULL, HFILL}},

        {&hf_zbncp_data_dlen8,
         {"Data Length", "zbncp.data.dlen8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dlen16,
         {"Data Length", "zbncp.data.dlen16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_param_len,
         {"Param Length", "zbncp.data.param_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_radius,
         {"Radius", "zbncp.data.radius", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_time_between_disc,
         {"Time between discoveries", "zbncp.data.time_between_disc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_enable_flag,
         {"Enable flag", "zbncp.data.enable_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "0 - to disable, 1 - to enable", HFILL}},

        {&hf_zbncp_data_array,
         {"Data", "zbncp.data.data_arr", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_use_alias,
         {"Use alias", "zbncp.data.use_alias", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_alias_src,
         {"Alias source address", "zbncp.data.alias_src", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_alias_seq,
         {"Alias sequence number", "zbncp.data.alias_seq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt,
         {"TX Options", "zbncp.data.tx_opt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_secur,
         {"Security enabled transmission", "zbncp.data.secur", FT_BOOLEAN, 8, NULL,
          0x01, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_obsolete,
         {"Obsolete", "zbncp.data.obsolete", FT_BOOLEAN, 8, NULL,
          0x02, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_ack,
         {"ACK", "zbncp.data.ack", FT_BOOLEAN, 8, NULL,
          0x04, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_frag,
         {"Fragmentation permitted", "zbncp.data.frag", FT_BOOLEAN, 8, NULL,
          0x08, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_inc_ext_nonce,
         {"Include extended nonce", "zbncp.data.ext_nonce", FT_BOOLEAN, 8, NULL,
          0x10, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_force_mesh_route,
         {"Force mesh route discovery for this request", "zbncp.data.force_mesh_route", FT_BOOLEAN, 8, NULL,
          0x20, NULL, HFILL}},

        {&hf_zbncp_data_tx_opt_send_route_record,
         {"Send route record for this request", "zbncp.data.send_route_record", FT_BOOLEAN, 8, NULL,
          0x40, NULL, HFILL}},

        {&hf_zbncp_data_lqi,
         {"LQI", "zbncp.data.lqi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_rssi,
         {"RSSI", "zbncp.data.rssi", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_do_cleanup,
         {"Do cleanup", "zbncp.data.do_clean", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_max_rx_bcast,
         {"max_rx_bcast", "zbncp.data.max_rx_bcast", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_bcast,
         {"max_tx_bcast", "zbncp.data.max_tx_bcast", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_rx_ucast,
         {"mac_rx_ucast", "zbncp.data.mac_rx_ucast", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_ucast_total_zcl,
         {"mac_tx_ucast_total_zcl", "zbncp.data.mac_tx_ucast_total_zcl", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_ucast_failures_zcl,
         {"mac_tx_ucast_failures_zcl", "zbncp.data.mac_tx_ucast_failures_zcl", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_ucast_retries_zcl,
         {"mac_tx_ucast_retries_zcl", "zbncp.data.mac_tx_ucast_retries_zcl", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_ucast_total,
         {"mac_tx_ucast_total", "zbncp.data.mac_tx_ucast_total", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_ucast_failures,
         {"mac_tx_ucast_failures", "zbncp.data.mac_tx_ucast_failures", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_tx_ucast_retries,
         {"mac_tx_ucast_retries", "zbncp.data.mac_tx_ucast_retries", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_validate_drop_cnt,
         {"mac_validate_drop_cnt", "zbncp.data.mac_validate_drop_cnt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_phy_cca_fail_count,
         {"phy_cca_fail_count", "zbncp.data.phy_cca_fail_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_phy_to_mac_que_lim_reached,
         {"phy_to_mac_que_lim_reached", "zbncp.data.phy_to_mac_que_lim_reached", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_period_of_time,
         {"period_of_time", "zbncp.data.period_of_time", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_last_msg_lqi,
         {"last_msg_lqi", "zbncp.data.last_msg_lqi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_last_msg_rssi,
         {"last_msg_rssi", "zbncp.data.last_msg_rssi", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_number_of_resets,
         {"number_of_resets", "zbncp.data.number_of_resets", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_tx_bcast,
         {"aps_tx_bcast", "zbncp.data.aps_tx_bcast", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_tx_ucast_success,
         {"aps_tx_ucast_success", "zbncp.data.aps_tx_ucast_success", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_tx_ucast_retry,
         {"aps_tx_ucast_retry", "zbncp.data.aps_tx_ucast_retry", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_tx_ucast_fail,
         {"aps_tx_ucast_fail", "zbncp.data.aps_tx_ucast_fail", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_route_disc_initiated,
         {"route_disc_initiated", "zbncp.data.route_disc_initiated", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_neighbor_added,
         {"nwk_neighbor_added", "zbncp.data.nwk_neighbor_added", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_neighbor_removed,
         {"nwk_neighbor_removed", "zbncp.data.nwk_neighbor_removed", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_neighbor_stale,
         {"nwk_neighbor_stale", "zbncp.data.nwk_neighbor_stale", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_upd_status_code,
         {"Device update status code", "zbncp.data.dev_upd_status_code", FT_UINT8, BASE_DEC, VALS(zbncp_dev_update_status_code), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_join_indication,
         {"join_indication", "zbncp.data.join_indication", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_childs_removed,
         {"childs_removed", "zbncp.data.childs_removed", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_fc_failure,
         {"nwk_fc_failure", "zbncp.data.nwk_fc_failure", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_unauthorized_key,
         {"aps_unauthorized_key", "zbncp.data.aps_unauthorized_key", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_decrypt_failure,
         {"nwk_decrypt_failure", "zbncp.data.nwk_decrypt_failure", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_decrypt_failure,
         {"aps_decrypt_failure", "zbncp.data.aps_decrypt_failure", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_packet_buffer_allocate_failures,
         {"packet_buffer_allocate_failures", "zbncp.data.packet_buffer_allocate_failures", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_average_mac_retry_per_aps_message_sent,
         {"average_mac_retry_per_aps_message_sent", "zbncp.data.avg_mac_retry", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_fc_failure,
         {"aps_fc_failure", "zbncp.data.aps_fc_failure", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_retry_overflow,
         {"nwk_retry_overflow", "zbncp.data.nwk_retry_overflow", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_bcast_table_full,
         {"nwk_bcast_table_full", "zbncp.data.nwk_bcast_table_full", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_status,
         {"status", "zbncp.data.status", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_auth_type,
         {"Authorization type", "zbncp.data.zdo_auth_type", FT_UINT8, BASE_DEC, VALS(zbncp_zdo_auth_types), 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_leg_auth_status_code,
         {"Status code", "zbncp.data.zdo_status_code", FT_UINT8, BASE_DEC, VALS(zbncp_zdo_leg_auth_status_codes), 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_tclk_auth_status_code,
         {"Status code", "zbncp.data.zdo_status_code", FT_UINT8, BASE_DEC, VALS(zbncp_zdo_tclk_auth_status_codes), 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_server_mask,
         {"Server mask", "zbncp.data.zdo_serv_mask", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_start_entry_idx,
         {"Start entry index", "zbncp.data.zdo_start_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_scan_duration,
         {"Scan duration", "zbncp.data.zdo_scan_duration", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_scan_cnt,
         {"Scan count", "zbncp.data.zdo_scan_cnt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_zdo_scan_mgr_addr,
         {"Manager NWK address", "zbncp.data.zdo_mgr_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_cnt,
         {"APS counter", "zbncp.data.aps_cnt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_fc,
         {"APS FC", "zbncp.data.aps_fc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_fc_deliv_mode,
         {"Delivery mode", "zbncp.data.aps_fc.deliv_mode", FT_UINT8, BASE_DEC, VALS(zbncp_deliv_mode),
          0x0C, NULL, HFILL}},

        {&hf_zbncp_data_aps_fc_secur,
         {"Security", "zbncp.data.aps_fc.secur", FT_BOOLEAN, 8, NULL,
          0x20, NULL, HFILL}},

        {&hf_zbncp_data_aps_fc_ack_retrans,
         {"ACK & retransmit", "zbncp.data.aps_fc.ack_retrans", FT_BOOLEAN, 8, NULL,
          0x40, NULL, HFILL}},

        {&hf_zbncp_data_aps_key_attr,
         {"APS key source & attr", "zbncp.data.aps_key_attr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_aps_key_attr_key_src,
         {"Key source", "zbncp.data.aps_key_attr.key_src", FT_UINT8, BASE_HEX, VALS(zbncp_aps_key_src),
          0x1, NULL, HFILL}},

        {&hf_zbncp_data_aps_key_attr_key_used,
         {"Key used", "zbncp.data.aps_key_attr.key_used", FT_UINT8, BASE_HEX, VALS(zbncp_aps_key_used),
          0x6, NULL, HFILL}},

        {&hf_zbncp_data_pkt_len,
         {"Packet length", "zbncp.data.pkt_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_pkt,
         {"Packet", "zbncp.data.pkt", FT_UINT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_scan_dur,
         {"Scan Duration", "zbncp.data.scan_dur", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_distr_nwk_flag,
         {"Distributed Network Flag", "zbncp.data.distr_nwk_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_count,
         {"Network Count", "zbncp.data.nwk_cnt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_nwk_upd_id,
         {"NWK Update ID", "zbncp.data.nwk_upd_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_rejoin,
         {"Rejoin", "zbncp.data.rejoin", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_rejoin_nwk,
         {"Rejoin Network", "zbncp.data.rejoin_nwk", FT_UINT8, BASE_DEC, VALS(zbncp_rejoin_nwk), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_secur_en,
         {"Security Enable", "zbncp.data.secur_en", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_enh_beacon,
         {"Enhanced Beacon", "zbncp.data.enh_beacon", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_beacon_type,
         {"Beacon Type", "zbncp.data.beacon_type", FT_UINT8, BASE_DEC, VALS(zbncp_beacon_type), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_beacon_order,
         {"Beacon Order", "zbncp.data.becon_order", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_superframe_order,
         {"Superframe Order", "zbncp.data.supeframe_order", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_battery_life_ext,
         {"Battery Life Extension", "zbncp.data.battery_life_ext", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_if,
         {"MAC interface #", "zbncp.data.mac_if", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_ed_config,
         {"ED config", "zbncp.data.ed_cfg", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_timeout_cnt,
         {"Timeout Counter", "zbncp.data.timeout_cnt", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_keepalive_mode,
         {"Keepalive mode", "zbncp.data.keepalive", FT_UINT8, BASE_DEC, VALS(zbncp_keepalive_mode), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_dev_timeout,
         {"Device Timeout", "zbncp.data.dev_timeout", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_relationship,
         {"Relationship", "zbncp.data.relationship", FT_UINT8, BASE_HEX, VALS(zbncp_relationship), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tx_fail_cnt,
         {"Transmit Failure Cnt", "zbncp.data.tx_fail_cnt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_out_cost,
         {"Outgoing Cost", "zbncp.data.out_cost", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_age,
         {"Age", "zbncp.data.age", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_trace_mask,
         {"Trace mask", "zbncp.data.trace_mask", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_trace_wireless_traf,
         {"Wireless traffic", "zbncp.data.trace_wireless_traf", FT_UINT32, BASE_DEC, NULL, 0x1, NULL, HFILL}},

        {&hf_zbncp_data_trace_reserved,
         {"Reserved", "zbncp.data.trace_reserved", FT_UINT32, BASE_DEC, NULL, 0x2, NULL, HFILL}},

        {&hf_zbncp_data_trace_ncp_ll_proto,
         {"NCP LL protocol", "zbncp.data.trace_ncp_ll_proto", FT_UINT32, BASE_DEC, NULL, 0x4, NULL, HFILL}},

        {&hf_zbncp_data_trace_host_int_line,
         {"HOST INT line", "zbncp.data.trace_host_int_line", FT_UINT32, BASE_DEC, NULL, 0x8, NULL, HFILL}},

        {&hf_zbncp_data_trace_sleep_awake,
         {"Sleep/awake", "zbncp.data.trace_sleep_awake", FT_UINT32, BASE_DEC, NULL, 0x10, NULL, HFILL}},

        {&hf_zbncp_data_keepalive_rec,
         {"Keepalive Received", "zbncp.data.keepalive_rec", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_mac_if_idx,
         {"MAC Interface Index", "zbncp.data.mac_if_idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_fast_poll_int,
         {"Fast Poll Interval", "zbncp.data.fast_poll", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_long_poll_int,
         {"Long Poll Interval", "zbncp.data.long_poll", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_fast_poll_flag,
         {"Fast Poll Flag", "zbncp.data.fast_poll_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_stop_fast_poll_result,
         {"Stop Fast Poll Result", "zbncp.data.stop_fast_poll_result", FT_UINT8, BASE_HEX, VALS(zbncp_stop_fast_poll_result), 0x0, NULL, HFILL}},

        {&hf_zbncp_data_time,
         {"Time", "zbncp.data.time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_pan_id_cnt,
         {"Pan ID count", "zbncp.data.pan_id_cnt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_ic,
         {"Install Code", "zbncp.data.ic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_ic_table_size,
         {"IC Table Size", "zbncp.data.table_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_ic_ent_cnt,
         {"Entry Count", "zbncp.data.entry_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_cs,
         {"Suite", "zbncp.data.cs", FT_UINT8, BASE_DEC, VALS(zbncp_cs), 0, NULL, HFILL}},

        {&hf_zbncp_data_ca_pub_key,
         {"CA Public Key", "zbncp.data.ca_pub_key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_ca_priv_key,
         {"Device Private Key", "zbncp.data.ca_priv_key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_cert,
         {"Certificate", "zbncp.data.cert", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_issuer,
         {"Issuer", "zbncp.data.issuer", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_ic_en,
         {"Enable IC", "zbncp.data.ic_en", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_key_type,
         {"Key type", "zbncp.data.key_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_data_tx_power,
         {"TX Power", "zbncp.data.tx_power", FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_tx_time,
         {"TX Time", "zbncp.data.tx_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_seed,
         {"Seed", "zbncp.data.seed", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_link_key,
         {"Link Key", "zbncp.data.link_key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_aps_link_key_type,
         {"APS Link Key Type", "zbncp.data.link_key_type", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_key_src,
         {"Key source", "zbncp.data.key_src", FT_UINT8, BASE_DEC, VALS(zbncp_key_src), 0, NULL, HFILL}},

        {&hf_zbncp_data_key_attr,
         {"Key attributes", "zbncp.data.key_attr", FT_UINT8, BASE_DEC, VALS(zbncp_key_attr), 0, NULL, HFILL}},

        {&hf_zbncp_data_out_frame_cnt,
         {"Outgoing frame counter", "zbncp.data.out_cnt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_inc_frame_cnt,
         {"Incoming frame counter", "zbncp.data.inc_cnt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_dump_type,
         {"Dump Type", "zbncp.data.dump_type", FT_UINT8, BASE_DEC, VALS(zbncp_dump_type), 0, NULL, HFILL}},

        {&hf_zbncp_data_dump_text,
         {"Dump", "zbncp.data.dump_text", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_dump_bin,
         {"Dump", "zbncp.data.dump_bin", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_offset,
         {"Offset", "zbncp.data.offset", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_do_erase,
         {"Do erase", "zbncp.data.do_erase", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_calibration_status,
         {"Calibration status", "zbncp.data.calibration_status", FT_UINT8, BASE_HEX, VALS(zbncp_calibration_status), 0, NULL, HFILL}},

        {&hf_zbncp_data_calibration_value,
         {"Calibration value", "zbncp.data.calibration_value", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_zgp_key_type,
         {"Key type", "zbncp.data.zgp_key_type", FT_UINT8, BASE_HEX, VALS(zbncp_zgp_key_types), 0, NULL, HFILL}},

        {&hf_zbncp_data_zgp_link_key,
         {"Link key", "zbncp.data.zgp_link_key", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_prod_conf_hdr_crc,
         {"Production confgi crc", "zbncp.data.prod_conf.hdr.crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_prod_conf_hdr_len,
         {"Length (with application section)", "zbncp.data.prod_conf.hdr.len", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_prod_conf_hdr_version,
         {"Version", "zbncp.data.prod_conf.hdr.version", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

        {&hf_zbncp_data_prod_conf_body,
         {"Production config body", "zbncp.data.prod_conf.body", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},

        /* ZBOSS NCP dump */
        {&hf_zbncp_dump_preambule,
         {"ZBNCP Dump preambule", "zbncp.dump.preambule", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zbncp_dump_version,
         {"ZBNCP Dump version", "zbncp.dump.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_zbncp_dump_type,
         {"Frame type", "zbncp.dump.ftype", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zbncp_dump_options,
         {"Options", "zbncp.dump.options", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zbncp_dump_options_dir,
         {"Direction", "zbncp.dump.options.direction", FT_BOOLEAN, 8, NULL, ZBNCP_DUMP_DIR_MASK,
          NULL, HFILL}},

        {&hf_zbncp_dump_options_int_state,
         {"HOST INT", "zbncp.dump.options.int_state", FT_BOOLEAN, 8, NULL, ZBNCP_DUMP_HOST_INT_DUMP_MASK,
          NULL, HFILL}},

        {&hf_zbncp_dump_options_tx_conflict,
         {"Potential TX/TX conflict", "zbncp.dump.options.tx_conflict", FT_BOOLEAN, 8, NULL, ZBNCP_DUMP_POTENTIAL_TX_RX_ERROR_MASK,
          NULL, HFILL}},

        /*  Capability Information Fields */

        {&hf_ieee802154_cinfo_alt_coord,
         {"Alternate PAN Coordinator", "zbncp.wpan.cinfo.alt_coord", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_ALT_PAN_COORD,
          "Whether this device can act as a PAN coordinator or not.", HFILL}},

        {&hf_ieee802154_cinfo_device_type,
         {"Device Type", "zbncp.wpan.cinfo.device_type", FT_BOOLEAN, 8, TFS(&tfs_cinfo_device_type), IEEE802154_CMD_CINFO_DEVICE_TYPE,
          "Whether this device is RFD (reduced-function device) or FFD (full-function device).", HFILL}},

        {&hf_ieee802154_cinfo_power_src,
         {"Power Source", "zbncp.wpan.cinfo.power_src", FT_BOOLEAN, 8, TFS(&tfs_cinfo_power_src), IEEE802154_CMD_CINFO_POWER_SRC,
          "Whether this device is operating on AC/mains or battery power.", HFILL}},

        {&hf_ieee802154_cinfo_idle_rx,
         {"Receive On When Idle", "zbncp.wpan.cinfo.idle_rx", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_IDLE_RX,
          "Whether this device can receive packets while idle or not.", HFILL}},

        {&hf_ieee802154_cinfo_sec_capable,
         {"Security Capability", "zbncp.wpan.cinfo.sec_capable", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_SEC_CAPABLE,
          "Whether this device is capable of receiving encrypted packets.", HFILL}},

        {&hf_ieee802154_cinfo_alloc_addr,
         {"Allocate Address", "zbncp.wpan.cinfo.alloc_addr", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_ALLOC_ADDR,
          "Whether this device wishes to use a 16-bit short address instead of its IEEE 802.15.4 64-bit long address.", HFILL}}};

    /* Protocol subtrees */
    static gint *ett[] =
        {
            &ett_zbncp_hdr,
            &ett_zbncp_hdr_flags,
            &ett_zbncp_ll_body,
            &ett_zbncp_hl_hdr,
            &ett_zbncp_hl_body,
            &ett_zbncp_data_in_cl_list,
            &ett_zbncp_data_out_cl_list,
            &ett_zbncp_data_mac_cap,
            &ett_zbncp_data_pwr_src,
            &ett_zbncp_data_cur_pwr_src,
            &ett_zbncp_data_asoc_nwk_list,
            &ett_zbncp_data_pwr_desc,
            &ett_zbncp_data_desc_cap,
            &ett_zbncp_data_flags,
            &ett_zbncp_data_server_mask,
            &ett_zbncp_data_ep_list,
            &ett_zbncp_data_leave_flags,
            &ett_zbncp_data_tx_opt,
            &ett_zbncp_data_zdo_rejoin_flags,
            &ett_zbncp_data_apc_fc,
            &ett_zbncp_data_prod_conf_hdr,
            &ett_zbncp_data_aps_key_attr,
            &ett_zbncp_data_ch_list,
            &ett_zbncp_data_channel,
            &ett_zbncp_data_nwk_descr,
            &ett_zbncp_data_cmd_opt,
            &ett_zbncp_data_joind_bitmask,
            &ett_zbncp_data_trace_bitmask,
            &ett_zbncp_dump,
            &ett_zbncp_dump_opt
        };

    zbncp_frame = proto_register_protocol("ZBOSS Network Coprocessor product", "ZB NCP",
                                          ZBNCP_PROTOABBREV);

    proto_register_field_array(zbncp_frame, hf_zbncp_phy, array_length(hf_zbncp_phy));
    proto_register_subtree_array(ett, array_length(ett));

    zbncp_handle = register_dissector("zbncp", dissect_zbncp, proto_zbncp);
} /* proto_register_zbncp */

void proto_reg_handoff_zbncp(void)
{
    zbncp_handle = create_dissector_handle(dissect_zbncp, zbncp_frame);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_ZBNCP, zbncp_handle);
}
