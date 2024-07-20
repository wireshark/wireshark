/* packet-zbee-zdp.h
 * Dissector routines for the ZigBee Device Profile (ZDP)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ZBEE_ZDP_H
#define PACKET_ZBEE_ZDP_H

/* The Profile ID for the ZigBee Device Profile. */
#define ZBEE_ZDP_PROFILE                          0x0000

/* ZDP Cluster Identifiers. */
#define ZBEE_ZDP_REQ_NWK_ADDR                     0x0000
#define ZBEE_ZDP_REQ_IEEE_ADDR                    0x0001
#define ZBEE_ZDP_REQ_NODE_DESC                    0x0002
#define ZBEE_ZDP_REQ_POWER_DESC                   0x0003
#define ZBEE_ZDP_REQ_SIMPLE_DESC                  0x0004
#define ZBEE_ZDP_REQ_ACTIVE_EP                    0x0005
#define ZBEE_ZDP_REQ_MATCH_DESC                   0x0006
#define ZBEE_ZDP_REQ_COMPLEX_DESC                 0x0010
#define ZBEE_ZDP_REQ_USER_DESC                    0x0011
#define ZBEE_ZDP_REQ_DISCOVERY_CACHE              0x0012
#define ZBEE_ZDP_REQ_DEVICE_ANNCE                 0x0013
#define ZBEE_ZDP_REQ_SET_USER_DESC                0x0014
#define ZBEE_ZDP_REQ_SYSTEM_SERVER_DISC           0x0015  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_STORE_DISCOVERY              0x0016  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_STORE_NODE_DESC              0x0017  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_STORE_POWER_DESC             0x0018  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_STORE_ACTIVE_EP              0x0019  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_STORE_SIMPLE_DESC            0x001a  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_REMOVE_NODE_CACHE            0x001b  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_FIND_NODE_CACHE              0x001c  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_EXT_SIMPLE_DESC              0x001d  /* ZigBee 2007 & later. */
#define ZBEE_ZDP_REQ_EXT_ACTIVE_EP                0x001e  /* ZigBee 2007 & later. */
#define ZBEE_ZDP_REQ_PARENT_ANNCE                 0x001f  /* r21 */
#define ZBEE_ZDP_REQ_END_DEVICE_BIND              0x0020
#define ZBEE_ZDP_REQ_BIND                         0x0021
#define ZBEE_ZDP_REQ_UNBIND                       0x0022
#define ZBEE_ZDP_REQ_BIND_REGISTER                0x0023  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_REPLACE_DEVICE               0x0024  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_STORE_BAK_BIND_ENTRY         0x0025  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_REMOVE_BAK_BIND_ENTRY        0x0026  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_BACKUP_BIND_TABLE            0x0027  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_RECOVER_BIND_TABLE           0x0028  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_BACKUP_SOURCE_BIND           0x0029  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_RECOVER_SOURCE_BIND          0x002a  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_CLEAR_ALL_BINDINGS           0x002b  /* R23 */
#define ZBEE_ZDP_REQ_MGMT_NWK_DISC                0x0030
#define ZBEE_ZDP_REQ_MGMT_LQI                     0x0031
#define ZBEE_ZDP_REQ_MGMT_RTG                     0x0032
#define ZBEE_ZDP_REQ_MGMT_BIND                    0x0033
#define ZBEE_ZDP_REQ_MGMT_LEAVE                   0x0034
#define ZBEE_ZDP_REQ_MGMT_DIRECT_JOIN             0x0035
#define ZBEE_ZDP_REQ_MGMT_PERMIT_JOIN             0x0036  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_MGMT_CACHE                   0x0037  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_REQ_MGMT_NWKUPDATE               0x0038  /* ZigBee 2007 & later. */
#define ZBEE_ZDP_REQ_MGMT_NWKUPDATE_ENH           0x0039  /* R22 */
#define ZBEE_ZDP_REQ_MGMT_IEEE_JOIN_LIST          0x003a  /* R22 */
#define ZBEE_ZDP_REQ_MGMT_NWK_BEACON_SURVEY       0x003c
#define ZBEE_ZDP_REQ_SECURITY_START_KEY_NEGOTIATION  0x0040  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_GET_AUTH_TOKEN      0x0041  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_GET_AUTH_LEVEL      0x0042  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_SET_CONFIGURATION   0x0043  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_GET_CONFIGURATION   0x0044  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_START_KEY_UPDATE    0x0045  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_DECOMMISSION        0x0046  /* R23 */
#define ZBEE_ZDP_REQ_SECURITY_CHALLENGE           0x0047  /* R23 */

#define ZBEE_ZDP_RSP_NWK_ADDR                     0x8000
#define ZBEE_ZDP_RSP_IEEE_ADDR                    0x8001
#define ZBEE_ZDP_RSP_NODE_DESC                    0x8002
#define ZBEE_ZDP_RSP_POWER_DESC                   0x8003
#define ZBEE_ZDP_RSP_SIMPLE_DESC                  0x8004
#define ZBEE_ZDP_RSP_ACTIVE_EP                    0x8005
#define ZBEE_ZDP_RSP_MATCH_DESC                   0x8006
#define ZBEE_ZDP_RSP_COMPLEX_DESC                 0x8010
#define ZBEE_ZDP_RSP_USER_DESC                    0x8011
#define ZBEE_ZDP_RSP_DISCOVERY_CACHE              0x8012
#define ZBEE_ZDP_RSP_CONF_USER_DESC               0x8014  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_SYSTEM_SERVER_DISC           0x8015  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_STORE_DISCOVERY              0x8016  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_STORE_NODE_DESC              0x8017  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_STORE_POWER_DESC             0x8018  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_STORE_ACTIVE_EP              0x8019  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_STORE_SIMPLE_DESC            0x801a  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_REMOVE_NODE_CACHE            0x801b  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_FIND_NODE_CACHE              0x801c  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_EXT_SIMPLE_DESC              0x801d  /* ZigBee 2007 & later. */
#define ZBEE_ZDP_RSP_EXT_ACTIVE_EP                0x801e  /* ZigBee 2007 & later. */
#define ZBEE_ZDP_RSP_PARENT_ANNCE                 0x801f  /* r21 */
#define ZBEE_ZDP_RSP_END_DEVICE_BIND              0x8020
#define ZBEE_ZDP_RSP_BIND                         0x8021
#define ZBEE_ZDP_RSP_UNBIND                       0x8022
#define ZBEE_ZDP_RSP_BIND_REGISTER                0x8023  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_REPLACE_DEVICE               0x8024  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_STORE_BAK_BIND_ENTRY         0x8025  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_REMOVE_BAK_BIND_ENTRY        0x8026  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_BACKUP_BIND_TABLE            0x8027  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_RECOVER_BIND_TABLE           0x8028  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_BACKUP_SOURCE_BIND           0x8029  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_RECOVER_SOURCE_BIND          0x802a  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_CLEAR_ALL_BINDINGS           0x802b  /* R23 */
#define ZBEE_ZDP_RSP_MGMT_NWK_DISC                0x8030
#define ZBEE_ZDP_RSP_MGMT_LQI                     0x8031
#define ZBEE_ZDP_RSP_MGMT_RTG                     0x8032
#define ZBEE_ZDP_RSP_MGMT_BIND                    0x8033
#define ZBEE_ZDP_RSP_MGMT_LEAVE                   0x8034
#define ZBEE_ZDP_RSP_MGMT_DIRECT_JOIN             0x8035
#define ZBEE_ZDP_RSP_MGMT_PERMIT_JOIN             0x8036  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_RSP_MGMT_CACHE                   0x8037  /* ZigBee 2006 & later. */
#define ZBEE_ZDP_NOT_MGMT_NWKUPDATE               0x8038  /* ZigBee 2007 & later. */
#define ZBEE_ZDP_NOT_MGMT_NWKUPDATE_ENH           0x8039  /* R22 */
#define ZBEE_ZDP_RSP_MGMT_IEEE_JOIN_LIST          0x803a  /* R22 */
#define ZBEE_ZDP_NOT_MGMT_UNSOLICITED_NWKUPDATE   0x803b  /* R22 */
#define ZBEE_ZDP_RSP_MGMT_NWK_BEACON_SURVEY       0x803c
#define ZBEE_ZDP_RSP_SECURITY_START_KEY_NEGOTIATION  0x8040  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_GET_AUTH_TOKEN      0x8041  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_GET_AUTH_LEVEL      0x8042  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_SET_CONFIGURATION   0x8043  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_GET_CONFIGURATION   0x8044  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_START_KEY_UPDATE    0x8045  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_DECOMMISSION        0x8046  /* R23 */
#define ZBEE_ZDP_RSP_SECURITY_CHALLENGE           0x8047  /* R23 */

#define ZBEE_ZDP_MSG_RESPONSE_BIT                 0x8000
#define ZBEE_ZDP_MSG_MASK                         (ZBEE_ZDP_MSG_RESPONSE_BIT-1)
#define ZBEE_ZDP_MSG_RESPONSE_BIT_2003            0x0080
#define ZBEE_ZDP_MSG_MASK_2003                    (ZBEE_ZDP_MSG_RESPONSE_BIT_2003-1)

#define ZBEE_ZDP_STATUS_SUCCESS                     0x00
#define ZBEE_ZDP_STATUS_INV_REQUESTTYPE             0x80
#define ZBEE_ZDP_STATUS_DEVICE_NOT_FOUND            0x81
#define ZBEE_ZDP_STATUS_INVALID_EP                  0x82
#define ZBEE_ZDP_STATUS_NOT_ACTIVE                  0x83
#define ZBEE_ZDP_STATUS_NOT_SUPPORTED               0x84
#define ZBEE_ZDP_STATUS_TIMEOUT                     0x85
#define ZBEE_ZDP_STATUS_NO_MATCH                    0x86
#define ZBEE_ZDP_STATUS_NO_ENTRY                    0x88
#define ZBEE_ZDP_STATUS_NO_DESCRIPTOR               0x89
#define ZBEE_ZDP_STATUS_INSUFFICIENT_SPACE          0x8a
#define ZBEE_ZDP_STATUS_NOT_PERMITTED               0x8b
#define ZBEE_ZDP_STATUS_TABLE_FULL                  0x8c
#define ZBEE_ZDP_STATUS_NOT_AUTHORIZED              0x8d
#define ZBEE_ZDP_STATUS_DEVICE_BINDING_TABLE_FULL   0x8e
#define ZBEE_ZDP_STATUS_INVALID_INDEX               0x8f
#define ZBEE_ZDP_STATUS_RESPONSE_TOO_LARGE          0x90
#define ZBEE_ZDP_STATUS_MISSING_TLV                 0x91

#define ZBEE_ZDP_REQ_TYPE_SINGLE                    0x00
#define ZBEE_ZDP_REQ_TYPE_EXTENDED                  0x01

#define ZBEE_ZDP_NODE_TYPE                        0x0007
#define ZBEE_ZDP_NODE_TYPE_COORD                  0x0000
#define ZBEE_ZDP_NODE_TYPE_FFD                    0x0001
#define ZBEE_ZDP_NODE_TYPE_RFD                    0x0002
#define ZBEE_ZDP_NODE_COMPLEX                     0x0008
#define ZBEE_ZDP_NODE_USER                        0x0010
#define ZBEE_ZDP_NODE_FRAG_SUPPORT                0x0020
#define ZBEE_ZDP_NODE_APS                         0x0700
#define ZBEE_ZDP_NODE_FREQ                        0xf800
#define ZBEE_ZDP_NODE_FREQ_868MHZ                 0x0800
#define ZBEE_ZDP_NODE_FREQ_900MHZ                 0x2000
#define ZBEE_ZDP_NODE_FREQ_2400MHZ                0x4000
#define ZBEE_ZDP_NODE_FREQ_EU_SUB_GHZ             0x8000

#define ZBEE_ZDP_NODE_SERVER_PRIMARY_TRUST        0x0001
#define ZBEE_ZDP_NODE_SERVER_BACKUP_TRUST         0x0002
#define ZBEE_ZDP_NODE_SERVER_PRIMARY_BIND         0x0004
#define ZBEE_ZDP_NODE_SERVER_BACKUP_BIND          0x0008
#define ZBEE_ZDP_NODE_SERVER_PRIMARY_DISC         0x0010
#define ZBEE_ZDP_NODE_SERVER_BACKUP_DISC          0x0020
#define ZBEE_ZDP_NODE_SERVER_NETWORK_MANAGER      0x0040
#define ZBEE_ZDP_NODE_SERVER_STACK_COMPL_REV      0xfe00

#define ZBEE_ZDP_POWER_MODE                       0x000f
#define ZBEE_ZDP_POWER_MODE_RX_ON                 0x0000
#define ZBEE_ZDP_POWER_MODE_RX_PERIODIC           0x0001
#define ZBEE_ZDP_POWER_MODE_RX_STIMULATE          0x0002
#define ZBEE_ZDP_POWER_AVAIL                      0x00f0
#define ZBEE_ZDP_POWER_AVAIL_AC                   0x0010
#define ZBEE_ZDP_POWER_AVAIL_RECHARGEABLE         0x0020
#define ZBEE_ZDP_POWER_AVAIL_DISPOSABLE           0x0040
#define ZBEE_ZDP_POWER_SOURCE                     0x0f00
#define ZBEE_ZDP_POWER_SOURCE_AC                  0x0100
#define ZBEE_ZDP_POWER_SOURCE_RECHARGEABLE        0x0200
#define ZBEE_ZDP_POWER_SOURCE_DISPOSABLE          0x0400
#define ZBEE_ZDP_POWER_LEVEL                      0xf000
#define ZBEE_ZDP_POWER_LEVEL_FULL                 0xc000
#define ZBEE_ZDP_POWER_LEVEL_OK                   0x8000
#define ZBEE_ZDP_POWER_LEVEL_LOW                  0x4000
#define ZBEE_ZDP_POWER_LEVEL_CRITICAL             0x0000

#define ZBEE_ZDP_ADDR_MODE_GROUP                    0x01
#define ZBEE_ZDP_ADDR_MODE_UNICAST                  0x03

#define ZBEE_ZDP_MGMT_LEAVE_CHILDREN                0x40
#define ZBEE_ZDP_MGMT_LEAVE_REJOIN                  0x80

#define ZBEE_ZDP_PERM_JOIN_FC_TLV_UPDATE            0x1

#define ZBEE_ZDP_NWKUPDATE_SCAN_MAX                 0x05
#define ZBEE_ZDP_NWKUPDATE_CHANNEL_HOP              0xfe
#define ZBEE_ZDP_NWKUPDATE_PARAMETERS               0xff

#define ZBEE_ZDP_NWKUPDATE_PAGE               0xF8000000
#define ZBEE_ZDP_NWKUPDATE_CHANNEL            0x07FFFFFF

#define ZBEE_ZDP_DCF_EAELA                          0x01
#define ZBEE_ZDP_DCF_ESDLA                          0x02



/**************************************
 * Field Indicies
 **************************************
 */
/* General indicies. */
extern int hf_zbee_zdp_ext_addr;
extern int hf_zbee_zdp_nwk_addr;
extern int hf_zbee_zdp_req_type;
extern int hf_zbee_zdp_index;
extern int hf_zbee_zdp_ep_count;
extern int hf_zbee_zdp_endpoint;
extern int hf_zbee_zdp_profile;
extern int hf_zbee_zdp_cluster;
extern int hf_zbee_zdp_addr_mode;
extern int hf_zbee_zdp_in_count;
extern int hf_zbee_zdp_out_count;
extern int hf_zbee_zdp_in_cluster;
extern int hf_zbee_zdp_out_cluster;
extern int hf_zbee_zdp_table_size;
extern int hf_zbee_zdp_table_count;
extern int hf_zbee_zdp_assoc_device_count;
extern int hf_zbee_zdp_assoc_device;
extern int hf_zbee_zdp_cache_address;

/* Discovery indicies. */
extern int hf_zbee_zdp_cache;
extern int hf_zbee_zdp_disc_node_size;
extern int hf_zbee_zdp_disc_power_size;
extern int hf_zbee_zdp_disc_ep_count;
extern int hf_zbee_zdp_disc_simple_count;
extern int hf_zbee_zdp_disc_simple_size;

/* Descriptor indicies. */
extern int hf_zbee_zdp_complex_length;
extern int hf_zbee_zdp_user;
extern int hf_zbee_zdp_user_length;
extern int hf_zbee_zdp_simple_length;

/* Binding indicies. */
extern int hf_zbee_zdp_target;
extern int hf_zbee_zdp_replacement;
extern int hf_zbee_zdp_replacement_ep;
extern int hf_zbee_zdp_bind_src;
extern int hf_zbee_zdp_bind_src64;
extern int hf_zbee_zdp_bind_src_ep;
extern int hf_zbee_zdp_bind_dst;
extern int hf_zbee_zdp_bind_dst64;
extern int hf_zbee_zdp_bind_dst_ep;

/* Network Management indicies. */
extern int hf_zbee_zdp_duration;
extern int hf_zbee_zdp_leave_children;
extern int hf_zbee_zdp_leave_rejoin;
extern int hf_zbee_zdp_significance;
extern int hf_zbee_zdp_scan_count;
extern int hf_zbee_zdp_update_id;
extern int hf_zbee_zdp_manager;
extern int hf_zbee_zdp_tx_total;
extern int hf_zbee_zdp_tx_fail;
extern int hf_zbee_zdp_tx_retries;
extern int hf_zbee_zdp_period_time_results;
extern int hf_zbee_zdp_channel_count;
extern int hf_zbee_zdp_channel_mask;
extern int hf_zbee_zdp_channel_page;
extern int hf_zbee_zdp_channel_page_count;
extern int hf_zbee_zdp_channel_energy;
extern int hf_zbee_zdp_pan_eui64;
extern int hf_zbee_zdp_pan_uint;
extern int hf_zbee_zdp_channel;
extern int hf_zbee_zdp_nwk_desc_profile;
extern int hf_zbee_zdp_profile_version;
extern int hf_zbee_zdp_beacon;
extern int hf_zbee_zdp_superframe;
extern int hf_zbee_zdp_permit_joining;
extern int hf_zbee_zdp_extended_pan;
extern int hf_zbee_zdp_addr;
extern int hf_zbee_zdp_table_entry_type;
extern int hf_zbee_zdp_table_entry_idle_rx_0c;
extern int hf_zbee_zdp_table_entry_relationship_70;
extern int hf_zbee_zdp_table_entry_idle_rx_04;
extern int hf_zbee_zdp_table_entry_relationship_18;
extern int hf_zbee_zdp_depth;
extern int hf_zbee_zdp_permit_joining_03;
extern int hf_zbee_zdp_lqi;
extern int hf_zbee_zdp_ieee_join_start_index;
extern int hf_zbee_zdp_ieee_join_status;
extern int hf_zbee_zdp_ieee_join_update_id;
extern int hf_zbee_zdp_ieee_join_policy;
extern int hf_zbee_zdp_ieee_join_list_total;
extern int hf_zbee_zdp_ieee_join_list_start;
extern int hf_zbee_zdp_ieee_join_list_count;
extern int hf_zbee_zdp_ieee_join_list_ieee;
extern int hf_zbee_zdp_number_of_children;
extern int hf_zbee_zdp_tlv_count;
extern int hf_zbee_zdp_tlv_id;

/* Routing Table */
extern int hf_zbee_zdp_rtg;
extern int hf_zbee_zdp_rtg_entry;
extern int hf_zbee_zdp_rtg_destination;
extern int hf_zbee_zdp_rtg_next_hop;
extern int hf_zbee_zdp_rtg_status;

extern int hf_zbee_zdp_beacon_survey_scan_mask_cnt;
extern int hf_zbee_zdp_beacon_survey_scan_mask;
extern int hf_zbee_zdp_beacon_survey_conf_mask;
extern int hf_zbee_zdp_beacon_survey_total;
extern int hf_zbee_zdp_beacon_survey_cur_zbn;
extern int hf_zbee_zdp_beacon_survey_cur_zbn_potent_parents;
extern int hf_zbee_zdp_beacon_survey_other_zbn;
extern int hf_zbee_zdp_beacon_survey_current_parent;
extern int hf_zbee_zdp_beacon_survey_cnt_parents;
extern int hf_zbee_zdp_beacon_survey_potent_parent;
extern int hf_zbee_zdp_beacon_survey_parent;

/* Subtree indicies. */
extern int ett_zbee_zdp_endpoint;
extern int ett_zbee_zdp_match_in;
extern int ett_zbee_zdp_match_out;
extern int ett_zbee_zdp_node;
extern int ett_zbee_zdp_power;
extern int ett_zbee_zdp_simple;
extern int ett_zbee_zdp_cinfo;
extern int ett_zbee_zdp_server;
extern int ett_zbee_zdp_simple_sizes;
extern int ett_zbee_zdp_bind;
extern int ett_zbee_zdp_bind_entry;
extern int ett_zbee_zdp_bind_end_in;
extern int ett_zbee_zdp_bind_end_out;
extern int ett_zbee_zdp_bind_source;
extern int ett_zbee_zdp_assoc_device;
extern int ett_zbee_zdp_nwk;
extern int ett_zbee_zdp_lqi;
extern int ett_zbee_zdp_rtg;
extern int ett_zbee_zdp_cache;
extern int ett_zbee_zdp_nwk_desc;
extern int ett_zbee_zdp_table_entry;
extern int ett_zbee_zdp_perm_join_fc;
/**************************************
 * Helper Functions
 **************************************
 */
extern const char   *zdp_status_name       (uint8_t status);
extern void     zdp_dump_excess            (tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree);
extern uint64_t zbee_parse_eui64           (proto_tree *tree, int hfindex, tvbuff_t *tvb, unsigned *offset, unsigned length, proto_item **ti);
extern void     zbee_append_info           (proto_item *item, packet_info *pinfo, const char *format, ...) G_GNUC_PRINTF(3, 4);

extern void     zdp_parse_node_desc        (proto_tree *tree, packet_info *pinfo, bool show_ver_flags, int ettindex, tvbuff_t *tvb, unsigned *offset, uint8_t version);
extern void     zdp_parse_power_desc       (proto_tree *tree, int ettindex, tvbuff_t *tvb, unsigned *offset);
extern void     zdp_parse_simple_desc      (proto_tree *tree, int ettindex, tvbuff_t *tvb, unsigned *offset, uint8_t version);
extern void     zdp_parse_complex_desc     (packet_info *pinfo, proto_tree *tree, int ettindex, tvbuff_t *tvb, unsigned *offset, unsigned length);
extern void     zdp_parse_bind_table_entry (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint8_t version);

extern uint8_t  zdp_parse_status           (proto_tree *tree, tvbuff_t *tvb, unsigned *offset);
extern unsigned zdp_parse_set_configuration_response(proto_tree *tree, tvbuff_t *tvb, unsigned offset);
extern uint32_t zdp_parse_chanmask         (proto_tree *tree, tvbuff_t *tvb, unsigned *offset, int hf_page, int hf_channel);
extern uint8_t  zdp_parse_cinfo            (proto_tree *tree, int ettindex, tvbuff_t *tvb, unsigned *offset);
extern uint16_t zdp_parse_server_flags     (proto_tree *tree, int ettindex, tvbuff_t *tvb, unsigned *offset);

/* Message dissector routines. */
extern void dissect_zbee_zdp_req_nwk_addr               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_ext_addr               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_node_desc              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_power_desc             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_simple_desc            (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_active_ep              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_match_desc             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_complex_desc           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_user_desc              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_discovery_cache        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_device_annce               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_parent_annce               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_parent_annce           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_set_user_desc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_system_server_disc     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_discovery        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_node_desc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_store_power_desc       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_active_ep        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_simple_desc      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_remove_node_cache      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_find_node_cache        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_ext_simple_desc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_ext_active_ep          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_req_end_device_bind        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_bind                   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_unbind                 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_bind_register          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_replace_device         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_bak_bind_entry   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_remove_bak_bind_entry  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_backup_bind_table      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_recover_bind_table     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_backup_source_bind     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_recover_source_bind    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_req_mgmt_nwk_disc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hf_channel);
extern void dissect_zbee_zdp_req_mgmt_lqi               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_rtg               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_bind              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_leave             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_req_mgmt_direct_join       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_permit_join       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_cache             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_nwkupdate         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_nwkupdate_enh     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_ieee_join_list    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_nwk_beacon_survey (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_start_key_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_get_auth_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_get_auth_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_set_configuration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_get_configuration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_start_key_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_decommission  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_security_challenge     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_rsp_nwk_addr               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_ext_addr               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_node_desc              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_power_desc             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_simple_desc            (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_active_ep              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_match_desc             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_complex_desc           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_user_desc              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_user_desc_conf         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_discovery_cache        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_system_server_disc     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_discovery_store        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_node_desc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_power_desc       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_active_ep        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_simple_desc      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_remove_node_cache      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_find_node_cache        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_ext_simple_desc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_ext_active_ep          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_req_clear_all_bindings     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_end_device_bind        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_bind                   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_unbind                 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_bind_register          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_replace_device         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_bak_bind_entry   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_remove_bak_bind_entry  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_backup_bind_table      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_recover_bind_table     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_backup_source_bind     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_recover_source_bind    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_clear_all_bindings     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_rsp_mgmt_nwk_disc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_mgmt_lqi               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_mgmt_rtg               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_bind              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t version);
extern void dissect_zbee_zdp_rsp_mgmt_leave             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_direct_join       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_permit_join       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_cache             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_not_mgmt_nwkupdate         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_ieee_join_list    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_not_mgmt_unsolicited_nwkupdate    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_nwk_beacon_survey (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_start_key_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_get_auth_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_get_auth_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_set_configuration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_get_configuration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_start_key_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_decommission(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_security_challenge     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern const value_string zbee_zdp_cluster_names[];
extern const value_string zbee_zdp_rtg_status_vals[];

#endif /* PACKET_ZBEE_ZDP_H */

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
