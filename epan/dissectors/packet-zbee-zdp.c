/* packet-zbee-zdp.c
 * Dissector routines for the ZigBee Device Profile (ZDP)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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

/*  Include Files */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <glib.h>
#include <gmodule.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-zbee.h"
#include "packet-zbee-zdp.h"

/*************************/
/* Function Declarations */
/*************************/
/* Local Helper routines. */
static guint16 zdp_convert_2003cluster     (guint8 cluster);

/* Message dissector routines. */
extern void dissect_zbee_zdp_req_nwk_addr           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_ext_addr           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_node_desc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_power_desc         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_simple_desc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_active_ep          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_match_desc         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_complex_desc       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_user_desc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_discovery_cache    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_device_annce           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_set_user_desc      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_system_server_disc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_discovery    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_node_desc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_power_desc   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_active_ep    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_simple_desc  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_remove_node_cache  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_find_node_cache    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_ext_simple_desc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_ext_active_ep      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_req_end_device_bind    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_bind               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_unbind             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_bind_register      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_replace_device     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_store_bak_bind_entry   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_remove_bak_bind_entry  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_backup_bind_table  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_recover_bind_table (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_backup_source_bind (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_recover_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_req_mgmt_nwk_disc      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_lqi           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_rtg           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_bind          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_leave         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_direct_join   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_permit_join   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_cache         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_req_mgmt_nwkupdate     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_rsp_nwk_addr           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_ext_addr           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_node_desc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_power_desc         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_simple_desc        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_active_ep          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_match_desc         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_complex_desc       (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_user_desc          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_user_desc_conf     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_discovery_cache    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_system_server_disc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_discovery_store    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_node_desc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_power_desc   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_active_ep    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_simple_desc  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_remove_node_cache  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_find_node_cache    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_ext_simple_desc    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_ext_active_ep      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_rsp_end_device_bind    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_bind               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_unbind             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_bind_register      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_replace_device     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_store_bak_bind_entry   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_remove_bak_bind_entry  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_backup_bind_table  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_recover_bind_table (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_backup_source_bind (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_recover_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern void dissect_zbee_zdp_rsp_mgmt_nwk_disc      (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_lqi           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_rtg           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_bind          (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_leave         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_direct_join   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_permit_join   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_cache         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_zbee_zdp_rsp_mgmt_nwkupdate     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**************************************
 * Field Indicies
 **************************************
 */
/* Global field indicies. */
int proto_zbee_zdp = -1;
int hf_zbee_zdp_seqno = -1;
int hf_zbee_zdp_length = -1; /* Deprecates since ZigBee 2006. */

/* General indicies. */
int hf_zbee_zdp_ext_addr = -1;
int hf_zbee_zdp_device = -1;
int hf_zbee_zdp_req_type = -1;
int hf_zbee_zdp_index = -1;
int hf_zbee_zdp_status = -1;
int hf_zbee_zdp_ep_count = -1;
int hf_zbee_zdp_endpoint = -1;
int hf_zbee_zdp_profile = -1;
int hf_zbee_zdp_cluster = -1;
int hf_zbee_zdp_addr_mode = -1;
int hf_zbee_zdp_table_size = -1;
int hf_zbee_zdp_table_count = -1;
int hf_zbee_zdp_in_count = -1;
int hf_zbee_zdp_out_count = -1;
int hf_zbee_zdp_in_cluster = -1;
int hf_zbee_zdp_out_cluster = -1;
int hf_zbee_zdp_assoc_device_count = -1;
int hf_zbee_zdp_assoc_device = -1;

/* Capability information indicies. */
int hf_zbee_zdp_cinfo_alloc = -1;
int hf_zbee_zdp_cinfo_security = -1;
int hf_zbee_zdp_cinfo_idle_rx = -1;
int hf_zbee_zdp_cinfo_power = -1;
int hf_zbee_zdp_cinfo_ffd = -1;
int hf_zbee_zdp_cinfo_alt_coord = -1;

/* Server mode flag indicies. */
int hf_zbee_zdp_server_pri_trust = -1;
int hf_zbee_zdp_server_bak_trust = -1;
int hf_zbee_zdp_server_pri_bind = -1;
int hf_zbee_zdp_server_bak_bind = -1;
int hf_zbee_zdp_server_pri_disc = -1;
int hf_zbee_zdp_server_bak_disc = -1;

/* Node descriptor indicies. */
int hf_zbee_zdp_node_type = -1;
int hf_zbee_zdp_node_complex = -1;
int hf_zbee_zdp_node_user = -1;
int hf_zbee_zdp_node_freq_868 = -1;
int hf_zbee_zdp_node_freq_900 = -1;
int hf_zbee_zdp_node_freq_2400 = -1;
int hf_zbee_zdp_node_manufacturer = -1;
int hf_zbee_zdp_node_max_buffer = -1;
int hf_zbee_zdp_node_max_transfer = -1;

/* Power descriptor indicies. */
int hf_zbee_zdp_power_mode = -1;
int hf_zbee_zdp_power_avail_ac = -1;
int hf_zbee_zdp_power_avail_recharge = -1;
int hf_zbee_zdp_power_avail_dispose = -1;
int hf_zbee_zdp_power_source_ac = -1;
int hf_zbee_zdp_power_source_recharge = -1;
int hf_zbee_zdp_power_source_dispose = -1;
int hf_zbee_zdp_power_level = -1;

/* Simple descriptor indicies. */
int hf_zbee_zdp_simple_app_device = -1;
int hf_zbee_zdp_simple_app_version = -1;
int hf_zbee_zdp_simple_length = -1;

/* Complex descriptor indicies. */
int hf_zbee_zdp_complex_length = -1;
int hf_zbee_zdp_complex_tag = -1;
int hf_zbee_zdp_complex = -1;

/* User descriptor indicies. */
int hf_zbee_zdp_user = -1;
int hf_zbee_zdp_user_length = -1;

/* Discovery indicies. */
int hf_zbee_zdp_cache = -1;
int hf_zbee_zdp_disc_node_size = -1;
int hf_zbee_zdp_disc_power_size = -1;
int hf_zbee_zdp_disc_ep_count = -1;
int hf_zbee_zdp_disc_simple_count = -1;
int hf_zbee_zdp_disc_simple_size = -1;

/* Binding indicies. */
int hf_zbee_zdp_target = -1;
int hf_zbee_zdp_target64 = -1;
int hf_zbee_zdp_target_ep = -1;
int hf_zbee_zdp_replacement = -1;
int hf_zbee_zdp_replacement_ep = -1;
int hf_zbee_zdp_bind_src = -1;
int hf_zbee_zdp_bind_src64 = -1;
int hf_zbee_zdp_bind_src_ep = -1;
int hf_zbee_zdp_bind_dst = -1;
int hf_zbee_zdp_bind_dst64 = -1;
int hf_zbee_zdp_bind_dst_ep = -1;

/* Network Management indicies. */
int hf_zbee_zdp_duration = -1;
int hf_zbee_zdp_leave_children = -1;
int hf_zbee_zdp_leave_rejoin = -1;
int hf_zbee_zdp_significance = -1;
int hf_zbee_zdp_scan_count = -1;
int hf_zbee_zdp_update_id = -1;
int hf_zbee_zdp_manager = -1;
int hf_zbee_zdp_tx_total = -1;
int hf_zbee_zdp_tx_fail = -1;
int hf_zbee_zdp_channel_count = -1;

/* Subtree indicies. */
gint ett_zbee_zdp = -1;
gint ett_zbee_zdp_endpoint = -1;
gint ett_zbee_zdp_match_in = -1;
gint ett_zbee_zdp_match_out = -1;
gint ett_zbee_zdp_node = -1;
gint ett_zbee_zdp_node_in = -1;
gint ett_zbee_zdp_node_out = -1;
gint ett_zbee_zdp_power = -1;
gint ett_zbee_zdp_simple = -1;
gint ett_zbee_zdp_complex = -1;
gint ett_zbee_zdp_cinfo = -1;
gint ett_zbee_zdp_server = -1;
gint ett_zbee_zdp_simple_sizes = -1;
gint ett_zbee_zdp_bind = -1;
gint ett_zbee_zdp_bind_end_in = -1;
gint ett_zbee_zdp_bind_end_out = -1;
gint ett_zbee_zdp_bind_table = -1;
gint ett_zbee_zdp_bind_source = -1;
gint ett_zbee_zdp_channels = -1;
gint ett_zbee_zdp_assoc_device = -1;
gint ett_zbee_zdp_nwk = -1;
gint ett_zbee_zdp_lqi = -1;
gint ett_zbee_zdp_rtg = -1;
gint ett_zbee_zdp_cache = -1;

/* Data dissector handle. */
static dissector_handle_t  data_handle;

/**************************************
 * Value Strings
 **************************************
 */
static const value_string zbee_zdp_req_types[] = {
    { ZBEE_ZDP_REQ_TYPE_SINGLE,     "Single Device Response" },
    { ZBEE_ZDP_REQ_TYPE_EXTENDED,   "Extended Response" },
    { 0, NULL }
};

static const value_string zbee_zdp_cluster_names[] = {
    { ZBEE_ZDP_REQ_NWK_ADDR,            "Network Address Request" },
    { ZBEE_ZDP_REQ_IEEE_ADDR,           "Extended Address Request" },
    { ZBEE_ZDP_REQ_NODE_DESC,           "Node Descriptor Request" },
    { ZBEE_ZDP_REQ_POWER_DESC,          "Power Descriptor Request" },
    { ZBEE_ZDP_REQ_SIMPLE_DESC,         "Simple Descriptor Request" },
    { ZBEE_ZDP_REQ_ACTIVE_EP,           "Active Endpoint Request" },
    { ZBEE_ZDP_REQ_MATCH_DESC,          "Match Descriptor Request" },
    { ZBEE_ZDP_REQ_COMPLEX_DESC,        "Complex Descriptor Request" },
    { ZBEE_ZDP_REQ_USER_DESC,           "User Descriptor Request" },
    { ZBEE_ZDP_REQ_DISCOVERY_CACHE,     "Discovery Cache Request" },
    { ZBEE_ZDP_REQ_DEVICE_ANNCE,        "Device Announcement" },
    { ZBEE_ZDP_REQ_SET_USER_DESC,       "Set User Descriptor Request" },
    { ZBEE_ZDP_REQ_SYSTEM_SERVER_DISC,  "Server Discovery Request" },
    { ZBEE_ZDP_REQ_STORE_DISCOVERY,     "Store Discovery Request" },
    { ZBEE_ZDP_REQ_STORE_NODE_DESC,     "Store Node Descriptor Request" },
    { ZBEE_ZDP_REQ_STORE_POWER_DESC,    "Store Power Descriptor Request" },
    { ZBEE_ZDP_REQ_STORE_ACTIVE_EP,     "Store Active Endpoints Request" },
    { ZBEE_ZDP_REQ_STORE_SIMPLE_DESC,   "Store Simple Descriptor Request" },
    { ZBEE_ZDP_REQ_REMOVE_NODE_CACHE,   "Remove Node Cache Request" },
    { ZBEE_ZDP_REQ_FIND_NODE_CACHE,     "Find Node Cache Request" },
    { ZBEE_ZDP_REQ_EXT_SIMPLE_DESC,     "Extended Simple Descriptor Request" },
    { ZBEE_ZDP_REQ_EXT_ACTIVE_EP,       "Extended Active Endpoint Request" },
    { ZBEE_ZDP_REQ_END_DEVICE_BIND,     "End Device Bind Request" },
    { ZBEE_ZDP_REQ_BIND,                "Bind Request" },
    { ZBEE_ZDP_REQ_UNBIND,              "Unbind Request" },
    { ZBEE_ZDP_REQ_BIND_REGISTER,       "Bind Register Request" },
    { ZBEE_ZDP_REQ_REPLACE_DEVICE,      "Replace Device Request" },
    { ZBEE_ZDP_REQ_STORE_BAK_BIND_ENTRY,    "Store Backup Binding Request" },
    { ZBEE_ZDP_REQ_REMOVE_BAK_BIND_ENTRY,   "Remove Backup Binding Request" },
    { ZBEE_ZDP_REQ_BACKUP_BIND_TABLE,   "Backup Binding Table Request" },
    { ZBEE_ZDP_REQ_RECOVER_BIND_TABLE,  "Recover Binding Table Request" },
    { ZBEE_ZDP_REQ_BACKUP_SOURCE_BIND,  "Backup Source Binding Request" },
    { ZBEE_ZDP_REQ_RECOVER_SOURCE_BIND, "Recover Source Binding Request" },
    { ZBEE_ZDP_REQ_MGMT_NWK_DISC,       "Network Discovery Request" },
    { ZBEE_ZDP_REQ_MGMT_LQI,            "Link Quality Request" },
    { ZBEE_ZDP_REQ_MGMT_RTG,            "Routing Table Request" },
    { ZBEE_ZDP_REQ_MGMT_BIND,           "Binding Table Request" },
    { ZBEE_ZDP_REQ_MGMT_LEAVE,          "Leave Request" },
    { ZBEE_ZDP_REQ_MGMT_DIRECT_JOIN,    "Direct Join Request" },
    { ZBEE_ZDP_REQ_MGMT_PERMIT_JOIN,    "Permit Join Request" },
    { ZBEE_ZDP_REQ_MGMT_CACHE,          "Cache Request" },
    { ZBEE_ZDP_REQ_MGMT_NWKUPDATE,      "Network Update Request" },

    { ZBEE_ZDP_RSP_NWK_ADDR,            "Network Address Response" },
    { ZBEE_ZDP_RSP_IEEE_ADDR,           "Extended Address Response" },
    { ZBEE_ZDP_RSP_NODE_DESC,           "Node Descriptor Response" },
    { ZBEE_ZDP_RSP_POWER_DESC,          "Power Descriptor Response" },
    { ZBEE_ZDP_RSP_SIMPLE_DESC,         "Simple Descriptor Response" },
    { ZBEE_ZDP_RSP_ACTIVE_EP,           "Active Endpoint Response" },
    { ZBEE_ZDP_RSP_MATCH_DESC,          "Match Descriptor Response" },
    { ZBEE_ZDP_RSP_COMPLEX_DESC,        "Complex Descriptor Response" },
    { ZBEE_ZDP_RSP_USER_DESC,           "User Descriptor Request" },
    { ZBEE_ZDP_RSP_DISCOVERY_CACHE,     "Discovery Cache Response" },
    { ZBEE_ZDP_RSP_CONF_USER_DESC,      "Set User Descriptor Confirm" },
    { ZBEE_ZDP_RSP_SYSTEM_SERVER_DISC,  "Server Discovery Response" },
    { ZBEE_ZDP_RSP_STORE_DISCOVERY,     "Store Discovery Response" },
    { ZBEE_ZDP_RSP_STORE_NODE_DESC,     "Store Node Descriptor Response" },
    { ZBEE_ZDP_RSP_STORE_POWER_DESC,    "Store Power Descriptor Response" },
    { ZBEE_ZDP_RSP_STORE_ACTIVE_EP,     "Store Active Endpoints Response" },
    { ZBEE_ZDP_RSP_STORE_SIMPLE_DESC,   "Store Simple Descriptor Response" },
    { ZBEE_ZDP_RSP_REMOVE_NODE_CACHE,   "Remove Node Cache Response" },
    { ZBEE_ZDP_RSP_FIND_NODE_CACHE,     "Find Node Cache Response" },
    { ZBEE_ZDP_RSP_EXT_SIMPLE_DESC,     "Extended Simple Descriptor Response" },
    { ZBEE_ZDP_RSP_EXT_ACTIVE_EP,       "Extended Active Endpoint Response" },
    { ZBEE_ZDP_RSP_END_DEVICE_BIND,     "End Device Bind Response" },
    { ZBEE_ZDP_RSP_BIND,                "Bind Response" },
    { ZBEE_ZDP_RSP_UNBIND,              "Unbind Response" },
    { ZBEE_ZDP_RSP_BIND_REGISTER,       "Bind Register Response" },
    { ZBEE_ZDP_RSP_REPLACE_DEVICE,      "Replace Device Response" },
    { ZBEE_ZDP_RSP_STORE_BAK_BIND_ENTRY,    "Store Backup Binding Response" },
    { ZBEE_ZDP_RSP_REMOVE_BAK_BIND_ENTRY,   "Remove Backup Binding Response" },
    { ZBEE_ZDP_RSP_BACKUP_BIND_TABLE,   "Backup Binding Table Response" },
    { ZBEE_ZDP_RSP_RECOVER_BIND_TABLE,  "Recover Binding Table Response" },
    { ZBEE_ZDP_RSP_BACKUP_SOURCE_BIND,  "Backup Source Binding Response" },
    { ZBEE_ZDP_RSP_RECOVER_SOURCE_BIND, "Recover Source Binding Response" },
    { ZBEE_ZDP_RSP_MGMT_NWK_DISC,       "Network Discovery Response" },
    { ZBEE_ZDP_RSP_MGMT_LQI,            "Link Quality Response" },
    { ZBEE_ZDP_RSP_MGMT_RTG,            "Routing Table Response" },
    { ZBEE_ZDP_RSP_MGMT_BIND,           "Binding Table Response" },
    { ZBEE_ZDP_RSP_MGMT_LEAVE,          "Leave Response" },
    { ZBEE_ZDP_RSP_MGMT_DIRECT_JOIN,    "Direct Join Response" },
    { ZBEE_ZDP_RSP_MGMT_PERMIT_JOIN,    "Permit Join Response" },
    { ZBEE_ZDP_RSP_MGMT_CACHE,          "Cache Response" },
    { ZBEE_ZDP_RSP_MGMT_NWKUPDATE,      "Network Update Notify" },
    { 0, NULL }
};

static const value_string zbee_zdp_status_names[] = {
    { ZBEE_ZDP_STATUS_SUCCESS,          "Success" },
    { ZBEE_ZDP_STATUS_INV_REQUESTTYPE,  "Invalid Request Type" },
    { ZBEE_ZDP_STATUS_DEVICE_NOT_FOUND, "Device Not Found" },
    { ZBEE_ZDP_STATUS_INVALID_EP,       "Invalid Endpoint" },
    { ZBEE_ZDP_STATUS_NOT_ACTIVE,       "Not Active" },
    { ZBEE_ZDP_STATUS_NOT_SUPPORTED,    "Not Supported" },
    { ZBEE_ZDP_STATUS_TIMEOUT,          "Timeout" },
    { ZBEE_ZDP_STATUS_NO_MATCH,         "No Match" },
    { ZBEE_ZDP_STATUS_NO_ENTRY,         "No Entry" },
    { ZBEE_ZDP_STATUS_NO_DESCRIPTOR,    "No Descriptor" },
    { ZBEE_ZDP_STATUS_INSUFFICIENT_SPACE,   "Insufficient Space" },
    { ZBEE_ZDP_STATUS_NOT_PERMITTED,    "Not Permitted" },
    { ZBEE_ZDP_STATUS_TABLE_FULL,       "Table Full" },
    { 0, NULL }
};

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_status_name
 *  DESCRIPTION
 *      Returns a status name for a given status value.
 *  PARAMETERS
 *      guint8  status;
 *  RETURNS
 *      const gchar *
 *---------------------------------------------------------------
 */
const gchar *
zdp_status_name(guint8 status)
{
    return val_to_str(status, zbee_zdp_status_names, "Reserved");
} /* zdp_status_name */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_convert_2003cluster
 *  DESCRIPTION
 *      Converts a ZigBee 2003 & earlier cluster ID to a 2006
 *      cluster ID. This change is necessary because the cluster
 *      ID field was enlarged from 8 to 16 bits in 2006, and the
 *      values for the response messages was changed.
 *  PARAMETERS
 *      guint8  cluster;
 *  RETURNS
 *      guint16
 *---------------------------------------------------------------
 */
static guint16
zdp_convert_2003cluster(guint8 cluster)
{
    guint16 cluster16 = (guint16)cluster;

    if (cluster16 & ZBEE_ZDP_MSG_RESPONSE_BIT_2003) {
        /* Clear the 2003 request bit. */
        cluster16 &= ~(ZBEE_ZDP_MSG_RESPONSE_BIT_2003);
        /* Set the 2006 request bit. */
        cluster16 |= (ZBEE_ZDP_MSG_RESPONSE_BIT);
    }
    return cluster16;
} /* zdp_convert_2003cluster */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_dump_excess
 *  DESCRIPTION
 *      Helper functions dumps any excess data into the data dissector.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      guint       offset  - offset after parsing last item.
 *      packet_info *pinfo  - packet information structure.
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zdp_dump_excess(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *root = proto_tree_get_root(tree);
    guint       length = tvb_length_remaining(tvb, offset);
    tvbuff_t    *excess;

    if (length > 0) {
        excess = tvb_new_subset(tvb, offset, length, length);
        call_dissector(data_handle, excess, pinfo, root);
    }
} /* zdp_dump_excess */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_append_info
 *  DESCRIPTION
 *      ZigBee helper function. Appends the info to the info column
 *      and proto item.
 *  PARAMETERS
 *      proto_item  *item   - item to display info on.
 *      packet_info *pinfo  - packet info struct.
 *      const gchar *format - format string.
 *      ...                 - variable argument list.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void
zbee_append_info(proto_item *item, packet_info *pinfo, const gchar *format, ...)
{
    static gchar    buffer[512];
    va_list         ap;

    va_start(ap, format);
    g_vsnprintf(buffer, 512, format, ap);
    va_end(ap);

    if (item) {
        proto_item_append_text(item, "%s", buffer);
    }
    col_append_str(pinfo->cinfo, COL_INFO, buffer);
} /* zbee_add_info */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_parse_uint
 *  DESCRIPTION
 *      ZigBee helper function. extracts an integer and displays it to the tree.
 *  PARAMETERS
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *      int         hfindex - index to field information.
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      guint       *offset - pointer to value of offset.
 *      guint       length  - length of the value to extract.
 *      proto_item  **ti    - optional pointer to get the created proto item.
 *  RETURNS
 *      guint   - the value read out of the tvbuff and added to the tree.
 *---------------------------------------------------------------
 */
guint
zbee_parse_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset, guint length, proto_item **ti)
{
    proto_item          *item = NULL;
    guint               value = 0;

    /* Get the value. */
    if (length == 0) {
        /* ??? */
        return 0;
    }
    else if (length == 1) {
        value = tvb_get_guint8(tvb, *offset);
    }
    else if (length == 2) {
        value = tvb_get_letohs(tvb, *offset);
    }
    else if (length == 3) {
        value = tvb_get_letohs(tvb, *offset);
        value += ((guint32)tvb_get_guint8(tvb, *offset + 2) << 16);
    }
    else {
        value = tvb_get_letohl(tvb, *offset);
    }

    /* Display it. */
    if (tree) {
        item = proto_tree_add_uint(tree, hfindex, tvb, *offset, length, value);
    }

    /* Increment the offset. */
    *offset += length;

    /* return the item if requested. */
    if (ti) *ti = item;

    /* return the value. */
    return value;
} /* zbee_parse_uint */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_parse_eui64
 *  DESCRIPTION
 *      ZigBee helper function. extracts an EUI64 address and displays
 *      it to the tree.
 *  PARAMETERS
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *      int         hfindex - index to field information.
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      guint       *offset - pointer to value of offset.
 *      guint       length  - length of the value to extract.
 *      proto_item  **ti    - optional pointer to get the created proto item.
 *  RETURNS
 *      guint64   - the value read out of the tvbuff and added to the tree.
 *---------------------------------------------------------------
 */
guint64
zbee_parse_eui64(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint *offset, guint length, proto_item **ti)
{
    proto_item          *item = NULL;
    guint64             value;

    /* Get the value. */
    value = tvb_get_letoh64(tvb, *offset);

    /* Display it. */
    if (tree) {
        item = proto_tree_add_eui64(tree, hfindex, tvb, *offset, length, value);
    }

    /* Increment the offset. */
    *offset += sizeof(guint64);

    /* return the item if requested. */
    if (ti) *ti = item;

    /* return the value. */
    return value;
} /* zbee_parse_eui64 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_status
 *  DESCRIPTION
 *      Parses and displays the status value.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the status value.
 *  RETURNS
 *      guint8
 *---------------------------------------------------------------
 */
guint8
zdp_parse_status(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    guint8      status;

    /* Get and display the flags. */
    status = tvb_get_guint8(tvb, *offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_zdp_status, tvb, *offset, sizeof(guint8), status);
    }
    *offset += sizeof(guint8);

    return status;
} /* zdp_parse_status */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_chanmask
 *  DESCRIPTION
 *      Parses and displays the a channel mask.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the status value.
 *  RETURNS
 *      guint32
 *---------------------------------------------------------------
 */
guint32
zdp_parse_chanmask(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    int         i;
    guint32     mask;
    proto_item  *ti;

    /* Get and display the channel mask. */
    mask = tvb_get_letohl(tvb, *offset);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, *offset, sizeof(guint32), "Channels: ");

        /* Check if there are any channels to display. */
        if (mask==0) {
            proto_item_append_text(ti, "None");
        }
        /* Display the first channel #. */
        for (i=0; i<(8*(int)sizeof(guint32)); i++) {
            if ((1<<i) & mask) {
                proto_item_append_text(ti, "%d", i++);
                break;
            }
        } /* for */
        /* Display the rest of the channels. */
        for (;i<(8*(int)sizeof(guint32)); i++) {
            if (!((1<<i) & mask)) {
                /* This channel isn't selected. */
                continue;
            }
            /* If the previous channel wasn't selected, then display the
             * channel number.
             */
            if ( ! ((1<<(i-1)) & mask) ) {
                proto_item_append_text(ti, ", %d", i);
            }
            /*
             * If the next channel is selected too, skip past it and display
             * a range of values instead.
             */
            if ((2<<i) & mask) {
                while ((2<<i) & mask) i++;
                proto_item_append_text(ti, "-%d", i);
            }
        } /* for */
    }
    *offset += sizeof(guint32);

    return mask;
} /* zdp_parse_chanmask */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_cinfo
 *  DESCRIPTION
 *      Parses and displays MAC capability info flags.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      gint       ettindex - subtree index to create the node descriptor in, or -1
 *                              to create it without a subtree.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the node descriptor.
 *  RETURNS
 *      guint8
 *---------------------------------------------------------------
 */
guint8
zdp_parse_cinfo(proto_tree *tree, gint ettindex, tvbuff_t *tvb, guint *offset)
{
    proto_item  *ti;
    proto_tree  *field_tree;
    guint8      flags;

    /* Get and display the flags. */
    flags = tvb_get_guint8(tvb, *offset);
    if (tree) {
        if (ettindex != -1) {
            ti = proto_tree_add_text(tree, tvb, *offset, sizeof(guint8), "Capability Information");
            field_tree = proto_item_add_subtree(ti, ettindex);
        }
        else field_tree = tree;

        proto_tree_add_boolean(field_tree, hf_zbee_zdp_cinfo_alt_coord, tvb, *offset, sizeof(guint8), flags & ZBEE_CINFO_ALT_COORD);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_cinfo_ffd, tvb, *offset, sizeof(guint8), flags & ZBEE_CINFO_FFD);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_cinfo_power, tvb, *offset, sizeof(guint8), flags & ZBEE_CINFO_POWER);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_cinfo_idle_rx, tvb, *offset, sizeof(guint8), flags & ZBEE_CINFO_IDLE_RX);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_cinfo_security, tvb, *offset, sizeof(guint8), flags & ZBEE_CINFO_SECURITY);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_cinfo_alloc, tvb, *offset, sizeof(guint8), flags & ZBEE_CINFO_ALLOC);
    }
    *offset += sizeof(guint8);

    return flags;
} /* zdp_parse_cinfo */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_server_flags
 *  DESCRIPTION
 *      Parses and displays server mode flags.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      gint       ettindex - subtree index to create the node descriptor in, or -1
 *                              to create it without a subtree.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the node descriptor.
 *  RETURNS
 *      guint16
 *---------------------------------------------------------------
 */
guint16
zdp_parse_server_flags(proto_tree *tree, gint ettindex, tvbuff_t *tvb, guint *offset)
{
    proto_item  *ti;
    proto_tree  *field_tree;
    guint16      flags;

    /* Get and display the flags. */
    flags = tvb_get_letohs(tvb, *offset);
    if (tree) {
        if (ettindex != -1) {
            ti = proto_tree_add_text(tree, tvb, *offset, sizeof(guint8), "Server Flags");
            field_tree = proto_item_add_subtree(ti, ettindex);
        }
        else field_tree = tree;

        proto_tree_add_boolean(field_tree, hf_zbee_zdp_server_pri_trust, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_SERVER_PRIMARY_TRUST);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_server_bak_trust, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_SERVER_BACKUP_TRUST);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_server_pri_bind, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_SERVER_PRIMARY_BIND);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_server_bak_bind, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_SERVER_BACKUP_BIND);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_server_pri_disc, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_SERVER_PRIMARY_DISC);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_server_bak_disc, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_SERVER_BACKUP_DISC);
    }
    *offset += sizeof(guint16);

    return flags;
} /* zdp_parse_server_flags */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_node_desc
 *  DESCRIPTION
 *      Parses and displays a node descriptor to the the specified
 *      tree.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      gint       ettindex - subtree index to create the node descriptor in, or -1
 *                              to create it without a subtree.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the node descriptor.
 *      packet_info *pinfo  - packet information structure.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zdp_parse_node_desc(proto_tree *tree, gint ettindex, tvbuff_t *tvb, guint *offset, packet_info *pinfo)
{
    proto_item  *ti;
    proto_item  *field_root = NULL;
    proto_tree  *field_tree = NULL;

    guint16     flags;
    /*guint8      capability;*/
    /*guint16     mfr_code;*/
    /*guint8      max_buff;*/
    /*guint16     max_transfer;*/

    if ((tree) && (ettindex != -1)) {
        field_root = proto_tree_add_text(tree, tvb, *offset, tvb_length_remaining(tvb, *offset), "Node Descriptor");
        field_tree = proto_item_add_subtree(field_root, ettindex);
    }
    else field_tree = tree;

    /* Get and display the flags. */
    flags = tvb_get_letohs(tvb, *offset);
    if (tree) {
        guint16 type = flags & ZBEE_ZDP_NODE_TYPE;
        ti = proto_tree_add_uint(field_tree, hf_zbee_zdp_node_type, tvb, *offset, sizeof(guint16), type);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_node_complex, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_COMPLEX);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_node_user, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_USER);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_node_freq_868, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_FREQ_868MHZ);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_node_freq_900, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_FREQ_900MHZ);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_node_freq_2400, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_NODE_FREQ_2400MHZ);

        /* Enumerate the type field. */
        if (type == ZBEE_ZDP_NODE_TYPE_COORD)    proto_item_append_text(ti, " (Coordinator)");
        else if (type == ZBEE_ZDP_NODE_TYPE_FFD) proto_item_append_text(ti, " (Router)");
        else if (type == ZBEE_ZDP_NODE_TYPE_RFD) proto_item_append_text(ti, " (End Device)");
        else proto_item_append_text(ti, " (Reserved)");
    }
    *offset += sizeof(guint16);

    /* Get and display the capability flags. */
    /*capability      =*/ zdp_parse_cinfo(field_tree, ett_zbee_zdp_cinfo, tvb, offset);
    /*mfr_code        =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_node_manufacturer, tvb, offset, sizeof(guint16), NULL);
    /*max_buff        =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_node_max_buffer, tvb, offset, sizeof(guint8), NULL);
    /*max_transfer    =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_node_max_transfer, tvb, offset, sizeof(guint16), NULL);

    /* Get and display the server flags. */
    if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
        zdp_parse_server_flags(field_tree, ett_zbee_zdp_server, tvb, offset);
    }

    /* Correct the length of the subtree. */
    if (tree && (ettindex != -1)) {
        proto_item_set_len(field_root, *offset);
    }

} /* zdp_parse_node_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_power_desc
 *  DESCRIPTION
 *      Parses and displays a node descriptor to the the specified
 *      tree.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      gint       ettindex - subtree index to create the node descriptor in, or -1
 *                              to create it without a subtree.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the node descriptor.
 *      packet_info *pinfo  - packet information structure.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zdp_parse_power_desc(proto_tree *tree, gint ettindex, tvbuff_t *tvb, guint *offset)
{
    proto_item  *ti;
    proto_tree  *field_tree;

    guint16     flags;
    guint16     mode;
    guint16     level;

    if ((tree) && (ettindex != -1)) {
        ti = proto_tree_add_text(tree, tvb, *offset, sizeof(guint16), "Power Descriptor");
        field_tree = proto_item_add_subtree(ti, ettindex);
    }
    else field_tree = tree;

    flags = tvb_get_letohs(tvb, *offset);
    mode  = flags & ZBEE_ZDP_POWER_MODE;
    level = flags & ZBEE_ZDP_POWER_LEVEL;
    if (tree) {
        ti = proto_tree_add_uint(field_tree, hf_zbee_zdp_power_mode, tvb, *offset, sizeof(guint16), mode);
        if (mode == ZBEE_ZDP_POWER_MODE_RX_ON)              proto_item_append_text(ti, " (Receiver Always On)");
        else if (mode == ZBEE_ZDP_POWER_MODE_RX_PERIODIC)   proto_item_append_text(ti, " (Receiver Periodically On)");
        else if (mode == ZBEE_ZDP_POWER_MODE_RX_STIMULATE)  proto_item_append_text(ti, " (Receiver On When Stimulated)");
        else proto_item_append_text(ti, " (Reserved)");

        proto_tree_add_boolean(field_tree, hf_zbee_zdp_power_avail_ac, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_POWER_AVAIL_AC);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_power_avail_recharge, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_POWER_AVAIL_RECHARGEABLE);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_power_avail_dispose, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_POWER_AVAIL_DISPOSEABLE);

        proto_tree_add_boolean(field_tree, hf_zbee_zdp_power_source_ac, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_POWER_SOURCE_AC);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_power_source_recharge, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_POWER_SOURCE_RECHARGEABLE);
        proto_tree_add_boolean(field_tree, hf_zbee_zdp_power_source_dispose, tvb, *offset, sizeof(guint16), flags & ZBEE_ZDP_POWER_SOURCE_DISPOSEABLE);

        if (level == ZBEE_ZDP_POWER_LEVEL_FULL)
            proto_tree_add_uint_format_value(field_tree, hf_zbee_zdp_power_level, tvb, *offset, sizeof(guint16), level, "Full");
        else if (level == ZBEE_ZDP_POWER_LEVEL_OK)
            proto_tree_add_uint_format_value(field_tree, hf_zbee_zdp_power_level, tvb, *offset, sizeof(guint16), level, "OK");
        else if (level == ZBEE_ZDP_POWER_LEVEL_LOW)
            proto_tree_add_uint_format_value(field_tree, hf_zbee_zdp_power_level, tvb, *offset, sizeof(guint16), level, "Low");
        else if (level == ZBEE_ZDP_POWER_LEVEL_CRITICAL)
            proto_tree_add_uint_format_value(field_tree, hf_zbee_zdp_power_level, tvb, *offset, sizeof(guint16), level, "Critical");
        else proto_tree_add_uint_format_value(field_tree, hf_zbee_zdp_power_level, tvb, *offset, sizeof(guint16), level, "Reserved");
    }
    *offset += sizeof(guint16);
} /* zdp_parse_power_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_simple_desc
 *  DESCRIPTION
 *      Parses and displays a simple descriptor to the the specified
 *      tree.
 *  PARAMETERS
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      gint       ettindex - subtree index to create the node descriptor in, or -1
 *                              to create it without a subtree.
 *      tvbuff_t   *tvb     - pointer to buffer containing raw packet.
 *      guint      *offset  - offset into the tvb to find the node descriptor.
 *      packet_info *pinfo  - packet information structure.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zdp_parse_simple_desc(proto_tree *tree, gint ettindex, tvbuff_t *tvb, guint *offset, packet_info *pinfo)
{
    proto_item  *ti;
    proto_item  *field_root = NULL;
    proto_tree  *field_tree = NULL, *cluster_tree = NULL;
    guint       i, sizeof_cluster;

    /*guint8      endpoint;*/
    /*guint16     profile;*/
    /*guint16     app_device;*/
    /*guint8      app_version;*/
    guint8      in_count;
    guint8      out_count;

    if ((tree) && (ettindex != -1)) {
        field_root = proto_tree_add_text(tree, tvb, *offset, tvb_length_remaining(tvb, *offset), "Simple Descriptor");
        field_tree = proto_item_add_subtree(field_root, ettindex);
    }
    else field_tree = tree;

    /*endpoint    =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_endpoint, tvb, offset, sizeof(guint8), NULL);
    /*profile     =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_profile, tvb, offset, sizeof(guint16), NULL);
    /*app_device  =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_simple_app_device, tvb, offset, sizeof(guint16), NULL);
    /*app_version =*/ zbee_parse_uint(field_tree, hf_zbee_zdp_simple_app_version, tvb, offset, sizeof(guint8), NULL);

    sizeof_cluster = (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007)?sizeof(guint16):sizeof(guint8);

    in_count    = zbee_parse_uint(field_tree, hf_zbee_zdp_in_count, tvb, offset, sizeof(guint8), NULL);
    if ((tree) && (in_count)) {
        ti = proto_tree_add_text(field_tree, tvb, *offset, in_count*sizeof_cluster, "Input Cluster List");
        cluster_tree = proto_item_add_subtree(ti, ett_zbee_zdp_node_in);
    }
    for (i=0; i<in_count && tvb_bytes_exist(tvb, *offset, sizeof_cluster); i++) {
        zbee_parse_uint(cluster_tree, hf_zbee_zdp_in_cluster, tvb, offset, sizeof_cluster, NULL);
    }

    out_count = zbee_parse_uint(field_tree, hf_zbee_zdp_out_count, tvb, offset, sizeof(guint8), NULL);
    if ((tree) && (out_count)) {
        ti = proto_tree_add_text(field_tree, tvb, *offset, in_count*sizeof_cluster, "Output Cluster List");
        cluster_tree = proto_item_add_subtree(ti, ett_zbee_zdp_node_out);
    }
    for (i=0; (i<out_count) && tvb_bytes_exist(tvb, *offset, sizeof_cluster); i++) {
        zbee_parse_uint(cluster_tree, hf_zbee_zdp_out_cluster, tvb, offset, sizeof_cluster, NULL);
    }

    if (tree && (ettindex != -1)) {
        proto_item_set_len(field_root, *offset);
    }
} /* zdp_parse_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_complex_desc
 *  DESCRIPTION
 *      Parses and displays a simple descriptor to the the specified
 *      tree.
 *  PARAMETERS
 *      proto_tree  *tree    - pointer to data tree Wireshark uses to display packet.
 *      gint        ettindex - subtree index to create the node descriptor in, or -1
 *                              to create it without a subtree.
 *      tvbuff_t    *tvb     - pointer to buffer containing raw packet.
 *      guint       *offset  - offset into the tvb to find the node descriptor.
 *      guint       length   - length of the complex descriptor.
 *      packet_info *pinfo   - packet information structure.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zdp_parse_complex_desc(proto_tree *tree, gint ettindex, tvbuff_t *tvb, guint *offset, guint length)
{
    enum {
        tag_charset = 1,
        tag_mfr_name = 2,
        tag_model_name = 3,
        tag_serial_no = 4,
        tag_url = 5,
        tag_icon = 6,
        tag_icon_url = 7
    };

    const gchar *tag_name[] = {
        "Reserved Tag",
        "languageChar",
        "manufacturerName",
        "modelName",
        "serialNumber",
        "deviceURL",
        "icon",
        "outliner"
    };

    const gint max_len = 128;

    proto_item  *field_root;
    proto_tree  *field_tree;

    gchar   *str = ep_alloc(length);
    gchar   *complex = ep_alloc(max_len);
    guint8  tag;

    if ((tree) && (ettindex != -1)) {
        field_root = proto_tree_add_text(tree, tvb, *offset, length, "Complex Descriptor");
        field_tree = proto_item_add_subtree(field_root, ettindex);
    }
    else field_tree = tree;

    tag = tvb_get_guint8(tvb, *offset);
    if (tag == tag_charset) {
        gchar   lang_str[3];
        guint8  charset  = tvb_get_guint8(tvb, *offset + 3);
        gchar   *charset_str;

        if (charset == 0x00) charset_str = "ASCII";
        else                 charset_str = "Unknown Character Set";

        lang_str[0] = tvb_get_guint8(tvb, *offset + 1);
        lang_str[1] = tvb_get_guint8(tvb, *offset + 2);
        lang_str[2] = '\0';

        g_snprintf(complex, max_len, "<%s>%s, %s</%s>", tag_name[tag_charset], lang_str, charset_str, tag_name[tag_charset]);
    }
    else if (tag == tag_icon) {
        /* TODO: */
        g_snprintf(complex, max_len, "<%s>FixMe</%s>", tag_name[tag_icon], tag_name[tag_icon]);
    }
    else {
        tvb_memcpy(tvb, str, *offset+1, length-1);
        str[length-1] = '\0';
        /* Handles all string type XML tags. */
        if (tag <= tag_icon_url) {
            g_snprintf(complex, max_len, "<%s>%s</%s>", tag_name[tag], str, tag_name[tag]);
        }
        else {
            g_snprintf(complex, max_len, "<%s>%s</%s>", tag_name[0], str, tag_name[0]);
        }
    }
    if (tree) {
        proto_tree_add_string(field_tree, hf_zbee_zdp_complex, tvb, *offset, length, complex);
    }
    *offset += (length);
} /* zdp_parse_complex_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_zbee_zdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *zdp_tree = NULL;
    proto_item      *proto_root;
    tvbuff_t        *zdp_tvb;

    guint8          seqno;
    guint16         cluster;
    guint           offset = 0;

    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_zbee_zdp, tvb, offset, tvb_length(tvb), "ZigBee Device Profile");
        zdp_tree = proto_item_add_subtree(proto_root, ett_zbee_zdp);
    }
#if 0
    /* Overwrite the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee ZDP");
#endif
    /* Get and display the sequence number. */
    seqno = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(zdp_tree, hf_zbee_zdp_seqno, tvb, offset, sizeof(guint8), seqno);
    }
    offset += sizeof(guint8);

    if (pinfo->zbee_stack_vers <= ZBEE_VERSION_2004) {
        /* ZigBee 2004 and earlier had different cluster identifiers, need to convert
         * them into the ZigBee 2006 & later values. */
        cluster = zdp_convert_2003cluster((guint8)pinfo->zbee_cluster_id);
    }
    else {
        cluster = pinfo->zbee_cluster_id;
    }

    /* Update info. */
    if (tree) {
        proto_item_append_text(zdp_tree, ", %s", val_to_str(cluster, zbee_zdp_cluster_names, "Unknown Cluster"));
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cluster, zbee_zdp_cluster_names, "Unknown Cluster"));
    }

    /* Create a new tvb for the zdp message. */
    zdp_tvb = tvb_new_subset_remaining(tvb, offset);

    switch (cluster) {
        case ZBEE_ZDP_REQ_NWK_ADDR:
            dissect_zbee_zdp_req_nwk_addr(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_IEEE_ADDR:
            dissect_zbee_zdp_req_ext_addr(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_NODE_DESC:
            dissect_zbee_zdp_req_node_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_POWER_DESC:
            dissect_zbee_zdp_req_power_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_SIMPLE_DESC:
            dissect_zbee_zdp_req_simple_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_ACTIVE_EP:
            dissect_zbee_zdp_req_active_ep(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MATCH_DESC:
            dissect_zbee_zdp_req_match_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_COMPLEX_DESC:
            dissect_zbee_zdp_req_complex_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_USER_DESC:
            dissect_zbee_zdp_req_user_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_DISCOVERY_CACHE:
            dissect_zbee_zdp_req_discovery_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_DEVICE_ANNCE:
            dissect_zbee_zdp_device_annce(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_SET_USER_DESC:
            dissect_zbee_zdp_req_set_user_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_SYSTEM_SERVER_DISC:
            dissect_zbee_zdp_req_system_server_disc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_STORE_DISCOVERY:
            dissect_zbee_zdp_req_store_discovery(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_STORE_NODE_DESC:
            dissect_zbee_zdp_req_store_node_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_STORE_POWER_DESC:
            dissect_zbee_zdp_req_store_power_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_STORE_ACTIVE_EP:
            dissect_zbee_zdp_req_store_active_ep(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_STORE_SIMPLE_DESC:
            dissect_zbee_zdp_req_store_simple_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_REMOVE_NODE_CACHE:
            dissect_zbee_zdp_req_remove_node_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_FIND_NODE_CACHE:
            dissect_zbee_zdp_req_find_node_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_EXT_SIMPLE_DESC:
            dissect_zbee_zdp_req_ext_simple_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_EXT_ACTIVE_EP:
            dissect_zbee_zdp_req_ext_active_ep(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_END_DEVICE_BIND:
            dissect_zbee_zdp_req_end_device_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_BIND:
            dissect_zbee_zdp_req_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_UNBIND:
            dissect_zbee_zdp_req_unbind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_BIND_REGISTER:
            dissect_zbee_zdp_req_bind_register(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_REPLACE_DEVICE:
            dissect_zbee_zdp_req_replace_device(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_STORE_BAK_BIND_ENTRY:
            dissect_zbee_zdp_req_store_bak_bind_entry(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_REMOVE_BAK_BIND_ENTRY:
            dissect_zbee_zdp_req_remove_bak_bind_entry(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_BACKUP_BIND_TABLE:
            dissect_zbee_zdp_req_backup_bind_table(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_RECOVER_BIND_TABLE:
            dissect_zbee_zdp_req_recover_bind_table(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_BACKUP_SOURCE_BIND:
            dissect_zbee_zdp_req_backup_source_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_RECOVER_SOURCE_BIND:
            dissect_zbee_zdp_req_recover_source_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_NWK_DISC:
            dissect_zbee_zdp_req_mgmt_nwk_disc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_LQI:
            dissect_zbee_zdp_req_mgmt_lqi(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_RTG:
            dissect_zbee_zdp_req_mgmt_rtg(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_BIND:
            dissect_zbee_zdp_req_mgmt_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_LEAVE:
            dissect_zbee_zdp_req_mgmt_leave(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_DIRECT_JOIN:
            dissect_zbee_zdp_req_mgmt_direct_join(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_PERMIT_JOIN:
            dissect_zbee_zdp_req_mgmt_permit_join(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_CACHE:
            dissect_zbee_zdp_req_mgmt_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_REQ_MGMT_NWKUPDATE:
            dissect_zbee_zdp_req_mgmt_nwkupdate(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_NWK_ADDR:
            dissect_zbee_zdp_rsp_nwk_addr(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_IEEE_ADDR:
            dissect_zbee_zdp_rsp_ext_addr(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_NODE_DESC:
            dissect_zbee_zdp_rsp_node_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_POWER_DESC:
            dissect_zbee_zdp_rsp_power_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_SIMPLE_DESC:
            dissect_zbee_zdp_rsp_simple_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_ACTIVE_EP:
            dissect_zbee_zdp_rsp_active_ep(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MATCH_DESC:
            dissect_zbee_zdp_rsp_match_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_COMPLEX_DESC:
            dissect_zbee_zdp_rsp_complex_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_USER_DESC:
            dissect_zbee_zdp_rsp_user_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_DISCOVERY_CACHE:
            dissect_zbee_zdp_rsp_discovery_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_CONF_USER_DESC:
            dissect_zbee_zdp_rsp_user_desc_conf(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_SYSTEM_SERVER_DISC:
            dissect_zbee_zdp_rsp_system_server_disc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_STORE_DISCOVERY:
            dissect_zbee_zdp_rsp_discovery_store(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_STORE_NODE_DESC:
            dissect_zbee_zdp_rsp_store_node_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_STORE_POWER_DESC:
            dissect_zbee_zdp_rsp_store_power_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_STORE_ACTIVE_EP:
            dissect_zbee_zdp_rsp_store_active_ep(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_STORE_SIMPLE_DESC:
            dissect_zbee_zdp_rsp_store_simple_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_REMOVE_NODE_CACHE:
            dissect_zbee_zdp_rsp_remove_node_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_FIND_NODE_CACHE:
            dissect_zbee_zdp_rsp_find_node_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_EXT_SIMPLE_DESC:
            dissect_zbee_zdp_rsp_ext_simple_desc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_EXT_ACTIVE_EP:
            dissect_zbee_zdp_rsp_ext_active_ep(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_END_DEVICE_BIND:
            dissect_zbee_zdp_rsp_end_device_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_BIND:
            dissect_zbee_zdp_rsp_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_UNBIND:
            dissect_zbee_zdp_rsp_unbind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_BIND_REGISTER:
            dissect_zbee_zdp_rsp_bind_register(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_REPLACE_DEVICE:
            dissect_zbee_zdp_rsp_replace_device(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_STORE_BAK_BIND_ENTRY:
            dissect_zbee_zdp_rsp_store_bak_bind_entry(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_REMOVE_BAK_BIND_ENTRY:
            dissect_zbee_zdp_rsp_remove_bak_bind_entry(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_BACKUP_BIND_TABLE:
            dissect_zbee_zdp_rsp_backup_bind_table(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_RECOVER_BIND_TABLE:
            dissect_zbee_zdp_rsp_recover_bind_table(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_BACKUP_SOURCE_BIND:
            dissect_zbee_zdp_rsp_backup_source_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_RECOVER_SOURCE_BIND:
            dissect_zbee_zdp_rsp_recover_source_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_NWK_DISC:
            dissect_zbee_zdp_rsp_mgmt_nwk_disc(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_LQI:
            dissect_zbee_zdp_rsp_mgmt_lqi(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_RTG:
            dissect_zbee_zdp_rsp_mgmt_rtg(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_BIND:
            dissect_zbee_zdp_rsp_mgmt_bind(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_LEAVE:
            dissect_zbee_zdp_rsp_mgmt_leave(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_DIRECT_JOIN:
            dissect_zbee_zdp_rsp_mgmt_direct_join(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_PERMIT_JOIN:
            dissect_zbee_zdp_rsp_mgmt_permit_join(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_CACHE:
            dissect_zbee_zdp_rsp_mgmt_cache(zdp_tvb, pinfo, zdp_tree);
            break;
        case ZBEE_ZDP_RSP_MGMT_NWKUPDATE:
            dissect_zbee_zdp_rsp_mgmt_nwkupdate(zdp_tvb, pinfo, zdp_tree);
            break;
        default:
            /* Invalid Cluster Identifier. */
            call_dissector(data_handle, zdp_tvb, pinfo, tree);
            break;
    } /* switch */
} /* dissect_zbee_zdp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zdp
 *  DESCRIPTION
 *      ZigBee Device Profile protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zbee_zdp(void)
{
    static hf_register_info hf[] = {
        { &hf_zbee_zdp_seqno,
        { "Sequence Number",            "zbee.zdp.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_length,
        { "Length",                     "zbee.zdp.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_ext_addr,
        { "Extended Address",           "zbee.zdp.ext_addr", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_device,
        { "Device",                     "zbee.zdp.device", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_req_type,
        { "Request Type",               "zbee.zdp.req_type", FT_UINT8, BASE_DEC, VALS(zbee_zdp_req_types), 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_index,
        { "Index",                      "zbee.zdp.index", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_status,
        { "Status",                     "zbee.zdp.status", FT_UINT8, BASE_DEC, VALS(zbee_zdp_status_names), 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_endpoint,
        { "Endpoint",                   "zbee.zdp.endpoint", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_ep_count,
        { "Endpoint Count",             "zbee.zdp.ep_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_profile,
        { "Profile",                    "zbee.zdp.profile", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_addr_mode,
        { "Address Mode",               "zbee.zdp.addr_mode", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_cluster,
        { "Cluster",                    "zbee.zdp.cluster", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_table_size,
        { "Table Size",                 "zbee.zdp.table_size", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of entries in the table.", HFILL }},

        { &hf_zbee_zdp_table_count,
        { "Table Count",                "zbee.zdp.table_count", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of table entries included in this message.", HFILL }},

        { &hf_zbee_zdp_in_count,
        { "Input Cluster Count",        "zbee.zdp.in_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_out_count,
        { "Output Cluster Count",       "zbee.zdp.out_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_in_cluster,
        { "Input Cluster",              "zbee.zdp.in_cluster", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_out_cluster,
        { "Output Cluster",             "zbee.zdp.out_cluster", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_assoc_device_count,
        { "Associated Device Count",    "zbee.zdp.assoc_device_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_assoc_device,
        { "Associated Device",          "zbee.zdp.assoc_device", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_cinfo_alt_coord,
        { "Alternate Coordinator",      "zbee.zdp.cinfo.alt_coord", FT_BOOLEAN, 8, NULL, ZBEE_CINFO_ALT_COORD,
            "Indicates that the device is able to operate as a PAN coordinator.", HFILL }},

        { &hf_zbee_zdp_cinfo_ffd,
        { "Full-Function Device",       "zbee.zdp.cinfo.ffd", FT_BOOLEAN, 8, NULL, ZBEE_CINFO_FFD,
            NULL, HFILL }},

        { &hf_zbee_zdp_cinfo_power,
        { "AC Power",                   "zbee.zdp.cinfo.power", FT_BOOLEAN, 8, NULL, ZBEE_CINFO_POWER,
            "Indicates this device is using AC/Mains power.", HFILL }},

        { &hf_zbee_zdp_cinfo_idle_rx,
        { "Rx On When Idle",            "zbee.zdp.cinfo.power", FT_BOOLEAN, 8, NULL, ZBEE_CINFO_IDLE_RX,
            "Indicates the receiver is active when the device is idle.", HFILL }},

        { &hf_zbee_zdp_cinfo_security,
        { "Security Capability",        "zbee.zdp.cinfo.security", FT_BOOLEAN, 8, NULL, ZBEE_CINFO_SECURITY,
            "Indicates this device is capable of performing encryption/decryption.", HFILL }},

        { &hf_zbee_zdp_cinfo_alloc,
        { "Allocate Short Address",     "zbee.zdp.cinfo.alloc", FT_BOOLEAN, 8, NULL, ZBEE_CINFO_ALLOC,
            "Flag requesting the parent to allocate a short address for this device.", HFILL }},

        { &hf_zbee_zdp_server_pri_trust,
        { "Primary Trust Center",       "zbee.zdp.server.pri_trust", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_SERVER_PRIMARY_TRUST,
            NULL, HFILL }},

        { &hf_zbee_zdp_server_bak_trust,
        { "Backup Trust Center",        "zbee.zdp.server.bak_trust", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_SERVER_BACKUP_TRUST,
            NULL, HFILL }},

        { &hf_zbee_zdp_server_pri_bind,
        { "Primary Binding Table Cache","zbee.zdp.server.pri_bind", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_SERVER_PRIMARY_BIND,
            NULL, HFILL }},

        { &hf_zbee_zdp_server_bak_bind,
        { "Backup Binding Table Cache", "zbee.zdp.server.bak_bind", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_SERVER_BACKUP_BIND,
            NULL, HFILL }},

        { &hf_zbee_zdp_server_pri_disc,
        { "Primary Discovery Cache",    "zbee.zdp.server.pri_disc", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_SERVER_PRIMARY_DISC,
            NULL, HFILL }},

        { &hf_zbee_zdp_server_bak_disc,
        { "Backup Discovery Cache",     "zbee.zdp.server.bak_bind", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_SERVER_BACKUP_DISC,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_type,
        { "Type",                       "zbee.zdp.node.type", FT_UINT16, BASE_DEC, NULL, ZBEE_ZDP_NODE_TYPE,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_complex,
        { "Complex Descriptor",         "zbee.zdp.node.complex", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_COMPLEX,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_user,
        { "User Descriptor",            "zbee.zdp.node.user", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_USER,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_freq_868,
        { "868MHz Band",                "zbee.zdp.node.freq.868mhz", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_FREQ_868MHZ,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_freq_900,
        { "900MHz Band",                "zbee.zdp.node.freq.900mhz", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_FREQ_900MHZ,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_freq_2400,
        { "2.4GHz Band",                "zbee.zdp.node.freq.2400mhz", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_NODE_FREQ_2400MHZ,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_manufacturer,
        { "Manufacturer Code",          "zbee.zdp.node.manufacturer", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_max_buffer,
        { "Max Buffer Size",            "zbee.zdp.node.max_buffer", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_node_max_transfer,
        { "Max Transfer Size",          "zbee.zdp.node.max_transfer", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_mode,
        { "Mode",                       "zbee.zdp.power.mode", FT_UINT16, BASE_DEC, NULL, ZBEE_ZDP_POWER_MODE,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_avail_ac,
        { "Available AC Power",         "zbee.zdp.power.avail.ac", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_POWER_AVAIL_AC,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_avail_recharge,
        { "Available Rechargeable Battery", "zbee.zdp.power.avail.rech", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_POWER_AVAIL_RECHARGEABLE,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_avail_dispose,
        { "Available Disposeable Battery",  "zbee.zdp.power.avail.disp", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_POWER_AVAIL_DISPOSEABLE,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_source_ac,
        { "Using AC Power",             "zbee.zdp.power.source.ac", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_POWER_SOURCE_AC,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_source_recharge,
        { "Using Rechargeable Battery", "zbee.zdp.power.source.ac", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_POWER_SOURCE_RECHARGEABLE,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_source_dispose,
        { "Using Disposeable Battery",  "zbee.zdp.power.source.ac", FT_BOOLEAN, 16, NULL, ZBEE_ZDP_POWER_SOURCE_DISPOSEABLE,
            NULL, HFILL }},

        { &hf_zbee_zdp_power_level,
        { "Level",                      "zbee.zdp.power.level", FT_UINT16, BASE_DEC, NULL, ZBEE_ZDP_POWER_LEVEL,
            NULL, HFILL }},

        { &hf_zbee_zdp_simple_app_device,
        { "Application Device",         "zbee.zdp.app.device", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_simple_app_version,
        { "Application Version",        "zbee.zdp.app.version", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_complex_length,
        { "Complex Descriptor Length",  "zbee.zdp.complex_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_complex,
        { "Complex Descriptor",         "zbee.zdp.complex", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_user,
        { "User Descriptor",            "zbee.zdp.user", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_user_length,
        { "User Descriptor Length",     "zbee.zdp.user_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_simple_length,
        { "Simple Descriptor Length",   "zbee.zdp.simple_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_disc_node_size,
        { "Node Descriptor Size",       "zbee.zdp.node_size", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_disc_power_size,
        { "Power Descriptor Size",      "zbee.zdp.power_size", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_cache,
        { "Cache",                      "zbee.zdp.cache", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Address of the device containing the discovery cache.", HFILL }},

        { &hf_zbee_zdp_disc_ep_count,
        { "Active Endpoint Count",      "zbee.zdp.ep_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_disc_simple_count,
        { "Simple Descriptor Count",    "zbee.zdp.simple_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_disc_simple_size,
        { "Simple Descriptor Size",     "zbee.zdp.simple_size", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_target,
        { "Target",                     "zbee.zdp.target", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_target64,
        { "Target",                     "zbee.zdp.target64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_target_ep,
        { "Target Endpoint",            "zbee.zdp.target_ep", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_replacement,
        { "Replacement",                "zbee.zdp.replacement", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_replacement_ep,
        { "Replacement Endpoint",       "zbee.zdp.replacement_ep", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_bind_src,
        { "Source",                     "zbee.zdp.bind.src", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_bind_src64,
        { "Source",                     "zbee.zdp.bind.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_bind_src_ep,
        { "Source Endpoint",            "zbee.zdp.bind.src_ep", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_bind_dst,
        { "Destination",                "zbee.zdp.bind.dst", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_bind_dst64,
        { "Destination",                "zbee.zdp.bind.dst64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_bind_dst_ep,
        { "Destination Endpoint",       "zbee.zdp.bind.dst_ep", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_duration,
        { "Duration",                   "zbee.zdp.duration", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_leave_children,
        { "Remove Children",            "zbee.zdp.leave.children", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_leave_rejoin,
        { "Rejoin",                     "zbee.zdp.leave.rejoin", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_significance,
        { "Significance",               "zbee.zdp.significance", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_scan_count,
        { "Scan Count",                 "zbee.zdp.scan_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_update_id,
        { "Update ID",                  "zbee.zdp.update_id", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_manager,
        { "Network Manager",            "zbee.zdp.manager", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_tx_total,
        { "Total Transmissions",        "zbee.zdp.tx_total", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_tx_fail,
        { "Failed Transmissions",       "zbee.zdp.tx_fail", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_channel_count,
        { "Channel List Count",         "zbee.zdp.channel_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }}
    };

    /*  APS subtrees */
    static gint *ett[] = {
        &ett_zbee_zdp,
        &ett_zbee_zdp_endpoint,
        &ett_zbee_zdp_match_in,
        &ett_zbee_zdp_match_out,
        &ett_zbee_zdp_node,
        &ett_zbee_zdp_node_in,
        &ett_zbee_zdp_node_out,
        &ett_zbee_zdp_power,
        &ett_zbee_zdp_simple,
        &ett_zbee_zdp_complex,
        &ett_zbee_zdp_cinfo,
        &ett_zbee_zdp_server,
        &ett_zbee_zdp_simple_sizes,
        &ett_zbee_zdp_bind,
        &ett_zbee_zdp_bind_end_in,
        &ett_zbee_zdp_bind_end_out,
        &ett_zbee_zdp_bind_table,
        &ett_zbee_zdp_bind_source,
        &ett_zbee_zdp_channels,
        &ett_zbee_zdp_assoc_device,
        &ett_zbee_zdp_nwk,
        &ett_zbee_zdp_lqi,
        &ett_zbee_zdp_rtg,
        &ett_zbee_zdp_cache
    };

    /* Register ZigBee ZDP protocol with Wireshark. */
    proto_zbee_zdp = proto_register_protocol("ZigBee Device Profile", "ZigBee ZDP", "zbee.zdp");
    proto_register_field_array(proto_zbee_zdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZDP dissector. */
    register_dissector("zbee.zdp", dissect_zbee_zdp, proto_zbee_zdp);
} /* proto_register_zbee_zdp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zdp
 *  DESCRIPTION
 *      Registers the Zigbee Device Profile dissector with Wireshark.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_zdp(void)
{
    dissector_handle_t  zdp_handle;

    /* Find the other dissectors we need. */
    data_handle     = find_dissector("data");

    /* Register our dissector with the ZigBee application dissectors. */
    zdp_handle = find_dissector("zbee.zdp");
    dissector_add_uint("zbee.profile", ZBEE_ZDP_PROFILE, zdp_handle);
} /* proto_reg_handoff_zbee_zdp */
