/* packet-zbee-nwk.c
 * Dissector routines for the ZigBee Network Layer (NWK)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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

/*  Include Files */
#include "config.h"


#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-security.h"

/*************************/
/* Function Declarations */
/*************************/
/* Dissector Routines */
static int         dissect_zbee_nwk        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static void        dissect_zbee_nwk_cmd    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zbee_nwk_packet* packet);
static int         dissect_zbee_beacon     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static int         dissect_zbip_beacon     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

/* Command Dissector Helpers */
static guint       dissect_zbee_nwk_route_req  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                zbee_nwk_packet * packet, guint offset);
static guint       dissect_zbee_nwk_route_rep  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 version);
static guint       dissect_zbee_nwk_status     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint       dissect_zbee_nwk_leave      (tvbuff_t *tvb, proto_tree *tree, guint offset);
static guint       dissect_zbee_nwk_route_rec  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                zbee_nwk_packet * packet, guint offset);
static guint       dissect_zbee_nwk_rejoin_req (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                zbee_nwk_packet * packet, guint offset);
static guint       dissect_zbee_nwk_rejoin_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                zbee_nwk_packet * packet, guint offset);
static guint       dissect_zbee_nwk_link_status(tvbuff_t *tvb, proto_tree *tree, guint offset);
static guint       dissect_zbee_nwk_report     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static guint       dissect_zbee_nwk_update     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
static void        proto_init_zbee_nwk         (void);
static void        proto_cleanup_zbee_nwk(void);
void               proto_register_zbee_nwk(void);
void               proto_reg_handoff_zbee_nwk(void);

/********************/
/* Global Variables */
/********************/
static int proto_zbee_nwk = -1;
static int proto_zbee_beacon = -1;
static int proto_zbip_beacon = -1;
static int hf_zbee_nwk_fcf = -1;
static int hf_zbee_nwk_frame_type = -1;
static int hf_zbee_nwk_proto_version = -1;
static int hf_zbee_nwk_discover_route = -1;
static int hf_zbee_nwk_multicast = -1;
static int hf_zbee_nwk_security = -1;
static int hf_zbee_nwk_source_route = -1;
static int hf_zbee_nwk_ext_dst = -1;
static int hf_zbee_nwk_ext_src = -1;
static int hf_zbee_nwk_dst = -1;
static int hf_zbee_nwk_src = -1;
static int hf_zbee_nwk_radius = -1;
static int hf_zbee_nwk_seqno = -1;
static int hf_zbee_nwk_mcast = -1;
static int hf_zbee_nwk_mcast_mode = -1;
static int hf_zbee_nwk_mcast_radius = -1;
static int hf_zbee_nwk_mcast_max_radius = -1;
static int hf_zbee_nwk_dst64 = -1;
static int hf_zbee_nwk_src64 = -1;
static int hf_zbee_nwk_src64_origin = -1;
static int hf_zbee_nwk_relay_count = -1;
static int hf_zbee_nwk_relay_index = -1;
static int hf_zbee_nwk_relay = -1;

static int hf_zbee_nwk_cmd_id = -1;
static int hf_zbee_nwk_cmd_addr = -1;
static int hf_zbee_nwk_cmd_route_id = -1;
static int hf_zbee_nwk_cmd_route_dest = -1;
static int hf_zbee_nwk_cmd_route_orig = -1;
static int hf_zbee_nwk_cmd_route_resp = -1;
static int hf_zbee_nwk_cmd_route_dest_ext = -1;
static int hf_zbee_nwk_cmd_route_orig_ext = -1;
static int hf_zbee_nwk_cmd_route_resp_ext = -1;
static int hf_zbee_nwk_cmd_route_cost = -1;
static int hf_zbee_nwk_cmd_route_options = -1;
static int hf_zbee_nwk_cmd_route_opt_repair = -1;
static int hf_zbee_nwk_cmd_route_opt_multicast = -1;
static int hf_zbee_nwk_cmd_route_opt_dest_ext = -1;
static int hf_zbee_nwk_cmd_route_opt_resp_ext = -1;
static int hf_zbee_nwk_cmd_route_opt_orig_ext = -1;
static int hf_zbee_nwk_cmd_route_opt_many_to_one = -1;
static int hf_zbee_nwk_cmd_nwk_status = -1;
static int hf_zbee_nwk_cmd_leave_rejoin = -1;
static int hf_zbee_nwk_cmd_leave_request = -1;
static int hf_zbee_nwk_cmd_leave_children = -1;
static int hf_zbee_nwk_cmd_relay_count = -1;
static int hf_zbee_nwk_cmd_relay_device = -1;
static int hf_zbee_nwk_cmd_cinfo = -1;
static int hf_zbee_nwk_cmd_cinfo_alt_coord = -1;
static int hf_zbee_nwk_cmd_cinfo_type = -1;
static int hf_zbee_nwk_cmd_cinfo_power = -1;
static int hf_zbee_nwk_cmd_cinfo_idle_rx = -1;
static int hf_zbee_nwk_cmd_cinfo_security = -1;
static int hf_zbee_nwk_cmd_cinfo_alloc = -1;
static int hf_zbee_nwk_cmd_rejoin_status = -1;
static int hf_zbee_nwk_cmd_link_last = -1;
static int hf_zbee_nwk_cmd_link_first = -1;
static int hf_zbee_nwk_cmd_link_count = -1;
static int hf_zbee_nwk_cmd_link_address = -1;
static int hf_zbee_nwk_cmd_link_incoming_cost = -1;
static int hf_zbee_nwk_cmd_link_outgoing_cost = -1;
static int hf_zbee_nwk_cmd_report_type = -1;
static int hf_zbee_nwk_cmd_report_count = -1;
static int hf_zbee_nwk_cmd_update_type = -1;
static int hf_zbee_nwk_cmd_update_count = -1;
static int hf_zbee_nwk_cmd_update_id = -1;
static int hf_zbee_nwk_panid = -1;
static int hf_zbee_nwk_cmd_epid = -1;

/*  ZigBee Beacons */
static int hf_zbee_beacon_protocol = -1;
static int hf_zbee_beacon_stack_profile = -1;
static int hf_zbee_beacon_version = -1;
static int hf_zbee_beacon_router_capacity = -1;
static int hf_zbee_beacon_depth = -1;
static int hf_zbee_beacon_end_device_capacity = -1;
static int hf_zbee_beacon_epid = -1;
static int hf_zbee_beacon_tx_offset = -1;
static int hf_zbee_beacon_update_id = -1;

static int hf_zbip_beacon_allow_join = -1;
static int hf_zbip_beacon_router_capacity = -1;
static int hf_zbip_beacon_host_capacity = -1;
static int hf_zbip_beacon_unsecure = -1;
static int hf_zbip_beacon_network_id = -1;

static gint ett_zbee_nwk = -1;
static gint ett_zbee_beacon = -1;
static gint ett_zbee_nwk_fcf = -1;
static gint ett_zbee_nwk_fcf_ext = -1;
static gint ett_zbee_nwk_mcast = -1;
static gint ett_zbee_nwk_route = -1;
static gint ett_zbee_nwk_cmd = -1;
static gint ett_zbee_nwk_cmd_options = -1;
static gint ett_zbee_nwk_cmd_cinfo = -1;
static gint ett_zbee_nwk_cmd_link = -1;

static expert_field ei_zbee_nwk_missing_payload = EI_INIT;

static dissector_handle_t   data_handle;
static dissector_handle_t   aps_handle;
static dissector_handle_t   zbee_gp_handle;

/********************/
/* Field Names      */
/********************/
/* Frame Types */
static const value_string zbee_nwk_frame_types[] = {
    { ZBEE_NWK_FCF_DATA,    "Data" },
    { ZBEE_NWK_FCF_CMD,     "Command" },
    { 0, NULL }
};

/* Route Discovery Modes */
static const value_string zbee_nwk_discovery_modes[] = {
    { ZBEE_NWK_FCF_DISCOVERY_SUPPRESS,  "Suppress" },
    { ZBEE_NWK_FCF_DISCOVERY_ENABLE,    "Enable" },
    { ZBEE_NWK_FCF_DISCOVERY_FORCE,     "Force" },
    { 0, NULL }
};

/* Command Names*/
static const value_string zbee_nwk_cmd_names[] = {
    { ZBEE_NWK_CMD_ROUTE_REQ,       "Route Request" },
    { ZBEE_NWK_CMD_ROUTE_REPLY,     "Route Reply" },
    { ZBEE_NWK_CMD_NWK_STATUS,      "Network Status" },
    { ZBEE_NWK_CMD_LEAVE,           "Leave" },
    { ZBEE_NWK_CMD_ROUTE_RECORD,    "Route Record" },
    { ZBEE_NWK_CMD_REJOIN_REQ,      "Rejoin Request" },
    { ZBEE_NWK_CMD_REJOIN_RESP,     "Rejoin Response" },
    { ZBEE_NWK_CMD_LINK_STATUS,     "Link Status" },
    { ZBEE_NWK_CMD_NWK_REPORT,      "Network Report" },
    { ZBEE_NWK_CMD_NWK_UPDATE,      "Network Update" },
    { 0, NULL }
};

/* Many-To-One Route Discovery Modes. */
static const value_string zbee_nwk_cmd_route_many_modes[] = {
    { ZBEE_NWK_CMD_ROUTE_OPTION_MANY_NONE,  "Not Many-to-One" },
    { ZBEE_NWK_CMD_ROUTE_OPTION_MANY_REC,   "With Source Routing" },
    { ZBEE_NWK_CMD_ROUTE_OPTION_MANY_NOREC, "Without Source Routing" },
    { 0, NULL }
};

/* Rejoin Status Codes */
static const value_string zbee_nwk_rejoin_codes[] = {
    { IEEE802154_CMD_ASRSP_AS_SUCCESS,      "Success" },
    { IEEE802154_CMD_ASRSP_PAN_FULL,        "PAN Full" },
    { IEEE802154_CMD_ASRSP_PAN_DENIED,      "PAN Access Denied" },
    { 0, NULL }
};

/* Network Report Types */
static const value_string zbee_nwk_report_types[] = {
    { ZBEE_NWK_CMD_NWK_REPORT_ID_PAN_CONFLICT,  "PAN Identifier Conflict" },
    { 0, NULL }
};

/* Network Update Types */
static const value_string zbee_nwk_update_types[] = {
    { ZBEE_NWK_CMD_NWK_UPDATE_ID_PAN_UPDATE,  "PAN Identifier Update" },
    { 0, NULL }
};

/* Network Status Codes */
static const value_string zbee_nwk_status_codes[] = {
    { ZBEE_NWK_STATUS_NO_ROUTE_AVAIL,       "No Route Available" },
    { ZBEE_NWK_STATUS_TREE_LINK_FAIL,       "Tree Link Failure" },
    { ZBEE_NWK_STATUS_NON_TREE_LINK_FAIL,   "Non-tree Link Failure" },
    { ZBEE_NWK_STATUS_LOW_BATTERY,          "Low Battery" },
    { ZBEE_NWK_STATUS_NO_ROUTING,           "No Routing Capacity" },
    { ZBEE_NWK_STATUS_NO_INDIRECT,          "No Indirect Capacity" },
    { ZBEE_NWK_STATUS_INDIRECT_EXPIRE,      "Indirect Transaction Expiry" },
    { ZBEE_NWK_STATUS_DEVICE_UNAVAIL,       "Target Device Unavailable" },
    { ZBEE_NWK_STATUS_ADDR_UNAVAIL,         "Target Address Unallocated" },
    { ZBEE_NWK_STATUS_PARENT_LINK_FAIL,     "Parent Link Failure" },
    { ZBEE_NWK_STATUS_VALIDATE_ROUTE,       "Validate Route" },
    { ZBEE_NWK_STATUS_SOURCE_ROUTE_FAIL,    "Source Route Failure" },
    { ZBEE_NWK_STATUS_MANY_TO_ONE_FAIL,     "Many-to-One Route Failure" },
    { ZBEE_NWK_STATUS_ADDRESS_CONFLICT,     "Address Conflict" },
    { ZBEE_NWK_STATUS_VERIFY_ADDRESS,       "Verify Address" },
    { ZBEE_NWK_STATUS_PANID_UPDATE,         "PAN ID Update" },
    { ZBEE_NWK_STATUS_ADDRESS_UPDATE,       "Network Address Update" },
    { ZBEE_NWK_STATUS_BAD_FRAME_COUNTER,    "Bad Frame Counter" },
    { ZBEE_NWK_STATUS_BAD_KEY_SEQNO,        "Bad Key Sequence Number" },
    { 0, NULL }
};

/* Stack Profile Values. */
static const value_string zbee_nwk_stack_profiles[] = {
    { 0x00, "Network Specific" },
    { 0x01, "ZigBee Home" },
    { 0x02, "ZigBee PRO" },
    { 0, NULL }
};

/* TODO: much of the following copied from ieee80154 dissector */
/*-------------------------------------
 * Hash Tables and Lists
 *-------------------------------------
 */
ieee802154_map_tab_t zbee_nwk_map = { NULL, NULL };
GHashTable *zbee_table_nwk_keyring = NULL;
GHashTable *zbee_table_link_keyring = NULL;

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_get_bit_field
 *  DESCRIPTION
 *      Extracts an integer sub-field from an int with a given mask
 *      if the mask is 0, this will return 0, if the mask is non-
 *      continuous the output is undefined.
 *  PARAMETERS
 *      guint       input
 *      guint       mask
 *  RETURNS
 *      guint
 *---------------------------------------------------------------
 */
guint
zbee_get_bit_field(guint input, guint mask)
{
    /* Sanity Check, don't want infinite loops. */
    if (mask == 0) return 0;
    /* Shift input and mask together. */
    while (!(mask & 0x1)) {
        input >>= 1;
        mask >>=1;
    } /* while */
    return (input & mask);
} /* zbee_get_bit_field */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_heur
 *  DESCRIPTION
 *      Heuristic interpreter for the ZigBee network dissectors.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      Boolean value, whether it handles the packet or not.
 *---------------------------------------------------------------
 */
static gboolean
dissect_zbee_nwk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;
    guint16             fcf;
    guint               ver;

    /* All ZigBee frames must always have a 16-bit source and destination address. */
    if (packet == NULL) return FALSE;
    if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) return FALSE;
    if (packet->dst_addr_mode != IEEE802154_FCF_ADDR_SHORT) return FALSE;

    /* If the frame type and version are not sane, then it's probably not ZigBee. */
    fcf = tvb_get_letohs(tvb, 0);
    ver = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_VERSION);
    if ((ver < ZBEE_VERSION_2004) || (ver > ZBEE_VERSION_2007)) return FALSE;
    if (!try_val_to_str(zbee_get_bit_field(fcf, ZBEE_NWK_FCF_FRAME_TYPE), zbee_nwk_frame_types)) return FALSE;

    /* Assume it's ZigBee */
    dissect_zbee_nwk(tvb, pinfo, tree, packet);
    return TRUE;
} /* dissect_zbee_heur */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_full
 *  DESCRIPTION
 *      ZigBee NWK packet dissection routine for 2006, 2007 and Pro stack versions.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - raw packet private data.
 *  RETURNS
 *      int
 *---------------------------------------------------------------
 */

static int
dissect_zbee_nwk_full(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tvbuff_t            *payload_tvb = NULL;

    proto_item          *proto_root;
    proto_item          *ti = NULL;
    proto_tree          *nwk_tree;

    zbee_nwk_packet     packet;
    ieee802154_packet   *ieee_packet;

    guint               offset = 0;
    gchar               *src_addr, *dst_addr;

    guint16             fcf;

    ieee802154_short_addr   addr16;
    ieee802154_map_rec     *map_rec;
    ieee802154_hints_t     *ieee_hints;

    zbee_nwk_hints_t       *nwk_hints;
    gboolean                unicast_src;

    static const int * fcf_flags_2007[] = {
        &hf_zbee_nwk_frame_type,
        &hf_zbee_nwk_proto_version,
        &hf_zbee_nwk_discover_route,
        &hf_zbee_nwk_multicast,
        &hf_zbee_nwk_security,
        &hf_zbee_nwk_source_route,
        &hf_zbee_nwk_ext_dst,
        &hf_zbee_nwk_ext_src,
        NULL
    };

    static const int * fcf_flags[] = {
        &hf_zbee_nwk_frame_type,
        &hf_zbee_nwk_proto_version,
        &hf_zbee_nwk_discover_route,
        &hf_zbee_nwk_security,
        NULL
    };

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    ieee_packet = (ieee802154_packet *)data;

    memset(&packet, 0, sizeof(packet));

    /* Set up hint structures */
    if (!pinfo->fd->flags.visited) {
        /* Allocate frame data with hints for upper layers */
        nwk_hints = wmem_new0(wmem_file_scope(), zbee_nwk_hints_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_zbee_nwk, 0, nwk_hints);
    } else {
        /* Retrieve existing structure */
        nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_zbee_nwk, 0);
    }

    ieee_hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
            proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);

    /* Add ourself to the protocol column, clear the info column, and create the protocol tree. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_root = proto_tree_add_item(tree, proto_zbee_nwk, tvb, offset, -1, ENC_NA);
    nwk_tree = proto_item_add_subtree(proto_root, ett_zbee_nwk);

    /* Get and parse the FCF */
    fcf = tvb_get_letohs(tvb, offset);
    packet.type         = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_FRAME_TYPE);
    packet.version      = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_VERSION);
    packet.discovery    = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_DISCOVER_ROUTE);
    packet.security     = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_SECURITY);
    packet.multicast    = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_MULTICAST);
    packet.route        = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_SOURCE_ROUTE);
    packet.ext_dst      = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_EXT_DEST);
    packet.ext_src      = zbee_get_bit_field(fcf, ZBEE_NWK_FCF_EXT_SOURCE);

    /* Display the FCF. */
    if (packet.version >= ZBEE_VERSION_2007) {
        ti = proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_fcf, ett_zbee_nwk_fcf, fcf_flags_2007, ENC_LITTLE_ENDIAN);
    } else {
        ti = proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_fcf, ett_zbee_nwk_fcf, fcf_flags, ENC_LITTLE_ENDIAN);
    }
    proto_item_append_text(ti, " %s", val_to_str_const(packet.type, zbee_nwk_frame_types, "Unknown"));
    offset += 2;

    /* Add the frame type to the info column and protocol root. */
    proto_item_append_text(proto_root, " %s", val_to_str_const(packet.type, zbee_nwk_frame_types, "Unknown Type"));
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet.type, zbee_nwk_frame_types, "Reserved Frame Type"));

    /* Get the destination address. */
    packet.dst = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(nwk_tree, hf_zbee_nwk_dst, tvb, offset, 2, packet.dst);

    offset += 2;

    /* Display the destination address. */
    if (   (packet.dst == ZBEE_BCAST_ALL)
        || (packet.dst == ZBEE_BCAST_ACTIVE)
        || (packet.dst == ZBEE_BCAST_ROUTERS)){
        dst_addr = wmem_strdup_printf(pinfo->pool, "Broadcast");
    }
    else {
        dst_addr = wmem_strdup_printf(pinfo->pool, "0x%04x", packet.dst);
    }

    SET_ADDRESS(&pinfo->net_dst, AT_STRINGZ, (int)strlen(dst_addr)+1, dst_addr);
    COPY_ADDRESS_SHALLOW(&pinfo->dst, &pinfo->net_dst);

    proto_item_append_text(proto_root, ", Dst: %s", dst_addr);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", dst_addr);


    /* Get the short nwk source address and pass it to upper layers */
    packet.src = tvb_get_letohs(tvb, offset);
    if (nwk_hints)
        nwk_hints->src = packet.src;
    proto_tree_add_uint(nwk_tree, hf_zbee_nwk_src, tvb, offset, 2, packet.src);
    offset += 2;

    /* Display the source address. */
    if (   (packet.src == ZBEE_BCAST_ALL)
        || (packet.src == ZBEE_BCAST_ACTIVE)
        || (packet.src == ZBEE_BCAST_ROUTERS)){
        /* Source Broadcast doesn't make much sense. */
        src_addr = wmem_strdup_printf(pinfo->pool, "Unexpected Source Broadcast");
        unicast_src = FALSE;
    }
    else {
        src_addr = wmem_strdup_printf(pinfo->pool, "0x%04x", packet.src);
        unicast_src = TRUE;
    }

    SET_ADDRESS(&pinfo->net_src, AT_STRINGZ, (int)strlen(src_addr)+1, src_addr);
    COPY_ADDRESS_SHALLOW(&pinfo->src, &pinfo->net_src);

    proto_item_append_text(proto_root, ", Src: %s", src_addr);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", src_addr);

    /* Get and display the radius. */
    packet.radius = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(nwk_tree, hf_zbee_nwk_radius, tvb, offset, 1, packet.radius);
    offset += 1;

    /* Get and display the sequence number. */
    packet.seqno = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(nwk_tree, hf_zbee_nwk_seqno, tvb, offset, 1, packet.seqno);
    offset += 1;

    /* Add the extended destination address (ZigBee 2006 and later). */
    if ((packet.version >= ZBEE_VERSION_2007) && packet.ext_dst) {
        packet.dst64 = tvb_get_letoh64(tvb, offset);
        proto_tree_add_item(nwk_tree, hf_zbee_nwk_dst64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    /* Display the extended source address. (ZigBee 2006 and later). */
    if (packet.version >= ZBEE_VERSION_2007) {
        addr16.pan = ieee_packet->src_pan;

        if (packet.ext_src) {
            packet.src64 = tvb_get_letoh64(tvb, offset);
            proto_tree_add_item(nwk_tree, hf_zbee_nwk_src64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            if (!pinfo->fd->flags.visited && nwk_hints) {
                /* Provide hints to upper layers */
                nwk_hints->src_pan = ieee_packet->src_pan;

                /* Update nwk extended address hash table */
                if ( unicast_src ) {
                    nwk_hints->map_rec = ieee802154_addr_update(&zbee_nwk_map,
                            packet.src, addr16.pan, packet.src64, pinfo->current_proto, pinfo->fd->num);
                }
            }
        }
        else {
            /* See if extended source info was previously sniffed */
            if (!pinfo->fd->flags.visited && nwk_hints) {
                nwk_hints->src_pan = ieee_packet->src_pan;
                addr16.addr = packet.src;

                map_rec = (ieee802154_map_rec *) g_hash_table_lookup(zbee_nwk_map.short_table, &addr16);
                if (map_rec) {
                    /* found a nwk mapping record */
                    nwk_hints->map_rec = map_rec;
                }
                else {
                    /* does ieee layer know? */
                    map_rec = (ieee802154_map_rec *) g_hash_table_lookup(ieee_packet->short_table, &addr16);
                    if (map_rec) nwk_hints->map_rec = map_rec;
                }
            } /* (!pinfo->fd->flags.visited) */
            else {
                if (nwk_hints && nwk_hints->map_rec ) {
                    /* Display inferred source address info */
                    ti = proto_tree_add_eui64(nwk_tree, hf_zbee_nwk_src64, tvb, offset, 0,
                            nwk_hints->map_rec->addr64);
                    PROTO_ITEM_SET_GENERATED(ti);

                    if ( nwk_hints->map_rec->start_fnum ) {
                        ti = proto_tree_add_uint(nwk_tree, hf_zbee_nwk_src64_origin, tvb, 0, 0,
                            nwk_hints->map_rec->start_fnum);
                    }
                    else {
                        ti = proto_tree_add_uint_format_value(nwk_tree, hf_zbee_nwk_src64_origin, tvb, 0, 0, 0, "Pre-configured");
                    }
                    PROTO_ITEM_SET_GENERATED(ti);
                }
            }
        }

        /* If ieee layer didn't know its extended source address, and nwk layer does, fill it in */
        if (!pinfo->fd->flags.visited) {
            if ( (ieee_packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&
                    ieee_hints && !ieee_hints->map_rec ) {
                addr16.pan = ieee_packet->src_pan;
                addr16.addr = ieee_packet->src16;
                map_rec = (ieee802154_map_rec *) g_hash_table_lookup(zbee_nwk_map.short_table, &addr16);

                if (map_rec) {
                    /* found a ieee mapping record */
                    ieee_hints->map_rec = map_rec;
                }
            }
        } /* (!pinfo->fd->flags.visited */
    } /* (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) */

    /* Add multicast control field (ZigBee 2006 and later). */
    if ((packet.version >= ZBEE_VERSION_2007) && packet.multicast) {
        static const int * multicast_flags[] = {
            &hf_zbee_nwk_mcast_mode,
            &hf_zbee_nwk_mcast_radius,
            &hf_zbee_nwk_mcast_max_radius,
            NULL
        };

        guint8 mcast_control = tvb_get_guint8(tvb, offset);
        packet.mcast_mode = zbee_get_bit_field(mcast_control, ZBEE_NWK_MCAST_MODE);
        packet.mcast_radius = zbee_get_bit_field(mcast_control, ZBEE_NWK_MCAST_RADIUS);
        packet.mcast_max_radius = zbee_get_bit_field(mcast_control, ZBEE_NWK_MCAST_MAX_RADIUS);

        proto_tree_add_bitmask(nwk_tree, tvb, offset, hf_zbee_nwk_mcast, ett_zbee_nwk_mcast, multicast_flags, ENC_NA);
        offset += 1;
    }

    /* Add the Source Route field. (ZigBee 2006 and later). */
    if ((packet.version >= ZBEE_VERSION_2007) && packet.route) {
        proto_tree *field_tree;
        guint8      relay_count;
        guint16     relay_addr;
        guint       i;

        /* Create a subtree for the source route field. */
        field_tree = proto_tree_add_subtree(nwk_tree, tvb, offset, 1, ett_zbee_nwk_route, &ti, "Source Route");

        /* Get and display the relay count. */
        relay_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_relay_count, tvb, offset, 1, relay_count);
        proto_item_append_text(ti, ", Length: %d", relay_count);
        offset += 1;

        /* Correct the length of the source route fields. */
        proto_item_set_len(ti, 1 + relay_count*2);

        /* Get and display the relay index. */
        proto_tree_add_item(field_tree, hf_zbee_nwk_relay_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* Get and display the relay list. */
        for (i=0; i<relay_count; i++) {
            relay_addr = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint_format(field_tree, hf_zbee_nwk_relay, tvb, offset, 2, relay_addr, "Relay %d: 0x%04x", i+1, relay_addr);
            offset += 2;
        } /* for */
    }

    /*
     * Ensure that the payload exists. There are no valid ZigBee network
     * packets that have no payload.
     */
    if (offset >= tvb_captured_length(tvb)) {
        /* Non-existent or truncated payload. */
        expert_add_info(pinfo, proto_root, &ei_zbee_nwk_missing_payload);
        THROW(BoundsError);
    }
    /* Payload is encrypted, attempt security operations. */
    else if (packet.security) {
        payload_tvb = dissect_zbee_secure(tvb, pinfo, nwk_tree, offset);
        if (payload_tvb == NULL) {
            /* If Payload_tvb is NULL, then the security dissector cleaned up. */
            return tvb_captured_length(tvb);
        }
    }
    /* Plaintext payload. */
    else {
        payload_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    if (packet.type == ZBEE_NWK_FCF_CMD) {
        /* Dissect the Network Command. */
        dissect_zbee_nwk_cmd(payload_tvb, pinfo, nwk_tree, &packet);
    }
    else if (packet.type == ZBEE_NWK_FCF_DATA) {
        /* Dissect the Network Payload (APS layer). */
        call_dissector_with_data(aps_handle, payload_tvb, pinfo, tree, &packet);
    }
    else {
        /* Invalid type. */
        call_dissector(data_handle, payload_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_nwk */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk
 *  DESCRIPTION
 *      ZigBee packet dissection with proto version determination.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *      void *data          - raw packet private data.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static int
dissect_zbee_nwk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint8 fcf0;
    guint8 proto_version;

    fcf0 = tvb_get_guint8(tvb, 0);
    proto_version = (fcf0 & ZBEE_NWK_FCF_VERSION) >> 2;
    if (proto_version == ZBEE_VERSION_GREEN_POWER) {
        call_dissector(zbee_gp_handle, tvb, pinfo, tree);
    } else {
        /* TODO: add check for FCF proto versions. */
        dissect_zbee_nwk_full(tvb, pinfo, tree, data);
    }
    return tvb_captured_length(tvb);
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_cmd
 *  DESCRIPTION
 *      ZigBee Network command packet dissection routine for Wireshark.
 *          note: this dissector differs from others in that it shouldn't be
 *                  passed the main tree pointer, but the nwk tree instead.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zbee_nwk_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zbee_nwk_packet* packet)
{
    proto_tree  *cmd_tree;
    proto_item  *cmd_root;

    guint       offset=0;
    guint8      cmd_id = tvb_get_guint8(tvb, offset);

    /* Create a subtree for this command. */
    cmd_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_zbee_nwk_cmd, &cmd_root, "Command Frame: %s",
                                    val_to_str_const(cmd_id, zbee_nwk_cmd_names, "Unknown"));

    /* Add the command ID. */
    proto_tree_add_uint(cmd_tree, hf_zbee_nwk_cmd_id, tvb, offset, 1, cmd_id);
    offset += 1;

    /* Add the command name to the info column. */
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, zbee_nwk_cmd_names, "Unknown Command"));


    /* Handle the command. */
    switch(cmd_id){
        case ZBEE_NWK_CMD_ROUTE_REQ:
            /* Route Request Command. */
            offset = dissect_zbee_nwk_route_req(tvb, pinfo, cmd_tree, packet, offset);
            break;

        case ZBEE_NWK_CMD_ROUTE_REPLY:
            /* Route Reply Command. */
            offset = dissect_zbee_nwk_route_rep(tvb, pinfo, cmd_tree, offset, packet->version);
            break;

        case ZBEE_NWK_CMD_NWK_STATUS:
            /* Network Status Command. */
            offset = dissect_zbee_nwk_status(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_NWK_CMD_LEAVE:
            /* Leave Command. */
            offset = dissect_zbee_nwk_leave(tvb, cmd_tree, offset);
            break;

        case ZBEE_NWK_CMD_ROUTE_RECORD:
            /* Route Record Command. */
            offset = dissect_zbee_nwk_route_rec(tvb, pinfo, cmd_tree, packet, offset);
            break;

        case ZBEE_NWK_CMD_REJOIN_REQ:
            /* Rejoin Request Command. */
            offset = dissect_zbee_nwk_rejoin_req(tvb, pinfo, cmd_tree, packet, offset);
            break;

        case ZBEE_NWK_CMD_REJOIN_RESP:
            /* Rejoin Response Command. */
            offset = dissect_zbee_nwk_rejoin_resp(tvb, pinfo, cmd_tree, packet, offset);
            break;

        case ZBEE_NWK_CMD_LINK_STATUS:
            /* Link Status Command. */
            offset = dissect_zbee_nwk_link_status(tvb, cmd_tree, offset);
            break;

        case ZBEE_NWK_CMD_NWK_REPORT:
            /* Network Report Command. */
            offset = dissect_zbee_nwk_report(tvb, pinfo, cmd_tree, offset);
            break;

        case ZBEE_NWK_CMD_NWK_UPDATE:
            /* Network Update Command. */
            offset = dissect_zbee_nwk_update(tvb, pinfo, cmd_tree, offset);
            break;

        default:
            /* Just break out and let the overflow handler deal with the payload. */
            break;
    } /* switch */

    /* There is excess data in the packet. */
    if (offset < tvb_captured_length(tvb)) {
        /* There are leftover bytes! */
        tvbuff_t    *leftover_tvb   = tvb_new_subset_remaining(tvb, offset);
        proto_tree  *root;

        /* Correct the length of the command tree. */
        root = proto_tree_get_root(tree);
        proto_item_set_len(cmd_root, offset);

        /* Dump the leftover to the data dissector. */
        call_dissector(data_handle, leftover_tvb, pinfo, root);
    }
} /* dissect_zbee_nwk_cmd */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_route_req
 *  DESCRIPTION
 *      Helper dissector for the Route Request command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      zbee_nwk_packet *packet - pointer to the network packet struct.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_route_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zbee_nwk_packet * packet, guint offset)
{
    guint8  route_options;
    guint16 dest_addr;

    static const int * nwk_route_command_options_2007[] = {
        &hf_zbee_nwk_cmd_route_opt_multicast,
        &hf_zbee_nwk_cmd_route_opt_dest_ext,
        &hf_zbee_nwk_cmd_route_opt_many_to_one,
        NULL
    };

    static const int * nwk_route_command_options[] = {
        &hf_zbee_nwk_cmd_route_opt_repair,
        NULL
    };

    /* Get and display the route options field. */
    route_options = tvb_get_guint8(tvb, offset);
    if (packet->version >= ZBEE_VERSION_2007) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_cmd_route_options, ett_zbee_nwk_cmd_options, nwk_route_command_options_2007, ENC_NA);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_cmd_route_options, ett_zbee_nwk_cmd_options, nwk_route_command_options, ENC_NA);
    }
    offset += 1;

    /* Get and display the route request ID. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the destination address. */
    dest_addr = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_dest, tvb, offset, 2, dest_addr);
    offset += 2;

    /* Get and display the path cost. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_cost, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the extended destination address. */
    if (route_options & ZBEE_NWK_CMD_ROUTE_OPTION_DEST_EXT) {
        proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_dest_ext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: 0x%04x, Src: 0x%04x", dest_addr, packet->src);

    /* Done */
    return offset;
} /* dissect_zbee_nwk_route_req */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_route_rep
 *  DESCRIPTION
 *      Helper dissector for the Route Reply command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_route_rep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 version)
{
    guint8  route_options;
    guint16 orig_addr;
    guint16 resp_addr;

    static const int * nwk_route_command_options_2007[] = {
        &hf_zbee_nwk_cmd_route_opt_multicast,
        &hf_zbee_nwk_cmd_route_opt_resp_ext,
        &hf_zbee_nwk_cmd_route_opt_orig_ext,
        NULL
    };

    static const int * nwk_route_command_options[] = {
        &hf_zbee_nwk_cmd_route_opt_repair,
        NULL
    };

    /* Get and display the route options field. */
    route_options = tvb_get_guint8(tvb, offset);
    if (version >= ZBEE_VERSION_2007) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_cmd_route_options, ett_zbee_nwk_cmd_options, nwk_route_command_options_2007, ENC_NA);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_cmd_route_options, ett_zbee_nwk_cmd_options, nwk_route_command_options, ENC_NA);
    }
    offset += 1;

    /* Get and display the route request ID. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the originator address. */
    orig_addr = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_orig, tvb, offset, 2, orig_addr);
    offset += 2;

    /* Get and display the responder address. */
    resp_addr = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_resp, tvb, offset, 2, resp_addr);
    offset += 2;

    /* Get and display the path cost. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_cost, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the originator extended address. */
    if (route_options & ZBEE_NWK_CMD_ROUTE_OPTION_ORIG_EXT) {
        proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_orig_ext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    /* Get and display the responder extended address. */
    if (route_options & ZBEE_NWK_CMD_ROUTE_OPTION_RESP_EXT) {
        proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_resp_ext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: 0x%04x, Src: 0x%04x", resp_addr, orig_addr);

    /* Done */
    return offset;
} /* dissect_zbee_nwk_route_rep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_status
 *  DESCRIPTION
 *      Helper dissector for the Network Status command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  status_code;
    guint16 addr;

    /* Get and display the status code. */
    status_code = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_nwk_status, tvb, offset, 1, status_code);
    offset += 1;

    /* Get and display the destination address. */
    addr = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_dest, tvb, offset, 2, addr);
    offset += 2;

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", 0x%04x: %s", addr, val_to_str_const(status_code, zbee_nwk_status_codes, "Unknown Status Code"));

    /* Done */
    return offset;
} /* dissect_zbee_nwk_status */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_leave
 *  DESCRIPTION
 *      Helper dissector for the Leave command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_leave(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    static const int * leave_options[] = {
        &hf_zbee_nwk_cmd_leave_rejoin,
        &hf_zbee_nwk_cmd_leave_request,
        &hf_zbee_nwk_cmd_leave_children,
        NULL
    };

    /* Get and display the leave options. */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, leave_options, ENC_NA);
    offset += 1;

    /* Done */
    return offset;
} /* dissect_zbee_nwk_leave */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_route_rec
 *  DESCRIPTION
 *      Helper dissector for the Reoute Record command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      zbee_nwk_packet *packet - pointer to the network packet struct.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_route_rec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zbee_nwk_packet * packet, guint offset)
{
    guint8  relay_count;
    guint16 relay_addr;
    guint   i;

    /* Get and display the relay count. */
    relay_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_relay_count, tvb, offset, 1, relay_count);
    offset += 1;

    /* Get and display the relay addresses. */
    for (i=0; i<relay_count; i++) {
        relay_addr = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint_format(tree, hf_zbee_nwk_cmd_relay_device, tvb, offset, 2, relay_addr,
                                   "Relay Device %d: 0x%04x", i+1, relay_addr);
        offset += 2;
    } /* for */

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: 0x%04x", packet->dst);


    /* Done */
    return offset;
} /* dissect_zbee_nwk_route_rec */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_rejoin_req
 *  DESCRIPTION
 *      Helper dissector for the Rejoin Request command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      zbee_nwk_packet *packet - pointer to the network packet struct.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_rejoin_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zbee_nwk_packet * packet, guint offset)
{
    static const int * capabilities[] = {
        &hf_zbee_nwk_cmd_cinfo_alt_coord,
        &hf_zbee_nwk_cmd_cinfo_type,
        &hf_zbee_nwk_cmd_cinfo_power,
        &hf_zbee_nwk_cmd_cinfo_idle_rx,
        &hf_zbee_nwk_cmd_cinfo_security,
        &hf_zbee_nwk_cmd_cinfo_alloc,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_cmd_cinfo, ett_zbee_nwk_cmd_cinfo, capabilities, ENC_NA);
    offset += 1;

    /* Update the info column.*/
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Device: 0x%04x", packet->src);

    /* Done */
    return offset;
} /* dissect_zbee_nwk_rejoin_req */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_rejoin_resp
 *  DESCRIPTION
 *      Helper dissector for the Rejoin Response command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      zbee_nwk_packet *packet - pointer to the network packet struct.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_rejoin_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zbee_nwk_packet * packet, guint offset)
{
    guint8  status;

    /* Get and display the short address. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Get and display the rejoin status. */
    status = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_rejoin_status, tvb, offset, 1, status);
    offset += 1;

    /* Update the info column. */
    if (status == IEEE802154_CMD_ASRSP_AS_SUCCESS) {
       col_append_fstr(pinfo->cinfo, COL_INFO, ", Address: 0x%04x", packet->src);
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(status, zbee_nwk_rejoin_codes, "Unknown Rejoin Response"));
    }

    /* Done */
    return offset;
} /* dissect_zbee_nwk_rejoin_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_link_status
 *  DESCRIPTION
 *      Helper dissector for the Link Status command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_link_status(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8  options;
    int     i, link_count;
    proto_tree *subtree;
    static const int * link_options[] = {
        &hf_zbee_nwk_cmd_link_last,
        &hf_zbee_nwk_cmd_link_first,
        &hf_zbee_nwk_cmd_link_count,
        NULL
    };

    /* Get and Display the link status options. */
    options = tvb_get_guint8(tvb, offset);
    link_count = options & ZBEE_NWK_CMD_LINK_OPTION_COUNT_MASK;
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, link_options, ENC_NA);
    offset += 1;

    /* Get and Display the link status list. */
    for (i=0; i<link_count; i++) {
        /* Get the address and link status. */
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 3, ett_zbee_nwk_cmd_link, NULL, "Link %d", i+1);
        proto_tree_add_item(subtree, hf_zbee_nwk_cmd_link_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(subtree, hf_zbee_nwk_cmd_link_incoming_cost, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_zbee_nwk_cmd_link_outgoing_cost, tvb, offset+2, 1, ENC_NA);
        offset += (2+1);
    } /* for */

    /* TODO: Update the info column. */
    return offset;
} /* dissect_zbee_nwk_link_status */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_report
 *  DESCRIPTION
 *      Helper dissector for the Network Report command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  options;
    guint8  report_type;
    int     report_count;
    int     i;

    /* Get and display the command options field. */
    options = tvb_get_guint8(tvb, offset);
    report_count = options & ZBEE_NWK_CMD_NWK_REPORT_COUNT_MASK;
    report_type = options & ZBEE_NWK_CMD_NWK_REPORT_ID_MASK;
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_report_type, tvb, offset, 1, report_type);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_report_count, tvb, offset, 1, report_count);
    offset += 1;

    /* Get and display the epid. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_epid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    if (report_type == ZBEE_NWK_CMD_NWK_REPORT_ID_PAN_CONFLICT) {

        /* Report information contains a list of PANS with range of the sender. */
        for (i=0; i<report_count; i++) {
            proto_tree_add_item(tree, hf_zbee_nwk_panid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } /* for */
    }

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(report_type, zbee_nwk_report_types, "Unknown Report Type"));

    /* Done */
    return offset;
} /* dissect_zbee_nwk_report */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_update
 *  DESCRIPTION
 *      Helper dissector for the Network Update command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to the command subtree.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static guint
dissect_zbee_nwk_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8  options;
    guint8  update_type;
    guint8  update_id;
    int     update_count;
    int     i;

    /* Get and display the command options field. */
    options = tvb_get_guint8(tvb, offset);
    update_count = options & ZBEE_NWK_CMD_NWK_UPDATE_COUNT_MASK;
    update_type = options & ZBEE_NWK_CMD_NWK_UPDATE_ID_MASK;
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_update_type, tvb, offset, 1, update_type);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_update_count, tvb, offset, 1, update_count);
    offset += 1;

    /* Get and display the epid. */
    proto_tree_add_item(tree, hf_zbee_nwk_cmd_epid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Get and display the updateID. */
    update_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_zbee_nwk_cmd_update_id, tvb, offset, 1, update_id);
    offset += 1;

    if (update_type == ZBEE_NWK_CMD_NWK_UPDATE_ID_PAN_UPDATE) {

        /* Report information contains a list of PANS with range of the sender. */
        for (i=0; i<update_count; i++) {
            proto_tree_add_item(tree, hf_zbee_nwk_panid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } /* for */
    }

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(update_type, zbee_nwk_update_types, "Unknown Update Type"));

    /* Done */
    return offset;
} /* dissect_zbee_nwk_update */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_beacon_heur
 *  DESCRIPTION
 *      Heuristic interpreter for the ZigBee PRO beacon dissectors.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      Boolean value, whether it handles the packet or not.
 *---------------------------------------------------------------
 */
static gboolean
dissect_zbee_beacon_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;

    /* All ZigBee frames must always have a 16-bit source address. */
    if (!packet) return FALSE;
    if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) return FALSE;

    /* ZigBee beacons begin with a protocol identifier. */
    if (tvb_get_guint8(tvb, 0) != ZBEE_NWK_BEACON_PROTOCOL_ID) return FALSE;
    dissect_zbee_beacon(tvb, pinfo, tree, packet);
    return TRUE;
} /* dissect_zbee_beacon_heur */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_beacon
 *  DESCRIPTION
 *      Dissector for ZigBee network beacons.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static int dissect_zbee_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    ieee802154_packet   *packet;

    proto_item  *beacon_root;
    proto_tree  *beacon_tree;
    guint       offset = 0;

    guint8      version;
    guint64     epid;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    packet = (ieee802154_packet *)data;

    /* Add ourself to the protocol column. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee");
    /* Create the tree for this beacon. */
    beacon_root = proto_tree_add_item(tree, proto_zbee_beacon, tvb, 0, -1, ENC_NA);
    beacon_tree = proto_item_add_subtree(beacon_root, ett_zbee_beacon);

    /* Update the info column. */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Beacon, Src: 0x%04x", packet->src16);

    /* Get and display the protocol id, must be 0 on all ZigBee beacons. */
    proto_tree_add_item(beacon_tree, hf_zbee_beacon_protocol, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the stack profile and protocol version. */
    version = zbee_get_bit_field(tvb_get_guint8(tvb, offset), ZBEE_NWK_BEACON_PROTOCOL_VERSION);
    proto_tree_add_item(beacon_tree, hf_zbee_beacon_stack_profile, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(beacon_tree, hf_zbee_beacon_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Get and display the security level and flags. */
    proto_tree_add_item(beacon_tree, hf_zbee_beacon_router_capacity, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(beacon_tree, hf_zbee_beacon_depth, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(beacon_tree, hf_zbee_beacon_end_device_capacity, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (version >= ZBEE_VERSION_2007) {
        /* In ZigBee 2006 and later, the beacon contains an extended PAN ID. */
        epid = tvb_get_letoh64(tvb, offset);
        proto_tree_add_item(beacon_tree, hf_zbee_beacon_epid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        /* Update the Info Column with the EPID. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", EPID: %s", eui64_to_display(wmem_packet_scope(), epid));

        /*
         * In ZigBee 2006 the Tx-Offset is optional, while in the 2007 and
         * later versions, the Tx-Offset is a required value. Since both 2006 and
         * and 2007 versions have the same protocol version (2), we should treat
         * the Tx-Offset as well as the update ID as optional elements
         */
        if (tvb_bytes_exist(tvb, offset, 3)) {
            proto_tree_add_item(beacon_tree, hf_zbee_beacon_tx_offset, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            /* Get and display the update ID. */
            if(tvb_captured_length_remaining(tvb, offset)) {
                proto_tree_add_item(beacon_tree, hf_zbee_beacon_update_id, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
    }
    else if (tvb_bytes_exist(tvb, offset, 3)) {
        /* In ZigBee 2004, the Tx-Offset is an optional value. */
        proto_tree_add_item(beacon_tree, hf_zbee_beacon_tx_offset, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        /* Update the info column with the PAN ID. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", packet->src_pan);
    }

    /* Check for leftover bytes. */
    if (offset < tvb_captured_length(tvb)) {
        /* Bytes leftover! */
        tvbuff_t    *leftover_tvb   = tvb_new_subset_remaining(tvb, offset);
        proto_tree  *root;

        /* Correct the length of the beacon tree. */
        root = proto_tree_get_root(tree);
        proto_item_set_len(beacon_root, offset);

        /* Dump the leftover to the data dissector. */
        call_dissector(data_handle, leftover_tvb, pinfo, root);
    }

    return tvb_captured_length(tvb);
} /* dissect_zbee_beacon */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbip_beacon_heur
 *  DESCRIPTION
 *      Heuristic interpreter for the ZigBee IP beacon dissectors.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      Boolean value, whether it handles the packet or not.
 *---------------------------------------------------------------
 */
static gboolean
dissect_zbip_beacon_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;

    /* All ZigBee frames must always have a 16-bit source address. */
    if (!packet) return FALSE;
    if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) return FALSE;

    /* ZigBee beacons begin with a protocol identifier. */
    if (tvb_get_guint8(tvb, 0) != ZBEE_IP_BEACON_PROTOCOL_ID) return FALSE;
    dissect_zbip_beacon(tvb, pinfo, tree, packet);
    return TRUE;
} /* dissect_zbip_beacon_heur */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbip_beacon
 *  DESCRIPTION
 *      Dissector for ZigBee IP beacons.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static int dissect_zbip_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;

    proto_item  *beacon_root;
    proto_tree  *beacon_tree;
    guint       offset = 0;
    guint8      proto_id;
    char        *ssid;

    /* Reject the packet if data is NULL */
    if (!packet) return 0;

    /* Add ourself to the protocol column. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee IP");
    /* Create the tree for this beacon. */
    beacon_root = proto_tree_add_item(tree, proto_zbip_beacon, tvb, 0, -1, ENC_NA);
    beacon_tree = proto_item_add_subtree(beacon_root, ett_zbee_beacon);

    /* Update the info column. */
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Beacon, Src: 0x%04x", packet->src16);

    /* Get and display the protocol id, must be 0x02 on all ZigBee beacons. */
    proto_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(beacon_tree, hf_zbee_beacon_protocol, tvb, offset, 1, proto_id);
    offset += 1;

    /* Get and display the beacon flags */
    proto_tree_add_item(beacon_tree, hf_zbip_beacon_allow_join, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(beacon_tree, hf_zbip_beacon_router_capacity, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(beacon_tree, hf_zbip_beacon_host_capacity, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(beacon_tree, hf_zbip_beacon_unsecure, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get and display the network ID. */
    proto_tree_add_item(beacon_tree, hf_zbip_beacon_network_id, tvb, offset, 16, ENC_ASCII|ENC_NA);

    ssid = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 16, ENC_ASCII|ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", SSID: %s", ssid);
    offset += 16;

    /* Check for leftover bytes. */
    if (offset < tvb_captured_length(tvb)) {
        /* TODO: There are TLV's to parse. */
        /* Bytes leftover! */
        tvbuff_t    *leftover_tvb   = tvb_new_subset_remaining(tvb, offset);
        proto_tree  *root;

        /* Correct the length of the beacon tree. */
        root = proto_tree_get_root(tree);
        proto_item_set_len(beacon_root, offset);

        /* Dump the leftover to the data dissector. */
        call_dissector(data_handle, leftover_tvb, pinfo, root);
    }
    return tvb_captured_length(tvb);
} /* dissect_zbip_beacon */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_nwk
 *  DESCRIPTION
 *      ZigBee protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zbee_nwk(void)
{
    static hf_register_info hf[] = {

            { &hf_zbee_nwk_fcf,
            { "Frame Control Field",             "zbee_nwk.fcf", FT_UINT16, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

            { &hf_zbee_nwk_frame_type,
            { "Frame Type",             "zbee_nwk.frame_type", FT_UINT16, BASE_HEX, VALS(zbee_nwk_frame_types),
                ZBEE_NWK_FCF_FRAME_TYPE, NULL, HFILL }},

            { &hf_zbee_nwk_proto_version,
            { "Protocol Version",       "zbee_nwk.proto_version", FT_UINT16, BASE_DEC, NULL, ZBEE_NWK_FCF_VERSION,
                NULL, HFILL }},

            { &hf_zbee_nwk_discover_route,
            { "Discover Route",         "zbee_nwk.discovery", FT_UINT16, BASE_HEX, VALS(zbee_nwk_discovery_modes),
                ZBEE_NWK_FCF_DISCOVER_ROUTE,
                "Determines how route discovery may be handled, if at all.", HFILL }},

            { &hf_zbee_nwk_multicast,
            { "Multicast",              "zbee_nwk.multicast", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_MULTICAST,
                NULL, HFILL }},

            { &hf_zbee_nwk_security,
            { "Security",               "zbee_nwk.security", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_SECURITY,
                "Whether or not security operations are performed on the network payload.", HFILL }},

            { &hf_zbee_nwk_source_route,
            { "Source Route",           "zbee_nwk.src_route", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_SOURCE_ROUTE,
                NULL, HFILL }},

            { &hf_zbee_nwk_ext_dst,
            { "Destination",            "zbee_nwk.ext_dst", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_EXT_DEST,
                NULL, HFILL }},

            { &hf_zbee_nwk_ext_src,
            { "Extended Source",        "zbee_nwk.ext_src", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_EXT_SOURCE,
                NULL, HFILL }},

            { &hf_zbee_nwk_dst,
            { "Destination",            "zbee_nwk.dst", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_src,
            { "Source",                 "zbee_nwk.src", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_radius,
            { "Radius",                 "zbee_nwk.radius", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of hops remaining for a range-limited broadcast packet.", HFILL }},

            { &hf_zbee_nwk_seqno,
            { "Sequence Number",        "zbee_nwk.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_mcast,
            { "Multicast Control Field",         "zbee_nwk.multicast", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_mcast_mode,
            { "Multicast Mode",         "zbee_nwk.multicast.mode", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_MCAST_MODE,
                "Controls whether this packet is permitted to be routed through non-members of the multicast group.",
                HFILL }},

            { &hf_zbee_nwk_mcast_radius,
            { "Non-Member Radius",      "zbee_nwk.multicast.radius", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_MCAST_RADIUS,
                "Limits the range of multicast packets when being routed through non-members.", HFILL }},

            { &hf_zbee_nwk_mcast_max_radius,
            { "Max Non-Member Radius",  "zbee_nwk.multicast.max_radius", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_MCAST_MAX_RADIUS, NULL, HFILL }},

            { &hf_zbee_nwk_dst64,
            { "Destination",   "zbee_nwk.dst64", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_src64,
            { "Extended Source",        "zbee_nwk.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_src64_origin,
            { "Origin",        "zbee_nwk.src64.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_relay_count,
            { "Relay Count",            "zbee_nwk.relay.count", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of entries in the relay list.", HFILL }},

            { &hf_zbee_nwk_relay_index,
            { "Relay Index",            "zbee_nwk.relay.index", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of relays required to route to the source device.", HFILL }},

            { &hf_zbee_nwk_relay,
            { "Relay",            "zbee_nwk.relay", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_id,
            { "Command Identifier",     "zbee_nwk.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_nwk_cmd_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_addr,
            { "Address",                "zbee_nwk.cmd.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_id,
            { "Route ID",               "zbee_nwk.cmd.route.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                "A sequence number for routing commands.", HFILL }},

            { &hf_zbee_nwk_cmd_route_dest,
            { "Destination",            "zbee_nwk.cmd.route.dest", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_orig,
            { "Originator",             "zbee_nwk.cmd.route.orig", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_resp,
            { "Responder",              "zbee_nwk.cmd.route.resp", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_dest_ext,
            { "Extended Destination",   "zbee_nwk.cmd.route.dest_ext", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_orig_ext,
            { "Extended Originator",    "zbee_nwk.cmd.route.orig_ext", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_resp_ext,
            { "Extended Responder",     "zbee_nwk.cmd.route.resp_ext", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_cost,
            { "Path Cost",              "zbee_nwk.cmd.route.cost", FT_UINT8, BASE_DEC, NULL, 0x0,
                "A value specifying the efficiency of this route.", HFILL }},

            { &hf_zbee_nwk_cmd_route_options,
            { "Command Options",           "zbee_nwk.cmd.route.opts", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_repair,
            { "Route Repair",           "zbee_nwk.cmd.route.opts.repair", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_REPAIR,
                "Flag identifying whether the route request command was to repair a failed route.", HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_multicast,
            { "Multicast",              "zbee_nwk.cmd.route.opts.mcast", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_MCAST,
                "Flag identifying this as a multicast route request.", HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_dest_ext,
            { "Extended Destination",   "zbee_nwk.cmd.route.opts.dest_ext", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_DEST_EXT, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_resp_ext,
            { "Extended Responder",   "zbee_nwk.cmd.route.opts.resp_ext", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_RESP_EXT, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_orig_ext,
            { "Extended Originator",    "zbee_nwk.cmd.route.opts.orig_ext", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_ORIG_EXT, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_many_to_one,
            { "Many-to-One Discovery",  "zbee_nwk.cmd.route.opts.many2one", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_cmd_route_many_modes), ZBEE_NWK_CMD_ROUTE_OPTION_MANY_MASK,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_nwk_status,
            { "Status Code",            "zbee_nwk.cmd.status", FT_UINT8, BASE_HEX, VALS(zbee_nwk_status_codes), 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_leave_rejoin,
            { "Rejoin",                 "zbee_nwk.cmd.leave.rejoin", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LEAVE_OPTION_REJOIN, "Flag instructing the device to rejoin the network.", HFILL }},

            { &hf_zbee_nwk_cmd_leave_request,
            { "Request",                "zbee_nwk.cmd.leave.request", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LEAVE_OPTION_REQUEST,
                "Flag identifying the direction of this command. 1=Request, 0=Indication", HFILL }},

            { &hf_zbee_nwk_cmd_leave_children,
            { "Remove Children",        "zbee_nwk.cmd.leave.children", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LEAVE_OPTION_CHILDREN,
                "Flag instructing the device to remove its children in addition to itself.", HFILL }},

            { &hf_zbee_nwk_cmd_relay_count,
            { "Relay Count",            "zbee_nwk.cmd.relay_count", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of relays required to route to the destination.", HFILL }},

            { &hf_zbee_nwk_cmd_relay_device,
            { "Relay Device",            "zbee_nwk.cmd.relay_device", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_cinfo,
            { "Capability Information",  "zbee_nwk.cmd.cinfo", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_alt_coord,
            { "Alternate Coordinator",  "zbee_nwk.cmd.cinfo.alt_coord", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_ALT_PAN_COORD,
                "Indicates that the device is able to operate as a PAN coordinator.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_type,
            { "Full-Function Device",   "zbee_nwk.cmd.cinfo.ffd", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_DEVICE_TYPE, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_power,
            { "AC Power",               "zbee_nwk.cmd.cinfo.power", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_POWER_SRC, "Indicates this device is using AC/Mains power.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_idle_rx,
            { "Rx On When Idle",        "zbee_nwk.cmd.cinfo.power", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_IDLE_RX,
                "Indicates the receiver is active when the device is idle.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_security,
            { "Security Capability",    "zbee_nwk.cmd.cinfo.security", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_SEC_CAPABLE,
                "Indicates this device is capable of performing encryption/decryption.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_alloc,
            { "Allocate Short Address", "zbee_nwk.cmd.cinfo.alloc", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_ALLOC_ADDR,
                "Flag requesting the parent to allocate a short address for this device.", HFILL }},

            { &hf_zbee_nwk_cmd_rejoin_status,
            { "Status",                 "zbee_nwk.cmd.rejoin_status", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_rejoin_codes), 0x0, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_link_last,
            { "Last Frame",             "zbee_nwk.cmd.link.last", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LINK_OPTION_LAST_FRAME,
                "Flag indicating the last in a series of link status commands.", HFILL }},

            { &hf_zbee_nwk_cmd_link_first,
            { "First Frame",            "zbee_nwk.cmd.link.first", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LINK_OPTION_FIRST_FRAME,
                "Flag indicating the first in a series of link status commands.", HFILL }},

            { &hf_zbee_nwk_cmd_link_count,
            { "Link Status Count",      "zbee_nwk.cmd.link.count", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_LINK_OPTION_COUNT_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_link_address,
            { "Address",      "zbee_nwk.cmd.link.address", FT_UINT16, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_link_incoming_cost,
            { "Incoming Cost",      "zbee_nwk.cmd.link.incoming_cost", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_LINK_INCOMMING_COST_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_link_outgoing_cost,
            { "Outgoing Cost",      "zbee_nwk.cmd.link.outgoing_cost", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_LINK_OUTGOING_COST_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_report_type,
            { "Report Type",            "zbee_nwk.cmd.report.type", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_report_types), ZBEE_NWK_CMD_NWK_REPORT_ID_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_report_count,
            { "Report Information Count",   "zbee_nwk.cmd.report.count", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_NWK_REPORT_COUNT_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_update_type,
            { "Update Type",            "zbee_nwk.cmd.update.type", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_update_types), ZBEE_NWK_CMD_NWK_UPDATE_ID_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_update_count,
            { "Update Information Count",   "zbee_nwk.cmd.update.count", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_NWK_UPDATE_COUNT_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_update_id,
            { "Update ID",              "zbee_nwk.cmd.update.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_panid,
            { "PAN ID",        "zbee_nwk.panid", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_epid,
            { "Extended PAN ID",        "zbee_nwk.cmd.epid", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_beacon_protocol,
            { "Protocol ID",            "zbee_beacon.protocol", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_beacon_stack_profile,
            { "Stack Profile",          "zbee_beacon.profile", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_stack_profiles), ZBEE_NWK_BEACON_STACK_PROFILE, NULL, HFILL }},

            { &hf_zbee_beacon_version,
            { "Protocol Version",       "zbee_beacon.version", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_BEACON_PROTOCOL_VERSION,
                NULL, HFILL }},

            { &hf_zbee_beacon_router_capacity,
            { "Router Capacity", "zbee_beacon.router", FT_BOOLEAN, 8, NULL, ZBEE_NWK_BEACON_ROUTER_CAPACITY,
                "Whether the device can accept join requests from routing capable devices.", HFILL }},

            { &hf_zbee_beacon_depth,
            { "Device Depth",           "zbee_beacon.depth", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_BEACON_NETWORK_DEPTH,
                "The tree depth of the device, 0 indicates the network coordinator.", HFILL }},

            { &hf_zbee_beacon_end_device_capacity,
            { "End Device Capacity",        "zbee_beacon.end_dev", FT_BOOLEAN, 8, NULL, ZBEE_NWK_BEACON_END_DEVICE_CAPACITY,
                "Whether the device can accept join requests from ZigBee end devices.", HFILL }},

            { &hf_zbee_beacon_epid,
            { "Extended PAN ID",        "zbee_beacon.ext_panid", FT_EUI64, BASE_NONE, NULL, 0x0,
                "Extended PAN identifier.", HFILL }},

            { &hf_zbee_beacon_tx_offset,
            { "Tx Offset",              "zbee_beacon.tx_offset", FT_UINT24, BASE_DEC, NULL, 0x0,
                "The time difference between a device and its parent's beacon.", HFILL }},

            { &hf_zbee_beacon_update_id,
            { "Update ID",              "zbee_beacon.update_id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbip_beacon_allow_join,
            { "Allow Join",             "zbip_beacon.allow_join", FT_BOOLEAN, 8, NULL, ZBEE_IP_BEACON_ALLOW_JOIN,
                NULL, HFILL }},

            { &hf_zbip_beacon_router_capacity,
            { "Router Capacity",        "zbip_beacon.router", FT_BOOLEAN, 8, NULL, ZBEE_IP_BEACON_ROUTER_CAPACITY,
                "Whether this device can accept new routers on the network.", HFILL }},

            { &hf_zbip_beacon_host_capacity,
            { "Host Capacity",        "zbip_beacon.host", FT_BOOLEAN, 8, NULL, ZBEE_IP_BEACON_HOST_CAPACITY,
                "Whether this device can accept new host on the network.", HFILL }},

            { &hf_zbip_beacon_unsecure,
            { "Unsecure Network",     "zbip_beacon.unsecure", FT_BOOLEAN, 8, NULL, ZBEE_IP_BEACON_UNSECURE,
                "Indicates that this network is not using link layer security.", HFILL }},

            { &hf_zbip_beacon_network_id,
            { "Network ID",           "zbip_beacon.network_id", FT_STRING, BASE_NONE, NULL, 0x0,
                "A string that uniquely identifies this network.", HFILL }},

    };

    /*  NWK Layer subtrees */
    static gint *ett[] = {
        &ett_zbee_nwk,
        &ett_zbee_beacon,
        &ett_zbee_nwk_fcf,
        &ett_zbee_nwk_fcf_ext,
        &ett_zbee_nwk_mcast,
        &ett_zbee_nwk_route,
        &ett_zbee_nwk_cmd,
        &ett_zbee_nwk_cmd_options,
        &ett_zbee_nwk_cmd_cinfo,
        &ett_zbee_nwk_cmd_link
    };

    static ei_register_info ei[] = {
        { &ei_zbee_nwk_missing_payload, { "zbee_nwk.missing_payload", PI_MALFORMED, PI_ERROR, "Missing Payload", EXPFILL }},
    };

    expert_module_t* expert_zbee_nwk;

    expert_zbee_nwk = expert_register_protocol(proto_zbee_nwk);
    expert_register_field_array(expert_zbee_nwk, ei, array_length(ei));

    register_init_routine(proto_init_zbee_nwk);
    register_cleanup_routine(proto_cleanup_zbee_nwk);

    /* Register the protocol with Wireshark. */
    proto_zbee_nwk = proto_register_protocol("ZigBee Network Layer", "ZigBee", ZBEE_PROTOABBREV_NWK);
    proto_zbee_beacon = proto_register_protocol("ZigBee Beacon", "ZigBee Beacon", "zbee_beacon");
    proto_zbip_beacon = proto_register_protocol("ZigBee IP Beacon", "ZigBee IP Beacon", "zbip_beacon");
    proto_register_field_array(proto_zbee_nwk, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissectors with Wireshark. */
    new_register_dissector(ZBEE_PROTOABBREV_NWK, dissect_zbee_nwk, proto_zbee_nwk);
    new_register_dissector("zbee_beacon", dissect_zbee_beacon, proto_zbee_beacon);
    new_register_dissector("zbip_beacon", dissect_zbip_beacon, proto_zbip_beacon);

    /* Register the Security dissector. */
    zbee_security_register(NULL, proto_zbee_nwk);
} /* proto_register_zbee_nwk */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_nwk
 *  DESCRIPTION
 *      Registers the zigbee dissector with Wireshark.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_nwk(void)
{
    /* Find the other dissectors we need. */
    data_handle     = find_dissector("data");
    aps_handle      = find_dissector(ZBEE_PROTOABBREV_APS);
    zbee_gp_handle  = find_dissector(ZBEE_PROTOABBREV_NWK_GP);

    /* Register our dissector with IEEE 802.15.4 */
    dissector_add_for_decode_as(IEEE802154_PROTOABBREV_WPAN_PANID, find_dissector(ZBEE_PROTOABBREV_NWK));
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN_BEACON, dissect_zbee_beacon_heur, "ZigBee Beacon", "zbee_wlan_beacon", proto_zbee_beacon, HEURISTIC_ENABLE);
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN_BEACON, dissect_zbip_beacon_heur, "ZigBee IP Beacon", "zbip_wlan_beacon", proto_zbip_beacon, HEURISTIC_ENABLE);
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_zbee_nwk_heur, "ZigBee Network Layer over IEEE 802.15.4", "zbee_nwk_wlan", proto_zbee_nwk, HEURISTIC_ENABLE);

    /* Handoff the ZigBee security dissector code. */
    zbee_security_handoff();
} /* proto_reg_handoff_zbee */

static void free_keyring_key(gpointer key)
{
    g_free(key);
}

static void free_keyring_val(gpointer a)
{
    GSList **slist = (GSList **)a;
#if GLIB_CHECK_VERSION(2, 28, 0)
    g_slist_free_full(*slist, g_free);
#else
    g_slist_foreach(*slist, (GFunc)g_free, NULL);
    g_slist_free(*slist);
#endif /* GLIB_CHECK_VERSION(2, 28, 0) */
    g_free(slist);
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_init_zbee_nwk
 *  DESCRIPTION
 *      Init routine for the nwk dissector. Creates a
 *      hash table for mapping 16-bit to 64-bit addresses and
 *      populates it with static address pairs from a UAT
 *      preference table.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
proto_init_zbee_nwk(void)
{
    zbee_nwk_map.short_table = g_hash_table_new(ieee802154_short_addr_hash, ieee802154_short_addr_equal);
    zbee_nwk_map.long_table = g_hash_table_new(ieee802154_long_addr_hash, ieee802154_long_addr_equal);
    zbee_table_nwk_keyring  = g_hash_table_new_full(g_int_hash, g_int_equal, free_keyring_key, free_keyring_val);
} /* proto_init_zbee_nwk */

static void
proto_cleanup_zbee_nwk(void)
{
    g_hash_table_destroy(zbee_nwk_map.short_table);
    g_hash_table_destroy(zbee_nwk_map.long_table);
    g_hash_table_destroy(zbee_table_nwk_keyring);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
