/* packet-zbee-nwk.c
 * Dissector routines for the ZigBee Network Layer (NWK)
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
#endif /* HAVEHCONFIG_H */

#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <gmodule.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/value_string.h>

#include "packet-ieee802154.h"
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-security.h"

/*************************/
/* Function Declarations */
/*************************/
/* Dissector Routines */
static void        dissect_zbee_nwk        (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void        dissect_zbee_nwk_cmd    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void        dissect_zbee_beacon     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Command Dissector Helpers */
static guint       dissect_zbee_nwk_route_req  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                zbee_nwk_packet * packet, guint offset);
static guint       dissect_zbee_nwk_route_rep  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset);
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
void               proto_register_zbee_nwk(void);
void               proto_reg_handoff_zbee_nwk(void);

/********************/
/* Global Variables */
/********************/
static int proto_zbee_nwk = -1;
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
static int hf_zbee_nwk_mcast_mode = -1;
static int hf_zbee_nwk_mcast_radius = -1;
static int hf_zbee_nwk_mcast_max_radius = -1;
static int hf_zbee_nwk_dst64 = -1;
static int hf_zbee_nwk_src64 = -1;
static int hf_zbee_nwk_src64_origin = -1;
static int hf_zbee_nwk_relay_count = -1;
static int hf_zbee_nwk_relay_index = -1;

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
static int hf_zbee_nwk_cmd_report_type = -1;
static int hf_zbee_nwk_cmd_report_count = -1;
static int hf_zbee_nwk_cmd_update_type = -1;
static int hf_zbee_nwk_cmd_update_count = -1;
static int hf_zbee_nwk_cmd_update_id = -1;
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

static gint ett_zbee_nwk = -1;
static gint ett_zbee_beacon = -1;
static gint ett_zbee_nwk_fcf = -1;
static gint ett_zbee_nwk_mcast = -1;
static gint ett_zbee_nwk_route = -1;
static gint ett_zbee_nwk_cmd = -1;
static gint ett_zbee_nwk_cmd_options = -1;
static gint ett_zbee_nwk_cmd_cinfo = -1;

static dissector_handle_t   data_handle;
static dissector_handle_t   aps_handle;

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
dissect_zbee_nwk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    ieee802154_packet   *packet = (ieee802154_packet *)pinfo->private_data;

    /* All ZigBee frames must always have a 16-bit source address. */
    if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) {
        return FALSE;
    }
    /* ZigBee MAC frames must always contain a 16-bit destination address. */
    if ( (packet->frame_type == IEEE802154_FCF_DATA) &&
         (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) ) {
        dissect_zbee_nwk(tvb, pinfo, tree);
        return TRUE;
    }
    /* ZigBee MAC Beacons must have the first byte (protocol ID) equal to the
     * ZigBee protocol ID. */
    if ( (packet->frame_type == IEEE802154_FCF_BEACON) &&
         (tvb_get_guint8(tvb, 0) == ZBEE_NWK_BEACON_PROCOL_ID) ) {
        dissect_zbee_beacon(tvb, pinfo, tree);
        return TRUE;
    }
    /* If we get this far, then this packet did not meet the requirements for
     * a ZigBee frame.
     */
    return FALSE;
} /* dissect_zbee_heur */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk
 *  DESCRIPTION
 *      ZigBee packet dissection routine for Wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_zbee_nwk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t            *payload_tvb = NULL;

    proto_item          *proto_root = NULL;
    proto_item          *ti = NULL;
    proto_tree          *nwk_tree = NULL;
    proto_tree          *field_tree = NULL;

    zbee_nwk_packet     packet;
    ieee802154_packet   *ieee_packet = (ieee802154_packet *)pinfo->private_data;

    guint               offset = 0;
    gchar               *src_addr = (gchar *)ep_alloc(32);
    gchar               *dst_addr = (gchar *)ep_alloc(32);

    guint16             fcf;

    ieee802154_short_addr   addr16;
    ieee802154_map_rec     *map_rec;
    ieee802154_hints_t     *ieee_hints;

    zbee_nwk_hints_t       *nwk_hints;
    gboolean                unicast_src;

    memset(&packet, 0, sizeof(packet));

    /* Set up hint structures */
    if (!pinfo->fd->flags.visited) {
        /* Allocate frame data with hints for upper layers */
        nwk_hints = se_alloc0(sizeof(zbee_nwk_hints_t));
        p_add_proto_data(pinfo->fd, proto_zbee_nwk, nwk_hints);
    } else {
        /* Retrieve existing structure */
        nwk_hints = p_get_proto_data(pinfo->fd, proto_zbee_nwk);
    }

    ieee_hints = (ieee802154_hints_t *)p_get_proto_data(pinfo->fd,
            proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN));

    /* Add ourself to the protocol column, clear the info column, and create the protocol tree. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee");
    col_clear(pinfo->cinfo, COL_INFO);
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_zbee_nwk, tvb, offset,
                                                    tvb_length(tvb), "ZigBee Network Layer");
        nwk_tree = proto_item_add_subtree(proto_root, ett_zbee_nwk);
    }

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
    pinfo->zbee_stack_vers = packet.version;

    /* Display the FCF. */
    if (tree) {
        /* Create a subtree for the FCF. */
        ti = proto_tree_add_text(nwk_tree, tvb, offset, 2, "Frame Control Field: %s (0x%04x)",
                val_to_str(packet.type, zbee_nwk_frame_types, "Unknown"), fcf);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_fcf);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_frame_type, tvb, offset, 1,
                            fcf & ZBEE_NWK_FCF_FRAME_TYPE);

        /*  Add the rest of the fcf fields to the subtree */
        proto_tree_add_uint(field_tree, hf_zbee_nwk_proto_version, tvb, offset, 1,
                            fcf & ZBEE_NWK_FCF_VERSION);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_discover_route, tvb, offset, 1,
                            fcf & ZBEE_NWK_FCF_DISCOVER_ROUTE);
        if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_multicast, tvb, offset+1,
                            1, fcf & ZBEE_NWK_FCF_MULTICAST);
        }
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_security, tvb, offset+1,
                            1, fcf & ZBEE_NWK_FCF_SECURITY);
        if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_source_route, tvb, offset+1,
                            1, fcf & ZBEE_NWK_FCF_SOURCE_ROUTE);
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_ext_dst, tvb, offset+1,
                            1, fcf & ZBEE_NWK_FCF_EXT_DEST);
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_ext_src, tvb, offset+1,
                            1, fcf & ZBEE_NWK_FCF_EXT_SOURCE);
        }
    }
    offset += 2;

    /* Add the frame type to the info column and protocol root. */
    if (tree) {
        proto_item_append_text(proto_root, " %s", val_to_str(packet.type, zbee_nwk_frame_types, "Unknown Type"));
    }
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet.type, zbee_nwk_frame_types, "Reserved Frame Type"));

    /* Get the destination address. */
    packet.dst = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(nwk_tree, hf_zbee_nwk_dst, tvb, offset, 2, packet.dst);
    }
    offset += 2;

    /* Display the destination address. */
    if (   (packet.dst == ZBEE_BCAST_ALL)
        || (packet.dst == ZBEE_BCAST_ACTIVE)
        || (packet.dst == ZBEE_BCAST_ROUTERS)){
        g_snprintf(dst_addr, 32, "Broadcast");
    }
    else {
        g_snprintf(dst_addr, 32, "0x%04x", packet.dst);
    }

    SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(dst_addr)+1, dst_addr);
    SET_ADDRESS(&pinfo->net_dst, AT_STRINGZ, (int)strlen(dst_addr)+1, dst_addr);

    if (tree) {
        proto_item_append_text(proto_root, ", Dst: %s", dst_addr);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", dst_addr);


    /* Get the short nwk source address and pass it to upper layers */
    packet.src = tvb_get_letohs(tvb, offset);
    if (nwk_hints) nwk_hints->src = packet.src;
    if (tree) {
        proto_tree_add_uint(nwk_tree, hf_zbee_nwk_src, tvb, offset, 2, packet.src);
    }
    offset += 2;

    /* Display the source address. */
    if (   (packet.src == ZBEE_BCAST_ALL)
        || (packet.src == ZBEE_BCAST_ACTIVE)
        || (packet.src == ZBEE_BCAST_ROUTERS)){
        /* Source Broadcast doesn't make much sense. */
        g_snprintf(src_addr, 32, "Unexpected Source Broadcast");
        unicast_src = FALSE;
    }
    else {
        g_snprintf(src_addr, 32, "0x%04x", packet.src);
        unicast_src = TRUE;
    }

    SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(src_addr)+1, src_addr);
    SET_ADDRESS(&pinfo->net_src, AT_STRINGZ, (int)strlen(src_addr)+1, src_addr);

    if (tree) {
        proto_item_append_text(proto_root, ", Src: %s", src_addr);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", src_addr);

    /* Get and display the radius. */
    packet.radius = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(nwk_tree, hf_zbee_nwk_radius, tvb, offset, 1, packet.radius);
    }
    offset += 1;

    /* Get and display the sequence number. */
    packet.seqno = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(nwk_tree, hf_zbee_nwk_seqno, tvb, offset, 1, packet.seqno);
    }
    offset += 1;

    /* Add Multicast control field. (ZigBee 2006 and later). */
    if ((pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) && packet.multicast) {
        guint8  mcast_control = tvb_get_guint8(tvb, offset);

        packet.mcast_mode       = zbee_get_bit_field(mcast_control, ZBEE_NWK_MCAST_MODE);
        packet.mcast_radius     = zbee_get_bit_field(mcast_control, ZBEE_NWK_MCAST_RADIUS);
        packet.mcast_max_radius = zbee_get_bit_field(mcast_control, ZBEE_NWK_MCAST_MAX_RADIUS);
        if (tree) {
            /* Create a subtree for the multicast control field. */
            ti = proto_tree_add_text(nwk_tree, tvb, offset, 1, "Multicast Control Field");
            field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_mcast);
            /* Add the fields. */
            ti = proto_tree_add_uint(field_tree, hf_zbee_nwk_mcast_mode, tvb, offset, 1,
                                    mcast_control & ZBEE_NWK_MCAST_MODE);
            proto_tree_add_uint(field_tree, hf_zbee_nwk_mcast_radius, tvb, offset, 1,
                                    mcast_control & ZBEE_NWK_MCAST_RADIUS);
            proto_tree_add_uint(field_tree, hf_zbee_nwk_mcast_max_radius, tvb, offset, 1,
                                    mcast_control & ZBEE_NWK_MCAST_MAX_RADIUS);
        }
        offset += 1;
    }

    /* Add the extended destination address (ZigBee 2006 and later). */
    if ((pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) && packet.ext_dst) {
        packet.dst64 = tvb_get_letoh64(tvb, offset);
        if (tree) {
            proto_tree_add_item(nwk_tree, hf_zbee_nwk_dst64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
        offset += 8;
    }

    /* Display the extended source address. (ZigBee 2006 and later). */
    if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
        addr16.pan = ieee_packet->src_pan;

        if (packet.ext_src) {
            packet.src64 = tvb_get_letoh64(tvb, offset);
            if (tree) {
                proto_tree_add_item(nwk_tree, hf_zbee_nwk_src64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            }
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
                if (tree && nwk_hints && nwk_hints->map_rec ) {
                    /* Display inferred source address info */
                    ti = proto_tree_add_eui64(nwk_tree, hf_zbee_nwk_src64, tvb, offset, 0,
                            nwk_hints->map_rec->addr64);
                    PROTO_ITEM_SET_GENERATED(ti);

                    if ( nwk_hints->map_rec->start_fnum ) {
                        ti = proto_tree_add_uint(nwk_tree, hf_zbee_nwk_src64_origin, tvb, 0, 0,
                            nwk_hints->map_rec->start_fnum);
                    }
                    else {
                        ti = proto_tree_add_text(nwk_tree, tvb, 0, 0, "Origin: Pre-configured");
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

    /* Add the Source Route field. (ZigBee 2006 and later). */
    if ((pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) && packet.route) {
        guint8  relay_count;
        guint8  relay_index;
        guint16 relay_addr;
        guint   i;

        if (tree) {
            /* Create a subtree for the source route field. */
            ti = proto_tree_add_text(nwk_tree, tvb, offset, 1, "Source Route");
            field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_route);
        }

        /* Get and display the relay count. */
        relay_count = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(field_tree, hf_zbee_nwk_relay_count, tvb, offset, 1, relay_count);
            proto_item_append_text(ti, ", Length: %d", relay_count);
        }
        offset += 1;

        if (tree) {
            /* Correct the length of the source route fields. */
            proto_item_set_len(ti, 1 + relay_count*2);
        }

        /* Get and display the relay index. */
        relay_index = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(field_tree, hf_zbee_nwk_relay_index, tvb, offset, 1, relay_index);
        }
        offset += 1;

        /* Get and display the relay list. */
        for (i=0; i<relay_count; i++) {
            relay_addr = tvb_get_letohs(tvb, offset);
            if (tree) {
                proto_tree_add_text(field_tree, tvb, offset, 2, "Relay %d: 0x%04x", i+1, relay_addr);
            }
            offset += 2;
        } /* for */
    }

    /*
     * Link the packet structure into the private data pointer so the
     * APS layer can retrieve the network source address.
     *
     * BUGBUG: Ideally, the APS layer could just pull this out of the
     * pinfo structure. But there is no suitable address type to use
     * for ZigBee's 16-bit short address.
     */
    pinfo->private_data = (void *)&packet;

    /*
     * Ensure that the payload exists. There are no valid ZigBee network
     * packets that have no payload.
     */
    if (offset >= tvb_length(tvb)) {
        /* Non-existent or truncated payload. */
        expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_ERROR, "Missing Payload");
        THROW(BoundsError);
    }
    /* Payload is encrypted, attempt security operations. */
    else if (packet.security) {
        payload_tvb = dissect_zbee_secure(tvb, pinfo, nwk_tree, offset);
        if (payload_tvb == NULL) {
            /* If Payload_tvb is NULL, then the security dissector cleaned up. */
            return;
        }
    }
    /* Plaintext payload. */
    else {
        payload_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    if (packet.type == ZBEE_NWK_FCF_CMD) {
        /* Dissect the Network Command. */
        dissect_zbee_nwk_cmd(payload_tvb, pinfo, nwk_tree);
    }
    else if (packet.type == ZBEE_NWK_FCF_DATA) {
        /* Dissect the Network Payload (APS layer). */
        call_dissector(aps_handle, payload_tvb, pinfo, tree);
    }
    else {
        /* Invalid type. */
        call_dissector(data_handle, payload_tvb, pinfo, tree);
    }
} /* dissect_zbee_nwk */

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
static void dissect_zbee_nwk_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *cmd_tree = NULL;
    proto_item  *cmd_root = NULL;

    zbee_nwk_packet *packet = (zbee_nwk_packet *)pinfo->private_data;

    guint       offset=0;
    guint8      cmd_id = tvb_get_guint8(tvb, offset);

    /* Create a subtree for this command. */
    if (tree) {
        cmd_root = proto_tree_add_text(tree, tvb, offset, tvb_length(tvb), "Command Frame: %s",
                                        val_to_str(cmd_id, zbee_nwk_cmd_names, "Unknown"));
        cmd_tree = proto_item_add_subtree(cmd_root, ett_zbee_nwk_cmd);

        /* Add the command ID. */
        proto_tree_add_uint(cmd_tree, hf_zbee_nwk_cmd_id, tvb, offset, 1, cmd_id);
    }
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
            offset = dissect_zbee_nwk_route_rep(tvb, pinfo, cmd_tree, offset);
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
    if (offset < tvb_length(tvb)) {
        /* There are leftover bytes! */
        guint       leftover_len    = tvb_length(tvb) - offset;
        tvbuff_t    *leftover_tvb   = tvb_new_subset(tvb, offset, leftover_len, leftover_len);
        proto_tree  *root           = NULL;

        /* Correct the length of the command tree. */
        if (tree) {
            root = proto_tree_get_root(tree);
            proto_item_set_len(cmd_root, offset);
        }

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
    proto_tree  *field_tree;
    proto_item  *ti;

    guint8  route_options;
    guint8  route_id;
    guint16 dest_addr;
    guint8  path_cost;

    /* Get and display the route options field. */
    route_options = tvb_get_guint8(tvb, offset);
    if (tree) {
        /* Create a subtree for the command options. */
        ti = proto_tree_add_text(tree, tvb, offset, 1, "Command Options (0x%02x)", route_options);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);

        if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_route_opt_multicast, tvb, offset,
                                    1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_MCAST);
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_route_opt_dest_ext, tvb, offset,
                                    1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_DEST_EXT);
            proto_tree_add_uint(field_tree, hf_zbee_nwk_cmd_route_opt_many_to_one, tvb, offset,
                                    1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_MANY_MASK);
        }
        else {
            proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_route_opt_repair, tvb, offset, 1,
                                    route_options & ZBEE_NWK_CMD_ROUTE_OPTION_REPAIR);
        }
    }
    offset += 1;

    /* Get and display the route request ID. */
    route_id = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_id, tvb, offset, 1, route_id);
    }
    offset += 1;

    /* Get and display the destination address. */
    dest_addr = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_dest, tvb, offset, 2, dest_addr);
    }
    offset += 2;

    /* Get and display the path cost. */
    path_cost = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_cost, tvb, offset, 1, path_cost);
    }
    offset += 1;

    /* Get and display the extended destination address. */
    if (route_options & ZBEE_NWK_CMD_ROUTE_OPTION_DEST_EXT) {
        if (tree) {
            proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_dest_ext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
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
dissect_zbee_nwk_route_rep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    proto_tree  *field_tree;
    proto_item  *ti;

    guint8  route_options;
    guint8  route_id;
    guint16 orig_addr;
    guint16 resp_addr;
    guint8  path_cost;

    /* Get and display the route options field. */
    route_options = tvb_get_guint8(tvb, offset);
    if (tree) {
        /* Create a subtree for the command options. */
        ti = proto_tree_add_text(tree, tvb, offset, 1, "Command Options (0x%02x)", route_options);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);

        if (pinfo->zbee_stack_vers >= ZBEE_VERSION_2007) {
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_route_opt_multicast, tvb, offset, 1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_MCAST);
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_route_opt_resp_ext, tvb, offset, 1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_RESP_EXT);
            proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_route_opt_orig_ext, tvb, offset, 1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_ORIG_EXT);
        }
        else {
            proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_route_opt_repair, tvb, offset, 1, route_options & ZBEE_NWK_CMD_ROUTE_OPTION_REPAIR);
        }
    }
    offset += 1;

    /* Get and display the route request ID. */
    route_id = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_id, tvb, offset, 1, route_id);
    }
    offset += 1;

    /* Get and display the originator address. */
    orig_addr = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_orig, tvb, offset, 2, orig_addr);
    }
    offset += 2;

    /* Get and display the responder address. */
    resp_addr = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_resp, tvb, offset, 2, resp_addr);
    }
    offset += 2;

    /* Get and display the path cost. */
    path_cost = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_cost, tvb, offset, 1, path_cost);
    }
    offset += 1;

    /* Get and display the originator extended address. */
    if (route_options & ZBEE_NWK_CMD_ROUTE_OPTION_ORIG_EXT) {
        if (tree) {
            proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_orig_ext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
        offset += 8;
    }

    /* Get and display the responder extended address. */
    if (route_options & ZBEE_NWK_CMD_ROUTE_OPTION_RESP_EXT) {
        if (tree) {
            proto_tree_add_item(tree, hf_zbee_nwk_cmd_route_resp_ext, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
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
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_nwk_status, tvb, offset, 1, status_code);
    }
    offset += 1;

    /* Get and display the destination address. */
    addr = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_route_dest, tvb, offset, 2, addr);
    }
    offset += 2;

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", 0x%04x: %s", addr, val_to_str(status_code, zbee_nwk_status_codes, "Unknown Status Code"));

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
    guint8  leave_options;

    /* Get and display the leave options. */
    leave_options = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_leave_rejoin, tvb, offset, 1,
                                 leave_options & ZBEE_NWK_CMD_LEAVE_OPTION_REJOIN);
        proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_leave_request, tvb, offset, 1,
                                 leave_options & ZBEE_NWK_CMD_LEAVE_OPTION_REQUEST);
        proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_leave_children, tvb, offset, 1,
                                leave_options & ZBEE_NWK_CMD_LEAVE_OPTION_CHILDREN);
    }
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
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_relay_count, tvb, offset, 1, relay_count);
    }
    offset += 1;

    /* Get and display the relay addresses. */
    for (i=0; i<relay_count; i++) {
        relay_addr = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, 2, "Relay Device %d: 0x%04x", i+1, relay_addr);
        }
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
    proto_tree  *field_tree;
    proto_item  *ti;

    guint8  capabilities;

    /* Get and dispaly the capabilities information. */
    capabilities = tvb_get_guint8(tvb, offset);
    if (tree) {
        /* Create a subtree for the capability information. */
        ti = proto_tree_add_text(tree, tvb, offset, 1, "Capability Information");
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_cinfo);

        /* Add the capability info flags. */
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_cinfo_alt_coord, tvb, offset, 1,
                                capabilities & ZBEE_CINFO_ALT_COORD);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_cinfo_type, tvb, offset, 1,
                                capabilities & ZBEE_CINFO_FFD);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_cinfo_power, tvb, offset, 1,
                                capabilities & ZBEE_CINFO_POWER);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_cinfo_idle_rx, tvb, offset, 1,
                                capabilities & ZBEE_CINFO_IDLE_RX);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_cinfo_security, tvb, offset, 1,
                                capabilities & ZBEE_CINFO_SECURITY);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_cmd_cinfo_alloc, tvb, offset, 1,
                                capabilities & ZBEE_CINFO_ALLOC);
    }
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
    guint16 addr;
    guint8  status;

    /* Get and display the short address. */
    addr = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_addr, tvb, offset, 2, addr);
    }
    offset += 2;

    /* Get and display the rejoin status. */
    status = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_rejoin_status, tvb, offset, 1, status);
    }
    offset += 1;

    /* Update the info column. */
    if (status == IEEE802154_CMD_ASRSP_AS_SUCCESS) {
       col_append_fstr(pinfo->cinfo, COL_INFO, ", Address: 0x%04x", packet->src);
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(status, zbee_nwk_rejoin_codes, "Unknown Rejoin Response"));
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
    guint16 addr;
    int     i, link_count;

    /* Get and Display the link status options. */
    options = tvb_get_guint8(tvb, offset);
    link_count = options & ZBEE_NWK_CMD_LINK_OPTION_COUNT_MASK;
    if (tree) {
        proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_link_last, tvb, offset, 1,
                options & ZBEE_NWK_CMD_LINK_OPTION_LAST_FRAME);
        proto_tree_add_boolean(tree, hf_zbee_nwk_cmd_link_first, tvb, offset, 1,
                options & ZBEE_NWK_CMD_LINK_OPTION_FIRST_FRAME);
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_link_count, tvb, offset, 1, link_count);
    }
    offset += 1;

    /* Get and Display the link status list. */
    for (i=0; i<link_count; i++) {
        /* Get the address and link status. */
        addr = tvb_get_letohs(tvb, offset);
        options = tvb_get_guint8(tvb, offset+2);
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, 2+1,
                    "0x%04x, Incoming Cost: %d Outgoing Cost: %d", addr,
                    options & ZBEE_NWK_CMD_LINK_INCOMMING_COST_MASK,
                    (options & ZBEE_NWK_CMD_LINK_OUTGOING_COST_MASK)>>4);
        }
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
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_report_type, tvb, offset, 1, report_type);
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_report_count, tvb, offset, 1, report_count);
    }
    offset += 1;

    /* Get and display the epid. */
    if (tree) {
        proto_tree_add_item(tree, hf_zbee_nwk_cmd_epid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    }
    offset += 8;

    if (report_type == ZBEE_NWK_CMD_NWK_REPORT_ID_PAN_CONFLICT) {
        guint16 panId;

        /* Report information contains a list of PANS with range of the sender. */
        for (i=0; i<report_count; i++) {
            panId = tvb_get_letohs(tvb, offset);
            if (tree) {
                proto_tree_add_text(tree, tvb, offset, 2, "PANID: 0x%04x", panId);
            }
            offset += 2;
        } /* for */
    }

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(report_type, zbee_nwk_report_types, "Unknown Report Type"));

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
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_update_type, tvb, offset, 1, update_type);
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_update_count, tvb, offset, 1, update_count);
    }
    offset += 1;

    /* Get and display the epid. */
    if (tree) {
        proto_tree_add_item(tree, hf_zbee_nwk_cmd_epid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    }
    offset += 8;

    /* Get and display the updateID. */
    update_id = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_cmd_update_id, tvb, offset, 1, update_id);
    }
    offset += 1;

    if (update_type == ZBEE_NWK_CMD_NWK_UPDATE_ID_PAN_UPDATE) {
        guint16 panId;

        /* Report information contains a list of PANS with range of the sender. */
        for (i=0; i<update_count; i++) {
            panId = tvb_get_letohs(tvb, offset);
            if (tree) {
                proto_tree_add_text(tree, tvb, offset, 2, "PANID: 0x%04x", panId);
            }
            offset += 2;
        } /* for */
    }

    /* Update the info column. */
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(update_type, zbee_nwk_update_types, "Unknown Update Type"));

    /* Done */
    return offset;
} /* dissect_zbee_nwk_update */

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
static void dissect_zbee_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    ieee802154_packet   *packet = (ieee802154_packet *)pinfo->private_data;

    proto_item  *beacon_root = NULL;
    proto_tree  *beacon_tree = NULL;
    guint       offset = 0;

    guint8      temp;
    guint8      version;
    guint64     epid;
    guint32     tx_offset;

    /* Add ourself to the protocol column. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee");
    /* Create the tree for this beacon. */
    if (tree) {
        beacon_root = proto_tree_add_protocol_format(tree, proto_zbee_nwk, tvb, 0, tvb_length(tvb), "ZigBee Beacon");
        beacon_tree = proto_item_add_subtree(beacon_root, ett_zbee_beacon);
    }

    /* Update the info column. */
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Beacon, Src: 0x%04x", packet->src16);

    /* Get and display the protocol id, must be 0 on all ZigBee beacons. */
    temp = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(beacon_tree, hf_zbee_beacon_protocol, tvb, offset, 1, temp);
    }
    offset += 1;

    /* Get and display the stack profile and protocol version. */
    temp = tvb_get_guint8(tvb, offset);
    pinfo->zbee_stack_vers = version = zbee_get_bit_field(temp, ZBEE_NWK_BEACON_PROTOCOL_VERSION);
    if (tree) {
        proto_tree_add_uint(beacon_tree, hf_zbee_beacon_stack_profile, tvb, offset, 1,
                zbee_get_bit_field(temp, ZBEE_NWK_BEACON_STACK_PROFILE));
        proto_tree_add_uint(beacon_tree, hf_zbee_beacon_version, tvb, offset, 1, version);
    }
    offset += 1;

    /* Get and display the security level and flags. */
    temp        = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_boolean(beacon_tree, hf_zbee_beacon_router_capacity, tvb, offset, 1,
                zbee_get_bit_field(temp, ZBEE_NWK_BEACON_ROUTER_CAPACITY));
        proto_tree_add_uint(beacon_tree, hf_zbee_beacon_depth, tvb, offset, 1,
                zbee_get_bit_field(temp, ZBEE_NWK_BEACON_NETWORK_DEPTH));
        proto_tree_add_boolean(beacon_tree, hf_zbee_beacon_end_device_capacity, tvb, offset, 1,
                zbee_get_bit_field(temp, ZBEE_NWK_BEACON_END_DEVICE_CAPACITY));
    }
    offset += 1;

    if (version >= ZBEE_VERSION_2007) {
        /* In ZigBee 2006 and later, the beacon contains an extended PAN ID. */
        epid = tvb_get_letoh64(tvb, offset);
        if (tree) {
            proto_tree_add_item(beacon_tree, hf_zbee_beacon_epid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
        offset += 8;

        /* Update the Info Column with the EPID. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", EPID: %s", get_eui64_name(epid));

        /*
         * In ZigBee 2006 the Tx-Offset is optional, while in the 2007 and
         * later versions, the Tx-Offset is a required value. Since both 2006 and
         * and 2007 versions have the same protocol version (2), we should treat
         * the Tx-Offset as well as the update ID as optional elements
         */
        if (tvb_bytes_exist(tvb, offset, 3)) {
            tx_offset = tvb_get_letoh24(tvb, offset);
            proto_tree_add_uint(beacon_tree, hf_zbee_beacon_tx_offset, tvb, offset, 3, tx_offset);
            offset += 3;

            /* Get and display the update ID. */
            if(tvb_length_remaining(tvb, offset)) {
                temp = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(beacon_tree, hf_zbee_beacon_update_id, tvb, offset, 1, temp);
                offset += 1;
            }
        }
    }
    else if (tvb_bytes_exist(tvb, offset, 3)) {
        /* In ZigBee 2004, the Tx-Offset is an optional value. */
        tx_offset = tvb_get_letoh24(tvb, offset);
        if (tree) {
            proto_tree_add_uint(beacon_tree, hf_zbee_beacon_tx_offset, tvb, offset, 3, tx_offset);
        }
        offset += 3;

        /* Update the info column with the PAN ID. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", packet->src_pan);
    }

    /* Check for leftover bytes. */
    if (offset < tvb_length(tvb)) {
        /* Bytes leftover! */
        guint       leftover_len    = tvb_length(tvb) - offset;
        tvbuff_t    *leftover_tvb   = tvb_new_subset(tvb, offset, leftover_len, leftover_len);
        proto_tree  *root           = NULL;

        /* Correct the length of the beacon tree. */
        if (tree) {
            root = proto_tree_get_root(tree);
            proto_item_set_len(beacon_root, offset);
        }

        /* Dump the leftover to the data dissector. */
        call_dissector(data_handle, leftover_tvb, pinfo, root);
    }
} /* dissect_zbee_beacon */

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

            { &hf_zbee_nwk_frame_type,
            { "Frame Type",             "zbee.nwk.frame_type", FT_UINT16, BASE_HEX, VALS(zbee_nwk_frame_types),
                ZBEE_NWK_FCF_FRAME_TYPE, NULL, HFILL }},

            { &hf_zbee_nwk_proto_version,
            { "Protocol Version",       "zbee.nwk.proto_version", FT_UINT16, BASE_DEC, NULL, ZBEE_NWK_FCF_VERSION,
                NULL, HFILL }},

            { &hf_zbee_nwk_discover_route,
            { "Discover Route",         "zbee.nwk.discovery", FT_UINT16, BASE_HEX, VALS(zbee_nwk_discovery_modes),
                ZBEE_NWK_FCF_DISCOVER_ROUTE,
                "Determines how route discovery may be handled, if at all.", HFILL }},

            { &hf_zbee_nwk_multicast,
            { "Multicast",              "zbee.nwk.multicast", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_MULTICAST,
                NULL, HFILL }},

            { &hf_zbee_nwk_security,
            { "Security",               "zbee.nwk.security", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_SECURITY,
                "Whether or not security operations are performed on the network payload.", HFILL }},

            { &hf_zbee_nwk_source_route,
            { "Source Route",           "zbee.nwk.src_route", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_SOURCE_ROUTE,
                NULL, HFILL }},

            { &hf_zbee_nwk_ext_dst,
            { "Destination",            "zbee.nwk.ext_dst", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_EXT_DEST,
                NULL, HFILL }},

            { &hf_zbee_nwk_ext_src,
            { "Extended Source",        "zbee.nwk.ext_src", FT_BOOLEAN, 16, NULL, ZBEE_NWK_FCF_EXT_SOURCE,
                NULL, HFILL }},

            { &hf_zbee_nwk_dst,
            { "Destination",            "zbee.nwk.dst", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_src,
            { "Source",                 "zbee.nwk.src", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_radius,
            { "Radius",                 "zbee.nwk.radius", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of hops remaining for a range-limited broadcast packet.", HFILL }},

            { &hf_zbee_nwk_seqno,
            { "Sequence Number",        "zbee.nwk.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_mcast_mode,
            { "Multicast Mode",         "zbee.nwk.multicast.mode", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_MCAST_MODE,
                "Controls whether this packet is permitted to be routed through non-members of the multicast group.",
                HFILL }},

            { &hf_zbee_nwk_mcast_radius,
            { "Non-Member Radius",      "zbee.nwk.multicast.radius", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_MCAST_RADIUS,
                "Limits the range of multicast packets when being routed through non-members.", HFILL }},

            { &hf_zbee_nwk_mcast_max_radius,
            { "Max Non-Member Radius",  "zbee.nwk.multicast.max_radius", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_MCAST_MAX_RADIUS, NULL, HFILL }},

            { &hf_zbee_nwk_dst64,
            { "Destination",   "zbee.nwk.dst64", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_src64,
            { "Extended Source",        "zbee.nwk.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_src64_origin,
            { "Origin",        "zbee.nwk.src64.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_relay_count,
            { "Relay Count",            "zbee.nwk.relay.count", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of entries in the relay list.", HFILL }},

            { &hf_zbee_nwk_relay_index,
            { "Relay Index",            "zbee.nwk.relay.index", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of relays required to route to the source device.", HFILL }},

            { &hf_zbee_nwk_cmd_id,
            { "Command Identifier",     "zbee.nwk.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_nwk_cmd_names), 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_addr,
            { "Address",                "zbee.nwk.cmd.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_id,
            { "Route ID",               "zbee.nwk.cmd.route.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                "A sequence number for routing commands.", HFILL }},

            { &hf_zbee_nwk_cmd_route_dest,
            { "Destination",            "zbee.nwk.cmd.route.dest", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_orig,
            { "Originator",             "zbee.nwk.cmd.route.orig", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_resp,
            { "Responder",              "zbee.nwk.cmd.route.resp", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_dest_ext,
            { "Extended Destination",   "zbee.nwk.cmd.route.dest_ext", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_orig_ext,
            { "Extended Originator",    "zbee.nwk.cmd.route.orig_ext", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_resp_ext,
            { "Extended Responder",     "zbee.nwk.cmd.route.resp_ext", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_cost,
            { "Path Cost",              "zbee.nwk.cmd.route.cost", FT_UINT8, BASE_DEC, NULL, 0x0,
                "A value specifying the efficiency of this route.", HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_repair,
            { "Route Repair",           "zbee.nwk.cmd.route.opts.repair", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_REPAIR,
                "Flag identifying whether the route request command was to repair a failed route.", HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_multicast,
            { "Multicast",              "zbee.nwk.cmd.route.opts.mcast", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_MCAST,
                "Flag identifying this as a multicast route request.", HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_dest_ext,
            { "Extended Destination",   "zbee.nwk.cmd.route.opts.dest_ext", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_DEST_EXT, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_resp_ext,
            { "Extended Responder",   "zbee.nwk.cmd.route.opts.resp_ext", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_RESP_EXT, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_orig_ext,
            { "Extended Originator",    "zbee.nwk.cmd.route.opts.orig_ext", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_ROUTE_OPTION_ORIG_EXT, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_route_opt_many_to_one,
            { "Many-to-One Discovery",  "zbee.nwk.cmd.route.opts.many2one", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_cmd_route_many_modes), ZBEE_NWK_CMD_ROUTE_OPTION_MANY_MASK,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_nwk_status,
            { "Status Code",            "zbee.nwk.cmd.status", FT_UINT8, BASE_HEX, VALS(zbee_nwk_status_codes), 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_leave_rejoin,
            { "Rejoin",                 "zbee.nwk.cmd.leave.rejoin", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LEAVE_OPTION_REJOIN, "Flag instructing the device to rejoin the network.", HFILL }},

            { &hf_zbee_nwk_cmd_leave_request,
            { "Request",                "zbee.nwk.cmd.leave.request", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LEAVE_OPTION_REQUEST,
                "Flag identifying the direction of this command. 1=Request, 0=Indication", HFILL }},

            { &hf_zbee_nwk_cmd_leave_children,
            { "Remove Children",        "zbee.nwk.cmd.leave.children", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LEAVE_OPTION_CHILDREN,
                "Flag instructing the device to remove its children in addition to itself.", HFILL }},

            { &hf_zbee_nwk_cmd_relay_count,
            { "Relay Count",            "zbee.nwk.cmd.relay_count", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of relays required to route to the destination.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_alt_coord,
            { "Alternate Coordinator",  "zbee.nwk.cmd.cinfo.alt_coord", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_ALT_PAN_COORD,
                "Indicates that the device is able to operate as a PAN coordinator.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_type,
            { "Full-Function Device",   "zbee.nwk.cmd.cinfo.ffd", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_DEVICE_TYPE, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_power,
            { "AC Power",               "zbee.nwk.cmd.cinfo.power", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_POWER_SRC, "Indicates this device is using AC/Mains power.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_idle_rx,
            { "Rx On When Idle",        "zbee.nwk.cmd.cinfo.power", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_IDLE_RX,
                "Indicates the receiver is active when the device is idle.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_security,
            { "Security Capability",    "zbee.nwk.cmd.cinfo.security", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_SEC_CAPABLE,
                "Indicates this device is capable of performing encryption/decryption.", HFILL }},

            { &hf_zbee_nwk_cmd_cinfo_alloc,
            { "Allocate Short Address", "zbee.nwk.cmd.cinfo.alloc", FT_BOOLEAN, 8, NULL,
                IEEE802154_CMD_CINFO_ALLOC_ADDR,
                "Flag requesting the parent to allocate a short address for this device.", HFILL }},

            { &hf_zbee_nwk_cmd_rejoin_status,
            { "Status",                 "zbee.nwk.cmd.rejoin_status", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_rejoin_codes), 0x0, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_link_last,
            { "Last Frame",             "zbee.nwk.cmd.link.last", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LINK_OPTION_LAST_FRAME,
                "Flag indicating the last in a series of link status commands.", HFILL }},

            { &hf_zbee_nwk_cmd_link_first,
            { "First Frame",            "zbee.nwk.cmd.link.first", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_CMD_LINK_OPTION_FIRST_FRAME,
                "Flag indicating the first in a series of link status commands.", HFILL }},

            { &hf_zbee_nwk_cmd_link_count,
            { "Link Status Count",      "zbee.nwk.cmd.link.count", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_LINK_OPTION_COUNT_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_report_type,
            { "Report Type",            "zbee.nwk.cmd.report.type", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_report_types), ZBEE_NWK_CMD_NWK_REPORT_ID_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_report_count,
            { "Report Information Count",   "zbee.nwk.cmd.report.count", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_NWK_REPORT_COUNT_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_update_type,
            { "Update Type",            "zbee.nwk.cmd.update.type", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_update_types), ZBEE_NWK_CMD_NWK_UPDATE_ID_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_update_count,
            { "Update Information Count",   "zbee.nwk.cmd.update.count", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_CMD_NWK_UPDATE_COUNT_MASK, NULL, HFILL }},

            { &hf_zbee_nwk_cmd_update_id,
            { "Update ID",              "zbee.nwk.cmd.update.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_nwk_cmd_epid,
            { "Extended PAN ID",        "zbee.nwk.cmd.epid", FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_beacon_protocol,
            { "Protocol ID",            "zbee.beacon.protocol", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_beacon_stack_profile,
            { "Stack Profile",          "zbee.beacon.profile", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_stack_profiles), 0x0, NULL, HFILL }},

            { &hf_zbee_beacon_version,
            { "Protocol Version",       "zbee.beacon.version", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_beacon_router_capacity,
            { "Router Capacity", "zbee.beacon.router", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Whether the device can accept join requests from routing capable devices.", HFILL }},

            { &hf_zbee_beacon_depth,
            { "Device Depth",           "zbee.beacon.depth", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The tree depth of the device, 0 indicates the network coordinator.", HFILL }},

            { &hf_zbee_beacon_end_device_capacity,
            { "End Device Capacity",        "zbee.beacon.end_dev", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Whether the device can accept join requests from ZigBee end devices.", HFILL }},

            { &hf_zbee_beacon_epid,
            { "Extended PAN ID",        "zbee.beacon.ext_panid", FT_EUI64, BASE_NONE, NULL, 0x0,
                "Extended PAN identifier.", HFILL }},

            { &hf_zbee_beacon_tx_offset,
            { "Tx Offset",              "zbee.beacon.tx_offset", FT_UINT32, BASE_DEC, NULL, 0x0,
                "The time difference between a device and its parent's beacon.", HFILL }},

            { &hf_zbee_beacon_update_id,
            { "Update ID",              "zbee.beacon.update_id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }}
    };

    /*  NWK Layer subtrees */
    static gint *ett[] = {
        &ett_zbee_nwk,
        &ett_zbee_beacon,
        &ett_zbee_nwk_fcf,
        &ett_zbee_nwk_mcast,
        &ett_zbee_nwk_route,
        &ett_zbee_nwk_cmd,
        &ett_zbee_nwk_cmd_options,
        &ett_zbee_nwk_cmd_cinfo
    };

    register_init_routine(proto_init_zbee_nwk);

    /* Register the protocol with Wireshark. */
    proto_zbee_nwk = proto_register_protocol("ZigBee Network Layer", "ZigBee NWK", ZBEE_PROTOABBREV_NWK);
    proto_register_field_array(proto_zbee_nwk, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissectors with Wireshark. */
    register_dissector(ZBEE_PROTOABBREV_NWK, dissect_zbee_nwk, proto_zbee_nwk);
    register_dissector("zbee.beacon", dissect_zbee_beacon, proto_zbee_nwk);

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
    aps_handle      = find_dissector("zbee.aps");

    /* Register our dissector with IEEE 802.15.4 */
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_zbee_nwk_heur, proto_zbee_nwk);

    /* Handoff the ZigBee security dissector code. */
    zbee_security_handoff();
} /* proto_reg_handoff_zbee */

static void free_keyring_val(gpointer a)
{
    GSList **slist = (GSList **)a;
    g_slist_free(*slist);
    return;
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
    /* Destroy the hash tables, if they exist. */
    if (zbee_nwk_map.short_table) g_hash_table_destroy(zbee_nwk_map.short_table);
    if (zbee_nwk_map.long_table) g_hash_table_destroy(zbee_nwk_map.long_table);
    if (zbee_table_nwk_keyring) g_hash_table_destroy(zbee_table_nwk_keyring);

    /* (Re)create the hash tables. */
    zbee_nwk_map.short_table = g_hash_table_new(ieee802154_short_addr_hash, ieee802154_short_addr_equal);
    zbee_nwk_map.long_table = g_hash_table_new(ieee802154_long_addr_hash, ieee802154_long_addr_equal);
    zbee_table_nwk_keyring  = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, free_keyring_val);
} /* proto_init_zbee_nwk */
