/* packet-zbee-zdp-management.c
 * Dissector helper routines for the management services of the ZigBee Device Profile
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-zbee.h"
#include "packet-zbee-zdp.h"

/**************************************
 * HELPER FUNCTIONS
 **************************************
 */
/**
 *Parses and displays a single network descriptor
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static void
zdp_parse_nwk_desc(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 version)
{
    proto_tree      *network_tree;
    proto_item      *ti;

    guint8      beacon;

    if (version >= ZBEE_VERSION_2007) {
        network_tree = proto_tree_add_subtree(tree, tvb, *offset, 12, ett_zbee_zdp_nwk_desc, NULL, "Network descriptor");
        /* Extended PAN Identifiers are used in ZigBee 2006 & later. */
        proto_tree_add_item(network_tree, hf_zbee_zdp_pan_eui64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
    }
    else {
        network_tree = proto_tree_add_subtree(tree, tvb, *offset, 6, ett_zbee_zdp_nwk_desc, NULL, "Network descriptor");
        /* Short PAN Identifiers are used in ZigBee 2003 and earlier. */
        proto_tree_add_item(network_tree, hf_zbee_zdp_pan_uint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    proto_tree_add_item(network_tree, hf_zbee_zdp_channel, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    proto_tree_add_item(network_tree, hf_zbee_zdp_profile, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(network_tree, hf_zbee_zdp_profile_version, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    ti = proto_tree_add_item(network_tree, hf_zbee_zdp_beacon, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(network_tree, hf_zbee_zdp_superframe, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    beacon      = tvb_get_guint8(tvb, *offset) & 0x0f;
    if (beacon == 0xf) {
        proto_item_append_text(ti, " (Beacons Disabled)");
    }
    *offset += 1;

    proto_tree_add_item(network_tree, hf_zbee_zdp_permit_joining, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

} /* zdp_parse_nwk_desc */

/**
 *Parses and displays a neighbor table entry.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static void
zdp_parse_neighbor_table_entry(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 version)
{
    proto_tree      *table_tree;
    proto_item      *ti = NULL;
    guint           len = 0;

    if (version >= ZBEE_VERSION_2007) {
        table_tree = proto_tree_add_subtree(tree, tvb, *offset, 8, ett_zbee_zdp_table_entry, &ti, "Table Entry");
        /* ZigBee 2006 & later use an extended PAN Identifier. */
        proto_tree_add_item(table_tree, hf_zbee_zdp_extended_pan, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        len += 8;
    }
    else {
        table_tree = proto_tree_add_subtree(tree, tvb, *offset, 2, ett_zbee_zdp_table_entry, &ti, "Table Entry");
        /* ZigBee 2003 & earlier use a short PAN Identifier. */
        proto_tree_add_item(table_tree, hf_zbee_zdp_pan_uint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        len += 2;
    }

    proto_tree_add_item(table_tree, hf_zbee_zdp_ext_addr, tvb, *offset + len, 8, ENC_LITTLE_ENDIAN);
    len += 8;

    proto_tree_add_item(table_tree, hf_zbee_zdp_addr, tvb, *offset + len, 2, ENC_LITTLE_ENDIAN);
    len += 2;

    if (version >= ZBEE_VERSION_2007) {
        proto_tree_add_item(table_tree, hf_zbee_zdp_table_entry_type, tvb, *offset + len, 1, ENC_NA);
        proto_tree_add_item(table_tree, hf_zbee_zdp_table_entry_idle_rx_0c, tvb, *offset + len, 1, ENC_NA);
        proto_tree_add_item(table_tree, hf_zbee_zdp_table_entry_relationship_70, tvb, *offset + len, 1, ENC_NA);
    }
    else {
        proto_tree_add_item(table_tree, hf_zbee_zdp_table_entry_type, tvb, *offset + len, 1, ENC_NA);
        proto_tree_add_item(table_tree, hf_zbee_zdp_table_entry_idle_rx_04, tvb, *offset + len, 1, ENC_NA);
        proto_tree_add_item(table_tree, hf_zbee_zdp_table_entry_relationship_18, tvb, *offset + len, 1, ENC_NA);
    }
    len += 1;

    if (version <= ZBEE_VERSION_2004) {
        /* In ZigBee 2003 & earlier, the depth field is before the permit joining field. */
        proto_tree_add_item(table_tree, hf_zbee_zdp_depth, tvb, *offset + len, 1, ENC_NA);
        len += 1;
    }

    proto_tree_add_item(table_tree, hf_zbee_zdp_permit_joining_03, tvb, *offset + len, 1, ENC_NA);
    len += 1;

    if (version >= ZBEE_VERSION_2007) {
        /* In ZigBee 2006 & later, the depth field is after the permit joining field. */
        proto_tree_add_item(table_tree, hf_zbee_zdp_depth, tvb, *offset + len, 1, ENC_NA);
        len += 1;
    }

    proto_tree_add_item(table_tree, hf_zbee_zdp_lqi, tvb, *offset + len, 1, ENC_NA);
    len += 1;

    if (tree) proto_item_set_len(ti, len);
    *offset += len;
} /* zdp_parse_neighbor_table_entry */

/**
 *Parses and displays a routing table entry.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static void
zdp_parse_routing_table_entry(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
    guint       len = 0;
    proto_item  *ti;
    proto_tree  *field_tree;
    guint16     dest;
    guint8      status;
    guint16     next;

    ti = proto_tree_add_item(tree, hf_zbee_zdp_rtg_entry, tvb, *offset + len, 2 + 1 + 2, ENC_NA);
    field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_rtg);

    proto_tree_add_item(field_tree, hf_zbee_zdp_rtg_destination, tvb,  *offset + len, 2, ENC_LITTLE_ENDIAN);
    dest = tvb_get_letohs(tvb, *offset + len);
    len += 2;

    proto_tree_add_item(field_tree, hf_zbee_zdp_rtg_status, tvb, *offset + len , 1, ENC_LITTLE_ENDIAN);
    status = tvb_get_guint8(tvb, *offset + len);
    len += 1;

    proto_tree_add_item(field_tree, hf_zbee_zdp_rtg_next_hop, tvb, *offset + len , 2, ENC_LITTLE_ENDIAN);
    next = tvb_get_letohs(tvb, *offset + len);
    len += 2;

    /* Display the next hop first, because it looks a lot cleaner that way. */
    proto_item_append_text(ti, " {Destination: 0x%04x, Next Hop: 0x%04x, Status: %s}", dest, next, val_to_str_const(status, zbee_zdp_rtg_status_vals, "Unknown"));
    *offset += len;
} /* zdp_parse_routing_table_entry */


/**************************************
 * MANAGEMENT REQUESTS
 **************************************
 */
/**
 *ZigBee Device Profile dissector for the network discovery
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_nwk_disc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hf_channel)
{
    proto_item  *ti;
    guint       i;

    guint   offset = 0;
    guint32 channels;

    /* Get the channel bitmap. */
    channels = tvb_get_letohl(tvb, offset);
    if (tree) {
        gboolean    first = 1;
        ti = proto_tree_add_uint_format(tree, hf_channel, tvb, offset, 4, channels, "Scan Channels: ");

        for (i=0; i<27; i++) {
            if (channels & (1<<i)) {
                if (first) proto_item_append_text(ti, "%d", i);
                else       proto_item_append_text(ti, ", %d", i);
                if (channels & (2<<i)) {
                    while ((channels&(2<<i)) && (i<26)) i++;
                    proto_item_append_text(ti, "-%d", i);
                }
                first = 0;
            }
        }
        if (first) proto_item_append_text(ti, "None");
    }
    offset += 4;

    proto_tree_add_item(tree, hf_zbee_zdp_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_nwk_disc */

/**
 *ZigBee Device Profile dissector for the link quality information
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_lqi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;

    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_lqi */

/**
 *ZigBee Device Profile dissector for the routing table
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_rtg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;

    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_rtg */

/**
 *ZigBee Device Profile dissector for the binding table
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;

    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_bind */

/**
 *ZigBee Device Profile dissector for the leave request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_leave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint   offset = 0;
    guint64 ext_addr;
    static int * const flags[] = {
        &hf_zbee_zdp_leave_children,
        &hf_zbee_zdp_leave_rejoin,
        NULL
    };

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, 8, NULL);
    if (version >= ZBEE_VERSION_2007) {
        /* Flags present on ZigBee 2006 & later. */
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_NA);
        offset += 1;
    }

    zbee_append_info(tree, pinfo, ", Device: %s", eui64_to_display(wmem_packet_scope(), ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_bind */

/**
 *ZigBee Device Profile dissector for the direct join request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_direct_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint64 ext_addr;
    /*guint8  cinfo;*/

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, 8, NULL);
    /*cinfo    =*/ zdp_parse_cinfo(tree, ett_zbee_zdp_cinfo, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Device: %s", eui64_to_display(wmem_packet_scope(), ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_direct_join */

/**
 *ZigBee Device Profile dissector for the permit joining
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_permit_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;

    proto_tree_add_item(tree, hf_zbee_zdp_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_significance, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_permit_join */

/**
 *ZigBee Device Profile dissector for the cache request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;

    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_cache */

/**
 *ZigBee Device Profile dissector for the nwk update request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_nwkupdate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint32  duration;

    zdp_parse_chanmask(tree, tvb, &offset, hf_zbee_zdp_channel_page, hf_zbee_zdp_channel_mask);
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN, &duration);
    offset += 1;

    if (duration == ZBEE_ZDP_NWKUPDATE_PARAMETERS) {
        proto_tree_add_item(tree, hf_zbee_zdp_update_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_zbee_zdp_manager, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
    else if (duration == ZBEE_ZDP_NWKUPDATE_CHANNEL_HOP) {
        proto_tree_add_item(tree, hf_zbee_zdp_update_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (duration <= ZBEE_ZDP_NWKUPDATE_SCAN_MAX) {
        proto_tree_add_item(tree, hf_zbee_zdp_scan_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_nwkupdate */

/**
 *ZigBee Device Profile dissector for the enhanced nwk update request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_nwkupdate_enh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint32 i, duration, count;

    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_channel_page_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
    offset += 1;

    for (i=0; i<count; i++) {
        zdp_parse_chanmask(tree, tvb, &offset, hf_zbee_zdp_channel_page, hf_zbee_zdp_channel_mask);
    }

    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN, &duration);
    offset += 1;

    if (duration == ZBEE_ZDP_NWKUPDATE_PARAMETERS) {
        proto_tree_add_item(tree, hf_zbee_zdp_update_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_zbee_zdp_manager, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
    else if (duration == ZBEE_ZDP_NWKUPDATE_CHANNEL_HOP) {
        proto_tree_add_item(tree, hf_zbee_zdp_update_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (duration <= ZBEE_ZDP_NWKUPDATE_SCAN_MAX) {
        proto_tree_add_item(tree, hf_zbee_zdp_scan_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_nwkupdate_enh */

/**
 *ZigBee Device Profile dissector for the IEEE Joining List Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_mgmt_ieee_join_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset = 0;

    proto_tree_add_item(tree, hf_zbee_zdp_ieee_join_start_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_ieee_join_list */

/**************************************
 * MANAGEMENT RESPONSES
 **************************************
 */
/**
 *ZigBee Device Profile dissector for the network discovery
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_nwk_disc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_tree  *field_tree = NULL;
    guint       offset = 0;

    guint8  status;
    guint32  i, table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    proto_tree_add_item(tree, hf_zbee_zdp_table_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_table_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &table_count);
    offset += 1;

    if (tree && table_count) {
        field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_zdp_nwk, NULL, "Network List");
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_nwk_desc(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_nwk_disc */

/**
 *ZigBee Device Profile dissector for the link quality information
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_lqi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_tree  *field_tree = NULL;
    guint       offset = 0;

    guint8  status;
    guint32  i, table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    proto_tree_add_item(tree, hf_zbee_zdp_table_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_table_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &table_count);
    offset += 1;

    if (table_count) {
        field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_zdp_lqi, NULL, "Neighbor Table");
        for (i=0; i<table_count; i++) {
            zdp_parse_neighbor_table_entry(field_tree, tvb, &offset, version);
        }
    }

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_lqi */

/**
 *ZigBee Device Profile dissector for the routing table
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_rtg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;

    guint8  status;
    guint32  i, table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    proto_tree_add_item(tree, hf_zbee_zdp_table_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_table_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &table_count);
    offset += 1;

    if (tree && table_count) {
        ti = proto_tree_add_item(tree, hf_zbee_zdp_rtg, tvb, offset, -1, ENC_NA);
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_rtg);
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_routing_table_entry(field_tree, tvb, &offset);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_rtg */

/**
 *ZigBee Device Profile dissector for the binding table
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_tree  *field_tree = NULL;
    guint       offset = 0;

    guint8  status;
    guint32  i, table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    proto_tree_add_item(tree, hf_zbee_zdp_table_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_table_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &table_count);
    offset += 1;


    if (tree && table_count) {
        field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_zdp_bind, NULL, "Binding Table");
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_bind */

/**
 *ZigBee Device Profile dissector for the leave response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_leave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_bind */

/**
 *ZigBee Device Profile dissector for the direct join response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_direct_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_direct_join */

/**
 *ZigBee Device Profile dissector for the permit joining response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_permit_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_permit_join */

/**
 *ZigBee Device Profile dissector for the cache response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *field_tree = NULL;
    proto_tree  *ti;
    guint       offset = 0;

    guint8  status;
    guint32  i, table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    proto_tree_add_item(tree, hf_zbee_zdp_table_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_zbee_zdp_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_table_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &table_count);
    offset += 1;

    if (table_count) {
        field_tree = proto_tree_add_subtree(tree, tvb, offset, table_count*(2+8),
                                ett_zbee_zdp_cache, NULL, "Discovery Cache");

        for (i=0; i<table_count; i++) {
            guint16 addr16 = tvb_get_letohs(tvb, offset+8);

            ti = proto_tree_add_item(field_tree, hf_zbee_zdp_cache_address, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            /* XXX - make 16-bit address filterable? */
            proto_item_append_text(ti, " = 0x%04x", addr16);
            proto_item_set_len(ti, 8+2);
            offset += 2+8;
        }
    }

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_bind */

/**
 *ZigBee Device Profile dissector for both the enhanced and
 *non-enhanced nwk update notify.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_not_mgmt_nwkupdate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;
    guint       i, j;

    /*guint8      status;*/
    guint32     channels, channel_count;

    /*status      =*/ zdp_parse_status(tree, tvb, &offset);
    channels    = zdp_parse_chanmask(tree, tvb, &offset, hf_zbee_zdp_channel_page, hf_zbee_zdp_channel_mask);
    proto_tree_add_item(tree, hf_zbee_zdp_tx_total, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zbee_zdp_tx_fail, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_channel_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &channel_count);
    offset += 1;

    /* Display the channel list. */
    for (i=0, j=0; i<(8*4); i++) {
        guint8  energy;

        if ( ! ((1<<i) & channels) ) {
            /* Channel not scanned. */
            continue;
        }
        if (j>=channel_count) {
            /* Channel list has ended. */
            break;
        }
        /* Get and display the channel energy. */
        energy = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_zbee_zdp_channel_energy, tvb, offset, 1, energy, "Channel %d Energy: 0x%02x", i, energy);
        offset += 1;
        /* Increment the number of channels we found energy values for. */
        j++;
    } /* for */

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_not_mgmt_nwkupdate */

/**
 *ZigBee Device Profile dissector for the IEEE Joining List Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_mgmt_ieee_join_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint32     i, status, list_total, list_count;
    guint       offset = 0;

    status = zdp_parse_status(tree, tvb, &offset);
    if (status == 0x00) {
        proto_tree_add_item(tree, hf_zbee_zdp_ieee_join_update_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_zbee_zdp_ieee_join_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_ieee_join_list_total, tvb, offset, 1, ENC_LITTLE_ENDIAN, &list_total);
        offset += 1;

        if (list_total > 0) {
            proto_tree_add_item(tree, hf_zbee_zdp_ieee_join_list_start, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item_ret_uint(tree, hf_zbee_zdp_ieee_join_list_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &list_count);
            offset += 1;

            for(i=0; i<list_count; i++) {
                zbee_parse_eui64(tree, hf_zbee_zdp_ieee_join_list_ieee, tvb, &offset, 8, NULL);
            }
        }
    }
    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_ieee_join_list */

/**
 *ZigBee Device Profile dissector for the unsolicited nwk update notify.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_not_mgmt_unsolicited_nwkupdate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;

    zdp_parse_status(tree, tvb, &offset);
    zdp_parse_chanmask(tree, tvb, &offset, hf_zbee_zdp_channel_page, hf_zbee_zdp_channel_mask);
    proto_tree_add_item(tree, hf_zbee_zdp_tx_total, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zbee_zdp_tx_fail, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zbee_zdp_tx_retries, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zbee_zdp_period_time_results, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_not_mgmt_unsolicited_nwkupdate */

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
