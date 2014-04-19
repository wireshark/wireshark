/* packet-zbee-zdp-management.c
 * Dissector helper routines for the management services of the ZigBee Device Profile
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-zbee.h"
#include "packet-zbee-zdp.h"

/**************************************
 * HELPER FUNCTIONS
 **************************************
 */
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_nwk_desc
 *  DESCRIPTION
 *      Parses and displays a single network descriptor
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zdp_parse_nwk_desc(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 version)
{
    proto_item      *ti = NULL;
    guint           len = 0;

    guint64     ext_pan;
    guint16     pan;
    guint8      channel;
    guint8      profile;
    guint8      profile_version;
    guint8      beacon;
    guint8      superframe;
    gboolean    permit;

    if (version >= ZBEE_VERSION_2007) {
        /* Extended PAN Identifiers are used in ZigBee 2006 & later. */
        ext_pan = tvb_get_letoh64(tvb, *offset + len);
        if (tree) ti = proto_tree_add_text(tree, tvb, *offset, 0, "{Pan: %s", eui64_to_str(ext_pan));
        len += 8;
    }
    else {
        /* Short PAN Identifiers are used in ZigBee 2003 and earlier. */
        pan = tvb_get_letohs(tvb, *offset + len);
        if (tree) ti = proto_tree_add_text(tree, tvb, *offset, 0, "{Pan: 0x%04x", pan);
        len += 2;
    }

    channel = tvb_get_guint8(tvb, *offset + len);
    if (tree) proto_item_append_text(ti, ", Channel: %d", channel);
    len += 1;

    profile = (tvb_get_guint8(tvb, *offset + len) & 0x0f) >> 0;
    profile_version = (tvb_get_guint8(tvb, *offset + len) & 0xf0) >> 4;
    if (tree) proto_item_append_text(ti, ", Profile: 0x%01x, Version: %d", profile, profile_version);
    len += 1;

    beacon      = (tvb_get_guint8(tvb, *offset + len) & 0x0f) >> 0;
    superframe  = (tvb_get_guint8(tvb, *offset + len) & 0xf0) >> 4;
    if ((tree) && (beacon == 0xf)) {
        proto_item_append_text(ti, ", Beacons Disabled");
    }
    else if (tree) {
        proto_item_append_text(ti, ", BeaconOrder: %d, SuperframeOrder: %d", beacon, superframe);
    }
    len += 1;

    permit = tvb_get_guint8(tvb, *offset) & 0x01;
    if (tree) proto_item_append_text(ti, ", PermitJoining: %s}", permit?"True":"False");
    len += 1;

    if (tree) proto_item_set_len(ti, len);
    *offset += len;
} /* zdp_parse_nwk_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_neighbor_table_entry
 *  DESCRIPTION
 *      Parses and displays a neighbor table entry.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zdp_parse_neighbor_table_entry(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 version)
{
    proto_item      *ti = NULL;
    guint           len = 0;

    guint64 ext_pan;
    guint16 pan;
    guint64 ext_addr;
    guint16 device;
    guint8  type;
    guint8  idle_rx;
    guint8  rel;
    guint8  permit_joining;
    guint8  depth;
    guint8  lqi;

    if (version >= ZBEE_VERSION_2007) {
        /* ZigBee 2006 & later use an extended PAN Identifier. */
        ext_pan = tvb_get_letoh64(tvb, *offset + len);
        if (tree) ti = proto_tree_add_text(tree, tvb, *offset, 0, "{Extended PAN: %s", eui64_to_str(ext_pan));
        len += 8;
    }
    else {
        /* ZigBee 2003 & earlier use a short PAN Identifier. */
        pan = tvb_get_letohs(tvb, *offset + len);
        if (tree) ti = proto_tree_add_text(tree, tvb, *offset, 0, "{PAN: 0x%04x", pan);
        len += 2;
    }

    ext_addr = tvb_get_letoh64(tvb, *offset + len);
    if (tree) proto_item_append_text(ti, ", Extended Addr: %s", ep_eui64_to_display(ext_addr));
    len += 8;

    device = tvb_get_letohs(tvb, *offset + len);
    if (tree) proto_item_append_text(ti, ", Addr: 0x%04x", device);
    len += 2;

    if (version >= ZBEE_VERSION_2007) {
        type    = (tvb_get_guint8(tvb, *offset + len) & 0x03) >> 0;
        idle_rx = (tvb_get_guint8(tvb, *offset + len) & 0x0c) >> 2;
        rel     = (tvb_get_guint8(tvb, *offset + len) & 0x70) >> 4;
    }
    else {
        type    = (tvb_get_guint8(tvb, *offset + len) & 0x03) >> 0;
        idle_rx = (tvb_get_guint8(tvb, *offset + len) & 0x04) >> 2;
        rel     = (tvb_get_guint8(tvb, *offset + len) & 0x18) >> 3;
    }
    if (tree) {
        if (type == 0x00)       proto_item_append_text(ti, ", Type: Coordinator");
        else if (type == 0x01)  proto_item_append_text(ti, ", Type: Router");
        else if (type == 0x02)  proto_item_append_text(ti, ", Type: End Device");
        else                    proto_item_append_text(ti, ", Type: Unknown");

        if (idle_rx == 0x00)    proto_item_append_text(ti, ", Idle Rx: False");
        else if (idle_rx==0x01) proto_item_append_text(ti, ", Idle Rx: True");
        else                    proto_item_append_text(ti, ", Idle Rx: Unknown");

        if (rel == 0x00)        proto_item_append_text(ti, ", Relationship: Parent");
        else if (rel == 0x01)   proto_item_append_text(ti, ", Relationship: Child");
        else if (rel == 0x02)   proto_item_append_text(ti, ", Relationship: Sibling");
        else if (rel == 0x03)   proto_item_append_text(ti, ", Relationship: None");
        else if (rel == 0x04)   proto_item_append_text(ti, ", Relationship: Previous Child");
        else                    proto_item_append_text(ti, ", Relationship: Unknown");
    }
    len += 1;

    if (version <= ZBEE_VERSION_2004) {
        /* In ZigBee 2003 & earlier, the depth field is before the permit joining field. */
        depth = tvb_get_guint8(tvb, *offset + len);
        if (tree) proto_item_append_text(ti, ", Depth: %d", depth);
        len += 1;
    }

    permit_joining = (tvb_get_guint8(tvb, *offset + len) & 0x03) >> 0;
    if (tree) {
        if (permit_joining == 0x00)     proto_item_append_text(ti, ", Permit Joining: False");
        else if (permit_joining == 0x01)proto_item_append_text(ti, ", Permit Joining: True");
        else                            proto_item_append_text(ti, ", Permit Joining: Unknown");
    }
    len += 1;

    if (version >= ZBEE_VERSION_2007) {
        /* In ZigBee 2006 & later, the depth field is after the permit joining field. */
        depth = tvb_get_guint8(tvb, *offset + len);
        if (tree) proto_item_append_text(ti, ", Depth: %d", depth);
        len += 1;
    }

    lqi = tvb_get_guint8(tvb, *offset + len);
    if (tree) proto_item_append_text(ti, ", LQI: %d}", lqi);
    len += 1;

    if (tree) proto_item_set_len(ti, len);
    *offset += len;
} /* zdp_parse_neighbor_table_entry */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zdp_parse_routing_table_entry
 *  DESCRIPTION
 *      Parses and displays a routing table entry.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
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
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_nwk_disc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the network discovery
 *      request. Cluster ID = 0x0030.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_nwk_disc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    guint       i;

    guint   offset = 0;
    guint32 channels;
    /*guint8  duration;*/
    /*guint8  idx;*/

    /* Get the channel bitmap. */
    channels = tvb_get_letohl(tvb, offset);
    if (tree) {
        gboolean    first = 1;
        ti = proto_tree_add_text(tree, tvb, offset, 4, "Scan Channels: ");

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

    /*duration =*/ zbee_parse_uint(tree, hf_zbee_zdp_duration, tvb, &offset, 1, NULL);
    /*idx      =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_nwk_disc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_lqi
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the link quality information
 *      request. Cluster ID = 0x0031.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_lqi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint8  idx;*/

    /*idx =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_lqi */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_rtg
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the routing table
 *      request. Cluster ID = 0x0032.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_rtg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint8  idx;*/

    /*idx =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_rtg */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the binding table
 *      request. Cluster ID = 0x0033.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint8  idx;*/

    /*idx =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_leave
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the leave request.
 *      Cluster ID = 0x0034.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_leave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint   offset = 0;
    guint64 ext_addr;
    guint8  flags;

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, 8, NULL);
    if (version >= ZBEE_VERSION_2007) {
        /* Flags present on ZigBee 2006 & later. */
        flags    = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_boolean(tree, hf_zbee_zdp_leave_children, tvb, offset, 1, flags & ZBEE_ZDP_MGMT_LEAVE_CHILDREN);
            proto_tree_add_boolean(tree, hf_zbee_zdp_leave_rejoin, tvb, offset, 1, flags & ZBEE_ZDP_MGMT_LEAVE_REJOIN);
        }
        offset += 1;
    }

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_direct_join
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the direct join request.
 *      Cluster ID = 0x0035.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_direct_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint64 ext_addr;
    /*guint8  cinfo;*/

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, 8, NULL);
    /*cinfo    =*/ zdp_parse_cinfo(tree, ett_zbee_zdp_cinfo, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_direct_join */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_permit_join
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the permit joining
 *      request. Cluster ID = 0x0036.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_permit_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint8  duration;*/
    /*guint8  significance;*/

    /*duration     =*/ zbee_parse_uint(tree, hf_zbee_zdp_duration, tvb, &offset, 1, NULL);
    /*significance =*/ zbee_parse_uint(tree, hf_zbee_zdp_significance, tvb, &offset, 1, NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_permit_join */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the cache request.
 *      Cluster ID = 0x0037.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint8  idx;*/

    /*idx =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_mgmt_nwkupdate
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the nwk update request.
 *      Cluster ID = 0x0038.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_mgmt_nwkupdate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint32 channels;*/
    guint8  duration;
    /*guint8  count;*/
    /*guint8  update_id;*/
    /*guint16 manager;*/

    /*channels =*/ zdp_parse_chanmask(tree, tvb, &offset);
    duration = zbee_parse_uint(tree, hf_zbee_zdp_duration, tvb, &offset, 1, NULL);
    if (duration == ZBEE_ZDP_NWKUPDATE_PARAMETERS) {
        /*update_id =*/ zbee_parse_uint(tree, hf_zbee_zdp_update_id, tvb, &offset, 1, NULL);
        /*manager =*/ zbee_parse_uint(tree, hf_zbee_zdp_manager, tvb, &offset, 2, NULL);
    }
    else if (duration == ZBEE_ZDP_NWKUPDATE_CHANNEL_HOP) {
        /*update_id =*/ zbee_parse_uint(tree, hf_zbee_zdp_update_id, tvb, &offset, 1, NULL);
    }
    else if (duration <= ZBEE_ZDP_NWKUPDATE_SCAN_MAX) {
        /*count =*/ zbee_parse_uint(tree, hf_zbee_zdp_scan_count, tvb, &offset, 1, NULL);
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_mgmt_nwkupdate */

/**************************************
 * MANAGEMENT RESPONSES
 **************************************
 */
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_nwk_disc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the network discovery
 *      response. Cluster ID = 0x8030.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_mgmt_nwk_disc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint8  table_size;*/
    /*guint8  idx;*/
    guint8  table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, 1, NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, 1, NULL);

    if (tree && table_count) {
        ti = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Network List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_nwk);
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_nwk_desc(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_nwk_disc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_lqi
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the link quality information
 *      response. Cluster ID = 0x8031.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_mgmt_lqi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint8  table_size;*/
    /*guint8  idx;*/
    guint8  table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, 1, NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, 1, NULL);

    if (tree && table_count) {
        ti = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Neighbor Table");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_lqi);
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_neighbor_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_lqi */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_rtg
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the routing table
 *      response. Cluster ID = 0x8032.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_mgmt_rtg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint8  table_size;*/
    /*guint8  idx;*/
    guint8  table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, 1, NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, 1, NULL);

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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the binding table
 *      response. Cluster ID = 0x8033.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_mgmt_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint8  table_size;*/
    /*guint8  idx;*/
    guint8  table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, 1, NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, 1, NULL);

    if (tree && table_count) {
        ti = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Binding Table");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind);
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_leave
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the leave response.
 *      Cluster ID = 0x8034.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_direct_join
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the direct join response.
 *      Cluster ID = 0x8035.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_permit_join
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the permit joining response.
 *      Cluster ID = 0x8036.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the cache response.
 *      Cluster ID = 0x8037.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_mgmt_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint8  table_size;*/
    /*guint8  idx;*/
    guint8  table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, 1, NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, 1, NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, 1, NULL);

    if (tree && table_count) {
        ti = proto_tree_add_text(tree, tvb, offset, table_count*(2+8), "Discovery Cache");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_cache);
    } else {
        field_tree = NULL;
    }
    for (i=0; i<table_count; i++) {
        guint64 addr64 = tvb_get_letoh64(tvb, offset);
        guint16 addr16 = tvb_get_letohs(tvb, offset+8);

        if (field_tree) {
            proto_tree_add_text(field_tree, tvb, offset, 2+8, "{%s = 0x%04x}", ep_eui64_to_display(addr64), addr16);
        }
        offset += 2+8;
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_mgmt_nwkupdate
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the nwk update notify.
 *      Cluster ID = 0x8038.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_mgmt_nwkupdate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;
    guint       i, j;

    /*guint8      status;*/
    guint32     channels;
    /*guint16     tx_total;*/
    /*guint16     tx_fail;*/
    guint8      channel_count;

    /*status      =*/ zdp_parse_status(tree, tvb, &offset);
    channels    = zdp_parse_chanmask(tree, tvb, &offset);
    /*tx_total    =*/ zbee_parse_uint(tree, hf_zbee_zdp_tx_total, tvb, &offset, 2, NULL);
    /*tx_fail     =*/ zbee_parse_uint(tree, hf_zbee_zdp_tx_fail, tvb, &offset, 2, NULL);
    channel_count     = zbee_parse_uint(tree, hf_zbee_zdp_channel_count, tvb, &offset, 1, NULL);

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
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, 1, "Channel %d Energy = 0x%02x", i, energy);
        }
        offset += 1;
        /* Increment the number of channels we found energy values for. */
        j++;
    } /* for */

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_mgmt_nwkupdate */
