/* packet-zbee-zdp-discovery.c
 * Dissector helper routines for the discovery services of the ZigBee Device Profile
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
#include <epan/wmem/wmem.h>

#include "packet-zbee.h"
#include "packet-zbee-zdp.h"

/**************************************
 * DISCOVERY REQUESTS
 **************************************
 */
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_nwk_addr
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the network address
 *      request. Cluster ID = 0x0000.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_nwk_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint64 ext_addr;
    /*guint8  req_type;*/
    /*guint8  idx;*/

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, sizeof(guint64), NULL);
    /*req_type =*/ zbee_parse_uint(tree, hf_zbee_zdp_req_type, tvb, &offset, sizeof(guint8), NULL);
    /*idx      =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, sizeof(guint8), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_nwk_addr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_ext_addr
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the extended address
 *      request. Cluster ID = 0x0001.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_ext_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint16 device;
    /*guint8  req_type;*/
    /*guint8  idx;*/

    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, sizeof(guint16), NULL);
    /*req_type =*/ zbee_parse_uint(tree, hf_zbee_zdp_req_type, tvb, &offset, sizeof(guint8), NULL);
    /*idx      =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, sizeof(guint8), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_ext_addr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the descriptor
 *      requests. Cluster ID = 0x0002.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_node_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, sizeof(guint16), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_node_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_power_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the node descriptor
 *      request. Cluster ID = 0x0003.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_power_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, sizeof(guint16), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_power_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_simple_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the simple descriptor
 *      request. Cluster ID = 0x0004.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_simple_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;
    guint8  endpt;

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, sizeof(guint16), NULL);
    endpt  = zbee_parse_uint(tree, hf_zbee_zdp_endpoint, tvb, &offset, sizeof(guint8), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x, Endpoint: %d", device, endpt);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_active_ep
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the active endpoint list
 *      request. Cluster ID = 0x0005.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_active_ep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, sizeof(guint16), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_active_ep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_match_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the matching descriptor
 *      request. Cluster ID = 0x0006.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_match_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item      *ti;
    proto_tree      *field_tree = NULL;
    guint           offset = 0, i;
    guint           sizeof_cluster = (version >= ZBEE_VERSION_2007)?(int)sizeof(guint16):(int)sizeof(guint8);

    guint16 device;
    guint16 profile;
    guint8  in_count;
    guint8  out_count;

    device  = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    profile = zbee_parse_uint(tree, hf_zbee_zdp_profile, tvb, &offset, (int)sizeof(guint16), NULL);

    /* Add the input cluster list. */
    in_count = zbee_parse_uint(tree, hf_zbee_zdp_in_count, tvb, &offset, (int)sizeof(guint8), NULL);
    if (tree && in_count) {
        ti = proto_tree_add_text(tree, tvb, offset, in_count*sizeof_cluster, "Input Cluster List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_match_in);
    }
    for (i=0; i<in_count; i++) zbee_parse_uint(field_tree, hf_zbee_zdp_in_cluster, tvb, &offset, sizeof_cluster, NULL);

    /* Add the output cluster list. */
    out_count = zbee_parse_uint(tree, hf_zbee_zdp_out_count, tvb, &offset, (int)sizeof(guint8), NULL);
    if (tree && out_count) {
        ti = proto_tree_add_text(tree, tvb, offset, out_count*sizeof_cluster, "Output Cluster List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_match_out);
    }
    for (i=0; i<out_count; i++) zbee_parse_uint(field_tree, hf_zbee_zdp_out_cluster, tvb, &offset, sizeof_cluster, NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x, Profile: 0x%04x", device, profile);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_complex_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the complex descriptor
 *      request. Cluster ID = 0x0010.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_complex_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_complex_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_user_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the user descriptor
 *      request. Cluster ID = 0x0011.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_user_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_user_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_discovery_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the discovery cache
 *      request. Cluster ID = 0x0012.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_discovery_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 device;*/
    guint64 ext_addr;

    /*device   =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_discovery_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_device_annce
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the device announcement.
 *      Cluster ID = 0x0013.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_device_annce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 device;*/
    guint64 ext_addr;
    /*guint8  capability;*/

    /*device      =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr    = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    /*capability  =*/ zdp_parse_cinfo(tree, ett_zbee_zdp_cinfo, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_device_annce */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_set_user_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the end set user
 *      descriptor request. Cluster ID = 0x0014.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_set_user_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint   offset = 0;
    guint16 device;
    guint8  user_length;
    gchar   *user;

    device      = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    if (version >= ZBEE_VERSION_2007) {
        user_length = zbee_parse_uint(tree, hf_zbee_zdp_user_length, tvb, &offset, (int)sizeof(guint8), NULL);
    }
    else {
        /* No Length field in ZigBee 2003 & earlier, uses a fixed length of 16. */
        user_length = 16;
    }
    user        = (gchar *)wmem_alloc(wmem_packet_scope(), user_length+1);
    user        = (gchar *)tvb_memcpy(tvb, user, offset, user_length);
    user[user_length] = '\0';
    if (tree) {
        proto_tree_add_string(tree, hf_zbee_zdp_user, tvb, offset, user_length, user);
    }
    offset += user_length;

    zbee_append_info(tree, pinfo, ", Device: 0x%04x, Desc: \'%s\'", device, user);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_set_user_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_system_server_disc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the system server
 *      discovery request. Cluster ID = 0x0015.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_system_server_disc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 server_flags;*/

    /*server_flags =*/ zdp_parse_server_flags(tree, ett_zbee_zdp_server, tvb, &offset);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_system_server_disc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_store_discovery
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store node cache
 *      request. Cluster ID = 0x0016.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_store_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    /*guint16 device;*/
    guint64 ext_addr;
    /*guint8  node_size;*/
    /*guint8  power_size;*/
    /*guint8  ep_count;*/
    guint8  simple_count;

    /*device      =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr    = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    /*node_size   =*/ zbee_parse_uint(tree, hf_zbee_zdp_disc_node_size, tvb, &offset, (int)sizeof(guint8), NULL);
    /*power_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_disc_power_size, tvb, &offset, (int)sizeof(guint8), NULL);
    /*ep_count    =*/ zbee_parse_uint(tree, hf_zbee_zdp_disc_ep_count, tvb, &offset, (int)sizeof(guint8), NULL);
    simple_count= zbee_parse_uint(tree, hf_zbee_zdp_disc_simple_count, tvb, &offset, (int)sizeof(guint8), NULL);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, simple_count, "Simple Descriptor Sizes");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_simple_sizes);
    }
    for (i=0; i<simple_count; i++) {
        zbee_parse_uint(field_tree, hf_zbee_zdp_disc_simple_size, tvb, &offset, (int)sizeof(guint8), NULL);
    }

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_discovery */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_store_node_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store node descriptor
 *      request. Cluster ID = 0x0017.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_store_node_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint   offset = 0;
    /*guint16 device;*/
    guint64 ext_addr;

    /*device   =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    zdp_parse_node_desc(tree, ett_zbee_zdp_node, tvb, &offset, version);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_node_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_store_power_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store power descriptor
 *      request. Cluster ID = 0x0018.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_store_power_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 device;*/
    guint64 ext_addr;

    /*device   =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    zdp_parse_power_desc(tree, ett_zbee_zdp_power, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_power_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_store_active_ep
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store active endpoint
 *      request. Cluster ID = 0x0019.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_store_active_ep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    /*guint16     device;*/
    guint64     ext_addr;
    guint8      ep_count;

    /*device   =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    ep_count = zbee_parse_uint(tree, hf_zbee_zdp_ep_count, tvb, &offset, (int)sizeof(guint8), NULL);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, ep_count, "Active Endpoints");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_endpoint);
    }
    for (i=0; i<ep_count; i++) {
        (void)zbee_parse_uint(field_tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
    }

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_active_ep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_store_simple_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store simple descriptor
 *      request. Cluster ID = 0x001a.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_store_simple_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint   offset = 0;
    /*guint16 device;*/
    guint64 ext_addr;
    /*guint8  simple_len;*/

    /*device      =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr    = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    /*simple_len  =*/ zbee_parse_uint(tree, hf_zbee_zdp_simple_length, tvb, &offset, (int)sizeof(guint8), NULL);
    zdp_parse_simple_desc(tree, ett_zbee_zdp_simple, tvb, &offset, version);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_remove_node_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the remove node cache
 *      request. Cluster ID = 0x001b.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_remove_node_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset   = 0;
    /*guint16 device;*/
    guint64 ext_addr;

    /*device   =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_remove_node_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_find_node_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the find node cache
 *      request. Cluster ID = 0x001c.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_find_node_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 device;*/
    guint64 ext_addr;

    /*device   =*/ zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_find_node_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_ext_simple_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the extended simple
 *      descriptor request. Cluster ID = 0x001d.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_ext_simple_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;
    guint8  endpt;
    /*guint8  idx;*/

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    endpt  = zbee_parse_uint(tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
    /*idx    =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint8), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x, Endpoint: %d", device, endpt);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_ext_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_ext_active_ep
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the extended active
 *      endpoint list request. Cluster ID = 0x001e.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_ext_active_ep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint16 device;
    /*guint8  idx;*/

    device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx    =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint8), NULL);

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_ext_active_ep */

/**************************************
 * DISCOVERY RESPONSES
 **************************************
 */
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_nwk_addr
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the network address
 *      response. Cluster ID = 0x8000.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_nwk_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8      status;
    guint64     ext_addr;
    guint16     device;
    guint8      assoc;
    /*guint8      idx;*/

    status   = zdp_parse_status(tree, tvb, &offset);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);

    if (tvb_bytes_exist(tvb, offset, 2*(int)sizeof(guint8))) {
        /* The presence of these fields depends on the request message. Include them if they exist. */
        assoc    = zbee_parse_uint(tree, hf_zbee_zdp_assoc_device_count, tvb, &offset, (int)sizeof(guint8), NULL);
        /*idx      =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint8), NULL);

        if ((tree) && (assoc)) {
            ti = proto_tree_add_text(tree, tvb, offset, assoc*(int)sizeof(guint16), "Associated Device List");
            field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_assoc_device);
        }
        for (i=0; i<assoc; i++) {
            (void)zbee_parse_uint(field_tree, hf_zbee_zdp_assoc_device, tvb, &offset, (int)sizeof(guint16), NULL);
        }
    }

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));
    if (status == ZBEE_ZDP_STATUS_SUCCESS) {
        zbee_append_info(tree, pinfo, ", Device: %s = 0x%04x", ep_eui64_to_display(ext_addr), device);
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_nwk_addr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_ext_addr
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the extended address
 *      response. Cluster ID = 0x8001.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_ext_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8      status;
    guint64     ext_addr;
    guint16     device;
    guint8      assoc;
    /*guint8      idx;*/

    status   = zdp_parse_status(tree, tvb, &offset);
    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);

    if (tvb_bytes_exist(tvb, offset, 2*(int)sizeof(guint8))) {
        /* The presence of these fields depends on the request message. Include them if they exist. */
        assoc    = zbee_parse_uint(tree, hf_zbee_zdp_assoc_device_count, tvb, &offset, (int)sizeof(guint8), NULL);
        /*idx      =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint8), NULL);

        if ((tree) && (assoc)) {
            ti = proto_tree_add_text(tree, tvb, offset, assoc*(int)sizeof(guint16), "Associated Device List");
            field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_assoc_device);
        }
        for (i=0; i<assoc; i++) {
            (void)zbee_parse_uint(field_tree, hf_zbee_zdp_assoc_device, tvb, &offset, (int)sizeof(guint16), NULL);
        }
    }

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));
    if (status == ZBEE_ZDP_STATUS_SUCCESS) {
        zbee_append_info(tree, pinfo, ", Device: 0x%04x = %s", device, ep_eui64_to_display(ext_addr));
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_ext_addr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_node_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the node descriptor
 *      response. Cluster ID = 0x8002.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_node_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint       offset = 0;

    guint8      status;
    guint16     device;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    if (status == ZBEE_ZDP_STATUS_SUCCESS) {
        zdp_parse_node_desc(tree, ett_zbee_zdp_node, tvb, &offset, version);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_node_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_power_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the power descriptor
 *      response. Cluster ID = 0x8003.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_power_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;
    guint16     device;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    if (status == ZBEE_ZDP_STATUS_SUCCESS) {
        zdp_parse_power_desc(tree, ett_zbee_zdp_power, tvb, &offset);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_power_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_simple_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the simple descriptor
 *      response. Cluster ID = 0x8004.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_simple_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint       offset = 0;

    guint8      status;
    /*guint8      length;*/
    guint16     device;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    /*length   =*/ zbee_parse_uint(tree, hf_zbee_zdp_simple_length, tvb, &offset, (int)sizeof(guint8), NULL);
    if (status == ZBEE_ZDP_STATUS_SUCCESS) {
        zdp_parse_simple_desc(tree, ett_zbee_zdp_simple, tvb, &offset, version);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_active_ep
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the active endpoint
 *      response. Cluster ID = 0x8005.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_active_ep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8      status;
    guint16     device;
    guint8      ep_count;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ep_count = zbee_parse_uint(tree, hf_zbee_zdp_ep_count, tvb, &offset, (int)sizeof(guint8), NULL);

    if (tree && ep_count) {
        ti = proto_tree_add_text(tree, tvb, offset, ep_count*(int)sizeof(guint8), "Active Endpoint List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_endpoint);
    }
    for (i=0; i<ep_count; i++) {
        (void)zbee_parse_uint(field_tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_active_ep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_match_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the simple descriptor
 *      response. Cluster ID = 0x8003.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_match_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8      status;
    guint16     device;
    guint8      ep_count;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ep_count = zbee_parse_uint(tree, hf_zbee_zdp_ep_count, tvb, &offset, (int)sizeof(guint8), NULL);

    if (tree && ep_count) {
        ti = proto_tree_add_text(tree, tvb, offset, ep_count*(int)sizeof(guint8), "Matching Endpoint List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_endpoint);
    }
    for (i=0; i<ep_count; i++) {
        (void)zbee_parse_uint(field_tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_match_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_complex_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the complex descriptor
 *      response. Cluster ID = 0x8010.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_complex_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;
    guint8      length;
    guint16     device;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    length   = zbee_parse_uint(tree, hf_zbee_zdp_complex_length, tvb, &offset, (int)sizeof(guint8), NULL);
    if (length) {
        zdp_parse_complex_desc(tree, -1, tvb, &offset, length);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_complex_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_user_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the user descriptor
 *      response. Cluster ID = 0x8011.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_user_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint       offset = 0;
    guint8      status;
    guint16     device;
    guint8      user_length;
    gchar       *user;

    status      = zdp_parse_status(tree, tvb, &offset);
    device      = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    if ((version >= ZBEE_VERSION_2007) || (status == ZBEE_ZDP_STATUS_SUCCESS)) {
        /* In ZigBee 2003 & earlier, the length field is omitted if not successful. */
        user_length = zbee_parse_uint(tree, hf_zbee_zdp_user_length, tvb, &offset, (int)sizeof(guint8), NULL);
    }
    else user_length = 0;

    user        = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, user_length, ENC_ASCII);
    if (tree) {
        proto_tree_add_string(tree, hf_zbee_zdp_user, tvb, offset, user_length, user);
    }
    offset += user_length;

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    if (status == ZBEE_ZDP_STATUS_SUCCESS) {
        zbee_append_info(tree, pinfo, ", Desc: \'%s\'", user);
    }
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_user_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_user_desc_conf
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the set user descriptor
 *      confirmation. Cluster ID = 0x8014.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_user_desc_conf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint       offset = 0;
    guint8      status;
    guint16     device = 0;

    status      = zdp_parse_status(tree, tvb, &offset);
    if (version >= ZBEE_VERSION_2007) {
        /* Device address present only on ZigBee 2006 & later. */
        device = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_user_desc_conf */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_discovery_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the discovery cache
 *      response. Cluster ID = 0x8012.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_discovery_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status      = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_discovery_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_system_server_disc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the system server discovery
 *      response. Cluster ID = 0x8015.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_system_server_disc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;
    /*guint16     server;*/

    status   = zdp_parse_status(tree, tvb, &offset);
    /*server =*/ zdp_parse_server_flags(tree, ett_zbee_zdp_server, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_system_server_disc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_discovery_store
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the discovery store
 *      response. Cluster ID = 0x8016.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_discovery_store(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_discovery_store */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_store_node_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store node descriptor
 *      response. Cluster ID = 0x8017.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_store_node_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status      = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_store_node_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_store_power_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store power descriptor
 *      response. Cluster ID = 0x8018.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_store_power_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status      = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_store_power_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_store_active_ep
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store active endpoints
 *      response. Cluster ID = 0x8019.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_store_active_ep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status      = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_store_active_ep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_store_simple_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store power descriptor
 *      response. Cluster ID = 0x801a.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_store_simple_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status      = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_store_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_remove_node_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the remove node cache
 *      response. Cluster ID = 0x801b.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_remove_node_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint8      status;

    status      = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_remove_node_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_find_node_cache
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the find node cache
 *      response. Cluster ID = 0x801c.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_find_node_cache(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;

    guint16     cache;
    guint16     device;
    /*guint64     ext_addr;*/

    cache    = zbee_parse_uint(tree, hf_zbee_zdp_cache, tvb, &offset, (int)sizeof(guint16), NULL);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    /*ext_addr =*/ zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);

    zbee_append_info(tree, pinfo, ", Cache: 0x%04x", cache);
    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_find_node_cache */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_ext_simple_desc
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the extended simple
 *      descriptor response. Cluster ID = 0x801d.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_ext_simple_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint       offset = 0;
    guint       i;
    guint       sizeof_cluster = (int)sizeof(guint16);

    guint8      status;
    guint16     device;
    /*guint8      endpt;*/
    guint8      in_count;
    guint8      out_count;
    guint8      idx;

    status      = zdp_parse_status(tree, tvb, &offset);
    device      = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    /*endpt     =*/ zbee_parse_uint(tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
    in_count    = zbee_parse_uint(tree, hf_zbee_zdp_in_count, tvb, &offset, (int)sizeof(guint8), NULL);
    out_count   = zbee_parse_uint(tree, hf_zbee_zdp_out_count, tvb, &offset, (int)sizeof(guint8), NULL);
    idx         = zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint8), NULL);

    /* Display the input cluster list. */
    for (i=idx; (i<in_count) && tvb_bytes_exist(tvb, offset, sizeof_cluster); i++) {
        zbee_parse_uint(tree, hf_zbee_zdp_in_cluster, tvb, &offset, sizeof_cluster, NULL);
    } /* for */
    for (i-=in_count; (i<out_count) && tvb_bytes_exist(tvb, offset, sizeof_cluster); i++) {
        zbee_parse_uint(tree, hf_zbee_zdp_out_cluster, tvb, &offset, sizeof_cluster, NULL);
    } /* for */

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_ext_simple_desc */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_ext_active_ep
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the extended active
 *      endpoint response. Cluster ID = 0x801e.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_ext_active_ep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8      status;
    guint16     device;
    guint8      ep_count;
    guint8      idx;

    status   = zdp_parse_status(tree, tvb, &offset);
    device   = zbee_parse_uint(tree, hf_zbee_zdp_device, tvb, &offset, (int)sizeof(guint16), NULL);
    ep_count = zbee_parse_uint(tree, hf_zbee_zdp_ep_count, tvb, &offset, (int)sizeof(guint8), NULL);
    idx      = zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint8), NULL);

    if (tree && ep_count) {
        ti = proto_tree_add_text(tree, tvb, offset, ep_count*(int)sizeof(guint8), "Active Endpoint List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_endpoint);
        for (i=idx; (i<ep_count) && tvb_bytes_exist(tvb, offset, (int)sizeof(guint8)); i++) {
            (void)zbee_parse_uint(field_tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
        }
    }

    zbee_append_info(tree, pinfo, ", Device: 0x%04x", device);
    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_ext_active_ep */
