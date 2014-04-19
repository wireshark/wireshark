/* packet-zbee-zdp-binding.c
 * Dissector helper routines for the binding services of the ZigBee Device Profile
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
 *      zdp_parse_bind_table_entry
 *  DESCRIPTION
 *      Parses and displays a single binding table entry.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zdp_parse_bind_table_entry(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 version)
{
    proto_item      *ti = NULL;
    guint           len = 0;

    guint64 src64;
    guint8  src_ep;
    guint16 cluster;
    guint8  mode;
    guint64 dst64;
    guint16 dst;
    guint8  dst_ep;

    /* Add the source address. */
    src64 = tvb_get_letoh64(tvb, *offset + len);
    if (tree) ti = proto_tree_add_text(tree, tvb, *offset, 0, "Bind {Src: %s", ep_eui64_to_display(src64));
    len += (int)sizeof(guint64);

    /* Add the source endpoint. */
    src_ep = tvb_get_guint8(tvb, *offset + len);
    if (tree) proto_item_append_text(ti, ", Src Endpoint: %d", src_ep);
    len += (int)sizeof(guint8);

    /* Add the cluster ID. */
    if (version >= ZBEE_VERSION_2007) {
        cluster = tvb_get_letohs(tvb, *offset + len);
        len += (int)sizeof(guint16);
    }
    else {
        cluster = tvb_get_guint8(tvb, *offset + len);
        len += (int)sizeof(guint8);
    }
    if (tree) proto_item_append_text(ti, ", Cluster: %d", cluster);

    /* Get the destination address mode. */
    if (version >= ZBEE_VERSION_2007) {
        mode = tvb_get_guint8(tvb, *offset + len);
        len += (int)sizeof(guint8);
    }
    else {
        /* Mode field doesn't exist and always uses unicast in 2003 & earlier. */
        mode = ZBEE_ZDP_ADDR_MODE_UNICAST;
    }

    /* Add the destination address. */
    if (mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        dst = tvb_get_letohs(tvb, *offset + len);
        if (tree) proto_item_append_text(ti, ", Dst: 0x%04x}", dst);
        len += (int)sizeof(guint16);
    }
    else if (mode == ZBEE_ZDP_ADDR_MODE_UNICAST) {
        dst64 = tvb_get_letoh64(tvb, *offset + len);
        if (tree) proto_item_append_text(ti, ", Dst: %s", ep_eui64_to_display(dst64));
        len += (int)sizeof(guint64);

        dst_ep = tvb_get_guint8(tvb, *offset + len);
        if (tree) proto_item_append_text(ti, ", Dst Endpoint: %d}", dst_ep);
        len += (int)sizeof(guint8);
    }
    else {
        if (tree) proto_item_append_text(ti, "}");
    }

    if (tree) {
        proto_item_set_len(ti, len);
    }
    *offset += len;
} /* zdp_parse_bind_table_entry */

/**************************************
 * BINDING REQUESTS
 **************************************
 */
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_end_device_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the end device bind
 *      request. Cluster ID = 0x0020.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_end_device_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint           sizeof_cluster = (version >= ZBEE_VERSION_2007)?(int)sizeof(guint16):(int)sizeof(guint8);
    guint           i;
    proto_item      *ti;
    proto_tree      *field_tree = NULL;

    guint   offset = 0;
    guint16 target;
    guint64 ext_addr = 0;
    /*guint8  src_ep;*/
    /*guint16 profile;*/
    guint8  in_count;
    guint8  out_count;

    target   = zbee_parse_uint(tree, hf_zbee_zdp_target, tvb, &offset, (guint)sizeof(guint16), NULL);
    if (version >= ZBEE_VERSION_2007) {
        /* Extended address present on ZigBee 2006 & later. */
        ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (guint)sizeof(guint64), NULL);
    }
    /*src_ep   =*/ zbee_parse_uint(tree, hf_zbee_zdp_endpoint, tvb, &offset, (guint)sizeof(guint8), NULL);
    /*profile  =*/ zbee_parse_uint(tree, hf_zbee_zdp_profile, tvb, &offset, (guint)sizeof(guint16), NULL);

    in_count = zbee_parse_uint(tree, hf_zbee_zdp_in_count, tvb, &offset, (guint)sizeof(guint8), NULL);
    if ((tree) && (in_count)){
        ti = proto_tree_add_text(tree, tvb, offset, (int)(in_count*sizeof_cluster), "Input Cluster List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind_end_in);
    }
    for (i=0; i<in_count; i++) zbee_parse_uint(field_tree, hf_zbee_zdp_in_cluster, tvb, &offset, (guint)sizeof_cluster, NULL);

    out_count = zbee_parse_uint(tree, hf_zbee_zdp_out_count, tvb, &offset, (guint)sizeof(guint8), NULL);
    if ((tree) && (out_count)) {
        ti = proto_tree_add_text(tree, tvb, offset, (int)(out_count*sizeof_cluster), "Output Cluster List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind_end_out);
    }
    for (i=0; i<out_count; i++) zbee_parse_uint(field_tree, hf_zbee_zdp_out_cluster, tvb, &offset, sizeof_cluster, NULL);

    if (version >= ZBEE_VERSION_2007) {
        zbee_append_info(tree, pinfo, " Src: %s", ep_eui64_to_display(ext_addr));
    }
    zbee_append_info(tree, pinfo, ", Target: 0x%04x", target);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_end_device_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the bind request.
 *      Cluster ID = 0x0021.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item      *ti;

    guint   offset = 0;
    guint64 src64;
    /*guint8  src_ep;*/
    /*guint16 cluster;*/
    guint8  dst_mode;
    guint16 dst = 0;
    guint64 dst64 = 0;
    /*guint8  dst_ep;*/

    src64    = zbee_parse_eui64(tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);
    /*src_ep   =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_src_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    /*cluster  =*/ zbee_parse_uint(tree, hf_zbee_zdp_cluster, tvb, &offset, ZBEE_HAS_2006(version)?(int)sizeof(guint16):(int)sizeof(guint8), NULL);
    if (version >= ZBEE_VERSION_2007) {
        dst_mode = zbee_parse_uint(tree, hf_zbee_zdp_addr_mode, tvb, &offset, (int)sizeof(guint8), &ti);
        if (tree) {
            if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP)        proto_item_append_text(ti, " (Group)");
            else if (dst_mode == ZBEE_ZDP_ADDR_MODE_UNICAST) proto_item_append_text(ti, " (Unicast)");
            else                                             proto_item_append_text(ti, " (Reserved)");
        }
    }
    else {
        /* ZigBee 2003 & earlier does not have a address mode, and is unicast only. */
        dst_mode = ZBEE_ZDP_ADDR_MODE_UNICAST;
    }

    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        dst = zbee_parse_uint(tree, hf_zbee_zdp_bind_dst, tvb, &offset, (int)sizeof(guint16), NULL);
    }
    else if (dst_mode == ZBEE_ZDP_ADDR_MODE_UNICAST) {
        dst64   = zbee_parse_eui64(tree, hf_zbee_zdp_bind_dst64, tvb, &offset, (int)sizeof(guint64), NULL);
        /*dst_ep  =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_dst_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    }

    if (version >= ZBEE_VERSION_2007) {
        zbee_append_info(tree, pinfo, " Src: %s", ep_eui64_to_display(src64));
    }
    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        zbee_append_info(tree, pinfo, ", Dst: 0x%04x", dst);
    }
    else {
        zbee_append_info(tree, pinfo, ", Dst: %s", eui64_to_str(dst64));
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_unbind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the unbind request.
 *      Cluster ID = 0x0022.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_unbind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item      *ti;

    guint   offset = 0;
    guint64 src64;
    /*guint8  src_ep;*/
    /*guint16 cluster;*/
    guint8  dst_mode;
    guint16 dst = 0;
    guint64 dst64 = 0;
    /*guint8  dst_ep;*/

    src64    = zbee_parse_eui64(tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);
    /*src_ep   =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_src_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    /*cluster  =*/ zbee_parse_uint(tree, hf_zbee_zdp_cluster, tvb, &offset, (version >= ZBEE_VERSION_2007)?(int)sizeof(guint16):(int)sizeof(guint8), NULL);
    if (version >= ZBEE_VERSION_2007) {
        dst_mode = zbee_parse_uint(tree, hf_zbee_zdp_addr_mode, tvb, &offset, (int)sizeof(guint8), &ti);
        if (tree) {
            if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP)        proto_item_append_text(ti, " (Group)");
            else if (dst_mode == ZBEE_ZDP_ADDR_MODE_UNICAST) proto_item_append_text(ti, " (Unicast)");
            else                                             proto_item_append_text(ti, " (Reserved)");
        }
    }
    else {
        /* ZigBee 2003 & earlier does not have a address mode, and is unicast only. */
        dst_mode = ZBEE_ZDP_ADDR_MODE_UNICAST;
    }

    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        dst = zbee_parse_uint(tree, hf_zbee_zdp_bind_dst, tvb, &offset, (int)sizeof(guint16), NULL);
    }
    else if (dst_mode == ZBEE_ZDP_ADDR_MODE_UNICAST) {
        dst64   = zbee_parse_eui64(tree, hf_zbee_zdp_bind_dst64, tvb, &offset, (int)sizeof(guint64), NULL);
        /*dst_ep  =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_dst_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    }

    if (version >= ZBEE_VERSION_2007) {
        zbee_append_info(tree, pinfo, " Src: %s", ep_eui64_to_display(src64));
    }
    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        zbee_append_info(tree, pinfo, ", Dst: 0x%04x", dst);
    }
    else {
        zbee_append_info(tree, pinfo, ", Dst: %s", eui64_to_str(dst64));
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_unbind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_bind_register
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the bind register
 *      request. Cluster ID = 0x0023.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_bind_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset   = 0;
    guint64 ext_addr;

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_bind_register */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_replace_device
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the replace device
 *      request. Cluster ID = 0x0024.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_replace_device(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint64 ext_addr;
    /*guint8  endpoint;*/
    guint64 new_addr;
    /*guint8  new_ep;*/

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);
    /*endpoint =*/ zbee_parse_uint(tree, hf_zbee_zdp_endpoint, tvb, &offset, (int)sizeof(guint8), NULL);
    new_addr = zbee_parse_eui64(tree, hf_zbee_zdp_replacement, tvb, &offset, (int)sizeof(guint64), NULL);
    /*new_ep   =*/ zbee_parse_uint(tree, hf_zbee_zdp_replacement_ep, tvb, &offset, (int)sizeof(guint8), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", ep_eui64_to_display(ext_addr));
    zbee_append_info(tree, pinfo, ", Replacement: %s", ep_eui64_to_display(new_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_replace_device */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_store_bak_bind_entry
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store backup binding
 *      entry request. Cluster ID = 0x0025.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_store_bak_bind_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item      *ti;

    guint   offset = 0;
    guint64 src64;
    guint8  src_ep;
    guint16 cluster;
    guint8  dst_mode;

    src64    = zbee_parse_eui64(tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);
    src_ep   = zbee_parse_uint(tree, hf_zbee_zdp_bind_src_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    cluster  = zbee_parse_uint(tree, hf_zbee_zdp_cluster, tvb, &offset, (version >= ZBEE_VERSION_2007)?(int)sizeof(guint16):(int)sizeof(guint8), NULL);
    dst_mode = zbee_parse_uint(tree, hf_zbee_zdp_addr_mode, tvb, &offset, (int)sizeof(guint8), &ti);

    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        /*guint16 dst;*/
        if (tree) proto_item_append_text(ti, " (Group)");
        /*dst =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_dst, tvb, &offset, (int)sizeof(guint16), NULL);
    }
    else if (dst_mode == ZBEE_ZDP_ADDR_MODE_UNICAST) {
        /*guint64 dst64;*/
        /*guint8  dst_ep;*/
        if (tree) proto_item_append_text(ti, " (Unicast)");
        /*dst64   =*/ zbee_parse_eui64(tree, hf_zbee_zdp_bind_dst64, tvb, &offset, (int)sizeof(guint64), NULL);
        /*dst_ep  =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_dst_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    }
    else if (tree) proto_item_append_text(ti, " (Reserved)");

    zbee_append_info(tree, pinfo, ", Src: %s", ep_eui64_to_display(src64));
    zbee_append_info(tree, pinfo, ", Src Endpoint: %d", src_ep);
    zbee_append_info(tree, pinfo, ", Cluster: %d", cluster);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_bak_bind_entry */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_remove_bak_bind_entry
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the remove backup binding
 *      entry request. Cluster ID = 0x0026.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_remove_bak_bind_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item      *ti;

    guint   offset = 0;
    guint64 src64;
    guint8  src_ep;
    guint16 cluster;
    guint8  dst_mode;

    src64    = zbee_parse_eui64(tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);
    src_ep   = zbee_parse_uint(tree, hf_zbee_zdp_bind_src_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    cluster  = zbee_parse_uint(tree, hf_zbee_zdp_cluster, tvb, &offset, (version >= ZBEE_VERSION_2007)?(int)sizeof(guint16):(int)sizeof(guint8), NULL);
    dst_mode = zbee_parse_uint(tree, hf_zbee_zdp_addr_mode, tvb, &offset, (int)sizeof(guint8), &ti);

    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        /*guint16 dst;*/
        if (tree) proto_item_append_text(ti, " (Group)");
        /*dst =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_dst, tvb, &offset, (int)sizeof(guint16), NULL);
    }
    else if (dst_mode == ZBEE_ZDP_ADDR_MODE_UNICAST) {
        /*guint64 dst64;*/
        /*guint8  dst_ep;*/
        if (tree) proto_item_append_text(ti, " (Unicast)");
        /*dst64   =*/ zbee_parse_eui64(tree, hf_zbee_zdp_bind_dst64, tvb, &offset, (int)sizeof(guint64), NULL);
        /*dst_ep  =*/ zbee_parse_uint(tree, hf_zbee_zdp_bind_dst_ep, tvb, &offset, (int)sizeof(guint8), NULL);
    }
    else if (tree) proto_item_append_text(ti, " (Reserved)");

    zbee_append_info(tree, pinfo, ", Src: %s", ep_eui64_to_display(src64));
    zbee_append_info(tree, pinfo, ", Src Endpoint: %d", src_ep);
    zbee_append_info(tree, pinfo, ", Cluster: %d", cluster);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_remove_bak_bind_entry */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_backup_bind_table
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the backup binding
 *      table request. Cluster ID = 0x0027.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_backup_bind_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item      *ti;
    proto_tree      *field_tree = NULL;
    guint           i;

    guint   offset = 0;
    /*guint16 table_size;*/
    /*guint16 idx;*/
    guint16 table_count;

    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Binding Table");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind);
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_backup_bind_table */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_recover_bind_table
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the recover binding
 *      table request. Cluster ID = 0x0028.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_recover_bind_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 idx;*/

    /*idx  =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_recover_bind_table */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_backup_source_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the backup source binding
 *      request. Cluster ID = 0x0029.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_backup_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       i;

    guint   offset = 0;
    /*guint16 entries;*/
    /*guint16 idx;*/
    guint16 count;

    /*entries =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx     =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);
    count   = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, count*(int)sizeof(guint64), "Source Table");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind_source);
    }
    for (i=0; i<count; i++) zbee_parse_eui64(field_tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_backup_source_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_req_recover_source_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the recover source
 *      binding request. Cluster ID = 0x002a.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_req_recover_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    /*guint16 idx;*/

    /*idx  =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_recover_source_bind */

/**************************************
 * BINDING RESPONSES
 **************************************
 */
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_end_device_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the end device bind
 *      response. Cluster ID = 0x8020.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_end_device_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_end_device_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the bind response.
 *      Cluster ID = 0x8021.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_unbind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the unbind response.
 *      Cluster ID = 0x8022.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_unbind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_unbind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_bind_register
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the bind registration
 *      response. Cluster ID = 0x8023.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_bind_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint   offset = 0;
    guint   i;

    guint8  status;
    /*guint16 table_size;*/
    guint16 table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

    if (tree && table_count) {
        ti = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Binding List");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind);
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_bind_register */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_replace_device
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the device replacement
 *      response. Cluster ID = 0x8024.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_replace_device(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_replace_device */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_store_bak_bind_entry
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the store backup binding
 *      table entry response. Cluster ID = 0x8025.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_store_bak_bind_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_store_bak_bind_entry */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_remove_bak_bind_entry
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the remove backup binding
 *      table entry response. Cluster ID = 0x8026.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_remove_bak_bind_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_remove_bak_bind_entry */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_backup_bind_table
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the backup binding
 *      table response. Cluster ID = 0x8027.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_backup_bind_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;
    /*guint16 count;*/

    status = zdp_parse_status(tree, tvb, &offset);
    /*count  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_backup_bind_table */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_recover_bind_table
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the recover binding
 *      table response. Cluster ID = 0x8028.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_recover_bind_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint16 table_size;*/
    /*guint16 idx;*/
    guint16 table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

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
} /* dissect_zbee_zdp_rsp_recover_bind_table */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_backup_source_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the backup source binding
 *      response. Cluster ID = 0x8029.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_backup_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset = 0;
    guint8  status;

    status = zdp_parse_status(tree, tvb, &offset);

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_backup_source_bind */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zdp_rsp_recover_source_bind
 *  DESCRIPTION
 *      ZigBee Device Profile dissector for the recover source binding
 *      response. Cluster ID = 0x8029.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
dissect_zbee_zdp_rsp_recover_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *field_tree = NULL;
    guint       offset = 0;
    guint       i;

    guint8  status;
    /*guint16 table_size;*/
    /*guint16 idx;*/
    guint16 table_count;

    status      = zdp_parse_status(tree, tvb, &offset);
    /*table_size  = */ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx         = */ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

    if (tree && table_count) {
        ti = proto_tree_add_text(tree, tvb, offset, table_count * (int)sizeof(guint64), "Source Table");
        field_tree = proto_item_add_subtree(ti, ett_zbee_zdp_bind_source);
    }
    for (i=0; i<table_count; i++) {
        (void)zbee_parse_eui64(field_tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_recover_source_bind */
