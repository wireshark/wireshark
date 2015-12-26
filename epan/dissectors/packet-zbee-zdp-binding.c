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

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-zbee.h"
#include "packet-zbee-zdp.h"


/**************************************
 * HELPER FUNCTIONS
 **************************************
 */
/**
 *Parses and displays a single binding table entry.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
zdp_parse_bind_table_entry(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 version)
{
    proto_tree      *bind_tree;
    proto_item      *ti;
    guint           len = 0;

    guint8  mode;

    /* Add the source address. */
    bind_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zdp_bind_entry, &ti, "Bind");
    proto_tree_add_item(bind_tree, hf_zbee_zdp_bind_src64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    len += 8;

    /* Add the source endpoint. */
    proto_tree_add_item(bind_tree, hf_zbee_zdp_bind_src_ep, tvb, *offset + len, 1, ENC_LITTLE_ENDIAN);
    len += 1;

    /* Add the cluster ID. */
    if (version >= ZBEE_VERSION_2007) {
        proto_tree_add_item(bind_tree, hf_zbee_zdp_cluster, tvb, *offset + len, 2, ENC_LITTLE_ENDIAN);
        len += 2;
    }
    else {
        proto_tree_add_item(bind_tree, hf_zbee_zdp_cluster, tvb, *offset + len, 1, ENC_LITTLE_ENDIAN);
        len += 1;
    }

    /* Get the destination address mode. */
    if (version >= ZBEE_VERSION_2007) {
        mode = tvb_get_guint8(tvb, *offset + len);
        len += 1;
    }
    else {
        /* Mode field doesn't exist and always uses unicast in 2003 & earlier. */
        mode = ZBEE_ZDP_ADDR_MODE_UNICAST;
    }

    /* Add the destination address. */
    if (mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        proto_tree_add_item(bind_tree, hf_zbee_zdp_bind_dst, tvb, *offset + len, 2, ENC_LITTLE_ENDIAN);
        len += 2;
    }
    else if (mode == ZBEE_ZDP_ADDR_MODE_UNICAST) {
        proto_tree_add_item(bind_tree, hf_zbee_zdp_bind_dst64, tvb, *offset + len, 8, ENC_LITTLE_ENDIAN);
        len += 8;
        proto_tree_add_item(bind_tree, hf_zbee_zdp_bind_dst_ep, tvb, *offset + len, 1, ENC_LITTLE_ENDIAN);
        len += 1;
    }

    proto_item_set_len(ti, len);
    *offset += len;
} /* zdp_parse_bind_table_entry */

/**************************************
 * BINDING REQUESTS
 **************************************
 */
/**
 *ZigBee Device Profile dissector for the end device bind
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_end_device_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    guint           sizeof_cluster = (version >= ZBEE_VERSION_2007)?(int)sizeof(guint16):(int)sizeof(guint8);
    guint           i;
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
        field_tree = proto_tree_add_subtree(tree, tvb, offset, (int)(in_count*sizeof_cluster),
                ett_zbee_zdp_bind_end_in, NULL, "Input Cluster List");
    }
    for (i=0; i<in_count; i++) zbee_parse_uint(field_tree, hf_zbee_zdp_in_cluster, tvb, &offset, (guint)sizeof_cluster, NULL);

    out_count = zbee_parse_uint(tree, hf_zbee_zdp_out_count, tvb, &offset, (guint)sizeof(guint8), NULL);
    if ((tree) && (out_count)) {
        field_tree = proto_tree_add_subtree(tree, tvb, offset, (int)(out_count*sizeof_cluster),
                                ett_zbee_zdp_bind_end_out, NULL, "Output Cluster List");
    }
    for (i=0; i<out_count; i++) zbee_parse_uint(field_tree, hf_zbee_zdp_out_cluster, tvb, &offset, sizeof_cluster, NULL);

    if (version >= ZBEE_VERSION_2007) {
        zbee_append_info(tree, pinfo, " Src: %s", eui64_to_display(wmem_packet_scope(), ext_addr));
    }
    zbee_append_info(tree, pinfo, ", Target: 0x%04x", target);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_end_device_bind */

/**
 *ZigBee Device Profile dissector for the bind request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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
        zbee_append_info(tree, pinfo, " Src: %s", eui64_to_display(wmem_packet_scope(), src64));
    }
    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        zbee_append_info(tree, pinfo, ", Dst: 0x%04x", dst);
    }
    else {
        zbee_append_info(tree, pinfo, ", Dst: %s", eui64_to_display(wmem_packet_scope(), dst64));
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_bind */

/**
 *ZigBee Device Profile dissector for the unbind request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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
        zbee_append_info(tree, pinfo, " Src: %s", eui64_to_display(wmem_packet_scope(), src64));
    }
    if (dst_mode == ZBEE_ZDP_ADDR_MODE_GROUP) {
        zbee_append_info(tree, pinfo, ", Dst: 0x%04x", dst);
    }
    else {
        zbee_append_info(tree, pinfo, ", Dst: %s", eui64_to_display(wmem_packet_scope(), dst64));
    }

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_unbind */

/**
 *ZigBee Device Profile dissector for the bind register
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_bind_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint   offset   = 0;
    guint64 ext_addr;

    ext_addr = zbee_parse_eui64(tree, hf_zbee_zdp_ext_addr, tvb, &offset, (int)sizeof(guint64), NULL);

    zbee_append_info(tree, pinfo, ", Device: %s", eui64_to_display(wmem_packet_scope(), ext_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_bind_register */

/**
 *ZigBee Device Profile dissector for the replace device
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

    zbee_append_info(tree, pinfo, ", Device: %s", eui64_to_display(wmem_packet_scope(), ext_addr));
    zbee_append_info(tree, pinfo, ", Replacement: %s", eui64_to_display(wmem_packet_scope(), new_addr));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_replace_device */

/**
 *ZigBee Device Profile dissector for the store backup binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

    zbee_append_info(tree, pinfo, ", Src: %s", eui64_to_display(wmem_packet_scope(), src64));
    zbee_append_info(tree, pinfo, ", Src Endpoint: %d", src_ep);
    zbee_append_info(tree, pinfo, ", Cluster: %d", cluster);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_store_bak_bind_entry */

/**
 *ZigBee Device Profile dissector for the remove backup binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

    zbee_append_info(tree, pinfo, ", Src: %s", eui64_to_display(wmem_packet_scope(), src64));
    zbee_append_info(tree, pinfo, ", Src Endpoint: %d", src_ep);
    zbee_append_info(tree, pinfo, ", Cluster: %d", cluster);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_remove_bak_bind_entry */

/**
 *ZigBee Device Profile dissector for the backup binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_backup_bind_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
    proto_tree      *field_tree;
    guint           i;

    guint   offset = 0;
    /*guint16 table_size;*/
    /*guint16 idx;*/
    guint16 table_count;

    /*table_size  =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx         =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);
    table_count = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

    field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_zdp_bind, NULL, "Binding Table");

    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_backup_bind_table */

/**
 *ZigBee Device Profile dissector for the recover binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the backup source binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_req_backup_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *field_tree;
    guint       i;

    guint   offset = 0;
    /*guint16 entries;*/
    /*guint16 idx;*/
    guint16 count;

    /*entries =*/ zbee_parse_uint(tree, hf_zbee_zdp_table_size, tvb, &offset, (int)sizeof(guint16), NULL);
    /*idx     =*/ zbee_parse_uint(tree, hf_zbee_zdp_index, tvb, &offset, (int)sizeof(guint16), NULL);
    count   = zbee_parse_uint(tree, hf_zbee_zdp_table_count, tvb, &offset, (int)sizeof(guint16), NULL);

    field_tree = proto_tree_add_subtree(tree, tvb, offset, count*(int)sizeof(guint64),
                    ett_zbee_zdp_bind_source, NULL, "Source Table");

    for (i=0; i<count; i++) zbee_parse_eui64(field_tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_req_backup_source_bind */

/**
 *ZigBee Device Profile dissector for the recover source
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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
/**
 *ZigBee Device Profile dissector for the end device bind
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the bind response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the unbind response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the bind registration
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_bind_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
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
        field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_zdp_bind, NULL, "Binding List");
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_bind_register */

/**
 *ZigBee Device Profile dissector for the device replacement
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the store backup binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the remove backup binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the backup binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the recover binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_recover_bind_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version)
{
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
        field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_zdp_bind, NULL, "Binding Table");
    }
    for (i=0; i<table_count; i++) {
        zdp_parse_bind_table_entry(field_tree, tvb, &offset, version);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_recover_bind_table */

/**
 *ZigBee Device Profile dissector for the backup source binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
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

/**
 *ZigBee Device Profile dissector for the recover source binding
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
void
dissect_zbee_zdp_rsp_recover_source_bind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
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
        field_tree = proto_tree_add_subtree(tree, tvb, offset, table_count * (int)sizeof(guint64),
                        ett_zbee_zdp_bind_source, NULL, "Source Table");
    }
    for (i=0; i<table_count; i++) {
        (void)zbee_parse_eui64(field_tree, hf_zbee_zdp_bind_src64, tvb, &offset, (int)sizeof(guint64), NULL);
    } /* for */

    zbee_append_info(tree, pinfo, ", Status: %s", zdp_status_name(status));

    /* Dump any leftover bytes. */
    zdp_dump_excess(tvb, offset, pinfo, tree);
} /* dissect_zbee_zdp_rsp_recover_source_bind */

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
