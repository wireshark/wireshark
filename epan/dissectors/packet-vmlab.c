/* packet-vmlab.c
 * Routines for VMware Lab Manager Frame Dis-assembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/* History
 *
 * Apr 4, 2010 - David Aggeler
 *
 * - Initial version based on packet-vlan.c
 *
 *   VMware Lab Manager is using this encapsulation directly as Ethernet Frames
 *   or inside VLANs. The Ethernet type was originally registered to Akimbi, but VMware
 *   acquired this company in 2006. No public information found, so the decoding here
 *   is an educated guess. Since one of the features of Lab Manager is to separate
 *   VMs with equal host name, IP and MAC Address, I expect the upper layer dissectors
 *   (namely ARP, ICMP, IP, TCP) to create false alerts, since identical configurations
 *   may communicate at the same time. The main goal of this dissector is to be able
 *   to troubleshoot connectivity, preferably pings. It's also a little to understand
 *   as to how host spanning fenced configurations actually talk.
 *
 */

#include "config.h"

#include <glib.h>
#include <epan/addr_resolv.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_vmlab = -1;

static int hf_vmlab_flags_part1 = -1;           /* Unknown so far */
static int hf_vmlab_flags_fragment = -1;
static int hf_vmlab_flags_part2 = -1;           /* Unknown so far */

static int hf_vmlab_portgroup = -1;
static int hf_vmlab_eth_src = -1;
static int hf_vmlab_eth_dst = -1;
static int hf_vmlab_eth_addr = -1;
static int hf_vmlab_etype = -1;
static int hf_vmlab_trailer = -1;

static gint ett_vmlab = -1;

static const value_string fragment_vals[] = {
    { 0, "Not set" },
    { 1, "Set" },
    { 0, NULL }
};

static void
dissect_vmlab(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    proto_tree*     volatile vmlab_tree;
    proto_item*     ti;

    guint32         offset=0;

    const guint8*   src_addr;
    const guint8*   dst_addr;
    guint8          attributes;
    guint8          portgroup;

    volatile guint16 encap_proto;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMLAB");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vmlab, tvb, 0, 24, ENC_NA);
    vmlab_tree = proto_item_add_subtree(ti, ett_vmlab);

    /* Flags*/
    attributes = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(vmlab_tree, hf_vmlab_flags_part1,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vmlab_tree, hf_vmlab_flags_fragment, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vmlab_tree, hf_vmlab_flags_part2,    tvb, offset, 1, ENC_BIG_ENDIAN);
    if (attributes & 0x04) {
        proto_item_append_text(ti, ", Fragment");
    }
    offset += 1;

    /* Portgroup*/
    portgroup = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(vmlab_tree, hf_vmlab_portgroup, tvb, offset, 1, portgroup);
    proto_item_append_text(ti, ", Portgroup: %d", portgroup);
    offset += 1;

    /* The next two bytes were always 0x0000 as far as I could tell*/
    offset += 2;

    /* Not really clear, what the difference between this and the next MAC address is
       Both are usually equal*/
    proto_tree_add_item(vmlab_tree, hf_vmlab_eth_addr, tvb, offset, 6, ENC_NA);
    offset += 6;

    dst_addr=tvb_get_ptr(tvb, offset, 6);
    proto_tree_add_item(vmlab_tree, hf_vmlab_eth_dst, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* Source MAC*/
    src_addr=tvb_get_ptr(tvb, offset, 6);
    proto_tree_add_item(vmlab_tree, hf_vmlab_eth_src, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_item_append_text(ti, ", Src: %s (%s), Dst: %s (%s)",
                           get_ether_name(src_addr), ether_to_str(src_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));

    /* Encapsulated Ethertype is also part of the block*/
    encap_proto = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Now call whatever was encapsulated*/
    ethertype(encap_proto, tvb, offset, pinfo, tree, vmlab_tree, hf_vmlab_etype, hf_vmlab_trailer, 0);

}

void
proto_register_vmlab(void)
{
    static hf_register_info hf[] = {

        { &hf_vmlab_flags_part1,    { "Unknown", "vmlab.unknown1",
            FT_UINT8, BASE_HEX,  NULL, 0xF8, NULL, HFILL }},
        { &hf_vmlab_flags_fragment, { "More Fragments", "vmlab.fragment",
            FT_UINT8, BASE_DEC, VALS(fragment_vals), 0x04, NULL, HFILL }},
        { &hf_vmlab_flags_part2,    { "Unknown", "vmlab.unknown2",
            FT_UINT8, BASE_HEX,  NULL, 0x03, NULL, HFILL }},

        { &hf_vmlab_portgroup,      { "Portgroup", "vmlab.pgrp",
            FT_UINT8, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_vmlab_eth_src,        { "Source", "vmlab.src",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vmlab_eth_dst,        { "Destination", "vmlab.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vmlab_eth_addr,       { "Address", "vmlab.addr",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vmlab_etype,          { "Encapsulated Type", "vmlab.subtype",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }},
        { &hf_vmlab_trailer,        { "Trailer", "vmlab.trailer",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };
    static gint *ett[] = {
        &ett_vmlab
    };

    proto_vmlab = proto_register_protocol("VMware Lab Manager", "VMLAB", "vmlab");
    proto_register_field_array(proto_vmlab, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vmlab(void)
{
    dissector_handle_t vmlab_handle;

    vmlab_handle = create_dissector_handle(dissect_vmlab, proto_vmlab);

    dissector_add_uint("ethertype", ETHERTYPE_VMLAB, vmlab_handle);
}
