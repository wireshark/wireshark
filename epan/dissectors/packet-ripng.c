/* packet-ripng.c
 * Routines for RIPng disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 * derived from packet-rip.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Enhance RIPng by Alexis La Goutte
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
 *
 * References:
 * RFC2080: RIPng for IPv6
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

void proto_register_ripng(void);
void proto_reg_handoff_ripng(void);

static int proto_ripng = -1;
static int hf_ripng_cmd = -1;
static int hf_ripng_version = -1;
static int hf_ripng_reserved = -1;

static int hf_ripng_rte = -1;
static int hf_ripng_rte_ipv6_prefix = -1;
static int hf_ripng_rte_route_tag = -1;
static int hf_ripng_rte_prefix_length = -1;
static int hf_ripng_rte_metric = -1;

static gint ett_ripng = -1;
static gint ett_ripng_rte = -1;

#define UDP_PORT_RIPNG  521

#define RIP6_REQUEST    1
#define RIP6_RESPONSE   2

static const value_string cmdvals[] = {
    { RIP6_REQUEST,  "Request" },
    { RIP6_RESPONSE, "Response" },
    { 0, NULL },
};

static int
dissect_ripng(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    int offset = 0;
    proto_tree *ripng_tree = NULL, *rte_tree = NULL;
    proto_item *ti, *rte_ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RIPng");
    col_add_fstr(pinfo->cinfo, COL_INFO," Command %s, Version %u",
                 val_to_str(tvb_get_guint8(tvb, offset), cmdvals, "Unknown (%u)"),
                 tvb_get_guint8(tvb, offset +1));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ripng, tvb, offset, -1, ENC_NA);
        ripng_tree = proto_item_add_subtree(ti, ett_ripng);

        /* Command */
        proto_tree_add_item(ripng_tree, hf_ripng_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Version */
        proto_tree_add_item(ripng_tree, hf_ripng_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Reserved */
        proto_tree_add_item(ripng_tree, hf_ripng_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;

        /* Route Table Entry */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {

            rte_ti = proto_tree_add_item(ripng_tree, hf_ripng_rte, tvb, offset, 16 + 2 + 1 + 1, ENC_NA);
            rte_tree = proto_item_add_subtree(rte_ti, ett_ripng_rte);

            /* IPv6 Prefix */
            proto_tree_add_item(rte_tree, hf_ripng_rte_ipv6_prefix, tvb, offset, 16, ENC_NA);
            proto_item_append_text(rte_ti, ": IPv6 Prefix: %s", tvb_ip6_to_str(tvb, offset));
            offset += 16;

            /* Route Tag */
            proto_tree_add_item(rte_tree, hf_ripng_rte_route_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Prefix Length */
            proto_tree_add_item(rte_tree, hf_ripng_rte_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(rte_ti, "/%u", tvb_get_guint8(tvb, offset));
            offset += 1;

            /* Metric */
            proto_tree_add_item(rte_tree, hf_ripng_rte_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(rte_ti, " Metric: %u", tvb_get_guint8(tvb, offset));
            offset += 1;
        }
    }
    return tvb_captured_length(tvb);
}

void
proto_register_ripng(void)
{
    static hf_register_info hf[] = {
        { &hf_ripng_cmd,
          { "Command",          "ripng.cmd",
            FT_UINT8, BASE_DEC, VALS(cmdvals), 0x0,
            "Used to specify the purpose of this message", HFILL }},
        { &hf_ripng_version,
          { "Version",          "ripng.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Version of RIPng", HFILL }},
        { &hf_ripng_reserved,
          { "Reserved",         "ripng.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Must be Zero", HFILL }},
        { &hf_ripng_rte,
          { "Route Table Entry",                "ripng.rte",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ripng_rte_ipv6_prefix,
          { "IPv6 Prefix",              "ripng.rte.ipv6_prefix",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "Destination", HFILL }},
        { &hf_ripng_rte_route_tag,
          { "Route Tag",                "ripng.rte.route_tag",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Provides a method of separating internal RIPng routes (routes for networks within the RIPng routing domain) from external RIPng routes, which may have been imported from an EGP or another IGP", HFILL }},

        { &hf_ripng_rte_prefix_length,
          { "Prefix Length",            "ripng.rte.prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The length in bits of the significant part of the prefix starting from the left of the prefix", HFILL }},

        { &hf_ripng_rte_metric,
          { "Metric",           "ripng.rte.metric",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The current metric for the destination; the value 16 (infinity) indicates that the destination is not reachable", HFILL }},
    };

    static gint *ett[] = {
        &ett_ripng,
        &ett_ripng_rte,
    };

    proto_ripng = proto_register_protocol("RIPng", "RIPng", "ripng");
    proto_register_field_array(proto_ripng, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ripng(void)
{
    dissector_handle_t ripng_handle;

    ripng_handle = create_dissector_handle(dissect_ripng, proto_ripng);
    dissector_add_uint("udp.port", UDP_PORT_RIPNG, ripng_handle);
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
