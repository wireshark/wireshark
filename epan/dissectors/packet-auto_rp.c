/* packet-auto_rp.c
 * Routines for the Cisco Auto-RP protocol
 * ftp://ftpeng.cisco.com/ftp/ipmulticast/specs/pim-autorp-spec01.txt
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

static gint proto_auto_rp = -1;
static gint ett_auto_rp = -1;
static gint ett_auto_rp_ver_type = -1;
static gint ett_auto_rp_map = -1;
static gint ett_auto_rp_group = -1;

static gint hf_auto_rp_version = -1;
static gint hf_auto_rp_type = -1;
static gint hf_auto_rp_count = -1;
static gint hf_auto_rp_holdtime = -1;
static gint hf_auto_rp_pim_ver = -1;
static gint hf_auto_rp_rp_addr = -1;
static gint hf_auto_rp_prefix_sgn = -1;
static gint hf_auto_rp_mask_len = -1;
static gint hf_auto_rp_group_prefix = -1;

#define UDP_PORT_PIM_RP_DISC 496

struct auto_rp_fixed_hdr {
#define AUTO_RP_VERSION_MASK 0xf0
#define AUTO_RP_TYPE_MASK    0x0f
        guint8  ver_type;       /* pim-autorp-spec01.txt defines version 1+ */
        guint8  rp_count;       /* Number of struct auto_rp_maps that follow the this header */
        guint16 holdtime;       /* Time in seconds this announcement is valid. 0 equals forever */
        guint32 reserved;
};

struct auto_rp_map_hdr {
        guint32 rp_address;       /* The unicast IPv4 address of this RP */
#define AUTO_RP_PIM_VER_MASK 0x03
        guint8  pim_version;      /* RP's highest PIM version. 2-bit field */
        guint8  group_count;      /* Number of encoded group addresses that follow this header */
};

struct auto_rp_enc_grp_hdr {   /* Encoded group address */
#define AUTO_RP_SIGN_MASK 0x01
        guint8  prefix_sgn;    /* 0 positive, 1 negative group prefix */
        guint8  mask_len;      /* Length of group prefix */
        guint32 addr;          /* Group prefix */
};

#define AUTO_RP_VER_1PLUS 1
static const value_string auto_rp_ver_vals[] = {
        {AUTO_RP_VER_1PLUS, "1 or 1+"},
        {0,                 NULL}
};

#define AUTO_RP_TYPE_ANNOUNCEMENT 1
#define AUTO_RP_TYPE_MAPPING      2
static const value_string auto_rp_type_vals[] = {
        {AUTO_RP_TYPE_ANNOUNCEMENT, "RP announcement"},
        {AUTO_RP_TYPE_MAPPING,      "RP mapping"},
        {0,                         NULL}
};

#define AUTO_RP_PIM_VERSION_UNKNOWN 0x00
#define AUTO_RP_PIM_VERSION_1       0x01
#define AUTO_RP_PIM_VERSION_2       0x02
#define AUTO_RP_PIM_VERSION_DUAL    0x03
static const value_string auto_rp_pim_ver_vals[] = {
        {AUTO_RP_PIM_VERSION_UNKNOWN, "Version unknown"},
        {AUTO_RP_PIM_VERSION_1,       "Version 1"},
        {AUTO_RP_PIM_VERSION_2,       "Version 2"},
        {AUTO_RP_PIM_VERSION_DUAL,    "Dual version 1 and 2"},
        {0,                           NULL}
};

#define AUTO_RP_GROUP_MASK_SIGN_POS 0
#define AUTO_RP_GROUP_MASK_SIGN_NEG 1
static const value_string auto_rp_mask_sign_vals[] = {
        {AUTO_RP_GROUP_MASK_SIGN_POS,  "Positive group prefix"},
        {AUTO_RP_GROUP_MASK_SIGN_NEG,  "Negative group prefix"},
        {0,                            NULL}
};

static int do_auto_rp_map(tvbuff_t *tvb, int offset, proto_tree *auto_rp_tree);

static void dissect_auto_rp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint8 ver_type, rp_count;

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Auto-RP");
        col_clear(pinfo->cinfo, COL_INFO);

        ver_type = tvb_get_guint8(tvb, 0);
        rp_count = tvb_get_guint8(tvb, 1);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (v%s) for %u RP%s",
                     val_to_str_const(lo_nibble(ver_type), auto_rp_type_vals, "Unknown"),
                     val_to_str_const(hi_nibble(ver_type), auto_rp_ver_vals,  "Unknown"),
                     rp_count, plurality(rp_count, "", "s"));

        if (tree) {
                proto_item *ti, *tv;
                proto_tree *auto_rp_tree, *ver_type_tree;
                int         i, offset;
                guint16     holdtime;

                offset = 0;
                ti = proto_tree_add_item(tree, proto_auto_rp, tvb, offset, -1, ENC_NA);
                auto_rp_tree = proto_item_add_subtree(ti, ett_auto_rp);

                tv = proto_tree_add_text(auto_rp_tree, tvb, offset, 1, "Version: %s, Packet type: %s",
                                         val_to_str_const(hi_nibble(ver_type), auto_rp_ver_vals,  "Unknown"),
                                         val_to_str_const(lo_nibble(ver_type), auto_rp_type_vals, "Unknown"));
                ver_type_tree = proto_item_add_subtree(tv, ett_auto_rp_ver_type);
                proto_tree_add_uint(ver_type_tree, hf_auto_rp_version, tvb, offset, 1, ver_type);
                proto_tree_add_uint(ver_type_tree, hf_auto_rp_type, tvb, offset, 1, ver_type);
                offset++;

                proto_tree_add_uint(auto_rp_tree, hf_auto_rp_count, tvb, offset, 1, rp_count);
                offset++;

                holdtime = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint_format_value(auto_rp_tree, hf_auto_rp_holdtime, tvb, offset, 2, holdtime,
                                           "%u second%s", holdtime, plurality(holdtime, "", "s"));
                offset+=2;

                proto_tree_add_text(auto_rp_tree, tvb, offset, 4, "Reserved: 0x%x", tvb_get_ntohs(tvb, offset));
                offset+=4;

                for (i = 0; i < rp_count; i++)
                        offset = do_auto_rp_map(tvb, offset, auto_rp_tree);

                if (tvb_offset_exists(tvb, offset))
                        proto_tree_add_text(tree, tvb, offset, -1, "Trailing junk");
        }

        return;
}

/*
 * Handles one Auto-RP map entry. Returns the new offset.
 */
static int do_auto_rp_map(tvbuff_t *tvb, int offset, proto_tree *auto_rp_tree)
{
        proto_item *ti;
        proto_tree *map_tree;
        guint8      group_count;
        guint32     rp_addr;    /* In network byte order */
        int         i;

        rp_addr = tvb_get_ipv4(tvb, offset);
        group_count = tvb_get_guint8(tvb, offset + 5);

        /* sizeof map header + n * sizeof encoded group addresses */
        ti = proto_tree_add_text(auto_rp_tree, tvb, offset, 6 + group_count * 6,
                                 "RP %s: %u group%s", ip_to_str((void *)&rp_addr),
                                 group_count, plurality(group_count, "", "s"));
        map_tree = proto_item_add_subtree(ti, ett_auto_rp_map);

        proto_tree_add_ipv4(map_tree, hf_auto_rp_rp_addr, tvb, offset, 4, rp_addr);
        offset += 4;
        proto_tree_add_uint(map_tree, hf_auto_rp_pim_ver, tvb, offset, 1, tvb_get_guint8(tvb, offset));
        offset++;
        proto_tree_add_text(map_tree, tvb, offset, 1, "Number of groups this RP maps to: %u", group_count);
        offset++;

        for (i = 0; i < group_count; i++) {
                proto_item *gi;
                proto_tree *grp_tree;
                guint8      sign, mask_len;
                guint32     group_addr; /* In network byte order */

                sign = tvb_get_guint8(tvb, offset);
                mask_len = tvb_get_guint8(tvb, offset + 1);
                group_addr = tvb_get_ipv4(tvb, offset + 2);
                gi = proto_tree_add_text(map_tree, tvb, offset, 6, "Group %s/%u (%s)",
                                         ip_to_str((void *)&group_addr), mask_len,
                                         val_to_str_const(sign&AUTO_RP_SIGN_MASK, auto_rp_mask_sign_vals, ""));
                grp_tree = proto_item_add_subtree(gi, ett_auto_rp_group);

                proto_tree_add_uint(grp_tree, hf_auto_rp_prefix_sgn, tvb, offset, 1, sign);
                offset++;
                proto_tree_add_uint(grp_tree, hf_auto_rp_mask_len, tvb, offset, 1, mask_len);
                offset++;
                proto_tree_add_ipv4(grp_tree, hf_auto_rp_group_prefix, tvb, offset, 4, group_addr);
                offset += 4;

        }

        return offset;
}

void proto_register_auto_rp(void)
{
        static hf_register_info hf[] = {
                { &hf_auto_rp_version,
                  {"Protocol version", "auto_rp.version",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_ver_vals), AUTO_RP_VERSION_MASK,
                   "Auto-RP protocol version", HFILL }},

                { &hf_auto_rp_type,
                  {"Packet type", "auto_rp.type",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_type_vals), AUTO_RP_TYPE_MASK,
                   "Auto-RP packet type", HFILL }},

                { &hf_auto_rp_count,
                  {"RP count", "auto_rp.rp_count",
                   FT_UINT8, BASE_DEC, NULL, 0,
                   "The number of RP addresses contained in this message", HFILL }},

                { &hf_auto_rp_holdtime,
                  {"Holdtime", "auto_rp.holdtime",
                   FT_UINT16, BASE_DEC, NULL, 0,
                   "The amount of time in seconds this announcement is valid", HFILL }},

                { &hf_auto_rp_pim_ver,
                  {"Version", "auto_rp.pim_ver",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_pim_ver_vals), AUTO_RP_PIM_VER_MASK,
                   "RP's highest PIM version", HFILL }},

                { &hf_auto_rp_rp_addr,
                  {"RP address", "auto_rp.rp_addr",
                   FT_IPv4, BASE_NONE, NULL, 0,
                   "The unicast IP address of the RP", HFILL }},

                { &hf_auto_rp_prefix_sgn,
                  {"Sign", "auto_rp.prefix_sign",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_mask_sign_vals), AUTO_RP_SIGN_MASK,
                   "Group prefix sign", HFILL }},

                { &hf_auto_rp_mask_len,
                  {"Mask length", "auto_rp.mask_len",
                   FT_UINT8, BASE_DEC, NULL, 0x0,
                   "Length of group prefix", HFILL }},

                { &hf_auto_rp_group_prefix,
                  {"Prefix", "auto_rp.group_prefix",
                   FT_IPv4, BASE_NONE, NULL, 0,
                   "Group prefix", HFILL }}
        };

        static gint *ett[] = {
                &ett_auto_rp,
                &ett_auto_rp_ver_type,
                &ett_auto_rp_map,
                &ett_auto_rp_group
        };

        proto_auto_rp = proto_register_protocol("Cisco Auto-RP",
                                                "Auto-RP", "auto_rp");
        proto_register_field_array(proto_auto_rp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        return;
}

void
proto_reg_handoff_auto_rp(void)
{
        dissector_handle_t auto_rp_handle;

        auto_rp_handle = create_dissector_handle(dissect_auto_rp,
                                                 proto_auto_rp);
        dissector_add_uint("udp.port", UDP_PORT_PIM_RP_DISC, auto_rp_handle);
}
