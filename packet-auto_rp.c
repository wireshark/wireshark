/* packet-auto_rp.c
 * Routines for the Cisco Auto-RP protocol
 * ftp://ftpeng.cisco.com/ftp/ipmulticast/specs/pim-autorp-spec01.txt
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-auto_rp.c,v 1.6 2000/05/31 05:06:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"

static gint proto_auto_rp = -1;
static gint ett_auto_rp = -1;
static gint ett_auto_rp_ver_type = -1;
static gint ett_auto_rp_map = -1;
static gint ett_auto_rp_group = -1;

static gint hf_auto_rp_ver_type = -1;
static gint hf_auto_rp_version = -1;
static gint hf_auto_rp_type = -1;
static gint hf_auto_rp_map = -1;
static gint hf_auto_rp_pim_ver = -1;
static gint hf_auto_rp_group = -1;
static gint hf_auto_rp_mask_sgn = -1;

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

static int do_auto_rp_map(const u_char *pd, int offset, frame_data *fd, proto_tree *auto_rp_tree);

static void dissect_auto_rp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        struct auto_rp_fixed_hdr arh;
        gboolean short_hdr = FALSE;

        if (sizeof(struct auto_rp_fixed_hdr) > END_OF_FRAME)
                short_hdr = TRUE;
        else
                memcpy(&arh, pd + offset, sizeof(struct auto_rp_fixed_hdr));

        if (check_col(fd, COL_PROTOCOL))
                col_add_str(fd, COL_PROTOCOL, "Auto-RP");
        
        if (check_col(fd, COL_INFO)) {
                if (short_hdr)
                        col_add_fstr(fd, COL_INFO, "Short packet header, length %u", END_OF_FRAME);
                else
                        col_add_fstr(fd, COL_INFO, "%s (v%s) for %u RP%s",
                                     val_to_str(lo_nibble(arh.ver_type), auto_rp_type_vals, "Unknown"),
                                     val_to_str(hi_nibble(arh.ver_type), auto_rp_ver_vals, "Unknown"),
                                     arh.rp_count, plurality(arh.rp_count, "", "s"));
        }

        if (tree) {
                proto_item *ti, *tv;
                proto_tree *auto_rp_tree, *ver_type_tree;
                int i;

                if (short_hdr) {
                        dissect_data(pd, offset, fd, tree);
                        return;
                }

                ti = proto_tree_add_item(tree, proto_auto_rp, NullTVB, offset, END_OF_FRAME, FALSE);
                auto_rp_tree = proto_item_add_subtree(ti, ett_auto_rp);

                tv = proto_tree_add_uint_format(auto_rp_tree, hf_auto_rp_ver_type, NullTVB, offset, 1,
                                                arh.ver_type, "Version: %s, Packet type: %s",
                                                val_to_str(hi_nibble(arh.ver_type), auto_rp_ver_vals, "Unknown"),
                                                val_to_str(lo_nibble(arh.ver_type), auto_rp_type_vals, "Unknown"));
                ver_type_tree = proto_item_add_subtree(tv, ett_auto_rp_ver_type);
                proto_tree_add_uint(ver_type_tree, hf_auto_rp_version, NullTVB, offset, 1, arh.ver_type);
                proto_tree_add_uint(ver_type_tree, hf_auto_rp_type, NullTVB, offset, 1, arh.ver_type);
                offset++;

                proto_tree_add_text(auto_rp_tree, NullTVB, offset++, 1, "RP Count: %u", arh.rp_count);
                proto_tree_add_text(auto_rp_tree, NullTVB, offset, 2, "Holdtime: %u second%s",
                                    ntohs(arh.holdtime),
                                    plurality(ntohs(arh.holdtime), "", "s"));
                offset+=2;
                proto_tree_add_text(auto_rp_tree, NullTVB, offset, 4, "Reserved: 0x%x", arh.reserved);
                offset+=4;

                for (i = 0; i < arh.rp_count; i++) {
                        int ret;
                        if (sizeof(struct auto_rp_map_hdr) > END_OF_FRAME)
                                break;
                        ret = do_auto_rp_map(pd, offset, fd, auto_rp_tree);
                        if (ret < 0)
                                break;
                        offset += ret;
                }

                if (END_OF_FRAME > 0)
                        dissect_data(pd, offset, fd, tree);
        }

        return;
}

void proto_register_auto_rp(void)
{
        static hf_register_info hf[] = {
                { &hf_auto_rp_ver_type,
                  {"Auto-RP message version and type", "auto_rp.typever",
                   FT_UINT8, BASE_DEC, NULL, 0x0,
                   "Auto-RP version and type"}},

                { &hf_auto_rp_version,
                  {"Auto-RP protocol version", "auto_rp.version",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_ver_vals), AUTO_RP_VERSION_MASK,
                   "Auto-RP version"}},

                { &hf_auto_rp_type,
                  {"Auto-RP packet type", "auto_rp.type",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_type_vals), AUTO_RP_TYPE_MASK,
                   "Auto-RP type"}},

                { &hf_auto_rp_map,
                  {"Auto-RP address map", "auto_rp.map",
                   FT_UINT8, BASE_DEC, NULL, 0x0,
                   "Auto-RP mapping"}},

                { &hf_auto_rp_pim_ver,
                  {"RP's highest PIM version", "auto_rp.pim_ver",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_pim_ver_vals), AUTO_RP_PIM_VER_MASK,
                   "Auto-RP PIM version"}},

                { &hf_auto_rp_group,
                  {"Group mapping to this RP", "auto_rp.grp",
                   FT_UINT8, BASE_DEC, NULL, 0x0,
                   "RP's group"}},

                { &hf_auto_rp_mask_sgn,
                  {"Group prefix sign", "auto_rp.mask_sgn",
                   FT_UINT8, BASE_DEC, VALS(auto_rp_mask_sign_vals), AUTO_RP_SIGN_MASK,
                   "Prefix sign"}}
        };

        static gint *ett[] = {
                &ett_auto_rp,
                &ett_auto_rp_ver_type,
                &ett_auto_rp_map,
                &ett_auto_rp_group
        };

        proto_auto_rp = proto_register_protocol("Cisco Auto-RP", "auto_rp");
        proto_register_field_array(proto_auto_rp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        return;
}

void
proto_reg_handoff_auto_rp(void)
{
	dissector_add("udp.port", UDP_PORT_PIM_RP_DISC, dissect_auto_rp);
}

/*
 * Handles one Auto-RP map entry. Returns the number of bytes in the map entry or < 0 for error.
 */
static int do_auto_rp_map(const u_char *pd, int offset, frame_data *fd, proto_tree *auto_rp_tree)
{
        struct auto_rp_map_hdr m;
        proto_item *ti;
        proto_tree *map_tree;
        struct auto_rp_enc_grp_hdr g;
        int i;

        if (sizeof(struct auto_rp_map_hdr) > END_OF_FRAME)
                return -1;
        memcpy(&m, pd+offset, sizeof(struct auto_rp_map_hdr));

        ti = proto_tree_add_uint_format(auto_rp_tree, hf_auto_rp_map, NullTVB, offset,
                                        MIN(sizeof(m) + m.group_count*sizeof(g), END_OF_FRAME), 1,
                                        "RP %s: %u group%s", ip_to_str((void *)&m.rp_address),
                                        m.group_count, plurality(m.group_count, "", "s"));
        map_tree = proto_item_add_subtree(ti, ett_auto_rp_map);
        proto_tree_add_text(map_tree, NullTVB, offset, 4, "Unicast IP address of this RP: %s (%s)",
                            ip_to_str((void *)&m.rp_address), get_hostname(m.rp_address));
        offset +=4;
        proto_tree_add_uint(map_tree, hf_auto_rp_pim_ver, NullTVB, offset, 1, pd[offset]);
        offset++;
        proto_tree_add_text(map_tree, NullTVB, offset, 1, "Number of groups this RP maps to: %u", m.group_count);
        offset++;

        for (i = 0; i < m.group_count; i++) {
                proto_item *gi;
                proto_tree *grp_tree;
                if (2*sizeof(guint8) + sizeof(guint32) > END_OF_FRAME) /* struct auto_rp_enc_grp_hdr */
                        return -1;

                gi = proto_tree_add_uint_format(map_tree, hf_auto_rp_group, NullTVB, offset, 6, 1,
                                                "group %s/%u (%s)", ip_to_str(pd + offset + 2),
                                                pd[offset + 1],
                                                val_to_str(pd[offset]&AUTO_RP_SIGN_MASK, auto_rp_mask_sign_vals, ""));
                grp_tree = proto_item_add_subtree(gi, ett_auto_rp_group);

                proto_tree_add_uint(grp_tree, hf_auto_rp_mask_sgn, NullTVB, offset, 1, pd[offset]);
                offset++;
                proto_tree_add_text(grp_tree, NullTVB, offset, 1, "Group mask length: %u", pd[offset]);
                offset++;
                proto_tree_add_text(grp_tree, NullTVB, offset, 4, "Group prefix: %s", ip_to_str(pd + offset));
                offset +=4;
         
        }

        return offset;
}
