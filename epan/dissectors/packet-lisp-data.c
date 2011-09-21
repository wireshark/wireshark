/* packet-lisp-data.c
 * Routines for LISP Data Message dissection
 * Copyright 2010, Lorand Jakab <lj@lispmon.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

/* See draft-ietf-lisp-07 "Locator/ID Separation Protocol (LISP)" */

/*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |N|L|E|V|I|flags|            Nonce/Map-Version                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Instance ID/Locator Status Bits               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define LISP_DATA_PORT          4341
#define LISP_DATA_HEADER_LEN    8       /* Number of bytes in LISP data header */

#define LISP_DATA_FLAGS_WIDTH   8       /* Width (in bits) of the flags field */
#define LISP_DATA_FLAG_N        0x80    /* Nonce present */
#define LISP_DATA_FLAG_L        0x40    /* Locator-Status-Bits field enabled */
#define LISP_DATA_FLAG_E        0x20    /* Echo-Nonce-Request */
#define LISP_DATA_FLAG_V        0x10    /* Map-Version present */
#define LISP_DATA_FLAG_I        0x08    /* Instance ID present */
#define LISP_DATA_FLAG_RES      0x07    /* Reserved */

/* Initialize the protocol and registered fields */
static int proto_lisp_data = -1;
static int hf_lisp_data_flags = -1;
static int hf_lisp_data_flags_nonce = -1;
static int hf_lisp_data_flags_lsb = -1;
static int hf_lisp_data_flags_enr = -1;
static int hf_lisp_data_flags_mv = -1;
static int hf_lisp_data_flags_iid = -1;
static int hf_lisp_data_flags_res = -1;
static int hf_lisp_data_nonce = -1;
static int hf_lisp_data_mapver = -1;
static int hf_lisp_data_srcmapver = -1;
static int hf_lisp_data_dstmapver = -1;
static int hf_lisp_data_iid = -1;
static int hf_lisp_data_lsb = -1;
static int hf_lisp_data_lsb8 = -1;

/* Initialize the subtree pointers */
static gint ett_lisp_data = -1;
static gint ett_lisp_data_flags = -1;
static gint ett_lisp_data_mapver = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;

/* Code to actually dissect the packets */
static int
dissect_lisp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    guint8 flags;
    guint8 ip_ver;
    tvbuff_t *next_tvb;
    proto_item *ti;
    proto_item *tif;
    proto_tree *lisp_data_tree;
    proto_tree *lisp_data_flags_tree;

    /* Check that there's enough data */
    if (tvb_length(tvb) < LISP_DATA_HEADER_LEN)
        return 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LISP");

    col_set_str(pinfo->cinfo, COL_INFO, "LISP Encapsulation Header");

    if (tree) {

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_lisp_data, tvb, 0,
                LISP_DATA_HEADER_LEN, FALSE);

        lisp_data_tree = proto_item_add_subtree(ti, ett_lisp_data);

        tif = proto_tree_add_item(lisp_data_tree,
                hf_lisp_data_flags, tvb, offset, 1, FALSE);

        lisp_data_flags_tree = proto_item_add_subtree(tif, ett_lisp_data_flags);

        proto_tree_add_item(lisp_data_flags_tree,
                hf_lisp_data_flags_nonce, tvb, offset, 1, FALSE);
        proto_tree_add_item(lisp_data_flags_tree,
                hf_lisp_data_flags_lsb, tvb, offset, 1, FALSE);
        proto_tree_add_item(lisp_data_flags_tree,
                hf_lisp_data_flags_enr, tvb, offset, 1, FALSE);
        proto_tree_add_item(lisp_data_flags_tree,
                hf_lisp_data_flags_mv, tvb, offset, 1, FALSE);
        proto_tree_add_item(lisp_data_flags_tree,
                hf_lisp_data_flags_iid, tvb, offset, 1, FALSE);
        proto_tree_add_item(lisp_data_flags_tree,
                hf_lisp_data_flags_res, tvb, offset, 1, FALSE);

        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags&LISP_DATA_FLAG_E && !(flags&LISP_DATA_FLAG_N)) {
            proto_tree_add_text(lisp_data_tree, tvb, offset, 0,
                    "Invalid flag combination: if E is set, N MUST be set");
        }

        if (flags&LISP_DATA_FLAG_N) {
            if (flags&LISP_DATA_FLAG_V) {
                proto_tree_add_text(lisp_data_tree, tvb, offset, 0,
                        "Invalid flag combination: N and V can't be set both");
            }
            proto_tree_add_item(lisp_data_tree,
                    hf_lisp_data_nonce, tvb, offset, 3, FALSE);
        } else {
            if (flags&LISP_DATA_FLAG_V) {
                proto_item *tiv;
                proto_tree *lisp_data_mapver_tree;

                tiv = proto_tree_add_item(lisp_data_tree,
                        hf_lisp_data_mapver, tvb, offset, 3, FALSE);

                lisp_data_mapver_tree = proto_item_add_subtree(tiv, ett_lisp_data_mapver);

                proto_tree_add_item(lisp_data_mapver_tree,
                        hf_lisp_data_srcmapver, tvb, offset, 3, FALSE);
                proto_tree_add_item(lisp_data_mapver_tree,
                        hf_lisp_data_dstmapver, tvb, offset, 3, FALSE);
            }
        }
        offset += 3;

        if (flags&LISP_DATA_FLAG_I) {
            proto_tree_add_item(lisp_data_tree,
                    hf_lisp_data_iid, tvb, offset, 3, FALSE);
            offset += 3;
            if (flags&LISP_DATA_FLAG_L) {
                proto_tree_add_item(lisp_data_tree,
                        hf_lisp_data_lsb8, tvb, offset, 1, FALSE);
            }
            offset +=1;
        } else {
            if (flags&LISP_DATA_FLAG_L) {
                proto_tree_add_item(lisp_data_tree,
                        hf_lisp_data_lsb, tvb, offset, 4, FALSE);
                offset += 4;
            }
        }
    }

    /* Check if there is stuff left in the buffer, and return if not */

    /* Determine if encapsulated packet is IPv4 or IPv6, and call dissector */
    next_tvb = tvb_new_subset(tvb, LISP_DATA_HEADER_LEN, -1, -1);
    ip_ver = tvb_get_bits8(next_tvb, 0, 4);
    switch (ip_ver) {
        case 4:
            call_dissector(ipv4_handle, next_tvb, pinfo, tree);
            break;
        case 6:
            call_dissector(ipv6_handle, next_tvb, pinfo, tree);
            break;
        default:
            call_dissector(data_handle, next_tvb, pinfo, tree);
            break;
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_lisp_data(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_lisp_data_flags,
                { "Flags", "lisp-data.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, "LISP Data Header Flags", HFILL }},
        { &hf_lisp_data_flags_nonce,
                { "N bit (Nonce present)", "lisp-data.flags.nonce",
                FT_BOOLEAN, LISP_DATA_FLAGS_WIDTH, TFS(&tfs_set_notset),
                LISP_DATA_FLAG_N, NULL, HFILL }},
        { &hf_lisp_data_flags_lsb,
                { "L bit (Locator-Status-Bits field enabled)", "lisp-data.flags.lsb",
                FT_BOOLEAN, LISP_DATA_FLAGS_WIDTH, TFS(&tfs_set_notset),
                LISP_DATA_FLAG_L, NULL, HFILL }},
        { &hf_lisp_data_flags_enr,
                { "E bit (Echo-Nonce-Request)", "lisp-data.flags.enr",
                FT_BOOLEAN, LISP_DATA_FLAGS_WIDTH, TFS(&tfs_set_notset),
                LISP_DATA_FLAG_E, NULL, HFILL }},
        { &hf_lisp_data_flags_mv,
                { "V bit (Map-Version present)", "lisp-data.flags.mv",
                FT_BOOLEAN, LISP_DATA_FLAGS_WIDTH, TFS(&tfs_set_notset),
                LISP_DATA_FLAG_V, NULL, HFILL }},
        { &hf_lisp_data_flags_iid,
                { "I bit (Instance ID present)", "lisp-data.flags.iid",
                FT_BOOLEAN, LISP_DATA_FLAGS_WIDTH, TFS(&tfs_set_notset),
                LISP_DATA_FLAG_I, NULL, HFILL }},
        { &hf_lisp_data_flags_res,
                { "Reserved", "lisp-data.flags.res",
                FT_UINT8, BASE_HEX, NULL,
                LISP_DATA_FLAG_RES, "Must be zero", HFILL }},
        { &hf_lisp_data_nonce,
                { "Nonce", "lisp-data.nonce",
                FT_UINT24, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_data_mapver,
                { "Map-Version", "lisp-data.mapver",
                FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_data_srcmapver,
                { "Source Map-Version", "lisp-data.srcmapver",
                FT_UINT24, BASE_DEC, NULL, 0xFFF000, NULL, HFILL }},
        { &hf_lisp_data_dstmapver,
                { "Destination Map-Version", "lisp-data.dstmapver",
                FT_UINT24, BASE_DEC, NULL, 0x000FFF, NULL, HFILL }},
        { &hf_lisp_data_iid,
                { "Instance ID", "lisp-data.iid",
                FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_data_lsb,
                { "Locator-Status-Bits", "lisp-data.lsb",
                FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFF, NULL, HFILL }},
        { &hf_lisp_data_lsb8,
                { "Locator-Status-Bits", "lisp-data.lsb8",
                FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_lisp_data,
        &ett_lisp_data_flags,
        &ett_lisp_data_mapver
    };

    /* Register the protocol name and description */
    proto_lisp_data = proto_register_protocol("Locator/ID Separation Protocol (Data)",
        "LISP Data", "lisp-data");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_lisp_data, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* Simple form of proto_reg_handoff_lisp_data which can be used if there are
   no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_lisp_data(void)
{
    dissector_handle_t lisp_data_handle;

    lisp_data_handle = new_create_dissector_handle(dissect_lisp_data,
                             proto_lisp_data);
    dissector_add_uint("udp.port", LISP_DATA_PORT, lisp_data_handle);
    ipv4_handle = find_dissector("ip");
    ipv6_handle = find_dissector("ipv6");
    data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
