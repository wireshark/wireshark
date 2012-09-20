/* packet-maap.c
 * Routines for 802.3 MAC Address Allocation Protocol defined by IEEE1722
 * Copyright 2012, Jason Damori, Biamp Systems <jdamori at biamp dot com>
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
 *
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

/* MAAP starts after common 1722 header */
#define MAAP_START_OFFSET                   1

/* MAAP Field Offsets */
#define MAAP_MSG_TYPE_OFFSET                0+MAAP_START_OFFSET
#define MAAP_VERSION_OFFSET                 1+MAAP_START_OFFSET
#define MAAP_STREAM_ID_OFFSET               3+MAAP_START_OFFSET
#define MAAP_REQ_START_ADDR_OFFSET          11+MAAP_START_OFFSET
#define MAAP_REQ_COUNT_OFFSET               17+MAAP_START_OFFSET
#define MAAP_CONFLICT_START_ADDR_OFFSET     19+MAAP_START_OFFSET
#define MAAP_CONFLICT_COUNT_OFFSET          25+MAAP_START_OFFSET

/* Bit Field Masks */
#define MAAP_MSG_TYPE_MASK                  0x0f
#define MAAP_VERSION_MASK                   0xf8
#define MAAP_DATA_LEN_MASK                  0x07ff

/* MAAP message_type */
#define MAAP_MSG_TYPE_RESERVED_0            0x00
#define MAAP_MSG_TYPE_PROBE                 0x01
#define MAAP_MSG_TYPE_DEFEND                0x02
#define MAAP_MSG_TYPE_ANNOUNCE              0x03
#define MAAP_MSG_TYPE_RESERVED_4            0x04
#define MAAP_MSG_TYPE_RESERVED_5            0x05

static const value_string maap_msg_type_vals [] = {
    {MAAP_MSG_TYPE_PROBE,       "MAAP_PROBE"},
    {MAAP_MSG_TYPE_DEFEND,      "MAAP_DEFEND"},
    {MAAP_MSG_TYPE_ANNOUNCE,    "MAAP_ANNOUNCE"},
    {0,                         NULL}
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
static int proto_maap = -1;

/* MAAP PDU */
static int hf_maap_message_type = -1;
static int hf_maap_version = -1;
static int hf_maap_data_length = -1;
static int hf_maap_stream_id = -1;
static int hf_maap_req_start_addr = -1;
static int hf_maap_req_count = -1;
static int hf_maap_conflict_start_addr = -1;
static int hf_maap_conflict_count = -1;

/* Initialize the subtree pointers */
static int ett_maap = -1;

static void
dissect_maap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8      maap_msg_type;
    proto_item *maap_item     = NULL;
    proto_tree *maap_tree     = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAAP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* The maap msg type will be handy in a moment */
    maap_msg_type = tvb_get_guint8(tvb, MAAP_MSG_TYPE_OFFSET);
    maap_msg_type &= 0x0f;

    /* Display the name of the packet type in the info column. */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s:",
                val_to_str(maap_msg_type, maap_msg_type_vals,
                            "Unknown Type(0x%02x)"));

    /* Now, we'll add the start and conflict addresses and counts to the info column as appropriate */
    switch (maap_msg_type)
    {
    case MAAP_MSG_TYPE_PROBE:
    case MAAP_MSG_TYPE_ANNOUNCE:
        col_append_fstr(pinfo->cinfo, COL_INFO, " req_start=%s, cnt=%d",
                        tvb_ether_to_str(tvb, MAAP_REQ_START_ADDR_OFFSET),
                        tvb_get_ntohs(tvb, MAAP_REQ_COUNT_OFFSET));

        break;
    case MAAP_MSG_TYPE_DEFEND:
        col_append_fstr(pinfo->cinfo, COL_INFO, " conflict_start=%s, cnt=%d",
                        tvb_ether_to_str(tvb, MAAP_CONFLICT_START_ADDR_OFFSET),
                        tvb_get_ntohs(tvb, MAAP_CONFLICT_COUNT_OFFSET));
        break;
    default:
        /* no info for reserved or unknown msg types */
        break;
    }


    if (tree) {
        maap_item = proto_tree_add_item(tree, proto_maap, tvb, MAAP_START_OFFSET, -1, ENC_NA);
        maap_tree = proto_item_add_subtree(maap_item, ett_maap);

        proto_tree_add_item(maap_tree, hf_maap_message_type,        tvb, MAAP_MSG_TYPE_OFFSET,            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(maap_tree, hf_maap_version,             tvb, MAAP_VERSION_OFFSET,             1, ENC_BIG_ENDIAN);
        proto_tree_add_item(maap_tree, hf_maap_data_length,         tvb, MAAP_VERSION_OFFSET,             2, ENC_BIG_ENDIAN);
        proto_tree_add_item(maap_tree, hf_maap_stream_id,           tvb, MAAP_STREAM_ID_OFFSET,           8, ENC_BIG_ENDIAN);
        proto_tree_add_item(maap_tree, hf_maap_req_start_addr,      tvb, MAAP_REQ_START_ADDR_OFFSET,      6, ENC_NA);
        proto_tree_add_item(maap_tree, hf_maap_req_count,           tvb, MAAP_REQ_COUNT_OFFSET,           2, ENC_BIG_ENDIAN);
        proto_tree_add_item(maap_tree, hf_maap_conflict_start_addr, tvb, MAAP_CONFLICT_START_ADDR_OFFSET, 6, ENC_NA);
        proto_tree_add_item(maap_tree, hf_maap_conflict_count,      tvb, MAAP_CONFLICT_COUNT_OFFSET,      2, ENC_BIG_ENDIAN);
    }
} /* end dissect_maap() */

/* Register the protocol with Wireshark */
void
proto_register_maap(void)
{
    static hf_register_info hf[] = {
        { &hf_maap_message_type,
            { "Message Type", "maap.message_type",
                FT_UINT8, BASE_HEX,
                VALS(maap_msg_type_vals), MAAP_MSG_TYPE_MASK,
                NULL, HFILL }},

        { &hf_maap_version,
            { "MAAP Version", "maap.version",
                FT_UINT8, BASE_HEX,
                NULL, MAAP_VERSION_MASK,
                NULL, HFILL }},

        { &hf_maap_data_length,
            { "Data Length", "maap.data_length",
                FT_UINT16, BASE_HEX,
                NULL, MAAP_DATA_LEN_MASK,
                NULL, HFILL }},

        { &hf_maap_stream_id,
            { "Stream ID", "maap.stream_id",
                FT_UINT64, BASE_HEX,
                NULL, 0x00,
                NULL, HFILL }},

        { &hf_maap_req_start_addr,
            { "Requested Start Address", "maap.req_start_addr",
                FT_ETHER, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }},

        { &hf_maap_req_count,
            { "Request Count", "maap.req_count",
                FT_UINT16, BASE_HEX,
                NULL, 0x00,
                NULL, HFILL }},

        { &hf_maap_conflict_start_addr,
            { "Conflict Start Address", "maap.conflict_start_addr",
                FT_ETHER, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }},

        { &hf_maap_conflict_count,
            { "Conflict Count", "maap.conflict_count",
                FT_UINT16, BASE_HEX,
                NULL, 0x00,
                NULL, HFILL }}
    }; /* end of static hf_register_info hf[] = */

    /* Setup protocol subtree array */
    static gint *ett[] = { &ett_maap };

    /* Register the protocol name and description */
    proto_maap = proto_register_protocol (
        "IEEE 1722 MAAP Protocol", /* name */
        "MAAP", /* short name */
        "maap" /* abbrev */
        );

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_maap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

} /* end proto_register_maap() */

void
proto_reg_handoff_maap(void)
{
    dissector_handle_t maap_handle;

    maap_handle = create_dissector_handle(dissect_maap, proto_maap);
    dissector_add_uint("ieee1722.subtype", 0x7E, maap_handle);
}
