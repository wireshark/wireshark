/*
 * packet-raknet.c
 *
 * Routines for RakNet protocol packet disassembly.
 *
 * Ref: https://github.com/OculusVR/RakNet
 *
 * Nick Carter <ncarter100@gmail.com>
 * Copyright 2014 Nick Carter
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

#include <epan/packet.h>
#include <epan/expert.h>

/*
 * RAKNET Protocol Constants.
 */
#define RAKNET_MAGIC 0x00ffff00fefefefefdfdfdfd12345678
#define RAKNET_SECURITY_AND_COOKIE 0x043f57fefd

static int proto_raknet = -1;
static gint ett_raknet = -1; /* Should this node be expanded */

/*
 * Dissectors
 */
static dissector_table_t raknet_dissector_table;
static expert_field ei_raknet_uknown_id = EI_INIT;

/*
 * First byte gives us the packet id
 */
static int hf_raknet_packet_id = -1;

/*
 * General fields (fields that are in >1 packet types.
 */
static int hf_raknet_general_client_id = -1;
static int hf_raknet_general_elapsed_time = -1;
static int hf_raknet_general_magic = -1;
static int hf_raknet_general_mtu_size = -1;
static int hf_raknet_general_raknet_proto_ver = -1;
static int hf_raknet_general_security = -1;
static int hf_raknet_general_server_id = -1;
static int hf_raknet_general_udp_port = -1;
/*
 * Fields specific to a packet id type
 */
static int hf_raknet_0x05_null_padding = -1;
static int hf_raknet_0x06_server_security = -1;
static int hf_raknet_0x07_cookie = -1;
static int hf_raknet_0x1C_server_id_str_len = -1;
static int hf_raknet_0x1C_server_id_str = -1;

/*
 * Forward declaration.
 */
void proto_register_raknet(void);
void proto_reg_handoff_raknet(void);
static proto_tree *init_raknet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);


struct raknet_handler_entry {
    value_string vs;
    dissector_t dissector_fp;
};

static int
raknet_dissect_0x00(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_elapsed_time, tvb,
                offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_elapsed_time, tvb,
                            offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                            item_size, ENC_NA);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x02(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_elapsed_time, tvb,
                            offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                            item_size, ENC_NA);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x05(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
        offset += item_size;

        item_size = 1;
        proto_tree_add_item(sub_tree, hf_raknet_general_raknet_proto_ver, tvb,
                offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = -1; /* -1 read to end of tvb buffer */
        proto_tree_add_item(sub_tree, hf_raknet_0x05_null_padding, tvb, offset,
                item_size, ENC_NA);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x06(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
        offset += item_size;

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_server_id, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 1;
        proto_tree_add_item(sub_tree, hf_raknet_0x06_server_security, tvb,
                offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 2;
        proto_tree_add_item(sub_tree, hf_raknet_general_mtu_size, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x07(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
        offset += item_size;

        item_size = 1;
        proto_tree_add_item(sub_tree, hf_raknet_general_security, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 4;
        proto_tree_add_item(sub_tree, hf_raknet_0x07_cookie, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 2;
        proto_tree_add_item(sub_tree, hf_raknet_general_udp_port, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 2;
        proto_tree_add_item(sub_tree, hf_raknet_general_mtu_size, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_client_id, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x08(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
        offset += item_size;

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_server_id, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 1;
        proto_tree_add_item(sub_tree, hf_raknet_general_security, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 4;
        proto_tree_add_item(sub_tree, hf_raknet_0x07_cookie, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 2;
        proto_tree_add_item(sub_tree, hf_raknet_general_udp_port, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 2;
        proto_tree_add_item(sub_tree, hf_raknet_general_mtu_size, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 1;
        proto_tree_add_item(sub_tree, hf_raknet_general_security, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x19(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 1;
        proto_tree_add_item(sub_tree, hf_raknet_general_raknet_proto_ver, tvb,
                offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
        offset += item_size;

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_server_id, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int
raknet_dissect_0x1C(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
    proto_tree *sub_tree;
    gint item_size;
    gint str_size;
    gint offset;

    sub_tree = init_raknet(tvb, pinfo, tree, &offset);

    if (sub_tree != NULL) {

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_elapsed_time, tvb,
                offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 8;
        proto_tree_add_item(sub_tree, hf_raknet_general_server_id, tvb, offset,
                item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        item_size = 16;
        proto_tree_add_item(sub_tree, hf_raknet_general_magic, tvb, offset,
                item_size, ENC_NA);
        offset += item_size;

        /* raknet precedes strings with a short (2 bytes) holding string length. */
        str_size = tvb_get_ntohs(tvb, offset);
        item_size = 2;
        proto_tree_add_item(sub_tree, hf_raknet_0x1C_server_id_str_len, tvb,
                offset, item_size, ENC_BIG_ENDIAN);
        offset += item_size;

        proto_tree_add_item(sub_tree, hf_raknet_0x1C_server_id_str, tvb, offset,
                str_size, ENC_NA|ENC_ASCII);
    }
    return tvb_reported_length(tvb);
}

/*
 * Protocol definition and handlers.
 */
static const struct raknet_handler_entry raknet_handler[] = {
    /*
     * Ref: ..RakNet/Source/MessageIdentifiers.h
     */
    { { 0x0, "ID_CONNECTED_PING" },
        raknet_dissect_0x00 },
    { { 0x1, "ID_UNCONNECTED_PING" },
        raknet_dissect_0x01 },
    { { 0x2, "ID_UNCONNECTED_PING_OPEN_CONNECTIONS" },
        raknet_dissect_0x02 },
    { { 0x5, "ID_OPEN_CONNECTION_REQUEST_1" },
        raknet_dissect_0x05 },
    { { 0x6, "ID_OPEN_CONNECTION_REPLY_1" },
        raknet_dissect_0x06 },
    { { 0x7, "ID_OPEN_CONNECTION_REQUEST_2" },
        raknet_dissect_0x07 },
    { { 0x8, "ID_OPEN_CONNECTION_REPLY_2" },
        raknet_dissect_0x08 },
    { { 0x19, "ID_INCOMPATIBLE_PROTOCOL_VERSION" },
        raknet_dissect_0x19 },
    { { 0x1C, "ID_UNCONNECTED_PONG" },
        raknet_dissect_0x1C },
};

#define RAKNET_PACKET_ID_COUNT \
    (sizeof(raknet_handler) / sizeof(raknet_handler[0]))

/*
 * Look up packet id to packet name, value_string is wireshark type.
 */
static value_string packet_names[RAKNET_PACKET_ID_COUNT+1];

static void
raknet_init_packet_names(void)
{
    unsigned int i;

    for (i = 0; i < RAKNET_PACKET_ID_COUNT; i++) {
        packet_names[i].value  = raknet_handler[i].vs.value;
        packet_names[i].strptr = raknet_handler[i].vs.strptr;
    }
    packet_names[RAKNET_PACKET_ID_COUNT].value  = 0;
    packet_names[RAKNET_PACKET_ID_COUNT].strptr = NULL;
}

/*
 * Fill out the Info column and protocol subtree.
 *
 * Offset is updated for the caller.
 */
static proto_tree *
init_raknet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_tree *sub_tree;
    proto_item *ti;
    guint8 packet_id;

    *offset = 0;

    /*
     * Take buffer start 0 to end -1 as single raknet item.
     */
    ti = proto_tree_add_item(tree, proto_raknet, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_raknet);

    packet_id = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(sub_tree, hf_raknet_packet_id, tvb, *offset,
                        1, ENC_BIG_ENDIAN);
    *offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
             val_to_str(packet_id, packet_names, "Unknown (%#x)"));

    /*
     * Append description to the raknet item.
     */
    proto_item_append_text(ti, ", Packet id %#x", packet_id);


    return sub_tree;
}

/*
 * Decode the tvb buffer.
 *
 * RakNet is just a dissector.  It is invoked by protocols whose applications
 * are built using the RakNet libs.
 */
static int
dissect_raknet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8 packet_id;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RAKNET");
    col_clear(pinfo->cinfo, COL_INFO);

    packet_id = tvb_get_guint8(tvb, 0);

    if (!dissector_try_uint_new(raknet_dissector_table, packet_id, tvb,
                pinfo, tree, TRUE, NULL)) {
        proto_tree_add_expert(tree, pinfo, &ei_raknet_uknown_id, tvb,
                0, 1);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_raknet(void)
{
    static hf_register_info hf[] = {
        /*
         * Packet ID field.
         */
        { &hf_raknet_packet_id,
            { "RAKNET Packet ID", "raknet.id",
                FT_UINT8, BASE_HEX,
                VALS(packet_names), 0x0,
                NULL, HFILL }
        },
        /*
         * General fields (fields in >1 packet).
         */
        { &hf_raknet_general_client_id,
            { "RAKNET Client ID", "raknet.client_id",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_elapsed_time,
            { "RAKNET time since start (ms)", "raknet.elapsed_time",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_magic,
            { "RAKNET magic", "raknet.con_pingopen_magic",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_mtu_size,
            { "RAKNET MTU size", "raknet.MTU_size",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_raknet_proto_ver,
            { "RAKNET RakNet protocol version", "raknet.proto_ver",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_server_id,
            { "RAKNET Server ID", "raknet.server_id",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_security,
            { "RAKNET security", "raknet.security",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_general_udp_port,
            { "RAKNET UDP port", "raknet.UDP_port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x05
         */
        { &hf_raknet_0x05_null_padding,
            { "RAKNET Null padding", "raknet.null_padding",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x06
         */
        { &hf_raknet_0x06_server_security,
            { "RAKNET Server security", "raknet.server_security",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x07
         */
        { &hf_raknet_0x07_cookie,
            { "RAKNET cookie", "raknet.cookie",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x1C
         */
        { &hf_raknet_0x1C_server_id_str_len,
            { "RAKNET Server ID string len", "raknet.server_id_str_len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_0x1C_server_id_str,
            { "RAKNET Server ID string", "raknet.server_id_str",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        }
    };

    /*
     * Setup protocol subtree array
     */
    static gint *ett[] = {
        &ett_raknet,
    };

    /*
     * Set up expert info.
     */
    static ei_register_info ei[] = {
        { &ei_raknet_uknown_id, { "raknet.unknown.id", PI_UNDECODED, PI_ERROR,
                                  "RakNet unknown or not implemented packet id",
                                  EXPFILL }
        }
    };
    expert_module_t *expert_raknet;

    /*
     * Init data structs.
     */
    raknet_init_packet_names();

    /*
     * Register expert support.
     */
    expert_raknet = expert_register_protocol(proto_raknet);
    expert_register_field_array(expert_raknet, ei, array_length(ei));

    /*
     * Register the protocol with wireshark.
     */
    proto_raknet = proto_register_protocol (
            "RAKNET game libs", /* name */
            "RAKNET",           /* short name */
            "raknet"            /* abbrev */
            );

    /*
     * Register detailed dissection arrays.
     */
    proto_register_field_array(proto_raknet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    raknet_dissector_table =
        register_dissector_table("raknet.packet_id", "RakNet libs packet ids",
                                 proto_raknet, FT_UINT8, BASE_HEX);
    /*
     * Raknet subdissector for use by external protocols.
     */
    register_dissector("raknet", dissect_raknet, proto_raknet);
}

void
proto_reg_handoff_raknet(void)
{
    dissector_handle_t raknet_handle_tmp;
    unsigned int i;

    for (i = 0; i < RAKNET_PACKET_ID_COUNT; i++) {
        raknet_handle_tmp =
            create_dissector_handle(raknet_handler[i].dissector_fp,
                                        proto_raknet);
        dissector_add_uint("raknet.packet_id", raknet_handler[i].vs.value,
                           raknet_handle_tmp);
    }
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
