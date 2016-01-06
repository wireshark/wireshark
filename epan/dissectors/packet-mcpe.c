/*
 * packet-mcpe.c
 *
 * Routines for Minecraft Pocket Edition protocol packet disassembly.
 *
 * Nick Carter <ncarter100@gmail.com>
 * Copyright 2014 Nick Carter
 *
 * Using info found at:
 *   http://wiki.vg/Pocket_Minecraft_Protocol#Packet_Encapsulation
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
#include <epan/prefs.h>

#define MCPE_UDP_PORT_DEFAULT 19132
static guint mcpe_udp_port_requested = MCPE_UDP_PORT_DEFAULT;

static int proto_mcpe = -1;
static gint ett_mcpe = -1; /* Should this node be expanded */


/*
 * First byte gives us the packet id
 */
static int hf_mcpe_packet_id = -1;

/*
 * Custom payload encoding header.
 */
static int hf_mcpe_payload_encoding = -1;
static int hf_mcpe_general_packet_number = -1;
static int hf_mcpe_general_packet_payload = -1;
static int hf_mcpe_general_packet_payload_length = -1;
static int hf_mcpe_general_packet_payload_count = -1;

/*
 * Fields specific to a packet id type.
 */
static int hf_mcpe_0xC0_unknown = -1;
static int hf_mcpe_0xC0_single_packet = -1;

/*
 * Forward declarations.
 */
void proto_register_mcpe(void);
void proto_reg_handoff_mcpe(void);

static void
mcpe_dissect_detail_0xA0(tvbuff_t *tvb, proto_tree *raknet_tree, gint offset)
{
    gboolean single_packet;
    gint item_size;

    item_size = 2;
    proto_tree_add_item(raknet_tree, hf_mcpe_0xC0_unknown, tvb, offset,
                        item_size, ENC_BIG_ENDIAN);
    offset += item_size;

    single_packet = (tvb_get_guint8(tvb, offset) != 0);
    item_size = 1;
    proto_tree_add_item(raknet_tree, hf_mcpe_0xC0_single_packet, tvb, offset,
                        item_size, ENC_BIG_ENDIAN);
    offset += item_size;

    item_size = 3;
    proto_tree_add_item(raknet_tree, hf_mcpe_general_packet_number, tvb, offset,
                        item_size, ENC_BIG_ENDIAN);
    offset += item_size;

    if (!single_packet) {
        item_size = 3;
        proto_tree_add_item(raknet_tree, hf_mcpe_general_packet_number, tvb,
                            offset, item_size, ENC_BIG_ENDIAN);
        /*offset += item_size;*/
    }
}

/*
 * offset is updated for use by the caller.
 */
static void
mcpe_dissect_detail_payload_0x00(tvbuff_t *tvb, proto_tree *mcpe_tree,
                                gint *offset)
{
    gint item_size;

    item_size = 2;
    proto_tree_add_item(mcpe_tree, hf_mcpe_general_packet_payload_length, tvb,
                        *offset, item_size, ENC_BIG_ENDIAN);
    *offset += item_size;
}

/*
 * offset is updated for use by the caller.
 */
static void
mcpe_dissect_detail_payload_0x40(tvbuff_t *tvb, proto_tree *mcpe_tree,
                                gint *offset)
{
    gint item_size;

    item_size = 2;
    proto_tree_add_item(mcpe_tree, hf_mcpe_general_packet_payload_length, tvb,
                        *offset, item_size, ENC_BIG_ENDIAN);
    *offset += item_size;

    item_size = 3;
    proto_tree_add_item(mcpe_tree, hf_mcpe_general_packet_payload_count, tvb,
                        *offset, item_size, ENC_BIG_ENDIAN);
    *offset += item_size;
}

static void
mcpe_dissect_detail_payload(tvbuff_t *tvb, proto_tree *mcpe_tree, gint offset)
{
    gint payload_encoding;
    gint item_size;

    item_size = 3;
    proto_tree_add_item(mcpe_tree, hf_mcpe_general_packet_number, tvb, offset,
                        item_size, ENC_BIG_ENDIAN);
    offset += item_size;

    payload_encoding = tvb_get_guint8(tvb, offset);

    item_size = 1;
    proto_tree_add_item(mcpe_tree, hf_mcpe_payload_encoding, tvb, offset,
                        item_size, ENC_BIG_ENDIAN);
    offset += item_size;

    switch (payload_encoding) {
    case 0x00:
        mcpe_dissect_detail_payload_0x00(tvb, mcpe_tree, &offset);
        break;
    case 0x40:
    case 0x50:
    case 0x60:
        /*
         * 0x50 and 0x60 contain extra fields before the payload.  These fields
         * are currently unknown, so just use 0x40 for a correct partial
         * dissection.
         */
        mcpe_dissect_detail_payload_0x40(tvb, mcpe_tree, &offset);
        break;
    default:
        break;
    }

    item_size = -1; /* Read to end of buffer */
    proto_tree_add_item(mcpe_tree, hf_mcpe_general_packet_payload, tvb, offset,
                        item_size, ENC_NA);
}

/*
 * Common MCPE packet data
 */
static proto_tree *
mcpe_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    const char *packet_desc;
    guint8 packet_id;
    proto_tree *sub_tree;
    proto_item *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCPE");
    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * Take buffer start 0 to end -1 as single mcpe item.
     */
    ti = proto_tree_add_item(tree, proto_mcpe, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_mcpe);

    packet_id = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(sub_tree, hf_mcpe_packet_id, tvb, *offset,
                        1, ENC_BIG_ENDIAN);
    *offset += 1;

    switch (packet_id) {
    case 0xA0:
        packet_desc = " (NACK)";
        break;
    case 0xC0:
        packet_desc = " (ACK)";
        break;
    default:
        packet_desc = "";
        break;
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %#x%s", packet_id, packet_desc);

    proto_item_append_text(ti, ", Packet id %#x", packet_id);

    return sub_tree;
}

static int
mcpe_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
             void *data _U_)
{
    proto_tree *sub_tree;
    gint offset;

    offset = 0;
    sub_tree = mcpe_info(tvb, pinfo, tree, &offset);
    if (sub_tree != NULL) {
        mcpe_dissect_detail_payload(tvb, sub_tree, offset);
    }
    return tvb_reported_length(tvb);
}

static int
mcpe_dissect_0xA0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  void *data _U_)
{
    proto_tree *sub_tree;
    gint offset;

    offset = 0;
    sub_tree = mcpe_info(tvb, pinfo, tree, &offset);
    if (sub_tree != NULL) {
        mcpe_dissect_detail_0xA0(tvb, sub_tree, offset);
    }
    return tvb_reported_length(tvb);
}

static int
mcpe_dissect_0xC0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  void *data _U_)
{
    proto_tree *sub_tree;
    gint offset;

    offset = 0;
    sub_tree = mcpe_info(tvb, pinfo, tree, &offset);
    if (sub_tree != NULL) {
        mcpe_dissect_detail_0xA0(tvb, sub_tree, offset); /* 0xA0 */
    }
    return tvb_reported_length(tvb);
}

void
proto_register_mcpe(void)
{
    /*
     * Arrays for detailed dissection, controls output formatting.
     */
    static hf_register_info hf[] = {
        { &hf_mcpe_packet_id,
            { "MCPE Packet ID", "mcpe.type",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mcpe_payload_encoding,
            { "MCPE Payload encoding", "mcpe.payload_encoding",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mcpe_general_packet_number,
            { "MCPE Packet number", "mcpe.packet_number",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mcpe_general_packet_payload,
            { "MCPE Packet Payload", "mcpe.packet_payload",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mcpe_general_packet_payload_length,
            { "MCPE Payload length in *bits*", "mcpe.payload_length_bits",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mcpe_general_packet_payload_count,
            { "MCPE Packet payload count", "mcpe.payload_count",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0xC0
         */
        { &hf_mcpe_0xC0_unknown,
            { "MCPE Unknown field", "mcpe.unknown",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mcpe_0xC0_single_packet,
            { "MCPE single packet (boolean)", "mcpe.single_packet",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        }
    };

    /*
     * Setup protocol subtree array
     */
    static gint *ett[] = {
        &ett_mcpe,
    };
    module_t *mcpe_module;

    /*
     * Register the protocol with wireshark.
     */
    proto_mcpe = proto_register_protocol (
            "Minecraft Pocket Edition", /* name */
            "MCPE",                     /* short name */
            "mcpe"                      /* abbrev */
            );

    /*
     * Register detailed dissection arrays.
     */
    proto_register_field_array(proto_mcpe, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register a configuration option for UDP port */
    mcpe_module = prefs_register_protocol(proto_mcpe,
                                          proto_reg_handoff_mcpe);
    prefs_register_uint_preference(mcpe_module, "udp.port",
            "MCPE Server UDP Port",
            "Set the UDP port for the MCPE Server",
            10, &mcpe_udp_port_requested);
}

void
proto_reg_handoff_mcpe(void)
{
    static dissector_handle_t raknet_dissector = NULL;
    static guint last_server_port;
    static gboolean init_done = FALSE;

    if (init_done) {
        /*
         * Just delete the dissector before the new add.
         */
        dissector_delete_uint("udp.port", last_server_port, raknet_dissector);
    } else {
        /*
         * First time, create dissector handle, and find raknet dissector.
         */
        dissector_handle_t mcpe_gen_handle;

        init_done = TRUE;
        raknet_dissector = find_dissector("raknet");

        mcpe_gen_handle = create_dissector_handle(mcpe_dissect, proto_mcpe);
        dissector_add_uint("raknet.packet_id", 0x80, mcpe_gen_handle);
        dissector_add_uint("raknet.packet_id", 0x84, mcpe_gen_handle);
        dissector_add_uint("raknet.packet_id", 0x88, mcpe_gen_handle);
        dissector_add_uint("raknet.packet_id", 0x8C, mcpe_gen_handle);
        dissector_add_uint("raknet.packet_id", 0xA0,
                           create_dissector_handle(mcpe_dissect_0xA0,
                                                       proto_mcpe));
        dissector_add_uint("raknet.packet_id", 0xC0,
                           create_dissector_handle(mcpe_dissect_0xC0,
                                                       proto_mcpe));
    }

    last_server_port = mcpe_udp_port_requested;

    /* MCPE is the protocol that carries RakNet packets over UDP */
    dissector_add_uint("udp.port", mcpe_udp_port_requested, raknet_dissector);
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
