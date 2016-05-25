/* packet-aruba-papi.c
 * Routines for Aruba PAPI dissection
 * Copyright 2010, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Real name of PAPI : Protocol Application Program Interface
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* This is not IANA assigned nor registered */
#define UDP_PORT_PAPI 8211

void proto_register_papi(void);
void proto_reg_handoff_papi(void);

/* Initialize the protocol and registered fields */
static int proto_papi = -1;
static int hf_papi_hdr_magic = -1;
static int hf_papi_hdr_version = -1;
static int hf_papi_hdr_dest_ip = -1;
static int hf_papi_hdr_src_ip = -1;
static int hf_papi_hdr_nat_port_number = -1;
static int hf_papi_hdr_garbage = -1;
static int hf_papi_hdr_dest_port = -1;
static int hf_papi_hdr_src_port = -1;
static int hf_papi_hdr_packet_type = -1;
static int hf_papi_hdr_packet_size = -1;
static int hf_papi_hdr_seq_number = -1;
static int hf_papi_hdr_message_code = -1;
static int hf_papi_hdr_checksum = -1;

static int hf_papi_debug = -1;
static int hf_papi_debug_text = -1;
static int hf_papi_debug_text_length = -1;
static int hf_papi_debug_48bits = -1;
static int hf_papi_debug_8bits = -1;
static int hf_papi_debug_16bits = -1;
static int hf_papi_debug_32bits = -1;
static int hf_papi_debug_ipv4 = -1;
static int hf_papi_debug_64bits = -1;
static int hf_papi_debug_bytes = -1;
static int hf_papi_debug_bytes_length = -1;

static expert_field ei_papi_debug_unknown = EI_INIT;

/* Global PAPI Debug Preference */
static gboolean g_papi_debug = FALSE;

/* Initialize the subtree pointers */
static gint ett_papi = -1;

/* PAPI Debug loop ! */
static int
dissect_papi_debug(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *debug_tree, *debug_sub_tree;


    ti = proto_tree_add_item(tree, hf_papi_debug, tvb, offset, -1, ENC_NA);
    debug_tree = proto_item_add_subtree(ti, ett_papi);

    while(offset < tvb_reported_length(tvb)) {
        switch(tvb_get_guint8(tvb,offset)) {
        case 0x00:
            ti = proto_tree_add_item(debug_tree, hf_papi_debug_text, tvb, offset+3, tvb_get_ntohs(tvb,offset+1), ENC_ASCII|ENC_NA);
            debug_sub_tree = proto_item_add_subtree(ti, ett_papi);
            proto_tree_add_item(debug_sub_tree, hf_papi_debug_text_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += tvb_get_ntohs(tvb, offset+1) + 3;
        break;
        case 0x01:
            proto_tree_add_item(debug_tree, hf_papi_debug_48bits, tvb, offset+1, 6, ENC_BIG_ENDIAN);
            offset += 7;
        break;
        case 0x02:
            proto_tree_add_item(debug_tree, hf_papi_debug_8bits, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case 0x03:
            proto_tree_add_item(debug_tree, hf_papi_debug_16bits, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += 3;
        break;
        case 0x04:
            proto_tree_add_item(debug_tree, hf_papi_debug_32bits, tvb, offset+1, 4, ENC_BIG_ENDIAN);
            offset += 5;
        break;
        case 0x05:
            proto_tree_add_item(debug_tree, hf_papi_debug_ipv4, tvb, offset+1, 4, ENC_BIG_ENDIAN);
            offset += 5;
        break;
        case 0x07:
            proto_tree_add_item(debug_tree, hf_papi_debug_16bits, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += 3;
        break;
        case 0x08:
            ti = proto_tree_add_item(debug_tree, hf_papi_debug_bytes, tvb, offset+3, tvb_get_ntohs(tvb,offset+1), ENC_NA);
            debug_sub_tree = proto_item_add_subtree(ti, ett_papi);
            proto_tree_add_item(debug_sub_tree, hf_papi_debug_bytes_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += tvb_get_ntohs(tvb,offset+1) + 3;
        break;
        case 0x09:
            proto_tree_add_item(debug_tree, hf_papi_debug_64bits, tvb, offset+1, 8, ENC_BIG_ENDIAN);
            offset += 9;
        break;
        default:
            proto_tree_add_expert_format(debug_tree, pinfo, &ei_papi_debug_unknown, tvb, offset, 1, "Unknown (%d)", tvb_get_guint8(tvb, offset));
            offset +=1;
           }
    }

    return offset;
}

static gboolean
dissect_papi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *papi_tree;
    guint     offset = 0;
    tvbuff_t *next_tvb;


    /* All PAPI packet start with 0x4972 !  */
    if ( tvb_get_ntohs(tvb, offset) != 0x4972 )
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PAPI");
    col_set_str(pinfo->cinfo, COL_INFO, "PAPI - Aruba AP Control Protocol");

    ti = proto_tree_add_item(tree, proto_papi, tvb, 0, -1, ENC_NA);
    papi_tree = proto_item_add_subtree(ti, ett_papi);

    proto_tree_add_item(papi_tree, hf_papi_hdr_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_dest_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(papi_tree, hf_papi_hdr_src_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(papi_tree, hf_papi_hdr_nat_port_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_garbage, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_dest_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_packet_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_packet_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_seq_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_message_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_checksum, tvb, offset, 16, ENC_NA);
    offset += 16;

    if(g_papi_debug)
    {
        offset = dissect_papi_debug(tvb, pinfo, offset, papi_tree);
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);

    return(TRUE);
}

void
proto_register_papi(void)
{
    module_t *papi_module;

    static hf_register_info hf[] = {
        { &hf_papi_hdr_magic,
            { "Magic", "papi.hdr.magic",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "PAPI Header Magic Number", HFILL }
        },
        { &hf_papi_hdr_version,
            { "Version",  "papi.hdr.version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "PAPI Protocol Version", HFILL }
        },
        { &hf_papi_hdr_dest_ip,
            { "Destination IP", "papi.hdr.dest.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_src_ip,
            { "Source IP", "papi.hdr.src.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_nat_port_number,
            { "NAT Port Number", "papi.hdr.nat_port_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_garbage,
            { "Garbage", "papi.hdr.garbage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_dest_port,
            { "Destination Port", "papi.hdr.dest.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_src_port,
            { "Source Port", "papi.hdr.src.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_packet_type,
            { "Packet Type", "papi.hdr.packet.type",
            FT_UINT16, BASE_DEC|BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_packet_size,
            { "Packet Size", "papi.hdr.packet.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_seq_number,
            { "Sequence Number", "papi.hdr.seq_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_message_code,
            { "Message Code", "papi.hdr.message_code",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_checksum,
            { "Checksum", "papi.hdr.checksum",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_papi_debug,
            { "Debug", "papi.debug",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_text,
            { "Debug (Text)", "papi.debug.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_text_length,
            { "Debug Text Length", "papi.debug.text_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_bytes,
            { "Debug (Bytes)", "papi.debug.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_bytes_length,
            { "Debug Bytes Length", "papi.debug.bytes_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_48bits,
            { "Debug (48 Bits)", "papi.debug.48bits",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_8bits,
            { "Debug (8 Bits)", "papi.debug.8bits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_16bits,
            { "Debug (16 Bits)", "papi.debug.16bits",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_32bits,
            { "Debug (32 Bits)", "papi.debug.32bits",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_ipv4,
            { "Debug (IPv4)", "papi.debug.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_64bits,
            { "Debug (64 Bits)", "papi.debug.64bits",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_papi
    };

    static ei_register_info ei[] = {
        { &ei_papi_debug_unknown, { "papi.debug.unknown", PI_PROTOCOL, PI_WARN, "Unknown", EXPFILL }},
    };

    expert_module_t* expert_papi;

    proto_papi = proto_register_protocol("Aruba PAPI", "PAPI", "papi");

    proto_register_field_array(proto_papi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_papi = expert_register_protocol(proto_papi);
    expert_register_field_array(expert_papi, ei, array_length(ei));

    papi_module = prefs_register_protocol(proto_papi, NULL);

    prefs_register_bool_preference(papi_module, "experimental_decode",
                       "Do experimental decode",
                       "Attempt to decode parts of the message that aren't fully understood yet",
                       &g_papi_debug);
}


void
proto_reg_handoff_papi(void)
{
    dissector_handle_t papi_handle;

    papi_handle = create_dissector_handle(dissect_papi, proto_papi);
    dissector_add_uint("udp.port", UDP_PORT_PAPI, papi_handle);
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
