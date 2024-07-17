/* packet-at-ldf.c
 * Dissector for Allied Telesis Loop Detection Frames
 *
 * Copyright (c) 2021-2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>

#define AT_LDF_LLC_CTRL 0xE3

#define AT_LDF_FRAME_LEN 79

void proto_register_at_ldf(void);
void proto_reg_handoff_at_ldf(void);

static dissector_handle_t at_ldf_handle;

static int proto_at_ldf;

/* Fields */
static int hf_at_ldf_version;
static int hf_at_ldf_src_vlan;
static int hf_at_ldf_src_port;
static int hf_at_ldf_ttl;
static int hf_at_ldf_id;
static int hf_at_ldf_text;

static int ett_at_ldf;

static int
dissect_at_ldf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /*
     * Packet description
     *
     * The frame is an LLC frame (non-SNAP) with DSAP=0, SSAP=0, Control=0xE3.
     * Ethernet destination address is the non-existing device address
     * with Allied Telesis OUI (00:00:f4:27:71:01).
     *
     * The payload contains information about protocol version, source VLAN and port,
     * TTL, random LDF identifier and an informational text.
     */


    /* Check if packet is destined to the Allied Telesis test address (00:00:F4:27:71:01) */
    uint8_t dst_mac[6] = {0x00, 0x00, 0xF4, 0x27, 0x71, 0x01};
    address dst_addr = ADDRESS_INIT_NONE;
    set_address(&dst_addr, AT_ETHER, sizeof(dst_mac), &dst_mac);

    if(!addresses_equal(&pinfo->dl_dst, &dst_addr))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AT LDF");
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Source VLAN: %u, Port: %u",
                    tvb_get_uint16(tvb, 1, ENC_BIG_ENDIAN),
                    tvb_get_uint16(tvb, 5, ENC_BIG_ENDIAN));

    /* Frame has fixed length, so we can directly set tree and reported length */
    tvb_set_reported_length(tvb, AT_LDF_FRAME_LEN);

    proto_item *ti = proto_tree_add_item(tree, proto_at_ldf, tvb, 0, AT_LDF_FRAME_LEN, ENC_NA);
    proto_tree *at_ldf_tree = proto_item_add_subtree(ti, ett_at_ldf);

    int offset = 0;
    proto_tree_add_item(at_ldf_tree, hf_at_ldf_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(at_ldf_tree, hf_at_ldf_src_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(at_ldf_tree, hf_at_ldf_src_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(at_ldf_tree, hf_at_ldf_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(at_ldf_tree, hf_at_ldf_id, tvb, offset, 7, ENC_NA);
    offset += 7;
    proto_tree_add_item(at_ldf_tree, hf_at_ldf_text, tvb, offset, 64, ENC_ASCII);

    return AT_LDF_FRAME_LEN;
}

void
proto_register_at_ldf(void)
{
    static hf_register_info hf[] = {
        { &hf_at_ldf_version,
            { "Version", "atldf.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_at_ldf_src_vlan,
            { "Source VLAN", "atldf.vlan",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_at_ldf_src_port,
            { "Source Port", "atldf.port",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_at_ldf_ttl,
            { "Time to Live", "atldf.ttl",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_at_ldf_id,
            { "Identifier", "atldf.id",
            FT_UINT56, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_at_ldf_text,
            { "Information", "atldf.info",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_at_ldf
    };

    proto_at_ldf = proto_register_protocol ("Allied Telesis Loop Detection", "AT LDF", "atldf");

    proto_register_field_array(proto_at_ldf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    at_ldf_handle = register_dissector("atldf", dissect_at_ldf, proto_at_ldf);
}

void
proto_reg_handoff_at_ldf(void)
{
    dissector_add_uint("llc.control", AT_LDF_LLC_CTRL, at_ldf_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
