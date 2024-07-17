/* packet-aruba-iap.c
 * Routines for Aruba IAP header disassembly
 * Copyright 2014, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/*
 * Aruba Instant AP broadcast on L2 Layer with ethertype 0x8ffd
 * All frame start with 0xbeef (Magic number)
 * Octet 1 : Header (version)
 * Octet 2 : Type (only see type 3, 4, 5, 7 with IP Address...)
 * Octet 3 : Length
 * Octet 4 : Id
 *
 * Only for Type 3, 4, 5 and 7
 * Octet 5 : Status (Master / Slave..)
 * Octet 6-9 : timestamp
 * Octet 10-13 : The address IP(v4) of VC (Virtual Controller)
 * Octet 14 : Model
 * Octet 15-16 : Vlan ID (of Uplink)
 * Octet 17-20 : Unknown...
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#define ETHERTYPE_IAP   0x8ffd
#define MAGIC_IAP       0xbeef

void proto_register_aruba_iap(void);
void proto_reg_handoff_aruba_iap(void);

static dissector_handle_t iap_handle;

static int proto_aruba_iap;
static int ett_aruba_iap;

static int hf_iap_magic;
static int hf_iap_version;
static int hf_iap_type;
static int hf_iap_length;
static int hf_iap_id;
static int hf_iap_status;
static int hf_iap_uptime;
static int hf_iap_vc_ip;
static int hf_iap_pvid;
static int hf_iap_model;
static int hf_iap_unknown_uint;
static int hf_iap_unknown_bytes;

static const value_string iap_model[] = {
    { 0x0a, "Orion (IAP-104, IAP-105, IAP-175, RAP-3WN and RAP-3WNP)" },
    { 0x0f, "Cassiopeia (IAP-130 Series)" },
    { 0x17, "Aries (RAP-155 and RAP-155P)" },
    { 0x19, "Centaurus (IAP-224, IAP-225, IAP-214/215, IAP-274, IAP-275 and IAP-277)" },
    { 0x1a, "Pegasus (RAP-108, RAP-109, IAP-114, IAP-115 and IAP-103)" },
    { 0x1e, "Taurus (IAP-204/205, IAP-205H)" },
    { 0x28, "Hercules (IAP-314/315, IAP-324/325, IAP 318 and IAP 374/375/377)" },
    { 0x2b, "Lupus (IAP-334/335)" },
    { 0x2e, "Vela (IAP-203H, IAP-207, IAP-203R and IAP-203RP)" },
    { 0x30, "Ursa (IAP-303, IAP-304/305, IAP-365/367 and IAP-303H)" },
    { 0x37, "Draco (IAP-344/345)" },
    { 0x39, "Scorpio (IAP-514 and IAP-515)" },
    { 0x40, "Gemini (IAP-500 Series)" },
    { 0x47, "Norma (IAP-635)" },
    { 0, NULL }
};

static int
dissect_aruba_iap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_tree *aruba_iap_tree;
    uint16_t magic;
    uint8_t type;
    int offset = 0;

    magic = tvb_get_ntohs(tvb, offset);

    if(magic != MAGIC_IAP)
    {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_aruba_iap, tvb, 0, -1, ENC_NA);
    aruba_iap_tree = proto_item_add_subtree(ti, ett_aruba_iap);

    proto_tree_add_item(aruba_iap_tree, hf_iap_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(aruba_iap_tree, hf_iap_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    col_add_fstr(pinfo->cinfo, COL_INFO, "Aruba Instant AP");

    proto_tree_add_item(aruba_iap_tree, hf_iap_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(aruba_iap_tree, hf_iap_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(aruba_iap_tree, hf_iap_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(type == 3 || type == 4 || type == 5 || type == 7){

        proto_tree_add_item(aruba_iap_tree, hf_iap_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(aruba_iap_tree, hf_iap_uptime, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(aruba_iap_tree, hf_iap_vc_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " VC IP: %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;

        proto_tree_add_item(aruba_iap_tree, hf_iap_model, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(aruba_iap_tree, hf_iap_pvid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_bytes, tvb, offset, -1, ENC_NA);

    } else {
        proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_bytes, tvb, offset, -1, ENC_NA);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_aruba_iap(void)
{
    static hf_register_info hf[] = {
        { &hf_iap_magic,
        { "Magic", "aruba_iap.magic", FT_UINT16, BASE_HEX, NULL,0x0,
        "Magic Number of IAP traffic (Always 0x8ffd)", HFILL}},

        { &hf_iap_version,
        { "Version", "aruba_iap.version", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_iap_type,
        { "Type", "aruba_iap.type", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Type of message", HFILL}},

        { &hf_iap_length,
        { "Length", "aruba_iap.length", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_iap_id,
        { "Id", "aruba_iap.id", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_iap_status,
        { "Status", "aruba_iap.status", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_iap_uptime,
        { "Uptime", "aruba_iap.uptime", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_iap_vc_ip,
        { "VC IP", "aruba_iap.vc_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
        "Address IP of Virtual Controller", HFILL}},

        { &hf_iap_pvid,
        { "PVID (Port Vlan ID)", "aruba_iap.pvid", FT_UINT16, BASE_DEC, NULL, 0x0,
        "Vlan ID (of Uplink)", HFILL}},

        { &hf_iap_model,
        { "Model", "aruba_iap.model", FT_UINT8, BASE_DEC_HEX, VALS(iap_model), 0x0,
        NULL, HFILL}},

        { &hf_iap_unknown_bytes,
        { "Unknown", "aruba_iap.unknown.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown Data...", HFILL}},

        { &hf_iap_unknown_uint,
        { "Unknown", "aruba_iap.unknown.uint", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        "Unknown (UINT) Data...", HFILL}},


    };

    static int *ett[] = {
        &ett_aruba_iap,
    };

    proto_aruba_iap = proto_register_protocol("Aruba Instant AP Protocol",
                    "aruba_iap", "aruba_iap");
    proto_register_field_array(proto_aruba_iap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    iap_handle = register_dissector("aruba_iap", dissect_aruba_iap, proto_aruba_iap);
}


void
proto_reg_handoff_aruba_iap(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_IAP, iap_handle);
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
