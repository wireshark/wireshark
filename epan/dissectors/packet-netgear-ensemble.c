/* packet-netgear-ensemble.c
 *
 * Routines for Netgear AP Ensemble Protocol
 * Charlie Lenahan <clenahan@sonicbison.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_nge(void);
void proto_reg_handoff_nge(void);

#define NETGEAR_ENSEMBLE_PORT 4554

static int proto_nge = -1;

static int hf_nge_version = -1;
static int hf_nge_unknown = -1;
static int hf_nge_unknown_int32 = -1;
static int hf_nge_sequence = -1;
static int hf_nge_tlv_length = -1;
static int hf_nge_ensemble_name = -1;
static int hf_nge_firmware_name = -1;
static int hf_nge_region_name = -1;
static int hf_nge_firmware_version = -1;
static int hf_nge_ap_name = -1;
static int hf_nge_uptime = -1;
static int hf_nge_mac = -1;
static int hf_nge_ip = -1;
static int hf_nge_uuid = -1;

static gint ett_nge = -1;
static gint ett_nge_lv = -1;
static gint ett_nge_ensemble = -1;


static void
dissect_nge_esemble(tvbuff_t *tvb,proto_tree *tree, int offset)
{
    guint strLen=0;

    guint32 length = tvb_get_guint32(tvb, offset,ENC_BIG_ENDIAN);
    proto_tree *ensemble_tree = proto_tree_add_subtree(tree, tvb, offset, length+4, ett_nge_ensemble, NULL,"Ensemble");

    proto_tree_add_uint(ensemble_tree, hf_nge_tlv_length, tvb, offset, 4, length);
    offset += 4;

    proto_tree_add_item(ensemble_tree, hf_nge_unknown, tvb, offset, 17, ENC_NA);
    offset += 17;

    /* type == 1 ? */
    proto_tree_add_item(ensemble_tree, hf_nge_unknown_int32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* uuid ? */
    proto_tree_add_item(ensemble_tree, hf_nge_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
    offset += 16;

    proto_tree_add_item(ensemble_tree, hf_nge_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(ensemble_tree, hf_nge_unknown, tvb, offset, 20, ENC_NA);
    offset += 20;

    proto_tree_add_item(ensemble_tree, hf_nge_mac, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* type == 2 ? */
    proto_tree_add_item(ensemble_tree, hf_nge_unknown_int32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_length(ensemble_tree, hf_nge_ensemble_name, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN, &strLen);
    offset += strLen;

    proto_tree_add_item_ret_length(ensemble_tree, hf_nge_firmware_name, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN, &strLen);
    offset += strLen;

    proto_tree_add_item_ret_length(ensemble_tree, hf_nge_region_name, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN, &strLen);
    offset += strLen;

    /* type == 0 ? */
    proto_tree_add_item(ensemble_tree, hf_nge_unknown_int32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_length(ensemble_tree, hf_nge_firmware_version, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN, &strLen);
    offset += strLen;

    proto_tree_add_item(ensemble_tree, hf_nge_unknown, tvb, offset, 16, ENC_NA);
    offset += 16;

    /* timestamp? */
    proto_tree_add_item(ensemble_tree, hf_nge_uptime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_length(ensemble_tree, hf_nge_ap_name, tvb, offset, 4, ENC_ASCII|ENC_BIG_ENDIAN, &strLen);
    offset += strLen;

    proto_tree_add_item(ensemble_tree, hf_nge_unknown, tvb, offset, -1, ENC_NA);

}

static int
dissect_nge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_item *ti = proto_tree_add_item(tree, proto_nge, tvb, 0, -1, ENC_NA);
    proto_tree *nge_tree = proto_item_add_subtree(ti, ett_nge);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NGE");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* presumed version */
    proto_tree_add_item(nge_tree, hf_nge_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(nge_tree, hf_nge_unknown, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(nge_tree, hf_nge_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    dissect_nge_esemble(tvb, nge_tree, offset);

    return tvb_captured_length(tvb);
}


void
proto_register_nge(void)
{
    static hf_register_info hf[] = {
        { &hf_nge_version,
            { "Version", "nge.version",FT_UINT8, BASE_DEC,
                NULL, 0x0,NULL, HFILL }},
        { &hf_nge_unknown,
            { "Unknown", "nge.unknown", FT_BYTES, BASE_NONE,
                NULL, 0x0,NULL, HFILL }},
        { &hf_nge_unknown_int32,
            { "Unknown", "nge.unknown.int32", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_sequence,
            { "Sequence", "nge.sequence", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_uptime,
            { "Uptime", "nge.uptime", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_mac,
            { "MAC", "nge.mac", FT_ETHER, BASE_NONE,
                NULL, 0x0,NULL, HFILL }},
        { &hf_nge_ip,
            { "IP", "nge.ip", FT_IPv4, BASE_NONE,
                NULL, 0x0,NULL, HFILL }},
        { &hf_nge_uuid,
            { "Device UUID", "nge.uuid", FT_GUID, BASE_NONE,
                NULL, 0x0,NULL, HFILL }},
        { &hf_nge_ensemble_name,
            { "Ensemble Name", "nge.ensemble_name", FT_UINT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_firmware_name,
            { "Firmware Name", "nge.firmware_name", FT_UINT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_region_name,
            { "Region Name", "nge.region_name", FT_UINT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_firmware_version,
            { "Firmware Version", "nge.firmware_version", FT_UINT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_ap_name,
            { "AP Name", "nge.ap_name", FT_UINT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_nge_tlv_length,
            { "Length",	"nge.tlv_len", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_nge,
        &ett_nge_lv,
        &ett_nge_ensemble
    };

    proto_nge = proto_register_protocol ("Netgear Ensemble Protocol", "NGE", "nge");

    proto_register_field_array(proto_nge, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nge(void)
{
    dissector_handle_t nge_handle;

    nge_handle = create_dissector_handle(dissect_nge, proto_nge);
    dissector_add_for_decode_as_with_preference("udp.port", nge_handle);
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
