/* packet-homepna.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_register_homepna(void);
void proto_reg_handoff_homepna(void);

static int proto_homepna = -1;

static int hf_homepna_type   = -1;
static int hf_homepna_length = -1;
static int hf_homepna_version = -1;
static int hf_homepna_data = -1;
static int hf_homepna_etype = -1;
static int hf_homepna_trailer = -1;

static gint ett_homepna  = -1;

static dissector_handle_t ethertype_handle;

static const range_string homepna_type_rvals[] = {
    { 0,     0,     "Non-standard" },
    { 1,     1,     "Rate Request Control Frame" },
    { 2,     2,     "Link Integrity Short Frame" },
    { 3,     3,     "Capabilities Announcement" },
    { 4,     4,     "LARQ" },
    { 5,     5,     "Vendor-specific short format type" },
    { 6,     127,   "Reserved for future use by the ITU-T" },
    { 128,   32767, "Reserved for future use by the ITU-T" },
    { 32768, 32768, "Reserved for future use by the ITU-T" },
    { 32769, 32769, "Vendor-specific long-format" },
    { 32770, 65535, "Reserved for future use by the ITU-T" },
    { 0, 0, NULL }
};

typedef enum
{
    HOMEPNA_FORMAT_SHORT,
    HOMEPNA_FORMAT_LONG
} homepna_format_e;

static int
dissect_homepna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_tree *homepna_tree;
    int offset = 0;
    guint32 control_length;
    homepna_format_e homepna_format = HOMEPNA_FORMAT_SHORT;
    guint16 protocol;
    ethertype_data_t ethertype_data;

    if (tvb_captured_length(tvb) < 4)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HomePNA");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_homepna, tvb, 0, -1, ENC_NA);
    homepna_tree = proto_item_add_subtree(ti, ett_homepna);

    if (tvb_get_guint8(tvb, offset) > 127)
        homepna_format = HOMEPNA_FORMAT_LONG;

    if (homepna_format == HOMEPNA_FORMAT_SHORT)
    {
        proto_tree_add_item(homepna_tree, hf_homepna_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item_ret_uint(homepna_tree, hf_homepna_length, tvb, offset, 1, ENC_BIG_ENDIAN, &control_length);
        offset += 1;
    }
    else
    {
        proto_tree_add_item(homepna_tree, hf_homepna_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item_ret_uint(homepna_tree, hf_homepna_length, tvb, offset, 2, ENC_BIG_ENDIAN, &control_length);
        offset += 2;
    }

    proto_tree_add_item(homepna_tree, hf_homepna_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(homepna_tree, hf_homepna_data, tvb, offset, control_length-3, ENC_NA);
    offset += (control_length-2);

    protocol = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(homepna_tree, hf_homepna_etype, tvb, offset, 2, protocol);
    offset += 2;

    ethertype_data.etype = protocol;
    ethertype_data.payload_offset = offset;
    ethertype_data.fh_tree = homepna_tree;
    ethertype_data.trailer_id = hf_homepna_trailer;
    ethertype_data.fcs_len = 4;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);

    return tvb_captured_length(tvb);
}

void
proto_register_homepna(void)
{
    static hf_register_info hf[] = {
        { &hf_homepna_type,
        { "Type", "hpna.type", FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(homepna_type_rvals), 0x0,
            NULL, HFILL}},
        { &hf_homepna_length,
        { "Length", "hpna.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},
        { &hf_homepna_version,
        { "Version", "hpna.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},
        { &hf_homepna_data,
        { "Data", "hpna.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}},
        { &hf_homepna_etype,
        { "Ethertype", "hpna.etype", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL}},
        { &hf_homepna_trailer,
        { "Trailer", "hpna.trailer", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}},

    };

    static gint *ett[] = {
        &ett_homepna,
    };

    proto_homepna = proto_register_protocol("HomePNA, wlan link local tunnel", "HomePNA", "hpna");
    proto_register_field_array(proto_homepna, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_homepna(void)
{
    dissector_handle_t homepna_handle;

    homepna_handle = create_dissector_handle(dissect_homepna, proto_homepna);
    dissector_add_uint("ethertype", ETHERTYPE_LINK_CTL, homepna_handle);

    ethertype_handle = find_dissector_add_dependency("ethertype", proto_homepna);
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
