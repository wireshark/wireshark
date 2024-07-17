/* packet-homepna.c
 *
 * ITU-T Rec. G.9954 (renumbered from G.989.2)
 * https://www.itu.int/rec/T-REC-G.9954/en
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

static dissector_handle_t homepna_handle;

static int proto_homepna;

static int hf_homepna_type;
static int hf_homepna_length;
static int hf_homepna_version;
static int hf_homepna_data;
static int hf_homepna_etype;
static int hf_homepna_trailer;

static int ett_homepna;

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
    /*
     * XXX: Ethertype 0x886C is assigned by IEEE to HomePNA, which was
     * originally developed by Epigram and bought by Broadcom.
     * Broadcom *also* uses 0x886C in their Wi-Fi firmware for certain
     * event frames with an entirely different unregistered protocol,
     * and at least up to certain firmware versions, there was an
     * exploit based on these so people might want to dissect them.
     * https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_11.html
     * https://github.com/kanstrup/bcmdhd-dissector/
     * https://android.googlesource.com/kernel/common.git/+/bcmdhd-3.10/drivers/net/wireless/bcmdhd/include/proto/ethernet.h
     * There's an example at
     * https://gitlab.com/wireshark/wireshark/-/issues/12759
     * We could eventually have a dissector for that; right now this
     * dissectors will incorrectly dissect such packets and probably call
     * them malformed.
     */

    proto_tree *ti;
    proto_tree *homepna_tree;
    int offset = 0;
    uint32_t control_length;
    homepna_format_e homepna_format = HOMEPNA_FORMAT_SHORT;
    uint16_t protocol;
    ethertype_data_t ethertype_data;

    if (tvb_captured_length(tvb) < 4)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HomePNA");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_homepna, tvb, 0, -1, ENC_NA);
    homepna_tree = proto_item_add_subtree(ti, ett_homepna);

    if (tvb_get_uint8(tvb, offset) > 127)
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
    if (protocol == 0) {
        /* No next layer protocol. Set our length here so the previous
         * dissector can find any padding, trailer, and FCS.
         */
        proto_item_set_len(ti, offset);
        set_actual_length(tvb, offset);
    } else {
        ethertype_data.etype = protocol;
        ethertype_data.payload_offset = offset;
        ethertype_data.fh_tree = homepna_tree;
        ethertype_data.trailer_id = hf_homepna_trailer;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    }

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

    static int *ett[] = {
        &ett_homepna,
    };

    proto_homepna = proto_register_protocol("HomePNA, wlan link local tunnel", "HomePNA", "hpna");
    proto_register_field_array(proto_homepna, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    homepna_handle = register_dissector("hpna", dissect_homepna, proto_homepna);
}


void
proto_reg_handoff_homepna(void)
{
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
