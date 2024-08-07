/* packet-h221_nonstd.c
 * Routines for H.221 nonstandard parameters disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_nonstd(void);
void proto_reg_handoff_nonstd(void);

static dissector_handle_t ms_nonstd_handle;

/* Define the nonstd proto */
static int proto_nonstd;

static int hf_h221_nonstd_netmeeting_codec;
static int hf_h221_nonstd_netmeeting_non_standard;

/*
 * Define the trees for nonstd
 * We need one for nonstd itself and one for the nonstd paramters
 */
static int ett_nonstd;

static const value_string ms_codec_vals[] = {
    {  0x0111, "L&H CELP 4.8k" },
    {  0x0200, "MS-ADPCM" },
    {  0x0211, "L&H CELP 8k" },
    {  0x0311, "L&H CELP 12k" },
    {  0x0411, "L&H CELP 16k" },
    {  0x1100, "IMA-ADPCM" },
    {  0x3100, "MS-GSM" },
    {  0xfeff, "E-AMR" },
    {  0, NULL }
};

static int
dissect_ms_nonstd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_item *it;
    proto_tree *tr;
    uint32_t offset=0;
    int tvb_len;
    uint16_t codec_extra;

    it=proto_tree_add_protocol_format(tree, proto_nonstd, tvb, 0, tvb_reported_length(tvb), "Microsoft NonStd");
    tr=proto_item_add_subtree(it, ett_nonstd);


    tvb_len = tvb_reported_length(tvb);

    /*
     * XXX - why do this test?  Are there any cases where throwing
     * an exception if the tvbuff is too short causes subsequent stuff
     * in the packet not to be dissected (e.g., if the octet string
     * containing the non-standard data is too short for the data
     * supposedly contained in it, and is followed by more items)?
     *
     * If so, the right fix might be to catch ReportedBoundsError in
     * the dissector calling this dissector, and report a malformed
     * nonStandardData item, and rethrow other exceptions (as a
     * BoundsError means you really *have* run out of packet data).
     */
    if(tvb_len >= 23)
    {

        codec_extra = tvb_get_ntohs(tvb,offset+22);

        if(codec_extra == 0x0100)
        {

            proto_tree_add_item(tr, hf_h221_nonstd_netmeeting_codec, tvb, offset+20, 2, ENC_BIG_ENDIAN);

        }
        else
        {

            proto_tree_add_item(tr, hf_h221_nonstd_netmeeting_non_standard, tvb, offset, -1, ENC_NA);

        }
    }
    return tvb_captured_length(tvb);
}

/* Register all the bits needed with the filtering engine */

void
proto_register_nonstd(void)
{
    static hf_register_info hf[] = {
        { &hf_h221_nonstd_netmeeting_codec,
            { "Microsoft NetMeeting Codec", "h221nonstd.netmeeting.codec", FT_UINT32, BASE_HEX,
                VALS(ms_codec_vals), 0, NULL, HFILL }
        },
        { &hf_h221_nonstd_netmeeting_non_standard,
            { "Microsoft NetMeeting Non Standard", "h221nonstd.netmeeting.non_standard", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_nonstd,
    };

    proto_nonstd = proto_register_protocol("H221NonStandard","h221nonstd", "h221nonstd");

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_nonstd, hf, array_length(hf));

    ms_nonstd_handle = register_dissector("h221nonstd", dissect_ms_nonstd, proto_nonstd);
}

/* The registration hand-off routine */
void
proto_reg_handoff_nonstd(void)
{
    dissector_add_uint("h245.nsp.h221",0xb500534c, ms_nonstd_handle);
    dissector_add_uint("h225.nsp.h221",0xb500534c, ms_nonstd_handle);
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
