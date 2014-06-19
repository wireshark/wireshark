/* packet-h221_nonstd.c
 * Routines for H.221 nonstandard parameters disassembly
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

#include <glib.h>
#include <epan/packet.h>

void proto_register_nonstd(void);
void proto_reg_handoff_nonstd(void);

/* Define the nonstd proto */
static int proto_nonstd = -1;

/*
 * Define the trees for nonstd
 * We need one for nonstd itself and one for the nonstd paramters
 */
static int ett_nonstd = -1;

const value_string ms_codec_vals[] = {
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

static void
dissect_ms_nonstd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *it;
    proto_tree *tr;
    guint32 offset=0;
    gint tvb_len;
    guint16 codec_value, codec_extra;

    it=proto_tree_add_protocol_format(tree, proto_nonstd, tvb, 0, tvb_length(tvb), "Microsoft NonStd");
    tr=proto_item_add_subtree(it, ett_nonstd);


    tvb_len = tvb_length(tvb);

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

        codec_value = tvb_get_ntohs(tvb,offset+20);
        codec_extra = tvb_get_ntohs(tvb,offset+22);

        if(codec_extra == 0x0100)
        {

            proto_tree_add_text(tr, tvb, offset+20, 2, "Microsoft NetMeeting Codec=0x%04X %s",
                                codec_value,val_to_str(codec_value, ms_codec_vals,"Unknown (%u)"));

        }
        else
        {

            proto_tree_add_text(tr, tvb, offset, -1, "Microsoft NetMeeting Non Standard");

        }
    }
}

/* Register all the bits needed with the filtering engine */

void
proto_register_nonstd(void)
{
    static gint *ett[] = {
        &ett_nonstd,
    };

    proto_nonstd = proto_register_protocol("H221NonStandard","h221nonstd", "h221nonstd");

    proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routine */
void
proto_reg_handoff_nonstd(void)
{
    static dissector_handle_t ms_nonstd_handle;


    ms_nonstd_handle = create_dissector_handle(dissect_ms_nonstd, proto_nonstd);

    dissector_add_uint("h245.nsp.h221",0xb500534c, ms_nonstd_handle);
    dissector_add_uint("h225.nsp.h221",0xb500534c, ms_nonstd_handle);

}
