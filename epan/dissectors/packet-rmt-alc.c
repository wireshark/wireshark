/* packet-rmt-alc.c
 * Reliable Multicast Transport (RMT)
 * ALC Protocol Instantiation dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Asynchronous Layered Coding (ALC):
 * ----------------------------------
 *
 * A massively scalable reliable content delivery protocol.
 * Asynchronous Layered Coding combines the Layered Coding Transport
 * (LCT) building block, a multiple rate congestion control building
 * block and the Forward Error Correction (FEC) building block to
 * provide congestion controlled reliable asynchronous delivery of
 * content to an unlimited number of concurrent receivers from a single
 * sender.
 *
 * References:
 *     RFC 3450, Asynchronous Layered Coding protocol instantiation
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
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-rmt-common.h"

/* Initialize the protocol and registered fields */
/* ============================================= */

void proto_register_alc(void);
void proto_reg_handoff_alc(void);

static int proto_rmt_alc = -1;

static int hf_version = -1;
static int hf_payload = -1;

static int ett_main = -1;

static expert_field ei_version1_only = EI_INIT;

static dissector_handle_t xml_handle;
static dissector_handle_t rmt_lct_handle;
static dissector_handle_t rmt_fec_handle;

static guint    g_default_udp_port          = 0; /* 4001 */
static gboolean g_codepoint_as_fec_encoding = TRUE;
static gint     g_ext_192                   = LCT_PREFS_EXT_192_FLUTE;
static gint     g_ext_193                   = LCT_PREFS_EXT_193_FLUTE;

/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_alc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8              version;
    lct_data_exchange_t lct;
    fec_data_exchange_t fec;
    int                 len;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *alc_tree;

    tvbuff_t *new_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ALC");
    col_clear(pinfo->cinfo, COL_INFO);

    /* ALC header dissection */
    /* --------------------- */

    version = hi_nibble(tvb_get_guint8(tvb, offset));

    /* Create subtree for the ALC protocol */
    ti = proto_tree_add_item(tree, proto_rmt_alc, tvb, offset, -1, ENC_NA);
    alc_tree = proto_item_add_subtree(ti, ett_main);

    /* Fill the ALC subtree */
    ti = proto_tree_add_uint(alc_tree, hf_version, tvb, offset, 1, version);

    /* This dissector supports only ALCv1 packets.
     * If version > 1 print only version field and quit.
     */
    if (version != 1) {
        expert_add_info(pinfo, ti, &ei_version1_only);

        /* Complete entry in Info column on summary display */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %u (not supported)", version);
        return 0;
    }

    /* LCT header dissection */
    /* --------------------- */
    new_tvb = tvb_new_subset_remaining(tvb,offset);

    lct.ext_192 = g_ext_192;
    lct.ext_193 = g_ext_193;
    lct.codepoint = 0;
    lct.is_flute = FALSE;
    len = call_dissector_with_data(rmt_lct_handle, new_tvb, pinfo, alc_tree, &lct);
    if (len < 0)
        return offset;

    offset += len;

    /* FEC header dissection */
    /* --------------------- */

    /* Only if LCT dissector has determined FEC Encoding ID */
    /* FEC dissector needs to be called with encoding_id filled */
    if (g_codepoint_as_fec_encoding && tvb_reported_length(tvb) > offset)
    {
        fec.encoding_id = lct.codepoint;

        new_tvb = tvb_new_subset_remaining(tvb,offset);
        len = call_dissector_with_data(rmt_fec_handle, new_tvb, pinfo, alc_tree, &fec);
        if (len < 0)
            return offset;

        offset += len;
    }

    /* Add the Payload item */
    if (tvb_reported_length(tvb) > offset){
        if(lct.is_flute){
            new_tvb = tvb_new_subset_remaining(tvb,offset);
            call_dissector(xml_handle, new_tvb, pinfo, alc_tree);
        }else{
            proto_tree_add_item(alc_tree, hf_payload, tvb, offset, -1, ENC_NA);
        }
    }

    return tvb_reported_length(tvb);
}

void proto_register_alc(void)
{
    /* Setup ALC header fields */
    static hf_register_info hf_ptr[] = {

        { &hf_version,
          { "Version", "alc.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_payload,
          { "Payload", "alc.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
    };

    static ei_register_info ei[] = {
        { &ei_version1_only, { "alc.version1_only", PI_PROTOCOL, PI_WARN, "Sorry, this dissector supports ALC version 1 only", EXPFILL }},
    };

    module_t *module;
    expert_module_t* expert_rmt_alc;

    /* Register the protocol name and description */
    proto_rmt_alc = proto_register_protocol("Asynchronous Layered Coding", "ALC", "alc");
    new_register_dissector("alc", dissect_alc, proto_rmt_alc);

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_rmt_alc, hf_ptr, array_length(hf_ptr));
    proto_register_subtree_array(ett_ptr, array_length(ett_ptr));
    expert_rmt_alc = expert_register_protocol(proto_rmt_alc);
    expert_register_field_array(expert_rmt_alc, ei, array_length(ei));

    /* Register preferences */
    module = prefs_register_protocol(proto_rmt_alc, proto_reg_handoff_alc);

    prefs_register_obsolete_preference(module, "default.udp_port.enabled");

    prefs_register_uint_preference(module,
                                   "default.udp_port",
                                   "UDP destination port",
                                   "Specifies the UDP destination port for automatic dissection of ALC packets",
                                   10, &g_default_udp_port);

    prefs_register_bool_preference(module,
                                   "lct.codepoint_as_fec_id",
                                   "LCT Codepoint as FEC Encoding ID",
                                   "Whether the LCT header Codepoint field should be considered the FEC Encoding ID of carried object",
                                   &g_codepoint_as_fec_encoding);

    prefs_register_enum_preference(module,
                                   "lct.ext.192",
                                   "LCT header extension 192",
                                   "How to decode LCT header extension 192",
                                   &g_ext_192,
                                   enum_lct_ext_192,
                                   FALSE);

    prefs_register_enum_preference(module,
                                   "lct.ext.193",
                                   "LCT header extension 193",
                                   "How to decode LCT header extension 193",
                                   &g_ext_193,
                                   enum_lct_ext_193,
                                   FALSE);
}

void proto_reg_handoff_alc(void)
{
    static dissector_handle_t handle;
    static gboolean           preferences_initialized = FALSE;
    static guint              old_udp_port            = 0;

    if (!preferences_initialized)
    {
        preferences_initialized = TRUE;
        handle = new_create_dissector_handle(dissect_alc, proto_rmt_alc);
        dissector_add_for_decode_as("udp.port", handle);
        xml_handle = find_dissector("xml");
        rmt_lct_handle = find_dissector("rmt-lct");
        rmt_fec_handle = find_dissector("rmt-fec");
    }

    /* Register UDP port for dissection */
    if(old_udp_port != 0 && old_udp_port != g_default_udp_port){
        dissector_delete_uint("udp.port", old_udp_port, handle);
    }

    if(g_default_udp_port != 0 && old_udp_port != g_default_udp_port) {
        dissector_add_uint("udp.port", g_default_udp_port, handle);
    }

    old_udp_port = g_default_udp_port;
}

/*
 * Editor modelines - http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
