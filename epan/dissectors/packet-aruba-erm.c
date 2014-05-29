/* packet-aruba-erm.c
 * Routines for the disassembly of Aruba encapsulated remote mirroring frames
 * (Adapted from packet-hp-erm.c and packet-cisco-erspan.c)
 *
 * Copyright 2010  Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * ERM Radio-Format added by Hadriel Kaplan
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * Format:
 *  Use the Header of Record (Packet) Header
 *
 * typedef struct pcaprec_hdr_s {
 *       guint32 ts_sec;          timestamp seconds
 *       guint32 ts_usec;         timestamp microseconds
 *       guint32 incl_len;        number of octets of packet saved in file
 *       guint32 orig_len;        actual length of packet
 * } pcaprec_hdr_t;
 *
 * Following with 802.11 header
 */

/*
 * Format:
 *  The ERM Radio-Format has the above header, plus more, like this:
 *
 *  struct radio_pcap_hdr {
 *   struct timeval ts;
 *   __u32  capture_length;
 *   __u32  frame_length;
 *   __u16  rate_per_half_mhz;
 *   __u8   channel;
 *   __u8   signal_percent;
 *  } __attribute__ ((packed));
 *
 * Following with 802.11 header
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#define PROTO_SHORT_NAME "ARUBA_ERM"
#define PROTO_LONG_NAME  "ARUBA encapsulated remote mirroring"

#define TYPE_PCAP 0
#define TYPE_PEEK 1
#define TYPE_AIRMAGNET 2
#define TYPE_PCAPPLUSRADIO 3
#define TYPE_PPI 4

static const value_string aruba_erm_type_vals[] = {
    { TYPE_PCAP,            "pcap (type 0)" },
    { TYPE_PEEK,            "peek (type 1)" },
    { TYPE_AIRMAGNET,       "Airmagnet (type 2)" },
    { TYPE_PCAPPLUSRADIO,   "pcap + radio (type 3)" },
    { TYPE_PPI,             "ppi (type 4)" },
    { 0, NULL }
};
void proto_register_aruba_erm(void);
void proto_reg_handoff_aruba_erm(void);
void proto_reg_handoff_aruba_erm_radio(void);

static range_t *global_aruba_erm_port_range;
static gint  aruba_erm_type         = 0;

static int  proto_aruba_erm       = -1;

static int  hf_aruba_erm_time             = -1;
static int  hf_aruba_erm_incl_len         = -1;
static int  hf_aruba_erm_orig_len         = -1;
static int  hf_aruba_erm_data_rate        = -1;
static int  hf_aruba_erm_data_rate_gen    = -1;
static int  hf_aruba_erm_channel          = -1;
static int  hf_aruba_erm_signal_strength  = -1;

static gint ett_aruba_erm = -1;

static expert_field ei_aruba_erm_airmagnet = EI_INIT;

static dissector_handle_t aruba_erm_handle;
static dissector_handle_t ieee80211_handle;
static dissector_handle_t peek_handle;
static dissector_handle_t ppi_handle;
static dissector_handle_t data_handle;

static int
dissect_aruba_erm_pcap(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *aruba_erm_tree, gint offset)
{
    nstime_t ts;

    ts.secs = tvb_get_ntohl(tvb, 0);
    ts.nsecs = tvb_get_ntohl(tvb,4)*1000;
    proto_tree_add_time(aruba_erm_tree, hf_aruba_erm_time, tvb, offset, 8,&ts);
    offset +=8;

    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_incl_len, tvb, 8, 4, ENC_BIG_ENDIAN);
    offset +=4;

    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_orig_len, tvb, 12, 4, ENC_BIG_ENDIAN);
    offset +=4;

    return offset;
}
static int
dissect_aruba_erm_pcap_radio(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *aruba_erm_tree, gint offset)
{
    proto_item *ti_data_rate;
    guint16 data_rate;

    data_rate = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_data_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
    ti_data_rate = proto_tree_add_float_format(aruba_erm_tree, hf_aruba_erm_data_rate_gen,
                                                tvb, 16, 2,
                                                (float)data_rate / 2,
                                                "Data Rate: %.1f Mb/s",
                                                (float)data_rate / 2);
    PROTO_ITEM_SET_GENERATED(ti_data_rate);
    offset += 2;

    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_channel, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_signal_strength, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}
static void
dissect_aruba_erm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    proto_item *ti;
    proto_tree *aruba_erm_tree;
    tvbuff_t   *eth_tvb;

    int offset = 0 ;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME);


    ti = proto_tree_add_item(tree, proto_aruba_erm, tvb, 0, 0, ENC_NA);
    proto_item_append_text(ti, ": %s", val_to_str(aruba_erm_type, aruba_erm_type_vals, "Unknown"));
    aruba_erm_tree = proto_item_add_subtree(ti, ett_aruba_erm);

    switch(aruba_erm_type){
        case TYPE_PCAP:
            offset = dissect_aruba_erm_pcap(tvb, pinfo, aruba_erm_tree, offset);
            proto_item_set_len(ti, offset);
            eth_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ieee80211_handle, eth_tvb, pinfo, tree);
            break;
        case TYPE_PEEK:
            call_dissector(peek_handle, tvb, pinfo, tree);
            break;
        case TYPE_AIRMAGNET:
            /* Not (yet) supported launch data dissector */
            proto_tree_add_expert(tree, pinfo, &ei_aruba_erm_airmagnet, tvb, offset, -1);
            call_dissector(data_handle, tvb, pinfo, tree);
            break;
        case TYPE_PCAPPLUSRADIO:
            offset = dissect_aruba_erm_pcap(tvb, pinfo, aruba_erm_tree, offset);
            offset = dissect_aruba_erm_pcap_radio(tvb, pinfo, aruba_erm_tree, offset);
            proto_item_set_len(ti, offset);
            eth_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ieee80211_handle, eth_tvb, pinfo, tree);
            break;
        case TYPE_PPI:
            call_dissector(ppi_handle, tvb, pinfo, tree);
            break;
        default:
            break;
    }


}


void
proto_register_aruba_erm(void)
{

    static hf_register_info hf[] = {

        { &hf_aruba_erm_time,
          { "Packet Capture Timestamp", "aruba_erm.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
            0x00, NULL, HFILL }},
        { &hf_aruba_erm_incl_len,
          { "Packet Captured Length", "aruba_erm.incl_len", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL }},
        { &hf_aruba_erm_orig_len,
          { "Packet Length", "aruba_erm.orig_len", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL }},
        { &hf_aruba_erm_data_rate,
          { "Data Rate", "aruba_erm.data_rate", FT_UINT16, BASE_DEC, NULL,
            0x00, "Data rate (1/2 Mb/s)", HFILL }},
        { &hf_aruba_erm_data_rate_gen,
          { "Data Rate", "aruba_erm.data_rate_gen", FT_FLOAT, BASE_NONE, NULL,
            0x00, "Data rate (1/2 Mb/s)", HFILL }},
        { &hf_aruba_erm_channel,
          { "Channel", "aruba_erm.channel", FT_UINT8, BASE_DEC, NULL,
            0x00, "802.11 channel number that this frame was sent/received on", HFILL }},
        { &hf_aruba_erm_signal_strength,
          { "Signal Strength  [percent]", "aruba_erm.signal_strength", FT_UINT8, BASE_DEC, NULL,
            0x00, "Signal strength (Percentage)", HFILL }},
    };

    /* both formats share the same tree */
    static gint *ett[] = {
        &ett_aruba_erm,
    };

    static ei_register_info ei[] = {
        { &ei_aruba_erm_airmagnet, { "aruba_erm.airmagnet", PI_UNDECODED, PI_ERROR, "Airmagnet (type 2) is no yet supported (Please use other type)", EXPFILL }}
    };

    static const enum_val_t aruba_erm_types[] = {
        { "pcap_type_0", "pcap (type 0)", TYPE_PCAP},
        { "peek_type_1", "peek (type1)", TYPE_PEEK},
        { "airmagnet_type_2", "airmagnet (type 2)", TYPE_AIRMAGNET},
        { "pcapplusradio_type_3", "pcap+radio header (type 3)", TYPE_PCAPPLUSRADIO},
        { "ppi_type_4", "ppi (type 4)", TYPE_PPI},
        { NULL, NULL, -1}
    };


    module_t *aruba_erm_module;
    expert_module_t* expert_aruba_erm;

    proto_aruba_erm = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "aruba_erm");

    range_convert_str (&global_aruba_erm_port_range, "0", MAX_UDP_PORT);

    aruba_erm_module = prefs_register_protocol(proto_aruba_erm, proto_reg_handoff_aruba_erm);

    prefs_register_range_preference(aruba_erm_module, "udp.ports", "ARUBA_ERM UDP Port numbers",
                                    "Set the UDP port numbers (typically the range 5555 to 5560) used for ARUBA"
                                    " encapsulated remote mirroring frames;\n"
                                    "0 (default) means that the ARUBA_ERM dissector is not active\n",
                                    &global_aruba_erm_port_range, MAX_UDP_PORT);

    prefs_register_enum_preference(aruba_erm_module, "type.captured",
                       "Type of formats for captured packets",
                       "Type of formats for captured packets",
                       &aruba_erm_type, aruba_erm_types, FALSE);

    proto_register_field_array(proto_aruba_erm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_aruba_erm = expert_register_protocol(proto_aruba_erm);
    expert_register_field_array(expert_aruba_erm, ei, array_length(ei));
}

void
proto_reg_handoff_aruba_erm(void)
{
    static range_t *aruba_erm_port_range;
    static range_t *aruba_erm_radio_port_range;
    static gboolean initialized = FALSE;

    if (!initialized) {
        ieee80211_handle = find_dissector("wlan_withoutfcs");
        ppi_handle = find_dissector("ppi");
        peek_handle = find_dissector("peekremote");
        data_handle = find_dissector("data");
        aruba_erm_handle = create_dissector_handle(dissect_aruba_erm, proto_aruba_erm);
        initialized = TRUE;
    } else {
        dissector_delete_uint_range("udp.port", aruba_erm_port_range, aruba_erm_handle);
        g_free(aruba_erm_port_range);
        g_free(aruba_erm_radio_port_range);
    }

    aruba_erm_port_range = range_copy(global_aruba_erm_port_range);

    dissector_add_uint_range("udp.port", aruba_erm_port_range, aruba_erm_handle);
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
