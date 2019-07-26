/* packet-aruba-erm.c
 * Routines for the disassembly of Aruba encapsulated remote mirroring frames
 * (Adapted from packet-hp-erm.c and packet-cisco-erspan.c)
 *
 * Copyright 2010  Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * ERM Radio-Format added by Hadriel Kaplan
 *
 * Type 6 added by Jeffrey Goff <jgoff at arubanetworks dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See
 *
 *    http://community.arubanetworks.com/t5/Unified-Wired-Wireless-Access/Bug-in-ArubaOS-Packet-Capture/td-p/237984
 *
 *    http://kjspgd.net/?p=30
 *
 * for more information.
 */

/*
 * Formats:
 *
 * Pcap (type 0):
 *
 * Payload contains a pcap record header:
 *
 * typedef struct pcaprec_hdr_s {
 *       guint32 ts_sec;          timestamp seconds
 *       guint32 ts_usec;         timestamp microseconds
 *       guint32 incl_len;        number of octets of packet saved in file
 *       guint32 orig_len;        actual length of packet
 * } pcaprec_hdr_t;
 *
 * followed by the packet data, starting with an 802.11 header.
 *
 * Peek (type 1):
 *
 * Payload contains a "Peek remote" packet, as supported by
 * EtherPeek/AiroPeek/OmniPeek.
 *
 * Airmagnet (type 2):
 *
 * Unknown payload format.
 *
 * Pcap + radio header (type 3):
 *
 * Payload contains a pcap record header, as per the above, followed
 * by a header with radio information:
 *
 *  struct radio_hdr {
 *   __u16  rate_per_half_mhz;
 *   __u8   channel;
 *   __u8   signal_percent;
 *  } __attribute__ ((packed));
 *
 * followed by the packet data, starting with an 802.11 header.
 *
 * PPI (type 4):
 *
 * Payload contains a PPI header followed by the packet data, starting
 * with an 802.11 header.
 *
 * Peek 11n/11ac (type 5):
 *
 * This is probably the "new" "Peek remote" format.  The "Peek remote"
 * dissector should probably be able to distinguish this from type 1,
 * as the "new" format has a magic number in it.  Given that there's
 * a heuristic "Peek remote new" dissector, those packets might
 * automatically be recognized without setting any preference whatsoever.
 *
 * Radiotap (type 6):
 *
 * As part of 802.11ax developement, Aruba has added radiotap capture
 * encapsulation. This new format can be used with any model of AP
 * be it 11ax, 11ac or 11n.
 * Note: type 6 is _only_ supported in ArubaOS 8.6 and higher.
 *
 */

#include "config.h"

#include <wiretap/wtap.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>

#define PROTO_SHORT_NAME "ARUBA_ERM"
#define PROTO_LONG_NAME  "Aruba Networks encapsulated remote mirroring"

#define TYPE_PCAP 0
#define TYPE_PEEK 1
#define TYPE_AIRMAGNET 2
#define TYPE_PCAPPLUSRADIO 3
#define TYPE_PPI 4

#define IS_ARUBA 0x01

#if 0
static const value_string aruba_erm_type_vals[] = {
    { TYPE_PCAP,            "pcap (type 0)" },
    { TYPE_PEEK,            "peek (type 1)" },
    { TYPE_AIRMAGNET,       "Airmagnet (type 2)" },
    { TYPE_PCAPPLUSRADIO,   "pcap + radio header (type 3)" },
    { TYPE_PPI,             "PPI (type 4)" },
    { 0, NULL }
};
#endif

void proto_register_aruba_erm(void);
void proto_reg_handoff_aruba_erm(void);
void proto_reg_handoff_aruba_erm_radio(void);

#if 0
static gint  aruba_erm_type         = 0;
#endif

static int  proto_aruba_erm       = -1;
static int  proto_aruba_erm_type0 = -1;
static int  proto_aruba_erm_type1 = -1;
static int  proto_aruba_erm_type2 = -1;
static int  proto_aruba_erm_type3 = -1;
static int  proto_aruba_erm_type4 = -1;
static int  proto_aruba_erm_type5 = -1;
static int  proto_aruba_erm_type6 = -1;

static int  hf_aruba_erm_time             = -1;
static int  hf_aruba_erm_incl_len         = -1;
static int  hf_aruba_erm_orig_len         = -1;
static int  hf_aruba_erm_data_rate        = -1;
static int  hf_aruba_erm_data_rate_gen    = -1;
static int  hf_aruba_erm_channel          = -1;
static int  hf_aruba_erm_signal_strength  = -1;

static gint ett_aruba_erm = -1;

static expert_field ei_aruba_erm_airmagnet = EI_INIT;
static expert_field ei_aruba_erm_decode = EI_INIT;

static dissector_handle_t aruba_erm_handle;
static dissector_handle_t aruba_erm_handle_type0;
static dissector_handle_t aruba_erm_handle_type1;
static dissector_handle_t aruba_erm_handle_type2;
static dissector_handle_t aruba_erm_handle_type3;
static dissector_handle_t aruba_erm_handle_type4;
static dissector_handle_t aruba_erm_handle_type5;
static dissector_handle_t aruba_erm_handle_type6;
static dissector_handle_t wlan_radio_handle;
static dissector_handle_t wlan_withfcs_handle;
static dissector_handle_t peek_handle;
static dissector_handle_t ppi_handle;
static dissector_handle_t radiotap_handle;

static dissector_table_t aruba_erm_subdissector_table;

static int
dissect_aruba_erm_pcap(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *aruba_erm_tree, gint offset)
{
    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_time, tvb, offset, 8, ENC_TIME_SECS_USECS|ENC_BIG_ENDIAN);
    offset +=8;

    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_incl_len, tvb, 8, 4, ENC_BIG_ENDIAN);
    offset +=4;

    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_orig_len, tvb, 12, 4, ENC_BIG_ENDIAN);
    offset +=4;

    return offset;
}

static proto_tree *
dissect_aruba_erm_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset _U_)
{

    proto_item *ti;
    proto_tree *aruba_erm_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME);


    ti = proto_tree_add_item(tree, proto_aruba_erm, tvb, 0, 0, ENC_NA);
    aruba_erm_tree = proto_item_add_subtree(ti, ett_aruba_erm);

    return aruba_erm_tree;


}


static int
dissect_aruba_erm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    if (!dissector_try_payload(aruba_erm_subdissector_table, tvb, pinfo, tree)) {

        dissect_aruba_erm_common(tvb, pinfo, tree, &offset);
        /* Add Expert info how decode...*/
        proto_tree_add_expert(tree, pinfo, &ei_aruba_erm_decode, tvb, offset, -1);
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}


static int
dissect_aruba_erm_type0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t * next_tvb;
    int offset = 0;
    proto_tree *aruba_erm_tree;

    aruba_erm_tree = dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    offset = dissect_aruba_erm_pcap(tvb, pinfo, aruba_erm_tree, offset);
    proto_item_set_len(aruba_erm_tree, offset);

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    /* No way to determine if TX or RX packet... (TX = no FCS, RX = FCS...)*/
    call_dissector(wlan_withfcs_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int
dissect_aruba_erm_type1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    /* Say to PEEK dissector, it is a Aruba PEEK packet */
    call_dissector_with_data(peek_handle, tvb, pinfo, tree, GUINT_TO_POINTER(IS_ARUBA));

    return tvb_captured_length(tvb);
}

static int
dissect_aruba_erm_type2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    /* Not (yet) supported launch data dissector */
    proto_tree_add_expert(tree, pinfo, &ei_aruba_erm_airmagnet, tvb, offset, -1);
    call_data_dissector(tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int
dissect_aruba_erm_type3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t * next_tvb;
    int offset = 0;
    proto_tree *aruba_erm_tree;
    struct ieee_802_11_phdr phdr;
    guint32 signal_strength;
    proto_item *ti_data_rate;
    guint16 data_rate;
    guint channel;

    aruba_erm_tree = dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    offset = dissect_aruba_erm_pcap(tvb, pinfo, aruba_erm_tree, offset);

    memset(&phdr, 0, sizeof(phdr));
    phdr.decrypted = FALSE;
    phdr.datapad = FALSE;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;
    phdr.has_data_rate = TRUE;
    data_rate = tvb_get_ntohs(tvb, offset);
    phdr.data_rate = data_rate;
    proto_tree_add_item(aruba_erm_tree, hf_aruba_erm_data_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
    ti_data_rate = proto_tree_add_float_format(aruba_erm_tree, hf_aruba_erm_data_rate_gen,
                                                tvb, 16, 2,
                                                (float)data_rate / 2,
                                                "Data Rate: %.1f Mb/s",
                                                (float)data_rate / 2);
    proto_item_set_generated(ti_data_rate);
    offset += 2;

    proto_tree_add_item_ret_uint(aruba_erm_tree, hf_aruba_erm_channel, tvb, offset, 1, ENC_BIG_ENDIAN, &channel);
    phdr.has_channel = TRUE;
    phdr.channel = channel;
    offset += 1;

    proto_tree_add_item_ret_uint(aruba_erm_tree, hf_aruba_erm_signal_strength, tvb, offset, 1, ENC_BIG_ENDIAN, &signal_strength);
    phdr.has_signal_percent = TRUE;
    phdr.signal_percent = signal_strength;
    offset += 1;

    proto_item_set_len(aruba_erm_tree, offset);
    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if(signal_strength == 100){ /* When signal = 100 %, it is TX packet and there is no FCS */
        phdr.fcs_len = 0; /* TX packet, no FCS */
    } else {
        phdr.fcs_len = 4; /* We have an FCS */
    }
    call_dissector_with_data(wlan_radio_handle, next_tvb, pinfo, tree, &phdr);
    return tvb_captured_length(tvb);
}

static int
dissect_aruba_erm_type4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    call_dissector(ppi_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/* Type 5 is the same of type 1 but with Peek Header version = 2, named internaly Peekremote -ng */
static int
dissect_aruba_erm_type5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    /* Say to PEEK dissector, it is a Aruba PEEK  packet */
    call_dissector_with_data(peek_handle, tvb, pinfo, tree, GUINT_TO_POINTER(IS_ARUBA));

    return tvb_captured_length(tvb);
}

static int
dissect_aruba_erm_type6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    dissect_aruba_erm_common(tvb, pinfo, tree, &offset);

    /* Note: In a similar manner to type 3, packets transmitted by the capturing
       AP will be passed with no FCS and a hardcoded 'antenna signal' of -30dBm.
       However, unlike type 3 we don't need to do anything about this because the
       radiotap header flag "FCS at end" will be correctly set to "False" in this case
       which is handled transparently by the radiotap dissector. All other received
       frames are expected to have a FCS and "FCS at end" set to "True".
     */
    call_dissector(radiotap_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static void
aruba_erm_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Aruba ERM payload as");
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
          { "Signal Strength [percent]", "aruba_erm.signal_strength", FT_UINT8, BASE_DEC, NULL,
            0x00, "Signal strength (Percentage)", HFILL }},
    };

    /* both formats share the same tree */
    static gint *ett[] = {
        &ett_aruba_erm,
    };

    static ei_register_info ei[] = {
        { &ei_aruba_erm_airmagnet, { "aruba_erm.airmagnet", PI_UNDECODED, PI_ERROR, "Airmagnet (type 2) is no yet supported (Please use other type)", EXPFILL }},
        { &ei_aruba_erm_decode, { "aruba_erm.decode", PI_UNDECODED, PI_NOTE, "Use Decode AS (Aruba ERM Type) for decoding payload", EXPFILL }}
    };

#if 0
    static const enum_val_t aruba_erm_types[] = {
        { "pcap_type_0", "pcap (type 0)", TYPE_PCAP},
        { "peek_type_1", "peek (type 1)", TYPE_PEEK},
        { "airmagnet_type_2", "Airmagnet (type 2)", TYPE_AIRMAGNET},
        { "pcapplusradio_type_3", "pcap + radio header (type 3)", TYPE_PCAPPLUSRADIO},
        { "ppi_type_4", "PPI (type 4)", TYPE_PPI},
        { NULL, NULL, -1}
    };
#endif

    module_t *aruba_erm_module;

    expert_module_t* expert_aruba_erm;

    proto_aruba_erm = proto_register_protocol(PROTO_LONG_NAME, "ARUBA_ERM" , "aruba_erm");
    proto_aruba_erm_type0 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - PCAP (Type 0)", "ARUBA ERM PCAP (Type 0)", "aruba_erm_type0", proto_aruba_erm, FT_PROTOCOL);
    proto_aruba_erm_type1 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - PEEK (Type 1)", "ARUBA ERM PEEK (type 1)", "aruba_erm_type1", proto_aruba_erm, FT_PROTOCOL);
    proto_aruba_erm_type2 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - AIRMAGNET (Type 2)", "ARUBA ERM AIRMAGNET (Type 2)", "aruba_erm_type2", proto_aruba_erm, FT_PROTOCOL);
    proto_aruba_erm_type3 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - PCAP+RADIO (Type 3)", "ARUBA ERM PCAP+RADIO (Type 3)", "aruba_erm_type3", proto_aruba_erm, FT_PROTOCOL);
    proto_aruba_erm_type4 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - PPI (Type 4)", "ARUBA ERM PPI (Type 4)", "aruba_erm_type4", proto_aruba_erm, FT_PROTOCOL);
    proto_aruba_erm_type5 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - PEEK (Type 5)", "ARUBA ERM PEEK-NG (type 5)", "aruba_erm_type5", proto_aruba_erm, FT_PROTOCOL);
    proto_aruba_erm_type6 = proto_register_protocol_in_name_only("Aruba Networks encapsulated remote mirroring - RADIOTAP (Type 6)", "ARUBA ERM RADIOTAP (type 6)", "aruba_erm_type6", proto_aruba_erm, FT_PROTOCOL);

    aruba_erm_module = prefs_register_protocol(proto_aruba_erm, NULL);

#if 0
    /* Obso...*/
    prefs_register_enum_preference(aruba_erm_module, "type.captured",
                       "Type of formats for captured packets",
                       "Type of formats for captured packets",
                       &aruba_erm_type, aruba_erm_types, FALSE);
#endif
    prefs_register_obsolete_preference(aruba_erm_module, "type.captured");

    proto_register_field_array(proto_aruba_erm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_aruba_erm = expert_register_protocol(proto_aruba_erm);
    expert_register_field_array(expert_aruba_erm, ei, array_length(ei));

    register_dissector("aruba_erm", dissect_aruba_erm, proto_aruba_erm);

    aruba_erm_subdissector_table = register_decode_as_next_proto(proto_aruba_erm, "aruba_erm.type",
                                                                "Aruba ERM Type", aruba_erm_prompt);
}

void
proto_reg_handoff_aruba_erm(void)
{
    wlan_radio_handle = find_dissector_add_dependency("wlan_radio", proto_aruba_erm);
    wlan_withfcs_handle = find_dissector_add_dependency("wlan_withfcs", proto_aruba_erm);
    ppi_handle = find_dissector_add_dependency("ppi", proto_aruba_erm);
    peek_handle = find_dissector_add_dependency("peekremote", proto_aruba_erm);
    radiotap_handle = find_dissector_add_dependency("radiotap", proto_aruba_erm);
    aruba_erm_handle = create_dissector_handle(dissect_aruba_erm, proto_aruba_erm);
    aruba_erm_handle_type0 = create_dissector_handle(dissect_aruba_erm_type0, proto_aruba_erm_type0);
    aruba_erm_handle_type1 = create_dissector_handle(dissect_aruba_erm_type1, proto_aruba_erm_type1);
    aruba_erm_handle_type2 = create_dissector_handle(dissect_aruba_erm_type2, proto_aruba_erm_type2);
    aruba_erm_handle_type3 = create_dissector_handle(dissect_aruba_erm_type3, proto_aruba_erm_type3);
    aruba_erm_handle_type4 = create_dissector_handle(dissect_aruba_erm_type4, proto_aruba_erm_type4);
    aruba_erm_handle_type5 = create_dissector_handle(dissect_aruba_erm_type5, proto_aruba_erm_type5);
    aruba_erm_handle_type6 = create_dissector_handle(dissect_aruba_erm_type6, proto_aruba_erm_type6);

    dissector_add_uint_range_with_preference("udp.port", "", aruba_erm_handle);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type0);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type1);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type2);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type3);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type4);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type5);
    dissector_add_for_decode_as("aruba_erm.type", aruba_erm_handle_type6);
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
