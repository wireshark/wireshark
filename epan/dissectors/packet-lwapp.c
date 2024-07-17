/* packet-lwapp.c
 *
 * Routines for LWAPP encapsulated packet disassembly
 * RFC 5412
 *
 * Copyright (c) 2003 by David Frascone <dave@frascone.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/expert.h>

void proto_register_lwapp(void);
void proto_reg_handoff_lwapp(void);

static dissector_handle_t lwapp_l3_handle;
static dissector_handle_t lwapp_handle;

#define LWAPP_8023_PORT     12220 /* Not IANA registered */
#define LWAPP_UDP_PORT_RANGE  "12222-12223" /* Not IANA registered */

#define LWAPP_FLAGS_T 0x04
#define LWAPP_FLAGS_F 0x02
#define LWAPP_FLAGS_FT 0x01

static int proto_lwapp;
static int proto_lwapp_l3;
static int proto_lwapp_control;
static int ett_lwapp;
static int ett_lwapp_l3;
static int ett_lwapp_flags;
static int ett_lwapp_control;

static int hf_lwapp_version;
static int hf_lwapp_slotid;
static int hf_lwapp_flags;
static int hf_lwapp_flags_type;
static int hf_lwapp_flags_fragment;
static int hf_lwapp_flags_fragment_type;
static int hf_lwapp_fragment_id;
static int hf_lwapp_length;
static int hf_lwapp_rssi;
static int hf_lwapp_snr;
/* static int hf_lwapp_control; */
static int hf_lwapp_control_mac;
static int hf_lwapp_control_type;
static int hf_lwapp_control_seq_no;
static int hf_lwapp_control_length;

#define LWAPP_MAX_NESTED_ENCAP 10

static expert_field ei_lwapp_too_many_encap;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t wlan_handle;
static dissector_handle_t wlan_bsfc_handle;

/* Set by preferences */
static bool swap_frame_control;

typedef struct {
    uint8_t flags;
    uint8_t fragmentId;
    uint16_t length;
    uint8_t rssi;
    uint8_t snr;
} LWAPP_Header;

typedef struct {
    uint8_t  tag;
    uint16_t length;
} CNTL_Data_Header;

typedef struct {
    uint8_t type;
    uint8_t seqNo;
    uint16_t length;
} CNTL_Header;

#if 0
typedef enum {
    RESULT_CODE = 1,
    MWAR_ADDR_PAYLOAD,
    RAD_PAYLOAD,
    RAD_SLOT_PAYLOAD,
    RAD_NAME_PAYLOAD,
    MWAR_PAYLOAD,
    VAP_PAYLOAD,
    STATION_CFG_PAYLOAD,
    OPERATION_RATE_SET_PAYLOAD,
    MULTI_DOMAIN_CAPABILITY_PAYLOAD,
    MAC_OPERATION_PAYLOAD,
    PHY_TX_POWER_PAYLOAD,
    PHY_TX_POWER_LEVEL_PAYLOAD,
    PHY_DSSS_PAYLOAD,
    PHY_OFDM_PAYLOAD,
    SUPPORTED_RATES_PAYLOAD,
    AUTH_PAYLOAD,
    TEST_PAYLOAD,
    RRM_NEIGHBOR_CTRL_PAYLOAD,
    RRM_NOISE_CTRL_PAYLOAD,
    RRM_NOISE_DATA_PAYLOAD,
    RRM_INTERFERENCE_CTRL_PAYLOAD,
    RRM_INTERFERENCE_DATA_PAYLOAD,
    RRM_LOAD_CTRL_PAYLOAD,
    RRM_LOAD_DATA_PAYLOAD,
    CHANGE_STATE_EVENT_PAYLOAD,
    ADMIN_STATE_PAYLOAD,
    DELETE_VAP_PAYLOAD,
    ADD_MOBILE_PAYLOAD,
    DELETE_MOBILE_PAYLOAD
} control_tags;
#endif

typedef enum {
    DISCOVERY_REQUEST = 1,
    DISCOVERY_REPLY,
    JOIN_REQUEST,
    JOIN_REPLY,
    HANDOFF_REQUEST,
    HANDOFF_REPLY,
    HANDOFF_COMMAND,
    HANDOFF_RESPONSE,
    HANDOFF_CONFIRM,
    CONFIGURE_REQUEST,
    CONFIGURE_RESPONSE,
    CONFIGURE_COMMAND,
    CONFIGURE_COMMAND_RES,
    STATISTICS_INFO,
    STATISTICS_INFO_RES,
    CHANGE_STATE_EVENT,
    CHANGE_STATE_EVENT_RES,
    RRM_CONTROL_REQ,
    RRM_CONTROL_RES,
    RRM_DATA_REQ,
    RRM_DATA_RES,
    ECHO_REQUEST,
    ECHO_RESPONSE,
    IMAGE_DATA,
    IMAGE_DATA_RES,
    RESET_REQ,
    RESET_RES,
    I_AM_UP_REQ,
    I_AM_UP_RES,
    KEY_UPDATE_REQ,
    KEY_UPDATE_RES,
    PRIMARY_DISCOVERY_REQ,
    PRIMARY_DISCOVERY_RES,
    DATA_TRANSFER,
    DATA_TRANSFER_RES,
    RESET_REQ_CLEAR_CONFIG
} CNTLMsgType;

static const value_string control_msg_vals[] = {
    {DISCOVERY_REQUEST      , "DISCOVERY_REQUEST"},
    {DISCOVERY_REPLY        , "DISCOVERY_REPLY"},
    {JOIN_REQUEST           , "JOIN_REQUEST"},
    {JOIN_REPLY             , "JOIN_REPLY"},
    {HANDOFF_REQUEST        , "HANDOFF_REQUEST"},
    {HANDOFF_REPLY          , "HANDOFF_REPLY"},
    {HANDOFF_COMMAND        , "HANDOFF_COMMAND"},
    {HANDOFF_RESPONSE       , "HANDOFF_RESPONSE"},
    {HANDOFF_CONFIRM        , "HANDOFF_CONFIRM"},
    {CONFIGURE_REQUEST      , "CONFIGURE_REQUEST"},
    {CONFIGURE_RESPONSE     , "CONFIGURE_RESPONSE"},
    {CONFIGURE_COMMAND      , "CONFIGURE_COMMAND"},
    {CONFIGURE_COMMAND_RES  , "CONFIGURE_COMMAND_RES"},
    {STATISTICS_INFO        , "STATISTICS_INFO"},
    {STATISTICS_INFO_RES    , "STATISTICS_INFO_RES"},
    {CHANGE_STATE_EVENT     , "CHANGE_STATE_EVENT"},
    {CHANGE_STATE_EVENT_RES , "CHANGE_STATE_EVENT_RES"},
    {RRM_CONTROL_REQ        , "RRM_CONTROL_REQ"},
    {RRM_CONTROL_RES        , "RRM_CONTROL_RES"},
    {RRM_DATA_REQ           , "RRM_DATA_REQ"},
    {RRM_DATA_RES           , "RRM_DATA_RES"},
    {ECHO_REQUEST           , "ECHO_REQUEST"},
    {ECHO_RESPONSE          , "ECHO_RESPONSE"},
    {IMAGE_DATA             , "IMAGE_DATA"},
    {IMAGE_DATA_RES         , "IMAGE_DATA_RES"},
    {RESET_REQ              , "RESET_REQ"},
    {RESET_RES              , "RESET_RES"},
    {I_AM_UP_REQ            , "I_AM_UP_REQ"},
    {I_AM_UP_RES            , "I_AM_UP_RES"},
    {KEY_UPDATE_REQ         , "KEY_UPDATE_REQ"},
    {KEY_UPDATE_RES         , "KEY_UPDATE_RES"},
    {PRIMARY_DISCOVERY_REQ  , "PRIMARY_DISCOVERY_REQ"},
    {PRIMARY_DISCOVERY_RES  , "PRIMARY_DISCOVERY_RES"},
    {DATA_TRANSFER          , "DATA_TRANSFER"},
    {DATA_TRANSFER_RES      , "DATA_TRANSFER_RES"},
    {RESET_REQ_CLEAR_CONFIG , "RESET_REQ_CLEAR_CONFIG"},

    { 0, NULL}
};
static value_string_ext control_msg_vals_ext = VALUE_STRING_EXT_INIT(control_msg_vals);

#if 0
static const value_string control_tag_vals[] = {

    {RESULT_CODE                     , "RESULT_CODE"},
    {MWAR_ADDR_PAYLOAD               , "MWAR_ADDR_PAYLOAD"},
    {RAD_PAYLOAD                     , "RAD_PAYLOAD"},
    {RAD_SLOT_PAYLOAD                , "RAD_SLOT_PAYLOAD"},
    {RAD_NAME_PAYLOAD                , "RAD_NAME_PAYLOAD"},
    {MWAR_PAYLOAD                    , "MWAR_PAYLOAD"},
    {VAP_PAYLOAD                     , "VAP_PAYLOAD"},
    {STATION_CFG_PAYLOAD             , "STATION_CFG_PAYLOAD"},
    {OPERATION_RATE_SET_PAYLOAD      , "OPERATION_RATE_SET_PAYLOAD"},
    {MULTI_DOMAIN_CAPABILITY_PAYLOAD , "MULTI_DOMAIN_CAPABILITY_PAYLOAD"},
    {MAC_OPERATION_PAYLOAD           , "MAC_OPERATION_PAYLOAD"},
    {PHY_TX_POWER_PAYLOAD            , "PHY_TX_POWER_PAYLOAD"},
    {PHY_TX_POWER_LEVEL_PAYLOAD      , "PHY_TX_POWER_LEVEL_PAYLOAD"},
    {PHY_DSSS_PAYLOAD                , "PHY_DSSS_PAYLOAD"},
    {PHY_OFDM_PAYLOAD                , "PHY_OFDM_PAYLOAD"},
    {SUPPORTED_RATES_PAYLOAD         , "SUPPORTED_RATES_PAYLOAD"},
    {AUTH_PAYLOAD                    , "AUTH_PAYLOAD"},
    {TEST_PAYLOAD                    , "TEST_PAYLOAD"},
    {RRM_NEIGHBOR_CTRL_PAYLOAD       , "RRM_NEIGHBOR_CTRL_PAYLOAD"},
    {RRM_NOISE_CTRL_PAYLOAD          , "RRM_NOISE_CTRL_PAYLOAD"},
    {RRM_NOISE_DATA_PAYLOAD          , "RRM_NOISE_DATA_PAYLOAD"},
    {RRM_INTERFERENCE_CTRL_PAYLOAD   , "RRM_INTERFERENCE_CTRL_PAYLOAD"},
    {RRM_INTERFERENCE_DATA_PAYLOAD   , "RRM_INTERFERENCE_DATA_PAYLOAD"},
    {RRM_LOAD_CTRL_PAYLOAD           , "RRM_LOAD_CTRL_PAYLOAD"},
    {RRM_LOAD_DATA_PAYLOAD           , "RRM_LOAD_DATA_PAYLOAD"},
    {CHANGE_STATE_EVENT_PAYLOAD      , "CHANGE_STATE_EVENT_PAYLOAD"},
    {ADMIN_STATE_PAYLOAD             , "ADMIN_STATE_PAYLOAD"},
    {DELETE_VAP_PAYLOAD              , "DELETE_VAP_PAYLOAD"},
    {ADD_MOBILE_PAYLOAD              , "ADD_MOBILE_PAYLOAD"},
    {DELETE_MOBILE_PAYLOAD           , "DELETE_MOBILE_PAYLOAD"},
    {0, NULL}
};
static value_string_ext control_tag_vals_ext = VALUE_STRING_EXT_INIT(control_tag_vals);
#endif

static const true_false_string lwapp_flags_type = {
    "LWAPP Control Packet" ,
    "Encapsulated 80211"
};

/*
 * dissect lwapp control packets.  This is not fully implemented,
 * but it's a good start.
 */
static void
dissect_control(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree)
{
    CNTL_Header  header;
    proto_tree  *control_tree;
    tvbuff_t    *next_tvb;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item      *ti;
    int              offset=0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWAPP");
    col_set_str(pinfo->cinfo, COL_INFO,
                    "CNTL ");

    /* Copy our header */
    tvb_memcpy(tvb, (uint8_t*) &header, offset, sizeof(header));

    /*
     * Fix the length (network byte ordering), and set our version &
     * slot id
     */
    header.length = g_ntohs(header.length);

    col_append_str(pinfo->cinfo, COL_INFO,
        val_to_str_ext(header.type, &control_msg_vals_ext, "Bad Type: 0x%02x"));

    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_lwapp_control, tvb, offset,
                                 -1, ENC_NA);
        control_tree = proto_item_add_subtree(ti, ett_lwapp_control);

        proto_tree_add_uint(control_tree, hf_lwapp_control_type,
                               tvb, offset, 1, header.type);
        offset++;

        proto_tree_add_uint(control_tree, hf_lwapp_control_seq_no,
                               tvb, offset, 1, header.seqNo);
        offset++;

        proto_tree_add_uint(control_tree, hf_lwapp_control_length,
                               tvb, offset, 2, header.length);
        offset += 2;

        /* Dissect rest of packet as data */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, tree);
    }

} /* dissect_control */

/*
 * This lwapp dissector assumes that there is an 802.3 header at
 * the start of the packet, so it simply re-calls the ethernet
 * dissector on the packet.
 */
static int
dissect_lwapp_l3(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void* data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *lwapp_tree;
    int         offset = 0;
    tvbuff_t   *next_client;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWAPP-L3");
    col_set_str(pinfo->cinfo, COL_INFO, "802.3 Packets over Layer 3");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_lwapp_l3, tvb, offset,
                                -1, ENC_NA);
    lwapp_tree = proto_item_add_subtree(ti, ett_lwapp_l3);

    /* Dissect as Ethernet */
    next_client = tvb_new_subset_remaining(tvb, 0);
    call_dissector(eth_withoutfcs_handle, next_client, pinfo, lwapp_tree);

    return tvb_captured_length(tvb);

} /* dissect_lwapp_l3*/


/*
 * This dissector dissects the lwapp protocol itself.  It assumes an
 * lwapp payload in the data, and doesn't care whether the data was
 * from a UDP packet, or a Layer 2 one.
 */
static int
dissect_lwapp(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree, void* data _U_)
{
    LWAPP_Header header;
    uint8_t      slotId;
    uint8_t      version;
    proto_tree  *lwapp_tree;
    tvbuff_t    *next_client;
    uint8_t      dest_mac[6];
    uint8_t      have_destmac=0;
    static int * const flags[] = {
        &hf_lwapp_flags_type,
        &hf_lwapp_flags_fragment,
        &hf_lwapp_flags_fragment_type,
        NULL
    };
    unsigned encap_nested_count;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item      *ti;
    int              offset=0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWAPP");
    col_set_str(pinfo->cinfo, COL_INFO,
                    "LWAPP IP or Layer 2");

    /* First, set up our dest mac, if we're a control packet with a
     * dest of port 12223 */
    if (pinfo->destport == 12223 ) {
        tvb_memcpy(tvb, dest_mac, offset, 6);
        have_destmac = 1;

        /* Copy our header */
        tvb_memcpy(tvb, (uint8_t*) &header, offset + 6, sizeof(header));
    } else {

        /* Copy our header */
        tvb_memcpy(tvb, (uint8_t*) &header, offset, sizeof(header));
    }


    /*
     * Fix the length (network byte ordering), and set our version &
     * slot id
     */
    header.length = g_ntohs(header.length);
    version = (header.flags & 0xc0) >> 6;
    slotId = (header.flags & 0x38) >> 3;

    if ((header.flags & LWAPP_FLAGS_T) != 0)
        col_append_str(pinfo->cinfo, COL_INFO,
                        " Control Packet");
    else
        col_append_str(pinfo->cinfo, COL_INFO,
                        " 802.11 Packet");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_lwapp, tvb, offset, -1, ENC_NA);
    encap_nested_count = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_lwapp, 0));
    if (++encap_nested_count > LWAPP_MAX_NESTED_ENCAP) {
        expert_add_info(pinfo, ti, &ei_lwapp_too_many_encap);
        return tvb_captured_length(tvb);
    }
    p_add_proto_data(pinfo->pool, pinfo, proto_lwapp, 0, GUINT_TO_POINTER(encap_nested_count));

    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {

        lwapp_tree = proto_item_add_subtree(ti, ett_lwapp);

        if (have_destmac) {
            proto_tree_add_ether(lwapp_tree, hf_lwapp_control_mac, tvb, offset,
                         6, dest_mac);
            offset += 6;
        }

        proto_tree_add_uint(lwapp_tree, hf_lwapp_version,
                               tvb, offset, 1, version);
        proto_tree_add_uint(lwapp_tree, hf_lwapp_slotid,
                               tvb, offset, 1, slotId);

        proto_tree_add_bitmask(lwapp_tree, tvb, offset, hf_lwapp_flags, ett_lwapp_flags, flags, ENC_NA);
        offset++;

        proto_tree_add_uint(lwapp_tree, hf_lwapp_fragment_id,
                               tvb, offset, 1, header.fragmentId);
        offset++;

        proto_tree_add_uint(lwapp_tree, hf_lwapp_length,
                               tvb, offset, 2, header.length);
        offset += 2;

        proto_tree_add_uint(lwapp_tree, hf_lwapp_rssi,
                               tvb, offset, 1, header.rssi);
        offset++;
        proto_tree_add_uint(lwapp_tree, hf_lwapp_snr,
                               tvb, offset, 1, header.snr);
        offset++;


    }  /* tree */

    next_client = tvb_new_subset_remaining(tvb, (have_destmac?6:0) + (int)sizeof(LWAPP_Header));
    if ((header.flags & LWAPP_FLAGS_T) == 0) {
        call_dissector(swap_frame_control ? wlan_bsfc_handle : wlan_handle,
                       next_client, pinfo, tree);
    } else {
        dissect_control(next_client, pinfo, tree);
    }
    return tvb_captured_length(tvb);

} /* dissect_lwapp*/

/* registration with the filtering engine */
void
proto_register_lwapp(void)
{
    static hf_register_info hf[] = {
        { &hf_lwapp_version,
          { "Version", "lwapp.version", FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
        { &hf_lwapp_slotid,
          { "slotId","lwapp.slotId", FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_lwapp_flags,
          { "Flags", "lwapp.flags", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_lwapp_flags_type,
          { "Type", "lwapp.flags.type", FT_BOOLEAN, 8,
            TFS(&lwapp_flags_type), LWAPP_FLAGS_T, NULL, HFILL }},
        { &hf_lwapp_flags_fragment,
          { "Fragment", "lwapp.flags.fragment", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), LWAPP_FLAGS_F,
            NULL, HFILL }},
        { &hf_lwapp_flags_fragment_type,
          { "Fragment Type", "lwapp.flags.fragmentType", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), LWAPP_FLAGS_FT,
            NULL, HFILL }},
        { &hf_lwapp_fragment_id,
          { "Fragment Id","lwapp.fragmentId", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_lwapp_length,
          { "Length","lwapp.Length", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_lwapp_rssi,
          { "RSSI","lwapp.rssi", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_lwapp_snr,
          { "SNR","lwapp.snr", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
#if 0
        { &hf_lwapp_control,
          { "Control Data (not dissected yet)","lwapp.control", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
#endif
        { &hf_lwapp_control_mac,
          { "AP Identity", "lwapp.apid", FT_ETHER, BASE_NONE, NULL, 0x0,
              "Access Point Identity", HFILL }},
        { &hf_lwapp_control_type,
          { "Control Type", "lwapp.control.type", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &control_msg_vals_ext, 0x00,
            NULL, HFILL }},
        { &hf_lwapp_control_seq_no,
          { "Control Sequence Number", "lwapp.control.seqno", FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
        { &hf_lwapp_control_length,
          { "Control Length","lwapp.control.length", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_lwapp_l3,
        &ett_lwapp,
        &ett_lwapp_control,
        &ett_lwapp_flags
    };
    static ei_register_info ei[] = {
        { &ei_lwapp_too_many_encap, { "lwapp.too_many_encap", PI_UNDECODED, PI_WARN, "Too many LWAPP encapsulation levels", EXPFILL }}
    };
    module_t *lwapp_module;
    expert_module_t* expert_lwapp;

    proto_lwapp = proto_register_protocol ("LWAPP Encapsulated Packet", "LWAPP", "lwapp");

    proto_lwapp_l3 = proto_register_protocol_in_name_only ("LWAPP Layer 3 Packet", "LWAPP-L3", "lwapp-l3", proto_lwapp, FT_PROTOCOL);

    proto_lwapp_control = proto_register_protocol_in_name_only ("LWAPP Control Message", "LWAPP-CNTL", "lwapp-cntl", proto_lwapp, FT_PROTOCOL);
    proto_register_field_array(proto_lwapp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lwapp = expert_register_protocol(proto_lwapp);
    expert_register_field_array(expert_lwapp, ei, array_length(ei));

    lwapp_module = prefs_register_protocol(proto_lwapp, NULL);

    prefs_register_bool_preference(lwapp_module,"swap_fc","Swap Frame Control",
                                   "Swap frame control bytes (needed for some APs).",
                                   &swap_frame_control);

    /* This dissector assumes lwapp packets in an 802.3 frame */
    lwapp_l3_handle = register_dissector("lwapp-l3", dissect_lwapp_l3, proto_lwapp_l3);

    /* This dissector assumes a lwapp packet */
    lwapp_handle = register_dissector("lwapp", dissect_lwapp, proto_lwapp);
}

void
proto_reg_handoff_lwapp(void)
{
    /*
     * Get handles for the Ethernet and wireless dissectors.
     */
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_lwapp);
    wlan_handle = find_dissector_add_dependency("wlan_withoutfcs", proto_lwapp);
    wlan_bsfc_handle = find_dissector_add_dependency("wlan_bsfc", proto_lwapp);

    /*
     * Ok, the following deserves some comments.  We have four
     * different ways lwapp can appear on the wire.  Mostly, this is
     * because lwapp is such a new protocol.
     *
     * First, lwapp can join on multiple udp ports, as encapsulated
     * packets on top of UDP.  In this case, there is a full raw
     * ethernet frame inside of the UDP packet.  This method is
     * becoming obscelete, but we still wanted to dissect the
     * packets.
     *
     * Next, lwapp can be over UDP, but packaged for L3 tunneling.  This
     * is the new-style.  In this case, LWAP headers are just transmitted
     * via UDP.
     *
     * The last method is lwapp directly over layer 2.  For this, we
     * dissect two different ethertypes (until IANA gives us one)
     *
     */

    /* Obsoleted LWAPP via encapsulated 802.3 over UDP */
    dissector_add_uint_with_preference("udp.port", LWAPP_8023_PORT, lwapp_l3_handle);

    /* new-style lwapp directly over UDP: L3-lwapp*/
    dissector_add_uint_range_with_preference("udp.port", LWAPP_UDP_PORT_RANGE, lwapp_handle);

    /* Lwapp over L2 */
    dissector_add_uint("ethertype", 0x88bb, lwapp_handle);
    dissector_add_uint("ethertype", 0xbbbb, lwapp_handle);

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
