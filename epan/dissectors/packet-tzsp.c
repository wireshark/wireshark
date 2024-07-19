/* packet-tzsp.c
 *
 * Copyright 2002, Tazmen Technologies Inc
 *
 * Tazmen Sniffer Protocol for encapsulating the packets across a network
 * from a remote packet sniffer. TZSP can encapsulate any other protocol.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

/*
 * See
 *
 *  http://web.archive.org/web/20050404125022/http://www.networkchemistry.com/support/appnotes/an001_tzsp.html
 *
 * for a description of the protocol.
 */

#define UDP_PORT_TZSP   0x9090 /* Not IANA registered */

void proto_register_tzsp(void);
void proto_reg_handoff_tzsp(void);

static int proto_tzsp;
static int hf_tzsp_version;
static int hf_tzsp_type;
static int hf_tzsp_encap;

static dissector_table_t tzsp_encap_table;

static dissector_handle_t tzsp_handle;

/*
 * Packet types.
 */
#define TZSP_RX_PACKET  0   /* Packet received from the sensor */
#define TZSP_TX_PACKET  1   /* Packet for the sensor to transmit */
#define TZSP_CONFIG     3   /* Configuration information for the sensor */
#define TZSP_NULL       4   /* Null frame, used as a keepalive */
#define TZSP_PORT       5   /* Port opener - opens a NAT tunnel */

static const value_string tzsp_type[] = {
    {TZSP_RX_PACKET,  "Received packet"},
    {TZSP_TX_PACKET,  "Packet for transmit"},
    {TZSP_CONFIG,     "Configuration"},
    {TZSP_NULL,       "Keepalive"},
    {TZSP_PORT,       "Port opener"},
    {0, NULL}
};

/* ************************************************************************* */
/*                        Encapsulation type values                          */
/*               Note that these are not all the same as DLT_ values         */
/* ************************************************************************* */

#define TZSP_ENCAP_ETHERNET                1
#define TZSP_ENCAP_TOKEN_RING              2
#define TZSP_ENCAP_SLIP                    3
#define TZSP_ENCAP_PPP                     4
#define TZSP_ENCAP_FDDI                    5
#define TZSP_ENCAP_RAW                     7   /* "Raw UO", presumably meaning "Raw IP" */
#define TZSP_ENCAP_IEEE_802_11             18
#define TZSP_ENCAP_IEEE_802_11_PRISM       119
#define TZSP_ENCAP_IEEE_802_11_RADIOTAP    126
#define TZSP_ENCAP_IEEE_802_11_AVS         127

/*
 * Packet encapsulations.
 */
static const value_string tzsp_encapsulation[] = {
    {TZSP_ENCAP_ETHERNET,             "Ethernet"},
    {TZSP_ENCAP_TOKEN_RING,           "Token Ring"},
    {TZSP_ENCAP_SLIP,                 "SLIP"},
    {TZSP_ENCAP_PPP,                  "PPP"},
    {TZSP_ENCAP_FDDI,                 "FDDI"},
    {TZSP_ENCAP_RAW,                  "Raw IP"},
    {TZSP_ENCAP_IEEE_802_11,          "IEEE 802.11"},
    {TZSP_ENCAP_IEEE_802_11_PRISM,    "IEEE 802.11 with Prism headers"},
    {TZSP_ENCAP_IEEE_802_11_RADIOTAP, "IEEE 802.11 with radiotap headers"},
    {TZSP_ENCAP_IEEE_802_11_AVS,      "IEEE 802.11 with AVS headers"},
    {0, NULL}
};

static int ett_tzsp;
static int ett_tag;

/* ************************************************************************* */
/*                WLAN radio header fields                                    */
/* ************************************************************************* */

static int hf_option_tag;
static int hf_option_length;
/* static int hf_status_field; */
static int hf_status_msg_type;
static int hf_status_pcf;
/* static int hf_status_mac_port; */
static int hf_status_undecrypted;
static int hf_status_fcs_error;

static int hf_time;
static int hf_silence;
static int hf_signal;
static int hf_rate;
static int hf_channel;
static int hf_unknown;
static int hf_original_length;
static int hf_sensormac;

static int hf_device_name;
static int hf_capture_location;
static int hf_capture_info;
static int hf_capture_id;
static int hf_time_stamp;
static int hf_packet_id;



/* ************************************************************************* */
/*                          Generic header options                           */
/* ************************************************************************* */

#define TZSP_HDR_PAD               0  /* Pad. */
#define TZSP_HDR_END               1  /* End of the list. */
#define TZSP_WLAN_STA             30  /* Station statistics */
#define TZSP_WLAN_PKT             31  /* Packet statistics */
#define TZSP_PACKET_ID            40  /* Unique ID of the packet */
#define TZSP_HDR_ORIGINAL_LENGTH  41  /* Length of the packet before slicing. 2 bytes. */
#define TZSP_HDR_SENSOR           60  /* Sensor MAC address packet was received on, 6 byte ethernet address.*/

#define TZSP_DEVICE_NAME          80
#define TZSP_CAPTURE_LOCATION     81
#define TZSP_TIME_STAMP           82
#define TZSP_INFO                 83  /* Addition TZSP Information; String type*/
#define TZSP_CAPTURE_ID           84  /* Capture Instance ID; 32 bits unsigned integer */




/* ************************************************************************* */
/*                          Options for 802.11 radios                        */
/* ************************************************************************* */

#define WLAN_RADIO_HDR_SIGNAL     10  /* Signal strength in dBm, signed byte. */
#define WLAN_RADIO_HDR_NOISE      11  /* Noise level in dBm, signed byte. */
#define WLAN_RADIO_HDR_RATE       12  /* Data rate, unsigned byte. */
#define WLAN_RADIO_HDR_TIMESTAMP  13  /* Timestamp in us, unsigned 32-bits network byte order. */
#define WLAN_RADIO_HDR_MSG_TYPE   14  /* Packet type, unsigned byte. */
#define WLAN_RADIO_HDR_CF         15  /* Whether packet arrived during CF period, unsigned byte. */
#define WLAN_RADIO_HDR_UN_DECR    16  /* Whether packet could not be decrypted by MAC, unsigned byte. */
#define WLAN_RADIO_HDR_FCS_ERR    17  /* Whether packet contains an FCS error, unsigned byte. */
#define WLAN_RADIO_HDR_CHANNEL    18  /* Channel number packet was received on, unsigned byte.*/

static const value_string option_tag_vals[] = {
    {TZSP_HDR_PAD,  "Pad"},
    {TZSP_HDR_END,  "End"},
    {TZSP_PACKET_ID,  "packet ID"},
    {TZSP_HDR_ORIGINAL_LENGTH,  "Original Length"},
    {TZSP_DEVICE_NAME,  "Device Name"},
    {TZSP_CAPTURE_LOCATION,  "Capture Location"},
    {TZSP_TIME_STAMP,  "Time Stamp"},
    {TZSP_INFO, "Information"},
    {TZSP_CAPTURE_ID, "Capture ID"},
    {WLAN_RADIO_HDR_SIGNAL,     "Signal"},
    {WLAN_RADIO_HDR_NOISE,      "Silence"},
    {WLAN_RADIO_HDR_RATE,       "Rate"},
    {WLAN_RADIO_HDR_TIMESTAMP,  "Time"},
    {WLAN_RADIO_HDR_MSG_TYPE,   "Message Type"},
    {WLAN_RADIO_HDR_CF,         "Point Coordination Function"},
    {WLAN_RADIO_HDR_UN_DECR,    "Undecrypted"},
    {WLAN_RADIO_HDR_FCS_ERR,    "Frame check sequence"},
    {WLAN_RADIO_HDR_CHANNEL,    "Channel"},
    {TZSP_HDR_SENSOR,           "Sensor MAC"},
    {0, NULL}
};


/* ************************************************************************* */
/*                Add option information to the display                      */
/* ************************************************************************* */

static int
add_option_info(tvbuff_t *tvb, int pos, proto_tree *tree, proto_item *ti)
{
    uint8_t     tag, length, fcs_err = 0, encr = 0, seen_fcs_err = 0;
    proto_tree *tag_tree;

    /*
     * Read all option tags in an endless loop. If the packet is malformed this
     * loop might be a problem.
     */
    while (true) {
        tag = tvb_get_uint8(tvb, pos);
        if ((tag != TZSP_HDR_PAD) && (tag != TZSP_HDR_END)) {
            length = tvb_get_uint8(tvb, pos+1);
            tag_tree = proto_tree_add_subtree(tree, tvb, pos, 2+length, ett_tag, NULL, val_to_str_const(tag, option_tag_vals, "Unknown"));
        } else {
            tag_tree = proto_tree_add_subtree(tree, tvb, pos, 1, ett_tag, NULL, val_to_str_const(tag, option_tag_vals, "Unknown"));
            length = 0;
        }

        proto_tree_add_item(tag_tree, hf_option_tag, tvb, pos, 1, ENC_BIG_ENDIAN);
        pos++;
        if ((tag != TZSP_HDR_PAD) && (tag != TZSP_HDR_END)) {
            proto_tree_add_item(tag_tree, hf_option_length, tvb, pos, 1, ENC_BIG_ENDIAN);
            pos++;
        }

        switch (tag) {
        case TZSP_HDR_PAD:
            break;

        case TZSP_HDR_END:
            /* Fill in header with information from other tags. */
            if (seen_fcs_err) {
                proto_item_append_text(ti,"%s", fcs_err?"FCS Error":(encr?"Encrypted":"Good"));
            }
            return pos;

        case TZSP_PACKET_ID:
            proto_tree_add_item(tag_tree, hf_packet_id, tvb, pos, 4, ENC_BIG_ENDIAN);
            break;

        case TZSP_HDR_ORIGINAL_LENGTH:
            proto_tree_add_item(tag_tree, hf_original_length, tvb, pos, 2, ENC_BIG_ENDIAN);
            break;

        case TZSP_DEVICE_NAME:
            proto_tree_add_item(tag_tree, hf_device_name, tvb, pos, length, ENC_ASCII);
            break;

        case TZSP_CAPTURE_LOCATION:
            proto_tree_add_item(tag_tree, hf_capture_location, tvb, pos, length, ENC_ASCII);
            break;

        case TZSP_INFO:
            proto_tree_add_item(tag_tree, hf_capture_info, tvb, pos, length, ENC_ASCII);
            break;

        case TZSP_CAPTURE_ID:
            proto_tree_add_item(tag_tree, hf_capture_id, tvb, pos, 4, ENC_BIG_ENDIAN);
            break;

        case TZSP_TIME_STAMP:
            proto_tree_add_item(tag_tree, hf_time_stamp, tvb, pos, length, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
            break;


        case WLAN_RADIO_HDR_SIGNAL:
            proto_tree_add_item(tag_tree, hf_signal, tvb, pos, 1, ENC_BIG_ENDIAN);
            break;

        case WLAN_RADIO_HDR_NOISE:
            proto_tree_add_item(tag_tree, hf_silence, tvb, pos, 1, ENC_BIG_ENDIAN);
            break;

        case WLAN_RADIO_HDR_RATE:
            proto_tree_add_item(tag_tree, hf_rate, tvb, pos, 1, ENC_BIG_ENDIAN);
            break;

        case WLAN_RADIO_HDR_TIMESTAMP:
            proto_tree_add_item(tag_tree, hf_time, tvb, pos, 4, ENC_BIG_ENDIAN);
            break;

        case WLAN_RADIO_HDR_MSG_TYPE:
            proto_tree_add_item(tag_tree, hf_status_msg_type, tvb, pos, 1, ENC_BIG_ENDIAN);
            break;

        case WLAN_RADIO_HDR_CF:
            proto_tree_add_item(tag_tree, hf_status_pcf, tvb, pos, 1, ENC_NA);
            break;

        case WLAN_RADIO_HDR_UN_DECR:
            proto_tree_add_item(tag_tree, hf_status_undecrypted, tvb, pos, 1, ENC_NA);
            encr = tvb_get_uint8(tvb, pos);
            break;

        case WLAN_RADIO_HDR_FCS_ERR:
            seen_fcs_err = 1;
            proto_tree_add_item(tag_tree, hf_status_fcs_error, tvb, pos, 1, ENC_NA);
            fcs_err = tvb_get_uint8(tvb, pos);
            break;

        case WLAN_RADIO_HDR_CHANNEL:
            proto_tree_add_item(tag_tree, hf_channel, tvb, pos, length, ENC_BIG_ENDIAN);
            break;

        case TZSP_HDR_SENSOR:
            proto_tree_add_item(tag_tree, hf_sensormac, tvb, pos, 6, ENC_NA);
            break;

        default:
            proto_tree_add_item(tag_tree, hf_unknown, tvb, pos, length, ENC_NA);
            break;
        }

        pos += length;
    }
}

/* ************************************************************************* */
/*                Dissect a TZSP packet                                      */
/* ************************************************************************* */

static int
dissect_tzsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree         *tzsp_tree     = NULL;
    proto_item         *ti            = NULL;
    int                 pos           = 0;
    tvbuff_t           *next_tvb;
    uint16_t            encapsulation = 0;
    const char         *info;
    uint8_t             type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TZSP");
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_uint8(tvb, 1);

    /* Find the encapsulation. */
    encapsulation = tvb_get_ntohs(tvb, 2);
    info = val_to_str(encapsulation, tzsp_encapsulation, "Unknown (%u)");

    col_add_str(pinfo->cinfo, COL_INFO, info);

    if (tree) {
        /* Adding TZSP item and subtree */
        ti = proto_tree_add_protocol_format(tree, proto_tzsp, tvb, 0,
            -1, "TZSP: %s ", info);
        tzsp_tree = proto_item_add_subtree(ti, ett_tzsp);

        proto_tree_add_item (tzsp_tree, hf_tzsp_version, tvb, 0, 1,
                    ENC_BIG_ENDIAN);
        proto_tree_add_uint (tzsp_tree, hf_tzsp_type, tvb, 1, 1,
                    type);
        proto_tree_add_uint (tzsp_tree, hf_tzsp_encap, tvb, 2, 2,
                    encapsulation);
    }

    /*
     * XXX - what about TZSP_CONFIG frames?
     *
     * The MIB at
     *
     *  http://web.archive.org/web/20021221195733/http://www.networkchemistry.com/support/appnotes/SENSOR-MIB
     *
     * seems to indicate that you can configure the probe using SNMP;
     * does TZSP_CONFIG also support that?  An old version of Kismet
     * included code to control a Network Chemistry WSP100 sensor:
     *
     *  https://www.kismetwireless.net/code-old/svn/tags/kismet-2004-02-R1/wsp100source.cc
     *
     * and it used SNMP to configure the probe.
     */
    if ((type != TZSP_NULL) && (type != TZSP_PORT)) {
        pos = add_option_info(tvb, 4, tzsp_tree, ti);

        if (tree)
            proto_item_set_end(ti, tvb, pos);
        next_tvb = tvb_new_subset_remaining(tvb, pos);
        if (dissector_try_uint(tzsp_encap_table, encapsulation, next_tvb, pinfo, tree) == 0) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
            col_add_fstr(pinfo->cinfo, COL_INFO, "TZSP_ENCAP = %u",
                    encapsulation);
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

/* ************************************************************************* */
/*                Register the TZSP dissector                                */
/* ************************************************************************* */

void
proto_register_tzsp(void)
{
    static const value_string msg_type[] = {
        {0, "Normal"},
        {1, "RFC1042 encoded"},
        {2, "Bridge-tunnel encoded"},
        {4, "802.11 management frame"},
        {0, NULL}
    };

    static const true_false_string pcf_flag = {
        "CF: Frame received during CF period",
        "Not CF"
    };

    static const true_false_string undecr_flag = {
        "Encrypted frame could not be decrypted",
        "Unencrypted"
    };

    static const true_false_string fcs_err_flag = {
        "FCS error, frame is corrupted",
        "Frame is valid"
    };

    static const value_string channels[] = {
        /* 802.11b/g */
        {  1, "1 (2.412 GHz)"},
        {  2, "2 (2.417 GHz)"},
        {  3, "3 (2.422 GHz)"},
        {  4, "4 (2.427 GHz)"},
        {  5, "5 (2.432 GHz)"},
        {  6, "6 (2.437 GHz)"},
        {  7, "7 (2.442 GHz)"},
        {  8, "8 (2.447 GHz)"},
        {  9, "9 (2.452 GHz)"},
        { 10, "10 (2.457 GHz)"},
        { 11, "11 (2.462 GHz)"},
        { 12, "12 (2.467 GHz)"},
        { 13, "13 (2.472 GHz)"},
        { 14, "14 (2.484 GHz)"},
        /* 802.11a */
        { 36, "36 (5.180 GHz)"},
        { 40, "40 (5.200 GHz)"},
        { 44, "44 (5.220 GHz)"},
        { 48, "48 (5.240 GHz)"},
        { 52, "52 (5.260 GHz)"},
        { 56, "56 (5.280 GHz)"},
        { 60, "60 (5.300 GHz)"},
        { 64, "64 (5.320 GHz)"},
        {149, "149 (5.745 GHz)"},
        {153, "153 (5.765 GHz)"},
        {157, "157 (5.785 GHz)"},
        {161, "161 (5.805 GHz)"},
        /* 802.11ax */
        {191, "191 (5.955 GHz)"},
        {195, "195 (5.975 GHz)"},
        {199, "199 (5.995 GHz)"},
        {203, "203 (6.015 GHz)"},
        {207, "207 (6.035 GHz)"},
        {211, "211 (6.055 GHz)"},
        {215, "215 (6.075 GHz)"},
        {219, "219 (6.095 GHz)"},
        {223, "223 (6.115 GHz)"},
        {227, "227 (6.135 GHz)"},
        {231, "231 (6.155 GHz)"},
        {235, "235 (6.175 GHz)"},
        {239, "239 (6.195 GHz)"},
        {243, "243 (6.215 GHz)"},
        {247, "247 (6.235 GHz)"},
        {251, "251 (6.255 GHz)"},
        {255, "255 (6.275 GHz)"},
        {259, "259 (6.295 GHz)"},
        {263, "263 (6.315 GHz)"},
        {267, "267 (6.335 GHz)"},
        {271, "271 (6.355 GHz)"},
        {275, "275 (6.375 GHz)"},
        {279, "279 (6.395 GHz)"},
        {283, "283 (6.415 GHz)"},
        {287, "287 (6.435 GHz)"},
        {291, "291 (6.455 GHz)"},
        {295, "295 (6.475 GHz)"},
        {299, "299 (6.495 GHz)"},
        {303, "303 (6.515 GHz)"},
        {307, "307 (6.535 GHz)"},
        {311, "311 (6.555 GHz)"},
        {315, "315 (6.575 GHz)"},
        {319, "319 (6.595 GHz)"},
        {323, "323 (6.615 GHz)"},
        {327, "327 (6.635 GHz)"},
        {331, "331 (6.655 GHz)"},
        {335, "335 (6.675 GHz)"},
        {339, "339 (6.695 GHz)"},
        {343, "343 (6.715 GHz)"},
        {347, "347 (6.735 GHz)"},
        {351, "351 (6.755 GHz)"},
        {355, "355 (6.775 GHz)"},
        {359, "359 (6.795 GHz)"},
        {363, "363 (6.815 GHz)"},
        {367, "367 (6.835 GHz)"},
        {371, "371 (6.855 GHz)"},
        {375, "375 (6.875 GHz)"},
        {379, "379 (6.895 GHz)"},
        {383, "383 (6.915 GHz)"},
        {387, "387 (6.935 GHz)"},
        {391, "391 (6.955 GHz)"},
        {395, "395 (6.975 GHz)"},
        {399, "399 (6.995 GHz)"},
        {403, "403 (7.015 GHz)"},
        {407, "407 (7.035 GHz)"},
        {411, "411 (7.055 GHz)"},
        {415, "415 (7.075 GHz)"},
        {419, "419 (7.095 GHz)"},
        {423, "423 (7.115 GHz)"},
        {0, NULL}
    };

    static const value_string rates[] = {
        /* Old PRISM rates */
        {0x0A, "1 Mbit/s"},
        {0x14, "2 Mbit/s"},
        {0x37, "5.5 Mbit/s"},
        {0x6E, "11 Mbit/s"},
        /* MicroAP rates */
        {  2,  "1 Mbit/s"},
        {  4,  "2 Mbit/s"},
        { 11,  "5.5 Mbit/s"},
        { 12,  "6 Mbit/s"},
        { 18,  "9 Mbit/s"},
        { 22,  "11 Mbit/s"},
        { 24,  "12 Mbit/s"},
        { 36,  "18 Mbit/s"},
        { 48,  "24 Mbit/s"},
        { 72,  "36 Mbit/s"},
        { 96,  "48 Mbit/s"},
        {108,  "54 Mbit/s"},
        {0, NULL}
    };

    static hf_register_info hf[] = {
        { &hf_tzsp_version, {
            "Version", "tzsp.version", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_tzsp_type, {
            "Type", "tzsp.type", FT_UINT8, BASE_DEC,
            VALS(tzsp_type), 0, NULL, HFILL }},
        { &hf_tzsp_encap, {
            "Encapsulation", "tzsp.encap", FT_UINT16, BASE_DEC,
            VALS(tzsp_encapsulation), 0, NULL, HFILL }},

        { &hf_option_tag, {
            "Option Tag", "tzsp.option_tag", FT_UINT8, BASE_DEC,
            VALS(option_tag_vals), 0, NULL, HFILL }},
        { &hf_option_length, {
            "Option Length", "tzsp.option_length", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
#if 0
        { &hf_status_field, {
            "Status", "tzsp.wlan.status", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL }},
#endif
        { &hf_status_msg_type, {
            "Type", "tzsp.wlan.status.msg_type", FT_UINT8, BASE_HEX,
            VALS(msg_type), 0, "Message type", HFILL }},
#if 0
        { &hf_status_mac_port, {
            "Port", "tzsp.wlan.status.mac_port", FT_UINT8, BASE_DEC,
            NULL, 0, "MAC port", HFILL }},
#endif
        { &hf_status_pcf, {
            "PCF", "tzsp.wlan.status.pcf", FT_BOOLEAN, BASE_NONE,
            TFS (&pcf_flag), 0x0, "Point Coordination Function", HFILL }},
        { &hf_status_undecrypted, {
            "Undecrypted", "tzsp.wlan.status.undecrypted", FT_BOOLEAN, BASE_NONE,
            TFS (&undecr_flag), 0x0, NULL, HFILL }},
        { &hf_status_fcs_error, {
            "FCS", "tzsp.wlan.status.fcs_err", FT_BOOLEAN, BASE_NONE,
            TFS (&fcs_err_flag), 0x0, "Frame check sequence", HFILL }},
        { &hf_time, {
            "Time", "tzsp.wlan.time", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_silence, {
            "Silence", "tzsp.wlan.silence", FT_INT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_original_length, {
            "Original Length", "tzsp.original_length", FT_INT16, BASE_DEC,
            NULL, 0, "OrigLength", HFILL }},
        { &hf_signal, {
            "Signal", "tzsp.wlan.signal", FT_INT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_rate, {
            "Rate", "tzsp.wlan.rate", FT_UINT8, BASE_DEC,
            VALS(rates), 0, NULL, HFILL }},
        { &hf_channel, {
            "Channel", "tzsp.wlan.channel", FT_UINT16, BASE_DEC,
            VALS(channels), 0, NULL, HFILL }},
        { &hf_unknown, {
            "Unknown tag", "tzsp.unknown", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_sensormac, {
            "Sensor Address", "tzsp.sensormac", FT_ETHER, BASE_NONE,
            NULL, 0, "Sensor MAC", HFILL }},

        { &hf_device_name, {
            "Device Name", "tzsp.device_name", FT_STRING, BASE_NONE,
            NULL, 0, "DeviceName", HFILL }},

        { &hf_capture_location, {
            "Capture Location", "tzsp.capture_location", FT_STRING, BASE_NONE,
            NULL, 0, "CaptureLocation", HFILL }},

        { &hf_capture_info, {
            "Capture Information", "tzsp.device_info", FT_STRING, BASE_NONE,
            NULL, 0, "CaptureInformation", HFILL }},

        { &hf_capture_id, {
            "Capture Id", "tzsp.device_id", FT_UINT32, BASE_DEC,
            NULL, 0, "CaptureID", HFILL }},

        {&hf_time_stamp, {
            "Time Stamp", "tzsp.time_stamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "TimeStamp", HFILL}},

        { &hf_packet_id, {
            "Packet Id", "tzsp.packet_id", FT_UINT32, BASE_DEC,
            NULL, 0, "PacketId", HFILL }}
    };

    static int *ett[] = {
        &ett_tzsp,
        &ett_tag
    };

    proto_tzsp = proto_register_protocol("Tazmen Sniffer Protocol", "TZSP", "tzsp");
    proto_register_field_array(proto_tzsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tzsp_handle = register_dissector("tzsp", dissect_tzsp, proto_tzsp);

    tzsp_encap_table = register_dissector_table("tzsp.encap", "TZSP Encapsulation Type",
            proto_tzsp, FT_UINT16, BASE_DEC);
}

void
proto_reg_handoff_tzsp(void)
{
    dissector_add_uint_with_preference("udp.port", UDP_PORT_TZSP, tzsp_handle);

    /* Get the data dissector for handling various encapsulation types. */
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_ETHERNET,           find_dissector("eth_maybefcs"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_TOKEN_RING,         find_dissector("tr"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_PPP,                find_dissector("ppp_hdlc"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_FDDI,               find_dissector("fddi"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_RAW,                find_dissector("raw_ip"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_IEEE_802_11,        find_dissector("wlan"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_IEEE_802_11_PRISM,  find_dissector("prism"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_IEEE_802_11_AVS,    find_dissector("wlancap"));
    dissector_add_uint("tzsp.encap", TZSP_ENCAP_IEEE_802_11_RADIOTAP, find_dissector("radiotap"));

    /* Register this protocol as an encapsulation type. */
    dissector_add_uint("wtap_encap", WTAP_ENCAP_TZSP, tzsp_handle);
}

/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
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
