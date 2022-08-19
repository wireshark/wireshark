/* packet-rtls.c
 * Routines for Real Time Location System dissection
 * Copyright 2016, Alexis La Goutte (See Authors)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * http://community.arubanetworks.com/aruba/attachments/aruba/unified-wired-wireless-access/23715/1/RTLS_integrationv6.docx
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_rtls(void);
void proto_register_rtls(void);

static dissector_handle_t rtls_handle;

static int proto_rtls = -1;
static int hf_rtls_message_type = -1;
static int hf_rtls_message_id = -1;
static int hf_rtls_version_major = -1;
static int hf_rtls_version_minor = -1;
static int hf_rtls_data_length = -1;
static int hf_rtls_ap_mac = -1;
static int hf_rtls_padding = -1;
static int hf_rtls_reserved = -1;
static int hf_rtls_signature = -1;

static int hf_rtls_as_tag_addr = -1;
static int hf_rtls_sr_mac_address = -1;
static int hf_rtls_nack_flags = -1;
static int hf_rtls_nack_flags_internal_error = -1;
static int hf_rtls_nack_flags_station_not_found = -1;
static int hf_rtls_nack_flags_reserved = -1;
static int hf_rtls_tr_bssid = -1;
static int hf_rtls_tr_rssi = -1;
static int hf_rtls_tr_rssi_calculated = -1;
static int hf_rtls_tr_noise_floor = -1;
static int hf_rtls_tr_timestamp = -1;
static int hf_rtls_tr_tag_mac = -1;
static int hf_rtls_tr_frame_control = -1;
static int hf_rtls_tr_sequence = -1;
static int hf_rtls_tr_data_rate = -1;
static int hf_rtls_tr_tx_power = -1;
static int hf_rtls_tr_channel = -1;
static int hf_rtls_tr_battery = -1;
static int hf_rtls_sr_mac = -1;
static int hf_rtls_sr_noise_floor = -1;
static int hf_rtls_sr_data_rate = -1;
static int hf_rtls_sr_channel = -1;
static int hf_rtls_sr_rssi = -1;
static int hf_rtls_sr_rssi_calculated = -1;
static int hf_rtls_sr_type = -1;
static int hf_rtls_sr_associated = -1;
static int hf_rtls_sr_radio_bssid = -1;
static int hf_rtls_sr_mon_bssid = -1;
static int hf_rtls_sr_age = -1;
static int hf_rtls_ser_mac = -1;
static int hf_rtls_ser_bssid = -1;
static int hf_rtls_ser_essid = -1;
static int hf_rtls_ser_channel = -1;
static int hf_rtls_ser_phy_type = -1;
static int hf_rtls_ser_rssi = -1;
static int hf_rtls_ser_rssi_calculated = -1;
static int hf_rtls_ser_duration = -1;
static int hf_rtls_ser_num_packets = -1;
static int hf_rtls_ser_noise_floor = -1;
static int hf_rtls_ser_classification = -1;
static int hf_rtls_aer_bssid = -1;
static int hf_rtls_aer_essid = -1;
static int hf_rtls_aer_channel = -1;
static int hf_rtls_aer_phy_type = -1;
static int hf_rtls_aer_rssi = -1;
static int hf_rtls_aer_rssi_calculated = -1;
static int hf_rtls_aer_duration = -1;
static int hf_rtls_aer_num_packets = -1;
static int hf_rtls_aer_noise_floor = -1;
static int hf_rtls_aer_classification = -1;
static int hf_rtls_aer_match_type = -1;
static int hf_rtls_aer_match_method = -1;
static int hf_rtls_cmr_messages = -1;

static int * const rtls_nack_flags[] = {
    &hf_rtls_nack_flags_internal_error,
    &hf_rtls_nack_flags_station_not_found,
    &hf_rtls_nack_flags_reserved,
    NULL
};

static expert_field ei_rtls_undecoded = EI_INIT;
static gint ett_rtls = -1;
static gint ett_rtls_message = -1;
static gint ett_rtls_nack_flags = -1;

#define RTLS_MIN_LENGTH 16

#define AR_AS_CONFIG_SET            0x0000
#define AR_STATION_REQUEST          0x0001
#define AR_ACK                      0x0010
#define AR_NACK                     0x0011
#define AR_TAG_REPORT               0x0012
#define AR_STATION_REPORT           0x0013
#define AR_COMPOUND_MESSAGE_REPORT  0x0014
#define AR_AP_NOTIFICATION          0x0015
#define AR_MMS_CONFIG_SET           0x0016
#define AR_STATION_EX_REPORT        0x0017
#define AR_AP_EX_REPORT             0x0018

static const value_string rtls_message_type_vals[] = {
    { AR_AS_CONFIG_SET, "AR_AS_CONFIG_SET" },
    { AR_STATION_REQUEST, "AR_STATION_REQUEST" },
    { AR_ACK, "AR_ACK"},
    { AR_NACK, "AR_NACK"},
    { AR_TAG_REPORT, "AR_TAG_REPORT"},
    { AR_STATION_REPORT, "AR_STATION_REPORT"},
    { AR_COMPOUND_MESSAGE_REPORT, "AR_COMPOUND_MESSAGE_REPORT"},
    { AR_AP_NOTIFICATION, "AR_AP_NOTIFICATION"},
    { AR_MMS_CONFIG_SET, "AR_MMS_CONFIG_SET"},
    { AR_STATION_EX_REPORT, "AR_STATION_EX_REPORT"},
    { AR_AP_EX_REPORT, "AR_AP_EX_REPORT"},
    { 0, NULL }
};

static const value_string rtls_sr_type_vals[] = {
    { 1, "AR_WLAN_CLIENT" },
    { 2, "AR_WLAN_AP" },
    {0, NULL}
};

static const value_string rtls_sr_associated_vals[] = {
    { 1, "AR_WLAN_ASSOCIATED (All APs and Associated Stations)" },
    { 2, "AR_WLAN_UNASSOCIATED (Unassociated Stations)" },
    {0, NULL}
};

static const value_string rtls_data_rate_vals[] = {
    { 0x00, "1 Mbits" },
    { 0x01, "2 Mbits" },
    { 0x02, "5.5 Mbits" },
    { 0x03, "6 Mbits" },
    { 0x04, "9 Mbits" },
    { 0x05, "11 Mbits" },
    { 0x06, "12 Mbits" },
    { 0x07, "18 Mbits" },
    { 0x08, "24 Mbits" },
    { 0x09, "36 Mbits" },
    { 0x0A, "48 Mbits" },
    { 0x0B, "54 Mbits" },
    {0, NULL}
};

static const value_string rtls_ex_phy_type_vals[] = {
    { 1, "802.11b" },
    { 2, "802.11a" },
    { 3, "802.11g" },
    { 4, "802.11ag" },
    {0, NULL}
};

static const value_string rtls_ex_classification_vals[] = {
    { 1, "Valid" },
    { 2, "interfering" },
    { 3, "DOS'ed" },
    {0, NULL}
};

static void
rssi_base_custom(gchar *result, guint32 rssi)
{
    /* Convert Hex to decimal and subtract 256 to get the signal value */
    snprintf(result, ITEM_LABEL_LENGTH, "%d", rssi - 256);

}

static int
dissect_rtls_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *rtls_tree, guint offset, guint *data_length)
{

    proto_tree_add_item(rtls_tree, hf_rtls_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(rtls_tree, hf_rtls_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(rtls_tree, hf_rtls_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(rtls_tree, hf_rtls_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(rtls_tree, hf_rtls_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    if(data_length){
        *data_length = tvb_get_ntohs(tvb, offset);
    }
    offset += 2;

    proto_tree_add_item(rtls_tree, hf_rtls_ap_mac, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(rtls_tree, hf_rtls_padding, tvb, offset, 2, ENC_NA);
    offset += 2;

    return offset;
}

static int
dissect_rtls_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *rtls_tree, guint offset, guint type)
{
    proto_item *ti_rssi;

    switch(type){
        case AR_AS_CONFIG_SET:
            proto_tree_add_item(rtls_tree, hf_rtls_as_tag_addr, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
        case AR_STATION_REQUEST:
            proto_tree_add_item(rtls_tree, hf_rtls_sr_mac_address, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
        case AR_ACK:
        case AR_AP_NOTIFICATION:
            /* No Payload */
        break;
        case AR_NACK:
            proto_tree_add_bitmask_with_flags(rtls_tree, tvb, offset,
hf_rtls_nack_flags, ett_rtls_nack_flags, rtls_nack_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
        case AR_TAG_REPORT:
            proto_tree_add_item(rtls_tree, hf_rtls_tr_bssid, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
            ti_rssi = proto_tree_add_item(rtls_tree, hf_rtls_tr_rssi_calculated, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_generated(ti_rssi);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_noise_floor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_tag_mac, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_frame_control, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_data_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_tx_power, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_tr_battery, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
       case AR_STATION_REPORT:
            proto_tree_add_item(rtls_tree, hf_rtls_sr_mac, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_noise_floor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_data_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
            ti_rssi = proto_tree_add_item(rtls_tree, hf_rtls_sr_rssi_calculated, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_generated(ti_rssi);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_associated, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_radio_bssid, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_mon_bssid, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_sr_age, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
       case AR_STATION_EX_REPORT:
            proto_tree_add_item(rtls_tree, hf_rtls_ser_mac, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_bssid, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_essid, tvb, offset, 33, ENC_ASCII);
            offset += 33;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_phy_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
            ti_rssi = proto_tree_add_item(rtls_tree, hf_rtls_ser_rssi_calculated, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_generated(ti_rssi);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_num_packets, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_noise_floor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_ser_classification, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
       case AR_AP_EX_REPORT:
            proto_tree_add_item(rtls_tree, hf_rtls_aer_bssid, tvb, offset, 6, ENC_NA );
            offset += 6;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_essid, tvb, offset, 33, ENC_ASCII);
            offset += 33;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_phy_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
            ti_rssi = proto_tree_add_item(rtls_tree, hf_rtls_aer_rssi_calculated, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_generated(ti_rssi);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_num_packets, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_noise_floor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_classification, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_match_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_aer_match_method, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
       case AR_COMPOUND_MESSAGE_REPORT:{
            guint32 cmr_messages;
            proto_tree *sub_tree;

            proto_tree_add_item_ret_uint(rtls_tree, hf_rtls_cmr_messages, tvb, offset, 2, ENC_BIG_ENDIAN, &cmr_messages);
            offset += 2;
            proto_tree_add_item(rtls_tree, hf_rtls_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            while(cmr_messages){
                guint32 data_length;
                type = tvb_get_ntohs(tvb, offset);
                sub_tree = proto_tree_add_subtree_format(rtls_tree, tvb, offset, -1, ett_rtls_message, NULL, "%s", val_to_str_const(type, rtls_message_type_vals, "(unknown %d)"));

                offset = dissect_rtls_header(tvb, pinfo, sub_tree, offset, &data_length);

                offset = dissect_rtls_message_type(tvb, pinfo, sub_tree, offset, type);

                proto_item_set_len(sub_tree, data_length + 16);
                cmr_messages--;
            }
            }
        break;
        default:{
            guint32 remaining;

            remaining = tvb_reported_length_remaining(tvb, offset) - 20; /* Remove 20 of signature */
            proto_tree_add_expert(rtls_tree, pinfo, &ei_rtls_undecoded, tvb, offset, remaining);
            offset += remaining;
            }
        break;
    }

    return offset;
}

static int
dissect_rtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *rtls_tree;
    guint       offset = 0;
    guint32     type;

    if (tvb_reported_length(tvb) < RTLS_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTLS");


    ti = proto_tree_add_item(tree, proto_rtls, tvb, 0, -1, ENC_NA);

    rtls_tree = proto_item_add_subtree(ti, ett_rtls);

    /* RTLS Header */
    type = tvb_get_ntohs(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(type, rtls_message_type_vals, "(unknown %d)"));

    offset = dissect_rtls_header(tvb, pinfo, rtls_tree, offset, NULL);

    offset = dissect_rtls_message_type(tvb, pinfo, rtls_tree, offset, type);

    /* TODO: Check signature ? HMAC-SHA1 with shared key and RTLS packet data */
    proto_tree_add_item(rtls_tree, hf_rtls_signature, tvb, offset, 20, ENC_NA);
    offset += 20;

    return offset;
}

void
proto_register_rtls(void)
{
    expert_module_t *expert_rtls;

    static hf_register_info hf[] = {

        /* RTLS Header*/
        { &hf_rtls_message_type,
          { "Message Type", "rtls.message_type",
            FT_UINT16, BASE_HEX, VALS(rtls_message_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_message_id,
          { "Message Id", "rtls.message_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_version_major,
          { "Version Major", "rtls.version_major",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_version_minor,
          { "Version Major", "rtls.version_minor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_data_length,
          { "Data Length", "rtls.data_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_ap_mac,
          { "AP MAC Address", "rtls.ap_mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_padding,
          { "Padding", "rtls.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_reserved,
          { "Reserved", "rtls.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_signature,
          { "Signature", "rtls.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* AR_AS_CONFIG_SET */
        { &hf_rtls_as_tag_addr,
          { "AS Tag Address", "rtls.as_tag_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Tag multicast address", HFILL }
        },
        /* AR_STATION_REQUEST */
        { &hf_rtls_sr_mac_address,
          { "MAC Address", "rtls.sr_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* AR_NACK */
        { &hf_rtls_nack_flags,
          { "Flags", "rtls.nack.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rtls_nack_flags_internal_error,
          { "Internal Error", "rtls.nack.flags.internal_errors",
            FT_UINT16, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_rtls_nack_flags_station_not_found,
          { "Station Not found", "rtls.nack.flags.station_not_found",
            FT_UINT16, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_rtls_nack_flags_reserved,
          { "Reserved", "rtls.nack.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0D,
            NULL, HFILL }
        },

        /* AR_TAG_REPORT */
        { &hf_rtls_tr_bssid,
          { "BSSID", "rtls.tr.bssid",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "MAC address of the radio where the frame was received", HFILL }
        },
        { &hf_rtls_tr_rssi,
          { "RSSI", "rtls.tr.rssi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Signal as a signed negative hex value", HFILL }
        },
        { &hf_rtls_tr_rssi_calculated,
          { "RSSI (calculated)", "rtls.tr.rssi.calculated",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(rssi_base_custom), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_tr_noise_floor,
          { "Noise Floor", "rtls.tr.noise_floor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Noise floor of the radio", HFILL }
        },
        { &hf_rtls_tr_timestamp,
          { "Timestamp", "rtls.tr.timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Millisecond granularity timestamp that represents local time in AP when message was sent", HFILL }
        },
        { &hf_rtls_tr_tag_mac,
          { "Tag Mac", "rtls.tr.tag_mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "MAC address of the tag", HFILL }
        },
        { &hf_rtls_tr_frame_control,
          { "Frame Control", "rtls.tr.frame_control",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Frame control from 802.11 header", HFILL }
        },
        { &hf_rtls_tr_sequence,
          { "Sequence", "rtls.tr.sequence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Sequence number from the 802.11 header", HFILL }
        },
        { &hf_rtls_tr_data_rate,
          { "Data Rate", "rtls.tr.data_rate",
            FT_UINT8, BASE_DEC, VALS(rtls_data_rate_vals), 0x0,
            "Data rate of chirp frame", HFILL }
        },
        { &hf_rtls_tr_tx_power,
          { "Tx Power", "rtls.tr.tx_power",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Transmit power in dbm", HFILL }
        },
        { &hf_rtls_tr_channel,
          { "Channel", "rtls.tr.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Channel of tag transmission", HFILL }
        },
        { &hf_rtls_tr_battery,
          { "Battery", "rtls.tr.battery",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Batter level information from the chirp frame if present", HFILL }
        },
        /* AR_STATION_REPORT */
        { &hf_rtls_sr_mac,
          { "MAC", "rtls.sr.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_sr_noise_floor,
          { "Noise Floor", "rtls.sr.noise_floor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Noise floor of the channel where the station was last heard", HFILL }
        },
        { &hf_rtls_sr_data_rate,
          { "Data Rate", "rtls.sr.data_rate",
            FT_UINT8, BASE_DEC, VALS(rtls_data_rate_vals), 0x0,
            "Data rate of chirp frame", HFILL }
        },
        { &hf_rtls_sr_channel,
          { "Channel", "rtls.sr.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Channel where station was last heard", HFILL }
        },
        { &hf_rtls_sr_rssi,
          { "RSSI", "rtls.sr.rssi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Signal as a signed negative hex value", HFILL }
        },
        { &hf_rtls_sr_rssi_calculated,
          { "RSSI (calculated)", "rtls.sr.rssi.calculated",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(rssi_base_custom), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_sr_type,
          { "Type", "rtls.sr.type",
            FT_UINT8, BASE_DEC, VALS(rtls_sr_type_vals), 0x0,
            "Type of device", HFILL }
        },
        { &hf_rtls_sr_associated,
          { "Associated", "rtls.sr.associated",
            FT_UINT8, BASE_DEC, VALS(rtls_sr_associated_vals), 0x0,
            "Association status of station", HFILL }
        },
        { &hf_rtls_sr_radio_bssid,
          { "Radio BSSID", "rtls.sr.radio_bssids",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Association status of station BSSID of the radio that detected the device", HFILL }
        },
        { &hf_rtls_sr_mon_bssid,
          { "Mon BSSID", "rtls.sr.mon_bssids",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "BSSID of the AP that the station is associated to", HFILL }
        },
        { &hf_rtls_sr_age,
          { "Age", "rtls.sr.age",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The number of seconds since the last packet was heard from this station", HFILL }
        },
        /* AR_STATION_EX_REPORT */
        { &hf_rtls_ser_mac,
          { "MAC", "rtls.ser.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "MAC address of station", HFILL }
        },
        { &hf_rtls_ser_bssid,
          { "BSSID", "rtls.ser.bssid",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "BSSID with which this station is associated", HFILL }
        },
        { &hf_rtls_ser_essid,
          { "ESSID", "rtls.ser.essid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "ESSID with which this station is associated", HFILL }
        },
        { &hf_rtls_ser_channel,
          { "Channel", "rtls.ser.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Channel where this station is active", HFILL }
        },
        { &hf_rtls_ser_phy_type,
          { "Phy type", "rtls.ser.phy_type",
            FT_UINT8, BASE_DEC, VALS(rtls_ex_phy_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_ser_rssi,
          { "RSSI", "rtls.ser.rssi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Average RSSI during the duration", HFILL }
        },
        { &hf_rtls_ser_rssi_calculated,
          { "RSSI (calculated)", "rtls.ser.rssi.calculated",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(rssi_base_custom), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_ser_duration,
          { "Duration", "rtls.ser.duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Average calculation duration", HFILL }
        },
        { &hf_rtls_ser_num_packets,
          { "Num Packets", "rtls.ser.num_packets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of packets used in average RSSI calculation", HFILL }
        },
        { &hf_rtls_ser_noise_floor,
          { "Noise Floor", "rtls.ser.noise_floor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Noise floor of the radio", HFILL }
        },
        { &hf_rtls_ser_classification,
          { "Classification", "rtls.ser.classification",
            FT_UINT8, BASE_DEC, VALS(rtls_ex_classification_vals), 0x0,
            "Millisecond granularity timestamp that represents local time in AP when message was sent", HFILL }
        },
        /* AR_AP_EX_REPORT */
        { &hf_rtls_aer_bssid,
          { "BSSID", "rtls.aer.bssid",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "BSSID with which this station is associated", HFILL }
        },
        { &hf_rtls_aer_essid,
          { "ESSID", "rtls.aer.essid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "ESSID with which this station is associated", HFILL }
        },
        { &hf_rtls_aer_channel,
          { "Channel", "rtls.aer.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Channel where this station is active", HFILL }
        },
        { &hf_rtls_aer_phy_type,
          { "Phy type", "rtls.aer.phy_type",
            FT_UINT8, BASE_DEC, VALS(rtls_ex_phy_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_aer_rssi,
          { "RSSI", "rtls.aer.rssi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Average RSSI during the duration", HFILL }
        },
        { &hf_rtls_aer_rssi_calculated,
          { "RSSI (calculated)", "rtls.aer.rssi.calculated",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(rssi_base_custom), 0x0,
            NULL, HFILL }
        },
        { &hf_rtls_aer_duration,
          { "Duration", "rtls.aer.duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Average calculation duration", HFILL }
        },
        { &hf_rtls_aer_num_packets,
          { "Num Packets", "rtls.aer.num_packets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of packets used in average RSSI calculation", HFILL }
        },
        { &hf_rtls_aer_noise_floor,
          { "Noise Floor", "rtls.aer.noise_floor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Noise floor of the radio", HFILL }
        },
        { &hf_rtls_aer_classification,
          { "Classification", "rtls.aer.classification",
            FT_UINT8, BASE_DEC, VALS(rtls_ex_classification_vals), 0x0,
            "Millisecond granularity timestamp that represents local time in AP when message was sent", HFILL }
        },
        { &hf_rtls_aer_match_type,
          { "Match Type", "rtls.aer.match_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Internal Aruba use", HFILL }
        },
        { &hf_rtls_aer_match_method,
          { "Match Method", "rtls.aer.match_method",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Internal Aruba use", HFILL }
        },

        { &hf_rtls_cmr_messages,
          { "Messages", "rtls.cmr_messages",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "number of messages", HFILL }
        },

    };

    static gint *ett[] = {
        &ett_rtls,
        &ett_rtls_message,
        &ett_rtls_nack_flags,
    };


    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_rtls_undecoded,
          { "rtls.undecoded", PI_UNDECODED, PI_NOTE, "Undecoded Payload", EXPFILL }
        }
    };


    proto_rtls = proto_register_protocol("Real Time Location System", "RTLS", "rtls");
    rtls_handle = register_dissector("rtls", dissect_rtls, proto_rtls);

    proto_register_field_array(proto_rtls, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_rtls = expert_register_protocol(proto_rtls);
    expert_register_field_array(expert_rtls, ei, array_length(ei));

}

void
proto_reg_handoff_rtls(void)
{
    dissector_add_for_decode_as_with_preference("udp.port", rtls_handle);
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
