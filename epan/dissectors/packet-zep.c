/* packet-zep.c
 * Dissector  routines for the ZigBee Encapsulation Protocol
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *------------------------------------------------------------
 *
 *      ZEP Packets must be received in the following format:
 *      |UDP Header|  ZEP Header |IEEE 802.15.4 Packet|
 *      | 8 bytes  | 16/32 bytes |    <= 127 bytes    |
 *------------------------------------------------------------
 *
 *      ZEP v1 Header will have the following format:
 *      |Preamble|Version|Channel ID|Device ID|CRC/LQI Mode|LQI Val|Reserved|Length|
 *      |2 bytes |1 byte |  1 byte  | 2 bytes |   1 byte   |1 byte |7 bytes |1 byte|
 *
 *      ZEP v2 Header will have the following format (if type=1/Data):
 *      |Preamble|Version| Type |Channel ID|Device ID|CRC/LQI Mode|LQI Val|NTP Timestamp|Sequence#|Reserved|Length|
 *      |2 bytes |1 byte |1 byte|  1 byte  | 2 bytes |   1 byte   |1 byte |   8 bytes   | 4 bytes |10 bytes|1 byte|
 *
 *      ZEP v2 Header will have the following format (if type=2/Ack):
 *      |Preamble|Version| Type |Sequence#|
 *      |2 bytes |1 byte |1 byte| 4 bytes |
 *------------------------------------------------------------
 */

#include "config.h"


#include <epan/packet.h>

/*  Function declarations */
void proto_reg_handoff_zep(void);
void proto_register_zep(void);

#define ZEP_DEFAULT_PORT   17754

/*  ZEP Preamble Code */
#define ZEP_PREAMBLE        "EX"

/*  ZEP Header lengths. */
#define ZEP_V1_HEADER_LEN   16
#define ZEP_V2_HEADER_LEN   32
#define ZEP_V2_ACK_LEN      8

#define ZEP_V2_TYPE_DATA    1
#define ZEP_V2_TYPE_ACK     2

#define ZEP_LENGTH_MASK     0x7F

static const range_string type_rvals[] = {
    {0, 0, "Reserved"},
    {ZEP_V2_TYPE_DATA, ZEP_V2_TYPE_DATA, "Data"},
    {ZEP_V2_TYPE_ACK, ZEP_V2_TYPE_ACK, "Ack"},
    {3, 255, "Reserved"   },
    {0, 0, NULL}
};


static const true_false_string tfs_crc_lqi = { "CRC", "LQI" };

/*  Initialize protocol and registered fields. */
static int proto_zep = -1;
static int hf_zep_version = -1;
static int hf_zep_type = -1;
static int hf_zep_channel_id = -1;
static int hf_zep_device_id = -1;
static int hf_zep_lqi_mode = -1;
static int hf_zep_lqi = -1;
static int hf_zep_timestamp = -1;
static int hf_zep_seqno = -1;
static int hf_zep_ieee_length = -1;
static int hf_zep_protocol_id = -1;
static int hf_zep_reserved_field = -1;

/* Initialize protocol subtrees. */
static gint ett_zep = -1;

/*  Dissector handle */
static dissector_handle_t zep_handle;

/*  Subdissector handles */
static dissector_handle_t ieee802154_handle;
static dissector_handle_t ieee802154_cc24xx_handle;

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zep
 *  DESCRIPTION
 *      IEEE 802.15.4 packet dissection routine for Wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static int dissect_zep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t      *next_tvb;
    proto_item    *proto_root;
    proto_tree    *zep_tree;
    guint8        ieee_packet_len;
    guint8        zep_header_len;
    guint8        version;
    guint8        type;
    guint32       channel_id, seqno;
    gboolean      lqi_mode = FALSE;

    dissector_handle_t  next_dissector;

    if (tvb_reported_length(tvb) < ZEP_V2_ACK_LEN)
        return 0;

    /*  Determine whether this is a Q51/IEEE 802.15.4 sniffer packet or not */
    if(strcmp(tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 2, ENC_ASCII), ZEP_PREAMBLE)){
        /*  This is not a Q51/ZigBee sniffer packet */
        return 0;
    }

    /*  Extract the protocol version from the ZEP header. */
    version = tvb_get_guint8(tvb, 2);
    if (version == 1) {
        /* Type indicates a ZEP_v1 packet. */

        zep_header_len = ZEP_V1_HEADER_LEN;
        if (tvb_reported_length(tvb) < ZEP_V1_HEADER_LEN)
            return 0;

        type = 0;
        ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V1_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
    }
    else {
        /* At the time of writing, v2 is the latest version of ZEP, assuming
         * anything higher than v2 has identical format. */

        type = tvb_get_guint8(tvb, 3);
        if (type == ZEP_V2_TYPE_ACK) {
            /* ZEP Ack has only the seqno. */
            zep_header_len = ZEP_V2_ACK_LEN;
            ieee_packet_len = 0;
        }
        else {
            /* Although, only type 1 corresponds to data, if another value is present, assume it is dissected the same. */
            zep_header_len = ZEP_V2_HEADER_LEN;
            if (tvb_reported_length(tvb) < ZEP_V2_HEADER_LEN)
                return 0;

            ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V2_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
        }
    }

    if(ieee_packet_len < tvb_reported_length(tvb)-zep_header_len){
        /* Packet's length is mis-reported, abort dissection */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, (version==1)?"ZEP":"ZEPv2");

    proto_root = proto_tree_add_item(tree, proto_zep, tvb, 0, zep_header_len, ENC_NA);
    zep_tree = proto_item_add_subtree(proto_root, ett_zep);

    proto_tree_add_item(zep_tree, hf_zep_protocol_id, tvb, 0, 2, ENC_NA|ENC_ASCII);
    proto_tree_add_uint(zep_tree, hf_zep_version, tvb, 2, 1, version);

    switch (version)
    {
    case 1:
        proto_tree_add_item_ret_uint(zep_tree, hf_zep_channel_id, tvb, 3, 1, ENC_NA, &channel_id);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated ZigBee Packet [Channel]=%u [Length]=%u", channel_id, ieee_packet_len);
        proto_item_append_text(proto_root, ", Channel: %u, Length: %u", channel_id, ieee_packet_len);

        proto_tree_add_item(zep_tree, hf_zep_device_id, tvb, 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_boolean(zep_tree, hf_zep_lqi_mode, tvb, 6, 1, ENC_NA, &lqi_mode);
        if (lqi_mode != 0) {
            proto_tree_add_item(zep_tree, hf_zep_lqi, tvb, 7, 1, ENC_NA);
            proto_tree_add_item(zep_tree, hf_zep_reserved_field, tvb, 8, 8, ENC_NA);
        } else {
            proto_tree_add_item(zep_tree, hf_zep_reserved_field, tvb, 7, 9, ENC_NA);

        }
        proto_tree_add_item(zep_tree, hf_zep_ieee_length, tvb, ZEP_V1_HEADER_LEN - 1, 1, ENC_NA);
        break;

    case 2:
    default:
        proto_tree_add_uint(zep_tree, hf_zep_type, tvb, 3, 1, type);
        if (type == ZEP_V2_TYPE_ACK) {
            proto_tree_add_item_ret_uint(zep_tree, hf_zep_seqno, tvb, 4, 4, ENC_BIG_ENDIAN, &seqno);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Ack, Sequence Number: %i", seqno);
            proto_item_append_text(proto_root, ", Ack");
        } else {
            proto_tree_add_item_ret_uint(zep_tree, hf_zep_channel_id, tvb, 4, 1, ENC_NA, &channel_id);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated ZigBee Packet [Channel]=%u [Length]=%u", channel_id, ieee_packet_len);
            proto_item_append_text(proto_root, ", Channel: %u, Length: %u", channel_id, ieee_packet_len);
            proto_tree_add_item(zep_tree, hf_zep_device_id, tvb, 5, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(zep_tree, hf_zep_lqi_mode, tvb, 7, 1, ENC_NA, &lqi_mode);
            if (lqi_mode == 0) {
                proto_tree_add_item(zep_tree, hf_zep_lqi, tvb, 8, 1, ENC_NA);
            }
            proto_tree_add_item(zep_tree, hf_zep_timestamp, tvb, 9, 8, ENC_BIG_ENDIAN|ENC_TIME_NTP);
            proto_tree_add_item(zep_tree, hf_zep_seqno, tvb, 17, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(zep_tree, hf_zep_ieee_length, tvb, ZEP_V2_HEADER_LEN - 1, 1, ENC_NA);
        }
        break;
    }

    /* Determine which dissector to call next. */
    if (lqi_mode) {
        /* CRC present, use standard IEEE dissector.
         * XXX - 2-octet or 4-octet CRC?
         */
        next_dissector = ieee802154_handle;
    }
    else {
        /* ChipCon/TI CC24xx-compliant metadata present, CRC absent */
        next_dissector = ieee802154_cc24xx_handle;
    }

    /*  Call the appropriate IEEE 802.15.4 dissector */
    if (!((version>=2) && (type==ZEP_V2_TYPE_ACK))) {
        next_tvb = tvb_new_subset_length(tvb, zep_header_len, ieee_packet_len);
        if (next_dissector != NULL) {
            call_dissector(next_dissector, next_tvb, pinfo, tree);
        } else {
            /* IEEE 802.15.4 dissectors couldn't be found. */
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }
    return tvb_captured_length(tvb);
} /* dissect_ieee802_15_4 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zep
 *  DESCRIPTION
 *      IEEE 802.15.4 protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zep(void)
{
    static hf_register_info hf[] = {
        { &hf_zep_version,
        { "Protocol Version",           "zep.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The version of the sniffer.", HFILL }},

        { &hf_zep_type,
        { "Type",                       "zep.type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(type_rvals), 0x0,
            NULL, HFILL }},

        { &hf_zep_channel_id,
        { "Channel ID",                 "zep.channel_id", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel on which this packet was detected.", HFILL }},

        { &hf_zep_device_id,
        { "Device ID",                  "zep.device_id", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The ID of the device that detected this packet.", HFILL }},

        { &hf_zep_lqi_mode,
        { "LQI/CRC Mode",               "zep.lqi_mode", FT_BOOLEAN, BASE_NONE, TFS(&tfs_crc_lqi), 0x0,
            "Determines what format the last two bytes of the MAC frame use.", HFILL }},

        { &hf_zep_lqi,
        { "Link Quality Indication",    "zep.lqi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_timestamp,
        { "Timestamp",                  "zep.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_seqno,
        { "Sequence Number",            "zep.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_ieee_length,
        { "Length",              "zep.length", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, ZEP_LENGTH_MASK,
            "The length (in bytes) of the encapsulated IEEE 802.15.4 MAC frame.", HFILL }},

        { &hf_zep_protocol_id,
        { "Protocol ID String",            "zep.protocol_id", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_reserved_field,
        { "Reserved Fields",            "zep.reserved_field", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_zep
    };

    /*  Register protocol name and description. */
    proto_zep = proto_register_protocol("ZigBee Encapsulation Protocol", "ZEP", "zep");

    /*  Register header fields and subtrees. */
    proto_register_field_array(proto_zep, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*  Register dissector with Wireshark. */
    zep_handle = register_dissector("zep", dissect_zep, proto_zep);
} /* proto_register_zep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zep
 *  DESCRIPTION
 *      Registers the zigbee dissector with Wireshark.
 *      Will be called every time 'apply' is pressed in the preferences menu.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zep(void)
{
    dissector_handle_t h;

    /* Get dissector handles. */
    if ( !(h = find_dissector("wpan")) ) { /* Try use built-in 802.15.4 dissector */
        h = find_dissector("ieee802154");  /* otherwise use older 802.15.4 plugin dissector */
    }
    ieee802154_handle = h;
    if ( !(h = find_dissector("wpan_cc24xx")) ) { /* Try use built-in 802.15.4 (Chipcon) dissector */
        h = find_dissector("ieee802154_ccfcs");   /* otherwise use older 802.15.4 (Chipcon) plugin dissector */
    }
    ieee802154_cc24xx_handle = h;

    dissector_add_uint("udp.port", ZEP_DEFAULT_PORT, zep_handle);
} /* proto_reg_handoff_zep */

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
