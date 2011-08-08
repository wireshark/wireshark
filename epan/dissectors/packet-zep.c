/* packet-zep.c
 * Dissector  routines for the ZigBee Encapsulation Protocol
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVEHCONFIG_H */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/stat.h>

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-ntp.h"

#include "packet-zep.h"

/*  Function declarations */
void proto_reg_handoff_zep(void);

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

/* Initialize protocol subtrees. */
static gint ett_zep = -1;

/* Initialize preferences. */
static guint32  gPREF_zep_udp_port = ZEP_DEFAULT_PORT;

/*  Dissector handles */
static dissector_handle_t data_handle;
static dissector_handle_t ieee802154_handle;
static dissector_handle_t ieee802154_ccfcs_handle;

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
static void dissect_zep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t            *next_tvb;
    proto_item          *proto_root, *pi;
    proto_tree          *zep_tree;
    guint8              ieee_packet_len;
    guint8              zep_header_len;
    zep_info            zep_data;

    dissector_handle_t  next_dissector;

    /*  Determine whether this is a Q51/IEEE 802.15.4 sniffer packet or not */
    if(strcmp(tvb_get_ephemeral_string(tvb, 0, 2), ZEP_PREAMBLE)){
        /*  This is not a Q51/ZigBee sniffer packet */
        call_dissector(data_handle, tvb, pinfo, tree);
        return;
    }

    memset(&zep_data, 0, sizeof(zep_data)); /* Zero all zep_data fields. */

    /*  Extract the protocol version from the ZEP header. */
    zep_data.version = tvb_get_guint8(tvb, 2);
    if (zep_data.version == 1) {
        /* Type indicates a ZEP_v1 packet. */

        zep_header_len = ZEP_V1_HEADER_LEN;
        zep_data.type = 0;
        zep_data.channel_id = tvb_get_guint8(tvb, 3);
        zep_data.device_id = tvb_get_ntohs(tvb, 4);
        zep_data.lqi_mode = tvb_get_guint8(tvb, 6)?1:0;
        zep_data.lqi = tvb_get_guint8(tvb, 7);
        ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V1_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
    }
    else {
        /* At the time of writing, v2 is the latest version of ZEP, assuming
         * anything higher than v2 has identical format. */

        zep_data.type = tvb_get_guint8(tvb, 3);
        if (zep_data.type == ZEP_V2_TYPE_ACK) {
            /* ZEP Ack has only the seqno. */
            zep_header_len = ZEP_V2_ACK_LEN;
            zep_data.seqno = tvb_get_ntohl(tvb, 4);
            ieee_packet_len = 0;
        }
        else {
            /* Although, only type 1 corresponds to data, if another value is present, assume it is dissected the same. */
            zep_header_len = ZEP_V2_HEADER_LEN;
            zep_data.channel_id = tvb_get_guint8(tvb, 4);
            zep_data.device_id = tvb_get_ntohs(tvb, 5);
            zep_data.lqi_mode = tvb_get_guint8(tvb, 7)?1:0;
            zep_data.lqi = tvb_get_guint8(tvb, 8);
            ntp_to_nstime(tvb, 9, &(zep_data.ntp_time));
            zep_data.seqno = tvb_get_ntohl(tvb, 17);
            ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V2_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
        }
    }

#if 0
/*??dat*/
    if (zep_data.ntp_time.secs && zep_data.ntp_time.nsecs) {
        pinfo->fd->abs_ts = zep_data.ntp_time;
    }
#endif

    if(ieee_packet_len < tvb_length(tvb)-zep_header_len){
        /* Packet's length is mis-reported, abort dissection */
        call_dissector(data_handle, tvb, pinfo, tree);
        return;
    }

    /*  Enter name info protocol field */
    if(check_col(pinfo->cinfo, COL_PROTOCOL)){
        col_set_str(pinfo->cinfo, COL_PROTOCOL, (zep_data.version==1)?"ZEP":"ZEPv2");
    }

    /*  Enter name info protocol field */
    if(check_col(pinfo->cinfo, COL_INFO)){
        col_clear(pinfo->cinfo, COL_INFO);
        if (!((zep_data.version>=2) && (zep_data.type==ZEP_V2_TYPE_ACK))) col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated ZigBee Packet [Channel]=%i [Length]=%i", zep_data.channel_id, ieee_packet_len);
        else col_add_fstr(pinfo->cinfo, COL_INFO, "Ack, Sequence Number: %i", zep_data.seqno);
    }

    if(tree){
        /*  Create subtree for the ZEP Header */
        if (!((zep_data.version>=2) && (zep_data.type==ZEP_V2_TYPE_ACK))) {
            proto_root = proto_tree_add_protocol_format(tree, proto_zep, tvb, 0, zep_header_len, "ZigBee Encapsulation Protocol, Channel: %i, Length: %i", zep_data.channel_id, ieee_packet_len);
        }
        else {
            proto_root = proto_tree_add_protocol_format(tree, proto_zep, tvb, 0, zep_header_len, "ZigBee Encapsulation Protocol, Ack");
        }
        zep_tree = proto_item_add_subtree(proto_root, ett_zep);

        /*  Display the information in the subtree */
        proto_tree_add_text(zep_tree, tvb, 0, 2, "Protocol ID String: EX");
        if (zep_data.version==1) {
            proto_tree_add_uint(zep_tree, hf_zep_version, tvb, 2, 1, zep_data.version);
            proto_tree_add_uint(zep_tree, hf_zep_channel_id, tvb, 3, 1, zep_data.channel_id);
            proto_tree_add_uint(zep_tree, hf_zep_device_id, tvb, 4, 2, zep_data.device_id);
            proto_tree_add_boolean_format(zep_tree, hf_zep_lqi_mode, tvb, 6, 1, zep_data.lqi_mode, "LQI/CRC Mode: %s", zep_data.lqi_mode?"CRC":"LQI");
            if(!(zep_data.lqi_mode)){
                proto_tree_add_uint(zep_tree, hf_zep_lqi, tvb, 7, 1, zep_data.lqi);
            }
            proto_tree_add_text(zep_tree, tvb, 7+((zep_data.lqi_mode)?0:1), 7+((zep_data.lqi_mode)?1:0), "Reserved Fields");
        }
        else {
            proto_tree_add_uint(zep_tree, hf_zep_version, tvb, 2, 1, zep_data.version);
            if (zep_data.type == ZEP_V2_TYPE_ACK) {
                proto_tree_add_uint_format(zep_tree, hf_zep_version, tvb, 3, 1, zep_data.type, "Type: %i (Ack)", ZEP_V2_TYPE_ACK);
                proto_tree_add_uint(zep_tree, hf_zep_seqno, tvb, 4, 4, zep_data.seqno);
            }
            else {
                proto_tree_add_uint_format(zep_tree, hf_zep_version, tvb, 3, 1, zep_data.type, "Type: %i (%s)", zep_data.type, (zep_data.type==ZEP_V2_TYPE_DATA)?"Data":"Reserved");
                proto_tree_add_uint(zep_tree, hf_zep_channel_id, tvb, 4, 1, zep_data.channel_id);
                proto_tree_add_uint(zep_tree, hf_zep_device_id, tvb, 5, 2, zep_data.device_id);
                proto_tree_add_boolean_format(zep_tree, hf_zep_lqi_mode, tvb, 7, 1, zep_data.lqi_mode, "LQI/CRC Mode: %s", zep_data.lqi_mode?"CRC":"LQI");
                if(!(zep_data.lqi_mode)){
                    proto_tree_add_uint(zep_tree, hf_zep_lqi, tvb, 8, 1, zep_data.lqi);
                }
                pi = proto_tree_add_time(zep_tree, hf_zep_timestamp, tvb, 9, 8, &(zep_data.ntp_time));
                proto_item_append_text(pi, " (%lu.%09lus)", (unsigned long)zep_data.ntp_time.secs, (unsigned long)zep_data.ntp_time.nsecs);
                proto_tree_add_uint(zep_tree, hf_zep_seqno, tvb, 17, 4, zep_data.seqno);
            }
        }
        if (!((zep_data.version==2) && (zep_data.type==ZEP_V2_TYPE_ACK))) proto_tree_add_uint_format(zep_tree, hf_zep_ieee_length, tvb, zep_header_len - 1, 1, ieee_packet_len, "Length: %i %s", ieee_packet_len, (ieee_packet_len==1)?"Byte":"Bytes");
    }

    /* Determine which dissector to call next. */
    if (zep_data.lqi_mode) {
        /* CRC present, use standard IEEE dissector. */
        next_dissector = ieee802154_handle;
    }
    else {
        /* ChipCon compliant FCS present. */
        next_dissector = ieee802154_ccfcs_handle;
    }
    if (!next_dissector) {
        /* IEEE 802.15.4 dissectors couldn't be found. */
        next_dissector = data_handle;
    }

    /*  Call the IEEE 802.15.4 dissector */
    if (!((zep_data.version>=2) && (zep_data.type==ZEP_V2_TYPE_ACK))) {
        next_tvb = tvb_new_subset(tvb, zep_header_len, ieee_packet_len, ieee_packet_len);
        call_dissector(next_dissector, next_tvb, pinfo, tree);
    }
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
    module_t *zep_module;

    static hf_register_info hf[] = {
        { &hf_zep_version,
        { "Protocol Version",           "zep.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The version of the sniffer.", HFILL }},

        { &hf_zep_type,
        { "Type",                       "zep.type", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_channel_id,
        { "Channel ID",                 "zep.channel_id", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel on which this packet was detected.", HFILL }},

        { &hf_zep_device_id,
        { "Device ID",                  "zep.device_id", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The ID of the device that detected this packet.", HFILL }},

        { &hf_zep_lqi_mode,
        { "LQI/CRC Mode",               "zep.lqi_mode", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
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
        { "Length",              "zep.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The length (in bytes) of the encapsulated IEEE 802.15.4 MAC frame.", HFILL }},
    };

    static gint *ett[] = {
        &ett_zep
    };

    /*  Register protocol name and description. */
    proto_zep = proto_register_protocol("ZigBee Encapsulation Protocol", "ZEP", "zep");

    /*  Register header fields and subtrees. */
    proto_register_field_array(proto_zep, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*  Register preferences module */
    zep_module = prefs_register_protocol(proto_zep, proto_reg_handoff_zep);

    /*  Register preferences */
    prefs_register_uint_preference(zep_module, "udp.port", "ZEP UDP port",
                 "Set the port for ZEP Protocol\n"
                 "Default port is 17754",
                 10, &gPREF_zep_udp_port);

    /*  Register dissector with Wireshark. */
    register_dissector("zep", dissect_zep, proto_zep);
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
    static dissector_handle_t  zep_handle;
    static int                 lastPort;
    static gboolean            inited = FALSE;

    if ( !inited) {
        dissector_handle_t h;
        /* Get dissector handles. */
        if ( !(h = find_dissector("wpan")) ) { /* Try use built-in 802.15.4 disector */
            h = find_dissector("ieee802154");  /* otherwise use older 802.15.4 plugin disector */
        }
        ieee802154_handle = h;
        if ( !(h = find_dissector("wpan_cc24xx")) ) { /* Try use built-in 802.15.4 (Chipcon) disector */
            h = find_dissector("ieee802154_ccfcs");   /* otherwise use older 802.15.4 (Chipcon) plugin disector */
        }
        ieee802154_ccfcs_handle = h;
        zep_handle = find_dissector("zep");
        data_handle = find_dissector("data");
        inited = TRUE;
    } else {
        /* If we were already registered, de-register our dissector
         * to free the port. */
        dissector_delete_uint("udp.port", lastPort, zep_handle);
    }

    /* Register our dissector. */
    dissector_add_uint("udp.port", gPREF_zep_udp_port, zep_handle);
    lastPort = gPREF_zep_udp_port;
} /* proto_reg_handoff_zep */

