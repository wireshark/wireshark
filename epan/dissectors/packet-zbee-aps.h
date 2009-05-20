/* packet-zbee-aps.h
 * Dissector routines for the ZigBee Application Support Sub-layer (APS)
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
 */

#ifndef PACKET_ZBEE_APS_H
#define PACKET_ZBEE_APS_H

/*  Structure to contain the APS frame information */
typedef struct{
    gboolean    indirect_mode;  // ZigBee 2004 and Earlier
    gboolean    ack_mode;       // ZigBee 2007 and Later
    gboolean    security;
    gboolean    ack_req;
    gboolean    ext_header;     // ZigBee 2007 and Later
    guint8      type;
    guint8      delivery;

    guint8      dst;
    guint16     group;          // ZigBee 2006 and Later
    guint16     cluster;
    guint16     profile;
    guint8      src;
    guint8      counter;

    /* Fragmentation Fields. */
    guint8      fragmentation;  // ZigBee 2007 and Later
    guint8      block_number;   // ZigBee 2007 and Later
    guint8      ack_bitfield;   // ZigBee 2007 and Later

    /* Some helpers for the upper layers. */
    gboolean    profile_present;
    gboolean    dst_present;
    gboolean    src_present;
} zbee_aps_packet;

#define ZBEE_APS_FCF_FRAME_TYPE     0x03
#define ZBEE_APS_FCF_DELIVERY_MODE  0x0c
#define ZBEE_APS_FCF_INDIRECT_MODE  0x10    // ZigBee 2004 and earlier.
#define ZBEE_APS_FCF_ACK_MODE       0x10    // ZigBee 2007 and later.
#define ZBEE_APS_FCF_SECURITY       0x20
#define ZBEE_APS_FCF_ACK_REQ        0x40
#define ZBEE_APS_FCF_EXT_HEADER     0x80

#define ZBEE_APS_FCF_DATA           0x00
#define ZBEE_APS_FCF_CMD            0x01
#define ZBEE_APS_FCF_ACK            0x02

#define ZBEE_APS_FCF_UNICAST        0x00
#define ZBEE_APS_FCF_INDIRECT       0x01
#define ZBEE_APS_FCF_BCAST          0x02
#define ZBEE_APS_FCF_GROUP          0x03    // ZigBee 2006 and later.

#define ZBEE_APS_EXT_FCF_FRAGMENT           0x03
#define ZBEE_APS_EXT_FCF_FRAGMENT_NONE      0x00
#define ZBEE_APS_EXT_FCF_FRAGMENT_FIRST     0x01
#define ZBEE_APS_EXT_FCF_FRAGMENT_MIDDLE    0x02

#define ZBEE_APS_CMD_SKKE1                  0x01
#define ZBEE_APS_CMD_SKKE2                  0x02
#define ZBEE_APS_CMD_SKKE3                  0x03
#define ZBEE_APS_CMD_SKKE4                  0x04
#define ZBEE_APS_CMD_TRANSPORT_KEY          0x05
#define ZBEE_APS_CMD_UPDATE_DEVICE          0x06
#define ZBEE_APS_CMD_REMOVE_DEVICE          0x07
#define ZBEE_APS_CMD_REQUEST_KEY            0x08
#define ZBEE_APS_CMD_SWITCH_KEY             0x09
#define ZBEE_APS_CMD_EA_INIT_CHLNG          0x0a
#define ZBEE_APS_CMD_EA_RESP_CHLNG          0x0b
#define ZBEE_APS_CMD_EA_INIT_MAC_DATA       0x0c
#define ZBEE_APS_CMD_EA_RESP_MAC_DATA       0x0d
#define ZBEE_APS_CMD_TUNNEL                 0x0e

#define ZBEE_APS_CMD_KEY_TC_MASTER          0x00
#define ZBEE_APS_CMD_KEY_STANDARD_NWK       0x01
#define ZBEE_APS_CMD_KEY_APP_MASTER         0x02
#define ZBEE_APS_CMD_KEY_APP_LINK           0x03
#define ZBEE_APS_CMD_KEY_TC_LINK            0x04
#define ZBEE_APS_CMD_KEY_HIGH_SEC_NWK       0x05

#define ZBEE_APS_CMD_SKKE_DATA_LENGTH       16
#define ZBEE_APS_CMD_KEY_LENGTH             16

#define ZBEE_APS_CMD_REQ_NWK_KEY            0x01
#define ZBEE_APS_CMD_REQ_APP_KEY            0x02

#define ZBEE_APS_CMD_UPDATE_STANDARD_SEC_REJOIN     0x00
#define ZBEE_APS_CMD_UPDATE_STANDARD_UNSEC_JOIN     0x01
#define ZBEE_APS_CMD_UPDATE_LEAVE                   0x02
#define ZBEE_APS_CMD_UPDATE_STANDARD_UNSEC_REJOIN   0x03
#define ZBEE_APS_CMD_UPDATE_HIGH_SEC_REJOIN         0x04
#define ZBEE_APS_CMD_UPDATE_HIGH_UNSEC_JOIN         0x05
#define ZBEE_APS_CMD_UPDATE_HIGH_UNSEC_REJOIN       0x07

#define ZBEE_APS_CMD_EA_KEY_NWK             0x00
#define ZBEE_APS_CMD_EA_KEY_LINK            0x01
#define ZBEE_APS_CMD_EA_CHALLENGE_LENGTH    16
#define ZBEE_APS_CMD_EA_MAC_LENGTH          16
#define ZBEE_APS_CMD_EA_DATA_LENGTH         4

/* Fields for ZigBee 2004 and earlier. */
#define ZBEE_APP_TYPE                       0xF0
#define ZBEE_APP_COUNT                      0x0F

#define ZBEE_APP_TYPE_KVP                   0x01
#define ZBEE_APP_TYPE_MSG                   0x02

#define ZBEE_APP_KVP_CMD                    0x0F
#define ZBEE_APP_KVP_TYPE                   0xF0

#define ZBEE_APP_KVP_SET                    0x01
#define ZBEE_APP_KVP_EVENT                  0x02
#define ZBEE_APP_KVP_GET_ACK                0x04
#define ZBEE_APP_KVP_SET_ACK                0x05
#define ZBEE_APP_KVP_EVENT_ACK              0x06
#define ZBEE_APP_KVP_GET_RESP               0x08
#define ZBEE_APP_KVP_SET_RESP               0x09
#define ZBEE_APP_KVP_EVENT_RESP             0x0A

#define ZBEE_APP_KVP_NO_DATA                0x00
#define ZBEE_APP_KVP_UINT8                  0x01
#define ZBEE_APP_KVP_INT8                   0x02
#define ZBEE_APP_KVP_UINT16                 0x03
#define ZBEE_APP_KVP_INT16                  0x04
#define ZBEE_APP_KVP_FLOAT16                0x0B
#define ZBEE_APP_KVP_ABS_TIME               0x0C
#define ZBEE_APP_KVP_REL_TIME               0x0D
#define ZBEE_APP_KVP_CHAR_STRING            0x0E
#define ZBEE_APP_KVP_OCT_STRING             0x0F

#define ZBEE_APP_KVP_OVERHEAD               4

#endif /* PACKET_ZBEE_APS_H*/
