/* packet-zbee-aps.h
 * Dissector routines for the ZigBee Application Support Sub-layer (APS)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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

#ifndef PACKET_ZBEE_APS_H
#define PACKET_ZBEE_APS_H

/* ZigBee APS */
#define ZBEE_APS_FCF_FRAME_TYPE     0x03
#define ZBEE_APS_FCF_DELIVERY_MODE  0x0c
#define ZBEE_APS_FCF_INDIRECT_MODE  0x10    /* ZigBee 2004 and earlier.  */
#define ZBEE_APS_FCF_ACK_FORMAT     0x10    /* ZigBee 2007 and later.    */
#define ZBEE_APS_FCF_SECURITY       0x20
#define ZBEE_APS_FCF_ACK_REQ        0x40
#define ZBEE_APS_FCF_EXT_HEADER     0x80

#define ZBEE_APS_FCF_DATA           0x00
#define ZBEE_APS_FCF_CMD            0x01
#define ZBEE_APS_FCF_ACK            0x02

#define ZBEE_APS_FCF_UNICAST        0x00
#define ZBEE_APS_FCF_INDIRECT       0x01
#define ZBEE_APS_FCF_BCAST          0x02
#define ZBEE_APS_FCF_GROUP          0x03    /* ZigBee 2006 and later.    */

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

/* ZCL Cluster IDs - General */
#define ZBEE_ZCL_CID_BASIC                          0x0000
#define ZBEE_ZCL_CID_POWER_CONFIG                   0x0001
#define ZBEE_ZCL_CID_DEVICE_TEMP_CONFIG             0x0002
#define ZBEE_ZCL_CID_IDENTIFY                       0x0003
#define ZBEE_ZCL_CID_GROUPS                         0x0004
#define ZBEE_ZCL_CID_SCENES                         0x0005
#define ZBEE_ZCL_CID_ON_OFF                         0x0006
#define ZBEE_ZCL_CID_ON_OFF_SWITCH_CONFIG           0x0007
#define ZBEE_ZCL_CID_LEVEL_CONTROL                  0x0008
#define ZBEE_ZCL_CID_ALARMS                         0x0009
#define ZBEE_ZCL_CID_TIME                           0x000a
#define ZBEE_ZCL_CID_RSSI_LOCATION                  0x000b
#define ZBEE_ZCL_CID_ANALOG_INPUT_BASIC             0x000c
#define ZBEE_ZCL_CID_ANALOG_OUTPUT_BASIC            0x000d
#define ZBEE_ZCL_CID_ANALOG_VALUE_BASIC             0x000e
#define ZBEE_ZCL_CID_BINARY_INPUT_BASIC             0x000f
#define ZBEE_ZCL_CID_BINARY_OUTPUT_BASIC            0x0010
#define ZBEE_ZCL_CID_BINARY_VALUE_BASIC             0x0011
#define ZBEE_ZCL_CID_MULTISTATE_INPUT_BASIC         0x0012
#define ZBEE_ZCL_CID_MULTISTATE_OUTPUT_BASIC        0x0013
#define ZBEE_ZCL_CID_MULTISTATE_VALUE_BASIC         0x0014
#define ZBEE_ZCL_CID_COMMISSIONING                  0x0015
#define ZBEE_ZCL_CID_PARTITION                      0x0016
#define ZBEE_ZCL_CID_OTA_UPGRADE                    0x0019
#define ZBEE_ZCL_CID_POLL_CONTROL                   0x0020
/* */
#define ZBEE_ZCL_CID_POWER_PROFILE                  0x001a
#define ZBEE_ZCL_CID_APPLIANCE_CONTROL              0x001b

/* ZCL Cluster IDs - Closures */
#define ZBEE_ZCL_CID_SHADE_CONFIG                   0x0100
#define ZBEE_ZCL_CID_DOOR_LOCK                      0X0101

/* ZCL Cluster IDs - HVAC */
#define ZBEE_ZCL_CID_PUMP_CONFIG_CONTROL            0x0200
#define ZBEE_ZCL_CID_THERMOSTAT                     0x0201
#define ZBEE_ZCL_CID_FAN_CONTROL                    0x0202
#define ZBEE_ZCL_CID_DEHUMIDIFICATION_CONTROL       0x0203
#define ZBEE_ZCL_CID_THERMOSTAT_UI_CONFIG           0x0204

/* ZCL Cluster IDs - Lighting */
#define ZBEE_ZCL_CID_COLOR_CONTROL                  0x0300
#define ZBEE_ZCL_CID_BALLAST_CONFIG                 0x0301

/* ZCL Cluster IDs - Measurement and Sensing */
#define ZBEE_ZCL_CID_ILLUMINANCE_MEASUREMENT        0x0400
#define ZBEE_ZCL_CID_ILLUMINANCE_LEVEL_SENSING      0x0401
#define ZBEE_ZCL_CID_TEMPERATURE_MEASUREMENT        0x0402
#define ZBEE_ZCL_CID_PRESSURE_MEASUREMENT           0x0403
#define ZBEE_ZCL_CID_FLOW_MEASUREMENT               0x0404
#define ZBEE_ZCL_CID_REL_HUMIDITY_MEASUREMENT       0x0405
#define ZBEE_ZCL_CID_OCCUPANCY_SENSING              0x0406

/* ZCL Cluster IDs - Security and Safety */
#define ZBEE_ZCL_CID_IAS_ZONE                       0x0500
#define ZBEE_ZCL_CID_IAS_ACE                        0x0501
#define ZBEE_ZCL_CID_IAS_WD                         0x0502

/* ZCL Cluster IDs - Protocol Interfaces */
#define ZBEE_ZCL_CID_GENERIC_TUNNEL                 0x0600
#define ZBEE_ZCL_CID_BACNET_PROTOCOL_TUNNEL         0x0601
#define ZBEE_ZCL_CID_BACNET_ANALOG_INPUT_REG        0x0602
#define ZBEE_ZCL_CID_BACNET_ANALOG_INPUT_EXT        0x0603
#define ZBEE_ZCL_CID_BACNET_ANALOG_OUTPUT_REG       0x0604
#define ZBEE_ZCL_CID_BACNET_ANALOG_OUTPUT_EXT       0x0605
#define ZBEE_ZCL_CID_BACNET_ANALOG_VALUE_REG        0x0606
#define ZBEE_ZCL_CID_BACNET_ANALOG_VALUE_EXT        0x0607
#define ZBEE_ZCL_CID_BACNET_BINARY_INPUT_REG        0x0608
#define ZBEE_ZCL_CID_BACNET_BINARY_INPUT_EXT        0x0609
#define ZBEE_ZCL_CID_BACNET_BINARY_OUTPUT_REG       0x060a
#define ZBEE_ZCL_CID_BACNET_BINARY_OUTPUT_EXT       0x060b
#define ZBEE_ZCL_CID_BACNET_BINARY_VALUE_REG        0x060c
#define ZBEE_ZCL_CID_BACNET_BINARY_VALUE_EXT        0x060d
#define ZBEE_ZCL_CID_BACNET_MULTISTATE_INPUT_REG    0x060e
#define ZBEE_ZCL_CID_BACNET_MULTISTATE_INPUT_EXT    0x060f
#define ZBEE_ZCL_CID_BACNET_MULTISTATE_OUTPUT_REG   0x0610
#define ZBEE_ZCL_CID_BACNET_MULTISTATE_OUTPUT_EXT   0x0611
#define ZBEE_ZCL_CID_BACNET_MULTISTATE_VALUE_REG    0x0612
#define ZBEE_ZCL_CID_BACNET_MULTISTATE_VALUE_EXT    0x0613

/* ZCL Cluster IDs - Smart Energy */
#define ZBEE_ZCL_CID_PRICE                          0x0700
#define ZBEE_ZCL_CID_DEMAND_RESPONSE_LOAD_CONTROL   0x0701
#define ZBEE_ZCL_CID_SIMPLE_METERING                0x0702
#define ZBEE_ZCL_CID_MESSAGE                        0x0703
#define ZBEE_ZCL_CID_SMART_ENERGY_TUNNELING         0x0704
#define ZBEE_ZCL_CID_PRE_PAYMENT                    0x0705

/* ZCL Cluster IDs - Home Automation */
#define ZBEE_ZCL_CID_APPLIANCE_IDENTIFICATION       0x0b00
#define ZBEE_ZCL_CID_METER_IDENTIFICATION           0x0b01
#define ZBEE_ZCL_CID_APPLIANCE_EVENTS_AND_ALERT     0x0b02
#define ZBEE_ZCL_CID_APPLIANCE_STATISTICS           0x0b03

/* ZCL Test Profile #2 Clusters */
#define ZBEE_APS_T2_CID_TCP                         0x0001
#define ZBEE_APS_T2_CID_RESPC                       0x0002
#define ZBEE_APS_T2_CID_RETPC                       0x0003
#define ZBEE_APS_T2_CID_PCR                         0x0004
#define ZBEE_APS_T2_CID_BTREQ                       0x001c
#define ZBEE_APS_T2_CID_BTGREQ                      0x001d
#define ZBEE_APS_T2_CID_BTRES                       0x0054
#define ZBEE_APS_T2_CID_BTRES_S_SBT                 0x00
#define ZBEE_APS_T2_CID_BTRES_S_TFOFA               0x01
#define ZBEE_APS_T2_CID_BTGRES                      0x0055
#define ZBEE_APS_T2_CID_RDREQ                       0x1000
#define ZBEE_APS_T2_CID_RDRES                       0x1001
#define ZBEE_APS_T2_CID_FREQ                        0xa0a8
#define ZBEE_APS_T2_CID_FRES                        0xe000
#define ZBEE_APS_T2_CID_FNDR                        0xe001
#define ZBEE_APS_T2_CID_BR                          0xf000
#define ZBEE_APS_T2_CID_BTADR                       0xf001
#define ZBEE_APS_T2_CID_BTARXOWIDR                  0xf00a
#define ZBEE_APS_T2_CID_BTARACR                     0xf00e

/*  Structure to contain the APS frame information */
typedef struct{
    gboolean    indirect_mode;  /* ZigBee 2004 and Earlier  */
    guint8      type;
    guint8      delivery;
    gboolean    ack_format;     /* ZigBee 2007 and Later    */
    gboolean    security;
    gboolean    ack_req;
    gboolean    ext_header;     /* ZigBee 2007 and Later    */

    guint8      dst;
    guint16     group;          /* ZigBee 2006 and Later    */
    guint16     profile;
    guint8      src;
    guint8      counter;

    /* Fragmentation Fields. */
    guint8      fragmentation;  /* ZigBee 2007 and Later    */
    guint8      block_number;   /* ZigBee 2007 and Later    */
    guint8      ack_bitfield;   /* ZigBee 2007 and Later    */

    /* Some helpers for the upper layers. */
    gboolean    profile_present;
    gboolean    dst_present;
    gboolean    src_present;
} zbee_aps_packet;

/**************************************
 * Value Strings
 **************************************
 */

extern const value_string zbee_aps_cid_names[];

#endif /* PACKET_ZBEE_APS_H*/
