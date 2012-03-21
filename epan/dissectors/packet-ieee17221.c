/* packet-ieee17221.c
 * Dissector for IEEE P1722.1
 * Copyright 2011-2012, Thomas Bottom <tom.bottom@labxtechnologies.com>
 *                      Chris Pane <chris.pane@labxtechnologies.com>
 *
 * Copyright 2011, Andy Lucas <andy@xmos.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

/* DEV NOTES
 * This file uses 3 space indentation
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* #include <stdio.h> */

#include <epan/packet.h>
#include <epan/etypes.h>

/* 1722.1 ADP Offsets */
#define ADP_CD_OFFSET                       0
#define ADP_VERSION_OFFSET                  1
#define ADP_VALID_TIME_OFFSET               2
#define ADP_CD_LENGTH_OFFSET                3
#define ADP_ENTITY_GUID_OFFSET              4
#define ADP_VENDOR_ID_OFFSET                12
#define ADP_MODEL_ID_OFFSET                 16
#define ADP_ENTITY_CAP_OFFSET               20
#define ADP_TALKER_STREAM_SRCS_OFFSET       24
#define ADP_TALKER_CAP_OFFSET               26
#define ADP_LISTENER_STREAM_SINKS_OFFSET    28
#define ADP_LISTENER_CAP_OFFSET             30
#define ADP_CONTROLLER_CAP_OFFSET           32
#define ADP_AVAIL_INDEX_OFFSET              36
#define ADP_AS_GM_ID_OFFSET                 40
#define ADP_DEF_AUDIO_FORMAT_OFFSET         48
#define ADP_CHAN_FORMAT_OFFSET              50
#define ADP_DEF_VIDEO_FORMAT_OFFSET         52
#define ADP_ASSOC_ID_OFFSET                 56
#define ADP_ENTITY_TYPE_OFFSET              64

/* Bit Field Masks */

#define ADP_MSG_TYPE_MASK                   0x0f
#define ADP_VALID_TIME_MASK                 0xf8
#define ADP_CD_LENGTH_MASK                  0x07ff

/* message_type */

#define ADP_ENTITY_AVAILABLE_MESSAGE        0x00
#define ADP_ENTITY_DEPARTING_MESSAGE        0x01
#define ADP_ENTITY_DISCOVER_MESSAGE         0x02

/* entity_capabilities_flags                            */
#define ADP_AVDECC_IP_BITMASK                0x01
#define ADP_ZERO_CONF_BITMASK                0x02
#define ADP_GATEWAY_ENTITY_BITMASK           0x04
#define ADP_AVDECC_CONTROL_BITMASK           0x08
#define ADP_LEGACY_AVC_BITMASK               0x10
#define ADP_ASSOC_ID_SUPPORT_BITMASK         0x20
#define ADP_ASSOC_ID_VALID_BITMASK           0x40

/* talker capabilities flags                            */
#define ADP_TALK_IMPLEMENTED_BITMASK         0x0001
#define ADP_TALK_OTHER_SRC_BITMASK           0x0200
#define ADP_TALK_CONTROL_SRC_BITMASK         0x0400
#define ADP_TALK_MEDIA_CLK_SRC_BITMASK       0x0800
#define ADP_TALK_SMPTE_SRC_BITMASK           0x1000

#define ADP_TALK_MIDI_SRC_BITMASK            0x2000
#define ADP_TALK_AUDIO_SRC_BITMASK           0x4000
#define ADP_TALK_VIDEO_SRC_BITMASK           0x8000

/* listener capabilities flags                            */
#define ADP_LIST_IMPLEMENTED_BITMASK         0x0001
#define ADP_LIST_OTHER_SINK_BITMASK          0x0200
#define ADP_LIST_CONTROL_SINK_BITMASK        0x0400
#define ADP_LIST_MEDIA_CLK_SINK_BITMASK      0x0800
#define ADP_LIST_SMPTE_SINK_BITMASK          0x1000
#define ADP_LIST_MIDI_SINK_BITMASK           0x2000
#define ADP_LIST_AUDIO_SINK_BITMASK          0x4000
#define ADP_LIST_VIDEO_SINK_BITMASK          0x8000

/* Controller capabilities flags                        */
#define ADP_CONT_IMPLEMENTED_BITMASK         0x00000001
#define ADP_CONT_LAYER3_PROXY_BITMASK        0x00000002

/* Default audio formats fields */
#define ADP_DEF_AUDIO_SAMPLE_RATES_MASK      0xFC
#define ADP_DEF_AUDIO_MAX_CHANS_MASK         0x03FC
#define ADP_DEF_AUDIO_SAF_MASK               0x0002
#define ADP_DEF_AUDIO_FLOAT_MASK             0x0001

/* Default sample rates flags */
#define ADP_SAMP_RATE_44K1_BITMASK           0x01<<2
#define ADP_SAMP_RATE_48K_BITMASK            0x02<<2
#define ADP_SAMP_RATE_88K2_BITMASK           0x04<<2
#define ADP_SAMP_RATE_96K_BITMASK            0x08<<2
#define ADP_SAMP_RATE_176K4_BITMASK          0x10<<2
#define ADP_SAMP_RATE_192K_BITMASK           0x20<<2

/* channel_formats flags */

#define ADP_CHAN_FORMAT_MONO                        (0x00000001)
#define ADP_CHAN_FORMAT_2CH                         (0x00000002)
#define ADP_CHAN_FORMAT_3CH                         (0x00000004)
#define ADP_CHAN_FORMAT_4CH                         (0x00000008)
#define ADP_CHAN_FORMAT_5CH                         (0x00000010)
#define ADP_CHAN_FORMAT_6CH                         (0x00000020)
#define ADP_CHAN_FORMAT_7CH                         (0x00000040)
#define ADP_CHAN_FORMAT_8CH                         (0x00000080)
#define ADP_CHAN_FORMAT_10CH                        (0x00000100)
#define ADP_CHAN_FORMAT_12CH                        (0x00000200)
#define ADP_CHAN_FORMAT_14CH                        (0x00000400)
#define ADP_CHAN_FORMAT_16CH                        (0x00000800)
#define ADP_CHAN_FORMAT_18CH                        (0x00001000)
#define ADP_CHAN_FORMAT_20CH                        (0x00002000)
#define ADP_CHAN_FORMAT_22CH                        (0x00004000)
#define ADP_CHAN_FORMAT_24CH                        (0x00008000)

/******************************************************************************/
/* 1722.1 ACMP Offsets */
#define ACMP_CD_OFFSET                      0
#define ACMP_VERSION_OFFSET                 1
#define ACMP_STATUS_FIELD_OFFSET            2
#define ACMP_CD_LENGTH_OFFSET               3
#define ACMP_STREAM_ID_OFFSET               4
#define ACMP_CONTROLLER_GUID_OFFSET         12
#define ACMP_TALKER_GUID_OFFSET             20
#define ACMP_LISTENER_GUID_OFFSET           28
#define ACMP_TALKER_UNIQUE_ID_OFFSET        36
#define ACMP_LISTENER_UNIQUE_ID_OFFSET      38
#define ACMP_DEST_MAC_OFFSET                40
#define ACMP_CONNECTION_COUNT_OFFSET        46
#define ACMP_SEQUENCE_ID_OFFSET             48
#define ACMP_FLAGS_OFFSET                   50
#define ACMP_DEFAULT_FORMAT_OFFSET          52

/* Bit Field Masks */

#define ACMP_MSG_TYPE_MASK                  0x0f
#define ACMP_STATUS_FIELD_MASK              0xf8
#define ACMP_CD_LENGTH_MASK                 0x07ff

/* message_type */

#define ACMP_CONNECT_TX_COMMAND             0
#define ACMP_CONNECT_TX_RESPONSE            1
#define ACMP_DISCONNECT_TX_COMMAND          2
#define ACMP_DISCONNECT_TX_RESPONSE         3
#define ACMP_GET_TX_STATE_COMMAND           4
#define ACMP_GET_TX_STATE_RESPONSE          5
#define ACMP_CONNECT_RX_COMMAND             6
#define ACMP_CONNECT_RX_RESPONSE            7
#define ACMP_DISCONNECT_RX_COMMAND          8
#define ACMP_DISCONNECT_RX_RESPONSE         9
#define ACMP_GET_RX_STATE_COMMAND           10
#define ACMP_GET_RX_STATE_RESPONSE          11
#define ACMP_GET_TX_CONNECTION_COMMAND      12
#define ACMP_GET_TX_CONNECTION_RESPONSE     13

/* status_field */

#define ACMP_STATUS_SUCCESS                             0
#define ACMP_STATUS_LISTENER_UNKNOWN_ID                 1
#define ACMP_STATUS_TALKER_UNKNOWN_ID                   2
#define ACMP_STATUS_TALKER_DEST_MAC_FAIL                3
#define ACMP_STATUS_TALKER_NO_STREAM_INDEX              4
#define ACMP_STATUS_TALKER_NO_BANDWIDTH                 5
#define ACMP_STATUS_TALKER_EXCLUSIVE                    6
#define ACMP_STATUS_LISTENER_TALKER_TIMEOUT             7
#define ACMP_STATUS_LISTENER_EXCLUSIVE                  8
#define ACMP_STATUS_STATE_UNAVAILABLE                   9
#define ACMP_STATUS_NOT_CONNECTED                       10
#define ACMP_STATUS_NO_SUCH_CONNECTION                  11
#define ACMP_STATUS_COULD_NOT_SEND_MESSAGE              12
#define ACMP_STATUS_LISTENER_DEFAULT_FORMAT_INVALID     13
#define ACMP_STATUS_TALKER_DEFAULT_FORMAT_INVALID       14
#define ACMP_STATUS_DEFAULT_SET_DIFFERENT               15
#define ACMP_STATUS_NOT_SUPPORTED                       31

/* ACMP flags                                   */
#define ACMP_FLAG_CLASS_B_BITMASK               0x0001
#define ACMP_FLAG_FAST_CONNECT_BITMASK          0x0002
#define ACMP_FLAG_SAVED_STATE_BITMASK           0x0004
#define ACMP_FLAG_STREAMING_WAIT_BITMASK        0x0008

/******************************************************************************/
/* 1722.1 AECP Offsets */

#define AECP_VERSION_OFFSET                        1
#define AECP_TARGET_GUID_OFFSET                    4
#define AECP_CONTROLLER_GUID_OFFSET                12
#define AECP_SEQUENCE_ID_OFFSET                    20
#define AECP_U_FLAG_OFFSET                         22
#define AECP_COMMAND_TYPE_OFFSET                   22
#define AECP_UNLOCK_FLAG_OFFSET                    27
#define AECP_LOCKED_GUID_OFFSET                    28
#define AECP_CD_LENGTH_OFFSET                      2
#define AECP_FLAGS_OFFSET                          24
#define AECP_LOCKED_GUID_OFFSET                    28
#define AECP_CONFIGURATION_OFFSET                  24
#define AECP_DESCRIPTOR_TYPE_OFFSET_28             28
#define AECP_DESCRIPTOR_ID_OFFSET_30               30
#define AECP_DESCRIPTOR_TYPE_OFFSET                24
#define AECP_DESCRIPTOR_ID_OFFSET                  26
#define AECP_PERSISTENT_FLAG_OFFSET                24
#define AECP_OWNER_GUID_OFFSET                     28
#define AECP_CLOCK_SOURCE_ID_OFFSET                24
#define AECP_SOURCE_TYPE_OFFSET                    28
#define AECP_SOURCE_ID_OFFSET                      30
#define AECP_MATRIX_COLUMN_OFFSET                  28
#define AECP_MATRIX_ROW_OFFSET                     30
#define AECP_MATRIX_REGION_WIDTH_OFFSET            32
#define AECP_MATRIX_REGION_HEIGHT_OFFSET           34
#define AECP_MATRIX_REP_OFFSET                     36
#define AECP_MATRIX_DIRECTION_OFFSET               36
#define AECP_MATRIX_VALUE_COUNT_OFFSET             36
#define AECP_MATRIX_ITEM_OFFSET_OFFSET             38
#define AECP_MATRIX_AFFECTED_ITEM_COUNT_OFFSET     40
#define AECP_FLAGS28_OFFSET                        28
#define AECP_STREAM_CLOCK_SOURCE_ID_OFFSET         58
#define AECP_STREAM_FORMAT_OFFSET                  28
#define AECP_OFFSET_GET_STREAM_INFO_STREAM_FORMAT  32
#define AECP_OFFSET_GET_STREAM_INFO_STREAM_ID      40
#define AECP_MSRP_ACC_LAT_OFFSET                   56
#define AECP_SET_MSRP_ACC_LAT_OFFSET               32
#define AECP_DEST_MAC_OFFSET                       60
#define AECP_DEFAULT_FORMAT_OFFSET                 68
#define AECP_NAME_INDEX_OFFSET                     28
#define AECP_NAME_OFFSET                           32
#define AECP_KEYCHAIN_ID_OFFSET                    24
#define AECP_KEY_ID_OFFSET                         24
#define AECP_KEY_LENGTH_OFFSET                     26
#define AECP_SIGNATURE_INFO_OFFSET                 28
#define AECP_SIGNATURE_ID_OFFSET                   28
#define AECP_SIGNATURE_LENGTH_OFFSET               30
#define AECP_KEY_PERMISSIONS_OFFSET                32
#define AECP_KEY_AND_SIG_OFFSET                    36
#define AECP_AUTH_SIG_INFO_OFFSET                  24
#define AECP_AUTH_SIG_ID_OFFSET                    24
#define AECP_AUTH_SIG_LENGTH_OFFSET                26
#define AECP_AUTH_KEY_PERM_OFFSET                  28
#define AECP_AUTH_SIG_OFFSET                       32
#define AECP_MEDIA_FORMAT_OFFSET                   28
#define AECP_ADDRESS_TYPE_OFFSET                   24
#define AECP_ADDRESS_OFFSET                        28
#define AECP_QUERY_PERIOD_OFFSET                   24
#define AECP_QUERY_LIMIT_OFFSET                    26
#define AECP_QUERY_TYPE_OFFSET                     28
#define AECP_QUERY_ID_OFFSET                       30
#define AECP_QUERY_DESC_T_OFFSET                   32
#define AECP_QUERY_DESC_ID_OFFSET                  34
#define AECP_DEREG_QUERY_ID_OFFSET                 24
#define AECP_COUNT_OFFSET                          24
#define AECP_VALUES_COUNT_OFFSET                   28
#define AECP_VALUES_OFFSET                         30
#define AECP_OPERATION_ID_OFFSET                   28
#define AECP_OPERATION_TYPE_OFFSET                 30
#define AECP_PERCENT_COMPLETE_OFFSET               30
#define AECP_KEY_COUNT_OFFSET                      24
#define AECP_RELEASE_FLAG_OFFSET                   24
#define AECP_ASSOCIATION_ID_OFFSET                 56
#define AECP_DESCRIPTORS_OFFSET_DQN                28


#define AECP_FLAGS_32_OFFSET                       28

#define AECP_OFFSET_ACQUIRE_ENTITY_FLAGS           24
#define AECP_OFFSET_ACQUIRE_ENTITY_OWNER_GUID      28
#define AECP_OFFSET_ACQUIRE_ENTITY_DESCRIPTOR_TYPE 36
#define AECP_OFFSET_ACQUIRE_ENTITY_DESCRIPTOR_ID   38

#define AECP_OFFSET_CLOCK_SOURCE_DESCRIPTOR_TYPE   24
#define AECP_OFFSET_CLOCK_SOURCE_DESCRIPTOR_ID     26
#define AECP_OFFSET_CLOCK_SOURCE_CLOCK_SOURCE_ID   28

/* counters offsets */
#define AECP_OFFSET_COUNTERS_VALID_GPTP_GM_CHANGED          0
#define AECP_OFFSET_COUNTERS_VALID_GPTP_UNLOCKED            4
#define AECP_OFFSET_COUNTERS_VALID_GPTP_LOCKED              8
#define AECP_OFFSET_COUNTERS_VALID_MEDIA_UNLOCKED           12
#define AECP_OFFSET_COUNTERS_VALID_MEDIA_LOCKED             16
#define AECP_OFFSET_COUNTERS_VALID_MEDIA_SEQ_ERROR          20
#define AECP_OFFSET_COUNTERS_VALID_STREAM_RESET             24
#define AECP_OFFSET_COUNTERS_VALID_SRP_REFUSED              28
#define AECP_OFFSET_COUNTERS_VALID_BACKUP_STREAM_SWITCH     32
#define AECP_OFFSET_COUNTERS_VALID_MISSED_AVDECC_RESPONSE   36
#define AECP_OFFSET_COUNTERS_VALID_REFUSED_AVDECC_COMMAND   40
#define AECP_OFFSET_COUNTERS_VALID_SEQ_NUM_MISMATCH         44
#define AECP_OFFSET_COUNTERS_VALID_MEDIA_CLOCK_TOGGLES      48
#define AECP_OFFSET_COUNTERS_VALID_TIMESTAMP_UNCERTAINS     52
#define AECP_OFFSET_COUNTERS_VALID_TIMESTAMP_VALIDS         56
#define AECP_OFFSET_COUNTERS_VALID_UNSUPPORTED_FORMATS      60
#define AECP_OFFSET_COUNTERS_VALID_BAD_PRESENTATION_TIMES   64
#define AECP_OFFSET_COUNTERS_VALID_SRP_LATENCY_VIOLATIONS   68
#define AECP_OFFSET_COUNTERS_VALID_PACKETS_TX               72
#define AECP_OFFSET_COUNTERS_VALID_PACKETS_RX               76
#define AECP_OFFSET_COUNTERS_VALID_PACKETS_OF_INTEREST_RX   80
#define AECP_OFFSET_COUNTERS_VALID_TALKER_BW_RESERVED       84
#define AECP_OFFSET_COUNTERS_VALID_RESERVED1                88
#define AECP_OFFSET_COUNTERS_VALID_RESERVED2                92
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_1        96
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_2        100
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_3        104
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_4        108
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_5        112
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_6        116
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_7        120
#define AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_8        124

/* aecp_message_type */
/* 1722.1 draft 2011-11-14 table 9.1 */
#define AECP_AEM_COMMAND_MESSAGE                0
#define AECP_AEM_RESPONSE_MESSAGE               1
#define AECP_ADDRESS_ACCESS_COMMAND_MESSAGE     2
#define AECP_ADDRESS_ACCESS_RESPONSE_MESSAGE    3
#define AECP_AVC_COMMAND_MESSAGE                4
#define AECP_AVC_RESPONSE_MESSAGE               5
#define AECP_VENDOR_UNIQUE_COMMAND_MESSAGE      6
#define AECP_VENDOR_UNIQUE_RESPONSE_MESSAGE     7
#define AECP_EXTENDED_COMMAND_MESSAGE           14
#define AECP_EXTENDED_RESPONSE_MESSAGE          15

/* aecp status field */
/* 1722.1 draft 2011-11-14 table 9.2 */
#define AECP_STATUS_SUCCESS          0
#define AECP_STATUS_NOT_IMPLEMENTED  1

/* AECP Address Type */
/* 1722.1 draft 2011-11-14 sec 7.4.35.1 table 7.82 */
#define AECP_ADDRESS_MAC  0x0000
#define AECP_ADDRESS_IPV4 0x0001
#define AECP_ADDRESS_IPV6 0x0002

/* AECP Direction Field Values */
/* 1722.1 draft 2011-11-14 table 7.78 */
#define AECP_DIRECTION_HORIZONTAL 0
#define AECP_DIRECTION_VERTICAL   1

/* AECP Keychain Type Values */
/* 1722.1 draft 2011-11-14 table 7.80 */
#define AECP_KEYCHAIN_NONE         0x0
#define AECP_KEYCHAIN_MANUFACTURER 0x1
#define AECP_KEYCHAIN_PRODUCT      0x2
#define AECP_KEYCHAIN_ENTITY       0x3
#define AECP_KEYCHAIN_USER         0x4

/* AECP Command Codes */
/* IEEE 1722.1 draft 2011-11-14 Table 7.74 */
#define AECP_COMMAND_LOCK_ENTITY                    0x0000
#define AECP_COMMAND_READ_DESCRIPTOR                0x0001
#define AECP_COMMAND_WRITE_DESCRIPTOR               0x0002
#define AECP_COMMAND_ACQUIRE_ENTITY                 0x0003
#define AECP_COMMAND_CONTROLLER_AVAILABLE           0x0004
#define AECP_COMMAND_SET_CLOCK_SOURCE               0x0005
#define AECP_COMMAND_GET_CLOCK_SOURCE               0x0006
#define AECP_COMMAND_SET_STREAM_FORMAT              0x0007
#define AECP_COMMAND_GET_STREAM_FORMAT              0x0008
#define AECP_COMMAND_SET_CONFIGURATION              0x0009
#define AECP_COMMAND_GET_CONFIGURATION              0x000a
#define AECP_COMMAND_SET_CONTROL_VALUE              0x000b
#define AECP_COMMAND_GET_CONTROL_VALUE              0x000c
#define AECP_COMMAND_SET_SIGNAL_SELECTOR            0x000d
#define AECP_COMMAND_GET_SIGNAL_SELECTOR            0x000e
#define AECP_COMMAND_SET_MIXER                      0x000f
#define AECP_COMMAND_GET_MIXER                      0x0010
#define AECP_COMMAND_SET_MATRIX                     0x0011
#define AECP_COMMAND_GET_MATRIX                     0x0012
#define AECP_COMMAND_START_STREAMING                0x0013
#define AECP_COMMAND_STOP_STREAMING                 0x0014
#define AECP_COMMAND_SET_STREAM_INFO                0x0015
#define AECP_COMMAND_GET_STREAM_INFO                0x0016
#define AECP_COMMAND_SET_NAME                       0x0017
#define AECP_COMMAND_GET_NAME                       0x0018
#define AECP_COMMAND_SET_ASSOCIATION_ID             0x0019
#define AECP_COMMAND_GET_ASSOCIATION_ID             0x001a
#define AECP_COMMAND_AUTH_ADD_KEY                   0x001b
#define AECP_COMMAND_AUTH_GET_KEY                   0x001c
#define AECP_COMMAND_AUTHENTICATE                   0x001d
#define AECP_COMMAND_GET_COUNTERS                   0x001e
#define AECP_COMMAND_REBOOT                         0x001f
#define AECP_COMMAND_SET_MEDIA_FORMAT               0x0020
#define AECP_COMMAND_GET_MEDIA_FORMAT               0x0021
#define AECP_COMMAND_REGISTER_STATE_NOTIFICATION    0x0022
#define AECP_COMMAND_DEREGISTER_STATE_NOTIFICATION  0x0023
#define AECP_COMMAND_REGISTER_QUERY_NOTIFICATION    0x0024
#define AECP_COMMAND_DEREGISTER_QUERY_NOTIFICATION  0x0025
#define AECP_COMMAND_IDENTIFY_NOTIFICATION          0x0026
#define AECP_COMMAND_STATE_CHANGE_NOTIFICATION      0x0027
#define AECP_COMMAND_INCREMENT_CONTROL_VALUE        0x0028
#define AECP_COMMAND_DECREMENT_CONTROL_VALUE        0x0029
#define AECP_COMMAND_START_OPERATION                0x002a
#define AECP_COMMAND_ABORT_OPERATION                0x002b
#define AECP_COMMAND_OPERATION_STATUS               0x002c
#define AECP_COMMAND_AUTH_GET_KEY_COUNT             0x002d
#define AECP_COMMAND_GET_AS_PATH                    0x002e
#define AECP_COMMAND_DEAUTHENTICATE                 0x002f
#define AECP_COMMAND_AUTH_REVOKE_KEY                0x0030
/* 0x002e - 0x7ffe RESERVED for future use */
#define AECP_COMMAND_EXPANSION                      0x7fff /* reserved */

/* AEM common format packet STATUS field values */
/* IEEE 1722.1 draft 2011-11-14 Table 7.75 */
#define AEM_STATUS_SUCCESS                 0
#define AEM_STATUS_NOT_IMPLEMENTED         1
#define AEM_STATUS_NO_SUCH_DESCRIPTOR      2
#define AEM_STATUS_ENTITY_LOCKED           3
#define AEM_STATUS_ENTITY_ACQUIRED         4
#define AEM_STATUS_NOT_AUTHORIZED          5
#define AEM_STATUS_INSUFFICIENT_PRIVILEGES 6
#define AEM_STATUS_BAD_ARGUMENTS           7
#define AEM_STATUS_NO_RESOURCES            8
#define AEM_STATUS_IN_PROGRESS             9
/* 10 - 31 RESERVED */

/* * * * AEM DESCRIPTOR TYPES - TABLE 7.1 * * * */
#define AEM_DESCRIPTOR_ENTITY               0x0000
#define AEM_DESCRIPTOR_CONFIGURATION        0x0001
#define AEM_DESCRIPTOR_AUDIO                0x0002
#define AEM_DESCRIPTOR_VIDEO                0x0003
#define AEM_DESCRIPTOR_SENSOR               0x0004
#define AEM_DESCRIPTOR_STREAM_INPUT         0x0005
#define AEM_DESCRIPTOR_STREAM_OUTPUT        0x0006
#define AEM_DESCRIPTOR_EXTERNAL_JACK_INPUT  0x0007
#define AEM_DESCRIPTOR_EXTERNAL_JACK_OUTPUT 0x0008
#define AEM_DESCRIPTOR_AUDIO_PORT_INPUT     0x0009
#define AEM_DESCRIPTOR_AUDIO_PORT_OUTPUT    0x000a
#define AEM_DESCRIPTOR_VIDEO_PORT_INPUT     0x000b
#define AEM_DESCRIPTOR_VIDEO_PORT_OUTPUT    0x000c
#define AEM_DESCRIPTOR_EXTERNAL_PORT_INPUT  0x000d
#define AEM_DESCRIPTOR_EXTERNAL_PORT_OUTPUT 0x000e
#define AEM_DESCRIPTOR_SENSOR_PORT_INPUT    0x000f
#define AEM_DESCRIPTOR_SENSOR_PORT_OUTPUT   0x0010
#define AEM_DESCRIPTOR_INTERNAL_PORT_INPUT  0x0011
#define AEM_DESCRIPTOR_INTERNAL_PORT_OUTPUT 0x0012
#define AEM_DESCRIPTOR_AVB_INTERFACE        0x0013
#define AEM_DESCRIPTOR_CLOCK_SOURCE         0x0014
#define AEM_DESCRIPTOR_AUDIO_MAP            0x0015
#define AEM_DESCRIPTOR_AUDIO_CLUSTER        0x0016
#define AEM_DESCRIPTOR_CONTROL              0x0017
#define AEM_DESCRIPTOR_SIGNAL_SELECTOR      0x0018
#define AEM_DESCRIPTOR_MIXER                0x0019
#define AEM_DESCRIPTOR_MATRIX               0x001a
#define AEM_DESCRIPTOR_LOCALE               0x001b
#define AEM_DESCRIPTOR_STRINGS              0x001c
#define AEM_DESCRIPTOR_MATRIX_SIGNAL        0x001d
#define AEM_DESCRIPTOR_MEMORY_OBJECT        0x001e
#define AEM_DESCRIPTOR_INVALID              0xffff

/* AEM JACK TYPES (Table 7.14) */
#define AEM_JACKTYPE_SPEAKER              0x0000
#define AEM_JACKTYPE_HEADPHONE            0x0001
#define AEM_JACKTYPE_ANALOG_MICROPHONE    0x0002
#define AEM_JACKTYPE_SPDIF                0x0003
#define AEM_JACKTYPE_ADAT                 0x0004
#define AEM_JACKTYPE_TDIF                 0x0005
#define AEM_JACKTYPE_MADI                 0x0006
#define AEM_JACKTYPE_UNBALANCED_ANALOG    0x0007
#define AEM_JACKTYPE_BALANCED_ANALOG      0x0008
#define AEM_JACKTYPE_DIGITAL              0x0009
#define AEM_JACKTYPE_MIDI                 0x000a
#define AEM_JACKTYPE_AES_EBU              0x000b
#define AEM_JACKTYPE_COMPOSITE_VIDEO      0x000c
#define AEM_JACKTYPE_S_VHS_VIDEO          0x000d
#define AEM_JACKTYPE_COMPONENT_VIDEO      0x000e
#define AEM_JACKTYPE_DVI                  0x000f
#define AEM_JACKTYPE_HDMI                 0x0010
#define AEM_JACKTYPE_UDI                  0x0011
#define AEM_JACKTYPE_DISPLAYPORT          0x0012
#define AEM_JACKTYPE_ANTENNA              0x0013
#define AEM_JACKTYPE_ANALOG_TUNER         0x0014
#define AEM_JACKTYPE_ETHERNET             0x0015
#define AEM_JACKTYPE_WIFI                 0x0016
#define AEM_JACKTYPE_USB                  0x0017
#define AEM_JACKTYPE_PCI                  0x0018
#define AEM_JACKTYPE_PCI_E                0x0019
#define AEM_JACKTYPE_SCSI                 0x001a
#define AEM_JACKTYPE_ATA                  0x001b
#define AEM_JACKTYPE_IMAGER               0x001c
#define AEM_JACKTYPE_IR                   0x001d
#define AEM_JACKTYPE_THUNDERBOLT          0x001e
#define AEM_JACKTYPE_SATA                 0x001f
#define AEM_JACKTYPE_SMPTE_LTC            0x0020
#define AEM_JACKTYPE_DIGITAL_MICROPHONE   0x0021

#define AEM_CONTROL_ENABLE              0x90e0f00000000000
#define AEM_CONTROL_DELAY               0x90e0f00000000001
#define AEM_CONTROL_POW_LINE_FREQ       0x90e0f00000000002
#define AEM_CONTROL_ROLLPITCHYAW_ABS    0x90e0f00000000003
#define AEM_CONTROL_ROLLPITCHYAW_REL    0x90e0f00000000004
#define AEM_CONTROL_SURGESWAYHEAVE_ABS  0x90e0f00000000005
#define AEM_CONTROL_SURGESWAYHEAVE_REL  0x90e0f00000000006
#define AEM_CONTROL_IDENTIFY            0x90e0f00000000007
#define AEM_CONTROL_POWER_STATUS        0x90e0f00000000008
#define AEM_CONTROL_FAN_STATUS          0x90e0f00000000009
#define AEN_CONTROL_TEMPERATURE         0x90e0f0000000000a
#define AEM_CONTROL_TEMPERATURE_SENSOR  0x90e0f0000000000b
#define AEM_CONTROL_ALTITUDE            0x90e0f0000000000c
#define AEM_CONTROL_HUMIDITY            0x90e0f0000000000d
/* 0x90e0f0000000000e - 0x90e0f0000000ffff reserved */
#define AEM_CONTROL_MUTE                0x90e0f00000010000
#define AEM_CONTROL_VOLUME              0x90e0f00000010001
#define AEM_CONTROL_INVERT              0x90e0f00000010002
#define AEM_CONTROL_PANPOT              0x90e0f00000010003
#define AEM_CONTROL_ISOLATE             0x90e0f00000010004
#define AEM_CONTROL_POSITION            0x90e0f00000010005
#define AEM_CONTROL_PHANTOM             0x90e0f00000010006
#define AEM_CONTROL_AUDIO_SCALE         0x90e0f00000010007
#define AEM_CONTROL_AUDIO_METERS        0x90e0f00000010008
#define AEM_CONTROL_AUDIO_SPECTRUM      0x90e0f00000010009
#define AEM_CONTROL_FILTER_RESPONSE     0x90e0f0000001000a
/* 0x90e0f0000001000b - 0x90e0f0000001ffff reserved */
#define AEM_CONTROL_SCANNING_MODE       0x90e0f00000020000
#define AEM_CONTROL_AUTO_EXP_MODE       0x90e0f00000020001
#define AEM_CONTROL_AUTO_EXP_PRIO       0x90e0f00000020002
#define AEM_CONTROL_EXP_TIME_ABS        0x90e0f00000020003
#define AEM_CONTROL_EXP_TIME_REL        0x90e0f00000020004
#define AEM_CONTROL_FOCUS_ABS           0x90e0f00000020005
#define AEM_CONTROL_FOCUS_REL           0x90e0f00000020006
#define AEM_CONTROL_FOCUS_AUTO          0x90e0f00000020007
#define AEM_CONTROL_IRIS_ABS            0x90e0f00000020008
#define AEM_CONTROL_IRIS_REL            0x90e0f00000020009
#define AEM_CONTROL_ZOOM_ABS            0x90e0f0000002000a
#define AEM_CONTROL_ZOOM_REL            0x90e0f0000002000b
#define AEM_CONTROL_PRIVACY             0x90e0f0000002000c
#define AEM_CONTROL_BACKLIGHT           0x90e0f0000002000d
#define AEM_CONTROL_BRIGHTNESS          0x90e0f0000002000e
#define AEM_CONTROL_CONTRAST            0x90e0f0000002000f
#define AEM_CONTROL_GAIN                0x90e0f00000020010
#define AEM_CONTROL_HUE                 0x90e0f00000020011
#define AEM_CONTROL_SATURATION          0x90e0f00000020012
#define AEM_CONTROL_SHARPNESS           0x90e0f00000020013
#define AEM_CONTROL_GAMMA               0x90e0f00000020014
#define AEM_CONTROL_WHITE_BAL_TEMP      0x90e0f00000020015
#define AEM_CONTROL_WHITE_BAL_TENP_AUTO 0x90e0f00000020016
#define AEM_CONTROL_WHITE_BAL_COMP      0x90e0f00000020017
#define AEM_CONTROL_WHITE_BAL_COMP_AUTO 0x90e0f00000020018
#define AEM_CONTROL_DIGITAL_ZOOM        0x90e0f00000020019
/* 0x90e0f0000002001a - 0x90e0f0ffffffffff reserved */

/* AEM Control Value Types (7.31) */
#define AEM_CONTROL_LINEAR_INT8       0x0000
#define AEM_CONTROL_LINEAR_UINT8      0x0001
#define AEM_CONTROL_LINEAR_INT16      0x0002
#define AEM_CONTROL_LINEAR_UINT16     0x0003
#define AEM_CONTROL_LINEAR_INT32      0x0004
#define AEM_CONTROL_LINEAR_UINT32     0x0005
#define AEM_CONTROL_LINEAR_INT64      0x0006
#define AEM_CONTROL_LINEAR_UINT64     0x0007
#define AEM_CONTROL_LINEAR_FLOAT      0x0008
#define AEM_CONTROL_LINEAR_DOUBLE     0x0009
#define AEM_CONTROL_SELECTOR_INT8     0x000a
#define AEM_CONTROL_SELECTOR_UINT8    0x000b
#define AEM_CONTROL_SELECTOR_INT16    0x000c
#define AEM_CONTROL_SELECTOR_UINT16   0x000d
#define AEM_CONTROL_SELECTOR_INT32    0x000e
#define AEM_CONTROL_SELECTOR_UINT32   0x000f
#define AEM_CONTROL_SELECTOR_INT64    0x0010
#define AEM_CONTROL_SELECTOR_UINT64   0x0011
#define AEM_CONTROL_SELECTOR_FLOAT    0x0012
#define AEM_CONTROL_SELECTOR_DOUBLE   0x0013
#define AEM_CONTROL_UTF8              0x0014
#define AEM_CONTROL_BODE_PLOT         0x0015
#define AEM_CONTROL_ARRAY_INT8        0x0016
#define AEM_CONTROL_ARRAY_UINT8       0x0017
#define AEM_CONTROL_ARRAY_INT16       0x0018
#define AEM_CONTROL_ARRAY_UINT16      0x0019
#define AEM_CONTROL_ARRAY_INT32       0x001a
#define AEM_CONTROL_ARRAY_UINT32      0x001b
#define AEM_CONTROL_ARRAY_INT64       0x001c
#define AEM_CONTROL_ARRAY_UINT64      0x001d
#define AEM_CONTROL_ARRAY_FLOAT       0x001e
#define AEM_CONTROL_ARRAY_DOUBLE      0x001f
/* 0x0020-0xfffd RESERVED Reserved for future use. */
#define AEM_CONTROL_VENDOR            0xfffe /* TODO - update value in D18 */
/* 0xffff EXPANSION Reserved for future use. */

/* AEM Clock Source Types (Table 7.25) */
#define AEM_CLOCK_LOCAL_OSCILLATOR  0x0000
#define AEM_CLOCK_INPUT_STREAM      0x0001
#define AEM_CLOCK_WORLD_CLOCK       0x0002
#define AEM_CLOCK_ANALOG_INPUT      0x0003
#define AEM_CLOCK_DIGITAL_INPUT     0x0004
#define AEM_CLOCK_8021_AS           0x0005
#define AEM_CLOCK_THUNDERBOLT       0x0006

/* AEM Stream Format Definitions */
#define SF61883_IIDC_SUBTYPE          0x00
#define MMA_SUBTYPE                 0x01
#define EXPERIMENTAL_SUBTYPE        0x7f



/* AEM Offset Values */

#define AEM_OFFSET_DESCRIPTOR_TYPE           0
#define AEM_OFFSET_DESCRIPTOR_ID             2
#define AEM_OFFSET_ENTITY_GUID               4
#define AEM_OFFSET_VENDOR_ID                 12
#define AEM_OFFSET_ENTITY_MODEL_ID           16
#define AEM_OFFSET_ENTITY_CAPABILITIES       20
#define AEM_OFFSET_TALKER_STREAM_SOURCES     24
#define AEM_OFFSET_TALKER_CAPABILITIES       26
#define AEM_OFFSET_LISTENER_STREAM_SINKS     28
#define AEM_OFFSET_LISTENER_CAPABILITIES     30
#define AEM_OFFSET_CONTROLLER_CAPABILITIES   32
#define AEM_OFFSET_AVAILABLE_INDEX           36
#define AEM_OFFSET_AS_GRANDMASTER_ID         40
#define AEM_OFFSET_ASSOCIATION_ID            48
#define AEM_OFFSET_ENTITY_TYPE               56
#define AEM_OFFSET_ENTITY_NAME               60
#define AEM_OFFSET_VENDOR_NAME_STRING        124
#define AEM_OFFSET_MODEL_NAME_STRING         126
#define AEM_OFFSET_FIRMWARE_VERSION          128
#define AEM_OFFSET_GROUP_NAME                192
#define AEM_OFFSET_SERIAL_NUMBER             256
#define AEM_OFFSET_CONFIGURATIONS_COUNT      320
#define AEM_OFFSET_CURRENT_CONFIGURATION     322

#define AEM_OFFSET_CONFIGURATION_NAME        4
#define AEM_OFFSET_CONFIGURATION_NAME_STRING 68
#define AEM_OFFSET_DESCRIPTOR_COUNTS_COUNT   70
#define AEM_OFFSET_DESCRIPTOR_COUNTS_OFFSET  72
#define AEM_OFFSET_DESCRIPTOR_COUNTS         74

#define AEM_OFFSET_NUMBER_OF_STREAM_INPUT_PORTS    4
#define AEM_OFFSET_BASE_STREAM_INPUT_PORT          6
#define AEM_OFFSET_NUMBER_OF_STREAM_OUTPUT_PORTS   8
#define AEM_OFFSET_BASE_STREAM_OUTPUT_PORT         10
#define AEM_OFFSET_NUMBER_OF_EXTERNAL_INPUT_PORTS  12
#define AEM_OFFSET_BASE_EXTERNAL_INPUT_PORT        14
#define AEM_OFFSET_NUMBER_OF_EXTERNAL_OUTPUT_PORTS 16
#define AEM_OFFSET_BASE_EXTERNAL_OUTPUT_PORT       18
#define AEM_OFFSET_NUMBER_OF_INTERNAL_INPUT_PORTS  20
#define AEM_OFFSET_BASE_INTERNAL_INPUT_PORT        22
#define AEM_OFFSET_NUMBER_OF_INTERNAL_OUTPUT_PORTS 24
#define AEM_OFFSET_BASE_INTERNAL_OUTPUT_PORT       26
#define AEM_OFFSET_CLOCK_SOURCE_ID                 28
#define AEM_OFFSET_NUMBER_OF_CONTROLS              30
#define AEM_OFFSET_BASE_CONTROL                    32
#define AEM_OFFSET_UNIT_NAME                       34
#define AEM_OFFSET_UNIT_NAME_STRING                98
#define AEM_OFFSET_CURRENT_SAMPLE_RATE             100
#define AEM_OFFSET_SAMPLE_RATES_OFFSET             104
#define AEM_OFFSET_SAMPLE_RATES_COUNT              106
#define AEM_OFFSET_SAMPLE_RATES                    108

/* starting with the draft 18 updates the naming scheme for offsets will be changing *
 * to DESCRIPTOR_NAME_OFFSET_FIELD to make maintenance easier. Eventually all of the *
 * offsets will be changed to this form. For now, all changes will be added in this  *
 * format to avoid breaking anything that used the same offset in multiple places    */
#define AUDIO_UNIT_OFFSET_NUMBER_SIGNAL_SELECTORS  100
#define AUDIO_UNIT_OFFSET_BASE_SIGNAL_SELECTOR     102
#define AUDIO_UNIT_OFFSET_NUMBER_MIXERS            104
#define AUDIO_UNIT_OFFSET_BASE_MIXER               106
#define AUDIO_UNIT_OFFSET_NUMBER_MATRICES          108
#define AUDIO_UNIT_OFFSET_BASE_MATRIX              110
#define AUDIO_UNIT_OFFSET_CURRENT_SAMPLE_RATE      112
#define AUDIO_UNIT_OFFSET_SAMPLE_RATES_OFFSET      116
#define AUDIO_UNIT_OFFSET_SAMPLE_RATES_COUNT       118
#define AUDIO_UNIT_OFFSET_SAMPLE_RATES             120

#define VIDEO_UNIT_OFFSET_NUMBER_SIGNAL_SELECTORS  100
#define VIDEO_UNIT_OFFSET_BASE_SIGNAL_SELECTOR     102
#define VIDEO_UNIT_OFFSET_NUMBER_MIXERS            104
#define VIDEO_UNIT_OFFSET_BASE_MIXER               106
#define VIDEO_UNIT_OFFSET_NUMBER_MATRICES          108
#define VIDEO_UNIT_OFFSET_BASE_MATRIX              110

#define AEM_OFFSET_STREAM_NAME                     4
#define AEM_OFFSET_STREAM_NAME_STRING              68
#define AEM_OFFSET_STREAM_FLAGS                    70
#define AEM_OFFSET_STREAM_CHANNELS                 72
#define AEM_OFFSET_CLOCK_SOURCE_ID_STREAM          74

#define AEM_OFFSET_MAPPINGS_OFFSET                 4
#define AEM_OFFSET_NUMBER_OF_MAPPINGS              6
#define AEM_OFFSET_MAPPINGS                        8

#define AEM_OFFSET_SF_SUBTYPE                      0

#define AECP_OFFSET_SETMF_MEDIA_FMT                28
#define AECP_OFFSET_AUTH_ADD_KEY_KEYTYPE           24
#define AECP_OFFSET_AUTH_ADD_KEY_CONTINUED         26
#define AECP_OFFSET_AUTH_ADD_KEY_KEY_PART          26
#define AECP_OFFSET_AUTH_ADD_KEY_LENGTH            24
#define AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS   28
#define AECP_OFFSET_AUTH_ADD_KEY_KEY_GUID          32
#define AECP_OFFSET_AUTH_ADD_KEY_KEY               40

#define AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH      26
#define AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS   28
#define AECP_OFFSET_AUTHENTICATE_KEY_GUID          32
#define AECP_OFFSET_AUTHENTICATE_AUTH_TOKEN        40

#define AECP_OFFSET_GET_COUNTERS_VALID             28
#define AECP_OFFSET_GET_COUNTERS_BLOCK             32

#define AEM_OFFSET_CURRENT_FORMAT                  76
#define AEM_OFFSET_FORMATS_OFFSET                  84
#define AEM_OFFSET_NUMBER_OF_FORMATS               86
#define AEM_OFFSET_BACKUP_TALKER_GUID_0            88
#define AEM_OFFSET_BACKUP_TALKER_UNIQUE_0          96
#define AEM_OFFSET_BACKUP_TALKER_GUID_1            98
#define AEM_OFFSET_BACKUP_TALKER_UNIQUE_1          106
#define AEM_OFFSET_BACKUP_TALKER_GUID_2            108
#define AEM_OFFSET_BACKUP_TALKER_UNIQUE_2          116
#define AEM_OFFSET_BACKEDUP_TALKER_GUID            118
#define AEM_OFFSET_BACKEDUP_TALKER_UNIQUE          126
#define AEM_OFFSET_AVB_INTERFACE_ID                128
#define AEM_OFFSET_FORMATS                         130

#define AEM_OFFSET_JACK_NAME                       4
#define AEM_OFFSET_JACK_NAME_STRING                68
#define AEM_OFFSET_JACK_FLAGS                      70
#define AEM_OFFSET_JACK_TYPE                       72

#define AEM_OFFSET_PORT_FLAGS                      4
#define AEM_OFFSET_AUDIO_CHANNELS                  6
#define AEM_OFFSET_NUMBER_OF_CLUSTERS              8
#define AEM_OFFSET_BASE_CLUSTER                    10
#define AEM_OFFSET_AUDIO_MAP_ID                    12

#define AUDIO_PORT_OFFSET_BASE_AUDIO_MAP           12
#define AUDIO_PORT_OFFSET_NUMBER_AUDIO_MAPS        14


#define AEM_OFFSET_CURRENT_FORMAT_VID              6
#define AEM_OFFSET_SOURCE_TYPE                     22
#define AEM_OFFSET_SOURCE_ID                       24
#define AEM_OFFSET_STREAM_ID                       26
#define AEM_OFFSET_FORMATS_OFFSET_VID              28
#define AEM_OFFSET_FORMATS_COUNT_VID               30

#define VIDEO_PORT_OFFSET_BLOCK_LATENCY            32
#define VIDEO_PORT_OFFSET_FORMATS                  36

#define AEM_OFFSET_MEDIA_FORMATS_VID               32

#define AEM_OFFSET_STREAM_FORMATS                  32

#define AEM_OFFSET_SOURCE_TYPE_EXT                 6
#define AEM_OFFSET_SOURCE_ID_EXT                   8
#define EXTERNAL_PORT_OFFSET_JACK_ID               10
#define EXTERNAL_PORT_OFFSET_BLOCK_LATENCY         12

#define AEM_OFFSET_STREAM_ID_SEN                   10
#define SENSOR_PORT_OFFSET_BLOCK_LATENCY           12

#define INTERNAL_PORT_OFFSET_BLOCK_LATENCY         12

#define AEM_OFFSET_INTERNAL_ID                     10

#define AEM_OFFSET_MAC_ADDRESS                     4
#define AEM_OFFSET_AS_GRANDMASTER_ID_AVB           10
#define AEM_OFFSET_MSRP_MAPPINGS_OFFSET            18
#define AEM_OFFSET_MSRP_MAPPINGS_COUNT             20

#define AVB_INTERFACE_OFFSET_INTERFACE_NAME        22
#define AVB_INTERFACE_OFFSET_INTERFACE_NAME_STRING 86
#define AVB_INTERFACE_MSRP_MAPPINGS                88

#define AEM_OFFSET_CLOCK_SOURCE_NAME               4
#define AEM_OFFSET_CLOCK_SOURCE_NAME_STRING        68
#define AEM_OFFSET_CLOCK_SOURCE_FLAGS              70
#define AEM_OFFSET_CLOCK_SOURCE_TYPE               72
#define AEM_OFFSET_CLOCK_SOURCE_ID_CLK             74
#define AEM_OFFSET_CLOCK_SOURCE_LOCATION_TYPE      82
#define AEM_OFFSET_CLOCK_SOURCE_LOCATION_ID        84

#define AUDIO_CLUSTER_OFFSET_CHANNEL_COUNT         4
#define AUDIO_CLUSTER_OFFSET_PATH_LATENCY          6
#define AUDIO_CLUSTER_OFFSET_AM824_LABEL           10
#define AUDIO_CLUSTER_OFFSET_CLUSTER_NAME          11
#define AUDIO_CLUSTER_OFFSET_CLUSTER_NAME_STRING   75
#define AUDIO_CLUSTER_OFFSET_SIGNAL_TYPE           77
#define AUDIO_CLUSTER_OFFSET_SIGNAL_ID             79
#define AUDIO_CLUSTER_OFFSET_BLOCK_LATENCY         81

#define AEM_OFFSET_AM824_LABEL                     10
#define AEM_OFFSET_CLUSTER_NAME                    11
#define AEM_OFFSET_CLUSTER_NAME_STRING             75
#define AEM_OFFSET_SOURCE_TYPE_CLU                 77
#define AEM_OFFSET_SOURCE_ID_CLU                   79

#define AEM_OFFSET_CONTROL_TYPE                    4
#define AEM_OFFSET_CONTROL_LOCATION_TYPE           12
#define AEM_OFFSET_CONTROL_LOCATION_ID             14
#define AEM_OFFSET_CONTROL_VALUE_TYPE              16
#define AEM_OFFSET_CONTROL_DOMAIN                  18
#define AEM_OFFSET_CONTROL_NAME                    20
#define AEM_OFFSET_CONTROL_NAME_STRING             84
#define AEM_OFFSET_VALUES_OFFSET_CTRL              86
#define AEM_OFFSET_NUMBER_OF_VALUES_CTRL           88
#define AEM_OFFSET_SOURCE_TYPE_CTRL                90
#define AEM_OFFSET_SOURCE_ID_CTRL                  92

#define CONTROL_OFFSET_BLOCK_LATENCY               94
#define CONTROL_OFFSET_CONTROL_LATENCY             98
#define CONTROL_OFFSET_VALUE_DETAILS               102

#define AEM_OFFSET_CONTROL_LOCATION_TYPE_SIGS      4
#define AEM_OFFSET_CONTROL_LOCATION_ID_SIGS        6
#define AEM_OFFSET_CONTROL_DOMAIN_SIGS             8
#define AEM_OFFSET_CONTROL_NAME_SIGS               10
#define AEM_OFFSET_CONTROL_NAME_STRING_SIGS        74
#define AEM_OFFSET_SOURCES_OFFSET_SIGS             76
#define AEM_OFFSET_NUMBER_OF_SOURCES_SIGS          78
#define AEM_OFFSET_CURRENT_SOURCE_TYPE_SIGS        80
#define AEM_OFFSET_CURRENT_SOURCE_ID_SIGS          82
#define AEM_OFFSET_DEFAULT_SOURCE_TYPE_SIGS        84
#define AEM_OFFSET_DEFAULT_SOURCE_ID_SIGS          86

#define SIGNAL_SELECTOR_OFFSET_BLOCK_LATENCY       88
#define SIGNAL_SELECTOR_OFFSET_CONTROL_LATENCY     92
#define SIGNAL_SELECTOR_OFFSET_SOURCES             96

#define AEM_OFFSET_CONTROL_LOCATION_TYPE_MXR       4
#define AEM_OFFSET_CONTROL_LOCATION_ID_MXR         6
#define AEM_OFFSET_CONTROL_VALUE_TYPE_MXR          8
#define AEM_OFFSET_CONTROL_DOMAIN_MXR              10
#define AEM_OFFSET_CONTROL_NAME_MXR                12
#define AEM_OFFSET_CONTROL_NAME_STRING_MXR         76
#define AEM_OFFSET_SOURCES_OFFSET_MXR              78
#define AEM_OFFSET_NUMBER_OF_SOURCES_MXR           80
#define AEM_OFFSET_VALUE_OFFSET_MXR                82

#define MIXER_OFFSET_BLOCK_LATENCY                 84
#define MIXER_OFFSET_CONTROL_LATENCY               88
#define MIXER_OFFSET_SOURCES                       92

#define AEM_OFFSET_CONTROL_TYPE_MTRX               4
#define AEM_OFFSET_CONTROL_LOCATION_TYPE_MTRX      12
#define AEM_OFFSET_CONTROL_LOCATION_ID_MTRX        14
#define AEM_OFFSET_CONTROL_VALUE_TYPE_MTRX         16
#define AEM_OFFSET_CONTROL_DOMAIN_MTRX             18
#define AEM_OFFSET_CONTROL_NAME_MTRX               20
#define AEM_OFFSET_CONTROL_NAME_STRING_MTRX        84
#define AEM_OFFSET_WIDTH_MTRX                      86
#define AEM_OFFSET_HEIGHT_MTRX                     88
#define AEM_OFFSET_VALUES_OFFSET_MTRX              90
#define AEM_OFFSET_NUMBER_OF_VALUES_MTRX           92
#define AEM_OFFSET_VALUES_MTRX                     94

#define MATRIX_OFFSET_BLOCK_LATENCY                94
#define MATRIX_OFFSET_CONTROL_LATENCY              98
#define MATRIX_OFFSET_NUMBER_SOURCES               102
#define MATRIX_OFFSET_BASE_SOURCE                  104
#define MATRIX_OFFSET_NUMBER_DESTINATIONS          106
#define MATRIX_OFFSET_BASE_DESTINATION             108
#define MATRIX_OFFSET_VALUE_DETAILS                110

#define AEM_OFFSET_LOCALE_IDENTIFIER               4
#define AEM_OFFSET_NUMBER_OF_STRINGS               68
#define AEM_OFFSET_BASE_STRINGS                    70

#define AEM_OFFSET_STRING0                         4

#define MATRIX_SIGNAL_OFFSET_SIGNALS_COUNT         4
#define MATRIX_SIGNAL_OFFSET_SIGNALS_OFFSET        6
#define MATRIX_SIGNAL_OFFSET_SIGNALS               8

#define MEMORY_OBJECT_OFFSET_MEMORY_OBJECT_TYPE       4
#define MEMORY_OBJECT_OFFSET_TARGET_DESCRIPTOR_TYPE   6
#define MEMORY_OBJECT_OFFSET_TARGET_DESCRIPTOR_ID     8
#define MEMORY_OBJECT_OFFSET_OBJECT_NAME              10
#define MEMORY_OBJECT_OFFSET_OBJECT_NAME_STRING       74
#define MEMORY_OBJECT_OFFSET_START_ADDRESS            76
#define MEMORY_OBJECT_OFFSET_LENGTH                   84

#define AEM_OFFSET_MFD_TYPE                        3
#define AEM_OFFSET_DIV                             4
#define AEM_OFFSET_INTERLACE                       4
#define AEM_OFFSET_CHANNELS                        4
#define AEM_OFFSET_COLOR_FORMAT                    4
#define AEM_OFFSET_BPP                             5
#define AEM_OFFSET_ASPECT_X                        6
#define AEM_OFFSET_ASPECT_Y                        7
#define AEM_OFFSET_FRAME_RATE                      8
#define AEM_OFFSET_COMP1                           9
#define AEM_OFFSET_COMP2                           10
#define AEM_OFFSET_COMP3                           10
#define AEM_OFFSET_COMP4                           11
#define AEM_OFFSET_SVMF_WIDTH                      12
#define AEM_OFFSET_SVMF_HEIGHT                     14

#define AEM_OFFSET_CS_EUI64                        8

#define AEM_OFFSET_SF_VERSION                      0
#define AEM_OFFSET_SF                              1
#define AEM_OFFSET_IIDC_FORMAT                     5
#define AEM_OFFSET_IIDC_MODE                       6
#define AEM_OFFSET_IIDC_RATE                       7
#define AEM_OFFSET_FDF_EVT                         2
#define AEM_OFFSET_FDF_SFC                         2
#define AEM_OFFSET_DBS                             3
#define AEM_OFFSET_FMT                             1
#define AEM_OFFSET_B                               4
#define AEM_OFFSET_NB                              4
#define AEM_OFFSET_LABEL_IEC_60958_CNT             5
#define AEM_OFFSET_LABEL_MBLA_CNT                  6
#define AEM_OFFSET_LABEL_MIDI_CNT                  7
#define AEM_OFFSET_LABEL_SMPTE_CNT                 7

#define AEM_OFFSET_VIDEO_MODE                      5
#define AEM_OFFSET_COMPRESS_MODE                   6
#define AEM_OFFSET_COLOR_SPACE                     7

/* Bitmasks */
#define AECP_TOKEN_LENGTH_MASK                  0x07ff
#define AECP_KEY_PART_MASK                      0x78
#define AECP_CONTINUED_MASK                     0x80
#define AECP_CD_LENGTH_MASK                     0x07ff
#define AECP_COMMAND_TYPE_MASK                  0x7fff
#define AECP_CONNECTED_FLAG_MASK                0x08000000
#define AECP_DEFAULT_FORMAT_VALID_FLAG_MASK     0x80000000
#define AECP_DEST_MAC_VALID_FLAG_MASK           0x40000000
#define AECP_KEYCHAIN_ID_MASK                   0xe0
#define AECP_KEYTYPE_MASK                       0x1c
#define AECP_KEY_COUNT_MASK                     0x0fff
#define AECP_KEY_LENGTH_MASK                    0x07ff
#define AECP_KEY_NUMBER_MASK                    0x04ff
#define AECP_MATRIX_DIRECTION_MASK              0x70
#define AECP_MATRIX_REP_MASK                    0x80
#define AECP_MATRIX_VALUE_COUNT_MASK            0xfff
#define AECP_MSG_TYPE_MASK                      0x0f
#define AECP_MSRP_ACC_LAT_VALID_FLAG_MASK       0x20000000
#define AECP_PERSISTENT_FLAG_MASK               0x00000001
#define AECP_RELEASE_FLAG_MASK                  0x80000000
#define AECP_SIGNATURE_ID_MASK                  0x0fff
#define AECP_SIGNATURE_INFO_MASK                0x00f0
#define AECP_SIGNATURE_LENGTH_MASK              0x3ff
#define AECP_STREAM_ID_VALID_FLAG_MASK          0x10000000
#define AECP_UNLOCK_FLAG_MASK                   0x00000001
#define AECP_U_FLAG_MASK                        0x80

/* key permission flag masks */
#define AECP_PRIVATE_KEY_READ_FLAG_MASK         0x80000000
#define AECP_PRIVATE_KEY_WRITE_FLAG_MASK        0x40000000
#define AECP_PUBLIC_KEY_WRITE_FLAG_MASK         0x20000000
#define AECP_CONNECTION_FLAG_MASK               0x10000000
#define AECP_CONTROL_ADMIN_FLAG_MASK            0x08000000
#define AECP_MEM_OBJ_ADMIN_FLAG_MASK            0x04000000
#define AECP_MEM_OBJ_SETTINGS_FLAG_MASK         0x02000000
#define AECP_CONTROL_USER_L1_FLAG_MASK          0x00000008
#define AECP_CONTROL_USER_L2_FLAG_MASK          0x00000004
#define AECP_CONTROL_USER_L3_FLAG_MASK          0x00000002
#define AECP_CONTROL_USER_L4_FLAG_MASK          0x00000001

/* 7.105 counters_valid flag masks */
#define AECP_COUNTERS_VALID_GPTP_UNLOCKED          0x40000000
#define AECP_COUNTERS_VALID_GPTP_LOCKED            0x20000000
#define AECP_COUNTERS_VALID_MEDIA_UNLOCKED         0x10000000
#define AECP_COUNTERS_VALID_MEDIA_LOCKED           0x08000000
#define AECP_COUNTERS_VALID_STREAM_RESET           0x02000000
#define AECP_COUNTERS_VALID_SRP_REFUSED            0x01000000
#define AECP_COUNTERS_VALID_BACKUP_STREAM_SWITCH   0x00800000
#define AECP_COUNTERS_VALID_MISSED_AVDECC_RESPONSE 0x00400000
#define AECP_COUNTERS_VALID_REFUSED_AVDECC_COMMAND 0x00200000
#define AECP_COUNTERS_VALID_SEQ_NUM_MISMATCH       0x00100000
#define AECP_COUNTERS_VALID_MEDIA_CLOCK_TOGGLES    0x00080000
#define AECP_COUNTERS_VALID_TIMESTAMP_UNCERTAINS   0x00040000
#define AECP_COUNTERS_VALID_TIMESTAMP_VALIDS       0x00020000
#define AECP_COUNTERS_VALID_UNSUPPORTED_FORMATS    0x00010000
#define AECP_COUNTERS_VALID_BAD_PRESENTATION_TIMES 0x00008000
#define AECP_COUNTERS_VALID_SRP_LATENCY_VIOLATIONS 0x00004000
#define AECP_COUNTERS_VALID_PACKETS_TX             0x00002000
#define AECP_COUNTERS_VALID_PACKETS_RX             0x00001000
#define AECP_COUNTERS_VALID_PACKETS_OF_INTEREST_RX 0x00000800
#define AECP_COUNTERS_VALID_TALKER_BW_RESERVED     0x00000400
#define AECP_COUNTERS_VALID_RESERVED1              0x00000200
#define AECP_COUNTERS_VALID_RESERVED2              0x00000100
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_1      0x00000080
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_2      0x00000040
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_3      0x00000020
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_4      0x00000010
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_5      0x00000008
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_6      0x00000004
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_7      0x00000002
#define AECP_COUNTERS_VALID_ENTITY_SPECIFIC_8      0x00000001

#define AEM_ASYNC_SAMPLE_RATE_CONV_FLAG_MASK    0x00000002
#define AEM_BASE_FREQUENCY_MASK                 0x1fffffff
#define AEM_CAPTIVE_FLAG_MASK                   0x00000002
#define AEM_CLASS_A_FLAG_MASK                   0x00000002
#define AEM_CLASS_B_FLAG_MASK                   0x00000004
#define AEM_CLOCK_SYNC_SOURCE_FLAG_MASK         0x00000001
#define AEM_MASK_B                              0x80
#define AEM_MASK_BPP                            0x3F
#define AEM_MASK_CHANNELS                       0x3C
#define AEM_MASK_COLOR_FORMAT                   0x03C0
#define AEM_MASK_COMP1                          0x0F80
#define AEM_MASK_COMP2                          0x7C
#define AEM_MASK_COMP3                          0x03E0
#define AEM_MASK_COMP4                          0x1F
#define AEM_MASK_DIV                            0x80
#define AEM_MASK_FDF_EVT                        0xF8
#define AEM_MASK_FDF_SFC                        0x07
#define AEM_MASK_FMT                            0x3F
#define AEM_MASK_INTERLACE                      0x40
#define AEM_MASK_LABEL_MIDI_CNT                 0xF0
#define AEM_MASK_LABEL_SMPTE_CNT                0x0F
#define AEM_MASK_NB                             0x40
#define AEM_MASK_OUI24                          0xFFFFFF00
#define AEM_MASK_SF                             0x40
#define AEM_MASK_SF_SUBTYPE                     0x3F80
#define AEM_MASK_SF_VERSION                     0xC0
#define AEM_PULL_FIELD_MASK                     0xe0
#define AEM_SYNC_SAMPLE_RATE_CONV_FLAG_MASK     0x00000001

#define MFD_TYPE_VIDEO                          0x00
#define MFD_TYPE_TRANSPORT_STRM                 0x01
#define MFD_TYPE_MIDI                           0x02
#define MFD_TYPE_TIME_CODE                      0x03
#define MFD_TYPE_CONTROL_PROTO                  0x04

#define COLOR_FORMAT_MONO                       0x0
#define COLOR_FORMAT_RGB                        0x1
#define COLOR_FORMAT_RGBA                       0x2
#define COLOR_FORMAT_BGRA                       0x3
#define COLOR_FORMAT_CMYK                       0x4
#define COLOR_FORMAT_HSL                        0x5
#define COLOR_FORMAT_YUV                        0x6
#define COLOR_FORMAT_YCBCR                      0x7
#define COLOR_FORMAT_YPBPR                      0x08

#define OUI24_STANDARD_MEDIA_FORMAT             0x90e0f0

#define MEMORY_OBJECT_TYPE_FIRMWARE_IMAGE       0x0000
#define MEMORY_OBJECT_TYPE_VENDOR_SPECIFIC      0x0001
#define MEMORY_OBJECT_TYPE_CRASH_DUMP           0x0002
#define MEMORY_OBJECT_TYPE_LOG_OBJECT           0x0003
#define MEMORY_OBJECT_TYPE_AUTOSTART_SETTINGS   0x0004
#define MEMORY_OBJECT_TYPE_SNAPSHOT_SETTINGS    0x0005

#define KEY_TYPE_NONE            0
#define KEY_TYPE_SHA256          1
#define KEY_TYPE_AES128          2
#define KEY_TYPE_AES256          3
#define KEY_TYPE_RSA1024_PUBLIC  4
#define KEY_TYPE_RSA1024_PRIVATE 5
#define KEY_TYPE_X509            6

static const value_string aecp_keytype_type_vals [] = {
   {KEY_TYPE_NONE,            "NO_KEY"},
   {KEY_TYPE_SHA256,          "SHA256"},
   {KEY_TYPE_AES128,          "AES128"},
   {KEY_TYPE_AES256,          "AES256"},
   {KEY_TYPE_RSA1024_PUBLIC,  "RSA1024_PUBLIC"},
   {KEY_TYPE_RSA1024_PRIVATE, "RSA1024_PRIVATE"},
   {KEY_TYPE_X509,            "RSA1024_X509"},
   {0,                         NULL}
};

static const value_string aem_memory_object_type_vals [] = {
   {MEMORY_OBJECT_TYPE_FIRMWARE_IMAGE,       "FIRMWARE_IMAGE"},
   {MEMORY_OBJECT_TYPE_VENDOR_SPECIFIC,      "VENDOR_SPECIFIC"},
   {MEMORY_OBJECT_TYPE_CRASH_DUMP,           "CRASH_DUMP"},
   {MEMORY_OBJECT_TYPE_LOG_OBJECT,           "LOG_OBJECT"},
   {MEMORY_OBJECT_TYPE_AUTOSTART_SETTINGS,   "AUTOSTART_SETTINGS"},
   {MEMORY_OBJECT_TYPE_SNAPSHOT_SETTINGS,    "SNAPSHOT_SETTINGS"},
   {0,                                       NULL}
};

static const value_string aem_stream_format_subtype_vals [] = {
   {SF61883_IIDC_SUBTYPE,        "61883_IIDC_SUBTYPE"},
   {MMA_SUBTYPE,                 "MMA_SUBTYPE"},
   {EXPERIMENTAL_SUBTYPE,        "EXPERIMENTAL_SUBTYPE"},
   {0,                            NULL}
};

static const value_string aem_color_format_type_vals [] = {
   {COLOR_FORMAT_MONO,  "Monochrome"},
   {COLOR_FORMAT_RGB,   "RGB"},
   {COLOR_FORMAT_RGBA,  "RGBA"},
   {COLOR_FORMAT_BGRA,  "BGRA"},
   {COLOR_FORMAT_CMYK,  "CMYK"},
   {COLOR_FORMAT_HSL,   "HSL"},
   {COLOR_FORMAT_YUV,   "YUV"},
   {COLOR_FORMAT_YCBCR, "YCbCr"},
   {COLOR_FORMAT_YPBPR, "YPbPr"},
   {0,                   NULL}
};

static const value_string aem_mfd_type_vals [] = {
   {MFD_TYPE_VIDEO,             "VIDEO"},
   {MFD_TYPE_TRANSPORT_STRM,    "TRANSPORT_STREAM"},
   {MFD_TYPE_MIDI,              "MIDI"},
   {MFD_TYPE_TIME_CODE,         "TIME_CODE"},
   {MFD_TYPE_CONTROL_PROTO,     "CONTROL_PROTOCOL"},
   {0,                           NULL}
};

static const value_string aem_clock_source_type_vals [] = {
   {AEM_CLOCK_LOCAL_OSCILLATOR  , "LOCAL OSCILLATOR"},
   {AEM_CLOCK_INPUT_STREAM      , "INPUT STREAM"},
   {AEM_CLOCK_WORLD_CLOCK       , "WORLD CLOCK"},
   {AEM_CLOCK_ANALOG_INPUT      , "ANALOG INPUT"},
   {AEM_CLOCK_DIGITAL_INPUT     , "DIGITAL INPUT"},
   {AEM_CLOCK_8021_AS           , "8021_AS"},
   {AEM_CLOCK_THUNDERBOLT       , "THUNDERBOLT"},
   {0, NULL}
};

/* frequency multipliers from table 7.6 pull field values */
static const value_string aem_frequency_multiplier_type_vals [] = {
   {0, "1.0"},
   {1, "1/1.001"},
   {2, "1.001"},
   {3, "24/25"},
   {4, "25/24"},
   {0, NULL}
};

static const value_string aem_control_value_type_vals [] = {
   {AEM_CONTROL_LINEAR_INT8        ,"CONTROL_LINEAR_INT8"},
   {AEM_CONTROL_LINEAR_UINT8       ,"CONTROL_LINEAR_UINT8"},
   {AEM_CONTROL_LINEAR_INT16       ,"CONTROL_LINEAR_INT16"},
   {AEM_CONTROL_LINEAR_UINT16      ,"CONTROL_LINEAR_UINT16"},
   {AEM_CONTROL_LINEAR_INT32       ,"CONTROL_LINEAR_INT32"},
   {AEM_CONTROL_LINEAR_UINT32      ,"CONTROL_LINEAR_UINT32"},
   {AEM_CONTROL_LINEAR_INT64       ,"CONTROL_LINEAR_INT64"},
   {AEM_CONTROL_LINEAR_UINT64      ,"CONTROL_LINEAR_UINT64"},
   {AEM_CONTROL_LINEAR_FLOAT       ,"CONTROL_LINEAR_FLOAT"},
   {AEM_CONTROL_LINEAR_DOUBLE      ,"CONTROL_LINEAR_DOUBLE"},
   {AEM_CONTROL_SELECTOR_INT8      ,"CONTROL_SELECTOR_INT8"},
   {AEM_CONTROL_SELECTOR_UINT8     ,"CONTROL_SELECTOR_UINT8"},
   {AEM_CONTROL_SELECTOR_INT16     ,"CONTROL_SELECTOR_INT16"},
   {AEM_CONTROL_SELECTOR_UINT16    ,"CONTROL_SELECTOR_UINT16"},
   {AEM_CONTROL_SELECTOR_INT32     ,"CONTROL_SELECTOR_INT32"},
   {AEM_CONTROL_SELECTOR_UINT32    ,"CONTROL_SELECTOR_UINT32"},
   {AEM_CONTROL_SELECTOR_INT64     ,"CONTROL_SELECTOR_INT64"},
   {AEM_CONTROL_SELECTOR_UINT64    ,"CONTROL_SELECTOR_UINT64"},
   {AEM_CONTROL_SELECTOR_FLOAT     ,"CONTROL_SELECTOR_FLOAT"},
   {AEM_CONTROL_SELECTOR_DOUBLE    ,"CONTROL_SELECTOR_DOUBLE"},
   {AEM_CONTROL_UTF8               ,"CONTROL_UTF8"},
   {AEM_CONTROL_BODE_PLOT          ,"CONTROL_BODE_PLOT"},
   {AEM_CONTROL_ARRAY_INT8         ,"CONTROL_ARRAY_INT8"},
   {AEM_CONTROL_ARRAY_UINT8        ,"CONTROL_ARRAY_UINT8"},
   {AEM_CONTROL_ARRAY_INT16        ,"CONTROL_ARRAY_INT16"},
   {AEM_CONTROL_ARRAY_UINT16       ,"CONTROL_ARRAY_UINT16"},
   {AEM_CONTROL_ARRAY_INT32        ,"CONTROL_ARRAY_INT32"},
   {AEM_CONTROL_ARRAY_UINT32       ,"CONTROL_ARRAY_UINT32"},
   {AEM_CONTROL_ARRAY_INT64        ,"CONTROL_ARRAY_INT64"},
   {AEM_CONTROL_ARRAY_UINT64       ,"CONTROL_ARRAY_UINT64"},
   {AEM_CONTROL_ARRAY_FLOAT        ,"CONTROL_ARRAY_FLOAT"},
   {AEM_CONTROL_ARRAY_DOUBLE       ,"CONTROL_ARRAY_DOUBLE"},
   {AEM_CONTROL_VENDOR             ,"CONTROL_CONTROL_VENDOR"},
   {0                              , NULL}
};

static const value_string aem_jack_type_vals [] = {
   {AEM_JACKTYPE_SPEAKER            ,"SPEAKER" },
   {AEM_JACKTYPE_HEADPHONE          ,"HEADPHONE" },
   {AEM_JACKTYPE_ANALOG_MICROPHONE  ,"ANALOG_MICROPHONE" },
   {AEM_JACKTYPE_SPDIF              ,"SPDIF" },
   {AEM_JACKTYPE_ADAT               ,"ADAT" },
   {AEM_JACKTYPE_TDIF               ,"TDIF" },
   {AEM_JACKTYPE_MADI               ,"MADI" },
   {AEM_JACKTYPE_UNBALANCED_ANALOG  ,"UNBALANCED_ANALOG" },
   {AEM_JACKTYPE_BALANCED_ANALOG    ,"BALANCED_ANALOG" },
   {AEM_JACKTYPE_DIGITAL            ,"DIGITAL" },
   {AEM_JACKTYPE_MIDI               ,"MIDI" },
   {AEM_JACKTYPE_AES_EBU            ,"AES_EBU" },
   {AEM_JACKTYPE_COMPOSITE_VIDEO    ,"COMPOSITE_VIDEO" },
   {AEM_JACKTYPE_S_VHS_VIDEO        ,"S_VHS_VIDEO" },
   {AEM_JACKTYPE_COMPONENT_VIDEO    ,"COMPONENT_VIDEO" },
   {AEM_JACKTYPE_DVI                ,"DVI" },
   {AEM_JACKTYPE_HDMI               ,"HDMI" },
   {AEM_JACKTYPE_UDI                ,"UDI" },
   {AEM_JACKTYPE_DISPLAYPORT        ,"DISPLAYPORT" },
   {AEM_JACKTYPE_ANTENNA            ,"ANTENNA" },
   {AEM_JACKTYPE_ANALOG_TUNER       ,"ANALOG_TUNER" },
   {AEM_JACKTYPE_ETHERNET           ,"ETHERNET" },
   {AEM_JACKTYPE_WIFI               ,"WIFI" },
   {AEM_JACKTYPE_USB                ,"USB" },
   {AEM_JACKTYPE_PCI                ,"PCI" },
   {AEM_JACKTYPE_PCI_E              ,"PDI_E" },
   {AEM_JACKTYPE_SCSI               ,"SCSI" },
   {AEM_JACKTYPE_ATA                ,"ATA" },
   {AEM_JACKTYPE_IMAGER             ,"IMAGER" },
   {AEM_JACKTYPE_IR                 ,"IR" },
   {AEM_JACKTYPE_THUNDERBOLT        ,"THUNDERBOLT" },
   {AEM_JACKTYPE_SATA               ,"SATA" },
   {AEM_JACKTYPE_SMPTE_LTC          ,"SMPTE_LTC" },
   {AEM_JACKTYPE_DIGITAL_MICROPHONE ,"DIGITAL_MICROPHONE" },
   {0, NULL }
};

/* value_string uses a 32 bit integer id, control uses 64.
 * TODO - make custom formatter for hf_aem_control_type
static const value_string aem_control_type_vals [] = {
   {AEM_CONTROL_ENABLE              , "ENABLE"},
   {AEM_CONTROL_DELAY               , "DELAY"},
   {AEM_CONTROL_POW_LINE_FREQ       , "POW_LINE_FREQ"},
   {AEM_CONTROL_ROLLPITCHYAW_ABS    , "ROLLPITCHYAW_ABS"},
   {AEM_CONTROL_ROLLPITCHYAW_REL    , "ROLLPITCHYAW_REL"},
   {AEM_CONTROL_SURGESWAYHEAVE_ABS  , "SURGESWAYHEAVE_ABS"},
   {AEM_CONTROL_SURGESWAYHEAVE_REL  , "SURGESWAYHEAVE_REL"},
   {AEM_CONTROL_IDENTIFY            , "IDENTIFY"},
   {AEM_CONTROL_POWER_STATUS        , "POWER_STATUS"},
   {AEM_CONTROL_FAN_STATUS          , "FAN_STATUS"},
   {AEN_CONTROL_TEMPERATURE         , "TEMPERATURE"},
   {AEM_CONTROL_TEMPERATURE_SENSOR  , "TEMPERATURE_SENSOR"},
   {AEM_CONTROL_ALTITUDE            , "ALTITUDE"},
   {AEM_CONTROL_HUMIDITY            , "HUMIDITY"},
   {AEM_CONTROL_MUTE                , "MUTE"},
   {AEM_CONTROL_VOLUME              , "VOLUME"},
   {AEM_CONTROL_INVERT              , "INVERT"},
   {AEM_CONTROL_PANPOT              , "PANPOT"},
   {AEM_CONTROL_ISOLATE             , "ISOLATE"},
   {AEM_CONTROL_POSITION            , "POSITION"},
   {AEM_CONTROL_PHANTOM             , "PHANTOM"},
   {AEM_CONTROL_AUDIO_SCALE         , "AUDIO_SCALE"},
   {AEM_CONTROL_AUDIO_METERS        , "AUDIO_METERS"},
   {AEM_CONTROL_AUDIO_SPECTRUM      , "AUDIO_SPECTRUM"},
   {AEM_CONTROL_FILTER_RESPONSE     , "FILTER_RESPONSE"},
   {AEM_CONTROL_SCANNING_MODE       , "SCANNING_MODE"},
   {AEM_CONTROL_AUTO_EXP_MODE       , "AUTO_EXP_MODE"},
   {AEM_CONTROL_AUTO_EXP_PRIO       , "AUTO_EXP_PRIO"},
   {AEM_CONTROL_EXP_TIME_ABS        , "EXP_TIME_ABS"},
   {AEM_CONTROL_EXP_TIME_REL        , "EXP_TIME_REL"},
   {AEM_CONTROL_FOCUS_ABS           , "FOCUS_ABS"},
   {AEM_CONTROL_FOCUS_REL           , "FOCUS_REL"},
   {AEM_CONTROL_FOCUS_AUTO          , "FOCUS_AUTO"},
   {AEM_CONTROL_IRIS_ABS            , "IRIS_ABS"},
   {AEM_CONTROL_IRIS_REL            , "IRIS_REL"},
   {AEM_CONTROL_ZOOM_ABS            , "ZOOM_ABS"},
   {AEM_CONTROL_ZOOM_REL            , "ZOOM_REL"},
   {AEM_CONTROL_PRIVACY             , "PRIVACY"},
   {AEM_CONTROL_BACKLIGHT           , "BACKLIGHT"},
   {AEM_CONTROL_BRIGHTNESS          , "BRIGHTNESS"},
   {AEM_CONTROL_CONTRAST            , "CONTRAST"},
   {AEM_CONTROL_GAIN                , "GAIN"},
   {AEM_CONTROL_HUE                 , "HUE"},
   {AEM_CONTROL_SATURATION          , "SATURATION"},
   {AEM_CONTROL_SHARPNESS           , "SHARPNESS"},
   {AEM_CONTROL_GAMMA               , "GAMMA"},
   {AEM_CONTROL_WHITE_BAL_TEMP      , "WHITE_BAL_TEMP"},
   {AEM_CONTROL_WHITE_BAL_TENP_AUTO , "WHITE_BAL_TEMP_AUTO"},
   {AEM_CONTROL_WHITE_BAL_COMP      , "WHITE_BAL_COMP"},
   {AEM_CONTROL_WHITE_BAL_COMP_AUTO , "WHITE_BAL_COMP_AUTO"},
   {AEM_CONTROL_DIGITAL_ZOOM        , "DIGITAL_ZOOM"},
   {0                               , NULL}
};
*/

static const value_string aecp_address_type_vals [] = {
   {AECP_ADDRESS_MAC  , "MAC"},
   {AECP_ADDRESS_IPV4 , "IPV4"},
   {AECP_ADDRESS_IPV6 , "IPV6"},
   {0                 , NULL}
};

static const value_string aecp_keychain_id_type_vals [] = {
   {AECP_KEYCHAIN_NONE         , "NONE"},
   {AECP_KEYCHAIN_MANUFACTURER , "MANUFACTURER"},
   {AECP_KEYCHAIN_PRODUCT      , "PRODUCT"},
   {AECP_KEYCHAIN_ENTITY       , "ENTITY"},
   {AECP_KEYCHAIN_USER         , "USER"},
   {0                          ,  NULL}
};

static const value_string aecp_direction_type_vals [] = {
   {AECP_DIRECTION_HORIZONTAL , "HORIZONTAL"},
   {AECP_DIRECTION_VERTICAL   , "VERTICAL"},
   {0                         , NULL}
};

static const value_string aem_descriptor_type_vals[] = {
   {AEM_DESCRIPTOR_ENTITY              , "ENTITY"},
   {AEM_DESCRIPTOR_CONFIGURATION       , "CONFIGURATION"},
   {AEM_DESCRIPTOR_AUDIO               , "AUDIO_UNIT"},
   {AEM_DESCRIPTOR_VIDEO               , "VIDEO_UNIT"},
   {AEM_DESCRIPTOR_SENSOR              , "SENSOR_UNIT"},
   {AEM_DESCRIPTOR_STREAM_INPUT        , "STREAM_INPUT"},
   {AEM_DESCRIPTOR_STREAM_OUTPUT       , "STREAM_OUTPUT"},
   {AEM_DESCRIPTOR_EXTERNAL_JACK_INPUT , "JACK_INPUT"},
   {AEM_DESCRIPTOR_EXTERNAL_JACK_OUTPUT, "JACK_OUTPUT"},
   {AEM_DESCRIPTOR_AUDIO_PORT_INPUT    , "AUDIO_PORT_INPUT"},
   {AEM_DESCRIPTOR_AUDIO_PORT_OUTPUT   , "AUDIO_PORT_OUTPUT"},
   {AEM_DESCRIPTOR_VIDEO_PORT_INPUT    , "VIDEO_PORT_INPUT"},
   {AEM_DESCRIPTOR_VIDEO_PORT_OUTPUT   , "VIDEO_PORT_OUTPUT"},
   {AEM_DESCRIPTOR_EXTERNAL_PORT_INPUT , "EXTERNAL_PORT_INPUT"},
   {AEM_DESCRIPTOR_EXTERNAL_PORT_OUTPUT, "EXTERNAL_PORT_OUTPUT"},
   {AEM_DESCRIPTOR_SENSOR_PORT_INPUT   , "SENSOR_PORT_INPUT"},
   {AEM_DESCRIPTOR_SENSOR_PORT_OUTPUT  , "SENSOR_PORT_OUTPUT"},
   {AEM_DESCRIPTOR_INTERNAL_PORT_INPUT , "INTERNAL_PORT_INPUT"},
   {AEM_DESCRIPTOR_INTERNAL_PORT_OUTPUT, "INTERNAL_PORT_OUTPUT"},
   {AEM_DESCRIPTOR_AVB_INTERFACE       , "AVB_INTERFACE"},
   {AEM_DESCRIPTOR_CLOCK_SOURCE        , "CLOCK_SOURCE"},
   {AEM_DESCRIPTOR_AUDIO_MAP           , "AUDIO_MAP"},
   {AEM_DESCRIPTOR_AUDIO_CLUSTER       , "AUDIO_CLUSTER"},
   {AEM_DESCRIPTOR_CONTROL             , "CONTROL"},
   {AEM_DESCRIPTOR_SIGNAL_SELECTOR     , "SIGNAL_SELECTOR"},
   {AEM_DESCRIPTOR_MIXER               , "MIXER"},
   {AEM_DESCRIPTOR_MATRIX              , "MATRIX"},
   {AEM_DESCRIPTOR_LOCALE              , "LOCALE"},
   {AEM_DESCRIPTOR_STRINGS             , "STRINGS"},
   {AEM_DESCRIPTOR_MATRIX_SIGNAL       , "MATRIX_SIGNAL"},
   {AEM_DESCRIPTOR_MEMORY_OBJECT       , "MEMORY_OBJECT"},
   {0                                  , NULL}
};

static const value_string aem_status_type_vals[] = {
   {AEM_STATUS_SUCCESS                , "AEM_SUCCESS"},
   {AEM_STATUS_NOT_IMPLEMENTED        , "AEM_NOT_IMPLEMENTED"},
   {AEM_STATUS_NO_SUCH_DESCRIPTOR     , "AEM_NO_SUCH_DESCRIPTOR"},
   {AEM_STATUS_ENTITY_LOCKED          , "AEM_ENTITY_LOCKED"},
   {AEM_STATUS_ENTITY_ACQUIRED        , "AEM_ENTITY_ACQUIRED"},
   {AEM_STATUS_NOT_AUTHORIZED         , "AEM_NOT_AUTHORIZED"},
   {AEM_STATUS_INSUFFICIENT_PRIVILEGES, "AEM_INSUFFICIENT_PRIVILEGES"},
   {AEM_STATUS_BAD_ARGUMENTS          , "AEM_BAD_ARGUMENTS"},
   {AEM_STATUS_NO_RESOURCES           , "AEM_NO_RESOURCES"},
   {AEM_STATUS_IN_PROGRESS            , "AEM_IN_PROGRESS"},
   {0                                 , NULL}
};

static const value_string aecp_message_type_vals[] = {
   {AECP_AEM_COMMAND_MESSAGE,             "AEM_COMMAND"},
   {AECP_AEM_RESPONSE_MESSAGE,            "AEM_RESPONSE"},
   {AECP_ADDRESS_ACCESS_COMMAND_MESSAGE,  "ADDRESS_ACCESS_COMMAND"},
   {AECP_ADDRESS_ACCESS_RESPONSE_MESSAGE, "ADDRESS_ACCESS_RESPONSE"},
   {AECP_AVC_COMMAND_MESSAGE,             "AVC_COMMAND"},
   {AECP_AVC_RESPONSE_MESSAGE,            "AVC_RESPONSE"},
   {AECP_VENDOR_UNIQUE_COMMAND_MESSAGE,   "VENDOR_UNIQUE_COMMAND"},
   {AECP_VENDOR_UNIQUE_RESPONSE_MESSAGE,  "VENDOR_UNIQUEU_RESPONSE"},
   {AECP_EXTENDED_COMMAND_MESSAGE,        "EXTENDED_COMMAND"},
   {AECP_EXTENDED_RESPONSE_MESSAGE,       "EXTENDED_RESPONSE"},
   {0,                                    NULL }
};

static const value_string aecp_command_type_vals[] = {
   {AECP_COMMAND_LOCK_ENTITY                   , "LOCK_ENTIY"},
   {AECP_COMMAND_READ_DESCRIPTOR               , "READ_DESCRIPTOR"},
   {AECP_COMMAND_WRITE_DESCRIPTOR              , "WRITE_DESCRIPTOR"},
   {AECP_COMMAND_ACQUIRE_ENTITY                , "ACQUIRE_ENTITY"},
   {AECP_COMMAND_CONTROLLER_AVAILABLE          , "CONTROLLER_AVAILABLE"},
   {AECP_COMMAND_SET_CLOCK_SOURCE              , "SET_CLOCK_SOURCE"},
   {AECP_COMMAND_GET_CLOCK_SOURCE              , "GET_CLOCK_SOURCE"},
   {AECP_COMMAND_SET_STREAM_FORMAT             , "SET_STREAM_FORMAT"},
   {AECP_COMMAND_GET_STREAM_FORMAT             , "GET_STREAM_FORMAT"},
   {AECP_COMMAND_SET_CONFIGURATION             , "SET_CONFIGURATION"},
   {AECP_COMMAND_GET_CONFIGURATION             , "GET_CONFIGURATION"},
   {AECP_COMMAND_SET_CONTROL_VALUE             , "SET_CONTROL_VALUE"},
   {AECP_COMMAND_GET_CONTROL_VALUE             , "GET_CONTROL_VALUE"},
   {AECP_COMMAND_SET_SIGNAL_SELECTOR           , "SET_SIGNAL_SELECTOR"},
   {AECP_COMMAND_GET_SIGNAL_SELECTOR           , "GET_SIGNAL_SELECTOR"},
   {AECP_COMMAND_SET_MIXER                     , "SET_MIXER"},
   {AECP_COMMAND_GET_MIXER                     , "GET_MIXER"},
   {AECP_COMMAND_SET_MATRIX                    , "SET_MATRIX"},
   {AECP_COMMAND_GET_MATRIX                    , "GET_MATRIX"},
   {AECP_COMMAND_START_STREAMING               , "START_STREAMING"},
   {AECP_COMMAND_STOP_STREAMING                , "STOP_STREAMING"},
   {AECP_COMMAND_SET_STREAM_INFO               , "SET_STREAM_INFO"},
   {AECP_COMMAND_GET_STREAM_INFO               , "GET_STREAM_INFO"},
   {AECP_COMMAND_SET_NAME                      , "SET_NAME"},
   {AECP_COMMAND_GET_NAME                      , "GET_NAME"},
   {AECP_COMMAND_SET_ASSOCIATION_ID            , "SET_ASSOCIATION_ID"},
   {AECP_COMMAND_GET_ASSOCIATION_ID            , "GET_ASSOCIATION_ID"},
   {AECP_COMMAND_AUTH_ADD_KEY                  , "AUTH_ADD_KEY"},
   {AECP_COMMAND_AUTH_GET_KEY                  , "AUTH_GET_KEY"},
   {AECP_COMMAND_AUTHENTICATE                  , "AUTHENTICATE"},
   {AECP_COMMAND_GET_COUNTERS                  , "GET_COUNTERS"},
   {AECP_COMMAND_REBOOT                        , "REBOOT"},
   {AECP_COMMAND_SET_MEDIA_FORMAT              , "SET_MEDIA_FORMAT"},
   {AECP_COMMAND_GET_MEDIA_FORMAT              , "GET_MEDIA_FORMAT"},
   {AECP_COMMAND_REGISTER_STATE_NOTIFICATION   , "REGISTER_STATE_NOTIFICATION"},
   {AECP_COMMAND_DEREGISTER_STATE_NOTIFICATION , "DEREGISTER_STATE_NOTIFICATION"},
   {AECP_COMMAND_REGISTER_QUERY_NOTIFICATION   , "REGISTER_QUERY_NOTIFICATION"},
   {AECP_COMMAND_DEREGISTER_QUERY_NOTIFICATION , "DEREGISTER_QUERY_NOTIFICATION"},
   {AECP_COMMAND_IDENTIFY_NOTIFICATION         , "IDENTIFY_NOTIFICATION"},
   {AECP_COMMAND_STATE_CHANGE_NOTIFICATION     , "STATE_CHANGE_NOTIFICATION"},
   {AECP_COMMAND_INCREMENT_CONTROL_VALUE       , "INCREMENT_CONTROL_VALUE"},
   {AECP_COMMAND_DECREMENT_CONTROL_VALUE       , "DECREMENT_CONTROL_VALUE"},
   {AECP_COMMAND_START_OPERATION               , "START_OPERATION"},
   {AECP_COMMAND_ABORT_OPERATION               , "ABORT_OPERATION"},
   {AECP_COMMAND_OPERATION_STATUS              , "OPERATION_STATUS"},
   {AECP_COMMAND_AUTH_GET_KEY_COUNT            , "AUTH_GET_KEY_COUNT"},
   {AECP_COMMAND_EXPANSION                     , "EXPANSION_RESERVED"},
   {AECP_COMMAND_GET_AS_PATH                   , "GET_AS_PATH"},
   {AECP_COMMAND_DEAUTHENTICATE                , "DEAUTHENTICATE"},
   {AECP_COMMAND_AUTH_REVOKE_KEY               , "AUTH_REVOKE_KEY"},
   {0                                          , NULL}
};


static const value_string adp_message_type_vals[] = {
   {ADP_ENTITY_AVAILABLE_MESSAGE,       "ENTITY_AVAILABLE"},
   {ADP_ENTITY_DEPARTING_MESSAGE,       "ENTITY_DEPARTING"},
   {ADP_ENTITY_DISCOVER_MESSAGE,        "ENTITY_DISCOVER"},
   {0,                                  NULL }
};

static const value_string acmp_message_type_vals[] = {
   {ACMP_CONNECT_TX_COMMAND,           "CONNECT_TX_COMMAND"},
   {ACMP_CONNECT_TX_RESPONSE,          "CONNECT_TX_RESPONSE"},
   {ACMP_DISCONNECT_TX_COMMAND,        "DISCONNECT_TX_COMMAND"},
   {ACMP_DISCONNECT_TX_RESPONSE,       "DISCONNECT_TX_RESPONSE"},
   {ACMP_GET_TX_STATE_COMMAND,         "GET_TX_STATE_COMMAND"},
   {ACMP_GET_TX_STATE_RESPONSE,        "GET_TX_STATE_RESPONSE"},
   {ACMP_CONNECT_RX_COMMAND,           "CONNECT_RX_COMMAND"},
   {ACMP_CONNECT_RX_RESPONSE,          "CONNECT_RX_RESPONSE"},
   {ACMP_DISCONNECT_RX_COMMAND,        "DISCONNECT_RX_COMMAND"},
   {ACMP_DISCONNECT_RX_RESPONSE,       "DISCONNECT_RX_RESPONSE"},
   {ACMP_GET_RX_STATE_COMMAND,         "GET_RX_STATE_COMMAND"},
   {ACMP_GET_RX_STATE_RESPONSE,        "GET_RX_STATE_RESPONSE"},
   {ACMP_GET_TX_CONNECTION_COMMAND,    "GET_TX_CONNECTION_COMMAND"},
   {ACMP_GET_TX_CONNECTION_RESPONSE,   "GET_TX_CONNECTION_RESPONSE"},
   {0,                                  NULL }
};

static const value_string acmp_status_field_vals[] = {
   {ACMP_STATUS_SUCCESS,                               "SUCCESS"},
   {ACMP_STATUS_LISTENER_UNKNOWN_ID,                   "LISTENER_UNKNOWN_ID"},
   {ACMP_STATUS_TALKER_UNKNOWN_ID,                     "TALKER_UNKNOWN_ID"},
   {ACMP_STATUS_TALKER_DEST_MAC_FAIL,                  "TALKER_DEST_MAC_FAIL"},
   {ACMP_STATUS_TALKER_NO_STREAM_INDEX,                "TALKER_NO_STREAM_INDEX"},
   {ACMP_STATUS_TALKER_NO_BANDWIDTH,                   "TALKER_NO_BANDWIDTH"},
   {ACMP_STATUS_TALKER_EXCLUSIVE,                      "TALKER_EXCLUSIVE"},
   {ACMP_STATUS_LISTENER_TALKER_TIMEOUT,               "LISTENER_TALKER_TIMEOUT"},
   {ACMP_STATUS_LISTENER_EXCLUSIVE,                    "LISTENER_EXCLUSIVE"},
   {ACMP_STATUS_STATE_UNAVAILABLE,                     "STATE_UNAVAILABLE"},
   {ACMP_STATUS_NOT_CONNECTED,                         "NOT_CONNECTED"},
   {ACMP_STATUS_NO_SUCH_CONNECTION,                    "NO_SUCH_CONNECTION"},
   {ACMP_STATUS_COULD_NOT_SEND_MESSAGE,                "COULD_NOT_SEND_MESSAGE"},
   {ACMP_STATUS_LISTENER_DEFAULT_FORMAT_INVALID,       "LISTENER_DEFAULT_FORMAT_INVALID"},
   {ACMP_STATUS_TALKER_DEFAULT_FORMAT_INVALID,         "TALKER_DEFAULT_FORMAT_INVALID"},
   {ACMP_STATUS_DEFAULT_SET_DIFFERENT,                 "DEFAULT_SET_DIFFERENT"},
   {ACMP_STATUS_NOT_SUPPORTED,                         "NOT_SUPPORTED"},
   {0,                                  NULL }
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
static int proto_17221 = -1;

/* AVDECC Discovery Protocol Data Unit (ADPDU) */
static int hf_adp_message_type = -1;
static int hf_adp_valid_time = -1;
static int hf_adp_cd_length = -1;
static int hf_adp_entity_guid = -1;
static int hf_adp_vendor_id = -1;
static int hf_adp_model_id = -1;
static int hf_adp_entity_cap = -1;
static int hf_adp_talker_stream_srcs = -1;
static int hf_adp_talker_cap = -1;
static int hf_adp_listener_stream_sinks = -1;
static int hf_adp_listener_cap = -1;
static int hf_adp_controller_cap = -1;
static int hf_adp_avail_index = -1;
static int hf_adp_as_gm_id = -1;
static int hf_adp_def_aud_format = -1;
static int hf_adp_def_vid_format = -1;
static int hf_adp_assoc_id = -1;
static int hf_adp_entity_type = -1;

/* Entity Capabilties Flags */
static int hf_adp_entity_cap_avdecc_ip = -1;
static int hf_adp_entity_cap_zero_conf = -1;
static int hf_adp_entity_cap_gateway_entity = -1;
static int hf_adp_entity_cap_avdecc_control = -1;
static int hf_adp_entity_cap_legacy_avc = -1;
static int hf_adp_entity_cap_assoc_id_support = -1;
static int hf_adp_entity_cap_assoc_id_valid = -1;

/* Talker Capabilities Flags */
static int hf_adp_talk_cap_implement = -1;
static int hf_adp_talk_cap_other_src = -1;
static int hf_adp_talk_cap_control_src = -1;
static int hf_adp_talk_cap_media_clk_src = -1;
static int hf_adp_talk_cap_smpte_src = -1;
static int hf_adp_talk_cap_midi_src = -1;
static int hf_adp_talk_cap_audio_src = -1;
static int hf_adp_talk_cap_video_src = -1;

/* Listener Capabilities Flags */
static int hf_adp_list_cap_implement = -1;
static int hf_adp_list_cap_other_sink = -1;
static int hf_adp_list_cap_control_sink = -1;
static int hf_adp_list_cap_media_clk_sink = -1;
static int hf_adp_list_cap_smpte_sink = -1;
static int hf_adp_list_cap_midi_sink = -1;
static int hf_adp_list_cap_audio_sink = -1;
static int hf_adp_list_cap_video_sink = -1;

/* Controller Capabilities Flags */
static int hf_adp_cont_cap_implement = -1;
static int hf_adp_cont_cap_layer3_proxy = -1;

/* Default Audio Format */
static int hf_adp_def_aud_sample_rates = -1;
static int hf_adp_def_aud_max_chan = -1;
static int hf_adp_def_aud_saf_flag = -1;
static int hf_adp_def_aud_float_flag = -1;
static int hf_adp_def_aud_chan_formats = -1;

/* Default Audio Sample Rates */
static int hf_adp_samp_rate_44k1 = -1;
static int hf_adp_samp_rate_48k = -1;
static int hf_adp_samp_rate_88k2 = -1;
static int hf_adp_samp_rate_96k = -1;
static int hf_adp_samp_rate_176k4 = -1;
static int hf_adp_samp_rate_192k = -1;

/* Audio Channel Formats */
static int hf_adp_chan_format_mono = -1;
static int hf_adp_chan_format_2ch = -1;
static int hf_adp_chan_format_3ch = -1;
static int hf_adp_chan_format_4ch = -1;
static int hf_adp_chan_format_5ch = -1;
static int hf_adp_chan_format_6ch = -1;
static int hf_adp_chan_format_7ch = -1;
static int hf_adp_chan_format_8ch = -1;
static int hf_adp_chan_format_10ch = -1;
static int hf_adp_chan_format_12ch = -1;
static int hf_adp_chan_format_14ch = -1;
static int hf_adp_chan_format_16ch = -1;
static int hf_adp_chan_format_18ch = -1;
static int hf_adp_chan_format_20ch = -1;
static int hf_adp_chan_format_22ch = -1;
static int hf_adp_chan_format_24ch = -1;


/* ***************************************************************** */
/*     AVDECC Enumeration and Control Protocol Data Unit (AECPDU)    */
/* ***************************************************************** */
static int hf_aecp_address_type = -1;
static int hf_aecp_association_id = -1;
static int hf_aecp_auth_token = -1;
static int hf_aecp_backup_stream_switch = -1;
static int hf_aecp_backup_stream_switch_valid = -1;
static int hf_aecp_bad_presentation_times = -1;
static int hf_aecp_bad_presentation_times_valid = -1;
static int hf_aecp_cd_length    = -1;
static int hf_aecp_clock_source_id = -1;
static int hf_aecp_command_type = -1;
static int hf_aecp_configuration = -1;
static int hf_aecp_connected_flag = -1;
static int hf_aecp_connection_flag = -1;
static int hf_aecp_continued_flag = -1;
static int hf_aecp_control_admin_flag = -1;
static int hf_aecp_control_user_l1 = -1;
static int hf_aecp_control_user_l2 = -1;
static int hf_aecp_control_user_l3 = -1;
static int hf_aecp_control_user_l4 = -1;
static int hf_aecp_controller_guid = -1;
static int hf_aecp_count = -1;
static int hf_aecp_default_format_valid_flag = -1;
static int hf_aecp_descriptor_id = -1;
static int hf_aecp_descriptor_type = -1;
static int hf_aecp_descriptors = -1;
static int hf_aecp_dest_mac_valid_flag = -1;
static int hf_aecp_entity_specific1 = -1;
static int hf_aecp_entity_specific1_valid = -1;
static int hf_aecp_entity_specific2 = -1;
static int hf_aecp_entity_specific2_valid = -1;
static int hf_aecp_entity_specific3 = -1;
static int hf_aecp_entity_specific3_valid = -1;
static int hf_aecp_entity_specific4 = -1;
static int hf_aecp_entity_specific4_valid = -1;
static int hf_aecp_entity_specific5 = -1;
static int hf_aecp_entity_specific5_valid = -1;
static int hf_aecp_entity_specific6 = -1;
static int hf_aecp_entity_specific6_valid = -1;
static int hf_aecp_entity_specific7 = -1;
static int hf_aecp_entity_specific7_valid = -1;
static int hf_aecp_entity_specific8 = -1;
static int hf_aecp_entity_specific8_valid = -1;
static int hf_aecp_flags_32 = -1;
static int hf_aecp_gptp_gm_changed = -1;
static int hf_aecp_gptp_locked = -1;
static int hf_aecp_gptp_unlocked = -1;
static int hf_aecp_gptp_unlocked_valid = -1;
static int hf_aecp_gtpt_locked_valid = -1;
static int hf_aecp_ipv4_address = -1;
static int hf_aecp_ipv6_address = -1;
static int hf_aecp_key = -1;
static int hf_aecp_key_count = -1;
static int hf_aecp_key_guid = -1;
static int hf_aecp_key_length = -1;
static int hf_aecp_key_number = -1;
static int hf_aecp_key_part = -1;
static int hf_aecp_key_permissions = -1;
static int hf_aecp_keychain_id = -1;
static int hf_aecp_keytype = -1;
static int hf_aecp_locked_guid = -1;
static int hf_aecp_mac_address = -1;
static int hf_aecp_matrix_affected_item_count = -1;
static int hf_aecp_matrix_column = -1;
static int hf_aecp_matrix_direction = -1;
static int hf_aecp_matrix_item_offset = -1;
static int hf_aecp_matrix_region_height = -1;
static int hf_aecp_matrix_region_width = -1;
static int hf_aecp_matrix_rep = -1;
static int hf_aecp_matrix_row = -1;
static int hf_aecp_matrix_value_count = -1;
static int hf_aecp_media_clock_toggles = -1;
static int hf_aecp_media_clock_toggles_valid = -1;
static int hf_aecp_media_format = -1;
static int hf_aecp_media_locked = -1;
static int hf_aecp_media_locked_valid = -1;
static int hf_aecp_media_seq_error = -1;
static int hf_aecp_media_unlocked = -1;
static int hf_aecp_media_unlocked_valid = -1;
static int hf_aecp_mem_obj_admin_flag = -1;
static int hf_aecp_mem_obj_settings_flag = -1;
static int hf_aecp_message_type = -1;
static int hf_aecp_missed_avdecc_response = -1;
static int hf_aecp_missed_avdecc_response_valid = -1;
static int hf_aecp_msrp_acc_lat_valid_flag = -1;
static int hf_aecp_msrp_accumulated_latency = -1;
static int hf_aecp_name = -1;
static int hf_aecp_name_index = -1;
static int hf_aecp_operation_id = -1;
static int hf_aecp_operation_type = -1;
static int hf_aecp_owner_guid = -1;
static int hf_aecp_packets_interest_rx = -1;
static int hf_aecp_packets_interest_rx_valid = -1;
static int hf_aecp_packets_rx = -1;
static int hf_aecp_packets_rx_valid = -1;
static int hf_aecp_packets_tx = -1;
static int hf_aecp_packets_tx_valid = -1;
static int hf_aecp_percent_complete = -1;
static int hf_aecp_persistent_flag = -1;
static int hf_aecp_private_key_read_flag = -1;
static int hf_aecp_private_key_write_flag = -1;
static int hf_aecp_public_key_write_flag = -1;
static int hf_aecp_query_id = -1;
static int hf_aecp_query_limit = -1;
static int hf_aecp_query_period = -1;
static int hf_aecp_query_type = -1;
static int hf_aecp_refused_avdecc_command = -1;
static int hf_aecp_refused_avdecc_command_valid = -1;
static int hf_aecp_release_flag = -1;
static int hf_aecp_reserved1_valid = -1;
static int hf_aecp_reserved2_valid = -1;
static int hf_aecp_reserved_counter = -1;
static int hf_aecp_seq_num_mismatch = -1;
static int hf_aecp_seq_num_mismatch_valid = -1;
static int hf_aecp_sequence_id = -1;
static int hf_aecp_signal_id = -1;
static int hf_aecp_signal_type = -1;
static int hf_aecp_signature = -1;
static int hf_aecp_signature_id = -1;
static int hf_aecp_signature_info = -1;
static int hf_aecp_signature_length = -1;
static int hf_aecp_srp_latency_violations = -1;
static int hf_aecp_srp_latency_violations_valid = -1;
static int hf_aecp_srp_refused = -1;
static int hf_aecp_srp_refused_valid = -1;
static int hf_aecp_stream_format = -1;
static int hf_aecp_stream_id_valid_flag = -1;
static int hf_aecp_stream_reset = -1;
static int hf_aecp_stream_reset_valid = -1;
static int hf_aecp_talker_bw_reserved = -1;
static int hf_aecp_talker_bw_reserved_valid = -1;
static int hf_aecp_target_guid  = -1;
static int hf_aecp_timestamp_uncertains = -1;
static int hf_aecp_timestamp_uncertains_valid = -1;
static int hf_aecp_timestamp_valids = -1;
static int hf_aecp_timestamp_valids_valid = -1;
static int hf_aecp_token_length = -1;
static int hf_aecp_u_flag = -1;
static int hf_aecp_unlock_flag = -1;
static int hf_aecp_unsupported_formats = -1;
static int hf_aecp_unsupported_formats_valid = -1;
static int hf_aecp_values = -1;
static int hf_aecp_values_count = -1;
static int hf_aecp_values_list = -1;

/* ***************************************************************** */
/*                   AVDECC Entity Model (AEM)                       */
/* ***************************************************************** */
static int hf_aem_am824_label = -1;
static int hf_aem_aspect_x = -1;
static int hf_aem_aspect_y = -1;
static int hf_aem_audio_channels = -1;
static int hf_aem_avb_interface_id = -1;
static int hf_aem_b_flag = -1;
static int hf_aem_backedup_talker_guid = -1;
static int hf_aem_backedup_talker_unique = -1;
static int hf_aem_backup_talker_guid_0 = -1;
static int hf_aem_backup_talker_guid_1 = -1;
static int hf_aem_backup_talker_guid_2 = -1;
static int hf_aem_backup_talker_unique_0 = -1;
static int hf_aem_backup_talker_unique_1 = -1;
static int hf_aem_backup_talker_unique_2 = -1;
static int hf_aem_base_audio_map = -1;
static int hf_aem_base_cluster = -1;
static int hf_aem_base_control = -1;
static int hf_aem_base_destination = -1;
static int hf_aem_base_external_input_port = -1;
static int hf_aem_base_external_output_port = -1;
static int hf_aem_base_frequency = -1;
static int hf_aem_base_internal_input_port = -1;
static int hf_aem_base_internal_output_port = -1;
static int hf_aem_base_matrix = -1;
static int hf_aem_base_mixer = -1;
static int hf_aem_base_signal_selector = -1;
static int hf_aem_base_source = -1;
static int hf_aem_base_stream_input_port = -1;
static int hf_aem_base_stream_output_port = -1;
static int hf_aem_base_strings = -1;
static int hf_aem_binary_blob = -1;
static int hf_aem_blob_size = -1;
static int hf_aem_block_latency = -1;
static int hf_aem_bpp = -1;
static int hf_aem_channel_count = -1;
static int hf_aem_channel_format = -1;
static int hf_aem_channels = -1;
static int hf_aem_clock_source_flags = -1;
static int hf_aem_clock_source_id = -1;
static int hf_aem_clock_source_location_id = -1;
static int hf_aem_clock_source_location_type = -1;
static int hf_aem_clock_source_name = -1;
static int hf_aem_clock_source_name_string = -1;
static int hf_aem_clock_source_type = -1;
static int hf_aem_cluster_name = -1;
static int hf_aem_cluster_name_string = -1;
static int hf_aem_color_format = -1;
static int hf_aem_color_space = -1;
static int hf_aem_comp1 = -1;
static int hf_aem_comp2 = -1;
static int hf_aem_comp3 = -1;
static int hf_aem_comp4 = -1;
static int hf_aem_compress_mode = -1;
static int hf_aem_configuration_name = -1;
static int hf_aem_configuration_name_string = -1;
static int hf_aem_configurations_count = -1;
static int hf_aem_control_domain = -1;
static int hf_aem_control_latency = -1;
static int hf_aem_control_location_id = -1;
static int hf_aem_control_location_type = -1;
static int hf_aem_control_name = -1;
static int hf_aem_control_name_string = -1;
static int hf_aem_control_type = -1;
static int hf_aem_control_value_type = -1;
static int hf_aem_count = -1;
static int hf_aem_cs_eui64 = -1;
static int hf_aem_ctrl_double = -1;
static int hf_aem_ctrl_float = -1;
static int hf_aem_ctrl_int16 = -1;
static int hf_aem_ctrl_int32 = -1;
static int hf_aem_ctrl_int64 = -1;
static int hf_aem_ctrl_int8 = -1;
static int hf_aem_ctrl_uint16 = -1;
static int hf_aem_ctrl_uint32 = -1;
static int hf_aem_ctrl_uint64 = -1;
static int hf_aem_ctrl_uint8 = -1;
static int hf_aem_ctrl_vals = -1;
static int hf_aem_current_configuration = -1;
static int hf_aem_current_format = -1;
static int hf_aem_current_sample_rate = -1;
static int hf_aem_current_signal_id = -1;
static int hf_aem_current_signal_type = -1;
static int hf_aem_dbs = -1;
static int hf_aem_default_signal_id = -1;
static int hf_aem_default_signal_type = -1;
static int hf_aem_descriptor_counts = -1;
static int hf_aem_descriptor_counts_count = -1;
static int hf_aem_descriptor_counts_offset = -1;
static int hf_aem_div = -1;
static int hf_aem_entity_guid = -1;
static int hf_aem_entity_model_id = -1;
static int hf_aem_entity_name = -1;
static int hf_aem_fdf_evt = -1;
static int hf_aem_fdf_sfc = -1;
static int hf_aem_firmware_version = -1;
static int hf_aem_flags_async_sample_rate_conv = -1;
static int hf_aem_flags_captive = -1;
static int hf_aem_flags_class_a = -1;
static int hf_aem_flags_class_b = -1;
static int hf_aem_flags_clock_sync_source = -1;
static int hf_aem_flags_sync_sample_rate_conv = -1;
static int hf_aem_fmt = -1;
static int hf_aem_formats_count = -1;
static int hf_aem_formats_offset = -1;
static int hf_aem_frame_rate = -1;
static int hf_aem_frequency = -1;
static int hf_aem_group_name = -1;
static int hf_aem_guid = -1;
static int hf_aem_height = -1;
static int hf_aem_iidc_format = -1;
static int hf_aem_iidc_mode = -1;
static int hf_aem_iidc_rate = -1;
static int hf_aem_interface_name = -1;
static int hf_aem_interface_name_string = -1;
static int hf_aem_interlace = -1;
static int hf_aem_internal_id = -1;
static int hf_aem_jack_flags = -1;
static int hf_aem_jack_id = -1;
static int hf_aem_jack_name = -1;
static int hf_aem_jack_name_string = -1;
static int hf_aem_jack_type = -1;
static int hf_aem_label_iec_60958_cnt = -1;
static int hf_aem_label_mbla_cnt = -1;
static int hf_aem_label_midi_cnt = -1;
static int hf_aem_label_smpte_cnt = -1;
static int hf_aem_length = -1;
static int hf_aem_locale_identifier = -1;
static int hf_aem_mapping_audio_channel = -1;
static int hf_aem_mapping_stream_channel = -1;
static int hf_aem_mapping_stream_index = -1;
static int hf_aem_mappings = -1;
static int hf_aem_mappings_offset = -1;
static int hf_aem_memory_object_type = -1;
static int hf_aem_mf_height = -1;
static int hf_aem_mf_width = -1;
static int hf_aem_mfd_type = -1;
static int hf_aem_model_name_string = -1;
static int hf_aem_msrp_mapping_priority = -1;
static int hf_aem_msrp_mapping_traffic_class = -1;
static int hf_aem_msrp_mappings = -1;
static int hf_aem_msrp_mappings_count = -1;
static int hf_aem_msrp_mappings_offset = -1;
static int hf_aem_msrp_vlan_id = -1;
static int hf_aem_nb_flag = -1;
static int hf_aem_number_audio_maps = -1;
static int hf_aem_number_destinations = -1;
static int hf_aem_number_matrices = -1;
static int hf_aem_number_mixers = -1;
static int hf_aem_number_of_clusters = -1;
static int hf_aem_number_of_controls = -1;
static int hf_aem_number_of_external_input_ports = -1;
static int hf_aem_number_of_external_output_ports = -1;
static int hf_aem_number_of_formats = -1;
static int hf_aem_number_of_internal_input_ports = -1;
static int hf_aem_number_of_internal_output_ports = -1;
static int hf_aem_number_of_mappings = -1;
static int hf_aem_number_of_sources = -1;
static int hf_aem_number_of_stream_input_ports = -1;
static int hf_aem_number_of_stream_output_ports = -1;
static int hf_aem_number_of_strings = -1;
static int hf_aem_number_of_values = -1;
static int hf_aem_number_signal_selectors = -1;
static int hf_aem_object_name = -1;
static int hf_aem_object_name_string = -1;
static int hf_aem_oui24 = -1;
static int hf_aem_path_latency = -1;
static int hf_aem_port_flags = -1;
static int hf_aem_pull_field = -1;
static int hf_aem_sample_rates = -1;
static int hf_aem_sample_rates_count = -1;
static int hf_aem_sample_rates_offset = -1;
static int hf_aem_serial_number = -1;
static int hf_aem_sf = -1;
static int hf_aem_sf_version = -1;
static int hf_aem_signal_id = -1;
static int hf_aem_signal_type = -1;
static int hf_aem_signals_count = -1;
static int hf_aem_signals_offset = -1;
static int hf_aem_sources = -1;
static int hf_aem_sources_offset = -1;
static int hf_aem_start_address = -1;
static int hf_aem_stream_channels = -1;
static int hf_aem_stream_flags = -1;
static int hf_aem_stream_format = -1;
static int hf_aem_stream_formats = -1;
static int hf_aem_stream_id = -1;
static int hf_aem_stream_name = -1;
static int hf_aem_stream_name_string = -1;
static int hf_aem_string = -1;
static int hf_aem_string_ref = -1;
static int hf_aem_subtype = -1;
static int hf_aem_supported_sample_rate = -1;
static int hf_aem_target_descriptor_id = -1;
static int hf_aem_target_descriptor_type = -1;
static int hf_aem_unit = -1;
static int hf_aem_unit_name = -1;
static int hf_aem_unit_name_string = -1;
static int hf_aem_unknown_descriptor = -1;
static int hf_aem_value_offset = -1;
static int hf_aem_values_offset = -1;
static int hf_aem_vendor_id = -1;
static int hf_aem_vendor_name_string = -1;
static int hf_aem_video_mode = -1;
static int hf_aem_width = -1;

/****************************************************************** */
/*     AVDECC Connection Management Protocol Data Unit (ACMPDU)     */
/* **************************************************************** */
static int hf_acmp_message_type = -1;
static int hf_acmp_status_field = -1;
static int hf_acmp_cd_length = -1;
static int hf_acmp_stream_id = -1;
static int hf_acmp_controller_guid = -1;
static int hf_acmp_talker_guid = -1;
static int hf_acmp_listener_guid = -1;
static int hf_acmp_talker_unique_id = -1;
static int hf_acmp_listener_unique_id = -1;
static int hf_acmp_stream_dest_mac = -1;
static int hf_acmp_connection_count = -1;
static int hf_acmp_sequence_id = -1;
static int hf_acmp_flags = -1;
static int hf_acmp_default_format = -1;

/* ACMP Flags */
static int hf_acmp_flags_class_b = -1;
static int hf_acmp_flags_fast_connect = -1;
static int hf_acmp_flags_saved_state = -1;
static int hf_acmp_flags_streaming_wait = -1;

/* Initialize the subtree pointers */
static int ett_17221 = -1;
/* ADP */
static int ett_adp_ent_cap = -1;
static int ett_adp_talk_cap = -1;
static int ett_adp_list_cap = -1;
static int ett_adp_cont_cap = -1;
static int ett_adp_aud_format = -1;
static int ett_adp_samp_rates = -1;
static int ett_adp_chan_format = -1;
/* ACMP */
static int ett_acmp_flags = -1;
/* AEM */
static int ett_aem_descriptor = -1;
static int ett_aem_desc_counts = -1;
static int ett_aem_sample_rates = -1;
static int ett_aem_stream_flags = -1;
static int ett_aem_stream_formats = -1;
static int ett_aem_jack_flags = -1;
static int ett_aem_port_flags = -1;
static int ett_aem_msrp_mappings = -1;
static int ett_aem_clock_source_flags = -1;
static int ett_aem_mappings = -1;
static int ett_aem_ctrl_vals = -1;
static int ett_aem_sources = -1;
static int ett_aem_media_format = -1;
static int ett_aem_stream_format = -1;

static int ett_aecp_descriptors = -1;
static int ett_aecp_flags_32 = -1;

typedef struct {
   int hf;
   guint16 size;
} ctrl_ref_vals;

/* convenience function */
static inline ctrl_ref_vals
get_ctrl_ref_vals(guint16 ctrl_val_type)
{
   ctrl_ref_vals ret;

   switch(ctrl_val_type) {
      case AEM_CONTROL_LINEAR_INT8:
      case AEM_CONTROL_SELECTOR_INT8:
      case AEM_CONTROL_ARRAY_INT8:
         ret.hf = hf_aem_ctrl_int8;
         ret.size = 1;
         break;
      case AEM_CONTROL_LINEAR_UINT8:
      case AEM_CONTROL_SELECTOR_UINT8:
      case AEM_CONTROL_ARRAY_UINT8:
         ret.hf = hf_aem_ctrl_uint8;
         ret.size = 1;
         break;
      case AEM_CONTROL_LINEAR_INT16:
      case AEM_CONTROL_SELECTOR_INT16:
      case AEM_CONTROL_ARRAY_INT16:
         ret.hf = hf_aem_ctrl_int16;
         ret.size = 2;
         break;
      case AEM_CONTROL_LINEAR_UINT16:
      case AEM_CONTROL_SELECTOR_UINT16:
      case AEM_CONTROL_ARRAY_UINT16:
         ret.hf = hf_aem_ctrl_uint16;
         ret.size = 2;
         break;
      case AEM_CONTROL_LINEAR_INT32:
      case AEM_CONTROL_SELECTOR_INT32:
      case AEM_CONTROL_ARRAY_INT32:
         ret.hf = hf_aem_ctrl_int32;
         ret.size = 4;
         break;
      case AEM_CONTROL_LINEAR_UINT32:
      case AEM_CONTROL_SELECTOR_UINT32:
      case AEM_CONTROL_ARRAY_UINT32:
         ret.hf = hf_aem_ctrl_uint32;
         ret.size = 4;
         break;
      case AEM_CONTROL_LINEAR_FLOAT:
      case AEM_CONTROL_SELECTOR_FLOAT:
      case AEM_CONTROL_ARRAY_FLOAT:
         ret.hf = hf_aem_ctrl_float;
         ret.size = 4;
         break;
      case AEM_CONTROL_LINEAR_INT64:
      case AEM_CONTROL_SELECTOR_INT64:
      case AEM_CONTROL_ARRAY_INT64:
         ret.hf = hf_aem_ctrl_int64;
         ret.size = 8;
         break;
      case AEM_CONTROL_LINEAR_UINT64:
      case AEM_CONTROL_SELECTOR_UINT64:
      case AEM_CONTROL_ARRAY_UINT64:
         ret.hf = hf_aem_ctrl_uint64;
         ret.size = 8;
         break;
      case AEM_CONTROL_LINEAR_DOUBLE:
      case AEM_CONTROL_SELECTOR_DOUBLE:
      case AEM_CONTROL_ARRAY_DOUBLE:
         ret.hf = hf_aem_ctrl_double;
         ret.size = 8;
         break;
      case AEM_CONTROL_BODE_PLOT:
         ret.hf = -1;
         ret.size = 12;
         break;
      default:
         ret.size = 0;
         ret.hf = -1;
         break;
   }
   return ret;
}

static void
dissect_17221_stream_format(tvbuff_t *tvb, proto_tree *tree)
{
   proto_item *stream_tree;
   proto_item *stream_ti;
   guint8 version;
   guint16 subtype;
   guint8 sf;
   guint8 fmt;
   guint8 fdf_evt;

   /* subtree */
   stream_ti = proto_tree_add_item(tree, hf_aem_stream_format, tvb,
         0, 8, ENC_NA);
   stream_tree = proto_item_add_subtree(stream_ti, ett_aem_stream_format);

   /* get version */
   version = tvb_get_guint8(tvb, 0) & 0xC0;

   /* add the version to the tree */
   proto_tree_add_item(stream_tree, hf_aem_sf_version, tvb,
         AEM_OFFSET_SF_VERSION, 1, ENC_BIG_ENDIAN);


   if (version == 0) {       /* stream format version 0 */

      subtype = tvb_get_ntohs(tvb, 0) & AEM_MASK_SF_SUBTYPE;

      proto_tree_add_item(stream_tree, hf_aem_sf, tvb,
            AEM_OFFSET_SF_SUBTYPE, 2, ENC_BIG_ENDIAN);

      switch(subtype) {
         case SF61883_IIDC_SUBTYPE:
            /* get sf */
            sf = tvb_get_guint8(tvb, 1) & 0x40;
            proto_tree_add_item(stream_tree, hf_aem_sf, tvb,
                  AEM_OFFSET_SF, 1, ENC_BIG_ENDIAN);

            if (sf == 0) { /* IIDC Stream Format */
               proto_tree_add_item(stream_tree, hf_aem_iidc_format, tvb,
                     AEM_OFFSET_IIDC_FORMAT, 1, ENC_BIG_ENDIAN);
               proto_tree_add_item(stream_tree, hf_aem_iidc_mode, tvb,
                     AEM_OFFSET_IIDC_MODE, 1, ENC_BIG_ENDIAN);
               proto_tree_add_item(stream_tree, hf_aem_iidc_rate, tvb,
                     AEM_OFFSET_IIDC_RATE, 1, ENC_BIG_ENDIAN);

            } else { /* 61883 Stream Format */
               proto_tree_add_item(stream_tree, hf_aem_fmt, tvb,
                     AEM_OFFSET_FMT, 1, ENC_BIG_ENDIAN);
               fmt = tvb_get_guint8(tvb, AEM_OFFSET_FMT) & 0x3F;
               if (fmt == 0x40) {       /* 61883-6 Stream Format */
                  proto_tree_add_item(stream_tree, hf_aem_fdf_evt, tvb,
                        AEM_OFFSET_FDF_EVT, 1, ENC_BIG_ENDIAN);
                  proto_tree_add_item(stream_tree, hf_aem_fdf_sfc, tvb,
                        AEM_OFFSET_FDF_SFC, 1, ENC_BIG_ENDIAN);
                  proto_tree_add_item(stream_tree, hf_aem_dbs, tvb,
                        AEM_OFFSET_DBS, 1, ENC_BIG_ENDIAN);

                  fdf_evt = tvb_get_guint8(tvb, AEM_OFFSET_FDF_EVT) & AEM_MASK_FDF_EVT;

                  proto_tree_add_item(stream_tree, hf_aem_b_flag, tvb,
                        AEM_OFFSET_B, 1, ENC_BIG_ENDIAN);
                  proto_tree_add_item(stream_tree, hf_aem_nb_flag, tvb,
                        AEM_OFFSET_NB, 1, ENC_BIG_ENDIAN);

                 if (fdf_evt == 0x00) { /* 61883-6 AM824 Stream Format  */
                    proto_tree_add_item(stream_tree, hf_aem_label_iec_60958_cnt, tvb,
                          AEM_OFFSET_LABEL_IEC_60958_CNT, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stream_tree, hf_aem_label_mbla_cnt, tvb,
                          AEM_OFFSET_LABEL_MBLA_CNT, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stream_tree, hf_aem_label_midi_cnt, tvb,
                          AEM_OFFSET_LABEL_MIDI_CNT, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stream_tree, hf_aem_label_smpte_cnt, tvb,
                          AEM_OFFSET_LABEL_SMPTE_CNT, 1, ENC_BIG_ENDIAN);
                  }
               } else if (fmt == 0x01) { /* 61883-8 Stream Format */
                  proto_tree_add_item(stream_tree, hf_aem_video_mode, tvb,
                        AEM_OFFSET_VIDEO_MODE, 1, ENC_BIG_ENDIAN);
                  proto_tree_add_item(stream_tree, hf_aem_compress_mode, tvb,
                        AEM_OFFSET_COMPRESS_MODE, 1, ENC_BIG_ENDIAN);
                  proto_tree_add_item(stream_tree, hf_aem_color_space, tvb,
                        AEM_OFFSET_COLOR_SPACE, 1, ENC_BIG_ENDIAN);
               }
            }
            break;
         case MMA_SUBTYPE:
            /* Defined by the MMA */
            break;
         case EXPERIMENTAL_SUBTYPE:
            /* used for experimental formats for development purposes only */
            break;
         default:
            /* unknown or unimplemented subtype */
            /* possibly a weather baloon, or swamp gas */
            break;
      }
   }
}

static void
dissect_17221_media_format(tvbuff_t *tvb, proto_tree *tree)
{
   proto_item *media_tree;
   proto_item *media_ti;
   guint32 oui24;
   guint8  mfd_type;

   /* grab the oui24 and mfd_type */
   oui24 = tvb_get_ntoh24(tvb, 0);
   mfd_type = tvb_get_guint8(tvb, 3);

   /* subtree */
   media_ti = proto_tree_add_item(tree, hf_aecp_media_format, tvb,
         0, 16, ENC_NA);
   media_tree = proto_item_add_subtree(media_ti, ett_aem_media_format);

   /* standard media formats */
   if (oui24 == OUI24_STANDARD_MEDIA_FORMAT) {
      /* Standard Media Format Fields */
      proto_tree_add_item(media_tree, hf_aem_oui24, tvb,
            0, 3, ENC_BIG_ENDIAN);
      proto_tree_add_item(media_tree, hf_aem_mfd_type, tvb,
            AEM_OFFSET_MFD_TYPE, 1, ENC_BIG_ENDIAN);

      /* break down the standard media format types */
      switch(mfd_type) {
         case MFD_TYPE_VIDEO:
            proto_tree_add_item(media_tree, hf_aem_div, tvb,
                  AEM_OFFSET_DIV, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_interlace, tvb,
                  AEM_OFFSET_INTERLACE, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_channels, tvb,
                  AEM_OFFSET_CHANNELS, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_color_format, tvb,
                  AEM_OFFSET_COLOR_FORMAT, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_bpp, tvb,
                  AEM_OFFSET_BPP, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_aspect_x, tvb,
                  AEM_OFFSET_ASPECT_X, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_aspect_y, tvb,
                  AEM_OFFSET_ASPECT_Y, 1 ,ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_frame_rate, tvb,
                  AEM_OFFSET_FRAME_RATE, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_comp1, tvb,
                  AEM_OFFSET_COMP1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_comp2, tvb,
                  AEM_OFFSET_COMP2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_comp3, tvb,
                  AEM_OFFSET_COMP3, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_comp4, tvb,
                  AEM_OFFSET_COMP4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_mf_width, tvb,
                  AEM_OFFSET_SVMF_WIDTH, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(media_tree, hf_aem_mf_height, tvb,
                  AEM_OFFSET_SVMF_HEIGHT, 2, ENC_BIG_ENDIAN);
            break;
         case MFD_TYPE_TRANSPORT_STRM:
            break;
         case MFD_TYPE_MIDI:
            break;
         case MFD_TYPE_TIME_CODE:
            break;
         case MFD_TYPE_CONTROL_PROTO:
            proto_tree_add_item(media_tree, hf_aem_cs_eui64, tvb,
                  AEM_OFFSET_CS_EUI64, 8, ENC_BIG_ENDIAN);
            break;
         default:
            /* unsupported MFD type */
            break;
      }
   } else { /* vendor specific media formats */

      /* these are not the media formats you are looking for */

   }
}


/* TODO following updates in Draft 18 and the pending Draft 19 this section will require major overhaul */
static void
dissect_17221_ctrl_val(tvbuff_t *tvb, proto_tree *tree, guint16 num_ctrl_vals, guint16 ctrl_val_type,
                       guint16 ctrl_offset)
{
   proto_item *ctrl_item;
   proto_item *ctrl_subtree;
   int i;
   guint32 bin_blob_size;
   gint string_length;
   ctrl_ref_vals ref;

   /* set up control values tree */
   ctrl_item = proto_tree_add_item(tree, hf_aem_ctrl_vals, tvb,
         0, 0, ENC_NA);
   ctrl_subtree = proto_item_add_subtree(ctrl_item, ett_aem_ctrl_vals);

   /* ctrl_val_type's are dissected below in this if/else block */
   /* for now only a few value types are in use, if I have time to come
      back to it I will add more fields to this but for now when viewing
      control_values you will need a copy of the spec handy to figure
      out what you are looking at, the get_ctrl_ref_vals function above
      will ideally be eliminated and this section will be a lot cleaner
      if/when that happens */

   ref = get_ctrl_ref_vals(ctrl_val_type);

   /* LINEAR TYPES */
   if (ctrl_val_type < 0xa) {
      for(i = 0; i < num_ctrl_vals; ++i) {
         proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
               ctrl_offset, ref.size, ENC_BIG_ENDIAN);
         ctrl_offset += ref.size;
         proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
               ctrl_offset, ref.size, ENC_BIG_ENDIAN);
         ctrl_offset += ref.size;
         proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
               ctrl_offset, ref.size, ENC_BIG_ENDIAN);
         ctrl_offset += ref.size;
         proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
               ctrl_offset, ref.size, ENC_BIG_ENDIAN);
         ctrl_offset += ref.size;
         proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
               ctrl_offset, ref.size, ENC_BIG_ENDIAN);
         ctrl_offset += ref.size;
         proto_tree_add_item(ctrl_subtree, hf_aem_unit, tvb,
               ctrl_offset, 2, ENC_BIG_ENDIAN);
         ctrl_offset += 2;
         proto_tree_add_item(ctrl_subtree, hf_aem_string_ref, tvb,
               ctrl_offset, 2, ENC_BIG_ENDIAN);
         ctrl_offset += 2;
      }

      /* SELECTOR TYPES */
   } else if (ctrl_val_type > 0x9 && ctrl_val_type < 0x14) {
      proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
            ctrl_offset, ref.size, ENC_BIG_ENDIAN);
      ctrl_offset += 2;
      proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
            ctrl_offset, ref.size, ENC_BIG_ENDIAN);
      ctrl_offset += 2;
      for(i = 0; i < num_ctrl_vals; ++i) {
         proto_tree_add_item(ctrl_subtree, ref.hf, tvb,
               ctrl_offset, ref.size, ENC_BIG_ENDIAN);
         ctrl_offset += 2;
      }
      proto_tree_add_item(ctrl_subtree, hf_aem_unit, tvb,
            ctrl_offset, 2, ENC_BIG_ENDIAN);

      /* UTF8 STRING TYPE */
   } else if (ctrl_val_type == 0x14) {
      tvb_get_const_stringz(tvb, ctrl_offset, &string_length);
      proto_tree_add_item(ctrl_subtree, hf_aem_string, tvb,
            ctrl_offset, string_length, ENC_ASCII|ENC_NA);

      /* BODE_PLOT TYPE */
   } else if (ctrl_val_type == 0x15) {
      for(i = 0; i < 12 + (num_ctrl_vals * 3); ++i) {
         proto_tree_add_item(ctrl_subtree, hf_aem_ctrl_float, tvb,
               ctrl_offset, 4, ENC_BIG_ENDIAN);
         ctrl_offset += 4;
      }

      /* ARRAY TYPES */
   } else if (ctrl_val_type > 0x15 && ctrl_val_type < 0x1f) {
      /* VENDOR CONTROL TYPE */
   } else if (ctrl_val_type == 0xfffe) {
      proto_tree_add_item(ctrl_subtree, hf_aem_guid, tvb,
            ctrl_offset, 8, ENC_BIG_ENDIAN);
      ctrl_offset += 8;
      bin_blob_size = tvb_get_ntohl(tvb, ctrl_offset);
      proto_tree_add_item(ctrl_subtree, hf_aem_blob_size, tvb,
            ctrl_offset, 4, ENC_BIG_ENDIAN);
      ctrl_offset += 4;
      proto_tree_add_item(ctrl_subtree, hf_aem_binary_blob, tvb,
            ctrl_offset, bin_blob_size, ENC_NA);
   }
}

/* dissect descriptors from the AVDECC Entity Model (AEM) */
/* this dissector is not registered */
static void
dissect_17221_aem(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
   guint16 desc_type;
   guint16 ctrl_val_type;
   guint16 num_ctrl_vals;
   tvbuff_t *next_tvb;
   int i;

   /* Mr. Subtree and Mr. Counter will be used as the loop limit and
    * subtree object for arrays in the descriptors, rather than declaring
    * a separate variable for each possible case in the switch which uses
    * arrays.
    */
   proto_item *mr_subtree;
   proto_item *mr_item;
   guint32 mr_offset;
   guint16 mr_counter;

   gdouble frequency;
   gint freq_mult;
   gint base_freq;

   proto_item *aem_tree;
   /* used in creation of descriptor subtree */
   proto_item *desc_ti;


   /* get the type of this descriptor */
   desc_type = tvb_get_ntohs(tvb, 0);

   /* Load the descriptor type and id fields, add subtree */
   desc_ti = proto_tree_add_item(tree, hf_aecp_descriptor_type, tvb,
         AEM_OFFSET_DESCRIPTOR_TYPE, 2, ENC_BIG_ENDIAN);
   aem_tree = proto_item_add_subtree(desc_ti, ett_aem_descriptor);

   proto_tree_add_item(aem_tree, hf_aecp_descriptor_id, tvb,
         AEM_OFFSET_DESCRIPTOR_ID, 2, ENC_BIG_ENDIAN);

   /* Dissect descriptors based on type. Where possible multiple cases *
    * will fall through to the same code                               */
   switch(desc_type) {
      case AEM_DESCRIPTOR_ENTITY:
         proto_tree_add_item(aem_tree, hf_aem_entity_guid, tvb,
               AEM_OFFSET_ENTITY_GUID, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_vendor_id, tvb,
               AEM_OFFSET_VENDOR_ID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_entity_model_id, tvb,
               AEM_OFFSET_ENTITY_MODEL_ID, 4, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_entity_cap, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_avdecc_ip, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_zero_conf, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_gateway_entity, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_avdecc_control, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_legacy_avc, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_assoc_id_support, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_cap_assoc_id_valid, tvb,
               AEM_OFFSET_ENTITY_CAPABILITIES, 4, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_talker_stream_srcs, tvb,
               AEM_OFFSET_TALKER_STREAM_SOURCES, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_talker_cap, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_implement, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_other_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_control_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_media_clk_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_smpte_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_midi_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_audio_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_talk_cap_video_src, tvb,
               AEM_OFFSET_TALKER_CAPABILITIES, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_listener_stream_sinks, tvb,
               AEM_OFFSET_LISTENER_STREAM_SINKS, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_listener_cap, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_implement, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_other_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_control_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_media_clk_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_smpte_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_midi_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_audio_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_list_cap_video_sink, tvb,
               AEM_OFFSET_LISTENER_CAPABILITIES, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_controller_cap, tvb,
               AEM_OFFSET_CONTROLLER_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_cont_cap_implement, tvb,
               AEM_OFFSET_CONTROLLER_CAPABILITIES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_cont_cap_layer3_proxy, tvb,
               AEM_OFFSET_CONTROLLER_CAPABILITIES, 4, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_adp_avail_index, tvb,
               AEM_OFFSET_AVAILABLE_INDEX, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_as_gm_id, tvb,
               AEM_OFFSET_AS_GRANDMASTER_ID, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aecp_association_id, tvb,
               AEM_OFFSET_ASSOCIATION_ID, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_adp_entity_type, tvb,
               AEM_OFFSET_ENTITY_TYPE, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_entity_name, tvb,
               AEM_OFFSET_ENTITY_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_vendor_name_string, tvb,
               AEM_OFFSET_VENDOR_NAME_STRING, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_model_name_string, tvb,
               AEM_OFFSET_MODEL_NAME_STRING, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_firmware_version, tvb,
               AEM_OFFSET_FIRMWARE_VERSION, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_group_name, tvb,
               AEM_OFFSET_GROUP_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_serial_number, tvb,
               AEM_OFFSET_SERIAL_NUMBER, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_configurations_count, tvb,
               AEM_OFFSET_CONFIGURATIONS_COUNT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_current_configuration, tvb,
               AEM_OFFSET_CURRENT_CONFIGURATION, 2, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_CONFIGURATION:
         proto_tree_add_item(aem_tree, hf_aem_configuration_name, tvb,
               AEM_OFFSET_CONFIGURATION_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_configuration_name_string, tvb,
               AEM_OFFSET_CONFIGURATION_NAME_STRING, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_descriptor_counts_count, tvb,
               AEM_OFFSET_DESCRIPTOR_COUNTS_COUNT, 2, ENC_BIG_ENDIAN);

         /* set up subtree, counter, and offset for sample rates array */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_descriptor_counts_offset, tvb,
               AEM_OFFSET_DESCRIPTOR_COUNTS_OFFSET, 2, ENC_BIG_ENDIAN);
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_DESCRIPTOR_COUNTS_COUNT);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_desc_counts);
         mr_offset = AEM_OFFSET_DESCRIPTOR_COUNTS;

         for(i = 0; i < mr_counter; ++i)
         {
            proto_tree_add_item(mr_subtree, hf_aecp_descriptor_type, tvb, mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
            proto_tree_add_item(mr_subtree, hf_aem_count, tvb, mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
         }
         break;
      case AEM_DESCRIPTOR_AUDIO:
         proto_tree_add_item(aem_tree, hf_aem_number_of_stream_input_ports, tvb,
               AEM_OFFSET_NUMBER_OF_STREAM_INPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_stream_input_port, tvb,
               AEM_OFFSET_BASE_STREAM_INPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_stream_output_ports, tvb,
               AEM_OFFSET_NUMBER_OF_STREAM_OUTPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_stream_output_port, tvb,
               AEM_OFFSET_BASE_STREAM_OUTPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_external_input_ports, tvb,
               AEM_OFFSET_NUMBER_OF_EXTERNAL_INPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_external_input_port, tvb,
               AEM_OFFSET_BASE_EXTERNAL_INPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_external_output_ports, tvb,
               AEM_OFFSET_NUMBER_OF_EXTERNAL_OUTPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_external_output_port, tvb,
               AEM_OFFSET_BASE_EXTERNAL_OUTPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_internal_input_ports, tvb,
               AEM_OFFSET_NUMBER_OF_INTERNAL_INPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_internal_input_port, tvb,
               AEM_OFFSET_BASE_INTERNAL_INPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_internal_output_ports, tvb,
               AEM_OFFSET_NUMBER_OF_INTERNAL_OUTPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_internal_output_port, tvb,
               AEM_OFFSET_BASE_INTERNAL_OUTPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_clock_source_id, tvb,
               AEM_OFFSET_CLOCK_SOURCE_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_controls, tvb,
               AEM_OFFSET_NUMBER_OF_CONTROLS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_control, tvb,
               AEM_OFFSET_BASE_CONTROL, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_unit_name, tvb,
               AEM_OFFSET_UNIT_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_unit_name_string, tvb,
               AEM_OFFSET_UNIT_NAME_STRING, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_aem_number_signal_selectors, tvb,
               AUDIO_UNIT_OFFSET_NUMBER_SIGNAL_SELECTORS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_signal_selector, tvb,
               AUDIO_UNIT_OFFSET_BASE_SIGNAL_SELECTOR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_mixers, tvb,
               AUDIO_UNIT_OFFSET_NUMBER_MIXERS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_mixer, tvb,
               AUDIO_UNIT_OFFSET_BASE_MIXER, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_matrices, tvb,
               AUDIO_UNIT_OFFSET_NUMBER_MATRICES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_matrix, tvb,
               AUDIO_UNIT_OFFSET_BASE_MATRIX, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_aem_current_sample_rate, tvb,
               AUDIO_UNIT_OFFSET_CURRENT_SAMPLE_RATE, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_sample_rates_offset, tvb,
               AUDIO_UNIT_OFFSET_SAMPLE_RATES_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_sample_rates_count, tvb,
               AUDIO_UNIT_OFFSET_SAMPLE_RATES_COUNT, 2, ENC_BIG_ENDIAN);

         /* set up subtree, counter, and offset for sample rates array */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_sample_rates, tvb,
               0, 0, ENC_NA);
         mr_counter = tvb_get_ntohs(tvb, AUDIO_UNIT_OFFSET_SAMPLE_RATES_COUNT);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_sample_rates);;
         mr_offset = AUDIO_UNIT_OFFSET_SAMPLE_RATES;

         /* loop to get the array values */
         for(i = 0; i < mr_counter; ++i) {
            proto_tree_add_item(mr_subtree, hf_aem_pull_field, tvb,
                  mr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mr_subtree, hf_aem_base_frequency, tvb,
                  mr_offset, 4, ENC_BIG_ENDIAN);
            base_freq = tvb_get_ntohl(tvb, mr_offset);
            freq_mult = base_freq;

            freq_mult &= 0xe0000000;
            freq_mult = freq_mult >> 29;
            base_freq &= 0x1fffffff;
            /* replace this with something not horrible */
            frequency = freq_mult == 0 ? 1 :
               freq_mult == 1 ? 1 / 1.001 :
               freq_mult == 2 ? 1.001 :
               freq_mult == 3 ? 24 / 25 :
               freq_mult == 4 ? 54 / 24 : 0;

            frequency *= base_freq;
            proto_tree_add_double(mr_subtree, hf_aem_frequency, tvb, mr_offset, 4, frequency);

            mr_offset += 4;
         }
         break;
      case AEM_DESCRIPTOR_VIDEO:
      case AEM_DESCRIPTOR_SENSOR:
         proto_tree_add_item(aem_tree, hf_aem_number_of_stream_input_ports, tvb,
               AEM_OFFSET_NUMBER_OF_STREAM_INPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_stream_input_port, tvb,
               AEM_OFFSET_BASE_STREAM_INPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_stream_output_ports, tvb,
               AEM_OFFSET_NUMBER_OF_STREAM_OUTPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_stream_output_port, tvb,
               AEM_OFFSET_BASE_STREAM_OUTPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_external_input_ports, tvb,
               AEM_OFFSET_NUMBER_OF_EXTERNAL_INPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_external_input_port, tvb,
               AEM_OFFSET_BASE_EXTERNAL_INPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_external_output_ports, tvb,
               AEM_OFFSET_NUMBER_OF_EXTERNAL_OUTPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_external_output_port, tvb,
               AEM_OFFSET_BASE_EXTERNAL_OUTPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_internal_input_ports, tvb,
               AEM_OFFSET_NUMBER_OF_INTERNAL_INPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_internal_input_port, tvb,
               AEM_OFFSET_BASE_INTERNAL_INPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_internal_output_ports, tvb,
               AEM_OFFSET_NUMBER_OF_INTERNAL_OUTPUT_PORTS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_internal_output_port, tvb,
               AEM_OFFSET_BASE_INTERNAL_OUTPUT_PORT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_clock_source_id, tvb,
               AEM_OFFSET_CLOCK_SOURCE_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_controls, tvb,
               AEM_OFFSET_NUMBER_OF_CONTROLS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_control, tvb,
               AEM_OFFSET_BASE_CONTROL, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_unit_name, tvb,
               AEM_OFFSET_UNIT_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_unit_name_string, tvb,
               AEM_OFFSET_UNIT_NAME_STRING, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_aem_number_signal_selectors, tvb,
               VIDEO_UNIT_OFFSET_NUMBER_SIGNAL_SELECTORS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_signal_selector, tvb,
               VIDEO_UNIT_OFFSET_BASE_SIGNAL_SELECTOR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_mixers, tvb,
               VIDEO_UNIT_OFFSET_NUMBER_MIXERS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_mixer, tvb,
               VIDEO_UNIT_OFFSET_BASE_MIXER, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_matrices, tvb,
               VIDEO_UNIT_OFFSET_NUMBER_MATRICES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_matrix, tvb,
               VIDEO_UNIT_OFFSET_BASE_MATRIX, 2, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_STREAM_INPUT:
      case AEM_DESCRIPTOR_STREAM_OUTPUT:
         proto_tree_add_item(aem_tree, hf_aem_stream_name, tvb,
               AEM_OFFSET_STREAM_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_stream_name_string, tvb,
               AEM_OFFSET_STREAM_NAME_STRING, 2, ENC_BIG_ENDIAN);
         /* set up a flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_stream_flags, tvb,
               AEM_OFFSET_STREAM_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_stream_flags);
         /* add flags to new subtree */
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_STREAM_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_class_a, tvb,
               AEM_OFFSET_STREAM_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_class_b, tvb,
               AEM_OFFSET_STREAM_FLAGS, 2, ENC_BIG_ENDIAN);
         /* done adding flags, continue with fields */
         proto_tree_add_item(aem_tree, hf_aem_stream_channels, tvb,
               AEM_OFFSET_STREAM_CHANNELS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_clock_source_id, tvb,
               AEM_OFFSET_CLOCK_SOURCE_ID_STREAM, 2, ENC_BIG_ENDIAN);

         /* stream format dissection */
         next_tvb = tvb_new_subset(tvb, AEM_OFFSET_CURRENT_FORMAT, 8, 8);
         dissect_17221_stream_format(next_tvb, aem_tree);

         proto_tree_add_item(aem_tree, hf_aem_formats_offset, tvb,
               AEM_OFFSET_FORMATS_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_formats, tvb,
               AEM_OFFSET_NUMBER_OF_FORMATS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backup_talker_guid_0, tvb,
               AEM_OFFSET_BACKUP_TALKER_GUID_0, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backup_talker_unique_0, tvb,
               AEM_OFFSET_BACKUP_TALKER_UNIQUE_0, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backup_talker_guid_1, tvb,
               AEM_OFFSET_BACKUP_TALKER_GUID_1, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backup_talker_unique_1, tvb,
               AEM_OFFSET_BACKUP_TALKER_UNIQUE_1, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backup_talker_guid_2, tvb,
               AEM_OFFSET_BACKUP_TALKER_GUID_2, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backup_talker_unique_2, tvb,
               AEM_OFFSET_BACKUP_TALKER_UNIQUE_2, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backedup_talker_guid, tvb,
               AEM_OFFSET_BACKEDUP_TALKER_GUID, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_backedup_talker_unique, tvb,
               AEM_OFFSET_BACKEDUP_TALKER_UNIQUE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_avb_interface_id, tvb,
               AEM_OFFSET_AVB_INTERFACE_ID, 2, ENC_BIG_ENDIAN);

         /* set up subtree, counter, and offset for formats array */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_stream_formats, tvb,
               0, 0, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_stream_formats);
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_FORMATS);
         mr_offset =  AEM_OFFSET_FORMATS;

         for(i = 0; i < mr_counter; ++i) {
            next_tvb = tvb_new_subset(tvb, mr_offset, 8, 8);
            dissect_17221_stream_format(next_tvb, mr_subtree);
            mr_offset += 8;
         }
         break;
      case AEM_DESCRIPTOR_EXTERNAL_JACK_INPUT:
      case AEM_DESCRIPTOR_EXTERNAL_JACK_OUTPUT:
         proto_tree_add_item(aem_tree, hf_aem_jack_name, tvb,
               AEM_OFFSET_JACK_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_jack_name_string, tvb,
               AEM_OFFSET_JACK_NAME_STRING, 2, ENC_BIG_ENDIAN);

         /* set up jack flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_jack_flags, tvb,
               AEM_OFFSET_JACK_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_jack_flags);
         proto_tree_add_item(mr_subtree, hf_aem_flags_captive, tvb,
               AEM_OFFSET_JACK_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_JACK_FLAGS, 2, ENC_BIG_ENDIAN);
         /* end jack flags subtree */

         proto_tree_add_item(aem_tree, hf_aem_jack_type, tvb,
               AEM_OFFSET_JACK_TYPE, 2, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_AUDIO_PORT_INPUT:
      case AEM_DESCRIPTOR_AUDIO_PORT_OUTPUT:
         /* set up port_flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_port_flags, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_port_flags);
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_async_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_sync_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         /* end port_flags subtree */
         proto_tree_add_item(aem_tree, hf_aem_audio_channels, tvb,
               AEM_OFFSET_AUDIO_CHANNELS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_clusters, tvb,
               AEM_OFFSET_NUMBER_OF_CLUSTERS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_cluster, tvb,
               AEM_OFFSET_BASE_CLUSTER, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_audio_map, tvb,
               AUDIO_PORT_OFFSET_BASE_AUDIO_MAP, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_audio_maps, tvb,
               AUDIO_PORT_OFFSET_NUMBER_AUDIO_MAPS, 2, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_VIDEO_PORT_INPUT:
      case AEM_DESCRIPTOR_VIDEO_PORT_OUTPUT:
         /* set up port_flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_port_flags, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_port_flags);
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_async_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_sync_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         /* end port_flags subtree */

         /* media format subdissection */
         next_tvb = tvb_new_subset(tvb, 6, 16, 16);
         dissect_17221_media_format(next_tvb, aem_tree);

         proto_tree_add_item(aem_tree, hf_aem_signal_type, tvb,
               AEM_OFFSET_SOURCE_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_id, tvb,
               AEM_OFFSET_SOURCE_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_stream_id, tvb,
               AEM_OFFSET_STREAM_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_formats_offset, tvb,
               AEM_OFFSET_FORMATS_OFFSET_VID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_formats_count, tvb,
               AEM_OFFSET_FORMATS_COUNT_VID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               VIDEO_PORT_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);

         /* load formats array */
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_FORMATS_COUNT_VID);
         mr_offset = VIDEO_PORT_OFFSET_FORMATS;
         for(i = 0; i < mr_counter; ++i) {
            next_tvb = tvb_new_subset(tvb, mr_offset, 16, 16);
            dissect_17221_media_format(next_tvb, aem_tree);
            mr_offset += 16;
         }
         break;
      case AEM_DESCRIPTOR_EXTERNAL_PORT_INPUT:
      case AEM_DESCRIPTOR_EXTERNAL_PORT_OUTPUT:
         /* set up port_flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_port_flags, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_port_flags);
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_async_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_sync_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         /* end port_flags subtree */
         proto_tree_add_item(aem_tree, hf_aem_signal_type, tvb,
               AEM_OFFSET_SOURCE_TYPE_EXT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_id, tvb,
               AEM_OFFSET_SOURCE_ID_EXT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_jack_id, tvb,
               EXTERNAL_PORT_OFFSET_JACK_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               EXTERNAL_PORT_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_SENSOR_PORT_INPUT:
      case AEM_DESCRIPTOR_SENSOR_PORT_OUTPUT:
         /* set up port_flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_port_flags, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_port_flags);
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_async_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_sync_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         /* end port_flags subtree */
         proto_tree_add_item(aem_tree, hf_aem_signal_type, tvb,
               AEM_OFFSET_SOURCE_TYPE_EXT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_id, tvb,
               AEM_OFFSET_SOURCE_ID_EXT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_stream_id, tvb,
               AEM_OFFSET_STREAM_ID_SEN, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               SENSOR_PORT_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_INTERNAL_PORT_INPUT:
      case AEM_DESCRIPTOR_INTERNAL_PORT_OUTPUT:
         /* set up port_flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_port_flags, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_port_flags);
         proto_tree_add_item(mr_subtree, hf_aem_flags_clock_sync_source, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_async_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_flags_sync_sample_rate_conv, tvb,
               AEM_OFFSET_PORT_FLAGS, 2, ENC_BIG_ENDIAN);
         /* end port_flags subtree */
         proto_tree_add_item(aem_tree, hf_aem_signal_type, tvb,
               AEM_OFFSET_SOURCE_TYPE_EXT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_id, tvb,
               AEM_OFFSET_SOURCE_ID_EXT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_internal_id, tvb,
               AEM_OFFSET_INTERNAL_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               INTERNAL_PORT_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_AVB_INTERFACE:
         proto_tree_add_item(aem_tree, hf_aecp_mac_address, tvb,
               AEM_OFFSET_MAC_ADDRESS, 6, ENC_NA);
         proto_tree_add_item(aem_tree, hf_adp_as_gm_id, tvb,
               AEM_OFFSET_AS_GRANDMASTER_ID_AVB, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_msrp_mappings_offset, tvb,
               AEM_OFFSET_MSRP_MAPPINGS_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_msrp_mappings_count, tvb,
               AEM_OFFSET_MSRP_MAPPINGS_COUNT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_interface_name, tvb,
               AVB_INTERFACE_OFFSET_INTERFACE_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_interface_name_string, tvb,
               AVB_INTERFACE_OFFSET_INTERFACE_NAME_STRING, 2, ENC_BIG_ENDIAN);

         /* set up subtree for mappings array */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_msrp_mappings, tvb,
               AVB_INTERFACE_MSRP_MAPPINGS, 0, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_msrp_mappings);
         mr_offset = AVB_INTERFACE_MSRP_MAPPINGS;
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_MSRP_MAPPINGS_COUNT);

         for(i = 0; i < mr_counter; ++i) {
           proto_tree_add_item(mr_subtree, hf_aem_msrp_mapping_traffic_class, tvb,
                 mr_offset, 1, ENC_BIG_ENDIAN);
           ++mr_offset;
           proto_tree_add_item(mr_subtree, hf_aem_msrp_mapping_priority, tvb,
                 mr_offset, 1, ENC_BIG_ENDIAN);
           ++mr_offset;
           proto_tree_add_item(mr_subtree, hf_aem_msrp_vlan_id, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
         }
         break;
      case AEM_DESCRIPTOR_CLOCK_SOURCE:
         proto_tree_add_item(aem_tree, hf_aem_clock_source_name, tvb,
               AEM_OFFSET_CLOCK_SOURCE_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_clock_source_name_string, tvb,
               AEM_OFFSET_CLOCK_SOURCE_NAME_STRING, 2, ENC_BIG_ENDIAN);
         /* set up clock_source_flags subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_clock_source_flags, tvb,
               AEM_OFFSET_CLOCK_SOURCE_FLAGS, 2, ENC_BIG_ENDIAN);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_clock_source_flags);
         /* all flags reserved */
         /* end clock_source_flags subtree */
         proto_tree_add_item(mr_subtree, hf_aem_clock_source_type, tvb,
               AEM_OFFSET_CLOCK_SOURCE_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aecp_clock_source_id, tvb,
               AEM_OFFSET_CLOCK_SOURCE_ID_CLK, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_clock_source_location_type, tvb,
               AEM_OFFSET_CLOCK_SOURCE_LOCATION_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(mr_subtree, hf_aem_clock_source_location_id, tvb,
               AEM_OFFSET_CLOCK_SOURCE_LOCATION_ID, 2, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_AUDIO_MAP:
         proto_tree_add_item(aem_tree, hf_aem_mappings_offset, tvb,
               AEM_OFFSET_MAPPINGS_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_mappings, tvb,
               AEM_OFFSET_NUMBER_OF_MAPPINGS, 2, ENC_BIG_ENDIAN);
         /* prepare mappings subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_mappings, tvb,
               0, 0, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_mappings);
         mr_offset = AEM_OFFSET_MAPPINGS;
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_MAPPINGS);

         for(i = 0; i < mr_counter; ++i) {
            proto_tree_add_item(mr_subtree, hf_aem_mapping_stream_index, tvb,
               mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
            proto_tree_add_item(mr_subtree, hf_aem_mapping_stream_channel, tvb,
               mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
            proto_tree_add_item(mr_subtree, hf_aem_mapping_audio_channel, tvb,
               mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
         }
         break;
      case AEM_DESCRIPTOR_AUDIO_CLUSTER:
         proto_tree_add_item(aem_tree, hf_aem_channel_count, tvb,
               AUDIO_CLUSTER_OFFSET_CHANNEL_COUNT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_path_latency, tvb,
               AUDIO_CLUSTER_OFFSET_PATH_LATENCY, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_am824_label, tvb,
               AUDIO_CLUSTER_OFFSET_AM824_LABEL, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_cluster_name, tvb,
               AUDIO_CLUSTER_OFFSET_CLUSTER_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_cluster_name_string, tvb,
               AUDIO_CLUSTER_OFFSET_CLUSTER_NAME_STRING, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_type, tvb,
               AUDIO_CLUSTER_OFFSET_SIGNAL_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_id, tvb,
               AUDIO_CLUSTER_OFFSET_SIGNAL_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               AUDIO_CLUSTER_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_CONTROL:
         proto_tree_add_item(aem_tree, hf_aem_control_type, tvb,
               AEM_OFFSET_CONTROL_TYPE, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_location_type, tvb,
               AEM_OFFSET_CONTROL_LOCATION_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_location_id, tvb,
               AEM_OFFSET_CONTROL_LOCATION_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_value_type, tvb,
               AEM_OFFSET_CONTROL_VALUE_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_domain, tvb,
               AEM_OFFSET_CONTROL_DOMAIN, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_name, tvb,
               AEM_OFFSET_CONTROL_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_control_name_string, tvb,
               AEM_OFFSET_CONTROL_NAME_STRING, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_values_offset, tvb,
               AEM_OFFSET_VALUES_OFFSET_CTRL, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_values, tvb,
               AEM_OFFSET_NUMBER_OF_VALUES_CTRL, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_type, tvb,
               AEM_OFFSET_SOURCE_TYPE_CTRL, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signal_id, tvb,
               AEM_OFFSET_SOURCE_ID_CTRL, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               CONTROL_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_latency, tvb,
               CONTROL_OFFSET_CONTROL_LATENCY, 4, ENC_BIG_ENDIAN);

         ctrl_val_type = tvb_get_ntohs(tvb, AEM_OFFSET_CONTROL_VALUE_TYPE);
         num_ctrl_vals = tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_VALUES_CTRL);
         dissect_17221_ctrl_val(tvb, aem_tree, num_ctrl_vals, ctrl_val_type,
                                CONTROL_OFFSET_VALUE_DETAILS);

         break;
      case AEM_DESCRIPTOR_SIGNAL_SELECTOR:
         proto_tree_add_item(aem_tree, hf_aem_control_location_type, tvb,
               AEM_OFFSET_CONTROL_LOCATION_TYPE_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_location_id, tvb,
               AEM_OFFSET_CONTROL_LOCATION_ID_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_domain, tvb,
               AEM_OFFSET_CONTROL_DOMAIN_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_name, tvb,
               AEM_OFFSET_CONTROL_NAME_SIGS, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_control_name_string, tvb,
               AEM_OFFSET_CONTROL_NAME_STRING_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_sources_offset, tvb,
               AEM_OFFSET_SOURCES_OFFSET_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_sources, tvb,
               AEM_OFFSET_NUMBER_OF_SOURCES_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_current_signal_type, tvb,
               AEM_OFFSET_CURRENT_SOURCE_TYPE_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_current_signal_id, tvb,
               AEM_OFFSET_CURRENT_SOURCE_ID_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_default_signal_type, tvb,
               AEM_OFFSET_DEFAULT_SOURCE_TYPE_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_default_signal_id, tvb,
               AEM_OFFSET_DEFAULT_SOURCE_ID_SIGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               SIGNAL_SELECTOR_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_latency, tvb,
               SIGNAL_SELECTOR_OFFSET_CONTROL_LATENCY, 4, ENC_BIG_ENDIAN);

         /* set up sources subtree */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_sources, tvb,
               0, 0, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_sources);
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_SOURCES_SIGS);
         mr_offset = SIGNAL_SELECTOR_OFFSET_SOURCES;

         for(i = 0; i < mr_counter; ++i) {
           proto_tree_add_item(mr_subtree, hf_aem_signal_type, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
           proto_tree_add_item(mr_subtree, hf_aem_signal_id, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
         }
         break;
      case AEM_DESCRIPTOR_MIXER:
         proto_tree_add_item(aem_tree, hf_aem_control_location_type, tvb,
               AEM_OFFSET_CONTROL_LOCATION_TYPE_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_location_id, tvb,
               AEM_OFFSET_CONTROL_LOCATION_ID_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_value_type, tvb,
               AEM_OFFSET_CONTROL_VALUE_TYPE_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_domain, tvb,
               AEM_OFFSET_CONTROL_DOMAIN_MXR, 2 ,ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_name, tvb,
               AEM_OFFSET_CONTROL_NAME_MXR, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_control_name_string, tvb,
               AEM_OFFSET_CONTROL_NAME_STRING_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_sources_offset, tvb,
               AEM_OFFSET_SOURCES_OFFSET_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_sources, tvb,
               AEM_OFFSET_NUMBER_OF_SOURCES_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_value_offset, tvb,
               AEM_OFFSET_VALUE_OFFSET_MXR, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               MIXER_OFFSET_BLOCK_LATENCY, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_latency, tvb,
               MIXER_OFFSET_CONTROL_LATENCY, 2, ENC_BIG_ENDIAN);

         /* set up subtree for sources */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_sources, tvb,
               0, 0, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_sources);
         mr_counter = tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_SOURCES_MXR);
         mr_offset = MIXER_OFFSET_SOURCES;

         for(i = 0; i < mr_counter; ++i) {
           proto_tree_add_item(mr_subtree, hf_aem_signal_type, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
           proto_tree_add_item(mr_subtree, hf_aem_signal_id, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
         }

         /* end sources subtree */

         ctrl_val_type = tvb_get_ntohs(tvb, AEM_OFFSET_CONTROL_VALUE_TYPE_MXR);
         num_ctrl_vals = 1;
         dissect_17221_ctrl_val(tvb, aem_tree, num_ctrl_vals, ctrl_val_type,
               MIXER_OFFSET_SOURCES + (tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_SOURCES_MXR) * 4));
         break;
      case AEM_DESCRIPTOR_MATRIX:
         proto_tree_add_item(aem_tree, hf_aem_control_type, tvb,
               AEM_OFFSET_CONTROL_TYPE_MTRX, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_location_type, tvb,
               AEM_OFFSET_CONTROL_LOCATION_TYPE_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_location_id, tvb,
               AEM_OFFSET_CONTROL_LOCATION_ID_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_value_type, tvb,
               AEM_OFFSET_CONTROL_VALUE_TYPE_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_domain, tvb,
               AEM_OFFSET_CONTROL_DOMAIN_MTRX, 2 ,ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_name, tvb,
               AEM_OFFSET_CONTROL_NAME_MTRX, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_control_name_string, tvb,
               AEM_OFFSET_CONTROL_NAME_STRING_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_width, tvb,
               AEM_OFFSET_WIDTH_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_height, tvb,
               AEM_OFFSET_HEIGHT_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_values_offset, tvb,
               AEM_OFFSET_VALUES_OFFSET_MTRX, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_values, tvb,
               AEM_OFFSET_NUMBER_OF_VALUES_MTRX, 2, ENC_BIG_ENDIAN);

         proto_tree_add_item(aem_tree, hf_aem_block_latency, tvb,
               MATRIX_OFFSET_BLOCK_LATENCY, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_control_latency, tvb,
               MATRIX_OFFSET_CONTROL_LATENCY, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_of_sources, tvb,
               MATRIX_OFFSET_NUMBER_SOURCES, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_source, tvb,
               MATRIX_OFFSET_BASE_SOURCE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_number_destinations, tvb,
               MATRIX_OFFSET_NUMBER_DESTINATIONS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_destination, tvb,
               MATRIX_OFFSET_BASE_DESTINATION, 2, ENC_BIG_ENDIAN);

         ctrl_val_type = tvb_get_ntohs(tvb, AEM_OFFSET_CONTROL_VALUE_TYPE_MTRX);
         num_ctrl_vals = tvb_get_ntohs(tvb, AEM_OFFSET_NUMBER_OF_VALUES_MTRX);
         dissect_17221_ctrl_val(tvb, aem_tree, num_ctrl_vals, ctrl_val_type,
                                MATRIX_OFFSET_VALUE_DETAILS);
         break;
      case AEM_DESCRIPTOR_LOCALE:
         proto_tree_add_item(aem_tree, hf_aem_locale_identifier, tvb,
               AEM_OFFSET_LOCALE_IDENTIFIER, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_number_of_strings, tvb,
               AEM_OFFSET_NUMBER_OF_STRINGS, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_base_strings, tvb,
               AEM_OFFSET_BASE_STRINGS, 2, ENC_BIG_ENDIAN);
         break;
      case AEM_DESCRIPTOR_STRINGS:
         mr_offset = AEM_OFFSET_STRING0;
         for(i = 0; i < 7; ++i) {
            proto_tree_add_item(aem_tree, hf_aem_string, tvb,
                  mr_offset, 64, ENC_ASCII|ENC_NA);
            mr_offset += 64;
         }
         break;
      case AEM_DESCRIPTOR_MATRIX_SIGNAL:
         proto_tree_add_item(aem_tree, hf_aem_signals_count, tvb,
               MATRIX_SIGNAL_OFFSET_SIGNALS_COUNT, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_signals_offset, tvb,
               MATRIX_SIGNAL_OFFSET_SIGNALS_OFFSET, 2, ENC_BIG_ENDIAN);
         /* set up subtree for signals */
         mr_item = proto_tree_add_item(aem_tree, hf_aem_sources, tvb,
               0, 0, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aem_sources);
         mr_counter = tvb_get_ntohs(tvb, MATRIX_SIGNAL_OFFSET_SIGNALS_COUNT);
         mr_offset = MATRIX_SIGNAL_OFFSET_SIGNALS_OFFSET;

         for(i = 0; i < mr_counter; ++i) {
           proto_tree_add_item(mr_subtree, hf_aem_signal_type, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
           proto_tree_add_item(mr_subtree, hf_aem_signal_id, tvb,
                 mr_offset, 2, ENC_BIG_ENDIAN);
           mr_offset += 2;
         }
         break;
      case AEM_DESCRIPTOR_MEMORY_OBJECT:
         proto_tree_add_item(aem_tree, hf_aem_memory_object_type, tvb,
               MEMORY_OBJECT_OFFSET_MEMORY_OBJECT_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_target_descriptor_type, tvb,
               MEMORY_OBJECT_OFFSET_TARGET_DESCRIPTOR_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_target_descriptor_id, tvb,
               MEMORY_OBJECT_OFFSET_TARGET_DESCRIPTOR_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_object_name, tvb,
               MEMORY_OBJECT_OFFSET_OBJECT_NAME, 64, ENC_ASCII|ENC_NA);
         proto_tree_add_item(aem_tree, hf_aem_object_name_string, tvb,
               MEMORY_OBJECT_OFFSET_OBJECT_NAME_STRING, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_start_address, tvb,
               MEMORY_OBJECT_OFFSET_START_ADDRESS, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aem_tree, hf_aem_length, tvb,
               MEMORY_OBJECT_OFFSET_LENGTH, 8, ENC_BIG_ENDIAN);
         break;
      default:
         proto_tree_add_item(aem_tree, hf_aem_unknown_descriptor, tvb,
               4, tvb_length(tvb) - 4, ENC_NA);
         break;
   }
}

/* dissect enumeration and control packets */
static void
dissect_17221_aecp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aecp_tree)
{
   guint16 c_type;
   guint16 addr_type;
#if 0
   guint16 ctrl_data_len;
   guint16 mess_status;
#endif
   guint16 mess_type;
   guint32 mr_offset;
   guint16 mr_counter;
   proto_item *mr_subtree;
   proto_item *mr_item;
   int i;
   /* next tvb for use in subdissection */
   tvbuff_t *next_tvb;
   proto_tree *flags_tree;
   proto_item *flags_ti;


   /* AEM Common Format Fields */
   proto_tree_add_item(aecp_tree, hf_aecp_message_type, tvb,
         AECP_VERSION_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(aecp_tree, hf_aecp_cd_length, tvb,
         AECP_CD_LENGTH_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(aecp_tree, hf_aecp_target_guid, tvb,
         AECP_TARGET_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(aecp_tree, hf_aecp_controller_guid, tvb,
         AECP_CONTROLLER_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(aecp_tree, hf_aecp_sequence_id, tvb,
         AECP_SEQUENCE_ID_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(aecp_tree, hf_aecp_u_flag, tvb,
         AECP_U_FLAG_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(aecp_tree, hf_aecp_command_type, tvb,
         AECP_COMMAND_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);

   /* get the command type for detailed dissection */
   c_type = tvb_get_ntohs(tvb, AECP_COMMAND_TYPE_OFFSET) & AECP_COMMAND_TYPE_MASK;

   /* get the control data length field - number of octets following target_guid */
#if 0
   ctrl_data_len = tvb_get_ntohs(tvb, AECP_CD_LENGTH_OFFSET) & AECP_CD_LENGTH_MASK;
#endif

   /* get the message type */
   mess_type = tvb_get_ntohs(tvb, 0) & ACMP_MSG_TYPE_MASK;

   /* get the status */
#if 0
   mess_status = tvb_get_ntohs(tvb, 2) & 0xF800;
#endif

   /* break dissection down by command type */
   /* fields are added in the order they are listed by 1722.1 */
   switch(c_type) {
      case AECP_COMMAND_LOCK_ENTITY:
         proto_tree_add_item(aecp_tree, hf_aecp_unlock_flag, tvb,
               AECP_FLAGS_OFFSET, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_locked_guid, tvb,
               AECP_LOCKED_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_READ_DESCRIPTOR:
         proto_tree_add_item(aecp_tree, hf_aecp_configuration, tvb,
               AECP_CONFIGURATION_OFFSET, 2, ENC_BIG_ENDIAN);

         if (mess_type == AECP_AEM_COMMAND_MESSAGE)
         {
            proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
                  AECP_DESCRIPTOR_TYPE_OFFSET_28, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
                  AECP_DESCRIPTOR_ID_OFFSET_30, 2, ENC_BIG_ENDIAN);
         }
         else
         {
            next_tvb = tvb_new_subset_remaining(tvb, 28);
            dissect_17221_aem(next_tvb, pinfo, aecp_tree);
         }
         break;
      case AECP_COMMAND_WRITE_DESCRIPTOR:
         proto_tree_add_item(aecp_tree, hf_aecp_configuration, tvb,
               AECP_CONFIGURATION_OFFSET, 2, ENC_BIG_ENDIAN);

         /* on command descriptor is value to write
          * on response descriptor is command value if successful
          * or old value if unsuccessful */
         next_tvb = tvb_new_subset_remaining(tvb, 28);
         dissect_17221_aem(next_tvb, pinfo, aecp_tree);
         break;
      case AECP_COMMAND_ACQUIRE_ENTITY:
         /* set up the flags subtree */
         flags_ti = proto_tree_add_item(aecp_tree, hf_aecp_flags_32, tvb,
               AECP_OFFSET_ACQUIRE_ENTITY_FLAGS, 4, ENC_BIG_ENDIAN);
         flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);
         proto_tree_add_item(flags_tree, hf_aecp_persistent_flag, tvb,
               AECP_OFFSET_ACQUIRE_ENTITY_FLAGS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_release_flag, tvb,
               AECP_OFFSET_ACQUIRE_ENTITY_FLAGS, 4, ENC_BIG_ENDIAN);
         /* end flags subtree */
         proto_tree_add_item(aecp_tree, hf_aecp_owner_guid, tvb,
               AECP_OFFSET_ACQUIRE_ENTITY_OWNER_GUID, 8, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_OFFSET_ACQUIRE_ENTITY_DESCRIPTOR_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_OFFSET_ACQUIRE_ENTITY_DESCRIPTOR_ID, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_CLOCK_SOURCE:
      case AECP_COMMAND_GET_CLOCK_SOURCE:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_OFFSET_CLOCK_SOURCE_DESCRIPTOR_TYPE, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_OFFSET_CLOCK_SOURCE_DESCRIPTOR_ID, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aem_clock_source_id, tvb,
               AECP_OFFSET_CLOCK_SOURCE_CLOCK_SOURCE_ID, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_STREAM_FORMAT:
      case AECP_COMMAND_GET_STREAM_FORMAT:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         next_tvb = tvb_new_subset(tvb, AECP_STREAM_FORMAT_OFFSET, 8, 8);
         dissect_17221_stream_format(next_tvb, aecp_tree);
         break;
      case AECP_COMMAND_SET_CONFIGURATION:
      case AECP_COMMAND_GET_CONFIGURATION:
         proto_tree_add_item(aecp_tree, hf_aecp_configuration,
               tvb, AECP_CONFIGURATION_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_CONTROL_VALUE:
      case AECP_COMMAND_GET_CONTROL_VALUE:
      case AECP_COMMAND_SET_MIXER:
      case AECP_COMMAND_GET_MIXER:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_SIGNAL_SELECTOR:
      case AECP_COMMAND_GET_SIGNAL_SELECTOR:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_signal_type, tvb,
               AECP_SOURCE_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_signal_id, tvb,
               AECP_SOURCE_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_MATRIX:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_column, tvb,
               AECP_MATRIX_COLUMN_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_row, tvb,
               AECP_MATRIX_ROW_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_region_width, tvb,
               AECP_MATRIX_REGION_WIDTH_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_region_height, tvb,
               AECP_MATRIX_REGION_HEIGHT_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_rep, tvb,
               AECP_MATRIX_REP_OFFSET, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_direction, tvb,
               AECP_MATRIX_DIRECTION_OFFSET, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_value_count, tvb,
               AECP_MATRIX_VALUE_COUNT_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_item_offset, tvb,
               AECP_MATRIX_ITEM_OFFSET_OFFSET, 3, ENC_BIG_ENDIAN);

         if (mess_type == AECP_AEM_RESPONSE_MESSAGE) {
            proto_tree_add_item(aecp_tree, hf_aecp_matrix_affected_item_count, tvb,
                  AECP_MATRIX_AFFECTED_ITEM_COUNT_OFFSET, 4, ENC_BIG_ENDIAN);
         }
         break;
      case AECP_COMMAND_GET_MATRIX:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_column, tvb,
               AECP_MATRIX_COLUMN_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_row, tvb,
               AECP_MATRIX_ROW_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_region_width, tvb,
               AECP_MATRIX_REGION_WIDTH_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_region_height, tvb,
               AECP_MATRIX_REGION_HEIGHT_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_direction, tvb,
               AECP_MATRIX_DIRECTION_OFFSET, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_value_count, tvb,
               AECP_MATRIX_VALUE_COUNT_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_matrix_item_offset, tvb,
               AECP_MATRIX_ITEM_OFFSET_OFFSET, 2, ENC_BIG_ENDIAN);
         /* values */
         break;
      case AECP_COMMAND_START_STREAMING:
      case AECP_COMMAND_STOP_STREAMING:
      case AECP_COMMAND_REBOOT:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_STREAM_INFO:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);

         /* set up the flags subtree */
         flags_ti = proto_tree_add_item(aecp_tree, hf_aecp_flags_32, tvb,
               AECP_FLAGS_32_OFFSET, 4, ENC_BIG_ENDIAN);
         flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);
         proto_tree_add_item(flags_tree, hf_acmp_flags_class_b, tvb,
               AECP_FLAGS_32_OFFSET, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_acmp_flags_fast_connect, tvb,
               AECP_FLAGS_32_OFFSET, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_acmp_flags_saved_state, tvb,
               AECP_FLAGS_32_OFFSET, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_acmp_flags_streaming_wait, tvb,
               AECP_FLAGS_32_OFFSET, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_msrp_acc_lat_valid_flag, tvb,
               AECP_FLAGS_32_OFFSET, 4, ENC_BIG_ENDIAN);
         /* end flags subtree */
         proto_tree_add_item(aecp_tree, hf_aecp_msrp_accumulated_latency, tvb,
               AECP_SET_MSRP_ACC_LAT_OFFSET, 4, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_GET_STREAM_INFO:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         if (mess_type == AECP_AEM_RESPONSE_MESSAGE) { /* if response */
            proto_tree_add_item(aecp_tree, hf_acmp_flags_class_b, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_acmp_flags_fast_connect, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_acmp_flags_saved_state, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_acmp_flags_streaming_wait, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_aecp_connected_flag, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_aecp_stream_id_valid_flag, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_aecp_msrp_acc_lat_valid_flag, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_aecp_dest_mac_valid_flag, tvb,
                  AECP_FLAGS28_OFFSET, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(aecp_tree, hf_aecp_stream_format, tvb,
                  AECP_OFFSET_GET_STREAM_INFO_STREAM_FORMAT, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_acmp_stream_id, tvb,
                  AECP_OFFSET_GET_STREAM_INFO_STREAM_ID, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(aecp_tree, hf_aecp_msrp_accumulated_latency, tvb,
                  AECP_MSRP_ACC_LAT_OFFSET, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(aecp_tree, hf_acmp_stream_dest_mac, tvb,
                  AECP_DEST_MAC_OFFSET, 6, ENC_NA);
            proto_tree_add_item(aecp_tree, hf_aem_clock_source_id, tvb,
                  AECP_STREAM_CLOCK_SOURCE_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         }
         break;
      case AECP_COMMAND_SET_NAME:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_name_index, tvb,
               AECP_NAME_INDEX_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_name, tvb,
               AECP_NAME_OFFSET, 64, ENC_ASCII|ENC_NA);
         break;
      case AECP_COMMAND_GET_NAME:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_name_index, tvb,
               AECP_NAME_INDEX_OFFSET, 2, ENC_BIG_ENDIAN);
         if (mess_type == AECP_AEM_RESPONSE_MESSAGE) {
            proto_tree_add_item(aecp_tree, hf_aecp_name, tvb,
                  AECP_NAME_OFFSET, 64, ENC_ASCII|ENC_NA);
         }
         break;
      case AECP_COMMAND_SET_ASSOCIATION_ID:
      case AECP_COMMAND_GET_ASSOCIATION_ID:
         proto_tree_add_item(aecp_tree, hf_aecp_association_id, tvb,
               AECP_ASSOCIATION_ID_OFFSET, 8, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_AUTH_ADD_KEY:
      case AECP_COMMAND_AUTH_GET_KEY:
      case AECP_COMMAND_AUTH_GET_KEY_COUNT:
      case AECP_COMMAND_AUTH_REVOKE_KEY:
         proto_tree_add_item(aecp_tree, hf_aecp_keychain_id, tvb,
               AECP_KEYCHAIN_ID_OFFSET, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_keytype, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEYTYPE, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_key_number, tvb,
               AECP_KEY_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_continued_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_CONTINUED, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_key_part, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PART, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_key_length, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_LENGTH, 2, ENC_BIG_ENDIAN);

         /* set up key permissions flag subtree */
         flags_ti = proto_tree_add_item(aecp_tree, hf_aecp_flags_32, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);

         proto_tree_add_item(flags_tree, hf_aecp_private_key_read_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_private_key_write_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_public_key_write_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_connection_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_admin_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_mem_obj_admin_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_mem_obj_settings_flag, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l4, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l3, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l2, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l1, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         /* end key permissions flag subtree */

         proto_tree_add_item(aecp_tree, hf_aecp_key_guid, tvb,
               AECP_OFFSET_AUTH_ADD_KEY_KEY_GUID, 8, ENC_BIG_ENDIAN);

         mr_counter = tvb_get_ntohs(tvb, AECP_OFFSET_AUTH_ADD_KEY_LENGTH) & AECP_KEY_LENGTH_MASK;
         mr_offset = AECP_OFFSET_AUTH_ADD_KEY_KEY;
         proto_tree_add_item(aecp_tree, hf_aecp_key, tvb,
               mr_offset, mr_counter, ENC_NA);
         break;
      case AECP_COMMAND_AUTHENTICATE:
      case AECP_COMMAND_DEAUTHENTICATE:
         proto_tree_add_item(aecp_tree, hf_aecp_token_length, tvb,
               AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH, 2, ENC_BIG_ENDIAN);
         /* set up key permissions flag subtree */
         flags_ti = proto_tree_add_item(aecp_tree, hf_aecp_flags_32, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);

         proto_tree_add_item(flags_tree, hf_aecp_private_key_read_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_private_key_write_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_public_key_write_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_connection_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_admin_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_mem_obj_admin_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_mem_obj_settings_flag, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l4, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l3, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l2, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_control_user_l1, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_PERMISSIONS, 4, ENC_BIG_ENDIAN);
         /* end key permissions flag subtree */
         proto_tree_add_item(aecp_tree, hf_aecp_key_guid, tvb,
               AECP_OFFSET_AUTHENTICATE_KEY_GUID, 8, ENC_BIG_ENDIAN);

         mr_counter = tvb_get_ntohs(tvb, AECP_OFFSET_AUTHENTICATE_TOKEN_LENGTH)
            & AECP_TOKEN_LENGTH_MASK;
         mr_offset = AECP_OFFSET_AUTHENTICATE_AUTH_TOKEN;
         proto_tree_add_item(aecp_tree, hf_aecp_auth_token, tvb,
               mr_offset, mr_counter, ENC_NA);
         break;
      case AECP_COMMAND_GET_COUNTERS:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         /* begin counters_valid flags field */
         flags_ti = proto_tree_add_item(aecp_tree, hf_aecp_flags_32, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);

         proto_tree_add_item(flags_tree, hf_aecp_gptp_unlocked_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_gtpt_locked_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_media_unlocked_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_media_locked_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_stream_reset_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_srp_refused_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_backup_stream_switch_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_missed_avdecc_response_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_refused_avdecc_command_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_seq_num_mismatch_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_media_clock_toggles_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_timestamp_uncertains_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_timestamp_valids_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_unsupported_formats_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_bad_presentation_times_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_srp_latency_violations_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_packets_tx_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_packets_rx_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_packets_interest_rx_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_talker_bw_reserved_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_reserved1_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_reserved2_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific1_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific2_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific3_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific4_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific5_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific6_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific7_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_aecp_entity_specific8_valid, tvb,
               AECP_OFFSET_GET_COUNTERS_VALID, 4, ENC_BIG_ENDIAN);
         /* end counters_valid flags field */

         proto_tree_add_item(aecp_tree, hf_aecp_gptp_gm_changed, tvb,
               AECP_OFFSET_COUNTERS_VALID_GPTP_GM_CHANGED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_gptp_unlocked, tvb,
               AECP_OFFSET_COUNTERS_VALID_GPTP_UNLOCKED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_gptp_locked, tvb,
               AECP_OFFSET_COUNTERS_VALID_GPTP_LOCKED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_media_unlocked, tvb,
               AECP_OFFSET_COUNTERS_VALID_MEDIA_UNLOCKED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_media_locked, tvb,
               AECP_OFFSET_COUNTERS_VALID_MEDIA_LOCKED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_media_seq_error, tvb,
               AECP_OFFSET_COUNTERS_VALID_MEDIA_SEQ_ERROR, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_stream_reset, tvb,
               AECP_OFFSET_COUNTERS_VALID_STREAM_RESET, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_srp_refused, tvb,
               AECP_OFFSET_COUNTERS_VALID_SRP_REFUSED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_backup_stream_switch, tvb,
               AECP_OFFSET_COUNTERS_VALID_BACKUP_STREAM_SWITCH, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_missed_avdecc_response, tvb,
               AECP_OFFSET_COUNTERS_VALID_MISSED_AVDECC_RESPONSE, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_refused_avdecc_command, tvb,
               AECP_OFFSET_COUNTERS_VALID_REFUSED_AVDECC_COMMAND, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_seq_num_mismatch, tvb,
               AECP_OFFSET_COUNTERS_VALID_SEQ_NUM_MISMATCH, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_media_clock_toggles, tvb,
               AECP_OFFSET_COUNTERS_VALID_MEDIA_CLOCK_TOGGLES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_timestamp_uncertains, tvb,
               AECP_OFFSET_COUNTERS_VALID_TIMESTAMP_UNCERTAINS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_timestamp_valids, tvb,
               AECP_OFFSET_COUNTERS_VALID_TIMESTAMP_VALIDS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_unsupported_formats, tvb,
               AECP_OFFSET_COUNTERS_VALID_UNSUPPORTED_FORMATS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_bad_presentation_times, tvb,
               AECP_OFFSET_COUNTERS_VALID_BAD_PRESENTATION_TIMES, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_srp_latency_violations, tvb,
               AECP_OFFSET_COUNTERS_VALID_SRP_LATENCY_VIOLATIONS, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_packets_tx, tvb,
               AECP_OFFSET_COUNTERS_VALID_PACKETS_TX, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_packets_rx, tvb,
               AECP_OFFSET_COUNTERS_VALID_PACKETS_RX, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_packets_interest_rx, tvb,
               AECP_OFFSET_COUNTERS_VALID_PACKETS_OF_INTEREST_RX, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_talker_bw_reserved, tvb,
               AECP_OFFSET_COUNTERS_VALID_TALKER_BW_RESERVED, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_reserved_counter, tvb,
               AECP_OFFSET_COUNTERS_VALID_RESERVED1, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_reserved_counter, tvb,
               AECP_OFFSET_COUNTERS_VALID_RESERVED2, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific1, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_1, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific2, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_2, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific3, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_3, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific4, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_4, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific5, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_5, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific6, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_6, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific7, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_7, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_entity_specific8, tvb,
               AECP_OFFSET_COUNTERS_VALID_ENTITY_SPECIFIC_8, 4, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_SET_MEDIA_FORMAT:
      case AECP_COMMAND_GET_MEDIA_FORMAT:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_media_format, tvb,
               AECP_MEDIA_FORMAT_OFFSET, 16, ENC_NA);
         next_tvb = tvb_new_subset(tvb, AECP_OFFSET_SETMF_MEDIA_FMT, 16, 16);
         dissect_17221_media_format(next_tvb, aecp_tree);
         break;
      case AECP_COMMAND_REGISTER_STATE_NOTIFICATION:
         if (mess_type == AECP_AEM_RESPONSE_MESSAGE) {
            proto_tree_add_item(aecp_tree, hf_aecp_address_type, tvb,
                  AECP_ADDRESS_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
            addr_type = tvb_get_ntohs(tvb, AECP_ADDRESS_TYPE_OFFSET);
            if (addr_type == AECP_ADDRESS_MAC) {
               proto_tree_add_item(aecp_tree, hf_aecp_mac_address, tvb,
                     AECP_ADDRESS_OFFSET, 6, ENC_NA);
            } else if (addr_type == AECP_ADDRESS_IPV4) {
               proto_tree_add_item(aecp_tree, hf_aecp_ipv4_address, tvb,
                     AECP_ADDRESS_OFFSET, 4, ENC_BIG_ENDIAN);
            } else if (addr_type == AECP_ADDRESS_IPV6) {
               proto_tree_add_item(aecp_tree, hf_aecp_ipv6_address, tvb,
                     AECP_ADDRESS_OFFSET, 8, ENC_NA);
            }
         }
         break;
      case AECP_COMMAND_REGISTER_QUERY_NOTIFICATION:
         proto_tree_add_item(aecp_tree, hf_aecp_query_period, tvb,
               AECP_QUERY_PERIOD_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_query_limit, tvb,
               AECP_QUERY_LIMIT_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_query_type, tvb,
               AECP_QUERY_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_query_id, tvb,
               AECP_QUERY_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_QUERY_DESC_T_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_QUERY_DESC_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         /* TODO - add query specific fields */
         break;
      case AECP_COMMAND_DEREGISTER_QUERY_NOTIFICATION:
         proto_tree_add_item(aecp_tree, hf_aecp_query_id, tvb,
               AECP_DEREG_QUERY_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_IDENTIFY_NOTIFICATION:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_STATE_CHANGE_NOTIFICATION:
         proto_tree_add_item(aecp_tree, hf_aecp_count, tvb,
               AECP_COUNT_OFFSET, 2, ENC_BIG_ENDIAN);

         mr_counter = tvb_get_ntohs(tvb, AECP_COUNT_OFFSET);
         mr_offset = AECP_DESCRIPTORS_OFFSET_DQN;
         mr_item = proto_tree_add_item(aecp_tree, hf_aecp_descriptors, tvb,
               mr_offset, mr_counter * 4, ENC_NA);
         mr_subtree = proto_item_add_subtree(mr_item, ett_aecp_descriptors);

         for(i = 0; i < mr_counter; ++i) {
            proto_tree_add_item(mr_subtree, hf_aecp_descriptor_type, tvb,
                  mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
            proto_tree_add_item(mr_subtree, hf_aecp_descriptor_id, tvb,
                  mr_offset, 2, ENC_BIG_ENDIAN);
            mr_offset += 2;
         }
         break;
      case AECP_COMMAND_INCREMENT_CONTROL_VALUE:
      case AECP_COMMAND_DECREMENT_CONTROL_VALUE:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         if (mess_type == AECP_AEM_COMMAND_MESSAGE) {
            proto_tree_add_item(aecp_tree, hf_aecp_values_count, tvb,
                  AECP_VALUES_COUNT_OFFSET, 2, ENC_BIG_ENDIAN);
            mr_counter = tvb_get_ntohs(tvb, AECP_VALUES_COUNT_OFFSET);
            proto_tree_add_item(aecp_tree, hf_aecp_values, tvb,
                  AECP_VALUES_OFFSET, mr_counter, ENC_NA);
         }
         break;
      case AECP_COMMAND_START_OPERATION:
      case AECP_COMMAND_ABORT_OPERATION:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_operation_id, tvb,
               AECP_OPERATION_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_operation_type, tvb,
               AECP_OPERATION_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         /* TODO - add values support when operation types are defined */
         break;
      case AECP_COMMAND_OPERATION_STATUS:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_operation_id, tvb,
               AECP_OPERATION_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_percent_complete, tvb,
               AECP_PERCENT_COMPLETE_OFFSET, 2, ENC_BIG_ENDIAN);
         break;
      case AECP_COMMAND_GET_AS_PATH:
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_type, tvb,
               AECP_DESCRIPTOR_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);
         proto_tree_add_item(aecp_tree, hf_aecp_descriptor_id, tvb,
               AECP_DESCRIPTOR_ID_OFFSET, 2, ENC_BIG_ENDIAN);
         if (mess_type == AECP_AEM_RESPONSE_MESSAGE) {
            /* TODO - how big is path sequence? */
         }
         break;

         /* * * * AEM COMMON FORMAT PACKETS * * * */
      case AECP_COMMAND_CONTROLLER_AVAILABLE:
      case AECP_COMMAND_DEREGISTER_STATE_NOTIFICATION:
         break;
      default:
         /* the command type is not one of the valid spec values */
         break;
   }
}

static void
dissect_17221_adp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *adp_tree)
{
   proto_item *ent_cap_ti;
   proto_item *talk_cap_ti;
   proto_item *list_cap_ti;
   proto_item *cont_cap_ti;
   proto_item *aud_format_ti;
   proto_item *samp_rates_ti;
   proto_item *chan_format_ti;

   proto_tree *ent_cap_flags_tree;
   proto_tree *talk_cap_flags_tree;
   proto_tree *list_cap_flags_tree;
   proto_tree *cont_cap_flags_tree;
   proto_tree *aud_format_tree;
   proto_tree *samp_rates_tree;
   proto_tree *chan_format_tree;


   proto_tree_add_item(adp_tree, hf_adp_message_type, tvb, ADP_VERSION_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_valid_time, tvb, ADP_VALID_TIME_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_cd_length, tvb, ADP_CD_LENGTH_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_entity_guid, tvb, ADP_ENTITY_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_vendor_id, tvb, ADP_VENDOR_ID_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_model_id, tvb, ADP_MODEL_ID_OFFSET, 4, ENC_BIG_ENDIAN);

   /* Subtree for entity_capabilities field */
   ent_cap_ti = proto_tree_add_item(adp_tree, hf_adp_entity_cap, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   ent_cap_flags_tree = proto_item_add_subtree(ent_cap_ti, ett_adp_ent_cap);

   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_avdecc_ip, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_zero_conf, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_gateway_entity, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_avdecc_control, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_legacy_avc, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_assoc_id_support, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(ent_cap_flags_tree,
         hf_adp_entity_cap_assoc_id_valid, tvb, ADP_ENTITY_CAP_OFFSET, 4, ENC_BIG_ENDIAN);

   proto_tree_add_item(adp_tree, hf_adp_talker_stream_srcs, tvb, ADP_TALKER_STREAM_SRCS_OFFSET, 2, ENC_BIG_ENDIAN);

   talk_cap_ti = proto_tree_add_item(adp_tree, hf_adp_talker_cap, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   talk_cap_flags_tree = proto_item_add_subtree(talk_cap_ti, ett_adp_talk_cap);

   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_implement, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_other_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_control_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_media_clk_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_smpte_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_midi_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_audio_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(talk_cap_flags_tree,
         hf_adp_talk_cap_video_src, tvb, ADP_TALKER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);

   proto_tree_add_item(adp_tree, hf_adp_listener_stream_sinks,
         tvb, ADP_LISTENER_STREAM_SINKS_OFFSET, 2, ENC_BIG_ENDIAN);

   list_cap_ti = proto_tree_add_item(adp_tree, hf_adp_listener_cap, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   list_cap_flags_tree = proto_item_add_subtree(list_cap_ti, ett_adp_list_cap);

   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_implement, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_other_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_control_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_media_clk_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_smpte_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_midi_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_audio_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(list_cap_flags_tree,
         hf_adp_list_cap_video_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, ENC_BIG_ENDIAN);

   cont_cap_ti = proto_tree_add_item(adp_tree, hf_adp_controller_cap, tvb, ADP_CONTROLLER_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   cont_cap_flags_tree = proto_item_add_subtree(cont_cap_ti, ett_adp_cont_cap);

   proto_tree_add_item(cont_cap_flags_tree,
         hf_adp_cont_cap_implement, tvb, ADP_CONTROLLER_CAP_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(cont_cap_flags_tree,
         hf_adp_cont_cap_layer3_proxy, tvb, ADP_CONTROLLER_CAP_OFFSET, 4, ENC_BIG_ENDIAN);

   proto_tree_add_item(adp_tree, hf_adp_avail_index, tvb, ADP_AVAIL_INDEX_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_as_gm_id, tvb, ADP_AS_GM_ID_OFFSET, 8, ENC_BIG_ENDIAN);

   aud_format_ti = proto_tree_add_item(adp_tree, hf_adp_def_aud_format, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 4, ENC_BIG_ENDIAN);
   aud_format_tree = proto_item_add_subtree(aud_format_ti, ett_adp_aud_format);

   samp_rates_ti = proto_tree_add_item(aud_format_tree,
         hf_adp_def_aud_sample_rates, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);
   samp_rates_tree = proto_item_add_subtree(samp_rates_ti, ett_adp_samp_rates);

   proto_tree_add_item(samp_rates_tree,
         hf_adp_samp_rate_44k1, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(samp_rates_tree,
         hf_adp_samp_rate_48k, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(samp_rates_tree,
         hf_adp_samp_rate_88k2, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(samp_rates_tree,
         hf_adp_samp_rate_96k, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(samp_rates_tree,
         hf_adp_samp_rate_176k4, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(samp_rates_tree,
         hf_adp_samp_rate_192k, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, ENC_BIG_ENDIAN);

   proto_tree_add_item(aud_format_tree,
         hf_adp_def_aud_max_chan, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(aud_format_tree,
         hf_adp_def_aud_saf_flag, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(aud_format_tree,
         hf_adp_def_aud_float_flag, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);

   chan_format_ti = proto_tree_add_item(aud_format_tree,
         hf_adp_def_aud_chan_formats, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   chan_format_tree = proto_item_add_subtree(chan_format_ti, ett_adp_chan_format);

   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_mono, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_2ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_3ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_4ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_5ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_6ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_7ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_8ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_10ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_12ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_14ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_16ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_18ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_20ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_22ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(chan_format_tree,
         hf_adp_chan_format_24ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, ENC_BIG_ENDIAN);

   proto_tree_add_item(adp_tree, hf_adp_def_vid_format, tvb, ADP_DEF_VIDEO_FORMAT_OFFSET, 4, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_assoc_id, tvb, ADP_ASSOC_ID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(adp_tree, hf_adp_entity_type, tvb, ADP_ENTITY_TYPE_OFFSET, 4, ENC_BIG_ENDIAN);
}

static void
dissect_17221_acmp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *acmp_tree)
{
   proto_item *flags_ti;
   proto_tree *flags_tree;

   proto_tree_add_item(acmp_tree, hf_acmp_message_type, tvb, ACMP_VERSION_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_status_field, tvb, ACMP_STATUS_FIELD_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_cd_length, tvb, ACMP_CD_LENGTH_OFFSET, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_stream_id, tvb, ACMP_STREAM_ID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_controller_guid, tvb, ACMP_CONTROLLER_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_talker_guid, tvb, ACMP_TALKER_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_listener_guid, tvb, ACMP_LISTENER_GUID_OFFSET, 8, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_talker_unique_id, tvb, ACMP_TALKER_UNIQUE_ID_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_listener_unique_id, tvb, ACMP_LISTENER_UNIQUE_ID_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_stream_dest_mac, tvb, ACMP_DEST_MAC_OFFSET, 6, ENC_NA);
   proto_tree_add_item(acmp_tree, hf_acmp_connection_count, tvb, ACMP_CONNECTION_COUNT_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(acmp_tree, hf_acmp_sequence_id, tvb, ACMP_SEQUENCE_ID_OFFSET, 2, ENC_BIG_ENDIAN);

   flags_ti = proto_tree_add_item(acmp_tree, hf_acmp_flags, tvb, ACMP_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);
   flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);

   proto_tree_add_item(flags_tree, hf_acmp_flags_class_b, tvb, ACMP_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(flags_tree, hf_acmp_flags_fast_connect, tvb, ACMP_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(flags_tree, hf_acmp_flags_saved_state, tvb, ACMP_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(flags_tree, hf_acmp_flags_streaming_wait, tvb, ACMP_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

   proto_tree_add_item(acmp_tree, hf_acmp_default_format, tvb, ACMP_DEFAULT_FORMAT_OFFSET, 4, ENC_BIG_ENDIAN);
}

static void
dissect_17221(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   guint8 subtype = 0;
   proto_item *ieee17221_item;
   proto_tree *ieee17221_tree;
   subtype = tvb_get_guint8(tvb, 0);
   subtype &= 0x7F;

   /* fprintf(stderr, "subtype: %d\n", subtype); */

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE1722-1");

   ieee17221_item = proto_tree_add_item(tree, proto_17221, tvb, 0, -1, ENC_NA);
   ieee17221_tree = proto_item_add_subtree(ieee17221_item, ett_17221);

   switch (subtype)
   {
      case 0x7A:
         {
            col_set_str(pinfo->cinfo, COL_INFO, "AVDECC Discovery Protocol");
            if (tree)
               dissect_17221_adp(tvb, pinfo, ieee17221_tree);
            break;
         }
      case 0x7B:
         {
            col_set_str(pinfo->cinfo, COL_INFO, "AVDECC Enumeration and Control Protocol");
            if (tree)
               dissect_17221_aecp(tvb, pinfo, ieee17221_tree);
            break;
         }
      case 0x7C:
         {
            col_set_str(pinfo->cinfo, COL_INFO, "AVDECC Connection Management Protocol");
            if (tree)
               dissect_17221_acmp(tvb, pinfo, ieee17221_tree);
            break;
         }
      default:
         {
            /* Shouldn't get here */
            col_set_str(pinfo->cinfo, COL_INFO, "1722.1 Unknown");
            return;
         }
   }

}

/* Register the protocol with Wireshark */
void
proto_register_17221(void)
{
   static hf_register_info hf[] = {
      { &hf_adp_message_type,
         { "Message Type", "ieee17221.message_type",
            FT_UINT8, BASE_DEC, VALS(adp_message_type_vals), ADP_MSG_TYPE_MASK, NULL, HFILL }
      },
      { &hf_adp_valid_time,
         { "Valid Time", "ieee17221.valid_time",
            FT_UINT8, BASE_DEC, NULL, ADP_VALID_TIME_MASK, NULL, HFILL }
      },
      { &hf_adp_cd_length,
         { "Control Data Length", "ieee17221.control_data_length",
            FT_UINT16, BASE_DEC, NULL, ADP_CD_LENGTH_MASK, NULL, HFILL }
      },
      { &hf_adp_entity_guid,
         { "Entity GUID", "ieee17221.entity_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_vendor_id,
         { "Vendor ID", "ieee17221.vendor_id",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_model_id,
         { "Model ID", "ieee17221.model_id",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_entity_cap,
         { "Entity Capabilities", "ieee17221.entity_capabilities",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* Entity Capability Flags Begin */
      { &hf_adp_entity_cap_avdecc_ip,
         { "AVDECC_IP", "ieee17221.entity_capabilities.avdecc_ip",
            FT_BOOLEAN, 32, NULL, ADP_AVDECC_IP_BITMASK, NULL, HFILL }
      },
      { &hf_adp_entity_cap_zero_conf,
         { "ZERO_CONF", "ieee17221.entity_capabilities.zero_conf",
            FT_BOOLEAN, 32, NULL, ADP_ZERO_CONF_BITMASK, NULL, HFILL }
      },
      { &hf_adp_entity_cap_gateway_entity,
         { "GATEWAY_ENTITY", "ieee17221.entity_capabilities.gateway_entity",
            FT_BOOLEAN, 32, NULL, ADP_GATEWAY_ENTITY_BITMASK, NULL, HFILL }
      },
      { &hf_adp_entity_cap_avdecc_control,
         { "AVDECC_CONTROL", "ieee17221.entity_capabilities.avdecc_control",
            FT_BOOLEAN, 32, NULL, ADP_AVDECC_CONTROL_BITMASK, NULL, HFILL }
      },
      { &hf_adp_entity_cap_legacy_avc,
         { "LEGACY_AVC", "ieee17221.entity_capabilities.legacy_avc",
            FT_BOOLEAN, 32, NULL, ADP_LEGACY_AVC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_entity_cap_assoc_id_support,
         { "ASSOCIATION_ID_SUPPORTED", "ieee17221.entity_capabilities.association_id_supported",
            FT_BOOLEAN, 32, NULL, ADP_ASSOC_ID_SUPPORT_BITMASK, NULL, HFILL }
      },
      { &hf_adp_entity_cap_assoc_id_valid,
         { "ASSOCIATION_ID_VALID", "ieee17221.entity_capabilities.association_id_valid",
            FT_BOOLEAN, 32, NULL, ADP_ASSOC_ID_VALID_BITMASK, NULL, HFILL }
      },
      /* Entity Capability Flags End */
      { &hf_adp_talker_stream_srcs,
         { "Talker Stream Sources", "ieee17221.talker_stream_sources",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_talker_cap,
         { "Talker Capabilities", "ieee17221.talker_capabilities",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* Talker Capability Flags Begin */
      { &hf_adp_talk_cap_implement,
         { "IMPLEMENTED", "ieee17221.talker_capabilities.implemented",
            FT_BOOLEAN, 16, NULL, ADP_TALK_IMPLEMENTED_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_other_src,
         { "OTHER_SOURCE", "ieee17221.talker_capabilities.other_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_OTHER_SRC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_control_src,
         { "CONTROL_SOURCE", "ieee17221.talker_capabilities.control_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_CONTROL_SRC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_media_clk_src,
         { "MEDIA_CLOCK_SOURCE", "ieee17221.talker_capabilities.media_clock_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_MEDIA_CLK_SRC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_smpte_src,
         { "SMPTE_SOURCE", "ieee17221.talker_capabilities.smpte_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_SMPTE_SRC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_midi_src,
         { "MIDI_SOURCE", "ieee17221.talker_capabilities.midi_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_MIDI_SRC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_audio_src,
         { "AUDIO_SOURCE", "ieee17221.talker_capabilities.audio_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_AUDIO_SRC_BITMASK, NULL, HFILL }
      },
      { &hf_adp_talk_cap_video_src,
         { "VIDEO_SOURCE", "ieee17221.talker_capabilities.video_source",
            FT_BOOLEAN, 16, NULL, ADP_TALK_VIDEO_SRC_BITMASK, NULL, HFILL }
      },
      /* Talker Capability Flags End */
      { &hf_adp_listener_stream_sinks,
         { "Listener Stream Sinks", "ieee17221.listener_stream_sinks",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_listener_cap,
         { "Listener Capabilities", "ieee17221.listener_capabilities",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* Listener Capability Flags Begin */
      { &hf_adp_list_cap_implement,
         { "IMPLEMENTED", "ieee17221.listener_capabilities.implemented",
            FT_BOOLEAN, 16, NULL, ADP_LIST_IMPLEMENTED_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_other_sink,
         { "OTHER_SINK", "ieee17221.listener_capabilities.other_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_OTHER_SINK_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_control_sink,
         { "CONTROL_SINK", "ieee17221.listener_capabilities.control_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_CONTROL_SINK_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_media_clk_sink,
         { "MEDIA_CLOCK_SINK", "ieee17221.listener_capabilities.media_clock_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_MEDIA_CLK_SINK_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_smpte_sink,
         { "SMPTE_SINK", "ieee17221.listener_capabilities.smpte_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_SMPTE_SINK_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_midi_sink,
         { "MIDI_SINK", "ieee17221.listener_capabilities.midi_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_MIDI_SINK_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_audio_sink,
         { "AUDIO_SINK", "ieee17221.listener_capabilities.audio_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_AUDIO_SINK_BITMASK, NULL, HFILL }
      },
      { &hf_adp_list_cap_video_sink,
         { "VIDEO_SINK", "ieee17221.listener_capabilities.video_source",
            FT_BOOLEAN, 16, NULL, ADP_LIST_VIDEO_SINK_BITMASK, NULL, HFILL }
      },
      /* Listener Capability Flags End */
      { &hf_adp_controller_cap,
         { "Controller Capabilities", "ieee17221.controller_capabilities",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* Controller Capability Flags Begin */
      { &hf_adp_cont_cap_implement,
         { "IMPLEMENTED", "ieee17221.controller_capabilities.implemented",
            FT_BOOLEAN, 16, NULL, ADP_CONT_IMPLEMENTED_BITMASK, NULL, HFILL }
      },
      { &hf_adp_cont_cap_layer3_proxy,
         { "LAYER3_PROXY", "ieee17221.controller_capabilities.layer3_proxy",
            FT_BOOLEAN, 16, NULL, ADP_CONT_LAYER3_PROXY_BITMASK, NULL, HFILL }
      },
      /* Controller Capability Flags End */
      { &hf_adp_avail_index,
         { "Available Index", "ieee17221.available_index",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_as_gm_id,
         { "AS Grandmaster ID", "ieee17221.as_grandmaster_id",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_def_aud_format,
         { "Default Audio Format", "ieee17221.default_audio_format",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* Default Audio Formats Fields Begin */
      { &hf_adp_def_aud_sample_rates,
         { "Sample Rates", "ieee17221.default_audio_format.sample_rates",
            FT_UINT8, BASE_HEX, NULL, ADP_DEF_AUDIO_SAMPLE_RATES_MASK, NULL, HFILL }
      },
      /* Sample rates Begin */
      { &hf_adp_samp_rate_44k1,
         { "44.1kHz", "ieee17221.default_audio_format.sample_rates.44k1",
            FT_BOOLEAN, 8, NULL, ADP_SAMP_RATE_44K1_BITMASK, NULL, HFILL }
      },
      { &hf_adp_samp_rate_48k,
         { "48kHz", "ieee17221.default_audio_format.sample_rates.48k",
            FT_BOOLEAN, 8, NULL, ADP_SAMP_RATE_48K_BITMASK, NULL, HFILL }
      },
      { &hf_adp_samp_rate_88k2,
         { "88.2kHz", "ieee17221.default_audio_format.sample_rates.88k2",
            FT_BOOLEAN, 8, NULL, ADP_SAMP_RATE_88K2_BITMASK, NULL, HFILL }
      },
      { &hf_adp_samp_rate_96k,
         { "96kHz", "ieee17221.default_audio_format.sample_rates.96k",
            FT_BOOLEAN, 8, NULL, ADP_SAMP_RATE_96K_BITMASK, NULL, HFILL }
      },
      { &hf_adp_samp_rate_176k4,
         { "176.4kHz", "ieee17221.default_audio_format.sample_rates.176k4",
            FT_BOOLEAN, 8, NULL, ADP_SAMP_RATE_176K4_BITMASK, NULL, HFILL }
      },
      { &hf_adp_samp_rate_192k,
         { "192kHz", "ieee17221.default_audio_format.sample_rates.192k",
            FT_BOOLEAN, 8, NULL, ADP_SAMP_RATE_192K_BITMASK, NULL, HFILL }
      },
      /* Sample rates End */
      { &hf_adp_def_aud_max_chan,
         { "Max Channels", "ieee17221.default_audio_format.max_channels",
            FT_UINT16, BASE_DEC, NULL, ADP_DEF_AUDIO_MAX_CHANS_MASK, NULL, HFILL }
      },
      { &hf_adp_def_aud_saf_flag,
         { "saf", "ieee17221.default_audio_format.saf",
            FT_BOOLEAN, 16, NULL, ADP_DEF_AUDIO_SAF_MASK, NULL, HFILL }
      },
      { &hf_adp_def_aud_float_flag,
         { "float", "ieee17221.default_audio_format.float",
            FT_BOOLEAN, 16, NULL, ADP_DEF_AUDIO_FLOAT_MASK, NULL, HFILL }
      },
      { &hf_adp_def_aud_chan_formats,
         { "Channel Formats", "ieee17221.default_audio_format.channel_formats",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* Channel Formats Fields Start */
      { &hf_adp_chan_format_mono,
         { "MONO", "ieee17221.default_audio_format.channel_formats.mono",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_MONO, NULL, HFILL }
      },
      { &hf_adp_chan_format_2ch,
         { "2_CH", "ieee17221.default_audio_format.channel_formats.2_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_2CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_3ch,
         { "3_CH", "ieee17221.default_audio_format.channel_formats.3_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_3CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_4ch,
         { "4_CH", "ieee17221.default_audio_format.channel_formats.4_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_4CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_5ch,
         { "5_CH", "ieee17221.default_audio_format.channel_formats.5_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_5CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_6ch,
         { "6_CH", "ieee17221.default_audio_format.channel_formats.6_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_6CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_7ch,
         { "7_CH", "ieee17221.default_audio_format.channel_formats.7_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_7CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_8ch,
         { "8_CH", "ieee17221.default_audio_format.channel_formats.8_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_8CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_10ch,
         { "10_CH", "ieee17221.default_audio_format.channel_formats.10_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_10CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_12ch,
         { "12_CH", "ieee17221.default_audio_format.channel_formats.12_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_12CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_14ch,
         { "14_CH", "ieee17221.default_audio_format.channel_formats.14_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_14CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_16ch,
         { "16_CH", "ieee17221.default_audio_format.channel_formats.16_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_16CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_18ch,
         { "18_CH", "ieee17221.default_audio_format.channel_formats.18_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_18CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_20ch,
         { "20_CH", "ieee17221.default_audio_format.channel_formats.20_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_20CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_22ch,
         { "22_CH", "ieee17221.default_audio_format.channel_formats.22_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_22CH, NULL, HFILL }
      },
      { &hf_adp_chan_format_24ch,
         { "24_CH", "ieee17221.default_audio_format.channel_formats.24_ch",
            FT_BOOLEAN, 16, NULL, ADP_CHAN_FORMAT_24CH, NULL, HFILL }
      },
      /* Channel Formats Fields End */
      /* Default Audio Formats Fields End */
      { &hf_adp_def_vid_format,
         { "Default Video Format", "ieee17221.default_video_format",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_assoc_id,
         { "Assocation ID", "ieee17221.assocation_id",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_adp_entity_type,
         { "Entity Type", "ieee17221.entity_type",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /*******************************************************************/
      { &hf_acmp_message_type,
         { "Message Type", "ieee17221.message_type",
            FT_UINT8, BASE_DEC, VALS(acmp_message_type_vals), ACMP_MSG_TYPE_MASK, NULL, HFILL }
      },
      { &hf_acmp_status_field,
         { "Status Field", "ieee17221.status_field",
            FT_UINT8, BASE_DEC, VALS(acmp_status_field_vals), ACMP_STATUS_FIELD_MASK, NULL, HFILL }
      },
      { &hf_acmp_cd_length,
         { "Control Data Length", "ieee17221.control_data_length",
           FT_UINT16, BASE_DEC, NULL, ACMP_CD_LENGTH_MASK, NULL, HFILL }
      },
      { &hf_acmp_stream_id,
         { "Stream ID", "ieee17221.stream_id",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_controller_guid,
         { "Controller GUID", "ieee17221.controller_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_talker_guid,
         { "Talker GUID", "ieee17221.talker_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_listener_guid,
         { "Listener GUID", "ieee17221.listener_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_talker_unique_id,
         { "Talker Unique ID", "ieee17221.talker_unique_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_listener_unique_id,
         { "Listener Unique ID", "ieee17221.listener_unique_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_stream_dest_mac,
         { "Destination MAC address", "ieee17221.dest_mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_connection_count,
         { "Connection Count", "ieee17221.connection_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_sequence_id,
         { "Sequence ID", "ieee17221.sequence_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_acmp_flags,
         { "Flags", "ieee17221.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* ACMP Flags Begin */
      { &hf_acmp_flags_class_b,
         { "CLASS_B", "ieee17221.flags.class_b",
            FT_BOOLEAN, 8, NULL, ACMP_FLAG_CLASS_B_BITMASK, NULL, HFILL }
      },
      { &hf_acmp_flags_fast_connect,
         { "FAST_CONNECT", "ieee17221.flags.fast_connect",
            FT_BOOLEAN, 8, NULL, ACMP_FLAG_FAST_CONNECT_BITMASK, NULL, HFILL }
      },
      { &hf_acmp_flags_saved_state,
         { "SAVED_STATE", "ieee17221.flags.saved_state",
            FT_BOOLEAN, 8, NULL, ACMP_FLAG_SAVED_STATE_BITMASK, NULL, HFILL }
      },
      { &hf_acmp_flags_streaming_wait,
         { "STREAMING_WAIT", "ieee17221.flags.streaming_wait",
            FT_BOOLEAN, 8, NULL, ACMP_FLAG_STREAMING_WAIT_BITMASK, NULL, HFILL }
      },
      /* ACMP Flags End */
      { &hf_acmp_default_format,
         { "Default Format", "ieee17221.default_format",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /******* AECP ******/
      /* COMMON FIELDS */
      { &hf_aecp_message_type,
         { "Message Type", "ieee17221.message_type",
            FT_UINT8, BASE_DEC, VALS(aecp_message_type_vals), AECP_MSG_TYPE_MASK, NULL, HFILL }
      },
      { &hf_aecp_cd_length,
         { "Control Data Length", "ieee17221.control_data_length",
            FT_UINT16, BASE_DEC, NULL, AECP_CD_LENGTH_MASK, NULL, HFILL }
      },
      { &hf_aecp_target_guid,
         { "Target GUID", "ieee17221.target_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_controller_guid,
         { "Controller GUID", "ieee17221.controller_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_sequence_id,
         { "Sequence ID", "ieee17221.sequence_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_u_flag,
         { "U Flag", "ieee17221.u_flag",
            FT_BOOLEAN, 8, NULL, AECP_U_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_command_type,
         { "Command Type", "ieee17221.command_type",
            FT_UINT16, BASE_HEX, VALS(aecp_command_type_vals), AECP_COMMAND_TYPE_MASK, NULL, HFILL }
      },

      /* SLIGHTLY LESS COMMON FIELDS */
      { &hf_aecp_descriptor_type,
         { "Descriptor Type", "ieee17221.descriptor_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aecp_descriptor_id,
         {"Descriptor ID", "ieee17221._descriptor_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* AECP Commands and Responses 1722.1 Sec 7.4 */
      /* LOCK_ENTITY */
      { &hf_aecp_unlock_flag,
         { "UNLOCK Flag", "ieee17221.flags.unlock",
            FT_BOOLEAN, 8, NULL, AECP_UNLOCK_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_locked_guid,
         { "Locked GUID", "ieee17221.locked_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL}
      },

      /* READ_DESCRIPTOR */
      { &hf_aecp_configuration,
         { "Configuration", "ieee17221._configuration",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* WRITE_DESCRIPTOR */

      /* ACQUIRE_ENTITY */
      { &hf_aecp_persistent_flag,
         { "Peristent Flag", "ieee17221.flags.persistent",
            FT_BOOLEAN, 32, NULL, AECP_PERSISTENT_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_release_flag,
         { "Release Flag", "ieee17221.flags.release",
            FT_BOOLEAN, 32, NULL, AECP_RELEASE_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_owner_guid,
         { "Owner GUID", "ieee17221.owner_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* CONTROLLER_AVAILABLE */

      /* SET_CLOCK_SOURCE / GET_CLOCK_SOURCE */
      { &hf_aecp_clock_source_id,
         { "Clock Source ID", "ieee17221.clock_source_id",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* SET_STREAM_FORMAT */
      { &hf_aecp_stream_format,
         {"Stream Format", "ieee17221.stream_format",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* GET_STREAM_FORMAT */

      /* SET_CONFIGURATION / GET_CONFIGURATION */

      /* SET_CONTROL_VALUE / GET_CONTROL_VALUE */

      /* SET_SIGNAL_SELECTOR / GET_SIGNAL_SELECTOR */
      { &hf_aecp_signal_type,
         {"Signal Type", "ieee17221.signal_type",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_signal_id,
         {"Signal ID", "ieee17221.signal_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* SET_MIXER / GET_MIXER */

      /* SET_MATRIX / GET_MATRIX */
      { &hf_aecp_matrix_column,
         {"Matrix Column", "ieee17221.matrix_column",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_matrix_row,
         {"Matrix Row", "ieee17221.matrix_row",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_matrix_region_width,
         {"Region Width", "ieee17221.matrix_region_width",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_matrix_region_height,
         {"Region Height", "ieee17221.matrix_region_height",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_matrix_rep,
         {"Rep", "ieee17221.matrix_rep",
            FT_BOOLEAN, 8, NULL, AECP_MATRIX_REP_MASK, NULL, HFILL }
      },
      { &hf_aecp_matrix_direction,
         {"Direction", "ieee17221.matrix_direction",
            FT_UINT8, BASE_DEC, VALS(aecp_direction_type_vals), AECP_MATRIX_DIRECTION_MASK, NULL, HFILL }
      },
      { &hf_aecp_matrix_value_count,
         {"Value Count", "ieee17221.matrix_value_count",
            FT_UINT16, BASE_DEC, NULL, AECP_MATRIX_VALUE_COUNT_MASK, NULL, HFILL }
      },
      { &hf_aecp_matrix_item_offset,
         {"Item Offset", "ieee17221.matrix_item_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_matrix_affected_item_count,
         {"Affected Item Count", "ieee17221.matrix_affected_item_count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* START_STREAMING */

      /* STOP_STREAMING */


      /* GET_STREAM_INFO */
      { &hf_aecp_msrp_accumulated_latency,
         {"MSRP Accumulated Latency", "ieee17221.msrp_accumulated_latency",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_connected_flag,
         {"Connected Flag", "ieee17221.flags.connected",
            FT_BOOLEAN, 32, NULL, AECP_CONNECTED_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_stream_id_valid_flag,
         {"Stream ID Valid Flag", "ieee17221.flags.stream_id_valid",
            FT_BOOLEAN, 32, NULL, AECP_STREAM_ID_VALID_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_msrp_acc_lat_valid_flag,
         {"MSRP Accumulated Latency Field Valid Flag", "ieee17221.flags.msrp_acc_lat_valid",
            FT_BOOLEAN, 32, NULL, AECP_MSRP_ACC_LAT_VALID_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_dest_mac_valid_flag,
         {"Dest MAC Valid Flag", "ieee17221.flags.dest_mac_valid",
            FT_BOOLEAN, 32, NULL, AECP_DEST_MAC_VALID_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_default_format_valid_flag,
         {"Default Format Valid Flag", "ieee17221.flags.default_format_valid",
            FT_BOOLEAN, 32, NULL, AECP_DEFAULT_FORMAT_VALID_FLAG_MASK, NULL, HFILL }
      },

      /* SET_NAME / GET_NAME */
      { &hf_aecp_name_index,
         {"Name Index", "ieee17221.name_index",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_name,
         {"Name", "ieee17221.name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* SET_ASSOCIATION_ID / GET_ASSOCIATION_ID */
      { &hf_aecp_association_id,
         {"Association ID", "ieee17221.association_id",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* AUTH_ADD_KEY */
      { &hf_aecp_keychain_id,
         {"Keychain ID", "ieee17221.keychain_id",
            FT_UINT8, BASE_HEX, VALS(aecp_keychain_id_type_vals), AECP_KEYCHAIN_ID_MASK, NULL, HFILL }
      },
      { &hf_aecp_keytype,
         {"Key Type", "ieee17221.keytype",
            FT_UINT8, BASE_HEX, VALS(aecp_keytype_type_vals), AECP_KEYTYPE_MASK, NULL, HFILL }
      },
      { &hf_aecp_key_number,
         {"Key ID", "ieee17221.key_id",
            FT_UINT16, BASE_HEX, NULL, AECP_KEY_NUMBER_MASK, NULL, HFILL }
      },
      { &hf_aecp_continued_flag,
         {"Continued", "ieee17221.continued",
            FT_BOOLEAN, 8, NULL, AECP_CONTINUED_MASK, NULL, HFILL }
      },
      { &hf_aecp_key_part,
         {"Key Part", "ieee17221.key_part",
            FT_UINT8, BASE_DEC, NULL, AECP_KEY_PART_MASK, NULL, HFILL }
      },

      { &hf_aecp_key_length,
         {"Key Length", "ieee17221.key_length",
            FT_UINT16, BASE_DEC, NULL, AECP_KEY_LENGTH_MASK, NULL, HFILL }
      },
      { &hf_aecp_signature_info,
         {"Signature Info", "ieee17221.signature_info",
            FT_UINT8, BASE_HEX, VALS(aecp_keychain_id_type_vals), AECP_SIGNATURE_INFO_MASK, NULL, HFILL }
      },
      { &hf_aecp_signature_id,
         {"Signature ID", "ieee17221.signature_id",
            FT_UINT16, BASE_HEX, NULL, AECP_SIGNATURE_ID_MASK, NULL, HFILL }
      },
      { &hf_aecp_signature_length,
         {"Signature Length", "ieee17221.signature_length",
            FT_UINT16, BASE_DEC, NULL, AECP_SIGNATURE_LENGTH_MASK, NULL, HFILL }
      },
      { &hf_aecp_key_permissions,
         {"Key Permissions", "ieee17221.key_permissions",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_private_key_read_flag,
         {"Private Key Read Flag", "ieee17221.flags.private_key_read",
            FT_BOOLEAN, 32, NULL, AECP_PRIVATE_KEY_READ_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_private_key_write_flag,
         {"Private Key Write Flag", "ieee17221.flags.private_key_write",
            FT_BOOLEAN, 32, NULL, AECP_PRIVATE_KEY_WRITE_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_public_key_write_flag,
         {"Public Key Write Flag", "ieee17221.flags.public_key_write",
            FT_BOOLEAN, 32, NULL, AECP_PUBLIC_KEY_WRITE_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_connection_flag,
         {"Connection Flag", "ieee17221.flags.connection",
            FT_BOOLEAN, 32, NULL, AECP_CONNECTION_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_control_admin_flag,
         {"Control Admin Flag", "ieee17221.flags.control_admin",
            FT_BOOLEAN, 32, NULL, AECP_CONTROL_ADMIN_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_mem_obj_admin_flag,
         {"Memory Object Admin", "ieee17221.mem_obj_admin",
            FT_BOOLEAN, 32, NULL, AECP_MEM_OBJ_ADMIN_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_mem_obj_settings_flag,
         {"Memory Object Settings", "ieee17221.mem_obj_settings",
            FT_BOOLEAN, 32, NULL, AECP_MEM_OBJ_SETTINGS_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_control_user_l1,
         {"Control User L1 flag", "ieee17221.flags.control_user_l1",
            FT_BOOLEAN, 32, NULL, AECP_CONTROL_USER_L1_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_control_user_l2,
         {"Control User L2 flag", "ieee17221.flags.control_user_l2",
            FT_BOOLEAN, 32, NULL, AECP_CONTROL_USER_L2_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_control_user_l3,
         {"Control User L3 flag", "ieee17221.flags.control_user_l3",
            FT_BOOLEAN, 32, NULL, AECP_CONTROL_USER_L3_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aecp_control_user_l4,
         {"Control User L4 flag", "ieee17221.flags.control_user_l4",
            FT_BOOLEAN, 32, NULL, AECP_CONTROL_USER_L4_FLAG_MASK, NULL, HFILL }
      },

      { &hf_aecp_gptp_gm_changed,
         {"GPTP GM Changed", "ieee17221.gtptp_gm_changed",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_gptp_unlocked,
         {"GPTP Unlocked", "ieee17221.gptp_unlocked",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_gptp_locked,
         {"GPTP Locked", "ieee17221.gptp_locked",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_media_unlocked,
         {"Media Unlocked", "ieee17221.media_unlocked",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_media_locked,
         {"Media Locked", "ieee17221.media_locked",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_media_seq_error,
         {"Media Seq Error", "ieee17221.media_seq_error",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_stream_reset,
         {"stream_reset", "ieee17221.stream_reset",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_srp_refused,
         {"SRP Refused", "ieee17221.srp_refused",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_backup_stream_switch,
         {"Backup Stream Switch", "ieee17221.backup_stream_switch",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_missed_avdecc_response,
         {"Missed Avdecc Response", "ieee17221.missed_avdecc_response",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_refused_avdecc_command,
         {"Refused Avdecc Command", "ieee17221.refused_avdecc_command",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_seq_num_mismatch,
         {"Seq Num Mismatch", "ieee17221.seq_num_mismatch",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_media_clock_toggles,
         {"Media Clock Toggles", "ieee17221.media_clock_toggles",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_timestamp_uncertains,
         {"Timestamp Uncertains", "ieee17221.timestamp_uncertains",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_timestamp_valids,
         {"Timestamp Valids", "ieee17221.timestamp_valids",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_unsupported_formats,
         {"Unsupported Formats", "ieee17221.unsupported_formats",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_bad_presentation_times,
         {"Bad Presentation Times", "ieee17221.bad_presentation_times",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_srp_latency_violations,
         {"SRP Latency Violations", "ieee17221.srp_latency_violations",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_packets_tx,
         {"Packets TX", "ieee17221.packets_tx",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_packets_rx,
         {"Packets RX", "ieee17221.packets_rx",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_packets_interest_rx,
         {"Packets of Interest RX", "ieee17221.packets_interest_rx",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_talker_bw_reserved,
         {"Talker BW Reserved", "ieee17221.talker_bw_reserved",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_reserved_counter,
         {"RESERVED", "ieee17221.reserved",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific1,
         {"Entity Specific #1", "ieee17221.entity_specific_1",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific2,
         {"Entity Specific #2", "ieee17221.entity_specific_2",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific3,
         {"Entity Specific #3", "ieee17221.entity_specific_3",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific4,
         {"Entity Specific #4", "ieee17221.entity_specific_4",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific5,
         {"Entity Specific #5", "ieee17221.entity_specific_5",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific6,
         {"Entity Specific #6", "ieee17221.entity_specific_6",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific7,
         {"Entity Specific #7", "ieee17221.entity_specific_7",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_entity_specific8,
         {"Entity Specific #8", "ieee17221.entity_specific_8",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}
      },
      { &hf_aecp_key_guid,
         {"Key GUID", "ieee17221.key_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_token_length,
         {"Token Length", "ieee17221.token_length",
            FT_UINT16, BASE_DEC, NULL, AECP_TOKEN_LENGTH_MASK, NULL, HFILL }
      },
      { &hf_aecp_key,
         {"Key", "ieee17221.key",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_signature,
         {"Signature", "ieee17221.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_auth_token,
         {"Auth Token", "ieee17221.auth_token",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_flags_32,
         {"Flags", "ieee17221.flags",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* AUTH_GET_KEY */
      /* AUTHENTICATE */
      /* GET_COUNTERS */
      { &hf_aecp_gptp_unlocked_valid,
         {"GPTP Unlocked Valid", "ieee17221.flags.gptp_unlocked_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_GPTP_UNLOCKED, NULL, HFILL }
      },
      { &hf_aecp_gtpt_locked_valid,
         {"GPTP Locked Valid", "ieee17221.flags.gptp_locked_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_GPTP_LOCKED, NULL, HFILL }
      },
      { &hf_aecp_media_unlocked_valid,
         {"Media Unlocked Valid", "ieee17221.flags.media_unlocked_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_MEDIA_UNLOCKED, NULL, HFILL }
      },
      { &hf_aecp_media_locked_valid,
         {"Media Locked Valid", "ieee17221.flags._valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_MEDIA_LOCKED, NULL, HFILL }
      },
      { &hf_aecp_stream_reset_valid,
         {"Stream Reset Valid", "ieee17221.flags.stream_reset_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_STREAM_RESET, NULL, HFILL }
      },
      { &hf_aecp_srp_refused_valid,
         {"SRP Refused Valid", "ieee17221.flags.srt_refused_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_SRP_REFUSED, NULL, HFILL }
      },
      { &hf_aecp_backup_stream_switch_valid,
         {"Backup Stream Switch Valid", "ieee17221.flags.backup_stream_switch_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_BACKUP_STREAM_SWITCH, NULL, HFILL }
      },
      { &hf_aecp_missed_avdecc_response_valid,
         {"Missed Avdecc Response Valid", "ieee17221.flags.missed_avdecc_response_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_MISSED_AVDECC_RESPONSE, NULL, HFILL }
      },
      { &hf_aecp_refused_avdecc_command_valid,
         {"Refused Avdecc Command Valid", "ieee17221.flags.refused_avdecc_command_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_REFUSED_AVDECC_COMMAND, NULL, HFILL }
      },
      { &hf_aecp_seq_num_mismatch_valid,
         {"Seq Num Mismatch Valid", "ieee17221.flags.seq_num_mismatch_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_SEQ_NUM_MISMATCH, NULL, HFILL }
      },
      { &hf_aecp_media_clock_toggles_valid,
         {"Media Clock Toggles Valid", "ieee17221.flags.media_clock_toggles_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_MEDIA_CLOCK_TOGGLES, NULL, HFILL }
      },
      { &hf_aecp_timestamp_uncertains_valid,
         {"Timestamp Uncertains Valid", "ieee17221.flags.timestamp_uncertains_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_TIMESTAMP_UNCERTAINS, NULL, HFILL }
      },
      { &hf_aecp_timestamp_valids_valid,
         {"Timestamp Valids Valid", "ieee17221.flags.timestamp_valids_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_TIMESTAMP_VALIDS, NULL, HFILL }
      },
      { &hf_aecp_unsupported_formats_valid,
         {"Unsupported Formats Valid", "ieee17221.flags.unsupported_formats_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_UNSUPPORTED_FORMATS, NULL, HFILL }
      },
      { &hf_aecp_bad_presentation_times_valid,
         {"Bad Presentation Times Valid", "ieee17221.flags.bad_presentation_times_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_BAD_PRESENTATION_TIMES, NULL, HFILL }
      },
      { &hf_aecp_srp_latency_violations_valid,
         {"SRP Latency Violations Valid", "ieee17221.flags.srp_latency_violations_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_SRP_LATENCY_VIOLATIONS, NULL, HFILL }
      },
      { &hf_aecp_packets_tx_valid,
         {"Packets TX Valid", "ieee17221.flags.packets_tx_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_PACKETS_TX, NULL, HFILL }
      },
      { &hf_aecp_packets_rx_valid,
         {"Packets RX Valid", "ieee17221.flags.packets_rx_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_PACKETS_RX, NULL, HFILL }
      },
      { &hf_aecp_packets_interest_rx_valid,
         {"Packets of Interest RX Valid", "ieee17221.flags.packets_interest_rx_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_PACKETS_OF_INTEREST_RX, NULL, HFILL }
      },
      { &hf_aecp_talker_bw_reserved_valid,
         {"Talker BW Reserved Valid", "ieee17221.flags.talker_bw_reserved_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_TALKER_BW_RESERVED, NULL, HFILL }
      },
      { &hf_aecp_reserved1_valid,
         {"RESERVED", "ieee17221.flags.reserved",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_RESERVED1, NULL, HFILL }
      },
      { &hf_aecp_reserved2_valid,
         {"RESERVED", "ieee17221.flags.reserved",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_RESERVED2, NULL, HFILL }
      },
      { &hf_aecp_entity_specific1_valid,
         {"Entity Specific 1", "ieee17221.flags.entity_specific1_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_1, NULL, HFILL }
      },
      { &hf_aecp_entity_specific2_valid,
         {"Entity Specific 2", "ieee17221.flags.entity_specific2_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_2, NULL, HFILL }
      },
      { &hf_aecp_entity_specific3_valid,
         {"Entity Specific 3", "ieee17221.flags.entity_specific3_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_3, NULL, HFILL }
      },
      { &hf_aecp_entity_specific4_valid,
         {"Entity Specific 4", "ieee17221.flags.entity_specific4_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_4, NULL, HFILL }
      },
      { &hf_aecp_entity_specific5_valid,
         {"Entity Specific 5", "ieee17221.flags.entity_specific5_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_5, NULL, HFILL }
      },
      { &hf_aecp_entity_specific6_valid,
         {"Entity Specific 6", "ieee17221.flags.entity_specific6_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_6, NULL, HFILL }
      },
      { &hf_aecp_entity_specific7_valid,
         {"Entity Specific 7", "ieee17221.flags.entity_specific7_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_7, NULL, HFILL }
      },
      { &hf_aecp_entity_specific8_valid,
         {"Entity Specific 8", "ieee17221.flags.entity_specific8_valid",
            FT_BOOLEAN, 32, NULL, AECP_COUNTERS_VALID_ENTITY_SPECIFIC_8, NULL, HFILL }
      },

      /* REBOOT */

      /* SET_MEDIA_FORMAT / GET_MEDIA_FORMAT */
      { &hf_aecp_media_format,
         {"Media Format", "ieee17221.media_format",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* REGISTER_STATE_NOTIFICATION */
      { &hf_aecp_address_type,
         {"Address Type", "ieee17221.address_type",
            FT_UINT16, BASE_HEX, VALS(aecp_address_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aecp_mac_address,
         { "MAC address", "ieee17221.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_ipv4_address,
         {"IPV4 Address", "ieee17221.ipv4_address",
            FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_ipv6_address,
         {"IPv6 Address", "ieee17221.ipv6_address",
            FT_IPv6, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* DEREGISTER_STATE_NOTIFICATION */

      /* REGISTER_QUERY_NOTIFICATION / DEREGISTER_QUERY_NOTIFICATION */
      { &hf_aecp_query_period,
         {"Query Period (ms)", "ieee17221.query_period",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_query_limit,
         {"Query Limit", "ieee17221.query_limit",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_query_type,
         {"Query Type", "ieee17221.query_type",
            FT_UINT16, BASE_HEX, VALS(aecp_command_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aecp_query_id,
         {"Query ID", "ieee17221.query_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* IDENTIFY_NOTIFICATION */

      /* STATE_CHANGE_NOTIFICATION */
      { &hf_aecp_count,
         {"Count", "ieee17221.count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_descriptors,
         {"Descriptors Array", "ieee17221.descriptors",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* INCREMENT_CONTROL_VALUE / DECREMENT_CONTROL_VALUE */
      { &hf_aecp_values_count,
         {"Values Count", "ieee17221.values_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_values_list,
         {"Values List", "ieee17221.values_list",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* START_OPERATION */
      { &hf_aecp_operation_id,
         {"Operation ID", "ieee17221.operation_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_operation_type,
         {"Operation Type", "ieee17221.operation_type",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },/* draft spec says this is defined by control_type field *
         * start_operation does not include a control type field *
         * There is an operation type table 7.83 that has not    *
         * yet beed defined. control_type may be part of a       *
         * descriptor; will check                                */

      /* ABORT_OPERATION */

      /* OPERATION_STATUS */
      { &hf_aecp_percent_complete,
         {"Percent Complete", "ieee17221.percent_complete",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* AUTH_GET_KEY_COUNT */
      { &hf_aecp_key_count,
         {"Key Count", "ieee17221.key_count",
            FT_UINT16, BASE_DEC, NULL, AECP_KEY_COUNT_MASK, NULL, HFILL }
      },

      /* * AVDECC ENTITY MODEL DESCRIPTOR FIELDS * */

      /* ENTITY */
      /* hf_aecp_descriptor_type */
      /* hf_aecp_descriptor_id */
      { &hf_aem_entity_guid,
         {"Entity GUID", "ieee17221.entity_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_vendor_id,
         {"Vendor ID", "ieee17221.vendor_id",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_entity_model_id,
         {"Entity Model ID", "ieee17221.entity_model_id",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      /* hf_adp_entity_cap
       * hf_adp_entity_cap_avdecc_ip
       * hf_adp_entity_cap_zero_conf
       * hf_adp_entity_cap_gateway_entity
       * hf_adp_entity_cap_avdecc_control
       * hf_adp_entity_cap_legacy_avc
       * hf_adp_entity_cap_assoc_id_support
       * hf_adp_entity_cap_assoc_id_valid
       */
      /* hf_adp_talker_stream_srcs */
      /* hf_adp_talker_cap & flags */
      /* hf_adp_listener_stream_sinks */
      /* hf_adp_listener_cap & flags */
      /* hf_adp_controller_cap & flags */
      /* hf_adp_avail_index */
      /* where appropriate use adp values */
      { &hf_aem_entity_name,
         {"Entity Name", "ieee17221.entity_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_vendor_name_string,
         {"Vendor Name String (ptr)", "ieee17221.vendor_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_model_name_string,
         {"Model Name String (ptr)", "ieee17221.model_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_firmware_version,
         {"Firmware Version", "ieee17221.firmware_version",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_group_name,
         {"Group Name", "ieee17221.group_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_serial_number,
         {"Serial Number", "ieee17221.serial_number",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_configurations_count,
         {"Configurations Count", "ieee17221.configurations_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_current_configuration,
         {"Current Configuration", "ieee17221.current_configuration",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* CONFIGURATION */
      { &hf_aem_configuration_name,
         {"Configuration Name", "ieee17221.configuration_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_configuration_name_string,
         {"Configuration Name String", "ieee17221.configuration_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_descriptor_counts_count,
         {"Descriptor Counts Count", "ieee17221.descriptor_counts_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_descriptor_counts_offset,
         {"Descriptor Counts Offset", "ieee17221.descriptor_counts_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_descriptor_counts,
         {"Descriptor Counts", "ieee17221.descriptor_counts",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_count,
         {"Count", "ieee17221.count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* AUDIO */
      { &hf_aem_number_of_stream_input_ports,
         {"Number Of Stream Input Ports", "ieee17221.number_of_stream_input_ports",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_stream_input_port,
         {"Base Stream Input Port", "ieee17221.base_stream_input_port",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_stream_output_ports,
         {"Number Of Stream Output Ports", "ieee17221.number_of_stream_output_ports",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_stream_output_port,
         {"Base Stream Output Port", "ieee17221.base_stream_output_port",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_external_input_ports,
         {"Number Of External Input Ports", "ieee17221.number_of_external_input_ports",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_external_input_port,
         {"Base External Input Port", "ieee17221.base_external_input_port",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_external_output_ports,
         {"Number Of External Output Ports", "ieee17221.number_of_external_output_ports",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_external_output_port,
         {"Base External Output Port", "ieee17221.base_external_output_port",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_internal_input_ports,
         {"Number Of Internal Input Ports", "ieee17221.number_of_internal_input_ports",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_internal_input_port,
         {"Base Internal Input Port", "ieee17221.base_internal_input_port",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_internal_output_ports,
         {"Number Of Internal Output Ports", "ieee17221.number_of_internal_output_ports",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_internal_output_port,
         {"Base Internal Output Port", "ieee17221.base_internal_output_port",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_clock_source_id,
         {"Clock Source ID", "ieee17221.clock_source_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_controls,
         {"Number Of Controls", "ieee17221.number_of_controls",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_control,
         {"Base Control", "ieee17221.base_control",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_unit_name,
         {"Unit Name", "ieee17221.unit_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_unit_name_string,
         {"Unit Name String", "ieee17221.unit_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_current_sample_rate,
         {"Current Sample Rate", "ieee17221.current_sample_rate",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_signal_selectors,
         {"Number of Signal Selectors", "ieee17221.num_signal_selectors",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_signal_selector,
         {"Base Signal Selector", "ieee17221.base_signal_selector",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_mixers,
         {"Number of Mixers", "ieee17221.num_mixers",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_mixer,
         {"Base Mixer", "ieee17221.base_mixer",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_matrices,
         {"Number of Matrices", "ieee17221.num_matrices",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_matrix,
         {"Base Matrix", "ieee17221.base_matrix",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* sample rate is 3 bit pull field multiplier and 29 bit base freq in Hz */
      { &hf_aem_sample_rates_offset,
         {"Sample Rates Offset", "ieee17221.sample_rates_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_sample_rates_count,
         {"Sample Rates Count", "ieee17221.sample_rates_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_supported_sample_rate,
         {"Supported Sample Rate", "ieee17221.supported_sample_rate",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_sample_rates,
         {"Sample Rates", "ieee17221.sample_rates",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      { &hf_aem_base_frequency,
         {"Base Frequency", "ieee17221.base_frequency",
            FT_UINT32, BASE_DEC, NULL, AEM_BASE_FREQUENCY_MASK, NULL, HFILL }
      },
      { &hf_aem_pull_field,
         {"Pull Field (frequency multiplier)", "ieee17221.pull_field",
            FT_UINT8, BASE_HEX, VALS(aem_frequency_multiplier_type_vals), AEM_PULL_FIELD_MASK, NULL, HFILL }
      },

      /* VIDEO */

      /* SENSOR */

      /* STREAM_INPUT */
      /* STREAM_OUTPUT */
      { &hf_aem_stream_name,
         {"Stream Name", "ieee17221.stream_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_stream_name_string,
         {"Stream Name String", "ieee17221.stream_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_stream_flags,
         {"Stream Flags", "ieee17221.stream_flags",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_flags_clock_sync_source,
         {"Clock Sync Source Flag", "ieee17221.flags.clock_sync_source",
            FT_BOOLEAN, 16, NULL, AEM_CLOCK_SYNC_SOURCE_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aem_flags_class_a,
         {"Class A Flag", "ieee17221.flags.class_a",
            FT_BOOLEAN, 16, NULL, AEM_CLASS_A_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aem_flags_class_b,
         {"Class B Flag", "ieee17221.flags.class_b",
            FT_BOOLEAN, 16, NULL, AEM_CLASS_B_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aem_stream_channels,
         {"Stream Channels", "ieee17221.stream_channels",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_channel_format,
         {"Channel Format", "ieee17221.channel_format",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_formats_offset,
         {"Formats Offset", "ieee17221.formats_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_formats,
         {"Number Of Formats", "ieee17221.number_of_formats",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backup_talker_guid_0,
         {"Primary Backup Talker GUID", "ieee17221.backup_talker_guid_0",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backup_talker_unique_0,
         {"Primary Backup Talker Unique ID", "ieee17221.backup_talker_unique_0",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backup_talker_guid_1,
         {"Secondary Backup Talker GUID", "ieee17221.backup_talker_guid_1",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backup_talker_unique_1,
         {"Secondary Backup Talker Unique ID", "ieee17221.backup_talker_unique_1",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backup_talker_guid_2,
         {"Tertiary Backup Talker GUID", "ieee17221.backup_talker_guid_2",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backup_talker_unique_2,
         {"Tertiary Backup Talker Unique ID", "ieee17221.backup_talker_unique_2",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backedup_talker_guid,
         {"Backedup Talker GUID", "ieee17221.backedup_talker_guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_backedup_talker_unique,
         {"Backedup Talker Unique ID", "ieee17221.backedup_talker_unique",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_avb_interface_id,
         {"AVB Interface ID", "ieee17221.avb_interface_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },


      /* array head. uses ett_aem_stream_formats */
      { &hf_aem_stream_formats,
         {"Stream Formats Array", "ieee17221.stream_formats",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* EXTERNAL_JACK_INPUT */
      /* EXTERNAL_JACK_OUTPUT*/
      { &hf_aem_jack_name,
         {"Jack Name", "ieee17221.jack_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_jack_name_string,
         {"Jack Name String", "ieee17221.jack_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_interface_name,
         {"Interface Name", "ieee17221.interface_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_interface_name_string,
         {"Interface Name String", "ieee17221.interface_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_jack_flags,
         {"Jack Flags", "ieee17221.jack_flags",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_flags_captive,
         {"Captive Flag", "ieee17221.flags.captive",
            FT_BOOLEAN, 32, NULL, AEM_CAPTIVE_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aem_jack_type,
         {"Jack Type", "ieee17221.jack_type",
            FT_UINT16, BASE_HEX, VALS(aem_jack_type_vals), 0x00, NULL, HFILL }
      },
      /* AUDIO_PORT_INPUT */
      /* AUDIO_PORT_OUTPUT */
      { &hf_aem_port_flags,
         {"Port Flags", "ieee17221.port_flags",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_flags_async_sample_rate_conv,
         {"Asynchronous Sample Rate Converter Flag", "ieee17221.flags.async_sample_rate_conv",
            FT_BOOLEAN, 16, NULL, AEM_ASYNC_SAMPLE_RATE_CONV_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aem_flags_sync_sample_rate_conv,
         {"Synchronous Sample Rate Converter Flag", "ieee17221.flags.sync_sample_rate_conv",
            FT_BOOLEAN, 16, NULL, AEM_SYNC_SAMPLE_RATE_CONV_FLAG_MASK, NULL, HFILL }
      },
      { &hf_aem_audio_channels,
         {"Audio Channels", "ieee17221.audio_channels",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_clusters,
         {"Number of Clusters", "ieee17221.number_of_clusters",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_cluster,
         {"Base Cluster", "ieee17221.base_cluster",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_audio_map,
         {"Base Audio Map", "ieee17221.base_audio_map",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_audio_maps,
         {"Number of Audio Maps", "ieee17221.num_audio_maps",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      /* VIDEO_PORT_INPUT */
      /* VIDEO_PORT_OUTPUT */
      { &hf_aem_current_format,
         {"Current Format", "ieee17221.current_format",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { & hf_aem_stream_id,
         {"Stream Descriptor ID", "ieee17221.stream_descriptor_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_formats_count,
         {"Formats Count", "ieee17221.formats_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* EXTERNAL_PORT_INPUT */
      /* EXTERNAL_PORT_OUTPUT */
      { &hf_aem_jack_id,
         {"Jack ID", "ieee17221.jack_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* SENSOR_PORT_INPUT */
      /* SENSOR_PORT_OUTPUT */
      /* INTERNAL_PORT_INPUT */
      /* INTERNAL_PORT_OUTPUT */
      { &hf_aem_internal_id,
         {"Internal ID", "ieee17221.internal_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      /* AVB_INTERFACE */
      { &hf_aem_msrp_mappings_offset,
         {"MSRP Mappings Offset", "ieee17221.msrp_mappings_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_msrp_mappings_count,
         {"MSRP Mappings Count", "ieee17221.msrp_mappings_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_msrp_mappings,
         {"MSRP Mappings", "ieee17221.msrp_mappings",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_msrp_mapping_traffic_class,
         {"MSRP Mapping Traffic Class", "ieee17221.msrp_mapping_traffic_class",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_msrp_mapping_priority,
         {"MSRP Mapping Priority", "ieee17221.msrp_mapping_priority",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_msrp_vlan_id,
         {"MSRP VLAN ID", "ieee17221.msrp_vlan_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },


      /* CLOCK_SOURCE */
      { &hf_aem_clock_source_name,
         {"Clock Source Name", "ieee17221.clock_source_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_clock_source_name_string,
         {"Clock Source Name String", "ieee17221.clock_source_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_clock_source_flags,
         {"Clock Source Flags", "ieee17221.clock_source_flags",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      }, /* no flags currently defined */
      { &hf_aem_clock_source_type,
         {"Clock Source Type", "ieee17221.clock_source_type",
            FT_UINT16, BASE_HEX, VALS(aem_clock_source_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_clock_source_location_type,
         {"Clock Source Location Type", "ieee17221.clock_source_location_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_clock_source_location_id,
         {"Clock Source Location ID", "ieee17221.clock_source_location_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      /* AUDIO_MAP */
      { &hf_aem_mappings_offset,
         {"Mappings Offset", "ieee17221.mappings_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_mappings,
         {"Number of Mappings", "ieee17221.number_of_mappings",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_mappings,
         {"Mappings", "ieee17221.mappings",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_mapping_stream_index,
         {"Mapping Stream Index", "ieee17221.mapping_stream_index",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_mapping_stream_channel,
         {"Mapping Stream Channel", "ieee17221.mapping_stream_channel",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_mapping_audio_channel,
         {"Mapping Audio Channel", "ieee17221.mapping_audio_channel",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      /* AUDIO_CLUSTER */
      { &hf_aem_channel_count,
         {"Channel Count", "ieee17221.channel_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_path_latency,
         {"Path Latency", "ieee17221.path_latency",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_am824_label,
         {"AM824 Label", "ieee17221.am824_label",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_cluster_name,
         {"Cluster Name", "ieee17221.cluster_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_cluster_name_string,
         {"Cluster Name String", "ieee17221.cluster_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* CONTROL */
      { &hf_aem_control_type,
         {"Control Type", "ieee17221.control_type",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_control_location_type,
         {"Control Location Type", "ieee17221.control_location_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_control_location_id,
         {"Control Location ID", "ieee17221.control_location_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_control_value_type,
         {"Control Value Type", "ieee17221.control_value_type",
            FT_UINT16, BASE_HEX, VALS(aem_control_value_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_control_domain,
         {"Control Domain", "ieee17221.control_domain",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_control_name,
         {"Control Name", "ieee17221.control_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_control_name_string,
         {"Control Name String", "ieee17221.control_name_string",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_values_offset,
         {"Values Offset", "ieee17221.values_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_values,
         {"Number Of Values", "ieee17221.number_of_values",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_control_latency,
         {"Control Latency", "ieee17221.control_latency",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* SIGNAL_SELECTOR */
      { &hf_aem_sources_offset,
         {"Sources Offset", "ieee17221.sources_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_current_signal_type,
         {"Current Signal Type", "ieee17221.current_signal_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_current_signal_id,
         {"Current Signal ID", "ieee17221.current_signal_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_default_signal_type,
         {"Default Signal Type", "ieee17221.default_signal_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_default_signal_id,
         {"Default Signal ID", "ieee17221.default_signal_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_block_latency,
         {"Block Latency", "ieee17221.block_latency",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_signal_type,
         {"Signal Type", "ieee17221.signal_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_signal_id,
         {"Signal ID", "ieee17221.signal_id",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* MIXER */
      { &hf_aem_number_of_sources,
         {"Number of Sources", "ieee17221.number_of_sources",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_value_offset,
         {"Value Offset", "ieee17221.value_offset",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* MATRIX */
      { &hf_aem_width,
         {"Width", "ieee17221.width",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_height,
         {"Height", "ieee17221.height",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_source,
         {"Base Source", "ieee17221.base_source",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_destinations,
         {"Number of Destinations", "ieee17221.num_destinations",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_destination,
         {"Base Destination", "ieee17221.base_destination",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* LOCALE */
      { &hf_aem_locale_identifier,
         {"Locale Identifier", "ieee17221.locale_identifier",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_number_of_strings,
         {"Number of Strings", "ieee17221.number_of_strings",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_base_strings,
         {"Base Strings", "ieee17221.base_strings",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },

      /* STRINGS */
      { &hf_aem_string,
         {"String", "ieee17221.string",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* MATRIX SIGNAL */
      { &hf_aem_signals_count,
         {"Signals Count", "ieee17221.signals_count",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_signals_offset,
         {"Signals Offset", "ieee17221.signals_offset",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },

      /* MEMORY OBJECT */
      { &hf_aem_memory_object_type,
         {"Memory Object Type", "ieee17221.memory_object_type",
            FT_UINT16, BASE_HEX, VALS(aem_memory_object_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_target_descriptor_type,
         {"Target Descriptor Type", "ieee17221.target_descriptor_type",
            FT_UINT16, BASE_HEX, VALS(aem_descriptor_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_target_descriptor_id,
         {"Target Descriptor ID", "ieee17221.target_descriptor_id",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_object_name,
         {"Object Name", "ieee17221.object_name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_object_name_string,
         {"Object Name String", "ieee17221.object_name_string",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_start_address,
         {"Start Address", "ieee17221.start_address",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_length,
         {"Length", "ieee17221.length",
            FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },


      /* CONTROL VALUE TYPES */
      { &hf_aem_ctrl_int8,
         {"Control INT8", "ieee17221.ctrl_int8",
            FT_INT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_uint8,
         {"Control UINT8", "ieee17221.ctrl_uint8",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_int16,
         {"Control INT16", "ieee17221.ctrl_int16",
            FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_uint16,
         {"Control UINT16", "ieee17221.ctrl_uint16",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_int32,
         {"Control INT32", "ieee17221.ctrl_int32",
            FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_uint32,
         {"Control UINT32", "ieee17221.ctrl_uint32",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_int64,
         {"Control INT64", "ieee17221.ctrl_int64",
            FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_uint64,
         {"Control UINT64", "ieee17221.ctrl_uint64",
            FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_float,
         {"Control FLOAT", "ieee17221.ctrl_float",
            FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_double,
         {"Control DOUBLE", "ieee17221.ctrl_double",
            FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_ctrl_vals,
         {"Control Values", "ieee17221.ctrl_vals",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_unit,
         {"Control Value Units", "ieee17221.units",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_string_ref,
         {"String Reference", "ieee17221.string_ref",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_guid,
         {"GUID", "ieee17221.guid",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_blob_size,
         {"Blob Size", "ieee17221.blob_size",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_binary_blob,
         {"Binary Blob", "ieee17221.binary_blob",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_sources,
         {"Sources", "ieee17221.sources",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_unknown_descriptor,
         {"Unknown or Malformed Descriptor", "ieee17221.unknown_descriptor",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_frequency,
         {"Frequency", "ieee17221.frequency",
            FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },

      /* AEM MEDIA FORMAT FIELDS */
      /* Standard media formats are defined by always having the 24 most significant bits
       * of the EUI64 set to 0x90e0f0
       */
      { &hf_aem_oui24,
         {"OUI-24", "ieee17221.oui24",
            FT_UINT32, BASE_HEX, NULL, AEM_MASK_OUI24, NULL, HFILL }
      },
      { &hf_aem_mfd_type,
         {"MFD Type", "ieee17221.mfd_type",
            FT_UINT8, BASE_HEX, VALS(aem_mfd_type_vals), 0x00, NULL, HFILL }
      },
      { &hf_aem_div,
         {"Div Flag", "ieee17221.div",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_interlace,
         {"Interlace Flag", "ieee17221.interlace",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_channels,
         {"Video Channel Count", "ieee17221.channels",
            FT_UINT8, BASE_DEC, NULL, AEM_MASK_CHANNELS, NULL, HFILL }
      },
      { &hf_aem_color_format,
         {"Color Format", "ieee17221.color_format",
            FT_UINT16, BASE_HEX, VALS(aem_color_format_type_vals), AEM_MASK_COLOR_FORMAT, NULL, HFILL }
      },
      { &hf_aem_bpp,
         {"Bits Per Pixel", "ieee17221.bpp",
            FT_UINT8, BASE_DEC, NULL, AEM_MASK_BPP, NULL, HFILL }
      },
      { &hf_aem_aspect_x,
         {"Aspect X", "ieee17221.aspect_x",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_aspect_y,
         {"Aspect Y", "ieee17221.aspect_y",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_frame_rate,
         {"Frame Rate", "ieee17221.frame_rate",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_comp1,
         {"Comp 1", "ieee17221.comp1",
            FT_UINT16, BASE_DEC, NULL, AEM_MASK_COMP1, NULL, HFILL }
      },
      { &hf_aem_comp2,
         {"Comp 2", "ieee17221.comp2",
            FT_UINT8, BASE_DEC, NULL, AEM_MASK_COMP2, NULL, HFILL }
      },
      { &hf_aem_comp3,
         {"Comp 3", "ieee17221.comp3",
            FT_UINT16, BASE_DEC, NULL, AEM_MASK_COMP3, NULL, HFILL }
      },
      { &hf_aem_comp4,
         {"Comp 4", "ieee17221.comp4",
            FT_UINT8, BASE_DEC, NULL, AEM_MASK_COMP4, NULL, HFILL }
      },
      { &hf_aem_mf_width,
         {"Width", "ieee17221.width",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_mf_height,
         {"Height", "ieee17221.height",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_cs_eui64,
         {"CS EUI64", "ieee17221.cs_eui64",
            FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      /* BEGIN STREAM FORMAT (SF) FIELDS */
      { &hf_aem_stream_format,
         {"Stream Format", "ieee17221.stream_format",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_sf_version,
         {"Version", "ieee17221.sf_version",
            FT_UINT8, BASE_HEX, NULL, AEM_MASK_SF_VERSION, NULL, HFILL }
      },
      { &hf_aem_subtype,
         {"Subtype", "ieee17221.sf_subtype",
            FT_UINT16, BASE_HEX, VALS(aem_stream_format_subtype_vals), AEM_MASK_SF_SUBTYPE, NULL, HFILL }
      },
      { &hf_aem_sf,
         {"SF", "ieee17221.sf",
            FT_BOOLEAN, 8, NULL, AEM_MASK_SF, NULL, HFILL }
      },
      { &hf_aem_iidc_format,
         {"IIDC Format", "ieee17221.iidc_format",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_iidc_mode,
         {"IIDC Mode", "ieee17221.iidc_mode",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_iidc_rate,
         {"IIDC Rate", "ieee17221.iidc_rate",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_fmt,
         {"FMT", "ieee17221.fmt",
            FT_UINT8, BASE_HEX, NULL, AEM_MASK_FMT, NULL, HFILL }
      },
      { &hf_aem_fdf_evt,
         {"FDF EVT", "ieee17221.fdf_evt",
            FT_UINT8, BASE_HEX, NULL, AEM_MASK_FDF_EVT, NULL, HFILL }
      },
      { &hf_aem_fdf_sfc,
         {"FDF SFC", "ieee17221.fdf_sfc",
            FT_UINT8, BASE_HEX, NULL, AEM_MASK_FDF_SFC, NULL, HFILL }
      },
      { &hf_aem_dbs,
         {"DBS", "ieee17221.dbs",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_b_flag,
         {"Blocking Flag", "ieee17221.flags.b",
            FT_BOOLEAN, 8, NULL, AEM_MASK_B, NULL, HFILL }
      },
      { &hf_aem_nb_flag,
         {"NonBlocking Flag", "ieee17221.flags.nb",
            FT_BOOLEAN, 8, NULL, AEM_MASK_NB, NULL, HFILL }
      },
      { &hf_aem_label_iec_60958_cnt,
         {"Label IEC 60958 Count", "ieee17221.label_iec_60958_cnt",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_label_mbla_cnt,
         {"Label Multi-Bit Linear Audio Count", "ieee17221.label_mbla_cnt",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_label_midi_cnt,
         {"Label Midi Slot Count", "ieee17221.label_midi_cnt",
            FT_UINT8, BASE_DEC, NULL, AEM_MASK_LABEL_MIDI_CNT, NULL, HFILL }
      },
      { &hf_aem_label_smpte_cnt,
         {"Label SMPTE Slot Count", "ieee17221.label_smpte_cnt",
            FT_UINT8, BASE_DEC, NULL, AEM_MASK_LABEL_SMPTE_CNT, NULL, HFILL }
      },
      { &hf_aem_video_mode,
         {"Video Mode", "ieee17221.video_mode",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_compress_mode,
         {"Compress Mode", "ieee17221.compress_mode",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aem_color_space,
         {"Color Space", "ieee17221.color_sapce",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
      },
      { &hf_aecp_values,
         {"Values", "ieee17221.values",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
      }

      /* END STREAM FORMAT (SF) FIELDS */
   };

   /* Setup protocol subtree array */
   static gint *ett[] = {
      &ett_17221,
      &ett_adp_ent_cap,
      &ett_adp_talk_cap,
      &ett_adp_list_cap,
      &ett_adp_cont_cap,
      &ett_adp_aud_format,
      &ett_adp_samp_rates,
      &ett_adp_chan_format,
      &ett_acmp_flags,
      &ett_aem_desc_counts,
      &ett_aem_descriptor,
      &ett_aem_sample_rates,
      &ett_aem_stream_flags,
      &ett_aem_stream_formats,
      &ett_aem_jack_flags,
      &ett_aem_port_flags,
      &ett_aem_msrp_mappings,
      &ett_aem_clock_source_flags,
      &ett_aem_mappings,
      &ett_aem_ctrl_vals,
      &ett_aem_sources,
      &ett_aem_media_format,
      &ett_aecp_descriptors,
      &ett_aecp_flags_32,
      &ett_aem_stream_format
   };

   /* Register the protocol name and description */
   proto_17221 = proto_register_protocol("IEEE 1722.1 Protocol", "IEEE1722.1", "ieee17221");

   /* Required function calls to register the header fields and subtrees used */
   proto_register_field_array(proto_17221, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_17221(void)
{

   dissector_handle_t avb17221_handle;

   /* avb17221_handle = find_dissector("ieee1722"); */

   avb17221_handle = create_dissector_handle(dissect_17221, proto_17221);
   dissector_add_uint("ieee1722.subtype", 0x7A, avb17221_handle);
   dissector_add_uint("ieee1722.subtype", 0x7B, avb17221_handle);
   dissector_add_uint("ieee1722.subtype", 0x7C, avb17221_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
