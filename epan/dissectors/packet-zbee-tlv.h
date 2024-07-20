
/* packet-zbee-tlv.h
 * Dissector routines for the Zbee TLV (R23+)
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_ZBEE_TLV_H
#define _PACKET_ZBEE_TLV_H

#define ZBEE_TLV_HEADER_LENGTH 2
#define ZBEE_TLV_GLOBAL_START_NUMBER           64

/* Global TLV */
#define ZBEE_TLV_TYPE_MANUFACTURER_SPECIFIC                64
#define ZBEE_TLV_TYPE_SUPPORTED_KEY_NEGOTIATION_METHODS    65
#define ZBEE_TLV_TYPE_PANID_CONFLICT_REPORT                66
#define ZBEE_TLV_TYPE_NEXT_PAN_ID                          67
#define ZBEE_TLV_TYPE_NEXT_CHANNEL_CHANGE                  68
#define ZBEE_TLV_TYPE_PASSPHRASE                           69
#define ZBEE_TLV_TYPE_ROUTER_INFORMATION                   70
#define ZBEE_TLV_TYPE_FRAGMENTATION_PARAMETERS             71
#define ZBEE_TLV_TYPE_JOINER_ENCAPSULATION_GLOBAL          72
#define ZBEE_TLV_TYPE_BEACON_APPENDIX_ENCAPSULATION_GLOBAL 73
/* RESERVED 74 */
#define ZBEE_TLV_TYPE_CONFIGURATION_MODE_PARAMETERS        75
#define ZBEE_TLV_TYPE_DEVICE_CAPABILITY_EXTENSION          76 /* zb direct */

/* ZigBee local TLV source types */
#define ZBEE_TLV_SRC_TYPE_DEFAULT                     0x00
#define ZBEE_TLV_SRC_TYPE_ZBEE_NWK                    0x01
#define ZBEE_TLV_SRC_TYPE_ZBEE_APS                    0x02
#define ZBEE_TLV_SRC_TYPE_ZBEE_ZDP                    0x03
#define ZBEE_TLV_SRC_TYPE_ZB_DIRECT                   0x04

/* Local TLV Tags*/
/* Clear All Bindings Request */
#define ZBEE_TLV_TYPE_CLEAR_ALL_BINDIGS_REQ_EUI64                    0
/* Security Key Update request/response */
#define ZBEE_TLV_TYPE_KEY_UPD_REQ_SELECTED_KEY_NEGOTIATION_METHOD    0
/* Security Start Key Negotiation request/response */
#define ZBEE_TLV_TYPE_KEY_NEG_REQ_CURVE25519_PUBLIC_POINT            0
/* Security Get Authentication Token Request */
#define ZBEE_TLV_TYPE_REQUESTED_AUTH_TOKEN_ID                        0
/* Security Get Authentication Token Request */
#define ZBEE_TLV_TYPE_TARGET_IEEE_ADDRESS                            0
/* Security Decommission Request */
#define ZBEE_TLV_TYPE_EUI64                                          0
/* Beacon Survey Request */
#define ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION                    0
#define ZBEE_TLV_TYPE_BEACON_SURVEY_RESULTS                          1
#define ZBEE_TLV_TYPE_BEACON_SURVEY_POTENTIAL_PARENTS                2

/* Security Get_Authentication_Level Response */
#define ZBEE_TLV_TYPE_GET_AUTH_LEVEL                                 0

/* ZigBee Direct Communication Service */
#define ZBEE_TLV_TYPE_COMM_EXT_PAN_ID       0              /* Extended PAN ID */
#define ZBEE_TLV_TYPE_COMM_SHORT_PAN_ID     1              /* Short PAN ID */
#define ZBEE_TLV_TYPE_COMM_NWK_CH           2              /* Short PAN ID */
#define ZBEE_TLV_TYPE_COMM_NWK_KEY          3              /* Network Channel */
#define ZBEE_TLV_TYPE_COMM_LNK_KEY          4              /* Link Key */
#define ZBEE_TLV_TYPE_COMM_DEV_TYPE         5              /* Device Type */
#define ZBEE_TLV_TYPE_COMM_NWK_ADDR         6              /* NWK Address */
#define ZBEE_TLV_TYPE_COMM_JOIN_METHOD      7              /* Joining Method */
#define ZBEE_TLV_TYPE_COMM_IEEE_ADDR        8              /* IEEE Address */
#define ZBEE_TLV_TYPE_COMM_TC_ADDR          9              /* Trust Center Address */
#define ZBEE_TLV_TYPE_COMM_NWK_STATUS_MAP   10             /* Network Status Map */
#define ZBEE_TLV_TYPE_COMM_NWK_UPD_ID       11             /* NWK Update ID */
#define ZBEE_TLV_TYPE_COMM_KEY_SEQ_NUM      12             /* NWK Active Key Seq Number */
#define ZBEE_TLV_TYPE_COMM_ADMIN_KEY        13             /* Admin Key */
#define ZBEE_TLV_TYPE_COMM_STATUS_CODE      14             /* Extended Status Code */

/* ZigBee Direct Manage Joiners TLV IDs */
#define ZBEE_TLV_TYPE_COMM_MJ_PROVISIONAL_LINK_KEY  0      /* Provisional Link Key */
#define ZBEE_TLV_TYPE_COMM_MJ_IEEE_ADDR             1      /* IEEE Address */
#define ZBEE_TLV_TYPE_COMM_MJ_CMD                   2      /* Manage Joiners Command */

/* ZigBee Direct Tunnel Service */
#define ZBEE_TLV_TYPE_TUNNELING_NPDU_MESSAGE  0            /* NPDU Message */

/* ZigBee Direct Security Service */
#define ZBEE_TLV_TYPE_KEY_METHOD        0        /* ZigBee Direct Key Negotiation Method */
#define ZBEE_TLV_TYPE_PUB_POINT_P256    1        /* ZigBee Direct Key Negotiation P-256 Public Point */
#define ZBEE_TLV_TYPE_PUB_POINT_C25519  2        /* ZigBee Direct Key Negotiation Curve25519 Public Point */
#define ZBEE_TLV_TYPE_NWK_KEY_SEQ_NUM   3        /* Network Key Sequence Number */
#define ZBEE_TLV_TYPE_MAC_TAG           4        /* MacTag */

/* TLV parameters*/
#define ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_KEY_REQUEST                                     1 << 0
#define ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ANONYMOUS_ECDHE_USING_CURVE25519_AES_MMO128     1 << 1
#define ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ANONYMOUS_ECDHE_USING_CURVE25519_SHA256         1 << 2
#define ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ECDHE_AUTHENTICATION_CURVE25519_AES_MMO128      1 << 3
#define ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ECDHE_AUTHENTICATION_CURVE25519_SHA256          1 << 4

#define ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ZB_30                                  0x0
#define ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ECDHE_USING_CURVE25519_AES_MMO128      0x1
#define ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ECDHE_USING_CURVE25519_SHA256          0x2

#define ZBEE_TLV_SELECTED_PRE_SHARED_WELL_KNOWN_KEY           0xff
#define ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_AUTH_TOKEN        0x00
#define ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_LINK_KEY_IC       0x01
#define ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_VLEN_PASSCODE     0x02
#define ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_BASIC_ACCESS_KEY  0x03
#define ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_ADMIN_ACCESS_KEY  0x04

#define ZBEE_TLV_ROUTER_INFORMATION_HUB_CONNECTIVITY                                               1 << 0
#define ZBEE_TLV_ROUTER_INFORMATION_UPTIME                                                         1 << 1
#define ZBEE_TLV_ROUTER_INFORMATION_PREF_PARENT                                                    1 << 2
#define ZBEE_TLV_ROUTER_INFORMATION_BATTERY_BACKUP                                                 1 << 3
#define ZBEE_TLV_ROUTER_INFORMATION_ENHANCED_BEACON_REQUEST_SUPPORT                                1 << 4
#define ZBEE_TLV_ROUTER_INFORMATION_MAC_DATA_POLL_KEEPALIVE_SUPPORT                                1 << 5
#define ZBEE_TLV_ROUTER_INFORMATION_END_DEVICE_KEEPALIVE_SUPPORT                                   1 << 6
#define ZBEE_TLV_ROUTER_INFORMATION_POWER_NEGOTIATION_SUPPORT                                      1 << 7

#define ZBEE_TLV_LINK_KEY_UNIQUE                                                                   1 << 0
#define ZBEE_TLV_LINK_KEY_PROVISIONAL                                                              1 << 1

#define ZBEE_TLV_STATUS_MAP_JOINED_STATUS                                                      0b00000111
#define ZBEE_TLV_STATUS_MAP_OPEN_STATUS                                                        0b00001000
#define ZBEE_TLV_STATUS_MAP_NETWORK_TYPE                                                       0b00010000

#define ZBEE_TLV_TYPE_MSG_SE1 1
#define ZBEE_TLV_TYPE_MSG_SE2 2
#define ZBEE_TLV_TYPE_MSG_SE3 3
#define ZBEE_TLV_TYPE_MSG_SE4 4

#define ZBEE_TLV_TYPE_KEY_ECDHE_KEY_REQUEST_ZB_30           0 /* Static Key Update Request */
#define ZBEE_TLV_TYPE_DIRECT_KEY_ECDHE_RESERVED_MIN         0 /* 0 is reserved in zigbee direct */
#define ZBEE_TLV_TYPE_KEY_ECDHE_CURVE_25519_HASH_AESMMO128  1
#define ZBEE_TLV_TYPE_KEY_ECDHE_CURVE_25519_HASH_SHA256     2
#define ZBEE_TLV_TYPE_KEY_ECDHE_RESERVED_MAX                3 /* 3-15 is reserved in r23 */
#define ZBEE_TLV_TYPE_KEY_ECDHE_CURVE_P256_HASH_SHA256      3

#define ZBEE_TLV_TYPE_PSK_WELL_KNOWN_KEY                   0xFF
#define ZBEE_TLV_TYPE_PSK_SECRET_AUTH_TOKEN                0
#define ZBEE_TLV_TYPE_PSK_SECRET_INSTALL_CODE              1
#define ZBEE_TLV_TYPE_PSK_SECRET_PAKE_PASSCODE             2
#define ZBEE_TLV_TYPE_PSK_SECRET_BASIC_ACCESS_KEY          3
#define ZBEE_TLV_TYPE_PSK_SECRET_ADMINISTRATIVE_ACCESS_KEY 4

#define ZBEE_TLV_TYPE_DEV_TYPE_ZC 0
#define ZBEE_TLV_TYPE_DEV_TYPE_ZR 1
#define ZBEE_TLV_TYPE_DEV_TYPE_ED 2

#define ZBEE_TLV_TYPE_JOIN_METHOD_MAC_ASS           0
#define ZBEE_TLV_TYPE_JOIN_METHOD_NWK_REJ           1
#define ZBEE_TLV_TYPE_JOIN_METHOD_OOB_WITH_CHECK    2
#define ZBEE_TLV_TYPE_JOIN_METHOD_OOB_WITHOUT_CHECK 3

#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_GENERAL         0x00
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_FORM            0x01
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_JOIN            0x02
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_PERMIT_JOIN     0x03
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_LEAVE           0x04
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_MANAGE_JOINERS  0x05
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_IDENTIFY        0x06
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_FINDING_BINDING 0x07
#define ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_MAX             0x08

#define ZBEE_TLV_TYPE_JOINED_STATUS_NO_NWK           0
#define ZBEE_TLV_TYPE_JOINED_STATUS_JOINING          1
#define ZBEE_TLV_TYPE_JOINED_STATUS_JOINED           2
#define ZBEE_TLV_TYPE_JOINED_STATUS_JOINED_NO_PARENT 3
#define ZBEE_TLV_TYPE_JOINED_STATUS_LEAVING          4

#define ZBEE_TLV_NWK_TYPE_DISTRIBUTED 0
#define ZBEE_TLV_NWK_TYPE_CENTRALIZED 1

#define ZBEE_TLV_TYPE_NWK_STATE_CLOSED 0
#define ZBEE_TLV_TYPE_NWK_STATE_OPENED 1

#define ZBEE_TLV_TYPE_MANAGE_JOINERS_CMD_DROP    0
#define ZBEE_TLV_TYPE_MANAGE_JOINERS_CMD_ADD     1
#define ZBEE_TLV_TYPE_MANAGE_JOINERS_CMD_REMOVE  2

#define ZBEE_TLV_TYPE_LINK_KEY_FLAG_GLOBAL  0
#define ZBEE_TLV_TYPE_LINK_KEY_FLAG_UNIQUE  1

#define ZBEE_TLV_TYPE_LINK_KEY_FLAG_PERMANENT   0
#define ZBEE_TLV_TYPE_LINK_KEY_FLAG_PROVISIONAL 1

unsigned dissect_zbee_tlvs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void *data, uint8_t source_type, unsigned cmd_id);

#endif
