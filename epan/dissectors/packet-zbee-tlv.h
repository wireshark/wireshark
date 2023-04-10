
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

guint dissect_zbee_tlvs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, void *data, guint8 source_type, guint cmd_id);

#endif
