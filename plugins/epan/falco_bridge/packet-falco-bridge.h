/* packet-falco-bridge.h
 *
 * By Loris Degioanni
 * Copyright (C) 2021 Sysdig, Inc.
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __PACKET_FALCO_BRIDGE_H__
#define __PACKET_FALCO_BRIDGE_H__

/*
 * API versions of this plugin engine
 */
#define PLUGIN_API_VERSION_MAJOR 0
#define PLUGIN_API_VERSION_MINOR 2
#define PLUGIN_API_VERSION_PATCH 0

/*
 * Return types
 */
#define SCAP_SUCCESS 0
#define SCAP_FAILURE 1
#define SCAP_TIMEOUT -1
#define SCAP_ILLEGAL_INPUT 3
#define SCAP_NOTFOUND 4
#define SCAP_INPUT_TOO_SMALL 5
#define SCAP_EOF 6
#define SCAP_UNEXPECTED_BLOCK 7
#define SCAP_VERSION_MISMATCH 8
#define SCAP_NOT_SUPPORTED 9

#define PROTO_DATA_BRIDGE_HANDLE    0x00
#define PROTO_DATA_CONVINFO_USER_0   10000
#define PROTO_DATA_CONVINFO_USER_1   10001
#define PROTO_DATA_CONVINFO_USER_2   10002
#define PROTO_DATA_CONVINFO_USER_3   10003
#define PROTO_DATA_CONVINFO_USER_4   10004
#define PROTO_DATA_CONVINFO_USER_5   10005
#define PROTO_DATA_CONVINFO_USER_6   10006
#define PROTO_DATA_CONVINFO_USER_7   10007
#define PROTO_DATA_CONVINFO_USER_8   10008
#define PROTO_DATA_CONVINFO_USER_9   10009
#define PROTO_DATA_CONVINFO_USER_10  10010
#define PROTO_DATA_CONVINFO_USER_11  10011
#define PROTO_DATA_CONVINFO_USER_12  10012
#define PROTO_DATA_CONVINFO_USER_13  10013
#define PROTO_DATA_CONVINFO_USER_14  10014
#define PROTO_DATA_CONVINFO_USER_15  10015
#define PROTO_DATA_CONVINFO_USER_BASE PROTO_DATA_CONVINFO_USER_0

typedef enum bridge_field_flags_e {
    BFF_NONE = 0,
    BFF_HIDDEN = 1 << 1, // Unused
    BFF_INFO = 1 << 2,
    BFF_CONVERSATION = 1 << 3
} bridge_field_flags_e;

typedef struct bridge_info {
    sinsp_source_info_t *ssi;
    uint32_t source_id;
    int proto;
    hf_register_info* hf;
    int* hf_ids;
    uint32_t visible_fields;
    uint32_t* field_flags;
    int* field_ids;
} bridge_info;

typedef struct conv_fld_info {
    const char* proto_name;
    hf_register_info* field_info;
    char field_val[4096];
} conv_fld_info;

#endif // __PACKET_FALCO_BRIDGE_H__
