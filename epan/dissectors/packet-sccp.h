/* packet-sccp.h
 * Definitions for Signalling Connection Control Part (SCCP) dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SCCP_H
#define __PACKET_SCCP_H

#include "ws_symbol_export.h"

#define SCCP_MSG_TYPE_CR    0x01
#define SCCP_MSG_TYPE_CC    0x02
#define SCCP_MSG_TYPE_CREF  0x03
#define SCCP_MSG_TYPE_RLSD  0x04
#define SCCP_MSG_TYPE_RLC   0x05
#define SCCP_MSG_TYPE_DT1   0x06
#define SCCP_MSG_TYPE_DT2   0x07
#define SCCP_MSG_TYPE_AK    0x08
#define SCCP_MSG_TYPE_UDT   0x09
#define SCCP_MSG_TYPE_UDTS  0x0a
#define SCCP_MSG_TYPE_ED    0x0b
#define SCCP_MSG_TYPE_EA    0x0c
#define SCCP_MSG_TYPE_RSR   0x0d
#define SCCP_MSG_TYPE_RSC   0x0e
#define SCCP_MSG_TYPE_ERR   0x0f
#define SCCP_MSG_TYPE_IT    0x10
#define SCCP_MSG_TYPE_XUDT  0x11
#define SCCP_MSG_TYPE_XUDTS 0x12
#define SCCP_MSG_TYPE_LUDT  0x13
#define SCCP_MSG_TYPE_LUDTS 0x14

WS_DLL_PUBLIC const value_string sccp_message_type_acro_values[];
WS_DLL_PUBLIC const value_string sccp_release_cause_values[];
WS_DLL_PUBLIC const value_string sccp_return_cause_values[];
WS_DLL_PUBLIC const value_string sccp_reset_cause_values[];
WS_DLL_PUBLIC const value_string sccp_error_cause_values[];
WS_DLL_PUBLIC const value_string sccp_refusal_cause_values[];

/* from packet-sua.c */
WS_DLL_PUBLIC const value_string sua_co_class_type_acro_values[];

typedef enum _sccp_payload_t {
    SCCP_PLOAD_NONE,
    SCCP_PLOAD_BSSAP,
    SCCP_PLOAD_RANAP,
    SCCP_PLOAD_NUM_PLOADS
} sccp_payload_t;

typedef struct _sccp_msg_info_t {
	unsigned framenum;
	unsigned offset;
	unsigned type;

	union {
		struct {
			char* label;
			char* comment;
			char* imsi;
			struct _sccp_assoc_info_t* assoc;
			struct _sccp_msg_info_t* next;
		} co;
		struct {
			uint8_t* calling_gt;
			unsigned calling_ssn;
			uint8_t* called_gt;
			unsigned called_ssn;
		} ud;
	} data;
} sccp_msg_info_t;

typedef struct _sccp_assoc_info_t {
    uint32_t id;
    uint32_t calling_dpc;
    uint32_t called_dpc;
    uint8_t calling_ssn;
    uint8_t called_ssn;
    bool has_fw_key;
    bool has_bw_key;
    sccp_msg_info_t* msgs;
    sccp_msg_info_t* curr_msg;

    sccp_payload_t payload;
    char* calling_party;
    char* called_party;
    char* extra_info;
    char* imsi;
    uint32_t app_info;  /* used only by dissectors of protocols above SCCP */

} sccp_assoc_info_t;

typedef struct _sccp_decode_context_t {
    uint8_t message_type;
    unsigned dlr;
    unsigned slr;
    sccp_assoc_info_t* assoc;
    sccp_msg_info_t*   sccp_msg;

} sccp_decode_context_t;

extern sccp_assoc_info_t* get_sccp_assoc(packet_info* pinfo, unsigned offset, sccp_decode_context_t* value);
extern bool looks_like_valid_sccp(uint32_t frame_num, tvbuff_t *tvb, uint8_t my_mtp3_standard);

#define INVALID_LR 0xffffff /* a reserved value */

#define GT_SIGNAL_LENGTH     1
#define GT_ODD_SIGNAL_MASK   0x0f
#define GT_EVEN_SIGNAL_MASK  0xf0
#define GT_EVEN_SIGNAL_SHIFT 4
#define GT_MAX_SIGNALS (32*7)	/* it's a bit big, but it allows for adding a lot of "(spare)" and "Unknown" values (7 chars) if there are errors - e.g. ANSI vs ITU wrongly selected */
WS_DLL_PUBLIC const value_string sccp_address_signal_values[];

#endif
