/* packet-dect_nwk.c
 *
 * Dissector for the DECT (Digital Enhanced Cordless Telecommunications)
 * NWK protocol layer as described in ETSI EN 300 175-5 V2.7.1 (2017-11)
 *
 * Copyright 2018 by Harald Welte <laforge@gnumonks.org>
 * Copyright 2022 by Bernhard Dick <bernhard@bdick.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/value_string.h>
#include <ftypes/ftypes.h>

static int proto_dect_nwk = -1;

static gint hf_nwk_ti = -1;
static gint hf_nwk_pdisc = -1;
static gint hf_nwk_msg_type_lce = -1;
static gint hf_nwk_msg_type_cc = -1;
static gint hf_nwk_msg_type_mm = -1;

static gint ett_dect_nwk_s_ie_element = -1;

static gint hf_dect_nwk_s_ie_fl = -1;
static gint hf_dect_nwk_s_ie_type = -1;
static gint hf_dect_nwk_s_ie_length = -1;

static gint hf_dect_nwk_s_ie_cipher_info_yn = -1;
static gint hf_dect_nwk_s_ie_cipher_info_algorithm = -1;
static gint hf_dect_nwk_s_ie_cipher_info_proprietary_algorithm = -1;
static gint hf_dect_nwk_s_ie_cipher_info_key_type = -1;
static gint hf_dect_nwk_s_ie_cipher_info_key_number = -1;

static gint hf_dect_nwk_s_ie_fixed_identity_type = -1;
static gint hf_dect_nwk_s_ie_fixed_identity_value_length = -1;
static gint hf_dect_nwk_s_ie_fixed_identity_arc = -1;
static gint hf_dect_nwk_s_ie_fixed_identity_ard = -1;
static gint hf_dect_nwk_s_ie_fixed_identity_padding = -1;

static gint hf_dect_nwk_s_ie_nwk_assigned_identity_type = -1;
static gint hf_dect_nwk_s_ie_nwk_assigned_identity_value_length = -1;
static gint hf_dect_nwk_s_ie_nwk_assigned_identity_value = -1;
static gint hf_dect_nwk_s_ie_nwk_assigned_identity_padding = -1;

static gint hf_dect_nwk_s_ie_portable_identity_type = -1;
static gint hf_dect_nwk_s_ie_portable_identity_value_length = -1;
static gint hf_dect_nwk_s_ie_portable_identity_put = -1;
static gint hf_dect_nwk_s_ie_portable_identity_padding = -1;
static gint hf_dect_ipui_o_number = -1;

static gint hf_dect_nwk_s_ie_escape_to_proprietary_discriminator_type = -1;
static gint hf_dect_nwk_s_ie_escape_to_proprietary_discriminator = -1;

static gint ett_dect_nwk = -1;

static dissector_handle_t dect_nwk_handle;

/*********************************************************************************
 * DECT DEFINITIONS
 *********************************************************************************/

/* Section 7.2 */
enum dect_nwk_proto_disc {
	DECT_NWK_PDISC_LCE		= 0x0,
	DECT_NWK_PDISC_CC		= 0x3,
	DECT_NWK_PDISC_CISS		= 0x4,
	DECT_NWK_PDISC_MM		= 0x5,
	DECT_NWK_PDISC_CMSS		= 0x6,
	DECT_NWK_PDISC_COMS		= 0x7,
};

/* Section 7.4.1 */
enum dect_nwk_cc_msg_type {
	DECT_NWK_CC_ALERTING		= 0x01,
	DECT_NWK_CC_CALL_PROC		= 0x02,
	DECT_NWK_CC_SETUP		= 0x05,
	DECT_NWK_CC_CONNECT		= 0x07,
	DECT_NWK_CC_SETUP_ACK		= 0x0d,
	DECT_NWK_CC_CONNECT_ACK		= 0x0f,
	DECT_NWK_CC_SERVICE_CHANGE	= 0x20,
	DECT_NWK_CC_SERVICE_ACCEPT	= 0x21,
	DECT_NWK_CC_SERVICE_REJECT	= 0x23,
	DECT_NWK_CC_RELEASE		= 0x4d,
	DECT_NWK_CC_RELEASE_COM		= 0x5a,
	DECT_NWK_CC_IWU_INFO		= 0x60,
	DECT_NWK_CC_NOTIFY		= 0x6e,
	DECT_NWK_CC_INFO		= 0x7b,
};

/* Section 7.4.2 */
enum dect_nwk_ss_msg_type {
	DECT_NWK_SS_CISS_RELEASE_COM	= 0x5a,
	DECT_NWK_SS_CISS_FACILITY	= 0x62,
	DECT_NWK_SS_CISS_REGISTER	= 0x64,

	DECT_NWK_SS_CRSS_HOLD		= 0x24,
	DECT_NWK_SS_CRSS_HOLD_ACK	= 0x28,
	DECT_NWK_SS_CRSS_HOLD_REJ	= 0x30,
	DECT_NWK_SS_CRSS_RETRIEVE	= 0x31,
	DECT_NWK_SS_CRSS_RETRIEVE_ACK	= 0x33,
	DECT_NWK_SS_CRSS_RETRIEVE_REJ	= 0x37,
#define DECT_NWK_SS_CRSS_FACILITY	DECT_NWK_SS_CISS_FACILITY
};

/* Section 7.4.3 */
enum dect_nwk_coms_msg_type {
	DECT_NWK_COMS_SETUP		= 0x05,
	DECT_NWK_COMS_CONNECT		= 0x07,
	DECT_NWK_COMS_NOTIFY		= 0x08,
	DECT_NWK_COMS_RELEASE		= 0x4d,
	DECT_NWK_COMS_RELEASE_COM	= 0x5a,
	DECT_NWK_COMS_INFO		= 0x7b,
	DECT_NWK_COMS_ACK		= 0x78,
};

/* Section 7.4.4 */
enum dect_nwk_clms_msg_type {
	DECT_NWK_CLMS_VARIABLE		= 0x01,
};

/* Section 7.4.5 */
enum dect_nwk_mm_msg_type {
	DECT_NWK_MM_AUTH_REQ		= 0x40,
	DECT_NWK_MM_AUTH_REPLY		= 0x41,
	DECT_NWK_MM_KEY_ALLOC		= 0x42,
	DECT_NWK_MM_AUTH_REJ		= 0x43,
	DECT_NWK_MM_ACC_RIGHTS_REQ	= 0x44,
	DECT_NWK_MM_ACC_RIGHTS_ACK	= 0x45,
	DECT_NWK_MM_ACC_RIGHTS_REJ	= 0x47,
	DECT_NWK_MM_ACC_RIGHTS_TERM_REQ	= 0x48,
	DECT_NWK_MM_ACC_RIGHTS_TERM_ACK	= 0x49,
	DECT_NWK_MM_ACC_RIGHTS_TERM_REJ	= 0x4b,
	DECT_NWK_MM_CIPH_REQ		= 0x4c,
	DECT_NWK_MM_CIPH_SUGGEST	= 0x4e,
	DECT_NWK_MM_CIPH_REJ		= 0x4f,
	DECT_NWK_MM_INFO_REQ		= 0x50,
	DECT_NWK_MM_INFO_ACK		= 0x51,
	DECT_NWK_MM_INFO_SUGGEST	= 0x52,
	DECT_NWK_MM_INFO_REJ		= 0x53,
	DECT_NWK_MM_LOCATE_REQ		= 0x54,
	DECT_NWK_MM_LOCATE_ACK		= 0x55,
	DECT_NWK_MM_DETACH		= 0x56,
	DECT_NWK_MM_LOCATE_REJ		= 0x57,
	DECT_NWK_MM_ID_REQ		= 0x58,
	DECT_NWK_MM_ID_REPLY		= 0x59,
	DECT_NWK_MM_IWU			= 0x5b,
	DECT_NWK_MM_TID_ASSIGN		= 0x5c,
	DECT_NWK_MM_TID_ASSIGN_ACK	= 0x5d,
	DECT_NWK_MM_TID_ASSIGN_REJ	= 0x5f,
	DECT_NWK_MM_NOTIFY		= 0x6e,
};

/* Section 7.4.6 */
enum dect_nwk_lce_msg_type {
	DECT_NWK_LCE_PAGE_RESP		= 0x71,
	DECT_NWK_LCE_PAGE_REJ		= 0x72,
};

/* Section 7.6.1 */

enum dect_nwk_s_fl_ie_type {
	DECT_NWK_S_IE_FL_RESERVERD            = 0x0,
	DECT_NWK_S_IE_FL_SHIFT                = 0x1,
	DECT_NWK_S_IE_FL_CONTROL              = 0x2,
	DECT_NWK_S_IE_FL_REPEAT_INDICATOR     = 0x5,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT = 0x6,
};

enum dect_nwk_s_fl_ie_control_type {
	DECT_NWK_S_IE_FL_CONTROL_SENDING_COMPLETE  = 0x1,
	DECT_NWK_S_IE_FL_CONTROL_DELIMITER_REQUEST = 0x2,
	DECT_NWK_S_IE_FL_CONTROL_USE_TPUI          = 0x3
};

enum dect_nwk_s_fl_ie_double_octet_type {
	DECT_NWK_S_IE_DOUBLE_OCTET_BASIC_SERVICE     = 0x0,
	DECT_NWK_S_IE_DOUBLE_OCTET_RELEASE_REASON    = 0x2,
	DECT_NWK_S_IE_DOUBLE_OCTET_SIGNAL            = 0x4,
	DECT_NWK_S_IE_DOUBLE_OCTET_TIMER_RESTART     = 0x5,
	DECT_NWK_S_IE_DOUBLE_OCTET_TEST_HOOK_CONTROL = 0x6,
	DECT_NWK_S_IE_DOUBLE_OCTET_SINGLE_DISPLAY    = 0x8,
	DECT_NWK_S_IE_DOUBLE_OCTET_SINGLE_KEYPAD     = 0x9,
	DECT_NWK_S_IE_DOUBLE_OCTET_RESERVED          = 0xF,
};

/* Section 7.7.1 */
enum dect_nkw_s_ie_type {
	DECT_NWK_S_IE_INFO_TYPE                  = 0x01,
	DECT_NWK_S_IE_IDENTITY_TYPE              = 0x02,
	DECT_NWK_S_IE_PORTABLE_IDENTITY          = 0x05,
	DECT_NWK_S_IE_FIXED_IDENTITY             = 0x06,
	DECT_NWK_S_IE_LOCATION_AREA              = 0x07,
	DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY      = 0x09,
	DECT_NWK_S_IE_AUTH_TYPE                  = 0x0A,
	DECT_NWK_S_IE_ALLOCATION_TYPE            = 0x0B,
	DECT_NWK_S_IE_RAND                       = 0x0C,
	DECT_NWK_S_IE_RES                        = 0x0D,
	DECT_NWK_S_IE_RS                         = 0x0E,
	DECT_NWK_S_IE_IWU_ATTRIBUTES             = 0x12,
	DECT_NWK_S_IE_CALL_ATTRIBUES             = 0x13,
	DECT_NWK_S_IE_SERVICE_CHANGE_INFO        = 0x16,
	DECT_NWK_S_IE_CONNECTION_ATTRIBUTES      = 0x17,
	DECT_NWK_S_IE_CIPHER_INFO                = 0x19,
	DECT_NWK_S_IE_CALL_IDENTITY              = 0x1A,
	DECT_NWK_S_IE_CONNECTION_IDENTITY        = 0x1B,
	DECT_NWK_S_IE_FACILITY                   = 0x1C,
	DECT_NWK_S_IE_PROGRESS_INDICATOR         = 0x1E,
	DECT_NWK_S_IE_MMS_GENERIC_HEADER         = 0x20,
	DECT_NWK_S_IE_MMS_OBJECT_HEADER          = 0x21,
	DECT_NWK_S_IE_MMS_EXTENDED_HEADER        = 0x22,
	DECT_NWK_S_IE_TIME_DATE                  = 0x23,
	DECT_NWK_S_IE_MULTI_DISPLAY              = 0x28,
	DECT_NWK_S_IE_MULTI_KEYPAD               = 0x2A,
	DECT_NWK_S_IE_FEATURE_ACTIVATE           = 0x38,
	DECT_NWK_S_IE_FEATURE_INDICATE           = 0x39,
	DECT_NWK_S_IE_NETWORK_PARAMETER          = 0x41,
	DECT_NWK_S_IE_EXT_HO_INDICATOR           = 0x42,
	DECT_NWK_S_IE_ZAP_FIELD                  = 0x52,
	DECT_NWK_S_IE_SERVICE_CLASS              = 0x54,
	DECT_NWK_S_IE_KEY                        = 0x56,
	DECT_NWK_S_IE_REJECT_REASON              = 0x60,
	DECT_NWK_S_IE_SETUP_CAPABILITY           = 0x62,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY        = 0x63,
	DECT_NWK_S_IE_END_TO_END_COMPATIBILITY   = 0x64,
	DECT_NWK_S_IE_RATE_PARAMETERS            = 0x65,
	DECT_NWK_S_IE_TRANSIT_DELAY              = 0x66,
	DECT_NWK_S_IE_WINDOW_SIZE                = 0x67,
	DECT_NWK_S_IE_ULE_MAC_CONFIGURATION_INFO = 0x68,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER       = 0x6C,
	DECT_NWK_S_IE_CALLING_PARTY_NAME         = 0x6D,
	DECT_NWK_S_IE_CALLED_PARTY_NUMBER        = 0x70,
	DECT_NWK_S_IE_CALLED_PARTY_SUBADDR       = 0x71,
	DECT_NWK_S_IE_DURATION                   = 0x72,
	DECT_NWK_S_IE_CALLED_PARTY_NAME          = 0x73,
	DECT_NWK_S_IE_LIST_CHANGE_DETAILS        = 0x74,
	DECT_NWK_S_IE_SEGMENTED_INFO             = 0x75,
	DECT_NWK_S_IE_ALPHANUMERIC               = 0x76,
	DECT_NWK_S_IE_IWU_TO_IWU                 = 0x77,
	DECT_NWK_S_IE_MODEL_IDENTIFIER           = 0x78,
	DECT_NWK_S_IE_IWU_PACKET                 = 0x7A,
	DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY      = 0x7B,
	DECT_NWK_S_IE_CODEC_LIST                 = 0x7C,
	DECT_NWK_S_IE_EVENTS_NOTIFICATION        = 0x7D,
	DECT_NWK_S_IE_CALL_INFORMATION           = 0x7E,
	DECT_NWK_S_IE_ESCAPE_FOR_EXTENSION       = 0x7F,
};

/* Section 7.7.10 */
enum dect_nwk_s_ie_cipher_info_algorithm {
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC         = 0x01,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC2        = 0x02,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_NO     = 0x28,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA1   = 0x29,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA2   = 0x2A,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA3   = 0x2B,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA4   = 0x2C,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA5   = 0x2D,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA6   = 0x2E,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA7   = 0x2F,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY = 0xFF,
};

enum dect_nwk_s_ie_cipher_info_key_type {
	DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_DERIVED = 0x9,
	DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_STATIC  = 0xA,
};

/* Section 7.7.18 */
enum dect_nwk_s_ie_fixed_identity_type {
	DECT_NWK_S_IE_FIXED_IDENTITY_ARI              = 0x00,
	DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN     = 0x01,
	DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN_WRS = 0x02,
	DECT_NWK_S_IE_FIXED_IDENTITY_PARK             = 0x20,
};

enum dect_nwk_arc_type {
	DECT_NWK_ARC_TYPE_A = 0x0,
	DECT_NWK_ARC_TYPE_B = 0x1,
	DECT_NWK_ARC_TYPE_C = 0x2,
	DECT_NWK_ARC_TYPE_D = 0x3,
	DECT_NWK_ARC_TYPE_E = 0x4,
	DECT_NWK_ARC_TYPE_F = 0x5,
	DECT_NWK_ARC_TYPE_G = 0x6,
	DECT_NWK_ARC_TYPE_H = 0x7,
};

/* Section 7.7.28 */
enum dect_nwk_s_ie_nwk_assigned_identity_type {
	DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_TMSI        = 0xE4,
	DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_PROPRIETARY = 0xFF,
};

/* Section 7.7.30 */
enum dect_nwk_s_ie_portable_identity_type {
	DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI = 0x00,
	DECT_NWK_S_IE_PORTABLE_IDENTITY_IPEI = 0x10,
	DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI = 0x20,
};

enum dect_nwk_ipui_type {
	DECT_NWK_IPUI_TYPE_N = 0x0,
	DECT_NWK_IPUI_TYPE_O = 0x1,
	DECT_NWK_IPUI_TYPE_P = 0x2,
	DECT_NWK_IPUI_TYPE_Q = 0x3,
	DECT_NWK_IPUI_TYPE_R = 0x4,
	DECT_NWK_IPUI_TYPE_S = 0x5,
	DECT_NWK_IPUI_TYPE_T = 0x6,
	DECT_NWK_IPUI_TYPE_U = 0x7,
};

/* Section 7.7.45 */
enum dect_nwk_s_ie_escape_to_proprietary_discriminator_type {
	DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_UNSPECIFIED = 0x00,
	DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_EMC = 0x01,
};

/*********************************************************************************
 * DECT VALUE STRINGS
 *********************************************************************************/

/* Section 7.2 */
static const value_string nwk_pdisc_vals[] = {
	{ DECT_NWK_PDISC_LCE,		"Link Control Entity (LCE)" },
	{ DECT_NWK_PDISC_CC,		"Call Control (CC)" },
	{ DECT_NWK_PDISC_CISS,		"Call Independent Supplementary Services (CISS)" },
	{ DECT_NWK_PDISC_MM,		"Mobility Management (MM)" },
	{ DECT_NWK_PDISC_CMSS,		"ConnectionLess Message Service (CMSS)" },
	{ DECT_NWK_PDISC_COMS,		"Connection Oriented Message Service (COMS)" },
	{ 0, NULL }
};

/* Section 7.4.1 */
static const value_string nwk_cc_msgt_vals[] = {
	{ DECT_NWK_CC_ALERTING,		"CC-ALERTING" },
	{ DECT_NWK_CC_CALL_PROC,	"CC-CALL-PROC" },
	{ DECT_NWK_CC_SETUP,		"CC-SETUP" },
	{ DECT_NWK_CC_CONNECT,		"CC-CONNECT" },
	{ DECT_NWK_CC_SETUP_ACK,	"CC-SETUP-ACK" },
	{ DECT_NWK_CC_CONNECT_ACK,	"CC-CONNECT-ACK" },
	{ DECT_NWK_CC_SERVICE_CHANGE,	"CC-SERVICE-CHANGE" },
	{ DECT_NWK_CC_SERVICE_ACCEPT,	"CC-SERVICE-ACCEPT" },
	{ DECT_NWK_CC_SERVICE_REJECT,	"CC-SERVICE-REJECT" },
	{ DECT_NWK_CC_RELEASE,		"CC-RELEASE" },
	{ DECT_NWK_CC_RELEASE_COM,	"CC-RELEASE-COM" },
	{ DECT_NWK_CC_IWU_INFO,		"CC-IWU-INFO" },
	{ DECT_NWK_CC_NOTIFY,		"CC-NOTIFY" },
	{ DECT_NWK_CC_INFO,		"CC-INFO" },
	{ 0, NULL }
};

/* Section 7.4.5 */
static const value_string nwk_mm_msgt_vals[] = {
	{ DECT_NWK_MM_AUTH_REQ,		"MM-AUTH-REQ" },
	{ DECT_NWK_MM_AUTH_REPLY,	"MM-AUTH-REPLY" },
	/* FIXME: all other MM messages */
	{ 0, NULL }
};

/* Section 7.4.6 */
static const value_string nwk_lce_msgt_vals[] = {
	{ DECT_NWK_LCE_PAGE_RESP,	"LCE-PAGE-RESPONSE" },
	{ DECT_NWK_LCE_PAGE_REJ, 	"LCE-PAGE-REJECT" },
	{ 0, NULL }
};

/* Section 7.7.1 */
static const value_string dect_nwk_s_ie_type_val[] = {
	{ DECT_NWK_S_IE_INFO_TYPE,                 "INFO-TYPE" },
	{ DECT_NWK_S_IE_IDENTITY_TYPE,             "IDENTITY-TYPE" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY,         "PORTABLE-IDENTITY" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY,            "FIXED-IDENTITY" },
	{ DECT_NWK_S_IE_LOCATION_AREA,             "LOCATION-AREA" },
	{ DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY,     "NWK-ASSIGNED-IDENTITY" },
	{ DECT_NWK_S_IE_AUTH_TYPE,                  "AUTH-TYPE" },
	{ DECT_NWK_S_IE_ALLOCATION_TYPE,            "ALLOCATION-TYPE" },
	{ DECT_NWK_S_IE_RAND,                       "RAND" },
	{ DECT_NWK_S_IE_RES,                        "RES" },
	{ DECT_NWK_S_IE_RS,                         "RS" },
	{ DECT_NWK_S_IE_IWU_ATTRIBUTES,             "IWU-ATTRIBUTES" },
	{ DECT_NWK_S_IE_CALL_ATTRIBUES,             "CALL-ATTRIBUTES" },
	{ DECT_NWK_S_IE_SERVICE_CHANGE_INFO,        "SERVICE-CHANGE-INFO" },
	{ DECT_NWK_S_IE_CONNECTION_ATTRIBUTES,      "CONNECTION-ATTRIBUTES" },
	{ DECT_NWK_S_IE_CIPHER_INFO,                "CIPHER-INFO" },
	{ DECT_NWK_S_IE_CALL_IDENTITY,              "CALL-IDENTITY" },
	{ DECT_NWK_S_IE_CONNECTION_IDENTITY,        "CONNECTION-IDENTITY" },
	{ DECT_NWK_S_IE_FACILITY,                   "FACILITY" },
	{ DECT_NWK_S_IE_PROGRESS_INDICATOR,         "PROGRESS-INDICATOR" },
	{ DECT_NWK_S_IE_MMS_GENERIC_HEADER,         "MMS-GENERIC-HEADER" },
	{ DECT_NWK_S_IE_MMS_OBJECT_HEADER,          "MMS-OBJECT-HEADER" },
	{ DECT_NWK_S_IE_MMS_EXTENDED_HEADER,        "MMS-EXTENDED-HEADER" },
	{ DECT_NWK_S_IE_TIME_DATE,                  "TIME-DATE" },
	{ DECT_NWK_S_IE_MULTI_DISPLAY,              "MULTI-DISPLAY" },
	{ DECT_NWK_S_IE_MULTI_KEYPAD,               "MULTI-KEYPAD" },
	{ DECT_NWK_S_IE_FEATURE_ACTIVATE,           "FEATURE-ACTIVATE" },
	{ DECT_NWK_S_IE_FEATURE_INDICATE,           "FEATURE-INDICATE" },
	{ DECT_NWK_S_IE_NETWORK_PARAMETER,          "NETWORK-PARAMETER" },
	{ DECT_NWK_S_IE_EXT_HO_INDICATOR,           "EXT-HO-INDICATOR" },
	{ DECT_NWK_S_IE_ZAP_FIELD,                  "ZAP-FIELD" },
	{ DECT_NWK_S_IE_SERVICE_CLASS,              "SERVICE-CLASS" },
	{ DECT_NWK_S_IE_KEY,                        "KEY" },
	{ DECT_NWK_S_IE_REJECT_REASON,              "REJECT-REASON" },
	{ DECT_NWK_S_IE_SETUP_CAPABILITY,           "SETUP-CAPABILITY" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY,        "TERMINAL-CAPABILITY" },
	{ DECT_NWK_S_IE_END_TO_END_COMPATIBILITY,   "END-TO-END-COMPATIBILITY" },
	{ DECT_NWK_S_IE_RATE_PARAMETERS,            "RATE-PARAMETERS" },
	{ DECT_NWK_S_IE_TRANSIT_DELAY,              "TRANSIT-DELAY" },
	{ DECT_NWK_S_IE_WINDOW_SIZE,                "WINDOWS-SIZE" },
	{ DECT_NWK_S_IE_ULE_MAC_CONFIGURATION_INFO, "ULE-MAC-CONFIGURATION-INFO" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER,       "CALLING-PARTY-NUMBER" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NAME,         "CALLING-PARTY-NAME" },
	{ DECT_NWK_S_IE_CALLED_PARTY_NUMBER,        "CALLED-PARTY-NUMBER" },
	{ DECT_NWK_S_IE_CALLED_PARTY_SUBADDR,       "CALLED-PARTY-SUBADDR" },
	{ DECT_NWK_S_IE_DURATION,                   "DURATION" },
	{ DECT_NWK_S_IE_CALLED_PARTY_NAME,          "CALLED-PARTY-NAME" },
	{ DECT_NWK_S_IE_LIST_CHANGE_DETAILS,        "LIST-CHANGE-DETAILS" },
	{ DECT_NWK_S_IE_SEGMENTED_INFO,             "SEGMENTED_INFO" },
	{ DECT_NWK_S_IE_ALPHANUMERIC,               "ALPHANUMERIC" },
	{ DECT_NWK_S_IE_IWU_TO_IWU,                 "IWU-TO-IWU" },
	{ DECT_NWK_S_IE_MODEL_IDENTIFIER,           "MODEL-IDENTIFIER" },
	{ DECT_NWK_S_IE_IWU_PACKET,                 "IWU-PACKET" },
	{ DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY,      "ESCAPE-TO-PROPRIETARY" },
	{ DECT_NWK_S_IE_CODEC_LIST,                 "CODEC-LIST" },
	{ DECT_NWK_S_IE_EVENTS_NOTIFICATION,        "EVENTS-NOTIFICATION" },
	{ DECT_NWK_S_IE_CALL_INFORMATION,           "CALL-INFORMATION" },
	{ DECT_NWK_S_IE_ESCAPE_FOR_EXTENSION,       "ESCAPE-FOR-EXTENSION" },
};

/* Section 7.7.10 */
static const value_string dect_nwk_s_ie_cipher_info_algorithm_val[] = {
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC,         "DECT Standard Cipher algorithm #1 (DSC)" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC2,        "DECT Standard Cipher algorithm #2 (DSC2)" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_NO,     "GPRS ciphering not used" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA1,   "GPRS encryption algorithm GEA/1" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA2,   "GPRS encryption algorithm GEA/2" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA3,   "GPRS encryption algorithm GEA/3" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA4,   "GPRS encryption algorithm GEA/4" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA5,   "GPRS encryption algorithm GEA/5" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA6,   "GPRS encryption algorithm GEA/6" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA7,   "GPRS encryption algorithm GEA/7" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY, "Escape to proprietary algorithm identifier" },
};

static const value_string dect_nwk_s_ie_cipher_info_key_type_val[] = {
	{ DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_DERIVED, "Derived cipher key" },
	{ DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_STATIC,  "Static cipher key" },
};

/* Section 7.7.18 */
static const value_string dect_nwk_s_ie_fixed_identity_type_val[] = {
	{ DECT_NWK_S_IE_FIXED_IDENTITY_ARI,              "Access rights identity (ARI)" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN,     "Access rights identity plus radio fixed part number (ARI + RPN)" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN_WRS, "Access rights identity plus radio fixed part number for WRS (ARI + RPN for WRS)" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY_PARK,             "Portable access rights key (PARK)" },
};

static const value_string dect_nwk_arc_type_val[] = {
	{ DECT_NWK_ARC_TYPE_A, "A (small residential 1..7 RFPs" },
	{ DECT_NWK_ARC_TYPE_B, "B (LAN and multi-cell)" },
	{ DECT_NWK_ARC_TYPE_C, "C (public access)" },
	{ DECT_NWK_ARC_TYPE_D, "D (public with GSM/UMTS)" },
	{ DECT_NWK_ARC_TYPE_E, "E (PP-to-PP)"},
};

/* Section 7.7.28 */
static const value_string dect_nwk_s_ie_nwk_assigned_identity_type_val[] = {
	{ DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_TMSI,        "Temporary Mobile Subscriber Identity (TMSI, P-TMSI)" },
	{ DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_PROPRIETARY, "Proprietary (application specific)" },
};

/* Section 7.7.30 */
static const value_string dect_nwk_s_ie_portable_identity_type_val[] = {
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI, "International Portable User Identity (IPUI)" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_IPEI, "International Portable Equipment Identity (IPEI)" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI, "Temporary Portable User Identity (TPUI)" },
	{ 0, NULL }
};

/* Section 6.2 in ETSI EN 300 175-6 */
static const value_string dect_nwk_ipui_type_val[] = {
	{ DECT_NWK_IPUI_TYPE_N, "N (residential/default)" },
	{ DECT_NWK_IPUI_TYPE_O, "O (private)" },
	{ DECT_NWK_IPUI_TYPE_P, "P (public/public access service)" },
	{ DECT_NWK_IPUI_TYPE_Q, "Q (public/general)" },
	{ DECT_NWK_IPUI_TYPE_R, "R (public/IMSI)" },
	{ DECT_NWK_IPUI_TYPE_S, "S (PSTN/ISDN)" },
	{ DECT_NWK_IPUI_TYPE_T, "T (private extended)" },
	{ DECT_NWK_IPUI_TYPE_U, "U (public/general)" }
};

/* Section 7.7.45 */
static const value_string dect_nwk_s_ie_escape_to_proprietary_discriminator_type_val[] = {
	{ DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_UNSPECIFIED, "Unspecified" },
	{ DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_EMC,         "EMC" },
};

/* TOOD: value_string for other protocols */

#define DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_MASK 0x7F

#define DECT_NWK_S_IE_FIXED_LENGTH_MASK  0x80
#define DECT_NWK_S_IE_FIXED_LENGTH_SHIFT 7

#define DECT_NWK_S_IE_FL_TYPE_MASK 0x70
#define DECT_NWK_S_IE_FL_TYPE_SHIFT 4

#define DECT_NWK_S_IE_PORTABLE_IDENTITY_TYPE_MASK 0x7F
#define DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_MASK 0xF0
#define DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_SHIFT 4

#define DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_MASK 0x7F

/*********************************************************************************
 * DECT dissector code
 *********************************************************************************/

static int dissect_dect_nwk_s_ie_cipher_info(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	guint8 algorithm;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_yn, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_algorithm, tvb, offset, 1, ENC_NA);
	algorithm = tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_MASK;
	offset++;
	if (algorithm == DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_proprietary_algorithm, tvb, offset, 1, ENC_NA);
		offset++;
	}
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_key_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_key_number, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

static int dissect_dect_nwk_s_ie_fixed_identity(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	guint8 value_length;
	guint bit_offset, no_of_bits;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_fixed_identity_type, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_fixed_identity_value_length, tvb, offset, 1, ENC_NA);
	value_length = tvb_get_guint8(tvb, offset) & 0x7F;
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_fixed_identity_arc, tvb, offset, 1, ENC_NA);
	bit_offset = ( offset * 8 ) + 4;
	no_of_bits = value_length - 4;
	proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_fixed_identity_ard, tvb, bit_offset, no_of_bits, ENC_NA);
	bit_offset += no_of_bits;
	offset += value_length / 8;
	if (value_length % 8) {
		no_of_bits = 8 - (value_length % 8);
		proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_fixed_identity_padding, tvb, bit_offset, no_of_bits, ENC_NA);
		offset++;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_nwk_assigned_identity(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	guint8 value_length;
	guint bit_offset, no_of_bits;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_type, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_value_length, tvb, offset, 1, ENC_NA);
	value_length = tvb_get_guint8(tvb, offset) & 0x7F;
	offset++;
	bit_offset = offset * 8;
	proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_value, tvb, bit_offset, value_length, ENC_NA);
	bit_offset += value_length;
	offset += value_length / 8;
	if (value_length % 8) {
		no_of_bits = 8 - (value_length % 8);
		proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_padding, tvb, bit_offset, no_of_bits, ENC_NA);
		offset++;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_portable_identity(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	guint8 value_length, identity_type, ipui_type;
	guint bit_offset, no_of_bits;
	identity_type = tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_PORTABLE_IDENTITY_TYPE_MASK;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_type, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_value_length, tvb, offset, 1, ENC_NA);
	value_length = tvb_get_guint8(tvb, offset) & 0x7F;
	offset++;
	bit_offset = ( offset * 8 ) + 4;
	switch(identity_type) {
		case DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI:
			ipui_type = ( tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_MASK ) >> DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_SHIFT;
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_put, tvb, offset, 1, ENC_NA);
			no_of_bits = value_length - 4;
			switch(ipui_type) {
				case DECT_NWK_IPUI_TYPE_N:
					/* FIXME implement this*/
					break;
				case DECT_NWK_IPUI_TYPE_O:
					proto_tree_add_bits_item(tree, hf_dect_ipui_o_number, tvb, bit_offset, no_of_bits, ENC_NA);
					break;
				case DECT_NWK_IPUI_TYPE_P:
					/* FIXME IPUI Type P */
				case DECT_NWK_IPUI_TYPE_Q:
					/* FIXME IPUI Type Q */
				case DECT_NWK_IPUI_TYPE_R:
					/* FIXME IPUI Type R */
				case DECT_NWK_IPUI_TYPE_S:
					/* FIXME IPUI Type S */
				case DECT_NWK_IPUI_TYPE_T:
					/* FIXME IPUI Type T */
				case DECT_NWK_IPUI_TYPE_U:
					/* FIXME IPUI Type U */
					break;
			}

			bit_offset += no_of_bits;
			offset += value_length / 8;
			if (value_length % 8) {
				no_of_bits = 8 - (value_length % 8);
				proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_fixed_identity_padding, tvb, bit_offset, no_of_bits, ENC_NA);
				offset++;
			}
			break;
		case DECT_NWK_S_IE_PORTABLE_IDENTITY_IPEI:
			no_of_bits = value_length - 4;
			offset += 5;
			/* FIXME IPEI decoding */
			break;
		case DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI:
			no_of_bits = value_length;
			offset += 3;
			/* FIXME TPUI decoding */
			break;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_escape_to_proprietary(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	guint8 discriminator_type;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_escape_to_proprietary_discriminator_type, tvb, offset, 1, ENC_NA);
	discriminator_type = tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_MASK;
	offset++;
	if (discriminator_type == DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_EMC) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_escape_to_proprietary_discriminator, tvb, offset, 2, ENC_NA);
		offset+=2;
	}
	/* FIXME: Content Handling */
	return offset;
}

static int dissect_dect_nwk_lce(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	gboolean fixed_length;
	guint8 element_type, element_length, fl_ie_type;
	proto_tree *field_tree;
	proto_tree *field_tree_item;

	proto_tree_add_item(tree, hf_nwk_msg_type_lce, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_lce_msgt_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		fixed_length = (tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_FIXED_LENGTH_MASK) >> DECT_NWK_S_IE_FIXED_LENGTH_SHIFT;
		if(fixed_length) {
			/* FIXME: Fixed Lenght IE dissection */
			fl_ie_type = ( tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_FL_TYPE_MASK ) >> DECT_NWK_S_IE_FL_TYPE_SHIFT;
			offset++;
			if ( fl_ie_type == DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT ) {
				offset++;
			}
		} else {
			element_type = ( tvb_get_guint8(tvb, offset) & 0x7F);
			element_length = tvb_get_guint8(tvb, offset + 1);
			field_tree = proto_tree_add_subtree(tree, tvb, offset, element_length + 2, ett_dect_nwk_s_ie_element, &field_tree_item, "Element: ");
			proto_item_append_text(field_tree_item, "%s", val_to_str(element_type, dect_nwk_s_ie_type_val, "Unkown: 0x%0x"));
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_type, tvb, offset, 1, ENC_NA);
			offset++;
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_length, tvb, offset, 1, ENC_NA);
			offset++;
			switch (element_type) {
				case DECT_NWK_S_IE_CIPHER_INFO:
					offset = dissect_dect_nwk_s_ie_cipher_info(tvb, offset, field_tree, data);
					break;
				case DECT_NWK_S_IE_FIXED_IDENTITY:
					offset = dissect_dect_nwk_s_ie_fixed_identity(tvb, offset, field_tree, data);
					break;
				case DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY:
					offset = dissect_dect_nwk_s_ie_nwk_assigned_identity(tvb, offset, field_tree, data);
					break;
				case DECT_NWK_S_IE_PORTABLE_IDENTITY:
					offset = dissect_dect_nwk_s_ie_portable_identity(tvb, offset, field_tree, data);
					break;
				case DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY:
					dissect_dect_nwk_s_ie_escape_to_proprietary(tvb, offset, field_tree, data);
					offset += element_length;
					break;
				default:
					offset += element_length;
					break;
			}
		}
	}

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}

static int dissect_dect_nwk_cc(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_cc, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_cc_msgt_vals, "Unknown 0x%02x"));
	offset++;

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}

static int dissect_dect_nwk_mm(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_mm, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_mm_msgt_vals, "Unknown 0x%02x"));
	offset++;

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}


static int dissect_dect_nwk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *nwk_tree;
	proto_item *nwk_ti;
	guint8 pdisc, msg_type;
	guint len;
	guint offset = 0;
	int available_length;

	len = tvb_reported_length(tvb);

	col_append_str(pinfo->cinfo, COL_INFO, "(NWK) ");

	nwk_ti = proto_tree_add_item(tree, proto_dect_nwk, tvb, 0, len, ENC_NA);
	nwk_tree = proto_item_add_subtree(nwk_ti, ett_dect_nwk);

	proto_tree_add_item(nwk_tree, hf_nwk_ti, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(nwk_tree, hf_nwk_pdisc, tvb, 0, 1, ENC_NA);
	pdisc = tvb_get_guint8(tvb, 0) & 0x0F;
	msg_type = tvb_get_guint8(tvb, 1);

	switch (pdisc) {
	case DECT_NWK_PDISC_LCE:
		offset = dissect_dect_nwk_lce(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CC:
		offset = dissect_dect_nwk_cc(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_MM:
		offset = dissect_dect_nwk_mm(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CISS:
	case DECT_NWK_PDISC_CMSS:
	case DECT_NWK_PDISC_COMS:
		/* FIXME */
	default:
		break;
	}

	/* whatever was not dissected: Use generic data dissector */
	available_length = tvb_captured_length(tvb) - offset;
	if (available_length) {
		tvbuff_t *payload = tvb_new_subset_length_caplen(tvb, offset, MIN(len-offset, available_length), len);
		call_data_dissector(payload, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

void proto_register_dect_nwk(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_nwk_ti,
			{ "Transaction Identifier", "dect_nwk.ti", FT_UINT8, BASE_HEX,
				 NULL, 0xF0, NULL, HFILL
			}
		},
		{ &hf_nwk_pdisc,
			{ "Proticol Discriminator", "dect_nwk.pdisc", FT_UINT8, BASE_HEX,
				VALS(nwk_pdisc_vals), 0x0F, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_cc,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_cc_msgt_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_mm,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_mm_msgt_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_lce,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_lce_msgt_vals), 0x0, NULL, HFILL
			}
		},


		/* S Type common */
		{ &hf_dect_nwk_s_ie_fl,
			{ "Fixed Length", "dect_nwk.s.fixed_length", FT_BOOLEAN, 8,
				NULL, 0x80, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_type,
			{ "Message Type", "dect_nwk.s.ie.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_length,
			{ "Content Length", "dect_nwk.s.ie.length", FT_UINT8, BASE_DEC,
				NULL, 0xFF, "Length indicator", HFILL
			}
		},
		/* Cipher info */
		{ &hf_dect_nwk_s_ie_cipher_info_yn,
			{ "Y/N", "dect_nwk.s.ie.cipher_info.yn", FT_BOOLEAN, BASE_NONE, NULL, 0x80, NULL, HFILL}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_algorithm,
			{ "Algorithm", "dect_nwk.s.ie.cipher_info.algorithm", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_cipher_info_algorithm_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_proprietary_algorithm,
			{ "Proprietary algorithm", "dect_nwk.s.ie.cipher_info.proprietary_algorithm", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_key_type,
			{ "Key Type", "dect_nwk.s.ie.cipher_info.key_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_cipher_info_key_type_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_key_number,
			{ "Key Number", "dect_nwk.s.ie.cipher_info.key_number", FT_UINT8, BASE_HEX,
				NULL, 0x0F, NULL, HFILL
			}
		},
		/* Fixed Identity */
		{ &hf_dect_nwk_s_ie_fixed_identity_type,
			{ "Type", "dect_nwk.s.ie.fixed_identity.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fixed_identity_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_value_length,
			{ "Value Length", "dect_nwk.s.ie.fixed_identity.value_length", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_arc,
			{ "ARC", "dect_nwk.s.ie.fixed_identity.arc", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_arc_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_ard,
			{ "ARD", "dect_nwk.s.ie.fixed_identity.ard", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_padding,
			{ "Padding", "dect_nwk.s.ie.fixed_identity.padding", FT_NONE, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* NWK assigend Identity */
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_type,
			{ "Type", "dect_nwk.s.ie.nwk_assigned_identity.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_nwk_assigned_identity_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_value_length,
			{ "Value Length", "dect_nwk.s.ie.nwk_assigned_identity.value_length", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_value,
			{ "Value", "dect_nwk.s.ie.nwk_assigned_identity.value", FT_UINT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_padding,
			{ "Padding", "dect_nwk.s.ie.nwk_assigned_identity.padding", FT_NONE, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Portable Identity */
		{ &hf_dect_nwk_s_ie_portable_identity_type,
			{ "Type", "dect_nwk.s.ie.portable_identity.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_portable_identity_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_portable_identity_value_length,
			{ "Value Length", "dect_nwk.s.ie.portable_identity.value_length", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_portable_identity_put,
			{ "PUT", "dect_nwk.s.ie.portable_identity.ipui.put", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_ipui_type_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_ipui_o_number,
			{ "Number", "dect_nwk.s.ie.portable_identity.ipui.number", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_padding,
			{ "Padding", "dect_nwk.s.ie.portable_identity.padding", FT_NONE, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Escape to proprietary */
		{ &hf_dect_nwk_s_ie_escape_to_proprietary_discriminator_type,
			{ "Discriminator type", "dect_nwk.s.ie.escape_to_proprietary.discriminator_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_escape_to_proprietary_discriminator_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_escape_to_proprietary_discriminator,
			{ "Discriminator", "dect_nwk.s.ie.escape_to_proprietary.discriminator", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
	};

	static gint *ett[] = {
		&ett_dect_nwk,
		&ett_dect_nwk_s_ie_element,
	};

	/* Register protocol */
	proto_dect_nwk = proto_register_protocol("DECT NWK", "DECT-NWK", "dect_nwk");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_nwk, hf, array_length(hf));

	dect_nwk_handle = register_dissector("dect_nwk", dissect_dect_nwk, proto_dect_nwk);
}

void proto_reg_handoff_dect_nwk(void)
{
	dissector_add_uint("dect_dlc.sapi", 0, dect_nwk_handle);
	dissector_add_uint("dect_dlc.sapi", 3, dect_nwk_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
