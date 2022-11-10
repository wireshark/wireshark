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
#include <epan/tfs.h>
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

static gint hf_dect_nwk_s_ie_fl_type = -1;
static gint hf_dect_nwk_s_ie_fl_double_octet_type = -1;

static gint hf_dect_nwk_s_ie_fl_control_type = -1;

static gint hf_dect_nwk_s_ie_fl_repeat_indicator_type = -1;

static gint hf_dect_nwk_s_ie_fl_shift_locking = -1;
static gint hf_dect_nwk_s_ie_fl_shift_new_codeset = -1;

static gint hf_dect_nwk_s_ie_fl_basic_service_call_class = -1;
static gint hf_dect_nwk_s_ie_fl_basic_service_type = -1;

static gint hf_dect_nwk_s_ie_fl_single_display_display_info = -1;

static gint hf_dect_nwk_s_ie_fl_single_keypad_keypad_info = -1;

static gint hf_dect_nwk_s_ie_fl_release_reason_code = -1;

static gint hf_dect_nwk_s_ie_fl_signal_value = -1;

static gint hf_dect_nwk_s_ie_fl_timer_restart_value = -1;

static gint hf_dect_nwk_s_ie_fl_test_hook_control_hook_value = -1;

static gint hf_dect_nwk_s_ie_type = -1;
static gint hf_dect_nwk_s_ie_length = -1;

static gint hf_dect_nwk_s_ie_octet_group_extension = -1;

static gint hf_dect_nwk_s_ie_auth_type_authentication_algorithm = -1;
static gint hf_dect_nwk_s_ie_auth_type_proprietary_algorithm = -1;
static gint hf_dect_nwk_s_ie_auth_type_ak_type = -1;
static gint hf_dect_nwk_s_ie_auth_type_ak_number = -1;
static gint hf_dect_nwk_s_ie_auth_type_inc = -1;
static gint hf_dect_nwk_s_ie_auth_type_def = -1;
static gint hf_dect_nwk_s_ie_auth_type_txc = -1;
static gint hf_dect_nwk_s_ie_auth_type_upc = -1;
static gint hf_dect_nwk_s_ie_auth_type_cipher_key_number = -1;
static gint hf_dect_nwk_s_ie_auth_type_cipher_key_number_related = -1;
static gint hf_dect_nwk_s_ie_auth_type_default_cipher_key_index = -1;
static gint hf_dect_nwk_s_ie_auth_type_default_cipher_key_algorithm = -1;

static gint hf_dect_nwk_s_ie_calling_party_number_type = -1;
static gint hf_dect_nwk_s_ie_calling_party_number_numbering_plan = -1;
static gint hf_dect_nwk_s_ie_calling_party_number_presentation = -1;
static gint hf_dect_nwk_s_ie_calling_party_number_screening = -1;
static gint hf_dect_nwk_s_ie_calling_party_number_address = -1;

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

static gint hf_dect_nwk_s_ie_rand_rand_field = -1;

static gint hf_dect_nwk_s_ie_res_res_field = -1;

static gint hf_dect_nwk_s_ie_rs_rs_field = -1;

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

/* Section 7.5.3 */
enum dect_nwk_s_fl_ie_shift_codeset {
	DECT_NWK_S_FL_IE_SHIFT_CODESET_INITIAL        = 0x0,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_0 = 0x4,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_1 = 0x5,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_2 = 0x6,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_3 = 0x7,
};

/* Section 7.6.1 */
enum dect_nwk_s_fl_ie_type {
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
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_BASIC_SERVICE     = 0x0,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_RELEASE_REASON    = 0x2,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_SIGNAL            = 0x4,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_TIMER_RESTART     = 0x5,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_TEST_HOOK_CONTROL = 0x6,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_DISPLAY    = 0x8,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_KEYPAD     = 0x9,
};

/* Section 7.6.3 */
enum dect_nwk_s_ie_fl_repeat_indicator_type {
	DECT_NWK_S_IE_FL_REPEAT_INDICATOR_NON_PRIORITIZED = 0x1,
	DECT_NWK_S_IE_FL_REPEAT_INDICATOR_PRIORITIZED     = 0x2,
};

/* Section 7.6.4 */
enum dect_nwk_s_ie_fl_basic_service_call_class {
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_LIA                   = 0x2,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_ULE                   = 0x3,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_MESSAGE               = 0x4,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_DECT_ISDN_IIP         = 0x7,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_NORMAL                = 0x8,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_INTERNAL              = 0x9,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EMERGENCY             = 0xA,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SERVICE               = 0xB,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EXTERNAL_HANDOVER     = 0xC,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SUPPLEMENTARY_SERVICE = 0xD,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_OA_M                  = 0xE,
};

enum dect_nwk_s_ie_fl_basic_service_type {
	DECT_NWK_S_IE_FL_BASIC_SERVICE_BASIC_SPEECH              = 0x0,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_GSM_IWP              = 0x4,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_LRMS                      = 0x5,
	/* Specification assigns 0b0110 to DECT UMTS IWP and GSM IWP SMS*/
	DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_UMTS_IWP_GSM_IWP_SMS = 0x6,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_WIDEBAND_SPEECH           = 0x8,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_4_DPRS        = 0x9,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_3_DPRS        = 0xA,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_DTAM_WIDEBAND_SPEECH      = 0xB,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_OTHER                     = 0xF,
};

/* Section 7.6.7 */
enum dect_nwk_s_ie_fl_release_reason {
	DECT_NWK_S_IE_FL_RELEASE_REASON_NORMAL                                = 0x00,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNEXPECTED_MESSAGE                    = 0x01,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_TRANSACTION_IDENTIFIER        = 0x02,
	DECT_NWK_S_IE_FL_RELEASE_REASON_MANDATORY_INFORMATION_ELEMENT_MISSING = 0x03,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_INFORMATION_ELEMENT_CONTENTS  = 0x04,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INCOMPATIBLE_SERVICE                  = 0x05,
	DECT_NWK_S_IE_FL_RELEASE_REASON_SERVICE_NOT_IMPLEMENTED               = 0x06,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_NOT_SUPPORTED             = 0x07,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_ENTITY                        = 0x08,
	DECT_NWK_S_IE_FL_RELEASE_REASON_AUTHENTICATION_FAILED                 = 0x09,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_IDENTITY                      = 0x0A,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_FAILED                    = 0x0B,
	DECT_NWK_S_IE_FL_RELEASE_REASON_COLLISION                             = 0x0C,
	DECT_NWK_S_IE_FL_RELEASE_REASON_TIMER_EXPIRY                          = 0x0D,
	DECT_NWK_S_IE_FL_RELEASE_REASON_PARTIAL_RELEASE                       = 0x0E,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN                               = 0x0F,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_DETACHED                         = 0x10,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_NOT_IN_RANGE                     = 0x11,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_UNKNOWN                          = 0x12,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_ALREADY_ACTIVE                   = 0x13,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_BUSY                             = 0x14,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_REJECTION                        = 0x15,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_CALL_MODIFY                      = 0x16,
	DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_NOT_SUPPORTED       = 0x21,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NETWORK_PARAMETERS_MISSING            = 0x22,
	DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_RELEASE             = 0x23,
	DECT_NWK_S_IE_FL_RELEASE_REASON_OVERLOAD                              = 0x31,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_RESOURCES                = 0x32,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_BEARERS_AVAILABLE        = 0x33,
	DECT_NWK_S_IE_FL_RELEASE_REASON_IWU_CONGESTION                        = 0x34,
	DECT_NWK_S_IE_FL_RELEASE_REASON_SECURITY_ATTACK_ASSUMED               = 0x40,
	DECT_NWK_S_IE_FL_RELEASE_REASON_ENCRYPTION_ACTIVATION_FAILED          = 0x41,
	DECT_NWK_S_IE_FL_RELEASE_REASON_RE_KEYING_FAILED                      = 0x42,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NO_CIPHER_KEY_AVAILABLE               = 0x43,
};

/* Section 7.6.8 */
enum dect_nwk_s_ie_fl_signal_value {
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_DIAL_TONE_ON = 0x00,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_RINGBACK_TONE_ON = 0x01,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_INTERCEPT_TONE_ON = 0x02,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_NETWORK_CONGESTION_TONE_ON = 0x03,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_BUSY_TONE_ON               = 0x04,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_CONFIRM_TONE_ON            = 0x05,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ANSWER_TONE_ON             = 0x06,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_CALL_WAITING_TONE_ON       = 0x07,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_OFF_HOOK_WARNING_TONE_ON   = 0x08,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_NEGATIVE_ACK_TONE          = 0x09,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_TONES_OFF                  = 0x3F,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_0      = 0x40,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_1      = 0x41,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_2      = 0x42,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_3      = 0x43,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_4      = 0x44,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_5      = 0x45,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_6      = 0x46,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_7      = 0x47,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_CONTINUOUS     = 0x48,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_OFF               = 0x4F,
};

/* Section 7.6.9 */
enum dect_nwk_s_ie_fl_timer_restart_value {
	DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_RESTART_TIMER = 0x00,
	DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_STOP_TIMER = 0x01,
};

/* Section 7.6.10 */
enum dect_nwk_s_ie_fl_test_hook_control_hook_value {
	DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_ON_HOOK  = 0x00,
	DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_OFF_HOOK = 0x01,
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

/* Section 7.7.4 */
enum dect_nwk_s_ie_auth_type_authentication_algorithm {
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA        = 0x01,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA2       = 0x02,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_UMTS        = 0x20,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_GSM         = 0x40,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_PROPRIETARY = 0x7F,
};

enum dect_nwk_s_ie_auth_type_ak_type {
	DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_AK             = 0x1,
	DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_PERSONAL_ID    = 0x3,
	DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_AUTHENTICATION_CODE = 0x4,
};

enum dect_nwk_s_ie_auth_type_default_cipher_key_algorithm {
	DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC =  0x0,
	DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC2 = 0x1,
};

/* Section 7.7.9 */
enum dect_nwk_s_ie_calling_party_number_type {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_UNKNOWN          = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_INTERNATIONAL    = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NATIONAL         = 0x2,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NETWORK_SPECIFIC = 0x3,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_SUBSCRIBER       = 0x4,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_ABBREVIATED      = 0x6,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_RESERVED         = 0x7,
};

enum dect_nwk_s_ie_calling_party_number_numbering_plan {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_UNKNOWN  = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_ISDN     = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_DATA     = 0x3,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_TCP_IP   = 0x7,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_NATIONAL = 0x8,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PRIVATE  = 0x9,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_SIP      = 0xA,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_INTERNET = 0xB,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_LAN_MAC  = 0xC,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_X400     = 0xD,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PROFILE  = 0xE,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_RESERVED = 0xF,
};

enum dect_nwk_s_ie_calling_party_number_presentation {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_ALLOWED              = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESTRICTED           = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NUMBER_NOT_AVAILABLE = 0x2,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESERVED             = 0x3,
};

enum dect_nwk_s_ie_calling_party_number_screening {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_NOT_SCREENED    = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_PASSED = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_FAILED = 0x2,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NETWORK              = 0x3,
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
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY = 0x7F,
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
	{ DECT_NWK_MM_AUTH_REQ,            "MM-AUTH-REQ" },
	{ DECT_NWK_MM_AUTH_REPLY,          "MM-AUTH-REPLY" },
	{ DECT_NWK_MM_KEY_ALLOC,           "MM-KEY-ALLOCATE" },
	{ DECT_NWK_MM_AUTH_REJ,            "MM-AUTH-REJECT" },
	{ DECT_NWK_MM_ACC_RIGHTS_REQ,      "MM-ACCESS-RIGHTS-REQUEST" },
	{ DECT_NWK_MM_ACC_RIGHTS_ACK,      "MM-ACCESS-RIGHTS-ACCEPT" },
	{ DECT_NWK_MM_ACC_RIGHTS_REJ,      "MM-ACCESS-RIGHTS-REJECT" },
	{ DECT_NWK_MM_ACC_RIGHTS_TERM_REQ, "MM-ACCESS-RIGHTS-TERMINATE-REQUEST" },
	{ DECT_NWK_MM_ACC_RIGHTS_ACK,      "MM-ACCESS-RIGHTS-TERMINATE-ACCEPT" },
	{ DECT_NWK_MM_ACC_RIGHTS_TERM_REJ, "MM-ACCESS-RIGHTS-TERMINATE-REJECT" },
	{ DECT_NWK_MM_CIPH_REQ,            "MM-CIPHER-REQUEST" },
	{ DECT_NWK_MM_CIPH_SUGGEST,        "MM-CIPHER-SUGGEST" },
	{ DECT_NWK_MM_CIPH_REJ,            "MM-CIPHER-REJECT" },
	{ DECT_NWK_MM_INFO_REQ,            "MM-INFO-REQUEST" },
	{ DECT_NWK_MM_INFO_ACK,            "MM-INFO-ACCEPT" },
	{ DECT_NWK_MM_INFO_SUGGEST,        "MM-INFO-SUGGEST" },
	{ DECT_NWK_MM_INFO_REJ,            "MM-INFO-REJECT" },
	{ DECT_NWK_MM_LOCATE_REQ,          "MM-LOCATE-REQUEST" },
	{ DECT_NWK_MM_LOCATE_ACK,          "MM-LOCATE-ACCEPT" },
	{ DECT_NWK_MM_DETACH,              "MM-DETACH" },
	{ DECT_NWK_MM_LOCATE_REJ,          "MM-LOCATE-REJECT" },
	{ DECT_NWK_MM_ID_REQ,              "MM-IDENTITY-REQUEST" },
	{ DECT_NWK_MM_ID_REPLY,            "MM-IDENTITY-REPLY" },
	{ DECT_NWK_MM_IWU,                 "MM-IWU" },
	{ DECT_NWK_MM_TID_ASSIGN,          "MM-TEMPORARY-IDENTITY-ASSIGN" },
	{ DECT_NWK_MM_TID_ASSIGN_ACK,      "MM-TEMPORARY-IDENTITY-ASSIGN-ACK" },
	{ DECT_NWK_MM_TID_ASSIGN_REJ,      "MM-TEMPORARY-IDENTITY-ASSIGN-REJ" },
	{ DECT_NWK_MM_NOTIFY,              "MM-NOTIFY" },
	{ 0, NULL }
};

/* Section 7.4.6 */
static const value_string nwk_lce_msgt_vals[] = {
	{ DECT_NWK_LCE_PAGE_RESP,	"LCE-PAGE-RESPONSE" },
	{ DECT_NWK_LCE_PAGE_REJ, 	"LCE-PAGE-REJECT" },
	{ 0, NULL }
};

/* Section 7.5.3 */
static const true_false_string dect_nwk_s_ie_fl_shift_locking_tfs = {
	"non-locking",
	"locking"
};

static const value_string dect_nwk_s_ie_fl_shift_codeset_val[] = {
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_INITIAL, "Initial codeset" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_0, "Non-Standard codeset 0" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_1, "Non-Standard codeset 1" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_2, "Non-Standard codeset 2" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_3, "Non-Standard codeset 3" },
};

/* Section 7.6.1 */
static const value_string dect_nwk_s_ie_fl_type_val[] = {
	{ DECT_NWK_S_IE_FL_SHIFT,                "SHIFT" },
	{ DECT_NWK_S_IE_FL_CONTROL,              "CONTROL" },
	{ DECT_NWK_S_IE_FL_REPEAT_INDICATOR,     "REPEAT-INDICATOR" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT, "DOUBLE-OCTET-ELEMENT" },
};

static const value_string dect_nwk_s_ie_fl_control_type_val[] = {
	{ DECT_NWK_S_IE_FL_CONTROL_SENDING_COMPLETE,  "SENDING-COMPLETE" },
	{ DECT_NWK_S_IE_FL_CONTROL_DELIMITER_REQUEST, "DELIMITER-REQUEST" },
	{ DECT_NWK_S_IE_FL_CONTROL_USE_TPUI,          "USE-TPUI" },
};

static const value_string dect_nwk_s_ie_fl_double_octet_type_val[] = {
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_BASIC_SERVICE,     "BASIC-SERVICE" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_RELEASE_REASON,    "RELEASE-REASON" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_SIGNAL,            "SIGNAL" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_TIMER_RESTART,     "TIMER-RESTART" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_TEST_HOOK_CONTROL, "TEST-HOOK-CONTROL" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_DISPLAY,    "SINGLE-DISPLAY" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_KEYPAD,     "SINGLE-KEYPAD" },
};

/* Section 7.6.3 */
static const value_string dect_nwk_s_ie_fl_repeat_indicator_type_val[] = {
	{ DECT_NWK_S_IE_FL_REPEAT_INDICATOR_NON_PRIORITIZED, "Non prioritized list" },
	{ DECT_NWK_S_IE_FL_REPEAT_INDICATOR_PRIORITIZED,     "Prioritized list" },
};

/* Section 7.6.4 */
static const value_string dect_nwk_s_ie_fl_basic_service_call_class_val[] = {
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_LIA,                   "Basic speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_ULE,                   "ULE service call setup"},
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_MESSAGE,               "Message call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_DECT_ISDN_IIP,         "DECT/ISDN IIP" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_NORMAL,                "Normal call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_INTERNAL,              "Internal call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EMERGENCY,             "Emergency call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SERVICE,               "Service call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EXTERNAL_HANDOVER,     "External handover call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SUPPLEMENTARY_SERVICE, "Supplementary service call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_OA_M,                  "OA&M call setup" },
};

static const value_string dect_nwk_s_ie_fl_basic_service_type_val[] = {
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_BASIC_SPEECH,              "Basic speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_GSM_IWP,              "DECT GSM IWP profile (Phase 2)" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_LRMS,                      "LRMS (E-profile) service" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_UMTS_IWP_GSM_IWP_SMS, "DECT UMTS IWP or GSM IWP SMS" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_WIDEBAND_SPEECH,           "Wideband speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_4_DPRS,        "Light data services: SUOTA, Class 4 DPRS management, default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_3_DPRS,        "Light data services: SUOTA, Class 3 DPRS management, default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_DTAM_WIDEBAND_SPEECH,      "DTAM Wideband speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_OTHER,                     "Other" },
};

/* Section 7.6.7 */
static const value_string dect_nwk_s_ie_fl_release_reason_val[] = {
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NORMAL,                                "Normal" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNEXPECTED_MESSAGE,                    "Unexpected Message" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_TRANSACTION_IDENTIFIER,        "Unknown Transaction Identifier" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_MANDATORY_INFORMATION_ELEMENT_MISSING, "Mandatory information element missing" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_INFORMATION_ELEMENT_CONTENTS,  "Invalid information element contents" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INCOMPATIBLE_SERVICE,                  "Incompatible service" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_SERVICE_NOT_IMPLEMENTED,               "Service not implemented" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_NOT_SUPPORTED,             "Negotiation not supported" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_ENTITY,                        "Invalid identity" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_AUTHENTICATION_FAILED,                 "Authentication failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_IDENTITY,                      "Unknown identity" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_FAILED,                    "Negotiation failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_COLLISION,                             "Collision" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_TIMER_EXPIRY,                          "Timer expiry" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_PARTIAL_RELEASE,                       "Partial release" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN,                               "Unknown" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_DETACHED,                         "User detached" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_NOT_IN_RANGE,                     "User not in range" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_UNKNOWN,                          "User unknown" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_ALREADY_ACTIVE,                   "User already active" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_BUSY,                             "User busy" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_REJECTION,                        "User rejection" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_CALL_MODIFY,                      "User call modify" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_NOT_SUPPORTED,       "External Handover not supported" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NETWORK_PARAMETERS_MISSING,            "Network Parameters missing" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_RELEASE,             "External Handover release" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_OVERLOAD,                              "Overload" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_RESOURCES,                "Insufficient resources" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_BEARERS_AVAILABLE,        "Insufficient bearers available" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_IWU_CONGESTION,                        "IWU congestion" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_SECURITY_ATTACK_ASSUMED,               "Security attack assumed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_ENCRYPTION_ACTIVATION_FAILED,          "Encryption activation failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_RE_KEYING_FAILED,                      "Re-Keying failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NO_CIPHER_KEY_AVAILABLE,               "No Cipher Key available" },
};

/* Section 7.6.8 */
static const value_string dect_nwk_s_ie_fl_signal_value_val[] = {
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_DIAL_TONE_ON,               "Dial tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_RINGBACK_TONE_ON,           "Ring-back tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_INTERCEPT_TONE_ON,          "Intercep tone on " },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_NETWORK_CONGESTION_TONE_ON, "Network congestion tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_BUSY_TONE_ON,               "Busy tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_CONFIRM_TONE_ON,            "Confirm tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ANSWER_TONE_ON,             "Answer tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_CALL_WAITING_TONE_ON,       "Call waiting tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_OFF_HOOK_WARNING_TONE_ON,   "Off-hook warning tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_NEGATIVE_ACK_TONE,          "Negative acknowledgement tone" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_TONES_OFF,                  "Tones off" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_0,      "Alerting on - pattern 0" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_1,      "Alerting on - pattern 1" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_2,      "Alerting on - pattern 2" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_3,      "Alerting on - pattern 3" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_4,      "Alerting on - pattern 4" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_5,      "Alerting on - pattern 5" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_6,      "Alerting on - pattern 6" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_7,      "Alerting on - pattern 7" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_CONTINUOUS,     "Alerting on - continuous" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_OFF,               "Alerting off" },
};

/* Section 7.6.9 */
static const value_string dect_nwk_s_ie_fl_timer_restart_value_val[] = {
	{ DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_RESTART_TIMER, "Restart timer" },
	{ DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_STOP_TIMER,    "Stop timer" },
};

/* Section 7.6.10 */
static const value_string dect_nwk_s_ie_fl_test_hook_control_hook_value_val[] = {
	{ DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_ON_HOOK,  "On-Hook" },
	{ DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_OFF_HOOK, "Off-Hook" },
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

/* Section 7.7.4 */
static const value_string dect_nwk_s_ie_auth_type_authentication_algorithm_val[] = {
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA,        "DECT standard authentication algorithm (DSAA)" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA2,       "DECT standard authentication algorithm #2 (DSAA2)" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_UMTS,        "GSM authentication algorithm" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_GSM,         "UMTS authentication algorithm" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_PROPRIETARY, "Escape to proprietary algorithm identifier" },
};

static const value_string dect_nwk_s_ie_auth_type_ak_type_val[] = {
	{ DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_AK,             "User authentication key" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_PERSONAL_ID,    "User personal identity" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_AUTHENTICATION_CODE, "Authentication code" },
};

static const value_string dect_nwk_s_ie_auth_type_default_cipher_key_algorithm_val[] = {
	{ DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC,  "DSC" },
	{ DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC2, "DSC2" },
};

static const true_false_string dect_nwk_s_ie_auth_type_cipher_key_number_related_tfs = {
	"IPUI/PARK pair",
	"IPUI"
};

/* Section 7.7.9 */
static const value_string dect_nwk_s_ie_calling_party_number_type_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_UNKNOWN,          "Unknown" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_INTERNATIONAL,    "International number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NATIONAL,         "National number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NETWORK_SPECIFIC, "Network specific number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_SUBSCRIBER,       "Subscriber number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_ABBREVIATED,      "Abbreviated number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_RESERVED,         "Reserved for extension" },
};

static const value_string dect_nwk_s_ie_calling_party_number_numbering_plan_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_UNKNOWN,  "Unknown" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_ISDN,     "ISDN/telephony plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_DATA,     "Data plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_TCP_IP,   "TCP/IP address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_NATIONAL, "National standard plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PRIVATE,  "Private plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_SIP,      "SIP addressing scheme, \"From:\" field" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_INTERNET, "Internet character format address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_LAN_MAC,  "LAN MAC address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_X400,     "Recommendation ITU-T X.400 address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PROFILE,  "Profile service specific alphanumeric identifier" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_RESERVED, "Reserved for extension" },
};

static const value_string dect_nwk_s_ie_calling_party_number_presentation_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_ALLOWED,              "Presentation allowed" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESTRICTED,           "Presentation restricted" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NUMBER_NOT_AVAILABLE, "Number not available" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESERVED,             "Reserved" },
};

static const value_string dect_nwk_s_ie_calling_party_number_screening_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_NOT_SCREENED,    "User-provided, not screened" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_PASSED, "User-provided, verified and passed" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_FAILED, "User-provided, verified and failed" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NETWORK,              "Network provided" },
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

static const true_false_string tfs_last_more = {
	"Last",
	"More"
};

/* TOOD: value_string for other protocols */

#define DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK 0x80
#define DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT 7

#define DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_MASK 0x7F

#define DECT_NWK_S_IE_FIXED_LENGTH_MASK  0x80
#define DECT_NWK_S_IE_FIXED_LENGTH_SHIFT 7

#define DECT_NWK_S_IE_FL_TYPE_MASK 0x70
#define DECT_NWK_S_IE_FL_TYPE_SHIFT 4
#define DECT_NWK_S_IE_FL_DOUBLE_OCTET_TYPE_MASK 0x0F

#define DECT_NWK_S_IE_AUTH_TYPE_DEF_MASK 0x40
#define DECT_NWK_S_IE_AUTH_TYPE_DEF_SHIFT 6

#define DECT_NWK_S_IE_PORTABLE_IDENTITY_TYPE_MASK 0x7F
#define DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_MASK 0xF0
#define DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_SHIFT 4

#define DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_MASK 0x7F

/*********************************************************************************
 * DECT dissector code
 *********************************************************************************/

static int dissect_dect_nwk_s_ie_auth_type(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	guint8 authentication_algorithm;
	gboolean def;

	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_authentication_algorithm, tvb, offset, 1, ENC_NA);
	authentication_algorithm = tvb_get_guint8(tvb, offset);
	offset++;
	if ( authentication_algorithm == DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_PROPRIETARY ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_proprietary_algorithm, tvb, offset, 1, ENC_NA);
		offset++;
	}
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_ak_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_ak_number, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_inc, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_def, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_txc, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_upc, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_cipher_key_number, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_cipher_key_number_related, tvb, offset, 1, ENC_NA);
	def = ( tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_AUTH_TYPE_DEF_MASK ) >> DECT_NWK_S_IE_AUTH_TYPE_DEF_SHIFT;
	offset++;
	if( def ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_default_cipher_key_index, tvb, offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_default_cipher_key_algorithm, tvb, offset, 2, ENC_NA);
		offset++;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_calling_party_number(tvbuff_t *tvb, guint offset, guint8 ie_length, proto_tree *tree, void _U_ *data)
{
	gboolean octet_group_extension;
	guint8 address_length;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_numbering_plan, tvb, offset, 1, ENC_NA);
	octet_group_extension = ( tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
	offset++;
	if ( !octet_group_extension ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_presentation, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_screening, tvb, offset, 1, ENC_NA);
		offset++;
		address_length = ie_length - 2;
	} else {
		address_length = ie_length - 1;
	}
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_address, tvb, offset, address_length, ENC_3GPP_TS_23_038_7BITS_UNPACKED);
	/* TODO: Check encoding of address field */
	return offset + address_length;
}

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

static int dissect_dect_nwk_s_ie(tvbuff_t *tvb, guint offset, proto_tree *tree, void _U_ *data)
{
	gboolean fixed_length;
	guint8 element_type, element_length, fl_ie_type, fl_ie_double_octet_type;
	proto_tree *field_tree;
	proto_tree *field_tree_item;

	fixed_length = (tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_FIXED_LENGTH_MASK) >> DECT_NWK_S_IE_FIXED_LENGTH_SHIFT;
	if(fixed_length) {
		fl_ie_type = ( tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_FL_TYPE_MASK ) >> DECT_NWK_S_IE_FL_TYPE_SHIFT;
		fl_ie_double_octet_type = ( tvb_get_guint8(tvb, offset) & DECT_NWK_S_IE_FL_DOUBLE_OCTET_TYPE_MASK );
		if ( fl_ie_type == DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT ) {
			element_length = 2;
			field_tree = proto_tree_add_subtree(tree, tvb, offset, element_length, ett_dect_nwk_s_ie_element, &field_tree_item, "Fixed length Element: ");
			proto_item_append_text(field_tree_item, "%s", val_to_str(fl_ie_double_octet_type, dect_nwk_s_ie_fl_double_octet_type_val, "Unkown: 0x%0x"));
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_type, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_double_octet_type, tvb, offset, 1, ENC_NA);
			offset++;
			switch (fl_ie_double_octet_type) {
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_BASIC_SERVICE:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_basic_service_call_class, tvb, offset, 1, ENC_NA);
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_basic_service_type, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_RELEASE_REASON:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_release_reason_code, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_SIGNAL:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_signal_value, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_TIMER_RESTART:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_timer_restart_value, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_TEST_HOOK_CONTROL:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_test_hook_control_hook_value, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_DISPLAY:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_single_display_display_info, tvb, offset, 1, ENC_3GPP_TS_23_038_7BITS_UNPACKED);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_KEYPAD:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_single_keypad_keypad_info, tvb, offset, 1, ENC_3GPP_TS_23_038_7BITS_UNPACKED);
					break;
			}
		} else {
			element_length = 1;
			field_tree = proto_tree_add_subtree(tree, tvb, offset, element_length, ett_dect_nwk_s_ie_element, &field_tree_item, "Fixed length Element: ");
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_type, tvb, offset, 1, ENC_NA);
			if ( fl_ie_type == DECT_NWK_S_IE_FL_CONTROL ) {
				proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_control_type, tvb, offset, 1, ENC_NA);
				proto_item_append_text(field_tree_item, "%s", val_to_str(fl_ie_double_octet_type, dect_nwk_s_ie_fl_control_type_val, "Unkown: 0x%0x"));
			} else {
				proto_item_append_text(field_tree_item, "%s", val_to_str(fl_ie_type, dect_nwk_s_ie_fl_type_val, "Unkown: 0x%0x"));
				switch (fl_ie_type) {
					case DECT_NWK_S_IE_FL_SHIFT:
						proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_shift_locking, tvb, offset, 1, ENC_NA);
						proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_shift_new_codeset, tvb, offset, 1, ENC_NA);
						break;
					case DECT_NWK_S_IE_FL_REPEAT_INDICATOR:
						proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_repeat_indicator_type, tvb, offset, 1, ENC_NA);
						break;
				}
			}
		}
		offset ++;
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
			case DECT_NWK_S_IE_AUTH_TYPE:
				offset = dissect_dect_nwk_s_ie_auth_type(tvb, offset, field_tree, data);
				break;
			case DECT_NWK_S_IE_CALLING_PARTY_NUMBER:
				offset = dissect_dect_nwk_s_ie_calling_party_number(tvb, offset, element_length, field_tree, data);
				break;
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
			case DECT_NWK_S_IE_RAND:
				proto_tree_add_item(field_tree,hf_dect_nwk_s_ie_rand_rand_field, tvb, offset, element_length, ENC_NA);
				offset += element_length;
				break;
			case DECT_NWK_S_IE_RES:
				proto_tree_add_item(field_tree,hf_dect_nwk_s_ie_res_res_field, tvb, offset, element_length, ENC_NA);
				offset += element_length;
				break;
			case DECT_NWK_S_IE_RS:
				proto_tree_add_item(field_tree,hf_dect_nwk_s_ie_rs_rs_field, tvb, offset, element_length, ENC_NA);
				offset += element_length;
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
	return offset;
}

static int dissect_dect_nwk_lce(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{


	proto_tree_add_item(tree, hf_nwk_msg_type_lce, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_lce_msgt_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, tree, data);
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

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, tree, data);
	}

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}

static int dissect_dect_nwk_mm(tvbuff_t *tvb, guint8 msg_type, guint offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_mm, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_mm_msgt_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, tree, data);
	}
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
		{ &hf_dect_nwk_s_ie_octet_group_extension,
			{ "Extension", "dect_nwk.s.ie.group_extension", FT_BOOLEAN, 8,
				TFS(&tfs_last_more), 0x80, NULL, HFILL
			}
		},
		/* Fixed length elements */
		{ &hf_dect_nwk_s_ie_fl_type,
			{ "Message Type", "dect_nwk.s.ie.fl.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_control_type,
			{ "CTRL Type", "dect_nwk.s.ie.fl.control_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_control_type_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_double_octet_type,
			{ "Double Octet Type", "dect_nwk.s.ie.fl.double_octet_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_double_octet_type_val), 0x0F, NULL, HFILL
			}
		},
		/* Shift */
		{ &hf_dect_nwk_s_ie_fl_shift_locking,
			{ "Shift Procedure", "dect_nwk.s.ie.fl.shift.locking", FT_BOOLEAN, 8,
				TFS(&dect_nwk_s_ie_fl_shift_locking_tfs), 0x08, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_shift_new_codeset,
			{ "New Codeset", "dect_nwk.s.ie.fl.shift.new_codeset", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_shift_codeset_val), 0x07, NULL, HFILL
			}
		},
		/* Repeat indicator */
		{ &hf_dect_nwk_s_ie_fl_repeat_indicator_type,
			{ "Indicator Type", "dect_nwk.s.ie.fl.repeat_indicator.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_repeat_indicator_type_val), 0x0F, NULL, HFILL
			}
		},
		/* Basic service */
		{ &hf_dect_nwk_s_ie_fl_basic_service_call_class,
			{ "Call class", "dect_nwk.s.ie.fl.basic_service.call_class", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_basic_service_call_class_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_basic_service_type,
			{ "Basic Service", "dect_nwk.s.ie.fl.basic_service", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_basic_service_type_val), 0x0F, NULL, HFILL
			}
		},
		/* Single display */
		{ &hf_dect_nwk_s_ie_fl_single_display_display_info,
			{ "Display Info", "dect_nwk.s.ie.fl.single_display.display_info", FT_CHAR, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Single keypad */
		{ &hf_dect_nwk_s_ie_fl_single_keypad_keypad_info,
			{ "Keypad Info", "dect_nwk.s.ie.fl.single_keypad.keypad_info", FT_CHAR, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Release reason */
		{ &hf_dect_nwk_s_ie_fl_release_reason_code,
			{ "Release Reason Code", "dect_nwk.s.ie.fl.release_reason.code", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_release_reason_val), 0x0, NULL, HFILL
			}
		},
		/* Signal */
		{ &hf_dect_nwk_s_ie_fl_signal_value,
			{ "Signal value", "dect_nwk.s.ie.fl.signal.value", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_signal_value_val), 0x0, NULL, HFILL
			}
		},
		/* Timer restart */
		{ &hf_dect_nwk_s_ie_fl_timer_restart_value,
			{ "Restart value", "dect_nwk.s.ie.fl.timer_restart.restart_value", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_timer_restart_value_val), 0x0, NULL, HFILL
			}
		},
		/* Test hook control */
		{ &hf_dect_nwk_s_ie_fl_test_hook_control_hook_value,
			{ "Hook value", "dect_nwk.s.ie.fl.test_hook_control.hook_value", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_test_hook_control_hook_value_val), 0x0, NULL, HFILL
			}
		},
		/* Auth type*/
		{ &hf_dect_nwk_s_ie_auth_type_authentication_algorithm,
			{ "Authentication algorithm", "dect_nwk.s.ie.auth_type.authentication_algorithm", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_auth_type_authentication_algorithm_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_proprietary_algorithm,
			{ "Proprietary algorithm", "dect_nwk.s.ie.auth_type.proprietary_algorithm", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_ak_type,
			{ "AK Type", "dect_nwk.s.ie.auth_type.ak_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_auth_type_ak_type_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_ak_number,
			{ "AK Number", "dect_nwk.s.ie.auth_type.ak_number", FT_UINT8, BASE_HEX,
				NULL, 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_inc,
			{ "INC", "dect_nwk.s.ie.auth_type.inc", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x80, "Increment value of the ZAP field", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_def,
			{ "DEF", "dect_nwk.s.ie.auth_type.def", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x40, "Use generated derived cipher key as default cipher key for early encryption", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_txc,
			{ "TXC", "dect_nwk.s.ie.auth_type.tx", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x20, "Include derived cipher key in the AUTHENTICATION-REPLY message", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_upc,
			{ "UPC", "dect_nwk.s.ie.auth_type.upc", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x10, "Store derived cipher key", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_cipher_key_number,
			{ "Cipher key number", "dect_nwk.s.ie.auth_type.cipher_key_number", FT_UINT8, BASE_HEX,
				NULL, 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_cipher_key_number_related,
			{ "Key related to", "dect_nwk.s.ie.auth_type.key_related_to", FT_BOOLEAN, 8,
				TFS(&dect_nwk_s_ie_auth_type_cipher_key_number_related_tfs), 0x08, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_default_cipher_key_index,
			{ "Default Cipher Key Index", "dect_nwk.s.ie.auth_type.default_cipher_key_index", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_default_cipher_key_algorithm,
			{ "Default Cipher Key Algorithm", "dect_nwk.s.ie.auth_type.default_cipher_key_algorithm", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_auth_type_default_cipher_key_algorithm_val), 0x03, NULL, HFILL
			}
		},
		/* Calling party number */
		{ &hf_dect_nwk_s_ie_calling_party_number_type,
			{ "Type", "dect_nwk.s.ie.calling_party_number.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_numbering_plan,
			{ "Numbering plan", "dect_nwk.s.ie.calling_party_number.numbering_plan", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_numbering_plan_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_presentation,
			{ "Presentation", "dect_nwk.s.ie.calling_party_number.presentation", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_presentation_val), 0x60, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_screening,
			{ "Screening", "dect_nwk.s.ie.calling_party_number.screening", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_screening_val), 0x03, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_address,
			{ "Address", "dect_nwk.s.ie.calling_party_number.address", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Cipher info */
		{ &hf_dect_nwk_s_ie_cipher_info_yn,
			{ "Y/N", "dect_nwk.s.ie.cipher_info.yn", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
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
		/* RAND */
		{ &hf_dect_nwk_s_ie_rand_rand_field,
			{ "RAND Field", "dect_nwk.s.ie.rand.rand_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* RES */
		{ &hf_dect_nwk_s_ie_res_res_field,
			{ "RES Field", "dect_nwk.s.ie.res.res_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* RS */
		{ &hf_dect_nwk_s_ie_rs_rs_field,
			{ "RS Field", "dect_nwk.s.ie.rs.rs_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
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
