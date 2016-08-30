/* packet-isi.c
 * Dissector for Nokia's Intelligent Service Interface protocol
 * Copyright 2010, Sebastian Reichel <sre@ring0.de>
 * Copyright 2010, Tyson Key <tyson.key@gmail.com>
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

#include "config.h"

#include <glib.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-sll.h"
#include "packet-e212.h"

void proto_register_isi(void);
void proto_reg_handoff_isi(void);

/* Dissector table for the isi resource */
static dissector_table_t isi_resource_dissector_table;

static const value_string hf_isi_device[] = {
	{0x00, "Modem" },
	{0x6c, "Host" },
	{0xFF, "Any" },
	{0x00, NULL },
};

static const value_string hf_isi_resource[] = {
	{0x01, "Call"},
	{0x02, "SMS"},
	{0x06, "Subscriber Services"},
	{0x08, "SIM Authentication"},
	{0x09, "SIM"},
	{0x0A, "Network"},
	{0x10, "Indication"},
	{0x15, "MTC"},
	{0x1B, "Phone Information"},
	{0x31, "GPRS"},
	{0x32, "General Stack Server"}, /* Mysterious type 50 - I don't know what this is*/
	{0x54, "GPS"},
	{0x62, "EPOC Info"},
	{0xB4, "Radio Settings"}, /* Mysterious type 180? */
	{0x00, NULL }
};

static const value_string isi_sim_auth_id[] = {
	{0x01, "SIM_AUTH_PROTECTED_REQ"},
	{0x02, "SIM_AUTH_PROTECTED_RESP"},
	{0x04, "SIM_AUTH_UPDATE_REQ"},
	{0x05, "SIM_AUTH_UPDATE_SUCCESS_RESP"},
	{0x06, "SIM_AUTH_UPDATE_FAIL_RESP"},
	{0x07, "SIM_AUTH_REQ"},
	{0x08, "SIM_AUTH_SUCCESS_RESP"},
	{0x09, "SIM_AUTH_FAIL_RESP"},
	{0x10, "SIM_AUTH_STATUS_IND"},
	{0x11, "SIM_AUTH_STATUS_REQ"},
	{0x12, "SIM_AUTH_STATUS_RESP"},
	{0x00, NULL }
};

static const value_string isi_sim_auth_pw_type[] = {
	{0x02, "SIM_AUTH_PIN"},
	{0x03, "SIM_AUTH_PUK"},
	{0x63, "SIM_AUTH_NONE"},
	{0x00, NULL}
};

static const value_string isi_sim_auth_protection_req[] = {
	{0x00, "SIM_AUTH_PROTECTION_DISABLE"},
	{0x01, "SIM_AUTH_PROTECTION_ENABLE"},
	{0x04, "SIM_AUTH_PROTECTION_STATUS"},
	{0x00, NULL}
};

static const value_string isi_sim_auth_resp[] = {
	{0x02, "SIM_AUTH_STATUS_RESP_NEED_PIN"},
	{0x03, "SIM_AUTH_STATUS_RESP_NEED_PUK"},
	{0x05, "SIM_AUTH_STATUS_RESP_RUNNING"},
	{0x07, "SIM_AUTH_STATUS_RESP_INIT"},
	{0x00, NULL}
};

static const value_string isi_sim_auth_indication[] = {
	{0x01, "SIM_AUTH_NEED_AUTH"},
	{0x02, "SIM_AUTH_NEED_NO_AUTH"},
	{0x03, "SIM_AUTH_VALID"},
	{0x04, "SIM_AUTH_INVALID"},
	{0x05, "SIM_AUTH_AUTHORIZED"},
	{0x06, "SIM_AUTH_IND_CONFIG"},
	{0x00, NULL}
};

static const value_string isi_sim_auth_indication_cfg[] = {
	{0x0B, "SIM_AUTH_PIN_PROTECTED_DISABLE"},
	{0x0C, "SIM_AUTH_PIN_PROTECTED_ENABLE"},
	{0x00, NULL}
};

static const value_string isi_sim_message_id[] = {
	{0x19, "SIM_NETWORK_INFO_REQ"},
	{0x1A, "SIM_NETWORK_INFO_RESP"},
	{0x1D, "SIM_IMSI_REQ_READ_IMSI"},
	{0x1E, "SIM_IMSI_RESP_READ_IMSI"},
	{0x21, "SIM_SERV_PROV_NAME_REQ"},
	{0x22, "SIM_SERV_PROV_NAME_RESP"},
	{0xBA, "SIM_READ_FIELD_REQ"},
	{0xBB, "SIM_READ_FIELD_RESP"},
	{0xBC, "SIM_SMS_REQ"},
	{0xBD, "SIM_SMS_RESP"},
	{0xDC, "SIM_PB_REQ_SIM_PB_READ"},
	{0xDD, "SIM_PB_RESP_SIM_PB_READ"},
	{0xEF, "SIM_IND"},
	{0xF0, "SIM_COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_sim_service_type[] = {
	{0x01, "SIM_ST_PIN"},
	{0x05, "SIM_ST_ALL_SERVICES"},
	{0x0D, "SIM_ST_INFO"},
	{0x2C, "SIM_ST_READ_SERV_PROV_NAME"},
	{0x0F, "SIM_PB_READ"},
	{0x2D, "READ_IMSI"},
	{0x2F, "READ_HPLMN"},
	{0x52, "READ_PARAMETER"},
	{0x53, "UPDATE_PARAMETER"},
	{0x66, "ICC"},
	{0x00, NULL}
};

static const value_string isi_sim_cause[] = {
	{0x00, "SIM_SERV_NOT_AVAIL"},
	{0x01, "SIM_SERV_OK"},
	{0x02, "SIM_SERV_PIN_VERIFY_REQUIRED"},
	{0x03, "SIM_SERV_PIN_REQUIRED"},
	{0x04, "SIM_SERV_SIM_BLOCKED"},
	{0x05, "SIM_SERV_SIM_PERMANENTLY_BLOCKED"},
	{0x06, "SIM_SERV_SIM_DISCONNECTED"},
	{0x07, "SIM_SERV_SIM_REJECTED"},
	{0x08, "SIM_SERV_LOCK_ACTIVE"},
	{0x09, "SIM_SERV_AUTOLOCK_CLOSED"},
	{0x0A, "SIM_SERV_AUTOLOCK_ERROR"},
	{0x0B, "SIM_SERV_INIT_OK"},
	{0x0C, "SIM_SERV_INIT_NOT_OK"},
	{0x0D, "SIM_SERV_WRONG_OLD_PIN"},
	{0x0E, "SIM_SERV_PIN_DISABLED"},
	{0x0F, "SIM_SERV_COMMUNICATION_ERROR"},
	{0x10, "SIM_SERV_UPDATE_IMPOSSIBLE"},
	{0x11, "SIM_SERV_NO_SECRET_CODE_IN_SIM"},
	{0x12, "SIM_SERV_PIN_ENABLE_OK"},
	{0x13, "SIM_SERV_PIN_DISABLE_OK"},
	{0x15, "SIM_SERV_WRONG_UNBLOCKING_KEY"},
	{0x19, "SIM_FDN_ENABLED"},
	{0x1A, "SIM_FDN_DISABLED"},
	{0x1C, "SIM_SERV_NOT_OK"},
	{0x1E, "SIM_SERV_PN_LIST_ENABLE_OK"},
	{0x1F, "SIM_SERV_PN_LIST_DISABLE_OK"},
	{0x20, "SIM_SERV_NO_PIN"},
	{0x21, "SIM_SERV_PIN_VERIFY_OK"},
	{0x22, "SIM_SERV_PIN_BLOCKED"},
	{0x23, "SIM_SERV_PIN_PERM_BLOCKED"},
	{0x24, "SIM_SERV_DATA_NOT_AVAIL"},
	{0x25, "SIM_SERV_IN_HOME_ZONE"},
	{0x27, "SIM_SERV_STATE_CHANGED"},
	{0x28, "SIM_SERV_INF_NBR_READ_OK"},
	{0x29, "SIM_SERV_INF_NBR_READ_NOT_OK"},
	{0x2A, "SIM_SERV_IMSI_EQUAL"},
	{0x2B, "SIM_SERV_IMSI_NOT_EQUAL"},
	{0x2C, "SIM_SERV_INVALID_LOCATION"},
	{0x2E, "SIM_SERV_ILLEGAL_NUMBER"},
	{0x30, "SIM_SERV_CIPHERING_INDICATOR_DISPLAY_REQUIRED"},
	{0x31, "SIM_SERV_CIPHERING_INDICATOR_DISPLAY_NOT_REQUIRED"},
	{0x35, "SIM_SERV_STA_SIM_REMOVED"},
	{0x36, "SIM_SERV_SECOND_SIM_REMOVED_CS"},
	{0x37, "SIM_SERV_CONNECTED_INDICATION_CS"},
	{0x38, "SIM_SERV_SECOND_SIM_CONNECTED_CS"},
	{0x39, "SIM_SERV_PIN_RIGHTS_LOST_IND_CS"},
	{0x3A, "SIM_SERV_PIN_RIGHTS_GRANTED_IND_CS"},
	{0x3B, "SIM_SERV_INIT_OK_CS"},
	{0x3C, "SIM_SERV_INIT_NOT_OK_CS"},
	{0x45, "SIM_SERV_INVALID_FILE"},
	{0x49, "SIM_SERV_ICC_EQUAL"},
	{0x4A, "SIM_SERV_ICC_NOT_EQUAL"},
	{0x4B, "SIM_SERV_SIM_NOT_INITIALISED"},
	{0x4D, "SIM_SERV_FILE_NOT_AVAILABLE"},
	{0x4F, "SIM_SERV_DATA_AVAIL"},
	{0x50, "SIM_SERV_SERVICE_NOT_AVAIL"},
	{0x57, "SIM_SERV_FDN_STATUS_ERROR"},
	{0x58, "SIM_SERV_FDN_CHECK_PASSED"},
	{0x59, "SIM_SERV_FDN_CHECK_FAILED"},
	{0x5A, "SIM_SERV_FDN_CHECK_DISABLED"},
	{0x5B, "SIM_SERV_FDN_CHECK_NO_FDN_SIM"},
	{0x5C, "SIM_STA_ISIM_AVAILABLE_PIN_REQUIRED"},
	{0x5D, "SIM_STA_ISIM_AVAILABLE"},
	{0x5E, "SIM_STA_USIM_AVAILABLE"},
	{0x5F, "SIM_STA_SIM_AVAILABLE"},
	{0x60, "SIM_STA_ISIM_NOT_INITIALISED"},
	{0x61, "SIM_STA_IMS_READY"},
	{0x96, "SIM_STA_APP_DATA_READ_OK"},
	{0x97, "SIM_STA_APP_ACTIVATE_OK"},
	{0x98, "SIM_STA_APP_ACTIVATE_NOT_OK"},
	{0xF9, "SIM_SERV_NOT_DEFINED"},
	{0xFA, "SIM_SERV_NOSERVICE"},
	{0xFB, "SIM_SERV_NOTREADY"},
	{0xFC, "SIM_SERV_ERROR"},
	{0x00, NULL }
};

value_string_ext isi_sim_cause_ext = VALUE_STRING_EXT_INIT(isi_sim_cause);

static const value_string isi_sim_pb_subblock[] = {
	{0xE4, "SIM_PB_INFO_REQUEST"},
	{0xFB, "SIM_PB_STATUS"},
	{0xFE, "SIM_PB_LOCATION"},
	{0xFF, "SIM_PB_LOCATION_SEARCH"},
	{0x00, NULL }
};

static const value_string isi_sim_pb_type[] = {
	{0xC8, "SIM_PB_ADN"},
	{0x00, NULL }
};

static const value_string isi_sim_pb_tag[] = {
	{0xCA, "SIM_PB_ANR"},
	{0xDD, "SIM_PB_EMAIL"},
	{0xF7, "SIM_PB_SNE"},
	{0x00, NULL }
};

static const value_string isi_gss_message_id[] = {
	{0x00, "GSS_CS_SERVICE_REQ"},
	{0x01, "GSS_CS_SERVICE_RESP"},
	{0x02, "GSS_CS_SERVICE_FAIL_RESP"},
	{0xF0, "COMMON_MESSAGE"},
	{0x00, NULL }
};

#if 0
static const value_string isi_gss_subblock[] = {
	{0x0B, "GSS_RAT_INFO"},
	{0x00, NULL }
};
#endif

static const value_string isi_gss_operation[] = {
	{0x0E, "GSS_SELECTED_RAT_WRITE"},
	{0x9C, "GSS_SELECTED_RAT_READ"},
	{0x00, NULL }
};

static const value_string isi_gss_cause[] = {
	{0x01, "GSS_SERVICE_FAIL"},
	{0x02, "GSS_SERVICE_NOT_ALLOWED"},
	{0x03, "GSS_SERVICE_FAIL_CS_INACTIVE"},
	{0x00, NULL }
};

static const value_string isi_gss_common_message_id[] = {
	{0x01, "COMM_SERVICE_NOT_IDENTIFIED_RESP"},
	{0x12, "COMM_ISI_VERSION_GET_REQ"},
	{0x13, "COMM_ISI_VERSION_GET_RESP"},
	{0x14, "COMM_ISA_ENTITY_NOT_REACHABLE_RESP"},
	{0x00, NULL }
};

static const value_string isi_gps_id[] = {
	{0x7d, "GPS_STATUS_IND"},
	{0x90, "GPS_POWER_STATUS_REQ"},
	{0x91, "GPS_POWER_STATUS_RSP"},
	{0x92, "GPS_DATA_IND"},
	{0x00, NULL }
};

static const value_string isi_gps_sub_id[] = {
	{0x02, "GPS_POSITION"},
	{0x03, "GPS_TIME_DATE"},
	{0x04, "GPS_MOVEMENT"},
	{0x05, "GPS_SAT_INFO"},
	{0x07, "GPS_CELL_INFO_GSM"},
	{0x08, "GPS_CELL_INFO_WCDMA"},
	{0x00, NULL }
};

static const value_string isi_gps_status[] = {
	{0x00, "GPS_DISABLED"},
	{0x01, "GPS_NO_LOCK"},
	{0x02, "GPS_LOCK"},
	{0x00, NULL }
};

static const value_string isi_ss_message_id[] = {
	{0x00, "SS_SERVICE_REQ"},
	{0x01, "SS_SERVICE_COMPLETED_RESP"},
	{0x02, "SS_SERVICE_FAILED_RESP"},
	{0x03, "SS_SERVICE_NOT_SUPPORTED_RESP"},
	{0x04, "SS_GSM_USSD_SEND_REQ"},
	{0x05, "SS_GSM_USSD_SEND_RESP"},
	{0x06, "SS_GSM_USSD_RECEIVE_IND"},
	{0x09, "SS_STATUS_IND"},
	{0x10, "SS_SERVICE_COMPLETED_IND"},
	{0x11, "SS_CANCEL_REQ"},
	{0x12, "SS_CANCEL_RESP"},
	{0x15, "SS_RELEASE_REQ"},
	{0x16, "SS_RELEASE_RESP"},
	{0xF0, "COMMON_MESSAGE"},
	{0x00, NULL }
};

static const value_string isi_ss_ussd_type[] = {
	{0x01, "SS_GSM_USSD_MT_REPLY"},
	{0x02, "SS_GSM_USSD_COMMAND"},
	{0x03, "SS_GSM_USSD_REQUEST"},
	{0x04, "SS_GSM_USSD_NOTIFY"},
	{0x05, "SS_GSM_USSD_END"},
	{0x00, NULL }
};

static const value_string isi_ss_subblock[] = {
	{0x00, "SS_FORWARDING"},
	{0x01, "SS_STATUS_RESULT"},
	{0x03, "SS_GSM_PASSWORD"},
	{0x04, "SS_GSM_FORWARDING_INFO"},
	{0x05, "SS_GSM_FORWARDING_FEATURE"},
	{0x08, "SS_GSM_DATA"},
	{0x09, "SS_GSM_BSC_INFO"},
	{0x0B, "SS_GSM_PASSWORD_INFO"},
	{0x0D, "SS_GSM_INDICATE_PASSWORD_ERROR"},
	{0x0E, "SS_GSM_INDICATE_ERROR"},
	{0x2F, "SS_GSM_ADDITIONAL_INFO"},
	{0x32, "SS_GSM_USSD_STRING"},
	{0x00, NULL }
};

static const value_string isi_ss_operation[] = {
	{0x01, "SS_ACTIVATION"},
	{0x02, "SS_DEACTIVATION"},
	{0x03, "SS_REGISTRATION"},
	{0x04, "SS_ERASURE"},
	{0x05, "SS_INTERROGATION"},
	{0x06, "SS_GSM_PASSWORD_REGISTRATION"},
	{0x00, NULL }
};

static const value_string isi_ss_service_code[] = {
	{0x00, "SS_ALL_TELE_AND_BEARER"},
	{0x0A, "SS_GSM_ALL_TELE"},
	{0x0B, "SS_GSM_TELEPHONY"},
	{0x0C, "SS_GSM_ALL_DATA_TELE"},
	{0x0D, "SS_GSM_FACSIMILE"},
	{0x10, "SS_GSM_SMS"},
	{0x00, NULL}
};

static const value_string isi_ss_status_indication[] = {
	{0x00, "SS_STATUS_REQUEST_SERVICE_START"},
	{0x01, "SS_STATUS_REQUEST_SERVICE_STOP"},
	{0x02, "SS_GSM_STATUS_REQUEST_USSD_START"},
	{0x03, "SS_GSM_STATUS_REQUEST_USSD_STOP"},
	{0x00, NULL}
};

static const value_string isi_ss_common_message_id[] = {
	{0x01, "COMM_SERVICE_NOT_IDENTIFIED_RESP"},
	{0x12, "COMM_ISI_VERSION_GET_REQ"},
	{0x13, "COMM_ISI_VERSION_GET_RESP"},
	{0x14, "COMM_ISA_ENTITY_NOT_REACHABLE_RESP"},
	{0x00, NULL }
};

static const value_string isi_network_id[] = {
	{0x07, "NET_SET_REQ"},
	{0x08, "NET_SET_RESP"},
	{0x0B, "NET_RSSI_GET_REQ"},
	{0x0C, "NET_RSSI_GET_RESP"},
	{0x1E, "NET_RSSI_IND"},
	{0x20, "NET_CIPHERING_IND"},
	{0x35, "NET_RAT_IND"},
	{0x36, "NET_RAT_REQ"},
	{0x37, "NET_RAT_RESP"},
	{0x42, "NET_CELL_INFO_IND"},
	{0xE0, "NET_REG_STATUS_GET_REQ"},
	{0xE1, "NET_REG_STATUS_GET_RESP"},
	{0xE2, "NET_REG_STATUS_IND"},
	{0xE3, "NET_AVAILABLE_GET_REQ"},
	{0xE4, "NET_AVAILABLE_GET_RESP"},
	{0xE5, "NET_OPER_NAME_READ_REQ"},
	{0xE6, "NET_OPER_NAME_READ_RESP"},
	{0xF0, "NET_COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_network_status_sub_id[] = {
	{0x00, "NET_REG_INFO_COMMON"},
	{0x02, "NET_OPERATOR_INFO_COMMON"},
	{0x04, "NET_RSSI_CURRENT"},
	{0x09, "NET_GSM_REG_INFO"},
	{0x0B, "NET_DETAILED_NETWORK_INFO"},
	{0x0C, "NET_GSM_OPERATOR_INFO"},
	{0x11, "NET_GSM_BAND_INFO"},
	{0x2C, "NET_RAT_INFO"},
	{0xE1, "NET_AVAIL_NETWORK_INFO_COMMON"},
	{0xE7, "NET_OPER_NAME_INFO"},
	{0x00, NULL}
};

static const value_string isi_network_cell_info_sub_id[] = {
	{0x46, "NET_GSM_CELL_INFO"},
	{0x47, "NET_WCDMA_CELL_INFO"},
	{0x50, "NET_EPS_CELL_INFO"},
	{0x00, NULL}
};

/* centimeter per second to kilometer per hour */
#define CMS_TO_KMH 0.036
#define SAT_PKG_LEN 12

static const value_string isi_sms_message_id[] = {
	{0x00, "SMS_MESSAGE_CAPABILITY_REQ"},
	{0x01, "SMS_MESSAGE_CAPABILITY_RESP"},
	{0x02, "SMS_MESSAGE_SEND_REQ"},
	{0x03, "SMS_MESSAGE_SEND_RESP"},
	{0x04, "SMS_RECEIVED_MT_PP_IND"},
	{0x05, "SMS_RECEIVED_MWI_PP_IND"},
	{0x06, "SMS_PP_ROUTING_REQ"},
	{0x07, "SMS_PP_ROUTING_RESP"},
	{0x08, "SMS_PP_ROUTING_NTF"},
	{0x09, "SMS_GSM_RECEIVED_PP_REPORT_REQ"},
	{0x0A, "SMS_GSM_RECEIVED_PP_REPORT_RESP"},
	{0x0B, "SMS_GSM_CB_ROUTING_REQ"},
	{0x0C, "SMS_GSM_CB_ROUTING_RESP"},
	{0x0D, "SMS_GSM_CB_ROUTING_NTF"},
	{0x0E, "SMS_GSM_TEMP_CB_ROUTING_REQ"},
	{0x0F, "SMS_GSM_TEMP_CB_ROUTING_RESP"},
	{0x10, "SMS_GSM_TEMP_CB_ROUTING_NTF"},
	{0x11, "SMS_GSM_CBCH_PRESENT_IND"},
	{0x12, "SMS_PARAMETERS_UPDATE_REQ"},
	{0x13, "SMS_PARAMETERS_UPDATE_RESP"},
	{0x14, "SMS_PARAMETERS_READ_REQ"},
	{0x15, "SMS_PARAMETERS_READ_RESP"},
	{0x16, "SMS_PARAMETERS_CAPACITY_REQ"},
	{0x17, "SMS_PARAMETERS_CAPACITY_RESP"},
	{0x18, "SMS_GSM_SETTINGS_UPDATE_REQ"},
	{0x19, "SMS_GSM_SETTINGS_UPDATE_RESP"},
	{0x1A, "SMS_GSM_SETTINGS_READ_REQ"},
	{0x1B, "SMS_GSM_SETTINGS_READ_RESP"},
	{0x1C, "SMS_GSM_MCN_SETTING_CHANGED_IND"},
	{0x1D, "SMS_MEMORY_CAPACITY_EXC_IND"},
	{0x1E, "SMS_STORAGE_STATUS_UPDATE_REQ"},
	{0x1F, "SMS_STORAGE_STATUS_UPDATE_RESP"},
	{0x22, "SMS_MESSAGE_SEND_STATUS_IND"},
	{0x23, "SMS_GSM_RESEND_CANCEL_REQ"},
	{0x24, "SMS_GSM_RESEND_CANCEL_RESP"},
	{0x25, "SMS_SM_CONTROL_ACTIVATE_REQ"},
	{0x26, "SMS_SM_CONTROL_ACTIVATE_RESP"},
	/* 0x29 is undocumented, but appears in traces */
	{0xF0, "COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_sms_routing_command[] = {
	{0x00, "SMS_ROUTING_RELEASE"},
	{0x01, "SMS_ROUTING_SET"},
	{0x02, "SMS_ROUTING_SUSPEND"},
	{0x03, "SMS_ROUTING_RESUME"},
	{0x04, "SMS_ROUTING_UPDATE"},
	{0x05, "SMS_ROUTING_QUERY"},
	{0x06, "SMS_ROUTING_QUERY_ALL"},
	{0x00, NULL}
};

static const value_string isi_sms_routing_mode[] = {
	{0x00, "SMS_GSM_ROUTING_MODE_CLASS_DISP"},
	{0x01, "SMS_GSM_ROUTING_MODE_CLASS_TE"},
	{0x02, "SMS_GSM_ROUTING_MODE_CLASS_ME"},
	{0x03, "SMS_GSM_ROUTING_MODE_CLASS_SIM"},
	{0x04, "SMS_GSM_ROUTING_MODE_CLASS_UD1"},
	{0x05, "SMS_GSM_ROUTING_MODE_CLASS_UD2"},
	{0x06, "SMS_GSM_ROUTING_MODE_DATACODE_WAP"},
	{0x07, "SMS_GSM_ROUTING_MODE_DATACODE_8BIT"},
	{0x08, "SMS_GSM_ROUTING_MODE_DATACODE_TXT"},
	{0x09, "SMS_GSM_ROUTING_MODE_MWI_DISCARD"},
	{0x0A, "SMS_GSM_ROUTING_MODE_MWI_STORE"},
	{0x0B, "SMS_GSM_ROUTING_MODE_ALL"},
	{0x0C, "SMS_GSM_ROUTING_MODE_CB_DDL"},
	{0x00, NULL}
};

static const value_string isi_sms_route[] = {
	{0x00, "SMS_ROUTE_GPRS_PREF"},
	{0x01, "SMS_ROUTE_CS"},
	{0x02, "SMS_ROUTE_GPRS"},
	{0x03, "SMS_ROUTE_CS_PREF"},
	{0x04, "SMS_ROUTE_DEFAULT"},
	{0x00, NULL}
};

/*
static const value_string isi_sms_subblock[] = {
	{0x00, "SS_FORWARDING"},
	{0x01, "SS_STATUS_RESULT"},
	{0x03, "SS_GSM_PASSWORD"},
	{0x04, "SS_GSM_FORWARDING_INFO"},
	{0x05, "SS_GSM_FORWARDING_FEATURE"},
	{0x08, "SS_GSM_DATA"},
	{0x09, "SS_GSM_BSC_INFO"},
	{0x0B, "SS_GSM_PASSWORD_INFO"},
	{0x0D, "SS_GSM_INDICATE_PASSWORD_ERROR"},
	{0x0E, "SS_GSM_INDICATE_ERROR"},
	{0x2F, "SS_GSM_ADDITIONAL_INFO"},
	{0x32, "SS_GSM_USSD_STRING"},
	{0x00, NULL }
};
*/

static const value_string isi_sms_send_status[] = {
	{0x00, "SMS_MSG_REROUTED"},
	{0x01, "SMS_MSG_REPEATED"},
	{0x02, "SMS_MSG_WAITING_NETWORK"},
	{0x03, "SMS_MSG_IDLE"},
	{0x00, NULL},
};

static const value_string isi_sms_common_message_id[] = {
	{0x01, "COMM_SERVICE_NOT_IDENTIFIED_RESP"},
	{0x12, "COMM_ISI_VERSION_GET_REQ"},
	{0x13, "COMM_ISI_VERSION_GET_RESP"},
	{0x14, "COMM_ISA_ENTITY_NOT_REACHABLE_RESP"},
	{0x00, NULL }
};


static int proto_isi = -1;

static int hf_isi_rdev = -1;
static int hf_isi_sdev = -1;
static int hf_isi_res  = -1;
static int hf_isi_len  = -1;
static int hf_isi_robj = -1;
static int hf_isi_sobj = -1;
static int hf_isi_id   = -1;

static int hf_isi_sim_auth_payload = -1;
static int hf_isi_sim_auth_cmd = -1;
static int hf_isi_sim_auth_status_rsp = -1;
static int hf_isi_sim_auth_protection_req = -1;
static int hf_isi_sim_auth_protection_rsp = -1;
static int hf_isi_sim_auth_pin = -1;
static int hf_isi_sim_auth_puk = -1;
static int hf_isi_sim_auth_new_pin = -1;
static int hf_isi_sim_auth_pw_type = -1;
static int hf_isi_sim_auth_indication = -1;
static int hf_isi_sim_auth_indication_cfg = -1;

static int hf_isi_sim_payload = -1;
static int hf_isi_sim_message_id = -1;
static int hf_isi_sim_service_type = -1;
static int hf_isi_sim_cause = -1;
static int hf_isi_sim_secondary_cause = -1;
static int hf_isi_sim_subblock_count = -1;
static int hf_isi_sim_subblock_size = -1;
static int hf_isi_sim_pb_subblock = -1;
static int hf_isi_sim_pb_type = -1;
static int hf_isi_sim_pb_location = -1;
static int hf_isi_sim_pb_tag_count = -1;
static int hf_isi_sim_pb_tag = -1;
static int hf_isi_sim_imsi_length = -1;

static int hf_isi_gss_payload = -1;
static int hf_isi_gss_message_id = -1;
#if 0
static int hf_isi_gss_subblock = -1;
#endif
static int hf_isi_gss_operation = -1;
static int hf_isi_gss_subblock_count = -1;
static int hf_isi_gss_cause = -1;
static int hf_isi_gss_common_message_id = -1;

static int hf_isi_gps_payload = -1;
static int hf_isi_gps_cmd = -1;
static int hf_isi_gps_sub_pkgs = -1;
static int hf_isi_gps_sub_type = -1;
static int hf_isi_gps_sub_len = -1;
static int hf_isi_gps_status = -1;
static int hf_isi_gps_year = -1;
static int hf_isi_gps_month = -1;
static int hf_isi_gps_day = -1;
static int hf_isi_gps_hour = -1;
static int hf_isi_gps_minute = -1;
static int hf_isi_gps_second = -1;
static int hf_isi_gps_latitude = -1;
static int hf_isi_gps_longitude = -1;
static int hf_isi_gps_eph = -1;
static int hf_isi_gps_altitude = -1;
static int hf_isi_gps_epv = -1;
static int hf_isi_gps_course = -1;
static int hf_isi_gps_epd = -1;
static int hf_isi_gps_speed = -1;
static int hf_isi_gps_eps = -1;
static int hf_isi_gps_climb = -1;
static int hf_isi_gps_epc = -1;
static int hf_isi_gps_mcc = -1;
static int hf_isi_gps_mnc = -1;
static int hf_isi_gps_lac = -1;
static int hf_isi_gps_cid = -1;
static int hf_isi_gps_ucid = -1;
static int hf_isi_gps_satellites = -1;
static int hf_isi_gps_prn = -1;
static int hf_isi_gps_sat_used = -1;
static int hf_isi_gps_sat_strength = -1;
static int hf_isi_gps_sat_elevation = -1;
static int hf_isi_gps_sat_azimuth = -1;

static int hf_isi_ss_payload = -1;
static int hf_isi_ss_message_id = -1;
static int hf_isi_ss_ussd_type = -1;
static int hf_isi_ss_subblock_count = -1;
static int hf_isi_ss_subblock = -1;
static int hf_isi_ss_operation = -1;
static int hf_isi_ss_service_code = -1;
static int hf_isi_ss_status_indication = -1;
static int hf_isi_ss_ussd_length = -1;
static int hf_isi_ss_common_message_id = -1;

static int hf_isi_network_payload = -1;
static int hf_isi_network_cmd = -1;
static int hf_isi_network_data_sub_pkgs = -1;
static int hf_isi_network_status_sub_type = -1;
static int hf_isi_network_status_sub_len = -1;
static int hf_isi_network_status_sub_lac = -1;
static int hf_isi_network_status_sub_cid = -1;
static int hf_isi_network_status_sub_msg = -1;
static int hf_isi_network_status_sub_msg_len = -1;
static int hf_isi_network_cell_info_sub_type = -1;
static int hf_isi_network_cell_info_sub_len  = -1;
static int hf_isi_network_cell_info_sub_operator = -1;
static int hf_isi_network_gsm_band_900 = -1;
static int hf_isi_network_gsm_band_1800 = -1;
static int hf_isi_network_gsm_band_1900 = -1;
static int hf_isi_network_gsm_band_850 = -1;

static int hf_isi_sms_payload = -1;
static int hf_isi_sms_message_id = -1;
static int hf_isi_sms_routing_command = -1;
static int hf_isi_sms_routing_mode = -1;
static int hf_isi_sms_route = -1;
static int hf_isi_sms_subblock_count = -1;
static int hf_isi_sms_send_status = -1;
static int hf_isi_sms_common_message_id = -1;

static int ett_isi = -1;
static int ett_isi_msg = -1;
static int ett_isi_network_gsm_band_info = -1;

static expert_field ei_isi_len = EI_INIT;
static expert_field ei_isi_unsupported_packet = EI_INIT;

static int dissect_isi_sim_auth(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_) {
	proto_item *item;
	proto_tree *tree;
	guint8 cmd, code;

	item = proto_tree_add_item(isitree, hf_isi_sim_auth_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_sim_auth_cmd, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {
		case 0x01: /* SIM_AUTH_PROTECTED_REQ */
			proto_tree_add_item(tree, hf_isi_sim_auth_protection_req, tvb, 2, 1, ENC_BIG_ENDIAN);
			cmd = tvb_get_guint8(tvb, 2);
			switch(cmd) {
				case 0x00: /* DISABLE */
					proto_tree_add_item(tree, hf_isi_sim_auth_pin, tvb, 3, -1, ENC_ASCII|ENC_NA);
					col_set_str(pinfo->cinfo, COL_INFO, "disable SIM startup protection");
					break;
				case 0x01: /* ENABLE */
					proto_tree_add_item(tree, hf_isi_sim_auth_pin, tvb, 3, -1, ENC_ASCII|ENC_NA);
					col_set_str(pinfo->cinfo, COL_INFO, "enable SIM startup protection");
					break;
				case 0x04: /* STATUS */
					col_set_str(pinfo->cinfo, COL_INFO, "get SIM startup protection status");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM startup protection packet");
					break;
			}
			break;
		case 0x02: /* SIM_AUTH_PROTECTED_RESP */
			proto_tree_add_item(tree, hf_isi_sim_auth_protection_rsp, tvb, 1, 1, ENC_BIG_ENDIAN);
			if(tvb_get_guint8(tvb, 1))
				col_set_str(pinfo->cinfo, COL_INFO, "SIM startup protection enabled");
			else
				col_set_str(pinfo->cinfo, COL_INFO, "SIM startup protection disabled");
			break;
		case 0x04: /* SIM_AUTH_UPDATE_REQ */
			proto_tree_add_item(tree, hf_isi_sim_auth_pw_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x02: /* PIN */
					col_set_str(pinfo->cinfo, COL_INFO, "update SIM PIN");
					proto_tree_add_item(tree, hf_isi_sim_auth_pin, tvb, 2, 11, ENC_ASCII|ENC_NA);
					proto_tree_add_item(tree, hf_isi_sim_auth_new_pin, tvb, 13, 11, ENC_ASCII|ENC_NA);
					break;
				case 0x03: /* PUK */
					col_set_str(pinfo->cinfo, COL_INFO, "update SIM PUK");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM Authentication update request");
					break;
			}
			break;
		case 0x05: /* SIM_AUTH_UPDATE_SUCCESS_RESP */
			col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication update successful");
			break;
		case 0x06: /* SIM_AUTH_UPDATE_FAIL_RESP */
			col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication update failed");
			break;
		case 0x07: /* SIM_AUTH_REQ */
			proto_tree_add_item(tree, hf_isi_sim_auth_pw_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x02: /* PIN */
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication with PIN");
					proto_tree_add_item(tree, hf_isi_sim_auth_pin, tvb, 2, 11, ENC_ASCII|ENC_NA);
					break;
				case 0x03: /* PUK */
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication with PUK");
					proto_tree_add_item(tree, hf_isi_sim_auth_puk, tvb, 2, 11, ENC_ASCII|ENC_NA);
					proto_tree_add_item(tree, hf_isi_sim_auth_new_pin, tvb, 13, 11, ENC_ASCII|ENC_NA);
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM Authentication request");
					break;
			}
			break;
		case 0x08: /* SIM_AUTH_SUCCESS_RESP */
			col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication successful");
			break;
		case 0x09: /* SIM_AUTH_FAIL_RESP */
			col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication failed");
			break;
		case 0x10: /* SIM_AUTH_STATUS_IND */
			proto_tree_add_item(tree, hf_isi_sim_auth_indication, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			proto_tree_add_item(tree, hf_isi_sim_auth_pw_type, tvb, 2, 1, ENC_BIG_ENDIAN);
			switch(code) {
				case 0x01:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication indication: Authentication needed");
					break;
				case 0x02:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication indication: No Authentication needed");
					break;
				case 0x03:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication indication: Authentication valid");
					break;
				case 0x04:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication indication: Authentication invalid");
					break;
				case 0x05:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication indication: Authorized");
					break;
				case 0x06:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication indication: Config");
					proto_tree_add_item(tree, hf_isi_sim_auth_indication_cfg, tvb, 3, 1, ENC_BIG_ENDIAN);
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM Authentication indication");
					break;
			}
			break;
		case 0x11: /* SIM_AUTH_STATUS_REQ */
			col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication status request");
			break;
		case 0x12: /* SIM_AUTH_STATUS_RESP */
			proto_tree_add_item(tree, hf_isi_sim_auth_status_rsp, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x02:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication status: need PIN");
					break;
				case 0x03:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication status: need PUK");
					break;
				case 0x05:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication status: running");
					break;
				case 0x07:
					col_set_str(pinfo->cinfo, COL_INFO, "SIM Authentication status: initializing");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM Authentication status response packet");
					break;
			}
			break;
		default:
			col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM Authentication packet");
			break;
	}
	return tvb_captured_length(tvb);
}

static int dissect_isi_sim(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_) {
	proto_item *item;
	proto_tree *tree;
	guint8 cmd, code;

	item = proto_tree_add_item(isitree, hf_isi_sim_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_sim_message_id, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {

		case 0x19: /* SIM_NETWORK_INFO_REQ */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x2F:
					col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request");
					break;
			}
			break;

		case 0x1A: /* SIM_NETWORK_INFO_RESP */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 2, 1, ENC_BIG_ENDIAN);

			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x2F:
					dissect_e212_mcc_mnc(tvb, pinfo, tree, 3, E212_LAI, FALSE);
					col_set_str(pinfo->cinfo, COL_INFO, "Network Information Response: Home PLMN");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Network Information Response");
					break;
			}
			break;

		case 0x1D: /* SIM_IMSI_REQ_READ_IMSI */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Read IMSI Request");
					break;
			}
			break;

		case 0x1E: /* SIM_IMSI_RESP_READ_IMSI */

			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);

			/* If properly decoded, an IMSI should look like 234 100 733569423 in split Base10

			0000   1e 2d 01 08 | 29 43 01 | 70 33 65 49 32
						    92 34 10 | 07 33 56 94 23

			Switch 0x29 to produce 0x92

			AND 0x92 with 0xF0 to strip the leading 9

			Switch 0x43 to produce 0x34

			Concatenate 0x02 and 0x34 to produce 0x02 34 - which is our MCC for the UK

			Switch 0x01 to produce 0x10 - first byte of the MNC

			Switch 0x70 to produce 0x07 - second bit of the MNC, and first bit of the MSIN

			Remainder of MSIN follows:

			Switch 0x33 to produce 0x33

			Switch 0x65 to produce 0x56

			Switch 0x49 to produce 0x94

			Switch 0x32 to produce 0x23

			When regrouped, we should have something that looks like 0x02|0x34|0x10|0x07|0x33|0x56|0x94|0x23

			Can we use the E212 dissector?
				No, it appears that the current version of the dissector is hard-coded in a way that ignores all of our set-up work. :(

			*/

			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					proto_tree_add_item(tree, hf_isi_sim_imsi_length, tvb, 3, 1, ENC_BIG_ENDIAN);

					/*
					next_tvb = tvb_new_subset(tvb, 0, -1, -1);
					proto_tree_add_item(tree, hf_isi_sim_imsi_byte_1, next_tvb, 4, 1, ENC_LITTLE_ENDIAN);
					dissect_e212_mcc_mnc(next_tvb, pinfo, tree, 4, FALSE );
					proto_tree_add_item(tree, hf_E212_msin, tvb, 2, 7, FALSE);

					*/

					col_set_str(pinfo->cinfo, COL_INFO, "Read IMSI Response");
					break;
			}
			break;

		case 0x21: /* SIM_SERV_PROV_NAME_REQ */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Provider Name Request");
					break;
			}
			break;

		case 0x22: /* SIM_SERV_PROV_NAME_RESP */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x2c:
					proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 1, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_isi_sim_secondary_cause, tvb, 2, 1, ENC_BIG_ENDIAN);
					col_set_str(pinfo->cinfo, COL_INFO, "Service Provider Name Response: Invalid Location");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Provider Name Response");
					break;
			}
			break;

		case 0xBA: /* SIM_READ_FIELD_REQ */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x66:
					col_set_str(pinfo->cinfo, COL_INFO, "Read Field Request: Integrated Circuit Card Identification (ICCID)");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Read Field Request");
					break;
			}
			break;

		case 0xBB: /* SIM_READ_FIELD_RESP */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x66:
					proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 2, 1, ENC_BIG_ENDIAN);
					col_set_str(pinfo->cinfo, COL_INFO, "Read Field Response: Integrated Circuit Card Identification (ICCID)");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Read Field Response");
					break;
			}
			break;

		case 0xBC: /* SIM_SMS_REQ */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Request");
					break;
			}
			break;

		case 0xBD: /* SIM_SMS_RESP */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Response");
					break;
			}
			break;

		case 0xDC: /* SIM_PB_REQ_SIM_PB_READ */

			/* A phonebook record in a typical O2 UK SIM card issued in 2009 can hold:

				* A name encoded in UTF-16/UCS-2 - up to 18 (or 15 double-byte/accented) characters can be entered on an S60 device
				* Up to 2 telephone numbers - up to 2 * 20 (or 40-1 field) characters can be entered on an S60 device
				* An e-mail address encoded in UTF-16/UCS-2 - up to 40 characters can be entered on an S60 device

				Up to 250 of these records can be stored, and 9 of them are pre-populated on a brand new card.

			*/
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_subblock_count, tvb, 2, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_pb_subblock, tvb, 4, 1, ENC_BIG_ENDIAN);

			/* Should probably be 8, and not 2048... Officially starts/ends at 5/3, I think. */
			proto_tree_add_item(tree, hf_isi_sim_subblock_size, tvb, 6, 2, ENC_LITTLE_ENDIAN);

			proto_tree_add_item(tree, hf_isi_sim_pb_type, tvb, 8, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_pb_location, tvb, 9, 2, ENC_BIG_ENDIAN);

			proto_tree_add_item(tree, hf_isi_sim_pb_subblock, tvb, 12, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_subblock_count, tvb, 13, 2, ENC_BIG_ENDIAN);

			proto_tree_add_item(tree, hf_isi_sim_pb_tag_count, tvb, 15, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_pb_type, tvb, 18, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_pb_tag, tvb, 20, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_pb_tag, tvb, 22, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_pb_tag, tvb, 24, 1, ENC_BIG_ENDIAN);

			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Phonebook Read Request");
					break;
			}
			break;

		case 0xDD: /* SIM_PB_RESP_SIM_PB_READ */
			proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Phonebook Read Response");
					break;
			}
			break;

		case 0xEF: /* SIM_IND */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Indicator");
					break;
			}
			break;

		case 0xF0: /* SIM_COMMON_MESSAGE */
			proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sim_secondary_cause, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x00:
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: SIM Server Not Available");
					break;
				case 0x12:
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: PIN Enable OK");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message");
					break;
			}
			break;

		default:
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
			break;
	}
	return tvb_captured_length(tvb);
}

static int dissect_isi_gss(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_) {
	proto_item *item;
	proto_tree *tree;
	guint8 cmd, code;

	item = proto_tree_add_item(isitree, hf_isi_gss_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_gss_message_id, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {
		case 0x00: /* GSS_CS_SERVICE_REQ */
			proto_tree_add_item(tree, hf_isi_gss_operation, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x0E:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Radio Access Type Write");
					break;

				case 0x9C:
					proto_tree_add_item(tree, hf_isi_gss_subblock_count, tvb, 2, 1, ENC_BIG_ENDIAN);
					col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Radio Access Type Read");
					break;

				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Request");
					break;
			}
			break;

		case 0x01: /* GSS_CS_SERVICE_RESP */
			/* proto_tree_add_item(tree, hf_isi_gss_service_type, tvb, 1, 1, FALSE); */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				/* case 0x9C:
					col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					break; */
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Response");
					break;
			}
			break;

		case 0x02: /* GSS_CS_SERVICE_FAIL_RESP */
			proto_tree_add_item(tree, hf_isi_gss_operation, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_gss_cause, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x9C:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Failed Response: Radio Access Type Read");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Failed Response");
					break;
			}
			break;

		case 0xF0: /* Common Message */
			proto_tree_add_item(tree, hf_isi_gss_common_message_id, tvb, 1, 1, ENC_BIG_ENDIAN);
			/* proto_tree_add_item(tree, hf_isi_gss_cause, tvb, 2, 1, ENC_BIG_ENDIAN); */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x01: /* COMM_SERVICE_NOT_IDENTIFIED_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: Service Not Identified Response");
					break;
				case 0x12: /* COMM_ISI_VERSION_GET_REQ */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Request");
					break;
				case 0x13: /* COMM_ISI_VERSION_GET_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Response");
					break;
				case 0x14: /* COMM_ISA_ENTITY_NOT_REACHABLE_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISA Entity Not Reachable");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message");
					break;
			}
			break;


		default:
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
			break;
	}
	return tvb_captured_length(tvb);
}

static void dissect_isi_gps_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *item _U_, proto_tree *tree)
{
	int i;
	double tmp_double;
	float tmp_float;
	int tmp_int32;
	int offset = 0x0b; /* subpackets start here */

	guint8 pkgcount = tvb_get_guint8(tvb, 0x07);
	proto_tree_add_item(tree, hf_isi_gps_sub_pkgs, tvb, 0x07, 1, ENC_BIG_ENDIAN);

	for(i=0; i<pkgcount; i++) {
		guint8 sptype = tvb_get_guint8(tvb, offset+1);
		guint8 splen = tvb_get_guint8(tvb, offset+3);
		proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, offset, splen, ett_isi_msg, NULL, "Subpacket (%s)", val_to_str(sptype, isi_gps_sub_id, "unknown: 0x%x"));

		proto_tree_add_item(subtree, hf_isi_gps_sub_type, tvb, offset+1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isi_gps_sub_len, tvb,  offset+3, 1, ENC_BIG_ENDIAN);

		offset += 4;
		switch(sptype) {
			case 0x02: /* Position */
				tmp_double = tvb_get_ntohl(tvb, offset+0);
				tmp_double = (tmp_double*360)/4294967296.0;
				if(tmp_double > 180.0) tmp_double -= 360.0;
				proto_tree_add_double(subtree, hf_isi_gps_latitude, tvb, offset+0, 4, tmp_double);

				tmp_double = tvb_get_ntohl(tvb, offset+4);
				tmp_double = (tmp_double*360)/4294967296.0;
				if(tmp_double > 180.0) tmp_double -= 360.0;
				proto_tree_add_double(subtree, hf_isi_gps_longitude, tvb, offset+4, 4, tmp_double);

				tmp_float = (float)(tvb_get_ntohl(tvb, offset+12) / 100.0);
				proto_tree_add_float(subtree, hf_isi_gps_eph, tvb, offset+12, 4, tmp_float);

				tmp_int32 = (tvb_get_ntohs(tvb, offset+18) - tvb_get_ntohs(tvb, offset+22))/2;
				proto_tree_add_int(subtree, hf_isi_gps_altitude, tvb, offset+18, 6, tmp_int32);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+20) / 2.0);
				proto_tree_add_float(subtree, hf_isi_gps_epv, tvb, offset+20, 2, tmp_float);

				break;
			case 0x03: /* Date and Time */
				proto_tree_add_item(subtree, hf_isi_gps_year,    tvb, offset+0, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_month,   tvb, offset+2, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_day,     tvb, offset+3, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_hour,    tvb, offset+5, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_minute,  tvb, offset+6, 1, ENC_BIG_ENDIAN);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+8) / 1000.0);
				proto_tree_add_float(subtree, hf_isi_gps_second, tvb, offset+8, 2, tmp_float);
				break;
			case 0x04: /* Movement */
				tmp_float = (float)(tvb_get_ntohs(tvb, offset+0) / 100.0);
				proto_tree_add_float(subtree, hf_isi_gps_course, tvb, offset+0, 2, tmp_float);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+2) / 100.0);
				proto_tree_add_float(subtree, hf_isi_gps_epd, tvb, offset+2, 2, tmp_float);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+6) * CMS_TO_KMH);
				proto_tree_add_float(subtree, hf_isi_gps_speed, tvb, offset+6, 2, tmp_float);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+8) * CMS_TO_KMH);
				proto_tree_add_float(subtree, hf_isi_gps_eps, tvb, offset+8, 2, tmp_float);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+10) * CMS_TO_KMH);
				proto_tree_add_float(subtree, hf_isi_gps_climb, tvb, offset+10, 2, tmp_float);

				tmp_float = (float)(tvb_get_ntohs(tvb, offset+12) * CMS_TO_KMH);
				proto_tree_add_float(subtree, hf_isi_gps_epc, tvb, offset+12, 2, tmp_float);
				break;
			case 0x05: /* Satellite Info */
				{
				guint8 satellites = tvb_get_guint8(tvb, offset+0);
				int sat;
				proto_tree_add_item(subtree, hf_isi_gps_satellites, tvb, offset+0, 1, ENC_BIG_ENDIAN);

				for(sat = 0; sat < satellites ; sat++) {
					int pos = offset+4+(sat*SAT_PKG_LEN);
					proto_tree *sattree = proto_tree_add_subtree_format(subtree, tvb, pos, SAT_PKG_LEN, ett_isi_msg, NULL, "Satellite %d", sat);

					float signal_strength = (float)(tvb_get_ntohs(tvb, pos+3) / 100.0);
					float elevation       = (float)(tvb_get_ntohs(tvb, pos+6) / 100.0);
					float azimuth         = (float)(tvb_get_ntohs(tvb, pos+8) / 100.0);

					proto_tree_add_item(sattree, hf_isi_gps_prn,            tvb, pos+1, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(sattree, hf_isi_gps_sat_used,       tvb, pos+2, 1, ENC_BIG_ENDIAN);
					proto_tree_add_float(sattree, hf_isi_gps_sat_strength,  tvb, pos+3, 2, signal_strength);
					proto_tree_add_float(sattree, hf_isi_gps_sat_elevation, tvb, pos+6, 2, elevation);
					proto_tree_add_float(sattree, hf_isi_gps_sat_azimuth,   tvb, pos+8, 2, azimuth);
				}
				}
				break;
			case 0x07: /* CellInfo GSM */
				proto_tree_add_item(subtree, hf_isi_gps_mcc,  tvb, offset+0, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_mnc,  tvb, offset+2, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_lac,  tvb, offset+4, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_cid,  tvb, offset+6, 2, ENC_BIG_ENDIAN);
				break;
			case 0x08: /* CellInfo WCDMA */
				proto_tree_add_item(subtree, hf_isi_gps_mcc,  tvb, offset+0, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_mnc,  tvb, offset+2, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_gps_ucid, tvb, offset+4, 4, ENC_BIG_ENDIAN);
				break;
			default:
				break;
		}

		offset += splen - 4;
	}

}

static int dissect_isi_gps(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_)
{
	proto_item *item;
	proto_tree *tree;
	guint8 cmd;

	item = proto_tree_add_item(isitree, hf_isi_gps_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_gps_cmd, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {
		case 0x7d: /* GPS Status */
			proto_tree_add_item(tree, hf_isi_gps_status, tvb, 2, 1, ENC_BIG_ENDIAN);
			col_add_fstr(pinfo->cinfo, COL_INFO, "GPS Status Indication: %s", val_to_str(tvb_get_guint8(tvb, 2), isi_gps_status, "unknown (0x%x)"));
			break;
		case 0x84:
		case 0x85:
		case 0x86:
		case 0x87:
		case 0x88:
		case 0x89:
		case 0x8a:
		case 0x8b:
			col_add_fstr(pinfo->cinfo, COL_INFO, "unknown A-GPS packet (0x%02x)", cmd);
			break;
		case 0x90: /* GPS Power Request */
			col_set_str(pinfo->cinfo, COL_INFO, "GPS Power Request");
			break;
		case 0x91: /* GPS Power Request */
			col_set_str(pinfo->cinfo, COL_INFO, "GPS Power Response");
			break;
		case 0x92: /* GPS Data */
			col_set_str(pinfo->cinfo, COL_INFO, "GPS Data");
			dissect_isi_gps_data(tvb, pinfo, item, tree);
			break;
		default:
			col_add_fstr(pinfo->cinfo, COL_INFO, "unknown GPS packet (0x%02x)", cmd);
			break;
	}
	return tvb_captured_length(tvb);
}

static int dissect_isi_ss(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_)
{
	proto_item *item;
	proto_tree *tree;
	guint8 cmd, code;

	item = proto_tree_add_item(isitree, hf_isi_ss_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_ss_message_id, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {
		case 0x00: /* SS_SERVICE_REQ */
			proto_tree_add_item(tree, hf_isi_ss_operation, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_ss_service_code, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x05:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Interrogation");
					break;
				case 0x06:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Request: GSM Password Registration");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Request");
					break;
			}
			break;

		case 0x01: /* SS_SERVICE_COMPLETED_RESP */
			proto_tree_add_item(tree, hf_isi_ss_operation, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_ss_service_code, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x05:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Response: Interrogation");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Response");
					break;
			}
			break;

		case 0x02: /* SS_SERVICE_FAILED_RESP */
			/* proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE); */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				/* case 0x2F:
				   col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
				   break;
				*/
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Failed Response");
					break;
			}
			break;

		case 0x04: /* SS_GSM_USSD_SEND_REQ */
			proto_tree_add_item(tree, hf_isi_ss_ussd_type, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_ss_subblock_count, tvb, 2, 1, ENC_BIG_ENDIAN);

			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x02: /* SS_GSM_USSD_COMMAND */
					proto_tree_add_item(tree, hf_isi_ss_subblock, tvb, 3, 1, ENC_BIG_ENDIAN);
					col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Send Command Request");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Send Request");
					break;
			}
			break;

		case 0x05: /* SS_GSM_USSD_SEND_RESP */
			/* proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE); */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				/* case 0x2F:
					col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					break; */
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Send Response");
					break;
			}
			break;

		case 0x06: /* SS_GSM_USSD_RECEIVE_IND */
			/* An unknown Encoding Information byte precedes - see 3GPP TS 23.038 chapter 5 */
			proto_tree_add_item(tree, hf_isi_ss_ussd_type, tvb, 2, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_ss_ussd_length, tvb, 3, 1, ENC_BIG_ENDIAN);

			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x04:



					col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Received Notification");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Received Indication");
					break;
			}
			break;

		case 0x09: /* SS_STATUS_IND */
			proto_tree_add_item(tree, hf_isi_ss_status_indication, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_ss_subblock_count, tvb, 2, 1, ENC_BIG_ENDIAN);
			/* proto_tree_add_item(tree, hf_isi_ss_subblock, tvb, 3, 1, ENC_BIG_ENDIAN); */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x00:
					col_set_str(pinfo->cinfo, COL_INFO, "Status Indication: Request Service Start");
					break;
				case 0x01:
					col_set_str(pinfo->cinfo, COL_INFO, "Status Indication: Request Service Stop");
					break;
				case 0x02:
					col_set_str(pinfo->cinfo, COL_INFO, "Status Indication: Request USSD Start");
					break;
				case 0x03:
					col_set_str(pinfo->cinfo, COL_INFO, "Status Indication: Request USSD Stop");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Status Indication");
					break;
			}
			break;

		case 0x10: /* SS_SERVICE_COMPLETED_IND */
			proto_tree_add_item(tree, hf_isi_ss_operation, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_ss_service_code, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x05:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Indication: Interrogation");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Indication");
					break;
			}
			break;

		case 0xF0: /* SS_COMMON_MESSAGE */
			proto_tree_add_item(tree, hf_isi_ss_common_message_id, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x01: /* COMM_SERVICE_NOT_IDENTIFIED_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: Service Not Identified Response");
					break;
				case 0x12: /* COMM_ISI_VERSION_GET_REQ */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Request");
					break;
				case 0x13: /* COMM_ISI_VERSION_GET_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Response");
					break;
				case 0x14: /* COMM_ISA_ENTITY_NOT_REACHABLE_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISA Entity Not Reachable");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message");
					break;
			}
			break;


		default:
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
			break;
	}
	return tvb_captured_length(tvb);
}

static void dissect_isi_network_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *item _U_, proto_tree *tree)
{
	int i;
	int offset = 0x03; /* subpackets start here */
	guint16 len;

	guint8 pkgcount = tvb_get_guint8(tvb, 0x02);
	proto_tree_add_item(tree, hf_isi_network_data_sub_pkgs, tvb, 0x02, 1, ENC_BIG_ENDIAN);

	for(i=0; i<pkgcount; i++) {
		guint8 sptype = tvb_get_guint8(tvb, offset+0);
		guint8 splen = tvb_get_guint8(tvb, offset+1);

		proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, offset, splen, ett_isi_msg, NULL, "Subpacket (%s)", val_to_str(sptype, isi_network_status_sub_id, "unknown: 0x%x"));

		proto_tree_add_item(subtree, hf_isi_network_status_sub_type, tvb, offset+0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isi_network_status_sub_len, tvb,  offset+1, 1, ENC_BIG_ENDIAN);

		offset += 2;

		switch(sptype) {
			case 0x00: /* NET_REG_INFO_COMMON */
				/* FIXME: TODO */
				break;
			case 0x09: /* NET_GSM_REG_INFO */
				proto_tree_add_item(subtree, hf_isi_network_status_sub_lac, tvb, offset+0, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_network_status_sub_cid, tvb, offset+4, 4, ENC_BIG_ENDIAN);
				/* FIXME: TODO */
				break;
			case 0xe3: /* UNKNOWN */
				/* FIXME: TODO: byte 0: message type (provider name / network name) ? */

				len = tvb_get_ntohs(tvb, offset+2);
				proto_tree_add_item(subtree, hf_isi_network_status_sub_msg_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);

				proto_tree_add_item(subtree, hf_isi_network_status_sub_msg, tvb, offset+4, len*2, ENC_UTF_16|ENC_BIG_ENDIAN);
				break;
			default:
				break;
		}

		offset += splen - 2;
	}
}

static void dissect_isi_network_cell_info_ind(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	int i;
	int offset = 0x03;
	guint8 pkgcount = tvb_get_guint8(tvb, 0x02);

	static const int *gsm_band_fields[] = {
		&hf_isi_network_gsm_band_900,
		&hf_isi_network_gsm_band_1800,
		&hf_isi_network_gsm_band_1900,
		&hf_isi_network_gsm_band_850,
		NULL
	};

	proto_tree_add_item(tree, hf_isi_network_data_sub_pkgs, tvb, 0x02, 1, ENC_BIG_ENDIAN);

	for(i=0; i<pkgcount; i++) {
		guint8 sptype = tvb_get_guint8(tvb, offset+0);
		guint8 splen = tvb_get_guint8(tvb, offset+1);

		proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, offset, splen, ett_isi_msg, NULL, "Subpacket (%s)", val_to_str(sptype, isi_network_cell_info_sub_id, "unknown: 0x%x"));

		proto_tree_add_item(subtree, hf_isi_network_cell_info_sub_type, tvb, offset+0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isi_network_cell_info_sub_len, tvb,  offset+1, 1, ENC_BIG_ENDIAN);

		offset += 2;

		switch(sptype) {
			case 0x50: /* NET_EPS_CELL_INFO */
				/* TODO: not yet implemented */
				expert_add_info(pinfo, item, &ei_isi_unsupported_packet);
				break;
			case 0x46: /* NET_GSM_CELL_INFO */
				proto_tree_add_item(subtree, hf_isi_network_status_sub_lac, tvb, offset+0, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_isi_network_status_sub_cid, tvb, offset+2, 4, ENC_BIG_ENDIAN);
				proto_tree_add_bitmask_text(subtree, tvb, offset+6, 4, "GSM Bands: ", "all bands, since none is selected", ett_isi_network_gsm_band_info, gsm_band_fields, FALSE, BMT_NO_FALSE | BMT_NO_TFS);
				proto_tree_add_item(subtree, hf_isi_network_cell_info_sub_operator, tvb, offset+10, 3, ENC_BIG_ENDIAN);
				/* TODO: analysis of the following 5 bytes (which were 0x00 in my dumps) */
				break;
			case 0x47: /* NET_WCDMA_CELL_INFO */
				/* TODO: not yet implemented */
				expert_add_info(pinfo, item, &ei_isi_unsupported_packet);
				break;
			default:
				expert_add_info(pinfo, item, &ei_isi_unsupported_packet);
				break;
		}

		offset += splen - 2;
	}
}

static int dissect_isi_network(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_) {
	proto_item *item;
	proto_tree *tree;
	guint8 cmd;

	item = proto_tree_add_item(isitree, hf_isi_network_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_network_cmd, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {
		case 0x07:
			col_set_str(pinfo->cinfo, COL_INFO, "Network Selection Request");
			expert_add_info(pinfo, item, &ei_isi_unsupported_packet);
			break;
		case 0x20:
			col_set_str(pinfo->cinfo, COL_INFO, "Network Ciphering Indication");
			expert_add_info(pinfo, item, &ei_isi_unsupported_packet);
			break;
		case 0xE2:
			col_set_str(pinfo->cinfo, COL_INFO, "Network Status Indication");
			dissect_isi_network_status(tvb, pinfo, item, tree);
			break;
		case 0x42:
			col_set_str(pinfo->cinfo, COL_INFO, "Network Cell Info Indication");
			dissect_isi_network_cell_info_ind(tvb, pinfo, item, tree);
			break;
		default:
			col_set_str(pinfo->cinfo, COL_INFO, "unknown Network packet");
			expert_add_info(pinfo, item, &ei_isi_unsupported_packet);
			break;
	}
	return tvb_captured_length(tvb);
}

static int dissect_isi_sms(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree, void* data _U_) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	item = proto_tree_add_item(isitree, hf_isi_sms_payload, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_isi_msg);

	proto_tree_add_item(tree, hf_isi_sms_message_id, tvb, 0, 1, ENC_BIG_ENDIAN);
	cmd = tvb_get_guint8(tvb, 0);

	switch(cmd) {
		case 0x03: /* SMS_MESSAGE_SEND_RESP */
			proto_tree_add_item(tree, hf_isi_sms_subblock_count, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
#if 0
				case 0x05:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Interrogation");
						break;
				case 0x06:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: GSM Password Registration");
						break;
#endif
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Send Response");
					break;
			}
			break;

		case 0x06: /* SMS_PP_ROUTING_REQ */
			proto_tree_add_item(tree, hf_isi_sms_routing_command, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sms_subblock_count, tvb, 2, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
#if 0
				case 0x05:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Interrogation");
						break;
				case 0x06:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: GSM Password Registration");
						break;
#endif
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Point-to-Point Routing Request");
					break;
			}
			break;

		case 0x07: /* SMS_PP_ROUTING_RESP */
			/* proto_tree_add_item(tree, hf_isi_sms_service_type, tvb, 1, 1, FALSE); */
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
					/* case 0x2F:
						col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
						break; */
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Point-to-Point Routing Response");
					break;
			}
			break;

		case 0x0B: /* SMS_GSM_CB_ROUTING_REQ */
			proto_tree_add_item(tree, hf_isi_sms_routing_command, tvb, 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_isi_sms_routing_mode, tvb, 2, 1, ENC_BIG_ENDIAN);
#if 0
				proto_tree_add_item(tree, hf_isi_sms_cb_subject_list_type, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sms_cb_subject_count, tvb, 4, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sms_cb_language_count, tvb, 5, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sms_cb_range, tvb, 6, 1, FALSE);
#endif
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x00:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Release");
					break;
				case 0x01:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Set");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Request");
					break;
			}
			break;

		case 0x0C: /* SMS_GSM_CB_ROUTING_RESP */
#if 0
				proto_tree_add_item(tree, hf_isi_sms_operation, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sms_service_code, tvb, 2, 1, FALSE);
#endif
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
					/* case 0x05:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Response: Interrogation");
						break; */
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Response");
					break;
			}
			break;

		case 0x22: /* SMS_MESSAGE_SEND_STATUS_IND */
			proto_tree_add_item(tree, hf_isi_sms_send_status, tvb, 1, 1, ENC_BIG_ENDIAN);
			/* The second byte is a "segment" identifier/"Message Reference" */
			proto_tree_add_item(tree, hf_isi_sms_route, tvb, 3, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x02:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Sending Status: Waiting for Network");
					break;
				case 0x03:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Sending Status: Idle");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Sending Status Indication");
					break;
			}
			break;

		case 0xF0: /* SS_COMMON_MESSAGE */
			proto_tree_add_item(tree, hf_isi_sms_common_message_id, tvb, 1, 1, ENC_BIG_ENDIAN);
			code = tvb_get_guint8(tvb, 1);
			switch(code) {
				case 0x01: /* COMM_SERVICE_NOT_IDENTIFIED_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: Service Not Identified Response");
					break;
				case 0x12: /* COMM_ISI_VERSION_GET_REQ */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Request");
					break;
				case 0x13: /* COMM_ISI_VERSION_GET_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Response");
					break;
				case 0x14: /* COMM_ISA_ENTITY_NOT_REACHABLE_RESP */
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISA Entity Not Reachable");
					break;
				default:
					col_set_str(pinfo->cinfo, COL_INFO, "Common Message");
					break;
			}
			break;

		default:
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
			break;
	}
	return tvb_captured_length(tvb);
}

static int dissect_isi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
	proto_tree *isi_tree;
	proto_item *item, *item_len;
	tvbuff_t *content_tvb;

	guint8 src;
	guint8 dst;
	guint8 resource;
	guint16 length;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISI");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Start with a top-level item to add everything else to */
	item = proto_tree_add_item(tree, proto_isi, tvb, 0, -1, ENC_NA);
	isi_tree = proto_item_add_subtree(item, ett_isi);

	/* Common Phonet/ISI Header */
	proto_tree_add_item(isi_tree, hf_isi_rdev, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(isi_tree, hf_isi_sdev, tvb, 1, 1, ENC_NA);
	proto_tree_add_item(isi_tree, hf_isi_res,  tvb, 2, 1, ENC_NA);
	item_len = proto_tree_add_item(isi_tree, hf_isi_len,  tvb, 3, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(isi_tree, hf_isi_robj, tvb, 5, 1, ENC_NA);
	proto_tree_add_item(isi_tree, hf_isi_sobj, tvb, 6, 1, ENC_NA);
	proto_tree_add_item(isi_tree, hf_isi_id,   tvb, 7, 1, ENC_NA);

	length = tvb_get_ntohs(tvb, 3) - 3;
	resource = tvb_get_guint8(tvb, 2);
	dst = tvb_get_guint8(tvb, 0);
	src = tvb_get_guint8(tvb, 1);

	if (tvb_reported_length(tvb) - 8 < length) {
		expert_add_info_format(pinfo, item_len, &ei_isi_len, "Broken Length (%d > %d)", length, tvb_reported_length(tvb)-8);
		length = tvb_reported_length(tvb) - 8;
	}

	col_set_str(pinfo->cinfo, COL_DEF_SRC, val_to_str_const(src, hf_isi_device, "Unknown"));
	col_set_str(pinfo->cinfo, COL_DEF_DST, val_to_str_const(dst, hf_isi_device, "Unknown"));

	content_tvb = tvb_new_subset_length(tvb, 8, length);

	/* Call subdissector depending on the resource ID */
	if (!dissector_try_uint(isi_resource_dissector_table, resource, content_tvb, pinfo, isi_tree))
		call_data_dissector(content_tvb, pinfo, isi_tree);

	return tvb_captured_length(tvb);
}

/* Experimental approach based upon the one used for PPP*/
static gboolean dissect_usb_isi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	tvbuff_t *next_tvb;

	if(tvb_get_guint8(tvb, 0) != 0x1B)
		return FALSE;

	next_tvb = tvb_new_subset_remaining(tvb, 1);
	dissect_isi(next_tvb, pinfo, tree, data);

	return TRUE;
}

void
proto_register_isi(void)
{
	static hf_register_info hf[] = {
		{ &hf_isi_rdev,
		  { "Receiver Device", "isi.rdev", FT_UINT8, BASE_HEX,
		    VALS(hf_isi_device), 0x0, NULL, HFILL }},
		{ &hf_isi_sdev,
		  { "Sender Device", "isi.sdev", FT_UINT8, BASE_HEX,
		    VALS(hf_isi_device), 0x0, NULL, HFILL }},
		{ &hf_isi_res,
		  { "Resource", "isi.res", FT_UINT8, BASE_HEX,
		    VALS(hf_isi_resource), 0x0, NULL, HFILL }},
		{ &hf_isi_len,
		  { "Length", "isi.len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_robj,
		  { "Receiver Object", "isi.robj", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sobj,
		  { "Sender Object", "isi.sobj", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_id,
		  { "Packet ID", "isi.id", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }}
    };

	static hf_register_info simauth_hf[] = {
		{ &hf_isi_sim_auth_payload,
		  { "Payload", "isi.sim.auth.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_cmd,
		  { "Command", "isi.sim.auth.cmd", FT_UINT8, BASE_HEX, VALS(isi_sim_auth_id), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_pw_type,
		  { "Password Type", "isi.sim.auth.type", FT_UINT8, BASE_HEX, VALS(isi_sim_auth_pw_type), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_pin,
		  { "PIN", "isi.sim.auth.pin", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_puk,
		  { "PUK", "isi.sim.auth.puk", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_new_pin,
		  { "New PIN", "isi.sim.auth.new_pin", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_protection_req,
		  { "Protection Request", "isi.sim.auth.request.protection", FT_UINT8, BASE_HEX, VALS(isi_sim_auth_protection_req), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_protection_rsp,
		  { "Protection Response", "isi.sim.auth.response.protection", FT_BOOLEAN, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_status_rsp,
		  { "Status Response", "isi.sim.auth.response.status", FT_UINT8, BASE_HEX, VALS(isi_sim_auth_resp), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_indication,
		  { "Indication", "isi.sim.auth.indication", FT_UINT8, BASE_HEX, VALS(isi_sim_auth_indication), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_auth_indication_cfg,
		  { "Configuration", "isi.sim.auth.cfg", FT_UINT8, BASE_HEX, VALS(isi_sim_auth_indication_cfg), 0x0, NULL, HFILL }}
	};

	static hf_register_info sim_hf[] = {
		{ &hf_isi_sim_payload,
		  { "Payload", "isi.sim.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_message_id,
		  { "Message ID", "isi.sim.msg_id", FT_UINT8, BASE_HEX, VALS(isi_sim_message_id), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_service_type,
		  { "Service Type", "isi.sim.service_type", FT_UINT8, BASE_HEX, VALS(isi_sim_service_type), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_cause,
		  { "Cause", "isi.sim.cause", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &isi_sim_cause_ext, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_secondary_cause,
		  { "Secondary Cause", "isi.sim.secondary_cause", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &isi_sim_cause_ext, 0x0, NULL, HFILL }},
		{&hf_isi_sim_subblock_count,
		  { "Subblock Count", "isi.sim.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{&hf_isi_sim_subblock_size,
		  { "Subblock Size", "isi.sim.subblock_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_pb_subblock,
		  { "Subblock", "isi.sim.pb.subblock", FT_UINT8, BASE_HEX, VALS(isi_sim_pb_subblock), 0x0, NULL, HFILL }},
		{ &hf_isi_sim_pb_type,
		  { "Phonebook Type", "isi.sim.pb.type", FT_UINT8, BASE_HEX, VALS(isi_sim_pb_type), 0x0, NULL, HFILL }},
		{&hf_isi_sim_pb_location,
		  { "Phonebook Location", "isi.sim.pb.location", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{&hf_isi_sim_pb_tag_count,
		  { "Tag Count", "isi.sim.pb.tag.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sim_pb_tag,
		  { "Phonebook Item Type", "isi.sim.pb.tag", FT_UINT8, BASE_HEX, VALS(isi_sim_pb_tag), 0x0, NULL, HFILL }},
		/* {&hf_isi_sim_imsi_byte_1,
		  { "IMSI Byte 1", "isi.sim.imsi.byte1", FT_UINT16, BASE_HEX, NULL, 0xF0, NULL, HFILL }},*/
		{&hf_isi_sim_imsi_length,
		  { "IMSI Length", "isi.sim.imsi.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	};

	static hf_register_info gps_hf[] = {
		{ &hf_isi_gps_payload,
		  { "Payload", "isi.gps.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_cmd,
		  { "Command", "isi.gps.cmd", FT_UINT8, BASE_HEX, VALS(isi_gps_id), 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sub_pkgs,
		  { "Number of Subpackets", "isi.gps.pkgs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sub_type,
		  { "Subpacket Type", "isi.gps.sub.type", FT_UINT8, BASE_HEX, VALS(isi_gps_sub_id), 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sub_len,
		  { "Subpacket Length", "isi.gps.sub.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_status,
		  { "Status", "isi.gps.status", FT_UINT8, BASE_HEX, VALS(isi_gps_status), 0x0, NULL, HFILL }},
		{ &hf_isi_gps_year,
		  { "Year", "isi.gps.date.year", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_month,
		  { "Month", "isi.gps.date.month", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_day,
		  { "Day", "isi.gps.date.day", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_hour,
		  { "Hour", "isi.gps.time.hour", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_minute,
		  { "Minute", "isi.gps.time.minute", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_second,
		  { "Second", "isi.gps.time.second", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_latitude,
		  { "Latitude", "isi.gps.lat", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_longitude,
		  { "Longitude", "isi.gps.lon", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_eph,
		  { "Position Accuracy", "isi.gps.eph", FT_FLOAT, BASE_NONE, NULL, 0x0, "EPH (position accuracy) in meter", HFILL }},
		{ &hf_isi_gps_altitude,
		  { "Altitude", "isi.gps.alt", FT_INT16, BASE_DEC, NULL, 0x0, "Altitude in meter", HFILL }},
		{ &hf_isi_gps_epv,
		  { "Altitude Accuracy", "isi.gps.epv", FT_FLOAT, BASE_NONE, NULL, 0x0, "EPV (altitude accuracy) in meter", HFILL }},
		{ &hf_isi_gps_course,
		  { "Course", "isi.gps.course", FT_FLOAT, BASE_NONE, NULL, 0x0, "Course in degree", HFILL }},
		{ &hf_isi_gps_epd,
		  { "Course Accuracy", "isi.gps.epd", FT_FLOAT, BASE_NONE, NULL, 0x0, "EPD (course accuracy) in degree", HFILL }},
		{ &hf_isi_gps_speed,
		  { "Speed", "isi.gps.speed", FT_FLOAT, BASE_NONE, NULL, 0x0, "Speed in km/h", HFILL }},
		{ &hf_isi_gps_eps,
		  { "Speed Accuracy", "isi.gps.eps", FT_FLOAT, BASE_NONE, NULL, 0x0, "EPS (speed accuracy) in km/h", HFILL }},
		{ &hf_isi_gps_climb,
		  { "Climb", "isi.gps.climb", FT_FLOAT, BASE_NONE, NULL, 0x0, "Climb in km/h", HFILL }},
		{ &hf_isi_gps_satellites,
		  { "Visible Satellites", "isi.gps.satellites", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_prn,
		  { "Pseudorandom Noise (PRN)", "isi.gps.sat.prn", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sat_used,
		  { "in use", "isi.gps.sat.used", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sat_strength,
		  { "Signal Strength", "isi.gps.sat.strength", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sat_elevation,
		  { "Elevation", "isi.gps.sat.elevation", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_sat_azimuth,
		  { "Azimuth", "isi.gps.sat.azimuth", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_epc,
		  { "Climb Accuracy", "isi.gps.epc", FT_FLOAT, BASE_NONE, NULL, 0x0, "EPC (climb accuracy) in km/h", HFILL }},
		{ &hf_isi_gps_mcc,
		  { "Mobile Country Code (MCC)", "isi.gps.gsm.mcc", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_mnc,
		  { "Mobile Network Code (MNC)", "isi.gps.gsm.mnc", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_lac,
		  { "Location Area Code (LAC)", "isi.gps.gsm.lac", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_cid,
		  { "Cell ID (CID)", "isi.gps.gsm.cid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gps_ucid,
		  { "Cell ID (UCID)", "isi.gps.gsm.ucid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }}
	};

	static hf_register_info gss_hf[] = {
		{ &hf_isi_gss_payload,
		  { "Payload", "isi.gss.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gss_message_id,
		  { "Message ID", "isi.gss.msg_id", FT_UINT8, BASE_HEX, VALS(isi_gss_message_id), 0x0, NULL, HFILL }},
#if 0
		{ &hf_isi_gss_subblock,
		  { "Subblock", "isi.gss.subblock", FT_UINT8, BASE_HEX, VALS(isi_gss_subblock), 0x0, NULL, HFILL }},
#endif
		{ &hf_isi_gss_operation,
		  { "Operation", "isi.gss.operation", FT_UINT8, BASE_HEX, VALS(isi_gss_operation), 0x0, NULL, HFILL }},
		{ &hf_isi_gss_subblock_count,
		  { "Subblock Count", "isi.gss.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_gss_cause,
		  { "Cause", "isi.gss.cause", FT_UINT8, BASE_HEX, VALS(isi_gss_cause), 0x0, NULL, HFILL }},
		{ &hf_isi_gss_common_message_id,
		  { "Common Message ID", "isi.gss.common.msg_id", FT_UINT8, BASE_HEX, VALS(isi_gss_common_message_id), 0x0, NULL, HFILL }},
	};

	static hf_register_info ss_hf[] = {
		{ &hf_isi_ss_payload,
		  { "Payload", "isi.ss.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_ss_message_id,
		  { "Message ID", "isi.ss.msg_id", FT_UINT8, BASE_HEX, VALS(isi_ss_message_id), 0x0, NULL, HFILL }},
		{ &hf_isi_ss_ussd_type,
		  { "USSD Type", "isi.ss.ussd.type", FT_UINT8, BASE_HEX, VALS(isi_ss_ussd_type), 0x0, NULL, HFILL }},
		{ &hf_isi_ss_subblock_count,
		  { "Subblock Count", "isi.ss.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_ss_subblock,
		  { "Subblock", "isi.ss.subblock", FT_UINT8, BASE_HEX, VALS(isi_ss_subblock), 0x0, NULL, HFILL }},
		{ &hf_isi_ss_operation,
		  { "Operation", "isi.ss.operation", FT_UINT8, BASE_HEX, VALS(isi_ss_operation), 0x0, NULL, HFILL }},
		{ &hf_isi_ss_service_code,
		  { "Service Code", "isi.ss.service_code", FT_UINT8, BASE_HEX, VALS(isi_ss_service_code), 0x0, NULL, HFILL }},
		{ &hf_isi_ss_status_indication,
		  { "Status Indication", "isi.ss.status_indication", FT_UINT8, BASE_HEX, VALS(isi_ss_status_indication), 0x0, NULL, HFILL }},
		{ &hf_isi_ss_ussd_length,
		  { "Length", "isi.ss.ussd.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_ss_common_message_id,
		  { "Common Message ID", "isi.ss.common.msg_id", FT_UINT8, BASE_HEX, VALS(isi_ss_common_message_id), 0x0, NULL, HFILL }},
	};

	static hf_register_info network_hf[] = {
		{ &hf_isi_network_payload,
		  { "Payload", "isi.network.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_cmd,
		  { "Command", "isi.network.cmd", FT_UINT8, BASE_HEX, VALS(isi_network_id), 0x0, NULL, HFILL }},
		{ &hf_isi_network_data_sub_pkgs,
		  { "Number of Subpackets", "isi.network.pkgs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_status_sub_type,
		  { "Subpacket Type", "isi.network.sub.type", FT_UINT8, BASE_HEX, VALS(isi_network_status_sub_id), 0x0, NULL, HFILL }},
		{ &hf_isi_network_status_sub_len,
		  { "Subpacket Length", "isi.network.sub.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_status_sub_lac,
		  { "Location Area Code (LAC)", "isi.network.sub.lac", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_status_sub_cid,
		  { "Cell ID (CID)", "isi.network.sub.cid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_status_sub_msg_len,
		  { "Message Length", "isi.network.sub.msg_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_status_sub_msg,
		  { "Message", "isi.network.sub.msg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_cell_info_sub_type,
		  { "Subpacket Type", "isi.network.sub.type", FT_UINT8, BASE_HEX, VALS(isi_network_cell_info_sub_id), 0x0, NULL, HFILL }},
		{ &hf_isi_network_cell_info_sub_len,
		  { "Subpacket Length", "isi.network.sub.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_cell_info_sub_operator,
		  { "Operator Code", "isi.network.sub.operator", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_network_gsm_band_900,
		  { "900 Mhz Band", "isi.network.sub.gsm_band_900", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }},
		{ &hf_isi_network_gsm_band_1800,
		  { "1800 Mhz Band", "isi.network.sub.gsm_band_1800", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }},
		{ &hf_isi_network_gsm_band_1900,
		  { "1900 Mhz Band", "isi.network.sub.gsm_band_1900", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }},
		{ &hf_isi_network_gsm_band_850,
		  { "850 Mhz Band", "isi.network.sub.gsm_band_850", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }}
	};

	static hf_register_info sms_hf[] = {
		{ &hf_isi_sms_payload,
		  { "Payload", "isi.sms.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sms_message_id,
		  { "Message ID", "isi.sms.msg_id", FT_UINT8, BASE_HEX, VALS(isi_sms_message_id), 0x0, NULL, HFILL }},
		{ &hf_isi_sms_routing_command,
		  { "SMS Routing Command", "isi.sms.routing.command", FT_UINT8, BASE_HEX, VALS(isi_sms_routing_command), 0x0, NULL, HFILL }},
		{ &hf_isi_sms_routing_mode,
		  { "Routing Mode", "isi.sms.routing.mode", FT_UINT8, BASE_HEX, VALS(isi_sms_routing_mode), 0x0, NULL, HFILL }},
		{ &hf_isi_sms_route,
		  { "Message Route", "isi.sms.route", FT_UINT8, BASE_HEX, VALS(isi_sms_route), 0x0, NULL, HFILL }},
		{ &hf_isi_sms_subblock_count,
		  { "Subblock Count", "isi.sms.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isi_sms_send_status,
		  { "Sending Status", "isi.sms.sending_status", FT_UINT8, BASE_HEX, VALS(isi_sms_send_status), 0x0, NULL, HFILL }},
#if 0
		{ &hf_isi_sms_subblock,
		  { "Subblock", "isi.sms.subblock", FT_UINT8, BASE_HEX, VALS(isi_sms_subblock), 0x0, NULL, HFILL }},
#endif
		{ &hf_isi_sms_common_message_id,
		  { "Common Message ID", "isi.sms.common.msg_id", FT_UINT8, BASE_HEX, VALS(isi_sms_common_message_id), 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_isi,
		&ett_isi_msg,
		&ett_isi_network_gsm_band_info
	};

	static ei_register_info ei[] = {
		{ &ei_isi_len, { "isi.len.invalid", PI_PROTOCOL, PI_WARN, "Broken Length", EXPFILL }},
		{ &ei_isi_unsupported_packet, { "isi.unsupported_packet", PI_UNDECODED, PI_WARN, "Unsupported packet", EXPFILL }},
	};

	expert_module_t* expert_isi;

	proto_isi = proto_register_protocol("Intelligent Service Interface", "ISI", "isi");

	proto_register_field_array(proto_isi, hf, array_length(hf));
	proto_register_field_array(proto_isi, simauth_hf, array_length(simauth_hf));
	proto_register_field_array(proto_isi, sim_hf, array_length(sim_hf));
	proto_register_field_array(proto_isi, gss_hf, array_length(gss_hf));
	proto_register_field_array(proto_isi, gps_hf, array_length(gps_hf));
	proto_register_field_array(proto_isi, ss_hf, array_length(ss_hf));
	proto_register_field_array(proto_isi, network_hf, array_length(network_hf));
	proto_register_field_array(proto_isi, sms_hf, array_length(sms_hf));

	proto_register_subtree_array(ett, array_length(ett));
	expert_isi = expert_register_protocol(proto_isi);
	expert_register_field_array(expert_isi, ei, array_length(ei));

	/* create new dissector table for isi resource */
	isi_resource_dissector_table = register_dissector_table("isi.resource", "ISI resource", proto_isi, FT_UINT8, BASE_HEX);
}

/* Handler registration */
void
proto_reg_handoff_isi(void)
{
	static gboolean initialized=FALSE;

	if(!initialized) {
		dissector_add_uint("sll.ltype", LINUX_SLL_P_ISI, create_dissector_handle(dissect_isi, proto_isi));

		heur_dissector_add("usb.bulk", dissect_usb_isi, "ISI bulk endpoint", "usb_bulk_isi", proto_isi, HEURISTIC_DISABLE);

		dissector_add_uint("isi.resource", 0x02, create_dissector_handle(dissect_isi_sms, proto_isi));
		dissector_add_uint("isi.resource", 0x06, create_dissector_handle(dissect_isi_ss, proto_isi));
		dissector_add_uint("isi.resource", 0x08, create_dissector_handle(dissect_isi_sim_auth, proto_isi));
		dissector_add_uint("isi.resource", 0x09, create_dissector_handle(dissect_isi_sim, proto_isi));
		dissector_add_uint("isi.resource", 0x0a, create_dissector_handle(dissect_isi_network, proto_isi));
		dissector_add_uint("isi.resource", 0x32, create_dissector_handle(dissect_isi_gss, proto_isi));
		dissector_add_uint("isi.resource", 0x54, create_dissector_handle(dissect_isi_gps, proto_isi));
	}
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
