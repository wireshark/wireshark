/* packet-m3ua.c
 * Routines for MTP3 User Adaptation Layer dissection
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m3ua-06.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m3ua-10.txt
 * To do: - clean up the code
 *        - provide better handling of length parameters
 *        - provide good information in summary window
 *
 * Copyright 2000, 2001, 2002, Michael Tuexen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-m3ua.c,v 1.15 2002/02/26 10:18:22 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>


#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "prefs.h"

#define SCTP_PORT_M3UA         2905
#define M3UA_PAYLOAD_PROTO_ID  3

#define VERSION_LENGTH         1
#define RESERVED_LENGTH        1
#define MESSAGE_CLASS_LENGTH   1
#define MESSAGE_TYPE_LENGTH    1
#define MESSAGE_LENGTH_LENGTH  4
#define COMMON_HEADER_LENGTH   (VERSION_LENGTH + RESERVED_LENGTH + MESSAGE_CLASS_LENGTH + \
                                MESSAGE_TYPE_LENGTH + MESSAGE_LENGTH_LENGTH)

#define VERSION_OFFSET         0
#define RESERVED_OFFSET        (VERSION_OFFSET + VERSION_LENGTH)
#define MESSAGE_CLASS_OFFSET   (RESERVED_OFFSET + RESERVED_LENGTH)
#define MESSAGE_TYPE_OFFSET    (MESSAGE_CLASS_OFFSET + MESSAGE_CLASS_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)

#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_TAG_OFFSET    0
#define PARAMETER_LENGTH_OFFSET (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET  (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET PARAMETER_TAG_OFFSET

#define V6_NETWORK_APPEARANCE_PARAMETER_TAG            1
#define V6_PROTOCOL_DATA_1_PARAMETER_TAG               2
#define V6_PROTOCOL_DATA_2_PARAMETER_TAG               3
#define V6_INFO_PARAMETER_TAG                          4
#define V6_AFFECTED_DESTINATIONS_PARAMETER_TAG         5
#define V6_ROUTING_CONTEXT_PARAMETER_TAG               6
#define V6_DIAGNOSTIC_INFORMATION_PARAMETER_TAG        7
#define V6_HEARTBEAT_DATA_PARAMETER_TAG                8
#define V6_USER_CAUSE_PARAMETER_TAG                    9
#define V6_REASON_PARAMETER_TAG                       10
#define V6_TRAFFIC_MODE_TYPE_PARAMETER_TAG            11
#define V6_ERROR_CODE_PARAMETER_TAG                   12
#define V6_STATUS_PARAMETER_TAG                       13
#define V6_CONGESTION_INDICATION_PARAMETER_TAG        14
#define V6_CONCERNED_DESTINATION_PARAMETER_TAG        15
#define V6_ROUTING_KEY_PARAMETER_TAG                  16
#define V6_REGISTRATION_RESULT_PARAMETER_TAG          17
#define V6_DEREGISTRATION_RESULT_PARAMETER_TAG        18
#define V6_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG 19
#define V6_DESTINATION_POINT_CODE_PARAMETER_TAG       20
#define V6_SERVICE_INDICATORS_PARAMETER_TAG           21
#define V6_SUBSYSTEM_NUMBERS_PARAMETER_TAG            22
#define V6_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG  23
#define V6_CIRCUIT_RANGE_PARAMETER_TAG                24
#define V6_REGISTRATION_RESULTS_PARAMETER_TAG         25
#define V6_DEREGISTRATION_RESULTS_PARAMETER_TAG       26

static const value_string m3ua_v6_parameter_tag_values[] = {
  { V6_NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" },
  { V6_PROTOCOL_DATA_1_PARAMETER_TAG,              "Protocol data 1" },
  { V6_PROTOCOL_DATA_2_PARAMETER_TAG,              "Protocol data 2" },
  { V6_INFO_PARAMETER_TAG,                         "Info" },
  { V6_AFFECTED_DESTINATIONS_PARAMETER_TAG,        "Affected destinations" },
  { V6_ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { V6_DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic information" },
  { V6_HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { V6_USER_CAUSE_PARAMETER_TAG,                   "User / Cause" },
  { V6_REASON_PARAMETER_TAG,                       "Reason" },
  { V6_TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { V6_ERROR_CODE_PARAMETER_TAG,                   "Error code" },
  { V6_STATUS_PARAMETER_TAG,                       "Status" }, 
  { V6_CONGESTION_INDICATION_PARAMETER_TAG,        "Congestion indication" },
  { V6_CONCERNED_DESTINATION_PARAMETER_TAG,        "Concerned destination" },
  { V6_ROUTING_KEY_PARAMETER_TAG,                  "Routing Key" },
  { V6_REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" },
  { V6_DEREGISTRATION_RESULT_PARAMETER_TAG,        "De-registration result" },
  { V6_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG, "Local routing key identifier" },
  { V6_DESTINATION_POINT_CODE_PARAMETER_TAG,       "Destination point code" },
  { V6_SERVICE_INDICATORS_PARAMETER_TAG,           "Service indicators" },
  { V6_SUBSYSTEM_NUMBERS_PARAMETER_TAG,            "Subsystem numbers" },
  { V6_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG,  "Originating point code list" },
  { V6_CIRCUIT_RANGE_PARAMETER_TAG,                "Circuit range" },
  { V6_REGISTRATION_RESULTS_PARAMETER_TAG,         "Registration results" },
  { V6_DEREGISTRATION_RESULTS_PARAMETER_TAG,       "De-registration results" },
  { 0,                           NULL } };
  
#define V10_INFO_STRING_PARAMETER_TAG                  0x0004
#define V10_ROUTING_CONTEXT_PARAMETER_TAG              0x0006
#define V10_DIAGNOSTIC_INFORMATION_PARAMETER_TAG       0x0007
#define V10_HEARTBEAT_DATA_PARAMETER_TAG               0x0009
#define V10_TRAFFIC_MODE_TYPE_PARAMETER_TAG            0x000b
#define V10_ERROR_CODE_PARAMETER_TAG                   0x000c
#define V10_STATUS_PARAMETER_TAG                       0x000d
#define V10_ASP_IDENTIFIER_PARAMETER_TAG               0x0011
#define V10_AFFECTED_POINT_CODE_PARAMETER_TAG          0x0012
#define V10_NETWORK_APPEARANCE_PARAMETER_TAG           0x0200
#define V10_USER_CAUSE_PARAMETER_TAG                   0x0204
#define V10_CONGESTION_INDICATIONS_PARAMETER_TAG       0x0205
#define V10_CONCERNED_DESTINATION_PARAMETER_TAG        0x0206
#define V10_ROUTING_KEY_PARAMETER_TAG                  0x0207
#define V10_REGISTRATION_RESULT_PARAMETER_TAG          0x0208
#define V10_DEREGISTRATION_RESULT_PARAMETER_TAG        0x0209
#define V10_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG 0x020a
#define V10_DESTINATION_POINT_CODE_PARAMETER_TAG       0x020b
#define V10_SERVICE_INDICATORS_PARAMETER_TAG           0x020c
#define V10_SUBSYSTEM_NUMBERS_PARAMETER_TAG            0x020d
#define V10_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG  0x020e
#define V10_CIRCUIT_RANGE_PARAMETER_TAG                0x020f
#define V10_PROTOCOL_DATA_PARAMETER_TAG                0x0210
#define V10_CORRELATION_IDENTIFIER_PARAMETER_TAG       0x0211
#define V10_REGISTRATION_STATUS_PARAMETER_TAG          0x0212
#define V10_DEREGISTRATION_STATUS_PARAMETER_TAG        0x0213

static const value_string m3ua_v10_parameter_tag_values[] = {
  { V10_INFO_STRING_PARAMETER_TAG,                  "Info string" } ,
  { V10_ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" } ,
  { V10_DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic Information" } ,
  { V10_HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" } ,
  { V10_TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" } ,
  { V10_ERROR_CODE_PARAMETER_TAG,                   "Error code" } ,
  { V10_STATUS_PARAMETER_TAG,                       "Status" } ,
  { V10_ASP_IDENTIFIER_PARAMETER_TAG,               "ASP identifier" } ,
  { V10_AFFECTED_POINT_CODE_PARAMETER_TAG,          "Affected point code" } ,
  { V10_NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" } ,
  { V10_USER_CAUSE_PARAMETER_TAG,                   "User / cause" } ,
  { V10_CONGESTION_INDICATIONS_PARAMETER_TAG,       "Congestion indications" } ,
  { V10_CONCERNED_DESTINATION_PARAMETER_TAG,        "Concerned destination" } ,
  { V10_ROUTING_KEY_PARAMETER_TAG,                  "Routing key" } ,
  { V10_REGISTRATION_RESULT_PARAMETER_TAG,          "Registration result" } ,
  { V10_DEREGISTRATION_RESULT_PARAMETER_TAG,        "Deregistration result" } ,
  { V10_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG, "Local routing key identifier" } ,
  { V10_DESTINATION_POINT_CODE_PARAMETER_TAG,       "Destination point code" } ,
  { V10_SERVICE_INDICATORS_PARAMETER_TAG,           "Service indicators" } ,
  { V10_SUBSYSTEM_NUMBERS_PARAMETER_TAG,            "Subsystem number" } ,
  { V10_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG,  "Originating point code list" } ,
  { V10_CIRCUIT_RANGE_PARAMETER_TAG,                "Circuit range" } ,
  { V10_PROTOCOL_DATA_PARAMETER_TAG,                "Protocol data" } ,
  { V10_CORRELATION_IDENTIFIER_PARAMETER_TAG,       "Correlation identifier" } ,
  { V10_REGISTRATION_STATUS_PARAMETER_TAG,          "Registration status" } ,
  { V10_DEREGISTRATION_STATUS_PARAMETER_TAG,        "Deregistration status" } ,
  { 0,                           NULL } };

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string m3ua_protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_TFER_MESSAGE        1
#define MESSAGE_CLASS_SSNM_MESSAGE        2
#define MESSAGE_CLASS_ASPSM_MESSAGE       3
#define MESSAGE_CLASS_ASPTM_MESSAGE       4
#define MESSAGE_CLASS_RKM_MESSAGE         9

static const value_string m3ua_message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_TFER_MESSAGE,   "Transfer messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_RKM_MESSAGE,    "Routing key management messages" },
  { 0,                           NULL } };

#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1

#define MESSAGE_TYPE_DATA                 1

#define MESSAGE_TYPE_DUNA                 1
#define MESSAGE_TYPE_DAVA                 2
#define MESSAGE_TYPE_DAUD                 3
#define MESSAGE_TYPE_SCON                 4
#define MESSAGE_TYPE_DUPU                 5
#define MESSAGE_TYPE_DRST                 6

#define MESSAGE_TYPE_UP                   1
#define MESSAGE_TYPE_DOWN                 2
#define MESSAGE_TYPE_BEAT                 3
#define MESSAGE_TYPE_UP_ACK               4
#define MESSAGE_TYPE_DOWN_ACK             5
#define MESSAGE_TYPE_BEAT_ACK             6

#define MESSAGE_TYPE_ACTIVE               1
#define MESSAGE_TYPE_INACTIVE             2
#define MESSAGE_TYPE_ACTIVE_ACK           3
#define MESSAGE_TYPE_INACTIVE_ACK         4

#define MESSAGE_TYPE_REG_REQ              1
#define MESSAGE_TYPE_REG_RSP              2
#define MESSAGE_TYPE_DEREG_REQ            3
#define MESSAGE_TYPE_DEREG_RSP            4


static const value_string m3ua_message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "Notify (NTFY)" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "Payload data (DATA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "Destination unavailable (DUNA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "Destination available (DAVA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "Destination state audit (DAUD)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SS7 Network congestion state (SCON)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "Destination userpart unavailable (DUPU)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DRST,          "Destination Restricted (DRST)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,            "ASP up (UP)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,          "ASP down (DOWN)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,          "Heartbeat (BEAT)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,        "ASP up ack (UP ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP down ack (DOWN ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,      "Heartbeat ack (BEAT ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,       "ASP active (ACTIVE)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,     "ASP inactive (INACTIVE)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,   "ASP active ack (ACTIVE ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK , "ASP inactive ack (INACTIVE ACK)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "Registration request (REG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "Registration response (REG_RSP)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "Deregistration request (DEREG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "Deregistration response (DEREG_RSP)" },
  { 0,                           NULL } };

static const value_string m3ua_message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "NTFY" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "DATA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "DUNA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "DAVA" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "DAUD" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SCON" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "DUPU" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DRST,          "DRST" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,            "ASP_UP" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,          "ASP_DOWN" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,          "BEAT" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,        "ASP_UP_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP_DOWN_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,      "BEAT_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,       "ASP_ACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,     "ASP_INACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,   "ASP_ACTIVE_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK , "ASP_INACTIVE_ACK" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "REG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "REG_RSP" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "DEREG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "DEREG_RSP" },
  { 0,                           NULL } };





#define PROTOCOL_DATA_OFFSET PARAMETER_VALUE_OFFSET


#define UNSPECIFIED_REASON          0
#define USER_UNAVAILABLE_REASON     1
#define MANAGEMENT_BLOCKING_REASON  2

static const value_string m3ua_reason_values[] = {
  { UNSPECIFIED_REASON,                             "Unspecified" },
  { USER_UNAVAILABLE_REASON,                        "User unavailable" },
  { MANAGEMENT_BLOCKING_REASON,                     "Management blocking" },
  {0,                           NULL } };

#define REASON_LENGTH 4
#define REASON_OFFSET PARAMETER_VALUE_OFFSET

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

/* Initialize the protocol and registered fields */
static int proto_m3ua = -1;
static int hf_m3ua_version = -1;
static int hf_m3ua_reserved = -1;
static int hf_m3ua_message_class = -1;
static int hf_m3ua_message_type = -1;
static int hf_m3ua_message_length = -1;
static int hf_m3ua_parameter_tag = -1;
static int hf_m3ua_parameter_length = -1;
static int hf_m3ua_parameter_value = -1;
static int hf_m3ua_parameter_padding = -1;
static int hf_m3ua_network_appearance = -1;
static int hf_m3ua_info_string = -1;
static int hf_m3ua_routing_context = -1;
static int hf_m3ua_diagnostic_information = -1;
static int hf_m3ua_heartbeat_data = -1;
static int hf_m3ua_error_code = -1;
static int hf_m3ua_status_type = -1;
static int hf_m3ua_status_info = -1;
static int hf_m3ua_asp_identifier = -1;
static int hf_m3ua_affected_point_code_mask = -1;
static int hf_m3ua_affected_point_code_pc = -1;
static int hf_m3ua_unavailability_cause = -1;
static int hf_m3ua_user_identity = -1;
static int hf_m3ua_reason = -1;
static int hf_m3ua_traffic_mode_type = -1;
static int hf_m3ua_congestion_reserved = -1;
static int hf_m3ua_congestion_level = -1;
static int hf_m3ua_concerned_dest_reserved = -1;
static int hf_m3ua_concerned_dest_pc = -1;
static int hf_m3ua_local_rk_identifier = -1;
static int hf_m3ua_dpc_mask = -1;
static int hf_m3ua_dpc_pc = -1;
static int hf_m3ua_si = -1;
static int hf_m3ua_ssn = -1;
static int hf_m3ua_opc_list_mask = -1;
static int hf_m3ua_opc_list_pc = -1;
static int hf_m3ua_cic_range_mask = -1;
static int hf_m3ua_cic_range_pc = -1;
static int hf_m3ua_cic_range_upper = -1;
static int hf_m3ua_cic_range_lower = -1;
static int hf_m3ua_protocol_data_opc = -1;
static int hf_m3ua_protocol_data_dpc = -1;
static int hf_m3ua_protocol_data_si = -1;
static int hf_m3ua_protocol_data_ni = -1;
static int hf_m3ua_protocol_data_mp = -1;
static int hf_m3ua_protocol_data_sls = -1;
static int hf_m3ua_correlation_identifier = -1;
static int hf_m3ua_registration_status = -1;
static int hf_m3ua_deregistration_status = -1;
static int hf_m3ua_registration_result_identifier = -1;
static int hf_m3ua_registration_result_status = -1;
static int hf_m3ua_registration_result_context = -1;
static int hf_m3ua_deregistration_result_status = -1;
static int hf_m3ua_deregistration_result_context = -1;
static int hf_m3ua_li = -1;

/* Initialize the subtree pointers */
static gint ett_m3ua = -1;
static gint ett_m3ua_parameter = -1;

static module_t *m3ua_module;
static dissector_handle_t mtp3_handle, data_handle;
static dissector_table_t m3ua_si_dissector_table;

/* stuff for supporting multiple versions */
#define M3UA_V6            1
#define M3UA_V10           2
static gint m3ua_version = M3UA_V10;

static void
dissect_m3ua_parameters(tvbuff_t *, packet_info *, proto_tree *, proto_tree *);

static guint 
nr_of_padding_bytes (guint length)
{
  guint remainder;

  remainder = length % 4;

  if (remainder == 0)
    return 0;
  else
    return 4 - remainder;
}

static void
dissect_m3ua_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *m3ua_tree)
{
  guint8  version, reserved, message_class, message_type;
  guint32 message_length;
  
  /* Extract the common header */
  version        = tvb_get_guint8(common_header_tvb, VERSION_OFFSET);
  reserved       = tvb_get_guint8(common_header_tvb, RESERVED_OFFSET);
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);
  message_length = tvb_get_ntohl (common_header_tvb, MESSAGE_LENGTH_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(message_class * 256 + message_type, m3ua_message_class_type_acro_values, "reserved"));
    col_append_str(pinfo->cinfo, COL_INFO, " ");
  }

  if (m3ua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(m3ua_tree, hf_m3ua_version, common_header_tvb, VERSION_OFFSET, VERSION_LENGTH, version);
    proto_tree_add_uint(m3ua_tree, hf_m3ua_reserved, common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH, reserved);
    proto_tree_add_uint(m3ua_tree, hf_m3ua_message_class, common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH, message_class);
    proto_tree_add_uint_format(m3ua_tree, hf_m3ua_message_type, common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH, message_type,
                               "Message type: %s (%u)", 
                               val_to_str(message_class * 256 + message_type, m3ua_message_class_type_values, "reserved"), message_type);
    proto_tree_add_uint(m3ua_tree, hf_m3ua_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, message_length);
  }
}

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_m3ua_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, info_string_length;
  char *info_string;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  info_string_length = length - PARAMETER_HEADER_LENGTH;
  info_string = (char *)tvb_get_ptr(parameter_tvb, INFO_STRING_OFFSET, info_string_length);
  proto_tree_add_string(parameter_tree, hf_m3ua_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, info_string);
  proto_item_set_text(parameter_item, "Info String (%.*s)", info_string_length, info_string);
}

#define ROUTING_CONTEXT_LENGTH 4

static void
dissect_m3ua_routing_context_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_contexts, context_number;
  guint32 context;
  gint context_offset;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_contexts = (length - PARAMETER_HEADER_LENGTH) / 4;
  context_offset = PARAMETER_VALUE_OFFSET;
  for(context_number=1; context_number <= number_of_contexts; context_number++) {
    context = tvb_get_ntohl(parameter_tvb, context_offset);
    proto_tree_add_uint(parameter_tree, hf_m3ua_routing_context, parameter_tvb, context_offset, ROUTING_CONTEXT_LENGTH, context);
    context_offset += ROUTING_CONTEXT_LENGTH;
  }
  proto_item_set_text(parameter_item, "Routing context parameter (%u context%s)", number_of_contexts, plurality(number_of_contexts, "", "s"));
}

static void
dissect_m3ua_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, diagnostic_info_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  diagnostic_info_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_bytes(parameter_tree, hf_m3ua_diagnostic_information, parameter_tvb, PARAMETER_VALUE_OFFSET, diagnostic_info_length,
		                   tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, diagnostic_info_length));

  proto_item_set_text(parameter_item, "Diagnostic information (%u byte%s)", diagnostic_info_length, plurality(diagnostic_info_length, "", "s"));
}

static void
dissect_m3ua_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, heartbeat_data_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  heartbeat_data_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_bytes(parameter_tree, hf_m3ua_heartbeat_data, parameter_tvb, PARAMETER_VALUE_OFFSET, heartbeat_data_length,
		                   tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, heartbeat_data_length));

  proto_item_set_text(parameter_item, "Heartbeat data (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}

#define OVER_RIDE_TYPE           1
#define LOAD_SHARE_TYPE          2
#define OVER_RIDE_STANDBY_TYPE   3
#define LOAD_SHARE_STANDBY_TYPE  4

static const value_string m3ua_v6_traffic_mode_type_values[] = {
  { OVER_RIDE_TYPE ,                             "Over-ride" },
  { LOAD_SHARE_TYPE,                             "Load-share" },
  { OVER_RIDE_STANDBY_TYPE,                      "Over-ride (standby)" },
  { LOAD_SHARE_STANDBY_TYPE,                     "Load-share (standby)" },
  {0,                           NULL } };

static void
dissect_m3ua_v6_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 traffic_mode_type;

  traffic_mode_type = tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_m3ua_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, traffic_mode_type,
                             "Traffic mode type: %u (%s)", traffic_mode_type, val_to_str(traffic_mode_type, m3ua_v6_traffic_mode_type_values, "unknown"));
  proto_item_set_text(parameter_item, "Traffic mode type parameter (%s)", val_to_str(traffic_mode_type, m3ua_v6_traffic_mode_type_values, "unknown"));
}

#define BROADCAST_TYPE   3

static const value_string m3ua_v10_traffic_mode_type_values[] = {
  { OVER_RIDE_TYPE ,                             "Over-ride" },
  { LOAD_SHARE_TYPE,                             "Load-share" },
  { BROADCAST_TYPE,                              "Broadcast" },
  {0,                           NULL } };

static void
dissect_m3ua_v10_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 traffic_mode_type;

  traffic_mode_type = tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_m3ua_traffic_mode_type, 
			                       parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH,
			                       traffic_mode_type, "Traffic mode type: %u (%s)",
			                       traffic_mode_type, val_to_str(traffic_mode_type, m3ua_v10_traffic_mode_type_values, "unknown"));
  proto_item_set_text(parameter_item, "Traffic mode type parameter (%s)", val_to_str(traffic_mode_type, m3ua_v10_traffic_mode_type_values, "unknown"));
}

#define V6_INVALID_VERSION_ERROR_CODE               1
#define V6_INVALID_NETWORK_APPEARANCE_ERROR_CODE    2
#define V6_UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE     3
#define V6_UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE      4
#define V6_INVALID_TRAFFIC_HANDLING_MODE_ERROR_CODE 5
#define V6_UNEXPECTED_MESSAGE_ERROR_CODE            6
#define V6_PROTOCOL_ERROR_ERROR_CODE                7
#define V6_INVALID_ROUTING_CONTEXT_ERROR_CODE       8
#define V6_INVALID_STREAM_IDENTIFIER_ERROR_CODE     9
#define V6_INVALID_PARAMETER_VALUE_ERROR_CODE      10

static const value_string m3ua_v6_error_code_values[] = {
  { V6_INVALID_VERSION_ERROR_CODE,               "Invalid version" },
  { V6_INVALID_NETWORK_APPEARANCE_ERROR_CODE,    "Invalid network appearance" },
  { V6_UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE,     "Unsupported message class" },
  { V6_UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE,      "Unsupported message type" },
  { V6_INVALID_TRAFFIC_HANDLING_MODE_ERROR_CODE, "Invalid traffic handling mode" },
  { V6_UNEXPECTED_MESSAGE_ERROR_CODE,            "Unexpected message" },
  { V6_PROTOCOL_ERROR_ERROR_CODE,                "Protocol error" },
  { V6_INVALID_ROUTING_CONTEXT_ERROR_CODE,       "Invalid routing context" },
  { V6_INVALID_STREAM_IDENTIFIER_ERROR_CODE,     "Invalid stream identifier" },
  { V6_INVALID_PARAMETER_VALUE_ERROR_CODE,       "Invalid parameter value" },
  { 0,                           NULL } };

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_m3ua_v6_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 error_code;

  error_code = tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET);
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, error_code,
                             "Error code: %u (%s)", error_code, val_to_str(error_code, m3ua_v6_error_code_values, "unknown"));
  proto_item_set_text(parameter_item, "Error code parameter (%s)", val_to_str(error_code, m3ua_v6_error_code_values, "unknown"));
}


#define V10_INVALID_VERSION_ERROR_CODE                   0x01
#define V10_UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE         0x03
#define V10_UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE          0x04
#define V10_UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR_CODE 0x05
#define V10_UNEXPECTED_MESSAGE_ERROR_CODE                0x06
#define V10_PROTOCOL_ERROR_ERROR_CODE                    0x07
#define V10_INVALID_STREAM_IDENTIFIER_ERROR_CODE         0x09
#define V10_REFUSED_ERROR_CODE                           0x0d
#define V10_ASP_IDENTIFIER_REQUIRED_ERROR_CODE           0x0e
#define V10_INVALID_ASP_IDENTIFIER_ERROR_CODE            0x0f
#define V10_INVALID_ROUTING_CONTEXT_ERROR_CODE           0x10
#define V10_INVALID_PARAMETER_VALUE_ERROR_CODE           0x11
#define V10_PARAMETER_FIELD_ERROR_CODE                   0x12
#define V10_UNEXPECTED_PARAMETER_ERROR_CODE              0x13
#define V10_DESTINATION_STATUS_UNKNOWN_ERROR_CODE        0x14
#define V10_INVALID_NETWORK_APPEARANCE_ERROR_CODE        0x15
#define V10_NO_CONFIGURED_AS_FOR_ASP_ERROR_CODE          0x16

static const value_string m3ua_v10_error_code_values[] = {
  { V10_INVALID_VERSION_ERROR_CODE,                   "Invalid version" },
  { V10_UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE,         "Unsupported message class" },
  { V10_UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE,          "Unsupported message type" },
  { V10_UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR_CODE, "Unsupported traffic handling mode" },
  { V10_UNEXPECTED_MESSAGE_ERROR_CODE,                "Unexpected message" },
  { V10_PROTOCOL_ERROR_ERROR_CODE,                    "Protocol error" },
  { V10_INVALID_STREAM_IDENTIFIER_ERROR_CODE,         "Invalid stream identifier" },
  { V10_REFUSED_ERROR_CODE,                           "Refused - management blocking" },
  { V10_ASP_IDENTIFIER_REQUIRED_ERROR_CODE,           "ASP identifier required" },
  { V10_INVALID_ASP_IDENTIFIER_ERROR_CODE,            "Invalid ASP identifier" },
  { V10_INVALID_ROUTING_CONTEXT_ERROR_CODE,           "Invalid routing context" },
  { V10_INVALID_PARAMETER_VALUE_ERROR_CODE,           "Invalid parameter value" },
  { V10_PARAMETER_FIELD_ERROR_CODE,                   "Parameter field error" },
  { V10_UNEXPECTED_PARAMETER_ERROR_CODE,              "Unexpected parameter" },
  { V10_DESTINATION_STATUS_UNKNOWN_ERROR_CODE,        "Destination status unknown" },
  { V10_INVALID_NETWORK_APPEARANCE_ERROR_CODE,        "Invalid network sppearance" },
  { V10_NO_CONFIGURED_AS_FOR_ASP_ERROR_CODE,          "No configured AS for ASP" },
  { 0,                                            NULL } };

static void
dissect_m3ua_v10_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 error_code;

  error_code = tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET);
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, error_code,
                             "Error code: %u (%s)",error_code, val_to_str(error_code, m3ua_v10_error_code_values, "unknown"));
  proto_item_set_text(parameter_item, "Error code parameter (%s)", val_to_str(error_code, m3ua_v10_error_code_values, "unknown"));
}

#define AS_STATE_CHANGE_TYPE       1
#define OTHER_TYPE                 2

static const value_string m3ua_status_type_values[] = {
  { AS_STATE_CHANGE_TYPE,            "Application server state change" },
  { OTHER_TYPE,                      "Other" },
  { 0,                           NULL } };

#define RESERVED_INFO              1
#define AS_INACTIVE_INFO           2
#define AS_ACTIVE_INFO             3
#define AS_PENDING_INFO            4

#define INSUFFICIENT_ASP_RES_INFO  1
#define ALTERNATE_ASP_ACTIVE_INFO  2
#define ASP_FAILURE_INFO           3

static const value_string m3ua_status_type_info_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  { OTHER_TYPE           * 256 * 256 + ASP_FAILURE_INFO,          "ASP Failure" },
  {0,                           NULL } };

#define STATUS_TYPE_LENGTH 2
#define STATUS_INFO_LENGTH 2

#define STATUS_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define STATUS_INFO_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

static void
dissect_m3ua_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_info;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_info = tvb_get_ntohs(parameter_tvb, STATUS_INFO_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_m3ua_status_type, parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH, status_type);
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_status_info, parameter_tvb, STATUS_INFO_OFFSET, STATUS_INFO_LENGTH, status_info,
                             "Status info: %s (%u)", val_to_str(status_type * 256 * 256 + status_info, m3ua_status_type_info_values, "unknown"), status_info);

  proto_item_set_text(parameter_item, 
                      "Status type / ID (%s)", val_to_str(status_type * 256 * 256 + status_info, m3ua_status_type_info_values, "unknown status information"));
}

#define ASP_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define ASP_IDENTIFIER_LENGTH  4

static void
dissect_m3ua_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 identifier;
  
  identifier = tvb_get_ntohl(parameter_tvb, ASP_IDENTIFIER_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_asp_identifier, parameter_tvb, ASP_IDENTIFIER_OFFSET, ASP_IDENTIFIER_LENGTH, identifier);
  proto_item_set_text(parameter_item, "ASP identifier (%u)", identifier);
}

#define AFFECTED_MASK_LENGTH       1
#define AFFECTED_PC_LENGTH         3
#define AFFECTED_POINT_CODE_LENGTH (AFFECTED_MASK_LENGTH + AFFECTED_PC_LENGTH)

#define AFFECTED_MASK_OFFSET        0
#define AFFECTED_PC_OFFSET         (AFFECTED_MASK_OFFSET + AFFECTED_MASK_LENGTH)

static void
dissect_m3ua_affected_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  mask;
  guint16 length, number_of_point_codes, point_code_number;
  guint32 pc;
  gint point_code_offset;

  length                = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_point_codes = (length - PARAMETER_HEADER_LENGTH) / AFFECTED_POINT_CODE_LENGTH;

  point_code_offset = PARAMETER_VALUE_OFFSET;
  for(point_code_number=1; point_code_number <= number_of_point_codes; point_code_number++) {
    mask = tvb_get_guint8(parameter_tvb, point_code_offset + AFFECTED_MASK_OFFSET);
    pc   = tvb_get_ntoh24(parameter_tvb, point_code_offset + AFFECTED_PC_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m3ua_affected_point_code_mask, parameter_tvb, point_code_offset + AFFECTED_MASK_OFFSET, AFFECTED_MASK_LENGTH, mask);
    proto_tree_add_uint(parameter_tree, hf_m3ua_affected_point_code_pc, parameter_tvb, point_code_offset + AFFECTED_PC_OFFSET, AFFECTED_PC_LENGTH, pc);
    point_code_offset += AFFECTED_POINT_CODE_LENGTH;
  };
  proto_item_set_text(parameter_item, "Affected point code parameter (%u point code%s)", number_of_point_codes, plurality(number_of_point_codes, "", "s"));

}

#define NETWORK_APPEARANCE_LENGTH 4
#define NETWORK_APPEARANCE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_m3ua_network_appearance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 network_appearance;

  network_appearance = tvb_get_ntohl(parameter_tvb, NETWORK_APPEARANCE_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_network_appearance, parameter_tvb, NETWORK_APPEARANCE_OFFSET, NETWORK_APPEARANCE_LENGTH, network_appearance);
  proto_item_set_text(parameter_item, "Network appearance: %u", network_appearance);
}

#define UNKNOWN_UNAVAIL_CAUSE                  0
#define UNEQUIPPED_REMOTE_USER_UNAVAIL_CAUSE   1
#define INACCESSABLE_REMOTE_USER_UNAVAIL_CAUSE 2

static const value_string m3ua_unavailability_cause_values[] = {
  { UNKNOWN_UNAVAIL_CAUSE,                             "Unknown" },
  { UNEQUIPPED_REMOTE_USER_UNAVAIL_CAUSE,              "Unequipped remote user" },
  { INACCESSABLE_REMOTE_USER_UNAVAIL_CAUSE,            "Inaccessable remote user" },
  {0,                           NULL } };

#define RESERVED_0_USER_ID                0
#define RESERVED_1_USER_ID                1
#define RESERVED_2_USER_ID                2
#define SCCP_USER_ID                      3
#define TUP_USER_ID                       4
#define ISUP_USER_ID                      5
#define RESERVED_6_USER_ID                6
#define RESERVED_7_USER_ID                7
#define RESERVED_8_USER_ID                8
#define BROADBAND_ISUP_USER_ID            9
#define SATELLITE_ISUP_USER_ID           10

static const value_string m3ua_user_identity_values[] = {
  { RESERVED_0_USER_ID,                             "Reserved" },
  { RESERVED_1_USER_ID,                             "Reserved" },
  { RESERVED_2_USER_ID,                             "Reserved" },
  { SCCP_USER_ID,                                   "SCCP" },
  { TUP_USER_ID,                                    "TUP" },
  { ISUP_USER_ID,                                   "ISUP" },
  { RESERVED_6_USER_ID,                             "Reserved" },
  { RESERVED_7_USER_ID,                             "Reserved" },
  { RESERVED_8_USER_ID,                             "Reserved" },
  { BROADBAND_ISUP_USER_ID,                         "Broadband ISUP" },
  { SATELLITE_ISUP_USER_ID,                         "Satellite ISUP" },
  {0,                           NULL } };

#define CAUSE_LENGTH 2
#define USER_LENGTH  2

#define CAUSE_OFFSET  PARAMETER_VALUE_OFFSET
#define USER_OFFSET   (CAUSE_OFFSET + CAUSE_LENGTH)

static void
dissect_m3ua_user_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 cause, user;

  cause = tvb_get_ntohs(parameter_tvb, CAUSE_OFFSET);
  user  = tvb_get_ntohs(parameter_tvb, USER_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_m3ua_unavailability_cause, parameter_tvb, CAUSE_OFFSET, CAUSE_LENGTH, cause);
  proto_tree_add_uint(parameter_tree, hf_m3ua_user_identity, parameter_tvb, USER_OFFSET, USER_LENGTH, user);
  proto_item_set_text(parameter_item, "User / Cause parameter (%s: %s)",
		                  val_to_str(user, m3ua_user_identity_values, "Unknown user"),
                      val_to_str(cause, m3ua_unavailability_cause_values, "unknown cause"));
}

static void
dissect_m3ua_protocol_data_1_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, protocol_data_length;
  tvbuff_t *payload_tvb;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  protocol_data_length = length - PARAMETER_HEADER_LENGTH;
  payload_tvb          = tvb_new_subset(parameter_tvb, PROTOCOL_DATA_OFFSET, protocol_data_length, protocol_data_length);
  proto_item_set_text(parameter_item, "Protocol data (SS7 message of %u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);

}

#define LI_OCTETT_LENGTH 1
#define LI_OCTETT_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_m3ua_protocol_data_2_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 li;
  guint16 length, protocol_data_length;
  tvbuff_t *payload_tvb;

  length               = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  li                   = tvb_get_guint8(parameter_tvb, LI_OCTETT_OFFSET);
  protocol_data_length = length - PARAMETER_HEADER_LENGTH - LI_OCTETT_LENGTH;
  payload_tvb          = tvb_new_subset(parameter_tvb, PROTOCOL_DATA_OFFSET + LI_OCTETT_LENGTH, protocol_data_length, protocol_data_length);
  proto_tree_add_uint(parameter_tree, hf_m3ua_li, parameter_tvb, LI_OCTETT_OFFSET, LI_OCTETT_LENGTH, li);
  proto_item_set_text(parameter_item, "Protocol data (SS7 message of %u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH + LI_OCTETT_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}

static void
dissect_m3ua_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reason;

  reason = tvb_get_ntohl(parameter_tvb, REASON_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_m3ua_reason, parameter_tvb, REASON_OFFSET, REASON_LENGTH, reason);
  proto_item_set_text(parameter_item, "Reason parameter (%s)", val_to_str(reason, m3ua_reason_values, "unknown"));
}

#define NO_CONGESTION_LEVEL         0
#define CONGESTION_LEVEL_1_LEVEL    1
#define CONGESTION_LEVEL_2_LEVEL    2
#define CONGESTION_LEVEL_3_LEVEL    3

static const value_string m3ua_congestion_level_values[] = {
  { NO_CONGESTION_LEVEL,                             "No congestion or undefined" },
  { CONGESTION_LEVEL_1_LEVEL,                        "Congestion level 1" },
  { CONGESTION_LEVEL_2_LEVEL,                        "Congestion level 2" },
  { CONGESTION_LEVEL_3_LEVEL,                        "Congestion level 3" },
  {0,                           NULL } };

#define CONG_IND_RESERVED_LENGTH    3
#define CONG_IND_LEVEL_LENGTH       1

#define CONG_IND_RESERVED_OFFSET     PARAMETER_VALUE_OFFSET
#define CONG_IND_LEVEL_OFFSET        (CONG_IND_RESERVED_OFFSET + CONG_IND_RESERVED_LENGTH)

static void
dissect_m3ua_congestion_indication_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 level;
  
  level = tvb_get_guint8(parameter_tvb, CONG_IND_LEVEL_OFFSET);

  proto_tree_add_bytes(parameter_tree, hf_m3ua_congestion_reserved, parameter_tvb, CONG_IND_RESERVED_OFFSET, CONG_IND_RESERVED_LENGTH,
                       tvb_get_ptr(parameter_tvb, CONG_IND_RESERVED_OFFSET, CONG_IND_RESERVED_LENGTH));
  proto_tree_add_uint(parameter_tree, hf_m3ua_congestion_level, parameter_tvb, CONG_IND_LEVEL_OFFSET, CONG_IND_LEVEL_LENGTH, level);
  proto_item_set_text(parameter_item, "Congestion indication(%s)", val_to_str(level, m3ua_congestion_level_values, "unknown"));
}

#define CON_DEST_RESERVED_LENGTH    1
#define CON_DEST_PC_LENGTH          3

#define CON_DEST_RESERVED_OFFSET    PARAMETER_VALUE_OFFSET
#define CON_DEST_PC_OFFSET          (CON_DEST_RESERVED_OFFSET + CON_DEST_RESERVED_LENGTH)

static void
dissect_m3ua_concerned_destination_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 pc;
  
  pc = tvb_get_ntoh24(parameter_tvb, CON_DEST_PC_OFFSET);

  proto_tree_add_bytes(parameter_tree, hf_m3ua_concerned_dest_reserved, parameter_tvb, CON_DEST_RESERVED_OFFSET, CON_DEST_RESERVED_LENGTH,
                       tvb_get_ptr(parameter_tvb, CON_DEST_RESERVED_OFFSET, CON_DEST_RESERVED_LENGTH));
  proto_tree_add_uint(parameter_tree, hf_m3ua_concerned_dest_pc, parameter_tvb, CON_DEST_PC_OFFSET, CON_DEST_PC_LENGTH, pc);
  proto_item_set_text(parameter_item, "Concerned destination (%u)", pc);
}

static void
dissect_m3ua_routing_key_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb          = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_m3ua_parameters(parameters_tvb, pinfo, tree, parameter_tree);
  proto_item_set_text(parameter_item, "Routing key");
}

static const value_string m3ua_registration_result_status_values[] = {
  { 0,           "Successfully Registered" } ,
  { 1,           "Error - Unknown" } ,
  { 2,           "Error - Invalid DPC" } ,
  { 3,           "Error - Invalid Network Appearance" } ,
  { 4,           "Error - Invalid Routing Key" } ,
  { 5,           "Error - Permission Denied" } ,
  { 6,           "Error - Overlapping (Non-unique) Routing Key" } ,
  { 7,           "Error - Routing Key not Provisioned" } ,
  { 8,           "Error - Insufficient Resources" } ,
  { 0,           NULL } };

#define REG_RES_IDENTIFIER_LENGTH 4
#define REG_RES_STATUS_LENGTH     4
#define REG_RES_CONTEXT_LENGTH    4

#define REG_RES_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define REG_RES_STATUS_OFFSET     (REG_RES_IDENTIFIER_OFFSET + REG_RES_IDENTIFIER_LENGTH)
#define REG_RES_CONTEXT_OFFSET    (REG_RES_STATUS_OFFSET + REG_RES_STATUS_LENGTH)

static void
dissect_m3ua_v6_registration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 id, status, context;

  id      = tvb_get_ntohl(parameter_tvb, REG_RES_IDENTIFIER_OFFSET);
  status  = tvb_get_ntohl(parameter_tvb, REG_RES_STATUS_OFFSET);
  context = tvb_get_ntohl(parameter_tvb, REG_RES_CONTEXT_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_m3ua_registration_result_identifier, parameter_tvb, REG_RES_IDENTIFIER_OFFSET, REG_RES_IDENTIFIER_LENGTH, id);
  proto_tree_add_uint(parameter_tree, hf_m3ua_registration_result_status, parameter_tvb, REG_RES_STATUS_OFFSET, REG_RES_STATUS_LENGTH, status);
  proto_tree_add_uint(parameter_tree, hf_m3ua_registration_result_context, parameter_tvb, REG_RES_CONTEXT_OFFSET, REG_RES_CONTEXT_LENGTH, context); 
  proto_item_set_text(parameter_item, "Registration result");
}

static void
dissect_m3ua_v10_registration_result_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb          = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_m3ua_parameters(parameters_tvb, pinfo, tree, parameter_tree);
  proto_item_set_text(parameter_item, "Registration result");
}

static const value_string m3ua_deregistration_result_status_values[] = {
  { 0,           "Successfully De-registered" } ,
  { 1,           "Error - Unknown" } ,
  { 2,           "Error - Invalid Routing context" } ,
  { 3,           "Error - Permission Denied" } ,
  { 4,           "Error - Not registered" } ,
  { 0,           NULL } };

#define DEREG_RES_CONTEXT_LENGTH 4
#define DEREG_RES_STATUS_LENGTH  4

#define DEREG_RES_CONTEXT_OFFSET PARAMETER_VALUE_OFFSET
#define DEREG_RES_STATUS_OFFSET  (DEREG_RES_CONTEXT_OFFSET + DEREG_RES_CONTEXT_LENGTH)

static void
dissect_m3ua_v6_deregistration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 status, context;

  context = tvb_get_ntohl(parameter_tvb, DEREG_RES_CONTEXT_OFFSET);
  status  = tvb_get_ntohl(parameter_tvb, DEREG_RES_STATUS_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_m3ua_deregistration_result_context, parameter_tvb, DEREG_RES_CONTEXT_OFFSET, DEREG_RES_CONTEXT_LENGTH, context); 
  proto_tree_add_uint(parameter_tree, hf_m3ua_deregistration_result_status, parameter_tvb, DEREG_RES_STATUS_OFFSET, DEREG_RES_STATUS_LENGTH, status);
  proto_item_set_text(parameter_item, "De-registration result");

}

static void
dissect_m3ua_v10_deregistration_result_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb          = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_m3ua_parameters(parameters_tvb, pinfo, tree, parameter_tree);
  proto_item_set_text(parameter_item, "Deregistration result");
}


#define LOCAL_RK_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define LOCAL_RK_IDENTIFIER_LENGTH 4

static void
dissect_m3ua_local_routing_key_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 id;
  
  id = tvb_get_ntohl(parameter_tvb, LOCAL_RK_IDENTIFIER_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_local_rk_identifier, parameter_tvb, LOCAL_RK_IDENTIFIER_OFFSET, LOCAL_RK_IDENTIFIER_LENGTH, id);
  proto_item_set_text(parameter_item, "Local routing key identifier (%u)", id);
}

#define DPC_MASK_LENGTH    1
#define DPC_PC_LENGTH      3

#define DPC_MASK_OFFSET    PARAMETER_VALUE_OFFSET
#define DPC_PC_OFFSET      (DPC_MASK_OFFSET + DPC_MASK_LENGTH)

static void
dissect_m3ua_destination_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 pc;
  guint8  mask;
 
  mask = tvb_get_guint8(parameter_tvb, DPC_MASK_OFFSET);
  pc   = tvb_get_ntoh24(parameter_tvb, DPC_PC_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_m3ua_dpc_mask, parameter_tvb, DPC_MASK_OFFSET, DPC_MASK_LENGTH, mask);
  proto_tree_add_uint(parameter_tree, hf_m3ua_dpc_pc, parameter_tvb, DPC_PC_OFFSET, DPC_PC_LENGTH, pc);
  proto_item_set_text(parameter_item, "Destination point code (%u)", pc);
}

#define SI_LENGTH 1

static void
dissect_m3ua_service_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  si;
  guint16 length, number_of_sis, si_number;
  gint si_offset;

  length        = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_sis = length - PARAMETER_HEADER_LENGTH;

  si_offset = PARAMETER_VALUE_OFFSET;
  for(si_number=1; si_number <= number_of_sis; si_number++) {
    si = tvb_get_guint8(parameter_tvb, si_offset);
    proto_tree_add_uint(parameter_tree, hf_m3ua_si, parameter_tvb, si_offset, SI_LENGTH, si);
    si_offset += SI_LENGTH;
  };
  proto_item_set_text(parameter_item, "Service indicators (%u indicator%s)", number_of_sis, plurality(number_of_sis, "", "s"));

}
#define SSN_LENGTH 1

static void
dissect_m3ua_subsystem_numbers_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  ssn;
  guint16 length, number_of_ssns, ssn_number;
  gint ssn_offset;

  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_ssns = length - PARAMETER_HEADER_LENGTH;

  ssn_offset = PARAMETER_VALUE_OFFSET;
  for(ssn_number=1; ssn_number <= number_of_ssns; ssn_number++) {
    ssn = tvb_get_guint8(parameter_tvb, ssn_offset);
    proto_tree_add_uint(parameter_tree, hf_m3ua_ssn, parameter_tvb, ssn_offset, SSN_LENGTH, ssn);
    ssn_offset += SSN_LENGTH;
  };
  proto_item_set_text(parameter_item, "Subsystem numbers (%u number%s)", number_of_ssns, plurality(number_of_ssns, "", "s"));

}

#define OPC_MASK_LENGTH             1
#define OPC_PC_LENGTH               3
#define OPC_LENGTH                  (OPC_MASK_LENGTH + OPC_PC_LENGTH)
#define OPC_MASK_OFFSET             0
#define OPC_PC_OFFSET               (OPC_MASK_OFFSET + OPC_MASK_LENGTH)

static void
dissect_m3ua_originating_point_code_list_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  mask;
  guint16 length, number_of_point_codes, point_code_number;
  guint32 pc;
  gint point_code_offset;

  length                = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_point_codes = (length - PARAMETER_HEADER_LENGTH) / 4;

  point_code_offset = PARAMETER_VALUE_OFFSET;
  for(point_code_number=1; point_code_number <= number_of_point_codes; point_code_number++) {
    mask = tvb_get_guint8(parameter_tvb, point_code_offset + AFFECTED_MASK_OFFSET);
    pc   = tvb_get_ntoh24(parameter_tvb, point_code_offset + AFFECTED_PC_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m3ua_opc_list_mask, parameter_tvb, point_code_offset + OPC_MASK_OFFSET, OPC_MASK_LENGTH, mask);
    proto_tree_add_uint(parameter_tree, hf_m3ua_opc_list_pc, parameter_tvb, point_code_offset + OPC_PC_OFFSET, OPC_PC_LENGTH, pc);
    point_code_offset += OPC_LENGTH;
  };
  proto_item_set_text(parameter_item, "Originating point code list (%u point code%s)", number_of_point_codes, plurality(number_of_point_codes, "", "s"));
}

#define CIC_RANGE_MASK_LENGTH             1
#define CIC_RANGE_PC_LENGTH               3
#define CIC_RANGE_LOWER_LENGTH            2
#define CIC_RANGE_UPPER_LENGTH            2
#define CIC_RANGE_LENGTH                  (CIC_RANGE_MASK_LENGTH + CIC_RANGE_PC_LENGTH + CIC_RANGE_LOWER_LENGTH + CIC_RANGE_UPPER_LENGTH)
#define CIC_RANGE_MASK_OFFSET             0
#define CIC_RANGE_PC_OFFSET               (CIC_RANGE_MASK_OFFSET + CIC_RANGE_MASK_LENGTH)
#define CIC_RANGE_LOWER_OFFSET            (CIC_RANGE_PC_OFFSET + CIC_RANGE_PC_LENGTH)
#define CIC_RANGE_UPPER_OFFSET            (CIC_RANGE_LOWER_OFFSET + CIC_RANGE_LOWER_LENGTH)

static void
dissect_m3ua_circuit_range_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  mask;
  guint16 length, number_of_point_codes, point_code_number, lower, upper;
  guint32 pc;
  gint point_code_offset;

  length                = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_point_codes = (length - PARAMETER_HEADER_LENGTH) / CIC_RANGE_LENGTH;

  point_code_offset = PARAMETER_VALUE_OFFSET;
  for(point_code_number = 1; point_code_number <= number_of_point_codes; point_code_number++) {
    mask  = tvb_get_guint8(parameter_tvb, point_code_offset + CIC_RANGE_MASK_OFFSET);
    pc    = tvb_get_ntoh24(parameter_tvb, point_code_offset + CIC_RANGE_PC_OFFSET);
    lower = tvb_get_ntohs(parameter_tvb, point_code_offset + CIC_RANGE_LOWER_OFFSET);
    upper = tvb_get_ntohs(parameter_tvb, point_code_offset + CIC_RANGE_UPPER_OFFSET);

    proto_tree_add_uint(parameter_tree, hf_m3ua_cic_range_mask, parameter_tvb, point_code_offset + CIC_RANGE_MASK_OFFSET, CIC_RANGE_MASK_LENGTH, mask);
    proto_tree_add_uint(parameter_tree, hf_m3ua_cic_range_pc, parameter_tvb, point_code_offset + CIC_RANGE_PC_OFFSET, CIC_RANGE_PC_LENGTH, pc);
    proto_tree_add_uint(parameter_tree, hf_m3ua_cic_range_lower, parameter_tvb, point_code_offset + CIC_RANGE_LOWER_OFFSET, CIC_RANGE_LOWER_LENGTH, lower);
    proto_tree_add_uint(parameter_tree, hf_m3ua_cic_range_upper, parameter_tvb, point_code_offset + CIC_RANGE_UPPER_OFFSET, CIC_RANGE_UPPER_LENGTH, upper);
    point_code_offset += CIC_RANGE_LENGTH;
  };
  proto_item_set_text(parameter_item, "Circuit range (%u range%s)", number_of_point_codes, plurality(number_of_point_codes, "", "s"));
}

#define DATA_OPC_LENGTH   4
#define DATA_DPC_LENGTH   4
#define DATA_SI_LENGTH    1
#define DATA_NI_LENGTH    1
#define DATA_MP_LENGTH    1
#define DATA_SLS_LENGTH   1
#define DATA_HDR_LENGTH   (DATA_OPC_LENGTH + DATA_DPC_LENGTH + DATA_SI_LENGTH + DATA_NI_LENGTH + DATA_MP_LENGTH + DATA_SLS_LENGTH)

#define DATA_OPC_OFFSET   PARAMETER_VALUE_OFFSET
#define DATA_DPC_OFFSET   (DATA_OPC_OFFSET + DATA_OPC_LENGTH)
#define DATA_SI_OFFSET    (DATA_DPC_OFFSET + DATA_DPC_LENGTH)
#define DATA_NI_OFFSET    (DATA_SI_OFFSET + DATA_SI_LENGTH)
#define DATA_MP_OFFSET    (DATA_NI_OFFSET + DATA_NI_LENGTH)
#define DATA_SLS_OFFSET   (DATA_MP_OFFSET + DATA_MP_LENGTH)
#define DATA_ULP_OFFSET   (DATA_SLS_OFFSET + DATA_SLS_LENGTH)

static void
dissect_m3ua_protocol_data_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 opc, dpc;
  guint16 length, ulp_length;
  guint8 si, ni, mp, sls;
  tvbuff_t *payload_tvb;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  ulp_length = length - PARAMETER_HEADER_LENGTH - DATA_HDR_LENGTH;
  payload_tvb          = tvb_new_subset(parameter_tvb, DATA_ULP_OFFSET, ulp_length, ulp_length);
  opc = tvb_get_ntohl(parameter_tvb, DATA_OPC_OFFSET);
  dpc = tvb_get_ntohl(parameter_tvb, DATA_DPC_OFFSET);
  si  = tvb_get_guint8(parameter_tvb, DATA_SI_OFFSET);
  ni  = tvb_get_guint8(parameter_tvb, DATA_NI_OFFSET);
  mp  = tvb_get_guint8(parameter_tvb, DATA_MP_OFFSET);
  sls = tvb_get_guint8(parameter_tvb, DATA_SLS_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_protocol_data_opc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, opc);
  proto_tree_add_uint(parameter_tree, hf_m3ua_protocol_data_dpc, parameter_tvb, DATA_DPC_OFFSET, DATA_DPC_LENGTH, dpc);
  proto_tree_add_uint(parameter_tree, hf_m3ua_protocol_data_si,  parameter_tvb, DATA_SI_OFFSET,  DATA_SI_LENGTH,  si);
  proto_tree_add_uint(parameter_tree, hf_m3ua_protocol_data_ni,  parameter_tvb, DATA_NI_OFFSET,  DATA_NI_LENGTH,  ni);
  proto_tree_add_uint(parameter_tree, hf_m3ua_protocol_data_mp,  parameter_tvb, DATA_MP_OFFSET,  DATA_MP_LENGTH,  mp);
  proto_tree_add_uint(parameter_tree, hf_m3ua_protocol_data_sls, parameter_tvb, DATA_SLS_OFFSET, DATA_SLS_LENGTH, sls);

  proto_item_set_text(parameter_item, "Protocol data (SS7 message of %u byte%s)", ulp_length, plurality(ulp_length, "", "s"));
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH + DATA_HDR_LENGTH);
  
  if (!dissector_try_port(m3ua_si_dissector_table, si, payload_tvb, pinfo, tree)) {
    call_dissector(data_handle, payload_tvb, pinfo, tree);
  }
}

#define CORR_ID_OFFSET PARAMETER_VALUE_OFFSET
#define CORR_ID_LENGTH 4

static void
dissect_m3ua_correlation_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 id;
  
  id = tvb_get_ntohl(parameter_tvb, CORR_ID_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_correlation_identifier, parameter_tvb, CORR_ID_OFFSET, CORR_ID_LENGTH, id);
  proto_item_set_text(parameter_item, "Correlation Identifer (%u)", id);
}

#define REG_STATUS_LENGTH  4
#define REG_STATUS_OFFSET  PARAMETER_VALUE_OFFSET

static const value_string m3ua_registration_status_values[] = {
  {  0,           "Successfully Registered" },
  {  1,           "Error - Unknown" },
  {  2,           "Error - Invalid DPC" },
  {  3,           "Error - Invalid Network Appearance" },
  {  4,           "Error - Invalid Routing Key" },
  {  5,           "Error - Permission Denied" },
  {  6,           "Error - Cannot Support Unique Routing" },
  {  7,           "Error - Routing Key not Currently Provisioned" },
  {  8,           "Error - Insufficient Resources" },
  {  9,           "Error - Unsupported RK parameter Field" },
  { 10,           "Error - Unsupported/Invalid Traffic Handling Mode" },
  {  0,           NULL } };

static void
dissect_m3ua_registration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 status;
  
  status = tvb_get_ntohl(parameter_tvb, REG_STATUS_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_registration_status, parameter_tvb, REG_STATUS_OFFSET, REG_STATUS_LENGTH, status);
  proto_item_set_text(parameter_item, "Registration status (%s)", val_to_str(status, m3ua_registration_status_values, "unknown"));
}

#define DEREG_STATUS_LENGTH  4
#define DEREG_STATUS_OFFSET  PARAMETER_VALUE_OFFSET

static const value_string m3ua_deregistration_status_values[] = {
  { 0,          "Successfully Deregistered" },
  { 1,          "Error - Unknown" },
  { 2,          "Error - Invalid Routing Context" },
  { 3,          "Error - Permission Denied" },
  { 4,          "Error - Not Registered" },
  { 5,          "Error - ASP Currently Active for Routing Context" },
  { 0,          NULL } };

static void
dissect_m3ua_deregistration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 status;
  
  status = tvb_get_ntohl(parameter_tvb, DEREG_STATUS_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_m3ua_deregistration_status, parameter_tvb, DEREG_STATUS_OFFSET, DEREG_STATUS_LENGTH, status);
  proto_item_set_text(parameter_item, "Deregistration status (%s)", val_to_str(status, m3ua_deregistration_status_values, "unknown"));
}

static void
dissect_m3ua_registration_results_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;
  
  length            = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_m3ua_parameters(parameters_tvb, pinfo, tree, parameter_tree);
  proto_item_set_text(parameter_item, "Registration results");
}

static void
dissect_m3ua_deregistration_results_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  tvbuff_t *parameters_tvb;
  guint16 length, parameters_length;
  
  length            = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameters_length = length - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_m3ua_parameters(parameters_tvb, pinfo, tree, parameter_tree);
  proto_item_set_text(parameter_item, "Deregistration results");
}

static void
dissect_m3ua_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 tag, length, parameter_value_length;
  
  tag    = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_bytes(parameter_tree, hf_m3ua_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, 
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length));

  proto_item_set_text(parameter_item, "Parameter with tag %u and %u byte%s value", tag, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

static void
dissect_m3ua_v6_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  guint16 tag, length, padding_length, total_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  /* calculate padding and total length */
  padding_length = tvb_length(parameter_tvb) - length;
  total_length   = length + padding_length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_m3ua_parameter);

  /* add tag and length to the m3ua tree */
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, tag, 
                             "Parameter tag: %s (0x%x)", val_to_str(tag, m3ua_v6_parameter_tag_values, "unknown"), tag);
  proto_tree_add_uint(parameter_tree, hf_m3ua_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, length);

  switch(tag) {
  case V6_NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_m3ua_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_PROTOCOL_DATA_1_PARAMETER_TAG:
    dissect_m3ua_protocol_data_1_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V6_PROTOCOL_DATA_2_PARAMETER_TAG:
    dissect_m3ua_protocol_data_2_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V6_INFO_PARAMETER_TAG:
    dissect_m3ua_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_AFFECTED_DESTINATIONS_PARAMETER_TAG:
    dissect_m3ua_affected_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_m3ua_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_m3ua_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_m3ua_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_USER_CAUSE_PARAMETER_TAG:
    dissect_m3ua_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_REASON_PARAMETER_TAG:
    dissect_m3ua_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_m3ua_v6_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ERROR_CODE_PARAMETER_TAG:
    dissect_m3ua_v6_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_STATUS_PARAMETER_TAG:
    dissect_m3ua_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_CONGESTION_INDICATION_PARAMETER_TAG:
    dissect_m3ua_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_CONCERNED_DESTINATION_PARAMETER_TAG:
    dissect_m3ua_concerned_destination_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ROUTING_KEY_PARAMETER_TAG:
    dissect_m3ua_routing_key_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V6_REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_m3ua_v6_registration_result_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_m3ua_v6_deregistration_result_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG:
    dissect_m3ua_local_routing_key_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_DESTINATION_POINT_CODE_PARAMETER_TAG:
    dissect_m3ua_destination_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_SERVICE_INDICATORS_PARAMETER_TAG:
    dissect_m3ua_service_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_SUBSYSTEM_NUMBERS_PARAMETER_TAG:
    dissect_m3ua_subsystem_numbers_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG:
    dissect_m3ua_originating_point_code_list_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_CIRCUIT_RANGE_PARAMETER_TAG:
    dissect_m3ua_circuit_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V6_REGISTRATION_RESULTS_PARAMETER_TAG:
    dissect_m3ua_registration_results_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V6_DEREGISTRATION_RESULTS_PARAMETER_TAG:
    dissect_m3ua_deregistration_results_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  default:
    dissect_m3ua_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_m3ua_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, 
                         tvb_get_ptr(parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length));
}

static void
dissect_m3ua_v10_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  guint16 tag, length, padding_length, total_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  /* calculate padding and total length */
  padding_length = tvb_length(parameter_tvb) - length;
  total_length   = length + padding_length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_m3ua_parameter);

  /* add tag and length to the m3ua tree */
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, tag, 
                             "Parameter tag: %s (0x%x)", val_to_str(tag, m3ua_v10_parameter_tag_values, "unknown"), tag);
  proto_tree_add_uint(parameter_tree, hf_m3ua_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, length);

  switch(tag) {
  case V10_INFO_STRING_PARAMETER_TAG:
    dissect_m3ua_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_m3ua_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_m3ua_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_m3ua_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_m3ua_v10_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_ERROR_CODE_PARAMETER_TAG:
    dissect_m3ua_v10_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_STATUS_PARAMETER_TAG:
    dissect_m3ua_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_m3ua_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_AFFECTED_POINT_CODE_PARAMETER_TAG:
    dissect_m3ua_affected_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_m3ua_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_USER_CAUSE_PARAMETER_TAG:
    dissect_m3ua_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_CONGESTION_INDICATIONS_PARAMETER_TAG:
    dissect_m3ua_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_CONCERNED_DESTINATION_PARAMETER_TAG:
    dissect_m3ua_concerned_destination_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_ROUTING_KEY_PARAMETER_TAG:
    dissect_m3ua_routing_key_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V10_REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_m3ua_v10_registration_result_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V10_DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_m3ua_v10_deregistration_result_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V10_LOCAL_ROUTING_KEY_IDENTIFIER_PARAMETER_TAG:
    dissect_m3ua_local_routing_key_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_DESTINATION_POINT_CODE_PARAMETER_TAG:
    dissect_m3ua_destination_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_SERVICE_INDICATORS_PARAMETER_TAG:
    dissect_m3ua_service_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_ORIGINATING_POINT_CODE_LIST_PARAMETER_TAG:
    dissect_m3ua_originating_point_code_list_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_CIRCUIT_RANGE_PARAMETER_TAG:
    dissect_m3ua_circuit_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_PROTOCOL_DATA_PARAMETER_TAG:
    dissect_m3ua_protocol_data_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case V10_CORRELATION_IDENTIFIER_PARAMETER_TAG:
    dissect_m3ua_correlation_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_REGISTRATION_STATUS_PARAMETER_TAG:
    dissect_m3ua_registration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case V10_DEREGISTRATION_STATUS_PARAMETER_TAG:
    dissect_m3ua_deregistration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_m3ua_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_m3ua_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, 
                         tvb_get_ptr(parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length));
}

static void
dissect_m3ua_parameters(tvbuff_t *parameters_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  gint offset, length, padding_length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while((remaining_length = tvb_reported_length_remaining(parameters_tvb, offset))) {
    length         = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    if (remaining_length >= length)
      total_length = MIN(length + padding_length, remaining_length);
    else
      total_length = length + padding_length;
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb    = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    switch(m3ua_version) {
      case M3UA_V6:
        dissect_m3ua_v6_parameter(parameter_tvb, pinfo, tree, m3ua_tree); 
        break;
      case M3UA_V10:
        dissect_m3ua_v10_parameter(parameter_tvb, pinfo, tree, m3ua_tree);
        break;
    }
    /* get rid of the handled parameter */
    offset += total_length;
  }
}


static void
dissect_m3ua_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m3ua_tree)
{
  tvbuff_t *common_header_tvb, *parameters_tvb;

  common_header_tvb = tvb_new_subset(message_tvb, 0, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  parameters_tvb    = tvb_new_subset(message_tvb, COMMON_HEADER_LENGTH, -1, -1);
  dissect_m3ua_common_header(common_header_tvb, pinfo, m3ua_tree);  
  if (m3ua_tree)
    dissect_m3ua_parameters(parameters_tvb, pinfo, tree, m3ua_tree);
}

static void
dissect_m3ua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m3ua_item;
  proto_tree *m3ua_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "M3UA");
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m3ua protocol tree */
    m3ua_item = proto_tree_add_item(tree, proto_m3ua, message_tvb, 0, -1, FALSE);
    m3ua_tree = proto_item_add_subtree(m3ua_item, ett_m3ua);
  } else {
    m3ua_tree = NULL;
  };
  /* dissect the message */
  dissect_m3ua_message(message_tvb, pinfo, tree, m3ua_tree);
}

/* Register the protocol with Ethereal */
void
proto_register_m3ua(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_m3ua_version,
      { "Version", "m3ua.version",
	      FT_UINT8, BASE_DEC, VALS(m3ua_protocol_version_values), 0x0,          
        "", HFILL }
    },
    { &hf_m3ua_reserved,
      { "Reserved", "m3ua.reserved",
	      FT_UINT8, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_message_class,
      { "Message class", "m3ua.message_class",
        FT_UINT8, BASE_DEC, VALS(m3ua_message_class_values), 0x0,          
	      "", HFILL }
    },
    { &hf_m3ua_message_type,
      { "Message Type", "m3ua.message_type",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_m3ua_message_length,
      { "Message length", "m3ua.message_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_parameter_tag,
      { "Parameter Tag", "m3ua.parameter_tag",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
        "", HFILL }
    },
    { &hf_m3ua_parameter_length,
      { "Parameter length", "m3ua.parameter_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_parameter_value,
      { "Paramter value", "m3ua.parameter_value",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_parameter_padding,
      { "Padding", "m3ua.parameter_padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_info_string,
      { "Info string", "m3ua.info_string",
	      FT_STRING, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_routing_context,
      { "Routing context", "m3ua.routing_context",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
        "", HFILL }
    }, 
    { &hf_m3ua_diagnostic_information,
      { "Diagnostic information", "m3ua.diagnostic_information",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_heartbeat_data,
      { "Heartbeat data", "m3ua.heartbeat_data",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_error_code,
      { "Error code", "m3ua.error_code",
        FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_status_type,
      { "Status type", "m3ua.status_type",
	      FT_UINT16, BASE_DEC, VALS(m3ua_status_type_values), 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_status_info,
      { "Status info", "m3ua.status_info",
	      FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_asp_identifier,
      { "ASP identifier", "m3ua.asp_identifier",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_affected_point_code_mask,
      { "Mask", "m3ua.affected_point_code_mask",
        FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_affected_point_code_pc,
      { "Affected point code", "m3ua.affected_point_code_pc",
	      FT_UINT24, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_network_appearance,
      { "Network appearance", "m3ua.network_appearance",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_unavailability_cause,
      { "Unavailability cause", "m3ua.unavailability_cause",
	      FT_UINT16, BASE_DEC, VALS(m3ua_unavailability_cause_values), 0x0,          
        "", HFILL }
    }, 
    { &hf_m3ua_user_identity,
      { "User Identity", "m3ua.user_identity",
	       FT_UINT16, BASE_DEC, VALS(m3ua_user_identity_values), 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_congestion_reserved,
      { "Reserved", "m3ua.congestion_reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_congestion_level,
      { "Congestion level", "m3ua.congestion_level",
	       FT_UINT8, BASE_DEC, VALS(m3ua_congestion_level_values), 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_concerned_dest_reserved,
      { "Reserved", "m3ua.concerned_reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_concerned_dest_pc,
      { "Concerned DPC", "m3ua.concerned_dpc",
	       FT_UINT24, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_dpc_mask,
      { "Mask", "m3ua.dpc_mask",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_dpc_pc,
      { "Destination point code", "m3ua.dpc_pc",
	       FT_UINT24, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_si,
      { "Service indicator", "m3ua_si",
        FT_UINT8, BASE_DEC, VALS(m3ua_user_identity_values), 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_ssn,
      { "Subsystem number", "m3ua_ssn",
        FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_opc_list_mask,
      { "Mask", "m3ua.opc_list_mask",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_opc_list_pc,
      { "Originating point code", "m3ua.opc_list_pc",
	       FT_UINT24, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_cic_range_mask,
      { "Mask", "m3ua.cic_range_mask",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_cic_range_pc,
      { "Originating point code", "m3ua.cic_range_pc",
	       FT_UINT24, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_cic_range_lower,
      { "Lower CIC value", "m3ua.cic_range_lower",
	      FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_m3ua_cic_range_upper,
      { "Upper CIC value", "m3ua.cic_range_upper",
	       FT_UINT16, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_m3ua_local_rk_identifier,
      { "Local routing key identifier", "m3ua.local_rk_identifier",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_li,
      { "Length indicator", "m3ua.protocol_data_2_li",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_protocol_data_opc,
      { "OPC", "m3ua.protocol_data_opc",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_protocol_data_dpc,
      { "DPC", "m3ua.protocol_data_dpc",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_protocol_data_si,
      { "SI", "m3ua.protocol_data_si",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_protocol_data_ni,
      { "NI", "m3ua.protocol_data_ni",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_protocol_data_mp,
      { "MP", "m3ua.protocol_data_mp",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_protocol_data_sls,
      { "SLS", "m3ua.protocol_data_sls",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_correlation_identifier,
      { "Correlation Identifier", "m3ua.correlation_identifier",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_m3ua_registration_status,
      { "Registration status", "m3ua.registration_status",
	      FT_UINT32, BASE_DEC, VALS(m3ua_registration_status_values), 0x0,          
	      "", HFILL }
    },
    { &hf_m3ua_deregistration_status,
      { "Deregistration status", "m3ua.deregistration_status",
	      FT_UINT32, BASE_DEC, VALS(m3ua_deregistration_status_values), 0x0,          
	      "", HFILL }
    },
    { &hf_m3ua_reason,
      { "Reason", "m3ua_reason",
        FT_UINT32, BASE_DEC, VALS(m3ua_reason_values), 0x0,          
        "", HFILL }
    }, 
    { &hf_m3ua_traffic_mode_type,
      { "Traffic mode Type", "m3ua.traffic_mode_type",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_registration_result_identifier,
      { "Local RK-identifier value", "m3ua.registration_result_identifier",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_registration_result_status,
      { "Registration status", "m3ua.registration_results_status",
	      FT_UINT32, BASE_DEC, VALS(m3ua_registration_result_status_values), 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_registration_result_context,
      { "Routing context", "m3ua.registration_result_routing_context",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_deregistration_result_status,
      { "De-Registration status", "m3ua.deregistration_results_status",
	      FT_UINT32, BASE_DEC, VALS(m3ua_deregistration_result_status_values), 0x0,          
	      "", HFILL }
    }, 
    { &hf_m3ua_deregistration_result_context,
      { "Routing context", "m3ua.deregistration_result_routing_context",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m3ua,
    &ett_m3ua_parameter,
  };
  
  static enum_val_t m3ua_options[] = {
    { "Internet Draft version 6",        M3UA_V6 },
    { "Internet Draft version 10",       M3UA_V10 },
    { NULL, 0 }
  };

  /* Register the protocol name and description */
  proto_m3ua = proto_register_protocol("MTP 3 User Adaptation Layer", "M3UA",  "m3ua");
  m3ua_module = prefs_register_protocol(proto_m3ua, NULL);
  prefs_register_enum_preference(m3ua_module,
				                         "version", "M3UA Version", "Internet Draft version used by Ethereal",
				                         &m3ua_version, m3ua_options, FALSE);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_m3ua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  m3ua_si_dissector_table = register_dissector_table("m3ua.protocol_data_si", "MTP3 Service indicator", FT_UINT8, BASE_HEX);

};

void
proto_reg_handoff_m3ua(void)
{
  dissector_handle_t m3ua_handle;

  /*
   * Get a handle for the MTP3 dissector.
   */
  mtp3_handle = find_dissector("mtp3");
  data_handle = find_dissector("data");
  m3ua_handle = create_dissector_handle(dissect_m3ua, proto_m3ua);
  dissector_add("sctp.ppi",  M3UA_PAYLOAD_PROTO_ID, m3ua_handle);
  dissector_add("sctp.port", SCTP_PORT_M3UA, m3ua_handle);
}
