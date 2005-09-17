/* packet-m2ua.c
 * Routines for MTP2 User Adaptation Layer dissection
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/rfc/rfc3331.txt
 * To do: - provide better handling of length parameters
 *
 * Copyright 2002, Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * $Id$
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

#define SCTP_PORT_M2UA                  2904
#define NETWORK_BYTE_ORDER              FALSE



/* Initialize the protocol and registered fields */
static int proto_m2ua =                 -1;
static int hf_version =                 -1;
static int hf_reserved =                -1;
static int hf_message_class =           -1;
static int hf_message_type =            -1;
static int hf_message_length =          -1;
static int hf_parameter_tag =           -1;
static int hf_parameter_length =        -1;
static int hf_parameter_value =         -1;
static int hf_parameter_padding =       -1;
static int hf_interface_id_int =        -1;
static int hf_interface_id_text =       -1;
static int hf_info_string =             -1;
static int hf_diagnostic_information =  -1;
static int hf_interface_id_start =      -1;
static int hf_interface_id_stop =       -1;
static int hf_heartbeat_data =          -1;
static int hf_traffic_mode_type =       -1;
static int hf_error_code =              -1;
static int hf_status_type =             -1;
static int hf_status_ident =            -1;
static int hf_asp_id =                  -1;
static int hf_correlation_id =          -1;
static int hf_data_2_li =               -1;
static int hf_state =                   -1;
static int hf_event =                   -1;
static int hf_congestion_status =       -1;
static int hf_discard_status =          -1;
static int hf_action =                  -1;
static int hf_sequence_number =         -1;
static int hf_retrieval_result =        -1;
static int hf_local_lk_id =             -1;
static int hf_sdt_reserved =            -1;
static int hf_sdt_id =                  -1;
static int hf_sdl_reserved =            -1;
static int hf_sdl_id =                  -1;
static int hf_registration_status =     -1;
static int hf_deregistration_status =   -1;

/* Initialize the subtree pointers */
static gint ett_m2ua =                  -1;
static gint ett_m2ua_parameter =        -1;

static dissector_handle_t mtp3_handle;

static void
dissect_parameters(tvbuff_t *, packet_info *, proto_tree *, proto_tree *);

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

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

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE         0
#define MESSAGE_CLASS_ASPSM_MESSAGE        3
#define MESSAGE_CLASS_ASPTM_MESSAGE        4
#define MESSAGE_CLASS_MAUP_MESSAGE         6
#define MESSAGE_CLASS_IIM_MESSAGE         10

static const value_string message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_MAUP_MESSAGE,   "MTP2 user adaptation messages" },
  { MESSAGE_CLASS_IIM_MESSAGE,    "Interface identifier management messages" },
  { 0,                            NULL } };

/* MGMT */
#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1

/* ASPSM */
#define MESSAGE_TYPE_UP                   1
#define MESSAGE_TYPE_DOWN                 2
#define MESSAGE_TYPE_BEAT                 3
#define MESSAGE_TYPE_UP_ACK               4
#define MESSAGE_TYPE_DOWN_ACK             5
#define MESSAGE_TYPE_BEAT_ACK             6

/* ASPTM */
#define MESSAGE_TYPE_ACTIVE               1
#define MESSAGE_TYPE_INACTIVE             2
#define MESSAGE_TYPE_ACTIVE_ACK           3
#define MESSAGE_TYPE_INACTIVE_ACK         4

/* MAUP */
#define MESSAGE_TYPE_DATA                 1
#define MESSAGE_TYPE_ESTAB_REQ            2
#define MESSAGE_TYPE_ESTAB_CONF           3
#define MESSAGE_TYPE_REL_REQ              4
#define MESSAGE_TYPE_REL_CONF             5
#define MESSAGE_TYPE_REL_IND              6
#define MESSAGE_TYPE_STATE_REQ            7
#define MESSAGE_TYPE_STATE_CONF           8
#define MESSAGE_TYPE_STATE_IND            9
#define MESSAGE_TYPE_DATA_RETR_REQ       10
#define MESSAGE_TYPE_DATA_RETR_CONF      11
#define MESSAGE_TYPE_DATA_RETR_IND       12
#define MESSAGE_TYPE_DATA_RETR_COMP_IND  13
#define MESSAGE_TYPE_CONG_IND            14
#define MESSAGE_TYPE_DATA_ACK            15

/* IIM */
#define MESSAGE_TYPE_REG_REQ              1
#define MESSAGE_TYPE_REG_RSP              2
#define MESSAGE_TYPE_DEREG_REQ            3
#define MESSAGE_TYPE_DEREG_RSP            4

static const value_string message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,                "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,               "Notify (NTFY)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,                 "ASP up (UP)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,               "ASP down (DOWN)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,               "Heartbeat (BEAT)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,             "ASP up ack (UP ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,           "ASP down ack (DOWN ACK)" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,           "Heartbeat ack (BEAT ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,            "ASP active (ACTIVE)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,          "ASP inactive (INACTIVE)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,        "ASP active ack (ACTIVE ACK)" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK ,      "ASP inactive ack (INACTIVE ACK)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA,               "DATA (DATA)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_ESTAB_REQ,          "Establish request (ESTAB_REQ)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_ESTAB_CONF,         "Establish confirm (ESTAB_CONF)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_REL_REQ,            "Release request (REL_REQ)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_REL_CONF,           "Release confirm (REL_CONF)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_REL_IND,            "Release indication (REL_IND)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_STATE_REQ,          "State request (STATE_REQ)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_STATE_CONF,         "State confirm (STATE_CONF)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_STATE_IND,          "State indication (STATE_IND)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_REQ,      "Data retrieval request (DATA_RETR_REQ)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_CONF,     "Data retrieval confirm (DATA_RETR_CONF)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_IND,      "Data retrieval indication (DATA_RETR_IND)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_COMP_IND, "Data retrieval complete indication (DATA_RETR_COMP_IND)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_CONG_IND,           "Congestion indication (CONG_IND)" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_ACK,           "Data acknowledge (DATA_ACK)" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,           "Registration request (REG_REQ)" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,           "Registration response (REG_RSP)" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,         "Deregistration request (DEREG_REQ)" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,         "Deregistration response (DEREG_RSP)" },
  { 0,                           NULL } };

static const value_string message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,                "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,               "NTFY" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,                 "ASP_UP" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,               "ASP_DOWN" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,               "BEAT" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,             "ASP_UP_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,           "ASP_DOWN_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,           "BEAT_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,            "ASP_ACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,          "ASP_INACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,        "ASP_ACTIVE_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK ,      "ASP_INACTIVE_ACK" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA,               "DATA" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_ESTAB_REQ,          "ESTAB_REQ" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_ESTAB_CONF,         "ESTAB_CONF" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_REL_REQ,            "REL_REQ" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_REL_CONF,           "REL_CONF" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_REL_IND,            "REL_IND" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_STATE_REQ,          "STATE_REQ" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_STATE_CONF,         "STATE_CONF" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_STATE_IND,          "STATE_IND" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_REQ,      "DATA_RETR_REQ" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_CONF,     "DATA_RETR_CONF" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_IND,      "DATA_RETR_IND" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_RETR_COMP_IND, "DATA_RETR_COMP_IND" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_CONG_IND,           "CONG_IND" },
  { MESSAGE_CLASS_MAUP_MESSAGE  * 256 + MESSAGE_TYPE_DATA_ACK,           "DATA_ACK" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,           "REG_REQ" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,           "REG_RSP" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,         "DEREG_REQ" },
  { MESSAGE_CLASS_IIM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,         "DEREG_RSP" },
  { 0,                           NULL } };

static void
dissect_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *m2ua_tree)
{
  guint8  message_class, message_type;

  /* Extract the common header */
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_class * 256 + message_type, message_class_type_acro_values, "reserved"));

  if (m2ua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(m2ua_tree, hf_version,        common_header_tvb, VERSION_OFFSET,        VERSION_LENGTH,        NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2ua_tree, hf_reserved,       common_header_tvb, RESERVED_OFFSET,       RESERVED_LENGTH,       NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2ua_tree, hf_message_class,  common_header_tvb, MESSAGE_CLASS_OFFSET,  MESSAGE_CLASS_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_uint_format(m2ua_tree, hf_message_type, common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH, message_type,
                               "Message type: %s (%u)",
                               val_to_str(message_class * 256 + message_type, message_class_type_values, "reserved"), message_type);
    proto_tree_add_item(m2ua_tree, hf_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, NETWORK_BYTE_ORDER);
  }
}

#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_TAG_OFFSET    0
#define PARAMETER_LENGTH_OFFSET (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET  (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET PARAMETER_TAG_OFFSET


#define INT_INTERFACE_ID_OFFSET PARAMETER_VALUE_OFFSET
#define INT_INTERFACE_ID_LENGTH 4

static void
dissect_interface_identifier_int_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_interface_id_int, parameter_tvb, INT_INTERFACE_ID_OFFSET, INT_INTERFACE_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%d)", tvb_get_ntohl(parameter_tvb, INT_INTERFACE_ID_OFFSET));
}

#define TEXT_INTERFACE_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_interface_identifier_text_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 interface_id_length;

  interface_id_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  proto_tree_add_item(parameter_tree, hf_interface_id_text, parameter_tvb, TEXT_INTERFACE_ID_OFFSET, interface_id_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%.*s)", interface_id_length,
                         (const char *)tvb_get_ptr(parameter_tvb, TEXT_INTERFACE_ID_OFFSET, interface_id_length));
}

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info_string_length;

  info_string_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%.*s)", info_string_length,
                         (const char *)tvb_get_ptr(parameter_tvb, INFO_STRING_OFFSET, info_string_length));
}

#define DIAGNOSTIC_INFO_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 diag_info_length;

  diag_info_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_diagnostic_information, parameter_tvb, DIAGNOSTIC_INFO_OFFSET, diag_info_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u byte%s)", diag_info_length, plurality(diag_info_length, "", "s"));
}

#define START_LENGTH 4
#define END_LENGTH   4
#define INTERVAL_LENGTH (START_LENGTH + END_LENGTH)

#define START_OFFSET 0
#define END_OFFSET   (START_OFFSET + START_LENGTH)

static void
dissect_interface_identifier_range_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 number_of_ranges, range_number;
  gint offset;

  number_of_ranges = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / INTERVAL_LENGTH;
  offset = PARAMETER_VALUE_OFFSET;
  for(range_number = 1; range_number <= number_of_ranges; range_number++) {
    proto_tree_add_item(parameter_tree, hf_interface_id_start, parameter_tvb, offset + START_OFFSET, START_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(parameter_tree, hf_interface_id_stop,  parameter_tvb, offset + END_OFFSET,   END_LENGTH,   NETWORK_BYTE_ORDER);
    offset += INTERVAL_LENGTH;
  };

  proto_item_append_text(parameter_item, " (%u range%s)", number_of_ranges, plurality(number_of_ranges, "", "s"));
}

#define HEARTBEAT_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 heartbeat_data_length;

  heartbeat_data_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_heartbeat_data, parameter_tvb, HEARTBEAT_DATA_OFFSET, heartbeat_data_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}

#define OVER_RIDE_TYPE   1
#define LOAD_SHARE_TYPE  2
#define BROADCAST_TYPE   3

static const value_string traffic_mode_type_values[] = {
  { OVER_RIDE_TYPE ,            "Override" },
  { LOAD_SHARE_TYPE,            "Load-share" },
  { BROADCAST_TYPE,             "Broadcast" },
  { 0,                          NULL } };

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), traffic_mode_type_values, "unknown"));
}

#define INVALID_VERSION_ERROR_CODE                       0x01
#define INVALID_INTERFACE_IDENTIFIER_ERROR_CODE          0x02
#define UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE             0x03
#define UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE              0x04
#define UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR_CODE     0x05
#define UNEXPECTED_MESSAGE_ERROR_CODE                    0x06
#define PROTOCOL_ERROR_ERROR_CODE                        0x07
#define UNSUPPORTED_INTERFACE_IDENTIFIER_TYPE_ERROR_CODE 0x08
#define INVALID_STREAM_IDENTIFIER_ERROR_CODE             0x09
#define REFUSED_ERROR_CODE                               0x0d
#define ASP_IDENTIFIER_REQUIRED_ERROR_CODE               0x0e
#define INVALID_ASP_IDENTIFIER_ERROR_CODE                0x0f
#define ASP_ACTIVE_FOR_INTERFACE_IDENTIFIER_ERROR_CODE   0x10
#define INVALID_PARAMETER_VALUE_ERROR_CODE               0x11
#define PARAMETER_FIELD_ERROR_CODE                       0x12
#define UNEXPECTED_PARAMETER_ERROR_CODE                  0x13
#define MISSING_PARAMETER_ERROR_CODE                     0x16

static const value_string error_code_values[] = {
  { INVALID_VERSION_ERROR_CODE,                       "Invalid version" },
  { INVALID_INTERFACE_IDENTIFIER_ERROR_CODE,          "Invalid interface identifier" },
  { UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE,             "Unsupported message class" },
  { UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE,              "Unsupported message type" },
  { UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR_CODE,     "Unsupported traffic handling mode" },
  { UNEXPECTED_MESSAGE_ERROR_CODE,                    "Unexpected message" },
  { PROTOCOL_ERROR_ERROR_CODE,                        "Protocol error" },
  { UNSUPPORTED_INTERFACE_IDENTIFIER_TYPE_ERROR_CODE, "Unsupported interface identifier type" },
  { INVALID_STREAM_IDENTIFIER_ERROR_CODE,             "Invalid stream identifier" },
  { REFUSED_ERROR_CODE,                               "Refused - management blocking" },
  { ASP_IDENTIFIER_REQUIRED_ERROR_CODE,               "ASP identifier required" },
  { INVALID_ASP_IDENTIFIER_ERROR_CODE,                "Invalid ASP identifier" },
  { ASP_ACTIVE_FOR_INTERFACE_IDENTIFIER_ERROR_CODE,   "ASP active for interface identifier" },
  { INVALID_PARAMETER_VALUE_ERROR_CODE,               "Invalid parameter value" },
  { PARAMETER_FIELD_ERROR_CODE,                       "Parameter field error" },
  { UNEXPECTED_PARAMETER_ERROR_CODE,                  "Unexpected parameter" },
  { MISSING_PARAMETER_ERROR_CODE,                     "Missing parameter" },
  { 0,                                                NULL } };

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), error_code_values, "unknown"));
}

#define AS_STATE_CHANGE_TYPE       1
#define OTHER_TYPE                 2

static const value_string status_type_values[] = {
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

static const value_string status_type_id_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  { OTHER_TYPE           * 256 * 256 + ASP_FAILURE_INFO,          "ASP Failure" },
  {0,                           NULL } };

#define STATUS_TYPE_LENGTH  2
#define STATUS_IDENT_LENGTH 2

#define STATUS_TYPE_OFFSET  PARAMETER_VALUE_OFFSET
#define STATUS_IDENT_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

static void
dissect_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_id;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_id   = tvb_get_ntohs(parameter_tvb, STATUS_IDENT_OFFSET);

  proto_tree_add_item(parameter_tree, hf_status_type, parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_uint_format(parameter_tree, hf_status_ident,  parameter_tvb, STATUS_IDENT_OFFSET, STATUS_IDENT_LENGTH,
                             status_id, "Status identification: %u (%s)", status_id,
                             val_to_str(status_type * 256 * 256 + status_id, status_type_id_values, "unknown"));

  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(status_type * 256 * 256 + status_id, status_type_id_values, "unknown status information"));
}

#define ASP_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define ASP_IDENTIFIER_LENGTH  4

static void
dissect_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_asp_id, parameter_tvb, ASP_IDENTIFIER_OFFSET, ASP_IDENTIFIER_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, ASP_IDENTIFIER_OFFSET));
}

#define CORRELATION_ID_LENGTH 4
#define CORRELATION_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_correlation_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET));
}

#define DATA_1_MTP3_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_protocol_data_1_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_item *parameter_item)
{
  tvbuff_t *payload_tvb;
  guint32 payload_length;

  payload_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  payload_tvb = tvb_new_subset(parameter_tvb, DATA_1_MTP3_OFFSET, payload_length, payload_length);
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);

  proto_item_set_text(parameter_item, "Data 1 parameter");
}

#define DATA_2_LI_LENGTH   1
#define DATA_2_LI_OFFSET   PARAMETER_VALUE_OFFSET
#define DATA_2_MTP3_OFFSET (DATA_2_LI_OFFSET + DATA_2_LI_LENGTH)

static void
dissect_protocol_data_2_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  tvbuff_t *payload_tvb;
  guint32 payload_length;

  payload_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - DATA_2_LI_LENGTH;

  proto_tree_add_item(parameter_tree, hf_data_2_li, parameter_tvb, DATA_2_LI_OFFSET, DATA_2_LI_LENGTH, NETWORK_BYTE_ORDER);
  payload_tvb = tvb_new_subset(parameter_tvb, DATA_2_MTP3_OFFSET, payload_length, payload_length);
  proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH + DATA_2_LI_LENGTH);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}


#define STATUS_LPO_SET          0x0
#define STATUS_LPO_CLEAR        0x1
#define STATUS_EMER_SET         0x2
#define STATUS_EMER_CLEAR       0x3
#define STATUS_FLUSH_BUFFERS    0x4
#define STATUS_CONTINUE         0x5
#define STATUS_CLEAR_RTB        0x6
#define STATUS_AUDIT            0x7
#define STATUS_CONG_CLEAR       0x8
#define STATUS_CONG_ACCEPT      0x9
#define STATUS_CONG_DISCARD     0xa

static const value_string state_values[] = {
  { STATUS_LPO_SET,        "Request local processor outage" },
  { STATUS_LPO_CLEAR,      "Request local processor outage recovered" },
  { STATUS_EMER_SET,       "Request emergency alignment" },
  { STATUS_EMER_CLEAR,     "Request normal alignment (cancel emergency)" },
  { STATUS_FLUSH_BUFFERS,  "Flush or clear receive, transmit and retransmit queues" },
  { STATUS_CONTINUE,       "Continue or Resume" },
  { STATUS_CLEAR_RTB,      "Clear the retransmit queue" },
  { STATUS_AUDIT,          "Audit state of link" },
  { STATUS_CONG_CLEAR,     "Congestion cleared" },
  { STATUS_CONG_ACCEPT,    "Congestion accept" },
  { STATUS_CONG_DISCARD,   "Congestion discard" },
  {0,                       NULL } };

#define STATE_LENGTH 4
#define STATE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_state_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_state, parameter_tvb, STATE_OFFSET, STATE_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, STATE_OFFSET), state_values, "unknown"));
}

#define EVENT_RPO_ENTER        0x1
#define EVENT_RPO_EXIT         0x2
#define EVENT_LPO_ENTER        0x3
#define EVENT_LPO_EXIT         0x4

static const value_string event_values[] = {
  { EVENT_RPO_ENTER, "Remote entered processor outage" },
  { EVENT_RPO_EXIT,  "Remote exited processor outage" },
  { EVENT_LPO_ENTER, "Link entered processor outage" },
  { EVENT_LPO_EXIT,  "Link exited processor outage" },
  {0,                NULL } };

#define EVENT_LENGTH 4
#define EVENT_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_state_event_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_event, parameter_tvb, EVENT_OFFSET, EVENT_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, STATE_OFFSET), event_values, "unknown"));
}

#define LEVEL_NONE       0x0
#define LEVEL_1          0x1
#define LEVEL_2          0x2
#define LEVEL_3          0x3

static const value_string level_values[] = {
  { LEVEL_NONE, "No congestion" },
  { LEVEL_1,    "Congestion Level 1" },
  { LEVEL_2,    "Congestion Level 2" },
  { LEVEL_3,    "Congestion Level 3" },
  {0,           NULL } };

#define CONGESTION_STATUS_LENGTH 4
#define CONGESTION_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_congestion_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_congestion_status, parameter_tvb, CONGESTION_STATUS_OFFSET, CONGESTION_STATUS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, CONGESTION_STATUS_OFFSET), level_values, "unknown"));
}

#define DISCARD_STATUS_LENGTH 4
#define DISCARD_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_discard_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_discard_status, parameter_tvb, DISCARD_STATUS_OFFSET, DISCARD_STATUS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, DISCARD_STATUS_OFFSET), level_values, "unknown"));
}

#define ACTION_RTRV_BSN      0x1
#define ACTION_RTRV_MSGS     0x2

static const value_string action_values[] = {
  { ACTION_RTRV_BSN,  "Retrieve the backward sequence number" },
  { ACTION_RTRV_MSGS, "Retrieve the PDUs from the transmit and retransmit queues" },
  {0,                  NULL } };


#define ACTION_LENGTH 4
#define ACTION_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_action_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_uint(parameter_tree, hf_action, parameter_tvb, ACTION_OFFSET, ACTION_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ACTION_OFFSET), action_values, "unknown"));
}

#define SEQUENCE_NUMBER_LENGTH 4
#define SEQUENCE_NUMBER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sequence_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sequence_number, parameter_tvb, SEQUENCE_NUMBER_OFFSET, SEQUENCE_NUMBER_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, SEQUENCE_NUMBER_OFFSET));
}

#define RESULT_SUCCESS       0x0
#define RESULT_FAILURE       0x1

static const value_string retrieval_result_values[] = {
  { RESULT_SUCCESS,    "Action successful" },
  { RESULT_FAILURE ,   "Action failed" },
  { 0,                  NULL } };


#define RETRIEVAL_RESULT_LENGTH 4
#define RETRIEVAL_RESULT_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_retrieval_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_retrieval_result, parameter_tvb, RETRIEVAL_RESULT_OFFSET, RETRIEVAL_RESULT_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)",  val_to_str(tvb_get_ntohl(parameter_tvb, RETRIEVAL_RESULT_OFFSET), retrieval_result_values, "unknown"));
}

static void
dissect_link_key_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16 parameters_length;

  parameters_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

#define LOCAL_LK_ID_LENGTH 4
#define LOCAL_LK_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_local_lk_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_local_lk_id, parameter_tvb, LOCAL_LK_ID_OFFSET, LOCAL_LK_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u)",  tvb_get_ntohl(parameter_tvb, LOCAL_LK_ID_OFFSET));
}

#define SDT_RESERVED_LENGTH 2
#define SDT_ID_LENGTH       2
#define SDT_RESERVED_OFFSET PARAMETER_VALUE_OFFSET
#define SDT_ID_OFFSET       (SDT_RESERVED_OFFSET + SDT_RESERVED_LENGTH)

static void
dissect_sdt_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sdt_reserved, parameter_tvb, SDT_RESERVED_OFFSET, SDT_RESERVED_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_sdt_id, parameter_tvb,       SDT_ID_OFFSET,       SDT_ID_LENGTH,       NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u)",  tvb_get_ntohs(parameter_tvb, SDT_ID_OFFSET));
}

#define SDL_RESERVED_LENGTH 2
#define SDL_ID_LENGTH       2
#define SDL_RESERVED_OFFSET PARAMETER_VALUE_OFFSET
#define SDL_ID_OFFSET       (SDL_RESERVED_OFFSET + SDL_RESERVED_LENGTH)

static void
dissect_sdl_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sdl_reserved, parameter_tvb, SDL_RESERVED_OFFSET, SDL_RESERVED_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_sdl_id,       parameter_tvb, SDL_ID_OFFSET,       SDL_ID_LENGTH,       NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohs(parameter_tvb, SDL_ID_OFFSET));
}

static void
dissect_registration_result_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16  parameters_length;

  parameters_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

#define SUCCESSFULL_REGISTRATION_STATUS               0
#define UNKNOWN_REGISTRATION_STATUS                   1
#define INVALID_SDLI_REGISTRATION_STATUS              2
#define INVALID_SDTI_REGISTRATION_STATUS              3
#define INVALID_LINK_KEY_REGISTRATION_STATUS          4
#define PERMISSION_DENIED_REGISTRATION_STATUS         5
#define OVERLAPPING_LINK_KEY_REGISTRATION_STATUS      6
#define LINK_KEY_NOT_PROVISIONED_REGISTRATION_STATUS  7
#define INSUFFICIENT_RESOURCES_REGISTRATION_STATUS    8

static const value_string registration_status_values[] = {
  { SUCCESSFULL_REGISTRATION_STATUS,              "Successfully registered" },
  { UNKNOWN_REGISTRATION_STATUS,                  "Error - Unknown" },
  { INVALID_SDLI_REGISTRATION_STATUS,             "Error - Invalid SDLI" },
  { INVALID_SDTI_REGISTRATION_STATUS,             "Error - Invalid SDTI" },
  { INVALID_LINK_KEY_REGISTRATION_STATUS,         "Error - Invalid link key" },
  { PERMISSION_DENIED_REGISTRATION_STATUS,        "Error - Permission denied" },
  { OVERLAPPING_LINK_KEY_REGISTRATION_STATUS,     "Error - Overlapping (Non-unique) link key" },
  { LINK_KEY_NOT_PROVISIONED_REGISTRATION_STATUS, "Error - Link key not provisioned" },
  { INSUFFICIENT_RESOURCES_REGISTRATION_STATUS,   "Error - Insufficient resources" },
  { 0,                  NULL } };

#define REGISTRATION_STATUS_LENGTH 4
#define REGISTRATION_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_registration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_registration_status, parameter_tvb, REGISTRATION_STATUS_OFFSET, REGISTRATION_STATUS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)",  val_to_str(tvb_get_ntohl(parameter_tvb, REGISTRATION_STATUS_OFFSET), registration_status_values, "unknown"));
}

static void
dissect_deregistration_result_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;
  guint16  parameters_length;

  parameters_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  parameters_tvb    = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameters_length, parameters_length);
  dissect_parameters(parameters_tvb, pinfo, tree, parameter_tree);
}

#define SUCCESSFULL_DEREGISTRATION_STATUS                  0
#define UNKNOWN_DEREGISTRATION_STATUS                      1
#define INVALID_INTERFACE_IDENTIFIER_DEREGISTRATION_STATUS 2
#define PERMISSION_DENIED_DEREGISTRATION_STATUS            3
#define NOT_REGISTRED_DEREGISTRATION_STATUS                4

static const value_string deregistration_status_values[] = {
  { SUCCESSFULL_DEREGISTRATION_STATUS,                  "Successfully deregistered" },
  { UNKNOWN_DEREGISTRATION_STATUS,                      "Error - Unknown" },
  { INVALID_INTERFACE_IDENTIFIER_DEREGISTRATION_STATUS, "Error - Invalid interface identifier" },
  { PERMISSION_DENIED_DEREGISTRATION_STATUS,            "Error - Permission denied" },
  { NOT_REGISTRED_DEREGISTRATION_STATUS,                "Error - Not registered" },
  { 0,                                                  NULL } };

#define DEREGISTRATION_STATUS_LENGTH 4
#define DEREGISTRATION_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_deregistration_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_deregistration_status, parameter_tvb, DEREGISTRATION_STATUS_OFFSET, DEREGISTRATION_STATUS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)",  val_to_str(tvb_get_ntohl(parameter_tvb, DEREGISTRATION_STATUS_OFFSET), deregistration_status_values, "unknown"));
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 parameter_value_length;

  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " with tag %u and %u byte%s value",
                         tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET), parameter_value_length, plurality(parameter_value_length, "", "s"));
}

/* Common parameter tags */
#define INTERFACE_IDENTIFIER_INT_PARAMETER_TAG     0x0001
#define INTERFACE_IDENTIFIER_TEXT_PARAMETER_TAG    0x0003
#define INFO_STRING_PARAMETER_TAG                  0x0004
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG       0x0007
#define INTERFACE_IDENTIFIER_RANGE_PARAMETER_TAG   0x0008
#define HEARTBEAT_DATA_PARAMETER_TAG               0x0009
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG            0x000b
#define ERROR_CODE_PARAMETER_TAG                   0x000c
#define STATUS_PARAMETER_TAG                       0x000d
#define ASP_IDENTIFIER_PARAMETER_TAG               0x0011
#define CORRELATION_IDENTIFIER_PARAMETER_TAG       0x0013

/* M2PA specific parameter tags */
#define PROTOCOL_DATA_1_PARAMETER_TAG              0x0300
#define PROTOCOL_DATA_2_PARAMETER_TAG              0x0301
#define STATE_REQUEST_PARAMETER_TAG                0x0302
#define STATE_EVENT_PARAMETER_TAG                  0x0303
#define CONGESTION_STATUS_PARAMETER_TAG            0x0304
#define DISCARD_STATUS_PARAMETER_TAG               0x0305
#define ACTION_PARAMETER_TAG                       0x0306
#define SEQUENCE_NUMBER_PARAMETER_TAG              0x0307
#define RETRIEVAL_RESULT_PARAMETER_TAG             0x0308
#define LINK_KEY_PARAMETER_TAG                     0x0309
#define LOCAL_LK_IDENTIFIER_PARAMETER_TAG          0x030a
#define SDT_IDENTIFIER_PARAMETER_TAG               0x030b
#define SDL_IDENTIFIER_PARAMETER_TAG               0x030c
#define REG_RESULT_PARAMETER_TAG                   0x030d
#define REG_STATUS_PARAMETER_TAG                   0x030e
#define DEREG_RESULT_PARAMETER_TAG                 0x030f
#define DEREG_STATUS_PARAMETER_TAG                 0x0310

static const value_string parameter_tag_values[] = {
  { INTERFACE_IDENTIFIER_INT_PARAMETER_TAG,        "Interface identifier (integer)" },
  { INTERFACE_IDENTIFIER_TEXT_PARAMETER_TAG,       "Interface identifier (text)" },
  { INFO_STRING_PARAMETER_TAG,                     "Info string" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,          "Diagnostic information" },
  { INTERFACE_IDENTIFIER_RANGE_PARAMETER_TAG,      "Interface identifier (integer range)" },
  { HEARTBEAT_DATA_PARAMETER_TAG,                  "Heartbeat data" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,               "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                      "Error code" },
  { STATUS_PARAMETER_TAG,                          "Status type / information" },
  { ASP_IDENTIFIER_PARAMETER_TAG,                  "ASP identifier" },
  { CORRELATION_IDENTIFIER_PARAMETER_TAG,          "Correlation identifier" },
  { PROTOCOL_DATA_1_PARAMETER_TAG,                 "Protocol data 1" },
  { PROTOCOL_DATA_2_PARAMETER_TAG,                 "Protocol data 2" },
  { STATE_REQUEST_PARAMETER_TAG,                   "State request" },
  { STATE_EVENT_PARAMETER_TAG,                     "State event" },
  { CONGESTION_STATUS_PARAMETER_TAG,               "Congestion state" },
  { DISCARD_STATUS_PARAMETER_TAG,                  "Discard state" },
  { ACTION_PARAMETER_TAG,                          "Action" },
  { SEQUENCE_NUMBER_PARAMETER_TAG,                 "Sequence number" },
  { RETRIEVAL_RESULT_PARAMETER_TAG,                "Retrieval result" },
  { LINK_KEY_PARAMETER_TAG,                        "Link key" },
  { LOCAL_LK_IDENTIFIER_PARAMETER_TAG,             "Local LK identifier" },
  { SDT_IDENTIFIER_PARAMETER_TAG,                  "SDT identifier" },
  { SDL_IDENTIFIER_PARAMETER_TAG,                  "SDL identifer" },
  { REG_RESULT_PARAMETER_TAG,                      "Registration result" },
  { REG_STATUS_PARAMETER_TAG,                      "Registration status" },
  { DEREG_RESULT_PARAMETER_TAG,                    "Deregistration result" },
  { DEREG_STATUS_PARAMETER_TAG,                    "Deregistration status" },
  { 0,                           NULL } };

/*
 * Default preference for 'Protocol Data 1 Parameter Tag' is RFC3331 value
 * defined above (PROTOCOL_DATA_1_PARAMETER_TAG)
 *
 * The other option is the old Draft 7 value defined below.
 */
#define	PROTOCOL_DATA_1_DRAFT_7				0x000e
static guint protocol_data_1_global = PROTOCOL_DATA_1_PARAMETER_TAG;

static void
dissect_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m2ua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  /* calculate padding and total length */
  padding_length = tvb_length(parameter_tvb) - length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(m2ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb),
                                         val_to_str(tag, parameter_tag_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_m2ua_parameter);

  if ((protocol_data_1_global == PROTOCOL_DATA_1_DRAFT_7) &&
      (tag == PROTOCOL_DATA_1_DRAFT_7))
  {
     proto_tree_add_uint_hidden(parameter_tree, hf_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, tag);

     /* add tag and length to the m2ua tree */
     proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH,
		      "Parameter Tag: Protocol data 1 (0x000e)");

     proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, NETWORK_BYTE_ORDER);
     tag = PROTOCOL_DATA_1_PARAMETER_TAG;
  }
  else
  {
      /* add tag and length to the m2ua tree */
      proto_tree_add_item(parameter_tree, hf_parameter_tag,    parameter_tvb, PARAMETER_TAG_OFFSET,    PARAMETER_TAG_LENGTH,    NETWORK_BYTE_ORDER);
      proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, NETWORK_BYTE_ORDER);
  }

  switch(tag) {
  case INTERFACE_IDENTIFIER_INT_PARAMETER_TAG:
    dissect_interface_identifier_int_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INTERFACE_IDENTIFIER_TEXT_PARAMETER_TAG:
    dissect_interface_identifier_text_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INFO_STRING_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INTERFACE_IDENTIFIER_RANGE_PARAMETER_TAG:
    dissect_interface_identifier_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ERROR_CODE_PARAMETER_TAG:
    dissect_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATUS_PARAMETER_TAG:
    dissect_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CORRELATION_IDENTIFIER_PARAMETER_TAG:
    dissect_correlation_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_DATA_1_PARAMETER_TAG:
    if (protocol_data_1_global == PROTOCOL_DATA_1_DRAFT_7)
    {
       tag = PROTOCOL_DATA_1_DRAFT_7;
    }
    dissect_protocol_data_1_parameter(parameter_tvb, pinfo, tree, parameter_item);
    break;
  case PROTOCOL_DATA_2_PARAMETER_TAG:
    dissect_protocol_data_2_parameter(parameter_tvb, pinfo, tree, parameter_tree, parameter_item);
    break;
  case STATE_REQUEST_PARAMETER_TAG:
    dissect_state_request_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATE_EVENT_PARAMETER_TAG:
    dissect_state_event_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CONGESTION_STATUS_PARAMETER_TAG:
    dissect_congestion_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DISCARD_STATUS_PARAMETER_TAG:
    dissect_discard_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ACTION_PARAMETER_TAG:
    dissect_action_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_sequence_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case RETRIEVAL_RESULT_PARAMETER_TAG:
    dissect_retrieval_result_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case LINK_KEY_PARAMETER_TAG:
    dissect_link_key_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case LOCAL_LK_IDENTIFIER_PARAMETER_TAG:
    dissect_local_lk_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SDT_IDENTIFIER_PARAMETER_TAG:
    dissect_sdt_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SDL_IDENTIFIER_PARAMETER_TAG:
    dissect_sdl_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case REG_RESULT_PARAMETER_TAG:
    dissect_registration_result_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case REG_STATUS_PARAMETER_TAG:
    dissect_registration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DEREG_RESULT_PARAMETER_TAG:
    dissect_deregistration_result_parameter(parameter_tvb, pinfo, tree, parameter_tree);
    break;
  case DEREG_STATUS_PARAMETER_TAG:
    dissect_deregistration_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, NETWORK_BYTE_ORDER);
}


static void
dissect_parameters(tvbuff_t *parameters_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m2ua_tree)
{
  gint offset, length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while((remaining_length = tvb_reported_length_remaining(parameters_tvb, offset))) {
    length       = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    total_length = ADD_PADDING(length);
    if (remaining_length >= length)
      total_length = MIN(total_length, remaining_length);
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb    = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    dissect_parameter(parameter_tvb, pinfo, tree, m2ua_tree);
    /* get rid of the handled parameter */
    offset += total_length;
  }
}


static void
dissect_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *m2ua_tree)
{
  tvbuff_t *common_header_tvb, *parameters_tvb;

  common_header_tvb = tvb_new_subset(message_tvb, 0, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  parameters_tvb    = tvb_new_subset(message_tvb, COMMON_HEADER_LENGTH, -1, -1);
  dissect_common_header(common_header_tvb, pinfo, m2ua_tree);
  dissect_parameters(parameters_tvb, pinfo, tree, m2ua_tree);
}

static void
dissect_m2ua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m2ua_item;
  proto_tree *m2ua_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2UA");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m2ua protocol tree */
    m2ua_item = proto_tree_add_item(tree, proto_m2ua, message_tvb, 0, -1, FALSE);
    m2ua_tree = proto_item_add_subtree(m2ua_item, ett_m2ua);
  } else {
    m2ua_tree = NULL;
  };
  /* dissect the message */
  dissect_message(message_tvb, pinfo, tree, m2ua_tree);
}

/* Register the protocol with Ethereal */
void
proto_register_m2ua(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_version,                { "Version",                        "m2ua.version",                    FT_UINT8,  BASE_DEC,  VALS(protocol_version_values),      0x0, "", HFILL } },
    { &hf_reserved,               { "Reserved",                       "m2ua.reserved",                   FT_UINT8,  BASE_HEX,  NULL,                               0x0, "", HFILL } },
    { &hf_message_class,          { "Message class",                  "m2ua.message_class",              FT_UINT8,  BASE_DEC,  VALS(message_class_values),         0x0, "", HFILL } },
    { &hf_message_type,           { "Message Type",                   "m2ua.message_type",               FT_UINT8,  BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_message_length,         { "Message length",                 "m2ua.message_length",             FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_parameter_tag,          { "Parameter Tag",                  "m2ua.parameter_tag",              FT_UINT16, BASE_HEX,  VALS(parameter_tag_values),         0x0, "", HFILL } },
    { &hf_parameter_length,       { "Parameter length",               "m2ua.parameter_length",           FT_UINT16, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_parameter_value,        { "Parameter value",                "m2ua.parameter_value",            FT_BYTES,  BASE_NONE, NULL,                               0x0, "", HFILL } },
    { &hf_parameter_padding,      { "Padding",                        "m2ua.parameter_padding",          FT_BYTES,  BASE_NONE, NULL,                               0x0, "", HFILL } },
    { &hf_interface_id_int,       { "Interface Identifier (integer)", "m2ua.interface_identifier_int",   FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_interface_id_text,      { "Interface identifier (text)",    "m2ua.interface_identifier_text",  FT_STRING, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_info_string,            { "Info string",                    "m2ua.info_string",                FT_STRING, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_diagnostic_information, { "Diagnostic information",         "m2ua.diagnostic_information",     FT_BYTES,  BASE_NONE, NULL,                               0x0, "", HFILL } },
    { &hf_interface_id_start,     { "Interface Identifier (start)",   "m2ua.interface_identifier_start", FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_interface_id_stop,      { "Interface Identifier (stop)",    "m2ua.interface_identifier_stop",  FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_heartbeat_data,         { "Heartbeat data",                 "m2ua.heartbeat_data",             FT_BYTES,  BASE_NONE, NULL,                               0x0, "", HFILL } },
    { &hf_traffic_mode_type,      { "Traffic mode Type",              "m2ua.traffic_mode_type",          FT_UINT32, BASE_DEC,  VALS(traffic_mode_type_values),     0x0, "", HFILL } },
    { &hf_error_code,             { "Error code",                     "m2ua.error_code",                 FT_UINT32, BASE_DEC,  VALS(error_code_values),            0x0, "", HFILL } },
    { &hf_status_type,            { "Status type",                    "m2ua.status_type",                FT_UINT16, BASE_DEC,  VALS(status_type_values),           0x0, "", HFILL } },
    { &hf_status_ident,           { "Status info",                    "m2ua.status_info",                FT_UINT16, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_asp_id,                 { "ASP identifier",                 "m2ua.asp_identifier",             FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_correlation_id,         { "Correlation identifier",         "m2ua.correlation_identifier",     FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_data_2_li,              { "Length indicator",               "m2ua.data_2_li",                  FT_UINT8,  BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_state,                  { "State",                          "m2ua.state",                      FT_UINT32, BASE_DEC,  VALS(state_values),                 0x0, "", HFILL } },
    { &hf_event,                  { "Event",                          "m2ua.event",                      FT_UINT32, BASE_DEC,  VALS(event_values),                 0x0, "", HFILL } },
    { &hf_congestion_status,      { "Congestion status",              "m2ua.congestion_status",          FT_UINT32, BASE_DEC,  VALS(level_values),                 0x0, "", HFILL } },
    { &hf_discard_status,         { "Discard status",                 "m2ua.discard_status",             FT_UINT32, BASE_DEC,  VALS(level_values),                 0x0, "", HFILL } },
    { &hf_action,                 { "Actions",                        "m2ua.action",                     FT_UINT32, BASE_DEC,  VALS(action_values),                0x0, "", HFILL } },
    { &hf_sequence_number,        { "Sequence number",                "m2ua.sequence_number",            FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_retrieval_result,       { "Retrieval result",               "m2ua.retrieval_result",           FT_UINT32, BASE_DEC,  VALS(retrieval_result_values),      0x0, "", HFILL } },
    { &hf_local_lk_id,            { "Local LK identifier",            "m2ua.local_lk_identifier",        FT_UINT32, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_sdt_reserved,           { "Reserved",                       "m2ua.sdt_reserved",               FT_UINT16, BASE_HEX,  NULL,                               0x0, "", HFILL } },
    { &hf_sdt_id,                 { "SDT identifier",                 "m2ua.sdt_identifier",             FT_UINT16, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_sdl_reserved,           { "Reserved",                       "m2ua.sdl_reserved",               FT_UINT16, BASE_HEX,  NULL,                               0x0, "", HFILL } },
    { &hf_sdl_id,                 { "SDL identifier",                 "m2ua.sdl_identifier",             FT_UINT16, BASE_DEC,  NULL,                               0x0, "", HFILL } },
    { &hf_registration_status,    { "Registration status",            "m2ua.registration_status",        FT_UINT32, BASE_DEC,  VALS(registration_status_values),   0x0, "", HFILL } },
    { &hf_deregistration_status,  { "Deregistration status",          "m2ua.deregistration_status",      FT_UINT32, BASE_DEC,  VALS(deregistration_status_values), 0x0, "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m2ua,
    &ett_m2ua_parameter,
  };

  static enum_val_t protocol_data_1_options[] = {
    { "draft-7", "0x000e (Draft 7)", PROTOCOL_DATA_1_DRAFT_7 },
    { "rfc3331", "0x0300 (RFC3331)", PROTOCOL_DATA_1_PARAMETER_TAG },
    { NULL, NULL, 0 }
  };

  module_t *m2ua_module;

  /* Register the protocol name and description */
  proto_m2ua = proto_register_protocol("MTP 2 User Adaptation Layer", "M2UA",  "m2ua");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_m2ua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  m2ua_module = prefs_register_protocol(proto_m2ua, NULL);

  prefs_register_enum_preference(m2ua_module,
    "protocol_data_1_tag",
    "Protocol Data 1 Parameter Tag",
    "The value of the parameter tag for protocol data 1",
    &protocol_data_1_global,
    protocol_data_1_options,
    FALSE);
}

void
proto_reg_handoff_m2ua(void)
{
  dissector_handle_t m2ua_handle;

  mtp3_handle = find_dissector("mtp3");
  m2ua_handle = create_dissector_handle(dissect_m2ua, proto_m2ua);
  dissector_add("sctp.ppi",  M2UA_PAYLOAD_PROTOCOL_ID, m2ua_handle);
  dissector_add("sctp.port", SCTP_PORT_M2UA, m2ua_handle);
}
