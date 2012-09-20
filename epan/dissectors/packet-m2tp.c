/* packet-m2tp.c
 * Routines for M2TP User Adaptation Layer dissection
 * M2TP - MTP2 Transparent Proxy - is a Radisys proprietary
 * protocol based on the IETF SIGTRAN standard
 *
 * Copyright 2001, Heinz Prantner <heinz.prantner[AT]radisys.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m3ua.c
 * Thanks to Michael Tuexen for his valuable improvements
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

#include <epan/packet.h>
#include <epan/sctpppids.h>

#define SCTP_PORT_M2TP        9908  /* unassigned port number (not assigned by IANA) */

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

#define PARAMETER_TAG_OFFSET      0
#define PARAMETER_LENGTH_OFFSET   (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET    (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET   PARAMETER_TAG_OFFSET

#define INTERFACE_IDENTIFIER_PARAMETER_TAG     1
#define MASTER_SLAVE_INDICATOR_PARAMETER_TAG   2
#define M2TP_USER_IDENTIFIER_PARAMETER_TAG     3
#define INFO_PARAMETER_TAG                     4
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG   7
#define HEARTBEAT_DATA_PARAMETER_TAG           9
#define REASON_PARAMETER_TAG                  10
#define ERROR_CODE_PARAMETER_TAG              12
#define PROTOCOL_DATA_PARAMETER_TAG           13


static const value_string m2tp_parameter_tag_values[] = {
  { INTERFACE_IDENTIFIER_PARAMETER_TAG,         "Interface Identifier" },
  { MASTER_SLAVE_INDICATOR_PARAMETER_TAG,       "Master Slave Indicator" },
  { M2TP_USER_IDENTIFIER_PARAMETER_TAG,         "M2tp User Identifier" },
  { INFO_PARAMETER_TAG,                         "Info" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic Information" },
  { HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat Data" },
  { REASON_PARAMETER_TAG,                       "Reason" },
  { ERROR_CODE_PARAMETER_TAG,                   "Error Code" },
  { PROTOCOL_DATA_PARAMETER_TAG,                "Protocol Data" },
  { 0,                           NULL } };

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string m2tp_protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_SGSM_MESSAGE        3
#define MESSAGE_CLASS_MAUP_MESSAGE        6
#define MESSAGE_CLASS_DATA_MESSAGE        255

static const value_string m2tp_message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management Messages" },
  { MESSAGE_CLASS_SGSM_MESSAGE,   "SG State Maintenance Messages" },
  { MESSAGE_CLASS_MAUP_MESSAGE,   "MTP2 User Adaptation Messages" },
  { MESSAGE_CLASS_DATA_MESSAGE,   "User Data Messages" },
  { 0,                            NULL } };

/* management messages */
#define MESSAGE_TYPE_ERR                  0

/* sg state maintenance messages */
#define MESSAGE_TYPE_UP                   1
#define MESSAGE_TYPE_DOWN                 2
#define MESSAGE_TYPE_BEAT                 3
#define MESSAGE_TYPE_UP_ACK               4
#define MESSAGE_TYPE_DOWN_ACK             5
#define MESSAGE_TYPE_BEAT_ACK             6

/* mtp2 user message */
#define MESSAGE_TYPE_DATA                 1


static const value_string m2tp_message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_DATA_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "Payload data (DATA)" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_UP,            "ASP up (UP)" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_DOWN,          "ASP down (DOWN)" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_BEAT,          "Heartbeat (BEAT)" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_UP_ACK,        "ASP up ack (UP ACK)" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP down ack (DOWN ACK)" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_BEAT_ACK,      "Heartbeat ack (BEAT ACK)" },
  { 0,                           NULL } };

static const value_string m2tp_message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "ERR" },
  { MESSAGE_CLASS_DATA_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "DATA" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_UP,            "ASP_UP" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_DOWN,          "ASP_DOWN" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_BEAT,          "BEAT" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_UP_ACK,        "ASP_UP_ACK" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_DOWN_ACK,      "ASP_DOWN_ACK" },
  { MESSAGE_CLASS_SGSM_MESSAGE  * 256 + MESSAGE_TYPE_BEAT_ACK,      "BEAT_ACK" },
  { 0,                           NULL } };



#define HEARTBEAT_PERIOD_OFFSET PARAMETER_VALUE_OFFSET

#define INTERFACE_IDENTIFIER_LENGTH 4
#define INTERFACE_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

#define M2TP_USER_LENGTH 4
#define M2TP_USER_OFFSET PARAMETER_VALUE_OFFSET

#define PROTOCOL_DATA_OFFSET PARAMETER_VALUE_OFFSET

#define MASTER_SLAVE_LENGTH 4
#define MASTER_SLAVE_OFFSET PARAMETER_VALUE_OFFSET

#define REASON_LENGTH 4
#define REASON_OFFSET PARAMETER_VALUE_OFFSET

#define HEART_BEAT_DATA_OFFSET PARAMETER_VALUE_OFFSET

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

#define BSN_OFFSET PARAMETER_VALUE_OFFSET
#define FSN_OFFSET PARAMETER_VALUE_OFFSET+1

#define M2TP_USER_MTP2          1
#define M2TP_USER_Q921          2
#define M2TP_USER_FRAME_RELAY   3

static const value_string m2tp_user_identifier_values[] = {
    { M2TP_USER_MTP2,        "MTP2" },
    { M2TP_USER_Q921,        "Q.921" },
    { M2TP_USER_FRAME_RELAY, "Frame Relay" },
    { 0, NULL }};

#define M2TP_MODE_MASTER 1
#define M2TP_MODE_SLAVE  2

static const value_string m2tp_mode_values[] = {
    { M2TP_MODE_MASTER,      "Master" },
    { M2TP_MODE_SLAVE,       "Slave" },
    { 0, NULL}};

#define M2TP_ERROR_CODE_INVALID_VERSION                         1
#define M2TP_ERROR_CODE_INVALID_INTERFACE_IDENTIFIER            2
#define M2TP_ERROR_CODE_INVALID_ADAPTATION_LAYER_IDENTIFIER     3
#define M2TP_ERROR_CODE_INVALID_MESSAGE_TYPE                    4
#define M2TP_ERROR_CODE_INVALID_TRAFFIC_HANDLING_MODE           5
#define M2TP_ERROR_CODE_UNEXPECTED_MESSAGE                      6
#define M2TP_ERROR_CODE_PROTOCOL_ERROR                          7
#define M2TP_ERROR_CODE_INVALID_STREAM_IDENTIFIER               8
#define M2TP_ERROR_CODE_INCOMPATIBLE_MASTER_SLAVE_CONFIGURATION 9

static const value_string m2tp_error_code_values[] = {
      { M2TP_ERROR_CODE_INVALID_VERSION,                        "Invalid Version" },
      { M2TP_ERROR_CODE_INVALID_INTERFACE_IDENTIFIER,           "Invalid Interface Identifier" },
      { M2TP_ERROR_CODE_INVALID_ADAPTATION_LAYER_IDENTIFIER,    "Invalid Adaptation Layer Identifier" },
      { M2TP_ERROR_CODE_INVALID_MESSAGE_TYPE,                   "Invalid Message Type" },
      { M2TP_ERROR_CODE_INVALID_TRAFFIC_HANDLING_MODE,          "Invalid Traffic Handling Mode" },
      { M2TP_ERROR_CODE_UNEXPECTED_MESSAGE,                     "Unexpected Message" },
      { M2TP_ERROR_CODE_PROTOCOL_ERROR,                         "Protocol Error" },
      { M2TP_ERROR_CODE_INVALID_STREAM_IDENTIFIER,              "Invalid Stream Identified" },
      { M2TP_ERROR_CODE_INCOMPATIBLE_MASTER_SLAVE_CONFIGURATION,"Incompatible Master Slave Configuration" },
      { 0,                                                      NULL } };

#define MANAGEMENT_ORDER_REASON_CODE       1
#define MTP_RELEASE_REASON_CODE            2

static const value_string m2tp_reason_code_values[] = {
      { MANAGEMENT_ORDER_REASON_CODE,                      "Management Order" },
      { MTP_RELEASE_REASON_CODE,                           "MTP Release" },
      { 0,                                                 NULL } };


/* Initialize the protocol and registered fields */
static int proto_m2tp = -1;
static int hf_m2tp_version = -1;
static int hf_m2tp_reserved = -1;
static int hf_m2tp_message_class = -1;
static int hf_m2tp_message_type = -1;
static int hf_m2tp_message_length = -1;
static int hf_m2tp_parameter_tag = -1;
static int hf_m2tp_parameter_length = -1;
static int hf_m2tp_parameter_value = -1;
static int hf_m2tp_parameter_padding = -1;
static int hf_m2tp_interface_identifier = -1;
static int hf_m2tp_user = -1;
static int hf_m2tp_master_slave = -1;
static int hf_m2tp_info_string = -1;
static int hf_m2tp_heartbeat_data = -1;
static int hf_m2tp_diagnostic_info = -1;
static int hf_m2tp_error_code = -1;
static int hf_m2tp_reason = -1;

/* Initialize the subtree pointers */
static gint ett_m2tp = -1;
static gint ett_m2tp_parameter = -1;

static dissector_handle_t mtp2_handle;

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

/* Common Header */
static void
dissect_m2tp_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *m2tp_tree)
{
  guint8  version, reserved, message_class, message_type;
  guint32 message_length;

  /* Extract the common header */
  version        = tvb_get_guint8(common_header_tvb, VERSION_OFFSET);
  reserved       = tvb_get_guint8(common_header_tvb, RESERVED_OFFSET);
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);
  message_length = tvb_get_ntohl (common_header_tvb, MESSAGE_LENGTH_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(message_class * 256 + message_type, m2tp_message_class_type_acro_values, "reserved"));

  if (m2tp_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(m2tp_tree, hf_m2tp_version, common_header_tvb, VERSION_OFFSET, VERSION_LENGTH, version);
    proto_tree_add_uint(m2tp_tree, hf_m2tp_reserved, common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH, reserved);
    proto_tree_add_uint(m2tp_tree, hf_m2tp_message_class, common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH, message_class);
    proto_tree_add_uint_format(m2tp_tree, hf_m2tp_message_type,
                               common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
                               message_type, "Message type: %u (%s)",
                               message_type, val_to_str_const(message_class * 256 + message_type, m2tp_message_class_type_values, "reserved"));
    proto_tree_add_uint(m2tp_tree, hf_m2tp_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, message_length);
  };
}

/* Interface Identifier */
static void
dissect_m2tp_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 parameter_value;

  if (parameter_tree) {
    parameter_value = tvb_get_ntohl(parameter_tvb, PARAMETER_VALUE_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m2tp_interface_identifier, parameter_tvb, INTERFACE_IDENTIFIER_OFFSET, INTERFACE_IDENTIFIER_LENGTH, parameter_value);
    proto_item_set_text(parameter_item, "Interface Identifier (%u)", parameter_value);
  }
}

/* Master Slave Indicator */
static void
dissect_m2tp_master_slave_parameter (tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 parameter_value;

  if (parameter_tree) {
    parameter_value = tvb_get_ntohl(parameter_tvb, PARAMETER_VALUE_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m2tp_master_slave, parameter_tvb, MASTER_SLAVE_OFFSET, MASTER_SLAVE_LENGTH, parameter_value);
    proto_item_set_text(parameter_item, "Master Slave Indicator (%s)", val_to_str_const(parameter_value, m2tp_mode_values, "unknown"));
  }
}

/* M2tp User Identifier */
static void
dissect_m2tp_user_identifier_parameter (tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 parameter_value;

  if (parameter_tree) {
    parameter_value = tvb_get_ntohl(parameter_tvb, PARAMETER_VALUE_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m2tp_user, parameter_tvb, M2TP_USER_OFFSET, M2TP_USER_LENGTH, parameter_value);
    proto_item_set_text(parameter_item, "M2TP User Identifier (%u)", parameter_value);
  }
}

/* Info String */
static void
dissect_m2tp_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, info_string_length;
  const char *info_string;

  if (parameter_tree) {
    length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
    info_string_length = length - PARAMETER_HEADER_LENGTH;
    info_string = tvb_get_ephemeral_string(parameter_tvb, INFO_STRING_OFFSET, info_string_length);
    proto_tree_add_string(parameter_tree, hf_m2tp_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, info_string);
    proto_item_set_text(parameter_item, "Info String (%.*s)", info_string_length, info_string);
  }
}

/* Diagnostic Information */
static void
dissect_m2tp_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, diagnostic_info_length;

  if (parameter_tree) {
    length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
    diagnostic_info_length = length - PARAMETER_HEADER_LENGTH;
    proto_tree_add_item(parameter_tree, hf_m2tp_diagnostic_info, parameter_tvb, PARAMETER_VALUE_OFFSET, diagnostic_info_length, ENC_NA);
    proto_item_set_text(parameter_item, "Diagnostic information (%u byte%s)", diagnostic_info_length, plurality(diagnostic_info_length, "", "s"));
  }
}

/* Heartbeat Data */
static void
dissect_m2tp_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, heartbeat_data_length;

  if (parameter_tree) {
    length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
    heartbeat_data_length = length - PARAMETER_HEADER_LENGTH;
    proto_tree_add_item(parameter_tree, hf_m2tp_heartbeat_data, parameter_tvb, PARAMETER_VALUE_OFFSET, heartbeat_data_length, ENC_NA);
    proto_item_set_text(parameter_item, "Heartbeat data (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
  }
}

/* Reason Parameter */
static void
dissect_m2tp_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reason;

  if (parameter_tree) {
    reason = tvb_get_ntohl(parameter_tvb, REASON_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m2tp_reason, parameter_tvb, REASON_OFFSET, REASON_LENGTH, reason);
    proto_item_set_text(parameter_item, "Reason parameter (%s)", val_to_str_const(reason, m2tp_reason_code_values, "unknown"));
  }
}

/* Error Code */
static void
dissect_m2tp_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 error_code;

  if (parameter_tree) {
    error_code = tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET);
    proto_tree_add_uint(parameter_tree, hf_m2tp_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, error_code);
    proto_item_set_text(parameter_item, "Error code parameter (%s)", val_to_str_const(error_code, m2tp_error_code_values, "unknown"));
  }
}

/* Protocol Data */
static void
dissect_m2tp_protocol_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, packet_info *pinfo, proto_item *m2tp_item, proto_tree *tree)
{
  guint16 length, protocol_data_length, padding_length;
  tvbuff_t *mtp2_tvb;

  length               = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length       = nr_of_padding_bytes(length);
  protocol_data_length = length - PARAMETER_HEADER_LENGTH;

  mtp2_tvb = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, protocol_data_length, protocol_data_length);
  call_dissector(mtp2_handle, mtp2_tvb, pinfo, tree);

  if (parameter_tree) {
    proto_item_set_text(parameter_item, "Protocol data (SS7 message)");
    proto_item_set_len(parameter_item, proto_item_get_len(parameter_item) - protocol_data_length - padding_length);
    proto_item_set_len(m2tp_item,      proto_item_get_len(m2tp_item)      - protocol_data_length - padding_length);

  }
}

/* Unknown Parameter */
static void
dissect_m2tp_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 tag, length, parameter_value_length;

  if (parameter_tree) {
    tag    = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
    length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

    parameter_value_length = length - PARAMETER_HEADER_LENGTH;
    proto_tree_add_item(parameter_tree, hf_m2tp_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);

    proto_item_set_text(parameter_item, "Parameter with tag %u and %u byte%s value", tag, parameter_value_length, plurality(parameter_value_length, "", "s"));
  }
}

/* M2TP Parameter */
static void
dissect_m2tp_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *m2tp_tree, proto_item *m2tp_item, proto_tree *tree)
{
  guint16 tag, length, padding_length, total_length;
  proto_item *parameter_item = NULL;
  proto_tree *parameter_tree = NULL;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  /* calculate padding and total length */
  padding_length = nr_of_padding_bytes(length);
  total_length   = length + padding_length;

  if (tree) {
    /* create proto_tree stuff */
    parameter_item   = proto_tree_add_text(m2tp_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
    parameter_tree   = proto_item_add_subtree(parameter_item, ett_m2tp_parameter);

    /* add tag and length to the m2tp tree */
    proto_tree_add_uint(parameter_tree, hf_m2tp_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, tag);
    proto_tree_add_uint(parameter_tree, hf_m2tp_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, length);
  }

  switch(tag) {
    case INTERFACE_IDENTIFIER_PARAMETER_TAG:
      dissect_m2tp_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case MASTER_SLAVE_INDICATOR_PARAMETER_TAG:
      dissect_m2tp_master_slave_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case M2TP_USER_IDENTIFIER_PARAMETER_TAG:
      dissect_m2tp_user_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case INFO_PARAMETER_TAG:
      dissect_m2tp_info_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
      dissect_m2tp_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case HEARTBEAT_DATA_PARAMETER_TAG:
      dissect_m2tp_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case REASON_PARAMETER_TAG:
      dissect_m2tp_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case ERROR_CODE_PARAMETER_TAG:
      dissect_m2tp_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case PROTOCOL_DATA_PARAMETER_TAG:
      dissect_m2tp_protocol_data_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo, m2tp_item, tree);
      break;
    default:
      dissect_m2tp_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
  };

  if ((parameter_tree) && (padding_length > 0))
    proto_tree_add_item(parameter_tree, hf_m2tp_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

/* M2TP Message */
static void
dissect_m2tp_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2tp_item, proto_tree *m2tp_tree, proto_tree *tree)
{
  gint offset, length, padding_length, total_length;
  tvbuff_t *common_header_tvb, *parameter_tvb;

  offset = 0;

  /* extract and process the common header */
  common_header_tvb = tvb_new_subset(message_tvb, offset, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_m2tp_common_header(common_header_tvb, pinfo, m2tp_tree);
  offset += COMMON_HEADER_LENGTH;

  /* extract zero or more parameters and process them individually */
  while(tvb_reported_length_remaining(message_tvb, offset)) {
    length         = tvb_get_ntohs(message_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb    = tvb_new_subset(message_tvb, offset, total_length, total_length);
    dissect_m2tp_parameter(parameter_tvb, pinfo, m2tp_tree, m2tp_item, tree);
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

/* M2tp */
static void
dissect_m2tp(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m2tp_item;
  proto_tree *m2tp_tree;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2TP");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m2tp protocol tree */
    m2tp_item = proto_tree_add_item(tree, proto_m2tp, message_tvb, 0, -1, ENC_NA);
    m2tp_tree = proto_item_add_subtree(m2tp_item, ett_m2tp);
  } else {
    m2tp_item = NULL;
    m2tp_tree = NULL;
  };
  /* dissect the message */
  dissect_m2tp_message(message_tvb, pinfo, m2tp_item, m2tp_tree, tree);
}

/* Register the protocol with Wireshark */
void
proto_register_m2tp(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_m2tp_version,
      { "Version", "m2tp.version",
        FT_UINT8, BASE_DEC, VALS(m2tp_protocol_version_values), 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_reserved,
      { "Reserved", "m2tp.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_message_class,
      { "Message class", "m2tp.message_class",
        FT_UINT8, BASE_DEC, VALS(m2tp_message_class_values), 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_message_type,
      { "Message Type", "m2tp.message_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_message_length,
      { "Message length", "m2tp.message_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_parameter_tag,
      { "Parameter Tag", "m2tp.parameter_tag",
        FT_UINT16, BASE_DEC, VALS(m2tp_parameter_tag_values), 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_parameter_length,
      { "Parameter length", "m2tp.parameter_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_parameter_value,
      { "Parameter Value", "m2tp.parameter_value",
	      FT_BYTES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }
    },
    { &hf_m2tp_parameter_padding,
      { "Padding", "m2tp.parameter_padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }
    },
    { &hf_m2tp_interface_identifier,
      { "Interface Identifier", "m2tp.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_user,
      { "M2tp User Identifier", "m2tp.user_identifier",
        FT_UINT32, BASE_DEC, VALS(m2tp_user_identifier_values), 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_master_slave,
      { "Master Slave Indicator", "m2tp.master_slave",
        FT_UINT32, BASE_DEC, VALS(m2tp_mode_values), 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_info_string,
      { "Info string", "m2tp.info_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_diagnostic_info,
      { "Diagnostic information", "m2tp.diagnostic_info",
	       FT_BYTES, BASE_NONE, NULL, 0x0,
	       NULL, HFILL }
    },
    { &hf_m2tp_heartbeat_data,
      { "Heartbeat data", "m2tp.heartbeat_data",
	       FT_BYTES, BASE_NONE, NULL, 0x0,
	       NULL, HFILL }
    },
    { &hf_m2tp_error_code,
      { "Error code", "m2tp.error_code",
        FT_UINT32, BASE_DEC, VALS(m2tp_error_code_values), 0x0,
        NULL, HFILL}
    },
    { &hf_m2tp_reason,
      { "Reason", "m2tp.reason",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m2tp,
    &ett_m2tp_parameter,
  };

  /* Register the protocol name and description */
  proto_m2tp = proto_register_protocol("MTP 2 Transparent Proxy", "M2TP",  "m2tp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_m2tp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_m2tp(void)
{
  dissector_handle_t m2tp_handle;
  mtp2_handle   = find_dissector("mtp2");
  m2tp_handle   = create_dissector_handle(dissect_m2tp, proto_m2tp);
  dissector_add_uint("sctp.ppi",  M2TP_PAYLOAD_PROTOCOL_ID, m2tp_handle);
  dissector_add_uint("sctp.port", SCTP_PORT_M2TP, m2tp_handle);
}
