/* packet-dua.c
 * Routines for DPNSS/DASS2-User Adaptation Layer dissection
 *
 * It is hopefully (needs testing) compliant to
 *   http://www.ietf.org/internet-drafts/draft-ietf-sigtran-dua-08.txt
 *   http://www.ietf.org/internet-drafts/draft-ietf-sigtran-rfc3057bis-02.txt
 *
 * To do: - provide better handling of length parameters
 *
 * Copyright 2005, Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-iua.c
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
#include <epan/sctpppids.h>

/* Initialize the protocol and registered fields */
static int proto_dua                = -1;
static int hf_int_interface_id      = -1;
static int hf_text_interface_id     = -1;
static int hf_info_string           = -1;
static int hf_dlci_reserved         = -1;
static int hf_dlci_v_bit            = -1;
static int hf_dlci_zero_bit         = -1;
static int hf_dlci_channel          = -1;
static int hf_dlci_one_bit          = -1;
static int hf_dlci_spare            = -1;
static int hf_diag_info             = -1;
static int hf_interface_range_start = -1;
static int hf_interface_range_end   = -1;
static int hf_heartbeat_data        = -1;
static int hf_traffic_mode_type     = -1;
static int hf_error_code            = -1;
static int hf_status_type           = -1;
static int hf_status_id             = -1;
static int hf_release_reason        = -1;
static int hf_tei_status            = -1;
static int hf_asp_id                = -1;
static int hf_states                = -1;
static int hf_parameter_tag         = -1;
static int hf_parameter_length      = -1;
static int hf_parameter_value       = -1;
static int hf_parameter_padding     = -1;
static int hf_version               = -1;
static int hf_reserved              = -1;
static int hf_message_class         = -1;
static int hf_message_type          = -1;
static int hf_message_length        = -1;

/* Initialize the subtree pointers */
static gint ett_dua                 = -1;
static gint ett_dua_parameter       = -1;

static dissector_handle_t data_handle;
static dissector_handle_t dpnss_handle;

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

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
dissect_int_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_int_interface_id, parameter_tvb, INT_INTERFACE_ID_OFFSET, INT_INTERFACE_ID_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%d)", tvb_get_ntohl(parameter_tvb, INT_INTERFACE_ID_OFFSET));
}

#define TEXT_INTERFACE_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_text_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 interface_id_length;

  interface_id_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  proto_tree_add_item(parameter_tree, hf_text_interface_id, parameter_tvb, TEXT_INTERFACE_ID_OFFSET, interface_id_length, ENC_ASCII|ENC_NA);
  proto_item_append_text(parameter_item, " (%.*s)", interface_id_length,
                         tvb_get_ephemeral_string(parameter_tvb, TEXT_INTERFACE_ID_OFFSET, interface_id_length));
}

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info_string_length;

  info_string_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, ENC_ASCII|ENC_NA);
  proto_item_append_text(parameter_item, " (%.*s)", info_string_length,
                         tvb_get_ephemeral_string(parameter_tvb, INFO_STRING_OFFSET, info_string_length));
}

#define DLCI_LENGTH  2
#define SPARE_LENGTH 2

#define DLCI_OFFSET  PARAMETER_VALUE_OFFSET
#define SPARE_OFFSET (DLCI_OFFSET + DLCI_LENGTH)

#define RESERVED_BIT_MASK 0xfe00
#define V_BIT_MASK        0x0100
#define ZERO_BIT_MASK     0x0080
#define CHANNEL_BIT_MASK  0x007e
#define ONE_BIT_MASK      0x0001

static void
dissect_dlci_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_dlci_reserved, parameter_tvb, DLCI_OFFSET,  DLCI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_v_bit,    parameter_tvb, DLCI_OFFSET,  DLCI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_zero_bit, parameter_tvb, DLCI_OFFSET,  DLCI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_channel,  parameter_tvb, DLCI_OFFSET,  DLCI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_one_bit,  parameter_tvb, DLCI_OFFSET,  DLCI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_spare,    parameter_tvb, SPARE_OFFSET, SPARE_LENGTH, ENC_BIG_ENDIAN);
}

static void
dissect_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 diag_info_length;

  diag_info_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_diag_info, parameter_tvb, PARAMETER_VALUE_OFFSET, diag_info_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", diag_info_length, plurality(diag_info_length, "", "s"));
}

#define START_LENGTH 4
#define END_LENGTH   4
#define INTERVAL_LENGTH (START_LENGTH + END_LENGTH)

#define START_OFFSET 0
#define END_OFFSET   (START_OFFSET + START_LENGTH)

static void
dissect_integer_range_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 number_of_ranges, range_number;
  gint offset;

  number_of_ranges = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / INTERVAL_LENGTH;
  offset = PARAMETER_VALUE_OFFSET;
  for(range_number = 1; range_number <= number_of_ranges; range_number++) {
    proto_tree_add_item(parameter_tree, hf_interface_range_start, parameter_tvb, offset + START_OFFSET, START_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_interface_range_end,   parameter_tvb, offset + END_OFFSET,   END_LENGTH,   ENC_BIG_ENDIAN);
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
  proto_tree_add_item(parameter_tree, hf_heartbeat_data, parameter_tvb, HEARTBEAT_DATA_OFFSET, heartbeat_data_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}

#define OVER_RIDE_TRAFFIC_MODE_TYPE  1
#define LOAD_SHARE_TRAFFIC_MODE_TYPE 2

static const value_string traffic_mode_type_values[] = {
  { OVER_RIDE_TRAFFIC_MODE_TYPE,      "Over-ride" },
  { LOAD_SHARE_TRAFFIC_MODE_TYPE,     "Load-share" },
  { 0,                    NULL } };

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), traffic_mode_type_values, "unknown"));
}

#define INVALID_VERSION_ERROR                         0x01
#define INVALID_INTERFACE_IDENTIFIER_ERROR            0x02
#define UNSUPPORTED_MESSAGE_CLASS_ERROR               0x03
#define UNSUPPORTED_MESSAGE_TYPE_ERROR                0x04
#define UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR       0x05
#define UNEXPECTED_MESSAGE_ERROR                      0x06
#define PROTOCOL_ERROR                                0x07
#define UNSUPPORTED_INTERFACE_IDENTIFIER_TYPE_ERROR   0x08
#define INVALID_STREAM_IDENTIFIER_ERROR               0x09
#define REFUSED_MANAGEMENT_BLOCKING_ERROR             0x0d
#define ASP_IDENTIFIER_REQUIRED_ERROR                 0x0e
#define INVALID_ASP_IDENTIFIER_ERROR                  0x0f
#define CHANNEL_NUMBER_OUT_OF_RANGE_ERROR             0x1c
#define CHANNEL_NUMBER_NOT_CONFIGURED                 0x1d

static const value_string error_code_values[] = {
  { INVALID_VERSION_ERROR,                       "Invalid version" },
  { INVALID_INTERFACE_IDENTIFIER_ERROR,          "Invalid interface identifier" },
  { UNSUPPORTED_MESSAGE_CLASS_ERROR,             "Unsupported message class" },
  { UNSUPPORTED_MESSAGE_TYPE_ERROR,              "Unsupported message type" },
  { UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR,     "Unsupported traffic handling mode" },
  { UNEXPECTED_MESSAGE_ERROR,                    "Unexpected message" },
  { PROTOCOL_ERROR,                              "Protocol error" },
  { UNSUPPORTED_INTERFACE_IDENTIFIER_TYPE_ERROR, "Unsupported interface identifier type" },
  { INVALID_STREAM_IDENTIFIER_ERROR,             "Invalid stream identifier" },
  { REFUSED_MANAGEMENT_BLOCKING_ERROR,           "Refused - Management blocking" },
  { ASP_IDENTIFIER_REQUIRED_ERROR,               "ASP identifier required" },
  { INVALID_ASP_IDENTIFIER_ERROR,                "Invalid ASP Identifier" },
  { CHANNEL_NUMBER_OUT_OF_RANGE_ERROR,           "Channel number out of range" },
  { CHANNEL_NUMBER_NOT_CONFIGURED,               "Channel number not configured" },
  { 0,                                           NULL } };

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_error_code, parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET), error_code_values, "unknown"));
}

#define ASP_STATE_CHANGE_STATUS_TYPE  0x01
#define OTHER_STATUS_TYPE             0x02

static const value_string status_type_values[] = {
  { ASP_STATE_CHANGE_STATUS_TYPE,        "Application server state change" },
  { OTHER_STATUS_TYPE,                   "Other" },
  { 0,                                   NULL } };

#define AS_DOWN_STATUS_IDENT          0x01
#define AS_INACTIVE_STATUS_IDENT      0x02
#define AS_ACTIVE_STATUS_IDENT        0x03
#define AS_PENDING_STATUS_IDENT       0x04

#define INSUFFICIENT_ASP_RESOURCES_STATUS_IDENT 0x01
#define ALTERNATE_ASP_ACTIVE_STATUS_IDENT       0x02

static const value_string status_type_id_values[] = {
  { ASP_STATE_CHANGE_STATUS_TYPE * 256 * 256 + AS_DOWN_STATUS_IDENT,         "Application server down" },
  { ASP_STATE_CHANGE_STATUS_TYPE * 256 * 256 + AS_INACTIVE_STATUS_IDENT,     "Application server inactive" },
  { ASP_STATE_CHANGE_STATUS_TYPE * 256 * 256 + AS_ACTIVE_STATUS_IDENT,       "Application server active" },
  { ASP_STATE_CHANGE_STATUS_TYPE * 256 * 256 + AS_PENDING_STATUS_IDENT,      "Application server pending" },
  { OTHER_STATUS_TYPE * 256 * 256 + INSUFFICIENT_ASP_RESOURCES_STATUS_IDENT, "Insufficient ASP resources active in AS" },
  { OTHER_STATUS_TYPE * 256 * 256 + ALTERNATE_ASP_ACTIVE_STATUS_IDENT,       "Alternate ASP active" },
  { 0,                                           NULL } };

#define STATUS_TYPE_LENGTH  2
#define STATUS_IDENT_LENGTH 2
#define STATUS_TYPE_OFFSET  PARAMETER_VALUE_OFFSET
#define STATUS_IDENT_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

static void
dissect_status_type_identification_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_id;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_id   = tvb_get_ntohs(parameter_tvb, STATUS_IDENT_OFFSET);

  proto_tree_add_item(parameter_tree, hf_status_type, parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_uint_format(parameter_tree, hf_status_id,  parameter_tvb, STATUS_IDENT_OFFSET, STATUS_IDENT_LENGTH,
                             status_id, "Status identification: %u (%s)", status_id,
                             val_to_str(status_type * 256 * 256 + status_id, status_type_id_values, "unknown"));

  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(status_type * 256 * 256 + status_id, status_type_id_values, "unknown status information"));
}

#define PROTOCOL_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_protocol_data_parameter(tvbuff_t *parameter_tvb, proto_item *parameter_item, packet_info *pinfo, proto_tree *tree)
{
  guint16 protocol_data_length;
  tvbuff_t *protocol_data_tvb;

  protocol_data_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  protocol_data_tvb    = tvb_new_subset(parameter_tvb, PROTOCOL_DATA_OFFSET, protocol_data_length, protocol_data_length);
  if(dpnss_handle){
	  call_dissector(dpnss_handle, protocol_data_tvb, pinfo, tree);
	  return;
  }

  call_dissector(data_handle, protocol_data_tvb, pinfo, tree);

  proto_item_append_text(parameter_item, " (%u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
}

#define RELEASE_MGMT_REASON   0
#define RELEASE_PHYS_REASON   1
#define RELEASE_DM_REASON     2
#define RELEASE_OTHER_REASON  3

static const value_string release_reason_values[] = {
  { RELEASE_MGMT_REASON,  "Management layer generated release" },
  { RELEASE_PHYS_REASON,  "Physical layer alarm generated release" },
  { RELEASE_DM_REASON,    "Layer 2 should release" },
  { RELEASE_OTHER_REASON, "Other reason" },
  { 0,                    NULL } };

#define RELEASE_REASON_OFFSET PARAMETER_VALUE_OFFSET
#define RELEASE_REASON_LENGTH 4

static void
dissect_release_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_release_reason, parameter_tvb, RELEASE_REASON_OFFSET, RELEASE_REASON_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, RELEASE_REASON_OFFSET), release_reason_values, "unknown"));
}

#define TEI_STATUS_ASSIGNED       0
#define TEI_STATUS_UNASSIGNED     1

static const value_string tei_status_values[] = {
  { TEI_STATUS_ASSIGNED,   "TEI is considered assigned by Q.921" },
  { TEI_STATUS_UNASSIGNED, "TEI is considered unassigned by Q.921" },
  { 0,                    NULL } };

#define TEI_STATUS_LENGTH 4
#define TEI_STATUS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_tei_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_tei_status, parameter_tvb, TEI_STATUS_OFFSET, TEI_STATUS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)",
                      val_to_str(tvb_get_ntohl(parameter_tvb, TEI_STATUS_OFFSET), tei_status_values, "unknown"));
}

#define ASP_ID_LENGTH 4
#define ASP_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_asp_id, parameter_tvb, ASP_ID_OFFSET, ASP_ID_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%u)", tvb_get_ntohl(parameter_tvb, ASP_ID_OFFSET));
}

static void
dissect_dlc_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint16 parameter_value_length;

  /* FIXME: This can be done better */
  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_states, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 parameter_value_length;

  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);
  proto_item_append_text(parameter_item, " with tag %u and %u byte%s value",
                         tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET), parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define INT_INTERFACE_IDENTIFIER_PARAMETER_TAG           0x01
#define TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG          0x03
#define INFO_PARAMETER_TAG                               0x04
#define DLCI_PARAMETER_TAG                               0x05
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG             0x07
#define INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG 0x08
#define HEARTBEAT_DATA_PARAMETER_TAG                     0x09
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG                  0x0b
#define ERROR_CODE_PARAMETER_TAG                         0x0c
#define STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG        0x0d
#define PROTOCOL_DATA_PARAMETER_TAG                      0x0e
#define RELEASE_REASON_PARAMETER_TAG                     0x0f
#define TEI_STATUS_PARAMETER_TAG                         0x10
#define ASP_IDENTIFIER_PARAMETER_TAG                     0x11
#define DLC_STATUS_PARAMETER_TAG                         0x12

static const value_string parameter_tag_values[] = {
  { INT_INTERFACE_IDENTIFIER_PARAMETER_TAG,                "Integer interface identifier" },
  { TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG,               "Text interface identifier" },
  { INFO_PARAMETER_TAG,                                    "Info" },
  { DLCI_PARAMETER_TAG,                                    "DLCI" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,                  "Diagnostic information" },
  { INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG,      "Integer range interface identifier" },
  { HEARTBEAT_DATA_PARAMETER_TAG,                          "Heartbeat data" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,                       "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                              "Error code" },
  { STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG,             "Status type/identification" },
  { PROTOCOL_DATA_PARAMETER_TAG,                           "Protocol data" },
  { RELEASE_REASON_PARAMETER_TAG,                          "Reason" },
  { TEI_STATUS_PARAMETER_TAG,                              "TEI status" },
  { ASP_IDENTIFIER_PARAMETER_TAG,                          "ASP identifier"},
  { DLC_STATUS_PARAMETER_TAG,                              "DLC status" },
  { 0,                                                     NULL } };

static void
dissect_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *dua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(dua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s",
                                         val_to_str(tag, parameter_tag_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_dua_parameter);

  /* add tag and length to the dua tree */
  proto_tree_add_item(parameter_tree, hf_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(tag) {
  case INT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_int_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_text_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INFO_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DLCI_PARAMETER_TAG:
    dissect_dlci_parameter(parameter_tvb, parameter_tree);
    break;
  case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_integer_range_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
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
  case STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG:
    dissect_status_type_identification_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_DATA_PARAMETER_TAG:
    dissect_protocol_data_parameter(parameter_tvb, parameter_item, pinfo, tree);
    break;
  case RELEASE_REASON_PARAMETER_TAG:
    dissect_release_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TEI_STATUS_PARAMETER_TAG:
    dissect_tei_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DLC_STATUS_PARAMETER_TAG:
    dissect_dlc_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
}

static void
dissect_parameters(tvbuff_t *parameters_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *dua_tree)
{
  gint offset, length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while((remaining_length = tvb_length_remaining(parameters_tvb, offset))) {
    length       = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    total_length = ADD_PADDING(length);
    if (remaining_length >= length)
      total_length = MIN(total_length, remaining_length);
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb  = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    dissect_parameter(parameter_tvb, pinfo, tree, dua_tree);
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

#define VERSION_LENGTH         1
#define RESERVED_LENGTH        1
#define MESSAGE_CLASS_LENGTH   1
#define MESSAGE_TYPE_LENGTH    1
#define MESSAGE_LENGTH_LENGTH  4
#define COMMON_HEADER_LENGTH   (VERSION_LENGTH + RESERVED_LENGTH + MESSAGE_CLASS_LENGTH + \
                                MESSAGE_TYPE_LENGTH + MESSAGE_LENGTH_LENGTH)

#define COMMON_HEADER_OFFSET   0
#define VERSION_OFFSET         COMMON_HEADER_OFFSET
#define RESERVED_OFFSET        (VERSION_OFFSET + VERSION_LENGTH)
#define MESSAGE_CLASS_OFFSET   (RESERVED_OFFSET + RESERVED_LENGTH)
#define MESSAGE_TYPE_OFFSET    (MESSAGE_CLASS_OFFSET + MESSAGE_CLASS_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)
#define PARAMETERS_OFFSET      (COMMON_HEADER_OFFSET + COMMON_HEADER_LENGTH)

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_ASPSM_MESSAGE       3
#define MESSAGE_CLASS_ASPTM_MESSAGE       4
#define MESSAGE_CLASS_DPTM_MESSAGE       13

static const value_string message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_DPTM_MESSAGE,   "DPNSS/DASS2 boundary primitive transport messages" },
  { 0,                             NULL } };

/* message types for MGMT messages */
#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1
#define MESSAGE_TYPE_DLC_STAT_REQ         5
#define MESSAGE_TYPE_DLC_STAT_CON         6
#define MESSAGE_TYPE_DLC_STAT_IND         7

/* message types for ASPSM messages */
#define MESSAGE_TYPE_UP                   1
#define MESSAGE_TYPE_DOWN                 2
#define MESSAGE_TYPE_BEAT                 3
#define MESSAGE_TYPE_UP_ACK               4
#define MESSAGE_TYPE_DOWN_ACK             5
#define MESSAGE_TYPE_BEAT_ACK             6

/* message types for ASPTM messages */
#define MESSAGE_TYPE_ACTIVE               1
#define MESSAGE_TYPE_INACTIVE             2
#define MESSAGE_TYPE_ACTIVE_ACK           3
#define MESSAGE_TYPE_INACTIVE_ACK         4

/* message types for DPTM messages */
#define MESSAGE_TYPE_DATA_REQUEST         1
#define MESSAGE_TYPE_DATA_INDICATION      2
#define MESSAGE_TYPE_ESTABLISH_REQUEST    5
#define MESSAGE_TYPE_ESTABLISH_CONFIRM    6
#define MESSAGE_TYPE_ESTABLISH_INDICATION 7
#define MESSAGE_TYPE_RELEASE_REQUEST      8
#define MESSAGE_TYPE_RELEASE_CONFIRM      9
#define MESSAGE_TYPE_RELEASE_INDICATION  10


static const value_string message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,                  "Error" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,                 "Notify" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_DLC_STAT_REQ,         "DLC status request" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_DLC_STAT_CON,         "DLC status confirm" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_DLC_STAT_IND,         "DLC status indication" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,                   "ASP up" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,                 "ASP down" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,                 "Heartbeat" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,               "ASP up ack" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,             "ASP down ack" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,             "Heartbeat ack" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,              "ASP active" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,            "ASP inactive" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,          "ASP active ack" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK ,        "ASP inactive ack" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_REQUEST,         "Data request" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_INDICATION,      "Data indication" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_REQUEST,    "Establish request" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_CONFIRM,    "Establish confirmation" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_INDICATION, "Establish indication" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_REQUEST,      "Release request" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_CONFIRM,      "Release confirmation" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_INDICATION,   "Release indication" },
  { 0,                                                                     NULL } };

static const value_string message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,                  "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,                 "NTFY" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_DLC_STAT_REQ,         "DLC_STAT_REQ" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_DLC_STAT_CON,         "DLC_STAT_CON" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_DLC_STAT_IND,         "DLC_STAT_IND" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP,                   "ASP_UP" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN,                 "ASP_DOWN" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT,                 "BEAT" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_UP_ACK,               "ASP_UP_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_DOWN_ACK,             "ASP_DOWN_ACK" },
  { MESSAGE_CLASS_ASPSM_MESSAGE * 256 + MESSAGE_TYPE_BEAT_ACK,             "BEAT_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE ,              "ASP_ACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE ,            "ASP_INACTIVE" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_ACTIVE_ACK ,          "ASP_ACTIVE_ACK" },
  { MESSAGE_CLASS_ASPTM_MESSAGE * 256 + MESSAGE_TYPE_INACTIVE_ACK ,        "ASP_INACTIVE_ACK" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_REQUEST,         "DATA_REQ" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_INDICATION,      "DATA_IND" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_REQUEST,    "EST_REQ" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_CONFIRM,    "EST_CON" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_INDICATION, "EST_IND" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_REQUEST,      "REL_REQ" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_CONFIRM,      "REL_CON" },
  { MESSAGE_CLASS_DPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_INDICATION,   "REL_IND" },
  { 0,                                                                     NULL } };

static void
dissect_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *dua_tree)
{
  guint8 message_class, message_type;

  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_class * 256 + message_type, message_class_type_acro_values, "UNKNOWN"));

  if (dua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(dua_tree, hf_version, common_header_tvb, VERSION_OFFSET, VERSION_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(dua_tree, hf_reserved, common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(dua_tree, hf_message_class, common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(dua_tree, hf_message_type,
                               common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
                               message_type, "Message type: %u (%s)",
                               message_type, val_to_str(message_class * 256 + message_type, message_class_type_values, "reserved"));
    proto_tree_add_item(dua_tree, hf_message_length, common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  }
}

static void
dissect_dua_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *dua_tree)
{
  tvbuff_t *common_header_tvb, *parameters_tvb;

  common_header_tvb = tvb_new_subset(message_tvb, COMMON_HEADER_OFFSET, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  parameters_tvb    = tvb_new_subset_remaining(message_tvb, PARAMETERS_OFFSET);
  dissect_common_header(common_header_tvb, pinfo, dua_tree);
  dissect_parameters(parameters_tvb, pinfo, tree, dua_tree);
}

static void
dissect_dua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *dua_item;
  proto_tree *dua_tree;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DUA");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m3ua protocol tree */
    dua_item = proto_tree_add_item(tree, proto_dua, message_tvb, 0, -1, ENC_NA);
    dua_tree = proto_item_add_subtree(dua_item, ett_dua);
  } else {
    dua_tree = NULL;
  };
  /* dissect the message */
  dissect_dua_message(message_tvb, pinfo, tree, dua_tree);
}

/* Register the protocol with Wireshark */
void
proto_register_dua(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_int_interface_id,      { "Integer interface identifier", "dua.int_interface_identifier",  FT_UINT32,   BASE_HEX,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_text_interface_id,     { "Text interface identifier",    "dua.text_interface_identifier", FT_STRING,  BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_info_string,           { "Info string",                  "dua.info_string",               FT_STRING,  BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_dlci_reserved,         { "Reserved",                     "dua.dlci_reserved",             FT_UINT16,  BASE_DEC,  NULL,                           RESERVED_BIT_MASK, NULL, HFILL } },
    { &hf_dlci_v_bit,            { "V-bit",                        "dua.dlci_v_bit",                FT_BOOLEAN, 16,        NULL,                           V_BIT_MASK,        NULL, HFILL } },
    { &hf_dlci_zero_bit,         { "Zero bit",                     "dua.dlci_zero_bit",             FT_BOOLEAN, 16,        NULL,                           ZERO_BIT_MASK,     NULL, HFILL } },
    { &hf_dlci_channel,          { "Channel",                      "dua.dlci_channel",              FT_UINT16,   BASE_DEC, NULL,                           CHANNEL_BIT_MASK,  NULL, HFILL } },
    { &hf_dlci_one_bit,          { "One bit",                      "dua.dlci_one_bit",              FT_BOOLEAN, 16,        NULL,                           ONE_BIT_MASK,      NULL, HFILL } },
    { &hf_dlci_spare,            { "Spare",                        "dua.dlci_spare",                FT_UINT16,  BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_diag_info,             { "Diagnostic information",       "dua.diagnostic_information",    FT_BYTES,   BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_interface_range_start, { "Start",                        "dua.interface_range_start",     FT_UINT32,  BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_interface_range_end,   { "End",                          "dua.interface_range_end",       FT_UINT32,  BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_heartbeat_data,        { "Heartbeat data",               "dua.heartbeat_data",            FT_BYTES,   BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_traffic_mode_type,     { "Traffic mode type",            "dua.traffic_mode_type",         FT_UINT32,  BASE_HEX,  VALS(traffic_mode_type_values), 0x0,               NULL, HFILL } },
    { &hf_error_code,            { "Error code",                   "dua.error_code",                FT_UINT32,  BASE_DEC,  VALS(error_code_values),        0x0,               NULL, HFILL } },
    { &hf_status_type,           { "Status type",                  "dua.status_type",               FT_UINT16,  BASE_DEC,  VALS(status_type_values),       0x0,               NULL, HFILL } },
    { &hf_status_id,             { "Status identification",        "dua.status_identification",     FT_UINT16,  BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_release_reason,        { "Reason",                       "dua.release_reason",            FT_UINT32,  BASE_HEX,  VALS(release_reason_values),    0x0,               NULL, HFILL } },
    { &hf_tei_status,            { "TEI status",                   "dua.tei_status",                FT_UINT32,  BASE_HEX,  VALS(tei_status_values),        0x0,               NULL, HFILL } },
    { &hf_asp_id,                { "ASP identifier",               "dua.asp_identifier",            FT_UINT32,  BASE_HEX,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_states,                { "States",                       "dua.states",                    FT_BYTES,   BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_parameter_tag,         { "Parameter Tag",                "dua.parameter_tag",             FT_UINT16,  BASE_DEC,  VALS(parameter_tag_values),     0x0,               NULL, HFILL } },
    { &hf_parameter_length,      { "Parameter length",             "dua.parameter_length",          FT_UINT16,  BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_parameter_value,       { "Parameter value",              "dua.parameter_value",           FT_BYTES,   BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_parameter_padding,     { "Parameter padding",            "dua.parameter_padding",         FT_BYTES,   BASE_NONE, NULL,                           0x0,               NULL, HFILL } },
    { &hf_version,               { "Version",                      "dua.version",                   FT_UINT8,   BASE_DEC,  VALS(protocol_version_values),  0x0,               NULL, HFILL } },
    { &hf_reserved,              { "Reserved",                     "dua.reserved",                  FT_UINT8,   BASE_HEX,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_message_class,         { "Message class",                "dua.message_class",             FT_UINT8,   BASE_DEC,  VALS(message_class_values),     0x0,               NULL, HFILL } },
    { &hf_message_type,          { "Message Type",                 "dua.message_type",              FT_UINT8,   BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
    { &hf_message_length,        { "Message length",               "dua.message_length",            FT_UINT32,  BASE_DEC,  NULL,                           0x0,               NULL, HFILL } },
   };
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_dua,
    &ett_dua_parameter,
  };

  /* Register the protocol name and description */
  proto_dua = proto_register_protocol("DPNSS/DASS2-User Adaptation Layer", "DUA", "dua");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_dua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Allow other dissectors to find this one by name. */
  register_dissector("dua", dissect_dua, proto_dua);
}

void
proto_reg_handoff_dua(void)
{
  dissector_handle_t dua_handle;

  dua_handle  = find_dissector("dua");
  data_handle = find_dissector("data");
  dpnss_handle = find_dissector("dpnss");
  dissector_add_uint("sctp.ppi", DUA_PAYLOAD_PROTOCOL_ID, dua_handle);
}
