/* packet-iua.c
 * Routines for ISDN Q.921-User Adaptation Layer dissection
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-iua-10.txt
 * To do: - clean up the code
 *        - provide better handling of length parameters
 *        - think about making use of the existing Q.931 dissector
 *
 * Copyright 2000, Michael Tüxen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-iua.c,v 1.6 2001/04/23 18:05:19 guy Exp $
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

#include "packet.h"

#define SCTP_PORT_IUA 9900
#define IUA_PAYLOAD_PROTO_ID   1

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

static const value_string iua_protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_TFER_MESSAGE        1
#define MESSAGE_CLASS_SSNM_MESSAGE        2
#define MESSAGE_CLASS_ASPSM_MESSAGE       3
#define MESSAGE_CLASS_ASPTM_MESSAGE       4
#define MESSAGE_CLASS_QPTM_MESSAGE        5
#define MESSAGE_CLASS_MAUP_MESSAGE        6
#define MESSAGE_CLASS_CL_SUA_MESSAGE      7
#define MESSAGE_CLASS_CO_SUA_MESSAGE      8

static const value_string iua_message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_TFER_MESSAGE,   "Transfer messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_QPTM_MESSAGE,   "Q.921/Q.931 boundary primitive transport messages" },
  { MESSAGE_CLASS_MAUP_MESSAGE,   "MTP2 user adaptation messages" },
  { MESSAGE_CLASS_CL_SUA_MESSAGE, "Connectionless messages (SUA)" },
  { MESSAGE_CLASS_CO_SUA_MESSAGE, "Connection-oriented messages (SUA)" },
  { 0,                             NULL } };

/* message types for MGMT messages */
#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1
#define MESSAGE_TYPE_TEI_STATUS_REQ       2
#define MESSAGE_TYPE_TEI_STATUS_CON       3
#define MESSAGE_TYPE_TEI_STATUS_IND       4

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

/* message types for QPTM messages */
#define MESSAGE_TYPE_DATA_REQUEST         1
#define MESSAGE_TYPE_DATA_INDICATION      2
#define MESSAGE_TYPE_UNIT_DATA_REQUEST    3
#define MESSAGE_TYPE_UNIT_DATA_INDICATION 4
#define MESSAGE_TYPE_ESTABLISH_REQUEST    5
#define MESSAGE_TYPE_ESTABLISH_CONFIRM    6
#define MESSAGE_TYPE_ESTABLISH_INDICATION 7
#define MESSAGE_TYPE_RELEASE_REQUEST      8
#define MESSAGE_TYPE_RELEASE_CONFIRM      9
#define MESSAGE_TYPE_RELEASE_INDICATION  10


static const value_string iua_message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,                  "Error" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,                 "Notify" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_TEI_STATUS_REQ,       "TEI status request" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_TEI_STATUS_CON,       "TEI status confirmation" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_TEI_STATUS_IND,       "TEI status indication" },
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
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_REQUEST,         "Data request" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_INDICATION,      "Data indication" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_UNIT_DATA_REQUEST,    "Unit data request" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_UNIT_DATA_INDICATION, "Unit data indication" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_REQUEST,    "Establish request" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_CONFIRM,    "Establish confirmation" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_INDICATION, "Establish indication" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_REQUEST,      "Release request" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_CONFIRM,      "Release confirmation" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_INDICATION,   "Release indication" },
  { 0,                                                                     NULL } };

static const value_string iua_message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,                  "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,                 "NTFY" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_TEI_STATUS_REQ,       "TEI_STAT_REQ" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_TEI_STATUS_CON,       "TEI_STAT_CON" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_TEI_STATUS_IND,       "TEI_STAT_IND" },
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
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_REQUEST,         "DATA_REQ" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_DATA_INDICATION,      "DATA_IND" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_UNIT_DATA_REQUEST,    "U_DATA_REQ" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_UNIT_DATA_INDICATION, "U_DATA_IND" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_REQUEST,    "EST_REQ" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_CONFIRM,    "EST_CON" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_ESTABLISH_INDICATION, "EST_IND" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_REQUEST,      "REL_REQ" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_CONFIRM,      "REL_CON" },
  { MESSAGE_CLASS_QPTM_MESSAGE  * 256 + MESSAGE_TYPE_RELEASE_INDICATION,   "REL_IND" },
  { 0,                                                                     NULL } };

#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_TAG_OFFSET      0
#define PARAMETER_LENGTH_OFFSET   (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET    (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET   PARAMETER_TAG_OFFSET

#define INT_INTERFACE_IDENTIFIER_PARAMETER_TAG           0x01
#define TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG          0x03
#define INFO_PARAMETER_TAG                               0x04
#define DLCI_PARAMETER_TAG                               0x05
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG             0x07
#define INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG 0x08
#define HEARTBEAT_DATA_PARAMETER_TAG                     0x09
#define ASP_REASON_PARAMETER_TAG                         0x0a
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG                  0x0b
#define ERROR_CODE_PARAMETER_TAG                         0x0c
#define STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG        0x0d
#define PROTOCOL_DATA_PARAMETER_TAG                      0x0e
#define RELEASE_REASON_PARAMETER_TAG                     0x0f
#define TEI_STATUS_PARAMETER_TAG                         0x10

static const value_string iua_parameter_tag_values[] = {
  { INT_INTERFACE_IDENTIFIER_PARAMETER_TAG,                "Integer interface identifier" },
  { TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG,               "Text interface identifier" },
  { INFO_PARAMETER_TAG,                                    "Info" },
  { DLCI_PARAMETER_TAG,                                    "DLCI" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,                  "Diagnostic information" },
  { INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG,      "Integer range interface identifier" },
  { HEARTBEAT_DATA_PARAMETER_TAG,                          "Hearbeat data" },
  { ASP_REASON_PARAMETER_TAG,                              "Reason" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,                       "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                              "Error code" },
  { STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG,             "Status type/identification" },
  { PROTOCOL_DATA_PARAMETER_TAG,                           "Protocol data" },
  { RELEASE_REASON_PARAMETER_TAG,                          "Reason" },
  { TEI_STATUS_PARAMETER_TAG,                              "TEI status" },
  { 0,                           NULL } };


#define INT_INTERFACE_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define INT_INTERFACE_IDENTIFIER_LENGTH 4

#define TEXT_INTERFACE_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET
#define TEXT_INTERFACE_IDENTIFIER_LENGTH 4

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

#define START_LENGTH 4
#define END_LENGTH   4
#define START_OFFSET 0
#define END_OFFSET   (START_OFFSET + START_LENGTH)

#define DLCI_LENGTH 2
#define DLCI_OFFSET PARAMETER_VALUE_OFFSET

#define ZERO_BIT_MASK 0x80
#define SPARE_BIT_MASK  0x40
#define SAPI_MASK     0x3f
#define ONE_BIT_MASK   0x80
#define TEI_MASK      0x7f

#define ASP_MGMT_REASON   1

static const value_string iua_asp_reason_values[] = {
  { ASP_MGMT_REASON,      "Management inhibit" },
  { 0,                    NULL } };

#define ASP_REASON_LENGTH 4
#define ASP_REASON_OFFSET PARAMETER_VALUE_OFFSET

#define OVER_RIDE_TRAFFIC_MODE_TYPE  1
#define LOAD_SHARE_TRAFFIC_MODE_TYPE 2

static const value_string iua_traffic_mode_type_values[] = {
  { OVER_RIDE_TRAFFIC_MODE_TYPE,      "Over-ride" },
  { LOAD_SHARE_TRAFFIC_MODE_TYPE,     "Load-share" },
  { 0,                    NULL } };

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

#define INVALID_VERSION_ERROR                         0x01
#define INVALID_INTERFACE_IDENTIFIER_ERROR            0x02
#define UNSUPPORTED_MESSAGE_CLASS_ERROR               0x03
#define UNSUPPORTED_MESSAGE_TYPE_ERROR                0x04
#define UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR       0x05
#define UNEXPECTED_MESSAGE_ERROR                      0x06
#define PROTOCOL_ERROR                                0x07
#define UNSUPPORTED_INTERFACE_IDENTIFIER_TYPE_ERROR   0x08
#define INVALID_STREAM_IDENTIFIER_ERROR               0x09
#define UNASSIGNED_TEI_ERROR                          0x0a
#define UNRECOGNIZED_SAPI_ERROR                       0x0b
#define INVALID_TEI_SAPI_COMBINATION                  0x0c

static const value_string iua_error_code_values[] = {
  { INVALID_VERSION_ERROR,                       "Invalid version" },
  { INVALID_INTERFACE_IDENTIFIER_ERROR,          "Invalid interface identifier" },
  { UNSUPPORTED_MESSAGE_CLASS_ERROR,             "Unsuported message class" },
  { UNSUPPORTED_MESSAGE_TYPE_ERROR,              "Unsupported message type" },
  { UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR,     "Unsupported traffic handling mode" },
  { UNEXPECTED_MESSAGE_ERROR,                    "Unexpected message" },
  { PROTOCOL_ERROR,                              "Protocol error" },
  { UNSUPPORTED_INTERFACE_IDENTIFIER_TYPE_ERROR, "Unsupported interface identifier type" },
  { INVALID_STREAM_IDENTIFIER_ERROR,             "Invalid stream identifier" },
  { UNASSIGNED_TEI_ERROR,                        "Unassigned TEI" },
  { UNRECOGNIZED_SAPI_ERROR,                     "Unrecognized SAPI" },
  { INVALID_TEI_SAPI_COMBINATION,                "Invalid TEI/SAPI combination" },
  { 0,                                           NULL } };

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

#define ASP_STATE_CHANGE_STATUS_TYPE  0x01
#define OTHER_STATUS_TYPE             0x02

static const value_string iua_status_type_values[] = {
  { ASP_STATE_CHANGE_STATUS_TYPE,        "Application server state change" },
  { OTHER_STATUS_TYPE,                   "Other" },
  { 0,                                   NULL } };

#define AS_DOWN_STATUS_IDENT          0x01
#define AS_INACTIVE_STATUS_IDENT      0x02
#define AS_ACTIVE_STATUS_IDENT        0x03
#define AS_PENDING_STATUS_IDENT       0x04

#define INSUFFICIENT_ASP_RESOURCES_STATUS_IDENT 0x01
#define ALTERNATE_ASP_ACTIVE_STATUS_IDENT       0x02

static const value_string iua_status_type_ident_values[] = {
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

#define PROTOCOL_DATA_OFFSET PARAMETER_VALUE_OFFSET

#define RELEASE_MGMT_REASON   0
#define RELEASE_PHYS_REASON   1
#define RELEASE_DM_REASON     2
#define RELEASE_OTHER_REASON  4

static const value_string iua_release_reason_values[] = {
  { RELEASE_MGMT_REASON,  "Management layer generated release" },
  { RELEASE_PHYS_REASON,  "Physical layer alarm generated release" },
  { RELEASE_DM_REASON,    "Layer 2 should release" },
  { RELEASE_OTHER_REASON, "Other reason" },
  { 0,                    NULL } };

#define RELEASE_REASON_OFFSET PARAMETER_VALUE_OFFSET
#define RELEASE_REASON_LENGTH 4

#define TEI_STATUS_ASSIGNED       0
#define TEI_STATUS_UNASSIGNED     1

static const value_string iua_tei_status_values[] = {
  { TEI_STATUS_ASSIGNED,   "TEI is considered assigned by Q.921" },
  { TEI_STATUS_UNASSIGNED, "TEI is considered unassigned by Q.921" },
  { 0,                    NULL } };

#define TEI_STATUS_LENGTH 4
#define TEI_STATUS_OFFSET PARAMETER_VALUE_OFFSET

/* Initialize the protocol and registered fields */
static int proto_iua = -1;
static int hf_iua_version = -1;
static int hf_iua_reserved = -1;
static int hf_iua_message_class = -1;
static int hf_iua_message_type = -1;
static int hf_iua_message_length = -1;
static int hf_iua_parameter_tag = -1;
static int hf_iua_parameter_length = -1;
static int hf_iua_int_interface_identifier = -1;
static int hf_iua_text_interface_identifier = -1;
static int hf_iua_info_string = -1;
static int hf_iua_interface_range_start = -1;
static int hf_iua_interface_range_end = -1;
static int hf_iua_zero_bit = -1;
static int hf_iua_spare_bit = -1;
static int hf_iua_sapi = -1;
static int hf_iua_one_bit = -1;
static int hf_iua_tei = -1;
static int hf_iua_status_type = -1;
static int hf_iua_status_ident = -1;
static int hf_iua_release_reason = -1;
static int hf_iua_traffic_mode_type = -1;
static int hf_iua_error_code = -1;
static int hf_iua_asp_reason = -1;
static int hf_iua_tei_status = -1;

/* Initialize the subtree pointers */
static gint ett_iua = -1;
static gint ett_iua_parameter = -1;
static gint ett_iua_dlci = -1;
static gint ett_iua_range = -1;

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
dissect_iua_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *iua_tree)
{
  guint8  version, reserved, message_class, message_type;
  guint32 message_length;

  /* Extract the common header */
  version        = tvb_get_guint8(common_header_tvb, VERSION_OFFSET);
  reserved       = tvb_get_guint8(common_header_tvb, RESERVED_OFFSET);
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);
  message_length = tvb_get_ntohl (common_header_tvb, MESSAGE_LENGTH_OFFSET);

  if (check_col(pinfo->fd, COL_INFO)) {
    col_append_str(pinfo->fd, COL_INFO, val_to_str(message_class * 256 + message_type, iua_message_class_type_acro_values, "UNKNOWN"));
    col_append_str(pinfo->fd, COL_INFO, " ");
  };

  if (iua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint_format(iua_tree, hf_iua_version, 
			       common_header_tvb, VERSION_OFFSET, VERSION_LENGTH,
			       version, "Version: %u (%s)",
			       version, val_to_str(version, iua_protocol_version_values, "unknown"));
    proto_tree_add_uint(iua_tree, hf_iua_reserved,
			common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH,
			reserved);
    proto_tree_add_uint_format(iua_tree, hf_iua_message_class, 
			       common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH,
			       message_class, "Message class: %u (%s)",
			       message_class, val_to_str(message_class, iua_message_class_values, "reserved"));
    proto_tree_add_uint_format(iua_tree, hf_iua_message_type, 
			       common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
			       message_type, "Message type: %u (%s)",
			       message_type, val_to_str(message_class * 256 + message_type, iua_message_class_type_values, "reserved"));
    proto_tree_add_uint(iua_tree, hf_iua_message_length,
			common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH,
			message_length);
  }
}

static void
dissect_iua_int_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 interface_identifier;

  interface_identifier = tvb_get_ntohl(parameter_tvb, INT_INTERFACE_IDENTIFIER_OFFSET);
  
  proto_tree_add_uint(parameter_tree, hf_iua_int_interface_identifier, 
		      parameter_tvb, INT_INTERFACE_IDENTIFIER_OFFSET, INT_INTERFACE_IDENTIFIER_LENGTH,
		      interface_identifier);
 
  proto_item_set_text(parameter_item, "Integer interface identifier (%u)", interface_identifier);
}

static void
dissect_iua_text_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, interface_identifier_length;
  char *interface_identifier;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  interface_identifier_length = length - PARAMETER_HEADER_LENGTH;
  interface_identifier = (char *)tvb_get_ptr(parameter_tvb, TEXT_INTERFACE_IDENTIFIER_OFFSET, interface_identifier_length);

  proto_tree_add_string(parameter_tree, hf_iua_text_interface_identifier,
			parameter_tvb, TEXT_INTERFACE_IDENTIFIER_OFFSET, interface_identifier_length ,
			interface_identifier);

  proto_item_set_text(parameter_item, "Text interface identifier (%s)", interface_identifier);
}

static void
dissect_iua_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, info_string_length;
  char *info_string;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  info_string_length = length - PARAMETER_HEADER_LENGTH;
  info_string = (char *)tvb_get_ptr(parameter_tvb, INFO_STRING_OFFSET, info_string_length);

  proto_tree_add_string(parameter_tree, hf_iua_info_string,
			parameter_tvb, INFO_STRING_OFFSET, info_string_length ,
			info_string);

  proto_item_set_text(parameter_item, "Info String (%s)", info_string);
}

static void
dissect_iua_dlci_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 dlci;
  proto_item *dlci_item;
  proto_tree *dlci_tree;

  dlci  = tvb_get_ntohs(parameter_tvb, DLCI_OFFSET);
  dlci_item   = proto_tree_add_text(parameter_tree, parameter_tvb, DLCI_OFFSET, DLCI_LENGTH, "DLCI");
  dlci_tree   = proto_item_add_subtree(dlci_item, ett_iua_dlci);
  
  proto_tree_add_boolean(dlci_tree, hf_iua_zero_bit, parameter_tvb, DLCI_OFFSET, 1, dlci);
  proto_tree_add_boolean(dlci_tree, hf_iua_spare_bit, parameter_tvb, DLCI_OFFSET, 1, dlci);
  proto_tree_add_uint(dlci_tree, hf_iua_sapi, parameter_tvb, DLCI_OFFSET, 1, dlci);
  proto_tree_add_boolean(dlci_tree, hf_iua_one_bit, parameter_tvb, DLCI_OFFSET+1, 1, dlci);
  proto_tree_add_uint(dlci_tree, hf_iua_tei, parameter_tvb, DLCI_OFFSET+1, 1, dlci);

  proto_item_set_text(parameter_item, "DLCI");
}

static void
dissect_iua_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, diagnostic_info_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  diagnostic_info_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_VALUE_OFFSET, diagnostic_info_length,
		      "Diagnostic information (%u byte%s)",
		      diagnostic_info_length, plurality(diagnostic_info_length, "", "s"));

  proto_item_set_text(parameter_item, "Diagnostic information (%u byte%s)",
		      diagnostic_info_length, plurality(diagnostic_info_length, "", "s"));
}

static void
dissect_iua_integer_range_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_ranges, range_number;
  guint32 start, end;
  gint    offset;

  proto_item *range_item;
  proto_tree *range_tree;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  number_of_ranges = (length - PARAMETER_HEADER_LENGTH) / (2 * 4);

  offset = PARAMETER_VALUE_OFFSET;
  for(range_number = 1; range_number <= number_of_ranges; range_number++) {
    start = tvb_get_ntohl(parameter_tvb, offset + START_OFFSET);
    end   = tvb_get_ntohl(parameter_tvb, offset + END_OFFSET);
    range_item = proto_tree_add_text(parameter_tree, parameter_tvb,
				     offset + START_OFFSET, START_LENGTH + END_LENGTH,
				     "Integer interface range: %u - %u",
				     start, end);
    range_tree = proto_item_add_subtree(range_item, ett_iua_range);
    proto_tree_add_uint(range_tree, hf_iua_interface_range_start, 
			parameter_tvb,
			offset + START_OFFSET, START_LENGTH,
			start);
    proto_tree_add_uint(range_tree, hf_iua_interface_range_end, 
			parameter_tvb,
			offset + END_OFFSET, END_LENGTH,
			end);
    offset += START_LENGTH + END_LENGTH;
  };

  proto_item_set_text(parameter_item, "Integer interface identifier (%u range%s)",
		      number_of_ranges, plurality(number_of_ranges, "", "s"));
}

static void
dissect_iua_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, heartbeat_data_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  heartbeat_data_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_VALUE_OFFSET, heartbeat_data_length,
		      "Heartbeat data (%u byte%s)",
		      heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));

  proto_item_set_text(parameter_item, "Heartbeat data (%u byte%s)",
		      heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}

static void
dissect_iua_asp_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reason;

  reason = tvb_get_ntohl(parameter_tvb, ASP_REASON_OFFSET);
  
  proto_tree_add_uint_format(parameter_tree, hf_iua_asp_reason, 
			     parameter_tvb, ASP_REASON_OFFSET, ASP_REASON_LENGTH,
			     reason, "Reason: %u (%s)",
			     reason, val_to_str(reason, iua_asp_reason_values, "unknown"));

  proto_item_set_text(parameter_item, "Reason (%s)", val_to_str(reason, iua_asp_reason_values, "unknown"));
}

static void
dissect_iua_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 traffic_mode_type;

  traffic_mode_type = tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET);
  
  proto_tree_add_uint_format(parameter_tree, hf_iua_traffic_mode_type, 
			     parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH,
			     traffic_mode_type, "Traffic mode type: %u (%s)",
			     traffic_mode_type, val_to_str(traffic_mode_type, iua_traffic_mode_type_values, "unknown"));

  proto_item_set_text(parameter_item, "Traffic mode type (%s)", 
		      val_to_str(traffic_mode_type, iua_traffic_mode_type_values, "unknown"));
}

static void
dissect_iua_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 error_code;

  error_code = tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET);
  proto_tree_add_uint_format(parameter_tree, hf_iua_error_code, 
			     parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH,
			     error_code, "Error code: %u (%s)",
			     error_code, val_to_str(error_code, iua_error_code_values, "unknown"));
  proto_item_set_text(parameter_item, "Error code (%s)",
		      val_to_str(error_code, iua_error_code_values, "unknown"));
}

static void
dissect_iua_status_type_identification_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_ident;

  status_type  = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_ident = tvb_get_ntohs(parameter_tvb, STATUS_IDENT_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_iua_status_type, 
			     parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH,
			     status_type, "Status type: %u (%s)",
			     status_type, val_to_str(status_type, iua_status_type_values, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_iua_status_ident, 
			     parameter_tvb, STATUS_IDENT_OFFSET, STATUS_IDENT_LENGTH,
			     status_ident, "Status identification: %u (%s)",
			     status_ident, val_to_str(status_type * 256 * 256 + 
                                                     status_ident, iua_status_type_ident_values, "unknown"));

  proto_item_set_text(parameter_item, "Status type / status identification (%s)",
		      val_to_str(status_type * 256 * 256 + 
				 status_ident, iua_status_type_ident_values, "unknown status information"));
}

static void
dissect_iua_protocol_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, protocol_data_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  protocol_data_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, PROTOCOL_DATA_OFFSET, protocol_data_length,
		      "Protocol data (%u byte%s)",
		      protocol_data_length, plurality(protocol_data_length, "", "s"));

  proto_item_set_text(parameter_item, "Protocol data (%u byte%s)",
		      protocol_data_length, plurality(protocol_data_length, "", "s"));
}

static void
dissect_iua_release_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reason;

  reason = tvb_get_ntohl(parameter_tvb, RELEASE_REASON_OFFSET);
  
  proto_tree_add_uint_format(parameter_tree, hf_iua_release_reason, 
			     parameter_tvb, RELEASE_REASON_OFFSET, RELEASE_REASON_LENGTH,
			     reason, "Reason: %u (%s)",
			     reason, val_to_str(reason, iua_release_reason_values, "unknown"));

  proto_item_set_text(parameter_item, "Reason (%s)", val_to_str(reason, iua_release_reason_values, "unknown"));
}

static void
dissect_iua_tei_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 status;

  status = tvb_get_ntohl(parameter_tvb, TEI_STATUS_OFFSET);
  
  proto_tree_add_uint_format(parameter_tree, hf_iua_release_reason, 
			     parameter_tvb, TEI_STATUS_OFFSET, TEI_STATUS_LENGTH,
			     status, "TEI status: %u (%s)",
			     status, val_to_str(status, iua_tei_status_values, "unknown"));

  proto_item_set_text(parameter_item, "TEI status (%s)", val_to_str(status, iua_tei_status_values, "unknown"));
}

static void
dissect_iua_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 tag, length, parameter_value_length;
  
  tag    = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length,
		      "Parameter value (%u byte%s)",
		      parameter_value_length, plurality(parameter_value_length, "", "s"));

  proto_item_set_text(parameter_item, "Parameter with tag %u and %u byte%s value",
		      tag, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

static void
dissect_iua_parameter(tvbuff_t *parameter_tvb, proto_tree *iua_tree)
{
  guint16 tag, length, padding_length, total_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  /* calculate padding and total length */
  padding_length = nr_of_padding_bytes(length);
  total_length   = length + padding_length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(iua_tree, parameter_tvb,
					 PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_iua_parameter);

  /* add tag and length to the m3ua tree */
  proto_tree_add_uint_format(parameter_tree, hf_iua_parameter_tag, 
			     parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH,
			     tag, "Identifier: %u (%s)",
			     tag, val_to_str(tag, iua_parameter_tag_values, "unknown"));
  proto_tree_add_uint(parameter_tree, hf_iua_parameter_length, 
		      parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH,
		      length);

  switch(tag) {
  case INT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_iua_int_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_iua_text_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INFO_PARAMETER_TAG:
    dissect_iua_info_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DLCI_PARAMETER_TAG:
    dissect_iua_dlci_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_iua_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_iua_integer_range_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_iua_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_REASON_PARAMETER_TAG:
    dissect_iua_asp_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_iua_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ERROR_CODE_PARAMETER_TAG:
    dissect_iua_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG:
    dissect_iua_status_type_identification_parameter(parameter_tvb, parameter_tree, parameter_item);   
    break;
  case PROTOCOL_DATA_PARAMETER_TAG:
    dissect_iua_protocol_data_parameter(parameter_tvb, parameter_tree, parameter_item);   
    break;
  case RELEASE_REASON_PARAMETER_TAG:
    dissect_iua_release_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TEI_STATUS_PARAMETER_TAG:
    dissect_iua_tei_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_iua_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
  
  if (padding_length > 0)
    proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
}

static void
dissect_iua_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *iua_tree)
{
  gint offset, length, padding_length, total_length;
  tvbuff_t *common_header_tvb, *parameter_tvb;

  offset = 0;

  /* extract and process the common header */
  common_header_tvb = tvb_new_subset(message_tvb, offset, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_iua_common_header(common_header_tvb, pinfo, iua_tree);
  offset += COMMON_HEADER_LENGTH;

  if (iua_tree) {
    /* extract zero or more parameters and process them individually */
    while(tvb_length_remaining(message_tvb, offset)) {
      length         = tvb_get_ntohs(message_tvb, offset + PARAMETER_LENGTH_OFFSET);
      padding_length = nr_of_padding_bytes(length);
      total_length   = length + padding_length;
      /* create a tvb for the parameter including the padding bytes */
      parameter_tvb    = tvb_new_subset(message_tvb, offset, total_length, total_length);
      dissect_iua_parameter(parameter_tvb, iua_tree); 
      /* get rid of the handled parameter */
      offset += total_length;
    }
  }
}

static void
dissect_iua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *iua_item;
  proto_tree *iua_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_add_str(pinfo->fd, COL_PROTOCOL, "IUA");
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m3ua protocol tree */
    iua_item = proto_tree_add_item(tree, proto_iua, message_tvb, 0, tvb_length(message_tvb), FALSE);
    iua_tree = proto_item_add_subtree(iua_item, ett_iua);
  } else {
    iua_tree = NULL;
  };
  /* dissect the message */
  dissect_iua_message(message_tvb, pinfo, iua_tree);
}

/* Register the protocol with Ethereal */
void
proto_register_iua(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_iua_version,
      { "Version", "iua.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_iua_reserved,
      { "Reserved", "iua.reserved",
	FT_UINT8, BASE_HEX, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_message_class,
      { "Message class", "iua.message_class",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_iua_message_type,
      { "Message Type", "iua.message_type",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_iua_message_length,
      { "Message length", "iua.message_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_parameter_tag,
      { "Parameter Tag", "iua.parameter_tag",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_iua_parameter_length,
      { "Parameter length", "iua.parameter_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_int_interface_identifier,
      { "Integer interface identifier", "iua.int_interface_identifier",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_text_interface_identifier,
      { "Text interface identifier", "iua.text_interface_identifier",
	FT_STRING, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_spare_bit,
      { "Spare bit", "hf.iua.spare_bit",
	FT_BOOLEAN, 8, NULL, SPARE_BIT_MASK,          
	""}
    }, 
    { &hf_iua_sapi,
      { "SAPI", "hf.iua.sapi",
	FT_UINT8, BASE_HEX, NULL, SAPI_MASK,          
	""}
    }, 
    { &hf_iua_zero_bit,
      { "Zero bit", "hf.iua.zero_bit",
	FT_BOOLEAN, 8, NULL, ZERO_BIT_MASK,          
	""}
    }, 
    { &hf_iua_one_bit,
      { "One bit", "hf.iua.one_bit",
	FT_BOOLEAN, 8, NULL, ONE_BIT_MASK,          
	""}
    }, 
    { &hf_iua_tei,
      { "TEI", "hf.iua.tei",
	FT_UINT8, BASE_HEX, NULL, TEI_MASK,          
	""}
    },
    { &hf_iua_info_string,
      { "Info string", "iua.info_string",
	FT_STRING, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_interface_range_start,
      { "Start", "iua.interface_range_start",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_interface_range_end,
      { "End", "iua.interface_range_end",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_release_reason,
      { "Reason", "iua.release_reason",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    },
    { &hf_iua_status_type,
      { "Status type", "iua.status_type",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },    
    { &hf_iua_status_ident,
      { "Status identification", "iua.status_identification",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },    
    { &hf_iua_traffic_mode_type,
      { "Traffic mode type", "iua.traffic_mode_type",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_error_code,
      { "Error code", "iua.error_code",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_asp_reason,
      { "Reason", "iua.asp_reason",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    }, 
    { &hf_iua_tei_status,
      { "TEI status", "iua.tei_status",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    }, 
 };
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_iua,
    &ett_iua_parameter,
    &ett_iua_dlci,
    &ett_iua_range,
  };
  
  /* Register the protocol name and description */
  proto_iua = proto_register_protocol("ISDN Q.921-User Adaptation Layer",
                                      "IUA", "iua");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_iua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_iua(void)
{
  dissector_add("sctp.port", SCTP_PORT_IUA, dissect_iua, proto_iua);
  dissector_add("sctp.ppi", IUA_PAYLOAD_PROTO_ID, dissect_iua, proto_iua);
}
