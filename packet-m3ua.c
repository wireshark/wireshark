/* packet-m3ua.c
 * Routines for MTP3 User Adaptation Layer dissection
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m3ua-05.txt
 * To do: - clean up the code
 *        - provide better handling of length parameters
 *        - provide good information in summary window
 *
 * Copyright 2000, Michael Tüxen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-m3ua.c,v 1.3 2001/01/14 10:15:56 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
#include "packet-ip.h"


#define SCTP_PORT_M3UA 2905
#define M3UA_PAYLOAD_PROTO_ID 3

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

#define NETWORK_APPEARANCE_PARAMETER_TAG       1
#define PROTOCOL_DATA_PARAMETER_TAG            3
#define INFO_PARAMETER_TAG                     4
#define AFFECTED_DESTINATIONS_PARAMETER_TAG    5
#define ROUTING_CONTEXT_PARAMETER_TAG          6
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG   7
#define HEARTBEAT_DATA_PARAMETER_TAG           8
#define USER_CAUSE_PARAMETER_TAG               9
#define REASON_PARAMETER_TAG                  10
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG       11
#define ERROR_CODE_PARAMETER_TAG              12
#define STATUS_TYPE_PARAMETER_TAG             13
#define CONGESTION_INDICATION_PARAMETER_TAG   14


static const value_string m3ua_parameter_tag_values[] = {
  { NETWORK_APPEARANCE_PARAMETER_TAG,           "Network appearance" },
  { PROTOCOL_DATA_PARAMETER_TAG,                "Protocol data" },
  { INFO_PARAMETER_TAG,                         "Info" },
  { AFFECTED_DESTINATIONS_PARAMETER_TAG,        "Affected destinations" },
  { ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,       "Diagnostic information" },
  { HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { USER_CAUSE_PARAMETER_TAG,                   "User / Cause" },
  { REASON_PARAMETER_TAG,                       "Reason" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                   "Error code" },
  { STATUS_TYPE_PARAMETER_TAG,                  "Status type" }, 
  { CONGESTION_INDICATION_PARAMETER_TAG,        "Congestion Indication" },
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

static const value_string m3ua_message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_TFER_MESSAGE,   "Transfer messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { 0,                           NULL } };

#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1

#define MESSAGE_TYPE_DATA                 1

#define MESSAGE_TYPE_DUNA                 1
#define MESSAGE_TYPE_DAVA                 2
#define MESSAGE_TYPE_DAUD                 3
#define MESSAGE_TYPE_SCON                 4
#define MESSAGE_TYPE_DUPU                 5

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

static const value_string m3ua_message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "Notify (NTFY)" },
  { MESSAGE_CLASS_TFER_MESSAGE  * 256 + MESSAGE_TYPE_DATA,          "Payload data (DATA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUNA,          "Destination unavailable (DUNA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAVA,          "Destination available (DAVA)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DAUD,          "Destination state audit (DAUD)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_SCON,          "SS7 Network congestion state (SCON)" },
  { MESSAGE_CLASS_SSNM_MESSAGE  * 256 + MESSAGE_TYPE_DUPU,          "Destination userpart unavailable (DUPU)" },
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
  { 0,                           NULL } };




#define NETWORK_APPEARANCE_LENGTH 4
#define NETWORK_APPEARANCE_OFFSET PARAMETER_VALUE_OFFSET

#define PROTOCOL_DATA_OFFSET PARAMETER_VALUE_OFFSET

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET


#define INVALID_VERSION_ERROR_CODE               1
#define INVALID_NETWORK_APPEARANCE_ERROR_CODE    2
#define UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE      3
#define INVALID_MESSAGE_TYPE_ERROR_CODE          4
#define INVALID_TRAFFIC_HANDLING_MODE_ERROR_CODE 5
#define UNEXPECTED_MESSAGE_ERROR_CODE            6
#define PROTOCOL_ERROR_ERROR_CODE                7
#define INVALID_ROUTING_CONTEXT_ERROR_CODE       8

static const value_string m3ua_error_code_values[] = {
  { INVALID_VERSION_ERROR_CODE,               "Invalid version" },
  { INVALID_NETWORK_APPEARANCE_ERROR_CODE,    "Invalid network appearance" },
  { UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE,      "Unsupported message type" },
  { INVALID_MESSAGE_TYPE_ERROR_CODE,          "Invalid message type" },
  { INVALID_TRAFFIC_HANDLING_MODE_ERROR_CODE, "Invalid traffic handling mode" },
  { UNEXPECTED_MESSAGE_ERROR_CODE,            "Unexpected message" },
  { PROTOCOL_ERROR_ERROR_CODE,                "Protocol error" },
  { INVALID_ROUTING_CONTEXT_ERROR_CODE,       "Invalid routing contexted" },
  { 0,                           NULL } };

#define ERROR_CODE_LENGTH 4
#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

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

static const value_string m3ua_status_type_info_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  {0,                           NULL } };

#define STATUS_TYPE_LENGTH 2
#define STATUS_INFO_LENGTH 2

#define STATUS_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define STATUS_INFO_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

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


#define OVER_RIDE_TYPE           1
#define LOAD_SHARE_TYPE          2
#define OVER_RIDE_STANDBY_TYPE   3
#define LOAD_SHARE_STANDBY_TYPE  4

static const value_string m3ua_traffic_mode_type_values[] = {
  { OVER_RIDE_TYPE ,                             "Over-ride" },
  { LOAD_SHARE_TYPE,                             "Load-share" },
  { OVER_RIDE_STANDBY_TYPE,                      "Over-ride (standby)" },
  { LOAD_SHARE_STANDBY_TYPE,                     "Load-share (standby)" },
  {0,                           NULL } };

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

#define ROUTING_CONTEXT_LENGTH 4

#define AFFECTED_DESTINATION_LENGTH 4
#define AFFECTED_MASK_LENGTH        1
#define AFFECTED_DPC_LENGTH         3

#define AFFECTED_MASK_OFFSET        0
#define AFFECTED_DPC_OFFSET         (AFFECTED_MASK_OFFSET + AFFECTED_MASK_LENGTH)

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

/* Initialize the protocol and registered fields */
static int proto_m3ua = -1;
static int hf_m3ua_version = -1;
static int hf_m3ua_reserved = -1;
static int hf_m3ua_message_class = -1;
static int hf_m3ua_message_type = -1;
static int hf_m3ua_message_length = -1;
static int hf_m3ua_parameter_tag = -1;
static int hf_m3ua_parameter_length = -1;
static int hf_m3ua_network_appearance = -1;
static int hf_m3ua_info_string = -1;
static int hf_m3ua_error_code = -1;
static int hf_m3ua_status_type = -1;
static int hf_m3ua_status_info = -1;
static int hf_m3ua_unavailability_cause = -1;
static int hf_m3ua_user_identity = -1;
static int hf_m3ua_reason = -1;
static int hf_m3ua_traffic_mode_type = -1;
static int hf_m3ua_routing_context = -1;
static int hf_m3ua_mask = -1;
static int hf_m3ua_dpc = -1;
static int hf_m3ua_congestion_level = -1;

/* Initialize the subtree pointers */
static gint ett_m3ua = -1;
static gint ett_m3ua_parameter = -1;
static gint ett_m3ua_affected_destination = -1;

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

  if (check_col(pinfo->fd, COL_INFO)) {
    col_append_str(pinfo->fd, COL_INFO, val_to_str(message_class * 256 + message_type, m3ua_message_class_type_acro_values, "reserved"));
    col_append_str(pinfo->fd, COL_INFO, " ");
  };

  if (m3ua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint_format(m3ua_tree, hf_m3ua_version, 
			       common_header_tvb, VERSION_OFFSET, VERSION_LENGTH,
			       version, "Version: %u (%s)",
			       version, val_to_str(version, m3ua_protocol_version_values, "unknown"));
    proto_tree_add_uint(m3ua_tree, hf_m3ua_reserved,
			common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH,
			reserved);
    proto_tree_add_uint_format(m3ua_tree, hf_m3ua_message_class, 
			       common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH,
			     message_class, "Message class: %u (%s)",
			       message_class, val_to_str(message_class, m3ua_message_class_values, "reserved"));
    proto_tree_add_uint_format(m3ua_tree, hf_m3ua_message_type, 
			       common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
			       message_type, "Message type: %u (%s)",
			       message_type, val_to_str(message_class * 256 + message_type, m3ua_message_class_type_values, "reserved"));
    proto_tree_add_uint(m3ua_tree, hf_m3ua_message_length,
			common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH,
			message_length);
  };
}

static void
dissect_m3ua_network_appearance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 network_appearance;

  network_appearance = tvb_get_ntohl(parameter_tvb, NETWORK_APPEARANCE_OFFSET);
  
  proto_tree_add_uint(parameter_tree, hf_m3ua_network_appearance, 
		      parameter_tvb, NETWORK_APPEARANCE_OFFSET, NETWORK_APPEARANCE_LENGTH,
		      network_appearance);
 
  proto_item_set_text(parameter_item, "Network appearance: %u", network_appearance);
}

static void
dissect_m3ua_protocol_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, protocol_data_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  protocol_data_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, PROTOCOL_DATA_OFFSET, protocol_data_length,
		      "Protocol data (%u byte%s)",
		      protocol_data_length, plurality(protocol_data_length, "", "s"));

  proto_item_set_text(parameter_item, "Protocol data (SS7 message of %u byte%s)",
		      protocol_data_length, plurality(protocol_data_length, "", "s"));
}

static void
dissect_m3ua_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, info_string_length;
  char *info_string;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  info_string_length = length - PARAMETER_HEADER_LENGTH;
  info_string = (char *)tvb_get_ptr(parameter_tvb, INFO_STRING_OFFSET, info_string_length);

  proto_tree_add_string(parameter_tree, hf_m3ua_info_string,
			parameter_tvb, INFO_STRING_OFFSET, info_string_length ,
			info_string);

  proto_item_set_text(parameter_item, "Info String (%s)", info_string);
}

static void
dissect_m3ua_affected_destinations_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  mask;
  guint16 length, number_of_destinations, destination_number;
  guint32 dpc;
  gint destination_offset;
  proto_item *destination_item;
  proto_tree *destination_tree;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_destinations= (length - PARAMETER_HEADER_LENGTH) / 4;

  destination_offset = PARAMETER_VALUE_OFFSET;
  for(destination_number=1; destination_number <= number_of_destinations; destination_number++) {
    mask = tvb_get_guint8(parameter_tvb, destination_offset + AFFECTED_MASK_OFFSET);
    dpc  = tvb_get_ntoh24(parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET);
    destination_item = proto_tree_add_text(parameter_tree, parameter_tvb, destination_offset, AFFECTED_DESTINATION_LENGTH,
					  "Affected destination");
    destination_tree = proto_item_add_subtree(destination_item, ett_m3ua_affected_destination);

    proto_tree_add_uint(destination_tree, hf_m3ua_mask, 
			parameter_tvb, destination_offset + AFFECTED_MASK_OFFSET, AFFECTED_MASK_LENGTH,
			mask);
    proto_tree_add_uint(destination_tree, hf_m3ua_dpc, 
			parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET, AFFECTED_DPC_LENGTH,
			dpc);
    destination_offset += AFFECTED_DESTINATION_LENGTH;
  };
  proto_item_set_text(parameter_item, "Affected destinations parameter (%u destination%s)",
		      number_of_destinations, plurality(number_of_destinations, "", "s"));

}

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
    proto_tree_add_uint(parameter_tree, hf_m3ua_routing_context, 
			parameter_tvb, context_offset, ROUTING_CONTEXT_LENGTH,
			context);
    context_offset += ROUTING_CONTEXT_LENGTH;
  };
  proto_item_set_text(parameter_item, "Routing context parameter (%u context%s)",
		      number_of_contexts, plurality(number_of_contexts, "", "s"));
}

static void
dissect_m3ua_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
dissect_m3ua_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
dissect_m3ua_user_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 cause, user;

  cause = tvb_get_ntohs(parameter_tvb, CAUSE_OFFSET);
  user  = tvb_get_ntohs(parameter_tvb, USER_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_m3ua_unavailability_cause, 
			     parameter_tvb, CAUSE_OFFSET, CAUSE_LENGTH,
			     cause, "Unavailability cause: %u (%s)",
			     cause, val_to_str(cause, m3ua_unavailability_cause_values, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_user_identity, 
			     parameter_tvb, USER_OFFSET, USER_LENGTH,
			     user, "User identity: %u (%s)",
			     user, val_to_str(user, m3ua_user_identity_values, "unknown"));
  proto_item_set_text(parameter_item, "User / Cause parameter (%s: %s)",
		      val_to_str(user, m3ua_user_identity_values, "Unknown user"),
		      val_to_str(cause, m3ua_unavailability_cause_values, "unknown cause"));
}

static void
dissect_m3ua_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reason;

  reason = tvb_get_ntohl(parameter_tvb, REASON_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_m3ua_reason, 
			     parameter_tvb, REASON_OFFSET, REASON_LENGTH,
			     reason, "Reason: %u (%s)",
			     reason, val_to_str(reason, m3ua_reason_values, "unknown"));
  proto_item_set_text(parameter_item, "Reason parameter (%s)",
		      val_to_str(reason, m3ua_reason_values, "unknown"));
}

static void
dissect_m3ua_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 traffic_mode_type;

  traffic_mode_type = tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_m3ua_traffic_mode_type, 
			     parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH,
			     traffic_mode_type, "Traffic mode type: %u (%s)",
			     traffic_mode_type, val_to_str(traffic_mode_type, m3ua_traffic_mode_type_values, "unknown"));
  proto_item_set_text(parameter_item, "Traffic mode type parameter (%s)",
		      val_to_str(traffic_mode_type, m3ua_traffic_mode_type_values, "unknown"));
}

static void
dissect_m3ua_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 error_code;

  error_code = tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET);
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_error_code, 
			     parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH,
			     error_code, "Error code: %u (%s)",
			     error_code, val_to_str(error_code, m3ua_error_code_values, "unknown"));
  proto_item_set_text(parameter_item, "Error code parameter (%s)",
		      val_to_str(error_code, m3ua_error_code_values, "unknown"));
}

static void
dissect_m3ua_status_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_info;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_info = tvb_get_ntohs(parameter_tvb, STATUS_INFO_OFFSET);

  proto_tree_add_uint_format(parameter_tree, hf_m3ua_status_type, 
			     parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH,
			     status_type, "Status type: %u (%s)",
			     status_type, val_to_str(status_type, m3ua_status_type_values, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_status_info, 
			     parameter_tvb, STATUS_INFO_OFFSET, STATUS_INFO_LENGTH,
			     status_info, "Status info: %u (%s)",
			     status_info, val_to_str(status_type * 256 * 256 + 
                                                     status_info, m3ua_status_type_info_values, "unknown"));

  proto_item_set_text(parameter_item, "Status type / ID (%s)",
		      val_to_str(status_type * 256 * 256 + 
				 status_info, m3ua_status_type_info_values, "unknown status information"));
}

static void
dissect_m3ua_congestion_indication_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 level;
  
  level = tvb_get_guint8(parameter_tvb, CONG_IND_LEVEL_OFFSET);

  proto_tree_add_text(parameter_tree, parameter_tvb, CONG_IND_RESERVED_OFFSET, CONG_IND_RESERVED_LENGTH,
			"Reserved: %u byte%s",
			CONG_IND_RESERVED_LENGTH, plurality(CONG_IND_RESERVED_LENGTH, "", "s"));
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_congestion_level, 
			     parameter_tvb, CONG_IND_LEVEL_OFFSET, CONG_IND_LEVEL_LENGTH,
			     level, "Congestion level: %u (%s)",
			     level, val_to_str(level, m3ua_congestion_level_values, "unknown"));
  proto_item_set_text(parameter_item, "Congestion indication (%s)",
		      val_to_str(level, m3ua_congestion_level_values, "unknown"));
}

static void
dissect_m3ua_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
dissect_m3ua_parameter(tvbuff_t *parameter_tvb, proto_tree *m3ua_tree)
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
  parameter_item   = proto_tree_add_text(m3ua_tree, parameter_tvb,
				     PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_m3ua_parameter);

  /* add tag and length to the m3ua tree */
  proto_tree_add_uint_format(parameter_tree, hf_m3ua_parameter_tag, 
			     parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH,
			     tag, "Identifier: %u (%s)",
			     tag, val_to_str(tag, m3ua_parameter_tag_values, "unknown"));
  proto_tree_add_uint(parameter_tree, hf_m3ua_parameter_length, 
		      parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH,
		      length);

  switch(tag) {
  case NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_m3ua_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_DATA_PARAMETER_TAG:
    dissect_m3ua_protocol_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INFO_PARAMETER_TAG:
    dissect_m3ua_info_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case AFFECTED_DESTINATIONS_PARAMETER_TAG:
    dissect_m3ua_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_m3ua_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_m3ua_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_m3ua_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case USER_CAUSE_PARAMETER_TAG:
    dissect_m3ua_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case REASON_PARAMETER_TAG:
    dissect_m3ua_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_m3ua_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ERROR_CODE_PARAMETER_TAG:
    dissect_m3ua_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case  STATUS_TYPE_PARAMETER_TAG:
    dissect_m3ua_status_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case  CONGESTION_INDICATION_PARAMETER_TAG:
    dissect_m3ua_congestion_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_m3ua_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
}

static void
dissect_m3ua_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *m3ua_tree)
{
  gint offset, length, padding_length, total_length;
  tvbuff_t *common_header_tvb, *parameter_tvb;

  offset = 0;

  /* extract and process the common header */
  common_header_tvb = tvb_new_subset(message_tvb, offset, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_m3ua_common_header(common_header_tvb, pinfo, m3ua_tree);
  offset += COMMON_HEADER_LENGTH;
  
  if (m3ua_tree) {
    /* extract zero or more parameters and process them individually */
    while(tvb_length_remaining(message_tvb, offset)) {
      length         = tvb_get_ntohs(message_tvb, offset + PARAMETER_LENGTH_OFFSET);
      padding_length = nr_of_padding_bytes(length);
      total_length   = length + padding_length;
      /* create a tvb for the parameter including the padding bytes */
      parameter_tvb    = tvb_new_subset(message_tvb, offset, total_length, total_length);
      dissect_m3ua_parameter(parameter_tvb, m3ua_tree); 
      /* get rid of the handled parameter */
      offset += total_length;
    }
  }
}

static void
dissect_m3ua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m3ua_item;
  proto_tree *m3ua_tree;

  CHECK_DISPLAY_AS_DATA(proto_m3ua, message_tvb, pinfo, tree);

  pinfo->current_proto = "M3UA";

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_set_str(pinfo->fd, COL_PROTOCOL, "M3UA");
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m3ua protocol tree */
    m3ua_item = proto_tree_add_item(tree, proto_m3ua, message_tvb, 0, tvb_length(message_tvb), FALSE);
    m3ua_tree = proto_item_add_subtree(m3ua_item, ett_m3ua);
  } else {
    m3ua_tree = NULL;
  };
  /* dissect the message */
  dissect_m3ua_message(message_tvb, pinfo, m3ua_tree);
}

/* Register the protocol with Ethereal */
void
proto_register_m3ua(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_m3ua_version,
      { "Version", "m3ua.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_m3ua_reserved,
      { "Reserved", "m3ua.reserved",
	FT_UINT8, BASE_HEX, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_message_class,
      { "Message class", "m3ua.message_class",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_m3ua_message_type,
      { "Message Type", "m3ua.message_type",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_m3ua_message_length,
      { "Message length", "m3ua.message_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_parameter_tag,
      { "Parameter Tag", "m3ua.parameter_tag",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_m3ua_parameter_length,
      { "Parameter length", "m3ua.parameter_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_network_appearance,
      { "Network appearance", "m3ua.network_appearance",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_info_string,
      { "Info string", "m3ua.info_string",
	FT_STRING, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_error_code,
      { "Error code", "m3ua.error_code",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_status_type,
      { "Status type", "m3ua.status_type",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_status_info,
      { "Status info", "m3ua.status_info",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_unavailability_cause,
      { "Unavailability cause", "m3ua.unavailability_cause",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_user_identity,
      { "User Identity", "m3ua.user_identity",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_reason,
      { "Reason", "m3ua.reason",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_traffic_mode_type,
      { "Traffic mode Type", "m3ua.traffic_mode_type",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_routing_context,
      { "Routing context", "m3ua.routing_context",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_mask,
      { "Mask", "m3ua.mask",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_dpc,
      { "Affected DPC", "m3ua.affected_dpc",
	FT_UINT24, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_m3ua_congestion_level,
      { "Congestion level", "m3ua.congestion_level",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    }, 
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m3ua,
    &ett_m3ua_parameter,
    &ett_m3ua_affected_destination,
  };
  
  /* Register the protocol name and description */
  proto_m3ua = proto_register_protocol("MTP 3 User Adaptation Layer",
                                      "M3UA",  "m3ua");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_m3ua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_m3ua(void)
{
  dissector_add("sctp.ppi",  M3UA_PAYLOAD_PROTO_ID, dissect_m3ua, proto_m3ua);
  dissector_add("sctp.port", SCTP_PORT_M3UA, dissect_m3ua, proto_m3ua);
}
