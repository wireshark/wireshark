/* packet-sua.c
 * Routines for  SS7 SCCP-User Adaptation Layer (SUA) dissection
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-sua-08.txt
 * and also supports SUA light, a trivial Siemens proprietary version.
 *
 * Copyright 2000, Michael Tüxen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-sua.c,v 1.6 2002/01/24 09:20:52 guy Exp $
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

#define SCTP_PORT_SUA          14001
#define SUA_PAYLOAD_PROTO_ID   4

#define RESERVED_1_LENGTH      1
#define RESERVED_2_LENGTH      2
#define RESERVED_3_LENGTH      3

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

#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_TAG_OFFSET      0
#define PARAMETER_LENGTH_OFFSET   (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_VALUE_OFFSET    (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET   PARAMETER_TAG_OFFSET

#define DATA_PARAMETER_TAG                         0x0003
#define INFO_STRING_PARAMETER_TAG                  0x0004
#define ROUTING_CONTEXT_PARAMETER_TAG              0x0006
#define DIAGNOSTIC_INFO_PARAMETER_TAG              0x0007
#define HEARTBEAT_DATA_PARAMETER_TAG               0x0009
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG            0x000b
#define ERROR_CODE_PARAMETER_TAG                   0x000c
#define STATUS_PARAMETER_TAG                       0x000d
#define CONGESTION_LEVEL_PARAMETER_TAG             0x000f
#define ASP_IDENTIFIER_PARAMETER_TAG               0x0011
#define AFFECTED_POINT_CODE_PARAMETER_TAG          0x0012
#define SS7_HOP_COUNTER_PARAMETER_TAG              0x0101
#define SOURCE_ADDRESS_PARAMETER_TAG               0x0102
#define DESTINATION_ADDRESS_PARAMETER_TAG          0x0103
#define SOURCE_REFERENCE_NUMBER_PARAMETER_TAG      0x0104
#define DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG 0x0105
#define SCCP_CAUSE_PARAMETER_TAG                   0x0106
#define SEQUENCE_NUMBER_PARAMETER_TAG              0x0107
#define RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG      0x0108
#define ASP_CAPABILITIES_PARAMETER_TAG             0x0109
#define CREDIT_PARAMETER_TAG                       0x010a
#define USER_CAUSE_PARAMETER_TAG                   0x010c
#define NETWORK_APPEARANCE_PARAMETER_TAG           0x010d
#define ROUTING_KEY_PARAMETER_TAG                  0x010e
#define REGISTRATION_RESULT_PARAMETER_TAG          0x010f
#define DEREGISTRATION_RESULT_PARAMETER_TAG        0x0110
#define ADDRESS_RANGE_PARAMETER_TAG                0x0111
#define CORRELATION_ID_PARAMETER_TAG               0x0112
#define IMPORTANCE_PARAMETER_TAG                   0x0113
#define MESSAGE_PRIORITY_PARAMETER_TAG             0x0114
#define PROTOCOL_CLASS_PARAMETER_TAG               0x0115
#define SEQUENCE_CONTROL_PARAMETER_TAG             0x0116
#define SEGMENTATION_PARAMETER_TAG                 0x0117
#define SMI_PARAMETER_TAG                          0x0118
#define TID_LABEL_PARAMETER_TAG                    0x0119
#define DRN_LABEL_PARAMETER_TAG                    0x011a
#define GLOBAL_TITLE_PARAMETER_TAG                 0x8001
#define POINT_CODE_PARAMETER_TAG                   0x8002
#define SUBSYSTEM_NUMBER_PARAMETER_TAG             0x8003
#define IPV4_ADDRESS_PARAMETER_TAG                 0x8004
#define HOSTNAME_PARAMETER_TAG                     0x8005
#define IPV6_ADDRESS_PARAMETER_TAG                 0x8006

static const value_string sua_parameter_tag_values[] = {
  { DATA_PARAMETER_TAG,                         "Data" },
  { INFO_STRING_PARAMETER_TAG,                  "Info String" },
  { ROUTING_CONTEXT_PARAMETER_TAG,              "Routing context" },
  { DIAGNOSTIC_INFO_PARAMETER_TAG,              "Diagnostic Info" },
  { HEARTBEAT_DATA_PARAMETER_TAG,               "Heartbeat data" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,            "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                   "Error code" },  
  { STATUS_PARAMETER_TAG,                       "Status" },
  { CONGESTION_LEVEL_PARAMETER_TAG,             "Congestion Level" },
  { ASP_IDENTIFIER_PARAMETER_TAG,               "ASP Identifier" },
  { AFFECTED_POINT_CODE_PARAMETER_TAG,          "Affected Point Code" },
  { SS7_HOP_COUNTER_PARAMETER_TAG,              "SS7 Hop Counter" },
  { SOURCE_ADDRESS_PARAMETER_TAG,               "Source Address" },
  { DESTINATION_ADDRESS_PARAMETER_TAG,          "Destination Address" },
  { SOURCE_REFERENCE_NUMBER_PARAMETER_TAG,      "Source Reference Number" },
  { DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG, "Destination Reference Number" },
  { SCCP_CAUSE_PARAMETER_TAG,                   "SCCP Cause" },
  { SEQUENCE_NUMBER_PARAMETER_TAG,              "Sequence Number" },
  { RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG,      "Receive Sequence Number" },
  { ASP_CAPABILITIES_PARAMETER_TAG,             "ASP Capabilities" },
  { CREDIT_PARAMETER_TAG,                       "Credit" },
  { USER_CAUSE_PARAMETER_TAG,                   "User/Cause" },
  { NETWORK_APPEARANCE_PARAMETER_TAG,           "Network Appearance" },
  { ROUTING_KEY_PARAMETER_TAG,                  "Routing Key" },
  { REGISTRATION_RESULT_PARAMETER_TAG,          "Registration Result" },
  { DEREGISTRATION_RESULT_PARAMETER_TAG,        "Deregistration Result" },
  { ADDRESS_RANGE_PARAMETER_TAG,                "Address Range" },
  { CORRELATION_ID_PARAMETER_TAG,               "Correlation ID" },
  { IMPORTANCE_PARAMETER_TAG,                   "Importance" },
  { MESSAGE_PRIORITY_PARAMETER_TAG,             "Message Priority" },
  { PROTOCOL_CLASS_PARAMETER_TAG,               "Protocol Class" },
  { SEQUENCE_CONTROL_PARAMETER_TAG,             "Sequence Control" },
  { SEGMENTATION_PARAMETER_TAG,                 "Segmentation" },
  { SMI_PARAMETER_TAG,                          "SMI" },
  { TID_LABEL_PARAMETER_TAG,                    "TID Label" },
  { DRN_LABEL_PARAMETER_TAG,                    "DRN Label" },
  { GLOBAL_TITLE_PARAMETER_TAG,                 "Global Title" },
  { POINT_CODE_PARAMETER_TAG,                   "Point Code" },
  { SUBSYSTEM_NUMBER_PARAMETER_TAG,             "Subsystem Number" },
  { IPV4_ADDRESS_PARAMETER_TAG,                 "IPv4 Address" },
  { HOSTNAME_PARAMETER_TAG,                     "Hostname" },
  { IPV6_ADDRESS_PARAMETER_TAG,                 "IPv6 Address" },
  { 0,                                          NULL } };

#define PROTOCOL_VERSION_RELEASE_1             1

static const value_string sua_protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_MGMT_MESSAGE        0
#define MESSAGE_CLASS_TFER_MESSAGE        1
#define MESSAGE_CLASS_SSNM_MESSAGE        2
#define MESSAGE_CLASS_ASPSM_MESSAGE       3
#define MESSAGE_CLASS_ASPTM_MESSAGE       4
#define MESSAGE_CLASS_CL_MESSAGE          7
#define MESSAGE_CLASS_CO_MESSAGE          8
#define MESSAGE_CLASS_RKM_MESSAGE         9

static const value_string sua_message_class_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE,   "Management messages" },
  { MESSAGE_CLASS_SSNM_MESSAGE,   "SS7 signalling network management messages" },
  { MESSAGE_CLASS_ASPSM_MESSAGE,  "ASP state maintenance messages" },
  { MESSAGE_CLASS_ASPTM_MESSAGE,  "ASP traffic maintenance messages" },
  { MESSAGE_CLASS_CL_MESSAGE,     "Connectionless messages" },
  { MESSAGE_CLASS_CO_MESSAGE,     "Connection-Oriented messages" },
  { MESSAGE_CLASS_RKM_MESSAGE,    "Routing key management Messages" },
  { 0,                           NULL } };

#define MESSAGE_TYPE_ERR                  0
#define MESSAGE_TYPE_NTFY                 1

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

#define MESSAGE_TYPE_CLDT                 1
#define MESSAGE_TYPE_CLDR                 2

#define MESSAGE_TYPE_CORE                 1
#define MESSAGE_TYPE_COAK                 2
#define MESSAGE_TYPE_COREF                3
#define MESSAGE_TYPE_RELRE                4
#define MESSAGE_TYPE_RELCO                5
#define MESSAGE_TYPE_RESCO                6
#define MESSAGE_TYPE_RESRE                7
#define MESSAGE_TYPE_CODT                 8
#define MESSAGE_TYPE_CODA                 9
#define MESSAGE_TYPE_COERR               10
#define MESSAGE_TYPE_COIT                11

#define MESSAGE_TYPE_REG_REQ              1
#define MESSAGE_TYPE_REG_RSP              2
#define MESSAGE_TYPE_DEREG_REQ            3
#define MESSAGE_TYPE_DEREG_RSP            4


static const value_string sua_message_class_type_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "Error (ERR)" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "Notify (NTFY)" },
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
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDR ,         "Connectionless Data Response (CLDR)" },
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDT ,         "Connectionless Data Transfer (CLDT)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CORE ,         "Connection Request (CORE)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COAK ,         "Connection Acknowledge (COAK)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COREF ,        "Connection Refused (COREF)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELRE ,        "Release Request (RELRE)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELCO ,        "Release Complete (RELCO)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESCO ,        "Reset Confirm (RESCO)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESRE ,        "Reset Request (RESRE)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODT ,         "Connection Oriented Data Transfer (CODT)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODA ,         "Connection Oriented Data Acknowledge (CODA)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COERR ,        "Connection Oriented Error (COERR)" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COIT ,         "Inactivity Test (COIT)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "Registration Request (REG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "Registartion Response (REG_RSP)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "Deregistration Request (DEREG_REQ)" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "Deregistartion Response (DEREG_RSP)" },
  { 0,                           NULL } };

static const value_string sua_message_class_type_acro_values[] = {
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_ERR,           "ERR" },
  { MESSAGE_CLASS_MGMT_MESSAGE  * 256 + MESSAGE_TYPE_NTFY,          "NTFY" },
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
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDR ,         "CLDR" },
  { MESSAGE_CLASS_CL_MESSAGE    * 256 + MESSAGE_TYPE_CLDT ,         "CLDT" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CORE ,         "CORE" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COAK ,         "COAK" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COREF ,        "COREF" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELRE ,        "RELRE" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RELCO ,        "RELCO" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESCO ,        "RESCO" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_RESRE ,        "RESRE" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODT ,         "CODT" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_CODA ,         "CODA" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COERR ,        "COERR" },
  { MESSAGE_CLASS_CO_MESSAGE    * 256 + MESSAGE_TYPE_COIT ,         "COIT" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_REQ ,      "REG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_REG_RSP ,      "REG_RSP" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_REQ ,    "DEREG_REQ" },
  { MESSAGE_CLASS_RKM_MESSAGE   * 256 + MESSAGE_TYPE_DEREG_RSP ,    "DEREG_RSP" },
  { 0,                           NULL } };

/* Initialize the protocol and registered fields */
static module_t *sua_module;
static int proto_sua = -1;
static int hf_sua_version = -1;
static int hf_sua_reserved = -1;
static int hf_sua_message_class = -1;
static int hf_sua_message_type = -1;
static int hf_sua_message_length = -1;
static int hf_sua_parameter_tag = -1;
static int hf_sua_parameter_length = -1;
static int hf_sua_parameter_value = -1;
static int hf_sua_parameter_padding = -1;
static int hf_sua_data_padding = -1;
static int hf_sua_info_string = -1;
static int hf_sua_info_string_padding = -1;
static int hf_sua_routing_context = -1;
static int hf_sua_diagnostic_information_info = -1;
static int hf_sua_diagnostic_information_padding = -1;
static int hf_sua_heartbeat_data = -1;
static int hf_sua_heartbeat_padding = -1;
static int hf_sua_traffic_mode_type = -1;
static int hf_sua_error_code = -1;
static int hf_sua_status_type = -1;
static int hf_sua_status_info = -1;
static int hf_sua_congestion_level = -1;
static int hf_sua_asp_identifier = -1;
static int hf_sua_mask = -1;
static int hf_sua_dpc = -1;
static int hf_sua_source_address_routing_indicator = -1;
static int hf_sua_source_address_reserved_bits = -1;
static int hf_sua_source_address_gt_bit = -1;
static int hf_sua_source_address_pc_bit = -1;
static int hf_sua_source_address_ssn_bit = -1;
static int hf_sua_destination_address_routing_indicator = -1;
static int hf_sua_destination_address_reserved_bits = -1;
static int hf_sua_destination_address_gt_bit = -1;
static int hf_sua_destination_address_pc_bit = -1;
static int hf_sua_destination_address_ssn_bit = -1;
static int hf_sua_ss7_hop_counter_counter = -1;
static int hf_sua_ss7_hop_counter_reserved = -1;
static int hf_sua_destination_reference_number = -1;
static int hf_sua_source_reference_number = -1;
static int hf_sua_cause_reserved = -1;
static int hf_sua_cause_type = -1;
static int hf_sua_cause_value = -1;
static int hf_sua_sequence_number_reserved = -1;
static int hf_sua_sequence_number_rec_number = -1;
static int hf_sua_sequence_number_spare_bit = -1;
static int hf_sua_sequence_number_sent_number = -1;
static int hf_sua_sequence_number_more_data_bit = -1;
static int hf_sua_receive_sequence_number_reserved = -1;
static int hf_sua_receive_sequence_number_number = -1;
static int hf_sua_receive_sequence_number_spare_bit = -1;
static int hf_sua_asp_capabilities_reserved = -1;
static int hf_sua_asp_capabilities_reserved_bits = -1;
static int hf_sua_asp_capabilities_a_bit =-1;
static int hf_sua_asp_capabilities_b_bit =-1;
static int hf_sua_asp_capabilities_c_bit =-1;
static int hf_sua_asp_capabilities_d_bit =-1;
static int hf_sua_asp_capabilities_interworking = -1;
static int hf_sua_credit = -1;
static int hf_sua_cause = -1;
static int hf_sua_user = -1;
static int hf_sua_network_appearance = -1;
static int hf_sua_routing_key_identifier = -1;
static int hf_sua_registration_result_routing_key_identifier = -1;
static int hf_sua_registration_result_status = -1;
static int hf_sua_registration_result_routing_context = -1;
static int hf_sua_deregistration_result_status = -1;
static int hf_sua_deregistration_result_routing_context = -1;
static int hf_sua_correlation_id = -1;
static int hf_sua_importance_reserved = -1;
static int hf_sua_importance = -1;
static int hf_sua_message_priority_reserved = -1;
static int hf_sua_message_priority = -1;
static int hf_sua_protocol_class_reserved = -1;
static int hf_sua_return_on_error_bit = -1;
static int hf_sua_protocol_class = -1;
static int hf_sua_sequence_control = -1;
static int hf_sua_first_bit = -1;
static int hf_sua_number_of_remaining_segments = -1;
static int hf_sua_segmentation_reference = -1;
static int hf_sua_smi = -1;
static int hf_sua_smi_reserved = -1;
static int hf_sua_tid_label_start = -1;
static int hf_sua_tid_label_end = -1;
static int hf_sua_tid_label_value = -1;
static int hf_sua_drn_label_start = -1;
static int hf_sua_drn_label_end = -1;
static int hf_sua_drn_label_value = -1;
static int hf_sua_number_of_digits = -1;
static int hf_sua_translation_type = -1;
static int hf_sua_numbering_plan = -1;
static int hf_sua_nature_of_address = -1;
static int hf_sua_global_title = -1;
static int hf_sua_global_title_padding = -1;
static int hf_sua_point_code_mask = -1;
static int hf_sua_point_code_dpc = -1;
static int hf_sua_ssn_reserved = -1;
static int hf_sua_ssn_number = -1;
static int hf_sua_ipv4 = -1;
static int hf_sua_hostname = -1;
static int hf_sua_hostname_padding = -1;
static int hf_sua_ipv6 = -1;
/* Support of Light version starts here */
static int hf_sua_light_version = -1;
static int hf_sua_light_spare_1 = -1;
static int hf_sua_light_message_type = -1;
static int hf_sua_light_subsystem_number = -1;
static int hf_sua_light_spare_2 = -1;
static int hf_sua_light_message_length = -1;
static int hf_sua_light_error_code = -1;
/* Support of Light version end here */

/* Initialize the subtree pointers */
static gint ett_sua = -1;
static gint ett_sua_parameter = -1;
static gint ett_sua_source_address_indicator = -1;
static gint ett_sua_destination_address_indicator = -1;
static gint ett_sua_affected_destination = -1;
static gint ett_sua_first_remaining = -1;
static gint ett_sua_sequence_number_rec_number = -1;
static gint ett_sua_sequence_number_sent_number = -1;
static gint ett_sua_receive_sequence_number_number = -1;
static gint ett_sua_return_on_error_bit_and_protocol_class = -1;
static gint ett_sua_protcol_classes = -1;

/* stuff for supporting multiple versions */
#define SIEMENS_VERSION   1
#define IETF_VERSION08    2
static gint sua_version = IETF_VERSION08;

static dissector_table_t sua_light_dissector_table;
/* ends here */

static void
dissect_sua_tlv_list(tvbuff_t *tlv_tvb, proto_tree *sua_tree, gint initial_offset);

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
dissect_sua_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *sua_tree)
{
  guint8  version, message_class, message_type;
  guint32 message_length;
  /* Extract the common header */
  version        = tvb_get_guint8(common_header_tvb, VERSION_OFFSET);
  message_class  = tvb_get_guint8(common_header_tvb, MESSAGE_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, MESSAGE_TYPE_OFFSET);
  message_length = tvb_get_ntohl (common_header_tvb, MESSAGE_LENGTH_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(message_class * 256 + message_type, sua_message_class_type_acro_values, "reserved"));
    col_append_str(pinfo->cinfo, COL_INFO, " ");
  };

  if (sua_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(sua_tree, hf_sua_version, 
                        common_header_tvb, VERSION_OFFSET, VERSION_LENGTH,
                        version);
    proto_tree_add_bytes(sua_tree, hf_sua_reserved,
			                   common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH,
                         tvb_get_ptr(common_header_tvb, RESERVED_OFFSET, RESERVED_LENGTH));
    proto_tree_add_uint(sua_tree, hf_sua_message_class, 
                        common_header_tvb, MESSAGE_CLASS_OFFSET, MESSAGE_CLASS_LENGTH,
                        message_class);
    proto_tree_add_uint_format(sua_tree, hf_sua_message_type, 
                               common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
                               message_type, "Message Type: %s (%u)",
			                         val_to_str(message_class * 256 + message_type, sua_message_class_type_values, "reserved"), message_type);
    proto_tree_add_uint(sua_tree, hf_sua_message_length,
                        common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH,
			                  message_length);
  };
}

#define DATA_PARAMETER_DATA_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, data_length, padding_length;
 
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  data_length    = length - PARAMETER_HEADER_LENGTH;
  padding_length = nr_of_padding_bytes(length);
  
  proto_tree_add_text(parameter_tree, parameter_tvb, DATA_PARAMETER_DATA_OFFSET, data_length,
		                  "Data (%u byte%s)", data_length, plurality(data_length, "", "s"));

  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_data_padding, 
                         parameter_tvb, PARAMETER_VALUE_OFFSET + data_length, padding_length,
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET + data_length, padding_length));

  proto_item_set_text(parameter_item, "Data (SS7 message of %u byte%s)",
		                  data_length, plurality(data_length, "", "s"));
}

#define INFO_PARAMETER_INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, info_string_length, padding_length;
  char *info_string;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
 
  info_string_length = length - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_sua_info_string,
			                parameter_tvb, INFO_PARAMETER_INFO_STRING_OFFSET, info_string_length, FALSE);

  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_info_string_padding, 
                         parameter_tvb, PARAMETER_VALUE_OFFSET + info_string_length, padding_length,
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET + info_string_length, padding_length));
                         
  info_string = (char *)tvb_get_ptr(parameter_tvb, INFO_PARAMETER_INFO_STRING_OFFSET, info_string_length);
  proto_item_set_text(parameter_item, "Info String (%.*s)", (int) info_string_length, info_string);
}

#define ROUTING_CONTEXT_LENGTH 4

static void
dissect_sua_routing_context_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, number_of_contexts, context_number;
  guint32 context;
  gint context_offset;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  number_of_contexts = (length - PARAMETER_HEADER_LENGTH) / 4;

  context_offset = PARAMETER_VALUE_OFFSET;
  for(context_number=1; context_number <= number_of_contexts; context_number++) {
    context = tvb_get_ntohl(parameter_tvb, context_offset);
    proto_tree_add_uint(parameter_tree, hf_sua_routing_context, parameter_tvb, context_offset, ROUTING_CONTEXT_LENGTH, context);
    context_offset += ROUTING_CONTEXT_LENGTH;
  };
  
  proto_item_set_text(parameter_item, "Routing context (%u context%s)",
		                  number_of_contexts, plurality(number_of_contexts, "", "s"));
}

static void
dissect_sua_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, info_length, padding_length;
  
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  info_length    = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_bytes(parameter_tree, hf_sua_diagnostic_information_info, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, info_length,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, info_length));
  
  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_diagnostic_information_padding, 
                         parameter_tvb, PARAMETER_VALUE_OFFSET + info_length, padding_length,
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET + info_length, padding_length));

  proto_item_set_text(parameter_item, "Diagnostic information (%u byte%s)", info_length, plurality(info_length, "", "s"));
}

static void
dissect_sua_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, data_length, padding_length;
  
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  data_length    = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_bytes(parameter_tree, hf_sua_heartbeat_data, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, data_length,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, data_length));
  
  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_heartbeat_padding, 
                         parameter_tvb, PARAMETER_VALUE_OFFSET + data_length, padding_length,
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET + data_length, padding_length));

  proto_item_set_text(parameter_item, "Heartbeat data (%u byte%s)", data_length, plurality(data_length, "", "s"));
}

#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define TRAFFIC_MODE_TYPE_LENGTH 4
        
#define OVER_RIDE_TYPE           1
#define LOAD_SHARE_TYPE          2
#define BROADCAST_TYPE           3

static const value_string sua_traffic_mode_type_values[] = {
  { OVER_RIDE_TYPE ,                             "Over-ride" },
  { LOAD_SHARE_TYPE,                             "Load-share" },
  { BROADCAST_TYPE,                              "Broadcast" },
  {0,                           NULL } };

static void
dissect_sua_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 traffic_mode_type;

  traffic_mode_type = tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_traffic_mode_type, 
                      parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH,
                      traffic_mode_type);
  
  proto_item_set_text(parameter_item, "Traffic mode type (%s)", val_to_str(traffic_mode_type, sua_traffic_mode_type_values, "unknown"));
}

#define ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET
#define ERROR_CODE_LENGTH 4

#define INVALID_VERSION_ERROR_CODE                   0x01
#define INVALID_INTERFACE_IDENTIFIER_ERROR_CODE      0x02
#define UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE         0x03
#define UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE          0x04
#define UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR_CODE 0x05
#define UNEXPECTED_MESSAGE_ERROR_CODE                0x06
#define PROTOCOL_ERROR_ERROR_CODE                    0x07
#define INVALID_STREAM_IDENTIFIER_ERROR_CODE         0x09
#define REFUSED_ERROR_CODE                           0x0d
#define ASP_IDENTIFIER_REQUIRED_ERROR_CODE           0x0e
#define INVALID_ASP_IDENTIFIER_ERROR_CODE            0x0f
#define INVALID_ROUTING_CONTEXT_ERROR_CODE           0x10
#define INVALID_PARAMETER_VALUE_ERROR_CODE           0x11
#define PARAMETER_FIELD_ERROR_CODE                   0x12
#define UNEXPECTED_PARAMETER_ERROR_CODE              0x13
#define DESTINATION_STATUS_UNKNOWN_ERROR_CODE        0x14
#define INVALID_NETWORK_APPEARANCE_ERROR_CODE        0x15
#define MISSING_PARAMETER_VALUE_ERROR_CODE           0x16
#define ROUTING_CONTEXT_CHANGE_REFUSED               0x17
#define INVALID_LOADSHARING_LABEL_ERROR_CODE         0x18

static const value_string sua_error_code_values[] = {
  { INVALID_VERSION_ERROR_CODE,                   "Invalid version" },
  { INVALID_INTERFACE_IDENTIFIER_ERROR_CODE,      "Ivalid Interface Identifier" },
  { UNSUPPORTED_MESSAGE_CLASS_ERROR_CODE,         "Unsupported message class" },
  { UNSUPPORTED_MESSAGE_TYPE_ERROR_CODE,          "Unsupported message type" },
  { UNSUPPORTED_TRAFFIC_HANDLING_MODE_ERROR_CODE, "Unsupported traffic handling mode" },
  { UNEXPECTED_MESSAGE_ERROR_CODE,                "Unexpected message" },
  { PROTOCOL_ERROR_ERROR_CODE,                    "Protocol error" },
  { INVALID_STREAM_IDENTIFIER_ERROR_CODE,         "Invalid Stream Identifier" },
  { REFUSED_ERROR_CODE,                           "Refused - Management Blocking" },
  { ASP_IDENTIFIER_REQUIRED_ERROR_CODE,           "ASP Identifier Required" },
  { INVALID_ASP_IDENTIFIER_ERROR_CODE,            "Invalid ASP Identifier" },
  { INVALID_ROUTING_CONTEXT_ERROR_CODE,           "Invalid Routing Context" },
  { INVALID_PARAMETER_VALUE_ERROR_CODE,           "Invalid Parameter Value" },
  { PARAMETER_FIELD_ERROR_CODE,                   "Parameter Field Error" },
  { UNEXPECTED_PARAMETER_ERROR_CODE,              "Unexpected Parameter" },
  { DESTINATION_STATUS_UNKNOWN_ERROR_CODE,        "Destination Status Unknown" },
  { INVALID_NETWORK_APPEARANCE_ERROR_CODE,        "Invalid Netwrok Appearance" },
  { MISSING_PARAMETER_VALUE_ERROR_CODE,           "Missing Parameter" },
  { ROUTING_CONTEXT_CHANGE_REFUSED,               "Routing Key Change Refused" },
  { INVALID_LOADSHARING_LABEL_ERROR_CODE,         "Invalid Loadsharing Label" },
  { 0,                                            NULL } };

static void
dissect_sua_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 error_code;

  error_code = tvb_get_ntohl(parameter_tvb, ERROR_CODE_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_sua_error_code, 
                      parameter_tvb, ERROR_CODE_OFFSET, ERROR_CODE_LENGTH,
                      error_code);
  proto_item_set_text(parameter_item, "Error code (%s)", val_to_str(error_code, sua_error_code_values, "unknown"));
}

#define STATUS_TYPE_LENGTH 2
#define STATUS_INFO_LENGTH 2
#define STATUS_TYPE_OFFSET PARAMETER_VALUE_OFFSET
#define STATUS_INFO_OFFSET (STATUS_TYPE_OFFSET + STATUS_TYPE_LENGTH)

#define AS_STATE_CHANGE_TYPE       1
#define OTHER_TYPE                 2

static const value_string sua_status_type_values[] = {
  { AS_STATE_CHANGE_TYPE,            "Application server state change" },
  { OTHER_TYPE,                      "Other" },
  { 0,                           NULL } };

#define RESERVED_INFO              1
#define AS_INACTIVE_INFO           2
#define AS_ACTIVE_INFO             3
#define AS_PENDING_INFO            4

#define INSUFFICIENT_ASP_RES_INFO  1
#define ALTERNATE_ASP_ACTIVE_INFO  2
#define ASP_FAILURE                3

static const value_string sua_status_type_info_values[] = {
  { AS_STATE_CHANGE_TYPE * 256 * 256 + RESERVED_INFO,             "Reserved" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_INACTIVE_INFO,          "Application server inactive" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_ACTIVE_INFO,            "Application server active" },
  { AS_STATE_CHANGE_TYPE * 256 * 256 + AS_PENDING_INFO,           "Application server pending" },
  { OTHER_TYPE           * 256 * 256 + INSUFFICIENT_ASP_RES_INFO, "Insufficient ASP resources active in AS" },
  { OTHER_TYPE           * 256 * 256 + ALTERNATE_ASP_ACTIVE_INFO, "Alternate ASP active" },
  { OTHER_TYPE           * 256 * 256 + ASP_FAILURE,               "ASP Failure" },
  {0,                           NULL } };

static void
dissect_sua_status_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_info;

  status_type = tvb_get_ntohs(parameter_tvb, STATUS_TYPE_OFFSET);
  status_info = tvb_get_ntohs(parameter_tvb, STATUS_INFO_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_status_type, 
                      parameter_tvb, STATUS_TYPE_OFFSET, STATUS_TYPE_LENGTH,
                      status_type);
  proto_tree_add_uint_format(parameter_tree, hf_sua_status_info, 
			                       parameter_tvb, STATUS_INFO_OFFSET, STATUS_INFO_LENGTH,
			                       status_info, "Status info: %s (%u)",
			                       val_to_str(status_type * 256 * 256 + status_info, sua_status_type_info_values, "unknown"), status_info);

  proto_item_set_text(parameter_item, "Status type / ID (%s)",
		      val_to_str(status_type * 256 * 256 + status_info, sua_status_type_info_values, "unknown status information"));
}

#define CONGESTION_LEVEL_LENGTH 4
#define CONGESTION_LEVEL_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_congestion_level_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 congestion_level;

  congestion_level = tvb_get_ntohl(parameter_tvb, CONGESTION_LEVEL_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_congestion_level, 
                      parameter_tvb, CONGESTION_LEVEL_OFFSET, CONGESTION_LEVEL_LENGTH,
                      congestion_level);
    
  proto_item_set_text(parameter_item, "Congestion Level: %u", congestion_level);

}

#define ASP_IDENTIFIER_LENGTH 4
#define ASP_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 asp_identifier;

  asp_identifier = tvb_get_ntohl(parameter_tvb, ASP_IDENTIFIER_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_asp_identifier, 
                      parameter_tvb, ASP_IDENTIFIER_OFFSET, ASP_IDENTIFIER_LENGTH,
                      asp_identifier);
    
  proto_item_set_text(parameter_item, "ASP Identifer: %u", asp_identifier);
}

#define AFFECTED_MASK_LENGTH 1
#define AFFECTED_DPC_LENGTH  3
#define AFFECTED_DESTINATION_LENGTH (AFFECTED_MASK_LENGTH + AFFECTED_DPC_LENGTH)

#define AFFECTED_MASK_OFFSET 0
#define AFFECTED_DPC_OFFSET  1

static void
dissect_sua_affected_destinations_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
    destination_item = proto_tree_add_text(parameter_tree, parameter_tvb, destination_offset, AFFECTED_DESTINATION_LENGTH, "Affected destination");
    destination_tree = proto_item_add_subtree(destination_item, ett_sua_affected_destination);

    proto_tree_add_uint(destination_tree, hf_sua_mask, 
			                  parameter_tvb, destination_offset + AFFECTED_MASK_OFFSET, AFFECTED_MASK_LENGTH,
			                  mask);
    proto_tree_add_uint(destination_tree, hf_sua_dpc, 
			                  parameter_tvb, destination_offset + AFFECTED_DPC_OFFSET, AFFECTED_DPC_LENGTH,
			                  dpc);
    destination_offset += AFFECTED_DESTINATION_LENGTH;
  };
  proto_item_set_text(parameter_item, "Affected destination (%u destination%s)",
		                  number_of_destinations, plurality(number_of_destinations, "", "s"));

}

#define SS7_HOP_COUNTER_LENGTH 1
#define SS7_HOP_COUNTER_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_sua_ss7_hop_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 hop_counter;
 
  hop_counter = tvb_get_guint8(parameter_tvb,  SS7_HOP_COUNTER_OFFSET);
    
  proto_tree_add_bytes(parameter_tree, hf_sua_ss7_hop_counter_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));
                       
  proto_tree_add_uint(parameter_tree, hf_sua_ss7_hop_counter_counter, 
                      parameter_tvb, SS7_HOP_COUNTER_OFFSET, SS7_HOP_COUNTER_LENGTH,
                      hop_counter);
  
  proto_item_set_text(parameter_item, "SS7 Hop Counter (%u)", hop_counter);
}

#define ROUTING_INDICATOR_LENGTH  2
#define ADDRESS_INDICATOR_LENGTH  2

#define ROUTING_INDICATOR_OFFSET  PARAMETER_VALUE_OFFSET
#define ADDRESS_INDICATOR_OFFSET  (ROUTING_INDICATOR_OFFSET + ROUTING_INDICATOR_LENGTH)
#define ADDRESS_PARAMETERS_OFFSET (ADDRESS_INDICATOR_OFFSET + ADDRESS_INDICATOR_LENGTH)

#define RESERVED_ROUTING_INDICATOR              0
#define ROUTE_ON_GT_ROUTING_INDICATOR           1
#define ROUTE_ON_SSN_PC_ROUTING_INDICATOR       2
#define ROUTE_ON_HOSTNAMEROUTING_INDICATOR      3
#define ROUTE_ON_SSN_IP_ROUTING_INDICATOR       4

static const value_string sua_routing_indicator_values[] = {
  { RESERVED_ROUTING_INDICATOR,            "Reserved" },
  { ROUTE_ON_GT_ROUTING_INDICATOR,         "Route on Global Title" },
  { ROUTE_ON_SSN_PC_ROUTING_INDICATOR,     "Route on SSN + PC" },
  { ROUTE_ON_HOSTNAMEROUTING_INDICATOR,    "Route on Hostname" },
  { ROUTE_ON_SSN_IP_ROUTING_INDICATOR,     "Route on SSN + IP Address" },
  { 0,                                     NULL } };

#define ADDRESS_RESERVED_BITMASK 0xfff8
#define ADDRESS_GT_BITMASK       0x0004
#define ADDRESS_PC_BITMASK       0x0002
#define ADDRESS_SSN_BITMASK      0x0001

static void
dissect_sua_source_address_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 routing_indicator, address_indicator;
  proto_item *address_indicator_item;
  proto_tree *address_indicator_tree;
  
  routing_indicator = tvb_get_ntohs(parameter_tvb, ROUTING_INDICATOR_OFFSET);
  address_indicator = tvb_get_ntohs(parameter_tvb, ADDRESS_INDICATOR_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_source_address_routing_indicator, 
                      parameter_tvb, ROUTING_INDICATOR_OFFSET, ROUTING_INDICATOR_LENGTH,
                      routing_indicator);
  
  address_indicator_item = proto_tree_add_text(parameter_tree, parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, "Address Indicator");
  address_indicator_tree = proto_item_add_subtree(address_indicator_item, ett_sua_source_address_indicator);
  proto_tree_add_uint(address_indicator_tree, hf_sua_source_address_reserved_bits, 
                      parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH,
                      address_indicator);
  proto_tree_add_boolean(address_indicator_tree, hf_sua_source_address_gt_bit, parameter_tvb,
			                   ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, address_indicator);
  proto_tree_add_boolean(address_indicator_tree, hf_sua_source_address_pc_bit, parameter_tvb,
			                   ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, address_indicator);
  proto_tree_add_boolean(address_indicator_tree, hf_sua_source_address_ssn_bit, parameter_tvb,
			                   ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, address_indicator);

  proto_item_set_text(parameter_item, "Source Address");
  
  /* dissect address parameters */
  dissect_sua_tlv_list(parameter_tvb, parameter_tree, ADDRESS_PARAMETERS_OFFSET);
}

static void
dissect_sua_destination_address_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 routing_indicator, address_indicator;
  proto_item *address_indicator_item;
  proto_tree *address_indicator_tree;
  
  routing_indicator = tvb_get_ntohs(parameter_tvb, ROUTING_INDICATOR_OFFSET);
  address_indicator = tvb_get_ntohs(parameter_tvb, ADDRESS_INDICATOR_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_destination_address_routing_indicator, 
                      parameter_tvb, ROUTING_INDICATOR_OFFSET, ROUTING_INDICATOR_LENGTH,
                      routing_indicator);
  
  address_indicator_item = proto_tree_add_text(parameter_tree, parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, "Address Indicator");
  address_indicator_tree = proto_item_add_subtree(address_indicator_item, ett_sua_destination_address_indicator);
  proto_tree_add_uint(address_indicator_tree, hf_sua_destination_address_reserved_bits, 
                      parameter_tvb, ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH,
                      address_indicator);
  proto_tree_add_boolean(address_indicator_tree, hf_sua_destination_address_gt_bit, parameter_tvb,
			                   ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, address_indicator);
  proto_tree_add_boolean(address_indicator_tree, hf_sua_destination_address_pc_bit, parameter_tvb,
			                   ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, address_indicator);
  proto_tree_add_boolean(address_indicator_tree, hf_sua_destination_address_ssn_bit, parameter_tvb,
			                   ADDRESS_INDICATOR_OFFSET, ADDRESS_INDICATOR_LENGTH, address_indicator);

  proto_item_set_text(parameter_item, "Destination Address");
  
  /* dissect address parameters */
  dissect_sua_tlv_list(parameter_tvb, parameter_tree, ADDRESS_PARAMETERS_OFFSET);
}

#define SOURCE_REFERENCE_NUMBER_LENGTH 4
#define SOURCE_REFERENCE_NUMBER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_source_reference_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reference;

  reference = tvb_get_ntohl(parameter_tvb, SOURCE_REFERENCE_NUMBER_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_source_reference_number, 
                      parameter_tvb, SOURCE_REFERENCE_NUMBER_OFFSET, SOURCE_REFERENCE_NUMBER_LENGTH,
                      reference);
    
  proto_item_set_text(parameter_item, "Source Reference Number: %u", reference);
}

#define DESTINATION_REFERENCE_NUMBER_LENGTH 4
#define DESTINATION_REFERENCE_NUMBER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_destination_reference_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 reference;

  reference = tvb_get_ntohl(parameter_tvb, DESTINATION_REFERENCE_NUMBER_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_destination_reference_number, 
                      parameter_tvb, DESTINATION_REFERENCE_NUMBER_OFFSET, DESTINATION_REFERENCE_NUMBER_LENGTH,
                      reference);
    
  proto_item_set_text(parameter_item, "Destination Reference Number: %u", reference);
}

#define CAUSE_TYPE_LENGTH 1
#define CAUSE_VALUE_LENGTH 1

#define CAUSE_TYPE_OFFSET  (PARAMETER_VALUE_OFFSET + RESERVED_2_LENGTH)
#define CAUSE_VALUE_OFFSET (CAUSE_TYPE_OFFSET + CAUSE_TYPE_LENGTH)

#define RETURN_CAUSE_TYPE    0x1
#define REFUSAL_CAUSE_TYPE   0x2
#define RELEASE_CAUSE_TYPE   0x3
#define RESET_CAUSE_TYPE     0x4
#define ERROR_CAUSE_TYPE     0x5

static const value_string sua_cause_type_values[] = {
  { RETURN_CAUSE_TYPE,    "Return Cause" },
  { REFUSAL_CAUSE_TYPE,   "Refusual Cause" },
  { RELEASE_CAUSE_TYPE,   "Release Cause" },
  { RESET_CAUSE_TYPE,     "Reset Cause" },
  { ERROR_CAUSE_TYPE,     "Error cause" },
  { 0,                    NULL } };

static void
dissect_sua_sccp_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 type, value;
 
  type  = tvb_get_guint8(parameter_tvb,  CAUSE_TYPE_OFFSET);
  value = tvb_get_guint8(parameter_tvb,  CAUSE_VALUE_OFFSET);
    
  proto_tree_add_bytes(parameter_tree, hf_sua_cause_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH));
  proto_tree_add_uint(parameter_tree, hf_sua_cause_type, 
                      parameter_tvb, CAUSE_TYPE_OFFSET, CAUSE_TYPE_LENGTH,
                      type);
  proto_tree_add_uint(parameter_tree, hf_sua_cause_value, 
                      parameter_tvb, CAUSE_VALUE_OFFSET, CAUSE_VALUE_LENGTH,
                      value);
  
  proto_item_set_text(parameter_item, "SCCP Cause (%s)", val_to_str(type, sua_cause_type_values, "unknown"));
}

#define SEQUENCE_NUMBER_REC_SEQ_LENGTH  1
#define SEQUENCE_NUMBER_SENT_SEQ_LENGTH 1
#define SEQUENCE_NUMBER_REC_SEQ_OFFSET  (PARAMETER_VALUE_OFFSET + RESERVED_2_LENGTH)
#define SEQUENCE_NUMBER_SENT_SEQ_OFFSET (SEQUENCE_NUMBER_REC_SEQ_OFFSET + SEQUENCE_NUMBER_REC_SEQ_LENGTH)

#define SEQ_NUM_MASK       0xFE
#define SPARE_BIT_MASK     0x01
#define MORE_DATA_BIT_MASK 0x01

static const true_false_string sua_more_data_bit_value = {
  "More Data",
  "Not More Data"
};

static void
dissect_sua_sequence_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  receive_sequence_number, sent_sequence_number;
  proto_item *sent_sequence_number_item;
  proto_tree *sent_sequence_number_tree;
  proto_item *receive_sequence_number_item;
  proto_tree *receive_sequence_number_tree;
  
  receive_sequence_number = tvb_get_guint8(parameter_tvb, SEQUENCE_NUMBER_REC_SEQ_OFFSET);
  sent_sequence_number    = tvb_get_guint8(parameter_tvb, SEQUENCE_NUMBER_SENT_SEQ_OFFSET);

  proto_tree_add_bytes(parameter_tree, hf_sua_sequence_number_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH));
                       
  receive_sequence_number_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                                     SEQUENCE_NUMBER_REC_SEQ_OFFSET,
                                                     SEQUENCE_NUMBER_REC_SEQ_LENGTH, "Receive Sequence Number");
  receive_sequence_number_tree = proto_item_add_subtree(receive_sequence_number_item, ett_sua_sequence_number_rec_number);
  proto_tree_add_uint(receive_sequence_number_tree, hf_sua_sequence_number_rec_number, 
                      parameter_tvb, SEQUENCE_NUMBER_REC_SEQ_OFFSET, SEQUENCE_NUMBER_REC_SEQ_LENGTH,
                      receive_sequence_number);
  proto_tree_add_boolean(receive_sequence_number_tree, hf_sua_sequence_number_more_data_bit,
                         parameter_tvb, SEQUENCE_NUMBER_REC_SEQ_OFFSET, SEQUENCE_NUMBER_REC_SEQ_LENGTH, 
                         receive_sequence_number);
  
  sent_sequence_number_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                                     SEQUENCE_NUMBER_SENT_SEQ_OFFSET,
                                                     SEQUENCE_NUMBER_SENT_SEQ_LENGTH, "Sent Sequence Number");
  sent_sequence_number_tree = proto_item_add_subtree(sent_sequence_number_item, ett_sua_sequence_number_sent_number);
  proto_tree_add_uint(sent_sequence_number_tree, hf_sua_sequence_number_sent_number, 
                      parameter_tvb, SEQUENCE_NUMBER_SENT_SEQ_OFFSET, SEQUENCE_NUMBER_SENT_SEQ_LENGTH,
                      sent_sequence_number);
  proto_tree_add_boolean(sent_sequence_number_tree, hf_sua_sequence_number_spare_bit,
                         parameter_tvb, SEQUENCE_NUMBER_SENT_SEQ_OFFSET, SEQUENCE_NUMBER_SENT_SEQ_LENGTH, 
                         sent_sequence_number);

  proto_item_set_text(parameter_item, "Sequence Number");
}

#define RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH 1
#define RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_sua_receive_sequence_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  receive_sequence_number;
  proto_item *receive_sequence_number_item;
  proto_tree *receive_sequence_number_tree;
  
  receive_sequence_number = tvb_get_guint8(parameter_tvb, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET);
  
  proto_tree_add_bytes(parameter_tree, hf_sua_receive_sequence_number_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));
  receive_sequence_number_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                                     RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET,
                                                     RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH, "Receive Sequence Number");
  receive_sequence_number_tree = proto_item_add_subtree(receive_sequence_number_item, ett_sua_receive_sequence_number_number);
  proto_tree_add_uint(receive_sequence_number_tree, hf_sua_receive_sequence_number_number, 
                      parameter_tvb, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH,
                      receive_sequence_number);
  proto_tree_add_boolean(receive_sequence_number_tree, hf_sua_receive_sequence_number_spare_bit,
                         parameter_tvb, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_OFFSET, RECEIVE_SEQUENCE_NUMBER_REC_SEQ_LENGTH, 
                         receive_sequence_number);

  proto_item_set_text(parameter_item, "Receive Sequence Number");
}

#define PROTOCOL_CLASSES_LENGTH        1
#define INTERWORKING_LENGTH            1
#define PROTOCOL_CLASSES_OFFSET        (PARAMETER_VALUE_OFFSET + RESERVED_2_LENGTH)
#define INTERWORKING_OFFSET            (PROTOCOL_CLASSES_OFFSET + PROTOCOL_CLASSES_LENGTH)

#define A_BIT_MASK 0x08
#define B_BIT_MASK 0x04
#define C_BIT_MASK 0x02
#define D_BIT_MASK 0x01
#define RESERVED_BITS_MASK 0xF0

static const true_false_string sua_supported_bit_value = {
  "Supported",
  "Unsupported"
};

#define NO_INTERWORKING      0x0
#define ASP_SS7_INTERWORKING 0x1
#define SG_INTERWORKING      0x2
#define RELAY_INTERWORKING   0x3

static const value_string sua_interworking_values[] = {
  { NO_INTERWORKING,        "No Interworking with SS7 Networks" },
  { ASP_SS7_INTERWORKING,   "IP-Signalling Endpoint interworking with with SS7 networks" },
  { SG_INTERWORKING,        "Signalling Gateway" },
  { RELAY_INTERWORKING,     "Relay Node Support" },
  { 0,                      NULL } };

static void
dissect_sua_asp_capabilities_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  protocol_classes, interworking;
  proto_item *protocol_classes_item;
  proto_tree *protocol_classes_tree;
  
  protocol_classes = tvb_get_guint8(parameter_tvb, PROTOCOL_CLASSES_OFFSET);
  interworking     = tvb_get_guint8(parameter_tvb, INTERWORKING_OFFSET);
  
  proto_tree_add_bytes(parameter_tree, hf_sua_asp_capabilities_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_2_LENGTH));
  protocol_classes_item = proto_tree_add_text(parameter_tree, parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, "Protocol classes");
  protocol_classes_tree = proto_item_add_subtree(protocol_classes_item, ett_sua_protcol_classes);
  proto_tree_add_uint(protocol_classes_tree, hf_sua_asp_capabilities_reserved_bits, 
                      parameter_tvb, PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH,
                      protocol_classes);
  proto_tree_add_boolean(protocol_classes_tree, hf_sua_asp_capabilities_a_bit, parameter_tvb,
			                   PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, protocol_classes);
  proto_tree_add_boolean(protocol_classes_tree, hf_sua_asp_capabilities_b_bit, parameter_tvb,
			                   PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, protocol_classes);
  proto_tree_add_boolean(protocol_classes_tree, hf_sua_asp_capabilities_c_bit, parameter_tvb,
			                   PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, protocol_classes);
  proto_tree_add_boolean(protocol_classes_tree, hf_sua_asp_capabilities_d_bit, parameter_tvb,
			                   PROTOCOL_CLASSES_OFFSET, PROTOCOL_CLASSES_LENGTH, protocol_classes);

  proto_tree_add_uint(parameter_tree, hf_sua_asp_capabilities_interworking, 
                      parameter_tvb, INTERWORKING_OFFSET, INTERWORKING_LENGTH,
                      interworking);
  
  proto_item_set_text(parameter_item, "ASP Capabilities");
}

#define CREDIT_LENGTH 4
#define CREDIT_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_credit_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 credit;

  credit = tvb_get_ntohl(parameter_tvb, CREDIT_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_credit, 
                      parameter_tvb, CREDIT_OFFSET, CREDIT_LENGTH,
                      credit);
    
  proto_item_set_text(parameter_item, "Credit: %u", credit);
}

#define CAUSE_LENGTH 2
#define USER_LENGTH  2
#define CAUSE_OFFSET PARAMETER_VALUE_OFFSET
#define USER_OFFSET (CAUSE_OFFSET + CAUSE_LENGTH)

#define UNAVAILABLE_CAUSE    0x0
#define UNEQUIPPED_CAUSE     0x2
#define INACCESSABLE_CAUSE   0x3

static const value_string sua_cause_values[] = {
  { UNAVAILABLE_CAUSE,    "Remote SCCP unavailable, Reason unknown" },
  { UNEQUIPPED_CAUSE,     "Remote SCCP unequipped" },
  { INACCESSABLE_CAUSE,   "Remote SCCP inaccessable" },
  { 0,                    NULL } };

static void
dissect_sua_user_cause_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 cause, user;

  cause = tvb_get_ntohs(parameter_tvb, CAUSE_OFFSET);
  user  = tvb_get_ntohs(parameter_tvb, USER_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_cause, 
                      parameter_tvb, CAUSE_OFFSET, CAUSE_LENGTH,
                      cause);
  proto_tree_add_uint(parameter_tree, hf_sua_user, 
                      parameter_tvb, USER_OFFSET, USER_LENGTH,
                      user);
   
  proto_item_set_text(parameter_item, "User / Cause");
}

#define NETWORK_APPEARANCE_LENGTH 4
#define NETWORK_APPEARANCE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_network_appearance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 appearance;

  appearance = tvb_get_ntohl(parameter_tvb, NETWORK_APPEARANCE_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_network_appearance, 
                      parameter_tvb, NETWORK_APPEARANCE_OFFSET, NETWORK_APPEARANCE_LENGTH,
                      appearance);
    
  proto_item_set_text(parameter_item, "Network Appearance: %u", appearance);
}

#define IDENTIFIER_LENGTH      4
#define IDENTIFIER_OFFSET      PARAMETER_VALUE_OFFSET
#define KEY_PARAMETERS_OFFSET  (IDENTIFIER_OFFSET + IDENTIFIER_LENGTH)

static void
dissect_sua_routing_key_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 identifier;
  
  identifier = tvb_get_ntohl(parameter_tvb, IDENTIFIER_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_routing_key_identifier, 
                      parameter_tvb, IDENTIFIER_OFFSET, IDENTIFIER_LENGTH,
                      identifier);
  
  proto_item_set_text(parameter_item, "Routing Key");
  
  dissect_sua_tlv_list(parameter_tvb, parameter_tree, KEY_PARAMETERS_OFFSET);
}

#define LOCAL_ROUTING_KEY_ID_LENGTH         4
#define REGISTRATION_STATUS_LENGTH          4
#define REGISTRATION_ROUTING_CONTEXT_LENGTH 4
#define LOCAL_ROUTING_KEY_OFFSET            PARAMETER_VALUE_OFFSET
#define REGISTRATION_STATUS_OFFSET          (LOCAL_ROUTING_KEY_OFFSET + LOCAL_ROUTING_KEY_ID_LENGTH)
#define REGISTRATION_ROUTING_CONTEXT_OFFSET (REGISTRATION_STATUS_OFFSET + REGISTRATION_STATUS_LENGTH)

#define SUCCESSFULLY_REGISTERED_REGISTRATION_STATUS               0x0
#define UNKNOWN_REGISTRATION_STATUS                               0x1
#define INVALID_DESTINATION_ADDRESSS_REGISTRATION_STATUS          0x2
#define INVALID_NETWORK_APPEARANCE_REGISTRATION_STATUS            0x3
#define INVALID_ROUTING_KEY_REGISTRATION_STATUS                   0x4
#define PERMISSION_DENIED_REGISTRATION_STATUS                     0x5
#define CANNOT_SUPPORT_UNIQUE_ROUTING_REGISTRATION_STATUS         0x6
#define ROUTING_KEY_NOT_PROVISIONED_REGISTRATION_STATUS           0x7
#define INSUFFICIENT_RESOURCES_REGISTRATION_STATUS                0x8
#define UNSUPPORTED_RK_PARAMETER_REGISTRATION_FIELD_STATUS        0x9
#define UNSUPPORTED_INVALID_TRAFFIC_MODE_TYPE_REGISTRATION_STATUS 0xa

static const value_string sua_registration_status_values[] = {
  { SUCCESSFULLY_REGISTERED_REGISTRATION_STATUS,               "Successfully Registered" },
  { UNKNOWN_REGISTRATION_STATUS,                               "Error - Unknown" },
  { INVALID_DESTINATION_ADDRESSS_REGISTRATION_STATUS,          "Error - Invalid Destination Address" },
  { INVALID_NETWORK_APPEARANCE_REGISTRATION_STATUS,            "Error - Invalid Network Appearance" },
  { INVALID_ROUTING_KEY_REGISTRATION_STATUS,                   "Error - Invalid Routing Key" },
  { PERMISSION_DENIED_REGISTRATION_STATUS,                     "Error - Permission Denied" },
  { CANNOT_SUPPORT_UNIQUE_ROUTING_REGISTRATION_STATUS,         "Error - Cannot Support Unique Routing" },
  { ROUTING_KEY_NOT_PROVISIONED_REGISTRATION_STATUS,           "Error - Routing Key Not Currently Provisioned" },
  { INSUFFICIENT_RESOURCES_REGISTRATION_STATUS,                "Error - Insufficient Resources" },
  { UNSUPPORTED_RK_PARAMETER_REGISTRATION_FIELD_STATUS,        "Error - Unsupported Routing Key Parameter Field" },
  { UNSUPPORTED_INVALID_TRAFFIC_MODE_TYPE_REGISTRATION_STATUS, "Error - Unsupported / Invalid Traffic Mode Type" },
  { 0,                                            NULL } };

static void
dissect_sua_registration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 local_routing_key_identifier, registration_status, routing_context;

  local_routing_key_identifier = tvb_get_ntohl(parameter_tvb, LOCAL_ROUTING_KEY_OFFSET);
  registration_status = tvb_get_ntohl(parameter_tvb, REGISTRATION_STATUS_OFFSET);
  routing_context = tvb_get_ntohl(parameter_tvb, REGISTRATION_ROUTING_CONTEXT_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_registration_result_routing_key_identifier, 
                      parameter_tvb, LOCAL_ROUTING_KEY_OFFSET, LOCAL_ROUTING_KEY_ID_LENGTH,
                      local_routing_key_identifier);
  proto_tree_add_uint(parameter_tree, hf_sua_registration_result_status, 
                      parameter_tvb, REGISTRATION_STATUS_OFFSET, REGISTRATION_STATUS_LENGTH,
                      registration_status);
  proto_tree_add_uint(parameter_tree, hf_sua_registration_result_routing_context, 
                      parameter_tvb, REGISTRATION_ROUTING_CONTEXT_OFFSET, REGISTRATION_ROUTING_CONTEXT_LENGTH,
                      routing_context);
   
  proto_item_set_text(parameter_item, "Registration Result: %s", val_to_str(registration_status, sua_registration_status_values, "Unknown"));
}

#define DEREGISTRATION_ROUTING_CONTEXT_LENGTH 4
#define DEREGISTRATION_STATUS_LENGTH          4

#define DEREGISTRATION_ROUTING_CONTEXT_OFFSET PARAMETER_VALUE_OFFSET
#define DEREGISTRATION_STATUS_OFFSET          (DEREGISTRATION_ROUTING_CONTEXT_OFFSET + DEREGISTRATION_ROUTING_CONTEXT_LENGTH)

#define SUCCESSFULLY_DEREGISTERED_DEREGISTRATION_STATUS                0x0
#define UNKNOWN_DEREGISTRATION_STATUS                                  0x1
#define INVALID_ROUTING_CONTEXT_DEREGISTRATION_STATUS                  0x2
#define PERMISSION_DENIED_DEREGISTRATION_STATUS                        0x3
#define NOT_REGISTERED_DEREGISTRATION_STATUS                           0x4
#define ASP_CURRENTLY_ACTIVE_FOR_ROUTING_CONTEXT_DEREGISTRATION_STATUS 0x5

static const value_string sua_deregistration_status_values[] = {
  { SUCCESSFULLY_DEREGISTERED_DEREGISTRATION_STATUS,                "Successfully Deregistered" },
  { UNKNOWN_DEREGISTRATION_STATUS,                                  "Error - Unknown" },
  { INVALID_ROUTING_CONTEXT_DEREGISTRATION_STATUS,                  "Error - Invalid Routing Context" },
  { PERMISSION_DENIED_DEREGISTRATION_STATUS,                        "Error - Permission Denied" },
  { NOT_REGISTERED_DEREGISTRATION_STATUS,                           "Error - Not Registered" },
  { ASP_CURRENTLY_ACTIVE_FOR_ROUTING_CONTEXT_DEREGISTRATION_STATUS, "Error - ASP Currently Active for Routing Context" },
  { 0,                                                              NULL } };

static void
dissect_sua_deregistration_result_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 routing_context, deregistration_status;

  routing_context       = tvb_get_ntohl(parameter_tvb, DEREGISTRATION_ROUTING_CONTEXT_OFFSET);
  deregistration_status = tvb_get_ntohl(parameter_tvb, DEREGISTRATION_STATUS_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_deregistration_result_routing_context, 
                      parameter_tvb, DEREGISTRATION_ROUTING_CONTEXT_OFFSET, DEREGISTRATION_ROUTING_CONTEXT_LENGTH,
                      routing_context);
  proto_tree_add_uint(parameter_tree, hf_sua_deregistration_result_status, 
                      parameter_tvb, REGISTRATION_STATUS_OFFSET, REGISTRATION_STATUS_LENGTH,
                      deregistration_status);
   
  proto_item_set_text(parameter_item, "Deregistration Result: %s", val_to_str(deregistration_status, sua_deregistration_status_values, "Unknown"));
}

#define ADDRESS_RANGE_ADDRESS_PARAMETERS_OFFSET  PARAMETER_VALUE_OFFSET

static void
dissect_sua_address_range_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item_set_text(parameter_item, "Address Range");
  
  dissect_sua_tlv_list(parameter_tvb, parameter_tree, ADDRESS_RANGE_ADDRESS_PARAMETERS_OFFSET);
}

#define CORRELATION_ID_LENGTH 4
#define CORRELATION_ID_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_correlation_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 correlation_id;

  correlation_id = tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_correlation_id, 
                      parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH,
                      correlation_id);
    
  proto_item_set_text(parameter_item, "Correlation ID: %u", correlation_id);
}

#define IMPORTANCE_LENGTH 1
#define IMPORTANCE_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_sua_importance_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 importance;
 
  importance = tvb_get_guint8(parameter_tvb,  IMPORTANCE_OFFSET);
    
  proto_tree_add_bytes(parameter_tree, hf_sua_importance_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));
  proto_tree_add_uint(parameter_tree, hf_sua_importance, 
                      parameter_tvb, IMPORTANCE_OFFSET, IMPORTANCE_LENGTH,
                      importance);
  
  proto_item_set_text(parameter_item, "Importance (%u)", importance);
}

#define MESSAGE_PRIORITY_LENGTH 1
#define MESSAGE_PRIORITY_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_sua_message_priority_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 priority;
 
  priority = tvb_get_guint8(parameter_tvb,  MESSAGE_PRIORITY_OFFSET);
  proto_tree_add_bytes(parameter_tree, hf_sua_message_priority_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));
  
  proto_tree_add_uint(parameter_tree, hf_sua_message_priority, 
                      parameter_tvb, MESSAGE_PRIORITY_OFFSET, MESSAGE_PRIORITY_LENGTH,
                      priority);
  
  proto_item_set_text(parameter_item, "Message Priority (%u)", priority);
}

#define PROTOCOL_CLASS_LENGTH         1
#define PROTOCOL_CLASS_OFFSET         (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

#define RETURN_ON_ERROR_BIT_MASK 0x80
#define PROTOCOL_CLASS_MASK      0x7f


static const true_false_string sua_return_on_error_bit_value = {
  "Return Message On Error",
  "No Special Options"
};

static void
dissect_sua_protocol_class_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  protocol_class;
  proto_item *protocol_class_item;
  proto_tree *protocol_class_tree;
  
  protocol_class = tvb_get_guint8(parameter_tvb, PROTOCOL_CLASS_OFFSET);
  
  proto_tree_add_bytes(parameter_tree, hf_sua_protocol_class_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));

  protocol_class_item = proto_tree_add_text(parameter_tree, parameter_tvb, PROTOCOL_CLASS_OFFSET, PROTOCOL_CLASS_LENGTH,
                                            "Protocol Class");
  protocol_class_tree = proto_item_add_subtree(protocol_class_item, ett_sua_return_on_error_bit_and_protocol_class);
 
  proto_tree_add_boolean(protocol_class_tree, hf_sua_return_on_error_bit, parameter_tvb,
			                   PROTOCOL_CLASS_OFFSET, PROTOCOL_CLASS_LENGTH, protocol_class);
  proto_tree_add_uint(protocol_class_tree, hf_sua_protocol_class, 
                      parameter_tvb, PROTOCOL_CLASS_OFFSET, PROTOCOL_CLASS_LENGTH,
                      protocol_class); 
   
  proto_item_set_text(parameter_item, "Protocol Class");
}

#define SEQUENCE_CONTROL_LENGTH 4
#define SEQUENCE_CONTROL_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_sequence_control_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 sequence_control;

  sequence_control = tvb_get_ntohl(parameter_tvb, SEQUENCE_CONTROL_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_sequence_control, 
                      parameter_tvb, SEQUENCE_CONTROL_OFFSET, SEQUENCE_CONTROL_LENGTH,
                      sequence_control);
    
  proto_item_set_text(parameter_item, "Sequence Control: %u", sequence_control);
}

#define FIRST_REMAINING_LENGTH        1
#define SEGMENTATION_REFERENCE_LENGTH 3
#define FIRST_REMAINING_OFFSET        PARAMETER_VALUE_OFFSET
#define SEGMENTATION_REFERENCE_OFFSET (FIRST_REMAINING_OFFSET + FIRST_REMAINING_LENGTH)

#define FIRST_BIT_MASK 0x80
#define NUMBER_OF_SEGMENTS_MASK 0x7f

static const true_false_string sua_first_bit_value = {
  "First segment",
  "Subsequent segment"
};

static void
dissect_sua_segmentation_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  first_remaining;
  guint32 segmentation_reference;
  proto_item *first_remaining_item;
  proto_tree *first_remaining_tree;
  
  first_remaining        = tvb_get_guint8(parameter_tvb, FIRST_REMAINING_OFFSET);
  segmentation_reference = tvb_get_ntoh24(parameter_tvb, SEGMENTATION_REFERENCE_OFFSET);
  
  first_remaining_item = proto_tree_add_text(parameter_tree, parameter_tvb, FIRST_REMAINING_OFFSET, FIRST_REMAINING_LENGTH,
				                                     "First / Remaining");
  first_remaining_tree = proto_item_add_subtree(first_remaining_item, ett_sua_first_remaining);
  proto_tree_add_boolean(first_remaining_tree, hf_sua_first_bit, parameter_tvb,
			                   FIRST_REMAINING_OFFSET, FIRST_REMAINING_LENGTH, first_remaining);
  proto_tree_add_uint(first_remaining_tree, hf_sua_number_of_remaining_segments, 
                      parameter_tvb, FIRST_REMAINING_OFFSET, FIRST_REMAINING_LENGTH,
                      first_remaining);

  proto_tree_add_uint(parameter_tree, hf_sua_segmentation_reference, 
                      parameter_tvb, SEGMENTATION_REFERENCE_OFFSET, SEGMENTATION_REFERENCE_LENGTH,
                      segmentation_reference);
  
  proto_item_set_text(parameter_item, "Segmentation");
}

#define SMI_LENGTH 1
#define SMI_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_sua_smi_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 smi;
 
  smi = tvb_get_guint8(parameter_tvb,  SMI_OFFSET);
    
  proto_tree_add_bytes(parameter_tree, hf_sua_smi_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));
  proto_tree_add_uint(parameter_tree, hf_sua_smi, 
                      parameter_tvb, SMI_OFFSET, SMI_LENGTH,
                      smi);
  
  proto_item_set_text(parameter_item, "SMI (%u)", smi);
}

#define TID_START_LENGTH 1
#define TID_END_LENGTH 1
#define TID_VALUE_LENGTH 2

#define TID_START_OFFSET PARAMETER_VALUE_OFFSET
#define TID_END_OFFSET   (TID_START_OFFSET + TID_START_LENGTH)
#define TID_VALUE_OFFSET (TID_END_OFFSET + TID_END_LENGTH)

static void
dissect_sua_tid_label_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  start, end;
  guint16 value;
  
  start = tvb_get_guint8(parameter_tvb,  TID_START_OFFSET);
  end   = tvb_get_guint8(parameter_tvb,  TID_END_OFFSET);
  value = tvb_get_ntohs(parameter_tvb,   TID_VALUE_OFFSET);
   
  proto_tree_add_uint(parameter_tree, hf_sua_tid_label_start, 
                      parameter_tvb, TID_START_OFFSET, TID_START_LENGTH,
                      start);
  proto_tree_add_uint(parameter_tree, hf_sua_tid_label_end, 
                      parameter_tvb, TID_END_OFFSET, TID_END_LENGTH,
                      end);
  proto_tree_add_uint(parameter_tree, hf_sua_tid_label_value, 
                      parameter_tvb, TID_VALUE_OFFSET, TID_VALUE_LENGTH,
                      value);
  
  proto_item_set_text(parameter_item, "TID Label");
}

#define DRN_START_LENGTH 1
#define DRN_END_LENGTH 1
#define DRN_VALUE_LENGTH 2

#define DRN_START_OFFSET PARAMETER_VALUE_OFFSET
#define DRN_END_OFFSET   (DRN_START_OFFSET + DRN_START_LENGTH)
#define DRN_VALUE_OFFSET (DRN_END_OFFSET + DRN_END_LENGTH)

static void
dissect_sua_drn_label_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  start, end;
  guint16 value;
  
  start = tvb_get_guint8(parameter_tvb,  DRN_START_OFFSET);
  end   = tvb_get_guint8(parameter_tvb,  DRN_END_OFFSET);
  value = tvb_get_ntohs(parameter_tvb,   DRN_VALUE_OFFSET);
   
  proto_tree_add_uint(parameter_tree, hf_sua_drn_label_start, 
                      parameter_tvb, DRN_START_OFFSET, DRN_START_LENGTH,
                      start);
  proto_tree_add_uint(parameter_tree, hf_sua_drn_label_end, 
                      parameter_tvb, DRN_END_OFFSET, DRN_END_LENGTH,
                      end);
  proto_tree_add_uint(parameter_tree, hf_sua_drn_label_value, 
                      parameter_tvb, DRN_VALUE_OFFSET, DRN_VALUE_LENGTH,
                      value);
  
  proto_item_set_text(parameter_item, "DRN Label");
}

#define NO_OF_DIGITS_LENGTH      1
#define TRANSLATION_TYPE_LENGTH  1
#define NUMBERING_PLAN_LENGTH    1
#define NATURE_OF_ADDRESS_LENGTH 1

#define NO_OF_DIGITS_OFFSET      PARAMETER_VALUE_OFFSET
#define TRANSLATION_TYPE_OFFSET  (NO_OF_DIGITS_OFFSET + NO_OF_DIGITS_LENGTH)
#define NUMBERING_PLAN_OFFSET    (TRANSLATION_TYPE_OFFSET + TRANSLATION_TYPE_LENGTH)
#define NATURE_OF_ADDRESS_OFFSET (NUMBERING_PLAN_OFFSET + NUMBERING_PLAN_LENGTH)
#define GLOBAL_TITLE_OFFSET      (NATURE_OF_ADDRESS_OFFSET + NATURE_OF_ADDRESS_LENGTH)

#define ISDN_TELEPHONY_NUMBERING_PLAN   1
#define GENERIC_NUMBERING_PLAN          2
#define DATA_NUMBERING_PLAN             3
#define TELEX_NUMBERING_PLAN            4
#define MARITIME_MOBILE_NUMBERING_PLAN  5
#define LAND_MOBILE_NUMBERING_PLAN      6
#define ISDN_MOBILE_NUMBERING_PLAN      7
#define PRIVATE_NETWORK_NUMBERING_PLAN 14

static const value_string sua_numbering_plan_values[] = {
  { ISDN_TELEPHONY_NUMBERING_PLAN,  "ISDN/Telephony Numbering Plan (Rec. E.161 and E.164)" },
  { GENERIC_NUMBERING_PLAN,         "Generic Numbering Plan" },
  { DATA_NUMBERING_PLAN,            "Data Numbering Plan (Rec. X.121)" },
  { TELEX_NUMBERING_PLAN,           "Telex Numbering Plan (Rec. F.69)" },
  { MARITIME_MOBILE_NUMBERING_PLAN, "Maritime Mobile Numbering Plan (Rec. E.210 and E.211)" },
  { LAND_MOBILE_NUMBERING_PLAN,     "Land Mobile Numbering Plan (Rec. E.212)" },
  { ISDN_MOBILE_NUMBERING_PLAN,     "ISDN/Mobile Numbering Plan (Rec. E.214)" },
  { PRIVATE_NETWORK_NUMBERING_PLAN, "Private Network Or Network-Specific Numbering Plan" },
  { 0,                                             NULL } };

#define UNKNOWN_NATURE_OF_ADDRESS                       0
#define SUBSCRIBER_NUMBER_NATURE_OF_ADDRESS             1
#define RESERVED_FOR_NATIONAL_USE_NATURE_OF_ADDRESS     2
#define NATIONAL_SIGNIFICANT_NUMBER_NATURE_OF_ADDRESS   3
#define INTERNATION_NUMBER_NATURE_OF_ADDRESS            4

static const value_string sua_nature_of_address_values[] = {
  { UNKNOWN_NATURE_OF_ADDRESS,                     "Unknown" },
  { SUBSCRIBER_NUMBER_NATURE_OF_ADDRESS,           "Subscriber Number" },
  { RESERVED_FOR_NATIONAL_USE_NATURE_OF_ADDRESS,   "Reserved For National Use" },
  { NATIONAL_SIGNIFICANT_NUMBER_NATURE_OF_ADDRESS, "Natinal Significant Number" },
  { INTERNATION_NUMBER_NATURE_OF_ADDRESS,          "International Number" },
  { 0,                                             NULL } };

static void
dissect_sua_global_title_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  number_of_digits, translation_type, numbering_plan, nature_of_address;
  guint16 length, global_title_length, padding_length;
  
  length              = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  global_title_length = length - (PARAMETER_HEADER_LENGTH + NO_OF_DIGITS_LENGTH
                                                          + TRANSLATION_TYPE_LENGTH
                                                          + NUMBERING_PLAN_LENGTH
                                                          + NATURE_OF_ADDRESS_LENGTH);
  padding_length      = nr_of_padding_bytes(length);

  number_of_digits  = tvb_get_guint8(parameter_tvb, NO_OF_DIGITS_OFFSET);
  translation_type  = tvb_get_guint8(parameter_tvb, TRANSLATION_TYPE_OFFSET);
  numbering_plan    = tvb_get_guint8(parameter_tvb, NUMBERING_PLAN_OFFSET);
  nature_of_address = tvb_get_guint8(parameter_tvb, NATURE_OF_ADDRESS_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_number_of_digits, 
                      parameter_tvb, NO_OF_DIGITS_OFFSET, NO_OF_DIGITS_LENGTH,
                      number_of_digits);
  proto_tree_add_uint(parameter_tree, hf_sua_translation_type, 
                      parameter_tvb, TRANSLATION_TYPE_OFFSET, TRANSLATION_TYPE_LENGTH,
                      translation_type);
  proto_tree_add_uint(parameter_tree, hf_sua_numbering_plan, 
                      parameter_tvb, NUMBERING_PLAN_OFFSET, NUMBERING_PLAN_LENGTH,
                      numbering_plan);
  proto_tree_add_uint(parameter_tree, hf_sua_nature_of_address, 
                      parameter_tvb, NATURE_OF_ADDRESS_OFFSET, NATURE_OF_ADDRESS_LENGTH,
                      nature_of_address);
  proto_tree_add_bytes(parameter_tree, hf_sua_global_title, 
                       parameter_tvb, GLOBAL_TITLE_OFFSET, global_title_length,
                       tvb_get_ptr(parameter_tvb, GLOBAL_TITLE_OFFSET, global_title_length));

  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_global_title_padding, 
                         parameter_tvb, GLOBAL_TITLE_OFFSET + global_title_length, padding_length,
                         tvb_get_ptr(parameter_tvb, GLOBAL_TITLE_OFFSET + global_title_length, padding_length));
                         
  proto_item_set_text(parameter_item, "Global Title");

}

static void
dissect_sua_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8  mask;
  guint32 dpc;

  mask = tvb_get_guint8(parameter_tvb, AFFECTED_MASK_OFFSET);
  dpc  = tvb_get_ntoh24(parameter_tvb, AFFECTED_DPC_OFFSET);

  proto_tree_add_uint(parameter_tree, hf_sua_point_code_mask, 
                      parameter_tvb, PARAMETER_VALUE_OFFSET + AFFECTED_MASK_OFFSET, AFFECTED_MASK_LENGTH,
                      mask);
  proto_tree_add_uint(parameter_tree, hf_sua_point_code_dpc, 
                      parameter_tvb, PARAMETER_VALUE_OFFSET + AFFECTED_DPC_OFFSET, AFFECTED_DPC_LENGTH,
                      dpc);
  proto_item_set_text(parameter_item, "Point Code");

}

#define SSN_LENGTH 1
#define SSN_OFFSET (PARAMETER_VALUE_OFFSET + RESERVED_3_LENGTH)

static void
dissect_sua_ssn_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 ssn;
 
  ssn = tvb_get_guint8(parameter_tvb,  SSN_OFFSET);
    
  proto_tree_add_bytes(parameter_tree, hf_sua_ssn_reserved, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, RESERVED_3_LENGTH));
  proto_tree_add_uint(parameter_tree, hf_sua_ssn_number, 
                      parameter_tvb, SSN_OFFSET, SSN_LENGTH,
                      ssn);
  
  proto_item_set_text(parameter_item, "Subsystem number (%u)", ssn);
}

#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 ipv4_address;

  tvb_memcpy(parameter_tvb, (guint8 *)&ipv4_address, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH); 
  proto_tree_add_ipv4(parameter_tree, hf_sua_ipv4,
		                  parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH,
		                  ipv4_address);  
  proto_item_set_text(parameter_item, "IPV4 Address");
}

static void
dissect_sua_hostname_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16  length, hostname_length, padding_length;
  char *hostname;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  hostname_length = length - PARAMETER_HEADER_LENGTH;
  hostname = (char *)tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, hostname_length);
  
  proto_tree_add_string(parameter_tree, hf_sua_hostname, parameter_tvb,
			                  PARAMETER_VALUE_OFFSET, hostname_length,
			                  hostname);
  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_hostname_padding, 
                         parameter_tvb, PARAMETER_VALUE_OFFSET + hostname_length, padding_length,
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET + hostname_length, padding_length));

  proto_item_set_text(parameter_item, "Hostname (%s)", hostname);
}

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_sua_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_ipv6(parameter_tree, hf_sua_ipv6,
		                  parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH,
		                  tvb_get_ptr(parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH));
  
  proto_item_set_text(parameter_item, "IPV6 Address");
}

static void
dissect_sua_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 tag, length, parameter_value_length, padding_length;
  
  tag            = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);

  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_bytes(parameter_tree, hf_sua_parameter_value, 
                       parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length,
                       tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length));
  
  if (padding_length > 0)
    proto_tree_add_bytes(parameter_tree, hf_sua_parameter_padding, 
                         parameter_tvb, PARAMETER_VALUE_OFFSET + parameter_value_length, padding_length,
                         tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET + parameter_value_length, padding_length));

  proto_item_set_text(parameter_item, "Parameter with tag %u and %u byte%s value",
		                  tag, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

static void
dissect_sua_parameter(tvbuff_t *parameter_tvb, proto_tree *sua_tree)
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
  parameter_item   = proto_tree_add_text(sua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, total_length, "Incomplete parameter");
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_sua_parameter);

  /* add tag and length to the sua tree */
  proto_tree_add_uint(parameter_tree, hf_sua_parameter_tag, 
		                  parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH,
		                  tag);
  
  proto_tree_add_uint(parameter_tree, hf_sua_parameter_length, 
		                  parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH,
		                  length);

  switch(tag) {
  case DATA_PARAMETER_TAG:
    dissect_sua_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INFO_STRING_PARAMETER_TAG:
    dissect_sua_info_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_CONTEXT_PARAMETER_TAG:
    dissect_sua_routing_context_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFO_PARAMETER_TAG:
    dissect_sua_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_sua_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_sua_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ERROR_CODE_PARAMETER_TAG:
    dissect_sua_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATUS_PARAMETER_TAG:
    dissect_sua_status_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CONGESTION_LEVEL_PARAMETER_TAG:
    dissect_sua_congestion_level_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_sua_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case AFFECTED_POINT_CODE_PARAMETER_TAG:
    dissect_sua_affected_destinations_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SS7_HOP_COUNTER_PARAMETER_TAG:
    dissect_sua_ss7_hop_counter_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SOURCE_ADDRESS_PARAMETER_TAG:
    dissect_sua_source_address_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DESTINATION_ADDRESS_PARAMETER_TAG:
    dissect_sua_destination_address_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SOURCE_REFERENCE_NUMBER_PARAMETER_TAG:
    dissect_sua_source_reference_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DESTINATION_REFERENCE_NUMBER_PARAMETER_TAG:
    dissect_sua_destination_reference_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SCCP_CAUSE_PARAMETER_TAG:
    dissect_sua_sccp_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_sua_sequence_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case RECEIVE_SEQUENCE_NUMBER_PARAMETER_TAG:
    dissect_sua_receive_sequence_number_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_CAPABILITIES_PARAMETER_TAG:
    dissect_sua_asp_capabilities_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CREDIT_PARAMETER_TAG:
    dissect_sua_credit_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case USER_CAUSE_PARAMETER_TAG:
    dissect_sua_user_cause_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case NETWORK_APPEARANCE_PARAMETER_TAG:
    dissect_sua_network_appearance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ROUTING_KEY_PARAMETER_TAG:
    dissect_sua_routing_key_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case REGISTRATION_RESULT_PARAMETER_TAG:
    dissect_sua_registration_result_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DEREGISTRATION_RESULT_PARAMETER_TAG:
    dissect_sua_deregistration_result_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ADDRESS_RANGE_PARAMETER_TAG:
    dissect_sua_address_range_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case CORRELATION_ID_PARAMETER_TAG:
    dissect_sua_correlation_id_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IMPORTANCE_PARAMETER_TAG:
    dissect_sua_importance_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case MESSAGE_PRIORITY_PARAMETER_TAG:
    dissect_sua_message_priority_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_CLASS_PARAMETER_TAG:
    dissect_sua_protocol_class_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEQUENCE_CONTROL_PARAMETER_TAG:
    dissect_sua_sequence_control_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SEGMENTATION_PARAMETER_TAG:
    dissect_sua_segmentation_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SMI_PARAMETER_TAG:
    dissect_sua_smi_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TID_LABEL_PARAMETER_TAG:
    dissect_sua_tid_label_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DRN_LABEL_PARAMETER_TAG:
    dissect_sua_drn_label_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case GLOBAL_TITLE_PARAMETER_TAG:
    dissect_sua_global_title_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case POINT_CODE_PARAMETER_TAG:
    dissect_sua_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SUBSYSTEM_NUMBER_PARAMETER_TAG:
    dissect_sua_ssn_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV4_ADDRESS_PARAMETER_TAG:
    dissect_sua_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HOSTNAME_PARAMETER_TAG:
    dissect_sua_hostname_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV6_ADDRESS_PARAMETER_TAG:
    dissect_sua_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_sua_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
}

static void
dissect_sua_tlv_list(tvbuff_t *tlv_tvb, proto_tree *sua_tree, gint initial_offset)
{
  gint offset, length, padding_length, total_length;
  tvbuff_t *parameter_tvb;
  
  offset = initial_offset;
  
  while(tvb_reported_length_remaining(tlv_tvb, offset)) {
    length         = tvb_get_ntohs(tlv_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb    = tvb_new_subset(tlv_tvb, offset, total_length, total_length);
    dissect_sua_parameter(parameter_tvb, sua_tree); 
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

static void
dissect_sua_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *sua_tree)
{
  tvbuff_t *common_header_tvb;

  common_header_tvb = tvb_new_subset(message_tvb, COMMON_HEADER_OFFSET, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_sua_common_header(common_header_tvb, pinfo, sua_tree);
  
  if (sua_tree)
    dissect_sua_tlv_list(message_tvb, sua_tree, COMMON_HEADER_LENGTH);
}

/* Support of Siemens Light Version starts here */
#define SUAL_VERSION_LENGTH          1
#define SUAL_SPARE_1_LENGTH          1
#define SUAL_MESSAGE_TYPE_LENGTH     2
#define SUAL_SUBSYSTEM_NUMBER_LENGTH 2
#define SUAL_SPARE_2_LENGTH          2
#define SUAL_MESSAGE_LENGTH_LENGTH   4
#define SUAL_COMMON_HEADER_LENGTH   (SUAL_VERSION_LENGTH + SUAL_SPARE_1_LENGTH + SUAL_MESSAGE_TYPE_LENGTH + \
                                     SUAL_SUBSYSTEM_NUMBER_LENGTH + SUAL_SPARE_2_LENGTH + SUAL_MESSAGE_LENGTH_LENGTH)

#define SUAL_VERSION_OFFSET          0
#define SUAL_SPARE_1_OFFSET          (SUAL_VERSION_OFFSET + SUAL_VERSION_LENGTH)
#define SUAL_MESSAGE_TYPE_OFFSET     (SUAL_SPARE_1_OFFSET + SUAL_SPARE_1_LENGTH)
#define SUAL_SUBSYSTEM_NUMBER_OFFSET (SUAL_MESSAGE_TYPE_OFFSET + SUAL_MESSAGE_TYPE_LENGTH)
#define SUAL_SPARE_2_OFFSET          (SUAL_SUBSYSTEM_NUMBER_OFFSET + SUAL_SUBSYSTEM_NUMBER_LENGTH)
#define SUAL_MESSAGE_LENGTH_OFFSET   (SUAL_SPARE_2_OFFSET + SUAL_SPARE_2_LENGTH)

/* SUAL message type coding */
#define SUAL_MSG_CLDT                     0x0501
#define SUAL_MSG_CORE                     0x0701
#define SUAL_MSG_COAK_CC            	    0x0702
#define SUAL_MSG_COAK_CREF                0x0712
#define SUAL_MSG_RELRE                    0x0703
#define SUAL_MSG_RELCO                    0x0704
#define SUAL_MSG_CODT                     0x0707
#define SUAL_MSG_ERR                      0x0000

static const value_string sua_light_message_type_values[] = {
  {  SUAL_MSG_CLDT,              "Connectionless Data Transfer (CLDT)"},
  {  SUAL_MSG_CORE,              "Connection Request (CORE)"},
  {  SUAL_MSG_COAK_CC,           "Connection Acknowledge (COAK_CC)"},
  {  SUAL_MSG_COAK_CREF,         "Connection Acknowledge (COAK_CREF)"},
  {  SUAL_MSG_RELRE,             "Release Request (RELRE)"},
  {  SUAL_MSG_RELCO,             "Release Complete (RELCO)"},
  {  SUAL_MSG_CODT,              "Connection Oriented Data Transfer (CODT)"},
  {  SUAL_MSG_ERR,               "Error (ERR)"},
  {  0,                          NULL}};

static const value_string sua_light_message_type_acro_values[] = {
  {  SUAL_MSG_CLDT,              "CLDT"},
  {  SUAL_MSG_CORE,              "CORE"},
  {  SUAL_MSG_COAK_CC,           "COAK_CC"},
  {  SUAL_MSG_COAK_CREF,         "COAK_CREF"},
  {  SUAL_MSG_RELRE,             "RELRE"},
  {  SUAL_MSG_RELCO,             "RELCO"},
  {  SUAL_MSG_CODT,              "CODT"},
  {  SUAL_MSG_ERR,               "ERR"},
  {  0,                          NULL}};


/* SUAL Error Codes */
#define SUAL_ERR_INVVERS		0x0001
#define SUAL_ERR_INVSTRID		0x0005
#define SUAL_ERR_INVMSGTYP	0x0006

static const value_string sua_light_error_code_values[] = {
  {  SUAL_ERR_INVVERS,		"Invalid Protocol Version"},	
  {  SUAL_ERR_INVSTRID,		"Invalid Stream Identifier"},	
  {  SUAL_ERR_INVMSGTYP,      	"Invalid Message Type"},
  {  0,                          NULL}};

static void
dissect_sua_light_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, 
                                proto_tree *sual_tree, guint16  *subsystem_number)
{
  guint8  version, spare_1;
  guint16 message_type, spare_2; 
  guint32 message_length;

  /* Extract the common header */
  version           = tvb_get_guint8(common_header_tvb, SUAL_VERSION_OFFSET);
  spare_1           = tvb_get_guint8(common_header_tvb, SUAL_SPARE_1_OFFSET);
  message_type      = tvb_get_ntohs(common_header_tvb,  SUAL_MESSAGE_TYPE_OFFSET);
  *subsystem_number = tvb_get_ntohs(common_header_tvb,  SUAL_SUBSYSTEM_NUMBER_OFFSET);
  spare_2           = tvb_get_ntohs(common_header_tvb,  SUAL_SPARE_2_OFFSET);
  message_length    = tvb_get_ntohl(common_header_tvb,  SUAL_MESSAGE_LENGTH_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, sua_light_message_type_acro_values, "Unknown"));
    col_append_str(pinfo->cinfo, COL_INFO, " ");
  };

  if (sual_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(sual_tree, hf_sua_light_version, common_header_tvb, SUAL_VERSION_OFFSET, SUAL_VERSION_LENGTH, version);
    proto_tree_add_uint(sual_tree, hf_sua_light_spare_1, common_header_tvb, SUAL_SPARE_1_OFFSET, SUAL_SPARE_1_LENGTH, spare_1);
    proto_tree_add_uint(sual_tree, hf_sua_light_message_type, common_header_tvb, SUAL_MESSAGE_TYPE_OFFSET, SUAL_MESSAGE_TYPE_LENGTH,message_type);
    proto_tree_add_uint(sual_tree, hf_sua_light_subsystem_number, common_header_tvb, SUAL_SUBSYSTEM_NUMBER_OFFSET, SUAL_SUBSYSTEM_NUMBER_LENGTH, *subsystem_number);
    proto_tree_add_uint(sual_tree, hf_sua_light_spare_2, common_header_tvb, SUAL_SPARE_2_OFFSET, SUAL_SPARE_2_LENGTH, spare_2);
    proto_tree_add_uint(sual_tree, hf_sua_light_message_length, common_header_tvb, SUAL_MESSAGE_LENGTH_OFFSET, SUAL_MESSAGE_LENGTH_LENGTH, message_length);
  };
}

static void
dissect_sua_light_payload(tvbuff_t *payload_tvb, packet_info *pinfo,
                          guint16 subsystem_number, proto_tree *sual_tree, proto_tree *tree)
{
  guint		payload_length = tvb_reported_length(payload_tvb);
	
  /* do lookup with the subdissector table */
  if ( ! dissector_try_port (sua_light_dissector_table, subsystem_number, payload_tvb, pinfo, tree))
  {
     if (sual_tree)
       proto_tree_add_text(sual_tree, payload_tvb, 0, -1, "Payload: %u byte%s", payload_length, plurality(payload_length, "", "s"));
  }
}

static void
dissect_sua_light_error_payload(tvbuff_t *payload_tvb, proto_tree *sual_tree)
{
    if (sual_tree) 
       proto_tree_add_item(sual_tree, hf_sua_light_error_code, payload_tvb, 0, 2, FALSE); 
}

static void
dissect_sua_light_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *sual_tree, proto_tree *tree)
{
  gint     offset, payload_length;
  guint16  subsystem_number;
  guint16  message_type;
  tvbuff_t *common_header_tvb;
  tvbuff_t *payload_tvb;

  offset = 0;
  /* extract and process the common header */
  common_header_tvb = tvb_new_subset(message_tvb, offset, SUAL_COMMON_HEADER_LENGTH, SUAL_COMMON_HEADER_LENGTH);
  message_type      = tvb_get_ntohs(common_header_tvb, SUAL_MESSAGE_TYPE_OFFSET);
  dissect_sua_light_common_header(common_header_tvb, pinfo, sual_tree, &subsystem_number);
  offset           += SUAL_COMMON_HEADER_LENGTH;
  payload_length    = tvb_length(message_tvb) - SUAL_COMMON_HEADER_LENGTH;
  if (payload_length != 0)
  {
     payload_tvb = tvb_new_subset(message_tvb, offset, payload_length, payload_length);
     if (message_type != SUAL_MSG_ERR)
        dissect_sua_light_payload(payload_tvb, pinfo, subsystem_number, sual_tree, tree);
     else
     	dissect_sua_light_error_payload(payload_tvb, sual_tree);   
  }
}

static void
dissect_sua(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *sua_item;
  proto_tree *sua_tree;

  /* make entry in the Protocol column on summary display */
  switch(sua_version) {
    case IETF_VERSION08:
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SUA");
      break;
    case SIEMENS_VERSION: 
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SUA-Light");
      break;
  }
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the sua protocol tree */
    sua_item = proto_tree_add_item(tree, proto_sua, message_tvb, 0, -1, FALSE);
    sua_tree = proto_item_add_subtree(sua_item, ett_sua);
  } else {
    sua_tree = NULL;
  };
  
  /* dissect the message */
  switch(sua_version) {
    case IETF_VERSION08:
        dissect_sua_message(message_tvb, pinfo, sua_tree);
        break;
    case SIEMENS_VERSION:
        dissect_sua_light_message(message_tvb, pinfo, sua_tree, tree);
        break;
  }
}

/* Register the protocol with Ethereal */
void
proto_register_sua(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_sua_version,
      { "Version", "sua.version",
	      FT_UINT8, BASE_DEC, VALS(sua_protocol_version_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_reserved,
      { "Reserved", "sua.reserved",
	       FT_BYTES, BASE_NONE, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_message_class,
      { "Message Class", "sua.message_class",
	       FT_UINT8, BASE_DEC, VALS(sua_message_class_values), 0x0,          
	       "", HFILL }
    },
    { &hf_sua_message_type,
      { "Message Type", "sua.message_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_message_length,
      { "Message Length", "sua.message_length",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_sua_parameter_tag,
      { "Parameter Tag", "sua.parameter_tag",
    	FT_UINT16, BASE_HEX, VALS(sua_parameter_tag_values), 0x0,          
	    "", HFILL }
    },
    { &hf_sua_parameter_length,
      { "Parameter Length", "sua.parameter_length",
	      FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_sua_parameter_value,
      { "Parameter Value", "sua.parameter_value",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_parameter_padding,
      { "Padding", "sua.parameter_padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_data_padding,
      { "Padding", "sua.data.padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_info_string,
      { "Info string", "sua.info_string.string",
	      FT_STRING, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_sua_info_string_padding,
      { "Padding", "sua.info_string.padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_routing_context,
      { "Routing context", "sua.routing_context.context",
        FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_diagnostic_information_info,
      { "Diagnostic Information", "sua.diagnostic_information.info",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_diagnostic_information_padding,
      { "Padding", "sua.diagnostic_information.padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_heartbeat_data,
      { "Heratbeat Data", "sua.heartbeat.data",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_heartbeat_padding,
      { "Padding", "sua.heartbeat.padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_traffic_mode_type,
      { "Traffic mode Type", "sua.traffic_mode_type.type",
	      FT_UINT32, BASE_DEC, VALS(sua_traffic_mode_type_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_error_code,
      { "Error code", "sua.error_code.code",
	      FT_UINT32, BASE_DEC, VALS(sua_error_code_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_status_type,
      { "Status type", "sua.status.type",
	    FT_UINT16, BASE_DEC, VALS(sua_status_type_values), 0x0,          
	    "", HFILL }
    }, 
    { &hf_sua_status_info,
      { "Status info", "sua.status.info",
     	  FT_UINT16, BASE_DEC, NULL, 0x0,          
    	  "", HFILL }
    }, 
    { &hf_sua_congestion_level,
      { "Congestion Level", "sua.congestion_level.level",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_asp_identifier,
      { "ASP Identifier", "sua.asp_identifier.id",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_mask,
      { "Mask", "sua.affected_point_code.mask",
	      FT_UINT8, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_sua_dpc,
      { "Affected DPC", "sua.affected_pointcode.dpc",
	      FT_UINT24, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_sua_ss7_hop_counter_counter,
      { "SS7 Hop Counter", "sua.ss7_hop_counter.counter",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_ss7_hop_counter_reserved,
      { "Reserved", "sua.ss7_hop_counter.reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },   
    { &hf_sua_source_address_routing_indicator,
      { "Routing Indicator", "sua.source_address.routing_indicator",
	      FT_UINT16, BASE_DEC, VALS(sua_routing_indicator_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_source_address_reserved_bits,
      { "Reserved Bits", "sua.source_address.reserved_bits",
	      FT_UINT16, BASE_DEC, NULL, ADDRESS_RESERVED_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_source_address_gt_bit,
      { "Include GT", "sua.source_address.gt_bit",
	      FT_BOOLEAN, 16, NULL, ADDRESS_GT_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_source_address_pc_bit,
      { "Include PC", "sua.source_address.pc_bit",
	      FT_BOOLEAN, 16, NULL, ADDRESS_PC_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_source_address_ssn_bit,
      { "Include SSN", "sua.source_address.ssn_bit",
	      FT_BOOLEAN, 16, NULL, ADDRESS_SSN_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_destination_address_routing_indicator,
      { "Routing Indicator", "sua.destination_address.routing_indicator",
	      FT_UINT16, BASE_DEC, VALS(sua_routing_indicator_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_destination_address_reserved_bits,
      { "Reserved Bits", "sua.destination_address.reserved_bits",
	      FT_UINT16, BASE_DEC, NULL, ADDRESS_RESERVED_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_destination_address_gt_bit,
      { "Include GT", "sua.destination_address.gt_bit",
	      FT_BOOLEAN, 16, NULL, ADDRESS_GT_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_destination_address_pc_bit,
      { "Include PC", "sua.destination_address.pc_bit",
	      FT_BOOLEAN, 16, NULL, ADDRESS_PC_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_destination_address_ssn_bit,
      { "Include SSN", "sua.destination_address.ssn_bit",
	      FT_BOOLEAN, 16, NULL, ADDRESS_SSN_BITMASK,          
	      "", HFILL }
    },
    { &hf_sua_source_reference_number,
      { "Source Reference Number", "sua.source_reference_number.number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_destination_reference_number,
      { "Destination Reference Number", "sua.destination_reference_number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_cause_reserved,
      { "Reserved", "sua.sccp_cause.reserved",
	       FT_BYTES, BASE_NONE, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_cause_type,
      { "Cause Type", "sua.sccp_cause.type",
	       FT_UINT8, BASE_HEX, VALS(sua_cause_type_values), 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_cause_value,
      { "Cause Value", "sua.sccp_cause.value",
	       FT_UINT8, BASE_HEX, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_sequence_number_reserved,
      { "Reserved", "sua.sequence_number.reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_sequence_number_rec_number,
      { "Receive Sequence Number P(R)", "sua.sequence_number.receive_sequence_number",
	      FT_UINT8, BASE_DEC, NULL, SEQ_NUM_MASK,          
	      "", HFILL }
    },
    { &hf_sua_sequence_number_more_data_bit,
      { "More Data Bit", "sua.sequence_number.more_data_bit",
	      FT_BOOLEAN, 8, TFS(&sua_more_data_bit_value), MORE_DATA_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_sequence_number_sent_number,
      { "Sent Sequence Number P(S)", "sua.sequence_number.sent_sequence_number",
	      FT_UINT8, BASE_DEC, NULL, SEQ_NUM_MASK,          
	      "", HFILL }
    },
    { &hf_sua_sequence_number_spare_bit,
      { "Spare Bit", "sua.sequence_number.spare_bit",
	      FT_BOOLEAN, 8, NULL, SPARE_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_receive_sequence_number_reserved,
      { "Reserved", "sua.receive_sequence_number.reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_receive_sequence_number_number,
      { "Receive Sequence Number P(R)", "sua.receive_sequence_number.number",
	      FT_UINT8, BASE_DEC, NULL, SEQ_NUM_MASK,          
	      "", HFILL }
    },
    { &hf_sua_receive_sequence_number_spare_bit,
      { "Spare Bit", "sua.receive_sequence_number.spare_bit",
	      FT_BOOLEAN, 8, NULL, SPARE_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_asp_capabilities_reserved,
      { "Reserved", "sua.asp_capabilities.reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_asp_capabilities_reserved_bits,
      { "Reserved Bits", "sua.asp_capabilities.reserved_bits",
	      FT_UINT8, BASE_HEX, NULL, RESERVED_BITS_MASK,          
	      "", HFILL }
    },
    { &hf_sua_asp_capabilities_a_bit,
      { "Protocol Class 3", "sua.asp_capabilities.a_bit",
	      FT_BOOLEAN, 8, TFS(&sua_supported_bit_value), A_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_asp_capabilities_b_bit,
      { "Protocol Class 2", "sua.asp_capabilities.b_bit",
	      FT_BOOLEAN, 8, TFS(&sua_supported_bit_value), B_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_asp_capabilities_c_bit,
      { "Protocol Class 1", "sua.asp_capabilities.c_bit",
	      FT_BOOLEAN, 8, TFS(&sua_supported_bit_value), C_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_asp_capabilities_d_bit,
      { "Protocol Class 0", "sua.asp_capabilities.d_bit",
	      FT_BOOLEAN, 8, TFS(&sua_supported_bit_value), D_BIT_MASK,          
	      "", HFILL }
    },
    { &hf_sua_asp_capabilities_interworking,
      { "Interworking", "sua.asp_capabilities.interworking",
	      FT_UINT8, BASE_HEX, VALS(sua_interworking_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_credit,
      { "Credit", "sua.credit.credit",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_cause,
      { "Cause", "sua.cause_user.cause",
	      FT_UINT16, BASE_DEC, VALS(sua_cause_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_user,
      { "User", "sua.cause_user.user",
	      FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_network_appearance,
      { "Network Appearance", "sua.network_appearance.appearance",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_routing_key_identifier,
      { "Local Routing Key Identifier", "sua.routing_key.identifier",
	      FT_UINT32, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_registration_result_routing_key_identifier,
      { "Local Routing Key Identifier", "sua.registration_result.local_routing_key_identifier",
	    FT_UINT32, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_sua_registration_result_status,
      { "Registration Status", "sua.registration_result.registration_status",
	    FT_UINT32, BASE_DEC, VALS(sua_registration_status_values), 0x0,          
	    "", HFILL }
    }, 
    { &hf_sua_registration_result_routing_context,
      { "Routing Context", "sua.registration_result.routing_context",
	    FT_UINT32, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_sua_deregistration_result_status,
      { "Deregistration Status", "sua.deregistration_result.deregistration_status",
	    FT_UINT32, BASE_DEC, VALS(sua_deregistration_status_values), 0x0,          
	    "", HFILL }
    }, 
    { &hf_sua_deregistration_result_routing_context,
      { "Routing Context", "sua.deregistration_result.routing_context",
	    FT_UINT32, BASE_DEC, NULL, 0x0,          
	    "", HFILL }
    }, 
    { &hf_sua_correlation_id,
      { "Correlation ID", "sua.correlation_id.identifier",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_importance_reserved,
      { "Reserved", "sua.importance.reserved",
	       FT_BYTES, BASE_NONE, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_importance,
      { "Importance", "sua.importance.inportance",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_message_priority_reserved,
      { "Reserved", "sua.message_priority.reserved",
	       FT_BYTES, BASE_NONE, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_message_priority,
      { "Message Priority", "sua.message_priority.priority",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_protocol_class_reserved,
      { "Reserved", "sua.protcol_class.reserved",
	      FT_BYTES, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    },
    {&hf_sua_return_on_error_bit,
     { "Return On Error Bit", "sua.protocol_class.return_on_error_bit",
       FT_BOOLEAN, 8, TFS(&sua_return_on_error_bit_value), RETURN_ON_ERROR_BIT_MASK,          
       "", HFILL }
    },
    {&hf_sua_protocol_class,
     { "Protocol Class", "sua.protocol_class.class",
       FT_UINT8, BASE_DEC, NULL, PROTOCOL_CLASS_MASK,          
       "", HFILL }
    },
    { &hf_sua_sequence_control,
      { "Sequence Control", "sua.sequence_control.sequence_control",
	      FT_UINT32, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    {&hf_sua_first_bit,
     { "First Segment Bit", "sua.segmentation.first_bit",
       FT_BOOLEAN, 8, TFS(&sua_first_bit_value), FIRST_BIT_MASK,          
       "", HFILL }
    },
    {&hf_sua_number_of_remaining_segments,
     { "Number of Remaining Segments", "sua.segmentation.number_of_remaining_segments",
       FT_UINT8, BASE_DEC, NULL, NUMBER_OF_SEGMENTS_MASK,          
       "", HFILL }
    },
    { &hf_sua_segmentation_reference,
      { "Segmentation Reference", "sua.segmentation.reference",
	      FT_UINT24, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_smi_reserved,
      { "Reserved", "sua.smi.reserved",
	       FT_BYTES, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_smi,
      { "SMI", "sua.smi.smi",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_tid_label_start,
      { "Start", "sua.tid_label.start",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_tid_label_end,
      { "End", "sua.tid_label.end",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_tid_label_value,
      { "Label Value", "sua.tid_label.value",
	       FT_UINT16, BASE_HEX, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_drn_label_start,
      { "Start", "sua.drn_label.start",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_drn_label_end,
      { "End", "sua.drn_label.end",
	       FT_UINT8, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_drn_label_value,
      { "Label Value", "sua.drn_label.value",
	       FT_UINT16, BASE_HEX, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sua_number_of_digits,
      { "Number of Digits", "sua.global_title.number_of_digits",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_translation_type,
      { "Translation Type", "sua.global_title.translation_type",
	      FT_UINT8, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_numbering_plan,
      { "Numbering Plan", "sua.global_title.numbering_plan",
	      FT_UINT8, BASE_HEX, VALS(sua_numbering_plan_values), 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_nature_of_address,
      { "Nature of Address", "sua.global_title.nature_of_address",
	      FT_UINT8, BASE_HEX, VALS(sua_nature_of_address_values), 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_nature_of_address,
      { "Nature Of Address", "sua.global_title.nature_of_address",
	      FT_UINT8, BASE_HEX, VALS(sua_nature_of_address_values), 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_global_title,
      { "Global Title", "sua.global_title.signals",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_global_title_padding,
      { "Padding", "sua.global_title.padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_point_code_mask,
      { "Mask", "sua.point_code.mask",
	      FT_UINT8, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_point_code_dpc,
      { "Point Code", "sua.point_code.pc",
	      FT_UINT24, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_ssn_reserved,
      { "Reserved", "sua.ssn.reserved",
	      FT_BYTES, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },    
    { &hf_sua_ssn_number,
      { "Subsystem Number", "sua.ssn.number",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },    
    {&hf_sua_ipv4,
     { "IP Version 4 address", "sua.ipv4.address",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    {&hf_sua_hostname,
     { "Hostname", "sua.hostname.name",
       FT_STRING, BASE_NONE, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sua_hostname_padding,
     { "Padding", "sua.hostname.padding",
       FT_BYTES, BASE_NONE, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sua_ipv6,
     { "IP Version 6 address", "sua.ipv6.address",
       FT_IPv6, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    { &hf_sua_light_version,
      { "Version", "sua.light.version",
	      FT_UINT8, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_light_spare_1,
      { "Spare", "sua.light.spare_1",
	      FT_UINT8, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    }, 
    { &hf_sua_light_message_type,
      { "Message Type", "sua.light.message_type",
	      FT_UINT16, BASE_DEC, VALS(sua_light_message_type_values), 0x0,          
	      "", HFILL }
    },
    { &hf_sua_light_subsystem_number,
      { "Subsystem number", "sua.light.subsystem_number",
	      FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_light_spare_2,
      { "Spare", "sua.light.spare_2",
	      FT_UINT16, BASE_DEC, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sua_light_message_length,
      { "Message length", "sua.light.message_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    },
    { &hf_sua_light_error_code,
      { "Error Code", "sua.light.error_code",
        FT_UINT16, BASE_HEX, VALS(&sua_light_error_code_values), 0x0,
	      "", HFILL }
    }
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sua,
    &ett_sua_parameter,
    &ett_sua_source_address_indicator,
    &ett_sua_destination_address_indicator,
    &ett_sua_affected_destination,
    &ett_sua_sequence_number_rec_number,
    &ett_sua_sequence_number_sent_number,
    &ett_sua_receive_sequence_number_number,
    &ett_sua_protcol_classes,
    &ett_sua_first_remaining,
    &ett_sua_return_on_error_bit_and_protocol_class
  };
  
  static enum_val_t sua_options[] = {
    { "Internet draft 8 version",        IETF_VERSION08 },
    { "SUA light (Siemens proprietary)", SIEMENS_VERSION },
    { NULL, 0 }
  };

  
  /* Register the protocol name and description */
  proto_sua = proto_register_protocol("SS7 SCCP-User Adaptation Layer", "SUA", "sua");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
    
  sua_module = prefs_register_protocol(proto_sua, NULL);
  sua_light_dissector_table = register_dissector_table("sual.subsystem_number",
				"SUA Light subsystem number", FT_UINT16,
				BASE_DEC);

  prefs_register_enum_preference(sua_module,
				 "sua_version",
				 "SUA Version",
				 "SUA Version",
				 &sua_version,
				 sua_options, FALSE);
};

void
proto_reg_handoff_sua(void)
{
  dissector_handle_t sua_handle;

  sua_handle = create_dissector_handle(dissect_sua, proto_sua);
  dissector_add("sctp.ppi",  SUA_PAYLOAD_PROTO_ID, sua_handle);
  dissector_add("sctp.port", SCTP_PORT_SUA,        sua_handle);
}
