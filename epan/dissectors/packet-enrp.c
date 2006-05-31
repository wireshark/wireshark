/* packet-enrp.c
 * Routines for Endpoint Handlespace Redundancy Protocol (ENRP)
 * It is hopefully (needs testing) compilant to
 * http://www.ietf.org/internet-drafts/draft-ietf-rserpool-common-param-09.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-rserpool-enrp-12.txt
 *
 * The code is not as simple as possible for the current protocol
 * but allows to be easily adopted to future versions of the protocol.
 * I will reconsider this after the protocol is an RFC.
 *
 * TODO:
 *   - check message lengths
 *
 * Copyright 2004, 2005 Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <epan/sctpppids.h>

/* Initialize the protocol and registered fields */
static int proto_enrp = -1;
static int hf_cause_code = -1;
static int hf_cause_length = -1;
static int hf_cause_info = -1;
static int hf_cause_padding = -1;
static int hf_message_type = -1;
static int hf_message_flags = -1;
static int hf_message_length = -1;
static int hf_message_value = -1;
static int hf_parameter_type = -1;
static int hf_parameter_length = -1;
static int hf_parameter_value = -1;
static int hf_parameter_padding = -1;
static int hf_parameter_ipv4_address = -1;
static int hf_parameter_ipv6_address = -1;
static int hf_sctp_port = -1;
static int hf_transport_use = -1;
static int hf_tcp_port = -1;
static int hf_udp_port = -1;
static int hf_udp_reserved = -1;
static int hf_policy_type = -1;
static int hf_policy_value = -1;
static int hf_pool_handle = -1;
static int hf_pe_pe_identifier = -1;
static int hf_home_enrp_id = -1;
static int hf_reg_life = -1;
static int hf_server_identifier = -1;
static int hf_m_bit = -1;
static int hf_reserved = -1;
static int hf_cookie = -1;
static int hf_pe_identifier = -1;
static int hf_pe_checksum = -1;
static int hf_pe_checksum_reserved = -1;
static int hf_sender_servers_id = -1;
static int hf_receiver_servers_id = -1;
static int hf_target_servers_id = -1;
static int hf_update_action = -1;
static int hf_pmu_reserved = -1;
static int hf_reply_required_bit = -1;
static int hf_own_children_only_bit = -1;
static int hf_more_to_send_bit = -1;
static int hf_reject_bit = -1;

/* Initialize the subtree pointers */
static gint ett_enrp = -1;
static gint ett_enrp_parameter = -1;
static gint ett_enrp_cause = -1;
static gint ett_enrp_flags = -1;

static void
dissect_parameters(tvbuff_t *, proto_tree *);
static void
dissect_parameter(tvbuff_t *, proto_tree *);
static void
dissect_enrp_message(tvbuff_t *, packet_info *, proto_tree *);

#define NETWORK_BYTE_ORDER     FALSE
#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

/* These following ports are NOT reserved. */
#define ENRP_UDP_PORT  3864
#define ASAP_SCTP_PORT 3864

/* Dissectors for error causes. This is common for ASAP and ENRP. */

#define CAUSE_CODE_LENGTH   2
#define CAUSE_LENGTH_LENGTH 2
#define CAUSE_HEADER_LENGTH (CAUSE_CODE_LENGTH + CAUSE_LENGTH_LENGTH)

#define CAUSE_HEADER_OFFSET 0
#define CAUSE_CODE_OFFSET   CAUSE_HEADER_OFFSET
#define CAUSE_LENGTH_OFFSET (CAUSE_CODE_OFFSET + CAUSE_CODE_LENGTH)
#define CAUSE_INFO_OFFSET   (CAUSE_LENGTH_OFFSET + CAUSE_LENGTH_LENGTH)

static void
dissect_unknown_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 code, length, cause_info_length;

  code              = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length            = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  cause_info_length = length - CAUSE_HEADER_LENGTH;
  if (cause_info_length > 0)
    proto_tree_add_bytes(cause_tree, hf_cause_info, cause_tvb, CAUSE_INFO_OFFSET, cause_info_length,
                         tvb_get_ptr(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length));
  proto_item_append_text(cause_item, " (code %u and %u byte%s information)", code, cause_info_length, plurality(cause_info_length, "", "s"));
}

#define UNRECOGNIZED_PARAMETER_CAUSE_CODE                  1
#define UNRECONGNIZED_MESSAGE_CAUSE_CODE                   2
#define INVALID_VALUES                                     3
#define NON_UNIQUE_PE_IDENTIFIER                           4
#define POOLING_POLICY_INCONSISTENT_CAUSE_CODE             5
#define LACK_OF_RESOURCES_CAUSE_CODE                       6
#define INCONSISTENT_TRANSPORT_TYPE_CAUSE_CODE             7
#define INCONSISTENT_DATA_CONTROL_CONFIGURATION_CAUSE_CODE 8
#define UNKNOWN_POOL_HANDLE                                9

static const value_string cause_code_values[] = {
  { UNRECOGNIZED_PARAMETER_CAUSE_CODE,                  "Unrecognized parameter"         },
  { UNRECONGNIZED_MESSAGE_CAUSE_CODE,                   "Unrecognized message"           },
  { INVALID_VALUES,                                     "Invalid values"                 },
  { NON_UNIQUE_PE_IDENTIFIER,                           "Non-unique PE identifier"       },
  { POOLING_POLICY_INCONSISTENT_CAUSE_CODE,             "Pooling policy inconsistent"    },
  { LACK_OF_RESOURCES_CAUSE_CODE,                       "Lack of resources"              },
  { INCONSISTENT_TRANSPORT_TYPE_CAUSE_CODE,             "Inconsistent transport type"    },
  { INCONSISTENT_DATA_CONTROL_CONFIGURATION_CAUSE_CODE, "Inconsistent data/control type" },
  { UNKNOWN_POOL_HANDLE,                                "Unknown pool handle"            },
  { 0,                                                  NULL                             } };

static void
dissect_error_cause(tvbuff_t *cause_tvb, proto_tree *parameter_tree)
{
  guint16 code, length, padding_length;
  proto_item *cause_item;
  proto_tree *cause_tree;
  tvbuff_t *parameter_tvb, *message_tvb;

  code           = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length         = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  padding_length = tvb_length(cause_tvb) - length;

  cause_item = proto_tree_add_text(parameter_tree, cause_tvb, CAUSE_HEADER_OFFSET, tvb_length(cause_tvb), val_to_str(code, cause_code_values, "Unknown error cause"));
  cause_tree = proto_item_add_subtree(cause_item, ett_enrp_cause);

  proto_tree_add_item(cause_tree, hf_cause_code,   cause_tvb, CAUSE_CODE_OFFSET,   CAUSE_CODE_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(cause_tree, hf_cause_length, cause_tvb, CAUSE_LENGTH_OFFSET, CAUSE_LENGTH_LENGTH, NETWORK_BYTE_ORDER);

  switch(code) {
  case UNRECOGNIZED_PARAMETER_CAUSE_CODE:
    parameter_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, -1, -1);
    dissect_parameter(parameter_tvb, parameter_tree);
    break;
  case UNRECONGNIZED_MESSAGE_CAUSE_CODE:
    message_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, -1, -1);
    dissect_enrp_message(message_tvb, NULL, parameter_tree);
    break;
    break;
  case INVALID_VALUES:
    parameter_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, -1, -1);
    dissect_parameter(parameter_tvb, parameter_tree);
    break;
  case NON_UNIQUE_PE_IDENTIFIER:
    break;
  case POOLING_POLICY_INCONSISTENT_CAUSE_CODE:
    parameter_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, -1, -1);
    dissect_parameter(parameter_tvb, parameter_tree);
    break;
  case LACK_OF_RESOURCES_CAUSE_CODE:
    break;
  case INCONSISTENT_TRANSPORT_TYPE_CAUSE_CODE:
    parameter_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, -1, -1);
    dissect_parameter(parameter_tvb, parameter_tree);
    break;
  case INCONSISTENT_DATA_CONTROL_CONFIGURATION_CAUSE_CODE:
    break;
  case UNKNOWN_POOL_HANDLE:
    break;
  default:
    dissect_unknown_cause(cause_tvb, cause_tree, cause_item);
    break;
  }
  if (padding_length > 0)
    proto_tree_add_item(cause_tree, hf_cause_padding, cause_tvb, CAUSE_HEADER_OFFSET + length, padding_length, NETWORK_BYTE_ORDER);
}

static void
dissect_error_causes(tvbuff_t *error_causes_tvb, proto_tree *parameter_tree)
{
  guint16 length, total_length;
  gint offset;
  tvbuff_t *error_cause_tvb;

  offset = 0;
  while(tvb_reported_length_remaining(error_causes_tvb, offset)) {
    length          = tvb_get_ntohs(error_causes_tvb, offset + CAUSE_LENGTH_OFFSET);
    total_length    = ADD_PADDING(length);
    error_cause_tvb = tvb_new_subset(error_causes_tvb, offset , total_length, total_length);
    dissect_error_cause(error_cause_tvb, parameter_tree);
    offset += total_length;
  }
}

/* Dissectors for parameters. This is common for ASAP and ENRP. */

#define PARAMETER_TYPE_LENGTH   2
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_HEADER_LENGTH (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET 0
#define PARAMETER_TYPE_OFFSET   PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET  (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_parameter_ipv4_address, parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", ip_to_str((const guint8 *)tvb_get_ptr(parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH)));
}

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_parameter_ipv6_address, parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%s)", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH)));
}

#define TRANSPORT_USE_DATA_ONLY         0
#define TRANSPORT_USE_DATA_PLUS_CONTROL 1

static const value_string transport_use_values[] = {
  { TRANSPORT_USE_DATA_ONLY,          "Data only"         },
  { TRANSPORT_USE_DATA_PLUS_CONTROL,  "Data plus control" },
  { 0,                                NULL                } };

#define SCTP_PORT_LENGTH          2
#define SCTP_TRANSPORT_USE_LENGTH 2
#define SCTP_PORT_OFFSET          PARAMETER_VALUE_OFFSET
#define SCTP_TRANSPORT_USE_OFFSET (SCTP_PORT_OFFSET + SCTP_PORT_LENGTH)
#define SCTP_ADDRESS_OFFSET       (SCTP_TRANSPORT_USE_OFFSET + SCTP_TRANSPORT_USE_LENGTH)

static void
dissect_sctp_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_sctp_port,     parameter_tvb, SCTP_PORT_OFFSET,          SCTP_PORT_LENGTH,          NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_transport_use, parameter_tvb, SCTP_TRANSPORT_USE_OFFSET, SCTP_TRANSPORT_USE_LENGTH, NETWORK_BYTE_ORDER);

  parameters_tvb = tvb_new_subset(parameter_tvb, SCTP_ADDRESS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define TCP_PORT_LENGTH          2
#define TCP_TRANSPORT_USE_LENGTH 2
#define TCP_PORT_OFFSET          PARAMETER_VALUE_OFFSET
#define TCP_TRANSPORT_USE_OFFSET (TCP_PORT_OFFSET + TCP_PORT_LENGTH)
#define TCP_ADDRESS_OFFSET       (TCP_TRANSPORT_USE_OFFSET + TCP_TRANSPORT_USE_LENGTH)

static void
dissect_tcp_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_tcp_port,      parameter_tvb, TCP_PORT_OFFSET,          TCP_PORT_LENGTH,          NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_transport_use, parameter_tvb, TCP_TRANSPORT_USE_OFFSET, TCP_TRANSPORT_USE_LENGTH, NETWORK_BYTE_ORDER);

  parameters_tvb = tvb_new_subset(parameter_tvb, TCP_ADDRESS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define UDP_PORT_LENGTH     2
#define UDP_RESERVED_LENGTH 2
#define UDP_PORT_OFFSET     PARAMETER_VALUE_OFFSET
#define UDP_RESERVED_OFFSET (UDP_PORT_OFFSET + UDP_PORT_LENGTH)
#define UDP_ADDRESS_OFFSET  (UDP_RESERVED_OFFSET + UDP_RESERVED_LENGTH)

static void
dissect_udp_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_udp_port,     parameter_tvb, UDP_PORT_OFFSET,     UDP_PORT_LENGTH,     NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_udp_reserved, parameter_tvb, UDP_RESERVED_OFFSET, UDP_RESERVED_LENGTH, NETWORK_BYTE_ORDER);

  parameters_tvb = tvb_new_subset(parameter_tvb, UDP_ADDRESS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define POLICY_TYPE_LENGTH   1
#define POLICY_VALUE_LENGTH  3

#define POLICY_TYPE_OFFSET   PARAMETER_VALUE_OFFSET
#define POLICY_VALUE_OFFSET  (POLICY_TYPE_OFFSET + POLICY_TYPE_LENGTH)

#define ROUND_ROBIN_POLICY   1
#define LEAST_USED_POLICY    2
#define LEAST_USED_WITH_DEG  3
#define WEIGHTED_ROUND_ROBIN 4

static const value_string policy_type_values[] = {
  { ROUND_ROBIN_POLICY,   "Round robin" },
  { LEAST_USED_POLICY,    "Least used" },
  { LEAST_USED_WITH_DEG,  "Least used with degradation" },
  { WEIGHTED_ROUND_ROBIN, "Weighted round robin" },
  { 0,                    NULL } };

static void
dissect_pool_member_selection_policy_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_policy_type,  parameter_tvb, POLICY_TYPE_OFFSET,  POLICY_TYPE_LENGTH,  NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_policy_value, parameter_tvb, POLICY_VALUE_OFFSET, POLICY_VALUE_LENGTH, NETWORK_BYTE_ORDER);
}

#define POOL_HANDLE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_pool_handle_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  guint16 handle_length;

  handle_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_pool_handle, parameter_tvb, POOL_HANDLE_OFFSET, handle_length, NETWORK_BYTE_ORDER);
}

#define PE_PE_IDENTIFIER_LENGTH         4
#define HOME_ENRP_INDENTIFIER_LENGTH    4
#define REGISTRATION_LIFE_LENGTH        4

#define PE_PE_IDENTIFIER_OFFSET         PARAMETER_VALUE_OFFSET
#define HOME_ENRP_INDENTIFIER_OFFSET    (PE_PE_IDENTIFIER_OFFSET + PE_PE_IDENTIFIER_LENGTH)
#define REGISTRATION_LIFE_OFFSET        (HOME_ENRP_INDENTIFIER_OFFSET + HOME_ENRP_INDENTIFIER_LENGTH)
#define USER_TRANSPORT_PARAMETER_OFFSET (REGISTRATION_LIFE_OFFSET + REGISTRATION_LIFE_LENGTH)

static void
dissect_pool_element_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_pe_pe_identifier, parameter_tvb, PE_PE_IDENTIFIER_OFFSET,      PE_PE_IDENTIFIER_LENGTH,      NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_home_enrp_id,     parameter_tvb, HOME_ENRP_INDENTIFIER_OFFSET, HOME_ENRP_INDENTIFIER_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_reg_life,         parameter_tvb, REGISTRATION_LIFE_OFFSET,     REGISTRATION_LIFE_LENGTH,     NETWORK_BYTE_ORDER);

  parameters_tvb = tvb_new_subset(parameter_tvb, USER_TRANSPORT_PARAMETER_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define SERVER_ID_LENGTH         4
#define RESERVED_LENGTH          4

#define SERVER_ID_OFFSET         PARAMETER_VALUE_OFFSET
#define RESERVED_OFFSET          (SERVER_ID_OFFSET + SERVER_ID_LENGTH)
#define SERVER_TRANSPORT_OFFSET  (RESERVED_OFFSET + RESERVED_LENGTH)

#define M_BIT_MASK               0x80000000
#define RESERVED_MASK            0x7fffffff

static void
dissect_server_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_server_identifier, parameter_tvb, SERVER_ID_OFFSET, SERVER_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_m_bit,             parameter_tvb, RESERVED_OFFSET,  RESERVED_LENGTH,  NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_reserved,          parameter_tvb, RESERVED_OFFSET,  RESERVED_LENGTH,  NETWORK_BYTE_ORDER);

  parameters_tvb = tvb_new_subset(parameter_tvb, SERVER_TRANSPORT_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define ERROR_CAUSES_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_operation_error_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *error_causes_tvb;

  error_causes_tvb = tvb_new_subset(parameter_tvb, ERROR_CAUSES_OFFSET, -1,-1);
  dissect_error_causes(error_causes_tvb, parameter_tree);
}

#define COOKIE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_cookie_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 cookie_length;

  cookie_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (cookie_length > 0)
    proto_tree_add_item(parameter_tree, hf_cookie, parameter_tvb, COOKIE_OFFSET, cookie_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (%u byte%s)", cookie_length, plurality(cookie_length, "", "s"));
}

#define PE_IDENTIFIER_LENGTH 4
#define PE_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_pe_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_pe_identifier, parameter_tvb, PE_IDENTIFIER_OFFSET, PE_IDENTIFIER_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (0x%x)", tvb_get_ntohl(parameter_tvb, PE_IDENTIFIER_OFFSET));
}

#define PE_CHECKSUM_LENGTH 2
#define PE_CHECKSUM_RESERVED_LENGTH 2

#define PE_CHECKSUM_OFFSET PARAMETER_VALUE_OFFSET
#define PE_CHECKSUM_RESERVED_OFFSET (PE_CHECKSUM_OFFSET + PE_CHECKSUM_LENGTH)

static void
dissect_pe_checksum_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_pe_checksum,          parameter_tvb, PE_CHECKSUM_OFFSET,          PE_CHECKSUM_LENGTH,          NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_pe_checksum_reserved, parameter_tvb, PE_CHECKSUM_RESERVED_OFFSET, PE_CHECKSUM_RESERVED_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (0x%x)", tvb_get_ntohs(parameter_tvb, PE_CHECKSUM_OFFSET));
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 type, parameter_value_length;

  type                   = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, NETWORK_BYTE_ORDER);

  proto_item_append_text(parameter_item, " (type %u and %u byte%s value)", type, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define IPV4_ADDRESS_PARAMETER_TYPE                 0x01
#define IPV6_ADDRESS_PARAMETER_TYPE                 0x02
#define SCTP_TRANSPORT_PARAMETER_TYPE               0x03
#define TCP_TRANSPORT_PARAMETER_TYPE                0x04
#define UDP_TRANSPORT_PARAMETER_TYPE                0x05
#define POOL_MEMBER_SELECTION_POLICY_PARAMETER_TYPE 0x06
#define POOL_HANDLE_PARAMETER_TYPE                  0x07
#define POOL_ELEMENT_PARAMETER_TYPE                 0x08
#define SERVER_INFORMATION_PARAMETER_TYPE           0x09
#define OPERATION_ERROR_PARAMETER_TYPE              0x0a
#define COOKIE_PARAMETER_TYPE                       0x0b
#define PE_IDENTIFIER_PARAMETER_TYPE                0x0c
#define PE_CHECKSUM_PARAMETER_TYPE                  0x0d

static const value_string parameter_type_values[] = {
  { IPV4_ADDRESS_PARAMETER_TYPE,                 "IPV4 address" },
  { IPV6_ADDRESS_PARAMETER_TYPE,                 "IPV6 address" },
  { SCTP_TRANSPORT_PARAMETER_TYPE,               "SCTP transport address" },
  { TCP_TRANSPORT_PARAMETER_TYPE,                "TCP transport address" },
  { UDP_TRANSPORT_PARAMETER_TYPE,                "UDP transport address" },
  { POOL_MEMBER_SELECTION_POLICY_PARAMETER_TYPE, "Pool member selection policy" },
  { POOL_HANDLE_PARAMETER_TYPE,                  "Pool handle" },
  { POOL_ELEMENT_PARAMETER_TYPE,                 "Pool element" },
  { SERVER_INFORMATION_PARAMETER_TYPE,           "Server Information" },
  { OPERATION_ERROR_PARAMETER_TYPE,              "Operation error" },
  { COOKIE_PARAMETER_TYPE,                       "Cookie" },
  { PE_IDENTIFIER_PARAMETER_TYPE,                "Pool Element identifier" },
  { PE_CHECKSUM_PARAMETER_TYPE,                  "PE checksum" },
  { 0,                                           NULL } };


static void
dissect_parameter(tvbuff_t *parameter_tvb, proto_tree *enrp_tree)
{
  guint16 type, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  type           = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(enrp_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), val_to_str(type, parameter_type_values, "Unknown parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_enrp_parameter);

  /* add tag and length to the enrp tree */
  proto_tree_add_item(parameter_tree, hf_parameter_type,   parameter_tvb, PARAMETER_TYPE_OFFSET,   PARAMETER_TYPE_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, NETWORK_BYTE_ORDER);

  switch(type) {
  case IPV4_ADDRESS_PARAMETER_TYPE:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV6_ADDRESS_PARAMETER_TYPE:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SCTP_TRANSPORT_PARAMETER_TYPE:
    dissect_sctp_transport_parameter(parameter_tvb, parameter_tree);
    break;
  case TCP_TRANSPORT_PARAMETER_TYPE:
    dissect_tcp_transport_parameter(parameter_tvb, parameter_tree);
    break;
  case UDP_TRANSPORT_PARAMETER_TYPE:
    dissect_udp_transport_parameter(parameter_tvb, parameter_tree);
    break;
  case POOL_MEMBER_SELECTION_POLICY_PARAMETER_TYPE:
    dissect_pool_member_selection_policy_parameter(parameter_tvb, parameter_tree);
    break;
  case POOL_HANDLE_PARAMETER_TYPE:
    dissect_pool_handle_parameter(parameter_tvb, parameter_tree);
    break;
  case POOL_ELEMENT_PARAMETER_TYPE:
    dissect_pool_element_parameter(parameter_tvb, parameter_tree);
    break;
  case SERVER_INFORMATION_PARAMETER_TYPE:
    dissect_server_information_parameter(parameter_tvb, parameter_tree);
    break;
  case OPERATION_ERROR_PARAMETER_TYPE:
    dissect_operation_error_parameter(parameter_tvb, parameter_tree);
    break;
  case COOKIE_PARAMETER_TYPE:
    dissect_cookie_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PE_IDENTIFIER_PARAMETER_TYPE:
    dissect_pe_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PE_CHECKSUM_PARAMETER_TYPE:
    dissect_pe_checksum_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, NETWORK_BYTE_ORDER);
}

static void
dissect_parameters(tvbuff_t *parameters_tvb, proto_tree *tree)
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
    dissect_parameter(parameter_tvb, tree);
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

/* Dissectors for messages. This is specific to ENRP */

#define MESSAGE_TYPE_LENGTH   1
#define MESSAGE_FLAGS_LENGTH  1
#define MESSAGE_LENGTH_LENGTH 2
#define MESSAGE_HEADER_LENGTH (MESSAGE_TYPE_LENGTH + MESSAGE_FLAGS_LENGTH + MESSAGE_LENGTH_LENGTH)

#define MESSAGE_TYPE_OFFSET   0
#define MESSAGE_FLAGS_OFFSET  (MESSAGE_TYPE_OFFSET   + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET (MESSAGE_FLAGS_OFFSET  + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_VALUE_OFFSET  (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)

#define SENDER_SERVERS_ID_LENGTH   4
#define RECEIVER_SERVERS_ID_LENGTH 4

#define SENDER_SERVERS_ID_OFFSET   MESSAGE_VALUE_OFFSET
#define RECEIVER_SERVERS_ID_OFFSET (SENDER_SERVERS_ID_OFFSET + SENDER_SERVERS_ID_LENGTH)
#define MESSAGE_PARAMETERS_OFFSET  (RECEIVER_SERVERS_ID_OFFSET + RECEIVER_SERVERS_ID_LENGTH)

#define REPLY_REQUIRED_BIT_MASK 0x01

static const true_false_string reply_required_bit_value = {
  "Reply required",
  "Reply not required"
};

static void
dissect_enrp_presence_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(flags_tree,   hf_reply_required_bit,  message_tvb, MESSAGE_FLAGS_OFFSET,       MESSAGE_FLAGS_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  parameters_tvb = tvb_new_subset(message_tvb, MESSAGE_PARAMETERS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, message_tree);
}

#define OWN_CHILDREN_ONLY_BIT_MASK 0x01

static const true_false_string own_children_only_bit_value = {
  "Only information for own PEs",
  "Information for all PEs"
};


static void
dissect_enrp_handle_table_request_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree)
{
  /* FIXME: ensure that the length is 12 bytes. */
  proto_tree_add_item(flags_tree,   hf_own_children_only_bit,  message_tvb, MESSAGE_FLAGS_OFFSET,       MESSAGE_FLAGS_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_sender_servers_id,      message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id,    message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
}

#define REJECT_BIT_MASK       0x01
#define MORE_TO_SEND_BIT_MASK 0x02

static const true_false_string reject_bit_value = {
  "Rejected",
  "Accepted"
};

static const true_false_string more_to_send_bit_value = {
  "More information available",
  "All information included"
};

static void
dissect_enrp_handle_table_response_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(flags_tree,   hf_more_to_send_bit,    message_tvb, MESSAGE_FLAGS_OFFSET,       MESSAGE_FLAGS_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(flags_tree,   hf_reject_bit,          message_tvb, MESSAGE_FLAGS_OFFSET,       MESSAGE_FLAGS_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  parameters_tvb = tvb_new_subset(message_tvb, MESSAGE_PARAMETERS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, message_tree);
}

#define UPDATE_ACTION_LENGTH 2
#define PNU_RESERVED_LENGTH  2

#define UPDATE_ACTION_OFFSET           (MESSAGE_VALUE_OFFSET + SENDER_SERVERS_ID_LENGTH + RECEIVER_SERVERS_ID_LENGTH)
#define PNU_RESERVED_OFFSET            (UPDATE_ACTION_OFFSET + UPDATE_ACTION_LENGTH)
#define PNU_MESSAGE_PARAMETERS_OFFSET  (PNU_RESERVED_OFFSET + PNU_RESERVED_LENGTH)

static const value_string update_action_values[] = {
  { 0, "Add pool element"    },
  { 1, "Delete pool element" },
  { 0, NULL                  } };

static void
dissect_enrp_handle_update_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_update_action,       message_tvb, UPDATE_ACTION_OFFSET,       UPDATE_ACTION_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_pmu_reserved,        message_tvb, PNU_RESERVED_OFFSET,        PNU_RESERVED_LENGTH,        NETWORK_BYTE_ORDER);
  parameters_tvb = tvb_new_subset(message_tvb, PNU_MESSAGE_PARAMETERS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, message_tree);
}

static void
dissect_enrp_list_request_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  /* FIXME: ensure that the length is 12 bytes. */
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
}

static void
dissect_enrp_list_response_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(flags_tree,   hf_reject_bit,          message_tvb, MESSAGE_FLAGS_OFFSET,       MESSAGE_FLAGS_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  parameters_tvb = tvb_new_subset(message_tvb, MESSAGE_PARAMETERS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, message_tree);
}

#define TARGET_SERVERS_ID_LENGTH 4
#define TARGET_SERVERS_ID_OFFSET (RECEIVER_SERVERS_ID_OFFSET + RECEIVER_SERVERS_ID_LENGTH)

static void
dissect_enrp_init_takeover_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  /* FIXME: ensure that the length is 16 bytes. */
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_target_servers_id,   message_tvb, TARGET_SERVERS_ID_OFFSET,   TARGET_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
}

static void
dissect_enrp_init_takeover_ack_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  /* FIXME: ensure that the length is 16 bytes. */
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_target_servers_id,   message_tvb, TARGET_SERVERS_ID_OFFSET,   TARGET_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
}

static void
dissect_enrp_init_takeover_server_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  /* FIXME: ensure that the length is 16 bytes. */
  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_target_servers_id,   message_tvb, TARGET_SERVERS_ID_OFFSET,   TARGET_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
}

static void
dissect_enrp_error_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(message_tree, hf_sender_servers_id,   message_tvb, SENDER_SERVERS_ID_OFFSET,   SENDER_SERVERS_ID_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(message_tree, hf_receiver_servers_id, message_tvb, RECEIVER_SERVERS_ID_OFFSET, RECEIVER_SERVERS_ID_LENGTH, NETWORK_BYTE_ORDER);
  parameters_tvb = tvb_new_subset(message_tvb, MESSAGE_PARAMETERS_OFFSET, -1, -1);
  dissect_parameters(parameters_tvb, message_tree);
}

static void
dissect_unknown_message(tvbuff_t *message_tvb, proto_tree *message_tree, proto_tree *flags_tree _U_)
{
  proto_tree_add_item(message_tree, hf_message_value, message_tvb, MESSAGE_VALUE_OFFSET, tvb_length(message_tvb) - MESSAGE_HEADER_LENGTH, NETWORK_BYTE_ORDER);
}

#define ENRP_PRESENCE_MESSAGE_TYPE              0x01
#define ENRP_HANDLE_TABLE_REQUEST_MESSAGE_TYPE  0x02
#define ENRP_HANDLE_TABLE_RESPONSE_MESSAGE_TYPE 0x03
#define ENRP_HANDLE_UPDATE_MESSAGE_TYPE         0x04
#define ENRP_LIST_REQUEST_MESSAGE_TYPE          0x05
#define ENRP_LIST_RESPONSE_MESSAGE_TYPE         0x06
#define ENRP_INIT_TAKEOVER_MESSAGE_TYPE         0x07
#define ENRP_INIT_TAKEOVER_ACK_MESSAGE_TYPE     0x08
#define ENRP_TAKEOVER_SERVER_MESSAGE_TYPE       0x09
#define ENRP_ERROR_MESSAGE_TYPE                 0x0a

static const value_string message_type_values[] = {
  { ENRP_PRESENCE_MESSAGE_TYPE,              "ENRP Presence" },
  { ENRP_HANDLE_TABLE_REQUEST_MESSAGE_TYPE,  "ENRP Handle Table Request" },
  { ENRP_HANDLE_TABLE_RESPONSE_MESSAGE_TYPE, "ENRP Handle Table Response" },
  { ENRP_HANDLE_UPDATE_MESSAGE_TYPE,         "ENRP Handle Update" },
  { ENRP_LIST_REQUEST_MESSAGE_TYPE,          "ENRP List Request" },
  { ENRP_LIST_RESPONSE_MESSAGE_TYPE,         "ENRP List Response" },
  { ENRP_INIT_TAKEOVER_MESSAGE_TYPE,         "ENRP Init Takeover" },
  { ENRP_INIT_TAKEOVER_ACK_MESSAGE_TYPE,     "ENRP Init Takeover Ack" },
  { ENRP_TAKEOVER_SERVER_MESSAGE_TYPE,       "ENRP Takeover Server" },
  { ENRP_ERROR_MESSAGE_TYPE,                 "ENRP Error" },
  { 0,                                       NULL } };

static void
dissect_enrp_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *enrp_tree)
{
  proto_item *flags_item;
  proto_tree *flags_tree;
  guint8 type;

  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  /* pinfo is NULL only if dissect_enrp_message is called from dissect_error cause */
  if (pinfo && (check_col(pinfo->cinfo, COL_INFO)))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown ENRP type"));

  if (enrp_tree) {
    proto_tree_add_item(enrp_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   NETWORK_BYTE_ORDER);
    flags_item = proto_tree_add_item(enrp_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  NETWORK_BYTE_ORDER);
    flags_tree  = proto_item_add_subtree(flags_item, ett_enrp_flags);
    proto_tree_add_item(enrp_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, NETWORK_BYTE_ORDER);
    switch (type) {
      case ENRP_PRESENCE_MESSAGE_TYPE:
        dissect_enrp_presence_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_HANDLE_TABLE_REQUEST_MESSAGE_TYPE:
        dissect_enrp_handle_table_request_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_HANDLE_TABLE_RESPONSE_MESSAGE_TYPE:
        dissect_enrp_handle_table_response_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_HANDLE_UPDATE_MESSAGE_TYPE:
        dissect_enrp_handle_update_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_LIST_REQUEST_MESSAGE_TYPE:
        dissect_enrp_list_request_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_LIST_RESPONSE_MESSAGE_TYPE:
        dissect_enrp_list_response_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_INIT_TAKEOVER_MESSAGE_TYPE:
        dissect_enrp_init_takeover_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_INIT_TAKEOVER_ACK_MESSAGE_TYPE:
        dissect_enrp_init_takeover_ack_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_TAKEOVER_SERVER_MESSAGE_TYPE:
        dissect_enrp_init_takeover_server_message(message_tvb, enrp_tree, flags_tree);
        break;
      case ENRP_ERROR_MESSAGE_TYPE:
        dissect_enrp_error_message(message_tvb, enrp_tree, flags_tree);
        break;
      default:
        dissect_unknown_message(message_tvb, enrp_tree, flags_tree);
        break;
    }
  }
}

static void
dissect_enrp(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *enrp_item;
  proto_tree *enrp_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENRP");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the enrp protocol tree */
    enrp_item = proto_tree_add_item(tree, proto_enrp, message_tvb, 0, -1, FALSE);
    enrp_tree = proto_item_add_subtree(enrp_item, ett_enrp);
  } else {
    enrp_tree = NULL;
  };
  /* dissect the message */
  dissect_enrp_message(message_tvb, pinfo, enrp_tree);
}

/* Register the protocol with Wireshark */
void
proto_register_enrp(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,           { "Type",                        "enrp.message_type",                             FT_UINT8,   BASE_DEC,  VALS(message_type_values),         0x0,                        "", HFILL } },
    { &hf_message_flags,          { "Flags",                       "enrp.message_flags",                            FT_UINT8,   BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_message_length,         { "Length",                      "enrp.message_length",                           FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_message_value,          { "Value",                       "enrp.message_value",                            FT_BYTES,   BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_cause_code,             { "Cause code",                  "enrp.cause_code",                               FT_UINT16,  BASE_HEX,  VALS(cause_code_values),           0x0,                        "", HFILL } },
    { &hf_cause_length,           { "Cause length",                "enrp.cause_length",                             FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_cause_info,             { "Cause info",                  "enrp.cause_info",                               FT_BYTES,   BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_cause_padding,          { "Padding",                     "enrp.cause_padding",                            FT_BYTES,   BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_parameter_type,         { "Parameter Type",              "enrp.parameter_type",                           FT_UINT16,  BASE_HEX,  VALS(parameter_type_values),       0x0,                        "", HFILL } },
    { &hf_parameter_length,       { "Parameter length",            "enrp.parameter_length",                         FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_parameter_value,        { "Parameter value",             "enrp.parameter_value",                          FT_BYTES,   BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_parameter_padding,      { "Padding",                     "enrp.parameter_padding",                        FT_BYTES,   BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_parameter_ipv4_address, { "IP Version 4 address",        "enrp.ipv4_address",                             FT_IPv4,    BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_parameter_ipv6_address, { "IP Version 6 address",        "enrp.ipv6_address",                             FT_IPv6,    BASE_NONE, NULL,                              0x0,                        "", HFILL } },
    { &hf_sctp_port,              { "Port",                        "enrp.sctp_transport_port",                      FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_transport_use,          { "Transport use",               "enrp.transport_use",                            FT_UINT16,  BASE_DEC,  VALS(transport_use_values),        0x0,                        "", HFILL } },
    { &hf_tcp_port,               { "Port",                        "enrp.tcp_transport_port",                       FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_udp_port,               { "Port",                        "enrp.udp_transport_port",                       FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_udp_reserved,           { "Reserved",                    "enrp.udp_transport_reserved",                   FT_UINT16,  BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_policy_type,            { "Policy type",                 "enrp.pool_member_slection_policy_type",         FT_UINT8,   BASE_DEC,  VALS(policy_type_values),          0x0,                        "", HFILL } },
    { &hf_policy_value,           { "Policy value",                "enrp.pool_member_slection_policy_value",        FT_INT24,   BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_pool_handle,            { "Pool handle",                 "enrp.pool_handle_pool_handle",                  FT_BYTES,   BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_pe_pe_identifier,       { "PE identifier",               "enrp.pool_element_pe_identifier",               FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_home_enrp_id,           { "Home ENRP server identifier", "enrp.pool_element_home_enrp_server_identifier", FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_reg_life,               { "Registration life",           "enrp.pool_element_registration_life",           FT_INT32,   BASE_DEC,  NULL,                              0x0,                        "", HFILL } },
    { &hf_server_identifier,      { "Server identifier",           "enrp.server_information_server_identifier",     FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_m_bit,                  { "M-Bit",                       "enrp.server_information_m_bit",                 FT_BOOLEAN, 32,        NULL,                              M_BIT_MASK,                 "", HFILL } },
    { &hf_reserved,               { "Reserved",                    "enrp.server_information_reserved",              FT_UINT32,  BASE_HEX,  NULL,                              RESERVED_MASK,              "", HFILL } },
    { &hf_cookie,                 { "Cookie",                      "enrp.cookie",                                   FT_BYTES,   BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_pe_identifier,          { "PE identifier",               "enrp.pe_identifier",                            FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_pe_checksum,            { "PE checksum",                 "enrp.pe_checksum",                              FT_UINT16,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_pe_checksum_reserved,   { "Reserved",                    "enrp.pe_checksum_reserved",                     FT_UINT16,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_sender_servers_id,      { "Sender server's ID",          "enrp.sender_servers_id",                        FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_receiver_servers_id,    { "Receiver server's ID",        "enrp.receiver_servers_id",                      FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_target_servers_id,      { "Target server's ID",          "enrp.target_servers_id",                        FT_UINT32,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_update_action,          { "Update action",               "enrp.update_action",                            FT_UINT16,  BASE_DEC,  VALS(update_action_values),        0x0,                        "", HFILL } },
    { &hf_pmu_reserved,           { "Reserved",                    "enrp.reserved",                                 FT_UINT16,  BASE_HEX,  NULL,                              0x0,                        "", HFILL } },
    { &hf_reply_required_bit,     { "R bit",                       "enrp.r_bit",                                    FT_BOOLEAN, 8,         TFS(&reply_required_bit_value),    REPLY_REQUIRED_BIT_MASK,    "", HFILL } },
    { &hf_own_children_only_bit,  { "W bit",                       "enrp.w_bit",                                    FT_BOOLEAN, 8,         TFS(&own_children_only_bit_value), OWN_CHILDREN_ONLY_BIT_MASK, "", HFILL } },
    { &hf_more_to_send_bit,       { "M bit",                       "enrp.m_bit",                                    FT_BOOLEAN, 8,         TFS(&more_to_send_bit_value),      MORE_TO_SEND_BIT_MASK,      "", HFILL } },
    { &hf_reject_bit,             { "R bit",                       "enrp.r_bit",                                    FT_BOOLEAN, 8,         TFS(&reject_bit_value),            REJECT_BIT_MASK,            "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_enrp,
    &ett_enrp_parameter,
    &ett_enrp_cause,
    &ett_enrp_flags,
  };

  /* Register the protocol name and description */
  proto_enrp = proto_register_protocol("Endpoint Handlespace Redundancy Protocol", "ENRP",  "enrp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_enrp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_enrp(void)
{
  dissector_handle_t enrp_handle;

  enrp_handle = create_dissector_handle(dissect_enrp, proto_enrp);
  dissector_add("sctp.ppi", ENRP_PAYLOAD_PROTOCOL_ID, enrp_handle);
/* The following line will be uncommented AFTER a port number is assinged. */
/* dissector_add("udp.port", ENRP_UDP_PORT,            enrp_handle);       */
}
