/* packet-asap.c
 * Routines for Aggregate Server Access Protocol (ASAP)
 * It is hopefully (needs testing) compliant to
 * RFC 5352
 * RFC 5354
 * RFC 5356
 * http://www.ietf.org/internet-drafts/draft-dreibholz-asap-hropt-03.txt
 * http://www.ietf.org/internet-drafts/draft-dreibholz-rserpool-delay-02.txt
 *
 * The code is not as simple as possible for the current protocol
 * but allows to be easily adopted to future versions of the protocol.
 * I will reconsider this after the protocol is an RFC.
 *
 * TODO:
 *   - check message lengths
 *
 * Copyright 2004, 2005, 2006, 2007 Michael Tuexen <tuexen [AT] fh-muenster.de>
 * Copyright 2008 Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
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
static int proto_asap = -1;
static int hf_cause_code = -1;
static int hf_cause_length = -1;
static int hf_cause_info = -1;
static int hf_cause_padding = -1;
static int hf_message_type = -1;
static int hf_message_flags = -1;
static int hf_message_length = -1;
static int hf_parameter_type = -1;
static int hf_parameter_length = -1;
static int hf_parameter_value = -1;
static int hf_parameter_padding = -1;
static int hf_parameter_ipv4_address = -1;
static int hf_parameter_ipv6_address = -1;
static int hf_dccp_port = -1;
static int hf_dccp_reserved = -1;
static int hf_dccp_service_code = -1;
static int hf_sctp_port = -1;
static int hf_transport_use = -1;
static int hf_tcp_port = -1;
static int hf_udp_port = -1;
static int hf_udp_reserved = -1;
static int hf_udp_lite_port = -1;
static int hf_udp_lite_reserved = -1;
static int hf_policy_type = -1;
static int hf_policy_value = -1;
static int hf_policy_weight = -1;
static int hf_policy_priority = -1;
static int hf_policy_load = -1;
static int hf_policy_degradation = -1;
static int hf_policy_loaddpf = -1;
static int hf_policy_weightdpf = -1;
static int hf_policy_distance = -1;
static int hf_pool_handle = -1;
static int hf_pe_pe_identifier = -1;
static int hf_home_enrp_id = -1;
static int hf_reg_life = -1;
static int hf_server_identifier = -1;
static int hf_cookie = -1;
static int hf_pe_identifier = -1;
static int hf_pe_checksum = -1;
static int hf_hropt_items = -1;
static int hf_home_enrp_server_bit = -1;
static int hf_reject_bit = -1;

/* Initialize the subtree pointers */
static gint ett_asap = -1;
static gint ett_asap_parameter = -1;
static gint ett_asap_cause = -1;
static gint ett_asap_flags = -1;

static void
dissect_parameters(tvbuff_t *, proto_tree *);
static void
dissect_parameter(tvbuff_t *, proto_tree *);
static void
dissect_asap(tvbuff_t *, packet_info *, proto_tree *);

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

#define ASAP_UDP_PORT 3863
#define ASAP_TCP_PORT 3863
#define ASAP_SCTP_PORT 3863

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
    proto_tree_add_item(cause_tree, hf_cause_info, cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, ENC_NA);
  proto_item_append_text(cause_item, " (code %u and %u byte%s information)", code, cause_info_length, plurality(cause_info_length, "", "s"));
}

#define UNRECOGNIZED_PARAMETER_CAUSE_CODE                  0x1
#define UNRECONGNIZED_MESSAGE_CAUSE_CODE                   0x2
#define INVALID_VALUES                                     0x3
#define NON_UNIQUE_PE_IDENTIFIER                           0x4
#define POOLING_POLICY_INCONSISTENT_CAUSE_CODE             0x5
#define LACK_OF_RESOURCES_CAUSE_CODE                       0x6
#define INCONSISTENT_TRANSPORT_TYPE_CAUSE_CODE             0x7
#define INCONSISTENT_DATA_CONTROL_CONFIGURATION_CAUSE_CODE 0x8
#define UNKNOWN_POOL_HANDLE                                0x9
#define REJECTION_DUE_TO_SECURITY_CAUSE_CODE               0xa

static const value_string cause_code_values[] = {
  { UNRECOGNIZED_PARAMETER_CAUSE_CODE,                  "Unrecognized parameter"                  },
  { UNRECONGNIZED_MESSAGE_CAUSE_CODE,                   "Unrecognized message"                    },
  { INVALID_VALUES,                                     "Invalid values"                          },
  { NON_UNIQUE_PE_IDENTIFIER,                           "Non-unique PE identifier"                },
  { POOLING_POLICY_INCONSISTENT_CAUSE_CODE,             "Pooling policy inconsistent"             },
  { LACK_OF_RESOURCES_CAUSE_CODE,                       "Lack of resources"                       },
  { INCONSISTENT_TRANSPORT_TYPE_CAUSE_CODE,             "Inconsistent transport type"             },
  { INCONSISTENT_DATA_CONTROL_CONFIGURATION_CAUSE_CODE, "Inconsistent data/control type"          },
  { UNKNOWN_POOL_HANDLE,                                "Unknown pool handle"                     },
  { REJECTION_DUE_TO_SECURITY_CAUSE_CODE,               "Rejected due to security considerations" },
  { 0,                                                  NULL                                      } };

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

  cause_item = proto_tree_add_text(parameter_tree, cause_tvb, CAUSE_HEADER_OFFSET, tvb_length(cause_tvb), "%s", val_to_str(code, cause_code_values, "Unknown error cause"));
  cause_tree = proto_item_add_subtree(cause_item, ett_asap_cause);

  proto_tree_add_item(cause_tree, hf_cause_code,   cause_tvb, CAUSE_CODE_OFFSET,   CAUSE_CODE_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(cause_tree, hf_cause_length, cause_tvb, CAUSE_LENGTH_OFFSET, CAUSE_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(code) {
  case UNRECOGNIZED_PARAMETER_CAUSE_CODE:
    parameter_tvb = tvb_new_subset_remaining(cause_tvb, CAUSE_INFO_OFFSET);
    dissect_parameter(parameter_tvb, cause_tree);
    break;
  case UNRECONGNIZED_MESSAGE_CAUSE_CODE:
    message_tvb = tvb_new_subset_remaining(cause_tvb, CAUSE_INFO_OFFSET);
    dissect_asap(message_tvb, NULL, cause_tree);
    break;
    break;
  case INVALID_VALUES:
    parameter_tvb = tvb_new_subset_remaining(cause_tvb, CAUSE_INFO_OFFSET);
    dissect_parameter(parameter_tvb, cause_tree);
    break;
  case NON_UNIQUE_PE_IDENTIFIER:
    break;
  case POOLING_POLICY_INCONSISTENT_CAUSE_CODE:
    parameter_tvb = tvb_new_subset_remaining(cause_tvb, CAUSE_INFO_OFFSET);
    dissect_parameter(parameter_tvb, cause_tree);
    break;
  case LACK_OF_RESOURCES_CAUSE_CODE:
    break;
  case INCONSISTENT_TRANSPORT_TYPE_CAUSE_CODE:
    parameter_tvb = tvb_new_subset_remaining(cause_tvb, CAUSE_INFO_OFFSET);
    dissect_parameter(parameter_tvb, cause_tree);
    break;
  case INCONSISTENT_DATA_CONTROL_CONFIGURATION_CAUSE_CODE:
    break;
  case UNKNOWN_POOL_HANDLE:
    break;
  case REJECTION_DUE_TO_SECURITY_CAUSE_CODE:
    break;
  default:
    dissect_unknown_cause(cause_tvb, cause_tree, cause_item);
    break;
  }
  if (padding_length > 0)
    proto_tree_add_item(cause_tree, hf_cause_padding, cause_tvb, CAUSE_HEADER_OFFSET + length, padding_length, ENC_NA);
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
  proto_tree_add_item(parameter_tree, hf_parameter_ipv4_address, parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)", tvb_ip_to_str(parameter_tvb, IPV4_ADDRESS_OFFSET));
}

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_parameter_ipv6_address, parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH, ENC_NA);
  proto_item_append_text(parameter_item, " (%s)", tvb_ip6_to_str(parameter_tvb, IPV6_ADDRESS_OFFSET));
}

#define DCCP_PORT_LENGTH         2
#define DCCP_RESERVED_LENGTH     2
#define DCCP_SERVICE_CODE_LENGTH 4
#define DCCP_PORT_OFFSET         PARAMETER_VALUE_OFFSET
#define DCCP_RESERVED_OFFSET     (DCCP_PORT_OFFSET + DCCP_PORT_LENGTH)
#define DCCP_SERVICE_CODE_OFFSET (DCCP_RESERVED_OFFSET + DCCP_RESERVED_LENGTH)
#define DCCP_ADDRESS_OFFSET      (DCCP_SERVICE_CODE_OFFSET + DCCP_SERVICE_CODE_LENGTH)

static void
dissect_dccp_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_dccp_port,         parameter_tvb, DCCP_PORT_OFFSET,         DCCP_PORT_LENGTH,         ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dccp_reserved,     parameter_tvb, DCCP_RESERVED_OFFSET,     DCCP_RESERVED_LENGTH,     ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dccp_service_code, parameter_tvb, DCCP_SERVICE_CODE_OFFSET, DCCP_SERVICE_CODE_LENGTH, ENC_BIG_ENDIAN);

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, DCCP_ADDRESS_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree);
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

  proto_tree_add_item(parameter_tree, hf_sctp_port,     parameter_tvb, SCTP_PORT_OFFSET,          SCTP_PORT_LENGTH,          ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_transport_use, parameter_tvb, SCTP_TRANSPORT_USE_OFFSET, SCTP_TRANSPORT_USE_LENGTH, ENC_BIG_ENDIAN);

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, SCTP_ADDRESS_OFFSET);
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

  proto_tree_add_item(parameter_tree, hf_tcp_port,      parameter_tvb, TCP_PORT_OFFSET,          TCP_PORT_LENGTH,          ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_transport_use, parameter_tvb, TCP_TRANSPORT_USE_OFFSET, TCP_TRANSPORT_USE_LENGTH, ENC_BIG_ENDIAN);

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, TCP_ADDRESS_OFFSET);
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

  proto_tree_add_item(parameter_tree, hf_udp_port,     parameter_tvb, UDP_PORT_OFFSET,     UDP_PORT_LENGTH,     ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_udp_reserved, parameter_tvb, UDP_RESERVED_OFFSET, UDP_RESERVED_LENGTH, ENC_BIG_ENDIAN);

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, UDP_ADDRESS_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define UDP_LITE_PORT_LENGTH     2
#define UDP_LITE_RESERVED_LENGTH 2
#define UDP_LITE_PORT_OFFSET     PARAMETER_VALUE_OFFSET
#define UDP_LITE_RESERVED_OFFSET (UDP_LITE_PORT_OFFSET + UDP_LITE_PORT_LENGTH)
#define UDP_LITE_ADDRESS_OFFSET  (UDP_LITE_RESERVED_OFFSET + UDP_LITE_RESERVED_LENGTH)

static void
dissect_udp_lite_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_udp_lite_port,     parameter_tvb, UDP_LITE_PORT_OFFSET,     UDP_LITE_PORT_LENGTH,     ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_udp_lite_reserved, parameter_tvb, UDP_LITE_RESERVED_OFFSET, UDP_LITE_RESERVED_LENGTH, ENC_BIG_ENDIAN);

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, UDP_LITE_ADDRESS_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define POLICY_TYPE_LENGTH               4
#define POLICY_WEIGHT_LENGTH             4
#define POLICY_PRIORITY_LENGTH           4
#define POLICY_LOAD_LENGTH               4
#define POLICY_DEGRADATION_LENGTH        4
#define POLICY_LUDPF_LOADDPF_LENGTH      4
#define POLICY_LUDPF_DISTANCE_LENGTH     4
#define POLICY_WRANDDPF_WEIGHTDPF_LENGTH 4
#define POLICY_WRANDDPF_DISTANCE_LENGTH  4

#define POLICY_TYPE_OFFSET        PARAMETER_VALUE_OFFSET
#define POLICY_VALUE_OFFSET       (POLICY_TYPE_OFFSET + POLICY_TYPE_LENGTH)
#define POLICY_WEIGHT_OFFSET      POLICY_VALUE_OFFSET
#define POLICY_PRIORITY_OFFSET    POLICY_VALUE_OFFSET
#define POLICY_LOAD_OFFSET        POLICY_VALUE_OFFSET
#define POLICY_DEGRADATION_OFFSET (POLICY_LOAD_OFFSET + POLICY_LOAD_LENGTH)

#define POLICY_LUDPF_LOADDPF_OFFSET      (POLICY_LOAD_OFFSET + POLICY_LOAD_LENGTH)
#define POLICY_LUDPF_DISTANCE_OFFSET     (POLICY_LUDPF_LOADDPF_OFFSET + POLICY_LUDPF_LOADDPF_LENGTH)
#define POLICY_WRANDDPF_WEIGHTDPF_OFFSET (POLICY_WEIGHT_OFFSET + POLICY_WEIGHT_LENGTH)
#define POLICY_WRANDDPF_DISTANCE_OFFSET  (POLICY_WRANDDPF_WEIGHTDPF_OFFSET + POLICY_WRANDDPF_WEIGHTDPF_LENGTH)


#define ROUND_ROBIN_POLICY           0x00000001
#define WEIGHTED_ROUND_ROBIN_POLICY  0x00000002
#define RANDOM_POLICY                0x00000003
#define WEIGHTED_RANDOM_POLICY       0x00000004
#define PRIORITY_POLICY              0x00000005
#define LEAST_USED_POLICY            0x40000001
#define LEAST_USED_WITH_DEG_POLICY   0x40000002
#define PRIORITY_LEAST_USED_POLICY   0x40000003
#define RANDOMIZED_LEAST_USED_POLICY 0x40000004

#define PRIORITY_LEAST_USED_DEG_POLICY 0xb0001003
#define WEIGHTED_RANDOM_DPF_POLICY     0xb0002001
#define LEAST_USED_DPF_POLICY          0xb0002002

static const value_string policy_type_values[] = {
  { ROUND_ROBIN_POLICY,             "Round Robin (RR)" },
  { WEIGHTED_ROUND_ROBIN_POLICY,    "Weighted Round Robin (WRR)" },
  { RANDOM_POLICY,                  "Random (RAND)"},
  { WEIGHTED_RANDOM_POLICY,         "Weighted Random (WRAND)" },
  { PRIORITY_POLICY,                "Priority (PRI)" },
  { LEAST_USED_POLICY,              "Least Used (LU)" },
  { LEAST_USED_WITH_DEG_POLICY,     "Least Used with Degradation (LUD)" },
  { PRIORITY_LEAST_USED_POLICY,     "Priority Least Used (PLU)" },
  { PRIORITY_LEAST_USED_DEG_POLICY, "Priority Least Used with Degradation (PLUD)" },
  { RANDOMIZED_LEAST_USED_POLICY,   "Randomized Least Used (RLU)" },
  { LEAST_USED_DPF_POLICY,          "Least Used with Delay Penalty Factor (LU-DPF)" },
  { WEIGHTED_RANDOM_DPF_POLICY,     "Weighted Random with Delay Penalty Factor (WRAND-DPF)" },
  { 0,                              NULL } };

static void
dissect_pool_member_selection_policy_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  guint32 type;
  guint   length;

  proto_tree_add_item(parameter_tree, hf_policy_type,  parameter_tvb, POLICY_TYPE_OFFSET,  POLICY_TYPE_LENGTH,  ENC_BIG_ENDIAN);
  type = tvb_get_ntohl(parameter_tvb, POLICY_TYPE_OFFSET);
  switch (type) {
  case RANDOM_POLICY:
  case ROUND_ROBIN_POLICY:
    break;
  case WEIGHTED_RANDOM_POLICY:
  case WEIGHTED_ROUND_ROBIN_POLICY:
    proto_tree_add_item(parameter_tree, hf_policy_weight, parameter_tvb, POLICY_WEIGHT_OFFSET, POLICY_WEIGHT_LENGTH, ENC_BIG_ENDIAN);
    break;
  case PRIORITY_POLICY:
    proto_tree_add_item(parameter_tree, hf_policy_priority, parameter_tvb, POLICY_PRIORITY_OFFSET, POLICY_PRIORITY_LENGTH, ENC_BIG_ENDIAN);
    break;
  case LEAST_USED_POLICY:
  case RANDOMIZED_LEAST_USED_POLICY:
    proto_tree_add_double_format_value(parameter_tree, hf_policy_load, parameter_tvb, POLICY_LOAD_OFFSET, POLICY_LOAD_LENGTH,
                                       100.0 * tvb_get_ntohl(parameter_tvb, POLICY_LOAD_OFFSET) / (double)0xffffffff, "%1.2f%%",
                                       100.0 * tvb_get_ntohl(parameter_tvb, POLICY_LOAD_OFFSET) / (double)0xffffffff);
    break;
  case LEAST_USED_WITH_DEG_POLICY:
  case PRIORITY_LEAST_USED_POLICY:
    proto_tree_add_double_format_value(parameter_tree, hf_policy_load, parameter_tvb, POLICY_LOAD_OFFSET, POLICY_LOAD_LENGTH,
                                       100.0 * tvb_get_ntohl(parameter_tvb, POLICY_LOAD_OFFSET) / (double)0xffffffff, "%1.2f%%",
                                       100.0 * tvb_get_ntohl(parameter_tvb, POLICY_LOAD_OFFSET) / (double)0xffffffff);
    proto_tree_add_double_format_value(parameter_tree, hf_policy_degradation, parameter_tvb, POLICY_DEGRADATION_OFFSET, POLICY_DEGRADATION_LENGTH,
                                       100.0 * tvb_get_ntohl(parameter_tvb, POLICY_DEGRADATION_OFFSET) / (double)0xffffffff, "%1.2f%%",
                                       100.0 * tvb_get_ntohl(parameter_tvb, POLICY_DEGRADATION_OFFSET) / (double)0xffffffff);
    break;
  case LEAST_USED_DPF_POLICY:
    proto_tree_add_double_format_value(parameter_tree, hf_policy_load, parameter_tvb, POLICY_LOAD_OFFSET, POLICY_LOAD_LENGTH,
                                      100.0 * tvb_get_ntohl(parameter_tvb, POLICY_LOAD_OFFSET) / (double)0xffffffff, "%1.2f%%",
                                      100.0 * tvb_get_ntohl(parameter_tvb, POLICY_LOAD_OFFSET) / (double)0xffffffff);
    proto_tree_add_double_format_value(parameter_tree, hf_policy_loaddpf, parameter_tvb, POLICY_LUDPF_LOADDPF_OFFSET, POLICY_LUDPF_LOADDPF_LENGTH,
                                      tvb_get_ntohl(parameter_tvb, POLICY_LUDPF_LOADDPF_OFFSET) / (double)0xffffffff, "%1.5f",
                                      tvb_get_ntohl(parameter_tvb, POLICY_LUDPF_LOADDPF_OFFSET) / (double)0xffffffff);
    proto_tree_add_item(parameter_tree, hf_policy_distance, parameter_tvb, POLICY_LUDPF_DISTANCE_OFFSET, POLICY_LUDPF_DISTANCE_LENGTH, ENC_BIG_ENDIAN);
    break;
  case WEIGHTED_RANDOM_DPF_POLICY:
    proto_tree_add_item(parameter_tree, hf_policy_weight, parameter_tvb, POLICY_WEIGHT_OFFSET, POLICY_WEIGHT_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_double_format_value(parameter_tree, hf_policy_weightdpf, parameter_tvb, POLICY_WRANDDPF_WEIGHTDPF_OFFSET, POLICY_WRANDDPF_WEIGHTDPF_LENGTH,
                                       tvb_get_ntohl(parameter_tvb, POLICY_WRANDDPF_WEIGHTDPF_OFFSET) / (double)0xffffffff, "%1.5f",
                                       tvb_get_ntohl(parameter_tvb, POLICY_WRANDDPF_WEIGHTDPF_OFFSET) / (double)0xffffffff);
    proto_tree_add_item(parameter_tree, hf_policy_distance, parameter_tvb, POLICY_WRANDDPF_DISTANCE_OFFSET, POLICY_WRANDDPF_DISTANCE_LENGTH, ENC_BIG_ENDIAN);
    break;
  default:
    length = tvb_length(parameter_tvb) - POLICY_VALUE_OFFSET;
    if (length > 0) {
      proto_tree_add_item(parameter_tree, hf_policy_value, parameter_tvb, POLICY_VALUE_OFFSET, length, ENC_NA);
    }
    break;
  }
}

#define POOL_HANDLE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_pool_handle_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  guint16 handle_length;
  proto_item*    pi;
  char*          tmp;

  handle_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  pi = proto_tree_add_item(parameter_tree, hf_pool_handle, parameter_tvb, POOL_HANDLE_OFFSET, handle_length, ENC_NA);

  tmp = (gchar*)tvb_get_ephemeral_string(parameter_tvb, POOL_HANDLE_OFFSET, handle_length);
  proto_item_append_text(pi, " (%s)", tmp);
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
  tvbuff_t*   parameters_tvb;
  proto_item* pi;

  proto_tree_add_item(parameter_tree, hf_pe_pe_identifier, parameter_tvb, PE_PE_IDENTIFIER_OFFSET,      PE_PE_IDENTIFIER_LENGTH,      ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_home_enrp_id,     parameter_tvb, HOME_ENRP_INDENTIFIER_OFFSET, HOME_ENRP_INDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  pi = proto_tree_add_item(parameter_tree, hf_reg_life,    parameter_tvb, REGISTRATION_LIFE_OFFSET,     REGISTRATION_LIFE_LENGTH,     ENC_BIG_ENDIAN);
  proto_item_append_text(pi, "ms");

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, USER_TRANSPORT_PARAMETER_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define SERVER_ID_LENGTH         4
#define SERVER_ID_OFFSET         PARAMETER_VALUE_OFFSET
#define SERVER_TRANSPORT_OFFSET  (SERVER_ID_OFFSET + SERVER_ID_LENGTH)

static void
dissect_server_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *parameters_tvb;

  proto_tree_add_item(parameter_tree, hf_server_identifier, parameter_tvb, SERVER_ID_OFFSET, SERVER_ID_LENGTH, ENC_BIG_ENDIAN);

  parameters_tvb = tvb_new_subset_remaining(parameter_tvb, SERVER_TRANSPORT_OFFSET);
  dissect_parameters(parameters_tvb, parameter_tree);
}

#define ERROR_CAUSES_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_operation_error_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  tvbuff_t *error_causes_tvb;

  error_causes_tvb = tvb_new_subset_remaining(parameter_tvb, ERROR_CAUSES_OFFSET);
  dissect_error_causes(error_causes_tvb, parameter_tree);
}

#define COOKIE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_cookie_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 cookie_length;

  cookie_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (cookie_length > 0)
    proto_tree_add_item(parameter_tree, hf_cookie, parameter_tvb, COOKIE_OFFSET, cookie_length, ENC_NA);
  proto_item_append_text(parameter_item, " (%u byte%s)", cookie_length, plurality(cookie_length, "", "s"));
}

#define PE_IDENTIFIER_LENGTH 4
#define PE_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_pe_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_pe_identifier, parameter_tvb, PE_IDENTIFIER_OFFSET, PE_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (0x%x)", tvb_get_ntohl(parameter_tvb, PE_IDENTIFIER_OFFSET));
}

#define PE_CHECKSUM_LENGTH 2
#define PE_CHECKSUM_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_pe_checksum_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_pe_checksum, parameter_tvb, PE_CHECKSUM_OFFSET, PE_CHECKSUM_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (0x%x)", tvb_get_ntohs(parameter_tvb, PE_CHECKSUM_OFFSET));
}

#define HROPT_ITEMS_LENGTH 4
#define HROPT_ITEMS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_handle_resolution_option_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  proto_tree_add_item(parameter_tree, hf_hropt_items, parameter_tvb, HROPT_ITEMS_OFFSET, HROPT_ITEMS_LENGTH, ENC_BIG_ENDIAN);
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 type, parameter_value_length;

  type                   = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);

  proto_item_append_text(parameter_item, " (type %u and %u byte%s value)", type, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define IPV4_ADDRESS_PARAMETER_TYPE                 0x01
#define IPV6_ADDRESS_PARAMETER_TYPE                 0x02
#define DCCP_TRANSPORT_PARAMETER_TYPE               0x03
#define SCTP_TRANSPORT_PARAMETER_TYPE               0x04
#define TCP_TRANSPORT_PARAMETER_TYPE                0x05
#define UDP_TRANSPORT_PARAMETER_TYPE                0x06
#define UDP_LITE_TRANSPORT_PARAMETER_TYPE           0x07
#define POOL_MEMBER_SELECTION_POLICY_PARAMETER_TYPE 0x08
#define POOL_HANDLE_PARAMETER_TYPE                  0x09
#define POOL_ELEMENT_PARAMETER_TYPE                 0x0a
#define SERVER_INFORMATION_PARAMETER_TYPE           0x0b
#define OPERATION_ERROR_PARAMETER_TYPE              0x0c
#define COOKIE_PARAMETER_TYPE                       0x0d
#define PE_IDENTIFIER_PARAMETER_TYPE                0x0e
#define PE_CHECKSUM_PARAMETER_TYPE                  0x0f
#define HANDLE_RESOLUTION_OPTION_PARAMETER_TYPE     0x803f

static const value_string parameter_type_values[] = {
  { IPV4_ADDRESS_PARAMETER_TYPE,                 "IPV4 Address Parameter" },
  { IPV6_ADDRESS_PARAMETER_TYPE,                 "IPV6 Address Parameter" },
  { DCCP_TRANSPORT_PARAMETER_TYPE,               "DCCP Transport Address Parameter" },
  { SCTP_TRANSPORT_PARAMETER_TYPE,               "SCTP Transport Address Parameter" },
  { TCP_TRANSPORT_PARAMETER_TYPE,                "TCP Transport Address Parameter" },
  { UDP_TRANSPORT_PARAMETER_TYPE,                "UDP Transport Address Parameter" },
  { UDP_LITE_TRANSPORT_PARAMETER_TYPE,           "UDP-Lite Transport Address Parameter" },
  { POOL_MEMBER_SELECTION_POLICY_PARAMETER_TYPE, "Pool Member Selection Policy Parameter" },
  { POOL_HANDLE_PARAMETER_TYPE,                  "Pool Handle Parameter" },
  { POOL_ELEMENT_PARAMETER_TYPE,                 "Pool Element Parameter" },
  { SERVER_INFORMATION_PARAMETER_TYPE,           "Server Information Parameter" },
  { OPERATION_ERROR_PARAMETER_TYPE,              "Operation Error Parameter" },
  { COOKIE_PARAMETER_TYPE,                       "Cookie Parameter" },
  { PE_IDENTIFIER_PARAMETER_TYPE,                "Pool Element Identifier Parameter" },
  { PE_CHECKSUM_PARAMETER_TYPE,                  "PE Checksum Parameter" },
  { HANDLE_RESOLUTION_OPTION_PARAMETER_TYPE,     "Handle Resolution Option Parameter" },
  { 0,                                           NULL } };


static void
dissect_parameter(tvbuff_t *parameter_tvb, proto_tree *asap_tree)
{
  guint16 type, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  type           = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  /* create proto_tree stuff */
  parameter_item   = proto_tree_add_text(asap_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s", val_to_str(type, parameter_type_values, "Unknown Parameter"));
  parameter_tree   = proto_item_add_subtree(parameter_item, ett_asap_parameter);

  /* add tag and length to the asap tree */
  proto_tree_add_item(parameter_tree, hf_parameter_type,   parameter_tvb, PARAMETER_TYPE_OFFSET,   PARAMETER_TYPE_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(type) {
  case IPV4_ADDRESS_PARAMETER_TYPE:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV6_ADDRESS_PARAMETER_TYPE:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DCCP_TRANSPORT_PARAMETER_TYPE:
    dissect_dccp_transport_parameter(parameter_tvb, parameter_tree);
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
  case UDP_LITE_TRANSPORT_PARAMETER_TYPE:
    dissect_udp_lite_transport_parameter(parameter_tvb, parameter_tree);
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
  case HANDLE_RESOLUTION_OPTION_PARAMETER_TYPE:
    dissect_handle_resolution_option_parameter(parameter_tvb, parameter_tree);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
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

/* Dissectors for messages. This is specific to ASAP */

#define MESSAGE_TYPE_LENGTH   1
#define MESSAGE_FLAGS_LENGTH  1
#define MESSAGE_LENGTH_LENGTH 2

#define MESSAGE_TYPE_OFFSET   0
#define MESSAGE_FLAGS_OFFSET  (MESSAGE_TYPE_OFFSET   + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET (MESSAGE_FLAGS_OFFSET  + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_VALUE_OFFSET  (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)

#define REGISTRATION_MESSAGE_TYPE               0x01
#define DEREGISTRATION_MESSAGE_TYPE             0x02
#define REGISTRATION_RESPONSE_MESSAGE_TYPE      0x03
#define DEREGISTRATION_RESPONSE_MESSAGE_TYPE    0x04
#define HANDLE_RESOLUTION_MESSAGE_TYPE          0x05
#define HANDLE_RESOLUTION_RESPONSE_MESSAGE_TYPE 0x06
#define ENDPOINT_KEEP_ALIVE_MESSAGE_TYPE        0x07
#define ENDPOINT_KEEP_ALIVE_ACK_MESSAGE_TYPE    0x08
#define ENDPOINT_UNREACHABLE_MESSAGE_TYPE       0x09
#define SERVER_ANNOUNCE_MESSAGE_TYPE            0x0a
#define COOKIE_MESSAGE_TYPE                     0x0b
#define COOKIE_ECHO_MESSAGE_TYPE                0x0c
#define BUSINESS_CARD_MESSAGE_TYPE              0x0d
#define ERROR_MESSAGE_TYPE                      0x0e

static const value_string message_type_values[] = {
  { REGISTRATION_MESSAGE_TYPE,               "ASAP Registration" },
  { DEREGISTRATION_MESSAGE_TYPE,             "ASAP Deregistration" },
  { REGISTRATION_RESPONSE_MESSAGE_TYPE,      "ASAP Registration Response" },
  { DEREGISTRATION_RESPONSE_MESSAGE_TYPE,    "ASAP Deregistration Response" },
  { HANDLE_RESOLUTION_MESSAGE_TYPE,          "ASAP Handle Resolution" },
  { HANDLE_RESOLUTION_RESPONSE_MESSAGE_TYPE, "ASAP Handle Resolution Response" },
  { ENDPOINT_KEEP_ALIVE_MESSAGE_TYPE,        "ASAP Endpoint Keep-Alive" },
  { ENDPOINT_KEEP_ALIVE_ACK_MESSAGE_TYPE,    "ASAP Endpoint Keep-Alive Acknowledgement" },
  { ENDPOINT_UNREACHABLE_MESSAGE_TYPE,       "ASAP Endpoint Unreachable" },
  { SERVER_ANNOUNCE_MESSAGE_TYPE,            "ASAP Server Announce" },
  { COOKIE_MESSAGE_TYPE,                     "ASAP Cookie" },
  { COOKIE_ECHO_MESSAGE_TYPE,                "ASAP Cookie Echo" },
  { BUSINESS_CARD_MESSAGE_TYPE,              "ASAP Business Card" },
  { ERROR_MESSAGE_TYPE,                      "ASAP Error" },
  { 0,                                       NULL } };

#define SERVER_IDENTIFIER_OFFSET MESSAGE_VALUE_OFFSET
#define SERVER_IDENTIFIER_LENGTH 4

#define HOME_ENRP_SERVER_BIT_MASK 0x01
#define REJECT_BIT_MASK           0x01

static const true_false_string home_enrp_server_bit_value = {
  "Want to be new ENRP server",
  "Do not want to be new ENRP server"
};

static const true_false_string reject_bit_value = {
  "Rejected",
  "Accepted"
};

static void
dissect_asap_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *asap_tree)
{
  tvbuff_t *parameters_tvb;
  proto_item *flags_item;
  proto_tree *flags_tree;
  guint8 type;


  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  /* pinfo is NULL only if dissect_asap_message is called via dissect_error cause */
  if (pinfo)
   col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown ASAP type"));

  if (asap_tree) {
    proto_tree_add_item(asap_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   ENC_BIG_ENDIAN);
    flags_item = proto_tree_add_item(asap_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(flags_item, ett_asap_flags);
    if (type == REGISTRATION_RESPONSE_MESSAGE_TYPE) {
      proto_tree_add_item(flags_tree, hf_reject_bit, message_tvb, MESSAGE_FLAGS_OFFSET, MESSAGE_FLAGS_LENGTH, ENC_BIG_ENDIAN);
    }
    if (type == ENDPOINT_KEEP_ALIVE_MESSAGE_TYPE) {
      proto_tree_add_item(flags_tree, hf_home_enrp_server_bit, message_tvb, MESSAGE_FLAGS_OFFSET, MESSAGE_FLAGS_LENGTH, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(asap_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
    if ((type == SERVER_ANNOUNCE_MESSAGE_TYPE) || (type == ENDPOINT_KEEP_ALIVE_MESSAGE_TYPE)) {
      proto_tree_add_item(asap_tree, hf_server_identifier, message_tvb, SERVER_IDENTIFIER_OFFSET, SERVER_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
      parameters_tvb = tvb_new_subset_remaining(message_tvb, MESSAGE_VALUE_OFFSET + SERVER_IDENTIFIER_LENGTH);
    } else {
      parameters_tvb = tvb_new_subset_remaining(message_tvb, MESSAGE_VALUE_OFFSET);
    }
    dissect_parameters(parameters_tvb, asap_tree);
    }
}

static void
dissect_asap(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *asap_item;
  proto_tree *asap_tree;

  /* pinfo is NULL only if dissect_asap is called from dissect_error cause */
  if (pinfo)
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASAP");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the asap protocol tree */
    asap_item = proto_tree_add_item(tree, proto_asap, message_tvb, 0, -1, ENC_NA);
    asap_tree = proto_item_add_subtree(asap_item, ett_asap);
  } else {
    asap_tree = NULL;
  };
  /* dissect the message */
  dissect_asap_message(message_tvb, pinfo, asap_tree);
}

/* Register the protocol with Wireshark */
void
proto_register_asap(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,           { "Type",                        "asap.message_type",                             FT_UINT8,   BASE_DEC,  VALS(message_type_values),        0x0,                       NULL, HFILL } },
    { &hf_message_flags,          { "Flags",                       "asap.message_flags",                            FT_UINT8,   BASE_HEX,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_message_length,         { "Length",                      "asap.message_length",                           FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_cause_code,             { "Cause Code",                  "asap.cause_code",                               FT_UINT16,  BASE_HEX,  VALS(cause_code_values),          0x0,                       NULL, HFILL } },
    { &hf_cause_length,           { "Cause Length",                "asap.cause_length",                             FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_cause_info,             { "Cause Info",                  "asap.cause_info",                               FT_BYTES,   BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_cause_padding,          { "Padding",                     "asap.cause_padding",                            FT_BYTES,   BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_parameter_type,         { "Parameter Type",              "asap.parameter_type",                           FT_UINT16,  BASE_HEX,  VALS(parameter_type_values),      0x0,                       NULL, HFILL } },
    { &hf_parameter_length,       { "Parameter Length",            "asap.parameter_length",                         FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_parameter_value,        { "Parameter Value",             "asap.parameter_value",                          FT_BYTES,   BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_parameter_padding,      { "Padding",                     "asap.parameter_padding",                        FT_BYTES,   BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_parameter_ipv4_address, { "IP Version 4 Address",        "asap.ipv4_address",                             FT_IPv4,    BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_parameter_ipv6_address, { "IP Version 6 Address",        "asap.ipv6_address",                             FT_IPv6,    BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_dccp_port,              { "Port",                        "asap.dccp_transport_port",                      FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_dccp_reserved,          { "Reserved",                    "asap.dccp_transport_reserved",                  FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_dccp_service_code,      { "Service Code",                "asap.dccp_transport_service_code",              FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_sctp_port,              { "Port",                        "asap.sctp_transport_port",                      FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_transport_use,          { "Transport Use",               "asap.transport_use",                            FT_UINT16,  BASE_DEC,  VALS(transport_use_values),       0x0,                       NULL, HFILL } },
    { &hf_tcp_port,               { "Port",                        "asap.tcp_transport_port",                       FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_udp_port,               { "Port",                        "asap.udp_transport_port",                       FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_udp_reserved,           { "Reserved",                    "asap.udp_transport_reserved",                   FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_udp_lite_port,          { "Port",                        "asap.udp_lite_transport_port",                  FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_udp_lite_reserved,      { "Reserved",                    "asap.udp_lite_transport_reserved",              FT_UINT16,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_type,            { "Policy Type",                 "asap.pool_member_selection_policy_type",        FT_UINT32,  BASE_HEX,  VALS(policy_type_values),         0x0,                       NULL, HFILL } },
    { &hf_policy_weight,          { "Policy Weight",               "asap.pool_member_selection_policy_weight",      FT_UINT32,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_priority,        { "Policy Priority",             "asap.pool_member_selection_policy_priority",    FT_UINT32,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_load,            { "Policy Load",                 "asap.pool_member_selection_policy_load",        FT_DOUBLE,  BASE_NONE,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_degradation,     { "Policy Degradation",          "asap.pool_member_selection_policy_degradation", FT_DOUBLE,  BASE_NONE,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_loaddpf,         { "Policy Load DPF",             "asap.pool_member_selection_policy_load_dpf",    FT_DOUBLE,  BASE_NONE,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_weightdpf,       { "Policy Weight DPF",           "asap.pool_member_selection_policy_weight_dpf",  FT_DOUBLE,  BASE_NONE,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_distance,        { "Policy Distance",             "asap.pool_member_selection_policy_distance",    FT_UINT32,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_policy_value,           { "Policy Value",                "asap.pool_member_selection_policy_value",       FT_BYTES,   BASE_NONE, NULL,                             0x0,                       NULL, HFILL } },
    { &hf_pool_handle,            { "Pool Handle",                 "asap.pool_handle_pool_handle",                  FT_BYTES,   BASE_NONE,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_pe_pe_identifier,       { "PE Identifier",               "asap.pool_element_pe_identifier",               FT_UINT32,  BASE_HEX,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_home_enrp_id,           { "Home ENRP Server Identifier", "asap.pool_element_home_enrp_server_identifier", FT_UINT32,  BASE_HEX,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_reg_life,               { "Registration Life",           "asap.pool_element_registration_life",           FT_INT32,   BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_cookie,                 { "Cookie",                      "asap.cookie",                                   FT_BYTES,   BASE_NONE,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_pe_identifier,          { "PE Identifier",               "asap.pe_identifier",                            FT_UINT32,  BASE_HEX,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_pe_checksum,            { "PE Checksum",                 "asap.pe_checksum",                              FT_UINT32,  BASE_HEX,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_hropt_items,            { "Items",                       "asap.hropt_items",                              FT_UINT32,  BASE_DEC,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_server_identifier,      { "Server Identifier",           "asap.server_identifier",                        FT_UINT32,  BASE_HEX,  NULL,                             0x0,                       NULL, HFILL } },
    { &hf_home_enrp_server_bit,   { "H Bit",                       "asap.h_bit",                                    FT_BOOLEAN, 8,         TFS(&home_enrp_server_bit_value), HOME_ENRP_SERVER_BIT_MASK, NULL, HFILL } },
    { &hf_reject_bit,             { "R Bit",                       "asap.r_bit",                                    FT_BOOLEAN, 8,         TFS(&reject_bit_value),           REJECT_BIT_MASK,           NULL, HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_asap,
    &ett_asap_flags,
    &ett_asap_parameter,
    &ett_asap_cause,
  };

  /* Register the protocol name and description */
  proto_asap = proto_register_protocol("Aggregate Server Access Protocol", "ASAP",  "asap");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_asap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_asap(void)
{
  dissector_handle_t asap_handle;

  asap_handle = create_dissector_handle(dissect_asap, proto_asap);
  dissector_add_uint("sctp.ppi",  ASAP_PAYLOAD_PROTOCOL_ID, asap_handle);
  dissector_add_uint("udp.port",  ASAP_UDP_PORT,  asap_handle);
  dissector_add_uint("tcp.port",  ASAP_TCP_PORT,  asap_handle);
  dissector_add_uint("sctp.port", ASAP_SCTP_PORT, asap_handle);
}
