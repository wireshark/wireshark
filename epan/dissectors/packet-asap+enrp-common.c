/* packet-asap+enrp-common.c
 * Common routines for
 * Aggregate Server Access Protocol (ASAP) and
 * Endpoint Handlespace Redundancy Protocol (ENRP)
 * It is hopefully (needs testing) compliant to
 * RFC 5352
 * RFC 5354
 * RFC 5356
 * https://tools.ietf.org/html/draft-dreibholz-rserpool-asap-hropt-27
 * https://tools.ietf.org/html/draft-dreibholz-rserpool-delay-26
 * https://tools.ietf.org/html/draft-dreibholz-rserpool-enrp-takeover-21
 *
 * Copyright 2008-2021 Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 * Copyright 2004-2007 Michael Tüxen <tuexen [AT] fh-muenster.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet-asap+enrp-common.h"

const value_string cause_code_values[] = {
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

const value_string policy_type_values[] = {
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

const value_string transport_use_values[] = {
  { TRANSPORT_USE_DATA_ONLY,          "Data only"         },
  { TRANSPORT_USE_DATA_PLUS_CONTROL,  "Data plus control" },
  { 0,                                NULL                } };

const value_string parameter_type_values[] = {
  { IPV4_ADDRESS_PARAMETER_TYPE,                 "IPv4 Address Parameter" },
  { IPV6_ADDRESS_PARAMETER_TYPE,                 "IPv6 Address Parameter" },
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

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
