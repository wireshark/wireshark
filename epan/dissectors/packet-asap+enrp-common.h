/* packet-lisp.h
 * Routines for Locator/ID Separation Protocol (LISP) Control Message dissection
 * Copyright 2018 Lorand Jakab <ljakab@ac.upc.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ASAP_ENRP_COMMON_H__
#define __PACKET_ASAP_ENRP_COMMON_H__

#include <epan/packet.h>


#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)


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

extern const value_string cause_code_values[];


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

extern const value_string policy_type_values[];


#define TRANSPORT_USE_DATA_ONLY         0
#define TRANSPORT_USE_DATA_PLUS_CONTROL 1

extern const value_string transport_use_values[];


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

extern const value_string parameter_type_values[];

#endif /* __PACKET_ASAP_ENRP_COMMON_H__ */
