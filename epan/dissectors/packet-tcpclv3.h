/* packet-tcpclv3.h
 * References:
 *     RFC 7242: https://tools.ietf.org/html/rfc7242
 *
 * Copyright 2006-2007 The MITRE Corporation.
 * All Rights Reserved.
 * Approved for Public Release; Distribution Unlimited.
 * Tracking Number 07-0090.
 *
 * The US Government will not be charged any license fee and/or royalties
 * related to this software. Neither name of The MITRE Corporation; nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_TCPCLV3_H
#define PACKET_TCPCLV3_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TCP Convergence Layer - Message Types */
#define TCP_CONV_MSG_TYPE_DATA          0x01
#define TCP_CONV_MSG_TYPE_ACK           0x02
#define TCP_CONV_MSG_TYPE_KEEP_ALIVE    0x03
#define TCP_CONV_MSG_TYPE_SHUTDOWN      0x04

/* TCP Convergence Layer (3) - Message Types */
#define TCP_CONVERGENCE_TYPE_MASK       0xf0
#define TCP_CONVERGENCE_DATA_SEGMENT    0x10
#define TCP_CONVERGENCE_ACK_SEGMENT     0x20
#define TCP_CONVERGENCE_REFUSE_BUNDLE   0x30
#define TCP_CONVERGENCE_KEEP_ALIVE      0x40
#define TCP_CONVERGENCE_SHUTDOWN        0x50
#define TCP_CONVERGENCE_LENGTH          0x60

/* TCP Convergence Layer - Contact Header Flags */
#define TCP_CONV_BUNDLE_ACK_FLAG        0x01
#define TCP_CONV_REACTIVE_FRAG_FLAG     0x02
#define TCP_CONV_CONNECTOR_RCVR_FLAG    0x04

/* TCP Convergence Layer - Data Segment Flags */
#define TCP_CONVERGENCE_DATA_FLAGS      0x03
#define TCP_CONVERGENCE_DATA_END_FLAG   0x01
#define TCP_CONVERGENCE_DATA_START_FLAG 0x02

/* TCP Convergence Layer - Shutdown Segment Flags */
#define TCP_CONVERGENCE_SHUTDOWN_FLAGS  0x03
#define TCP_CONVERGENCE_SHUTDOWN_REASON 0x02
#define TCP_CONVERGENCE_SHUTDOWN_DELAY  0x01

/* REFUSE-BUNDLE Reason-Codes */
#define TCP_REFUSE_BUNDLE_REASON_UNKNOWN       0x00
#define TCP_REFUSE_BUNDLE_REASON_RX_COMPLETE   0x01
#define TCP_REFUSE_BUNDLE_REASON_RX_EXHAUSTED  0x02
#define TCP_REFUSE_BUNDLE_REASON_RX_RETRANSMIT 0x03
/* 0x4-0x7 - Unassigned
 * 0x8-0xf - Reserved for future Use */

/*
 * TCP Convergence Layer - Minimum buffer sizes
 * For Data Packet require 5 bytes fixed plus
 * up to 4 additional for length SDV
 */

#define TCP_CONV_MIN_DATA_BUFFER        9

/* Header Fixed Sizes */
#define TCP_CONV_HDR_DATA_FIXED_LENGTH  5
#define TCP_CONV_HDR_ACK_LENGTH         9
#define TCP_CONV_HDR_KEEP_ALIVE_LENGTH  1
#define TCP_CONV_HDR_SHUTDOWN_LENGTH    1

#ifdef __cplusplus
}
#endif

#endif /* PACKET_TCPCLV3_H */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
