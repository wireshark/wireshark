/* packet-bpv6.h
 * References:
 *     RFC 5050: https://tools.ietf.org/html/rfc5050
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
#ifndef PACKET_BPV6_H
#define PACKET_BPV6_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BUNDLE_PORT 4556

#define BUNDLE_PROCFLAGS_FRAG_MASK      0x01
#define BUNDLE_PROCFLAGS_ADMIN_MASK     0x02
#define BUNDLE_PROCFLAGS_DONTFRAG_MASK  0x04
#define BUNDLE_PROCFLAGS_XFERREQ_MASK   0x08
#define BUNDLE_PROCFLAGS_SINGLETON_MASK 0x10
#define BUNDLE_PROCFLAGS_APP_ACK_MASK   0x20

#define BUNDLE_COSFLAGS_PRIORITY_MASK   0x03
#define BUNDLE_COSFLAGS_PRIORITY_BULK   0x00
#define BUNDLE_COSFLAGS_PRIORITY_NORMAL 0x01
#define BUNDLE_COSFLAGS_PRIORITY_EXP    0x02

#define BUNDLE_SRRFLAGS_REPORT_MASK     0x01
#define BUNDLE_SRRFLAGS_CUSTODY_MASK    0x02
#define BUNDLE_SRRFLAGS_FORWARD_MASK    0x04
#define BUNDLE_SRRFLAGS_DELIVERY_MASK   0x08
#define BUNDLE_SRRFLAGS_DELETION_MASK   0x10
#define BUNDLE_SRRFLAGS_ACK_MASK        0x20

/* Header Processing Flags (non-primary) */
#define HEADER_PROCFLAGS_REPLICATE      0x01
#define HEADER_PROCFLAGS_XMIT_STATUS    0x02
#define HEADER_PROCFLAGS_DISCARD        0x04
#define HEADER_PROCFLAGS_LAST_HEADER    0x08

/* Header Types (excluding Primary Header) */
#define BUNDLE_BLOCK_TYPE_PAYLOAD               0x01 /* RFC5050 */
#define BUNDLE_BLOCK_TYPE_AUTHENTICATION        0x02 /* RFC6257 */
#define BUNDLE_BLOCK_TYPE_INTEGRITY             0x03 /* RFC6257 */
#define BUNDLE_BLOCK_TYPE_CONFIDENTIALITY       0x04 /* RFC6257 */
#define BUNDLE_BLOCK_TYPE_PREVIOUS_HOP_INSERT   0x05 /* RFC6259 */
#define BUNDLE_BLOCK_TYPE_METADATA_EXTENSION    0x08 /* RFC6258 */
#define BUNDLE_BLOCK_TYPE_EXTENSION_SECURITY    0x09 /* RFC6257 */
#define BUNDLE_BLOCK_TYPE_CUSTODY_TRANSFER      0x0a /* http://bioserve.colorado.edu/bp-acs/ */
#define BUNDLE_BLOCK_TYPE_EXTENDED_COS          0x13 /* http://tools.ietf.org/html/draft-irtf-dtnrg-ecos-02 */
#define BUNDLE_BLOCK_TYPE_BUNDLE_AGE            0x14 /* https://tools.ietf.org/html/draft-irtf-dtnrg-bundle-age-block-01 */

/* Payload Header Processing Flags */
#define PAYLOAD_PROCFLAGS_REPLICATE_MASK        0x01
#define PAYLOAD_PROCFLAGS_XMIT_STATUS           0x02
#define PAYLOAD_PROCFLAGS_DISCARD_FAILURE       0x04
#define PAYLOAD_PROCFLAGS_LAST_HEADER           0x08

/* Administrative Record Definitions */
#define ADMIN_REC_TYPE_STATUS_REPORT            0x01
#define ADMIN_REC_TYPE_CUSTODY_SIGNAL           0x02
#define ADMIN_REC_TYPE_AGGREGATE_CUSTODY_SIGNAL 0x04
#define ADMIN_REC_TYPE_ANNOUNCE_BUNDLE          0x05

#define ADMIN_REC_FLAGS_FRAGMENT        0x01
#define ADMIN_REC_CUSTODY_REASON_MASK   0x7f

/* Bundle Status Report Flags */
#define ADMIN_STATUS_FLAGS_RECEIVED     0x01
#define ADMIN_STATUS_FLAGS_ACCEPTED     0x02
#define ADMIN_STATUS_FLAGS_FORWARDED    0x04
#define ADMIN_STATUS_FLAGS_DELIVERED    0x08
#define ADMIN_STATUS_FLAGS_DELETED      0x10
#define ADMIN_STATUS_FLAGS_ACKNOWLEDGED 0x20

/* Block Processing Control Flags (Version 5) */
#define BLOCK_CONTROL_REPLICATE         0x01
#define BLOCK_CONTROL_TRANSMIT_STATUS   0x02
#define BLOCK_CONTROL_DELETE_BUNDLE     0x04
#define BLOCK_CONTROL_LAST_BLOCK        0x08
#define BLOCK_CONTROL_DISCARD_BLOCK     0x10
#define BLOCK_CONTROL_NOT_PROCESSED     0x20
#define BLOCK_CONTROL_EID_REFERENCE     0x40

/* ECOS Flags */
#define ECOS_FLAGS_CRITICAL             0x01
#define ECOS_FLAGS_STREAMING            0x02
#define ECOS_FLAGS_FLOWLABEL            0x04
#define ECOS_FLAGS_RELIABLE             0x08

/* Ciphersuite Flags */
#define BLOCK_CIPHERSUITE_PARAMS        0x01

#define DTN_SCHEME_STR                  "dtn"
#define IPN_SCHEME_STR                  "ipn"

#ifdef __cplusplus
}
#endif

#endif /* PACKET_AMP_H */

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
