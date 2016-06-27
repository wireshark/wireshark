/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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

/*
 * TCP Convergence Layer - Minimum buffer sizes
 * For Data Packet require 5 bytes fixed plus
 * up to 4 additional for length SDV
 */

#define TCP_CONV_MIN_DATA_BUFFER        9


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

/* Payload Header Processing Flags */
#define PAYLOAD_PROCFLAGS_REPLICATE_MASK        0x01
#define PAYLOAD_PROCFLAGS_XMIT_STATUS           0x02
#define PAYLOAD_PROCFLAGS_DISCARD_FAILURE       0x04
#define PAYLOAD_PROCFLAGS_LAST_HEADER           0x08

/* Header Fixed Sizes */
#define TCP_CONV_HDR_DATA_FIXED_LENGTH  5
#define TCP_CONV_HDR_ACK_LENGTH         9
#define TCP_CONV_HDR_KEEP_ALIVE_LENGTH  1
#define TCP_CONV_HDR_SHUTDOWN_LENGTH    1

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

#define DTN_SCHEME_STR                  "dtn"
#define IPN_SCHEME_STR                  "ipn"

int evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount);
gint64 evaluate_sdnv_64(tvbuff_t *tvb, int offset, int *bytecount);


/* Special Functions to evaluate unsigned SDNVs with error indication
 *    bytecount returns the number bytes consumed
 *    value returns the actual value
 *
 *    result is TRUE (1) on success else FALSE (0)
 */
int evaluate_sdnv32(tvbuff_t *tvb, int offset, int *bytecount, guint32 *value);
int evaluate_sdnv64(tvbuff_t *tvb, int offset, int *bytecount, guint64 *value);

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
