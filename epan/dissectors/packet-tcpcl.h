/* packet-tcpcl.h
 * References:
 *     RFC 7242: https://tools.ietf.org/html/rfc7242
 *     RFC 9174: https://www.rfc-editor.org/rfc/rfc9174.html
 *
 * TCPCLv4 portions copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
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
#ifndef PACKET_TCPCL_H
#define PACKET_TCPCL_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Extension points for TCPCLv4 are available as:
 * For session extension item dissectors, the dissector table
 * "tcpcl.v4.sess_ext" has a FT_UINT16 key for registering.
 * For transfer extension item dissectors, the dissector table
 * "tcpcl.v4.xfer_ext" has a FT_UINT16 key for registering.
 * Both have user data dissection context which is obtained with the
 * tcpcl_dissect_ctx_get() function.
 */

/* TCP Convergence Layer v3 - Message Types */
typedef enum {
    TCPCLV3_TYPE_MASK = 0xf0,
    TCPCLV3_DATA_SEGMENT = 0x10,
    TCPCLV3_ACK_SEGMENT = 0x20,
    TCPCLV3_REFUSE_BUNDLE = 0x30,
    TCPCLV3_KEEP_ALIVE = 0x40,
    TCPCLV3_SHUTDOWN = 0x50,
    TCPCLV3_LENGTH = 0x60,
} Tcpclv3MessageType;

/* TCP Convergence Layer - Contact Header Flags */
typedef enum {
    TCPCLV3_BUNDLE_ACK_FLAG = 0x01,
    TCPCLV3_REACTIVE_FRAG_FLAG = 0x02,
    TCPCLV3_CONNECTOR_RCVR_FLAG = 0x04,
} Tcpclv3ContactFlag;

/* TCP Convergence Layer - Data Segment Flags */
typedef enum {
    TCPCLV3_DATA_FLAGS = 0x03,
    TCPCLV3_DATA_END_FLAG = 0x01,
    TCPCLV3_DATA_START_FLAG = 0x02,
} Tcpclv3DataSegmentFlag;

/* TCP Convergence Layer - Shutdown Segment Flags */
typedef enum {
    TCPCLV3_SHUTDOWN_FLAGS = 0x03,
    TCPCLV3_SHUTDOWN_REASON = 0x02,
    TCPCLV3_SHUTDOWN_DELAY = 0x01,
} Tcpclv3ShutdownFlag;

/* REFUSE-BUNDLE Reason-Codes */
typedef enum {
    TCPCLV3_REFUSE_REASON_UNKNOWN = 0x00,
    TCPCLV3_REFUSE_REASON_RX_COMPLETE = 0x01,
    TCPCLV3_REFUSE_REASON_RX_EXHAUSTED = 0x02,
    TCPCLV3_REFUSE_REASON_RX_RETRANSMIT = 0x03,
    /* 0x4-0x7 - Unassigned
     * 0x8-0xf - Reserved for future Use */
} Tcpclv3RefuseType;

typedef enum {
    TCPCLV4_MSGTYPE_INVALID = 0x00,
    TCPCLV4_MSGTYPE_XFER_SEGMENT = 0x01,
    TCPCLV4_MSGTYPE_XFER_ACK = 0x02,
    TCPCLV4_MSGTYPE_XFER_REFUSE = 0x03,
    TCPCLV4_MSGTYPE_KEEPALIVE = 0x04,
    TCPCLV4_MSGTYPE_SESS_TERM = 0x05,
    TCPCLV4_MSGTYPE_MSG_REJECT = 0x06,
    TCPCLV4_MSGTYPE_SESS_INIT = 0x07,
} Tcpclv4MessageType;

typedef enum {
    TCPCLV4_SESSEXT_INVALID = 0x00,
} Tcpclv4SessExtenionType;

typedef enum {
    TCPCLV4_XFEREXT_INVALID = 0x00,
    TCPCLV4_XFEREXT_TRANSFER_LEN = 0x01,
} Tcpclv4XferExtenionType;

typedef enum {
    TCPCLV4_CONTACT_FLAG_CANTLS = 0x01,
} Tcpclv4ContactFlag;

typedef enum {
    TCPCLV4_SESS_TERM_FLAG_REPLY = 0x01,
} Tcpclv4SessTermFlag;

typedef enum {
    TCPCLV4_TRANSFER_FLAG_START = 0x02,
    TCPCLV4_TRANSFER_FLAG_END = 0x01,
} Tcpclv4TransferFlag;

typedef enum {
    TCPCLV4_EXTENSION_FLAG_CRITICAL = 0x01,
} Tcpclv4ExtensionFlag;

/// Finer grained locating than just the frame number
typedef struct {
    /// Index of the frame
    uint32_t frame_num;
    /// Source index within the frame
    int src_ix;
    /// Offset within the source TVB
    int raw_offset;
} tcpcl_frame_loc_t;

typedef struct {
    /// Ordered list of seg_meta_t* for XFER_SEGMENT as seen in the first scan.
    wmem_list_t *seg_list;

    /// Ordered list of ack_meta_t* for XFER_ACK as seen in the first scan.
    wmem_list_t *ack_list;

    /// Optional Transfer Length extension
    uint64_t *total_length;
} tcpcl_transfer_t;

typedef struct {
    /// Address for this peer
    address addr;
    /// Port for the this peer
    uint32_t port;

    /// True if a contact header was not seen at the start of connection
    bool chdr_missing;
    /// Frame number in which the contact header starts
    tcpcl_frame_loc_t *chdr_seen;
    /// TCPCL version seen from this peer
    uint8_t version;
    /// CAN_TLS flag from the contact header
    bool can_tls;

    /// Frame number in which the v4 SESS_INIT message starts
    tcpcl_frame_loc_t *sess_init_seen;
    /// Keepalive duration (s) from v4 SESS_INIT
    uint16_t keepalive;
    /// Segment MRU
    uint64_t segment_mru;
    /// Transfer MRU
    uint64_t transfer_mru;

    /// Frame number in which the SESS_TERM message starts
    tcpcl_frame_loc_t *sess_term_seen;
    /// SESS_TERM reason
    uint8_t sess_term_reason;

    /// Map from tcpcl_frame_loc_t* to possible associated transfer ID uint64_t*
    wmem_map_t *frame_loc_to_transfer;

    /// Map from transfer ID uint64_t* to tcpcl_transfer_t* sent from this peer
    wmem_map_t *transfers;
} tcpcl_peer_t;

/// Persistent state associated with a TCP conversation
typedef struct {
    /// Information for the active side of the session
    tcpcl_peer_t *active;
    /// Information for the passive side of the session
    tcpcl_peer_t *passive;

    /// Set to the first TCPCL version seen.
    /// Used later for validity check.
    uint8_t *version;
    /// True when contact negotiation is finished
    bool contact_negotiated;
    /// Negotiated use of TLS from @c can_tls of the peers
    bool session_use_tls;
    /// The last frame before TLS handshake
    tcpcl_frame_loc_t *session_tls_start;

    /// True when session negotiation is finished
    bool sess_negotiated;
    /// Negotiated session keepalive
    uint16_t sess_keepalive;
} tcpcl_conversation_t;

/// Context for a single packet dissection
typedef struct {
    tcpcl_conversation_t *convo;
    /// Dissection cursor
    tcpcl_frame_loc_t *cur_loc;
    /// True if the dissection is on a contact header
    bool is_contact;
    /// The sending peer
    tcpcl_peer_t *tx_peer;
    /// The receiving peer
    tcpcl_peer_t *rx_peer;
    /// Possible transfer payload
    tvbuff_t *xferload;
} tcpcl_dissect_ctx_t;

/** Initialize members of the dissection context.
 *
 * @param pinfo Packet info for the frame.
 * @param tvb The buffer dissected.
 * @param offset The start offset.
 * @return ctx The new packet context.
 */
WS_DLL_PUBLIC
tcpcl_dissect_ctx_t * tcpcl_dissect_ctx_get(tvbuff_t *tvb, packet_info *pinfo, const int offset);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_TCPCL_H */

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
