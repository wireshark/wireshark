/* packet-infiniband_sdp.c
 * Routines for Infiniband Sockets Direct Protocol dissection
 * Copyright 2010, Mellanox Technologies Ltd.
 * Code by Amir Vadai and Slava Koyfman.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>         /* needed to define AF_ values on UNIX */
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>           /* needed to define AF_ values on Windows */
#endif
#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include "packet-infiniband.h"

/* If the service-id is non-zero after being ANDed with the following mask then
   this is SDP traffic */
#define SERVICE_ID_MASK 0x0000000000010000

/* Forward declaration we need below (for using proto_reg_handoff as a prefs callback) */
void proto_reg_handoff_ib_sdp(void);

static int proto_infiniband = -1;   /* we'll need the Infiniband protocol index sometimes, so keep it here */

/* Initialize the protocol and registered fields... */
static int proto_ib_sdp = -1;

static int hf_ib_sdp = -1;

/* IB SDP BSDH Header */
static int hf_ib_sdp_bsdh = -1;
static int hf_ib_sdp_mid = -1;
static int hf_ib_sdp_flags = -1;
static int hf_ib_sdp_flags_oobpres  = -1;
static int hf_ib_sdp_flags_oob_pend = -1;
static int hf_ib_sdp_flags_reqpipe  = -1;

static int hf_ib_sdp_len = -1;
static int hf_ib_sdp_bufs = -1;
static int hf_ib_sdp_mseq = -1;
static int hf_ib_sdp_mseqack = -1;

/* IB SDP Hello Header */
static int hf_ib_sdp_hh = -1;
static int hf_ib_sdp_majv = -1;
static int hf_ib_sdp_minv = -1;
static int hf_ib_sdp_ipv = -1;
static int hf_ib_sdp_cap = -1;
static int hf_ib_sdp_cap_invalidate = -1;
static int hf_ib_sdp_cap_extmaxadverts = -1;
static int hf_ib_sdp_maxadverts = -1;
static int hf_ib_sdp_desremrcvsz = -1;
static int hf_ib_sdp_localrcvsz = -1;
static int hf_ib_sdp_localport = -1;
static int hf_ib_sdp_src_ip = -1;
static int hf_ib_sdp_dst_ip = -1;
static int hf_ib_sdp_extmaxadverts = -1;
static int hf_ib_sdp_hah = -1;
static int hf_ib_sdp_rwch = -1;
static int hf_ib_sdp_rrch = -1;
static int hf_ib_sdp_mch = -1;
static int hf_ib_sdp_crbh = -1;
static int hf_ib_sdp_crbah = -1;
static int hf_ib_sdp_suspch = -1;
static int hf_ib_sdp_sinkah = -1;
static int hf_ib_sdp_srcah = -1;
static int hf_ib_sdp_data = -1;

/* Initialize the subtree pointers */
static gint ett_ib_sdp = -1;
static gint ett_ib_sdp_bsdh = -1;
static gint ett_ib_sdp_hh = -1;

/* global preferences */
static gboolean gPREF_MAN_EN    = FALSE;
static gint gPREF_TYPE[2]       = {0};
static const char *gPREF_ID[2]  = {NULL};
static guint gPREF_QP[2]        = {0};

/* source/destination addresses from preferences menu (parsed from gPREF_TYPE[?], gPREF_ID[?]) */
address manual_addr[2];
void *manual_addr_data[2];

static enum_val_t pref_address_types[] = {
    {"lid", "LID", 0},
    {"gid", "GID", 1},
    {NULL, NULL, -1}
};

typedef enum {
    Hello = 0x0,
    HelloAck,
    DisConn,
    AbortConn,
    SendSm,
    RdmaWrCompl,
    RdmaRdCompl,
    ModeChange,
    SrcAvailCancel,
    SinkAvailCancel,
    SinkCancelAck,
    ChRcvBuf,
    ChRcvBufAck,
    SuspComm,
    SuspCommAck,
    SinkAvail = 0xfd,
    SrcAvail,
    Data
} message_by_mid_t;

static const range_string mid_meanings[] = {
        { Hello, Hello, "Hello" },
        { HelloAck, HelloAck, "HelloAck" },
        { DisConn, DisConn, "DisConn" },
        { AbortConn, AbortConn, "AbortConn" },
        { SendSm, SendSm, "SendSm" },
        { RdmaWrCompl, RdmaWrCompl, "RdmaWrCompl" },
        { RdmaRdCompl, RdmaRdCompl, "RdmaRdCompl" },
        { ModeChange, ModeChange, "ModeChange" },
        { SrcAvailCancel, SrcAvailCancel, "SrcAvailCancel" },
        { SinkAvailCancel, SinkAvailCancel, "SinkAvailCancel" },
        { SinkCancelAck, SinkCancelAck, "SinkCancelAck" },
        { ChRcvBuf, ChRcvBuf, "ChRcvBuf" },
        { ChRcvBufAck, ChRcvBufAck, "ChRcvBufAck" },
        { SuspComm, SuspComm, "SuspComm" },
        { SuspCommAck, SuspCommAck, "SuspCommAck" },
        { SinkAvail, SinkAvail, "SinkAvail" },
        { SrcAvail, SrcAvail, "SrcAvail" },
        { Data, Data, "Data" },
        { 0x00001111, 0x00111111, "Reserved" },
        { 0x01000000, 0x01111111, "Experimental" },
        { 0x10000000, 0x11111100, "Reserved" },
        { 0, 0, NULL }
};

/* Code to actually dissect the packets */
static int
dissect_ib_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int local_offset = 0;
    proto_item *SDP_header_item = NULL;
    proto_tree *SDP_header_tree = NULL;
    proto_item *SDP_BSDH_header_item = NULL;
    proto_tree *SDP_BSDH_header_tree = NULL;
    proto_item *SDP_EH_header_item = NULL;
    proto_tree *SDP_EH_header_tree = NULL;
    guint8 mid;
    conversation_t *conv;
    conversation_infiniband_data *convo_data = NULL;
    dissector_handle_t infiniband_handle;

    if (tvb_length(tvb) < 16)   /* check this has at least enough bytes for the BSDH */
        return 0;

    if (gPREF_MAN_EN) {
        /* If the manual settings are enabled see if this fits - in which case we can skip
           the following checks entirely and go straight to dissecting */
        if (    (ADDRESSES_EQUAL(&pinfo->src, &manual_addr[0]) &&
                 ADDRESSES_EQUAL(&pinfo->dst, &manual_addr[1]) &&
                 (pinfo->srcport == 0xffffffff /* is unknown */ || pinfo->srcport == gPREF_QP[0]) &&
                 (pinfo->destport == 0xffffffff /* is unknown */ || pinfo->destport == gPREF_QP[1]))    ||
                (ADDRESSES_EQUAL(&pinfo->src, &manual_addr[1]) &&
                 ADDRESSES_EQUAL(&pinfo->dst, &manual_addr[0]) &&
                 (pinfo->srcport == 0xffffffff /* is unknown */ || pinfo->srcport == gPREF_QP[1]) &&
                 (pinfo->destport == 0xffffffff /* is unknown */ || pinfo->destport == gPREF_QP[0]))    )
            goto manual_override;
    }

    /* first try to find a conversation between the two current hosts. in most cases this
       will not work since we do not have the source QP. this WILL succeed when we're still
       in the process of CM negotiations */
    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                             PT_IBQP, pinfo->srcport, pinfo->destport, 0);

    if (!conv) {
        /* if not, try to find an established RC channel. recall Infiniband conversations are
           registered with one side of the channel. since the packet is only guaranteed to
           contain the qpn of the destination, we'll use this */
        conv = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->dst,
                                 PT_IBQP, pinfo->destport, pinfo->destport, NO_ADDR_B|NO_PORT_B);

        if (!conv)
            return 0;   /* nothing to do with no conversation context */
    }

    if (proto_infiniband < 0) {     /* first time - get the infiniband protocol index*/
        infiniband_handle = find_dissector("infiniband");
        if (!infiniband_handle)
            return 0;   /* no infiniband handle? can't get our proto-data; sorry, can't help you without this */
        proto_infiniband = dissector_handle_get_protocol_index(infiniband_handle);
    }
    convo_data = conversation_get_proto_data(conv, proto_infiniband);

    if (!(convo_data->service_id & SERVICE_ID_MASK))
        return 0;   /* the service id doesn't match that of SDP - nothing for us to do here */

manual_override:

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDP");

    SDP_header_item = proto_tree_add_item(tree, hf_ib_sdp, tvb, local_offset, -1, ENC_NA);
    SDP_header_tree = proto_item_add_subtree(SDP_header_item, ett_ib_sdp);

    SDP_BSDH_header_item = proto_tree_add_item(SDP_header_tree, hf_ib_sdp_bsdh, tvb, local_offset, 16, ENC_NA);
    SDP_BSDH_header_tree = proto_item_add_subtree(SDP_BSDH_header_item, ett_ib_sdp_bsdh);

    mid =  tvb_get_guint8(tvb, local_offset);
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_mid, tvb, local_offset, 1, ENC_BIG_ENDIAN); local_offset += 1;

    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_flags, tvb, local_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_flags_oobpres, tvb, local_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_flags_oob_pend, tvb, local_offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_flags_reqpipe, tvb, local_offset, 4, ENC_BIG_ENDIAN); local_offset += 1;

    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_bufs, tvb, local_offset, 2, ENC_BIG_ENDIAN); local_offset += 2;
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_len, tvb, local_offset, 4, ENC_BIG_ENDIAN); local_offset += 4;
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_mseq, tvb, local_offset, 4, ENC_BIG_ENDIAN); local_offset += 4;
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_mseqack, tvb, local_offset, 4, ENC_BIG_ENDIAN); local_offset += 4;

    switch (mid) {
        case Hello:
            SDP_EH_header_item = proto_tree_add_item(SDP_header_tree, hf_ib_sdp_hh, tvb, local_offset, 48, ENC_NA);
            SDP_EH_header_tree = proto_item_add_subtree(SDP_EH_header_item, ett_ib_sdp_hh);
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_majv, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_minv, tvb, local_offset, 1, ENC_BIG_ENDIAN); local_offset += 1;
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_ipv, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_cap, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_cap_invalidate, tvb, local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_cap_extmaxadverts, tvb, local_offset, 1, ENC_BIG_ENDIAN); local_offset += 1;
            local_offset += 1;  /* skip reserved */
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_maxadverts, tvb, local_offset, 1, ENC_BIG_ENDIAN); local_offset += 1;
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_desremrcvsz, tvb, local_offset, 4, ENC_BIG_ENDIAN); local_offset += 4;
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_localrcvsz, tvb, local_offset, 4, ENC_BIG_ENDIAN); local_offset += 4;
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_localport, tvb, local_offset, 2, ENC_BIG_ENDIAN); local_offset += 2;
            local_offset += 2;  /* skip reserved */
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_src_ip, tvb, local_offset, 16, ENC_NA); local_offset += 16;
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_dst_ip, tvb, local_offset, 16, ENC_NA); local_offset += 16;
            local_offset += 2;  /* skip reserved */
            proto_tree_add_item(SDP_EH_header_tree, hf_ib_sdp_extmaxadverts, tvb, local_offset, 2, ENC_BIG_ENDIAN); /*local_offset += 2;*/
            break;
        case HelloAck:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_hah, tvb, local_offset, 48, ENC_NA);
            break;
        case DisConn:
            break;
        case AbortConn:
            break;
        case SendSm:
            break;
        case RdmaWrCompl:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_rwch, tvb, local_offset, 48, ENC_NA);
            break;
        case RdmaRdCompl:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_rrch, tvb, local_offset, 48, ENC_NA);
            break;
        case ModeChange:
            proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_mch, tvb, local_offset, 48, ENC_NA);
            break;
        case SrcAvailCancel:
            break;
        case SinkAvailCancel:
            break;
        case SinkCancelAck:
            break;
        case ChRcvBuf:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_crbh, tvb, local_offset, 48, ENC_NA);
            break;
        case ChRcvBufAck:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_crbah, tvb, local_offset, 48, ENC_NA);
            break;
        case SuspComm:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_suspch, tvb, local_offset, 48, ENC_NA);
            break;
        case SuspCommAck:
            break;
        case SinkAvail:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_sinkah, tvb, local_offset, 48, ENC_NA);
            break;
        case SrcAvail:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_srcah, tvb, local_offset, 48, ENC_NA);
            break;
        case Data:
            proto_tree_add_item(SDP_header_tree, hf_ib_sdp_data, tvb, local_offset, -1, ENC_NA);
            break;
        default:
            break;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "(SDP %s)",
                    rval_to_str(mid, mid_meanings, "Unknown"));

    return tvb_length(tvb);
}

void
proto_register_ib_sdp(void)
{
    module_t *ib_sdp_module;
    static hf_register_info hf[] = {
        { &hf_ib_sdp, {
            "SDP", "infiniband.sdp",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* SDP BSDH Header */
        { &hf_ib_sdp_bsdh, {
            "BSDH", "infiniband.sdp.bsdh",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_ib_sdp_mid, {
            "MID", "infiniband.sdp.bsdh.mid",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(mid_meanings), 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_flags, {
            "Flags", "infiniband.sdp.bsdh.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_flags_oobpres, {
            "OOB_PRES", "infiniband.sdp.bsdh.oobpres",
            FT_UINT8, BASE_HEX, NULL, 0x1, "Out-Of-Band Data is present", HFILL}
        },
        {&hf_ib_sdp_flags_oob_pend, {
            "OOB_PEND", "infiniband.sdp.bsdh.oobpend",
            FT_UINT8, BASE_HEX, NULL, 0x2, "Out-Of-Band Data is pending", HFILL}
        },
        {&hf_ib_sdp_flags_reqpipe, {
            "REQ_PIPE", "infiniband.sdp.bsdh.reqpipe",
            FT_UINT8, BASE_HEX, NULL, 0x4, "Request change to Pipelined Mode", HFILL}
        },
        {&hf_ib_sdp_bufs, {
            "Buffers", "infiniband.sdp.bsdh.bufs",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_len, {
            "Length", "infiniband.sdp.bsdh.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_mseq, {
            "MSeq", "infiniband.sdp.bsdh.mseq",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Message Sequence Number", HFILL}
        },
        {&hf_ib_sdp_mseqack, {
            "MSeqAck", "infiniband.sdp.bsdh.mseqack",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Message Sequence Number Acknowledgement", HFILL}
        },
        /* SDP Hello Header */
        {&hf_ib_sdp_hh, {
            "Hello Header", "infiniband.sdp.hh",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        {&hf_ib_sdp_majv, {
            "Major Protocol Version Number", "infiniband.sdp.hh.majv",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        {&hf_ib_sdp_minv, {
            "Minor Protocol Version Number", "infiniband.sdp.hh.minv",
            FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        {&hf_ib_sdp_ipv,
            {"IP version", "infiniband.sdp.hh.ipv",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        {&hf_ib_sdp_cap, {
            "Capabilities", "infiniband.sdp.hh.cap",
            FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        {&hf_ib_sdp_cap_invalidate, {
            "INVALIDATE_CAP", "infiniband.sdp.hh.cap_invalidate",
            FT_UINT8, BASE_HEX, NULL, 0x1, "Supports incoming Send w/Invalidate opcode", HFILL}
        },
        {&hf_ib_sdp_cap_extmaxadverts, {
            "EXTENDED_MAXADVERTS", "infiniband.sdp.hh.cap_extmaxadverts",
            FT_UINT8, BASE_HEX, NULL, 0x2, "Extended MaxAdverts is used", HFILL}
        },
        {&hf_ib_sdp_maxadverts, {
            "Maximum Advertisements", "infiniband.sdp.hh.maxadverts",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_desremrcvsz, {
            "DesRemRcvSz", "infiniband.sdp.hh.desremrcvsz",
            FT_UINT32, BASE_DEC, NULL, 0x0, "Desired Remote Receive Size", HFILL}
        },
        {&hf_ib_sdp_localrcvsz,
            {"LocalRcvSz", "infiniband.sdp.hh.localrcvsz",
                FT_UINT32, BASE_DEC, NULL, 0x0, "Local Receive Size", HFILL}
        },
        {&hf_ib_sdp_localport, {
            "Local Port", "infiniband.sdp.hh.localport",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_src_ip, {
            "Source IP", "infiniband.sdp.hh.src_ip",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_dst_ip, {
            "Destination IP", "infiniband.sdp.hh.dst_ip",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_extmaxadverts, {
            "Extended MaxAdverts", "infiniband.sdp.hh.extmaxadverts",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Rest of Headers */
        {&hf_ib_sdp_hah, {
            "HelloAck Header", "infiniband.sdp.hah",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        {&hf_ib_sdp_rwch, {
            "RdmaWrCompl Header", "infiniband.sdp.rwch",
            FT_NONE, BASE_NONE, NULL, 0x00, "RDMA Write Complete", HFILL}
        },
        {&hf_ib_sdp_rrch, {
            "RdmaRdCompl Header", "infiniband.sdp.rrch",
            FT_NONE, BASE_NONE, NULL, 0x00, "RDMA Read Complete", HFILL}
        },
        {&hf_ib_sdp_mch, {
            "ModeChange Header", "infiniband.sdp.mch",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        {&hf_ib_sdp_crbh, {
            "ChRcvBuf Header", "infiniband.sdp.crbh",
            FT_NONE, BASE_NONE, NULL, 0x00, "Change Receive private Buffer size", HFILL}
        },
        {&hf_ib_sdp_crbah, {
            "ChRcvBufAck Header", "infiniband.sdp.crbah",
            FT_NONE, BASE_NONE, NULL, 0x00, "Change Receive private Buffer size Acknowledgement", HFILL}
        },
        {&hf_ib_sdp_suspch, {
            "SuspComm Header", "infiniband.sdp.suspch",
            FT_NONE, BASE_NONE, NULL, 0x00, "Suspend Communication", HFILL}
        },
        {&hf_ib_sdp_sinkah, {
            "SinkAvail Header", "infiniband.sdp.sinkah",
            FT_NONE, BASE_NONE, NULL, 0x00, "Data Sink Available", HFILL}
        },
        {&hf_ib_sdp_srcah, {
            "SrcAvail Header", "infiniband.sdp.srcah",
            FT_NONE, BASE_NONE, NULL, 0x00, "Data Source Available", HFILL}
        },
        {&hf_ib_sdp_data, {
            "Data", "infiniband.sdp.Data",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ib_sdp,
        &ett_ib_sdp_bsdh,
        &ett_ib_sdp_hh,
    };

    proto_ib_sdp = proto_register_protocol("Infiniband Sockets Direct Protocol", "Infiniband SDP", "ib_sdp");

    new_register_dissector("infiniband.sdp", dissect_ib_sdp, proto_ib_sdp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ib_sdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    ib_sdp_module = prefs_register_protocol(proto_ib_sdp, proto_reg_handoff_ib_sdp);

    prefs_register_bool_preference(ib_sdp_module, "manual_en", "Enable manual settings",
        "Check to treat all traffic between the configured source/destination as SDP",
        &gPREF_MAN_EN);

    prefs_register_static_text_preference(ib_sdp_module, "addr_a", "Address A",
        "Side A of the manually-configured connection");
    prefs_register_enum_preference(ib_sdp_module, "addr_a_type", "Address Type",
        "Type of address specified", &gPREF_TYPE[0], pref_address_types, FALSE);
    prefs_register_string_preference(ib_sdp_module, "addr_a_id", "ID",
        "LID/GID of address A", &gPREF_ID[0]);
    prefs_register_uint_preference(ib_sdp_module, "addr_a_qp", "QP Number",
        "QP Number for address A", 10, &gPREF_QP[0]);

    prefs_register_static_text_preference(ib_sdp_module, "addr_b", "Address B",
        "Side B of the manually-configured connection");
    prefs_register_enum_preference(ib_sdp_module, "addr_b_type", "Address Type",
        "Type of address specified", &gPREF_TYPE[1], pref_address_types, FALSE);
    prefs_register_string_preference(ib_sdp_module, "addr_b_id", "ID",
        "LID/GID of address B", &gPREF_ID[1]);
    prefs_register_uint_preference(ib_sdp_module, "addr_b_qp", "QP Number",
        "QP Number for address B", 10, &gPREF_QP[1]);
}

void
proto_reg_handoff_ib_sdp(void)
{
    static gboolean initialized = FALSE;

    if (!initialized) {
        heur_dissector_add("infiniband.payload", dissect_ib_sdp, proto_ib_sdp);
        heur_dissector_add("infiniband.mad.cm.private", dissect_ib_sdp, proto_ib_sdp);

        /* allocate enough space in the addresses to store the largest address (a GID) */
        manual_addr_data[0] = se_alloc(GID_SIZE);
        manual_addr_data[1] = se_alloc(GID_SIZE);

        initialized = TRUE;
    }

    if (gPREF_MAN_EN) {
        /* the manual setting is enabled, so parse the settings into the address type */
        gboolean error_occured = FALSE;
        char *not_parsed;
        int i;

        for (i = 0; i < 2; i++) {
            if (gPREF_TYPE[i] == 0) {   /* LID */
                errno = 0;  /* reset any previous error indicators */
                *((guint16*)manual_addr_data[i]) = (guint16)strtoul(gPREF_ID[i], &not_parsed, 0);
                if (errno || *not_parsed != '\0') {
                    error_occured = TRUE;
                } else {
                    SET_ADDRESS(&manual_addr[i], AT_IB, sizeof(guint16), manual_addr_data[i]);
                }
            } else {    /* GID */
                if (! inet_pton(AF_INET6, gPREF_ID[i], manual_addr_data[i]) ) {
                    error_occured = TRUE;
                } else {
                    SET_ADDRESS(&manual_addr[i], AT_IB, GID_SIZE, manual_addr_data[i]);
                }
            }

            if (error_occured) {
                /* an invalid id was specified - disable manual settings until it's fixed */
                gPREF_MAN_EN = FALSE;
                break;
            }
        }

    }
}

