/* packet-infiniband_sdp.c
 * Routines for Infiniband Sockets Direct Protocol dissection
 * Copyright 2010, Mellanox Technologies Ltd.
 * Code by Amir Vadai and Slava Koyfman.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>

#include "packet-infiniband.h"

void proto_register_ib_sdp(void);
void proto_reg_handoff_ib_sdp(void);

/* If the service-id is non-zero after being ANDed with the following mask then
   this is SDP traffic */
#define SERVICE_ID_MASK 0x0000000000010000

static int proto_infiniband = -1;   /* we'll need the Infiniband protocol index for conversation data */

/* Initialize the protocol and registered fields... */
static int proto_ib_sdp = -1;

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
dissect_ib_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int local_offset = 0;
    proto_item *SDP_header_item;
    proto_tree *SDP_header_tree;
    proto_item *SDP_BSDH_header_item;
    proto_tree *SDP_BSDH_header_tree;
    proto_item *SDP_EH_header_item;
    proto_tree *SDP_EH_header_tree;
    guint8 mid;

    if (tvb_captured_length(tvb) < 16)   /* check this has at least enough bytes for the BSDH */
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDP");

    SDP_header_item = proto_tree_add_item(tree, proto_ib_sdp, tvb, local_offset, -1, ENC_NA);
    SDP_header_tree = proto_item_add_subtree(SDP_header_item, ett_ib_sdp);

    SDP_BSDH_header_item = proto_tree_add_item(SDP_header_tree, hf_ib_sdp_bsdh, tvb, local_offset, 16, ENC_NA);
    SDP_BSDH_header_tree = proto_item_add_subtree(SDP_BSDH_header_item, ett_ib_sdp_bsdh);

    mid =  tvb_get_guint8(tvb, local_offset);
    proto_tree_add_item(SDP_BSDH_header_tree, hf_ib_sdp_mid, tvb, local_offset, 1, ENC_BIG_ENDIAN); local_offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, "(SDP %s)",
                    rval_to_str(mid, mid_meanings, "Unknown"));

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

    return tvb_captured_length(tvb);
}

static gboolean
dissect_ib_sdp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conv;
    conversation_infiniband_data *convo_data = NULL;

    if (tvb_captured_length(tvb) < 16)   /* check this has at least enough bytes for the BSDH */
        return FALSE;

    /* first try to find a conversation between the two current hosts. in most cases this
       will not work since we do not have the source QP. this WILL succeed when we're still
       in the process of CM negotiations */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                             ENDPOINT_IBQP, pinfo->srcport, pinfo->destport, 0);

    if (!conv) {
        /* if not, try to find an established RC channel. recall Infiniband conversations are
           registered with one side of the channel. since the packet is only guaranteed to
           contain the qpn of the destination, we'll use this */
        conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
                                 ENDPOINT_IBQP, pinfo->destport, pinfo->destport, NO_ADDR_B|NO_PORT_B);

        if (!conv)
            return FALSE;   /* nothing to do with no conversation context */
    }

    convo_data = (conversation_infiniband_data *)conversation_get_proto_data(conv, proto_infiniband);

    if (!convo_data)
        return FALSE;

    if (!(convo_data->service_id & SERVICE_ID_MASK))
        return FALSE;   /* the service id doesn't match that of SDP - nothing for us to do here */

    dissect_ib_sdp(tvb, pinfo, tree, data);
    return TRUE;
}

void
proto_register_ib_sdp(void)
{
    module_t *ib_sdp_module;
    static hf_register_info hf[] = {
        /* SDP BSDH Header */
        { &hf_ib_sdp_bsdh, {
            "BSDH", "infiniband_sdp.bsdh",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_ib_sdp_mid, {
            "MID", "infiniband_sdp.bsdh.mid",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(mid_meanings), 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_flags, {
            "Flags", "infiniband_sdp.bsdh.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_flags_oobpres, {
            "OOB_PRES", "infiniband_sdp.bsdh.oobpres",
            FT_UINT8, BASE_HEX, NULL, 0x1, "Out-Of-Band Data is present", HFILL}
        },
        {&hf_ib_sdp_flags_oob_pend, {
            "OOB_PEND", "infiniband_sdp.bsdh.oobpend",
            FT_UINT8, BASE_HEX, NULL, 0x2, "Out-Of-Band Data is pending", HFILL}
        },
        {&hf_ib_sdp_flags_reqpipe, {
            "REQ_PIPE", "infiniband_sdp.bsdh.reqpipe",
            FT_UINT8, BASE_HEX, NULL, 0x4, "Request change to Pipelined Mode", HFILL}
        },
        {&hf_ib_sdp_bufs, {
            "Buffers", "infiniband_sdp.bsdh.bufs",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_len, {
            "Length", "infiniband_sdp.bsdh.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_mseq, {
            "MSeq", "infiniband_sdp.bsdh.mseq",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Message Sequence Number", HFILL}
        },
        {&hf_ib_sdp_mseqack, {
            "MSeqAck", "infiniband_sdp.bsdh.mseqack",
            FT_UINT32, BASE_HEX, NULL, 0x0, "Message Sequence Number Acknowledgement", HFILL}
        },
        /* SDP Hello Header */
        {&hf_ib_sdp_hh, {
            "Hello Header", "infiniband_sdp.hh",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        {&hf_ib_sdp_majv, {
            "Major Protocol Version Number", "infiniband_sdp.hh.majv",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        {&hf_ib_sdp_minv, {
            "Minor Protocol Version Number", "infiniband_sdp.hh.minv",
            FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        {&hf_ib_sdp_ipv,
            {"IP version", "infiniband_sdp.hh.ipv",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        {&hf_ib_sdp_cap, {
            "Capabilities", "infiniband_sdp.hh.cap",
            FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        {&hf_ib_sdp_cap_invalidate, {
            "INVALIDATE_CAP", "infiniband_sdp.hh.cap_invalidate",
            FT_UINT8, BASE_HEX, NULL, 0x1, "Supports incoming Send w/Invalidate opcode", HFILL}
        },
        {&hf_ib_sdp_cap_extmaxadverts, {
            "EXTENDED_MAXADVERTS", "infiniband_sdp.hh.cap_extmaxadverts",
            FT_UINT8, BASE_HEX, NULL, 0x2, "Extended MaxAdverts is used", HFILL}
        },
        {&hf_ib_sdp_maxadverts, {
            "Maximum Advertisements", "infiniband_sdp.hh.maxadverts",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_desremrcvsz, {
            "DesRemRcvSz", "infiniband_sdp.hh.desremrcvsz",
            FT_UINT32, BASE_DEC, NULL, 0x0, "Desired Remote Receive Size", HFILL}
        },
        {&hf_ib_sdp_localrcvsz,
            {"LocalRcvSz", "infiniband_sdp.hh.localrcvsz",
                FT_UINT32, BASE_DEC, NULL, 0x0, "Local Receive Size", HFILL}
        },
        {&hf_ib_sdp_localport, {
            "Local Port", "infiniband_sdp.hh.localport",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_src_ip, {
            "Source IP", "infiniband_sdp.hh.src_ip",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_dst_ip, {
            "Destination IP", "infiniband_sdp.hh.dst_ip",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_ib_sdp_extmaxadverts, {
            "Extended MaxAdverts", "infiniband_sdp.hh.extmaxadverts",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Rest of Headers */
        {&hf_ib_sdp_hah, {
            "HelloAck Header", "infiniband_sdp.hah",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        {&hf_ib_sdp_rwch, {
            "RdmaWrCompl Header", "infiniband_sdp.rwch",
            FT_NONE, BASE_NONE, NULL, 0x00, "RDMA Write Complete", HFILL}
        },
        {&hf_ib_sdp_rrch, {
            "RdmaRdCompl Header", "infiniband_sdp.rrch",
            FT_NONE, BASE_NONE, NULL, 0x00, "RDMA Read Complete", HFILL}
        },
        {&hf_ib_sdp_mch, {
            "ModeChange Header", "infiniband_sdp.mch",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        {&hf_ib_sdp_crbh, {
            "ChRcvBuf Header", "infiniband_sdp.crbh",
            FT_NONE, BASE_NONE, NULL, 0x00, "Change Receive private Buffer size", HFILL}
        },
        {&hf_ib_sdp_crbah, {
            "ChRcvBufAck Header", "infiniband_sdp.crbah",
            FT_NONE, BASE_NONE, NULL, 0x00, "Change Receive private Buffer size Acknowledgement", HFILL}
        },
        {&hf_ib_sdp_suspch, {
            "SuspComm Header", "infiniband_sdp.suspch",
            FT_NONE, BASE_NONE, NULL, 0x00, "Suspend Communication", HFILL}
        },
        {&hf_ib_sdp_sinkah, {
            "SinkAvail Header", "infiniband_sdp.sinkah",
            FT_NONE, BASE_NONE, NULL, 0x00, "Data Sink Available", HFILL}
        },
        {&hf_ib_sdp_srcah, {
            "SrcAvail Header", "infiniband_sdp.srcah",
            FT_NONE, BASE_NONE, NULL, 0x00, "Data Source Available", HFILL}
        },
        {&hf_ib_sdp_data, {
            "Data", "infiniband_sdp.Data",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ib_sdp,
        &ett_ib_sdp_bsdh,
        &ett_ib_sdp_hh,
    };

    proto_ib_sdp = proto_register_protocol("Infiniband Sockets Direct Protocol", "Infiniband SDP", "infiniband_sdp");

    register_dissector("infiniband_sdp", dissect_ib_sdp, proto_ib_sdp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ib_sdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    ib_sdp_module = prefs_register_protocol(proto_ib_sdp, NULL);

    prefs_register_static_text_preference(ib_sdp_module, "use_decode_as",
        "Heuristic matching preferences removed.  Use Infiniband protocol preferences or Decode As.",
        "Simple heuristics can still be enable (may generate false positives) through Infiniband protocol preferences."
        "To force Infiniband SDP dissection use Decode As");

    prefs_register_obsolete_preference(ib_sdp_module, "manual_en");

    prefs_register_obsolete_preference(ib_sdp_module, "addr_a");
    prefs_register_obsolete_preference(ib_sdp_module, "addr_a_type");
    prefs_register_obsolete_preference(ib_sdp_module, "addr_a_id");
    prefs_register_obsolete_preference(ib_sdp_module, "addr_a_qp");

    prefs_register_obsolete_preference(ib_sdp_module, "addr_b");
    prefs_register_obsolete_preference(ib_sdp_module, "addr_b_type");
    prefs_register_obsolete_preference(ib_sdp_module, "addr_b_id");
    prefs_register_obsolete_preference(ib_sdp_module, "addr_b_qp");
}

void
proto_reg_handoff_ib_sdp(void)
{
    heur_dissector_add("infiniband.payload", dissect_ib_sdp_heur, "Infiniband SDP", "sdp_infiniband", proto_ib_sdp, HEURISTIC_ENABLE);
    heur_dissector_add("infiniband.mad.cm.private", dissect_ib_sdp_heur, "Infiniband SDP in PrivateData of CM packets", "sdp_ib_private", proto_ib_sdp, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("infiniband", create_dissector_handle( dissect_ib_sdp, proto_ib_sdp ) );

    proto_infiniband = proto_get_id_by_filter_name( "infiniband" );
}

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
