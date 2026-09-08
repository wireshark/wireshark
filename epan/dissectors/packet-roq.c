/* packet-roq.c
 * Routines for RTP over QUIC (RoQ) dissection
 * draft-ietf-avtcore-rtp-over-quic-14
 * https://datatracker.ietf.org/doc/html/draft-ietf-avtcore-rtp-over-quic-14
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * RoQ multiplexes RTP and RTCP packets on top of a QUIC connection,
 * negotiated with the ALPN token "roq". Packets are carried either on
 * QUIC streams or in QUIC DATAGRAM frames (RFC 9221):
 *
 *  Stream {
 *    Flow Identifier (i),
 *    RTP Payload (..) ...,
 *  }
 *
 *  RTP Payload {
 *    Length (i),
 *    RTP Packet / RTCP Packet (..),
 *  }
 *
 *  Datagram {
 *    Flow Identifier (i),
 *    RTP Packet / RTCP Packet (..),
 *  }
 *
 * where (i) is a QUIC variable-length integer (RFC 9000, Section 16).
 * A QUIC stream starts with a single flow identifier followed by a
 * sequence of length-prefixed RTP/RTCP packets, while each DATAGRAM
 * frame carries a flow identifier followed by exactly one packet.
 * RTP and RTCP packets sharing a flow identifier are demultiplexed
 * using the rules of RFC 5761.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-quic.h"

void proto_register_roq(void);
void proto_reg_handoff_roq(void);

static dissector_handle_t roq_handle;
static dissector_handle_t roq_datagram_handle;
static dissector_handle_t rtp_handle;
static dissector_handle_t rtcp_handle;

static int proto_roq;

static int hf_roq_flow_id;
static int hf_roq_payload;
static int hf_roq_length;

static int ett_roq;
static int ett_roq_payload;

static expert_field ei_roq_flow_id_invalid;
static expert_field ei_roq_length_invalid;
static expert_field ei_roq_stream_head_missing;

/** Per-stream information, valid for the whole lifetime of a QUIC stream. */
typedef struct _roq_stream_info {
    uint64_t flow_id;       /**< Flow identifier sent at the start of the stream. */
    bool     flow_id_set;   /**< True once the flow identifier has been dissected. */
} roq_stream_info_t;

/**
 * Attempt to parse a QUIC-encoded variable-length integer.
 * Returns false if the tvb does not (yet) contain the complete varint.
 */
static bool
try_get_quic_varint(tvbuff_t *tvb, int offset, uint64_t *value, int *lenvar)
{
    if (tvb_reported_length_remaining(tvb, offset) == 0) {
        return false;
    }
    unsigned len = 1U << (tvb_get_uint8(tvb, offset) >> 6);
    if (tvb_reported_length_remaining(tvb, offset) < len) {
        return false;
    }
    *lenvar = (int)len;
    if (value) {
        unsigned n = tvb_get_varint(tvb, offset, -1, value, ENC_VARINT_QUIC);
        DISSECTOR_ASSERT_CMPUINT(n, ==, len);
    }
    return true;
}

/**
 * Dissect a single RTP or RTCP packet, demultiplexed as described in
 * RFC 5761: RTCP packet types 192-223 occupy the octet that carries
 * the marker bit and payload type in RTP, so RTP payload types 64-95
 * (with the marker bit set) cannot occur.
 */
static void
dissect_roq_rtp_rtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissector_handle_t handle = rtp_handle;

    if (tvb_captured_length(tvb) >= 2) {
        uint8_t pt = tvb_get_uint8(tvb, 1);
        if (pt >= 192 && pt <= 223) {
            handle = rtcp_handle;
        }
    }
    if (handle) {
        call_dissector(handle, tvb, pinfo, tree);
    } else {
        call_data_dissector(tvb, pinfo, tree);
    }
}

/** Dissect RoQ carried on a QUIC stream. */
static int
dissect_roq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    quic_stream_info *stream_info = (quic_stream_info *)data;
    roq_stream_info_t *roq_stream;
    proto_item *ti, *ti_flow_id;
    proto_tree *roq_tree;
    int offset = 0;
    uint64_t flow_id;
    int lenvar;

    if (!stream_info) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RoQ");

    roq_stream = (roq_stream_info_t *)quic_stream_get_proto_data(pinfo, stream_info);
    if (!roq_stream) {
        roq_stream = wmem_new0(wmem_file_scope(), roq_stream_info_t);
        quic_stream_add_proto_data(pinfo, stream_info, roq_stream);
    }

    ti = proto_tree_add_item(tree, proto_roq, tvb, 0, -1, ENC_NA);
    roq_tree = proto_item_add_subtree(ti, ett_roq);

    if (stream_info->offset == 0) {
        /* Start of the stream, which begins with the flow identifier. */
        if (!try_get_quic_varint(tvb, offset, &flow_id, &lenvar)) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return tvb_captured_length(tvb);
        }
        proto_tree_add_uint64(roq_tree, hf_roq_flow_id, tvb, offset, lenvar, flow_id);
        offset += lenvar;
        roq_stream->flow_id = flow_id;
        roq_stream->flow_id_set = true;
    } else if (roq_stream->flow_id_set) {
        ti_flow_id = proto_tree_add_uint64(roq_tree, hf_roq_flow_id, tvb, 0, 0, roq_stream->flow_id);
        proto_item_set_generated(ti_flow_id);
    } else {
        /* The beginning of the stream was not captured, so the packet
         * boundaries within the stream are unknown. */
        proto_tree_add_expert(roq_tree, pinfo, &ei_roq_stream_head_missing, tvb, offset, -1);
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, roq_tree);
        return tvb_captured_length(tvb);
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Flow ID: %" PRIu64, roq_stream->flow_id);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        uint64_t pkt_len;
        int len_size;
        unsigned remaining;
        proto_item *ti_payload;
        proto_tree *payload_tree;

        if (!try_get_quic_varint(tvb, offset, &pkt_len, &len_size)) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            break;
        }
        if (pkt_len >= INT32_MAX - (uint64_t)len_size) {
            proto_tree_add_expert(roq_tree, pinfo, &ei_roq_length_invalid, tvb, offset, len_size);
            break;
        }
        remaining = tvb_reported_length_remaining(tvb, offset + len_size);
        if ((uint64_t)remaining < pkt_len) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = (int)(pkt_len - remaining);
            break;
        }

        ti_payload = proto_tree_add_item(roq_tree, hf_roq_payload, tvb, offset,
                                         len_size + (int)pkt_len, ENC_NA);
        payload_tree = proto_item_add_subtree(ti_payload, ett_roq_payload);
        proto_tree_add_uint64(payload_tree, hf_roq_length, tvb, offset, len_size, pkt_len);
        offset += len_size;

        dissect_roq_rtp_rtcp(tvb_new_subset_length(tvb, offset, (int)pkt_len), pinfo, tree);
        offset += (int)pkt_len;
    }

    proto_item_set_len(ti, offset);
    return tvb_captured_length(tvb);
}

/** Dissect RoQ carried in a QUIC DATAGRAM frame (RFC 9221). */
static int
dissect_roq_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *roq_tree;
    int offset = 0;
    uint64_t flow_id;
    int lenvar;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RoQ");

    ti = proto_tree_add_item(tree, proto_roq, tvb, 0, -1, ENC_NA);
    roq_tree = proto_item_add_subtree(ti, ett_roq);

    if (!try_get_quic_varint(tvb, offset, &flow_id, &lenvar)) {
        proto_tree_add_expert(roq_tree, pinfo, &ei_roq_flow_id_invalid, tvb, offset, -1);
        return tvb_captured_length(tvb);
    }
    proto_tree_add_uint64(roq_tree, hf_roq_flow_id, tvb, offset, lenvar, flow_id);
    offset += lenvar;
    proto_item_set_len(ti, offset);

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Flow ID: %" PRIu64, flow_id);

    /* The remainder of the datagram is a single RTP or RTCP packet. */
    dissect_roq_rtp_rtcp(tvb_new_subset_remaining(tvb, offset), pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_roq(void)
{
    static hf_register_info hf[] = {
        { &hf_roq_flow_id,
          { "Flow Identifier", "roq.flow_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Identifies the RTP or RTCP flow the packets belong to", HFILL }
        },
        { &hf_roq_payload,
          { "RoQ Payload", "roq.payload",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Length-prefixed RTP or RTCP packet", HFILL }
        },
        { &hf_roq_length,
          { "Length", "roq.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the RTP or RTCP packet that follows", HFILL }
        },
    };

    static int *ett[] = {
        &ett_roq,
        &ett_roq_payload,
    };

    static ei_register_info ei[] = {
        { &ei_roq_flow_id_invalid,
          { "roq.flow_id.invalid", PI_MALFORMED, PI_ERROR,
            "Truncated or invalid flow identifier", EXPFILL }
        },
        { &ei_roq_length_invalid,
          { "roq.length.invalid", PI_MALFORMED, PI_ERROR,
            "Payload length is too large to dissect", EXPFILL }
        },
        { &ei_roq_stream_head_missing,
          { "roq.stream_head_missing", PI_UNDECODED, PI_WARN,
            "Beginning of the QUIC stream was not captured, cannot determine packet boundaries", EXPFILL }
        },
    };

    expert_module_t *expert_roq;

    proto_roq = proto_register_protocol("RTP over QUIC", "RoQ", "roq");

    proto_register_field_array(proto_roq, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_roq = expert_register_protocol(proto_roq);
    expert_register_field_array(expert_roq, ei, array_length(ei));

    roq_handle = register_dissector("roq", dissect_roq, proto_roq);
    roq_datagram_handle = register_dissector("roq.datagram", dissect_roq_datagram, proto_roq);
}

void
proto_reg_handoff_roq(void)
{
    rtp_handle = find_dissector_add_dependency("rtp", proto_roq);
    rtcp_handle = find_dissector_add_dependency("rtcp", proto_roq);

    dissector_add_string("quic.proto", "roq", roq_handle);
    dissector_add_string("quic.proto.datagram", "roq", roq_datagram_handle);
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
