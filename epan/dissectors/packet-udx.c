/* packet-udx.c
 * Routines for UDX dissection
 * Copyright 2026, Frank <frankolien123@gmail.com>
 *
 * UDX is a reliable, multiplexed, UDP-based transport protocol used by the
 * Holepunch peer-to-peer stack. Reference implementation:
 * https://github.com/holepunchto/libudx
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/follow.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include "packet-udp.h"
#include <wsutil/wmem/wmem_map.h>
#include <wsutil/wmem/wmem_tree.h>

/*
 * UDX wire format (all multi-byte fields little-endian):
 *
 *  offset  size  field
 *       0     1  magic (0xff)
 *       1     1  version (1)
 *       2     1  type flags
 *       3     1  data offset: bytes between the fixed header and the payload,
 *                occupied by SACK blocks, or by padding on MTU probes
 *       4     4  id      - the *receiver's* stream id
 *       8     4  window  - sender's receive window in bytes
 *      12     4  seq     - per-PACKET sequence counter (not bytes)
 *      16     4  ack     - next seq expected from the peer
 *      20   8*n  SACK blocks: pairs of uint32 (start, end) seq ranges
 *       ...      payload
 */

#define UDX_HEADER_SIZE      20
#define UDX_MAGIC_BYTE       0xff
#define UDX_VERSION          1

#define UDX_FLAG_DATA        0x01
#define UDX_FLAG_END         0x02
#define UDX_FLAG_SACK        0x04
#define UDX_FLAG_MESSAGE     0x08
#define UDX_FLAG_DESTROY     0x10
#define UDX_FLAG_HEARTBEAT   0x20
#define UDX_FLAG_MASK        0x3f

/*
 * Sequence numbers count packets and wrap at 2^32, so all comparisons are
 * made in circular arithmetic.
 */
#define UDX_SEQ_LT(a, b)  ((int32_t)((a) - (b)) < 0)
#define UDX_SEQ_GT(a, b)  ((int32_t)((a) - (b)) > 0)
#define UDX_SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)

/* Bounds the SACK blocks examined per packet; data_offset caps the area at
 * 255 bytes, i.e. 31 blocks. */
#define UDX_MAX_SACK_BLOCKS 32

/* Floor for the derived retransmission timeout, in seconds. Below this a
 * repeat is attributed to loss recovery rather than to a timer firing. */
#define UDX_MIN_RTO 0.2

/* A repeat arriving within this window of the original is a duplicate
 * datagram rather than anything the sender chose to send again. */
#define UDX_DUP_WINDOW 0.0005

/* Shortest pause credited to a tail loss probe timer when no round-trip
 * time has been measured yet. */
#define UDX_MIN_PROBE_DELAY 0.010

void proto_register_udx(void);
void proto_reg_handoff_udx(void);

static dissector_handle_t udx_handle;

static int proto_udx;

static bool udx_analyze_sequence_numbers = true;

static int udx_follow_tap;

/* Stream numbers are handed out across the whole capture so that a filter
 * such as "udx.stream eq 3" identifies exactly one stream. */
static uint32_t udx_stream_count;

/* Queued for the follow taps: one packet's payload, where it belongs in the
 * stream and which side sent it. */
typedef struct udx_follow_tap_data {
    tvbuff_t *tvb;
    uint32_t  stream;
    uint32_t  offset;       /* position of this packet within its direction */
    bool      from_server;
} udx_follow_tap_data_t;

/* One transmitted packet, remembered so that a later acknowledgement can be
 * linked back to it. */
typedef struct udx_seg {
    uint32_t frame;
    nstime_t ts;
    uint32_t len;
    uint32_t acked_in_frame;
    nstime_t ack_ts;
    unsigned retrans;
    bool     sacked;
} udx_seg_t;

/* One direction of one stream: the packets one endpoint sends bearing the
 * peer's stream id. */
typedef struct udx_flow {
    uint32_t     id;
    unsigned     dir;
    unsigned     order;         /* creation order within this direction */
    nstime_t     first_ts;
    wmem_tree_t *segs;          /* seq -> udx_seg_t */
    uint32_t     base_seq;      /* first sequence number seen on this flow */
    uint32_t     max_seq;       /* highest sequence number sent */
    bool         have_seq;
    uint32_t     outstanding_bytes;
    uint32_t     outstanding_pkts;
    uint32_t     max_ack;       /* highest acknowledgement this flow emitted */
    bool         have_ack;
    uint32_t     max_sacked;    /* highest sequence the peer selectively acked */
    bool         have_sacked;
    uint32_t     last_rwnd;
    bool         rwnd_zero;
    double       srtt;
    double       rttvar;
    bool         have_rtt;
    uint32_t     stream_num;
    struct udx_flow *paired;
    struct udx_flow *cand;      /* pairing candidate under consideration */
    unsigned     cand_hits;
} udx_flow_t;

typedef struct udx_conv {
    wmem_map_t *flows;          /* (dir << 32 | id) -> udx_flow_t */
    unsigned    n_flows[2];
    unsigned    client_dir;     /* the side that sent first is the client */
    bool        have_client_dir;
} udx_conv_t;

/* Verdicts reached on the first pass and replayed on every later visit. */
#define UDX_A_RETRANS        0x0001
#define UDX_A_FAST_RETRANS   0x0002
#define UDX_A_RTO_RETRANS    0x0004
#define UDX_A_TLP            0x0008
#define UDX_A_SPURIOUS       0x0010
#define UDX_A_OUT_OF_ORDER   0x0020
#define UDX_A_LOST_SEGMENT   0x0040
#define UDX_A_KEEPALIVE      0x0080
#define UDX_A_ZERO_WIN_PROBE 0x0100
#define UDX_A_ZERO_WIN       0x0200
#define UDX_A_WINDOW_UPDATE  0x0400
#define UDX_A_MTU_PROBE      0x0800
#define UDX_A_END            0x1000
#define UDX_A_DESTROY        0x2000
#define UDX_A_DUPLICATE      0x4000

typedef struct udx_ppd {
    uint32_t flags;
    uint32_t acks_frame;        /* frame this packet acknowledges */
    nstime_t ack_rtt;
    bool     have_ack_rtt;
    uint32_t bytes_in_flight;
    uint32_t packets_in_flight;
    uint32_t seq;               /* sender sequence, to find our own segment */
    bool     tracked;           /* this packet consumed a sequence number */
    uint32_t stream;            /* stream number at analysis time */
    uint32_t follow_offset;     /* position within this direction */
    bool     from_server;
    bool     follow_ok;         /* payload belongs in the reassembled stream */
    udx_flow_t *flow;
} udx_ppd_t;

static int hf_udx_magic;
static int hf_udx_version;
static int hf_udx_flags;
static int hf_udx_flags_data;
static int hf_udx_flags_end;
static int hf_udx_flags_sack;
static int hf_udx_flags_message;
static int hf_udx_flags_destroy;
static int hf_udx_flags_heartbeat;
static int hf_udx_data_offset;
static int hf_udx_id;
static int hf_udx_window;
static int hf_udx_seq;
static int hf_udx_ack;
static int hf_udx_sacks;
static int hf_udx_sack_block;
static int hf_udx_sack_start;
static int hf_udx_sack_end;
static int hf_udx_padding;
static int hf_udx_payload;
static int hf_udx_payload_len;
static int hf_udx_stream;
static int hf_udx_analysis;
static int hf_udx_analysis_acks_frame;
static int hf_udx_analysis_acked_in;
static int hf_udx_analysis_ack_rtt;
static int hf_udx_analysis_bytes_in_flight;
static int hf_udx_analysis_pkts_in_flight;
static int hf_udx_analysis_no_reverse;

static int ett_udx;
static int ett_udx_flags;
static int ett_udx_sacks;
static int ett_udx_sack_block;
static int ett_udx_analysis;

static expert_field ei_udx_retrans;
static expert_field ei_udx_fast_retrans;
static expert_field ei_udx_rto_retrans;
static expert_field ei_udx_tlp;
static expert_field ei_udx_spurious_retrans;
static expert_field ei_udx_duplicate;
static expert_field ei_udx_out_of_order;
static expert_field ei_udx_lost_segment;
static expert_field ei_udx_keepalive;
static expert_field ei_udx_zero_window_probe;
static expert_field ei_udx_zero_window;
static expert_field ei_udx_window_update;
static expert_field ei_udx_mtu_probe;
static expert_field ei_udx_end;
static expert_field ei_udx_destroy;

static int * const udx_flag_fields[] = {
    &hf_udx_flags_data,
    &hf_udx_flags_end,
    &hf_udx_flags_sack,
    &hf_udx_flags_message,
    &hf_udx_flags_destroy,
    &hf_udx_flags_heartbeat,
    NULL
};

/* Build a "DATA,SACK"-style summary of the flags byte; bare 0 is an ACK. */
static void
udx_flags_to_str(uint8_t flags, char *buf, size_t buf_len)
{
    static const struct {
        uint8_t     bit;
        const char *name;
    } bits[] = {
        { UDX_FLAG_DATA,      "DATA"      },
        { UDX_FLAG_END,       "END"       },
        { UDX_FLAG_SACK,      "SACK"      },
        { UDX_FLAG_MESSAGE,   "MESSAGE"   },
        { UDX_FLAG_DESTROY,   "DESTROY"   },
        { UDX_FLAG_HEARTBEAT, "HEARTBEAT" },
    };
    size_t pos = 0;

    if (flags == 0) {
        (void) g_strlcpy(buf, "ACK", buf_len);
        return;
    }
    buf[0] = '\0';
    for (size_t i = 0; i < array_length(bits); i++) {
        if (flags & bits[i].bit) {
            if (pos > 0)
                pos += g_strlcpy(buf + pos, ",", buf_len - pos);
            pos += g_strlcpy(buf + pos, bits[i].name, buf_len - pos);
        }
    }
}

/*
 * A stable label for the two endpoints of the enclosing UDP conversation.
 * Which endpoint gets 0 does not matter; only that a given endpoint keeps
 * the same label for the whole capture.
 */
static unsigned
udx_direction(const packet_info *pinfo)
{
    int c = cmp_address(&pinfo->src, &pinfo->dst);

    if (c != 0)
        return (c < 0) ? 0 : 1;
    return (pinfo->srcport < pinfo->destport) ? 0 : 1;
}

static udx_flow_t *
udx_get_flow(udx_conv_t *conv, unsigned dir, uint32_t id, const nstime_t *ts)
{
    uint64_t    key = ((uint64_t) dir << 32) | id;
    udx_flow_t *flow = (udx_flow_t *) wmem_map_lookup(conv->flows, &key);
    uint64_t   *key_copy;

    if (flow != NULL)
        return flow;

    flow = wmem_new0(wmem_file_scope(), udx_flow_t);
    flow->id = id;
    flow->dir = dir;
    flow->order = conv->n_flows[dir]++;
    flow->first_ts = *ts;
    flow->segs = wmem_tree_new(wmem_file_scope());
    flow->stream_num = udx_stream_count++;

    key_copy = wmem_new(wmem_file_scope(), uint64_t);
    *key_copy = key;
    wmem_map_insert(conv->flows, key_copy, flow);

    return flow;
}

/*
 * Pairing a flow with its reverse.
 *
 * A UDX conversation is a six tuple, but a packet carries only the receiver's
 * stream id: the ids are exchanged in an encrypted handshake that is not
 * visible here. The reverse flow therefore has to be inferred.
 *
 * Candidates are the flows travelling the other way. Each is scored on
 *   - plausibility: the acknowledgement carried by this packet must fall
 *     within the sequence numbers the candidate has actually sent;
 *   - creation order: streams are set up in pairs, so the n'th flow in one
 *     direction usually answers the n'th flow in the other;
 *   - proximity: the two flows should have appeared at about the same time.
 *
 * A candidate is adopted once it has been the sole best choice twice, which
 * keeps a single ambiguous packet from binding the wrong pair. Once bound,
 * a pairing is never revised.
 */
typedef struct udx_pair_scan {
    udx_flow_t *self;
    uint32_t    ack;
    udx_flow_t *best;
    int         best_score;
    bool        tie;
} udx_pair_scan_t;

static void
udx_score_candidate(void *key _U_, void *value, void *userdata)
{
    udx_flow_t      *cand = (udx_flow_t *) value;
    udx_pair_scan_t *scan = (udx_pair_scan_t *) userdata;
    double           dt;
    int              score = 0;

    if (cand->dir == scan->self->dir || cand->paired != NULL)
        return;

    /* The acknowledgement must not reach past what the candidate has sent. */
    if (cand->have_seq) {
        if (UDX_SEQ_GT(scan->ack, cand->max_seq + 1))
            return;
        score += 4;
    }

    if (cand->order == scan->self->order)
        score += 2;

    dt = nstime_to_sec(&cand->first_ts) - nstime_to_sec(&scan->self->first_ts);
    if (dt < 0)
        dt = -dt;
    if (dt < 0.050)
        score += 1;

    if (score > scan->best_score) {
        scan->best_score = score;
        scan->best = cand;
        scan->tie = false;
    } else if (score == scan->best_score && scan->best != NULL) {
        scan->tie = true;
    }
}

static void
udx_try_pair(udx_conv_t *conv, udx_flow_t *flow, uint32_t ack)
{
    udx_pair_scan_t scan;

    scan.self = flow;
    scan.ack = ack;
    scan.best = NULL;
    scan.best_score = 0;
    scan.tie = false;

    wmem_map_foreach(conv->flows, udx_score_candidate, &scan);

    if (scan.best == NULL || scan.tie) {
        flow->cand = NULL;
        flow->cand_hits = 0;
        return;
    }

    /*
     * One unambiguous winner is adopted at once, so that a stream is paired
     * from its first packet on. An ambiguous scan binds nothing and is
     * retried on the next packet, by which time the acknowledgements have
     * usually separated the candidates.
     */
    flow->cand = scan.best;
    flow->cand_hits++;

    flow->paired = scan.best;
    scan.best->paired = flow;

    /* Both halves report the lower of the two numbers. */
    if (scan.best->stream_num < flow->stream_num)
        flow->stream_num = scan.best->stream_num;
    else
        scan.best->stream_num = flow->stream_num;
}

/* RFC 6298 smoothing, fed only by segments that were never retransmitted. */
static void
udx_update_rtt(udx_flow_t *flow, double sample)
{
    if (!flow->have_rtt) {
        flow->srtt = sample;
        flow->rttvar = sample / 2;
        flow->have_rtt = true;
        return;
    }
    flow->rttvar = 0.75 * flow->rttvar + 0.25 * fabs(flow->srtt - sample);
    flow->srtt = 0.875 * flow->srtt + 0.125 * sample;
}

static double
udx_rto(const udx_flow_t *flow)
{
    double rto;

    if (!flow->have_rtt)
        return UDX_MIN_RTO;
    rto = flow->srtt + 4 * flow->rttvar;
    return (rto < UDX_MIN_RTO) ? UDX_MIN_RTO : rto;
}

/*
 * Retire every segment of the acknowledged flow below "ack", link the last
 * of them to the acknowledging packet, and take an RTT sample from it.
 */
static void
udx_process_ack(packet_info *pinfo, udx_flow_t *acked_flow, udx_flow_t *acking_flow,
                uint32_t ack, udx_ppd_t *ppd)
{
    udx_seg_t *newest = NULL;
    uint32_t   seq = ack - 1;
    unsigned   guard;

    if (!acked_flow->have_seq)
        return;

    /* Walk back from the acknowledgement over the segments it covers. The
     * walk stops at the first segment already retired by an earlier
     * acknowledgement; the counter only bounds pathological captures. */
    for (guard = 0; guard < 1024; guard++, seq--) {
        udx_seg_t *seg = (udx_seg_t *) wmem_tree_lookup32(acked_flow->segs, seq);

        if (seg == NULL || seg->acked_in_frame != 0)
            break;

        seg->acked_in_frame = pinfo->num;
        seg->ack_ts = pinfo->abs_ts;

        if (acked_flow->outstanding_pkts > 0) {
            acked_flow->outstanding_pkts--;
            acked_flow->outstanding_bytes -= seg->len;
        }
        if (newest == NULL)
            newest = seg;
    }

    if (newest != NULL) {
        nstime_t rtt;

        nstime_delta(&rtt, &pinfo->abs_ts, &newest->ts);
        ppd->acks_frame = newest->frame;
        ppd->ack_rtt = rtt;
        ppd->have_ack_rtt = true;

        /* Karn's algorithm: a retransmitted segment yields no usable sample. */
        if (newest->retrans == 0)
            udx_update_rtt(acking_flow, nstime_to_sec(&rtt));
    }
}

static void
udx_analyze(packet_info *pinfo, udx_conv_t *conv, uint8_t flags, uint8_t data_offset,
            uint32_t id, uint32_t window, uint32_t seq, uint32_t ack,
            uint32_t payload_len, const uint32_t *sack_start, const uint32_t *sack_end,
            unsigned n_sacks, udx_ppd_t *ppd)
{
    unsigned    dir = udx_direction(pinfo);
    udx_flow_t *flow = udx_get_flow(conv, dir, id, &pinfo->abs_ts);
    udx_flow_t *rflow;
    udx_seg_t  *seg;
    bool        consumes_seq;

    if (!conv->have_client_dir) {
        conv->client_dir = dir;
        conv->have_client_dir = true;
    }

    ppd->flow = flow;
    ppd->seq = seq;
    ppd->from_server = (dir != conv->client_dir);

    if (flow->paired == NULL)
        udx_try_pair(conv, flow, ack);
    rflow = flow->paired;

    /* DATA and END occupy a sequence number; MESSAGE is an unordered
     * datagram outside the stream and a bare ACK only reports one. */
    consumes_seq = (flags & (UDX_FLAG_DATA | UDX_FLAG_END)) != 0;

    if (consumes_seq) {
        seg = (udx_seg_t *) wmem_tree_lookup32(flow->segs, seq);

        if (seg == NULL) {
            if (flow->have_seq && UDX_SEQ_GT(seq, flow->max_seq + 1))
                ppd->flags |= UDX_A_LOST_SEGMENT;
            else if (flow->have_seq && UDX_SEQ_LT(seq, flow->max_seq))
                ppd->flags |= UDX_A_OUT_OF_ORDER;

            seg = wmem_new0(wmem_file_scope(), udx_seg_t);
            seg->frame = pinfo->num;
            seg->ts = pinfo->abs_ts;
            seg->len = payload_len;
            wmem_tree_insert32(flow->segs, seq, seg);

            if (!flow->have_seq) {
                flow->base_seq = seq;
                flow->max_seq = seq;
                flow->have_seq = true;
            } else if (UDX_SEQ_GT(seq, flow->max_seq)) {
                flow->max_seq = seq;
            }
            flow->outstanding_pkts++;
            flow->outstanding_bytes += payload_len;
        } else {
            double dt = nstime_to_sec(&pinfo->abs_ts) - nstime_to_sec(&seg->ts);

            seg->retrans++;
            ppd->flags |= UDX_A_RETRANS;

            if (seg->acked_in_frame != 0) {
                ppd->flags |= UDX_A_SPURIOUS;
            } else if (flow->have_sacked && UDX_SEQ_GT(flow->max_sacked, seq)) {
                /* The peer has selectively acknowledged later packets, so
                 * this one was resent because it was reported missing rather
                 * than because a timer expired. */
                ppd->flags |= UDX_A_FAST_RETRANS;
            } else if (dt >= udx_rto(flow)) {
                ppd->flags |= UDX_A_RTO_RETRANS;
            } else if (dt < UDX_DUP_WINDOW) {
                /* Too soon to be any sender timer: the datagram was
                 * delivered, or captured, twice. */
                ppd->flags |= UDX_A_DUPLICATE;
            } else if (seq == flow->max_seq &&
                       dt >= (flow->have_rtt ? 2 * flow->srtt : UDX_MIN_PROBE_DELAY)) {
                /* A repeat of the tail after a probe-sized pause, with
                 * nothing newer sent, is how a tail loss probe looks here. */
                ppd->flags |= UDX_A_TLP;
            }
        }

        ppd->tracked = true;
        ppd->bytes_in_flight = flow->outstanding_bytes;
        ppd->packets_in_flight = flow->outstanding_pkts;

        /*
         * Position within the stream, counted from the first packet seen on
         * this flow. Anything before that point arrived out of order at the
         * very start of the capture and cannot be placed.
         */
        if (payload_len > 0 && UDX_SEQ_GEQ(seq, flow->base_seq)) {
            ppd->follow_offset = seq - flow->base_seq;
            ppd->follow_ok = true;
        }
    }

    if (flags & UDX_FLAG_END)
        ppd->flags |= UDX_A_END;
    if (flags & UDX_FLAG_DESTROY)
        ppd->flags |= UDX_A_DESTROY;

    /* An MTU probe pads between the header and the payload; the same byte
     * delimits SACK blocks when they are present. */
    if (data_offset > 0 && !(flags & UDX_FLAG_SACK))
        ppd->flags |= UDX_A_MTU_PROBE;

    /* Acknowledgement side: retire the peer's segments, then record the
     * selective ranges so a later repeat can be recognised as recovery. */
    if (rflow != NULL) {
        if (!flow->have_ack || UDX_SEQ_GT(ack, flow->max_ack))
            udx_process_ack(pinfo, rflow, flow, ack, ppd);

        for (unsigned i = 0; i < n_sacks; i++) {
            uint32_t s;
            unsigned guard = 0;

            for (s = sack_start[i]; UDX_SEQ_LT(s, sack_end[i]) && guard < 1024;
                 s++, guard++) {
                udx_seg_t *ss = (udx_seg_t *) wmem_tree_lookup32(rflow->segs, s);

                if (ss != NULL)
                    ss->sacked = true;
            }

            /* Remember how far the selective acknowledgements reach: a
             * retransmission below this point is loss recovery. */
            if (!rflow->have_sacked || UDX_SEQ_GT(sack_end[i] - 1, rflow->max_sacked)) {
                rflow->max_sacked = sack_end[i] - 1;
                rflow->have_sacked = true;
            }
        }
    }

    if (!flow->have_ack || UDX_SEQ_GT(ack, flow->max_ack)) {
        flow->max_ack = ack;
        flow->have_ack = true;
    }

    /* Receive window transitions. */
    if (window == 0) {
        ppd->flags |= UDX_A_ZERO_WIN;
        flow->rwnd_zero = true;
    } else if (flow->rwnd_zero) {
        ppd->flags |= UDX_A_WINDOW_UPDATE;
        flow->rwnd_zero = false;
    }
    flow->last_rwnd = window;

    /*
     * Keepalives and zero-window probes are the same bytes on the wire: a
     * bare heartbeat. Only the peer's advertised window tells them apart.
     */
    if ((flags & UDX_FLAG_HEARTBEAT) && payload_len == 0) {
        if (rflow != NULL && rflow->rwnd_zero)
            ppd->flags |= UDX_A_ZERO_WIN_PROBE;
        else
            ppd->flags |= UDX_A_KEEPALIVE;
    }

    ppd->stream = (flow->paired != NULL && flow->paired->stream_num < flow->stream_num)
        ? flow->paired->stream_num
        : flow->stream_num;
}

/*
 * Render the verdicts reached on the first pass. Nothing here computes: on a
 * revisit the stored results are simply replayed, so what is shown never
 * depends on how the packet was reached.
 */
static void
udx_show_analysis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, udx_ppd_t *ppd)
{
    proto_item *ti;
    proto_tree *an_tree;
    udx_seg_t  *seg;

    if (ppd->flow == NULL)
        return;

    ti = proto_tree_add_uint(tree, hf_udx_stream, tvb, 0, 0,
                             (ppd->flow->paired != NULL &&
                              ppd->flow->paired->stream_num < ppd->flow->stream_num)
                                 ? ppd->flow->paired->stream_num
                                 : ppd->flow->stream_num);
    proto_item_set_generated(ti);

    /* Nothing to report on a packet that neither carries data nor advances
     * an acknowledgement, so leave the subtree out entirely rather than
     * showing an empty one. */
    if (ppd->flags == 0 && ppd->acks_frame == 0 && !ppd->tracked &&
        ppd->flow->paired != NULL)
        return;

    ti = proto_tree_add_item(tree, hf_udx_analysis, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(ti);
    an_tree = proto_item_add_subtree(ti, ett_udx_analysis);

    if (ppd->flow->paired == NULL) {
        proto_item *rev_ti = proto_tree_add_item(an_tree, hf_udx_analysis_no_reverse,
                                                 tvb, 0, 0, ENC_NA);
        proto_item_set_generated(rev_ti);
    }

    if (ppd->acks_frame != 0) {
        ti = proto_tree_add_uint(an_tree, hf_udx_analysis_acks_frame, tvb, 0, 0,
                                 ppd->acks_frame);
        proto_item_set_generated(ti);

        if (ppd->have_ack_rtt) {
            ti = proto_tree_add_time(an_tree, hf_udx_analysis_ack_rtt, tvb, 0, 0,
                                     &ppd->ack_rtt);
            proto_item_set_generated(ti);
        }
    }

    /* A packet that carried data learns only later which packet acked it. */
    if (ppd->tracked) {
        seg = (udx_seg_t *) wmem_tree_lookup32(ppd->flow->segs, ppd->seq);
        if (seg != NULL && seg->frame == pinfo->num && seg->acked_in_frame != 0) {
            nstime_t rtt;

            ti = proto_tree_add_uint(an_tree, hf_udx_analysis_acked_in, tvb, 0, 0,
                                     seg->acked_in_frame);
            proto_item_set_generated(ti);

            nstime_delta(&rtt, &seg->ack_ts, &seg->ts);
            ti = proto_tree_add_time(an_tree, hf_udx_analysis_ack_rtt, tvb, 0, 0, &rtt);
            proto_item_set_generated(ti);
        }

        ti = proto_tree_add_uint(an_tree, hf_udx_analysis_bytes_in_flight, tvb, 0, 0,
                                 ppd->bytes_in_flight);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(an_tree, hf_udx_analysis_pkts_in_flight, tvb, 0, 0,
                                 ppd->packets_in_flight);
        proto_item_set_generated(ti);
    }

    /* Expert notes, most specific classification first. */
    if (ppd->flags & UDX_A_LOST_SEGMENT)
        expert_add_info(pinfo, ti, &ei_udx_lost_segment);
    if (ppd->flags & UDX_A_OUT_OF_ORDER)
        expert_add_info(pinfo, ti, &ei_udx_out_of_order);

    if (ppd->flags & UDX_A_SPURIOUS)
        expert_add_info(pinfo, ti, &ei_udx_spurious_retrans);
    else if (ppd->flags & UDX_A_FAST_RETRANS)
        expert_add_info(pinfo, ti, &ei_udx_fast_retrans);
    else if (ppd->flags & UDX_A_RTO_RETRANS)
        expert_add_info(pinfo, ti, &ei_udx_rto_retrans);
    else if (ppd->flags & UDX_A_TLP)
        expert_add_info(pinfo, ti, &ei_udx_tlp);
    else if (ppd->flags & UDX_A_DUPLICATE)
        expert_add_info(pinfo, ti, &ei_udx_duplicate);
    else if (ppd->flags & UDX_A_RETRANS)
        expert_add_info(pinfo, ti, &ei_udx_retrans);

    if (ppd->flags & UDX_A_ZERO_WIN_PROBE)
        expert_add_info(pinfo, ti, &ei_udx_zero_window_probe);
    else if (ppd->flags & UDX_A_KEEPALIVE)
        expert_add_info(pinfo, ti, &ei_udx_keepalive);

    if (ppd->flags & UDX_A_ZERO_WIN)
        expert_add_info(pinfo, ti, &ei_udx_zero_window);
    if (ppd->flags & UDX_A_WINDOW_UPDATE)
        expert_add_info(pinfo, ti, &ei_udx_window_update);
    if (ppd->flags & UDX_A_MTU_PROBE)
        expert_add_info(pinfo, ti, &ei_udx_mtu_probe);
    if (ppd->flags & UDX_A_END)
        expert_add_info(pinfo, ti, &ei_udx_end);
    if (ppd->flags & UDX_A_DESTROY)
        expert_add_info(pinfo, ti, &ei_udx_destroy);
}


/*
 * Follow stream.
 *
 * Payload is delivered in sequence order per direction. A packet that
 * arrives early is held until the gap before it is filled, and a payload
 * already delivered - a retransmission - is dropped, so the reassembled
 * conversation reads the way the application saw it rather than the way the
 * network happened to deliver it.
 */

/* Stream numbers restart with every capture file, as they do for TCP. */
static void
udx_init(void)
{
    udx_stream_count = 0;
}

static char *
udx_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo,
                       unsigned *stream, unsigned *sub_stream _U_)
{
    udx_ppd_t *ppd = (udx_ppd_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_udx, 0);

    if (ppd == NULL || ppd->flow == NULL)
        return NULL;

    *stream = ppd->stream;
    return ws_strdup_printf("udx.stream eq %u", ppd->stream);
}

static char *
udx_follow_index_filter(unsigned stream, unsigned sub_stream _U_)
{
    return ws_strdup_printf("udx.stream eq %u", stream);
}

static unsigned
udx_get_stream_count(void)
{
    return udx_stream_count;
}

static void
udx_follow_append(follow_info_t *follow_info, follow_record_t *record)
{
    follow_info->payload = g_list_prepend(follow_info->payload, record);
    follow_info->bytes_written[record->is_server ? 1 : 0] += record->data->len;
}

static int
udx_follow_seq_cmp(const void *a, const void *b)
{
    const follow_record_t *ra = (const follow_record_t *) a;
    const follow_record_t *rb = (const follow_record_t *) b;

    if (ra->seq == rb->seq)
        return 0;
    return (ra->seq < rb->seq) ? -1 : 1;
}

/*
 * Release held payload that now continues the stream. The pending list is
 * kept in sequence order, so this only ever walks its front.
 */
static void
udx_follow_drain(follow_info_t *follow_info, int dir)
{
    while (follow_info->fragments[dir] != NULL) {
        follow_record_t *held = (follow_record_t *) follow_info->fragments[dir]->data;

        if (held->seq != follow_info->seq[dir])
            break;

        follow_info->seq[dir]++;
        follow_info->fragments[dir] = g_list_delete_link(follow_info->fragments[dir],
                                                         follow_info->fragments[dir]);
        udx_follow_append(follow_info, held);
    }
}

static tap_packet_status
udx_follow_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
                        const void *data, tap_flags_t flags _U_)
{
    follow_info_t               *follow_info = (follow_info_t *) tapdata;
    const udx_follow_tap_data_t *follow_data = (const udx_follow_tap_data_t *) data;
    follow_record_t             *record;
    unsigned                     length = tvb_captured_length(follow_data->tvb);
    int                          dir = follow_data->from_server ? 1 : 0;

    if (follow_info->stream_id != follow_data->stream)
        return TAP_PACKET_DONT_REDRAW;

    /* Already delivered: a retransmission or a duplicate. */
    if (follow_data->offset < follow_info->seq[dir])
        return TAP_PACKET_DONT_REDRAW;

    record = g_new0(follow_record_t, 1);
    record->is_server = follow_data->from_server;
    record->packet_num = pinfo->fd->num;
    record->abs_ts = pinfo->fd->abs_ts;
    record->seq = follow_data->offset;
    record->data = g_byte_array_sized_new(length);
    record->data = g_byte_array_append(record->data,
                                       tvb_get_ptr(follow_data->tvb, 0, length), length);

    if (follow_data->from_server) {
        if (follow_info->server_port == 0) {
            follow_info->server_port = pinfo->srcport;
            copy_address(&follow_info->server_ip, &pinfo->src);
            follow_info->client_port = pinfo->destport;
            copy_address(&follow_info->client_ip, &pinfo->dst);
        }
    } else {
        if (follow_info->client_port == 0) {
            follow_info->client_port = pinfo->srcport;
            copy_address(&follow_info->client_ip, &pinfo->src);
            follow_info->server_port = pinfo->destport;
            copy_address(&follow_info->server_ip, &pinfo->dst);
        }
    }

    if (follow_data->offset == follow_info->seq[dir]) {
        follow_info->seq[dir]++;
        udx_follow_append(follow_info, record);
        udx_follow_drain(follow_info, dir);
    } else {
        /* Arrived early: hold it, in order, until the gap ahead is filled.
         * The framework frees whatever is still pending when the stream is
         * reset, so an unfilled gap leaks nothing. */
        follow_info->fragments[dir] = g_list_insert_sorted(follow_info->fragments[dir],
                                                           record, udx_follow_seq_cmp);
    }

    return TAP_PACKET_DONT_REDRAW;
}

static int
dissect_udx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *udx_tree;
    uint8_t     flags, data_offset;
    uint32_t    id, window, seq, ack;
    int         offset = 0;
    int         sack_end_offset;
    unsigned    payload_len;
    char        flags_str[64];
    uint32_t    sack_start[UDX_MAX_SACK_BLOCKS];
    uint32_t    sack_end[UDX_MAX_SACK_BLOCKS];
    unsigned    n_sacks = 0;
    udx_ppd_t  *ppd = NULL;

    /*
     * Reached either from the heuristic, which has already validated the
     * header, or directly once a conversation has been claimed or through
     * "Decode As". The latter routes make this check load bearing.
     */
    if (tvb_reported_length(tvb) < UDX_HEADER_SIZE)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDX");
    col_clear(pinfo->cinfo, COL_INFO);

    flags = tvb_get_uint8(tvb, 2);
    data_offset = tvb_get_uint8(tvb, 3);
    id = tvb_get_letohl(tvb, 4);
    window = tvb_get_letohl(tvb, 8);
    seq = tvb_get_letohl(tvb, 12);
    ack = tvb_get_letohl(tvb, 16);

    udx_flags_to_str(flags, flags_str, sizeof(flags_str));

    /* Collect the selective acknowledgement ranges before anything is added
     * to the tree: the analysis below needs them, and the display needs the
     * analysis. */
    if (flags & UDX_FLAG_SACK) {
        /* Blocks fill the area delimited by data_offset; a packet with no
         * payload may leave that byte zero and run to the end instead. */
        sack_end_offset = (data_offset > 0)
            ? UDX_HEADER_SIZE + data_offset
            : (int) tvb_reported_length(tvb);
    } else {
        /* Anything reserved without SACK blocks is MTU probe padding. */
        sack_end_offset = UDX_HEADER_SIZE + data_offset;
    }

    /* data_offset is not trustworthy on a packet this dissector did not
     * validate, so never let it point past the datagram. */
    sack_end_offset = MIN(sack_end_offset, (int) tvb_reported_length(tvb));

    if (flags & UDX_FLAG_SACK) {
        int pos = UDX_HEADER_SIZE;

        while (pos + 8 <= sack_end_offset && n_sacks < UDX_MAX_SACK_BLOCKS) {
            sack_start[n_sacks] = tvb_get_letohl(tvb, pos);
            sack_end[n_sacks] = tvb_get_letohl(tvb, pos + 4);
            n_sacks++;
            pos += 8;
        }
    }

    payload_len = (unsigned) MAX(0, (int) tvb_reported_length(tvb) - sack_end_offset);

    if (udx_analyze_sequence_numbers) {
        if (!PINFO_FD_VISITED(pinfo)) {
            conversation_t *conversation = find_or_create_conversation(pinfo);
            udx_conv_t     *conv;

            conv = (udx_conv_t *) conversation_get_proto_data(conversation, proto_udx);
            if (conv == NULL) {
                conv = wmem_new0(wmem_file_scope(), udx_conv_t);
                conv->flows = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
                conversation_add_proto_data(conversation, proto_udx, conv);
            }

            ppd = wmem_new0(wmem_file_scope(), udx_ppd_t);
            udx_analyze(pinfo, conv, flags, data_offset, id, window, seq, ack,
                        payload_len, sack_start, sack_end, n_sacks, ppd);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_udx, 0, ppd);
        } else {
            ppd = (udx_ppd_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_udx, 0);
        }
    }

    ti = proto_tree_add_item(tree, proto_udx, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", %s, Id: %u, Seq: %u, Ack: %u", flags_str, id, seq, ack);
    udx_tree = proto_item_add_subtree(ti, ett_udx);

    proto_tree_add_item(udx_tree, hf_udx_magic, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(udx_tree, hf_udx_version, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(udx_tree, tvb, offset, hf_udx_flags, ett_udx_flags,
                           udx_flag_fields, ENC_NA);
    offset += 1;
    proto_tree_add_item(udx_tree, hf_udx_data_offset, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(udx_tree, hf_udx_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(udx_tree, hf_udx_window, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(udx_tree, hf_udx_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(udx_tree, hf_udx_ack, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if (n_sacks > 0) {
        proto_item *sacks_ti;
        proto_tree *sacks_tree, *block_tree;

        sacks_ti = proto_tree_add_item(udx_tree, hf_udx_sacks, tvb, offset,
                                       sack_end_offset - offset, ENC_NA);
        proto_item_append_text(sacks_ti, " (%u)", n_sacks);
        sacks_tree = proto_item_add_subtree(sacks_ti, ett_udx_sacks);

        for (unsigned i = 0; i < n_sacks; i++) {
            block_tree = proto_tree_add_subtree_format(sacks_tree, tvb, offset, 8,
                                                       ett_udx_sack_block, NULL,
                                                       "SACK: %u-%u",
                                                       sack_start[i], sack_end[i]);
            proto_tree_add_item(block_tree, hf_udx_sack_start, tvb, offset, 4,
                                ENC_LITTLE_ENDIAN);
            proto_tree_add_item(block_tree, hf_udx_sack_end, tvb, offset + 4, 4,
                                ENC_LITTLE_ENDIAN);
            offset += 8;
        }
    } else if (!(flags & UDX_FLAG_SACK) && data_offset > 0) {
        /*
         * Padding between header and payload with no SACK blocks: inserted by
         * mtu_probeify_packet() in libudx - this datagram is an MTU probe.
         */
        proto_tree_add_item(udx_tree, hf_udx_padding, tvb, offset, data_offset, ENC_NA);
        offset += data_offset;
    }

    if (payload_len > 0) {
        ti = proto_tree_add_uint(udx_tree, hf_udx_payload_len, tvb, 0, 0, payload_len);
        proto_item_set_generated(ti);
        proto_tree_add_item(udx_tree, hf_udx_payload, tvb, sack_end_offset,
                            (int) payload_len, ENC_NA);
    }

    if (ppd != NULL) {
        udx_show_analysis(tvb, pinfo, udx_tree, ppd);

        /* MESSAGE payloads travel outside the ordered stream, so they are
         * shown per packet but left out of the reassembled conversation. */
        if (ppd->follow_ok && !(flags & UDX_FLAG_MESSAGE) &&
            have_tap_listener(udx_follow_tap)) {
            udx_follow_tap_data_t *follow_data = wmem_new0(pinfo->pool, udx_follow_tap_data_t);

            follow_data->tvb = tvb_new_subset_length(tvb, sack_end_offset, (int) payload_len);
            follow_data->stream = ppd->stream;
            follow_data->offset = ppd->follow_offset;
            follow_data->from_server = ppd->from_server;
            tap_queue_packet(udx_follow_tap, pinfo, follow_data);
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Id=%u Seq=%u Ack=%u Rwnd=%u",
                 flags_str, id, seq, ack, window);
    if (payload_len > 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, " Len=%u", payload_len);
    if (ppd != NULL && (ppd->flags & UDX_A_RETRANS))
        col_append_str(pinfo->cinfo, COL_INFO, " [retransmission]");

    return tvb_reported_length(tvb);
}

static bool
test_udx(tvbuff_t *tvb)
{
    uint8_t flags, data_offset;

    if (tvb_captured_length(tvb) < UDX_HEADER_SIZE)
        return false;
    if (tvb_get_uint8(tvb, 0) != UDX_MAGIC_BYTE)
        return false;
    if (tvb_get_uint8(tvb, 1) != UDX_VERSION)
        return false;

    flags = tvb_get_uint8(tvb, 2);
    if (flags & ~UDX_FLAG_MASK)
        return false;

    data_offset = tvb_get_uint8(tvb, 3);
    if (UDX_HEADER_SIZE + (unsigned) data_offset > tvb_reported_length(tvb))
        return false;
    /* The area delimited by data_offset holds SACK blocks (uint32 pairs) when
     * the SACK flag is set - anything not a multiple of 8 is not UDX. */
    if ((flags & UDX_FLAG_SACK) && data_offset > 0 && (data_offset % 8) != 0)
        return false;

    /*
     * Only DATA and MESSAGE packets carry a payload. Everything else is the
     * fixed header followed at most by selective acknowledgement blocks, so
     * its length is known exactly and anything else is not UDX.
     */
    if (!(flags & (UDX_FLAG_DATA | UDX_FLAG_MESSAGE))) {
        unsigned trailing = tvb_reported_length(tvb) - UDX_HEADER_SIZE;

        if (flags & UDX_FLAG_SACK) {
            if ((trailing % 8) != 0)
                return false;
        } else if (trailing != 0) {
            return false;
        }
    }

    return true;
}

static bool
dissect_udx_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;

    if (!test_udx(tvb))
        return false;

    /* Claim the whole UDP conversation so weaker frames (e.g. bare 20-byte
     * heartbeats) and future packets skip the heuristic. */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, udx_handle);

    dissect_udx(tvb, pinfo, tree, data);
    return true;
}

void
proto_register_udx(void)
{
    static hf_register_info hf[] = {
        { &hf_udx_magic,
          { "Magic Byte", "udx.magic_byte", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Always 0xff", HFILL }
        },
        { &hf_udx_version,
          { "Version", "udx.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_udx_flags,
          { "Type", "udx.type", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Packet type flags", HFILL }
        },
        { &hf_udx_flags_data,
          { "Data", "udx.type.data", FT_BOOLEAN, 8, NULL, UDX_FLAG_DATA,
            "Carries stream payload", HFILL }
        },
        { &hf_udx_flags_end,
          { "End", "udx.type.end", FT_BOOLEAN, 8, NULL, UDX_FLAG_END,
            "Graceful end of stream (consumes a sequence number)", HFILL }
        },
        { &hf_udx_flags_sack,
          { "SACK", "udx.type.sack", FT_BOOLEAN, 8, NULL, UDX_FLAG_SACK,
            "Carries selective acknowledgement blocks", HFILL }
        },
        { &hf_udx_flags_message,
          { "Message", "udx.type.message", FT_BOOLEAN, 8, NULL, UDX_FLAG_MESSAGE,
            "Unordered datagram outside the byte stream", HFILL }
        },
        { &hf_udx_flags_destroy,
          { "Destroy", "udx.type.destroy", FT_BOOLEAN, 8, NULL, UDX_FLAG_DESTROY,
            "Abrupt stream termination", HFILL }
        },
        { &hf_udx_flags_heartbeat,
          { "Heartbeat", "udx.type.heartbeat", FT_BOOLEAN, 8, NULL, UDX_FLAG_HEARTBEAT,
            "Keepalive or zero-window probe", HFILL }
        },
        { &hf_udx_data_offset,
          { "Data Offset", "udx.data_offset", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Bytes between the fixed header and the payload", HFILL }
        },
        { &hf_udx_id,
          { "Id", "udx.id", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Receiver's stream id", HFILL }
        },
        { &hf_udx_window,
          { "Window", "udx.rwnd", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Sender's receive window in bytes", HFILL }
        },
        { &hf_udx_seq,
          { "Seq", "udx.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Packet sequence number (counts packets, not bytes)", HFILL }
        },
        { &hf_udx_ack,
          { "Ack", "udx.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Next sequence number expected from the peer", HFILL }
        },
        { &hf_udx_sacks,
          { "SACK Blocks", "udx.sacks", FT_NONE, BASE_NONE, NULL, 0x0,
            "Selective acknowledgement ranges", HFILL }
        },
        { &hf_udx_sack_block,
          { "SACK Block", "udx.sack", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_udx_sack_start,
          { "Start", "udx.sack.start", FT_UINT32, BASE_DEC, NULL, 0x0,
            "First sequence number in the acknowledged range", HFILL }
        },
        { &hf_udx_sack_end,
          { "End", "udx.sack.end", FT_UINT32, BASE_DEC, NULL, 0x0,
            "One past the last acknowledged sequence number", HFILL }
        },
        { &hf_udx_padding,
          { "Padding", "udx.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
            "MTU probe padding", HFILL }
        },
        { &hf_udx_payload,
          { "Payload", "udx.payload", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_udx_payload_len,
          { "Payload Length", "udx.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_udx_stream,
          { "Stream index", "udx.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Index of the paired flows carrying this stream", HFILL }
        },
        { &hf_udx_analysis,
          { "SEQ/ACK analysis", "udx.analysis", FT_NONE, BASE_NONE, NULL, 0x0,
            "Results of the sequence number analysis", HFILL }
        },
        { &hf_udx_analysis_acks_frame,
          { "This is an ACK to the packet in frame", "udx.analysis.acks_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0,
            NULL, HFILL }
        },
        { &hf_udx_analysis_acked_in,
          { "ACKed in frame", "udx.analysis.acked_in", FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
            "The frame that acknowledged this packet", HFILL }
        },
        { &hf_udx_analysis_ack_rtt,
          { "Time to ACK", "udx.analysis.ack_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time between the packet and its acknowledgement", HFILL }
        },
        { &hf_udx_analysis_bytes_in_flight,
          { "Bytes in flight", "udx.analysis.bytes_in_flight", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Unacknowledged payload bytes on this flow", HFILL }
        },
        { &hf_udx_analysis_pkts_in_flight,
          { "Packets in flight", "udx.analysis.packets_in_flight", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Unacknowledged packets on this flow", HFILL }
        },
        { &hf_udx_analysis_no_reverse,
          { "Reverse flow not identified", "udx.analysis.no_reverse", FT_NONE, BASE_NONE,
            NULL, 0x0, "The stream carrying the other direction has not been paired",
            HFILL }
        },
    };

    static int *ett[] = {
        &ett_udx,
        &ett_udx_flags,
        &ett_udx_sacks,
        &ett_udx_sack_block,
        &ett_udx_analysis,
    };

    static ei_register_info ei[] = {
        { &ei_udx_retrans,
          { "udx.analysis.retransmission", PI_SEQUENCE, PI_NOTE,
            "This packet was retransmitted", EXPFILL }
        },
        { &ei_udx_fast_retrans,
          { "udx.analysis.fast_retransmission", PI_SEQUENCE, PI_NOTE,
            "Fast retransmission: resent while later packets were selectively"
            " acknowledged", EXPFILL }
        },
        { &ei_udx_rto_retrans,
          { "udx.analysis.rto_retransmission", PI_SEQUENCE, PI_NOTE,
            "Retransmission timeout: resent after more than the estimated RTO",
            EXPFILL }
        },
        { &ei_udx_tlp,
          { "udx.analysis.tail_loss_probe", PI_SEQUENCE, PI_NOTE,
            "Tail loss probe: the last packet of a burst was resent to elicit an"
            " acknowledgement", EXPFILL }
        },
        { &ei_udx_spurious_retrans,
          { "udx.analysis.spurious_retransmission", PI_SEQUENCE, PI_NOTE,
            "Spurious retransmission: this packet was already acknowledged", EXPFILL }
        },
        { &ei_udx_duplicate,
          { "udx.analysis.duplicate", PI_SEQUENCE, PI_NOTE,
            "Duplicate packet: the same packet was seen twice in quick succession",
            EXPFILL }
        },
        { &ei_udx_out_of_order,
          { "udx.analysis.out_of_order", PI_SEQUENCE, PI_NOTE,
            "Out-of-order packet", EXPFILL }
        },
        { &ei_udx_lost_segment,
          { "udx.analysis.lost_segment", PI_SEQUENCE, PI_WARN,
            "Previous packet not captured: a sequence number was skipped", EXPFILL }
        },
        { &ei_udx_keepalive,
          { "udx.analysis.keepalive", PI_SEQUENCE, PI_NOTE,
            "Keepalive", EXPFILL }
        },
        { &ei_udx_zero_window_probe,
          { "udx.analysis.zero_window_probe", PI_SEQUENCE, PI_NOTE,
            "Zero window probe: sent while the peer advertised no receive window",
            EXPFILL }
        },
        { &ei_udx_zero_window,
          { "udx.analysis.zero_window", PI_SEQUENCE, PI_WARN,
            "Zero window: the sender cannot accept more data", EXPFILL }
        },
        { &ei_udx_window_update,
          { "udx.analysis.window_update", PI_SEQUENCE, PI_CHAT,
            "Window update: the receive window reopened", EXPFILL }
        },
        { &ei_udx_mtu_probe,
          { "udx.analysis.mtu_probe", PI_SEQUENCE, PI_CHAT,
            "MTU probe: padded to test a larger path MTU", EXPFILL }
        },
        { &ei_udx_end,
          { "udx.analysis.end", PI_SEQUENCE, PI_CHAT,
            "End of stream", EXPFILL }
        },
        { &ei_udx_destroy,
          { "udx.analysis.destroy", PI_SEQUENCE, PI_WARN,
            "Stream destroyed: abrupt termination", EXPFILL }
        },
    };

    expert_module_t *expert_udx;
    module_t        *udx_module;

    proto_udx = proto_register_protocol("UDX Protocol", "UDX", "udx");
    proto_register_field_array(proto_udx, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_udx = expert_register_protocol(proto_udx);
    expert_register_field_array(expert_udx, ei, array_length(ei));

    udx_handle = register_dissector("udx", dissect_udx, proto_udx);

    register_init_routine(udx_init);

    udx_follow_tap = register_tap("udx_follow");
    register_follow_stream(proto_udx, "udx_follow",
                           udx_follow_conv_filter, udx_follow_index_filter,
                           udp_follow_address_filter, udp_port_to_display,
                           udx_follow_tap_listener, udx_get_stream_count, NULL);

    udx_module = prefs_register_protocol(proto_udx, NULL);
    prefs_register_bool_preference(udx_module, "analyze_sequence_numbers",
        "Analyze UDX sequence numbers",
        "Track sequence and acknowledgement numbers to pair flows, measure "
        "round-trip times and flag retransmissions",
        &udx_analyze_sequence_numbers);
}

void
proto_reg_handoff_udx(void)
{
    heur_dissector_add("udp", dissect_udx_heur, "UDX over UDP", "udx_udp",
                       proto_udx, HEURISTIC_DISABLE);
    dissector_add_for_decode_as_with_preference("udp.port", udx_handle);
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
