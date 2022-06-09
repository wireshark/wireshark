/* packet-gsm_osmux.c
 * Routines for packet dissection of Osmux voice/signalling multiplex protocol
 * Copyright 2016 sysmocom s.f.m.c Daniel Willmann <dwillmann@sysmocom.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /* FIXME: I didn't find a way yet to reliably differentiate between streams
  * using same IPs+PORTs+CID over time. That means: if a recording session is
  * long enough, a call may have allocated a CID which was already used by
  * someone else in the past, and wireshark will handle those two calls as the
  * same stream. This is bad specially for statistics such as jitter.
  */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/stats_tree.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/strutil.h>

void proto_register_osmux(void);
void proto_reg_handoff_osmux(void);

#define OSMUX_FT_SIGNAL 0x00
#define OSMUX_FT_AMR 0x01
#define OSMUX_FT_DUMMY 0x02

static const value_string osmux_ft_vals[] =
{
    {OSMUX_FT_SIGNAL, "Signalling"},
    {OSMUX_FT_AMR, "AMR"},
    {OSMUX_FT_DUMMY, "Dummy"},
    {0, NULL}
};

#define AMR_FT_0    0
#define AMR_FT_1    1
#define AMR_FT_2    2
#define AMR_FT_3    3
#define AMR_FT_4    4
#define AMR_FT_5    5
#define AMR_FT_6    6
#define AMR_FT_7    7
#define AMR_FT_SID  8
#define AMR_FT_MAX  9

static const value_string amr_ft_names[] =
{
    {AMR_FT_0, "AMR 4.75"},
    {AMR_FT_1, "AMR 5.15"},
    {AMR_FT_2, "AMR 5.90"},
    {AMR_FT_3, "AMR 6.70"},
    {AMR_FT_4, "AMR 7.40"},
    {AMR_FT_5, "AMR 7.95"},
    {AMR_FT_6, "AMR 10.2"},
    {AMR_FT_7, "AMR 12.2"},
    {AMR_FT_SID, "AMR SID"},
    {0, NULL}
};

static guint8 amr_ft_bytes[AMR_FT_MAX] = {12, 13, 15, 17, 19, 20, 26, 31, 6};

#define OSMUX_AMR_HEADER_LEN 4

/* Initialize the protocol and registered fields */
static dissector_handle_t osmux_handle;
static int proto_osmux = -1;
static int osmux_tap = -1;

static int hf_osmux_stream_id = -1;
static int hf_osmux_ft_ctr = -1;
static int hf_osmux_rtp_m = -1;
static int hf_osmux_ft = -1;
static int hf_osmux_ctr = -1;
static int hf_osmux_amr_f = -1;
static int hf_osmux_amr_q = -1;
static int hf_osmux_seq = -1;
static int hf_osmux_circuit_id = -1;
static int hf_osmux_amr_ft_cmr = -1;
static int hf_osmux_amr_ft = -1;
static int hf_osmux_amr_cmr = -1;
static int hf_osmux_amr_data = -1;

/* Initialize the subtree pointers */
static gint ett_osmux = -1;
static gint ett_osmux_ft_ctr = -1;
static gint ett_osmux_amr_ft_cmr = -1;

/* Stream handling */
static wmem_map_t *osmux_stream_hash;
static guint32 osmux_next_stream_id;

struct osmux_stream_key {
    address src;
    address dst;
    port_type ptype;
    guint32 srcport;
    guint32 destport;
    guint32 cid;
};

struct osmux_stats_tree {
    gint node_id;
    gboolean amr_received;
    guint32 last_seq;
    guint32 prev_seq;
    nstime_t prev_ts;
    double jitter;
};

struct osmux_stream {
    struct osmux_stream_key *key;
    struct osmux_stats_tree stats;
    guint32 id;
};

/* Tap structure of Osmux header */
struct osmux_hdr {
    gboolean rtp_m;
    guint8 ft;
    guint8 ctr;
    gboolean amr_f;
    gboolean amr_q;
    guint8 seq;
    guint8 circuit_id;
    guint8 amr_cmr;
    guint8 amr_ft;
    gboolean is_old_dummy;
    struct osmux_stream *stream;
};

/* Code to calculate AMR payload size */
static guint8
amr_ft_to_bytes(guint8 amr_ft)
{
    if (amr_ft >= AMR_FT_MAX) /* malformed packet ? */
        return 0;
    return amr_ft_bytes[amr_ft];
}

/*
 * Hash Functions
 */
static gint
osmux_equal(gconstpointer v, gconstpointer w)
{
    const struct osmux_stream_key *v1 = (const struct osmux_stream_key *)v;
    const struct osmux_stream_key *v2 = (const struct osmux_stream_key *)w;

    if (v1->ptype != v2->ptype)
        return 0;	/* different types of port */

    if (v1->srcport == v2->srcport &&
        v1->destport == v2->destport &&
        addresses_equal(&v1->src, &v2->src) &&
        addresses_equal(&v1->dst, &v2->dst) &&
        v1->cid == v2->cid) {
        return 1;
    }

    return 0;
}

static guint
osmux_hash (gconstpointer v)
{
    const struct osmux_stream_key *key = (const struct osmux_stream_key *)v;
    guint hash_val;
    address tmp_addr;

    hash_val = 0;
    tmp_addr.len  = 4;

    hash_val = add_address_to_hash(hash_val, &key->src);
    tmp_addr.data = &key->srcport;
    hash_val = add_address_to_hash(hash_val, &tmp_addr);

    hash_val = add_address_to_hash(hash_val, &key->dst);
    tmp_addr.data = &key->destport;
    hash_val = add_address_to_hash(hash_val, &tmp_addr);

    tmp_addr.data = &key->cid;
    hash_val = add_address_to_hash(hash_val, &tmp_addr);

    hash_val += ( hash_val << 3 );
    hash_val ^= ( hash_val >> 11 );
    hash_val += ( hash_val << 15 );

    return hash_val;
}


static gchar* stream_str(struct osmux_stream *stream, packet_info* pinfo)
{
    gchar *ip_str, *ip2_str, *str;

    ip_str = address_to_str(NULL, &stream->key->src);
    ip2_str = address_to_str(NULL, &stream->key->dst);
    str = wmem_strdup_printf(pinfo->pool, "%u ([%s:%u->%s:%u]:%u)", stream->id,
                ip_str, stream->key->srcport, ip2_str, stream->key->destport,
                stream->key->cid);
    wmem_free(NULL, ip_str);
    wmem_free(NULL, ip2_str);

    return str;
}

static struct osmux_stream *
get_stream(packet_info *pinfo, guint32 cid)
{
    struct osmux_stream_key key, *new_key;
    struct osmux_stream *stream;

    copy_address_shallow(&key.src, &pinfo->src);
    copy_address_shallow(&key.dst, &pinfo->dst);
    key.ptype = pinfo->ptype;
    key.srcport = pinfo->srcport;
    key.destport = pinfo->destport;
    key.cid = cid;

    stream = (struct osmux_stream *) wmem_map_lookup(osmux_stream_hash, &key);
    if (!stream) {
        new_key = wmem_new(wmem_file_scope(), struct osmux_stream_key);
        *new_key = key;
        copy_address_wmem(wmem_file_scope(), &new_key->src, &key.src);
        copy_address_wmem(wmem_file_scope(), &new_key->dst, &key.dst);

        stream = wmem_new0(wmem_file_scope(), struct osmux_stream);
        stream->key = new_key;
        stream->id = osmux_next_stream_id;
        osmux_next_stream_id++;

        wmem_map_insert(osmux_stream_hash, new_key, stream);
    }

    return stream;
}


static void finish_process_pkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct osmux_hdr *osmuxh)
{
    proto_item* ti;
    osmuxh->stream = get_stream(pinfo, osmuxh->circuit_id);

    ti = proto_tree_add_uint(tree, hf_osmux_stream_id, tvb, 0, 0, osmuxh->stream->id);
    proto_item_set_generated(ti);
    tap_queue_packet(osmux_tap, pinfo, osmuxh);
}

/* Code to actually dissect the packets */
static gint
dissect_osmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static int * const ft_ctr_fields[] = {
        &hf_osmux_rtp_m,
        &hf_osmux_ft,
        &hf_osmux_ctr,
        &hf_osmux_amr_f,
        &hf_osmux_amr_q,
        NULL
    };
    static int * const amr_ft_cmr_fields[] = {
        &hf_osmux_amr_ft,
        &hf_osmux_amr_cmr,
        NULL
    };

    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Osmux");
    col_clear(pinfo->cinfo, COL_INFO);

    while (tvb_reported_length_remaining(tvb, offset) >= 2) {

        struct osmux_hdr *osmuxh;
        proto_item *ti;
        proto_tree *osmux_tree = NULL;
        guint8 ft_ctr;
        guint64 amr_ft_cmr;
        guint8 i;
        guint32 size, temp;

        osmuxh = wmem_new0(pinfo->pool, struct osmux_hdr);

        ft_ctr = tvb_get_guint8(tvb, offset);

        osmuxh->rtp_m = ft_ctr >> 7;
        osmuxh->ft = (ft_ctr >> 5) & 0x3;
        osmuxh->ctr = (ft_ctr >> 2) & 0x7;
        osmuxh->amr_q = !!(ft_ctr & 0x02);
        osmuxh->amr_f = !!(ft_ctr & 0x01);

        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Osmux ");

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
                        val_to_str(osmuxh->ft, osmux_ft_vals,
                                   "unknown 0x%02x"));

        if (osmuxh->rtp_m)
            col_append_fstr(pinfo->cinfo, COL_INFO, "(M) ");

        ti = proto_tree_add_protocol_format(tree, proto_osmux, tvb, offset, -1,
                "Osmux type %s frame",
                val_to_str(osmuxh->ft, osmux_ft_vals, "unknown 0x%02x"));

        osmux_tree = proto_item_add_subtree(ti, ett_osmux);

        proto_tree_add_bitmask(osmux_tree, tvb, offset, hf_osmux_ft_ctr,
               ett_osmux_ft_ctr, ft_ctr_fields, ENC_BIG_ENDIAN);
         offset++;

        /* Old versions of the protocol used to send dummy packets of only 2 bytes (control + cid):_*/
        if (ft_ctr == 0x23 && tvb_reported_length_remaining(tvb, offset - 1) == 2) {
            osmuxh->is_old_dummy = TRUE;
            proto_tree_add_item_ret_uint(osmux_tree, hf_osmux_circuit_id, tvb, offset, 1, ENC_BIG_ENDIAN, &temp);
            osmuxh->circuit_id = (guint8)temp;
            col_append_fstr(pinfo->cinfo, COL_INFO, "Old Dummy (CID %u)", osmuxh->circuit_id);
            finish_process_pkt(tvb,  pinfo, tree, osmuxh);
            return tvb_reported_length(tvb);
        }

        proto_tree_add_item_ret_uint(osmux_tree, hf_osmux_seq, tvb, offset, 1, ENC_BIG_ENDIAN, &temp);
        osmuxh->seq = (guint8)temp;
        offset++;

        proto_tree_add_item_ret_uint(osmux_tree, hf_osmux_circuit_id, tvb, offset, 1, ENC_BIG_ENDIAN, &temp);
        osmuxh->circuit_id = (guint8)temp;
        offset++;
        col_append_fstr(pinfo->cinfo, COL_INFO, "(CID %u) ", osmuxh->circuit_id);

        proto_tree_add_bitmask_ret_uint64(osmux_tree, tvb, offset, hf_osmux_amr_ft_cmr,
                ett_osmux_amr_ft_cmr, amr_ft_cmr_fields, ENC_BIG_ENDIAN, &amr_ft_cmr);
        offset++;
        osmuxh->amr_ft = (guint32)(amr_ft_cmr & 0xf0) >> 4;
        osmuxh->amr_cmr = (guint32)amr_ft_cmr & 0x0f;
        size = amr_ft_to_bytes(osmuxh->amr_ft);
        for (i = 0; i < osmuxh->ctr + 1; i++) {
            proto_tree_add_item(osmux_tree, hf_osmux_amr_data, tvb, offset, size, ENC_NA);
            offset += size;
        }
        finish_process_pkt(tvb,  pinfo, tree, osmuxh);
    }

    return tvb_reported_length(tvb);
}

/* Statistics */
static const gchar *st_str_total_pkts = "Osmux Total Packets";
static const gchar *st_str_conn = "Osmux Streams";
static const gchar *st_str_pkts = "Count: Osmux Packets";
static const gchar *st_str_amr = "Count: AMR frames";
static const gchar *st_str_rtp_m = "Field: RTP Marker (M)";
static const gchar *st_str_seq_rep = "SeqNum Analysis: Consecutive Repeated";
static const gchar *st_str_seq_lost = "SeqNum Analysis: Lost";
static const gchar *st_str_seq_ord = "SeqNum Analysis: In Order";
static const gchar *st_str_seq_ooo = "SeqNum Analysis: Out Of Order";
static const gchar *st_str_jit_rtt = "Jitter Analysis: Relative Transmit Time [ms]";
static const gchar *st_str_jit_rtt_abs = "Jitter Analysis: Relative Transmit Time (abs) [ms]";
static const gchar *st_str_jit_jit = "Jitter Analysis: Jitter [ms]";

static int st_osmux_stats = -1;
static int st_osmux_stats_conn = -1;


static void stream_hash_clean_stats(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    struct osmux_stream *stream = (struct osmux_stream *)value;
    memset(&stream->stats, 0, sizeof(struct osmux_stats_tree));
}

static void osmux_stats_tree_init(stats_tree *st)
{
    wmem_map_foreach(osmux_stream_hash, stream_hash_clean_stats, NULL);
    st_osmux_stats = stats_tree_create_node(st, st_str_total_pkts, 0, STAT_DT_INT, TRUE);
    st_osmux_stats_conn = stats_tree_create_node(st, st_str_conn, st_osmux_stats, STAT_DT_INT, TRUE);
}

static tap_packet_status osmux_stats_tree_packet(stats_tree *st,
        packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_)
{
    gchar* stream_name;
    gchar* ft_name;
    const struct osmux_hdr *osmuxh = (const struct osmux_hdr*) p;
    struct osmux_stream *stream = osmuxh->stream;

    stream_name = stream_str(stream, pinfo);

    tick_stat_node(st, st_str_total_pkts, 0, TRUE);

    if (!stream->stats.node_id) {
        tick_stat_node(st, st_str_conn, st_osmux_stats, TRUE);
        stream->stats.node_id = stats_tree_create_node(st, stream_name, st_osmux_stats_conn, STAT_DT_INT, TRUE);
    }

    tick_stat_node(st, stream_name, st_osmux_stats_conn, TRUE);
    tick_stat_node(st, st_str_pkts, stream->stats.node_id, TRUE);

    ft_name = wmem_strdup_printf(pinfo->pool, "Field: FT: %s", osmuxh->is_old_dummy ? "Old Dummy" : osmux_ft_vals[osmuxh->ft].strptr);
    tick_stat_node(st, ft_name, stream->stats.node_id, TRUE);

    if (osmuxh->ft == OSMUX_FT_AMR && !osmuxh->is_old_dummy) {

        increase_stat_node(st, st_str_amr, stream->stats.node_id, TRUE, osmuxh->ctr+1);
        avg_stat_node_add_value_notick(st, st_str_amr, stream->stats.node_id, TRUE, osmuxh->ctr+1);

        increase_stat_node(st, st_str_rtp_m, stream->stats.node_id, TRUE, osmuxh->rtp_m);
        avg_stat_node_add_value_notick(st, st_str_rtp_m, stream->stats.node_id, TRUE, osmuxh->rtp_m);


        /* Calculate relative transmit time */
        if ((stream->stats.prev_ts.secs == 0 && stream->stats.prev_ts.nsecs == 0) || osmuxh->rtp_m) {
            avg_stat_node_add_value_int(st, st_str_jit_rtt, stream->stats.node_id, TRUE, 0);
            avg_stat_node_add_value_int(st, st_str_jit_rtt_abs, stream->stats.node_id, TRUE, 0);
            avg_stat_node_add_value_int(st, st_str_jit_jit, stream->stats.node_id, TRUE, 0);
            stream->stats.jitter = 0;
        } else {
            nstime_t diff_rx;
            gint32 diff_rx_ms, diff_tx_ms, Dij;
            guint32 abs_Dij;
            nstime_delta(&diff_rx, &pinfo->abs_ts, &stream->stats.prev_ts);
            diff_rx_ms = (guint32) nstime_to_msec(&diff_rx);
            diff_tx_ms = (osmuxh->seq - stream->stats.prev_seq)*(osmuxh->ctr+1)*20; /* SAMPLE RATE is 20msec/AMRframe */
            Dij = diff_rx_ms - diff_tx_ms;
            abs_Dij = Dij * ( Dij >= 0 ? 1 : -1 );
            stream->stats.jitter = stream->stats.jitter + ((double) abs_Dij - stream->stats.jitter)/16.0;
            avg_stat_node_add_value_int(st, st_str_jit_rtt, stream->stats.node_id, TRUE, Dij);
            avg_stat_node_add_value_int(st, st_str_jit_rtt_abs, stream->stats.node_id, TRUE, abs_Dij);
            avg_stat_node_add_value_int(st, st_str_jit_jit, stream->stats.node_id, TRUE, (gint) stream->stats.jitter);
        }
        stream->stats.prev_ts = pinfo->abs_ts;
        stream->stats.prev_seq = osmuxh->seq;

        /* Check sequence numbers */
        if (!stream->stats.amr_received || (stream->stats.last_seq + 1) % 256 == osmuxh->seq ) {
            /* normal case */
            tick_stat_node(st, st_str_seq_ord, stream->stats.node_id, TRUE);
            stream->stats.last_seq = osmuxh->seq;
            stream->stats.amr_received = TRUE;
        } else if (stream->stats.last_seq == osmuxh->seq) {
            /* Last packet is repeated */
            tick_stat_node(st, st_str_seq_rep, stream->stats.node_id, TRUE);
        } else if ((stream->stats.last_seq + 1) % 256 < osmuxh->seq) {
            /* Normal packet loss */
            increase_stat_node(st, st_str_seq_lost, stream->stats.node_id, TRUE, osmuxh->seq - stream->stats.last_seq - 1);
            stream->stats.last_seq = osmuxh->seq;
        } else if (stream->stats.last_seq - osmuxh->seq > 0x008F) {
            /* If last_Seq is a lot higher, a wraparound occurred with packet loss */
            increase_stat_node(st, st_str_seq_lost, stream->stats.node_id, TRUE, 255 - stream->stats.last_seq + osmuxh->seq);
            stream->stats.last_seq = osmuxh->seq;
        } else if (stream->stats.last_seq > osmuxh->seq || osmuxh->seq - stream->stats.last_seq > 0x008F) {
            /* Out of order packet */
            tick_stat_node(st, st_str_seq_ooo, stream->stats.node_id, TRUE);
            increase_stat_node(st, st_str_seq_lost, stream->stats.node_id, TRUE, -1);
        }

    }

    return TAP_PACKET_REDRAW;
}

void proto_register_osmux(void)
{
    static hf_register_info hf[] = {
        {&hf_osmux_stream_id,
         {"OSmux Stream ID", "osmux.stream_id",
          FT_UINT32, BASE_DEC, NULL, 0x00,
          "ID for a specific OSMUX flow", HFILL}
        },
        {&hf_osmux_ft_ctr,
         {"FTCTRByte", "osmux.ft_ctr",
          FT_UINT8, BASE_DEC, NULL, 0x00,
          "Byte with Fieldtype, Counter", HFILL}
        },
        {&hf_osmux_rtp_m,
         {"RTP Marker", "osmux.rtp_m",
          FT_BOOLEAN, 8, NULL, 0x80,
          "Type of data in packet", HFILL}
         },
        {&hf_osmux_ft,
         {"FieldType", "osmux.ft",
          FT_UINT8, BASE_DEC, VALS(osmux_ft_vals), 0x60,
          "Type of data in packet", HFILL}
         },
        {&hf_osmux_ctr,
         {"CTR", "osmux.ctr",
          FT_UINT8, BASE_HEX, NULL, 0x1c,
          "Number of AMR packets inside", HFILL}
         },
        {&hf_osmux_amr_q,
         {"AMR f", "osmux.amr_f",
          FT_BOOLEAN, 8, NULL, 0x02,
          "AMR f parameter", HFILL}
         },
        {&hf_osmux_amr_f,
         {"AMR q", "osmux.amr_q",
          FT_BOOLEAN, 8, NULL, 0x01,
          "AMR q parameter", HFILL}
         },
        {&hf_osmux_seq,
         {"Seq", "osmux.seq",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          "Sequence number", HFILL}
         },
        {&hf_osmux_circuit_id,
         {"Circuit ID", "osmux.circuit_id",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
         },
        {&hf_osmux_amr_ft_cmr,
         {"AMR info", "osmux.amr_ft_cmr",
          FT_UINT8, BASE_DEC, NULL, 0x00,
          "Byte with AMR params ft and cmr", HFILL}
        },
        {&hf_osmux_amr_ft,
         {"AMR ft", "osmux.amr_ft",
          FT_UINT8, BASE_HEX,VALS(amr_ft_names), 0xf0,
          "AMR parameter ft", HFILL}
         },
        {&hf_osmux_amr_cmr,
         {"AMR cmr", "osmux.amr_cmr",
          FT_UINT8, BASE_HEX, NULL, 0x0f,
          "AMR parameter cmr", HFILL}
         },
        {&hf_osmux_amr_data,
         {"AMR data", "osmux.amr_data",
          FT_BYTES, BASE_NONE, NULL, 0x00,
          "AMR voice data", HFILL}
         },
    };

    static gint *ett[] = {
        &ett_osmux,
        &ett_osmux_ft_ctr,
        &ett_osmux_amr_ft_cmr,
    };

    proto_osmux = proto_register_protocol("GSM multiplexing for AMR", "GSM Osmux", "osmux");

    proto_register_field_array(proto_osmux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    osmux_stream_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                             osmux_hash, osmux_equal);

}


void proto_reg_handoff_osmux(void)
{
    osmux_handle = create_dissector_handle(dissect_osmux, proto_osmux);
    dissector_add_for_decode_as_with_preference("udp.port", osmux_handle);

    osmux_tap = register_tap("osmux");

    stats_tree_register("osmux", "osmux", "Osmux/osmux", 0,
            osmux_stats_tree_packet, osmux_stats_tree_init, NULL);
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
