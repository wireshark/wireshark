/* packet-gsm_osmux.c
 * Routines for packet dissection of Osmux voice/signalling multiplex protocol
 * Copyright 2016 sysmocom s.f.m.c Daniel Willmann <dwillmann@sysmocom.de>
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

#include "config.h"

#include <string.h>
#include <stdio.h>

#include <epan/packet.h>
#include <epan/stats_tree.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include "packet-gsm_osmux.h"

void proto_register_osmux(void);
void proto_reg_handoff_osmux(void);

static const value_string osmux_ft_vals[] =
{
    {0x00, "Signalling"},
    {0x01, "AMR"},
    {0x02, "Dummy"},
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

/* Code to calculate AMR payload size */
static guint8
amr_ft_to_bytes(guint32 amr_ft)
{
    if (amr_ft >= AMR_FT_MAX) /* malformed packet ? */
        return 0;
    return amr_ft_bytes[amr_ft];
}

/* Code to actually dissect the packets */
static gint
dissect_osmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static const gint *ft_ctr_fields[] = {
        &hf_osmux_rtp_m,
        &hf_osmux_ft,
        &hf_osmux_ctr,
        &hf_osmux_amr_f,
        &hf_osmux_amr_q,
        NULL
    };
    static const gint *amr_ft_cmr_fields[] = {
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
        guint i;
        guint32 cid, size;

        osmuxh = wmem_new0(wmem_packet_scope(), struct osmux_hdr);

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
            proto_tree_add_item_ret_uint(osmux_tree, hf_osmux_circuit_id, tvb, offset, 1, ENC_BIG_ENDIAN, &cid);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Old Dummy (CID %u)", cid);
            tap_queue_packet(osmux_tap, pinfo, osmuxh);
            return tvb_reported_length(tvb);
        }

        proto_tree_add_item_ret_uint(osmux_tree, hf_osmux_seq, tvb, offset, 1, ENC_BIG_ENDIAN, &osmuxh->seq);
        offset++;

        proto_tree_add_item_ret_uint(osmux_tree, hf_osmux_circuit_id, tvb, offset, 1, ENC_BIG_ENDIAN, &osmuxh->circuit_id);
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

        tap_queue_packet(osmux_tap, pinfo, osmuxh);
    }

    return tvb_reported_length(tvb);
}

/* Statistics */
static const gchar *st_str_pkts = "Osmux Packets";
static const gchar *st_str_pkts_by_cid = "Osmux Packets by CID";
static const gchar *st_str_pkts_by_ctr = "Osmux Packets by AMR frame count";
static const gchar *st_str_pkts_by_src = "Osmux Packets by src Addr";
static const gchar *st_str_pkts_by_dst = "Osmux Packets by dst Addr";
static const gchar *st_str_pkts_by_conn = "Osmux Packets by stream";
static const gchar *st_str_pkts_by_rtp_m = "Osmux Packets by RTP Marker";

static int st_osmux_stats = -1;
static int st_osmux_stats_cid = -1;
static int st_osmux_stats_ctr = -1;
static int st_osmux_stats_src = -1;
static int st_osmux_stats_dst = -1;
static int st_osmux_stats_conn = -1;
static int st_osmux_stats_rtp_m = -1;

static void osmux_stats_tree_init(stats_tree *st)
{
    st_osmux_stats = stats_tree_create_node(st, st_str_pkts, 0, TRUE);
    st_osmux_stats_cid = stats_tree_create_node(st, st_str_pkts_by_cid, st_osmux_stats, TRUE);
    st_osmux_stats_ctr = stats_tree_create_node(st, st_str_pkts_by_ctr, st_osmux_stats, TRUE);
    st_osmux_stats_src = stats_tree_create_node(st, st_str_pkts_by_src, st_osmux_stats, TRUE);
    st_osmux_stats_dst = stats_tree_create_node(st, st_str_pkts_by_dst, st_osmux_stats, TRUE);
    st_osmux_stats_conn = stats_tree_create_node(st, st_str_pkts_by_conn, st_osmux_stats, TRUE);
    st_osmux_stats_rtp_m = stats_tree_create_node(st, st_str_pkts_by_rtp_m, st_osmux_stats, TRUE);
}

static int osmux_stats_tree_packet(stats_tree *st, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *p _U_)
{
    gchar *ip_str, *ip2_str;
    gchar temp[40];
    struct osmux_hdr *osmuxh = (struct osmux_hdr*) p;


    tick_stat_node(st, st_str_pkts, 0, FALSE);

    tick_stat_node(st, st_str_pkts_by_cid, st_osmux_stats, FALSE);
    g_snprintf(temp, 30, "%i", osmuxh->circuit_id);
    tick_stat_node(st, temp, st_osmux_stats_cid, TRUE);

    tick_stat_node(st, st_str_pkts_by_ctr, st_osmux_stats, FALSE);
    g_snprintf(temp, 30, "%i", osmuxh->ctr);
    tick_stat_node(st, temp, st_osmux_stats_ctr, TRUE);

    tick_stat_node(st, st_str_pkts_by_src, 0, FALSE);
    ip_str = address_to_str(NULL, &pinfo->src);
    tick_stat_node(st, ip_str, st_osmux_stats_src, TRUE);

    tick_stat_node(st, st_str_pkts_by_dst, 0, FALSE);
    ip2_str = address_to_str(NULL, &pinfo->dst);
    tick_stat_node(st, ip2_str, st_osmux_stats_dst, TRUE);

    tick_stat_node(st, st_str_pkts_by_conn, 0, FALSE);
    g_snprintf(temp, 40, "%s->%s:%i", ip_str, ip2_str, osmuxh->circuit_id);
    tick_stat_node(st, temp, st_osmux_stats_conn, TRUE);

    tick_stat_node(st, st_str_pkts_by_rtp_m, 0, FALSE);
    g_snprintf(temp, 30, "%s", (osmuxh->rtp_m ? "Yes" : "No"));
    tick_stat_node(st, temp, st_osmux_stats_rtp_m, TRUE);

    wmem_free(NULL, ip_str);
    wmem_free(NULL, ip2_str);

    return 1;
}

void proto_register_osmux(void)
{
    static hf_register_info hf[] = {
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
}


void proto_reg_handoff_osmux(void)
{
    osmux_handle = create_dissector_handle(dissect_osmux, proto_osmux);
    dissector_add_for_decode_as_with_preference("udp.port", osmux_handle);

    osmux_tap = register_tap("osmux");

    stats_tree_register("osmux", "osmux", "Osmux/Packets", 0,
            osmux_stats_tree_packet, osmux_stats_tree_init,
            NULL);
}

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
