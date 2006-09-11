/* Routines for UMTS FP disassembly
 *
 * Martin Mathieson
 *
 * $Id: packet-fp.c 18196 2006-05-21 04:49:01Z sahlberg $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-umts_fp.h"

/* Initialize the protocol and registered fields. */
int proto_fp = -1;

static int hf_fp_channel_type = -1;
static int hf_fp_direction = -1;
static int hf_fp_header_crc = -1;
static int hf_fp_ft = -1;
static int hf_fp_cfn = -1;
static int hf_fp_pch_cfn = -1;
static int hf_fp_pch_toa = -1;
static int hf_fp_cfn_control = -1;
static int hf_fp_toa = -1;
static int hf_fp_tfi = -1;
static int hf_fp_propagation_delay = -1;
static int hf_fp_tb = -1;
static int hf_fp_received_sync_ul_timing_deviation = -1;
static int hf_fp_pch_pi = -1;
static int hf_fp_pch_tfi = -1;
static int hf_fp_fach_tfi = -1;
static int hf_fp_transmit_power_level = -1;
static int hf_fp_paging_indication_bitmap = -1;
static int hf_fp_pdsch_set_id = -1;
static int hf_fp_rx_timing_deviation = -1;
static int hf_fp_dch_control_frame_type = -1;
static int hf_fp_dch_rx_timing_deviation = -1;
static int hf_fp_quality_estimate = -1;
static int hf_fp_payload_crc = -1;
static int hf_fp_edch_header_crc = -1;
static int hf_fp_edch_fsn = -1;
static int hf_fp_edch_subframe = -1;
static int hf_fp_edch_number_of_subframes = -1;
static int hf_fp_edch_harq_retransmissions = -1;
static int hf_fp_edch_subframe_number = -1;
static int hf_fp_edch_number_of_mac_es_pdus = -1;
static int hf_fp_edch_ddi = -1;
static int hf_fp_edch_subframe_header = -1;
static int hf_fp_edch_number_of_mac_d_pdus = -1;
static int hf_fp_edch_pdu_padding = -1;
static int hf_fp_edch_tsn = -1;
static int hf_fp_edch_mac_es_pdu = -1;
static int hf_fp_cmch_pi = -1;
static int hf_fp_user_buffer_size = -1;
static int hf_fp_hsdsch_credits = -1;
static int hf_fp_hsdsch_max_macd_pdu_len = -1;
static int hf_fp_hsdsch_interval = -1;
static int hf_fp_hsdsch_repetition_period = -1;
static int hf_fp_hsdsch_data_padding = -1;
static int hf_fp_timing_advance = -1;
static int hf_fp_num_of_pdu = -1;
static int hf_fp_mac_d_pdu_len = -1;
static int hf_fp_mac_d_pdu = -1;
static int hf_fp_data = -1;
static int hf_fp_crcis = -1;
static int hf_fp_crci[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static int hf_fp_common_control_frame_type = -1;
static int hf_fp_t1 = -1;
static int hf_fp_t2 = -1;
static int hf_fp_t3 = -1;

/* Subtrees. */
static int ett_fp = -1;
static int ett_fp_data = -1;
static int ett_fp_crcis = -1;
static int ett_fp_edch_subframe_header = -1;
static int ett_fp_edch_subframe = -1;


/* E-DCH channel header information */
struct subframe_info
{
    guint8  subframe_number;
    guint8  number_of_mac_es_pdus;
    guint8  ddi[64];
    guint16 number_of_mac_d_pdus[64];
};


static const value_string channel_type_vals[] =
{
    { CHANNEL_RACH_FDD,     "RACH_FDD" },
    { CHANNEL_RACH_TDD,     "RACH_TDD" },
    { CHANNEL_FACH_FDD,     "FACH_FDD" },
    { CHANNEL_FACH_TDD,     "FACH_TDD" },
    { CHANNEL_DSCH_FDD,     "DSCH_FDD" },
    { CHANNEL_DSCH_TDD,     "DSCH_TDD" },
    { CHANNEL_USCH_TDD_384, "USCH_TDD_384" },
    { CHANNEL_USCH_TDD_128, "USCH_TDD_128" },
    { CHANNEL_PCH,          "PCH" },
    { CHANNEL_CPCH,         "CPCH" },
    { CHANNEL_BCH,          "BCH" },
    { CHANNEL_DCH,          "DCH" },
    { CHANNEL_HSDSCH,       "HSDSCH" },
    { CHANNEL_IUR_CPCHF,    "IUR CPCHF" },
    { CHANNEL_IUR_FACH,     "IUR FACH" },
    { CHANNEL_IUR_DSCH,     "IUR DSCH" },
    { CHANNEL_EDCH,         "EDCH" },
    { CHANNEL_RACH_TDD_128, "RACH_TDD_128" },
    { 0, NULL }
};

static const value_string data_control_vals[] = {
    { 0,   "Data" },
    { 1,   "Control" },
    { 0,   NULL },
};

static const value_string direction_vals[] = {
    { 0,   "Downlink" },
    { 1,   "Uplink" },
    { 0,   NULL },
};

static const value_string crci_vals[] = {
    { 0,   "Correct" },
    { 1,   "Not correct" },
    { 0,   NULL },
};


/* DCH control types */
#define DCH_OUTER_LOOP_POWER_CONTROL            1
#define DCH_TIMING_ADJUSTMENT                   2
#define DCH_DL_SYNCHRONISATION                  3
#define DCH_UL_SYNCHRONISATION                  4

#define DCH_DL_NODE_SYNCHRONISATION             6
#define DCH_UL_NODE_SYNCHRONISATION             7
#define DCH_RX_TIMING_DEVIATION                 8
#define DCH_RADIO_INTERFACE_PARAMETER_UPDATE    9
#define DCH_TIMING_ADVANCE                      10
#define DCH_TNL_CONGESTION_INDICATION           11

static const value_string dch_control_frame_type_vals[] = {
    { DCH_OUTER_LOOP_POWER_CONTROL,         "OUTER LOOP POWER CONTROL" },
    { DCH_TIMING_ADJUSTMENT,                "TIMING ADJUSTMENT" },
    { DCH_DL_SYNCHRONISATION,               "DL SYNCHRONISATION" },
    { DCH_UL_SYNCHRONISATION,               "UL SYNCHRONISATION" },
    { 5,                                    "Reserved Value" },
    { DCH_DL_NODE_SYNCHRONISATION,          "DL NODE SYNCHRONISATION" },
    { DCH_UL_NODE_SYNCHRONISATION,          "UL NODE SYNCHRONISATION" },
    { DCH_RX_TIMING_DEVIATION,              "RX TIMING DEVIATION" },
    { DCH_RADIO_INTERFACE_PARAMETER_UPDATE, "RADIO INTERFACE PARAMETER UPDATE" },
    { DCH_TIMING_ADVANCE,                   "TIMING ADVANCE" },
    { DCH_TNL_CONGESTION_INDICATION,        "TNL CONGESTION INDICATION" },
    { 0,   NULL },
};


/* Common channel control types */
#define COMMON_OUTER_LOOP_POWER_CONTROL         1
#define COMMON_TIMING_ADJUSTMENT                2
#define COMMON_DL_SYNCHRONISATION               3
#define COMMON_UL_SYNCHRONISATION               4

#define COMMON_DL_NODE_SYNCHRONISATION          6
#define COMMON_UL_NODE_SYNCHRONISATION          7
#define COMMON_DYNAMIC_PUSCH_ASSIGNMENT         8
#define COMMON_TIMING_ADVANCE                   9
#define COMMON_HS_DSCH_Capacity_Request         10
#define COMMON_HS_DSCH_Capacity_Allocation      11

static const value_string common_control_frame_type_vals[] = {
    { COMMON_OUTER_LOOP_POWER_CONTROL,         "OUTER LOOP POWER CONTROL" },
    { COMMON_TIMING_ADJUSTMENT,                "TIMING ADJUSTMENT" },
    { COMMON_DL_SYNCHRONISATION,               "DL SYNCHRONISATION" },
    { COMMON_UL_SYNCHRONISATION,               "UL SYNCHRONISATION" },
    { 5,                                       "Reserved Value" },
    { COMMON_DL_NODE_SYNCHRONISATION,          "DL NODE SYNCHRONISATION" },
    { COMMON_UL_NODE_SYNCHRONISATION,          "UL NODE SYNCHRONISATION" },
    { COMMON_DYNAMIC_PUSCH_ASSIGNMENT,         "DYNAMIC PUSCH ASSIGNMENT" },
    { COMMON_TIMING_ADVANCE,                   "TIMING ADVANCE" },
    { COMMON_HS_DSCH_Capacity_Request,         "HS-DSCH Capacity Request" },
    { COMMON_HS_DSCH_Capacity_Allocation,      "HS-DSCH Capacity Allocation" },
    { 0,   NULL },
};

/* Dissect message parts */
static int dissect_tb_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           int offset, struct _fp_info *p_fp_info, int *num_tbs);
static int dissect_macd_pdu_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 int offset, guint16 length, guint8 number_of_pdus);
static int dissect_crci_bits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int num_tbs, int offset);

/* Dissect common control messages */
static void dissect_common_timing_adjustment(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                                             int offset, struct _fp_info *p_fp_info);
static void dissect_common_dl_node_synchronisation(packet_info *pinfo, proto_tree *tree,
                                                   tvbuff_t *tvb, int offset);
static void dissect_common_ul_node_synchronisation(packet_info *pinfo, proto_tree *tree,
                                                   tvbuff_t *tvb, int offset);
static void dissect_common_dl_syncronisation(packet_info *pinfo, proto_tree *tree,
                                             tvbuff_t *tvb, int offset,
                                             struct _fp_info *p_fp_info);
static void dissect_common_ul_syncronisation(packet_info *pinfo, proto_tree *tree,
                                             tvbuff_t *tvb, int offset,
                                             struct _fp_info *p_fp_info);
static void dissect_common_timing_advance(proto_tree *tree, tvbuff_t *tvb, int offset);
static void dissect_hsdpa_capacity_request(packet_info *pinfo, proto_tree *tree,
                                           tvbuff_t *tvb, int offset);
static void dissect_hsdpa_capacity_allocation(packet_info *pinfo, proto_tree *tree,
                                              tvbuff_t *tvb, int offset);
static void dissect_common_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   int offset, struct _fp_info *p_fp_info);

/* Dissect common channel types */
static void dissect_rach_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      int offset, struct _fp_info *p_fp_info);
static void dissect_fach_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      int offset, struct _fp_info *p_fp_info);
static void dissect_dsch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      int offset, struct _fp_info *p_fp_info);
static void dissect_usch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      int offset, struct _fp_info *p_fp_info);
static void dissect_pch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     int offset, struct _fp_info *p_fp_info);
static void dissect_iur_dsch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          int offset, struct _fp_info *p_fp_info _U_);
static void dissect_hsdsch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        int offset, struct _fp_info *p_fp_info);


/* Dissect DCH control messages */
static void dissect_dch_timing_adjustment(proto_tree *tree, packet_info *pinfo,
                                          tvbuff_t *tvb, int offset);
static void dissect_dch_rx_timing_deviation(proto_tree *tree, tvbuff_t *tvb, int offset);
static void dissect_dch_dl_synchronisation(proto_tree *tree, packet_info *pinfo,
                                           tvbuff_t *tvb, int offset);
static void dissect_dch_ul_synchronisation(proto_tree *tree, packet_info *pinfo,
                                           tvbuff_t *tvb, int offset);

/* Dissect a DCH channel */
static void dissect_dch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     int offset, struct _fp_info *p_fp_info);

/* Dissect dedicated channels */
static void dissect_e_dch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                int offset, struct _fp_info *p_fp_info);
static void dissect_fp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void proto_register_fp(void);
void proto_reg_handoff_fp(void);




/* Dissect the TBs of a data frame */
int dissect_tb_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    int offset, struct _fp_info *p_fp_info, int *num_tbs)
{
    int chan;
    int bit_offset = 0;
    guint data_bits = 0;
    proto_item *ti;
    proto_tree *data_tree;

    /* Add data subtree */
    ti =  proto_tree_add_string_format(tree, hf_fp_data, tvb, offset, 0,
                                       "",
                                       "TB data for %u chans",
                                       p_fp_info->num_chans);
    data_tree = proto_item_add_subtree(ti, ett_fp_data);


    /* Now for the TB data */
    for (chan=0; chan < p_fp_info->num_chans; chan++)
    {
        int n;
        for (n=0; n < p_fp_info->chan_num_tbs[chan]; n++)
        {
            proto_item *ti;
            ti = proto_tree_add_item(data_tree, hf_fp_tb, tvb,
                                     offset + (bit_offset/8),
                                     ((bit_offset % 8) + p_fp_info->chan_tf_size[chan] + 7) / 8,
                                     FALSE);
            proto_item_append_text(ti, " (chan %u, tb %u, %u bits)",
                                   chan+1, n+1, p_fp_info->chan_tf_size[chan]);
            (*num_tbs)++;

            /* Advance bit offset */
            bit_offset += p_fp_info->chan_tf_size[chan];
            data_bits += p_fp_info->chan_tf_size[chan];
        }

        /* Pad out to next byte */
        if (bit_offset % 8)
        {
            bit_offset += (8 - (bit_offset % 8));
        }
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "(%u bits in %u tbs)",
                        data_bits, *num_tbs);
    }

    /* Data tree should cover entire length */
    proto_item_set_len(data_tree, bit_offset/8);
    proto_item_append_text(ti, " (total %u tbs)", *num_tbs);

    /* Move offset past TBs (we know its already padded out to next byte) */
    offset += (bit_offset / 8);

    return offset;
}


/* Dissect the MAC-d PDUs of an HS-DSCH frame */
int dissect_macd_pdu_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          int offset, guint16 length, guint8 number_of_pdus)
{
    int pdu;
    int bit_offset = 0;
    proto_item *ti;
    proto_tree *data_tree;

    /* Add data subtree */
    ti =  proto_tree_add_string_format(tree, hf_fp_data, tvb, offset, 0,
                                       "",
                                       "%u MAC-d PDUs of %u bits",
                                       number_of_pdus,
                                       length);
    data_tree = proto_item_add_subtree(ti, ett_fp_data);

    /* Now for the PDUs */
    for (pdu=0; pdu < number_of_pdus; pdu++)
    {
        proto_item *ti;

        /* Show 4 bits padding at start of PDU */
        proto_tree_add_item(data_tree, hf_fp_hsdsch_data_padding, tvb, offset+(bit_offset/8), 1, FALSE);

        /* Data bytes! */
        ti = proto_tree_add_item(data_tree, hf_fp_mac_d_pdu, tvb,
                                 offset + (bit_offset/8),
                                 ((bit_offset % 8) + length + 7) / 8,
                                 FALSE);
        proto_item_append_text(ti, " (PDU %u)", pdu+1);

        /* Advance bit offset */
        bit_offset += length;

        /* Pad out to next byte */
        if (bit_offset % 8)
        {
            bit_offset += (8 - (bit_offset % 8));
        }
    }

    /* Data tree should cover entire length */
    proto_item_set_len(data_tree, bit_offset/8);

    /* Move offset past PDUs (we know its already padded out to next byte) */
    offset += (bit_offset / 8);

    /* Show summary in info column */
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %u PDUs of %u bits",
                        number_of_pdus, length);
    }

    return offset;
}


/* Dissect CRCI bits (uplink) */
int dissect_crci_bits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      int num_tbs, int offset)
{
    int n;
    proto_item *ti;
    proto_tree *crcis_tree;
    guint errors = 0;

    /* Add CRCIs subtree */
    ti =  proto_tree_add_string_format(tree, hf_fp_crcis, tvb, offset, 0,
                                       "",
                                       "CRCI bits for %u tbs",
                                       num_tbs);
    crcis_tree = proto_item_add_subtree(ti, ett_fp_crcis);

    /* CRCIs */
    for (n=0; n < num_tbs; n++)
    {
        int bit = (tvb_get_guint8(tvb, offset+(n/8)) >> (7-(n%8))) & 0x01;
        proto_tree_add_item(crcis_tree, hf_fp_crci[n%8], tvb, offset+(n/8),
                            1, FALSE);

        if (bit == 1)
        {
            errors++;
            expert_add_info_format(pinfo, ti,
                                   PI_CHECKSUM, PI_WARN,
                                   "CRCI error bit set for TB %u", n+1);
        }
    }

    /* Show error count in root text */
    proto_item_append_text(ti, " (%u errors)", errors);

    offset += ((num_tbs+7) / 8);
    return offset;
}



/***********************************************************/
/* Common control message types                            */

void dissect_common_timing_adjustment(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                                      int offset, struct _fp_info *p_fp_info)
{
    if (p_fp_info->channel != CHANNEL_PCH)
    {
        guint8 cfn;
        gint16 toa;

        /* CFN control */
        cfn = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
        offset++;

        /* ToA */
        toa = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_fp_toa, tvb, offset, 2, FALSE);
        offset++;

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   CFN=%u, ToA=%d", cfn, toa);
        }
    }
    else
    {
        guint16 cfn;
        gint32 toa;

        /* PCH CFN is 12 bits */
        cfn = (tvb_get_ntohs(tvb, offset) >> 4);
        proto_tree_add_item(tree, hf_fp_pch_cfn, tvb, offset, 2, FALSE);
        offset += 2;

        /* 4 bits of padding follow... */

        /* 20 bits of ToA (followed by 4 padding bits) */
        toa = ((int)(tvb_get_ntoh24(tvb, offset) << 8)) / 4096;
        proto_tree_add_int(tree, hf_fp_pch_toa, tvb, offset, 3, toa);

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   CFN=%u, ToA=%d", cfn, toa);
        }
    }
}

void dissect_common_dl_node_synchronisation(packet_info *pinfo, proto_tree *tree,
                                            tvbuff_t *tvb, int offset)
{
    /* T1 */
    guint32 t1 = tvb_get_ntoh24(tvb, offset);
    proto_tree_add_item(tree, hf_fp_t1, tvb, offset, 3, FALSE);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   T1=%u", t1);
    }
}

void dissect_common_ul_node_synchronisation(packet_info *pinfo, proto_tree *tree,
                                            tvbuff_t *tvb, int offset)
{
    guint32 t1, t2, t3;

    /* T1 */
    t1 = tvb_get_ntoh24(tvb, offset);
    proto_tree_add_item(tree, hf_fp_t1, tvb, offset, 3, FALSE);
    offset += 3;

    /* T2 */
    t2 = tvb_get_ntoh24(tvb, offset);
    proto_tree_add_item(tree, hf_fp_t2, tvb, offset, 3, FALSE);
    offset += 3;

    /* T3 */
    t3 = tvb_get_ntoh24(tvb, offset);
    proto_tree_add_item(tree, hf_fp_t3, tvb, offset, 3, FALSE);
    offset += 3;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   T1=%u T2=%u, T3=%u",
                        t1, t2, t3);
    }
}

void dissect_common_dl_syncronisation(packet_info *pinfo, proto_tree *tree,
                                      tvbuff_t *tvb, int offset, struct _fp_info *p_fp_info)
{
    guint16 cfn;

    if (p_fp_info->channel != CHANNEL_PCH)
    {
        /* CFN control */
        cfn = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
    }
    else
    {
        /* PCH CFN is 12 bits */
        cfn = (tvb_get_ntohs(tvb, offset) >> 4);
        proto_tree_add_item(tree, hf_fp_pch_cfn, tvb, offset, 2, FALSE);

        /* 4 bits of padding follow... */
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   CFN=%u", cfn);
    }
}

void dissect_common_ul_syncronisation(packet_info *pinfo, proto_tree *tree,
                                      tvbuff_t *tvb, int offset, struct _fp_info *p_fp_info)
{
    dissect_common_timing_adjustment(pinfo, tree, tvb, offset, p_fp_info);
}

void dissect_common_timing_advance(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint8 timing_advance;

    /* CFN control */
    proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
    offset++;

    /* Timing Advance */
    timing_advance = (tvb_get_guint8(tvb, offset) & 0x3f); 
    proto_tree_add_uint(tree, hf_fp_timing_advance, tvb, offset, 1, timing_advance*4);
    offset++;
}

void dissect_hsdpa_capacity_request(packet_info *pinfo, proto_tree *tree,
                                    tvbuff_t *tvb, int offset)
{
    guint8 priority;
    guint16 user_buffer_size;

    /* CmCH-PI */
    priority = (tvb_get_guint8(tvb, offset) & 0x0f);
    proto_tree_add_item(tree, hf_fp_cmch_pi, tvb, offset, 1, FALSE);
    offset++;

    /* User buffer size */
    user_buffer_size = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_fp_user_buffer_size, tvb, offset, 2, FALSE);
    offset += 2;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "      CmCH-PI=%u  User-Buffer-Size=%u",
                        priority, user_buffer_size);
    }

    /* TODO: Spare extension may follow */
}

void dissect_hsdpa_capacity_allocation(packet_info *pinfo, proto_tree *tree,
                                       tvbuff_t *tvb, int offset)
{
    proto_item *ti;
    guint16 max_pdu_length;
    guint8 repetition_period;
    guint8 interval;
    guint16 credits;

    /* CmCH-PI */
    proto_tree_add_item(tree, hf_fp_cmch_pi, tvb, offset, 1, FALSE);
    offset++;

    /* Max MAC-d PDU length (13 bits) */
    max_pdu_length = (tvb_get_ntohs(tvb, offset) >> 3);
    proto_tree_add_item(tree, hf_fp_hsdsch_max_macd_pdu_len, tvb, offset, 2, FALSE);
    offset++;

    /* HS-DSCH credits (11 bits) */
    credits = (tvb_get_ntohs(tvb, offset) & 0x07ff);
    ti = proto_tree_add_item(tree, hf_fp_hsdsch_credits, tvb, offset, 2, FALSE);
    offset += 2;
    if (credits == 0)
    {
        proto_item_append_text(ti, " (stop transmission)");
    }
    if (credits == 2047)
    {
        proto_item_append_text(ti, " (unlimited)");
    }

    /* HS-DSCH Interval */
    interval = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint(tree, hf_fp_hsdsch_interval, tvb, offset, 1, interval*10);
    offset++;
    if (interval == 0)
    {
        proto_item_append_text(ti, " (none of the credits shall be used)");
    }

    /* HS-DSCH Repetition period */
    repetition_period = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(tree, hf_fp_hsdsch_repetition_period, tvb, offset, 1, FALSE);
    offset++;
    if (repetition_period == 0)
    {
        proto_item_append_text(ti, " (unlimited repetition period)");
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        "   Max-PDU-len=%u  Credits=%u  Interval=%u  Rep-Period=%u",
                        max_pdu_length, credits, interval, repetition_period);
    }

    /* Spare extension may follow */
}


/* Dissect the control part of a common channel message */
void dissect_common_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            int offset, struct _fp_info *p_fp_info)
{
    /* Common control frame type */
    guint8 control_frame_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_fp_common_control_frame_type, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO,
                       val_to_str(control_frame_type, common_control_frame_type_vals, "Unknown"));
    }

    /* Frame-type specific dissection */
    switch (control_frame_type)
    {
        case COMMON_OUTER_LOOP_POWER_CONTROL:
            break;
        case COMMON_TIMING_ADJUSTMENT:
            dissect_common_timing_adjustment(pinfo, tree, tvb, offset, p_fp_info);
            break;
        case COMMON_DL_SYNCHRONISATION:
            dissect_common_dl_syncronisation(pinfo, tree, tvb, offset, p_fp_info);
            break;
        case COMMON_UL_SYNCHRONISATION:
            dissect_common_ul_syncronisation(pinfo, tree, tvb, offset, p_fp_info);
            break;
        case COMMON_DL_NODE_SYNCHRONISATION:
            dissect_common_dl_node_synchronisation(pinfo, tree, tvb, offset);
            break;
        case COMMON_UL_NODE_SYNCHRONISATION:
            dissect_common_ul_node_synchronisation(pinfo, tree, tvb, offset);
            break;
        case COMMON_DYNAMIC_PUSCH_ASSIGNMENT:
            /* TODO: */
            break;
        case COMMON_TIMING_ADVANCE:
            dissect_common_timing_advance(tree, tvb, offset);
            break;
        case COMMON_HS_DSCH_Capacity_Request:
            dissect_hsdpa_capacity_request(pinfo, tree, tvb, offset);
            break;
        case COMMON_HS_DSCH_Capacity_Allocation:
            dissect_hsdpa_capacity_allocation(pinfo, tree, tvb, offset);
            break;

        default:
            break;
    }
}



/**************************/
/* Dissect a RACH channel */
void dissect_rach_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        int num_tbs = 0;

        /* DATA */

        /* CFN */
        proto_tree_add_item(tree, hf_fp_cfn, tvb, offset, 1, FALSE);
        offset++;

        /* TFI */
        proto_tree_add_item(tree, hf_fp_tfi, tvb, offset, 1, FALSE);
        offset++;

        if (p_fp_info->channel == CHANNEL_RACH_FDD)
        {
            /* Propagation delay */
            proto_tree_add_item(tree, hf_fp_propagation_delay, tvb, offset, 1, FALSE);
            offset++;
        }

        if (p_fp_info->channel == CHANNEL_RACH_TDD)
        {
            /* RX Timing Deviation */
        }

        if (p_fp_info->channel == CHANNEL_RACH_TDD_128)
        {
            /* Received SYNC UL Timing Deviation */
            proto_tree_add_item(tree, hf_fp_received_sync_ul_timing_deviation, tvb, offset, 1, FALSE);
            offset++;
        }

        /* TB data */
        offset = dissect_tb_data(tvb, pinfo, tree, offset, p_fp_info, &num_tbs);

        /* CRCIs */
        offset = dissect_crci_bits(tvb, pinfo, tree, num_tbs, offset);

        /* Payload CRC */
        proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        offset += 2;
    }
}


/**************************/
/* Dissect a FACH channel */
void dissect_fach_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        int num_tbs = 0;

        /* DATA */

        /* CFN */
        proto_tree_add_item(tree, hf_fp_cfn, tvb, offset, 1, FALSE);
        offset++;

        /* TFI */
        proto_tree_add_item(tree, hf_fp_fach_tfi, tvb, offset, 1, FALSE);
        offset++;

        /* Transmit power level. TODO: units are 0.1dB */
        proto_tree_add_item(tree, hf_fp_transmit_power_level, tvb, offset, 1, FALSE);
        offset++;

        /* TB data */
        offset = dissect_tb_data(tvb, pinfo, tree, offset, p_fp_info, &num_tbs);

        /* Payload CRC */
        proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        offset += 2;
    }
}


/**************************/
/* Dissect a DSCH channel */
void dissect_dsch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        int num_tbs = 0;

        /* DATA */

        /* CFN */
        proto_tree_add_item(tree, hf_fp_cfn, tvb, offset, 1, FALSE);
        offset++;

        /* TFI */
        proto_tree_add_item(tree, hf_fp_tfi, tvb, offset, 1, FALSE);
        offset++;

        /* PDSCH Set Id */
        proto_tree_add_item(tree, hf_fp_pdsch_set_id, tvb, offset, 1, FALSE);
        offset++;

        /* Transmit power level. TODO: units are 0.1dB */
        proto_tree_add_item(tree, hf_fp_transmit_power_level, tvb, offset, 1, FALSE);
        offset++;

        /* TB data */
        offset = dissect_tb_data(tvb, pinfo, tree, offset, p_fp_info, &num_tbs);

        /* Payload CRC */
        proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        offset += 2;
    }
}


/**************************/
/* Dissect a USCH channel */
void dissect_usch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        int num_tbs = 0;

        /* DATA */

        /* CFN */
        proto_tree_add_item(tree, hf_fp_cfn, tvb, offset, 1, FALSE);
        offset++;

        /* Rx Timing Deviation */
        proto_tree_add_item(tree, hf_fp_rx_timing_deviation, tvb, offset, 1, FALSE);
        offset++;

        /* TB data */
        offset = dissect_tb_data(tvb, pinfo, tree, offset, p_fp_info, &num_tbs);

        /* QE */
        proto_tree_add_item(tree, hf_fp_quality_estimate, tvb, offset, 1, FALSE);
        offset++;

        /* CRCIs */
        dissect_crci_bits(tvb, pinfo, tree, num_tbs, offset);

        /* Payload CRC */
        proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        offset += 2;
    }
}



/**************************/
/* Dissect a PCH channel  */
void dissect_pch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;
    guint16  pch_cfn;
    gboolean paging_indication;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        int num_tbs = 0;

        /* DATA */

        /* 12-bit CFN value */
        proto_tree_add_item(tree, hf_fp_pch_cfn, tvb, offset, 2, FALSE);
        pch_cfn = (tvb_get_ntohs(tvb, offset) & 0xfff0) >> 4;
        offset++;

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "CFN=%04u ", pch_cfn);
        }

        /* Paging indication */
        proto_tree_add_item(tree, hf_fp_pch_pi, tvb, offset, 1, FALSE);
        paging_indication = tvb_get_guint8(tvb, offset) & 0x01;
        offset++;

        /* 5-bit TFI */
        proto_tree_add_item(tree, hf_fp_pch_tfi, tvb, offset, 1, FALSE);
        offset++;

        /* Optional paging indications */
        if (paging_indication)
        {
            proto_item *ti;
            ti = proto_tree_add_item(tree, hf_fp_paging_indication_bitmap, tvb,
                                     offset,
                                     (p_fp_info->paging_indications+7) / 8,
                                     FALSE);
            proto_item_append_text(ti, " (%u bits)", p_fp_info->paging_indications);
        }

        /* TB data */
        offset = dissect_tb_data(tvb, pinfo, tree, offset, p_fp_info, &num_tbs);

        /* Payload CRC */
        proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        offset += 2;
    }
}


/********************************/
/* Dissect an IUR DSCH channel  */
void dissect_iur_dsch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   int offset, struct _fp_info *p_fp_info _U_)
{
    gboolean is_control_frame;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }


    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        /* TODO: DATA */
    }
}




/************************/
/* DCH control messages */

void dissect_dch_timing_adjustment(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    guint8 control_cfn;
    gint16 toa;

    /* CFN control */
    control_cfn = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
    offset++;

    /* ToA */
    toa = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_fp_toa, tvb, offset, 2, FALSE);
    offset += 2;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " CFN = %u, ToA = %d", control_cfn, toa);
    }
}

void dissect_dch_rx_timing_deviation(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    /* CFN control */
    proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
    offset++;

    /* Rx Timing Deviation */
    proto_tree_add_item(tree, hf_fp_dch_rx_timing_deviation, tvb, offset, 1, FALSE);
    offset++;
}

void dissect_dch_dl_synchronisation(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    /* CFN control */
    guint cfn = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " CFN = %u", cfn);
    }
}

void dissect_dch_ul_synchronisation(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    guint8 cfn;
    gint16 toa;

    /* CFN control */
    cfn = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_fp_cfn_control, tvb, offset, 1, FALSE);
    offset++;

    /* ToA */
    toa = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_fp_toa, tvb, offset, 2, FALSE);
    offset += 2;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " CFN = %u, ToA = %d",
                        cfn, toa);
    }
}



/*******************************/
/* Dissect a DCH channel       */
void dissect_dch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;
    guint8   control_frame_type;
    guint8   cfn;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        /* DCH control frame */

        /* Control frame type */
        control_frame_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fp_dch_control_frame_type, tvb, offset, 1, FALSE);
        offset++;

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_str(pinfo->cinfo, COL_INFO,
                           val_to_str(control_frame_type,
                                      dch_control_frame_type_vals, "Unknown"));
        }

        switch (control_frame_type)
        {
            case DCH_TIMING_ADJUSTMENT:
                dissect_dch_timing_adjustment(tree, pinfo, tvb, offset);
                break;
            case DCH_RX_TIMING_DEVIATION:
                dissect_dch_rx_timing_deviation(tree, tvb, offset);
                break;
            case DCH_DL_SYNCHRONISATION:
                dissect_dch_dl_synchronisation(tree, pinfo, tvb, offset);
                break;
            case DCH_UL_SYNCHRONISATION:
                dissect_dch_ul_synchronisation(tree, pinfo, tvb, offset);
                break;

            case DCH_OUTER_LOOP_POWER_CONTROL:
            case DCH_DL_NODE_SYNCHRONISATION:
            case DCH_UL_NODE_SYNCHRONISATION:
            case DCH_RADIO_INTERFACE_PARAMETER_UPDATE:
            case DCH_TIMING_ADVANCE:
            case DCH_TNL_CONGESTION_INDICATION:
                /* TODO: */
                break;
        }
    }
    else
    {
        /************************/
        /* DCH data here        */
        int chan;
        int num_tbs = 0;

        /* CFN */
        proto_tree_add_item(tree, hf_fp_cfn, tvb, offset, 1, FALSE);
        cfn = tvb_get_guint8(tvb, offset);
        offset++;

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "CFN=%03u ", cfn);
        }

        /* One TFI for each channel */
        for (chan=0; chan < p_fp_info->num_chans; chan++)
        {
            proto_tree_add_item(tree, hf_fp_tfi, tvb, offset, 1, FALSE);
            offset++;
        }

        /* Dissect TB data */
        offset = dissect_tb_data(tvb, pinfo, tree, offset, p_fp_info, &num_tbs);

        /* QE (uplink only) */
        if (p_fp_info->is_uplink)
        {
            proto_tree_add_item(tree, hf_fp_quality_estimate, tvb, offset, 1, FALSE);
            offset++;
        }

        /* CRCI bits (uplink only) */
        if (p_fp_info->is_uplink)
        {
            offset = dissect_crci_bits(tvb, pinfo, tree, num_tbs, offset);
        }

        /* Payload CRC (optional) */
        if (p_fp_info->dch_crc_present)
        {
            proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        }
    }
}



/**********************************/
/* Dissect an E-DCH channel       */
void dissect_e_dch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;
    guint8   number_of_subframes;
    guint8   cfn;
    int      n;
    struct   subframe_info subframes[8];

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_edch_header_crc, tvb, offset, 2, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        /* TODO: will this be seen? */
    }
    else
    {
        /********************************/
        /* E-DCH data here        */

        guint  bit_offset = 0;
        guint  total_bits = 0;

        /* FSN */
        proto_tree_add_item(tree, hf_fp_edch_fsn, tvb, offset, 1, FALSE);
        offset++;

        /* Number of subframes (3 bits) */
        number_of_subframes = (tvb_get_guint8(tvb, offset) & 0x07);
        proto_tree_add_item(tree, hf_fp_edch_number_of_subframes, tvb, offset, 1, FALSE);
        offset++;

        /* CFN */
        cfn = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fp_cfn, tvb, offset, 1, FALSE);
        offset++;

        /* EDCH subframe header list */
        for (n=0; n < number_of_subframes; n++)
        {
            int i;
            proto_item *subframe_header_ti;
            proto_tree *subframe_header_tree;

            /* Add subframe header subtree */
            subframe_header_ti = proto_tree_add_string_format(tree, hf_fp_edch_subframe_header, tvb, offset, 0,
                                                              "", "Subframe");
            subframe_header_tree = proto_item_add_subtree(subframe_header_ti, ett_fp_edch_subframe_header);

            /* Number of HARQ Retransmissions */
            proto_tree_add_item(subframe_header_tree, hf_fp_edch_harq_retransmissions, tvb,
                                offset, 1, FALSE);

            /* Subframe number */
            subframes[n].subframe_number = (tvb_get_guint8(tvb, offset) & 0x07);
            proto_tree_add_item(subframe_header_tree, hf_fp_edch_subframe_number, tvb,
                                offset, 1, FALSE);
            offset++;

            /* Number of MAC-es PDUs */
            subframes[n].number_of_mac_es_pdus = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
            proto_tree_add_item(subframe_header_tree, hf_fp_edch_number_of_mac_es_pdus,
                                tvb, offset, 1, FALSE);
            bit_offset = 4;

            proto_item_append_text(subframe_header_ti, " %u header (%u MAC-es PDUs)",
                                   subframes[n].subframe_number,
                                   subframes[n].number_of_mac_es_pdus);

            /* Details of each MAC-es PDU */
            for (i=0; i < subframes[n].number_of_mac_es_pdus; i++)
            {
                guint8 ddi;
                int    ddi_offset;
                guint8 n_pdus;
                int    n_pdus_offset;

                /* DDI (6 bits) */
                ddi_offset = offset + (bit_offset / 8);

                switch (bit_offset%8)
                {
                    case 0:
                        ddi = (tvb_get_guint8(tvb, ddi_offset) >> 2);
                        break;
                    case 2:
                        ddi = (tvb_get_guint8(tvb, ddi_offset) & 0x3f);
                        break;
                    case 4:
                        ddi = (tvb_get_ntohs(tvb, ddi_offset) >> 6) & 0x003f;
                        break;
                    case 6:
                        ddi = (tvb_get_ntohs(tvb, ddi_offset) >> 4) & 0x003f;
                        break;
                    default:
                        /* Can't get here, but avoid warning */
                        return;
                }

                proto_tree_add_uint(subframe_header_tree, hf_fp_edch_ddi, tvb, ddi_offset,
                                    ((bit_offset%8) <= 2) ? 1 : 2, ddi);

                subframes[n].ddi[i] = ddi;
                bit_offset += 6;

                /* Number of MAC-d PDUs (6 bits) */
                n_pdus_offset = offset + (bit_offset / 8);
                switch (bit_offset%8)
                {
                    case 0:
                        n_pdus = (tvb_get_guint8(tvb, n_pdus_offset) >> 2);
                        break;
                    case 2:
                        n_pdus = (tvb_get_guint8(tvb, n_pdus_offset) & 0x3f);
                        break;
                    case 4:
                        n_pdus = (tvb_get_ntohs(tvb, n_pdus_offset) >> 6) & 0x003f;
                        break;
                    case 6:
                        n_pdus = (tvb_get_ntohs(tvb, n_pdus_offset) >> 4) & 0x003f;
                        break;
                    default:
                        /* Can't get here, but avoid warning */
                        return;
                }
                proto_tree_add_uint(subframe_header_tree, hf_fp_edch_number_of_mac_d_pdus, tvb, n_pdus_offset,
                                    ((bit_offset%8) <= 2) ? 1 : 2, n_pdus);

                subframes[n].number_of_mac_d_pdus[i] = n_pdus;
                bit_offset += 6;
            }

            /* Tree should cover entire subframe header */
            proto_item_set_len(subframe_header_ti, bit_offset/8);

            offset += ((bit_offset+7)/8);
        }

        /* EDCH subframes */
        bit_offset = 0;
        for (n=0; n < number_of_subframes; n++)
        {
            int i;
            proto_item *subframe_ti;
            proto_tree *subframe_tree;
            guint bits_in_subframe = 0;
            guint mac_d_pdus_in_subframe = 0;

            bit_offset = 0;

            /* Add subframe subtree */
            subframe_ti = proto_tree_add_string_format(tree, hf_fp_edch_subframe, tvb, offset, 0,
                                                       "", "Subframe %u", subframes[n].subframe_number);
            subframe_tree = proto_item_add_subtree(subframe_ti, ett_fp_edch_subframe);

            for (i=0; i < subframes[n].number_of_mac_es_pdus; i++)
            {
                int m;
                guint8 size = 0;
                guint  send_size;
                proto_item *ti;

                /* Look up mac-d pdu size for this ddi */
                for (m=0; m < p_fp_info->no_ddi_entries; m++)
                {
                    if (subframes[n].ddi[i] == p_fp_info->edch_ddi[m])
                    {
                        size = p_fp_info->edch_macd_pdu_size[m];
                        break;
                    }
                }

                if (m == p_fp_info->no_ddi_entries)
                {
                    /* Not found.  Oops */
                    return;
                }

                /* Send MAC-dd PDUs together as one MAC-es PDU */
                send_size = size * subframes[n].number_of_mac_d_pdus[i];

                /* 2 bits spare */
                proto_tree_add_item(subframe_tree, hf_fp_edch_pdu_padding, tvb,
                                    offset + (bit_offset/8),
                                    1, FALSE);
                bit_offset += 2;

                /* TSN */
                proto_tree_add_item(subframe_tree, hf_fp_edch_tsn, tvb,
                                    offset + (bit_offset/8),
                                    1, FALSE);
                bit_offset += 6;

                /* PDU */
                ti = proto_tree_add_item(subframe_tree, hf_fp_edch_mac_es_pdu, tvb,
                                         offset + (bit_offset/8),
                                         ((bit_offset % 8) + send_size + 7) / 8,
                                         FALSE);
                proto_item_append_text(ti, " (%u * %u = %u bits, subframe %d)",
                                       size, subframes[n].number_of_mac_d_pdus[i],
                                       send_size, n);
                bits_in_subframe += send_size;
                mac_d_pdus_in_subframe += subframes[n].number_of_mac_d_pdus[i];

                bit_offset += send_size;

                /* Pad out to next byte */
                if (bit_offset % 8)
                {
                    bit_offset += (8 - (bit_offset % 8));
                }
            }

            /* Tree should cover entire subframe */
            proto_item_set_len(subframe_ti, bit_offset/8);

            /* Append summary info to subframe label */
            proto_item_append_text(subframe_ti, " (%u bits in %u MAC-d PDUs)",
                                   bits_in_subframe, mac_d_pdus_in_subframe);
            total_bits += bits_in_subframe;

            offset += (bit_offset/8);
        }

        /* Report number of subframes in info column */
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " CFN = %u   (%u bits in %u subframes)",
                            cfn, total_bits, number_of_subframes);
        }

        /* Payload CRC (optional) */
        if (p_fp_info->dch_crc_present)
        {
            proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
        }
    }
}


/***********************************/
/* Dissect an HSDSCH channel       */
void dissect_hsdsch_channel_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 int offset, struct _fp_info *p_fp_info)
{
    gboolean is_control_frame;

    /* Header CRC */
    proto_tree_add_item(tree, hf_fp_header_crc, tvb, offset, 1, FALSE);

    /* Frame Type */
    is_control_frame = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_item(tree, hf_fp_ft, tvb, offset, 1, FALSE);
    offset++;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, is_control_frame ? " [Control] " : " [Data] ");
    }

    if (is_control_frame)
    {
        dissect_common_control(tvb, pinfo, tree, offset, p_fp_info);
    }
    else
    {
        guint8 number_of_pdus;
        guint16 pdu_length;

        /********************************/
        /* HS-DCH data here             */

        /* CmCH-PI */
        proto_tree_add_item(tree, hf_fp_cmch_pi, tvb, offset, 1, FALSE);
        offset++;

        /* MAC-d PDU Length (13 bits) */
        pdu_length = (tvb_get_ntohs(tvb, offset) >> 3);
        proto_tree_add_item(tree, hf_fp_mac_d_pdu_len, tvb, offset, 2, FALSE);
        offset += 2;

        /* Num of PDU */
        number_of_pdus = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fp_num_of_pdu, tvb, offset, 1, FALSE);
        offset++;

        /* User buffer size */
        proto_tree_add_item(tree, hf_fp_user_buffer_size, tvb, offset, 2, FALSE);
        offset += 2;

        /* MAC-d PDUs */
        offset = dissect_macd_pdu_data(tvb, pinfo, tree, offset, pdu_length,
                                       number_of_pdus);

        /* Extra R6 stuff */
        if (p_fp_info->release == 6)
        {
            /* TODO */
            offset += 3;
        }

        /* TODO: may be spare extension to skip */

        /* Payload CRC */
        proto_tree_add_item(tree, hf_fp_payload_crc, tvb, offset, 2, FALSE);
    }
}




/*****************************/
/* Main dissection function. */
void dissect_fp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree       *fp_tree;
    proto_item       *ti;
    gint             offset = 0;
    struct _fp_info  *p_fp_info;

    /* Append this protocol name rather than replace. */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FP");

    /* Create fp tree. */
    ti = proto_tree_add_item(tree, proto_fp, tvb, offset, -1, FALSE);
    fp_tree = proto_item_add_subtree(ti, ett_fp);

    /* Look for packet info! */
    p_fp_info = p_get_proto_data(pinfo->fd, proto_fp);

    /* Can't dissect anything without it... */
    if (p_fp_info == NULL)
    {
        return;
    }

    /* Show channel type in info column, tree */
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_set_str(pinfo->cinfo, COL_INFO,
                    val_to_str(p_fp_info->channel,
                               channel_type_vals,
                               "Unknown channel type"));
    }
    proto_item_append_text(ti, " (%s)",
                           val_to_str(p_fp_info->channel,
                                      channel_type_vals,
                                      "Unknown channel type"));

    /* Add channel type as a generated field */
    ti = proto_tree_add_uint(fp_tree, hf_fp_channel_type, tvb, 0, 0, p_fp_info->channel);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Add link direction as a generated field */
    ti = proto_tree_add_uint(fp_tree, hf_fp_direction, tvb, 0, 0, p_fp_info->is_uplink);
    PROTO_ITEM_SET_GENERATED(ti);


    /*************************************/
    /* Dissect according to channel type */
    switch (p_fp_info->channel)
    {
        case CHANNEL_RACH_TDD:
        case CHANNEL_RACH_TDD_128:
        case CHANNEL_RACH_FDD:
            dissect_rach_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_DCH:
            dissect_dch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_FACH_FDD:
        case CHANNEL_FACH_TDD:
            dissect_fach_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_DSCH_FDD:
        case CHANNEL_DSCH_TDD:
            dissect_dsch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_USCH_TDD_128:
        case CHANNEL_USCH_TDD_384:
            dissect_usch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_PCH:
            dissect_pch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_CPCH:
            break;
        case CHANNEL_BCH:
            break;
        case CHANNEL_HSDSCH:
            dissect_hsdsch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_IUR_CPCHF:
            break;
        case CHANNEL_IUR_FACH:
            break;
        case CHANNEL_IUR_DSCH:
            dissect_iur_dsch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;
        case CHANNEL_EDCH:
            dissect_e_dch_channel_info(tvb, pinfo, fp_tree, offset, p_fp_info);
            break;

        default:
            break;
    }
}

void proto_register_fp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_fp_channel_type,
            { "Channel Type",
              "fp.channel-type", FT_UINT8, BASE_HEX, VALS(channel_type_vals), 0x0,
              "Channel Type", HFILL
            }
        },
        { &hf_fp_direction,
            { "Direction",
              "fp.direction", FT_UINT8, BASE_HEX, VALS(direction_vals), 0x0,
              "Link direction", HFILL
            }
        },
        { &hf_fp_header_crc,
            { "Header CRC",
              "fp.header-crc", FT_UINT8, BASE_HEX, NULL, 0xfe,
              "Header CRC", HFILL
            }
        },
        { &hf_fp_ft,
            { "Frame Type",
              "fp.ft", FT_UINT8, BASE_HEX, VALS(data_control_vals), 0x01,
              "Frame Type", HFILL
            }
        },
        { &hf_fp_cfn,
            { "CFN",
              "fp.cfn", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Connection Frame Number", HFILL
            }
        },
        { &hf_fp_pch_cfn,
            { "CFN (PCH)",
              "fp.pch.cfn", FT_UINT16, BASE_DEC, NULL, 0xfff0,
              "PCH Connection Frame Number", HFILL
            }
        },
        { &hf_fp_pch_toa,
            { "ToA (PCH)",
              "fp.pch.toa", FT_INT24, BASE_DEC, NULL, 0x0,
              "PCH Time of Arrival", HFILL
            }
        },
        { &hf_fp_cfn_control,
            { "CFN control",
              "fp.cfn-control", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Connection Frame Number Control", HFILL
            }
        },
        { &hf_fp_toa,
            { "ToA",
              "fp.cfn-control", FT_INT16, BASE_DEC, NULL, 0x0,
              "Connection Frame Number Control", HFILL
            }
        },
        { &hf_fp_tb,
            { "TB",
              "fp.tb", FT_NONE, BASE_NONE, NULL, 0x0,
              "TB", HFILL
            }
        },
        { &hf_fp_tfi,
            { "TFI",
              "fp.tfi", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Transport Format Indicator", HFILL
            }
        },
        { &hf_fp_propagation_delay,
            { "Propagation Delay",
              "fp.propagation-delay", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Propagation Delay", HFILL
            }
        },
        { &hf_fp_dch_control_frame_type,
            { "Control Frame Type",
              "fp.dch.control.frame-type", FT_UINT8, BASE_HEX, VALS(dch_control_frame_type_vals), 0x0,
              "DCH Control Frame Type", HFILL
            }
        },
        { &hf_fp_dch_rx_timing_deviation,
            { "Rx Timing Deviation",
              "fp.dch.control.rx-timing-deviation", FT_UINT8, BASE_DEC, 0, 0x0,
              "DCH Rx Timing Deviation", HFILL
            }
        },
        { &hf_fp_quality_estimate,
            { "Quality Estimate",
              "fp.dch.quality-estimate", FT_UINT8, BASE_DEC, 0, 0x0,
              "Quality Estimate", HFILL
            }
        },
        { &hf_fp_payload_crc,
            { "Payload CRC",
              "fp.dch.payload-crc", FT_UINT16, BASE_HEX, 0, 0x0,
              "Payload CRC", HFILL
            }
        },
        { &hf_fp_common_control_frame_type,
            { "Control Frame Type",
              "fp.common.control.frame-type", FT_UINT8, BASE_HEX, VALS(common_control_frame_type_vals), 0x0,
              "Common Control Frame Type", HFILL
            }
        },
        { &hf_fp_crci[0],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x80,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[1],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x40,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[2],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x20,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[3],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x10,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[4],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x08,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[5],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x04,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[6],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x02,
              "CRCI", HFILL
            }
        },
        { &hf_fp_crci[7],
            { "CRCI",
              "fp.crci", FT_UINT8, BASE_HEX, VALS(crci_vals), 0x01,
              "CRCI", HFILL
            }
        },
        { &hf_fp_received_sync_ul_timing_deviation,
            { "Received SYNC UL Timing Deviation",
              "fp.rx-sync-ul-timing-deviation", FT_UINT8, BASE_DEC, 0, 0x0,
              "Received SYNC UL Timing Deviation", HFILL
            }
        },
        { &hf_fp_pch_pi,
            { "Paging Indication",
              "fp.pch.pi", FT_UINT8, BASE_DEC, 0, 0x01,
              "Describes if the PI Bitmap is present", HFILL
            }
        },
        { &hf_fp_pch_tfi,
            { "TFI",
              "fp.pch.tfi", FT_UINT8, BASE_DEC, 0, 0x1f,
              "Transport Format Indicator", HFILL
            }
        },
        { &hf_fp_fach_tfi,
            { "TFI",
              "fp.fach.tfi", FT_UINT8, BASE_DEC, 0, 0x1f,
              "Transport Format Indicator", HFILL
            }
        },
        { &hf_fp_transmit_power_level,
            { "Transmit Power Level",
              "fp.transmit-power-level", FT_UINT8, BASE_DEC, 0, 0x0,
              "Transmit Power Level", HFILL
            }
        },
        { &hf_fp_pdsch_set_id,
            { "PDSCH Set Id",
              "fp.pdsch-set-id", FT_UINT8, BASE_DEC, 0, 0x0,
              "A pointer to the PDSCH Set which shall be used to transmit", HFILL
            }
        },
        { &hf_fp_paging_indication_bitmap,
            { "Paging Indications bitmap",
              "fp.pch.pi-bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Paging Indication bitmap", HFILL
            }
        },
        { &hf_fp_rx_timing_deviation,
            { "Rx Timing Deviation",
              "fp.common.control.rx-timing-deviation", FT_UINT8, BASE_DEC, 0, 0x0,
              "Common Rx Timing Deviation", HFILL
            }
        },
        { &hf_fp_edch_header_crc,
            { "E-DCH Header CRC",
              "fp.edch.header-crc", FT_UINT16, BASE_HEX, 0, 0xfef,
              "E-DCH Header CRC", HFILL
            }
        },
        { &hf_fp_edch_fsn,
            { "FSN",
              "fp.edch.fsn", FT_UINT8, BASE_DEC, 0, 0x0f,
              "E-DCH FSN", HFILL
            }
        },
        { &hf_fp_edch_number_of_subframes,
            { "No of subframes",
              "fp.edch.no-of-subgrames", FT_UINT8, BASE_DEC, 0, 0x07,
              "E-DCH Number of subframes", HFILL
            }
        },
        { &hf_fp_edch_harq_retransmissions,
            { "No of HARQ Retransmissions",
              "fp.edch.no-of-harq-retransmissions", FT_UINT8, BASE_DEC, 0, 0x78,
              "E-DCH Number of HARQ retransmissions", HFILL
            }
        },
        { &hf_fp_edch_subframe_number,
            { "Subframe number",
              "fp.edch.subframe-number", FT_UINT8, BASE_DEC, 0, 0x07,
              "E-DCH Subframe number", HFILL
            }
        },
        { &hf_fp_edch_number_of_mac_es_pdus,
            { "Number of Mac-es PDUs",
              "fp.edch.number-of-mac-es-pdus", FT_UINT8, BASE_DEC, 0, 0xf0,
              "Number of Mac-es PDUs", HFILL
            }
        },
        { &hf_fp_edch_ddi,
            { "DDI",
              "fp.edch.ddi", FT_UINT8, BASE_DEC, 0, 0x0,
              "E-DCH Data Description Indicator", HFILL
            }
        },
        { &hf_fp_edch_subframe,
            { "Subframe",
              "fp.edch.subframe", FT_STRING, BASE_NONE, NULL, 0x0,
              "EDCH Subframe", HFILL
            }
        },
        { &hf_fp_edch_subframe_header,
            { "Subframe header",
              "fp.edch.subframe-header", FT_STRING, BASE_NONE, NULL, 0x0,
              "EDCH Subframe header", HFILL
            }
        },
        { &hf_fp_edch_number_of_mac_d_pdus,
            { "Number of Mac-d PDUs",
              "fp.edch.number-of-mac-d-pdus", FT_UINT8, BASE_DEC, 0, 0x0,
              "Number of Mac-d PDUs", HFILL
            }
        },
        { &hf_fp_edch_pdu_padding,
            { "Padding",
              "fp.edch-data-padding", FT_UINT8, BASE_DEC, 0, 0xc0,
              "E-DCH padding before PDU", HFILL
            }
        },
        { &hf_fp_edch_tsn,
            { "TSN",
              "fp.edch-tsn", FT_UINT8, BASE_DEC, 0, 0x3f,
              "E-DCH Transmission Sequence Number", HFILL
            }
        },
        { &hf_fp_edch_mac_es_pdu,
            { "MAC-es PDU",
              "fp.edch.mac-es-pdu", FT_NONE, BASE_NONE, NULL, 0x0,
              "MAC-es PDU", HFILL
            }
        },
        { &hf_fp_cmch_pi,
            { "CmCH-PI",
              "fp.cmch-pi", FT_UINT8, BASE_DEC, 0, 0x0f,
              "Common Transport Channel Priority Indicator", HFILL
            }
        },
        { &hf_fp_user_buffer_size,
            { "User buffer size",
              "fp.user-buffer-size", FT_UINT16, BASE_DEC, 0, 0x0,
              "User buffer size in octets", HFILL
            }
        },
        { &hf_fp_hsdsch_credits,
            { "HS-DSCH Credits",
              "fp.hsdsch-credits", FT_UINT16, BASE_DEC, 0, 0x07ff,
              "HS-DSCH Credits", HFILL
            }
        },
        { &hf_fp_hsdsch_max_macd_pdu_len,
            { "Max MAC-d PDU Length",
              "fp.hsdsch.max-macd-pdu-len", FT_UINT16, BASE_DEC, 0, 0xfff8,
              "Maximum MAC-d PDU Length in bits", HFILL
            }
        },
        { &hf_fp_hsdsch_interval,
            { "HS-DSCH Interval in milliseconds",
              "fp.hsdsch-interval", FT_UINT8, BASE_DEC, 0, 0x0,
              "HS-DSCH Interval in milliseconds", HFILL
            }
        },
        { &hf_fp_hsdsch_repetition_period,
            { "HS-DSCH Repetition Period",
              "fp.hsdsch-repetition-period", FT_UINT8, BASE_DEC, 0, 0x0,
              "HS-DSCH Repetition Period in milliseconds", HFILL
            }
        },
        { &hf_fp_hsdsch_data_padding,
            { "Padding",
              "fp.hsdsch-data-padding", FT_UINT8, BASE_DEC, 0, 0xf0,
              "HS-DSCH Repetition Period in milliseconds", HFILL
            }
        },
        { &hf_fp_timing_advance,
            { "Timing advance",
              "fp.timing-advance", FT_UINT8, BASE_DEC, 0, 0x3f,
              "Timing advance in chips", HFILL
            }
        },
        { &hf_fp_num_of_pdu,
            { "Number of PDUs",
              "fp.hsdsch.num-of-pdu", FT_UINT8, BASE_DEC, 0, 0x0,
              "Number of PDUs in the payload", HFILL
            }
        },
        { &hf_fp_mac_d_pdu_len,
            { "MAC-d PDU Length",
              "fp.hsdsch.mac-d-pdu-len", FT_UINT16, BASE_DEC, 0, 0xfff8,
              "MAC-d PDU Length in bits", HFILL
            }
        },
        { &hf_fp_mac_d_pdu,
            { "MAC-d PDU",
              "fp.mac-d-pdu", FT_NONE, BASE_NONE, NULL, 0x0,
              "MAC-d PDU", HFILL
            }
        },
        { &hf_fp_data,
            { "Data",
              "fp.data", FT_STRING, BASE_NONE, NULL, 0x0,
              "Data", HFILL
            }
        },
        { &hf_fp_crcis,
            { "CRCIs",
              "fp.crcis", FT_STRING, BASE_NONE, NULL, 0x0,
              "CRCIs for uplink TBs", HFILL
            }
        },
        { &hf_fp_t1,
            { "T1",
              "fp.t1", FT_UINT24, BASE_DEC, NULL, 0x0,
              "RNC frame number indicating time it sends frame", HFILL
            }
        },
        { &hf_fp_t2,
            { "T2",
              "fp.t2", FT_UINT24, BASE_DEC, NULL, 0x0,
              "NodeB frame number indicating time it received DL Sync", HFILL
            }
        },
        { &hf_fp_t3,
            { "T3",
              "fp.t3", FT_UINT24, BASE_DEC, NULL, 0x0,
              "NodeB frame number indicating time it sends frame", HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_fp,
        &ett_fp_data,
        &ett_fp_crcis,
        &ett_fp_edch_subframe_header,
        &ett_fp_edch_subframe
    };

    /* Register protocol. */
    proto_fp = proto_register_protocol("FP", "FP", "fp");
    proto_register_field_array(proto_fp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("fp", dissect_fp, proto_fp);
}


void proto_reg_handoff_fp(void)
{
}

