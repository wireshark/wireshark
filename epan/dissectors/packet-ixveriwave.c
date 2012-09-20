/* packet-ixveriwave-common.c
 * Routines for calling the right protocol for the ethertype.
 *
 * $Id$
 *
 * Tom Cook <tcook@ixiacom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/crc32-tvb.h>

#include "packet-eth.h"

static void dissect_ixveriwave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void ethernettap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree);
static void wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree);

typedef struct {
    guint32 previous_frame_num;
    guint64 previous_end_time;
} frame_end_data;

typedef struct ifg_info {
    guint32 ifg;
    guint64 previous_end_time;
    guint64 current_start_time;
} ifg_info;

static frame_end_data previous_frame_data = {0,0};

/* static int ieee80211_mhz2ieee(int freq, int flags); */

#define COMMON_LENGTH_OFFSET 2
#define ETHERNETTAP_VWF_TXF                 0x01    /* frame was transmitted flag */
#define ETHERNETTAP_VWF_FCSERR              0x02    /* frame has FCS error */

#define VW_RADIOTAPF_TXF                    0x01    /* frame was transmitted */
#define VW_RADIOTAPF_FCSERR                 0x02    /* FCS error detected */
#define VW_RADIOTAPF_RETRERR                0x04    /* excess retry error detected */
#define VW_RADIOTAPF_DCRERR                 0x10    /* decrypt error detected */
#define VW_RADIOTAPF_ENCMSK                 0x60    /* encryption type mask */
                                                    /* 0 = none, 1 = WEP, 2 = TKIP, 3 = CCKM */
#define VW_RADIOTAPF_ENCSHIFT               5       /* shift amount to right-align above field */
#define VW_RADIOTAPF_IS_WEP                 0x20    /* encryption type value = WEP */
#define VW_RADIOTAPF_IS_TKIP                0x40    /* encryption type value = TKIP */
#define VW_RADIOTAPF_IS_CCMP                0x60    /* encryption type value = CCMP */
#define VW_RADIOTAPF_SEQ_ERR                0x80    /* flow sequence error detected */

#define VW_RADIOTAP_FPGA_VER_vVW510021      0x000C  /* vVW510021 version detected */
#define VW_RADIOTAP_FPGA_VER_vVW510021_11n  0x000D

#define IEEE80211_CHAN_CCK                  0x00020 /* CCK channel */
#define IEEE80211_CHAN_OFDM                 0x00040 /* OFDM channel */
#define IEEE80211_CHAN_2GHZ                 0x00080 /* 2 GHz spectrum channel. */
#define IEEE80211_CHAN_5GHZ                 0x00100 /* 5 GHz spectrum channel */

#define IEEE80211_RADIOTAP_F_FCS            0x0010  /* frame includes FCS */
#define IEEE80211_RADIOTAP_F_DATAPAD        0x0020  /* frame has padding between
                         * 802.11 header and payload
                         * (to 32-bit boundary)
                         */
#define IEEE80211_RADIOTAP_F_HT             0x0040  /* HT mode */
#define IEEE80211_RADIOTAP_F_CFP            0x0001  /* sent/received
                         * during CFP
                         */
#define IEEE80211_RADIOTAP_F_SHORTPRE       0x0002  /* sent/received
                         * with short
                         * preamble
                         */
#define IEEE80211_RADIOTAP_F_WEP            0x0004  /* sent/received
                         * with WEP encryption
                         */
#define IEEE80211_RADIOTAP_F_FRAG           0x0008  /* sent/received
                         * with fragmentation
                         */
#define IEEE80211_PLCP_RATE_MASK        0x7f    /* parses out the rate or MCS index from the PLCP header(s) */
#define IEEE80211_RADIOTAP_F_40MHZ      0x0080  /* 40 Mhz channel bandwidth */
#define IEEE80211_RADIOTAP_F_SHORTGI    0x0100

#define ETHERNET_PORT           1
#define WLAN_PORT               0

static int proto_ixveriwave = -1;
static dissector_handle_t ethernet_handle;

/* static int hf_ixveriwave_version = -1; */
static int hf_ixveriwave_frame_length = -1;

/* static int hf_ixveriwave_fcs = -1; */

static int hf_ixveriwave_vw_vcid = -1;
static int hf_ixveriwave_vw_msdu_length = -1;
static int hf_ixveriwave_vw_seqnum = -1;
static int hf_ixveriwave_vw_flowid = -1;

static int hf_ixveriwave_vw_mslatency = -1;
static int hf_ixveriwave_vw_latency = -1;
static int hf_ixveriwave_vw_pktdur = -1;
static int hf_ixveriwave_vw_ifg = -1;
static int hf_ixveriwave = -1;
static int hf_ixveriwave_vw_startt = -1;
static int hf_ixveriwave_vw_endt = -1;

static gint ett_commontap = -1;
static gint ett_commontap_times = -1;
static gint ett_ethernettap_info = -1;
static gint ett_ethernettap_error = -1;
static gint ett_ethernettap_flags = -1;

/* static gint ett_radiotap = -1;
static gint ett_radiotap_present = -1;
*/
static gint ett_radiotap_flags = -1;
/* static gint ett_radiotap_channel_flags = -1; */

static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_datapad_handle;

/* Ethernet fields */
static int hf_ixveriwave_vw_info = -1;
static int hf_ixveriwave_vw_error = -1;

static int hf_ixveriwave_vwf_txf = -1;
static int hf_ixveriwave_vwf_fcserr = -1;

static int hf_ixveriwave_vw_l4id = -1;

/*veriwave note:  i know the below method seems clunky, but
they didn't have a item_format at the time to dynamically add the appropriate decode text*/
static int hf_ixveriwave_vw_info_retryCount = -1;
static int hf_ixveriwave_vw_info_tx_bit15 = -1;

static int hf_ixveriwave_vw_info_rx_1_bit8 = -1;
static int hf_ixveriwave_vw_info_rx_1_bit9 = -1;

/*error flags*/
static int hf_ixveriwave_vw_error_tx_bit1 = -1;
static int hf_ixveriwave_vw_error_tx_bit5 = -1;
static int hf_ixveriwave_vw_error_tx_bit9 = -1;
static int hf_ixveriwave_vw_error_tx_bit10 = -1;
static int hf_ixveriwave_vw_error_tx_bit11 = -1;

static int hf_ixveriwave_vw_error_rx_1_bit0 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit1 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit2 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit3 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit4 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit5 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit6 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit7 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit8 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit9 = -1;

static int hf_radiotap_flags = -1;
static int hf_radiotap_datarate = -1;
static int hf_radiotap_dbm_antsignal = -1;
static int hf_radiotap_txpower = -1;
static int hf_radiotap_fcs_bad = -1;

static int hf_radiotap_flags_cfp = -1;
static int hf_radiotap_flags_preamble = -1;
static int hf_radiotap_flags_wep = -1;
static int hf_radiotap_flags_frag = -1;
static int hf_radiotap_flags_fcs = -1;
static int hf_radiotap_flags_datapad = -1;
static int hf_radiotap_flags_ht = -1;
static int hf_radiotap_flags_40mhz = -1;
static int hf_radiotap_flags_shortgi = -1;

/* start VeriWave specific 6-2007*/
static int hf_radiotap_vw_errors = -1;
static int hf_radiotap_vw_info = -1;
static int hf_radiotap_vw_ht_length = -1;

static int hf_radiotap_vw_info_tx_bit10 = -1;
static int hf_radiotap_vw_info_tx_bit11 = -1;
static int hf_radiotap_vw_info_tx_bit12 = -1;
static int hf_radiotap_vw_info_tx_bit13 = -1;
static int hf_radiotap_vw_info_tx_bit14 = -1;
static int hf_radiotap_vw_info_tx_bit15 = -1;

static int hf_radiotap_vw_info_rx_2_bit8 = -1;
static int hf_radiotap_vw_info_rx_2_bit9 = -1;
static int hf_radiotap_vw_info_rx_2_bit10 = -1;
static int hf_radiotap_vw_info_rx_2_bit11 = -1;
static int hf_radiotap_vw_info_rx_2_bit12 = -1;
static int hf_radiotap_vw_info_rx_2_bit13 = -1;
static int hf_radiotap_vw_info_rx_2_bit14 = -1;
static int hf_radiotap_vw_info_rx_2_bit15 = -1;

static int hf_radiotap_vw_errors_rx_1_bit0 = -1;
static int hf_radiotap_vw_errors_rx_1_bit1 = -1;
static int hf_radiotap_vw_errors_rx_1_bit2 = -1;
static int hf_radiotap_vw_errors_rx_1_bit3 = -1;
static int hf_radiotap_vw_errors_rx_1_bit4 = -1;
static int hf_radiotap_vw_errors_rx_1_bit5 = -1;
static int hf_radiotap_vw_errors_rx_1_bit6 = -1;
static int hf_radiotap_vw_errors_rx_1_bit7 = -1;
static int hf_radiotap_vw_errors_rx_1_bit8 = -1;
static int hf_radiotap_vw_errors_rx_1_bit9 = -1;
static int hf_radiotap_vw_errors_rx_1_bit10 = -1;
static int hf_radiotap_vw_errors_rx_1_bit11 = -1;
static int hf_radiotap_vw_errors_rx_1_bit12 = -1;
static int hf_radiotap_vw_errors_rx_1_bit13 = -1;
static int hf_radiotap_vw_errors_rx_1_bit14 = -1;
static int hf_radiotap_vw_errors_rx_1_bit15 = -1;

static int hf_radiotap_vw_errors_rx_2_bit0 = -1;
static int hf_radiotap_vw_errors_rx_2_bit1 = -1;
static int hf_radiotap_vw_errors_rx_2_bit2 = -1;
static int hf_radiotap_vw_errors_rx_2_bit4 = -1;
static int hf_radiotap_vw_errors_rx_2_bit5 = -1;
static int hf_radiotap_vw_errors_rx_2_bit6 = -1;
static int hf_radiotap_vw_errors_rx_2_bit7 = -1;
static int hf_radiotap_vw_errors_rx_2_bit8 = -1;
static int hf_radiotap_vw_errors_rx_2_bit10 = -1;
static int hf_radiotap_vw_errors_rx_2_bit11 = -1;

static int hf_radiotap_vw_errors_tx_bit1 = -1;
static int hf_radiotap_vw_errors_tx_bit5 = -1;

static int hf_radiotap_vwf_txf = -1;
static int hf_radiotap_vwf_fcserr = -1;
static int hf_radiotap_vwf_dcrerr = -1;
static int hf_radiotap_vwf_retrerr = -1;
static int hf_radiotap_vwf_enctype = -1;

static gint ett_radiotap_info = -1;
static gint ett_radiotap_errors = -1;
static gint ett_radiotap_times = -1;

#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

/* Conversion of MCS index, guard interval, channel bandwidth to HT rate */
static int canonical_ndbps_20[] = {26, 52, 78, 104, 156, 208, 234, 260};
static int canonical_ndbps_40[] = {54, 108, 162, 216, 324, 432, 486, 540};
static float getHTrate( guint8 rate, guint8 rflags );

static void
dissect_ixveriwave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *common_tree                            = NULL;
    proto_item *ti                                     = NULL;
    proto_item *vw_times_ti                            = NULL;
    proto_tree *vw_times_tree                          = NULL;
    int         align_offset, offset, time_tree_offset = 0;
    guint16     version, length;
    guint       length_remaining;
    guint64     vw_startt = 0, vw_endt=0;
    guint32     true_length;
    guint32     vw_latency, vw_pktdur, vw_flowid;
    guint16     vw_vcid, vw_msdu_length, vw_seqnum;
    tvbuff_t   *next_tvb;
    ifg_info   *p_ifg_info;

    offset = 0;
    version = tvb_get_letohs(tvb, offset);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, version ? "ETH" : "WLAN");
    col_clear(pinfo->cinfo, COL_INFO);

    length = tvb_get_letohs(tvb, offset + COMMON_LENGTH_OFFSET);

    true_length = pinfo->fd->pkt_len - length - tvb_get_letohs(tvb, offset + length) + 4;   /* add FCS length into captured length */

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Capture, Length %u",
        version ? "IxVeriWave Ethernet Tap" : "IxVeriWave Radio Tap", length);

    /* Dissect the packet */
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ixveriwave,
            tvb, 0, length, "%s Header, Length %u", version ? "IxVeriWave Ethernet Tap" : "IxVeriWave Radio Tap", length);

        common_tree = proto_item_add_subtree(ti, ett_commontap);

        proto_tree_add_uint(common_tree, hf_ixveriwave_frame_length,
                            tvb, 4, 2, true_length);
    }

    length_remaining = length;

    offset           += 4;
    length_remaining -= 4;

    /*extract msdu/octets , 2 bytes*/
    align_offset      = ALIGN_OFFSET(offset, 2);
    offset           += align_offset;
    length_remaining -= align_offset;

    if (length_remaining >= 2) {

        vw_msdu_length = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_msdu_length,
                tvb, offset, 2, vw_msdu_length);
        }

        offset           += 2;
        length_remaining -= 2;
    }

    /*extract flow id , 4bytes*/
    if (length_remaining >= 4) {
        align_offset      = ALIGN_OFFSET(offset, 4);
        offset           += align_offset;
        length_remaining -= align_offset;

        vw_flowid = tvb_get_letohl(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_flowid,
                tvb, offset, 4, vw_flowid);
        }

        offset           += 4;
        length_remaining -= 4;
    }

    /*extract client id, 2bytes*/
    if (length_remaining >= 2) {
        align_offset      = ALIGN_OFFSET(offset, 2);
        offset           += align_offset;
        length_remaining -= align_offset;

        vw_vcid = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_vcid,
                tvb, offset, 2, vw_vcid);
        }

        offset           += 2;
        length_remaining -= 2;
    }

    /*extract sequence number , 2bytes*/
    if (length_remaining >= 2) {

        vw_seqnum = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_seqnum,
                tvb, offset, 2, vw_seqnum);
        }

        offset           += 2;
        length_remaining -= 2;
    }

    /*extract latency, 4 bytes*/
    if (length_remaining >= 4) {
        align_offset      = ALIGN_OFFSET(offset, 4);
        offset           += align_offset;
        length_remaining -= align_offset;

        vw_latency = tvb_get_letohl(tvb, offset);

        if (tree) {
            /* start a tree going for the various packet times */
            if (vw_latency != 0) {
                vw_times_ti = proto_tree_add_float_format(common_tree,
                    hf_ixveriwave_vw_mslatency,
                    tvb, offset, 4, (float)(vw_latency/1000000.0),
                    "Frame timestamp values: (latency %.3f msec)",
                    (float)(vw_latency/1000000.0));
                vw_times_tree = proto_item_add_subtree(vw_times_ti, ett_commontap_times);

                proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_latency,
                    tvb, offset, 4, vw_latency,
                    "Frame latency: %u nsec", vw_latency);
            }
            else
            {
                vw_times_ti = proto_tree_add_float_format(common_tree,
                    hf_ixveriwave_vw_mslatency,
                    tvb, offset, 4, (float)(vw_latency/1000000.0),
                    "Frame timestamp values:");
                vw_times_tree = proto_item_add_subtree(vw_times_ti, ett_commontap_times);

                proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_latency,
                    tvb, offset, 4, vw_latency,
                    "Frame latency: N/A");
            }
        }

        offset           += 4;
        length_remaining -= 4;
    }



    /*extract signature timestamp, 4 bytes (32 LSBs only, nsec)*/
    if (length_remaining >= 4) {
        align_offset      = ALIGN_OFFSET(offset, 4);
        offset           += align_offset;
        length_remaining -= align_offset;

        if (tree) {
            if (vw_times_tree != NULL) {
                /* TODO: what should this fieldname be? */
                proto_tree_add_item(vw_times_tree, hf_ixveriwave,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
            }
        }
        time_tree_offset  = offset;
        offset           += 4;
        length_remaining -= 4;
    }

    /*extract frame start timestamp, 8 bytes (nsec)*/
    if (length_remaining >= 8) {
        align_offset      = ALIGN_OFFSET(offset, 8);
        offset           += align_offset;
        length_remaining -= align_offset;

        vw_startt = tvb_get_letoh64(tvb, offset);

        if (tree) {
            if (vw_times_tree != NULL) {
                proto_tree_add_uint64_format(vw_times_tree, hf_ixveriwave_vw_startt,
                    tvb, offset, 8, vw_startt,
                    "Frame start timestamp: %" G_GINT64_MODIFIER "u usec", vw_startt);
            }
        }

        offset           += 8;
        length_remaining -= 8;
    }

    /*extract frame end timestamp, 8 bytes (nsec)*/
    if (length_remaining >= 8) {
        align_offset      = ALIGN_OFFSET(offset, 8);
        offset           += align_offset;
        length_remaining -= align_offset;

        vw_endt = tvb_get_letoh64(tvb, offset);

        if (tree) {
            if (vw_times_tree != NULL) {
                proto_tree_add_uint64_format(vw_times_tree, hf_ixveriwave_vw_endt,
                    tvb, offset, 8, vw_endt,
                    "Frame end timestamp: %" G_GINT64_MODIFIER "u usec", vw_endt);
            }
        }

        offset           += 8;
        length_remaining -= 8;
    }
    /*extract frame duration , 4 bytes*/
    if (length_remaining >= 4) {
        align_offset  = ALIGN_OFFSET(offset, 4);
        offset       += align_offset;
        vw_pktdur     = tvb_get_letohl(tvb, offset);

        if (tree) {
            if (vw_times_tree != NULL) {
                proto_item *duration_ti;
                if (vw_endt >= vw_startt) {
                    duration_ti = proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                                             tvb, offset-16, 16, vw_pktdur,
                                                             "Frame duration: %u nsec", vw_pktdur);

                    /* Add to root summary */
                    proto_item_append_text(vw_times_ti, " (Frame duration=%u nsecs)", vw_pktdur);
                }
                else {
                    duration_ti = proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                                             tvb, offset, 0, vw_pktdur,
                                                             "Frame duration: N/A");

                    /* Add to root summary */
                    proto_item_append_text(vw_times_ti, " (Frame duration=N/A)");
                }

                PROTO_ITEM_SET_GENERATED(duration_ti);
            }
        }

        offset += 4;
    }

    if (vw_times_ti) {
        proto_item_set_len(vw_times_ti, offset-time_tree_offset);
    }

    /* Calculate the IFG */

    /* Check for an existing ifg value associated with the frame */
    p_ifg_info = p_get_proto_data(pinfo->fd, proto_ixveriwave);
    if (!p_ifg_info)
    {
        /* allocate the space */
        p_ifg_info = se_alloc0(sizeof(struct ifg_info));

        /* Doesn't exist, so we need to calculate the value */
        if (previous_frame_data.previous_frame_num !=0 && (pinfo->fd->num - previous_frame_data.previous_frame_num == 1))
        {
            p_ifg_info->ifg = (guint32)(vw_startt - previous_frame_data.previous_end_time);
            p_ifg_info->previous_end_time = previous_frame_data.previous_end_time;
        }
        else
        {
            p_ifg_info->ifg               = 0;
            p_ifg_info->previous_end_time = 0;
        }

        /* Store current data into the static structure */
        previous_frame_data.previous_end_time = vw_endt;
        previous_frame_data.previous_frame_num = pinfo->fd->num;

        /* Record the current start time */
        p_ifg_info->current_start_time = vw_startt;

        /* Add the ifg onto the frame */
        p_add_proto_data(pinfo->fd, proto_ixveriwave, p_ifg_info);
    }

    if (tree) {
        ti = proto_tree_add_uint(common_tree, hf_ixveriwave_vw_ifg,
                tvb, offset, 0, p_ifg_info->ifg);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset_remaining(tvb, length);

    /* dissect the ethernet or wlan header next */
    if (version == ETHERNET_PORT)
        ethernettap_dissect(next_tvb, pinfo, tree, common_tree);
    else
        wlantap_dissect(next_tvb, pinfo, tree, common_tree);
}

/*
 * Returns the amount required to align "offset" with "width"
 */
#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

static void
ethernettap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree)
{
    proto_tree *vweft, *vw_errorFlags_tree = NULL, *vwift,*vw_infoFlags_tree = NULL;
    int         align_offset, offset;
    tvbuff_t   *next_tvb;
    guint       length, length_remaining;
    guint16     vw_flags, vw_info;
    guint16     vw_l4id;
    guint32     vw_error;
    gint32      vwf_txf, vwf_fcserr;

    vwf_txf = 0;

    offset = 0;

    length = tvb_get_letohs(tvb, offset);
    length_remaining = length;

    offset           += 2;
    length_remaining -= 2;

    /* extract flags (currently use only TX/RX and FCS error flag) */
    if (length >= 2) {
        align_offset      = ALIGN_OFFSET(offset, 2);
        offset           += align_offset;
        length_remaining -= align_offset;
        vw_flags          = tvb_get_letohs(tvb, offset);
        vwf_txf           = ((vw_flags & ETHERNETTAP_VWF_TXF) == 0) ? 0 : 1;
        vwf_fcserr        = ((vw_flags & ETHERNETTAP_VWF_FCSERR) == 0) ? 0 : 1;

        if (tap_tree) {
            proto_tree_add_uint(tap_tree, hf_ixveriwave_vwf_txf,
                tvb, 0, 0, vwf_txf);
            proto_tree_add_uint(tap_tree, hf_ixveriwave_vwf_fcserr,
                tvb, 0, 0, vwf_fcserr);
        }

        offset           += 2;
        length_remaining -= 2;
    }

    /*extract info flags , 2bytes*/

    if (length_remaining >= 2) {
        vw_info = tvb_get_letohs(tvb, offset);

        if (tap_tree) {
            vwift = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_info,
            tvb, offset, 2, vw_info);
            vw_infoFlags_tree = proto_item_add_subtree(vwift, ett_ethernettap_info);

            if (vwf_txf == 0) {
                /* then it's an rx case */
                proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_rx_1_bit8,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_rx_1_bit9,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            } else {
                /* it's a tx case */
                proto_tree_add_uint_format(vw_infoFlags_tree, hf_ixveriwave_vw_info_retryCount,
                    tvb, offset, 2, vw_info,
                "Retry count: %u ", vw_info);
            }
        } /*end of if tree */

        offset           += 2;
        length_remaining -= 2;
    }

    /*extract error , 4bytes*/
    if (length_remaining >= 4) {
        vw_error = tvb_get_letohl(tvb, offset);

        if (tap_tree) {
            vweft = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_error,
                tvb, offset, 4, vw_error);
            vw_errorFlags_tree = proto_item_add_subtree(vweft, ett_ethernettap_error);

            if (vwf_txf == 0) {
                /* then it's an rx case */
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit0,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit1,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit2,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit3,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit4,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit5,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit6,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit7,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit8,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_rx_1_bit9,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
            } else {
                /* it's a tx case */
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_tx_bit1,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_tx_bit5,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_tx_bit9,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_tx_bit10,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(vw_errorFlags_tree, hf_ixveriwave_vw_error_tx_bit11,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
        } /*end of if (tree) */

        offset           += 4;
        length_remaining -= 4;
    }
    /*extract l4id , 4bytes*/
    if (length_remaining >= 4) {
        vw_l4id = tvb_get_letohl(tvb, offset);
        if (tap_tree) {
            proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_l4id,
            tvb, offset, 4, vw_l4id);
        }
        offset           += 4;
        length_remaining -= 4;
    }

    /*extract pad, 4bytes*/
    if (length_remaining >= 4) {
        tvb_get_letohl(tvb, offset);   /* throw away pad */
    }

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset(tvb, length, -1, -1);

    /* dissect the ethernet header next */
    call_dissector(ethernet_handle, next_tvb, pinfo, tree);
}

static void
wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree)
{
    proto_tree *ft, *flags_tree = NULL;
    proto_item *hdr_fcs_ti      = NULL;
    int         align_offset, offset;
    guint32     calc_fcs;
    tvbuff_t   *next_tvb;
    guint       length;
    guint32     rate;
    gint8       dbm;
    guint8      rflags          = 0;

    proto_tree *vweft, *vw_errorFlags_tree = NULL, *vwift,*vw_infoFlags_tree = NULL;
    guint16     vw_flags, vw_info, vw_ht_length, vw_rflags;
    guint32     vw_errors;
    gint8       tx_power;
    float       ht_rate;

    offset = 0;
    length = tvb_get_letohs(tvb, offset);

    offset += 2;

    vw_rflags = tvb_get_letohs(tvb, offset);
    if (tree) {
        ft = proto_tree_add_uint(tap_tree, hf_radiotap_flags,
            tvb, offset, 2, vw_rflags);
        flags_tree = proto_item_add_subtree(ft, ett_radiotap_flags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_cfp,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_preamble,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_wep,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_frag,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_fcs,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_datapad,
            tvb, offset, 2, vw_rflags);
        if ( vw_rflags & IEEE80211_RADIOTAP_F_HT ) {
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_ht,
                tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_40mhz,
                tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_shortgi,
                tvb, offset, 2, vw_rflags);
        }
    }
    offset += 2;

    /* Need to add in 2 more bytes to the offset to account for the channel flags */
    offset += 2;

    rate = tvb_get_guint8(tvb, offset);
    if (vw_rflags & IEEE80211_RADIOTAP_F_HT) {
        ht_rate = getHTrate( rate, rflags );
        col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f",
            ht_rate);
        if (tree) {
            proto_tree_add_uint_format(tap_tree, hf_radiotap_datarate,
                tvb, offset, 1, tvb_get_guint8(tvb, offset),
                "Data rate: %.1f (MCS %d)", ht_rate, rate & IEEE80211_PLCP_RATE_MASK);
        }
    } else {
        col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%d.%d",
                        (rate & IEEE80211_PLCP_RATE_MASK)/ 2, rate & 1 ? 5 : 0);
        if (tree) {
                proto_tree_add_uint_format(tap_tree, hf_radiotap_datarate,
                tvb, offset, 1, tvb_get_guint8(tvb, offset),
                "Data rate: %d.%d Mb/s", (rate & IEEE80211_PLCP_RATE_MASK)/ 2,
                        (rate & IEEE80211_PLCP_RATE_MASK) & 1 ? 5 : 0);
        }
    }
    offset++;

    dbm = (gint8) tvb_get_guint8(tvb, offset);
    offset++;

    tx_power = (gint8)tvb_get_guint8(tvb, offset);
    if (dbm != 100)
    {
        col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
        if (tree) {
            proto_tree_add_int_format(tap_tree,
                hf_radiotap_dbm_antsignal,
                tvb, offset, 1, dbm,
                "RX SSI signal: %d dBm", dbm);
        }
    }
    else if (tx_power != 100)
    {
        col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", tx_power);
        if (tree) {
            proto_tree_add_int_format(tap_tree,
                hf_radiotap_txpower,
                tvb, offset, 1, tx_power,
                "Transmit power (TX): %d ", tx_power);
        }
    }
    offset += 2;

    vw_flags = tvb_get_letohs(tvb, offset);

    if (tree) {
        proto_tree_add_uint(tap_tree, hf_radiotap_vwf_txf,
            tvb, offset, 2, (vw_flags & VW_RADIOTAPF_TXF) != 0);
        proto_tree_add_uint(tap_tree, hf_radiotap_vwf_fcserr,
            tvb, offset, 2, (vw_flags & VW_RADIOTAPF_FCSERR) != 0);
        proto_tree_add_uint(tap_tree, hf_radiotap_vwf_dcrerr,
            tvb, offset, 2, (vw_flags & VW_RADIOTAPF_DCRERR) != 0);
        proto_tree_add_uint(tap_tree, hf_radiotap_vwf_retrerr,
            tvb, offset, 2, (vw_flags & VW_RADIOTAPF_RETRERR) != 0);
        proto_tree_add_uint(tap_tree, hf_radiotap_vwf_enctype,
            tvb, offset, 2, (vw_flags & VW_RADIOTAPF_ENCMSK) >>
                                    VW_RADIOTAPF_ENCSHIFT);
    }

    offset += 2;

    align_offset  = ALIGN_OFFSET(offset, 2);
    offset       += align_offset;

    vw_ht_length = tvb_get_letohs(tvb, offset);
    if ((tree) && (vw_ht_length != 0)) {
        proto_tree_add_uint_format(tap_tree, hf_radiotap_vw_ht_length,
            tvb, offset, 2,
            vw_ht_length,
            "HT length: %u (includes the sum of the pieces of the aggregate and their respective Start_Spacing"
            " + Delimiter + MPDU + Padding)",
            vw_ht_length);
    }
    offset += 2;

    align_offset  = ALIGN_OFFSET(offset, 2);
    offset       += align_offset;

    vw_info = tvb_get_letohs(tvb, offset);

    if (tree) {
        vwift = proto_tree_add_uint(tap_tree, hf_radiotap_vw_info,
                    tvb, offset, 2, vw_info);
        vw_infoFlags_tree = proto_item_add_subtree(vwift, ett_radiotap_info);

        if (tx_power == 0) {                   /* then it's an rx case */
            /*FPGA_VER_vVW510021 version decodes */

            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit8,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit9,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit10, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit11, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit12, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit13, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit14, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit15, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        } else {                                    /* it's a tx case */
            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx info decodes same*/
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit10,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit11,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit12,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit13,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit14,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit15,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
    }

    offset += 2;

    align_offset  = ALIGN_OFFSET(offset, 4);
    offset       += align_offset;

    vw_errors = tvb_get_letohl(tvb, offset);

    if (tree) {
        vweft = proto_tree_add_uint(tap_tree, hf_radiotap_vw_errors,
                    tvb, offset, 4, vw_errors);
        vw_errorFlags_tree = proto_item_add_subtree(vweft,
                    ett_radiotap_errors);

        /* build the individual subtrees for the various types of error flags */
        /* NOTE: as the upper 16 bits aren't used at the moment, we pretend that */
        /* the error flags field is only 16 bits (instead of 32) to save space */
        if (tx_power == 0) {
            /* then it's an rx case */

            /*FPGA_VER_vVW510021 version decodes */
            proto_tree_add_item(vw_errorFlags_tree,
                    hf_radiotap_vw_errors_rx_2_bit0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                    hf_radiotap_vw_errors_rx_2_bit1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                    hf_radiotap_vw_errors_rx_2_bit2, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            /* veriwave removed 8-2007, don't display reserved bit*/

            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit4,     tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit5,     tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit6,     tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit7,     tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit8,     tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit10,    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit11,    tvb, offset, 2, ENC_LITTLE_ENDIAN);

        } else {                                  /* it's a tx case */
            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx error decodes same*/

            proto_tree_add_item(vw_errorFlags_tree,
                    hf_radiotap_vw_errors_tx_bit1,   tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(vw_errorFlags_tree,
                    hf_radiotap_vw_errors_tx_bit5,   tvb, offset, 2, ENC_LITTLE_ENDIAN);

        }
    }

    /* This handles the case of an FCS existing at the end of the frame. */
    if (rflags & IEEE80211_RADIOTAP_F_FCS)
        pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
    else
        pinfo->pseudo_header->ieee_802_11.fcs_len = 0;

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset(tvb, length, -1, -1);

    /* If we had an in-header FCS, check it. */
    if (hdr_fcs_ti) {
        /* It would be very strange for the header to have an FCS for the
         * frame *and* the frame to have the FCS at the end, but it's possible, so
         * take that into account by using the FCS length recorded in pinfo. */

        /* Watch out for [erroneously] short frames */
        if (tvb_length(next_tvb) > (unsigned int) pinfo->pseudo_header->ieee_802_11.fcs_len) {
            guint32 sent_fcs = 0;
            calc_fcs = crc32_802_tvb(next_tvb,
                tvb_length(next_tvb) - pinfo->pseudo_header->ieee_802_11.fcs_len);

            /* By virtue of hdr_fcs_ti being set, we know that 'tree' is set,
             * so there's no need to check it here. */
            if (calc_fcs == sent_fcs) {
                proto_item_append_text(hdr_fcs_ti, " [correct]");
            }
            else {
                proto_item_append_text(hdr_fcs_ti, " [incorrect, should be 0x%08x]", calc_fcs);
                proto_tree_add_boolean(tap_tree, hf_radiotap_fcs_bad,
                    tvb, 0, 4, TRUE);
            }
        }
        else {
            proto_item_append_text(hdr_fcs_ti,
                " [cannot verify - not enough data]");
        }
    }

    /* dissect the 802.11 header next */
    call_dissector((rflags & IEEE80211_RADIOTAP_F_DATAPAD) ?
        ieee80211_datapad_handle : ieee80211_handle,
        next_tvb, pinfo, tree);
}

static float getHTrate( guint8 rate, guint8 rflags )
{
    int   mcs_index, ndbps;
    float symbol_tx_time, bitrate;

    /* Guard interval is the most significant bit.  Short GI if the bit is set */
    if ( rate & 0x80)
        symbol_tx_time = (float)3.6;
    else
        symbol_tx_time = (float)4.0;

    mcs_index = rate & IEEE80211_PLCP_RATE_MASK;

    if ( rflags & IEEE80211_RADIOTAP_F_40MHZ )
        ndbps = canonical_ndbps_40[ mcs_index - 8*(int)(mcs_index/8) ];
    else
        ndbps = canonical_ndbps_20[ mcs_index - 8*(int)(mcs_index/8) ];

    bitrate = ( ndbps * (((int)(mcs_index/8) + 1) )) / symbol_tx_time;

    return bitrate;
}

void proto_register_ixveriwave(void)
{
    /* value_strings for TX/RX and FCS error flags */
    static const value_string tx_rx_type[] = {
        { 0, "Received" },
        { 1, "Transmitted" },
        { 0, NULL },
    };

    static const value_string fcserr_type[] = {
        { 0, "Correct" },
        { 1, "Incorrect" },
        { 0, NULL },
    };

    static const true_false_string preamble_type = {
      "Short",
      "Long",
    };

    /* Added value_string for decrypt error flag */
    static const value_string decrypterr_type[] = {
    { 0, "Decrypt Succeeded" },
    { 1, "Decrypt Failed" },
    { 0, NULL },
    };

    /* Added value_string for excess retry error flag */
    static const value_string retryerr_type[] = {
    { 0, "Retry limit not reached" },
    { 1, "Excess retry abort" },
    { 0, NULL },
    };

    /* Added value_string for encryption type field */
    static const value_string encrypt_type[] = {
    { 0, "No encryption" },
    { 1, "WEP encryption" },
    { 2, "TKIP encryption" },
    { 3, "AES-CCMP encryption" },
    { 0, NULL },
    };

    static hf_register_info hf[] = {
        { &hf_ixveriwave_frame_length,
          { "Actual frame length", "ixveriwave.frame_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_msdu_length,
          { "MSDU length", "ixveriwave.msdu_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_vcid,
          { "Client ID", "ixveriwave.clientid",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_flowid,
          { "Flow ID", "ixveriwave.flowid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_seqnum,
          { "Sequence number", "ixveriwave.seqnum",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_mslatency,
          { "Msec latency", "ixveriwave.mslatency",
            FT_FLOAT, 0, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_latency,
          { "Latency", "ixveriwave.latency",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave,
          { "Signature (32 LSBs)", "ixveriwave.sig_ts",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_startt,
          { "Starting frame timestamp", "ixveriwave.startt",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_endt,
          { "Ending frame timestamp", "ixveriwave.endt",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_pktdur,
          { "Packet duration", "ixveriwave.pktdur",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_ifg,
          { "Inter-frame gap (usecs)", "ixveriwave.ifg",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vwf_txf,
          { "Frame direction", "ixveriwave.vwflags.txframe",
            FT_UINT32, BASE_DEC, VALS(tx_rx_type), 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vwf_fcserr,
          { "MAC FCS check", "ixveriwave.vwflags.fcserr",
            FT_UINT32, BASE_DEC, VALS(fcserr_type), 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_info,
          { "Info field", "ixveriwave.info",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_ixveriwave_vw_info_retryCount,
          { "Info field retry count", "ixveriwave.info",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

/* tx info decodes for VW510024 and 510012 */
/* we don't need to enumerate through these, basically for both,
   info is the retry count.  for 510024, the 15th bit indicates if
   the frame was impressed on the enet tx media with one or more octets having tx_en
   framing signal deasserted.  this is caused by software setting the drain all register bit.
*/
        { &hf_ixveriwave_vw_info_tx_bit15,
          { "Info bit 15-frame was impressed on the ent tx media with one or more octets having tx_en framing signal deasserted.", "ixveriwave.info.bit15",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },

        /* rx info decodes for fpga ver VW510024 */
        /*all are reserved*/

        /* rx info decodes for fpga ver VW510012 */
        { &hf_ixveriwave_vw_info_rx_1_bit8,
          { "Go no flow", "ixveriwave.info.bit8",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_ixveriwave_vw_info_rx_1_bit9,
          { "Go with flow", "ixveriwave.info.bit9",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

        { &hf_ixveriwave_vw_error,
          { "Errors", "ixveriwave.error",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        /* tx error decodes for VW510024 and previous versions */

        { &hf_ixveriwave_vw_error_tx_bit1,
          { "Packet FCS error", "ixveriwave.error.bit1",
            FT_BOOLEAN, 12, NULL, 0x0002, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_tx_bit5,
          { "IP checksum error", "ixveriwave.error.bit5",
            FT_BOOLEAN, 12, NULL, 0x0020, NULL, HFILL } },
        /*bit 6 is actually reserved in 500012, but i thought it would be okay to leave it here*/
        { &hf_ixveriwave_vw_error_tx_bit9,
          { "Underflow error", "ixveriwave.error.bit9",
            FT_BOOLEAN, 12, NULL, 0x0200, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_tx_bit10,
          { "Late collision error", "ixveriwave.error.bit10",
            FT_BOOLEAN, 12, NULL, 0x0400, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_tx_bit11,
          { "Excessive collisions error", "ixveriwave.error.bit11",
            FT_BOOLEAN, 12, NULL, 0x0800, NULL, HFILL } },
        /*all other bits are reserved */

        /* rx error decodes for fpga ver VW510012 and VW510024 */
        { &hf_ixveriwave_vw_error_rx_1_bit0,
          { "Alignment error", "ixveriwave.error.bit0",
            FT_BOOLEAN, 12, NULL, 0x0001, "error bit 0", HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit1,
          { "Packet FCS error", "ixveriwave.error.bit1",
            FT_BOOLEAN, 12, NULL, 0x0002, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit2,
          { "Bad magic byte signature.", "ixveriwave.error.bit2",
            FT_BOOLEAN, 12, NULL, 0x0004, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit3,
          { "Bad payload checksum.", "ixveriwave.error.bit3",
            FT_BOOLEAN, 12, NULL, 0x0008, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit4,
          { "Frame too long error", "ixveriwave.error.bit4",
            FT_BOOLEAN, 12, NULL, 0x0010, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit5,
          { "IP checksum error", "ixveriwave.error.bit5",
            FT_BOOLEAN, 12, NULL, 0x0020, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit6,
          { "TCP/ICMP/IGMP/UDP checksum error", "ixveriwave.error.bit6",
            FT_BOOLEAN, 12, NULL, 0x0040, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit7,
          { "ID mismatch(for fpga510012)", "ixveriwave.error.bit7",
            FT_BOOLEAN, 12, NULL, 0x0080, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit8,
          { "Length error", "ixveriwave.error.bit8",
            FT_BOOLEAN, 12, NULL, 0x0100, NULL, HFILL } },
        { &hf_ixveriwave_vw_error_rx_1_bit9,
          { "Underflow", "ixveriwave.error.bit9",
            FT_BOOLEAN, 12, NULL, 0x0200, NULL, HFILL } },
        { &hf_radiotap_vw_errors_tx_bit1,
          { "Packet FCS error", "ixveriwave.errors.bit1",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_radiotap_vw_errors_tx_bit5,
          { "IP checksum error", "ixveriwave.errors.bit5",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

        /* All other enumerations are reserved.*/

        { &hf_ixveriwave_vw_l4id,
          { "Layer 4 ID", "ixveriwave.layer4id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* Presense flags */
#define RADIOTAP_MASK_VW_FPGA_VERSION       (1 << VW_RADIOTAP_FPGA_VERSION)
#define RADIOTAP_MASK_VW_MCID               (1 << VW_RADIOTAP_MCID)
#define RADIOTAP_MASK_VW_ERRORS             (1 << VW_RADIOTAP_ERRORS)
#define RADIOTAP_MASK_VW_INFO               (1 << VW_RADIOTAP_INFO)
#define RADIOTAP_MASK_VW_MSDU_LENGTH        (1 << VW_RADIOTAP_MSDU_LENGTH)
#define RADIOTAP_MASK_VW_HT_LENGTH          (1 << VW_RADIOTAP_HT_LENGTH)
#define RADIOTAP_MASK_VW_FLOWID             (1 << VW_RADIOTAP_FLOWID)
#define RADIOTAP_MASK_VW_SEQNUM             (1 << VW_RADIOTAP_SEQNUM)
#define RADIOTAP_MASK_VW_LATENCY            (1 << VW_RADIOTAP_LATENCY)
#define RADIOTAP_MASK_VW_SIG_TS             (1 << VW_RADIOTAP_SIG_TS)
#define RADIOTAP_MASK_VW_STARTT             (1 << VW_RADIOTAP_STARTT)
#define RADIOTAP_MASK_VW_ENDT               (1 << VW_RADIOTAP_ENDT)
#define RADIOTAP_MASK_VW_PKTDUR             (1 << VW_RADIOTAP_PKTDUR)
#define RADIOTAP_MASK_VW_IFG                (1 << VW_RADIOTAP_IFG)
        /* end veriwave addition*/

        { &hf_radiotap_datarate,
          { "Data rate", "ixveriwave.datarate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Speed this frame was sent/received at", HFILL } },

        /* Boolean 'present.flags' flags */
        { &hf_radiotap_flags,
          { "Flags", "ixveriwave.flags",
            FT_UINT16, BASE_HEX, NULL,  0x0, NULL, HFILL } },

        { &hf_radiotap_flags_cfp,
          { "CFP", "ixveriwave.flags.cfp",
            FT_BOOLEAN, 12, NULL,  IEEE80211_RADIOTAP_F_CFP,
            "Sent/Received during CFP", HFILL } },

        { &hf_radiotap_flags_preamble,
          { "Preamble", "ixveriwave.flags.preamble",
            FT_BOOLEAN, 12, TFS(&preamble_type),  IEEE80211_RADIOTAP_F_SHORTPRE,
            "Sent/Received with short preamble", HFILL } },

        { &hf_radiotap_flags_wep,
          { "WEP", "ixveriwave.flags.wep",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_WEP,
            "Sent/Received with WEP encryption", HFILL } },

        { &hf_radiotap_flags_frag,
          { "Fragmentation", "ixveriwave.flags.frag",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_FRAG,
            "Sent/Received with fragmentation", HFILL } },

        { &hf_radiotap_flags_fcs,
          { "FCS at end", "ixveriwave.flags.fcs",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_FCS,
            "Frame includes FCS at end", HFILL } },

        { &hf_radiotap_flags_datapad,
          { "Data Pad", "ixveriwave.flags.datapad",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_DATAPAD,
            "Frame has padding between 802.11 header and payload", HFILL } },

        { &hf_radiotap_flags_ht,
          { "HT frame", "ixveriwave.flags.ht",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_HT, NULL, HFILL } },

        { &hf_radiotap_flags_40mhz,
          { "40 MHz channel bandwidth", "ixveriwave.flags.40mhz",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_40MHZ, NULL, HFILL } },

        { &hf_radiotap_flags_shortgi,
          { "Short guard interval", "ixveriwave.flags.shortgi",
            FT_BOOLEAN, 12, NULL, IEEE80211_RADIOTAP_F_SHORTGI, NULL, HFILL } },

        { &hf_radiotap_dbm_antsignal,
          { "SSI Signal (dBm)", "ixveriwave.dbm_antsignal",
            FT_INT32, BASE_DEC, NULL, 0x0,
            "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

        { &hf_radiotap_txpower,
          { "Transmit power", "ixveriwave.txpower",
            FT_INT32, BASE_DEC, NULL, 0x0,
            "Transmit power in decibels per one milliwatt (dBm)", HFILL } },

        /* Boolean 'present' flags */
        /* VeriWave-specific flags */
        { &hf_radiotap_vwf_txf,
          { "Frame direction", "ixveriwave.vwflags.txframe",
            FT_UINT32, BASE_DEC, VALS(tx_rx_type), 0x0, NULL, HFILL } },

        { &hf_radiotap_vwf_fcserr,
          { "MAC FCS check", "ixveriwave.vwflags.fcserr",
            FT_UINT32, BASE_DEC, VALS(fcserr_type), 0x0, NULL, HFILL } },

        { &hf_radiotap_vwf_dcrerr,
          { "Decryption error", "ixveriwave.vwflags.decrypterr",
            FT_UINT32, BASE_DEC, VALS(decrypterr_type), 0x0, NULL, HFILL } },

        { &hf_radiotap_vwf_retrerr,
          { "TX retry limit", "ixveriwave.vwflags.retryerr",
            FT_UINT32, BASE_DEC, VALS(retryerr_type), 0x0, NULL, HFILL } },

        { &hf_radiotap_vwf_enctype,
          { "Encryption type", "ixveriwave.vwflags.encrypt",
            FT_UINT32, BASE_DEC, VALS(encrypt_type), 0x0, NULL, HFILL } },

        /* start VeriWave-specific radiotap header elements 6-2007 */
        { &hf_radiotap_vw_ht_length,
          { "Total IP length (incl all pieces of an aggregate)", "ixveriwave.ht_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_radiotap_vw_errors,
          { "Errors", "ixveriwave.errors",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* rx error decodes for fpga ver VW510006 */
        { &hf_radiotap_vw_errors_rx_1_bit0,
          { "L1 error", "ixveriwave.errors.bit0",
            FT_BOOLEAN, 16, NULL, 0x0001, "error bit 0", HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit1,
          { "Packet FCS error", "ixveriwave.errors.bit1",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit2,
          { "Bad magic byte signature.", "ixveriwave.errors.bit2",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit3,
          { "Bad payload checksum.", "ixveriwave.errors.bit3",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit4,
          { "Duplicate MPDU", "ixveriwave.errors.bit4",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit5,
          { "IP checksum error", "ixveriwave.errors.bit5",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit6,
          { "TCP/ICMP/IGMP/UDP checksum error", "ixveriwave.errors.bit6",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit7,
          { "Reserved", "ixveriwave.errors.bit7",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit8,
          { "RX WEP IVC / TKIP/CCMP MIC miscompare", "ixveriwave.errors.bit8",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit9,
          { "RX TKIP / CCMP TSC SEQERR", "ixveriwave.errors.bit9",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit10,
          { "RX crypto short", "ixveriwave.errors.bit10",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit11,
          { "RX EXTIV fault A", "ixveriwave.errors.bit11",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit12,
          { "RX EXTIV fault B", "ixveriwave.errors.bit12",
            FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit13,
          { "RX protected fault A", "ixveriwave.errors.bit13",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit14,
          { "RX protected fault B", "ixveriwave.errors.bit14",
            FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_1_bit15,
          { "Reserved", "ixveriwave.errors.bit15",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },
        /* All other enumerations are reserved.*/

        /* rx error decodes for fpga ver VW510021 */
        { &hf_radiotap_vw_errors_rx_2_bit0,
          { "CRC16 or parity error", "ixveriwave.errors.bit0",
            FT_BOOLEAN, 16, NULL, 0x0001, "error bit 0", HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit1,
          { "Non-supported rate or service field", "ixveriwave.errors.bit1",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit2,
          { "Short frame error.  Frame is shorter than length.", "ixveriwave.errors.bit2",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit4,
          { "FCS_Error", "ixveriwave.errors.bit4",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit5,
          { "L2 de-aggregation error", "ixveriwave.errors.bit5",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit6,
          { "Duplicate MPDU", "ixveriwave.errors.bit6",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit7,
          { "Bad_Sig:  Bad flow magic number (includes bad flow crc16)", "ixveriwave.errors.bit7",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit8,
          { "Bad flow payload checksum", "ixveriwave.errors.bit8",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit10,
          { "Bad IP checksum error", "ixveriwave.errors.bit10",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

        { &hf_radiotap_vw_errors_rx_2_bit11,
          { "L4(TCP/ICMP/IGMP/UDP) checksum error", "ixveriwave.errors.bit11",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

        { &hf_radiotap_vw_info,
          { "Info field", "ixveriwave.info",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* tx info decodes for VW510021 and previous versions */
        { &hf_radiotap_vw_info_tx_bit10,
          { "MPDU of A-MPDU", "ixveriwave.info.bit10",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

        { &hf_radiotap_vw_info_tx_bit11,
          { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

        { &hf_radiotap_vw_info_tx_bit12,
          { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
            FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL } },

        { &hf_radiotap_vw_info_tx_bit13,
          { "MSDU of A-MSDU", "ixveriwave.info.bit13",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL } },

        { &hf_radiotap_vw_info_tx_bit14,
          { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
            FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },

        { &hf_radiotap_vw_info_tx_bit15,
          { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },
        /*v510006 uses bits */

        /* rx info decodes for fpga ver VW510021 */
        { &hf_radiotap_vw_info_rx_2_bit8,
          { "ACK withheld from frame", "ixveriwave.info.bit8",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit9,
          { "Sent CTS to self before data", "ixveriwave.info.bit9",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit10,
          { "MPDU of an A-MPDU", "ixveriwave.info.bit10",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit11,
          { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit12,
          { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
            FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit13,
          { "MSDU of A-MSDU", "ixveriwave.info.bit13",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit14,
          { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
            FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },

        { &hf_radiotap_vw_info_rx_2_bit15,
          { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_commontap,
        &ett_commontap_times,
        &ett_ethernettap_info,
        &ett_ethernettap_error,
        &ett_ethernettap_flags,
        &ett_radiotap_flags,
        &ett_radiotap_info,
        &ett_radiotap_times,
        &ett_radiotap_errors
    };

    proto_ixveriwave = proto_register_protocol("ixveriwave", "ixveriwave", "ixveriwave");
    proto_register_field_array(proto_ixveriwave, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("ixveriwave", dissect_ixveriwave, proto_ixveriwave);
}

void proto_reg_handoff_ixveriwave(void)
{
    dissector_handle_t ixveriwave_handle;

    /* handle for ethertype dissector */
    ethernet_handle          = find_dissector("eth_withoutfcs");
    /* handle for 802.11 dissector */
    ieee80211_handle         = find_dissector("wlan");
    ieee80211_datapad_handle = find_dissector("wlan_datapad");

    ixveriwave_handle = create_dissector_handle(dissect_ixveriwave, proto_ixveriwave);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_IXVERIWAVE, ixveriwave_handle);
}

