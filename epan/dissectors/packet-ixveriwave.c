/* packet-ixveriwave.c
 * Routines for calling the right protocol for the ethertype.
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

#include <epan/packet.h>
#include <epan/proto_data.h>

#include <wiretap/wtap.h>

void proto_register_ixveriwave(void);
void proto_reg_handoff_ixveriwave(void);

static void ethernettap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree);
static void wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree, guint16 vw_msdu_length);

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

#define CHAN_CCK                            0x00020 /* CCK channel */
#define CHAN_OFDM                           0x00040 /* OFDM channel */

#define FLAGS_SHORTPRE                      0x0002  /* sent/received
                                                     * with short
                                                     * preamble
                                                     */
#define FLAGS_WEP                           0x0004  /* sent/received
                                                     * with WEP encryption
                                                     */
#define FLAGS_FCS                           0x0010  /* frame includes FCS */
#define FLAGS_CHAN_HT                       0x0040  /* HT mode */
#define FLAGS_CHAN_VHT                      0x0080  /* VHT mode */
#define FLAGS_CHAN_SHORTGI                  0x0100  /* short guard interval */
#define FLAGS_CHAN_40MHZ                    0x0200  /* 40 Mhz channel bandwidth */
#define FLAGS_CHAN_80MHZ                    0x0400  /* 80 Mhz channel bandwidth */
#define FLAGS_CHAN_160MHZ                   0x0800  /* 160 Mhz channel bandwidth */

#define INFO_MPDU_OF_A_MPDU                 0x0400  /* MPDU of A-MPDU */
#define INFO_FIRST_MPDU_OF_A_MPDU           0x0800  /* first MPDU of A-MPDU */
#define INFO_LAST_MPDU_OF_A_MPDU            0x1000  /* last MPDU of A-MPDU */
#define INFO_MSDU_OF_A_MSDU                 0x2000  /* MSDU of A-MSDU */
#define INFO_FIRST_MSDU_OF_A_MSDU           0x4000  /* first MSDU of A-MSDU */
#define INFO_LAST_MSDU_OF_A_MSDU            0x8000  /* last MSDU of A-MSDU */

#define PLCP_TYPE_LEGACY        0x00        /* pre-HT (11 legacy/11b/11a/11g) */
#define PLCP_TYPE_MIXED         0x01        /* HT, mixed (11n) */
#define PLCP_TYPE_GREENFIELD    0x02        /* HT, greenfield (11n) */
#define PLCP_TYPE_VHT_MIXED     0x03        /* VHT (11ac) */

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

static dissector_handle_t ieee80211_radio_handle;

/* Ethernet fields */
static int hf_ixveriwave_vw_info = -1;
static int hf_ixveriwave_vw_error = -1;

static int hf_ixveriwave_vwf_txf = -1;
static int hf_ixveriwave_vwf_fcserr = -1;

static int hf_ixveriwave_vw_l4id = -1;

/*veriwave note:  i know the below method seems clunky, but
they didn't have a item_format at the time to dynamically add the appropriate decode text*/
static int hf_ixveriwave_vw_info_retryCount = -1;

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
static int hf_radiotap_mcsindex = -1;
static int hf_radiotap_plcptype = -1;
static int hf_radiotap_nss = -1;
static int hf_radiotap_dbm_antsignal = -1;
static int hf_radiotap_dbm_antb = -1;
static int hf_radiotap_dbm_antc = -1;
static int hf_radiotap_dbm_antd = -1;

static int hf_radiotap_flags_preamble = -1;
static int hf_radiotap_flags_wep = -1;
static int hf_radiotap_flags_fcs_present = -1;
static int hf_radiotap_flags_ht = -1;
static int hf_radiotap_flags_vht = -1;
static int hf_radiotap_flags_40mhz = -1;
static int hf_radiotap_flags_80mhz = -1;
static int hf_radiotap_flags_shortgi = -1;

/* start VeriWave specific 6-2007*/
static int hf_radiotap_vw_errors = -1;
static int hf_radiotap_vw_info = -1;
static int hf_radiotap_vw_ht_length = -1;
static int hf_radiotap_vht_grp_id = -1;
static int hf_radiotap_vht_su_nsts = -1;
static int hf_radiotap_vht_su_partial_aid = -1;
static int hf_radiotap_vht_u0_nsts = -1;
static int hf_radiotap_vht_u1_nsts = -1;
static int hf_radiotap_vht_u2_nsts = -1;
static int hf_radiotap_vht_u3_nsts = -1;
static int hf_radiotap_vht_beamformed = -1;
static int hf_radiotap_vht_user_pos = -1;
static int hf_radiotap_vht_mu_mimo_flg = -1;
static int hf_radiotap_vht_u0_coding_type = -1;
static int hf_radiotap_vht_u1_coding_type = -1;
static int hf_radiotap_vht_u2_coding_type = -1;
static int hf_radiotap_vht_u3_coding_type = -1;

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

static dissector_handle_t ixveriwave_handle;

#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

static int
dissect_ixveriwave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *common_tree                 = NULL;
    proto_item *ti                          = NULL;
    proto_item *vw_times_ti                 = NULL;
    proto_tree *vw_times_tree               = NULL;
    int         offset, time_tree_offset    = 0;
    guint16     version, length;
    guint       length_remaining;
    guint64     vw_startt=0, vw_endt=0;
    guint32     true_length;
    guint32     vw_latency, vw_pktdur, vw_flowid;
    guint16     vw_vcid, vw_msdu_length=0, vw_seqnum;
    tvbuff_t   *next_tvb;
    ifg_info   *p_ifg_info;

    offset = 0;
    version = tvb_get_letohs(tvb, offset);

    length = tvb_get_letohs(tvb, offset + COMMON_LENGTH_OFFSET);

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "%s", version ? "ETH" : "WLAN");
    col_clear(pinfo->cinfo, COL_INFO);

    true_length = pinfo->fd->pkt_len - length - tvb_get_letohs(tvb, offset + length) + 4;   /* add FCS length into captured length */

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Capture, Length %u",
                 version ? "IxVeriWave Ethernet Tap" : "IxVeriWave Radio Tap", length);

    /* Dissect the packet */
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ixveriwave,
                                            tvb, 0, length, "%s Header, Length %u",
                                            version ? "IxVeriWave Ethernet Tap" : "IxVeriWave Radio Tap", length);

        common_tree = proto_item_add_subtree(ti, ett_commontap);

        proto_tree_add_uint(common_tree, hf_ixveriwave_frame_length,
                            tvb, 4, 2, true_length);
    }

    length_remaining = length;

    offset              +=4;
    length_remaining    -=4;

    if (length_remaining >= 2) {

        vw_msdu_length = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_msdu_length,
            tvb, offset, 2, vw_msdu_length);
        }

        offset              +=2;
        length_remaining    -=2;
    }

    /*extract flow id , 4bytes*/
    if (length_remaining >= 4) {
        vw_flowid = tvb_get_letohl(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_flowid,
                                tvb, offset, 4, vw_flowid);
        }

        offset              +=4;
        length_remaining    -=4;
    }

    /*extract client id, 2bytes*/
    if (length_remaining >= 2) {
        vw_vcid = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_vcid,
                                tvb, offset, 2, vw_vcid);
        }

        offset              +=2;
        length_remaining    -=2;
    }

    /*extract sequence number , 2bytes*/
    if (length_remaining >= 2) {

        vw_seqnum = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(common_tree, hf_ixveriwave_vw_seqnum,
                                tvb, offset, 2, vw_seqnum);
        }

        offset              +=2;
        length_remaining    -=2;
    }

    /*extract latency, 4 bytes*/
    if (length_remaining >= 4) {
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

        offset              +=4;
        length_remaining    -=4;
    }



    /*extract signature timestamp, 4 bytes (32 LSBs only, nsec)*/
    if (length_remaining >= 4) {
        /* TODO: what should this fieldname be? */
        proto_tree_add_item(vw_times_tree, hf_ixveriwave,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
        time_tree_offset    = offset;
        offset              +=4;
        length_remaining    -=4;
    }

    /*extract frame start timestamp, 8 bytes (nsec)*/
    if (length_remaining >= 8) {
        vw_startt = tvb_get_letoh64(tvb, offset);

        proto_tree_add_uint64_format_value(vw_times_tree, hf_ixveriwave_vw_startt,
                tvb, offset, 8, vw_startt,
                "%" G_GINT64_MODIFIER "u usec", vw_startt);

        offset              +=8;
        length_remaining    -=8;
    }

    /* extract frame end timestamp, 8 bytes (nsec)*/
    if (length_remaining >= 8) {
        vw_endt = tvb_get_letoh64(tvb, offset);

        proto_tree_add_uint64_format_value(vw_times_tree, hf_ixveriwave_vw_endt,
                tvb, offset, 8, vw_endt,
                "%" G_GINT64_MODIFIER "u usec", vw_endt);

        offset              +=8;
        length_remaining    -=8;
    }
    /*extract frame duration , 4 bytes*/
    if (length_remaining >= 4) {
        vw_pktdur = tvb_get_letohl(tvb, offset);

        if (vw_endt >= vw_startt) {
            /* Add to root summary */
            if (version == ETHERNET_PORT) {
                proto_item_append_text(vw_times_ti, " (Frame duration=%u nsecs)", vw_pktdur);
                proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                    tvb, offset-16, 16, vw_pktdur,
                                    "Frame duration: %u nsec", vw_pktdur);
            }
            else {
                proto_item_append_text(vw_times_ti, " (Frame duration=%u usecs)", vw_pktdur);
                proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                    tvb, offset-16, 16, vw_pktdur,
                                    "Frame duration: %u usec", vw_pktdur);
            }
        }
        else {
            proto_tree_add_uint_format(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                        tvb, offset, 0, vw_pktdur,
                                        "Frame duration: N/A");

            /* Add to root summary */
            proto_item_append_text(vw_times_ti, " (Frame duration=N/A)");
        }

        offset              +=4;
    }

    if (vw_times_ti) {
        proto_item_set_len(vw_times_ti, offset-time_tree_offset);
    }

    /* Calculate the IFG */

    /* Check for an existing ifg value associated with the frame */
    p_ifg_info = (ifg_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    if (!p_ifg_info)
    {
        /* allocate the space */
        p_ifg_info = wmem_new0(wmem_file_scope(), struct ifg_info);

        /* Doesn't exist, so we need to calculate the value */
        if (previous_frame_data.previous_frame_num !=0 && (pinfo->num - previous_frame_data.previous_frame_num == 1))
        {
            p_ifg_info->ifg = (guint32)(vw_startt - previous_frame_data.previous_end_time);
            p_ifg_info->previous_end_time = previous_frame_data.previous_end_time;
        }
        else
        {
            p_ifg_info->ifg                 = 0;
            p_ifg_info->previous_end_time   = 0;
        }

        /* Store current data into the static structure */
        previous_frame_data.previous_end_time = vw_endt;
        previous_frame_data.previous_frame_num = pinfo->num;

        /* Record the current start time */
        p_ifg_info->current_start_time = vw_startt;

        /* Add the ifg onto the frame */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0, p_ifg_info);
    }

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset_remaining(tvb, length);

    /* dissect the ethernet or wlan header next */
    if (version == ETHERNET_PORT)
        ethernettap_dissect(next_tvb, pinfo, tree, common_tree);
    else
        wlantap_dissect(next_tvb, pinfo, tree, common_tree, vw_msdu_length);
    return tvb_captured_length(tvb);
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
    int         offset;
    tvbuff_t   *next_tvb;
    guint       length, length_remaining;
    guint16     vw_flags, vw_info;
    guint16     vw_l4id;
    guint32     vw_error;
    gint32      vwf_txf, vwf_fcserr;
    ifg_info   *p_ifg_info;
    proto_item *ti;

    vwf_txf = 0;

    offset = 0;

    /* First add the IFG information */
    p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    if (tap_tree) {
        ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg,
                                 tvb, offset, 0, p_ifg_info->ifg);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    length = tvb_get_letohs(tvb, offset);
    length_remaining = length;

    offset += 2;
    length_remaining -= 2;

    /* extract flags (currently use only TX/RX and FCS error flag) */
    if (length >= 2) {
        vw_flags = tvb_get_letohs(tvb, offset);
        vwf_txf = ((vw_flags & ETHERNETTAP_VWF_TXF) == 0) ? 0 : 1;
        vwf_fcserr = ((vw_flags & ETHERNETTAP_VWF_FCSERR) == 0) ? 0 : 1;

        if (tap_tree) {
            proto_tree_add_uint(tap_tree, hf_ixveriwave_vwf_txf,
                tvb, 0, 0, vwf_txf);
            proto_tree_add_uint(tap_tree, hf_ixveriwave_vwf_fcserr,
                tvb, 0, 0, vwf_fcserr);
        }

        offset += 2;
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

        offset              +=2;
        length_remaining    -=2;
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
        } /*end of if (tap_tree) */

        offset              +=4;
        length_remaining    -=4;
    }
    /*extract l4id , 4bytes*/
    if (length_remaining >= 4) {
        vw_l4id = tvb_get_letohl(tvb, offset);
        if (tap_tree) {
            proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_l4id,
            tvb, offset, 4, vw_l4id);
        }
        offset              +=4;
        length_remaining    -=4;
    }

    /*extract pad, 4bytes*/
    if (length_remaining >= 4) {
        tvb_get_letohl(tvb, offset);   /* throw away pad */
    }

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset_remaining(tvb, length);

    /* dissect the ethernet header next */
    call_dissector(ethernet_handle, next_tvb, pinfo, tree);
}

static void
wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree, guint16 vw_msdu_length)
{
    proto_tree *ft, *flags_tree         = NULL;
    int         align_offset, offset;
    tvbuff_t   *next_tvb;
    guint       length;
    gint8       dbm;
    guint8      plcp_type;
    guint8      mcs_index;
    guint8      nss;
    guint8      vht_ndp_flag,vht_mu_mimo_flg,vht_coding_type,vht_u0_coding_type,vht_u1_coding_type,vht_u2_coding_type;
    float       phyRate;
    guint       i;

    proto_tree *vweft, *vw_errorFlags_tree = NULL, *vwift,*vw_infoFlags_tree = NULL;
    guint16     vw_flags, vw_chanflags, vw_info, vw_ht_length, vht_su_partial_id, vw_rflags;
    guint32     vw_errors;
    guint8      vht_grp_id1, vht_grp_id2, vht_grp_id, vht_su_nsts,vht_beamformed,vht_user_pos,vht_u0_nsts,vht_u1_nsts,vht_u2_nsts,vht_u3_nsts,vht_su_partial_id1,vht_su_partial_id2;

    ifg_info   *p_ifg_info;
    proto_item *ti;
    struct ieee_802_11_phdr phdr;

    /* We don't have any 802.11 metadata yet. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.fcs_len = -1;
    phdr.decrypted = FALSE;
    phdr.datapad = FALSE;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;

    /* First add the IFG information, need to grab the info bit field here */
    vw_info = tvb_get_letohs(tvb, 20);
    p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    if (tap_tree) {
        if ((vw_info & INFO_MPDU_OF_A_MPDU) && !(vw_info & INFO_FIRST_MPDU_OF_A_MPDU))  /* If the packet is part of an A-MPDU but not the first MPDU */
            ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, 0);
        else
            ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, p_ifg_info->ifg);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    offset      = 0;

    /* Length of the metadata header */
    length = tvb_get_letohs(tvb, offset);
    offset      += 2;

    vw_rflags = tvb_get_letohs(tvb, offset);
    if (vw_rflags & FLAGS_FCS)
        phdr.fcs_len = 4;
    else
        phdr.fcs_len = 0;
    if (tap_tree) {
        ft = proto_tree_add_uint(tap_tree, hf_radiotap_flags, tvb, offset, 2, vw_rflags);
        flags_tree = proto_item_add_subtree(ft, ett_radiotap_flags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_preamble,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_wep,
            tvb, offset, 2, vw_rflags);
        proto_tree_add_boolean(flags_tree, hf_radiotap_flags_fcs_present,
            tvb, offset, 2, vw_rflags);
        if ( vw_rflags & FLAGS_CHAN_HT ) {
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_ht,
            tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_40mhz,
            tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_shortgi,
            tvb, offset, 2, vw_rflags);
        }
        if ( vw_rflags & FLAGS_CHAN_VHT ) {
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_vht,
            tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_shortgi,
            tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_40mhz,
            tvb, offset, 2, vw_rflags);
            proto_tree_add_boolean(flags_tree, hf_radiotap_flags_80mhz,
            tvb, offset, 2, vw_rflags);
        }
    }
    offset      += 2;

    vw_chanflags = tvb_get_letohs(tvb, offset);
    offset      += 2;
    phyRate = (float)tvb_get_letohs(tvb, offset) / 10;
    offset      += 2;
    plcp_type = tvb_get_guint8(tvb,offset) & 0x03;
    vht_ndp_flag = tvb_get_guint8(tvb,offset) & 0x80;
    offset++;

    mcs_index = tvb_get_guint8(tvb, offset);
    offset++;
    nss = tvb_get_guint8(tvb, offset);
    offset++;

    if ((vw_rflags & FLAGS_CHAN_HT) || (vw_rflags & FLAGS_CHAN_VHT)) {
        if (vw_rflags & FLAGS_CHAN_VHT) {
            phdr.phy = PHDR_802_11_PHY_11AC;
            phdr.phy_info.info_11ac.has_short_gi = TRUE;
            phdr.phy_info.info_11ac.short_gi = ((vw_rflags & FLAGS_CHAN_SHORTGI) != 0);
            /*
             * XXX - this probably has only one user, so only one MCS index
             * and only one NSS.
             */
            phdr.phy_info.info_11ac.nss[0] = nss;
            phdr.phy_info.info_11ac.mcs[0] = mcs_index;
            for (i = 1; i < 4; i++)
                phdr.phy_info.info_11ac.nss[i] = 0;
        } else {
            /*
             * XXX - where's the number of extension spatial streams?
             * The code in wiretap/vwr.c doesn't seem to provide it.
             */
            phdr.phy = PHDR_802_11_PHY_11N;
            phdr.phy_info.info_11n.has_mcs_index = TRUE;
            phdr.phy_info.info_11n.mcs_index = mcs_index;

            phdr.phy_info.info_11n.has_short_gi = TRUE;
            phdr.phy_info.info_11n.short_gi = ((vw_rflags & FLAGS_CHAN_SHORTGI) != 0);

            phdr.phy_info.info_11n.has_greenfield = TRUE;
            phdr.phy_info.info_11n.greenfield = (plcp_type == PLCP_TYPE_GREENFIELD);
        }
        if (tap_tree) {
            proto_tree_add_item(tap_tree, hf_radiotap_mcsindex,
                                tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(tap_tree, hf_radiotap_nss,
                                tvb, offset - 1, 1, ENC_BIG_ENDIAN);

            proto_tree_add_uint_format_value(tap_tree, hf_radiotap_datarate,
                                       tvb, offset - 5, 2, tvb_get_letohs(tvb, offset-5),
                                       "%.1f (MCS %d)", phyRate, mcs_index);
        }
    } else {
        /*
         * XXX - CHAN_OFDM could be 11a or 11g.  Unfortunately, we don't
         * have the frequency, or anything else, to distinguish between
         * them.
         */
        if (vw_chanflags & CHAN_CCK) {
            phdr.phy = PHDR_802_11_PHY_11B;
        }
        phdr.has_data_rate = TRUE;
        phdr.data_rate = tvb_get_letohs(tvb, offset-5) / 5;
        if (tap_tree) {
            proto_tree_add_uint_format_value(tap_tree, hf_radiotap_datarate,
            tvb, offset - 5, 2, tvb_get_letohs(tvb, offset-5),
            "%.1f Mb/s", phyRate);
        }
    }
    col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", phyRate);

    dbm = (gint8) tvb_get_guint8(tvb, offset);
    phdr.has_signal_dbm = TRUE;
    phdr.signal_dbm = dbm;
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
    if (tap_tree) {
        proto_tree_add_int_format_value(tap_tree,
                                  hf_radiotap_dbm_antsignal,
                                  tvb, offset, 1, dbm,
                                  "%d dBm", dbm);
    }

    offset++;
    dbm = (gint8) tvb_get_guint8(tvb, offset);
    if (tap_tree && dbm != 100) {
        proto_tree_add_int_format_value(tap_tree,
                                  hf_radiotap_dbm_antb,
                                  tvb, offset, 1, dbm,
                                  "%d dBm", dbm);
    }
    offset++;
    dbm = (gint8) tvb_get_guint8(tvb, offset);
    if (tap_tree && dbm != 100) {
        proto_tree_add_int_format_value(tap_tree,
                                  hf_radiotap_dbm_antc,
                                  tvb, offset, 1, dbm,
                                  "%d dBm", dbm);
    }
    offset++;
    dbm = (gint8) tvb_get_guint8(tvb, offset);
    if (tap_tree && dbm != 100) {
        proto_tree_add_int_format_value(tap_tree,
                                  hf_radiotap_dbm_antd,
                                  tvb, offset, 1, dbm,
                                  "%d dBm", dbm);
    }
    offset+=2;

    vw_flags = tvb_get_letohs(tvb, offset);

    if (tap_tree) {
      if ((vw_rflags & FLAGS_CHAN_HT) || (vw_rflags & FLAGS_CHAN_VHT)) {
        if (plcp_type == PLCP_TYPE_VHT_MIXED) {
          if (!(vw_flags & VW_RADIOTAPF_TXF) && (vht_ndp_flag == 0x80)) {
            /*** VHT-NDP rx frame and ndp_flag is set***/
            proto_tree_add_uint_format(tap_tree, hf_radiotap_plcptype,
                                       tvb, offset-3, 1, plcp_type,
                                       "VHT-NDP");
          } else {
            /*** VHT-NDP transmitted frame ***/
            if (vw_msdu_length == 4) { /*** Transmit frame and msdu_length = 4***/
              proto_tree_add_uint_format(tap_tree, hf_radiotap_plcptype,
                                         tvb, offset-3, 1, plcp_type,
                                         "VHT-NDP");
            }
          }
        }
      }

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

    offset      += 2;

    align_offset = ALIGN_OFFSET(offset, 2);
    offset += align_offset;

    vw_ht_length = tvb_get_letohs(tvb, offset);
    if ((tree) && (vw_ht_length != 0)) {
        proto_tree_add_uint_format(tap_tree, hf_radiotap_vw_ht_length,
            tvb, offset, 2, vw_ht_length, "HT length: %u (includes the sum of the pieces of the aggregate and their respective Start_Spacing + Delimiter + MPDU + Padding)",
            vw_ht_length);
    }
    offset      += 2;

    align_offset = ALIGN_OFFSET(offset, 2);
    offset += align_offset;

    /* vw_info grabbed in the beginning of the dissector */

    if (tap_tree) {
        vwift = proto_tree_add_uint(tap_tree, hf_radiotap_vw_info,
        tvb, offset, 2, vw_info);
        vw_infoFlags_tree = proto_item_add_subtree(vwift, ett_radiotap_info);

        if (!(vw_flags & VW_RADIOTAPF_TXF)) {                   /* then it's an rx case */
            /*FPGA_VER_vVW510021 version decodes */

            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit8, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_rx_2_bit9, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
                hf_radiotap_vw_info_tx_bit10, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit11, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit12, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit13, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit14, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree,
                hf_radiotap_vw_info_tx_bit15, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
    }
    offset      += 2;

    vw_errors = tvb_get_letohl(tvb, offset);
    if (tap_tree) {
        vweft = proto_tree_add_uint(tap_tree, hf_radiotap_vw_errors,
                                    tvb, offset, 4, vw_errors);
        vw_errorFlags_tree = proto_item_add_subtree(vweft, ett_radiotap_errors);

        /* build the individual subtrees for the various types of error flags */
        /* NOTE: as the upper 16 bits aren't used at the moment, we pretend that */
        /* the error flags field is only 16 bits (instead of 32) to save space */
        if (!(vw_flags & VW_RADIOTAPF_TXF)) {
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
                hf_radiotap_vw_errors_rx_2_bit4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit6, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit7, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit8, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_bit10, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_bit11, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        } else {                                  /* it's a tx case */
            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx error decodes same*/

            proto_tree_add_item(vw_errorFlags_tree,
                                hf_radiotap_vw_errors_tx_bit1, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(vw_errorFlags_tree,
                                hf_radiotap_vw_errors_tx_bit5, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        }
    }
    offset      += 4;

    /*
     * XXX - this appears to be the NDP flag for received frames and 0
     * for transmitted frames.  The PLCP header follows it.
     */

    /*** POPULATE THE AMSDU VHT MIXED MODE CONTAINER FORMAT ***/
    if ((vw_rflags & FLAGS_CHAN_VHT) && vw_ht_length != 0) {
        /*** Extract SU/MU MIMO flag from RX L1 Info ***/
        vht_user_pos = tvb_get_guint8(tvb, offset);
        vht_mu_mimo_flg = (vht_user_pos & 0x08) >> 3;

        if (vht_mu_mimo_flg == 1) {
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_mu_mimo_flg,
                tvb, offset, 1, vht_mu_mimo_flg, "VHT MU MIMO: %u ",vht_mu_mimo_flg);

            /*** extract user Position in case of mu-mimo ***/
            vht_user_pos = (vht_user_pos & 0x03);
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_user_pos,
                tvb, offset, 1, vht_user_pos, "VHT User Pos: %u ",vht_user_pos);

        } else {
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_mu_mimo_flg,
                tvb, offset, 1, vht_mu_mimo_flg, "VHT SU MIMO: %u ",vht_mu_mimo_flg);
        }
        offset += 1; /*** skip the RX L1 Info byte ****/

        /*
         * XXX - no, 3 bytes are for the L-SIG.
         */
        offset += 3; /** 3 bytes are for HT length ***/

        /*
         * Beginning of VHT-SIG-A1, 24 bits.
         * XXX - get STBC from the 0x08 bit of the first byte
         * and BW from the 0x03 bits?
         */
        /* vht_grp_id = tvb_get_letohs(tvb, offset); */
        vht_grp_id1 = tvb_get_guint8(tvb, offset);
        vht_grp_id2 = tvb_get_guint8(tvb, offset+1);
        vht_grp_id = ((vht_grp_id1 &0xF0) >> 4) + ((vht_grp_id2 &0x03) << 4);
        phdr.phy_info.info_11ac.has_group_id = TRUE;
        phdr.phy_info.info_11ac.group_id = vht_grp_id;
        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_grp_id,
            tvb, offset, 2, vht_grp_id, "VHT Group Id: %u ",vht_grp_id);

        if ((vht_grp_id == 0) || (vht_grp_id == 63)) /*** SU VHT type*/
        {
            vht_su_nsts = tvb_get_guint8(tvb, offset+1);
            vht_su_nsts = ((vht_su_nsts & 0x1c) >> 2);
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_su_nsts,
                tvb, offset, 2, vht_su_nsts, "VHT NSTS: %u ",vht_su_nsts);

            offset += 1; /* Skip to second byte of VHT-SIG-A1 */
            vht_su_partial_id1 = tvb_get_guint8(tvb,offset);
            vht_su_partial_id2 = tvb_get_guint8(tvb,offset+1);
            vht_su_partial_id = ((vht_su_partial_id1 &0xE0) >> 5) + ((vht_su_partial_id2 &0x3f) << 3);
            phdr.phy_info.info_11ac.has_partial_aid = TRUE;
            phdr.phy_info.info_11ac.partial_aid = vht_su_partial_id;
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_su_partial_aid,
                tvb, offset, 2, vht_su_partial_id, "VHT PARTIAL AID: %u ",vht_su_partial_id);
        }
        else {
            /*** The below is MU VHT type**/
            vht_u0_nsts = tvb_get_guint8(tvb, offset+1);
            vht_u0_nsts = ((vht_u0_nsts & 0x1c) >> 2);
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_nsts,
                tvb, offset, 2, vht_u0_nsts, "VHT U0 NSTS: %u ",vht_u0_nsts);

            vht_u1_nsts = tvb_get_guint8(tvb, offset+1);
            vht_u1_nsts = ((vht_u1_nsts & 0xe0) >> 5);
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_nsts,
                tvb, offset, 2, vht_u1_nsts, "VHT U1 NSTS: %u ",vht_u1_nsts);

            offset += 1; /* Skip to second byte of VHT-SIG-A1 */
            vht_u2_nsts = tvb_get_guint8(tvb, offset+1);
            vht_u2_nsts = (vht_u2_nsts & 0x07);
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_nsts,
                tvb, offset, 2, vht_u2_nsts, "VHT U2 NSTS: %u ",vht_u2_nsts);

            vht_u3_nsts = tvb_get_guint8(tvb, offset+1);
            vht_u3_nsts = ((vht_u3_nsts & 0x38) >> 3);
            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u3_nsts,
                tvb, offset, 2, vht_u3_nsts, "VHT U3 NSTS: %u ",vht_u3_nsts);
        }

        /*
         * Skip past the other 2 bytes of VHT-SIG-A1.
         *
         * XXX - extract TXOP_PS_NOT_ALLOWED from the third byte of
         * the VHT-SIG-A1 structure?
         */
        offset += 2;

        /*
         * Beginning of VHT-SIG-A2, 24 bits.
         *
         * XXX - extract Short GI NSYM Disambiguation from the first
         * byte?
         */
        /*** extract LDPC or BCC coding *****/
        vht_coding_type = tvb_get_guint8(tvb, offset);
        vht_u0_coding_type = ((vht_coding_type & 0x04) >> 2);
        if ((vht_grp_id == 0) || (vht_grp_id == 63)) /*** SU VHT type*/
        {
            if (vht_u0_coding_type == 0) {
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                   tvb, offset, 1, vht_u0_coding_type, "VHT BCC Coding : %u ",vht_u0_coding_type);
            }
            else {
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                   tvb, offset, 1, vht_u0_coding_type, "VHT LDPC Coding : %u ",vht_u0_coding_type);
            }
            /*** extract SU-MIMO VHT MCS ******/
            /*****
                vht_su_mcs = tvb_get_guint8(tvb, offset);
                vht_su_mcs = ((vht_su_mcs & 0xF0) >> 4);
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_su_mcs,
                    tvb, offset, 1, vht_su_mcs, "VHT SU MCS : %u ",vht_su_mcs);
            *******/
        } else {
            /*** it is MU MIMO type BCC coding ****/
            /*** extract U0 Coding ***/
            if (vht_u0_nsts) {
                if (vht_u0_coding_type == 0) {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                    tvb, offset, 1, vht_u0_coding_type, "VHT U0 BCC Coding : %u ",vht_u0_coding_type);
                } else {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                    tvb, offset, 1, vht_u0_coding_type, "VHT U0 LDPC Coding : %u ",vht_u0_coding_type);
                }
            } else {
                /*** reserved **/
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                tvb, offset, 1, vht_u0_coding_type, "VHT U0 Reserved Coding : %u ",vht_u0_coding_type);
            }
            /*** extract U1 Coding type***/
            vht_u1_coding_type = ((vht_coding_type & 0x10) >> 4);
            if (vht_u1_nsts) {
                if (vht_u1_coding_type == 0) {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_coding_type,
                        tvb, offset, 1, vht_u1_coding_type, "VHT U1 BCC Coding : %u ",vht_u1_coding_type);
                } else {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_coding_type,
                        tvb, offset, 1, vht_u1_coding_type, "VHT U1 LDPC Coding : %u ",vht_u1_coding_type);
                }
            } else {
                /*** Reserved **/
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_coding_type,
                    tvb, offset, 1, vht_u1_coding_type, "VHT U1 Reserved Coding : %u ",vht_u1_coding_type);
            }

            /*** extract U2 Coding type***/
            vht_u2_coding_type = ((vht_coding_type & 0x20) >> 5);
            if (vht_u2_nsts) {
                if (vht_u2_coding_type == 0) {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_coding_type,
                    tvb, offset, 1, vht_u2_coding_type, "VHT U2 BCC Coding : %u ",vht_u2_coding_type);
                } else {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_coding_type,
                    tvb, offset, 1, vht_u2_coding_type, "VHT U2 LDPC Coding : %u ",vht_u2_coding_type);
                }
            }else {
               /**** Reserved *******/
               proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_coding_type,
               tvb, offset, 1, vht_u2_coding_type, "VHT U2 Reserved Coding : %u ",vht_u2_coding_type);
            }

            /*** extract U3 Coding type***/
            if (vht_u3_nsts == 1) {
                guint vht_u3_coding_type;

                vht_u3_coding_type = ((vht_coding_type & 0x40) >> 6);
                if (vht_u3_coding_type == 0) {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u3_coding_type,
                    tvb, offset, 1, vht_u3_coding_type, "VHT U3 BCC Coding : %u ",vht_u3_coding_type);
                } else {
                    proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u3_coding_type,
                    tvb, offset, 1, vht_u3_coding_type, "VHT U3 LDPC Coding : %u ",vht_u3_coding_type);
                }
            }
        }

        /*** decode Beamformed bit ****/
        offset = offset + 1;
        vht_beamformed = tvb_get_guint8(tvb, offset);
        vht_beamformed = (vht_beamformed & 0x01);
        phdr.phy_info.info_11ac.has_beamformed = TRUE;
        phdr.phy_info.info_11ac.beamformed = vht_beamformed;
        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_beamformed,
            tvb, offset, 1, vht_beamformed, "VHT Beamformed: %u ",vht_beamformed);
    }

    /*
     * Skip the 16 bytes of PLCP + 1 byte of L1InfoC(UserPos) inserted
     * by the Veriwave reader code in libwiretap.
     */
    length = length + 17;

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset_remaining(tvb, length);

    /* dissect the 802.11 packet next */
    call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
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
        { "Frame start timestamp", "ixveriwave.startt",
        FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_endt,
        { "Frame end timestamp", "ixveriwave.endt",
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

    { &hf_radiotap_datarate,
        { "Data rate", "ixveriwave.datarate",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Speed this frame was sent/received at", HFILL } },

    { &hf_radiotap_plcptype,
        { "VHT_NDP", "ixveriwave.vhtmixedmode",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_mcsindex,
        { "MCS index", "ixveriwave.mcs",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_nss,
        { "Number of spatial streams", "ixveriwave.nss",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /* Boolean 'present.flags' flags */
    { &hf_radiotap_flags,
        { "Flags", "ixveriwave.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_flags_preamble,
        { "Preamble", "ixveriwave.flags.preamble",
        FT_BOOLEAN, 12, TFS(&preamble_type),  FLAGS_SHORTPRE,
        "Sent/Received with short preamble", HFILL } },

    { &hf_radiotap_flags_wep,
        { "WEP", "ixveriwave.flags.wep",
        FT_BOOLEAN, 12, NULL, FLAGS_WEP,
        "Sent/Received with WEP encryption", HFILL } },

    { &hf_radiotap_flags_fcs_present,
        { "FCS present", "ixveriwave.flags.fcs_present",
        FT_BOOLEAN, 12, NULL, FLAGS_FCS,
        "FCS present in frame", HFILL } },

    { &hf_radiotap_flags_ht,
        { "HT frame", "ixveriwave.flags.ht",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_HT, NULL, HFILL } },

    { &hf_radiotap_flags_vht,
        { "VHT frame", "ixveriwave.flags.vht",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_VHT, NULL, HFILL } },

    { &hf_radiotap_flags_40mhz,
        { "40 MHz channel bandwidth", "ixveriwave.flags.40mhz",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_40MHZ, NULL, HFILL } },

    { &hf_radiotap_flags_80mhz,
        { "80 MHz channel bandwidth", "ixveriwave.flags.80mhz",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_80MHZ, NULL, HFILL } },

    { &hf_radiotap_flags_shortgi,
        { "Short guard interval", "ixveriwave.flags.shortgi",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_SHORTGI, NULL, HFILL } },

    { &hf_radiotap_dbm_antsignal,
        { "SSI Signal", "ixveriwave.dbm_antsignal",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_antb,
        { "SSI Signal for Antenna B", "ixveriwave.dbm_antb",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_antc,
        { "SSI Signal for Antenna C", "ixveriwave.dbm_antc",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_antd,
        { "SSI Signal for Antenna D", "ixveriwave.dbm_antd",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

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

    { &hf_radiotap_vht_grp_id,
        { "VHT GRP ID})", "ixveriwave.VHT_GRPID",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_su_nsts,
        { "VHT SU NSTS})", "ixveriwave.VHT_SU_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_su_partial_aid,
        { "VHT SU Partial ID})", "ixveriwave.VHT_SU_PARTIAL_AID",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u0_nsts,
        { "VHT U0 NSTS})", "ixveriwave.VHT_U0_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u1_nsts,
        { "VHT U1 NSTS})", "ixveriwave.VHT_U1_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u2_nsts,
        { "VHT U2 NSTS})", "ixveriwave.VHT_U2_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u3_nsts,
        { "VHT U3 NSTS})", "ixveriwave.VHT_U3_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_beamformed,
        { "VHT Beamformed", "ixveriwave.VHT_BEAMFORMED",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_user_pos,
        { "VHT User Pos", "ixveriwave.VHT_user_pos",
         FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_mu_mimo_flg,
        { "VHT MU SU", "ixveriwave.VHT_mu_mimo_flg",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u0_coding_type,
        { "VHT CODING", "ixveriwave.VHT_u0_CODING_TYPE",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u1_coding_type,
        { "VHT CODING", "ixveriwave.VHT_u1_CODING_TYPE",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u2_coding_type,
        { "VHT CODING", "ixveriwave.VHT_u2_CODING_TYPE",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u3_coding_type,
        { "VHT CODING", "ixveriwave.VHT_u3_CODING_TYPE",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vw_errors,
        { "Errors", "ixveriwave.errors",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

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
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },
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
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },
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

    ixveriwave_handle = register_dissector("ixveriwave", dissect_ixveriwave, proto_ixveriwave);
}

void proto_reg_handoff_ixveriwave(void)
{
    /* handle for ethertype dissector */
    ethernet_handle          = find_dissector_add_dependency("eth_withoutfcs", proto_ixveriwave);
    /* handle for 802.11+radio information dissector */
    ieee80211_radio_handle   = find_dissector_add_dependency("wlan_radio", proto_ixveriwave);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_IXVERIWAVE, ixveriwave_handle);
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
