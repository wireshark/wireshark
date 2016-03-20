/*
 * packet-ppi.c
 * Routines for PPI Packet Header dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * Dustin Johnson - Dustin@Dustinj.us, Dustin.Johnson@cacetech.com
 *     May 7, 2008 - Added 'Aggregation Extension' and '802.3 Extension'
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/exceptions.h>
#include <epan/ptvcursor.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <wsutil/frequency-utils.h>
#include <wsutil/pint.h>
#include <wsutil/str_util.h>

/*
 * Per-Packet Information (PPI) header.
 * See the PPI Packet Header documentation at http://www.cacetech.com/documents
 * for details.
 */

/*
 * PPI headers have the following format:
 *
 * ,---------------------------------------------------------.
 * | PPH | PFH 1 | Field data 1 | PFH 2 | Field data 2 | ... |
 * `---------------------------------------------------------'
 *
 * The PPH struct has the following format:
 *
 * typedef struct ppi_packetheader {
 *     guint8  pph_version;     // Version.  Currently 0
 *     guint8  pph_flags;       // Flags.
 *     guint16 pph_len; // Length of entire message, including this header and TLV payload.
 *     guint32 pph_dlt; // libpcap Data Link Type of the captured packet data.
 * } ppi_packetheader_t;
 *
 * The PFH struct has the following format:
 *
 * typedef struct ppi_fieldheader {
 *     guint16 pfh_type;        // Type
 *     guint16 pfh_datalen;     // Length of data
 * } ppi_fieldheader_t;
 *
 * Anyone looking to add their own PPI dissector would probably do well to imitate the GPS
 * ones separation into a distinct file.  Here is a step by step guide:
 * 1) add the number you received to the enum ppi_field_type declaration.
 * 2) Add a value string for your number into vs_ppi_field_type
 * 3) declare a dissector handle by the ppi_gps_handle, and initialize it inside proto_reg_handoff
 * 4) add  case inside dissect_ppi to call your new handle.
 * 5) Write your parser, and get it loaded.
 * Following these steps will result in less churn inside the ppi proper parser, and avoid namespace issues.
 */


#define PPI_PADDED (1 << 0)

#define PPI_V0_HEADER_LEN 8
#define PPI_80211_COMMON_LEN 20
#define PPI_80211N_MAC_LEN 12
#define PPI_80211N_MAC_PHY_OFF 9
#define PPI_80211N_MAC_PHY_LEN 48
#define PPI_AGGREGATION_EXTENSION_LEN 4
#define PPI_8023_EXTENSION_LEN 8

#define PPI_FLAG_ALIGN 0x01
#define IS_PPI_FLAG_ALIGN(x) ((x) & PPI_FLAG_ALIGN)

#define DOT11_FLAG_HAVE_FCS     0x0001
#define DOT11_FLAG_TSF_TIMER_MS 0x0002
#define DOT11_FLAG_FCS_INVALID  0x0004
#define DOT11_FLAG_PHY_ERROR    0x0008

#define DOT11N_FLAG_GREENFIELD      0x0001
#define DOT11N_FLAG_HT40            0x0002
#define DOT11N_FLAG_SHORT_GI        0x0004
#define DOT11N_FLAG_DUPLICATE_RX    0x0008
#define DOT11N_FLAG_IS_AGGREGATE    0x0010
#define DOT11N_FLAG_MORE_AGGREGATES 0x0020
#define DOT11N_FLAG_AGG_CRC_ERROR   0x0040

#define DOT11N_IS_AGGREGATE(flags)      (flags & DOT11N_FLAG_IS_AGGREGATE)
#define DOT11N_MORE_AGGREGATES(flags)   ( \
    (flags & DOT11N_FLAG_MORE_AGGREGATES) && \
    !(flags & DOT11N_FLAG_AGG_CRC_ERROR))
#define AGGREGATE_MAX 65535
#define AMPDU_MAX 16383

/* XXX - Start - Copied from packet-radiotap.c */
/* Channel flags. */
#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel. */
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#define IEEE80211_CHAN_DYN      0x0400  /* Dynamic CCK-OFDM channel */
#define IEEE80211_CHAN_GFSK     0x0800  /* GFSK channel (FHSS PHY) */

#define	IEEE80211_CHAN_ALL \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_GFSK | \
         IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_ALLTURBO \
	(IEEE80211_CHAN_ALL | IEEE80211_CHAN_TURBO)

/*
 * Useful combinations of channel characteristics.
 */
#define IEEE80211_CHAN_FHSS \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_DSSS \
	(IEEE80211_CHAN_2GHZ)
#define IEEE80211_CHAN_A \
        (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_B \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define IEEE80211_CHAN_PUREG \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_108A \
	(IEEE80211_CHAN_A | IEEE80211_CHAN_TURBO)
#define IEEE80211_CHAN_108G \
        (IEEE80211_CHAN_G | IEEE80211_CHAN_TURBO)
#define IEEE80211_CHAN_108PUREG \
        (IEEE80211_CHAN_PUREG | IEEE80211_CHAN_TURBO)
/* XXX - End - Copied from packet-radiotap.c */

void proto_register_ppi(void);
void proto_reg_handoff_ppi(void);

typedef enum {
    /* 0 - 29999: Public types */
    PPI_80211_COMMON          =  2,
    PPI_80211N_MAC            =  3,
    PPI_80211N_MAC_PHY        =  4,
    PPI_SPECTRUM_MAP          =  5,
    PPI_PROCESS_INFO          =  6,
    PPI_CAPTURE_INFO          =  7,
    PPI_AGGREGATION_EXTENSION =  8,
    PPI_8023_EXTENSION        =  9,
    /* 11 - 29999: RESERVED */

    /* 30000 - 65535: Private types */
    INTEL_CORP_PRIVATE           = 30000,
    MOHAMED_THAGA_PRIVATE        = 30001,
    PPI_GPS_INFO                 = 30002, /* 30002 - 30005 described in PPI-GEOLOCATION specifcation */
    PPI_VECTOR_INFO              = 30003, /* currently available in draft from. jellch@harris.com */
    PPI_SENSOR_INFO              = 30004,
    PPI_ANTENNA_INFO             = 30005,
    FNET_PRIVATE                 = 0xC017,
    CACE_PRIVATE                 = 0xCACE
    /* All others RESERVED.  Contact the WinPcap team for an assignment */
} ppi_field_type;

/* Protocol */
static int proto_ppi = -1;

/* Packet header */
static int hf_ppi_head_version = -1;
static int hf_ppi_head_flags = -1;
static int hf_ppi_head_flag_alignment = -1;
static int hf_ppi_head_flag_reserved = -1;
static int hf_ppi_head_len = -1;
static int hf_ppi_head_dlt = -1;

/* Field header */
static int hf_ppi_field_type = -1;
static int hf_ppi_field_len = -1;

/* 802.11 Common */
static int hf_80211_common_tsft = -1;
static int hf_80211_common_flags = -1;
static int hf_80211_common_flags_fcs = -1;
static int hf_80211_common_flags_tsft = -1;
static int hf_80211_common_flags_fcs_valid = -1;
static int hf_80211_common_flags_phy_err = -1;
static int hf_80211_common_rate = -1;
static int hf_80211_common_chan_freq = -1;
static int hf_80211_common_chan_flags = -1;

static int hf_80211_common_chan_flags_turbo = -1;
static int hf_80211_common_chan_flags_cck = -1;
static int hf_80211_common_chan_flags_ofdm = -1;
static int hf_80211_common_chan_flags_2ghz = -1;
static int hf_80211_common_chan_flags_5ghz = -1;
static int hf_80211_common_chan_flags_passive = -1;
static int hf_80211_common_chan_flags_dynamic = -1;
static int hf_80211_common_chan_flags_gfsk = -1;

static int hf_80211_common_fhss_hopset = -1;
static int hf_80211_common_fhss_pattern = -1;
static int hf_80211_common_dbm_antsignal = -1;
static int hf_80211_common_dbm_antnoise = -1;

/* 802.11n MAC */
static int hf_80211n_mac_flags = -1;
static int hf_80211n_mac_flags_greenfield = -1;
static int hf_80211n_mac_flags_ht20_40 = -1;
static int hf_80211n_mac_flags_rx_guard_interval = -1;
static int hf_80211n_mac_flags_duplicate_rx = -1;
static int hf_80211n_mac_flags_more_aggregates = -1;
static int hf_80211n_mac_flags_aggregate = -1;
static int hf_80211n_mac_flags_delimiter_crc_after = -1;
static int hf_80211n_mac_ampdu_id = -1;
static int hf_80211n_mac_num_delimiters = -1;
static int hf_80211n_mac_reserved = -1;

/* 802.11n MAC+PHY */
static int hf_80211n_mac_phy_mcs = -1;
static int hf_80211n_mac_phy_num_streams = -1;
static int hf_80211n_mac_phy_rssi_combined = -1;
static int hf_80211n_mac_phy_rssi_ant0_ctl = -1;
static int hf_80211n_mac_phy_rssi_ant1_ctl = -1;
static int hf_80211n_mac_phy_rssi_ant2_ctl = -1;
static int hf_80211n_mac_phy_rssi_ant3_ctl = -1;
static int hf_80211n_mac_phy_rssi_ant0_ext = -1;
static int hf_80211n_mac_phy_rssi_ant1_ext = -1;
static int hf_80211n_mac_phy_rssi_ant2_ext = -1;
static int hf_80211n_mac_phy_rssi_ant3_ext = -1;
static int hf_80211n_mac_phy_ext_chan_freq = -1;
static int hf_80211n_mac_phy_ext_chan_flags = -1;
static int hf_80211n_mac_phy_ext_chan_flags_turbo = -1;
static int hf_80211n_mac_phy_ext_chan_flags_cck = -1;
static int hf_80211n_mac_phy_ext_chan_flags_ofdm = -1;
static int hf_80211n_mac_phy_ext_chan_flags_2ghz = -1;
static int hf_80211n_mac_phy_ext_chan_flags_5ghz = -1;
static int hf_80211n_mac_phy_ext_chan_flags_passive = -1;
static int hf_80211n_mac_phy_ext_chan_flags_dynamic = -1;
static int hf_80211n_mac_phy_ext_chan_flags_gfsk = -1;
static int hf_80211n_mac_phy_dbm_ant0signal = -1;
static int hf_80211n_mac_phy_dbm_ant0noise = -1;
static int hf_80211n_mac_phy_dbm_ant1signal = -1;
static int hf_80211n_mac_phy_dbm_ant1noise = -1;
static int hf_80211n_mac_phy_dbm_ant2signal = -1;
static int hf_80211n_mac_phy_dbm_ant2noise = -1;
static int hf_80211n_mac_phy_dbm_ant3signal = -1;
static int hf_80211n_mac_phy_dbm_ant3noise = -1;
static int hf_80211n_mac_phy_evm0 = -1;
static int hf_80211n_mac_phy_evm1 = -1;
static int hf_80211n_mac_phy_evm2 = -1;
static int hf_80211n_mac_phy_evm3 = -1;

/* 802.11n-Extensions A-MPDU fragments */
static int hf_ampdu_reassembled_in = -1;
/* static int hf_ampdu_segments = -1; */
static int hf_ampdu_segment = -1;
static int hf_ampdu_count  = -1;

/* Spectrum-Map */
static int hf_spectrum_map = -1;

/* Process-Info */
static int hf_process_info = -1;

/* Capture-Info */
static int hf_capture_info = -1;

/* Aggregation Extension */
static int hf_aggregation_extension_interface_id = -1;

/* 802.3 Extension */
static int hf_8023_extension_flags = -1;
static int hf_8023_extension_flags_fcs_present = -1;
static int hf_8023_extension_errors = -1;
static int hf_8023_extension_errors_fcs = -1;
static int hf_8023_extension_errors_sequence = -1;
static int hf_8023_extension_errors_symbol = -1;
static int hf_8023_extension_errors_data = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ppi_antenna = -1;
static int hf_ppi_harris = -1;
static int hf_ppi_reserved = -1;
static int hf_ppi_vector = -1;
static int hf_ppi_fnet = -1;
static int hf_ppi_gps = -1;

static gint ett_ppi_pph = -1;
static gint ett_ppi_flags = -1;
static gint ett_dot11_common = -1;
static gint ett_dot11_common_flags = -1;
static gint ett_dot11_common_channel_flags = -1;
static gint ett_dot11n_mac = -1;
static gint ett_dot11n_mac_flags = -1;
static gint ett_dot11n_mac_phy = -1;
static gint ett_dot11n_mac_phy_ext_channel_flags = -1;
static gint ett_ampdu_segments = -1;
static gint ett_ampdu = -1;
static gint ett_ampdu_segment  = -1;
static gint ett_aggregation_extension = -1;
static gint ett_8023_extension = -1;
static gint ett_8023_extension_flags = -1;
static gint ett_8023_extension_errors = -1;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_ppi_invalid_length = EI_INIT;

static dissector_handle_t ppi_handle;

static dissector_handle_t ieee80211_radio_handle;
static dissector_handle_t pcap_pktdata_handle;
static dissector_handle_t ppi_gps_handle, ppi_vector_handle, ppi_sensor_handle, ppi_antenna_handle;
static dissector_handle_t ppi_fnet_handle;

static const true_false_string tfs_ppi_head_flag_alignment = { "32-bit aligned", "Not aligned" };
static const true_false_string tfs_tsft_ms = { "milliseconds", "microseconds" };
static const true_false_string tfs_ht20_40 = { "HT40", "HT20" };
static const true_false_string tfs_phy_error = { "PHY error", "No errors"};

static const value_string vs_ppi_field_type[] = {
    {PPI_80211_COMMON,          "802.11-Common"},
    {PPI_80211N_MAC,            "802.11n MAC Extensions"},
    {PPI_80211N_MAC_PHY,        "802.11n MAC+PHY Extensions"},
    {PPI_SPECTRUM_MAP,          "Spectrum-Map"},
    {PPI_PROCESS_INFO,          "Process-Info"},
    {PPI_CAPTURE_INFO,          "Capture-Info"},
    {PPI_AGGREGATION_EXTENSION, "Aggregation Extension"},
    {PPI_8023_EXTENSION,        "802.3 Extension"},

    {INTEL_CORP_PRIVATE,        "Intel Corporation (private)"},
    {MOHAMED_THAGA_PRIVATE,     "Mohamed Thaga (private)"},
    {PPI_GPS_INFO,              "GPS Tagging"},
    {PPI_VECTOR_INFO,           "Vector Tagging"},
    {PPI_SENSOR_INFO,           "Sensor tagging"},
    {PPI_ANTENNA_INFO,          "Antenna Tagging"},
    {FNET_PRIVATE,              "FlukeNetworks (private)"},
    {CACE_PRIVATE,              "CACE Technologies (private)"},
    {0, NULL}
};

/* Table for A-MPDU reassembly */
static reassembly_table ampdu_reassembly_table;

/* Reassemble A-MPDUs? */
static gboolean ppi_ampdu_reassemble = TRUE;


static gboolean
capture_ppi(const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    guint32  dlt;
    guint    ppi_len;

    ppi_len = pletoh16(pd+2);
    if(ppi_len < PPI_V0_HEADER_LEN || !BYTES_ARE_IN_FRAME(0, len, ppi_len))
        return FALSE;

    dlt = pletoh32(pd+4);

    return try_capture_dissector("ppi", dlt, pd, ppi_len, len, cpinfo, pseudo_header);
}

static void
ptvcursor_add_invalid_check(ptvcursor_t *csr, int hf, gint len, guint64 invalid_val) {
    proto_item *ti;
    guint64     val = invalid_val;

    switch (len) {
        case 8:
            val = tvb_get_letoh64(ptvcursor_tvbuff(csr),
                ptvcursor_current_offset(csr));
            break;
        case 4:
            val = tvb_get_letohl(ptvcursor_tvbuff(csr),
                ptvcursor_current_offset(csr));
            break;
        case 2:
            val = tvb_get_letohs(ptvcursor_tvbuff(csr),
                ptvcursor_current_offset(csr));
            break;
        case 1:
            val = tvb_get_guint8(ptvcursor_tvbuff(csr),
                ptvcursor_current_offset(csr));
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    ti = ptvcursor_add(csr, hf, len, ENC_LITTLE_ENDIAN);
    if (val == invalid_val)
        proto_item_append_text(ti, " [invalid]");
}

static void
add_ppi_field_header(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    ptvcursor_t *csr;

    csr = ptvcursor_new(tree, tvb, *offset);
    ptvcursor_add(csr, hf_ppi_field_type, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_ppi_field_len, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_free(csr);
    *offset=ptvcursor_current_offset(csr);
}

/* XXX - The main dissection function in the 802.11 dissector has the same name. */
static void
dissect_80211_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int data_len, struct ieee_802_11_phdr *phdr)
{
    proto_tree  *ftree;
    proto_item  *ti;
    ptvcursor_t *csr;
    guint64      tsft_raw;
    guint        rate_raw;
    guint        rate_kbps;
    guint32      common_flags;
    guint16      common_frequency;
    guint16      chan_flags;
    gint8        dbm_value;
    gchar       *chan_str;

    ftree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_dot11_common, NULL, "802.11-Common");
    add_ppi_field_header(tvb, ftree, &offset);
    data_len -= 4; /* Subtract field header length */

    if (data_len != PPI_80211_COMMON_LEN) {
        proto_tree_add_expert_format(ftree, pinfo, &ei_ppi_invalid_length, tvb, offset, data_len, "Invalid length: %u", data_len);
        return;
    }

    common_flags = tvb_get_letohs(tvb, offset + 8);
    if (common_flags & DOT11_FLAG_HAVE_FCS)
        phdr->fcs_len = 4;
    else
        phdr->fcs_len = 0;

    csr = ptvcursor_new(ftree, tvb, offset);

    tsft_raw = tvb_get_letoh64(tvb, offset);
    if (tsft_raw != 0) {
        phdr->has_tsf_timestamp = TRUE;
        if (common_flags & DOT11_FLAG_TSF_TIMER_MS)
            phdr->tsf_timestamp = tsft_raw * 1000;
        else
            phdr->tsf_timestamp = tsft_raw;
    }

    ptvcursor_add_invalid_check(csr, hf_80211_common_tsft, 8, 0);

    ptvcursor_add_with_subtree(csr, hf_80211_common_flags, 2, ENC_LITTLE_ENDIAN,
                               ett_dot11_common_flags);
    ptvcursor_add_no_advance(csr, hf_80211_common_flags_fcs, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_flags_tsft, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_flags_fcs_valid, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_80211_common_flags_phy_err, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(csr);

    rate_raw = tvb_get_letohs(tvb, ptvcursor_current_offset(csr));
    if (rate_raw != 0) {
        phdr->has_data_rate = TRUE;
        phdr->data_rate = rate_raw;
    }
    rate_kbps = rate_raw * 500;
    ti = proto_tree_add_uint_format(ftree, hf_80211_common_rate, tvb,
                                    ptvcursor_current_offset(csr), 2, rate_kbps, "Rate: %.1f Mbps",
                                    rate_kbps / 1000.0);
    if (rate_kbps == 0)
        proto_item_append_text(ti, " [invalid]");
    col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f Mbps", rate_kbps / 1000.0);
    ptvcursor_advance(csr, 2);

    common_frequency = tvb_get_letohs(ptvcursor_tvbuff(csr), ptvcursor_current_offset(csr));
    if (common_frequency != 0) {
        gint calc_channel;

        phdr->has_frequency = TRUE;
        phdr->frequency = common_frequency;
        calc_channel = ieee80211_mhz_to_chan(common_frequency);
        if (calc_channel != -1) {
            phdr->has_channel = TRUE;
            phdr->channel = calc_channel;
        }
    }
    chan_str = ieee80211_mhz_to_str(common_frequency);
    proto_tree_add_uint_format_value(ptvcursor_tree(csr), hf_80211_common_chan_freq, ptvcursor_tvbuff(csr),
                               ptvcursor_current_offset(csr), 2, common_frequency, "%s", chan_str);
    col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%s", chan_str);
    g_free(chan_str);
    ptvcursor_advance(csr, 2);

    memset(&phdr->phy_info, 0, sizeof(phdr->phy_info));
    chan_flags = tvb_get_letohs(ptvcursor_tvbuff(csr), ptvcursor_current_offset(csr));
    switch (chan_flags & IEEE80211_CHAN_ALLTURBO) {

    case IEEE80211_CHAN_FHSS:
        phdr->phy = PHDR_802_11_PHY_11_FHSS;
        break;

    case IEEE80211_CHAN_DSSS:
        phdr->phy = PHDR_802_11_PHY_11_DSSS;
        break;

    case IEEE80211_CHAN_A:
        phdr->phy = PHDR_802_11_PHY_11A;
        phdr->phy_info.info_11a.has_turbo_type = TRUE;
        phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_NORMAL;
        break;

    case IEEE80211_CHAN_B:
        phdr->phy = PHDR_802_11_PHY_11B;
        break;

    case IEEE80211_CHAN_PUREG:
        phdr->phy = PHDR_802_11_PHY_11G;
        phdr->phy_info.info_11g.has_mode = TRUE;
        phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
        break;

    case IEEE80211_CHAN_G:
        phdr->phy = PHDR_802_11_PHY_11G;
        phdr->phy_info.info_11g.has_mode = TRUE;
        phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
        break;

    case IEEE80211_CHAN_108A:
        phdr->phy = PHDR_802_11_PHY_11A;
        phdr->phy_info.info_11a.has_turbo_type = TRUE;
        /* We assume non-STURBO is dynamic turbo */
        phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO;
        break;

    case IEEE80211_CHAN_108PUREG:
        phdr->phy = PHDR_802_11_PHY_11G;
        phdr->phy_info.info_11g.has_mode = TRUE;
        phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_SUPER_G;
        break;
    }
    ptvcursor_add_with_subtree(csr, hf_80211_common_chan_flags, 2, ENC_LITTLE_ENDIAN,
                               ett_dot11_common_channel_flags);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_turbo, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_cck, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_ofdm, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_2ghz, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_5ghz, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_passive, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211_common_chan_flags_dynamic, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_80211_common_chan_flags_gfsk, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(csr);


    if (phdr->phy == PHDR_802_11_PHY_11_FHSS) {
        phdr->phy_info.info_11_fhss.has_hop_set = TRUE;
        phdr->phy_info.info_11_fhss.hop_set = tvb_get_guint8(ptvcursor_tvbuff(csr), ptvcursor_current_offset(csr));
    }
    ptvcursor_add(csr, hf_80211_common_fhss_hopset, 1, ENC_LITTLE_ENDIAN);
    if (phdr->phy == PHDR_802_11_PHY_11_FHSS) {
        phdr->phy_info.info_11_fhss.has_hop_pattern = TRUE;
        phdr->phy_info.info_11_fhss.hop_pattern = tvb_get_guint8(ptvcursor_tvbuff(csr), ptvcursor_current_offset(csr));
    }
    ptvcursor_add(csr, hf_80211_common_fhss_pattern, 1, ENC_LITTLE_ENDIAN);

    dbm_value = (gint8) tvb_get_guint8(tvb, ptvcursor_current_offset(csr));
    if (dbm_value != -128 && dbm_value != 0) {
        /*
         * XXX - the spec says -128 is invalid, presumably meaning "use
         * -128 if you don't have the signal strength", but some captures
         * have 0 for noise, presumably meaning it's incorrectly being
         * used for "don't have it", so we check for it as well.
         */
        col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm_value);
        phdr->has_signal_dbm = TRUE;
        phdr->signal_dbm = dbm_value;
    }
    ptvcursor_add_invalid_check(csr, hf_80211_common_dbm_antsignal, 1, 0x80); /* -128 */

    dbm_value = (gint8) tvb_get_guint8(tvb, ptvcursor_current_offset(csr));
    if (dbm_value != -128 && dbm_value != 0) {
        /*
         * XXX - the spec says -128 is invalid, presumably meaning "use
         * -128 if you don't have the noise level", but some captures
         * have 0, presumably meaning it's incorrectly being used for
         * "don't have it", so we check for it as well.
         */
        phdr->has_noise_dbm = TRUE;
        phdr->noise_dbm = dbm_value;
    }
    ptvcursor_add_invalid_check(csr, hf_80211_common_dbm_antnoise, 1, 0x80);

    ptvcursor_free(csr);
}

static void
dissect_80211n_mac(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int data_len, gboolean add_subtree, guint32 *n_mac_flags, guint32 *ampdu_id, struct ieee_802_11_phdr *phdr)
{
    proto_tree  *ftree       = tree;
    ptvcursor_t *csr;
    guint32      flags;

    phdr->phy = PHDR_802_11_PHY_11N;

    if (add_subtree) {
        ftree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_dot11n_mac, NULL, "802.11n MAC");
        add_ppi_field_header(tvb, ftree, &offset);
        data_len -= 4; /* Subtract field header length */
    }

    if (data_len != PPI_80211N_MAC_LEN) {
        proto_tree_add_expert_format(ftree, pinfo, &ei_ppi_invalid_length, tvb, offset, data_len, "Invalid length: %u", data_len);
        return;
    }

    csr = ptvcursor_new(ftree, tvb, offset);

    flags = tvb_get_letohl(tvb, ptvcursor_current_offset(csr));
    *n_mac_flags = flags;
    phdr->phy_info.info_11n.has_short_gi = TRUE;
    phdr->phy_info.info_11n.has_greenfield = TRUE;
    phdr->phy_info.info_11n.short_gi = ((flags & DOT11N_FLAG_SHORT_GI) != 0);
    phdr->phy_info.info_11n.greenfield = ((flags & DOT11N_FLAG_GREENFIELD) != 0);
    if (DOT11N_IS_AGGREGATE(flags)) {
        phdr->has_aggregate_info = 1;
        phdr->aggregate_flags = 0;
        if (!(flags & DOT11N_FLAG_MORE_AGGREGATES))
            phdr->aggregate_flags |= PHDR_802_11_LAST_PART_OF_A_MPDU;
        if (flags & DOT11N_FLAG_AGG_CRC_ERROR)
            phdr->aggregate_flags |= PHDR_802_11_A_MPDU_DELIM_CRC_ERROR;
    }
    ptvcursor_add_with_subtree(csr, hf_80211n_mac_flags, 4, ENC_LITTLE_ENDIAN,
                               ett_dot11n_mac_flags);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_flags_greenfield, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_flags_ht20_40, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_flags_rx_guard_interval, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_flags_duplicate_rx, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_flags_aggregate, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_flags_more_aggregates, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_80211n_mac_flags_delimiter_crc_after, 4, ENC_LITTLE_ENDIAN); /* Last */
    ptvcursor_pop_subtree(csr);

    if (DOT11N_IS_AGGREGATE(flags)) {
        *ampdu_id = tvb_get_letohl(tvb, ptvcursor_current_offset(csr));
        phdr->aggregate_id = *ampdu_id;
    }
    ptvcursor_add(csr, hf_80211n_mac_ampdu_id, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_80211n_mac_num_delimiters, 1, ENC_LITTLE_ENDIAN);

    if (add_subtree) {
        ptvcursor_add(csr, hf_80211n_mac_reserved, 3, ENC_LITTLE_ENDIAN);
    }

    ptvcursor_free(csr);
}

static void
dissect_80211n_mac_phy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int data_len, guint32 *n_mac_flags, guint32 *ampdu_id, struct ieee_802_11_phdr *phdr)
{
    proto_tree  *ftree;
    proto_item  *ti;
    ptvcursor_t *csr;
    guint8       mcs;
    guint8       ness;
    guint16      ext_frequency;
    gchar       *chan_str;

    ftree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_dot11n_mac_phy, NULL, "802.11n MAC+PHY");
    add_ppi_field_header(tvb, ftree, &offset);
    data_len -= 4; /* Subtract field header length */

    if (data_len != PPI_80211N_MAC_PHY_LEN) {
        proto_tree_add_expert_format(ftree, pinfo, &ei_ppi_invalid_length, tvb, offset, data_len, "Invalid length: %u", data_len);
        return;
    }

    dissect_80211n_mac(tvb, pinfo, ftree, offset, PPI_80211N_MAC_LEN,
                       FALSE, n_mac_flags, ampdu_id, phdr);
    offset += PPI_80211N_MAC_PHY_OFF;

    csr = ptvcursor_new(ftree, tvb, offset);

    mcs = tvb_get_guint8(tvb, ptvcursor_current_offset(csr));
    if (mcs != 255) {
        phdr->phy_info.info_11n.has_mcs_index = TRUE;
        phdr->phy_info.info_11n.mcs_index = mcs;
    }
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_mcs, 1, 255);

    ness = tvb_get_guint8(tvb, ptvcursor_current_offset(csr));
    phdr->phy_info.info_11n.has_ness = TRUE;
    phdr->phy_info.info_11n.ness = ness;
    ti = ptvcursor_add(csr, hf_80211n_mac_phy_num_streams, 1, ENC_LITTLE_ENDIAN);
    if (tvb_get_guint8(tvb, ptvcursor_current_offset(csr) - 1) == 0)
        proto_item_append_text(ti, " (unknown)");
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_combined, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant0_ctl, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant1_ctl, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant2_ctl, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant3_ctl, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant0_ext, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant1_ext, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant2_ext, 1, 255);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_rssi_ant3_ext, 1, 255);

    ext_frequency = tvb_get_letohs(ptvcursor_tvbuff(csr), ptvcursor_current_offset(csr));
    chan_str = ieee80211_mhz_to_str(ext_frequency);
    proto_tree_add_uint_format(ptvcursor_tree(csr), hf_80211n_mac_phy_ext_chan_freq, ptvcursor_tvbuff(csr),
                               ptvcursor_current_offset(csr), 2, ext_frequency, "Ext. Channel frequency: %s", chan_str);
    g_free(chan_str);
    ptvcursor_advance(csr, 2);

    ptvcursor_add_with_subtree(csr, hf_80211n_mac_phy_ext_chan_flags, 2, ENC_LITTLE_ENDIAN,
                               ett_dot11n_mac_phy_ext_channel_flags);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_turbo, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_cck, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_ofdm, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_2ghz, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_5ghz, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_passive, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_80211n_mac_phy_ext_chan_flags_dynamic, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_80211n_mac_phy_ext_chan_flags_gfsk, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(csr);

    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant0signal, 1, 0x80); /* -128 */
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant0noise, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant1signal, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant1noise, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant2signal, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant2noise, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant3signal, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_dbm_ant3noise, 1, 0x80);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_evm0, 4, 0);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_evm1, 4, 0);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_evm2, 4, 0);
    ptvcursor_add_invalid_check(csr, hf_80211n_mac_phy_evm3, 4, 0);

    ptvcursor_free(csr);
}

static void
dissect_aggregation_extension(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int data_len)
{
    proto_tree *ftree;
    ptvcursor_t *csr;

    ftree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_aggregation_extension, NULL, "Aggregation Extension");
    add_ppi_field_header(tvb, ftree, &offset);
    data_len -= 4; /* Subtract field header length */

    if (data_len != PPI_AGGREGATION_EXTENSION_LEN) {
        proto_tree_add_expert_format(ftree, pinfo, &ei_ppi_invalid_length, tvb, offset, data_len, "Invalid length: %u", data_len);
        return;
    }

    csr = ptvcursor_new(ftree, tvb, offset);

    ptvcursor_add(csr, hf_aggregation_extension_interface_id, 4, ENC_LITTLE_ENDIAN); /* Last */
    ptvcursor_free(csr);
}

static void
dissect_8023_extension(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int data_len)
{
    proto_tree  *ftree;
    ptvcursor_t *csr;

    ftree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_8023_extension, NULL, "802.3 Extension");
    add_ppi_field_header(tvb, ftree, &offset);
    data_len -= 4; /* Subtract field header length */

    if (data_len != PPI_8023_EXTENSION_LEN) {
        proto_tree_add_expert_format(ftree, pinfo, &ei_ppi_invalid_length, tvb, offset, data_len, "Invalid length: %u", data_len);
        return;
    }

    csr = ptvcursor_new(ftree, tvb, offset);

    ptvcursor_add_with_subtree(csr, hf_8023_extension_flags, 4, ENC_LITTLE_ENDIAN, ett_8023_extension_flags);
    ptvcursor_add(csr, hf_8023_extension_flags_fcs_present, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(csr);

    ptvcursor_add_with_subtree(csr, hf_8023_extension_errors, 4, ENC_LITTLE_ENDIAN, ett_8023_extension_errors);
    ptvcursor_add_no_advance(csr, hf_8023_extension_errors_fcs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_8023_extension_errors_sequence, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(csr, hf_8023_extension_errors_symbol, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(csr, hf_8023_extension_errors_data, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(csr);

    ptvcursor_free(csr);
}


#define PADDING4(x) ((((x + 3) >> 2) << 2) - x)
#define ADD_BASIC_TAG(hf_tag) \
    if (tree)   \
        proto_tree_add_item(ppi_tree, hf_tag, tvb, offset, data_len, ENC_NA)

static int
dissect_ppi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree    *ppi_tree    = NULL, *ppi_flags_tree = NULL, *seg_tree = NULL, *ampdu_tree = NULL;
    proto_tree    *agg_tree    = NULL;
    proto_item    *ti          = NULL;
    tvbuff_t      *next_tvb;
    int            offset      = 0;
    guint          version, flags;
    gint           tot_len, data_len;
    guint          data_type;
    guint32        dlt;
    guint32        n_ext_flags = 0;
    guint32        ampdu_id    = 0;
    fragment_head *fd_head     = NULL;
    fragment_item *ft_fdh      = NULL;
    gint           mpdu_count  = 0;
    gchar         *mpdu_str;
    gboolean       first_mpdu  = TRUE;
    guint          last_frame  = 0;
    gint len_remain, /*pad_len = 0,*/ ampdu_len = 0;
    struct ieee_802_11_phdr phdr;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPI");
    col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_guint8(tvb, offset);
    flags = tvb_get_guint8(tvb, offset + 1);

    tot_len = tvb_get_letohs(tvb, offset+2);
    dlt = tvb_get_letohl(tvb, offset+4);

    col_add_fstr(pinfo->cinfo, COL_INFO, "PPI version %u, %u bytes",
                 version, tot_len);

    /* Dissect the packet */
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ppi,
                                            tvb, 0, tot_len, "PPI version %u, %u bytes", version, tot_len);
        ppi_tree = proto_item_add_subtree(ti, ett_ppi_pph);
        proto_tree_add_item(ppi_tree, hf_ppi_head_version,
                            tvb, offset, 1, ENC_LITTLE_ENDIAN);

        ti = proto_tree_add_item(ppi_tree, hf_ppi_head_flags,
                                 tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
        ppi_flags_tree = proto_item_add_subtree(ti, ett_ppi_flags);
        proto_tree_add_item(ppi_flags_tree, hf_ppi_head_flag_alignment,
                            tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ppi_flags_tree, hf_ppi_head_flag_reserved,
                            tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(ppi_tree, hf_ppi_head_len,
                                 tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ppi_tree, hf_ppi_head_dlt,
                                 tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
    }

    tot_len -= PPI_V0_HEADER_LEN;
    offset += 8;

    /* We don't have any 802.11 metadata yet. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.fcs_len = -1;
    phdr.decrypted = FALSE;
    phdr.datapad = FALSE;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;

    while (tot_len > 0) {
        data_type = tvb_get_letohs(tvb, offset);
        data_len = tvb_get_letohs(tvb, offset + 2) + 4;
        tot_len -= data_len;

        switch (data_type) {

        case PPI_80211_COMMON:
            dissect_80211_common(tvb, pinfo, ppi_tree, offset, data_len, &phdr);
            break;

        case PPI_80211N_MAC:
            dissect_80211n_mac(tvb, pinfo, ppi_tree, offset, data_len,
                TRUE, &n_ext_flags, &ampdu_id, &phdr);
            break;

        case PPI_80211N_MAC_PHY:
            dissect_80211n_mac_phy(tvb, pinfo, ppi_tree, offset,
                data_len, &n_ext_flags, &ampdu_id, &phdr);
            break;

        case PPI_SPECTRUM_MAP:
            ADD_BASIC_TAG(hf_spectrum_map);
            break;

        case PPI_PROCESS_INFO:
            ADD_BASIC_TAG(hf_process_info);
            break;

        case PPI_CAPTURE_INFO:
            ADD_BASIC_TAG(hf_capture_info);
            break;

        case PPI_AGGREGATION_EXTENSION:
            dissect_aggregation_extension(tvb, pinfo, ppi_tree, offset, data_len);
            break;

        case PPI_8023_EXTENSION:
            dissect_8023_extension(tvb, pinfo, ppi_tree, offset, data_len);
            break;

        case PPI_GPS_INFO:
            if (ppi_gps_handle == NULL)
            {
                proto_tree_add_item(ppi_tree, hf_ppi_gps, tvb, offset, data_len, ENC_NA);
            }
            else /* we found a suitable dissector */
            {
                /* skip over the ppi_fieldheader, and pass it off to the dedicated GPS dissetor */
                next_tvb = tvb_new_subset(tvb, offset + 4, data_len - 4 , -1);
                call_dissector(ppi_gps_handle, next_tvb, pinfo, ppi_tree);
            }
            break;

        case PPI_VECTOR_INFO:
            if (ppi_vector_handle == NULL)
            {
                proto_tree_add_item(ppi_tree, hf_ppi_vector, tvb, offset, data_len, ENC_NA);
            }
            else /* we found a suitable dissector */
            {
                /* skip over the ppi_fieldheader, and pass it off to the dedicated VECTOR dissetor */
                next_tvb = tvb_new_subset(tvb, offset + 4, data_len - 4 , -1);
                call_dissector(ppi_vector_handle, next_tvb, pinfo, ppi_tree);
            }
            break;

        case PPI_SENSOR_INFO:
            if (ppi_sensor_handle == NULL)
            {
                proto_tree_add_item(ppi_tree, hf_ppi_harris, tvb, offset, data_len, ENC_NA);
            }
            else /* we found a suitable dissector */
            {
                /* skip over the ppi_fieldheader, and pass it off to the dedicated SENSOR dissetor */
                next_tvb = tvb_new_subset(tvb, offset + 4, data_len - 4 , -1);
                call_dissector(ppi_sensor_handle, next_tvb, pinfo, ppi_tree);
            }
            break;

        case PPI_ANTENNA_INFO:
            if (ppi_antenna_handle == NULL)
            {
                proto_tree_add_item(ppi_tree, hf_ppi_antenna, tvb, offset, data_len, ENC_NA);
            }
            else /* we found a suitable dissector */
            {
                /* skip over the ppi_fieldheader, and pass it off to the dedicated ANTENNA dissetor */
                next_tvb = tvb_new_subset(tvb, offset + 4, data_len - 4 , -1);
                call_dissector(ppi_antenna_handle, next_tvb, pinfo, ppi_tree);
            }
            break;

        case FNET_PRIVATE:
            if (ppi_fnet_handle == NULL)
            {
                proto_tree_add_item(ppi_tree, hf_ppi_fnet, tvb, offset, data_len, ENC_NA);
            }
            else /* we found a suitable dissector */
            {
                /* skip over the ppi_fieldheader, and pass it off to the dedicated FNET dissetor */
                next_tvb = tvb_new_subset(tvb, offset + 4, data_len - 4 , -1);
                call_dissector(ppi_fnet_handle, next_tvb, pinfo, ppi_tree);
            }
            break;

        default:
            proto_tree_add_item(ppi_tree, hf_ppi_reserved, tvb, offset, data_len, ENC_NA);
        }

        offset += data_len;
        if (IS_PPI_FLAG_ALIGN(flags)){
            offset += PADDING4(offset);
        }
    }

    if (ppi_ampdu_reassemble && DOT11N_IS_AGGREGATE(n_ext_flags)) {
        len_remain = tvb_captured_length_remaining(tvb, offset);
#if 0 /* XXX: pad_len never actually used ?? */
        if (DOT11N_MORE_AGGREGATES(n_ext_flags)) {
            pad_len = PADDING4(len_remain);
        }
#endif
        pinfo->fragmented = TRUE;

        /* Make sure we aren't going to go past AGGREGATE_MAX
         * and caclulate our full A-MPDU length */
        fd_head = fragment_get(&ampdu_reassembly_table, pinfo, ampdu_id, NULL);
        while (fd_head) {
            ampdu_len += fd_head->len + PADDING4(fd_head->len) + 4;
            fd_head = fd_head->next;
        }
        if (ampdu_len > AGGREGATE_MAX) {
            proto_tree_add_expert_format(ppi_tree, pinfo, &ei_ppi_invalid_length, tvb, offset, -1, "Aggregate length greater than maximum (%u)", AGGREGATE_MAX);
            return offset;
        }

        /*
         * Note that we never actually reassemble our A-MPDUs.  Doing
         * so would require prepending each MPDU with an A-MPDU delimiter
         * and appending it with padding, only to hand it off to some
         * routine which would un-do the work we just did.  We're using
         * the reassembly code to track MPDU sizes and frame numbers.
         */
        /*??fd_head = */fragment_add_seq_next(&ampdu_reassembly_table,
            tvb, offset, pinfo, ampdu_id, NULL, len_remain, TRUE);
        pinfo->fragmented = TRUE;

        /* Do reassembly? */
        fd_head = fragment_get(&ampdu_reassembly_table, pinfo, ampdu_id, NULL);

        /* Show our fragments */
        if (fd_head && tree) {
            ft_fdh = fd_head;
            /* List our fragments */
            seg_tree = proto_tree_add_subtree_format(ppi_tree, tvb, offset, -1,
                    ett_ampdu_segments, &ti, "A-MPDU (%u bytes w/hdrs):", ampdu_len);
            PROTO_ITEM_SET_GENERATED(ti);

            while (ft_fdh) {
                if (ft_fdh->tvb_data && ft_fdh->len) {
                    last_frame = ft_fdh->frame;
                    if (!first_mpdu)
                        proto_item_append_text(ti, ",");
                    first_mpdu = FALSE;
                    proto_item_append_text(ti, " #%u(%u)",
                        ft_fdh->frame, ft_fdh->len);
                    proto_tree_add_uint_format(seg_tree, hf_ampdu_segment,
                        tvb, 0, 0, last_frame,
                        "Frame: %u (%u byte%s)",
                        last_frame,
                        ft_fdh->len,
                        plurality(ft_fdh->len, "", "s"));
                }
                ft_fdh = ft_fdh->next;
            }
            if (last_frame && last_frame != pinfo->num)
                proto_tree_add_uint(seg_tree, hf_ampdu_reassembled_in,
                    tvb, 0, 0, last_frame);
        }

        if (fd_head && !DOT11N_MORE_AGGREGATES(n_ext_flags)) {
            if (tree) {
                ti = proto_tree_add_protocol_format(tree,
                    proto_get_id_by_filter_name("wlan_aggregate"),
                    tvb, 0, tot_len, "IEEE 802.11 Aggregate MPDU");
                agg_tree = proto_item_add_subtree(ti, ett_ampdu);
            }

            while (fd_head) {
                if (fd_head->tvb_data && fd_head->len) {
                    mpdu_count++;
                    mpdu_str = wmem_strdup_printf(wmem_packet_scope(), "MPDU #%d", mpdu_count);

                    next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                    add_new_data_source(pinfo, next_tvb, mpdu_str);

                    ampdu_tree = proto_tree_add_subtree(agg_tree, next_tvb, 0, -1, ett_ampdu_segment, NULL, mpdu_str);
                    call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, ampdu_tree, &phdr);
                }
                fd_head = fd_head->next;
            }
            proto_tree_add_uint(seg_tree, hf_ampdu_count, tvb, 0, 0, mpdu_count);
            pinfo->fragmented=FALSE;
        } else {
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 802.11n");
            col_set_str(pinfo->cinfo, COL_INFO, "Unreassembled A-MPDU data");
            call_data_dissector(next_tvb, pinfo, tree);
        }
        return tvb_captured_length(tvb);
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    /*
     * Handle LINKTYPE_IEEE802_11, which is 105, specially; call the
     * "802.11 with radio information" dissector, and pass it a pointer
     * to the struct ieee_802_11_phdr we've constructed from the PPI data,
     * so that it can display that information.
     *
     * Handle everything else with the pcap_pktdata dissector, letting
     * it do whatever needs to be done about pseudo-headers.
     */
    if (dlt == 105) {
        /* LINKTYPE_IEEE802_11 */
        call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
    } else {
        /* Everything else. */
        call_dissector_with_data(pcap_pktdata_handle, next_tvb, pinfo, tree, &dlt);
    }
    return tvb_captured_length(tvb);
}

/* Establish our beachead */

static void
ampdu_reassemble_init(void)
{
    reassembly_table_init(&ampdu_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
ampdu_reassemble_cleanup(void)
{
    reassembly_table_destroy(&ampdu_reassembly_table);
}

void
proto_register_ppi(void)
{
    static hf_register_info hf[] = {
    { &hf_ppi_head_version,
      { "Version", "ppi.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "PPI header format version", HFILL } },
    { &hf_ppi_head_flags,
      { "Flags", "ppi.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "PPI header flags", HFILL } },
    { &hf_ppi_head_flag_alignment,
      { "Alignment", "ppi.flags.alignment",
        FT_BOOLEAN, 8, TFS(&tfs_ppi_head_flag_alignment), 0x01,
        "PPI header flags - 32bit Alignment", HFILL } },
    { &hf_ppi_head_flag_reserved,
      { "Reserved", "ppi.flags.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xFE,
        "PPI header flags - Reserved Flags", HFILL } },
    { &hf_ppi_head_len,
       { "Header length", "ppi.length",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         "Length of header including payload", HFILL } },
    { &hf_ppi_head_dlt,
       { "DLT", "ppi.dlt",
         FT_UINT32, BASE_DEC, NULL, 0x0, "libpcap Data Link Type (DLT) of the payload", HFILL } },

    { &hf_ppi_field_type,
       { "Field type", "ppi.field_type",
         FT_UINT16, BASE_DEC, VALS(vs_ppi_field_type), 0x0, "PPI data field type", HFILL } },
    { &hf_ppi_field_len,
       { "Field length", "ppi.field_len",
         FT_UINT16, BASE_DEC, NULL, 0x0, "PPI data field length", HFILL } },

    { &hf_80211_common_tsft,
       { "TSFT", "ppi.80211-common.tsft",
         FT_UINT64, BASE_DEC, NULL, 0x0, "PPI 802.11-Common Timing Synchronization Function Timer (TSFT)", HFILL } },
    { &hf_80211_common_flags,
       { "Flags", "ppi.80211-common.flags",
         FT_UINT16, BASE_HEX, NULL, 0x0, "PPI 802.11-Common Flags", HFILL } },
    { &hf_80211_common_flags_fcs,
       { "FCS present flag", "ppi.80211-common.flags.fcs",
         FT_BOOLEAN, 16, TFS(&tfs_present_absent), DOT11_FLAG_HAVE_FCS, "PPI 802.11-Common Frame Check Sequence (FCS) Present Flag", HFILL } },
    { &hf_80211_common_flags_tsft,
       { "TSFT flag", "ppi.80211-common.flags.tsft",
         FT_BOOLEAN, 16, TFS(&tfs_tsft_ms), DOT11_FLAG_TSF_TIMER_MS, "PPI 802.11-Common Timing Synchronization Function Timer (TSFT) msec/usec flag", HFILL } },
    { &hf_80211_common_flags_fcs_valid,
       { "FCS validity", "ppi.80211-common.flags.fcs-invalid",
         FT_BOOLEAN, 16, TFS(&tfs_invalid_valid), DOT11_FLAG_FCS_INVALID, "PPI 802.11-Common Frame Check Sequence (FCS) Validity flag", HFILL } },
    { &hf_80211_common_flags_phy_err,
       { "PHY error flag", "ppi.80211-common.flags.phy-err",
         FT_BOOLEAN, 16, TFS(&tfs_phy_error), DOT11_FLAG_PHY_ERROR, "PPI 802.11-Common Physical level (PHY) Error", HFILL } },
    { &hf_80211_common_rate,
       { "Data rate", "ppi.80211-common.rate",
         FT_UINT16, BASE_DEC, NULL, 0x0, "PPI 802.11-Common Data Rate (x 500 Kbps)", HFILL } },
    { &hf_80211_common_chan_freq,
       { "Channel frequency", "ppi.80211-common.chan.freq",
         FT_UINT16, BASE_DEC, NULL, 0x0,
        "PPI 802.11-Common Channel Frequency", HFILL } },
    { &hf_80211_common_chan_flags,
       { "Channel flags", "ppi.80211-common.chan.flags",
         FT_UINT16, BASE_HEX, NULL, 0x0, "PPI 802.11-Common Channel Flags", HFILL } },

    { &hf_80211_common_chan_flags_turbo,
       { "Turbo", "ppi.80211-common.chan.flags.turbo",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_TURBO, "PPI 802.11-Common Channel Flags Turbo", HFILL } },
    { &hf_80211_common_chan_flags_cck,
       { "Complementary Code Keying (CCK)", "ppi.80211-common.chan.flags.cck",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_CCK, "PPI 802.11-Common Channel Flags Complementary Code Keying (CCK) Modulation", HFILL } },
    { &hf_80211_common_chan_flags_ofdm,
       { "Orthogonal Frequency-Division Multiplexing (OFDM)", "ppi.80211-common.chan.flags.ofdm",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_OFDM, "PPI 802.11-Common Channel Flags Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL } },
    { &hf_80211_common_chan_flags_2ghz,
       { "2 GHz spectrum", "ppi.80211-common.chan.flags.2ghz",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_2GHZ, "PPI 802.11-Common Channel Flags 2 GHz spectrum", HFILL } },
    { &hf_80211_common_chan_flags_5ghz,
       { "5 GHz spectrum", "ppi.80211-common.chan.flags.5ghz",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_5GHZ, "PPI 802.11-Common Channel Flags 5 GHz spectrum", HFILL } },
    { &hf_80211_common_chan_flags_passive,
       { "Passive", "ppi.80211-common.chan.flags.passive",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_PASSIVE, "PPI 802.11-Common Channel Flags Passive", HFILL } },
    { &hf_80211_common_chan_flags_dynamic,
       { "Dynamic CCK-OFDM", "ppi.80211-common.chan.flags.dynamic",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_DYN, "PPI 802.11-Common Channel Flags Dynamic CCK-OFDM Channel", HFILL } },
    { &hf_80211_common_chan_flags_gfsk,
       { "Gaussian Frequency Shift Keying (GFSK)", "ppi.80211-common.chan.flags.gfsk",
         FT_BOOLEAN, 16, NULL, IEEE80211_CHAN_GFSK, "PPI 802.11-Common Channel Flags Gaussian Frequency Shift Keying (GFSK) Modulation", HFILL } },

    { &hf_80211_common_fhss_hopset,
       { "FHSS hopset", "ppi.80211-common.fhss.hopset",
         FT_UINT8, BASE_HEX, NULL, 0x0, "PPI 802.11-Common Frequency-Hopping Spread Spectrum (FHSS) Hopset", HFILL } },
    { &hf_80211_common_fhss_pattern,
       { "FHSS pattern", "ppi.80211-common.fhss.pattern",
         FT_UINT8, BASE_HEX, NULL, 0x0, "PPI 802.11-Common Frequency-Hopping Spread Spectrum (FHSS) Pattern", HFILL } },
    { &hf_80211_common_dbm_antsignal,
       { "dBm antenna signal", "ppi.80211-common.dbm.antsignal",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11-Common dBm Antenna Signal", HFILL } },
    { &hf_80211_common_dbm_antnoise,
       { "dBm antenna noise", "ppi.80211-common.dbm.antnoise",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11-Common dBm Antenna Noise", HFILL } },

    /* 802.11n MAC */
    { &hf_80211n_mac_flags,
       { "MAC flags", "ppi.80211n-mac.flags",
         FT_UINT32, BASE_HEX, NULL, 0x0, "PPI 802.11n MAC flags", HFILL } },
    { &hf_80211n_mac_flags_greenfield,
       { "Greenfield flag", "ppi.80211n-mac.flags.greenfield",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), DOT11N_FLAG_GREENFIELD, "PPI 802.11n MAC Greenfield Flag", HFILL } },
    { &hf_80211n_mac_flags_ht20_40,
       { "HT20/HT40 flag", "ppi.80211n-mac.flags.ht20_40",
         FT_BOOLEAN, 32, TFS(&tfs_ht20_40), DOT11N_FLAG_HT40, "PPI 802.11n MAC HT20/HT40 Flag", HFILL } },
    { &hf_80211n_mac_flags_rx_guard_interval,
       { "RX Short Guard Interval (SGI) flag", "ppi.80211n-mac.flags.rx.short_guard_interval",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), DOT11N_FLAG_SHORT_GI, "PPI 802.11n MAC RX Short Guard Interval (SGI) Flag", HFILL } },
    { &hf_80211n_mac_flags_duplicate_rx,
       { "Duplicate RX flag", "ppi.80211n-mac.flags.rx.duplicate",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), DOT11N_FLAG_DUPLICATE_RX, "PPI 802.11n MAC Duplicate RX Flag", HFILL } },
    { &hf_80211n_mac_flags_aggregate,
       { "Aggregate flag", "ppi.80211n-mac.flags.agg",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), DOT11N_FLAG_IS_AGGREGATE, "PPI 802.11 MAC Aggregate Flag", HFILL } },
    { &hf_80211n_mac_flags_more_aggregates,
       { "More aggregates flag", "ppi.80211n-mac.flags.more_agg",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), DOT11N_FLAG_MORE_AGGREGATES, "PPI 802.11n MAC More Aggregates Flag", HFILL } },
    { &hf_80211n_mac_flags_delimiter_crc_after,
       { "A-MPDU Delimiter CRC error after this frame flag", "ppi.80211n-mac.flags.delim_crc_error_after",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), DOT11N_FLAG_AGG_CRC_ERROR, "PPI 802.11n MAC A-MPDU Delimiter CRC Error After This Frame Flag", HFILL } },
    { &hf_80211n_mac_ampdu_id,
       { "AMPDU-ID", "ppi.80211n-mac.ampdu_id",
         FT_UINT32, BASE_HEX, NULL, 0x0, "PPI 802.11n MAC AMPDU-ID", HFILL } },
    { &hf_80211n_mac_num_delimiters,
       { "Num-Delimiters", "ppi.80211n-mac.num_delimiters",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC number of zero-length pad delimiters", HFILL } },
    { &hf_80211n_mac_reserved,
       { "Reserved", "ppi.80211n-mac.reserved",
         FT_UINT24, BASE_HEX, NULL, 0x0, "PPI 802.11n MAC Reserved", HFILL } },


    /* 802.11n MAC+PHY */
    { &hf_80211n_mac_phy_mcs,
       { "MCS", "ppi.80211n-mac-phy.mcs",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Modulation Coding Scheme (MCS)", HFILL } },
    { &hf_80211n_mac_phy_num_streams,
       { "Number of spatial streams", "ppi.80211n-mac-phy.num_streams",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY number of spatial streams", HFILL } },
    { &hf_80211n_mac_phy_rssi_combined,
       { "RSSI combined", "ppi.80211n-mac-phy.rssi.combined",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Received Signal Strength Indication (RSSI) Combined", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant0_ctl,
       { "Antenna 0 control RSSI", "ppi.80211n-mac-phy.rssi.ant0ctl",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 0 Control Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant1_ctl,
       { "Antenna 1 control RSSI", "ppi.80211n-mac-phy.rssi.ant1ctl",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 1 Control Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant2_ctl,
       { "Antenna 2 control RSSI", "ppi.80211n-mac-phy.rssi.ant2ctl",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 2 Control Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant3_ctl,
       { "Antenna 3 control RSSI", "ppi.80211n-mac-phy.rssi.ant3ctl",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 3 Control Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant0_ext,
       { "Antenna 0 extension RSSI", "ppi.80211n-mac-phy.rssi.ant0ext",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 0 Extension Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant1_ext,
       { "Antenna 1 extension RSSI", "ppi.80211n-mac-phy.rssi.ant1ext",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 1 Extension Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant2_ext,
       { "Antenna 2 extension RSSI", "ppi.80211n-mac-phy.rssi.ant2ext",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 2 Extension Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_rssi_ant3_ext,
       { "Antenna 3 extension RSSI", "ppi.80211n-mac-phy.rssi.ant3ext",
         FT_UINT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Antenna 3 Extension Channel Received Signal Strength Indication (RSSI)", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_freq,
       { "Extended channel frequency", "ppi.80211-mac-phy.ext-chan.freq",
         FT_UINT16, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Extended Channel Frequency", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags,
       { "Channel flags", "ppi.80211-mac-phy.ext-chan.flags",
         FT_UINT16, BASE_HEX, NULL, 0x0, "PPI 802.11n MAC+PHY Channel Flags", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_turbo,
       { "Turbo", "ppi.80211-mac-phy.ext-chan.flags.turbo",
         FT_BOOLEAN, 16, NULL, 0x0010, "PPI 802.11n MAC+PHY Channel Flags Turbo", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_cck,
       { "Complementary Code Keying (CCK)", "ppi.80211-mac-phy.ext-chan.flags.cck",
         FT_BOOLEAN, 16, NULL, 0x0020, "PPI 802.11n MAC+PHY Channel Flags Complementary Code Keying (CCK) Modulation", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_ofdm,
       { "Orthogonal Frequency-Division Multiplexing (OFDM)", "ppi.80211-mac-phy.ext-chan.flags.ofdm",
         FT_BOOLEAN, 16, NULL, 0x0040, "PPI 802.11n MAC+PHY Channel Flags Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_2ghz,
       { "2 GHz spectrum", "ppi.80211-mac-phy.ext-chan.flags.2ghz",
         FT_BOOLEAN, 16, NULL, 0x0080, "PPI 802.11n MAC+PHY Channel Flags 2 GHz spectrum", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_5ghz,
       { "5 GHz spectrum", "ppi.80211-mac-phy.ext-chan.flags.5ghz",
         FT_BOOLEAN, 16, NULL, 0x0100, "PPI 802.11n MAC+PHY Channel Flags 5 GHz spectrum", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_passive,
       { "Passive", "ppi.80211-mac-phy.ext-chan.flags.passive",
         FT_BOOLEAN, 16, NULL, 0x0200, "PPI 802.11n MAC+PHY Channel Flags Passive", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_dynamic,
       { "Dynamic CCK-OFDM", "ppi.80211-mac-phy.ext-chan.flags.dynamic",
         FT_BOOLEAN, 16, NULL, 0x0400, "PPI 802.11n MAC+PHY Channel Flags Dynamic CCK-OFDM Channel", HFILL } },
    { &hf_80211n_mac_phy_ext_chan_flags_gfsk,
       { "Gaussian Frequency Shift Keying (GFSK)", "ppi.80211-mac-phy.ext-chan.flags.gfsk",
         FT_BOOLEAN, 16, NULL, 0x0800, "PPI 802.11n MAC+PHY Channel Flags Gaussian Frequency Shift Keying (GFSK) Modulation", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant0signal,
       { "dBm antenna 0 signal", "ppi.80211n-mac-phy.dbmant0.signal",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 0 Signal", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant0noise,
       { "dBm antenna 0 noise", "ppi.80211n-mac-phy.dbmant0.noise",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 0 Noise", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant1signal,
       { "dBm antenna 1 signal", "ppi.80211n-mac-phy.dbmant1.signal",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 1 Signal", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant1noise,
       { "dBm antenna 1 noise", "ppi.80211n-mac-phy.dbmant1.noise",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 1 Noise", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant2signal,
       { "dBm antenna 2 signal", "ppi.80211n-mac-phy.dbmant2.signal",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 2 Signal", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant2noise,
       { "dBm antenna 2 noise", "ppi.80211n-mac-phy.dbmant2.noise",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 2 Noise", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant3signal,
       { "dBm antenna 3 signal", "ppi.80211n-mac-phy.dbmant3.signal",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 3 Signal", HFILL } },
    { &hf_80211n_mac_phy_dbm_ant3noise,
       { "dBm antenna 3 noise", "ppi.80211n-mac-phy.dbmant3.noise",
         FT_INT8, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY dBm Antenna 3 Noise", HFILL } },
    { &hf_80211n_mac_phy_evm0,
       { "EVM-0", "ppi.80211n-mac-phy.evm0",
         FT_UINT32, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Error Vector Magnitude (EVM) for chain 0", HFILL } },
    { &hf_80211n_mac_phy_evm1,
       { "EVM-1", "ppi.80211n-mac-phy.evm1",
         FT_UINT32, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Error Vector Magnitude (EVM) for chain 1", HFILL } },
    { &hf_80211n_mac_phy_evm2,
       { "EVM-2", "ppi.80211n-mac-phy.evm2",
         FT_UINT32, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Error Vector Magnitude (EVM) for chain 2", HFILL } },
    { &hf_80211n_mac_phy_evm3,
       { "EVM-3", "ppi.80211n-mac-phy.evm3",
         FT_UINT32, BASE_DEC, NULL, 0x0, "PPI 802.11n MAC+PHY Error Vector Magnitude (EVM) for chain 3", HFILL } },

    { &hf_ampdu_segment,
        { "A-MPDU", "ppi.80211n-mac.ampdu",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0, "802.11n Aggregated MAC Protocol Data Unit (A-MPDU)", HFILL }},
#if 0
    { &hf_ampdu_segments,
        { "Reassembled A-MPDU", "ppi.80211n-mac.ampdu.reassembled",
            FT_NONE, BASE_NONE, NULL, 0x0, "Reassembled Aggregated MAC Protocol Data Unit (A-MPDU)", HFILL }},
#endif
    { &hf_ampdu_reassembled_in,
        { "Reassembled A-MPDU in frame", "ppi.80211n-mac.ampdu.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The A-MPDU that doesn't end in this segment is reassembled in this frame",
            HFILL }},
    { &hf_ampdu_count,
        { "MPDU count", "ppi.80211n-mac.ampdu.count",
            FT_UINT16, BASE_DEC, NULL, 0x0, "The number of aggregated MAC Protocol Data Units (MPDUs)", HFILL }},

    { &hf_spectrum_map,
       { "Radio spectrum map", "ppi.spectrum-map",
            FT_BYTES, BASE_NONE, NULL, 0x0, "PPI Radio spectrum map", HFILL } },
    { &hf_process_info,
       { "Process information", "ppi.proc-info",
            FT_BYTES, BASE_NONE, NULL, 0x0, "PPI Process information", HFILL } },
    { &hf_capture_info,
       { "Capture information", "ppi.cap-info",
            FT_BYTES, BASE_NONE, NULL, 0x0, "PPI Capture information", HFILL } },

    /* Aggregtion Extension */
    { &hf_aggregation_extension_interface_id,
       { "Interface ID", "ppi.aggregation_extension.interface_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, "Zero-based index of the physical interface the packet was captured from", HFILL } },

    /* 802.3 Extension */
    { &hf_8023_extension_flags,
       { "Flags", "ppi.8023_extension.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0, "PPI 802.3 Extension Flags", HFILL } },
    { &hf_8023_extension_flags_fcs_present,
       { "FCS Present Flag", "ppi.8023_extension.flags.fcs_present",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001, "FCS (4 bytes) is present at the end of the packet", HFILL } },
    { &hf_8023_extension_errors,
       { "Errors", "ppi.8023_extension.errors",
            FT_UINT32, BASE_HEX, NULL, 0x0, "PPI 802.3 Extension Errors", HFILL } },
    { &hf_8023_extension_errors_fcs,
       { "FCS Error", "ppi.8023_extension.errors.fcs",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001,
            "PPI 802.3 Extension FCS Error", HFILL } },
    { &hf_8023_extension_errors_sequence,
       { "Sequence Error", "ppi.8023_extension.errors.sequence",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0002,
            "PPI 802.3 Extension Sequence Error", HFILL } },
    { &hf_8023_extension_errors_symbol,
       { "Symbol Error", "ppi.8023_extension.errors.symbol",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0004,
            "PPI 802.3 Extension Symbol Error", HFILL } },
    { &hf_8023_extension_errors_data,
       { "Data Error", "ppi.8023_extension.errors.data",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0008,
            "PPI 802.3 Extension Data Error", HFILL } },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ppi_gps, { "GPS", "ppi.gps", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ppi_vector, { "VECTOR", "ppi.vector", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ppi_harris, { "HARRIS", "ppi.harris", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ppi_antenna, { "ANTENNA", "ppi.antenna", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ppi_fnet, { "FNET", "ppi.fnet", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ppi_reserved, { "Reserved", "ppi.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_ppi_pph,
        &ett_ppi_flags,
        &ett_dot11_common,
        &ett_dot11_common_flags,
        &ett_dot11_common_channel_flags,
        &ett_dot11n_mac,
        &ett_dot11n_mac_flags,
        &ett_dot11n_mac_phy,
        &ett_dot11n_mac_phy_ext_channel_flags,
        &ett_ampdu_segments,
        &ett_ampdu,
        &ett_ampdu_segment,
        &ett_aggregation_extension,
        &ett_8023_extension,
        &ett_8023_extension_flags,
        &ett_8023_extension_errors
    };

    static ei_register_info ei[] = {
        { &ei_ppi_invalid_length, { "ppi.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
    };

    module_t *ppi_module;
    expert_module_t* expert_ppi;

    proto_ppi = proto_register_protocol("PPI Packet Header", "PPI", "ppi");
    proto_register_field_array(proto_ppi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ppi = expert_register_protocol(proto_ppi);
    expert_register_field_array(expert_ppi, ei, array_length(ei));

    ppi_handle = register_dissector("ppi", dissect_ppi, proto_ppi);
    register_capture_dissector_table("ppi", "PPI");

    register_init_routine(ampdu_reassemble_init);
    register_cleanup_routine(ampdu_reassemble_cleanup);

    /* Configuration options */
    ppi_module = prefs_register_protocol(proto_ppi, NULL);
    prefs_register_bool_preference(ppi_module, "reassemble",
                                   "Reassemble fragmented 802.11 A-MPDUs",
                                   "Whether fragmented 802.11 aggregated MPDUs should be reassembled",
                                   &ppi_ampdu_reassemble);
}

void
proto_reg_handoff_ppi(void)
{
    ieee80211_radio_handle = find_dissector_add_dependency("wlan_radio", proto_ppi);
    pcap_pktdata_handle = find_dissector_add_dependency("pcap_pktdata", proto_ppi);
    ppi_gps_handle = find_dissector_add_dependency("ppi_gps", proto_ppi);
    ppi_vector_handle = find_dissector_add_dependency("ppi_vector", proto_ppi);
    ppi_sensor_handle = find_dissector_add_dependency("ppi_sensor", proto_ppi);
    ppi_antenna_handle = find_dissector_add_dependency("ppi_antenna", proto_ppi);
    ppi_fnet_handle = find_dissector_add_dependency("ppi_fnet", proto_ppi);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_PPI, ppi_handle);
    register_capture_dissector("wtap_encap", WTAP_ENCAP_PPI, capture_ppi, proto_ppi);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
