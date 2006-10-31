/*
 *  packet-radiotap.c
 *	Decode packets with a Radiotap header
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/crc32.h>
#include "packet-ieee80211.h"
#include "packet-radiotap.h"

/* Written with info from:
 *
 * http://madwifi.org/wiki/DevDocs/RadiotapHeader
 */

struct ieee80211_radiotap_header {
    guint8	it_version;	/* Version 0. Only increases
				 * for drastic changes,
				 * introduction of compatible
				 * new fields does not count.
				 */
    guint8	it_pad;
    guint16     it_len;         /* length of the whole
				 * header in bytes, including
				 * it_version, it_pad,
				 * it_len, and data fields.
				 */
#define MAX_PRESENT 1
    guint32   it_present[MAX_PRESENT];	/* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
};

enum ieee80211_radiotap_type {
    IEEE80211_RADIOTAP_TSFT = 0,
    IEEE80211_RADIOTAP_FLAGS = 1,
    IEEE80211_RADIOTAP_RATE = 2,
    IEEE80211_RADIOTAP_CHANNEL = 3,
    IEEE80211_RADIOTAP_FHSS = 4,
    IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
    IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
    IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
    IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
    IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
    IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
    IEEE80211_RADIOTAP_ANTENNA = 11,
    IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
    IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_FCS = 14,
    IEEE80211_RADIOTAP_EXT = 31
};

/* Channel flags. */
#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel. */
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x0800	/* GFSK channel (FHSS PHY) */

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_T \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108G \
	(IEEE80211_CHAN_G | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108PUREG \
	(IEEE80211_CHAN_PUREG | IEEE80211_CHAN_TURBO)

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
						 * during CFP
						 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
						 * with short
						 * preamble
						 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
						 * with fragmentation
						 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */

/* protocol */
static int proto_radiotap = -1;

static int hf_radiotap_version = -1;
static int hf_radiotap_pad = -1;
static int hf_radiotap_length = -1;
static int hf_radiotap_present = -1;
static int hf_radiotap_mactime = -1;
static int hf_radiotap_channel_frequency = -1;
static int hf_radiotap_channel_flags = -1;
static int hf_radiotap_datarate = -1;
static int hf_radiotap_antenna = -1;
static int hf_radiotap_dbm_antsignal = -1;
static int hf_radiotap_db_antsignal = -1;
static int hf_radiotap_dbm_antnoise = -1;
static int hf_radiotap_db_antnoise = -1;
static int hf_radiotap_txpower = -1;

/* "Present" flags */
static int hf_radiotap_present_tsft = -1;
static int hf_radiotap_present_flags = -1;
static int hf_radiotap_present_rate = -1;
static int hf_radiotap_present_channel = -1;
static int hf_radiotap_present_fhss = -1;
static int hf_radiotap_present_dbm_antsignal = -1;
static int hf_radiotap_present_dbm_antnoise = -1;
static int hf_radiotap_present_lock_quality = -1;
static int hf_radiotap_present_tx_attenuation = -1;
static int hf_radiotap_present_db_tx_attenuation = -1;
static int hf_radiotap_present_dbm_tx_attenuation = -1;
static int hf_radiotap_present_antenna = -1;
static int hf_radiotap_present_db_antsignal = -1;
static int hf_radiotap_present_db_antnoise = -1;
static int hf_radiotap_present_fcs = -1;
static int hf_radiotap_present_ext = -1;

/* "present.flags" flags */
static int hf_radiotap_flags = -1;
static int hf_radiotap_flags_cfp = -1;
static int hf_radiotap_flags_preamble = -1;
static int hf_radiotap_flags_wep = -1;
static int hf_radiotap_flags_frag = -1;
static int hf_radiotap_flags_fcs = -1;
static int hf_radiotap_flags_datapad = -1;

static int hf_radiotap_quality = -1;
static int hf_radiotap_fcs = -1;
static int hf_radiotap_fcs_bad = -1;

static gint ett_radiotap = -1;
static gint ett_radiotap_present = -1;
static gint ett_radiotap_flags = -1;

static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_datapad_handle;

static void
dissect_radiotap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)	(1 << n)

/*
 * XXX - There are roundup macros defined in other dissectors.  We should
 * move them to a common location at some point.
 */
#ifndef roundup2
#define roundup2(x, y)  (((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

void
capture_radiotap(const guchar *pd, int offset, int len, packet_counts *ld)
{
    const struct ieee80211_radiotap_header *hdr;
    guint16 it_len;
    guint32 present;
    guint8 rflags;

    if(!BYTES_ARE_IN_FRAME(offset, len, (int)sizeof(*hdr))) {
        ld->other ++;
        return;
    }
    hdr = (const struct ieee80211_radiotap_header *)&pd[offset];
    it_len = pletohs(&hdr->it_len);
    if(!BYTES_ARE_IN_FRAME(offset, len, it_len)) {
        ld->other ++;
        return;
    }

    if(it_len > len) {
        /* Header length is bigger than total packet length */
        ld->other ++;
        return;
    }

    if(it_len < sizeof(*hdr)) {
        /* Header length is shorter than fixed-length portion of header */
        ld->other ++;
        return;
    }

    present = pletohl(&hdr->it_present);
    offset += sizeof(*hdr);
    it_len -= sizeof(*hdr);

    rflags = 0;

    /*
     * IEEE80211_RADIOTAP_TSFT is the lowest-order bit.
     */
    if (present & BIT(IEEE80211_RADIOTAP_TSFT)) {
    	if (it_len < 8) {
	    /* No room in header for this field. */
	    ld->other ++;
	    return;
	}
	/* That field is present, and it's 8 bits long. */
	offset += 8;
	it_len -= 8;
    }

    /*
     * IEEE80211_RADIOTAP_FLAGS is the next bit.
     */
    if (present & BIT(IEEE80211_RADIOTAP_FLAGS)) {
    	if (it_len < 1) {
	    /* No room in header for this field. */
	    ld->other ++;
	    return;
	}
	/* That field is present; fetch it. */
	if(!BYTES_ARE_IN_FRAME(offset, len, 1)) {
	    ld->other ++;
	    return;
	}
	rflags = pd[offset];
    }

    /* 802.11 header follows */
    if (rflags & IEEE80211_RADIOTAP_F_DATAPAD)
	capture_ieee80211_datapad(pd, offset + it_len, len, ld);
    else
	capture_ieee80211(pd, offset + it_len, len, ld);
}

void
proto_register_radiotap(void)
{
  static const value_string phy_type[] = {
    { 0, "Unknown" },
    { IEEE80211_CHAN_A,		"802.11a" },
    { IEEE80211_CHAN_B,		"802.11b" },
    { IEEE80211_CHAN_PUREG,	"802.11g (pure-g)" },
    { IEEE80211_CHAN_G,		"802.11g" },
    { IEEE80211_CHAN_T,		"802.11a (turbo)" },
    { IEEE80211_CHAN_108PUREG,	"802.11g (pure-g, turbo)" },
    { IEEE80211_CHAN_108G,	"802.11g (turbo)" },
    { IEEE80211_CHAN_FHSS,	"FHSS" },
    { 0, NULL },
  };

  static const true_false_string preamble_type = {
      "Short",
      "Long",
  };

  static hf_register_info hf[] = {
    { &hf_radiotap_version,
      { "Header revision", "radiotap.version",
	FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_pad,
      { "Header pad", "radiotap.pad",
	FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_length,
       { "Header length", "radiotap.length",
	 FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_present,
       { "Present flags", "radiotap.present",
	 FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },

#define RADIOTAP_MASK_TSFT                  0x00000001
#define RADIOTAP_MASK_FLAGS                 0x00000002
#define RADIOTAP_MASK_RATE                  0x00000004
#define RADIOTAP_MASK_CHANNEL               0x00000008
#define RADIOTAP_MASK_FHSS                  0x00000010
#define RADIOTAP_MASK_DBM_ANTSIGNAL         0x00000020
#define RADIOTAP_MASK_DBM_ANTNOISE          0x00000040
#define RADIOTAP_MASK_LOCK_QUALITY          0x00000080
#define RADIOTAP_MASK_TX_ATTENUATION        0x00000100
#define RADIOTAP_MASK_DB_TX_ATTENUATION     0x00000200
#define RADIOTAP_MASK_DBM_TX_ATTENUATION    0x00000400
#define RADIOTAP_MASK_ANTENNA               0x00000800
#define RADIOTAP_MASK_DB_ANTSIGNAL          0x00001000
#define RADIOTAP_MASK_DB_ANTNOISE           0x00002000
#define RADIOTAP_MASK_FCS                   0x00004000
#define RADIOTAP_MASK_EXT                   0x80000000

    /* Boolean 'present' flags */
    { &hf_radiotap_present_tsft,
      { "TSFT", "radiotap.present.tsft",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_TSFT, "", HFILL } },
    { &hf_radiotap_present_flags,
      { "Flags", "radiotap.present.flags",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_FLAGS, "", HFILL } },
    { &hf_radiotap_present_rate,
      { "Rate", "radiotap.present.rate",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_RATE, "", HFILL } },
    { &hf_radiotap_present_channel,
      { "Channel", "radiotap.present.channel",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_CHANNEL, "", HFILL } },
    { &hf_radiotap_present_fhss,
      { "FHSS", "radiotap.present.fhss",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_FHSS, "", HFILL } },
    { &hf_radiotap_present_dbm_antsignal,
      { "DBM Antenna Signal", "radiotap.present.dbm_antsignal",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DBM_ANTSIGNAL, "", HFILL } },
    { &hf_radiotap_present_dbm_antnoise,
      { "DBM Antenna Noise", "radiotap.present.dbm_antnoise",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DBM_ANTNOISE, "", HFILL } },
    { &hf_radiotap_present_lock_quality,
      { "Lock Quality", "radiotap.present.lock_quality",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_LOCK_QUALITY, "", HFILL } },
    { &hf_radiotap_present_tx_attenuation,
      { "TX Attenuation", "radiotap.present.tx_attenuation",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_TX_ATTENUATION, "", HFILL } },
    { &hf_radiotap_present_db_tx_attenuation,
      { "DB TX Attenuation", "radiotap.present.db_tx_attenuation",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DB_TX_ATTENUATION, "", HFILL } },
    { &hf_radiotap_present_dbm_tx_attenuation,
      { "DBM TX Attenuation", "radiotap.present.dbm_tx_attenuation",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DBM_TX_ATTENUATION, "", HFILL } },
    { &hf_radiotap_present_antenna,
      { "Antenna", "radiotap.present.antenna",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_ANTENNA, "", HFILL } },
    { &hf_radiotap_present_db_antsignal,
      { "DB Antenna Signal", "radiotap.present.db_antsignal",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DB_ANTSIGNAL, "", HFILL } },
    { &hf_radiotap_present_db_antnoise,
      { "DB Antenna Noise", "radiotap.present.db_antnoise",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DB_ANTNOISE, "", HFILL } },
    { &hf_radiotap_present_fcs,
      { "FCS in header", "radiotap.present.fcs",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_FCS,
    "Radiotap header contains FCS", HFILL } },
    { &hf_radiotap_present_ext,
      { "Ext", "radiotap.present.ext",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_EXT, "", HFILL } },


    /* Boolean 'present.flags' flags */
    { &hf_radiotap_flags,
      { "Flags", "radiotap.flags",
	FT_UINT8, BASE_HEX, NULL,  0x0, "", HFILL } },
    { &hf_radiotap_flags_cfp,
      { "CFP", "radiotap.flags.cfp",
	FT_BOOLEAN, 8, NULL,  IEEE80211_RADIOTAP_F_CFP,
    "Sent/Received during CFP", HFILL } },
    { &hf_radiotap_flags_preamble,
      { "Preamble", "radiotap.flags.preamble",
	FT_BOOLEAN, 8, TFS(&preamble_type),  IEEE80211_RADIOTAP_F_SHORTPRE,
    "Sent/Received with short preamble", HFILL } },
    { &hf_radiotap_flags_wep,
      { "WEP", "radiotap.flags.wep",
	FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_WEP,
    "Sent/Received with WEP encryption", HFILL } },
    { &hf_radiotap_flags_frag,
      { "Fragmentation", "radiotap.flags.frag",
	FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_FRAG,
    "Sent/Received with fragmentation", HFILL } },
    { &hf_radiotap_flags_fcs,
      { "FCS at end", "radiotap.flags.fcs",
	FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_FCS,
    "Frame includes FCS at end", HFILL } },
    { &hf_radiotap_flags_datapad,
      { "Data Pad", "radiotap.flags.datapad",
	FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_DATAPAD,
    "Frame has padding between 802.11 heaer and payload", HFILL } },


    { &hf_radiotap_mactime,
       { "MAC timestamp", "radiotap.mactime",
	 FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_quality,
       { "Signal Quality", "radiotap.quality",
	 FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_fcs,
       { "802.11 FCS", "radiotap.fcs",
	 FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_channel_frequency,
      { "Channel frequency", "radiotap.channel.freq",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_channel_flags,
      { "Channel type", "radiotap.channel.flags",
	FT_UINT16, BASE_HEX, VALS(phy_type), 0x0, "", HFILL } },
    { &hf_radiotap_datarate,
      { "Data rate", "radiotap.datarate",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_antenna,
      { "Antenna", "radiotap.antenna",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_dbm_antsignal,
      { "SSI Signal (dBm)", "radiotap.dbm_antsignal",
	FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_db_antsignal,
      { "SSI Signal (dB)", "radiotap.db_antsignal",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_dbm_antnoise,
      { "SSI Noise (dBm)", "radiotap.dbm_antnoise",
	FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_db_antnoise,
      { "SSI Noise (dB)", "radiotap.db_antnoise",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_txpower,
      { "Transmit power", "radiotap.txpower",
	FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } },

    /* Special variables */
    { &hf_radiotap_fcs_bad,
      { "Bad FCS", "radiotap.fcs_bad",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL } },

  };
  static gint *ett[] = {
    &ett_radiotap,
    &ett_radiotap_present,
    &ett_radiotap_flags
  };

  proto_radiotap = proto_register_protocol("IEEE 802.11 Radiotap Capture header", "802.11 Radiotap", "radiotap");
  proto_register_field_array(proto_radiotap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("radiotap", dissect_radiotap, proto_radiotap);

}

/*
 * Convert MHz frequency to IEEE channel number.
 */
static int
ieee80211_mhz2ieee(int freq, int flags)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)
    if (flags & IEEE80211_CHAN_2GHZ) {		/* 2GHz band */
	if (freq == 2484)
	    return 14;
	if (freq < 2484)
	    return (freq - 2407) / 5;
	else
	    return 15 + ((freq - 2512) / 20);
    } else if (flags & IEEE80211_CHAN_5GHZ) {	/* 5Ghz band */
	if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq))
	    return ((freq * 10) + (((freq % 5) == 2) ? 5 : 0) - 49400) / 5;
	if (freq <= 5000)
	    return (freq - 4000) / 5;
	else
	    return (freq - 5000) / 5;
    } else {					/* either, guess */
	if (freq == 2484)
	    return 14;
	if (freq < 2484)
	    return (freq - 2407) / 5;
	if (freq < 5000) {
	    if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq))
		return ((freq * 10) + (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
	    else if (freq > 4900)
		return (freq - 4000) / 5;
	    else
		return 15 + ((freq - 2512) / 20);
	}
	return (freq - 5000) / 5;
    }
#undef IS_CHAN_IN_PUBLIC_SAFETY_BAND
}

static void
dissect_radiotap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *radiotap_tree = NULL;
    proto_tree *pt, *present_tree = NULL;
    proto_tree *ft, *flags_tree = NULL;
    proto_item *ti = NULL;
    proto_item *hdr_fcs_ti = NULL;
    int hdr_fcs_offset = 0;
    int offset;
    guint32 sent_fcs = 0;
    guint32 calc_fcs;
    tvbuff_t *next_tvb;
    guint32 version;
    guint length, length_remaining;
    guint32 rate, freq, flags;
    gint8 dbm;
    guint8 db, rflags;
    guint32 present, next_present;
    int bit;

    if(check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
    if(check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);
    offset = 0;

    version = tvb_get_guint8(tvb, offset);
    length = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);

    if(check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Radiotap Capture v%u, Length %u",
		version, length);

    /* Dissect the packet */
    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_radiotap,
	    tvb, 0, length, "Radiotap Header v%u, Length %u", version, length);
	radiotap_tree = proto_item_add_subtree(ti, ett_radiotap);
	proto_tree_add_uint(radiotap_tree, hf_radiotap_version,
	    tvb, offset, 1, version);
	proto_tree_add_item(radiotap_tree, hf_radiotap_pad,
	    tvb, offset + 1, 1, FALSE);
	ti = proto_tree_add_uint(radiotap_tree, hf_radiotap_length,
	    tvb, offset + 2, 2, length);
    }
    length_remaining = length;

    /*
     * FIXME: This only works if there is exactly 1 it_present
     *        field in the header
     */
    if (length_remaining < sizeof(struct ieee80211_radiotap_header)) {
	/*
	 * Radiotap header is shorter than the fixed-length portion
	 * plus one "present" bitset.
	 */
	if (tree)
	    proto_item_append_text(ti, " (bogus - minimum length is 8)");
	return;
    }
    /* Subtree for the "present flags" bitfield. */
    if (tree) {
	pt = proto_tree_add_uint(radiotap_tree, hf_radiotap_present,
	    tvb, offset + 4, 4, present);
	present_tree = proto_item_add_subtree(pt, ett_radiotap_present);

    proto_tree_add_item(present_tree, hf_radiotap_present_tsft,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_flags,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_rate,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_channel,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_fhss,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_dbm_antsignal,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_dbm_antnoise,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_lock_quality,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_tx_attenuation,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_db_tx_attenuation,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_dbm_tx_attenuation,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_antenna,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_db_antsignal,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_db_antnoise,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_fcs,
        tvb, 4, 4, TRUE);
    proto_tree_add_item(present_tree, hf_radiotap_present_ext,
        tvb, 4, 4, TRUE);
    }
    offset += sizeof(struct ieee80211_radiotap_header);
    length_remaining -= sizeof(struct ieee80211_radiotap_header);

    rflags = 0;
    for (; present; present = next_present) {
	/* clear the least significant bit that is set */
	next_present = present & (present - 1);

	/* extract the least significant bit that is set */
	bit = BITNO_32(present ^ next_present);

	switch (bit) {
	case IEEE80211_RADIOTAP_FLAGS:
	    if (length_remaining < 1)
		break;
	    rflags = tvb_get_guint8(tvb, offset);
	    if (tree) {
        ft = proto_tree_add_item(radiotap_tree, hf_radiotap_flags,
            tvb, offset, 1, FALSE);
        flags_tree = proto_item_add_subtree(ft, ett_radiotap_flags);

		proto_tree_add_item(flags_tree, hf_radiotap_flags_cfp,
			tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_radiotap_flags_preamble,
			tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_radiotap_flags_wep,
			tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_radiotap_flags_frag,
			tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_radiotap_flags_fcs,
			tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_radiotap_flags_datapad,
			tvb, offset, 1, FALSE);
	    }
	    offset++;
	    length_remaining--;
	    break;

	case IEEE80211_RADIOTAP_RATE:
	    if (length_remaining < 1)
		break;
	    rate = tvb_get_guint8(tvb, offset) & 0x7f;
	    if (check_col(pinfo->cinfo, COL_TX_RATE)) {
		col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%d.%d",
		    rate / 2, rate & 1 ? 5 : 0);
	    }
	    if (tree) {
		proto_tree_add_uint_format(radiotap_tree, hf_radiotap_datarate,
			tvb, offset, 1, tvb_get_guint8(tvb, offset),
			"Data Rate: %d.%d Mb/s", rate / 2, rate & 1 ? 5 : 0);
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	    if (length_remaining < 1)
		break;
	    dbm = (gint8) tvb_get_guint8(tvb, offset);
	    if (check_col(pinfo->cinfo, COL_RSSI)) {
		col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
	    }
	    if (tree) {
		proto_tree_add_int_format(radiotap_tree,
					  hf_radiotap_dbm_antsignal,
					  tvb, offset, 1, dbm,
					  "SSI Signal: %d dBm", dbm);
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	    if (length_remaining < 1)
		break;
	    db = tvb_get_guint8(tvb, offset);
	    if (check_col(pinfo->cinfo, COL_RSSI)) {
		col_add_fstr(pinfo->cinfo, COL_RSSI, "%u dB", db);
	    }
	    if (tree) {
		proto_tree_add_uint_format(radiotap_tree,
					   hf_radiotap_db_antsignal,
					   tvb, offset, 1, db,
					   "SSI Signal: %u dB", db);
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	    if (length_remaining < 1)
		break;
	    dbm = (gint8) tvb_get_guint8(tvb, offset);
	    if (tree) {
		proto_tree_add_int_format(radiotap_tree,
					  hf_radiotap_dbm_antnoise,
					  tvb, offset, 1, dbm,
					  "SSI Noise: %d dBm", dbm);
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	    if (length_remaining < 1)
		break;
	    db = tvb_get_guint8(tvb, offset);
	    if (tree) {
		proto_tree_add_uint_format(radiotap_tree,
					   hf_radiotap_db_antnoise,
					   tvb, offset, 1, db,
					   "SSI Noise: %u dB", db);
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_ANTENNA:
	    if (length_remaining < 1)
		break;
	    if (tree) {
		proto_tree_add_uint(radiotap_tree, hf_radiotap_antenna,
				   tvb, offset, 1, tvb_get_guint8(tvb, offset));
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	    if (length_remaining < 1)
		break;
	    if (tree) {
		proto_tree_add_int(radiotap_tree, hf_radiotap_txpower,
				   tvb, offset, 1, tvb_get_guint8(tvb, offset));
	    }
	    offset++;
	    length_remaining--;
	    break;
	case IEEE80211_RADIOTAP_CHANNEL:
	    if (length_remaining < 4)
		break;
	    if (tree) {
		freq = tvb_get_letohs(tvb, offset);
		flags = tvb_get_letohs(tvb, offset+2);
	        proto_tree_add_uint_format(radiotap_tree, hf_radiotap_channel_frequency,
			tvb, offset, 2, freq,
			"Channel: %u (chan %u)", freq, ieee80211_mhz2ieee(freq, flags));
	        proto_tree_add_uint(radiotap_tree, hf_radiotap_channel_flags,
			tvb, offset+2, 2, flags);
	    }
	    offset+=4;
	    length_remaining-=4;
	    break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	    if (length_remaining < 2)
		break;
#if 0
	    tvb_get_letohs(tvb, offset);
#endif
	    offset+=2;
	    length_remaining-=2;
	    break;
	case IEEE80211_RADIOTAP_TSFT:
	    if (length_remaining < 8)
		break;
	    if (tree) {
		proto_tree_add_uint64(radiotap_tree, hf_radiotap_mactime,
				tvb, offset, 8, tvb_get_letoh64(tvb, offset));
	    }
	    offset+=8;
	    length_remaining-=8;
	    break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	    if (length_remaining < 2)
		break;
	    if (tree) {
		proto_tree_add_uint(radiotap_tree, hf_radiotap_quality,
				tvb, offset, 2, tvb_get_letohs(tvb, offset));
	    }
	    offset+=2;
	    length_remaining-=2;
	    break;
	case IEEE80211_RADIOTAP_FCS:
        /* This handles the case of an FCS existing inside the radiotap header. */
	    offset = roundup2(offset, 4);
	    if (length_remaining < 4)
		break;
        if (tree) {
        sent_fcs = tvb_get_ntohl(tvb, offset);
		hdr_fcs_ti = proto_tree_add_uint(radiotap_tree, hf_radiotap_fcs,
				tvb, offset, 4, sent_fcs);
        hdr_fcs_offset = offset;
        }
	    offset+=4;
	    length_remaining-=4;
	    break;
	default:
	    /*
	     * This indicates a field whose size we do not
	     * know, so we cannot proceed.
	     */
	    next_present = 0;
	    continue;
	}
    }

    /* This handles the case of an FCS exiting at the end of the frame. */
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
            calc_fcs = crc32_802_tvb(next_tvb,
                    tvb_length(next_tvb) - pinfo->pseudo_header->ieee_802_11.fcs_len);

            /* By virtue of hdr_fcs_ti being set, we know that 'tree' is set,
             * so there's no need to check it here. */
            if (calc_fcs == sent_fcs) {
                proto_item_append_text(hdr_fcs_ti, " [correct]");
            }
            else {
                proto_item_append_text(hdr_fcs_ti,
                        " [incorrect, should be 0x%08x]", calc_fcs);
                proto_tree_add_boolean_hidden(radiotap_tree, hf_radiotap_fcs_bad,
                        tvb, hdr_fcs_offset, 4, TRUE);
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

void
proto_reg_handoff_radiotap(void)
{
    dissector_handle_t radiotap_handle;

    /* handle for 802.11 dissector */
    ieee80211_handle = find_dissector("wlan");
    ieee80211_datapad_handle = find_dissector("wlan_datapad");

    radiotap_handle = create_dissector_handle(dissect_radiotap, proto_radiotap);

    dissector_add("wtap_encap", WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP, radiotap_handle);
}
