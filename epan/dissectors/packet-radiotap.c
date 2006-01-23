/*
 *  packet-radiotap.c
 *	Decode packets with a Radiotap header
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "packet-ieee80211.h"
#include "packet-radiotap.h"

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
static int hf_radiotap_present1 = -1;
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
static int hf_radiotap_preamble = -1;
static int hf_radiotap_fcs = -1;
static int hf_radiotap_datapad = -1;

static gint ett_radiotap = -1;
static gint ett_radiotap_present = -1;

static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_datapad_handle;

static void
dissect_radiotap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void
capture_radiotap(const guchar *pd, int offset, int len, packet_counts *ld)
{
    const struct ieee80211_radiotap_header *hdr;

    if(!BYTES_ARE_IN_FRAME(offset, len, (int)sizeof(*hdr))) {
        ld->other ++;
        return;
    }
    hdr = (const struct ieee80211_radiotap_header *)pd;
    if(!BYTES_ARE_IN_FRAME(offset, len, hdr->it_len)) {
        ld->other ++;
        return;
    }

    /* 802.11 header follows */
    capture_ieee80211(pd, offset + hdr->it_len, len, ld);
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

  static const value_string preamble_type[] = {
    { 0, "Long" },
    { 1, "Short" },
    { 0, NULL },
  };

  static const value_string truefalse_type[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL },
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
    { &hf_radiotap_present1,
       { "Present elements", "radiotap.present",
	 FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },

    { &hf_radiotap_preamble,
      { "Preamble", "radiotap.flags.preamble",
	FT_UINT32, BASE_DEC, VALS(preamble_type), 0x0, "", HFILL } },

    /* XXX for debugging */
    { &hf_radiotap_fcs,
      { "FCS", "radiotap.flags.fcs",
	FT_UINT32, BASE_DEC, VALS(truefalse_type), 0x0, "", HFILL } },
    { &hf_radiotap_datapad,
      { "DATAPAD", "radiotap.flags.datapad",
	FT_UINT32, BASE_DEC, VALS(truefalse_type), 0x0, "", HFILL } },

    { &hf_radiotap_mactime,
       { "MAC timestamp", "radiotap.mactime",
	 FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL } },
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
  };
  static gint *ett[] = {
    &ett_radiotap,
    &ett_radiotap_present
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
#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)	(1 << n)
    proto_tree *radiotap_tree = NULL;
    proto_tree *pt, *present_tree;
    proto_item *ti;
    int offset;
    guint32 version, pad;
    guint32 length;
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
    pad = tvb_get_guint8(tvb, offset+1);
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
	proto_tree_add_uint(radiotap_tree, hf_radiotap_pad,
	    tvb, offset + 1, 1, pad);
	proto_tree_add_uint(radiotap_tree, hf_radiotap_length,
	    tvb, offset + 2, 2, length);
	pt = proto_tree_add_uint_format(radiotap_tree, hf_radiotap_present1,
	    tvb, offset + 4, 4, present, "Present flags (0x%08x)", present);
	present_tree = proto_item_add_subtree(pt, ett_radiotap_present);
    }
    /*
     * FIXME: This only works if there is exactly 1 it_present
     *        field in the header
     */
    offset += sizeof(struct ieee80211_radiotap_header);

    rflags = 0;
    for (; present; present = next_present) {
	/* clear the least significant bit that is set */
	next_present = present & (present - 1);

	/* extract the least significant bit that is set */
	bit = BITNO_32(present ^ next_present);

	switch (bit) {
	case IEEE80211_RADIOTAP_FLAGS:
	    rflags = tvb_get_guint8(tvb, offset);
	    if (tree) {
		proto_tree_add_uint(radiotap_tree, hf_radiotap_preamble,
			tvb, 0, 0, (rflags&IEEE80211_RADIOTAP_F_SHORTPRE) != 0);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_fcs,
			tvb, 0, 0, (rflags&IEEE80211_RADIOTAP_F_FCS) != 0);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_datapad,
			tvb, 0, 0, (rflags&IEEE80211_RADIOTAP_F_DATAPAD) != 0);
	    }
	    offset++;
	    /* XXX CFP, WEP, FRAG */
	    break;
	case IEEE80211_RADIOTAP_RATE:
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
	    break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
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
	    break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
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
	    break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	    dbm = (gint8) tvb_get_guint8(tvb, offset);
	    if (tree) {
		proto_tree_add_int_format(radiotap_tree,
					  hf_radiotap_dbm_antnoise,
					  tvb, offset, 1, dbm,
					  "SSI Noise: %d dBm", dbm);
	    }
	    offset++;
	    break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	    db = tvb_get_guint8(tvb, offset);
	    if (tree) {
		proto_tree_add_uint_format(radiotap_tree,
					   hf_radiotap_db_antnoise,
					   tvb, offset, 1, db,
					   "SSI Noise: %u dB", db);
	    }
	    offset++;
	    break;
	case IEEE80211_RADIOTAP_ANTENNA:
	    if (tree) {
		proto_tree_add_uint(radiotap_tree, hf_radiotap_antenna,
				   tvb, offset, 1, tvb_get_guint8(tvb, offset));
	    }
	    offset++;
	    break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	    if (tree) {
		proto_tree_add_int(radiotap_tree, hf_radiotap_txpower,
				   tvb, offset, 1, tvb_get_guint8(tvb, offset));
	    }
	    offset++;
	    break;
	case IEEE80211_RADIOTAP_CHANNEL:
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
	    break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
#if 0
	    tvb_get_letohs(tvb, offset);
#endif
	    offset+=2;
	    break;
	case IEEE80211_RADIOTAP_TSFT:
	    if (tree) {
		proto_tree_add_uint64(radiotap_tree, hf_radiotap_mactime,
				tvb, offset, 8, tvb_get_letoh64(tvb, offset));
	    }
	    offset+=8;
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

    if (rflags & IEEE80211_RADIOTAP_F_FCS)
	pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
    /* dissect the 802.11 header next */
    call_dissector((rflags & IEEE80211_RADIOTAP_F_DATAPAD) ?
	ieee80211_datapad_handle : ieee80211_handle,
	tvb_new_subset(tvb, length, -1, -1), pinfo, tree);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
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
