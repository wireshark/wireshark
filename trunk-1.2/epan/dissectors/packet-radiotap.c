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
#include <epan/frequency-utils.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include "packet-ieee80211.h"
#include "packet-radiotap.h"

/* Written with info from:
 *
 * http://madwifi.org/wiki/DevDocs/RadiotapHeader
 * NetBSD's ieee80211_radiotap.h file
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

#define RADIOTAP_MIN_HEADER_LEN	8	/* minimum header length */
#define RADIOTAP_VERSION_OFFSET	0	/* offset of version field */
#define RADIOTAP_LENGTH_OFFSET	2	/* offset of length field */
#define RADIOTAP_PRESENT_OFFSET	4	/* offset of "present" field */

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
    IEEE80211_RADIOTAP_RX_FLAGS = 14,
    IEEE80211_RADIOTAP_XCHANNEL = 18,
    IEEE80211_RADIOTAP_EXT = 31
};

/* Channel flags. */
#define	IEEE80211_CHAN_TURBO	0x00010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x00020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x00040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x00080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x00100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x00200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x00400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x00800	/* GFSK channel (FHSS PHY) */
#define	IEEE80211_CHAN_GSM	0x01000	/* 900 MHz spectrum channel */
#define	IEEE80211_CHAN_STURBO	0x02000	/* 11a static turbo channel only */
#define	IEEE80211_CHAN_HALF	0x04000	/* Half rate channel */
#define	IEEE80211_CHAN_QUARTER	0x08000	/* Quarter rate channel */
#define	IEEE80211_CHAN_HT20	0x10000	/* HT 20 channel */
#define	IEEE80211_CHAN_HT40U	0x20000	/* HT 40 channel w/ ext above */
#define	IEEE80211_CHAN_HT40D	0x40000	/* HT 40 channel w/ ext below */

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
#define	IEEE80211_RADIOTAP_F_BADFCS	0x40	/* does not pass FCS check */
#define	IEEE80211_RADIOTAP_F_SHORTGI	0x80	/* HT short GI */

/* For IEEE80211_RADIOTAP_RX_FLAGS */
#define IEEE80211_RADIOTAP_F_RX_BADPLCP		0x0002 /* bad PLCP */

/* XXX need max array size */
static const int ieee80211_htrates[16] = {
	13,		/* IFM_IEEE80211_MCS0 */
	26,		/* IFM_IEEE80211_MCS1 */
	39,		/* IFM_IEEE80211_MCS2 */
	52,		/* IFM_IEEE80211_MCS3 */
	78,		/* IFM_IEEE80211_MCS4 */
	104,		/* IFM_IEEE80211_MCS5 */
	117,		/* IFM_IEEE80211_MCS6 */
	130,		/* IFM_IEEE80211_MCS7 */
	26,		/* IFM_IEEE80211_MCS8 */
	52,		/* IFM_IEEE80211_MCS9 */
	78,		/* IFM_IEEE80211_MCS10 */
	104,		/* IFM_IEEE80211_MCS11 */
	156,		/* IFM_IEEE80211_MCS12 */
	208,		/* IFM_IEEE80211_MCS13 */
	234,		/* IFM_IEEE80211_MCS14 */
	260,		/* IFM_IEEE80211_MCS15 */
};

/* protocol */
static int proto_radiotap = -1;

static int hf_radiotap_version = -1;
static int hf_radiotap_pad = -1;
static int hf_radiotap_length = -1;
static int hf_radiotap_present = -1;
static int hf_radiotap_mactime = -1;
static int hf_radiotap_channel = -1;
static int hf_radiotap_channel_frequency = -1;
static int hf_radiotap_channel_flags = -1;
static int hf_radiotap_channel_flags_turbo = -1;
static int hf_radiotap_channel_flags_cck = -1;
static int hf_radiotap_channel_flags_ofdm = -1;
static int hf_radiotap_channel_flags_2ghz = -1;
static int hf_radiotap_channel_flags_5ghz = -1;
static int hf_radiotap_channel_flags_passive = -1;
static int hf_radiotap_channel_flags_dynamic = -1;
static int hf_radiotap_channel_flags_gfsk = -1;
static int hf_radiotap_channel_flags_gsm = -1;
static int hf_radiotap_channel_flags_sturbo = -1;
static int hf_radiotap_channel_flags_half = -1;
static int hf_radiotap_channel_flags_quarter = -1;
static int hf_radiotap_rxflags = -1;
static int hf_radiotap_rxflags_badplcp = -1;
static int hf_radiotap_xchannel = -1;
static int hf_radiotap_xchannel_frequency = -1;
static int hf_radiotap_xchannel_flags = -1;
static int hf_radiotap_xchannel_flags_turbo = -1;
static int hf_radiotap_xchannel_flags_cck = -1;
static int hf_radiotap_xchannel_flags_ofdm = -1;
static int hf_radiotap_xchannel_flags_2ghz = -1;
static int hf_radiotap_xchannel_flags_5ghz = -1;
static int hf_radiotap_xchannel_flags_passive = -1;
static int hf_radiotap_xchannel_flags_dynamic = -1;
static int hf_radiotap_xchannel_flags_gfsk = -1;
static int hf_radiotap_xchannel_flags_gsm = -1;
static int hf_radiotap_xchannel_flags_sturbo = -1;
static int hf_radiotap_xchannel_flags_half = -1;
static int hf_radiotap_xchannel_flags_quarter = -1;
static int hf_radiotap_xchannel_flags_ht20 = -1;
static int hf_radiotap_xchannel_flags_ht40u = -1;
static int hf_radiotap_xchannel_flags_ht40d = -1;
#if 0
static int hf_radiotap_xchannel_maxpower = -1;
#endif
static int hf_radiotap_fhss_hopset = -1;
static int hf_radiotap_fhss_pattern = -1;
static int hf_radiotap_datarate = -1;
static int hf_radiotap_antenna = -1;
static int hf_radiotap_dbm_antsignal = -1;
static int hf_radiotap_db_antsignal = -1;
static int hf_radiotap_dbm_antnoise = -1;
static int hf_radiotap_db_antnoise = -1;
static int hf_radiotap_tx_attenuation = -1;
static int hf_radiotap_db_tx_attenuation = -1;
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
static int hf_radiotap_present_hdrfcs = -1;
static int hf_radiotap_present_rxflags = -1;
static int hf_radiotap_present_xchannel = -1;
static int hf_radiotap_present_ext = -1;

/* "present.flags" flags */
static int hf_radiotap_flags = -1;
static int hf_radiotap_flags_cfp = -1;
static int hf_radiotap_flags_preamble = -1;
static int hf_radiotap_flags_wep = -1;
static int hf_radiotap_flags_frag = -1;
static int hf_radiotap_flags_fcs = -1;
static int hf_radiotap_flags_datapad = -1;
static int hf_radiotap_flags_badfcs = -1;
static int hf_radiotap_flags_shortgi = -1;

static int hf_radiotap_quality = -1;
static int hf_radiotap_fcs = -1;
static int hf_radiotap_fcs_bad = -1;

static gint ett_radiotap = -1;
static gint ett_radiotap_present = -1;
static gint ett_radiotap_flags = -1;
static gint ett_radiotap_rxflags = -1;
static gint ett_radiotap_channel_flags = -1;
static gint ett_radiotap_xchannel_flags = -1;

static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_datapad_handle;

static int radiotap_tap = -1;

/* Settings */
static gboolean radiotap_bit14_fcs = FALSE;

static void
dissect_radiotap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)	(1 << n)

/*
 * The NetBSD ieee80211_radiotap man page
 * (http://netbsd.gw.com/cgi-bin/man-cgi?ieee80211_radiotap+9+NetBSD-current)
 * says:
 *
 *    Radiotap capture fields must be naturally aligned.  That is, 16-, 32-,
 *    and 64-bit fields must begin on 16-, 32-, and 64-bit boundaries, respec-
 *    tively.  In this way, drivers can avoid unaligned accesses to radiotap
 *    capture fields.  radiotap-compliant drivers must insert padding before a
 *    capture field to ensure its natural alignment.  radiotap-compliant packet
 *    dissectors, such as tcpdump(8), expect the padding.
 */

/*
 * Returns the amount required to align "offset" with "width"
 */
#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )


void
capture_radiotap(const guchar *pd, int offset, int len, packet_counts *ld)
{
    guint16 it_len;
    guint32 present;
    guint8 rflags;

    if(!BYTES_ARE_IN_FRAME(offset, len, RADIOTAP_MIN_HEADER_LEN)) {
        ld->other ++;
        return;
    }
    it_len = pletohs(&pd[RADIOTAP_LENGTH_OFFSET]);
    if(!BYTES_ARE_IN_FRAME(offset, len, it_len)) {
        ld->other ++;
        return;
    }

    if(it_len > len) {
        /* Header length is bigger than total packet length */
        ld->other ++;
        return;
    }

    if(it_len < RADIOTAP_MIN_HEADER_LEN) {
        /* Header length is shorter than fixed-length portion of header */
        ld->other ++;
        return;
    }

    present = pletohl(&pd[RADIOTAP_PRESENT_OFFSET]);
    offset += RADIOTAP_MIN_HEADER_LEN;
    it_len -= RADIOTAP_MIN_HEADER_LEN;

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
    { IEEE80211_CHAN_A | IEEE80211_CHAN_HT20,		"802.11a (ht20)" },
    { IEEE80211_CHAN_A | IEEE80211_CHAN_HT40U,		"802.11a (ht40+)" },
    { IEEE80211_CHAN_A | IEEE80211_CHAN_HT40D,		"802.11a (ht40-)" },
    { IEEE80211_CHAN_B,		"802.11b" },
    { IEEE80211_CHAN_PUREG,	"802.11g (pure-g)" },
    { IEEE80211_CHAN_G,		"802.11g" },
    { IEEE80211_CHAN_G | IEEE80211_CHAN_HT20,		"802.11g (ht20)" },
    { IEEE80211_CHAN_G | IEEE80211_CHAN_HT40U,		"802.11g (ht40+)" },
    { IEEE80211_CHAN_G | IEEE80211_CHAN_HT40D,		"802.11g (ht40-)" },
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
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Version of radiotap header format", HFILL } },
    { &hf_radiotap_pad,
      { "Header pad", "radiotap.pad",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Padding", HFILL } },
    { &hf_radiotap_length,
       { "Header length", "radiotap.length",
	 FT_UINT16, BASE_DEC, NULL, 0x0,
	 "Length of header including version, pad, length and data fields", HFILL } },
    { &hf_radiotap_present,
       { "Present flags", "radiotap.present",
	 FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask indicating which fields are present", HFILL } },

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
#define RADIOTAP_MASK_RX_FLAGS              0x00004000
#define RADIOTAP_MASK_XCHANNEL              0x00040000
#define RADIOTAP_MASK_EXT                   0x80000000

    /* Boolean 'present' flags */
    { &hf_radiotap_present_tsft,
      { "TSFT", "radiotap.present.tsft",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_TSFT,
	"Specifies if the Time Synchronization Function Timer field is present", HFILL } },

    { &hf_radiotap_present_flags,
      { "Flags", "radiotap.present.flags",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_FLAGS,
	"Specifies if the channel flags field is present", HFILL } },

    { &hf_radiotap_present_rate,
      { "Rate", "radiotap.present.rate",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_RATE,
	"Specifies if the transmit/receive rate field is present", HFILL } },

    { &hf_radiotap_present_channel,
      { "Channel", "radiotap.present.channel",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_CHANNEL,
	"Specifies if the transmit/receive frequency field is present", HFILL } },

    { &hf_radiotap_present_fhss,
      { "FHSS", "radiotap.present.fhss",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_FHSS,
	"Specifies if the hop set and pattern is present for frequency hopping radios", HFILL } },

    { &hf_radiotap_present_dbm_antsignal,
      { "DBM Antenna Signal", "radiotap.present.dbm_antsignal",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DBM_ANTSIGNAL,
	"Specifies if the antenna signal strength in dBm is present", HFILL } },

    { &hf_radiotap_present_dbm_antnoise,
      { "DBM Antenna Noise", "radiotap.present.dbm_antnoise",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DBM_ANTNOISE,
	"Specifies if the RF noise power at antenna field is present", HFILL } },

    { &hf_radiotap_present_lock_quality,
      { "Lock Quality", "radiotap.present.lock_quality",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_LOCK_QUALITY,
	"Specifies if the signal quality field is present", HFILL } },

    { &hf_radiotap_present_tx_attenuation,
      { "TX Attenuation", "radiotap.present.tx_attenuation",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_TX_ATTENUATION,
	"Specifies if the transmit power from max power field is present", HFILL } },

    { &hf_radiotap_present_db_tx_attenuation,
      { "DB TX Attenuation", "radiotap.present.db_tx_attenuation",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DB_TX_ATTENUATION,
	"Specifies if the transmit power from max power (in dB) field is present", HFILL } },

    { &hf_radiotap_present_dbm_tx_attenuation,
      { "DBM TX Attenuation", "radiotap.present.dbm_tx_attenuation",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DBM_TX_ATTENUATION,
	"Specifies if the transmit power from max power (in dBm) field is present", HFILL } },

    { &hf_radiotap_present_antenna,
      { "Antenna", "radiotap.present.antenna",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_ANTENNA,
	"Specifies if the antenna number field is present", HFILL } },

    { &hf_radiotap_present_db_antsignal,
      { "DB Antenna Signal", "radiotap.present.db_antsignal",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DB_ANTSIGNAL,
	"Specifies if the RF signal power at antenna in dB field is present", HFILL } },

    { &hf_radiotap_present_db_antnoise,
      { "DB Antenna Noise", "radiotap.present.db_antnoise",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_DB_ANTNOISE,
	"Specifies if the RF signal power at antenna in dBm field is present", HFILL } },

    { &hf_radiotap_present_rxflags,
      { "RX flags", "radiotap.present.rxflags",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_RX_FLAGS,
	"Specifies if the RX flags field is present", HFILL } },

    { &hf_radiotap_present_hdrfcs,
      { "FCS in header", "radiotap.present.fcs",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_RX_FLAGS,
	"Specifies if the FCS field is present", HFILL } },

    { &hf_radiotap_present_xchannel,
      { "Channel+", "radiotap.present.xchannel",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_XCHANNEL,
	"Specifies if the extended channel info field is present", HFILL } },

    { &hf_radiotap_present_ext,
      { "Ext", "radiotap.present.ext",
	FT_BOOLEAN, 32, NULL, RADIOTAP_MASK_EXT,
	"Specifies if there are any extensions to the header present", HFILL } },

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
    "Frame has padding between 802.11 header and payload", HFILL } },

    { &hf_radiotap_flags_badfcs,
      { "Bad FCS", "radiotap.flags.badfcs",
	FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_BADFCS,
        "Frame received with bad FCS", HFILL } },

    { &hf_radiotap_flags_shortgi,
      { "Short GI", "radiotap.flags.shortgi",
	FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_SHORTGI,
    "Frame Sent/Received with HT short Guard Interval", HFILL } },


    { &hf_radiotap_mactime,
       { "MAC timestamp", "radiotap.mactime",
	 FT_UINT64, BASE_DEC, NULL, 0x0,
	 " Value in microseconds of the MAC's Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC.", HFILL } },

    { &hf_radiotap_quality,
       { "Signal Quality", "radiotap.quality",
	 FT_UINT16, BASE_DEC, NULL, 0x0,
	 "Signal quality (unitless measure)", HFILL } },

    { &hf_radiotap_fcs,
       { "802.11 FCS", "radiotap.fcs",
	 FT_UINT32, BASE_HEX, NULL, 0x0,
	 "Frame check sequence of this frame", HFILL } },

    { &hf_radiotap_channel,
      { "Channel", "radiotap.channel",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"802.11 channel number that this frame was sent/received on", HFILL } },

    { &hf_radiotap_channel_frequency,
      { "Channel frequency", "radiotap.channel.freq",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Channel frequency in megahertz that this frame was sent/received on", HFILL } },

    { &hf_radiotap_channel_flags,
      { "Channel type", "radiotap.channel.type",
	FT_UINT16, BASE_HEX, VALS(phy_type), 0x0,
	"Channel type", HFILL } },

    { &hf_radiotap_channel_flags_turbo,
       { "Turbo", "radiotap.channel.type.turbo",
	 FT_BOOLEAN, 16, NULL, 0x0010, "Channel Type Turbo", HFILL } },
    { &hf_radiotap_channel_flags_cck,
       { "Complementary Code Keying (CCK)", "radiotap.channel.type.cck",
	 FT_BOOLEAN, 16, NULL, 0x0020, "Channel Type Complementary Code Keying (CCK) Modulation", HFILL } },
    { &hf_radiotap_channel_flags_ofdm,
       { "Orthogonal Frequency-Division Multiplexing (OFDM)", "radiotap.channel.type.ofdm",
	 FT_BOOLEAN, 16, NULL, 0x0040, "Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL } },
    { &hf_radiotap_channel_flags_2ghz,
       { "2 GHz spectrum", "radiotap.channel.type.2ghz",
	 FT_BOOLEAN, 16, NULL, 0x0080, "Channel Type 2 GHz spectrum", HFILL } },
    { &hf_radiotap_channel_flags_5ghz,
       { "5 GHz spectrum", "radiotap.channel.type.5ghz",
	 FT_BOOLEAN, 16, NULL, 0x0100, "Channel Type 5 GHz spectrum", HFILL } },
    { &hf_radiotap_channel_flags_passive,
       { "Passive", "radiotap.channel.type.passive",
	 FT_BOOLEAN, 16, NULL, 0x0200, "Channel Type Passive", HFILL } },
    { &hf_radiotap_channel_flags_dynamic,
       { "Dynamic CCK-OFDM", "radiotap.channel.type.dynamic",
	 FT_BOOLEAN, 16, NULL, 0x0400, "Channel Type Dynamic CCK-OFDM Channel", HFILL } },
    { &hf_radiotap_channel_flags_gfsk,
       { "Gaussian Frequency Shift Keying (GFSK)", "radiotap.channel.type.gfsk",
	 FT_BOOLEAN, 16, NULL, 0x0800, "Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation", HFILL } },
    { &hf_radiotap_channel_flags_gsm,
       { "GSM (900MHz)", "radiotap.channel.type.gsm",
	 FT_BOOLEAN, 16, NULL, 0x1000, "Channel Type GSM", HFILL } },
    { &hf_radiotap_channel_flags_sturbo,
       { "Static Turbo", "radiotap.channel.type.sturbo",
	 FT_BOOLEAN, 16, NULL, 0x2000, "Channel Type Status Turbo", HFILL } },
    { &hf_radiotap_channel_flags_half,
       { "Half Rate Channel (10MHz Channel Width)", "radiotap.channel.type.half",
	 FT_BOOLEAN, 16, NULL, 0x4000, "Channel Type Half Rate", HFILL } },
    { &hf_radiotap_channel_flags_quarter,
       { "Quarter Rate Channel (5MHz Channel Width)", "radiotap.channel.type.quarter",
	 FT_BOOLEAN, 16, NULL, 0x8000, "Channel Type Quarter Rate", HFILL } },

    { &hf_radiotap_rxflags,
      { "RX flags", "radiotap.rxflags",
	FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL } },

    { &hf_radiotap_rxflags_badplcp,
       { "Bad PLCP", "radiotap.rxflags.badplcp",
	 FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_RX_BADPLCP,
	 "Frame with bad PLCP", HFILL } },

    { &hf_radiotap_xchannel,
      { "Channel number", "radiotap.xchannel",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_xchannel_frequency,
      { "Channel frequency", "radiotap.xchannel.freq",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_radiotap_xchannel_flags,
      { "Channel type", "radiotap.xchannel.flags",
	FT_UINT32, BASE_HEX, VALS(phy_type), 0x0, "", HFILL } },

    { &hf_radiotap_xchannel_flags_turbo,
       { "Turbo", "radiotap.xchannel.type.turbo",
	 FT_BOOLEAN, 24, NULL, 0x0010, "Channel Type Turbo", HFILL } },
    { &hf_radiotap_xchannel_flags_cck,
       { "Complementary Code Keying (CCK)", "radiotap.xchannel.type.cck",
	 FT_BOOLEAN, 24, NULL, 0x0020, "Channel Type Complementary Code Keying (CCK) Modulation", HFILL } },
    { &hf_radiotap_xchannel_flags_ofdm,
       { "Orthogonal Frequency-Division Multiplexing (OFDM)", "radiotap.xchannel.type.ofdm",
	 FT_BOOLEAN, 24, NULL, 0x0040, "Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL } },
    { &hf_radiotap_xchannel_flags_2ghz,
       { "2 GHz spectrum", "radiotap.xchannel.type.2ghz",
	 FT_BOOLEAN, 24, NULL, 0x0080, "Channel Type 2 GHz spectrum", HFILL } },
    { &hf_radiotap_xchannel_flags_5ghz,
       { "5 GHz spectrum", "radiotap.xchannel.type.5ghz",
	 FT_BOOLEAN, 24, NULL, 0x0100, "Channel Type 5 GHz spectrum", HFILL } },
    { &hf_radiotap_xchannel_flags_passive,
       { "Passive", "radiotap.channel.xtype.passive",
	 FT_BOOLEAN, 24, NULL, 0x0200, "Channel Type Passive", HFILL } },
    { &hf_radiotap_xchannel_flags_dynamic,
       { "Dynamic CCK-OFDM", "radiotap.xchannel.type.dynamic",
	 FT_BOOLEAN, 24, NULL, 0x0400, "Channel Type Dynamic CCK-OFDM Channel", HFILL } },
    { &hf_radiotap_xchannel_flags_gfsk,
       { "Gaussian Frequency Shift Keying (GFSK)", "radiotap.xchannel.type.gfsk",
	 FT_BOOLEAN, 24, NULL, 0x0800, "Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation", HFILL } },
    { &hf_radiotap_xchannel_flags_gsm,
       { "GSM (900MHz)", "radiotap.xchannel.type.gsm",
	 FT_BOOLEAN, 24, NULL, 0x1000, "Channel Type GSM", HFILL } },
    { &hf_radiotap_xchannel_flags_sturbo,
       { "Static Turbo", "radiotap.xchannel.type.sturbo",
	 FT_BOOLEAN, 24, NULL, 0x2000, "Channel Type Status Turbo", HFILL } },
    { &hf_radiotap_xchannel_flags_half,
       { "Half Rate Channel (10MHz Channel Width)", "radiotap.xchannel.type.half",
	 FT_BOOLEAN, 24, NULL, 0x4000, "Channel Type Half Rate", HFILL } },
    { &hf_radiotap_xchannel_flags_quarter,
       { "Quarter Rate Channel (5MHz Channel Width)", "radiotap.xchannel.type.quarter",
	 FT_BOOLEAN, 24, NULL, 0x8000, "Channel Type Quarter Rate", HFILL } },
    { &hf_radiotap_xchannel_flags_ht20,
       { "HT Channel (20MHz Channel Width)", "radiotap.xchannel.type.ht20",
	 FT_BOOLEAN, 24, NULL, 0x10000, "Channel Type HT/20", HFILL } },
    { &hf_radiotap_xchannel_flags_ht40u,
       { "HT Channel (40MHz Channel Width with Extension channel above)", "radiotap.xchannel.type.ht40u",
	 FT_BOOLEAN, 24, NULL, 0x20000, "Channel Type HT/40+", HFILL } },
    { &hf_radiotap_xchannel_flags_ht40d,
       { "HT Channel (40MHz Channel Width with Extension channel below)", "radiotap.xchannel.type.ht40d",
	 FT_BOOLEAN, 24, NULL, 0x40000, "Channel Type HT/40-", HFILL } },
#if 0
    { &hf_radiotap_xchannel_maxpower,
      { "Max transmit power", "radiotap.xchannel.maxpower",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
#endif
    { &hf_radiotap_fhss_hopset,
      { "FHSS Hop Set", "radiotap.fhss.hopset",
	FT_UINT8, BASE_DEC, NULL,  0x0,
	"Frequency Hopping Spread Spectrum hopset", HFILL } },

    { &hf_radiotap_fhss_pattern,
      { "FHSS Pattern", "radiotap.fhss.pattern",
	FT_UINT8, BASE_DEC, NULL,  0x0,
	"Frequency Hopping Spread Spectrum hop pattern", HFILL } },

    { &hf_radiotap_datarate,
      { "Data rate", "radiotap.datarate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Speed this frame was sent/received at", HFILL } },

    { &hf_radiotap_antenna,
      { "Antenna", "radiotap.antenna",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Antenna number this frame was sent/received over (starting at 0)", HFILL } },

    { &hf_radiotap_dbm_antsignal,
      { "SSI Signal (dBm)", "radiotap.dbm_antsignal",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_db_antsignal,
      { "SSI Signal (dB)", "radiotap.db_antsignal",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"RF signal power at the antenna from a fixed, arbitrary value in decibels", HFILL } },

    { &hf_radiotap_dbm_antnoise,
      { "SSI Noise (dBm)", "radiotap.dbm_antnoise",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"RF noise power at the antenna from a fixed, arbitrary value in decibels per one milliwatt", HFILL } },

    { &hf_radiotap_db_antnoise,
      { "SSI Noise (dB)", "radiotap.db_antnoise",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"RF noise power at the antenna from a fixed, arbitrary value in decibels", HFILL } },

    { &hf_radiotap_tx_attenuation,
      { "Transmit attenuation", "radiotap.txattenuation",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Transmit power expressed as unitless distance from max power set at factory (0 is max power)", HFILL } },

    { &hf_radiotap_db_tx_attenuation,
      { "Transmit attenuation (dB)", "radiotap.db_txattenuation",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Transmit power expressed as decibels from max power set at factory (0 is max power)", HFILL } },

    { &hf_radiotap_txpower,
      { "Transmit power", "radiotap.txpower",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"Transmit power in decibels per one milliwatt (dBm)", HFILL } },

    /* Special variables */
    { &hf_radiotap_fcs_bad,
      { "Bad FCS", "radiotap.fcs_bad",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Specifies if this frame has a bad frame check sequence", HFILL } },

  };
  static gint *ett[] = {
    &ett_radiotap,
    &ett_radiotap_present,
    &ett_radiotap_flags,
    &ett_radiotap_rxflags,
    &ett_radiotap_channel_flags,
    &ett_radiotap_xchannel_flags
  };
  module_t *radiotap_module;

  proto_radiotap = proto_register_protocol("IEEE 802.11 Radiotap Capture header", "802.11 Radiotap", "radiotap");
  proto_register_field_array(proto_radiotap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("radiotap", dissect_radiotap, proto_radiotap);

  radiotap_tap = register_tap("radiotap");

  radiotap_module = prefs_register_protocol(proto_radiotap, NULL);
  prefs_register_bool_preference(radiotap_module, "bit14_fcs_in_header",
      "Assume bit 14 means FCS in header",
      "Radiotap has a bit to indicate whether the FCS is still on the frame or not. "
      "Some generators (e.g. AirPcap) use a non-standard radiotap flag 14 to put "
      "the FCS into the header.",
      &radiotap_bit14_fcs);
}

static void
dissect_radiotap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *radiotap_tree = NULL;
    proto_tree *pt, *present_tree = NULL;
    proto_tree *ft, *flags_tree = NULL;
    proto_item *ti = NULL, *hidden_item;
    int align_offset, offset;
    tvbuff_t *next_tvb;
    guint32 version;
    guint length, length_remaining;
    guint32 rate, freq, flags;
    gint8 dbm;
    guint8 db, rflags;
    guint32 present, next_present;
    int bit;
    /* backward compat with bit 14 == fcs in header */
    proto_item *hdr_fcs_ti = NULL;
    int hdr_fcs_offset = 0;
    guint32 sent_fcs = 0;
    guint32 calc_fcs;

    struct _radiotap_info *radiotap_info;
    static struct _radiotap_info rtp_info_arr[1];
    
    radiotap_info = &rtp_info_arr[0];

    if(check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
    if(check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);
    offset = 0;

    version = tvb_get_guint8(tvb, offset);
    length = tvb_get_letohs(tvb, offset+2);
    present = tvb_get_letohl(tvb, offset+4);
    
    radiotap_info->radiotap_length = length;

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
    if (length_remaining < RADIOTAP_MIN_HEADER_LEN) {
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
	if (radiotap_bit14_fcs) {
		proto_tree_add_item(present_tree, hf_radiotap_present_hdrfcs,
			tvb, 4, 4, TRUE);
	} else {
		proto_tree_add_item(present_tree, hf_radiotap_present_rxflags,
			tvb, 4, 4, TRUE);
	}
	proto_tree_add_item(present_tree, hf_radiotap_present_xchannel,
	    tvb, 4, 4, TRUE);
	proto_tree_add_item(present_tree, hf_radiotap_present_ext,
	    tvb, 4, 4, TRUE);
    }
    offset += RADIOTAP_MIN_HEADER_LEN;
    length_remaining -= RADIOTAP_MIN_HEADER_LEN;

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
		proto_tree_add_item(flags_tree, hf_radiotap_flags_badfcs,
			tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_radiotap_flags_shortgi,
			tvb, offset, 1, FALSE);
	    }
	    offset++;
	    length_remaining--;
	    break;

	case IEEE80211_RADIOTAP_RATE:
	    if (length_remaining < 1)
		break;
	    rate = tvb_get_guint8(tvb, offset);
	    if (rate & 0x80) {
		/* XXX adjust by CW and short GI like other sniffers? */
		rate = ieee80211_htrates[rate & 0xf];
	    }
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
            radiotap_info->rate = rate;
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
            radiotap_info->dbm_antsignal=dbm;
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
            radiotap_info->dbm_antnoise=dbm;
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
	{
	    proto_item *it;
	    proto_tree *flags_tree;
	    gchar *chan_str;

	    align_offset = ALIGN_OFFSET(offset, 2);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 2)
		break;
	    if (tree) {
		freq = tvb_get_letohs(tvb, offset);
		flags = tvb_get_letohs(tvb, offset+2);
		chan_str = ieee80211_mhz_to_str(freq);
		if (check_col(pinfo->cinfo, COL_FREQ_CHAN)) {
		    col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%s", chan_str);
		}
		proto_tree_add_uint_format(radiotap_tree, hf_radiotap_channel_frequency,
				tvb, offset, 2, freq,
				"Channel frequency: %s", chan_str);
		g_free(chan_str);
		/* We're already 2-byte aligned. */
		it = proto_tree_add_uint(radiotap_tree, hf_radiotap_channel_flags,
			tvb, offset+2, 2, flags);
		flags_tree = proto_item_add_subtree(it, ett_radiotap_channel_flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_turbo,
			tvb, offset+2, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_cck,
			tvb, offset+2, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_ofdm,
			tvb, offset+2, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_2ghz,
			tvb, offset+2, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_5ghz,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_passive,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_dynamic,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_gfsk,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_gsm,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_sturbo,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_half,
			tvb, offset+3, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_channel_flags_quarter,
			tvb, offset+3, 1, flags);
                radiotap_info->freq=freq;
                radiotap_info->flags=flags;
	    }
	    offset+=4 /* Channel + flags */;
	    length_remaining-=4;
	    break;
	}
	case IEEE80211_RADIOTAP_XCHANNEL: {
	    proto_item *it;
	    proto_tree *flags_tree;

	    align_offset = ALIGN_OFFSET(offset, 4);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 8)
		break;
	    if (tree) {
	        int channel;
	        guint8 maxpower;

		flags = tvb_get_letohl(tvb, offset);
		freq = tvb_get_letohs(tvb, offset+4);
		channel = tvb_get_guint8(tvb, offset+6);
		maxpower = tvb_get_guint8(tvb, offset+7);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_xchannel,
			tvb, offset+6, 1, (guint32) channel);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_xchannel_frequency,
			tvb, offset+4, 2, freq);
		it = proto_tree_add_uint(radiotap_tree, hf_radiotap_xchannel_flags,
			tvb, offset+0, 4, flags);
		flags_tree = proto_item_add_subtree(it, ett_radiotap_xchannel_flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_turbo,
			tvb, offset+0, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_cck,
			tvb, offset+0, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_ofdm,
			tvb, offset+0, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_2ghz,
			tvb, offset+0, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_5ghz,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_passive,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_dynamic,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_gfsk,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_gsm,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_sturbo,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_half,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_quarter,
			tvb, offset+1, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_ht20,
			tvb, offset+2, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_ht40u,
			tvb, offset+2, 1, flags);
		proto_tree_add_boolean(flags_tree, hf_radiotap_xchannel_flags_ht40d,
			tvb, offset+2, 1, flags);
#if 0
		proto_tree_add_uint(radiotap_tree, hf_radiotap_xchannel_maxpower,
			tvb, offset+7, 1, maxpower);
#endif
	    }
	    offset+=8 /* flags + freq + ieee + maxregpower */;
	    length_remaining-=8;
	    break;
	}
	case IEEE80211_RADIOTAP_FHSS:
	    align_offset = ALIGN_OFFSET(offset, 2);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 2)
		break;
	    proto_tree_add_item(radiotap_tree, hf_radiotap_fhss_hopset,
		tvb, offset, 1, FALSE);
	    proto_tree_add_item(radiotap_tree, hf_radiotap_fhss_pattern,
		tvb, offset, 1, FALSE);
	    offset+=2;
	    length_remaining-=2;
	    break;
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	    align_offset = ALIGN_OFFSET(offset, 2);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 2)
		break;
	    proto_tree_add_item(radiotap_tree, hf_radiotap_tx_attenuation,
		tvb, offset, 2, FALSE);
	    offset+=2;
	    length_remaining-=2;
	    break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	    align_offset = ALIGN_OFFSET(offset, 2);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 2)
		break;
	    proto_tree_add_item(radiotap_tree, hf_radiotap_db_tx_attenuation,
		tvb, offset, 2, FALSE);
	    offset+=2;
	    length_remaining-=2;
	    break;
	case IEEE80211_RADIOTAP_TSFT:
	    align_offset = ALIGN_OFFSET(offset, 8);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 8)
		break;
            radiotap_info->tsft=tvb_get_letoh64(tvb, offset);
	    if (tree) {
		proto_tree_add_uint64(radiotap_tree, hf_radiotap_mactime,
				tvb, offset, 8,radiotap_info->tsft );
	    }
	    offset+=8;
	    length_remaining-=8;
	    break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	    align_offset = ALIGN_OFFSET(offset, 2);
	    offset += align_offset;
	    length_remaining -= align_offset;
	    if (length_remaining < 2)
		break;
	    if (tree) {
		proto_tree_add_uint(radiotap_tree, hf_radiotap_quality,
				tvb, offset, 2, tvb_get_letohs(tvb, offset));
	    }
	    offset+=2;
	    length_remaining-=2;
	    break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
	    if (radiotap_bit14_fcs) {
	        align_offset = ALIGN_OFFSET(offset, 4);
	        offset += align_offset;
	        length_remaining -= align_offset;
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
	    } else {
	        proto_item *it;

                align_offset = ALIGN_OFFSET(offset, 2);
                offset += align_offset;
                length_remaining -= align_offset;
                if (length_remaining < 2)
                    break;
                if (tree) {
                    flags = tvb_get_letohs(tvb, offset);
                    it = proto_tree_add_uint(radiotap_tree, hf_radiotap_rxflags,
                            tvb, offset, 2, flags);
                    flags_tree = proto_item_add_subtree(it, ett_radiotap_rxflags);
                    proto_tree_add_boolean(flags_tree, hf_radiotap_rxflags_badplcp,
                            tvb, offset, 1, flags);
                }
                offset+=2;
                length_remaining-=2;
            }
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

    /* If we had an in-header FCS, check it.
     * This can only happen if the backward-compat configuration option
     * is chosen by the user. */
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
                hidden_item = proto_tree_add_boolean(radiotap_tree, hf_radiotap_fcs_bad,
                        tvb, hdr_fcs_offset, 4, TRUE);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
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
    
    tap_queue_packet(radiotap_tap, pinfo, radiotap_info);
}

void
proto_reg_handoff_radiotap(void)
{
    dissector_handle_t radiotap_handle;

    /* handle for 802.11 dissector */
    ieee80211_handle = find_dissector("wlan");
    ieee80211_datapad_handle = find_dissector("wlan_datapad");

    radiotap_handle = find_dissector("radiotap");

    dissector_add("wtap_encap", WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP, radiotap_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 noexpandtab
 * :indentSize=4:tabSize=8:noTabs=false:
 */

