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
#include "config.h"
#endif

#include <glib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/crc32-tvb.h>
#include <epan/frequency-utils.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include "packet-ieee80211.h"
#include "packet-radiotap.h"
#include "packet-radiotap-iter.h"
#include "packet-radiotap-defs.h"

/* not officially defined (yet) */
#define IEEE80211_RADIOTAP_F_SHORTGI	0x80
#define IEEE80211_RADIOTAP_XCHANNEL	18
#define IEEE80211_CHAN_HT20		0x10000	/* HT 20 channel */
#define IEEE80211_CHAN_HT40U		0x20000	/* HT 40 channel w/ ext above */
#define IEEE80211_CHAN_HT40D		0x40000	/* HT 40 channel w/ ext below */

/* Official specifcation:
 *
 * http://www.radiotap.org/
 *
 * Unofficial and historical specifications:
 * http://madwifi-project.org/wiki/DevDocs/RadiotapHeader
 * NetBSD's ieee80211_radiotap.h file
 */

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

#define MAX_MCS_INDEX	76

/*
 * Indices are:
 *
 *	the MCS index (0-76);
 *
 *	0 for 20 MHz, 1 for 40 MHz;
 *
 *	0 for a long guard interval, 1 for a short guard interval.
 */
static const float ieee80211_float_htrates[MAX_MCS_INDEX+1][2][2] = {
	/* MCS  0  */
	{	/* 20 Mhz */ {    6.5f,		/* SGI */    7.2f, },
		/* 40 Mhz */ {   13.5f,		/* SGI */   15.0f, },
	},

	/* MCS  1  */
	{	/* 20 Mhz */ {   13.0f,		/* SGI */   14.4f, },
		/* 40 Mhz */ {   27.0f,		/* SGI */   30.0f, },
	},

	/* MCS  2  */
	{	/* 20 Mhz */ {   19.5f,		/* SGI */   21.7f, },
		/* 40 Mhz */ {   40.5f,		/* SGI */   45.0f, },
	},

	/* MCS  3  */
	{	/* 20 Mhz */ {   26.0f,		/* SGI */   28.9f, },
		/* 40 Mhz */ {   54.0f,		/* SGI */   60.0f, },
	},

	/* MCS  4  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS  5  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS  6  */
	{	/* 20 Mhz */ {   58.5f,		/* SGI */   65.0f, },
		/* 40 Mhz */ {  121.5f,		/* SGI */  135.0f, },
	},

	/* MCS  7  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {   135.0f,	/* SGI */  150.0f, },
	},

	/* MCS  8  */
	{	/* 20 Mhz */ {   13.0f,		/* SGI */   14.4f, },
		/* 40 Mhz */ {   27.0f,		/* SGI */   30.0f, },
	},

	/* MCS  9  */
	{	/* 20 Mhz */ {   26.0f,		/* SGI */   28.9f, },
		/* 40 Mhz */ {   54.0f,		/* SGI */   60.0f, },
	},

	/* MCS 10  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS 11  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 12  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 13  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 14  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 15  */
	{	/* 20 Mhz */ {  130.0f,		/* SGI */  144.4f, },
		/* 40 Mhz */ {  270.0f,		/* SGI */  300.0f, },
	},

	/* MCS 16  */
	{	/* 20 Mhz */ {   19.5f,		/* SGI */   21.7f, },
		/* 40 Mhz */ {   40.5f,		/* SGI */   45.0f, },
	},

	/* MCS 17  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS 18  */
	{	/* 20 Mhz */ {   58.5f,		/* SGI */   65.0f, },
		/* 40 Mhz */ {  121.5f,		/* SGI */  135.0f, },
	},

	/* MCS 19  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 20  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 21  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 22  */
	{	/* 20 Mhz */ {  175.5f,		/* SGI */  195.0f, },
		/* 40 Mhz */ {  364.5f,		/* SGI */  405.0f, },
	},

	/* MCS 23  */
	{	/* 20 Mhz */ {  195.0f,		/* SGI */  216.7f, },
		/* 40 Mhz */ {  405.0f,		/* SGI */  450.0f, },
	},

	/* MCS 24  */
	{	/* 20 Mhz */ {   26.0f,		/* SGI */   28.9f, },
		/* 40 Mhz */ {   54.0f,		/* SGI */   60.0f, },
	},

	/* MCS 25  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 26  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 27  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 28  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 29  */
	{	/* 20 Mhz */ {  208.0f,		/* SGI */  231.1f, },
		/* 40 Mhz */ {  432.0f,		/* SGI */  480.0f, },
	},

	/* MCS 30  */
	{	/* 20 Mhz */ {  234.0f,		/* SGI */  260.0f, },
		/* 40 Mhz */ {  486.0f,		/* SGI */  540.0f, },
	},

	/* MCS 31  */
	{	/* 20 Mhz */ {  260.0f,		/* SGI */  288.9f, },
		/* 40 Mhz */ {  540.0f,		/* SGI */  600.0f, },
	},

	/* MCS 32  */
	{	/* 20 Mhz */ {    0.0f,		/* SGI */    0.0f, }, /* not valid */
		/* 40 Mhz */ {    6.0f,		/* SGI */    6.7f, },
	},

	/* MCS 33  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS 34  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 35  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 36  */
	{	/* 20 Mhz */ {   58.5f,		/* SGI */   65.0f, },
		/* 40 Mhz */ {  121.5f,		/* SGI */  135.0f, },
	},

	/* MCS 37  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 38  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 39  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 40  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 41  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 42  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 43  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 44  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 45  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 46  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 47  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 48  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 49  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 50  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 51  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 52  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 53  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 54  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 55  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 56  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 57  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 58  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 59  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 60  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 61  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 62  */
	{	/* 20 Mhz */ {  130.0f,		/* SGI */  144.4f, },
		/* 40 Mhz */ {  270.0f,		/* SGI */  300.0f, },
	},

	/* MCS 63  */
	{	/* 20 Mhz */ {  130.0f,		/* SGI */  144.4f, },
		/* 40 Mhz */ {  270.0f,		/* SGI */  300.0f, },
	},

	/* MCS 64  */
	{	/* 20 Mhz */ {  143.0f,		/* SGI */  158.9f, },
		/* 40 Mhz */ {  297.0f,		/* SGI */  330.0f, },
	},

	/* MCS 65  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 66  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 67  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 68  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 69  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 70  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 71  */
	{	/* 20 Mhz */ {  175.5f,		/* SGI */  195.0f, },
		/* 40 Mhz */ {  364.5f,		/* SGI */  405.0f, },
	},

	/* MCS 72  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 73  */
	{	/* 20 Mhz */ {  175.5f,		/* SGI */  195.0f, },
		/* 40 Mhz */ {  364.5f,		/* SGI */  405.0f, },
	},

	/* MCS 74  */
	{	/* 20 Mhz */ {  195.0f,		/* SGI */  216.7f, },
		/* 40 Mhz */ {  405.0f,		/* SGI */  450.0f, },
	},

	/* MCS 75  */
	{	/* 20 Mhz */ {  195.0f,		/* SGI */  216.7f, },
		/* 40 Mhz */ {  405.0f,		/* SGI */  450.0f, },
	},

	/* MCS 76  */
	{	/* 20 Mhz */ {  214.5f,		/* SGI */  238.3f, },
		/* 40 Mhz */ {  445.5f,		/* SGI */  495.0f, },
	},
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
static int hf_radiotap_vendor_ns = -1;
static int hf_radiotap_ven_oui = -1;
static int hf_radiotap_ven_subns = -1;
static int hf_radiotap_ven_skip = -1;
static int hf_radiotap_ven_data = -1;
static int hf_radiotap_mcs = -1;
static int hf_radiotap_mcs_known = -1;
static int hf_radiotap_mcs_have_bw = -1;
static int hf_radiotap_mcs_have_index = -1;
static int hf_radiotap_mcs_have_gi = -1;
static int hf_radiotap_mcs_have_format = -1;
static int hf_radiotap_mcs_have_fec = -1;
static int hf_radiotap_mcs_bw = -1;
static int hf_radiotap_mcs_index = -1;
static int hf_radiotap_mcs_gi = -1;
static int hf_radiotap_mcs_format = -1;
static int hf_radiotap_mcs_fec = -1;

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
static int hf_radiotap_present_mcs = -1;
static int hf_radiotap_present_rtap_ns = -1;
static int hf_radiotap_present_vendor_ns = -1;
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
static gint ett_radiotap_vendor = -1;
static gint ett_radiotap_mcs = -1;
static gint ett_radiotap_mcs_known = -1;

static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_datapad_handle;

static int radiotap_tap = -1;

/* Settings */
static gboolean radiotap_bit14_fcs = FALSE;

static void
dissect_radiotap(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

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

void
capture_radiotap(const guchar * pd, int offset, int len, packet_counts * ld)
{
	guint16 it_len;
	guint32 present, xpresent;
	guint8 rflags;
	struct ieee80211_radiotap_header *hdr;

	if (!BYTES_ARE_IN_FRAME(offset, len,
				sizeof(struct ieee80211_radiotap_header))) {
		ld->other++;
		return;
	}
	hdr = (void *)pd;
	it_len = pletohs(&hdr->it_len);
	if (!BYTES_ARE_IN_FRAME(offset, len, it_len)) {
		ld->other++;
		return;
	}

	if (it_len > len) {
		/* Header length is bigger than total packet length */
		ld->other++;
		return;
	}

	if (it_len < sizeof(struct ieee80211_radiotap_header)) {
		/* Header length is shorter than fixed-length portion of header */
		ld->other++;
		return;
	}

	present = pletohl(&hdr->it_present);
	offset += sizeof(struct ieee80211_radiotap_header);
	it_len -= sizeof(struct ieee80211_radiotap_header);

	/* skip over other present bitmaps */
	xpresent = present;
	while (xpresent & BIT(IEEE80211_RADIOTAP_EXT)) {
		if (!BYTES_ARE_IN_FRAME(offset, 4, it_len)) {
			ld->other++;
			return;
		}
		xpresent = pletohl(pd + offset);
		offset += 4;
		it_len -= 4;
	}

	rflags = 0;

	/*
	 * IEEE80211_RADIOTAP_TSFT is the lowest-order bit,
	 * just skip over it.
	 */
	if (present & BIT(IEEE80211_RADIOTAP_TSFT)) {
		/* align it properly */
		if (offset & 7) {
			int pad = 8 - (offset & 7);
			offset += pad;
			it_len -= pad;
		}

		if (it_len < 8) {
			/* No room in header for this field. */
			ld->other++;
			return;
		}
		/* That field is present, and it's 8 bytes long. */
		offset += 8;
		it_len -= 8;
	}

	/*
	 * IEEE80211_RADIOTAP_FLAGS is the next bit.
	 */
	if (present & BIT(IEEE80211_RADIOTAP_FLAGS)) {
		if (it_len < 1) {
			/* No room in header for this field. */
			ld->other++;
			return;
		}
		/* That field is present; fetch it. */
		if (!BYTES_ARE_IN_FRAME(offset, len, 1)) {
			ld->other++;
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

void proto_register_radiotap(void)
{
	static const value_string phy_type[] = {
		{0, "Unknown"},
		{IEEE80211_CHAN_A, "802.11a"},
		{IEEE80211_CHAN_A | IEEE80211_CHAN_HT20, "802.11a (ht20)"},
		{IEEE80211_CHAN_A | IEEE80211_CHAN_HT40U, "802.11a (ht40+)"},
		{IEEE80211_CHAN_A | IEEE80211_CHAN_HT40D, "802.11a (ht40-)"},
		{IEEE80211_CHAN_B, "802.11b"},
		{IEEE80211_CHAN_PUREG, "802.11g (pure-g)"},
		{IEEE80211_CHAN_G, "802.11g"},
		{IEEE80211_CHAN_G | IEEE80211_CHAN_HT20, "802.11g (ht20)"},
		{IEEE80211_CHAN_G | IEEE80211_CHAN_HT40U, "802.11g (ht40+)"},
		{IEEE80211_CHAN_G | IEEE80211_CHAN_HT40D, "802.11g (ht40-)"},
		{IEEE80211_CHAN_T, "802.11a (turbo)"},
		{IEEE80211_CHAN_108PUREG, "802.11g (pure-g, turbo)"},
		{IEEE80211_CHAN_108G, "802.11g (turbo)"},
		{IEEE80211_CHAN_FHSS, "FHSS"},
		{0, NULL}
	};

	static const value_string mcs_bandwidth[] = {
		{ IEEE80211_RADIOTAP_MCS_BW_20, "20 MHz" },
		{ IEEE80211_RADIOTAP_MCS_BW_40, "40 MHz" },
		{ IEEE80211_RADIOTAP_MCS_BW_20L, "20 MHz lower" },
		{ IEEE80211_RADIOTAP_MCS_BW_20U, "20 MHz upper" },
		{0, NULL}
	};

	static const value_string mcs_format[] = {
		{ 0, "mixed" },
		{ 1, "greenfield" },
		{0, NULL},
	};

	static const value_string mcs_fec[] = {
		{ 0, "BCC" },
		{ 1, "LDPC" },
		{0, NULL}
	};

	static const value_string mcs_gi[] = {
		{ 0, "long" },
		{ 1, "short" },
		{0, NULL}
	};

	static const true_false_string preamble_type = {
		"Short",
		"Long",
	};

	static hf_register_info hf[] = {
		{&hf_radiotap_version,
		 {"Header revision", "radiotap.version",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Version of radiotap header format", HFILL}},
		{&hf_radiotap_pad,
		 {"Header pad", "radiotap.pad",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Padding", HFILL}},
		{&hf_radiotap_length,
		 {"Header length", "radiotap.length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Length of header including version, pad, length and data fields",
		  HFILL}},
		{&hf_radiotap_present,
		 {"Present flags", "radiotap.present",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  "Bitmask indicating which fields are present", HFILL}},

#define RADIOTAP_MASK(name)	BIT(IEEE80211_RADIOTAP_ ##name)

		/* Boolean 'present' flags */
		{&hf_radiotap_present_tsft,
		 {"TSFT", "radiotap.present.tsft",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(TSFT),
		  "Specifies if the Time Synchronization Function Timer field is present",
		  HFILL}},

		{&hf_radiotap_present_flags,
		 {"Flags", "radiotap.present.flags",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(FLAGS),
		  "Specifies if the channel flags field is present", HFILL}},

		{&hf_radiotap_present_rate,
		 {"Rate", "radiotap.present.rate",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(RATE),
		  "Specifies if the transmit/receive rate field is present",
		  HFILL}},

		{&hf_radiotap_present_channel,
		 {"Channel", "radiotap.present.channel",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(CHANNEL),
		  "Specifies if the transmit/receive frequency field is present",
		  HFILL}},

		{&hf_radiotap_present_fhss,
		 {"FHSS", "radiotap.present.fhss",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(FHSS),
		  "Specifies if the hop set and pattern is present for frequency hopping radios",
		  HFILL}},

		{&hf_radiotap_present_dbm_antsignal,
		 {"DBM Antenna Signal", "radiotap.present.dbm_antsignal",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(DBM_ANTSIGNAL),
		  "Specifies if the antenna signal strength in dBm is present",
		  HFILL}},

		{&hf_radiotap_present_dbm_antnoise,
		 {"DBM Antenna Noise", "radiotap.present.dbm_antnoise",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(DBM_ANTNOISE),
		  "Specifies if the RF noise power at antenna field is present",
		  HFILL}},

		{&hf_radiotap_present_lock_quality,
		 {"Lock Quality", "radiotap.present.lock_quality",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(LOCK_QUALITY),
		  "Specifies if the signal quality field is present", HFILL}},

		{&hf_radiotap_present_tx_attenuation,
		 {"TX Attenuation", "radiotap.present.tx_attenuation",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(TX_ATTENUATION),
		  "Specifies if the transmit power from max power field is present",
		  HFILL}},

		{&hf_radiotap_present_db_tx_attenuation,
		 {"DB TX Attenuation", "radiotap.present.db_tx_attenuation",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(DB_TX_ATTENUATION),
		  "Specifies if the transmit power from max power (in dB) field is present",
		  HFILL}},

		{&hf_radiotap_present_dbm_tx_attenuation,
		 {"DBM TX Attenuation", "radiotap.present.dbm_tx_attenuation",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(DB_TX_ATTENUATION),
		  "Specifies if the transmit power from max power (in dBm) field is present",
		  HFILL}},

		{&hf_radiotap_present_antenna,
		 {"Antenna", "radiotap.present.antenna",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(ANTENNA),
		  "Specifies if the antenna number field is present", HFILL}},

		{&hf_radiotap_present_db_antsignal,
		 {"DB Antenna Signal", "radiotap.present.db_antsignal",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(DB_ANTSIGNAL),
		  "Specifies if the RF signal power at antenna in dB field is present",
		  HFILL}},

		{&hf_radiotap_present_db_antnoise,
		 {"DB Antenna Noise", "radiotap.present.db_antnoise",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(DB_ANTNOISE),
		  "Specifies if the RF signal power at antenna in dBm field is present",
		  HFILL}},

		{&hf_radiotap_present_rxflags,
		 {"RX flags", "radiotap.present.rxflags",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(RX_FLAGS),
		  "Specifies if the RX flags field is present", HFILL}},

		{&hf_radiotap_present_hdrfcs,
		 {"FCS in header", "radiotap.present.fcs",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(RX_FLAGS),
		  "Specifies if the FCS field is present", HFILL}},

		{&hf_radiotap_present_xchannel,
		 {"Channel+", "radiotap.present.xchannel",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(XCHANNEL),
		  "Specifies if the extended channel info field is present",
		  HFILL}},

		{&hf_radiotap_present_mcs,
		 {"HT information", "radiotap.present.mcs",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(MCS),
		  "Specifies if the HT field is present", HFILL}},

		{&hf_radiotap_present_rtap_ns,
		 {"Radiotap NS next", "radiotap.present.rtap_ns",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(RADIOTAP_NAMESPACE),
		  "Specifies a reset to the radiotap namespace", HFILL}},

		{&hf_radiotap_present_vendor_ns,
		 {"Vendor NS next", "radiotap.present.vendor_ns",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(VENDOR_NAMESPACE),
		  "Specifies that the next bitmap is in a vendor namespace",
		  HFILL}},

		{&hf_radiotap_present_ext,
		 {"Ext", "radiotap.present.ext",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(EXT),
		  "Specifies if there are any extensions to the header present",
		  HFILL}},

		/* Boolean 'present.flags' flags */
		{&hf_radiotap_flags,
		 {"Flags", "radiotap.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_flags_cfp,
		 {"CFP", "radiotap.flags.cfp",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_CFP,
		  "Sent/Received during CFP", HFILL}},

		{&hf_radiotap_flags_preamble,
		 {"Preamble", "radiotap.flags.preamble",
		  FT_BOOLEAN, 8, TFS(&preamble_type),
		  IEEE80211_RADIOTAP_F_SHORTPRE,
		  "Sent/Received with short preamble", HFILL}},

		{&hf_radiotap_flags_wep,
		 {"WEP", "radiotap.flags.wep",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_WEP,
		  "Sent/Received with WEP encryption", HFILL}},

		{&hf_radiotap_flags_frag,
		 {"Fragmentation", "radiotap.flags.frag",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_FRAG,
		  "Sent/Received with fragmentation", HFILL}},

		{&hf_radiotap_flags_fcs,
		 {"FCS at end", "radiotap.flags.fcs",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_FCS,
		  "Frame includes FCS at end", HFILL}},

		{&hf_radiotap_flags_datapad,
		 {"Data Pad", "radiotap.flags.datapad",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_DATAPAD,
		  "Frame has padding between 802.11 header and payload",
		  HFILL}},

		{&hf_radiotap_flags_badfcs,
		 {"Bad FCS", "radiotap.flags.badfcs",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_BADFCS,
		  "Frame received with bad FCS", HFILL}},

		{&hf_radiotap_flags_shortgi,
		 {"Short GI", "radiotap.flags.shortgi",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_SHORTGI,
		  "Frame Sent/Received with HT short Guard Interval", HFILL}},

		{&hf_radiotap_mactime,
		 {"MAC timestamp", "radiotap.mactime",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Value in microseconds of the MAC's Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC.",
		  HFILL}},

		{&hf_radiotap_quality,
		 {"Signal Quality", "radiotap.quality",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Signal quality (unitless measure)", HFILL}},

		{&hf_radiotap_fcs,
		 {"802.11 FCS", "radiotap.fcs",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Frame check sequence of this frame", HFILL}},

		{&hf_radiotap_channel,
		 {"Channel", "radiotap.channel",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "802.11 channel number that this frame was sent/received on",
		  HFILL}},

		{&hf_radiotap_channel_frequency,
		 {"Channel frequency", "radiotap.channel.freq",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Channel frequency in megahertz that this frame was sent/received on",
		  HFILL}},

		{&hf_radiotap_channel_flags,
		 {"Channel type", "radiotap.channel.type",
		  FT_UINT16, BASE_HEX, VALS(phy_type), 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_channel_flags_turbo,
		 {"Turbo", "radiotap.channel.type.turbo",
		  FT_BOOLEAN, 16, NULL, 0x0010, "Channel Type Turbo", HFILL}},
		{&hf_radiotap_channel_flags_cck,
		 {"Complementary Code Keying (CCK)",
		  "radiotap.channel.type.cck",
		  FT_BOOLEAN, 16, NULL, 0x0020,
		  "Channel Type Complementary Code Keying (CCK) Modulation",
		  HFILL}},
		{&hf_radiotap_channel_flags_ofdm,
		 {"Orthogonal Frequency-Division Multiplexing (OFDM)",
		  "radiotap.channel.type.ofdm",
		  FT_BOOLEAN, 16, NULL, 0x0040,
		  "Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)",
		  HFILL}},
		{&hf_radiotap_channel_flags_2ghz,
		 {"2 GHz spectrum", "radiotap.channel.type.2ghz",
		  FT_BOOLEAN, 16, NULL, 0x0080, "Channel Type 2 GHz spectrum",
		  HFILL}},
		{&hf_radiotap_channel_flags_5ghz,
		 {"5 GHz spectrum", "radiotap.channel.type.5ghz",
		  FT_BOOLEAN, 16, NULL, 0x0100, "Channel Type 5 GHz spectrum",
		  HFILL}},
		{&hf_radiotap_channel_flags_passive,
		 {"Passive", "radiotap.channel.type.passive",
		  FT_BOOLEAN, 16, NULL, 0x0200, "Channel Type Passive", HFILL}},
		{&hf_radiotap_channel_flags_dynamic,
		 {"Dynamic CCK-OFDM", "radiotap.channel.type.dynamic",
		  FT_BOOLEAN, 16, NULL, 0x0400,
		  "Channel Type Dynamic CCK-OFDM Channel", HFILL}},
		{&hf_radiotap_channel_flags_gfsk,
		 {"Gaussian Frequency Shift Keying (GFSK)",
		  "radiotap.channel.type.gfsk",
		  FT_BOOLEAN, 16, NULL, 0x0800,
		  "Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation",
		  HFILL}},
		{&hf_radiotap_channel_flags_gsm,
		 {"GSM (900MHz)", "radiotap.channel.type.gsm",
		  FT_BOOLEAN, 16, NULL, 0x1000, "Channel Type GSM", HFILL}},
		{&hf_radiotap_channel_flags_sturbo,
		 {"Static Turbo", "radiotap.channel.type.sturbo",
		  FT_BOOLEAN, 16, NULL, 0x2000, "Channel Type Status Turbo",
		  HFILL}},
		{&hf_radiotap_channel_flags_half,
		 {"Half Rate Channel (10MHz Channel Width)",
		  "radiotap.channel.type.half",
		  FT_BOOLEAN, 16, NULL, 0x4000, "Channel Type Half Rate",
		  HFILL}},
		{&hf_radiotap_channel_flags_quarter,
		 {"Quarter Rate Channel (5MHz Channel Width)",
		  "radiotap.channel.type.quarter",
		  FT_BOOLEAN, 16, NULL, 0x8000, "Channel Type Quarter Rate",
		  HFILL}},

		{&hf_radiotap_rxflags,
		 {"RX flags", "radiotap.rxflags",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_rxflags_badplcp,
		 {"Bad PLCP", "radiotap.rxflags.badplcp",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_RX_BADPLCP,
		  "Frame with bad PLCP", HFILL}},

		{&hf_radiotap_xchannel,
		 {"Channel number", "radiotap.xchannel",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&hf_radiotap_xchannel_frequency,
		 {"Channel frequency", "radiotap.xchannel.freq",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&hf_radiotap_xchannel_flags,
		 {"Channel type", "radiotap.xchannel.flags",
		  FT_UINT32, BASE_HEX, VALS(phy_type), 0x0, NULL, HFILL}},

		{&hf_radiotap_xchannel_flags_turbo,
		 {"Turbo", "radiotap.xchannel.type.turbo",
		  FT_BOOLEAN, 24, NULL, 0x0010, "Channel Type Turbo", HFILL}},
		{&hf_radiotap_xchannel_flags_cck,
		 {"Complementary Code Keying (CCK)",
		  "radiotap.xchannel.type.cck",
		  FT_BOOLEAN, 24, NULL, 0x0020,
		  "Channel Type Complementary Code Keying (CCK) Modulation",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_ofdm,
		 {"Orthogonal Frequency-Division Multiplexing (OFDM)",
		  "radiotap.xchannel.type.ofdm",
		  FT_BOOLEAN, 24, NULL, 0x0040,
		  "Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_2ghz,
		 {"2 GHz spectrum", "radiotap.xchannel.type.2ghz",
		  FT_BOOLEAN, 24, NULL, 0x0080, "Channel Type 2 GHz spectrum",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_5ghz,
		 {"5 GHz spectrum", "radiotap.xchannel.type.5ghz",
		  FT_BOOLEAN, 24, NULL, 0x0100, "Channel Type 5 GHz spectrum",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_passive,
		 {"Passive", "radiotap.channel.xtype.passive",
		  FT_BOOLEAN, 24, NULL, 0x0200, "Channel Type Passive", HFILL}},
		{&hf_radiotap_xchannel_flags_dynamic,
		 {"Dynamic CCK-OFDM", "radiotap.xchannel.type.dynamic",
		  FT_BOOLEAN, 24, NULL, 0x0400,
		  "Channel Type Dynamic CCK-OFDM Channel", HFILL}},
		{&hf_radiotap_xchannel_flags_gfsk,
		 {"Gaussian Frequency Shift Keying (GFSK)",
		  "radiotap.xchannel.type.gfsk",
		  FT_BOOLEAN, 24, NULL, 0x0800,
		  "Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_gsm,
		 {"GSM (900MHz)", "radiotap.xchannel.type.gsm",
		  FT_BOOLEAN, 24, NULL, 0x1000, "Channel Type GSM", HFILL}},
		{&hf_radiotap_xchannel_flags_sturbo,
		 {"Static Turbo", "radiotap.xchannel.type.sturbo",
		  FT_BOOLEAN, 24, NULL, 0x2000, "Channel Type Status Turbo",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_half,
		 {"Half Rate Channel (10MHz Channel Width)",
		  "radiotap.xchannel.type.half",
		  FT_BOOLEAN, 24, NULL, 0x4000, "Channel Type Half Rate",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_quarter,
		 {"Quarter Rate Channel (5MHz Channel Width)",
		  "radiotap.xchannel.type.quarter",
		  FT_BOOLEAN, 24, NULL, 0x8000, "Channel Type Quarter Rate",
		  HFILL}},
		{&hf_radiotap_xchannel_flags_ht20,
		 {"HT Channel (20MHz Channel Width)",
		  "radiotap.xchannel.type.ht20",
		  FT_BOOLEAN, 24, NULL, 0x10000, "Channel Type HT/20", HFILL}},
		{&hf_radiotap_xchannel_flags_ht40u,
		 {"HT Channel (40MHz Channel Width with Extension channel above)", "radiotap.xchannel.type.ht40u",
		  FT_BOOLEAN, 24, NULL, 0x20000, "Channel Type HT/40+", HFILL}},
		{&hf_radiotap_xchannel_flags_ht40d,
		 {"HT Channel (40MHz Channel Width with Extension channel below)", "radiotap.xchannel.type.ht40d",
		  FT_BOOLEAN, 24, NULL, 0x40000, "Channel Type HT/40-", HFILL}},
#if 0
		{&hf_radiotap_xchannel_maxpower,
		 {"Max transmit power", "radiotap.xchannel.maxpower",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
#endif
		{&hf_radiotap_fhss_hopset,
		 {"FHSS Hop Set", "radiotap.fhss.hopset",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Frequency Hopping Spread Spectrum hopset", HFILL}},

		{&hf_radiotap_fhss_pattern,
		 {"FHSS Pattern", "radiotap.fhss.pattern",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Frequency Hopping Spread Spectrum hop pattern", HFILL}},

		{&hf_radiotap_datarate,
		 {"Data rate (Mb/s)", "radiotap.datarate",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_antenna,
		 {"Antenna", "radiotap.antenna",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Antenna number this frame was sent/received over (starting at 0)",
		  HFILL}},

		{&hf_radiotap_dbm_antsignal,
		 {"SSI Signal (dBm)", "radiotap.dbm_antsignal",
		  FT_INT32, BASE_DEC, NULL, 0x0,
		  "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt",
		  HFILL}},

		{&hf_radiotap_db_antsignal,
		 {"SSI Signal (dB)", "radiotap.db_antsignal",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "RF signal power at the antenna from a fixed, arbitrary value in decibels",
		  HFILL}},

		{&hf_radiotap_dbm_antnoise,
		 {"SSI Noise (dBm)", "radiotap.dbm_antnoise",
		  FT_INT32, BASE_DEC, NULL, 0x0,
		  "RF noise power at the antenna from a fixed, arbitrary value in decibels per one milliwatt",
		  HFILL}},

		{&hf_radiotap_db_antnoise,
		 {"SSI Noise (dB)", "radiotap.db_antnoise",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "RF noise power at the antenna from a fixed, arbitrary value in decibels",
		  HFILL}},

		{&hf_radiotap_tx_attenuation,
		 {"Transmit attenuation", "radiotap.txattenuation",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Transmit power expressed as unitless distance from max power set at factory (0 is max power)",
		  HFILL}},

		{&hf_radiotap_db_tx_attenuation,
		 {"Transmit attenuation (dB)", "radiotap.db_txattenuation",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Transmit power expressed as decibels from max power set at factory (0 is max power)",
		  HFILL}},

		{&hf_radiotap_txpower,
		 {"Transmit power", "radiotap.txpower",
		  FT_INT32, BASE_DEC, NULL, 0x0,
		  "Transmit power in decibels per one milliwatt (dBm)", HFILL}},

		{&hf_radiotap_mcs,
		 {"MCS information", "radiotap.mcs",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
		{&hf_radiotap_mcs_known,
		 {"Known MCS information", "radiotap.mcs.known",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bit mask indicating what MCS information is present", HFILL}},
		{&hf_radiotap_mcs_have_bw,
		 {"Bandwidth", "radiotap.mcs.have_bw",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_MCS_HAVE_BW,
		  "Bandwidth information present", HFILL}},
		{&hf_radiotap_mcs_have_gi,
		 {"Guard interval", "radiotap.mcs.have_gi",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_MCS_HAVE_GI,
		  "Sent/Received guard interval information present", HFILL}},
		{&hf_radiotap_mcs_have_format,
		 {"Format", "radiotap.mcs.have_format",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_MCS_HAVE_FMT,
		  "Format information present", HFILL}},
		{&hf_radiotap_mcs_have_fec,
		 {"FEC", "radiotap.mcs.have_fec",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_MCS_HAVE_FEC,
		  "Forward error correction information present", HFILL}},
		{&hf_radiotap_mcs_have_index,
		 {"MCS index", "radiotap.mcs.have_index",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_MCS_HAVE_MCS,
		  "MCS index information present", HFILL}},
		{&hf_radiotap_mcs_bw,
		 {"Bandwidth", "radiotap.mcs.bw",
		  FT_UINT8, BASE_DEC, VALS(mcs_bandwidth),
		  IEEE80211_RADIOTAP_MCS_BW_MASK, NULL, HFILL}},
		{&hf_radiotap_mcs_gi,
		 {"Guard interval", "radiotap.mcs.gi",
		  FT_UINT8, BASE_DEC, VALS(mcs_gi), IEEE80211_RADIOTAP_MCS_SGI,
		  "Sent/Received guard interval", HFILL}},
		{&hf_radiotap_mcs_format,
		 {"Format", "radiotap.mcs.format",
		  FT_UINT8, BASE_DEC, VALS(mcs_format), IEEE80211_RADIOTAP_MCS_FMT_GF,
		  NULL, HFILL}},
		{&hf_radiotap_mcs_fec,
		 {"FEC", "radiotap.mcs.fec",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), IEEE80211_RADIOTAP_MCS_FEC_LDPC,
		  "forward error correction", HFILL}},
		{&hf_radiotap_mcs_index,
		 {"MCS index", "radiotap.mcs.index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_vendor_ns,
		 {"Vendor namespace", "radiotap.vendor_namespace",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ven_oui,
		 {"Vendor OUI", "radiotap.vendor_oui",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ven_subns,
		 {"Vendor sub namespace", "radiotap.vendor_subns",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Vendor-specified sub namespace", HFILL}},

		{&hf_radiotap_ven_skip,
		 {"Vendor data length", "radiotap.vendor_data_len",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Length of vendor-specified data", HFILL}},

		{&hf_radiotap_ven_data,
		 {"Vendor data", "radiotap.vendor_data",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  "Vendor-specified data", HFILL}},

		/* Special variables */
		{&hf_radiotap_fcs_bad,
		 {"Bad FCS", "radiotap.fcs_bad",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Specifies if this frame has a bad frame check sequence",
		  HFILL}},

	};
	static gint *ett[] = {
		&ett_radiotap,
		&ett_radiotap_present,
		&ett_radiotap_flags,
		&ett_radiotap_rxflags,
		&ett_radiotap_channel_flags,
		&ett_radiotap_xchannel_flags,
		&ett_radiotap_vendor,
		&ett_radiotap_mcs,
		&ett_radiotap_mcs_known,
	};
	module_t *radiotap_module;

	proto_radiotap =
	    proto_register_protocol("IEEE 802.11 Radiotap Capture header",
				    "802.11 Radiotap", "radiotap");
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
dissect_radiotap(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_tree *radiotap_tree = NULL;
	proto_tree *pt, *present_tree = NULL;
	proto_tree *ft;
	proto_item *ti = NULL;
	proto_item *hidden_item;
	int offset;
	tvbuff_t *next_tvb;
	guint8 version;
	guint length;
	guint32 rate, freq, flags;
	gint8 dbm, db;
	guint8 rflags = 0;
	/* backward compat with bit 14 == fcs in header */
	proto_item *hdr_fcs_ti = NULL;
	int hdr_fcs_offset = 0;
	guint32 sent_fcs = 0;
	guint32 calc_fcs;
	gint err;
	struct ieee80211_radiotap_iterator iter;
	void *data;
	struct _radiotap_info *radiotap_info;
	static struct _radiotap_info rtp_info_arr;

	/* our non-standard overrides */
	static struct radiotap_override overrides[] = {
		{IEEE80211_RADIOTAP_XCHANNEL, 4, 8},	/* xchannel */

		/* keep last */
		{14, 4, 4},	/* FCS in header */
	};
	guint n_overrides = array_length(overrides);

	if (!radiotap_bit14_fcs)
		n_overrides--;

	radiotap_info = &rtp_info_arr;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_guint8(tvb, 0);
	length = tvb_get_letohs(tvb, 2);

	radiotap_info->radiotap_length = length;

	col_add_fstr(pinfo->cinfo, COL_INFO, "Radiotap Capture v%u, Length %u",
		     version, length);

	/* Dissect the packet */
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_radiotap,
						    tvb, 0, length,
						    "Radiotap Header v%u, Length %u",
						    version, length);
		radiotap_tree = proto_item_add_subtree(ti, ett_radiotap);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_version,
				    tvb, 0, 1, version);
		proto_tree_add_item(radiotap_tree, hf_radiotap_pad,
				    tvb, 1, 1, FALSE);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_length,
				    tvb, 2, 2, length);
	}

	data = ep_tvb_memdup(tvb, 0, length);
	if (!data)
		return;

	if (ieee80211_radiotap_iterator_init(&iter, data, length, NULL)) {
		if (tree)
			proto_item_append_text(ti, " (invalid)");
		/* maybe the length was correct anyway ... */
		goto hand_off_to_80211;
	}

	iter.overrides = overrides;
	iter.n_overrides = n_overrides;

	/* Add the "present flags" bitmaps. */
	if (tree) {
		guchar *bmap_start = (guchar *) data + 4;
		guint n_bitmaps = (guint)(iter.this_arg - bmap_start) / 4;
		guint i;
		gboolean rtap_ns, rtap_ns_next = TRUE;
		guint rtap_ns_offset, rtap_ns_offset_next = 0;

		pt = proto_tree_add_item(radiotap_tree, hf_radiotap_present,
					 tvb, 4, n_bitmaps * 4,
					 FALSE /* ?? */ );

		for (i = 0; i < n_bitmaps; i++) {
			guint32 bmap = pletohl(bmap_start + 4 * i);

			rtap_ns_offset = rtap_ns_offset_next;
			rtap_ns_offset_next += 32;

			present_tree =
			    proto_item_add_subtree(pt, ett_radiotap_present);

			offset = 4 * i;

			rtap_ns = rtap_ns_next;

			/* Evaluate what kind of namespaces will come next */
			if (bmap & BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)) {
				rtap_ns_next = TRUE;
				rtap_ns_offset_next = 0;
			}
			if (bmap & BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))
				rtap_ns_next = FALSE;
			if ((bmap & (BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) |
				     BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE)))
				== (BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) |
				    BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE)))
				goto malformed;

			if (!rtap_ns)
				goto always_bits;

			/* Currently, we don't know anything about bits >= 32 */
			if (rtap_ns_offset)
				goto always_bits;

			proto_tree_add_item(present_tree,
					    hf_radiotap_present_tsft, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_flags, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_rate, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_channel, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_fhss, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_dbm_antsignal,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_dbm_antnoise,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_lock_quality,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_tx_attenuation,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_db_tx_attenuation,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_dbm_tx_attenuation,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_antenna, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_db_antsignal,
					    tvb, offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_db_antnoise,
					    tvb, offset + 4, 4, TRUE);
			if (radiotap_bit14_fcs) {
				proto_tree_add_item(present_tree,
						    hf_radiotap_present_hdrfcs,
						    tvb, offset + 4, 4, TRUE);
			} else {
				proto_tree_add_item(present_tree,
						    hf_radiotap_present_rxflags,
						    tvb, offset + 4, 4, TRUE);
			}
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_xchannel, tvb,
					    offset + 4, 4, TRUE);

			proto_tree_add_item(present_tree,
					    hf_radiotap_present_mcs, tvb,
					    offset + 4, 4, TRUE);
 always_bits:
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_rtap_ns, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_vendor_ns, tvb,
					    offset + 4, 4, TRUE);
			proto_tree_add_item(present_tree,
					    hf_radiotap_present_ext, tvb,
					    offset + 4, 4, TRUE);
		}
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		offset = (int)((guchar *) iter.this_arg - (guchar *) data);

		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE
		    && tree) {
			proto_tree *vt, *ven_tree = NULL;
			const gchar *manuf_name;
			guint8 subns;

			manuf_name = tvb_get_manuf_name(tvb, offset);
			subns = tvb_get_guint8(tvb, offset+3);

			vt = proto_tree_add_bytes_format(radiotap_tree,
							 hf_radiotap_vendor_ns,
							 tvb, offset,
							 iter.this_arg_size,
							 NULL,
							 "Vendor namespace: %s-%d",
							 manuf_name, subns);
			ven_tree = proto_item_add_subtree(vt, ett_radiotap_vendor);
			proto_tree_add_bytes_format(ven_tree,
						    hf_radiotap_ven_oui, tvb,
						    offset, 3, NULL,
						    "Vendor: %s", manuf_name);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_subns,
					    tvb, offset + 3, 1, FALSE);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_skip, tvb,
					    offset + 4, 2, TRUE);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_data, tvb,
					    offset + 6, iter.this_arg_size - 6,
					    ENC_NA);
		}

		if (!iter.is_radiotap_ns)
			continue;

		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_TSFT:
			radiotap_info->tsft = tvb_get_letoh64(tvb, offset);
			if (tree) {
				proto_tree_add_uint64(radiotap_tree,
						      hf_radiotap_mactime, tvb,
						      offset, 8,
						      radiotap_info->tsft);
			}
			break;

		case IEEE80211_RADIOTAP_FLAGS: {
			proto_tree *flags_tree;

			rflags = tvb_get_guint8(tvb, offset);
			if (tree) {
				ft = proto_tree_add_item(radiotap_tree,
							 hf_radiotap_flags,
							 tvb, offset, 1, FALSE);
				flags_tree =
				    proto_item_add_subtree(ft,
							   ett_radiotap_flags);

				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_cfp,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_preamble,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_wep,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_frag,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_fcs,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_datapad,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_badfcs,
						    tvb, offset, 1, FALSE);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_shortgi,
						    tvb, offset, 1, FALSE);
			}
			break;
		}

		case IEEE80211_RADIOTAP_RATE:
			rate = tvb_get_guint8(tvb, offset);
			/*
			 * XXX On FreeBSD rate & 0x80 means we have an MCS. On
			 * Linux and AirPcap it does not.  (What about
			 * Mac OS X, NetBSD, OpenBSD, and DragonFly BSD?)
			 *
			 * This is an issue either for proprietary extensions
			 * to 11a or 11g, which do exist, or for 11n
			 * implementations that stuff a rate value into
			 * this field, which also appear to exist.
			 *
			 * We currently handle that by assuming that
			 * if the 0x80 bit is set *and* the remaining
			 * bits have a value between 0 and 15 it's
			 * an MCS value, otherwise it's a rate.  If
			 * there are cases where systems that use
			 * "0x80 + MCS index" for MCS indices > 15,
			 * or stuff a rate value here between 64 and
			 * 71.5 Mb/s in here, we'll need a preference
			 * setting.  Such rates do exist, e.g. 11n
			 * MCS 7 at 20 MHz with a long guard interval.
			 */
			if (rate >= 0x80 && rate <= 0x8f) {
				/*
				 * XXX - we don't know the channel width
				 * or guard interval length, so we can't
				 * convert this to a data rate.
				 *
				 * If you want us to show a data rate,
				 * use the MCS field, not the Rate field;
				 * the MCS field includes not only the
				 * MCS index, it also includes bandwidth
				 * and guard interval information.
				 *
				 * XXX - can we get the channel width
				 * from XChannel and the guard interval
				 * information from Flags, at least on
				 * FreeBSD?
				 */
				if (tree) {
					proto_tree_add_uint(radiotap_tree,
							    hf_radiotap_mcs_index,
							    tvb, offset, 1,
							    rate & 0x7f);
				}
			} else {
				col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%d.%d",
					     rate / 2, rate & 1 ? 5 : 0);
				if (tree) {
					proto_tree_add_float_format(radiotap_tree,
								    hf_radiotap_datarate,
								    tvb, offset, 1,
								    (float)rate / 2,
								    "Data Rate: %.1f Mb/s",
								    (float)rate / 2);
				}
				radiotap_info->rate = rate;
			}
			break;

		case IEEE80211_RADIOTAP_CHANNEL: {
			proto_item *it;
			proto_tree *flags_tree;
			gchar *chan_str;

			if (tree) {
				freq = tvb_get_letohs(tvb, offset);
				flags = tvb_get_letohs(tvb, offset + 2);
				chan_str = ieee80211_mhz_to_str(freq);
				col_add_fstr(pinfo->cinfo,
					     COL_FREQ_CHAN, "%s", chan_str);
				proto_tree_add_uint_format(radiotap_tree,
							   hf_radiotap_channel_frequency,
							   tvb, offset, 2, freq,
							   "Channel frequency: %s",
							   chan_str);
				g_free(chan_str);
				/* We're already 2-byte aligned. */
				it = proto_tree_add_uint(radiotap_tree,
							 hf_radiotap_channel_flags,
							 tvb, offset + 2, 2, flags);
				flags_tree =
				    proto_item_add_subtree(it,
							   ett_radiotap_channel_flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_turbo,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_cck,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_ofdm,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_2ghz,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_5ghz,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_passive,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_dynamic,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_gfsk,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_gsm,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_sturbo,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_half,
						       tvb, offset + 3, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_channel_flags_quarter,
						       tvb, offset + 3, 1, flags);
				radiotap_info->freq = freq;
				radiotap_info->flags = flags;
			}
			break;
		}

		case IEEE80211_RADIOTAP_FHSS:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_fhss_hopset, tvb,
					    offset, 1, FALSE);
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_fhss_pattern, tvb,
					    offset, 1, FALSE);
			break;

		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			dbm = (gint8) tvb_get_guint8(tvb, offset);
			col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
			if (tree) {
				proto_tree_add_int_format(radiotap_tree,
							  hf_radiotap_dbm_antsignal,
							  tvb, offset, 1, dbm,
							  "SSI Signal: %d dBm",
							  dbm);
			}
			radiotap_info->dbm_antsignal = dbm;
			break;

		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			dbm = (gint8) tvb_get_guint8(tvb, offset);
			if (tree) {
				proto_tree_add_int_format(radiotap_tree,
							  hf_radiotap_dbm_antnoise,
							  tvb, offset, 1, dbm,
							  "SSI Noise: %d dBm",
							  dbm);
			}
			radiotap_info->dbm_antnoise = dbm;
			break;

		case IEEE80211_RADIOTAP_LOCK_QUALITY:
			if (tree) {
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_quality, tvb,
						    offset, 2,
						    tvb_get_letohs(tvb,
								   offset));
			}
			break;

		case IEEE80211_RADIOTAP_TX_ATTENUATION:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_tx_attenuation, tvb,
					    offset, 2, FALSE);
			break;

		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_db_tx_attenuation, tvb,
					    offset, 2, FALSE);
			break;

		case IEEE80211_RADIOTAP_DBM_TX_POWER:
			if (tree) {
				proto_tree_add_int(radiotap_tree,
						   hf_radiotap_txpower, tvb,
						   offset, 1,
						   tvb_get_guint8(tvb, offset));
			}
			break;

		case IEEE80211_RADIOTAP_ANTENNA:
			if (tree) {
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_antenna, tvb,
						    offset, 1,
						    tvb_get_guint8(tvb,
								   offset));
			}
			break;

		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			db = tvb_get_guint8(tvb, offset);
			col_add_fstr(pinfo->cinfo, COL_RSSI, "%u dB", db);
			if (tree) {
				proto_tree_add_uint_format(radiotap_tree,
							   hf_radiotap_db_antsignal,
							   tvb, offset, 1, db,
							   "SSI Signal: %u dB",
							   db);
			}
			break;

		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			db = tvb_get_guint8(tvb, offset);
			if (tree) {
				proto_tree_add_uint_format(radiotap_tree,
							   hf_radiotap_db_antnoise,
							   tvb, offset, 1, db,
							   "SSI Noise: %u dB",
							   db);
			}
			break;

		case IEEE80211_RADIOTAP_RX_FLAGS: {
			proto_tree *flags_tree;

			if (radiotap_bit14_fcs) {
				if (tree) {
					sent_fcs = tvb_get_ntohl(tvb, offset);
					hdr_fcs_ti = proto_tree_add_uint(radiotap_tree,
									 hf_radiotap_fcs, tvb,
									 offset, 4, sent_fcs);
					hdr_fcs_offset = offset;
				}
			} else {
				proto_item *it;

				if (tree) {
					flags = tvb_get_letohs(tvb, offset);
					it = proto_tree_add_uint(radiotap_tree,
								 hf_radiotap_rxflags,
								 tvb, offset, 2, flags);
					flags_tree =
					    proto_item_add_subtree(it,
								   ett_radiotap_rxflags);
					proto_tree_add_boolean(flags_tree,
							       hf_radiotap_rxflags_badplcp,
							       tvb, offset, 1, flags);
				}
			}
			break;
		}

		case IEEE80211_RADIOTAP_XCHANNEL: {
			proto_item *it;
			proto_tree *flags_tree;

			if (tree) {
				int channel;

				flags = tvb_get_letohl(tvb, offset);
				freq = tvb_get_letohs(tvb, offset + 4);
				channel = tvb_get_guint8(tvb, offset + 6);
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_xchannel,
						    tvb, offset + 6, 1,
						    (guint32) channel);
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_xchannel_frequency,
						    tvb, offset + 4, 2, freq);
				it = proto_tree_add_uint(radiotap_tree,
							 hf_radiotap_xchannel_flags,
							 tvb, offset + 0, 4, flags);
				flags_tree =
				    proto_item_add_subtree(it, ett_radiotap_xchannel_flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_turbo,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_cck,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ofdm,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_2ghz,
						       tvb, offset + 0, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_5ghz,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_passive,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_dynamic,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_gfsk,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_gsm,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_sturbo,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_half,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_quarter,
						       tvb, offset + 1, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ht20,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ht40u,
						       tvb, offset + 2, 1, flags);
				proto_tree_add_boolean(flags_tree,
						       hf_radiotap_xchannel_flags_ht40d,
						       tvb, offset + 2, 1, flags);
#if 0
				proto_tree_add_uint(radiotap_tree,
						    hf_radiotap_xchannel_maxpower,
						    tvb, offset + 7, 1, maxpower);
#endif
			}
			break;
		}
		case IEEE80211_RADIOTAP_MCS: {
			proto_item *it;
			proto_tree *mcs_tree = NULL, *mcs_known_tree;
			guint8 mcs_known, mcs_flags;
			guint8 mcs;
			guint bandwidth;
			guint gi_length;
			gboolean can_calculate_rate;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = TRUE;

			mcs_known = tvb_get_guint8(tvb, offset);
			mcs_flags = tvb_get_guint8(tvb, offset + 1);
			mcs = tvb_get_guint8(tvb, offset + 2);

			if (tree) {
				it = proto_tree_add_item(radiotap_tree, hf_radiotap_mcs,
							 tvb, offset, 3, ENC_NA);
				mcs_tree = proto_item_add_subtree(it, ett_radiotap_mcs);
				it = proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_known,
							 tvb, offset, 1, mcs_known);
				mcs_known_tree = proto_item_add_subtree(it, ett_radiotap_mcs_known);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_bw,
					    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_index,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_gi,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_format,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(mcs_known_tree, hf_radiotap_mcs_have_fec,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
				bandwidth = ((mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40) ?
				    1 : 0;
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_bw,
							    tvb, offset + 1, 1, mcs_flags);
			} else {
				bandwidth = 0;
				can_calculate_rate = FALSE;	/* no bandwidth */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
				gi_length = (mcs_flags & IEEE80211_RADIOTAP_MCS_SGI) ?
				    1 : 0;
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_gi,
							    tvb, offset + 1, 1, mcs_flags);
			} else {
				gi_length = 0;
				can_calculate_rate = FALSE;	/* no GI width */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_format,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_fec,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
				if (mcs_tree)
					proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_index,
							    tvb, offset + 2, 1, mcs);
			} else
				can_calculate_rate = FALSE;	/* no MCS index */

			/*
			 * If we have the MCS index, channel width, and
			 * guard interval length, and the MCS index is
			 * valid, we can compute the rate.  If the resulting
			 * rate is non-zero, report it.  (If it's zero,
			 * it's an MCS/channel width/GI combination that
			 * 802.11n doesn't support.)
			 */
			if (can_calculate_rate && mcs <= MAX_MCS_INDEX
			    && ieee80211_float_htrates[mcs][bandwidth][gi_length] != 0.0) {
				col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f",
					     ieee80211_float_htrates[mcs][bandwidth][gi_length]);
				if (tree) {
					proto_tree_add_float_format(radiotap_tree,
								    hf_radiotap_datarate,
								    tvb, offset, 1,
								    ieee80211_float_htrates[mcs][bandwidth][gi_length],
								    "Data Rate: %.1f Mb/s",
								    ieee80211_float_htrates[mcs][bandwidth][gi_length]);
				}
			}
			break;
		}
		}
	}

	if (err != -ENOENT && tree) {
 malformed:
		proto_item_append_text(ti, " (malformed)");
	}

	/* This handles the case of an FCS exiting at the end of the frame. */
	if (rflags & IEEE80211_RADIOTAP_F_FCS)
		pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
	else
		pinfo->pseudo_header->ieee_802_11.fcs_len = 0;

 hand_off_to_80211:
	/* Grab the rest of the frame. */
	next_tvb = tvb_new_subset_remaining(tvb, length);

	/* If we had an in-header FCS, check it.
	 * This can only happen if the backward-compat configuration option
	 * is chosen by the user. */
	if (hdr_fcs_ti) {
		/* It would be very strange for the header to have an FCS for the
		 * frame *and* the frame to have the FCS at the end, but it's possible, so
		 * take that into account by using the FCS length recorded in pinfo. */

		/* Watch out for [erroneously] short frames */
		if (tvb_length(next_tvb) >
		    (unsigned int)pinfo->pseudo_header->ieee_802_11.fcs_len) {
			calc_fcs =
			    crc32_802_tvb(next_tvb,
			    	tvb_length(next_tvb) -
			    	pinfo->pseudo_header->ieee_802_11.fcs_len);

			/* By virtue of hdr_fcs_ti being set, we know that 'tree' is set,
			 * so there's no need to check it here. */
			if (calc_fcs == sent_fcs) {
				proto_item_append_text(hdr_fcs_ti,
						       " [correct]");
			} else {
				proto_item_append_text(hdr_fcs_ti,
						       " [incorrect, should be 0x%08x]",
						       calc_fcs);
				hidden_item =
				    proto_tree_add_boolean(radiotap_tree,
							   hf_radiotap_fcs_bad,
							   tvb, hdr_fcs_offset,
							   4, TRUE);
				PROTO_ITEM_SET_HIDDEN(hidden_item);
			}
		} else {
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

void proto_reg_handoff_radiotap(void)
{
	dissector_handle_t radiotap_handle;

	/* handle for 802.11 dissector */
	ieee80211_handle = find_dissector("wlan");
	ieee80211_datapad_handle = find_dissector("wlan_datapad");

	radiotap_handle = find_dissector("radiotap");

	dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP,
		      radiotap_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
