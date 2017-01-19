/*
 *  packet-ieee80211-radiotap.c
 *	Decode packets with a Radiotap header
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <errno.h>

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/crc32-tvb.h>
#include <wsutil/frequency-utils.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include "packet-ieee80211.h"
#include "packet-ieee80211-radiotap-iter.h"

void proto_register_radiotap(void);
void proto_reg_handoff_radiotap(void);

/* protocol */
static int proto_radiotap = -1;

static int hf_radiotap_version = -1;
static int hf_radiotap_pad = -1;
static int hf_radiotap_length = -1;
static int hf_radiotap_present = -1;
static int hf_radiotap_mactime = -1;
/* static int hf_radiotap_channel = -1; */
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
static int hf_radiotap_xchannel_channel = -1;
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
static int hf_radiotap_mcs_have_stbc = -1;
static int hf_radiotap_mcs_have_ness = -1;
static int hf_radiotap_mcs_ness_bit1 = -1;
static int hf_radiotap_mcs_bw = -1;
static int hf_radiotap_mcs_index = -1;
static int hf_radiotap_mcs_gi = -1;
static int hf_radiotap_mcs_format = -1;
static int hf_radiotap_mcs_fec = -1;
static int hf_radiotap_mcs_stbc = -1;
static int hf_radiotap_mcs_ness_bit0 = -1;
static int hf_radiotap_ampdu = -1;
static int hf_radiotap_ampdu_ref = -1;
static int hf_radiotap_ampdu_flags = -1;
static int hf_radiotap_ampdu_flags_report_zerolen = -1;
static int hf_radiotap_ampdu_flags_is_zerolen = -1;
static int hf_radiotap_ampdu_flags_last_known = -1;
static int hf_radiotap_ampdu_flags_is_last = -1;
static int hf_radiotap_ampdu_flags_delim_crc_error = -1;
static int hf_radiotap_ampdu_delim_crc = -1;
static int hf_radiotap_vht = -1;
static int hf_radiotap_vht_known = -1;
static int hf_radiotap_vht_have_stbc = -1;
static int hf_radiotap_vht_have_txop_ps = -1;
static int hf_radiotap_vht_have_gi = -1;
static int hf_radiotap_vht_have_sgi_nsym_da = -1;
static int hf_radiotap_vht_have_ldpc_extra = -1;
static int hf_radiotap_vht_have_bf = -1;
static int hf_radiotap_vht_have_bw = -1;
static int hf_radiotap_vht_have_gid = -1;
static int hf_radiotap_vht_have_p_aid = -1;
static int hf_radiotap_vht_stbc = -1;
static int hf_radiotap_vht_txop_ps = -1;
static int hf_radiotap_vht_gi = -1;
static int hf_radiotap_vht_sgi_nsym_da = -1;
static int hf_radiotap_vht_ldpc_extra = -1;
static int hf_radiotap_vht_bf = -1;
static int hf_radiotap_vht_bw = -1;
static int hf_radiotap_vht_nsts[4] = { -1, -1, -1, -1 };
static int hf_radiotap_vht_mcs[4] = { -1, -1, -1, -1 };
static int hf_radiotap_vht_nss[4] = { -1, -1, -1, -1 };
static int hf_radiotap_vht_coding[4] = { -1, -1, -1, -1 };
static int hf_radiotap_vht_datarate[4] = { -1, -1, -1, -1 };
static int hf_radiotap_vht_gid = -1;
static int hf_radiotap_vht_p_aid = -1;
static int hf_radiotap_vht_user = -1;

/* "Present" flags */
static int hf_radiotap_present_word = -1;
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
static int hf_radiotap_present_dbm_tx_power = -1;
static int hf_radiotap_present_antenna = -1;
static int hf_radiotap_present_db_antsignal = -1;
static int hf_radiotap_present_db_antnoise = -1;
static int hf_radiotap_present_hdrfcs = -1;
static int hf_radiotap_present_rxflags = -1;
static int hf_radiotap_present_xchannel = -1;
static int hf_radiotap_present_mcs = -1;
static int hf_radiotap_present_ampdu = -1;
static int hf_radiotap_present_vht = -1;
static int hf_radiotap_present_reserved = -1;
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
static gint ett_radiotap_present_word = -1;
static gint ett_radiotap_flags = -1;
static gint ett_radiotap_rxflags = -1;
static gint ett_radiotap_channel_flags = -1;
static gint ett_radiotap_xchannel_flags = -1;
static gint ett_radiotap_vendor = -1;
static gint ett_radiotap_mcs = -1;
static gint ett_radiotap_mcs_known = -1;
static gint ett_radiotap_ampdu = -1;
static gint ett_radiotap_ampdu_flags = -1;
static gint ett_radiotap_vht = -1;
static gint ett_radiotap_vht_known = -1;
static gint ett_radiotap_vht_user = -1;

static expert_field ei_radiotap_data_past_header = EI_INIT;
static expert_field ei_radiotap_present_reserved = EI_INIT;
static expert_field ei_radiotap_present = EI_INIT;
static expert_field ei_radiotap_invalid_data_rate = EI_INIT;

static dissector_handle_t ieee80211_radio_handle;

static int radiotap_tap = -1;

/* Settings */
static gboolean radiotap_bit14_fcs = FALSE;
static gboolean radiotap_interpret_high_rates_as_mcs = FALSE;

struct _radiotap_info {
	guint radiotap_length;
	guint32 rate;
	gint8 dbm_antsignal;
	gint8 dbm_antnoise;
	guint32 freq;
	guint32 flags;
	guint64 tsft;
};

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x)  (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x)  (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x)  (((x) & 2) ? 1 : 0)
#define BIT(n)	(1U << n)

/* not officially defined (yet) */
#define IEEE80211_RADIOTAP_F_SHORTGI	0x80
#define IEEE80211_RADIOTAP_XCHANNEL	18

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
#define	IEEE80211_CHAN_DSSS \
	(IEEE80211_CHAN_2GHZ)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_108A \
	(IEEE80211_CHAN_A | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108G \
	(IEEE80211_CHAN_G | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108PUREG \
	(IEEE80211_CHAN_PUREG | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_ST \
	(IEEE80211_CHAN_108A | IEEE80211_CHAN_STURBO)

#define MAX_MCS_VHT_INDEX	9
#define MAX_VHT_NSS             8

/*
 * Maps a VHT bandwidth index to ieee80211_vhtinfo.rates index.
 */
static const int ieee80211_vht_bw2rate_index[] = {
		/*  20Mhz total */	0,
		/*  40Mhz total */	1, 0, 0,
		/*  80Mhz total */	2, 1, 1, 0, 0, 0, 0,
		/* 160Mhz total */	3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
};

struct mcs_vht_valid {
	gboolean valid[4][MAX_VHT_NSS]; /* indexed by bandwidth and NSS-1 */
};

static const struct mcs_vht_valid ieee80211_vhtvalid[MAX_MCS_VHT_INDEX+1] = {
		/* MCS  0  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  1  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  2  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  3  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  4  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  5  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  6  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  FALSE, TRUE,  TRUE,  TRUE,  FALSE, TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  7  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  8  */
		{
			{	/* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		},
		/* MCS  9  */
		{
			{	/* 20 Mhz */  { FALSE, FALSE, TRUE,  FALSE, FALSE, TRUE,  FALSE, FALSE },
				/* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
				/* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  FALSE, TRUE,  TRUE },
				/* 160 Mhz */ { TRUE,  TRUE,  FALSE, TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
			}
		}
};

struct mcs_vht_info {
	const char *modulation;
	const char *coding_rate;
	float       rates[4][2]; /* indexed by bandwidth and GI length */
};

static const struct mcs_vht_info ieee80211_vhtinfo[MAX_MCS_VHT_INDEX+1] = {
		/* MCS  0  */
		{	"BPSK",		"1/2",
				{		/* 20 Mhz */  {    6.5f,		/* SGI */    7.2f, },
						/* 40 Mhz */  {   13.5f,		/* SGI */   15.0f, },
						/* 80 Mhz */  {   29.3f,		/* SGI */   32.5f, },
						/* 160 Mhz */ {   58.5f,		/* SGI */   65.0f, }
				}
		},
		/* MCS  1  */
		{	"QPSK",		"1/2",
				{		/* 20 Mhz */  {   13.0f,		/* SGI */   14.4f, },
						/* 40 Mhz */  {   27.0f,		/* SGI */   30.0f, },
						/* 80 Mhz */  {   58.5f,		/* SGI */   65.0f, },
						/* 160 Mhz */ {  117.0f,		/* SGI */  130.0f, }
				}
		},
		/* MCS  2  */
		{	"QPSK",		"3/4",
				{		/* 20 Mhz */  {   19.5f,		/* SGI */   21.7f, },
						/* 40 Mhz */  {   40.5f,		/* SGI */   45.0f, },
						/* 80 Mhz */  {   87.8f,		/* SGI */   97.5f, },
						/* 160 Mhz */ {  175.5f,		/* SGI */  195.0f, }
				}
		},
		/* MCS  3  */
		{	"16-QAM",	"1/2",
				{		/* 20 Mhz */  {   26.0f,		/* SGI */   28.9f, },
						/* 40 Mhz */  {   54.0f,		/* SGI */   60.0f, },
						/* 80 Mhz */  {  117.0f,		/* SGI */  130.0f, },
						/* 160 Mhz */ {  234.0f,		/* SGI */  260.0f, }
				}
		},
		/* MCS  4  */
		{	"16-QAM",	"3/4",
				{		/* 20 Mhz */  {   39.0f,		/* SGI */   43.3f, },
						/* 40 Mhz */  {   81.0f,		/* SGI */   90.0f, },
						/* 80 Mhz */  {  175.5f,		/* SGI */  195.0f, },
						/* 160 Mhz */ {  351.0f,		/* SGI */  390.0f, }
				}
		},
		/* MCS  5  */
		{	"64-QAM",	"2/3",
				{		/* 20 Mhz */  {   52.0f,		/* SGI */   57.8f, },
						/* 40 Mhz */  {  108.0f,		/* SGI */  120.0f, },
						/* 80 Mhz */  {  234.0f,		/* SGI */  260.0f, },
						/* 160 Mhz */ {  468.0f,		/* SGI */  520.0f, }
				}
		},
		/* MCS  6  */
		{	"64-QAM",	"3/4",
				{		/* 20 Mhz */  {   58.5f,		/* SGI */   65.0f, },
						/* 40 Mhz */  {  121.5f,		/* SGI */  135.0f, },
						/* 80 Mhz */  {  263.3f,		/* SGI */  292.5f, },
						/* 160 Mhz */ {  526.5f,		/* SGI */  585.0f, }
				}
		},
		/* MCS  7  */
		{	"64-QAM",	"5/6",
				{		/* 20 Mhz */  {   65.0f,		/* SGI */   72.2f, },
						/* 40 Mhz */  {  135.0f,		/* SGI */  150.0f, },
						/* 80 Mhz */  {  292.5f,		/* SGI */  325.0f, },
						/* 160 Mhz */ {  585.0f,		/* SGI */  650.0f, }
				}
		},
		/* MCS  8  */
		{	"256-QAM",	"3/4",
				{		/* 20 Mhz */  {   78.0f,		/* SGI */   86.7f, },
						/* 40 Mhz */  {  162.0f,		/* SGI */  180.0f, },
						/* 80 Mhz */  {  351.0f,		/* SGI */  390.0f, },
						/* 160 Mhz */ {  702.0f,		/* SGI */  780.0f, }
				}
		},
		/* MCS  9  */
		{	"256-QAM",	"5/6",
				{		/* 20 Mhz */  {   86.7f,		/* SGI */   96.3f, },
						/* 40 Mhz */  {  180.0f,		/* SGI */  200.0f, },
						/* 80 Mhz */  {  390.0f,		/* SGI */  433.3f, },
						/* 160 Mhz */ {  780.0f,		/* SGI */  866.7f, }
				}
		}
};

/* In order by value */
static const value_string vht_bandwidth[] = {
	{ IEEE80211_RADIOTAP_VHT_BW_20,    "20 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_40,    "40 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_20L,   "20 MHz lower" },
	{ IEEE80211_RADIOTAP_VHT_BW_20U,   "20 MHz upper" },
	{ IEEE80211_RADIOTAP_VHT_BW_80,    "80 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_40L,   "40 MHz lower" },
	{ IEEE80211_RADIOTAP_VHT_BW_40U,   "40 MHz upper" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LL,  "20 MHz, channel 1/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LU,  "20 MHz, channel 2/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UL,  "20 MHz, channel 3/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UU,  "20 MHz, channel 4/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_160,   "160 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_80L,   "80 MHz lower" },
	{ IEEE80211_RADIOTAP_VHT_BW_80U,   "80 MHz upper" },
	{ IEEE80211_RADIOTAP_VHT_BW_40LL,  "40 MHz, channel 1/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_40LU,  "40 MHz, channel 2/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_40UL,  "40 MHz, channel 3/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_40UU,  "40 MHz, channel 4/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LLL, "20 MHz, channel 1/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LLU, "20 MHz, channel 2/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LUL, "20 MHz, channel 3/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LUU, "20 MHz, channel 4/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20ULL, "20 MHz, channel 5/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20ULU, "20 MHz, channel 6/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UUL, "20 MHz, channel 7/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UUU, "20 MHz, channel 8/8" },
	{ 0, NULL }
};
static value_string_ext vht_bandwidth_ext = VALUE_STRING_EXT_INIT(vht_bandwidth);

static const value_string mcs_bandwidth[] = {
	{ IEEE80211_RADIOTAP_MCS_BW_20,  "20 MHz" },
	{ IEEE80211_RADIOTAP_MCS_BW_40,  "40 MHz" },
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

static gboolean
capture_radiotap(const guchar * pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	guint16 it_len;
	guint32 present, xpresent;
	guint8  rflags;
	const struct ieee80211_radiotap_header *hdr;

	if (!BYTES_ARE_IN_FRAME(offset, len,
				sizeof(struct ieee80211_radiotap_header))) {
		return FALSE;
	}
	hdr = (const struct ieee80211_radiotap_header *)pd;
	it_len = pletoh16(&hdr->it_len);
	if (!BYTES_ARE_IN_FRAME(offset, len, it_len))
		return FALSE;

	if (it_len > len) {
		/* Header length is bigger than total packet length */
		return FALSE;
	}

	if (it_len < sizeof(struct ieee80211_radiotap_header)) {
		/* Header length is shorter than fixed-length portion of header */
		return FALSE;
	}

	present = pletoh32(&hdr->it_present);
	offset += (int)sizeof(struct ieee80211_radiotap_header);
	it_len -= (int)sizeof(struct ieee80211_radiotap_header);

	/* skip over other present bitmaps */
	xpresent = present;
	while (xpresent & BIT(IEEE80211_RADIOTAP_EXT)) {
		if (!BYTES_ARE_IN_FRAME(offset, 4, it_len)) {
			return FALSE;
		}
		xpresent = pletoh32(pd + offset);
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
			return FALSE;
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
			return FALSE;
		}
		/* That field is present; fetch it. */
		if (!BYTES_ARE_IN_FRAME(offset, len, 1)) {
			return FALSE;
		}
		rflags = pd[offset];
	}

	/* 802.11 header follows */
	if (rflags & IEEE80211_RADIOTAP_F_DATAPAD)
		return capture_ieee80211_datapad(pd, offset + it_len, len, cpinfo, pseudo_header);

	return capture_ieee80211(pd, offset + it_len, len, cpinfo, pseudo_header);
}

static int
dissect_radiotap(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* unused_data _U_)
{
	proto_tree *radiotap_tree     = NULL;
	proto_item *present_item      = NULL;
	proto_tree *present_tree      = NULL;
	proto_item *present_word_item = NULL;
	proto_tree *present_word_tree = NULL;
	proto_tree *ft;
	proto_item *ti                = NULL;
	proto_item *hidden_item;
	int         offset;
	tvbuff_t   *next_tvb;
	guint8      version;
	guint       length;
	guint16     cflags;
	guint32     freq;
	proto_item *rate_ti;
	gint8       dbm, db;
	gboolean    have_rflags       = FALSE;
	guint8      rflags            = 0;
	guint32     xcflags;
	/* backward compat with bit 14 == fcs in header */
	proto_item *hdr_fcs_ti        = NULL;
	int         hdr_fcs_offset    = 0;
	guint32     sent_fcs          = 0;
	guint32     calc_fcs;
	gint        err               = -ENOENT;
	void       *data;
	struct _radiotap_info              *radiotap_info;
	static struct _radiotap_info        rtp_info_arr;
	struct ieee80211_radiotap_iterator  iter;
	struct ieee_802_11_phdr phdr;

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

	/* We don't have any 802.11 metadata yet. */
	memset(&phdr, 0, sizeof(phdr));
	phdr.fcs_len = -1;
	phdr.decrypted = FALSE;
	phdr.datapad = FALSE;
	phdr.phy = PHDR_802_11_PHY_UNKNOWN;

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
				    tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_length,
				    tvb, 2, 2, length);
	}

	data = tvb_memdup(wmem_packet_scope(), tvb, 0, length);

	if (ieee80211_radiotap_iterator_init(&iter, (struct ieee80211_radiotap_header *)data, length, NULL)) {
		if (tree)
			proto_item_append_text(ti, " (invalid)");
		/* maybe the length was correct anyway ... */
		goto hand_off_to_80211;
	}

	iter.overrides = overrides;
	iter.n_overrides = n_overrides;

	/* Add the "present flags" bitmaps. */
	if (tree) {
		guchar	 *bmap_start	      = (guchar *)data + 4;
		guint	  n_bitmaps	      = (guint)(iter.this_arg - bmap_start) / 4;
		guint	  i;
		gboolean  rtap_ns;
		gboolean  rtap_ns_next	      = TRUE;
		guint	  rtap_ns_offset;
		guint	  rtap_ns_offset_next = 0;

		present_item = proto_tree_add_item(radiotap_tree,
		    hf_radiotap_present, tvb, 4, n_bitmaps * 4, ENC_NA);
		present_tree = proto_item_add_subtree(present_item,
		    ett_radiotap_present);

		for (i = 0; i < n_bitmaps; i++) {
			guint32 bmap = pletoh32(bmap_start + 4 * i);

			rtap_ns_offset = rtap_ns_offset_next;
			rtap_ns_offset_next += 32;

			offset = 4 * i;

			present_word_item =
			    proto_tree_add_item(present_tree,
			      hf_radiotap_present_word,
			      tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);

			present_word_tree =
			    proto_item_add_subtree(present_word_item,
			      ett_radiotap_present_word);

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
				    BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))) {
				expert_add_info_format(pinfo, present_word_item,
				    &ei_radiotap_present,
				    "Both radiotap and vendor namespace specified in bitmask word %u",
				    i);
				goto malformed;
			}

			if (!rtap_ns)
				goto always_bits;

			/* Currently, we don't know anything about bits >= 32 */
			if (rtap_ns_offset)
				goto always_bits;

			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_tsft, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_flags, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_rate, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_channel, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_fhss, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_dbm_antsignal,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_dbm_antnoise,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_lock_quality,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_tx_attenuation,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_db_tx_attenuation,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_dbm_tx_power,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_antenna, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_db_antsignal,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_db_antnoise,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			if (radiotap_bit14_fcs) {
				proto_tree_add_item(present_word_tree,
						    hf_radiotap_present_hdrfcs,
						    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(present_word_tree,
						    hf_radiotap_present_rxflags,
						    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			}
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_xchannel, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);

			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_mcs, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_ampdu, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_vht, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			ti = proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_reserved, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			/* Check if Reserved/Not Defined is not "zero" */
			if(bmap & IEEE80211_RADIOTAP_NOTDEFINED)
			{
				expert_add_info(pinfo, present_word_item,
				    &ei_radiotap_present_reserved);
			}
 always_bits:
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_rtap_ns, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_vendor_ns, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_ext, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
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

			vt = proto_tree_add_bytes_format_value(radiotap_tree,
							 hf_radiotap_vendor_ns,
							 tvb, offset,
							 iter.this_arg_size,
							 NULL,
							 "%s-%d",
							 manuf_name, subns);
			ven_tree = proto_item_add_subtree(vt, ett_radiotap_vendor);
			proto_tree_add_bytes_format_value(ven_tree,
						    hf_radiotap_ven_oui, tvb,
						    offset, 3, NULL,
						    "%s", manuf_name);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_subns,
					    tvb, offset + 3, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_skip, tvb,
					    offset + 4, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_data, tvb,
					    offset + 6, iter.this_arg_size - 6,
					    ENC_NA);
		}

		if (!iter.is_radiotap_ns)
			continue;

		switch (iter.this_arg_index) {

		case IEEE80211_RADIOTAP_TSFT:
			radiotap_info->tsft = tvb_get_letoh64(tvb, offset);
			phdr.tsf_timestamp = radiotap_info->tsft;
			phdr.has_tsf_timestamp = TRUE;
			if (tree) {
				proto_tree_add_uint64(radiotap_tree,
						      hf_radiotap_mactime, tvb,
						      offset, 8,
						      radiotap_info->tsft);
			}
			break;

		case IEEE80211_RADIOTAP_FLAGS: {
			rflags = tvb_get_guint8(tvb, offset);
			have_rflags = TRUE;
			if (rflags & IEEE80211_RADIOTAP_F_DATAPAD)
				phdr.datapad = TRUE;
			if (rflags & IEEE80211_RADIOTAP_F_FCS)
				phdr.fcs_len = 4;
			else
				phdr.fcs_len = 0;

			if (tree) {
				proto_tree *flags_tree;

				ft = proto_tree_add_item(radiotap_tree,
							 hf_radiotap_flags,
							 tvb, offset, 1, ENC_BIG_ENDIAN);
				flags_tree =
				    proto_item_add_subtree(ft,
							   ett_radiotap_flags);

				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_cfp,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_preamble,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_wep,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_frag,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_fcs,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_datapad,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_badfcs,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(flags_tree,
						    hf_radiotap_flags_shortgi,
						    tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			break;
		}

		case IEEE80211_RADIOTAP_RATE: {
			guint32 rate;
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
			 */
			if (radiotap_interpret_high_rates_as_mcs &&
					rate >= 0x80 && rate <= (0x80+76)) {
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
				phdr.has_data_rate = TRUE;
				phdr.data_rate = rate;
			}
			break;
		}

		case IEEE80211_RADIOTAP_CHANNEL: {
			freq = tvb_get_letohs(tvb, offset);
			if (freq != 0) {
				/*
				 * XXX - some captures have 0, which is
				 * obviously bogus.
				 */
				gint calc_channel;

				phdr.has_frequency = TRUE;
				phdr.frequency = freq;
				calc_channel = ieee80211_mhz_to_chan(freq);
				if (calc_channel != -1) {
					phdr.has_channel = TRUE;
					phdr.channel = calc_channel;
				}
			}
			memset(&phdr.phy_info, 0, sizeof(phdr.phy_info));
			cflags = tvb_get_letohs(tvb, offset + 2);
			switch (cflags & IEEE80211_CHAN_ALLTURBO) {

			case IEEE80211_CHAN_FHSS:
				phdr.phy = PHDR_802_11_PHY_11_FHSS;
				break;

			case IEEE80211_CHAN_DSSS:
				phdr.phy = PHDR_802_11_PHY_11_DSSS;
				break;

			case IEEE80211_CHAN_A:
				phdr.phy = PHDR_802_11_PHY_11A;
				phdr.phy_info.info_11a.has_turbo_type = TRUE;
				phdr.phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_NORMAL;
				break;

			case IEEE80211_CHAN_B:
				phdr.phy = PHDR_802_11_PHY_11B;
				if (have_rflags) {
					phdr.phy_info.info_11b.has_short_preamble = TRUE;
					phdr.phy_info.info_11b.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_PUREG:
				phdr.phy = PHDR_802_11_PHY_11G;
				phdr.phy_info.info_11g.has_mode = TRUE;
				phdr.phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
				if (have_rflags) {
					phdr.phy_info.info_11g.has_short_preamble = TRUE;
					phdr.phy_info.info_11g.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_G:
				phdr.phy = PHDR_802_11_PHY_11G;
				phdr.phy_info.info_11g.has_mode = TRUE;
				phdr.phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
				if (have_rflags) {
					phdr.phy_info.info_11g.has_short_preamble = TRUE;
					phdr.phy_info.info_11g.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_108A:
				phdr.phy = PHDR_802_11_PHY_11A;
				phdr.phy_info.info_11a.has_turbo_type = TRUE;
				/* We assume non-STURBO is dynamic turbo */
				phdr.phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO;
				break;

			case IEEE80211_CHAN_108PUREG:
				phdr.phy = PHDR_802_11_PHY_11G;
				phdr.phy_info.info_11g.has_mode = TRUE;
				phdr.phy_info.info_11g.mode = PHDR_802_11G_MODE_SUPER_G;
				if (have_rflags) {
					phdr.phy_info.info_11g.has_short_preamble = TRUE;
					phdr.phy_info.info_11g.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;
			}
			if (tree) {
				gchar	   *chan_str;
				static const int * channel_flags[] = {
					&hf_radiotap_channel_flags_turbo,
					&hf_radiotap_channel_flags_cck,
					&hf_radiotap_channel_flags_ofdm,
					&hf_radiotap_channel_flags_2ghz,
					&hf_radiotap_channel_flags_5ghz,
					&hf_radiotap_channel_flags_passive,
					&hf_radiotap_channel_flags_dynamic,
					&hf_radiotap_channel_flags_gfsk,
					&hf_radiotap_channel_flags_gsm,
					&hf_radiotap_channel_flags_sturbo,
					&hf_radiotap_channel_flags_half,
					&hf_radiotap_channel_flags_quarter,
					NULL
				};

				chan_str = ieee80211_mhz_to_str(freq);
				col_add_fstr(pinfo->cinfo,
					     COL_FREQ_CHAN, "%s", chan_str);
				proto_tree_add_uint_format_value(radiotap_tree,
							   hf_radiotap_channel_frequency,
							   tvb, offset, 2, freq,
							   "%s",
							   chan_str);
				g_free(chan_str);

				/* We're already 2-byte aligned. */
				proto_tree_add_bitmask(radiotap_tree, tvb, offset + 2, hf_radiotap_channel_flags, ett_radiotap_channel_flags, channel_flags, ENC_LITTLE_ENDIAN);
				radiotap_info->freq = freq;
				radiotap_info->flags = cflags;
			}
			break;
		}

		case IEEE80211_RADIOTAP_FHSS:
			/*
			 * Just in case we didn't have a Channel field or
			 * it said this was something other than 11 legacy
			 * FHSS.
			 */
			phdr.phy = PHDR_802_11_PHY_11_FHSS;
			phdr.phy_info.info_11_fhss.has_hop_set = TRUE;
			phdr.phy_info.info_11_fhss.hop_set = tvb_get_guint8(tvb, offset);
			phdr.phy_info.info_11_fhss.has_hop_pattern = TRUE;
			phdr.phy_info.info_11_fhss.hop_pattern = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_fhss_hopset, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_fhss_pattern, tvb,
					    offset + 1, 1, ENC_BIG_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			dbm = (gint8)tvb_get_guint8(tvb, offset);
			phdr.has_signal_dbm = TRUE;
			phdr.signal_dbm = dbm;
			col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
			proto_tree_add_int_format_value(radiotap_tree,
							  hf_radiotap_dbm_antsignal,
							  tvb, offset, 1, dbm,
							  "%d dBm",
							  dbm);
			radiotap_info->dbm_antsignal = dbm;
			break;

		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			dbm = (gint8) tvb_get_guint8(tvb, offset);
			phdr.has_noise_dbm = TRUE;
			phdr.noise_dbm = dbm;
			if (tree) {
				proto_tree_add_int_format_value(radiotap_tree,
							  hf_radiotap_dbm_antnoise,
							  tvb, offset, 1, dbm,
							  "%d dBm",
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
					    offset, 2, ENC_BIG_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			proto_tree_add_item(radiotap_tree,
					    hf_radiotap_db_tx_attenuation, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
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
				proto_tree_add_uint_format_value(radiotap_tree,
							   hf_radiotap_db_antsignal,
							   tvb, offset, 1, db,
							   "%u dB",
							   db);
			}
			break;

		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			db = tvb_get_guint8(tvb, offset);
			if (tree) {
				proto_tree_add_uint_format_value(radiotap_tree,
							   hf_radiotap_db_antnoise,
							   tvb, offset, 1, db,
							   "%u dB",
							   db);
			}
			break;

		case IEEE80211_RADIOTAP_RX_FLAGS: {
			if (radiotap_bit14_fcs) {
				if (tree) {
					sent_fcs   = tvb_get_ntohl(tvb, offset);
					hdr_fcs_ti = proto_tree_add_uint(radiotap_tree,
									 hf_radiotap_fcs, tvb,
									 offset, 4, sent_fcs);
					hdr_fcs_offset = offset;
				}
			} else {
				static const int * rxflags[] = {
					&hf_radiotap_rxflags_badplcp,
					NULL
				};

				proto_tree_add_bitmask(radiotap_tree, tvb, offset, hf_radiotap_rxflags, ett_radiotap_rxflags, rxflags, ENC_LITTLE_ENDIAN);
			}
			break;
		}

		case IEEE80211_RADIOTAP_XCHANNEL: {
			xcflags = tvb_get_letohl(tvb, offset);
			switch (xcflags & IEEE80211_CHAN_ALLTURBO) {

			case IEEE80211_CHAN_FHSS:
				/*
				 * Don't overwrite any FHSS information
				 * we've seen before this.
				 */
				if (phdr.phy != PHDR_802_11_PHY_11_FHSS) {
					phdr.phy = PHDR_802_11_PHY_11_FHSS;
				}
				break;

			case IEEE80211_CHAN_DSSS:
				phdr.phy = PHDR_802_11_PHY_11_DSSS;
				break;

			case IEEE80211_CHAN_A:
				phdr.phy = PHDR_802_11_PHY_11A;
				phdr.phy_info.info_11a.has_turbo_type = TRUE;
				phdr.phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_NORMAL;
				break;

			case IEEE80211_CHAN_B:
				phdr.phy = PHDR_802_11_PHY_11B;
				if (have_rflags) {
					phdr.phy_info.info_11b.has_short_preamble = TRUE;
					phdr.phy_info.info_11b.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_PUREG:
				phdr.phy = PHDR_802_11_PHY_11G;
				phdr.phy_info.info_11g.has_mode = TRUE;
				phdr.phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
				if (have_rflags) {
					phdr.phy_info.info_11g.has_short_preamble = TRUE;
					phdr.phy_info.info_11g.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_G:
				phdr.phy = PHDR_802_11_PHY_11G;
				phdr.phy_info.info_11g.has_mode = TRUE;
				phdr.phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
				if (have_rflags) {
					phdr.phy_info.info_11g.has_short_preamble = TRUE;
					phdr.phy_info.info_11g.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_108A:
				phdr.phy = PHDR_802_11_PHY_11A;
				phdr.phy_info.info_11a.has_turbo_type = TRUE;
				/* We assume non-STURBO is dynamic turbo */
				phdr.phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO;
				break;

			case IEEE80211_CHAN_108PUREG:
				phdr.phy = PHDR_802_11_PHY_11G;
				phdr.phy_info.info_11g.has_mode = TRUE;
				phdr.phy_info.info_11g.mode = PHDR_802_11G_MODE_SUPER_G;
				if (have_rflags) {
					phdr.phy_info.info_11g.has_short_preamble = TRUE;
					phdr.phy_info.info_11g.short_preamble = (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) != 0;
				}
				break;

			case IEEE80211_CHAN_ST:
				phdr.phy = PHDR_802_11_PHY_11A;
				phdr.phy_info.info_11a.has_turbo_type = TRUE;
				phdr.phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_STATIC_TURBO;
				break;

			case IEEE80211_CHAN_A|IEEE80211_CHAN_HT20:
			case IEEE80211_CHAN_A|IEEE80211_CHAN_HT40D:
			case IEEE80211_CHAN_A|IEEE80211_CHAN_HT40U:
			case IEEE80211_CHAN_G|IEEE80211_CHAN_HT20:
			case IEEE80211_CHAN_G|IEEE80211_CHAN_HT40U:
			case IEEE80211_CHAN_G|IEEE80211_CHAN_HT40D:
				phdr.phy = PHDR_802_11_PHY_11N;

				/*
				 * This doesn't supply "short GI" information,
				 * so use the 0x80 bit in the Flags field,
				 * if we have it; it's "Currently unspecified
				 * but used" for that purpose, according to
				 * the radiotap.org page for that field.
				 */
				if (have_rflags) {
					phdr.phy_info.info_11n.has_short_gi = TRUE;
					if (rflags & 0x80)
						phdr.phy_info.info_11n.short_gi = 1;
					else
						phdr.phy_info.info_11n.short_gi = 0;
				}
				break;
			}
			freq = tvb_get_letohs(tvb, offset + 4);
			if (freq != 0) {
				/*
				 * XXX - some captures have 0, which is
				 * obviously bogus.
				 */
				phdr.has_frequency = TRUE;
				phdr.frequency = freq;
			}
			phdr.has_channel = TRUE;
			phdr.channel = tvb_get_guint8(tvb, offset + 6);
			if (tree) {
				static const int * xchannel_flags[] = {
					&hf_radiotap_xchannel_flags_turbo,
					&hf_radiotap_xchannel_flags_cck,
					&hf_radiotap_xchannel_flags_ofdm,
					&hf_radiotap_xchannel_flags_2ghz,
					&hf_radiotap_xchannel_flags_5ghz,
					&hf_radiotap_xchannel_flags_passive,
					&hf_radiotap_xchannel_flags_dynamic,
					&hf_radiotap_xchannel_flags_gfsk,
					&hf_radiotap_xchannel_flags_gsm,
					&hf_radiotap_xchannel_flags_sturbo,
					&hf_radiotap_xchannel_flags_half,
					&hf_radiotap_xchannel_flags_quarter,
					&hf_radiotap_xchannel_flags_ht20,
					&hf_radiotap_xchannel_flags_ht40u,
					&hf_radiotap_xchannel_flags_ht40d,
					NULL
				};

				proto_tree_add_item(radiotap_tree,
							hf_radiotap_xchannel_channel,
							tvb, offset + 6, 1,
							ENC_LITTLE_ENDIAN);
				proto_tree_add_item(radiotap_tree,
							hf_radiotap_xchannel_frequency,
							tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);

				proto_tree_add_bitmask(radiotap_tree, tvb, offset, hf_radiotap_xchannel_flags, ett_radiotap_xchannel_flags, xchannel_flags, ENC_LITTLE_ENDIAN);


#if 0
				proto_tree_add_uint(radiotap_tree,
							hf_radiotap_xchannel_maxpower,
							tvb, offset + 7, 1, maxpower);
#endif
			}
			break;
		}
		case IEEE80211_RADIOTAP_MCS: {
			proto_tree *mcs_tree = NULL;
			guint8	    mcs_known, mcs_flags;
			guint8	    mcs;
			guint	    bandwidth;
			guint	    gi_length;
			gboolean    can_calculate_rate;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = TRUE;

			mcs_known = tvb_get_guint8(tvb, offset);
			/*
			 * If there's actually any data here, not an
			 * empty field, this is 802.11n.
			 */
			if (mcs_known != 0) {
				phdr.phy = PHDR_802_11_PHY_11N;
				memset(&phdr.phy_info.info_11n, 0, sizeof(phdr.phy_info.info_11n));
			}

			mcs_flags = tvb_get_guint8(tvb, offset + 1);
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
				mcs = tvb_get_guint8(tvb, offset + 2);
				phdr.phy_info.info_11n.has_mcs_index = TRUE;
				phdr.phy_info.info_11n.mcs_index = mcs;
			} else {
				mcs = 0;
				can_calculate_rate = FALSE;	/* no MCS index */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
				phdr.phy_info.info_11n.has_bandwidth = TRUE;
				phdr.phy_info.info_11n.bandwidth = (mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
				gi_length = (mcs_flags & IEEE80211_RADIOTAP_MCS_SGI) ?
				    1 : 0;
				phdr.phy_info.info_11n.has_short_gi = TRUE;
				phdr.phy_info.info_11n.short_gi = gi_length;
			} else {
				gi_length = 0;
				can_calculate_rate = FALSE;	/* no GI width */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
				phdr.phy_info.info_11n.has_greenfield = TRUE;
				phdr.phy_info.info_11n.greenfield = (mcs_flags & IEEE80211_RADIOTAP_MCS_FMT_GF) != 0;
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
				phdr.phy_info.info_11n.has_fec = TRUE;
				phdr.phy_info.info_11n.fec = (mcs_flags & IEEE80211_RADIOTAP_MCS_FEC_LDPC) ? 1 : 0;
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				phdr.phy_info.info_11n.has_stbc_streams = TRUE;
				phdr.phy_info.info_11n.stbc_streams = (mcs_flags & IEEE80211_RADIOTAP_MCS_STBC_MASK) >> IEEE80211_RADIOTAP_MCS_STBC_SHIFT;
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_NESS) {
				phdr.phy_info.info_11n.has_ness = TRUE;
				/* This is stored a bit weirdly */
				phdr.phy_info.info_11n.ness =
				    ((mcs_known & IEEE80211_RADIOTAP_MCS_NESS_BIT1) >> 6) |
				    ((mcs_flags & IEEE80211_RADIOTAP_MCS_NESS_BIT0) >> 7);
			}

			if (tree) {
				proto_item *it;
				static const int * mcs_haves_with_ness_bit1[] = {
					&hf_radiotap_mcs_have_bw,
					&hf_radiotap_mcs_have_index,
					&hf_radiotap_mcs_have_gi,
					&hf_radiotap_mcs_have_format,
					&hf_radiotap_mcs_have_fec,
					&hf_radiotap_mcs_have_stbc,
					&hf_radiotap_mcs_have_ness,
					&hf_radiotap_mcs_ness_bit1,
					NULL
				};
				static const int * mcs_haves_without_ness_bit1[] = {
					&hf_radiotap_mcs_have_bw,
					&hf_radiotap_mcs_have_index,
					&hf_radiotap_mcs_have_gi,
					&hf_radiotap_mcs_have_format,
					&hf_radiotap_mcs_have_fec,
					&hf_radiotap_mcs_have_stbc,
					&hf_radiotap_mcs_have_ness,
					NULL
				};

				it = proto_tree_add_item(radiotap_tree, hf_radiotap_mcs,
							 tvb, offset, 3, ENC_NA);
				mcs_tree = proto_item_add_subtree(it, ett_radiotap_mcs);

				if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_NESS)
					proto_tree_add_bitmask(mcs_tree, tvb, offset, hf_radiotap_mcs_known, ett_radiotap_mcs_known, mcs_haves_with_ness_bit1, ENC_LITTLE_ENDIAN);
				else
					proto_tree_add_bitmask(mcs_tree, tvb, offset, hf_radiotap_mcs_known, ett_radiotap_mcs_known, mcs_haves_without_ness_bit1, ENC_LITTLE_ENDIAN);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
				bandwidth = ((mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40) ?
				    1 : 0;
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_bw,
							    tvb, offset + 1, 1, mcs_flags);
			} else {
				bandwidth = 0;
				can_calculate_rate = FALSE;	/* no bandwidth */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_gi,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_format,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_fec,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_stbc,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_NESS) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_ness_bit0,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_index,
							    tvb, offset + 2, 1, mcs);
			}

			/*
			 * If we have the MCS index, channel width, and
			 * guard interval length, and the MCS index is
			 * valid, we can compute the rate.  If the resulting
			 * rate is non-zero, report it.  (If it's zero,
			 * it's an MCS/channel width/GI combination that
			 * 802.11n doesn't support.)
			 */
			if (can_calculate_rate && mcs <= MAX_MCS_INDEX
					&& ieee80211_ht_Dbps[mcs] != 0) {
				float rate = ieee80211_htrate(mcs, bandwidth, gi_length);
				col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", rate);
				if (tree) {
					rate_ti = proto_tree_add_float_format(radiotap_tree,
						hf_radiotap_datarate,
						tvb, offset, 3, rate,
						"Data Rate: %.1f Mb/s", rate);
					PROTO_ITEM_SET_GENERATED(rate_ti);
				}
			}
			break;
		}
		case IEEE80211_RADIOTAP_AMPDU_STATUS: {
			proto_item *it;
			proto_tree *ampdu_tree = NULL, *ampdu_flags_tree;
			guint16	    ampdu_flags;

			phdr.has_aggregate_info = 1;
			phdr.aggregate_flags = 0;
			phdr.aggregate_id = tvb_get_letohl(tvb, offset);

			ampdu_flags = tvb_get_letohs(tvb, offset + 4);
			if (ampdu_flags & IEEE80211_RADIOTAP_AMPDU_IS_LAST)
				phdr.aggregate_flags |= PHDR_802_11_LAST_PART_OF_A_MPDU;
			if (ampdu_flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR)
				phdr.aggregate_flags |= PHDR_802_11_A_MPDU_DELIM_CRC_ERROR;

			if (tree) {
				it = proto_tree_add_item(radiotap_tree, hf_radiotap_ampdu,
							 tvb, offset, 8, ENC_NA);
				ampdu_tree = proto_item_add_subtree(it, ett_radiotap_ampdu);

				proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_ref,
						    tvb, offset, 4, ENC_LITTLE_ENDIAN);

				it = proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_flags,
							 tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				ampdu_flags_tree = proto_item_add_subtree(it, ett_radiotap_ampdu_flags);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_report_zerolen,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_is_zerolen,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_last_known,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_is_last,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_delim_crc_error,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
			}
			if (ampdu_flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN) {
				if (ampdu_tree)
					proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_delim_crc,
							    tvb, offset + 6, 1, ENC_NA);
			}
			break;
		}
		case IEEE80211_RADIOTAP_VHT: {
			proto_item *it, *it_root = NULL;
			proto_tree *vht_tree	 = NULL, *vht_known_tree = NULL, *user_tree = NULL;
			guint16	    known;
			guint8	    vht_flags, bw, mcs_nss;
			guint	    bandwidth	 = 0;
			guint	    gi_length	 = 0;
			guint	    nss		 = 0;
			guint	    mcs		 = 0;
			gboolean    can_calculate_rate;
			guint	    i;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = TRUE;

			known = tvb_get_letohs(tvb, offset);
			/*
			 * If there's actually any data here, not an
			 * empty field, this is 802.11ac.
			 */
			if (known != 0) {
				phdr.phy = PHDR_802_11_PHY_11AC;
			}
			vht_flags = tvb_get_guint8(tvb, offset + 2);
			if (tree) {
				it_root = proto_tree_add_item(radiotap_tree, hf_radiotap_vht,
						tvb, offset, 12, ENC_NA);
				vht_tree = proto_item_add_subtree(it_root, ett_radiotap_vht);
				it = proto_tree_add_item(vht_tree, hf_radiotap_vht_known,
						tvb, offset, 2, known);
				vht_known_tree = proto_item_add_subtree(it, ett_radiotap_vht_known);

				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_stbc,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_txop_ps,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_gi,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_sgi_nsym_da,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_ldpc_extra,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_bf,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_bw,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_gid,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_p_aid,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_STBC) {
				phdr.phy_info.info_11ac.has_stbc = TRUE;
				phdr.phy_info.info_11ac.stbc = (vht_flags & IEEE80211_RADIOTAP_VHT_STBC) != 0;
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_stbc,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_TXOP_PS) {
				phdr.phy_info.info_11ac.has_txop_ps_not_allowed = TRUE;
				phdr.phy_info.info_11ac.txop_ps_not_allowed = (vht_flags & IEEE80211_RADIOTAP_VHT_TXOP_PS) != 0;
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_txop_ps,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_GI) {
				gi_length = (vht_flags & IEEE80211_RADIOTAP_VHT_SGI) ? 1 : 0;
				phdr.phy_info.info_11ac.has_short_gi = TRUE;
				phdr.phy_info.info_11ac.short_gi = gi_length;
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_gi,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
				}
			} else {
				can_calculate_rate = FALSE;	/* no GI width */
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_SGI_NSYM_DA) {
				phdr.phy_info.info_11ac.has_short_gi_nsym_disambig = TRUE;
				phdr.phy_info.info_11ac.short_gi_nsym_disambig = (vht_flags & IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA) != 0;
				if (vht_tree) {
					it = proto_tree_add_item(vht_tree, hf_radiotap_vht_sgi_nsym_da,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
					if ((vht_flags & IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA) &&
						(known & IEEE80211_RADIOTAP_VHT_HAVE_GI) &&
						!(vht_flags & IEEE80211_RADIOTAP_VHT_SGI))
						proto_item_append_text(it, " (invalid)");
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_LDPC_EXTRA) {
				phdr.phy_info.info_11ac.has_ldpc_extra_ofdm_symbol = TRUE;
				phdr.phy_info.info_11ac.ldpc_extra_ofdm_symbol = (vht_flags & IEEE80211_RADIOTAP_VHT_LDPC_EXTRA) != 0;
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_ldpc_extra,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_BF) {
				phdr.phy_info.info_11ac.has_beamformed = TRUE;
				phdr.phy_info.info_11ac.beamformed = (vht_flags & IEEE80211_RADIOTAP_VHT_BF) != 0;
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_bf,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_BW) {
				bw = tvb_get_guint8(tvb, offset + 3) & IEEE80211_RADIOTAP_VHT_BW_MASK;
				phdr.phy_info.info_11ac.has_bandwidth = TRUE;
				phdr.phy_info.info_11ac.bandwidth = bw;
				if (bw < sizeof(ieee80211_vht_bw2rate_index)/sizeof(ieee80211_vht_bw2rate_index[0]))
					bandwidth = ieee80211_vht_bw2rate_index[bw];
				else
					can_calculate_rate = FALSE; /* unknown bandwidth */

				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_bw,
							tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
			} else {
				can_calculate_rate = FALSE;	/* no bandwidth */
			}

			phdr.phy_info.info_11ac.has_fec = TRUE;
			phdr.phy_info.info_11ac.fec = tvb_get_guint8(tvb, offset + 8);

			for(i=0; i<4; i++) {
				mcs_nss = tvb_get_guint8(tvb, offset + 4 + i);
				nss = (mcs_nss & IEEE80211_RADIOTAP_VHT_NSS);
				mcs = (mcs_nss & IEEE80211_RADIOTAP_VHT_MCS) >> 4;
				phdr.phy_info.info_11ac.mcs[i] = mcs;
				phdr.phy_info.info_11ac.nss[i] = nss;

				if (nss) {
					/*
					 * OK, there's some data here.
					 * If we haven't already flagged this
					 * as VHT, do so.
					 */
					if (phdr.phy != PHDR_802_11_PHY_11AC) {
						phdr.phy = PHDR_802_11_PHY_11AC;
					}
					if (vht_tree) {
						it = proto_tree_add_item(vht_tree, hf_radiotap_vht_user,
							tvb, offset + 4, 5, ENC_NA);
						proto_item_append_text(it, " %d: MCS %u", i, mcs);
						user_tree = proto_item_add_subtree(it, ett_radiotap_vht_user);

						it = proto_tree_add_item(user_tree, hf_radiotap_vht_mcs[i],
							tvb, offset + 4 + i, 1,
							ENC_LITTLE_ENDIAN);
						if (mcs > MAX_MCS_VHT_INDEX) {
							proto_item_append_text(it, " (invalid)");
						} else {
							proto_item_append_text(it, " (%s %s)",
								ieee80211_vhtinfo[mcs].modulation,
								ieee80211_vhtinfo[mcs].coding_rate);
						}

						proto_tree_add_item(user_tree, hf_radiotap_vht_nss[i],
							tvb, offset + 4 + i, 1, ENC_LITTLE_ENDIAN);
						if (known & IEEE80211_RADIOTAP_VHT_HAVE_STBC) {
							guint nsts;
							proto_item *nsts_ti;

							if (vht_flags & IEEE80211_RADIOTAP_VHT_STBC)
								nsts = 2 * nss;
							else
								nsts = nss;
							nsts_ti = proto_tree_add_uint(user_tree, hf_radiotap_vht_nsts[i],
								tvb, offset + 4 + i, 1, nsts);
							PROTO_ITEM_SET_GENERATED(nsts_ti);
						}
						proto_tree_add_item(user_tree, hf_radiotap_vht_coding[i],
							tvb, offset + 8, 1,ENC_LITTLE_ENDIAN);
					}

					if (can_calculate_rate && mcs <= MAX_MCS_VHT_INDEX &&
					    nss <= MAX_VHT_NSS ) {
						float rate = ieee80211_vhtinfo[mcs].rates[bandwidth][gi_length] * nss;
						if (rate != 0.0f ) {
							rate_ti = proto_tree_add_float_format(user_tree,
									hf_radiotap_vht_datarate[i],
									tvb, offset, 12, rate,
									"Data Rate: %.1f Mb/s", rate);
							PROTO_ITEM_SET_GENERATED(rate_ti);
							if (ieee80211_vhtvalid[mcs].valid[bandwidth][nss] == FALSE)
								expert_add_info(pinfo, rate_ti, &ei_radiotap_invalid_data_rate);

						}
					}
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_GID) {
				phdr.phy_info.info_11ac.has_group_id = TRUE;
				phdr.phy_info.info_11ac.group_id = tvb_get_guint8(tvb, offset + 9);
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_gid,
							tvb, offset+9, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_PAID) {
				phdr.phy_info.info_11ac.has_partial_aid = TRUE;
				phdr.phy_info.info_11ac.partial_aid = tvb_get_letohs(tvb, offset + 10);
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_p_aid,
							tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
				}
			}

			break;
		}
		}
	}

	if (err != -ENOENT && tree) {
		expert_add_info(pinfo, present_item,
		    &ei_radiotap_data_past_header);
 malformed:
		proto_item_append_text(ti, " (malformed)");
	}

 hand_off_to_80211:
	/* Grab the rest of the frame. */
	next_tvb = tvb_new_subset_remaining(tvb, length);

	/* If we had an in-header FCS, check it.
	 * This can only happen if the backward-compat configuration option
	 * is chosen by the user. */
	if (hdr_fcs_ti) {
		guint captured_length = tvb_captured_length(next_tvb);
		guint reported_length = tvb_reported_length(next_tvb);
		guint fcs_len = (phdr.fcs_len > 0) ? phdr.fcs_len : 0;

		/* It would be very strange for the header to have an FCS for the
		 * frame *and* the frame to have the FCS at the end, but it's possible, so
		 * take that into account by using the FCS length recorded in pinfo. */

		/* Watch out for [erroneously] short frames */
		if (captured_length >= reported_length &&
		    captured_length > fcs_len) {
			calc_fcs =
			    crc32_802_tvb(next_tvb, tvb_captured_length(next_tvb) - fcs_len);

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

	/* dissect the 802.11 packet next */
	call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo,
	    tree, &phdr);

	tap_queue_packet(radiotap_tap, pinfo, radiotap_info);
	return tvb_captured_length(tvb);
}

void proto_register_radiotap(void)
{

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
		  "Length of header including version, pad, length and data fields", HFILL}},

		{&hf_radiotap_present,
		 {"Present flags", "radiotap.present",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  "Bitmask indicating which fields are present", HFILL}},

		{&hf_radiotap_present_word,
		 {"Present flags word", "radiotap.present.word",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Word from present flags bitmask", HFILL}},

#define RADIOTAP_MASK(name)	BIT(IEEE80211_RADIOTAP_ ##name)

		/* Boolean 'present' flags */
		{&hf_radiotap_present_tsft,
		 {"TSFT", "radiotap.present.tsft",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TSFT),
		  "Specifies if the Time Synchronization Function Timer field is present", HFILL}},

		{&hf_radiotap_present_flags,
		 {"Flags", "radiotap.present.flags",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(FLAGS),
		  "Specifies if the channel flags field is present", HFILL}},

		{&hf_radiotap_present_rate,
		 {"Rate", "radiotap.present.rate",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(RATE),
		  "Specifies if the transmit/receive rate field is present", HFILL}},

		{&hf_radiotap_present_channel,
		 {"Channel", "radiotap.present.channel",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(CHANNEL),
		  "Specifies if the transmit/receive frequency field is present", HFILL}},

		{&hf_radiotap_present_fhss,
		 {"FHSS", "radiotap.present.fhss",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(FHSS),
		  "Specifies if the hop set and pattern is present for frequency hopping radios", HFILL}},

		{&hf_radiotap_present_dbm_antsignal,
		 {"dBm Antenna Signal", "radiotap.present.dbm_antsignal",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DBM_ANTSIGNAL),
		  "Specifies if the antenna signal strength in dBm is present", HFILL}},

		{&hf_radiotap_present_dbm_antnoise,
		 {"dBm Antenna Noise", "radiotap.present.dbm_antnoise",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DBM_ANTNOISE),
		  "Specifies if the RF noise power at antenna field is present", HFILL}},

		{&hf_radiotap_present_lock_quality,
		 {"Lock Quality", "radiotap.present.lock_quality",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(LOCK_QUALITY),
		  "Specifies if the signal quality field is present", HFILL}},

		{&hf_radiotap_present_tx_attenuation,
		 {"TX Attenuation", "radiotap.present.tx_attenuation",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TX_ATTENUATION),
		  "Specifies if the transmit power distance from max power field is present", HFILL}},

		{&hf_radiotap_present_db_tx_attenuation,
		 {"dB TX Attenuation", "radiotap.present.db_tx_attenuation",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DB_TX_ATTENUATION),
		  "Specifies if the transmit power distance from max power (in dB) field is present", HFILL}},

		{&hf_radiotap_present_dbm_tx_power,
		 {"dBm TX Power", "radiotap.present.dbm_tx_power",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DBM_TX_POWER),
		  "Specifies if the transmit power (in dBm) field is present", HFILL}},

		{&hf_radiotap_present_antenna,
		 {"Antenna", "radiotap.present.antenna",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(ANTENNA),
		  "Specifies if the antenna number field is present", HFILL}},

		{&hf_radiotap_present_db_antsignal,
		 {"dB Antenna Signal", "radiotap.present.db_antsignal",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DB_ANTSIGNAL),
		  "Specifies if the RF signal power at antenna in dB field is present", HFILL}},

		{&hf_radiotap_present_db_antnoise,
		 {"dB Antenna Noise", "radiotap.present.db_antnoise",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DB_ANTNOISE),
		  "Specifies if the RF signal power at antenna in dBm field is present", HFILL}},

		{&hf_radiotap_present_rxflags,
		 {"RX flags", "radiotap.present.rxflags",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(RX_FLAGS),
		  "Specifies if the RX flags field is present", HFILL}},

		{&hf_radiotap_present_hdrfcs,
		 {"FCS in header", "radiotap.present.fcs",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(RX_FLAGS),
		  "Specifies if the FCS field is present", HFILL}},

		{&hf_radiotap_present_xchannel,
		 {"Channel+", "radiotap.present.xchannel",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(XCHANNEL),
		  "Specifies if the extended channel info field is present", HFILL}},

		{&hf_radiotap_present_mcs,
		 {"MCS information", "radiotap.present.mcs",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(MCS),
		  "Specifies if the MCS field is present", HFILL}},

		{&hf_radiotap_present_ampdu,
		 {"A-MPDU Status", "radiotap.present.ampdu",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(AMPDU_STATUS),
		  "Specifies if the A-MPDU status field is present", HFILL}},

		{&hf_radiotap_present_vht,
		 {"VHT information", "radiotap.present.vht",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(VHT),
		  "Specifies if the VHT field is present", HFILL}},

		{&hf_radiotap_present_reserved,
		 {"Reserved", "radiotap.present.reserved",
		  FT_UINT32, BASE_HEX, NULL, IEEE80211_RADIOTAP_NOTDEFINED,
		  "Not (yet) defined present flags (Must be zero)", HFILL}},

		{&hf_radiotap_present_rtap_ns,
		 {"Radiotap NS next", "radiotap.present.rtap_ns",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(RADIOTAP_NAMESPACE),
		  "Specifies a reset to the radiotap namespace", HFILL}},

		{&hf_radiotap_present_vendor_ns,
		 {"Vendor NS next", "radiotap.present.vendor_ns",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(VENDOR_NAMESPACE),
		  "Specifies that the next bitmap is in a vendor namespace", HFILL}},

		{&hf_radiotap_present_ext,
		 {"Ext", "radiotap.present.ext",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(EXT),
		  "Specifies if there are any extensions to the header present", HFILL}},

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
		  "Frame has padding between 802.11 header and payload", HFILL}},

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
		  "Value in microseconds of the MAC's Time Synchronization Function timer"
		  " when the first bit of the MPDU arrived at the MAC.",
		  HFILL}},

		{&hf_radiotap_quality,
		 {"Signal Quality", "radiotap.quality",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Signal quality (unitless measure)", HFILL}},

		{&hf_radiotap_fcs,
		 {"802.11 FCS", "radiotap.fcs",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Frame check sequence of this frame", HFILL}},

#if 0
		{&hf_radiotap_channel,
		 {"Channel", "radiotap.channel",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "802.11 channel number that this frame was sent/received on", HFILL}},
#endif

		{&hf_radiotap_channel_frequency,
		 {"Channel frequency", "radiotap.channel.freq",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Channel frequency in megahertz that this frame was sent/received on", HFILL}},

		{&hf_radiotap_channel_flags,
		 {"Channel flags", "radiotap.channel.flags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_channel_flags_turbo,
		 {"Turbo", "radiotap.channel.flags.turbo",
		  FT_BOOLEAN, 16, NULL, 0x0010, "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_channel_flags_cck,
		 {"Complementary Code Keying (CCK)", "radiotap.channel.flags.cck",
		  FT_BOOLEAN, 16, NULL, 0x0020,
		  "Channel Flags Complementary Code Keying (CCK) Modulation", HFILL}},

		{&hf_radiotap_channel_flags_ofdm,
		 {"Orthogonal Frequency-Division Multiplexing (OFDM)", "radiotap.channel.flags.ofdm",
		  FT_BOOLEAN, 16, NULL, 0x0040,
		  "Channel Flags Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL}},

		{&hf_radiotap_channel_flags_2ghz,
		 {"2 GHz spectrum", "radiotap.channel.flags.2ghz",
		  FT_BOOLEAN, 16, NULL, 0x0080, "Channel Flags 2 GHz spectrum", HFILL}},

		{&hf_radiotap_channel_flags_5ghz,
		 {"5 GHz spectrum", "radiotap.channel.flags.5ghz",
		  FT_BOOLEAN, 16, NULL, 0x0100, "Channel Flags 5 GHz spectrum", HFILL}},

		{&hf_radiotap_channel_flags_passive,
		 {"Passive", "radiotap.channel.flags.passive",
		  FT_BOOLEAN, 16, NULL, 0x0200,
		  "Channel Flags Passive", HFILL}},

		{&hf_radiotap_channel_flags_dynamic,
		 {"Dynamic CCK-OFDM", "radiotap.channel.flags.dynamic",
		  FT_BOOLEAN, 16, NULL, 0x0400,
		  "Channel Flags Dynamic CCK-OFDM Channel", HFILL}},

		{&hf_radiotap_channel_flags_gfsk,
		 {"Gaussian Frequency Shift Keying (GFSK)", "radiotap.channel.flags.gfsk",
		  FT_BOOLEAN, 16, NULL, 0x0800,
		  "Channel Flags Gaussian Frequency Shift Keying (GFSK) Modulation", HFILL}},

		{&hf_radiotap_channel_flags_gsm,
		 {"GSM (900MHz)", "radiotap.channel.flags.gsm",
		  FT_BOOLEAN, 16, NULL, 0x1000,
		  "Channel Flags GSM", HFILL}},

		{&hf_radiotap_channel_flags_sturbo,
		 {"Static Turbo", "radiotap.channel.flags.sturbo",
		  FT_BOOLEAN, 16, NULL, 0x2000,
		  "Channel Flags Status Turbo", HFILL}},

		{&hf_radiotap_channel_flags_half,
		 {"Half Rate Channel (10MHz Channel Width)", "radiotap.channel.flags.half",
		  FT_BOOLEAN, 16, NULL, 0x4000,
		  "Channel Flags Half Rate", HFILL}},

		{&hf_radiotap_channel_flags_quarter,
		 {"Quarter Rate Channel (5MHz Channel Width)", "radiotap.channel.flags.quarter",
		  FT_BOOLEAN, 16, NULL, 0x8000,
		  "Channel Flags Quarter Rate", HFILL}},

		{&hf_radiotap_rxflags,
		 {"RX flags", "radiotap.rxflags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_rxflags_badplcp,
		 {"Bad PLCP", "radiotap.rxflags.badplcp",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_RX_BADPLCP,
		  "Frame with bad PLCP", HFILL}},

		{&hf_radiotap_xchannel_channel,
		 {"Channel number", "radiotap.xchannel.channel",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_xchannel_frequency,
		 {"Channel frequency", "radiotap.xchannel.freq",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_xchannel_flags,
		 {"Channel flags", "radiotap.xchannel.flags",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_xchannel_flags_turbo,
		 {"Turbo", "radiotap.xchannel.flags.turbo",
		  FT_BOOLEAN, 24, NULL, 0x0010,
		  "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_xchannel_flags_cck,
		 {"Complementary Code Keying (CCK)", "radiotap.xchannel.flags.cck",
		  FT_BOOLEAN, 24, NULL, 0x0020,
		  "Channel Flags Complementary Code Keying (CCK) Modulation", HFILL}},

		{&hf_radiotap_xchannel_flags_ofdm,
		 {"Orthogonal Frequency-Division Multiplexing (OFDM)", "radiotap.xchannel.flags.ofdm",
		  FT_BOOLEAN, 24, NULL, 0x0040,
		  "Channel Flags Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL}},

		{&hf_radiotap_xchannel_flags_2ghz,
		 {"2 GHz spectrum", "radiotap.xchannel.flags.2ghz",
		  FT_BOOLEAN, 24, NULL, 0x0080,
		  "Channel Flags 2 GHz spectrum", HFILL}},

		{&hf_radiotap_xchannel_flags_5ghz,
		 {"5 GHz spectrum", "radiotap.xchannel.flags.5ghz",
		  FT_BOOLEAN, 24, NULL, 0x0100,
		  "Channel Flags 5 GHz spectrum", HFILL}},

		{&hf_radiotap_xchannel_flags_passive,
		 {"Passive", "radiotap.channel.xtype.passive",
		  FT_BOOLEAN, 24, NULL, 0x0200,
		  "Channel Flags Passive", HFILL}},

		{&hf_radiotap_xchannel_flags_dynamic,
		 {"Dynamic CCK-OFDM", "radiotap.xchannel.flags.dynamic",
		  FT_BOOLEAN, 24, NULL, 0x0400,
		  "Channel Flags Dynamic CCK-OFDM Channel", HFILL}},

		{&hf_radiotap_xchannel_flags_gfsk,
		 {"Gaussian Frequency Shift Keying (GFSK)",
		  "radiotap.xchannel.flags.gfsk",
		  FT_BOOLEAN, 24, NULL, 0x0800,
		  "Channel Flags Gaussian Frequency Shift Keying (GFSK) Modulation",
		  HFILL}},

		{&hf_radiotap_xchannel_flags_gsm,
		 {"GSM (900MHz)", "radiotap.xchannel.flags.gsm",
		  FT_BOOLEAN, 24, NULL, 0x1000,
		  "Channel Flags GSM", HFILL}},

		{&hf_radiotap_xchannel_flags_sturbo,
		 {"Static Turbo", "radiotap.xchannel.flags.sturbo",
		  FT_BOOLEAN, 24, NULL, 0x2000,
		  "Channel Flags Status Turbo", HFILL}},

		{&hf_radiotap_xchannel_flags_half,
		 {"Half Rate Channel (10MHz Channel Width)", "radiotap.xchannel.flags.half",
		  FT_BOOLEAN, 24, NULL, 0x4000,
		  "Channel Flags Half Rate", HFILL}},

		{&hf_radiotap_xchannel_flags_quarter,
		 {"Quarter Rate Channel (5MHz Channel Width)", "radiotap.xchannel.flags.quarter",
		  FT_BOOLEAN, 24, NULL, 0x8000,
		  "Channel Flags Quarter Rate", HFILL}},

		{&hf_radiotap_xchannel_flags_ht20,
		 {"HT Channel (20MHz Channel Width)", "radiotap.xchannel.flags.ht20",
		  FT_BOOLEAN, 24, NULL, 0x10000,
		  "Channel Flags HT/20", HFILL}},

		{&hf_radiotap_xchannel_flags_ht40u,
		 {"HT Channel (40MHz Channel Width with Extension channel above)", "radiotap.xchannel.flags.ht40u",
		  FT_BOOLEAN, 24, NULL, 0x20000,
		  "Channel Flags HT/40+", HFILL}},

		{&hf_radiotap_xchannel_flags_ht40d,
		 {"HT Channel (40MHz Channel Width with Extension channel below)", "radiotap.xchannel.flags.ht40d",
		  FT_BOOLEAN, 24, NULL, 0x40000,
		  "Channel Flags HT/40-", HFILL}},
#if 0
		{&hf_radiotap_xchannel_maxpower,
		 {"Max transmit power", "radiotap.xchannel.maxpower",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
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
		  "Antenna number this frame was sent/received over (starting at 0)", HFILL}},

		{&hf_radiotap_dbm_antsignal,
		 {"SSI Signal", "radiotap.dbm_antsignal",
		  FT_INT32, BASE_DEC, NULL, 0x0,
		  "RF signal power at the antenna from a fixed,"
		  " arbitrary value in decibels from one milliwatt", HFILL}},

		{&hf_radiotap_db_antsignal,
		 {"SSI Signal", "radiotap.db_antsignal",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "RF signal power at the antenna from a fixed, arbitrary value in decibels", HFILL}},

		{&hf_radiotap_dbm_antnoise,
		 {"SSI Noise", "radiotap.dbm_antnoise",
		  FT_INT32, BASE_DEC, NULL, 0x0,
		  "RF noise power at the antenna from a fixed, arbitrary value"
		  " in decibels per one milliwatt", HFILL}},

		{&hf_radiotap_db_antnoise,
		 {"SSI Noise", "radiotap.db_antnoise",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "RF noise power at the antenna from a fixed, arbitrary value"
		  " in decibels", HFILL}},

		{&hf_radiotap_tx_attenuation,
		 {"Transmit attenuation", "radiotap.txattenuation",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Transmit power expressed as unitless distance from max power"
		  " set at factory (0 is max power)", HFILL}},

		{&hf_radiotap_db_tx_attenuation,
		 {"Transmit attenuation (dB)", "radiotap.db_txattenuation",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Transmit power expressed as decibels from max power"
		  " set at factory (0 is max power)", HFILL}},

		{&hf_radiotap_txpower,
		 {"Transmit power", "radiotap.txpower",
		  FT_INT32, BASE_DEC, NULL, 0x0,
		  "Transmit power in decibels per one milliwatt (dBm)", HFILL}},

		{&hf_radiotap_mcs,
		 {"MCS information", "radiotap.mcs",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_mcs_known,
		 {"Known MCS information", "radiotap.mcs.known",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bit mask indicating what MCS information is present", HFILL}},

		{&hf_radiotap_mcs_have_bw,
		 {"Bandwidth", "radiotap.mcs.have_bw",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_BW,
		  "Bandwidth information present", HFILL}},

		{&hf_radiotap_mcs_have_index,
		 {"MCS index", "radiotap.mcs.have_index",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_MCS,
		  "MCS index information present", HFILL}},

		{&hf_radiotap_mcs_have_gi,
		 {"Guard interval", "radiotap.mcs.have_gi",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_GI,
		  "Sent/Received guard interval information present", HFILL}},

		{&hf_radiotap_mcs_have_format,
		 {"Format", "radiotap.mcs.have_format",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_FMT,
		  "Format information present", HFILL}},

		{&hf_radiotap_mcs_have_fec,
		 {"FEC type", "radiotap.mcs.have_fec",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_FEC,
		  "Forward error correction type information present", HFILL}},

		{&hf_radiotap_mcs_have_stbc,
		 {"STBC streams", "radiotap.mcs.have_stbc",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_STBC,
		  "Space Time Block Coding streams information present", HFILL}},

		{&hf_radiotap_mcs_have_ness,
		 {"Number of extension spatial streams", "radiotap.mcs.have_ness",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_NESS,
		  "Number of extension spatial streams information present", HFILL}},

		{&hf_radiotap_mcs_ness_bit1,
		 {"Number of extension spatial streams bit 1", "radiotap.mcs.ness_bit1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_MCS_NESS_BIT1,
		  "Bit 1 of number of extension spatial streams information", HFILL}},

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
		 {"FEC type", "radiotap.mcs.fec",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), IEEE80211_RADIOTAP_MCS_FEC_LDPC,
		  "Forward error correction type", HFILL}},

		{&hf_radiotap_mcs_stbc,
		 {"STBC streams", "radiotap.mcs.stbc",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_MCS_STBC_MASK,
		  "Number of Space Time Block Code streams", HFILL}},

		{&hf_radiotap_mcs_ness_bit0,
		 {"Number of extension spatial streams bit 0", "radiotap.mcs.ness_bit1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_MCS_NESS_BIT1,
		  "Bit 0 of number of extension spatial streams information", HFILL}},

		{&hf_radiotap_mcs_index,
		 {"MCS index", "radiotap.mcs.index",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu,
		 {"A-MPDU status", "radiotap.ampdu",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_ref,
		 {"A-MPDU reference number", "radiotap.ampdu.reference",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags,
		 {"A-MPDU flags", "radiotap.ampdu.flags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "A-MPDU status flags", HFILL}},

		{&hf_radiotap_ampdu_flags_report_zerolen,
		 {"Driver reports 0-length subframes in this A-MPDU", "radiotap.ampdu.flags.report_zerolen",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_is_zerolen,
		 {"This is a 0-length subframe", "radiotap.ampdu.flags.is_zerolen",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_last_known,
		 {"Last subframe of this A-MPDU is known", "radiotap.ampdu.flags.lastknown",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_is_last,
		 {"This is the last subframe of this A-MPDU", "radiotap.ampdu.flags.last",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_IS_LAST,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_delim_crc_error,
		 {"Delimiter CRC error on this subframe", "radiotap.ampdu.flags.delim_crc_error",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_delim_crc,
		 {"A-MPDU subframe delimiter CRC", "radiotap.ampdu.delim_crc",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht,
		 {"VHT information", "radiotap.vht",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_known,
		 {"Known VHT information", "radiotap.vht.known",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bit mask indicating what VHT information is present", HFILL}},

		{&hf_radiotap_vht_user,
		 {"User", "radiotap.vht.user",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_stbc,
		 {"STBC", "radiotap.vht.have_stbc",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_STBC,
		  "Space Time Block Coding information present", HFILL}},

		{&hf_radiotap_vht_have_txop_ps,
		 {"TXOP_PS_NOT_ALLOWED", "radiotap.vht.have_txop_ps",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_TXOP_PS,
		  "TXOP_PS_NOT_ALLOWED information present", HFILL}},

		{&hf_radiotap_vht_have_gi,
		 {"Guard interval", "radiotap.vht.have_gi",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_GI,
		  "Short/Long guard interval information present", HFILL}},

		{&hf_radiotap_vht_have_sgi_nsym_da,
		 {"SGI Nsym disambiguation", "radiotap.vht.have_sgi_nsym_da",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_SGI_NSYM_DA,
		  "Short guard interval Nsym disambiguation information present", HFILL}},

		{&hf_radiotap_vht_have_ldpc_extra,
		 {"LDPC extra OFDM symbol", "radiotap.vht.ldpc_extra",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_LDPC_EXTRA,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_bf,
		 {"Beamformed", "radiotap.vht.have_beamformed",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_BF,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_bw,
		 {"Bandwidth", "radiotap.mcs.have_bw",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_BW,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_gid,
		 {"Group ID", "radiotap.mcs.have_gid",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_GID,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_p_aid,
		 {"Partial AID", "radiotap.mcs.have_paid",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_PAID,
		  NULL, HFILL}},

		{&hf_radiotap_vht_stbc,
		 {"STBC", "radiotap.vht.stbc",
		  FT_BOOLEAN, 8, TFS(&tfs_on_off), IEEE80211_RADIOTAP_VHT_STBC,
		  "Space Time Block Coding flag", HFILL}},

		{&hf_radiotap_vht_txop_ps,
		 {"TXOP_PS_NOT_ALLOWED", "radiotap.vht.txop_ps",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_TXOP_PS,
		  "Flag indicating whether STAs may doze during TXOP", HFILL}},

		{&hf_radiotap_vht_gi,
		 {"Guard interval", "radiotap.vht.gi",
		  FT_UINT8, BASE_DEC, VALS(mcs_gi), IEEE80211_RADIOTAP_VHT_SGI,
		  "Short/Long guard interval", HFILL}},

		{&hf_radiotap_vht_sgi_nsym_da,
		 {"SGI Nsym disambiguation", "radiotap.vht.sgi_nsym_da",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA,
		  "Short Guard Interval Nsym disambiguation", HFILL}},

		{&hf_radiotap_vht_ldpc_extra,
		 {"LDPC extra OFDM symbol", "radiotap.vht.ldpc_extra",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_LDPC_EXTRA,
		  NULL, HFILL}},

		{&hf_radiotap_vht_bf,
		 {"Beamformed", "radiotap.vht.beamformed",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_BF,
		  NULL, HFILL}},

		{&hf_radiotap_vht_bw,
		 {"Bandwidth", "radiotap.vht.bw",
		  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vht_bandwidth_ext, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_nsts[0],
		 {"Space-time streams 0", "radiotap.vht.nsts.0",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_nsts[1],
		 {"Space-time streams 1", "radiotap.vht.nsts.1",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_nsts[2],
		 {"Space-time streams 2", "radiotap.vht.nsts.2",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_nsts[3],
		 {"Space-time streams 3", "radiotap.vht.nsts.3",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_mcs[0],
		 {"MCS index 0", "radiotap.vht.mcs.0",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_mcs[1],
		 {"MCS index 1", "radiotap.vht.mcs.1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_mcs[2],
		 {"MCS index 2", "radiotap.vht.mcs.2",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_mcs[3],
		 {"MCS index 3", "radiotap.vht.mcs.3",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_nss[0],
		 {"Spatial streams 0", "radiotap.vht.nss.0",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_nss[1],
		 {"Spatial streams 1", "radiotap.vht.nss.1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_nss[2],
		 {"Spatial streams 2", "radiotap.vht.nss.2",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_nss[3],
		 {"Spatial streams 3", "radiotap.vht.nss.3",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_coding[0],
		 {"Coding 0", "radiotap.vht.coding.0",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x01,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_coding[1],
		 {"Coding 1", "radiotap.vht.coding.1",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x02,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_coding[2],
		 {"Coding 2", "radiotap.vht.coding.2",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x04,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_coding[3],
		 {"Coding 3", "radiotap.vht.coding.3",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x08,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_datarate[0],
		 {"Data rate (Mb/s) 0", "radiotap.vht.datarate.0",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_datarate[1],
		 {"Data rate (Mb/s) 1", "radiotap.vht.datarate.1",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_datarate[2],
		 {"Data rate (Mb/s) 2", "radiotap.vht.datarate.2",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_datarate[3],
		 {"Data rate (Mb/s) 3", "radiotap.vht.datarate.3",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_gid,
		 {"Group Id", "radiotap.vht.gid",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_p_aid,
		 {"Partial AID", "radiotap.vht.paid",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

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
		  "Specifies if this frame has a bad frame check sequence", HFILL}},

	};
	static gint *ett[] = {
		&ett_radiotap,
		&ett_radiotap_present,
		&ett_radiotap_present_word,
		&ett_radiotap_flags,
		&ett_radiotap_rxflags,
		&ett_radiotap_channel_flags,
		&ett_radiotap_xchannel_flags,
		&ett_radiotap_vendor,
		&ett_radiotap_mcs,
		&ett_radiotap_mcs_known,
		&ett_radiotap_ampdu,
		&ett_radiotap_ampdu_flags,
		&ett_radiotap_vht,
		&ett_radiotap_vht_known,
		&ett_radiotap_vht_user
	};
	static ei_register_info ei[] = {
		{ &ei_radiotap_present, { "radiotap.present.radiotap_and_vendor", PI_MALFORMED, PI_ERROR, "Both radiotap and vendor namespace specified in bitmask word", EXPFILL }},
		{ &ei_radiotap_present_reserved, { "radiotap.present.reserved.unknown", PI_UNDECODED, PI_NOTE, "Unknown Radiotap fields, code not implemented, Please check radiotap documentation, Contact Wireshark developers if you want this supported", EXPFILL }},
		{ &ei_radiotap_data_past_header, { "radiotap.data_past_header", PI_MALFORMED, PI_ERROR, "Radiotap data goes past the end of the radiotap header", EXPFILL }},
		{ &ei_radiotap_invalid_data_rate, { "radiotap.vht.datarate.invalid", PI_PROTOCOL, PI_WARN, "Data rate invalid", EXPFILL }},
	};

	module_t *radiotap_module;
	expert_module_t* expert_radiotap;

	proto_radiotap =
	    proto_register_protocol("IEEE 802.11 Radiotap Capture header", "802.11 Radiotap", "radiotap");
	proto_register_field_array(proto_radiotap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_radiotap = expert_register_protocol(proto_radiotap);
	expert_register_field_array(expert_radiotap, ei, array_length(ei));
	register_dissector("radiotap", dissect_radiotap, proto_radiotap);

	radiotap_tap = register_tap("radiotap");

	radiotap_module = prefs_register_protocol(proto_radiotap, NULL);
	prefs_register_bool_preference(radiotap_module, "bit14_fcs_in_header",
				       "Assume bit 14 means FCS in header",
				       "Radiotap has a bit to indicate whether the FCS is still on the frame or not. "
				       "Some generators (e.g. AirPcap) use a non-standard radiotap flag 14 to put "
				       "the FCS into the header.",
				       &radiotap_bit14_fcs);

	prefs_register_bool_preference(radiotap_module, "interpret_high_rates_as_mcs",
				       "Interpret high rates as MCS",
				       "Some generators use rates with bit 7 set to indicate an MCS, e.g. BSD. "
					   "others (Linux, AirPcap) do not.",
				       &radiotap_interpret_high_rates_as_mcs);
}

void proto_reg_handoff_radiotap(void)
{
	dissector_handle_t radiotap_handle;

	/* handle for 802.11+radio information dissector */
	ieee80211_radio_handle = find_dissector_add_dependency("wlan_radio", proto_radiotap);

	radiotap_handle = find_dissector_add_dependency("radiotap", proto_radiotap);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_RADIOTAP,
			   radiotap_handle);

	register_capture_dissector("wtap_encap", WTAP_ENCAP_IEEE_802_11_RADIOTAP, capture_radiotap, proto_radiotap);
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
