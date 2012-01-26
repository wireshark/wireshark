/* packet-gsmtap.c
 * Routines for GSMTAP captures
 *
 * (C) 2008-2011 by Harald Welte <laforge@gnumonks.org>
 * (C) 2011 by Holger Hans Peter Freyther
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 */

/* GSMTAP is a generic header format for GSM protocol captures,
 * it uses the IANA-assigned UDP port number 4729 and carries
 * payload in various formats of GSM interfaces such as Um MAC
 * blocks or Um bursts.
 *
 * Example programs generating GSMTAP data are airprobe
 * (http://airprobe.org/) or OsmocomBB (http://bb.osmocom.org/)
 *
 * It has also been used for Tetra by the OsmocomTETRA project.
 * (http://tetra.osmocom.org/)
 *
 * GSMTAP also carries payload in various formats of WiMAX interfaces.
 * It uses the wimax plugin to decode the WiMAX bursts.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-tetra.h"

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* The following types and definitions are imported from libosmocore,
 * the original source of the GSMTAP format.
 *
 * prior to getting them accepted/included into the official Osmocom
 * GSMTAP definition, available from
 * http://cgit.osmocom.org/cgit/libosmocore/tree/include/osmocom/core/gsmtap.h
 *
 * The GSMTAP maintainer can be contacted via the
 * openbsc@lists.osmocom.org mailing list, or by private e-mail
 * to laforge@gnumonks.org
 */
/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
#define GSMTAP_TYPE_UM				0x01
#define GSMTAP_TYPE_ABIS			0x02
#define GSMTAP_TYPE_UM_BURST		0x03	/* raw burst bits */
#define GSMTAP_TYPE_SIM				0x04
#define GSMTAP_TYPE_TETRA_I1		0x05	/* tetra air interface */
#define GSMTAP_TTPE_TETRA_I1_BURST	0x06	/* tetra air interface */
#define GSMTAP_TYPE_WMX_BURST		0x07	/* WiMAX burst */
#define GSMTAP_TYPE_GB_LLC			0x08 /* GPRS Gb interface: LLC */
#define GSMTAP_TYPE_GB_SNDCP		0x09 /* GPRS Gb interface: SNDCP */

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
#define GSMTAP_BURST_UNKNOWN		0x00
#define GSMTAP_BURST_FCCH			0x01
#define GSMTAP_BURST_PARTIAL_SCH	0x02
#define GSMTAP_BURST_SCH			0x03
#define GSMTAP_BURST_CTS_SCH		0x04
#define GSMTAP_BURST_COMPACT_SCH	0x05
#define GSMTAP_BURST_NORMAL			0x06
#define GSMTAP_BURST_DUMMY			0x07
#define GSMTAP_BURST_ACCESS			0x08
#define GSMTAP_BURST_NONE			0x09
/* WiMAX bursts */
#define GSMTAP_BURST_CDMA_CODE          0x10	/* WiMAX CDMA Code Attribute burst */
#define GSMTAP_BURST_FCH                0x11	/* WiMAX FCH burst */
#define GSMTAP_BURST_FFB                0x12	/* WiMAX Fast Feedback burst */
#define GSMTAP_BURST_PDU                0x13	/* WiMAX PDU burst */
#define GSMTAP_BURST_HACK               0x14	/* WiMAX HARQ ACK burst */
#define GSMTAP_BURST_PHY_ATTRIBUTES     0x15	/* WiMAX PHY Attributes burst */

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* sub-types for TYPE_UM */
#define GSMTAP_CHANNEL_UNKNOWN    0x00
#define GSMTAP_CHANNEL_BCCH       0x01
#define GSMTAP_CHANNEL_CCCH       0x02
#define GSMTAP_CHANNEL_RACH       0x03
#define GSMTAP_CHANNEL_AGCH       0x04
#define GSMTAP_CHANNEL_PCH        0x05
#define GSMTAP_CHANNEL_SDCCH      0x06
#define GSMTAP_CHANNEL_SDCCH4     0x07
#define GSMTAP_CHANNEL_SDCCH8     0x08
#define GSMTAP_CHANNEL_TCH_F      0x09
#define GSMTAP_CHANNEL_TCH_H      0x0a
#define GSMTAP_CHANNEL_PACCH      0x0b
#define GSMTAP_CHANNEL_CBCH52     0x0c
#define GSMTAP_CHANNEL_PDCH       0x0d
#define GSMTAP_CHANNEL_PTCCH      0x0e
#define GSMTAP_CHANNEL_CBCH51     0x0f
#define GSMTAP_CHANNEL_ACCH       0x80

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* sub-types for TYPE_TETRA_AIR */
#define GSMTAP_TETRA_BSCH			0x01
#define GSMTAP_TETRA_AACH			0x02
#define GSMTAP_TETRA_SCH_HU			0x03
#define GSMTAP_TETRA_SCH_HD			0x04
#define GSMTAP_TETRA_SCH_F			0x05
#define GSMTAP_TETRA_BNCH			0x06
#define GSMTAP_TETRA_STCH			0x07
#define GSMTAP_TETRA_TCH_F			0x08

#define GSMTAP_ARFCN_F_PCS			0x8000
#define GSMTAP_ARFCN_F_UPLINK		0x4000
#define GSMTAP_ARFCN_MASK			0x3fff

#define GSMTAP_UDP_PORT				4729

/* This is the header as it is used by gsmtap-generating software.
 * It is not used by the wireshark dissector and provided for reference only.
struct gsmtap_hdr {
	guint8 version;		// version, set to 0x01 currently
	guint8 hdr_len;		// length in number of 32bit words
	guint8 type;		// see GSMTAP_TYPE_*
	guint8 timeslot;	// timeslot (0..7 on Um)

	guint16 arfcn;		// ARFCN (frequency)
	gint8 signal_dbm;	// signal level in dBm
	gint8 snr_db;		// signal/noise ratio in dB

	guint32 frame_number;	// GSM Frame Number (FN)

	guint8 sub_type;	// Type of burst/channel, see above
	guint8 antenna_nr;	// Antenna Number
	guint8 sub_slot;	// sub-slot within timeslot
	guint8 res;		// reserved for future use (RFU)
}
 */

static int proto_gsmtap = -1;

static int hf_gsmtap_version = -1;
static int hf_gsmtap_hdrlen = -1;
static int hf_gsmtap_type = -1;
static int hf_gsmtap_timeslot = -1;
static int hf_gsmtap_subslot = -1;
static int hf_gsmtap_arfcn = -1;
static int hf_gsmtap_uplink = -1;
static int hf_gsmtap_noise_dbm = -1;
static int hf_gsmtap_signal_dbm = -1;
static int hf_gsmtap_frame_nr = -1;
static int hf_gsmtap_burst_type = -1;
static int hf_gsmtap_channel_type = -1;
static int hf_gsmtap_tetra_channel_type = -1;
static int hf_gsmtap_antenna = -1;

static int hf_sacch_l1h_power_lev = -1;
static int hf_sacch_l1h_fpc = -1;
static int hf_sacch_l1h_ta = -1;

static gint ett_gsmtap = -1;

enum {
	GSMTAP_SUB_DATA = 0,
	GSMTAP_SUB_UM,
	GSMTAP_SUB_UM_LAPDM,
	GSMTAP_SUB_UM_RLC_MAC_UL,
	GSMTAP_SUB_UM_RLC_MAC_DL,
	GSMTAP_SUB_LLC,
	GSMTAP_SUB_SNDCP,
	GSMTAP_SUB_ABIS,
	/* WiMAX sub handles */
	GSMTAP_SUB_CDMA_CODE, 
	GSMTAP_SUB_FCH,
	GSMTAP_SUB_FFB,
	GSMTAP_SUB_PDU,
	GSMTAP_SUB_HACK,
	GSMTAP_SUB_PHY_ATTRIBUTES,
	GSMTAP_SUB_CBCH,

	GSMTAP_SUB_MAX
};

static dissector_handle_t sub_handles[GSMTAP_SUB_MAX];

static const value_string gsmtap_bursts[] = {
	{ GSMTAP_BURST_UNKNOWN,		"UNKNOWN" },
	{ GSMTAP_BURST_FCCH,		"FCCH" },
	{ GSMTAP_BURST_PARTIAL_SCH,	"PARTIAL SCH" },
	{ GSMTAP_BURST_SCH,			"SCH" },
	{ GSMTAP_BURST_CTS_SCH,		"CTS SCH" },
	{ GSMTAP_BURST_COMPACT_SCH,	"COMPACT SCH" },
	{ GSMTAP_BURST_NORMAL,		"NORMAL" },
	{ GSMTAP_BURST_DUMMY,		"DUMMY" },
	{ GSMTAP_BURST_ACCESS,		"RACH" },
	/* WiMAX bursts */
 	{ GSMTAP_BURST_CDMA_CODE,       "CDMA Code"  },
	{ GSMTAP_BURST_FCH,             "FCH"  },
	{ GSMTAP_BURST_FFB,             "Fast Feedback" },
	{ GSMTAP_BURST_PDU,             "PDU" },
	{ GSMTAP_BURST_HACK,            "HACK" },
	{ GSMTAP_BURST_PHY_ATTRIBUTES,  "PHY Attributes" },
	{ 0,				NULL },
};

static const value_string gsmtap_channels[] = {
	{ GSMTAP_CHANNEL_UNKNOWN,	"UNKNOWN" },
	{ GSMTAP_CHANNEL_BCCH,		"BCCH" },
	{ GSMTAP_CHANNEL_CCCH,		"CCCH" },
	{ GSMTAP_CHANNEL_RACH,		"RACH" },
	{ GSMTAP_CHANNEL_AGCH,		"AGCH" },
	{ GSMTAP_CHANNEL_PCH,		"PCH" },
	{ GSMTAP_CHANNEL_SDCCH,		"SDCCH" },
	{ GSMTAP_CHANNEL_SDCCH4,	"SDCCH/4" },
	{ GSMTAP_CHANNEL_SDCCH8,	"SDCCH/8" },
	{ GSMTAP_CHANNEL_TCH_F,		"FACCH/F" },
	{ GSMTAP_CHANNEL_TCH_H,		"FACCH/H" },
	{ GSMTAP_CHANNEL_PACCH,		"PACCH" },
	{ GSMTAP_CHANNEL_CBCH52,    "CBCH" },
	{ GSMTAP_CHANNEL_PDCH,      "PDCH" },
	{ GSMTAP_CHANNEL_PTCCH,     "PTTCH" },
	{ GSMTAP_CHANNEL_CBCH51,    "CBCH" },

    { GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_SDCCH,		"LSACCH" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_SDCCH4,	"SACCH/4" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_SDCCH8,	"SACCH/8" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_TCH_F,		"SACCH/F" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_TCH_H,		"SACCH/H" },
	{ 0,				NULL },
};

static const value_string gsmtap_tetra_channels[] = {
	{ GSMTAP_TETRA_BSCH,		"BSCH"   },
	{ GSMTAP_TETRA_AACH,		"AACH"   },
	{ GSMTAP_TETRA_SCH_HU,		"SCH/HU" },
	{ GSMTAP_TETRA_SCH_HD,		"SCH/HD" },
	{ GSMTAP_TETRA_SCH_F,		"SCH/F"	 },
	{ GSMTAP_TETRA_BNCH,		"BNCH"   },
	{ GSMTAP_TETRA_STCH,		"STCH"   },
	{ GSMTAP_TETRA_TCH_F,		"AACH"   },
	{ 0,				NULL     },
};

/* the mapping is not complete */
static const int gsmtap_to_tetra[9] = {
	0,
	TETRA_CHAN_BSCH,
	TETRA_CHAN_AACH,
	TETRA_CHAN_SCH_HU,
	0,
	TETRA_CHAN_SCH_F,
	TETRA_CHAN_BNCH,
	TETRA_CHAN_STCH,
	0
};

static const value_string gsmtap_types[] = {
	{ GSMTAP_TYPE_UM,	"GSM Um (MS<->BTS)" },
	{ GSMTAP_TYPE_ABIS,	"GSM Abis (BTS<->BSC)" },
	{ GSMTAP_TYPE_UM_BURST,	"GSM Um burst (MS<->BTS)" },
	{ GSMTAP_TYPE_SIM,	"SIM" },
	{ GSMTAP_TYPE_TETRA_I1, "TETRA V+D"},
	{ GSMTAP_TTPE_TETRA_I1_BURST, "TETRA V+D burst"},
	{ GSMTAP_TYPE_WMX_BURST,"WiMAX burst" },
	{ 0,			NULL },
};

/* dissect a SACCH L1 header which is included in the first 2 bytes
 * of every SACCH frame (according to TS 04.04) */
static void
dissect_sacch_l1h(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *l1h_tree = NULL;

	if (!tree)
		return;

	ti = proto_tree_add_protocol_format(tree, proto_gsmtap, tvb, 0, 2,
			"SACCH L1 Header, Power Level: %u, Timing Advance: %u",
			tvb_get_guint8(tvb, 0) & 0x1f,
			tvb_get_guint8(tvb, 1));
	l1h_tree = proto_item_add_subtree(ti, ett_gsmtap);
	/* Power Level */
	proto_tree_add_item(l1h_tree, hf_sacch_l1h_power_lev, tvb, 0, 1, ENC_BIG_ENDIAN);
	/* Fast Power Control */
	proto_tree_add_item(l1h_tree, hf_sacch_l1h_fpc, tvb, 0, 1, ENC_BIG_ENDIAN);
	/* Acutal Timing Advance */
	proto_tree_add_item(l1h_tree, hf_sacch_l1h_ta, tvb, 1, 1, ENC_BIG_ENDIAN);
}


static void
handle_tetra(int channel _U_, tvbuff_t *payload_tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	int tetra_chan;
	if (channel < 0 || channel > GSMTAP_TETRA_TCH_F)
		return;

	tetra_chan = gsmtap_to_tetra[channel];
	if (tetra_chan <= 0)
		return;

	tetra_dissect_pdu(tetra_chan, TETRA_DOWNLINK, payload_tvb, tree, pinfo);
}

/* dissect a GSMTAP header and hand payload off to respective dissector */
static void
dissect_gsmtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int sub_handle, len, offset = 0;
	proto_item *ti;
	proto_tree *gsmtap_tree = NULL;
	tvbuff_t *payload_tvb, *l1h_tvb = NULL;
	guint8 hdr_len, type, sub_type;
	guint16 arfcn;

	len = tvb_length(tvb);

	hdr_len = tvb_get_guint8(tvb, offset + 1) <<2;
	type = tvb_get_guint8(tvb, offset + 2);
	sub_type = tvb_get_guint8(tvb, offset + 12);
	arfcn = tvb_get_ntohs(tvb, offset + 4);

	/* In case of a SACCH, there is a two-byte L1 header in front
	 * of the packet (see TS 04.04) */
	if (type == GSMTAP_TYPE_UM &&
	    sub_type & GSMTAP_CHANNEL_ACCH) {
		l1h_tvb = tvb_new_subset(tvb, hdr_len, 2, 2);
		payload_tvb = tvb_new_subset(tvb, hdr_len+2, len-(hdr_len+2),
					     len-(hdr_len+2));
	} else {
		payload_tvb = tvb_new_subset(tvb, hdr_len, len-hdr_len,
					     len-hdr_len);
	}

	/* We don't want any UDP related info left in the INFO field, as the
	 * gsm_a_dtap dissector will not clear but only append */
	col_clear(pinfo->cinfo, COL_INFO);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSMTAP");

	if (arfcn & GSMTAP_ARFCN_F_UPLINK) {
		col_append_str(pinfo->cinfo, COL_RES_NET_SRC, "MS");
		col_append_str(pinfo->cinfo, COL_RES_NET_DST, "BTS");
		/* p2p_dir is used by the LAPDm dissector */
		pinfo->p2p_dir = P2P_DIR_SENT;
	} else {
		col_set_str(pinfo->cinfo, COL_RES_NET_SRC, "BTS");
		switch (sub_type & ~GSMTAP_CHANNEL_ACCH) {
		case GSMTAP_CHANNEL_BCCH:
		case GSMTAP_CHANNEL_CCCH:
		case GSMTAP_CHANNEL_PCH:
		case GSMTAP_CHANNEL_AGCH:
		case GSMTAP_CHANNEL_CBCH51:
        case GSMTAP_CHANNEL_CBCH52:
			col_set_str(pinfo->cinfo, COL_RES_NET_DST, "Broadcast");
			break;
		default:
			col_set_str(pinfo->cinfo, COL_RES_NET_DST, "MS");
			break;
		}
		/* p2p_dir is used by the LAPDm dissector */
		pinfo->p2p_dir = P2P_DIR_RECV;
	}

	if (tree) {
		guint8 channel;
		const char *channel_str;
		channel = tvb_get_guint8(tvb, offset+12);
		if (type == GSMTAP_TYPE_TETRA_I1)
			channel_str = val_to_str(channel, gsmtap_tetra_channels, "Unknown: %d");
		else
			channel_str = val_to_str(channel, gsmtap_channels, "Unknown: %d");

		ti = proto_tree_add_protocol_format(tree, proto_gsmtap, tvb, 0, hdr_len,
			"GSM TAP Header, ARFCN: %u (%s), TS: %u, Channel: %s (%u)",
			arfcn & GSMTAP_ARFCN_MASK,
			arfcn & GSMTAP_ARFCN_F_UPLINK ? "Uplink" : "Downlink",
			tvb_get_guint8(tvb, offset+3),
			channel_str,
			tvb_get_guint8(tvb, offset+14));
		gsmtap_tree = proto_item_add_subtree(ti, ett_gsmtap);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_version,
				    tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint_format(gsmtap_tree, hf_gsmtap_hdrlen,
				    tvb, offset+1, 1, hdr_len,
				    "Header length: %u bytes", hdr_len);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_type,
				    tvb, offset+2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_timeslot,
				    tvb, offset+3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_arfcn,
				    tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_uplink,
				    tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_noise_dbm,
				    tvb, offset+6, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_signal_dbm,
				    tvb, offset+7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_frame_nr,
				    tvb, offset+8, 4, ENC_BIG_ENDIAN);
		if (type == GSMTAP_TYPE_UM_BURST)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_burst_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_UM)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_channel_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_TETRA_I1)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_tetra_channel_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_WMX_BURST)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_burst_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_antenna,
				    tvb, offset+13, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_subslot,
				    tvb, offset+14, 1, ENC_BIG_ENDIAN);
	}

	switch (type) {
	case GSMTAP_TYPE_UM:
		if (l1h_tvb)
			dissect_sacch_l1h(l1h_tvb, tree);
		switch (sub_type & ~GSMTAP_CHANNEL_ACCH) {
		case GSMTAP_CHANNEL_BCCH:
		case GSMTAP_CHANNEL_CCCH:
		case GSMTAP_CHANNEL_PCH:
		case GSMTAP_CHANNEL_AGCH:
			/* FIXME: we might want to skip idle frames */
			sub_handle = GSMTAP_SUB_UM;
			break;
		case GSMTAP_CHANNEL_SDCCH:
		case GSMTAP_CHANNEL_SDCCH4:
		case GSMTAP_CHANNEL_SDCCH8:
		case GSMTAP_CHANNEL_TCH_F:
		case GSMTAP_CHANNEL_TCH_H:
			sub_handle = GSMTAP_SUB_UM_LAPDM;
			break;
		case GSMTAP_CHANNEL_PACCH:
			if (pinfo->p2p_dir == P2P_DIR_SENT) {
				sub_handle = GSMTAP_SUB_UM_RLC_MAC_UL;
			}
			else
			{
				sub_handle = GSMTAP_SUB_UM_RLC_MAC_DL;
			}
			break;

        case GSMTAP_CHANNEL_CBCH51:
        case GSMTAP_CHANNEL_CBCH52:
           sub_handle = GSMTAP_SUB_CBCH;
			break;

		case GSMTAP_CHANNEL_RACH:
		default:
			sub_handle = GSMTAP_SUB_DATA;
			break;
		}
		break;
	case GSMTAP_TYPE_ABIS:
		sub_handle = GSMTAP_SUB_ABIS;
		break;
	case GSMTAP_TYPE_GB_LLC:
		sub_handle = GSMTAP_SUB_LLC;
		break;
	case GSMTAP_TYPE_GB_SNDCP:
		sub_handle = GSMTAP_SUB_SNDCP;
		break;
	case GSMTAP_TYPE_TETRA_I1:
		handle_tetra(tvb_get_guint8(tvb, offset+12), payload_tvb, pinfo, tree);
		return;
	case GSMTAP_TYPE_WMX_BURST:
		switch (sub_type) { 
	        case GSMTAP_BURST_CDMA_CODE: 
			sub_handle = GSMTAP_SUB_CDMA_CODE;
			break;
	        case GSMTAP_BURST_FCH: 
			sub_handle = GSMTAP_SUB_FCH;
			break;
	        case GSMTAP_BURST_FFB: 
			sub_handle = GSMTAP_SUB_FFB;
			break;
	        case GSMTAP_BURST_PDU: 
			sub_handle = GSMTAP_SUB_PDU;
			break;
	        case GSMTAP_BURST_HACK: 
			sub_handle = GSMTAP_SUB_HACK;
			break;
	        case GSMTAP_BURST_PHY_ATTRIBUTES: 
			sub_handle = GSMTAP_SUB_PHY_ATTRIBUTES;
			break;
	        default: 
	                sub_handle = GSMTAP_SUB_DATA; 
	                break; 
	        }
 		break;
	case GSMTAP_TYPE_UM_BURST:
	default:
		sub_handle = GSMTAP_SUB_DATA;
		break;
	}
	call_dissector(sub_handles[sub_handle], payload_tvb, pinfo, tree);
}

static const true_false_string sacch_l1h_fpc_mode_vals = {
	"In use",
	"Not in use"
};

void
proto_register_gsmtap(void)
{
	static hf_register_info hf[] = {
		{ &hf_gsmtap_version, { "Version", "gsmtap.version",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_hdrlen, { "Header Length", "gsmtap.hdr_len",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_type, { "Payload Type", "gsmtap.type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_types), 0, NULL, HFILL } },
		{ &hf_gsmtap_timeslot, { "Time Slot", "gsmtap.ts",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_arfcn, { "ARFCN", "gsmtap.arfcn",
		  FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_MASK, NULL, HFILL } },
		{ &hf_gsmtap_uplink, { "Uplink", "gsmtap.uplink",
		  FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_F_UPLINK, NULL, HFILL } },
		{ &hf_gsmtap_noise_dbm, { "Signal/Noise Ratio (dB)", "gsmtap.snr_db",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_signal_dbm, { "Signal Level (dBm)", "gsmtap.signal_dbm",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_frame_nr, { "GSM Frame Number", "gsmtap.frame_nr",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_burst_type, { "Burst Type", "gsmtap.burst_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_bursts), 0, NULL, HFILL }},
		{ &hf_gsmtap_channel_type, { "Channel Type", "gsmtap.chan_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_channels), 0, NULL, HFILL }},
		{ &hf_gsmtap_tetra_channel_type, { "Channel Type", "gsmtap.tetra_chan_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_tetra_channels), 0, NULL, HFILL }},
		{ &hf_gsmtap_antenna, { "Antenna Number", "gsmtap.antenna",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_subslot, { "Sub-Slot", "gsmtap.sub_slot",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

		{ &hf_sacch_l1h_power_lev, { "MS power level", "gsmtap.sacch_l1.power_lev",
		  FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
		{ &hf_sacch_l1h_fpc, { "FPC", "gsmtap.sacch_l1.fpc",
		  FT_BOOLEAN, 8, TFS(&sacch_l1h_fpc_mode_vals), 0x04,
		  NULL, HFILL } },
		{ &hf_sacch_l1h_ta, { "Actual Timing Advance", "gsmtap.sacch_l1.ta",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_gsmtap
	};

	proto_gsmtap = proto_register_protocol("GSM Radiotap", "GSMTAP", "gsmtap");
	proto_register_field_array(proto_gsmtap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gsmtap(void)
{
	dissector_handle_t gsmtap_handle;

	sub_handles[GSMTAP_SUB_DATA] = find_dissector("data");
	sub_handles[GSMTAP_SUB_UM] = find_dissector("gsm_a_ccch");
	sub_handles[GSMTAP_SUB_UM_LAPDM] = find_dissector("lapdm");
	sub_handles[GSMTAP_SUB_UM_RLC_MAC_UL] = find_dissector("gsm_rlcmac_ul");
	sub_handles[GSMTAP_SUB_UM_RLC_MAC_DL] = find_dissector("gsm_rlcmac_dl");
	sub_handles[GSMTAP_SUB_LLC] = find_dissector("llcgprs");
	sub_handles[GSMTAP_SUB_SNDCP] = find_dissector("sndcp");
	sub_handles[GSMTAP_SUB_ABIS] = find_dissector("gsm_a_dtap");
	sub_handles[GSMTAP_SUB_CDMA_CODE] = find_dissector("wimax_cdma_code_burst_handler"); 
	sub_handles[GSMTAP_SUB_FCH] = find_dissector("wimax_fch_burst_handler"); 
	sub_handles[GSMTAP_SUB_FFB] = find_dissector("wimax_ffb_burst_handler"); 
	sub_handles[GSMTAP_SUB_PDU] = find_dissector("wimax_pdu_burst_handler");
	sub_handles[GSMTAP_SUB_HACK] = find_dissector("wimax_hack_burst_handler");
	sub_handles[GSMTAP_SUB_PHY_ATTRIBUTES] = find_dissector("wimax_phy_attributes_burst_handler");
	sub_handles[GSMTAP_SUB_CBCH] = find_dissector("gsm_cbch");
	gsmtap_handle = create_dissector_handle(dissect_gsmtap, proto_gsmtap);
	dissector_add_uint("udp.port", GSMTAP_UDP_PORT, gsmtap_handle);
}
