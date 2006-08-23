/* packet-ntp.c
 * Routines for NTP packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <stdio.h>

#include <string.h>
#include <time.h>
#include <math.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include "packet-ntp.h"

/*
 * Dissecting NTP packets version 3 and 4 (RFC2030, RFC1769, RFC1361,
 * RFC1305).
 *
 * Those packets have simple structure:
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Root Delay                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Root Dispersion                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Reference Identifier                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Reference Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Originate Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Receive Timestamp (64)                     |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Transmit Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Key Identifier (optional) (32)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Message Digest (optional) (128)               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * NTP timestamps are represented as a 64-bit unsigned fixed-point number,
 * in seconds relative to 0h on 1 January 1900. The integer part is in the
 * first 32 bits and the fraction part in the last 32 bits.
 */

#define UDP_PORT_NTP	123
#define TCP_PORT_NTP	123

/* Leap indicator, 2bit field is used to warn of a inserted/deleted
 * second, or to alarm loosed synchronization.
 */
#define NTP_LI_MASK	0xC0

#define NTP_LI_NONE	0
#define NTP_LI_61	1
#define NTP_LI_59	2
#define NTP_LI_ALARM	3

static const value_string li_types[] = {
	{ NTP_LI_NONE,	"no warning" },
	{ NTP_LI_61,	"last minute has 61 seconds" },
	{ NTP_LI_59,	"last minute has 59 seconds" },
	{ NTP_LI_ALARM,	"alarm condition (clock not synchronized)" },
	{ 0,		NULL}
};

/* Version info, 3bit field informs about NTP version used in particular
 * packet. According to rfc2030, version info could be only 3 or 4, but I
 * have noticed packets with 1 or even 6 as version numbers. They are
 * produced as a result of ntptrace command. Are those packets mailformed
 * on purpose? I don't know yet, probably some browsing through ntp sources
 * would help. My solution is to put them as reserved for now.
 */
#define NTP_VN_MASK	0x38

static const value_string ver_nums[] = {
	{ 0,	"reserved" },
	{ 1,	"reserved" },
	{ 2,	"reserved" },
	{ 3,	"NTP Version 3" },
	{ 4,	"NTP Version 4" },
	{ 5,	"reserved" },
	{ 6,	"reserved" },
	{ 7,	"reserved" },
	{ 0,	NULL}
};

/* Mode, 3bit field representing mode of comunication.
 */
#define NTP_MODE_MASK   7

#define NTP_MODE_RSV	0
#define NTP_MODE_SYMACT	1
#define NTP_MODE_SYMPAS	2
#define NTP_MODE_CLIENT	3
#define NTP_MODE_SERVER	4
#define NTP_MODE_BCAST	5
#define NTP_MODE_CTRL	6
#define NTP_MODE_PRIV	7

static const value_string mode_types[] = {
	{ NTP_MODE_RSV,		"reserved" },
	{ NTP_MODE_SYMACT,	"symmetric active" },
	{ NTP_MODE_SYMPAS,	"symmetric passive" },
	{ NTP_MODE_CLIENT,	"client" },
	{ NTP_MODE_SERVER,	"server" },
	{ NTP_MODE_BCAST,	"broadcast" },
	{ NTP_MODE_CTRL,	"reserved for NTP control message"},
	{ NTP_MODE_PRIV,	"reserved for private use" },
	{ 0,		NULL}
};

/* According to rfc, primary (stratum-0 and stratum-1) servers should set
 * their Reference Clock ID (4bytes field) according to following table:
 */
static const struct {
	const char *id;
	const char *data;
} primary_sources[] = {
	{ "LOCL",	"uncalibrated local clock" },
	{ "PPS\0",	"atomic clock or other pulse-per-second source" },
	{ "ACTS",	"NIST dialup modem service" },
	{ "USNO",	"USNO modem service" },
	{ "PTB\0",	"PTB (Germany) modem service" },
	{ "TDF\0",	"Allouis (France) Radio 164 kHz" },
	{ "DCF\0",	"Mainflingen (Germany) Radio 77.5 kHz" },
	{ "MSF\0",	"Rugby (UK) Radio 60 kHz" },
	{ "WWV\0",	"Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz" },
	{ "WWVB",	"Boulder (US) Radio 60 kHz" },
	{ "WWVH",	"Kaui Hawaii (US) Radio 2.5, 5, 10, 15 MHz" },
	{ "CHU\0",	"Ottawa (Canada) Radio 3330, 7335, 14670 kHz" },
	{ "LORC",	"LORAN-C radionavigation system" },
	{ "OMEG",	"OMEGA radionavigation system" },
	{ "GPS\0",	"Global Positioning Service" },
	{ "GOES",	"Geostationary Orbit Environment Satellite" },
	{ "DCN\0",	"DCN routing protocol" },
	{ "NIST",	"NIST public modem" },
	{ "TSP\0",	"TSP time protocol" },
	{ "DTS\0",	"Digital Time Service" },
	{ "ATOM",	"Atomic clock (calibrated)" },
	{ "VLF\0",	"VLF radio (OMEGA,, etc.)" },
	{ "IRIG",	"IRIG-B timecode" },
	{ "1PPS",	"External 1 PPS input" },
	{ "FREE",	"(Internal clock)" },
	{ "INIT",	"(Initialization)" },
	{ "\0\0\0\0",	"NULL" },
	{ NULL,		NULL}
};

#define NTP_EXT_R_MASK 0x80

static const value_string ext_r_types[] = {
	{ 0,		"Request" },
	{ 1,		"Response" },
	{ 0,		NULL}
};

#define NTP_EXT_ERROR_MASK 0x40
#define NTP_EXT_VN_MASK 0x3f

static const value_string ext_op_types[] = {
	{ 0,		"NULL" },
	{ 1,		"ASSOC" },
	{ 2,		"CERT" },
	{ 3,		"COOK" },
	{ 4,		"AUTO" },
	{ 5,		"TAI" },
	{ 6,		"SIGN" },
	{ 7,		"IFF" },
	{ 8,		"GQ" },
	{ 9,		"MV" },
	{ 0,		NULL}
};

#define NTPCTRL_R_MASK 0x80

#define ctrl_r_types ext_r_types

#define NTPCTRL_ERROR_MASK 0x40
#define NTPCTRL_MORE_MASK 0x20
#define NTPCTRL_OP_MASK 0x1f

static const value_string ctrl_op_types[] = {
	{ 0,		"UNSPEC" },
	{ 1,		"READSTAT" },
	{ 2,		"READVAR" },
	{ 3,		"WRITEVAR" },
	{ 4,		"READCLOCK" },
	{ 5,		"WRITECLOCK" },
	{ 6,		"SETTRAP" },
	{ 7,		"ASYNCMSG" },
	{ 31,		"UNSETTRAP" },
	{ 0,		NULL}
};

#define NTPPRIV_R_MASK 0x80

#define priv_r_types ext_r_types

#define NTPPRIV_MORE_MASK 0x40

#define NTPPRIV_AUTH_MASK 0x80
#define NTPPRIV_SEQ_MASK 0x7f

static const value_string priv_impl_types[] = {
	{ 0,		"UNIV" },
	{ 2,		"XNTPD_OLD (pre-IPv6)" },
	{ 3,		"XNTPD" },
	{ 0,		NULL}
};

static const value_string priv_rc_types[] = {
	{ 0,		"PEER_LIST" },
	{ 1,		"PEER_LIST_SUM" },
	{ 2,		"PEER_INFO" },
	{ 3,		"PEER_STATS" },
	{ 4,		"SYS_INFO" },
	{ 5,		"SYS_STATS" },
	{ 6,		"IO_STATS" },
	{ 7,		"MEM_STATS" },
	{ 8,		"LOOP_INFO" },
	{ 9,		"TIMER_STATS" },
	{ 10,		"CONFIG" },
	{ 11,		"UNCONFIG" },
	{ 12,		"SET_SYS_FLAG" },
	{ 13,		"CLR_SYS_FLAG" },
	{ 16,		"GET_RESTRICT" },
	{ 17,		"RESADDFLAGS" },
	{ 18,		"RESSUBFLAGS" },
	{ 19,		"UNRESTRICT" },
	{ 20,		"MON_GETLIST" },
	{ 21,		"RESET_STATS" },
	{ 22,		"RESET_PEER" },
	{ 23,		"REREAD_KEYS" },
	{ 26,		"TRUSTKEY" },
	{ 27,		"UNTRUSTKEY" },
	{ 28,		"AUTHINFO" },
	{ 29,		"TRAPS" },
	{ 30,		"ADD_TRAP" },
	{ 31,		"CLR_TRAP" },
	{ 32,		"REQUEST_KEY" },
	{ 33,		"CONTROL_KEY" },
	{ 34,		"GET_CTLSTATS" },
	{ 36,		"GET_CLOCKINFO" },
	{ 37,		"SET_CLKFUDGE" },
	{ 38,		"GET_KERNEL" },
	{ 39,		"GET_CLKBUGINFO" },
	{ 42,		"MON_GETLIST_1" },
	{ 43,		"HOSTNAME_ASSOCID" },
	{ 0,		NULL}
};

/*
 * Maximum MAC length.
 */
#define MAX_MAC_LEN	(5 * sizeof (guint32))

static int proto_ntp = -1;

static int hf_ntp_flags = -1;
static int hf_ntp_flags_li = -1;
static int hf_ntp_flags_vn = -1;
static int hf_ntp_flags_mode = -1;
static int hf_ntp_stratum = -1;
static int hf_ntp_ppoll = -1;
static int hf_ntp_precision = -1;
static int hf_ntp_rootdelay = -1;
static int hf_ntp_rootdispersion = -1;
static int hf_ntp_refid = -1;
static int hf_ntp_reftime = -1;
static int hf_ntp_org = -1;
static int hf_ntp_rec = -1;
static int hf_ntp_xmt = -1;
static int hf_ntp_keyid = -1;
static int hf_ntp_mac = -1;

static int hf_ntp_ext = -1;
static int hf_ntp_ext_flags = -1;
static int hf_ntp_ext_flags_r = -1;
static int hf_ntp_ext_flags_error = -1;
static int hf_ntp_ext_flags_vn = -1;
static int hf_ntp_ext_op = -1;
static int hf_ntp_ext_len = -1;
static int hf_ntp_ext_associd = -1;
static int hf_ntp_ext_tstamp = -1;
static int hf_ntp_ext_fstamp = -1;
static int hf_ntp_ext_vallen = -1;
static int hf_ntp_ext_val = -1;
static int hf_ntp_ext_siglen = -1;
static int hf_ntp_ext_sig = -1;

static int hf_ntpctrl_flags2 = -1;
static int hf_ntpctrl_flags2_r = -1;
static int hf_ntpctrl_flags2_error = -1;
static int hf_ntpctrl_flags2_more = -1;
static int hf_ntpctrl_flags2_opcode = -1;

static int hf_ntppriv_flags_r = -1;
static int hf_ntppriv_flags_more = -1;
static int hf_ntppriv_auth_seq = -1;
static int hf_ntppriv_auth = -1;
static int hf_ntppriv_seq = -1;
static int hf_ntppriv_impl = -1;
static int hf_ntppriv_reqcode = -1;

static gint ett_ntp = -1;
static gint ett_ntp_flags = -1;
static gint ett_ntp_ext = -1;
static gint ett_ntp_ext_flags = -1;
static gint ett_ntpctrl_flags2 = -1;
static gint ett_ntppriv_auth_seq = -1;

static void dissect_ntp_std(tvbuff_t *, proto_tree *, guint8);
static void dissect_ntp_ctrl(tvbuff_t *, proto_tree *, guint8);
static void dissect_ntp_priv(tvbuff_t *, proto_tree *, guint8);
static int dissect_ntp_ext(tvbuff_t *, proto_tree *, int);

static const char *mon_names[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

/* ntp_fmt_ts - converts NTP timestamp to human readable string.
 * reftime - 64bit timestamp (IN)
 * returns pointer to filled buffer.  This buffer will be freed automatically once
 * dissection of the next packet occurs.
 */
char *
ntp_fmt_ts(const guint8 *reftime)
{
	guint32 tempstmp, tempfrac;
	time_t temptime;
	struct tm *bd;
	double fractime;
	char *buff;

	tempstmp = pntohl(&reftime[0]);
	tempfrac = pntohl(&reftime[4]);
	if ((tempstmp == 0) && (tempfrac == 0)) {
		return "NULL";
	}

	temptime = tempstmp - (guint32) NTP_BASETIME;
	bd = gmtime(&temptime);
	if(!bd){
		return "Not representable";
	}

	fractime = bd->tm_sec + tempfrac / 4294967296.0;
	buff=ep_alloc(NTP_TS_SIZE);
	g_snprintf(buff, NTP_TS_SIZE,
                 "%s %2d, %d %02d:%02d:%07.4f UTC",
		 mon_names[bd->tm_mon],
		 bd->tm_mday,
		 bd->tm_year + 1900,
		 bd->tm_hour,
		 bd->tm_min,
		 fractime);
	return buff;
}

/* dissect_ntp - dissects NTP packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static void
dissect_ntp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *ntp_tree;
	proto_item	*ti;
	guint8		flags;
	const char *infostr;
	void (*dissector)(tvbuff_t *, proto_item *, guint8);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NTP");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	flags = tvb_get_guint8(tvb, 0);
	switch (flags & NTP_MODE_MASK) {
	default:
		infostr = "NTP";
		dissector = dissect_ntp_std;
		break;
	case NTP_MODE_CTRL:
		infostr = "NTP control";
		dissector = dissect_ntp_ctrl;
		break;
	case NTP_MODE_PRIV:
		infostr = "NTP private";
		dissector = dissect_ntp_priv;
		break;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, infostr);

	if (tree) {
		/* Adding NTP item and subtree */
		ti = proto_tree_add_item(tree, proto_ntp, tvb, 0, -1, FALSE);
		ntp_tree = proto_item_add_subtree(ti, ett_ntp);

		(*dissector)(tvb, ntp_tree, flags);
	}
}

static void
dissect_ntp_std(tvbuff_t *tvb, proto_tree *ntp_tree, guint8 flags)
{
	proto_tree      *flags_tree;
	proto_item	*tf;
	guint8		stratum;
	guint8		ppoll;
	gint8		precision;
	double		rootdelay;
	double		rootdispersion;
	const guint8	*refid;
	guint32		refid_addr;
	const guint8	*reftime;
	const guint8	*org;
	const guint8	*rec;
	const guint8	*xmt;
	gchar		*buff;
	int		i;
	int		macofs;
	gint            maclen;

	tf = proto_tree_add_uint(ntp_tree, hf_ntp_flags, tvb, 0, 1, flags);

	/* Adding flag subtree and items */
	flags_tree = proto_item_add_subtree(tf, ett_ntp_flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_li, tvb, 0, 1, flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_vn, tvb, 0, 1, flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_mode, tvb, 0, 1, flags);

	/* Stratum, 1byte field represents distance from primary source
	 */
	stratum = tvb_get_guint8(tvb, 1);
	if (stratum == 0) {
		buff="Peer Clock Stratum: unspecified or unavailable (%u)";
	} else if (stratum == 1) {
		buff="Peer Clock Stratum: primary reference (%u)";
	} else if ((stratum >= 2) && (stratum <= 15)) {
		buff="Peer Clock Stratum: secondary reference (%u)";
	} else {
		buff="Peer Clock Stratum: reserved: %u";
	}
	proto_tree_add_uint_format(ntp_tree, hf_ntp_stratum, tvb, 1, 1,
				   stratum, buff, stratum);
	/* Poll interval, 1byte field indicating the maximum interval
	 * between successive messages, in seconds to the nearest
	 * power of two.
	 */
	ppoll = tvb_get_guint8(tvb, 2);
	proto_tree_add_uint_format(ntp_tree, hf_ntp_ppoll, tvb, 2, 1,
				   ppoll,
				   (((ppoll >= 4) && (ppoll <= 16)) ?
				   "Peer Polling Interval: %u (%u sec)" :
				   "Peer Polling Interval: invalid (%u)"),
				   ppoll,
				   1 << ppoll);

	/* Precision, 1byte field indicating the precision of the
	 * local clock, in seconds to the nearest power of two.
	 */
	precision = tvb_get_guint8(tvb, 3);
	proto_tree_add_int_format(ntp_tree, hf_ntp_precision, tvb, 3, 1,
				   precision,
				   "Peer Clock Precision: %8.6f sec",
				   pow(2, precision));

	/* Root Delay is a 32-bit signed fixed-point number indicating
	 * the total roundtrip delay to the primary reference source,
	 * in seconds with fraction point between bits 15 and 16.
	 */
	rootdelay = ((gint16)tvb_get_ntohs(tvb, 4)) +
			(tvb_get_ntohs(tvb, 6) / 65536.0);
	proto_tree_add_double_format(ntp_tree, hf_ntp_rootdelay, tvb, 4, 4,
				   rootdelay,
				   "Root Delay: %9.4f sec",
				   rootdelay);

	/* Root Dispersion, 32-bit unsigned fixed-point number indicating
	 * the nominal error relative to the primary reference source, in
	 * seconds with fraction point between bits 15 and 16.
	 */
	rootdispersion = ((gint16)tvb_get_ntohs(tvb, 8)) +
				(tvb_get_ntohs(tvb, 10) / 65536.0);
	proto_tree_add_double_format(ntp_tree, hf_ntp_rootdispersion, tvb, 8, 4,
				   rootdispersion,
				   "Clock Dispersion: %9.4f sec",
				   rootdispersion);

	/* Now, there is a problem with secondary servers.  Standards
	 * asks from stratum-2 - stratum-15 servers to set this to the
	 * low order 32 bits of the latest transmit timestamp of the
	 * reference source.
	 * But, all V3 and V4 servers set this to IP adress of their
	 * higher level server. My decision was to resolve this address.
	 */
	refid = tvb_get_ptr(tvb, 12, 4);
	buff = ep_alloc(NTP_TS_SIZE);
	if (stratum <= 1) {
		g_snprintf (buff, NTP_TS_SIZE, "Unidentified reference source '%.4s'",
			refid);
		for (i = 0; primary_sources[i].id; i++) {
			if (memcmp (refid, primary_sources[i].id, 4) == 0) {
				g_snprintf(buff, NTP_TS_SIZE, "%s",
					primary_sources[i].data);
				break;
			}
		}
	} else {
		int buffpos;
		refid_addr = tvb_get_ipv4(tvb, 12);
		buffpos = g_snprintf(buff, NTP_TS_SIZE, "%s", get_hostname (refid_addr));
		if (buffpos >= NTP_TS_SIZE) {
			buff[NTP_TS_SIZE-4]='.';
			buff[NTP_TS_SIZE-3]='.';
			buff[NTP_TS_SIZE-2]='.';
			buff[NTP_TS_SIZE-1]=0;
		}
	}
	proto_tree_add_bytes_format(ntp_tree, hf_ntp_refid, tvb, 12, 4,
				   refid,
				   "Reference Clock ID: %s", buff);

	/* Reference Timestamp: This is the time at which the local clock was
	 * last set or corrected.
	 */
	reftime = tvb_get_ptr(tvb, 16, 8);
	proto_tree_add_bytes_format(ntp_tree, hf_ntp_reftime, tvb, 16, 8,
				   reftime,
			           "Reference Clock Update Time: %s",
				   ntp_fmt_ts(reftime));

	/* Originate Timestamp: This is the time at which the request departed
	 * the client for the server.
	 */
	org = tvb_get_ptr(tvb, 24, 8);
	proto_tree_add_bytes_format(ntp_tree, hf_ntp_org, tvb, 24, 8,
				   org,
			           "Originate Time Stamp: %s",
				   ntp_fmt_ts(org));

	/* Receive Timestamp: This is the time at which the request arrived at
	 * the server.
	 */
	rec = tvb_get_ptr(tvb, 32, 8);
	proto_tree_add_bytes_format(ntp_tree, hf_ntp_rec, tvb, 32, 8,
				   rec,
			           "Receive Time Stamp: %s",
				   ntp_fmt_ts(rec));

	/* Transmit Timestamp: This is the time at which the reply departed the
	 * server for the client.
	 */
	xmt = tvb_get_ptr(tvb, 40, 8);
	proto_tree_add_bytes_format(ntp_tree, hf_ntp_xmt, tvb, 40, 8,
				   xmt,
			           "Transmit Time Stamp: %s",
				   ntp_fmt_ts(xmt));

	/* MAX_MAC_LEN is the largest message authentication code
	 * (MAC) length.  If we have more data left in the packet
	 * after the header than that, the extra data is NTP4
	 * extensions; parse them as such.
	 */
	macofs = 48;
	while (tvb_reported_length_remaining(tvb, macofs) > (gint)MAX_MAC_LEN)
		macofs = dissect_ntp_ext(tvb, ntp_tree, macofs);

	/* When the NTP authentication scheme is implemented, the
	 * Key Identifier and Message Digest fields contain the
	 * message authentication code (MAC) information defined in
	 * Appendix C of RFC-1305. Will print this as hex code for now.
	 */
	if (tvb_reported_length_remaining(tvb, macofs) >= 4)
		proto_tree_add_item(ntp_tree, hf_ntp_keyid, tvb, macofs, 4,
				    FALSE);
	macofs += 4;
	maclen = tvb_reported_length_remaining(tvb, macofs);
	if (maclen > 0)
		proto_tree_add_item(ntp_tree, hf_ntp_mac, tvb, macofs,
				    maclen, FALSE);
}

static int
dissect_ntp_ext(tvbuff_t *tvb, proto_tree *ntp_tree, int offset)
{
	proto_tree      *ext_tree, *flags_tree;
	proto_item	*tf;
	guint16         extlen;
	int             endoffset;
	guint8          flags;
	guint32         vallen, vallen_round, siglen;

	extlen = tvb_get_ntohs(tvb, offset+2);
	if (extlen < 8) {
		/* Extension length isn't enough for the extension header.
		 * Report the error, and return an offset that goes to
		 * the end of the tvbuff, so we stop dissecting.
		 */
		proto_tree_add_text(ntp_tree, tvb, offset+2, 2,
				    "Extension length %u < 8", extlen);
		offset += tvb_length_remaining(tvb, offset);
		return offset;
	}
	if (extlen % 4) {
		/* Extension length isn't a multiple of 4.
		 * Report the error, and return an offset that goes
		 * to the end of the tvbuff, so we stop dissecting.
		 */
		proto_tree_add_text(ntp_tree, tvb, offset+2, 2,
			"Extension length %u isn't a multiple of 4",
				    extlen);
		offset += tvb_length_remaining(tvb, offset);
		return offset;
	}
	endoffset = offset + extlen;

	tf = proto_tree_add_item(ntp_tree, hf_ntp_ext, tvb, offset, extlen,
	    FALSE);
	ext_tree = proto_item_add_subtree(tf, ett_ntp_ext);

	flags = tvb_get_guint8(tvb, offset);
	tf = proto_tree_add_uint(ext_tree, hf_ntp_ext_flags, tvb, offset, 1,
				 flags);
	flags_tree = proto_item_add_subtree(tf, ett_ntp_ext_flags);
	proto_tree_add_uint(flags_tree, hf_ntp_ext_flags_r, tvb, offset, 1,
			    flags);
	proto_tree_add_uint(flags_tree, hf_ntp_ext_flags_error, tvb, offset, 1,
			    flags);
	proto_tree_add_uint(flags_tree, hf_ntp_ext_flags_vn, tvb, offset, 1,
			    flags);
	offset++;

	proto_tree_add_item(ext_tree, hf_ntp_ext_op, tvb, offset, 1, FALSE);
	offset++;

	proto_tree_add_uint(ext_tree, hf_ntp_ext_len, tvb, offset, 2, extlen);
	offset += 2;

	if ((flags & NTP_EXT_VN_MASK) != 2) {
		/* don't care about autokey v1 */
		return endoffset;
	}

	proto_tree_add_item(ext_tree, hf_ntp_ext_associd, tvb, offset, 4,
			    FALSE);
	offset += 4;

	/* check whether everything up to "vallen" is present */
	if (extlen < MAX_MAC_LEN) {
		/* XXX - report as error? */
		return endoffset;
	}

	proto_tree_add_item(ext_tree, hf_ntp_ext_tstamp, tvb, offset, 4,
			    FALSE);
	offset += 4;
	proto_tree_add_item(ext_tree, hf_ntp_ext_fstamp, tvb, offset, 4,
			    FALSE);
	offset += 4;
	/* XXX fstamp can be server flags */

	vallen = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(ext_tree, hf_ntp_ext_vallen, tvb, offset, 4,
			    vallen);
	offset += 4;
	vallen_round = (vallen + 3) & (-4);
	if (vallen != 0) {
		if ((guint32)(endoffset - offset) < vallen_round) {
			/*
			 * Value goes past the length of the extension
			 * field.
			 */
			proto_tree_add_text(ext_tree, tvb, offset,
					    endoffset - offset,
					    "Value length makes value go past the end of the extension field");
			return endoffset;
		}
		proto_tree_add_item(ext_tree, hf_ntp_ext_val, tvb, offset,
				    vallen, FALSE);
	}
	offset += vallen_round;

	siglen = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(ext_tree, hf_ntp_ext_siglen, tvb, offset, 4,
			    siglen);
	offset += 4;
	if (siglen != 0) {
		if (offset + (int)siglen > endoffset) {
			/*
			 * Value goes past the length of the extension
			 * field.
			 */
			proto_tree_add_text(ext_tree, tvb, offset,
					    endoffset - offset,
					    "Signature length makes value go past the end of the extension field");
			return endoffset;
		}
		proto_tree_add_item(ext_tree, hf_ntp_ext_sig, tvb,
			offset, siglen, FALSE);
	}
	return endoffset;
}

static void
dissect_ntp_ctrl(tvbuff_t *tvb, proto_tree *ntp_tree, guint8 flags)
{
	proto_tree      *flags_tree;
	proto_item	*tf;
	guint8 flags2;

	tf = proto_tree_add_uint(ntp_tree, hf_ntp_flags, tvb, 0, 1, flags);

	/* Adding flag subtree and items */
	flags_tree = proto_item_add_subtree(tf, ett_ntp_flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_li, tvb, 0, 1, flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_vn, tvb, 0, 1, flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_mode, tvb, 0, 1, flags);

	flags2 = tvb_get_guint8(tvb, 1);
	tf = proto_tree_add_uint(ntp_tree, hf_ntpctrl_flags2, tvb, 1, 1,
				 flags2);
	flags_tree = proto_item_add_subtree(tf, ett_ntpctrl_flags2);
	proto_tree_add_uint(flags_tree, hf_ntpctrl_flags2_r, tvb, 1, 1,
			    flags2);
	proto_tree_add_uint(flags_tree, hf_ntpctrl_flags2_error, tvb, 1, 1,
			    flags2);
	proto_tree_add_uint(flags_tree, hf_ntpctrl_flags2_more, tvb, 1, 1,
			    flags2);
	proto_tree_add_uint(flags_tree, hf_ntpctrl_flags2_opcode, tvb, 1, 1,
			    flags2);
}

static void
dissect_ntp_priv(tvbuff_t *tvb, proto_tree *ntp_tree, guint8 flags)
{
	proto_tree      *flags_tree;
	proto_item	*tf;
	guint8		auth_seq, impl, reqcode;

	tf = proto_tree_add_uint(ntp_tree, hf_ntp_flags, tvb, 0, 1, flags);

	/* Adding flag subtree and items */
	flags_tree = proto_item_add_subtree(tf, ett_ntp_flags);
	proto_tree_add_uint(flags_tree, hf_ntppriv_flags_r, tvb, 0, 1, flags);
	proto_tree_add_uint(flags_tree, hf_ntppriv_flags_more, tvb, 0, 1,
			    flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_vn, tvb, 0, 1, flags);
	proto_tree_add_uint(flags_tree, hf_ntp_flags_mode, tvb, 0, 1, flags);

	auth_seq = tvb_get_guint8(tvb, 1);
	tf = proto_tree_add_uint(ntp_tree, hf_ntppriv_auth_seq, tvb, 1, 1,
				 auth_seq);
	flags_tree = proto_item_add_subtree(tf, ett_ntppriv_auth_seq);
	proto_tree_add_uint(flags_tree, hf_ntppriv_auth, tvb, 1, 1, auth_seq);
	proto_tree_add_uint(flags_tree, hf_ntppriv_seq, tvb, 1, 1, auth_seq);

	impl = tvb_get_guint8(tvb, 2);
	proto_tree_add_uint(ntp_tree, hf_ntppriv_impl, tvb, 2, 1, impl);

	reqcode = tvb_get_guint8(tvb, 3);
	proto_tree_add_uint(ntp_tree, hf_ntppriv_reqcode, tvb, 3, 1, reqcode);
}

void
proto_register_ntp(void)
{
	static hf_register_info hf[] = {
		{ &hf_ntp_flags, {
			"Flags", "ntp.flags", FT_UINT8, BASE_HEX,
			NULL, 0, "Flags (Leap/Version/Mode)", HFILL }},
		{ &hf_ntp_flags_li, {
			"Leap Indicator", "ntp.flags.li", FT_UINT8, BASE_DEC,
			VALS(li_types), NTP_LI_MASK, "Leap Indicator", HFILL }},
		{ &hf_ntp_flags_vn, {
			"Version number", "ntp.flags.vn", FT_UINT8, BASE_DEC,
			VALS(ver_nums), NTP_VN_MASK, "Version number", HFILL }},
		{ &hf_ntp_flags_mode, {
			"Mode", "ntp.flags.mode", FT_UINT8, BASE_DEC,
			VALS(mode_types), NTP_MODE_MASK, "Mode", HFILL }},
		{ &hf_ntp_stratum, {
			"Peer Clock Stratum", "ntp.stratum", FT_UINT8, BASE_DEC,
			NULL, 0, "Peer Clock Stratum", HFILL }},
		{ &hf_ntp_ppoll, {
			"Peer Polling Interval", "ntp.ppoll", FT_UINT8, BASE_DEC,
			NULL, 0, "Peer Polling Interval", HFILL }},
		{ &hf_ntp_precision, {
			"Peer Clock Precision", "ntp.precision", FT_INT8, BASE_DEC,
			NULL, 0, "Peer Clock Precision", HFILL }},
		{ &hf_ntp_rootdelay, {
			"Root Delay", "ntp.rootdelay", FT_DOUBLE, BASE_DEC,
			NULL, 0, "Root Delay", HFILL }},
		{ &hf_ntp_rootdispersion, {
			"Clock Dispersion", "ntp.rootdispersion", FT_DOUBLE, BASE_DEC,
			NULL, 0, "Clock Dispersion", HFILL }},
		{ &hf_ntp_refid, {
			"Reference Clock ID", "ntp.refid", FT_BYTES, BASE_NONE,
			NULL, 0, "Reference Clock ID", HFILL }},
		{ &hf_ntp_reftime, {
			"Reference Clock Update Time", "ntp.reftime", FT_BYTES, BASE_NONE,
			NULL, 0, "Reference Clock Update Time", HFILL }},
		{ &hf_ntp_org, {
			"Originate Time Stamp", "ntp.org", FT_BYTES, BASE_NONE,
			NULL, 0, "Originate Time Stamp", HFILL }},
		{ &hf_ntp_rec, {
			"Receive Time Stamp", "ntp.rec", FT_BYTES, BASE_NONE,
			NULL, 0, "Receive Time Stamp", HFILL }},
		{ &hf_ntp_xmt, {
			"Transmit Time Stamp", "ntp.xmt", FT_BYTES, BASE_NONE,
			NULL, 0, "Transmit Time Stamp", HFILL }},
		{ &hf_ntp_keyid, {
			"Key ID", "ntp.keyid", FT_BYTES, BASE_HEX,
			NULL, 0, "Key ID", HFILL }},
		{ &hf_ntp_mac, {
			"Message Authentication Code", "ntp.mac", FT_BYTES, BASE_HEX,
			NULL, 0, "Message Authentication Code", HFILL }},

		{ &hf_ntp_ext, {
			"Extension", "ntp.ext", FT_NONE, BASE_NONE,
			NULL, 0, "Extension", HFILL }},
		{ &hf_ntp_ext_flags, {
			"Flags", "ntp.ext.flags", FT_UINT8, BASE_HEX,
			NULL, 0, "Flags (Response/Error/Version)", HFILL }},
		{ &hf_ntp_ext_flags_r, {
			"Response bit", "ntp.ext.flags.r", FT_UINT8, BASE_DEC,
			VALS(ext_r_types), NTP_EXT_R_MASK, "Response bit", HFILL }},
		{ &hf_ntp_ext_flags_error, {
			"Error bit", "ntp.ext.flags.error", FT_UINT8, BASE_DEC,
			NULL, NTP_EXT_ERROR_MASK, "Error bit", HFILL }},
		{ &hf_ntp_ext_flags_vn, {
			"Version", "ntp.ext.flags.vn", FT_UINT8, BASE_DEC,
			NULL, NTP_EXT_VN_MASK, "Version", HFILL }},
		{ &hf_ntp_ext_op, {
			"Opcode", "ntp.ext.op", FT_UINT8, BASE_DEC,
			VALS(ext_op_types), 0, "Opcode", HFILL }},
		{ &hf_ntp_ext_len, {
			"Extension length", "ntp.ext.len", FT_UINT16, BASE_DEC,
			NULL, 0, "Extension length", HFILL }},
		{ &hf_ntp_ext_associd, {
			"Association ID", "ntp.ext.associd", FT_UINT32, BASE_DEC,
			NULL, 0, "Association ID", HFILL }},
		{ &hf_ntp_ext_tstamp, {
			"Timestamp", "ntp.ext.tstamp", FT_UINT32, BASE_HEX,
			NULL, 0, "Timestamp", HFILL }},
		{ &hf_ntp_ext_fstamp, {
			"File Timestamp", "ntp.ext.fstamp", FT_UINT32, BASE_HEX,
			NULL, 0, "File Timestamp", HFILL }},
		{ &hf_ntp_ext_vallen, {
			"Value length", "ntp.ext.vallen", FT_UINT32, BASE_DEC,
			NULL, 0, "Value length", HFILL }},
		{ &hf_ntp_ext_val, {
			"Value", "ntp.ext.val", FT_BYTES, BASE_HEX,
			NULL, 0, "Value", HFILL }},
		{ &hf_ntp_ext_siglen, {
			"Signature length", "ntp.ext.siglen", FT_UINT32, BASE_DEC,
			NULL, 0, "Signature length", HFILL }},
		{ &hf_ntp_ext_sig, {
			"Signature", "ntp.ext.sig", FT_BYTES, BASE_HEX,
			NULL, 0, "Signature", HFILL }},

		{ &hf_ntpctrl_flags2, {
			"Flags 2", "ntpctrl.flags2", FT_UINT8, BASE_HEX,
			NULL, 0, "Flags (Response/Error/More/Opcode)", HFILL }},
		{ &hf_ntpctrl_flags2_r, {
			"Response bit", "ntpctrl.flags2.r", FT_UINT8, BASE_DEC,
			VALS(ctrl_r_types), NTPCTRL_R_MASK, "Response bit", HFILL }},
		{ &hf_ntpctrl_flags2_error, {
			"Error bit", "ntpctrl.flags2.error", FT_UINT8, BASE_DEC,
			NULL, NTPCTRL_ERROR_MASK, "Error bit", HFILL }},
		{ &hf_ntpctrl_flags2_more, {
			"More bit", "ntpctrl.flags2.more", FT_UINT8, BASE_DEC,
			NULL, NTPCTRL_MORE_MASK, "More bit", HFILL }},
		{ &hf_ntpctrl_flags2_opcode, {
			"Opcode", "ntpctrl.flags2.opcode", FT_UINT8, BASE_DEC,
			VALS(ctrl_op_types), NTPCTRL_OP_MASK, "Opcode", HFILL }},

		{ &hf_ntppriv_flags_r, {
			"Response bit", "ntppriv.flags.r", FT_UINT8, BASE_DEC,
			VALS(priv_r_types), NTPPRIV_R_MASK, "Response bit", HFILL }},
		{ &hf_ntppriv_flags_more, {
			"More bit", "ntppriv.flags.more", FT_UINT8, BASE_DEC,
			NULL, NTPPRIV_MORE_MASK, "More bit", HFILL }},
		{ &hf_ntppriv_auth_seq, {
			"Auth, sequence", "ntppriv.auth_seq", FT_UINT8, BASE_DEC,
			NULL, 0, "Auth bit, sequence number", HFILL }},
		{ &hf_ntppriv_auth, {
			"Auth bit", "ntppriv.auth", FT_UINT8, BASE_DEC,
			NULL, NTPPRIV_AUTH_MASK, "Auth bit", HFILL }},
		{ &hf_ntppriv_seq, {
			"Sequence number", "ntppriv.seq", FT_UINT8, BASE_DEC,
			NULL, NTPPRIV_SEQ_MASK, "Sequence number", HFILL }},
		{ &hf_ntppriv_impl, {
			"Implementation", "ntppriv.impl", FT_UINT8, BASE_DEC,
			VALS(priv_impl_types), 0, "Implementation", HFILL }},
		{ &hf_ntppriv_reqcode, {
			"Request code", "ntppriv.reqcode", FT_UINT8, BASE_DEC,
			VALS(priv_rc_types), 0, "Request code", HFILL }},
        };
	static gint *ett[] = {
		&ett_ntp,
		&ett_ntp_flags,
		&ett_ntp_ext,
		&ett_ntp_ext_flags,
		&ett_ntpctrl_flags2,
		&ett_ntppriv_auth_seq,
	};

	proto_ntp = proto_register_protocol("Network Time Protocol", "NTP",
	    "ntp");
	proto_register_field_array(proto_ntp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ntp(void)
{
	dissector_handle_t ntp_handle;

	ntp_handle = create_dissector_handle(dissect_ntp, proto_ntp);
	dissector_add("udp.port", UDP_PORT_NTP, ntp_handle);
	dissector_add("tcp.port", TCP_PORT_NTP, ntp_handle);
}
