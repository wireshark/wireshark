/* packet-ntp.c
 * Routines for NTP packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-ntp.c,v 1.5 1999/11/16 11:42:43 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <time.h>
#include <math.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include "packet.h"
#include "resolv.h"
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

 /* Leap indicator, 2bit field is used to warn of a inserted/deleted
  * second, or to alarm loosed synchronization.
  */
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
static const value_string ver_nums[] = {
	{ NTP_VN_R0,	"reserved" },
	{ NTP_VN_R1,	"reserved" },
	{ NTP_VN_R2,	"reserved" },
	{ NTP_VN_3,	"NTP Version 3" },
	{ NTP_VN_4,	"NTP Version 4" },
	{ NTP_VN_R5,	"reserved" },
	{ NTP_VN_R6,	"reserved" },
	{ NTP_VN_R7,	"reserved" },
	{ 0,		NULL}
};

/* Mode, 3bit field representing mode of comunication.
 */
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
	char *id;
	char *data;
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
	{ NULL,		NULL}
};

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

static gint ett_ntp = -1;
static gint ett_ntp_flags = -1;

/* ntm_fmt_ts - converts NTP timestamp to human readable string.
 * tsdata - 64bit timestamp (IN)
 * buff - string buffer for result (OUT)
 * returns pointer to filled buffer.
 */
char *
ntp_fmt_ts(guint32 tsdata[2], char* buff)
{
	guint32 tempstmp, tempfrac;
	time_t temptime;
	struct tm *bd;
	double fractime;

	tempstmp = ntohl(tsdata[0]);
	tempfrac = ntohl(tsdata[1]);
	if ((tempstmp == 0) && (tempfrac == 0)) {
		strcpy (buff, "NULL");
		return buff;
	} else {
		temptime = tempstmp - (guint32) NTP_BASETIME;
		bd = gmtime(&temptime);
		fractime = bd->tm_sec + tempfrac / 4294967296.0;
		snprintf(buff, NTP_TS_SIZE, "%04d-%02d-%02d %02d:%02d:%07.4f UTC",
			 bd->tm_year + 1900, bd->tm_mon, bd->tm_mday, bd->tm_hour,
			 bd->tm_min, fractime);
	}
	return buff;
}
		
/* dissect_ntp - dissects NTP packet data
 * pd - pointer to packet data (IN)
 * offset - offset of NTP data in pd (IN)
 * fd - frame data
 * proto_tree - resolved protocol tree
 */
void
dissect_ntp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *ntp_tree, *flags_tree;
	proto_item	*ti, *tf;
	struct ntp_packet *pkt;
	gchar buff[NTP_TS_SIZE];
	int i;

	/* get at least a full packet structure */
	if ( !BYTES_ARE_IN_FRAME(offset, 48) ) /* 48 without keyid or mac */
		return;

	pkt = (struct ntp_packet *) &pd[offset];
	
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NTP");

	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, "NTP");

	if (tree) {
		/* Adding NTP item and subtree */
		ti = proto_tree_add_item(tree, proto_ntp, offset, END_OF_FRAME, NULL);
		ntp_tree = proto_item_add_subtree(ti, ett_ntp);
		tf = proto_tree_add_item(ntp_tree, hf_ntp_flags, offset, 1, pkt->flags);

		/* Adding flag subtree and items */
		flags_tree = proto_item_add_subtree(tf, ett_ntp_flags);
		proto_tree_add_item_format(flags_tree, hf_ntp_flags_li, offset, 1,
					   *pkt->flags & NTP_LI_MASK,
					   decode_enumerated_bitfield(*pkt->flags, NTP_LI_MASK,
				           sizeof(pkt->flags) * 8, li_types, "Leap Indicator: %s"));
		proto_tree_add_item_format(flags_tree, hf_ntp_flags_vn, offset, 1,
					   *pkt->flags & NTP_VN_MASK,
					   decode_enumerated_bitfield(*pkt->flags, NTP_VN_MASK,
				           sizeof(pkt->flags) * 8, ver_nums, "Version number: %s"));
		proto_tree_add_item_format(flags_tree, hf_ntp_flags_mode, offset, 1,
					   *pkt->flags & NTP_MODE_MASK,
					   decode_enumerated_bitfield(*pkt->flags, NTP_MODE_MASK,
				           sizeof(pkt->flags) * 8, mode_types, "Mode: %s"));

		/* Stratum, 1byte field represents distance from primary source
		 */
		if (*pkt->stratum == 0) {
			strcpy (buff, "Peer Clock Stratum: unspecified or unavailable (%d)");
		} else if (*pkt->stratum == 1) {
			strcpy (buff, "Peer Clock Stratum: primary reference (%d)");
		} else if ((*pkt->stratum >= 2) && (*pkt->stratum <= 15)) {
			strcpy (buff, "Peer Clock Stratum: secondary reference (%d)");
		} else {
			strcpy (buff, "Peer Clock Stratum: reserved: %d");
		}
		proto_tree_add_item_format(ntp_tree, hf_ntp_stratum, offset+1, 1, pkt->stratum,
					   buff, (int) *pkt->stratum);
		/* Poll interval, 1byte field indicating the maximum interval between
		 * successive messages, in seconds to the nearest power of two.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_ppoll, offset+2, 1, pkt->ppoll,
					   (((*pkt->ppoll >= 4) && (*pkt->ppoll <= 16)) ? 
					   "Peer Pooling Interval: %d (%d sec)" :
					   "Peer Pooling Interval: invalid (%d)"), (int) *pkt->ppoll,
					   1 << *pkt->ppoll);
		/* Precision, 1byte field indicating the precision of the
		 * local clock, in seconds to the nearest power of two.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_precision, offset+3, 1, pkt->precision,
					   "Peer Clock Precision: %8.6f sec", pow(2, *pkt->precision));
		/* Root Delay is a 32-bit signed fixed-point number indicating the
		 * total roundtrip delay to the primary reference source, in seconds
		 * with fraction point between bits 15 and 16.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_rootdelay, offset+4, 4, pkt->rootdelay,
					   "Root Delay: %9.4f sec",
					   ((gint32) pntohs(pkt->rootdelay)) +
					   pntohs(pkt->rootdelay + 2) / 65536.0);
		/* Root Dispersion, 32-bit unsigned fixed-point number indicating
		 * the nominal error relative to the primary reference source, in
		 * seconds with fraction point between bits 15 and 16.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_rootdispersion, offset+8, 4, pkt->rootdispersion,
					   "Clock Dispersion: %9.4f sec",
					   ((gint32) pntohs(pkt->rootdispersion)) +
					   pntohs(pkt->rootdispersion + 2) / 65536.0);
		/* Now, there is a problem with secondary servers.  Standards asks
		 * from stratum-2 - stratum-15 servers to set this to the low order
		 * 32 bits of the latest transmit timestamp of the reference source.
		 * But, all V3 and V4 servers set this to IP adress of their higher
		 * level server. My decision was to resolve this address.
		 */
		if (*pkt->stratum <= 1) {
			strcpy (buff, "unindentified reference source"); 
			for (i = 0; primary_sources[i].id; i++)
				if (*((guint32 *) pkt->refid) == *((guint32 *) primary_sources[i].id))
					strcpy (buff, primary_sources[i].data); 
		} else strcpy (buff, get_hostname (*((u_int *) pkt->refid)));
		proto_tree_add_item_format(ntp_tree, hf_ntp_refid, offset+12, 4, pkt->refid,
					   "Reference Clock ID: %s", buff);
		/* Reference Timestamp: This is the time at which the local clock was
		 * last set or corrected.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_reftime, offset+16, 8, pkt->reftime,
				           "Reference Clock Update Time: %s", 
					   ntp_fmt_ts((guint32 *) pkt->reftime, buff));
		/* Originate Timestamp: This is the time at which the request departed
		 * the client for the server.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_org, offset+24, 8, pkt->org,
				           "Originate Time Stamp: %s", 
					   ntp_fmt_ts((guint32 *) pkt->org, buff));
		/* Receive Timestamp: This is the time at which the request arrived at
		 * the server.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_rec, offset+32, 8, pkt->rec,
				           "Receive Time Stamp: %s", 
					   ntp_fmt_ts((guint32 *) pkt->rec, buff));
		/* Transmit Timestamp: This is the time at which the reply departed the
		 * server for the client.
		 */
		proto_tree_add_item_format(ntp_tree, hf_ntp_xmt, offset+40, 8, pkt->xmt,
				           "Transmit Time Stamp: %s", 
					   ntp_fmt_ts((guint32 *) pkt->xmt, buff));

		/* When the NTP authentication scheme is implemented, the Key Identifier
		 * and Message Digest fields contain the message authentication code
		 * (MAC) information defined in Appendix C of RFC-1305. Will print this as
		 * hex code for now.
		 */
		if ( BYTES_ARE_IN_FRAME(offset, 50) )
			proto_tree_add_item(ntp_tree, hf_ntp_keyid, offset+48, 4, pkt->keyid);
		if ( BYTES_ARE_IN_FRAME(offset, 53) )
			proto_tree_add_item(ntp_tree, hf_ntp_mac, offset+52, END_OF_FRAME, pkt->mac);

	}
}

void
proto_register_ntp(void)
{
	static hf_register_info hf[] = {
			{ &hf_ntp_flags, {	
				"Flags", "ntp.flags", FT_BYTES, BASE_HEX, 
				NULL, 0, "Flags (Leap/Version/Mode)" }},
			{ &hf_ntp_flags_li, {
				"Leap Indicator", "ntp.flags.li", FT_UINT8, BASE_DEC,
				VALS(li_types), 0, "Leap Indicator" }},
			{ &hf_ntp_flags_vn, {
				"Version number", "ntp.flags.vn", FT_UINT8, BASE_DEC,
				VALS(ver_nums), 0, "Version number" }},
			{ &hf_ntp_flags_mode, {
				"Leap Indicator", "ntp.flags.mode", FT_UINT8, BASE_DEC,
				VALS(mode_types), 0, "Leap Indicator" }},
			{ &hf_ntp_stratum, {	
				"Peer Clock Stratum", "ntp.stratum", FT_BYTES, BASE_DEC, 
				NULL, 0, "Peer Clock Stratum" }},
			{ &hf_ntp_ppoll, {	
				"Peer Polling Interval", "ntp.ppoll", FT_BYTES, BASE_DEC, 
				NULL, 0, "Peer Polling Interval" }},
			{ &hf_ntp_precision, {	
				"Peer Clock Precision", "ntp.precision", FT_BYTES, BASE_DEC, 
				NULL, 0, "Peer Clock Precision" }},
			{ &hf_ntp_rootdelay, {	
				"Root Delay", "ntp.rootdelay", FT_BYTES, BASE_DEC, 
				NULL, 0, "Root Delay" }},
			{ &hf_ntp_rootdispersion, {	
				"Clock Dispersion", "ntp.rootdispersion", FT_BYTES, BASE_DEC, 
				NULL, 0, "Clock Dispersion" }},
			{ &hf_ntp_refid, {	
				"Reference Clock ID", "ntp.refid", FT_BYTES, BASE_NONE, 
				NULL, 0, "Reference Clock ID" }},
			{ &hf_ntp_reftime, {	
				"Reference Clock Update Time", "ntp.reftime", FT_BYTES, BASE_NONE, 
				NULL, 0, "Reference Clock Update Time" }},
			{ &hf_ntp_org, {	
				"Originate Time Stamp", "ntp.org", FT_BYTES, BASE_NONE, 
				NULL, 0, "Originate Time Stamp" }},
			{ &hf_ntp_rec, {	
				"Receive Time Stamp", "ntp.rec", FT_BYTES, BASE_NONE, 
				NULL, 0, "Receive Time Stamp" }},
			{ &hf_ntp_xmt, {	
				"Transmit Time Stamp", "ntp.xmt", FT_BYTES, BASE_NONE, 
				NULL, 0, "Transmit Time Stamp" }},
			{ &hf_ntp_keyid, {	
				"Key ID", "ntp.keyid", FT_BYTES, BASE_HEX, 
				NULL, 0, "Key ID" }},
			{ &hf_ntp_mac, {	
				"Message Authentication Code", "ntp.mac", FT_BYTES, BASE_HEX, 
				NULL, 0, "Message Authentication Code" }},
        };
	static gint *ett[] = {
		&ett_ntp,
		&ett_ntp_flags,
	};

	proto_ntp = proto_register_protocol("Network Time Protocol", "ntp");
	proto_register_field_array(proto_ntp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
