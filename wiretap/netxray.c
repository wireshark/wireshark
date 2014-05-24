/* netxray.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "netxray.h"
#include "buffer.h"
#include "atm.h"

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number size, in both 1.x and later files. */
#define MAGIC_SIZE	4

/* Magic number in NetXRay 1.x files. */
static const char old_netxray_magic[MAGIC_SIZE] = {
	'V', 'L', '\0', '\0'
};

/* Magic number in NetXRay 2.0 and later, and Windows Sniffer, files. */
static const char netxray_magic[MAGIC_SIZE] = {
	'X', 'C', 'P', '\0'
};

/* NetXRay file header (minus magic number).			*/
/*								*/
/* As field usages are identified, please revise as needed	*/
/* Please do *not* use netxray_hdr xxx... names in the code	*/
/* (Placeholder names for all 'unknown' fields are		*/
/*   of form xxx_x<hex_hdr_offset>				*/
/*   where <hex_hdr_offset> *includes* the magic number)	*/

struct netxray_hdr {
	char	version[8];	/* version number				*/
	guint32	start_time;	/* UNIX [UTC] time when capture started		*/

	guint32	nframes;	/* number of packets				*/
	guint32	xxx_x14;	/* unknown [some kind of file offset]		*/
	guint32	start_offset;	/* offset of first packet in capture		*/
	guint32	end_offset;	/* offset after last packet in capture		*/

	guint32 xxx_x20;	/* unknown [some kind of file offset]		*/
	guint32 xxx_x24;	/* unknown [unused ?]				*/
	guint32 xxx_x28;	/* unknown [some kind of file offset]		*/
	guint8	network;	/* datalink type				*/
	guint8	network_plus;	/* [See code]					*/
	guint8	xxx_x2E[2];	/* unknown					*/

	guint8	timeunit;	/* encodes length of a tick			*/
	guint8	xxx_x31[3];	/* XXX - upper 3 bytes of timeunit ?		*/
	guint32	timelo;		/* lower 32 bits of capture start time stamp	*/
	guint32	timehi;		/* upper 32 bits of capture start time stamp	*/
	guint32 linespeed;	/* speed of network, in bits/second		*/

	guint8	xxx_x40[12];	/* unknown [other stuff]			*/
	guint8	realtick[4];	/* (ticks/sec for Ethernet/Ndis/Timeunit=2 ?)	*/
				/* (realtick[1], realtick[2] also currently	*/
				/*  used as flag for 'FCS presence')		*/

	guint8	xxx_x50[4];	/* unknown [other stuff]			*/
	guint8	captype;	/* capture type					*/
	guint8  xxx_x55[3];	/* unknown [other stuff]			*/
	guint8  xxx_x58[4];	/* unknown [other stuff]			*/
	guint8  wan_hdlc_subsub_captype; /* WAN HDLC subsub_captype		*/
	guint8  xxx_x5D[3];	/* unknown [other stuff]			*/

	guint8	xxx_x60[16];	/* unknown [other stuff]			*/

	guint8  xxx_x70[14];    /* unknown [other stuff]			*/
	gint16 timezone_hrs;	/* timezone hours [at least for version 2.2..];	*/
				/*  positive values = west of UTC:		*/
				/*  negative values = east of UTC:		*/
				/*  e.g. +5 is American Eastern			*/
				/* [Does not appear to be adjusted for DST ]	*/
};

/*
 * Capture type, in hdr.captype.
 *
 * Values other than 0 are dependent on the network type.
 * For Ethernet captures, it indicates the type of capture pod.
 * For WAN captures (all of which are done with a pod), it indicates
 * the link-layer type.
 */
#define CAPTYPE_NDIS	0		/* Capture on network interface using NDIS 			*/

/*
 * Ethernet capture types.
 */
#define ETH_CAPTYPE_GIGPOD	2	/* gigabit Ethernet captured with pod				*/
#define ETH_CAPTYPE_OTHERPOD	3	/* non-gigabit Ethernet captured with pod			*/
#define ETH_CAPTYPE_OTHERPOD2	5	/* gigabit Ethernet via pod ??					*/
					/*  Captype 5 seen in capture from Distributed Sniffer with:	*/
					/*    Version 4.50.211 software					*/
					/*    SysKonnect SK-9843 Gigabit Ethernet Server Adapter	*/
#define ETH_CAPTYPE_GIGPOD2	6	/* gigabit Ethernet, captured with blade on S6040-model Sniffer */

/*
 * WAN capture types.
 */
#define WAN_CAPTYPE_BROUTER	1	/* Bridge/router captured with pod */
#define WAN_CAPTYPE_PPP		3	/* PPP captured with pod */
#define WAN_CAPTYPE_FRELAY	4	/* Frame Relay captured with pod */
#define WAN_CAPTYPE_BROUTER2	5	/* Bridge/router captured with pod */
#define WAN_CAPTYPE_HDLC	6	/* HDLC (X.25, ISDN) captured with pod */
#define WAN_CAPTYPE_SDLC	7	/* SDLC captured with pod */
#define WAN_CAPTYPE_HDLC2	8	/* HDLC captured with pod */
#define WAN_CAPTYPE_BROUTER3	9	/* Bridge/router captured with pod */
#define WAN_CAPTYPE_SMDS	10	/* SMDS DXI */
#define WAN_CAPTYPE_BROUTER4	11	/* Bridge/router captured with pod */
#define WAN_CAPTYPE_BROUTER5	12	/* Bridge/router captured with pod */
#define WAN_CAPTYPE_CHDLC 	19	/* Cisco router (CHDLC) captured with pod */

#define CAPTYPE_ATM		15	/* ATM captured with pod */

/*
 * # of ticks that equal 1 second, in version 002.xxx files other
 * than Ethernet captures with a captype other than CAPTYPE_NDIS;
 * the index into this array is hdr.timeunit.
 *
 * DO NOT SEND IN PATCHES THAT CHANGE ANY OF THE NON-ZERO VALUES IN
 * ANY OF THE TpS TABLES.  THOSE VALUES ARE CORRECT FOR AT LEAST ONE
 * CAPTURE, SO CHANGING THEM WILL BREAK AT LEAST SOME CAPTURES.  WE
 * WILL NOT CHECK IN PATCHES THAT CHANGE THESE VALUES.
 *
 * Instead, if a value in a TpS table is wrong, check whether captype
 * has a non-zero value; if so, perhaps we need a new TpS table for the
 * corresponding network type and captype, or perhaps the 'realtick'
 * field contains the correct ticks-per-second value.
 *
 * TpS...[] entries of 0.0 mean that no capture file for the
 * corresponding captype/timeunit values has yet been seen, or that
 * we're using the 'realtick' value.
 *
 * XXX - 05/29/07: For Ethernet captype = 0 (NDIS) and timeunit = 2:
 *  Perusal of a number of Sniffer captures
 *  (including those from Wireshark bug reports
 *  and those from the Wireshark 'menagerie')
 *  suggests that 'realtick' for this case
 *  contains the correct ticks/second to be used.
 *  So: we'll use realtick for Ethernet captype=0 and timeunit=2.
 *  (It might be that realtick should be used for Ethernet captype = 0
 *  and timeunit = 1 but I've not yet enough captures to be sure).
 *   Based upon the captures reviewed to date, realtick cannot be used for
 *   any of the other Ethernet captype/timeunit combinations for which there
 *   are non-zero values in the TpS tables.
 *
 *  In at least one capture where "realtick" doesn't correspond
 *  to the value from the appropriate TpS table, the per-packet header's
 *  "xxx" field is all zero, so it's not as if a 2.x header includes
 *  a "compatibility" time stamp corresponding to the value from the
 *  TpS table and a "real" time stamp corresponding to "realtick".
 *
 * XXX - the item corresponding to timeunit = 2 is 1193180.0, presumably
 *  because somebody found it gave the right answer for some captures, but
 *  3 times that, i.e. 3579540.0, appears to give the right answer for some
 *  other captures.
 *
 *  Some captures have realtick of 1193182, some have 3579545, and some
 *  have 1193000.  Most of those, in one set of captures somebody has,
 *  are wrong.  (Did that mean "wrong for some capture files, but not
 *  for the files in which they occurred", or "wrong for the files in
 *  which they occurred?  If it's "wrong for some capture files, but
 *  not for the files in which they occurred", perhaps those were Ethernet
 *  captures with a captype of 0 and timeunit = 2, so that we now use
 *  realtick, and perhaps that fixes the problems.)
 *
 * XXX - in at least one ATM capture, hdr.realtick is 1193180.0
 *  and hdr.timeunit is 0.  Does that capture have a captype of
 *  CAPTYPE_ATM?  If so, what should the table for ATM captures with
 *  that captype be?
 */
static const double TpS[] = { 1e6, 1193000.0, 1193182.0 };
#define NUM_NETXRAY_TIMEUNITS (sizeof TpS / sizeof TpS[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_GIGPOD.
 * 0.0 means "unknown".
 *
 * It appears that, at least for Ethernet captures, if captype is
 * ETH_CAPTYPE_GIGPOD, that indicates that it's a gigabit Ethernet
 * capture, possibly from a special whizzo gigabit pod, and also
 * indicates that the time stamps have some higher resolution than
 * in other captures, possibly thanks to a high-resolution timer
 * on the pod.
 *
 * It also appears that the time units might differ for gigabit pod
 * captures between version 002.001 and 002.002.  For 002.001,
 * the values below are correct; for 002.002, it's claimed that
 * the right value for TpS_gigpod[2] is 1250000.0, but at least one
 * 002.002 gigabit pod capture has 31250000.0 as the right value.
 * XXX: Note that the TpS_otherpod[2] value is 1250000.0; It seems
 *  reasonable to suspect that the original claim might actually
 *  have been for a capture with a captype of 'otherpod'.
 * (Based upon captures reviewed realtick does not contain the
 *   correct TpS values for the 'gigpod' captype).
 */
static const double TpS_gigpod[] = { 1e9, 0.0, 31250000.0 };
#define NUM_NETXRAY_TIMEUNITS_GIGPOD (sizeof TpS_gigpod / sizeof TpS_gigpod[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_OTHERPOD.
 *  (Based upon captures reviewed realtick does not contain the
 *   correct TpS values for the 'otherpod' captype).
 */
static const double TpS_otherpod[] = { 1e6, 0.0, 1250000.0 };
#define NUM_NETXRAY_TIMEUNITS_OTHERPOD (sizeof TpS_otherpod / sizeof TpS_otherpod[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_OTHERPOD2.
 * (Based upon captures reviewed realtick does not contain the
 *   correct TpS values for the 'otherpod2' captype).
 */
static const double TpS_otherpod2[] = { 1e6, 0.0, 0.0 };
#define NUM_NETXRAY_TIMEUNITS_OTHERPOD2 (sizeof TpS_otherpod2 / sizeof TpS_otherpod2[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_GIGPOD2.
 * (Based upon captures reviewed realtick does not contain the
 *   correct TpS values for the 'gigpod2' captype).
 */
static const double TpS_gigpod2[] = { 1e9, 0.0, 20000000.0 };
#define NUM_NETXRAY_TIMEUNITS_GIGPOD2 (sizeof TpS_gigpod2 / sizeof TpS_gigpod2[0])

/* Version number strings. */
static const char vers_1_0[] = {
	'0', '0', '1', '.', '0', '0', '0', '\0'
};

static const char vers_1_1[] = {
	'0', '0', '1', '.', '1', '0', '0', '\0'
};

static const char vers_2_000[] = {
	'0', '0', '2', '.', '0', '0', '0', '\0'
};

static const char vers_2_001[] = {
	'0', '0', '2', '.', '0', '0', '1', '\0'
};

static const char vers_2_002[] = {
	'0', '0', '2', '.', '0', '0', '2', '\0'
};

static const char vers_2_003[] = {
	'0', '0', '2', '.', '0', '0', '3', '\0'
};

/* Old NetXRay data record format - followed by frame data. */
struct old_netxrayrec_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	len;		/* packet length */
	guint8	xxx[6];		/* unknown */
};

/* NetXRay format version 1.x data record format - followed by frame data. */
struct netxrayrec_1_x_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	orig_len;	/* packet length */
	guint16	incl_len;	/* capture length */
	guint8	xxx[16];	/* unknown */
};

/*
 * NetXRay format version 2.x data record format - followed by frame data.
 *
 * The xxx fields appear to be:
 *
 *	xxx[0]: ATM traffic type and subtype in the low 3 bits of
 *	each nibble, and flags(?) in the upper bit of each nibble.
 *
 *	xxx[2], xxx[3]: for Ethernet, 802.11, ISDN LAPD, LAPB,
 *	Frame Relay, if both are 0xff, there are 4 bytes of stuff
 *	at the end of the packet data, which might be an FCS or
 *	which might be junk to discard.
 *
 *	xxx[8], xxx[9]: 2 bytes of a flag word?  If treated as
 *	a 2-byte little-endian flag word:
 *
 *		0x0001: Error of some sort, including bad CRC, although
 *		    in one ISDN capture it's set in some B2 channel
 *		    packets of unknown content (as opposed to the B1
 *		    traffic in the capture, which is PPP)
 *		0x0004: Some particular type of error?
 *		0x0008: For (Gigabit?) Ethernet (with special probe?),
 *		    4 bytes at end are junk rather than CRC?
 *		0x0100: CRC error on ATM?  Protected and Not decrypted
 *		    for 802.11?
 *		0x0200: Something for ATM? Something else for 802.11?
 *		0x0400: raw ATM cell
 *		0x0800: OAM cell?
 *		0x2000: port on which the packet was captured?
 *
 *	The Sniffer Portable 4.8 User's Guide lists a set of packet status
 *	flags including:
 *
 *		packet is marked;
 *		packet was captured from Port A on the pod or adapter card;
 *		packet was captured from Port B on the pod or adapter card;
 *		packet has a symptom or diagnosis associated with it;
 *		packet is an event filter trigger;
 *		CRC error packet with normal packet size;
 *		CRC error packet with oversize error;
 *		packet size < 64 bytes (including CRC) but with valid CRC;
 *		packet size < 64 bytes (including CRC) with CRC error;
 *		packet size > 1518 bytes (including CRC) but with valid CRC;
 *		packet damaged by a collision;
 *		packet length not a multiple of 8 bits;
 *		address conflict in the ring on Token Ring;
 *		packet is not copied (received) by the destination host on
 *		    Token Ring;
 *		AAL5 length error;
 *		AAL5 maximum segments error;
 *		ATM timeout error;
 *		ATM buffer error;
 *		ATM unknown error;
 *		and a ton of AAL2 errors.
 *
 *	Not all those bits necessarily correspond to flag bits in the file,
 *	but some might.
 *
 *	In one ATM capture, the 0x2000 bit was set for all frames; in another,
 *	it's unset for all frames.  This, plus the ATMbook having two ports,
 *	suggests that it *might* be a "port A vs. port B" flag.
 *
 *	The 0x0001 bit appears to be set for CRC errors on Ethernet and 802.11.
 *	It also appears to be set on ATM for AAL5 PDUs that appear to be
 *	completely reassembled and that have a CRC error and for frames that
 *	appear to be part of a full AAL5 PDU.  In at least two files with
 *	frames of the former type, the 0x0100 and 0x0200 flags are set;
 *	in at least one file with frames of the latter type, neither of
 *	those flags are set.
 *
 *	The field appears to be somewhat random in some captures,
 *	however.
 *
 *	xxx[11]: for 802.11, 0x05 if the packet is WEP-encrypted(?).
 *
 *	xxx[12]: for 802.11, channel number.
 *
 *	xxx[13]: for 802.11, data rate.
 *
 *	xxx[14]: for 802.11, signal strength.
 *
 *	xxx[15]: for 802.11, noise level; 0xFF means none reported,
 *	    0x7F means 100%.
 *
 *	xxx[20-25]: for 802.11, MAC address of sending machine(?).
 */
struct netxrayrec_2_x_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	orig_len;	/* packet length */
	guint16	incl_len;	/* capture length */
	guint8	xxx[28];	/* various data */
};

/*
 * Union of the data record headers.
 */
union netxrayrec_hdr {
	struct old_netxrayrec_hdr old_hdr;
	struct netxrayrec_1_x_hdr hdr_1_x;
	struct netxrayrec_2_x_hdr hdr_2_x;
};

typedef struct {
	time_t		start_time;
	double		ticks_per_sec;
	double		start_timestamp;
	gboolean	wrapped;
	guint32		nframes;
	gint64		start_offset;
	gint64		end_offset;
	int		version_major;
	gboolean	fcs_valid;	/* if packets have valid FCS at the end */
	guint		isdn_type;	/* 1 = E1 PRI, 2 = T1 PRI, 3 = BRI */
} netxray_t;

static gboolean netxray_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean netxray_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static int netxray_process_rec_header(wtap *wth, FILE_T fh,
    struct wtap_pkthdr *phdr, int *err, gchar **err_info);
static void netxray_guess_atm_type(wtap *wth, struct wtap_pkthdr *phdr,
    Buffer *buf);
static gboolean netxray_dump_1_1(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err);
static gboolean netxray_dump_close_1_1(wtap_dumper *wdh, int *err);
static gboolean netxray_dump_2_0(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err);
static gboolean netxray_dump_close_2_0(wtap_dumper *wdh, int *err);

int
netxray_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[MAGIC_SIZE];
	gboolean is_old;
	struct netxray_hdr hdr;
	guint network_type;
	double ticks_per_sec;
	int version_major, version_minor;
	int file_type;
	double start_timestamp;
	static const int netxray_encap[] = {
		WTAP_ENCAP_UNKNOWN,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TOKEN_RING,
		WTAP_ENCAP_FDDI_BITSWAPPED,
		/*
		 * XXX - some PPP captures may look like Ethernet,
		 * perhaps because they're using NDIS to capture on the
		 * same machine and it provides simulated-Ethernet
		 * packets, but captures taken with various serial
		 * pods use the same network type value but aren't
		 * shaped like Ethernet.  We handle that below.
		 */
		WTAP_ENCAP_ETHERNET,		/* WAN(PPP), but shaped like Ethernet */
		WTAP_ENCAP_UNKNOWN,		/* LocalTalk */
		WTAP_ENCAP_UNKNOWN,		/* "DIX" - should not occur */
		WTAP_ENCAP_UNKNOWN,		/* ARCNET raw */
		WTAP_ENCAP_UNKNOWN,		/* ARCNET 878.2 */
		WTAP_ENCAP_ATM_PDUS_UNTRUNCATED,/* ATM */
		WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
						/* Wireless WAN with radio information */
		WTAP_ENCAP_UNKNOWN		/* IrDA */
	};
	#define NUM_NETXRAY_ENCAPS (sizeof netxray_encap / sizeof netxray_encap[0])
	int file_encap;
	guint isdn_type = 0;
	netxray_t *netxray;

	/* Read in the string that should be at the start of a NetXRay
	 * file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, MAGIC_SIZE, wth->fh);
	if (bytes_read != MAGIC_SIZE) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return -1;
		return 0;
	}

	if (memcmp(magic, netxray_magic, MAGIC_SIZE) == 0) {
		is_old = FALSE;
	} else if (memcmp(magic, old_netxray_magic, MAGIC_SIZE) == 0) {
		is_old = TRUE;
	} else {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}

	if (is_old) {
		version_major = 0;
		version_minor = 0;
		file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_OLD;
	} else {
		/* It appears that version 1.1 files (as produced by Windows
		 * Sniffer Pro 2.0.01) have the time stamp in microseconds,
		 * rather than the milliseconds version 1.0 files appear to
		 * have.
		 *
		 * It also appears that version 2.00x files have per-packet
		 * headers with some extra fields. */
		if (memcmp(hdr.version, vers_1_0, sizeof vers_1_0) == 0) {
			version_major = 1;
			version_minor = 0;
			file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_0;
		} else if (memcmp(hdr.version, vers_1_1, sizeof vers_1_1) == 0) {
			version_major = 1;
			version_minor = 1;
			file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_1;
		} else if (memcmp(hdr.version, vers_2_000, sizeof vers_2_000) == 0) {
			version_major = 2;
			version_minor = 0;
			file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x;
		} else if (memcmp(hdr.version, vers_2_001, sizeof vers_2_001) == 0) {
			version_major = 2;
			version_minor = 1;
			file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x;
		} else if (memcmp(hdr.version, vers_2_002, sizeof vers_2_002) == 0) {
			version_major = 2;
			version_minor = 2;
			file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x;
		} else if (memcmp(hdr.version, vers_2_003, sizeof vers_2_003) == 0) {
			version_major = 2;
			version_minor = 3;
			file_type = WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x;
		} else {
			*err = WTAP_ERR_UNSUPPORTED;
			*err_info = g_strdup_printf("netxray: version \"%.8s\" unsupported", hdr.version);
			return -1;
		}
	}

	switch (hdr.network_plus) {

	case 0:
		/*
		 * The byte after hdr.network is usually 0, in which case
		 * the hdr.network byte is an NDIS network type value - 1.
		 */
		network_type = hdr.network + 1;
		break;

	case 2:
		/*
		 * However, in some Ethernet captures, it's 2, and the
		 * hdr.network byte is 1 rather than 0.  We assume
		 * that if there's a byte after hdr.network with the value
		 * 2, the hdr.network byte is an NDIS network type, rather
		 * than an NDIS network type - 1.
		 */
		network_type = hdr.network;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("netxray: the byte after the network type has the value %u, which I don't understand",
		    hdr.network_plus);
		return -1;
	}

	if (network_type >= NUM_NETXRAY_ENCAPS
	    || netxray_encap[network_type] == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("netxray: network type %u (%u) unknown or unsupported",
		    network_type, hdr.network_plus);
		return -1;
	}

	/*
	 * Figure out the time stamp units and start time stamp.
	 */
	start_timestamp = (double)pletoh32(&hdr.timelo)
	    + (double)pletoh32(&hdr.timehi)*4294967296.0;
	switch (file_type) {

	case WTAP_FILE_TYPE_SUBTYPE_NETXRAY_OLD:
		ticks_per_sec = 1000.0;
		wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_0:
		ticks_per_sec = 1000.0;
		wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_1:
		/*
		 * In version 1.1 files (as produced by Windows Sniffer
		 * Pro 2.0.01), the time stamp is in microseconds,
		 * rather than the milliseconds time stamps in NetXRay
		 * and older versions of Windows Sniffer.
		 */
		ticks_per_sec = 1000000.0;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x:
		/*
		 * Get the time stamp units from the appropriate TpS
		 * table or from the file header.
		 */
		switch (network_type) {

		case 1:
			/*
			 * Ethernet - the table to use depends on whether
			 * this is an NDIS or pod capture.
			 */
			switch (hdr.captype) {

			case CAPTYPE_NDIS:
				if (hdr.timeunit >= NUM_NETXRAY_TIMEUNITS) {
					*err = WTAP_ERR_UNSUPPORTED;
					*err_info = g_strdup_printf(
					    "netxray: Unknown timeunit %u for Ethernet/CAPTYPE_NDIS version %.8s capture",
					    hdr.timeunit, hdr.version);
					return -1;
				}
				/*
				XXX: 05/29/07: Use 'realtick' instead of TpS table if timeunit=2;
					Using 'realtick' in this case results
					in the correct 'ticks per second' for all the captures that
					I have of this type (including captures from a number of Wireshark
					bug reports).
				*/
				if (hdr.timeunit == 2) {
					ticks_per_sec = pletoh32(hdr.realtick);
				}
				else {
					ticks_per_sec = TpS[hdr.timeunit];
				}
				break;

			case ETH_CAPTYPE_GIGPOD:
				if (hdr.timeunit >= NUM_NETXRAY_TIMEUNITS_GIGPOD
				    || TpS_gigpod[hdr.timeunit] == 0.0) {
					*err = WTAP_ERR_UNSUPPORTED;
					*err_info = g_strdup_printf(
					    "netxray: Unknown timeunit %u for Ethernet/ETH_CAPTYPE_GIGPOD version %.8s capture",
					    hdr.timeunit, hdr.version);
					return -1;
				}
				ticks_per_sec = TpS_gigpod[hdr.timeunit];

				/*
				 * At least for 002.002 and 002.003
				 * captures, the start time stamp is 0,
				 * not the value in the file.
				 */
				if (version_minor == 2 || version_minor == 3)
					start_timestamp = 0.0;
				break;

			case ETH_CAPTYPE_OTHERPOD:
				if (hdr.timeunit >= NUM_NETXRAY_TIMEUNITS_OTHERPOD
				    || TpS_otherpod[hdr.timeunit] == 0.0) {
					*err = WTAP_ERR_UNSUPPORTED;
					*err_info = g_strdup_printf(
					    "netxray: Unknown timeunit %u for Ethernet/ETH_CAPTYPE_OTHERPOD version %.8s capture",
					    hdr.timeunit, hdr.version);
					return -1;
				}
				ticks_per_sec = TpS_otherpod[hdr.timeunit];

				/*
				 * At least for 002.002 and 002.003
				 * captures, the start time stamp is 0,
				 * not the value in the file.
				 */
				if (version_minor == 2 || version_minor == 3)
					start_timestamp = 0.0;
				break;

			case ETH_CAPTYPE_OTHERPOD2:
				if (hdr.timeunit >= NUM_NETXRAY_TIMEUNITS_OTHERPOD2
				    || TpS_otherpod2[hdr.timeunit] == 0.0) {
					*err = WTAP_ERR_UNSUPPORTED;
					*err_info = g_strdup_printf(
					    "netxray: Unknown timeunit %u for Ethernet/ETH_CAPTYPE_OTHERPOD2 version %.8s capture",
					    hdr.timeunit, hdr.version);
					return -1;
				}
				ticks_per_sec = TpS_otherpod2[hdr.timeunit];
				/*
				 * XXX: start time stamp in the one capture file examined of this type was 0;
				 *      We'll assume the start time handling is the same as for other pods.
				 *
				 * At least for 002.002 and 002.003
				 * captures, the start time stamp is 0,
				 * not the value in the file.
				 */
				if (version_minor == 2 || version_minor == 3)
					start_timestamp = 0.0;
				break;

			case ETH_CAPTYPE_GIGPOD2:
				if (hdr.timeunit >= NUM_NETXRAY_TIMEUNITS_GIGPOD2
				    || TpS_gigpod2[hdr.timeunit] == 0.0) {
					*err = WTAP_ERR_UNSUPPORTED;
					*err_info = g_strdup_printf(
					    "netxray: Unknown timeunit %u for Ethernet/ETH_CAPTYPE_GIGPOD2 version %.8s capture",
					    hdr.timeunit, hdr.version);
					return -1;
				}
				ticks_per_sec = TpS_gigpod2[hdr.timeunit];
				/*
				 * XXX: start time stamp in the one capture file examined of this type was 0;
				 *	We'll assume the start time handling is the same as for other pods.
				 *
				 * At least for 002.002 and 002.003
				 * captures, the start time stamp is 0,
				 * not the value in the file.
				 */
				if (version_minor == 2 || version_minor == 3)
					start_timestamp = 0.0;
				break;

			default:
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = g_strdup_printf(
				    "netxray: Unknown capture type %u for Ethernet version %.8s capture",
				    hdr.captype, hdr.version);
				return -1;
			}
			break;

		default:
			if (hdr.timeunit >= NUM_NETXRAY_TIMEUNITS) {
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = g_strdup_printf(
				    "netxray: Unknown timeunit %u for %u/%u version %.8s capture",
				    hdr.timeunit, network_type, hdr.captype,
				    hdr.version);
				return -1;
			}
			ticks_per_sec = TpS[hdr.timeunit];
			break;
		}

		/*
		 * If the number of ticks per second is greater than
		 * 1 million, make the precision be nanoseconds rather
		 * than microseconds.
		 *
		 * XXX - do values only slightly greater than one million
		 * correspond to a resolution sufficiently better than
		 * 1 microsecond to display more digits of precision?
		 * XXX - Seems reasonable to use nanosecs only if TPS >= 10M
		 */
		if (ticks_per_sec >= 1e7)
			wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		else
			wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	default:
		g_assert_not_reached();
		ticks_per_sec = 0.0;
	}
	start_timestamp = start_timestamp/ticks_per_sec;

	if (network_type == 4) {
		/*
		 * In version 0 and 1, we assume, for now, that all
		 * WAN captures have frames that look like Ethernet
		 * frames (as a result, presumably, of having passed
		 * through NDISWAN).
		 *
		 * In version 2, it looks as if there's stuff in the
		 * file header to specify what particular type of WAN
		 * capture we have.
		 */
		if (version_major == 2) {
			switch (hdr.captype) {

			case WAN_CAPTYPE_PPP:
				/*
				 * PPP.
				 */
				file_encap = WTAP_ENCAP_PPP_WITH_PHDR;
				break;

			case WAN_CAPTYPE_FRELAY:
				/*
				 * Frame Relay.
				 *
				 * XXX - in at least one capture, this
				 * is Cisco HDLC, not Frame Relay, but
				 * in another capture, it's Frame Relay.
				 *
				 * [Bytes in each capture:
				 * Cisco HDLC:  hdr.xxx_x60[06:10]: 0x02 0x00 0x01 0x00 0x06
				 * Frame Relay: hdr.xxx_x60[06:10]  0x00 0x00 0x00 0x00 0x00

				 * Cisco HDLC:  hdr.xxx_x60[14:15]: 0xff 0xff
				 * Frame Relay: hdr.xxx_x60[14:15]: 0x00 0x00
				 * ]
				 */
				file_encap = WTAP_ENCAP_FRELAY_WITH_PHDR;
				break;

			case WAN_CAPTYPE_HDLC:
			case WAN_CAPTYPE_HDLC2:
				/*
				 * Various HDLC flavors?
				 */
				switch (hdr.wan_hdlc_subsub_captype) {

				case 0:	/* LAPB/X.25 */
					/*
					 * XXX - at least one capture of
					 * this type appears to be PPP.
					 */
					file_encap = WTAP_ENCAP_LAPB;
					break;

				case 1:	/* E1 PRI */
				case 2:	/* T1 PRI */
				case 3:	/* BRI */
					file_encap = WTAP_ENCAP_ISDN;
					isdn_type = hdr.wan_hdlc_subsub_captype;
					break;

				default:
					*err = WTAP_ERR_UNSUPPORTED_ENCAP;
					*err_info = g_strdup_printf("netxray: WAN HDLC capture subsubtype 0x%02x unknown or unsupported",
					   hdr.wan_hdlc_subsub_captype);
					return -1;
				}
				break;

			case WAN_CAPTYPE_SDLC:
				/*
				 * SDLC.
				 */
				file_encap = WTAP_ENCAP_SDLC;
				break;

			case WAN_CAPTYPE_CHDLC:
				/*
				 *  Cisco router (CHDLC) captured with pod
				 */
				file_encap = WTAP_ENCAP_CHDLC_WITH_PHDR;
				break;

			default:
				*err = WTAP_ERR_UNSUPPORTED_ENCAP;
				*err_info = g_strdup_printf("netxray: WAN capture subtype 0x%02x unknown or unsupported",
				   hdr.captype);
				return -1;
			}
		} else
			file_encap = WTAP_ENCAP_ETHERNET;
	} else
		file_encap = netxray_encap[network_type];

	/* This is a netxray file */
	wth->file_type_subtype = file_type;
	netxray = (netxray_t *)g_malloc(sizeof(netxray_t));
	wth->priv = (void *)netxray;
	wth->subtype_read = netxray_read;
	wth->subtype_seek_read = netxray_seek_read;
	wth->file_encap = file_encap;
	wth->snapshot_length = 0;	/* not available in header */
	netxray->start_time = pletoh32(&hdr.start_time);
	netxray->ticks_per_sec = ticks_per_sec;
	netxray->start_timestamp = start_timestamp;
	netxray->version_major = version_major;

	/*
	 * If frames have an extra 4 bytes of stuff at the end, is
	 * it an FCS, or just junk?
	 */
	netxray->fcs_valid = FALSE;
	switch (file_encap) {

	case WTAP_ENCAP_ETHERNET:
	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	case WTAP_ENCAP_ISDN:
	case WTAP_ENCAP_LAPB:
		/*
		 * It appears that, in at least some version 2 Ethernet
		 * captures, for frames that have 0xff in hdr_2_x.xxx[2]
		 * and hdr_2_x.xxx[3] in the per-packet header:
		 *
		 *	if, in the file header, hdr.realtick[1] is 0x34
		 *	and hdr.realtick[2] is 0x12, the frames have an
		 *	FCS at the end;
		 *
		 *	otherwise, they have 4 bytes of junk at the end.
		 *
		 * Yes, it's strange that you have to check the *middle*
		 * of the time stamp field; you can't check for any
		 * particular value of the time stamp field.
		 *
		 * For now, we assume that to be true for 802.11 captures
		 * as well; it appears to be the case for at least one
		 * such capture - the file doesn't have 0x34 and 0x12,
		 * and the 4 bytes at the end of the frames with 0xff
		 * are junk, not an FCS.
		 *
		 * For ISDN captures, it appears, at least in some
		 * captures, to be similar, although I haven't yet
		 * checked whether it's a valid FCS.
		 *
		 * XXX - should we do this for all encapsulation types?
		 *
		 * XXX - is there some other field that *really* indicates
		 * whether we have an FCS or not?  The check of the time
		 * stamp is bizarre, as we're checking the middle.
		 * Perhaps hdr.realtick[0] is 0x00, in which case time
		 * stamp units in the range 1192960 through 1193215
		 * correspond to captures with an FCS, but that's still
		 * a bit bizarre.
		 *
		 * Note that there are captures with a network type of 0
		 * (Ethernet) and capture type of 0 (NDIS) that do, and
		 * that don't, have 0x34 0x12 in them, and at least one
		 * of the NDIS captures with 0x34 0x12 in it has FCSes,
		 * so it's not as if no NDIS captures have an FCS.
		 *
		 * There are also captures with a network type of 4 (WAN),
		 * capture type of 6 (HDLC), and subtype of 2 (T1 PRI) that
		 * do, and that don't, have 0x34 0x12, so there are at least
		 * some captures taken with a WAN pod that might lack an FCS.
		 * (We haven't yet tried dissecting the 4 bytes at the
		 * end of packets with hdr_2_x.xxx[2] and hdr_2_x.xxx[3]
		 * equal to 0xff as an FCS.)
		 *
		 * All captures I've seen that have 0x34 and 0x12 *and*
		 * have at least one frame with an FCS have a value of
		 * 0x01 in xxx_x40[4].  No captures I've seen with a network
		 * type of 0 (Ethernet) missing 0x34 0x12 have 0x01 there,
		 * however.  However, there's at least one capture
		 * without 0x34 and 0x12, with a network type of 0,
		 * and with 0x01 in xxx_x40[4], *without* FCSes in the
		 * frames - the 4 bytes at the end are all zero - so it's
		 * not as simple as "xxx_x40[4] = 0x01 means the 4 bytes at
		 * the end are FCSes".  Also, there's also at least one
		 * 802.11 capture with an xxx_x40[4] value of 0x01 with junk
		 * rather than an FCS at the end of the frame, so xxx_x40[4]
		 * isn't an obvious flag to determine whether the
		 * capture has FCSes.
		 *
		 * There don't seem to be any other values in any of the
		 * xxx_x5..., xxx_x6...., xxx_x7.... fields
		 * that obviously correspond to frames having an FCS.
		 *
		 * 05/29/07: Examination of numerous sniffer captures suggests
		 *            that the apparent correlation of certain realtick
		 *            bytes to 'FCS presence' may actually be
		 *            a 'false positive'.
		 *           ToDo: Review analysis and update code.
		 *           It might be that the ticks-per-second value
		 *           is hardware-dependent, and that hardware with
		 *           a particular realtick value puts an FCS there
		 *	     and other hardware doesn't.
		 */
		if (version_major == 2) {
			if (hdr.realtick[1] == 0x34 && hdr.realtick[2] == 0x12)
				netxray->fcs_valid = TRUE;
		}
		break;
	}

	/*
	 * Remember the ISDN type, as we need it to interpret the
	 * channel number in ISDN captures.
	 */
	netxray->isdn_type = isdn_type;

	/* Remember the offset after the last packet in the capture (which
	 * isn't necessarily the last packet in the file), as it appears
	 * there's sometimes crud after it.
	 * XXX: Remember 'start_offset' to help testing for 'short file' at EOF
	 */
	netxray->wrapped      = FALSE;
	netxray->nframes      = pletoh32(&hdr.nframes);
	netxray->start_offset = pletoh32(&hdr.start_offset);
	netxray->end_offset   = pletoh32(&hdr.end_offset);

	/* Seek to the beginning of the data records. */
	if (file_seek(wth->fh, netxray->start_offset, SEEK_SET, err) == -1) {
		return -1;
	}

	return 1;
}

/* Read the next packet */
static gboolean
netxray_read(wtap *wth, int *err, gchar **err_info,
	     gint64 *data_offset)
{
	netxray_t *netxray = (netxray_t *)wth->priv;
	int	padding;

reread:
	/*
	 * Return the offset of the record header, so we can reread it
	 * if we go back to this frame.
	 */
	*data_offset = file_tell(wth->fh);

	/* Have we reached the end of the packet data? */
	if (*data_offset == netxray->end_offset) {
		/* Yes. */
		*err = 0;	/* it's just an EOF, not an error */
		return FALSE;
	}

	/* Read and process record header. */
	padding = netxray_process_rec_header(wth, wth->fh, &wth->phdr, err,
	    err_info);
	if (padding < 0) {
		/*
		 * Error or EOF.
		 */
		if (*err != 0) {
			/*
			 * Error of some sort; give up.
			 */
			return FALSE;
		}

		/* We're at EOF.  Wrap?
		 * XXX: Need to handle 'short file' cases
		 *      (Distributed Sniffer seems to have a
		 *	 certain small propensity to generate 'short' files
		 *       i.e. [many] bytes are missing from the end of the file)
		 *   case 1: start_offset < end_offset
		 *           wrap will read already read packets again;
		 *           so: error with "short file"
		 *   case 2: start_offset > end_offset ("circular" file)
		 *           wrap will mean there's a gap (missing packets).
		 *	     However, I don't see a good way to identify this
		 *           case so we'll just have to allow the wrap.
		 *           (Maybe there can be an error message after all
		 *            packets are read since there'll be less packets than
		 *            specified in the file header).
		 * Note that these cases occur *only* if a 'short' eof occurs exactly
		 * at the expected beginning of a frame header record; If there is a
		 * partial frame header (or partial frame data) record, then the
		 * netxray_read... functions will detect the short record.
		 */
		if (netxray->start_offset < netxray->end_offset) {
			*err = WTAP_ERR_SHORT_READ;
			return FALSE;
		}

		if (!netxray->wrapped) {
			/* Yes.  Remember that we did. */
			netxray->wrapped = TRUE;
			if (file_seek(wth->fh, CAPTUREFILE_HEADER_SIZE,
			    SEEK_SET, err) == -1)
				return FALSE;
			goto reread;
		}

		/* We've already wrapped - don't wrap again. */
		return FALSE;
	}

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(wth->fh, wth->frame_buffer,
	    wth->phdr.caplen, err, err_info))
		return FALSE;

	/*
	 * If there's extra stuff at the end of the record, skip it.
	 */
	if (file_seek(wth->fh, padding, SEEK_CUR, err) == -1)
		return FALSE;

	/*
	 * If it's an ATM packet, and we don't have enough information
	 * from the packet header to determine its type or subtype,
	 * attempt to guess them from the packet data.
	 */
	netxray_guess_atm_type(wth, &wth->phdr, wth->frame_buffer);
	return TRUE;
}

static gboolean
netxray_seek_read(wtap *wth, gint64 seek_off,
		  struct wtap_pkthdr *phdr, Buffer *buf,
		  int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (netxray_process_rec_header(wth, wth->random_fh, phdr, err,
	    err_info) == -1) {
		if (*err == 0) {
			/*
			 * EOF - we report that as a short read, as
			 * we've read this once and know that it
			 * should be there.
			 */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(wth->random_fh, buf, phdr->caplen, err,
	    err_info))
		return FALSE;

	/*
	 * If it's an ATM packet, and we don't have enough information
	 * from the packet header to determine its type or subtype,
	 * attempt to guess them from the packet data.
	 */
	netxray_guess_atm_type(wth, phdr, buf);
	return TRUE;
}

static int
netxray_process_rec_header(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
			int *err, gchar **err_info)
{
	netxray_t *netxray = (netxray_t *)wth->priv;
	union netxrayrec_hdr hdr;
	int	bytes_read;
	int	hdr_size = 0;
	double	t;
	int	packet_size;
	int	padding = 0;

	/* Read record header. */
	switch (netxray->version_major) {

	case 0:
		hdr_size = sizeof (struct old_netxrayrec_hdr);
		break;

	case 1:
		hdr_size = sizeof (struct netxrayrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netxrayrec_2_x_hdr);
		break;
	}
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read((void *)&hdr, hdr_size, fh);
	if (bytes_read != hdr_size) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}

		/*
		 * We're at EOF.  "*err" is 0; we return -1 - that
		 * combination tells our caller we're at EOF.
		 */
		return -1;
	}

	/*
	 * If this is Ethernet, 802.11, ISDN, X.25, or ATM, set the
	 * pseudo-header.
	 */
	switch (netxray->version_major) {

	case 1:
		switch (wth->file_encap) {

		case WTAP_ENCAP_ETHERNET:
			/*
			 * XXX - if hdr_1_x.xxx[15] is 1
			 * the frame appears not to have any extra
			 * stuff at the end, but if it's 0,
			 * there appears to be 4 bytes of stuff
			 * at the end, but it's not an FCS.
			 *
			 * Or is that just the low-order bit?
			 *
			 * For now, we just say "no FCS".
			 */
			phdr->pseudo_header.eth.fcs_len = 0;
			break;
		}
		break;

	case 2:
		switch (wth->file_encap) {

		case WTAP_ENCAP_ETHERNET:
			/*
			 * It appears, at least with version 2 captures,
			 * that we have 4 bytes of stuff (which might be
			 * a valid FCS or might be junk) at the end of
			 * the packet if hdr_2_x.xxx[2] and
			 * hdr_2_x.xxx[3] are 0xff, and we don't if
			 * they don't.
			 *
			 * It also appears that if the low-order bit of
			 * hdr_2_x.xxx[8] is set, the packet has a
			 * bad FCS.
			 */
			if (hdr.hdr_2_x.xxx[2] == 0xff &&
			    hdr.hdr_2_x.xxx[3] == 0xff) {
				/*
				 * We have 4 bytes of stuff at the
				 * end of the frame - FCS, or junk?
				 */
			    	if (netxray->fcs_valid) {
					/*
					 * FCS.
					 */
					phdr->pseudo_header.eth.fcs_len = 4;
				} else {
					/*
					 * Junk.
					 */
					padding = 4;
				}
			} else
				phdr->pseudo_header.eth.fcs_len = 0;
			break;

		case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
			/*
			 * It appears, in one 802.11 capture, that
			 * we have 4 bytes of junk at the ends of
			 * frames in which hdr_2_x.xxx[2] and
			 * hdr_2_x.xxx[3] are 0xff; I haven't
			 * seen any frames where it's an FCS, but,
			 * for now, we still check the fcs_valid
			 * flag - I also haven't seen any capture
			 * where we'd set it based on the realtick
			 * value.
			 *
			 * It also appears that if the low-order bit of
			 * hdr_2_x.xxx[8] is set, the packet has a
			 * bad FCS.  According to Ken Mann, the 0x4 bit
			 * is sometimes also set for errors.
			 *
			 * Ken also says that xxx[11] is 0x5 when the
			 * packet is WEP-encrypted.
			 */
			if (hdr.hdr_2_x.xxx[2] == 0xff &&
			    hdr.hdr_2_x.xxx[3] == 0xff) {
				/*
				 * We have 4 bytes of stuff at the
				 * end of the frame - FCS, or junk?
				 */
			    	if (netxray->fcs_valid) {
					/*
					 * FCS.
					 */
					phdr->pseudo_header.ieee_802_11.fcs_len = 4;
				} else {
					/*
					 * Junk.
					 */
					padding = 4;
				}
			} else
				phdr->pseudo_header.ieee_802_11.fcs_len = 0;

			phdr->pseudo_header.ieee_802_11.decrypted = FALSE;

			phdr->pseudo_header.ieee_802_11.channel =
			    hdr.hdr_2_x.xxx[12];
			phdr->pseudo_header.ieee_802_11.data_rate =
			    hdr.hdr_2_x.xxx[13];
			phdr->pseudo_header.ieee_802_11.signal_level =
			    hdr.hdr_2_x.xxx[14];
			/*
			 * According to Ken Mann, at least in the captures
			 * he's seen, xxx[15] is the noise level, which
			 * is either 0xFF meaning "none reported" or a value
			 * from 0x00 to 0x7F for 0 to 100%.
			 */
			break;

		case WTAP_ENCAP_ISDN:
			/*
			 * ISDN.
			 *
			 * The bottommost bit of byte 12 of hdr_2_x.xxx
			 * is the direction flag.
			 *
			 * The bottom 5 bits of byte 13 of hdr_2_x.xxx
			 * are the channel number, but some mapping is
			 * required for PRI.  (Is it really just the time
			 * slot?)
			 */
			phdr->pseudo_header.isdn.uton =
			    (hdr.hdr_2_x.xxx[12] & 0x01);
			phdr->pseudo_header.isdn.channel =
			    hdr.hdr_2_x.xxx[13] & 0x1F;
			switch (netxray->isdn_type) {

			case 1:
				/*
				 * E1 PRI.  Channel numbers 0 and 16
				 * are the D channel; channel numbers 1
				 * through 15 are B1 through B15; channel
				 * numbers 17 through 31 are B16 through
				 * B31.
				 */
				if (phdr->pseudo_header.isdn.channel == 16)
					phdr->pseudo_header.isdn.channel = 0;
				else if (phdr->pseudo_header.isdn.channel > 16)
					phdr->pseudo_header.isdn.channel -= 1;
				break;

			case 2:
				/*
				 * T1 PRI.  Channel numbers 0 and 24
				 * are the D channel; channel numbers 1
				 * through 23 are B1 through B23.
				 */
				if (phdr->pseudo_header.isdn.channel == 24)
					phdr->pseudo_header.isdn.channel = 0;
				else if (phdr->pseudo_header.isdn.channel > 24)
					phdr->pseudo_header.isdn.channel -= 1;
				break;
			}

			/*
			 * It appears, at least with version 2 captures,
			 * that we have 4 bytes of stuff (which might be
			 * a valid FCS or might be junk) at the end of
			 * the packet if hdr_2_x.xxx[2] and
			 * hdr_2_x.xxx[3] are 0xff, and we don't if
			 * they don't.
			 *
			 * XXX - does the low-order bit of hdr_2_x.xxx[8]
			 * indicate a bad FCS, as is the case with
			 * Ethernet?
			 */
			if (hdr.hdr_2_x.xxx[2] == 0xff &&
			    hdr.hdr_2_x.xxx[3] == 0xff) {
				/*
				 * FCS, or junk, at the end.
				 * XXX - is it an FCS if "fcs_valid" is
				 * true?
				 */
				padding = 4;
			}
			break;

		case WTAP_ENCAP_LAPB:
		case WTAP_ENCAP_FRELAY_WITH_PHDR:
			/*
			 * LAPB/X.25 and Frame Relay.
			 *
			 * The bottommost bit of byte 12 of hdr_2_x.xxx
			 * is the direction flag.  (Probably true for other
			 * HDLC encapsulations as well.)
			 */
			phdr->pseudo_header.x25.flags =
			    (hdr.hdr_2_x.xxx[12] & 0x01) ? 0x00 : FROM_DCE;

			/*
			 * It appears, at least with version 2 captures,
			 * that we have 4 bytes of stuff (which might be
			 * a valid FCS or might be junk) at the end of
			 * the packet if hdr_2_x.xxx[2] and
			 * hdr_2_x.xxx[3] are 0xff, and we don't if
			 * they don't.
			 *
			 * XXX - does the low-order bit of hdr_2_x.xxx[8]
			 * indicate a bad FCS, as is the case with
			 * Ethernet?
			 */
			if (hdr.hdr_2_x.xxx[2] == 0xff &&
			    hdr.hdr_2_x.xxx[3] == 0xff) {
				/*
				 * FCS, or junk, at the end.
				 * XXX - is it an FCS if "fcs_valid" is
				 * true?
				 */
				padding = 4;
			}
			break;

		case WTAP_ENCAP_PPP_WITH_PHDR:
		case WTAP_ENCAP_SDLC:
		case WTAP_ENCAP_CHDLC_WITH_PHDR:
			phdr->pseudo_header.p2p.sent =
			    (hdr.hdr_2_x.xxx[12] & 0x01) ? TRUE : FALSE;
			break;

		case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
			/*
			 * XXX - the low-order bit of hdr_2_x.xxx[8]
			 * seems to indicate some sort of error.  In
			 * at least one capture, a number of packets
			 * have that flag set, and they appear either
			 * to be the beginning part of an incompletely
			 * reassembled AAL5 PDU, with either checksum
			 * errors at higher levels (possibly due to
			 * the packet being reported as shorter than
			 * it actually is, and checksumming failing
			 * because it doesn't include all the data)
			 * or "Malformed frame" errors from being
			 * too short, or appear to be later parts
			 * of an incompletely reassembled AAL5 PDU
			 * with the last one in a sequence of errors
			 * having what looks like an AAL5 trailer,
			 * with a length and checksum.
			 *
			 * Does it just mean "reassembly failed",
			 * as appears to be the case in those
			 * packets, or does it mean "CRC error"
			 * at the AAL5 layer (which would be the
			 * case if you were treating an incompletely
			 * reassembled PDU as a completely reassembled
			 * PDU, although you'd also expect a length
			 * error in that case), or does it mean
			 * "generic error", with some other flag
			 * or flags indicating what particular
			 * error occurred?  The documentation
			 * for Sniffer Pro 4.7 indicates a bunch
			 * of different error types, both in general
			 * and for ATM in particular.
			 *
			 * No obvious bits in hdr_2_x.xxx appear
			 * to be additional flags of that sort.
			 *
			 * XXX - in that capture, I see several
			 * reassembly errors in a row; should those
			 * packets be reassembled in the ATM dissector?
			 * What happens if a reassembly fails because
			 * a cell is bad?
			 */
			phdr->pseudo_header.atm.flags = 0;
			if (hdr.hdr_2_x.xxx[8] & 0x01)
				phdr->pseudo_header.atm.flags |= ATM_REASSEMBLY_ERROR;
			/*
			 * XXX - is 0x08 an "OAM cell" flag?
			 * Are the 0x01 and 0x02 bits error indications?
			 * Some packets in one capture that have the
			 * 0x01 bit set in hdr_2_x.xxx[8] and that
			 * appear to have been reassembled completely
			 * but have a bad CRC have 0x03 in hdr_2_x.xxx[9]
			 * (and don't have the 0x20 bit set).
			 *
			 * In the capture with incomplete reassemblies,
			 * all packets have the 0x20 bit set.  In at
			 * least some of the captures with complete
			 * reassemblies with CRC errors, no packets
			 * have the 0x20 bit set.
			 *
			 * Are hdr_2_x.xxx[8] and hdr_2_x.xxx[9] a 16-bit
			 * flag field?
			 */
			if (hdr.hdr_2_x.xxx[9] & 0x04)
				phdr->pseudo_header.atm.flags |= ATM_RAW_CELL;
			phdr->pseudo_header.atm.vpi = hdr.hdr_2_x.xxx[11];
			phdr->pseudo_header.atm.vci = pletoh16(&hdr.hdr_2_x.xxx[12]);
			phdr->pseudo_header.atm.channel =
			    (hdr.hdr_2_x.xxx[15] & 0x10)? 1 : 0;
			phdr->pseudo_header.atm.cells = 0;

			/*
			 * XXX - the uppermost bit of hdr_2_xxx[0]
			 * looks as if it might be a flag of some sort.
			 * The remaining 3 bits appear to be an AAL
			 * type - 5 is, surprise surprise, AAL5.
			 */
			switch (hdr.hdr_2_x.xxx[0] & 0x70) {

			case 0x00:	/* Unknown */
				phdr->pseudo_header.atm.aal = AAL_UNKNOWN;
				phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
				phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case 0x10:	/* XXX - AAL1? */
				phdr->pseudo_header.atm.aal = AAL_UNKNOWN;
				phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
				phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case 0x20:	/* XXX - AAL2?  */
				phdr->pseudo_header.atm.aal = AAL_UNKNOWN;
				phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
				phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case 0x40:	/* XXX - AAL3/4? */
				phdr->pseudo_header.atm.aal = AAL_UNKNOWN;
				phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
				phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case 0x30:	/* XXX - AAL5 cells seen with this */
			case 0x50:	/* AAL5 (including signalling) */
			case 0x60:	/* XXX - AAL5 cells seen with this */
			case 0x70:	/* XXX - AAL5 cells seen with this */
				phdr->pseudo_header.atm.aal = AAL_5;
				/*
				 * XXX - is the 0x08 bit of hdr_2_x.xxx[0]
				 * a flag?  I've not yet seen a case where
				 * it matters.
				 */
				switch (hdr.hdr_2_x.xxx[0] & 0x07) {

				case 0x01:
				case 0x02:	/* Signalling traffic */
					phdr->pseudo_header.atm.aal = AAL_SIGNALLING;
					phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
					phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
					break;

				case 0x03:	/* ILMI */
					phdr->pseudo_header.atm.type = TRAF_ILMI;
					phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
					break;

				case 0x00:
				case 0x04:
				case 0x05:
					/*
					 * I've seen a frame with type
					 * 0x30 and subtype 0x08 that
					 * was LANE 802.3, a frame
					 * with type 0x30 and subtype
					 * 0x04 that was LANE 802.3,
					 * and another frame with type
					 * 0x30 and subtype 0x08 that
					 * was junk with a string in
					 * it that had also appeared
					 * in some CDP and LE Control
					 * frames, and that was preceded
					 * by a malformed LE Control
					 * frame - was that a reassembly
					 * failure?
					 *
					 * I've seen frames with type
					 * 0x50 and subtype 0x0c, some
					 * of which were LE Control
					 * frames, and at least one
					 * of which was neither an LE
					 * Control frame nor a LANE
					 * 802.3 frame, and contained
					 * the string "ForeThought_6.2.1
					 * Alpha" - does that imply
					 * FORE's own encapsulation,
					 * or was this a reassembly failure?
					 * The latter frame was preceded
					 * by a malformed LE Control
					 * frame.
					 *
					 * I've seen a couple of frames
					 * with type 0x60 and subtype 0x00,
					 * one of which was LANE 802.3 and
					 * one of which was LE Control.
					 * I've seen one frame with type
					 * 0x60 and subtype 0x0c, which
					 * was LANE 802.3.
					 *
					 * I've seen a couple of frames
					 * with type 0x70 and subtype 0x00,
					 * both of which were LANE 802.3.
					 */
					phdr->pseudo_header.atm.type = TRAF_LANE;
					phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
					break;

				case 0x06:	/* XXX - not seen yet */
					phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
					phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;
					break;

				case 0x07:	/* LLC multiplexed */
					phdr->pseudo_header.atm.type = TRAF_LLCMX;	/* XXX */
					phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;	/* XXX */
					break;
				}
				break;
			}
			break;
		}
		break;
	}

	phdr->rec_type = REC_TYPE_PACKET;
	if (netxray->version_major == 0) {
		phdr->presence_flags = WTAP_HAS_TS;
		t = (double)pletoh32(&hdr.old_hdr.timelo)
		    + (double)pletoh32(&hdr.old_hdr.timehi)*4294967296.0;
		t /= netxray->ticks_per_sec;
		t -= netxray->start_timestamp;
		phdr->ts.secs = netxray->start_time + (long)t;
		phdr->ts.nsecs = (int)((t-(double)(unsigned long)(t))
			*1.0e9);
		/*
		 * We subtract the padding from the packet size, so our caller
		 * doesn't see it.
		 */
		packet_size = pletoh16(&hdr.old_hdr.len);
		phdr->caplen = packet_size - padding;
		phdr->len = phdr->caplen;
	} else {
		phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
		t = (double)pletoh32(&hdr.hdr_1_x.timelo)
		    + (double)pletoh32(&hdr.hdr_1_x.timehi)*4294967296.0;
		t /= netxray->ticks_per_sec;
		t -= netxray->start_timestamp;
		phdr->ts.secs = netxray->start_time + (time_t)t;
		phdr->ts.nsecs = (int)((t-(double)(unsigned long)(t))
			*1.0e9);
		/*
		 * We subtract the padding from the packet size, so our caller
		 * doesn't see it.
		 */
		packet_size = pletoh16(&hdr.hdr_1_x.incl_len);
		phdr->caplen = packet_size - padding;
		phdr->len = pletoh16(&hdr.hdr_1_x.orig_len) - padding;
	}

	return padding;
}

static void
netxray_guess_atm_type(wtap *wth, struct wtap_pkthdr *phdr, Buffer *buf)
{
	const guint8 *pd;

	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS_UNTRUNCATED &&
	   !(phdr->pseudo_header.atm.flags & ATM_REASSEMBLY_ERROR)) {
		if (phdr->pseudo_header.atm.aal == AAL_UNKNOWN) {
			/*
			 * Try to guess the type and subtype based
			 * on the VPI/VCI and packet contents.
			 */
			pd = buffer_start_ptr(buf);
			atm_guess_traffic_type(phdr, pd);
		} else if (phdr->pseudo_header.atm.aal == AAL_5 &&
		    phdr->pseudo_header.atm.type == TRAF_LANE) {
			/*
			 * Try to guess the subtype based on the
			 * packet contents.
			 */
			pd = buffer_start_ptr(buf);
			atm_guess_lane_type(phdr, pd);
		}
	}
}

typedef struct {
	gboolean first_frame;
	nstime_t start;
	guint32	nframes;
} netxray_dump_t;

static const struct {
	int	wtap_encap_value;
	int	ndis_value;
} wtap_encap_1_1[] = {
	{ WTAP_ENCAP_ETHERNET, 0 },		/* -> NDIS Ethernet */
	{ WTAP_ENCAP_TOKEN_RING, 1 },		/* -> NDIS Token Ring */
	{ WTAP_ENCAP_FDDI, 2 },			/* -> NDIS FDDI */
	{ WTAP_ENCAP_FDDI_BITSWAPPED, 2 },	/* -> NDIS FDDI */
};
#define NUM_WTAP_ENCAPS_1_1 (sizeof wtap_encap_1_1 / sizeof wtap_encap_1_1[0])

static int
wtap_encap_to_netxray_1_1_encap(int encap)
{
	unsigned int i;

	for (i = 0; i < NUM_WTAP_ENCAPS_1_1; i++) {
		if (encap == wtap_encap_1_1[i].wtap_encap_value)
			return wtap_encap_1_1[i].ndis_value;
	}

	return -1;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int
netxray_dump_can_write_encap_1_1(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (wtap_encap_to_netxray_1_1_encap(encap) == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean
netxray_dump_open_1_1(wtap_dumper *wdh, int *err)
{
	netxray_dump_t *netxray;

	wdh->subtype_write = netxray_dump_1_1;
	wdh->subtype_close = netxray_dump_close_1_1;

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	if (wtap_dump_file_seek(wdh, CAPTUREFILE_HEADER_SIZE, SEEK_SET, err) == -1)
		return FALSE;
	wdh->bytes_dumped += CAPTUREFILE_HEADER_SIZE;

	netxray = (netxray_dump_t *)g_malloc(sizeof(netxray_dump_t));
	wdh->priv = (void *)netxray;
	netxray->first_frame = TRUE;
	netxray->start.secs = 0;
	netxray->start.nsecs = 0;
	netxray->nframes = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
netxray_dump_1_1(wtap_dumper *wdh,
		 const struct wtap_pkthdr *phdr,
		 const guint8 *pd, int *err)
{
	netxray_dump_t *netxray = (netxray_dump_t *)wdh->priv;
	guint64 timestamp;
	guint32 t32;
	struct netxrayrec_1_x_hdr rec_hdr;

	/* We can only write packet records. */
	if (phdr->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
		return FALSE;
	}

	/* The captured length field is 16 bits, so there's a hard
	   limit of 65535. */
	if (phdr->caplen > 65535) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return FALSE;
	}

	/* NetXRay/Windows Sniffer files have a capture start date/time
	   in the header, in a UNIX-style format, with one-second resolution,
	   and a start time stamp with microsecond resolution that's just
	   an arbitrary time stamp relative to some unknown time (boot
	   time?), and have times relative to the start time stamp in
	   the packet headers; pick the seconds value of the time stamp
	   of the first packet as the UNIX-style start date/time, and make
	   the high-resolution start time stamp 0, with the time stamp of
	   packets being the delta between the stamp of the packet and
	   the stamp of the first packet with the microseconds part 0. */
	if (netxray->first_frame) {
		netxray->first_frame = FALSE;
		netxray->start = phdr->ts;
	}

	/* build the header for each packet */
	memset(&rec_hdr, '\0', sizeof(rec_hdr));
	timestamp = ((guint64)phdr->ts.secs - (guint64)netxray->start.secs)*1000000
		+ ((guint64)phdr->ts.nsecs)/1000;
	t32 = (guint32)(timestamp%G_GINT64_CONSTANT(4294967296));
	rec_hdr.timelo = GUINT32_TO_LE(t32);
	t32 = (guint32)(timestamp/G_GINT64_CONSTANT(4294967296));
	rec_hdr.timehi = GUINT32_TO_LE(t32);
	rec_hdr.orig_len = GUINT16_TO_LE(phdr->len);
	rec_hdr.incl_len = GUINT16_TO_LE(phdr->caplen);

	if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof(rec_hdr), err))
		return FALSE;
	wdh->bytes_dumped += sizeof(rec_hdr);

	/* write the packet data */
	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
	wdh->bytes_dumped += phdr->caplen;

	netxray->nframes++;

	return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
netxray_dump_close_1_1(wtap_dumper *wdh, int *err)
{
	char hdr_buf[CAPTUREFILE_HEADER_SIZE - sizeof(netxray_magic)];
	netxray_dump_t *netxray = (netxray_dump_t *)wdh->priv;
	gint64 filelen;
	struct netxray_hdr file_hdr;

	if (-1 == (filelen = wtap_dump_file_tell(wdh, err)))
		return FALSE;

	/* Go back to beginning */
	if (wtap_dump_file_seek(wdh, 0, SEEK_SET, err) == -1)
		return FALSE;

	/* Rewrite the file header. */
	if (!wtap_dump_file_write(wdh, netxray_magic, sizeof netxray_magic, err))
		return FALSE;

	/* "sniffer" version ? */
	memset(&file_hdr, '\0', sizeof file_hdr);
	memcpy(file_hdr.version, vers_1_1, sizeof vers_1_1);
	file_hdr.start_time = GUINT32_TO_LE(netxray->start.secs);
	file_hdr.nframes = GUINT32_TO_LE(netxray->nframes);
	file_hdr.start_offset = GUINT32_TO_LE(CAPTUREFILE_HEADER_SIZE);
	/* XXX - large files? */
	file_hdr.end_offset = GUINT32_TO_LE((guint32)filelen);
	file_hdr.network = wtap_encap_to_netxray_1_1_encap(wdh->encap);
	file_hdr.timelo = GUINT32_TO_LE(0);
	file_hdr.timehi = GUINT32_TO_LE(0);

	memset(hdr_buf, '\0', sizeof hdr_buf);
	memcpy(hdr_buf, &file_hdr, sizeof(file_hdr));
	if (!wtap_dump_file_write(wdh, hdr_buf, sizeof hdr_buf, err))
		return FALSE;

	return TRUE;
}

static const struct {
	int	wtap_encap_value;
	int	ndis_value;
} wtap_encap_2_0[] = {
	{ WTAP_ENCAP_ETHERNET, 0 },			/* -> NDIS Ethernet */
	{ WTAP_ENCAP_TOKEN_RING, 1 },		/* -> NDIS Token Ring */
	{ WTAP_ENCAP_FDDI, 2 },			/* -> NDIS FDDI */
	{ WTAP_ENCAP_FDDI_BITSWAPPED, 2 },		/* -> NDIS FDDI */
	{ WTAP_ENCAP_PPP_WITH_PHDR, 3 },		/* -> NDIS WAN */
	{ WTAP_ENCAP_FRELAY_WITH_PHDR, 3 },		/* -> NDIS WAN */
	{ WTAP_ENCAP_LAPB, 3 },			/* -> NDIS WAN */
	{ WTAP_ENCAP_SDLC, 3 },			/* -> NDIS WAN */
};
#define NUM_WTAP_ENCAPS_2_0 (sizeof wtap_encap_2_0 / sizeof wtap_encap_2_0[0])

static int
wtap_encap_to_netxray_2_0_encap(int encap)
{
	unsigned int i;

	for (i = 0; i < NUM_WTAP_ENCAPS_2_0; i++) {
		if (encap == wtap_encap_2_0[i].wtap_encap_value)
			return wtap_encap_2_0[i].ndis_value;
	}

	return -1;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int
netxray_dump_can_write_encap_2_0(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (wtap_encap_to_netxray_2_0_encap(encap) == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean
netxray_dump_open_2_0(wtap_dumper *wdh, int *err)
{
	netxray_dump_t *netxray;

	wdh->subtype_write = netxray_dump_2_0;
	wdh->subtype_close = netxray_dump_close_2_0;

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	if (wtap_dump_file_seek(wdh, CAPTUREFILE_HEADER_SIZE, SEEK_SET, err) == -1)
		return FALSE;

	wdh->bytes_dumped += CAPTUREFILE_HEADER_SIZE;

	netxray = (netxray_dump_t *)g_malloc(sizeof(netxray_dump_t));
	wdh->priv = (void *)netxray;
	netxray->first_frame = TRUE;
	netxray->start.secs = 0;
	netxray->start.nsecs = 0;
	netxray->nframes = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
netxray_dump_2_0(wtap_dumper *wdh,
		 const struct wtap_pkthdr *phdr,
		 const guint8 *pd, int *err)
{
	const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	netxray_dump_t *netxray = (netxray_dump_t *)wdh->priv;
	guint64 timestamp;
	guint32 t32;
	struct netxrayrec_2_x_hdr rec_hdr;

	/* We can only write packet records. */
	if (phdr->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
		return FALSE;
	}

	/* Don't write anything we're not willing to read. */
	if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return FALSE;
	}

	/* NetXRay/Windows Sniffer files have a capture start date/time
	   in the header, in a UNIX-style format, with one-second resolution,
	   and a start time stamp with microsecond resolution that's just
	   an arbitrary time stamp relative to some unknown time (boot
	   time?), and have times relative to the start time stamp in
	   the packet headers; pick the seconds value of the time stamp
	   of the first packet as the UNIX-style start date/time, and make
	   the high-resolution start time stamp 0, with the time stamp of
	   packets being the delta between the stamp of the packet and
	   the stamp of the first packet with the microseconds part 0. */
	if (netxray->first_frame) {
		netxray->first_frame = FALSE;
		netxray->start = phdr->ts;
	}

	/* build the header for each packet */
	memset(&rec_hdr, '\0', sizeof(rec_hdr));
	timestamp = ((guint64)phdr->ts.secs - (guint64)netxray->start.secs)*1000000
		+ ((guint64)phdr->ts.nsecs)/1000;
	t32 = (guint32)(timestamp%G_GINT64_CONSTANT(4294967296));
	rec_hdr.timelo = GUINT32_TO_LE(t32);
	t32 = (guint32)(timestamp/G_GINT64_CONSTANT(4294967296));
	rec_hdr.timehi = GUINT32_TO_LE(t32);
	rec_hdr.orig_len = GUINT16_TO_LE(phdr->len);
	rec_hdr.incl_len = GUINT16_TO_LE(phdr->caplen);

	switch (phdr->pkt_encap) {

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
		rec_hdr.xxx[12] = pseudo_header->ieee_802_11.channel;
		rec_hdr.xxx[13] = (guint8)pseudo_header->ieee_802_11.data_rate;
		rec_hdr.xxx[14] = pseudo_header->ieee_802_11.signal_level;
		break;

	case WTAP_ENCAP_PPP_WITH_PHDR:
	case WTAP_ENCAP_SDLC:
		rec_hdr.xxx[12] |= pseudo_header->p2p.sent ? 0x01 : 0x00;
		break;

	case WTAP_ENCAP_FRELAY_WITH_PHDR:
		rec_hdr.xxx[12] |= (pseudo_header->x25.flags & FROM_DCE) ? 0x00 : 0x01;
		break;
	}

	if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof(rec_hdr), err))
		return FALSE;
	wdh->bytes_dumped += sizeof(rec_hdr);

	/* write the packet data */
	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
	wdh->bytes_dumped += phdr->caplen;

	netxray->nframes++;

	return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
netxray_dump_close_2_0(wtap_dumper *wdh, int *err)
{
	char hdr_buf[CAPTUREFILE_HEADER_SIZE - sizeof(netxray_magic)];
	netxray_dump_t *netxray = (netxray_dump_t *)wdh->priv;
	gint64 filelen;
	struct netxray_hdr file_hdr;

	if (-1 == (filelen = wtap_dump_file_tell(wdh, err)))
		return FALSE;

	/* Go back to beginning */
	if (wtap_dump_file_seek(wdh, 0, SEEK_SET, err) == -1)
		return FALSE;

	/* Rewrite the file header. */
	if (!wtap_dump_file_write(wdh, netxray_magic, sizeof netxray_magic, err))
		return FALSE;

	/* "sniffer" version ? */
	memset(&file_hdr, '\0', sizeof file_hdr);
	memcpy(file_hdr.version, vers_2_001, sizeof vers_2_001);
	file_hdr.start_time = GUINT32_TO_LE(netxray->start.secs);
	file_hdr.nframes = GUINT32_TO_LE(netxray->nframes);
	file_hdr.start_offset = GUINT32_TO_LE(CAPTUREFILE_HEADER_SIZE);
	/* XXX - large files? */
	file_hdr.end_offset = GUINT32_TO_LE((guint32)filelen);
	file_hdr.network = wtap_encap_to_netxray_2_0_encap(wdh->encap);
	file_hdr.timelo = GUINT32_TO_LE(0);
	file_hdr.timehi = GUINT32_TO_LE(0);
	switch (wdh->encap) {

	case WTAP_ENCAP_PPP_WITH_PHDR:
		file_hdr.captype = WAN_CAPTYPE_PPP;
		break;

	case WTAP_ENCAP_FRELAY_WITH_PHDR:
		file_hdr.captype = WAN_CAPTYPE_FRELAY;
		break;

	case WTAP_ENCAP_LAPB:
		file_hdr.captype = WAN_CAPTYPE_HDLC;
		file_hdr.wan_hdlc_subsub_captype = 0;
		break;

	case WTAP_ENCAP_SDLC:
		file_hdr.captype = WAN_CAPTYPE_SDLC;
		break;

	default:
		file_hdr.captype = CAPTYPE_NDIS;
		break;
	}

	memset(hdr_buf, '\0', sizeof hdr_buf);
	memcpy(hdr_buf, &file_hdr, sizeof(file_hdr));
	if (!wtap_dump_file_write(wdh, hdr_buf, sizeof hdr_buf, err))
		return FALSE;

	return TRUE;
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
