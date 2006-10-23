/* netxray.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "netxray.h"
#include "buffer.h"
#include "atm.h"

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number in NetXRay 1.x files. */
static const char old_netxray_magic[] = {
	'V', 'L', '\0', '\0'
};

/* Magic number in NetXRay 2.0 and later, and Windows Sniffer, files. */
static const char netxray_magic[] = {	/* magic header */
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
	guint8	realtick[4];	/* in v2, means ???                     	*/

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
 * XXX - S6040-model Sniffers with gigabit blades store 6 here for
 * Ethernet captures, and some other Ethernet captures had a capture
 * type of 3, so presumably the interpretation of the capture type
 * depends on the network type.  We prefix all the capture types
 * for WAN captures with WAN_.
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
#define ETH_CAPTYPE_GIGPOD2	6	/* gigabit Ethernet captured with pod */

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
 * corresponding network type and captype.
 *
 * TpS...[] entries of 0.0 mean that no capture file for the
 * corresponding captype/timeunit values has yet been seen
 *
 * Note that the "realtick" value is wrong in many captures, so
 * we no longer use it.  We don't know what significance it has.
 * In at least one capture where "realtick" doesn't correspond
 * to the value from the appropriate TpS table, the per-packet header's
 * "xxx" field is all zero, so it's not as if a 2.x header includes
 * a "compatibility" time stamp corresponding to the value from the
 * TpS table and a "real" time stamp corresponding to "realtick".
 *
 * XXX - the third item is 1193180.0, presumably because somebody found
 * it gave the right answer for some captures, but 3 times that, i.e.
 * 3579540.0, appears to give the right answer for some other captures.
 * Some captures have realtick of 1193182, some have 3579545, and some
 * have 1193000.  Most of those, in one set of captures somebody has,
 * are wrong.
 *
 * XXX - in at least one ATM capture, hdr.realtick is 1193180.0
 * and hdr.timeunit is 0.  Does that capture have a captype of
 * CAPTYPE_ATM?  If so, what should the table for ATM captures with
 * that captype be?
 */
static double TpS[] = { 1e6, 1193000.0, 1193182.0 };
#define NUM_NETXRAY_TIMEUNITS (sizeof TpS / sizeof TpS[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_GIGPOD.
 * 0.0 means "unknown.
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
 */
static double TpS_gigpod[] = { 1e9, 0.0, 31250000.0 };
#define NUM_NETXRAY_TIMEUNITS_GIGPOD (sizeof TpS_gigpod / sizeof TpS_gigpod[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_OTHERPOD.
 */
static double TpS_otherpod[] = { 1e6, 0.0, 1250000.0 }; 
#define NUM_NETXRAY_TIMEUNITS_OTHERPOD (sizeof TpS_otherpod / sizeof TpS_otherpod[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_OTHERPOD2.
 */
static double TpS_otherpod2[] = { 1e6, 0.0, 0.0 }; 
#define NUM_NETXRAY_TIMEUNITS_OTHERPOD2 (sizeof TpS_otherpod2 / sizeof TpS_otherpod2[0])

/*
 * Table of time units for Ethernet captures with captype ETH_CAPTYPE_GIGPOD2. 
 */
static double TpS_gigpod2[] = { 1e9, 0.0, 20000000.0 };
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

/* NetXRay format version 2.x data record format - followed by frame data. */
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

static gboolean netxray_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset);
static gboolean netxray_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);
static int netxray_read_rec_header(wtap *wth, FILE_T fh,
    union netxrayrec_hdr *hdr, int *err);
static guint netxray_set_pseudo_header(wtap *wth, const guint8 *pd, int len,
    union wtap_pseudo_header *pseudo_header, union netxrayrec_hdr *hdr);
static gboolean netxray_read_rec_data(FILE_T fh, guint8 *data_ptr,
    guint32 packet_size, int *err);
static void netxray_close(wtap *wth);
static gboolean netxray_dump_1_1(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
static gboolean netxray_dump_close_1_1(wtap_dumper *wdh, int *err);
static gboolean netxray_dump_2_0(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
static gboolean netxray_dump_close_2_0(wtap_dumper *wdh, int *err);

int netxray_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[sizeof netxray_magic];
	gboolean is_old;
	struct netxray_hdr hdr;
	guint network_type;
	double timeunit;
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

	/* Read in the string that should be at the start of a NetXRay
	 * file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	if (memcmp(magic, netxray_magic, sizeof magic) == 0) {
		is_old = FALSE;
	} else if (memcmp(magic, old_netxray_magic, sizeof magic) == 0) {
		is_old = TRUE;
	} else {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof hdr;

	if (is_old) {
		version_major = 0;
		version_minor = 0;
		file_type = WTAP_FILE_NETXRAY_OLD;
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
			file_type = WTAP_FILE_NETXRAY_1_0;
		} else if (memcmp(hdr.version, vers_1_1, sizeof vers_1_1) == 0) {
			version_major = 1;
			version_minor = 1;
			file_type = WTAP_FILE_NETXRAY_1_1;
		} else if (memcmp(hdr.version, vers_2_000, sizeof vers_2_000) == 0) {
			version_major = 2;
			version_minor = 0;
			file_type = WTAP_FILE_NETXRAY_2_00x;
		} else if (memcmp(hdr.version, vers_2_001, sizeof vers_2_001) == 0) {
			version_major = 2;
			version_minor = 1;
			file_type = WTAP_FILE_NETXRAY_2_00x;
		} else if (memcmp(hdr.version, vers_2_002, sizeof vers_2_002) == 0) {
			version_major = 2;
			version_minor = 2;
			file_type = WTAP_FILE_NETXRAY_2_00x;
		} else if (memcmp(hdr.version, vers_2_003, sizeof vers_2_003) == 0) {
			version_major = 2;
			version_minor = 3;
			file_type = WTAP_FILE_NETXRAY_2_00x;
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
	start_timestamp = (double)pletohl(&hdr.timelo)
	    + (double)pletohl(&hdr.timehi)*4294967296.0;
	switch (file_type) {

	case WTAP_FILE_NETXRAY_OLD:
		timeunit = 1000.0;
		wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
		break;

	case WTAP_FILE_NETXRAY_1_0:
		timeunit = 1000.0;
		wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
		break;

	case WTAP_FILE_NETXRAY_1_1:
		/*
		 * In version 1.1 files (as produced by Windows Sniffer
		 * Pro 2.0.01), the time stamp is in microseconds,
		 * rather than the milliseconds time stamps in NetXRay
		 * and older versions of Windows Sniffer.
		 */
		timeunit = 1000000.0;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case WTAP_FILE_NETXRAY_2_00x:
		/*
		 * Get the time stamp value from the appropriate TpS
		 * table.
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
				timeunit = TpS[hdr.timeunit];
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
				timeunit = TpS_gigpod[hdr.timeunit];

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
				timeunit = TpS_otherpod[hdr.timeunit];

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
				timeunit = TpS_otherpod2[hdr.timeunit];
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
				timeunit = TpS_gigpod2[hdr.timeunit];
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
			timeunit = TpS[hdr.timeunit];
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
		if (timeunit >= 1e7)
			wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		else
			wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	default:
		g_assert_not_reached();
		timeunit = 0.0;
	}
	start_timestamp = start_timestamp/timeunit;

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
	wth->file_type = file_type;
	wth->capture.netxray = g_malloc(sizeof(netxray_t));
	wth->subtype_read = netxray_read;
	wth->subtype_seek_read = netxray_seek_read;
	wth->subtype_close = netxray_close;
	wth->file_encap = file_encap;
	wth->snapshot_length = 0;	/* not available in header */
	wth->capture.netxray->start_time = pletohl(&hdr.start_time);
	wth->capture.netxray->timeunit = timeunit;
	wth->capture.netxray->start_timestamp = start_timestamp;
	wth->capture.netxray->version_major = version_major;

	/*
	 * If frames have an extra 4 bytes of stuff at the end, is
	 * it an FCS, or just junk?
	 */
	wth->capture.netxray->fcs_valid = FALSE;
	switch (file_encap) {

	case WTAP_ENCAP_ETHERNET:
	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	case WTAP_ENCAP_ISDN:
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
		 */
		if (version_major == 2) {
			if (hdr.realtick[1] == 0x34 && hdr.realtick[2] == 0x12)
				wth->capture.netxray->fcs_valid = TRUE;
		}
		break;
	}

	/*
	 * Remember the ISDN type, as we need it to interpret the
	 * channel number in ISDN captures.
	 */
	wth->capture.netxray->isdn_type = isdn_type;

	/* Remember the offset after the last packet in the capture (which
	 * isn't necessarily the last packet in the file), as it appears
	 * there's sometimes crud after it.
	 * XXX: Remember 'start_offset' to help testing for 'short file' at EOF
	 */
	wth->capture.netxray->wrapped      = FALSE;
	wth->capture.netxray->nframes      = pletohl(&hdr.nframes);
	wth->capture.netxray->start_offset = pletohl(&hdr.start_offset);
	wth->capture.netxray->end_offset   = pletohl(&hdr.end_offset);

	/* Seek to the beginning of the data records. */
	if (file_seek(wth->fh, pletohl(&hdr.start_offset), SEEK_SET, err) == -1) {
		g_free(wth->capture.netxray);
		return -1;
	}
	wth->data_offset = pletohl(&hdr.start_offset);

	return 1;
}

/* Read the next packet */
static gboolean netxray_read(wtap *wth, int *err, gchar **err_info _U_,
    long *data_offset)
{
	guint32	packet_size;
	union netxrayrec_hdr hdr;
	int	hdr_size;
	double	t;
	guint8  *pd;
	guint	padding;

reread:
	/* Have we reached the end of the packet data? */
	if (wth->data_offset == wth->capture.netxray->end_offset) {
		/* Yes. */
		*err = 0;	/* it's just an EOF, not an error */
		return FALSE;
	}
	/* Read record header. */
	hdr_size = netxray_read_rec_header(wth, wth->fh, &hdr, err);
	if (hdr_size == 0) {
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
		if (wth->capture.netxray->start_offset < wth->capture.netxray->end_offset) {
			*err = WTAP_ERR_SHORT_READ;
			return FALSE;
		}
		
		if (!wth->capture.netxray->wrapped) {
			/* Yes.  Remember that we did. */
			wth->capture.netxray->wrapped = TRUE;
			if (file_seek(wth->fh, CAPTUREFILE_HEADER_SIZE,
			    SEEK_SET, err) == -1)
				return FALSE;
			wth->data_offset = CAPTUREFILE_HEADER_SIZE;
			goto reread;
		}

		/* We've already wrapped - don't wrap again. */
		return FALSE;
	}

	/*
	 * Return the offset of the record header, so we can reread it
	 * if we go back to this frame.
	 */
	*data_offset = wth->data_offset;
	wth->data_offset += hdr_size;

	/*
	 * Read the packet data.
	 */
	if (wth->capture.netxray->version_major == 0)
		packet_size = pletohs(&hdr.old_hdr.len);
	else
		packet_size = pletohs(&hdr.hdr_1_x.incl_len);
	buffer_assure_space(wth->frame_buffer, packet_size);
	pd = buffer_start_ptr(wth->frame_buffer);
	if (!netxray_read_rec_data(wth->fh, pd, packet_size, err))
		return FALSE;
	wth->data_offset += packet_size;

	/*
	 * Set the pseudo-header.
	 */
	padding = netxray_set_pseudo_header(wth, pd, packet_size,
	    &wth->pseudo_header, &hdr);

	if (wth->capture.netxray->version_major == 0) {
		t = (double)pletohl(&hdr.old_hdr.timelo)
		    + (double)pletohl(&hdr.old_hdr.timehi)*4294967296.0;
		t /= wth->capture.netxray->timeunit;
		t -= wth->capture.netxray->start_timestamp;
		wth->phdr.ts.secs = wth->capture.netxray->start_time + (long)t;
		wth->phdr.ts.nsecs = (unsigned long)((t-(double)(unsigned long)(t))
			*1.0e9);
		/*
		 * We subtract the padding from the packet size, so our caller
		 * doesn't see it.
		 */
		wth->phdr.caplen = packet_size - padding;
		wth->phdr.len = wth->phdr.caplen;
	} else {
		t = (double)pletohl(&hdr.hdr_1_x.timelo)
		    + (double)pletohl(&hdr.hdr_1_x.timehi)*4294967296.0;
		t /= wth->capture.netxray->timeunit;
		t -= wth->capture.netxray->start_timestamp;
		wth->phdr.ts.secs = wth->capture.netxray->start_time + (long)t;
		wth->phdr.ts.nsecs = (unsigned long)((t-(double)(unsigned long)(t))
			*1.0e9);
		/*
		 * We subtract the padding from the packet size, so our caller
		 * doesn't see it.
		 */
		wth->phdr.caplen = packet_size - padding;
		wth->phdr.len = pletohs(&hdr.hdr_1_x.orig_len) - padding;
	}

	return TRUE;
}

static gboolean
netxray_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info _U_)
{
	union netxrayrec_hdr hdr;
	gboolean ret;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!netxray_read_rec_header(wth, wth->random_fh, &hdr, err)) {
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
	ret = netxray_read_rec_data(wth->random_fh, pd, length, err);
	if (!ret)
		return FALSE;

	/*
	 * Set the pseudo-header.
	 */
	netxray_set_pseudo_header(wth, pd, length, pseudo_header, &hdr);
	return TRUE;
}

static int
netxray_read_rec_header(wtap *wth, FILE_T fh, union netxrayrec_hdr *hdr,
    int *err)
{
	int	bytes_read;
	int	hdr_size = 0;

	/* Read record header. */
	switch (wth->capture.netxray->version_major) {

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
	bytes_read = file_read(hdr, 1, hdr_size, fh);
	if (bytes_read != hdr_size) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return 0;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return 0;
		}

		/*
		 * We're at EOF.  "*err" is 0; we return FALSE - that
		 * combination tells our caller we're at EOF.
		 */
		return 0;
	}
	return hdr_size;
}

static guint
netxray_set_pseudo_header(wtap *wth, const guint8 *pd, int len,
    union wtap_pseudo_header *pseudo_header, union netxrayrec_hdr *hdr)
{
	guint padding = 0;

	/*
	 * If this is Ethernet, 802.11, ISDN, X.25, or ATM, set the
	 * pseudo-header.
	 */
	switch (wth->capture.netxray->version_major) {

	case 1:
		switch (wth->file_encap) {

		case WTAP_ENCAP_ETHERNET:
			/*
			 * XXX - if hdr->hdr_1_x.xxx[15] is 1
			 * the frame appears not to have any extra
			 * stuff at the end, but if it's 0,
			 * there appears to be 4 bytes of stuff
			 * at the end, but it's not an FCS.
			 *
			 * Or is that just the low-order bit?
			 *
			 * For now, we just say "no FCS".
			 */
			pseudo_header->eth.fcs_len = 0;
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
			 * the packet if hdr->hdr_2_x.xxx[2] and
			 * hdr->hdr_2_x.xxx[3] are 0xff, and we don't if
			 * they don't.
			 *
			 * It also appears that if the low-order bit of
			 * hdr->hdr_2_x.xxx[8] is set, the packet has a
			 * bad FCS.
			 */
			if (hdr->hdr_2_x.xxx[2] == 0xff &&
			    hdr->hdr_2_x.xxx[3] == 0xff) {
				/*
				 * We have 4 bytes of stuff at the
				 * end of the frame - FCS, or junk?
				 */
			    	if (wth->capture.netxray->fcs_valid) {
					/*
					 * FCS.
					 */
					pseudo_header->eth.fcs_len = 4;
				} else {
					/*
					 * Junk.
					 */
					padding = 4;
				}
			} else
				pseudo_header->eth.fcs_len = 0;
			break;

		case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
			/*
			 * It appears, in one 802.11 capture, that
			 * we have 4 bytes of junk at the ends of
			 * frames in which hdr->hdr_2_x.xxx[2] and
			 * hdr->hdr_2_x.xxx[3] are 0xff; I haven't
			 * seen any frames where it's an FCS, but,
			 * for now, we still check the fcs_valid
			 * flag - I also haven't seen any capture
			 * where we'd set it based on the realtick
			 * value.
			 *
			 * It also appears that if the low-order bit of
			 * hdr->hdr_2_x.xxx[8] is set, the packet has a
			 * bad FCS.  According to Ken Mann, the 0x4 bit
			 * is sometimes also set for errors.
			 *
			 * Ken also says that xxx[11] is 0x5 when the
			 * packet is WEP-encrypted.
			 */
			if (hdr->hdr_2_x.xxx[2] == 0xff &&
			    hdr->hdr_2_x.xxx[3] == 0xff) {
				/*
				 * We have 4 bytes of stuff at the
				 * end of the frame - FCS, or junk?
				 */
			    	if (wth->capture.netxray->fcs_valid) {
					/*
					 * FCS.
					 */
					pseudo_header->ieee_802_11.fcs_len = 4;
				} else {
					/*
					 * Junk.
					 */
					padding = 4;
				}
			} else
				pseudo_header->ieee_802_11.fcs_len = 0;

			pseudo_header->ieee_802_11.channel =
			    hdr->hdr_2_x.xxx[12];
			pseudo_header->ieee_802_11.data_rate =
			    hdr->hdr_2_x.xxx[13];
			pseudo_header->ieee_802_11.signal_level =
			    hdr->hdr_2_x.xxx[14];
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
			 * The bottommost bit of byte 12 of "hdr.hdr_2_x.xxx"
			 * is the direction flag.
			 *
			 * The bottom 5 bits of byte 13 of "hdr.hdr_2_x.xxx"
			 * are the channel number, but some mapping is
			 * required for PRI.  (Is it really just the time
			 * slot?)
			 */
			pseudo_header->isdn.uton =
			    (hdr->hdr_2_x.xxx[12] & 0x01);
			pseudo_header->isdn.channel =
			    hdr->hdr_2_x.xxx[13] & 0x1F;
			switch (wth->capture.netxray->isdn_type) {

			case 1:
				/*
				 * E1 PRI.  Channel numbers 0 and 16
				 * are the D channel; channel numbers 1
				 * through 15 are B1 through B15; channel
				 * numbers 17 through 31 are B16 through
				 * B31.
				 */
				if (pseudo_header->isdn.channel == 16)
					pseudo_header->isdn.channel = 0;
				else if (pseudo_header->isdn.channel > 16)
					pseudo_header->isdn.channel -= 1;
				break;

			case 2:
				/*
				 * T1 PRI.  Channel numbers 0 and 24
				 * are the D channel; channel numbers 1
				 * through 23 are B1 through B23.
				 */
				if (pseudo_header->isdn.channel == 24)
					pseudo_header->isdn.channel = 0;
				else if (pseudo_header->isdn.channel > 24)
					pseudo_header->isdn.channel -= 1;
				break;
			}

			/*
			 * It appears, at least with version 2 captures,
			 * that we have 4 bytes of stuff (which might be
			 * a valid FCS or might be junk) at the end of
			 * the packet if hdr->hdr_2_x.xxx[2] and
			 * hdr->hdr_2_x.xxx[3] are 0xff, and we don't if
			 * they don't.
			 *
			 * XXX - does the low-order bit of hdr->hdr_2_x.xxx[8]
			 * indicate a bad FCS, as is the case with
			 * Ethernet?
			 */
			if (hdr->hdr_2_x.xxx[2] == 0xff &&
			    hdr->hdr_2_x.xxx[3] == 0xff) {
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
			 * The bottommost bit of byte 12 of "hdr.hdr_2_x.xxx"
			 * is the direction flag.  (Probably true for other
			 * HDLC encapsulations as well.)
			 */
			pseudo_header->x25.flags =
			    (hdr->hdr_2_x.xxx[12] & 0x01) ? 0x00 : FROM_DCE;
			break;

		case WTAP_ENCAP_PPP_WITH_PHDR:
		case WTAP_ENCAP_SDLC:
			pseudo_header->p2p.sent =
			    (hdr->hdr_2_x.xxx[12] & 0x01) ? TRUE : FALSE;
			break;

		case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
			pseudo_header->atm.flags = 0;
			/*
			 * XXX - is 0x08 an "OAM cell" flag?
			 */
			if (hdr->hdr_2_x.xxx[9] & 0x04)
				pseudo_header->atm.flags |= ATM_RAW_CELL;
			pseudo_header->atm.vpi = hdr->hdr_2_x.xxx[11];
			pseudo_header->atm.vci = pletohs(&hdr->hdr_2_x.xxx[12]);
			pseudo_header->atm.channel =
			    (hdr->hdr_2_x.xxx[15] & 0x10)? 1 : 0;
			pseudo_header->atm.cells = 0;

			switch (hdr->hdr_2_x.xxx[0] & 0xF0) {

			case 0x00:	/* Unknown */
				/*
				 * Infer the AAL, traffic type, and subtype.
				 */
				atm_guess_traffic_type(pd, len,
				    pseudo_header);
				break;

			case 0x50:	/* AAL5 (including signalling) */
				pseudo_header->atm.aal = AAL_5;
				switch (hdr->hdr_2_x.xxx[0] & 0x0F) {

				case 0x09:
				case 0x0a:	/* Signalling traffic */
					pseudo_header->atm.aal = AAL_SIGNALLING;
					pseudo_header->atm.type = TRAF_UNKNOWN;
					pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
					break;

				case 0x0b:	/* ILMI */
					pseudo_header->atm.type = TRAF_ILMI;
					pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
					break;

				case 0x0c:	/* LANE LE Control */
					pseudo_header->atm.type = TRAF_LANE;
					pseudo_header->atm.subtype = TRAF_ST_LANE_LE_CTRL;
					break;

				case 0x0d:
					/*
					 * 0x0d is *mostly* LANE 802.3,
					 * but I've seen an LE Control frame
					 * with 0x0d.
					 */
					pseudo_header->atm.type = TRAF_LANE;
					atm_guess_lane_type(pd, len,
					    pseudo_header);
					break;

				case 0x0f:	/* LLC multiplexed */
					pseudo_header->atm.type = TRAF_LLCMX;	/* XXX */
					pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;	/* XXX */
					break;

				default:
					/*
					 * XXX - discover the other types.
					 */
					pseudo_header->atm.type = TRAF_UNKNOWN;
					pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
					break;
				}
				break;

			default:
				/*
				 * 0x60 seen, and dissected by Sniffer
				 * Pro as a raw cell.
				 *
				 * XXX - discover what those types are.
				 */
				pseudo_header->atm.aal = AAL_UNKNOWN;
				pseudo_header->atm.type = TRAF_UNKNOWN;
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;
			}
			break;
		}
		break;
	}
	return padding;
}

static gboolean
netxray_read_rec_data(FILE_T fh, guint8 *data_ptr, guint32 packet_size,
    int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(data_ptr, 1, packet_size, fh);

	if (bytes_read <= 0 || (guint32)bytes_read != packet_size) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

static void
netxray_close(wtap *wth)
{
	g_free(wth->capture.netxray);
}

static const struct {
	int	wtap_encap_value;
	int	ndis_value;
} wtap_encap_1_1[] = {
    { WTAP_ENCAP_ETHERNET, 0 },		/* -> NDIS Ethernet */
    { WTAP_ENCAP_TOKEN_RING, 1 },	/* -> NDIS Token Ring */
    { WTAP_ENCAP_FDDI, 2 },		/* -> NDIS FDDI */
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
int netxray_dump_can_write_encap_1_1(int encap)
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
gboolean netxray_dump_open_1_1(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
    /* This is a NetXRay file.  We can't fill in some fields in the header
       until all the packets have been written, so we can't write to a
       pipe. */
    if (cant_seek) {
	*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
	return FALSE;
    }

    wdh->subtype_write = netxray_dump_1_1;
    wdh->subtype_close = netxray_dump_close_1_1;

    /* We can't fill in all the fields in the file header, as we
       haven't yet written any packets.  As we'll have to rewrite
       the header when we've written out all the packets, we just
       skip over the header for now. */
    if (fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET) == -1) {
	*err = errno;
	return FALSE;
    }

    wdh->dump.netxray = g_malloc(sizeof(netxray_dump_t));
    wdh->dump.netxray->first_frame = TRUE;
    wdh->dump.netxray->start.secs = 0;
    wdh->dump.netxray->start.nsecs = 0;
    wdh->dump.netxray->nframes = 0;

    return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_1_1(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint64 timestamp;
    guint32 t32;
    struct netxrayrec_1_x_hdr rec_hdr;
    size_t nwritten;

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
    rec_hdr.timelo = htolel(t32);
    t32 = (guint32)(timestamp/G_GINT64_CONSTANT(4294967296));
    rec_hdr.timehi = htolel(t32);
    rec_hdr.orig_len = htoles(phdr->len);
    rec_hdr.incl_len = htoles(phdr->caplen);

    nwritten = fwrite(&rec_hdr, 1, sizeof(rec_hdr), wdh->fh);
    if (nwritten != sizeof(rec_hdr)) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    /* write the packet data */
    nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
    if (nwritten != phdr->caplen) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    netxray->nframes++;

    return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_close_1_1(wtap_dumper *wdh, int *err)
{
    char hdr_buf[CAPTUREFILE_HEADER_SIZE - sizeof(netxray_magic)];
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint32 filelen;
    struct netxray_hdr file_hdr;
    size_t nwritten;

    filelen = ftell(wdh->fh);

    /* Go back to beginning */
    fseek(wdh->fh, 0, SEEK_SET);

    /* Rewrite the file header. */
    nwritten = fwrite(netxray_magic, 1, sizeof netxray_magic, wdh->fh);
    if (nwritten != sizeof netxray_magic) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    /* "sniffer" version ? */
    memset(&file_hdr, '\0', sizeof file_hdr);
    memcpy(file_hdr.version, vers_1_1, sizeof vers_1_1);
    file_hdr.start_time = htolel(netxray->start.secs);
    file_hdr.nframes = htolel(netxray->nframes);
    file_hdr.start_offset = htolel(CAPTUREFILE_HEADER_SIZE);
    file_hdr.end_offset = htolel(filelen);
    file_hdr.network = wtap_encap_to_netxray_1_1_encap(wdh->encap);
    file_hdr.timelo = htolel(0);
    file_hdr.timehi = htolel(0);

    memset(hdr_buf, '\0', sizeof hdr_buf);
    memcpy(hdr_buf, &file_hdr, sizeof(file_hdr));
    nwritten = fwrite(hdr_buf, 1, sizeof hdr_buf, wdh->fh);
    if (nwritten != sizeof hdr_buf) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

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
int netxray_dump_can_write_encap_2_0(int encap)
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
gboolean netxray_dump_open_2_0(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
    /* This is a NetXRay file.  We can't fill in some fields in the header
       until all the packets have been written, so we can't write to a
       pipe. */
    if (cant_seek) {
	*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
	return FALSE;
    }

    wdh->subtype_write = netxray_dump_2_0;
    wdh->subtype_close = netxray_dump_close_2_0;

    /* We can't fill in all the fields in the file header, as we
       haven't yet written any packets.  As we'll have to rewrite
       the header when we've written out all the packets, we just
       skip over the header for now. */
    if (fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET) == -1) {
	*err = errno;
	return FALSE;
    }

    wdh->dump.netxray = g_malloc(sizeof(netxray_dump_t));
    wdh->dump.netxray->first_frame = TRUE;
    wdh->dump.netxray->start.secs = 0;
    wdh->dump.netxray->start.nsecs = 0;
    wdh->dump.netxray->nframes = 0;

    return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_2_0(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint64 timestamp;
    guint32 t32;
    struct netxrayrec_2_x_hdr rec_hdr;
    size_t nwritten;

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
    rec_hdr.timelo = htolel(t32);
    t32 = (guint32)(timestamp/G_GINT64_CONSTANT(4294967296));
    rec_hdr.timehi = htolel(t32);
    rec_hdr.orig_len = htoles(phdr->len);
    rec_hdr.incl_len = htoles(phdr->caplen);

    switch (phdr->pkt_encap) {

    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
	rec_hdr.xxx[12] = pseudo_header->ieee_802_11.channel;
	rec_hdr.xxx[13] = pseudo_header->ieee_802_11.data_rate;
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

    nwritten = fwrite(&rec_hdr, 1, sizeof(rec_hdr), wdh->fh);
    if (nwritten != sizeof(rec_hdr)) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    /* write the packet data */
    nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
    if (nwritten != phdr->caplen) {
	if (nwritten == 0 && ferror(wdh->fh))
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }

    netxray->nframes++;

    return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netxray_dump_close_2_0(wtap_dumper *wdh, int *err)
{
    char hdr_buf[CAPTUREFILE_HEADER_SIZE - sizeof(netxray_magic)];
    netxray_dump_t *netxray = wdh->dump.netxray;
    guint32 filelen;
    struct netxray_hdr file_hdr;
    size_t nwritten;

    filelen = ftell(wdh->fh);

    /* Go back to beginning */
    fseek(wdh->fh, 0, SEEK_SET);

    /* Rewrite the file header. */
    nwritten = fwrite(netxray_magic, 1, sizeof netxray_magic, wdh->fh);
    if (nwritten != sizeof netxray_magic) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    /* "sniffer" version ? */
    memset(&file_hdr, '\0', sizeof file_hdr);
    memcpy(file_hdr.version, vers_2_001, sizeof vers_2_001);
    file_hdr.start_time = htolel(netxray->start.secs);
    file_hdr.nframes = htolel(netxray->nframes);
    file_hdr.start_offset = htolel(CAPTUREFILE_HEADER_SIZE);
    file_hdr.end_offset = htolel(filelen);
    file_hdr.network = wtap_encap_to_netxray_2_0_encap(wdh->encap);
    file_hdr.timelo = htolel(0);
    file_hdr.timehi = htolel(0);
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
    nwritten = fwrite(hdr_buf, 1, sizeof hdr_buf, wdh->fh);
    if (nwritten != sizeof hdr_buf) {
	if (err != NULL) {
	    if (nwritten == 0 && ferror(wdh->fh))
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	}
	return FALSE;
    }

    return TRUE;
}
