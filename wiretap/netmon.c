/* netmon.c
 *
 * $Id: netmon.c,v 1.9 1999/08/18 04:17:38 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <time.h>
#include "wtap.h"
#include "buffer.h"
#include "netmon.h"

/* The file at
 *
 *	ftp://ftp.microsoft.com/developr/drg/cifs/cifs/Bhfile.zip
 *
 * contains "STRUCT.H", which declares the typedef CAPTUREFILE_HEADER
 * for the header of a Microsoft Network Monitor capture file.
 */

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number in Network Monitor 1.x files. */
static const char netmon_1_x_magic[] = {
	'R', 'T', 'S', 'S'
};

/* Magic number in Network Monitor 2.x files. */
static const char netmon_2_x_magic[] = {
	'G', 'M', 'B', 'U'
};

/* Network Monitor file header (minus magic number). */
struct netmon_hdr {
	guint8	ver_minor;	/* minor version number */
	guint8	ver_major;	/* major version number */
	guint16	network;	/* network type */
	guint16	ts_year;	/* year of capture start */
	guint16	ts_month;	/* month of capture start (January = 1) */
	guint16	ts_dow;		/* day of week of capture start (Sun = 0) */
	guint16	ts_day;		/* day of month of capture start */
	guint16	ts_hour;	/* hour of capture start */
	guint16	ts_min;		/* minute of capture start */
	guint16	ts_sec;		/* second of capture start */
	guint16	ts_msec;	/* millisecond of capture start */
	guint32	frametableoffset;	/* frame index table offset */
	guint32	frametablelength;	/* frame index table size */
	guint32	userdataoffset;		/* user data offset */
	guint32	userdatalength;		/* user data size */
	guint32	commentdataoffset;	/* comment data offset */
	guint32	commentdatalength;	/* comment data size */
	guint32	statisticsoffset;	/* offset to statistics structure */
	guint32	statisticslength;	/* length of statistics structure */
	guint32	networkinfooffset;	/* offset to network info structure */
	guint32	networkinfolength;	/* length of network info structure */
};

/* Network Monitor record header; not defined in STRUCT.H, but deduced by
 * looking at capture files. */
struct netmonrec_1_x_hdr {
	guint32	ts_delta;	/* time stamp - msecs since start of capture */
	guint16	orig_len;	/* actual length of packet */
	guint16	incl_len;	/* number of octets captured in file */
};

struct netmonrec_2_x_hdr {
	guint32	ts_delta_lo;	/* time stamp - usecs since start of capture */
	guint32	ts_delta_hi;	/* time stamp - usecs since start of capture */
	guint32	orig_len;	/* actual length of packet */
	guint32	incl_len;	/* number of octets captured in file */
};

/* Returns WTAP_FILE_NETMON on success, WTAP_FILE_UNKNOWN on failure */
int netmon_open(wtap *wth)
{
	int bytes_read;
	char magic[sizeof netmon_1_x_magic];
	struct netmon_hdr hdr;
	int file_type;
	static const int netmon_encap[] = {
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TR,
		WTAP_ENCAP_FDDI,
		WTAP_ENCAP_NONE,	/* WAN */
		WTAP_ENCAP_NONE,	/* LocalTalk */
		WTAP_ENCAP_NONE,	/* "DIX" - should not occur */
		WTAP_ENCAP_NONE,	/* ARCNET raw */
		WTAP_ENCAP_NONE,	/* ARCNET 878.2 */
		WTAP_ENCAP_NONE,	/* ATM */
		WTAP_ENCAP_NONE,	/* Wireless WAN */
		WTAP_ENCAP_NONE		/* IrDA */
	};
	#define NUM_NETMON_ENCAPS (sizeof netmon_encap / sizeof netmon_encap[0])
	struct tm tm;

	/* Read in the string that should be at the start of a Network
	 * Monitor file */
	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, sizeof magic, wth->fh);

	if (bytes_read != sizeof magic) {
		return WTAP_FILE_UNKNOWN;
	}

	if (memcmp(magic, netmon_1_x_magic, sizeof netmon_1_x_magic) != 0
	 && memcmp(magic, netmon_2_x_magic, sizeof netmon_1_x_magic) != 0) {
		return WTAP_FILE_UNKNOWN;
	}

	/* Read the rest of the header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		return WTAP_FILE_UNKNOWN;
	}

	switch (hdr.ver_major) {

	case 1:
		file_type = WTAP_FILE_NETMON_1_x;
		break;

	case 2:
		file_type = WTAP_FILE_NETMON_2_x;
		break;

	default:
		return WTAP_FILE_UNKNOWN;
	}

	hdr.network = pletohs(&hdr.network);
	if (hdr.network >= NUM_NETMON_ENCAPS) {
		g_error("netmon: network type %d unknown", hdr.network);
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a netmon file */
	wth->capture.netmon = g_malloc(sizeof(netmon_t));
	wth->subtype_read = netmon_read;
	wth->file_encap = netmon_encap[hdr.network];
	wth->snapshot_length = 16384;	/* XXX - not available in header */
	/*
	 * Convert the time stamp to a "time_t" and a number of
	 * milliseconds.
	 */
	tm.tm_year = pletohs(&hdr.ts_year) - 1900;
	tm.tm_mon = pletohs(&hdr.ts_month) - 1;
	tm.tm_mday = pletohs(&hdr.ts_day);
	tm.tm_hour = pletohs(&hdr.ts_hour);
	tm.tm_min = pletohs(&hdr.ts_min);
	tm.tm_sec = pletohs(&hdr.ts_sec);
	tm.tm_isdst = -1;
	wth->capture.netmon->start_secs = mktime(&tm);
	/*
	 * XXX - what if "secs" is -1?  Unlikely, but if the capture was
	 * done in a time zone that switches between standard and summer
	 * time sometime other than when we do, and thus the time was one
	 * that doesn't exist here because a switch from standard to summer
	 * time zips over it, it could happen.
	 *
	 * On the other hand, if the capture was done in a different time
	 * zone, this won't work right anyway; unfortunately, the time
	 * zone isn't stored in the capture file (why the hell didn't
	 * they stuff a FILETIME, which is the number of 100-nanosecond
	 * intervals since 1601-01-01 00:00:00 "UTC", there, instead
	 * of stuffing a SYSTEMTIME, which is time-zone-dependent, there?).
	 */
	wth->capture.netmon->start_usecs = pletohs(&hdr.ts_msec)*1000;

	wth->capture.netmon->version_major = hdr.ver_major;

	/*
	 * The "frame index table" appears to come after the last
	 * packet; remember its offset, so we know when we have no
	 * more packets to read.
	 */
	wth->capture.netmon->end_offset = pletohl(&hdr.frametableoffset);

	/* Seek to the beginning of the data records. */
	fseek(wth->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET);

	return file_type;
}

/* Read the next packet */
int netmon_read(wtap *wth)
{
	int	packet_size = 0;
	int	bytes_read;
	union {
		struct netmonrec_1_x_hdr hdr_1_x;
		struct netmonrec_2_x_hdr hdr_2_x;
	}	hdr;
	int	hdr_size = 0;
	int	data_offset;
	time_t	secs;
	guint32	usecs;
	double	t;

	/* Have we reached the end of the packet data? */
	data_offset = ftell(wth->fh);
	if (data_offset >= wth->capture.netmon->end_offset) {
		/* Yes. */
		return 0;
	}
	/* Read record header. */
	/* Read record header. */
	switch (wth->capture.netmon->version_major) {

	case 1:
		hdr_size = sizeof (struct netmonrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netmonrec_2_x_hdr);
		break;
	}
	bytes_read = fread(&hdr, 1, hdr_size, wth->fh);
	if (bytes_read != hdr_size) {
		if (bytes_read != 0) {
			g_error("netmon_read: not enough packet header data (%d bytes)",
					bytes_read);
			return -1;
		}
		return 0;
	}
	data_offset += hdr_size;

	switch (wth->capture.netmon->version_major) {

	case 1:
		packet_size = pletohs(&hdr.hdr_1_x.incl_len);
		break;

	case 2:
		packet_size = pletohl(&hdr.hdr_2_x.incl_len);
		break;
	}
	buffer_assure_space(wth->frame_buffer, packet_size);
	bytes_read = fread(buffer_start_ptr(wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh)) {
			g_error("netmon_read: fread for data: read error\n");
		} else {
			g_error("netmon_read: fread for data: %d bytes out of %d",
				bytes_read, packet_size);
		}
		return -1;
	}

	t = (double)wth->capture.netmon->start_usecs;
	switch (wth->capture.netmon->version_major) {

	case 1:
		t += ((double)pletohl(&hdr.hdr_1_x.ts_delta))*1000;
		break;

	case 2:
		t += (double)pletohl(&hdr.hdr_2_x.ts_delta_lo)
		    + (double)pletohl(&hdr.hdr_2_x.ts_delta_hi)*4294967296.0;
		break;
	}
	secs = (time_t)(t/1000000);
	usecs = (guint32)(t - secs*1000000);
	wth->phdr.ts.tv_sec = wth->capture.netmon->start_secs + secs;
	wth->phdr.ts.tv_usec = usecs;
	wth->phdr.caplen = packet_size;
	switch (wth->capture.netmon->version_major) {

	case 1:
		wth->phdr.len = pletohs(&hdr.hdr_1_x.orig_len);
		break;

	case 2:
		wth->phdr.len = pletohl(&hdr.hdr_2_x.orig_len);
		break;
	}
	wth->phdr.pkt_encap = wth->file_encap;

	return data_offset;
}
