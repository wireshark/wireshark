/* netmon.c
 *
 * $Id: netmon.c,v 1.5 1999/03/01 18:57:05 gram Exp $
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
#include <netinet/in.h>
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

/* Magic number in Network Monitor files. */
static const char netmon_magic[] = {
	'R', 'T', 'S', 'S'
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
struct netmonrec_hdr {
	guint32	ts_delta;	/* time stamp - msecs since start of capture */
	guint16	orig_len;	/* actual length of packet */
	guint16	incl_len;	/* number of octets captured in file */
};

/* Returns WTAP_FILE_NETMON on success, WTAP_FILE_UNKNOWN on failure */
int netmon_open(wtap *wth)
{
	int bytes_read;
	char magic[sizeof netmon_magic];
	struct netmon_hdr hdr;
	static const int netmon_encap[] = {
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TR

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

	if (memcmp(magic, netmon_magic, sizeof netmon_magic) != 0) {
		return WTAP_FILE_UNKNOWN;
	}

	/* Read the rest of the header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
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
	wth->capture.netmon->start_msecs = pletohs(&hdr.ts_msec);

	/*
	 * The "frame index table" appears to come after the last
	 * packet; remember its offset, so we know when we have no
	 * more packets to read.
	 */
	wth->capture.netmon->end_offset = pletohl(&hdr.frametableoffset);

	/* Seek to the beginning of the data records. */
	fseek(wth->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET);

	return WTAP_FILE_NETMON;
}

/* Read the next packet */
int netmon_read(wtap *wth)
{
	int	packet_size;
	int	bytes_read;
	struct netmonrec_hdr hdr;
	int	data_offset;
	time_t	secs;
	guint32	msecs;

	/* Have we reached the end of the packet data? */
	data_offset = ftell(wth->fh);
	if (data_offset >= wth->capture.netmon->end_offset) {
		/* Yes. */
		return 0;
	}
	/* Read record header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		if (bytes_read != 0) {
			g_error("netmon_read: not enough packet header data (%d bytes)",
					bytes_read);
			return -1;
		}
		return 0;
	}
	data_offset += sizeof hdr;

	packet_size = pletohs(&hdr.incl_len);
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

	msecs = wth->capture.netmon->start_msecs + pletohl(&hdr.ts_delta);
	secs = wth->capture.netmon->start_secs + msecs/1000;
	msecs = msecs%1000;
	wth->phdr.ts.tv_sec = secs;
	wth->phdr.ts.tv_usec = msecs*1000;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = pletohs(&hdr.orig_len);
	wth->phdr.pkt_encap = wth->file_encap;

	return data_offset;
}
