/* netmon.c
 *
 * $Id: netmon.c,v 1.22 1999/12/15 01:34:17 guy Exp $
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
#include <errno.h>
#include <time.h>
#include <string.h>
#include "wtap.h"
#include "file.h"
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

/* Network Monitor 1.x record header; not defined in STRUCT.H, but deduced by
 * looking at capture files. */
struct netmonrec_1_x_hdr {
	guint32	ts_delta;	/* time stamp - msecs since start of capture */
	guint16	orig_len;	/* actual length of packet */
	guint16	incl_len;	/* number of octets captured in file */
};

/* Network Monitor 2.x record header; not defined in STRUCT.H, but deduced by
 * looking at capture files. */
struct netmonrec_2_x_hdr {
	guint32	ts_delta_lo;	/* time stamp - usecs since start of capture */
	guint32	ts_delta_hi;	/* time stamp - usecs since start of capture */
	guint32	orig_len;	/* actual length of packet */
	guint32	incl_len;	/* number of octets captured in file */
};

static int netmon_read(wtap *wth, int *err);
static gboolean netmon_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const u_char *pd, int *err);
static gboolean netmon_dump_close(wtap_dumper *wdh, int *err);

int netmon_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof netmon_1_x_magic];
	struct netmon_hdr hdr;
	int file_type;
	static const int netmon_encap[] = {
		WTAP_ENCAP_UNKNOWN,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TR,
		WTAP_ENCAP_FDDI_BITSWAPPED,
		WTAP_ENCAP_UNKNOWN,	/* WAN */
		WTAP_ENCAP_UNKNOWN,	/* LocalTalk */
		WTAP_ENCAP_UNKNOWN,	/* "DIX" - should not occur */
		WTAP_ENCAP_UNKNOWN,	/* ARCNET raw */
		WTAP_ENCAP_UNKNOWN,	/* ARCNET 878.2 */
		WTAP_ENCAP_UNKNOWN,	/* ATM */
		WTAP_ENCAP_UNKNOWN,	/* Wireless WAN */
		WTAP_ENCAP_UNKNOWN	/* IrDA */
	};
	#define NUM_NETMON_ENCAPS (sizeof netmon_encap / sizeof netmon_encap[0])
	struct tm tm;
	guint32 frame_table_length;
	guint32 first_frame_table_entry;

	/* Read in the string that should be at the start of a Network
	 * Monitor file */
	file_seek(wth->fh, 0, SEEK_SET);
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	if (memcmp(magic, netmon_1_x_magic, sizeof netmon_1_x_magic) != 0
	 && memcmp(magic, netmon_2_x_magic, sizeof netmon_1_x_magic) != 0) {
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

	switch (hdr.ver_major) {

	case 1:
		file_type = WTAP_FILE_NETMON_1_x;
		break;

	case 2:
		file_type = WTAP_FILE_NETMON_2_x;
		break;

	default:
		g_message("netmon: major version %u unsupported", hdr.ver_major);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	hdr.network = pletohs(&hdr.network);
	if (hdr.network >= NUM_NETMON_ENCAPS
	    || netmon_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("netmon: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/* This is a netmon file */
	wth->file_type = file_type;
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

	/*
	 * It appears that some NetMon 2.x files don't have the
	 * first packet starting exactly 128 bytes into the file.
	 * So we read the first entry from the frame table, and
	 * use that as the offset of the first packet.
	 *
	 * First, make sure the frame table has at least one entry
	 * in it....
	 */
	frame_table_length = pletohl(&hdr.frametablelength);
	if (frame_table_length < sizeof first_frame_table_entry) {
		g_message("netmon: frame table length is %u, which means it's less than one entry in size",
		    frame_table_length);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/*
	 * Now read that entry.  (It appears that the N+1st frame immediately
	 * follows the Nth frame, so we don't need any entries after the
	 * first entry.)
	 */
	errno = WTAP_ERR_CANT_READ;
	file_seek(wth->fh, wth->capture.netmon->end_offset, SEEK_SET);
	bytes_read = file_read(&first_frame_table_entry, 1,
	    sizeof first_frame_table_entry, wth->fh);
	if (bytes_read != sizeof first_frame_table_entry) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* Seek to the beginning of the data records. */
	wth->data_offset = pletohl(&first_frame_table_entry);
	file_seek(wth->fh, wth->data_offset, SEEK_SET);

	return 1;
}

/* Read the next packet */
static int netmon_read(wtap *wth, int *err)
{
	guint32	packet_size = 0;
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
	if (wth->data_offset >= wth->capture.netmon->end_offset) {
		/* Yes. */
		return 0;
	}
	/* Read record header. */
	switch (wth->capture.netmon->version_major) {

	case 1:
		hdr_size = sizeof (struct netmonrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netmonrec_2_x_hdr);
		break;
	}
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, hdr_size, wth->fh);
	if (bytes_read != hdr_size) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += hdr_size;

	switch (wth->capture.netmon->version_major) {

	case 1:
		packet_size = pletohs(&hdr.hdr_1_x.incl_len);
		break;

	case 2:
		packet_size = pletohl(&hdr.hdr_2_x.incl_len);
		break;
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		g_message("netmon: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}
	buffer_assure_space(wth->frame_buffer, packet_size);
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += packet_size;

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

static const int wtap_encap[] = {
	-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
	1,		/* WTAP_ENCAP_ETHERNET -> NDIS Ethernet */
	2,		/* WTAP_ENCAP_TR -> NDIS Token Ring */
	-1,		/* WTAP_ENCAP_SLIP -> unsupported */
	-1,		/* WTAP_ENCAP_PPP -> unsupported */
	3,		/* WTAP_ENCAP_FDDI -> NDIS FDDI */
	3,		/* WTAP_ENCAP_FDDI_BITSWAPPED -> NDIS FDDI */
	-1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
	-1,		/* WTAP_ENCAP_ARCNET -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
	-1,		/* WTAP_ENCAP_LAPB -> unsupported*/
	-1,		/* WTAP_ENCAP_ATM_SNIFFER -> unsupported */
	-1		/* WTAP_ENCAP_NULL -> unsupported */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int netmon_dump_can_write_encap(int filetype, int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean netmon_dump_open(wtap_dumper *wdh, int *err)
{
	/* This is a netmon file */
	wdh->subtype_write = netmon_dump;
	wdh->subtype_close = netmon_dump_close;

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET);

	wdh->private.netmon = g_malloc(sizeof(netmon_dump_t));
	wdh->private.netmon->frame_table_offset = CAPTUREFILE_HEADER_SIZE;
	wdh->private.netmon->got_first_record_time = FALSE;
	wdh->private.netmon->frame_table = NULL;
	wdh->private.netmon->frame_table_index = 0;
	wdh->private.netmon->frame_table_size = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netmon_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const u_char *pd, int *err)
{
	netmon_dump_t *priv = wdh->private.netmon;
	struct netmonrec_1_x_hdr rec_1_x_hdr;
	struct netmonrec_2_x_hdr rec_2_x_hdr;
	char *hdrp;
	int hdr_size;
	int nwritten;

	/* NetMon files have a capture start time in the file header,
	   and have times relative to that in the packet headers;
	   pick the time of the first packet as the capture start
	   time. */
	if (!priv->got_first_record_time) {
		priv->first_record_time = phdr->ts;
		priv->got_first_record_time = TRUE;
	}
	
	switch (wdh->file_type) {

	case WTAP_FILE_NETMON_1_x:
		rec_1_x_hdr.ts_delta = htolel(
		    (phdr->ts.tv_sec - priv->first_record_time.tv_sec)*1000
		  + (phdr->ts.tv_usec - priv->first_record_time.tv_usec + 500)/1000);
		rec_1_x_hdr.orig_len = htoles(phdr->len);
		rec_1_x_hdr.incl_len = htoles(phdr->caplen);
		hdrp = (char *)&rec_1_x_hdr;
		hdr_size = sizeof rec_1_x_hdr;
		break;

	case WTAP_FILE_NETMON_2_x:
		/* XXX - fill in 64-bit time diff in microseconds */
		rec_2_x_hdr.orig_len = htolel(phdr->len);
		rec_2_x_hdr.incl_len = htolel(phdr->caplen);
		hdrp = (char *)&rec_2_x_hdr;
		hdr_size = sizeof rec_2_x_hdr;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	nwritten = fwrite(hdrp, 1, hdr_size, wdh->fh);
	if (nwritten != hdr_size) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	/*
	 * Stash the file offset of this frame.
	 */
	if (priv->frame_table_size == 0) {
		/*
		 * Haven't yet allocated the buffer for the frame table.
		 */
		priv->frame_table = g_malloc(1024 * sizeof *priv->frame_table);
		priv->frame_table_size = 1024;
	} else {
		/*
		 * We've allocated it; are we at the end?
		 */
		if (priv->frame_table_index >= priv->frame_table_size) {
			/*
			 * Yes - double the size of the frame table.
			 */
			priv->frame_table_size *= 2;
			priv->frame_table = g_realloc(priv->frame_table,
			    priv->frame_table_size * sizeof *priv->frame_table);
		}
	}
	priv->frame_table[priv->frame_table_index] =
	    htolel(priv->frame_table_offset);
	priv->frame_table_index++;
	priv->frame_table_offset += hdr_size + phdr->caplen;

	return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netmon_dump_close(wtap_dumper *wdh, int *err)
{
	netmon_dump_t *priv = wdh->private.netmon;
	int n_to_write;
	int nwritten;
	struct netmon_hdr file_hdr;
	const char *magicp;
	int magic_size;
	struct tm *tm;

	/* Write out the frame table.  "priv->frame_table_index" is
	   the number of entries we've put into it. */
	n_to_write = priv->frame_table_index * sizeof *priv->frame_table;
	nwritten = fwrite(priv->frame_table, 1, n_to_write, wdh->fh);
	if (nwritten != n_to_write) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	/* Now go fix up the file header. */
	fseek(wdh->fh, 0, SEEK_SET);
	memset(&file_hdr, '\0', sizeof file_hdr);
	switch (wdh->file_type) {

	case WTAP_FILE_NETMON_1_x:
		magicp = netmon_1_x_magic;
		magic_size = sizeof netmon_1_x_magic;
		/* current NetMon version, for 1.x, is 1.1 */
		file_hdr.ver_minor = 1;
		file_hdr.ver_major = 1;
		break;

	case WTAP_FILE_NETMON_2_x:
		magicp = netmon_2_x_magic;
		magic_size = sizeof netmon_2_x_magic;
		/* XXX - fill in V2 stuff. */
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}
	nwritten = fwrite(magicp, 1, magic_size, wdh->fh);
	if (nwritten != magic_size) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	file_hdr.network = htoles(wtap_encap[wdh->encap]);
	tm = localtime(&priv->first_record_time.tv_sec);
	file_hdr.ts_year = htoles(1900 + tm->tm_year);
	file_hdr.ts_month = htoles(tm->tm_mon + 1);
	file_hdr.ts_dow = htoles(tm->tm_wday);
	file_hdr.ts_day = htoles(tm->tm_mday);
	file_hdr.ts_hour = htoles(tm->tm_hour);
	file_hdr.ts_min = htoles(tm->tm_min);
	file_hdr.ts_sec = htoles(tm->tm_sec);
	file_hdr.ts_msec = htoles(priv->first_record_time.tv_usec/1000);
		/* XXX - what about rounding? */
	file_hdr.frametableoffset = htolel(priv->frame_table_offset);
	file_hdr.frametablelength =
	    htolel(priv->frame_table_index * sizeof *priv->frame_table);
	nwritten = fwrite(&file_hdr, 1, sizeof file_hdr, wdh->fh);
	if (nwritten != sizeof file_hdr) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	return TRUE;
}
