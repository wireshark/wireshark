/* netxray.c
 *
 * $Id: netxray.c,v 1.16 1999/10/05 07:06:06 guy Exp $
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

#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "wtap.h"
#include "file.h"
#include "netxray.h"
#include "buffer.h"

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number in NetXRay files. */
static const char netxray_magic[] = {	/* magic header */
	'X', 'C', 'P', '\0'
};

/* NetXRay file header (minus magic number). */
struct netxray_hdr {
	char	version[8];	/* version number */
	guint32	start_time;	/* UNIX time when capture started */
	guint32	xxx[2];		/* unknown */
	guint32	start_offset;	/* offset of first packet in capture */
	guint32	end_offset;	/* offset after last packet in capture */
	guint32 xxy[3];		/* unknown */
	guint16	network;	/* datalink type */
	guint8	xxz[6];
	guint32	timelo;		/* lower 32 bits of time stamp of capture start */
	guint32	timehi;		/* upper 32 bits of time stamp of capture start */
	/*
	 * XXX - other stuff.
	 */
};

/* Version number strings. */
static const char vers_1_0[] = {
	'0', '0', '1', '.', '0', '0', '0', '\0'
};

static const char vers_1_1[] = {
	'0', '0', '1', '.', '1', '0', '0', '\0'
};

static const char vers_2_001[] = {
	'0', '0', '2', '.', '0', '0', '1', '\0'
};

/* NetXRay 1.x data record format - followed by frame data. */
struct netxrayrec_1_x_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	orig_len;	/* packet length */
	guint16	incl_len;	/* capture length */
	guint32	xxx[4];		/* unknown */
};

/* NetXRay 2.x data record format - followed by frame data. */
struct netxrayrec_2_x_hdr {
	guint32	timelo;		/* lower 32 bits of time stamp */
	guint32	timehi;		/* upper 32 bits of time stamp */
	guint16	orig_len;	/* packet length */
	guint16	incl_len;	/* capture length */
	guint32	xxx[7];		/* unknown */
};

static int netxray_read(wtap *wth, int *err);

int netxray_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof netxray_magic];
	struct netxray_hdr hdr;
	double timeunit;
	int version_major;
	int file_type;
	double t;
	static const int netxray_encap[] = {
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
	#define NUM_NETXRAY_ENCAPS (sizeof netxray_encap / sizeof netxray_encap[0])

	/* Read in the string that should be at the start of a NetXRay
	 * file */
	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	if (memcmp(magic, netxray_magic, sizeof netxray_magic) != 0) {
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

	/* It appears that version 1.1 files (as produced by Windows
	 * Sniffer Pro 2.0.01) have the time stamp in microseconds,
	 * rather than the milliseconds version 1.0 files appear to have.
	 *
	 * It also appears that version 2.001 files (as produced by
	 * Windows(?) Sniffer Pro 2.50.05) have per-packet headers with
	 * some extra fields. */
	if (memcmp(hdr.version, vers_1_0, sizeof vers_1_0) == 0) {
		timeunit = 1000.0;
		version_major = 1;
		file_type = WTAP_FILE_NETXRAY_1_0;
	} else if (memcmp(hdr.version, vers_1_1, sizeof vers_1_1) == 0) {
		timeunit = 1000000.0;
		version_major = 1;
		file_type = WTAP_FILE_NETXRAY_1_1;
	} else if (memcmp(hdr.version, vers_2_001, sizeof vers_2_001) == 0) {
		timeunit = 1000000.0;
		version_major = 2;
		file_type = WTAP_FILE_NETXRAY_2_001;
	} else {
		g_message("netxray: version \"%.8s\" unsupported", hdr.version);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	hdr.network = pletohs(&hdr.network);
	if (hdr.network >= NUM_NETXRAY_ENCAPS
	    || netxray_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("netxray: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/* This is a netxray file */
	wth->file_type = file_type;
	wth->capture.netxray = g_malloc(sizeof(netxray_t));
	wth->subtype_read = netxray_read;
	wth->file_encap = netxray_encap[hdr.network];
	wth->snapshot_length = 16384;	/* XXX - not available in header */
	wth->capture.netxray->start_time = pletohl(&hdr.start_time);
	wth->capture.netxray->timeunit = timeunit;
	t = (double)pletohl(&hdr.timelo)
	    + (double)pletohl(&hdr.timehi)*4294967296.0;
	t = t/timeunit;
	wth->capture.netxray->start_timestamp = t;
	wth->capture.netxray->version_major = version_major;
	/*wth->frame_number = 0;*/
	/*wth->file_byte_offset = 0x10b;*/

	/* Remember the offset after the last packet in the capture (which
	 * isn't necessarily the last packet in the file), as it appears
	 * there's sometimes crud after it. */
	wth->capture.netxray->wrapped = 0;
	wth->capture.netxray->end_offset = pletohl(&hdr.end_offset);

	/* Seek to the beginning of the data records. */
	file_seek(wth->fh, pletohl(&hdr.start_offset), SEEK_SET);
	wth->data_offset = pletohl(&hdr.start_offset);

	return 1;
}

/* Read the next packet */
static int netxray_read(wtap *wth, int *err)
{
	guint32	packet_size;
	int	bytes_read;
	union {
		struct netxrayrec_1_x_hdr hdr_1_x;
		struct netxrayrec_2_x_hdr hdr_2_x;
	}	hdr;
	int	hdr_size = 0;
	int	data_offset;
	double	t;

reread:
	/* Have we reached the end of the packet data? */
	if (wth->data_offset == wth->capture.netxray->end_offset) {
		/* Yes. */
		return 0;
	}
	/* Read record header. */
	switch (wth->capture.netxray->version_major) {

	case 1:
		hdr_size = sizeof (struct netxrayrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netxrayrec_2_x_hdr);
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

		/* We're at EOF.  Wrap? */
		if (!wth->capture.netxray->wrapped) {
			/* Yes.  Remember that we did. */
			wth->capture.netxray->wrapped = 1;
			file_seek(wth->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET);
			wth->data_offset = CAPTUREFILE_HEADER_SIZE;
			goto reread;
		}

		/* We've already wrapped - don't wrap again. */
		return 0;
	}
	wth->data_offset += hdr_size;

	packet_size = pletohs(&hdr.hdr_1_x.incl_len);
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

	t = (double)pletohl(&hdr.hdr_1_x.timelo)
	    + (double)pletohl(&hdr.hdr_1_x.timehi)*4294967296.0;
	t /= wth->capture.netxray->timeunit;
	t -= wth->capture.netxray->start_timestamp;
	wth->phdr.ts.tv_sec = wth->capture.netxray->start_time + (long)t;
	wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(unsigned long)(t))
		*1.0e6);
	wth->phdr.caplen = packet_size;
	wth->phdr.len = pletohs(&hdr.hdr_1_x.orig_len);
	wth->phdr.pkt_encap = wth->file_encap;

	return data_offset;
}
