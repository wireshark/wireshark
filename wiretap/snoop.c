/* snoop.c
 *
 * $Id: snoop.c,v 1.1 1998/11/15 05:29:14 guy Exp $
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
#include "wtap.h"
#include "snoop.h"
#include <netinet/in.h>

/* See RFC 1761 for a description of the "snoop" file format. */

/* Magic number in "snoop" files. */
static char snoop_magic[] = {
	's', 'n', 'o', 'o', 'p', '\0', '\0', '\0'
};

/* "snoop" file header (minus magic number). */
struct snoop_hdr {
	guint32	version;	/* version number (should be 2) */
	guint32	network;	/* network type */
};

/* "snoop" record header. */
struct snooprec_hdr {
	guint32	orig_len;	/* actual length of packet */
	guint32	incl_len;	/* number of octets captured in file */
	guint32	rec_len;	/* length of record */
	guint32	cum_drops;	/* cumulative number of dropped packets */
	guint32	ts_sec;		/* timestamp seconds */
	guint32	ts_usec;	/* timestamp microseconds */
};

/* Returns WTAP_FILE_SNOOP on success, WTAP_FILE_UNKNOWN on failure */
int snoop_open(wtap *wth)
{
	int bytes_read;
	char magic[sizeof snoop_magic];
	struct snoop_hdr hdr;
	static const int snoop_encap[] = {
		WTAP_ENCAP_NONE,	/* IEEE 802.3 */
		WTAP_ENCAP_NONE,	/* IEEE 802.4 Token Bus */
		WTAP_ENCAP_TR,
		WTAP_ENCAP_NONE,	/* IEEE 802.6 Metro Net */
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_NONE,	/* HDLC */
		WTAP_ENCAP_NONE,	/* Character Synchronous */
		WTAP_ENCAP_NONE,	/* IBM Channel-to-Channel */
		WTAP_ENCAP_FDDI,
		WTAP_ENCAP_NONE		/* Other */
	};
	#define NUM_SNOOP_ENCAPS (sizeof snoop_encap / sizeof snoop_encap[0])

	/* Read in the string that should be at the start of a "snoop" file */
	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, sizeof magic, wth->fh);

	if (bytes_read != sizeof magic) {
		return WTAP_FILE_UNKNOWN;
	}

	if (memcmp(magic, snoop_magic, sizeof snoop_magic) != 0) {
		return WTAP_FILE_UNKNOWN;
	}

	/* Read the rest of the header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		return WTAP_FILE_UNKNOWN;
	}

	hdr.version = ntohl(hdr.version);
	if (hdr.version != 2) {
		/* We only support version 2. */
		return WTAP_FILE_UNKNOWN;
	}
	hdr.network = ntohl(hdr.network);
	if (hdr.network >= NUM_SNOOP_ENCAPS) {
		g_error("snoop: network type %d unknown", hdr.network);
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a snoop file */
	wth->subtype_read = snoop_read;
	wth->encapsulation = snoop_encap[hdr.network];
	wth->snapshot_length = 16384;	/* XXX - not available in header */
	/*wth->frame_number = 0;*/
	/*wth->file_byte_offset = 0x10b;*/

	return WTAP_FILE_SNOOP;
}

/* Read the next packet */
int snoop_read(wtap *wth)
{
	int	packet_size;
	int	bytes_read;
	struct snooprec_hdr hdr;
	int	data_offset;

	/* Read record header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		if (bytes_read != 0) {
			g_error("snoop_read: not enough packet header data (%d bytes)",
					bytes_read);
			return -1;
		}
		return 0;
	}

	packet_size = ntohl(hdr.incl_len);
	buffer_assure_space(&wth->frame_buffer, packet_size);
	data_offset = ftell(wth->fh);
	bytes_read = fread(buffer_start_ptr(&wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh)) {
			g_error("snoop_read: fread for data: read error\n");
		} else {
			g_error("snoop_read: fread for data: %d bytes out of %d",
				bytes_read, packet_size);
		}
		return -1;
	}

	wth->phdr.ts.tv_sec = ntohl(hdr.ts_sec);
	wth->phdr.ts.tv_usec = ntohl(hdr.ts_usec);
	wth->phdr.caplen = packet_size;
	wth->phdr.len = ntohl(hdr.orig_len);

	/* Skip over the padding. */
	fseek(wth->fh, ntohl(hdr.rec_len) - (sizeof hdr + packet_size),
	    SEEK_CUR);

	return data_offset;
}
