/* snoop.c
 *
 * $Id: snoop.c,v 1.9 1999/08/28 01:19:45 guy Exp $
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
#include "wtap.h"
#include "buffer.h"
#include "snoop.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* See RFC 1761 for a description of the "snoop" file format. */

/* Magic number in "snoop" files. */
static const char snoop_magic[] = {
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

static int snoop_read(wtap *wth, int *err);

int snoop_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof snoop_magic];
	struct snoop_hdr hdr;
	static const int snoop_encap[] = {
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.3 */
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.4 Token Bus */
		WTAP_ENCAP_TR,
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.6 Metro Net */
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_UNKNOWN,	/* HDLC */
		WTAP_ENCAP_UNKNOWN,	/* Character Synchronous */
		WTAP_ENCAP_UNKNOWN,	/* IBM Channel-to-Channel */
		WTAP_ENCAP_FDDI_BITSWAPPED,
		WTAP_ENCAP_UNKNOWN	/* Other */
	};
	#define NUM_SNOOP_ENCAPS (sizeof snoop_encap / sizeof snoop_encap[0])

	/* Read in the string that should be at the start of a "snoop" file */
	fseek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		if (ferror(wth->fh)) {
			*err = errno;
			return -1;
		}
		return 0;
	}
	wth->data_offset += sizeof magic;

	if (memcmp(magic, snoop_magic, sizeof snoop_magic) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		if (ferror(wth->fh)) {
			*err = errno;
			return -1;
		}
		return 0;
	}
	wth->data_offset += sizeof hdr;

	hdr.version = ntohl(hdr.version);
	if (hdr.version != 2) {
		/* We only support version 2. */
		g_message("snoop: version %u unsupported", hdr.version);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}
	hdr.network = ntohl(hdr.network);
	if (hdr.network >= NUM_SNOOP_ENCAPS
	    || snoop_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("snoop: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/* This is a snoop file */
	wth->file_type = WTAP_FILE_SNOOP;
	wth->subtype_read = snoop_read;
	wth->file_encap = snoop_encap[hdr.network];
	wth->snapshot_length = 16384;	/* XXX - not available in header */
	return 1;
}

/* Read the next packet */
static int snoop_read(wtap *wth, int *err)
{
	guint32	packet_size;
	int	bytes_read;
	struct snooprec_hdr hdr;
	int	data_offset;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		if (ferror(wth->fh)) {
			*err = errno;
			return -1;
		}
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += sizeof hdr;

	packet_size = ntohl(hdr.incl_len);
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		g_message("snoop: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}
	buffer_assure_space(wth->frame_buffer, packet_size);
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(buffer_start_ptr(wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += packet_size;

	wth->phdr.ts.tv_sec = ntohl(hdr.ts_sec);
	wth->phdr.ts.tv_usec = ntohl(hdr.ts_usec);
	wth->phdr.caplen = packet_size;
	wth->phdr.len = ntohl(hdr.orig_len);
	wth->phdr.pkt_encap = wth->file_encap;

	/* Skip over the padding. */
	fseek(wth->fh, ntohl(hdr.rec_len) - (sizeof hdr + packet_size),
	    SEEK_CUR);
	wth->data_offset += ntohl(hdr.rec_len) - (sizeof hdr + packet_size);

	return data_offset;
}
