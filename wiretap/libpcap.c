/* libpcap.c
 *
 * $Id: libpcap.c,v 1.4 1999/03/01 18:57:05 gram Exp $
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
#include "buffer.h"
#include "libpcap.h"

/* See source to the "libpcap" library for information on the "libpcap"
   file format. */

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.  */
#define	PCAP_MAGIC		0xa1b2c3d4
#define	PCAP_SWAPPED_MAGIC	0xd4c3b2a1

/* Macros to byte-swap 32-bit and 16-bit quantities. */
#define	BSWAP32(x) \
	((((x)&0xFF000000)>>24) | \
	 (((x)&0x00FF0000)>>8) | \
	 (((x)&0x0000FF00)<<8) | \
	 (((x)&0x000000FF)<<24))
#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))

/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
	guint16	version_major;	/* major version number */
	guint16	version_minor;	/* minor version number */
	gint32	thiszone;	/* GMT to local correction */
	guint32	sigfigs;	/* accuracy of timestamps */
	guint32	snaplen;	/* max length of captured packets, in octets */
	guint32	network;	/* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
	guint32	ts_sec;		/* timestamp seconds */
	guint32	ts_usec;	/* timestamp microseconds */
	guint32	incl_len;	/* number of octets captured in file */
	guint32	orig_len;	/* actual length of packet */
};

/* Returns WTAP_FILE_PCAP on success, WTAP_FILE_UNKNOWN on failure */
int libpcap_open(wtap *wth)
{
	int bytes_read;
	guint32 magic;
	struct pcap_hdr hdr;
	static const int pcap_encap[] = {
		WTAP_ENCAP_NONE,	/* no encapsulation */
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_NONE,	/* 3Mb experimental Ethernet */
		WTAP_ENCAP_NONE,	/* Amateur Radio AX.25 */
		WTAP_ENCAP_NONE,	/* Proteon ProNET Token Ring */
		WTAP_ENCAP_NONE,	/* Chaos */
		WTAP_ENCAP_TR,		/* IEEE 802 Networks - assume token ring */
		WTAP_ENCAP_ARCNET,
		WTAP_ENCAP_SLIP,
		WTAP_ENCAP_PPP,
		WTAP_ENCAP_FDDI,
		WTAP_ENCAP_ATM_RFC1483,
		WTAP_ENCAP_RAW_IP
	};
	#define NUM_PCAP_ENCAPS (sizeof pcap_encap / sizeof pcap_encap[0])
	int byte_swapped = 0;

	/* Read in the number that should be at the start of a "libpcap" file */
	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(&magic, 1, sizeof magic, wth->fh);

	if (bytes_read != sizeof magic) {
		return WTAP_FILE_UNKNOWN;
	}

	if (magic == PCAP_SWAPPED_MAGIC) {
		/* Host that wrote it has a byte order opposite to ours. */
		magic = PCAP_MAGIC;
		byte_swapped = 1;
	}
	if (magic != PCAP_MAGIC) {
		return WTAP_FILE_UNKNOWN;
	}

	/* Read the rest of the header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		return WTAP_FILE_UNKNOWN;
	}

	if (byte_swapped) {
		/* Byte-swap the header fields about which we care. */
		hdr.version_major = BSWAP16(hdr.version_major);
		hdr.version_minor = BSWAP16(hdr.version_minor);
		hdr.snaplen = BSWAP32(hdr.snaplen);
		hdr.network = BSWAP32(hdr.network);
	}
	if (hdr.version_major < 2) {
		/* We only support version 2.0 and later. */
		return WTAP_FILE_UNKNOWN;
	}
	if (hdr.network >= NUM_PCAP_ENCAPS) {
		g_error("pcap: network type %d unknown", hdr.network);
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a libpcap file */
	wth->capture.pcap = g_malloc(sizeof(libpcap_t));
	wth->capture.pcap->byte_swapped = byte_swapped;
	wth->capture.pcap->version_major = hdr.version_major;
	wth->capture.pcap->version_minor = hdr.version_minor;
	wth->subtype_read = libpcap_read;
	wth->file_encap = pcap_encap[hdr.network];
	wth->snapshot_length = hdr.snaplen;

	return WTAP_FILE_PCAP;
}

/* Read the next packet */
int libpcap_read(wtap *wth)
{
	int	packet_size;
	int	bytes_read;
	struct pcaprec_hdr hdr;
	int	data_offset;

	/* Read record header. */
	bytes_read = fread(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		if (bytes_read != 0) {
			g_error("pcap_read: not enough packet header data (%d bytes)",
					bytes_read);
			return -1;
		}
		return 0;
	}

	if (wth->capture.pcap->byte_swapped) {
		/* Byte-swap the record header fields. */
		hdr.ts_sec = BSWAP32(hdr.ts_sec);
		hdr.ts_usec = BSWAP32(hdr.ts_usec);
		hdr.incl_len = BSWAP32(hdr.incl_len);
		hdr.orig_len = BSWAP32(hdr.orig_len);
	}

	/* In file format version 2.3, the "incl_len" and "orig_len" fields
	   were swapped, in order to match the BPF header layout.

	   Unfortunately, some files were, according to a comment in the
	   "libpcap" source, written with version 2.3 in their headers
	   but without the interchanged fields, so if "incl_len" is
	   greater than "orig_len" - which would make no sense - we
	   assume that we need to swap them.  */
	if (wth->capture.pcap->version_major == 2 &&
	    (wth->capture.pcap->version_minor < 3 ||
	     (wth->capture.pcap->version_minor == 3 &&
	      hdr.incl_len > hdr.orig_len))) {
		guint32 temp;

		temp = hdr.orig_len;
		hdr.orig_len = hdr.incl_len;
		hdr.incl_len = temp;
	}

	packet_size = hdr.incl_len;
	buffer_assure_space(wth->frame_buffer, packet_size);
	data_offset = ftell(wth->fh);
	bytes_read = fread(buffer_start_ptr(wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh)) {
			g_error("pcap_read: fread for data: read error\n");
		} else {
			g_error("pcap_read: fread for data: %d bytes out of %d",
				bytes_read, packet_size);
		}
		return -1;
	}

	wth->phdr.ts.tv_sec = hdr.ts_sec;
	wth->phdr.ts.tv_usec = hdr.ts_usec;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = hdr.orig_len;
	wth->phdr.pkt_encap = wth->file_encap;

	return data_offset;
}
