/* libpcap.c
 *
 * $Id: libpcap.c,v 1.22 1999/11/06 08:42:00 guy Exp $
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
#include "wtap.h"
#include "file.h"
#include "buffer.h"
#include "libpcap.h"

/* See source to the "libpcap" library for information on the "libpcap"
   file format. */

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.

   PCAP_MUTANT_MAGIC is for Alexey Kuznetsov's modified "libpcap"
   format, as generated on Linux systems that have a "libpcap" with
   his patches, at
   
	http://ftp.sunet.se/pub/os/Linux/ip-routing/lbl-tools/

   applied; PCAP_SWAPPED_MUTANT_MAGIC is the byte-swapped version. */
#define	PCAP_MAGIC			0xa1b2c3d4
#define	PCAP_SWAPPED_MAGIC		0xd4c3b2a1
#define	PCAP_MUTANT_MAGIC		0xa1b2cd34
#define	PCAP_SWAPPED_MUTANT_MAGIC	0x34cdb2a1

/* Macros to byte-swap 32-bit and 16-bit quantities. */
#define	BSWAP32(x) \
	((((x)&0xFF000000)>>24) | \
	 (((x)&0x00FF0000)>>8) | \
	 (((x)&0x0000FF00)<<8) | \
	 (((x)&0x000000FF)<<24))
#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))

/* On some systems, the FDDI MAC addresses are bit-swapped. */
#if !defined(ultrix) && !defined(__alpha) && !defined(__bsdi__)
#define BIT_SWAPPED_MAC_ADDRS
#endif

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
	guint32	incl_len;	/* number of octets of packet saved in file */
	guint32	orig_len;	/* actual length of packet */
};

/* "libpcap" record header for Alexey's patched version. */
struct pcaprec_mutant_hdr {
	struct pcaprec_hdr hdr;	/* the regular header */
	guint32 ifindex;	/* index, in *capturing* machine's list of
				   interfaces, of the interface on which this
				   packet came in. */
	guint16 protocol;	/* Ethernet packet type */
	guint8 pkt_type;	/* broadcast/multicast/etc. indication */
};

static int libpcap_read(wtap *wth, int *err);
static int libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const u_char *pd, int *err);
static int libpcap_dump_close(wtap_dumper *wdh, int *err);

/*
 * XXX - this is a bit of a mess.  OpenBSD, and perhaps NetBSD, and
 * BSD/OS have different DLT_ codes from FreeBSD (and from the LBL
 * BPF code), and, at least in some cases, from each other.
 * For now, we simply treat those type values with different
 * meanings on different platforms, except for DLT_RAW, as "unknown";
 * this means you won't be able to capture from a network using those
 * types in Ethereal (and that capturing from the loopback interface
 * won't necessarily work right on OpenBSD, either, as it uses
 * DLT_LOOP, which is the same as DLT_RAW on other platforms).
 *
 * Does anybody know what BSD/OS uses as DLT_ types for SLIP and
 * PPP?  The LBL code, and the OpenBSD code, appear to disagree....
 *
 * Nothing in FreeBSD appears to use DLT_RAW, so it's not clear what
 * link-layer header or fake header appears for DLT_RAW.  If it's
 * completely unused, or if it behaves the same way OpenBSD DLT_LOOP
 * behaves, i.e. it puts an address family in *network* byte order
 * (as opposed to the *host* byte order that DLT_NULL uses on FreeBSD),
 * then we should just make it WTAP_ENCAP_NULL, which we treat in
 * such a fashion as to cause it to work with DLT_LOOP headers.
 */
static const int pcap_encap[] = {
	WTAP_ENCAP_NULL,	/* null encapsulation */
	WTAP_ENCAP_ETHERNET,
	WTAP_ENCAP_UNKNOWN,	/* 3Mb experimental Ethernet */
	WTAP_ENCAP_UNKNOWN,	/* Amateur Radio AX.25 */
	WTAP_ENCAP_UNKNOWN,	/* Proteon ProNET Token Ring */
	WTAP_ENCAP_UNKNOWN,	/* Chaos */
	WTAP_ENCAP_TR,		/* IEEE 802 Networks - assume token ring */
	WTAP_ENCAP_ARCNET,
	WTAP_ENCAP_SLIP,
	WTAP_ENCAP_PPP,
#ifdef BIT_SWAPPED_MAC_ADDRS
	WTAP_ENCAP_FDDI_BITSWAPPED,
#else
	WTAP_ENCAP_FDDI,
#endif
	WTAP_ENCAP_ATM_RFC1483,	/* or, on BSD/OS, Frame Relay */
	WTAP_ENCAP_RAW_IP,	/* or, on OpenBSD, DLT_LOOP, and on BSD/OS,
				   Cisco HDLC */
	WTAP_ENCAP_UNKNOWN,	/* In LBL BPF and FreeBSD, BSD/OS SLIP;
				   on OpenBSD, DLT_ENC; on BSD/OS,
				   DLT_ATM_RFC1483 */
	WTAP_ENCAP_UNKNOWN,	/* In LBL BPF and FreeBSD, BSD/OS PPP;
				   on OpenBSD and BSD/OS, DLT_RAW */
	WTAP_ENCAP_UNKNOWN,	/* In OpenBSD and BSD/OS, BSD/OS SLIP,
				   but the BSD/OS header says "internal
				   to libpcap", whatever that means */
	WTAP_ENCAP_UNKNOWN,	/* In OpenBSD and BSD/OS, BSD/OS PPP,
				   but the BSD/OS header says "internal
				   to libpcap", whatever that means */
	WTAP_ENCAP_UNKNOWN,
	WTAP_ENCAP_UNKNOWN,
	WTAP_ENCAP_LINUX_ATM_CLIP
};
#define NUM_PCAP_ENCAPS (sizeof pcap_encap / sizeof pcap_encap[0])

int libpcap_open(wtap *wth, int *err)
{
	int bytes_read;
	guint32 magic;
	struct pcap_hdr hdr;
	gboolean byte_swapped = FALSE;
	gboolean mutant = FALSE;

	/* Read in the number that should be at the start of a "libpcap" file */
	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	switch (magic) {

	case PCAP_MAGIC:
		/* Host that wrote it has our byte order. */
		byte_swapped = FALSE;
		mutant = FALSE;
		break;

	case PCAP_MUTANT_MAGIC:
		/* Host that wrote it has our byte order, but was running
		   a program using the patched "libpcap". */
		byte_swapped = FALSE;
		mutant = TRUE;
		break;

	case PCAP_SWAPPED_MAGIC:
		/* Host that wrote it has a byte order opposite to ours. */
		byte_swapped = TRUE;
		mutant = FALSE;
		break;

	case PCAP_SWAPPED_MUTANT_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using the patched
		   "libpcap". */
		byte_swapped = TRUE;
		mutant = TRUE;
		break;

	default:
		/* Not a "libpcap" type we know about. */
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

	if (byte_swapped) {
		/* Byte-swap the header fields about which we care. */
		hdr.version_major = BSWAP16(hdr.version_major);
		hdr.version_minor = BSWAP16(hdr.version_minor);
		hdr.snaplen = BSWAP32(hdr.snaplen);
		hdr.network = BSWAP32(hdr.network);
	}
	if (hdr.version_major < 2) {
		/* We only support version 2.0 and later. */
		g_message("pcap: major version %u unsupported",
		    hdr.version_major);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}
	if (hdr.network >= NUM_PCAP_ENCAPS
	    || pcap_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("pcap: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/* This is a libpcap file */
	wth->file_type = WTAP_FILE_PCAP;
	wth->capture.pcap = g_malloc(sizeof(libpcap_t));
	wth->capture.pcap->byte_swapped = byte_swapped;
	wth->capture.pcap->mutant = mutant;
	wth->capture.pcap->version_major = hdr.version_major;
	wth->capture.pcap->version_minor = hdr.version_minor;
	wth->subtype_read = libpcap_read;
	wth->file_encap = pcap_encap[hdr.network];
	wth->snapshot_length = hdr.snaplen;
	return 1;
}

/* Read the next packet */
static int libpcap_read(wtap *wth, int *err)
{
	guint	packet_size;
	int	bytes_to_read, bytes_read;
	struct pcaprec_mutant_hdr hdr;
	int	data_offset;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_to_read = wth->capture.pcap->mutant ? sizeof hdr : sizeof hdr.hdr;
	bytes_read = file_read(&hdr, 1, bytes_to_read, wth->fh);
	if (bytes_read != bytes_to_read) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += bytes_read;

	if (wth->capture.pcap->byte_swapped) {
		/* Byte-swap the record header fields. */
		hdr.hdr.ts_sec = BSWAP32(hdr.hdr.ts_sec);
		hdr.hdr.ts_usec = BSWAP32(hdr.hdr.ts_usec);
		hdr.hdr.incl_len = BSWAP32(hdr.hdr.incl_len);
		hdr.hdr.orig_len = BSWAP32(hdr.hdr.orig_len);
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
	      hdr.hdr.incl_len > hdr.hdr.orig_len))) {
		guint32 temp;

		temp = hdr.hdr.orig_len;
		hdr.hdr.orig_len = hdr.hdr.incl_len;
		hdr.hdr.incl_len = temp;
	}

	packet_size = hdr.hdr.incl_len;
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		g_message("pcap: File has %u-byte packet, bigger than maximum of %u",
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

	wth->phdr.ts.tv_sec = hdr.hdr.ts_sec;
	wth->phdr.ts.tv_usec = hdr.hdr.ts_usec;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = hdr.hdr.orig_len;
	wth->phdr.pkt_encap = wth->file_encap;

	return data_offset;
}

int wtap_pcap_encap_to_wtap_encap(int encap)
{
	if (encap < 0 || encap >= NUM_PCAP_ENCAPS)
		return WTAP_ENCAP_UNKNOWN;
	return pcap_encap[encap];
}

/* Returns 1 on success, 0 on failure; sets "*err" to an error code on
   failure */
int libpcap_dump_open(wtap_dumper *wdh, int *err)
{
	static const guint32 pcap_magic = PCAP_MAGIC;
	struct pcap_hdr file_hdr;
	static const int wtap_encap[] = {
		-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
		1,		/* WTAP_ENCAP_ETHERNET -> DLT_EN10MB */
		6,		/* WTAP_ENCAP_TR -> DLT_IEEE802 */
		8,		/* WTAP_ENCAP_SLIP -> DLT_SLIP */
		9,		/* WTAP_ENCAP_PPP -> DLT_PPP */
		10,		/* WTAP_ENCAP_FDDI -> DLT_FDDI */
		10,		/* WTAP_ENCAP_FDDI_BITSWAPPED -> DLT_FDDI */
		12,		/* WTAP_ENCAP_RAW_IP -> DLT_RAW */
		7,		/* WTAP_ENCAP_ARCNET -> DLT_ARCNET */
		11,		/* WTAP_ENCAP_ATM_RFC1483 -> DLT_ATM_RFC1483 */
		19,		/* WTAP_ENCAP_LINUX_ATM_CLIP */
		-1,		/* WTAP_ENCAP_LAPB -> unsupported*/
		-1,		/* WTAP_ENCAP_ATM_SNIFFER -> unsupported */
		0		/* WTAP_ENCAP_NULL -> DLT_NULL */
	};
	#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])
	int nwritten;

	/* Per-packet encapsulations aren't supported. */
	if (wdh->encap == WTAP_ENCAP_PER_PACKET) {
		*err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
		return 0;
	}

	if (wdh->encap < 0 || wdh->encap >= NUM_WTAP_ENCAPS
	    || wtap_encap[wdh->encap] == -1) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return 0;
	}

	/* This is a libpcap file */
	wdh->subtype_write = libpcap_dump;
	wdh->subtype_close = libpcap_dump_close;

	/* Write the file header. */
	nwritten = fwrite(&pcap_magic, 1, sizeof pcap_magic, wdh->fh);
	if (nwritten != sizeof pcap_magic) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return 0;
	}

	/* current "libpcap" format is 2.4 */
	file_hdr.version_major = 2;
	file_hdr.version_minor = 4;
	file_hdr.thiszone = 0;	/* XXX - current offset? */
	file_hdr.sigfigs = 0;	/* unknown, but also apparently unused */
	file_hdr.snaplen = wdh->snaplen;
	file_hdr.network = wtap_encap[wdh->encap];
	nwritten = fwrite(&file_hdr, 1, sizeof file_hdr, wdh->fh);
	if (nwritten != sizeof file_hdr) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return 0;
	}

	return 1;
}

/* Write a record for a packet to a dump file.
   Returns 1 on success, 0 on failure. */
static int libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const u_char *pd, int *err)
{
	struct pcaprec_hdr rec_hdr;
	int nwritten;

	rec_hdr.ts_sec = phdr->ts.tv_sec;
	rec_hdr.ts_usec = phdr->ts.tv_usec;
	rec_hdr.incl_len = phdr->caplen;
	rec_hdr.orig_len = phdr->len;
	nwritten = fwrite(&rec_hdr, 1, sizeof rec_hdr, wdh->fh);
	if (nwritten != sizeof rec_hdr) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return 0;
	}
	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return 0;
	}
	return 1;
}

/* Finish writing to a dump file.
   Returns 1 on success, 0 on failure. */
static int libpcap_dump_close(wtap_dumper *wdh, int *err)
{
	/* Nothing to do here. */
	return 1;
}
