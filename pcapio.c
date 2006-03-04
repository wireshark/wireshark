/* pcapio.c
 * Our own private code for writing libpcap files when capturing.
 *
 * We have these because we want a way to open a stream for output given
 * only a file descriptor.  libpcap 0.9[.x] has "pcap_dump_fopen()", which
 * provides that, but
 *
 *	1) earlier versions of libpcap doesn't have it
 *
 * and
 *
 *	2) WinPcap doesn't have it, because a file descriptor opened
 *	   by code built for one version of the MSVC++ C library
 *	   can't be used by library routines built for another version
 *	   (e.g., threaded vs. unthreaded).
 *
 * Libpcap's pcap_dump() also doesn't return any error indications.
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
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
#include <stdio.h>
#include <errno.h>

#include <pcap.h>

#include <glib.h>

#include "pcapio.h"

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.

   PCAP_NSEC_MAGIC is for Ulf Lamping's modified "libpcap" format,
   which uses the same common file format as PCAP_MAGIC, but the 
   timestamps are saved in nanosecond resolution instead of microseconds.
   PCAP_SWAPPED_NSEC_MAGIC is a byte-swapped version of that. */
#define	PCAP_MAGIC			0xa1b2c3d4
#define	PCAP_SWAPPED_MAGIC		0xd4c3b2a1
#define	PCAP_NSEC_MAGIC			0xa1b23c4d
#define	PCAP_SWAPPED_NSEC_MAGIC		0x4d3cb2a1

/* "libpcap" file header. */
struct pcap_hdr {
	guint32 magic;		/* magic number */
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
	guint32	ts_usec;	/* timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) */
	guint32	incl_len;	/* number of octets of packet saved in file */
	guint32	orig_len;	/* actual length of packet */
};

/* Returns a FILE * to write to on success, NULL on failure; sets "*err" to
   an error code, or 0 for a short write, on failure */
FILE *
libpcap_fdopen(int fd, int linktype, int snaplen, long *bytes_written,
    int *err)
{
	FILE *fp;
	struct pcap_hdr file_hdr;
	size_t nwritten;

	fp = fdopen(fd, "wb");
	if (fp == NULL) {
		*err = errno;
		return NULL;
	}

	file_hdr.magic = PCAP_MAGIC;
	/* current "libpcap" format is 2.4 */
	file_hdr.version_major = 2;
	file_hdr.version_minor = 4;
	file_hdr.thiszone = 0;	/* XXX - current offset? */
	file_hdr.sigfigs = 0;	/* unknown, but also apparently unused */
	file_hdr.snaplen = snaplen;
	file_hdr.network = linktype;
	nwritten = fwrite(&file_hdr, 1, sizeof file_hdr, fp);
	if (nwritten != sizeof file_hdr) {
		if (nwritten == 0 && ferror(fp))
			*err = errno;
		else
			*err = 0;	/* short write */
		fclose(fp);
		return NULL;
	}
	*bytes_written = sizeof file_hdr;

	return fp;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
gboolean
libpcap_write_packet(FILE *fp, const struct pcap_pkthdr *phdr, const u_char *pd,
    long *bytes_written, int *err)
{
	struct pcaprec_hdr rec_hdr;
	size_t nwritten;

	rec_hdr.ts_sec = phdr->ts.tv_sec;
	rec_hdr.ts_usec = phdr->ts.tv_usec;
	rec_hdr.incl_len = phdr->caplen;
	rec_hdr.orig_len = phdr->len;
	nwritten = fwrite(&rec_hdr, 1, sizeof rec_hdr, fp);
	if (nwritten != sizeof rec_hdr) {
		if (nwritten == 0 && ferror(fp))
			*err = errno;
		else
			*err = 0;	/* short write */
		return FALSE;
	}
	*bytes_written += sizeof rec_hdr;

	nwritten = fwrite(pd, 1, phdr->caplen, fp);
	if (nwritten != phdr->caplen) {
		if (nwritten == 0 && ferror(fp))
			*err = errno;
		else
			*err = 0;	/* short write */
		return FALSE;
	}
	*bytes_written += phdr->caplen;
	return TRUE;
}

gboolean
libpcap_dump_flush(FILE *pd, int *err)
{
	if (fflush(pd) == EOF) {
		if (err != NULL)
			*err = errno;
		return FALSE;
	}
	return TRUE;
}

gboolean
libpcap_dump_close(FILE *pd, int *err)
{
	if (fclose(pd) == EOF) {
		if (err != NULL)
			*err = errno;
		return FALSE;
	}
	return TRUE;
}
