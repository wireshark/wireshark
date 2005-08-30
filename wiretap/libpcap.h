/* libpcap.h
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

#ifndef __W_LIBPCAP_H__
#define __W_LIBPCAP_H__

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.

   PCAP_MODIFIED_MAGIC is for Alexey Kuznetsov's modified "libpcap"
   format, as generated on Linux systems that have a "libpcap" with
   his patches, at

	http://ftp.sunet.se/pub/os/Linux/ip-routing/lbl-tools/

   applied; PCAP_SWAPPED_MODIFIED_MAGIC is the byte-swapped version. 

   PCAP_NSEC_MAGIC is for Ulf Lamping's modified "libpcap" format,
   which uses the same common file format as PCAP_MAGIC, but the 
   timestamps are saved in nanosecond resolution instead of microseconds.
   PCAP_SWAPPED_NSEC_MAGIC is a byte-swapped version of that. */
#define	PCAP_MAGIC			0xa1b2c3d4
#define	PCAP_SWAPPED_MAGIC		0xd4c3b2a1
#define	PCAP_MODIFIED_MAGIC		0xa1b2cd34
#define	PCAP_SWAPPED_MODIFIED_MAGIC	0x34cdb2a1
#define	PCAP_NSEC_MAGIC			0xa1b23c4d
#define	PCAP_SWAPPED_NSEC_MAGIC		0x4d3cb2a1

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
	guint32	ts_usec;	/* timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) */
	guint32	incl_len;	/* number of octets of packet saved in file */
	guint32	orig_len;	/* actual length of packet */
};

/* "libpcap" record header for Alexey's patched version. */
struct pcaprec_modified_hdr {
	struct pcaprec_hdr hdr;	/* the regular header */
	guint32 ifindex;	/* index, in *capturing* machine's list of
				   interfaces, of the interface on which this
				   packet came in. */
	guint16 protocol;	/* Ethernet packet type */
	guint8 pkt_type;	/* broadcast/multicast/etc. indication */
	guint8 pad;		/* pad to a 4-byte boundary */
};

/* "libpcap" record header for Alexey's patched version in its ss990915
   incarnation; this version shows up in SuSE Linux 6.3. */
struct pcaprec_ss990915_hdr {
	struct pcaprec_hdr hdr;	/* the regular header */
	guint32 ifindex;	/* index, in *capturing* machine's list of
				   interfaces, of the interface on which this
				   packet came in. */
	guint16 protocol;	/* Ethernet packet type */
	guint8 pkt_type;	/* broadcast/multicast/etc. indication */
	guint8 cpu1, cpu2;	/* SMP debugging gunk? */
	guint8 pad[3];		/* pad to a 4-byte boundary */
};

/* "libpcap" record header for version used on some Nokia boxes (firewalls?) */
struct pcaprec_nokia_hdr {
	struct pcaprec_hdr hdr;	/* the regular header */
	guint8 stuff[4];	/* mysterious stuff */
};

int libpcap_open(wtap *wth, int *err, gchar **err_info);
gboolean libpcap_dump_open(wtap_dumper *wdh, gboolean cant_seek, int *err);
int libpcap_dump_can_write_encap(int encap);

#endif
