/* libpcap.c
 *
 * $Id: libpcap.c,v 1.37 2000/07/30 16:54:11 oabad Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "libpcap.h"

/* See source to the "libpcap" library for information on the "libpcap"
   file format. */

/* On some systems, the FDDI MAC addresses are bit-swapped. */
#if !defined(ultrix) && !defined(__alpha) && !defined(__bsdi__)
#define BIT_SWAPPED_MAC_ADDRS
#endif

static int libpcap_read(wtap *wth, int *err);
static void adjust_header(wtap *wth, struct pcaprec_hdr *hdr);
static void libpcap_close(wtap *wth);
static gboolean libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err);

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
				   to libpcap", whatever that means;
				   in Linux with the ISDN4Linux patches
				   applied to libpcap, DLT_I4L_RAWIP,
				   which looks just like DLT_RAW but
				   is given a different DLT_ code for
				   no obvious good reason */
	WTAP_ENCAP_UNKNOWN,	/* In OpenBSD and BSD/OS, BSD/OS PPP,
				   but the BSD/OS header says "internal
				   to libpcap", whatever that means;
				   in Linux with the ISDN4Linux patches
				   applied to libpcap, DLT_I4L_IP,
				   which provides only a 2-octet
				   Ethernet type as a link-layer header,
				   with a type of 0xFFFF meaning
				   ETH_P_802_3, a "Dummy type for 802.3
				   frames" */
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
	gboolean byte_swapped;
	gboolean modified;
	struct pcaprec_modified_hdr first_rec_hdr;
	struct pcaprec_modified_hdr second_rec_hdr;
	int hdr_len;

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
		/* Host that wrote it has our byte order, and was running
		   a program using either standard or ss990417 libpcap. */
		byte_swapped = FALSE;
		modified = FALSE;
		break;

	case PCAP_MODIFIED_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either ss990915 or ss991029 libpcap. */
		byte_swapped = FALSE;
		modified = TRUE;
		break;

	case PCAP_SWAPPED_MAGIC:
		/* Host that wrote it has a byte order opposite to ours,
		   and was running a program using either standard or
		   ss990417 libpcap. */
		byte_swapped = TRUE;
		modified = FALSE;
		break;

	case PCAP_SWAPPED_MODIFIED_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using either ss990915
		   or ss991029 libpcap. */
		byte_swapped = TRUE;
		modified = TRUE;
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
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/* This is a libpcap file */
	wth->file_type = modified ? WTAP_FILE_PCAP_SS991029 : WTAP_FILE_PCAP;
	wth->capture.pcap = g_malloc(sizeof(libpcap_t));
	wth->capture.pcap->byte_swapped = byte_swapped;
	wth->capture.pcap->version_major = hdr.version_major;
	wth->capture.pcap->version_minor = hdr.version_minor;
	wth->subtype_read = libpcap_read;
	wth->subtype_seek_read = wtap_def_seek_read;
	wth->subtype_close = libpcap_close;
	wth->file_encap = pcap_encap[hdr.network];
	wth->snapshot_length = hdr.snaplen;

	/*
	 * Yes.  Let's look at the header for the first record,
	 * and see if, interpreting it as a standard header (if the
	 * magic number was standard) or a modified header (if the
	 * magic number was modified), the position where it says the
	 * header for the *second* record is contains a corrupted header.
	 *
	 * If so, then:
	 *
	 *	If this file had the standard magic number, it may be
	 *	an ss990417 capture file - in that version of Alexey's
	 *	patch, the packet header format was changed but the
	 *	magic number wasn't, and, alas, Red Hat appear to have
	 *	picked up that version of the patch for RH 6.1, meaning
	 *	RH 6.1 has a tcpdump that writes out files that can't
	 *	be read by any software that expects non-modified headers
	 *	if the magic number isn't the modified magic number (e.g.,
	 *	any normal version of tcpdump, and Ethereal if we don't
	 *	do this gross heuristic).
	 *
	 *	If this file had the modified magic number, it may be
	 *	an ss990915 capture file - in that version of Alexey's
	 *	patch, the magic number was changed, but the record
	 *	header had some extra fields, and, alas, SuSE appear
	 *	to have picked up that version of the patch for SuSE
	 *	6.3, meaning that programs expecting the standard per-
	 *	packet header in captures with the modified magic number
	 *	can't read dumps from its tcpdump.
	 */
	hdr_len = modified ? sizeof (struct pcaprec_modified_hdr) :
			     sizeof (struct pcaprec_hdr);
	bytes_read = file_read(&first_rec_hdr, 1, hdr_len, wth->fh);
	if (bytes_read != hdr_len) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;	/* failed to read it */

		/*
		 * Short read - assume the file isn't modified,
		 * and put the seek pointer back.  The attempt
		 * to read the first packet will presumably get
		 * the same short read.
		 */
		goto give_up;
	}

	adjust_header(wth, &first_rec_hdr.hdr);

	if (first_rec_hdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
		/*
		 * The first record is bogus, so this is probably
		 * a corrupt file.  Assume the file has the
		 * expected header type, and put the seek pointer
		 * back.  The attempt to read the first packet will
		 * probably get the same bogus length.
		 */
		goto give_up;
	}

	file_seek(wth->fh,
	    wth->data_offset + hdr_len + first_rec_hdr.hdr.incl_len, SEEK_SET);
	bytes_read = file_read(&second_rec_hdr, 1, hdr_len, wth->fh);

	/*
	 * OK, does the next packet's header look sane?
	 */
	if (bytes_read != hdr_len) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;	/* failed to read it */

		/*
		 * Short read - assume the file has the expected
		 * header type, and put the seek pointer back.  The
		 * attempt to read the second packet will presumably get
		 * the same short read error.
		 */
		goto give_up;
	}

	adjust_header(wth, &second_rec_hdr.hdr);
	if (second_rec_hdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Oh, dear.  Maybe it's a Capture File
		 * From Hell, and what looks like the
		 * "header" of the next packet is actually
		 * random junk from the middle of a packet.
		 * Try treating it as having the other type for
		 * the magic number it had; if that doesn't work,
		 * it probably *is* a corrupt file.
		 */
		wth->file_type = modified ? WTAP_FILE_PCAP_SS990915 :
					    WTAP_FILE_PCAP_SS990417;
	}

give_up:
	/*
	 * Restore the seek pointer.
	 */
	file_seek(wth->fh, wth->data_offset, SEEK_SET);

	return 1;
}

/* Read the next packet */
static int libpcap_read(wtap *wth, int *err)
{
	guint	packet_size;
	int	bytes_to_read, bytes_read;
	struct pcaprec_ss990915_hdr hdr;
	int	data_offset;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	switch (wth->file_type) {

	case WTAP_FILE_PCAP:
		bytes_to_read = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_PCAP_SS990417:
	case WTAP_FILE_PCAP_SS991029:
		bytes_to_read = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_PCAP_SS990915:
		bytes_to_read = sizeof (struct pcaprec_ss990915_hdr);
		break;

	default:
		g_assert_not_reached();
		bytes_to_read = 0;
	}
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

	adjust_header(wth, &hdr.hdr);

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

static void
adjust_header(wtap *wth, struct pcaprec_hdr *hdr)
{
	if (wth->capture.pcap->byte_swapped) {
		/* Byte-swap the record header fields. */
		hdr->ts_sec = BSWAP32(hdr->ts_sec);
		hdr->ts_usec = BSWAP32(hdr->ts_usec);
		hdr->incl_len = BSWAP32(hdr->incl_len);
		hdr->orig_len = BSWAP32(hdr->orig_len);
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
	      hdr->incl_len > hdr->orig_len))) {
		guint32 temp;

		temp = hdr->orig_len;
		hdr->orig_len = hdr->incl_len;
		hdr->incl_len = temp;
	}
}

static void
libpcap_close(wtap *wth)
{
	g_free(wth->capture.pcap);
}

int wtap_pcap_encap_to_wtap_encap(int encap)
{
	if (encap < 0 || encap >= NUM_PCAP_ENCAPS)
		return WTAP_ENCAP_UNKNOWN;
	return pcap_encap[encap];
}

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

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int libpcap_dump_can_write_encap(int filetype, int encap)
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
gboolean libpcap_dump_open(wtap_dumper *wdh, int *err)
{
	guint32 magic;
	struct pcap_hdr file_hdr;
	int nwritten;

	/* This is a libpcap file */
	wdh->subtype_write = libpcap_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
		magic = PCAP_MAGIC;
		break;

	case WTAP_FILE_PCAP_SS990915:	/* new magic, extra crap */
	case WTAP_FILE_PCAP_SS991029:
		magic = PCAP_MODIFIED_MAGIC;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	nwritten = fwrite(&magic, 1, sizeof magic, wdh->fh);
	if (nwritten != sizeof magic) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
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
		return FALSE;
	}

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err)
{
	struct pcaprec_ss990915_hdr rec_hdr;
	int hdr_size;
	int nwritten;

	rec_hdr.hdr.ts_sec = phdr->ts.tv_sec;
	rec_hdr.hdr.ts_usec = phdr->ts.tv_usec;
	rec_hdr.hdr.incl_len = phdr->caplen;
	rec_hdr.hdr.orig_len = phdr->len;
	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
		hdr_size = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_PCAP_SS991029:
		/* XXX - what should we supply here?

		   Alexey's "libpcap" looks up the interface in the system's
		   interface list if "ifindex" is non-zero, and prints
		   the interface name.  It ignores "protocol", and uses
		   "pkt_type" to tag the packet as "host", "broadcast",
		   "multicast", "other host", "outgoing", or "none of the
		   above", but that's it.

		   If the capture we're writing isn't a modified or
		   RH 6.1 capture, we'd have to do some work to
		   generate the packet type and interface index - and
		   we can't generate the interface index unless we
		   just did the capture ourselves in any case.

		   I'm inclined to continue to punt; systems other than
		   those with the older patch can read standard "libpcap"
		   files, and systems with the older patch, e.g. RH 6.1,
		   will just have to live with this. */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		hdr_size = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_PCAP_SS990915:	/* new magic, extra crap at the end */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_ss990915_hdr);
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		g_assert_not_reached();
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	nwritten = fwrite(&rec_hdr, 1, hdr_size, wdh->fh);
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
	return TRUE;
}
