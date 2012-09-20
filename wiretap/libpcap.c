/* libpcap.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "pcap-common.h"
#include "pcap-encap.h"
#include "libpcap.h"
#include "erf.h"

/* See source to the "libpcap" library for information on the "libpcap"
   file format. */

/*
 * Private per-wtap_t data needed to read a file.
 */
typedef enum {
	NOT_SWAPPED,
	SWAPPED,
	MAYBE_SWAPPED
} swapped_type_t;

typedef struct {
	gboolean byte_swapped;
	swapped_type_t lengths_swapped;
	guint16	version_major;
	guint16	version_minor;
} libpcap_t;

/* On some systems, the FDDI MAC addresses are bit-swapped. */
#if !defined(ultrix) && !defined(__alpha) && !defined(__bsdi__)
#define BIT_SWAPPED_MAC_ADDRS
#endif

/* Try to read the first two records of the capture file. */
typedef enum {
	THIS_FORMAT,		/* the reads succeeded, assume it's this format */
	BAD_READ,		/* the file is probably not valid */
	OTHER_FORMAT		/* the file may be valid, but not in this format */
} libpcap_try_t;
static libpcap_try_t libpcap_try(wtap *wth, int *err);

static gboolean libpcap_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean libpcap_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static int libpcap_read_header(wtap *wth, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr);
static void adjust_header(wtap *wth, struct pcaprec_hdr *hdr);
static gboolean libpcap_read_rec_data(FILE_T fh, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err);

int libpcap_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	guint32 magic;
	struct pcap_hdr hdr;
	gboolean byte_swapped;
	gboolean modified;
	gboolean aix;
	int file_encap;
	gint64 first_packet_offset;
	libpcap_t *libpcap;

	/* Read in the number that should be at the start of a "libpcap" file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&magic, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	switch (magic) {

	case PCAP_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either standard or ss990417 libpcap. */
		byte_swapped = FALSE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_MODIFIED_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either ss990915 or ss991029 libpcap. */
		byte_swapped = FALSE;
		modified = TRUE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_SWAPPED_MAGIC:
		/* Host that wrote it has a byte order opposite to ours,
		   and was running a program using either standard or
		   ss990417 libpcap. */
		byte_swapped = TRUE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_SWAPPED_MODIFIED_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using either ss990915
		   or ss991029 libpcap. */
		byte_swapped = TRUE;
		modified = TRUE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_NSEC_MAGIC:
		/* Host that wrote it has our byte order, and was writing
		   the file in a format similar to standard libpcap
		   except that the time stamps have nanosecond resolution. */
		byte_swapped = FALSE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;

	case PCAP_SWAPPED_NSEC_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was writing the file in a format similar to
		   standard libpcap except that the time stamps have
		   nanosecond resolution. */
		byte_swapped = TRUE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;

	default:
		/* Not a "libpcap" type we know about. */
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
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
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("pcap: major version %u unsupported",
		    hdr.version_major);
		return -1;
	}

	/*
	 * AIX's non-standard tcpdump uses a minor version number of 2.
	 * Unfortunately, older versions of libpcap might have used
	 * that as well.
	 *
	 * The AIX libpcap uses RFC 1573 ifType values rather than
	 * DLT_ values in the header; the ifType values for LAN devices
	 * are:
	 *
	 *	Ethernet	6
	 *	Token Ring	9
	 *	FDDI		15
	 *
	 * which correspond to DLT_IEEE802 (used for Token Ring),
	 * DLT_PPP, and DLT_SLIP_BSDOS, respectively.  The ifType value
	 * for a loopback interface is 24, which currently isn't
	 * used by any version of libpcap I know about (and, as
	 * tcpdump.org are assigning DLT_ values above 100, and
	 * NetBSD started assigning values starting at 50, and
	 * the values chosen by other libpcaps appear to stop at
	 * 19, it's probably not going to be used by any libpcap
	 * in the future).
	 *
	 * We shall assume that if the minor version number is 2, and
	 * the network type is 6, 9, 15, or 24, that it's AIX libpcap.
	 *
	 * I'm assuming those older versions of libpcap didn't
	 * use DLT_IEEE802 for Token Ring, and didn't use DLT_SLIP_BSDOS
	 * as that came later.  It may have used DLT_PPP, however, in
	 * which case we're out of luck; we assume it's Token Ring
	 * in AIX libpcap rather than PPP in standard libpcap, as
	 * you're probably more likely to be handing an AIX libpcap
	 * token-ring capture than an old (pre-libpcap 0.4) PPP capture
	 * to Wireshark.
	 */
	aix = FALSE;	/* assume it's not AIX */
	if (hdr.version_major == 2 && hdr.version_minor == 2) {
		switch (hdr.network) {

		case 6:
			hdr.network = 1;	/* DLT_EN10MB, Ethernet */
			aix = TRUE;
			break;

		case 9:
			hdr.network = 6;	/* DLT_IEEE802, Token Ring */
			aix = TRUE;
			break;

		case 15:
			hdr.network = 10;	/* DLT_FDDI, FDDI */
			aix = TRUE;
			break;

		case 24:
			hdr.network = 0;	/* DLT_NULL, loopback */
			aix = TRUE;
			break;
		}
	}

	file_encap = wtap_pcap_encap_to_wtap_encap(hdr.network);
	if (file_encap == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("pcap: network type %u unknown or unsupported",
		    hdr.network);
		return -1;
	}

	/* This is a libpcap file */
	libpcap = (libpcap_t *)g_malloc(sizeof(libpcap_t));
	libpcap->byte_swapped = byte_swapped;
	libpcap->version_major = hdr.version_major;
	libpcap->version_minor = hdr.version_minor;
	wth->priv = (void *)libpcap;
	wth->subtype_read = libpcap_read;
	wth->subtype_seek_read = libpcap_seek_read;
	wth->file_encap = file_encap;
	wth->snapshot_length = hdr.snaplen;

	/* In file format version 2.3, the order of the "incl_len" and
	   "orig_len" fields in the per-packet header was reversed,
	   in order to match the BPF header layout.

	   Therefore, in files with versions prior to that, we must swap
	   those two fields.

	   Unfortunately, some files were, according to a comment in the
	   "libpcap" source, written with version 2.3 in their headers
	   but without the interchanged fields, so if "incl_len" is
	   greater than "orig_len" - which would make no sense - we
	   assume that we need to swap them in version 2.3 files
	   as well.

	   In addition, DG/UX's tcpdump uses version 543.0, and writes
	   the two fields in the pre-2.3 order. */
	switch (hdr.version_major) {

	case 2:
		if (hdr.version_minor < 3)
			libpcap->lengths_swapped = SWAPPED;
		else if (hdr.version_minor == 3)
			libpcap->lengths_swapped = MAYBE_SWAPPED;
		else
			libpcap->lengths_swapped = NOT_SWAPPED;
		break;

	case 543:
		libpcap->lengths_swapped = SWAPPED;
		break;

	default:
		libpcap->lengths_swapped = NOT_SWAPPED;
		break;
	}

	/*
	 * Is this AIX format?
	 */
	if (aix) {
		/*
		 * Yes.  Skip all the tests for other mutant formats,
		 * and for the ERF link-layer header type, and set the
		 * precision to nanosecond precision.
		 */
		wth->file_type = WTAP_FILE_PCAP_AIX;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		return 1;
	}

	/*
	 * No.  Let's look at the header for the first record,
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
	 *	any normal version of tcpdump, and Wireshark if we don't
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
	 *
	 * Oh, and if it has the standard magic number, it might, instead,
	 * be a Nokia libpcap file, so we may need to try that if
	 * neither normal nor ss990417 headers work.
	 */
	if (modified) {
		/*
		 * Well, we have the magic number from Alexey's
		 * later two patches.
		 *
		 * Try ss991029, the last of his patches, first.
		 */
		wth->file_type = WTAP_FILE_PCAP_SS991029;
		first_packet_offset = file_tell(wth->fh);
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			g_free(wth->priv);
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be 991029.
			 * Put the seek pointer back, and finish.
			 */
			if (file_seek(wth->fh, first_packet_offset, SEEK_SET, err) == -1) {
				g_free(wth->priv);
				return -1;
			}
			goto done;

		case OTHER_FORMAT:
			/*
			 * Try the next format.
			 */
			break;
		}

		/*
		 * Well, it's not completely unreadable,
		 * but it's not ss991029.  Try ss990915;
		 * there are no other types to try after that,
		 * so we put the seek pointer back and treat
		 * it as 990915.
		 */
		wth->file_type = WTAP_FILE_PCAP_SS990915;
		if (file_seek(wth->fh, first_packet_offset, SEEK_SET, err) == -1) {
			g_free(wth->priv);
			return -1;
		}
	} else {
		/*
		 * Well, we have the standard magic number.
		 *
		 * Try the standard format first.
		 */
		if(wth->tsprecision == WTAP_FILE_TSPREC_NSEC) {
			wth->file_type = WTAP_FILE_PCAP_NSEC;
		} else {
			wth->file_type = WTAP_FILE_PCAP;
		}
		first_packet_offset = file_tell(wth->fh);
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			g_free(wth->priv);
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be a standard
			 * libpcap file.
			 * Put the seek pointer back, and finish.
			 */
			if (file_seek(wth->fh, first_packet_offset, SEEK_SET, err) == -1) {
				g_free(wth->priv);
				return -1;
			}
			goto done;

		case OTHER_FORMAT:
			/*
			 * Try the next format.
			 */
			break;
		}

		/*
		 * Well, it's not completely unreadable, but it's not
		 * a standard file.  Put the seek pointer back and try
		 * ss990417.
		 */
		wth->file_type = WTAP_FILE_PCAP_SS990417;
		if (file_seek(wth->fh, first_packet_offset, SEEK_SET, err) == -1) {
			g_free(wth->priv);
			return -1;
		}
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			g_free(wth->priv);
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be ss990417.
			 * Put the seek pointer back, and finish.
			 */
			if (file_seek(wth->fh, first_packet_offset, SEEK_SET, err) == -1) {
				g_free(wth->priv);
				return -1;
			}
			goto done;

		case OTHER_FORMAT:
			/*
			 * Try the next format.
			 */
			break;
		}

		/*
		 * Well, it's not completely unreadable,
		 * but it's not a standard file *nor* is it ss990417.
		 * Try it as a Nokia file; there are no other types
		 * to try after that, so we put the seek pointer back
		 * and treat it as a Nokia file.
		 */
		wth->file_type = WTAP_FILE_PCAP_NOKIA;
		if (file_seek(wth->fh, first_packet_offset, SEEK_SET, err) == -1) {
			g_free(wth->priv);
			return -1;
		}
	}

done:
	/*
	 * We treat a DLT_ value of 13 specially - it appears that in
	 * Nokia libpcap format, it's some form of ATM with what I
	 * suspect is a pseudo-header (even though Nokia's IPSO is
	 * based on FreeBSD, which #defines DLT_SLIP_BSDOS as 13).
	 *
	 * If this is a Nokia capture, treat 13 as WTAP_ENCAP_ATM_PDUS,
	 * rather than as what we normally treat it.
	 */
	if (wth->file_type == WTAP_FILE_PCAP_NOKIA && hdr.network == 13)
		wth->file_encap = WTAP_ENCAP_ATM_PDUS;

	if (wth->file_encap == WTAP_ENCAP_ERF) {
		/*
		 * Populate set of interface IDs for ERF format.
		 * Currently, this *has* to be done at open time.
		 */
		erf_populate_interfaces(wth);
	}
	return 1;
}

/* Try to read the first two records of the capture file. */
static libpcap_try_t libpcap_try(wtap *wth, int *err)
{
	/*
	 * pcaprec_ss990915_hdr is the largest header type.
	 */
	struct pcaprec_ss990915_hdr first_rec_hdr, second_rec_hdr;


	/*
	 * Attempt to read the first record's header.
	 */
	if (libpcap_read_header(wth, err, NULL, &first_rec_hdr) == -1) {
		if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
			/*
			 * EOF or short read - assume the file is in this
			 * format.
			 * When our client tries to read the first packet
			 * they will presumably get the same EOF or short
			 * read.
			 */
			return THIS_FORMAT;
		}

		if (*err == WTAP_ERR_BAD_FILE) {
			/*
			 * The first record is bogus, so this is probably
			 * a corrupt file.  Assume the file is in this
			 * format.  When our client tries to read the
			 * first packet they will presumably get the
			 * same bogus record.
			 */
			return THIS_FORMAT;
		}

		/*
		 * Some other error, e.g. an I/O error; just give up.
		 */
		return BAD_READ;
	}

	/*
	 * Now skip over the first record's data, under the assumption
	 * that the header is sane.
	 */
	if (file_seek(wth->fh, first_rec_hdr.hdr.incl_len, SEEK_CUR, err) == -1)
		return BAD_READ;

	/*
	 * Now attempt to read the second record's header.
	 */
	if (libpcap_read_header(wth, err, NULL, &second_rec_hdr) == -1) {
		if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
			/*
			 * EOF or short read - assume the file is in this
			 * format.
			 * When our client tries to read the second packet
			 * they will presumably get the same EOF or short
			 * read.
			 */
			return THIS_FORMAT;
		}

		if (*err == WTAP_ERR_BAD_FILE) {
			/*
			 * The second record is bogus; maybe it's a
			 * Capture File From Hell, and what looks like
			 * the "header" of the next packet is actually
			 * random junk from the middle of a packet.
			 * Try the next format; if we run out of formats,
			 * it probably *is* a corrupt file.
			 */
			return OTHER_FORMAT;
		}

		/*
		 * Some other error, e.g. an I/O error; just give up.
		 */
		return BAD_READ;
	}

	/*
	 * OK, the first two records look OK; assume this is the
	 * right format.
	 */
	return THIS_FORMAT;
}

/* Read the next packet */
static gboolean libpcap_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	struct pcaprec_ss990915_hdr hdr;
	guint packet_size;
	guint orig_size;
	int bytes_read;
	guint8 fddi_padding[3];
	int phdr_len;
	libpcap_t *libpcap;

	bytes_read = libpcap_read_header(wth, err, err_info, &hdr);
	if (bytes_read == -1) {
		/*
		 * We failed to read the header.
		 */
		return FALSE;
	}

	packet_size = hdr.hdr.incl_len;
	orig_size = hdr.hdr.orig_len;

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (wth->file_type == WTAP_FILE_PCAP_AIX &&
	    (wth->file_encap == WTAP_ENCAP_FDDI ||
	     wth->file_encap == WTAP_ENCAP_FDDI_BITSWAPPED)) {
		/*
		 * The packet size is really a record size and includes
		 * the padding.
		 */
		packet_size -= 3;
		orig_size -= 3;

		/*
		 * Read the padding.
		 */
		if (!libpcap_read_rec_data(wth->fh, fddi_padding, 3, err,
		    err_info))
			return FALSE;	/* Read error */
	}

	*data_offset = file_tell(wth->fh);

	libpcap = (libpcap_t *)wth->priv;
	phdr_len = pcap_process_pseudo_header(wth->fh, wth->file_type,
	    wth->file_encap, packet_size, TRUE, &wth->phdr,
	    &wth->pseudo_header, err, err_info);
	if (phdr_len < 0)
		return FALSE;	/* error */

	/*
	 * Don't count any pseudo-header as part of the packet.
	 */
	orig_size -= phdr_len;
	packet_size -= phdr_len;

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!libpcap_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
	    packet_size, err, err_info))
		return FALSE;	/* Read error */

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	/* Update the Timestamp, if not already done */
	if (wth->file_encap != WTAP_ENCAP_ERF) {
	  wth->phdr.ts.secs = hdr.hdr.ts_sec;
	  if(wth->tsprecision == WTAP_FILE_TSPREC_NSEC) {
	    wth->phdr.ts.nsecs = hdr.hdr.ts_usec;
	  } else {
	    wth->phdr.ts.nsecs = hdr.hdr.ts_usec * 1000;
	  }
	} else {
	  /* Set interface ID for ERF format */
	  wth->phdr.presence_flags |= WTAP_HAS_INTERFACE_ID;
	  wth->phdr.interface_id = wth->pseudo_header.erf.phdr.flags & 0x03;
	}
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;

	pcap_read_post_process(wth->file_type, wth->file_encap,
	    &wth->pseudo_header, buffer_start_ptr(wth->frame_buffer),
	    wth->phdr.caplen, libpcap->byte_swapped, -1);
	return TRUE;
}

static gboolean
libpcap_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	int phdr_len;
	libpcap_t *libpcap;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	libpcap = (libpcap_t *)wth->priv;
	phdr_len = pcap_process_pseudo_header(wth->random_fh, wth->file_type,
	    wth->file_encap, length, FALSE, NULL, pseudo_header, err, err_info);
	if (phdr_len < 0)
		return FALSE;	/* error */

	/*
	 * Read the packet data.
	 */
	if (!libpcap_read_rec_data(wth->random_fh, pd, length, err, err_info))
		return FALSE;	/* failed */

	pcap_read_post_process(wth->file_type, wth->file_encap,
	    pseudo_header, pd, length, libpcap->byte_swapped, -1);
	return TRUE;
}

/* Read the header of the next packet.

   Return -1 on an error, or the number of bytes of header read on success. */
static int libpcap_read_header(wtap *wth, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr)
{
	int	bytes_to_read, bytes_read;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	switch (wth->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_AIX:
	case WTAP_FILE_PCAP_NSEC:
		bytes_to_read = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_PCAP_SS990417:
	case WTAP_FILE_PCAP_SS991029:
		bytes_to_read = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_PCAP_SS990915:
		bytes_to_read = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case WTAP_FILE_PCAP_NOKIA:
		bytes_to_read = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		g_assert_not_reached();
		bytes_to_read = 0;
	}
	bytes_read = file_read(hdr, bytes_to_read, wth->fh);
	if (bytes_read != bytes_to_read) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	adjust_header(wth, &hdr->hdr);

	if (hdr->hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; return an error,
		 * so that our caller doesn't blow up trying to allocate
		 * space for an immensely-large packet, and so that
		 * the code to try to guess what type of libpcap file
		 * this is can tell when it's not the type we're guessing
		 * it is.
		 */
		*err = WTAP_ERR_BAD_FILE;
		if (err_info != NULL) {
			*err_info = g_strdup_printf("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr->hdr.incl_len, WTAP_MAX_PACKET_SIZE);
		}
		return -1;
	}

	if (hdr->hdr.orig_len > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; return an error,
		 * so that our caller doesn't blow up trying to
		 * cope with a huge "real" packet length, and so that
		 * the code to try to guess what type of libpcap file
		 * this is can tell when it's not the type we're guessing
		 * it is.
		 */
		*err = WTAP_ERR_BAD_FILE;
		if (err_info != NULL) {
			*err_info = g_strdup_printf("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr->hdr.orig_len, WTAP_MAX_PACKET_SIZE);
		}
		return -1;
	}

	return bytes_read;
}

static void
adjust_header(wtap *wth, struct pcaprec_hdr *hdr)
{
	guint32 temp;
	libpcap_t *libpcap;

	libpcap = (libpcap_t *)wth->priv;
	if (libpcap->byte_swapped) {
		/* Byte-swap the record header fields. */
		hdr->ts_sec = BSWAP32(hdr->ts_sec);
		hdr->ts_usec = BSWAP32(hdr->ts_usec);
		hdr->incl_len = BSWAP32(hdr->incl_len);
		hdr->orig_len = BSWAP32(hdr->orig_len);
	}

	/* Swap the "incl_len" and "orig_len" fields, if necessary. */
	switch (libpcap->lengths_swapped) {

	case NOT_SWAPPED:
		break;

	case MAYBE_SWAPPED:
		if (hdr->incl_len <= hdr->orig_len) {
			/*
			 * The captured length is <= the actual length,
			 * so presumably they weren't swapped.
			 */
			break;
		}
		/* FALLTHROUGH */

	case SWAPPED:
		temp = hdr->orig_len;
		hdr->orig_len = hdr->incl_len;
		hdr->incl_len = temp;
		break;
	}
}

static gboolean
libpcap_read_rec_data(FILE_T fh, guint8 *pd, int length, int *err,
    gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int libpcap_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (wtap_wtap_encap_to_pcap_encap(encap) == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean libpcap_dump_open(wtap_dumper *wdh, int *err)
{
	guint32 magic;
	struct pcap_hdr file_hdr;

	/* This is a libpcap file */
	wdh->subtype_write = libpcap_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_PCAP_NOKIA:	/* Nokia libpcap of some sort */
		magic = PCAP_MAGIC;
		wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case WTAP_FILE_PCAP_SS990915:	/* new magic, extra crap */
	case WTAP_FILE_PCAP_SS991029:
		magic = PCAP_MODIFIED_MAGIC;
		wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case WTAP_FILE_PCAP_NSEC:		/* same as WTAP_FILE_PCAP, but nsec precision */
		magic = PCAP_NSEC_MAGIC;
		wdh->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	if (!wtap_dump_file_write(wdh, &magic, sizeof magic, err))
		return FALSE;
	wdh->bytes_dumped += sizeof magic;

	/* current "libpcap" format is 2.4 */
	file_hdr.version_major = 2;
	file_hdr.version_minor = 4;
	file_hdr.thiszone = 0;	/* XXX - current offset? */
	file_hdr.sigfigs = 0;	/* unknown, but also apparently unused */
	/*
	 * Tcpdump cannot handle capture files with a snapshot length of 0,
	 * as BPF filters return either 0 if they fail or the snapshot length
	 * if they succeed, and a snapshot length of 0 means success is
	 * indistinguishable from failure and the filter expression would
	 * reject all packets.
	 *
	 * A snapshot length of 0, inside Wiretap, means "snapshot length
	 * unknown"; if the snapshot length supplied to us is 0, we make
	 * the snapshot length in the header file WTAP_MAX_PACKET_SIZE.
	 */
	file_hdr.snaplen = (wdh->snaplen != 0) ? wdh->snaplen :
						 WTAP_MAX_PACKET_SIZE;
	file_hdr.network = wtap_wtap_encap_to_pcap_encap(wdh->encap);
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
		return FALSE;
	wdh->bytes_dumped += sizeof file_hdr;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean libpcap_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header,
	const guint8 *pd, int *err)
{
	struct pcaprec_ss990915_hdr rec_hdr;
	size_t hdr_size;
	int phdrsize;

	phdrsize = pcap_get_phdr_size(wdh->encap, pseudo_header);

	rec_hdr.hdr.ts_sec = (guint32) phdr->ts.secs;
	if(wdh->tsprecision == WTAP_FILE_TSPREC_NSEC) {
		rec_hdr.hdr.ts_usec = phdr->ts.nsecs;
	} else {
		rec_hdr.hdr.ts_usec = phdr->ts.nsecs / 1000;
	}
	rec_hdr.hdr.incl_len = phdr->caplen + phdrsize;
	rec_hdr.hdr.orig_len = phdr->len + phdrsize;

	if (rec_hdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE || rec_hdr.hdr.orig_len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_FILE;
		return FALSE;
	}

	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_NSEC:
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

	case WTAP_FILE_PCAP_NOKIA:	/* old magic, extra crap at the end */
		/* restore the "mysterious stuff" that came with the packet */
		memcpy(&rec_hdr.ifindex, pseudo_header->nokia.stuff, 4);
		/* not written */
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		g_assert_not_reached();
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	if (!wtap_dump_file_write(wdh, &rec_hdr, hdr_size, err))
		return FALSE;
	wdh->bytes_dumped += hdr_size;

	if (!pcap_write_phdr(wdh, wdh->encap, pseudo_header, err))
		return FALSE;

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
        wdh->bytes_dumped += phdr->caplen;
	return TRUE;
}
