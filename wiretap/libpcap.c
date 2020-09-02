/* libpcap.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "pcap-common.h"
#include "pcap-encap.h"
#include "libpcap.h"
#include "erf-common.h"

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
	void *encap_priv;
} libpcap_t;

/* Try to read the first few records of the capture file. */
static int libpcap_try(wtap *wth, int *err, gchar **err_info);
static int libpcap_try_record(wtap *wth, FILE_T fh, int *err, gchar **err_info);

static gboolean libpcap_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *data_offset);
static gboolean libpcap_seek_read(wtap *wth, gint64 seek_off,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static gboolean libpcap_read_packet(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static gboolean libpcap_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info);
static int libpcap_read_header(wtap *wth, FILE_T fh, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr);
static void libpcap_close(wtap *wth);

wtap_open_return_val libpcap_open(wtap *wth, int *err, gchar **err_info)
{
	guint32 magic;
	struct pcap_hdr hdr;
	gboolean byte_swapped;
	gboolean modified;
	gboolean aix;
	int file_encap;
	gint64 first_packet_offset;
	libpcap_t *libpcap;
	static const int subtypes_modified[] = {
		WTAP_FILE_TYPE_SUBTYPE_PCAP_SS991029,
		WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990915
	};
#define N_SUBTYPES_MODIFIED	G_N_ELEMENTS(subtypes_modified)
	static const int subtypes_standard[] = {
		WTAP_FILE_TYPE_SUBTYPE_PCAP,
		WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990417,
		WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA
	};
#define N_SUBTYPES_STANDARD	G_N_ELEMENTS(subtypes_standard)
#define MAX_FIGURES_OF_MERIT \
	MAX(N_SUBTYPES_MODIFIED, N_SUBTYPES_STANDARD)
	int figures_of_merit[MAX_FIGURES_OF_MERIT];
	const int *subtypes;
	int n_subtypes;
	int best_subtype;
	int i;
	int skip_size = 0;
	int sizebytes;

	/* Read in the number that should be at the start of a "libpcap" file */
	if (!wtap_read_bytes(wth->fh, &magic, sizeof magic, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	switch (magic) {

	case PCAP_IXIAHW_MAGIC:
	case PCAP_IXIASW_MAGIC:
		skip_size = 1;
		/* FALLTHROUGH */
	case PCAP_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either standard or ss990417 libpcap. */
		byte_swapped = FALSE;
		modified = FALSE;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_MODIFIED_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either ss990915 or ss991029 libpcap. */
		byte_swapped = FALSE;
		modified = TRUE;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_SWAPPED_IXIAHW_MAGIC:
	case PCAP_SWAPPED_IXIASW_MAGIC:
		skip_size = 1;
		/* FALLTHROUGH */
	case PCAP_SWAPPED_MAGIC:
		/* Host that wrote it has a byte order opposite to ours,
		   and was running a program using either standard or
		   ss990417 libpcap. */
		byte_swapped = TRUE;
		modified = FALSE;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_SWAPPED_MODIFIED_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using either ss990915
		   or ss991029 libpcap. */
		byte_swapped = TRUE;
		modified = TRUE;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_NSEC_MAGIC:
		/* Host that wrote it has our byte order, and was writing
		   the file in a format similar to standard libpcap
		   except that the time stamps have nanosecond resolution. */
		byte_swapped = FALSE;
		modified = FALSE;
		wth->file_tsprec = WTAP_TSPREC_NSEC;
		break;

	case PCAP_SWAPPED_NSEC_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was writing the file in a format similar to
		   standard libpcap except that the time stamps have
		   nanosecond resolution. */
		byte_swapped = TRUE;
		modified = FALSE;
		wth->file_tsprec = WTAP_TSPREC_NSEC;
		break;

	default:
		/* Not a "libpcap" type we know about. */
		return WTAP_OPEN_NOT_MINE;
	}

	/* Read the rest of the header. */
	if (!wtap_read_bytes(wth->fh, &hdr, sizeof hdr, err, err_info))
		return WTAP_OPEN_ERROR;
	if (skip_size==1 && !wtap_read_bytes(wth->fh, &sizebytes, sizeof sizebytes, err, err_info))
		return WTAP_OPEN_ERROR;

	if (byte_swapped) {
		/* Byte-swap the header fields about which we care. */
		hdr.version_major = GUINT16_SWAP_LE_BE(hdr.version_major);
		hdr.version_minor = GUINT16_SWAP_LE_BE(hdr.version_minor);
		hdr.snaplen = GUINT32_SWAP_LE_BE(hdr.snaplen);
		hdr.network = GUINT32_SWAP_LE_BE(hdr.network);
	}
	if (hdr.version_major < 2) {
		/* We only support version 2.0 and later. */
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("pcap: major version %u unsupported",
		    hdr.version_major);
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Link-layer header types are assigned for both pcap and
	 * pcapng, and the same value must work with both.  In pcapng,
	 * the link-layer header type field in an Interface Description
	 * Block is 16 bits, so only the bottommost 16 bits of the
	 * link-layer header type in a pcap file can be used for the
	 * header type value.
	 *
	 * In libpcap, the upper 16 bits are divided into:
	 *
	 *    A "class" field, to support non-standard link-layer
	 *    header types; class 0 is for standard header types,
	 *    class 0x224 was reserved for a NetBSD feature, and
	 *    all other class values are reserved.  That is in the
	 *    lower 10 bits of the upper 16 bits.
	 *
	 *    An "FCS length" field, to allow the FCS length to
	 *    be specified, just as it can be specified in the
	 *    if_fcslen field of the pcapng IDB.  That is in the
	 *    topmost 4 bits of the upper 16 bits.  The field is
	 *    in units of 16 bits, i.e. 1 means 16 bits of FCS,
	 *    2 means 32 bits of FCS, etc..
	 *
	 *    An "FCS length present" flag; if 0, the "FCS length"
	 *    field should be ignored, and if 1, the "FCS length"
	 *    field should be used.  That is in the bit just above
	 *    the "class" field.
	 *
	 *    The one remaining bit is reserved.
	 */

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
		/*
		 * AIX pcap files didn't use the upper 16 bits,
		 * so we don't need to ignore them here - they'll
		 * be 0.
		 */
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

	/*
	 * Map the "network" field from the header to a Wiretap
	 * encapsulation.  We ignore the FCS information and reserved
	 * bit; we include the "class" field, in case there's ever
	 * a need to implement it - currently, any link-layer header
	 * type with a non-zero class value will fail.
	 */
	file_encap = wtap_pcap_encap_to_wtap_encap(hdr.network & 0x03FFFFFF);
	if (file_encap == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("pcap: network type %u unknown or unsupported",
		    hdr.network);
		return WTAP_OPEN_ERROR;
	}

	/* This is a libpcap file */
	libpcap = (libpcap_t *)g_malloc(sizeof(libpcap_t));
	libpcap->byte_swapped = byte_swapped;
	libpcap->version_major = hdr.version_major;
	libpcap->version_minor = hdr.version_minor;
	libpcap->encap_priv = NULL;
	wth->priv = (void *)libpcap;
	wth->subtype_read = libpcap_read;
	wth->subtype_seek_read = libpcap_seek_read;
	wth->subtype_close = libpcap_close;
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
		wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAP_AIX;
		wth->file_tsprec = WTAP_TSPREC_NSEC;

		/*
		 * Add an IDB; we don't know how many interfaces were
		 * involved, so we just say one interface, about which
		 * we only know the link-layer type, snapshot length,
		 * and time stamp resolution.
		 */
		wtap_add_generated_idb(wth);

		return WTAP_OPEN_MINE;
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
	 *
	 * But don't do that if the input is a pipe; that would mean the
	 * open won't complete until two packets have been written to
	 * the pipe, unless the pipe is closed after one packet has
	 * been written, so a program reading from the file won't see
	 * the first packet until the second packet has been written.
	 */
	if (modified) {
		/*
		 * Well, we have the magic number from Alexey's
		 * later two patches.  Try the subtypes for that,
		 * and fail if we're reading from a pipe.
		 */
		wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
		subtypes = subtypes_modified;
		n_subtypes = N_SUBTYPES_MODIFIED;
	} else {
		if (wth->file_tsprec == WTAP_TSPREC_NSEC) {
			/*
			 * We have nanosecond-format libpcap's magic
			 * number.  There's only one format with that
			 * magic number (if somebody comes up with
			 * another one, we'll just refuse to support
			 * it and tell them to ask The Tcpdump Group
			 * for another magic number).
			 */
			wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC;
			subtypes = NULL;
			n_subtypes = 0;
		} else {
			/*
			 * We have the regular libpcap magic number.
			 * Try the subtypes for that, unless we're
			 * reading from a pipe, in which case we
			 * just assume it's a regular libpcap file.
			 */
			wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAP;
			subtypes = subtypes_standard;
			n_subtypes = N_SUBTYPES_STANDARD;
		}
	}

	/*
	 * Do we have any subtypes to try?
	 */
	if (n_subtypes == 0) {
		/*
		 * No, so just use what we picked.
		 */
		goto done;
	} else if (wth->ispipe) {
		/*
		 * It's a pipe, so use what we picked, unless we picked
		 * WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, in which case we fail.
		 */
		if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
			*err = WTAP_ERR_UNSUPPORTED;
			*err_info = g_strdup("pcap: that type of pcap file can't be read from a pipe");
			return WTAP_OPEN_ERROR;
		}
		goto done;
	} else {
		first_packet_offset = file_tell(wth->fh);
		for (i = 0; i < n_subtypes; i++) {
			wth->file_type_subtype = subtypes[i];
			figures_of_merit[i] = libpcap_try(wth, err, err_info);
			if (figures_of_merit[i] == -1) {
				/*
				 * Well, we couldn't even read it.
				 * Give up.
				 */
				return WTAP_OPEN_ERROR;
			}
			if (figures_of_merit[i] == 0) {
				/*
				 * This format doesn't have any issues.
				 * Put the seek pointer back, and finish,
				 * using that format as the subtype.
				 */
				if (file_seek(wth->fh, first_packet_offset,
				    SEEK_SET, err) == -1) {
					return WTAP_OPEN_ERROR;
				}
				goto done;
			}

			/*
			 * OK, we've recorded the figure of merit for this
			 * one; go back to the first packet and try the
			 * next one.
			 */
			if (file_seek(wth->fh, first_packet_offset, SEEK_SET,
			    err) == -1) {
				return WTAP_OPEN_ERROR;
			}
		}

		/*
		 * OK, none are perfect; let's see which one is least bad.
		 */
		best_subtype = INT_MAX;
		for (i = 0; i < n_subtypes; i++) {
			/*
			 * Is this subtype better than the last one we saw?
			 */
			if (figures_of_merit[i] < best_subtype) {
				/*
				 * Yes.  Choose it until we find a better one.
				 */
				wth->file_type_subtype = subtypes[i];
				best_subtype = figures_of_merit[i];
			}
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
	if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA &&
	    hdr.network == 13)
		wth->file_encap = WTAP_ENCAP_ATM_PDUS;

	if (wth->file_encap == WTAP_ENCAP_ERF) {
		/*Reset the ERF interface lookup table*/
		libpcap->encap_priv = erf_priv_create();
	}

	/*
	 * Add an IDB; we don't know how many interfaces were involved,
	 * so we just say one interface, about which we only know
	 * the link-layer type, snapshot length, and time stamp
	 * resolution.
	 *
	 * XXX - this will be a bit weird if you're trying to convert
	 * a LINKTYPE_ERF pcap file to a pcapng file; it'll have a
	 * placeholder interface added here, *plus* interfaces
	 * added from the ERF records.  Ideally, at some point in
	 * the future, libpcap will have a more pcapng-friendly API
	 * for capturing, and the DAG capture code will use it, so that
	 * if you're capturing on more than one interface, they'll all
	 * get regular IDBs, with no need for the placeholder.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

/*
 * Maximum number of records to try to read.  Must be >= 2.
 */
#define MAX_RECORDS_TO_TRY	3

/* Try to read the first MAX_RECORDS_TO_TRY records of the capture file. */
static int libpcap_try(wtap *wth, int *err, gchar **err_info)
{
	int ret;
	int i;

	/*
	 * Attempt to read the first record.
	 */
	ret = libpcap_try_record(wth, wth->fh, err, err_info);
	if (ret != 0) {
		/*
		 * Error or mismatch; return the error indication or
		 * the figure of merit (demerit?).
		 */
		return ret;
	}

	/*
	 * Now attempt to read the next MAX_RECORDS_TO_TRY-1 records.
	 * Get the maximum figure of (de?)merit, as that represents the
	 * figure of merit for the record that had the most problems.
	 */
	for (i = 1; i < MAX_RECORDS_TO_TRY; i++) {
		/*
		 * Attempt to read this record.
		 */
		ret = libpcap_try_record(wth, wth->fh, err, err_info);
		if (ret != 0) {
			/*
			 * Error or mismatch; return the error indication or
			 * the figure of merit (demerit?).
			 */
			return ret;
		}
	}

	/* They all succeeded. */
	return 0;
}

/* Read the header of the next packet and, if that succeeds, read the
   data of the next packet.

   Return -1 on an I/O error, 0 on success, or a positive number if the
   header looks corrupt.  The higher the positive number, the more things
   are wrong with the header; this is used by the heuristics that try to
   guess what type of file it is, with the type with the fewest problems
   being chosen. */
static int libpcap_try_record(wtap *wth, FILE_T fh, int *err, gchar **err_info)
{
	/*
	 * pcaprec_ss990915_hdr is the largest header type.
	 */
	struct pcaprec_ss990915_hdr rec_hdr;
	int	ret;

	if (!libpcap_read_header(wth, fh, err, err_info, &rec_hdr)) {
		if (*err == 0) {
			/*
			 * EOF - assume the file is in this format.
			 * This means it doesn't have all the
			 * records we're trying to read.
			 */
			return 0;
		}
		if (*err == WTAP_ERR_SHORT_READ) {
			/*
			 * Short read; this might be a corrupt
			 * file in this format or might not be
			 * in this format.  Return a figure of
			 * merit of 1.
			 */
			return 1;
		}
		/* Hard error. */
		return -1;
	}

	ret = 0;	/* start out presuming everything's OK */
	switch (wth->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC:
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_AIX:
		/*
		 * Nanosecond resolution; treat fractions-of-a-second
		 * values >= 1 000 000 000 as an indication that
		 * the header format might not be what we think it is.
		 */
		if (rec_hdr.hdr.ts_usec >= 1000000000)
			ret++;
		break;

	default:
		/*
		 * Microsecond resolution; treat fractions-of-a-second
		 * values >= 1 000 000 as an indication that the header
		 * format might not be what we think it is.
		 */
		if (rec_hdr.hdr.ts_usec >= 1000000)
			ret++;
		break;
	}
	if (rec_hdr.hdr.incl_len > wtap_max_snaplen_for_encap(wth->file_encap)) {
		/*
		 * Probably either a corrupt capture file or a file
		 * of a type different from the one we're trying.
		 */
		ret++;
	}

	if (rec_hdr.hdr.orig_len > 128*1024*1024) {
		/*
		 * In theory I guess the on-the-wire packet size can be
		 * arbitrarily large, and it can certainly be larger than the
		 * maximum snapshot length which bounds the snapshot size,
		 * but any file claiming 128MB in a single packet is *probably*
		 * corrupt, and treating them as such makes the heuristics
		 * much more reliable. See, for example,
		 *
		 *    https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9634
		 *
		 * (128MB is an arbitrary size at this point, chosen to be
		 * large enough for the largest D-Bus packet).
		 */
		ret++;
	}

	if (rec_hdr.hdr.incl_len > wth->snapshot_length) {
	        /*
	         * This is not a fatal error, and packets that have one
	         * such packet probably have thousands. For discussion,
	         * see
	         * https://www.wireshark.org/lists/wireshark-dev/201307/msg00076.html
	         * and related messages.
	         *
	         * The packet contents will be copied to a Buffer, which
	         * expands as necessary to hold the contents; we don't have
	         * to worry about fixed-length buffers allocated based on
	         * the original snapshot length.
	         *
	         * We just treat this as an indication that we might be
	         * trying the wrong file type here.
	         */
		ret++;
	}

	if (rec_hdr.hdr.incl_len > rec_hdr.hdr.orig_len) {
		/*
		 * Another hint that this might be the wrong file type.
		 */
		ret++;
	}

	if (ret != 0) {
		/*
		 * Might be the wrong file type; stop trying, and give
		 * this as the figure of merit for this file type.
		 */
		return ret;
	}

	/*
	 * Now skip over the record's data, under the assumption that
	 * the header is sane.
	 */
	if (!wtap_read_bytes(wth->fh, NULL, rec_hdr.hdr.incl_len, err,
	    err_info)) {
		if (*err == WTAP_ERR_SHORT_READ) {
			/*
			 * Short read - treat that as a suggestion that
			 * the header isn't sane, and return a figure of
			 * merit value of 1.
			 */
			return 1;
		}
		/* Hard error. */
		return -1;
	}

	/* Success. */
	return 0;
}

/* Read the next packet */
static gboolean libpcap_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return libpcap_read_packet(wth, wth->fh, rec, buf, err, err_info);
}

static gboolean
libpcap_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec,
    Buffer *buf, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!libpcap_read_packet(wth, wth->random_fh, rec, buf, err,
	    err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

static gboolean
libpcap_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
    Buffer *buf, int *err, gchar **err_info)
{
	struct pcaprec_ss990915_hdr hdr;
	guint packet_size;
	guint orig_size;
	int phdr_len;
	libpcap_t *libpcap;

	libpcap = (libpcap_t *)wth->priv;

	if (!libpcap_read_header(wth, fh, err, err_info, &hdr))
		return FALSE;

	if (hdr.hdr.incl_len > wtap_max_snaplen_for_encap(wth->file_encap)) {
		/*
		 * Probably a corrupt capture file; return an error,
		 * so that our caller doesn't blow up trying to allocate
		 * space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		if (err_info != NULL) {
			*err_info = g_strdup_printf("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr.hdr.incl_len,
			    wtap_max_snaplen_for_encap(wth->file_encap));
		}
		return FALSE;
	}

	packet_size = hdr.hdr.incl_len;
	orig_size = hdr.hdr.orig_len;

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_PCAP_AIX &&
	    (wth->file_encap == WTAP_ENCAP_FDDI ||
	     wth->file_encap == WTAP_ENCAP_FDDI_BITSWAPPED)) {
		/*
		 * The packet size is really a record size and includes
		 * the padding.
		 */
		packet_size -= 3;
		orig_size -= 3;

		/*
		 * Skip the padding.
		 */
		if (!wtap_read_bytes(fh, NULL, 3, err, err_info))
			return FALSE;
	}

	phdr_len = pcap_process_pseudo_header(fh, wth->file_type_subtype,
	    wth->file_encap, packet_size, rec, err, err_info);
	if (phdr_len < 0)
		return FALSE;	/* error */

	/*
	 * Don't count any pseudo-header as part of the packet.
	 */
	orig_size -= phdr_len;
	packet_size -= phdr_len;

	rec->rec_type = REC_TYPE_PACKET;
	rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	/* Update the timestamp, if not already done */
	if (wth->file_encap != WTAP_ENCAP_ERF) {
		rec->ts.secs = hdr.hdr.ts_sec;
		if (wth->file_tsprec == WTAP_TSPREC_NSEC)
			rec->ts.nsecs = hdr.hdr.ts_usec;
		else
			rec->ts.nsecs = hdr.hdr.ts_usec * 1000;
	} else {
		int interface_id;
		/* Set interface ID for ERF format */
		rec->presence_flags |= WTAP_HAS_INTERFACE_ID;
		if ((interface_id = erf_populate_interface_from_header((erf_t*) libpcap->encap_priv, wth, &rec->rec_header.packet_header.pseudo_header)) < 0)
			return FALSE;

		rec->rec_header.packet_header.interface_id = (guint) interface_id;
	}
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = orig_size;

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
		return FALSE;	/* failed */

	pcap_read_post_process(wth->file_type_subtype, wth->file_encap,
	    rec, ws_buffer_start_ptr(buf), libpcap->byte_swapped, -1);
	return TRUE;
}

/* Read the header of the next packet.

   Return FALSE on an error, TRUE on success. */
static int libpcap_read_header(wtap *wth, FILE_T fh, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr)
{
	int bytes_to_read;
	guint32 temp;
	libpcap_t *libpcap;

	switch (wth->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_PCAP:
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_AIX:
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC:
		bytes_to_read = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990417:
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS991029:
		bytes_to_read = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990915:
		bytes_to_read = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA:
		bytes_to_read = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		g_assert_not_reached();
		bytes_to_read = 0;
	}
	if (!wtap_read_bytes_or_eof(fh, hdr, bytes_to_read, err, err_info))
		return FALSE;

	libpcap = (libpcap_t *)wth->priv;
	if (libpcap->byte_swapped) {
		/* Byte-swap the record header fields. */
		hdr->hdr.ts_sec = GUINT32_SWAP_LE_BE(hdr->hdr.ts_sec);
		hdr->hdr.ts_usec = GUINT32_SWAP_LE_BE(hdr->hdr.ts_usec);
		hdr->hdr.incl_len = GUINT32_SWAP_LE_BE(hdr->hdr.incl_len);
		hdr->hdr.orig_len = GUINT32_SWAP_LE_BE(hdr->hdr.orig_len);
	}

	/* Swap the "incl_len" and "orig_len" fields, if necessary. */
	switch (libpcap->lengths_swapped) {

	case NOT_SWAPPED:
		break;

	case MAYBE_SWAPPED:
		if (hdr->hdr.incl_len <= hdr->hdr.orig_len) {
			/*
			 * The captured length is <= the actual length,
			 * so presumably they weren't swapped.
			 */
			break;
		}
		/* FALLTHROUGH */

	case SWAPPED:
		temp = hdr->hdr.orig_len;
		hdr->hdr.orig_len = hdr->hdr.incl_len;
		hdr->hdr.incl_len = temp;
		break;
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
		return WTAP_ERR_UNWRITABLE_ENCAP;

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

	/* Write the file header. */
	switch (wdh->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_PCAP:
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA:	/* Nokia libpcap of some sort */
		magic = PCAP_MAGIC;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990915:	/* new magic, extra crap */
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS991029:
		magic = PCAP_MODIFIED_MAGIC;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC:		/* same as WTAP_FILE_TYPE_SUBTYPE_PCAP, but nsec precision */
		magic = PCAP_NSEC_MAGIC;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
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
	 * the snapshot length in the header file the maximum for the
	 * link-layer type we'll be writing.
	 */
	file_hdr.snaplen = (wdh->snaplen != 0) ? (guint)wdh->snaplen :
						 wtap_max_snaplen_for_encap(wdh->encap);
	file_hdr.network = wtap_wtap_encap_to_pcap_encap(wdh->encap);
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
		return FALSE;
	wdh->bytes_dumped += sizeof file_hdr;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean libpcap_dump(wtap_dumper *wdh,
	const wtap_rec *rec,
	const guint8 *pd, int *err, gchar **err_info _U_)
{
	const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
	struct pcaprec_ss990915_hdr rec_hdr;
	size_t hdr_size;
	int phdrsize;

	phdrsize = pcap_get_phdr_size(wdh->encap, pseudo_header);

	/* We can only write packet records. */
	if (rec->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		return FALSE;
	}

	/*
	 * Make sure this packet doesn't have a link-layer type that
	 * differs from the one for the file.
	 */
	if (wdh->encap != rec->rec_header.packet_header.pkt_encap) {
		*err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
		return FALSE;
	}

	/*
	 * Don't write anything we're not willing to read.
	 * (The cast is to prevent an overflow.)
	 */
	if ((guint64)rec->rec_header.packet_header.caplen + phdrsize > wtap_max_snaplen_for_encap(wdh->encap)) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return FALSE;
	}

	rec_hdr.hdr.incl_len = rec->rec_header.packet_header.caplen + phdrsize;
	rec_hdr.hdr.orig_len = rec->rec_header.packet_header.len + phdrsize;

	switch (wdh->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_PCAP:
		rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
		rec_hdr.hdr.ts_usec = rec->ts.nsecs / 1000;
		hdr_size = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC:
		rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
		rec_hdr.hdr.ts_usec = rec->ts.nsecs;
		hdr_size = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS991029:
		rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
		rec_hdr.hdr.ts_usec = rec->ts.nsecs / 1000;
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

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990915:	/* new magic, extra crap at the end */
		rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
		rec_hdr.hdr.ts_usec = rec->ts.nsecs / 1000;
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA:	/* old magic, extra crap at the end */
		rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
		rec_hdr.hdr.ts_usec = rec->ts.nsecs / 1000;
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
		*err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
		return FALSE;
	}

	if (!wtap_dump_file_write(wdh, &rec_hdr, hdr_size, err))
		return FALSE;
	wdh->bytes_dumped += hdr_size;

	if (!pcap_write_phdr(wdh, wdh->encap, pseudo_header, err))
		return FALSE;

	if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
		return FALSE;
	wdh->bytes_dumped += rec->rec_header.packet_header.caplen;
	return TRUE;
}

static void libpcap_close(wtap *wth)
{
	libpcap_t *libpcap = (libpcap_t *)wth->priv;

	if (libpcap->encap_priv) {
		switch (wth->file_encap) {

		case WTAP_ENCAP_ERF:
			erf_priv_free((erf_t*) libpcap->encap_priv);
			break;

		default:
			g_free(libpcap->encap_priv);
			break;
		}
	}
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
