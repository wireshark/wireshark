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
#include "required_file_handlers.h"
#include "pcap-common.h"
#include "pcap-encap.h"
#include "libpcap.h"
#include "erf-common.h"
#include <wsutil/ws_assert.h>

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

/*
 * Variants of pcap, some distinguished by the magic number and some,
 * alas, not.
 *
 * (Don't do that.  Srsly.)
 */
typedef enum {
	PCAP,		/* OG pcap */
	PCAP_NSEC,	/* PCAP with nanosecond resolution */
	PCAP_AIX,	/* AIX pcap */
	PCAP_SS990417,	/* Modified, from 1999-04-17 patch */
	PCAP_SS990915,	/* Modified, from 1999-09-15 patch */
	PCAP_SS991029,	/* Modified, from 1999-10-29 patch */
	PCAP_NOKIA,	/* Nokia pcap */
	PCAP_UNKNOWN	/* Unknown as yet */
} pcap_variant_t;

typedef struct {
	gboolean byte_swapped;
	swapped_type_t lengths_swapped;
	guint16	version_major;
	guint16	version_minor;
	pcap_variant_t variant;
	int fcs_len;
	void *encap_priv;
} libpcap_t;

/* Try to read the first few records of the capture file. */
static gboolean libpcap_try_variants(wtap *wth, const pcap_variant_t *variants,
    size_t n_variants, int *err, gchar **err_info);
static int libpcap_try(wtap *wth, int *err, gchar **err_info);
static int libpcap_try_record(wtap *wth, int *err, gchar **err_info);

static gboolean libpcap_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *data_offset);
static gboolean libpcap_seek_read(wtap *wth, gint64 seek_off,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static gboolean libpcap_read_packet(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static int libpcap_read_header(wtap *wth, FILE_T fh, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr);
static void libpcap_close(wtap *wth);

static gboolean libpcap_dump_pcap(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info);
static gboolean libpcap_dump_pcap_nsec(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info);
static gboolean libpcap_dump_pcap_ss990417(wtap_dumper *wdh,
    const wtap_rec *rec, const guint8 *pd, int *err, gchar **err_info);
static gboolean libpcap_dump_pcap_ss990915(wtap_dumper *wdh,
    const wtap_rec *rec, const guint8 *pd, int *err, gchar **err_info);
static gboolean libpcap_dump_pcap_ss991029(wtap_dumper *wdh,
    const wtap_rec *rec, const guint8 *pd, int *err, gchar **err_info);
static gboolean libpcap_dump_pcap_nokia(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info);

/*
 * Subfields of the field containing the link-layer header type.
 *
 * Link-layer header types are assigned for both pcap and
 * pcapng, and the same value must work with both.  In pcapng,
 * the link-layer header type field in an Interface Description
 * Block is 16 bits, so only the bottommost 16 bits of the
 * link-layer header type in a pcap file can be used for the
 * header type value.
 *
 * In libpcap, the upper 16 bits, from the top down, are divided into:
 *
 *    A 4-bit "FCS length" field, to allow the FCS length to
 *    be specified, just as it can be specified in the if_fcslen
 *    field of the pcapng IDB.  The field is in units of 16 bits,
 *    i.e. 1 means 16 bits of FCS, 2 means 32 bits of FCS, etc..
 *
 *    A reserved bit, which must be zero.
 *
 *    An "FCS length present" flag; if 0, the "FCS length" field
 *    should be ignored, and if 1, the "FCS length" field should
 *    be used.
 *
 *    10 reserved bits, which must be zero.  They were originally
 *    intended to be used as a "class" field, allowing additional
 *    classes of link-layer types to be defined, with a class value
 *    of 0 indicating that the link-layer type is a LINKTYPE_ value.
 *    A value of 0x224 was, at one point, used by NetBSD to define
 *    "raw" packet types, with the lower 16 bits containing a
 *    NetBSD AF_ value; see
 *
 *        https://marc.info/?l=tcpdump-workers&m=98296750229149&w=2
 *
 *    It's unknown whether those were ever used in capture files,
 *    or if the intent was just to use it as a link-layer type
 *    for BPF programs; NetBSD's libpcap used to support them in
 *    the BPF code generator, but it no longer does so.  If it
 *    was ever used in capture files, or if classes other than
 *    "LINKTYPE_ value" are ever useful in capture files, we could
 *    re-enable this, and use the reserved 16 bits following the
 *    link-layer type in pcapng files to hold the class information
 *    there.  (Note, BTW, that LINKTYPE_RAW/DLT_RAW is now being
 *    interpreted by libpcap, tcpdump, and Wireshark as "raw IP",
 *    including both IPv4 and IPv6, with the version number in the
 *    header being checked to see which it is, not just "raw IPv4";
 *    there are LINKTYPE_IPV4/DLT_IPV4 and LINKTYPE_IPV6/DLT_IPV6
 *    values if "these are IPv{4,6} and only IPv{4,6} packets"
 *    types are needed.)
 *
 *    Or we might be able to use it for other purposes.
 */
#define LT_LINKTYPE(x)			((x) & 0x0000FFFF)
#define LT_RESERVED1(x)			((x) & 0x03FF0000)
#define LT_FCS_LENGTH_PRESENT(x)	((x) & 0x04000000)
#define LT_FCS_LENGTH(x)		(((x) & 0xF0000000) >> 28)
#define LT_FCS_DATALINK_EXT(x)		(((x) & 0xF) << 28) | 0x04000000)

/*
 * Private file type/subtype values; pcap and nanosecond-resolution
 * pcap are imported from wiretap/file_access.c.
 */
static int pcap_aix_file_type_subtype = -1;
static int pcap_ss990417_file_type_subtype = -1;
static int pcap_ss990915_file_type_subtype = -1;
static int pcap_ss991029_file_type_subtype = -1;
static int pcap_nokia_file_type_subtype = -1;

/*
 * pcap variants that use the standard magic number.
 */
static const pcap_variant_t variants_standard[] = {
	PCAP,
	PCAP_SS990417,
	PCAP_NOKIA
};
#define N_VARIANTS_STANDARD	G_N_ELEMENTS(variants_standard)

/*
 * pcap variants that use the modified magic number.
 */
static const pcap_variant_t variants_modified[] = {
	PCAP_SS991029,
	PCAP_SS990915
};
#define N_VARIANTS_MODIFIED	G_N_ELEMENTS(variants_modified)

wtap_open_return_val libpcap_open(wtap *wth, int *err, gchar **err_info)
{
	guint32 magic;
	struct pcap_hdr hdr;
	gboolean byte_swapped;
	pcap_variant_t variant;
	libpcap_t *libpcap;
	int skip_size = 0;
	int sizebytes;

	/* Read in the number that should be at the start of a "libpcap" file */
	if (!wtap_read_bytes(wth->fh, &magic, sizeof magic, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	switch (magic) {

	case PCAP_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either standard or ss990417 libpcap,
		   or maybe it was written by AIX.  That means we don't
		   yet know the variant. */
		byte_swapped = FALSE;
		variant = PCAP_UNKNOWN;
		break;

	case PCAP_SWAPPED_MAGIC:
		/* Host that wrote it has a byte order opposite to ours,
		   and was running a program using either standard or
		   ss990417 libpcap, or maybe it was written by AIX.
		   That means we don't yet know the variant. */
		byte_swapped = TRUE;
		variant = PCAP_UNKNOWN;
		break;

	case PCAP_IXIAHW_MAGIC:
	case PCAP_IXIASW_MAGIC:
		/* Weird Ixia variant that has extra crud, written in our
		   byte order.  It's otherwise like standard pcap. */
		skip_size = 1;
		byte_swapped = FALSE;
		variant = PCAP;
		break;

	case PCAP_SWAPPED_IXIAHW_MAGIC:
	case PCAP_SWAPPED_IXIASW_MAGIC:
		/* Weird Ixia variant that has extra crud, written in a
		   byte order opposite to ours.  It's otherwise like
		   standard pcap. */
		skip_size = 1;
		byte_swapped = TRUE;
		variant = PCAP;
		break;

	case PCAP_MODIFIED_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either ss990915 or ss991029 libpcap.
		   That means we don't yet know the variant; there's
		   no obvious default, so default to "unknown". */
		byte_swapped = FALSE;
		variant = PCAP_UNKNOWN;
		break;

	case PCAP_SWAPPED_MODIFIED_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using either ss990915
		   or ss991029 libpcap.  That means we don't yet know
		   the variant; there's no obvious default, so default
		   to "unknown". */
		byte_swapped = TRUE;
		variant = PCAP_UNKNOWN;
		break;

	case PCAP_NSEC_MAGIC:
		/* Host that wrote it has our byte order, and was writing
		   the file in a format similar to standard libpcap
		   except that the time stamps have nanosecond resolution. */
		byte_swapped = FALSE;
		variant = PCAP_NSEC;
		break;

	case PCAP_SWAPPED_NSEC_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was writing the file in a format similar to
		   standard libpcap except that the time stamps have
		   nanosecond resolution. */
		byte_swapped = TRUE;
		variant = PCAP_NSEC;
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
		magic = GUINT32_SWAP_LE_BE(magic);
		hdr.version_major = GUINT16_SWAP_LE_BE(hdr.version_major);
		hdr.version_minor = GUINT16_SWAP_LE_BE(hdr.version_minor);
		hdr.snaplen = GUINT32_SWAP_LE_BE(hdr.snaplen);
		hdr.network = GUINT32_SWAP_LE_BE(hdr.network);
	}
	if (hdr.version_major < 2) {
		/* We only support version 2.0 and later. */
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("pcap: major version %u unsupported",
		    hdr.version_major);
		return WTAP_OPEN_ERROR;
	}

	/* This is a libpcap file */
	wth->subtype_read = libpcap_read;
	wth->subtype_seek_read = libpcap_seek_read;
	wth->subtype_close = libpcap_close;
	wth->snapshot_length = hdr.snaplen;
	libpcap = g_new0(libpcap_t, 1);
	wth->priv = (void *)libpcap;
	/*
	 * Fill in the information we already know or can determine
	 * at this point, so the private data is usable by the code
	 * that tries reading packets as a heuristic to guess the
	 * variant.
	 */
	libpcap->byte_swapped = byte_swapped;
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
	libpcap->version_major = hdr.version_major;
	libpcap->version_minor = hdr.version_minor;
	/*
	 * Check whether this is an AIX pcap before we convert the
	 * link-layer type in the header file to an encapsulation,
	 * because AIX pcaps use RFC 1573 ifType values in the header.
	 *
	 * AIX pcap files use the standard magic number, and have a
	 * major and minor version of 2.
	 *
	 * Unfortunately, that's also true of older versions of libpcap,
	 * so we need to do some heuristics to try to identify AIX pcap
	 * files.
	 */
	if (magic ==  PCAP_MAGIC && hdr.version_major == 2 &&
	    hdr.version_minor == 2) {
		/*
		 * The AIX libpcap uses RFC 1573 ifType values rather
		 * than LINKTYPE_/DLT_ values in the header; the ifType
		 * values for LAN devices are:
		 *
		 *	Ethernet	6
		 *	Token Ring	9
		 *	FDDI		15
		 *
		 * which correspond to LINKTYPE_IEEE802_5/DLT_IEEE802 (used
		 * for Token Ring), LINKTYPE_PPP/DLT_PPP, and
		 * LINKTYPE_SLIP_BSDOS/DLT_SLIP_BSDOS, respectively, and
		 * the ifType value for a loopback interface is 24, which
		 * currently isn't used by any version of libpcap I know
		 * about (and, as tcpdump.org are assigning LINKTYPE_/DLT_
		 * values above 100, and NetBSD started assigning values
		 * starting at 50, and the values chosen by other libpcaps
		 * appear to stop at 19, it's probably not going to be used
		 * by any libpcap in the future).
		 *
		 * So we shall assume that if the network type is 6, 9, 15,
		 * or 24 it's AIX libpcap.
		 *
		 * We also assume those older versions of libpcap didn't use
		 * LINKTYPE_IEEE802_5/DLT_IEEE802 for Token Ring, and didn't
		 * use LINKTYPE_SLIP_BSDOS/DLT_SLIP_BSDOS as that came later.
		 * It may have used LINKTYPE_PPP/DLT_PPP, however, in which
		 * case we're out of luck; we assume it's Token Ring in AIX
		 * libpcap rather than PPP in standard libpcap, as you're
		 * probably more likely to be handing an AIX libpcap token-
		 *ring capture than an old (pre-libpcap 0.4) PPP capture to
		 * Wireshark.
		 *
		 * AIX pcap files didn't use the upper 16 bits, so we don't
		 * need to ignore them here - they'll be 0.
		 */
		switch (hdr.network) {

		case 6:
			hdr.network = 1;	/* LINKTYPE_EN10MB, Ethernet */
			variant = PCAP_AIX;
			break;

		case 9:
			hdr.network = 6;	/* LINKTYPE_IEEE802_5, Token Ring */
			variant = PCAP_AIX;
			break;

		case 15:
			hdr.network = 10;	/* LINKTYPE_FDDI, FDDI */
			variant = PCAP_AIX;
			break;

		case 24:
			hdr.network = 0;	/* LINKTYPE_NULL, loopback */
			variant = PCAP_AIX;
			break;
		}
	}

	/*
	 * Check the main reserved field.
	 */
	if (LT_RESERVED1(hdr.network) != 0) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("pcap: network type reserved field not zero (0x%08x)",
		    LT_RESERVED1(hdr.network));
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Map the link-layer type from the "network" field in
	 * the header to a Wiretap encapsulation.
	 */
	wth->file_encap = wtap_pcap_encap_to_wtap_encap(LT_LINKTYPE(hdr.network));
	if (wth->file_encap == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("pcap: network type %u unknown or unsupported",
		    hdr.network);
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Extract the FCS information, if present.
	 */
	libpcap->fcs_len = -1;
	if (LT_FCS_LENGTH_PRESENT(hdr.network)) {
		/*
		 * We have an FCS length.
		 */
		libpcap->fcs_len = LT_FCS_LENGTH(hdr.network) * 16;
	}

	libpcap->encap_priv = NULL;

	/*
	 * If this file has the standard magic number, it could be
	 * one of a number of variants, including regular pcap, the
	 * AIX variant, the ss990417 variant, and a Nokia variant.
	 * The ss990417 variant is used in, for example, Red Hat 6.1,
	 * so some versions of AIX, RH 6.1, and some Nokia devices
	 * write files that can't be read by any software that expects
	 * standard libpcap packet record headers if the magic number
	 * is the standard magic number (e.g., any program such as
	 * tcpdump that uses libpcap, when using the standard libpcap,
	 * and Wireshark if we don't do the heuristics below).
	 *
	 * If this file has the patched magic number, used by the
	 * ss990915 and ss991029 variants, then it could be either
	 * of those.  The ss991029 variant uses the same packet
	 * record header as the ss990417 variant, but the ss990915
	 * variant uses a packet record header with some additional
	 * fields and it is used in, for example, SuSE 6.3, so SuSE
	 * 6.3 writes files that can't be read by any software that
	 * expects ss990417 packet record headers if the magic number
	 * is the modified magic number.
	 *
	 * So, for the standard and modified magic number:
	 *
	 * For the standard magic number, we first do some heuristic
	 * checks of data from the file header to see if it looks like
	 * an AIX libpcap file.  If so, we choose PCAP_AIX as the variant,
	 * and we don't have to do any more guessing.
	 *
	 * Otherwise, we determine the variant by, for each variant,
	 * trying to read the first few packets as if that file were
	 * in that variant's format, and seeing whether the packet
	 * record headers make sense.
	 *
	 * But don't do the latter if the input is a pipe; that would mean
	 * the open won't complete until two packets have been written to
	 * the pipe, unless the pipe is closed after one packet has been
	 * written, so a program reading from the file won't see the
	 * first packet until the second packet has been written.
	 */
	switch (magic) {

	case PCAP_MAGIC:
		/*
		 * Original libpcap magic.
		 *
		 * If we still don't know the variant, look at the first
		 * few packets to see what type of per-packet header they
		 * have.
		 *
		 * Default to PCAP, as that's probably what this is;
		 * libpcap_try_variants() will just give up if we're
		 * reading from a pipe.
		 */
		if (variant == PCAP_UNKNOWN) {
			if (wth->ispipe) {
				/*
				 * We can't do the heuristics.
				 * Just go with standard libpcap.
				 */
				libpcap->variant = PCAP;
			} else {
				/*
				 * Try the variants that use the standard
				 * pcap magic number.
				 */
				if (!libpcap_try_variants(wth, variants_standard,
				    N_VARIANTS_STANDARD, err, err_info)) {
					/*
					 * File read error.
					 */
					return WTAP_OPEN_ERROR;
				}
			}
		} else {
			/*
			 * Use the variant we found.
			 */
			libpcap->variant = variant;
		}
		break;

	case PCAP_MODIFIED_MAGIC:
		/*
		 * Modified libpcap magic, from Alexey's later two
		 * patches.
		 *
		 * This might be one of two different flavors of
		 * pcap file, with different modified per-packet
		 * headers.
		 *
		 * If we're reading from a pipe, we don't have an
		 * obvious choice to use as a default.
		 */
		if (wth->ispipe) {
			/*
			 * We can't do the heuristics.
			 * There's no obvious choice to use as a
			 * default, so just report an error.
			 */
			*err = WTAP_ERR_UNSUPPORTED;
			*err_info = g_strdup("pcap: that type of pcap file can't be read from a pipe");
			return WTAP_OPEN_ERROR;
		} else {
			/*
			 * Try the variants that use the modified
			 * pcap magic number.
			 */
			if (!libpcap_try_variants(wth, variants_modified,
			    N_VARIANTS_MODIFIED, err, err_info)) {
				/*
				 * File read error.
				 */
				return WTAP_OPEN_ERROR;
			}
		}
		break;

	default:
		/*
		 * None of these require heuristics to guess the
		 * variant; just use the variant we found.
		 */
		libpcap->variant = variant;
		break;
	}

	/*
	 * Set the file type and subtype, and handle some variants
	 * specially.
	 */
	switch (libpcap->variant) {

	case PCAP:
		wth->file_type_subtype = pcap_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_NSEC:
		wth->file_type_subtype = pcap_nsec_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_NSEC;
		break;

	case PCAP_SS990417:
		wth->file_type_subtype = pcap_ss990417_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_SS990915:
		wth->file_type_subtype = pcap_ss990915_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_SS991029:
		wth->file_type_subtype = pcap_ss991029_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		break;

	case PCAP_AIX:
		wth->file_type_subtype = pcap_aix_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_NSEC;
		break;

	case PCAP_NOKIA:
		wth->file_type_subtype = pcap_nokia_file_type_subtype;
		wth->file_tsprec = WTAP_TSPREC_USEC;
		/*
		 * We treat a DLT_ value of 13 specially - it appears
		 * that in Nokia libpcap format, it's some form of ATM
		 * with what I suspect is a pseudo-header (even though
		 * Nokia's IPSO is based on FreeBSD, which #defines
		 * DLT_SLIP_BSDOS as 13).
		 *
		 * Treat 13 as WTAP_ENCAP_ATM_PDUS, rather than as what
		 * we normally treat it.
		 */
		if (hdr.network == 13)
			wth->file_encap = WTAP_ENCAP_ATM_PDUS;
		break;

	default:
		ws_assert_not_reached();
	}

	if (wth->file_encap == WTAP_ENCAP_ERF) {
		/* Reset the ERF interface lookup table */
		libpcap->encap_priv = erf_priv_create();
	} else {
		/*
		 * Add an IDB; we don't know how many interfaces were
		 * involved, so we just say one interface, about which
		 * we only know the link-layer type, snapshot length,
		 * and time stamp resolution.
		 */
		wtap_add_generated_idb(wth);
	}

	return WTAP_OPEN_MINE;
}

static gboolean libpcap_try_variants(wtap *wth, const pcap_variant_t *variants,
    size_t n_variants, int *err, gchar **err_info)
{
	libpcap_t *libpcap = (libpcap_t *)wth->priv;
#define MAX_FIGURES_OF_MERIT \
	MAX(N_VARIANTS_MODIFIED, N_VARIANTS_STANDARD)
	int figures_of_merit[MAX_FIGURES_OF_MERIT];
	int best_variant;
	gint64 first_packet_offset;

	first_packet_offset = file_tell(wth->fh);
	for (size_t i = 0; i < n_variants; i++) {
		libpcap->variant = variants[i];
		figures_of_merit[i] = libpcap_try(wth, err, err_info);
		if (figures_of_merit[i] == -1) {
			/*
			 * Well, we couldn't even read it.  Give up.
			 */
			return FALSE;
		}
		if (figures_of_merit[i] == 0) {
			/*
			 * This format doesn't have any issues.
			 * Put the seek pointer back, and finish,
			 * using that format as the subtype.
			 */
			if (file_seek(wth->fh, first_packet_offset, SEEK_SET,
			    err) == -1) {
				return FALSE;
			}
			return TRUE;
		}

		/*
		 * OK, we've recorded the figure of merit for this
		 * one; go back to the first packet and try the
		 * next one.
		 */
		if (file_seek(wth->fh, first_packet_offset, SEEK_SET,
		    err) == -1) {
			return FALSE;
		}
	}

	/*
	 * OK, none are perfect; let's see which one is least bad.
	 */
	best_variant = INT_MAX;
	for (size_t i = 0; i < n_variants; i++) {
		/*
		 * Is this subtype better than the last one we saw?
		 */
		if (figures_of_merit[i] < best_variant) {
			/*
			 * Yes.  Choose it until we find a better one.
			 */
			libpcap->variant = variants[i];
			best_variant = figures_of_merit[i];
		}
	}
	return TRUE;
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
	ret = libpcap_try_record(wth, err, err_info);
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
		ret = libpcap_try_record(wth, err, err_info);
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
static int libpcap_try_record(wtap *wth, int *err, gchar **err_info)
{
	/*
	 * pcaprec_ss990915_hdr is the largest header type.
	 */
	struct pcaprec_ss990915_hdr rec_hdr;
	int	ret;

	if (!libpcap_read_header(wth, wth->fh, err, err_info, &rec_hdr)) {
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

	/*
	 * The only file types for which we have to do variant
	 * determination by looking at packets have microsecond
	 * resolution; treat fractions-of-a-second values >= 1 000 000
	 * as an indication that the header format might not be
	 * what we think it is.
	 */
	if (rec_hdr.hdr.ts_usec >= 1000000)
		ret++;

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
		 *    https://gitlab.com/wireshark/wireshark/-/issues/9634
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
	libpcap_t *libpcap = (libpcap_t *)wth->priv;
	gboolean is_nokia;

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
			*err_info = ws_strdup_printf("pcap: File has %u-byte packet, bigger than maximum of %u",
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
	if (libpcap->variant == PCAP_AIX &&
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

	is_nokia = (libpcap->variant == PCAP_NOKIA);
	phdr_len = pcap_process_pseudo_header(fh, is_nokia,
	    wth->file_encap, packet_size, rec, err, err_info);
	if (phdr_len < 0)
		return FALSE;	/* error */

	/*
	 * Don't count any pseudo-header as part of the packet.
	 */
	orig_size -= phdr_len;
	packet_size -= phdr_len;

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	/* Update the timestamp, if not already done */
	if (wth->file_encap != WTAP_ENCAP_ERF) {
		rec->ts.secs = hdr.hdr.ts_sec;
		if (libpcap->variant == PCAP_NSEC ||
		    libpcap->variant == PCAP_AIX)
			rec->ts.nsecs = hdr.hdr.ts_usec;
		else
			rec->ts.nsecs = hdr.hdr.ts_usec * 1000;
	} else {
		int interface_id;
		/* Set interface ID for ERF format */
		rec->presence_flags |= WTAP_HAS_INTERFACE_ID;
		if ((interface_id = erf_populate_interface_from_header((erf_t*) libpcap->encap_priv, wth, &rec->rec_header.packet_header.pseudo_header, err, err_info)) < 0)
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

	pcap_read_post_process(is_nokia, wth->file_encap, rec,
	    ws_buffer_start_ptr(buf), libpcap->byte_swapped, libpcap->fcs_len);
	return TRUE;
}

/* Read the header of the next packet.

   Return FALSE on an error, TRUE on success. */
static int libpcap_read_header(wtap *wth, FILE_T fh, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr)
{
	int bytes_to_read;
	guint32 temp;
	libpcap_t *libpcap = (libpcap_t *)wth->priv;

	switch (libpcap->variant) {

	case PCAP:
	case PCAP_AIX:
	case PCAP_NSEC:
		bytes_to_read = sizeof (struct pcaprec_hdr);
		break;

	case PCAP_SS990417:
	case PCAP_SS991029:
		bytes_to_read = sizeof (struct pcaprec_modified_hdr);
		break;

	case PCAP_SS990915:
		bytes_to_read = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case PCAP_NOKIA:
		bytes_to_read = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		bytes_to_read = 0;
		ws_assert_not_reached();
	}
	if (!wtap_read_bytes_or_eof(fh, hdr, bytes_to_read, err, err_info))
		return FALSE;

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
static int libpcap_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (wtap_wtap_encap_to_pcap_encap(encap) == -1)
		return WTAP_ERR_UNWRITABLE_ENCAP;

	return 0;
}

static gboolean libpcap_dump_write_file_header(wtap_dumper *wdh, guint32 magic,
    int *err)
{
	struct pcap_hdr file_hdr;

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

/* Good old fashioned pcap.
   Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
static gboolean
libpcap_dump_open_pcap(wtap_dumper *wdh, int *err, gchar **err_info _U_)
{
	/* This is a libpcap file */
	wdh->subtype_write = libpcap_dump_pcap;

	/* Write the file header. */
	return libpcap_dump_write_file_header(wdh, PCAP_MAGIC, err);
}

/* Like classic pcap, but with nanosecond resolution.
   Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
static gboolean
libpcap_dump_open_pcap_nsec(wtap_dumper *wdh, int *err, gchar **err_info _U_)
{
	/* This is a nanosecond-resolution libpcap file */
	wdh->subtype_write = libpcap_dump_pcap_nsec;

	/* Write the file header. */
	return libpcap_dump_write_file_header(wdh, PCAP_NSEC_MAGIC, err);
}

/* Modified, but with the old magic, sigh.
   Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
static gboolean
libpcap_dump_open_pcap_ss990417(wtap_dumper *wdh, int *err,
    gchar **err_info _U_)
{
	/* This is a modified-by-patch-SS990417 libpcap file */
	wdh->subtype_write = libpcap_dump_pcap_ss990417;

	/* Write the file header. */
	return libpcap_dump_write_file_header(wdh, PCAP_MAGIC, err);
}

/* New magic, extra crap.
   Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
static gboolean
libpcap_dump_open_pcap_ss990915(wtap_dumper *wdh, int *err,
    gchar **err_info _U_)
{
	/* This is a modified-by-patch-SS990915 libpcap file */
	wdh->subtype_write = libpcap_dump_pcap_ss990915;

	/* Write the file header. */
	return libpcap_dump_write_file_header(wdh, PCAP_MODIFIED_MAGIC, err);
}

/* Same magic as SS990915, *different* extra crap, sigh.
   Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
static gboolean
libpcap_dump_open_pcap_ss991029(wtap_dumper *wdh, int *err,
    gchar **err_info _U_)
{
	/* This is a modified-by-patch-SS991029 libpcap file */
	wdh->subtype_write = libpcap_dump_pcap_ss991029;

	/* Write the file header. */
	return libpcap_dump_write_file_header(wdh, PCAP_MODIFIED_MAGIC, err);
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

/* Nokia libpcap of some sort.
   Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
static gboolean
libpcap_dump_open_pcap_nokia(wtap_dumper *wdh, int *err, gchar **err_info _U_)
{
	/* This is a Nokia libpcap file */
	wdh->subtype_write = libpcap_dump_pcap_nokia;

	/* Write the file header. */
	return libpcap_dump_write_file_header(wdh, PCAP_MAGIC, err);
}

static gboolean
libpcap_dump_write_packet(wtap_dumper *wdh, const wtap_rec *rec,
    struct pcaprec_hdr *hdr, size_t hdr_size, const guint8 *pd, int *err)
{
	const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
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

	hdr->incl_len = rec->rec_header.packet_header.caplen + phdrsize;
	hdr->orig_len = rec->rec_header.packet_header.len + phdrsize;

	if (!wtap_dump_file_write(wdh, hdr, hdr_size, err))
		return FALSE;
	wdh->bytes_dumped += hdr_size;

	if (!pcap_write_phdr(wdh, wdh->encap, pseudo_header, err))
		return FALSE;

	if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
		return FALSE;
	wdh->bytes_dumped += rec->rec_header.packet_header.caplen;
	return TRUE;
}

/* Good old fashioned pcap.
   Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
libpcap_dump_pcap(wtap_dumper *wdh, const wtap_rec *rec, const guint8 *pd,
    int *err, gchar **err_info _U_)
{
	struct pcaprec_hdr rec_hdr;

	/*
	 * Some code that reads libpcap files may handle time
	 * stamps as unsigned, but most of it probably handles
	 * them as signed.
	 */
	if (rec->ts.secs < 0 || rec->ts.secs > G_MAXINT32) {
		*err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
		return FALSE;
	}
	rec_hdr.ts_sec = (guint32) rec->ts.secs;
	rec_hdr.ts_usec = rec->ts.nsecs / 1000;
	return libpcap_dump_write_packet(wdh, rec, &rec_hdr, sizeof rec_hdr,
	    pd, err);
}

/* Like classic pcap, but with nanosecond resolution.
   Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
libpcap_dump_pcap_nsec(wtap_dumper *wdh, const wtap_rec *rec, const guint8 *pd,
    int *err, gchar **err_info _U_)
{
	struct pcaprec_hdr rec_hdr;

	/*
	 * Some code that reads libpcap files may handle time
	 * stamps as unsigned, but most of it probably handles
	 * them as signed.
	 */
	if (rec->ts.secs < 0 || rec->ts.secs > G_MAXINT32) {
		*err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
		return FALSE;
	}
	rec_hdr.ts_sec = (guint32) rec->ts.secs;
	rec_hdr.ts_usec = rec->ts.nsecs;
	return libpcap_dump_write_packet(wdh, rec, &rec_hdr, sizeof rec_hdr,
	    pd, err);
}

/* Modified, but with the old magic, sigh.
   Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
libpcap_dump_pcap_ss990417(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info _U_)
{
	struct pcaprec_modified_hdr rec_hdr;

	/*
	 * Some code that reads libpcap files may handle time
	 * stamps as unsigned, but most of it probably handles
	 * them as signed.
	 */
	if (rec->ts.secs < 0 || rec->ts.secs > G_MAXINT32) {
		*err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
		return FALSE;
	}
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
	return libpcap_dump_write_packet(wdh, rec, &rec_hdr.hdr, sizeof rec_hdr,
	    pd, err);
}

/* New magic, extra crap.
   Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
libpcap_dump_pcap_ss990915(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info _U_)
{
	struct pcaprec_ss990915_hdr rec_hdr;

	/*
	 * Some code that reads libpcap files may handle time
	 * stamps as unsigned, but most of it probably handles
	 * them as signed.
	 */
	if (rec->ts.secs < 0 || rec->ts.secs > G_MAXINT32) {
		*err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
		return FALSE;
	}
	rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
	rec_hdr.hdr.ts_usec = rec->ts.nsecs / 1000;
	rec_hdr.ifindex = 0;
	rec_hdr.protocol = 0;
	rec_hdr.pkt_type = 0;
	rec_hdr.cpu1 = 0;
	rec_hdr.cpu2 = 0;
	return libpcap_dump_write_packet(wdh, rec, &rec_hdr.hdr, sizeof rec_hdr,
	    pd, err);
}

/* Same magic as SS990915, *different* extra crap, sigh.
   Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
libpcap_dump_pcap_ss991029(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info _U_)
{
	struct pcaprec_modified_hdr rec_hdr;

	/*
	 * Some code that reads libpcap files may handle time
	 * stamps as unsigned, but most of it probably handles
	 * them as signed.
	 */
	if (rec->ts.secs < 0 || rec->ts.secs > G_MAXINT32) {
		*err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
		return FALSE;
	}
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
	return libpcap_dump_write_packet(wdh, rec, &rec_hdr.hdr, sizeof rec_hdr,
	    pd, err);
}

/* Nokia libpcap of some sort.
   Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean
libpcap_dump_pcap_nokia(wtap_dumper *wdh, const wtap_rec *rec,
    const guint8 *pd, int *err, gchar **err_info _U_)
{
	struct pcaprec_nokia_hdr rec_hdr;
	const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;

	/*
	 * Some code that reads libpcap files may handle time
	 * stamps as unsigned, but most of it probably handles
	 * them as signed.
	 */
	if (rec->ts.secs < 0 || rec->ts.secs > G_MAXINT32) {
		*err = WTAP_ERR_TIME_STAMP_NOT_SUPPORTED;
		return FALSE;
	}
	rec_hdr.hdr.ts_sec = (guint32) rec->ts.secs;
	rec_hdr.hdr.ts_usec = rec->ts.nsecs / 1000;
	/* restore the "mysterious stuff" that came with the packet */
	memcpy(rec_hdr.stuff, pseudo_header->nokia.stuff, 4);
	return libpcap_dump_write_packet(wdh, rec, &rec_hdr.hdr, sizeof rec_hdr,
	    pd, err);
}

static const struct supported_block_type pcap_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info pcap_info = {
	/* Gianluca Varenni suggests that we add "deprecated" to the description. */
	"Wireshark/tcpdump/... - pcap", "pcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	libpcap_dump_can_write_encap, libpcap_dump_open_pcap, NULL
};

static const struct file_type_subtype_info pcap_nsec_info = {
	"Wireshark/tcpdump/... - nanosecond pcap", "nsecpcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	libpcap_dump_can_write_encap, libpcap_dump_open_pcap_nsec, NULL
};

static const struct file_type_subtype_info pcap_aix_info = {
	"AIX tcpdump - pcap", "aixpcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	NULL, NULL, NULL
};

static const struct file_type_subtype_info pcap_ss990417_info = {
	"RedHat 6.1 tcpdump - pcap", "rh6_1pcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	libpcap_dump_can_write_encap, libpcap_dump_open_pcap_ss990417, NULL
};

static const struct file_type_subtype_info pcap_ss990915_info = {
	"SuSE 6.3 tcpdump - pcap", "suse6_3pcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	libpcap_dump_can_write_encap, libpcap_dump_open_pcap_ss990915, NULL
};

static const struct file_type_subtype_info pcap_ss991029_info = {
	"Modified tcpdump - pcap", "modpcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	libpcap_dump_can_write_encap, libpcap_dump_open_pcap_ss991029, NULL
};

static const struct file_type_subtype_info pcap_nokia_info = {
	"Nokia tcpdump - pcap", "nokiapcap", "pcap", "cap;dmp",
	FALSE, BLOCKS_SUPPORTED(pcap_blocks_supported),
	libpcap_dump_can_write_encap, libpcap_dump_open_pcap_nokia, NULL
};

void register_pcap(void)
{
	pcap_file_type_subtype = wtap_register_file_type_subtype(&pcap_info);
	pcap_nsec_file_type_subtype = wtap_register_file_type_subtype(&pcap_nsec_info);
	pcap_aix_file_type_subtype = wtap_register_file_type_subtype(&pcap_aix_info);
	pcap_ss990417_file_type_subtype = wtap_register_file_type_subtype(&pcap_ss990417_info);
	pcap_ss990915_file_type_subtype = wtap_register_file_type_subtype(&pcap_ss990915_info);
	pcap_ss991029_file_type_subtype = wtap_register_file_type_subtype(&pcap_ss991029_info);
	pcap_nokia_file_type_subtype = wtap_register_file_type_subtype(&pcap_nokia_info);

	/*
	 * We now call the libpcap file format just pcap, but we allow
	 * the various variants of it to be specified using names
	 * containing "libpcap" as well as "pcap", for backwards
	 * compatibility.
	 *
	 * Register names for that purpose.
	 */
	wtap_register_compatibility_file_subtype_name("libpcap", "pcap");
	wtap_register_compatibility_file_subtype_name("nseclibpcap", "nsecpcap");
	wtap_register_compatibility_file_subtype_name("aixlibpcap", "aixpcap");
	wtap_register_compatibility_file_subtype_name("modlibpcap", "modpcap");
	wtap_register_compatibility_file_subtype_name("nokialibpcap", "nokiapcap");
	wtap_register_compatibility_file_subtype_name("rh6_1libpcap", "rh6_1pcap");
	wtap_register_compatibility_file_subtype_name("suse6_3libpcap", "suse6_3pcap");

	/*
	 * Register names for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("PCAP",
	    pcap_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PCAP_NSEC",
	    pcap_nsec_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PCAP_AIX",
	    pcap_aix_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PCAP_SS990417",
	    pcap_ss990417_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PCAP_SS990915",
	    pcap_ss990915_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PCAP_SS991029",
	    pcap_ss991029_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PCAP_NOKIA",
	    pcap_nokia_file_type_subtype);
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
