/* libpcap.c
 *
 * $Id: libpcap.c,v 1.57 2001/11/13 23:55:43 gram Exp $
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


/* Try to read the first two records of the capture file. */
typedef enum {
	THIS_FORMAT,		/* the reads succeeded, assume it's this format */
	BAD_READ,		/* the file is probably not valid */
	OTHER_FORMAT		/* the file may be valid, but not in this format */
} libpcap_try_t;
static libpcap_try_t libpcap_try(wtap *wth, int *err);

static gboolean libpcap_read(wtap *wth, int *err, long *data_offset);
static int libpcap_read_header(wtap *wth, int *err,
    struct pcaprec_ss990915_hdr *hdr, gboolean silent);
static void adjust_header(wtap *wth, struct pcaprec_hdr *hdr);
static void libpcap_close(wtap *wth);
static gboolean libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err);

/*
 * Either LBL NRG wasn't an adequate central registry (e.g., because of
 * the slow rate of releases from them), or nobody bothered using them
 * as a central registry, as many different groups have patched libpcap
 * (and BPF, on the BSDs) to add new encapsulation types, and have ended
 * up using the same DLT_ values for different encapsulation types.
 *
 * For those numerical encapsulation type values that everybody uses for
 * the same encapsulation type (which inclues those that some platforms
 * specify different DLT_ names for but don't appear to use), we map
 * those values to the appropriate Wiretap values.
 *
 * For those numerical encapsulation type values that different libpcap
 * variants use for different encapsulation types, we check what
 * <pcap.h> defined to determine how to interpret them, so that we
 * interpret them the way the libpcap with which we're building
 * Ethereal/Wiretap interprets them (which, if it doesn't support
 * them at all, means we don't support them either - any capture files
 * using them are foreign, and we don't hazard a guess as to which
 * platform they came from; we could, I guess, choose the most likely
 * platform).
 */

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

static const struct {
	int	dlt_value;
	int	wtap_encap_value;
} pcap_to_wtap_map[] = {
	/*
	 * These are the values that are almost certainly the same
	 * in all libpcaps (I've yet to find one where the values
	 * in question are used for some purpose other than the
	 * one below, but...), and that Wiretap and Ethereal
	 * currently support.
	 */
	{ 0,		WTAP_ENCAP_NULL },	/* null encapsulation */
	{ 1,		WTAP_ENCAP_ETHERNET },
	{ 6,		WTAP_ENCAP_TOKEN_RING },	/* IEEE 802 Networks - assume token ring */
	{ 7,		WTAP_ENCAP_ARCNET },
	{ 8,		WTAP_ENCAP_SLIP },
	{ 9,		WTAP_ENCAP_PPP },
#ifdef BIT_SWAPPED_MAC_ADDRS
	{ 10,		WTAP_ENCAP_FDDI_BITSWAPPED },
#else
	{ 10,		WTAP_ENCAP_FDDI },
#endif

	/*
	 * 11 is DLT_ATM_RFC1483 on most platforms; the only libpcaps I've
	 * seen that define anything other than DLT_ATM_RFC1483 as 11 are
	 * the BSD/OS one, which defines DLT_FR as 11, and libpcap 0.5,
	 * which define it as 100, mapping the kernel's value to 100, in
	 * an attempt to hide the different values used on different
	 * platforms.
	 *
	 * If this is a platform where DLT_FR is defined as 11, we
	 * don't handle 11 at all; otherwise, we handle it as
	 * DLT_ATM_RFC1483 (this means we'd misinterpret Frame Relay
	 * captures from BSD/OS if running on platforms other than BSD/OS,
	 * but
	 *
	 *	1) we don't yet support DLT_FR
	 *
	 * and
	 *
	 *	2) nothing short of a heuristic would let us interpret
	 *	   them correctly).
	 */
#if defined(DLT_FR) && (DLT_FR == 11)
	/* Put entry for Frame Relay here */
#else
	{ 11,		WTAP_ENCAP_ATM_RFC1483 },
#endif

	/*
	 * 12 is DLT_RAW on most platforms, but it's DLT_C_HDLC on
	 * BSD/OS, and DLT_LOOP on OpenBSD.
	 *
	 * We don't yet handle DLT_C_HDLC, but we can handle DLT_LOOP
	 * (it's just like DLT_NULL, only with the AF_ value in network
	 * rather than host byte order - Ethereal figures out the
	 * byte order from the data, so we don't care what byte order
	 * it's in), so if DLT_LOOP is defined as 12, interpret 12
	 * as WTAP_ENCAP_NULL, otherwise, unless DLT_C_HDLC is defined
	 * as 12, interpret it as WTAP_ENCAP_RAW_IP.
	 */
#if defined(DLT_LOOP) && (DLT_LOOP == 12)
	{ 12,		WTAP_ENCAP_NULL },
#elif defined(DLT_C_HDLC) && (DLT_C_HDLC == 12)
	/*
	 * Put entry for Cisco HDLC here.
	 * XXX - is this just WTAP_ENCAP_CHDLC, i.e. does the frame
	 * start with a 4-byte Cisco HDLC header?
	 */
#else
	{ 12,		WTAP_ENCAP_RAW_IP },
#endif

	/*
	 * 13 is DLT_SLIP_BSDOS on FreeBSD and NetBSD, but those OSes
	 * don't actually generate it.  I infer that BSD/OS translates
	 * DLT_SLIP from the kernel BPF code to DLT_SLIP_BSDOS in
	 * libpcap, as the BSD/OS link-layer header is different;
	 * however, in BSD/OS, DLT_SLIP_BSDOS is 15.
	 *
	 * From this, I infer that there's no point in handling 13
	 * as DLT_SLIP_BSDOS.
	 *
	 * 13 is DLT_ATM_RFC1483 on BSD/OS.
	 *
	 * 13 is DLT_ENC in OpenBSD, which is, I suspect, some kind
	 * of decrypted IPSEC traffic.
	 */
#if defined(DLT_ATM_RFC1483) && (DLT_ATM_RFC1483 == 13)
	{ 13,		WTAP_ENCAP_ATM_RFC1483 },
#elif defined(DLT_ENC) && (DLT_ENC == 13)
	/* Put entry for DLT_ENC here */
#endif

	/*
	 * 14 is DLT_PPP_BSDOS on FreeBSD and NetBSD, but those OSes
	 * don't actually generate it.  I infer that BSD/OS translates
	 * DLT_PPP from the kernel BPF code to DLT_PPP_BSDOS in
	 * libpcap, as the BSD/OS link-layer header is different;
	 * however, in BSD/OS, DLT_PPP_BSDOS is 16.
	 *
	 * From this, I infer that there's no point in handling 14
	 * as DLT_PPP_BSDOS.
	 *
	 * 14 is DLT_RAW on BSD/OS and OpenBSD.
	 */
	{ 14,		WTAP_ENCAP_RAW_IP },

	/*
	 * 15 is:
	 *
	 *	DLT_SLIP_BSDOS on BSD/OS;
	 *
	 *	DLT_HIPPI on NetBSD;
	 *
	 *	DLT_LANE8023 with Alexey Kuznetzov's patches for
	 *	Linux libpcap;
	 *
	 *	DLT_I4L_RAWIP with the ISDN4Linux patches for libpcap
	 *	(and on SuSE 6.3);
	 *
	 * but we don't currently handle any of those.
	 */

	/*
	 * 16 is:
	 *
	 *	DLT_PPP_BSDOS on BSD/OS;
	 *
	 *	DLT_HDLC on NetBSD (Cisco HDLC);
	 *
	 *	DLT_CIP with Alexey Kuznetzov's patches for
	 *	Linux libpcap - this is WTAP_ENCAP_LINUX_ATM_CLIP;
	 *
	 *	DLT_I4L_IP with the ISDN4Linux patches for libpcap
	 *	(and on SuSE 6.3).
	 */
#if defined(DLT_CIP) && (DLT_CIP == 16)
	{ 16,		WTAP_ENCAP_LINUX_ATM_CLIP },
#endif
#if defined(DLT_HDLC) && (DLT_HDLC == 16)
	{ 16,		WTAP_ENCAP_CHDLC },
#endif

	/*
	 * 17 is DLT_LANE8023 in SuSE 6.3 libpcap; we don't currently
	 * handle it.
	 */

	/*
	 * 18 is DLT_CIP in SuSE 6.3 libpcap; if it's the same as the
	 * DLT_CIP of 16 that the Alexey Kuznetzov patches for
	 * libpcap/tcpdump define, it's WTAP_ENCAP_LINUX_ATM_CLIP.
	 * I've not found any libpcap that uses it for any other purpose -
	 * hopefully nobody will do so in the future.
	 */
	{ 18,		WTAP_ENCAP_LINUX_ATM_CLIP },

	/*
	 * 19 is DLT_ATM_CLIP in the libpcap/tcpdump patches in the
	 * recent versions I've seen of the Linux ATM distribution;
	 * I've not yet found any libpcap that uses it for any other
	 * purpose - hopefully nobody will do so in the future.
	 */
	{ 19,		WTAP_ENCAP_LINUX_ATM_CLIP },

	/*
	 * 50 is DLT_PPP_SERIAL in NetBSD; it appears that DLT_PPP
	 * on BSD (at least according to standard tcpdump) has, as
	 * the first octet, an indication of whether the packet was
	 * transmitted or received (rather than having the standard
	 * PPP address value of 0xff), but that DLT_PPP_SERIAL puts
	 * a real live PPP header there, or perhaps a Cisco PPP header
	 * as per section 4.3.1 of RFC 1547 (implementations of this
	 * exist in various BSDs in "sys/net/if_spppsubr.c", and
	 * I think also exist either in standard Linux or in
	 * various Linux patches; the implementations show how to handle
	 * Cisco keepalive packets).
	 *
	 * However, I don't see any obvious place in FreeBSD "if_ppp.c"
	 * where anything other than the standard PPP header would be
	 * passed up.  I see some stuff that sets the first octet
	 * to 0 for incoming and 1 for outgoing packets before applying
	 * a BPF filter to see whether to drop packets whose protocol
	 * field has the 0x8000 bit set, i.e. network control protocols -
	 * those are handed up to userland - but that code puts the
	 * address field back before passing the packet up.
	 *
	 * I also don't see anything immediately obvious that munges
	 * the address field for sync PPP, either.
	 *
	 * Ethereal currently assumes that if the first octet of a
	 * PPP frame is 0xFF, it's the address field and is followed
	 * by a control field and a 2-byte protocol, otherwise the
	 * address and control fields are absent and the frame begins
	 * with a protocol field.  If we ever see a BSD/OS PPP
	 * capture, we'll have to handle it differently, and we may
	 * have to handle standard BSD captures differently if, in fact,
	 * they don't have 0xff 0x03 as the first two bytes - but, as per
	 * the two paragraphs preceding this, it's not clear that
	 * the address field *is* munged into an incoming/outgoing
	 * field when the packet is handed to the BPF device.
	 *
	 * For now, we just map DLT_PPP_SERIAL to WTAP_ENCAP_PPP, as
	 * we treat WTAP_ENCAP_PPP packets as if those beginning with
	 * 0xff have the standard RFC 1662 "PPP in HDLC-like Framing"
	 * 0xff 0x03 address/control header, and DLT_PPP_SERIAL frames
	 * appear to contain that unless they're Cisco frames (if we
	 * ever see a capture with them, we'd need to implement the
	 * RFC 1547 stuff, and the keepalive protocol stuff).
	 *
	 * We may have to distinguish between "PPP where if it doesn't
	 * begin with 0xff there's no HDLC encapsulation and the frame
	 * begins with the protocol field" (which is how we handle
	 * WTAP_ENCAP_PPP now) and "PPP where there's either HDLC
	 * encapsulation or Cisco PPP" (which is what DLT_PPP_SERIAL
	 * is) at some point.
	 *
	 * XXX - NetBSD has DLT_HDLC, which appears to be used for
	 * Cisco HDLC.  Ideally, they should use DLT_PPP_SERIAL
	 * only for real live HDLC-encapsulated PPP, not for Cisco
	 * HDLC.
	 */
	{ 50,		WTAP_ENCAP_PPP },

	/*
	 * These are the values that libpcap 0.5 uses, in an attempt
	 * to work around the confusion decried above, and that Wiretap
	 * and Ethereal currently support.
	 *
	 * The next version of libpcap will probably not use them as
	 * DLT_ values in its API, but will probably use them in capture
	 * file headers.
	 */
	{ 100,		WTAP_ENCAP_ATM_RFC1483 },
	{ 101,		WTAP_ENCAP_RAW_IP },
#if 0
	/*
	 * More values used by libpcap 0.5 as DLT_ values and used by the
	 * current CVS version of libpcap in capture file headers.
	 * They are not yet handled in Ethereal.
	 * If we get a capture that contains them, we'll implement them.
	 */
	{ 102,		WTAP_ENCAP_SLIP_BSDOS },
	{ 103,		WTAP_ENCAP_PPP_BSDOS },
#endif

	/*
	 * These ones are handled in Ethereal, though.
	 */
	{ 104,		WTAP_ENCAP_CHDLC },	/* Cisco HDLC */
	{ 106,		WTAP_ENCAP_LINUX_ATM_CLIP },

	/*
	 * Values not yet used by the current CVS version of libpcap,
	 * but reserved for future use; the IEEE 802.11 value is
	 * there for use with a capture program from Axis Communications.
	 */
	{ 105,		WTAP_ENCAP_IEEE_802_11 },
#if 0
	/*
	 * Not yet handled in Ethereal; we don't know what encapsulation
	 * BSD/OS uses, so we don't know whether it can be handed to
	 * the Frame Relay dissector or not.
	 */
	{ 107,		WTAP_ENCAP_FR },	/* Frame Relay */
#endif
	{ 108,		WTAP_ENCAP_NULL },	/* OpenBSD loopback */
#if 0
	{ 109,		WTAP_ENCAP_ENC },	/* OpenBSD IPSEC enc */
	{ 110,		WTAP_ENCAP_LANE_802_3 },/* ATM LANE 802.3 */
	{ 111,		WTAP_ENCAP_HIPPI },	/* NetBSD HIPPI */
#endif
	{ 112,		WTAP_ENCAP_CHDLC },	/* NetBSD HDLC framing */

	/*
	 * Linux "cooked mode" captures, used by the current CVS version
	 * of libpcap.
	 */
	{ 113,		WTAP_ENCAP_SLL },	/* Linux cooked capture */

    { 118,      WTAP_ENCAP_CISCO_IOS },
};
#define NUM_PCAP_ENCAPS (sizeof pcap_to_wtap_map / sizeof pcap_to_wtap_map[0])

int libpcap_open(wtap *wth, int *err)
{
	int bytes_read;
	guint32 magic;
	struct pcap_hdr hdr;
	gboolean byte_swapped;
	gboolean modified;
	gboolean aix;
	int file_encap;

	/* Read in the number that should be at the start of a "libpcap" file */
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
	 * DLT_PPP, and DLT_SLIP_BSDOS, respectively.  We shall
	 * assume that if the minor version number is 2, and
	 * the network type is 6, 9, or 15, that it's AIX libpcap;
	 *
	 * I'm assuming those older versions of libpcap didn't
	 * use DLT_IEEE802 for Token Ring, and didn't use DLT_SLIP_BSDOS
	 * as that came later.  It may have used DLT_SLIP, however, in
	 * which case we're out of luck; we assume it's Token Ring
	 * in AIX libpcap rather than PPP in standard libpcap, as
	 * you're probably more likely to be handing an AIX libpcap
	 * token-ring capture than an old (pre-libpcap 0.4) PPP capture
	 * to Ethereal.
	 */
	aix = FALSE;	/* assume it's not AIX */
	if (hdr.version_major == 2 && hdr.version_minor == 2) {
		switch (hdr.network) {

		case 6:
			hdr.network = 1;	/* DLT_EN10MB, Ethernet */
			aix = TRUE;
			break;

		case 8:
			hdr.network = 6;	/* DLT_IEEE802, Token Ring */
			aix = TRUE;
			break;

		case 15:
			hdr.network = 10;	/* DLT_FDDI, FDDI */
			aix = TRUE;
			break;
		}
	}
	file_encap = wtap_pcap_encap_to_wtap_encap(hdr.network);
	if (file_encap == WTAP_ENCAP_UNKNOWN) {
		g_message("pcap: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/* This is a libpcap file */
	wth->capture.pcap = g_malloc(sizeof(libpcap_t));
	wth->capture.pcap->byte_swapped = byte_swapped;
	wth->capture.pcap->version_major = hdr.version_major;
	wth->capture.pcap->version_minor = hdr.version_minor;
	wth->subtype_read = libpcap_read;
	wth->subtype_seek_read = wtap_def_seek_read;
	wth->subtype_close = libpcap_close;
	wth->file_encap = file_encap;
	wth->snapshot_length = hdr.snaplen;

	/*
	 * Is this AIX format?
	 */
	if (aix) {
		/*
		 * Yes.  Skip all the tests for other mutant formats.
		 */
		wth->file_type = WTAP_FILE_PCAP_AIX;
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
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be 991029.
			 * Put the seek pointer back, and return success.
			 */
			file_seek(wth->fh, wth->data_offset, SEEK_SET);
			return 1;

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
		file_seek(wth->fh, wth->data_offset, SEEK_SET);
	} else {
		/*
		 * Well, we have the standard magic number.
		 *
		 * Try the standard format first.
		 */
		wth->file_type = WTAP_FILE_PCAP;
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be a standard
			 * libpcap file.
			 * Put the seek pointer back, and return success.
			 */
			file_seek(wth->fh, wth->data_offset, SEEK_SET);
			return 1;

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
		file_seek(wth->fh, wth->data_offset, SEEK_SET);
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be ss990417.
			 * Put the seek pointer back, and return success.
			 */
			file_seek(wth->fh, wth->data_offset, SEEK_SET);
			return 1;

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
		file_seek(wth->fh, wth->data_offset, SEEK_SET);
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
	if (libpcap_read_header(wth, err, &first_rec_hdr, TRUE) == -1) {
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

		if (*err == WTAP_ERR_BAD_RECORD) {
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
	file_seek(wth->fh, first_rec_hdr.hdr.incl_len, SEEK_CUR);

	/*
	 * Now attempt to read the second record's header.
	 */
	if (libpcap_read_header(wth, err, &second_rec_hdr, TRUE) == -1) {
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

		if (*err == WTAP_ERR_BAD_RECORD) {
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
static gboolean libpcap_read(wtap *wth, int *err, long *data_offset)
{
	struct pcaprec_ss990915_hdr hdr;
	guint packet_size;
	int bytes_read;

	bytes_read = libpcap_read_header(wth, err, &hdr, FALSE);
	if (bytes_read == -1) {
		/*
		 * We failed to read the header.
		 */
		return FALSE;
	}

	wth->data_offset += bytes_read;
	packet_size = hdr.hdr.incl_len;

	buffer_assure_space(wth->frame_buffer, packet_size);
	*data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
			packet_size, wth->fh);

	if ((guint)bytes_read != packet_size) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	wth->data_offset += packet_size;

	wth->phdr.ts.tv_sec = hdr.hdr.ts_sec;
	wth->phdr.ts.tv_usec = hdr.hdr.ts_usec;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = hdr.hdr.orig_len;
	wth->phdr.pkt_encap = wth->file_encap;

	return TRUE;
}

/* Read the header of the next packet; if "silent" is TRUE, don't complain
   to the console, as we're testing to see if the file appears to be of a
   particular type.

   Return -1 on an error, or the number of bytes of header read on success. */
static int libpcap_read_header(wtap *wth, int *err,
    struct pcaprec_ss990915_hdr *hdr, gboolean silent)
{
	int	bytes_to_read, bytes_read;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	switch (wth->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_AIX:
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
	bytes_read = file_read(hdr, 1, bytes_to_read, wth->fh);
	if (bytes_read != bytes_to_read) {
		*err = file_error(wth->fh);
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
		if (!silent) {
			g_message("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr->hdr.incl_len, WTAP_MAX_PACKET_SIZE);
		}
		*err = WTAP_ERR_BAD_RECORD;
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
		if (!silent) {
			g_message("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr->hdr.orig_len, WTAP_MAX_PACKET_SIZE);
		}
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}

	return bytes_read;
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

	/* If this is AIX, convert the time stamp from seconds/nanoseconds
	   to seconds/microseconds.  */
	if (wth->file_type == WTAP_FILE_PCAP_AIX)
		hdr->ts_usec = hdr->ts_usec/1000;

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
	unsigned int i;

	for (i = 0; i < NUM_PCAP_ENCAPS; i++) {
		if (pcap_to_wtap_map[i].dlt_value == encap)
			return pcap_to_wtap_map[i].wtap_encap_value;
	}
	return WTAP_ENCAP_UNKNOWN;
}

static int wtap_wtap_encap_to_pcap_encap(int encap)
{
	unsigned int i;

	/*
	 * Special-case WTAP_ENCAP_FDDI and WTAP_ENCAP_FDDI_BITSWAPPED;
	 * both of them get mapped to DLT_FDDI (even though that may
	 * mean that the bit order in the FDDI MAC addresses is wrong;
	 * so it goes - libpcap format doesn't record the byte order,
	 * so that's not fixable).
	 */
	if (encap == WTAP_ENCAP_FDDI || encap == WTAP_ENCAP_FDDI_BITSWAPPED)
		return 10;	/* that's DLT_FDDI */
	for (i = 0; i < NUM_PCAP_ENCAPS; i++) {
		if (pcap_to_wtap_map[i].wtap_encap_value == encap)
			return pcap_to_wtap_map[i].dlt_value;
	}
	return -1;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int libpcap_dump_can_write_encap(int filetype, int encap)
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
	size_t nwritten;

	/* This is a libpcap file */
	wdh->subtype_write = libpcap_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_PCAP_NOKIA:	/* Nokia libpcap of some sort */
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
		if (nwritten == 0 && ferror(wdh->fh))
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
	file_hdr.network = wtap_wtap_encap_to_pcap_encap(wdh->encap);
	nwritten = fwrite(&file_hdr, 1, sizeof file_hdr, wdh->fh);
	if (nwritten != sizeof file_hdr) {
		if (nwritten == 0 && ferror(wdh->fh))
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
	size_t hdr_size;
	size_t nwritten;

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

	case WTAP_FILE_PCAP_NOKIA:	/* old magic, extra crap at the end */
		rec_hdr.ifindex = 0;
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

	nwritten = fwrite(&rec_hdr, 1, hdr_size, wdh->fh);
	if (nwritten != hdr_size) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	return TRUE;
}
