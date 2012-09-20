/* peekclassic.c
 * Routines for opening files in what WildPackets calls the classic file
 * format in the description of their "PeekRdr Sample Application" (C++
 * source code to read their capture files, downloading of which requires
 * a maintenance contract, so it's not free as in beer and probably not
 * as in speech, either).
 *
 * As that description says, it's used by AiroPeek and AiroPeek NX prior
 * to 2.0, EtherPeek prior to 6.0, and EtherPeek NX prior to 3.0.  It
 * was probably also used by TokenPeek.
 *
 * This handles versions 5, 6, and 7 of that format (the format version
 * number is what appears in the file, and is distinct from the application
 * version number).
 *
 * Copyright (c) 2001, Daniel Thompson <d.thompson@gmx.net>
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
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "peekclassic.h"
/* CREDITS
 *
 * This file decoder could not have been writen without examining how
 * tcptrace (http://www.tcptrace.org/) handles EtherPeek files.
 */

/* master header */
typedef struct peekclassic_master_header {
	guint8  version;
	guint8  status;
} peekclassic_master_header_t;
#define PEEKCLASSIC_MASTER_HDR_SIZE 2

/* secondary header (V5,V6,V7) */
typedef struct peekclassic_v567_header {
	guint32 filelength;
	guint32 numPackets;
	guint32 timeDate;
	guint32 timeStart;
	guint32 timeStop;
	guint32 mediaType;  /* Media Type Ethernet=0 Token Ring = 1 */
	guint32 physMedium; /* Physical Medium native=0 802.1=1 */
	guint32 appVers;    /* App Version Number Maj.Min.Bug.Build */
	guint32 linkSpeed;  /* Link Speed Bits/sec */
	guint32 reserved[3];
} peekclassic_v567_header_t;
#define PEEKCLASSIC_V567_HDR_SIZE 48

/* full header */
typedef struct peekclassic_header {
	peekclassic_master_header_t master;
	union {
		peekclassic_v567_header_t v567;
	} secondary;
} peekclassic_header_t;

/*
 * Packet header (V5, V6).
 *
 * NOTE: the time stamp, although it's a 32-bit number, is only aligned
 * on a 16-bit boundary.  (Does this date back to 68K Macs?  The 68000
 * only required 16-bit alignment of 32-bit quantities, as did the 68010,
 * and the 68020/68030/68040 required no alignment.)
 *
 * As such, we cannot declare this as a C structure, as compilers on
 * most platforms will put 2 bytes of padding before the time stamp to
 * align it on a 32-bit boundary.
 *
 * So, instead, we #define numbers as the offsets of the fields.
 */
#define PEEKCLASSIC_V56_LENGTH_OFFSET		0
#define PEEKCLASSIC_V56_SLICE_LENGTH_OFFSET	2
#define PEEKCLASSIC_V56_FLAGS_OFFSET		4
#define PEEKCLASSIC_V56_STATUS_OFFSET		5
#define PEEKCLASSIC_V56_TIMESTAMP_OFFSET	6
#define PEEKCLASSIC_V56_DESTNUM_OFFSET		10
#define PEEKCLASSIC_V56_SRCNUM_OFFSET		12
#define PEEKCLASSIC_V56_PROTONUM_OFFSET		14
#define PEEKCLASSIC_V56_PROTOSTR_OFFSET		16
#define PEEKCLASSIC_V56_FILTERNUM_OFFSET	24
#define PEEKCLASSIC_V56_PKT_SIZE		26

/* 64-bit time in micro seconds from the (Mac) epoch */
typedef struct peekclassic_utime {
	guint32 upper;
	guint32 lower;
} peekclassic_utime;

/*
 * Packet header (V7).
 *
 * This doesn't have the same alignment problem, but we do it with
 * #defines anyway.
 */
#define PEEKCLASSIC_V7_PROTONUM_OFFSET		0
#define PEEKCLASSIC_V7_LENGTH_OFFSET		2
#define PEEKCLASSIC_V7_SLICE_LENGTH_OFFSET	4
#define PEEKCLASSIC_V7_FLAGS_OFFSET		6
#define PEEKCLASSIC_V7_STATUS_OFFSET		7
#define PEEKCLASSIC_V7_TIMESTAMP_OFFSET		8
#define PEEKCLASSIC_V7_PKT_SIZE			16

typedef struct peekclassic_encap_lookup {
	guint16 protoNum;
	int     encap;
} peekclassic_encap_lookup_t;

static const unsigned int mac2unix = 2082844800u;
static const peekclassic_encap_lookup_t peekclassic_encap[] = {
	{ 1400, WTAP_ENCAP_ETHERNET }
};
#define NUM_PEEKCLASSIC_ENCAPS \
	(sizeof (peekclassic_encap) / sizeof (peekclassic_encap[0]))

typedef struct {
	struct timeval reference_time;
} peekclassic_t;

static gboolean peekclassic_read_v7(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean peekclassic_seek_read_v7(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean peekclassic_read_v56(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean peekclassic_seek_read_v56(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);

int
peekclassic_open(wtap *wth, int *err, gchar **err_info)
{
	peekclassic_header_t ep_hdr;
	struct timeval reference_time;
	int file_encap;
	peekclassic_t *peekclassic;

	/* Peek classic files do not start with a magic value large enough
	 * to be unique; hence we use the following algorithm to determine
	 * the type of an unknown file:
	 *  - populate the master header and reject file if there is no match
	 *  - populate the secondary header and check that the reserved space
	 *      is zero, and check some other fields; this isn't perfect,
	 *	and we may have to add more checks at some point.
	 */
	g_assert(sizeof(ep_hdr.master) == PEEKCLASSIC_MASTER_HDR_SIZE);
	wtap_file_read_unknown_bytes(
		&ep_hdr.master, sizeof(ep_hdr.master), wth->fh, err, err_info);

	/*
	 * It appears that EtherHelp (a free application from WildPackets
	 * that did blind capture, saving to a file, so that you could
	 * give the resulting file to somebody with EtherPeek) saved
	 * captures in EtherPeek format except that it ORed the 0x80
	 * bit on in the version number.
	 *
	 * We therefore strip off the 0x80 bit in the version number.
	 * Perhaps there's some reason to care whether the capture
	 * came from EtherHelp; if we discover one, we should check
	 * that bit.
	 */
	ep_hdr.master.version &= ~0x80;

	/* switch on the file version */
	switch (ep_hdr.master.version) {

	case 5:
	case 6:
	case 7:
		/* get the secondary header */
		g_assert(sizeof(ep_hdr.secondary.v567) ==
		        PEEKCLASSIC_V567_HDR_SIZE);
		wtap_file_read_unknown_bytes(
			&ep_hdr.secondary.v567,
			sizeof(ep_hdr.secondary.v567), wth->fh, err, err_info);

		if ((0 != ep_hdr.secondary.v567.reserved[0]) ||
		    (0 != ep_hdr.secondary.v567.reserved[1]) ||
		    (0 != ep_hdr.secondary.v567.reserved[2])) {
			/* still unknown */
			return 0;
		}

		/*
		 * Check the mediaType and physMedium fields.
		 * We assume it's not a Peek classic file if
		 * these aren't values we know, rather than
		 * reporting them as invalid Peek classic files,
		 * as, given the lack of a magic number, we need
		 * all the checks we can get.
		 */
		ep_hdr.secondary.v567.mediaType =
		    g_ntohl(ep_hdr.secondary.v567.mediaType);
		ep_hdr.secondary.v567.physMedium =
		    g_ntohl(ep_hdr.secondary.v567.physMedium);

		switch (ep_hdr.secondary.v567.physMedium) {

		case 0:
			/*
			 * "Native" format, presumably meaning
			 * Ethernet or Token Ring.
			 */
			switch (ep_hdr.secondary.v567.mediaType) {

			case 0:
				file_encap = WTAP_ENCAP_ETHERNET;
				break;

			case 1:
				file_encap = WTAP_ENCAP_TOKEN_RING;
				break;

			default:
				/*
				 * Assume this isn't a Peek classic file.
				 */
				return 0;
			}
			break;

		case 1:
			switch (ep_hdr.secondary.v567.mediaType) {

			case 0:
				/*
				 * 802.11, with a private header giving
				 * some radio information.  Presumably
				 * this is from AiroPeek.
				 */
				file_encap = WTAP_ENCAP_IEEE_802_11_AIROPEEK;
				break;

			default:
				/*
				 * Assume this isn't a Peek classic file.
				 */
				return 0;
			}
			break;

		default:
			/*
			 * Assume this isn't a Peek classic file.
			 */
			return 0;
		}


		/*
		 * Assume this is a V5, V6 or V7 Peek classic file, and
		 * byte swap the rest of the fields in the secondary header.
		 *
		 * XXX - we could check the file length if the file were
		 * uncompressed, but it might be compressed.
		 */
		ep_hdr.secondary.v567.filelength =
		    g_ntohl(ep_hdr.secondary.v567.filelength);
		ep_hdr.secondary.v567.numPackets =
		    g_ntohl(ep_hdr.secondary.v567.numPackets);
		ep_hdr.secondary.v567.timeDate =
		    g_ntohl(ep_hdr.secondary.v567.timeDate);
		ep_hdr.secondary.v567.timeStart =
		    g_ntohl(ep_hdr.secondary.v567.timeStart);
		ep_hdr.secondary.v567.timeStop =
		    g_ntohl(ep_hdr.secondary.v567.timeStop);
		ep_hdr.secondary.v567.appVers =
		    g_ntohl(ep_hdr.secondary.v567.appVers);
		ep_hdr.secondary.v567.linkSpeed =
		    g_ntohl(ep_hdr.secondary.v567.linkSpeed);

		/* Get the reference time as a "struct timeval" */
		reference_time.tv_sec  =
		    ep_hdr.secondary.v567.timeDate - mac2unix;
		reference_time.tv_usec = 0;
		break;

	default:
		/*
		 * Assume this isn't a Peek classic file.
		 */
		return 0;
	}

	/*
	 * This is a Peek classic file.
	 *
	 * At this point we have recognised the file type and have populated
	 * the whole ep_hdr structure in host byte order.
	 */
	peekclassic = (peekclassic_t *)g_malloc(sizeof(peekclassic_t));
	wth->priv = (void *)peekclassic;
	peekclassic->reference_time = reference_time;
	switch (ep_hdr.master.version) {

	case 5:
	case 6:
		wth->file_type = WTAP_FILE_PEEKCLASSIC_V56;
		/*
		 * XXX - can we get the file encapsulation from the
		 * header in the same way we do for V7 files?
		 */
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
		wth->subtype_read = peekclassic_read_v56;
		wth->subtype_seek_read = peekclassic_seek_read_v56;
		break;

	case 7:
		wth->file_type = WTAP_FILE_PEEKCLASSIC_V7;
		wth->file_encap = file_encap;
		wth->subtype_read = peekclassic_read_v7;
		wth->subtype_seek_read = peekclassic_seek_read_v7;
		break;

	default:
		/* this is impossible */
		g_assert_not_reached();
	}

	wth->snapshot_length   = 0; /* not available in header */
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1;
}

static gboolean
peekclassic_read_v7(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	guint8 ep_pkt[PEEKCLASSIC_V7_PKT_SIZE];
#if 0
	guint16 protoNum;
#endif
	guint16 length;
	guint16 sliceLength;
#if 0
	guint8  flags;
#endif
	guint8  status;
	guint64 timestamp;
	time_t tsecs;
	guint32 tusecs;

	*data_offset = file_tell(wth->fh);

	wtap_file_read_expected_bytes(ep_pkt, sizeof(ep_pkt), wth->fh, err,
	    err_info);

	/* Extract the fields from the packet */
#if 0
	protoNum = pntohs(&ep_pkt[PEEKCLASSIC_V7_PROTONUM_OFFSET]);
#endif
	length = pntohs(&ep_pkt[PEEKCLASSIC_V7_LENGTH_OFFSET]);
	sliceLength = pntohs(&ep_pkt[PEEKCLASSIC_V7_SLICE_LENGTH_OFFSET]);
#if 0
	flags = ep_pkt[PEEKCLASSIC_V7_FLAGS_OFFSET];
#endif
	status = ep_pkt[PEEKCLASSIC_V7_STATUS_OFFSET];
	timestamp = pntohll(&ep_pkt[PEEKCLASSIC_V7_TIMESTAMP_OFFSET]);

	/* force sliceLength to be the actual length of the packet */
	if (0 == sliceLength) {
		sliceLength = length;
	}

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	
	/* fill in packet header length values before slicelength may be
	   adjusted */
	wth->phdr.len    = length;
	wth->phdr.caplen = sliceLength;

	if (sliceLength % 2) /* packets are padded to an even length */
		sliceLength++;

	switch (wth->file_encap) {

	case WTAP_ENCAP_IEEE_802_11_AIROPEEK:
		wth->pseudo_header.ieee_802_11.fcs_len = 0;		/* no FCS */
		wth->pseudo_header.ieee_802_11.decrypted = FALSE;
		break;

	case WTAP_ENCAP_ETHERNET:
		/* XXX - it appears that if the low-order bit of
		   "status" is 0, there's an FCS in this frame,
		   and if it's 1, there's 4 bytes of 0. */
		wth->pseudo_header.eth.fcs_len = (status & 0x01) ? 0 : 4;
		break;
	}

	/* read the frame data */
	buffer_assure_space(wth->frame_buffer, sliceLength);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
	                              sliceLength, wth->fh, err, err_info);

	/* fill in packet header values */
	tsecs = (time_t) (timestamp/1000000);
	tusecs = (guint32) (timestamp - tsecs*1000000);
	wth->phdr.ts.secs  = tsecs - mac2unix;
	wth->phdr.ts.nsecs = tusecs * 1000;

	if (wth->file_encap == WTAP_ENCAP_IEEE_802_11_AIROPEEK) {
		/*
		 * The last 4 bytes appear to be random data - the length
		 * might include the FCS - so we reduce the length by 4.
		 *
		 * Or maybe this is just the same kind of random 4 bytes
		 * of junk at the end you get in Wireless Sniffer
		 * captures.
		 */
		 wth->phdr.len -= 4;
		 wth->phdr.caplen -= 4;
	}

	return TRUE;
}

static gboolean
peekclassic_seek_read_v7(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	guint8 ep_pkt[PEEKCLASSIC_V7_PKT_SIZE];
	guint8  status;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* Read the packet header. */
	wtap_file_read_expected_bytes(ep_pkt, sizeof(ep_pkt), wth->random_fh,
	    err, err_info);
	status = ep_pkt[PEEKCLASSIC_V7_STATUS_OFFSET];

	switch (wth->file_encap) {

	case WTAP_ENCAP_IEEE_802_11_AIROPEEK:
		pseudo_header->ieee_802_11.fcs_len = 0;		/* no FCS */
		pseudo_header->ieee_802_11.decrypted = FALSE;
		break;

	case WTAP_ENCAP_ETHERNET:
		/* XXX - it appears that if the low-order bit of
		   "status" is 0, there's an FCS in this frame,
		   and if it's 1, there's 4 bytes of 0. */
		pseudo_header->eth.fcs_len = (status & 0x01) ? 0 : 4;
		break;
	}

	/*
	 * XXX - should "errno" be set in "wtap_file_read_expected_bytes()"?
	 */
	errno = WTAP_ERR_CANT_READ;
	wtap_file_read_expected_bytes(pd, length, wth->random_fh, err,
	    err_info);
	return TRUE;
}

static gboolean
peekclassic_read_v56(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	peekclassic_t *peekclassic = (peekclassic_t *)wth->priv;
	guint8 ep_pkt[PEEKCLASSIC_V56_PKT_SIZE];
	guint16 length;
	guint16 sliceLength;
#if 0
	guint8  flags;
	guint8  status;
#endif
	guint32 timestamp;
#if 0
	guint16 destNum;
	guint16 srcNum;
#endif
	guint16 protoNum;
	char    protoStr[8];
	unsigned int i;

	/*
	 * XXX - in order to figure out whether this packet is an
	 * Ethernet packet or not, we have to look at the packet
	 * header, so we have to remember the address of the header,
	 * not the address of the data, for random access.
	 *
	 * If we can determine that from the file header, rather than
	 * the packet header, we can remember the offset of the data,
	 * and not have the seek_read routine read the header.
	 */
	*data_offset = file_tell(wth->fh);

	wtap_file_read_expected_bytes(ep_pkt, sizeof(ep_pkt), wth->fh, err,
	    err_info);

	/* Extract the fields from the packet */
	length = pntohs(&ep_pkt[PEEKCLASSIC_V56_LENGTH_OFFSET]);
	sliceLength = pntohs(&ep_pkt[PEEKCLASSIC_V56_SLICE_LENGTH_OFFSET]);
#if 0
	flags = ep_pkt[PEEKCLASSIC_V56_FLAGS_OFFSET];
	status = ep_pkt[PEEKCLASSIC_V56_STATUS_OFFSET];
#endif
	timestamp = pntohl(&ep_pkt[PEEKCLASSIC_V56_TIMESTAMP_OFFSET]);
#if 0
	destNum = pntohs(&ep_pkt[PEEKCLASSIC_V56_DESTNUM_OFFSET]);
	srcNum = pntohs(&ep_pkt[PEEKCLASSIC_V56_SRCNUM_OFFSET]);
#endif
	protoNum = pntohs(&ep_pkt[PEEKCLASSIC_V56_PROTONUM_OFFSET]);
	memcpy(protoStr, &ep_pkt[PEEKCLASSIC_V56_PROTOSTR_OFFSET],
	    sizeof protoStr);

	/*
	 * XXX - is the captured packet data padded to a multiple
	 * of 2 bytes?
	 */

	/* force sliceLength to be the actual length of the packet */
	if (0 == sliceLength) {
		sliceLength = length;
	}

	/* read the frame data */
	buffer_assure_space(wth->frame_buffer, sliceLength);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
	                              sliceLength, wth->fh, err, err_info);

	/* fill in packet header values */
	wth->phdr.len        = length;
	wth->phdr.caplen     = sliceLength;
	/* timestamp is in milliseconds since reference_time */
	wth->phdr.ts.secs  = peekclassic->reference_time.tv_sec
	    + (timestamp / 1000);
	wth->phdr.ts.nsecs = 1000 * (timestamp % 1000) * 1000;

	wth->phdr.pkt_encap = WTAP_ENCAP_UNKNOWN;
	for (i=0; i<NUM_PEEKCLASSIC_ENCAPS; i++) {
		if (peekclassic_encap[i].protoNum == protoNum) {
			wth->phdr.pkt_encap = peekclassic_encap[i].encap;
		}
	}

	switch (wth->phdr.pkt_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		wth->pseudo_header.eth.fcs_len = 0;
		break;
	}
	return TRUE;
}

static gboolean
peekclassic_seek_read_v56(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	guint8 ep_pkt[PEEKCLASSIC_V56_PKT_SIZE];
	int pkt_encap;
	guint16 protoNum;
	unsigned int i;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	wtap_file_read_expected_bytes(ep_pkt, sizeof(ep_pkt), wth->random_fh,
	    err, err_info);

	protoNum = pntohs(&ep_pkt[PEEKCLASSIC_V56_PROTONUM_OFFSET]);
	pkt_encap = WTAP_ENCAP_UNKNOWN;
	for (i=0; i<NUM_PEEKCLASSIC_ENCAPS; i++) {
		if (peekclassic_encap[i].protoNum == protoNum) {
			pkt_encap = peekclassic_encap[i].encap;
		}
	}

	switch (pkt_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		pseudo_header->eth.fcs_len = 0;
		break;
	}

	/*
	 * XXX - should "errno" be set in "wtap_file_read_expected_bytes()"?
	 */
	errno = WTAP_ERR_CANT_READ;
	wtap_file_read_expected_bytes(pd, length, wth->random_fh, err,
	    err_info);
	return TRUE;
}
