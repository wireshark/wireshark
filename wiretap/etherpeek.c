/* etherpeek.c
 * Routines for opening EtherPeek (and TokenPeek?) files
 * Copyright (c) 2001, Daniel Thompson <d.thompson@gmx.net>
 *
 * $Id: etherpeek.c,v 1.16 2002/02/15 11:35:13 guy Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "etherpeek.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* CREDITS
 *
 * This file decoder could not have been writen without examining how
 * tcptrace (http://www.tcptrace.org/) handles EtherPeek files.
 */

/* master header */
typedef struct etherpeek_master_header {
	guint8  version;
	guint8  status;
} etherpeek_master_header_t;
#define ETHERPEEK_MASTER_HDR_SIZE 2

/* secondary header (V5,V6,V7) */
typedef struct etherpeek_v567_header {
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
} etherpeek_v567_header_t;
#define ETHERPEEK_V567_HDR_SIZE 48

/* full header */
typedef struct etherpeek_header {
	etherpeek_master_header_t master;
	union {
		etherpeek_v567_header_t v567;
	} secondary;
} etherpeek_header_t;

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
#define ETHERPEEK_V56_LENGTH_OFFSET		0
#define ETHERPEEK_V56_SLICE_LENGTH_OFFSET	2
#define ETHERPEEK_V56_FLAGS_OFFSET		4
#define ETHERPEEK_V56_STATUS_OFFSET		5
#define ETHERPEEK_V56_TIMESTAMP_OFFSET		6
#define ETHERPEEK_V56_DESTNUM_OFFSET		10
#define ETHERPEEK_V56_SRCNUM_OFFSET		12
#define ETHERPEEK_V56_PROTONUM_OFFSET		14
#define ETHERPEEK_V56_PROTOSTR_OFFSET		16
#define ETHERPEEK_V56_FILTERNUM_OFFSET		24
#define ETHERPEEK_V56_PKT_SIZE			26

/* 64-bit time in micro seconds from the (Mac) epoch */
typedef struct etherpeek_utime {
	guint32 upper;
	guint32 lower;
} etherpeek_utime;

/*
 * Packet header (V7).
 *
 * This doesn't have the same alignment problem, but we do it with
 * #defines anyway.
 */
#define ETHERPEEK_V7_PROTONUM_OFFSET		0
#define ETHERPEEK_V7_LENGTH_OFFSET		2
#define ETHERPEEK_V7_SLICE_LENGTH_OFFSET	4
#define ETHERPEEK_V7_FLAGS_OFFSET		6
#define ETHERPEEK_V7_STATUS_OFFSET		7
#define ETHERPEEK_V7_TIMESTAMP_UPPER_OFFSET	8
#define ETHERPEEK_V7_TIMESTAMP_LOWER_OFFSET	12
#define ETHERPEEK_V7_PKT_SIZE			16

typedef struct etherpeek_encap_lookup {
	guint16 protoNum;
	int     encap;
} etherpeek_encap_lookup_t;

static const unsigned int mac2unix = 2082844800u;
static const etherpeek_encap_lookup_t etherpeek_encap[] = {
	{ 1400, WTAP_ENCAP_ETHERNET }
};
#define NUM_ETHERPEEK_ENCAPS \
	(sizeof (etherpeek_encap) / sizeof (etherpeek_encap[0]))

static gboolean etherpeek_read_v7(wtap *wth, int *err, long *data_offset);
static gboolean etherpeek_read_v56(wtap *wth, int *err, long *data_offset);
static void etherpeek_close(wtap *wth);

int etherpeek_open(wtap *wth, int *err)
{
	etherpeek_header_t ep_hdr;
	struct timeval reference_time;
	static const int etherpeek_v7_encap[] = {
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TOKEN_RING,
	};
	#define NUM_ETHERPEEK_V7_ENCAPS (sizeof etherpeek_v7_encap / sizeof etherpeek_v7_encap[0])
	int file_encap;

	/* EtherPeek files do not start with a magic value large enough
	 * to be unique; hence we use the following algorithm to determine
	 * the type of an unknown file:
	 *  - populate the master header and reject file if there is no match
	 *  - populate the secondary header and check that the reserved space
	 *      is zero, and check some other fields; this isn't perfect,
	 *	and we may have to add more checks at some point.
	 */
	g_assert(sizeof(ep_hdr.master) == ETHERPEEK_MASTER_HDR_SIZE);
	wtap_file_read_unknown_bytes(
		&ep_hdr.master, sizeof(ep_hdr.master), wth->fh, err);
	wth->data_offset += sizeof(ep_hdr.master);

	/* switch on the file version */
	switch (ep_hdr.master.version) {

	case 5:
	case 6:
	case 7:
		/* get the secondary header */
		g_assert(sizeof(ep_hdr.secondary.v567) ==
		        ETHERPEEK_V567_HDR_SIZE);
		wtap_file_read_unknown_bytes(
			&ep_hdr.secondary.v567,
			sizeof(ep_hdr.secondary.v567), wth->fh, err);
		wth->data_offset += sizeof(ep_hdr.secondary.v567);

		if ((0 != ep_hdr.secondary.v567.reserved[0]) ||
		    (0 != ep_hdr.secondary.v567.reserved[1]) ||
		    (0 != ep_hdr.secondary.v567.reserved[2])) {
			/* still unknown */
			return 0;
		}

		/*
		 * Check the mediaType and physMedium fields.
		 * We assume it's not an EtherPeek/TokenPeek/AiroPeek
		 * file if these aren't values we know, rather than
		 * reporting them as invalid *Peek files, as, given
		 * the lack of a magic number, we need all the checks
		 * we can get.
		 */
		ep_hdr.secondary.v567.mediaType =
		    ntohl(ep_hdr.secondary.v567.mediaType);
		ep_hdr.secondary.v567.physMedium =
		    ntohl(ep_hdr.secondary.v567.physMedium);

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
				 * Assume this isn't a *Peek file.
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
				file_encap = WTAP_ENCAP_AIROPEEK;
				break;

			default:
				/*
				 * Assume this isn't a *Peek file.
				 */
				return 0;
			}
			break;

		default:
			/*
			 * Assume this isn't a *Peek file.
			 */
			return 0;
		}
		

		/*
		 * Assume this is a V5, V6 or V7 *Peek file, and byte
		 * swap the rest of the fields in the secondary header.
		 *
		 * XXX - we could check the file length if the file were
		 * uncompressed, but it might be compressed.
		 */
		ep_hdr.secondary.v567.filelength =
		    ntohl(ep_hdr.secondary.v567.filelength);
		ep_hdr.secondary.v567.numPackets =
		    ntohl(ep_hdr.secondary.v567.numPackets);
		ep_hdr.secondary.v567.timeDate =
		    ntohl(ep_hdr.secondary.v567.timeDate);
		ep_hdr.secondary.v567.timeStart =
		    ntohl(ep_hdr.secondary.v567.timeStart);
		ep_hdr.secondary.v567.timeStop =
		    ntohl(ep_hdr.secondary.v567.timeStop);
		ep_hdr.secondary.v567.appVers =
		    ntohl(ep_hdr.secondary.v567.appVers);
		ep_hdr.secondary.v567.linkSpeed =
		    ntohl(ep_hdr.secondary.v567.linkSpeed);

		/* Get the reference time as a "struct timeval" */
		reference_time.tv_sec  =
		    ep_hdr.secondary.v567.timeDate - mac2unix;
		reference_time.tv_usec = 0;
		break;

	default:
		/*
		 * Assume this isn't a *Peek file.
		 */
		return 0;
	}

	/*
	 * This is an EtherPeek (or TokenPeek or AiroPeek?) file.
	 *
	 * At this point we have recognised the file type and have populated
	 * the whole ep_hdr structure in host byte order.
	 */
	wth->capture.etherpeek = g_malloc(sizeof(etherpeek_t));
	wth->capture.etherpeek->reference_time = reference_time;
	wth->subtype_close = etherpeek_close;
	switch (ep_hdr.master.version) {

	case 5:
	case 6:
		wth->file_type = WTAP_FILE_ETHERPEEK_V56;
		/*
		 * XXX - can we get the file encapsulation from the
		 * header in the same way we do for V7 files?
		 */
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
		wth->subtype_read = etherpeek_read_v56;
		wth->subtype_seek_read = wtap_def_seek_read;
		break;

	case 7:
		wth->file_type = WTAP_FILE_ETHERPEEK_V7;
		wth->file_encap = file_encap;
		wth->subtype_read = etherpeek_read_v7;
		wth->subtype_seek_read = wtap_def_seek_read;
		break;

	default:
		/* this is impossible */
		g_assert_not_reached();
	}

	wth->snapshot_length   = 0; /* not available in header */

	return 1;
}

static void etherpeek_close(wtap *wth)
{
	g_free(wth->capture.etherpeek);
}

static gboolean etherpeek_read_v7(wtap *wth, int *err, long *data_offset)
{
	guchar ep_pkt[ETHERPEEK_V7_PKT_SIZE];
	guint16 protoNum;
	guint16 length;
	guint16 sliceLength;
	guint8  flags;
	guint8  status;
	etherpeek_utime timestamp;
	double  t;
	unsigned int i;

	wtap_file_read_expected_bytes(ep_pkt, sizeof(ep_pkt), wth->fh, err);
	wth->data_offset += sizeof(ep_pkt);

	/* Extract the fields from the packet */
	protoNum = pntohs(&ep_pkt[ETHERPEEK_V7_PROTONUM_OFFSET]);
	length = pntohs(&ep_pkt[ETHERPEEK_V7_LENGTH_OFFSET]);
	sliceLength = pntohs(&ep_pkt[ETHERPEEK_V7_SLICE_LENGTH_OFFSET]);
	flags = ep_pkt[ETHERPEEK_V7_FLAGS_OFFSET];
	status = ep_pkt[ETHERPEEK_V7_STATUS_OFFSET];
	timestamp.upper = pntohl(&ep_pkt[ETHERPEEK_V7_TIMESTAMP_UPPER_OFFSET]);
	timestamp.lower = pntohl(&ep_pkt[ETHERPEEK_V7_TIMESTAMP_LOWER_OFFSET]);

	/* force sliceLength to be the actual length of the packet */
	if (0 == sliceLength) {
		sliceLength = length;
	}

	/* test for corrupt data */
	if (sliceLength > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	*data_offset = wth->data_offset;

	/* fill in packet header length values before slicelength may be
	   adjusted */
	wth->phdr.len    = length;
	wth->phdr.caplen = sliceLength;

	if (sliceLength % 2) /* packets are padded to an even length */
		sliceLength++;

	/* read the frame data */
	buffer_assure_space(wth->frame_buffer, sliceLength);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
	                              sliceLength, wth->fh, err);
	wth->data_offset += sliceLength;

	/* fill in packet header values */
	t =  (double) timestamp.lower +
	     (double) timestamp.upper * 4294967296.0;
	t -= (double) mac2unix * 1000000.0;
	wth->phdr.ts.tv_sec  = (time_t)  (t/1000000.0);
	wth->phdr.ts.tv_usec = (guint32) (t - (double) wth->phdr.ts.tv_sec *
	                                               1000000.0);

	wth->phdr.pkt_encap = wth->file_encap;
	return TRUE;
}

static gboolean etherpeek_read_v56(wtap *wth, int *err, long *data_offset)
{
	guchar ep_pkt[ETHERPEEK_V56_PKT_SIZE];
	guint16 length;
	guint16 sliceLength;
	guint8  flags;
	guint8  status;
	guint32 timestamp;
	guint16 destNum;
	guint16 srcNum;
	guint16 protoNum;
	char    protoStr[8];
	unsigned int i;

	wtap_file_read_expected_bytes(ep_pkt, sizeof(ep_pkt), wth->fh, err);
	wth->data_offset += sizeof(ep_pkt);

	/* Extract the fields from the packet */
	length = pntohs(&ep_pkt[ETHERPEEK_V56_LENGTH_OFFSET]);
	sliceLength = pntohs(&ep_pkt[ETHERPEEK_V56_SLICE_LENGTH_OFFSET]);
	flags = ep_pkt[ETHERPEEK_V56_FLAGS_OFFSET];
	status = ep_pkt[ETHERPEEK_V56_STATUS_OFFSET];
	timestamp = pntohl(&ep_pkt[ETHERPEEK_V56_TIMESTAMP_OFFSET]);
	destNum = pntohs(&ep_pkt[ETHERPEEK_V56_DESTNUM_OFFSET]);
	srcNum = pntohs(&ep_pkt[ETHERPEEK_V56_SRCNUM_OFFSET]);
	protoNum = pntohs(&ep_pkt[ETHERPEEK_V56_PROTONUM_OFFSET]);
	memcpy(protoStr, &ep_pkt[ETHERPEEK_V56_PROTOSTR_OFFSET],
	    sizeof protoStr);

	/*
	 * XXX - is the captured packet data padded to a multiple
	 * of 2 bytes?
	 */

	/* force sliceLength to be the actual length of the packet */
	if (0 == sliceLength) {
		sliceLength = length;
	}

	/* test for corrupt data */
	if (sliceLength > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	*data_offset = wth->data_offset;

	/* fill in packet header values */
	wth->phdr.len        = length;
	wth->phdr.caplen     = sliceLength;
	/* timestamp is in milliseconds since reference_time */
	wth->phdr.ts.tv_sec  = wth->capture.etherpeek->reference_time.tv_sec
	    + (timestamp / 1000);
	wth->phdr.ts.tv_usec = 1000 * (timestamp % 1000);

	wth->phdr.pkt_encap = WTAP_ENCAP_UNKNOWN;
	for (i=0; i<NUM_ETHERPEEK_ENCAPS; i++) {
		if (etherpeek_encap[i].protoNum == protoNum) {
			wth->phdr.pkt_encap = etherpeek_encap[i].encap;
		}
	}

	return TRUE;
}
