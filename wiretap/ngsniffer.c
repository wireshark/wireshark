/* ngsniffer.c
 *
 * $Id: ngsniffer.c,v 1.57 2001/01/08 22:18:22 guy Exp $
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

/* The code in ngsniffer.c that decodes the time fields for each packet in the
 * Sniffer trace originally came from code from TCPVIEW:
 *
 * TCPVIEW
 *
 * Author:	Martin Hunt
 *		Networks and Distributed Computing
 *		Computing & Communications
 *		University of Washington
 *		Administration Building, AG-44
 *		Seattle, WA  98195
 *		Internet: martinh@cac.washington.edu
 *
 *
 * Copyright 1992 by the University of Washington
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appears in all copies and that both the
 * above copyright notice and this permission notice appear in supporting
 * documentation, and that the name of the University of Washington not be
 * used in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  This software is made
 * available "as is", and
 * THE UNIVERSITY OF WASHINGTON DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * WITH REGARD TO THIS SOFTWARE, INCLUDING WITHOUT LIMITATION ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND IN
 * NO EVENT SHALL THE UNIVERSITY OF WASHINGTON BE LIABLE FOR ANY SPECIAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, TORT
 * (INCLUDING NEGLIGENCE) OR STRICT LIABILITY, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "ngsniffer.h"

/* Magic number in Sniffer files. */
static const char ngsniffer_magic[] = {
	'T', 'R', 'S', 'N', 'I', 'F', 'F', ' ', 'd', 'a', 't', 'a',
	' ', ' ', ' ', ' ', 0x1a
};

/*
 * Sniffer record types.
 */
#define REC_VERS	1	/* Version record (f_vers) */
#define REC_FRAME2	4	/* Frame data (f_frame2) */
#define	REC_FRAME4	8	/* Frame data (f_frame4) */
#define REC_FRAME6	12	/* Frame data (f_frame6) (see below) */
#define REC_EOF		3	/* End-of-file record (no data follows) */
/*
 * and now for some unknown header types
 */
#define REC_HEADER1	6	/* Header containing serial numbers? */
#define REC_HEADER2	7	/* Header containing ??? */
#define REC_V2DESC	8	/* In version 2 sniffer traces contains
				 * infos about this capturing session.
				 * Collides with REC_FRAME4 */
#define REC_HEADER3	13	/* Retransmission counts? */
#define REC_HEADER4	14	/* ? */
#define REC_HEADER5	15	/* ? */
#define REC_HEADER6	16	/* More broadcast/retransmission counts? */
#define REC_HEADER7	17	/* ? */


/*
 * Sniffer version record format.
 */
struct vers_rec {
	gint16	maj_vers;	/* major version number */
	gint16	min_vers;	/* minor version number */
	gint16	time;		/* DOS-format time */
	gint16	date;		/* DOS-format date */
	gint8	type;		/* what type of records follow */
	guint8	network;	/* network type */
	gint8	format;		/* format version */
	guint8	timeunit;	/* timestamp units */
	gint8	cmprs_vers;	/* compression version */
	gint8	cmprs_level;	/* compression level */
	gint16	rsvd[2];	/* reserved */
};

/*
 * Sniffer type 2 data record format - followed by frame data.
 */
struct frame2_rec {
	guint16	time_low;	/* low part of time stamp */
	guint16	time_med;	/* middle part of time stamp */
	guint16	time_high;	/* high part of time stamp */
	gint16	size;		/* number of bytes of data */
	guint8	fs;		/* frame error status bits */
	guint8	flags;		/* buffer flags */
	gint16	true_size;	/* size of original frame, in bytes */
	gint16	rsvd;		/* reserved */
};

/*
 * Sniffer type 4 data record format - followed by frame data.
 *
 * XXX - the manual says that the "flags" field holds "buffer flags;
 * BF_xxxx", but doesn't say what the BF_xxxx flags are.
 *
 * XXX - the manual also says there's an 8-byte "ATMTimeStamp" driver
 * time stamp at the end of "ATMSaveInfo", but, from an ATM Sniffer capture
 * file I've looked at, that appears not to be the case.
 */

/*
 * Fields from the AAL5 trailer for the frame, if it's an AAL5 frame
 * rather than a cell.
 */
typedef struct _ATM_AAL5Trailer {
	guint16	aal5t_u2u;	/* user-to-user indicator */
	guint16	aal5t_len;	/* length of the packet */
	guint32	aal5t_chksum; /* checksum for AAL5 packet */
} ATM_AAL5Trailer;

typedef struct _ATMTimeStamp {
	guint32	msw;	/* most significant word */
	guint32	lsw;	/* least significant word */
} ATMTimeStamp;

typedef struct _ATMSaveInfo {
	guint32 StatusWord;	/* status word from driver */
	ATM_AAL5Trailer Trailer; /* AAL5 trailer */
	guint8	AppTrafType;	/* traffic type */
	guint8	AppHLType;	/* protocol type */
	guint16	AppReserved;	/* reserved */
	guint16	Vpi;		/* virtual path identifier */
	guint16	Vci;		/* virtual circuit identifier */
	guint16	channel;	/* link: 0 for DCE, 1 for DTE */
	guint16	cells;		/* number of cells */
	guint32	AppVal1;	/* type-dependent */
	guint32	AppVal2;	/* type-dependent */
} ATMSaveInfo;

/*
 * Bits in StatusWord.
 */
#define	SW_ERRMASK		0x0F	/* Error mask: */
#define	SW_RX_FIFO_UNDERRUN	0x01	/* Receive FIFO underrun */
#define	SW_RX_FIFO_OVERRUN	0x02	/* Receive FIFO overrun */
#define	SW_RX_PKT_TOO_LONG	0x03	/* Received packet > max size */
#define	SW_CRC_ERROR		0x04	/* CRC error */
#define	SW_USER_ABORTED_RX	0x05	/* User aborted receive */
#define	SW_BUF_LEN_TOO_LONG	0x06	/* buffer len > max buf */
#define	SW_INTERNAL_T1_ERROR	0x07	/* Internal T1 error */
#define	SW_RX_CHANNEL_DEACTIV8	0x08	/* Rx channel deactivate */

#define	SW_ERROR		0x80	/* Error indicator */
#define	SW_CONGESTION		0x40	/* Congestion indicator */
#define	SW_CLP			0x20	/* Cell loss priority indicator */
#define	SW_RAW_CELL		0x100	/* RAW cell indicator */
#define	SW_OAM_CELL		0x200	/* OAM cell indicator */

/*
 * Bits in AppTrafType.
 *
 * For AAL types other than AAL5, the packet data is presumably for a
 * single cell, not a reassembled frame, as the ATM Sniffer manual says
 * it dosn't reassemble cells other than AAL5 cells.
 */
#define	ATT_AALTYPE		0x0F	/* AAL type: */
#define	ATT_AAL_UNKNOWN		0x00	/* Unknown AAL */
#define	ATT_AAL1		0x01	/* AAL1 */
#define	ATT_AAL3_4		0x02	/* AAL3/4 */
#define	ATT_AAL5		0x03	/* AAL5 */
#define	ATT_AAL_USER		0x04	/* User AAL */
#define	ATT_AAL_SIGNALLING	0x05	/* Signaling AAL */
#define	ATT_OAMCELL		0x06	/* OAM cell */

#define	ATT_HLTYPE		0xF0	/* Higher-layer type: */
#define	ATT_HL_UNKNOWN		0x00	/* unknown */
#define	ATT_HL_LLCMX		0x10	/* LLC multiplexed (probably RFC 1483) */
#define	ATT_HL_VCMX		0x20	/* VC multiplexed (probably RFC 1483) */
#define	ATT_HL_LANE		0x30	/* LAN Emulation */
#define	ATT_HL_ILMI		0x40	/* ILMI */
#define	ATT_HL_FRMR		0x50	/* Frame Relay */
#define	ATT_HL_SPANS		0x60	/* FORE SPANS */
#define	ATT_HL_IPSILON		0x70	/* Ipsilon */

/*
 * Values for AppHLType; the interpretation depends on the ATT_HLTYPE
 * bits in AppTrafType.
 */
#define	AHLT_UNKNOWN		0x0
#define	AHLT_VCMX_802_3_FCS	0x1	/* VCMX: 802.3 FCS */
#define	AHLT_LANE_LE_CTRL	0x1	/* LANE: LE Ctrl */
#define	AHLT_IPSILON_FT0	0x1	/* Ipsilon: Flow Type 0 */
#define	AHLT_VCMX_802_4_FCS	0x2	/* VCMX: 802.4 FCS */
#define	AHLT_LANE_802_3		0x2	/* LANE: 802.3 */
#define	AHLT_IPSILON_FT1	0x2	/* Ipsilon: Flow Type 1 */
#define	AHLT_VCMX_802_5_FCS	0x3	/* VCMX: 802.5 FCS */
#define	AHLT_LANE_802_5		0x3	/* LANE: 802.5 */
#define	AHLT_IPSILON_FT2	0x3	/* Ipsilon: Flow Type 2 */
#define	AHLT_VCMX_FDDI_FCS	0x4	/* VCMX: FDDI FCS */
#define	AHLT_LANE_802_3_MC	0x4	/* LANE: 802.3 multicast */
#define	AHLT_VCMX_802_6_FCS	0x5	/* VCMX: 802.6 FCS */
#define	AHLT_LANE_802_5_MC	0x5	/* LANE: 802.5 multicast */
#define	AHLT_VCMX_802_3		0x7	/* VCMX: 802.3 */
#define	AHLT_VCMX_802_4		0x8	/* VCMX: 802.4 */
#define	AHLT_VCMX_802_5		0x9	/* VCMX: 802.5 */
#define	AHLT_VCMX_FDDI		0xa	/* VCMX: FDDI */
#define	AHLT_VCMX_802_6		0xb	/* VCMX: 802.6 */
#define	AHLT_VCMX_FRAGMENTS	0xc	/* VCMX: Fragments */
#define	AHLT_VCMX_BPDU		0xe	/* VCMX: BPDU */

struct frame4_rec {
	guint16	time_low;	/* low part of time stamp */
	guint16	time_med;	/* middle part of time stamp */
	gint8	time_high;	/* high part of time stamp */
	gint8	time_day;	/* time in days since start of capture */
	gint16	size;		/* number of bytes of data */
	gint8	fs;		/* frame error status bits */
	gint8	flags;		/* buffer flags */
	gint16	true_size;	/* size of original frame, in bytes */
	gint16	rsvd3;		/* reserved */
	gint16	atm_pad;	/* pad to 4-byte boundary */
	ATMSaveInfo atm_info;	/* ATM-specific stuff */
};

/*
 * XXX - I have a version 5.50 file with a bunch of token ring
 * records listed as type "12".  The record format below was
 * derived from frame4_rec and a bit of experimentation.
 * - Gerald
 */
struct frame6_rec {
	guint16	time_low;	/* low part of time stamp */
	guint16	time_med;	/* middle part of time stamp */
	gint8	time_high;	/* high part of time stamp */
	gint8	time_day;	/* time in days since start of capture */
	gint16	size;		/* number of bytes of data */
	gint8	fs;		/* frame error status bits */
	gint8	flags;		/* buffer flags */
	gint16	true_size;	/* size of original frame, in bytes */
	guint8	chemical_x[22];	/* ? */
};

/* values for V.timeunit */
#define NUM_NGSNIFF_TIMEUNITS 7
static double Usec[] = { 15.0, 0.838096, 15.0, 0.5, 2.0, 1.0, 0.1 };

static int skip_header_records(wtap *wth, int *err, gint16 version);
static gboolean ngsniffer_read(wtap *wth, int *err, int *data_offset);
static int ngsniffer_seek_read(wtap *wth, int seek_off,
    union wtap_pseudo_header *pseudo_header, u_char *pd, int packet_size);
static int ngsniffer_read_rec_header(wtap *wth, gboolean is_random,
    guint16 *typep, guint16 *lengthp, int *err);
static int ngsniffer_read_frame2(wtap *wth, gboolean is_random,
    struct frame2_rec *frame2, int *err);
static void set_pseudo_header_frame2(union wtap_pseudo_header *pseudo_header,
    struct frame2_rec *frame2);
static int ngsniffer_read_frame4(wtap *wth, gboolean is_random,
    struct frame4_rec *frame4, int *err);
static void set_pseudo_header_frame4(union wtap_pseudo_header *pseudo_header,
    struct frame4_rec *frame4);
static int ngsniffer_read_frame6(wtap *wth, gboolean is_random,
    struct frame6_rec *frame6, int *err);
static void set_pseudo_header_frame6(union wtap_pseudo_header *pseudo_header,
    struct frame6_rec *frame6);
static int ngsniffer_read_rec_data(wtap *wth, gboolean is_random, u_char *pd,
    int length, int *err);
static void fix_pseudo_header(wtap *wth,
    union wtap_pseudo_header *pseudo_header);
static void ngsniffer_sequential_close(wtap *wth);
static void ngsniffer_close(wtap *wth);
static gboolean ngsniffer_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err);
static gboolean ngsniffer_dump_close(wtap_dumper *wdh, int *err);
static int SnifferDecompress( unsigned char * inbuf, size_t inlen,
        unsigned char * outbuf, size_t outlen, int *err );
static int ng_file_read(void *buffer, size_t elementsize, size_t numelements,
    wtap *wth, gboolean is_random, int *err);
static int read_blob(FILE_T infile, ngsniffer_comp_stream_t *comp_stream,
    int *err);
static long ng_file_seek_seq(wtap *wth, long offset, int whence);
static long ng_file_seek_rand(wtap *wth, long offset, int whence);

int ngsniffer_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof ngsniffer_magic];
	char record_type[2];
	char record_length[4]; /* only the first 2 bytes are length,
				  the last 2 are "reserved" and are thrown away */
	guint16 type, length;
	struct vers_rec version;
	guint16	start_date;
	guint16	start_time;
	static const int sniffer_encap[] = {
		WTAP_ENCAP_TOKEN_RING,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_ARCNET,
		WTAP_ENCAP_UNKNOWN,	/* StarLAN */
		WTAP_ENCAP_UNKNOWN,	/* PC Network broadband */
		WTAP_ENCAP_UNKNOWN,	/* LocalTalk */
		WTAP_ENCAP_UNKNOWN,	/* Znet */
		WTAP_ENCAP_UNKNOWN,	/* Internetwork analyzer (synchronous) */
		WTAP_ENCAP_UNKNOWN,	/* Internetwork analyzer (asynchronous) */
		WTAP_ENCAP_FDDI_BITSWAPPED,
		WTAP_ENCAP_ATM_SNIFFER
	};
	#define NUM_NGSNIFF_ENCAPS (sizeof sniffer_encap / sizeof sniffer_encap[0])
	struct tm tm;

	/* Read in the string that should be at the start of a Sniffer file */
	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	if (memcmp(magic, ngsniffer_magic, sizeof ngsniffer_magic)) {
		return 0;
	}

	/*
	 * Read the first record, which the manual says is a version
	 * record.
	 */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(record_type, 1, 2, wth->fh);
	bytes_read += file_read(record_length, 1, 4, wth->fh);
	if (bytes_read != 6) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += 6;

	type = pletohs(record_type);
	length = pletohs(record_length);

	if (type != REC_VERS) {
		g_message("ngsniffer: Sniffer file doesn't start with a version record");
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&version, 1, sizeof version, wth->fh);
	if (bytes_read != sizeof version) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof version;

	/* Check the data link type.
	   If "version.network" is 7, that's "Internetwork analyzer";
	   Sniffers appear to write out LAPB, LAPD and PPP captures
	   (and perhaps other types of captures) in that fashion,
	   and, so far, the only way we know of distinguishing them
	   is to look at the first byte of the packet - if it's 0xFF,
	   it's PPP, otherwise if it's odd, it's LAPB else it's LAPD.
	   Therefore, we treat it as WTAP_ENCAP_UNKNOWN for now, but
	   don't treat that as an error.

	   In one PPP capture, the two 16-bit words of the "rsvd" field
	   were 1 and 3, respectively, and in one X.25 capture, they
	   were both 0.  That's too small a sample from which to
	   conclude anything, however.... */
	if (version.network >= NUM_NGSNIFF_ENCAPS
	    || (sniffer_encap[version.network] == WTAP_ENCAP_UNKNOWN
	       && version.network != 7)) {
		g_message("ngsniffer: network type %u unknown or unsupported",
		    version.network);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/* Check the time unit */
	if (version.timeunit >= NUM_NGSNIFF_TIMEUNITS) {
		g_message("ngsniffer: Unknown timeunit %u", version.timeunit);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/* compressed or uncompressed Sniffer file? */
	if (version.format != 1) {
		wth->file_type = WTAP_FILE_NGSNIFFER_COMPRESSED;

	} else {
		wth->file_type = WTAP_FILE_NGSNIFFER_UNCOMPRESSED;
	}

	/*
	 * We don't know how to handle the remaining header record types,
	 * so we just skip them
	 */
	if (skip_header_records(wth, err, version.maj_vers) < 0)
		return -1;

	/*
	 * Now, if we have a random stream open, position it to the same
	 * location, which should be the beginning of the real data, and
	 * should be the beginning of the compressed data.
	 *
	 * XXX - will we see any records other than REC_FRAME2, REC_FRAME4,
	 * or REC_EOF after this?  If not, we can get rid of the loop in
	 * "ngsniffer_read()".
	 */
	if (wth->random_fh != NULL)
		file_seek(wth->random_fh, wth->data_offset, SEEK_SET);

	/* This is a ngsniffer file */
	wth->capture.ngsniffer = g_malloc(sizeof(ngsniffer_t));

	/* We haven't allocated any uncompression buffers yet. */
	wth->capture.ngsniffer->seq.buf = NULL;
	wth->capture.ngsniffer->rand.buf = NULL;

	/* Set the current file offset; the offset in the compressed file
	   and in the uncompressed data stream currently the same. */
	wth->capture.ngsniffer->seq.uncomp_offset = wth->data_offset;
	wth->capture.ngsniffer->seq.comp_offset = wth->data_offset;
	wth->capture.ngsniffer->rand.uncomp_offset = wth->data_offset;
	wth->capture.ngsniffer->rand.comp_offset = wth->data_offset;

	/* We don't yet have any list of compressed blobs. */
	wth->capture.ngsniffer->first_blob = NULL;
	wth->capture.ngsniffer->last_blob = NULL;
	wth->capture.ngsniffer->current_blob = NULL;

	wth->subtype_read = ngsniffer_read;
	wth->subtype_seek_read = ngsniffer_seek_read;
	wth->subtype_sequential_close = ngsniffer_sequential_close;
	wth->subtype_close = ngsniffer_close;
	wth->snapshot_length = 16384;	/* not available in header, only in frame */
	wth->capture.ngsniffer->timeunit = Usec[version.timeunit];
	wth->file_encap = sniffer_encap[version.network];
	wth->capture.ngsniffer->is_atm =
	    (wth->file_encap == WTAP_ENCAP_ATM_SNIFFER);

	/* Get capture start time */
	start_time = pletohs(&version.time);
	start_date = pletohs(&version.date);
	tm.tm_year = ((start_date&0xfe00)>>9) + 1980 - 1900;
	tm.tm_mon = ((start_date&0x1e0)>>5) - 1;
	tm.tm_mday = (start_date&0x1f);
	/* The time does not appear to act as an offset; only the date
	tm.tm_hour = (start_time&0xf800)>>11;
	tm.tm_min = (start_time&0x7e0)>>5;
	tm.tm_sec = (start_time&0x1f)<<1;*/
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	tm.tm_isdst = -1;
	wth->capture.ngsniffer->start = mktime(&tm);
	/*
	 * XXX - what if "secs" is -1?  Unlikely,
	 * but if the capture was done in a time
	 * zone that switches between standard and
	 * summer time sometime other than when we
	 * do, and thus the time was one that doesn't
	 * exist here because a switch from standard
	 * to summer time zips over it, it could
	 * happen.
	 *
	 * On the other hand, if the capture was done
	 * in a different time zone, this won't work
	 * right anyway; unfortunately, the time zone
	 * isn't stored in the capture file.
	 */

	return 1;
}

static int
skip_header_records(wtap *wth, int *err, gint16 version)
{
	int bytes_read;
	char record_type[2];
	char record_length[4]; /* only the first 2 bytes are length,
				  the last 2 are "reserved" and are thrown away */
	guint16 type, length;

	for (;;) {
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(record_type, 1, 2, wth->fh);
		if (bytes_read != 2) {
			*err = file_error(wth->fh);
			if (*err != 0)
				return -1;
			if (bytes_read != 0) {
				*err = WTAP_ERR_SHORT_READ;
				return -1;
			}
			return 0;	/* EOF */
		}

		type = pletohs(record_type);
		if ((type != REC_HEADER1) && (type != REC_HEADER2)
			&& ((type != REC_V2DESC) || (version > 2)) ) {
			/*
			 * Well, this is either some unknown header type
			 * (we ignore this case), an uncompressed data
			 * frame or the length of a compressed blob
			 * which implies data. Seek backwards over the
			 * two bytes we read, and return.
			 */
			file_seek(wth->fh, -2, SEEK_CUR);
			return 0;
		}

		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(record_length, 1, 4, wth->fh);
		if (bytes_read != 4) {
			*err = file_error(wth->fh);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		wth->data_offset += 6;

		length = pletohs(record_length);

		/* OK, now skip over it the data. */
		file_seek(wth->fh, length, SEEK_CUR);
		wth->data_offset += length;
	}
}

/* Read the next packet */
static gboolean ngsniffer_read(wtap *wth, int *err, int *data_offset)
{
	int	ret;
	guint16	type, length;
	struct frame2_rec frame2;
	struct frame4_rec frame4;
	struct frame6_rec frame6;
	double	t;
	guint16	time_low, time_med, time_high, true_size, size;
	u_char	*pd;

	for (;;) {
		/*
		 * Read the record header.
		 */
		*data_offset = wth->data_offset;
		ret = ngsniffer_read_rec_header(wth, FALSE, &type, &length,
		    err);
		if (ret <= 0) {
			/* Read error or EOF */
			return FALSE;
		}
		wth->data_offset += 6;

		switch (type) {

		case REC_FRAME2:
			if (wth->capture.ngsniffer->is_atm) {
				/*
				 * We shouldn't get a frame2 record in
				 * an ATM capture.
				 */
				g_message("ngsniffer: REC_FRAME2 record in an ATM Sniffer file");
				*err = WTAP_ERR_BAD_RECORD;
				return FALSE;
			}

			/* Read the f_frame2_struct */
			ret = ngsniffer_read_frame2(wth, FALSE, &frame2, err);
			if (ret < 0) {
				/* Read error */
				return FALSE;
			}
			wth->data_offset += sizeof frame2;
			time_low = pletohs(&frame2.time_low);
			time_med = pletohs(&frame2.time_med);
			time_high = pletohs(&frame2.time_high);
			size = pletohs(&frame2.size);
			true_size = pletohs(&frame2.true_size);

			length -= sizeof frame2;	/* we already read that much */

			t = (double)time_low+(double)(time_med)*65536.0 +
			    (double)time_high*4294967296.0;

			set_pseudo_header_frame2(&wth->pseudo_header, &frame2);
			goto found;

		case REC_FRAME4:
			if (!wth->capture.ngsniffer->is_atm) {
				/*
				 * We shouldn't get a frame2 record in
				 * a non-ATM capture.
				 */
				g_message("ngsniffer: REC_FRAME4 record in a non-ATM Sniffer file");
				*err = WTAP_ERR_BAD_RECORD;
				return FALSE;
			}

			/* Read the f_frame4_struct */
			ret = ngsniffer_read_frame4(wth, FALSE, &frame4, err);
			wth->data_offset += sizeof frame4;
			time_low = pletohs(&frame4.time_low);
			time_med = pletohs(&frame4.time_med);
			time_high = frame4.time_high;
			size = pletohs(&frame4.size);
			true_size = pletohs(&frame4.true_size);

			length -= sizeof frame4;	/* we already read that much */

			/*
			 * XXX - use the "time_day" field?  Is that for captures
			 * that take a *really* long time?
			 */
			t = (double)time_low+(double)(time_med)*65536.0 +
			    (double)time_high*4294967296.0;

			set_pseudo_header_frame4(&wth->pseudo_header, &frame4);
			goto found;

		case REC_FRAME6:
			/* XXX - Is this test valid? */
			if (wth->capture.ngsniffer->is_atm) {
				g_message("ngsniffer: REC_FRAME6 record in an ATM Sniffer file");
				*err = WTAP_ERR_BAD_RECORD;
				return FALSE;
			}

			/* Read the f_frame6_struct */
			ret = ngsniffer_read_frame6(wth, FALSE, &frame6, err);
			wth->data_offset += sizeof frame6;
			time_low = pletohs(&frame6.time_low);
			time_med = pletohs(&frame6.time_med);
			time_high = frame6.time_high;
			size = pletohs(&frame6.size);
			true_size = pletohs(&frame6.true_size);

			length -= sizeof frame6;	/* we already read that much */

			/*
			 * XXX - use the "time_day" field?  Is that for captures
			 * that take a *really* long time?
			 */
			t = (double)time_low+(double)(time_med)*65536.0 +
			    (double)time_high*4294967296.0;

			set_pseudo_header_frame6(&wth->pseudo_header, &frame6);
			goto found;

		case REC_EOF:
			/*
			 * End of file.  Return an EOF indication.
			 */
			*err = 0;	/* EOF, not error */
			return FALSE;

		default:
			break;	/* unknown type, skip it */
		}

		/*
		 * Well, we don't know what it is, or we know what
		 * it is but can't handle it.  Skip past the data
		 * portion, and keep looping.
		 */
		ng_file_seek_seq(wth, length, SEEK_CUR);
		wth->data_offset += length;
	}

found:
	/*
	 * OK, is the frame data size greater than than what's left of the
	 * record?
	 */
	if (size > length) {
		/*
		 * Yes - treat this as an error.
		 */
		g_message("ngsniffer: Record length is less than packet size");
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	wth->phdr.len = true_size ? true_size : size;
	wth->phdr.caplen = size;

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	pd = buffer_start_ptr(wth->frame_buffer);
	if (ngsniffer_read_rec_data(wth, FALSE, pd, length, err) < 0)
		return FALSE;	/* Read error */
	wth->data_offset += length;

	if (wth->file_encap == WTAP_ENCAP_UNKNOWN) {
		/*
		 * OK, this is from an "Internetwork analyzer"; let's
		 * look at the first byte of the packet, and figure
		 * out whether it's LAPB, LAPD, PPP, or Frame Relay.
		 */
		if (pd[0] == 0xFF) {
			/*
			 * PPP.
			 */
			wth->file_encap = WTAP_ENCAP_PPP;
		} else if (pd[0] == 0x34 || pd[0] == 0x28) {
			/*
			 * Frame Relay.
			 */
			wth->file_encap = WTAP_ENCAP_FRELAY;
		} else if (pd[0] & 1) {
			/*
			 * LAPB.
			 */
			wth->file_encap = WTAP_ENCAP_LAPB;
		} else {
			/*
			 * LAPD.
			 */
			wth->file_encap = WTAP_ENCAP_LAPD;
		}
	}

	/*
	 * Fix up the pseudo-header; we may have set "x25.flags",
	 * but, for some traffic, we should set "p2p.sent" instead.
	 */
	fix_pseudo_header(wth, &wth->pseudo_header);

	t = t/1000000.0 * wth->capture.ngsniffer->timeunit; /* t = # of secs */
	t += wth->capture.ngsniffer->start;
	wth->phdr.ts.tv_sec = (long)t;
	wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(wth->phdr.ts.tv_sec))
			*1.0e6);
	wth->phdr.pkt_encap = wth->file_encap;
	return TRUE;
}

static int ngsniffer_seek_read(wtap *wth, int seek_off,
    union wtap_pseudo_header *pseudo_header, u_char *pd, int packet_size)
{
	int	ret;
	int	err;	/* XXX - return this */
	guint16	type, length;
	struct frame2_rec frame2;
	struct frame4_rec frame4;
	struct frame6_rec frame6;

	ng_file_seek_rand(wth, seek_off, SEEK_SET);

	ret = ngsniffer_read_rec_header(wth, TRUE, &type, &length, &err);
	if (ret <= 0) {
		/* Read error or EOF */
		return ret;
	}

	switch (type) {

	case REC_FRAME2:
		/* Read the f_frame2_struct */
		ret = ngsniffer_read_frame2(wth, TRUE, &frame2, &err);
		if (ret < 0) {
			/* Read error */
			return ret;
		}

		length -= sizeof frame2;	/* we already read that much */

		set_pseudo_header_frame2(pseudo_header, &frame2);
		break;

	case REC_FRAME4:
		/* Read the f_frame4_struct */
		ret = ngsniffer_read_frame4(wth, TRUE, &frame4, &err);

		length -= sizeof frame4;	/* we already read that much */

		set_pseudo_header_frame4(pseudo_header, &frame4);
		break;

	case REC_FRAME6:
		/* Read the f_frame6_struct */
		ret = ngsniffer_read_frame6(wth, TRUE, &frame6, &err);

		length -= sizeof frame6;	/* we already read that much */

		set_pseudo_header_frame6(pseudo_header, &frame6);
		break;

	default:
		/*
		 * "Can't happen".
		 */
		g_assert_not_reached();
		return -1;
	}

	/*
	 * Fix up the pseudo-header; we may have set "x25.flags",
	 * but, for some traffic, we should set "p2p.sent" instead.
	 */
	fix_pseudo_header(wth, pseudo_header);

	/*
	 * Got the pseudo-header (if any), now get the data.
	 */
	return ngsniffer_read_rec_data(wth, TRUE, pd, packet_size, &err);
}

static int ngsniffer_read_rec_header(wtap *wth, gboolean is_random,
    guint16 *typep, guint16 *lengthp, int *err)
{
	int	bytes_read;
	char	record_type[2];
	char	record_length[4]; /* only 1st 2 bytes are length */

	/*
	 * Read the record header.
	 */
	bytes_read = ng_file_read(record_type, 1, 2, wth, is_random, err);
	if (bytes_read != 2) {
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	bytes_read = ng_file_read(record_length, 1, 4, wth, is_random, err);
	if (bytes_read != 4) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}

	*typep = pletohs(record_type);
	*lengthp = pletohs(record_length);
	return 1;	/* success */
}

static int ngsniffer_read_frame2(wtap *wth, gboolean is_random,
    struct frame2_rec *frame2, int *err)
{
	int bytes_read;

	/* Read the f_frame2_struct */
	bytes_read = ng_file_read(frame2, 1, sizeof *frame2, wth, is_random,
	    err);
	if (bytes_read != sizeof *frame2) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	return 0;
}

static void set_pseudo_header_frame2(union wtap_pseudo_header *pseudo_header,
    struct frame2_rec *frame2)
{
	/*
	 * In one PPP "Internetwork analyzer" capture,
	 * the only bit seen in "fs" is the 0x80 bit,
	 * which probably indicates the packet's
	 * direction; all other bits were zero.
	 * All bits in "frame2.flags" were zero.
	 *
	 * In one X.25 "Interenetwork analyzer" capture,
	 * the only bit seen in "fs" is the 0x80 bit,
	 * which probably indicates the packet's
	 * direction; all other bits were zero.
	 * "frame2.flags" was always 0x18.
	 *
	 * In one Ethernet capture, "fs" was always 0,
	 * and "flags" was either 0 or 0x18, with no
	 * obvious correlation with anything.
	 *
	 * In one Token Ring capture, "fs" was either 0
	 * or 0xcc, and "flags" was either 0 or 0x18,
	 * with no obvious correlation with anything.
	 */
	pseudo_header->x25.flags = (frame2->fs & 0x80) ? 0x00 : 0x80;
}

static int ngsniffer_read_frame4(wtap *wth, gboolean is_random,
    struct frame4_rec *frame4, int *err)
{
	int bytes_read;

	/* Read the f_frame4_struct */
	bytes_read = ng_file_read(frame4, 1, sizeof *frame4, wth, is_random,
	    err);
	if (bytes_read != sizeof *frame4) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	return 0;
}

static void set_pseudo_header_frame4(union wtap_pseudo_header *pseudo_header,
    struct frame4_rec *frame4)
{
	pseudo_header->ngsniffer_atm.AppTrafType = frame4->atm_info.AppTrafType;
	pseudo_header->ngsniffer_atm.AppHLType = frame4->atm_info.AppHLType;
	pseudo_header->ngsniffer_atm.Vpi = pletohs(&frame4->atm_info.Vpi);
	pseudo_header->ngsniffer_atm.Vci = pletohs(&frame4->atm_info.Vci);
	pseudo_header->ngsniffer_atm.channel = pletohs(&frame4->atm_info.channel);
	pseudo_header->ngsniffer_atm.cells = pletohs(&frame4->atm_info.cells);
	pseudo_header->ngsniffer_atm.aal5t_u2u = pletohs(&frame4->atm_info.Trailer.aal5t_u2u);
	pseudo_header->ngsniffer_atm.aal5t_len = pletohs(&frame4->atm_info.Trailer.aal5t_len);
	pseudo_header->ngsniffer_atm.aal5t_chksum = pletohl(&frame4->atm_info.Trailer.aal5t_chksum);
}

static int ngsniffer_read_frame6(wtap *wth, gboolean is_random,
    struct frame6_rec *frame6, int *err)
{
	int bytes_read;

	/* Read the f_frame6_struct */
	bytes_read = ng_file_read(frame6, 1, sizeof *frame6, wth, is_random,
	    err);
	if (bytes_read != sizeof *frame6) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	return 0;
}

static void set_pseudo_header_frame6(union wtap_pseudo_header *pseudo_header,
    struct frame6_rec *frame6)
{
	/* XXX - Once the frame format is divined, something will most likely go here */
}

static int ngsniffer_read_rec_data(wtap *wth, gboolean is_random, u_char *pd,
    int length, int *err)
{
	int	bytes_read;

	bytes_read = ng_file_read(pd, 1, length, wth, is_random, err);

	if (bytes_read != length) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	return 0;
}

static void fix_pseudo_header(wtap *wth,
    union wtap_pseudo_header *pseudo_header)
{
	switch (wth->file_encap) {

	case WTAP_ENCAP_LAPD:
		if (pseudo_header->x25.flags == 0x00)
			pseudo_header->p2p.sent = TRUE;
		else
			pseudo_header->p2p.sent = FALSE;
		break;
	}
}

/* Throw away the buffers used by the sequential I/O stream, but not
   those used by the random I/O stream. */
static void ngsniffer_sequential_close(wtap *wth)
{
	if (wth->capture.ngsniffer->seq.buf != NULL) {
		g_free(wth->capture.ngsniffer->seq.buf);
		wth->capture.ngsniffer->seq.buf = NULL;
	}
}

static void free_blob(gpointer data, gpointer user_data)
{
	g_free(data);
}

static void ngsniffer_close(wtap *wth)
{
	if (wth->capture.ngsniffer->seq.buf != NULL)
		g_free(wth->capture.ngsniffer->seq.buf);
	if (wth->capture.ngsniffer->rand.buf != NULL)
		g_free(wth->capture.ngsniffer->rand.buf);
	if (wth->capture.ngsniffer->first_blob != NULL) {
		g_list_foreach(wth->capture.ngsniffer->first_blob, free_blob, NULL);
		g_list_free(wth->capture.ngsniffer->first_blob);
	}
	g_free(wth->capture.ngsniffer);
}

static const int wtap_encap[] = {
    -1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
    1,		/* WTAP_ENCAP_ETHERNET */
    0,		/* WTAP_ENCAP_TOKEN_RING */
    -1,		/* WTAP_ENCAP_SLIP -> unsupported */
    7,		/* WTAP_ENCAP_PPP -> Internetwork analyzer (synchronous) FIXME ! */
    -1,		/* WTAP_ENCAP_FDDI -> unsupported */
    9,		/* WTAP_ENCAP_FDDI_BITSWAPPED */
    -1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
    2,		/* WTAP_ENCAP_ARCNET */
    -1,		/* WTAP_ENCAP_ATM_RFC1483 */
    -1,		/* WTAP_ENCAP_LINUX_ATM_CLIP */
    7,		/* WTAP_ENCAP_LAPB -> Internetwork analyzer (synchronous) */
    -1,		/* WTAP_ENCAP_ATM_SNIFFER */
    -1		/* WTAP_ENCAP_NULL -> unsupported */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int ngsniffer_dump_can_write_encap(int filetype, int encap)
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
gboolean ngsniffer_dump_open(wtap_dumper *wdh, int *err)
{
    int nwritten;
    char buf[6] = {REC_VERS, 0x00, 0x12, 0x00, 0x00, 0x00}; /* version record */

    /* This is a sniffer file */
    wdh->subtype_write = ngsniffer_dump;
    wdh->subtype_close = ngsniffer_dump_close;

    wdh->dump.ngsniffer = g_malloc(sizeof(ngsniffer_dump_t));
    wdh->dump.ngsniffer->first_frame = TRUE;
    wdh->dump.ngsniffer->start = 0;

    /* Write the file header. */
    nwritten = fwrite(ngsniffer_magic, 1, sizeof ngsniffer_magic, wdh->fh);
    if (nwritten != sizeof ngsniffer_magic) {
	if (nwritten < 0)
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }
    nwritten = fwrite(buf, 1, 6, wdh->fh);
    if (nwritten != 6) {
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
static gboolean ngsniffer_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err)
{
    ngsniffer_dump_t *priv = wdh->dump.ngsniffer;
    struct frame2_rec rec_hdr;
    int nwritten;
    char buf[6];
    double t;
    guint16 t_low, t_med, t_high;
    struct vers_rec version;
    gint16 maj_vers, min_vers;
    guint16 start_date;
    struct tm *tm;

    /* Sniffer files have a capture start date in the file header, and
       have times relative to the beginning of that day in the packet
       headers; pick the date of the first packet as the capture start
       date. */
    if (priv->first_frame) {
	priv->first_frame=FALSE;
	tm = localtime(&phdr->ts.tv_sec);
	start_date = (tm->tm_year - (1980 - 1900)) << 9;
	start_date |= (tm->tm_mon + 1) << 5;
	start_date |= tm->tm_mday;
	/* record the start date, not the start time */
	priv->start = phdr->ts.tv_sec - (3600*tm->tm_hour + 60*tm->tm_min + tm->tm_sec);

	/* "sniffer" version ? */
	maj_vers = 4;
	min_vers = 0;
	version.maj_vers = htoles(maj_vers);
	version.min_vers = htoles(min_vers);
	version.time = 0;
	version.date = htoles(start_date);
	version.type = 4;
	version.network = wtap_encap[wdh->encap];
	version.format = 1;
	version.timeunit = 1; /* 0.838096 */
	version.cmprs_vers = 0;
	version.cmprs_level = 0;
	version.rsvd[0] = 0;
	version.rsvd[1] = 0;
	nwritten = fwrite(&version, 1, sizeof version, wdh->fh);
	if (nwritten != sizeof version) {
	    if (nwritten < 0)
		*err = errno;
	    else
		*err = WTAP_ERR_SHORT_WRITE;
	    return FALSE;
	}
    }

    buf[0] = REC_FRAME2;
    buf[1] = 0x00;
    buf[2] = (char)((phdr->caplen + sizeof(struct frame2_rec))%256);
    buf[3] = (char)((phdr->caplen + sizeof(struct frame2_rec))/256);
    buf[4] = 0x00;
    buf[5] = 0x00;
    nwritten = fwrite(buf, 1, 6, wdh->fh);
    if (nwritten != 6) {
	if (nwritten < 0)
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }
    t = (double)phdr->ts.tv_sec + (double)phdr->ts.tv_usec/1.0e6; /* # of secs */
    t = (t - priv->start)*1.0e6 / Usec[1]; /* timeunit = 1 */
    t_low = (guint16)(t-(double)((guint32)(t/65536.0))*65536.0);
    t_med = (guint16)((guint32)(t/65536.0) % 65536);
    t_high = (guint16)(t/4294967296.0);
    rec_hdr.time_low = htoles(t_low);
    rec_hdr.time_med = htoles(t_med);
    rec_hdr.time_high = htoles(t_high);
    rec_hdr.size = htoles(phdr->caplen);
    if (wdh->encap == WTAP_ENCAP_LAPB || wdh->encap == WTAP_ENCAP_PPP)
	rec_hdr.fs = (pseudo_header->x25.flags & 0x80) ? 0x00 : 0x80;
    else
	rec_hdr.fs = 0;
    rec_hdr.flags = 0;
    rec_hdr.true_size = phdr->len != phdr->caplen ? htoles(phdr->len) : 0;
    rec_hdr.rsvd = 0;
    nwritten = fwrite(&rec_hdr, 1, sizeof rec_hdr, wdh->fh);
    if (nwritten != sizeof rec_hdr) {
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

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean ngsniffer_dump_close(wtap_dumper *wdh, int *err)
{
    /* EOF record */
    char buf[6] = {REC_EOF, 0x00, 0x00, 0x00, 0x00, 0x00};
    int nwritten;

    nwritten = fwrite(buf, 1, 6, wdh->fh);
    if (nwritten != 6) {
	if (nwritten < 0)
	    *err = errno;
	else
	    *err = WTAP_ERR_SHORT_WRITE;
	return FALSE;
    }
    return TRUE;
}

/*
   SnifferDecompress() decompresses a blob of compressed data from a
         Sniffer(R) capture file.

   This function is Copyright (c) 1999-2999 Tim Farley

   Parameters
      inbuf - buffer of compressed bytes from file, not including
         the preceding length word
      inlen - length of inbuf in bytes
      outbuf - decompressed contents, could contain a partial Sniffer
         record at the end.
      outlen - length of outbuf.

   Return value is the number of bytes in outbuf on return.
*/
static int
SnifferDecompress( unsigned char * inbuf, size_t inlen, 
                       unsigned char * outbuf, size_t outlen, int *err )
{
   unsigned char * pin = inbuf;
   unsigned char * pout = outbuf;
   unsigned char * pin_end = pin + inlen;
   unsigned char * pout_end = pout + outlen;
   unsigned int bit_mask;  /* one bit is set in this, to mask with bit_value */
   unsigned int bit_value = 0; /* cache the last 16 coding bits we retrieved */
   unsigned int code_type; /* encoding type, from high 4 bits of byte */
   unsigned int code_low;  /* other 4 bits from encoding byte */
   int length;             /* length of RLE sequence or repeated string */
   int offset;             /* offset of string to repeat */

   bit_mask  = 0;  /* don't have any bits yet */
   while (1)
   {
      /* Shift down the bit mask we use to see whats encoded */
      bit_mask = bit_mask >> 1;

      /* If there are no bits left, time to get another 16 bits */
      if ( 0 == bit_mask )
      {
         bit_mask  = 0x8000;  /* start with the high bit */
         bit_value = pletohs(pin);   /* get the next 16 bits */
         pin += 2;          /* skip over what we just grabbed */
         if ( pin >= pin_end )
         {
            *err = WTAP_ERR_UNC_TRUNCATED;	 /* data was oddly truncated */
            return ( -1 );
         }
      }

      /* Use the bits in bit_value to see what's encoded and what is raw data */
      if ( !(bit_mask & bit_value) )
      {
         /* bit not set - raw byte we just copy */
         *(pout++) = *(pin++);
      }
      else
      {
         /* bit set - next item is encoded.  Peel off high nybble
            of next byte to see the encoding type.  Set aside low
            nybble while we are at it */
         code_type = (unsigned int) ((*pin) >> 4 ) & 0xF;
         code_low  = (unsigned int) ((*pin) & 0xF );
         pin++;   /* increment over the code byte we just retrieved */
         if ( pin >= pin_end )
         {
            *err = WTAP_ERR_UNC_TRUNCATED;	 /* data was oddly truncated */
            return ( -1 );
         }

         /* Based on the code type, decode the compressed string */
         switch ( code_type )
         {
            case 0  :   /* RLE short runs */
                /*
                    Run length is the low nybble of the first code byte.
                    Byte to repeat immediately follows.
                    Total code size: 2 bytes.
                */    
                length = code_low + 3;
                /* If length would put us past end of output, avoid overflow */
                if ( pout + length > pout_end )
                {
                    *err = WTAP_ERR_UNC_OVERFLOW;
                    return ( -1 );
                }

                /* generate the repeated series of bytes */
                memset( pout, *pin++, length );
                pout += length;
                break;
            case 1  :   /* RLE long runs */
                /*
                    Low 4 bits of run length is the low nybble of the 
                    first code byte, upper 8 bits of run length is in 
                    the next byte.
                    Byte to repeat immediately follows.
                    Total code size: 3 bytes.
                */    
                length = code_low + ((unsigned int)(*pin++) << 4) + 19;
                /* If we are already at end of input, there is no byte
                   to repeat */
                if ( pin >= pin_end )
                {
                    *err = WTAP_ERR_UNC_TRUNCATED;	 /* data was oddly truncated */
                    return ( -1 );
                }
                /* If length would put us past end of output, avoid overflow */
                if ( pout + length > pout_end )
                {
                    *err = WTAP_ERR_UNC_OVERFLOW;
                    return ( -1 );
                }

                /* generate the repeated series of bytes */
                memset( pout, *pin++, length );
                pout += length;
                break;
            case 2  :   /* LZ77 long strings */
                /*
                    Low 4 bits of offset to string is the low nybble of the 
                    first code byte, upper 8 bits of offset is in 
                    the next byte.
                    Length of string immediately follows.
                    Total code size: 3 bytes.
                */    
                offset = code_low + ((unsigned int)(*pin++) << 4) + 3;
                /* If we are already at end of input, there is no byte
                   to repeat */
                if ( pin >= pin_end )
                {
                    *err = WTAP_ERR_UNC_TRUNCATED;	 /* data was oddly truncated */
                    return ( -1 );
                }
                /* Check if offset would put us back past begin of buffer */
                if ( pout - offset < outbuf )
                {
                    *err = WTAP_ERR_UNC_BAD_OFFSET;
                    return ( -1 );
                }

                /* get length from next byte, make sure it won't overrun buf */
                length = (unsigned int)(*pin++) + 16;
                if ( pout + length > pout_end )
                {
                    *err = WTAP_ERR_UNC_OVERFLOW;
                    return ( -1 );
                }

                /* Copy the string from previous text to output position,
                   advance output pointer */
                memcpy( pout, pout - offset, length );
                pout += length;
                break;
            default :   /* (3 to 15): LZ77 short strings */
                /*
                    Low 4 bits of offset to string is the low nybble of the 
                    first code byte, upper 8 bits of offset is in 
                    the next byte.
                    Length of string to repeat is overloaded into code_type.
                    Total code size: 2 bytes.
                */    
                offset = code_low + ((unsigned int)(*pin++) << 4) + 3;
                /* Check if offset would put us back past begin of buffer */
                if ( pout - offset < outbuf )
                {
                    *err = WTAP_ERR_UNC_BAD_OFFSET;
                    return ( -1 );
                }

                /* get length from code_type, make sure it won't overrun buf */
                length = code_type;
                if ( pout + length > pout_end )
                {
                    *err = WTAP_ERR_UNC_OVERFLOW;
                    return ( -1 );
                }

                /* Copy the string from previous text to output position,
                   advance output pointer */
                memcpy( pout, pout - offset, length );
                pout += length;
                break;
         }
      }

      /* If we've consumed all the input, we are done */
      if ( pin >= pin_end )
         break;
   }

   return ( pout - outbuf );  /* return length of expanded text */
}

/*
 * XXX - is there any guarantee that this is big enough to hold the
 * uncompressed data from any blob?
 */
#define	OUTBUF_SIZE	65536

/* Information about a compressed blob; we save the offset in the
   underlying compressed file, and the offset in the uncompressed data
   stream, of the blob. */
typedef struct {
	long	blob_comp_offset;
	long	blob_uncomp_offset;
} blob_info_t;

static int
ng_file_read(void *buffer, size_t elementsize, size_t numelements, wtap *wth,
    gboolean is_random, int *err)
{
    FILE_T infile;
    ngsniffer_comp_stream_t *comp_stream;
    int copybytes = elementsize * numelements; /* bytes left to be copied */
    int copied_bytes = 0; /* bytes already copied */
    unsigned char *outbuffer = buffer; /* where to write next decompressed data */
    blob_info_t *blob;
    int bytes_to_copy;
    int bytes_left;

    if (is_random) {
	infile = wth->random_fh;
	comp_stream = &wth->capture.ngsniffer->rand;
    } else {
	infile = wth->fh;
	comp_stream = &wth->capture.ngsniffer->seq;
    }

    if (wth->file_type == WTAP_FILE_NGSNIFFER_UNCOMPRESSED) {
	errno = WTAP_ERR_CANT_READ;
	copied_bytes = file_read(buffer, 1, copybytes, infile);
	if (copied_bytes != copybytes)
	    *err = file_error(infile);
	return copied_bytes;
    }

    /* Allocate the stream buffer if it hasn't already been allocated. */
    if (comp_stream->buf == NULL) {
	comp_stream->buf = g_malloc(OUTBUF_SIZE);

	if (is_random) {
	    /* This is the first read of the random file, so we're at
	       the beginning of the sequence of blobs in the file
	       (as we've not done any random reads yet to move the
	       current position in the random stream); set the
	       current blob to be the first blob. */
	    wth->capture.ngsniffer->current_blob =
		wth->capture.ngsniffer->first_blob;
	} else {
	    /* This is the first sequential read; if we also have a
	       random stream open, allocate the first element for the
	       list of blobs, and make it the last element as well. */
	    if (wth->random_fh != NULL) {
		g_assert(wth->capture.ngsniffer->first_blob == NULL);
		blob = g_malloc(sizeof (blob_info_t));
		blob->blob_comp_offset = comp_stream->comp_offset;
		blob->blob_uncomp_offset = comp_stream->uncomp_offset;
		wth->capture.ngsniffer->first_blob =
			g_list_append(wth->capture.ngsniffer->first_blob, blob);
		wth->capture.ngsniffer->last_blob =
			wth->capture.ngsniffer->first_blob;
	    }
	}

	/* Now read the first blob into the buffer. */
	if (read_blob(infile, comp_stream, err) < 0)
	    return -1;
    }
    while (copybytes > 0) {
	bytes_left = comp_stream->nbytes - comp_stream->nextout;
	if (bytes_left == 0) {
	    /* There's no decompressed stuff left to copy from the current
	       blob; get the next blob. */

	    if (is_random) {
		/* Move to the next blob in the list. */
		wth->capture.ngsniffer->current_blob =
			g_list_next(wth->capture.ngsniffer->current_blob);
		blob = wth->capture.ngsniffer->current_blob->data;
	    } else {
		/* If we also have a random stream open, add a new element,
		   for this blob, to the list of blobs; we know the list is
		   non-empty, as we initialized it on the first sequential
		   read, so we just add the new element at the end, and
		   adjust the pointer to the last element to refer to it. */
		if (wth->random_fh != NULL) {
		    blob = g_malloc(sizeof (blob_info_t));
		    blob->blob_comp_offset = comp_stream->comp_offset;
		    blob->blob_uncomp_offset = comp_stream->uncomp_offset;
		    wth->capture.ngsniffer->last_blob =
			g_list_append(wth->capture.ngsniffer->last_blob, blob);
		}
	    }

	    if (read_blob(infile, comp_stream, err) < 0)
		return -1;
	    bytes_left = comp_stream->nbytes - comp_stream->nextout;
	}
   	    
	bytes_to_copy = copybytes;
	if (bytes_to_copy > bytes_left)
	    bytes_to_copy = bytes_left;
	memcpy(outbuffer, &comp_stream->buf[comp_stream->nextout],
		bytes_to_copy);
	copybytes -= bytes_to_copy;
	copied_bytes += bytes_to_copy;
	outbuffer += bytes_to_copy;
	comp_stream->nextout += bytes_to_copy;
	comp_stream->uncomp_offset += bytes_to_copy;
    }
    return copied_bytes;
}

/* Read a blob from a compressed stream.
   Return -1 and set "*err" on error, otherwise return 0. */
static int
read_blob(FILE_T infile, ngsniffer_comp_stream_t *comp_stream, int *err)
{
    size_t in_len;
    size_t read_len;
    unsigned short blob_len;
    gint16 blob_len_host;
    gboolean uncompressed;
    unsigned char file_inbuf[65536];
    int out_len;

    /* Read one 16-bit word which is length of next compressed blob */
    errno = WTAP_ERR_CANT_READ;
    read_len = file_read(&blob_len, 1, 2, infile);
    if (2 != read_len) {
	*err = file_error(infile);
	return -1;
    }
    comp_stream->comp_offset += 2;
    blob_len_host = pletohs(&blob_len);

    /* Compressed or uncompressed? */
    if (blob_len_host < 0) {
    	/* Uncompressed blob; blob length is absolute value of the number. */
	in_len = -blob_len_host;
	uncompressed = TRUE;
    } else {
    	in_len = blob_len_host;
	uncompressed = FALSE;
    }

    /* Read the blob */
    errno = WTAP_ERR_CANT_READ;
    read_len = file_read(file_inbuf, 1, in_len, infile);
    if (in_len != read_len) {
	*err = file_error(infile);
	return -1;
    }
    comp_stream->comp_offset += in_len;

    if (uncompressed) {
	memcpy(comp_stream->buf, file_inbuf, in_len);
	out_len = in_len;
    } else {
	/* Decompress the blob */
	out_len = SnifferDecompress(file_inbuf, in_len,
				comp_stream->buf, OUTBUF_SIZE, err);
	if (out_len < 0)
	    return -1;
    }
    comp_stream->nextout = 0;
    comp_stream->nbytes = out_len;
    return 0;
}

/* Seek in the sequential data stream; we can only seek forward, and we
   do it on compressed files by skipping forward. */
static long
ng_file_seek_seq(wtap *wth, long offset, int whence)
{
   long delta;
   char buf[65536];
   long amount_to_read;
   int err;

   if (wth->file_type == WTAP_FILE_NGSNIFFER_UNCOMPRESSED)
	return file_seek(wth->fh, offset, whence);

    switch (whence) {

    case SEEK_SET:
    	break;		/* "offset" is the target offset */

    case SEEK_CUR:
	offset += wth->capture.ngsniffer->seq.uncomp_offset;
	break;		/* "offset" is relative to the current offset */

    case SEEK_END:
	g_assert_not_reached();	/* "offset" is relative to the end of the file... */
	break;		/* ...but we don't know where that is. */
    }

    delta = offset - wth->capture.ngsniffer->seq.uncomp_offset;
    g_assert(delta >= 0);

    /* Ok, now read and discard "delta" bytes. */
    while (delta != 0) {
	amount_to_read = delta;
	if (amount_to_read > sizeof buf)
	    amount_to_read = sizeof buf;
	if (ng_file_read(buf, 1, amount_to_read, wth, FALSE, &err) < 0)
	    return -1;	/* error */
	delta -= amount_to_read;
    }
    return offset;
}

/* Seek in the random data stream.

   On compressed files, we see whether we're seeking to a position within
   the blob we currently have in memory and, if not, we find in the list
   of blobs the last blob that starts at or before the position to which
   we're seeking, and read that blob in.  We can then move to the appropriate
   position within the blob we have in memory (whether it's the blob we
   already had in memory or, if necessary, the one we read in). */
static long
ng_file_seek_rand(wtap *wth, long offset, int whence)
{
   ngsniffer_t *ngsniffer;
   long delta;
   int err;
   GList *new, *next;
   blob_info_t *next_blob, *new_blob;

   if (wth->file_type == WTAP_FILE_NGSNIFFER_UNCOMPRESSED)
	return file_seek(wth->random_fh, offset, whence);

   /* OK, seeking in a compressed data stream is a pain - especially
      given that the compressed Sniffer data stream we're reading
      may actually be further compressed by gzip.

      For now, we implement random access the same way zlib does:

	compute the target position (we don't support relative-to-end);

	if the target position is ahead of where we are, read and throw
	away the number of bytes ahead it is;

	if the target position is behind where we are, seek backward
	to the beginning of the compressed part of the data (i.e.,
	seek backward to the stuff after the header), and then recompute
	the relative position based on the new position and seek forward
	by reading and throwing away data. */

    ngsniffer = wth->capture.ngsniffer;

    switch (whence) {

    case SEEK_SET:
    	break;		/* "offset" is the target offset */

    case SEEK_CUR:
	offset += ngsniffer->rand.uncomp_offset;
	break;		/* "offset" is relative to the current offset */

    case SEEK_END:
	g_assert_not_reached();	/* "offset" is relative to the end of the file... */
	break;		/* ...but we don't know where that is. */
    }

    delta = offset - ngsniffer->rand.uncomp_offset;

    /* Is the place to which we're seeking within the current buffer, or
       will we have to read a different blob into the buffer? */
    new = NULL;
    if (delta > 0) {
	/* We're going forwards.
	   Is the place to which we're seeking within the current buffer? */
	if (ngsniffer->rand.nextout + delta >= ngsniffer->rand.nbytes) {
	    /* No.  Search for a blob that contains the target offset in
	       the uncompressed byte stream, starting with the blob
	       following the current blob. */
	    new = g_list_next(ngsniffer->current_blob);
	    for (;;) {
		next = g_list_next(new);
		if (next == NULL) {
		    /* No more blobs; the current one is it. */
		    break;
		}

		next_blob = next->data;
		/* Does the next blob start after the target offset?
		   If so, the current blob is the one we want. */
		if (next_blob->blob_uncomp_offset > offset)
		    break;

		new = next;
	    }
	}
    } else if (delta < 0) {
	/* We're going backwards.
	   Is the place to which we're seeking within the current buffer? */
	if (ngsniffer->rand.nextout + delta < 0) {
	    /* No.  Search for a blob that contains the target offset in
	       the uncompressed byte stream, starting with the blob
	       preceding the current blob. */
	    new = g_list_previous(ngsniffer->current_blob);
	    for (;;) {
		/* Does this blob start at or before the target offset?
		   If so, the current blob is the one we want. */
		new_blob = new->data;
		if (new_blob->blob_uncomp_offset <= offset)
		    break;

		/* It doesn't - skip to the previous blob. */
		new = g_list_previous(new);
	    }
	}
    }

    if (new != NULL) {
	/* The place to which we're seeking isn't in the current buffer;
	   move to a new blob. */
	new_blob = new->data;

	/* Seek in the compressed file to the offset in the compressed file
	   of the beginning of that blob. */
	if (file_seek(wth->random_fh, new_blob->blob_comp_offset, SEEK_SET) == -1)
	    return -1;

	/* Make the blob we found the current one. */
	ngsniffer->current_blob = new;

	/* Now set the current offsets to the offsets of the beginning
	   of the blob. */
	ngsniffer->rand.uncomp_offset = new_blob->blob_uncomp_offset;
	ngsniffer->rand.comp_offset = new_blob->blob_comp_offset;

	/* Now fill the buffer. */
	if (read_blob(wth->random_fh, &ngsniffer->rand, &err) < 0)
	    return -1;

	/* Set "delta" to the amount to move within this blob; it had
	   better be >= 0, and < the amount of uncompressed data in
	   the blob, as otherwise it'd mean we need to seek before
	   the beginning or after the end of this blob. */
	delta = offset - ngsniffer->rand.uncomp_offset;
	g_assert(delta >= 0 && delta < ngsniffer->rand.nbytes);
    }

    /* OK, the place to which we're seeking is in the buffer; adjust
       "ngsniffer->rand.nextout" to point to the place to which
       we're seeking, and adjust "ngsniffer->rand.uncomp_offset" to be
       the destination offset. */
    ngsniffer->rand.nextout += delta;
    ngsniffer->rand.uncomp_offset += delta;

    return offset;
}
