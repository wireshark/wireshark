/* ngsniffer.c
 *
 * $Id: ngsniffer.c,v 1.8 1998/12/13 05:08:04 gram Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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

#include <stdlib.h>
#include <time.h>
#include "wtap.h"
#include "ngsniffer.h"

/* values for V.timeunit */
#define NUM_NGSNIFF_TIMEUNITS 7
static double Usec[] = { 15.0, 0.838096, 15.0, 0.5, 2.0, 0.0, 0.1 };

#define NUM_NGSNIFF_ENCAPS 11
static int sniffer_encap[] = {
		WTAP_ENCAP_TR,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_ARCNET,
		WTAP_ENCAP_NONE,	/* StarLAN */
		WTAP_ENCAP_NONE,	/* PC Network broadband */
		WTAP_ENCAP_NONE,	/* LocalTalk */
		WTAP_ENCAP_NONE,	/* Znet */
		WTAP_ENCAP_NONE,	/* Internetwork analyzer */
		WTAP_ENCAP_NONE,	/* type 8 not defined in Sniffer */
		WTAP_ENCAP_FDDI,
		WTAP_ENCAP_NONE		/* ATM */
};

/* Returns WTAP_FILE_NGSNIFFER on success, WTAP_FILE_UNKNOWN on failure */
int ngsniffer_open(wtap *wth)
{
	int bytes_read;
	char magic[18];
	char record_type[2];
	char record_length[4]; /* only the first 2 bytes are length,
							  the last 2 are "reserved" and are thrown away */
	guint16 type, length = 0;
	guint8	format;
	guint8	network;
	gchar	version[18]; /* to hold the entire version record */
	guint8	timeunit;
	guint16	start_date;
	guint16	start_time;
	struct tm tm;

	/* Read in the string that should be at the start of a Sniffer file */
	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, 17, wth->fh);

	if (bytes_read != 17) {
		return WTAP_FILE_UNKNOWN;
	}

	magic[17] = 0;

	if (strcmp(magic, "TRSNIFF data    \x1a")) {
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a ngsniffer file */
	wth->capture.ngsniffer = g_malloc(sizeof(ngsniffer_t));
	wth->subtype_read = ngsniffer_read;
	wth->snapshot_length = 16384;	/* not available in header, only in frame */
	/*wth->frame_number = 0;*/
	/*wth->file_byte_offset = 0x10b;*/

	/* Read records until we find the start of packets */
	while (1) {
		fseek(wth->fh, length, SEEK_CUR);
		bytes_read = fread(record_type, 1, 2, wth->fh);
		bytes_read += fread(record_length, 1, 4, wth->fh);
		if (bytes_read != 6) {
			free(wth->capture.ngsniffer);
			return WTAP_FILE_UNKNOWN;
		}

		type = pletohs(record_type);
		length = pletohs(record_length);

		switch (type) {
			/* Version Record */
			case REC_VERS:
				fread(version, 1, 18, wth->fh);
				length = 0; /* to fake the next iteration of while() */

				/* Make sure this is an uncompressed Sniffer file */
				format = version[10];
				if (format != 1) {
					g_message("ngsniffer: This Sniffer file type is not supported");
					free(wth->capture.ngsniffer);
					return WTAP_FILE_UNKNOWN;
				}

				/* Get data link type */
				network = version[9];
				if (network >= NUM_NGSNIFF_ENCAPS) {
					g_message("ngsniffer: network type %d unknown", network);
					free(wth->capture.ngsniffer);
					return WTAP_FILE_UNKNOWN;
				}
				else {
					wth->encapsulation = sniffer_encap[network];
				}

				/* Get time unit */
				timeunit = version[11];
				if (timeunit >= NUM_NGSNIFF_TIMEUNITS) {
					g_message("ngsniffer: Unknown timeunit %d", timeunit);
					free(wth->capture.ngsniffer);
					return WTAP_FILE_UNKNOWN;
				}
				else {
					wth->capture.ngsniffer->timeunit = Usec[timeunit];
				}

				/* Get capture start time */
				start_time = pletohs(&version[4]);
				start_date = pletohs(&version[6]);
				tm.tm_year = ((start_date&0xfe00)>>9) + 1980 - 1900;
				tm.tm_mon = ((start_date&0x1e0)>>5) - 1;
				tm.tm_mday = (start_date&0x1f);
				/* The time does not appear to act as an
				 * offset; only the date
				tm.tm_hour = (start_time&0xfc00)>>11;
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
				break;

			case REC_FRAME2:
				wth->capture.ngsniffer->pkt_len = length - 14;
				return WTAP_FILE_NGSNIFFER;

			default:
				/* Continue with while() loop */
		}
	}

	/* never gets here */
	return WTAP_FILE_NGSNIFFER;
}

/* Read the next packet */
int ngsniffer_read(wtap *wth)
{
	int	packet_size = wth->capture.ngsniffer->pkt_len;
	int	bytes_read;
	char record_type[2];
	char record_length[4]; /* only 1st 2 bytes are length */
	guint16 type, length;
	char frame2[14];
	double t;
	guint16 time_low, time_med, time_high, true_size, size;
	int	data_offset;

	/* if this is the very first packet, then the fh cursor will be at the
	 * start of a f_frame2_struct instead of at the start of the record.
	 * Check for this */
	if (!packet_size) {

		/* Read record info */
		bytes_read = fread(record_type, 1, 2, wth->fh);
		bytes_read += fread(record_length, 1, 4, wth->fh);
		if (bytes_read != 6) {
			return 0;
		}

		type = pletohs(record_type);
		length = pletohs(record_length);

		if (type != REC_FRAME2) {
			return 0;
		}
		else {
			packet_size = length - 14;
		}
	}
	else {
		wth->capture.ngsniffer->pkt_len = 0;
	}

	/* Read the f_frame2_struct */
	bytes_read = fread(frame2, 1, 14, wth->fh);
	if (bytes_read != 14) {
		g_message("ngsniffer_read: not enough frame2 data (%d bytes)",
				bytes_read);
		return 0;
	}

	/* Read some of the fields in frame2 */
	size = pletohs(&frame2[6]);
	true_size = pletohs(&frame2[10]);
	time_low = pletohs(&frame2[0]);
	time_med = pletohs(&frame2[2]);
	time_high = frame2[4];

	buffer_assure_space(&wth->frame_buffer, packet_size);
	data_offset = ftell(wth->fh);
	bytes_read = fread(buffer_start_ptr(&wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh)) {
			g_message("ngsniffer_read: fread for data: read error\n");
		} else {
			g_message("ngsniffer_read: fread for data: %d bytes out of %d",
				bytes_read, packet_size);
		}
		return -1;
	}

	t = (double)time_low+(double)(time_med)*65536.0 +
		(double)time_high*4294967296.0;
	t = t/1000000.0 * wth->capture.ngsniffer->timeunit; /* t = # of secs */
	t += wth->capture.ngsniffer->start;

	wth->phdr.ts.tv_sec = (long)t;
	wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(wth->phdr.ts.tv_sec))
			*1.0e6);
	wth->phdr.len = true_size ? true_size : size;
	wth->phdr.caplen = size;

	return data_offset;
}
