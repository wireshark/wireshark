/* lanalyzer.c
 *
 * $Id: lanalyzer.c,v 1.11 1999/08/19 05:31:34 guy Exp $
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "wtap.h"
#include "buffer.h"
#include "lanalyzer.h"

/* The LANalyzer format is documented (at least in part) in Novell document
   TID022037, which can be found at, among other places:

	http://www.hackzone.ru/nsp/info/nw/lan/trace.txt
 */

/* Record types. */
#define REC_TRACE_HEADER	0x1001
#define REC_CYCLIC_TRACE_HEADER	0x1007
#define REC_TRACE_SUMMARY	0x1002
#define REC_TRACE_PACKET_DATA	0x1005

/* LANalyzer board types (which indicate the type of network on which
   the capture was done). */
#define BOARD_325		226	/* LANalyzer 325 (Ethernet) */
#define BOARD_325TR		227	/* LANalyzer 325TR (Token-ring) */

static int lanalyzer_read(wtap *wth, int *err);

int lanalyzer_open(wtap *wth, int *err)
{
	int bytes_read;
	char record_type[2];
	char record_length[2];
	char summary[210];
	guint16 board_type, mxslc;
	guint16 type, length;
	guint8 cr_day, cr_month, cr_year;
	struct tm tm;

	fseek(wth->fh, 0, SEEK_SET);
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(record_type, 1, 2, wth->fh);
	bytes_read += fread(record_length, 1, 2, wth->fh);
	if (bytes_read != 4) {
		if (ferror(wth->fh)) {
			*err = errno;
			return -1;
		}
		return 0;
	}
	type = pletohs(record_type);
	length = pletohs(record_length); /* make sure to do this for while() loop */

	if (type != REC_TRACE_HEADER && type != REC_CYCLIC_TRACE_HEADER) {  
		return 0;
	}

	/* If we made it this far, then the file is a LANAlyzer file.
	 * Let's get some info from it */
	wth->file_type = WTAP_FILE_LANALYZER;
	wth->capture.lanalyzer = g_malloc(sizeof(lanalyzer_t));
	wth->subtype_read = lanalyzer_read;
/*	wth->snapshot_length = 16384; */ /* available in header as 'mxslc' */

	/* Read records until we find the start of packets */

	while (1) {
		fseek(wth->fh, length, SEEK_CUR);
		errno = WTAP_ERR_CANT_READ;
		bytes_read = fread(record_type, 1, 2, wth->fh);
		bytes_read += fread(record_length, 1, 2, wth->fh);
		if (bytes_read != 4) {
			if (ferror(wth->fh)) {
				*err = errno;
				free(wth->capture.lanalyzer);
				return -1;
			}
			free(wth->capture.lanalyzer);
			return 0;
		}

		type = pletohs(record_type);
		length = pletohs(record_length);

/*		g_message("Record 0x%04X Length %d", type, length);*/
		switch (type) {
			/* Trace Summary Record */
			case REC_TRACE_SUMMARY:
				errno = WTAP_ERR_CANT_READ;
				bytes_read = fread(summary, 1, sizeof summary,
				    wth->fh);
				if (bytes_read != sizeof summary) {
					if (ferror(wth->fh)) {
						*err = errno;
						free(wth->capture.lanalyzer);
						return -1;
					}
					free(wth->capture.lanalyzer);
					return 0;
				}

				/* Assume that the date of the creation of the trace file
				 * is the same date of the trace. Lanalyzer doesn't
				 * store the creation date/time of the trace, but only of
				 * the file. Unless you traced at 11:55 PM and saved at 00:05
				 * AM, the assumption that trace.date == file.date is true.
				 */
				cr_day = summary[0];
				cr_month = summary[1];
				cr_year = pletohs(&summary[2]);
				/*g_message("Day %d Month %d Year %d (%04X)", cr_day, cr_month,
						cr_year, cr_year);*/

				/* Get capture start time. I learned how to do
				 * this from Guy's code in ngsniffer.c
				 */
				/* this strange year offset is not in the
				 * lanalyzer file format documentation, but it
				 * works. */
				tm.tm_year = cr_year - (1900 - 1792);
				tm.tm_mon = cr_month - 1;
				tm.tm_mday = cr_day;
				tm.tm_hour = 0;
				tm.tm_min = 0;
				tm.tm_sec = 0;
				tm.tm_isdst = -1;
				wth->capture.lanalyzer->start = mktime(&tm);
				/*g_message("Day %d Month %d Year %d", tm.tm_mday,
						tm.tm_mon, tm.tm_year);*/
				mxslc = pletohs(&summary[30]);
				wth->snapshot_length = mxslc;

				length = 0; /* to fake the next iteration of while() */
				board_type = pletohs(&summary[188]);
				switch (board_type) {
					case BOARD_325:
						wth->file_encap = WTAP_ENCAP_ETHERNET;
						break;
					case BOARD_325TR:
						wth->file_encap = WTAP_ENCAP_TR;
						break;
					default:
						wth->file_encap = WTAP_ENCAP_NONE;
				}
				break;

			/* Trace Packet Data Record */
			case REC_TRACE_PACKET_DATA:
				wth->capture.lanalyzer->pkt_len = length - 32;
				return 1;

		/*	default: no default action */
		/*		printf("Record 0x%04X Length %d\n", type, length);*/
		}
	} 

	/* never gets here */
	return 0;
}

#define DESCRIPTOR_LEN	32

/* Read the next packet */
static int lanalyzer_read(wtap *wth, int *err)
{
	int packet_size = wth->capture.lanalyzer->pkt_len; /* slice, really */
	int bytes_read;
	char record_type[2];
	char record_length[2];
	guint16 type, length;
	gchar descriptor[DESCRIPTOR_LEN];
	int	data_offset;
	guint16 time_low, time_med, time_high, true_size;
	double t;

	/* If this is the very first packet, then the fh cursor will already
	 * be at the start of the packet data instead of at the start of the
	 * Trace Packet Data Record. Check for this */
	if (!packet_size) {
		/* This isn't the first packet (the record type and length
		 * of which we've already read in the loop in the open
		 * routine); read the record type and length. */
		errno = WTAP_ERR_CANT_READ;
		bytes_read = fread(record_type, 1, 2, wth->fh);
		if (bytes_read != 2) {
			if (ferror(wth->fh)) {
				*err = errno;
				return -1;
			}
			if (bytes_read != 0) {
				*err = WTAP_ERR_SHORT_READ;
				return -1;
			}
			return 0;
		}
		bytes_read = fread(record_length, 1, 2, wth->fh);
		if (bytes_read != 2) {
			if (ferror(wth->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_READ;
			return -1;
		}

		type = pletohs(record_type);
		length = pletohs(record_length);

		if (type != REC_TRACE_PACKET_DATA) {
			/* XXX - return -1 and set "*err" to
			 * WTAP_ERR_BAD_RECORD? */
			return 0;
		}
		else {
			packet_size = length - DESCRIPTOR_LEN;
		}
	}
	else {
		wth->capture.lanalyzer->pkt_len = 0;
	}	

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(descriptor, 1, DESCRIPTOR_LEN, wth->fh);
	if (bytes_read != DESCRIPTOR_LEN) {
		if (ferror(wth->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}

	/* Read the packet data */
	buffer_assure_space(wth->frame_buffer, packet_size);
	data_offset = ftell(wth->fh);
	errno = WTAP_ERR_CANT_READ;
	bytes_read = fread(buffer_start_ptr(wth->frame_buffer), 1,
		packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}

	true_size = pletohs(&descriptor[4]);
	time_low = pletohs(&descriptor[8]);
	time_med = pletohs(&descriptor[10]);
	time_high = pletohs(&descriptor[12]);

	t = (double)time_low+(double)(time_med)*65536.0 +
		(double)time_high*4294967296.0;
	t = t/1000000.0 * 0.5; /* t = # of secs */
	t += wth->capture.lanalyzer->start;

	wth->phdr.ts.tv_sec = (long)t;
	wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(wth->phdr.ts.tv_sec))
			*1.0e6);

	wth->phdr.len = true_size - 4;
	wth->phdr.caplen = packet_size;
	wth->phdr.pkt_encap = wth->file_encap;

	return data_offset;
}
