/* lanalyzer.c
 *
 * $Id: lanalyzer.c,v 1.22 2000/05/18 09:09:31 guy Exp $
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
#include <time.h>
#include "wtap.h"
#include "file_wrappers.h"
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
static void lanalyzer_close(wtap *wth);

int lanalyzer_open(wtap *wth, int *err)
{
	int bytes_read;
	char LE_record_type[2];
	char LE_record_length[2];
	char summary[210];
	guint16 board_type, mxslc;
	guint16 record_type, record_length;
	guint8 cr_day, cr_month, cr_year;
	struct tm tm;

	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(LE_record_type, 1, 2, wth->fh);
	bytes_read += file_read(LE_record_length, 1, 2, wth->fh);
	if (bytes_read != 4) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += 4;
	record_type = pletohs(LE_record_type);
	record_length = pletohs(LE_record_length); /* make sure to do this for while() loop */

	if (record_type != REC_TRACE_HEADER && record_type != REC_CYCLIC_TRACE_HEADER) {  
		return 0;
	}

	/* If we made it this far, then the file is a LANAlyzer file.
	 * Let's get some info from it. Note that we get wth->snapshot_length
	 * from a record later in the file. */
	wth->file_type = WTAP_FILE_LANALYZER;
	wth->capture.lanalyzer = g_malloc(sizeof(lanalyzer_t));
	wth->subtype_read = lanalyzer_read;
	wth->subtype_seek_read = wtap_def_seek_read;
	wth->subtype_close = lanalyzer_close;
	wth->snapshot_length = 0;

	/* Read records until we find the start of packets */
	while (1) {
		file_seek(wth->fh, record_length, SEEK_CUR);
		wth->data_offset += record_length;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(LE_record_type, 1, 2, wth->fh);
		bytes_read += file_read(LE_record_length, 1, 2, wth->fh);
		if (bytes_read != 4) {
			*err = file_error(wth->fh);
			if (*err != 0) {
				g_free(wth->capture.lanalyzer);
				return -1;
			}
			g_free(wth->capture.lanalyzer);
			return 0;
		}
		wth->data_offset += 4;

		record_type = pletohs(LE_record_type);
		record_length = pletohs(LE_record_length);

		/*g_message("Record 0x%04X Length %d", record_type, record_length);*/
		switch (record_type) {
			/* Trace Summary Record */
			case REC_TRACE_SUMMARY:
				errno = WTAP_ERR_CANT_READ;
				bytes_read = file_read(summary, 1, sizeof summary,
				    wth->fh);
				if (bytes_read != sizeof summary) {
					*err = file_error(wth->fh);
					if (*err != 0) {
						g_free(wth->capture.lanalyzer);
						return -1;
					}
					g_free(wth->capture.lanalyzer);
					return 0;
				}
				wth->data_offset += sizeof summary;

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

				record_length = 0; /* to fake the next iteration of while() */
				board_type = pletohs(&summary[188]);
				switch (board_type) {
					case BOARD_325:
						wth->file_encap = WTAP_ENCAP_ETHERNET;
						break;
					case BOARD_325TR:
						wth->file_encap = WTAP_ENCAP_TR;
						break;
					default:
						g_message("lanalyzer: board type %u unknown",
						    board_type);
						g_free(wth->capture.lanalyzer);
						*err = WTAP_ERR_UNSUPPORTED;
						return -1;
				}
				break;

			/* Trace Packet Data Record */
			case REC_TRACE_PACKET_DATA:
				/* Go back header number ob ytes so that lanalyzer_read
				 * can read this header */
				file_seek(wth->fh, -bytes_read, SEEK_CUR);
				wth->data_offset -= bytes_read;
				return 1;

			default:
				; /* no action */
		}
	} 

	/* never gets here */
	g_assert_not_reached();
	return 0;
}

#define DESCRIPTOR_LEN	32

/* Read the next packet */
static int lanalyzer_read(wtap *wth, int *err)
{
	int		packet_size = 0;
	int		bytes_read;
	char		LE_record_type[2];
	char		LE_record_length[2];
	guint16		record_type, record_length;
	gchar		descriptor[DESCRIPTOR_LEN];
	int		data_offset;
	guint16		time_low, time_med, time_high, true_size;
	double		t;

	/* read the record type and length. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(LE_record_type, 1, 2, wth->fh);
	if (bytes_read != 2) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += 2;
	bytes_read = file_read(LE_record_length, 1, 2, wth->fh);
	if (bytes_read != 2) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += 2;

	record_type = pletohs(LE_record_type);
	record_length = pletohs(LE_record_length);

	/* Only Trace Packet Data Records should occur now that we're in
	 * the middle of reading packets.  If any other record type exists
	 * after a Trace Packet Data Record, mark it as an error. */
	if (record_type != REC_TRACE_PACKET_DATA) {
		g_message("lanalyzer: record type %u seen after trace summary record",
		    record_type);
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}
	else {
		packet_size = record_length - DESCRIPTOR_LEN;
	}

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(descriptor, 1, DESCRIPTOR_LEN, wth->fh);
	if (bytes_read != DESCRIPTOR_LEN) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += DESCRIPTOR_LEN;

	/* Read the packet data */
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

static void
lanalyzer_close(wtap *wth)
{
	g_free(wth->capture.lanalyzer);
}
