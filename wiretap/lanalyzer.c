/* lanalyzer.c
 *
 * $Id: lanalyzer.c,v 1.4 1998/11/23 15:48:38 gram Exp $
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
#include <stdlib.h>
#include "wtap.h"
#include "lanalyzer.h"

int lanalyzer_open(wtap *wth)
{
	int bytes_read;
	char record_type[2];
	char record_length[2];
	char summary[210];
	guint16 board_type, mxslc;
	guint16 type, length;
	guint8 cr_day, cr_month, cr_year;

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(record_type, 1, 2, wth->fh);
	bytes_read += fread(record_length, 1, 2, wth->fh);
	type = pletohs(record_type);
	length = pletohs(record_length); /* make sure to do this for while() loop */

	if (bytes_read != 4) {
		return WTAP_FILE_UNKNOWN;
	}

	if (type != 0x1001 && type != 0x1007) {
		return WTAP_FILE_UNKNOWN;
	}

	/* If we made it this far, then the file is a LANAlyzer file.
	 * Let's get some info from it */
	wth->capture.lanalyzer = g_malloc(sizeof(lanalyzer_t));
	wth->subtype_read = lanalyzer_read;
/*	wth->snapshot_length = 16384; */ /* available in header as 'mxslc' */

	/* Read records until we find the start of packets */

	while (1) {
		fseek(wth->fh, length, SEEK_CUR);
		bytes_read = fread(record_type, 1, 2, wth->fh);
		bytes_read += fread(record_length, 1, 2, wth->fh);
		if (bytes_read != 4) {
			free(wth->capture.lanalyzer);
			return WTAP_FILE_UNKNOWN;
		}

		type = pletohs(record_type);
		length = pletohs(record_length);

/*		g_message("Record 0x%04X Length %d", type, length);*/
		switch (type) {
			/* Trace Summary Record */
			case 0x1002:
				fread(summary, 1, 210, wth->fh);

				/* Assume that the date of the creation of the trace file
				 * is the same date of the trace. Lanalyzer doesn't
				 * store the creation date/time of the trace, but only of
				 * the file. Unless you traced at 11:55 PM and saved at 00:05
				 * AM, the assumption that trace.date == file.date is true.
				 */
				cr_day = summary[0];
				cr_month = summary[1];
				cr_year = pletohs(&summary[2]);

				mxslc = pletohs(&summary[30]);
				wth->snapshot_length = mxslc;

				length = 0; /* to fake the next iteration of while() */
				board_type = pletohs(&summary[188]);
				switch (board_type) {
					case 226:
						wth->encapsulation = WTAP_ENCAP_ETHERNET;
						break;
					case 227:
						wth->encapsulation = WTAP_ENCAP_TR;
						break;
					default:
						wth->encapsulation = WTAP_ENCAP_NONE;
				}
				break;

			/* Trace Packet Data Record */
			case 0x1005:
				wth->capture.lanalyzer->pkt_len = length - 32;
				return WTAP_FILE_LANALYZER;

			default:
		/*		printf("Record 0x%04X Length %d\n", type, length);*/
		}
	} 

	/* never gets here */
	return WTAP_FILE_LANALYZER;
}

/* Read the next packet */
int lanalyzer_read(wtap *wth)
{
	int packet_size = wth->capture.lanalyzer->pkt_len; /* slice, really */
	int bytes_read;
	char record_type[2];
	char record_length[2];
	guint16 type, length;
	gchar descriptor[32];
	int	data_offset;
	guint16 time_low, time_med, time_high, true_size;
	double t, x;

	/* If this is the very first packet, then the fh cursor will already
	 * be at the start of the packet data instead of at the start of the Trace
	 * Packet Data Record. Check for this */
	if (!packet_size) {

		/* Increment fh cursor to next record */
		bytes_read = fread(record_type, 1, 2, wth->fh);
		bytes_read += fread(record_length, 1, 2, wth->fh);
		if (bytes_read != 4) {
			return 0;
		}

		type = pletohs(record_type);
		length = pletohs(record_length);

		if (type != 0x1005) {
			return 0;
		}
		else {
			packet_size = length - 32;
		}
	}
	else {
		wth->capture.lanalyzer->pkt_len = 0;
	}	

	/* Read the descriptor data */
	bytes_read = fread(descriptor, 1, 32, wth->fh);
	if (bytes_read != 32) {
		g_error("lanalyzer_read: not enough descriptor data (%d bytes)",
				bytes_read);
		return 0;
	}

	/* Read the packet data */
	buffer_assure_space(&wth->frame_buffer, packet_size);
	data_offset = ftell(wth->fh);
	bytes_read = fread(buffer_start_ptr(&wth->frame_buffer), 1,
		packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (ferror(wth->fh)) {
			g_error("lanalyzer_read: fread for data: read error\n");
		} else {
			g_error("lanalyzer_read: fread for data: %d bytes out of %d read",
				bytes_read, packet_size);
		}
		return -1;
	}

	true_size = pletohs(&descriptor[4]);
	time_low = pletohs(&descriptor[8]);
	time_med = pletohs(&descriptor[10]);
	time_high = pletohs(&descriptor[12]);

	x = 4.0 * (double)(1<<30);
	t = (double)time_low+(double)(time_med)*65536.0 +
		(double)time_high*x;
	t = t/1000000.0 * 0.5; /* t = # of secs */

	wth->phdr.ts.tv_sec = (long)t;
	wth->phdr.ts.tv_usec = (unsigned long)((t-(double)(wth->phdr.ts.tv_sec))
			*1.0e6);

	wth->phdr.len = true_size - 4;
	wth->phdr.caplen = packet_size;

	return data_offset;
}
