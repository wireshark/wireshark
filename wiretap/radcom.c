/* radcom.c
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
#include <time.h>
#include "wtap.h"
#include "buffer.h"
#include "radcom.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

struct frame_date {
	guint16	year;
	guint8	month;
	guint8	day;
	guint32	sec;		/* seconds since midnight */
	guint32	usec;
};

static char radcom_magic[8] = {
	0x42, 0xD2, 0x00, 0x34, 0x12, 0x66, 0x22, 0x88
};

/* Returns WTAP_FILE_RADCOM on success, WTAP_FILE_UNKNOWN on failure */
int radcom_open(wtap *wth)
{
	int bytes_read;
	char magic[8];
	struct frame_date start_date;
	struct tm tm;
	char byte;
	char encap_magic[7] = {0x54, 0x43, 0x50, 0x00, 0x42, 0x43, 0x09};
	char search_encap[7];

	/* Read in the string that should be at the start of a Sniffer file */
	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, 8, wth->fh);

	if (bytes_read != 8) {
		return WTAP_FILE_UNKNOWN;
	}

	if (memcmp(magic, radcom_magic, 8)) {
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a radcom file */
	wth->capture.radcom = g_malloc(sizeof(radcom_t));
	wth->subtype_read = radcom_read;
	wth->snapshot_length = 16384;	/* not available in header, only in frame */
	fseek(wth->fh, 0x8B, SEEK_SET);
	bytes_read = fread(&byte, 1, 1, wth->fh);
	if (bytes_read != 1) {
		return WTAP_FILE_UNKNOWN;
	}
	while (byte) {
		bytes_read = fread(&byte, 1, 1, wth->fh);
		if (bytes_read != 1) {
			return WTAP_FILE_UNKNOWN;
		}
	}
	fseek(wth->fh, 1, SEEK_CUR);

	/* Get capture start time */
	bytes_read = fread(&start_date, 1, sizeof(struct frame_date), wth->fh);

	if (bytes_read != sizeof(struct frame_date)) {
		return WTAP_FILE_UNKNOWN;
	}

	tm.tm_year = start_date.year-1900;
	tm.tm_mon = start_date.month-1;
	tm.tm_mday = start_date.day;
	tm.tm_hour = start_date.sec/3600;
	tm.tm_min = (start_date.sec%3600)/60;
	tm.tm_sec = start_date.sec%60;
	tm.tm_isdst = -1;
	wth->capture.radcom->start = mktime(&tm);

	fseek(wth->fh, sizeof(struct frame_date), SEEK_CUR);

	bytes_read = fread(search_encap, 1, 7, wth->fh);
	if (bytes_read != 7) {
		return WTAP_FILE_UNKNOWN;
	}
	while (memcmp(encap_magic, search_encap, 7)) {
		fseek(wth->fh, -6, SEEK_CUR);
		bytes_read = fread(search_encap, 1, 7, wth->fh);
		if (bytes_read != 7) {
			return WTAP_FILE_UNKNOWN;
		}
	}
	fseek(wth->fh, 12, SEEK_CUR);
	bytes_read = fread(search_encap, 1, 4, wth->fh);
	if (bytes_read != 4) {
		return WTAP_FILE_UNKNOWN;
	}
	if (!memcmp(search_encap, "LAPB", 4))
		wth->file_encap = WTAP_ENCAP_LAPB;
	else if (!memcmp(search_encap, "Ethe", 4))
		wth->file_encap = WTAP_ENCAP_ETHERNET;
	else
		return WTAP_FILE_UNKNOWN;

	/*bytes_read = fread(&next_date, 1, sizeof(struct frame_date), wth->fh);
	if (bytes_read != sizeof(struct frame_date)) {
		return WTAP_FILE_UNKNOWN;
	}

	while (memcmp(&start_date, &next_date, 4)) {
		fseek(wth->fh, 1-sizeof(struct frame_date), SEEK_CUR);
		bytes_read = fread(&next_date, 1, sizeof(struct frame_date),
				   wth->fh);
		if (bytes_read != sizeof(struct frame_date)) {
			return WTAP_FILE_UNKNOWN;
		}
	}*/

	if (wth->file_encap == WTAP_ENCAP_ETHERNET)
		fseek(wth->fh, 294, SEEK_CUR);
	else if (wth->file_encap == WTAP_ENCAP_LAPB)
		fseek(wth->fh, 297, SEEK_CUR);

	return WTAP_FILE_RADCOM;
}

/* Read the next packet */
int radcom_read(wtap *wth)
{
	int	bytes_read;
	guint16 length;
	struct frame_date date;
	int	data_offset;
	struct tm tm;
	char dce;

	fseek(wth->fh, 4, SEEK_CUR);

	/*
	 * Read the frame size
	 */
	bytes_read = fread(&length, 1, 2, wth->fh);
	if (bytes_read != 2) {
		/*
		 * End of file or error.
		 */
		g_message("radcom_read: not enough frame data (%d bytes)",
			bytes_read);
		return 0;
	}

	if (wth->file_encap == WTAP_ENCAP_LAPB) length -= 2; /* FCS */

	wth->phdr.len = length;
	wth->phdr.caplen = length;

	fseek(wth->fh, 5, SEEK_CUR);
	bytes_read = fread(&date, 1, sizeof(struct frame_date), wth->fh);
	if (bytes_read != sizeof(struct frame_date)) {
		/*
		 * End of file or error.
		 */
		g_message("radcom_read: not enough frame data (%d bytes)",
			bytes_read);
		return 0;
	}

	tm.tm_year = date.year-1900;
	tm.tm_mon = date.month-1;
	tm.tm_mday = date.day;
	tm.tm_hour = date.sec/3600;
	tm.tm_min = (date.sec%3600)/60;
	tm.tm_sec = date.sec%60;
	tm.tm_isdst = -1;
	wth->phdr.ts.tv_sec = mktime(&tm);
	wth->phdr.ts.tv_usec = date.usec;

	fseek(wth->fh, 6, SEEK_CUR);
	bytes_read = fread(&dce, 1, 1, wth->fh);
	if (bytes_read != 1) {
		/*
		 * End of file or error.
		 */
		g_message("radcom_read: not enough frame data (%d bytes)",
			bytes_read);
		return 0;
	}
	wth->phdr.flags = (dce & 0x1) ? 0x00 : 0x80;

	fseek(wth->fh, 9, SEEK_CUR);

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	data_offset = ftell(wth->fh);
	bytes_read = fread(buffer_start_ptr(wth->frame_buffer), 1,
			length, wth->fh);

	if (bytes_read != length) {
		if (ferror(wth->fh)) {
			g_message("radcom_read: fread for data: read error\n");
		} else {
			g_message("radcom_read: fread for data: %d bytes out of %d",
				bytes_read, length);
		}
		return -1;
	}

	wth->phdr.pkt_encap = wth->file_encap;

	if (wth->file_encap == WTAP_ENCAP_LAPB)
		fseek(wth->fh, 2, SEEK_CUR); /* FCS */

	return data_offset;
}
