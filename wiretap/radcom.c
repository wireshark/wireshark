/* radcom.c
 *
 * $Id: radcom.c,v 1.40 2002/12/17 21:53:57 oabad Exp $
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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "radcom.h"

struct frame_date {
	guint16	year;
	guint8	month;
	guint8	day;
	guint32	sec;		/* seconds since midnight */
	guint32	usec;
};

struct unaligned_frame_date {
	char	year[2];
	char	month;
	char	day;
	char	sec[4];		/* seconds since midnight */
	char	usec[4];
};

/* Found at the beginning of the file. Bytes 2 and 3 (D2:00) seem to be
 * different in some captures */
static guint8 radcom_magic[8] = {
	0x42, 0xD2, 0x00, 0x34, 0x12, 0x66, 0x22, 0x88
};

static guint8 encap_magic[4] = {
    0x00, 0x42, 0x43, 0x09
};

static guint8 active_time_magic[11] = {
	0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65
};

/* RADCOM record header - followed by frame data (perhaps including FCS).
   The first two bytes of "xxz" appear to equal "length", as do the
   second two bytes; if a RADCOM box can be told not to save all of
   the captured packet, might one or the other of those be the
   captured length of the packet? */
struct radcomrec_hdr {
	char	xxx[4];		/* unknown */
	char	length[2];	/* packet length */
	char	xxy[5];		/* unknown */
	struct unaligned_frame_date date; /* date/time stamp of packet */
	char	xxz[6];		/* unknown */
	char	dce;		/* DCE/DTE flag (and other flags?) */
	char	xxw[9];		/* unknown */
};

static gboolean radcom_read(wtap *wth, int *err, long *data_offset);
static gboolean radcom_seek_read(wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
	int *err);
static int radcom_read_rec_header(FILE_T fh, struct radcomrec_hdr *hdr,
	int *err);
static gboolean radcom_read_rec_data(FILE_T fh, guchar *pd, int length,
	int *err);

int radcom_open(wtap *wth, int *err)
{
	int bytes_read;
	guint8 r_magic[8], t_magic[11], search_encap[7];
	struct frame_date start_date;
	guint32 sec;
	struct tm tm;

	/* Read in the string that should be at the start of a RADCOM file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(r_magic, 1, 8, wth->fh);
	if (bytes_read != 8) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

        /* XXX: bytes 2 and 3 of the "magic" header seem to be different in some
         * captures. We force them to our standard value so that the test
         * succeeds (until we find if they have a special meaning, perhaps a
         * version number ?) */
        r_magic[1] = 0xD2;
        r_magic[2] = 0x00;
	if (memcmp(r_magic, radcom_magic, 8) != 0) {
		return 0;
	}

        /* Look for the "Active Time" string. The "frame_date" structure should
         * be located 32 bytes before the beginning of this string */
	wth->data_offset = 8;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(t_magic, 1, 11, wth->fh);
	if (bytes_read != 11) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
        while (memcmp(t_magic, active_time_magic, 11) != 0)
        {
            if (file_seek(wth->fh, -10, SEEK_CUR, err) == -1)
                return -1;
            wth->data_offset += 1;
            errno = WTAP_ERR_CANT_READ;
            bytes_read = file_read(t_magic, 1, 11, wth->fh);
            if (bytes_read != 11) {
                *err = file_error(wth->fh);
                if (*err != 0)
                    return -1;
                return 0;
            }
        }
        if (file_seek(wth->fh, -43, SEEK_CUR, err) == -1) return -1;
	wth->data_offset -= 32;

	/* Get capture start time */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&start_date, 1, sizeof(struct frame_date),
                               wth->fh);
	if (bytes_read != sizeof(struct frame_date)) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof(struct frame_date);

	/* This is a radcom file */
	wth->file_type = WTAP_FILE_RADCOM;
	wth->subtype_read = radcom_read;
	wth->subtype_seek_read = radcom_seek_read;
	wth->snapshot_length = 0; /* not available in header, only in frame */

	tm.tm_year = pletohs(&start_date.year)-1900;
	tm.tm_mon = start_date.month-1;
	tm.tm_mday = start_date.day;
	sec = pletohl(&start_date.sec);
	tm.tm_hour = sec/3600;
	tm.tm_min = (sec%3600)/60;
	tm.tm_sec = sec%60;
	tm.tm_isdst = -1;

	if (file_seek(wth->fh, sizeof(struct frame_date), SEEK_CUR, err) == -1)
		return -1;
	wth->data_offset += sizeof(struct frame_date);

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(search_encap, 1, 4, wth->fh);
	if (bytes_read != 4) {
		goto read_error;
	}
	wth->data_offset += 4;
	while (memcmp(encap_magic, search_encap, 4)) {
		if (file_seek(wth->fh, -3, SEEK_CUR, err) == -1)
			return -1;
		wth->data_offset -= 3;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(search_encap, 1, 4, wth->fh);
		if (bytes_read != 4) {
			goto read_error;
		}
		wth->data_offset += 4;
	}
	if (file_seek(wth->fh, 12, SEEK_CUR, err) == -1)
		return -1;
	wth->data_offset += 12;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(search_encap, 1, 4, wth->fh);
	if (bytes_read != 4) {
		goto read_error;
	}
	wth->data_offset += 4;
	if (!memcmp(search_encap, "LAPB", 4))
		wth->file_encap = WTAP_ENCAP_LAPB;
	else if (!memcmp(search_encap, "Ethe", 4))
		wth->file_encap = WTAP_ENCAP_ETHERNET;
	else {
		g_message("pcap: network type \"%.4s\" unknown", search_encap);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/*bytes_read = file_read(&next_date, 1, sizeof(struct frame_date), wth->fh);
	errno = WTAP_ERR_CANT_READ;
	if (bytes_read != sizeof(struct frame_date)) {
		goto read_error;
	}

	while (memcmp(&start_date, &next_date, 4)) {
		if (file_seek(wth->fh, 1-sizeof(struct frame_date), SEEK_CUR, err) == -1)
			return -1;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(&next_date, 1, sizeof(struct frame_date),
				   wth->fh);
		if (bytes_read != sizeof(struct frame_date)) {
			goto read_error;
		}
	}*/

	if (wth->file_encap == WTAP_ENCAP_ETHERNET) {
		if (file_seek(wth->fh, 294, SEEK_CUR, err) == -1)
			return -1;
		wth->data_offset += 294;
	} else if (wth->file_encap == WTAP_ENCAP_LAPB) {
		if (file_seek(wth->fh, 297, SEEK_CUR, err) == -1)
			return -1;
		wth->data_offset += 297;
	}

	return 1;

read_error:
	*err = file_error(wth->fh);
	if (*err != 0)
		return -1;
	return 0;
}

/* Read the next packet */
static gboolean radcom_read(wtap *wth, int *err, long *data_offset)
{
	int	ret;
	struct radcomrec_hdr hdr;
	guint16 length;
	guint32 sec;
	int	bytes_read;
	struct tm tm;
	char	fcs[2];

	/* Read record header. */
	*data_offset = wth->data_offset;
	ret = radcom_read_rec_header(wth->fh, &hdr, err);
	if (ret <= 0) {
		/* Read error or EOF */
		return FALSE;
	}
	wth->data_offset += sizeof hdr;
	length = pletohs(&hdr.length);
	if (length == 0) return FALSE;

	if (wth->file_encap == WTAP_ENCAP_LAPB)
		length -= 2; /* FCS */

	wth->phdr.len = length;
	wth->phdr.caplen = length;

	tm.tm_year = pletohs(&hdr.date.year)-1900;
	tm.tm_mon = hdr.date.month-1;
	tm.tm_mday = hdr.date.day;
	sec = pletohl(&hdr.date.sec);
	tm.tm_hour = sec/3600;
	tm.tm_min = (sec%3600)/60;
	tm.tm_sec = sec%60;
	tm.tm_isdst = -1;
	wth->phdr.ts.tv_sec = mktime(&tm);
	wth->phdr.ts.tv_usec = pletohl(&hdr.date.usec);
	wth->pseudo_header.x25.flags = (hdr.dce & 0x1) ? 0x00 : FROM_DCE;

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	if (!radcom_read_rec_data(wth->fh,
	    buffer_start_ptr(wth->frame_buffer), length, err))
		return FALSE;	/* Read error */
	wth->data_offset += length;

	wth->phdr.pkt_encap = wth->file_encap;

	if (wth->file_encap == WTAP_ENCAP_LAPB) {
		/* Read the FCS.
		   XXX - should we put it in the pseudo-header? */
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(&fcs, 1, sizeof fcs, wth->fh);
		if (bytes_read != sizeof fcs) {
			*err = file_error(wth->fh);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return FALSE;
		}
		wth->data_offset += sizeof fcs;
	}

	return TRUE;
}

static gboolean
radcom_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err)
{
	int	ret;
	struct radcomrec_hdr hdr;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* Read record header. */
	ret = radcom_read_rec_header(wth->random_fh, &hdr, err);
	if (ret <= 0) {
		/* Read error or EOF */
		if (ret == 0) {
			/* EOF means "short read" in random-access mode */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	pseudo_header->x25.flags = (hdr.dce & 0x1) ? 0x00 : FROM_DCE;

	/*
	 * Read the packet data.
	 */
	return radcom_read_rec_data(wth->random_fh, pd, length, err);
}

static int
radcom_read_rec_header(FILE_T fh, struct radcomrec_hdr *hdr, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(hdr, 1, sizeof *hdr, fh);
	if (bytes_read != sizeof *hdr) {
		*err = file_error(fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	return 1;
}

static gboolean
radcom_read_rec_data(FILE_T fh, guchar *pd, int length, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, 1, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}
