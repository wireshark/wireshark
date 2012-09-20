/* radcom.c
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
static const guint8 radcom_magic[8] = {
	0x42, 0xD2, 0x00, 0x34, 0x12, 0x66, 0x22, 0x88
};

static const guint8 encap_magic[4] = {
	0x00, 0x42, 0x43, 0x09
};

static const guint8 active_time_magic[11] = {
	0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65
};

/* RADCOM record header - followed by frame data (perhaps including FCS).

   "data_length" appears to be the length of packet data following
   the record header.  It's 0 in the last record.

   "length" appears to be the amount of captured packet data, and
   "real_length" might be the actual length of the frame on the wire -
   in some captures, it's the same as "length", and, in others,
   it's greater than "length".  In the last record, however, those
   may have bogus values (or is that some kind of trailer record?).

   "xxx" appears to be all-zero in all but the last record in one
   capture; if so, perhaps this indicates that the last record is,
   in fact, a trailer of some sort, and some field in the header
   is a record type. */
struct radcomrec_hdr {
	char	xxx[4];		/* unknown */
	char	data_length[2];	/* packet length? */
	char	xxy[5];		/* unknown */
	struct unaligned_frame_date date; /* date/time stamp of packet */
	char	real_length[2];	/* actual length of packet */
	char	length[2];	/* captured length of packet */
	char	xxz[2];		/* unknown */
	char	dce;		/* DCE/DTE flag (and other flags?) */
	char	xxw[9];		/* unknown */
};

static gboolean radcom_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean radcom_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
	int *err, gchar **err_info);
static int radcom_read_rec_header(FILE_T fh, struct radcomrec_hdr *hdr,
	int *err, gchar **err_info);
static gboolean radcom_read_rec_data(FILE_T fh, guint8 *pd, int length,
	int *err, gchar **err_info);

int radcom_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	guint8 r_magic[8], t_magic[11], search_encap[7];
	struct frame_date start_date;
#if 0
	guint32 sec;
	struct tm tm;
#endif

	/* Read in the string that should be at the start of a RADCOM file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(r_magic, 8, wth->fh);
	if (bytes_read != 8) {
		*err = file_error(wth->fh, err_info);
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
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(t_magic, 11, wth->fh);
	if (bytes_read != 11) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	while (memcmp(t_magic, active_time_magic, 11) != 0)
	{
		if (file_seek(wth->fh, -10, SEEK_CUR, err) == -1)
			return -1;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(t_magic, 11, wth->fh);
		if (bytes_read != 11) {
			*err = file_error(wth->fh, err_info);
			if (*err != 0)
				return -1;
			return 0;
		}
	}
	if (file_seek(wth->fh, -43, SEEK_CUR, err) == -1) return -1;

	/* Get capture start time */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&start_date, sizeof(struct frame_date),
			       wth->fh);
	if (bytes_read != sizeof(struct frame_date)) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* This is a radcom file */
	wth->file_type = WTAP_FILE_RADCOM;
	wth->subtype_read = radcom_read;
	wth->subtype_seek_read = radcom_seek_read;
	wth->snapshot_length = 0; /* not available in header, only in frame */
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

#if 0
	tm.tm_year = pletohs(&start_date.year)-1900;
	tm.tm_mon = start_date.month-1;
	tm.tm_mday = start_date.day;
	sec = pletohl(&start_date.sec);
	tm.tm_hour = sec/3600;
	tm.tm_min = (sec%3600)/60;
	tm.tm_sec = sec%60;
	tm.tm_isdst = -1;
#endif
	if (file_seek(wth->fh, sizeof(struct frame_date), SEEK_CUR, err) == -1)
		return -1;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(search_encap, 4, wth->fh);
	if (bytes_read != 4) {
		goto read_error;
	}
	while (memcmp(encap_magic, search_encap, 4)) {
		if (file_seek(wth->fh, -3, SEEK_CUR, err) == -1)
			return -1;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(search_encap, 4, wth->fh);
		if (bytes_read != 4) {
			goto read_error;
		}
	}
	if (file_seek(wth->fh, 12, SEEK_CUR, err) == -1)
		return -1;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(search_encap, 4, wth->fh);
	if (bytes_read != 4) {
		goto read_error;
	}
	if (memcmp(search_encap, "LAPB", 4) == 0)
		wth->file_encap = WTAP_ENCAP_LAPB;
	else if (memcmp(search_encap, "Ethe", 4) == 0)
		wth->file_encap = WTAP_ENCAP_ETHERNET;
	else if (memcmp(search_encap, "ATM/", 4) == 0)
		wth->file_encap = WTAP_ENCAP_ATM_RFC1483;
	else {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("radcom: network type \"%.4s\" unknown", search_encap);
		return -1;
	}

#if 0
	bytes_read = file_read(&next_date, sizeof(struct frame_date), wth->fh);
	errno = WTAP_ERR_CANT_READ;
	if (bytes_read != sizeof(struct frame_date)) {
		goto read_error;
	}

	while (memcmp(&start_date, &next_date, 4)) {
		if (file_seek(wth->fh, 1-sizeof(struct frame_date), SEEK_CUR, err) == -1)
			return -1;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(&next_date, sizeof(struct frame_date),
				   wth->fh);
		if (bytes_read != sizeof(struct frame_date)) {
			goto read_error;
		}
	}
#endif

	if (wth->file_encap == WTAP_ENCAP_ETHERNET) {
		if (file_seek(wth->fh, 294, SEEK_CUR, err) == -1)
			return -1;
	} else if (wth->file_encap == WTAP_ENCAP_LAPB) {
		if (file_seek(wth->fh, 297, SEEK_CUR, err) == -1)
			return -1;
	} else if (wth->file_encap == WTAP_ENCAP_ATM_RFC1483) {
		if (file_seek(wth->fh, 504, SEEK_CUR, err) == -1)
			return -1;
	}

	return 1;

read_error:
	*err = file_error(wth->fh, err_info);
	if (*err != 0)
		return -1;
	return 0;
}

/* Read the next packet */
static gboolean radcom_read(wtap *wth, int *err, gchar **err_info,
			    gint64 *data_offset)
{
	int	ret;
	struct radcomrec_hdr hdr;
	guint16 data_length, real_length, length;
	guint32 sec;
	int	bytes_read;
	struct tm tm;
	guint8	phdr[8];
	char	fcs[2];

	/* Read record header. */
	*data_offset = file_tell(wth->fh);
	ret = radcom_read_rec_header(wth->fh, &hdr, err, err_info);
	if (ret <= 0) {
		/* Read error or EOF */
		return FALSE;
	}
	data_length = pletohs(&hdr.data_length);
	if (data_length == 0) {
		/*
		 * The last record appears to have 0 in its "data_length"
		 * field, but non-zero values in other fields, so we
		 * check for that and treat it as an EOF indication.
		 */
		*err = 0;
		return FALSE;
	}
	length = pletohs(&hdr.length);
	real_length = pletohs(&hdr.real_length);

	if (wth->file_encap == WTAP_ENCAP_LAPB) {
		length -= 2; /* FCS */
		real_length -= 2;
	}

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	wth->phdr.len = real_length;
	wth->phdr.caplen = length;

	tm.tm_year = pletohs(&hdr.date.year)-1900;
	tm.tm_mon = (hdr.date.month&0x0f)-1;
	tm.tm_mday = hdr.date.day;
	sec = pletohl(&hdr.date.sec);
	tm.tm_hour = sec/3600;
	tm.tm_min = (sec%3600)/60;
	tm.tm_sec = sec%60;
	tm.tm_isdst = -1;
	wth->phdr.ts.secs = mktime(&tm);
	wth->phdr.ts.nsecs = pletohl(&hdr.date.usec) * 1000;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* XXX - is there an FCS? */
		wth->pseudo_header.eth.fcs_len = -1;
		break;

	case WTAP_ENCAP_LAPB:
		wth->pseudo_header.x25.flags = (hdr.dce & 0x1) ?
		    0x00 : FROM_DCE;
		break;

	case WTAP_ENCAP_ATM_RFC1483:
		/*
		 * XXX - is this stuff a pseudo-header?
		 * The direction appears to be in the "hdr.dce" field.
		 */
		if (!radcom_read_rec_data(wth->fh, phdr, sizeof phdr, err,
		    err_info))
			return FALSE;	/* Read error */
		length -= 8;
		wth->phdr.len -= 8;
		wth->phdr.caplen -= 8;
		break;
	}

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	if (!radcom_read_rec_data(wth->fh,
	    buffer_start_ptr(wth->frame_buffer), length, err, err_info))
		return FALSE;	/* Read error */

	if (wth->file_encap == WTAP_ENCAP_LAPB) {
		/* Read the FCS.
		   XXX - should we have some way of indicating the
		   presence and size of an FCS to our caller?
		   That'd let us handle other file types as well. */
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(&fcs, sizeof fcs, wth->fh);
		if (bytes_read != sizeof fcs) {
			*err = file_error(wth->fh, err_info);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
radcom_seek_read(wtap *wth, gint64 seek_off,
		 union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
		 int *err, gchar **err_info)
{
	int	ret;
	struct radcomrec_hdr hdr;
	guint8	phdr[8];

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* Read record header. */
	ret = radcom_read_rec_header(wth->random_fh, &hdr, err, err_info);
	if (ret <= 0) {
		/* Read error or EOF */
		if (ret == 0) {
			/* EOF means "short read" in random-access mode */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* XXX - is there an FCS? */
		pseudo_header->eth.fcs_len = -1;
		break;

	case WTAP_ENCAP_LAPB:
		pseudo_header->x25.flags = (hdr.dce & 0x1) ? 0x00 : FROM_DCE;
		break;

	case WTAP_ENCAP_ATM_RFC1483:
		/*
		 * XXX - is this stuff a pseudo-header?
		 * The direction appears to be in the "hdr.dce" field.
		 */
		if (!radcom_read_rec_data(wth->random_fh, phdr, sizeof phdr,
		    err, err_info))
			return FALSE;	/* Read error */
		break;
	}

	/*
	 * Read the packet data.
	 */
	return radcom_read_rec_data(wth->random_fh, pd, length, err, err_info);
}

static int
radcom_read_rec_header(FILE_T fh, struct radcomrec_hdr *hdr, int *err,
		       gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(hdr, sizeof *hdr, fh);
	if (bytes_read != sizeof *hdr) {
		*err = file_error(fh, err_info);
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
radcom_read_rec_data(FILE_T fh, guint8 *pd, int length, int *err,
		     gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}
