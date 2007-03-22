/* mpeg.c
 *
 * MPEG file format decoder for the Wiretap library.
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * $Id$
 *
 * Wiretap Library
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "mpeg.h"
#include "mpeg-audio.h"

#include "wtap-int.h"
#include "buffer.h"
#include "file_wrappers.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PES_PREFIX 1
#define PES_VALID(n) (((n) >> 8 & 0xffffff) == PES_PREFIX)

static size_t 
mpeg_resync(wtap *wth, int *err, gchar **err_info _U_)
{
	gint64 offset = file_tell(wth->fh);
	size_t count = 0;
	int sync = file_getc(wth->fh);

	while (sync != EOF) {
		if (sync == 0xff && count > 0) {
			sync = file_getc(wth->fh);
			if (sync != EOF && (sync & 0xe0) == 0xe0)
				break;
		} else
			sync = file_getc(wth->fh);
		count++;
	}
	file_seek(wth->fh, offset, SEEK_SET, err);
	return count;
}

static int 
mpeg_read_header(wtap *wth, int *err, gchar **err_info _U_,
		guint32 *n)
{
	int bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(n, 1, sizeof *n, wth->fh);
	if (bytes_read != sizeof *n) {
		*err = file_error(wth->fh);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	*n = g_ntohl(*n);
	if (file_seek(wth->fh, -(gint64)(sizeof *n), SEEK_CUR, err) == -1)
		return -1;
	return bytes_read;
}

static gboolean
mpeg_read_rec_data(FILE_T fh, guchar *pd, int length, int *err)
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

static struct wtap_nstime now;
static double t0;

static gboolean 
mpeg_read(wtap *wth, int *err, gchar **err_info _U_,
		gint64 *data_offset)
{
	guint32 n;
	int bytes_read = mpeg_read_header(wth, err, err_info, &n);
	unsigned packet_size;
	struct wtap_nstime ts = now;

	if (bytes_read == -1)
		return FALSE;
	if (PES_VALID(n)) {
		gint64 offset = file_tell(wth->fh);
		guint8 stream;
		int bytes_read;

		if (offset == -1)
			return -1;
		if (file_seek(wth->fh, 3, SEEK_CUR, err) == -1)
			return FALSE;

		bytes_read = file_read(&stream, 1, sizeof stream, wth->fh);
		if (bytes_read != sizeof stream) {
			*err = file_error(wth->fh);
			return FALSE;
		}

		if (stream == 0xba) {
			guint32 pack1;
			guint32 pack0;
			guint64 pack;
			guint8 stuffing;
			guint32 scr;
			guint16 scr_ext;
			double t;
			double secs;

			bytes_read = file_read(&pack1, 1, sizeof pack1, wth->fh);
			if (bytes_read != sizeof pack1) {
				*err = file_error(wth->fh);
				if (*err == 0 && bytes_read != 0)
					*err = WTAP_ERR_SHORT_READ;
				return FALSE;
			}
			bytes_read = file_read(&pack0, 1, sizeof pack0, wth->fh);
			if (bytes_read != sizeof pack0) {
				*err = file_error(wth->fh);
				if (*err == 0 && bytes_read != 0)
					*err = WTAP_ERR_SHORT_READ;
				return FALSE;
			}
			pack = (guint64)g_ntohl(pack1) << 32 | g_ntohl(pack0);

			switch (pack >> 62) {
				case 1:
					if (file_seek(wth->fh, 1, SEEK_CUR, err) == -1)
						return FALSE;
					bytes_read = file_read(&stuffing,
							1, sizeof stuffing, wth->fh);
					if (bytes_read != sizeof stuffing) {
						*err = file_error(wth->fh);
						return FALSE;
					}
					stuffing &= 0x07;
					packet_size = 14 + stuffing;

					scr = (guint32)
						((pack >> 59 & 0x0007) << 30 |
						(pack >> 43 & 0x7fff) << 15 |
						 (pack >> 27 & 0x7fff) << 0);
					scr_ext = (guint16)(pack >> 17 & 0x1ff);
					t = t0 + scr / 90e3 + scr_ext / 27e6;

					now.nsecs = (int)(modf(t, &secs) * 1e9);
					now.secs = (time_t)secs;
					ts = now;
					break;
				default:
					packet_size = 12;
			}
		} else {
			guint16 length;
			bytes_read = file_read(&length, 1, sizeof length, wth->fh);
			if (bytes_read != sizeof length) {
				*err = file_error(wth->fh);
				if (*err == 0 && bytes_read != 0)
					*err = WTAP_ERR_SHORT_READ;
				return FALSE;
			}
			length = g_ntohs(length);
			packet_size = 6 + length;
		}

		if (file_seek(wth->fh, offset, SEEK_SET, err) == -1)
			return FALSE;
	} else {
		struct mpa mpa;

		MPA_UNMARSHAL(&mpa, n);
		if (MPA_VALID(&mpa)) {
			packet_size = MPA_BYTES(&mpa);
			now.nsecs += MPA_DURATION_NS(&mpa);
			if (now.nsecs >= 1000000000) {
				now.secs++;
				now.nsecs -= 1000000000;
			}
		} else {
			packet_size = mpeg_resync(wth, err, err_info);
			if (packet_size == 0)
				return FALSE;
		}
	}
	*data_offset = wth->data_offset;

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!mpeg_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
				packet_size, err))
		return FALSE;
	wth->data_offset += packet_size;
	wth->phdr.ts = ts;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = packet_size;
	return TRUE;
}

static gboolean
mpeg_seek_read(wtap *wth, gint64 seek_off,
		union wtap_pseudo_header *pseudo_header _U_, guchar *pd, int length,
		int *err, gchar **err_info _U_)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;
	return mpeg_read_rec_data(wth->random_fh, pd, length, err);
}

static void
mpeg_close(wtap *wth _U_)
{

}

int 
mpeg_open(wtap *wth, int *err, gchar **err_info)
{
	guint32 n;
	struct mpa mpa;

	now.secs = time(NULL);
	now.nsecs = 0;
	t0 = now.secs;

	if (mpeg_read_header(wth, err, err_info, &n) == -1)
		return -1;
	MPA_UNMARSHAL(&mpa, n);
	if (!MPA_SYNC_VALID(&mpa)) {
		gint64 offset;
		size_t count;

		offset = file_tell(wth->fh);
		if (offset == -1)
			return -1;
		count = mpeg_resync(wth, err, err_info);
		if (count == 0)
			return 0;
		if (file_seek(wth->fh, count, SEEK_CUR, err) == -1)
			return -1;
		if (mpeg_read_header(wth, err, err_info, &n) == -1)
			return 0;
		MPA_UNMARSHAL(&mpa, n);
		if (!MPA_SYNC_VALID(&mpa))
			return 0;
		if (file_seek(wth->fh, offset, SEEK_SET, err) == -1)
			return -1;
	}

	wth->file_type = WTAP_FILE_MPEG;
	wth->file_encap = WTAP_ENCAP_MPEG;
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
	wth->subtype_read = mpeg_read;
	wth->subtype_seek_read = mpeg_seek_read;
	wth->subtype_close = mpeg_close;
	wth->snapshot_length = 0;
	return 1;
}
