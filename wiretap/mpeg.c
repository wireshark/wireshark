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
#include "wsutil/mpeg-audio.h"

#include "wtap-int.h"
#include "buffer.h"
#include "file_wrappers.h"
#include <errno.h>
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
	int byte = file_getc(wth->fh);

	while (byte != EOF) {
		if (byte == 0xff && count > 0) {
			byte = file_getc(wth->fh);
			if (byte != EOF && (byte & 0xe0) == 0xe0)
				break;
		} else
			byte = file_getc(wth->fh);
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

#define SCRHZ 27000000

static gboolean 
mpeg_read(wtap *wth, int *err, gchar **err_info _U_,
		gint64 *data_offset)
{
	guint32 n;
	int bytes_read = mpeg_read_header(wth, err, err_info, &n);
	unsigned packet_size;
	struct wtap_nstime ts = wth->capture.mpeg->now;

	if (bytes_read == -1)
		return FALSE;
	if (PES_VALID(n)) {
		gint64 offset = file_tell(wth->fh);
		guint8 stream;

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

					{
						guint64 bytes = pack >> 16;
						guint64 ts_val =
							(bytes >> 43 & 0x0007) << 30 |
							(bytes >> 27 & 0x7fff) << 15 |
							(bytes >> 11 & 0x7fff) << 0;
						unsigned ext = (unsigned)((bytes >> 1) & 0x1ff);
						guint64 cr = 300 * ts_val + ext;
						unsigned rem = (unsigned)(cr % SCRHZ);
						wth->capture.mpeg->now.secs
							= wth->capture.mpeg->t0 + (time_t)(cr / SCRHZ);
						wth->capture.mpeg->now.nsecs
							= (int)(G_GINT64_CONSTANT(1000000000) * rem / SCRHZ);
					}
					ts = wth->capture.mpeg->now;
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
			wth->capture.mpeg->now.nsecs += MPA_DURATION_NS(&mpa);
			if (wth->capture.mpeg->now.nsecs >= 1000000000) {
				wth->capture.mpeg->now.secs++;
				wth->capture.mpeg->now.nsecs -= 1000000000;
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
mpeg_close(wtap *wth)
{
	g_free(wth->capture.mpeg);
}

struct _mpeg_magic {
	size_t len;
	const gchar* match;
} magic[] = {
	{ 3, "TAG" }, /* ID3v1 */
	{ 3, "ID3" }, /* ID3v2 */
	{ 3, "\0\0\1" }, /* MPEG PES */
	{ 2, "\xff\xfb" }, /* MP3, taken from http://en.wikipedia.org/wiki/MP3#File_structure */
	{ 0, NULL }
};

int 
mpeg_open(wtap *wth, int *err, gchar **err_info _U_)
{
	int bytes_read;
	char magic_buf[16];
	struct _mpeg_magic* m;
	
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic_buf, 1, sizeof magic_buf, wth->fh);
	if (bytes_read != (int) sizeof magic_buf) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	for (m=magic; m->match; m++) {
		if (memcmp(magic_buf, m->match, m->len) == 0)
			goto good_magic;
	}
	
	return 0;

good_magic:
	/* This appears to be a file with MPEG data. */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return -1;

	wth->file_type = WTAP_FILE_MPEG;
	wth->file_encap = WTAP_ENCAP_MPEG;
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
	wth->subtype_read = mpeg_read;
	wth->subtype_seek_read = mpeg_seek_read;
	wth->subtype_close = mpeg_close;
	wth->snapshot_length = 0;

	wth->capture.mpeg = g_malloc(sizeof(mpeg_t));
	wth->capture.mpeg->now.secs = time(NULL);
	wth->capture.mpeg->now.nsecs = 0;
	wth->capture.mpeg->t0 = wth->capture.mpeg->now.secs;

	return 1;
}
