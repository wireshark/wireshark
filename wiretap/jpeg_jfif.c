/* jpeg_jfif.c
 *
 * JPEG/JFIF file format decoder for the Wiretap library.
 * Written by Marton Nemeth <nm127@freemail.hu>
 * Copyright 2009 Marton Nemeth
 *
 * $Id$
 *
 * The JPEG and JFIF specification can be found at:
 * http://www.jpeg.org/public/jfif.pdf
 * http://www.w3.org/Graphics/JPEG/itu-t81.pdf
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "jpeg_jfif.h"

static const guchar jpeg_jfif_magic[] = { 0xFF, 0xD8, /* SOF */
					  0xFF        /* start of the next marker */
					};

static gboolean
jpeg_jfif_read(wtap *wth, int *err, gchar **err_info,
		gint64 *data_offset)
{
	guint8 *buf;
	gint64 file_size;
	int packet_size;
	gint64 capture_size;

	*err = 0;

	/* interpret the file as one packet only */
	if (wth->data_offset)
		return FALSE;

	*data_offset = wth->data_offset;

	if ((file_size = wtap_file_size(wth, err)) == -1)
		return FALSE;

	/* Read maximum possible packet size */
	if (file_size <= WTAP_MAX_PACKET_SIZE) {
		capture_size = file_size;
	} else {
		capture_size = WTAP_MAX_PACKET_SIZE;
	}
	packet_size = (int)capture_size;

	buffer_assure_space(wth->frame_buffer, packet_size);
	buf = buffer_start_ptr(wth->frame_buffer);

	wtap_file_read_expected_bytes(buf, packet_size, wth->fh, err, err_info);

	wth->data_offset += packet_size;

	wth->phdr.caplen = packet_size;
	wth->phdr.len = (int)file_size;

	wth->phdr.ts.secs = 0;
	wth->phdr.ts.nsecs = 0;

	*err_info = NULL;
	return TRUE;
}

static gboolean
jpeg_jfif_seek_read(wtap *wth, gint64 seek_off,
		union wtap_pseudo_header *pseudo_header _U_, guchar *pd, int length,
		int *err, gchar **err_info)
{
	int packet_size = length;

	/* interpret the file as one packet only */
	if (0 < seek_off) {
		*err = 0;
		*err_info = NULL;
		return FALSE;
	}

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
		*err_info = NULL;
		return FALSE;
	}

	wtap_file_read_expected_bytes(pd, packet_size, wth->random_fh, err,
	    err_info);

	*err = 0;
	*err_info = NULL;
	return TRUE;
}

int
jpeg_jfif_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic_buf[3];
	int ret = 0;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic_buf, sizeof(magic_buf), wth->fh);
	if (bytes_read != (int) sizeof(magic_buf)) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0) {
			*err_info = NULL;
			ret = -1;
		}
	} else {
		if (memcmp(magic_buf, jpeg_jfif_magic, sizeof(magic_buf)) == 0) {
			ret = 1;

			wth->file_type = WTAP_FILE_JPEG_JFIF;
			wth->file_encap = WTAP_ENCAP_JPEG_JFIF;
			wth->tsprecision = WTAP_FILE_TSPREC_SEC;
			wth->subtype_read = jpeg_jfif_read;
			wth->subtype_seek_read = jpeg_jfif_seek_read;
			wth->snapshot_length = 0;
		}
	}

	/* Seek to the start of the file */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
		*err = -1;
		*err_info = NULL;
		ret = -1;
	}

	return ret;
}
