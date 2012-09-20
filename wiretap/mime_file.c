/* mime_file.c
 *
 * MIME file format decoder for the Wiretap library.
 *
 * This is for use with Wireshark dissectors that handle file
 * formats (e.g., because they handle a particular MIME media type).
 * It breaks the file into chunks of at most WTAP_MAX_PACKET_SIZE,
 * each of which is reported as a packet, so that files larger than
 * WTAP_MAX_PACKET_SIZE can be handled by reassembly.
 *
 * The "MIME file" dissector does the reassembly, and hands the result
 * off to heuristic dissectors to try to identify the file's contents.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

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
#include "mime_file.h"

typedef struct {
	gboolean last_packet;

} mime_file_private_t;

typedef struct {
	const guint8 *magic;
	guint magic_len;
} mime_files_t;

/*
 * Written by Marton Nemeth <nm127@freemail.hu>
 * Copyright 2009 Marton Nemeth
 * The JPEG and JFIF specification can be found at:
 *
 * http://www.jpeg.org/public/jfif.pdf
 * http://www.w3.org/Graphics/JPEG/itu-t81.pdf
 */
static const guint8 jpeg_jfif_magic[] = { 0xFF, 0xD8, /* SOF */
					  0xFF        /* start of the next marker */
					};

/* <?xml */
static const guint8 xml_magic[] = { '<', '?', 'x', 'm', 'l' };

static const mime_files_t magic_files[] = {
	{ jpeg_jfif_magic, sizeof(jpeg_jfif_magic) },
	{ xml_magic, sizeof(xml_magic) }
};

#define	N_MAGIC_TYPES	(sizeof(magic_files) / sizeof(magic_files[0]))

static gboolean
mime_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	mime_file_private_t *priv = (mime_file_private_t *) wth->priv;

	char _buf[WTAP_MAX_PACKET_SIZE];
	guint8 *buf;
	int packet_size;

	if (priv->last_packet) {
		*err = file_error(wth->fh, err_info);
		return FALSE;
	}

	wth->phdr.presence_flags = 0;

	wth->phdr.ts.secs = 0;
	wth->phdr.ts.nsecs = 0;

	*data_offset = file_tell(wth->fh);

	/* try to read max WTAP_MAX_PACKET_SIZE bytes */
	packet_size = file_read(_buf, sizeof(_buf), wth->fh);

	if (packet_size <= 0) {
		priv->last_packet = TRUE;
		/* signal error for packet-mime-encap */
		if (packet_size < 0)
			wth->phdr.ts.nsecs = 1000000000;

		wth->phdr.caplen = 0;
		wth->phdr.len = 0;
		return TRUE;
	}

	/* copy to wth frame buffer */
	buffer_assure_space(wth->frame_buffer, packet_size);
	buf = buffer_start_ptr(wth->frame_buffer);
	memcpy(buf, _buf, packet_size);

	wth->phdr.caplen = packet_size;
	wth->phdr.len = packet_size;
	return TRUE;
}

static gboolean
mime_seek_read(wtap *wth, gint64 seek_off, union wtap_pseudo_header *pseudo_header _U_, guint8 *pd, int length, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
		*err_info = NULL;
		return FALSE;
	}

	wtap_file_read_expected_bytes(pd, length, wth->random_fh, err, err_info);

	*err = 0;
	*err_info = NULL;
	return TRUE;
}

int
mime_file_open(wtap *wth, int *err, gchar **err_info)
{
	char magic_buf[128]; /* increase buffer size when needed */
	int bytes_read;
	int ret;
	guint i;

	guint read_bytes = 0;

	for (i = 0; i < N_MAGIC_TYPES; i++)
		read_bytes = MAX(read_bytes, magic_files[i].magic_len);

	read_bytes = MIN(read_bytes, sizeof(magic_buf));
	bytes_read = file_read(magic_buf, read_bytes, wth->fh);

	if (bytes_read > 0) {
		gboolean found_file = FALSE;
		/* guint file_ok; */

		for (i = 0; i < N_MAGIC_TYPES; i++) {
			if ((guint) bytes_read >= magic_files[i].magic_len && !memcmp(magic_buf, magic_files[i].magic, MIN(magic_files[i].magic_len, (guint) bytes_read))) {
				if (!found_file) {
					found_file = TRUE;
					/* file_ok = i; */
				} else
					return 0;	/* many files matched, bad file */
			}
		}

		if (!found_file)
			return 0;

		if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
			return -1;

		wth->file_type = WTAP_FILE_MIME;
		wth->file_encap = WTAP_ENCAP_MIME;
		wth->tsprecision = WTAP_FILE_TSPREC_SEC;
		wth->subtype_read = mime_read;
		wth->subtype_seek_read = mime_seek_read;
		wth->snapshot_length = 0;
		ret = 1;

		wth->priv = g_malloc0(sizeof(mime_file_private_t));

	} else {
		*err = file_error(wth->fh, err_info);
		ret = -1;
	}
	return ret;
}

