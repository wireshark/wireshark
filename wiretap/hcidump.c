/* hcidump.c
 *
 * $Id$
 *
 * Copyright (c) 2003 by Marcel Holtmann <marcel@holtmann.org>
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

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "hcidump.h"

struct dump_hdr {
	guint16 len;
	guint8  in;
	guint8  pad;
	guint32 ts_sec;
	guint32 ts_usec;
};

#define DUMP_HDR_SIZE (sizeof(struct dump_hdr))

static gboolean hcidump_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	struct dump_hdr dh;
	guint8 *buf;
	int bytes_read, packet_size;

	*data_offset = file_tell(wth->fh);

	bytes_read = file_read(&dh, DUMP_HDR_SIZE, wth->fh);
	if (bytes_read != DUMP_HDR_SIZE) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	packet_size = GUINT16_FROM_LE(dh.len);
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("hcidump: File has %u-byte packet, bigger than maximum of %u",
			packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	buffer_assure_space(wth->frame_buffer, packet_size);
	buf = buffer_start_ptr(wth->frame_buffer);

	bytes_read = file_read(buf, packet_size, wth->fh);
	if (bytes_read != packet_size) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	wth->phdr.presence_flags = WTAP_HAS_TS;
	wth->phdr.ts.secs = GUINT32_FROM_LE(dh.ts_sec);
	wth->phdr.ts.nsecs = GUINT32_FROM_LE(dh.ts_usec) * 1000;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = packet_size;

	wth->pseudo_header.p2p.sent = (dh.in ? FALSE : TRUE);

	return TRUE;
}

static gboolean hcidump_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	struct dump_hdr dh;
	int bytes_read;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	bytes_read = file_read(&dh, DUMP_HDR_SIZE, wth->random_fh);
	if (bytes_read != DUMP_HDR_SIZE) {
		*err = file_error(wth->random_fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	bytes_read = file_read(pd, length, wth->random_fh);
	if (bytes_read != length) {
		*err = file_error(wth->random_fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	pseudo_header->p2p.sent = (dh.in ? FALSE : TRUE);

	return TRUE;
}

int hcidump_open(wtap *wth, int *err, gchar **err_info)
{
	struct dump_hdr dh;
	guint8 type;
	int bytes_read;

	bytes_read = file_read(&dh, DUMP_HDR_SIZE, wth->fh);
	if (bytes_read != DUMP_HDR_SIZE) {
		*err = file_error(wth->fh, err_info);
		return (*err != 0) ? -1 : 0;
	}

	if ((dh.in != 0 && dh.in != 1) || dh.pad != 0
	    || GUINT16_FROM_LE(dh.len) < 1)
		return 0;

	bytes_read = file_read(&type, 1, wth->fh);
	if (bytes_read != 1) {
		*err = file_error(wth->fh, err_info);
		return (*err != 0) ? -1 : 0;
	}

	if (type < 1 || type > 4)
		return 0;

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return -1;

	wth->file_type = WTAP_FILE_HCIDUMP;
	wth->file_encap = WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
	wth->snapshot_length = 0;

	wth->subtype_read = hcidump_read;
	wth->subtype_seek_read = hcidump_seek_read;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1;
}
