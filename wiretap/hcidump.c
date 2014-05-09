/* hcidump.c
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

#include "wftap-int.h"
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

static gboolean hcidump_process_packet(FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
	struct dump_hdr dh;
	int bytes_read, packet_size;

	bytes_read = file_read(&dh, DUMP_HDR_SIZE, fh);
	if (bytes_read != DUMP_HDR_SIZE) {
		*err = file_error(fh, err_info);
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

	phdr->presence_flags = WTAP_HAS_TS;
	phdr->ts.secs = GUINT32_FROM_LE(dh.ts_sec);
	phdr->ts.nsecs = GUINT32_FROM_LE(dh.ts_usec) * 1000;
	phdr->caplen = packet_size;
	phdr->len = packet_size;

	phdr->pseudo_header.p2p.sent = (dh.in ? FALSE : TRUE);

	return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

static gboolean hcidump_read(wftap *wfth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	wtap* wth = (wtap*)wfth->tap_specific_data;
	*data_offset = file_tell(wfth->fh);

	return hcidump_process_packet(wfth->fh, &wth->phdr, wfth->frame_buffer,
	    err, err_info);
}

static gboolean hcidump_seek_read(wftap *wfth, gint64 seek_off,
    void* header, Buffer *buf, int *err, gchar **err_info)
{
	struct wtap_pkthdr *phdr = (struct wtap_pkthdr *)header;
	if (file_seek(wfth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	return hcidump_process_packet(wfth->random_fh, phdr, buf, err, err_info);
}

int hcidump_open(wftap *wfth, int *err, gchar **err_info)
{
	struct dump_hdr dh;
	guint8 type;
	int bytes_read;

	bytes_read = file_read(&dh, DUMP_HDR_SIZE, wfth->fh);
	if (bytes_read != DUMP_HDR_SIZE) {
		*err = file_error(wfth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return -1;
		return 0;
	}

	if ((dh.in != 0 && dh.in != 1) || dh.pad != 0
	    || GUINT16_FROM_LE(dh.len) < 1)
		return 0;

	bytes_read = file_read(&type, 1, wfth->fh);
	if (bytes_read != 1) {
		*err = file_error(wfth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return -1;
		return 0;
	}

	if (type < 1 || type > 4)
		return 0;

	if (file_seek(wfth->fh, 0, SEEK_SET, err) == -1)
		return -1;

	wfth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_HCIDUMP;
	wfth->file_encap = WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
	wfth->snapshot_length = 0;

	wfth->subtype_read = hcidump_read;
	wfth->subtype_seek_read = hcidump_seek_read;
	wfth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1;
}
