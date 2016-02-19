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

#include "wtap-int.h"
#include "file_wrappers.h"
#include "hcidump.h"

struct dump_hdr {
	guint16 len;
	guint8  in;
	guint8  pad;
	guint32 ts_sec;
	guint32 ts_usec;
};

#define DUMP_HDR_SIZE (sizeof(struct dump_hdr))

static gboolean hcidump_read_packet(FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
	struct dump_hdr dh;
	int packet_size;

	if (!wtap_read_bytes_or_eof(fh, &dh, DUMP_HDR_SIZE, err, err_info))
		return FALSE;

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

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = WTAP_HAS_TS;
	phdr->ts.secs = GUINT32_FROM_LE(dh.ts_sec);
	phdr->ts.nsecs = GUINT32_FROM_LE(dh.ts_usec) * 1000;
	phdr->caplen = packet_size;
	phdr->len = packet_size;

	phdr->pseudo_header.p2p.sent = (dh.in ? FALSE : TRUE);

	return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

static gboolean hcidump_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return hcidump_read_packet(wth->fh, &wth->phdr, wth->frame_buffer,
	    err, err_info);
}

static gboolean hcidump_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	return hcidump_read_packet(wth->random_fh, phdr, buf, err, err_info);
}

wtap_open_return_val hcidump_open(wtap *wth, int *err, gchar **err_info)
{
	struct dump_hdr dh;
	guint8 type;

	if (!wtap_read_bytes(wth->fh, &dh, DUMP_HDR_SIZE, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if ((dh.in != 0 && dh.in != 1) || dh.pad != 0
	    || GUINT16_FROM_LE(dh.len) < 1)
		return WTAP_OPEN_NOT_MINE;

	if (!wtap_read_bytes(wth->fh, &type, 1, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (type < 1 || type > 4)
		return WTAP_OPEN_NOT_MINE;

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_HCIDUMP;
	wth->file_encap = WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
	wth->snapshot_length = 0;

	wth->subtype_read = hcidump_read;
	wth->subtype_seek_read = hcidump_seek_read;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	return WTAP_OPEN_MINE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
