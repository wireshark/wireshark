/* packetlogger.c
 * Routines for opening Apple's (Bluetooth) PacketLogger file format captures
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on commview.c, Linux's BlueZ-Gnome Analyzer program and hexdumps of
 * the output files from Apple's PacketLogger tool.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "packetlogger.h"

typedef struct {
	gboolean little_endian;
} packetlogger_t;

typedef struct packetlogger_header {
	guint32 len;
	guint32 ts_secs;
	guint32 ts_usecs;
} packetlogger_header_t;

static gboolean packetlogger_read(wtap *wth, int *err, gchar **err_info,
				  gint64 *data_offset);
static gboolean packetlogger_seek_read(wtap *wth, gint64 seek_off,
				       struct wtap_pkthdr *phdr,
				       Buffer *buf, int *err, gchar **err_info);
static gboolean packetlogger_read_header(packetlogger_header_t *pl_hdr,
					 FILE_T fh, gboolean little_endian,
					 int *err, gchar **err_info);
static gboolean packetlogger_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
					 Buffer *buf, int *err,
					 gchar **err_info);

wtap_open_return_val packetlogger_open(wtap *wth, int *err, gchar **err_info)
{
	gboolean little_endian = FALSE;
	packetlogger_header_t pl_hdr;
	guint8 type;
	packetlogger_t *packetlogger;

	if(!packetlogger_read_header(&pl_hdr, wth->fh, little_endian,
	    err, err_info)) {
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (!wtap_read_bytes(wth->fh, &type, 1, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/*
	 * If the upper 16 bits of the length are non-zero and the lower
	 * 16 bits are zero, assume the file is little-endian.
	 */
	if ((pl_hdr.len & 0x0000FFFF) == 0 &&
	    (pl_hdr.len & 0xFFFF0000) != 0) {
		/*
		 * Byte-swap the upper 16 bits (the lower 16 bits are
		 * zero, so we don't have to look at them).
		 */
		pl_hdr.len = ((pl_hdr.len >> 24) & 0xFF) |
			     (((pl_hdr.len >> 16) & 0xFF) << 8);
		little_endian = TRUE;
	}

	/* Verify this file belongs to us */
	if (!((8 <= pl_hdr.len) && (pl_hdr.len < 65536) &&
	      (type < 0x04 || type == 0xFB || type == 0xFC || type == 0xFE || type == 0xFF)))
		return WTAP_OPEN_NOT_MINE;

	/* No file header. Reset the fh to 0 so we can read the first packet */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* This is a PacketLogger file */
	packetlogger = (packetlogger_t *)g_malloc(sizeof(packetlogger_t));
	packetlogger->little_endian = little_endian;
	wth->priv = (void *)packetlogger;

	/* Set up the pointers to the handlers for this file type */
	wth->subtype_read = packetlogger_read;
	wth->subtype_seek_read = packetlogger_seek_read;

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PACKETLOGGER;
	wth->file_encap = WTAP_ENCAP_PACKETLOGGER;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	return WTAP_OPEN_MINE; /* Our kind of file */
}

static gboolean
packetlogger_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return packetlogger_read_packet(wth, wth->fh, &wth->phdr,
	    wth->frame_buffer, err, err_info);
}

static gboolean
packetlogger_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
		       Buffer *buf, int *err, gchar **err_info)
{
	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if(!packetlogger_read_packet(wth, wth->random_fh, phdr, buf, err, err_info)) {
		if(*err == 0)
			*err = WTAP_ERR_SHORT_READ;

		return FALSE;
	}
	return TRUE;
}

static gboolean
packetlogger_read_header(packetlogger_header_t *pl_hdr, FILE_T fh,
			 gboolean little_endian, int *err, gchar **err_info)
{
	if (!wtap_read_bytes_or_eof(fh, &pl_hdr->len, 4, err, err_info))
		return FALSE;
	if (!wtap_read_bytes(fh, &pl_hdr->ts_secs, 4, err, err_info))
		return FALSE;
	if (!wtap_read_bytes(fh, &pl_hdr->ts_usecs, 4, err, err_info))
		return FALSE;

	/* Convert multi-byte values to host endian */
	if (little_endian) {
		pl_hdr->len = GUINT32_FROM_LE(pl_hdr->len);
		pl_hdr->ts_secs = GUINT32_FROM_LE(pl_hdr->ts_secs);
		pl_hdr->ts_usecs = GUINT32_FROM_LE(pl_hdr->ts_usecs);
	} else {
		pl_hdr->len = GUINT32_FROM_BE(pl_hdr->len);
		pl_hdr->ts_secs = GUINT32_FROM_BE(pl_hdr->ts_secs);
		pl_hdr->ts_usecs = GUINT32_FROM_BE(pl_hdr->ts_usecs);
	}

	return TRUE;
}

static gboolean
packetlogger_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
			 int *err, gchar **err_info)
{
	packetlogger_t *packetlogger = (packetlogger_t *)wth->priv;
	packetlogger_header_t pl_hdr;

	if(!packetlogger_read_header(&pl_hdr, fh, packetlogger->little_endian,
	    err, err_info))
		return FALSE;

	if (pl_hdr.len < 8) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("packetlogger: record length %u is too small", pl_hdr.len);
		return FALSE;
	}
	if (pl_hdr.len - 8 > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("packetlogger: File has %u-byte packet, bigger than maximum of %u",
		    pl_hdr.len - 8, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = WTAP_HAS_TS;

	phdr->len = pl_hdr.len - 8;
	phdr->caplen = pl_hdr.len - 8;

	phdr->ts.secs = (time_t)pl_hdr.ts_secs;
	phdr->ts.nsecs = (int)(pl_hdr.ts_usecs * 1000);

	return wtap_read_packet_bytes(fh, buf, phdr->caplen, err, err_info);
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
