/* i4btrace.c
 *
 * Wiretap Library
 * Copyright (c) 1999 by Bert Driehuis <driehuis@playbeing.org>
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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "i4b_trace.h"
#include "i4btrace.h"

typedef struct {
	gboolean byte_swapped;
} i4btrace_t;

static gboolean i4btrace_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean i4btrace_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static int i4b_read_rec(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info);

/*
 * Test some fields in the header to see if they make sense.
 */
#define	I4B_HDR_IS_OK(hdr) \
	(!((unsigned int)hdr.length < 3 || (unsigned int)hdr.length > 16384 || \
	    (unsigned int)hdr.unit > 4 || (unsigned int)hdr.type > 4 || \
	    (unsigned int)hdr.dir > 2 || (unsigned int)hdr.trunc > 2048))

int i4btrace_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	i4b_trace_hdr_t hdr;
	gboolean byte_swapped = FALSE;
	i4btrace_t *i4btrace;

	/* I4B trace files have no magic in the header... Sigh */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof(hdr), wth->fh);
	if (bytes_read != sizeof(hdr)) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return -1;
		return 0;
	}

	/* Silly heuristic... */
	if (!I4B_HDR_IS_OK(hdr)) {
		/*
		 * OK, try byte-swapping the header fields.
		 */
		hdr.length = GUINT32_SWAP_LE_BE(hdr.length);
		hdr.unit = GUINT32_SWAP_LE_BE(hdr.unit);
		hdr.type = GUINT32_SWAP_LE_BE(hdr.type);
		hdr.dir = GUINT32_SWAP_LE_BE(hdr.dir);
		hdr.trunc = GUINT32_SWAP_LE_BE(hdr.trunc);
		if (!I4B_HDR_IS_OK(hdr)) {
			/*
			 * It doesn't look valid in either byte order.
			 */
			return 0;
		}

		/*
		 * It looks valid byte-swapped, so assume it's a
		 * trace written in the opposite byte order.
		 */
		byte_swapped = TRUE;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return -1;

	/* Get capture start time */

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_I4BTRACE;
	i4btrace = (i4btrace_t *)g_malloc(sizeof(i4btrace_t));
	wth->priv = (void *)i4btrace;
	wth->subtype_read = i4btrace_read;
	wth->subtype_seek_read = i4btrace_seek_read;
	wth->snapshot_length = 0;	/* not known */

	i4btrace->byte_swapped = byte_swapped;

	wth->file_encap = WTAP_ENCAP_ISDN;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1;
}

/* Read the next packet */
static gboolean i4btrace_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return i4b_read_rec(wth, wth->fh, &wth->phdr, wth->frame_buffer,
	    err, err_info);
}

static gboolean
i4btrace_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!i4b_read_rec(wth, wth->random_fh, phdr, buf, err, err_info)) {
		/* Read error or EOF */
		if (*err == 0) {
			/* EOF means "short read" in random-access mode */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}
	return TRUE;
}

static gboolean
i4b_read_rec(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
	i4btrace_t *i4btrace = (i4btrace_t *)wth->priv;
	i4b_trace_hdr_t hdr;
	int	bytes_read;
	guint32 length;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(fh, err_info);
		if (*err == 0 && bytes_read != 0) {
			/* Read something, but not enough */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	if (i4btrace->byte_swapped) {
		/*
		 * Byte-swap the header.
		 */
		hdr.length = GUINT32_SWAP_LE_BE(hdr.length);
		hdr.unit = GUINT32_SWAP_LE_BE(hdr.unit);
		hdr.type = GUINT32_SWAP_LE_BE(hdr.type);
		hdr.dir = GUINT32_SWAP_LE_BE(hdr.dir);
		hdr.trunc = GUINT32_SWAP_LE_BE(hdr.trunc);
		hdr.count = GUINT32_SWAP_LE_BE(hdr.count);
		hdr.ts_sec = GUINT32_SWAP_LE_BE(hdr.ts_sec);
		hdr.ts_usec = GUINT32_SWAP_LE_BE(hdr.ts_usec);
	}

	if (hdr.length < sizeof(hdr)) {
		*err = WTAP_ERR_BAD_FILE;	/* record length < header! */
		*err_info = g_strdup_printf("i4btrace: record length %u < header length %lu",
		    hdr.length, (unsigned long)sizeof(hdr));
		return FALSE;
	}
	length = hdr.length - (guint32)sizeof(hdr);
	if (length > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("i4btrace: File has %u-byte packet, bigger than maximum of %u",
		    length, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = WTAP_HAS_TS;

	phdr->len = length;
	phdr->caplen = length;

	phdr->ts.secs = hdr.ts_sec;
	phdr->ts.nsecs = hdr.ts_usec * 1000;

	switch (hdr.type) {

	case TRC_CH_I:
		/*
		 * XXX - what is it?  It's probably not WTAP_ENCAP_NULL,
		 * as that means it has a 4-byte AF_ type as the
		 * encapsulation header.
		 */
		phdr->pkt_encap = WTAP_ENCAP_NULL;
		break;

	case TRC_CH_D:
		/*
		 * D channel, so it's LAPD; set "p2p.sent".
		 */
		phdr->pkt_encap = WTAP_ENCAP_ISDN;
		phdr->pseudo_header.isdn.channel = 0;
		break;

	case TRC_CH_B1:
		/*
		 * B channel 1.
		 */
		phdr->pkt_encap = WTAP_ENCAP_ISDN;
		phdr->pseudo_header.isdn.channel = 1;
		break;

	case TRC_CH_B2:
		/*
		 * B channel 2.
		 */
		phdr->pkt_encap = WTAP_ENCAP_ISDN;
		phdr->pseudo_header.isdn.channel = 2;
		break;
	}

	phdr->pseudo_header.isdn.uton = (hdr.dir == FROM_TE);

	/*
	 * Read the packet data.
	 */
	return wtap_read_packet_bytes(fh, buf, length, err, err_info);
}
