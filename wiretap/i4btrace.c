/* i4btrace.c
 *
 * Wiretap Library
 * Copyright (c) 1999 by Bert Driehuis <driehuis@playbeing.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "i4b_trace.h"
#include "i4btrace.h"

typedef struct {
	gboolean byte_swapped;
} i4btrace_t;

static gboolean i4btrace_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *offset);
static gboolean i4btrace_seek_read(wtap *wth, gint64 seek_off,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static int i4b_read_rec(wtap *wth, FILE_T fh, wtap_rec *rec,
    Buffer *buf, int *err, gchar **err_info);

/*
 * Byte-swap the header.
 */
#define I4B_BYTESWAP_HEADER(hdr) \
	{ \
		hdr.length = GUINT32_SWAP_LE_BE(hdr.length); \
		hdr.unit = GUINT32_SWAP_LE_BE(hdr.unit); \
		hdr.type = GUINT32_SWAP_LE_BE(hdr.type); \
		hdr.dir = GUINT32_SWAP_LE_BE(hdr.dir); \
		hdr.trunc = GUINT32_SWAP_LE_BE(hdr.trunc); \
		hdr.count = GUINT32_SWAP_LE_BE(hdr.count); \
		hdr.ts_sec = GUINT32_SWAP_LE_BE(hdr.ts_sec); \
		hdr.ts_usec = GUINT32_SWAP_LE_BE(hdr.ts_usec); \
	}

/*
 * Test some fields in the header to see if they make sense.
 */
#define	I4B_HDR_IS_OK(hdr) \
	(!(hdr.length < sizeof(hdr) || \
	    hdr.length > 16384 || \
	    hdr.unit > 4 || \
	    hdr.type > TRC_CH_B2 || \
	    hdr.dir > FROM_NT || \
	    hdr.trunc > 2048 || \
	    hdr.ts_usec >= 1000000))

/*
 * Number of packets to try reading.
 */
#define PACKETS_TO_CHECK	5

wtap_open_return_val i4btrace_open(wtap *wth, int *err, gchar **err_info)
{
	i4b_trace_hdr_t hdr;
	gboolean byte_swapped = FALSE;
	i4btrace_t *i4btrace;

	/* I4B trace files have no magic in the header... Sigh */
	if (!wtap_read_bytes(wth->fh, &hdr, sizeof(hdr), err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* Silly heuristic... */
	if (!I4B_HDR_IS_OK(hdr)) {
		/*
		 * OK, try byte-swapping the header fields.
		 */
		I4B_BYTESWAP_HEADER(hdr);
		if (!I4B_HDR_IS_OK(hdr)) {
			/*
			 * It doesn't look valid in either byte order.
			 */
			return WTAP_OPEN_NOT_MINE;
		}

		/*
		 * It looks valid byte-swapped, so assume it's a
		 * trace written in the opposite byte order.
		 */
		byte_swapped = TRUE;
	}

	/*
	 * Now try to read past the packet bytes; if that fails with
	 * a short read, we don't fail, so that we can report
	 * the file as a truncated I4B file.
	 */
	if (!wtap_read_bytes(wth->fh, NULL, hdr.length - (guint32)sizeof(hdr),
	    err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
	} else {
		/*
		 * Now try reading a few more packets.
		 */
		for (int i = 1; i < PACKETS_TO_CHECK; i++) {
			/*
			 * Read and check the file header; we've already
			 * decided whether this would be a byte-swapped file
			 * or not, so we swap iff we decided it was.
			 */
			if (!wtap_read_bytes_or_eof(wth->fh, &hdr, sizeof(hdr), err,
			    err_info)) {
				if (*err == 0) {
					/* EOF; no more packets to try. */
					break;
				}
				if (*err != WTAP_ERR_SHORT_READ)
					return WTAP_OPEN_ERROR;
				return WTAP_OPEN_NOT_MINE;
			}

			if (byte_swapped)
				I4B_BYTESWAP_HEADER(hdr);
			if (!I4B_HDR_IS_OK(hdr)) {
				/*
				 * It doesn't look valid.
				 */
				return WTAP_OPEN_NOT_MINE;
			}

			/*
			 * Now try to read past the packet bytes; if that
			 * fails with a short read, we don't fail, so that
			 * we can report the file as a truncated I4B file.
			 */
			if (!wtap_read_bytes(wth->fh, NULL,
			    hdr.length - (guint32)sizeof(hdr), err, err_info)) {
				if (*err != WTAP_ERR_SHORT_READ)
					return WTAP_OPEN_ERROR;

				/*
				 * Probably a truncated file, so just quit.
				 */
				break;
			}
		}
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Get capture start time */

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_I4BTRACE;
	i4btrace = (i4btrace_t *)g_malloc(sizeof(i4btrace_t));
	wth->priv = (void *)i4btrace;
	wth->subtype_read = i4btrace_read;
	wth->subtype_seek_read = i4btrace_seek_read;
	wth->snapshot_length = 0;	/* not known */

	i4btrace->byte_swapped = byte_swapped;

	wth->file_encap = WTAP_ENCAP_ISDN;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	/*
	 * Add an IDB; we don't know how many interfaces were
	 * involved, so we just say one interface, about which
	 * we only know the link-layer type, snapshot length,
	 * and time stamp resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

/* Read the next packet */
static gboolean i4btrace_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info, gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return i4b_read_rec(wth, wth->fh, rec, buf, err, err_info);
}

static gboolean
i4btrace_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec,
    Buffer *buf, int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!i4b_read_rec(wth, wth->random_fh, rec, buf, err, err_info)) {
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
i4b_read_rec(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info)
{
	i4btrace_t *i4btrace = (i4btrace_t *)wth->priv;
	i4b_trace_hdr_t hdr;
	guint32 length;

	if (!wtap_read_bytes_or_eof(fh, &hdr, sizeof hdr, err, err_info))
		return FALSE;

	if (i4btrace->byte_swapped) {
		/*
		 * Byte-swap the header.
		 */
		I4B_BYTESWAP_HEADER(hdr);
	}

	if (hdr.length < sizeof(hdr)) {
		*err = WTAP_ERR_BAD_FILE;	/* record length < header! */
		*err_info = g_strdup_printf("i4btrace: record length %u < header length %lu",
		    hdr.length, (unsigned long)sizeof(hdr));
		return FALSE;
	}
	length = hdr.length - (guint32)sizeof(hdr);
	if (length > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("i4btrace: File has %u-byte packet, bigger than maximum of %u",
		    length, WTAP_MAX_PACKET_SIZE_STANDARD);
		return FALSE;
	}

	rec->rec_type = REC_TYPE_PACKET;
	rec->presence_flags = WTAP_HAS_TS;

	rec->rec_header.packet_header.len = length;
	rec->rec_header.packet_header.caplen = length;

	rec->ts.secs = hdr.ts_sec;
	rec->ts.nsecs = hdr.ts_usec * 1000;

	switch (hdr.type) {

	case TRC_CH_I:
		/*
		 * XXX - what is it?  It's probably not WTAP_ENCAP_NULL,
		 * as that means it has a 4-byte AF_ type as the
		 * encapsulation header.
		 */
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NULL;
		break;

	case TRC_CH_D:
		/*
		 * D channel, so it's LAPD; set "p2p.sent".
		 */
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ISDN;
		rec->rec_header.packet_header.pseudo_header.isdn.channel = 0;
		break;

	case TRC_CH_B1:
		/*
		 * B channel 1.
		 */
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ISDN;
		rec->rec_header.packet_header.pseudo_header.isdn.channel = 1;
		break;

	case TRC_CH_B2:
		/*
		 * B channel 2.
		 */
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ISDN;
		rec->rec_header.packet_header.pseudo_header.isdn.channel = 2;
		break;
	}

	rec->rec_header.packet_header.pseudo_header.isdn.uton = (hdr.dir == FROM_TE);

	/*
	 * Read the packet data.
	 */
	return wtap_read_packet_bytes(fh, buf, length, err, err_info);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
