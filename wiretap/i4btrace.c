/* i4btrace.c
 *
 * $Id: i4btrace.c,v 1.14 2001/03/10 06:33:57 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "i4b_trace.h"

static gboolean i4btrace_read(wtap *wth, int *err, int *data_offset);
static int i4btrace_seek_read(wtap *wth, int seek_off,
    union wtap_pseudo_header *pseudo_header, u_char *pd, int length);
static int i4b_read_rec_header(FILE_T fh, i4b_trace_hdr_t *hdr, int *err);
static void i4b_byte_swap_header(wtap *wth, i4b_trace_hdr_t *hdr);
static int i4b_read_rec_data(FILE_T fh, u_char *pd, int length, int *err);
static void i4b_set_pseudo_header(wtap *wth, i4b_trace_hdr_t *hdr,
    union wtap_pseudo_header *pseudo_header);

/*
 * Test some fields in the header to see if they make sense.
 */
#define	I4B_HDR_IS_OK(hdr) \
	(!((unsigned)hdr.length < 3 || (unsigned)hdr.unit > 4 || \
	    (unsigned)hdr.type > 4 || (unsigned)hdr.dir > 2 || \
	    (unsigned)hdr.trunc > 2048))

int i4btrace_open(wtap *wth, int *err)
{
	int bytes_read;
	i4b_trace_hdr_t hdr;
	gboolean byte_swapped = FALSE;

	/* I4B trace files have no magic in the header... Sigh */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof(hdr), wth->fh);
	if (bytes_read != sizeof(hdr)) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* Silly heuristic... */
	if (!I4B_HDR_IS_OK(hdr)) {
		/*
		 * OK, try byte-swapping the header fields.
		 */
		hdr.length = BSWAP32(hdr.length);
		hdr.unit = BSWAP32(hdr.unit);
		hdr.type = BSWAP32(hdr.type);
		hdr.dir = BSWAP32(hdr.dir);
		hdr.trunc = BSWAP32(hdr.trunc);
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

	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;

	/* Get capture start time */

	wth->file_type = WTAP_FILE_I4BTRACE;
	wth->capture.i4btrace = g_malloc(sizeof(i4btrace_t));
	wth->subtype_read = i4btrace_read;
	wth->subtype_seek_read = i4btrace_seek_read;
	wth->snapshot_length = 2048;	/* actual length set per packet */

	wth->capture.i4btrace->bchannel_prot[0] = -1;
	wth->capture.i4btrace->bchannel_prot[1] = -1;
	wth->capture.i4btrace->byte_swapped = byte_swapped;

	wth->file_encap = WTAP_ENCAP_PER_PACKET;

	return 1;
}

#define V120SABME	"\010\001\177"

/* Read the next packet */
static gboolean i4btrace_read(wtap *wth, int *err, int *data_offset)
{
	int	ret;
	i4b_trace_hdr_t hdr;
	guint16 length;
	void *bufp;
	int channel;

	/* Read record header. */
	*data_offset = wth->data_offset;
	ret = i4b_read_rec_header(wth->fh, &hdr, err);
	if (ret <= 0) {
		/* Read error or EOF */
		return FALSE;
	}
	wth->data_offset += sizeof hdr;
	i4b_byte_swap_header(wth, &hdr);
	if (hdr.length < sizeof(hdr)) {
		*err = WTAP_ERR_BAD_RECORD;	/* record length < header! */
		return FALSE;
	}
	length = hdr.length - sizeof(hdr);

	wth->phdr.len = length;
	wth->phdr.caplen = length;

	wth->phdr.ts.tv_sec = hdr.time.tv_sec;
	wth->phdr.ts.tv_usec = hdr.time.tv_usec;

	/*
	 * Read the packet data.
	 */
	buffer_assure_space(wth->frame_buffer, length);
	bufp = buffer_start_ptr(wth->frame_buffer);
	if (i4b_read_rec_data(wth->fh, bufp, length, err) < 0)
		return FALSE;	/* Read error */
	wth->data_offset += length;

	switch (hdr.type) {

	case TRC_CH_I:
		/*
		 * XXX - what is it?  It's probably not WTAP_ENCAP_NULL,
		 * as that means it has a 4-byte AF_ type as the
		 * encapsulation header.
		 */
		wth->phdr.pkt_encap = WTAP_ENCAP_NULL;
		break;

	case TRC_CH_D:
		/*
		 * D channel, so it's LAPD.
		 */
		wth->phdr.pkt_encap = WTAP_ENCAP_LAPD;
		break;

	case TRC_CH_B1:
	case TRC_CH_B2:
		/*
		 * B channel, so it could be any of a number of things.
		 */
		channel = hdr.type - TRC_CH_B1;

		if (wth->capture.i4btrace->bchannel_prot[channel] == -1) {
			/*
			 * We don't know yet whether the datastream is
			 * V.120 or not; this heuristic tries to figure
			 * that out.
			 *
			 * We cannot glean this from the Q.931 SETUP message,
			 * because no commercial V.120 implementation I've
			 * seen actually sets the V.120 protocol discriminator
			 * (that, or I'm misreading the spec badly).
			 *
			 * TODO: reset the flag to -1 (unknown) after a close
			 * on the B channel is detected.
			 */
			if (memcmp(bufp, V120SABME, 3) == 0)
			    wth->capture.i4btrace->bchannel_prot[channel] = 1;
			else
			    wth->capture.i4btrace->bchannel_prot[channel] = 0;
		}
		if (wth->capture.i4btrace->bchannel_prot[channel] == 1) {
			/*
			 * V.120.
			 */
			wth->phdr.pkt_encap = WTAP_ENCAP_V120;
		} else {
			/*
			 * Not V.120.
			 *
			 * XXX - what is it?  It's probably not
			 * WTAP_ENCAP_NULL, as that means it has a
			 * 4-byte AF_ type as the encapsulation header.
			 * If it's PPP, we should use WTAP_ENCAP_PPP here.
			 */
			wth->phdr.pkt_encap = WTAP_ENCAP_NULL;
		}
		break;
	}

	i4b_set_pseudo_header(wth, &hdr, &wth->pseudo_header);

	return TRUE;
}

static int
i4btrace_seek_read(wtap *wth, int seek_off,
    union wtap_pseudo_header *pseudo_header, u_char *pd, int length)
{
	int	ret;
	int	err;		/* XXX - return this */
	i4b_trace_hdr_t hdr;

	file_seek(wth->random_fh, seek_off, SEEK_SET);

	/* Read record header. */
	ret = i4b_read_rec_header(wth->random_fh, &hdr, &err);
	if (ret <= 0) {
		/* Read error or EOF */
		return ret;
	}
	i4b_byte_swap_header(wth, &hdr);

	i4b_set_pseudo_header(wth, &hdr, pseudo_header);

	/*
	 * Read the packet data.
	 */
	return i4b_read_rec_data(wth->random_fh, pd, length, &err);
}

static int
i4b_read_rec_header(FILE_T fh, i4b_trace_hdr_t *hdr, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(hdr, 1, sizeof *hdr, fh);
	if (bytes_read != sizeof *hdr) {
		*err = file_error(fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	return 1;
}

static void
i4b_byte_swap_header(wtap *wth, i4b_trace_hdr_t *hdr)
{
	if (wth->capture.i4btrace->byte_swapped) {
		/*
		 * Byte-swap the header.
		 */
		hdr->length = BSWAP32(hdr->length);
		hdr->unit = BSWAP32(hdr->unit);
		hdr->type = BSWAP32(hdr->type);
		hdr->dir = BSWAP32(hdr->dir);
		hdr->trunc = BSWAP32(hdr->trunc);
		hdr->count = BSWAP32(hdr->count);
		hdr->time.tv_sec = BSWAP32(hdr->time.tv_sec);
		hdr->time.tv_usec = BSWAP32(hdr->time.tv_usec);
	}
}

static int
i4b_read_rec_data(FILE_T fh, u_char *pd, int length, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, 1, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	return 0;
}

static void
i4b_set_pseudo_header(wtap *wth, i4b_trace_hdr_t *hdr,
    union wtap_pseudo_header *pseudo_header)
{
	int channel;

	switch (hdr->type) {

	case TRC_CH_D:
		/*
		 * D channel, so it's LAPD; set "p2p.sent".
		 */
		pseudo_header->p2p.sent = (hdr->dir == FROM_TE) ? TRUE : FALSE;
		break;

	case TRC_CH_B1:
	case TRC_CH_B2:
		/*
		 * B channel, so it could be any of a number of things;
		 * if it's V.120, set "x25.flags".
		 */
		channel = hdr->type - TRC_CH_B1;

		if (wth->capture.i4btrace->bchannel_prot[channel] == 1) {
			/*
			 * V.120.
			 */
			pseudo_header->x25.flags =
			    (hdr->dir == FROM_TE) ? 0x00 : 0x80;
		}
		break;
	}
}
