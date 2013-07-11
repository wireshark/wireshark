/* frame_tvbuff.c
 * Implements a tvbuff for frame
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/tvbuff-int.h>
#include <epan/tvbuff.h>

#include "frame_tvbuff.h"

/* XXX, to read data with wtap_seek_read() we need: 
 *    cf->wth, fdata->file_off, fdata->cap_len 
 *    add when ready to structure below
 */

struct tvb_frame {
	struct tvbuff tvb;
};

static gsize
frame_sizeof(void)
{ 
	return sizeof(struct tvb_frame); 
}

static guint
frame_offset(const tvbuff_t *tvb _U_, const guint counter)
{
	return counter;
}

static const struct tvb_ops tvb_frame_ops = {
	frame_sizeof,         /* size */
	NULL,                 /* free */
	frame_offset,         /* offset */
	NULL,                 /* get_ptr */
	NULL,                 /* memcpy */
	NULL,                 /* find_guint8 */
	NULL,                 /* pbrk_guint8 */
};

/* based on tvb_new_real_data() */
tvbuff_t *
frame_tvbuff_new(const frame_data *fd, const guint8 *buf)
{
	tvbuff_t *tvb;

	tvb = tvb_new(&tvb_frame_ops);

	/*
	 * XXX - currently, the length arguments in
	 * tvbuff structure are signed, but the captured
	 * and reported length values are unsigned; this means
	 * that length values > 2^31 - 1 will appear as
	 * negative lengths
	 *
	 * Captured length values that large will already
	 * have been filtered out by the Wiretap modules
	 * (the file will be reported as corrupted), to
	 * avoid trying to allocate large chunks of data.
	 *
	 * Reported length values will not have been
	 * filtered out, and should not be filtered out,
	 * as those lengths are not necessarily invalid.
	 *
	 * For now, we clip the reported length at G_MAXINT
	 *
	 * (XXX, is this still a problem?) There was an exception when we call 
	 * tvb_new_real_data() now there's no one
	 */

	tvb->real_data       = buf;
	tvb->length          = fd->cap_len;
	tvb->reported_length = fd->pkt_len > G_MAXINT ? G_MAXINT : fd->pkt_len;
	tvb->initialized     = TRUE;

	/*
	 * This is the top-level real tvbuff for this data source,
	 * so its data source tvbuff is itself.
	 */
	tvb->ds_tvb = tvb;

	return tvb;
}

tvbuff_t *
frame_tvbuff_new_buffer(const frame_data *fd, Buffer *buf)
{
	return frame_tvbuff_new(fd, buffer_start_ptr(buf));
}
