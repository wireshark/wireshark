/* buffer.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 *
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "buffer.h"

/* Initializes a buffer with a certain amount of allocated space */
void buffer_init(Buffer* buffer, gsize space)
{
	buffer->data = (guint8*)g_malloc(space);
	buffer->allocated = space;
	buffer->start = 0;
	buffer->first_free = 0;
}

/* Frees the memory used by a buffer, and the buffer struct */
void buffer_free(Buffer* buffer)
{
	g_free(buffer->data);
}

/* Assures that there are 'space' bytes at the end of the used space
	so that another routine can copy directly into the buffer space. After
	doing that, the routine will also want to run
	buffer_increase_length(). */
void buffer_assure_space(Buffer* buffer, gsize space)
{
	gsize available_at_end = buffer->allocated - buffer->first_free;
	gsize space_used;
	gboolean space_at_beginning;

	/* If we've got the space already, good! */
	if (space <= available_at_end) {
		return;
	}

	/* Maybe we don't have the space available at the end, but we would
		if we moved the used space back to the beginning of the
		allocation. The buffer could have become fragmented through lots
		of calls to buffer_remove_start(). I'm using buffer->start as the
		same as 'available_at_start' in this comparison. */

	/* or maybe there's just no more room. */

	space_at_beginning = buffer->start >= space;
	if (space_at_beginning || buffer->start > 0) {
		space_used = buffer->first_free - buffer->start;
		/* this memory copy better be safe for overlapping memory regions! */
		memmove(buffer->data, buffer->data + buffer->start, space_used);
		buffer->start = 0;
		buffer->first_free = space_used;
	}
	/*if (buffer->start >= space) {*/
	if (space_at_beginning) {
		return;
	}

	/* We'll allocate more space */
	buffer->allocated += space + 1024;
	buffer->data = (guint8*)g_realloc(buffer->data, buffer->allocated);
}

void buffer_append(Buffer* buffer, guint8 *from, gsize bytes)
{
	buffer_assure_space(buffer, bytes);
	memcpy(buffer->data + buffer->first_free, from, bytes);
	buffer->first_free += bytes;
}

void buffer_remove_start(Buffer* buffer, gsize bytes)
{
	if (buffer->start + bytes > buffer->first_free) {
		g_error("buffer_remove_start trying to remove %" G_GINT64_MODIFIER "u bytes. s=%" G_GINT64_MODIFIER "u ff=%" G_GINT64_MODIFIER "u!\n",
			(guint64)bytes, (guint64)buffer->start,
			(guint64)buffer->first_free);
		/** g_error() does an abort() and thus never returns **/
	}
	buffer->start += bytes;

	if (buffer->start == buffer->first_free) {
		buffer->start = 0;
		buffer->first_free = 0;
	}
}


#ifndef SOME_FUNCTIONS_ARE_DEFINES
void buffer_clean(Buffer* buffer)
{
	buffer_remove_start(buffer, buffer_length(buffer));
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
void buffer_increase_length(Buffer* buffer, gsize bytes)
{
	buffer->first_free += bytes;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
gsize buffer_length(Buffer* buffer)
{
	return buffer->first_free - buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
guint8* buffer_start_ptr(Buffer* buffer)
{
	return buffer->data + buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
guint8* buffer_end_ptr(Buffer* buffer)
{
	return buffer->data + buffer->first_free;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
void buffer_append_buffer(Buffer* buffer, Buffer* src_buffer)
{
	buffer_append(buffer, buffer_start_ptr(src_buffer), buffer_length(src_buffer));
}
#endif
