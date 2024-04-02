/* buffer.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL
#include "buffer.h"

#include <stdlib.h>
#include <string.h>

#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#define SMALL_BUFFER_SIZE (2 * 1024) /* Everyone still uses 1500 byte frames, right? */
static GPtrArray *small_buffers; /* Guaranteed to be at least SMALL_BUFFER_SIZE */
/* XXX - Add medium and large buffers? */

/* Initializes a buffer with a certain amount of allocated space */
void
ws_buffer_init(Buffer* buffer, size_t space)
{
	ws_assert(buffer);
	if (G_UNLIKELY(!small_buffers)) small_buffers = g_ptr_array_sized_new(1024);

	if (space <= SMALL_BUFFER_SIZE) {
		if (small_buffers->len > 0) {
			buffer->data = (uint8_t*) g_ptr_array_remove_index(small_buffers, small_buffers->len - 1);
			ws_assert(buffer->data);
		} else {
			buffer->data = (uint8_t*)g_malloc(SMALL_BUFFER_SIZE);
		}
		buffer->allocated = SMALL_BUFFER_SIZE;
	} else {
		buffer->data = (uint8_t*)g_malloc(space);
		buffer->allocated = space;
	}
	buffer->start = 0;
	buffer->first_free = 0;
}

/* Frees the memory used by a buffer */
void
ws_buffer_free(Buffer* buffer)
{
	ws_assert(buffer);
	if (buffer->allocated == SMALL_BUFFER_SIZE) {
		ws_assert(buffer->data);
		g_ptr_array_add(small_buffers, buffer->data);
	} else {
		g_free(buffer->data);
	}
	buffer->allocated = 0;
	buffer->data = NULL;
}

/* Assures that there are 'space' bytes at the end of the used space
	so that another routine can copy directly into the buffer space. After
	doing that, the routine will also want to run
	ws_buffer_increase_length(). */
void
ws_buffer_assure_space(Buffer* buffer, size_t space)
{
	ws_assert(buffer);
	size_t available_at_end = buffer->allocated - buffer->first_free;
	size_t space_used;
	bool space_at_beginning;

	/* If we've got the space already, good! */
	if (space <= available_at_end) {
		return;
	}

	/* Maybe we don't have the space available at the end, but we would
		if we moved the used space back to the beginning of the
		allocation. The buffer could have become fragmented through lots
		of calls to ws_buffer_remove_start(). I'm using buffer->start as the
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
	buffer->data = (uint8_t*)g_realloc(buffer->data, buffer->allocated);
}

void
ws_buffer_append(Buffer* buffer, uint8_t *from, size_t bytes)
{
	ws_assert(buffer);
	ws_buffer_assure_space(buffer, bytes);
	memcpy(buffer->data + buffer->first_free, from, bytes);
	buffer->first_free += bytes;
}

void
ws_buffer_remove_start(Buffer* buffer, size_t bytes)
{
	ws_assert(buffer);
	if (buffer->start + bytes > buffer->first_free) {
		ws_error("ws_buffer_remove_start trying to remove %" PRIu64 " bytes. s=%" PRIu64 " ff=%" PRIu64 "!\n",
			(uint64_t)bytes, (uint64_t)buffer->start,
			(uint64_t)buffer->first_free);
		/** ws_error() does an abort() and thus never returns **/
	}
	buffer->start += bytes;

	if (buffer->start == buffer->first_free) {
		buffer->start = 0;
		buffer->first_free = 0;
	}
}


#ifndef SOME_FUNCTIONS_ARE_DEFINES
void
ws_buffer_clean(Buffer* buffer)
{
	ws_assert(buffer);
	ws_buffer_remove_start(buffer, ws_buffer_length(buffer));
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
void
ws_buffer_increase_length(Buffer* buffer, size_t bytes)
{
	ws_assert(buffer);
	buffer->first_free += bytes;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
size_t
ws_buffer_length(Buffer* buffer)
{
	ws_assert(buffer);
	return buffer->first_free - buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
uint8_t *
ws_buffer_start_ptr(Buffer* buffer)
{
	ws_assert(buffer);
	return buffer->data + buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
uint8_t *
ws_buffer_end_ptr(Buffer* buffer)
{
	ws_assert(buffer);
	return buffer->data + buffer->first_free;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
void
ws_buffer_append_buffer(Buffer* buffer, Buffer* src_buffer)
{
	ws_assert(buffer);
	ws_buffer_append(buffer, ws_buffer_start_ptr(src_buffer), ws_buffer_length(src_buffer));
}
#endif

void
ws_buffer_cleanup(void)
{
	if (small_buffers) {
		g_ptr_array_set_free_func(small_buffers, g_free);
		g_ptr_array_free(small_buffers, true);
		small_buffers = NULL;
	}
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
