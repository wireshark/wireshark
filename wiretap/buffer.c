/*
	buffer.c
	--------

*/


#include <stdio.h>
#include <string.h>

#include "buffer.h"

/*#define DEBUG*/
#define DEBUG_PROGRAM_NAME "buffer.c"
#include "debug.h"

/* Initializes a buffer with a certain amount of allocated space */
void buffer_init(Buffer* buffer, unsigned int space)
{
	debug("buffer_init\n");
	buffer->data = (char*)g_malloc(space);
	buffer->allocated = space;
	buffer->start = 0;
	buffer->first_free = 0;
}

/* Frees the memory used by a buffer, and the buffer struct */
void buffer_free(Buffer* buffer)
{
	debug("buffer_free\n");
	free(buffer->data);
}

/* Assures that there are 'space' bytes at the end of the used space
	so that another routine can copy directly into the buffer space. After
	doing that, the routine will also want to run
	buffer_increase_length(). */
void buffer_assure_space(Buffer* buffer, unsigned int space)
{
	unsigned int available_at_end = buffer->allocated - buffer->first_free;
	unsigned int space_used;
	int space_at_beginning;

	debug("buffer_assure_space %d bytes\n", space);
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
	buffer->data = (char*)g_realloc(buffer->data, buffer->allocated);
}

void buffer_append(Buffer* buffer, char *from, unsigned int bytes)
{
	debug("buffer_append %d bytes\n", bytes);
	buffer_assure_space(buffer, bytes);
	memcpy(buffer->data + buffer->first_free, from, bytes);
	buffer->first_free += bytes;
}

void buffer_remove_start(Buffer* buffer, unsigned int bytes)
{
	debug("buffer_remove_start %d bytes\n", bytes);
	if (buffer->start + bytes > buffer->first_free) {
		die("buffer_remove_start trying to remove %d bytes. s=%d ff=%d!\n",
			bytes, buffer->start, buffer->first_free);
	}
	buffer->start += bytes;

	if (buffer->start == buffer->first_free) {
		buffer->start = 0;
		buffer->first_free = 0;
	}
}


#ifndef SOME_FUNCTIONS_ARE_DEFINES
void buffer_increase_length(Buffer* buffer, unsigned int bytes)
{
	debug("buffer_increase_length %d bytes\n", bytes);
	buffer->first_free += bytes;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
unsigned int buffer_length(Buffer* buffer)
{
	debug("buffer_length\n");
	return buffer->first_free - buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
char* buffer_start_ptr(Buffer* buffer)
{
	debug("buffer_start_ptr\n");
	return buffer->data + buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
char* buffer_end_ptr(Buffer* buffer)
{
	debug("buffer_end_ptr\n");
	return buffer->data + buffer->first_free;
}
#endif
