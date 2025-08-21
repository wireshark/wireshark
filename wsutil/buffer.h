/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_BUFFER_H__
#define __W_BUFFER_H__

#include <inttypes.h>
#include <stddef.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SOME_FUNCTIONS_ARE_INLINE

typedef struct Buffer {
	uint8_t	*data;
	size_t	allocated;
	size_t	start;
	size_t	first_free;
} Buffer;

WS_DLL_PUBLIC
void ws_buffer_init(Buffer* buffer, size_t space);
WS_DLL_PUBLIC
void ws_buffer_free(Buffer* buffer);
WS_DLL_PUBLIC
void ws_buffer_assure_space(Buffer* buffer, size_t space);
WS_DLL_PUBLIC
void ws_buffer_append(Buffer* buffer, const uint8_t *from, size_t bytes);
WS_DLL_PUBLIC
void ws_buffer_remove_start(Buffer* buffer, size_t bytes);
WS_DLL_PUBLIC
void ws_buffer_cleanup(void);

#ifdef SOME_FUNCTIONS_ARE_INLINE
/* Or inlines */
static inline void
ws_buffer_clean(Buffer *buffer)
{
	buffer->start = 0;
	buffer->first_free = 0;
}

static inline void
ws_buffer_increase_length(Buffer* buffer, size_t bytes)
{
	buffer->first_free += bytes;
}

static inline size_t
ws_buffer_length(const Buffer* buffer)
{
	return buffer->first_free - buffer->start;
}

static inline uint8_t *
ws_buffer_start_ptr(const Buffer* buffer)
{
	return buffer->data + buffer->start;
}

static inline uint8_t *
ws_buffer_end_ptr(const Buffer* buffer)
{
	return buffer->data + buffer->first_free;
}

static inline void
ws_buffer_append_buffer(Buffer* buffer, const Buffer* src_buffer)
{
	ws_buffer_append(buffer, ws_buffer_start_ptr(src_buffer), ws_buffer_length(src_buffer));
}
#else
 WS_DLL_PUBLIC
 void ws_buffer_clean(Buffer* buffer);
 WS_DLL_PUBLIC
 void ws_buffer_increase_length(Buffer* buffer, size_t bytes);
 WS_DLL_PUBLIC
 size_t ws_buffer_length(const Buffer* buffer);
 WS_DLL_PUBLIC
 uint8_t* ws_buffer_start_ptr(const Buffer* buffer);
 WS_DLL_PUBLIC
 uint8_t* ws_buffer_end_ptr(const Buffer* buffer);
 WS_DLL_PUBLIC
 void ws_buffer_append_buffer(Buffer* buffer, const Buffer* src_buffer);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
