/* buffer.h
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

#ifndef __W_BUFFER_H__
#define __W_BUFFER_H__

#include <glib.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SOME_FUNCTIONS_ARE_DEFINES

typedef struct Buffer {
	guint8	*data;
	gsize	allocated;
	gsize	start;
	gsize	first_free;
} Buffer;

WS_DLL_PUBLIC
void ws_buffer_init(Buffer* buffer, gsize space);
WS_DLL_PUBLIC
void ws_buffer_free(Buffer* buffer);
WS_DLL_PUBLIC
void ws_buffer_assure_space(Buffer* buffer, gsize space);
WS_DLL_PUBLIC
void ws_buffer_append(Buffer* buffer, guint8 *from, gsize bytes);
WS_DLL_PUBLIC
void ws_buffer_remove_start(Buffer* buffer, gsize bytes);

#ifdef SOME_FUNCTIONS_ARE_DEFINES
# define ws_buffer_clean(buffer) ws_buffer_remove_start((buffer), ws_buffer_length(buffer))
# define ws_buffer_increase_length(buffer,bytes) (buffer)->first_free += (bytes)
# define ws_buffer_length(buffer) ((buffer)->first_free - (buffer)->start)
# define ws_buffer_start_ptr(buffer) ((buffer)->data + (buffer)->start)
# define ws_buffer_end_ptr(buffer) ((buffer)->data + (buffer)->first_free)
# define ws_buffer_append_buffer(buffer,src_buffer) ws_buffer_append((buffer), ws_buffer_start_ptr(src_buffer), ws_buffer_length(src_buffer))
#else
 void ws_buffer_clean(Buffer* buffer);
 void ws_buffer_increase_length(Buffer* buffer, unsigned int bytes);
 unsigned int ws_buffer_length(Buffer* buffer);
 guint8* ws_buffer_start_ptr(Buffer* buffer);
 guint8* ws_buffer_end_ptr(Buffer* buffer);
 void ws_buffer_append_buffer(Buffer* buffer, Buffer* src_buffer);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
