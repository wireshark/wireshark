/* print_stream.h
 * Definitions for print streams.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef __PRINT_STREAM_H__
#define __PRINT_STREAM_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Print stream code; this provides a "print stream" class with subclasses
 * of various sorts.  Additional subclasses might be implemented elsewhere.
 */
struct print_stream;

typedef struct print_stream_ops {
	gboolean (*print_preamble)(struct print_stream *self, gchar *filename, const char *version_string);
	gboolean (*print_line)(struct print_stream *self, int indent,
	    const char *line);
	gboolean (*print_bookmark)(struct print_stream *self,
	    const gchar *name, const gchar *title);
	gboolean (*new_page)(struct print_stream *self);
	gboolean (*print_finale)(struct print_stream *self);
	gboolean (*destroy)(struct print_stream *self);
} print_stream_ops_t;

typedef struct print_stream {
	const print_stream_ops_t *ops;
	gboolean isatty;
	const char *to_codeset;
	void *data;
} print_stream_t;

WS_DLL_PUBLIC print_stream_t *print_stream_text_new(gboolean to_file, const char *dest);
WS_DLL_PUBLIC print_stream_t *print_stream_text_stdio_new(FILE *fh);
WS_DLL_PUBLIC print_stream_t *print_stream_ps_new(gboolean to_file, const char *dest);
WS_DLL_PUBLIC print_stream_t *print_stream_ps_stdio_new(FILE *fh);

WS_DLL_PUBLIC gboolean print_preamble(print_stream_t *self, gchar *filename, const char *version_string);
WS_DLL_PUBLIC gboolean print_line(print_stream_t *self, int indent, const char *line);
WS_DLL_PUBLIC gboolean print_bookmark(print_stream_t *self, const gchar *name,
    const gchar *title);
WS_DLL_PUBLIC gboolean new_page(print_stream_t *self);
WS_DLL_PUBLIC gboolean print_finale(print_stream_t *self);
WS_DLL_PUBLIC gboolean destroy_print_stream(print_stream_t *self);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* print_stream.h */
