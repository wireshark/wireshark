/* print_stream.h
 * Definitions for print streams.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PRINT_STREAM_H__
#define __PRINT_STREAM_H__

#include "ws_symbol_export.h"

#include <wsutil/color.h>

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
	gboolean (*print_line_color)(struct print_stream *self, int indent, const char *line, const color_t *fg, const color_t *bg);
} print_stream_ops_t;

typedef struct print_stream {
	const print_stream_ops_t *ops;
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

/*
 * equivalent to print_line(), but if the stream supports text coloring then
 * the output text will also be colored with the given foreground and
 * background
 *
 * returns TRUE if the print was successful, FALSE otherwise
 */
WS_DLL_PUBLIC gboolean print_line_color(print_stream_t *self, int indent, const char *line, const color_t *fg, const color_t *bg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* print_stream.h */
