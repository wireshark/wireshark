/** @file
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
#include <wsutil/str_util.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Print stream code; this provides a "print stream" class with subclasses
 * of various sorts.  Additional subclasses might be implemented elsewhere.
 */
struct print_stream;

typedef struct print_stream_ops {
	bool (*print_preamble)(struct print_stream *self, char *filename, const char *version_string);
	bool (*print_line)(struct print_stream *self, int indent,
	    const char *line);
	bool (*print_line_color)(struct print_stream *self, int indent, const char *line, const color_t *fg, const color_t *bg);
	bool (*print_bookmark)(struct print_stream *self,
	    const char *name, const char *title);
	bool (*new_page)(struct print_stream *self);
	bool (*print_finale)(struct print_stream *self);
	bool (*destroy)(struct print_stream *self);
} print_stream_ops_t;

typedef struct print_stream {
	const print_stream_ops_t *ops;
	void *data;
} print_stream_t;

/*
 * These return a print_stream_t * on success and NULL on failure.
 */
WS_DLL_PUBLIC print_stream_t *print_stream_text_new(bool to_file, const char *dest);
WS_DLL_PUBLIC print_stream_t *print_stream_text_stdio_new(FILE *fh);
WS_DLL_PUBLIC print_stream_t *print_stream_ps_new(bool to_file, const char *dest);
WS_DLL_PUBLIC print_stream_t *print_stream_ps_stdio_new(FILE *fh);

/*
 * These return true if the print was successful, false otherwise.
 */
WS_DLL_PUBLIC bool print_preamble(print_stream_t *self, char *filename, const char *version_string);
WS_DLL_PUBLIC bool print_line(print_stream_t *self, int indent, const char *line);

/*
 * equivalent to print_line(), but if the stream supports text coloring then
 * the output text will also be colored with the given foreground and
 * background
 */
WS_DLL_PUBLIC bool print_line_color(print_stream_t *self, int indent, const char *line, const color_t *fg, const color_t *bg);
WS_DLL_PUBLIC bool print_bookmark(print_stream_t *self, const char *name,
    const char *title);
WS_DLL_PUBLIC bool new_page(print_stream_t *self);
WS_DLL_PUBLIC bool print_finale(print_stream_t *self);
WS_DLL_PUBLIC bool destroy_print_stream(print_stream_t *self);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* print_stream.h */
