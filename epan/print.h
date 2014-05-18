/* print.h
 * Definitions for printing packet analysis trees.
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

#ifndef __PRINT_H__
#define __PRINT_H__

#include <stdio.h>

#include <epan/epan.h>
#include <epan/packet.h>

#include <epan/packet-range.h>

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

/* print output format */
typedef enum {
  PR_FMT_TEXT,    /* plain text */
  PR_FMT_PS       /* postscript */
} print_format_e;

/* print_range, enum which frames should be printed */
typedef enum {
  print_range_selected_only,    /* selected frame(s) only (currently only one) */
  print_range_marked_only,      /* marked frames only */
  print_range_all_displayed,    /* all frames currently displayed */
  print_range_all_captured      /* all frames in capture */
} print_range_e;

/* print_dissections, enum how the dissections should be printed */
typedef enum {
  print_dissections_none,         /* no dissections at all */
  print_dissections_collapsed,    /* no dissection details */
  print_dissections_as_displayed, /* details as displayed */
  print_dissections_expanded      /* all dissection details */
} print_dissections_e;

typedef struct {
  print_stream_t *stream;       /* the stream to which we're printing */
  print_format_e format;        /* plain text or PostScript */
  gboolean to_file;             /* TRUE if we're printing to a file */
  char *file;                   /* file output pathname */
  char *cmd;                    /* print command string (not win32) */
  packet_range_t range;

  gboolean print_summary;       /* TRUE if we should print summary line. */
  gboolean print_col_headings;  /* TRUE if we should print column headings */
  print_dissections_e print_dissections;
  gboolean print_hex;           /* TRUE if we should print hex data;
                                 * FALSE if we should print only if not dissected. */
  gboolean print_formfeed;      /* TRUE if a formfeed should be printed before
                                 * each new packet */
} print_args_t;

/*
 * Print user selected list of fields
 */
struct _output_fields;
typedef struct _output_fields output_fields_t;

WS_DLL_PUBLIC output_fields_t* output_fields_new(void);
WS_DLL_PUBLIC void output_fields_free(output_fields_t* info);
WS_DLL_PUBLIC void output_fields_add(output_fields_t* info, const gchar* field);
WS_DLL_PUBLIC gsize output_fields_num_fields(output_fields_t* info);
WS_DLL_PUBLIC gboolean output_fields_set_option(output_fields_t* info, gchar* option);
WS_DLL_PUBLIC void output_fields_list_options(FILE *fh);
WS_DLL_PUBLIC gboolean output_fields_has_cols(output_fields_t* info);

/*
 * Output only these protocols
 */
WS_DLL_PUBLIC GHashTable *output_only_tables;

/*
 * Higher-level packet-printing code.
 */

WS_DLL_PUBLIC gboolean proto_tree_print(print_args_t *print_args, epan_dissect_t *edt,
     print_stream_t *stream);
WS_DLL_PUBLIC gboolean print_hex_data(print_stream_t *stream, epan_dissect_t *edt);

WS_DLL_PUBLIC void write_pdml_preamble(FILE *fh, const gchar* filename);
WS_DLL_PUBLIC void proto_tree_write_pdml(epan_dissect_t *edt, FILE *fh);
WS_DLL_PUBLIC void write_pdml_finale(FILE *fh);

WS_DLL_PUBLIC void write_psml_preamble(FILE *fh);
WS_DLL_PUBLIC void proto_tree_write_psml(epan_dissect_t *edt, FILE *fh);
WS_DLL_PUBLIC void write_psml_finale(FILE *fh);

WS_DLL_PUBLIC void write_csv_preamble(FILE *fh);
WS_DLL_PUBLIC void proto_tree_write_csv(epan_dissect_t *edt, FILE *fh);
WS_DLL_PUBLIC void write_csv_finale(FILE *fh);

WS_DLL_PUBLIC void write_carrays_preamble(FILE *fh);
WS_DLL_PUBLIC void proto_tree_write_carrays(guint32 num, FILE *fh, epan_dissect_t *edt);
WS_DLL_PUBLIC void write_carrays_finale(FILE *fh);

WS_DLL_PUBLIC void write_fields_preamble(output_fields_t* fields, FILE *fh);
WS_DLL_PUBLIC void proto_tree_write_fields(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_fields_finale(output_fields_t* fields, FILE *fh);

WS_DLL_PUBLIC gchar* get_node_field_value(field_info* fi, epan_dissect_t* edt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* print.h */
