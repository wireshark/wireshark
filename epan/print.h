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

#include <epan/print_stream.h>

#include <epan/packet-range.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

typedef enum {
  FORMAT_CSV,     /* CSV */
  FORMAT_JSON,    /* JSON */
  FORMAT_EK,      /* JSON bulk insert to Elasticsearch */
  FORMAT_XML,      /* PDML output */
} fields_format;

/*
 * Print user selected list of fields
 */
struct _output_fields;
typedef struct _output_fields output_fields_t;

WS_DLL_PUBLIC output_fields_t* output_fields_new(void);
WS_DLL_PUBLIC void output_fields_free(output_fields_t* info);
WS_DLL_PUBLIC void output_fields_add(output_fields_t* info, const gchar* field);
WS_DLL_PUBLIC GSList * output_fields_valid(output_fields_t* info);
WS_DLL_PUBLIC gsize output_fields_num_fields(output_fields_t* info);
WS_DLL_PUBLIC gboolean output_fields_set_option(output_fields_t* info, gchar* option);
WS_DLL_PUBLIC void output_fields_list_options(FILE *fh);
WS_DLL_PUBLIC gboolean output_fields_has_cols(output_fields_t* info);

/*
 * Higher-level packet-printing code.
 */

WS_DLL_PUBLIC gboolean proto_tree_print(print_args_t *print_args,
                                        epan_dissect_t *edt,
                                        GHashTable *output_only_tables,
                                        print_stream_t *stream);
WS_DLL_PUBLIC gboolean print_hex_data(print_stream_t *stream, epan_dissect_t *edt);

WS_DLL_PUBLIC void write_pdml_preamble(FILE *fh, const gchar* filename);
WS_DLL_PUBLIC void write_pdml_proto_tree(output_fields_t* fields, gchar **protocolfilter, epan_dissect_t *edt, FILE *fh);
WS_DLL_PUBLIC void write_pdml_finale(FILE *fh);

WS_DLL_PUBLIC void write_json_preamble(FILE *fh);
WS_DLL_PUBLIC void write_json_proto_tree(output_fields_t* fields, print_args_t *print_args, gchar **protocolfilter, epan_dissect_t *edt, FILE *fh);
WS_DLL_PUBLIC void write_json_finale(FILE *fh);

WS_DLL_PUBLIC void write_ek_proto_tree(output_fields_t* fields, print_args_t *print_args, gchar **protocolfilter, epan_dissect_t *edt, FILE *fh);

WS_DLL_PUBLIC void write_psml_preamble(column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_psml_columns(epan_dissect_t *edt, FILE *fh);
WS_DLL_PUBLIC void write_psml_finale(FILE *fh);

WS_DLL_PUBLIC void write_csv_column_titles(column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_csv_columns(epan_dissect_t *edt, FILE *fh);

WS_DLL_PUBLIC void write_carrays_hex_data(guint32 num, FILE *fh, epan_dissect_t *edt);

WS_DLL_PUBLIC void write_fields_preamble(output_fields_t* fields, FILE *fh);
WS_DLL_PUBLIC void write_fields_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_fields_finale(output_fields_t* fields, FILE *fh);

WS_DLL_PUBLIC gchar* get_node_field_value(field_info* fi, epan_dissect_t* edt);

extern void print_cache_field_handles(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* print.h */
