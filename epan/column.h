/* column.h
 * Definitions for column handling routines
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __COLUMN_H__
#define __COLUMN_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _fmt_data {
  gchar *title;            /* title of the column */
  int fmt;                 /* format of column */
  gchar *custom_field;     /* field name for COL_CUSTOM */
  gint custom_occurrence;  /* optional ordinal of occurrence of that field */
  gboolean visible;        /* if FALSE, hide this column */
  gboolean resolved;       /* if TRUE, show a more human-readable name */
} fmt_data;

const gchar         *col_format_to_string(const gint);
const gchar         *col_format_desc(const gint);
gint                 get_column_format(const gint);
void                 set_column_format(const gint, const gint);
void                 get_column_format_matches(gboolean *, const gint);
gint                 get_column_format_from_str(const gchar *);
gchar               *get_column_title(const gint);
void                 set_column_title(const gint, const gchar *);
gboolean             get_column_visible(const gint);
void                 set_column_visible(const gint, gboolean);
gboolean             get_column_resolved(const gint);
void                 set_column_resolved(const gint, gboolean);
const gchar         *get_column_custom_field(const gint);
void                 set_column_custom_field(const gint, const char *);
gint                 get_column_custom_occurrence(const gint);
void                 set_column_custom_occurrence(const gint, const gint);
const gchar         *get_column_width_string(const gint, const gint);
const char          *get_column_longest_string(const gint);
gint                 get_column_char_width(const gint format);

void
build_column_format_array(column_info *cinfo, const gint num_cols, const gboolean reset_fences);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* column.h */
