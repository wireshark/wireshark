/* column.h
 * Definitions for column handling routines
 *
 * $Id: column.h,v 1.7 2000/01/10 01:43:48 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

typedef struct _fmt_data {
  gchar *title;
  gchar *fmt;
} fmt_data;

enum col_resize_type {
  RESIZE_AUTO,          /* Automatically resize */
  RESIZE_LIVE,          /* Automatically resize even during live capture */
  RESIZE_MANUAL         /* Don't automatically resize */
};

gchar               *col_format_to_string(gint);
gchar               *col_format_desc(gint);
gint                 get_column_format(gint);
void                 get_column_format_matches(gboolean *, gint);
gint                 get_column_format_from_str(gchar *);
enum col_resize_type get_column_resize_type(gint);
gchar               *get_column_title(gint);
gchar               *col_format_to_pref_str(void);
char                *get_column_longest_string(gint);
gint                 get_column_char_width(gint format);

#endif /* column.h */
