/* prefs.h
 * Definitions for preference handling routines
 *
 * $Id: prefs.h,v 1.12 1999/12/29 20:09:47 gram Exp $
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

#ifndef __PREFS_H__
#define __PREFS_H__

#define PR_FMT_TEXT 0
#define PR_FMT_PS   1

#define PR_DEST_CMD  0
#define PR_DEST_FILE 1

#ifndef __GTK_H__
#include <gtk/gtk.h>
#endif

typedef struct _e_prefs {
  gint     pr_format;
  gint     pr_dest;
  gchar   *pr_file;
  gchar   *pr_cmd;
  GList   *col_list;
  gint     num_cols;
  GdkColor st_client_fg, st_client_bg, st_server_fg, st_server_bg;
  gboolean	gui_scrollbar_on_right;
  gboolean	gui_plist_sel_browse;
  gboolean	gui_ptree_sel_browse;
} e_prefs;

extern e_prefs prefs;

e_prefs* read_prefs(char **);
void write_prefs(void);

#endif /* prefs.h */
