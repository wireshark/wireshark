/* gtkglobals.h
 * GTK-related Global defines, etc.
 *
 * $Id: gtkglobals.h,v 1.5 1999/12/30 23:02:54 gram Exp $
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

#ifndef __GTKGLOBALS_H__
#define __GTKGLOBALS_H__

#ifndef __GTK_H__
#include <gtk/gtk.h>
#endif

extern GtkWidget   *top_level, *file_sel, *packet_list, *tree_view,
            *byte_view, *prog_bar, *info_bar;
extern GdkFont     *m_r_font, *m_b_font;

extern GtkStyle *item_style;

void set_scrollbar_placement(int); /* 1=right, 0=left */
void set_plist_sel_browse(gboolean);
void set_ptree_sel_browse(gboolean);
void set_ptree_line_style(gint style);
void set_ptree_expander_style(gint style);

#endif
