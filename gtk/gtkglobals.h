/* gtkglobals.h
 * GTK-related Global defines, etc.
 *
 * $Id: gtkglobals.h,v 1.14 2001/04/10 12:07:39 gram Exp $
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

extern GtkWidget   *top_level, *packet_list, *tree_view,
            *byte_nb_ptr, *info_bar;
extern GdkFont     *m_r_font, *m_b_font;
extern guint m_font_height, m_font_width;

extern GtkStyle *item_style;
void set_scrollbar_placement_scrollw(GtkWidget *, int); /* 0=left, 1=right */
void set_scrollbar_placement_all(int); /* 1=right, 0=left */
void remember_scrolled_window(GtkWidget *);


void set_plist_sel_browse(gboolean);
void set_plist_font(GdkFont *font);

#ifdef _WIN32
/* It appears that isprint() is not working well
 * with gtk+'s text widget. By narrowing down what
 * we print, the ascii portion of the hex display works.
 * MSVCRT's isprint() returns true on values like 0xd2,
 * which cause the GtkTextWidget to go wacko.
 *
 * This is a quick fix for the symptom, not the
 * underlying problem.
 */
#define isprint(c) (c >= 0x20 && c <= 0x7f)
#endif


#endif
