/* gtkglobals.h
 * GTK-related Global defines, etc.
 *
 * $Id: gtkglobals.h,v 1.23 2003/12/24 01:21:32 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __GTKGLOBALS_H__
#define __GTKGLOBALS_H__

extern GtkWidget *top_level, *packet_list, *tree_view, *byte_nb_ptr;
#if GTK_MAJOR_VERSION < 2
extern GdkFont   *m_r_font, *m_b_font;
extern guint      m_font_height, m_font_width;

extern GtkStyle  *item_style;

void set_plist_font(GdkFont *font);
#else
extern PangoFontDescription *m_r_font, *m_b_font;

void set_plist_font(PangoFontDescription *font);
#endif
void set_plist_sel_browse(gboolean);

#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
/*
 * XXX - "isprint()" can return "true" for non-ASCII characters, but
 * those don't work with GTK+ 1.3 or later, as they take UTF-8 strings
 * as input.  Until we fix up Ethereal to properly handle non-ASCII
 * characters in all output (both GUI displays and text printouts)
 * in those versions of GTK+, we work around the problem by escaping
 * all characters that aren't printable ASCII.
 */
#undef isprint
#define isprint(c) (c >= 0x20 && c < 0x7f)
#endif

#endif
