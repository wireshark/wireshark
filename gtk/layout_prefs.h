/* layout_prefs.h
 * Definitions for layout preferences window
 *
 * $Id: layout_prefs.h,v 1.1 2004/04/29 17:03:27 ulfl Exp $
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

#ifndef __LAYOUT_PREFS_H__
#define __LAYOUT_PREFS_H__

typedef enum {
    layout_unused,  /* entry currently unused */
    layout_type_5,
    layout_type_2,
    layout_type_1,
    layout_type_4,
    layout_type_3,
    layout_type_6
} layout_type_e;

typedef enum {
    layout_pane_content_none,
    layout_pane_content_plist,
    layout_pane_content_pdetails,
    layout_pane_content_pbytes
} layout_pane_content_e;


GtkWidget *layout_prefs_show(void);
void layout_prefs_fetch(GtkWidget *w);
void layout_prefs_apply(GtkWidget *w);
void layout_prefs_destroy(GtkWidget *w);

#endif
