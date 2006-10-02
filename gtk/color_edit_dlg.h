/* color_edit_dlg.h
 * Definitions for dialog boxes for color filters
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

#ifndef __COLOR_EDIT_DLG_H__
#define __COLOR_EDIT_DLG_H__

/** @file
 *  "Colorize Edit Display" dialog box.
 *  @ingroup dialog_group
 */

extern gint	  num_of_filters;  /* number of filters being displayed */
extern gint	  row_selected;	   /* row in color_filters that is selected */

/* new color filter edit dialog */
extern void
edit_color_filter_dialog(GtkWidget *color_filters,
                         gboolean is_new_filter);

/* edit dialog wants to destroy itself */
extern void
color_delete(gint row, GtkWidget  *color_filters);

#endif /* color_edit_dlg.h */
