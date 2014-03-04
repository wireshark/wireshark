/* color_edit_dlg.h
 * Definitions for dialog boxes for color filters
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

#ifndef __COLOR_EDIT_DLG_H__
#define __COLOR_EDIT_DLG_H__

/** @file
 *  "Colorize Edit Display" dialog box.
 *  @ingroup dialog_group
 */

struct _color_edit_dlg_info_t;

typedef struct _color_edit_dlg_info_t color_edit_dlg_info_t;

/* new color filter edit dialog */
extern void
color_edit_dlg_new(GtkWidget *color_filters,
                   gboolean is_new_filter);

#if 1 /* doesn't really belong here */
/* edit dialog wants to destroy itself */
extern void
color_delete_single(gint row, GtkWidget  *color_filters);
#endif

extern void
color_edit_dlg_destroy(color_edit_dlg_info_t *cedi);

#endif /* color_edit_dlg.h */
