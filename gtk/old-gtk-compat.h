/* 
 * Definitions to provide some functions that are not present in older
 * GTK versions (down to 2.12.0)
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

#ifndef OLD_GTK_COMPAT_H
#define OLD_GTK_COMPAT_H

#if !GTK_CHECK_VERSION (2, 14, 0)
#	define gtk_widget_get_window(widget) (widget)->window
#	define gtk_color_selection_dialog_get_color_selection(dialog) (dialog)->colorsel
#	define gtk_selection_data_get_length(seldata) (seldata)->length
#	define gtk_selection_data_get_data(seldata) (seldata)->data
#	define gtk_adjustment_set_upper(adj, val) (adj)->upper = val
#	define gtk_adjustment_get_upper(adj) (adj)->upper
#	define gtk_adjustment_set_step_increment(adj, val) (adj)->step_increment = val
#	define gtk_adjustment_set_page_increment(adj, val) (adj)->page_increment = val
#	define gtk_adjustment_get_page_increment(adj) (adj)->page_increment
#	define gtk_adjustment_set_page_size(adj, val) (adj)->page_size = val
#	define gtk_adjustment_get_page_size(adj) (adj)->page_size
#endif

#endif
