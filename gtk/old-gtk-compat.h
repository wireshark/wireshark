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
#	define gtk_adjustment_get_lower(adj) (adj)->lower
#	define gtk_adjustment_set_step_increment(adj, val) (adj)->step_increment = val
#	define gtk_adjustment_set_page_increment(adj, val) (adj)->page_increment = val
#	define gtk_adjustment_get_page_increment(adj) (adj)->page_increment
#	define gtk_adjustment_set_page_size(adj, val) (adj)->page_size = val
#	define gtk_adjustment_get_page_size(adj) (adj)->page_size
#	define gtk_dialog_get_content_area(GTK_DIALOG(dialog)) (dialog)->vbox 
#endif

#if !GTK_CHECK_VERSION (2, 16, 0)
#	define GTK_ORIENTABLE(x) GTK_TOOLBAR(x)
#	define gtk_orientable_set_orientation(x,y) gtk_toolbar_set_orientation(x,y)
#endif

#if !GTK_CHECK_VERSION (2, 18, 0)
#	define gtk_widget_get_has_window(x) (!GTK_WIDGET_NO_WINDOW(x))
#	define gtk_widget_get_visible(x) GTK_WIDGET_VISIBLE(x)
#	define gtk_widget_get_state(x) GTK_WIDGET_STATE(x)
#	define gtk_widget_get_allocation(x,y) (*(y) = x->allocation)
#endif

#if !GTK_CHECK_VERSION (2, 20, 0)
#	define gtk_widget_get_sensitive(x) GTK_WIDGET_SENSITIVE(x)
#	define gtk_widget_get_realized(x) GTK_WIDGET_REALIZED(x)
#endif

#if !GTK_CHECK_VERSION (2, 22, 0)
#endif

#if !GTK_CHECK_VERSION (2, 24, 0)
#	define GTK_COMBO_BOX_TEXT(x) GTK_COMBO_BOX(x)
#	define gtk_combo_box_text_get_active_text(x) gtk_combo_box_get_active_text(x)
#	define gtk_combo_box_text_new() gtk_combo_box_new_text()
#	define gtk_combo_box_text_insert_text(x,y,z) gtk_combo_box_insert_text(x,y,z)
#	define gtk_combo_box_text_append_text(x,y) gtk_combo_box_append_text(x,y)
#	define gtk_combo_box_text_remove(x,y) gtk_combo_box_remove_text(x,y)
#	define gtk_combo_box_text_new_with_entry() gtk_combo_box_entry_new_text()
#	define gtk_combo_box_text_prepend_text(x,y) gtk_combo_box_prepend_text(x,y)
#endif

#if !GTK_CHECK_VERSION (3, 0, 0)
#	define gtk_widget_get_preferred_size(x,y,z) gtk_widget_size_request(x,y)
#	define GtkStyleContext GtkStyle
#	define gtk_widget_get_style_context(x) gtk_widget_get_style(x)
#	define gtk_style_context_get_color(x,y,z) gdkcolor_to_color_t(&z, &x->text[y])
#	define gtk_style_context_get_color_background(x,y,z) gdkcolor_to_color_t(&z, &x->base[y])
#	define gtk_tree_view_column_get_button(x) x->button
#endif

#endif
