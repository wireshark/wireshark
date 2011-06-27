/* capture_ui_utils.c
 * Declarations of utilities for capture user interfaces
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

#ifndef __CAPTURE_UI_UTILS_H__
#define __CAPTURE_UI_UTILS_H__

#include "capture_opts.h"

/** @file
 *  GList of available capture interfaces.
 */

/**
 * Find user-specified capture device description that matches interface
 * name, if any.
 */
char *capture_dev_user_descr_find(const gchar *if_name);

/**
 * Find user-specified link-layer header type that matches interface
 * name, if any.
 */
gint capture_dev_user_linktype_find(const gchar *if_name);

/** Return as descriptive a name for an interface as we can get.
 * If the user has specified a comment, use that.  Otherwise,
 * if capture_interface_list() supplies a description, use that,
 * otherwise use the interface name.
 *
 * @param if_name The name of the interface.
 *
 * @return The descriptive name (must be g_free'd later)
 */
char *get_interface_descriptive_name(const char *if_name);

/** Build the GList of available capture interfaces.
 *
 * @param if_list An interface list from capture_interface_list().
 * @param do_hide Hide the "hidden" interfaces.
 *
 * @return A list of if_info_t structs (use free_capture_combo_list() later).
 */
GList *build_capture_combo_list(GList *if_list, gboolean do_hide);

/** Free the GList from build_capture_combo_list().
 *
 * @param combo_list the interface list from build_capture_combo_list()
 */
void free_capture_combo_list(GList *combo_list);


/** Given text that contains an interface name possibly prefixed by an
 * interface description, extract the interface name.
 *
 * @param if_text A string containing the interface description + name.
 * This is usually the data from one of the list elements returned by
 * build_capture_combo_list().
 *
 * @return The raw interface name, without description (must NOT be g_free'd later)
 */
const char *get_if_name(const char *if_text);

/** Convert plain interface name to the displayed name in the combo box.
 *
 * @param if_list The list of interfaces returned by build_capture_combo_list()
 * @param if_name The name of the interface.
 *
 * @return The descriptive name (must be g_free'd later)
 */
char *build_capture_combo_name(GList *if_list, gchar *if_name);

/** Return the interface description (after setting it if not already set)
 *
 * @param capture_opts The capture_options structure that contains the used interface
 * @param i The index of the interface
 *
 * @return A pointer to interface_opts->descr
 */
const char *get_iface_description_for_interface(capture_options *capture_opts, guint i);

#endif
