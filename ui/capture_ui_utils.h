/* capture_ui_utils.c
 * Declarations of utilities for capture user interfaces
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

#ifndef __CAPTURE_UI_UTILS_H__
#define __CAPTURE_UI_UTILS_H__

#include "capture_opts.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  GList of available capture interfaces.
 */

/**
 * Find user-specified capture device description that matches interface
 * name, if any.
 *
 * @param if_name The name of the interface.
 *
 * @return The device description (must be g_free'd later) or NULL
 * if not found.
 */
char *capture_dev_user_descr_find(const gchar *if_name);

/**
 * Find user-specified link-layer header type that matches interface
 * name, if any.
 *
 * @param if_name The name of the interface.
 *
 * @return The link-layer header type (a DLT_) or -1 if not found.
 */
gint capture_dev_user_linktype_find(const gchar *if_name);

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
/**
 * Find user-specified buffer size that matches interface
 * name, if any.
 *
 * @param if_name The name of the interface.
 *
 * @return The buffer size or -1 if not found.
 */
gint capture_dev_user_buffersize_find(const gchar *if_name);
#endif

/**
 * Find user-specified snap length that matches interface
 * name, if any.
 *
 * @param if_name The name of the interface.
 * @param hassnap Pointer to a variable to be set to TRUE if the
 * interface should be given a snap length or FALSE if it shouldn't
 * be given a snap length.
 * @param snaplen Pointer to a variable to be set to the snap length
 * if the interface should be given a snap length or the maximum
 * snap length if it shouldn't be given a snap length.
 *
 * @return TRUE if found or FALSE if not found.
 */
gboolean capture_dev_user_snaplen_find(const gchar *if_name, gboolean *hassnap, int *snaplen);

/**
 * Find user-specified promiscuous mode that matches interface
 * name, if any.
 *
 * @param if_name The name of the interface.
 * @param pmode Pointer to a variable to be set to TRUE if promiscuous
 * mode should be used and FALSE if it shouldn't be used.
 *
 * @return TRUE if found or FALSE if not found.
 */
gboolean capture_dev_user_pmode_find(const gchar *if_name, gboolean *pmode);

/**
 * Find user-specified capture filter that matches interface
 * name, if any.
 *
 * This is deprecated and should not be used in new code.
 *
 * @param if_name The name of the interface.
 *
 * @return The capture filter (must be g_free'd later) or NULL if not found.
 */
gchar* capture_dev_user_cfilter_find(const gchar *if_name);

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

/** Return the interface description (after setting it if not already set)
 *
 * @param capture_opts The capture_options structure that contains the used interface
 * @param i The index of the interface
 *
 * @return A pointer to interface_opts->descr
 */
const char *get_iface_description_for_interface(capture_options *capture_opts, guint i);

/** Set the active DLT for a device appropriately.
 *
 * @param device the device on which to set the active DLT
 * @param global_default_dlt the global default DLT
 */
extern void set_active_dlt(interface_t *device, int global_default_dlt);

/** Get a descriptive string for a list of interfaces.
 *
 * @param capture_opts The capture_options structure that contains the interfaces
 * @param style flags to indicate the style of string to use:
 *
 *  IFLIST_QUOTE_IF_DESCRIPTION: put the interface descriptive string in
 *  single quotes
 *
 *  IFLIST_SHOW_FILTER: include the capture filters in the string
 *
 * @return A GString set to the descriptive string
 */
#define IFLIST_QUOTE_IF_DESCRIPTION 0x00000001
#define IFLIST_SHOW_FILTER          0x00000002

extern GString *get_iface_list_string(capture_options *capture_opts, guint32 style);

/** Get the interface display name to present in the interfaces list.
 *
 * @param description A user-specified capture device description
 * @param if_info The if_info for the interface
 *
 * @return A interface display name (must be g_free'd later)
 */
extern gchar *get_iface_display_name(const gchar *description, const if_info_t *if_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_UI_UTILS_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
