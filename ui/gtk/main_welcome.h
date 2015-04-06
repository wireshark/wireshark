/* main_welcome.h
 * Welcome "page"
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

#ifndef __MAIN_WELCOME_H__
#define __MAIN_WELCOME_H__

#include "ui/gtk/capture_dlg.h"

enum
{
  ICON = 0,
  IFACE_DESCR,
  IFACE_NAME,
  NUMCOLUMNS
};

typedef struct selected_name_s {
  gchar *name;
  gboolean activate;
} selected_name_t;

/* reset the list of recently used files */
void main_welcome_reset_recent_capture_files(void);

/* add a new file to the list of recently used files */
void main_welcome_add_recent_capture_file(const char *widget_cf_name, GObject *menu_item);

/* reload the list of interfaces */
void welcome_if_panel_reload(void);

void welcome_header_set_message(gchar *msg);

GtkWidget* get_welcome_window(void);

void change_interface_selection(gchar* name, gboolean activate);

void change_selection_for_all(gboolean enable);

void update_welcome_list(void);

void set_sensitivity_for_start_icon(void);

#ifdef HAVE_PCAP_REMOTE
void add_interface_to_list(guint index);
#endif

#ifdef HAVE_LIBPCAP
void change_interface_name(gchar *oldname, guint index);
#endif
#endif /* __MAIN_WELCOME_H__ */
