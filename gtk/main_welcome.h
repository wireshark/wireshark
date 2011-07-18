/* main_welcome.h
 * Welcome "page"
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

#ifndef __MAIN_WELCOME_H__
#define __MAIN_WELCOME_H__

enum
{
  ICON = 0,
  IFACE_DESCR,
  IFACE_NAME,
  NUMCOLUMNS
};

GtkWidget *welcome_new(void);

/* reset the list of recently used files */
void main_welcome_reset_recent_capture_files(void);

/* add a new file to the list of recently used files */
void main_welcome_add_recent_capture_file(const char *widget_cf_name, GObject *menu_item);

/* reload the list of interfaces */
void welcome_if_panel_reload(void);

/** Push a status message into the welcome screen header similar to
 *  statusbar_push_*_msg(). This hides everything under the header.
 *  If msg is dynamically allocated, it is up to the caller to free
 *  it. If msg is NULL, the default message will be shown.
 *
 * @param msg The message
 */
void welcome_header_push_msg(const gchar *msg);

void welcome_header_set_message(gchar *msg);

/** Pop a status message from the welcome screen. If there are no
 *  messages on the stack, the default message and the main columns
 *  will be shown.
 */
void welcome_header_pop_msg(void);

void select_ifaces(void);

#endif /* __MAIN_WELCOME_H__ */
