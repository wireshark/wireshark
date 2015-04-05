/* main_welcome_private.h
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

#ifndef __MAIN_WELCOME_PRIVATE_H__
#define __MAIN_WELCOME_PRIVATE_H__

/*** PRIVATE INTERFACE BETWEEN main.c AND main_welcome.c DON'T USE OR TOUCH :-)*/

GtkWidget *welcome_new(void);
void welcome_cf_callback(gint event, gpointer data, gpointer user_data);
#ifdef HAVE_LIBPCAP
void welcome_capture_callback(gint event, capture_session *cap_session,
                                gpointer user_data);
#endif

#endif /* __MAIN_WELCOME_PRIVATE_H__ */
