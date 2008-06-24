/* main_statusbar_private.h
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

#ifndef __MAIN_STATUSBAR_PRIVATE_H__
#define __MAIN_STATUSBAR_PRIVATE_H__

/*** PRIVATE INTERFACE BETWEEN main.c AND main_statusbar.c DON'T USE OR TOUCH :-)*/

GtkWidget *statusbar_new(void);
void statusbar_load_window_geometry(void);
void statusbar_save_window_geometry(void);
void statusbar_widgets_emptying(GtkWidget *statusbar);
void statusbar_widgets_pack(GtkWidget *statusbar);
void statusbar_widgets_show_or_hide(GtkWidget *statusbar);
void statusbar_cf_callback(gint event, gpointer data, gpointer user_data);
#ifdef HAVE_LIBPCAP
void statusbar_capture_callback(gint event, capture_options *capture_opts,
                                gpointer user_data);
#endif

#endif /* __MAIN_STATUSBAR_PRIVATE_H__ */

