/* ethereal.h
 * Global defines, etc.
 *
 * $Id: main.h,v 1.9 2000/01/15 00:22:52 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __MAIN_H__
#define __MAIN_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __GLOBALS_H__
#include "globals.h"
#endif

#define RC_FILE PF_DIR "/gtkrc"
#define MONO_MEDIUM_FONT "-*-lucidatypewriter-medium-r-normal-*-*-120-*-*-*-*-iso8859-1"
#define MONO_BOLD_FONT "-*-lucidatypewriter-bold-r-normal-*-*-120-*-*-*-*-iso8859-1"
#define DEF_WIDTH 750
#define DEF_HEIGHT 550
#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE " Ready to load or capture"
#else
#define DEF_READY_MESSAGE " Ready to load file"
#endif

typedef struct _selection_info {
  GtkWidget *tree;
  GtkWidget *text;
} selection_info;

extern GtkStyle *item_style;

void about_ethereal( GtkWidget *, gpointer);
void blank_packetinfo();
void follow_stream_cb( GtkWidget *, gpointer);
void match_selected_cb( GtkWidget *, gpointer);
void file_open_cmd_cb(GtkWidget *, gpointer);
void file_save_cmd_cb(GtkWidget *, gpointer);
void file_save_as_cmd_cb(GtkWidget *, gpointer);
void file_close_cmd_cb(GtkWidget *, gpointer);
void file_quit_cmd_cb(GtkWidget *, gpointer);
void file_reload_cmd_cb(GtkWidget *, gpointer);
void file_print_cmd_cb(GtkWidget *, gpointer);
void file_print_packet_cmd_cb(GtkWidget *, gpointer);
#ifdef HAVE_PLUGINS
void tools_plugins_cmd_cb(GtkWidget *, gpointer);
#endif
void expand_all_cb(GtkWidget *, gpointer);
void collapse_all_cb(GtkWidget *, gpointer);
void filter_dialog_cb(GtkWidget *);

#endif /* __MAIN_H__ */
