/* main.h
 * Global defines, etc.
 *
 * $Id: main.h,v 1.20 2000/09/08 10:59:17 guy Exp $
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

#include "globals.h"

#define RC_FILE PF_DIR "/gtkrc"
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
void match_selected_cb( GtkWidget *, gpointer);
void file_quit_cmd_cb(GtkWidget *, gpointer);
void file_print_cmd_cb(GtkWidget *, gpointer);
void file_print_packet_cmd_cb(GtkWidget *, gpointer);
void tools_plugins_cmd_cb(GtkWidget *, gpointer);
void expand_all_cb(GtkWidget *, gpointer);
void collapse_all_cb(GtkWidget *, gpointer);
void resolve_name_cb(GtkWidget *, gpointer);
void mark_frame_cb(GtkWidget *, gpointer);
void mark_all_frames_cb(GtkWidget *w, gpointer);
void unmark_all_frames_cb(GtkWidget *w, gpointer);
void update_marked_frames(void);

char *boldify(const char *);

#endif /* __MAIN_H__ */
