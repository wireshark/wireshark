/* main.h
 * Global defines, etc.
 *
 * $Id: main.h,v 1.42 2004/02/03 00:16:58 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __MAIN_H__
#define __MAIN_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "globals.h"

/*
 * File under personal preferences directory in which GTK settings for
 * Ethereal are stored.
 */
#define RC_FILE "gtkrc"

#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE " Ready to load or capture"
#else
#define DEF_READY_MESSAGE " Ready to load file"
#endif

#define MATCH_SELECTED_REPLACE		0
#define MATCH_SELECTED_AND		1
#define MATCH_SELECTED_OR		2
#define MATCH_SELECTED_NOT		3
#define MATCH_SELECTED_AND_NOT		4
#define MATCH_SELECTED_OR_NOT		5

#define MATCH_SELECTED_MASK		0x0ff
#define MATCH_SELECTED_APPLY_NOW	0x100

typedef struct _selection_info {
  GtkWidget *tree;
  GtkWidget *text;
} selection_info;

#if GTK_MAJOR_VERSION < 2
extern GtkStyle *item_style;
#endif

void about_ethereal( GtkWidget *, gpointer);
void goto_framenum_cb(GtkWidget *, gpointer);
void goto_top_frame_cb(GtkWidget *w _U_, gpointer d _U_);
void goto_bottom_frame_cb(GtkWidget *w _U_, gpointer d _U_);
void view_zoom_in_cb(GtkWidget *w _U_, gpointer d _U_);
void view_zoom_out_cb(GtkWidget *w _U_, gpointer d _U_);
void view_zoom_100_cb(GtkWidget *w _U_, gpointer d _U_);
void match_selected_cb_replace_ptree( GtkWidget *, gpointer);
void match_selected_cb_and_ptree( GtkWidget *, gpointer);
void match_selected_cb_or_ptree( GtkWidget *, gpointer);
void match_selected_cb_not_ptree( GtkWidget *, gpointer);
void match_selected_cb_and_ptree_not( GtkWidget *, gpointer);
void match_selected_cb_or_ptree_not( GtkWidget *, gpointer);
void prepare_selected_cb_replace_ptree( GtkWidget *, gpointer);
void prepare_selected_cb_and_ptree( GtkWidget *, gpointer);
void prepare_selected_cb_or_ptree( GtkWidget *, gpointer);
void prepare_selected_cb_not_ptree( GtkWidget *, gpointer);
void prepare_selected_cb_and_ptree_not( GtkWidget *, gpointer);
void prepare_selected_cb_or_ptree_not( GtkWidget *, gpointer);
void match_selected_cb_replace_plist( GtkWidget *, gpointer);
void match_selected_cb_and_plist( GtkWidget *, gpointer);
void match_selected_cb_or_plist( GtkWidget *, gpointer);
void match_selected_cb_not_plist( GtkWidget *, gpointer);
void match_selected_cb_and_plist_not( GtkWidget *, gpointer);
void match_selected_cb_or_plist_not( GtkWidget *, gpointer);
void prepare_selected_cb_replace_plist( GtkWidget *, gpointer);
void prepare_selected_cb_and_plist( GtkWidget *, gpointer);
void prepare_selected_cb_or_plist( GtkWidget *, gpointer);
void prepare_selected_cb_not_plist( GtkWidget *, gpointer);
void prepare_selected_cb_and_plist_not( GtkWidget *, gpointer);
void prepare_selected_cb_or_plist_not( GtkWidget *, gpointer);
void file_quit_cmd_cb(GtkWidget *, gpointer);
void file_print_cmd_cb(GtkWidget *, gpointer);
void tools_plugins_cmd_cb(GtkWidget *, gpointer);
void expand_all_cb(GtkWidget *, gpointer);
void collapse_all_cb(GtkWidget *, gpointer);
void resolve_name_cb(GtkWidget *, gpointer);
void reftime_frame_cb(GtkWidget *, gpointer, guint);

extern gboolean dfilter_combo_add_recent(gchar *s);
extern void dfilter_combo_add_empty(void);
extern void dfilter_recent_combo_write_all(FILE *rf);

extern gboolean main_do_quit(void);
extern void main_widgets_rearrange(void);
extern int main_filter_packets(capture_file *cf, const gchar *dftext);
extern void dnd_open_file_cmd(gpointer cf_name);
extern void packets_bar_update(void);


typedef enum {
	FA_SUCCESS,
	FA_FONT_NOT_RESIZEABLE,
	FA_FONT_NOT_AVAILABLE
} fa_ret_t;
extern fa_ret_t font_apply(void);
#if GTK_MAJOR_VERSION < 2
char *font_boldify(const char *);
void set_fonts(GdkFont *regular, GdkFont *bold);
#else
void set_fonts(PangoFontDescription *regular, PangoFontDescription *bold);
#endif
void set_last_open_dir(char *dirname);

#endif /* __MAIN_H__ */
