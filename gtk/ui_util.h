/* ui_util.h
 * Definitions for UI utility routines
 *
 * $Id: ui_util.h,v 1.11 2004/05/30 11:54:37 ulfl Exp $
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

#ifndef __GTKGUIUI_UTIL_H__
#define __GTKGUIUI_UTIL_H__


/* Some words about windows / dialogs.
 * 
 * delete event: the window managers "X" (e.g. upper right edge) of the window 
 *   was clicked, default handler will call gtk_widget_destroy()
 * destroy event: everything is already gone, only cleanup of left over ressources
 *   can/should be done now
 *
 * Hint: don't use WIDGET_SET_SIZE() to set the size of a window,
 * use gtk_window_set_default_size() for that purpose!
 *
 * be sure, to call window_present() / window_destroy() appropriately, if you 
 *   want to have size and position handled by ui_util
 *
 * A typical window / dialog will be created by:
 *
 * window_new(...) will create a new window with default position and size
 *   use dlg_window_new() if you need a dialog (transient to the main window)
 *
 * gtk_window_set_default_size(...) to set the default size of the window, only
 *   needed, if the initial size is not appropriate, e.g. a scrolled_window_new() is used
 *   be sure the given is larger than the initial size, otherwise might get clipped content on GTK1
 *
 * SIGNAL_CONNECT(my_win, "destroy", my_destroy_cb, NULL) callback, if some cleanup needs to be 
 *   done after the window is destroyed, e.g. free up memory, or set the window pointer
 *   of a singleton window (only one instance allowed, e.g. about dialog) back to zero
 *
 * create and fill in the content and button widgets
 *
 * gtk_widget_show_all(my_win) show all the widgets in the window
 *
 * window_present(...) present the window on screen and 
 *   (if available) set previously saved position and size
 *
 * if you want to save size and position, be sure to call window_destroy() instead of only 
 *   gtk_widget_destroy(), so you will probably have to SIGNAL_CONNECT to the "delete_event"!
 */

/* Create a new window, of the specified type, with the specified title
 * (if any) and the Ethereal icon. 
 * If you want to create a dialog, use dlg_window_new() instead. 
 * type window type, typical  GTK_WINDOW_TOPLEVEL 
 * title title to show, will also set the window class for saving size etc. */
extern GtkWidget *window_new(GtkWindowType type, const gchar *title);

/* Same as window_new(), but will keep it's geometry values (size, position, ...).
 * Be sure to use window_present() and window_destroy() appropriately! */
extern GtkWidget *window_new_with_geom(GtkWindowType type, const gchar *title, const gchar *geom_name);

/* Present the created window. This will put the window on top and 
 * (if available) set previously saved position and size. */
extern void window_present(GtkWidget *win);

typedef void (*window_cancel_button_fct) (GtkWidget *w, gpointer data);

/* register the default cancel button "Cancel"/"Close"/"Ok" of this window */
extern void window_set_cancel_button(GtkWidget *win, GtkWidget *bt, window_cancel_button_fct cb);

/* Remember current window position and size and then destroy the window,
 * it's important to call this instead of gtk_widget_destroy(); */
extern void window_destroy(GtkWidget *win);

/* default callback handler for cancel button "clicked" signal, 
 * use this for window_set_cancel_button(), will simply call window_destroy() */
extern void window_cancel_button_cb(GtkWidget *w _U_, gpointer data);

/* default callback handler: the window managers X of the window was clicked (delete_event),
 * use this for SIGNAL_CONNECT(), will simply call window_destroy() */
extern gboolean
window_delete_event_cb(GtkWidget *win, GdkEvent *event _U_, gpointer user_data _U_);


typedef struct window_geometry_s {
    gchar       *key;    
    gboolean    set_pos;
    gint        x;
    gint        y;
    gboolean    set_size;
    gint        width;
    gint        height;

    gboolean    set_maximized;/* this is valid in GTK2 only */
    gboolean    maximized;    /* this is valid in GTK2 only */
} window_geometry_t;

/* get the geometry of a window from window_new() */
extern void window_get_geometry(GtkWidget *win, window_geometry_t *geom);
/* set the geometry of a window from window_new() */
extern void window_set_geometry(GtkWidget *win, window_geometry_t *geom);

/* write all geometry values of all windows to the recent file */
extern void window_geom_recent_write_all(gpointer rf);

/* read in a single geometry key value pair from the recent file */
extern void window_geom_recent_read_pair(const char *name, const char *key, const char *value);

/* Given a pointer to a GtkWidget for a top-level window, raise it and
   de-iconify it.  This routine is used if the user has done something to
   ask that a window of a certain type be popped up when there can be only
   one such window and such a window has already been popped up - we
   pop up the existing one rather than creating a new one. */
void reactivate_window(GtkWidget *win);

/* Create a GtkScrolledWindow, set its scrollbar placement appropriately,
   and remember it. */
GtkWidget *scrolled_window_new(GtkAdjustment *hadjustment,
			       GtkAdjustment *vadjustment);

/* Set the scrollbar placement of all scrolled windows based on user
   preference. */
void set_scrollbar_placement_all(void);

#if GTK_MAJOR_VERSION < 2
/* Create a GtkCTree, give it the right styles, and remember it. */
GtkWidget *ctree_new(gint columns, gint tree_column);
GtkWidget *ctree_new_with_titles(gint columns, gint tree_column,
				 gchar *titles[]);
#else
GtkWidget *tree_view_new(GtkTreeModel *model);
#endif

/* create a simple list widget */
extern GtkWidget *simple_list_new(gint cols, gchar **titles);
/* append a row to the simple list */
/* use it like: simple_list_append(list, 0, "first", 1, "second", -1) */
extern void simple_list_append(GtkWidget *list, ...);



/* Set the styles of all Trees based upon user preferences. */
void set_tree_styles_all(void);

/* convert an xpm picture into a GtkWidget showing it (top_level must already be visible!) */
GtkWidget *xpm_to_widget(const char ** xpm);

#endif /* __GTKGUIUI_UTIL_H__ */
