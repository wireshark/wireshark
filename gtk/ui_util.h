/* ui_util.h
 * Definitions for UI utility routines
 *
 * $Id: ui_util.h,v 1.13 2004/06/01 20:28:05 ulfl Exp $
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


/** @file 
 * Utilities for Windows and other user interface functions.
 *
 * Some words about windows / dialogs.
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
 * window_new() will create a new window with default position and size,
 *   use dlg_window_new() if you need a dialog (transient to the main window)
 *
 * gtk_window_set_default_size() to set the default size of the window, only
 *   needed, if the initial size is not appropriate, e.g. a scrolled_window_new() is used
 *   be sure the given is larger than the initial size, otherwise might get clipped content on GTK1
 *
 * SIGNAL_CONNECT(my_win, "destroy", my_destroy_cb, NULL) callback, if some cleanup needs to be 
 *   done after the window is destroyed, e.g. free up memory, or set the window pointer
 *   of a singleton window (only one instance allowed, e.g. about dialog) back to zero
 *
 * create and fill in the content and button widgets
 *
 * gtk_widget_show_all() show all the widgets in the window
 *
 * window_present() present the window on screen and 
 *   (if available) set previously saved position and size
 *
 * if you want to save size and position, be sure to call window_destroy() instead of only 
 *   gtk_widget_destroy(), so you will probably have to SIGNAL_CONNECT to the "delete_event"!
 */

/** Create a new window with the Ethereal icon. 
 *  If you want to create a dialog, use dlg_window_new() instead. 
 *
 * @param type window type, typical GTK_WINDOW_TOPLEVEL 
 * @param title the title for the new window
 * @return the newly created window
 */
extern GtkWidget *window_new(GtkWindowType type, const gchar *title);

/** Same as window_new(), but will keep it's geometry values (size, position, ...).
 *  Be sure to use window_present() and window_destroy() appropriately!
 * 
 * @param type window type, typical GTK_WINDOW_TOPLEVEL 
 * @param title the title for the new window
 * @param geom_name the name to distinguish this window, will also be used for the recent file
 * @return the newly created window
 */
extern GtkWidget *window_new_with_geom(GtkWindowType type, const gchar *title, const gchar *geom_name);

/** Present the created window on the top of the screen. This will put the window on top and 
 * (if available) set previously saved position and size.
 *
 * @param win the window from window_new()
 */
extern void window_present(GtkWidget *win);

/** callback function for window_set_cancel_button() */
typedef void (*window_cancel_button_fct) (GtkWidget *w, gpointer data);

/** Register the default cancel button "Cancel"/"Close"/"Ok" of this window.
 *  This will set the callback function for this button, grab this button as the default one and 
 *  set the "ESC" key handler to call the callback function if key is pressed.
 *
 * @param win the window from window_new()
 * @param bt the default button of this window
 * @param cb callback function to be called, when this button is pressed
 */
extern void window_set_cancel_button(GtkWidget *win, GtkWidget *bt, window_cancel_button_fct cb);

/** Remember the current window position / size and then destroy the window.
 *  It's important to call this instead of gtk_widget_destroy() when using window_new_with_geom().
 *
 * @param win the window from window_new()
 */
extern void window_destroy(GtkWidget *win);

/** Default callback handler for cancel button "clicked" signal.
 *  Use this for window_set_cancel_button(), if no user specific functionality required, 
 *  will simply call window_destroy()
 */
extern void window_cancel_button_cb(GtkWidget *w _U_, gpointer data);

/** Default callback handler if the window managers X of the window was clicked (delete_event).
 *  Use this for SIGNAL_CONNECT(), if no user specific functionality required, 
 *  will simply call window_destroy()
 */
extern gboolean window_delete_event_cb(GtkWidget *win, GdkEvent *event _U_, gpointer user_data _U_);

/** geometry values for use in window_get_geometry() and window_set_geometry() */
typedef struct window_geometry_s {
    gchar       *key;           /**< current key in hashtable (internally used only) */
    gboolean    set_pos;        /**< set the x and y position values */
    gint        x;              /**< the windows x position */
    gint        y;              /**< the windows y position */
    gboolean    set_size;       /**< set the width and height values */
    gint        width;          /**< the windows width */
    gint        height;         /**< the windows height */

    gboolean    set_maximized;  /**< set the maximized state (GTK2 only) */
    gboolean    maximized;      /**< the windows maximized state (GTK2 only) */
} window_geometry_t;

/** Get the geometry of a window.
 *
 * @param win the window from window_new()
 * @param geom the current geometry values of the window, the set_xy values will not be used
 * @todo if main uses the window_new_with_geom() to save size and such, make this function static
 */
extern void window_get_geometry(GtkWidget *win, window_geometry_t *geom);
/** Set the geometry of a window.
 *
 * @param win the window from window_new()
 * @param geom the new geometry values of the window
 * @todo if main uses the window_new_with_geom() to save size and such, make this function static
 */
extern void window_set_geometry(GtkWidget *win, window_geometry_t *geom);

/** Write all geometry values of all windows to the recent file.
 * Will call write_recent_geom() for every existing window type.
 *
 * @param rf recent file handle from caller
 */
extern void window_geom_recent_write_all(gpointer rf);

/** Read in a single geometry key value pair from the recent file.
 *
 * @param name the geom_name of the window
 * @param key the subkey of this pair (e.g. "x")
 * @param value the new value (e.g. "123")
 */
extern void window_geom_recent_read_pair(const char *name, const char *key, const char *value);

/** Raise a top-level window and de-iconify it.  
 *  This routine is used if the user has done something to
 *  ask that a window of a certain type be popped up when there can be only
 *  one such window and such a window has already been popped up - we
 *  pop up the existing one rather than creating a new one.
 *
 * @param win the window from window_new() to be reactivated
 */
void reactivate_window(GtkWidget *win);

/** Create a GtkScrolledWindow, set its scrollbar placement appropriately,
 *  and remember it.
 *
 * @param hadjustment horizontal adjustment
 * @param vadjustment vertical adjustment
 * @return the new scrolled window
 */
GtkWidget *scrolled_window_new(GtkAdjustment *hadjustment,
			       GtkAdjustment *vadjustment);

/** Set the scrollbar placement of all scrolled windows based on user
   preference. */
void set_scrollbar_placement_all(void);

#if GTK_MAJOR_VERSION < 2
/** Create a GtkCTree, give it the right styles, and remember it.
 *
 * @param columns the number of columns
 * @param tree_column which column has the tree graphic
 * @return the newly created GtkCTree
 */
GtkWidget *ctree_new(gint columns, gint tree_column);
/** Create a GtkCTree, give it the right styles, and remember it.
 *
 * @param columns the number of columns
 * @param tree_column which column has the tree graphic
 * @param titles the titles of all columns
 * @return the newly created GtkCTree
 */
GtkWidget *ctree_new_with_titles(gint columns, gint tree_column,
				 gchar *titles[]);
#else
/** Create a GtkTreeView, give it the right styles, and remember it.
 *
 * @param model the model (the data) of this tree view
 */
GtkWidget *tree_view_new(GtkTreeModel *model);
#endif

/** Create a simple list widget.
 *
 * @param cols number of columns
 * @param titles the titles of all columns
 * @return the new simple list widget
 */
extern GtkWidget *simple_list_new(gint cols, gchar **titles);
/** Append a row to the simple list.
 *
 * @param list the list from simple_list_new()
 * @param ... row and title, finished by -1 (e.g.: 0, "first", 1, "second", -1).
 */
extern void simple_list_append(GtkWidget *list, ...);



/** Set the styles of all Trees based upon user preferences. */
void set_tree_styles_all(void);

/** Convert an xpm picture into a GtkWidget showing it.
 * Beware: Ethereal's main window must already be visible!
 *
 * @param xpm the character array containing the picture
 * @return a newly created GtkWidget showing the picture
 */
GtkWidget *xpm_to_widget(const char ** xpm);

#endif /* __GTKGUIUI_UTIL_H__ */
