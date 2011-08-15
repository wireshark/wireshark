/* gui_utils.h
 * Declarations of GTK+-specific UI utility routines
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

#ifndef __GUI_UTILS_H__
#define __GUI_UTILS_H__

/** @defgroup windows_group Windows
 *
 * There are the following toplevel windows:
 *
 * - @ref main_window_group
 * - Statistic Windows (several different statistic windows)
 *
 * See: @ref howto_window_page for details.
 *
 */

/** @page howto_window_page How to develop a window / dialog
 *
 * Windows and dialogs are related to each other. Dialogs are special kind of windows, but they behave
 * slightly different. A dialog sticks on its parent window; A normal window will be much more independent
 * from its parent window. Dialogs should be used to ask or tell the user something, while windows should
 * show data which is independent of the main window.
 * Dialogs are created by calling dlg_window_new() which in turn will call window_new().
 * After that, dialogs can be developed the same way as windows; all window related functions in gui_utils.h
 * can be used for both.
 *
 * @section window_create Create a window
 *
 * A typical window / dialog will be created by the following calls:
 *
 * - window_new() will create a new window with default position and size,
 *     use dlg_window_new() if you need a dialog (transient to the main window)
 * - gtk_window_set_default_size() will set the default size of the window. Only
 *     needed, if the initial size is not appropriate, e.g. when a scrolled_window_new() is used.
 * - g_signal_connect(my_win, "destroy", my_destroy_cb, NULL) will create a callback if some cleanup
 *     needs to be done after the window is destroyed, e.g. free up memory, or set the window pointer
 *   of a singleton window (only one instance allowed, e.g. about dialog) back to zero
 * - create and fill in the content and button widgets
 * - gtk_widget_show_all() shows all the widgets in the window
 * - window_present() will present the window on screen and
 *     (if available) set previously saved position and size
 *
 * @section window_events Events
 *
 * The following events are usually interesting:
 *
 * - "delete_event": the window manager's "X" (e.g. upper right edge) of the window
 *     was clicked; the default handler will call gtk_widget_destroy()
 * - "destroy": everything is already gone; only cleanup of left over resources
 *     can/should be done now
 *
 * @section window_hints Hints
 *
 * If you want to save size and position, be sure to call window_destroy() instead of only
 *   gtk_widget_destroy(), so you will probably have to g_signal_connect() to the "delete_event"!
 *
 * Don't use gtk_widget_set_size_request() to set the size of a window;
 *   use gtk_window_set_default_size() for that purpose!
 *
 * Be sure to call window_present() / window_destroy() appropriately, if you
 *   want to have size and position of the window handled by ui_util.
 *
 */

/** @file
 * Utilities for Windows and other user interface functions. See: @ref howto_window_page for details.
 * @ingroup dialog_group
 * @ingroup windows_group
 */

/** @name Window Functions
 *  @todo Move these window functions to a new file win_utils.h?
 *  @{ */

/** Create a new window with the Wireshark icon.
 *  If you want to create a dialog, use dlg_window_new() instead.
 *
 * @param type window type, typical GTK_WINDOW_TOPLEVEL
 * @param title the title for the new window
 * @return the newly created window
 */
extern GtkWidget *window_new(GtkWindowType type, const gchar *title);

/** Same as window_new(), but will keep its geometry values (size, position, ...).
 *  Be sure to use window_present() and window_destroy() appropriately!
 *
 * @param type window type, typical GTK_WINDOW_TOPLEVEL
 * @param title the title for the new window
 * @param geom_name the name to distinguish this window; will also be used for the recent file (don't use special chars)
 * @return the newly created window
 */
extern GtkWidget *window_new_with_geom(GtkWindowType type, const gchar *title, const gchar *geom_name);

/** Create a new splash window, with no icon or title bar.
 *
 * @return the newly created window
 */
extern GtkWidget *splash_window_new(void);

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

/** Default callback handler if the window manager's X of the window was clicked (delete_event).
 *  Use this for g_signal_connect(), if no user specific functionality required,
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
 * @param geom the current geometry values of the window; the set_xy values will not be used
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
extern void reactivate_window(GtkWidget *win);

/** @} */

/** Create a GtkScrolledWindow, set its scrollbar placement appropriately,
 *  and remember it.
 *
 * @param hadjustment horizontal adjustment
 * @param vadjustment vertical adjustment
 * @return the new scrolled window
 */
extern GtkWidget *scrolled_window_new(GtkAdjustment *hadjustment,
			       GtkAdjustment *vadjustment);

/** Set the scrollbar placement of all scrolled windows based on user
   preference. */
extern void set_scrollbar_placement_all(void);

/** Create a GtkTreeView, give it the right styles, and remember it.
 *
 * @param model The model (the data) of this tree view.
 */
extern GtkWidget *tree_view_new(GtkTreeModel *model);

/** Move the currently-selected item in a list store up or down one position.
 *
 * @param tree GtkTreeView using a GtkListStore.
 * @param move_up TRUE to move the selected item up or FALSE to move it down.
 * @return TRUE if successful, FALSE otherwise.
 */
extern gboolean tree_view_list_store_move_selection(GtkTreeView *tree, gboolean move_up);

/** Find the selected row in a list store.
 *
 * @param tree GtkTreeView using a GtkListStore.
 * @return The selected row number or -1 if no row is selected.
 */
extern gint tree_view_list_store_get_selected_row(GtkTreeView *tree);

/** Create a simple list widget.
 *
 * @param cols number of columns
 * @param titles the titles of all columns
 * @return the new simple list widget
 */
extern GtkWidget *simple_list_new(gint cols, const gchar **titles);
/** Append a row to the simple list.
 *
 * @param list the list from simple_list_new()
 * @param ... row and title, finished by -1 (e.g.: 0, "first", 1, "second", -1).
 */
extern void simple_list_append(GtkWidget *list, ...);

/*** Make a column look like a url
 *
 * @param list the list from simple_list_new()
 * @param col the column to make the values lookk like urls
 */
extern void simple_list_url_col(GtkWidget *list, gint col);

/*** Make a cell underline to look like links
 *
 * @param cell the cell renderer that will show the text as a link
 */

extern void render_as_url(GtkCellRenderer *cell);

/** Set the styles of all Trees based upon user preferences. */
extern void set_tree_styles_all(void);

/** Convert an xpm picture into a GtkWidget showing it.
 * Beware: Wireshark's main window must already be visible!
 *
 * @param xpm the character array containing the picture
 * @return a newly created GtkWidget showing the picture
 */
extern GtkWidget *xpm_to_widget(const char ** xpm);

/** Convert an xpm picture into a GtkWidget showing it.
 * Beware: the given parent window must already be visible!
 *
 * @param parent the parent window of to widget to be generated
 * @param xpm the character array containing the picture
 * @return a newly created GtkWidget showing the picture
 */
/*extern GtkWidget *xpm_to_widget_from_parent(GtkWidget *parent, const char ** xpm);*/

/** Convert an pixbuf data to a GtkWidget
 *
 * @param pb_data Inline pixbuf data. This should be created with "gdk-pixbuf-csource --raw"
 */
extern GtkWidget *pixbuf_to_widget(const char * pb_data);

/** Copy a GString to the clipboard.
 *
 * @param str GString that is to be copied to the clipboard.
 */
extern void copy_to_clipboard(GString *str);

/** Copy an array of bytes to the clipboard.
 * Copies as mime-type application/octet_stream in GTK 2.
 *
 * @param data_p Pointer to data to be copied.
 * @param len Number of bytes in the data to be copied.
 */
extern void copy_binary_to_clipboard(const guint8* data_p, int len);

/** Create a new window title that includes user-defined preference string.
 *
 * @param caption string you want included in title (appended to user-defined string)
 * @return a newly created title string including user-defined preference (if specified)
 */
extern gchar *create_user_window_title(const gchar *caption);

/** Construct the main window's title with the current main_window_name optionally appended
 *  with the user-specified title and/or wireshark version. 
 *  Display the result in the main window's title bar and in its icon title
 */
extern void update_main_window_title(void);

/** Renders a float with two decimals precission, called from gtk_tree_view_column_set_cell_data_func().
 * the user data must be the colum number.
 * Present floats with two decimals 
 *
 * @param column A GtkTreeColumn 
 * @param renderer The GtkCellRenderer that is being rendered by tree_column 
 * @param model The GtkTreeModel being rendered 
 * @param iter A GtkTreeIter of the current row rendered 
 * @param user_data must be the colum number to fetch the data from
 */
void float_data_func (GtkTreeViewColumn *column, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer user_data);

/** Renders a unsinged integer as a hexadecimal value, called from gtk_tree_view_column_set_cell_data_func()
 * The user data must be the colum number.
 * Present value as hexadecimal. 
 * @param column A GtkTreeColumn 
 * @param renderer The GtkCellRenderer that is being rendered by tree_column 
 * @param model The GtkTreeModel being rendered 
 * @param iter A GtkTreeIter of the current row rendered 
 * @param user_data must be the colum number to fetch the data from
 */
void present_as_hex_func (GtkTreeViewColumn *column, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer user_data);

/** Renders an unsigned 64 bits integer with space as thousand separator, called from gtk_tree_view_column_set_cell_data_func()
 * The user data must be the colum number.
 * Present value as hexadecimal. 
 * @param column A GtkTreeColumn 
 * @param renderer The GtkCellRenderer that is being rendered by tree_column 
 * @param model The GtkTreeModel being rendered 
 * @param iter A GtkTreeIter of the current row rendered 
 * @param user_data must be the colum number to fetch the data from
 */
void u64_data_func (GtkTreeViewColumn *column, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer user_data);

/** This function can be called from gtk_tree_view_column_set_cell_data_func()
 * the user data must be the colum number.
 * Present value as hexadecimal. 
 * @param column A GtkTreeColumn 
 * @param renderer The GtkCellRenderer that is being rendered by tree_column 
 * @param model The GtkTreeModel being rendered 
 * @param iter A GtkTreeIter of the current row rendered 
 * @param user_data must be the colum number to fetch the data from
 */
void str_ptr_data_func(GtkTreeViewColumn *column, GtkCellRenderer *renderer, GtkTreeModel *model, GtkTreeIter *iter, gpointer user_data);

/** This function can be called from gtk_tree_sortable_set_sort_func()
 * the user data must be the colum number.
 * Used together with str_ptr_data_func to sort the corresponding column.
 * @param model The GtkTreeModel the comparison is within  
 * @param a A GtkTreeIter in model  
 * @param b Another GtkTreeIter in model  
 * @param user_data must be the colum number to fetch the data from
 */

gint str_ptr_sort_func(GtkTreeModel *model,
                       GtkTreeIter  *a,
                       GtkTreeIter  *b,
                       gpointer      user_data);

/** Switch a GtkTReeView to fixed columns (speed optimization)
 * @param view A GtkTreeView 
 */
void switch_to_fixed_col(GtkTreeView *view);

/** Return the size in pixels of a string displayed with the GtkWidget's font.
 * @param view A GtkWidget
 * @param str UTF8 string 
 */
gint get_default_col_size(GtkWidget *view, const gchar *str);


/** --------------------------------------------------
 * ws_combo_box_text_and_pointer convenience functions
 *  (Code adapted from GtkComboBox.c)
 */

/**
 * ws_combo_box_new_text_and_pointer_full:
 *
 * Convenience function which constructs a new "text and pointer" combo box, which
 * is a #GtkComboBox just displaying strings and storing a pointer associated with 
 * each combo_box entry; The pointer can be retrieved when an entry is selected. 
 * Also: optionally returns the cell renderer for the combo box.
 * If you use this function to create a text_and_pointer combo_box,
 * you should only manipulate its data source with the
 * following convenience functions:
 *   ws_combo_box_append_text_and_pointer()
 *   ws_combo_box_append_text_and_pointer_full()
 *
 * @param cell_p  pointer to return the 'GtkCellRenderer *' for the combo box (or NULL).
 * @return A pointer to a new text_and_pointer combo_box.
 */
GtkWidget *ws_combo_box_new_text_and_pointer_full(GtkCellRenderer **cell_p);

/**
 * ws_combo_box_new_text_and_pointer:
 *
 * Convenience function which constructs a new "text and pointer" combo box, which
 * is a #GtkComboBox just displaying strings and storing a pointer associated with 
 * each combo_box entry; The pointer can be retrieved when an entry is selected. 
 * If you use this function to create a text_and_pointer combo_box,
 * you should only manipulate its data source with the
 * following convenience functions:
 *   ws_combo_box_append_text_and_pointer()
 *   ws_combo_box_append_text_and_pointer_full()
 *
 * @return A pointer to a new text_and_pointer combo_box.
 */
GtkWidget *ws_combo_box_new_text_and_pointer(void);

/**
 * ws_combo_box_clear_text_and_pointer:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 *
 * Clears all the text_and_pointer entries in the text_and_pointer combo_box.
 * Note: A "changed" signal will be emitted after the clear if there was 
 * an active (selected) entry before the clear.
 * You should use this function only with combo boxes constructed with
 * ws_combo_box_new_text_and_pointer().
 */
void ws_combo_box_clear_text_and_pointer(GtkComboBox *combo_box);

/**
 * ws_combo_box_append_text_and_pointer_full:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 * @param parent_iter Parent row for apending; NULL if appending to tree top-level; 
 * @param text A string to be displayed as an entry in the dropdown list of the combo_box
 * @param ptr  A pointer to be associated with this entry of the combo_box
 * @param sensitive TRUE/FALSE to set sensitivity of the entry
 * @return A GtkTreeIter pointing to the appended GtkVomboBox entry.
 *
 * Appends text and ptr to the list of strings and pointers stored in combo_box.
 * The text and ptr can be appended to any existing level of the tree_store.
 * The sensitivity of the row will be set as requested.
 * Note that you can only use this function with combo boxes constructed with
 * ws_combo_box_new_text_and_pointer().
 */
GtkTreeIter
ws_combo_box_append_text_and_pointer_full(GtkComboBox   *combo_box,
                                          GtkTreeIter   *parent_iter,
                                          const gchar   *text,
                                          const gpointer ptr,
                                          const gboolean sensitive);

/**
 * ws_combo_box_append_text_and_pointer:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 * @param text A string to be displayed as an entry in the dropdown list of the combo_box
 * @param ptr  A pointer to be associated with this entry of the combo_box
 * @return A GtkTreeIter pointing to the appended GtkComboBox entry.
 *
 * Appends text and ptr to the list of strings and pointers stored in combo_box. Note that
 * you can only use this function with combo boxes constructed with
 * ws_combo_box_new_text_and_pointer().
 */
GtkTreeIter
ws_combo_box_append_text_and_pointer(GtkComboBox    *combo_box,
                                     const gchar    *text,
                                     const gpointer  ptr);

/**
 * ws_combo_box_get_active_pointer:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 * @param ptr  A pointer to a location in which to store the pointer associated with the active entry
 * @return TRUE if an entry is selected (i.e: an active entry exists); FALSE otherwise
 *
 * You can only use this function with combo boxes constructed with
 * ws_combo_box_new_text_and_pointer().
 */
gboolean ws_combo_box_get_active_pointer(GtkComboBox *combo_box, gpointer *ptr);

/**
 * ws_combo_box_get_active:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 * @return Index of the active entry; -1 if no entry is selected;
 *         Note: If the active item is not an immediate child of root of the tree then
 *          the index returned is that of the top-level for the acftive entry.
 */
gint ws_combo_box_get_active(GtkComboBox *combo_box);

/**
 * ws_combo_box_set_active:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 * @param idx Index of the entry which is to be set as active (ie: selected).
 *        Index refers to the immediate children of the tree.
 */
void ws_combo_box_set_active(GtkComboBox *combo_box, gint idx);

/**
 * ws_combo_box_set_active_iter:
 * @param combo_box A #GtkComboBox constructed using ws_combo_box_new_text_and_pointer()
 * @param iter of the entry which is to be set as active (ie: selected).
 */
void
ws_combo_box_set_active_iter(GtkComboBox *combo_box, GtkTreeIter *iter);

#if GTK_CHECK_VERSION(2,22,0)
#if !GTK_CHECK_VERSION(3,0,0)
GdkPixbuf *gdk_pixbuf_get_from_surface (cairo_surface_t *surface,
                                        gint             src_x,
                                        gint             src_y,
                                        gint             width,
                                        gint             height);
#endif
#endif
#endif /* __GUI_UTIL__H__ */
