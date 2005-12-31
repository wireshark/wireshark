/* filter_dlg.h
 * Definitions for dialog boxes for filter editing
 *
 * $Id$
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

#ifndef __FILTER_H__
#define __FILTER_H__

/** @file
 * "Capture Filter" / "Display Filter" / "Add expression" dialog boxes.
 * (This used to be a notebook page under "Preferences", hence the
 * "prefs" in the file name.)
 * @ingroup dialog_group
 */

/**
 * Structure giving properties of the filter editing dialog box to be
 * created.
 */
typedef struct {
    const gchar    *title;          /**< title of dialog box */
    gboolean wants_apply_button;    /**< dialog should have an Apply button */
    gboolean activate_on_ok;        /**< if parent text widget should be
                                        activated on "Ok" or "Apply" */
    gboolean modal_and_transient;   /**< dialog is modal and transient to the
                                        parent window (e.g. to gtk_file_chooser) */
} construct_args_t;

/** Create a "Capture Filter" dialog box caused by a button click.
 *
 * @param widget parent widget
 * @param user_data unused
 */
void capture_filter_construct_cb(GtkWidget *widget, gpointer user_data);

/** Create a "Display Filter" dialog box caused by a button click.
 *
 * @param widget parent widget
 * @param construct_args_ptr parameters to construct the dialog (construct_args_t)
 */
void display_filter_construct_cb(GtkWidget *widget, gpointer construct_args_ptr);

/** Should be called when the widget (usually a button) that creates filters
 *  is destroyed. It destroys any filter dialog created by that widget.
 *
 * @param widget parent widget
 * @param user_data unused
 */
void filter_button_destroy_cb(GtkWidget *widget, gpointer user_data);

/** User requested the "Capture Filter" dialog box by menu or toolbar.
 *
 * @param widget parent widget
 */
void cfilter_dialog_cb(GtkWidget *widget);

/** User requested the "Display Filter" dialog box by menu or toolbar.
 *
 * @param widget parent widget
 */
void dfilter_dialog_cb(GtkWidget *widget);

/** Create an "Add expression" dialog box caused by a button click.
 *
 * @param widget unused
 * @param main_w_arg parent widget
 */
void filter_add_expr_bt_cb(GtkWidget *widget, gpointer main_w_arg);

/** Colorize a text entry as empty.
 *
 * @param widget the text entry to colorize
 */
void colorize_filter_te_as_empty(GtkWidget *widget);

/** Colorize a text entry as a invalid.
 *
 * @param widget the text entry to colorize
 */
void colorize_filter_te_as_invalid(GtkWidget *widget);

/** Colorize a text entry as a valid.
 *
 * @param widget the text entry to colorize
 */
void colorize_filter_te_as_valid(GtkWidget *widget);

/** Colorize a filter text entry depending on "validity".
 *
 * @param widget the text entry to colorize
 */
void filter_te_syntax_check_cb(GtkWidget *widget);

/** The filter button of the top_level window. */
#define E_FILT_BT_PTR_KEY	    "filter_bt_ptr"

/** The filter text entry. */
#define E_FILT_TE_PTR_KEY	    "filter_te_ptr"

/** The filter text entry.
 *  @todo Check the usage of all the text entry keys.
 */
#define E_FILT_FILTER_TE_KEY    "filter_filter_te"

#endif /* filter.h */
