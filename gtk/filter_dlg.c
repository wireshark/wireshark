/* filter_dlg.c
 * Dialog boxes for (display and capture) filter editing
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/filesystem.h>

#include "filters.h"
#include "gtk/main.h"
#include "filter_dlg.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "simple_dialog.h"
#include "dfilter_expr_dlg.h"
#include "compat_macros.h"
#include "gtkglobals.h"
#include "help_dlg.h"

#define E_FILT_DIALOG_PTR_KEY       "filter_dialog_ptr"
#define E_FILT_BUTTON_PTR_KEY       "filter_button_ptr"
#define E_FILT_PARENT_FILTER_TE_KEY "filter_parent_filter_te"
#define E_FILT_CONSTRUCT_ARGS_KEY   "filter_construct_args"
#define E_FILT_LIST_ITEM_MODEL_KEY  "filter_list_item_model"
#define E_FILT_LBL_KEY              "filter_label"
#define E_FILT_FILTER_L_KEY         "filter_filter_l"
#define E_FILT_CHG_BT_KEY           "filter_chg_bt"
#define E_FILT_COPY_BT_KEY          "filter_copy_bt"
#define E_FILT_DEL_BT_KEY           "filter_del_bt"
#define E_FILT_NAME_TE_KEY          "filter_name_te"
#define E_FILT_DBLFUNC_KEY          "filter_dblfunc"
#define E_FILT_DBLARG_KEY           "filter_dblarg"
#define E_FILT_DBLACTIVATE_KEY      "filter_dblactivate"

typedef struct _filter_cb_data {
  GList     *fl;
  GtkWidget *win;
} filter_cb_data;

static GtkWidget *filter_dialog_new(GtkWidget *button, GtkWidget *filter_te,
                                    filter_list_type_t list_type,
                                    construct_args_t *construct_args);
static void filter_dlg_dclick(GtkWidget *dummy, gpointer main_w_arg,
			      gpointer activate);
static void filter_dlg_ok_cb(GtkWidget *ok_bt, gpointer dummy);
static void filter_dlg_apply_cb(GtkWidget *apply_bt, gpointer dummy);
static void filter_apply(GtkWidget *main_w, gboolean destroy);
static void filter_dlg_save_cb(GtkWidget *save_bt, gpointer parent_w);
static void filter_dlg_destroy_cb(GtkWidget *win, gpointer data);

static gboolean
filter_dlg_delete_event_cb(GtkWidget *prefs_w, GdkEvent *event, gpointer data);
static void
filter_dlg_cancel_cb(GtkWidget *cancel_bt, gpointer data);

static gint filter_sel_list_button_cb(GtkWidget *, GdkEventButton *,
                                      gpointer);
#if GTK_MAJOR_VERSION < 2
static void filter_sel_list_cb(GtkWidget *, gpointer);
#else
static void filter_sel_list_cb(GtkTreeSelection *, gpointer);
#endif
static void filter_new_bt_clicked_cb(GtkWidget *, gpointer);
static void filter_del_bt_clicked_cb(GtkWidget *, gpointer);
static void filter_name_te_changed_cb(GtkWidget *, gpointer);

#ifdef HAVE_LIBPCAP
/* Create a filter dialog for constructing a capture filter.

   This is to be used as a callback for a button next to a text entry box,
   which, when clicked, pops up this dialog to allow you to construct a
   display filter by browsing the list of saved filters (the dialog
   for constructing expressions assumes display filter syntax, not
   capture filter syntax).  The "OK" button sets the text entry box to the
   constructed filter and activates that text entry box (which should have
   no effect in the main capture dialog); this dialog is then dismissed. */
void
capture_filter_construct_cb(GtkWidget *w, gpointer user_data _U_)
{
	GtkWidget *filter_browse_w;
	GtkWidget *parent_filter_te;
	/* No Apply button, and "OK" just sets our text widget, it doesn't
	   activate it (i.e., it doesn't cause us to try to open the file). */
	static construct_args_t args = {
		"Wireshark: Capture Filter",
		FALSE,
		FALSE,
        FALSE
	};

	/* Has a filter dialog box already been opened for that button? */
	filter_browse_w = OBJECT_GET_DATA(w, E_FILT_DIALOG_PTR_KEY);

	if (filter_browse_w != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(filter_browse_w);
		return;
	}

	/* No.  Get the text entry attached to the button. */
	parent_filter_te = OBJECT_GET_DATA(w, E_FILT_TE_PTR_KEY);

	/* Now create a new dialog, without an "Add Expression..." button. */
	filter_browse_w = filter_dialog_new(w, parent_filter_te,
	    CFILTER_LIST, &args);
}
#endif

/* Create a filter dialog for constructing a display filter.

   This is to be used as a callback for a button next to a text entry box,
   which, when clicked, pops up this dialog to allow you to construct a
   display filter by browsing the list of saved filters and/or by adding
   test expressions constructed with another dialog.  The "OK" button
   sets the text entry box to the constructed filter and activates that
   text entry box, causing the filter to be used; this dialog is then
   dismissed.

   If "wants_apply_button" is non-null, we add an "Apply" button that
   acts like "OK" but doesn't dismiss this dialog. */
void
display_filter_construct_cb(GtkWidget *w, gpointer construct_args_ptr)
{
	construct_args_t *construct_args = construct_args_ptr;
	GtkWidget *filter_browse_w;
	GtkWidget *parent_filter_te;

	/* Has a filter dialog box already been opened for the button? */
	filter_browse_w = OBJECT_GET_DATA(w, E_FILT_DIALOG_PTR_KEY);

	if (filter_browse_w != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(filter_browse_w);
		return;
	}

	/* No.  Get the text entry attached to the button. */
	parent_filter_te = OBJECT_GET_DATA(w, E_FILT_TE_PTR_KEY);

	/* Now create a new dialog, possibly with an "Apply" button, and
	   definitely with an "Add Expression..." button. */
	filter_browse_w = filter_dialog_new(w, parent_filter_te,
	    DFILTER_LIST, construct_args);
}

/* Should be called when a button that creates filters is destroyed; it
   destroys any filter dialog created by that button. */
void
filter_button_destroy_cb(GtkWidget *button, gpointer user_data _U_)
{
	GtkWidget *filter_w;

	/* Is there a filter edit/selection dialog associated with this
	   button? */
	filter_w = OBJECT_GET_DATA(button, E_FILT_DIALOG_PTR_KEY);

	if (filter_w != NULL) {
		/* Yes.  Break the association, and destroy the dialog. */
		OBJECT_SET_DATA(button, E_FILT_DIALOG_PTR_KEY, NULL);
		window_destroy(filter_w);
	}
}

#ifdef HAVE_LIBPCAP
static GtkWidget *global_cfilter_w;

/* Create a filter dialog for editing capture filters; this is to be used
   as a callback for menu items, toolbars, etc.. */
void
cfilter_dialog_cb(GtkWidget *w _U_)
{
	/* No Apply button, and there's no text widget to set, much less
	   activate, on "OK". */
	static construct_args_t args = {
		"Wireshark: Capture Filter",
		FALSE,
		FALSE,
        FALSE
	};

	/* Has a filter dialog box already been opened for editing
	   capture filters? */
	if (global_cfilter_w != NULL) {
		/* Yes.  Just reactivate it. */
		reactivate_window(global_cfilter_w);
		return;
	}

	/*
	 * No.  Create one; we didn't pop this up as a result of pressing
	 * a button next to some text entry field, so don't associate it
	 * with a text entry field or button.
	 */
	global_cfilter_w = filter_dialog_new(NULL, NULL, CFILTER_LIST, &args);
}
#endif

/* Create a filter dialog for editing display filters; this is to be used
   as a callback for menu items, toolbars, etc.. */
void
dfilter_dialog_cb(GtkWidget *w _U_)
{
	static construct_args_t args = {
		"Wireshark: Display Filter",
		TRUE,
		TRUE,
        FALSE
	};

    display_filter_construct_cb(OBJECT_GET_DATA(top_level, E_FILT_BT_PTR_KEY), &args);
}

/* List of capture filter dialogs, so that if the list of filters changes
  (the model, if you will), we can update all of their lists displaying
   the filters (the views). */
static GList *cfilter_dialogs;

/* List of display filter dialogs, so that if the list of filters changes
  (the model, if you will), we can update all of their lists displaying
   the filters (the views). */
static GList *dfilter_dialogs;

static void
remember_filter_dialog(GtkWidget *main_w, GList **filter_dialogs)
{
	*filter_dialogs = g_list_append(*filter_dialogs, main_w);
}

/* Remove a filter dialog from the specified list of filter_dialogs. */
static void
forget_filter_dialog(GtkWidget *main_w, filter_list_type_t list_type)
{
	switch (list_type) {

	case CFILTER_EDITED_LIST:
		cfilter_dialogs = g_list_remove(cfilter_dialogs, main_w);
		break;

	case DFILTER_EDITED_LIST:
		dfilter_dialogs = g_list_remove(dfilter_dialogs, main_w);
		break;

	default:
		g_assert_not_reached();
		break;
	}
}

/* Get the dialog list corresponding to a particular filter list. */
static GList *
get_filter_dialog_list(filter_list_type_t list_type)
{
	switch (list_type) {

	case CFILTER_EDITED_LIST:
		return cfilter_dialogs;

	case DFILTER_EDITED_LIST:
		return dfilter_dialogs;

	default:
		g_assert_not_reached();
		return NULL;
	}
}


static void
fill_list(GtkWidget  *main_w, filter_list_type_t list_type)
{
    GList      *fl_entry;
    filter_def *filt;
    const gchar *filter_te_str = NULL;
#if GTK_MAJOR_VERSION < 2
    GtkWidget  *nl_item,
               *nl_lb,
               *l_select = NULL;
    GtkWidget  *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
#else
    gboolean           l_select = FALSE;
    GtkTreeView        *filter_l;
    GtkListStore       *store;
    GtkTreeIter        iter;
    GtkTreeIter        sel_iter;

    filter_l = GTK_TREE_VIEW(OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY));
    store = GTK_LIST_STORE(gtk_tree_view_get_model(filter_l));
#endif

    /* fill in data */
    fl_entry = get_filter_list_first(list_type);
    while (fl_entry != NULL) {
        filt    = (filter_def *) fl_entry->data;
#if GTK_MAJOR_VERSION < 2
        nl_lb   = gtk_label_new(filt->name);
        nl_item = gtk_list_item_new();

        SIGNAL_CONNECT(nl_item, "button_press_event", filter_sel_list_button_cb,
                       filter_l);

        gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
        gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
        gtk_widget_show(nl_lb);
        gtk_container_add(GTK_CONTAINER(filter_l), nl_item);
        gtk_widget_show(nl_item);
        OBJECT_SET_DATA(nl_item, E_FILT_LBL_KEY, nl_lb);
        OBJECT_SET_DATA(nl_item, E_FILT_LIST_ITEM_MODEL_KEY, fl_entry);
#else
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter, 0, filt->name,
                           1, fl_entry, -1);
#endif

        if (filter_te_str && filt->strval) {
            if (strcmp(filter_te_str, filt->strval) == 0) {
#if GTK_MAJOR_VERSION < 2 
                l_select = nl_item;
#else
                sel_iter = iter;
                l_select = TRUE;
#endif
            }
        }

        fl_entry = fl_entry->next;
    }
}

static void
clear_list(GtkWidget *main_w) {
    GtkWidget    *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(filter_l));
#endif

#if GTK_MAJOR_VERSION < 2
    gtk_list_clear_items(GTK_LIST(filter_l), 0, -1);
#else
    gtk_list_store_clear(GTK_LIST_STORE(model));
#endif
}

static GtkWidget *
filter_dialog_new(GtkWidget *button, GtkWidget *parent_filter_te,
                  filter_list_type_t list_type, construct_args_t *construct_args)
{
    GtkWidget  *main_w,           /* main window */
               *main_vb,          /* main container */
               *bbox,             /* button container */
               *ok_bt,            /* "OK" button */
               *apply_bt,         /* "Apply" button */
               *save_bt,          /* "Save" button */
               *cancel_bt,        /* "Cancel" button */
               *help_bt;          /* "Help" button */
    GtkWidget  *filter_vb,        /* filter settings box */
               *props_vb;
    GtkWidget  *top_hb,
               *list_bb,
               *new_bt,
               *del_bt,
               *filter_sc,
               *filter_l,
               *middle_hb,
               *name_lb,
               *name_te,
               *bottom_hb,
               *filter_lb,
               *filter_te,
               *add_expression_bt,
               *filter_fr,
               *edit_fr,
               *props_fr;
    GtkTooltips *tooltips;
    static filter_list_type_t cfilter_list_type = CFILTER_EDITED_LIST;
    static filter_list_type_t dfilter_list_type = DFILTER_EDITED_LIST;
    filter_list_type_t *filter_list_type_p;
    GList       **filter_dialogs;
    const gchar *filter_te_str = NULL;
#if GTK_MAJOR_VERSION < 2
    GtkWidget   *l_select = NULL;
#else
    gboolean           l_select = FALSE;
    GtkListStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    GtkTreeIter        sel_iter;
#endif

    /* Get a pointer to a static variable holding the type of filter on
       which we're working, so we can pass that pointer to callback
       routines. */
    switch (list_type) {

    case CFILTER_LIST:
        filter_dialogs = &cfilter_dialogs;
        filter_list_type_p = &cfilter_list_type;
        list_type = CFILTER_EDITED_LIST;
        break;

    case DFILTER_LIST:
        filter_dialogs = &dfilter_dialogs;
        filter_list_type_p = &dfilter_list_type;
        list_type = DFILTER_EDITED_LIST;
        break;

    default:
        g_assert_not_reached();
        filter_dialogs = NULL;
        filter_list_type_p = NULL;
        break;
    }

    tooltips = gtk_tooltips_new ();

    main_w = dlg_window_new(construct_args->title);
	gtk_window_set_default_size(GTK_WINDOW(main_w), 400, 400);
    OBJECT_SET_DATA(main_w, E_FILT_CONSTRUCT_ARGS_KEY, construct_args);

    if(construct_args->modal_and_transient) {
        GdkWindow*  parent = gtk_widget_get_parent_window(parent_filter_te);
        gtk_window_set_transient_for(GTK_WINDOW(main_w), GTK_WINDOW(parent));
        gtk_window_set_modal(GTK_WINDOW(main_w), TRUE);
    }

    main_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(main_w), main_vb);
    gtk_widget_show(main_vb);

    /* Make sure everything is set up */
    if (parent_filter_te)
        filter_te_str = gtk_entry_get_text(GTK_ENTRY(parent_filter_te));

    /* Container for each row of widgets */
    filter_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_border_width(GTK_CONTAINER(filter_vb), 0);
    gtk_container_add(GTK_CONTAINER(main_vb), filter_vb);
    gtk_widget_show(filter_vb);

    /* Top row: Buttons and filter list */
    top_hb = gtk_hbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(filter_vb), top_hb);
    gtk_widget_show(top_hb);

    edit_fr = gtk_frame_new("Edit");
    gtk_box_pack_start(GTK_BOX(top_hb), edit_fr, FALSE, FALSE, 0);
    gtk_widget_show(edit_fr);

    list_bb = gtk_vbox_new(TRUE, 0);
    gtk_container_border_width(GTK_CONTAINER(list_bb), 5);
    gtk_container_add(GTK_CONTAINER(edit_fr), list_bb);
    gtk_widget_show(list_bb);

    new_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_NEW);
    SIGNAL_CONNECT(new_bt, "clicked", filter_new_bt_clicked_cb, filter_list_type_p);
#if GTK_MAJOR_VERSION < 2
    WIDGET_SET_SIZE(new_bt, 50, 20);
#endif
    gtk_widget_show(new_bt);
    gtk_box_pack_start (GTK_BOX (list_bb), new_bt, FALSE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, new_bt, 
        "Create a new filter at the end of the list (with the current properties)", NULL);

    del_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_DELETE);
    gtk_widget_set_sensitive(del_bt, FALSE);
    SIGNAL_CONNECT(del_bt, "clicked", filter_del_bt_clicked_cb, filter_list_type_p);
    OBJECT_SET_DATA(main_w, E_FILT_DEL_BT_KEY, del_bt);
#if GTK_MAJOR_VERSION < 2
    WIDGET_SET_SIZE(del_bt, 50, 20);
#endif
    gtk_widget_show(del_bt);
    gtk_box_pack_start (GTK_BOX (list_bb), del_bt, FALSE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, del_bt, ("Delete the selected filter"), NULL);

    filter_fr = gtk_frame_new("Filter");
    gtk_box_pack_start(GTK_BOX(top_hb), filter_fr, TRUE, TRUE, 0);
    gtk_widget_show(filter_fr);

    filter_sc = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(filter_sc), 
                                   GTK_SHADOW_IN);
#endif

    gtk_container_set_border_width  (GTK_CONTAINER (filter_sc), 5);
    gtk_container_add(GTK_CONTAINER(filter_fr), filter_sc);
    gtk_widget_show(filter_sc);

#if GTK_MAJOR_VERSION < 2
    filter_l = gtk_list_new();
    gtk_list_set_selection_mode(GTK_LIST(filter_l), GTK_SELECTION_SINGLE);
    SIGNAL_CONNECT(filter_l, "selection_changed", filter_sel_list_cb,
                   filter_vb);
#else
    store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_POINTER);
    filter_l = tree_view_new(GTK_TREE_MODEL(store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(filter_l), FALSE);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("", renderer, "text",
                                                      0, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_append_column(GTK_TREE_VIEW(filter_l), column);
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
    SIGNAL_CONNECT(sel, "changed", filter_sel_list_cb, filter_vb);
    SIGNAL_CONNECT(filter_l, "button_press_event", filter_sel_list_button_cb,
                   NULL);
#endif
    OBJECT_SET_DATA(main_w, E_FILT_FILTER_L_KEY, filter_l);
#if GTK_MAJOR_VERSION < 2
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(filter_sc),
                                          filter_l);
#else
    gtk_container_add(GTK_CONTAINER(filter_sc), filter_l);
#endif
    gtk_widget_show(filter_l);

    OBJECT_SET_DATA(filter_l, E_FILT_DBLFUNC_KEY, filter_dlg_dclick);
    OBJECT_SET_DATA(filter_l, E_FILT_DBLARG_KEY, main_w);
    /* This is a Boolean, but we make it a non-null pointer for TRUE
       and a null pointer for FALSE, as object data is a pointer. */
    OBJECT_SET_DATA(filter_l, E_FILT_DBLACTIVATE_KEY,
                    construct_args->activate_on_ok ? "" : NULL);

    /* fill in data */
    fill_list(main_w, list_type);

#if GTK_MAJOR_VERSION >= 2 
    g_object_unref(G_OBJECT(store));
#endif


    props_fr = gtk_frame_new("Properties");
    gtk_box_pack_start(GTK_BOX(filter_vb), props_fr, FALSE, FALSE, 0);
    gtk_widget_show(props_fr);

    props_vb = gtk_vbox_new(FALSE, 3);
    gtk_container_border_width(GTK_CONTAINER(props_vb), 5);
    gtk_container_add(GTK_CONTAINER(props_fr), props_vb);
    gtk_widget_show(props_vb);

    /* row: Filter name entry */
    middle_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(props_vb), middle_hb);
    gtk_widget_show(middle_hb);

    name_lb = gtk_label_new("Filter name:");
    gtk_box_pack_start(GTK_BOX(middle_hb), name_lb, FALSE, FALSE, 0);
    gtk_widget_show(name_lb);

    name_te = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(middle_hb), name_te, TRUE, TRUE, 0);
    OBJECT_SET_DATA(main_w, E_FILT_NAME_TE_KEY, name_te);
    SIGNAL_CONNECT(name_te, "changed", filter_name_te_changed_cb, filter_list_type_p);
    gtk_widget_show(name_te);

    /* row: Filter text entry */
    bottom_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(props_vb), bottom_hb);
    gtk_widget_show(bottom_hb);

    filter_lb = gtk_label_new("Filter string:");
    gtk_box_pack_start(GTK_BOX(bottom_hb), filter_lb, FALSE, FALSE, 0);
    gtk_widget_show(filter_lb);

    filter_te = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(bottom_hb), filter_te, TRUE, TRUE, 0);
    OBJECT_SET_DATA(main_w, E_FILT_FILTER_TE_KEY, filter_te);
    SIGNAL_CONNECT(filter_te, "changed", filter_name_te_changed_cb, filter_list_type_p);
    gtk_widget_show(filter_te);

    OBJECT_SET_DATA(main_w, E_FILT_PARENT_FILTER_TE_KEY, parent_filter_te);

    if (list_type == DFILTER_EDITED_LIST) {
        gtk_tooltips_set_tip(tooltips, filter_te, 
            "Enter a display filter. "
            "The background color of this field is changed by a continuous syntax check (green is valid, red is invalid).", 
            NULL);

        /* Create the "Add Expression..." button, to pop up a dialog
           for constructing filter comparison expressions. */
        add_expression_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_ADD_EXPRESSION);
        SIGNAL_CONNECT(add_expression_bt, "clicked", filter_add_expr_bt_cb, main_w);
        gtk_box_pack_start(GTK_BOX(bottom_hb), add_expression_bt, FALSE, FALSE, 0);
        gtk_widget_show(add_expression_bt);
        gtk_tooltips_set_tip (tooltips, add_expression_bt, ("Add an expression to the filter string"), NULL);
    }


    /* button row */
    if (parent_filter_te != NULL) {
        if (construct_args->wants_apply_button) {
            bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
        } else {
            bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
        }
    } else {
        if (construct_args->wants_apply_button) {
            bbox = dlg_button_row_new(GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
        } else {
            bbox = dlg_button_row_new(GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
        }
    }
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);
    gtk_widget_show(bbox);

    ok_bt = NULL;
    if (parent_filter_te != NULL) {
        /*
         * We have a filter text entry that we can fill in if
         * the "OK" button is clicked, so put in an "OK" button.
         */
        ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
        SIGNAL_CONNECT(ok_bt, "clicked", filter_dlg_ok_cb, NULL);
        gtk_tooltips_set_tip (tooltips, ok_bt, ("Apply the filters and close this dialog"), NULL);

        /* Catch the "activate" signal on the filter name and filter
           expression text entries, so that if the user types Return
           there, we act as if the "OK" button had been selected, as
           happens if Return is typed if some widget that *doesn't*
           handle the Return key has the input focus. */
        dlg_set_activate(name_te, ok_bt);
        dlg_set_activate(filter_te, ok_bt);
    }

    if (construct_args->wants_apply_button) {
        apply_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_APPLY);
        SIGNAL_CONNECT(apply_bt, "clicked", filter_dlg_apply_cb, NULL);
        gtk_tooltips_set_tip (tooltips, apply_bt, ("Apply the filters and keep this dialog open"), NULL);
    }

    save_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_SAVE);
    SIGNAL_CONNECT(save_bt, "clicked", filter_dlg_save_cb, filter_list_type_p);
    gtk_tooltips_set_tip (tooltips, save_bt, ("Save the filters permanently and keep this dialog open"), NULL);

    cancel_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    gtk_tooltips_set_tip (tooltips, cancel_bt, ("Cancel the changes"), NULL);
    SIGNAL_CONNECT(cancel_bt, "clicked", filter_dlg_cancel_cb, filter_list_type_p);

    help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
    if (list_type == CFILTER_EDITED_LIST) {
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_CAPTURE_FILTERS_DIALOG);
    } else {
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_DISPLAY_FILTERS_DIALOG);
    }
    gtk_tooltips_set_tip (tooltips, help_bt, ("Show topic specific help"), NULL);

    if(ok_bt) {
        gtk_widget_grab_default(ok_bt);
    }

    remember_filter_dialog(main_w, filter_dialogs);

    if (button != NULL) {
	/* This dialog box was created by a "Filter" button.
	   Set the E_FILT_BUTTON_PTR_KEY for the new dialog to point to
	   the button. */
	OBJECT_SET_DATA(main_w, E_FILT_BUTTON_PTR_KEY, button);

	/* Set the E_FILT_DIALOG_PTR_KEY for the button to point to us */
	OBJECT_SET_DATA(button, E_FILT_DIALOG_PTR_KEY, main_w);
    }

    /* DO SELECTION THINGS *AFTER* SHOWING THE DIALOG! */
    /* otherwise the updatings can get confused */
#if GTK_MAJOR_VERSION < 2 
    if (l_select) {
        gtk_list_select_child(GTK_LIST(filter_l), l_select);
    } else if (filter_te_str && filter_te_str[0]) {
        gtk_entry_set_text(GTK_ENTRY(name_te), "New filter");
        gtk_entry_set_text(GTK_ENTRY(filter_te), filter_te_str);
    }
#else
    if (l_select) {
        gtk_tree_selection_select_iter(sel, &sel_iter);        
    } else if (filter_te_str && filter_te_str[0]) {
        gtk_entry_set_text(GTK_ENTRY(name_te), "New filter");
        gtk_entry_set_text(GTK_ENTRY(filter_te), filter_te_str);
    }
#endif

    SIGNAL_CONNECT(main_w, "delete_event", filter_dlg_delete_event_cb, filter_list_type_p);
    SIGNAL_CONNECT(main_w, "destroy", filter_dlg_destroy_cb, filter_list_type_p);

    gtk_widget_show(main_w);
    window_present(main_w);

    return main_w;
}

static void
filter_dlg_dclick(GtkWidget *filter_l, gpointer main_w_arg, gpointer activate)
{
    GtkWidget  *main_w = GTK_WIDGET(main_w_arg);
    GtkWidget  *parent_filter_te =
        OBJECT_GET_DATA(main_w, E_FILT_PARENT_FILTER_TE_KEY);
    GList      *flp;
    filter_def *filt;
#if GTK_MAJOR_VERSION < 2
    GList      *sl;
    GtkObject  *l_item;
#else
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));
#endif

    if (parent_filter_te != NULL) {
        /*
         * We have a text entry widget associated with this dialog
         * box; is one of the filters in the list selected?
         */
#if GTK_MAJOR_VERSION < 2
        sl = GTK_LIST(filter_l)->selection;
        if (sl != NULL) {
#else
        if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
#endif
            /*
             * Yes.  Is there a filter definition for that filter?
             */
#if GTK_MAJOR_VERSION < 2
            l_item = GTK_OBJECT(sl->data);
            flp = (GList *)OBJECT_GET_DATA(l_item,
                                               E_FILT_LIST_ITEM_MODEL_KEY);
#else
            gtk_tree_model_get(model, &iter, 1, &flp, -1);
#endif
            if (flp) {
                /*
                 * Yes - put it in the text entry widget.
                 */
                filt = (filter_def *) flp->data;
                gtk_entry_set_text(GTK_ENTRY(parent_filter_te),
                                   filt->strval);

                /*
                 * Are we supposed to cause the filter we
                 * put there to be applied?
                 */
                if (activate != NULL) {
                    /*
                     * Yes - do so.
                     */
                    SIGNAL_EMIT_BY_NAME(parent_filter_te, "activate", NULL);
                }
            }
        }
    }

    window_destroy(main_w);
}

static void
filter_dlg_ok_cb(GtkWidget *ok_bt, gpointer data _U_)
{
	/*
	 * Destroy the dialog box and apply the filter.
	 */
	filter_apply(gtk_widget_get_toplevel(ok_bt), TRUE);
}

static void
filter_dlg_apply_cb(GtkWidget *apply_bt, gpointer dummy _U_)
{
	/*
	 * Apply the filter, but don't destroy the dialog box.
	 */
	filter_apply(gtk_widget_get_toplevel(apply_bt), FALSE);
}

static void
filter_apply(GtkWidget *main_w, gboolean destroy)
{
	construct_args_t *construct_args =
	    OBJECT_GET_DATA(main_w, E_FILT_CONSTRUCT_ARGS_KEY);
	GtkWidget        *parent_filter_te =
	    OBJECT_GET_DATA(main_w, E_FILT_PARENT_FILTER_TE_KEY);
	GtkWidget        *filter_te;
	const gchar      *filter_string;

	if (parent_filter_te != NULL) {
		/*
		 * We have a text entry widget associated with this dialog
		 * box; put the filter in our text entry widget into that
		 * text entry widget.
		 */
		filter_te = OBJECT_GET_DATA(main_w, E_FILT_FILTER_TE_KEY);
		filter_string =
                    (const gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));
		gtk_entry_set_text(GTK_ENTRY(parent_filter_te), filter_string);

	}

	if (destroy) {
		/*
		 * Destroy the filter dialog box.
		 */
		window_destroy(main_w);
	}

	if (parent_filter_te != NULL) {
		/*
		 * We have a text entry widget associated with this dialog
		 * box; activate that widget to cause the filter we put
		 * there to be applied if we're supposed to do so.
		 *
		 * We do this after dismissing the filter dialog box,
		 * as activating the widget the dialog box to which
		 * it belongs to be dismissed, and that may cause it
		 * to destroy our dialog box if the filter succeeds.
		 * This means that our subsequent attempt to destroy
		 * it will fail.
		 *
		 * We don't know whether it'll destroy our dialog box,
		 * so we can't rely on it to do so.  Instead, we
		 * destroy it ourselves, which will clear the
		 * E_FILT_DIALOG_PTR_KEY pointer for their dialog box,
		 * meaning they won't think it has one and won't try
		 * to destroy it.
		 */
		if (construct_args->activate_on_ok) {
			SIGNAL_EMIT_BY_NAME(parent_filter_te, "activate", NULL);
		}
	}
}

static void
filter_dlg_save_cb(GtkWidget *save_bt _U_, gpointer data)
{
	filter_list_type_t list_type = *(filter_list_type_t *)data;
	char *pf_dir_path;
	char *f_path;
	int f_save_errno;
        const char *filter_type;

	switch (list_type) {

	case CFILTER_EDITED_LIST:
		filter_type = "capture";
                list_type = CFILTER_LIST;
                copy_filter_list(CFILTER_LIST, CFILTER_EDITED_LIST);
		break;

	case DFILTER_EDITED_LIST:
		filter_type = "display";
                list_type = DFILTER_LIST;
                copy_filter_list(DFILTER_LIST, DFILTER_EDITED_LIST);
		break;

	default:
		g_assert_not_reached();
		filter_type = NULL;
		break;
	}

	/* Create the directory that holds personal configuration files,
	   if necessary.  */
	if (create_persconffile_dir(&pf_dir_path) == -1) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't create directory\n\"%s\"\nfor filter files: %s.",
		    pf_dir_path, strerror(errno));
		g_free(pf_dir_path);
		return;
	}

	save_filter_list(list_type, &f_path, &f_save_errno);
	if (f_path != NULL) {
		/* We had an error saving the filter. */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Could not save to your %s filter file\n\"%s\": %s.",
		    filter_type, f_path, strerror(f_save_errno));
		g_free(f_path);
	}
}

/* update a remaining dialog if another one was cancelled */
static void filter_dlg_update_list_cb(gpointer data, gpointer user_data)
{
    GtkWidget  *main_w = data;
    filter_list_type_t list_type = *(filter_list_type_t *)user_data;

    /* refill the list */
    clear_list(main_w);
    fill_list(main_w, list_type);
}

/* cancel button pressed, revert changes and exit dialog */
static void
filter_dlg_cancel_cb(GtkWidget *cancel_bt, gpointer data)
{
    filter_list_type_t list_type = *(filter_list_type_t *)data;
    GtkWidget  *main_w = gtk_widget_get_toplevel(cancel_bt);


    /* revert changes in the edited list */
    switch (list_type) {
    case CFILTER_EDITED_LIST:
            copy_filter_list(CFILTER_EDITED_LIST, CFILTER_LIST);
	    break;
    case DFILTER_EDITED_LIST:
            copy_filter_list(DFILTER_EDITED_LIST, DFILTER_LIST);
	    break;
    default:
	    g_assert_not_reached();
	    break;
    }

    window_destroy(GTK_WIDGET(main_w));

    /* update other open filter dialogs */
    g_list_foreach(get_filter_dialog_list(list_type), filter_dlg_update_list_cb, &list_type);
}

/* Treat this as a cancel, by calling "filter_dlg_cancel_cb()" */
static gboolean
filter_dlg_delete_event_cb(GtkWidget *main_w, GdkEvent *event _U_,
                           gpointer data)
{
  filter_dlg_cancel_cb(main_w, data);
  return FALSE;
}


static void
filter_dlg_destroy_cb(GtkWidget *win, gpointer data)
{
	filter_list_type_t list_type = *(filter_list_type_t *)data;
	GtkWidget *button;

	/* Get the button that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	button = OBJECT_GET_DATA(win, E_FILT_BUTTON_PTR_KEY);

	if (button != NULL) {
		/* Tell it we no longer exist. */
		OBJECT_SET_DATA(button, E_FILT_DIALOG_PTR_KEY, NULL);
	} else {
		/* This is an editing dialog popped up from, for example,
		   a menu item; note that we no longer have one. */
		switch (list_type) {

#ifdef HAVE_LIBPCAP
		case CFILTER_EDITED_LIST:
			g_assert(win == global_cfilter_w);
			global_cfilter_w = NULL;
			break;
#endif
		default:
			g_assert_not_reached();
			break;
		}
	}

	/* Remove this from the list of filter dialog windows. */
	forget_filter_dialog(win, list_type);
}

#if GTK_MAJOR_VERSION < 2
static gint
filter_sel_list_button_cb(GtkWidget *widget, GdkEventButton *event,
                          gpointer func_data)
#else
static gint
filter_sel_list_button_cb(GtkWidget *list, GdkEventButton *event,
                          gpointer data _U_)
#endif
{
#if GTK_MAJOR_VERSION < 2
    GtkWidget *list = func_data;
#endif
    void (* func)(GtkWidget *, gpointer, gpointer);
    gpointer func_arg;
    gpointer func_activate;

#if GTK_MAJOR_VERSION < 2
    if (!GTK_IS_LIST_ITEM(widget)) return FALSE;
#endif
    if (event->type == GDK_2BUTTON_PRESS) {
        func = OBJECT_GET_DATA(list, E_FILT_DBLFUNC_KEY);
        func_arg = OBJECT_GET_DATA(list, E_FILT_DBLARG_KEY);
        func_activate = OBJECT_GET_DATA(list, E_FILT_DBLACTIVATE_KEY);

        if (func)
            (*func)(list, func_arg, func_activate);
    }

    return FALSE;
}

#if GTK_MAJOR_VERSION < 2
static void
filter_sel_list_cb(GtkWidget *l, gpointer data _U_)
#else
static void
filter_sel_list_cb(GtkTreeSelection *sel, gpointer data _U_)
#endif
{
#if GTK_MAJOR_VERSION < 2
    GtkWidget    *main_w = gtk_widget_get_toplevel(l);
    GList        *sl;
    GtkObject    *l_item;
#else
    GtkWidget    *filter_l = GTK_WIDGET(gtk_tree_selection_get_tree_view(sel));
    GtkWidget    *main_w = gtk_widget_get_toplevel(filter_l);
    GtkTreeModel *model;
    GtkTreeIter   iter;
#endif
    GtkWidget    *name_te = OBJECT_GET_DATA(main_w, E_FILT_NAME_TE_KEY);
    GtkWidget    *filter_te = OBJECT_GET_DATA(main_w, E_FILT_FILTER_TE_KEY);
    GtkWidget    *chg_bt = OBJECT_GET_DATA(main_w, E_FILT_CHG_BT_KEY);
    GtkWidget    *copy_bt = OBJECT_GET_DATA(main_w, E_FILT_COPY_BT_KEY);
    GtkWidget    *del_bt = OBJECT_GET_DATA(main_w, E_FILT_DEL_BT_KEY);
    filter_def   *filt;
    gchar        *name = NULL, *strval = NULL;
    GList        *flp;
    gint          sensitivity = FALSE;

#if GTK_MAJOR_VERSION < 2
    if (l)
        sl = GTK_LIST(l)->selection;
    else
        sl = NULL;

    if (sl) {  /* Something was selected */
        l_item = GTK_OBJECT(sl->data);
        flp    = (GList *) OBJECT_GET_DATA(l_item, E_FILT_LIST_ITEM_MODEL_KEY);
#else
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 1, &flp, -1);
#endif
        if (flp) {
            filt   = (filter_def *) flp->data;
            name   = g_strdup(filt->name);
            strval = g_strdup(filt->strval);
            sensitivity = TRUE;
        }
    }

    /*
     * Did you know that this function is called when the window is destroyed?
     * Funny, that.
     * This means that we have to:
     *
     *	attach to the top-level window data items containing pointers to
     *	the widgets we affect here;
     *
     *	give each of those widgets their own destroy callbacks;
     *
     *	clear that pointer when the widget is destroyed;
     *
     *	don't do anything to the widget if the pointer we get back is
     *	null;
     *
     * so that if we're called after any of the widgets we'd affect are
     * destroyed, we know that we shouldn't do anything to those widgets.
     */
    if (name_te != NULL)
        gtk_entry_set_text(GTK_ENTRY(name_te), name ? name : "");
    if (filter_te != NULL)
        gtk_entry_set_text(GTK_ENTRY(filter_te), strval ? strval : "");
    if (chg_bt != NULL)
        gtk_widget_set_sensitive(chg_bt, sensitivity);
    if (copy_bt != NULL)
        gtk_widget_set_sensitive(copy_bt, sensitivity);
    if (del_bt != NULL)
        gtk_widget_set_sensitive(del_bt, sensitivity);
    if (name != NULL)
        g_free(name);
    if (strval != NULL)
        g_free(strval);
}

/* To do: add input checking to each of these callbacks */

/* Structure containing arguments to be passed to "new_filter_cb()".

   "active_filter_l" is the list in the dialog box in which "New" or
   "Copy" was clicked; in that dialog box, but not in any other dialog
   box, we select the newly created list item.

   "nflp" is the GList member in the model (filter list) for the new
   filter. */
typedef struct {
	GtkWidget *active_filter_l;
	GList     *nflp;
} new_filter_cb_args_t;

static void
new_filter_cb(gpointer data, gpointer user_data)
{
    GtkWidget    *main_w = data;
#if GTK_MAJOR_VERSION < 2
    GtkWidget    *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
    GtkWidget    *nl_lb, *nl_item;
#else
    GtkTreeView  *filter_l;
    GtkListStore *store;
    GtkTreeIter   iter;
#endif
    new_filter_cb_args_t *args = user_data;
    filter_def *nfilt = args->nflp->data;

#if GTK_MAJOR_VERSION < 2
    nl_lb        = gtk_label_new(nfilt->name);
    nl_item      = gtk_list_item_new();
    gtk_misc_set_alignment(GTK_MISC(nl_lb), 0.0, 0.5);
    gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
    gtk_widget_show(nl_lb);
    gtk_container_add(GTK_CONTAINER(filter_l), nl_item);
    gtk_widget_show(nl_item);
    OBJECT_SET_DATA(nl_item, E_FILT_LBL_KEY, nl_lb);
    OBJECT_SET_DATA(GTK_OBJECT(nl_item), E_FILT_LIST_ITEM_MODEL_KEY,
                        args->nflp);
    if (filter_l == args->active_filter_l) {
        /* Select the item. */
        gtk_list_select_child(GTK_LIST(filter_l), nl_item);
    }
#else
    filter_l = GTK_TREE_VIEW(OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY));
    store = GTK_LIST_STORE(gtk_tree_view_get_model(filter_l));
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, nfilt->name, 1, args->nflp, -1);
    if (GTK_WIDGET(filter_l) == args->active_filter_l) {
        /* Select the item. */
        gtk_tree_selection_select_iter(gtk_tree_view_get_selection(filter_l),
                                       &iter);
    }
#endif
}

static void
filter_new_bt_clicked_cb(GtkWidget *w, gpointer data)
{
  GtkWidget  *main_w = gtk_widget_get_toplevel(w);
  GtkWidget  *name_te = OBJECT_GET_DATA(main_w, E_FILT_NAME_TE_KEY);
  GtkWidget  *filter_te = OBJECT_GET_DATA(main_w, E_FILT_FILTER_TE_KEY);
  GtkWidget  *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
  filter_list_type_t list_type = *(filter_list_type_t *)data;
  GList      *fl_entry;
  const gchar *name, *strval;
  new_filter_cb_args_t args;

  name   = gtk_entry_get_text(GTK_ENTRY(name_te));
  strval = gtk_entry_get_text(GTK_ENTRY(filter_te));

  /* if the user didn't entered a name, set default one */
  if (strlen(name) == 0) {
    name = "new";
  }

  /* if the user didn't entered a string value, set default one */
  if (strlen(strval) == 0) {
    strval = "new";
  }

    /* Add a new entry to the filter list. */
    fl_entry = add_to_filter_list(list_type, name, strval);

    /* Update all the filter list widgets, not just the one in
       the dialog box in which we clicked on "Copy". */
    args.active_filter_l = filter_l;
    args.nflp = fl_entry;
    g_list_foreach(get_filter_dialog_list(list_type), new_filter_cb, &args);

}

#if GTK_MAJOR_VERSION < 2
static void
chg_list_item_cb(GtkWidget *nl_item, gpointer data)
#else
static gboolean
chg_list_item_cb(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
                 gpointer data)
#endif
{
    GList      *flp = data;
    filter_def *filt = flp->data;
#if GTK_MAJOR_VERSION < 2
    GtkLabel   *nl_lb =
        GTK_LABEL(OBJECT_GET_DATA(nl_item, E_FILT_LBL_KEY));
    GList      *nl_model =
        OBJECT_GET_DATA(nl_item, E_FILT_LIST_ITEM_MODEL_KEY);
#else
    GList      *nl_model;
#endif

#if GTK_MAJOR_VERSION >= 2
    gtk_tree_model_get(model, iter, 1, &nl_model, -1);
#endif
    /* Is this the item corresponding to the filter list item in question? */
    if (flp == nl_model) {
        /* Yes - change the label to correspond to the new name for the
         * filter. */
#if GTK_MAJOR_VERSION < 2
        gtk_label_set(nl_lb, filt->name);
#else
        gtk_list_store_set(GTK_LIST_STORE(model), iter, 0, filt->name, -1);
        return TRUE;
#endif
    }
#if GTK_MAJOR_VERSION >= 2
    return FALSE;
#endif
}

static void
chg_filter_cb(gpointer data, gpointer user_data)
{
    GtkWidget  *main_w = data;
    GtkWidget  *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);

#if GTK_MAJOR_VERSION < 2
    gtk_container_foreach(GTK_CONTAINER(filter_l), chg_list_item_cb, user_data);
#else
    gtk_tree_model_foreach(gtk_tree_view_get_model(GTK_TREE_VIEW(filter_l)),
                           chg_list_item_cb, user_data);
#endif
}

static void
filter_name_te_changed_cb(GtkWidget *w, gpointer data)
{
    GtkWidget  *main_w = gtk_widget_get_toplevel(w);
    GtkWidget  *name_te = OBJECT_GET_DATA(main_w, E_FILT_NAME_TE_KEY);
    GtkWidget  *filter_te = OBJECT_GET_DATA(main_w, E_FILT_FILTER_TE_KEY);
    GtkWidget  *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
    filter_def *filt;
    GList      *fl_entry;
    filter_list_type_t  list_type = *(filter_list_type_t *)data;
    const gchar         *name = "";
    const gchar         *strval = "";

#if GTK_MAJOR_VERSION < 2
    GList      *sl;
    GtkObject  *l_item;
    GtkLabel   *nl_lb;
#else
    GtkTreeSelection  *sel;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
#endif

#if GTK_MAJOR_VERSION < 2
    sl     = GTK_LIST(filter_l)->selection;
#else
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));
#endif
    name   = gtk_entry_get_text(GTK_ENTRY(name_te));
    strval = gtk_entry_get_text(GTK_ENTRY(filter_te));

    if (DFILTER_EDITED_LIST == list_type) {
        /* colorize filter string entry */
        filter_te_syntax_check_cb(filter_te);
    }

    /* if something was selected */
#if GTK_MAJOR_VERSION < 2
    if (sl) {
        l_item = GTK_OBJECT(sl->data);
        fl_entry = (GList *) OBJECT_GET_DATA(l_item,
                                                 E_FILT_LIST_ITEM_MODEL_KEY);
        nl_lb = (GtkLabel *) OBJECT_GET_DATA(l_item, E_FILT_LBL_KEY);
        if (fl_entry != NULL && nl_lb != NULL) {
#else
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 1, &fl_entry, -1);
        if (fl_entry != NULL) {
#endif
            filt = (filter_def *) fl_entry->data;

            if (strlen(name) > 0 && strlen(strval) > 0 && filt) {
                g_free(filt->name);
                g_free(filt->strval);
                filt->name   = g_strdup(name);
                filt->strval = g_strdup(strval);

                /* Update all the filter list widgets, not just the one in
                   the dialog box in which we clicked on "Copy". */
                g_list_foreach(get_filter_dialog_list(list_type), chg_filter_cb,
                               fl_entry);
            }
        }
    }
}

static void
delete_filter_cb(gpointer data, gpointer user_data)
{
    GtkWidget    *main_w = data;
    GtkWidget    *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
#if GTK_MAJOR_VERSION < 2
    gint          pos = *(gint *)user_data;
#else
    gchar        *pos = (gchar *)user_data;
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(filter_l));
    GtkTreeIter   iter;
#endif

#if GTK_MAJOR_VERSION < 2
    gtk_list_clear_items(GTK_LIST(filter_l), pos, pos + 1);
#else
    gtk_tree_model_get_iter_from_string(model, &iter, pos);
    gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
#endif
}

static void
filter_del_bt_clicked_cb(GtkWidget *w, gpointer data)
{
    GtkWidget  *main_w = gtk_widget_get_toplevel(w);
    GtkWidget  *filter_l = OBJECT_GET_DATA(main_w, E_FILT_FILTER_L_KEY);
    filter_list_type_t list_type = *(filter_list_type_t *)data;
    GList      *fl_entry;
#if GTK_MAJOR_VERSION < 2
    GList      *sl;
    GtkObject  *l_item;
    gint        pos;
#else
    gchar             *pos;
    GtkTreeSelection  *sel;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
    GtkTreePath       *path;
#endif

#if GTK_MAJOR_VERSION < 2
    sl = GTK_LIST(filter_l)->selection;
    if (sl) {  /* Something was selected */
        l_item = GTK_OBJECT(sl->data);
        pos    = gtk_list_child_position(GTK_LIST(filter_l),
                                         GTK_WIDGET(l_item));
        fl_entry = (GList *) OBJECT_GET_DATA(l_item, E_FILT_LIST_ITEM_MODEL_KEY);
#else
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));
    /* If something was selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 1, &fl_entry, -1);
        path = gtk_tree_model_get_path(model, &iter);
        pos = gtk_tree_path_to_string(path);
        gtk_tree_path_free(path);
#endif
        if (fl_entry != NULL) {
            /* Remove the entry from the filter list. */
            remove_from_filter_list(list_type, fl_entry);

            /* Update all the filter list widgets, not just the one in
               the dialog box in which we clicked on "Delete". */
#if GTK_MAJOR_VERSION < 2
            g_list_foreach(get_filter_dialog_list(list_type), delete_filter_cb,
                           &pos);
#else
            g_list_foreach(get_filter_dialog_list(list_type), delete_filter_cb, pos);
#endif
        }
#if GTK_MAJOR_VERSION >= 2
        g_free(pos);
#endif
    }
}

void
filter_add_expr_bt_cb(GtkWidget *w _U_, gpointer main_w_arg)
{
	GtkWidget  *main_w = GTK_WIDGET(main_w_arg);
	GtkWidget  *filter_te;

	filter_te = OBJECT_GET_DATA(main_w, E_FILT_FILTER_TE_KEY);
	dfilter_expr_dlg_new(filter_te);
}

static void
color_filter_te(GtkWidget *w, guint16 red, guint16 green, guint16 blue)
{
    GdkColor    bg;
    GtkStyle    *style;

    bg.pixel    = 0;
    bg.red      = red;
    bg.green    = green;
    bg.blue     = blue;

    style = gtk_style_copy(gtk_widget_get_style(w));
    style->base[GTK_STATE_NORMAL] = bg;
    gtk_widget_set_style(w, style);
    gtk_style_unref(style);
}

void
colorize_filter_te_as_empty(GtkWidget *w)
{
    /* white */
    color_filter_te(w, 0xFFFF, 0xFFFF, 0xFFFF);
}

void
colorize_filter_te_as_invalid(GtkWidget *w)
{
    /* light red */
    color_filter_te(w, 0xFFFF, 0xAFFF, 0xAFFF);
}

void
colorize_filter_te_as_valid(GtkWidget *w)
{
    /* light green */
    color_filter_te(w, 0xAFFF, 0xFFFF, 0xAFFF);
}

void
filter_te_syntax_check_cb(GtkWidget *w)
{
    const gchar *strval;
    dfilter_t   *dfp;

    strval = gtk_entry_get_text(GTK_ENTRY(w));

    /* colorize filter string entry */
    if (strval && dfilter_compile(strval, &dfp)) {
    	if (dfp != NULL)
    	  dfilter_free(dfp);
        if (strlen(strval) == 0)
            colorize_filter_te_as_empty(w);
        else
            colorize_filter_te_as_valid(w);
    } else
        colorize_filter_te_as_invalid(w);
}


