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
#include <epan/prefs.h>
#include <epan/proto.h>

#include "../filters.h"
#include "ui/simple_dialog.h"
#include "ui/main_statusbar.h"

#include "ui/gtk/main.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dfilter_expr_dlg.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/filter_autocomplete.h"

#include "ui/gtk/old-gtk-compat.h"

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
static void filter_dlg_ok_cb(GtkWidget *ok_bt, gpointer data);
static void filter_dlg_apply_cb(GtkWidget *apply_bt, gpointer data);
static void filter_apply(GtkWidget *main_w, gboolean destroy);
static void filter_dlg_save(filter_list_type_t list_type);
static void filter_dlg_save_cb(GtkWidget *save_bt, gpointer parent_w);
static void filter_dlg_destroy_cb(GtkWidget *win, gpointer data);

static gboolean
filter_dlg_delete_event_cb(GtkWidget *prefs_w, GdkEvent *event, gpointer data);
static void
filter_dlg_cancel_cb(GtkWidget *cancel_bt, gpointer data);

static gboolean filter_sel_list_button_cb(GtkWidget *, GdkEventButton *,
                                      gpointer);
static void filter_sel_list_cb(GtkTreeSelection *, gpointer);
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
    filter_browse_w = g_object_get_data(G_OBJECT(w), E_FILT_DIALOG_PTR_KEY);

    if (filter_browse_w != NULL) {
        /* Yes.  Just re-activate that dialog box. */
        reactivate_window(filter_browse_w);
        return;
    }

    /* No.  Get the text entry attached to the button. */
    parent_filter_te = g_object_get_data(G_OBJECT(w), E_FILT_TE_PTR_KEY);

    /* Now create a new dialog, without an "Add Expression..." button. */
    filter_dialog_new(w, parent_filter_te, CFILTER_LIST, &args);
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
    filter_browse_w = g_object_get_data(G_OBJECT(w), E_FILT_DIALOG_PTR_KEY);

    if (filter_browse_w != NULL) {
        /* Yes.  Just re-activate that dialog box. */
        reactivate_window(filter_browse_w);
        return;
    }

    /* No.  Get the text entry attached to the button. */
    parent_filter_te = g_object_get_data(G_OBJECT(w), E_FILT_TE_PTR_KEY);

    /* Now create a new dialog, possibly with an "Apply" button, and
       definitely with an "Add Expression..." button. */
    filter_dialog_new(w, parent_filter_te, DFILTER_LIST, construct_args);
}

/* Should be called when a button that creates filters is destroyed; it
   destroys any filter dialog created by that button. */
void
filter_button_destroy_cb(GtkWidget *button, gpointer user_data _U_)
{
    GtkWidget *filter_w;

    /* Is there a filter edit/selection dialog associated with this
       button? */
    filter_w = g_object_get_data(G_OBJECT(button), E_FILT_DIALOG_PTR_KEY);

    if (filter_w != NULL) {
        /* Yes.  Break the association, and destroy the dialog. */
        g_object_set_data(G_OBJECT(button), E_FILT_DIALOG_PTR_KEY, NULL);
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

        display_filter_construct_cb(g_object_get_data(G_OBJECT(top_level), E_FILT_BT_PTR_KEY), &args);
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


static GtkTreeIter *
fill_list(GtkWidget  *main_w, filter_list_type_t list_type, const gchar *filter_te_str)
{
    GList      *fl_entry;
    filter_def *filt;
    GtkTreeView       *filter_l;
    GtkListStore      *store;
    GtkTreeIter       iter;
    GtkTreeIter       *l_select = NULL;

    filter_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY));
    store = GTK_LIST_STORE(gtk_tree_view_get_model(filter_l));

    /* fill in data */
    fl_entry = get_filter_list_first(list_type);
    while (fl_entry != NULL) {
        filt    = (filter_def *) fl_entry->data;
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter, 0, filt->name,
                   1, fl_entry, -1);

        if (filter_te_str && filt->strval) {
            if (strcmp(filter_te_str, filt->strval) == 0) {
                /*
                 * XXX - We're assuming that we can just copy a GtkTreeIter
                 * and use it later without any crashes.  This may not be a
                 * valid assumption.
                 */
                l_select = g_memdup(&iter, sizeof(iter));
            }
        }

        fl_entry = fl_entry->next;
    }
    return l_select;
}

#if 0
static void
clear_list(GtkWidget *main_w) {
    GtkWidget    *filter_l = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY);
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(filter_l));

    gtk_list_store_clear(GTK_LIST_STORE(model));
}
#endif /* 0 */

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
    GdkWindow  *parent;
    static filter_list_type_t cfilter_list_type = CFILTER_EDITED_LIST;
    static filter_list_type_t dfilter_list_type = DFILTER_EDITED_LIST;
    filter_list_type_t *filter_list_type_p;
    GList       **filter_dialogs;
    const gchar *filter_te_str = NULL;
    GtkListStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    GtkTreeIter       *l_select;
    gchar *list_name = NULL;

    /* Get a pointer to a static variable holding the type of filter on
       which we're working, so we can pass that pointer to callback
       routines. */
    switch (list_type) {

    case CFILTER_LIST:
        filter_dialogs = &cfilter_dialogs;
        filter_list_type_p = &cfilter_list_type;
        list_type = CFILTER_EDITED_LIST;
        list_name = "Capture Filter";
        break;

    case DFILTER_LIST:
        filter_dialogs = &dfilter_dialogs;
        filter_list_type_p = &dfilter_list_type;
        list_type = DFILTER_EDITED_LIST;
        list_name = "Display Filter";
        break;

    default:
        g_assert_not_reached();
        filter_dialogs = NULL;
        filter_list_type_p = NULL;
        break;
    }

    main_w = dlg_conf_window_new(construct_args->title);
    gtk_window_set_default_size(GTK_WINDOW(main_w), 400, 400);
    g_object_set_data(G_OBJECT(main_w), E_FILT_CONSTRUCT_ARGS_KEY, construct_args);

    main_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(main_w), main_vb);
    gtk_widget_show(main_vb);

    /* Make sure everything is set up */
    if (parent_filter_te)
        filter_te_str = gtk_entry_get_text(GTK_ENTRY(parent_filter_te));

    /* Container for each row of widgets */
    filter_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(filter_vb), 0);
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
    gtk_container_set_border_width(GTK_CONTAINER(list_bb), 5);
    gtk_container_add(GTK_CONTAINER(edit_fr), list_bb);
    gtk_widget_show(list_bb);

    new_bt = gtk_button_new_from_stock(GTK_STOCK_NEW);
    g_signal_connect(new_bt, "clicked", G_CALLBACK(filter_new_bt_clicked_cb), filter_list_type_p);
    gtk_widget_show(new_bt);
    gtk_box_pack_start (GTK_BOX (list_bb), new_bt, FALSE, FALSE, 0);
    gtk_widget_set_tooltip_text(new_bt, "Create a new filter at the end of the list (with the current properties)");

    del_bt = gtk_button_new_from_stock(GTK_STOCK_DELETE);
    gtk_widget_set_sensitive(del_bt, FALSE);
    g_signal_connect(del_bt, "clicked", G_CALLBACK(filter_del_bt_clicked_cb), filter_list_type_p);
    g_object_set_data(G_OBJECT(main_w), E_FILT_DEL_BT_KEY, del_bt);
    gtk_widget_show(del_bt);
    gtk_box_pack_start (GTK_BOX (list_bb), del_bt, FALSE, FALSE, 0);
    gtk_widget_set_tooltip_text(del_bt, "Delete the selected filter");

    filter_fr = gtk_frame_new(list_name);
    gtk_box_pack_start(GTK_BOX(top_hb), filter_fr, TRUE, TRUE, 0);
    gtk_widget_show(filter_fr);

    filter_sc = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(filter_sc),
                                   GTK_SHADOW_IN);

    gtk_container_set_border_width  (GTK_CONTAINER (filter_sc), 5);
    gtk_container_add(GTK_CONTAINER(filter_fr), filter_sc);
    gtk_widget_show(filter_sc);

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
    g_signal_connect(sel, "changed", G_CALLBACK(filter_sel_list_cb), NULL);
    g_signal_connect(filter_l, "button_press_event", G_CALLBACK(filter_sel_list_button_cb),
                   NULL);
    g_object_set_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY, filter_l);
    gtk_container_add(GTK_CONTAINER(filter_sc), filter_l);
    gtk_widget_show(filter_l);

    g_object_set_data(G_OBJECT(filter_l), E_FILT_DBLFUNC_KEY, filter_dlg_dclick);
    g_object_set_data(G_OBJECT(filter_l), E_FILT_DBLARG_KEY, main_w);
    /* This is a Boolean, but we make it a non-null pointer for TRUE
       and a null pointer for FALSE, as object data is a pointer. */
    g_object_set_data(G_OBJECT(filter_l), E_FILT_DBLACTIVATE_KEY,
                    construct_args->activate_on_ok ? "" : NULL);

    /* fill in data */
    l_select = fill_list(main_w, list_type, filter_te_str);

    g_object_unref(G_OBJECT(store));


    props_fr = gtk_frame_new("Properties");
    gtk_box_pack_start(GTK_BOX(filter_vb), props_fr, FALSE, FALSE, 0);
    gtk_widget_show(props_fr);

    props_vb = gtk_vbox_new(FALSE, 3);
    gtk_container_set_border_width(GTK_CONTAINER(props_vb), 5);
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
    g_object_set_data(G_OBJECT(main_w), E_FILT_NAME_TE_KEY, name_te);
    g_signal_connect(name_te, "changed", G_CALLBACK(filter_name_te_changed_cb), filter_list_type_p);
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
    g_object_set_data(G_OBJECT(main_w), E_FILT_FILTER_TE_KEY, filter_te);
    g_signal_connect(filter_te, "changed", G_CALLBACK(filter_name_te_changed_cb), filter_list_type_p);
    if (list_type == DFILTER_EDITED_LIST) {
        colorize_filter_te_as_empty(filter_te);

    g_object_set_data(G_OBJECT(main_w), E_FILT_AUTOCOMP_PTR_KEY, NULL);
    g_signal_connect(filter_te, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
    g_signal_connect(main_w, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
    }
    gtk_widget_show(filter_te);

    g_object_set_data(G_OBJECT(main_w), E_FILT_PARENT_FILTER_TE_KEY, parent_filter_te);

    if (list_type == DFILTER_EDITED_LIST) {
        gtk_widget_set_tooltip_text(filter_te,
            "Enter a display filter. "
            "The background color of this field is changed by a continuous syntax check"
              " (green is valid, red is invalid, yellow may have unexpected results).");

        /* Create the "Add Expression..." button, to pop up a dialog
           for constructing filter comparison expressions. */
        add_expression_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_ADD_EXPRESSION);
        g_signal_connect(add_expression_bt, "clicked", G_CALLBACK(filter_add_expr_bt_cb), main_w);
        gtk_box_pack_start(GTK_BOX(bottom_hb), add_expression_bt, FALSE, FALSE, 0);
        gtk_widget_show(add_expression_bt);
        gtk_widget_set_tooltip_text(add_expression_bt, "Add an expression to the filter string");
    }


    /* button row (create all possible buttons and hide the unrequired later - it's a lot easier) */
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);
    gtk_widget_show(bbox);

    ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(filter_dlg_ok_cb), filter_list_type_p);
    gtk_widget_set_tooltip_text(ok_bt, "Apply the filters and close this dialog");

    /* Catch the "activate" signal on the filter name and filter
       expression text entries, so that if the user types Return
       there, we act as if the "OK" button had been selected, as
       happens if Return is typed if some widget that *doesn't*
       handle the Return key has the input focus. */
    if (parent_filter_te != NULL) {
        dlg_set_activate(name_te, ok_bt);
        dlg_set_activate(filter_te, ok_bt);
    }

    apply_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_APPLY);
    g_signal_connect(apply_bt, "clicked", G_CALLBACK(filter_dlg_apply_cb), filter_list_type_p);
    gtk_widget_set_tooltip_text(apply_bt, "Apply the filters and keep this dialog open");

    save_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_SAVE);
    g_signal_connect(save_bt, "clicked", G_CALLBACK(filter_dlg_save_cb), filter_list_type_p);
    gtk_widget_set_tooltip_text(save_bt, "Save the filters permanently and keep this dialog open");

    cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
    gtk_widget_set_tooltip_text(cancel_bt, "Cancel the changes");
    g_signal_connect(cancel_bt, "clicked", G_CALLBACK(filter_dlg_cancel_cb), filter_list_type_p);
    window_set_cancel_button(main_w, cancel_bt, NULL);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    if (list_type == CFILTER_EDITED_LIST) {
        g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_CAPTURE_FILTERS_DIALOG);
    } else {
        g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_DISPLAY_FILTERS_DIALOG);
    }
    gtk_widget_set_tooltip_text(help_bt, "Show topic specific help");

    if(ok_bt) {
        gtk_widget_grab_default(ok_bt);
    }

    remember_filter_dialog(main_w, filter_dialogs);

    if (button != NULL) {
    /* This dialog box was created by a "Filter" button.
       Set the E_FILT_BUTTON_PTR_KEY for the new dialog to point to
       the button. */
    g_object_set_data(G_OBJECT(main_w), E_FILT_BUTTON_PTR_KEY, button);

    /* Set the E_FILT_DIALOG_PTR_KEY for the button to point to us */
    g_object_set_data(G_OBJECT(button), E_FILT_DIALOG_PTR_KEY, main_w);
    }

    /* DO SELECTION THINGS *AFTER* SHOWING THE DIALOG! */
    /* otherwise the updatings can get confused */
    if (l_select) {
        gtk_tree_selection_select_iter(sel, l_select);
        g_free(l_select);
    } else if (filter_te_str && filter_te_str[0]) {
        gtk_entry_set_text(GTK_ENTRY(name_te), "New filter");
        gtk_entry_set_text(GTK_ENTRY(filter_te), filter_te_str);
    }

    g_signal_connect(main_w, "delete_event", G_CALLBACK(filter_dlg_delete_event_cb), filter_list_type_p);
    g_signal_connect(main_w, "destroy", G_CALLBACK(filter_dlg_destroy_cb), filter_list_type_p);

    gtk_widget_show(main_w);

    if(construct_args->modal_and_transient) {
        parent = gtk_widget_get_parent_window(parent_filter_te);
        gdk_window_set_transient_for(gtk_widget_get_window(main_w), parent);
        gtk_window_set_modal(GTK_WINDOW(main_w), TRUE);
    }

    /* hide the Ok button, if we don't have to apply it and our caller wants a Save button */
    if (parent_filter_te == NULL && prefs.gui_use_pref_save) {
        gtk_widget_hide(ok_bt);
    }

    /* hide the Apply button, if our caller don't wants one */
    if (!construct_args->wants_apply_button) {
        gtk_widget_hide(apply_bt);
    }

    /* hide the Save button if the user uses implicit save */
    if (!prefs.gui_use_pref_save) {
        gtk_widget_hide(save_bt);
    }

    window_present(main_w);

    return main_w;
}

static void
filter_dlg_dclick(GtkWidget *filter_l, gpointer main_w_arg, gpointer activate)
{
    GtkWidget  *main_w = GTK_WIDGET(main_w_arg);
    GtkWidget  *parent_filter_te =
        g_object_get_data(G_OBJECT(main_w), E_FILT_PARENT_FILTER_TE_KEY);
    GList      *flp;
    filter_def *filt;
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));

    if (parent_filter_te != NULL) {
        /*
         * We have a text entry widget associated with this dialog
         * box; is one of the filters in the list selected?
         */
        if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
            /*
             * Yes.  Is there a filter definition for that filter?
             */
            gtk_tree_model_get(model, &iter, 1, &flp, -1);
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
                    g_signal_emit_by_name(G_OBJECT(parent_filter_te), "activate", NULL);
                }
            }
        }
    }

    window_destroy(main_w);
}

static void
filter_dlg_ok_cb(GtkWidget *ok_bt, gpointer data)
{
    filter_list_type_t list_type = *(filter_list_type_t *)data;

    /*
     * Destroy the dialog box and apply the filter.
     */
    filter_apply(gtk_widget_get_toplevel(ok_bt), TRUE);

    /* if we don't have a Save button, just save the settings now */
    if (!prefs.gui_use_pref_save) {
        filter_dlg_save(list_type);
    }
}

static void
filter_dlg_apply_cb(GtkWidget *apply_bt, gpointer data)
{
    filter_list_type_t list_type = *(filter_list_type_t *)data;

    /*
     * Apply the filter, but don't destroy the dialog box.
     */
    filter_apply(gtk_widget_get_toplevel(apply_bt), FALSE);

    /* if we don't have a Save button, just save the settings now */
    if (!prefs.gui_use_pref_save) {
        filter_dlg_save(list_type);
    }
}

static void
filter_apply(GtkWidget *main_w, gboolean destroy)
{
    construct_args_t *construct_args =
        g_object_get_data(G_OBJECT(main_w), E_FILT_CONSTRUCT_ARGS_KEY);
    GtkWidget        *parent_filter_te =
        g_object_get_data(G_OBJECT(main_w), E_FILT_PARENT_FILTER_TE_KEY);
    GtkWidget        *filter_te;
    const gchar      *filter_string;

    if (parent_filter_te != NULL) {
        /*
         * We have a text entry widget associated with this dialog
         * box; put the filter in our text entry widget into that
         * text entry widget.
         */
                filter_te = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_TE_KEY);
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
            g_signal_emit_by_name(G_OBJECT(parent_filter_te), "activate", NULL);
        }
    }
}


static void
filter_dlg_save(filter_list_type_t list_type)
{
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
            pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return;
    }

    save_filter_list(list_type, &f_path, &f_save_errno);
    if (f_path != NULL) {
        /* We had an error saving the filter. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Could not save to your %s filter file\n\"%s\": %s.",
            filter_type, f_path, g_strerror(f_save_errno));
        g_free(f_path);
    }
}


static void
filter_dlg_save_cb(GtkWidget *save_bt _U_, gpointer data)
{
    filter_list_type_t list_type = *(filter_list_type_t *)data;

    filter_dlg_save(list_type);
}

#if 0
/* update a remaining dialog if another one was cancelled */
static void
filter_dlg_update_list_cb(gpointer data, gpointer user_data)
{
    GtkWidget  *main_w = data;
    filter_list_type_t list_type = *(filter_list_type_t *)user_data;

    /* refill the list */
    clear_list(main_w);
    fill_list(main_w, list_type, NULL);
}
#endif

/* cancel button pressed, revert changes and exit dialog */
static void
filter_dlg_cancel_cb(GtkWidget *cancel_bt, gpointer data)
{
    filter_list_type_t list_type = *(filter_list_type_t *)data;
    GtkWidget  *main_w = gtk_widget_get_toplevel(cancel_bt);
    static GList *filter_list;


    window_destroy(GTK_WIDGET(main_w));

    /* if this was the last open filter dialog, revert the changes made */
    filter_list = get_filter_dialog_list(list_type);
    if(g_list_length(filter_list) == 0) {
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
    }

#if 0
    /* update other open filter dialogs */
    g_list_foreach(get_filter_dialog_list(list_type), filter_dlg_update_list_cb, &list_type);
#endif
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
    button = g_object_get_data(G_OBJECT(win), E_FILT_BUTTON_PTR_KEY);

    if (button != NULL) {
        /* Tell it we no longer exist. */
                g_object_set_data(G_OBJECT(button), E_FILT_DIALOG_PTR_KEY, NULL);
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

static gboolean
filter_sel_list_button_cb(GtkWidget *list, GdkEventButton *event,
                          gpointer data _U_)
{
    void (* func)(GtkWidget *, gpointer, gpointer);
    gpointer func_arg;
    gpointer func_activate;

    if (event->type == GDK_2BUTTON_PRESS) {
        func = g_object_get_data(G_OBJECT(list), E_FILT_DBLFUNC_KEY);
        func_arg = g_object_get_data(G_OBJECT(list), E_FILT_DBLARG_KEY);
        func_activate = g_object_get_data(G_OBJECT(list), E_FILT_DBLACTIVATE_KEY);

        if (func)
            (*func)(list, func_arg, func_activate);
    }

    return FALSE;
}

static void
filter_sel_list_cb(GtkTreeSelection *sel, gpointer data _U_)
{
    GtkWidget    *filter_l = GTK_WIDGET(gtk_tree_selection_get_tree_view(sel));
    GtkWidget    *main_w = gtk_widget_get_toplevel(filter_l);
    GtkTreeModel *model;
    GtkTreeIter   iter;
    GtkWidget    *name_te = g_object_get_data(G_OBJECT(main_w), E_FILT_NAME_TE_KEY);
    GtkWidget    *filter_te = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_TE_KEY);
    GtkWidget    *chg_bt = g_object_get_data(G_OBJECT(main_w), E_FILT_CHG_BT_KEY);
    GtkWidget    *copy_bt = g_object_get_data(G_OBJECT(main_w), E_FILT_COPY_BT_KEY);
    GtkWidget    *del_bt = g_object_get_data(G_OBJECT(main_w), E_FILT_DEL_BT_KEY);
    filter_def   *filt;
    gchar        *name = NULL, *strval = NULL;
    GList        *flp;
    gint          sensitivity = FALSE;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 1, &flp, -1);
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
     *  attach to the top-level window data items containing pointers to
     *  the widgets we affect here;
     *
     *  give each of those widgets their own destroy callbacks;
     *
     *  clear that pointer when the widget is destroyed;
     *
     *  don't do anything to the widget if the pointer we get back is
     *  null;
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
    g_free(name);
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
    GtkTreeView  *filter_l;
    GtkListStore *store;
    GtkTreeIter   iter;
    new_filter_cb_args_t *args = user_data;
    filter_def *nfilt = args->nflp->data;

    filter_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY));
    store = GTK_LIST_STORE(gtk_tree_view_get_model(filter_l));
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, nfilt->name, 1, args->nflp, -1);
    if (GTK_WIDGET(filter_l) == args->active_filter_l) {
        /* Select the item. */
        gtk_tree_selection_select_iter(gtk_tree_view_get_selection(filter_l),
                                       &iter);
    }
}

static void
filter_new_bt_clicked_cb(GtkWidget *w, gpointer data)
{
    GtkWidget  *main_w = gtk_widget_get_toplevel(w);
    GtkWidget  *name_te = g_object_get_data(G_OBJECT(main_w), E_FILT_NAME_TE_KEY);
    GtkWidget  *filter_te = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_TE_KEY);
    GtkWidget  *filter_l = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY);
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

static gboolean
chg_list_item_cb(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
                 gpointer data)
{
    GList      *flp = data;
    filter_def *filt = flp->data;
    GList      *nl_model;

    gtk_tree_model_get(model, iter, 1, &nl_model, -1);
    /* Is this the item corresponding to the filter list item in question? */
    if (flp == nl_model) {
        /* Yes - change the label to correspond to the new name for the
         * filter. */
        gtk_list_store_set(GTK_LIST_STORE(model), iter, 0, filt->name, -1);
        return TRUE;
    }
    return FALSE;
}

static void
chg_filter_cb(gpointer data, gpointer user_data)
{
    GtkWidget  *main_w = data;
    GtkWidget  *filter_l = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY);

    gtk_tree_model_foreach(gtk_tree_view_get_model(GTK_TREE_VIEW(filter_l)),
                           chg_list_item_cb, user_data);
}

static void
filter_name_te_changed_cb(GtkWidget *w, gpointer data)
{
    GtkWidget  *main_w = gtk_widget_get_toplevel(w);
    GtkWidget  *name_te = g_object_get_data(G_OBJECT(main_w), E_FILT_NAME_TE_KEY);
    GtkWidget  *filter_te = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_TE_KEY);
    GtkWidget  *filter_l = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY);
    filter_def *filt;
    GList      *fl_entry;
    filter_list_type_t  list_type = *(filter_list_type_t *)data;
    const gchar         *name = "";
    const gchar         *strval = "";

    GtkTreeSelection  *sel;
    GtkTreeModel      *model;
    GtkTreeIter        iter;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));
    name   = gtk_entry_get_text(GTK_ENTRY(name_te));
    strval = gtk_entry_get_text(GTK_ENTRY(filter_te));

    if (DFILTER_EDITED_LIST == list_type) {
        /* colorize filter string entry */
        filter_te_syntax_check_cb(filter_te, NULL);
    }

    /* if something was selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 1, &fl_entry, -1);
        if (fl_entry != NULL) {
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
    GtkWidget    *filter_l = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY);
    gchar        *pos = (gchar *)user_data;
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(filter_l));
    GtkTreeIter   iter;

    gtk_tree_model_get_iter_from_string(model, &iter, pos);
    gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
}

static void
filter_del_bt_clicked_cb(GtkWidget *w, gpointer data)
{
    GtkWidget  *main_w = gtk_widget_get_toplevel(w);
    GtkWidget  *filter_l = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_L_KEY);
    filter_list_type_t list_type = *(filter_list_type_t *)data;
    GList      *fl_entry;
    gchar             *pos;
    GtkTreeSelection  *sel;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
    GtkTreePath       *path;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(filter_l));
    /* If something was selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 1, &fl_entry, -1);
        path = gtk_tree_model_get_path(model, &iter);
        pos = gtk_tree_path_to_string(path);
        gtk_tree_path_free(path);
        if (fl_entry != NULL) {
            /* Remove the entry from the filter list. */
            remove_from_filter_list(list_type, fl_entry);

            /* Update all the filter list widgets, not just the one in
               the dialog box in which we clicked on "Delete". */
            g_list_foreach(get_filter_dialog_list(list_type), delete_filter_cb, pos);
        }
        g_free(pos);
    }
}

void
filter_add_expr_bt_cb(GtkWidget *w _U_, gpointer main_w_arg)
{
    GtkWidget  *main_w = GTK_WIDGET(main_w_arg);
    GtkWidget  *filter_te, *dfilter_w;

    filter_te = g_object_get_data(G_OBJECT(main_w), E_FILT_FILTER_TE_KEY);
    dfilter_w = dfilter_expr_dlg_new(filter_te);

    /* If we're opening a series of modal dialogs (such as when going
     * through file->open, make the latest dialog modal also so that it
     * takes over "control" from the other modal dialogs.  Also set
     * the transient property of the new dialog so the user doesn't try
     * to interact with the previous window when they can't.
         * XXX: containing widget might be the Filter Toolbar */

    if ( GTK_IS_WINDOW(main_w) && gtk_window_get_modal(GTK_WINDOW(main_w))) {
        gtk_window_set_modal(GTK_WINDOW(dfilter_w), TRUE);
        gtk_window_set_transient_for(GTK_WINDOW(dfilter_w),
                         GTK_WINDOW(main_w));
    }
}

static void
color_filter_te(GtkWidget *w, guint16 red, guint16 green, guint16 blue)
{
#if GTK_CHECK_VERSION(3,0,0)
    static GdkRGBA black = { 0, 0, 0, 1.0 };
    GdkRGBA bg;

    bg.red      = red / 65535.0;
    bg.green    = green / 65535.0;
    bg.blue     = blue / 65535.0;
    bg.alpha    = 1;

    gtk_widget_override_color(w, GTK_STATE_NORMAL, &black);
    gtk_widget_override_background_color(w, GTK_STATE_NORMAL, &bg);
    gtk_widget_override_cursor(w, &black, &black);
#else
    static GdkColor black = { 0, 0, 0, 0 };
    GdkColor    bg;

    bg.pixel    = 0;
    bg.red      = red;
    bg.green    = green;
    bg.blue     = blue;

    gtk_widget_modify_text(w, GTK_STATE_NORMAL, &black);
    gtk_widget_modify_base(w, GTK_STATE_NORMAL, &bg);
    gtk_widget_modify_cursor(w, &black, &black);
#endif
}

void
colorize_filter_te_as_empty(GtkWidget *w)
{
#if GTK_CHECK_VERSION(3,0,0)
    /* use defaults */
    gtk_widget_override_color(w, GTK_STATE_NORMAL, NULL);
    gtk_widget_override_background_color(w, GTK_STATE_NORMAL, NULL);
    gtk_widget_override_cursor(w, NULL, NULL);
#else    
    /* use defaults */
    gtk_widget_modify_text(w, GTK_STATE_NORMAL, NULL);
    gtk_widget_modify_base(w, GTK_STATE_NORMAL, NULL);
    gtk_widget_modify_cursor(w, NULL, NULL);
#endif
}

void
colorize_filter_te_as_invalid(GtkWidget *w)
{
    /* light red */
    color_filter_te(w, 0xFFFF, 0xAFFF, 0xAFFF);
}

static void
colorize_filter_te_as_deprecated(GtkWidget *w)
{
    /* light yellow */
    color_filter_te(w, 0xFFFF, 0xFFFF, 0xAFFF);
}

void
colorize_filter_te_as_valid(GtkWidget *w)
{
    /* light green */
    color_filter_te(w, 0xAFFF, 0xFFFF, 0xAFFF);
}

/*
 * XXX This calls dfilter_compile, which might call get_host_ipaddr or
 * get_host_ipaddr6. Either of of these will freeze the UI if the host
 * name resolution takes a long time to complete. We need to work
 * around this, either by disabling host name resolution or by doing
 * the resolution asynchronously.
 *
 * We could use a separate thread but we have be careful to only call
 * GTK+/GDK routines from the main thread. From the GDK threads
 * documentation:
 *
 * "With the Win32 backend, GDK calls should not be attempted from
 * multiple threads at all."
 */

void
filter_te_syntax_check_cb(GtkWidget *w, gpointer user_data _U_)
{
    const gchar *strval;
    dfilter_t   *dfp;
    GPtrArray   *depr = NULL;
    gboolean     use_statusbar;
    guchar       c;

    strval = gtk_entry_get_text(GTK_ENTRY(w));
    use_statusbar = g_object_get_data(G_OBJECT(w), E_FILT_FIELD_USE_STATUSBAR_KEY) ? TRUE : FALSE;

    if (use_statusbar) {
        statusbar_pop_filter_msg();
    }

    /* colorize filter string entry */
    if (g_object_get_data(G_OBJECT(w), E_FILT_FIELD_NAME_ONLY_KEY) &&
        strval && (c = proto_check_field_name(strval)) != 0)
    {
        colorize_filter_te_as_invalid(w);
        if (use_statusbar) {
            statusbar_push_filter_msg(" Illegal character in field name: '%c'", c);
        }
    } else if (strval && dfilter_compile(strval, &dfp)) {
        if (dfp != NULL) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (strlen(strval) == 0) {
            colorize_filter_te_as_empty(w);
        } else if (depr) {
            /* You keep using that word. I do not think it means what you think it means. */
            colorize_filter_te_as_deprecated(w);
            if (use_statusbar) {
                /*
                 * We're being lazy and only printing the first "problem" token.
                 * Would it be better to print all of them?
                 */
                statusbar_push_temporary_msg(" \"%s\" may have unexpected results (see the User's Guide)",
                                      (const char *) g_ptr_array_index(depr, 0));
            }
        } else {
            colorize_filter_te_as_valid(w);
        }
        dfilter_free(dfp);
    } else {
        colorize_filter_te_as_invalid(w);
        if (use_statusbar) {
            if (dfilter_error_msg) {
                statusbar_push_filter_msg(" Invalid filter: %s", dfilter_error_msg);
            } else {
                statusbar_push_filter_msg(" Invalid filter");
            }
        }
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
