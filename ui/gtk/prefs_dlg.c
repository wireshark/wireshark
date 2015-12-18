/* prefs_dlg.c
 * Routines for handling preferences
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <gtk/gtk.h>

#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/epan_dissect.h>

#include "ui/preference_utils.h"

#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/main.h"
#include "ui/gtk/prefs_column.h"
#include "ui/gtk/prefs_dlg.h"
#include "ui/gtk/prefs_filter_expressions.h"
#include "ui/gtk/prefs_font_color.h"
#include "ui/gtk/prefs_gui.h"
#include "ui/gtk/prefs_layout.h"
#include "ui/gtk/prefs_capture.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/uat_gui.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/packet_win.h"
#include "simple_dialog.h"

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
#include <caputils/capture-wpcap.h>
#endif /* _WIN32 */
#ifdef HAVE_AIRPCAP
#include <caputils/airpcap.h>
#include <caputils/airpcap_loader.h>
#include "airpcap_gui_utils.h"
#endif
#endif

static void     prefs_main_ok_cb(GtkWidget *, gpointer);
static void     prefs_main_apply_cb(GtkWidget *, gpointer);
static void     prefs_main_save_cb(GtkWidget *, gpointer);
static void     prefs_main_cancel_cb(GtkWidget *, gpointer);
static gboolean prefs_main_delete_event_cb(GtkWidget *, GdkEvent *, gpointer);
static void     prefs_main_destroy_cb(GtkWidget *, gpointer);
static void     prefs_tree_select_cb(GtkTreeSelection *, gpointer);

static GtkWidget *create_preference_path_entry(GtkWidget *, int,
   const gchar *, const gchar *, char *, gboolean);

#define E_PREFSW_SCROLLW_KEY          "prefsw_scrollw"
#define E_PREFSW_TREE_KEY             "prefsw_tree"
#define E_PREFSW_NOTEBOOK_KEY         "prefsw_notebook"
#define E_PREFSW_SAVE_BT_KEY          "prefsw_save_bt"
#define E_PAGE_ITER_KEY               "page_iter"
#define E_PAGE_MODULE_KEY             "page_module"
#define E_PAGESW_FRAME_KEY            "pagesw_frame"

#define E_GUI_PAGE_KEY                "gui_options_page"
#define E_GUI_LAYOUT_PAGE_KEY         "gui_layout_page"
#define E_GUI_COLUMN_PAGE_KEY         "gui_column_options_page"
#define E_GUI_FONT_PAGE_KEY           "gui_font_options_page"
#define E_GUI_FONT_COLORS_PAGE_KEY    "gui_font_colors_options_page"
#define E_CAPTURE_PAGE_KEY            "capture_options_page"
#define E_NAMERES_PAGE_KEY            "nameres_options_page"
#define E_FILTER_EXPRESSIONS_PAGE_KEY "filter_expressions_page"
#define E_GRID_MODULE_KEY             "grid_module"

/*
 * Keep a static pointer to the current "Preferences" window, if any, so that
 * if somebody tries to do "Edit:Preferences" while there's already a
 * "Preferences" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *prefs_w;

struct ct_struct {
  GtkWidget    *main_vb;
  GtkWidget    *notebook;
  GtkWidget    *tree;
  GtkTreeIter   iter;
  gint          page;
  GtkTreeStore *store;
};

static guint
pref_exists(pref_t *pref _U_, gpointer user_data _U_)
{
  return 1;
}

/* show a single preference on the GtkGrid of a preference page */
static guint
pref_show(pref_t *pref, gpointer user_data)
{
  GtkWidget  *main_grid = (GtkWidget *)user_data;
  module_t   *module  = (module_t *)g_object_get_data(G_OBJECT(main_grid), E_GRID_MODULE_KEY);
  const char *title;
  const char *type_name = prefs_pref_type_name(pref);
  char       *label_string;
  size_t      label_len;
  char        uint_str[10+1];
  char *tooltip_txt;

  /* Give this preference a label which is its title, followed by a colon,
     and left-align it. */
  title = pref->title;
  label_len = strlen(title) + 2;
  label_string = (char *)g_malloc(label_len);
  g_strlcpy(label_string, title, label_len);

  tooltip_txt = pref->description? g_strdup_printf("%s\n\nName: %s.%s\nType: %s",
                                                   pref->description,
                                                   module->name,
                                                   pref->name,
                                                   type_name ? type_name : "Unknown"
                                                   ): NULL;

  /*
   * Sometimes we don't want to append a ':' after a static text string...
   * If it is needed, we will specify it in the string itself.
   */
  if (pref->type != PREF_STATIC_TEXT)
    g_strlcat(label_string, ":", label_len);

  pref_stash(pref, NULL);

  /* Save the current value of the preference, so that we can revert it if
     the user does "Apply" and then "Cancel", and create the control for
     editing the preference. */
  switch (pref->type) {

  case PREF_UINT:
    /* XXX - there are no uint spinbuttons, so we can't use a spinbutton.
       Even more annoyingly, even if there were, GLib doesn't define
       G_MAXUINT - but I think ANSI C may define UINT_MAX, so we could
       use that. */
    switch (pref->info.base) {

    case 10:
      g_snprintf(uint_str, sizeof(uint_str), "%u", pref->stashed_val.uint);
      break;

    case 8:
      g_snprintf(uint_str, sizeof(uint_str), "%o", pref->stashed_val.uint);
      break;

    case 16:
      g_snprintf(uint_str, sizeof(uint_str), "%x", pref->stashed_val.uint);
      break;
    }
    pref->control = create_preference_entry(main_grid, pref->ordinal,
                                            label_string, tooltip_txt,
                                            uint_str);
    break;

  case PREF_BOOL:
    pref->control = create_preference_check_button(main_grid, pref->ordinal,
                                                   label_string, tooltip_txt,
                                                   pref->stashed_val.boolval);
    break;

  case PREF_ENUM:
    if (pref->info.enum_info.radio_buttons) {
      /* Show it as radio buttons. */
      pref->control = create_preference_radio_buttons(main_grid, pref->ordinal,
                                                      label_string, tooltip_txt,
                                                      pref->info.enum_info.enumvals,
                                                      pref->stashed_val.enumval);
    } else {
      /* Show it as an option menu. */
      pref->control = create_preference_option_menu(main_grid, pref->ordinal,
                                                    label_string, tooltip_txt,
                                                    pref->info.enum_info.enumvals,
                                                    pref->stashed_val.enumval);
    }
    break;

  case PREF_STRING:
    pref->control = create_preference_entry(main_grid, pref->ordinal,
                                            label_string, tooltip_txt,
                                            pref->stashed_val.string);
    break;

  case PREF_FILENAME:
    pref->control = create_preference_path_entry(main_grid, pref->ordinal,
                                                     label_string,
                                                     tooltip_txt,
                                                     pref->stashed_val.string, FALSE);
    break;

  case PREF_DIRNAME:
    pref->control = create_preference_path_entry(main_grid, pref->ordinal,
                                                     label_string,
                                                     tooltip_txt,
                                                     pref->stashed_val.string, TRUE);
    break;

  case PREF_RANGE:
  {
    char *range_str_p;

    range_str_p = range_convert_range(NULL, *pref->varp.range);
    pref->control = create_preference_entry(main_grid, pref->ordinal,
                                            label_string, tooltip_txt,
                                            range_str_p);
    wmem_free(NULL, range_str_p);
    break;
  }

  case PREF_STATIC_TEXT:
  {
    pref->control = create_preference_static_text(main_grid, pref->ordinal,
                                                  label_string, tooltip_txt);
    break;
  }

  case PREF_UAT:
  {
    if (pref->gui == GUI_ALL || pref->gui == GUI_GTK)
        pref->control = create_preference_uat(main_grid, pref->ordinal,
                                              label_string, tooltip_txt,
                                              pref->varp.uat);
    break;
  }

  case PREF_COLOR:
  case PREF_CUSTOM:
      /* currently not supported */

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  g_free(tooltip_txt);
  g_free(label_string);

  return 0;
}

#define prefs_tree_iter GtkTreeIter

/* add a page to the tree */
static prefs_tree_iter
prefs_tree_page_add(const gchar *title, gint page_nr,
                    gpointer store, prefs_tree_iter *parent_iter)
{
  prefs_tree_iter   iter;

  gtk_tree_store_append((GtkTreeStore *)store, &iter, parent_iter);
  gtk_tree_store_set((GtkTreeStore *)store, &iter, 0, title, 1, page_nr, -1);
  return iter;
}

/* add a page to the notebook */
static GtkWidget *
prefs_nb_page_add(GtkWidget *notebook, const gchar *title _U_, GtkWidget *page, const char *page_key)
{
  GtkWidget         *sw;
  GtkWidget         *frame;

  sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_widget_show(sw);

  frame = gtk_frame_new(NULL);
  gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_NONE);
  gtk_container_set_border_width(GTK_CONTAINER(frame), DLG_OUTER_MARGIN);
#if ! GTK_CHECK_VERSION(3,8,0)
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(sw), frame);
#else
  gtk_container_add(GTK_CONTAINER(sw), frame);
#endif
  gtk_widget_show(frame);

  if (page) {
    gtk_container_add(GTK_CONTAINER(frame), page);
    g_object_set_data(G_OBJECT(prefs_w), page_key, page);
  }

  gtk_notebook_append_page (GTK_NOTEBOOK(notebook), sw, NULL);

  return sw;
}

#define MAX_TREE_NODE_NAME_LEN 64

/* show prefs page for each registered module (protocol) */
static guint
module_prefs_show(module_t *module, gpointer user_data)
{
  struct ct_struct *cts = (struct ct_struct *)user_data;
  struct ct_struct  child_cts;
  GtkWidget        *main_vb, *main_grid, *frame, *main_sw;
  gchar             label_str[MAX_TREE_NODE_NAME_LEN];
  GtkTreeStore     *model;
  GtkTreeIter       iter;

  if (!module->use_gui) {
      /* This module uses its own GUI interface to modify its
       * preferences, so ignore it
       */
      return 0;
  }

  /*
   * Is this module an interior node, with modules underneath it?
   */
  if (!prefs_module_has_submodules(module)) {
    /*
     * No.
     * Does it have any preferences (other than possibly obsolete ones)?
     */
    if (prefs_pref_foreach(module, pref_exists, NULL) == 0) {
      /*
       * No.  Don't put the module into the preferences window,
       * as there's nothing to show.
       *
       * XXX - we should do the same for interior ndes; if the module
       * has no non-obsolete preferences *and* nothing under it has
       * non-obsolete preferences, don't put it into the window.
       */
      return 0;
    }
  }

  /*
   * Add this module to the tree.
   */
  g_strlcpy(label_str, module->title, MAX_TREE_NODE_NAME_LEN);
  model = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(cts->tree)));

  if (module->parent == NULL)
    gtk_tree_store_append(model, &iter, NULL);
  else
    gtk_tree_store_append(model, &iter, &cts->iter);

  /*
   * Is this an interior node?
   */
  if (prefs_module_has_submodules(module)) {
    /*
     * Yes.
     */
    gtk_tree_store_set(model, &iter, 0, label_str, 1, -1, -1);

    /*
     * Walk the subtree and attach stuff to it.
     */
    child_cts = *cts;
    child_cts.iter = iter;
    prefs_modules_foreach_submodules(module, module_prefs_show, &child_cts);

    /* keep the page count right */
    cts->page = child_cts.page;
  }

  /*
   * We create pages for interior nodes even if they don't have
   * preferences, so that we at least have something to show
   * if the user clicks on them, even if it's empty.
   */

  /* Scrolled window */
  main_sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(main_sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

  /* Frame */
  frame = gtk_frame_new(NULL);
  gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_NONE);
  gtk_container_set_border_width(GTK_CONTAINER(frame), DLG_OUTER_MARGIN);
#if ! GTK_CHECK_VERSION(3,8,0)
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(main_sw), frame);
#else
  gtk_container_add(GTK_CONTAINER(main_sw), frame);
#endif
  g_object_set_data(G_OBJECT(main_sw), E_PAGESW_FRAME_KEY, frame);

  /* Main vertical box */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(frame), main_vb);

  /* Main grid */
  main_grid = ws_gtk_grid_new();
  gtk_box_pack_start(GTK_BOX(main_vb), main_grid, FALSE, FALSE, 0);
#if GTK_CHECK_VERSION(3,0,0)
  gtk_widget_set_vexpand(GTK_WIDGET(main_grid), FALSE); /* Ignore VEXPAND requests from children */
#endif
  ws_gtk_grid_set_row_spacing(GTK_GRID(main_grid), 10);
  ws_gtk_grid_set_column_spacing(GTK_GRID(main_grid), 15);

  /* Add items for each of the preferences */
  g_object_set_data(G_OBJECT(main_grid), E_GRID_MODULE_KEY, module);
  prefs_pref_foreach(module, pref_show, main_grid);
  g_object_set_data(G_OBJECT(main_grid), E_GRID_MODULE_KEY, NULL);

  /* Associate this module with the page's frame. */
  g_object_set_data(G_OBJECT(frame), E_PAGE_MODULE_KEY, module);

  /* Add the page to the notebook */
  gtk_notebook_append_page(GTK_NOTEBOOK(cts->notebook), main_sw, NULL);

  /* Attach the page to the tree item */
  gtk_tree_store_set(model, &iter, 0, label_str, 1, cts->page, -1);
  g_object_set_data(G_OBJECT(frame), E_PAGE_ITER_KEY, gtk_tree_iter_copy(&iter));

  cts->page++;

  /* Show 'em what we got */
  gtk_widget_show_all(main_sw);

  return 0;
}


/* show the dialog */
void
prefs_cb(GtkWidget *w, gpointer dummy)
{
  prefs_page_cb (w, dummy, PREFS_PAGE_USER_INTERFACE);
}

void
prefs_page_cb(GtkWidget *w _U_, gpointer dummy _U_, PREFS_PAGE_E prefs_page)
{
  GtkWidget         *top_hb, *bbox, *prefs_nb, *ct_sb,
                    *ok_bt, *apply_bt, *save_bt, *cancel_bt, *help_bt;
  gchar              label_str[MAX_TREE_NODE_NAME_LEN];
  struct ct_struct   cts;
  GtkTreeStore      *store;
  GtkTreeSelection  *selection;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  gint               col_offset;
  prefs_tree_iter    gui_iter, layout_iter, columns_iter, capture_iter;
  gint               layout_page, columns_page;
  gint               capture_page = 0;


  if (prefs_w != NULL) {
    /* There's already a "Preferences" dialog box; reactivate it. */
    reactivate_window(prefs_w);
    return;
  }

  prefs_w = dlg_conf_window_new("Wireshark: Preferences");
  gtk_window_set_default_size(GTK_WINDOW(prefs_w), 400, 650);

  /*
   * Unfortunately, we can't arrange that a GtkGrid widget wrap an event box
   * around a grid row, so the spacing between the preference item's label
   * and its control widgets is inactive and the tooltip doesn't pop up when
   * the mouse is over it.
   */

  /* Container for each row of widgets */
  cts.main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(cts.main_vb), 5);
  gtk_container_add(GTK_CONTAINER(prefs_w), cts.main_vb);
  gtk_widget_show(cts.main_vb);

  /* Top row: Preferences tree and notebook */
  top_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10, FALSE);
  gtk_box_pack_start(GTK_BOX(cts.main_vb), top_hb, TRUE, TRUE, 0);
  gtk_widget_show(top_hb);

  /* scrolled window on the left for the categories tree */
  ct_sb = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(ct_sb),
                                   GTK_SHADOW_IN);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ct_sb),
                                 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_box_pack_start(GTK_BOX(top_hb), ct_sb, TRUE, TRUE, 0);
  gtk_widget_show(ct_sb);
  g_object_set_data(G_OBJECT(prefs_w), E_PREFSW_SCROLLW_KEY, ct_sb);

  /* categories tree */
  store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_INT);
  cts.tree = tree_view_new(GTK_TREE_MODEL(store));
  cts.iter.stamp = 0; /* mark this as the toplevel */
  g_object_set_data(G_OBJECT(prefs_w), E_PREFSW_TREE_KEY, cts.tree);
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(cts.tree), FALSE);
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(cts.tree));
  gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
  renderer = gtk_cell_renderer_text_new();
  col_offset = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(cts.tree),
                                                           -1, "Name", renderer,
                                                           "text", 0, NULL);
  column = gtk_tree_view_get_column(GTK_TREE_VIEW(cts.tree),
                                    col_offset - 1);
  gtk_tree_view_column_set_sizing(GTK_TREE_VIEW_COLUMN(column),
                                  GTK_TREE_VIEW_COLUMN_AUTOSIZE);
  g_signal_connect(selection, "changed", G_CALLBACK(prefs_tree_select_cb), NULL);
  gtk_container_add(GTK_CONTAINER(ct_sb), cts.tree);
  gtk_widget_show(cts.tree);

  /* A notebook widget without tabs is used to flip between prefs */
  prefs_nb = gtk_notebook_new();
  g_object_set_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY, prefs_nb);
  gtk_notebook_set_show_tabs(GTK_NOTEBOOK(prefs_nb), FALSE);
  gtk_notebook_set_show_border(GTK_NOTEBOOK(prefs_nb), FALSE);
  gtk_box_pack_start(GTK_BOX(top_hb), prefs_nb, TRUE, TRUE, 0);
  gtk_widget_show(prefs_nb);

  cts.page = 0;

  /* GUI prefs */
  g_strlcpy(label_str, "User Interface", MAX_TREE_NODE_NAME_LEN);
  prefs_nb_page_add(prefs_nb, label_str, gui_prefs_show(), E_GUI_PAGE_KEY);
  gui_iter = prefs_tree_page_add(label_str, cts.page, store, NULL);
  cts.page++;

  /* GUI layout prefs */
  g_strlcpy(label_str, "Layout", MAX_TREE_NODE_NAME_LEN);
  prefs_nb_page_add(prefs_nb, label_str, layout_prefs_show(), E_GUI_LAYOUT_PAGE_KEY);
  layout_iter = prefs_tree_page_add(label_str, cts.page, store, &gui_iter);
  layout_page = cts.page++;

  /* GUI Column prefs */
  g_strlcpy(label_str, "Columns", MAX_TREE_NODE_NAME_LEN);
  prefs_nb_page_add(prefs_nb, label_str, column_prefs_show(prefs_w), E_GUI_COLUMN_PAGE_KEY);
  columns_iter = prefs_tree_page_add(label_str, cts.page, store, &gui_iter);
  columns_page = cts.page++;

  /* GUI Colors prefs */
  g_strlcpy(label_str, "Font and Colors", MAX_TREE_NODE_NAME_LEN);
  prefs_nb_page_add(prefs_nb, label_str, font_color_prefs_show(), E_GUI_FONT_COLORS_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, &gui_iter);
  cts.page++;

  /* select the main GUI page as the default page and expand its children */
  gtk_tree_selection_select_iter(selection, &gui_iter);
  /* (expand will only take effect, when at least one child exists) */
  gtk_tree_view_expand_all(GTK_TREE_VIEW(cts.tree));

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  /* capture prefs */
  g_strlcpy(label_str, "Capture", MAX_TREE_NODE_NAME_LEN);
  prefs_nb_page_add(prefs_nb, label_str, capture_prefs_show(), E_CAPTURE_PAGE_KEY);
  capture_iter = prefs_tree_page_add(label_str, cts.page, store, NULL);
  capture_page = cts.page++;
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

  /* Saved filter prefs */
  g_strlcpy(label_str, "Filter Expressions", MAX_TREE_NODE_NAME_LEN);
  prefs_nb_page_add(prefs_nb, label_str, filter_expressions_prefs_show(),
    E_FILTER_EXPRESSIONS_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, NULL);
  cts.page++;

  /* Registered prefs */
  cts.notebook = prefs_nb;
  cts.store = store;
  prefs_modules_foreach_submodules(NULL, module_prefs_show, &cts);

  /* Button row: OK and alike buttons */
  bbox = dlg_button_row_new(GTK_STOCK_HELP, GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, NULL);
  gtk_box_pack_start(GTK_BOX(cts.main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(prefs_main_ok_cb), prefs_w);

  apply_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_APPLY);
  g_signal_connect(apply_bt, "clicked", G_CALLBACK(prefs_main_apply_cb), prefs_w);

  save_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_SAVE);
  g_signal_connect(save_bt, "clicked", G_CALLBACK(prefs_main_save_cb), prefs_w);
  g_object_set_data(G_OBJECT(prefs_w), E_PREFSW_SAVE_BT_KEY, save_bt);

  cancel_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  g_signal_connect(cancel_bt, "clicked", G_CALLBACK(prefs_main_cancel_cb), prefs_w);
  window_set_cancel_button(prefs_w, cancel_bt, NULL);

  gtk_widget_grab_default(ok_bt);

  help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_PREFERENCES_DIALOG);

  g_signal_connect(prefs_w, "delete_event", G_CALLBACK(prefs_main_delete_event_cb), NULL);
  g_signal_connect(prefs_w, "destroy", G_CALLBACK(prefs_main_destroy_cb), prefs_w);

  gtk_widget_show(prefs_w);

  /* hide the Save button if the user uses implicit save */
  if (!prefs.gui_use_pref_save) {
    gtk_widget_hide(save_bt);
  }

  window_present(prefs_w);

  switch (prefs_page) {
  case PREFS_PAGE_LAYOUT:
    gtk_tree_selection_select_iter(selection, &layout_iter);
    gtk_notebook_set_current_page((GtkNotebook *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY), layout_page);
    break;
  case PREFS_PAGE_COLUMNS:
    gtk_tree_selection_select_iter(selection, &columns_iter);
    gtk_notebook_set_current_page((GtkNotebook *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY), columns_page);
    break;
  case PREFS_PAGE_CAPTURE:
    if (capture_page) {
      gtk_tree_selection_select_iter(selection, &capture_iter);
      gtk_notebook_set_current_page((GtkNotebook *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY), capture_page);
    }
    break;
  default:
    /* Not implemented yet */
    break;
  }

  g_object_unref(G_OBJECT(store));
}

static void
set_option_label(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text)
{
  GtkWidget *label;
  GtkWidget *event_box;

  label = gtk_label_new(label_text);
  gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
  gtk_widget_show(label);

  event_box = gtk_event_box_new();
  gtk_event_box_set_visible_window (GTK_EVENT_BOX(event_box), FALSE);
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), event_box, 0, grid_position, 1, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(event_box, tooltip_text);
  gtk_container_add(GTK_CONTAINER(event_box), label);
  gtk_widget_show(event_box);
}

GtkWidget *
create_preference_check_button(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text, gboolean active)
{
  GtkWidget *check_box;

  set_option_label(main_grid, grid_position, label_text, tooltip_text);

  check_box = gtk_check_button_new();
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check_box), active);
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), check_box, 1, grid_position, 1, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(check_box, tooltip_text);

  return check_box;
}

GtkWidget *
create_preference_radio_buttons(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val)
{
  GtkWidget        *radio_button_hbox, *button = NULL;
  GSList           *rb_group;
  int               idx;
  const enum_val_t *enum_valp;
  GtkWidget        *event_box;

  set_option_label(main_grid, grid_position, label_text, tooltip_text);

  radio_button_hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
  rb_group = NULL;
  for (enum_valp = enumvals, idx = 0; enum_valp->name != NULL;
       enum_valp++, idx++) {
    button = gtk_radio_button_new_with_label(rb_group,
                                             enum_valp->description);
    gtk_widget_show(button);
    rb_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(button));
    gtk_box_pack_start(GTK_BOX(radio_button_hbox), button, FALSE,
                       FALSE, 10);
    if (enum_valp->value == current_val) {
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button),
                                   TRUE);
    }
  }
  gtk_widget_show(radio_button_hbox);

  event_box = gtk_event_box_new();
  gtk_event_box_set_visible_window (GTK_EVENT_BOX(event_box), FALSE);
  gtk_container_add(GTK_CONTAINER(event_box), radio_button_hbox);
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), event_box, 1, grid_position, 1, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(event_box, tooltip_text);
  gtk_widget_show(event_box);

  /*
   * It doesn't matter which of the buttons we return - we fetch
   * the value by looking at the entire radio button group to
   * which it belongs, and we can get that from any button.
   */
  return button;
}

static gint
label_to_enum_val(GtkWidget *label, const enum_val_t *enumvals)
{
  const gchar *label_string;
  int i;

  /* Get the label's text, and translate it to a value.
     We match only the descriptions, as those are what appear in
     the option menu items or as labels for radio buttons.
     We fail if we don't find a match, as that "can't happen". */
  label_string = gtk_label_get_text(GTK_LABEL(label));

  for (i = 0; enumvals[i].name != NULL; i++) {
    if (g_ascii_strcasecmp(label_string, enumvals[i].description) == 0) {
      return enumvals[i].value;
    }
  }
  g_assert_not_reached();
  return -1;
}

gint
fetch_preference_radio_buttons_val(GtkWidget *button,
    const enum_val_t *enumvals)
{
  GSList *rb_group;
  GSList *rb_entry;

  /*
   * Go through the list of of radio buttons in the button's group,
   * and find the first one that's active.
   */
  rb_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(button));
  button = NULL;
  for (rb_entry = rb_group; rb_entry != NULL;
       rb_entry = g_slist_next(rb_entry)) {
    button = (GtkWidget *)rb_entry->data;
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button)))
      break;
  }

  /* OK, now return the value corresponding to that button's label. */
  return label_to_enum_val(gtk_bin_get_child(GTK_BIN(button)), enumvals);
}

GtkWidget *
create_preference_option_menu(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val)
{
  GtkWidget        *menu_box, *combo_box;
  int               menu_idx, idx;
  const enum_val_t *enum_valp;
  GtkWidget        *event_box;

  set_option_label(main_grid, grid_position, label_text, tooltip_text);

  /* Create a menu from the enumvals */
  combo_box = gtk_combo_box_text_new();
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(combo_box, tooltip_text);
  menu_idx = 0;
  for (enum_valp = enumvals, idx = 0; enum_valp->name != NULL;
       enum_valp++, idx++) {
     gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), enum_valp->description);
    if (enum_valp->value == current_val)
      menu_idx = idx;
  }
  /* Set the current value active */
  gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), menu_idx);

  /*
   * Put the combo box in an hbox, so that it's only as wide
   * as the widest entry, rather than being as wide as the grid
   * space.
   */
  menu_box = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
  gtk_box_pack_start(GTK_BOX(menu_box), combo_box, FALSE, FALSE, 0);

  event_box = gtk_event_box_new();
  gtk_event_box_set_visible_window (GTK_EVENT_BOX(event_box), FALSE);
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), event_box, 1, grid_position, 1, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(event_box, tooltip_text);
  gtk_container_add(GTK_CONTAINER(event_box), menu_box);

  return combo_box;
}

gint
fetch_preference_option_menu_val(GtkWidget *combo_box, const enum_val_t *enumvals)
{
  /*
   * OK, now return the value corresponding to the label for the
   * currently active entry in the combo box.
   */
    int i;

    i = gtk_combo_box_get_active (GTK_COMBO_BOX(combo_box));

    return enumvals[i].value;
}

GtkWidget *
create_preference_entry(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text, char *value)
{
  GtkWidget *entry;

  set_option_label(main_grid, grid_position, label_text, tooltip_text);

  entry = gtk_entry_new();
  if (value != NULL)
    gtk_entry_set_text(GTK_ENTRY(entry), value);
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), entry, 1, grid_position, 1, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(entry, tooltip_text);
  gtk_widget_show(entry);

  return entry;
}

static void
preference_filename_entry_cb(GtkWidget *button, GtkWidget *filename_te)
{
    /* XXX - use a better browser dialog title */
    file_selection_browse(button, filename_te, "Wireshark: File preference",
                          FILE_SELECTION_READ_BROWSE);
}

static void
preference_dirname_entry_cb(GtkWidget *button, GtkWidget *filename_te)
{
    /* XXX - use a better browser dialog title */
    file_selection_browse(button, filename_te, "Wireshark: Directory preference",
                          FILE_SELECTION_CREATE_FOLDER);
}

static GtkWidget *
create_preference_path_entry(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text, char *value, gboolean dir_only)
{
  GtkWidget *entry;
  GtkWidget *button, *file_bt_hb;

  set_option_label(main_grid, grid_position, label_text, tooltip_text);
  file_bt_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), file_bt_hb, 1, grid_position, 1, 1);
  gtk_widget_show(file_bt_hb);

  button = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_BROWSE);
  gtk_box_pack_end(GTK_BOX(file_bt_hb), button, FALSE, FALSE, 0);
  gtk_widget_show(button);

  entry = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(file_bt_hb), entry, TRUE, TRUE, 0);
  if (value != NULL)
    gtk_entry_set_text(GTK_ENTRY(entry), value);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(entry, tooltip_text);
  gtk_widget_show(entry);

  if (dir_only) {
    g_signal_connect(button, "clicked", G_CALLBACK(preference_dirname_entry_cb), entry);
  } else {
    g_signal_connect(button, "clicked", G_CALLBACK(preference_filename_entry_cb), entry);
  }

  return entry;
}

GtkWidget *
create_preference_static_text(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text)
{
  GtkWidget *label;

  if (label_text != NULL)
    label = gtk_label_new(label_text);
  else
    label = gtk_label_new("");
  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), label, 0, grid_position, 2, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(label, tooltip_text);
  gtk_widget_show(label);

  return label;
}

GtkWidget *
create_preference_uat(GtkWidget *main_grid, int grid_position,
    const gchar *label_text, const gchar *tooltip_text, void* uat)
{
  GtkWidget *button;

  set_option_label(main_grid, grid_position, label_text, tooltip_text);

  button = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);

  g_signal_connect(button, "clicked", G_CALLBACK(uat_window_cb), uat);

  ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), button, 1, grid_position, 1, 1);
  if (tooltip_text != NULL)
    gtk_widget_set_tooltip_text(button, tooltip_text);
  gtk_widget_show(button);

  return button;
}


static guint
pref_check(pref_t *pref, gpointer user_data)
{
  const char  *str_val;
  char        *p;
  pref_t     **badpref = (pref_t **)user_data;

  /* Fetch the value of the preference, and check whether it's valid. */
  switch (pref->type) {

  case PREF_UINT:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    errno = 0;

    /* XXX: The following ugly hack prevents a gcc warning
       "ignoring return value of 'strtoul', declared with attribute warn_unused_result"
       which can occur when using certain gcc configurations (see -D_FORTIFY_SOURCE).
       A dummy variable is not used because when using gcc 4.6 with -Wextra a
       "set but not used [-Wunused-but-set-variable]" warning will occur.
       (Coverity & CLang apparently do not object to this hack).

       [Guy Harris comment:
        "... perhaps either using spin buttons for numeric preferences, or otherwise making
         it impossible to type something that's not a number into the GUI for those preferences,
         and thus avoiding the need to check whether it's a valid number, would also be a good idea."
       ]
    */
    if (strtoul(str_val, &p, pref->info.base)){}
    if (p == str_val || *p != '\0' || errno != 0) {
      *badpref = pref;
      return PREFS_SET_SYNTAX_ERR;      /* number was bad */
    }
    break;

  case PREF_BOOL:
    /* Value can't be bad. */
    break;

  case PREF_ENUM:
    /* Value can't be bad. */
    break;

  case PREF_STRING:
  case PREF_FILENAME:
  case PREF_DIRNAME:
    /* Value can't be bad. */
    break;

  case PREF_RANGE:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));

    if (strlen(str_val) != 0) {
      range_t *newrange;

      if (range_convert_str(&newrange, str_val, pref->info.max_value) != CVT_NO_ERROR) {
        *badpref = pref;
        return PREFS_SET_SYNTAX_ERR;    /* range was bad */
      }
      g_free(newrange);
    }
    break;

  case PREF_STATIC_TEXT:
  case PREF_UAT:
    /* Value can't be bad. */
    break;

  case PREF_COLOR:
  case PREF_CUSTOM:
      /* currently not supported */

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

static guint
module_prefs_check(module_t *module, gpointer user_data)
{
  /* Ignore any preferences with their own interface */
  if (!module->use_gui) {
      return 0;
  }

  /* For all preferences in this module, fetch its value from this
     module's notebook page and check whether it's valid. */
  return prefs_pref_foreach(module, pref_check, user_data);
}

static guint
pref_fetch(pref_t *pref, gpointer user_data)
{
  const char *str_val;
  char       *p;
  guint       uval;
  gboolean    bval;
  gint        enumval;
  gboolean   *pref_changed_p = (gboolean *)user_data;

  /* Fetch the value of the preference, and set the appropriate variable
     to it. */
  switch (pref->type) {

  case PREF_UINT:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    uval = (guint)strtoul(str_val, &p, pref->info.base);
#if 0
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;      /* number was bad */
#endif
    if (*pref->varp.uint != uval) {
      *pref_changed_p = TRUE;
      *pref->varp.uint = uval;
    }
    break;

  case PREF_BOOL:
    bval = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pref->control));
    if (*pref->varp.boolp != bval) {
      *pref_changed_p = TRUE;
      *pref->varp.boolp = bval;
    }
    break;

  case PREF_ENUM:
    if (pref->info.enum_info.radio_buttons) {
      enumval = fetch_preference_radio_buttons_val((GtkWidget *)pref->control,
          pref->info.enum_info.enumvals);
    } else {
      enumval = fetch_preference_option_menu_val((GtkWidget *)pref->control,
                                                 pref->info.enum_info.enumvals);
    }

    if (*pref->varp.enump != enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = enumval;
    }
    break;

  case PREF_STRING:
  case PREF_FILENAME:
  case PREF_DIRNAME:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    prefs_set_string_like_value(pref, str_val, pref_changed_p);
    break;

  case PREF_RANGE:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    if (!prefs_set_range_value(pref, str_val, pref_changed_p))
#if 0
      return PREFS_SET_SYNTAX_ERR;      /* range was bad */
#else
      return 0; /* XXX - should fail */
#endif

    break;

  case PREF_STATIC_TEXT:
  case PREF_UAT:
    break;

  case PREF_COLOR:
  case PREF_CUSTOM:
      /* currently not supported */

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

static guint
module_prefs_fetch(module_t *module, gpointer user_data)
{
  gboolean *must_redissect_p = (gboolean *)user_data;

  /* Ignore any preferences with their own interface */
  if (!module->use_gui) {
      return 0;
  }

  /* For all preferences in this module, fetch its value from this
     module's notebook page.  Find out whether any of them changed. */
  module->prefs_changed = FALSE;        /* assume none of them changed */
  prefs_pref_foreach(module, pref_fetch, &module->prefs_changed);

  /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
  if (module->prefs_changed)
    *must_redissect_p = TRUE;

  return 0;     /* keep fetching module preferences */
}

#ifdef HAVE_AIRPCAP
/*
 * This function is used to apply changes and update the Wireless Toolbar
 * whenever we apply some changes to the WEP preferences
 */
static void
prefs_airpcap_update(void)
{
  GtkWidget *decryption_cm;
  gint       cur_active;
  gboolean   wireshark_decryption_was_enabled    = FALSE;
  gboolean   airpcap_decryption_was_enabled      = FALSE;
  gboolean   wireshark_decryption_is_now_enabled = FALSE;

  decryption_cm = GTK_WIDGET(g_object_get_data(G_OBJECT(wireless_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY));

  if (decryption_cm == NULL) {
    return;
  }

  cur_active = gtk_combo_box_get_active(GTK_COMBO_BOX(decryption_cm));

  if (cur_active < 0) {
    return;
  }

  switch(cur_active) {
    /* XXX - Don't use magic numbers here. cf airpcap_dlg.c:on_decryption_mode_cb_changed() */
    case 1: /* Wireshark */
      wireshark_decryption_was_enabled = TRUE;
      airpcap_decryption_was_enabled = FALSE;
      break;
    case 2: /* Driver */
      wireshark_decryption_was_enabled = FALSE;
      airpcap_decryption_was_enabled = TRUE;
      break;
    default:
      wireshark_decryption_was_enabled = FALSE;
      airpcap_decryption_was_enabled = FALSE;
      break;
  }

  wireshark_decryption_is_now_enabled = wireshark_decryption_on();

  if (wireshark_decryption_is_now_enabled && airpcap_decryption_was_enabled)
  {
    set_airpcap_decryption(FALSE);
    gtk_combo_box_set_active(GTK_COMBO_BOX(decryption_cm), 1);
  }
  if (wireshark_decryption_is_now_enabled && !airpcap_decryption_was_enabled)
  {
    set_airpcap_decryption(FALSE);
    gtk_combo_box_set_active(GTK_COMBO_BOX(decryption_cm), 1);
  }
  else if (!wireshark_decryption_is_now_enabled && wireshark_decryption_was_enabled)
  {
    if (airpcap_decryption_was_enabled)
    {
      set_airpcap_decryption(TRUE);
      gtk_combo_box_set_active(GTK_COMBO_BOX(decryption_cm), 2);
    }
    else
    {
      set_airpcap_decryption(FALSE);
      gtk_combo_box_set_active(GTK_COMBO_BOX(decryption_cm), 0);
    }
  }
}
#endif

static guint
module_prefs_clean_stash(module_t *module, gpointer user_data _U_)
{
  /* Ignore any preferences with their own interface */
  if (!module->use_gui) {
      return 0;
  }

  /* For all preferences in this module, clean up any cruft allocated for
     use by the GUI code. */
  prefs_pref_foreach(module, pref_clean_stash, NULL);
  return 0;     /* keep cleaning modules */
}

/* fetch all pref values from all pages */
static gboolean
prefs_main_fetch_all(GtkWidget *dlg, gboolean *must_redissect)
{
  pref_t *badpref;

  /* First, check that the values are all valid. */
  /* XXX - check the non-registered preferences too */
  switch (prefs_modules_foreach(module_prefs_check, (gpointer)&badpref)) {

    case PREFS_SET_SYNTAX_ERR:
      switch (badpref->type) {

    case PREF_UINT:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "The value for \"%s\" isn't a valid number.",
                    badpref->title);
      return FALSE;

    case PREF_RANGE:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "The value for \"%s\" isn't a valid range.",
                    badpref->title);
      return FALSE;

    default:
      g_assert_not_reached();
      break;
    }
  }

  /* Fetch the preferences (i.e., make sure all the values set in all of
     the preferences panes have been copied to "prefs" and the registered
     preferences). */
  gui_prefs_fetch((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_PAGE_KEY));
  layout_prefs_fetch((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_LAYOUT_PAGE_KEY));
  column_prefs_fetch((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_COLUMN_PAGE_KEY));
  font_color_prefs_fetch((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_FONT_COLORS_PAGE_KEY));

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  capture_prefs_fetch((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_CAPTURE_PAGE_KEY));
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
  filter_expressions_prefs_fetch((GtkWidget *)g_object_get_data(G_OBJECT(dlg),
    E_FILTER_EXPRESSIONS_PAGE_KEY));
  prefs_modules_foreach(module_prefs_fetch, must_redissect);

  return TRUE;
}

/* apply all pref values to the real world */
static void
prefs_main_apply_all(GtkWidget *dlg, gboolean redissect)
{
  GtkWidget *save_bt;

  /*
   * Apply the protocol preferences first - "gui_prefs_apply()" could
   * cause redissection, and we have to make sure the protocol
   * preference changes have been fully applied.
   */
  prefs_apply_all();

  gui_prefs_apply((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_PAGE_KEY));
  layout_prefs_apply((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_LAYOUT_PAGE_KEY));
  column_prefs_apply((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_COLUMN_PAGE_KEY));
  font_color_prefs_apply((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_FONT_COLORS_PAGE_KEY), redissect);

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  capture_prefs_apply((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_CAPTURE_PAGE_KEY));
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

  /* show/hide the Save button - depending on setting */
  save_bt = (GtkWidget *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_SAVE_BT_KEY);
  if (prefs.gui_use_pref_save) {
    gtk_widget_show(save_bt);
  } else {
    gtk_widget_hide(save_bt);
  }
}


/* destroy all preferences ressources from all pages */
static void
prefs_main_destroy_all(GtkWidget *dlg)
{
  int        page_num;
  GtkWidget *frame;

  for (page_num = 0;
       (frame = gtk_notebook_get_nth_page((GtkNotebook *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY), page_num)) != NULL;
       page_num++) {
    if (g_object_get_data(G_OBJECT(frame), E_PAGE_ITER_KEY))
      gtk_tree_iter_free((GtkTreeIter *)g_object_get_data(G_OBJECT(frame), E_PAGE_ITER_KEY));
  }

  gui_prefs_destroy((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_PAGE_KEY));
  layout_prefs_destroy((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_LAYOUT_PAGE_KEY));
  column_prefs_destroy((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_COLUMN_PAGE_KEY));
  font_color_prefs_destroy((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_GUI_FONT_COLORS_PAGE_KEY));

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  capture_prefs_destroy((GtkWidget *)g_object_get_data(G_OBJECT(dlg), E_CAPTURE_PAGE_KEY));
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

  /* Free up the saved preferences (both for "prefs" and for registered
     preferences). */
  prefs_modules_foreach(module_prefs_clean_stash, NULL);
}

static guint
module_prefs_copy(module_t *module, gpointer user_data _U_)
{
  /* Ignore any preferences with their own interface */
  if (!module->use_gui) {
      return 0;
  }

  /* For all preferences in this module, (re)save current value */
  prefs_pref_foreach(module, pref_stash, NULL);
  return 0;     /* continue making copies */
}

/* Copy prefs to saved values so we can revert to these values */
/*  if the user selects Cancel.                                */
static void prefs_copy(void) {
  prefs_modules_foreach(module_prefs_copy, NULL);
}

static void
overwrite_existing_prefs_cb(gpointer dialog _U_, gint btn, gpointer parent_w _U_)
{
  switch (btn) {
    case(ESD_BTN_SAVE):
      prefs_main_write();
      prefs.unknown_prefs = FALSE;
      break;
    case(ESD_BTN_DONT_SAVE):
      break;
    default:
      g_assert_not_reached();
  }
}
static void
prefs_main_save(gpointer parent_w)
{
  if (prefs.unknown_prefs) {
    gpointer dialog;
    const gchar *msg =
      "Obsolete or unrecognized preferences have been detected and will be "
      "discarded when saving this profile. If you would like to preserve "
      "these preferences for a different Wireshark version, click "
      "'Continue without Saving' and save this profile under a different name.";

    if (prefs.saved_at_version) {
      dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE,
          "These preferences were last saved at version \"%s\".\n%s",
          prefs.saved_at_version, msg);
    } else {
      dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE,
          "%s", msg);
    }

    simple_dialog_set_cb(dialog, overwrite_existing_prefs_cb, parent_w);
  } else {
    prefs_main_write();
  }
}

static void
prefs_main_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  if (!prefs_main_fetch_all((GtkWidget *)parent_w, &must_redissect))
    return; /* Errors in some preference setting - already reported */

  /* if we don't have a Save button, just save the settings now */
  if (!prefs.gui_use_pref_save) {
    prefs_main_save(parent_w);
  }

#ifdef HAVE_AIRPCAP
  /*
   * Load the Wireshark decryption keys (just set) and save
   * the changes to the adapters' registry
   */
  airpcap_load_decryption_keys(g_airpcap_if_list);
#endif

  prefs_main_apply_all((GtkWidget *)parent_w, must_redissect);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

#ifdef HAVE_AIRPCAP
  prefs_airpcap_update();
#endif

  /* Now destroy the "Preferences" dialog. */
  window_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets();
    redissect_all_packet_windows();
  }

}

static void
prefs_main_apply_cb(GtkWidget *apply_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  if (!prefs_main_fetch_all((GtkWidget *)parent_w, &must_redissect))
    return; /* Errors in some preference setting - already reported */

  /* if we don't have a Save button, just save the settings now */
  if (!prefs.gui_use_pref_save) {
    prefs_main_save(parent_w);
    prefs_copy();     /* save prefs for reverting if Cancel */
  }

  prefs_main_apply_all((GtkWidget *)parent_w, must_redissect);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

#ifdef HAVE_AIRPCAP
  prefs_airpcap_update();
#endif

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets();
    redissect_all_packet_windows();
  }
}

static void
prefs_main_save_cb(GtkWidget *save_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  if (!prefs_main_fetch_all((GtkWidget *)parent_w, &must_redissect))
    return; /* Errors in some preference setting - already reported */

  prefs_main_save(parent_w);
  prefs_copy();     /* save prefs for reverting if Cancel */

  /* Now apply those preferences.
     XXX - should we do this?  The user didn't click "OK" or "Apply".
     However:

        1) by saving the preferences they presumably indicate that they
           like them;

        2) the next time they fire Wireshark up, those preferences will
           apply;

        3) we'd have to buffer "must_redissect" so that if they do
           "Apply" after this, we know we have to redissect;

        4) we did apply the protocol preferences, at least, in the past. */
  prefs_main_apply_all((GtkWidget *)parent_w, must_redissect);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets();
    redissect_all_packet_windows();
  }
}

static guint
module_prefs_revert(module_t *module, gpointer user_data)
{
  gboolean *must_redissect_p = (gboolean *)user_data;

  /* Ignore any preferences with their own interface */
  if (!module->use_gui) {
      return 0;
  }

  /* For all preferences in this module, revert its value to the value
     it had when we popped up the Preferences dialog.  Find out whether
     this changes any of them. */
  module->prefs_changed = FALSE;        /* assume none of them changed */
  prefs_pref_foreach(module, pref_unstash, &module->prefs_changed);

  /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
  if (module->prefs_changed)
    *must_redissect_p = TRUE;
  return 0;     /* keep processing modules */
}

/* cancel button pressed, revert prefs to saved and exit dialog */
static void
prefs_main_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  /* Free up the current preferences and copy the saved preferences to the
     current preferences. */
  cfile.columns_changed = FALSE; /* [XXX: "columns_changed" should treally be stored in prefs struct ??] */

  /* Now revert the registered preferences. */
  prefs_modules_foreach(module_prefs_revert, &must_redissect);

  /* Now apply the reverted-to preferences. */
  prefs_main_apply_all((GtkWidget *)parent_w, must_redissect);

  window_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets();
    redissect_all_packet_windows();
  }
}

/* Treat this as a cancel, by calling "prefs_main_cancel_cb()" */
static gboolean
prefs_main_delete_event_cb(GtkWidget *prefs_w_lcl, GdkEvent *event _U_,
                           gpointer user_data _U_)
{
  prefs_main_cancel_cb(NULL, prefs_w_lcl);
  return FALSE;
}


/* dialog *is* already destroyed, clean up memory and such */
static void
prefs_main_destroy_cb(GtkWidget *win _U_, gpointer parent_w)
{
  prefs_main_destroy_all((GtkWidget *)parent_w);

  /* Note that we no longer have a "Preferences" dialog box. */
  prefs_w = NULL;
}

struct properties_data {
  const char *title;
  module_t   *module;
};

static guint
module_search_properties(module_t *module, gpointer user_data)
{
  struct properties_data *p = (struct properties_data *)user_data;

  if (!module->use_gui) {
      /* This module uses its own GUI interface, so its not a part
       * of this search
       */
      return 0;
  }

  /* If this module has the specified title, remember it. */
  if (strcmp(module->title, p->title) == 0) {
    p->module = module;
    return 1;   /* stops the search */
  }

  if (prefs_module_has_submodules(module))
    return prefs_modules_foreach_submodules(module, module_search_properties, p);

  return 0;
}

static void
tree_expand_row(GtkTreeModel *model, GtkTreeView *tree_view, GtkTreeIter *iter)
{
  GtkTreeIter  parent;
  GtkTreePath *path;

  /* expand the parent first */
  if (gtk_tree_model_iter_parent(model, &parent, iter))
    tree_expand_row(model, tree_view, &parent);

  path = gtk_tree_model_get_path(model, iter);
  gtk_tree_view_expand_row(tree_view, path, FALSE);
  /*expand_tree(tree_view, &parent, NULL, NULL);*/

  gtk_tree_path_free(path);
}

/* select a node in the tree view */
/* XXX - this is almost 100% copied from byte_view_select() in proto_draw.c,
 *       find a way to combine both to have a generic function for this */
static void
tree_select_node(GtkWidget *tree, prefs_tree_iter *iter)
{
  GtkTreeIter   local_iter = *iter;
  GtkTreeView  *tree_view  = GTK_TREE_VIEW(tree);
  GtkTreeModel *model;
  GtkTreePath  *first_path;

  model = gtk_tree_view_get_model(tree_view);

  /* Expand our field's row */
  first_path = gtk_tree_model_get_path(model, &local_iter);

  /* expand from the top down */
  tree_expand_row(model, tree_view, &local_iter);

  /* select our field's row */
  gtk_tree_selection_select_path(gtk_tree_view_get_selection(tree_view),
                                 first_path);

  /* And position the window so the selection is visible.
   * Position the selection in the middle of the viewable
   * pane. */
  gtk_tree_view_scroll_to_cell(tree_view, first_path, NULL, TRUE, 0.5f, 0.0f);

  gtk_tree_path_free(first_path);
}


/* search the corresponding protocol page of the currently selected field */
void
properties_cb(GtkWidget *w, gpointer dummy)
{
  header_field_info      *hfinfo;
  const gchar            *title = NULL;
  struct properties_data  p;
  int                     page_num;
  GtkWidget              *sw;
  GtkWidget              *frame;
  module_t               *page_module;

  if (cfile.finfo_selected == NULL) {
    const gchar *abbrev;

    /* There is no field selected, try use on top protocol */
    if (cfile.edt && cfile.edt->tree) {
        GPtrArray          *ga;
        field_info         *v;
        guint              i;

        ga = proto_all_finfos(cfile.edt->tree);

        for (i = ga->len - 1; i > 0 ; i -= 1) {

            v = (field_info *)g_ptr_array_index (ga, i);
            hfinfo =  v->hfinfo;

            if (!g_str_has_prefix(hfinfo->abbrev, "text") &&
                    !g_str_has_prefix(hfinfo->abbrev, "_ws.expert") &&
                    !g_str_has_prefix(hfinfo->abbrev, "_ws.malformed")) {
                if (hfinfo->parent == -1) {
                    abbrev = hfinfo->abbrev;
                } else {
                    abbrev = proto_registrar_get_abbrev(hfinfo->parent);
                }
                title = prefs_get_title_by_name(abbrev);
                break;
            }
        }
    }
  } else {
    /* Find the title for the protocol for the selected field. */
    hfinfo = cfile.finfo_selected->hfinfo;
    if (hfinfo->parent == -1)
        title = prefs_get_title_by_name(hfinfo->abbrev);
    else
        title = prefs_get_title_by_name(proto_registrar_get_abbrev(hfinfo->parent));
  }

  if (!title)
    return;     /* Couldn't find it. XXX - just crash? "Can't happen"? */

  /* Find the module for that protocol by searching for one with that title.
     XXX - should we just associate protocols with modules directly? */
  p.title = title;
  p.module = NULL;
  prefs_modules_foreach_submodules(protocols_module, module_search_properties,
                            &p);
  if (p.module == NULL) {
    /* We didn't find it - that protocol probably has no preferences. */
    return;
  }

  /* Create a preferences window, or pop up an existing one. */
  if (prefs_w != NULL) {
    reactivate_window(prefs_w);
  } else {
    prefs_cb(w, dummy);
  }

  /* Search all the pages in that window for the one with the specified
     module. */
  for (page_num = 0;
       (sw = gtk_notebook_get_nth_page((GtkNotebook *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY), page_num)) != NULL;
       page_num++) {
    /* Get the frame from the scrollable window */
    frame = (GtkWidget *)g_object_get_data(G_OBJECT(sw), E_PAGESW_FRAME_KEY);
    /* Get the module for this page (non-protocol prefs don't have one). */
    if (frame) {
      page_module = (module_t *)g_object_get_data(G_OBJECT(frame), E_PAGE_MODULE_KEY);
      if (page_module != NULL) {
        if (page_module == p.module) {
          tree_select_node(
            (GtkWidget *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_TREE_KEY),
            (GtkTreeIter *)g_object_get_data(G_OBJECT(frame), E_PAGE_ITER_KEY));
          return;
        }
      }
    }
  }
}

/* Prefs tree selection callback.  The node data has been loaded with
   the proper notebook page to load. */
static void
prefs_tree_select_cb(GtkTreeSelection *sel, gpointer dummy _U_)
{
  gint          page;
  GtkTreeModel *model;
  GtkTreeIter   iter;

  if (gtk_tree_selection_get_selected(sel, &model, &iter))
  {
    gtk_tree_model_get(model, &iter, 1, &page, -1);
    if (page >= 0)
      gtk_notebook_set_current_page((GtkNotebook *)g_object_get_data(G_OBJECT(prefs_w), E_PREFSW_NOTEBOOK_KEY), page);
  }
}



/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
