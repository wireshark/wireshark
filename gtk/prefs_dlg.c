/* prefs_dlg.c
 * Routines for handling preferences
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

#include <gtk/gtk.h>

#include <string.h>

#include <epan/filesystem.h>

#include "main.h"
#include <epan/packet.h>
#include "file.h"
#include <epan/prefs.h>
#include "column_prefs.h"
#include "print.h"
#include "prefs_dlg.h"
#include "print_prefs.h"
#include "stream_prefs.h"
#include "gui_prefs.h"
#include "layout_prefs.h"
#include "capture_prefs.h"
#include "nameres_prefs.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "simple_dialog.h"
#include "compat_macros.h"
#include "help_dlg.h"
#include "keys.h"

#include <epan/prefs-int.h>

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
#include "capture-wpcap.h"
#endif /* _WIN32 */
#include "airpcap.h"
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"
#endif

static void     prefs_main_ok_cb(GtkWidget *, gpointer);
static void     prefs_main_apply_cb(GtkWidget *, gpointer);
static void     prefs_main_save_cb(GtkWidget *, gpointer);
static void     prefs_main_cancel_cb(GtkWidget *, gpointer);
static gboolean prefs_main_delete_event_cb(GtkWidget *, GdkEvent *, gpointer);
static void     prefs_main_destroy_cb(GtkWidget *, gpointer);
#if GTK_MAJOR_VERSION < 2
static void	prefs_tree_select_cb(GtkCTree *, GtkCTreeNode *, gint,
                                     gpointer);
#else
static void	prefs_tree_select_cb(GtkTreeSelection *, gpointer);
#endif

#define E_PREFSW_SCROLLW_KEY    "prefsw_scrollw"
#define E_PREFSW_TREE_KEY       "prefsw_tree"
#define E_PREFSW_NOTEBOOK_KEY   "prefsw_notebook"
#define E_PREFSW_SAVE_BT_KEY    "prefsw_save_bt"
#define E_PAGE_ITER_KEY         "page_iter"
#define E_PAGE_MODULE_KEY       "page_module"
#define E_PAGESW_FRAME_KEY      "pagesw_frame"

#define E_GUI_PAGE_KEY	        "gui_options_page"
#define E_GUI_LAYOUT_PAGE_KEY	"gui_layout_page"
#define E_GUI_COLUMN_PAGE_KEY   "gui_column_options_page"
#define E_GUI_FONT_PAGE_KEY     "gui_font_options_page"
#define E_GUI_COLORS_PAGE_KEY   "gui_colors_options_page"
#define E_CAPTURE_PAGE_KEY      "capture_options_page"
#define E_PRINT_PAGE_KEY        "printer_options_page"
#define E_NAMERES_PAGE_KEY      "nameres_options_page"

/*
 * Keep a static pointer to the current "Preferences" window, if any, so that
 * if somebody tries to do "Edit:Preferences" while there's already a
 * "Preferences" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *prefs_w;

/*
 * Save the value of the preferences as of when the preferences dialog
 * box was first popped up, so we can revert to those values if the
 * user selects "Cancel".
 */
static e_prefs saved_prefs;

struct ct_struct {
  GtkWidget    *main_vb;
  GtkWidget    *notebook;
  GtkWidget    *tree;
#if GTK_MAJOR_VERSION < 2
  GtkCTreeNode *node;
#else
  GtkTreeIter  iter;
#endif
  GtkTooltips  *tooltips;
  gint         page;
  gboolean     is_protocol;
};

static guint
pref_exists(pref_t *pref _U_, gpointer user_data _U_)
{
  return 1;
}

/* show a single preference on the GtkTable of a preference page */
static guint
pref_show(pref_t *pref, gpointer user_data)
{
  GtkWidget *main_tb = user_data;
  const char *title;
  char *label_string;
  char uint_str[10+1];

  /* Give this preference a label which is its title, followed by a colon,
     and left-align it. */
  title = pref->title;
  label_string = g_malloc(strlen(title) + 2);
  strcpy(label_string, title);
  strcat(label_string, ":");

  /* Save the current value of the preference, so that we can revert it if
     the user does "Apply" and then "Cancel", and create the control for
     editing the preference. */
  switch (pref->type) {

  case PREF_UINT:
    pref->saved_val.uint = *pref->varp.uint;

    /* XXX - there are no uint spinbuttons, so we can't use a spinbutton.
       Even more annoyingly, even if there were, GLib doesn't define
       G_MAXUINT - but I think ANSI C may define UINT_MAX, so we could
       use that. */
    switch (pref->info.base) {

    case 10:
      g_snprintf(uint_str, 10+1, "%u", pref->saved_val.uint);
      break;

    case 8:
      g_snprintf(uint_str, 10+1, "%o", pref->saved_val.uint);
      break;

    case 16:
      g_snprintf(uint_str, 10+1, "%x", pref->saved_val.uint);
      break;
    }
    pref->control = create_preference_entry(main_tb, pref->ordinal,
					    label_string, pref->description,
					    uint_str);
    break;

  case PREF_BOOL:
    pref->saved_val.boolval = *pref->varp.boolp;
    pref->control = create_preference_check_button(main_tb, pref->ordinal,
					       label_string, pref->description,
					       pref->saved_val.boolval);
    break;

  case PREF_ENUM:
    pref->saved_val.enumval = *pref->varp.enump;
    if (pref->info.enum_info.radio_buttons) {
      /* Show it as radio buttons. */
      pref->control = create_preference_radio_buttons(main_tb, pref->ordinal,
						  label_string, pref->description,
						  pref->info.enum_info.enumvals,
						  pref->saved_val.enumval);
    } else {
      /* Show it as an option menu. */
      pref->control = create_preference_option_menu(main_tb, pref->ordinal,
					 label_string, pref->description,
					 pref->info.enum_info.enumvals,
					 pref->saved_val.enumval);
    }
    break;

  case PREF_STRING:
    if (pref->saved_val.string != NULL)
      g_free(pref->saved_val.string);
    pref->saved_val.string = g_strdup(*pref->varp.string);
    pref->control = create_preference_entry(main_tb, pref->ordinal,
					    label_string, pref->description,
					    pref->saved_val.string);
    break;

  case PREF_RANGE:
  {
    char *range_string;

    if (pref->saved_val.range != NULL)
      g_free(pref->saved_val.range);
    pref->saved_val.range = range_copy(*pref->varp.range);
    range_string = range_convert_range(*pref->varp.range);
    pref->control = create_preference_entry(main_tb, pref->ordinal,
					    label_string, pref->description,
					    range_string);
    break;
  }

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  g_free(label_string);

  return 0;
}

#define MAX_TREE_NODE_NAME_LEN 64
/* show prefs page for each registered module (protocol) */
static guint
module_prefs_show(module_t *module, gpointer user_data)
{
  struct ct_struct *cts = user_data;
  struct ct_struct child_cts;
  GtkWidget        *main_vb, *main_tb, *frame, *main_sw;
  gchar            label_str[MAX_TREE_NODE_NAME_LEN];
#if GTK_MAJOR_VERSION < 2
  gchar            *label_ptr = label_str;
  GtkCTreeNode     *ct_node;
#else
  GtkTreeStore     *model;
  GtkTreeIter      iter;
#endif

  /*
   * Is this module a subtree, with modules underneath it?
   */
  if (!module->is_subtree) {
    /*
     * No.
     * Does it have any preferences (other than possibly obsolete ones)?
     */
    if (prefs_pref_foreach(module, pref_exists, NULL) == 0) {
      /*
       * No.  Don't put the module into the preferences window.
       * XXX - we should do the same for subtrees; if a subtree has
       * nothing under it that will be displayed, don't put it into
       * the window.
       */
      return 0;
    }
  }

  /*
   * Add this module to the tree.
   */
  strcpy(label_str, module->title);
#if GTK_MAJOR_VERSION < 2
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts->tree), cts->node, NULL,
  		&label_ptr, 5, NULL, NULL, NULL, NULL, !module->is_subtree,
  		FALSE);
#else
  model = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(cts->tree)));
  if (module->is_subtree)
      gtk_tree_store_append(model, &iter, NULL);
  else
      gtk_tree_store_append(model, &iter, &cts->iter);
#endif

  /*
   * Is this a subtree?
   */
  if (module->is_subtree) {
    /*
     * Yes.
     */

    /* Note that there's no page attached to this item */
#if GTK_MAJOR_VERSION < 2
    gtk_ctree_node_set_row_data(GTK_CTREE(cts->tree), ct_node,
  		GINT_TO_POINTER(-1));
#else
    gtk_tree_store_set(model, &iter, 0, label_str, 1, -1, -1);
#endif

    /*
     * Walk the subtree and attach stuff to it.
     */
    child_cts = *cts;
#if GTK_MAJOR_VERSION < 2
    child_cts.node = ct_node;
#else
    child_cts.iter = iter;
#endif
    if (module == protocols_module)
      child_cts.is_protocol = TRUE;
    prefs_module_list_foreach(module->prefs, module_prefs_show, &child_cts);
  } else {
    /*
     * No.  Create a notebook page for it.
     */

    /* Scrolled window */
    main_sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(main_sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

    /* Frame */
    frame = gtk_frame_new(module->description);
    gtk_container_set_border_width(GTK_CONTAINER(frame), 5);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(main_sw), frame);
    OBJECT_SET_DATA(main_sw, E_PAGESW_FRAME_KEY, frame);

    /* Main vertical box */
    main_vb = gtk_vbox_new(FALSE, 5);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(frame), main_vb);

    /* Main table */
    main_tb = gtk_table_new(module->numprefs, 2, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
    gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
    gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
    OBJECT_SET_DATA(main_tb, E_TOOLTIPS_KEY, cts->tooltips);

    /* Add items for each of the preferences */
    prefs_pref_foreach(module, pref_show, main_tb);

    /* Associate this module with the page's frame. */
    OBJECT_SET_DATA(frame, E_PAGE_MODULE_KEY, module);

    /* Add the page to the notebook */
    gtk_notebook_append_page(GTK_NOTEBOOK(cts->notebook), main_sw, NULL);

    /* Attach the page to the tree item */
#if GTK_MAJOR_VERSION < 2
    gtk_ctree_node_set_row_data(GTK_CTREE(cts->tree), ct_node,
  		GINT_TO_POINTER(cts->page));
    OBJECT_SET_DATA(frame, E_PAGE_ITER_KEY, ct_node);
#else
    gtk_tree_store_set(model, &iter, 0, label_str, 1, cts->page, -1);
    OBJECT_SET_DATA(frame, E_PAGE_ITER_KEY, gtk_tree_iter_copy(&iter));
#endif

    cts->page++;

    /* Show 'em what we got */
    gtk_widget_show_all(main_sw);
  }

  return 0;
}


#if GTK_MAJOR_VERSION < 2
#define prefs_tree_iter GtkCTreeNode *
#else
#define prefs_tree_iter GtkTreeIter
#endif

/* add a page to the tree */
static prefs_tree_iter
prefs_tree_page_add(const gchar *title, gint page_nr,
                    gpointer store, prefs_tree_iter *parent_iter,
                    gboolean has_child
#if GTK_MAJOR_VERSION >= 2
                    _U_
#endif
                    )
{
#if GTK_MAJOR_VERSION < 2
  const gchar       *label_ptr = title;
#endif
  prefs_tree_iter   iter;

#if GTK_MAJOR_VERSION < 2
  iter = gtk_ctree_insert_node(GTK_CTREE(store), parent_iter ? *parent_iter : NULL, NULL,
  		(gchar **) &label_ptr, 5, NULL, NULL, NULL, NULL, !has_child, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(store), iter,
  		GINT_TO_POINTER(page_nr));
#else
  gtk_tree_store_append(store, &iter, parent_iter);
  gtk_tree_store_set(store, &iter, 0, title, 1, page_nr, -1);
#endif
  return iter;
}

/* add a page to the notebook */
static GtkWidget *
prefs_nb_page_add(GtkWidget *notebook, const gchar *title, GtkWidget *page, const char *page_key)
{
  GtkWidget         *frame;

  frame = gtk_frame_new(title);
  gtk_widget_show(frame);
  gtk_container_add(GTK_CONTAINER(frame), page);
  OBJECT_SET_DATA(prefs_w, page_key, page);
  gtk_notebook_append_page (GTK_NOTEBOOK(notebook), frame, NULL);

  return frame;
}


/* show the dialog */
void
prefs_cb(GtkWidget *w _U_, gpointer dummy _U_)
{
  GtkWidget         *top_hb, *bbox, *prefs_nb, *ct_sb,
                    *ok_bt, *apply_bt, *save_bt, *cancel_bt, *help_bt;
  GtkWidget         *gui_font_pg;
  gchar             label_str[MAX_TREE_NODE_NAME_LEN];
  struct ct_struct  cts;
#if GTK_MAJOR_VERSION < 2
  gpointer          store = NULL;
  static gchar *fixedwidths[] = { "c", "m", NULL };
#else
  GtkTreeStore      *store;
  GtkTreeSelection  *selection;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  gint              col_offset;
#endif
  prefs_tree_iter   gui_iter;


  if (prefs_w != NULL) {
    /* There's already a "Preferences" dialog box; reactivate it. */
    reactivate_window(prefs_w);
    return;
  }

  /* Save the current preferences, so we can revert to those values
     if the user presses "Cancel". */
  copy_prefs(&saved_prefs, &prefs);

  prefs_w = dlg_window_new("Wireshark: Preferences");

  /*
   * Unfortunately, we can't arrange that a GtkTable widget wrap an event box
   * around a table row, so the spacing between the preference item's label
   * and its control widgets is inactive and the tooltip doesn't pop up when
   * the mouse is over it.
   */
  cts.tooltips = gtk_tooltips_new();

  /* Container for each row of widgets */
  cts.main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(cts.main_vb), 5);
  gtk_container_add(GTK_CONTAINER(prefs_w), cts.main_vb);
  gtk_widget_show(cts.main_vb);

  /* Top row: Preferences tree and notebook */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(cts.main_vb), top_hb);
  gtk_widget_show(top_hb);

  /* scrolled window on the left for the categories tree */
  ct_sb = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(ct_sb),
                                   GTK_SHADOW_IN);
#endif
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ct_sb),
  	GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(top_hb), ct_sb);
  gtk_widget_show(ct_sb);
  OBJECT_SET_DATA(prefs_w, E_PREFSW_SCROLLW_KEY, ct_sb);

  /* categories tree */
#if GTK_MAJOR_VERSION < 2
  cts.tree = ctree_new(1, 0);
  store = cts.tree;
  cts.node = NULL;
  gtk_clist_set_column_auto_resize(GTK_CLIST(cts.tree), 0, TRUE);
  SIGNAL_CONNECT(cts.tree, "tree-select-row", prefs_tree_select_cb, NULL);
  OBJECT_SET_DATA(prefs_w, E_PREFSW_TREE_KEY, cts.tree);
#else
  store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_INT);
  cts.tree = tree_view_new(GTK_TREE_MODEL(store));
  OBJECT_SET_DATA(prefs_w, E_PREFSW_TREE_KEY, cts.tree);
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
  SIGNAL_CONNECT(selection, "changed", prefs_tree_select_cb, NULL);
#endif
  gtk_container_add(GTK_CONTAINER(ct_sb), cts.tree);
  gtk_widget_show(cts.tree);

  /* A notebook widget without tabs is used to flip between prefs */
  prefs_nb = gtk_notebook_new();
  OBJECT_SET_DATA(prefs_w, E_PREFSW_NOTEBOOK_KEY, prefs_nb);
  gtk_notebook_set_show_tabs(GTK_NOTEBOOK(prefs_nb), FALSE);
  gtk_notebook_set_show_border(GTK_NOTEBOOK(prefs_nb), FALSE);
  gtk_container_add(GTK_CONTAINER(top_hb), prefs_nb);
  gtk_widget_show(prefs_nb);

  cts.page = 0;

  /* GUI prefs */
  strcpy(label_str, "User Interface");
  prefs_nb_page_add(prefs_nb, label_str, gui_prefs_show(), E_GUI_PAGE_KEY);
  gui_iter = prefs_tree_page_add(label_str, cts.page, store, NULL, TRUE);
  cts.page++;

  /* GUI layout prefs */
  strcpy(label_str, "Layout");
  prefs_nb_page_add(prefs_nb, label_str, layout_prefs_show(), E_GUI_LAYOUT_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, &gui_iter, FALSE);
  cts.page++;

  /* GUI Column prefs */
  strcpy(label_str, "Columns");
  prefs_nb_page_add(prefs_nb, label_str, column_prefs_show(), E_GUI_COLUMN_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, &gui_iter, FALSE);
  cts.page++;

  /* GUI Font prefs */
  strcpy(label_str, "Font");
  gui_font_pg = gui_font_prefs_show();
  prefs_nb_page_add(prefs_nb, label_str, gui_font_pg, E_GUI_FONT_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, &gui_iter, FALSE);
  cts.page++;

  gtk_container_border_width( GTK_CONTAINER(gui_font_pg), 5 );

  /* IMPORTANT: the following gtk_font_selection_set_xy() functions will only
     work, if the widget and it's corresponding window is already shown
     (so don't put the following into gui_font_prefs_show()) !!! */

  /* We set the current font and, for GTK+ 1.2[.x], the font filter
     now, because they appear not to work when run before appending
     the frame to the notebook. */

  /* Set the font to the current font.
     XXX - GTK+ 1.2.8, and probably earlier versions, have a bug
     wherein that doesn't necessarily cause that font to be
     selected in the dialog box.  I've sent to the GTK+ folk
     a fix; hopefully, it'll show up in 1.2.9 if, as, and when
     they put out a 1.2.9 release. */
  gtk_font_selection_set_font_name(
	    GTK_FONT_SELECTION(gui_font_pg), prefs.PREFS_GUI_FONT_NAME);

#if GTK_MAJOR_VERSION < 2
  /* Set its filter to show only fixed_width fonts. */
  gtk_font_selection_set_filter(
	    GTK_FONT_SELECTION(gui_font_pg),
	    GTK_FONT_FILTER_BASE, /* user can't change the filter */
	    GTK_FONT_ALL,	  /* bitmap or scalable are fine */
	    NULL,		  /* all foundries are OK */
	    NULL,		  /* all weights are OK (XXX - normal only?) */
	    NULL,		  /* all slants are OK (XXX - Roman only?) */
	    NULL,		  /* all setwidths are OK */
	    fixedwidths,	  /* ONLY fixed-width fonts */
	    NULL);	/* all charsets are OK (XXX - ISO 8859/1 only?) */
#endif

  /* GUI Colors prefs */
  strcpy(label_str, "Colors");
  prefs_nb_page_add(prefs_nb, label_str, stream_prefs_show(), E_GUI_COLORS_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, &gui_iter, FALSE);
  cts.page++;

  /* select the main GUI page as the default page and expand it's children */
#if GTK_MAJOR_VERSION < 2
  gtk_ctree_select(GTK_CTREE(cts.tree), gui_iter);
#else
  gtk_tree_selection_select_iter(selection, &gui_iter);
  /* (expand will only take effect, when at least one child exists) */
  gtk_tree_view_expand_all(GTK_TREE_VIEW(cts.tree));
#endif

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  /* capture prefs */
  strcpy(label_str, "Capture");
  prefs_nb_page_add(prefs_nb, label_str, capture_prefs_show(), E_CAPTURE_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, NULL, FALSE);
  cts.page++;
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

  /* Printing prefs */
  strcpy(label_str, "Printing");
  prefs_nb_page_add(prefs_nb, label_str, printer_prefs_show(), E_PRINT_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, NULL, FALSE);
  cts.page++;

  /* Name resolution prefs */
  strcpy(label_str, "Name Resolution");
  prefs_nb_page_add(prefs_nb, label_str, nameres_prefs_show(), E_NAMERES_PAGE_KEY);
  prefs_tree_page_add(label_str, cts.page, store, NULL, FALSE);
  cts.page++;

  /* Registered prefs */
  cts.notebook = prefs_nb;
  cts.is_protocol = FALSE;
  prefs_module_list_foreach(NULL, module_prefs_show, &cts);

  /* Button row: OK and alike buttons */

  if(topic_available(HELP_PREFERENCES_DIALOG)) {
    bbox = dlg_button_row_new(GTK_STOCK_HELP, GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, NULL);
  } else {
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, NULL);
  }
  gtk_box_pack_start(GTK_BOX(cts.main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  SIGNAL_CONNECT(ok_bt, "clicked", prefs_main_ok_cb, prefs_w);

  apply_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_APPLY);
  SIGNAL_CONNECT(apply_bt, "clicked", prefs_main_apply_cb, prefs_w);

  save_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_SAVE);
  SIGNAL_CONNECT(save_bt, "clicked", prefs_main_save_cb, prefs_w);
  OBJECT_SET_DATA(prefs_w, E_PREFSW_SAVE_BT_KEY, save_bt);

  cancel_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  SIGNAL_CONNECT(cancel_bt, "clicked", prefs_main_cancel_cb, prefs_w);
  window_set_cancel_button(prefs_w, cancel_bt, NULL);

  gtk_widget_grab_default(ok_bt);

  if(topic_available(HELP_PREFERENCES_DIALOG)) {
    help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
    SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_PREFERENCES_DIALOG);
  }

  SIGNAL_CONNECT(prefs_w, "delete_event", prefs_main_delete_event_cb, prefs_w);
  SIGNAL_CONNECT(prefs_w, "destroy", prefs_main_destroy_cb, prefs_w);

  gtk_widget_show(prefs_w);

  /* hide the Save button if the user uses implicit save */
  if(!prefs.gui_use_pref_save) {
    gtk_widget_hide(save_bt);
  }

  window_present(prefs_w);

#if GTK_MAJOR_VERSION >= 2
  g_object_unref(G_OBJECT(store));
#endif
}

static void
set_option_label(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, GtkTooltips *tooltips)
{
	GtkWidget *label;
	GtkWidget *event_box;

	label = gtk_label_new(label_text);
	gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
	gtk_widget_show(label);

	event_box = gtk_event_box_new();
	gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 0, 1,
	    table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, event_box, tooltip_text, NULL);
	gtk_container_add(GTK_CONTAINER(event_box), label);
	gtk_widget_show(event_box);
}

GtkWidget *
create_preference_check_button(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, gboolean active)
{
	GtkTooltips *tooltips;
	GtkWidget *check_box;

	tooltips = OBJECT_GET_DATA(main_tb, E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	check_box = gtk_check_button_new();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check_box), active);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), check_box, 1, 2,
	    table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, check_box, tooltip_text, NULL);

	return check_box;
}

GtkWidget *
create_preference_radio_buttons(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val)
{
	GtkTooltips *tooltips;
	GtkWidget *radio_button_hbox, *button = NULL;
	GSList *rb_group;
	int index;
	const enum_val_t *enum_valp;
	GtkWidget *event_box;

	tooltips = OBJECT_GET_DATA(main_tb, E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	radio_button_hbox = gtk_hbox_new(FALSE, 0);
	rb_group = NULL;
	for (enum_valp = enumvals, index = 0; enum_valp->name != NULL;
	    enum_valp++, index++) {
		button = gtk_radio_button_new_with_label(rb_group,
		    enum_valp->description);
		gtk_widget_show(button);
		rb_group = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
		gtk_box_pack_start(GTK_BOX(radio_button_hbox), button, FALSE,
		    FALSE, 10);
		if (enum_valp->value == current_val) {
			gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
			    TRUE);
		}
	}
	gtk_widget_show(radio_button_hbox);

	event_box = gtk_event_box_new();
	gtk_container_add(GTK_CONTAINER(event_box), radio_button_hbox);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 1, 2,
	    table_position, table_position+1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, event_box, tooltip_text, NULL);
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
	char *label_string;
	int i;

	/* Get the label's text, and translate it to a value.
	   We match only the descriptions, as those are what appear in
	   the option menu items or as labels for radio buttons.
	   We fail if we don't find a match, as that "can't happen". */
	gtk_label_get(GTK_LABEL(label), &label_string);

	for (i = 0; enumvals[i].name != NULL; i++) {
		if (strcasecmp(label_string, enumvals[i].description) == 0) {
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
	rb_group = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	button = NULL;
	for (rb_entry = rb_group; rb_entry != NULL;
	    rb_entry = g_slist_next(rb_entry)) {
		button = rb_entry->data;
		if (GTK_TOGGLE_BUTTON(button)->active)
			break;
	}

	/* OK, now return the value corresponding to that button's label. */
	return label_to_enum_val(GTK_BIN(button)->child, enumvals);
}

GtkWidget *
create_preference_option_menu(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val)
{
	GtkTooltips *tooltips;
	GtkWidget *menu_box, *menu, *menu_item, *option_menu;
	int menu_index, index;
	const enum_val_t *enum_valp;
	GtkWidget *event_box;

	tooltips = OBJECT_GET_DATA(main_tb, E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	/* Create a menu from the enumvals */
	menu = gtk_menu_new();
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, menu, tooltip_text, NULL);
	menu_index = -1;
	for (enum_valp = enumvals, index = 0; enum_valp->name != NULL;
	    enum_valp++, index++) {
		menu_item = gtk_menu_item_new_with_label(enum_valp->description);
		gtk_menu_append(GTK_MENU(menu), menu_item);
		if (enum_valp->value == current_val)
			menu_index = index;
		gtk_widget_show(menu_item);
	}

	/* Create the option menu from the menu */
	option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);

	/* Set its current value to the variable's current value */
	if (menu_index != -1)
		gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu),
		    menu_index);

	/*
	 * Put the option menu in an hbox, so that it's only as wide
	 * as the widest entry, rather than being as wide as the table
	 * space.
	 */
	menu_box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(menu_box), option_menu, FALSE, FALSE, 0);

	event_box = gtk_event_box_new();
	gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box,
	    1, 2, table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, event_box, tooltip_text, NULL);
	gtk_container_add(GTK_CONTAINER(event_box), menu_box);

	return option_menu;
}

gint
fetch_preference_option_menu_val(GtkWidget *optmenu, const enum_val_t *enumvals)
{
	/*
	 * OK, now return the value corresponding to the label for the
	 * currently active entry in the option menu.
	 *
	 * Yes, this is how you get the label for that entry.  See FAQ
	 * 6.8 in the GTK+ FAQ.
	 */
	return label_to_enum_val(GTK_BIN(optmenu)->child, enumvals);
}

GtkWidget *
create_preference_entry(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, char *value)
{
	GtkTooltips *tooltips;
	GtkWidget *entry;

	tooltips = OBJECT_GET_DATA(main_tb, E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	entry = gtk_entry_new();
	if (value != NULL)
		gtk_entry_set_text(GTK_ENTRY(entry), value);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2,
	    table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, entry, tooltip_text, NULL);
	gtk_widget_show(entry);

	return entry;
}

static guint
pref_check(pref_t *pref, gpointer user_data)
{
  const char *str_val;
  char *p;
  guint uval;
  pref_t **badpref = user_data;

  /* Fetch the value of the preference, and check whether it's valid. */
  switch (pref->type) {

  case PREF_UINT:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    uval = strtoul(str_val, &p, pref->info.base);
    if (p == str_val || *p != '\0') {
      *badpref = pref;
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    }
    break;

  case PREF_BOOL:
    /* Value can't be bad. */
    break;

  case PREF_ENUM:
    /* Value can't be bad. */
    break;

  case PREF_STRING:
    /* Value can't be bad. */
    break;

  case PREF_RANGE:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));

    if (strlen(str_val) != 0) {
	range_t *newrange;

	if (range_convert_str(&newrange, str_val, pref->info.max_value) !=
	    CVT_NO_ERROR) {
	    *badpref = pref;
	    return PREFS_SET_SYNTAX_ERR;	/* range was bad */
	}
	g_free(newrange);
    }
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

static guint
module_prefs_check(module_t *module, gpointer user_data)
{
  /* For all preferences in this module, fetch its value from this
     module's notebook page and check whether it's valid. */
  return prefs_pref_foreach(module, pref_check, user_data);
}

static guint
pref_fetch(pref_t *pref, gpointer user_data)
{
  const char *str_val;
  char *p;
  guint uval;
  gboolean bval;
  gint enumval;
  gboolean *pref_changed_p = user_data;

  /* Fetch the value of the preference, and set the appropriate variable
     to it. */
  switch (pref->type) {

  case PREF_UINT:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    uval = strtoul(str_val, &p, pref->info.base);
#if 0
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
#endif
    if (*pref->varp.uint != uval) {
      *pref_changed_p = TRUE;
      *pref->varp.uint = uval;
    }
    break;

  case PREF_BOOL:
    bval = GTK_TOGGLE_BUTTON(pref->control)->active;
    if (*pref->varp.boolp != bval) {
      *pref_changed_p = TRUE;
      *pref->varp.boolp = bval;
    }
    break;

  case PREF_ENUM:
    if (pref->info.enum_info.radio_buttons) {
      enumval = fetch_preference_radio_buttons_val(pref->control,
          pref->info.enum_info.enumvals);
    } else {
      enumval = fetch_preference_option_menu_val(pref->control,
          pref->info.enum_info.enumvals);
    }

    if (*pref->varp.enump != enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = enumval;
    }
    break;

  case PREF_STRING:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    if (strcmp(*pref->varp.string, str_val) != 0) {
      *pref_changed_p = TRUE;
      g_free((void *)*pref->varp.string);
      *pref->varp.string = g_strdup(str_val);
    }
    break;

  case PREF_RANGE:
  {
    range_t *newrange;
    convert_ret_t ret;

    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    ret = range_convert_str(&newrange, str_val, pref->info.max_value);
    if (ret != CVT_NO_ERROR)
#if 0
      return PREFS_SET_SYNTAX_ERR;	/* range was bad */
#else
      return 0;	/* XXX - should fail */
#endif

    if (!ranges_are_equal(*pref->varp.range, newrange)) {
      *pref_changed_p = TRUE;
      g_free(*pref->varp.range);
      *pref->varp.range = newrange;
    } else
      g_free(newrange);

    break;
  }

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

static guint
module_prefs_fetch(module_t *module, gpointer user_data)
{
  gboolean *must_redissect_p = user_data;

  /* For all preferences in this module, fetch its value from this
     module's notebook page.  Find out whether any of them changed. */
  module->prefs_changed = FALSE;	/* assume none of them changed */
  prefs_pref_foreach(module, pref_fetch, &module->prefs_changed);

  /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
  if (module->prefs_changed)
    *must_redissect_p = TRUE;

  return 0;	/* keep fetching module preferences */
}

#ifdef HAVE_AIRPCAP
/*
 * This function is used to apply changes and update the Wireless Toolbar
 * whenever we apply some changes to the WEP preferences
 */
static void
prefs_airpcap_update()
{
GtkWidget *decryption_cm;
GtkWidget *decryption_en;
gboolean wireshark_decryption_was_enabled;
gboolean airpcap_decryption_was_enabled;
gboolean wireshark_decryption_is_now_enabled;

decryption_cm = GTK_WIDGET(OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY));
decryption_en = GTK_WIDGET(GTK_ENTRY(GTK_COMBO(decryption_cm)->entry));

if( g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK) == 0 )
{
wireshark_decryption_was_enabled = TRUE;
airpcap_decryption_was_enabled = FALSE;
}
else if( g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP) == 0 )
{
wireshark_decryption_was_enabled = FALSE;
airpcap_decryption_was_enabled = TRUE;
}
else if( g_strcasecmp(gtk_entry_get_text(GTK_ENTRY(decryption_en)),AIRPCAP_DECRYPTION_TYPE_STRING_NONE) == 0 )
{
wireshark_decryption_was_enabled = FALSE;
airpcap_decryption_was_enabled = FALSE;
}

wireshark_decryption_is_now_enabled = wireshark_decryption_on();

if(wireshark_decryption_is_now_enabled && airpcap_decryption_was_enabled)
	{
	set_airpcap_decryption(FALSE);
	gtk_entry_set_text(GTK_ENTRY(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK);
	}
if(wireshark_decryption_is_now_enabled && !airpcap_decryption_was_enabled)
	{
	set_airpcap_decryption(FALSE);
	gtk_entry_set_text(GTK_ENTRY(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK);
	}
else if(!wireshark_decryption_is_now_enabled && wireshark_decryption_was_enabled)
	{
	if(airpcap_decryption_was_enabled)
		{
		set_airpcap_decryption(TRUE);
		gtk_entry_set_text(GTK_ENTRY(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP);
		}
	else
		{
		set_airpcap_decryption(FALSE);
		gtk_entry_set_text(GTK_ENTRY(decryption_en),AIRPCAP_DECRYPTION_TYPE_STRING_NONE);
		}
	}
}
#endif

static guint
pref_clean(pref_t *pref, gpointer user_data _U_)
{
  switch (pref->type) {

  case PREF_UINT:
    break;

  case PREF_BOOL:
    break;

  case PREF_ENUM:
    break;

  case PREF_STRING:
    if (pref->saved_val.string != NULL) {
      g_free(pref->saved_val.string);
      pref->saved_val.string = NULL;
    }
    break;

  case PREF_RANGE:
    if (pref->saved_val.range != NULL) {
      g_free(pref->saved_val.range);
      pref->saved_val.range = NULL;
    }
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

static guint
module_prefs_clean(module_t *module, gpointer user_data _U_)
{
  /* For all preferences in this module, clean up any cruft allocated for
     use by the GUI code. */
  prefs_pref_foreach(module, pref_clean, NULL);
  return 0;	/* keep cleaning modules */
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
  gui_prefs_fetch(OBJECT_GET_DATA(dlg, E_GUI_PAGE_KEY));
  layout_prefs_fetch(OBJECT_GET_DATA(dlg, E_GUI_LAYOUT_PAGE_KEY));
  column_prefs_fetch(OBJECT_GET_DATA(dlg, E_GUI_COLUMN_PAGE_KEY));
  stream_prefs_fetch(OBJECT_GET_DATA(dlg, E_GUI_COLORS_PAGE_KEY));

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  capture_prefs_fetch(OBJECT_GET_DATA(dlg, E_CAPTURE_PAGE_KEY));
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
  printer_prefs_fetch(OBJECT_GET_DATA(dlg, E_PRINT_PAGE_KEY));
  nameres_prefs_fetch(OBJECT_GET_DATA(dlg, E_NAMERES_PAGE_KEY));

  prefs_modules_foreach(module_prefs_fetch, must_redissect);

  return TRUE;
}

/* apply all pref values to the real world */
static void
prefs_main_apply_all(GtkWidget *dlg)
{
  GtkWidget *save_bt;

  /*
   * Apply the protocol preferences first - "gui_prefs_apply()" could
   * cause redissection, and we have to make sure the protocol
   * preference changes have been fully applied.
   */
  prefs_apply_all();

  gui_prefs_apply(OBJECT_GET_DATA(dlg, E_GUI_PAGE_KEY));
  layout_prefs_apply(OBJECT_GET_DATA(dlg, E_GUI_LAYOUT_PAGE_KEY));
  column_prefs_apply(OBJECT_GET_DATA(dlg, E_GUI_COLUMN_PAGE_KEY));
  stream_prefs_apply(OBJECT_GET_DATA(dlg, E_GUI_COLORS_PAGE_KEY));

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  capture_prefs_apply(OBJECT_GET_DATA(dlg, E_CAPTURE_PAGE_KEY));
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
  printer_prefs_apply(OBJECT_GET_DATA(dlg, E_PRINT_PAGE_KEY));
  nameres_prefs_apply(OBJECT_GET_DATA(dlg, E_NAMERES_PAGE_KEY));

  /* show/hide the Save button - depending on setting */
  save_bt = OBJECT_GET_DATA(prefs_w, E_PREFSW_SAVE_BT_KEY);
  if(prefs.gui_use_pref_save) {
    gtk_widget_show(save_bt);
  } else {
    gtk_widget_hide(save_bt);
  }
}


/* destroy all preferences ressources from all pages */
static void
prefs_main_destroy_all(GtkWidget *dlg)
{
#if GTK_MAJOR_VERSION >= 2
  int page_num;
  GtkWidget *frame;

  for (page_num = 0;
       (frame = gtk_notebook_get_nth_page(OBJECT_GET_DATA(prefs_w, E_PREFSW_NOTEBOOK_KEY), page_num)) != NULL;
       page_num++) {
		   if(OBJECT_GET_DATA(frame, E_PAGE_ITER_KEY))
               gtk_tree_iter_free(OBJECT_GET_DATA(frame, E_PAGE_ITER_KEY));
	   }
#endif

  gui_prefs_destroy(OBJECT_GET_DATA(dlg, E_GUI_PAGE_KEY));
  layout_prefs_destroy(OBJECT_GET_DATA(dlg, E_GUI_LAYOUT_PAGE_KEY));
  column_prefs_destroy(OBJECT_GET_DATA(dlg, E_GUI_COLUMN_PAGE_KEY));
  stream_prefs_destroy(OBJECT_GET_DATA(dlg, E_GUI_COLORS_PAGE_KEY));

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (has_wpcap) {
#endif /* _WIN32 */
  capture_prefs_destroy(OBJECT_GET_DATA(dlg, E_CAPTURE_PAGE_KEY));
#ifdef _WIN32
  }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
  printer_prefs_destroy(OBJECT_GET_DATA(dlg, E_PRINT_PAGE_KEY));
  nameres_prefs_destroy(OBJECT_GET_DATA(dlg, E_NAMERES_PAGE_KEY));

  /* Free up the saved preferences (both for "prefs" and for registered
     preferences). */
  free_prefs(&saved_prefs);
  prefs_modules_foreach(module_prefs_clean, NULL);
}


static void
prefs_main_write(void)
{
  int err;
  char *pf_dir_path;
  char *pf_path;

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't create directory\n\"%s\"\nfor preferences file: %s.", pf_dir_path,
      strerror(errno));
     g_free(pf_dir_path);
  } else {
    /* Write the preferencs out. */
    err = write_prefs(&pf_path);
    if (err != 0) {
       simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "Can't open preferences file\n\"%s\": %s.", pf_path,
        strerror(err));
       g_free(pf_path);
    }
  }

#ifdef HAVE_AIRPCAP
/* 
 * Load the Wireshark decryption keys (just set) and save 
 * the changes to the adapters' registry 
 */ 
airpcap_load_decryption_keys(airpcap_if_list);
#endif
}


static void
prefs_main_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  if (!prefs_main_fetch_all(parent_w, &must_redissect))
    return; /* Errors in some preference setting - already reported */

  /* if we don't have a Save button, just save the settings now */
  if (!prefs.gui_use_pref_save) {
      prefs_main_write();
  }

  prefs_main_apply_all(parent_w);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

	#ifdef HAVE_AIRPCAP
	prefs_airpcap_update();
	#endif

  /* Now destroy the "Preferences" dialog. */
  window_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    cf_redissect_packets(&cfile);
  }

}

static void
prefs_main_apply_cb(GtkWidget *apply_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  if (!prefs_main_fetch_all(parent_w, &must_redissect))
    return; /* Errors in some preference setting - already reported */

  /* if we don't have a Save button, just save the settings now */
  if (!prefs.gui_use_pref_save) {
      prefs_main_write();
  }

  prefs_main_apply_all(parent_w);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

  	#ifdef HAVE_AIRPCAP
	prefs_airpcap_update();
	#endif

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    cf_redissect_packets(&cfile);
  }
}

static void
prefs_main_save_cb(GtkWidget *save_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  if (!prefs_main_fetch_all(parent_w, &must_redissect))
    return; /* Errors in some preference setting - already reported */

  prefs_main_write();

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
  prefs_main_apply_all(parent_w);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    cf_redissect_packets(&cfile);
  }
}

static guint
pref_revert(pref_t *pref, gpointer user_data)
{
  gboolean *pref_changed_p = user_data;

  /* Revert the preference to its saved value. */
  switch (pref->type) {

  case PREF_UINT:
    if (*pref->varp.uint != pref->saved_val.uint) {
      *pref_changed_p = TRUE;
      *pref->varp.uint = pref->saved_val.uint;
    }
    break;

  case PREF_BOOL:
    if (*pref->varp.boolp != pref->saved_val.boolval) {
      *pref_changed_p = TRUE;
      *pref->varp.boolp = pref->saved_val.boolval;
    }
    break;

  case PREF_ENUM:
    if (*pref->varp.enump != pref->saved_val.enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = pref->saved_val.enumval;
    }
    break;

  case PREF_STRING:
    if (strcmp(*pref->varp.string, pref->saved_val.string) != 0) {
      *pref_changed_p = TRUE;
      g_free((void *)*pref->varp.string);
      *pref->varp.string = g_strdup(pref->saved_val.string);
    }
    break;

  case PREF_RANGE:
    if (!ranges_are_equal(*pref->varp.range, pref->saved_val.range)) {
      *pref_changed_p = TRUE;
      g_free(*pref->varp.range);
      *pref->varp.range = range_copy(pref->saved_val.range);
    }
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  return 0;
}

static guint
module_prefs_revert(module_t *module, gpointer user_data)
{
  gboolean *must_redissect_p = user_data;

  /* For all preferences in this module, revert its value to the value
     it had when we popped up the Preferences dialog.  Find out whether
     this changes any of them. */
  module->prefs_changed = FALSE;	/* assume none of them changed */
  prefs_pref_foreach(module, pref_revert, &module->prefs_changed);

  /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
  if (module->prefs_changed)
    *must_redissect_p = TRUE;
  return 0;	/* keep processing modules */
}

/* cancel button pressed, revert prefs to saved and exit dialog */
static void
prefs_main_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  /* Free up the current preferences and copy the saved preferences to the
     current preferences. */
  free_prefs(&prefs);
  copy_prefs(&prefs, &saved_prefs);

  /* Now revert the registered preferences. */
  prefs_modules_foreach(module_prefs_revert, &must_redissect);

  /* Now apply the reverted-to preferences. */
  prefs_main_apply_all(parent_w);

  window_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    cf_redissect_packets(&cfile);
  }
}

/* Treat this as a cancel, by calling "prefs_main_cancel_cb()" */
static gboolean
prefs_main_delete_event_cb(GtkWidget *prefs_w, GdkEvent *event _U_,
                           gpointer parent_w _U_)
{
  prefs_main_cancel_cb(NULL, prefs_w);
  return FALSE;
}


/* dialog *is* already destroyed, clean up memory and such */
static void
prefs_main_destroy_cb(GtkWidget *win _U_, gpointer parent_w)
{
  prefs_main_destroy_all(parent_w);

  /* Note that we no longer have a "Preferences" dialog box. */
  prefs_w = NULL;
}

struct properties_data {
  const char *title;
  module_t *module;
};

static guint
module_search_properties(module_t *module, gpointer user_data)
{
  struct properties_data *p = (struct properties_data *)user_data;

  /* If this module has the specified title, remember it. */
  if (strcmp(module->title, p->title) == 0) {
    p->module = module;
    return 1;	/* stops the search */
  }
  return 0;
}


/* select a node in the tree view */
/* XXX - this is almost 100% copied from byte_view_select() in proto_draw.c,
 *       find a way to combine both to have a generic function for this */
void
tree_select_node(GtkWidget *tree, prefs_tree_iter *iter)
{
#if GTK_MAJOR_VERSION < 2
    GtkCTree     *ctree = GTK_CTREE(tree);
    GtkCTreeNode *node = (GtkCTreeNode *) iter;
	GtkCTreeNode *parent;
#else
	GtkTreeIter  local_iter = *iter;
    GtkTreeView  *tree_view = GTK_TREE_VIEW(tree);
    GtkTreeModel *model;
    GtkTreePath  *first_path, *path;
    GtkTreeIter   parent;
#endif

#if GTK_MAJOR_VERSION < 2
    /* Expand and select our field's row */
    gtk_ctree_expand(ctree, node);
    gtk_ctree_select(ctree, node);
    /*expand_tree(ctree, node, NULL);*/

    /* ... and its parents */
    parent = GTK_CTREE_ROW(node)->parent;
    while (parent) {
        gtk_ctree_expand(ctree, parent);
        /*expand_tree(ctree, parent, NULL);*/
        parent = GTK_CTREE_ROW(parent)->parent;
    }

    /* And position the window so the selection is visible.
     * Position the selection in the middle of the viewable
     * pane. */
    gtk_ctree_node_moveto(ctree, node, 0, .5, 0);
#else
    model = gtk_tree_view_get_model(tree_view);

    /* Expand our field's row */
    first_path = gtk_tree_model_get_path(model, &local_iter);
    gtk_tree_view_expand_row(tree_view, first_path, FALSE);
    /*expand_tree(tree_view, &iter, NULL, NULL);*/

    /* ... and its parents */
    while (gtk_tree_model_iter_parent(model, &parent, &local_iter)) {
        path = gtk_tree_model_get_path(model, &parent);
        gtk_tree_view_expand_row(tree_view, path, FALSE);
        /*expand_tree(tree_view, &parent, NULL, NULL);*/
        local_iter = parent;
        gtk_tree_path_free(path);
    }

    /* select our field's row */
    gtk_tree_selection_select_path(gtk_tree_view_get_selection(tree_view),
                                   first_path);

    /* And position the window so the selection is visible.
     * Position the selection in the middle of the viewable
     * pane. */
    gtk_tree_view_scroll_to_cell(tree_view, first_path, NULL, TRUE, 0.5, 0.0);

    gtk_tree_path_free(first_path);
#endif
}


/* search the corresponding protocol page of the currently selected field */
void
properties_cb(GtkWidget *w, gpointer dummy)
{
  header_field_info *hfinfo;
  const gchar *title;
  struct properties_data p;
  int page_num;
  GtkWidget *sw;
  GtkWidget *frame;
  module_t *page_module;

  if (cfile.finfo_selected == NULL) {
    /* There is no field selected */
    return;
  }

  /* Find the title for the protocol for the selected field. */
  hfinfo = cfile.finfo_selected->hfinfo;
  if (hfinfo->parent == -1)
    title = prefs_get_title_by_name(hfinfo->abbrev);
  else
    title = prefs_get_title_by_name(proto_registrar_get_abbrev(hfinfo->parent));
  if (!title)
    return;	/* Couldn't find it. XXX - just crash? "Can't happen"? */

  /* Find the module for that protocol by searching for one with that title.
     XXX - should we just associate protocols with modules directly? */
  p.title = title;
  p.module = NULL;
  prefs_module_list_foreach(protocols_module->prefs, module_search_properties,
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
       (sw = gtk_notebook_get_nth_page(OBJECT_GET_DATA(prefs_w, E_PREFSW_NOTEBOOK_KEY), page_num)) != NULL;
       page_num++) {
    /* Get the frame from the scrollable window */
    frame = OBJECT_GET_DATA(sw, E_PAGESW_FRAME_KEY);
    /* Get the module for this page. */
    page_module = OBJECT_GET_DATA(frame, E_PAGE_MODULE_KEY);
    if (page_module == NULL)
      continue;	/* It doesn't have one. */
    if (page_module == p.module) {
	  tree_select_node(
		  OBJECT_GET_DATA(prefs_w, E_PREFSW_TREE_KEY),
		  OBJECT_GET_DATA(frame, E_PAGE_ITER_KEY));
	  return;
	}
  }
}

/* Prefs tree selection callback.  The node data has been loaded with
   the proper notebook page to load. */
#if GTK_MAJOR_VERSION < 2
static void
prefs_tree_select_cb(GtkCTree *ct, GtkCTreeNode *node, gint col _U_,
                     gpointer dummy _U_)
#else
static void
prefs_tree_select_cb(GtkTreeSelection *sel, gpointer dummy _U_)
#endif
{
  gint page;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeModel *model;
  GtkTreeIter   iter;
#endif

#if GTK_MAJOR_VERSION < 2
  page = GPOINTER_TO_INT(gtk_ctree_node_get_row_data(ct, node));

  if (page >= 0)
    gtk_notebook_set_page(OBJECT_GET_DATA(prefs_w, E_PREFSW_NOTEBOOK_KEY), page);
#else
  if (gtk_tree_selection_get_selected(sel, &model, &iter))
  {
    gtk_tree_model_get(model, &iter, 1, &page, -1);
    if (page >= 0)
      gtk_notebook_set_page(OBJECT_GET_DATA(prefs_w, E_PREFSW_NOTEBOOK_KEY), page);
  }
#endif
}
