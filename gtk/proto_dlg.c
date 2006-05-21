/* proto_dlg.c
 *
 * $Id$
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
#include <gdk/gdkkeysyms.h>
#include <string.h>

#include <epan/prefs.h>
#include "globals.h"
#include "main.h"
#include "util.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "proto_dlg.h"
#include "simple_dialog.h"
#include "compat_macros.h"
#include "disabled_protos.h"
#include <epan/filesystem.h>
#include "help_dlg.h"

static gboolean proto_delete_event_cb(GtkWidget *, GdkEvent *, gpointer);
static void proto_ok_cb(GtkWidget *, gpointer);
static void proto_apply_cb(GtkWidget *, gpointer);
static void proto_save_cb(GtkWidget *, gpointer);
static void proto_cancel_cb(GtkWidget *, gpointer);
static void proto_destroy_cb(GtkWidget *, gpointer);

#if GTK_MAJOR_VERSION < 2
static void show_proto_selection(GtkCList *proto_list);
#else
static void show_proto_selection(GtkListStore *proto_store);
#endif
static gboolean set_proto_selection(GtkWidget *);
static gboolean revert_proto_selection(void);

static void toggle_all_cb(GtkWidget *button, gpointer parent_w);
static void enable_all_cb(GtkWidget *button, gpointer parent_w);
static void disable_all_cb(GtkWidget *button, gpointer parent_w);
#if GTK_MAJOR_VERSION < 2
static void proto_list_select_cb(GtkCList *proto_list, gint row, gint col, 
                                 GdkEventButton *ev, gpointer gp);
static gboolean proto_list_keypress_cb(GtkWidget *pl, GdkEventKey *ev,
                                   gpointer gp);
#else
static void status_toggled(GtkCellRendererToggle *, gchar *, gpointer);
#endif

static GtkWidget *proto_w = NULL;

/* list of protocols */
static GSList *protocol_list = NULL;

typedef struct protocol_data {
  const char  *name;
  const char  *abbrev;
  int  	      hfinfo_index;
  gboolean    enabled;
  gboolean    was_enabled;
#if GTK_MAJOR_VERSION < 2
  gint        row;
#else
  GtkTreeIter iter;
#endif
} protocol_data_t;

#define DISABLED "Disabled"
#define STATUS_TXT(x) ((x) ? "" : DISABLED)

void
proto_cb(GtkWidget *w _U_, gpointer data _U_)
{

  GtkWidget *main_vb, *bbox, *proto_list, *label, *proto_sw, *proto_frame,
            *proto_vb, *button;
  const gchar *titles[] = { "Status", "Protocol", "Description" };
#if GTK_MAJOR_VERSION < 2
  gint width;
#else
  GtkListStore *proto_store;
  GtkCellRenderer *proto_rend;
  GtkTreeViewColumn *proto_col;
#endif


  if (proto_w != NULL) {
    reactivate_window(proto_w);
    return;
  }

  proto_w = dlg_window_new("Ethereal: Enabled Protocols");
  gtk_window_set_default_size(GTK_WINDOW(proto_w), DEF_WIDTH * 2/3, DEF_HEIGHT);

  /* Container for each row of widgets */

  main_vb = gtk_vbox_new(FALSE, 6);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 6);
  gtk_container_add(GTK_CONTAINER(proto_w), main_vb);
  gtk_widget_show(main_vb);

  /* Protocol selection list ("enable/disable" protocols) */

  proto_frame = gtk_frame_new("Enabled Protocols");
  gtk_box_pack_start(GTK_BOX(main_vb), proto_frame, TRUE, TRUE, 0);
  gtk_widget_show(proto_frame);

  /* Protocol list */
  
  proto_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(proto_frame), proto_vb);
  gtk_container_border_width(GTK_CONTAINER(proto_vb), 5);
  gtk_widget_show(proto_vb);
  
  proto_sw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(proto_sw), 
                                   GTK_SHADOW_IN);
#endif
  gtk_box_pack_start(GTK_BOX(proto_vb), proto_sw, TRUE, TRUE, 0);
  gtk_widget_show(proto_sw);

#if GTK_MAJOR_VERSION < 2
  proto_list = gtk_clist_new_with_titles(3, (gchar **) titles);
  gtk_container_add(GTK_CONTAINER(proto_sw), proto_list);
  gtk_clist_set_selection_mode(GTK_CLIST(proto_list), GTK_SELECTION_BROWSE);
  gtk_clist_column_titles_passive(GTK_CLIST(proto_list));
  gtk_clist_column_titles_show(GTK_CLIST(proto_list));
  gtk_clist_set_column_auto_resize(GTK_CLIST(proto_list), 0, FALSE);
  gtk_clist_set_column_auto_resize(GTK_CLIST(proto_list), 1, TRUE);
  gtk_clist_set_column_auto_resize(GTK_CLIST(proto_list), 2, TRUE);
  width = gdk_string_width(proto_list->style->font, DISABLED);
  gtk_clist_set_column_width(GTK_CLIST(proto_list), 0, width);
  SIGNAL_CONNECT(proto_list, "select-row", proto_list_select_cb, NULL);
  SIGNAL_CONNECT(proto_list, "key-press-event", proto_list_keypress_cb, NULL);
  show_proto_selection(GTK_CLIST(proto_list));
#else
  proto_store = gtk_list_store_new(4, G_TYPE_BOOLEAN, G_TYPE_STRING,
                                   G_TYPE_STRING, G_TYPE_POINTER);
  show_proto_selection(proto_store);
  /* default sort on "abbrev" column */
  gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(proto_store), 1,
                                       GTK_SORT_ASCENDING);
  proto_list = tree_view_new(GTK_TREE_MODEL(proto_store));
  gtk_container_add(GTK_CONTAINER(proto_sw), proto_list);
  proto_rend = gtk_cell_renderer_toggle_new();
  SIGNAL_CONNECT(proto_rend, "toggled", status_toggled, proto_store);
  proto_col = gtk_tree_view_column_new_with_attributes(titles[0], proto_rend,
                                                    "active", 0, NULL);
  gtk_tree_view_column_set_sort_column_id(proto_col, 0);
  gtk_tree_view_append_column(GTK_TREE_VIEW(proto_list), proto_col);
  proto_rend = gtk_cell_renderer_text_new();
  proto_col = gtk_tree_view_column_new_with_attributes(titles[1], proto_rend,
                                                    "text", 1, NULL);
  gtk_tree_view_column_set_sort_column_id(proto_col, 1);
  gtk_tree_view_append_column(GTK_TREE_VIEW(proto_list), proto_col);
  proto_rend = gtk_cell_renderer_text_new();
  proto_col = gtk_tree_view_column_new_with_attributes(titles[2], proto_rend,
                                                    "text", 2, NULL);
  gtk_tree_view_column_set_sort_column_id(proto_col, 2);
  gtk_tree_view_append_column(GTK_TREE_VIEW(proto_list), proto_col);
  g_object_unref(G_OBJECT(proto_store));
#endif
  gtk_widget_show(proto_list);

  label = gtk_label_new("Disabling a protocol prevents higher "
			"layer protocols from being displayed");
  gtk_misc_set_alignment(GTK_MISC(label), 0.5, 0.5);
  gtk_widget_show(label);
  gtk_box_pack_start(GTK_BOX(proto_vb), label, FALSE, FALSE, 5);


  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_box_pack_start(GTK_BOX(proto_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  /* Enable All */
  button = gtk_button_new_with_label("Enable All");
  SIGNAL_CONNECT(button, "clicked", enable_all_cb, proto_list);
  gtk_box_pack_start(GTK_BOX(bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  /* Disable All */
  button = gtk_button_new_with_label("Disable All");
  SIGNAL_CONNECT(button, "clicked", disable_all_cb, proto_list);
  gtk_box_pack_start(GTK_BOX(bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  /* Invert */
  button = gtk_button_new_with_label("Invert");
  SIGNAL_CONNECT(button, "clicked", toggle_all_cb, proto_list);
  gtk_box_pack_start(GTK_BOX(bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);


  /* Button row */
  if(topic_available(HELP_ENABLED_PROTOCOLS_DIALOG)) {
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  } else {
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, NULL);
  }
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  button = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  SIGNAL_CONNECT(button, "clicked", proto_ok_cb, proto_w);
  gtk_widget_grab_default(button);

  button = OBJECT_GET_DATA(bbox, GTK_STOCK_APPLY);
  SIGNAL_CONNECT(button, "clicked", proto_apply_cb, proto_w);

  button = OBJECT_GET_DATA(bbox, GTK_STOCK_SAVE);
  SIGNAL_CONNECT(button, "clicked", proto_save_cb, proto_w);

  button = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  window_set_cancel_button(proto_w, button, proto_cancel_cb);

  if(topic_available(HELP_ENABLED_PROTOCOLS_DIALOG)) {
    button = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
    SIGNAL_CONNECT(button, "clicked", topic_cb, HELP_ENABLED_PROTOCOLS_DIALOG);
  }

  SIGNAL_CONNECT(proto_w, "delete_event", proto_delete_event_cb, NULL);
  SIGNAL_CONNECT(proto_w, "destroy", proto_destroy_cb, NULL);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(proto_w));

  gtk_widget_show(proto_w);
  window_present(proto_w);
} /* proto_cb */

#if GTK_MAJOR_VERSION < 2
static void
proto_list_select_cb(GtkCList *proto_list, gint row, gint col, 
                     GdkEventButton *ev _U_, gpointer gp _U_) {
  protocol_data_t *p = gtk_clist_get_row_data(proto_list, row);
  
  if (row < 0 || col < 0)
    return;

  if (p->enabled)
    p->enabled = FALSE;
  else
    p->enabled = TRUE;

  gtk_clist_set_text(proto_list, row, 0, STATUS_TXT(p->enabled) );
} /* proto_list_select_cb */

static gboolean
proto_list_keypress_cb(GtkWidget *pl, GdkEventKey *ev, gpointer gp _U_) {
  GtkCList *proto_list = GTK_CLIST(pl);
  
  if (ev->keyval == GDK_space) {
    proto_list_select_cb(proto_list, proto_list->focus_row, 0, NULL, gp);
  }
  return TRUE;
}

#else
static void
status_toggled(GtkCellRendererToggle *cell _U_, gchar *path_str, gpointer data)
{
  GtkTreeModel    *model = (GtkTreeModel *)data;
  GtkTreeIter      iter;
  GtkTreePath     *path = gtk_tree_path_new_from_string(path_str);
  protocol_data_t *p;

  gtk_tree_model_get_iter(model, &iter, path);
  gtk_tree_model_get(model, &iter, 3, &p, -1);

  if (p->enabled)
    p->enabled = FALSE;
  else
    p->enabled = TRUE;

  gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, p->enabled, -1);

  gtk_tree_path_free(path);
} /* status toggled */
#endif

/* XXX - We need callbacks for Gtk2 */


/* Toggle All */
static void
toggle_all_cb(GtkWidget *button _U_, gpointer pl)
{
  GSList *entry;
#if GTK_MAJOR_VERSION < 2
  GtkCList *proto_list = GTK_CLIST(pl);
#else
  GtkListStore *s = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(pl)));
#endif

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;

    if (p->enabled)
      p->enabled = FALSE;
    else
      p->enabled = TRUE;
    
#if GTK_MAJOR_VERSION < 2
    gtk_clist_set_text(proto_list, p->row, 0, STATUS_TXT(p->enabled) );
#else
    gtk_list_store_set(s, &p->iter, 0, p->enabled, -1);
#endif
  }
}

/* Enable/Disable All Helper */
static void
set_active_all(GtkWidget *w, gboolean new_state)
{

#if GTK_MAJOR_VERSION < 2
  GtkCList *proto_list = GTK_CLIST(w);
#else
  GtkListStore *s = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(w)));
#endif
  GSList *entry;

#if GTK_MAJOR_VERSION < 2
  gtk_clist_freeze(proto_list);
#endif
  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;
    
    p->enabled = new_state;
#if GTK_MAJOR_VERSION < 2
    gtk_clist_set_text(proto_list, p->row, 0, STATUS_TXT(new_state) );
#else
    gtk_list_store_set(s, &p->iter, 0, new_state, -1);
#endif
  }
#if GTK_MAJOR_VERSION < 2
  gtk_clist_thaw(proto_list);
#endif
}

/* Enable All */
static void
enable_all_cb(GtkWidget *button _U_, gpointer pl)
{
	set_active_all(pl, TRUE);
}

/* Disable All */
static void
disable_all_cb(GtkWidget *button _U_, gpointer pl)
{
	set_active_all(pl, FALSE);
}

static void
proto_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
  GSList *entry;

  proto_w = NULL;

  /* remove protocol list */
  if (protocol_list) {
    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
      g_free(entry->data);
    }
    g_slist_free(protocol_list);
    protocol_list = NULL;
  }
}

/* Treat this as a cancel, by calling "proto_cancel_cb()".
   XXX - that'll destroy the Protocols dialog; will that upset
   a higher-level handler that says "OK, we've been asked to delete
   this, so destroy it"? */
static gboolean
proto_delete_event_cb(GtkWidget *proto_w, GdkEvent *event _U_,
                      gpointer dummy _U_)
{
  proto_cancel_cb(NULL, proto_w);
  return FALSE;
}

static void
proto_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  gboolean redissect;

  redissect = set_proto_selection(GTK_WIDGET(parent_w));
  window_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    cf_redissect_packets(&cfile);
}

static void
proto_apply_cb(GtkWidget *apply_bt _U_, gpointer parent_w)
{
  if (set_proto_selection(GTK_WIDGET(parent_w)))
    cf_redissect_packets(&cfile);
}

static void
proto_save_cb(GtkWidget *save_bt _U_, gpointer parent_w)
{
  gboolean must_redissect = FALSE;
  char *pf_dir_path;
  char *pf_path;
  int pf_save_errno;

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't create directory\n\"%s\"\nfor disabled protocols file: %s.", pf_dir_path,
      strerror(errno));
     g_free(pf_dir_path);
  } else {
    /*
     * make disabled/enabled protocol settings current
     */
    must_redissect = set_proto_selection(GTK_WIDGET(parent_w));

    save_disabled_protos_list(&pf_path, &pf_save_errno);
    if (pf_path != NULL) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Could not save to your disabled protocols file\n\"%s\": %s.",
	    pf_path, strerror(pf_save_errno));
	g_free(pf_path);
    }
  }

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    cf_redissect_packets(&cfile);
  }
}

static void
proto_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
  gboolean redissect;

  redissect = revert_proto_selection();
  window_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    cf_redissect_packets(&cfile);
}

static gboolean
set_proto_selection(GtkWidget *parent_w _U_)
{
  GSList *entry;
  gboolean need_redissect = FALSE;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;
    protocol_t *protocol;

    protocol = find_protocol_by_id(p->hfinfo_index);
    if (proto_is_protocol_enabled(protocol) != p->enabled) {
      proto_set_decoding(p->hfinfo_index, p->enabled);
      need_redissect = TRUE;
    }
  }

  return need_redissect;

} /* set_proto_selection */

static gboolean
revert_proto_selection(void)
{
  GSList *entry;
  gboolean need_redissect = FALSE;

  /*
   * Undo all the changes we've made to protocol enable flags.
   */
  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;
    protocol_t *protocol;

    protocol = find_protocol_by_id(p->hfinfo_index);
    if (proto_is_protocol_enabled(protocol) != p->was_enabled) {
      proto_set_decoding(p->hfinfo_index, p->was_enabled);
      need_redissect = TRUE;
    }
  }

  return need_redissect;

} /* revert_proto_selection */

static gint
protocol_data_compare(gconstpointer a, gconstpointer b)
{
  const protocol_data_t *ap = (const protocol_data_t *)a;
  const protocol_data_t *bp = (const protocol_data_t *)b;

  return strcmp(ap->abbrev, bp->abbrev);
}

static void
#if GTK_MAJOR_VERSION < 2
show_proto_selection(GtkCList *proto_list)
#else
show_proto_selection(GtkListStore *proto_store)
#endif
{
  GSList *entry;
  gint i;
  void *cookie;
  protocol_t *protocol;
  protocol_data_t *p;
#if GTK_MAJOR_VERSION < 2
  const gchar *proto_text[3];
#endif

  /* Iterate over all the protocols */

  for (i = proto_get_first_protocol(&cookie); i != -1;
       i = proto_get_next_protocol(&cookie)) {
      if (proto_can_toggle_protocol(i)) {
        p = g_malloc(sizeof(protocol_data_t));
        protocol = find_protocol_by_id(i);
        p->name = proto_get_protocol_name(i);
        p->abbrev = proto_get_protocol_short_name(protocol);
        p->hfinfo_index = i;
        p->enabled = proto_is_protocol_enabled(protocol);
	p->was_enabled = p->enabled;
        protocol_list = g_slist_insert_sorted(protocol_list,
					    p, protocol_data_compare);
      }
  }

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    p = entry->data;

#if GTK_MAJOR_VERSION < 2
    /* XXX - The preferred way to do this would be to have a check box
     * in the first column.  GtkClists don't let us put arbitrary widgets
     * in a cell, so we use the word "Disabled" instead.  We should be
     * able to use check boxes in Gtk2, however.
     */        
    proto_text[0] = STATUS_TXT (p->enabled);
    proto_text[1] = p->abbrev;
    proto_text[2] = p->name;
    p->row = gtk_clist_append(proto_list, (gchar **) proto_text);
    gtk_clist_set_row_data(proto_list, p->row, p);
#else
    gtk_list_store_append(proto_store, &p->iter);
    gtk_list_store_set(proto_store, &p->iter,
                       0, p->enabled,
                       1, p->abbrev,
                       2, p->name,
                       3, p,
                      -1);
#endif
  }

} /* show_proto_selection */
