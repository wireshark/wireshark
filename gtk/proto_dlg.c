/* proto_dlg.c
 *
 * $Id: proto_dlg.c,v 1.21 2002/12/01 22:51:56 gerald Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <string.h>

#include "prefs.h"
#include "globals.h"
#include "main.h"
#include "util.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "proto_dlg.h"
#include "compat_macros.h"

static gboolean proto_delete_cb(GtkWidget *, gpointer);
static void proto_ok_cb(GtkWidget *, gpointer);
static void proto_apply_cb(GtkWidget *, gpointer);
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
#endif

static GtkWidget *proto_w = NULL;

/* list of protocols */
static GSList *protocol_list = NULL;

typedef struct protocol_data {
  char     *name;
  char 	   *abbrev;
  int  	   hfinfo_index;
  gboolean enabled;
  gboolean was_enabled;
#if GTK_MAJOR_VERSION < 2
  gint     row;
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
  gchar *titles[] = { "Status", "Protocol", "Description" };
  gint width;
#if GTK_MAJOR_VERSION >= 2
  GtkListStore *proto_store;
  GtkCellRenderer *proto_rend;
  GtkTreeViewColumn *proto_col;
#endif


  if (proto_w != NULL) {
    reactivate_window(proto_w);
    return;
  }

  proto_w = dlg_window_new("Ethereal: Enabled Protocols");
  SIGNAL_CONNECT(proto_w, "delete_event", proto_delete_cb, NULL);
  SIGNAL_CONNECT(proto_w, "destroy", proto_destroy_cb, NULL);
  WIDGET_SET_SIZE(proto_w, DEF_WIDTH * 2/3, DEF_HEIGHT * 2/3);

  /* Container for each row of widgets */

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 1);
  gtk_container_add(GTK_CONTAINER(proto_w), main_vb);
  gtk_widget_show(main_vb);

  /* Protocol selection list ("enable/disable" protocols) */

  proto_frame = gtk_frame_new("Enabled Protocols");
  gtk_box_pack_start(GTK_BOX(main_vb), proto_frame, TRUE, TRUE, 0);
  gtk_container_border_width(GTK_CONTAINER(proto_frame), 5);
  gtk_widget_show(proto_frame);

  /* Protocol list */
  
  proto_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(proto_vb), 1);
  gtk_container_add(GTK_CONTAINER(proto_frame), proto_vb);
  gtk_container_border_width(GTK_CONTAINER(proto_vb), 5);
  gtk_widget_show(proto_vb);
  
  proto_sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_box_pack_start(GTK_BOX(proto_vb), proto_sw, TRUE, TRUE, 0);
  gtk_widget_show(proto_sw);

#if GTK_MAJOR_VERSION < 2
  proto_list = gtk_clist_new_with_titles(3, titles);
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
  show_proto_selection(GTK_CLIST(proto_list));
  gtk_widget_show(proto_list);
#else
  proto_store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
  show_proto_selection(proto_store);
  proto_list = tree_view_new(GTK_TREE_MODEL(proto_store));
  gtk_tree_view_set_search_column(GTK_TREE_VIEW(proto_list), 0);
  g_object_unref(G_OBJECT(proto_store));
  gtk_container_add(GTK_CONTAINER(proto_sw), proto_list);
  proto_rend = gtk_cell_renderer_text_new();
  proto_col = gtk_tree_view_column_new_with_attributes(titles[0], proto_rend,
                                                    "status", 0, NULL);
  gtk_tree_view_column_set_sort_column_id(proto_col, 0);
  gtk_tree_view_append_column(GTK_TREE_VIEW(proto_list), proto_col);
  proto_rend = gtk_cell_renderer_text_new();
  proto_col = gtk_tree_view_column_new_with_attributes(titles[1], proto_rend,
                                                    "abbrev", 1, NULL);
  gtk_tree_view_column_set_sort_column_id(proto_col, 1);
  gtk_tree_view_append_column(GTK_TREE_VIEW(proto_list), proto_col);
  proto_rend = gtk_cell_renderer_text_new();
  proto_col = gtk_tree_view_column_new_with_attributes(titles[2], proto_rend,
                                                    "name", 2, NULL);
  gtk_tree_view_column_set_sort_column_id(proto_col, 2);
  gtk_tree_view_append_column(GTK_TREE_VIEW(proto_list), proto_col);
#endif


  label = gtk_label_new("Disabling a protocol prevents higher "
			"layer protocols from being displayed");
  gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
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


  /* Ok, Apply, Cancel Buttons */

  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

#if GTK_MAJOR_VERSION < 2
  button = gtk_button_new_with_label ("OK");
#else
  button = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif
  SIGNAL_CONNECT(button, "clicked", proto_ok_cb, proto_w);
  GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), button, TRUE, TRUE, 0);
  gtk_widget_grab_default(button);
  gtk_widget_show(button);

#if GTK_MAJOR_VERSION < 2
  button = gtk_button_new_with_label ("Apply");
#else
  button = gtk_button_new_from_stock(GTK_STOCK_APPLY);
#endif
  SIGNAL_CONNECT(button, "clicked", proto_apply_cb, proto_w);
  GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

#if GTK_MAJOR_VERSION < 2
  button = gtk_button_new_with_label ("Cancel");
#else
  button = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
  SIGNAL_CONNECT(button, "clicked", proto_cancel_cb, proto_w);
  GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  dlg_set_cancel(proto_w, button);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(proto_w));
  gtk_widget_show(proto_w);

} /* proto_cb */

#if GTK_MAJOR_VERSION < 2
static void
proto_list_select_cb(GtkCList *proto_list, gint row, gint col, 
                                 GdkEventButton *ev, gpointer gp _U_) {
  protocol_data_t *p = gtk_clist_get_row_data(proto_list, row);
  
  if (row < 0 || col < 0)
    return;

  if (p->enabled)
    p->enabled = FALSE;
  else
    p->enabled = TRUE;

  gtk_clist_set_text(proto_list, row, 0, STATUS_TXT(p->enabled) );
} /* proto_list_select_cb */
#endif

/* XXX - We need a callback for Gtk2 */


/* Toggle All */
static void
toggle_all_cb(GtkWidget *button _U_, gpointer pl)
{

  GSList *entry;
#if GTK_MAJOR_VERSION < 2
  GtkCList *proto_list = GTK_CLIST(pl);
#endif

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;

    if (p->enabled)
      p->enabled = FALSE;
    else
      p->enabled = TRUE;
    
#if GTK_MAJOR_VERSION < 2
    gtk_clist_set_text(proto_list, p->row, 0, STATUS_TXT(p->enabled) );
#endif
  }
}

/* Enable/Disable All Helper */
static void
set_active_all(GtkWidget *w, gboolean new_state)
{

#if GTK_MAJOR_VERSION < 2
  GtkCList *proto_list = GTK_CLIST(w);
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

  if (proto_w)
    gtk_widget_destroy(proto_w);
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
proto_delete_cb(GtkWidget *proto_w, gpointer dummy _U_)
{
  proto_cancel_cb(NULL, proto_w);
  return FALSE;
}

static void
proto_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  gboolean redissect;

  redissect = set_proto_selection(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    redissect_packets(&cfile);
}

static void
proto_apply_cb(GtkWidget *apply_bt _U_, gpointer parent_w)
{
  if (set_proto_selection(GTK_WIDGET(parent_w)))
    redissect_packets(&cfile);
}

static void
proto_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
  gboolean redissect;

  redissect = revert_proto_selection();
  gtk_widget_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    redissect_packets(&cfile);
}

static gboolean
set_proto_selection(GtkWidget *parent_w _U_)
{
  GSList *entry;
  gboolean need_redissect = FALSE;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;

    if (proto_is_protocol_enabled(p->hfinfo_index) != p->enabled) {
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

    if (proto_is_protocol_enabled(p->hfinfo_index) != p->was_enabled) {
      proto_set_decoding(p->hfinfo_index, p->was_enabled);
      need_redissect = TRUE;
    }
  }

  return need_redissect;

} /* revert_proto_selection */

gint
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
  protocol_data_t *p;
#if GTK_MAJOR_VERSION < 2
  gchar *proto_text[3];
#else
  GtkTreeIter proto_iter;
#endif

  /* Iterate over all the protocols */

  for (i = proto_get_first_protocol(&cookie); i != -1;
       i = proto_get_next_protocol(&cookie)) {
      if (proto_can_disable_protocol(i)) {
        p = g_malloc(sizeof(protocol_data_t));
        p->name = proto_get_protocol_name(i);
        p->abbrev = proto_get_protocol_short_name(i);
        p->hfinfo_index = i;
        p->enabled = proto_is_protocol_enabled(i);
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
    p->row = gtk_clist_append(proto_list, proto_text);
    gtk_clist_set_row_data(proto_list, p->row, p);
#else
    gtk_list_store_append(proto_store, &proto_iter);
    gtk_list_store_set(proto_store, &proto_iter,
                       0, STATUS_TXT (p->enabled),
                       1, p->abbrev,
                       2, p->name,
                      -1);
#endif
  }

} /* show_proto_selection */
