/* filter_autocomplete.h
 * Definitions for filter autocomplete
 *
 * Copyright 2008, Bahaa Naamneh <b.naamneh@gmail.com>
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
#include <gdk/gdkkeysyms.h>

#include <epan/proto.h>

#include "gtk/gui_utils.h"
#include "gtk/filter_autocomplete.h"

#define E_FILT_AUTOCOMP_TREE_KEY    "filter_autocomplete_tree"


static GtkWidget *filter_autocomplete_new(GtkWidget *filter_te, const gchar *protocol_name, 
					  gboolean protocols_only);
static void autocomplete_protocol_string(GtkWidget  *filter_te, gchar* selected_str);
static void autoc_filter_row_activated_cb(GtkTreeView *treeview, 
                      GtkTreePath *path, 
                      GtkTreeViewColumn *column, 
                      gpointer data);
static gint filter_te_focus_out_cb(GtkWidget *filter_te, GdkEvent *event, gpointer data);
static void init_autocompletion_list(GtkWidget *list);
static void add_to_autocompletion_list(GtkWidget *list, const gchar *str);
static gboolean autocompletion_list_lookup(GtkWidget *popup_win, GtkWidget *list, const gchar *str);
static void filter_autocomplete_handle_backspace(GtkWidget *list, 
                         GtkWidget *popup_win,
                         gchar *prefix, 
                         GtkWidget *main_win);
static void filter_autocomplete_win_destroy_cb(GtkWidget *win, gpointer data);



static void
autocomplete_protocol_string(GtkWidget *filter_te, gchar *selected_str)
{
  int pos;
  gchar *filter_str;
  gchar *pch;

  /* Get the current filter string */
  pos = gtk_editable_get_position(GTK_EDITABLE(filter_te));
  filter_str = gtk_editable_get_chars(GTK_EDITABLE(filter_te), 0, pos);

  /* Start from the end */
  pch = filter_str + strlen(filter_str);

  /* Walk back through string to find last non-punctuation */
  while(pch != filter_str) {
    pch--;
    if(!g_ascii_isalnum(*pch) && (*pch) != '.' && (*pch) != '_' && (*pch) != '-') {
      pch++;
      break;
    }
  }

  if(strncmp(pch, selected_str, pos-(pch-filter_str))) {
    gtk_editable_delete_text(GTK_EDITABLE(filter_te), pch-filter_str, pos);
    pos = pch-filter_str;
    pch = selected_str;
  } else {
    pch = (selected_str + strlen(pch));
  }

  gtk_editable_insert_text(GTK_EDITABLE(filter_te), pch, strlen(pch), &pos);
  gtk_editable_set_position(GTK_EDITABLE(filter_te), pos);
}

/* On row activated signal, complete the protocol string automatically */
static void
autoc_filter_row_activated_cb(GtkTreeView *treeview, 
                              GtkTreePath *path, 
                              GtkTreeViewColumn *column _U_, 
                              gpointer data)
{
  GtkWidget *w_main;
  GtkTreeModel *model;
  GtkTreeIter iter;
  GtkWidget *win;
  gchar *proto;

  model = gtk_tree_view_get_model(treeview);

  if (gtk_tree_model_get_iter(model, &iter, path)) {

    gtk_tree_model_get(model, &iter, 0, &proto, -1);
    autocomplete_protocol_string(GTK_WIDGET(data), proto);

    g_free (proto);
  }

  w_main = gtk_widget_get_toplevel(GTK_WIDGET(data));
  win = g_object_get_data(G_OBJECT(w_main), E_FILT_AUTOCOMP_PTR_KEY);
  if(win != NULL) {
    gtk_widget_destroy(win);
    g_object_set_data(G_OBJECT(w_main), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  }
}

static gint
filter_te_focus_out_cb(GtkWidget *filter_te _U_, 
                       GdkEvent *event _U_, 
                       gpointer data)
{
  GtkWidget *win;

  win = g_object_get_data(G_OBJECT(data), E_FILT_AUTOCOMP_PTR_KEY);
  if(win != NULL) {
    gtk_widget_destroy(win);
    g_object_set_data(G_OBJECT(data), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  }

  return FALSE;
}

static void
init_autocompletion_list(GtkWidget *list)
{
  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;
  GtkListStore *store;

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes(NULL, renderer, "text", 0, NULL);

  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list), FALSE);

  store = gtk_list_store_new(1, G_TYPE_STRING);

  gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(store));

  g_object_unref(store);
}

static void
add_to_autocompletion_list(GtkWidget *list, const gchar *str)
{
  GtkListStore *store;
  GtkTreeIter iter;

  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));

  gtk_list_store_append(store, &iter);
  gtk_list_store_set(store, &iter, 0, str, -1);
}

static gboolean
autocompletion_list_lookup(GtkWidget *popup_win, GtkWidget *list, const gchar *str)
{
  GtkRequisition requisition;
  GtkListStore *store;
  GtkTreeIter iter;
  GtkTreeSelection *selection;
  gchar *curr_str;
  gboolean loop = TRUE;

  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));

  if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));

    do {

      gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &curr_str,  -1);

      if( !g_ascii_strncasecmp(str, curr_str, strlen(str)) )
        loop = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
      else
        loop = gtk_list_store_remove(store, &iter);

      g_free(curr_str);

    } while( loop );

    if(!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
      return FALSE;

    gtk_tree_selection_select_iter(GTK_TREE_SELECTION(selection), &iter);

    gtk_widget_size_request(list, &requisition);

    gtk_widget_set_size_request(popup_win, (requisition.width<100?125:requisition.width+25), (requisition.height<200? requisition.height+8:200));
    gtk_window_resize(GTK_WINDOW(popup_win), (requisition.width<100?125:requisition.width+25), (requisition.height<200? requisition.height+8:200));

    return TRUE;
  }

  return FALSE;
}

gboolean
filter_string_te_key_pressed_cb(GtkWidget *filter_te, GdkEventKey *event)
{
  GtkWidget *popup_win;
  GtkWidget *w_toplevel;
  GtkWidget *treeview;
  GtkTreeModel *model;
  GtkTreeSelection *selection;
/*  GtkListStore *store; */
  GtkTreeIter iter;
  const gchar *filter_te_str = "";
  gchar* prefix = "";
  gchar* prefix_start;
  guint k;
  gchar ckey;
  gint pos;

  w_toplevel = gtk_widget_get_toplevel(filter_te);

  popup_win = g_object_get_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY);

  k = event->keyval;
  ckey = event->string[0];

  /* If the pressed key is SHIFT then we have nothing to do with the pressed key. */
  if( k == GDK_Shift_L || k == GDK_Shift_R )
    return FALSE;

  /* get the string from filter_te, start from 0 till cursor's position */
  pos = gtk_editable_get_position(GTK_EDITABLE(filter_te));
  filter_te_str = gtk_editable_get_chars(GTK_EDITABLE(filter_te), 0, pos);

  /* If the pressed key is non-alphanumeric or one of the keys specified 
   * in the condition (decimal, period...) then destroy popup window.
   **/
  if( !g_ascii_isalnum(ckey) && 
      k != GDK_KP_Decimal && k != GDK_period && 
      k != GDK_underscore && k != GDK_minus &&
      k != GDK_space && k != GDK_Return && k != GDK_KP_Enter && 
      k != GDK_Down && k != GDK_Up &&
      k != GDK_BackSpace)
  {
    if (popup_win) {
      gtk_widget_destroy(popup_win);
      g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, NULL);
    }
    return FALSE;
  }

  /* Let prefix points to the first char that is not aphanumeric,'.', '_' or '-',
   * start from the end of filter_te_str.
   **/
  prefix = g_strdup(filter_te_str);
  prefix_start = prefix;
  prefix += strlen(filter_te_str);
  while(prefix != prefix_start) {
    prefix--;
    if(!g_ascii_isalnum((*prefix)) && (*prefix) != '.' && (*prefix) != '_' && (*prefix) != '-') {
      prefix++;
      break;
    }
  }

  /* Now, if the pressed key is decimal or period, and there is no period or
   * decimal before it in prefix then construct the popup window.
   *
   * If the pressed key is backspace, and there is no existing popup window
   * then construct the popup window again.
   **/
  if(k==GDK_period || k==GDK_KP_Decimal) {
    if( !strchr(prefix, '.') ) {

      gchar* name_with_period;

      if (popup_win) {
	gtk_widget_destroy (popup_win);
      }

      name_with_period = g_strconcat(prefix, event->string, NULL);
      popup_win = filter_autocomplete_new(filter_te, name_with_period, FALSE);
      g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, popup_win);

      if(name_with_period)
	g_free (name_with_period);
    }
    if(prefix_start)
      g_free(prefix_start);

    return FALSE;
  } else if(k==GDK_BackSpace && !popup_win) {

    if(strlen(prefix) > 1) {
      /* Delete the last character in the prefix string */
      prefix[strlen(prefix)-1] = '\0';
      if(strchr(prefix, '.')) {
        popup_win = filter_autocomplete_new(filter_te, prefix, FALSE);
        g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, popup_win);
      } else if(strlen(prefix)) {
        popup_win = filter_autocomplete_new(filter_te, prefix, TRUE);
        g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, popup_win);
      }
    }

    if(prefix_start)
      g_free(prefix_start);

    return FALSE;
  } else if(g_ascii_isalnum(ckey) && !popup_win) {
    gchar *name = g_strconcat(prefix, event->string, NULL);

    if (strlen(name) && !strchr(name, '.')) {
      popup_win = filter_autocomplete_new(filter_te, name, TRUE);
      g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, popup_win);
    }

    if (name)
      g_free (name);

    if(prefix_start)
      g_free(prefix_start);

    return FALSE;
  }

  /* If the popup window hasn't been constructed yet then we have nothing to do */
  if( !popup_win ) {
    if(prefix_start)
      g_free(prefix_start);

    return FALSE;
  }


  treeview = g_object_get_data(G_OBJECT(popup_win), E_FILT_AUTOCOMP_TREE_KEY);
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));

  switch(k)
    {
      /* a better implementation for UP/DOWN keys would be moving the control to the popup'ed window, and letting 
       * the treeview handle the up, down actions directly and return the control to the filter text once 
       * the user press Enter or any key except for UP, DOWN arrows. * I wasn't able to find a way to do that. *
       **/
    case GDK_Down:
      if( gtk_tree_selection_get_selected(selection, &model, &iter) ) {
        if(gtk_tree_model_iter_next(model, &iter)) {
          gtk_tree_selection_select_iter(GTK_TREE_SELECTION(selection), &iter);
          gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(treeview), 
                                       gtk_tree_model_get_path(model, &iter),
                                       NULL, FALSE, 0, 0);
        }
      } else {
      if(gtk_tree_model_get_iter_first(model, &iter))
        gtk_tree_selection_select_iter(GTK_TREE_SELECTION(selection), &iter);
      }

      if(prefix_start)
	g_free(prefix_start);

      /* stop event propagation */
      return TRUE;

    case GDK_Up: {
      GtkTreePath* path;

      if(gtk_tree_selection_get_selected(selection, &model, &iter) ) {
          path = gtk_tree_model_get_path(model, &iter);

        if(gtk_tree_path_prev(path)) {
          gtk_tree_selection_select_path(GTK_TREE_SELECTION(selection), path);
          gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(treeview), path, NULL, FALSE, 0, 0);
        }
      } else {
      if(gtk_tree_model_get_iter_first(model, &iter))
        gtk_tree_selection_select_iter(GTK_TREE_SELECTION(selection), &iter);
      }

      if(prefix_start)
	g_free(prefix_start);

      /* stop event propagation */
      return TRUE;
    }


      /* if pressed key is Space or Enter then autocomplete protocol string */
    case GDK_space:
    case GDK_Return:
    case GDK_KP_Enter:

      if(gtk_tree_selection_get_selected(selection, &model, &iter) ) {
        gchar *value;

	/* Do not autocomplete protocols with space yet, because we can be in
	 * a operator or a value field.
	 **/
	if(k != GDK_space || strchr(prefix, '.')) {
	  /* Use chosen string */
	  gtk_tree_model_get(model, &iter, 0, &value,  -1);
	  autocomplete_protocol_string(filter_te, value);
	  g_free(value);
	}
      }

      /* Lose popup */
      gtk_widget_destroy(popup_win);
      g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, NULL);
      break;

    case GDK_BackSpace:
      filter_autocomplete_handle_backspace(treeview, popup_win, prefix, w_toplevel);
      break;

    default: {
      gchar* updated_str;

      updated_str = g_strconcat(prefix, event->string, NULL);
      if( !autocompletion_list_lookup(popup_win, treeview, updated_str) ) {
        /* function returned false, ie the list is empty -> close popup  */
        gtk_widget_destroy(popup_win);
        g_object_set_data(G_OBJECT(w_toplevel), E_FILT_AUTOCOMP_PTR_KEY, NULL);
      }

      if(updated_str)
        g_free(updated_str);
    }

  }


  if(prefix_start)
    g_free(prefix_start);

  if(k == GDK_Return || k == GDK_KP_Enter)
    return TRUE;    /* stop event propagation */

  return FALSE;
}

static GtkWidget *
filter_autocomplete_new(GtkWidget *filter_te, const gchar *protocol_name, gboolean protocols_only)
{
  GtkWidget *popup_win;
  GtkWidget *treeview;
  GtkWidget *filter_sc;
  void *cookie, *cookie2;
  protocol_t *protocol;
  int i, protocol_name_len;
  header_field_info *hfinfo;
  gint x_pos, y_pos;
  GtkTreeSelection *selection;
  GtkTreeModel *model;
  GtkSortType order;
  GtkRequisition requisition;
  GtkWidget *w_toplevel;
  GtkListStore *store;
  GtkTreeIter iter;

  w_toplevel = gtk_widget_get_toplevel(filter_te);

  /* Create popup window */
  popup_win = gtk_window_new (GTK_WINDOW_POPUP); 

  /* Create scrolled window */
  filter_sc = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (filter_sc), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(filter_sc), GTK_SHADOW_IN);
  gtk_container_add(GTK_CONTAINER(popup_win), filter_sc);

  /* Create tree view */
  treeview = gtk_tree_view_new();
  init_autocompletion_list(treeview);
  g_object_set_data(G_OBJECT(popup_win), E_FILT_AUTOCOMP_TREE_KEY, treeview);

  /*
   * In my implementation, I'm looking for fields that match the protocol name in the whole fields list
   * and not only restrict the process by returning all the fields of the protocol that match the prefix using
   * 'proto_get_id_by_filter_name(protocol_name)'; because I have noticed that some of the fields
   * have a prefix different than its parent protocol; for example SIP protocol had this field raw_sip.line despite
   * that there is a protocol called RAW_SIP which it should be associated with it.
   * so the unorganized fields and nonexistent of a standardized protocols and fields naming rules prevent me from
   * implementing the autocomplete in an optimized way.
   **/
  protocol_name_len = strlen(protocol_name);

  /* Walk protocols list */
  for (i = proto_get_first_protocol(&cookie); i != -1; i = proto_get_next_protocol(&cookie)) {

    protocol = find_protocol_by_id(i);

    if (!proto_is_protocol_enabled(protocol))
      continue;

    if (protocols_only) {
      const gchar *name = proto_get_protocol_filter_name (i);

      if (!g_ascii_strncasecmp(protocol_name, name, protocol_name_len))
	add_to_autocompletion_list(treeview, name);
    } else {
      hfinfo = proto_registrar_get_nth(i);

      for (hfinfo = proto_get_first_protocol_field(i, &cookie2); 
	   hfinfo != NULL;
	   hfinfo = proto_get_next_protocol_field(&cookie2)) 
	{
	  if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
	    continue;

	  if(!g_ascii_strncasecmp(protocol_name, hfinfo->abbrev, protocol_name_len))
	    add_to_autocompletion_list(treeview, hfinfo->abbrev);
	}
    }
  }

  /* Don't show an empty autocompletion-list */
  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(treeview)));
  if( !gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {
    gtk_widget_destroy(popup_win);
    return NULL;
  }

  /* sort treeview */
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
  order = GTK_SORT_ASCENDING;
  if(model)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(model), 0, order);

  gtk_container_add (GTK_CONTAINER (filter_sc), treeview);

  g_signal_connect(treeview, "row-activated", G_CALLBACK(autoc_filter_row_activated_cb), filter_te);
  g_signal_connect(filter_te, "focus-out-event", G_CALLBACK(filter_te_focus_out_cb), w_toplevel);
  g_signal_connect(popup_win, "destroy", G_CALLBACK(filter_autocomplete_win_destroy_cb), NULL);

  /* Select first entry */
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
  gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);
  gtk_tree_selection_select_iter(GTK_TREE_SELECTION(selection), &iter);

  gtk_widget_size_request(treeview, &requisition);

  gtk_widget_set_size_request (popup_win, (requisition.width<100?125:requisition.width+25), (requisition.height<200? requisition.height+8:200));
  gtk_window_resize(GTK_WINDOW(popup_win), (requisition.width<100?125:requisition.width+25), (requisition.height<200? requisition.height+8:200));

  gtk_window_get_position(GTK_WINDOW(w_toplevel), &x_pos, &y_pos); 
  x_pos = x_pos + filter_te->allocation.x;
  y_pos = y_pos + filter_te->allocation.y + filter_te->allocation.height + 22;

  gtk_window_move(GTK_WINDOW(popup_win), x_pos, y_pos);

  gtk_widget_show_all (popup_win);

  return popup_win;
}

static void 
filter_autocomplete_handle_backspace(GtkWidget *list, GtkWidget *popup_win, gchar *prefix, GtkWidget *main_win)
{
  GtkListStore *store;
  GtkTreeSelection *selection;
  GtkRequisition requisition;
  GtkTreeIter iter;

  void *cookie, *cookie2;
  protocol_t *protocol;
  int i;
  header_field_info *hfinfo;
  gint prefix_len;
  gboolean protocols_only = FALSE;

  /* Delete the last character in the prefix string */
  prefix_len = strlen(prefix)-1;
  prefix[prefix_len] = '\0';

  if (prefix_len == 0) {
    /* Remove the popup window for protocols */
    gtk_widget_destroy(popup_win);
    g_object_set_data(G_OBJECT(main_win), E_FILT_AUTOCOMP_PTR_KEY, NULL);
    return;
  } else if(strchr(prefix, '.') == NULL) {
    protocols_only = TRUE;
  }

  /* Empty list */
  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
  gtk_list_store_clear(store);

  /* Look through enabled protocols for matching fields to show in list */
  for (i = proto_get_first_protocol(&cookie); i != -1; i = proto_get_next_protocol(&cookie)) {

    protocol = find_protocol_by_id(i);

    if (!proto_is_protocol_enabled(protocol))
      continue;

    if (protocols_only) {
      const gchar *name = proto_get_protocol_filter_name (i);

      if (!g_ascii_strncasecmp(prefix, name, prefix_len))
	add_to_autocompletion_list(list, name);
    } else {
      hfinfo = proto_registrar_get_nth(i);

      /* Try all fields in this protocol */
      for (hfinfo = proto_get_first_protocol_field(i, &cookie2); 
	   hfinfo != NULL;
	   hfinfo = proto_get_next_protocol_field(&cookie2)) 
      {
	if (hfinfo->same_name_prev != NULL) /* ignore duplicate names */
	  continue;

	/* Add if prefix matches */
	if(!g_ascii_strncasecmp(prefix, hfinfo->abbrev, prefix_len))
	  add_to_autocompletion_list(list, hfinfo->abbrev);
      }
    }
  }

  /* Select first entry */
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
  gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);
  gtk_tree_selection_select_iter(GTK_TREE_SELECTION(selection), &iter);

  gtk_widget_size_request(list, &requisition);

  gtk_widget_set_size_request (popup_win, (requisition.width<100?125:requisition.width+25), (requisition.height<200? requisition.height+8:200));
  gtk_window_resize(GTK_WINDOW(popup_win), (requisition.width<100?125:requisition.width+25), (requisition.height<200? requisition.height+8:200));
}

static void 
filter_autocomplete_win_destroy_cb(GtkWidget *win, gpointer data _U_)
{
  /* tell that the autocomplete window doesn't exist anymore */
  g_object_set_data(G_OBJECT(win), E_FILT_AUTOCOMP_PTR_KEY, NULL);
}

gboolean
filter_parent_dlg_key_pressed_cb(GtkWidget *win, GdkEventKey *event)
{
  GtkWidget *popup_win;

  popup_win = g_object_get_data(G_OBJECT(win), E_FILT_AUTOCOMP_PTR_KEY);

  if(popup_win && event->keyval == GDK_Escape) {
    gtk_widget_destroy(popup_win);
    g_object_set_data(G_OBJECT(win), E_FILT_AUTOCOMP_PTR_KEY, NULL);

    /* stop event propagation */
    return TRUE;
  }

  return FALSE;
}
