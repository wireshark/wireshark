/* proto_dlg.c
 *
 * $Id: proto_dlg.c,v 1.3 2000/08/16 21:08:47 deniel Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 *
 */

/*
 * TODO : 
 *
 * Modify proto.c to have a better protocol characteristics database
 * such as ordered list or hash table. This would allow a quick search
 * knowing the protocol abbreviation and to enhance this stuff by adding
 * other fields (hfinfo is currently limited since protocols and fields 
 * share the same structure type).
 *        
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "prefs.h"
#include "globals.h"
#include "gtkglobals.h"
#include "main.h"
#include "util.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "proto_dlg.h"

#define MAX_SCROLLED_WINDOWS	1

static void proto_ok_cb(GtkWidget *, gpointer);
static void proto_apply_cb(GtkWidget *, gpointer);
static void proto_close_cb(GtkWidget *, gpointer);

static void show_proto_selection(GtkWidget *main, GtkWidget *container);
static gboolean set_proto_selection(GtkWidget *);

static GtkWidget *scrolled_w[MAX_SCROLLED_WINDOWS];
static GtkWidget *proto_w = NULL;

/* list of protocols */
static GSList *protocol_list = NULL;

typedef struct protocol_data {
  char 	*abbrev;
  int  	hfinfo_index;
} protocol_data_t;

void proto_cb(GtkWidget *w, gpointer data)
{
  int nb_scroll = 0;
  GtkWidget *main_vb, *bbox, *proto_nb, *apply_bt, *cancel_bt, *ok_bt, 
    *label, *selection_vb;
  
  if (proto_w != NULL) {
    reactivate_window(proto_w);
    return;
  }

  for(nb_scroll = 0; nb_scroll < MAX_SCROLLED_WINDOWS; nb_scroll++) {
    scrolled_w[nb_scroll] = NULL;
  }

  nb_scroll = 0;

  proto_w = dlg_window_new();
  gtk_window_set_title(GTK_WINDOW(proto_w), "Ethereal: Protocol");
  gtk_signal_connect(GTK_OBJECT(proto_w), "destroy",
		     GTK_SIGNAL_FUNC(proto_close_cb), NULL);
  gtk_widget_set_usize(GTK_WIDGET(proto_w), DEF_WIDTH * 2/3, DEF_HEIGHT * 2/3);

  /* Container for each row of widgets */

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 1);
  gtk_container_add(GTK_CONTAINER(proto_w), main_vb);
  gtk_widget_show(main_vb);

  /* Protocol topics container */
  
  proto_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), proto_nb);
  /* XXX do not know why I need this to fill all space around buttons */
  gtk_widget_set_usize(GTK_WIDGET(proto_nb), DEF_WIDTH * 2/3 - 50,
		       DEF_HEIGHT * 2/3 - 50);

  /* Protocol selection panel ("enable/disable" protocols) */

  selection_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(selection_vb), 1);  
  label = gtk_label_new("Button pressed: protocol decoding is enabled");
  gtk_widget_show(label);
  gtk_box_pack_start(GTK_BOX(selection_vb), label, FALSE, FALSE, 0);
  scrolled_w[nb_scroll] = gtk_scrolled_window_new(NULL, NULL);         
  gtk_container_set_border_width(GTK_CONTAINER(scrolled_w[nb_scroll]), 1);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_w[nb_scroll]),
				 GTK_POLICY_AUTOMATIC,
				 GTK_POLICY_ALWAYS);
  set_scrollbar_placement_scrollw(scrolled_w[nb_scroll],
				  prefs.gui_scrollbar_on_right);
  remember_scrolled_window(scrolled_w[nb_scroll]);
  gtk_box_pack_start(GTK_BOX(selection_vb), scrolled_w[nb_scroll],
		     TRUE, TRUE, 0);
  show_proto_selection(proto_w, scrolled_w[nb_scroll]);
  gtk_widget_show(scrolled_w[nb_scroll]);
  gtk_widget_show(selection_vb);
  label = gtk_label_new("Decoding");
  gtk_notebook_append_page(GTK_NOTEBOOK(proto_nb), selection_vb, label);
  label = gtk_label_new("Note that when a protocol is disabled, "
			"all linked sub-protocols are as well");
  gtk_widget_show(label);
  gtk_box_pack_start(GTK_BOX(selection_vb), label, FALSE, FALSE, 0);

  /* XXX add other protocol-related panels here ... */

  gtk_widget_show(proto_nb);

  /* Ok, Apply, Cancel Buttons */  

  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		     GTK_SIGNAL_FUNC(proto_ok_cb), GTK_OBJECT(proto_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  apply_bt = gtk_button_new_with_label ("Apply");
  gtk_signal_connect(GTK_OBJECT(apply_bt), "clicked",
		     GTK_SIGNAL_FUNC(proto_apply_cb), GTK_OBJECT(proto_w));
  GTK_WIDGET_SET_FLAGS(apply_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), apply_bt, TRUE, TRUE, 0);
  gtk_widget_show(apply_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
		     GTK_SIGNAL_FUNC(proto_close_cb), GTK_OBJECT(proto_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  dlg_set_cancel(proto_w, cancel_bt);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(proto_w));
  gtk_widget_show(proto_w);

} /* proto_cb */

static void proto_close_cb(GtkWidget *w, gpointer data)
{
  GSList *entry;
  int nb_scroll;

  for(nb_scroll = 0; nb_scroll < MAX_SCROLLED_WINDOWS; nb_scroll++) {
    if (scrolled_w[nb_scroll]) {
      forget_scrolled_window(scrolled_w[nb_scroll]);
      scrolled_w[nb_scroll] = NULL;
    }
  }

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

static void proto_ok_cb(GtkWidget *ok_bt, gpointer parent_w) 
{
  gboolean redissect;
  redissect = set_proto_selection(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    redissect_packets(&cfile);
}

static void proto_apply_cb(GtkWidget *ok_bt, gpointer parent_w) 
{
  if (set_proto_selection(GTK_WIDGET(parent_w)))
    redissect_packets(&cfile);
}

static gboolean set_proto_selection(GtkWidget *parent_w)
{
  GSList *entry;
  gboolean need_redissect = FALSE;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    GtkWidget *button;
    header_field_info *hfinfo;
    protocol_data_t *p = entry->data;
    hfinfo = proto_registrar_get_nth(p->hfinfo_index);
    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					       hfinfo->abbrev);      
    /* XXX optimization but should not use display field */
    if (hfinfo->display != GTK_TOGGLE_BUTTON (button)->active) {
      proto_set_decoding(p->hfinfo_index, GTK_TOGGLE_BUTTON (button)->active);
      need_redissect = TRUE;
    }  
  }

return need_redissect;

} /* set_proto_selection */

gint protocol_data_compare(gconstpointer a, gconstpointer b)
{
  return strcmp(((protocol_data_t *)a)->abbrev, 
		((protocol_data_t *)b)->abbrev);
}

static void show_proto_selection(GtkWidget *main, GtkWidget *container)
{

#define NB_COL	7

  GSList *entry;
  GtkTooltips *tooltips;
  GtkWidget *table;
  int i, t = 0, l = 0, nb_line, nb_proto = 0;

  /* Obtain the number of "true" protocols */

  for (i = 0; i < proto_registrar_n() ; i++) {

    if (proto_registrar_is_protocol(i)) {

      protocol_data_t *p;
      header_field_info *hfinfo;
      hfinfo = proto_registrar_get_nth(i);	  

      if (strcmp(hfinfo->abbrev, "data") == 0 ||
	  strcmp(hfinfo->abbrev, "text") == 0 ||
	  strcmp(hfinfo->abbrev, "malformed") == 0 ||
	  strcmp(hfinfo->abbrev, "short") == 0 ||
	  strcmp(hfinfo->abbrev, "frame") == 0) continue;

      p = g_malloc(sizeof(protocol_data_t));
      p->abbrev = hfinfo->abbrev;
      p->hfinfo_index = i;
      protocol_list = g_slist_insert_sorted(protocol_list, 
					    p, protocol_data_compare);     
      nb_proto ++;
    }
  }

  /* create a table (n x NB_COL) of buttons */

  nb_line = (nb_proto % NB_COL) ? nb_proto / NB_COL + 1 : nb_proto / NB_COL;
  table = gtk_table_new (nb_line, NB_COL, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE (table), 1);
  gtk_table_set_col_spacings(GTK_TABLE (table), 1);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(container), table);
  gtk_widget_show(table);

  tooltips = gtk_tooltips_new();

  nb_proto = 0;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    GtkWidget *button;
    header_field_info *hfinfo;
    protocol_data_t *p = entry->data;
    hfinfo = proto_registrar_get_nth(p->hfinfo_index);	  
    /* button label is the protocol abbrev */
    button = gtk_toggle_button_new_with_label(hfinfo->abbrev);
    /* tip is the complete protocol name */
    gtk_tooltips_set_tip(tooltips, button, hfinfo->name, NULL);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), hfinfo->display);
    gtk_object_set_data(GTK_OBJECT(main), hfinfo->abbrev, button);
    gtk_table_attach_defaults (GTK_TABLE (table), button, l, l+1, t, t+1);
    gtk_widget_show (button);
    if (++nb_proto % NB_COL) {
      l++;
    }
    else {
      l = 0;
      t++;
    }
  }

} /* show_proto_selection */
