/* filter.c
 * Routines for managing filter sets
 *
 * $Id: filter.c,v 1.2 1998/09/16 03:21:58 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include <sys/stat.h>
#include <unistd.h>

#include "filter.h"
#include "packet.h"
#include "file.h"
#include "menu.h"

extern capture_file cf;

const gchar *fn_key = "filter_name";
const gchar *fl_key = "filter_label";
GtkWidget   *filter_l, *chg_bt, *copy_bt, *del_bt, *name_te, *filter_te;
gint         in_cancel = FALSE;
GList       *fl = NULL;

GList *
read_filter_list() {
  filter_def *filt;
  FILE       *ff;
  gchar      *ff_path, *ff_name = ".ethereal/filters", f_buf[256];
  gchar      *name_begin, *name_end, *filt_begin;
  int         len, line = 0;
  
  in_cancel = FALSE;
  
  /* To do: generalize this */
  ff_path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(ff_name) +  4);
  sprintf(ff_path, "%s/%s", getenv("HOME"), ff_name);

  if ((ff = fopen(ff_path, "r")) == NULL) {
    g_free(ff_path);
    return NULL;
  }

  while (fgets(f_buf, 256, ff)) {
    line++;
    len = strlen(f_buf);
    if (f_buf[len - 1] = '\n') {
      len--;
      f_buf[len] = '\0';
    }
    name_begin = strchr(f_buf, '"');
    /* Empty line */
    if (name_begin == NULL)
      continue;
    name_end = strchr(name_begin + 1, '"');
    /* No terminating quote */
    if (name_end == NULL) {
      g_warning("Malformed filter in '%s' line %d.", ff_path, line);
      continue;
    }
    name_begin++;
    name_end[0] = '\0';
    filt_begin  = name_end + 1;
    while(isspace(filt_begin[0])) filt_begin++;
    /* No filter string */
    if (filt_begin[0] == '\0') {
      g_warning("Malformed filter in '%s' line %d.", ff_path, line);
      continue;
    }
    filt         = (filter_def *) g_malloc(sizeof(filter_def));
    filt->name   = g_strdup(name_begin);
    filt->strval = g_strdup(filt_begin);
    fl = g_list_append(fl, filt);
  }
  fclose(ff);
  g_free(ff_path);
  return fl;
}

/* filter_sel_cb - Create and display the filter selection dialog. */
/* Called when the 'Filter' menu item is selected. */
void
filter_sel_cb(GtkWidget *w, gpointer d) {
  GtkWidget      *filter_w, *main_vb, *top_hb, *list_bb, *bbox,
                 *new_bt, *ok_bt, *save_bt, *cancel_bt, *filter_sc, *nl_item,
                 *nl_lb, *middle_hb, *name_lb, *bottom_hb, *filter_lb;
  GtkWidget      *l_select = NULL;
  GList          *flp = NULL, *nl = NULL;
  filter_def     *filt;
  
  fl = read_filter_list();

  filter_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(filter_w), "Ethereal: Filters");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(filter_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Top row: Filter list and buttons */
  top_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  list_bb = gtk_vbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (list_bb), GTK_BUTTONBOX_START);
  gtk_container_add(GTK_CONTAINER(top_hb), list_bb);
  gtk_widget_show(list_bb);

  new_bt = gtk_button_new_with_label ("New");
  gtk_signal_connect(GTK_OBJECT(new_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_new_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), new_bt);
  gtk_widget_show(new_bt);
  
  chg_bt = gtk_button_new_with_label ("Change");
  gtk_widget_set_sensitive(chg_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(chg_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_chg_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), chg_bt);
  gtk_widget_show(chg_bt);
  
  copy_bt = gtk_button_new_with_label ("Copy");
  gtk_widget_set_sensitive(copy_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(copy_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_copy_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), copy_bt);
  gtk_widget_show(copy_bt);
  
  del_bt = gtk_button_new_with_label ("Delete");
  gtk_widget_set_sensitive(del_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(del_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_del_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), del_bt);
  gtk_widget_show(del_bt);
  
  filter_sc = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(filter_sc),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_widget_set_usize(filter_sc, 250, 150);
  gtk_container_add(GTK_CONTAINER(top_hb), filter_sc);
  gtk_widget_show(filter_sc);

  filter_l = gtk_list_new();
  gtk_signal_connect(GTK_OBJECT(filter_l), "selection_changed",
    GTK_SIGNAL_FUNC(filter_sel_list_cb), NULL);
  gtk_container_add(GTK_CONTAINER(filter_sc), filter_l);
  gtk_widget_show(filter_l);

  flp = g_list_first(fl);
  while (flp) {
    filt    = (filter_def *) flp->data;
    nl_lb   = gtk_label_new(filt->name);
    nl_item = gtk_list_item_new();
    gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
    gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
    gtk_widget_show(nl_lb);
    gtk_container_add(GTK_CONTAINER(filter_l), nl_item);
    gtk_widget_show(nl_item);
    gtk_object_set_data(GTK_OBJECT(nl_item), fl_key, nl_lb);
    gtk_object_set_data(GTK_OBJECT(nl_item), fn_key, flp);
    if (cf.filter && filt->strval)
      if (strcmp(cf.filter, filt->strval) == 0)
        l_select = nl_item;
    flp = flp->next;
  }
  
  /* Middle row: Filter name entry */
  middle_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), middle_hb);
  gtk_widget_show(middle_hb);
  
  name_lb = gtk_label_new("Filter name:");
  gtk_box_pack_start(GTK_BOX(middle_hb), name_lb, FALSE, FALSE, 3);
  gtk_widget_show(name_lb);
  
  name_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(middle_hb), name_te, TRUE, TRUE, 3);
  gtk_widget_show(name_te);

  /* Bottom row: Filter text entry */
  bottom_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bottom_hb);
  gtk_widget_show(bottom_hb);
  
  filter_lb = gtk_label_new("Filter string:");
  gtk_box_pack_start(GTK_BOX(bottom_hb), filter_lb, FALSE, FALSE, 3);
  gtk_widget_show(filter_lb);
  
  filter_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(bottom_hb), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);
  
  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_ok_cb), (gpointer) filter_w);
  gtk_container_add(GTK_CONTAINER(bbox), ok_bt);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(ok_bt);  
  gtk_widget_show(ok_bt);

  save_bt = gtk_button_new_with_label ("Save");
  gtk_signal_connect(GTK_OBJECT(save_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_save_cb), (gpointer) fl);
  gtk_container_add(GTK_CONTAINER(bbox), save_bt);
  gtk_widget_show(save_bt);
  
  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_sel_cancel_cb), (gpointer) filter_w);
  gtk_container_add(GTK_CONTAINER(bbox), cancel_bt);
  gtk_widget_show(cancel_bt);
  
  gtk_widget_show(filter_w);

  if (l_select)
    gtk_list_select_child(GTK_LIST(filter_l), l_select);
}

void
filter_sel_list_cb(GtkWidget *l, gpointer data) {
  filter_def *filt;
  gchar      *name = "", *strval = "";
  GList      *sl, *flp;
  GtkObject  *l_item;
  gint        sensitivity = FALSE;

  sl = GTK_LIST(l)->selection;
          
  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    flp    = (GList *) gtk_object_get_data(l_item, fn_key);
    if (flp) {
      filt   = (filter_def *) flp->data;
      name   = filt->name;
      strval = filt->strval;
      sensitivity = TRUE;
    }
  }

  /* Did you know that this function is called when the window is destroyed? */
  /* Funny, that. */
  if (!in_cancel) {
    gtk_entry_set_text(GTK_ENTRY(name_te), name);
    gtk_entry_set_text(GTK_ENTRY(filter_te), strval);
    gtk_widget_set_sensitive(chg_bt, sensitivity);
    gtk_widget_set_sensitive(copy_bt, sensitivity);
    gtk_widget_set_sensitive(del_bt, sensitivity);
  }
}

/* To do: add input checking to each of these callbacks */
 
void
filter_sel_new_cb(GtkWidget *w, gpointer data) {
  GList      *nl = NULL;
  filter_def *filt;
  gchar      *name, *strval;
  GtkWidget  *nl_item, *nl_lb;
  
  name   = gtk_entry_get_text(GTK_ENTRY(name_te));
  strval = gtk_entry_get_text(GTK_ENTRY(filter_te));
  
  if (strlen(name) > 0 && strlen(strval) > 0) {
    filt         = (filter_def *) g_malloc(sizeof(filter_def));
    filt->name   = g_strdup(name);
    filt->strval = g_strdup(strval);
    fl           = g_list_append(fl, filt);
    nl_lb        = gtk_label_new(filt->name);
    nl_item      = gtk_list_item_new();
    gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
    gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
    gtk_widget_show(nl_lb);
    gtk_container_add(GTK_CONTAINER(filter_l), nl_item);
    gtk_widget_show(nl_item);
    gtk_object_set_data(GTK_OBJECT(nl_item), fl_key, nl_lb);
    gtk_object_set_data(GTK_OBJECT(nl_item), fn_key, g_list_last(fl));
  }
}

void
filter_sel_chg_cb(GtkWidget *w, gpointer data) {
  filter_def *filt;
  gchar      *name = "", *strval = "";
  GList      *sl, *flp;
  GtkObject  *l_item;
  GtkLabel   *nl_lb;
  gint        sensitivity = FALSE;

  sl     = GTK_LIST(filter_l)->selection;
  name   = gtk_entry_get_text(GTK_ENTRY(name_te));
  strval = gtk_entry_get_text(GTK_ENTRY(filter_te));

  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    flp    = (GList *) gtk_object_get_data(l_item, fn_key);
    nl_lb  = (GtkLabel *) gtk_object_get_data(l_item, fl_key);
    if (flp && nl_lb) {
      filt = (filter_def *) flp->data;
      
      if (strlen(name) > 0 && strlen(strval) > 0 && filt) {
        g_free(filt->name);
        g_free(filt->strval);
        filt->name   = g_strdup(name);
        filt->strval = g_strdup(strval);
        gtk_label_set(nl_lb, filt->name);
      }
    }
  }
}

void
filter_sel_copy_cb(GtkWidget *w, gpointer data) {
  GList      *nl = NULL, *sl, *flp;
  filter_def *filt, *nfilt;
  gchar      *name, *strval, *prefix = "Copy of ";
  GtkObject  *l_item;
  GtkWidget  *nl_item, *nl_lb;
  
  sl     = GTK_LIST(filter_l)->selection;
  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    flp    = (GList *) gtk_object_get_data(l_item, fn_key);
    if (flp) {
      filt          = (filter_def *) flp->data;
      nfilt         = (filter_def *) g_malloc(sizeof(filter_def));
      nfilt->name   = g_malloc(strlen(prefix) + strlen(filt->name) + 1);
      sprintf(nfilt->name, "%s%s", prefix, filt->name);
      nfilt->strval = g_strdup(filt->strval);
      fl            = g_list_append(fl, nfilt);
      nl_lb         = gtk_label_new(nfilt->name);
      nl_item       = gtk_list_item_new();
      gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
      gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
      gtk_widget_show(nl_lb);
      gtk_container_add(GTK_CONTAINER(filter_l), nl_item);
      gtk_widget_show(nl_item);
      gtk_object_set_data(GTK_OBJECT(nl_item), fl_key, nl_lb);
      gtk_object_set_data(GTK_OBJECT(nl_item), fn_key, g_list_last(fl));
    }
  }
}

void
filter_sel_del_cb(GtkWidget *w, gpointer data) {
  GList      *sl, *flp;
  filter_def *filt;
  GtkObject  *l_item;
  GtkWidget  *nl_item;
  gint        pos;
  
  sl = GTK_LIST(filter_l)->selection;
  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    pos    = gtk_list_child_position(GTK_LIST(filter_l),
      GTK_WIDGET(l_item));
    flp    = (GList *) gtk_object_get_data(l_item, fn_key);
    if (flp) {
      filt = (filter_def *) flp->data;
      g_free(filt->name);
      g_free(filt->strval);
      g_free(filt);
      fl = g_list_remove_link(fl, flp);
      gtk_list_clear_items(GTK_LIST(filter_l), pos, pos + 1);
    } 
  }
}

void
filter_sel_ok_cb(GtkWidget *w, gpointer data) {
  GList      *flp, *sl;
  GtkObject  *l_item;
  filter_def *filt;

  if (cf.filter) {
    g_free(cf.filter);
    cf.filter = NULL;
  }
    
  sl = GTK_LIST(filter_l)->selection;
  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    flp    = (GList *) gtk_object_get_data(l_item, fn_key);
    if (flp) {
      filt = (filter_def *) flp->data;
      cf.filter = g_strdup(filt->strval);
    }
  }

  filter_sel_cancel_cb(w, data);
}

void
filter_sel_save_cb(GtkWidget *w, gpointer data) {
  GList       *flp;
  filter_def  *filt;
  gchar       *ff_path, *ff_dir = ".ethereal", *ff_name = "filters";
  FILE        *ff;
  struct stat  s_buf;
  
  ff_path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(ff_dir) +  
    strlen(ff_name) + 4);
  sprintf(ff_path, "%s/%s", getenv("HOME"), ff_dir);

  if (stat(ff_path, &s_buf) != 0)
    mkdir(ff_path, 0755);
    
  sprintf(ff_path, "%s/%s/%s", getenv("HOME"), ff_dir, ff_name);

  if ((ff = fopen(ff_path, "w")) != NULL) {
    flp = g_list_first(fl);
    while (flp) {
      filt = (filter_def *) flp->data;
      fprintf(ff, "\"%s\" %s\n", filt->name, filt->strval);
      flp = flp->next;
    }
    fclose(ff);
  }

  g_free(ff_path);
}

void
filter_sel_cancel_cb(GtkWidget *w, gpointer win) {
  filter_def *filt;
  GList      *sl;
  
  while (fl) {
    if (fl->data) {
      filt = (filter_def *) fl->data;
      g_free(filt->name);
      g_free(filt->strval);
      g_free(filt);
    }
    fl = g_list_remove_link(fl, fl);
  }

  /* Let the list cb know we're about to destroy the widget tree, so it */
  /* doesn't operate on widgets that don't exist. */  
  in_cancel = TRUE;    
  gtk_widget_destroy(GTK_WIDGET(win));
} 
