/* prefs_dlg.c
 * Routines for handling preferences
 *
 * $Id: prefs_dlg.c,v 1.15 2000/07/09 03:29:42 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/stat.h>

#include "main.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "column_prefs.h"
#include "print.h"
#include "prefs_dlg.h"
#include "print_prefs.h"
#include "stream_prefs.h"
#include "gui_prefs.h"
#include "util.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "simple_dialog.h"

#include "prefs-int.h"

static void     prefs_main_ok_cb(GtkWidget *, gpointer);
static void     prefs_main_save_cb(GtkWidget *, gpointer);
static void     prefs_main_cancel_cb(GtkWidget *, gpointer);
static gboolean prefs_main_delete_cb(GtkWidget *, gpointer);
static void     prefs_main_destroy_cb(GtkWidget *, gpointer);

#define E_PRINT_PAGE_KEY  "printer_options_page"
#define E_COLUMN_PAGE_KEY "column_options_page"
#define E_STREAM_PAGE_KEY "tcp_stream_options_page"
#define E_GUI_PAGE_KEY	  "gui_options_page"

/*
 * Keep a static pointer to the current "Preferences" window, if any, so that
 * if somebody tries to do "Edit:Preferences" while there's already a
 * "Preferences" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *prefs_w;

static void
pref_show(pref_t *pref, gpointer user_data)
{
  GtkWidget *main_tb = user_data;
  const char *title;
  char *label_string;
  GtkWidget *label, *menu, *menu_item, *widget, *button;
  GSList *rb_group;
  char uint_str[10+1];
  const enum_val *enum_valp;
  int menu_index, index;

  /* Give this preference a label which is its title, followed by a colon,
     and left-align it. */
  title = pref->title;
  label_string = g_malloc(strlen(title) + 2);
  strcpy(label_string, title);
  strcat(label_string, ":");
  label = gtk_label_new(label_string);
  g_free(label_string);
  gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);

  /* Attach it to the table. */
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, pref->ordinal,
				pref->ordinal+1);

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
    widget = gtk_entry_new();
    switch (pref->info.base) {

    case 10:
      sprintf(uint_str, "%u", pref->saved_val.uint);
      break;

    case 8:
      sprintf(uint_str, "%o", pref->saved_val.uint);
      break;

    case 16:
      sprintf(uint_str, "%x", pref->saved_val.uint);
      break;
    }
    gtk_entry_set_text(GTK_ENTRY(widget), uint_str);
    pref->control = widget;
    break;

  case PREF_BOOL:
    pref->saved_val.bool = *pref->varp.bool;
    widget = gtk_check_button_new();
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(widget), pref->saved_val.bool);
    pref->control = widget;
    break;

  case PREF_ENUM:
    pref->saved_val.enumval = *pref->varp.enump;
    if (pref->info.enum_info.radio_buttons) {
      /* Show it as radio buttons. */
      widget = gtk_hbox_new(FALSE, 0);
      rb_group = NULL;
      for (enum_valp = pref->info.enum_info.enumvals, index = 0;
		enum_valp->name != NULL; enum_valp++, index++) {
	button = gtk_radio_button_new_with_label(rb_group, enum_valp->name);
	if (rb_group == NULL)
	  rb_group = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_box_pack_start(GTK_BOX(widget), button, FALSE, FALSE, 10);
	if (enum_valp->value == pref->saved_val.enumval)
	  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	pref->control = button;
      }
    } else {
      /* Show it as an option menu. */
      menu = gtk_menu_new();
      menu_index = -1;
      for (enum_valp = pref->info.enum_info.enumvals, index = 0;
		enum_valp->name != NULL; enum_valp++, index++) {
	menu_item = gtk_menu_item_new_with_label(enum_valp->name);
	gtk_menu_append(GTK_MENU(menu), menu_item);
	if (enum_valp->value == pref->saved_val.enumval)
	  menu_index = index;
      }

      /* Create the option menu from the option */
      widget = gtk_option_menu_new();
      gtk_option_menu_set_menu(GTK_OPTION_MENU(widget), menu);

      /* Set its current value to the variable's current value */
      if (menu_index != -1)
        gtk_option_menu_set_history(GTK_OPTION_MENU(widget), menu_index);
      pref->control = widget;
    }
    break;

  case PREF_STRING:
    widget = gtk_entry_new();
    if (pref->saved_val.string != NULL)
      g_free(pref->saved_val.string);
    pref->saved_val.string = g_strdup(*pref->varp.string);
    gtk_entry_set_text(GTK_ENTRY(widget), pref->saved_val.string);
    pref->control = widget;
    break;

  default:
    g_assert_not_reached();
    widget = NULL;
    break;
  }

  gtk_table_attach_defaults(GTK_TABLE(main_tb), widget, 1, 2, pref->ordinal,
				pref->ordinal+1);
}

static void
module_prefs_show(module_t *module, gpointer user_data)
{
  GtkWidget *prefs_nb = user_data;
  GtkWidget *main_vb, *main_tb, *label;

  /* Main vertical box */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

  /* Main table */
  main_tb = gtk_table_new(module->numprefs, 2, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);

  /* Add items for each of the preferences */
  prefs_pref_foreach(module, pref_show, main_tb);

  label = gtk_label_new(module->title);
  gtk_notebook_append_page(GTK_NOTEBOOK(prefs_nb), main_vb, label);

  /* Show 'em what we got */
  gtk_widget_show_all(main_vb);
}

void
prefs_cb(GtkWidget *w, gpointer dummy) {
  GtkWidget *main_vb, *top_hb, *bbox, *prefs_nb,
            *ok_bt, *save_bt, *cancel_bt;
  GtkWidget *print_pg, *column_pg, *stream_pg, *gui_pg, *label;

  if (prefs_w != NULL) {
    /* There's already a "Preferences" dialog box; reactivate it. */
    reactivate_window(prefs_w);
    return;
  }

  prefs_w = dlg_window_new();
  gtk_window_set_title(GTK_WINDOW(prefs_w), "Ethereal: Preferences");
  gtk_signal_connect(GTK_OBJECT(prefs_w), "delete-event",
    GTK_SIGNAL_FUNC(prefs_main_delete_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(prefs_w), "destroy",
	GTK_SIGNAL_FUNC(prefs_main_destroy_cb), NULL);
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(prefs_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Top row: Preferences notebook */
  top_hb = gtk_hbox_new(FALSE, 1);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  prefs_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), prefs_nb);
  gtk_widget_show(prefs_nb);
  
  /* Printing prefs */
  print_pg = printer_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY, print_pg);
  label = gtk_label_new ("Printing");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), print_pg, label);
    
  /* Column prefs */
  column_pg = column_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_COLUMN_PAGE_KEY, column_pg);
  label = gtk_label_new ("Columns");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), column_pg, label);
  
  /* TCP Streams prefs */
  stream_pg = stream_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_STREAM_PAGE_KEY, stream_pg);
  label = gtk_label_new ("TCP Streams");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), stream_pg, label);

  /* GUI prefs */
  gui_pg = gui_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_GUI_PAGE_KEY, gui_pg);
  label = gtk_label_new ("GUI");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), gui_pg, label);

  /* Registered prefs */
  prefs_module_foreach(module_prefs_show, prefs_nb);

  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);
  
  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_ok_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  save_bt = gtk_button_new_with_label ("Save");
  gtk_signal_connect(GTK_OBJECT(save_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_save_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(save_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), save_bt, TRUE, TRUE, 0);
  gtk_widget_show(save_bt);
  
  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_cancel_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(prefs_w, cancel_bt);

  gtk_widget_show(prefs_w);
}

static void
pref_fetch(pref_t *pref, gpointer user_data)
{
  GtkWidget *label;
  char *label_string;
  char *str_val;
  char *p;
  guint uval;
  gboolean bval;
  GSList *rb_entry;
  GtkWidget *button;
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
    if (*pref->varp.bool != bval) {
      *pref_changed_p = TRUE;
      *pref->varp.bool = bval;
    }
    break;

  case PREF_ENUM:
    if (pref->info.enum_info.radio_buttons) {
      /* Go through the list of of radio buttons in the group, and find
         the first one that's active. */
      button = NULL;
      for (rb_entry = gtk_radio_button_group(GTK_RADIO_BUTTON(pref->control));
		rb_entry != NULL;
		rb_entry = g_slist_next(rb_entry)) {
	button = rb_entry->data;
	if (GTK_TOGGLE_BUTTON(button)->active)
	  break;
      }
      /* OK, now find that button's label. */
      label = GTK_BIN(button)->child;
    } else {
      /* Get the label for the currently active entry in the option menu.
         Yes, this is how you do it.  See FAQ 6.8 in the GTK+ FAQ. */
      label = GTK_BIN(pref->control)->child;
    }

    /* Get the label, and translate it to a value. */
    gtk_label_get(GTK_LABEL(label), &label_string);
    enumval = find_val_for_string(label_string,
					pref->info.enum_info.enumvals, 1);
    if (*pref->varp.enump != enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = enumval;
    }
    break;

  case PREF_STRING:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    if (*pref->varp.string == NULL || strcmp(*pref->varp.string, str_val) != 0) {
      *pref_changed_p = TRUE;
      if (*pref->varp.string != NULL)
        g_free(*pref->varp.string);
      *pref->varp.string = g_strdup(str_val);
    }
    break;
  }
}

static void
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
}

static void
pref_clean(pref_t *pref, gpointer user_data)
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
  }
}

static void
module_prefs_clean(module_t *module, gpointer user_data)
{
  /* For all preferences in this module, clean up any cruft allocated for
     use by the GUI code. */
  prefs_pref_foreach(module, pref_clean, NULL);
}

static void
prefs_main_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  printer_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  prefs_module_foreach(module_prefs_fetch, &must_redissect);
  prefs_apply_all();
  prefs_module_foreach(module_prefs_clean, NULL);
  gtk_widget_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets(&cfile);
  }
}

static void
prefs_main_save_cb(GtkWidget *save_bt, gpointer parent_w)
{
  int err;
  char *pf_path;

  printer_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  prefs_module_foreach(module_prefs_fetch, NULL);
  err = write_prefs(&pf_path);
  if (err != 0) {
     simple_dialog(ESD_TYPE_WARN, NULL,
      "Can't open preferences file\n\"%s\": %s.", pf_path,
      strerror(err));
  }
}

static void
pref_revert(pref_t *pref, gpointer user_data)
{
  /* Fetch the value of the preference, and set the appropriate variable
     to it. */
  switch (pref->type) {

  case PREF_UINT:
    *pref->varp.uint = pref->saved_val.uint;
    break;

  case PREF_BOOL:
    *pref->varp.bool = pref->saved_val.bool;
    break;

  case PREF_ENUM:
    *pref->varp.enump = pref->saved_val.enumval;
    break;

  case PREF_STRING:
    if (*pref->varp.string != NULL)
      g_free(*pref->varp.string);
    *pref->varp.string = g_strdup(pref->saved_val.string);
    break;
  }
}

static void
module_prefs_revert(module_t *module, gpointer user_data)
{
  /* For all preferences in this module, revert its value to the value
     it had when we popped up the Preferences dialog. */
  prefs_pref_foreach(module, pref_revert, NULL);
}

static void
prefs_main_cancel_cb(GtkWidget *cancel_bt, gpointer parent_w)
{
  printer_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  prefs_module_foreach(module_prefs_revert, NULL);
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static gboolean
prefs_main_delete_cb(GtkWidget *prefs_w, gpointer dummy)
{
  printer_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY));
  column_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_COLUMN_PAGE_KEY));
  stream_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_STREAM_PAGE_KEY));
  gui_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_GUI_PAGE_KEY));
  return FALSE;
}

static void
prefs_main_destroy_cb(GtkWidget *win, gpointer user_data)
{
  /* XXX - call the delete callback?  Or move its stuff here and
     get rid of it? */

  /* Note that we no longer have a "Preferences" dialog box. */
  prefs_w = NULL;
}
