/* prefs.c
 * Routines for handling preferences
 *
 * $Id: prefs.c,v 1.8 1998/10/28 21:38:09 gerald Exp $
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

#include "ethereal.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "print.h"
#include "filter.h"
#include "util.h"

/* Internal functions */
static int  set_prefs(gchar*, gchar*);
static void write_prefs();
static void prefs_main_ok_cb(GtkWidget *, gpointer);
static void prefs_main_save_cb(GtkWidget *, gpointer);
static void prefs_main_cancel_cb(GtkWidget *, gpointer);

e_prefs prefs;
static int init_prefs = 1;

#define PF_NAME ".ethereal/preferences"

static gchar *pf_path = NULL;

void
prefs_cb(GtkWidget *w, gpointer sp) {
  GtkWidget *prefs_w, *main_vb, *top_hb, *bbox, *prefs_nb,
            *ok_bt, *save_bt, *cancel_bt;
  GtkWidget *print_pg, *filter_pg, *filter_te, *label;
/*  GtkWidget *nlabel; */
  gint       start_page = (gint) sp;

  prefs_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(prefs_w), "Ethereal: Preferences");
  
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
  
  /* General prefs */
/*   nlabel = gtk_label_new("Nothing here yet...");
  gtk_widget_show (nlabel);

  label = gtk_label_new ("General");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), nlabel, label);
 */  
  /* Printing prefs */
  print_pg = printer_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY, print_pg);
  label = gtk_label_new ("Printing");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), print_pg, label);
    
  /* Filter prefs */
  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_FILT_TE_PTR_KEY);
  filter_pg = filter_prefs_show(filter_te);
  
  /* Pass along the entry widget pointer from the calling widget */
  gtk_object_set_data(GTK_OBJECT(filter_pg), E_FILT_TE_PTR_KEY, filter_te);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_FILTER_PAGE_KEY, filter_pg);
  label = gtk_label_new ("Filters");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), filter_pg, label);

  /* Jump to the specified page, if it was supplied */
  if (start_page > E_PR_PG_NONE)
    gtk_notebook_set_page(GTK_NOTEBOOK(prefs_nb), start_page);
    
  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);
  
  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_ok_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  save_bt = gtk_button_new_with_label ("Save");
  gtk_signal_connect_object(GTK_OBJECT(save_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_save_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(save_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), save_bt, TRUE, TRUE, 0);
  gtk_widget_show(save_bt);
  
  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect_object(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_cancel_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  gtk_widget_show(prefs_w);
}

void
prefs_main_ok_cb(GtkWidget *w, gpointer win) {
  
  printer_prefs_ok(gtk_object_get_data(GTK_OBJECT(win), E_PRINT_PAGE_KEY));
  filter_prefs_ok(gtk_object_get_data(GTK_OBJECT(win), E_FILTER_PAGE_KEY));
  gtk_widget_destroy(GTK_WIDGET(win));
}

void
prefs_main_save_cb(GtkWidget *w, gpointer win) {
  printer_prefs_save(gtk_object_get_data(GTK_OBJECT(win), E_PRINT_PAGE_KEY));
  filter_prefs_save(gtk_object_get_data(GTK_OBJECT(win), E_FILTER_PAGE_KEY));
  write_prefs();
}

void
prefs_main_cancel_cb(GtkWidget *w, gpointer win) {

  printer_prefs_cancel(gtk_object_get_data(GTK_OBJECT(win), E_PRINT_PAGE_KEY));
  filter_prefs_cancel(gtk_object_get_data(GTK_OBJECT(win), E_FILTER_PAGE_KEY));
  gtk_widget_destroy(GTK_WIDGET(win));
}

/* Preferences file format:
 * - Configuration directives start at the beginning of the line, and 
 *   are terminated with a colon.
 * - Directives can be continued on the next line by preceding them with
 *   whitespace.
 *
 * Example:

# This is a comment line
print.command: lpr
print.file: /a/very/long/path/
	to/ethereal-out.ps
 *
 */

#define MAX_VAR_LEN  32
#define MAX_VAL_LEN 256
void
read_prefs() {
  enum { START, IN_VAR, PRE_VAL, IN_VAL, IN_SKIP };
  FILE   *pf;
  gchar   cur_var[MAX_VAR_LEN], cur_val[MAX_VAL_LEN];
  int     got_c, state = START;
  gint    var_len = 0, val_len = 0, fline = 1, pline = 1;
  
  /* Initialize preferences.  With any luck, these values will be
     overwritten below. */
  if (init_prefs) {
    init_prefs      = 0;
    prefs.pr_format = PR_FMT_TEXT;
    prefs.pr_dest   = PR_DEST_CMD;
    prefs.pr_file   = g_strdup("ethereal.out");
    prefs.pr_cmd    = g_strdup("lpr");
  }

  if (! pf_path) {
    pf_path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(PF_NAME) + 4);
    sprintf(pf_path, "%s/%s", getenv("HOME"), PF_NAME);
  }
    
  if ((pf = fopen(pf_path, "r")) == NULL) {
    simple_dialog(ESD_TYPE_WARN, NULL,
      "Can't open preferences file\n\"%s\".");
    return;
  }
    
  while ((got_c = getc(pf)) != EOF) {
    if (got_c == '\n') {
      state = START;
      fline++;
      continue;
    }
    if (var_len >= MAX_VAR_LEN) {
      g_warning ("%s line %d: Variable too long", pf_path, fline);
      state = IN_SKIP;
      var_len = 0;
      continue;
    }
    if (val_len >= MAX_VAL_LEN) {
      g_warning ("%s line %d: Value too long", pf_path, fline);
      state = IN_SKIP;
      var_len = 0;
      continue;
    }
    
    switch (state) {
      case START:
        if (isalnum(got_c)) {
          state = IN_VAR;
          if (var_len > 0) {
            cur_var[var_len] = '\0';
            cur_val[val_len] = '\0';
            if (! set_pref(cur_var, cur_val))
              g_warning ("%s line %d: Bogus preference", pf_path, pline);
          }
          cur_var[0] = got_c;
          var_len = 1;
          pline = fline;
        } else if (isspace(got_c) && var_len > 0) {
          state = PRE_VAL;
        } else if (got_c == '#') {
          state = IN_SKIP;
        } else {
          g_warning ("%s line %d: Malformed line", pf_path, fline);
        }
        break;
      case IN_VAR:
        if (got_c != ':') {
          cur_var[var_len] = got_c;
          var_len++;
        } else {
          state = PRE_VAL;
          val_len = 0;
        }
        break;
      case PRE_VAL:
        if (!isspace(got_c)) {
          state = IN_VAL;
          cur_val[val_len] = got_c;
          val_len++;
        }
        break;
      case IN_VAL:
        cur_val[val_len] = got_c;
        val_len++;
        break;
    }
  }
  if (var_len > 0) {
    cur_var[var_len] = '\0';
    cur_val[val_len] = '\0';
    if (! set_pref(cur_var, cur_val))
      g_warning ("%s line %d: Bogus preference", pf_path, pline);
  }
  fclose(pf);
}

#define PRS_PRINT_FMT  "print.format"
#define PRS_PRINT_DEST "print.destination"
#define PRS_PRINT_FILE "print.file"
#define PRS_PRINT_CMD  "print.command"

static gchar *pr_formats[] = { "text", "postscript" };
static gchar *pr_dests[]   = { "command", "file" };

int
set_pref(gchar *pref, gchar *value) {

  if (strcmp(pref, PRS_PRINT_FMT) == 0) {
    if (strcmp(value, pr_formats[PR_FMT_TEXT]) == 0) {
      prefs.pr_format = PR_FMT_TEXT;
    } else if (strcmp(value, pr_formats[PR_FMT_PS]) == 0) {
      prefs.pr_format = PR_FMT_PS;
    } else {
      return 0;
    }
  } else if (strcmp(pref, PRS_PRINT_DEST) == 0) {
    if (strcmp(value, pr_dests[PR_DEST_CMD]) == 0) {
      prefs.pr_dest = PR_DEST_CMD;
    } else if (strcmp(value, pr_dests[PR_DEST_FILE]) == 0) {
      prefs.pr_dest = PR_DEST_FILE;
    } else {
      return 0;
    }
  } else if (strcmp(pref, PRS_PRINT_FILE) == 0) {
    if (prefs.pr_file) g_free(prefs.pr_file);
    prefs.pr_file = g_strdup(value);
  } else if (strcmp(pref, PRS_PRINT_CMD) == 0) {
    if (prefs.pr_cmd) g_free(prefs.pr_cmd);
    prefs.pr_cmd = g_strdup(value);
  } else {
    return 0;
  }
  
  return 1;
}

void
write_prefs() {
  FILE   *pf;
  
  /* To do: Split output lines longer than MAX_VAL_LEN */

  if (! pf_path) {
    pf_path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(PF_NAME) + 4);
    sprintf(pf_path, "%s/%s", getenv("HOME"), PF_NAME);
  }
    
  if ((pf = fopen(pf_path, "w")) == NULL) {
     simple_dialog(ESD_TYPE_WARN, NULL,
      "Can't open preferences file\n\"%s\".");
   return;
 }
    
  fputs("# Configuration file for Ethereal " VERSION ".\n"
    "#\n"
    "# This file is regenerated each time preferences are saved within\n"
    "# Ethereal.  Making manual changes should be safe, however.\n"
    "\n"
    "######## Printing ########\n"
    "\n", pf);

  fprintf (pf, "# Can be one of \"text\" or \"postscript\".\n"
    "print.format: %s\n\n", pr_formats[prefs.pr_format]);

  fprintf (pf, "# Can be one of \"command\" or \"file\".\n"
    "print.destination: %s\n\n", pr_dests[prefs.pr_dest]);

  fprintf (pf, "# This is the file that gets written to when the "
    "destination is set to \"file\"\n"
    "%s: %s\n\n", PRS_PRINT_FILE, prefs.pr_file);

  fprintf (pf, "# Output gets piped to this command when the destination "
    "is set to \"command\"\n"
    "%s: %s\n", PRS_PRINT_CMD, prefs.pr_cmd);

  fclose(pf);
}
