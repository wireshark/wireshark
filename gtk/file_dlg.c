#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <string.h>

#ifndef __GLOBALS_H__
#include "globals.h"
#endif

#ifndef __KEYS_H__
#include "keys.h"
#endif

#ifndef __PREFS_DLG_H__
#include "prefs_dlg.h"
#endif

#ifndef __UTIL_H__
#include "util.h"
#endif

#ifndef __MENU_H__
#include "menu.h"
#endif

static void file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);

/* Open a file */
void
file_open_cmd_cb(GtkWidget *w, gpointer data) {
  GtkWidget *filter_hbox, *filter_bt, *filter_te;

  if (last_open_dir)
	  chdir(last_open_dir);

  file_sel = gtk_file_selection_new ("Ethereal: Open Capture File");
  
  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_open_ok_cb, file_sel );

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
      E_DFILTER_TE_KEY, gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY));

  filter_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_sel)->action_area),
    filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_cb), (gpointer) E_PR_PG_FILTER);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
    E_RFILTER_TE_KEY, filter_te);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

#ifdef HAVE_LIBPCAP
  if( fork_mode && (cf.save_file != NULL) )
#else
  if( cf.save_file != NULL )
#endif
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), cf.save_file);
  else
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");

  gtk_widget_show(file_sel);
}

static void
file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name, *rfilter, *s;
  GtkWidget *filter_te;
  dfilter   *rfcode = NULL;
  int        err;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_RFILTER_TE_KEY);
  rfilter = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (rfilter[0] != '\0') {
	rfcode = dfilter_new();
	if (dfilter_compile(rfcode, rfilter) != 0) {
		simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
		dfilter_destroy(rfcode);
		return;
	}
  }

  /* Try to open the capture file. */
  if ((err = open_cap_file(cf_name, &cf)) != 0) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_destroy(rfcode);
    return;
  }

  /* Attach the new read filter to "cf" ("open_cap_file()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cf.rfcode = rfcode;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  err = read_cap_file(&cf);
  /* Save the directory name; we can write over cf_name. */
  s = strrchr(cf_name, '/');
  if (s && last_open_dir) {
	  *s = '\0';
	  if (strcmp(last_open_dir, cf_name) != 0) {
		  g_free(last_open_dir);
		  last_open_dir = g_strdup(cf_name);
	  }
  }
  else if (s) { /* ! last_open_dir */
	  *s = '\0';
	  last_open_dir = g_strdup(cf_name);
  }
  else {
	  last_open_dir = NULL;
  }
  set_menu_sensitivity("/File/Save", FALSE);
  set_menu_sensitivity("/File/Save As...", TRUE);
  g_free(cf_name);
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget, gpointer data) {
  close_cap_file(&cf, info_bar, file_ctx);
}

void
file_save_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File");
 
  /* Connect the ok_button to file_save_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_save_ok_cb, file_sel );

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");

  gtk_widget_show(file_sel);
}

void
file_save_as_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File As");

  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_save_as_ok_cb, file_sel );

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");
  gtk_widget_show(file_sel);
}

static void
file_save_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
	gchar	*cf_name;
	int	err;

	cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
	gtk_widget_hide(GTK_WIDGET (fs));
	gtk_widget_destroy(GTK_WIDGET (fs));

	if (!file_mv(cf.save_file, cf_name))
		return;

	g_free(cf.save_file);
	cf.save_file = g_strdup(cf_name);
	cf.user_saved = 1;
        if ((err = open_cap_file(cf_name, &cf)) == 0) {
		err = read_cap_file(&cf);
		set_menu_sensitivity("/File/Save", FALSE);
		set_menu_sensitivity("/File/Save As...", TRUE);
	}
}

static void
file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
	gchar	*cf_name;
	int	err;

	cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
	gtk_widget_hide(GTK_WIDGET (fs));
	gtk_widget_destroy(GTK_WIDGET (fs));
	if (!file_cp(cf.filename, cf_name))
		return;
	g_free(cf.filename);
	cf.filename = g_strdup(cf_name);
	cf.user_saved = 1;
        if ((err = open_cap_file(cf.filename, &cf)) == 0) {
		err = read_cap_file(&cf);
		set_menu_sensitivity("/File/Save", FALSE);
		set_menu_sensitivity("/File/Save As...", TRUE);
	}
}

/* Reload a file using the current read and display filters */
void
file_reload_cmd_cb(GtkWidget *w, gpointer data) {
  /*GtkWidget *filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);*/
  GtkWidget *filter_te;

  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

  if (cf.dfilter) g_free(cf.dfilter);
  cf.dfilter = g_strdup(gtk_entry_get_text(GTK_ENTRY(filter_te)));
  if (open_cap_file(cf.filename, &cf) == 0)
    read_cap_file(&cf);
  /* XXX - change the menu if the open fails? */
}

