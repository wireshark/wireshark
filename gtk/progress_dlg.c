/* progress_dlg.c
 * Routines for progress-bar (modal) dialog
 *
 * $Id: progress_dlg.c,v 1.3 2000/07/05 02:45:41 guy Exp $
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

#include "gtkglobals.h"
#include "dlg_utils.h"
#include "ui_util.h"

#define	PROG_BAR_KEY	"progress_bar"

static void delete_cb(GtkWidget *w, GdkEvent *event, gpointer data);
static void cancel_cb(GtkWidget *w, gpointer data);

/*
 * Create and pop up the progress dialog; return a pointer to it, as
 * a "void *", so that our caller doesn't have to know the GUI
 * implementation.
 *
 * The first argument is the title to give the dialog box; the second
 * argument is a pointer to a Boolean variable that will be set to
 * TRUE if the user hits the "Cancel" button.
 *
 * XXX - should the button say "Cancel", or "Stop"?
 *
 * XXX - provide a way to specify the progress in units, with the total
 * number of units specified as an argument when the progress dialog
 * is created; updates would be given in units, with the progress dialog
 * code computing the percentage, and the progress bar would have a
 * label "0" on the left and <total number of units> on the right, with
 * a label in the middle giving the number of units we've processed
 * so far.  This could be used when filtering packets, for example; we
 * wouldn't always use it, as we have no idea how many packets are to
 * be read.
 */
void *
create_progress_dlg(gchar *title, gboolean *stop_flag)
{
	GtkWidget *dlg_w, *main_vb, *title_lb, *prog_bar, *cancel_al,
		  *cancel_bt;

	dlg_w = dlg_window_new();
	gtk_window_set_title(GTK_WINDOW(dlg_w), title);

	/*
	 * Container for dialog widgets.
	 */
	main_vb = gtk_vbox_new(FALSE, 1);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_container_add(GTK_CONTAINER(dlg_w), main_vb);
	gtk_widget_show(main_vb);

	/*
	 * Put the title here as a label indicating what we're
	 * doing; set its alignment and padding so it's aligned on the
	 * left.
	 */
	title_lb = gtk_label_new(title);
	gtk_box_pack_start(GTK_BOX(main_vb), title_lb, FALSE, TRUE, 3);
	gtk_misc_set_alignment(GTK_MISC(title_lb), 0.0, 0.0);
	gtk_misc_set_padding(GTK_MISC(title_lb), 0.0, 0.0);
	gtk_widget_show(title_lb);

	/*
	 * The progress bar.
	 */
	prog_bar = gtk_progress_bar_new();
	gtk_progress_set_activity_mode(GTK_PROGRESS(prog_bar), FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), prog_bar, FALSE, TRUE, 3);
	gtk_widget_show(prog_bar);

	/*
	 * Attach a pointer to the progress bar widget to the top-level
	 * widget.
	 */
	gtk_object_set_data(GTK_OBJECT(dlg_w), PROG_BAR_KEY, prog_bar);

	/*
	 * Allow user to either click a "Cancel" button, or the close button
	 * on the window, to stop an operation in progress.
	 *
	 * Put the button in an alignment so it doesn't get any wider than
	 * it needs to to say "Cancel".
	 */
	cancel_al = gtk_alignment_new(0.5, 0.0, 0.0, 0.0);
	cancel_bt = gtk_button_new_with_label("Cancel");
	gtk_container_add(GTK_CONTAINER(cancel_al), cancel_bt);
	gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
	    GTK_SIGNAL_FUNC(cancel_cb), (gpointer) stop_flag);
	gtk_signal_connect(GTK_OBJECT(dlg_w), "delete_event",
	    GTK_SIGNAL_FUNC(delete_cb), (gpointer) stop_flag);
	gtk_box_pack_end(GTK_BOX(main_vb), cancel_al, FALSE, FALSE, 3);
	GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(cancel_bt);
	GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(cancel_bt);
	gtk_widget_show(cancel_bt);
	gtk_widget_show(cancel_al);

	gtk_widget_show(dlg_w);
	gtk_grab_add(dlg_w);		/* make it modal */

	return dlg_w;	/* return as opaque pointer */
}

/*
 * Called when the dialog box is to be deleted.
 * We just treat this the same way we treat clicking the "Cancel" button.
 */
static void
delete_cb(GtkWidget *w, GdkEvent *event, gpointer data)
{
	cancel_cb(NULL, data);
}

/*
 * Called when the "Cancel" button is clicked.
 * Set the Boolean to TRUE.
 */
static void
cancel_cb(GtkWidget *w, gpointer data)
{
	gboolean *stop_flag = (gboolean *) data;
	GtkWidget *toplevel;
  
	*stop_flag = TRUE;
	if (w != NULL) {
		/*
		 * The cancel button was clicked, so we have to destroy
		 * the dialog box ourselves.
		 */
		toplevel = gtk_widget_get_toplevel(w);
		destroy_progress_dlg(toplevel);
	}
}

/*
 * Set the percentage value of the progress bar.
 */
void
update_progress_dlg(void *dlg, gfloat percentage)
{
	GtkWidget *dlg_w = dlg;
	GtkWidget *prog_bar;

	prog_bar = gtk_object_get_data(GTK_OBJECT(dlg_w), PROG_BAR_KEY);
	gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar), percentage);

	/*
	 * Flush out the update and process any input events.
	 */
	while (gtk_events_pending())
		gtk_main_iteration();
}

/*
 * Destroy the progress bar.
 */
void
destroy_progress_dlg(void *dlg)
{
	GtkWidget *dlg_w = dlg;

	gtk_grab_remove(GTK_WIDGET(dlg_w));
	gtk_widget_destroy(GTK_WIDGET(dlg_w));
}
