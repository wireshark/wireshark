/* print.c
 * Routines for printing packet analysis trees.
 *
 * $Id: print.c,v 1.4 1998/09/27 22:12:44 gerald Exp $
 *
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "print.h"
#include "ps.h"

static void printer_opts_file_cb(GtkWidget *w, gpointer te);
static void printer_opts_fs_cancel_cb(GtkWidget *w, gpointer data);
static void printer_opts_fs_ok_cb(GtkWidget *w, gpointer data);
static void printer_opts_toggle_format(GtkWidget *widget, gpointer data);
static void printer_opts_toggle_dest(GtkWidget *widget, gpointer data);
static void dumpit (FILE *fh, register const u_char *cp, register u_int length);
static void dumpit_ps (FILE *fh, register const u_char *cp, register u_int length);
static void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size);

/* #include "ps.c" */

pr_opts printer_opts;

/* Key for gtk_object_set_data */
const gchar *print_opt_key = "printer_options_data";
GtkWidget * printer_opts_pg()
{
	GtkWidget	*main_vb, *button;
	GtkWidget	*format_hb, *format_lb;
	GtkWidget	*dest_hb, *dest_lb;
	GtkWidget	*cmd_hb, *cmd_lb, *cmd_te;
	GtkWidget	*file_hb, *file_bt, *file_te;
	GtkWidget	*bbox, *ok_bt, *cancel_bt;
	GSList		*format_grp, *dest_grp;
	pr_opts		*temp_pr_opts = g_malloc(sizeof(pr_opts));

	/* Make a working copy of the printer data */
	memcpy(temp_pr_opts, &printer_opts, sizeof(pr_opts));
/*	temp_pr_opts->cmd = g_strdup(printer_opts->cmd);
	temp_pr_opts->file = g_strdup(printer_opts->file);*/

	/* Container for each row of widgets */
	main_vb = gtk_vbox_new(FALSE, 3);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_widget_show(main_vb);
        gtk_object_set_data(GTK_OBJECT(main_vb), print_opt_key,
          temp_pr_opts);

	/* Output format */
	format_hb = gtk_hbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(main_vb), format_hb);
	gtk_widget_show(format_hb);

	format_lb = gtk_label_new("Format:");
	gtk_box_pack_start(GTK_BOX(format_hb), format_lb, FALSE, FALSE, 3);
	gtk_widget_show(format_lb);

	button = gtk_radio_button_new_with_label(NULL, "Plain Text");
	if (printer_opts.output_format == 0) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_box_pack_start(GTK_BOX(format_hb), button, TRUE, TRUE, 0);
	gtk_widget_show(button);

	button = gtk_radio_button_new_with_label(format_grp, "PostScript");
	if (printer_opts.output_format == 1) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	gtk_signal_connect(GTK_OBJECT(button), "toggled",
			GTK_SIGNAL_FUNC(printer_opts_toggle_format),
			(gpointer)temp_pr_opts);
	gtk_box_pack_start(GTK_BOX(format_hb), button, TRUE, TRUE, 0);
	gtk_widget_show(button);

	/* Output destination */
	dest_hb = gtk_hbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(main_vb), dest_hb);
	gtk_widget_show(dest_hb);

	dest_lb = gtk_label_new("Print to:");
	gtk_box_pack_start(GTK_BOX(dest_hb), dest_lb, FALSE, FALSE, 3);
	gtk_widget_show(dest_lb);

	button = gtk_radio_button_new_with_label(NULL, "Command");
	if (printer_opts.output_dest == 0) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	dest_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	gtk_box_pack_start(GTK_BOX(dest_hb), button, TRUE, TRUE, 0);
	gtk_widget_show(button);

	button = gtk_radio_button_new_with_label(dest_grp, "File");
	if (printer_opts.output_dest == 1) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	gtk_signal_connect(GTK_OBJECT(button), "toggled",
			GTK_SIGNAL_FUNC(printer_opts_toggle_dest),
			(gpointer)temp_pr_opts);
	gtk_box_pack_start(GTK_BOX(dest_hb), button, TRUE, TRUE, 0);
	gtk_widget_show(button);

	/* Command text entry */
	cmd_hb = gtk_hbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(main_vb), cmd_hb);
	gtk_widget_show(cmd_hb);

	cmd_lb = gtk_label_new("Command:");
	gtk_box_pack_start(GTK_BOX(cmd_hb), cmd_lb, FALSE, FALSE, 3);
	gtk_widget_show(cmd_lb);

	cmd_te = gtk_entry_new();
	temp_pr_opts->cmd_te = cmd_te;
	gtk_entry_set_text(GTK_ENTRY(cmd_te), printer_opts.cmd);
	gtk_box_pack_start(GTK_BOX(cmd_hb), cmd_te, TRUE, TRUE, 3);
	gtk_widget_show(cmd_te);

	/* File button and text entry */
	file_hb = gtk_hbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(main_vb), file_hb);
	gtk_widget_show(file_hb);

	file_bt = gtk_button_new_with_label("File:");
	gtk_box_pack_start(GTK_BOX(file_hb), file_bt, FALSE, FALSE, 3);
	gtk_widget_show(file_bt);

	file_te = gtk_entry_new();
	temp_pr_opts->file_te = file_te;
	gtk_entry_set_text(GTK_ENTRY(file_te), printer_opts.file);
	gtk_box_pack_start(GTK_BOX(file_hb), file_te, TRUE, TRUE, 3);
	gtk_widget_show(file_te);

	gtk_signal_connect_object(GTK_OBJECT(file_bt), "clicked",
			GTK_SIGNAL_FUNC(printer_opts_file_cb), GTK_OBJECT(file_te));


	/* Button row: OK and cancel buttons */
/* 	bbox = gtk_hbutton_box_new();
	gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
	gtk_container_add(GTK_CONTAINER(main_vb), bbox);
	gtk_widget_show(bbox);

	ok_bt = gtk_button_new_with_label ("OK");
	gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		GTK_SIGNAL_FUNC(printer_opts_ok_cb), (gpointer)temp_pr_opts);
	gtk_container_add(GTK_CONTAINER(bbox), ok_bt);
	gtk_widget_show(ok_bt);

	cancel_bt = gtk_button_new_with_label ("Cancel");
	gtk_signal_connect_object(GTK_OBJECT(cancel_bt), "clicked",
		GTK_SIGNAL_FUNC(printer_opts_close_cb), (gpointer)temp_pr_opts);
	gtk_container_add(GTK_CONTAINER(bbox), cancel_bt);
	gtk_widget_show(cancel_bt);

 */
 
   return(main_vb);
}


static void
printer_opts_file_cb(GtkWidget *w, gpointer te) {
  GtkWidget *fs, **w_list;

  w_list = g_malloc(2 * sizeof(GtkWidget *));
  
  fs = gtk_file_selection_new ("Ethereal: Print to a File");
  w_list[0] = fs;
  w_list[1] = (GtkWidget *) te;

  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) printer_opts_fs_ok_cb, w_list);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) printer_opts_fs_cancel_cb, w_list);

  gtk_widget_show(fs);
}

static void
printer_opts_fs_ok_cb(GtkWidget *w, gpointer data) {
	GtkWidget **w_list = (GtkWidget **) data;
	  
	gtk_entry_set_text(GTK_ENTRY(w_list[1]),
		gtk_file_selection_get_filename (GTK_FILE_SELECTION(w_list[0])));
	printer_opts_fs_cancel_cb(w, data);
}

static void
printer_opts_fs_cancel_cb(GtkWidget *w, gpointer data) {
	GtkWidget **w_list = (GtkWidget **) data;
	  
	gtk_widget_destroy(w_list[0]);
	g_free(data);
} 

void
printer_opts_ok(GtkWidget *w)
{
	pr_opts *data = gtk_object_get_data(GTK_OBJECT(w), print_opt_key);
        
	printer_opts.output_format = ((pr_opts*)data)->output_format;
	printer_opts.output_dest = ((pr_opts*)data)->output_dest;

	free(printer_opts.cmd);
	printer_opts.cmd =
		g_strdup(gtk_entry_get_text(GTK_ENTRY(((pr_opts*)data)->cmd_te)));

	free(printer_opts.file);
	printer_opts.file =
		g_strdup(gtk_entry_get_text(GTK_ENTRY(((pr_opts*)data)->file_te)));

	g_free(data);
}

void
printer_opts_close(GtkWidget *w)
{
	pr_opts *data = gtk_object_get_data(GTK_OBJECT(w), print_opt_key);
        
	g_free(data);
}

static void
printer_opts_toggle_format(GtkWidget *widget, gpointer data)
{
		if (GTK_TOGGLE_BUTTON (widget)->active) {
			((pr_opts*)data)->output_format = 1;
			/* toggle file/cmd */
		}
		else {
			((pr_opts*)data)->output_format = 0;
			/* toggle file/cmd */
		}
}

static void
printer_opts_toggle_dest(GtkWidget *widget, gpointer data)
{
		if (GTK_TOGGLE_BUTTON (widget)->active) {
			((pr_opts*)data)->output_dest = 1;
		}
		else {
			((pr_opts*)data)->output_dest = 0;
		}
}

/* ========================================================== */
void print_tree(const u_char *pd, frame_data *fd, GtkTree *tree)
{
	FILE	*fh;
	char	*out;

	/* Open the file or command for output */
	if (printer_opts.output_dest == 0) {
		out = printer_opts.cmd;
		fh = popen(printer_opts.cmd, "w");
	}
	else {
		out = printer_opts.file;
		fh = fopen(printer_opts.file, "w");
	}

	if (!fh) {
		g_error("Cannot open %s for output.\n", out);
		return;
	}

	/* Create the output */
	if (printer_opts.output_format == 0) {
		print_tree_text(fh, pd, fd, tree);
	}
	else {
		print_ps_preamble(fh);
		print_tree_ps(fh, pd, fd, tree);
		print_ps_finale(fh);
	}

	/* Close the file or command */
	if (printer_opts.output_dest == 0) {
		pclose(fh);
	}
	else {
		fclose(fh);
	}
}

/* Print a tree's data in plain text */
void print_tree_text(FILE *fh, const u_char *pd, frame_data *fd, GtkTree *tree)
{
	GList		*children, *child, *widgets, *label;
	GtkWidget	*subtree;
	int		 num_children, i;
	char		*text;
	int		 num_spaces;
	char		space[41];
	gint		data_start, data_len;

	/* Prepare the tabs for printing, depending on tree level */
	num_spaces = tree->level * 4;
	if (num_spaces > 40) {
		num_spaces = 40;
	}
	for (i = 0; i < num_spaces; i++) {
		space[i] = ' ';
	}
	/* The string is NUL-terminated */
	space[num_spaces] = 0;

	/* Get the children of this tree */
	children = tree->children;
	num_children = g_list_length(children);

	for (i = 0; i < num_children; i++) {
		/* Each child of the tree is a widget container */
		child = g_list_nth(children, i);
		widgets = gtk_container_children(GTK_CONTAINER(child->data));

		/* And the container holds a label object, which holds text */
		label = g_list_nth(widgets, 0);
		gtk_label_get(GTK_LABEL(label->data), &text);

		/* Print the text */
		fprintf(fh, "%s%s\n", space, text);

		/* Recurse into the subtree, if it exists */
		subtree = (GTK_TREE_ITEM(child->data))->subtree;
		if (subtree) {
				print_tree_text(fh, pd, fd, GTK_TREE(subtree));
		}
		else if (strcmp("Data", text) == 0) {
			decode_start_len(GTK_TREE_ITEM(child->data), &data_start, &data_len);
			dumpit(fh, &pd[data_start], data_len);
		}
	}
}

/* This routine was created by Dan Lasley <DLASLEY@PROMUS.com>, and
only slightly modified for ethereal by Gilbert Ramirez. */
static
void dumpit (FILE *fh, register const u_char *cp, register u_int length)
{
        register int ad, i, j, k;
        u_char c;
        u_char line[60];
		static u_char binhex[16] = {
			'0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        memset (line, ' ', sizeof line);
        line[sizeof (line)-1] = 0;
        for (ad=i=j=k=0; i<length; i++) {
                c = *cp++;
                line[j++] = binhex[c>>4];
                line[j++] = binhex[c&0xf];
                if (i&1) j++;
                line[42+k++] = c >= ' ' && c < 0x7f ? c : '.';
                if ((i & 15) == 15) {
                        fprintf (fh, "\n%4x  %s", ad, line);
                        /*if (i==15) printf (" %d", length);*/
                        memset (line, ' ', sizeof line);
                        line[sizeof (line)-1] = j = k = 0;
                        ad += 16;
                }
        }

        if (line[0] != ' ') fprintf (fh, "\n%4x  %s", ad, line);
        fprintf(fh, "\n");
        return;

}

#define MAX_LINE_LENGTH 256

static
void dumpit_ps (FILE *fh, register const u_char *cp, register u_int length)
{
        register int ad, i, j, k;
        u_char c;
        u_char line[60];
		static u_char binhex[16] = {
			'0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		u_char psline[MAX_LINE_LENGTH];

        memset (line, ' ', sizeof line);
        line[sizeof (line)-1] = 0;
        for (ad=i=j=k=0; i<length; i++) {
                c = *cp++;
                line[j++] = binhex[c>>4];
                line[j++] = binhex[c&0xf];
                if (i&1) j++;
                line[42+k++] = c >= ' ' && c < 0x7f ? c : '.';
                if ((i & 15) == 15) {
						ps_clean_string(psline, line, MAX_LINE_LENGTH);
                        fprintf (fh, "(%4x  %s) hexdump\n", ad, psline);
                        memset (line, ' ', sizeof line);
                        line[sizeof (line)-1] = j = k = 0;
                        ad += 16;
                }
        }

        if (line[0] != ' ') {
			ps_clean_string(psline, line, MAX_LINE_LENGTH);
			fprintf (fh, "(%4x  %s) hexdump\n", ad, psline);
		}
        return;

}

/* Print a tree's data in PostScript */
void print_tree_ps(FILE *fh, const u_char *pd, frame_data *fd, GtkTree *tree)
{
	GList		*children, *child, *widgets, *label;
	GtkWidget	*subtree;
	int		num_children, i;
	char		*text;
	gint		data_start, data_len;
	char		psbuffer[MAX_LINE_LENGTH]; /* static sized buffer! */

	/* Get the children of this tree */
	children = tree->children;
	num_children = g_list_length(children);

	for (i = 0; i < num_children; i++) {
		/* Each child of the tree is a widget container */
		child = g_list_nth(children, i);
		widgets = gtk_container_children(GTK_CONTAINER(child->data));

		/* And the container holds a label object, which holds text */
		label = g_list_nth(widgets, 0);
		gtk_label_get(GTK_LABEL(label->data), &text);

		/* Print the text */
		ps_clean_string(psbuffer, text, MAX_LINE_LENGTH);
		fprintf(fh, "%d (%s) putline\n", tree->level, psbuffer);

		/* Recurse into the subtree, if it exists */
		subtree = (GTK_TREE_ITEM(child->data))->subtree;
		if (subtree) {
				print_tree_ps(fh, pd, fd, GTK_TREE(subtree));
		}
		else if (strcmp("Data", text) == 0) {
			decode_start_len(GTK_TREE_ITEM(child->data), &data_start, &data_len);
			print_ps_hex(fh);
			dumpit_ps(fh, &pd[data_start], data_len);
		}
	}
}

static
void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size)
{
	int rd, wr;
	char c;

	for (rd = 0, wr = 0 ; wr < outbuf_size; rd++, wr++ ) {
		c = in[rd];
		switch (c) {
			case '(':
			case ')':
			case '\\':
				out[wr] = '\\';
				out[++wr] = c;
				break;

			default:
				out[wr] = c;
				break;
		}

		if (c == 0) {
			break;
		}
	}
}
