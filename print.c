/* print.c
 * Routines for printing packet analysis trees.
 *
 * $Id: print.c,v 1.14 1999/07/23 08:29:22 guy Exp $
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
#include "gtkpacket.h"
#include "prefs.h"
#include "print.h"
#include "ps.h"

static void printer_opts_file_cb(GtkWidget *w, gpointer te);
static void printer_opts_fs_cancel_cb(GtkWidget *w, gpointer data);
static void printer_opts_fs_ok_cb(GtkWidget *w, gpointer data);
static void printer_opts_toggle_format(GtkWidget *widget, gpointer data);
static void printer_opts_toggle_dest(GtkWidget *widget, gpointer data);
static void proto_tree_print_node_text(GNode *node, gpointer data);
static void dumpit (FILE *fh, register const u_char *cp, register u_int length);
static void proto_tree_print_node_ps(GNode *node, gpointer data);
static void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size);
static void dumpit_ps (FILE *fh, register const u_char *cp, register u_int length);

extern int proto_data; /* in packet-data.c */

/* #include "ps.c" */

/* Key for gtk_object_set_data */
#define PRINT_CMD_TE_KEY  "printer_command_entry"
#define PRINT_FILE_TE_KEY "printer_file_entry"

GtkWidget * printer_prefs_show()
{
	GtkWidget	*main_vb, *main_tb, *button;
	GtkWidget	*format_hb, *format_lb;
	GtkWidget	*dest_hb, *dest_lb;
	GtkWidget	*cmd_lb, *cmd_te;
	GtkWidget	*file_bt_hb, *file_bt, *file_te;
	GSList		*format_grp, *dest_grp;

	/* Enclosing containers for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	main_tb = gtk_table_new(4, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

	/* Output format */
	format_lb = gtk_label_new("Format:");
  gtk_misc_set_alignment(GTK_MISC(format_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_lb, 0, 1, 0, 1);
	gtk_widget_show(format_lb);

	format_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_hb, 1, 2, 0, 1);
	gtk_widget_show(format_hb);

	button = gtk_radio_button_new_with_label(NULL, "Plain Text");
	if (prefs.pr_format == PR_FMT_TEXT) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	button = gtk_radio_button_new_with_label(format_grp, "PostScript");
	if (prefs.pr_format == PR_FMT_PS) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	gtk_signal_connect(GTK_OBJECT(button), "toggled",
			GTK_SIGNAL_FUNC(printer_opts_toggle_format), NULL);
	gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	/* Output destination */
	dest_lb = gtk_label_new("Print to:");
  gtk_misc_set_alignment(GTK_MISC(dest_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_lb, 0, 1, 1, 2);
	gtk_widget_show(dest_lb);

	dest_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_hb, 1, 2, 1, 2);
	gtk_widget_show(dest_hb);

	button = gtk_radio_button_new_with_label(NULL, "Command");
	if (prefs.pr_dest == PR_DEST_CMD) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	dest_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	gtk_box_pack_start(GTK_BOX(dest_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	button = gtk_radio_button_new_with_label(dest_grp, "File");
	if (prefs.pr_dest == PR_DEST_FILE) {
		gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
	}
	gtk_signal_connect(GTK_OBJECT(button), "toggled",
			GTK_SIGNAL_FUNC(printer_opts_toggle_dest), NULL);
	gtk_box_pack_start(GTK_BOX(dest_hb), button, FALSE, FALSE, 10);
	gtk_widget_show(button);

	/* Command text entry */
	cmd_lb = gtk_label_new("Command:");
  gtk_misc_set_alignment(GTK_MISC(cmd_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_lb, 0, 1, 2, 3);
	gtk_widget_show(cmd_lb);

	cmd_te = gtk_entry_new();
	gtk_object_set_data(GTK_OBJECT(main_vb), PRINT_CMD_TE_KEY, cmd_te);
	if (prefs.pr_cmd) gtk_entry_set_text(GTK_ENTRY(cmd_te), prefs.pr_cmd);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_te, 1, 2, 2, 3);
	gtk_widget_show(cmd_te);

	/* File button and text entry */
	file_bt_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_bt_hb, 0, 1, 3, 4);
	gtk_widget_show(file_bt_hb);

	file_bt = gtk_button_new_with_label("File:");
	gtk_box_pack_end(GTK_BOX(file_bt_hb), file_bt, FALSE, FALSE, 0);
	gtk_widget_show(file_bt);

	file_te = gtk_entry_new();
	gtk_object_set_data(GTK_OBJECT(main_vb), PRINT_FILE_TE_KEY, file_te);
	if (prefs.pr_file) gtk_entry_set_text(GTK_ENTRY(file_te), prefs.pr_file);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_te, 1, 2, 3, 4);
	gtk_widget_show(file_te);

	gtk_signal_connect(GTK_OBJECT(file_bt), "clicked",
			GTK_SIGNAL_FUNC(printer_opts_file_cb), GTK_OBJECT(file_te));

	gtk_widget_show(main_vb);
	return(main_vb);
}


static void
printer_opts_file_cb(GtkWidget *file_bt, gpointer file_te) {
  GtkWidget *fs;

  fs = gtk_file_selection_new ("Ethereal: Print to a File");
	gtk_object_set_data(GTK_OBJECT(fs), PRINT_FILE_TE_KEY, file_te);

  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) printer_opts_fs_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) printer_opts_fs_cancel_cb, fs);

  gtk_widget_show(fs);
}

static void
printer_opts_fs_ok_cb(GtkWidget *w, gpointer data) {
	  
	gtk_entry_set_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(data),
  	PRINT_FILE_TE_KEY)),
		gtk_file_selection_get_filename (GTK_FILE_SELECTION(data)));
	printer_opts_fs_cancel_cb(w, data);
}

static void
printer_opts_fs_cancel_cb(GtkWidget *w, gpointer data) {
	  
	gtk_widget_destroy(GTK_WIDGET(data));
} 

void
printer_prefs_ok(GtkWidget *w)
{
	if(prefs.pr_cmd) g_free(prefs.pr_cmd);
	prefs.pr_cmd =  
		g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(w),
    PRINT_CMD_TE_KEY))));

	if(prefs.pr_file) g_free(prefs.pr_file);
	prefs.pr_file =  
		g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(w),
    PRINT_FILE_TE_KEY))));
}

void
printer_prefs_save(GtkWidget *w)
{
	printer_prefs_ok(w);
}

void
printer_prefs_cancel(GtkWidget *w)
{
}

static void
printer_opts_toggle_format(GtkWidget *widget, gpointer data)
{
		if (GTK_TOGGLE_BUTTON (widget)->active) {
			prefs.pr_format = PR_FMT_PS;
			/* toggle file/cmd */
		}
		else {
			prefs.pr_format = PR_FMT_TEXT;
			/* toggle file/cmd */
		}
}

static void
printer_opts_toggle_dest(GtkWidget *widget, gpointer data)
{
		if (GTK_TOGGLE_BUTTON (widget)->active) {
			prefs.pr_dest = PR_DEST_FILE;
		}
		else {
			prefs.pr_dest = PR_DEST_CMD;
		}
}

/* ========================================================== */

typedef struct {
	int		level;
	FILE		*fh;
	const guint8	*pd;
} print_data;

FILE *open_print_dest(int to_file, const char *dest)
{
	FILE	*fh;
	char	*out;

	/* Open the file or command for output */
	out = dest;
	if (to_file)
		fh = fopen(dest, "w");
	else
		fh = popen(prefs.pr_cmd, "w");

	return fh;
}

void close_print_dest(int to_file, FILE *fh)
{
	/* Close the file or command */
	if (to_file)
		fclose(fh);
	else
		pclose(fh);
}

void proto_tree_print(GNode *protocol_tree, const u_char *pd, frame_data *fd,
    FILE *fh)
{
	print_data data;

	/* Create the output */
	data.level = 0;
	data.fh = fh;
	data.pd = pd;
	if (prefs.pr_format == PR_FMT_TEXT) {
		g_node_children_foreach((GNode*) protocol_tree, G_TRAVERSE_ALL,
			proto_tree_print_node_text, &data);
	} else {
		print_ps_preamble(fh);
		g_node_children_foreach((GNode*) protocol_tree, G_TRAVERSE_ALL,
			proto_tree_print_node_ps, &data);
		print_ps_finale(fh);
	}
}

/* Print a tree's data, and any child nodes, in plain text */
static
void proto_tree_print_node_text(GNode *node, gpointer data)
{
	field_info	*fi = (field_info*) (node->data);
	print_data	*pdata = (print_data*) data;
	int		i;
	int		 num_spaces;
	char		space[41];
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;

	if (!fi->visible)
		return;

	/* was a free format label produced? */
	if (fi->representation) {
		label_ptr = fi->representation;
	}
	else { /* no, make a generic label */
		label_ptr = label_str;
		proto_item_fill_label(fi, label_str);
	}
		
	/* Prepare the tabs for printing, depending on tree level */
	num_spaces = pdata->level * 4;
	if (num_spaces > 40) {
		num_spaces = 40;
	}
	for (i = 0; i < num_spaces; i++) {
		space[i] = ' ';
	}
	/* The string is NUL-terminated */
	space[num_spaces] = 0;

	/* Print the text */
	fprintf(pdata->fh, "%s%s\n", space, label_ptr);

	/* If it's uninterpreted data, dump it. */
	if (fi->hfinfo->id == proto_data)
		dumpit(pdata->fh, &pdata->pd[fi->start], fi->length);

	/* Recurse into the subtree, if it exists */
	if (g_node_n_children(node) > 0) {
		pdata->level++;
		g_node_children_foreach(node, G_TRAVERSE_ALL,
			proto_tree_print_node_text, pdata);
		pdata->level--;
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

/* Print a node's data, and any child nodes, in PostScript */
static
void proto_tree_print_node_ps(GNode *node, gpointer data)
{
	field_info	*fi = (field_info*) (node->data);
	print_data	*pdata = (print_data*) data;
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;
	char		psbuffer[MAX_LINE_LENGTH]; /* static sized buffer! */

	if (!fi->visible)
		return;

	/* was a free format label produced? */
	if (fi->representation) {
		label_ptr = fi->representation;
	}
	else { /* no, make a generic label */
		label_ptr = label_str;
		proto_item_fill_label(fi, label_str);
	}
		
	/* Print the text */
	ps_clean_string(psbuffer, label_ptr, MAX_LINE_LENGTH);
	fprintf(pdata->fh, "%d (%s) putline\n", pdata->level, psbuffer);

	/* If it's uninterpreted data, dump it. */
	if (fi->hfinfo->id == proto_data) {
		print_ps_hex(pdata->fh);
		dumpit_ps(pdata->fh, &pdata->pd[fi->start], fi->length);
	}

	/* Recurse into the subtree, if it exists */
	if (g_node_n_children(node) > 0) {
		pdata->level++;
		g_node_children_foreach(node, G_TRAVERSE_ALL,
			proto_tree_print_node_ps, pdata);
		pdata->level--;
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
