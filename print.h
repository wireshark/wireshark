/* print.h
 * Definitions for printing packet analysis trees.
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

#ifndef __PRINT_H__
#define __PRINT_H__

typedef struct pr_opts {
	int		output_format;	/* 0=text, 1=postscript */
	int		output_dest;	/* 0=cmd, 1=file */
	char	*file;
	char	*cmd;

	/* for the dialogue box */
	GtkWidget	*window;
	GtkWidget	*cmd_te;
	GtkWidget	*file_te;
} pr_opts;

/* Functions in print.h */

void printer_opts_cb(GtkWidget *, gpointer);
void print_tree_text(FILE *fh, const u_char *pd, frame_data *fd, GtkTree *tree);
void print_tree_ps(FILE *fh, const u_char *pd, frame_data *fd, GtkTree *tree);

#endif /* print.h */
