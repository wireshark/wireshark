/* print.h
 * Definitions for printing packet analysis trees.
 *
 * $Id: print.h,v 1.35 2004/01/24 10:53:24 guy Exp $
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __PRINT_H__
#define __PRINT_H__

#include <epan/packet.h>

#define PR_FMT_TEXT 0
#define PR_FMT_PS   1
#define PR_FMT_PDML 2

/* print_range, enum which frames should be printed */
typedef enum {
  print_range_selected_only,    /* selected frame(s) only (currently only one) */
  print_range_marked_only,      /* marked frames only */
  print_range_all_displayed,    /* all frames currently displayed */
  print_range_all_captured      /* all frames in capture */
} print_range_e;

/* print_dissections, enum how the dissections should be printed */
typedef enum {
  print_dissections_collapsed,    /* no dissection details */
  print_dissections_as_displayed, /* details as displayed */
  print_dissections_expanded      /* all dissection details */
} print_dissections_e;

typedef struct {
  gint		format;		/* text or PostScript */
  gboolean	to_file;	/* TRUE if we're printing to a file */
  char		*dest;		/* if printing to file, pathname;
				   if not, command string */
  packet_range_t range;

  gboolean	print_summary;	/* TRUE if we should just print summary;
				   FALSE if we should print protocol tree. */
  print_dissections_e   print_dissections;
  gboolean	print_hex;	/* TRUE if we should also print hex data;
				   FALSE if we should print only if not dissected. */
} print_args_t;

/* Functions in print.h */

FILE *open_print_dest(int to_file, const char *dest);
gboolean close_print_dest(int to_file, FILE *fh);
gboolean print_preamble(FILE *fh, gint format);
gboolean print_finale(FILE *fh, gint format);
void proto_tree_print(print_args_t *print_args, epan_dissect_t *edt,
    FILE *fh);
void print_hex_data(FILE *fh, gint format, epan_dissect_t *edt);
void print_line(FILE *fh, int indent, gint format, char *line);

#endif /* print.h */
