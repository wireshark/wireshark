/* print.h
 * Definitions for printing packet analysis trees.
 *
 * $Id: print.h,v 1.14 1999/10/30 06:41:36 guy Exp $
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

typedef struct {
  gboolean	to_file;	/* TRUE if we're printing to a file */
  char		*dest;		/* if printing to file, pathname;
				   if not, command string */
  gboolean	print_summary;	/* TRUE if we should just print summary;
				   FALSE if we should print protocol tree. */
  gboolean	print_hex;	/* TRUE if we should also print hex data;
				   FALSE if we should print only if not dissected. */
  gboolean	expand_all;	/* TRUE if we should expand all levels;
				   FALSE if we should expand as displayed. */
} print_args_t;

/* Functions in print.h */

FILE *open_print_dest(int to_file, const char *dest);
void close_print_dest(int to_file, FILE *fh);
void print_preamble(FILE *fh);
void print_finale(FILE *fh);
void print_file(FILE* fh, const char* filename);
void proto_tree_print(gboolean print_one_packet, print_args_t *print_args,
    GNode *protocol_tree, const u_char *pd, frame_data *fd, FILE *fh);
void print_hex_data(FILE *fh, register const u_char *cp,
    register u_int length);

#endif /* print.h */
