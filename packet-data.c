/* packet-data.c
 * Routines for raw data (default case)
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-data.c,v 1.7 1999/03/22 03:56:33 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "ethereal.h"
#include "packet.h"


void
dissect_data(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	if (fd->cap_len > offset && tree) {
		(void) add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
			"Data (%d bytes)", END_OF_FRAME);
	}
}

