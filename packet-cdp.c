/* packet-cdp.c
 * Routines for 
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.1 1998/12/19 00:12:21 hannes Exp $
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
 
#include "config.h"

#include <gtk/gtk.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"

void 
dissect_cdp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    GtkWidget *cdp_tree = NULL, *ti; 

    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "CDP");
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, "Cisco Discovery Protocol"); 

    if(tree){
        ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset), 
                                                          "Cisco Discovery Protocoll");
	cdp_tree = gtk_tree_new(); 
	add_subtree(ti, cdp_tree, ETT_CDP);
    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
    }
}

