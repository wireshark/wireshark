/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocoll"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.2 1999/01/04 20:07:28 hannes Exp $
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
    char *version;
    char *hostname;
    char *interface;
    
    typedef struct _e_tlv_struct{
		short type;
		short length;
    } e_tlv_struct;

    e_tlv_struct *tlv;
    int 	i,j;


    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "CDP");
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, "Cisco Discovery Protocol"); 

    if(tree){
        ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset), 
                                                          "Cisco Discovery Protocoll");
	cdp_tree = gtk_tree_new(); 
	add_subtree(ti, cdp_tree, ETT_CDP);
	
	version=(char *) &pd[offset];
	hostname=(char *) &pd[offset+8];
	interface=(char *) &pd[offset+34];

	add_item_to_tree(cdp_tree, offset, 0, "under development (hannes@boehm.org)");
	add_item_to_tree(cdp_tree, offset, 1, "Version: %d", *version);
	add_item_to_tree(cdp_tree, offset+8, 1, "Chassis ID: %s", hostname);
	add_item_to_tree(cdp_tree, offset+34, 1, "Interface: %s", interface);

	/* CVS -> exit here 
    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
	return;
        */
	
	i=4;
    j=0;
	while(i < 1500 ){
		tlv = (e_tlv_struct *)  &pd[offset+i];
		add_item_to_tree(cdp_tree, offset+i, 2, "Type: %d",  ntohs(tlv->type));
		add_item_to_tree(cdp_tree, offset+i+2, 2, "Length: %d", ntohs(tlv->length));
		if( (ntohs(tlv->type) == 0) && j==0) {
			j=1;
			i+= ntohs(tlv->length) + 4;
		} else if( (ntohs(tlv->type) == 0) && j==1) {
			j=0;
			i+= 4;
		} else {
			i+= ntohs(tlv->length) + 4;
		}
		
	}

    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
    }
}

