/* packet-ospf.c
 * Routines for RIPv1 and RIPv2 packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-rip.c,v 1.5 1998/11/18 03:01:36 gerald Exp $
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
#include "packet-rip.h"


void 
dissect_rip(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    e_riphdr *rip_header;
    e_rip_vektor rip_vektor;
    int auth = FALSE;

    GtkWidget *rip_tree = NULL, *ti; 
    GtkWidget *rip_vektor_tree;


    /* we do the range checking of the index when checking wether or not this is a RIP packet */
    char *packet_type[8] = { "never used", "Request", "Response", 
    "Traceon", "Traceoff", "Vendor specific (Sun)" };
    char *version[3] = { "RIP", "RIPv1", "RIPv2" };


    rip_header = (e_riphdr *) &pd[offset];
    /* Check if we 've realy got a RIP packet */

    switch(rip_header->version) {
	case RIPv1:
            /* the domain field has to be set to zero for RIPv1 */
            if(!(rip_header->domain == 0)){ 
                dissect_data(pd, offset, fd, tree);
                return;
            }
	    /* the RIPv2 checks are also made for v1 packets */
	case RIPv2:
	    /* check wether or not command nr. is between 1-7 
	     * (range checking for index of char* packet_type is done at the same time) 
	     */
            if( !( (rip_header->command > 0) && (rip_header->command <= 7) )){ 
                dissect_data(pd, offset, fd, tree);
                return;
            }
	    break;
	default:
	    /* we only know RIPv1 and RIPv2 */
            dissect_data(pd, offset, fd, tree);
            return;
    }


    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, version[rip_header->version] );
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, packet_type[rip_header->command]); 

    if (tree) {
	ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset), "Routing Information Protocol"); 
	rip_tree = gtk_tree_new(); 
	add_subtree(ti, rip_tree, ETT_RIP);

	add_item_to_tree(rip_tree, offset + 1, 1, "Version: %d", rip_header->version);
	add_item_to_tree(rip_tree, offset, 1, "Command: %d (%s)", rip_header->command, packet_type[rip_header->command]); 
	switch(ntohs(rip_header->family)){
	    case 2: /* IP */
	        add_item_to_tree(rip_tree, offset + 4 , 2, "Address Family ID: IP"); 
		break;
	    case 0xFFFF:
	        add_item_to_tree(rip_tree, offset + 4 , 2, "Authenticated Packet"); 
		auth = TRUE;
		break;
            default:
            	break;
	        /* return; */
	} 

	if(rip_header->version == RIPv2) {
	    add_item_to_tree(rip_tree, offset + 2 , 2, "Routing Domain: %d", ntohs(rip_header->domain)); 
	    add_item_to_tree(rip_tree, offset + 6 , 2, "Route Tag: %d", ntohs(rip_header->tag)); 
	}
	/* skip header */
	offset += RIP_HEADER_LENGTH;

	/* if present, skip the authentication */
	if(auth){
	    offset += RIP_VEKTOR_LENGTH;
	}
        /* zero or more distance vektors */

	while((fd->cap_len - offset) >= RIP_VEKTOR_LENGTH){
            ti = add_item_to_tree(GTK_WIDGET(rip_tree), offset, RIP_VEKTOR_LENGTH, "RIP Vektor"); 
            rip_vektor_tree = gtk_tree_new(); 
            add_subtree(ti, rip_vektor_tree, ETT_RIP_VEC);
	   
            memcpy(&rip_vektor, &pd[offset], sizeof(rip_vektor)); /* avoid alignment problem */
            add_item_to_tree(rip_vektor_tree, offset, 4, "IP Address: %s", ip_to_str((guint8 *) &(rip_vektor.ip))); 

	    if(rip_header->version == RIPv2) {
                add_item_to_tree(rip_vektor_tree, offset + 4 , 4, "Netmask: %s", 
		                                      ip_to_str((guint8 *) &(rip_vektor.mask))); 
                add_item_to_tree(rip_vektor_tree, offset + 8 , 4, "Next Hop: %s", 
		                                      ip_to_str((guint8 *) &(rip_vektor.next_hop))); 
            }

            add_item_to_tree(rip_vektor_tree, offset + 12 , 4, "Metric: %ld", (long)ntohl(rip_vektor.metric)); 

            offset += RIP_VEKTOR_LENGTH;
        };
    }
}
