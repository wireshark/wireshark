/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocoll"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.4 1999/01/05 00:08:49 hannes Exp $
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
    
    typedef struct _e_tlv_struct{
		gint16 type;
		gint16 length;
    } e_tlv_struct;

    typedef struct _e_cdp_hdr{
		char version;
		char flags;
		gint16 ttl;
	} e_cdp_hdr;

    e_tlv_struct *tlv;
	e_cdp_hdr *cdp_hdr;
    char *stringmem;
    gint32	mgmt_ip;


    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "CDP");
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, "Cisco Discovery Protocol"); 

    if(tree){
        ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset), 
                                                          "Cisco Discovery Protocol");
	cdp_tree = gtk_tree_new(); 
	add_subtree(ti, cdp_tree, ETT_CDP);
	
    /* CDP header */
	cdp_hdr = (e_cdp_hdr *) &pd[offset];
	add_item_to_tree(cdp_tree, offset, 0, "under development (hannes@boehm.org)");
	add_item_to_tree(cdp_tree, offset, 1, "Version: %d", cdp_hdr->version);
	add_item_to_tree(cdp_tree, offset+1, 1, "Flags (unknown)");
	add_item_to_tree(cdp_tree, offset+2, 2, "TTL (unknown)");
	offset+=4;

	/* CVS -> exit here 
    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
		return;
     */
	
	while( offset <= fd->cap_len ){
		tlv = (e_tlv_struct *)  &pd[offset];
		switch( ntohs(tlv->type) ){
			case 0: /* ??? Mgmt Addr */
				offset+=ntohs(tlv->length) + 4;
				break;
			case 1: /* ??? Chasis ID */
				add_item_to_tree(cdp_tree, offset + 4, ntohs(tlv->length) - 4, "Chassis ID: %s", &pd[offset+4] );
				offset+=ntohs(tlv->length);
				break;
			case 2:  
				/* this is quite strange: this tlv contains no data itself but two tlvs which
                 * calculate the length without the 2 byte type and 2 byte length field
                 */
				offset+=4; 
				break;
			case 3: /* ??? Port  */    
				add_item_to_tree(cdp_tree, offset + 4, ntohs(tlv->length) - 4, "Sent through Interface: %s", &pd[offset+4] );
				offset+=ntohs(tlv->length);
				break;
			case 5: /* ??? IOS Version */
				add_item_to_tree(cdp_tree, offset + 4, ntohs(tlv->length) - 4, 
				                                       "Software Version: %s", &pd[offset+4] );
				offset+=ntohs(tlv->length);
				break;
			case 6: /* ??? platform */
				
				stringmem = malloc(ntohs(tlv->length));
				bzero(stringmem, ntohs(tlv->length));
				memcpy(stringmem, &pd[offset+4], ntohs(tlv->length) - 4 );
				add_item_to_tree(cdp_tree, offset + 4, ntohs(tlv->length) - 4, 
                                                     "Platform: %s", stringmem );
				free(stringmem);
				offset+=ntohs(tlv->length);
				break;
			case 0x01cc: /* ??? Mgmt Addr */
				memcpy(&mgmt_ip, &pd[offset+4], 4);
				add_item_to_tree(cdp_tree, offset + 4, ntohs(tlv->length), 
                                                     "Mgmt IP: %s", inet_ntoa((mgmt_ip)) );
				offset+=ntohs(tlv->length) + 4;
				break;
			default:
/*
				if( ntohs(tlv->type) > 512){
					dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
					return;
				}
*/
/*
				add_item_to_tree(cdp_tree, offset, 2, "Type: %d",  ntohs(tlv->type));
				add_item_to_tree(cdp_tree, offset + 2, 2, "Length: %d", ntohs(tlv->length));
				add_item_to_tree(cdp_tree, offset + 4, ntohs(tlv->length) - 4, "Data");
*/

				offset+=ntohs(tlv->length);
		}

    }
    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
	}
}

