/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocol"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.7 1999/03/01 18:28:11 gram Exp $
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"

/* Offsets in TLV structure. */
#define	TLV_TYPE	0
#define	TLV_LENGTH	2

static void
add_multi_line_string_to_tree(GtkWidget *tree, gint start, gint len,
  const gchar *prefix, const gchar *string);

void 
dissect_cdp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    GtkWidget *cdp_tree = NULL, *ti; 
    
    typedef struct _e_cdp_hdr{
		char version;
		char flags;
		gint16 ttl;
	} e_cdp_hdr;

    e_cdp_hdr *cdp_hdr;
    char *stringmem;
    gint16 type;
    gint16 length;

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
	add_item_to_tree(cdp_tree, offset, 1, "Version: %d", cdp_hdr->version);
	add_item_to_tree(cdp_tree, offset+1, 1, "Flags (unknown)");
	add_item_to_tree(cdp_tree, offset+2, 2, "TTL (unknown)");
	offset+=4;

	/* CVS -> exit here 
    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
		return;
     */
	
	while( offset <= fd->cap_len ){
		type = pntohs(&pd[offset + TLV_TYPE]);
		length = pntohs(&pd[offset + TLV_LENGTH]);
		switch( type ){
			case 0: /* ??? Mgmt Addr */
				offset+=length + 4;
				break;
			case 1: /* ??? Chassis ID */
				add_item_to_tree(cdp_tree, offset + 4,
				    length - 4, "Chassis ID: %s", &pd[offset+4] );
				offset+=length;
				break;
			case 2:  
				/* this is quite strange: this tlv contains no data itself but two tlvs which
                 * calculate the length without the 2 byte type and 2 byte length field
                 */
				offset+=4; 
				break;
			case 3: /* ??? Port  */    
				add_item_to_tree(cdp_tree, offset + 4,
				  length - 4, "Sent through Interface: %s", &pd[offset+4] );
				offset+=length;
				break;
			case 5: /* ??? IOS Version */
				add_multi_line_string_to_tree(cdp_tree,
				    offset + 4, length - 4, "Software Version: ",
				    &pd[offset+4] );
				offset+=length;
				break;
			case 6: /* ??? platform */
				
				stringmem = malloc(length);
				memset(stringmem, '\0', length);
				memcpy(stringmem, &pd[offset+4], length - 4 );
				add_item_to_tree(cdp_tree, offset + 4, length - 4, 
                                                     "Platform: %s", stringmem );
				free(stringmem);
				offset+=length;
				break;
			case 0x01cc: /* ??? Mgmt Addr */
				add_item_to_tree(cdp_tree, offset + 4, length, 
                                                     "Mgmt IP: %s",
						     ip_to_str(&pd[offset+4]) );
				offset+=length + 4;
				break;
			default:
/*
				if( type > 512){
					dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
					return;
				}
*/
/*
				add_item_to_tree(cdp_tree, offset + TLV_TYPE,
				    2, "Type: %d", type);
				add_item_to_tree(cdp_tree, offset + TLV_LENGTH,
				    2, "Length: %d", length);
				add_item_to_tree(cdp_tree, offset + 4,
				    length - 4, "Data");
*/

				offset+=length;
		}

	}
    	dissect_data(pd, offset, fd, (GtkTree *) cdp_tree);
    }
}

static void
add_multi_line_string_to_tree(GtkWidget *tree, gint start, gint len,
  const gchar *prefix, const gchar *string)
{
    int prefix_len;
    int i;
    char blanks[64+1];
    const gchar *p, *q;
    int line_len;
    int data_len;

    prefix_len = strlen(prefix);
    if (prefix_len > 64)
	prefix_len = 64;
    for (i = 0; i < prefix_len; i++)
	blanks[i] = ' ';
    blanks[i] = '\0';
    p = string;
    for (;;) {
	q = strchr(p, '\n');
	if (q != NULL) {
	    line_len = q - p;
	    data_len = line_len + 1;
	} else {
	    line_len = strlen(p);
	    data_len = line_len;
	}
	add_item_to_tree(tree, start, data_len, "%s%.*s", prefix,
	   line_len, p);
	if (q == NULL)
	    break;
	p += data_len;
	start += data_len;
	prefix = blanks;
    }
}
