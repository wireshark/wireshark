/* packet-vines.c
 * Routines for Banyan VINES protocol packet disassembly
 *
 * $Id: packet-vines.c,v 1.1 1998/09/17 02:37:46 gerald Exp $
 *
 * Don Lafontaine <lafont02@cn.ca>
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
#include <pcap.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"
#include "packet-vines.h"

#define VINES_VSPP 2
#define VINES_DATA 1

void
dissect_vines(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) 
	{
  	e_vip       iph;
  	GtkWidget *vip_tree, *ti;
  	gchar      tos_str[32];

  /* To do: check for runts, errs, etc. */
  /* Avoids alignment problems on many architectures. */
  	memcpy(&iph, &pd[offset], sizeof(e_vip));

  	iph.vip_sum = pntohs(&pd[offset]);
  	iph.vip_len = pntohs(&pd[offset+2]);
  	iph.vip_dnet = pntohl(&pd[offset+6]);
  	iph.vip_snet = pntohl(&pd[offset+12]);
  	iph.vip_dsub = pntohs(&pd[offset+10]);
  	iph.vip_ssub = pntohs(&pd[offset+16]);

  	if (fd->win_info[0]) 
  		{
    	switch (iph.vip_proto) 
    		{
      		case VINES_VSPP:      
        		strcpy(fd->win_info[3], "Vines");
        		sprintf(fd->win_info[4], "VSPP (%02x)", iph.vip_proto);
        		break;
      		case VINES_DATA:
        		strcpy(fd->win_info[3], "Vines IP");
        		sprintf(fd->win_info[4], "DATA (%02x)", iph.vip_proto);
				break;
      		default:
        		strcpy(fd->win_info[3], "Vines IP");
        		sprintf(fd->win_info[4], "Unknown VIP protocol (%02x)", iph.vip_proto);
    		}

    	sprintf(fd->win_info[1], "%08x.%04x", iph.vip_snet, iph.vip_ssub);
    	sprintf(fd->win_info[2], "%08x.%04x", iph.vip_dnet, iph.vip_dsub);
  		}
  /*
  	iph.ip_tos = IPTOS_TOS(iph.ip_tos);
  	switch (iph.ip_tos) 
  		{
    	case IPTOS_NONE:
    	  	strcpy(tos_str, "None");
    	  	break;
    	case IPTOS_LOWDELAY:
    	  	strcpy(tos_str, "Minimize delay");
    	  	break;
    	case IPTOS_THROUGHPUT:
    	  	strcpy(tos_str, "Maximize throughput");
    	  	break;
    	case IPTOS_RELIABILITY:
    	  	strcpy(tos_str, "Maximize reliability");
    	  	break;
    	case IPTOS_LOWCOST:
    	  	strcpy(tos_str, "Minimize cost");
    	  	break;
    	default:
    	  	strcpy(tos_str, "Unknon.  Malformed?");
    	  	break;
  		}
  */
  	if (tree) 
  		{
    	ti = add_item_to_tree(GTK_WIDGET(tree), offset, (iph.vip_len),
      		"Vines IP");
    	vip_tree = gtk_tree_new();
    	add_subtree(ti, vip_tree, ETT_VINES);
    	add_item_to_tree(vip_tree, offset,      2, "Header checksum: 0x%04x", iph.vip_sum);
    	add_item_to_tree(vip_tree, offset +  2, 2, "Header length: 0x%02x (%d)", iph.vip_len, iph.vip_len); 
    	add_item_to_tree(vip_tree, offset +  4, 1, "Transport control: 0x%02x",
      		iph.vip_tos);
    	add_item_to_tree(vip_tree, offset +  5, 1, "Protocol: 0x%02x", iph.vip_proto);
  		}


  	offset += 18;
	switch (iph.vip_proto) 
		{
    	case VINES_VSPP:
	      	dissect_vspp(pd, offset, fd, tree); 
    		break;
  		}
	}
#define VINES_VSPP_DATA 1
#define VINES_VSPP_ACK 5
void dissect_vspp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) 
	{
  	e_vspp       iph;
  	GtkWidget *vspp_tree, *ti;
  	gchar      tos_str[32];

  /* To do: check for runts, errs, etc. */
  /* Avoids alignment problems on many architectures. */
  	memcpy(&iph, &pd[offset], sizeof(e_vspp));

  	iph.vspp_sport = ntohs(iph.vspp_sport);
  	iph.vspp_dport = ntohs(iph.vspp_dport);
  	iph.vspp_lclid = ntohs(iph.vspp_lclid);
  	iph.vspp_rmtid = ntohs(iph.vspp_rmtid);

  	if (fd->win_info[0]) 
  		{
    	switch (iph.vspp_pkttype) 
    		{
      		case VINES_VSPP_DATA:      
        		strcpy(fd->win_info[3], "Vines");
        		sprintf(fd->win_info[4], "VSPP Data Port=%04x(Transient) NS=%04x NR=%04x Window=%04x RID=%04x LID=%04x D=%04x S=%04x", 
        			iph.vspp_sport, iph.vspp_seq, iph.vspp_ack, iph.vspp_win, iph.vspp_rmtid,
        			iph.vspp_lclid, iph.vspp_dport, iph.vspp_sport);
        		break;
      		case VINES_VSPP_ACK:
        		strcpy(fd->win_info[3], "Vines");
        		sprintf(fd->win_info[4], "VSPP Ack Port=%04x(Transient) NS=%04x NR=%04x Window=%04x RID=%04x LID=%04x", 
        			iph.vspp_sport, iph.vspp_seq, iph.vspp_ack, iph.vspp_win, iph.vspp_rmtid,
        			iph.vspp_lclid);

				break;
      		default:
        		strcpy(fd->win_info[3], "Vines IP");
        		sprintf(fd->win_info[4], "Unknown VSPP packet type (%02x)", iph.vspp_pkttype);
    		}
  		}
  /*
  	iph.ip_tos = IPTOS_TOS(iph.ip_tos);
  	switch (iph.ip_tos) 
  		{
    	case IPTOS_NONE:
    	  	strcpy(tos_str, "None");
    	  	break;
    	case IPTOS_LOWDELAY:
    	  	strcpy(tos_str, "Minimize delay");
    	  	break;
    	case IPTOS_THROUGHPUT:
    	  	strcpy(tos_str, "Maximize throughput");
    	  	break;
    	case IPTOS_RELIABILITY:
    	  	strcpy(tos_str, "Maximize reliability");
    	  	break;
    	case IPTOS_LOWCOST:
    	  	strcpy(tos_str, "Minimize cost");
    	  	break;
    	default:
    	  	strcpy(tos_str, "Unknon.  Malformed?");
    	  	break;
  		}
*/ 
  	if (tree) 
  		{
    	ti = add_item_to_tree(GTK_WIDGET(tree), offset, sizeof(iph),
      		"Vines SPP");
    	vspp_tree = gtk_tree_new();
    	add_subtree(ti, vspp_tree, ETT_VSPP);
    	add_item_to_tree(vspp_tree, offset,      2, "Source port: 0x%04x", iph.vspp_sport);
    	add_item_to_tree(vspp_tree, offset+2,    2, "Destination port: 0x%04x", iph.vspp_dport); 
    	add_item_to_tree(vspp_tree, offset+4,    1, "Packet type: 0x%02x", iph.vspp_pkttype);
    	add_item_to_tree(vspp_tree, offset+5,    1, "Control: 0x%02x", iph.vspp_tos);
    	add_item_to_tree(vspp_tree, offset+6,    2, "Local Connection ID: 0x%04x", iph.vspp_lclid);
    	add_item_to_tree(vspp_tree, offset+8,    2, "Remote Connection ID: 0x%04x", iph.vspp_rmtid);
    	add_item_to_tree(vspp_tree, offset+10,   2, "Sequence number: 0x%04x", iph.vspp_seq);
    	add_item_to_tree(vspp_tree, offset+12,   2, "Ack number: 0x%04x", iph.vspp_ack);
    	add_item_to_tree(vspp_tree, offset+14,   2, "Window: 0x%04x", iph.vspp_win);
  		}

	}
