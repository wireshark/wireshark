/* packet-ddp.c
 * Routines for DDP packet disassembly.
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"
#include "resolv.h"

extern packet_info pi;

typedef struct _e_ddp {
#if BYTE_ORDER == BIG_ENDIAN
  guint16	pad:2,hops:4,len:10;
#else
  guint16	len:10,hops:4,pad:2;
#endif
  guint16	sum,dnet,snet;
  guint8	dnode,snode;
  guint8	dport,sport;
  guint8	type;
} e_ddp;

#define DDP_RTMPDATA	0x01
#define DDP_NBP		0x02
#define DDP_ATP		0x03
#define DDP_AEP		0x04
#define DDP_RTMPREQ	0x05
#define DDP_ZIP		0x06
#define DDP_ADSP	0x07

void
dissect_ddp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_ddp       ddp;
  GtkWidget *ddp_tree, *ti;
  value_string op_vals[] = { {DDP_RTMPDATA, "AppleTalk Routing Table response or data" },
  			     {DDP_NBP, "AppleTalk Name Binding Protocol packet"},
  			     {DDP_ATP, "AppleTalk Transaction Protocol packet"},
  			     {DDP_AEP, "AppleTalk Echo Protocol packet"},
  			     {DDP_RTMPREQ, "AppleTalk Routing Table request"},
  			     {DDP_ZIP, "AppleTalk Zone Information Protocol packet"},
  			     {DDP_ADSP, "AppleTalk Data Stream Protocol"},
                             {0, NULL} };

  memcpy(&ddp, &pd[offset], sizeof(e_ddp));
  ddp.dnet=ntohs(ddp.dnet);
  ddp.snet=ntohs(ddp.snet);
  ddp.sum=ntohs(ddp.sum);
  
  if (fd->win_info[COL_NUM]) {
    strcpy(fd->win_info[COL_PROTOCOL], "DDP");
    strcpy(fd->win_info[COL_INFO],
      val_to_str(ddp.type, op_vals, "Unknown DDP protocol (%02x)"));

    sprintf(fd->win_info[COL_SOURCE],"%d.%d:%d",ddp.snet,ddp.snode,ddp.sport);
    sprintf(fd->win_info[COL_DESTINATION], "%d.%d:%d",ddp.dnet,ddp.dnode,ddp.dport);
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 13,
      "Datagram Delivery Protocol");
    ddp_tree = gtk_tree_new();
    add_subtree(ti, ddp_tree, ETT_IP);
    add_item_to_tree(ddp_tree, offset,      1, "Hop count: %d", ddp.hops);
    add_item_to_tree(ddp_tree, offset,	    2, "Datagram length: %d", ddp.len);
    add_item_to_tree(ddp_tree, offset + 2,  2, "Checksum: %d",ddp.sum);
    add_item_to_tree(ddp_tree, offset + 4,  2, "Destination Net: %d",ddp.dnet);
    add_item_to_tree(ddp_tree, offset + 6,  2, "Source Net: %d",ddp.snet);
    add_item_to_tree(ddp_tree, offset + 8,  1, "Destination Node: %d",ddp.dnode);
    add_item_to_tree(ddp_tree, offset + 9,  1, "Source Node: %d",ddp.snode);
    add_item_to_tree(ddp_tree, offset + 10, 1, "Destination Socket: %d",ddp.dport);
    add_item_to_tree(ddp_tree, offset + 11, 1, "Source Socket: %d",ddp.sport);
    add_item_to_tree(ddp_tree, offset + 12, 1, "Type: %d",ddp.type);  
  }

  offset += 13;

}
