/* packet-tftp.c
 * Routines for tftp packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-tftp.c,v 1.1 1999/02/15 06:36:56 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-bootp.c
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

#include <arpa/tftp.h>

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"

char *tftp_opcodes[8] = {
  "Unknown Request",
  "Read Request",
  "Write Request",
  "Data Packet",
  "Acknowledgement",
  "Error Code",
  "Unknown Request",
  "Unknown Request"
};

char *tftp_errors[8] = {
  "Not defined",
  "File not found",
  "Access violation",
  "Disk full or allocation exceeded",
  "Illegal TFTP Operation",
  "Unknown transfer ID",
  "File already exists",
  "No such user"
};

void
dissect_tftp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree)
{
	GtkWidget	*tftp_tree, *ti;
	struct tftphdr  *tftp_pack = (struct tftphdr *)&pd[offset]; /* Want the hdr */
	u_int           i1;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TFTP");

	if (check_col(fd, COL_INFO)) {

	  i1 = ntohs(tftp_pack -> th_opcode);
	  col_add_fstr(fd, COL_INFO, "TFTP %s", i1 <= ERROR ? tftp_opcodes[i1 % 8] : "Unknown Request");

	}

	if (tree) {

	  ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
				"Trivial File Transfer Protocol");
	  tftp_tree = gtk_tree_new();
	  add_subtree(ti, tftp_tree, ETT_TFTP);

	  switch (i1 = ntohs(tftp_pack -> th_opcode)) {
	  case RRQ:
	    add_item_to_tree(tftp_tree, offset, 2, "Read Request");
	    offset += 2;
	    i1 = strlen(pd+offset);
	    add_item_to_tree(tftp_tree, offset, i1+1, "Source File: %s", pd+offset);
	    offset += i1 + 1;
	    add_item_to_tree(tftp_tree, offset, END_OF_FRAME, "Type: %s",pd+offset);
	    break;
	  case WRQ:
	    add_item_to_tree(tftp_tree, offset, 2, "Write Request");
	    offset += 2;
	    i1 = strlen(pd+offset);
	    add_item_to_tree(tftp_tree, offset, i1+1, "Destination File: %s", pd+offset);
	    offset += i1 + 1;
	    add_item_to_tree(tftp_tree, offset+2, END_OF_FRAME, "Type: %s",pd+offset);
	    break;
	  case DATA:
	    add_item_to_tree(tftp_tree, offset, 2, "Data Packet");
	    offset += 2;
	    i1 = ntohs(*(short *)(pd + offset));
	    add_item_to_tree(tftp_tree, offset, 2, "Block = %u", i1);
	    offset += 2;
	    add_item_to_tree(tftp_tree, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);
	    break;
	  case ACK:
	    add_item_to_tree(tftp_tree, offset, 2, "Acknowledgement");
	    offset += 2;
	    i1 = ntohs(*(short *)(pd + offset));
	    add_item_to_tree(tftp_tree, offset, END_OF_FRAME, "Block = %u", i1);
	    break;
	  case ERROR:
	    add_item_to_tree(tftp_tree, offset, 2, "Error Code");
	    offset += 2;
	    i1 = ntohs(*(short *)(pd + offset));
	    add_item_to_tree(tftp_tree, offset, 2, "Code = %s", tftp_errors[i1 % 8]);
	    offset += 2;
	    add_item_to_tree(tftp_tree, offset, END_OF_FRAME, "Error Message: %s", pd + offset);
	    break;
	  default:
	    add_item_to_tree(tftp_tree, offset, 2, "Unknown TFTP Request: %0X.", i1);
	    offset += 2;
	    add_item_to_tree(tftp_tree, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);
	    break;
	  }

	}
}
