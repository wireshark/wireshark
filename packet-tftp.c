/* packet-tftp.c
 * Routines for tftp packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-tftp.c,v 1.4 1999/07/07 22:51:56 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"

#define	RRQ	1
#define	WRQ	2
#define	DATA	3
#define	ACK	4
#define	ERROR	5

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
dissect_tftp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*tftp_tree;
	proto_item	*ti;
	u_int           i1;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TFTP");

	if (check_col(fd, COL_INFO)) {

	  i1 = pntohs(&pd[offset]);
	  col_add_fstr(fd, COL_INFO, "TFTP %s", i1 <= ERROR ? tftp_opcodes[i1 % 8] : "Unknown Request");

	}

	if (tree) {

	  ti = proto_tree_add_text(tree, offset, END_OF_FRAME,
				"Trivial File Transfer Protocol");
	  tftp_tree = proto_item_add_subtree(ti, ETT_TFTP);

	  switch (i1 = pntohs(pd+offset)) {
	  case RRQ:
	    proto_tree_add_text(tftp_tree, offset, 2, "Read Request");
	    offset += 2;
	    i1 = strlen(pd+offset);
	    proto_tree_add_text(tftp_tree, offset, i1+1, "Source File: %s", pd+offset);
	    offset += i1 + 1;
	    proto_tree_add_text(tftp_tree, offset, END_OF_FRAME, "Type: %s",pd+offset);
	    break;
	  case WRQ:
	    proto_tree_add_text(tftp_tree, offset, 2, "Write Request");
	    offset += 2;
	    i1 = strlen(pd+offset);
	    proto_tree_add_text(tftp_tree, offset, i1+1, "Destination File: %s", pd+offset);
	    offset += i1 + 1;
	    proto_tree_add_text(tftp_tree, offset+2, END_OF_FRAME, "Type: %s",pd+offset);
	    break;
	  case DATA:
	    proto_tree_add_text(tftp_tree, offset, 2, "Data Packet");
	    offset += 2;
	    i1 = pntohs(pd+offset);
	    proto_tree_add_text(tftp_tree, offset, 2, "Block = %u", i1);
	    offset += 2;
	    proto_tree_add_text(tftp_tree, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);
	    break;
	  case ACK:
	    proto_tree_add_text(tftp_tree, offset, 2, "Acknowledgement");
	    offset += 2;
	    i1 = pntohs(pd+offset);
	    proto_tree_add_text(tftp_tree, offset, END_OF_FRAME, "Block = %u", i1);
	    break;
	  case ERROR:
	    proto_tree_add_text(tftp_tree, offset, 2, "Error Code");
	    offset += 2;
	    i1 = pntohs(pd+offset);
	    proto_tree_add_text(tftp_tree, offset, 2, "Code = %s", tftp_errors[i1 % 8]);
	    offset += 2;
	    proto_tree_add_text(tftp_tree, offset, END_OF_FRAME, "Error Message: %s", pd + offset);
	    break;
	  default:
	    proto_tree_add_text(tftp_tree, offset, 2, "Unknown TFTP Request: %0X.", i1);
	    offset += 2;
	    proto_tree_add_text(tftp_tree, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);
	    break;
	  }

	}
}
