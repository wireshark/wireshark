/* packet-tftp.c
 * Routines for tftp packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 * Craig Newell <CraigN@cheque.uq.edu.au>
 *	RFC2347 TFTP Option Extension
 *
 * $Id: packet-tftp.c,v 1.13 2000/08/13 14:09:05 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

static int proto_tftp = -1;
static int hf_tftp_type = -1;
static int hf_tftp_error_code = -1;

static gint ett_tftp = -1;

#define	RRQ	1
#define	WRQ	2
#define	DATA	3
#define	ACK	4
#define	ERROR	5
#define OACK	6

char *tftp_opcodes[8] = {
  "Unknown Request",
  "Read Request",
  "Write Request",
  "Data Packet",
  "Acknowledgement",
  "Error Code",
  "Option Acknowledgement",
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

	OLD_CHECK_DISPLAY_AS_DATA(proto_tftp, pd, offset, fd, tree);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TFTP");

	if (check_col(fd, COL_INFO)) {

	  i1 = pntohs(&pd[offset]);
	  col_add_fstr(fd, COL_INFO, "TFTP %s", i1 <= OACK ? tftp_opcodes[i1 % 8] : "Unknown Request");

	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_tftp, NullTVB, offset, END_OF_FRAME, FALSE);
	  tftp_tree = proto_item_add_subtree(ti, ett_tftp);

	  i1 = pntohs(pd+offset);
	  proto_tree_add_uint_hidden(tftp_tree, hf_tftp_type, NullTVB, offset, 2, i1);
	    
	  switch (i1) {
	  case RRQ:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Read Request");
	    offset += 2;
	    i1 = strlen(pd+offset);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, i1+1, "Source File: %s", pd+offset);
	    offset += i1 + 1;
	    i1 = strlen(pd+offset);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, i1+1, "Type: %s",pd+offset);
	    offset += i1 + 1;
	    while (offset < pi.captured_len) {
	      int i2;
	      i1 = strlen(pd+offset);			/* length of option */
	      i2 = strlen(pd+offset+i1+1);		/* length of value */
	      proto_tree_add_text(tftp_tree, NullTVB, offset, i1+i2+2, "Option: %s = %s", 
                pd+offset, pd+offset+i1+1);
	      offset += i1 + i2 + 2;
	    }
	    break;
	  case WRQ:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Write Request");
	    offset += 2;
	    i1 = strlen(pd+offset);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, i1+1, "Destination File: %s", pd+offset);
	    offset += i1 + 1;
	    i1 = strlen(pd+offset);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, i1+1, "Type: %s",pd+offset);
	    offset += i1 + 1;
	    while (offset < pi.captured_len) {
	      int i2;
	      i1 = strlen(pd+offset);			/* length of option */
	      i2 = strlen(pd+offset+i1+1);		/* length of value */
	      proto_tree_add_text(tftp_tree, NullTVB, offset, i1+i2+2, "Option: %s = %s", 
                pd+offset, pd+offset+i1+1);
	      offset += i1 + i2 + 2;
	    }
	    break;
	  case DATA:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Data Packet");
	    offset += 2;
	    i1 = pntohs(pd+offset);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Block = %u", i1);
	    offset += 2;
	    proto_tree_add_text(tftp_tree, NullTVB, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);
	    break;
	  case ACK:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Acknowledgement");
	    offset += 2;
	    i1 = pntohs(pd+offset);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, END_OF_FRAME, "Block = %u", i1);
	    break;
	  case ERROR:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Error Code");
	    offset += 2;
	    i1 = pntohs(pd+offset);
	    proto_tree_add_uint_hidden(tftp_tree, hf_tftp_error_code, NullTVB, offset, 2, i1);
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Code = %s", tftp_errors[i1 % 8]);
	    offset += 2;
	    proto_tree_add_text(tftp_tree, NullTVB, offset, END_OF_FRAME, "Error Message: %s", pd + offset);
	    break;
	  case OACK:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Option Acknowledgement");
	    offset += 2;
	    while (offset < pi.captured_len) {
	      int i2;
	      i1 = strlen(pd+offset);			/* length of option */
	      i2 = strlen(pd+offset+i1+1);		/* length of value */
	      proto_tree_add_text(tftp_tree, NullTVB, offset, i1+i2+2, "Option: %s = %s", 
                pd+offset, pd+offset+i1+1);
	      offset += i1 + i2 + 2;
	    }
	    break;
	  default:
	    proto_tree_add_text(tftp_tree, NullTVB, offset, 2, "Unknown TFTP Request: %0X.", i1);
	    offset += 2;
	    proto_tree_add_text(tftp_tree, NullTVB, offset, END_OF_FRAME,
		"Data (%d bytes)", END_OF_FRAME);
	    break;
	  }

	}
}

void
proto_register_tftp(void)
{

  static hf_register_info hf[] = {
    { &hf_tftp_type,
      { "Type",		      "tftp.type",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"TFTP message type" }},

    { &hf_tftp_error_code,
      { "Error code",         "tftp.error.code",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Error code in case of TFTP error message" }}
  };
  static gint *ett[] = {
    &ett_tftp,
  };

  proto_tftp = proto_register_protocol("Trivial File Transfer Protocol", "tftp");
  proto_register_field_array(proto_tftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}
