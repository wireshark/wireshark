/* packet-telnet.c
 * Routines for telnet packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-telnet.c,v 1.10 2000/03/23 10:49:33 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_telnet = -1;

static gint ett_telnet = -1;
static gint ett_telnet_subopt = -1;

/* Some defines for Telnet */

#define TN_IAC   255
#define TN_DONT  254
#define TN_DO    253
#define TN_WONT  252
#define TN_WILL  251
#define TN_SB    250
#define TN_GA    249
#define TN_EL    248
#define TN_EC    247
#define TN_AYT   246
#define TN_AO    245
#define TN_IP    244
#define TN_BRK   243
#define TN_DM    242
#define TN_NOP   241
#define TN_SE    240
#define TN_EOR   239
#define TN_ABORT 238
#define TN_SUSP  237
#define TN_EOF   236

static const char *options[] = {
  "Binary Transmission",
  "Echo",
  "Reconnection",
  "Suppress Go Ahead",
  "Approx Message Size Negotiation",
  "Status",
  "Timing Mark",
  "Remote Controlled Trans and Echo",
  "Output Line Width",
  "Output Page Size",
  "Output Carriage-Return Disposition",
  "Output Horizontal Tab Stops",
  "Output Horizontal Tab Disposition",
  "Output Formfeed Disposition",
  "Output Vertical Tabstops",
  "Output Vertical Tab Disposition",
  "Output Linefeed Disposition",
  "Extended ASCII",
  "Logout",
  "Byte Macro",
  "Data Entry Terminal",
  "SUPDUP",
  "SUPDUP Output",
  "Send Location",
  "Terminal Type",
  "End of Record",
  "TACACS User Identification",
  "Output Marking",
  "Terminal Location Number",
  "Telnet 3270 Regime",
  "X.3 PAD",
  "Negotiate About Window Size",
  "Terminal Speed",
  "Remote Flow Control",
  "Linemode",
  "X Display Location",
  "Environment Option",
  "Authentication Option",
  "Encryption Option",
  "New Environment Option",
  "TN3270E"
};

#define	NOPTIONS	(sizeof options / sizeof options[0])

static int
telnet_sub_option(proto_tree *telnet_tree, const u_char *pd,
		int start_offset)
{
  proto_tree *ti, *option_tree;
  int offset = start_offset;
  int subneg_len, req;
  gboolean not_found = TRUE;
  const u_char *opt;

  offset += 2;	/* skip IAC and SB */

  /* Figure out the option and type */
  if (pd[offset] > NOPTIONS)
    opt = "<unknown option>";
  else
    opt = options[pd[offset]];
  offset++;
  req = pd[offset];
  offset++;

  while (offset < pi.captured_len && not_found) {  
    if (pd[offset] == TN_IAC)
      not_found = FALSE;
    else
      offset++;
  }

  subneg_len = offset - start_offset;

  ti = proto_tree_add_text(telnet_tree, start_offset, subneg_len,
			"Suboption Begin: %s", opt);

  option_tree = proto_item_add_subtree(ti, ett_telnet_subopt);

  proto_tree_add_text(option_tree, start_offset + 2, 2,
			"%s %s", (req ? "Send your" : "Here's my"), opt);

  if (req == 0) {  /* Add the value */
    proto_tree_add_text(option_tree, start_offset + 4, subneg_len - 4,
	"Value: %s", format_text(&pd[start_offset + 4], subneg_len - 4));
  }
  return offset;
}

static int
telnet_will_wont_do_dont(proto_tree *telnet_tree, const u_char *pd,
			int start_offset, char *type)
{
  int offset = start_offset;
  const char *opt;

  offset += 2;	/* skip IAC and WILL,WONT,DO,DONT} */
  if (pd[offset] > NOPTIONS)
    opt = "<unknown option>";
  else
    opt = options[pd[offset]];
  offset++;
		      
  proto_tree_add_text(telnet_tree, start_offset, 3,
			"Command: %s %s", type, opt);
  return offset;
}

static int
telnet_command(proto_tree *telnet_tree, const u_char *pd, int start_offset)
{
  int offset = start_offset;
  u_char optcode;
  
  offset += 1;	/* skip IAC */
  optcode = pd[offset];
  offset++;
  switch(optcode) {

  case TN_EOF:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: End of File");
    break;

  case TN_SUSP:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Suspend Current Process");
    break;

  case TN_ABORT:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Abort Process");
    break;

  case TN_EOR:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: End of Record");
    break;

  case TN_SE:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Suboption End");
    break;

  case TN_NOP:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: No Operation");
    break;

  case TN_DM:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Data Mark");
    break;

  case TN_BRK:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Break");
    break;

  case TN_IP:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Interrupt Process");
    break;

  case TN_AO:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Abort Output");
    break;

  case TN_AYT:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Are You There?");
    break;

  case TN_EC:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Escape Character");
    break;

  case TN_EL:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Erase Line");
    break;

  case TN_GA:
    proto_tree_add_text(telnet_tree, start_offset, 2,
			"Command: Go Ahead");
    break;

  case TN_SB:
    offset = telnet_sub_option(telnet_tree, pd, start_offset);
    break;

  case TN_WILL:
    offset = telnet_will_wont_do_dont(telnet_tree, pd, start_offset,
					"Will");
    break;

  case TN_WONT:
    offset = telnet_will_wont_do_dont(telnet_tree, pd, start_offset,
					"Won't");
    break;

  case TN_DO:
    offset = telnet_will_wont_do_dont(telnet_tree, pd, start_offset,
					"Do");
    break;

  case TN_DONT:
    offset = telnet_will_wont_do_dont(telnet_tree, pd, start_offset,
					"Don't");
    break;
  }

  return offset;
}

void
dissect_telnet(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        proto_tree      *telnet_tree, *ti;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TELNET");

	if (check_col(fd, COL_INFO))
	  col_add_fstr(fd, COL_INFO, "Telnet Data ...");

	if (tree) {
	  int data_offset;
	  int data_len;

	  ti = proto_tree_add_item(tree, proto_telnet, offset, END_OF_FRAME, NULL);
	  telnet_tree = proto_item_add_subtree(ti, ett_telnet);

	  data_offset = offset;
	  data_len = 0;

	  /*
	   * Scan through the buffer looking for an IAC byte.
	   */
	  while (offset < pi.captured_len) {
	    if (pd[offset] == TN_IAC) {
	      /*
	       * We found an IAC byte.
	       * If there's any data before it, add that data to the
	       * tree.
	       */
	      if (data_len > 0) {
		proto_tree_add_text(telnet_tree, data_offset, data_len,
			"Data: %s", format_text(&pd[data_offset], data_len));
		data_len = 0;
		data_offset = offset;
	      }
	      
	      /*
	       * Now interpret the command.
	       */
	      offset = telnet_command(telnet_tree, pd, offset);
	      data_offset = offset;
	    }
	    else {
	      data_len++;
	      offset++;
	    }
	  }

	  /*
	   * We've reached the end of the buffer.
	   * If there's any data left, add it to the tree.
	   */
	  if (data_len > 0) {
	    proto_tree_add_text(telnet_tree, data_offset, data_len, "Data: %s",
	    		format_text(&pd[data_offset], data_len));
	  }
	}
}

void
proto_register_telnet(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "telnet.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_telnet,
		&ett_telnet_subopt,
	};

        proto_telnet = proto_register_protocol("Telnet", "telnet");
 /*       proto_register_field_array(proto_telnet, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
