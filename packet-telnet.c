/* packet-pop.c
 * Routines for telnet packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-telnet.c,v 1.4 1999/07/29 05:47:05 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
#include "etypes.h"

static int proto_telnet = -1;

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

char *options[] = {
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

extern packet_info pi;

void telnet_sub_option(proto_tree *telnet_tree, char *rr, int *i, int offset, int max_data)
{
  proto_tree *ti, *option_tree;
  int subneg_len, req, si1, not_found = 1;
  volatile int i1;
  char *opt, sub_opt_data[1500];

  memset(sub_opt_data, '\0', sizeof(sub_opt_data));

  /* Figure out the option and type */

  opt = options[(unsigned int)rr[*i]];
  req = (unsigned int)rr[*i + 1];

  i1 = *i + 2; si1 = i1;
  while ((i1 < max_data) && (not_found)) {  

    if ((unsigned char)rr[i1] == (unsigned char)TN_IAC)
      not_found = 0;
    else
      i1++;

  }

  subneg_len = i1 - *i + 2;

  ti = proto_tree_add_text(telnet_tree, offset, subneg_len, "Suboption Begin: %s", opt);

  option_tree = proto_item_add_subtree(ti, ETT_TELNET_SUBOPT);

  proto_tree_add_text(option_tree, offset + 2, subneg_len - 2, "%s %s", (req ? "Send your" : "Here's my"), opt);

  if (req == 0) {  /* Add the value */

    memcpy(sub_opt_data, rr + *i + 2, subneg_len - 2);
    proto_tree_add_text(option_tree, offset + 4, subneg_len - 4, "Value: %s", format_text(sub_opt_data, subneg_len - 4));
    *i += subneg_len - 2;

  }
  else {

    *i += subneg_len - 2;

  }
}

void telnet_command(proto_tree *telnet_tree, char *rr, int *i, int offset, int max_data) 
{
  char *opt;
  
  switch((unsigned char)rr[*i]) {

  case TN_EOF:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: End of File");
    (*i)++;
    break;

  case TN_SUSP:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Suspend Current Process");
    (*i)++;
    break;

  case TN_ABORT:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Abort Process");
    (*i)++;
    break;

  case TN_EOR:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: End of Record");
    (*i)++;
    break;

  case TN_SE:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Suboption End");
    (*i)++;
    break;

  case TN_NOP:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: No Operation");
    (*i)++;
    break;

  case TN_DM:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Data Mark");
    (*i)++;
    break;

  case TN_BRK:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Break");
    (*i)++;
    break;

  case TN_IP:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Interrupt Process");
    (*i)++;
    break;

  case TN_AO:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Abort Output");
    (*i)++;
    break;

  case TN_AYT:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Are You There?");
    (*i)++;
    break;

  case TN_EC:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Escape Character");
    (*i)++;
    break;

  case TN_EL:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Erase Line");
    (*i)++;
    break;

  case TN_GA:

    proto_tree_add_text(telnet_tree, offset, 2, "Command: Go Ahead");
    (*i)++;
    break;

  case TN_SB:

    (*i)++;
    telnet_sub_option(telnet_tree, rr, i, offset, max_data);
    break;

  case TN_WILL:

    if (rr[*i + 1] > (sizeof(options)/sizeof(char *)))
      opt = "<unknown option>";
    else
      opt = options[(unsigned int)rr[*i + 1]];
		      
    proto_tree_add_text(telnet_tree, offset, 3, "Command: Will %s", opt);
    *i += 2; /* skip two chars */
    break;

  case TN_WONT:

    if (rr[*i + 1] > (sizeof(options)/sizeof(char *)))
      opt = "<unknown option>";
    else
      opt = options[(unsigned int)rr[*i + 1]];
		      
    proto_tree_add_text(telnet_tree, offset, 3, "Command: Won't %s", opt);
    *i += 2; /* skip two chars */
    break;

  case TN_DO:

    if (rr[*i + 1] > (sizeof(options)/sizeof(char *)))
      opt = "<unknown option>";
    else
      opt = options[(unsigned int)rr[*i + 1]];
		      
    proto_tree_add_text(telnet_tree, offset, 3, "Command: Do %s", opt);
    *i += 2; /* skip two chars */
    break;

  case TN_DONT:

    if (rr[*i + 1] > (sizeof(options)/sizeof(char *)))
      opt = "<unknown option>";
    else
      opt = options[(unsigned int)rr[*i + 1]];
		      
    proto_tree_add_text(telnet_tree, offset, 3, "Command: Don't %s", opt);
    *i += 2; /* skip two chars */
    break;

  }

}

void
dissect_telnet(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data)
{
        proto_tree      *telnet_tree, *ti;
	gchar           rr[1500];
	int i1;
	int i2;

	memset(rr, '\0', sizeof(rr));

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TELNET");

	if (check_col(fd, COL_INFO)) {

	  col_add_fstr(fd, COL_INFO, "Telnet Data ...");

	}

	if (tree) {

	  char data[1500];
	  int i3;

	  memset(data, '\0', sizeof(data));

	  memcpy(rr, pd + offset, max_data);

	  ti = proto_tree_add_item(tree, proto_telnet, offset, END_OF_FRAME, NULL);
	  telnet_tree = proto_item_add_subtree(ti, ETT_TELNET);

	  i1 = i2 = i3 = 0;

	  while (i1 < max_data) {

	    if ((unsigned char)rr[i1] == (unsigned char)TN_IAC) {

	      if (strlen(data) > 0) {

		proto_tree_add_text(telnet_tree, offset + i2, strlen(data), "Data: %s", format_text(data, strlen(data)));
		memset(data, '\0', sizeof(data));
		i3 = 0;

	      }
	      
	      i1++;
	      telnet_command(telnet_tree, rr, &i1, offset + i1 - 1, max_data);
	      i2 = i1;

	    }
	    else {

	      data[i3] = rr[i1];
	      i3++;
	      i1++;


	    }
	  }

	  if (strlen(data) > 0) { /* Still some data to add */

	    proto_tree_add_text(telnet_tree, offset + i2, strlen(data), "Data: %s", format_text(data, strlen(data)));

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

        proto_telnet = proto_register_protocol("Telnet", "telnet");
 /*       proto_register_field_array(proto_telnet, hf, array_length(hf));*/
}
