/* packet-telnet.c
 * Routines for telnet packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-telnet.c,v 1.25 2001/10/26 02:55:20 gram Exp $
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
#include "strutil.h"

static int proto_telnet = -1;

static gint ett_telnet = -1;
static gint ett_telnet_subopt = -1;

/* Some defines for Telnet */

#define TCP_PORT_TELNET			23

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
telnet_sub_option(proto_tree *telnet_tree, tvbuff_t *tvb, int start_offset)
{
  proto_tree *ti, *option_tree;
  int offset = start_offset;
  guint8 opt_byte;
  int subneg_len, req;
  const u_char *opt;
  guint len;

  offset += 2;	/* skip IAC and SB */

  /* Figure out the option and type */
  opt_byte = tvb_get_guint8(tvb, offset);
  if (opt_byte > NOPTIONS)
    opt = "<unknown option>";
  else
    opt = options[opt_byte];
  offset++;
  req = tvb_get_guint8(tvb, offset);
  offset++;

  /* Search for an IAC. */
  len = tvb_length_remaining(tvb, offset);
  offset = tvb_find_guint8(tvb, offset, len, TN_IAC);
  if (offset == -1) {
    /* None found - run to the end of the packet. */
    offset += len;
  }

  subneg_len = offset - start_offset;

  if (subneg_len > 0) {
      ti = proto_tree_add_text(telnet_tree, tvb, start_offset, subneg_len,
                "Suboption Begin: %s", opt);

      option_tree = proto_item_add_subtree(ti, ett_telnet_subopt);

      proto_tree_add_text(option_tree, tvb, start_offset + 2, 2,
                "%s %s", (req ? "Send your" : "Here's my"), opt);

      if (req == 0) {  /* Add the value */
        proto_tree_add_text(option_tree, tvb, start_offset + 4, subneg_len - 4,
        "Value: %s", tvb_format_text(tvb, start_offset + 4, subneg_len - 4));
      }
  }
  return offset;
}

static int
telnet_will_wont_do_dont(proto_tree *telnet_tree, tvbuff_t *tvb,
			int start_offset, char *type)
{
  int offset = start_offset;
  guint8 opt_byte;
  const char *opt;

  offset += 2;	/* skip IAC and WILL,WONT,DO,DONT} */
  opt_byte = tvb_get_guint8(tvb, offset);
  if (opt_byte > NOPTIONS)
    opt = "<unknown option>";
  else
    opt = options[opt_byte];
  offset++;
		      
  proto_tree_add_text(telnet_tree, tvb, start_offset, 3,
			"Command: %s %s", type, opt);
  return offset;
}

static int
telnet_command(proto_tree *telnet_tree, tvbuff_t *tvb, int start_offset)
{
  int offset = start_offset;
  u_char optcode;
  
  offset += 1;	/* skip IAC */
  optcode = tvb_get_guint8(tvb, offset);
  offset++;
  switch(optcode) {

  case TN_EOF:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: End of File");
    break;

  case TN_SUSP:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Suspend Current Process");
    break;

  case TN_ABORT:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Abort Process");
    break;

  case TN_EOR:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: End of Record");
    break;

  case TN_SE:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Suboption End");
    break;

  case TN_NOP:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: No Operation");
    break;

  case TN_DM:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Data Mark");
    break;

  case TN_BRK:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Break");
    break;

  case TN_IP:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Interrupt Process");
    break;

  case TN_AO:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Abort Output");
    break;

  case TN_AYT:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Are You There?");
    break;

  case TN_EC:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Escape Character");
    break;

  case TN_EL:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Erase Line");
    break;

  case TN_GA:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Go Ahead");
    break;

  case TN_SB:
    offset = telnet_sub_option(telnet_tree, tvb, start_offset);
    break;

  case TN_WILL:
    offset = telnet_will_wont_do_dont(telnet_tree, tvb, start_offset,
					"Will");
    break;

  case TN_WONT:
    offset = telnet_will_wont_do_dont(telnet_tree, tvb, start_offset,
					"Won't");
    break;

  case TN_DO:
    offset = telnet_will_wont_do_dont(telnet_tree, tvb, start_offset,
					"Do");
    break;

  case TN_DONT:
    offset = telnet_will_wont_do_dont(telnet_tree, tvb, start_offset,
					"Don't");
    break;
  }

  return offset;
}

static void
telnet_add_text(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
  gint next_offset;
  int linelen;
  guint8 c;
  gboolean last_char_was_cr;

  while (len != 0 && tvb_offset_exists(tvb, offset)) {
    /*
     * Find the end of the line.
     */
    linelen = tvb_find_line_end(tvb, offset, len, &next_offset);
    len -= next_offset - offset;	/* subtract out the line's characters */

    /*
     * In Telnet, CR NUL is the way you send a CR by itself in the
     * default ASCII mode; don't treat CR by itself as a line ending,
     * treat only CR NUL, CR LF, or LF by itself as a line ending.
     */
    if (next_offset == offset + linelen + 1 && len >= 1) {
      /*
       * Well, we saw a one-character line ending, so either it's a CR
       * or an LF; we have at least two characters left, including the
       * CR.
       *
       * If the line ending is a CR, skip all subsequent CRs; at
       * least one capture appeared to have multiple CRs at the end of
       * a line.
       */
      if (tvb_get_guint8(tvb, offset + linelen) == '\r') {
      	last_char_was_cr = TRUE;
      	while (len != 0 && tvb_offset_exists(tvb, next_offset)) {
          c = tvb_get_guint8(tvb, next_offset);
      	  next_offset++;	/* skip over that character */
      	  len--;
          if (c == '\n' || (c == '\0' && last_char_was_cr)) {
            /*
	     * LF is a line ending, whether preceded by CR or not.
	     * NUL is a line ending if preceded by CR.
	     */
            break;
          }
      	  last_char_was_cr = (c == '\r');
      	}
      }
    }

    /*
     * Now compute the length of the line *including* the end-of-line
     * indication, if any; we display it all.
     */
    linelen = next_offset - offset;

    proto_tree_add_text(tree, tvb, offset, linelen,
			"Data: %s",
			tvb_format_text(tvb, offset, linelen));
    offset = next_offset;
  }
}

static void
dissect_telnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree      *telnet_tree, *ti;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "TELNET");

	if (check_col(pinfo->fd, COL_INFO))
		col_add_fstr(pinfo->fd, COL_INFO, "Telnet Data ...");

	if (tree) {
	  gint offset = 0;
	  guint len;
	  int data_len;
	  gint iac_offset;

	  ti = proto_tree_add_item(tree, proto_telnet, tvb, offset,
	    tvb_length_remaining(tvb, offset), FALSE);
	  telnet_tree = proto_item_add_subtree(ti, ett_telnet);

	  /*
	   * Scan through the buffer looking for an IAC byte.
	   */
	  while ((len = tvb_length_remaining(tvb, offset)) > 0) {
	    iac_offset = tvb_find_guint8(tvb, offset, len, TN_IAC);
	    if (iac_offset != -1) {
	      /*
	       * We found an IAC byte.
	       * If there's any data before it, add that data to the
	       * tree, a line at a time.
	       */
	      data_len = iac_offset - offset;
	      if (data_len > 0)
	      	telnet_add_text(telnet_tree, tvb, offset, data_len);
	      
	      /*
	       * Now interpret the command.
	       */
	      offset = telnet_command(telnet_tree, tvb, iac_offset);
	    }
	    else {
	      /*
	       * We found no IAC byte, so what remains in the buffer
	       * is the last of the data in the packet.
	       * Add it to the tree, a line at a time, and then quit.
	       */
	      telnet_add_text(telnet_tree, tvb, offset, len);
	      break;
	    }
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

        proto_telnet = proto_register_protocol("Telnet", "TELNET", "telnet");
 /*       proto_register_field_array(proto_telnet, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_telnet(void)
{
	dissector_add("tcp.port", TCP_PORT_TELNET, dissect_telnet,
	    proto_telnet);
}
