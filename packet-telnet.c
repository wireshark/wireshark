/* packet-telnet.c
 * Routines for Telnet packet dissection; see RFC 854 and RFC 855
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-telnet.c,v 1.35 2003/02/24 01:04:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_telnet = -1;

static gint ett_telnet = -1;
static gint ett_telnet_subopt = -1;
static gint ett_status_subopt = -1;
static gint ett_rcte_subopt = -1;
static gint ett_olw_subopt = -1;
static gint ett_ops_subopt = -1;
static gint ett_crdisp_subopt = -1;
static gint ett_htstops_subopt = -1;
static gint ett_htdisp_subopt = -1;
static gint ett_ffdisp_subopt = -1;
static gint ett_vtstops_subopt = -1;
static gint ett_vtdisp_subopt = -1;
static gint ett_lfdisp_subopt = -1;
static gint ett_extasc_subopt = -1;
static gint ett_bytemacro_subopt = -1;
static gint ett_det_subopt = -1;
static gint ett_supdupout_subopt = -1;
static gint ett_sendloc_subopt = -1;
static gint ett_termtype_subopt = -1;
static gint ett_tacacsui_subopt = -1;
static gint ett_outmark_subopt = -1;
static gint ett_tlocnum_subopt = -1;
static gint ett_tn3270reg_subopt = -1;
static gint ett_x3pad_subopt = -1;
static gint ett_naws_subopt = -1;
static gint ett_tspeed_subopt = -1;
static gint ett_rfc_subopt = -1;
static gint ett_linemode_subopt = -1;
static gint ett_xdpyloc_subopt = -1;
static gint ett_env_subopt = -1;
static gint ett_auth_subopt = -1;
static gint ett_enc_subopt = -1;
static gint ett_newenv_subopt = -1;
static gint ett_tn3270e_subopt = -1;

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

typedef enum {
  NO_LENGTH,		/* option has no data, hence no length */
  FIXED_LENGTH,		/* option always has the same length */
  VARIABLE_LENGTH	/* option is variable-length - optlen is minimum */
} tn_opt_len_type;

/* Member of table of IP or TCP options. */
typedef struct tn_opt {
  char  *name;			/* name of option */
  gint  *subtree_index;		/* pointer to subtree index for option */
  tn_opt_len_type len_type;	/* type of option length field */
  int	optlen;			/* value length should be (minimum if VARIABLE) */
  void	(*dissect)(const char *, tvbuff_t *, int, int, proto_tree *);
				/* routine to dissect option */
} tn_opt;

static void
dissect_string_subopt(const char *optname, tvbuff_t *tvb, int offset, int len,
                      proto_tree *tree)
{
  guint8 cmd;

  cmd = tvb_get_guint8(tvb, offset);
  switch (cmd) {

  case 0:	/* IS */
    proto_tree_add_text(tree, tvb, offset, 1, "Here's my %s", optname);
    offset++;
    len--;
    if (len > 0) {
      proto_tree_add_text(tree, tvb, offset, len, "Value: %s",
                          tvb_format_text(tvb, offset, len));
    }
    break;

  case 1:	/* SEND */
    proto_tree_add_text(tree, tvb, offset, 1, "Send your %s", optname);
    offset++;
    len--;
    if (len > 0)
      proto_tree_add_text(tree, tvb, offset, len, "Extra data");
    break;

  default:
    proto_tree_add_text(tree, tvb, offset, 1, "Invalid %s subcommand %u",
                        optname, cmd);
    offset++;
    len--;
    if (len > 0)
      proto_tree_add_text(tree, tvb, offset, len, "Subcommand data");
    break;
  }
}

static void
dissect_outmark_subopt(const char *optname _U_, tvbuff_t *tvb, int offset,
                       int len, proto_tree *tree)
{
  guint8 cmd;
  int gs_offset, datalen;

  while (len > 0) {
    cmd = tvb_get_guint8(tvb, offset);
    switch (cmd) {

    case 6:	/* ACK */
      proto_tree_add_text(tree, tvb, offset, 1, "ACK");
      break;

    case 21:	/* NAK */
      proto_tree_add_text(tree, tvb, offset, 1, "NAK");
      break;

    case 'D':
      proto_tree_add_text(tree, tvb, offset, 1, "Default");
      break;

    case 'T':
      proto_tree_add_text(tree, tvb, offset, 1, "Top");
      break;

    case 'B':
      proto_tree_add_text(tree, tvb, offset, 1, "Bottom");
      break;

    case 'L':
      proto_tree_add_text(tree, tvb, offset, 1, "Left");
      break;

    case 'R':
      proto_tree_add_text(tree, tvb, offset, 1, "Right");
      break;

    default:
      proto_tree_add_text(tree, tvb, offset, 1, "Bogus value: %u", cmd);
      break;
    }
    offset++;
    len--;

    /* Look for a GS */
    gs_offset = tvb_find_guint8(tvb, offset, len, 29);
    if (gs_offset == -1) {
      /* None found - run to the end of the packet. */
      gs_offset = offset + len;
    }
    datalen = gs_offset - offset;
    if (datalen > 0) {
      proto_tree_add_text(tree, tvb, offset, datalen, "Banner: %s",
                          tvb_format_text(tvb, offset, datalen));
      offset += datalen;
      len -= datalen;
    }
  }
}

static void
dissect_htstops_subopt(const char *optname, tvbuff_t *tvb, int offset, int len,
                       proto_tree *tree)
{
  guint8 cmd;
  guint8 tabval;

  cmd = tvb_get_guint8(tvb, offset);
  switch (cmd) {

  case 0:	/* IS */
    proto_tree_add_text(tree, tvb, offset, 1, "Here's my %s", optname);
    offset++;
    len--;
    break;

  case 1:	/* SEND */
    proto_tree_add_text(tree, tvb, offset, 1, "Send your %s", optname);
    offset++;
    len--;
    break;

  default:
    proto_tree_add_text(tree, tvb, offset, 1, "Invalid %s subcommand %u",
                        optname, cmd);
    offset++;
    len--;
    if (len > 0)
      proto_tree_add_text(tree, tvb, offset, len, "Subcommand data");
    return;
  }

  while (len > 0) {
    tabval = tvb_get_guint8(tvb, offset);
    switch (tabval) {

    case 0:
      proto_tree_add_text(tree, tvb, offset, 1,
                          "Sender wants to handle tab stops");
      break;

    default:
      proto_tree_add_text(tree, tvb, offset, 1,
                          "Sender wants receiver to handle tab stop at %u",
                          tabval);
      break;

    case 251:
    case 252:
    case 253:
    case 254:
      proto_tree_add_text(tree, tvb, offset, 1,
                          "Invalid value: %u", tabval);
      break;

    case 255:
      proto_tree_add_text(tree, tvb, offset, 1,
                          "Sender wants receiver to handle tab stops");
      break;
    }
    offset++;
    len--;
  }
}

static void
dissect_naws_subopt(const char *optname _U_, tvbuff_t *tvb, int offset,
                    int len _U_, proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, 2, "Width: %u",
                      tvb_get_ntohs(tvb, offset));
  offset += 2;
  proto_tree_add_text(tree, tvb, offset, 2, "Height: %u",
                      tvb_get_ntohs(tvb, offset));
}

static const value_string rfc_opt_vals[] = {
	{ 0, "OFF" },
	{ 1, "ON" },
	{ 2, "RESTART-ANY" },
	{ 3, "RESTART-XON" },
	{ 0, NULL }
};

static void
dissect_rfc_subopt(const char *optname _U_, tvbuff_t *tvb, int offset,
                   int len _U_, proto_tree *tree)
{
  guint8 cmd;

  cmd = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2, "%s",
                      val_to_str(cmd, rfc_opt_vals, "Unknown (%u)"));
}

static void
dissect_subopt(const char *optname _U_, tvbuff_t *tvb, int offset, int len,
                    proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, len, "Option data");
}

static tn_opt options[] = {
  {
    "Binary Transmission",			/* RFC 856 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Echo",					/* RFC 857 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {    
    "Reconnection",				/* DOD Protocol Handbook */
    NULL,
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Suppress Go Ahead",			/* RFC 858 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Approx Message Size Negotiation",		/* Ethernet spec(!) */
    NULL,
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Status",					/* RFC 859 */
    &ett_status_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Timing Mark",				/* RFC 860 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Remote Controlled Trans and Echo",		/* RFC 726 */
    &ett_rcte_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Line Width",			/* DOD Protocol Handbook */
    &ett_olw_subopt,
    VARIABLE_LENGTH,				/* XXX - fill me in */
    0,						/* XXX - fill me in */
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Page Size",				/* DOD Protocol Handbook */
    &ett_ops_subopt,
    VARIABLE_LENGTH,				/* XXX - fill me in */
    0,						/* XXX - fill me in */
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Carriage-Return Disposition",	/* RFC 652 */
    &ett_crdisp_subopt,
    FIXED_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Horizontal Tab Stops",		/* RFC 653 */
    &ett_htstops_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_htstops_subopt
  },
  {
    "Output Horizontal Tab Disposition",	/* RFC 654 */
    &ett_htdisp_subopt,
    FIXED_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Formfeed Disposition",		/* RFC 655 */
    &ett_ffdisp_subopt,
    FIXED_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Vertical Tabstops",			/* RFC 656 */
    &ett_vtstops_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Vertical Tab Disposition",		/* RFC 657 */
    &ett_vtdisp_subopt,
    FIXED_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Linefeed Disposition",		/* RFC 658 */
    &ett_lfdisp_subopt,
    FIXED_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Extended ASCII",				/* RFC 698 */
    &ett_extasc_subopt,
    FIXED_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Logout",					/* RFC 727 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Byte Macro",				/* RFC 735 */
    &ett_bytemacro_subopt,
    VARIABLE_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Data Entry Terminal",			/* RFC 732, RFC 1043 */
    &ett_det_subopt,
    VARIABLE_LENGTH,
    2,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "SUPDUP",					/* RFC 734, RFC 736 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "SUPDUP Output",				/* RFC 749 */
    &ett_supdupout_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Send Location",				/* RFC 779 */
    &ett_sendloc_subopt,
    VARIABLE_LENGTH,
    0,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Terminal Type",				/* RFC 1091 */
    &ett_termtype_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_string_subopt
  },
  {
    "End of Record",				/* RFC 885 */
    NULL,					/* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "TACACS User Identification",		/* RFC 927 */
    &ett_tacacsui_subopt,
    FIXED_LENGTH,
    4,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Output Marking",				/* RFC 933 */
    &ett_outmark_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_outmark_subopt,
  },
  {
    "Terminal Location Number",			/* RFC 946 */
    &ett_tlocnum_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Telnet 3270 Regime",			/* RFC 1041 */
    &ett_tn3270reg_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "X.3 PAD",					/* RFC 1053 */
    &ett_x3pad_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Negotiate About Window Size",		/* RFC 1073, DW183 */
    &ett_naws_subopt,
    FIXED_LENGTH,
    4,
    dissect_naws_subopt
  },
  {
    "Terminal Speed",				/* RFC 1079 */
    &ett_tspeed_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Remote Flow Control",			/* RFC 1372 */
    &ett_rfc_subopt,
    FIXED_LENGTH,
    1,
    dissect_rfc_subopt
  },
  {
    "Linemode",					/* RFC 1184 */
    &ett_linemode_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "X Display Location",			/* RFC 1096 */
    &ett_xdpyloc_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_string_subopt
  },
  {
    "Environment Option",			/* RFC 1408, RFC 1571 */
    &ett_env_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Authentication Option",			/* RFC 2941 */
    &ett_auth_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "Encryption Option",			/* RFC 2946 */
    &ett_enc_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "New Environment Option",			/* RFC 1572 */
    &ett_newenv_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
  {
    "TN3270E",					/* RFC 1647 */
    &ett_tn3270e_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_subopt				/* XXX - fill me in */
  },
};

#define	NOPTIONS	(sizeof options / sizeof options[0])

static int
telnet_sub_option(proto_tree *telnet_tree, tvbuff_t *tvb, int start_offset)
{
  proto_tree *ti, *option_tree;
  int offset = start_offset;
  guint8 opt_byte;
  int subneg_len;
  const char *opt;
  gint ett;
  int iac_offset;
  guint len;
  void (*dissect)(const char *, tvbuff_t *, int, int, proto_tree *);

  offset += 2;	/* skip IAC and SB */

  /* Get the option code */
  opt_byte = tvb_get_guint8(tvb, offset);
  if (opt_byte > NOPTIONS) {
    opt = "<unknown option>";
    ett = ett_telnet_subopt;
    dissect = NULL;
  } else {
    opt = options[opt_byte].name;
    if (options[opt_byte].subtree_index != NULL)
      ett = *(options[opt_byte].subtree_index);
    else
      ett = ett_telnet_subopt;
    dissect = options[opt_byte].dissect;
  }
  offset++;

  /* Search for an IAC. */
  len = tvb_length_remaining(tvb, offset);
  iac_offset = tvb_find_guint8(tvb, offset, len, TN_IAC);
  if (iac_offset == -1) {
    /* None found - run to the end of the packet. */
    offset += len;
  } else
    offset = iac_offset;

  subneg_len = offset - start_offset;

  ti = proto_tree_add_text(telnet_tree, tvb, start_offset, subneg_len,
                           "Suboption Begin: %s", opt);
  option_tree = proto_item_add_subtree(ti, ett);
  start_offset += 3;	/* skip IAC, SB, and option code */
  subneg_len -= 3;

  if (subneg_len > 0) {
    switch (options[opt_byte].len_type) {

    case NO_LENGTH:
      /* There isn't supposed to *be* sub-option negotiation for this. */
      proto_tree_add_text(option_tree, tvb, start_offset, subneg_len,
                          "Bogus suboption data");
      return offset;

    case FIXED_LENGTH:
      /* Make sure the length is what it's supposed to be. */
      if (subneg_len != options[opt_byte].optlen) {
        proto_tree_add_text(option_tree, tvb, start_offset, subneg_len,
                          "Suboption parameter length is %d, should be %d",
                          subneg_len, options[opt_byte].optlen);
        return offset;
      }
      break;

    case VARIABLE_LENGTH:
      /* Make sure the length is greater than the minimum. */
      if (subneg_len < options[opt_byte].optlen) {
        proto_tree_add_text(option_tree, tvb, start_offset, subneg_len,
                            "Suboption parameter length is %d, should be at least %d",
                            subneg_len, options[opt_byte].optlen);
        return offset;
      }
      break;
    }

    /* Now dissect the suboption parameters. */
    (*dissect)(opt, tvb, start_offset, subneg_len, option_tree);
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
    opt = options[opt_byte].name;
  offset++;

  proto_tree_add_text(telnet_tree, tvb, start_offset, 3,
			"Command: %s %s", type, opt);
  return offset;
}

static int
telnet_command(proto_tree *telnet_tree, tvbuff_t *tvb, int start_offset)
{
  int offset = start_offset;
  guchar optcode;

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

  default:
    proto_tree_add_text(telnet_tree, tvb, start_offset, 2,
			"Command: Unknown (0x%02x)", optcode);
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
    linelen = tvb_find_line_end(tvb, offset, len, &next_offset, FALSE);
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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TELNET");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "Telnet Data ...");

	if (tree) {
	  gint offset = 0;
	  guint len;
	  int data_len;
	  gint iac_offset;

	  ti = proto_tree_add_item(tree, proto_telnet, tvb, offset, -1, FALSE);
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
		&ett_status_subopt,
		&ett_rcte_subopt,
		&ett_olw_subopt,
		&ett_ops_subopt,
		&ett_crdisp_subopt,
		&ett_htstops_subopt,
		&ett_htdisp_subopt,
		&ett_ffdisp_subopt,
		&ett_vtstops_subopt,
		&ett_vtdisp_subopt,
		&ett_lfdisp_subopt,
		&ett_extasc_subopt,
		&ett_bytemacro_subopt,
		&ett_det_subopt,
		&ett_supdupout_subopt,
		&ett_sendloc_subopt,
		&ett_termtype_subopt,
		&ett_tacacsui_subopt,
		&ett_outmark_subopt,
		&ett_tlocnum_subopt,
		&ett_tn3270reg_subopt,
		&ett_x3pad_subopt,
		&ett_naws_subopt,
		&ett_tspeed_subopt,
		&ett_rfc_subopt,
		&ett_linemode_subopt,
		&ett_xdpyloc_subopt,
		&ett_env_subopt,
		&ett_auth_subopt,
		&ett_enc_subopt,
		&ett_newenv_subopt,
		&ett_tn3270e_subopt,
	};

        proto_telnet = proto_register_protocol("Telnet", "TELNET", "telnet");
 /*       proto_register_field_array(proto_telnet, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_telnet(void)
{
	dissector_handle_t telnet_handle;

	telnet_handle = create_dissector_handle(dissect_telnet, proto_telnet);
	dissector_add("tcp.port", TCP_PORT_TELNET, telnet_handle);
}
