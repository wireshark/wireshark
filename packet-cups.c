/* packet-cups.c
* Routines for Common Unix Printing System (CUPS) Browsing Protocol
* packet disassembly for the Ethereal network traffic analyzer.
*
* Charles Levert <charles@comm.polymtl.ca>
* Copyright 2001 Charles Levert
*
* $Id: packet-cups.c,v 1.2 2001/03/13 21:34:23 gram Exp $
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
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"
#include "strutil.h"

/**********************************************************************/

/* From cups/cups.h, GNU GPL, Copyright 1997-2001 by Easy Software Products. */
typedef unsigned cups_ptype_t;          /**** Printer Type/Capability Bits ****/
enum                                    /* Not a typedef'd enum so we can OR */
{
  CUPS_PRINTER_LOCAL = 0x0000,          /* Local printer or class */
  CUPS_PRINTER_CLASS = 0x0001,          /* Printer class */
  CUPS_PRINTER_REMOTE = 0x0002,         /* Remote printer or class */
  CUPS_PRINTER_BW = 0x0004,             /* Can do B&W printing */
  CUPS_PRINTER_COLOR = 0x0008,          /* Can do color printing */
  CUPS_PRINTER_DUPLEX = 0x0010,         /* Can do duplexing */
  CUPS_PRINTER_STAPLE = 0x0020,         /* Can staple output */
  CUPS_PRINTER_COPIES = 0x0040,         /* Can do copies */
  CUPS_PRINTER_COLLATE = 0x0080,        /* Can collage copies */
  CUPS_PRINTER_PUNCH = 0x0100,          /* Can punch output */
  CUPS_PRINTER_COVER = 0x0200,          /* Can cover output */
  CUPS_PRINTER_BIND = 0x0400,           /* Can bind output */
  CUPS_PRINTER_SORT = 0x0800,           /* Can sort output */
  CUPS_PRINTER_SMALL = 0x1000,          /* Can do Letter/Legal/A4 */
  CUPS_PRINTER_MEDIUM = 0x2000,         /* Can do Tabloid/B/C/A3/A2 */
  CUPS_PRINTER_LARGE = 0x4000,          /* Can do D/E/A1/A0 */
  CUPS_PRINTER_VARIABLE = 0x8000,       /* Can do variable sizes */
  CUPS_PRINTER_IMPLICIT = 0x10000,      /* Implicit class */
  CUPS_PRINTER_DEFAULT = 0x20000,       /* Default printer on network */
  CUPS_PRINTER_OPTIONS = 0xfffc         /* ~(CLASS | REMOTE | IMPLICIT) */
};
/* End insert from cups/cups.h */

static const value_string cups_ptype_on[] = {
	{ CUPS_PRINTER_CLASS,		"printer class" },
	{ CUPS_PRINTER_REMOTE,		"remote" },
	{ CUPS_PRINTER_BW,		"can print black" },
	{ CUPS_PRINTER_COLOR,		"can print color" },
	{ CUPS_PRINTER_DUPLEX,		"can duplex" },
	{ CUPS_PRINTER_STAPLE,		"can staple" },
	{ CUPS_PRINTER_COPIES,		"can do fast copies" },
	{ CUPS_PRINTER_COLLATE,		"can do fast collating" },
	{ CUPS_PRINTER_PUNCH,		"can punch holes" },
	{ CUPS_PRINTER_COVER,		"can cover" },
	{ CUPS_PRINTER_BIND,		"can bind" },
	{ CUPS_PRINTER_SORT,		"can sort" },
	{ CUPS_PRINTER_SMALL,		"can print up to 9x14 inches" },
	{ CUPS_PRINTER_MEDIUM,		"can print up to 18x24 inches" },
	{ CUPS_PRINTER_LARGE,		"can print up to 36x48 inches" },
	{ CUPS_PRINTER_VARIABLE,	"can print variable sizes" },
	{ CUPS_PRINTER_IMPLICIT,	"implicit class" },
	{ CUPS_PRINTER_DEFAULT,		"default printer on network" }
};

static const value_string cups_ptype_off[] = {
	{ CUPS_PRINTER_CLASS,		"single printer" },
	{ CUPS_PRINTER_REMOTE,		"local (illegal)" },
	{ CUPS_PRINTER_BW,		"cannot print black" },
	{ CUPS_PRINTER_COLOR,		"cannot print color" },
	{ CUPS_PRINTER_DUPLEX,		"cannot duplex" },
	{ CUPS_PRINTER_STAPLE,		"cannot staple" },
	{ CUPS_PRINTER_COPIES,		"cannot do fast copies" },
	{ CUPS_PRINTER_COLLATE,		"cannot do fast collating" },
	{ CUPS_PRINTER_PUNCH,		"cannot punch holes" },
	{ CUPS_PRINTER_COVER,		"cannot cover" },
	{ CUPS_PRINTER_BIND,		"cannot bind" },
	{ CUPS_PRINTER_SORT,		"cannot sort" },
	{ CUPS_PRINTER_SMALL,		"cannot print up to 9x14 inches" },
	{ CUPS_PRINTER_MEDIUM,		"cannot print up to 18x24 inches" },
	{ CUPS_PRINTER_LARGE,		"cannot print up to 36x48 inches" },
	{ CUPS_PRINTER_VARIABLE,	"cannot print variable sizes" }
};

typedef enum _cups_state {
	CUPS_IDLE = 3,
	CUPS_PROCESSING,
	CUPS_STOPPED
} cups_state_t;

static const value_string cups_state_values[] = {
	{ CUPS_IDLE, 		"idle" },
	{ CUPS_PROCESSING,	"processing" },
	{ CUPS_STOPPED,		"stopped" }
};

static int proto_cups = -1;
static int hf_cups_ptype = -1;
static int hf_cups_state = -1;

static gint ett_cups = -1;
static gint ett_cups_ptype = -1;

/* This protocol is heavily related to IPP, but it is CUPS-specific
   and non-standard. */
#define UDP_PORT_CUPS	631
#define PROTO_TAG_CUPS	"CUPS"

static guint get_hex_uint(tvbuff_t *tvb, gint offset,
    gint *next_offset);
static void get_space(tvbuff_t *tvb, gint offset,
    gint *next_offset);
static const guint8* get_quoted_string(tvbuff_t *tvb, gint offset,
    gint *next_offset, guint *len);
static const guint8* get_unquoted_string(tvbuff_t *tvb, gint offset,
    gint *next_offset, guint *len);

/**********************************************************************/

static void
dissect_cups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*cups_tree = 0;
	proto_tree	*ptype_subtree = 0;
	proto_item	*ti = 0;
	gint		offset = 0;
	gint		next_offset;
	guint		len;
	unsigned int	u;
	const guint8	*str;
	cups_ptype_t	ptype;
	unsigned int	state;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, PROTO_TAG_CUPS);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_cups, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		cups_tree = proto_item_add_subtree(ti, ett_cups);
	}

	/* Format (1450 bytes max.):  */
	/* type state uri "location" "info" "make-and-model"\n */

	ptype = get_hex_uint(tvb, offset, &next_offset);
	len = next_offset - offset;
	if (cups_tree) {
		ti = proto_tree_add_uint(cups_tree, hf_cups_ptype,
		    tvb, offset, len, ptype);
		ptype_subtree = proto_item_add_subtree(ti, ett_cups_ptype);
		for (u = 1; match_strval(u, cups_ptype_on); u <<= 1) {
			if (ptype & u)
				proto_tree_add_text(
				    ptype_subtree, tvb, offset, len,
				    "  0x%05x => %s",
				    u, val_to_str(u, cups_ptype_on, ""));
			else if (match_strval(u, cups_ptype_off))
				proto_tree_add_text(
				    ptype_subtree, tvb, offset, len,
				    "! 0x%05x => %s",
				    u, val_to_str(u, cups_ptype_off, ""));
		}
	}
	offset = next_offset;

	get_space(tvb, offset, &next_offset);
	offset = next_offset;

	state = get_hex_uint(tvb, offset, &next_offset);
	len = next_offset - offset;
	if (cups_tree)
		proto_tree_add_uint(cups_tree, hf_cups_state,
		    tvb, offset, len, state);
	offset = next_offset;

	get_space(tvb, offset, &next_offset);
	offset = next_offset;

	str = get_unquoted_string(tvb, offset, &next_offset, &len);
	if (cups_tree)
		proto_tree_add_text(cups_tree, tvb, offset, len,
		    "URI: %.*s",
		    (guint16) len, str);
	if (check_col(pinfo->fd, COL_INFO))
		col_add_fstr(pinfo->fd, COL_INFO,
		    "%.*s (%s)",
		    (guint16) len, str,
		    val_to_str(state, cups_state_values, "0x%x"));
	offset = next_offset;

	if (!cups_tree)
		return;

	get_space(tvb, offset, &next_offset);
	offset = next_offset;

	str = get_quoted_string(tvb, offset, &next_offset, &len);
	proto_tree_add_text(cups_tree, tvb, offset+1, len,
	    "Location: \"%.*s\"",
	    (guint16) len, str);
	offset = next_offset;

	get_space(tvb, offset, &next_offset);
	offset = next_offset;

	str = get_quoted_string(tvb, offset, &next_offset, &len);
	proto_tree_add_text(cups_tree, tvb, offset+1, len,
	    "Information: \"%.*s\"",
	    (guint16) len, str);
	offset = next_offset;

	get_space(tvb, offset, &next_offset);
	offset = next_offset;

	str = get_quoted_string(tvb, offset, &next_offset, &len);
	proto_tree_add_text(cups_tree, tvb, offset+1, len,
	    "Make and model: \"%.*s\"",
	    (guint16) len, str);
	offset = next_offset;

	return;
}

static guint
get_hex_uint(tvbuff_t *tvb, gint offset, gint *next_offset)
{
	int c;
	guint u = 0;

	while (isxdigit(c = tvb_get_guint8(tvb, offset))) {
		if (isdigit(c))
			c -= '0';
		else if (isupper(c))
			c -= 'A' - 10;
		else if (islower(c))
			c -= 'a' - 10;
		else
			c = 0; /* This should not happen. */

		u = 16*u + c;

		offset++;
	}

	*next_offset = offset;

	return u;
}

static void
get_space(tvbuff_t *tvb, gint offset, gint *next_offset)
{
	int c;

	while ((c = tvb_get_guint8(tvb, offset)) == ' ')
		offset++;

	*next_offset = offset;

	return;
}

static const guint8*
get_quoted_string(tvbuff_t *tvb, gint offset, gint *next_offset, guint *len)
{
	int c;
	const guint8* s = NULL;
	guint l = 0;
	gint o;

	c = tvb_get_guint8(tvb, offset);
	if (c == '"') {
		o = tvb_find_guint8(tvb, offset+1, -1, '"');
		if (o != -1) {
			offset++;
			l = o - offset;
			s = tvb_get_ptr(tvb, offset, l);
			offset = o + 1;
		}
	}

	*next_offset = offset;
	*len = l;

	return s;
}

static const guint8*
get_unquoted_string(tvbuff_t *tvb, gint offset, gint *next_offset, guint *len)
{
	const guint8* s = NULL;
	guint l = 0;
	gint o;

	o = tvb_find_guint8(tvb, offset, -1, ' ');
	if (o != -1) {
		l = o - offset;
		s = tvb_get_ptr(tvb, offset, l);
		offset = o;
	}

	*next_offset = offset;
	*len = l;

	return s;
}

/**********************************************************************/

void
proto_register_cups(void)
{
	static hf_register_info hf[] = {
		/* This one could be split in separate fields. */
		{ &hf_cups_ptype,
			{ "Type", 	"cups.ptype", FT_UINT32, BASE_HEX,
			  NULL, 0x0, ""}},

		{ &hf_cups_state,
			{ "State",	"cups.state", FT_UINT8, BASE_HEX,
			  VALS(cups_state_values), 0x0, "" }}
	};

	static gint *ett[] = {
		&ett_cups,
		&ett_cups_ptype
	};

	proto_cups = proto_register_protocol(
	    "Common Unix Printing System (CUPS) Browsing Protocol",
	    "CUPS", "cups");
	proto_register_field_array(proto_cups, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cups(void)
{
	dissector_add("udp.port", UDP_PORT_CUPS, dissect_cups, proto_cups);
}
