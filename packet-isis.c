/* packet-isis-core.c
 * Routines for ISO/OSI network and transport protocol packet disassembly, core
 * bits.
 *
 * $Id: packet-isis.c,v 1.1 1999/12/15 04:34:19 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-isis.h"
#include "packet-isis-lsp.h"
#include "packet-isis-hello.h"
#include "packet-isis-snp.h"

/* isis base header */
static int proto_isis = -1;

static int hf_isis_irpd = -1;
static int hf_isis_header_length = -1;
static int hf_isis_version = -1;
static int hf_isis_reserved = -1;
static int hf_isis_type = -1;
static int hf_isis_version2 = -1;
static int hf_isis_eco = -1;
static int hf_isis_user_eco = -1;

static gint ett_isis = -1;

static const value_string irpd_vals[] = {
	{ ISIS_IRPD, "correct(0x83)" },
	{ 0,		NULL} };

static const value_string isis_vals[] = {
	{ ISIS_TYPE_L1_HELLO,	"L1 HELLO"},
	{ ISIS_TYPE_L2_HELLO,	"L2 HELLO"},
	{ ISIS_TYPE_PTP_HELLO,	"P2P HELLO"},
	{ ISIS_TYPE_L1_LSP,	"L1 LSP"},
	{ ISIS_TYPE_L2_LSP,	"L2 LSP"},
	{ ISIS_TYPE_L1_CSNP,	"L1 CSNP"},
	{ ISIS_TYPE_L2_CSNP,	"L2 CSNP"},
	{ ISIS_TYPE_L1_PSNP,	"L1 PSNP"},
	{ ISIS_TYPE_L2_PSNP,	"L2 PSNP"},
	{ 0,		NULL} };


/*
 * Name: dissect_isis_unknown()
 *
 * Description:
 *	There was some error in the protocol and we are in unknown space
 *	here.  Add a tree item to cover the error and go on.  Note
 *	that we make sure we don't go off the end of the bleedin packet here!
 *
 * Input
 * 	unt offset : Current offset into packet data.
 * 	int len : length of to dump.
 *	proto_tree * : tree of display data.  May be NULL.
 *	frame_data * fd : frame data
 *	char * : format text
 *
 * Output:
 *	void (may modify proto tree)
 */
void
isis_dissect_unknown(int offset,guint length,proto_tree *tree,frame_data *fd,
		char *fmat, ...){
	va_list	ap;

	if ( offset > fd->cap_len ) {
		/* 
		 * big oops   They were off the end of the packet already.
		 * Just ignore this one.
		 */
		return;
	}
	if ( (offset + length) > fd->cap_len ) {
		/* 
		 * length will take us past eop.  Truncate length.
		 */
		length = offset - fd->cap_len;
	}

	va_start(ap, fmat);
	proto_tree_add_text(tree, offset, length, fmat, ap);
	va_end(ap);
}

/*
 * Name: isis_address_to_string()
 *
 * Description:
 *	Function for taking a byte string and turn it into a "0000.0000...."
 *	format ISIS address.
 *
 * Input:
 *	u_char * : Packet data
 * 	unt offset : Current offset into packet data.
 * 	int len : length of to dump.
 *
 * Output:
 *	static char * : print string
 */
char 
*isis_address_to_string ( const u_char *pd, int offset, int len ) {
	static char sbuf[768];
	char *s;

	sbuf[0] = 0;
	s = sbuf;
	while ( len > 0 ) {
		/* special case: len is 1, put ending on it */
		if ( len == 1 ) {
			s += sprintf ( s, "%02x", pd[offset++] );
			len--;
		} else {
			/* general case, just add 2 bytes */
			s+= sprintf ( s, "%02x%02x", pd[offset++],
				pd[offset++] );
			len -= 2;
		}
		if ( len > 0 ) {
			s += sprintf ( s, "." );
		}
	}
	return sbuf;
}

/*
 * Name: dissect_isis()
 * 
 * Description:
 *	Main entry area for isis de-mangling.  This will build the
 *	main isis tree data and call the sub-protocols as needed.
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet where we are (packet_data[offset]== start
 *		of what we care about)
 *	frame_data * : frame data (whole packet with extra info)
 *	proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *	void, but we will add to the proto_tree if it is not NULL.
 */
void
dissect_isis(const u_char *pd, int offset, frame_data *fd, 
		proto_tree *tree) {
	isis_hdr_t *ihdr;
	proto_item *ti;
	proto_tree *isis_tree = NULL;

	if (fd->cap_len < offset + sizeof(*ihdr)) {
		isis_dissect_unknown(offset, sizeof(*ihdr), tree, fd,
			"not enough capture data for header (%d vs %d)",
			sizeof(*ihdr), offset - fd->cap_len);
		return;
	}

	ihdr = (isis_hdr_t *) &pd[offset];

	if (ihdr->isis_version != ISIS_REQUIRED_VERSION){
		isis_dissect_unknown(offset, fd->cap_len, tree, fd,
			"Unknown ISIS version (%d vs %d)",
			ihdr->isis_version, ISIS_REQUIRED_VERSION );
		return;
	}
	
	
	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis, offset, 
			fd->cap_len - offset, NULL );
		isis_tree = proto_item_add_subtree(ti, ett_isis);
		proto_tree_add_item_format(isis_tree, hf_isis_irpd, offset, 1,
			ihdr->isis_irpd, 
			"Intradomain Routing Protocol Discrimintator: 0x%02x",
			ihdr->isis_irpd );
		proto_tree_add_item(isis_tree, hf_isis_header_length,
			offset + 1, 1, ihdr->isis_header_length );
		proto_tree_add_item(isis_tree, hf_isis_version,
			offset + 2, 1, ihdr->isis_version );
		proto_tree_add_item(isis_tree, hf_isis_reserved,
			offset + 3, 1, ihdr->isis_reserved );
		proto_tree_add_item_format(isis_tree, hf_isis_type,
			offset + 4, 1, ihdr->isis_type,
			"Type: %s (R:%s%s%s)",
			val_to_str(ihdr->isis_type & ISIS_TYPE_MASK, isis_vals,
				"Unknown (0x%x)"),
			(ihdr->isis_type & ISIS_R8_MASK) ? "1" : "0",
			(ihdr->isis_type & ISIS_R7_MASK) ? "1" : "0",
			(ihdr->isis_type & ISIS_R6_MASK) ? "1" : "0");
		proto_tree_add_item(isis_tree, hf_isis_version2,
			offset + 5, 1, ihdr->isis_version2 );
		proto_tree_add_item(isis_tree, hf_isis_eco,
			offset + 6, 1, ihdr->isis_eco );
		proto_tree_add_item(isis_tree, hf_isis_user_eco,
			offset + 7, 1, ihdr->isis_user_eco );
	}


	/*
	 * Let us make sure we use the same names for all our decodes
	 * here.  First, dump the name into info column, and THEN
	 * dispatch the sub-type.
	 */
	if (check_col(fd, COL_INFO)) {
		col_add_str(fd, COL_INFO, val_to_str ( 
			ihdr->isis_type&ISIS_TYPE_MASK, isis_vals,
			"Unknown (0x%x)" ) );
	}

	/*
	 * Advance offset (we are past the header).
	 */
	offset += sizeof(*ihdr);
	switch (ihdr->isis_type) {
	case ISIS_TYPE_L1_HELLO:
		isis_dissect_isis_hello(ISIS_TYPE_L1_HELLO, 
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L2_HELLO:
		isis_dissect_isis_hello(ISIS_TYPE_L2_HELLO, 
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_PTP_HELLO:
		isis_dissect_isis_hello(ISIS_TYPE_PTP_HELLO, 
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L1_LSP:
		isis_dissect_isis_lsp(ISIS_TYPE_L1_LSP, ihdr->isis_header_length,
			pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L2_LSP:
		isis_dissect_isis_lsp(ISIS_TYPE_L2_LSP, ihdr->isis_header_length,
			pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L1_CSNP:
		isis_dissect_isis_csnp(ISIS_TYPE_L1_CSNP, 
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L2_CSNP:
		isis_dissect_isis_csnp(ISIS_TYPE_L2_CSNP,
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L1_PSNP:
		isis_dissect_isis_psnp(ISIS_TYPE_L1_PSNP, 
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	case ISIS_TYPE_L2_PSNP:
		isis_dissect_isis_psnp(ISIS_TYPE_L2_PSNP,
			ihdr->isis_header_length, pd, offset, fd, isis_tree);
		break;
	default:
		isis_dissect_unknown(offset, offset - fd->cap_len, tree, fd,
			"unknown ISIS packet type" );
	}
} /* dissect_isis */


/*
 * Name: proto_register_isis()
 *
 * Description:
 *	main register for isis protocol set.  We register some display
 *	formats and the protocol module variables.
 *
 * 	NOTE: this procedure to autolinked by the makefile process that
 *	builds register.c
 *
 * Input: 
 *	void
 *
 * Output:
 *	void
 */
void 
proto_register_isis(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_irpd,
		{ "Intradomain Routing Protocol Discriminator",	"isis.irpd",	
		  FT_UINT8, BASE_DEC, VALS(irpd_vals), 0xff, "" }},

		{ &hf_isis_header_length,
		{ "HDR Length",		"isis.hdr_len",	FT_UINT8, BASE_DEC, 
		  NULL, 0x0, "" }},

		{ &hf_isis_version,
		{ "Version (==1)",		"isis.version", FT_UINT8, 
		  BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_reserved,
		{ "Reserved(==0)",			"isis.reserved",	
		  FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_type,
		{ "Type code",            "isis.type",	FT_UINT8, BASE_DEC, 
		  VALS(isis_vals), 0xff, "" }},

		{ &hf_isis_version2,
		{ "Version2(==1)",   "isis.version2", FT_UINT8, BASE_DEC, NULL, 
		   0x0, "" }},

		{ &hf_isis_eco,
		{ "ECO (==0)",		"isis.eco",FT_UINT8, BASE_DEC, NULL, 
		  0x0, "" }},

		{ &hf_isis_user_eco,
		{ "User ECO (==0)", "isis.user_eco", FT_UINT8, BASE_DEC, NULL, 
		  0x0, "" }},

	};
	/*
	 * Note, we pull in the unknown CLV handler here, since it
	 * is used by all ISIS packet types.
	 */
	static gint *ett[] = {
		&ett_isis,
	};

	proto_isis = proto_register_protocol("clnp ISIS", "ISIS");
	proto_register_field_array(proto_isis, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
