/* packet-isis.c
 * Routines for ISO/OSI network and transport protocol packet disassembly, core
 * bits.
 *
 * $Id$
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/nlpid.h>
#include <epan/etypes.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-lsp.h"
#include "packet-isis-hello.h"
#include "packet-isis-snp.h"


/* isis base header */
static int proto_isis               = -1;

static int hf_isis_irpd             = -1;
static int hf_isis_header_length    = -1;
static int hf_isis_version          = -1;
static int hf_isis_system_id_length = -1;
static int hf_isis_type             = -1;
static int hf_isis_version2         = -1;
static int hf_isis_reserved         = -1;
static int hf_isis_max_area_adr     = -1;

static gint ett_isis                = -1;

static const value_string isis_vals[] = {
  { ISIS_TYPE_L1_HELLO,  "L1 HELLO"},
  { ISIS_TYPE_L2_HELLO,  "L2 HELLO"},
  { ISIS_TYPE_PTP_HELLO, "P2P HELLO"},
  { ISIS_TYPE_L1_LSP,    "L1 LSP"},
  { ISIS_TYPE_L2_LSP,    "L2 LSP"},
  { ISIS_TYPE_L1_CSNP,   "L1 CSNP"},
  { ISIS_TYPE_L2_CSNP,   "L2 CSNP"},
  { ISIS_TYPE_L1_PSNP,   "L1 PSNP"},
  { ISIS_TYPE_L2_PSNP,   "L2 PSNP"},
  { 0,                   NULL}      };

/*
 * Name: isis_dissect_unknown()
 *
 * Description:
 *	There was some error in the protocol and we are in unknown space
 *	here.  Add a tree item to cover the error and go on.  Note
 *	that we make sure we don't go off the end of the bleedin packet here!
 *
 * Input
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : tree of display data.  May be NULL.
 *	int : current offset into packet data
 *	char * : format text
 *	subsequent args : arguments to format
 *
 * Output:
 *	void (may modify proto tree)
 */
void
isis_dissect_unknown(tvbuff_t *tvb, proto_tree *tree, int offset,
	const char *fmat, ...)
{
	va_list	ap;

	va_start(ap, fmat);
	proto_tree_add_text_valist(tree, tvb, offset, -1, fmat, ap);
	va_end(ap);
}

/*
 * Name: dissect_isis()
 *
 * Description:
 *	Main entry area for isis de-mangling.  This will build the
 *	main isis tree data and call the sub-protocols as needed.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *	void, but we will add to the proto_tree if it is not NULL.
 */
static void
dissect_isis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *isis_tree = NULL;
	int offset = 0;
	guint8 isis_version;
	guint8 isis_header_length;
	guint8 isis_type_reserved;
	guint8 isis_type;
	guint8 isis_system_id_len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS");
	col_clear(pinfo->cinfo, COL_INFO);

	isis_version = tvb_get_guint8(tvb, 2);
	if (isis_version != ISIS_REQUIRED_VERSION){
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"Unknown ISIS version (%u vs %u)",
				isis_version, ISIS_REQUIRED_VERSION );
		}
		isis_dissect_unknown(tvb, tree, 0,
			"Unknown ISIS version (%d vs %d)",
			isis_version, ISIS_REQUIRED_VERSION);
		return;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis, tvb, 0, -1, ENC_NA);
		isis_tree = proto_item_add_subtree(ti, ett_isis);
	}

	if (tree) {
		proto_tree_add_item(isis_tree, hf_isis_irpd, tvb, offset, 1,
			ENC_BIG_ENDIAN );
	}
	offset += 1;

	isis_header_length = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(isis_tree, hf_isis_header_length, tvb,
			offset, 1, isis_header_length );
	}
	offset += 1;

	if (tree) {
		proto_tree_add_uint(isis_tree, hf_isis_version, tvb,
			offset, 1, isis_version );
	}
	offset += 1;

	isis_system_id_len = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(isis_tree, hf_isis_system_id_length, tvb,
			offset, 1, isis_system_id_len );
	}
	offset += 1;

	isis_type_reserved = tvb_get_guint8(tvb, offset);
	isis_type = isis_type_reserved & ISIS_TYPE_MASK;
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str ( isis_type, isis_vals, "Unknown (0x%x)" ) );
	}
	if (tree) {
		proto_tree_add_uint_format(isis_tree, hf_isis_type, tvb,
			offset, 1, isis_type,
			"PDU Type           : %s (R:%s%s%s)",
			val_to_str(isis_type, isis_vals, "Unknown (0x%x)"),
			(isis_type_reserved & ISIS_R8_MASK) ? "1" : "0",
			(isis_type_reserved & ISIS_R7_MASK) ? "1" : "0",
			(isis_type_reserved & ISIS_R6_MASK) ? "1" : "0");
	}
	offset += 1;

	if (tree) {
		proto_tree_add_item(isis_tree, hf_isis_version2, tvb, offset, 1,
			ENC_BIG_ENDIAN );
	}
	offset += 1;

	if (tree) {
		proto_tree_add_item(isis_tree, hf_isis_reserved, tvb, offset, 1,
			ENC_BIG_ENDIAN );
	}
	offset += 1;

	if (tree) {
		proto_tree_add_item(isis_tree, hf_isis_max_area_adr, tvb, offset, 1,
			ENC_BIG_ENDIAN );
	}
	offset += 1;

	/*
	 * Interpret the system ID length.
	 */
	if (isis_system_id_len == 0)
		isis_system_id_len = 6;	/* zero means 6-octet ID field length */
	else if (isis_system_id_len == 255) {
		isis_system_id_len = 0;	/* 255 means null ID field */
		/* XXX - what about the LAN ID? */
	}
	/* XXX - otherwise, must be in the range 1 through 8 */

	switch (isis_type) {
	case ISIS_TYPE_L1_HELLO:
	case ISIS_TYPE_L2_HELLO:
	case ISIS_TYPE_PTP_HELLO:
		isis_dissect_isis_hello(tvb, pinfo, isis_tree, offset,
			isis_type, isis_header_length, isis_system_id_len);
		break;
	case ISIS_TYPE_L1_LSP:
	case ISIS_TYPE_L2_LSP:
		isis_dissect_isis_lsp(tvb, pinfo, isis_tree, offset,
			isis_type, isis_header_length, isis_system_id_len);
		break;
	case ISIS_TYPE_L1_CSNP:
	case ISIS_TYPE_L2_CSNP:
		isis_dissect_isis_csnp(tvb, pinfo, isis_tree, offset,
			isis_type, isis_header_length, isis_system_id_len);
		break;
	case ISIS_TYPE_L1_PSNP:
	case ISIS_TYPE_L2_PSNP:
		isis_dissect_isis_psnp(tvb, pinfo, isis_tree, offset,
			isis_type, isis_header_length, isis_system_id_len);
		break;
	default:
		isis_dissect_unknown(tvb, tree, offset,
			"Unknown ISIS packet type");
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
      { "Intra Domain Routing Protocol Discriminator",	"isis.irpd",
        FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0x0, NULL, HFILL }},

    { &hf_isis_header_length,
      { "PDU Header Length", "isis.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_isis_version,
      { "Version (==1)", "isis.version", FT_UINT8,
         BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_isis_system_id_length,
      { "System ID Length", "isis.sysid_len",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_isis_type,
      { "PDU Type", "isis.type", FT_UINT8, BASE_DEC,
        VALS(isis_vals), 0xff, NULL, HFILL }},

    { &hf_isis_version2,
      { "Version2 (==1)", "isis.version2", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_isis_reserved,
      { "Reserved (==0)", "isis.reserved", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_isis_max_area_adr,
      { "Max.AREAs: (0==3)", "isis.max_area_adr", FT_UINT8, BASE_DEC, NULL,
      0x0, NULL, HFILL }},

    };
    /*
     * Note, we pull in the unknown CLV handler here, since it
     * is used by all ISIS packet types.
     */
    static gint *ett[] = {
      &ett_isis,
    };

    proto_isis = proto_register_protocol(PROTO_STRING_ISIS, "ISIS", "isis");
    proto_register_field_array(proto_isis, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*
     * Call registration routines for other source files in the ISIS
     * dissector.
     */
    isis_register_hello(proto_isis);
    isis_register_lsp(proto_isis);
    isis_register_csnp(proto_isis);
    isis_register_psnp(proto_isis);
}

void
proto_reg_handoff_isis(void)
{
    dissector_handle_t isis_handle;

    isis_handle = create_dissector_handle(dissect_isis, proto_isis);
    dissector_add_uint("osinl", NLPID_ISO10589_ISIS, isis_handle);
    dissector_add_uint("ethertype", ETHERTYPE_L2ISIS, isis_handle);
}
