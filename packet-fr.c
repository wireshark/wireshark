/* packet-fr.c
 * Routines for Frame Relay  dissection
 *
 * Copyright 2001, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id: packet-fr.c,v 1.10 2001/03/23 19:22:02 jfoster Exp $
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
 * References:
 *
 * http://www.protocols.com/pbook/frame.htm
 * http://www.frforum.com/5000/Approved/FRF.3/FRF.3.2.pdf
 * RFC-1490 
 * RFC-2427 
 * Cisco encapsulation
 * http://www.trillium.com/whats-new/wp_frmrly.html
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-llc.h"
#include "packet-chdlc.h"
#include "xdlc.h"
#include "oui.h"
#include "nlpid.h"
#include "greproto.h"
#include "conversation.h"

/*
 * Bits in the address field.
 */
#define	FRELAY_DLCI	0xfcf0		/* 2 byte DLCI Address */
#define	FRELAY_CR	0x0200		/* Command/Response bit */
#define	FRELAY_EA	0x0001		/* Address Extension bit */
#define	FRELAY_FECN	0x0008		/* Forward Explicit Congestion Notification */
#define	FRELAY_BECN	0x0004		/* Backward Explicit Congestion Notification */
#define	FRELAY_DE	0x0002		/* Discard Eligibility */
#define	FRELAY_DC	0x0002		/* Control bits */

#define FROM_DCE	0x80		/* for direction setting */

#define NLPID_WCP 0xb0 			/* Wellfleet compression ip */

static gint proto_fr    = -1;
static gint ett_fr      = -1;
static gint hf_fr_dlci  = -1;
static gint hf_fr_cr	= -1;
static gint hf_fr_becn  = -1;
static gint hf_fr_fecn  = -1;
static gint hf_fr_de    = -1;
static gint hf_fr_ea    = -1;
static gint hf_fr_dc    = -1;
static gint hf_fr_nlpid = -1;
static gint hf_fr_oui   = -1;
static gint hf_fr_pid   = -1;
static gint hf_fr_snaptype = -1;
static gint hf_fr_chdlctype = -1;

static const true_false_string cmd_string = {
                "Command",
                "Response"
        };
static const true_false_string ctrl_string = {
                "DLCI Address",
                "Control"
        };
static const true_false_string ea_string = {
                "Last Octet",
                "More Follows"
        };

dissector_table_t fr_subdissector_table;

static void dissect_lapf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_fr_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


static void add_dlci( tvbuff_t *tvb, proto_tree *tree) {

/* Display this DLCI address. Use special format because the DLCI address */
/* is a masked bit field with unused bits in the middle. */


   char buf[32];
   guint16 address = (( tvb_get_guint8( tvb, 0)& 0xfc) << 2) 
			| ((tvb_get_guint8( tvb, 1) & 0xf0) >> 4);

   decode_bitfield_value( buf, tvb_get_ntohs(tvb, 0), FRELAY_DLCI, 16);
   proto_tree_add_uint_format( tree, hf_fr_dlci, tvb, 0, 2, address, "%sDLCI: %d", 
      buf, address);
}


static void dissect_fr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fr_tree = NULL;
  guint16 fr_header,fr_type,offset=2; /* default header length of FR is 2 bytes */
  guint16 address;
  guint8  fr_nlpid,fr_ctrl;

  CHECK_DISPLAY_AS_DATA(proto_fr, tvb, pinfo, tree);

  pinfo->current_proto = "Frame Relay";
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
      col_set_str(pinfo->fd, COL_PROTOCOL, "FR");

  if (pinfo->pseudo_header->x25.flags & FROM_DCE) {
        if(check_col(pinfo->fd, COL_RES_DL_DST))
            col_set_str(pinfo->fd, COL_RES_DL_DST, "DTE");
        if(check_col(pinfo->fd, COL_RES_DL_SRC))
            col_set_str(pinfo->fd, COL_RES_DL_SRC, "DCE");
    }
    else {
        if(check_col(pinfo->fd, COL_RES_DL_DST))
            col_set_str(pinfo->fd, COL_RES_DL_DST, "DCE");
        if(check_col(pinfo->fd, COL_RES_DL_SRC))
            col_set_str(pinfo->fd, COL_RES_DL_SRC, "DTE");
    }

/*XXX We should check the EA bits and use that to generate the address. */

  fr_header = tvb_get_ntohs(tvb, 0);
  fr_ctrl = tvb_get_guint8( tvb, 2);
  address = ((fr_header & 0xfc00) >> 6) | ((fr_header & 0xf0) >> 4);

  if (check_col(pinfo->fd, COL_INFO)) 
      col_add_fstr(pinfo->fd, COL_INFO, "DLCI %u", address);

  if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_fr, tvb, 0, 4, "Frame Relay");
      fr_tree = proto_item_add_subtree(ti, ett_fr);

      add_dlci(tvb, fr_tree); 
      proto_tree_add_boolean(fr_tree, hf_fr_cr,   tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_fecn, tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_becn, tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_de,   tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_ea,   tvb, 0, offset, fr_header);
  }

  if (fr_ctrl == XDLC_U) {
      if (tree) {
		proto_tree_add_text(fr_tree, tvb, offset, 0, "------- IETF Encapsulation -------");
		/*
		 * XXX - if we're going to show this as Unnumbered
		 * Information, should we just hand it to
		 * "dissect_xdlc_control()"?
		 */
		proto_tree_add_text(fr_tree, tvb, offset, 1, "Unnumbered Information");
      }
      offset++;
      fr_nlpid = tvb_get_guint8 (tvb,offset);
      if (fr_nlpid == 0) {
		if (tree)
			proto_tree_add_text(fr_tree, tvb, offset, 1, "Padding");
		offset++;
		fr_nlpid=tvb_get_guint8( tvb,offset);
      }
      if (tree)
		proto_tree_add_uint(fr_tree, hf_fr_nlpid, tvb, offset, 1, fr_nlpid );
      offset++;

      SET_ADDRESS(&pinfo->dl_src, AT_DLCI, 2, (guint8*)&address);

      if (fr_nlpid == NLPID_SNAP) {
		dissect_snap(tvb, offset, pinfo, tree, fr_tree, fr_ctrl,
		      hf_fr_oui, hf_fr_snaptype, hf_fr_pid, 0);
		return;
      }
		                                  
      /*
       * XXX - we should just call "dissect_osi()" here, but
       * some of the routines "dissect_osi()" calls themselves put
       * the NLPID into the tree, and not everything registered with
       * "fr.ietf" is also registered with "osinl".
       *
       * We'd need to figure out what to do with the NLPID.
       * "dissect_osi()" is registered with the "llc.dsap" dissector
       * table, so if it were to put the NLPID into the protocol
       * tree it'd have to create its own subtree for it - not all its
       * callers can do that for it (without knowing whether they're
       * going to call it or not, and the LLC dissector doesn't).
       *
       * Currently, it hands the NLPID as part of the tvbuff to
       * the sub-dissectors it calls; if none of them need to look
       * at it, we could perhaps have it put the NLPID into the
       * tree and *not* have the subdissectors expect it - that's
       * what would have to be done for IP, for example, as IP,
       * unlike CLNP, doesn't expect an NLPID as the first byte.
       */
      if (!dissector_try_port(fr_subdissector_table,fr_nlpid, tvb_new_subset(tvb,offset,-1,-1), pinfo, tree))
		dissect_data(tvb_new_subset(tvb,offset,-1,-1), 0, pinfo, tree);
      return;
  } else {
      if ((fr_header && 0xFCF0) == 0) {
		/* this must be some sort of lapf on DLCI 0 for SVC */
		/* because DLCI 0 is rezerved for LMI and  SVC signaling encaplulated in lapf */
		/* and LMI is transmitted in unnumbered information (03) */
		/* so this must be lapf (guessing) */
		dissect_lapf(tvb_new_subset(tvb,offset,-1,-1),pinfo,tree);
		return;
      }
      if (fr_ctrl == (XDLC_U|XDLC_XID)) {
		dissect_fr_xid(tvb_new_subset(tvb,offset,-1,-1),pinfo,tree);
		return;
      }

      /*
       * If the data does not start with unnumbered information (03) and
       * the DLCI# is not 0, then there may be Cisco Frame Relay encapsulation.
       */
      proto_tree_add_text(fr_tree, tvb, offset, 0, "------- Cisco Encapsulation -------");
      fr_type  = tvb_get_ntohs(tvb, offset);
      chdlctype(fr_type, tvb, offset+2, pinfo, tree, fr_tree, hf_fr_chdlctype);
  }
}

static void dissect_lapf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, 0, 0, "Frame relay lapf not yet implemented");
	dissect_data(tvb_new_subset(tvb,0,-1,-1),0,pinfo,tree);
}
static void dissect_fr_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, 0, 0, "Frame relay xid not yet implemented");
	dissect_data(tvb_new_subset(tvb,0,-1,-1),0,pinfo,tree);
}
 
/* Register the protocol with Ethereal */
void proto_register_fr(void)
{                 
  static hf_register_info hf[] = {

        { &hf_fr_dlci, { 
           "DLCI", "fr.dlci", FT_UINT16, BASE_DEC, 
            NULL, FRELAY_DLCI, "Data-Link Connection Identifier" }},
        { &hf_fr_cr, { 
           "CR", "fr.cr", FT_BOOLEAN, 16, TFS(&cmd_string),
            FRELAY_CR, "Command/Response" }},
        { &hf_fr_dc, { 
           "DC", "fr.dc", FT_BOOLEAN, 16, TFS(&ctrl_string),
            FRELAY_CR, "Address/Control" }},

        { &hf_fr_fecn, { 
           "FECN", "fr.fecn", FT_BOOLEAN, 16, 
            NULL, FRELAY_FECN, "Forward Explicit Congestion Notification" }},
        { &hf_fr_becn, { 
           "BECN", "fr.becn", FT_BOOLEAN, 16, 
            NULL, FRELAY_BECN, "Backward Explicit Congestion Notification" }},
        { &hf_fr_de, { 
           "DE", "fr.de", FT_BOOLEAN, 16, 
            NULL, FRELAY_DE, "Discard Eligibility" }},
        { &hf_fr_ea, { 
           "EA", "fr.ea", FT_BOOLEAN, 16, TFS(&ea_string),
            FRELAY_EA, "Extended Address" }},
        { &hf_fr_nlpid, { 
           "NLPID", "fr.nlpid", FT_UINT8, BASE_HEX, 
            NULL, 0x0, "FrameRelay Encapsulated Protocol NLPID" }},
	{ &hf_fr_oui, {
	   "Organization Code",	"fr.snap.oui", FT_UINT24, BASE_HEX, 
	   VALS(oui_vals), 0x0, ""}},
	{ &hf_fr_pid, {
	   "Protocol ID", "fr.snap.pid", FT_UINT16, BASE_HEX, 
	   NULL, 0x0, ""}},
        { &hf_fr_snaptype, { 
           "Type", "fr.snaptype", FT_UINT16, BASE_HEX, 
            VALS(etype_vals), 0x0, "FrameRelay SNAP Encapsulated Protocol" }},
        { &hf_fr_chdlctype, { 
           "Type", "fr.chdlctype", FT_UINT16, BASE_HEX, 
            VALS(chdlc_vals), 0x0, "FrameRelay Cisco HDLC Encapsulated Protocol" }},
  };


  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_fr,
  };

  proto_fr = proto_register_protocol("Frame Relay", "FR", "fr");
  proto_register_field_array(proto_fr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  fr_subdissector_table = register_dissector_table("fr.ietf");
}

void proto_reg_handoff_fr(void)
{
  dissector_add("wtap_encap", WTAP_ENCAP_FRELAY, dissect_fr, proto_fr);
  dissector_add("gre.proto", GRE_FR, dissect_fr, proto_fr);
}
