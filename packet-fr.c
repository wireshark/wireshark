/* packet-fr.c
 * Routines for Frame Relay  dissection
 *
 * Copyright 2001, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id: packet-fr.c,v 1.21 2001/11/27 07:13:25 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 *
 *
 * References:
 *
 * http://www.protocols.com/pbook/frame.htm
 * http://www.frforum.com/5000/Approved/FRF.3/FRF.3.2.pdf
 * ITU Recommendation Q.933
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
#include "packet-osi.h"
#include "packet-llc.h"
#include "packet-chdlc.h"
#include "xdlc.h"
#include "etypes.h"
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

/*
 * Extract the DLCI from the address field.
 */
#define	EXTRACT_DLCI(addr)	((((addr)&0xfc00) >> 6) | (((addr)&0xf0) >> 4))

#define FROM_DCE	0x80		/* for direction setting */

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

static dissector_handle_t data_handle;

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

/*
 * This isn't the same as "nlpid_vals[]"; 0x08 is Q.933, not Q.931,
 * and 0x09 is LMI, not Q.2931.
 */
static const value_string fr_nlpid_vals[] = {
	{ NLPID_NULL,            "NULL" },
	{ NLPID_T_70,            "T.70" },
	{ NLPID_X_633,           "X.633" },
	{ NLPID_Q_931,           "Q.933" },
	{ NLPID_LMI,             "LMI" },
	{ NLPID_Q_2119,          "Q.2119" },
	{ NLPID_SNAP,            "SNAP" },
	{ NLPID_ISO8473_CLNP,    "CLNP" },
	{ NLPID_ISO9542_ESIS,    "ESIS" },
	{ NLPID_ISO10589_ISIS,   "ISIS" },
	{ NLPID_ISO10747_IDRP,   "IDRP" },
	{ NLPID_ISO9542X25_ESIS, "ESIS (X.25)" },
	{ NLPID_ISO10030,        "ISO 10030" },
	{ NLPID_ISO11577,        "ISO 11577" },
	{ NLPID_COMPRESSED,      "Data compression protocol" },
	{ NLPID_IP,              "IP" },
	{ NLPID_PPP,             "PPP" },
	{ 0,                     NULL },
};

dissector_table_t fr_subdissector_table;

static void dissect_fr_nlpid(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, proto_item *ti,
			     proto_tree *fr_tree, guint8 fr_ctrl);
static void dissect_lapf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_fr_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_fr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_tree *fr_tree = NULL;
  guint16 fr_header,fr_type,offset=2; /* default header length of FR is 2 bytes */
  guint16 address;
  char    buf[32];
  guint8  fr_ctrl;

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
  address = EXTRACT_DLCI(fr_header);

  if (check_col(pinfo->fd, COL_INFO)) 
      col_add_fstr(pinfo->fd, COL_INFO, "DLCI %u", address);

  if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_fr, tvb, 0, 3, "Frame Relay");
      fr_tree = proto_item_add_subtree(ti, ett_fr);

      decode_bitfield_value(buf, fr_header, FRELAY_DLCI, 16);
      proto_tree_add_uint_format(fr_tree, hf_fr_dlci, tvb, 0, 2, address,
	"%sDLCI: %u", buf, address);
      proto_tree_add_boolean(fr_tree, hf_fr_cr,   tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_fecn, tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_becn, tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_de,   tvb, 0, offset, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_ea,   tvb, 0, offset, fr_header);
  }

  if (fr_ctrl == XDLC_U) {
      if (tree) {
		proto_tree_add_text(fr_tree, tvb, offset, 0, "------- Q.933 Encapsulation -------");
		/*
		 * XXX - if we're going to show this as Unnumbered
		 * Information, should we just hand it to
		 * "dissect_xdlc_control()"?
		 */
		proto_tree_add_text(fr_tree, tvb, offset, 1, "Unnumbered Information");
      }
      offset++;

      SET_ADDRESS(&pinfo->dl_src, AT_DLCI, 2, (guint8*)&address);

      dissect_fr_nlpid(tvb, offset, pinfo, tree, ti, fr_tree, fr_ctrl);
  } else {
      if (address == 0) {
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
      if (ti != NULL) {
		/* Include the Cisco HDLC type in the top-level protocol
		   tree item. */
		proto_item_set_len(ti, offset+2);
      }
      chdlctype(fr_type, tvb, offset+2, pinfo, tree, fr_tree, hf_fr_chdlctype);
  }
}


static void dissect_fr_uncompressed(tvbuff_t *tvb, packet_info *pinfo,
				    proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_tree *fr_tree = NULL;

  if (check_col(pinfo->fd, COL_PROTOCOL)) 
      col_set_str(pinfo->fd, COL_PROTOCOL, "FR");
  if (check_col(pinfo->fd, COL_INFO)) 
      col_clear(pinfo->fd, COL_INFO);

  if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_fr, tvb, 0, 4, "Frame Relay");
      fr_tree = proto_item_add_subtree(ti, ett_fr);
  }
  dissect_fr_nlpid(tvb, 0, pinfo, tree, ti, fr_tree, XDLC_U);
}

static void dissect_fr_nlpid(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, proto_item *ti,
			     proto_tree *fr_tree, guint8 fr_ctrl)
{
  guint8  fr_nlpid;
  tvbuff_t *next_tvb;

  fr_nlpid = tvb_get_guint8 (tvb,offset);
  if (fr_nlpid == 0) {
	if (tree)
		proto_tree_add_text(fr_tree, tvb, offset, 1, "Padding");
	offset++;
	if (ti != NULL) {
		/* Include the padding in the top-level protocol tree item. */
		proto_item_set_len(ti, offset);
	}
	fr_nlpid=tvb_get_guint8( tvb,offset);
  }

  /*
   * OSI network layer protocols consider the NLPID to be part
   * of the frame, so we'll pass it as part of the payload and,
   * if the protocol is one of those, add it as a hidden item here.
   */
  next_tvb = tvb_new_subset(tvb,offset,-1,-1);
  if (dissector_try_port(osinl_subdissector_table, fr_nlpid, next_tvb,
			 pinfo, tree)) {
	/*
	 * Yes, we got a match.  Add the NLPID as a hidden item,
	 * so you can, at least, filter on it.
	 */
	if (tree)
		proto_tree_add_uint_hidden(fr_tree, hf_fr_nlpid,
		    tvb, offset, 1, fr_nlpid );
	return;
  }

  /*
   * All other protocols don't.
   *
   * XXX - not true for Q.933 and LMI, but we don't yet have a
   * Q.933 dissector (it'd be similar to the Q.931 dissector,
   * but I don't think it'd be identical, although it's less
   * different than is the Q.2931 dissector), and the LMI
   * dissector doesn't yet put the protocol discriminator
   * (NLPID) into the tree.
   *
   * Note that an NLPID of 0x08 for Q.933 could either be a
   * Q.933 signaling message or a message for a protocol
   * identified by a 2-octet layer 2 protocol type and a
   * 2-octet layer 3 protocol type, those protocol type
   * octets having the values from octets 6, 6a, 7, and 7a
   * of a Q.931 low layer compatibility information element
   * (section 4.5.19 of Q.931; Q.933 says they have the values
   * from a Q.933 low layer compatibility information element,
   * but Q.933 low layer compatibility information elements
   * don't have protocol values in them).
   *
   * Assuming that, as Q.933 seems to imply, that Q.933 messages
   * look just like Q.931 messages except where it explicitly
   * says they differ, then the octet after the NLPID would,
   * in a Q.933 message, have its upper 4 bits zero (that's
   * the length of the call reference value, in Q.931, and
   * is limited to 15 or fewer octets).  As appears to be the case,
   * octet 6 of a Q.931 low layer compatibility element has the
   * 0x40 bit set, so you can distinguish between a Q.933
   * message and an encapsulated packet by checking whether
   * the upper 4 bits of the octet after the NLPID are zero.
   *
   * To handle this, we'd handle Q.933's NLPID specially, which
   * we'd want to do anyway, so that we give it a tvbuff that
   * includes the NLPID.
   */
  if (tree)
	proto_tree_add_uint(fr_tree, hf_fr_nlpid, tvb, offset, 1, fr_nlpid );
  offset++;

  switch (fr_nlpid) {

  case NLPID_SNAP:
	if (ti != NULL) {
		/* Include the NLPID and SNAP header in the top-level
		   protocol tree item. */
		proto_item_set_len(ti, offset+5);
	}
	dissect_snap(tvb, offset, pinfo, tree, fr_tree, fr_ctrl,
	      hf_fr_oui, hf_fr_snaptype, hf_fr_pid, 0);
	return;

  default:
	if (ti != NULL) {
		/* Include the NLPID in the top-level protocol tree item. */
		proto_item_set_len(ti, offset);
	}
	next_tvb = tvb_new_subset(tvb,offset,-1,-1);
	if (!dissector_try_port(fr_subdissector_table,fr_nlpid,
				next_tvb, pinfo, tree))
		call_dissector(data_handle,next_tvb, pinfo, tree);
	break;
  }
}

static void dissect_lapf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, 0, 0, "Frame relay lapf not yet implemented");
	call_dissector(data_handle,tvb_new_subset(tvb,0,-1,-1),pinfo,tree);
}
static void dissect_fr_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, 0, 0, "Frame relay xid not yet implemented");
	call_dissector(data_handle,tvb_new_subset(tvb,0,-1,-1),pinfo,tree);
}
 
/* Register the protocol with Ethereal */
void proto_register_fr(void)
{                 
  static hf_register_info hf[] = {

        { &hf_fr_dlci, { 
           "DLCI", "fr.dlci", FT_UINT16, BASE_DEC, 
            NULL, FRELAY_DLCI, "Data-Link Connection Identifier", HFILL }},
        { &hf_fr_cr, { 
           "CR", "fr.cr", FT_BOOLEAN, 16, TFS(&cmd_string),
            FRELAY_CR, "Command/Response", HFILL }},
        { &hf_fr_dc, { 
           "DC", "fr.dc", FT_BOOLEAN, 16, TFS(&ctrl_string),
            FRELAY_CR, "Address/Control", HFILL }},

        { &hf_fr_fecn, { 
           "FECN", "fr.fecn", FT_BOOLEAN, 16, 
            NULL, FRELAY_FECN, "Forward Explicit Congestion Notification", HFILL }},
        { &hf_fr_becn, { 
           "BECN", "fr.becn", FT_BOOLEAN, 16, 
            NULL, FRELAY_BECN, "Backward Explicit Congestion Notification", HFILL }},
        { &hf_fr_de, { 
           "DE", "fr.de", FT_BOOLEAN, 16, 
            NULL, FRELAY_DE, "Discard Eligibility", HFILL }},
        { &hf_fr_ea, { 
           "EA", "fr.ea", FT_BOOLEAN, 16, TFS(&ea_string),
            FRELAY_EA, "Extended Address", HFILL }},
        { &hf_fr_nlpid, { 
           "NLPID", "fr.nlpid", FT_UINT8, BASE_HEX, 
            VALS(fr_nlpid_vals), 0x0, "FrameRelay Encapsulated Protocol NLPID", HFILL }},
	{ &hf_fr_oui, {
	   "Organization Code",	"fr.snap.oui", FT_UINT24, BASE_HEX, 
	   VALS(oui_vals), 0x0, "", HFILL }},
	{ &hf_fr_pid, {
	   "Protocol ID", "fr.snap.pid", FT_UINT16, BASE_HEX, 
	   NULL, 0x0, "", HFILL }},
        { &hf_fr_snaptype, { 
           "Type", "fr.snaptype", FT_UINT16, BASE_HEX, 
            VALS(etype_vals), 0x0, "FrameRelay SNAP Encapsulated Protocol", HFILL }},
        { &hf_fr_chdlctype, { 
           "Type", "fr.chdlctype", FT_UINT16, BASE_HEX, 
            VALS(chdlc_vals), 0x0, "FrameRelay Cisco HDLC Encapsulated Protocol", HFILL }},
  };


  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_fr,
  };

  proto_fr = proto_register_protocol("Frame Relay", "FR", "fr");
  proto_register_field_array(proto_fr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  fr_subdissector_table = register_dissector_table("fr.ietf");

  register_dissector("fr", dissect_fr_uncompressed, proto_fr);
}

void proto_reg_handoff_fr(void)
{
  dissector_add("wtap_encap", WTAP_ENCAP_FRELAY, dissect_fr, proto_fr);
  dissector_add("gre.proto", GRE_FR, dissect_fr, proto_fr);
  data_handle = find_dissector("data");
}
