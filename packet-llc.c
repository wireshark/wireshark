/* packet-llc.c
 * Routines for IEEE 802.2 LLC layer
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-llc.c,v 1.60 2000/05/16 04:44:12 gram Exp $
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"
#include "oui.h"
#include "xdlc.h"
#include "etypes.h"
#include "llcsaps.h"
#include "packet-bpdu.h"
#include "packet-cdp.h"
#include "packet-cgmp.h"
#include "packet-ip.h"
#include "packet-ipx.h"
#include "packet-netbios.h"
#include "packet-osi.h"
#include "packet-sna.h"
#include "packet-vtp.h"

static int proto_llc = -1;
static int hf_llc_dsap = -1;
static int hf_llc_ssap = -1;
static int hf_llc_dsap_ig = -1;
static int hf_llc_ssap_cr = -1;
static int hf_llc_ctrl = -1;
static int hf_llc_type = -1;
static int hf_llc_oui = -1;
static int hf_llc_pid = -1;

static gint ett_llc = -1;
static gint ett_llc_ctrl = -1;

static dissector_table_t subdissector_table;

typedef void (capture_func_t)(const u_char *, int, packet_counts *);

/* The SAP info is split into two tables, one value_string table and one
 * table of sap_info. This is so that the value_string can be used in the
 * header field registration.
 */
struct sap_info {
	guint8	sap;
	capture_func_t *capture_func;
};

/*
 * Group/Individual bit, in the DSAP.
 */
#define	DSAP_GI_BIT	0x01

/*
 * Command/Response bit, in the SSAP.
 *
 * The low-order bit of the SSAP apparently determines whether this
 * is a request or a response.  (RFC 1390, "Transmission of IP and
 * ARP over FDDI Networks", says
 *
 *	Command frames are identified by having the low order
 *	bit of the SSAP address reset to zero.  Response frames
 *	have the low order bit of the SSAP address set to one.
 *
 * and a page I've seen seems to imply that's part of 802.2.)
 */
#define	SSAP_CR_BIT	0x01

/*
 * Mask to extrace the SAP number from the DSAP or the SSAP.
 */
#define	SAP_MASK	0xFE

/*
 * These are for SSAP and DSAP, wth last bit always zero.
 * XXX - some DSAPs come in separate "individual" and "group" versions,
 * with the last bit 0 and 1, respectively (e.g., LLC Sub-layer Management,
 * IBM SNA Path Control, IBM Net Management), but, whilst 0xFE is
 * the ISO Network Layer Protocol, 0xFF is the Global LSAP.
 */
static const value_string sap_vals[] = {
	{ SAP_NULL,           "NULL LSAP" },
	{ SAP_LLC_SLMGMT,     "LLC Sub-Layer Management" },
	{ SAP_SNA_PATHCTRL,   "SNA Path Control" },
	{ SAP_IP,             "TCP/IP" },
	{ SAP_SNA1,           "SNA" },
	{ SAP_SNA2,           "SNA" },
	{ SAP_PROWAY_NM_INIT, "PROWAY (IEC955) Network Management and Initialization" },
	{ SAP_TI,             "Texas Instruments" },
	{ SAP_BPDU,           "Spanning Tree BPDU" },
	{ SAP_RS511,          "EIA RS-511 Manufacturing Message Service" },
#if 0
	/* XXX - setting the group bit makes this 0x7F; is that just
	   a group version of this? */
	{ 0x7E,               "ISO 8208 (X.25 over 802.2 Type 2)" },
#endif
	{ 0x7F,               "ISO 802.2" },
	{ SAP_XNS,            "XNS" },
	{ SAP_NESTAR,         "Nestar" },
	{ SAP_PROWAY_ASLM,    "PROWAY (IEC955) Active Station List Maintenance" },
	{ SAP_ARP,            "ARP" },	/* XXX - hand to "dissect_arp()"? */
	{ SAP_SNAP,           "SNAP" },
	{ SAP_VINES1,         "Banyan Vines" },
	{ SAP_VINES2,         "Banyan Vines" },
	{ SAP_NETWARE,        "NetWare" },
	{ SAP_NETBIOS,        "NetBIOS" },
	{ SAP_IBMNM,          "IBM Net Management" },
	{ SAP_RPL1,           "Remote Program Load" },
	{ SAP_UB,             "Ungermann-Bass" },
	{ SAP_RPL2,           "Remote Program Load" },
	{ SAP_OSINL,          "ISO Network Layer" },
	{ SAP_GLOBAL,         "Global LSAP" },
	{ 0x00,               NULL }
};

static struct sap_info	saps[] = {
	{ SAP_IP,			capture_ip },
	{ SAP_NETWARE,			capture_ipx },
	{ SAP_NETBIOS,			capture_netbios },
	{ 0x00,				NULL}
};

/*
 * See
 *
 * http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/vlan.htm
 *
 * for the PIDs for VTP and DRiP that go with an OUI of OUI_CISCO.
 */
const value_string oui_vals[] = {
	{ OUI_ENCAP_ETHER, "Encapsulated Ethernet" },
/*
http://www.cisco.com/univercd/cc/td/doc/product/software/ios113ed/113ed_cr/ibm_r/brprt1/brsrb.htm
*/
	{ OUI_CISCO,       "Cisco" },
	{ OUI_CISCO_90,    "Cisco IOS 9.0 Compatible" },
	{ OUI_BFR,         "Bridged Frame-Relay" }, /* RFC 2427 */
	{ OUI_ATM_FORUM,   "ATM Forum" },
	{ OUI_APPLE_ATALK, "Apple (AppleTalk)" },
	{ OUI_CABLE_BPDU,  "DOCSIS Spanning Tree" }, /* DOCSIS spanning tree BPDU */
	{ 0,               NULL }
};

static capture_func_t *
sap_capture_func(u_char sap) {
	int i=0;

	/* look for the second record where sap == 0, which should
	 * be the last record
	 */
	while (saps[i].sap > 0 || i == 0) {
		if (saps[i].sap == sap) {
			return saps[i].capture_func;
		}
		i++;
	}
	return NULL;
}

void
capture_llc(const u_char *pd, int offset, packet_counts *ld) {

	int		is_snap;
	guint16		control;
	int		llc_header_len;
	guint32		oui;
	guint16		etype;
	capture_func_t	*capture;

	if (!BYTES_ARE_IN_FRAME(offset, 2)) {
		ld->other++;
		return;
	}
	is_snap = (pd[offset] == SAP_SNAP) && (pd[offset+1] == SAP_SNAP);
	llc_header_len = 2;	/* DSAP + SSAP */

	/*
	 * XXX - the page referred to in the comment above about the
	 * Command/Response bit also implies that LLC Type 2 always
	 * uses extended operation, so we don't need to determine
	 * whether it's basic or extended operation; is that the case?
	 */
	control = get_xdlc_control(pd, offset+2, pd[offset+1] & SSAP_CR_BIT,
	    TRUE);
	llc_header_len += XDLC_CONTROL_LEN(control, TRUE);
	if (is_snap)
		llc_header_len += 5;	/* 3 bytes of OUI, 2 bytes of protocol ID */
	if (!BYTES_ARE_IN_FRAME(offset, llc_header_len)) {
		ld->other++;
		return;
	}

	if (is_snap) {
		oui = pd[offset+3] << 16 | pd[offset+4] << 8 | pd[offset+5];
		if (XDLC_IS_INFORMATION(control)) {
			etype = pntohs(&pd[offset+6]);
			switch (oui) {

			case OUI_ENCAP_ETHER:
			case OUI_APPLE_ATALK:
				/* No, I have no idea why Apple used
				   one of their own OUIs, rather than
				   OUI_ENCAP_ETHER, and an Ethernet
				   packet type as protocol ID, for
				   AppleTalk data packets - but used
				   OUI_ENCAP_ETHER and an Ethernet
				   packet type for AARP packets. */
				capture_ethertype(etype, offset+8, pd,
				    ld);
				break;
			case OUI_CISCO:
				capture_ethertype(etype,
						offset + 8, pd, ld);
				break;
			default:
				ld->other++;
				break;
			}
		}
	}		
	else {
		if (XDLC_IS_INFORMATION(control)) {
			capture = sap_capture_func(pd[offset]);

			/* non-SNAP */
			offset += llc_header_len;

			if (capture) {
				capture(pd, offset, ld);
			}
			else {
				ld->other++;
			}
		}
	}
}

void
dissect_llc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*llc_tree = NULL;
	proto_item	*ti = NULL;
	int		is_snap;
	guint16		control;
	int		llc_header_len;
	guint32		oui;
	guint16		etype;
	guint8		dsap, ssap;
	tvbuff_t	*next_tvb;
	const guint8	*pd;
	int		offset;

	pinfo->current_proto = "LLC";

	if (check_col(pinfo->fd, COL_PROTOCOL)) {
		col_add_str(pinfo->fd, COL_PROTOCOL, "LLC");
	}

	dsap = tvb_get_guint8(tvb, 0);
	ssap = tvb_get_guint8(tvb, 1);

	is_snap = (dsap == SAP_SNAP) && (ssap == SAP_SNAP);
	llc_header_len = 2;	/* DSAP + SSAP */

	if (tree) {
		ti = proto_tree_add_item(tree, proto_llc, tvb, 0, 0, NULL);
		llc_tree = proto_item_add_subtree(ti, ett_llc);
		proto_tree_add_item(llc_tree, hf_llc_dsap, tvb, 0, 
			1, dsap & SAP_MASK);
		proto_tree_add_item(llc_tree, hf_llc_dsap_ig, tvb, 0, 
			1, dsap & DSAP_GI_BIT);
		proto_tree_add_item(llc_tree, hf_llc_ssap, tvb, 1, 
			1, ssap & SAP_MASK);
		proto_tree_add_item(llc_tree, hf_llc_ssap_cr, tvb, 1, 
			1, ssap & SSAP_CR_BIT);
	} else
		llc_tree = NULL;

	/*
	 * XXX - the page referred to in the comment above about the
	 * Command/Response bit also implies that LLC Type 2 always
	 * uses extended operation, so we don't need to determine
	 * whether it's basic or extended operation; is that the case?
	 */
	tvb_compat(tvb, &pd, &offset);
	control = dissect_xdlc_control(pd, offset+2, pinfo->fd, llc_tree,
				hf_llc_ctrl, ett_llc_ctrl,
				pd[offset+1] & SSAP_CR_BIT, TRUE);
	llc_header_len += XDLC_CONTROL_LEN(control, TRUE);
	if (is_snap)
		llc_header_len += 5;	/* 3 bytes of OUI, 2 bytes of protocol ID */

	if (tree)
		proto_item_set_len(ti, llc_header_len);

	/*
	 * XXX - do we want to append the SAP information to the stuff
	 * "dissect_xdlc_control()" put in the COL_INFO column, rather
	 * than overwriting it?
	 */
	if (is_snap) {
		oui =	tvb_get_guint8(tvb, 3) << 16 |
			tvb_get_guint8(tvb, 4) << 8  |
			tvb_get_guint8(tvb, 5);
		etype = tvb_get_ntohs(tvb, 6);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO, "SNAP, OUI 0x%06X (%s), PID 0x%04X",
			    oui, val_to_str(oui, oui_vals, "Unknown"),
			    etype);
		}
		if (tree) {
			proto_tree_add_item(llc_tree, hf_llc_oui, tvb, 3, 3,
				oui);
		}

		next_tvb = tvb_new_subset(tvb, 8, -1, -1);
		tvb_compat(next_tvb, &pd, &offset);

		switch (oui) {

		case OUI_ENCAP_ETHER:
		case OUI_APPLE_ATALK:
			/* No, I have no idea why Apple used
			   one of their own OUIs, rather than
			   OUI_ENCAP_ETHER, and an Ethernet
			   packet type as protocol ID, for
			   AppleTalk data packets - but used
			   OUI_ENCAP_ETHER and an Ethernet
			   packet type for AARP packets. */
			if (XDLC_IS_INFORMATION(control)) {
				ethertype(etype, offset, pd,
				    pinfo->fd, tree, llc_tree, hf_llc_type);
			} else
				dissect_data_tvb(next_tvb, pinfo, tree);
			break;

		case OUI_CISCO:
			/* So are all CDP packets LLC packets
			   with an OUI of OUI_CISCO and a
			   protocol ID of 0x2000, or
			   are some of them raw or encapsulated
			   Ethernet? */
			if (tree) {
				proto_tree_add_item(llc_tree,
				    hf_llc_pid, tvb, 6, 2, etype);
			}
			if (XDLC_IS_INFORMATION(control)) {
				switch (etype) {

#if 0
				case 0x0102:
					dissect_drip(pd, offset, pinfo->fd, tree);
					break;
#endif

				case 0x2000:
					dissect_cdp(pd, offset, pinfo->fd, tree);
					break;

				case 0x2001:
					dissect_cgmp(pd, offset, pinfo->fd, tree);
					break;

				case 0x2003:
					dissect_vtp(pd, offset, pinfo->fd, tree);
					break;

				default:
					dissect_data_tvb(next_tvb, pinfo, tree);
					break;
				}
			} else
				dissect_data_tvb(next_tvb, pinfo, tree);
			break;

		case OUI_CABLE_BPDU:    /* DOCSIS cable modem spanning tree BPDU */
			if (tree) {
				proto_tree_add_item(llc_tree,
				hf_llc_pid, tvb, 6, 2, etype);
			}
			dissect_bpdu(pd, offset, pinfo->fd, tree);
			break;

		default:
			if (tree) {
				proto_tree_add_item(llc_tree,
				    hf_llc_pid, tvb, 6, 2, etype);
			}
			dissect_data_tvb(next_tvb, pinfo, tree);
			break;
		}
	}
	else {
		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO, 
			    "DSAP %s %s, SSAP %s %s",
			    val_to_str(dsap & SAP_MASK, sap_vals, "%02x"),
			    dsap & DSAP_GI_BIT ?
			      "Group" : "Individual",
			    val_to_str(ssap & SAP_MASK, sap_vals, "%02x"),
			    ssap & SSAP_CR_BIT ?
			      "Response" : "Command"
			);
		}

		next_tvb = tvb_new_subset(tvb, llc_header_len, -1, -1);
		if (XDLC_IS_INFORMATION(control)) {
			tvb_compat(tvb, &pd, &offset);
			/* non-SNAP */
			offset += llc_header_len;

			/* do lookup with the subdissector table */
			if (!dissector_try_port(subdissector_table, dsap,
			    pd, offset, pinfo->fd, tree)) {
				dissect_data_tvb(next_tvb, pinfo, tree);
			}
		} else {
			dissect_data_tvb(next_tvb, pinfo, tree);
		}
	}
}

void
proto_register_llc(void)
{
	static struct true_false_string ig_bit = { "Group", "Individual" };
	static struct true_false_string cr_bit = { "Response", "Command" };

	static hf_register_info hf[] = {
		{ &hf_llc_dsap,
		{ "DSAP",	"llc.dsap", FT_UINT8, BASE_HEX, 
			VALS(sap_vals), 0x0, "" }},

		{ &hf_llc_dsap_ig,
		{ "IG Bit",	"llc.dsap.ig", FT_BOOLEAN, BASE_HEX, 
			&ig_bit, 0x0, "Individual/Group" }},

		{ &hf_llc_ssap,
		{ "SSAP", "llc.ssap", FT_UINT8, BASE_HEX, 
			VALS(sap_vals), 0x0, "" }},

		{ &hf_llc_ssap_cr,
		{ "CR Bit", "llc.ssap.cr", FT_BOOLEAN, BASE_HEX, 
			&cr_bit, 0x0, "Command/Response" }},

		{ &hf_llc_ctrl,
		{ "Control", "llc.control", FT_UINT16, BASE_HEX, 
			NULL, 0x0, "" }},

		/* registered here but handled in ethertype.c */
		{ &hf_llc_type,
		{ "Type", "llc.type", FT_UINT16, BASE_HEX, 
			VALS(etype_vals), 0x0, "" }},

		{ &hf_llc_oui,
		{ "Organization Code",	"llc.oui", FT_UINT24, BASE_HEX, 
			VALS(oui_vals), 0x0, ""}},

		{ &hf_llc_pid,
		{ "Protocol ID", "llc.pid", FT_UINT16, BASE_HEX, 
			NULL, 0x0, ""}}
	};
	static gint *ett[] = {
		&ett_llc,
		&ett_llc_ctrl,
	};

	proto_llc = proto_register_protocol ("Logical-Link Control", "llc" );
	proto_register_field_array(proto_llc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	subdissector_table = register_dissector_table("llc.dsap");
}
