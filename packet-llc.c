/* packet-llc.c
 * Routines for IEEE 802.2 LLC layer
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-llc.c,v 1.53 2000/04/12 20:24:34 gram Exp $
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

typedef void (capture_func_t)(const u_char *, int, packet_counts *);
typedef void (dissect_func_t)(const u_char *, int, frame_data *, proto_tree *);

/* The SAP info is split into two tables, one value_string table and one table of sap_info. This is
 * so that the value_string can be used in the header field registration.
 */
struct sap_info {
	guint8	sap;
	capture_func_t *capture_func;
	dissect_func_t *dissect_func;
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

#define	SAP_SNAP	0xAA

/*
 * These are for SSAP and DSAP, wth last bit always zero.
 * XXX - some DSAPs come in separate "individual" and "group" versions,
 * with the last bit 0 and 1, respectively (e.g., LLC Sub-layer Management,
 * IBM SNA Path Control, IBM Net Management), but, whilst 0xFE is
 * the ISO Network Layer Protocol, 0xFF is the Global LSAP.
 */
static const value_string sap_vals[] = {
	{ 0x00,     "NULL LSAP" },
	{ 0x02,     "LLC Sub-Layer Management" },
	{ 0x04,     "SNA Path Control" },
	{ 0x06,     "TCP/IP" },
	{ 0x08,     "SNA" },
	{ 0x0C,     "SNA" },
	{ 0x0E,     "PROWAY (IEC955) Network Management and Initialization" },
	{ 0x18,     "Texas Instruments" },
	{ 0x42,     "Spanning Tree BPDU" },
	{ 0x4E,     "EIA RS-511 Manufacturing Message Service" },
#if 0
	/* XXX - setting the group bit makes this 0x7F; is that just
	   a group version of this? */
	{ 0x7E,     "ISO 8208 (X.25 over 802.2 Type 2)" },
#endif
	{ 0x7F,     "ISO 802.2" },
	{ 0x80,     "XNS" },
	{ 0x86,     "Nestar" },
	{ 0x8E,     "PROWAY (IEC955) Active Station List Maintenance" },
	{ 0x98,     "ARP" },	/* XXX - hand to "dissect_arp()"? */
	{ SAP_SNAP, "SNAP" },
	{ 0xBA,     "Banyan Vines" },
	{ 0xBC,     "Banyan Vines" },
	{ 0xE0,     "NetWare" },
	{ 0xF0,     "NetBIOS" },
	{ 0xF4,     "IBM Net Management" },
	{ 0xF8,     "Remote Program Load" },
	{ 0xFA,     "Ungermann-Bass" },
	{ 0xFC,     "Remote Program Load" },
	{ 0xFE,     "ISO Network Layer" },
	{ 0xFF,     "Global LSAP" },
	{ 0x00,     NULL }
};

static struct sap_info	saps[] = {
	{ 0x00,		NULL,		NULL },
	{ 0x02,		NULL,		NULL },
	{ 0x03,		NULL,		NULL },
	{ 0x04,		NULL,		dissect_sna },
	{ 0x05,		NULL,		NULL },
	{ 0x06,		capture_ip,	dissect_ip },
	{ 0x08,		NULL,		NULL },
	{ 0x0C,		NULL,		NULL },
	{ 0x42,		NULL,		dissect_bpdu },
	{ 0x7F,		NULL,		NULL },
	{ 0x80,		NULL,		NULL },
	{ SAP_SNAP,	NULL,		NULL },
	{ 0xBA,		NULL,		NULL },
	{ 0xBC,		NULL,		NULL },
	{ 0xE0,		capture_ipx,	dissect_ipx },
	{ 0xF0,		capture_netbios, dissect_netbios },
	{ 0xF4,		NULL,		NULL },
	{ 0xF5,		NULL,		NULL },
	{ 0xF8,		NULL,		NULL },
	{ 0xFC,		NULL,		NULL },
	{ 0xFE,		NULL,		dissect_osi },
	{ 0xFF,		NULL,		NULL },
	{ 0x00,		NULL,		NULL}
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

static dissect_func_t *
sap_dissect_func(u_char sap) {
	int i=0;

	/* look for the second record where sap == 0, which should
	 * be the last record
	 */
	while (saps[i].sap > 0 || i == 0) {
		if (saps[i].sap == sap) {
			return saps[i].dissect_func;
		}
		i++;
	}
	return &dissect_data;
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
dissect_llc(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*llc_tree = NULL;
	proto_item	*ti = NULL;
	int		is_snap;
	guint16		control;
	int		llc_header_len;
	guint32		oui;
	guint16		etype;
	dissect_func_t	*dissect;

	if (!BYTES_ARE_IN_FRAME(offset, 2)) {
		dissect_data(pd, offset, fd, tree);
		return;
	}
	is_snap = (pd[offset] == SAP_SNAP) && (pd[offset+1] == SAP_SNAP);
	llc_header_len = 2;	/* DSAP + SSAP */

	if (check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd, COL_PROTOCOL, "LLC");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_llc, offset, 0, NULL);
		llc_tree = proto_item_add_subtree(ti, ett_llc);
		proto_tree_add_item(llc_tree, hf_llc_dsap, offset, 
			1, pd[offset] & SAP_MASK);
		proto_tree_add_item(llc_tree, hf_llc_dsap_ig, offset, 
			1, pd[offset] & DSAP_GI_BIT);
		proto_tree_add_item(llc_tree, hf_llc_ssap, offset+1, 
			1, pd[offset+1] & SAP_MASK);
		proto_tree_add_item(llc_tree, hf_llc_ssap_cr, offset+1, 
			1, pd[offset+1] & SSAP_CR_BIT);
	} else
		llc_tree = NULL;

	/*
	 * XXX - the page referred to in the comment above about the
	 * Command/Response bit also implies that LLC Type 2 always
	 * uses extended operation, so we don't need to determine
	 * whether it's basic or extended operation; is that the case?
	 */
	control = dissect_xdlc_control(pd, offset+2, fd, llc_tree,
				hf_llc_ctrl, ett_llc_ctrl,
				pd[offset+1] & SSAP_CR_BIT, TRUE);
	llc_header_len += XDLC_CONTROL_LEN(control, TRUE);
	if (is_snap)
		llc_header_len += 5;	/* 3 bytes of OUI, 2 bytes of protocol ID */
	if (!BYTES_ARE_IN_FRAME(offset, llc_header_len)) {
		dissect_data(pd, offset, fd, tree);
		return;
	}
	if (tree)
		proto_item_set_len(ti, llc_header_len);

	/*
	 * XXX - do we want to append the SAP information to the stuff
	 * "dissect_xdlc_control()" put in the COL_INFO column, rather
	 * than overwriting it?
	 */
	if (is_snap) {
		oui = pd[offset+3] << 16 | pd[offset+4] << 8 | pd[offset+5];
		etype = pntohs(&pd[offset+6]);
		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO, "SNAP, OUI 0x%06X (%s), PID 0x%04X",
			    oui, val_to_str(oui, oui_vals, "Unknown"),
			    etype);
		}
		if (tree) {
			proto_tree_add_item(llc_tree, hf_llc_oui, offset+3, 3,
				oui);
		}
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
				ethertype(etype, offset+8, pd,
				    fd, tree, llc_tree, hf_llc_type);
			} else
				dissect_data(pd, offset+8, fd, tree);
			break;

		case OUI_CISCO:
			/* So are all CDP packets LLC packets
			   with an OUI of OUI_CISCO and a
			   protocol ID of 0x2000, or
			   are some of them raw or encapsulated
			   Ethernet? */
			if (tree) {
				proto_tree_add_item(llc_tree,
				    hf_llc_pid, offset+6, 2, etype);
			}
			if (XDLC_IS_INFORMATION(control)) {
				switch (etype) {

#if 0
				case 0x0102:
					dissect_drip(pd, offset+8, fd, tree);
					break;
#endif

				case 0x2000:
					dissect_cdp(pd, offset+8, fd, tree);
					break;

				case 0x2001:
					dissect_cgmp(pd, offset+8, fd, tree);
					break;

				case 0x2003:
					dissect_vtp(pd, offset+8, fd, tree);
					break;

				default:
					dissect_data(pd, offset+8, fd, tree);
					break;
				}
			} else
				dissect_data(pd, offset+8, fd, tree);
			break;

		case OUI_CABLE_BPDU:    /* DOCSIS cable modem spanning tree BPDU */
			if (tree) {
				proto_tree_add_item(llc_tree,
				hf_llc_pid, offset+6, 2, etype);
			}
			dissect_bpdu(pd, offset+8, fd, tree);
			break;

		default:
			if (tree) {
				proto_tree_add_item(llc_tree,
				    hf_llc_pid, offset+6, 2, etype);
			}
			dissect_data(pd, offset+8, fd, tree);
			break;
		}
	}		
	else {
		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO, 
			    "DSAP %s %s, SSAP %s %s",
			    val_to_str(pd[offset] & SAP_MASK, sap_vals, "%02x"),
			    pd[offset] & DSAP_GI_BIT ?
			      "Group" : "Individual",
			    val_to_str(pd[offset+1] & SAP_MASK, sap_vals, "%02x"),
			    pd[offset+1] & SSAP_CR_BIT ?
			      "Response" : "Command"
			);
		}

		if (XDLC_IS_INFORMATION(control)) {
			dissect = sap_dissect_func(pd[offset]);

			/* non-SNAP */
			offset += llc_header_len;

			if (dissect) {
				dissect(pd, offset, fd, tree);
			}
			else {
				dissect_data(pd, offset, fd, tree);
			}
		} else {
			offset += llc_header_len;
			dissect_data(pd, offset, fd, tree);
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
		{ "Control", "llc.control", FT_UINT8, BASE_HEX, 
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
}
