/* packet-itdm.c
 * Routines for I-TDM (Internal TDM) dissection
 * Compliant to PICMG SFP.0 and SFP.1 March 24, 2005
 *
 * Copyright 2008, Dan Gora <dg [AT] adax.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "epan/prefs.h"

/* Initialize the protocol and registered fields */
static int proto_itdm        = -1;
static int hf_itdm_timestamp = -1;
static int hf_itdm_seqnum    = -1;
static int hf_itdm_sop_eop   = -1;
static int hf_itdm_last_pack = -1;
static int hf_itdm_pktlen    = -1;
static int hf_itdm_chksum    = -1;
static int hf_itdm_uid       = -1;
static int hf_itdm_ack       = -1;
static int hf_itdm_act       = -1;
static int hf_itdm_chcmd     = -1;
static int hf_itdm_chid      = -1;
static int hf_itdm_chloc1    = -1;
static int hf_itdm_chloc2    = -1;
static int hf_itdm_pktrate   = -1;
static int hf_itdm_cxnsize   = -1;

/* Initialize the subtree pointers */
static gint ett_itdm       = -1;

/* ZZZZ some magic number.. */
static guint gbl_ItdmMPLSLabel = 0x99887;

static dissector_handle_t data_handle;

#define ITDM_CMD_NEW_CHAN     1
#define ITDM_CMD_CLOSE_CHAN   2
#define ITDM_CMD_RELOC_CHAN   3
#define ITDM_CMD_CYCLIC_REAF  4
#define ITDM_CMD_PACKET_RATE  5

#define ITDM_FLOWID_OFFSET    7
#define ITDM_CHCMD_OFFSET    10
#define ITDM_CHANID_OFFSET   11
#define ITDM_CHLOC1_OFFSET   14
#define ITDM_CHLOC2_OFFSET   16

static const value_string sop_eop_vals[] = {
	{ 0x0, "Middle of Packet" },
	{ 0x1, "End of Packet" },
	{ 0x2, "Start of Packet" },
	{ 0x3, "Complete Packet" },
	{ 0, NULL }
};

#if 0
static const value_string ack_vals[] = {
	{ 0x0, "Normal Command" },
	{ 0x1, "Acknowledging a command from remote node" },
	{ 0, NULL }
};
#else
static const true_false_string ack_tfs = {
	"Acknowledging a command from remote node",
	"Normal Command"
};
#endif

static const value_string chcmd_vals[] = {
	{ 0x0, "Reserved" },
	{ 0x1, "New Channel ID" },
	{ 0x2, "Close Channel ID" },
	{ 0x3, "Relocate Channel ID" },
	{ 0x4, "Cyclic Reaffirmation" },
	{ 0x5, "Packet Rate Integrity Check" },
	{ 0x6, "Reserved" },
	{ 0x7, "Reserved" },
	{ 0x8, "Reserved" },
	{ 0x9, "Reserved" },
	{ 0xa, "Reserved" },
	{ 0xb, "Reserved" },
	{ 0xc, "Reserved" },
	{ 0xd, "Reserved" },
	{ 0xe, "Reserved" },
	{ 0xf, "Reserved" },
	{ 0, NULL }
};

static void
dissect_itdm_125usec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t	*next_tvb;
  proto_item *itdm_item = NULL;
  proto_tree *itdm_tree = NULL;
  int offset;
  guint32 flowid;
  guint32 chanid;
  guint16 chloc1;
  guint16 chloc2;
  guint8 chcmd;
  guint8 actbit;
  guint8 ackbit;


  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ITDM");

  flowid = tvb_get_ntoh24(tvb, ITDM_FLOWID_OFFSET);
  chanid = tvb_get_ntoh24(tvb, ITDM_CHANID_OFFSET);
  chcmd  = tvb_get_guint8(tvb, ITDM_CHCMD_OFFSET);
  chloc1 = tvb_get_ntohs(tvb, ITDM_CHLOC1_OFFSET);
  actbit = (chcmd & 0x10) ? 1 : 0;
  ackbit = (chcmd & 0x20) ? 1 : 0;
  chcmd  = chcmd & 0x0f;

  if (check_col(pinfo->cinfo, COL_INFO))
  {
    col_add_fstr(pinfo->cinfo, COL_INFO,
      "Flow %d Chan %d ACT %d ACK %d %s",
      flowid, chanid, actbit, ackbit,
      val_to_str(chcmd, chcmd_vals, "Reserved"));
    if (chcmd == ITDM_CMD_NEW_CHAN ||
        chcmd == ITDM_CMD_CLOSE_CHAN ||
        chcmd == ITDM_CMD_CYCLIC_REAF)
    {
      col_append_fstr(pinfo->cinfo, COL_INFO,
        " Loc1 %d", chloc1);
    }
    else if (chcmd == ITDM_CMD_RELOC_CHAN)
    {
      chloc2 = tvb_get_ntohs(tvb, ITDM_CHLOC2_OFFSET);
      col_append_fstr(pinfo->cinfo, COL_INFO,
        " Loc1 %d Loc2 %d", chloc1, chloc2);
    }
  }

  offset = 0;

  if (tree)
  {
	itdm_item = proto_tree_add_item(tree, proto_itdm, tvb, 0, -1, FALSE);
	itdm_tree = proto_item_add_subtree(itdm_item, ett_itdm);

	proto_tree_add_item(itdm_tree, hf_itdm_timestamp, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(itdm_tree, hf_itdm_seqnum, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(itdm_tree, hf_itdm_sop_eop, tvb, offset, 1, FALSE);
	proto_tree_add_item(itdm_tree, hf_itdm_last_pack, tvb, offset, 1, FALSE);
	proto_tree_add_item(itdm_tree, hf_itdm_pktlen, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(itdm_tree, hf_itdm_chksum, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_item(itdm_tree, hf_itdm_uid, tvb, offset, 3, FALSE);
	offset += 3;
	proto_tree_add_item(itdm_tree, hf_itdm_ack, tvb, offset, 1, FALSE);
	proto_tree_add_item(itdm_tree, hf_itdm_act, tvb, offset, 1, FALSE);
	proto_tree_add_item(itdm_tree, hf_itdm_chcmd, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(itdm_tree, hf_itdm_chid, tvb, offset, 3, FALSE);
	offset += 3;
	if (chcmd == ITDM_CMD_PACKET_RATE)
	{
		proto_tree_add_item(itdm_tree, hf_itdm_pktrate, tvb, offset, 4, FALSE);
		offset += 4;
	}
	else
	{
		proto_tree_add_item(itdm_tree, hf_itdm_chloc1, tvb, offset, 2, FALSE);
		offset += 2;
		if (chcmd == ITDM_CMD_CYCLIC_REAF ||
		    chcmd == ITDM_CMD_NEW_CHAN ||
		    chcmd == ITDM_CMD_CLOSE_CHAN)
		{
			proto_tree_add_item(itdm_tree, hf_itdm_cxnsize, tvb, offset, 2, FALSE);
			offset += 2;
		}
		else
		{
			proto_tree_add_item(itdm_tree, hf_itdm_chloc2, tvb, offset, 2, FALSE);
			offset += 2;
		}
	}
  };

  next_tvb = tvb_new_subset(tvb, offset, -1 , -1);
  call_dissector(data_handle, next_tvb, pinfo, tree);
}

static void
dissect_itdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* ZZZ for now, always 125 usec mode */
	if (tvb_length(tvb) < 18)
		return;

	dissect_itdm_125usec(tvb, pinfo, tree);
}

void proto_reg_handoff_itdm(void);

void
proto_register_itdm(void)
{

  static hf_register_info hf[] = {
    { &hf_itdm_timestamp,{ "Timestamp", "itdm.timestamp",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_seqnum,{ "Sequence Number", "itdm.seqnum",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_sop_eop,{ "Start/End of Packet", "itdm.sop_eop",
			FT_UINT8, BASE_DEC, VALS(sop_eop_vals), 0xc0, NULL, HFILL } },
    { &hf_itdm_last_pack,{ "Last Packet", "itdm.last_pack",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x20, NULL, HFILL } },
    { &hf_itdm_pktlen,{ "Packet Length", "itdm.pktlen",
			FT_UINT16, BASE_DEC, NULL, 0x07ff, NULL, HFILL } },
    { &hf_itdm_chksum,{ "Checksum", "itdm.chksum",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_uid,{ "Flow ID", "itdm.uid",
			FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_ack,{ "ACK", "itdm.ack",
			FT_BOOLEAN, 8, TFS(&ack_tfs), 0x20, NULL, HFILL } },
    { &hf_itdm_act,{ "Activate", "itdm.act",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10, NULL, HFILL } },
    { &hf_itdm_chcmd,{ "Channel Command", "itdm.chcmd",
			FT_UINT8, BASE_DEC, VALS(chcmd_vals), 0x0f, NULL, HFILL } },
    { &hf_itdm_chid,{ "Channel ID", "itdm.chid",
			FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_chloc1,{ "Channel Location 1", "itdm.chloc1",
			FT_UINT16, BASE_DEC, NULL, 0x1ff, NULL, HFILL } },
    { &hf_itdm_chloc2,{ "Channel Location 2", "itdm.chloc2",
			FT_UINT16, BASE_DEC, NULL, 0x1ff, NULL, HFILL } },
    { &hf_itdm_pktrate,{ "IEEE 754 Packet Rate", "itdm.pktrate",
			 FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_cxnsize, { "Connection Size", "itdm.cxnsize",
			 FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } }
  };

  static gint *ett[] = {
    &ett_itdm
  };

  module_t *itdm_module;

  proto_itdm = proto_register_protocol("Internal TDM", "ITDM", "itdm");
  register_dissector("itdm", dissect_itdm, proto_itdm);

  proto_register_field_array(proto_itdm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  itdm_module = prefs_register_protocol(proto_itdm, proto_reg_handoff_itdm);
  prefs_register_uint_preference(itdm_module, "mpls_label",
    "ITDM MPLS label (Flow Bundle ID)",
    "The MPLS label (aka Flow Bundle ID) used by ITDM traffic.",
    16, &gbl_ItdmMPLSLabel);
}

void
proto_reg_handoff_itdm(void)
{
	static gboolean Initialized=FALSE;
	static dissector_handle_t itdm_handle;
	static guint ItdmMPLSLabel;

	if (!Initialized) {
		itdm_handle = find_dissector("itdm");;
		data_handle = find_dissector("data");
		Initialized=TRUE;
	} else {
		dissector_delete("mpls.label", ItdmMPLSLabel, itdm_handle);
	}

	ItdmMPLSLabel = gbl_ItdmMPLSLabel;
	dissector_add("mpls.label", gbl_ItdmMPLSLabel, itdm_handle);
}
