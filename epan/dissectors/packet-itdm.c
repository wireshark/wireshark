/* packet-itdm.c
 * Routines for I-TDM (Internal TDM) dissection
 * Compliant to PICMG SFP.0 and SFP.1 March 24, 2005
 *
 * Copyright 2008, Dan Gora <dg [AT] adax.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_itdm(void);
void proto_reg_handoff_itdm(void);

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

/* I-TDM control protocol fields */
static int hf_itdm_ctl_transid   = -1;
static int hf_itdm_ctl_command   = -1;
static int hf_itdm_ctl_flowid    = -1;
static int hf_itdm_ctl_dm        = -1;
static int hf_itdm_ctl_emts      = -1;
static int hf_itdm_ctl_pktrate   = -1;
static int hf_itdm_ctl_ptid      = -1;
static int hf_itdm_ctl_cksum     = -1;


/* Initialize the subtree pointers */
static gint ett_itdm       = -1;
static gint ett_itdm_ctl   = -1;

/* ZZZZ some magic number.. */
static guint gbl_ItdmMPLSLabel = 0x99887;
static guint gbl_ItdmCTLFlowNo = 0;

/* I-TDM 125usec mode commands for data flows */
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

/* I-TDM commands for I-TDM control flows */
#define ITDM_CTL_TRANSID_OFFSET    10
#define ITDM_CTL_CMD_OFFSET        14
#define ITDM_CTL_FLOWID_OFFSET     15
#define ITDM_CTL_ITDM_MODE_OFFSET  18
#define ITDM_CTL_EMTS_OFFSET       20
#define ITDM_CTL_PKTRATE_OFFSET    22
#define ITDM_CTL_PAIRED_TRANSID_OFFSET    26
#define ITDM_CTL_CRC_OFFSET        30

#define ITDM_CTL_CMD_AFI_REQ  1

static const value_string sop_eop_vals[] = {
  { 0x0, "Middle of Packet" },
  { 0x1, "End of Packet" },
  { 0x2, "Start of Packet" },
  { 0x3, "Complete Packet" },
  { 0, NULL }
};

static const true_false_string ack_tfs = {
  "Acknowledging a command from remote node",
  "Normal Command"
};

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

static const value_string itdm_ctl_command_vals[] = {
  { 0x0, "Not Used" },
  { 0x1, "AFI_REQ: Alloc Flow ID Req" },
  { 0x2, "AFI_RSP: Alloc Flow ID Rsp - Req Accepted." },
  { 0x3, "DFI_REQ: Dealloc Flow ID Req" },
  { 0x4, "DFI_RSP: Dealloc Flow ID Rsp - Req Accepted." },

  { 0x10, "AFI_RSP: Reject: Data Mode Field value Not Supported." },
  { 0x11, "AFI_RSP: Reject: Explicit Multi-timeslot value Not Supported." },
  { 0x12, "AFI_RSP: Reject: Packet Rate value Not Supported." },
  { 0x13, "AFI_RSP: Reject: Checksum Invalid." },
  { 0x14, "AFI_RSP: Reject: No more flows available." },

  { 0x20, "DFI_RSP: Reject: Data Mode Field value does not match Flow ID." },
  { 0x21, "DFI_RSP: Reject: Explicit Multi-timeslots value does not match." },
  { 0x22, "DFI_RSP: Reject: Packet Rate value does not match." },
  { 0x23, "DFI_RSP: Reject: Checksum Invalid." },
  { 0x24, "DFI_RSP: Reject: Flow ID invalid (out of range)." },
  { 0x25, "DFI_RSP: Reject: Flow ID not currently allocated." },
  { 0x26, "DFI_RSP: Reject: Other Flow ID in pair has active connections." },
  { 0, NULL }
};

static const value_string itdm_ctl_data_mode_vals[] = {
  { 0, "Not Used." },
  { 1, "I-TDM 1ms Data Mode." },
  { 2, "I-TDM 125usec Data Mode." },
  { 3, "I-TDM Explicit Multi-timeslot Data Mode." },
  { 4, "I-TDM CAS Signaling Data Mode." },
  { 0, NULL }
};

static const value_string itdm_ctl_pktrate_vals[] = {
  { 0x447A0000, "I-TDM 1ms Data Mode." },
  { 0x45FA0000, "I-TDM 125usec/EMTS Data Mode." },
  { 0x43A6AAAB, "I-TDM T1 CAS Mode." },
  { 0x43FA0000, "I-TDM E1 CAS Mode." },
  { 0, NULL }
};

static void
dissect_itdm_125usec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t  *next_tvb;
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


  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ITDM");

  flowid = tvb_get_ntoh24(tvb, ITDM_FLOWID_OFFSET);
  chanid = tvb_get_ntoh24(tvb, ITDM_CHANID_OFFSET);
  chcmd  = tvb_get_guint8(tvb, ITDM_CHCMD_OFFSET);
  chloc1 = tvb_get_ntohs(tvb, ITDM_CHLOC1_OFFSET);
  actbit = (chcmd & 0x10) ? 1 : 0;
  ackbit = (chcmd & 0x20) ? 1 : 0;
  chcmd  = chcmd & 0x0f;

  col_add_fstr(pinfo->cinfo, COL_INFO,
      "Flow %d Chan %d ACT %d ACK %d %s",
      flowid, chanid, actbit, ackbit,
      val_to_str_const(chcmd, chcmd_vals, "Reserved"));
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

  offset = 0;

  if (tree)
  {
  itdm_item = proto_tree_add_item(tree, proto_itdm, tvb, 0, -1, ENC_NA);
  itdm_tree = proto_item_add_subtree(itdm_item, ett_itdm);

  proto_tree_add_item(itdm_tree, hf_itdm_timestamp, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(itdm_tree, hf_itdm_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(itdm_tree, hf_itdm_sop_eop, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(itdm_tree, hf_itdm_last_pack, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(itdm_tree, hf_itdm_pktlen, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_checksum(itdm_tree, tvb, offset, hf_itdm_chksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
  offset += 2;
  proto_tree_add_item(itdm_tree, hf_itdm_uid, tvb, offset, 3, ENC_BIG_ENDIAN);
  offset += 3;
  proto_tree_add_item(itdm_tree, hf_itdm_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(itdm_tree, hf_itdm_act, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(itdm_tree, hf_itdm_chcmd, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(itdm_tree, hf_itdm_chid, tvb, offset, 3, ENC_BIG_ENDIAN);
  offset += 3;
  if (chcmd == ITDM_CMD_PACKET_RATE)
  {
    proto_tree_add_item(itdm_tree, hf_itdm_pktrate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  }
  else
  {
    proto_tree_add_item(itdm_tree, hf_itdm_chloc1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (chcmd == ITDM_CMD_CYCLIC_REAF ||
        chcmd == ITDM_CMD_NEW_CHAN ||
        chcmd == ITDM_CMD_CLOSE_CHAN)
    {
      proto_tree_add_item(itdm_tree, hf_itdm_cxnsize, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    else
    {
      proto_tree_add_item(itdm_tree, hf_itdm_chloc2, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
  }
  }

  next_tvb = tvb_new_subset_remaining(tvb, offset);
  call_data_dissector(next_tvb, pinfo, tree);
}

static void
dissect_itdm_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t  *next_tvb;
  proto_item *itdm_ctl_item = NULL;
  proto_tree *itdm_ctl_tree = NULL;
  int offset;
  guint32 flowid;
  guint8 command;
  guint32 trans_id;
  guint32 paired_trans_id;
  guint32 allocd_flowid;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ITDM-Control");

  flowid = tvb_get_ntoh24(tvb, ITDM_FLOWID_OFFSET);
  command = tvb_get_guint8(tvb, ITDM_CTL_CMD_OFFSET);
  allocd_flowid = tvb_get_ntoh24(tvb, ITDM_CTL_FLOWID_OFFSET);
  trans_id = tvb_get_ntohl(tvb, ITDM_CTL_TRANSID_OFFSET);
  paired_trans_id = tvb_get_ntohl(tvb, ITDM_CTL_PAIRED_TRANSID_OFFSET);

  col_add_fstr(pinfo->cinfo, COL_INFO,
      "Flow %d Command %s ",
      flowid, val_to_str_const(command, itdm_ctl_command_vals, "Reserved"));

  if (command != ITDM_CTL_CMD_AFI_REQ )
  {
    col_append_fstr(pinfo->cinfo, COL_INFO,
        " Alloc'd FlowID %d", allocd_flowid);
  }

  col_append_fstr(pinfo->cinfo, COL_INFO, " TransID 0x%x ", trans_id);

  if (command != ITDM_CTL_CMD_AFI_REQ )
  {
    col_append_fstr(pinfo->cinfo, COL_INFO,
        " Paired TransID 0x%x", paired_trans_id);
  }

  offset = 0;

  if (tree)
  {
  itdm_ctl_item = proto_tree_add_item(tree, proto_itdm, tvb, 0, -1, ENC_NA);
  itdm_ctl_tree = proto_item_add_subtree(itdm_ctl_item, ett_itdm_ctl);

  /* These eventually should go into a SFP.0 dissector... */
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_timestamp, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_seqnum, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_sop_eop, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_last_pack, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_pktlen, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_checksum(itdm_ctl_tree, tvb, offset, hf_itdm_chksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
  offset += 2;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_uid, tvb, offset, 3, ENC_BIG_ENDIAN);
  offset += 3;

  proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_transid, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_command, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  if (command != ITDM_CTL_CMD_AFI_REQ) {
    proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_flowid, tvb, offset, 3, ENC_BIG_ENDIAN);
  }
  offset += 3;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_dm, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  /* rsvd.. */
  offset += 1;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_emts, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_pktrate, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  if (command != ITDM_CTL_CMD_AFI_REQ) {
    proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_ptid, tvb, offset, 4, ENC_BIG_ENDIAN);
  }
  offset += 4;
  /* rsvd.. */
  offset += 2;
  proto_tree_add_item(itdm_ctl_tree, hf_itdm_ctl_cksum, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  }

  next_tvb = tvb_new_subset_remaining(tvb, offset);
  call_data_dissector(next_tvb, pinfo, tree);
}

static int
dissect_itdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint32 flowid;

  /* ZZZ for now, 125 usec mode and I-TDM control protocol
   * need to add 1ms mode */
  if (tvb_captured_length(tvb) < 18)
    return 0;

  /* See if this packet is a data flow or the I-TDM control flow. */
  flowid = tvb_get_ntoh24(tvb, ITDM_FLOWID_OFFSET);

  /* gbl_ItdmCTLFlowNo is the configurable flow number where
   * the control protocol resides... Usually 0.
   */
  if (flowid == gbl_ItdmCTLFlowNo)
    dissect_itdm_control(tvb, pinfo, tree);
  else
    dissect_itdm_125usec(tvb, pinfo, tree);
  return tvb_captured_length(tvb);
}

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
       FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_itdm_ctl_transid, { "Transaction ID", "itdm.ctl_transid",
       FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_command, { "Control Command", "itdm.ctl_cmd",
       FT_UINT8, BASE_DEC, VALS(itdm_ctl_command_vals), 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_flowid, { "Allocated Flow ID", "itdm.ctl_flowid",
       FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_dm, { "I-TDM Data Mode", "itdm.ctl_dm",
       FT_UINT8, BASE_DEC, VALS(itdm_ctl_data_mode_vals), 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_emts, { "I-TDM Explicit Multi-timeslot Size", "itdm.ctlemts",
       FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_pktrate, { "I-TDM Packet Rate", "itdm.ctl_pktrate",
       FT_UINT32, BASE_HEX, VALS(itdm_ctl_pktrate_vals), 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_ptid, { "Paired Transaction ID", "itdm.ctl_ptid",
       FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_itdm_ctl_cksum, { "ITDM Control Message Checksum", "itdm.ctl_cksum",
       FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } }
  };

  static gint *ett[] = {
    &ett_itdm,
    &ett_itdm_ctl
  };

  module_t *itdm_module;

  proto_itdm = proto_register_protocol("Internal TDM", "ITDM", "itdm");

  proto_register_field_array(proto_itdm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  itdm_module = prefs_register_protocol(proto_itdm, proto_reg_handoff_itdm);

  prefs_register_uint_preference(itdm_module, "mpls_label",
    "ITDM MPLS label (Flow Bundle ID in hex)",
    "The MPLS label (aka Flow Bundle ID) used by ITDM traffic.",
    16, &gbl_ItdmMPLSLabel);

  prefs_register_uint_preference(itdm_module, "ctl_flowno",
    "I-TDM Control Protocol Flow Number",
    "Flow Number used by I-TDM Control Protocol traffic.",
    10, &gbl_ItdmCTLFlowNo);
}

void
proto_reg_handoff_itdm(void)
{
  static gboolean Initialized=FALSE;
  static dissector_handle_t itdm_handle;
  static guint ItdmMPLSLabel;

  if (!Initialized) {
    itdm_handle = create_dissector_handle( dissect_itdm, proto_itdm );
    Initialized=TRUE;
  } else {
    dissector_delete_uint("mpls.label", ItdmMPLSLabel, itdm_handle);
  }

  ItdmMPLSLabel = gbl_ItdmMPLSLabel;
  dissector_add_uint("mpls.label", gbl_ItdmMPLSLabel, itdm_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
