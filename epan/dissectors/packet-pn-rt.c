/* packet-pn-rt.c
 * Routines for pn-rt (PROFINET Real-Time) packet dissection.
 * This is the base for other PROFINET protocols like IO, CBA, DCP, ...
 * (the "content subdissectors" will register themselves using a heuristic)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include "prefs.h"
#include <epan/strutil.h>
#include <etypes.h>

void proto_reg_handoff_pn_rt(void);

/* Define the pn-rt proto */
static int proto_pn_rt     = -1;

/* Define many header fields for pn-rt */
static int hf_pn_rt_id = -1;
static int hf_pn_rt_data = -1;
static int hf_pn_rt_cycle_counter = -1;
static int hf_pn_rt_transfer_status = -1;
static int hf_pn_rt_data_status = -1;
static int hf_pn_rt_data_status_res67 = -1;
static int hf_pn_rt_data_status_ok = -1;
static int hf_pn_rt_data_status_operate = -1;
static int hf_pn_rt_data_status_res3 = -1;
static int hf_pn_rt_data_status_valid = -1;
static int hf_pn_rt_data_status_res1 = -1;
static int hf_pn_rt_data_status_primary = -1;
static int hf_pn_rt_malformed = -1;

/* 
 * Define the trees for pn-rt
 * We need one tree for pn-rt itself and one for the pn-rt data status subtree
 */
static int ett_pn_rt = -1;
static int ett_pn_rt_data_status = -1;

/* 
 * Here are the global variables associated with  
 * the various user definable characteristics of the dissection
 */
/* Place summary in proto tree */
static gboolean pn_rt_summary_in_tree = TRUE;

/* heuristic to find the right pn-rt payload dissector */
static heur_dissector_list_t heur_subdissector_list;

/* the official "we don't know that data" dissector */
static dissector_handle_t data_handle;


/*
 * dissect_pn_rt - The dissector for the Soft-Real-Time protocol
 */
static void
dissect_pn_rt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint tvb_len;
  gint data_len;
  guint16 u16FrameID;
  guint8 u8DataStatus;
  guint8 u8TransferStatus;
  guint16 u16CycleCounter;
  const gchar *pszProtAddInfo;
  const gchar *pszProtShort;
  const gchar *pszProtSummary;
  const gchar *pszProtComment;
  proto_item *item = NULL;
  proto_tree *ds_tree = NULL;
  proto_tree *pn_rt_tree, *ti;
  gchar szFieldSummary[100];
  tvbuff_t *next_tvb;
  gboolean  bCyclic;


  /* Initialize variables */
  tvb_len = tvb_length(tvb) - 
	  /* subtract (optional) Ethernet FCS or trailer len */
	  ((pinfo->pseudo_header->eth.fcs_len != -1) ? pinfo->pseudo_header->eth.fcs_len : 0);
  tvb_set_reported_length(tvb, tvb_len);
  pn_rt_tree = NULL;
  ds_tree = NULL;
  ti = NULL;
  
  /*
   * Set the columns now, so that they'll be set correctly if we throw
   * an exception.  We can set them (or append things) later again ....
   */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PN-RT");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, "PROFINET Real-Time");

  if (tvb_len < 6) {
		/* packet is too short, mark it as malformed */
		proto_tree_add_bytes(tree, hf_pn_rt_malformed, tvb, 0, 10000, 
			tvb_get_ptr(tvb, 0, 10000));
  		return;
  }


    /* build some "raw" data */
	u16FrameID = tvb_get_ntohs(tvb, 0);
    if (u16FrameID < 0x0040) {
        pszProtShort 	= "PN-PTCP";
        pszProtAddInfo  = "Synchronization, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment	= "0x0000-0x003F: Acyclic Real-Time: Sync";
        bCyclic         = FALSE;
    } else if (u16FrameID < 0x0080) {
        pszProtShort 	= "PN-RT";
        pszProtAddInfo  = "reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment	= "0x0040-0x007F: Reserved ID";
        bCyclic         = FALSE;
    } else if (u16FrameID < 0x0100) {
        pszProtShort 	= "PN-RTC0";
        pszProtAddInfo  = "Synchronization, ";
        pszProtSummary  = "Isochronous-Real-Time";
        pszProtComment	= "0x0080-0x00FF: Isochronous-Real-Time: Clock-sync";
        bCyclic         = TRUE;
    } else if (u16FrameID < 0x8000){
        pszProtShort 	= "PN-RTC3";
        pszProtAddInfo  = "RTC3, ";
        pszProtSummary  = "Isochronous-Real-Time";
        pszProtComment	= "0x0100-0x7FFF: Isochronous-Real-Time(class=3): Cyclic";
        bCyclic         = TRUE;
    } else if (u16FrameID < 0xbf00){
        pszProtShort 	= "PN-RTC2";
        pszProtAddInfo  = "RTC2, ";
        pszProtSummary 	= "cyclic Real-Time";
        pszProtComment	= "0x8000-0xBEFF: Real-Time(class=2): Cyclic";
        bCyclic         = TRUE;
    } else if (u16FrameID < 0xc000){
        pszProtShort 	= "PN-RTC2";
        pszProtAddInfo  = "Multicast, ";
        pszProtSummary 	= "cyclic Real-Time";
        pszProtComment	= "0xBF00-0xBFFF: Real-Time(class=2 multicast): Cyclic";
        bCyclic         = TRUE;
    } else if (u16FrameID < 0xfb00){
        pszProtShort 	= "PN-RTC1";
        pszProtAddInfo  = "RTC1, ";
        pszProtSummary 	= "cyclic Real-Time";
        pszProtComment	= "0xC000-0xFAFF: Real-Time(class=1): Cyclic";
        bCyclic         = TRUE;
    } else if (u16FrameID < 0xfc00){
        pszProtShort 	= "PN-RTC1";
        pszProtAddInfo  = "Multicast, ";
        pszProtSummary 	= "cyclic Real-Time";
        pszProtComment	= "0xFB00-0xFBFF: Real-Time(class=1 multicast): Cyclic";
        bCyclic         = TRUE;
    } else if (u16FrameID < 0xfe00){
        pszProtShort 	= "PN-RTA";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary	= "acyclic Real-Time";
        pszProtComment	= "0xFC00-0xFDFF: Real-Time: Acyclic high priority";
        bCyclic         = FALSE;
        if (u16FrameID == 0xfc01) {
			pszProtShort 	= "PN-RTA";
            pszProtAddInfo  = "Alarm High, ";
	        pszProtSummary	= "acyclic Real-Time";
	        pszProtComment	= "Real-Time: Acyclic PN-IO Alarm high priority";
        }
    } else if (u16FrameID < 0xff00){
        pszProtShort 	= "PN-RTA";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary	= "acyclic Real-Time";
        pszProtComment	= "0xFE00-0xFEFF: Real-Time: Acyclic low priority";
        bCyclic         = FALSE;
        if (u16FrameID == 0xfe01) {
			pszProtShort 	= "PN-RTA";
            pszProtAddInfo  = "Alarm Low, ";
	        pszProtSummary	= "acyclic Real-Time";
	        pszProtComment	= "Real-Time: Acyclic PN-IO Alarm low priority";
        }
        if (u16FrameID == 0xfefd) {
			pszProtShort 	= "PN-RTA";
            pszProtAddInfo  = "";
	        pszProtSummary	= "acyclic Real-Time";
	        pszProtComment	= "Real-Time: DCP (Dynamic Configuration Protocol)";
        }
        if (u16FrameID == 0xfefe) {
			pszProtShort 	= "PN-RTA";
            pszProtAddInfo  = "";
	        pszProtSummary	= "acyclic Real-Time";
	        pszProtComment	= "Real-Time: DCP (Dynamic Configuration Protocol) multicast response";
        }
        if (u16FrameID == 0xfeff) {
			pszProtShort 	= "PN-RTA";
            pszProtAddInfo  = "";
	        pszProtSummary	= "acyclic Real-Time";
	        pszProtComment	= "Real-Time: DCP (Dynamic Configuration Protocol) multicast";
        }
    } else if (u16FrameID < 0xff20){
		pszProtShort 	= "PN-PTCP";
        pszProtAddInfo  = "RTA Sync, ";
        pszProtSummary	= "acyclic Real-Time";
        pszProtComment	= "0xFF00-0xFF1F: Acyclic Real-Time: RTA sync";
        bCyclic         = FALSE;
    } else if (u16FrameID < 0xff40){
		pszProtShort 	= "PN-PTCP";
        pszProtAddInfo  = "Follow Up, ";
        pszProtSummary	= "acyclic Real-Time";
        pszProtComment	= "0xFF20-0xFF3F: Acyclic Real-Time: Follow Up";
        bCyclic         = FALSE;
    } else if (u16FrameID < 0xff43){
		pszProtShort 	= "PN-PTCP";
        pszProtAddInfo  = "Delay, ";
        pszProtSummary	= "acyclic Real-Time";
        pszProtComment	= "0xFF40-0xFF42: Acyclic Real-Time: Delay";
        bCyclic         = FALSE;
    } else {
		pszProtShort 	= "PN-RT";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary	= "Real-Time";
        pszProtComment	= "0xFF43-0xFFFF: reserved ID";
        bCyclic         = FALSE;
	}

    /* decode optional cyclic fields at the packet end and build the summary line */
    if (bCyclic) {
        /* cyclic transfer has cycle counter, data status and transfer status fields at the end */
		u16CycleCounter = tvb_get_ntohs(tvb, tvb_len - 4);
		u8DataStatus = tvb_get_guint8(tvb, tvb_len - 2);
	    u8TransferStatus = tvb_get_guint8(tvb, tvb_len - 1);

		g_snprintf (szFieldSummary, sizeof(szFieldSummary),
				  "%sID:0x%04x, Len:%4u, Cycle:%5u (%s,%s,%s,%s)",
				pszProtAddInfo, u16FrameID, tvb_len - 2 - 4, u16CycleCounter,
			    (u8DataStatus & 0x04) ? "Valid" : "Invalid",
			    (u8DataStatus & 0x01) ? "Primary" : "Backup",
			    (u8DataStatus & 0x20) ? "Ok" : "Problem",
			    (u8DataStatus & 0x10) ? "Run" : "Stop");

        /* user data length is packet len - frame id - optional cyclic status fields */
        data_len = tvb_len - 2 - 4;
    } else {
        /* satisfy the gcc compiler, so it won't throw an "uninitialized" warning */
		u16CycleCounter     = 0;
		u8DataStatus        = 0;
	    u8TransferStatus    = 0;

        /* acyclic transfer has no fields at the end */
		g_snprintf (szFieldSummary, sizeof(szFieldSummary),
				  "%sID:0x%04x, Len:%4u",
				pszProtAddInfo, u16FrameID, tvb_len - 2);

        /* user data length is packet len - frame id field */
        data_len = tvb_len - 2;
    }

    /* build protocol tree only, if tree is really used */
    if (tree) {
		/* build pn_rt protocol tree with summary line */
	    if (pn_rt_summary_in_tree) {
	      ti = proto_tree_add_protocol_format(tree, proto_pn_rt, tvb, 0, tvb_len,
				"PROFINET %s, %s", pszProtSummary, szFieldSummary);
	    } else {
			ti = proto_tree_add_item(tree, proto_pn_rt, tvb, 0, tvb_len, FALSE);
	    }
		pn_rt_tree = proto_item_add_subtree(ti, ett_pn_rt);

		/* add frame ID */
        proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_id, tvb,
          0, 2, u16FrameID, "FrameID: 0x%04x (%s)", u16FrameID, pszProtComment);

        if (bCyclic) {
		    /* add cycle counter */
            proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_cycle_counter, tvb,
              tvb_len - 4, 2, u16CycleCounter, "CycleCounter: %u", u16CycleCounter);
		    
            /* add data status subtree */
		    item = proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_data_status, 
			    tvb, tvb_len - 2, 1, u8DataStatus,
			    "DataStatus: 0x%02x (Frame: %s and %s, Provider: %s and %s)", 
			    u8DataStatus, 
			    (u8DataStatus & 0x04) ? "Valid" : "Invalid",
			    (u8DataStatus & 0x01) ? "Primary" : "Backup",
			    (u8DataStatus & 0x20) ? "Ok" : "Problem",
			    (u8DataStatus & 0x10) ? "Run" : "Stop");
		    ds_tree = proto_item_add_subtree(item, ett_pn_rt_data_status);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_res67, tvb, tvb_len - 2, 1, u8DataStatus);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_ok, tvb, tvb_len - 2, 1, u8DataStatus);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_operate, tvb, tvb_len - 2, 1, u8DataStatus);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_res3, tvb, tvb_len - 2, 1, u8DataStatus);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_valid, tvb, tvb_len - 2, 1, u8DataStatus);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_res1, tvb, tvb_len - 2, 1, u8DataStatus);
	        proto_tree_add_uint(ds_tree, hf_pn_rt_data_status_primary, tvb, tvb_len - 2, 1, u8DataStatus);

	        /* add transfer status */
	        if (u8TransferStatus) {
		        proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_transfer_status, tvb,
		    	    tvb_len - 1, 1, u8TransferStatus, 
				    "TransferStatus: 0x%02x (ignore this frame)", u8TransferStatus);
		    } else {
		        proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_transfer_status, tvb,
		    	    tvb_len - 1, 1, u8TransferStatus, 
				    "TransferStatus: 0x%02x (OK)", u8TransferStatus);
		    }
        }
    }
		
	/* update column info now */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, szFieldSummary);
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, pszProtShort);

    pinfo->private_data = GUINT_TO_POINTER( (guint32) u16FrameID);

	/* get frame user data tvb (without header and footer) */
	next_tvb = tvb_new_subset(tvb, 2, data_len, data_len);

    /* ask heuristics, if some sub-dissector is interested in this packet payload */
    if(!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)) {
        /*if (check_col(pinfo->cinfo, COL_INFO))
              col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown");*/

        /* Oh, well, we don't know this; dissect it as data. */
        call_dissector(data_handle, next_tvb, pinfo, tree);
    }
}


/* Register all the bits needed by the filtering engine */
void 
proto_register_pn_rt(void)
{
  static hf_register_info hf[] = {
    { &hf_pn_rt_id,
      { "FrameID", "pn_rt.frame_id", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_rt_data,
      { "Data", "pn_rt.data", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_rt_cycle_counter, { 
		"CycleCounter", "pn_rt.cycle_counter", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_rt_data_status, { 
		"DataStatus", "pn_rt.ds", FT_UINT8, BASE_HEX, 0, 0x0, "", HFILL }},
	{ &hf_pn_rt_data_status_res67, { 
		"Reserved (should be zero)", "pn_rt.ds_res67", FT_UINT8, BASE_HEX, 0, 0xc0, "", HFILL }},
	{ &hf_pn_rt_data_status_ok, { 
		"StationProblemIndicator (1:Ok/0:Problem)", "pn_rt.ds_ok", FT_UINT8, BASE_HEX, 0, 0x20, "", HFILL }},
	{ &hf_pn_rt_data_status_operate, { 
		"ProviderState (1:Run/0:Stop)", "pn_rt.ds_operate", FT_UINT8, BASE_HEX, 0, 0x10, "", HFILL }},
	{ &hf_pn_rt_data_status_res3, { 
		"Reserved (should be zero)", "pn_rt.ds_res3", FT_UINT8, BASE_HEX, 0, 0x08, "", HFILL }},
	{ &hf_pn_rt_data_status_valid, { 
		"DataValid (1:Valid/0:Invalid)", "pn_rt.ds_valid", FT_UINT8, BASE_HEX, 0, 0x04, "", HFILL }},
	{ &hf_pn_rt_data_status_res1, { 
		"Reserved (should be zero)", "pn_rt.ds_res1", FT_UINT8, BASE_HEX, 0, 0x02, "", HFILL }},
	{ &hf_pn_rt_data_status_primary, { 
		"State (1:Primary/0:Backup)", "pn_rt.ds_primary", FT_UINT8, BASE_HEX, 0, 0x01, "", HFILL }},
    { &hf_pn_rt_transfer_status,
      { "TransferStatus", "pn_rt.transfer_status", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_rt_malformed,
	{ "Malformed", "pn_rt.malformed", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }}
  };
  static gint *ett[] = {
    &ett_pn_rt,
    &ett_pn_rt_data_status,
  };
  module_t *pn_rt_module; 

  proto_pn_rt = proto_register_protocol("PROFINET Real-Time Protocol",
				       "PN-RT", "pn_rt");

  proto_register_field_array(proto_pn_rt, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options */

  pn_rt_module = prefs_register_protocol(proto_pn_rt, proto_reg_handoff_pn_rt);

  prefs_register_bool_preference(pn_rt_module, "summary_in_tree",
	    "Show PN-RT summary in protocol tree",
	    "Whether the PN-RT summary line should be shown in the protocol tree",
	    &pn_rt_summary_in_tree);

  /* register heuristics anchor for payload dissectors */
  register_heur_dissector_list("pn_rt", &heur_subdissector_list);
}


/* The registration hand-off routine 
 * Is called at startup, and everytime the preferences of this protocol changed. */
void
proto_reg_handoff_pn_rt(void)
{
  static int pn_rt_prefs_initialized = FALSE;
  static dissector_handle_t pn_rt_handle;


  if (!pn_rt_prefs_initialized) {
    pn_rt_handle = create_dissector_handle(dissect_pn_rt, proto_pn_rt);
    pn_rt_prefs_initialized = TRUE;
  }
  else {
    dissector_delete("ethertype", ETHERTYPE_PROFINET, pn_rt_handle);
  }

  dissector_add("ethertype", ETHERTYPE_PROFINET, pn_rt_handle);

	/* the official "we don't know that data" dissector */
  data_handle = find_dissector("data");
}

