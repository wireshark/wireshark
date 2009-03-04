/* packet-rrc.c
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 25.331 version 6.7.0 Release 6) packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Ref: 3GPP TS 25.423 version 6.7.0 Release 6
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4049: compiler limit : terminating line number emission" */
#pragma warning(disable:4049)
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "Radio Resource Control (RRC) protocol"
#define PSNAME "RRC"
#define PFNAME "rrc"

static dissector_handle_t gsm_a_dtap_handle;
static dissector_handle_t rrc_ue_radio_access_cap_info_handle=NULL;
static dissector_handle_t rrc_dl_dcch_handle=NULL;

/* Include constants */
#include "packet-rrc-val.h"

/* Initialize the protocol and registered fields */
static int proto_rrc = -1;

#include "packet-rrc-hf.c"

/* Initialize the subtree pointers */
static int ett_rrc = -1;

#include "packet-rrc-ett.c"

/* Global variables */
static proto_tree *top_tree;

#include "packet-rrc-fn.c"

/* 
TODO: Remove the dummy function when these functions are taken into use

 These functions are not referenced from the ASN1 specifications
 as this generates a lot of unsued code warings from GCC this dummy function
 is introduced to reduce the number of warnings until the proper use is discovered
 */

static void
dissect_rrc_dummy_remove_unused_code_warnings(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_){

	/* Dummy code to keep GCC happy */
	switch(hf_index){
		case 0:
			dissect_rrc_UL_PhysChCapabilityFDD_r6( tvb, offset, actx , tree, hf_index);
			dissect_rrc_UE_Positioning_GANSS_Data( tvb, offset, actx , tree, hf_index);
			dissect_rrc_ToTargetRNC_Container( tvb, offset, actx , tree, hf_index);
			dissect_rrc_TargetRNC_ToSourceRNC_Container( tvb, offset, actx , tree, hf_index);
			break;
		default:
			break;
	}
}

static void
dissect_rrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* FIX ME Currently don't know the 'starting point' of this protocol
	 * exported DL-DCCH-Message is the entry point.
	 */
	proto_item	*rrc_item = NULL;
	proto_tree	*rrc_tree = NULL;

	top_tree = tree;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RRC");

	/* create the rrc protocol tree */
	rrc_item = proto_tree_add_item(tree, proto_rrc, tvb, 0, -1, FALSE);
	rrc_tree = proto_item_add_subtree(rrc_item, ett_rrc);

}
/*--- proto_register_rrc -------------------------------------------*/
void proto_register_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-rrc-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_rrc,
#include "packet-rrc-ettarr.c"
  };


  /* Register protocol */
  proto_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("rrc", dissect_rrc, proto_rrc);

#include "packet-rrc-dis-reg.c"

}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_rrc(void)
{

	gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
	rrc_ue_radio_access_cap_info_handle = find_dissector("rrc.ue_radio_access_cap_info");
	rrc_dl_dcch_handle = find_dissector("rrc.dl.dcch");
}


