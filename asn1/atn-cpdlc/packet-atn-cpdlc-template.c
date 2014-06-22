/* c-basic-offset: 2; tab-width: 2; indent-tabs-mode: t
 * vi: set shiftwidth=2 tabstop=2 noexpandtab:
 * :indentSize=2:tabSize=2:noTabs=false:
 */

/* packet-atn-cpdlc-template.c
 * By Mathias Guettler <guettler@web.de>
 * Copyright 2013
 *
 * Routines for ATN Cpdlcc protocol packet disassembly

 * details see:
 * http://en.wikipedia.org/wiki/CPDLC
 * http://members.optusnet.com.au/~cjr/introduction.htm

 * standards:
 * http://legacy.icao.int/anb/panels/acp/repository.cfm

 * note:
 * We are dealing with ATN/CPDLC aka ICAO Doc 9705 Ed2 here
 * (CPDLC may also be transmitted via ACARS/AOA aka "FANS-1/A ").

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

/*
 developper comments:
	Which CPDLC messages are supported ?
		Protected Mode CPDLC (AeQualifier 22) and Plain Old CPDLC (AeQualifier 2)
		The dissector has been tested with ICAO doc9705 Edition2 compliant traffic.
*/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-per.h>

#include <stdio.h>
#include <string.h>

#include "packet-atn-ulcs.h"

#define ATN_CPDLC_PROTO "ICAO Doc9705 CPDLC"

void proto_register_atn_cpdlc(void);
void proto_reg_handoff_atn_cpdlc(void);

static const char *object_identifier_id;

/* forward declarations */
static void dissect_GroundPDUs_PDU(
		tvbuff_t *tvb _U_,
		packet_info *pinfo _U_,
		proto_tree *tree _U_);
static void dissect_AircraftPDUs_PDU(
		tvbuff_t *tvb _U_,
		packet_info *pinfo _U_,
		proto_tree *tree _U_);
static void dissect_ProtectedGroundPDUs_PDU(
		tvbuff_t *tvb _U_,
		packet_info *pinfo _U_,
		proto_tree *tree _U_);
static void dissect_ProtectedAircraftPDUs_PDU(
		tvbuff_t *tvb _U_,
		packet_info *pinfo _U_,
		proto_tree *tree _U_);

#include "packet-atn-cpdlc-hf.c"

#include "packet-atn-cpdlc-ett.c"
static gint ett_atn_cpdlc = -1;

#include "packet-atn-cpdlc-fn.c"

/* Wireshark ID of CPDLC protocol */
static int proto_atn_cpdlc = -1;


static int
dissect_atn_cpdlc(
		tvbuff_t *tvb,
		packet_info *pinfo,
		proto_tree *tree,
		void *data _U_)
{
		/* note: */
		/* there are two co-existing applications of CPDLC: */
		/* "plain old" (ae-qualifier 2) and */
		/* "protected mode" (ae-qualifier 22) CPDLC. */
		/* "protected mode" was introduced to cope with a */
		/* safety issue in which a message would sent to the wrong aircraft. */

		/* note:*/
		/* The protection is an additional checksum and covers the message content, */
		/* the 24-bit address of the aircraft, the current flight id and */
		/* the current ground facility so that an aircraft would be able to reject */
		/* messages which are unexpected (i.e. messages to another flight or */
		/* messages from the wrong center). */

		/*note:*/
		/* although "plain old" CPDLC is more or less deprecated */
		/* many aircraft cannot perform  */
		/* "protected mode" for this largely depends on */
		/* upgraded avionics packages */

		/*note:*/
		/* The use of CPDLC is *optional* as the pilot  */
		/* may always use a voice radio channel to talk to the controller.*/

		proto_tree *atn_cpdlc_tree = NULL;
		atn_conversation_t *atn_cv = NULL;

		/* note: */
		/* we need the ae qualifier stored within the conversation */
		/* to decode "plain old cpdlc" or  */
		/* "protected mode cpdlc correctly " */

		/* DT: dstref present, srcref is always zero */
		if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){
				atn_cv = find_atn_conversation(
						&pinfo->dst,
						pinfo->clnp_dstref,
						&pinfo->src );
		}
		/* CR: srcref present, dstref is always zero */
		if((!pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
				atn_cv = find_atn_conversation(
						&pinfo->src,
						pinfo->clnp_srcref,
						&pinfo->dst );
		}
		/* CC: srcref and dstref present, always use src/srcref & dst */
		if((pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
				atn_cv = find_atn_conversation(
						&pinfo->src,
						pinfo->clnp_srcref,
						&pinfo->dst );
		}

		if(!atn_cv){ /* atn conversation not found */
			return 0; }

		atn_cpdlc_tree = proto_tree_add_subtree(
				tree, tvb, 0, -1, ett_atn_cpdlc, NULL,
				ATN_CPDLC_PROTO );

		switch(atn_cv->ae_qualifier){
				case  pmcpdlc:
						if( check_heur_msg_type(pinfo) == um ) {
								/* uplink PDU's = Ground PDU's */
								dissect_ProtectedGroundPDUs_PDU(
										tvb,
										pinfo,
										atn_cpdlc_tree);
						}else {  /* downlink PDU's = Aircraft PDU's */
								dissect_ProtectedAircraftPDUs_PDU(
										tvb,
										pinfo,
									atn_cpdlc_tree);
						}
						break;
				case cpdlc:
						if( check_heur_msg_type(pinfo) == um ) {
								/* uplink PDU's = Ground PDU's */
								dissect_GroundPDUs_PDU(
										tvb,
										pinfo,
										atn_cpdlc_tree);
						}else {  /* downlink PDU's = Aircraft PDU's */
								dissect_AircraftPDUs_PDU(
										tvb,
										pinfo,
										atn_cpdlc_tree);
						}
						break;
				default:
						break;
		}
		return tvb_reported_length_remaining(tvb, 0);
}

static gboolean
dissect_atn_cpdlc_heur(
		tvbuff_t *tvb,
		packet_info *pinfo,
		proto_tree *tree,
		void *data _U_)
{
		atn_conversation_t *atn_cv = NULL;
		volatile gboolean is_atn_cpdlc = FALSE;
		volatile gboolean is_pm = FALSE;
		int type;

		type = check_heur_msg_type(pinfo);

		switch(type){
			case um:
					TRY {
						dissect_ProtectedGroundPDUs_PDU(tvb, pinfo, NULL);
						is_atn_cpdlc = TRUE;
						is_pm = TRUE;
						break;}
					CATCH_ALL{
						is_atn_cpdlc = FALSE;
						is_pm = FALSE;}
					ENDTRY;
					TRY {
		        dissect_GroundPDUs_PDU(tvb, pinfo, NULL);
						is_pm = FALSE;
						is_atn_cpdlc = TRUE;
						break;}
					CATCH_ALL{
						is_atn_cpdlc = FALSE;
						is_pm = FALSE;}
					ENDTRY;
				break;
		case dm:
					TRY {
						dissect_ProtectedAircraftPDUs_PDU(tvb, pinfo, NULL);
						is_atn_cpdlc = TRUE;
						is_pm = TRUE;
						break;}
					CATCH_ALL {
						is_atn_cpdlc = FALSE;
						is_pm = FALSE; }
					ENDTRY;
					TRY{
						dissect_AircraftPDUs_PDU(tvb, pinfo, NULL);
						is_atn_cpdlc = TRUE;
						is_pm = FALSE;
						break;}
					CATCH_ALL{
						is_atn_cpdlc = FALSE;
						is_pm = FALSE;}
					ENDTRY;
			break;
		default:
			break;
	}

	if(is_atn_cpdlc){
		/* note: */
		/* all subsequent PDU's belonging to this conversation */
		/* are considered CPDLC */
		/* if the first CPDLC PDU has been decoded succesfully */
		/* (This is done in "atn-ulcs" by using "call_dissector_with_data()") */

		/* DT: dstref present, srcref is always zero */
		if((pinfo->clnp_dstref) && (!pinfo->clnp_srcref)){
				atn_cv = find_atn_conversation(&pinfo->dst,
													pinfo->clnp_dstref,
													&pinfo->src );
		}
		/* CR: srcref present, dstref is always zero */
		if((!pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
				atn_cv = find_atn_conversation(&pinfo->src,
													pinfo->clnp_srcref,
													&pinfo->dst );
		}
		/* CC: srcref and dstref present, always use src/srcref & dst */
		if((pinfo->clnp_dstref) && (pinfo->clnp_srcref)){
				atn_cv = find_atn_conversation(&pinfo->src,
													pinfo->clnp_srcref,
													&pinfo->dst );
		}

		if(atn_cv){ /* atn conversation found */
			if(is_pm == TRUE) {
				atn_cv->ae_qualifier =  pmcpdlc; }
			else {
				atn_cv->ae_qualifier =  cpdlc; }
			dissect_atn_cpdlc(tvb, pinfo, tree, NULL);
		}
	}else { /* there should *always* be an atn conversation */
		is_atn_cpdlc = FALSE;
	}

	return is_atn_cpdlc;
}



void proto_register_atn_cpdlc (void)
{
    static hf_register_info hf_atn_cpdlc[] = {
				#include "packet-atn-cpdlc-hfarr.c"
			};

		static gint *ett[] = {
				#include "packet-atn-cpdlc-ettarr.c"
				&ett_atn_cpdlc
		};

		/* register CPDLC */
		proto_atn_cpdlc = proto_register_protocol(
				ATN_CPDLC_PROTO ,
				"ATN-CPDLC",
				"atn-cpdlc");

		proto_register_field_array(
				proto_atn_cpdlc,
				hf_atn_cpdlc,
				array_length(hf_atn_cpdlc));

		proto_register_subtree_array(
				ett,
				array_length(ett));

		new_register_dissector(
				"atn-cpdlc",
				dissect_atn_cpdlc,
				proto_atn_cpdlc);
}

void proto_reg_handoff_atn_cpdlc(void)
{
		/* add session dissector to atn dissector list dissector list*/
		heur_dissector_add(
				"atn-ulcs",
				dissect_atn_cpdlc_heur,
				proto_atn_cpdlc);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 2
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=2 tabstop=2 noexpandtab:
 * :indentSize=2:tabSize=2:noTabs=false:
 */
