/* packet-rnsap.c
 * Routines for dissecting Universal Mobile Telecommunications System (UMTS);
 * UTRAN Iur interface Radio Network Subsystem
 * Application Part (RNSAP) signalling
 * (3GPP TS 25.423 version 6.7.0 Release 6) packet dissection
 * Copyright 2005 - 2006, Anders Broman <anders.broman@ericsson.com>
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-umts_rrc.h"
/*#include "packet-umts_rrc.h"*/

#define PNAME  "UTRAN Iur interface Radio Network Subsystem Application Part"
#define PSNAME "RNSAP"
#define PFNAME "rnsap"

#define SCCP_SSN_RNSAP 143

#define RNSAP_FDD 1

#include "packet-rnsap-val.h"

static dissector_handle_t rnsap_handle=NULL;

/* Initialize the protocol and registered fields */
static int proto_rnsap = -1;

static int hf_rnsap_pdu_length = -1;
static int hf_rnsap_IE_length = -1;
static int hf_rnsap_L3_DL_DCCH_Message_PDU = -1;

#include "packet-rnsap-hf.c"

/* Initialize the subtree pointers */
static int ett_rnsap = -1;
static int ett_rnsap_initiatingMessageValue = -1;
static int ett_rnsap_ProtocolIEValueValue = -1;
static int ett_rnsap_SuccessfulOutcomeValue = -1;
static int ett_rnsap_UnsuccessfulOutcomeValue = -1;

#include "packet-rnsap-ett.c"

/* Global variables */
static proto_tree *top_tree;
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ddMode;

/* Dissector tables */
static dissector_table_t rnsap_ies_dissector_table;
static dissector_table_t rnsap_extension_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int dissect_rnsap_InitiatingMessageValueValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_rnsap_SuccessfulOutcomeValueValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_rnsap_UnsuccessfulOutcomeValueValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
#include "packet-rnsap-fn.c"


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(rnsap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(rnsap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_rnsap_InitiatingMessageValueValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
	proto_tree	*value_tree = tree;
	asn1_ctx_t actx_str;
	asn1_ctx_t *actx = &actx_str;
	
	asn1_ctx_init(actx, ASN1_ENC_PER, TRUE, pinfo);
	switch(ProcedureCode){
	case RNSAP_ID_COMMONTRANSPORTCHANNELRESOURCESINITIALISATION:	/* 0 */
		offset = dissect_id_commonTransportChannelResourcesInitialisation(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_COMMONTRANSPORTCHANNELRESOURCESRELEASE:			/* 1 */
		offset = dissect_id_commonTransportChannelResourcesRelease(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_COMPRESSEDMODECOMMAND:							 /* 2 */
		offset = dissect_id_compressedModeCommand(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DOWNLINKPOWERCONTROL:								 /* 3 */
		offset = dissect_id_downlinkPowerTimeslotControl(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DOWNLINKPOWERTIMESLOTCONTROL:						 /* 4 */
		offset = dissect_id_downlinkPowerTimeslotControl(tvb, offset, actx, value_tree);
		break;
		break;
	case RNSAP_ID_DOWNLINKSIGNALLINGTRANSFER:						 /* 5 */
		offset = dissect_id_downlinkSignallingTransfer(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_ERRORINDICATION:									 /* 6 */
		offset = dissect_id_errorIndication(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DEDICATEDMEASUREMENTFAILURE:						 /* 7 */
		offset = dissect_id_dedicatedMeasurementFailure(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DEDICATEDMEASUREMENTINITIATION:					 /* 8 */
		offset = dissect_id_dedicatedMeasurementInitiation(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DEDICATEDMEASUREMENTREPORTING:					 /* 9 */
		offset = dissect_id_dedicatedMeasurementReporting(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DEDICATEDMEASUREMENTTERMINATION:					 /* 10 */
		offset = dissect_id_dedicatedMeasurementTermination(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_PAGING:											 /* 11 */
		offset = dissect_id_paging(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_PHYSICALCHANNELRECONFIGURATION:					 /* 12 */
		offset = dissect_id_physicalChannelReconfiguration(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_PRIVATEMESSAGE:									 /* 13 */
		offset = dissect_id_privateMessage(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKADDITION:								 /* 14 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkAddition(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkAddition_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_RADIOLINKCONGESTION:								 /* 34 */
		offset = dissect_id_radioLinkCongestion(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKDELETION:								 /* 15 */
		offset = dissect_id_radioLinkDeletion(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKFAILURE:									 /* 16 */
		offset = dissect_id_radioLinkFailure(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKPREEMPTION:								 /* 17 */
		offset = dissect_id_radioLinkPreemption(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKRESTORATION:								 /* 18 */
		offset = dissect_id_radioLinkRestoration(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKSETUP:									 /* 19 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkSetup(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkSetupTdd(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_RELOCATIONCOMMIT:									 /* 20 */
		offset = dissect_id_relocationCommit(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_SYNCHRONISEDRADIOLINKRECONFIGURATIONCANCELLATION:	 /* 21 */
		offset = dissect_id_synchronisedRadioLinkReconfigurationCancellation(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_SYNCHRONISEDRADIOLINKRECONFIGURATIONCOMMIT:		 /* 22 */
		offset = dissect_id_synchronisedRadioLinkReconfigurationCommit(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_SYNCHRONISEDRADIOLINKRECONFIGURATIONPREPARATION:	 /* 23 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_synchronisedRadioLinkReconfigurationPreparation(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_synchronisedRadioLinkReconfigurationPreparation_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_UNSYNCHRONISEDRADIOLINKRECONFIGURATION:			 /* 24 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_unSynchronisedRadioLinkReconfiguration(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_unSynchronisedRadioLinkReconfiguration_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_UPLINKSIGNALLINGTRANSFER:							 /* 25 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_uplinkSignallingTransfer(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_uplinkSignallingTransfer_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_COMMONMEASUREMENTFAILURE:							 /* 26 */
		offset = dissect_id_commonMeasurementFailure(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_COMMONMEASUREMENTINITIATION:						 /* 27 */
		offset = dissect_id_commonMeasurementInitiation(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_COMMONMEASUREMENTREPORTING:						 /* 28 */
		offset = dissect_id_commonMeasurementReporting(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_COMMONMEASUREMENTTERMINATION:						 /* 29 */
		offset = dissect_id_commonMeasurementTermination(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_INFORMATIONEXCHANGEFAILURE:						 /* 30 */
		offset = dissect_id_informationExchangeFailure(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_INFORMATIONEXCHANGEINITIATION:					 /* 31 */
		offset = dissect_id_informationExchangeInitiation(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_INFORMATIONREPORTING:								 /* 32 */
		offset = dissect_id_informationReporting(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_INFORMATIONEXCHANGETERMINATION:					 /* 33 */
		offset = dissect_id_informationExchangeTermination(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RESET:											 /* 35 */
		offset = dissect_id_reset(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKACTIVATION: 								 /* 36 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkActivation(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkActivation_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_GERANUPLINKSIGNALLINGTRANSFER:					 /* 37 */
		offset = dissect_id_gERANuplinkSignallingTransfer(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKPARAMETERUPDATE:							 /* 38 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkParameterUpdate(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkParameterUpdate_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_UEMEASUREMENTFAILURE:								 /* 39 */
		offset = dissect_id_uEMeasurementFailure(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_UEMEASUREMENTINITIATION:							 /* 40 */
		offset = dissect_id_uEMeasurementInitiation(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_UEMEASUREMENTREPORTING:							 /* 41 */
		offset = dissect_id_uEMeasurementReporting(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_UEMEASUREMENTTERMINATION:							 /* 42 */
		offset = dissect_id_uEMeasurementTermination(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_IURDEACTIVATETRACE:								 /* 43 */
		offset = dissect_id_iurDeactivateTrace(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_IURINVOKETRACE:									 /* 44 */
		offset = dissect_id_iurInvokeTrace(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_MBMSATTACH:										 /* 45 */
		offset = dissect_id_mBMSAttach(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_MBMSDETACH:										 /* 46 */
		offset = dissect_id_mBMSDetach(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DIRECTINFORMATIONTRANSFER:						 /* 48 */
		offset = dissect_id_directInformationTransfer(tvb, offset, actx, value_tree);
		break;
	}
	return offset;
}

static int dissect_rnsap_SuccessfulOutcomeValueValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
	proto_tree	*value_tree = tree;
	asn1_ctx_t actx_str;
	asn1_ctx_t *actx = &actx_str;
	
	asn1_ctx_init(actx, ASN1_ENC_PER, TRUE, pinfo);
	switch(ProcedureCode){
	case RNSAP_ID_COMMONTRANSPORTCHANNELRESOURCESINITIALISATION:
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_commonTransportChannelResourcesInitialisation1(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_commonTransportChannelResourcesInitialisation_TDD(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_DEDICATEDMEASUREMENTINITIATION:					 /* 8 */
		offset = dissect_id_dedicatedMeasurementInitiation2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_PHYSICALCHANNELRECONFIGURATION:					 /* 12 */
		offset = dissect_id_physicalChannelReconfiguration1(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKADDITION:								 /* 14 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkAddition1(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkAddition_TDD1(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_RADIOLINKDELETION:								 /* 15 */
		offset = dissect_id_radioLinkDeletion1(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKSETUP:									 /* 19 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkSetup1(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkSetupTdd1(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_SYNCHRONISEDRADIOLINKRECONFIGURATIONPREPARATION:	 /* 23 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_synchronisedRadioLinkReconfigurationPreparation1(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_synchronisedRadioLinkReconfigurationPreparation_TDD(tvb, offset, actx, value_tree);
		}
	case RNSAP_ID_UNSYNCHRONISEDRADIOLINKRECONFIGURATION:			 /* 24 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_unSynchronisedRadioLinkReconfiguration1(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_unSynchronisedRadioLinkReconfiguration_TDD1(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_COMMONMEASUREMENTINITIATION:						 /* 27 */
		offset = dissect_id_commonMeasurementInitiation1(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_INFORMATIONEXCHANGEINITIATION:					 /* 31 */
		offset = dissect_id_informationExchangeInitiation1(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RESET:											 /* 35 */
		offset = dissect_id_reset1(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_UEMEASUREMENTINITIATION:							 /* 40 */
		offset = dissect_id_uEMeasurementInitiation1(tvb, offset, actx, value_tree);
		break;
	}
	return offset;
}

static int dissect_rnsap_UnsuccessfulOutcomeValueValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
	proto_tree	*value_tree = tree;
	asn1_ctx_t actx_str;
	asn1_ctx_t *actx = &actx_str;
	
	asn1_ctx_init(actx, ASN1_ENC_PER, TRUE, pinfo);
	switch(ProcedureCode){
	case RNSAP_ID_COMMONTRANSPORTCHANNELRESOURCESINITIALISATION:
		offset = dissect_id_commonTransportChannelResourcesInitialisation2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_DEDICATEDMEASUREMENTINITIATION:					 /* 8 */
		offset = dissect_id_dedicatedMeasurementInitiation2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_PHYSICALCHANNELRECONFIGURATION:					 /* 12 */
		offset = dissect_id_physicalChannelReconfiguration2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_RADIOLINKADDITION:								 /* 14 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkAddition2(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkAddition_TDD2(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_RADIOLINKSETUP:									 /* 19 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_radioLinkSetup2(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_radioLinkSetupTdd2(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_SYNCHRONISEDRADIOLINKRECONFIGURATIONPREPARATION:	 /* 23 */
		offset = dissect_id_synchronisedRadioLinkReconfigurationPreparation2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_UNSYNCHRONISEDRADIOLINKRECONFIGURATION:			 /* 24 */
		if (ddMode==RNSAP_FDD){
			offset = dissect_id_unSynchronisedRadioLinkReconfiguration2(tvb, offset, actx, value_tree);
		}else{
			offset = dissect_id_unSynchronisedRadioLinkReconfiguration_TDD2(tvb, offset, actx, value_tree);
		}
		break;
	case RNSAP_ID_COMMONMEASUREMENTINITIATION:						 /* 27 */
		offset = dissect_id_commonMeasurementInitiation2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_INFORMATIONEXCHANGEINITIATION:					 /* 31 */
		offset = dissect_id_informationExchangeInitiation2(tvb, offset, actx, value_tree);
		break;
	case RNSAP_ID_UEMEASUREMENTINITIATION:							 /* 40 */
		offset = dissect_id_uEMeasurementInitiation2(tvb, offset, actx, value_tree);
		break;
	}
	return offset;
}


static void
dissect_rnsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*rnsap_item = NULL;
	proto_tree	*rnsap_tree = NULL;

	top_tree = tree;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RNSAP");

	/* create the rnsap protocol tree */
	rnsap_item = proto_tree_add_item(tree, proto_rnsap, tvb, 0, -1, FALSE);
	rnsap_tree = proto_item_add_subtree(rnsap_item, ett_rnsap);
	
	dissect_RNSAP_PDU_PDU(tvb, pinfo, rnsap_tree);
}

/*--- proto_register_rnsap -------------------------------------------*/
void proto_register_rnsap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
	{ &hf_rnsap_pdu_length,
		{ "PDU Length", "rnsap.pdu_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of octets in the PDU", HFILL }},
	{ &hf_rnsap_IE_length,
		{ "IE Length", "rnsap.ie_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of octets in the IE", HFILL }},
    { &hf_rnsap_L3_DL_DCCH_Message_PDU,
      { "DL-DCCH-Message", "rnsap.DL_DCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL-DCCH-Message", HFILL }},

#include "packet-rnsap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_rnsap,
		  &ett_rnsap_initiatingMessageValue,
		  &ett_rnsap_ProtocolIEValueValue,
		  &ett_rnsap_SuccessfulOutcomeValue,
		  &ett_rnsap_UnsuccessfulOutcomeValue,
#include "packet-rnsap-ettarr.c"
  };


  /* Register protocol */
  proto_rnsap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rnsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
 
  /* Register dissector */
  register_dissector("rnsap", dissect_rnsap, proto_rnsap);
  rnsap_handle = find_dissector("rnsap");

  /* Register dissector tables */
  rnsap_ies_dissector_table = register_dissector_table("rnsap.ies", "RNSAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  rnsap_extension_dissector_table = register_dissector_table("rnsap.extension", "RNSAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);


}


/*--- proto_reg_handoff_rnsap ---------------------------------------*/
void
proto_reg_handoff_rnsap(void)
{

	dissector_add("sccp.ssn", SCCP_SSN_RNSAP, rnsap_handle);
	/* Add heuristic dissector
	 * Perhaps we want a preference whether the heuristic dissector
	 * is or isn't enabled
	 */
	/*heur_dissector_add("sccp", dissect_sccp_rnsap_heur, proto_rnsap); */

#include "packet-rnsap-dis-tab.c"
}


