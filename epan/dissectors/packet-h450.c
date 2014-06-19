/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h450.c                                                              */
/* ../../tools/asn2wrs.py -c ./h450.cnf -s ./packet-h450-template -D . -O ../../epan/dissectors H4501-Supplementary-ServiceAPDU-Structure.asn Addressing-Data-Elements.asn H225-generic-parameters-definition.asn Manufacturer-specific-service-extension-definition.asn H4501-General-Error-List.asn Call-Transfer-Operations.asn Call-Diversion-Operations.asn Call-Hold-Operations.asn Call-Park-Pickup-Operations.asn Call-Waiting-Operations.asn Message-Waiting-Indication-Operations.asn Name-Operations.asn Call-Completion-Operations.asn Call-Offer-Operations.asn Call-Intrusion-Operations.asn Common-Information-Operations.asn */

/* Input file: packet-h450-template.c */

#line 1 "../../asn1/h450/packet-h450-template.c"
/* packet-h450.c
 * Routines for h450 packet dissection
 * Based on the previous h450 dissector by:
 * 2003  Graeme Reid (graeme.reid@norwoodsystems.com)
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Credit to Tomas Kukosa for developing the asn2wrs compiler.
 *
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-h225.h"

#include "packet-h450-ros.h"

#define PNAME  "H.450 Supplementary Services"
#define PSNAME "H.450"
#define PFNAME "h450"

void proto_register_h450(void);
void proto_reg_handoff_h450(void);


/* Initialize the protocol and registered fields */
static int proto_h450 = -1;
static int hf_h450_operation = -1;
static int hf_h450_error = -1;

/*--- Included file: packet-h450-hf.c ---*/
#line 1 "../../asn1/h450/packet-h450-hf.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

static int hf_h450_h450_H4501SupplementaryService_PDU = -1;  /* H4501SupplementaryService */
static int hf_h450_networkFacilityExtension = -1;  /* NetworkFacilityExtension */
static int hf_h450_interpretationApdu = -1;       /* InterpretationApdu */
static int hf_h450_serviceApdu = -1;              /* ServiceApdus */
static int hf_h450_sourceEntity = -1;             /* EntityType */
static int hf_h450_sourceEntityAddress = -1;      /* AddressInformation */
static int hf_h450_destinationEntity = -1;        /* EntityType */
static int hf_h450_destinationEntityAddress = -1;  /* AddressInformation */
static int hf_h450_endpoint = -1;                 /* NULL */
static int hf_h450_anyEntity = -1;                /* NULL */
static int hf_h450_discardAnyUnrecognizedInvokePdu = -1;  /* NULL */
static int hf_h450_clearCallIfAnyInvokePduNotRecognized = -1;  /* NULL */
static int hf_h450_rejectAnyUnrecognizedInvokePdu = -1;  /* NULL */
static int hf_h450_rosApdus = -1;                 /* T_rosApdus */
static int hf_h450_rosApdus_item = -1;            /* T_rosApdus_item */
static int hf_h450_destinationAddress = -1;       /* SEQUENCE_OF_AliasAddress */
static int hf_h450_destinationAddress_item = -1;  /* AliasAddress */
static int hf_h450_remoteExtensionAddress = -1;   /* AliasAddress */
static int hf_h450_destinationAddressPresentationIndicator = -1;  /* PresentationIndicator */
static int hf_h450_destinationAddressScreeningIndicator = -1;  /* ScreeningIndicator */
static int hf_h450_remoteExtensionAddressPresentationIndicator = -1;  /* PresentationIndicator */
static int hf_h450_remoteExtensionAddressScreeningIndicator = -1;  /* ScreeningIndicator */
static int hf_h450_userSpecifiedSubaddress = -1;  /* UserSpecifiedSubaddress */
static int hf_h450_nsapSubaddress = -1;           /* NSAPSubaddress */
static int hf_h450_subaddressInformation = -1;    /* SubaddressInformation */
static int hf_h450_oddCountIndicator = -1;        /* BOOLEAN */
static int hf_h450_extensionId = -1;              /* OBJECT_IDENTIFIER */
static int hf_h450_extensionArgument = -1;        /* T_extensionArgument */

/* --- Module Call-Transfer-Operations --- --- ---                            */

static int hf_h450_2_h450_2_DummyArg_PDU = -1;    /* DummyArg */
static int hf_h450_2_h450_2_CTIdentifyRes_PDU = -1;  /* CTIdentifyRes */
static int hf_h450_2_h450_2_CTInitiateArg_PDU = -1;  /* CTInitiateArg */
static int hf_h450_2_h450_2_DummyRes_PDU = -1;    /* DummyRes */
static int hf_h450_2_h450_2_CTSetupArg_PDU = -1;  /* CTSetupArg */
static int hf_h450_2_h450_2_CTUpdateArg_PDU = -1;  /* CTUpdateArg */
static int hf_h450_2_h450_2_SubaddressTransferArg_PDU = -1;  /* SubaddressTransferArg */
static int hf_h450_2_h450_2_CTCompleteArg_PDU = -1;  /* CTCompleteArg */
static int hf_h450_2_h450_2_CTActiveArg_PDU = -1;  /* CTActiveArg */
static int hf_h450_2_h450_2_PAR_unspecified_PDU = -1;  /* PAR_unspecified */
static int hf_h450_2_extensionSeq = -1;           /* ExtensionSeq */
static int hf_h450_2_nonStandardData = -1;        /* NonStandardParameter */
static int hf_h450_2_callIdentity = -1;           /* CallIdentity */
static int hf_h450_2_reroutingNumber = -1;        /* EndpointAddress */
static int hf_h450_2_cTInitiateArg_argumentExtension = -1;  /* T_cTInitiateArg_argumentExtension */
static int hf_h450_2_transferringNumber = -1;     /* EndpointAddress */
static int hf_h450_2_cTSetupArg_argumentExtension = -1;  /* T_cTSetupArg_argumentExtension */
static int hf_h450_2_resultExtension = -1;        /* T_resultExtension */
static int hf_h450_2_redirectionNumber = -1;      /* EndpointAddress */
static int hf_h450_2_redirectionInfo = -1;        /* BMPString_SIZE_1_128 */
static int hf_h450_2_basicCallInfoElements = -1;  /* H225InformationElement */
static int hf_h450_2_cTUpdateArg_argumentExtension = -1;  /* T_cTUpdateArg_argumentExtension */
static int hf_h450_2_redirectionSubaddress = -1;  /* PartySubaddress */
static int hf_h450_2_subaddressTransferArg_argumentExtension = -1;  /* T_subaddressTransferArg_argumentExtension */
static int hf_h450_2_endDesignation = -1;         /* EndDesignation */
static int hf_h450_2_callStatus = -1;             /* CallStatus */
static int hf_h450_2_cTCompleteArg_argumentExtension = -1;  /* T_cTCompleteArg_argumentExtension */
static int hf_h450_2_connectedAddress = -1;       /* EndpointAddress */
static int hf_h450_2_connectedInfo = -1;          /* BMPString_SIZE_1_128 */
static int hf_h450_2_cTActiveArg_argumentExtension = -1;  /* T_cTActiveArg_argumentExtension */
static int hf_h450_2_ExtensionSeq_item = -1;      /* Extension */
static int hf_h450_2_unspecified_extension = -1;  /* Extension */
static int hf_h450_2_nonStandard = -1;            /* NonStandardParameter */

/* --- Module Call-Diversion-Operations --- --- ---                           */

static int hf_h450_3_h450_3_ARG_activateDiversionQ_PDU = -1;  /* ARG_activateDiversionQ */
static int hf_h450_3_h450_3_RES_activateDiversionQ_PDU = -1;  /* RES_activateDiversionQ */
static int hf_h450_3_h450_3_ARG_deactivateDiversionQ_PDU = -1;  /* ARG_deactivateDiversionQ */
static int hf_h450_3_h450_3_RES_deactivateDiversionQ_PDU = -1;  /* RES_deactivateDiversionQ */
static int hf_h450_3_h450_3_ARG_interrogateDiversionQ_PDU = -1;  /* ARG_interrogateDiversionQ */
static int hf_h450_3_h450_3_IntResultList_PDU = -1;  /* IntResultList */
static int hf_h450_3_h450_3_ARG_checkRestriction_PDU = -1;  /* ARG_checkRestriction */
static int hf_h450_3_h450_3_RES_checkRestriction_PDU = -1;  /* RES_checkRestriction */
static int hf_h450_3_h450_3_ARG_callRerouting_PDU = -1;  /* ARG_callRerouting */
static int hf_h450_3_h450_3_RES_callRerouting_PDU = -1;  /* RES_callRerouting */
static int hf_h450_3_h450_3_ARG_divertingLegInformation1_PDU = -1;  /* ARG_divertingLegInformation1 */
static int hf_h450_3_h450_3_ARG_divertingLegInformation2_PDU = -1;  /* ARG_divertingLegInformation2 */
static int hf_h450_3_h450_3_ARG_divertingLegInformation3_PDU = -1;  /* ARG_divertingLegInformation3 */
static int hf_h450_3_h450_3_ARG_divertingLegInformation4_PDU = -1;  /* ARG_divertingLegInformation4 */
static int hf_h450_3_h450_3_ARG_cfnrDivertedLegFailed_PDU = -1;  /* ARG_cfnrDivertedLegFailed */
static int hf_h450_3_h450_3_PAR_unspecified_PDU = -1;  /* PAR_unspecified */
static int hf_h450_3_procedure = -1;              /* Procedure */
static int hf_h450_3_basicService = -1;           /* BasicService */
static int hf_h450_3_divertedToAddress = -1;      /* EndpointAddress */
static int hf_h450_3_servedUserNr = -1;           /* EndpointAddress */
static int hf_h450_3_activatingUserNr = -1;       /* EndpointAddress */
static int hf_h450_3_activateDiversionQArg_extension = -1;  /* ActivateDiversionQArg_extension */
static int hf_h450_3_extensionSeq = -1;           /* ExtensionSeq */
static int hf_h450_3_nonStandardData = -1;        /* NonStandardParameter */
static int hf_h450_3_deactivatingUserNr = -1;     /* EndpointAddress */
static int hf_h450_3_deactivateDiversionQArg_extension = -1;  /* DeactivateDiversionQArg_extension */
static int hf_h450_3_interrogatingUserNr = -1;    /* EndpointAddress */
static int hf_h450_3_interrogateDiversionQ_extension = -1;  /* InterrogateDiversionQ_extension */
static int hf_h450_3_divertedToNr = -1;           /* EndpointAddress */
static int hf_h450_3_checkRestrictionArg_extension = -1;  /* CheckRestrictionArg_extension */
static int hf_h450_3_reroutingReason = -1;        /* DiversionReason */
static int hf_h450_3_originalReroutingReason = -1;  /* DiversionReason */
static int hf_h450_3_calledAddress = -1;          /* EndpointAddress */
static int hf_h450_3_diversionCounter = -1;       /* INTEGER_1_15 */
static int hf_h450_3_h225InfoElement = -1;        /* H225InformationElement */
static int hf_h450_3_lastReroutingNr = -1;        /* EndpointAddress */
static int hf_h450_3_subscriptionOption = -1;     /* SubscriptionOption */
static int hf_h450_3_callingPartySubaddress = -1;  /* PartySubaddress */
static int hf_h450_3_callingNumber = -1;          /* EndpointAddress */
static int hf_h450_3_callingInfo = -1;            /* BMPString_SIZE_1_128 */
static int hf_h450_3_originalCalledNr = -1;       /* EndpointAddress */
static int hf_h450_3_redirectingInfo = -1;        /* BMPString_SIZE_1_128 */
static int hf_h450_3_originalCalledInfo = -1;     /* BMPString_SIZE_1_128 */
static int hf_h450_3_callReroutingArg_extension = -1;  /* CallReroutingArg_extension */
static int hf_h450_3_diversionReason = -1;        /* DiversionReason */
static int hf_h450_3_nominatedNr = -1;            /* EndpointAddress */
static int hf_h450_3_nominatedInfo = -1;          /* BMPString_SIZE_1_128 */
static int hf_h450_3_redirectingNr = -1;          /* EndpointAddress */
static int hf_h450_3_divertingLegInformation1Arg_extension = -1;  /* DivertingLegInformation1Arg_extension */
static int hf_h450_3_originalDiversionReason = -1;  /* DiversionReason */
static int hf_h450_3_divertingNr = -1;            /* EndpointAddress */
static int hf_h450_3_divertingLegInformation2Arg_extension = -1;  /* DivertingLegInformation2Arg_extension */
static int hf_h450_3_presentationAllowedIndicator = -1;  /* PresentationAllowedIndicator */
static int hf_h450_3_redirectionNr = -1;          /* EndpointAddress */
static int hf_h450_3_redirectionInfo = -1;        /* BMPString_SIZE_1_128 */
static int hf_h450_3_divertingLegInformation3Arg_extension = -1;  /* DivertingLegInformation3Arg_extension */
static int hf_h450_3_callingNr = -1;              /* EndpointAddress */
static int hf_h450_3_divertingLegInformation4Arg_extension = -1;  /* DivertingLegInformation4Arg_extension */
static int hf_h450_3_IntResultList_item = -1;     /* IntResult */
static int hf_h450_3_remoteEnabled = -1;          /* BOOLEAN */
static int hf_h450_3_intResult_extension = -1;    /* IntResult_extension */
static int hf_h450_3_unspecified_extension = -1;  /* Extension */
static int hf_h450_3_nonStandard = -1;            /* NonStandardParameter */
static int hf_h450_3_ExtensionSeq_item = -1;      /* Extension */

/* --- Module Call-Hold-Operations --- --- ---                                */

static int hf_h450_4_h450_4_HoldNotificArg_PDU = -1;  /* HoldNotificArg */
static int hf_h450_4_h450_4_RetrieveNotificArg_PDU = -1;  /* RetrieveNotificArg */
static int hf_h450_4_h450_4_RemoteHoldArg_PDU = -1;  /* RemoteHoldArg */
static int hf_h450_4_h450_4_RemoteHoldRes_PDU = -1;  /* RemoteHoldRes */
static int hf_h450_4_h450_4_RemoteRetrieveArg_PDU = -1;  /* RemoteRetrieveArg */
static int hf_h450_4_h450_4_RemoteRetrieveRes_PDU = -1;  /* RemoteRetrieveRes */
static int hf_h450_4_h450_4_PAR_undefined_PDU = -1;  /* PAR_undefined */
static int hf_h450_4_holdNotificArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_4_holdNotificArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_4_retrieveNotificArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_4_retrieveNotificArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_4_remoteHoldArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_4_remoteHoldArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_4_extensionRes = -1;           /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_4_extensionRes_item = -1;      /* MixedExtension */
static int hf_h450_4_remoteRetrieveArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_4_remoteRetrieveArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_4_mixedExtension_extension = -1;  /* Extension */
static int hf_h450_4_nonStandardData = -1;        /* NonStandardParameter */
static int hf_h450_4_PAR_undefined_item = -1;     /* MixedExtension */

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

static int hf_h450_5_h450_5_CpRequestArg_PDU = -1;  /* CpRequestArg */
static int hf_h450_5_h450_5_CpRequestRes_PDU = -1;  /* CpRequestRes */
static int hf_h450_5_h450_5_CpSetupArg_PDU = -1;  /* CpSetupArg */
static int hf_h450_5_h450_5_CpSetupRes_PDU = -1;  /* CpSetupRes */
static int hf_h450_5_h450_5_GroupIndicationOnArg_PDU = -1;  /* GroupIndicationOnArg */
static int hf_h450_5_h450_5_GroupIndicationOnRes_PDU = -1;  /* GroupIndicationOnRes */
static int hf_h450_5_h450_5_GroupIndicationOffArg_PDU = -1;  /* GroupIndicationOffArg */
static int hf_h450_5_h450_5_GroupIndicationOffRes_PDU = -1;  /* GroupIndicationOffRes */
static int hf_h450_5_h450_5_PickrequArg_PDU = -1;  /* PickrequArg */
static int hf_h450_5_h450_5_PickrequRes_PDU = -1;  /* PickrequRes */
static int hf_h450_5_h450_5_PickupArg_PDU = -1;   /* PickupArg */
static int hf_h450_5_h450_5_PickupRes_PDU = -1;   /* PickupRes */
static int hf_h450_5_h450_5_PickExeArg_PDU = -1;  /* PickExeArg */
static int hf_h450_5_h450_5_PickExeRes_PDU = -1;  /* PickExeRes */
static int hf_h450_5_h450_5_CpNotifyArg_PDU = -1;  /* CpNotifyArg */
static int hf_h450_5_h450_5_CpickupNotifyArg_PDU = -1;  /* CpickupNotifyArg */
static int hf_h450_5_h450_5_PAR_undefined_PDU = -1;  /* PAR_undefined */
static int hf_h450_5_parkingNumber = -1;          /* EndpointAddress */
static int hf_h450_5_parkedNumber = -1;           /* EndpointAddress */
static int hf_h450_5_parkedToNumber = -1;         /* EndpointAddress */
static int hf_h450_5_parkedToPosition = -1;       /* ParkedToPosition */
static int hf_h450_5_cpRequestArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_cpRequestArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_parkCondition = -1;          /* ParkCondition */
static int hf_h450_5_extensionRes = -1;           /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_extensionRes_item = -1;      /* MixedExtension */
static int hf_h450_5_cpSetupArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_cpSetupArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_callPickupId = -1;           /* CallIdentifier */
static int hf_h450_5_groupMemberUserNr = -1;      /* EndpointAddress */
static int hf_h450_5_retrieveCallType = -1;       /* CallType */
static int hf_h450_5_partyToRetrieve = -1;        /* EndpointAddress */
static int hf_h450_5_retrieveAddress = -1;        /* EndpointAddress */
static int hf_h450_5_parkPosition = -1;           /* ParkedToPosition */
static int hf_h450_5_groupIndicationOnArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_groupIndicationOnArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_groupIndicationOffArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_groupIndicationOffArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_picking_upNumber = -1;       /* EndpointAddress */
static int hf_h450_5_pickrequArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_pickrequArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_pickupArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_pickupArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_pickExeArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_pickExeArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_cpNotifyArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_cpNotifyArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_cpickupNotifyArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_5_cpickupNotifyArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_5_PAR_undefined_item = -1;     /* MixedExtension */

/* --- Module Call-Waiting-Operations --- --- ---                             */

static int hf_h450_6_h450_6_CallWaitingArg_PDU = -1;  /* CallWaitingArg */
static int hf_h450_6_nbOfAddWaitingCalls = -1;    /* INTEGER_0_255 */
static int hf_h450_6_callWaitingArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_6_callWaitingArg_extensionArg_item = -1;  /* MixedExtension */

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

static int hf_h450_7_h450_7_MWIActivateArg_PDU = -1;  /* MWIActivateArg */
static int hf_h450_7_h450_7_DummyRes_PDU = -1;    /* DummyRes */
static int hf_h450_7_h450_7_MWIDeactivateArg_PDU = -1;  /* MWIDeactivateArg */
static int hf_h450_7_h450_7_MWIInterrogateArg_PDU = -1;  /* MWIInterrogateArg */
static int hf_h450_7_h450_7_MWIInterrogateRes_PDU = -1;  /* MWIInterrogateRes */
static int hf_h450_7_h450_7_PAR_undefined_PDU = -1;  /* PAR_undefined */
static int hf_h450_7_servedUserNr = -1;           /* EndpointAddress */
static int hf_h450_7_basicService = -1;           /* BasicService */
static int hf_h450_7_msgCentreId = -1;            /* MsgCentreId */
static int hf_h450_7_nbOfMessages = -1;           /* NbOfMessages */
static int hf_h450_7_originatingNr = -1;          /* EndpointAddress */
static int hf_h450_7_timestamp = -1;              /* TimeStamp */
static int hf_h450_7_priority = -1;               /* INTEGER_0_9 */
static int hf_h450_7_mWIActivateArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_7_mWIActivateArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_7_DummyRes_item = -1;          /* MixedExtension */
static int hf_h450_7_callbackReq = -1;            /* BOOLEAN */
static int hf_h450_7_mWIDeactivateArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_7_mWIDeactivateArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_7_mWIInterrogateArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_7_mWIInterrogateArg_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_7_MWIInterrogateRes_item = -1;  /* MWIInterrogateResElt */
static int hf_h450_7_mWIInterrogateResElt_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_7_mWIInterrogateResElt_extensionArg_item = -1;  /* MixedExtension */
static int hf_h450_7_integer = -1;                /* INTEGER_0_65535 */
static int hf_h450_7_partyNumber = -1;            /* EndpointAddress */
static int hf_h450_7_numericString = -1;          /* NumericString_SIZE_1_10 */
static int hf_h450_7_PAR_undefined_item = -1;     /* MixedExtension */

/* --- Module Name-Operations --- --- ---                                     */

static int hf_h450_8_h450_8_ARG_callingName_PDU = -1;  /* ARG_callingName */
static int hf_h450_8_h450_8_ARG_alertingName_PDU = -1;  /* ARG_alertingName */
static int hf_h450_8_h450_8_ARG_connectedName_PDU = -1;  /* ARG_connectedName */
static int hf_h450_8_h450_8_ARG_busyName_PDU = -1;  /* ARG_busyName */
static int hf_h450_8_name = -1;                   /* Name */
static int hf_h450_8_extensionArg = -1;           /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_8_extensionArg_item = -1;      /* MixedExtension */
static int hf_h450_8_namePresentationAllowed = -1;  /* NamePresentationAllowed */
static int hf_h450_8_namePresentationRestricted = -1;  /* NamePresentationRestricted */
static int hf_h450_8_nameNotAvailable = -1;       /* NULL */
static int hf_h450_8_simpleName = -1;             /* SimpleName */
static int hf_h450_8_extendedName = -1;           /* ExtendedName */
static int hf_h450_8_restrictedNull = -1;         /* NULL */

/* --- Module Call-Completion-Operations --- --- ---                          */

static int hf_h450_9_h450_9_CcRequestArg_PDU = -1;  /* CcRequestArg */
static int hf_h450_9_h450_9_CcRequestRes_PDU = -1;  /* CcRequestRes */
static int hf_h450_9_h450_9_CcArg_PDU = -1;       /* CcArg */
static int hf_h450_9_h450_9_CcShortArg_PDU = -1;  /* CcShortArg */
static int hf_h450_9_numberA = -1;                /* EndpointAddress */
static int hf_h450_9_numberB = -1;                /* EndpointAddress */
static int hf_h450_9_ccIdentifier = -1;           /* CallIdentifier */
static int hf_h450_9_service = -1;                /* BasicService */
static int hf_h450_9_can_retain_service = -1;     /* BOOLEAN */
static int hf_h450_9_retain_sig_connection = -1;  /* BOOLEAN */
static int hf_h450_9_ccRequestArg_extension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_9_ccRequestArg_extension_item = -1;  /* MixedExtension */
static int hf_h450_9_retain_service = -1;         /* BOOLEAN */
static int hf_h450_9_ccRequestRes_extension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_9_ccRequestRes_extension_item = -1;  /* MixedExtension */
static int hf_h450_9_shortArg = -1;               /* CcShortArg */
static int hf_h450_9_longArg = -1;                /* CcLongArg */
static int hf_h450_9_ccShortArg_extension = -1;   /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_9_ccShortArg_extension_item = -1;  /* MixedExtension */
static int hf_h450_9_ccLongArg_extension = -1;    /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_9_ccLongArg_extension_item = -1;  /* MixedExtension */

/* --- Module Call-Offer-Operations --- --- ---                               */

static int hf_h450_10_h450_10_CoReqOptArg_PDU = -1;  /* CoReqOptArg */
static int hf_h450_10_h450_10_RUAlertOptArg_PDU = -1;  /* RUAlertOptArg */
static int hf_h450_10_h450_10_CfbOvrOptArg_PDU = -1;  /* CfbOvrOptArg */
static int hf_h450_10_coReqOptArg_extension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_10_coReqOptArg_extension_item = -1;  /* MixedExtension */
static int hf_h450_10_rUAlertOptArg_extension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_10_rUAlertOptArg_extension_item = -1;  /* MixedExtension */
static int hf_h450_10_cfbOvrOptArg_extension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_10_cfbOvrOptArg_extension_item = -1;  /* MixedExtension */

/* --- Module Call-Intrusion-Operations --- --- ---                           */

static int hf_h450_11_h450_11_CIRequestArg_PDU = -1;  /* CIRequestArg */
static int hf_h450_11_h450_11_CIRequestRes_PDU = -1;  /* CIRequestRes */
static int hf_h450_11_h450_11_CIGetCIPLOptArg_PDU = -1;  /* CIGetCIPLOptArg */
static int hf_h450_11_h450_11_CIGetCIPLRes_PDU = -1;  /* CIGetCIPLRes */
static int hf_h450_11_h450_11_CIIsOptArg_PDU = -1;  /* CIIsOptArg */
static int hf_h450_11_h450_11_CIIsOptRes_PDU = -1;  /* CIIsOptRes */
static int hf_h450_11_h450_11_CIFrcRelArg_PDU = -1;  /* CIFrcRelArg */
static int hf_h450_11_h450_11_CIFrcRelOptRes_PDU = -1;  /* CIFrcRelOptRes */
static int hf_h450_11_h450_11_CIWobOptArg_PDU = -1;  /* CIWobOptArg */
static int hf_h450_11_h450_11_CIWobOptRes_PDU = -1;  /* CIWobOptRes */
static int hf_h450_11_h450_11_CISilentArg_PDU = -1;  /* CISilentArg */
static int hf_h450_11_h450_11_CISilentOptRes_PDU = -1;  /* CISilentOptRes */
static int hf_h450_11_h450_11_CINotificationArg_PDU = -1;  /* CINotificationArg */
static int hf_h450_11_ciCapabilityLevel = -1;     /* CICapabilityLevel */
static int hf_h450_11_cIRequestArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIRequestArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_ciStatusInformation = -1;   /* CIStatusInformation */
static int hf_h450_11_cIRequestRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIRequestRes_resultExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIGetCIPLOptArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIGetCIPLOptArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_ciProtectionLevel = -1;     /* CIProtectionLevel */
static int hf_h450_11_silentMonitoringPermitted = -1;  /* NULL */
static int hf_h450_11_cIGetCIPLRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIGetCIPLRes_resultExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIIsOptArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIIsOptArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIIsOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIIsOptRes_resultExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIFrcRelArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIFrcRelArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIFrcRelOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIFrcRelOptRes_resultExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIWobOptArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIWobOptArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cIWobOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cIWobOptRes_resultExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_specificCall = -1;          /* CallIdentifier */
static int hf_h450_11_cISilentArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cISilentArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cISilentOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cISilentOptRes_resultExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_cINotificationArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_11_cINotificationArg_argumentExtension_item = -1;  /* MixedExtension */
static int hf_h450_11_callIntrusionImpending = -1;  /* NULL */
static int hf_h450_11_callIntruded = -1;          /* NULL */
static int hf_h450_11_callIsolated = -1;          /* NULL */
static int hf_h450_11_callForceReleased = -1;     /* NULL */
static int hf_h450_11_callIntrusionComplete = -1;  /* NULL */
static int hf_h450_11_callIntrusionEnd = -1;      /* NULL */

/* --- Module Common-Information-Operations --- --- ---                       */

static int hf_h450_12_h450_12_DummyArg_PDU = -1;  /* DummyArg */
static int hf_h450_12_h450_12_CmnArg_PDU = -1;    /* CmnArg */
static int hf_h450_12_featureList = -1;           /* FeatureList */
static int hf_h450_12_featureValues = -1;         /* FeatureValues */
static int hf_h450_12_featureControl = -1;        /* FeatureControl */
static int hf_h450_12_cmnArg_extension = -1;      /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_12_cmnArg_extension_item = -1;  /* MixedExtension */
static int hf_h450_12_extensionArg = -1;          /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_12_extensionArg_item = -1;     /* MixedExtension */
static int hf_h450_12_ssCFreRoutingSupported = -1;  /* NULL */
static int hf_h450_12_ssCTreRoutingSupported = -1;  /* NULL */
static int hf_h450_12_ssCCBSPossible = -1;        /* NULL */
static int hf_h450_12_ssCCNRPossible = -1;        /* NULL */
static int hf_h450_12_ssCOSupported = -1;         /* NULL */
static int hf_h450_12_ssCIForcedReleaseSupported = -1;  /* NULL */
static int hf_h450_12_ssCIIsolationSupported = -1;  /* NULL */
static int hf_h450_12_ssCIWaitOnBusySupported = -1;  /* NULL */
static int hf_h450_12_ssCISilentMonitoringSupported = -1;  /* NULL */
static int hf_h450_12_ssCIConferenceSupported = -1;  /* NULL */
static int hf_h450_12_ssCHFarHoldSupported = -1;  /* NULL */
static int hf_h450_12_ssMWICallbackSupported = -1;  /* NULL */
static int hf_h450_12_ssCPCallParkSupported = -1;  /* NULL */
static int hf_h450_12_partyCategory = -1;         /* PartyCategory */
static int hf_h450_12_ssCIprotectionLevel = -1;   /* SSCIProtectionLevel */
static int hf_h450_12_ssCHDoNotHold = -1;         /* NULL */
static int hf_h450_12_ssCTDoNotTransfer = -1;     /* NULL */
static int hf_h450_12_ssMWICallbackCall = -1;     /* NULL */
static int hf_h450_12_ssCISilentMonitorPermitted = -1;  /* NULL */

/*--- End of included file: packet-h450-hf.c ---*/
#line 54 "../../asn1/h450/packet-h450-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-h450-ett.c ---*/
#line 1 "../../asn1/h450/packet-h450-ett.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

static gint ett_h450_H4501SupplementaryService = -1;
static gint ett_h450_NetworkFacilityExtension = -1;
static gint ett_h450_EntityType = -1;
static gint ett_h450_InterpretationApdu = -1;
static gint ett_h450_ServiceApdus = -1;
static gint ett_h450_T_rosApdus = -1;
static gint ett_h450_EndpointAddress = -1;
static gint ett_h450_SEQUENCE_OF_AliasAddress = -1;
static gint ett_h450_PartySubaddress = -1;
static gint ett_h450_UserSpecifiedSubaddress = -1;
static gint ett_h450_Extension = -1;

/* --- Module Call-Transfer-Operations --- --- ---                            */

static gint ett_h450_2_DummyArg = -1;
static gint ett_h450_2_DummyRes = -1;
static gint ett_h450_2_CTInitiateArg = -1;
static gint ett_h450_2_T_cTInitiateArg_argumentExtension = -1;
static gint ett_h450_2_CTSetupArg = -1;
static gint ett_h450_2_T_cTSetupArg_argumentExtension = -1;
static gint ett_h450_2_CTIdentifyRes = -1;
static gint ett_h450_2_T_resultExtension = -1;
static gint ett_h450_2_CTUpdateArg = -1;
static gint ett_h450_2_T_cTUpdateArg_argumentExtension = -1;
static gint ett_h450_2_SubaddressTransferArg = -1;
static gint ett_h450_2_T_subaddressTransferArg_argumentExtension = -1;
static gint ett_h450_2_CTCompleteArg = -1;
static gint ett_h450_2_T_cTCompleteArg_argumentExtension = -1;
static gint ett_h450_2_CTActiveArg = -1;
static gint ett_h450_2_T_cTActiveArg_argumentExtension = -1;
static gint ett_h450_2_ExtensionSeq = -1;
static gint ett_h450_2_PAR_unspecified = -1;

/* --- Module Call-Diversion-Operations --- --- ---                           */

static gint ett_h450_3_ARG_activateDiversionQ = -1;
static gint ett_h450_3_ActivateDiversionQArg_extension = -1;
static gint ett_h450_3_RES_activateDiversionQ = -1;
static gint ett_h450_3_ARG_deactivateDiversionQ = -1;
static gint ett_h450_3_DeactivateDiversionQArg_extension = -1;
static gint ett_h450_3_RES_deactivateDiversionQ = -1;
static gint ett_h450_3_ARG_interrogateDiversionQ = -1;
static gint ett_h450_3_InterrogateDiversionQ_extension = -1;
static gint ett_h450_3_ARG_checkRestriction = -1;
static gint ett_h450_3_CheckRestrictionArg_extension = -1;
static gint ett_h450_3_RES_checkRestriction = -1;
static gint ett_h450_3_ARG_callRerouting = -1;
static gint ett_h450_3_CallReroutingArg_extension = -1;
static gint ett_h450_3_RES_callRerouting = -1;
static gint ett_h450_3_ARG_divertingLegInformation1 = -1;
static gint ett_h450_3_DivertingLegInformation1Arg_extension = -1;
static gint ett_h450_3_ARG_divertingLegInformation2 = -1;
static gint ett_h450_3_DivertingLegInformation2Arg_extension = -1;
static gint ett_h450_3_ARG_divertingLegInformation3 = -1;
static gint ett_h450_3_DivertingLegInformation3Arg_extension = -1;
static gint ett_h450_3_ARG_divertingLegInformation4 = -1;
static gint ett_h450_3_DivertingLegInformation4Arg_extension = -1;
static gint ett_h450_3_ARG_cfnrDivertedLegFailed = -1;
static gint ett_h450_3_IntResultList = -1;
static gint ett_h450_3_IntResult = -1;
static gint ett_h450_3_IntResult_extension = -1;
static gint ett_h450_3_PAR_unspecified = -1;
static gint ett_h450_3_ExtensionSeq = -1;

/* --- Module Call-Hold-Operations --- --- ---                                */

static gint ett_h450_4_HoldNotificArg = -1;
static gint ett_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_4_RetrieveNotificArg = -1;
static gint ett_h450_4_RemoteHoldArg = -1;
static gint ett_h450_4_RemoteHoldRes = -1;
static gint ett_h450_4_RemoteRetrieveArg = -1;
static gint ett_h450_4_RemoteRetrieveRes = -1;
static gint ett_h450_4_MixedExtension = -1;
static gint ett_h450_4_PAR_undefined = -1;

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

static gint ett_h450_5_CpRequestArg = -1;
static gint ett_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_5_CpRequestRes = -1;
static gint ett_h450_5_CpSetupArg = -1;
static gint ett_h450_5_CpSetupRes = -1;
static gint ett_h450_5_GroupIndicationOnArg = -1;
static gint ett_h450_5_GroupIndicationOnRes = -1;
static gint ett_h450_5_GroupIndicationOffArg = -1;
static gint ett_h450_5_GroupIndicationOffRes = -1;
static gint ett_h450_5_PickrequArg = -1;
static gint ett_h450_5_PickrequRes = -1;
static gint ett_h450_5_PickupArg = -1;
static gint ett_h450_5_PickupRes = -1;
static gint ett_h450_5_PickExeArg = -1;
static gint ett_h450_5_PickExeRes = -1;
static gint ett_h450_5_CpNotifyArg = -1;
static gint ett_h450_5_CpickupNotifyArg = -1;
static gint ett_h450_5_PAR_undefined = -1;

/* --- Module Call-Waiting-Operations --- --- ---                             */

static gint ett_h450_6_CallWaitingArg = -1;
static gint ett_h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

static gint ett_h450_7_MWIActivateArg = -1;
static gint ett_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_7_DummyRes = -1;
static gint ett_h450_7_MWIDeactivateArg = -1;
static gint ett_h450_7_MWIInterrogateArg = -1;
static gint ett_h450_7_MWIInterrogateRes = -1;
static gint ett_h450_7_MWIInterrogateResElt = -1;
static gint ett_h450_7_MsgCentreId = -1;
static gint ett_h450_7_PAR_undefined = -1;

/* --- Module Name-Operations --- --- ---                                     */

static gint ett_h450_8_ARG_callingName = -1;
static gint ett_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_8_ARG_alertingName = -1;
static gint ett_h450_8_ARG_connectedName = -1;
static gint ett_h450_8_ARG_busyName = -1;
static gint ett_h450_8_Name = -1;
static gint ett_h450_8_NamePresentationAllowed = -1;
static gint ett_h450_8_NamePresentationRestricted = -1;

/* --- Module Call-Completion-Operations --- --- ---                          */

static gint ett_h450_9_CcRequestArg = -1;
static gint ett_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_9_CcRequestRes = -1;
static gint ett_h450_9_CcArg = -1;
static gint ett_h450_9_CcShortArg = -1;
static gint ett_h450_9_CcLongArg = -1;

/* --- Module Call-Offer-Operations --- --- ---                               */

static gint ett_h450_10_CoReqOptArg = -1;
static gint ett_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_10_RUAlertOptArg = -1;
static gint ett_h450_10_CfbOvrOptArg = -1;

/* --- Module Call-Intrusion-Operations --- --- ---                           */

static gint ett_h450_11_CIRequestArg = -1;
static gint ett_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_11_CIRequestRes = -1;
static gint ett_h450_11_CIGetCIPLOptArg = -1;
static gint ett_h450_11_CIGetCIPLRes = -1;
static gint ett_h450_11_CIIsOptArg = -1;
static gint ett_h450_11_CIIsOptRes = -1;
static gint ett_h450_11_CIFrcRelArg = -1;
static gint ett_h450_11_CIFrcRelOptRes = -1;
static gint ett_h450_11_CIWobOptArg = -1;
static gint ett_h450_11_CIWobOptRes = -1;
static gint ett_h450_11_CISilentArg = -1;
static gint ett_h450_11_CISilentOptRes = -1;
static gint ett_h450_11_CINotificationArg = -1;
static gint ett_h450_11_CIStatusInformation = -1;

/* --- Module Common-Information-Operations --- --- ---                       */

static gint ett_h450_12_CmnArg = -1;
static gint ett_h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_12_DummyArg = -1;
static gint ett_h450_12_FeatureList = -1;
static gint ett_h450_12_FeatureValues = -1;
static gint ett_h450_12_FeatureControl = -1;

/*--- End of included file: packet-h450-ett.c ---*/
#line 57 "../../asn1/h450/packet-h450-template.c"

static const value_string h450_str_operation[] = {

/*--- Included file: packet-h450-table10.c ---*/
#line 1 "../../asn1/h450/packet-h450-table10.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

/* Unknown or empty loop list OPERATION */

/* --- Module Call-Transfer-Operations --- --- ---                            */

  {   7, "callTransferIdentify" },
  {   8, "callTransferAbandon" },
  {   9, "callTransferInitiate" },
  {  10, "callTransferSetup" },
  {  13, "callTransferUpdate" },
  {  14, "subaddressTransfer" },
  {  12, "callTransferComplete" },
  {  11, "callTransferActive" },

/* --- Module Call-Diversion-Operations --- --- ---                           */

  {  15, "activateDiversionQ" },
  {  16, "deactivateDiversionQ" },
  {  17, "interrogateDiversionQ" },
  {  18, "checkRestriction" },
  {  19, "callRerouting" },
  {  20, "divertingLegInformation1" },
  {  21, "divertingLegInformation2" },
  {  22, "divertingLegInformation3" },
  { 100, "divertingLegInformation4" },
  {  23, "cfnrDivertedLegFailed" },

/* --- Module Call-Hold-Operations --- --- ---                                */

  { 101, "holdNotific" },
  { 102, "retrieveNotific" },
  { 103, "remoteHold" },
  { 104, "remoteRetrieve" },

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

  { 106, "cpRequest" },
  { 107, "cpSetup" },
  { 108, "groupIndicationOn" },
  { 109, "groupIndicationOff" },
  { 110, "pickrequ" },
  { 111, "pickup" },
  { 112, "pickExe" },
  { 113, "cpNotify" },
  { 114, "cpickupNotify" },

/* --- Module Call-Waiting-Operations --- --- ---                             */

  { 105, "callWaiting" },

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

  {  80, "mwiActivate" },
  {  81, "mwiDeactivate" },
  {  82, "mwiInterrogate" },

/* --- Module Name-Operations --- --- ---                                     */

  {   0, "callingName" },
  {   1, "alertingName" },
  {   2, "connectedName" },
  {   3, "busyName" },

/* --- Module Call-Completion-Operations --- --- ---                          */

  {  40, "ccbsRequest" },
  {  27, "ccnrRequest" },
  {  28, "ccCancel" },
  {  29, "ccExecPossible" },
  {  31, "ccRingout" },
  {  32, "ccSuspend" },
  {  33, "ccResume" },

/* --- Module Call-Offer-Operations --- --- ---                               */

  {  34, "callOfferRequest" },
  { 115, "remoteUserAlerting" },
  {  49, "cfbOverride" },

/* --- Module Call-Intrusion-Operations --- --- ---                           */

  {  43, "callIntrusionRequest" },
  {  44, "callIntrusionGetCIPL" },
  {  45, "callIntrusionIsolate" },
  {  46, "callIntrusionForcedRelease" },
  {  47, "callIntrusionWOBRequest" },
  { 116, "callIntrusionSilentMonitor" },
  { 117, "callIntrusionNotification" },

/* --- Module Common-Information-Operations --- --- ---                       */

  {  84, "cmnRequest" },
  {  85, "cmnInform" },

/*--- End of included file: packet-h450-table10.c ---*/
#line 60 "../../asn1/h450/packet-h450-template.c"
  {   0, NULL}
};

static const value_string h450_str_error[] = {

/*--- Included file: packet-h450-table20.c ---*/
#line 1 "../../asn1/h450/packet-h450-table20.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

  {    0, "userNotSubscribed" },
  {    1, "rejectedByNetwork" },
  {    2, "rejectedByUser" },
  {    3, "notAvailable" },
  {    5, "insufficientInformation" },
  {    6, "invalidServedUserNumber" },
  {    7, "invalidCallState" },
  {    8, "basicServiceNotProvided" },
  {    9, "notIncomingCall" },
  {   10, "supplementaryServiceInteractionNotAllowed" },
  {   11, "resourceUnavailable" },
  {   25, "callFailure" },
  {   43, "proceduralError" },

/* --- Module Call-Transfer-Operations --- --- ---                            */

  { 1008, "unspecified" },
  { 1004, "invalidReroutingNumber" },
  { 1005, "unrecognizedCallIdentity" },
  { 1006, "establishmentFailure" },

/* --- Module Call-Diversion-Operations --- --- ---                           */

  {   12, "invalidDivertedNumber" },
  {   14, "specialServiceNumber" },
  {   15, "diversionToServedUserNumber" },
  {   24, "numberOfDiversionsExceeded" },
  { 1000, "temporarilyUnavailable" },
  { 1007, "notAuthorized" },
  { 1008, "unspecified" },

/* --- Module Call-Hold-Operations --- --- ---                                */

  { 2002, "undefined" },

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

  { 2000, "callPickupIdInvalid" },
  { 2001, "callAlreadyPickedUp" },
  { 2002, "undefined" },

/* --- Module Call-Waiting-Operations --- --- ---                             */

/* Unknown or empty loop list ERROR */

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

  { 2002, "undefined" },
  { 1018, "invalidMsgCentreId" },
  {   31, "notActivated" },

/* --- Module Name-Operations --- --- ---                                     */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Completion-Operations --- --- ---                          */

  { 1010, "shortTermRejection" },
  { 1011, "longTermRejection" },
  { 1012, "remoteUserBusyAgain" },
  { 1013, "failureToMatch" },

/* --- Module Call-Offer-Operations --- --- ---                               */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Intrusion-Operations --- --- ---                           */

  { 1009, "notBusy" },
  { 1000, "temporarilyUnavailable" },
  { 1007, "notAuthorized" },

/* --- Module Common-Information-Operations --- --- ---                       */

/* Unknown or empty loop list ERROR */

/*--- End of included file: packet-h450-table20.c ---*/
#line 65 "../../asn1/h450/packet-h450-template.c"
  {   0, NULL}
};

/* ROSE context */
static rose_ctx_t h450_rose_ctx;

/* Global variables */


/*--- Included file: packet-h450-fn.c ---*/
#line 1 "../../asn1/h450/packet-h450-fn.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */



static int
dissect_h450_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h450_EntityType_vals[] = {
  {   0, "endpoint" },
  {   1, "anyEntity" },
  { 0, NULL }
};

static const per_choice_t h450_EntityType_choice[] = {
  {   0, &hf_h450_endpoint       , ASN1_EXTENSION_ROOT    , dissect_h450_NULL },
  {   1, &hf_h450_anyEntity      , ASN1_EXTENSION_ROOT    , dissect_h450_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_EntityType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_EntityType, h450_EntityType_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_AddressInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t h450_NetworkFacilityExtension_sequence[] = {
  { &hf_h450_sourceEntity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EntityType },
  { &hf_h450_sourceEntityAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_AddressInformation },
  { &hf_h450_destinationEntity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EntityType },
  { &hf_h450_destinationEntityAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_AddressInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_NetworkFacilityExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_NetworkFacilityExtension, h450_NetworkFacilityExtension_sequence);

  return offset;
}


static const value_string h450_InterpretationApdu_vals[] = {
  {   0, "discardAnyUnrecognizedInvokePdu" },
  {   1, "clearCallIfAnyInvokePduNotRecognized" },
  {   2, "rejectAnyUnrecognizedInvokePdu" },
  { 0, NULL }
};

static const per_choice_t h450_InterpretationApdu_choice[] = {
  {   0, &hf_h450_discardAnyUnrecognizedInvokePdu, ASN1_EXTENSION_ROOT    , dissect_h450_NULL },
  {   1, &hf_h450_clearCallIfAnyInvokePduNotRecognized, ASN1_EXTENSION_ROOT    , dissect_h450_NULL },
  {   2, &hf_h450_rejectAnyUnrecognizedInvokePdu, ASN1_EXTENSION_ROOT    , dissect_h450_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_InterpretationApdu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_InterpretationApdu, h450_InterpretationApdu_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_T_rosApdus_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 61 "../../asn1/h450/h450.cnf"
  h450_rose_ctx.apdu_depth = 1;
  actx->rose_ctx = &h450_rose_ctx;

  offset = dissect_h450_ros_ROS(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t h450_T_rosApdus_sequence_of[1] = {
  { &hf_h450_rosApdus_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_T_rosApdus_item },
};

static int
dissect_h450_T_rosApdus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_T_rosApdus, h450_T_rosApdus_sequence_of,
                                                  1, NO_BOUND, FALSE);

  return offset;
}


static const value_string h450_ServiceApdus_vals[] = {
  {   0, "rosApdus" },
  { 0, NULL }
};

static const per_choice_t h450_ServiceApdus_choice[] = {
  {   0, &hf_h450_rosApdus       , ASN1_EXTENSION_ROOT    , dissect_h450_T_rosApdus },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ServiceApdus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ServiceApdus, h450_ServiceApdus_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_H4501SupplementaryService_sequence[] = {
  { &hf_h450_networkFacilityExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_NetworkFacilityExtension },
  { &hf_h450_interpretationApdu, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_InterpretationApdu },
  { &hf_h450_serviceApdu    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_ServiceApdus },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_H4501SupplementaryService(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 54 "../../asn1/h450/h450.cnf"
  proto_item *hidden_item;

  hidden_item = proto_tree_add_item(tree, proto_h450, tvb, offset, -1, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(hidden_item);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_H4501SupplementaryService, h450_H4501SupplementaryService_sequence);

  return offset;
}


static const per_sequence_t h450_SEQUENCE_OF_AliasAddress_sequence_of[1] = {
  { &hf_h450_destinationAddress_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h225_AliasAddress },
};

static int
dissect_h450_SEQUENCE_OF_AliasAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h450_SEQUENCE_OF_AliasAddress, h450_SEQUENCE_OF_AliasAddress_sequence_of);

  return offset;
}


static const per_sequence_t h450_EndpointAddress_sequence[] = {
  { &hf_h450_destinationAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_SEQUENCE_OF_AliasAddress },
  { &hf_h450_remoteExtensionAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_AliasAddress },
  { &hf_h450_destinationAddressPresentationIndicator, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_PresentationIndicator },
  { &hf_h450_destinationAddressScreeningIndicator, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_ScreeningIndicator },
  { &hf_h450_remoteExtensionAddressPresentationIndicator, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_PresentationIndicator },
  { &hf_h450_remoteExtensionAddressScreeningIndicator, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h225_ScreeningIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_EndpointAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_EndpointAddress, h450_EndpointAddress_sequence);

  return offset;
}



static int
dissect_h450_SubaddressInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}



static int
dissect_h450_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t h450_UserSpecifiedSubaddress_sequence[] = {
  { &hf_h450_subaddressInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_SubaddressInformation },
  { &hf_h450_oddCountIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_UserSpecifiedSubaddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_UserSpecifiedSubaddress, h450_UserSpecifiedSubaddress_sequence);

  return offset;
}



static int
dissect_h450_NSAPSubaddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}


static const value_string h450_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nsapSubaddress" },
  { 0, NULL }
};

static const per_choice_t h450_PartySubaddress_choice[] = {
  {   0, &hf_h450_userSpecifiedSubaddress, ASN1_EXTENSION_ROOT    , dissect_h450_UserSpecifiedSubaddress },
  {   1, &hf_h450_nsapSubaddress , ASN1_EXTENSION_ROOT    , dissect_h450_NSAPSubaddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_PartySubaddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_PartySubaddress, h450_PartySubaddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_PresentationAllowedIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h450_H225InformationElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_h450_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h450_T_extensionArgument(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t h450_Extension_sequence[] = {
  { &hf_h450_extensionId    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_OBJECT_IDENTIFIER },
  { &hf_h450_extensionArgument, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_T_extensionArgument },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_Extension, h450_Extension_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_H4501SupplementaryService_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_H4501SupplementaryService(tvb, offset, &asn1_ctx, tree, hf_h450_h450_H4501SupplementaryService_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Transfer-Operations --- --- ---                            */


static const per_sequence_t h450_2_ExtensionSeq_sequence_of[1] = {
  { &hf_h450_2_ExtensionSeq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_Extension },
};

static int
dissect_h450_2_ExtensionSeq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h450_2_ExtensionSeq, h450_2_ExtensionSeq_sequence_of);

  return offset;
}


static const value_string h450_2_DummyArg_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_DummyArg_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_DummyArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_DummyArg, h450_2_DummyArg_choice,
                                 NULL);

  return offset;
}


static const value_string h450_2_DummyRes_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_DummyRes_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_DummyRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_DummyRes, h450_2_DummyRes_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_2_CallIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          0, 4, FALSE);

  return offset;
}


static const value_string h450_2_T_cTInitiateArg_argumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_cTInitiateArg_argumentExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_cTInitiateArg_argumentExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_cTInitiateArg_argumentExtension, h450_2_T_cTInitiateArg_argumentExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_CTInitiateArg_sequence[] = {
  { &hf_h450_2_callIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_2_CallIdentity },
  { &hf_h450_2_reroutingNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_2_cTInitiateArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_cTInitiateArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_CTInitiateArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_CTInitiateArg, h450_2_CTInitiateArg_sequence);

  return offset;
}


static const value_string h450_2_T_cTSetupArg_argumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_cTSetupArg_argumentExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_cTSetupArg_argumentExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_cTSetupArg_argumentExtension, h450_2_T_cTSetupArg_argumentExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_CTSetupArg_sequence[] = {
  { &hf_h450_2_callIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_2_CallIdentity },
  { &hf_h450_2_transferringNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_2_cTSetupArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_cTSetupArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_CTSetupArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_CTSetupArg, h450_2_CTSetupArg_sequence);

  return offset;
}


static const value_string h450_2_T_resultExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_resultExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_resultExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_resultExtension, h450_2_T_resultExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_CTIdentifyRes_sequence[] = {
  { &hf_h450_2_callIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_2_CallIdentity },
  { &hf_h450_2_reroutingNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_2_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_CTIdentifyRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_CTIdentifyRes, h450_2_CTIdentifyRes_sequence);

  return offset;
}



static int
dissect_h450_2_BMPString_SIZE_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128, FALSE);

  return offset;
}


static const value_string h450_2_T_cTUpdateArg_argumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_cTUpdateArg_argumentExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_cTUpdateArg_argumentExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_cTUpdateArg_argumentExtension, h450_2_T_cTUpdateArg_argumentExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_CTUpdateArg_sequence[] = {
  { &hf_h450_2_redirectionNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_2_redirectionInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_BMPString_SIZE_1_128 },
  { &hf_h450_2_basicCallInfoElements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_H225InformationElement },
  { &hf_h450_2_cTUpdateArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_cTUpdateArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_CTUpdateArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_CTUpdateArg, h450_2_CTUpdateArg_sequence);

  return offset;
}


static const value_string h450_2_T_subaddressTransferArg_argumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_subaddressTransferArg_argumentExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_subaddressTransferArg_argumentExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_subaddressTransferArg_argumentExtension, h450_2_T_subaddressTransferArg_argumentExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_SubaddressTransferArg_sequence[] = {
  { &hf_h450_2_redirectionSubaddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_PartySubaddress },
  { &hf_h450_2_subaddressTransferArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_subaddressTransferArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_SubaddressTransferArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_SubaddressTransferArg, h450_2_SubaddressTransferArg_sequence);

  return offset;
}


static const value_string h450_2_EndDesignation_vals[] = {
  {   0, "primaryEnd" },
  {   1, "secondaryEnd" },
  { 0, NULL }
};


static int
dissect_h450_2_EndDesignation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string h450_2_CallStatus_vals[] = {
  {   0, "answered" },
  {   1, "alerting" },
  { 0, NULL }
};


static int
dissect_h450_2_CallStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string h450_2_T_cTCompleteArg_argumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_cTCompleteArg_argumentExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_cTCompleteArg_argumentExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_cTCompleteArg_argumentExtension, h450_2_T_cTCompleteArg_argumentExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_CTCompleteArg_sequence[] = {
  { &hf_h450_2_endDesignation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_2_EndDesignation },
  { &hf_h450_2_redirectionNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_2_basicCallInfoElements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_H225InformationElement },
  { &hf_h450_2_redirectionInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_BMPString_SIZE_1_128 },
  { &hf_h450_2_callStatus   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_CallStatus },
  { &hf_h450_2_cTCompleteArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_cTCompleteArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_CTCompleteArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_CTCompleteArg, h450_2_CTCompleteArg_sequence);

  return offset;
}


static const value_string h450_2_T_cTActiveArg_argumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_2_T_cTActiveArg_argumentExtension_choice[] = {
  {   0, &hf_h450_2_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_2_ExtensionSeq },
  {   1, &hf_h450_2_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_T_cTActiveArg_argumentExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_T_cTActiveArg_argumentExtension, h450_2_T_cTActiveArg_argumentExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_2_CTActiveArg_sequence[] = {
  { &hf_h450_2_connectedAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_2_basicCallInfoElements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_H225InformationElement },
  { &hf_h450_2_connectedInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_BMPString_SIZE_1_128 },
  { &hf_h450_2_cTActiveArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_2_T_cTActiveArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_2_CTActiveArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_2_CTActiveArg, h450_2_CTActiveArg_sequence);

  return offset;
}


static const value_string h450_2_PAR_unspecified_vals[] = {
  {   0, "extension" },
  {   1, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t h450_2_PAR_unspecified_choice[] = {
  {   0, &hf_h450_2_unspecified_extension, ASN1_NO_EXTENSIONS     , dissect_h450_Extension },
  {   1, &hf_h450_2_nonStandard  , ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_2_PAR_unspecified(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_2_PAR_unspecified, h450_2_PAR_unspecified_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_2_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_DummyArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_DummyArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_CTIdentifyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_CTIdentifyRes(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_CTIdentifyRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_CTInitiateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_CTInitiateArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_CTInitiateArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_DummyRes(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_DummyRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_CTSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_CTSetupArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_CTSetupArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_CTUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_CTUpdateArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_CTUpdateArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_SubaddressTransferArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_SubaddressTransferArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_SubaddressTransferArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_CTCompleteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_CTCompleteArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_CTCompleteArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_CTActiveArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_CTActiveArg(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_CTActiveArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_2_PAR_unspecified_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_2_PAR_unspecified(tvb, offset, &asn1_ctx, tree, hf_h450_2_h450_2_PAR_unspecified_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Diversion-Operations --- --- ---                           */


static const value_string h450_3_Procedure_vals[] = {
  {   0, "cfu" },
  {   1, "cfb" },
  {   2, "cfnr" },
  { 0, NULL }
};


static int
dissect_h450_3_Procedure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string h450_3_BasicService_vals[] = {
  {   0, "allServices" },
  { 0, NULL }
};


static int
dissect_h450_3_BasicService(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t h450_3_ExtensionSeq_sequence_of[1] = {
  { &hf_h450_3_ExtensionSeq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_Extension },
};

static int
dissect_h450_3_ExtensionSeq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h450_3_ExtensionSeq, h450_3_ExtensionSeq_sequence_of);

  return offset;
}


static const value_string h450_3_ActivateDiversionQArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_ActivateDiversionQArg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_ActivateDiversionQArg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_ActivateDiversionQArg_extension, h450_3_ActivateDiversionQArg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_activateDiversionQ_sequence[] = {
  { &hf_h450_3_procedure    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_Procedure },
  { &hf_h450_3_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_BasicService },
  { &hf_h450_3_divertedToAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_activatingUserNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_activateDiversionQArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_ActivateDiversionQArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_activateDiversionQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_activateDiversionQ, h450_3_ARG_activateDiversionQ_sequence);

  return offset;
}


static const value_string h450_3_RES_activateDiversionQ_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_RES_activateDiversionQ_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_RES_activateDiversionQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_RES_activateDiversionQ, h450_3_RES_activateDiversionQ_choice,
                                 NULL);

  return offset;
}


static const value_string h450_3_DeactivateDiversionQArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_DeactivateDiversionQArg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_DeactivateDiversionQArg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_DeactivateDiversionQArg_extension, h450_3_DeactivateDiversionQArg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_deactivateDiversionQ_sequence[] = {
  { &hf_h450_3_procedure    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_Procedure },
  { &hf_h450_3_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_BasicService },
  { &hf_h450_3_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_deactivatingUserNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_deactivateDiversionQArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DeactivateDiversionQArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_deactivateDiversionQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_deactivateDiversionQ, h450_3_ARG_deactivateDiversionQ_sequence);

  return offset;
}


static const value_string h450_3_RES_deactivateDiversionQ_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_RES_deactivateDiversionQ_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_RES_deactivateDiversionQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_RES_deactivateDiversionQ, h450_3_RES_deactivateDiversionQ_choice,
                                 NULL);

  return offset;
}


static const value_string h450_3_InterrogateDiversionQ_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_InterrogateDiversionQ_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_InterrogateDiversionQ_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_InterrogateDiversionQ_extension, h450_3_InterrogateDiversionQ_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_interrogateDiversionQ_sequence[] = {
  { &hf_h450_3_procedure    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_Procedure },
  { &hf_h450_3_basicService , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BasicService },
  { &hf_h450_3_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_interrogatingUserNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_interrogateDiversionQ_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_InterrogateDiversionQ_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_interrogateDiversionQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_interrogateDiversionQ, h450_3_ARG_interrogateDiversionQ_sequence);

  return offset;
}


static const value_string h450_3_CheckRestrictionArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_CheckRestrictionArg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_CheckRestrictionArg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_CheckRestrictionArg_extension, h450_3_CheckRestrictionArg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_checkRestriction_sequence[] = {
  { &hf_h450_3_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_BasicService },
  { &hf_h450_3_divertedToNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_checkRestrictionArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_CheckRestrictionArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_checkRestriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_checkRestriction, h450_3_ARG_checkRestriction_sequence);

  return offset;
}


static const value_string h450_3_RES_checkRestriction_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_RES_checkRestriction_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_RES_checkRestriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_RES_checkRestriction, h450_3_RES_checkRestriction_choice,
                                 NULL);

  return offset;
}


static const value_string h450_3_DiversionReason_vals[] = {
  {   0, "unknown" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfnr" },
  { 0, NULL }
};


static int
dissect_h450_3_DiversionReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_h450_3_INTEGER_1_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, FALSE);

  return offset;
}


static const value_string h450_3_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_h450_3_SubscriptionOption(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_h450_3_BMPString_SIZE_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128, FALSE);

  return offset;
}


static const value_string h450_3_CallReroutingArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_CallReroutingArg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_CallReroutingArg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_CallReroutingArg_extension, h450_3_CallReroutingArg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_callRerouting_sequence[] = {
  { &hf_h450_3_reroutingReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_DiversionReason },
  { &hf_h450_3_originalReroutingReason, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DiversionReason },
  { &hf_h450_3_calledAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_diversionCounter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_INTEGER_1_15 },
  { &hf_h450_3_h225InfoElement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_H225InformationElement },
  { &hf_h450_3_lastReroutingNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_subscriptionOption, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_SubscriptionOption },
  { &hf_h450_3_callingPartySubaddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_PartySubaddress },
  { &hf_h450_3_callingNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_callingInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_originalCalledNr, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_3_redirectingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_originalCalledInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_callReroutingArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_CallReroutingArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_callRerouting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_callRerouting, h450_3_ARG_callRerouting_sequence);

  return offset;
}


static const value_string h450_3_RES_callRerouting_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_RES_callRerouting_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_RES_callRerouting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_RES_callRerouting, h450_3_RES_callRerouting_choice,
                                 NULL);

  return offset;
}


static const value_string h450_3_DivertingLegInformation1Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_DivertingLegInformation1Arg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_DivertingLegInformation1Arg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_DivertingLegInformation1Arg_extension, h450_3_DivertingLegInformation1Arg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_divertingLegInformation1_sequence[] = {
  { &hf_h450_3_diversionReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_DiversionReason },
  { &hf_h450_3_subscriptionOption, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_SubscriptionOption },
  { &hf_h450_3_nominatedNr  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_nominatedInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_redirectingNr, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_3_redirectingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_divertingLegInformation1Arg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DivertingLegInformation1Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_divertingLegInformation1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_divertingLegInformation1, h450_3_ARG_divertingLegInformation1_sequence);

  return offset;
}


static const value_string h450_3_DivertingLegInformation2Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_DivertingLegInformation2Arg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_DivertingLegInformation2Arg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_DivertingLegInformation2Arg_extension, h450_3_DivertingLegInformation2Arg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_divertingLegInformation2_sequence[] = {
  { &hf_h450_3_diversionCounter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_INTEGER_1_15 },
  { &hf_h450_3_diversionReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_DiversionReason },
  { &hf_h450_3_originalDiversionReason, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DiversionReason },
  { &hf_h450_3_divertingNr  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_3_originalCalledNr, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_3_redirectingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_originalCalledInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_divertingLegInformation2Arg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DivertingLegInformation2Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_divertingLegInformation2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_divertingLegInformation2, h450_3_ARG_divertingLegInformation2_sequence);

  return offset;
}


static const value_string h450_3_DivertingLegInformation3Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_DivertingLegInformation3Arg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_DivertingLegInformation3Arg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_DivertingLegInformation3Arg_extension, h450_3_DivertingLegInformation3Arg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_divertingLegInformation3_sequence[] = {
  { &hf_h450_3_presentationAllowedIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_PresentationAllowedIndicator },
  { &hf_h450_3_redirectionNr, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_3_redirectionInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_divertingLegInformation3Arg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DivertingLegInformation3Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_divertingLegInformation3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_divertingLegInformation3, h450_3_ARG_divertingLegInformation3_sequence);

  return offset;
}


static const value_string h450_3_DivertingLegInformation4Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_DivertingLegInformation4Arg_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_DivertingLegInformation4Arg_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_DivertingLegInformation4Arg_extension, h450_3_DivertingLegInformation4Arg_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_ARG_divertingLegInformation4_sequence[] = {
  { &hf_h450_3_diversionReason, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_DiversionReason },
  { &hf_h450_3_subscriptionOption, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_SubscriptionOption },
  { &hf_h450_3_callingNr    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_callingInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_nominatedNr  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_nominatedInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BMPString_SIZE_1_128 },
  { &hf_h450_3_divertingLegInformation4Arg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_DivertingLegInformation4Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_ARG_divertingLegInformation4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_ARG_divertingLegInformation4, h450_3_ARG_divertingLegInformation4_sequence);

  return offset;
}


static const value_string h450_3_ARG_cfnrDivertedLegFailed_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_ARG_cfnrDivertedLegFailed_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_ARG_cfnrDivertedLegFailed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_ARG_cfnrDivertedLegFailed, h450_3_ARG_cfnrDivertedLegFailed_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_3_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string h450_3_IntResult_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_3_IntResult_extension_choice[] = {
  {   0, &hf_h450_3_extensionSeq , ASN1_NO_EXTENSIONS     , dissect_h450_3_ExtensionSeq },
  {   1, &hf_h450_3_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_IntResult_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_IntResult_extension, h450_3_IntResult_extension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_3_IntResult_sequence[] = {
  { &hf_h450_3_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_BasicService },
  { &hf_h450_3_procedure    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_3_Procedure },
  { &hf_h450_3_divertedToAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_3_remoteEnabled, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_BOOLEAN },
  { &hf_h450_3_intResult_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_3_IntResult_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_3_IntResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_3_IntResult, h450_3_IntResult_sequence);

  return offset;
}


static const per_sequence_t h450_3_IntResultList_set_of[1] = {
  { &hf_h450_3_IntResultList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_3_IntResult },
};

static int
dissect_h450_3_IntResultList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h450_3_IntResultList, h450_3_IntResultList_set_of,
                                             0, 29, FALSE);

  return offset;
}


static const value_string h450_3_PAR_unspecified_vals[] = {
  {   0, "extension" },
  {   1, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t h450_3_PAR_unspecified_choice[] = {
  {   0, &hf_h450_3_unspecified_extension, ASN1_NO_EXTENSIONS     , dissect_h450_Extension },
  {   1, &hf_h450_3_nonStandard  , ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_3_PAR_unspecified(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_3_PAR_unspecified, h450_3_PAR_unspecified_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_3_ARG_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_activateDiversionQ(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_activateDiversionQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_RES_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_RES_activateDiversionQ(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_RES_activateDiversionQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_deactivateDiversionQ(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_deactivateDiversionQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_RES_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_RES_deactivateDiversionQ(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_RES_deactivateDiversionQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_interrogateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_interrogateDiversionQ(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_interrogateDiversionQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_IntResultList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_IntResultList(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_IntResultList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_checkRestriction(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_checkRestriction_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_RES_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_RES_checkRestriction(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_RES_checkRestriction_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_callRerouting_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_callRerouting(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_callRerouting_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_RES_callRerouting_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_RES_callRerouting(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_RES_callRerouting_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_divertingLegInformation1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_divertingLegInformation1(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_divertingLegInformation1_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_divertingLegInformation2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_divertingLegInformation2(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_divertingLegInformation2_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_divertingLegInformation3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_divertingLegInformation3(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_divertingLegInformation3_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_divertingLegInformation4_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_divertingLegInformation4(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_divertingLegInformation4_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_ARG_cfnrDivertedLegFailed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_ARG_cfnrDivertedLegFailed(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_ARG_cfnrDivertedLegFailed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_3_PAR_unspecified_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_3_PAR_unspecified(tvb, offset, &asn1_ctx, tree, hf_h450_3_h450_3_PAR_unspecified_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Hold-Operations --- --- ---                                */


static const value_string h450_4_MixedExtension_vals[] = {
  {   0, "extension" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t h450_4_MixedExtension_choice[] = {
  {   0, &hf_h450_4_mixedExtension_extension, ASN1_NO_EXTENSIONS     , dissect_h450_Extension },
  {   1, &hf_h450_4_nonStandardData, ASN1_NO_EXTENSIONS     , dissect_h225_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_4_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_4_MixedExtension, h450_4_MixedExtension_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_4_holdNotificArg_extensionArg_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_4_HoldNotificArg_sequence[] = {
  { &hf_h450_4_holdNotificArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_4_HoldNotificArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_4_HoldNotificArg, h450_4_HoldNotificArg_sequence);

  return offset;
}


static const per_sequence_t h450_4_RetrieveNotificArg_sequence[] = {
  { &hf_h450_4_retrieveNotificArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_4_RetrieveNotificArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_4_RetrieveNotificArg, h450_4_RetrieveNotificArg_sequence);

  return offset;
}


static const per_sequence_t h450_4_RemoteHoldArg_sequence[] = {
  { &hf_h450_4_remoteHoldArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_4_RemoteHoldArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_4_RemoteHoldArg, h450_4_RemoteHoldArg_sequence);

  return offset;
}


static const per_sequence_t h450_4_RemoteHoldRes_sequence[] = {
  { &hf_h450_4_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_4_RemoteHoldRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_4_RemoteHoldRes, h450_4_RemoteHoldRes_sequence);

  return offset;
}


static const per_sequence_t h450_4_RemoteRetrieveArg_sequence[] = {
  { &hf_h450_4_remoteRetrieveArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_4_RemoteRetrieveArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_4_RemoteRetrieveArg, h450_4_RemoteRetrieveArg_sequence);

  return offset;
}


static const per_sequence_t h450_4_RemoteRetrieveRes_sequence[] = {
  { &hf_h450_4_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_4_RemoteRetrieveRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_4_RemoteRetrieveRes, h450_4_RemoteRetrieveRes_sequence);

  return offset;
}


static const per_sequence_t h450_4_PAR_undefined_sequence_of[1] = {
  { &hf_h450_4_PAR_undefined_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_4_PAR_undefined(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_4_PAR_undefined, h450_4_PAR_undefined_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_4_HoldNotificArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_HoldNotificArg(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_HoldNotificArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_4_RetrieveNotificArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_RetrieveNotificArg(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_RetrieveNotificArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_4_RemoteHoldArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_RemoteHoldArg(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_RemoteHoldArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_4_RemoteHoldRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_RemoteHoldRes(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_RemoteHoldRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_4_RemoteRetrieveArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_RemoteRetrieveArg(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_RemoteRetrieveArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_4_RemoteRetrieveRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_RemoteRetrieveRes(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_RemoteRetrieveRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_4_PAR_undefined_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_4_PAR_undefined(tvb, offset, &asn1_ctx, tree, hf_h450_4_h450_4_PAR_undefined_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Park-Pickup-Operations --- --- ---                         */



static int
dissect_h450_5_ParkedToPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_5_cpRequestArg_extensionArg_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_5_CpRequestArg_sequence[] = {
  { &hf_h450_5_parkingNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedToNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedToPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_ParkedToPosition },
  { &hf_h450_5_cpRequestArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_CpRequestArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_CpRequestArg, h450_5_CpRequestArg_sequence);

  return offset;
}


static const value_string h450_5_ParkCondition_vals[] = {
  {   0, "unspecified" },
  {   1, "parkedToUserIdle" },
  {   2, "parkedToUserBusy" },
  {   3, "parkedToGroup" },
  { 0, NULL }
};


static int
dissect_h450_5_ParkCondition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t h450_5_CpRequestRes_sequence[] = {
  { &hf_h450_5_parkedToNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedToPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_ParkedToPosition },
  { &hf_h450_5_parkCondition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_5_ParkCondition },
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_CpRequestRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_CpRequestRes, h450_5_CpRequestRes_sequence);

  return offset;
}


static const per_sequence_t h450_5_CpSetupArg_sequence[] = {
  { &hf_h450_5_parkingNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedToNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedToPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_ParkedToPosition },
  { &hf_h450_5_cpSetupArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_CpSetupArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_CpSetupArg, h450_5_CpSetupArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_CpSetupRes_sequence[] = {
  { &hf_h450_5_parkedToNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkedToPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_ParkedToPosition },
  { &hf_h450_5_parkCondition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_5_ParkCondition },
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_CpSetupRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_CpSetupRes, h450_5_CpSetupRes_sequence);

  return offset;
}


static const value_string h450_5_CallType_vals[] = {
  {   0, "parkedCall" },
  {   1, "alertingCall" },
  { 0, NULL }
};


static int
dissect_h450_5_CallType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t h450_5_GroupIndicationOnArg_sequence[] = {
  { &hf_h450_5_callPickupId , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h450_5_groupMemberUserNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_retrieveCallType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_5_CallType },
  { &hf_h450_5_partyToRetrieve, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_retrieveAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkPosition , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_ParkedToPosition },
  { &hf_h450_5_groupIndicationOnArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_GroupIndicationOnArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_GroupIndicationOnArg, h450_5_GroupIndicationOnArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_GroupIndicationOnRes_sequence[] = {
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_GroupIndicationOnRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_GroupIndicationOnRes, h450_5_GroupIndicationOnRes_sequence);

  return offset;
}


static const per_sequence_t h450_5_GroupIndicationOffArg_sequence[] = {
  { &hf_h450_5_callPickupId , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h450_5_groupMemberUserNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_groupIndicationOffArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_GroupIndicationOffArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_GroupIndicationOffArg, h450_5_GroupIndicationOffArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_GroupIndicationOffRes_sequence[] = {
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_GroupIndicationOffRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_GroupIndicationOffRes, h450_5_GroupIndicationOffRes_sequence);

  return offset;
}


static const per_sequence_t h450_5_PickrequArg_sequence[] = {
  { &hf_h450_5_picking_upNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_callPickupId , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_CallIdentifier },
  { &hf_h450_5_partyToRetrieve, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_5_retrieveAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_parkPosition , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_ParkedToPosition },
  { &hf_h450_5_pickrequArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_PickrequArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_PickrequArg, h450_5_PickrequArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_PickrequRes_sequence[] = {
  { &hf_h450_5_callPickupId , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_PickrequRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_PickrequRes, h450_5_PickrequRes_sequence);

  return offset;
}


static const per_sequence_t h450_5_PickupArg_sequence[] = {
  { &hf_h450_5_callPickupId , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h450_5_picking_upNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_pickupArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_PickupArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_PickupArg, h450_5_PickupArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_PickupRes_sequence[] = {
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_PickupRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_PickupRes, h450_5_PickupRes_sequence);

  return offset;
}


static const per_sequence_t h450_5_PickExeArg_sequence[] = {
  { &hf_h450_5_callPickupId , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225_CallIdentifier },
  { &hf_h450_5_picking_upNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_partyToRetrieve, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_5_pickExeArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_PickExeArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_PickExeArg, h450_5_PickExeArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_PickExeRes_sequence[] = {
  { &hf_h450_5_extensionRes , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_PickExeRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_PickExeRes, h450_5_PickExeRes_sequence);

  return offset;
}


static const per_sequence_t h450_5_CpNotifyArg_sequence[] = {
  { &hf_h450_5_parkingNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_5_cpNotifyArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_CpNotifyArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_CpNotifyArg, h450_5_CpNotifyArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_CpickupNotifyArg_sequence[] = {
  { &hf_h450_5_picking_upNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_5_cpickupNotifyArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_5_CpickupNotifyArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_5_CpickupNotifyArg, h450_5_CpickupNotifyArg_sequence);

  return offset;
}


static const per_sequence_t h450_5_PAR_undefined_sequence_of[1] = {
  { &hf_h450_5_PAR_undefined_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_5_PAR_undefined(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_5_PAR_undefined, h450_5_PAR_undefined_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_5_CpRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_CpRequestArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_CpRequestArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_CpRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_CpRequestRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_CpRequestRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_CpSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_CpSetupArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_CpSetupArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_CpSetupRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_CpSetupRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_CpSetupRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_GroupIndicationOnArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_GroupIndicationOnArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_GroupIndicationOnArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_GroupIndicationOnRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_GroupIndicationOnRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_GroupIndicationOnRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_GroupIndicationOffArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_GroupIndicationOffArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_GroupIndicationOffArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_GroupIndicationOffRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_GroupIndicationOffRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_GroupIndicationOffRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PickrequArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PickrequArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PickrequArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PickrequRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PickrequRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PickrequRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PickupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PickupArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PickupArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PickupRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PickupRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PickupRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PickExeArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PickExeArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PickExeArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PickExeRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PickExeRes(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PickExeRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_CpNotifyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_CpNotifyArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_CpNotifyArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_CpickupNotifyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_CpickupNotifyArg(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_CpickupNotifyArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_5_PAR_undefined_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_5_PAR_undefined(tvb, offset, &asn1_ctx, tree, hf_h450_5_h450_5_PAR_undefined_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Waiting-Operations --- --- ---                             */



static int
dissect_h450_6_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_6_callWaitingArg_extensionArg_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_6_CallWaitingArg_sequence[] = {
  { &hf_h450_6_nbOfAddWaitingCalls, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_6_INTEGER_0_255 },
  { &hf_h450_6_callWaitingArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_6_CallWaitingArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_6_CallWaitingArg, h450_6_CallWaitingArg_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_6_CallWaitingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_6_CallWaitingArg(tvb, offset, &asn1_ctx, tree, hf_h450_6_h450_6_CallWaitingArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Message-Waiting-Indication-Operations --- --- ---               */


static const value_string h450_7_BasicService_vals[] = {
  {   0, "allServices" },
  {   1, "speech" },
  {   2, "unrestrictedDigitalInformation" },
  {   3, "audio3100Hz" },
  {  32, "telephony" },
  {  33, "teletex" },
  {  34, "telefaxGroup4Class1" },
  {  35, "videotexSyntaxBased" },
  {  36, "videotelephony" },
  {  37, "telefaxGroup2-3" },
  {  38, "reservedNotUsed1" },
  {  39, "reservedNotUsed2" },
  {  40, "reservedNotUsed3" },
  {  41, "reservedNotUsed4" },
  {  42, "reservedNotUsed5" },
  {  51, "email" },
  {  52, "video" },
  {  53, "fileTransfer" },
  {  54, "shortMessageService" },
  {  55, "speechAndVideo" },
  {  56, "speechAndFax" },
  {  57, "speechAndEmail" },
  {  58, "videoAndFax" },
  {  59, "videoAndEmail" },
  {  60, "faxAndEmail" },
  {  61, "speechVideoAndFax" },
  {  62, "speechVideoAndEmail" },
  {  63, "speechFaxAndEmail" },
  {  64, "videoFaxAndEmail" },
  {  65, "speechVideoFaxAndEmail" },
  {  66, "multimediaUnknown" },
  {  67, "serviceUnknown" },
  {  68, "futureReserve1" },
  {  69, "futureReserve2" },
  {  70, "futureReserve3" },
  {  71, "futureReserve4" },
  {  72, "futureReserve5" },
  {  73, "futureReserve6" },
  {  74, "futureReserve7" },
  {  75, "futureReserve8" },
  { 0, NULL }
};

static guint32 h450_7_BasicService_value_map[40+0] = {0, 1, 2, 3, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75};

static int
dissect_h450_7_BasicService(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     40, NULL, FALSE, 0, h450_7_BasicService_value_map);

  return offset;
}



static int
dissect_h450_7_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_h450_7_NumericString_SIZE_1_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          1, 10, FALSE);

  return offset;
}


static const value_string h450_7_MsgCentreId_vals[] = {
  {   0, "integer" },
  {   1, "partyNumber" },
  {   2, "numericString" },
  { 0, NULL }
};

static const per_choice_t h450_7_MsgCentreId_choice[] = {
  {   0, &hf_h450_7_integer      , ASN1_NO_EXTENSIONS     , dissect_h450_7_INTEGER_0_65535 },
  {   1, &hf_h450_7_partyNumber  , ASN1_NO_EXTENSIONS     , dissect_h450_EndpointAddress },
  {   2, &hf_h450_7_numericString, ASN1_NO_EXTENSIONS     , dissect_h450_7_NumericString_SIZE_1_10 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_7_MsgCentreId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_7_MsgCentreId, h450_7_MsgCentreId_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_7_NbOfMessages(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_h450_7_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        12, 19, FALSE);

  return offset;
}



static int
dissect_h450_7_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_7_mWIActivateArg_extensionArg_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_7_MWIActivateArg_sequence[] = {
  { &hf_h450_7_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_7_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_7_BasicService },
  { &hf_h450_7_msgCentreId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_MsgCentreId },
  { &hf_h450_7_nbOfMessages , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_NbOfMessages },
  { &hf_h450_7_originatingNr, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_7_timestamp    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_TimeStamp },
  { &hf_h450_7_priority     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_INTEGER_0_9 },
  { &hf_h450_7_mWIActivateArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_7_MWIActivateArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_7_MWIActivateArg, h450_7_MWIActivateArg_sequence);

  return offset;
}


static const per_sequence_t h450_7_DummyRes_sequence_of[1] = {
  { &hf_h450_7_DummyRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_7_DummyRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_7_DummyRes, h450_7_DummyRes_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}



static int
dissect_h450_7_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t h450_7_MWIDeactivateArg_sequence[] = {
  { &hf_h450_7_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_7_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_7_BasicService },
  { &hf_h450_7_msgCentreId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_MsgCentreId },
  { &hf_h450_7_callbackReq  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_BOOLEAN },
  { &hf_h450_7_mWIDeactivateArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_7_MWIDeactivateArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_7_MWIDeactivateArg, h450_7_MWIDeactivateArg_sequence);

  return offset;
}


static const per_sequence_t h450_7_MWIInterrogateArg_sequence[] = {
  { &hf_h450_7_servedUserNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_7_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_7_BasicService },
  { &hf_h450_7_msgCentreId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_MsgCentreId },
  { &hf_h450_7_callbackReq  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_BOOLEAN },
  { &hf_h450_7_mWIInterrogateArg_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_7_MWIInterrogateArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_7_MWIInterrogateArg, h450_7_MWIInterrogateArg_sequence);

  return offset;
}


static const per_sequence_t h450_7_MWIInterrogateResElt_sequence[] = {
  { &hf_h450_7_basicService , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_7_BasicService },
  { &hf_h450_7_msgCentreId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_MsgCentreId },
  { &hf_h450_7_nbOfMessages , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_NbOfMessages },
  { &hf_h450_7_originatingNr, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_7_timestamp    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_TimeStamp },
  { &hf_h450_7_priority     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_INTEGER_0_9 },
  { &hf_h450_7_mWIInterrogateResElt_extensionArg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_7_MWIInterrogateResElt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_7_MWIInterrogateResElt, h450_7_MWIInterrogateResElt_sequence);

  return offset;
}


static const per_sequence_t h450_7_MWIInterrogateRes_sequence_of[1] = {
  { &hf_h450_7_MWIInterrogateRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_7_MWIInterrogateResElt },
};

static int
dissect_h450_7_MWIInterrogateRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_7_MWIInterrogateRes, h450_7_MWIInterrogateRes_sequence_of,
                                                  1, 64, FALSE);

  return offset;
}


static const per_sequence_t h450_7_PAR_undefined_sequence_of[1] = {
  { &hf_h450_7_PAR_undefined_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_7_PAR_undefined(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_7_PAR_undefined, h450_7_PAR_undefined_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_7_MWIActivateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_7_MWIActivateArg(tvb, offset, &asn1_ctx, tree, hf_h450_7_h450_7_MWIActivateArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_7_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_7_DummyRes(tvb, offset, &asn1_ctx, tree, hf_h450_7_h450_7_DummyRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_7_MWIDeactivateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_7_MWIDeactivateArg(tvb, offset, &asn1_ctx, tree, hf_h450_7_h450_7_MWIDeactivateArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_7_MWIInterrogateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_7_MWIInterrogateArg(tvb, offset, &asn1_ctx, tree, hf_h450_7_h450_7_MWIInterrogateArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_7_MWIInterrogateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_7_MWIInterrogateRes(tvb, offset, &asn1_ctx, tree, hf_h450_7_h450_7_MWIInterrogateRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_7_PAR_undefined_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_7_PAR_undefined(tvb, offset, &asn1_ctx, tree, hf_h450_7_h450_7_PAR_undefined_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Name-Operations --- --- ---                                     */



static int
dissect_h450_8_SimpleName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 50, FALSE, NULL);

  return offset;
}



static int
dissect_h450_8_ExtendedName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 256, FALSE);

  return offset;
}


static const value_string h450_8_NamePresentationAllowed_vals[] = {
  {   0, "simpleName" },
  {   1, "extendedName" },
  { 0, NULL }
};

static const per_choice_t h450_8_NamePresentationAllowed_choice[] = {
  {   0, &hf_h450_8_simpleName   , ASN1_EXTENSION_ROOT    , dissect_h450_8_SimpleName },
  {   1, &hf_h450_8_extendedName , ASN1_EXTENSION_ROOT    , dissect_h450_8_ExtendedName },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_8_NamePresentationAllowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_8_NamePresentationAllowed, h450_8_NamePresentationAllowed_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_8_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h450_8_NamePresentationRestricted_vals[] = {
  {   0, "simpleName" },
  {   1, "extendedName" },
  {   2, "restrictedNull" },
  { 0, NULL }
};

static const per_choice_t h450_8_NamePresentationRestricted_choice[] = {
  {   0, &hf_h450_8_simpleName   , ASN1_EXTENSION_ROOT    , dissect_h450_8_SimpleName },
  {   1, &hf_h450_8_extendedName , ASN1_EXTENSION_ROOT    , dissect_h450_8_ExtendedName },
  {   2, &hf_h450_8_restrictedNull, ASN1_EXTENSION_ROOT    , dissect_h450_8_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_8_NamePresentationRestricted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_8_NamePresentationRestricted, h450_8_NamePresentationRestricted_choice,
                                 NULL);

  return offset;
}


static const value_string h450_8_Name_vals[] = {
  {   0, "namePresentationAllowed" },
  {   1, "namePresentationRestricted" },
  {   2, "nameNotAvailable" },
  { 0, NULL }
};

static const per_choice_t h450_8_Name_choice[] = {
  {   0, &hf_h450_8_namePresentationAllowed, ASN1_EXTENSION_ROOT    , dissect_h450_8_NamePresentationAllowed },
  {   1, &hf_h450_8_namePresentationRestricted, ASN1_EXTENSION_ROOT    , dissect_h450_8_NamePresentationRestricted },
  {   2, &hf_h450_8_nameNotAvailable, ASN1_EXTENSION_ROOT    , dissect_h450_8_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_8_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_8_Name, h450_8_Name_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_8_extensionArg_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_8_ARG_callingName_sequence[] = {
  { &hf_h450_8_name         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_8_Name },
  { &hf_h450_8_extensionArg , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_8_ARG_callingName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_8_ARG_callingName, h450_8_ARG_callingName_sequence);

  return offset;
}


static const per_sequence_t h450_8_ARG_alertingName_sequence[] = {
  { &hf_h450_8_name         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_8_Name },
  { &hf_h450_8_extensionArg , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_8_ARG_alertingName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_8_ARG_alertingName, h450_8_ARG_alertingName_sequence);

  return offset;
}


static const per_sequence_t h450_8_ARG_connectedName_sequence[] = {
  { &hf_h450_8_name         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_8_Name },
  { &hf_h450_8_extensionArg , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_8_ARG_connectedName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_8_ARG_connectedName, h450_8_ARG_connectedName_sequence);

  return offset;
}


static const per_sequence_t h450_8_ARG_busyName_sequence[] = {
  { &hf_h450_8_name         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_8_Name },
  { &hf_h450_8_extensionArg , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_8_ARG_busyName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_8_ARG_busyName, h450_8_ARG_busyName_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_8_ARG_callingName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_8_ARG_callingName(tvb, offset, &asn1_ctx, tree, hf_h450_8_h450_8_ARG_callingName_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_8_ARG_alertingName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_8_ARG_alertingName(tvb, offset, &asn1_ctx, tree, hf_h450_8_h450_8_ARG_alertingName_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_8_ARG_connectedName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_8_ARG_connectedName(tvb, offset, &asn1_ctx, tree, hf_h450_8_h450_8_ARG_connectedName_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_8_ARG_busyName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_8_ARG_busyName(tvb, offset, &asn1_ctx, tree, hf_h450_8_h450_8_ARG_busyName_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Completion-Operations --- --- ---                          */



static int
dissect_h450_9_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_9_ccRequestArg_extension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_9_CcRequestArg_sequence[] = {
  { &hf_h450_9_numberA      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_9_numberB      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_EndpointAddress },
  { &hf_h450_9_ccIdentifier , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_CallIdentifier },
  { &hf_h450_9_service      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_7_BasicService },
  { &hf_h450_9_can_retain_service, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_9_BOOLEAN },
  { &hf_h450_9_retain_sig_connection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_9_BOOLEAN },
  { &hf_h450_9_ccRequestArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_9_CcRequestArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_9_CcRequestArg, h450_9_CcRequestArg_sequence);

  return offset;
}


static const per_sequence_t h450_9_CcRequestRes_sequence[] = {
  { &hf_h450_9_retain_service, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_9_BOOLEAN },
  { &hf_h450_9_ccRequestRes_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_9_CcRequestRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_9_CcRequestRes, h450_9_CcRequestRes_sequence);

  return offset;
}


static const per_sequence_t h450_9_CcShortArg_sequence[] = {
  { &hf_h450_9_ccIdentifier , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_CallIdentifier },
  { &hf_h450_9_ccShortArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_9_CcShortArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_9_CcShortArg, h450_9_CcShortArg_sequence);

  return offset;
}


static const per_sequence_t h450_9_CcLongArg_sequence[] = {
  { &hf_h450_9_numberA      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_9_numberB      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_EndpointAddress },
  { &hf_h450_9_ccIdentifier , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_CallIdentifier },
  { &hf_h450_9_service      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_7_BasicService },
  { &hf_h450_9_ccLongArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_9_CcLongArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_9_CcLongArg, h450_9_CcLongArg_sequence);

  return offset;
}


static const value_string h450_9_CcArg_vals[] = {
  {   0, "shortArg" },
  {   1, "longArg" },
  { 0, NULL }
};

static const per_choice_t h450_9_CcArg_choice[] = {
  {   0, &hf_h450_9_shortArg     , ASN1_EXTENSION_ROOT    , dissect_h450_9_CcShortArg },
  {   1, &hf_h450_9_longArg      , ASN1_EXTENSION_ROOT    , dissect_h450_9_CcLongArg },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_9_CcArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_9_CcArg, h450_9_CcArg_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_9_CcRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_9_CcRequestArg(tvb, offset, &asn1_ctx, tree, hf_h450_9_h450_9_CcRequestArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_9_CcRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_9_CcRequestRes(tvb, offset, &asn1_ctx, tree, hf_h450_9_h450_9_CcRequestRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_9_CcArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_9_CcArg(tvb, offset, &asn1_ctx, tree, hf_h450_9_h450_9_CcArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_9_CcShortArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_9_CcShortArg(tvb, offset, &asn1_ctx, tree, hf_h450_9_h450_9_CcShortArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Offer-Operations --- --- ---                               */


static const per_sequence_t h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_10_coReqOptArg_extension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_10_CoReqOptArg_sequence[] = {
  { &hf_h450_10_coReqOptArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_10_CoReqOptArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_10_CoReqOptArg, h450_10_CoReqOptArg_sequence);

  return offset;
}


static const per_sequence_t h450_10_RUAlertOptArg_sequence[] = {
  { &hf_h450_10_rUAlertOptArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_10_RUAlertOptArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_10_RUAlertOptArg, h450_10_RUAlertOptArg_sequence);

  return offset;
}


static const per_sequence_t h450_10_CfbOvrOptArg_sequence[] = {
  { &hf_h450_10_cfbOvrOptArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_10_CfbOvrOptArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_10_CfbOvrOptArg, h450_10_CfbOvrOptArg_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_10_CoReqOptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_10_CoReqOptArg(tvb, offset, &asn1_ctx, tree, hf_h450_10_h450_10_CoReqOptArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_10_RUAlertOptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_10_RUAlertOptArg(tvb, offset, &asn1_ctx, tree, hf_h450_10_h450_10_RUAlertOptArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_10_CfbOvrOptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_10_CfbOvrOptArg(tvb, offset, &asn1_ctx, tree, hf_h450_10_h450_10_CfbOvrOptArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Call-Intrusion-Operations --- --- ---                           */


static const value_string h450_11_CICapabilityLevel_vals[] = {
  {   1, "intrusionLowCap" },
  {   2, "intrusionMediumCap" },
  {   3, "intrusionHighCap" },
  { 0, NULL }
};


static int
dissect_h450_11_CICapabilityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_11_cIRequestArg_argumentExtension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_11_CIRequestArg_sequence[] = {
  { &hf_h450_11_ciCapabilityLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_11_CICapabilityLevel },
  { &hf_h450_11_cIRequestArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIRequestArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIRequestArg, h450_11_CIRequestArg_sequence);

  return offset;
}



static int
dissect_h450_11_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h450_11_CIStatusInformation_vals[] = {
  {   0, "callIntrusionImpending" },
  {   1, "callIntruded" },
  {   2, "callIsolated" },
  {   3, "callForceReleased" },
  {   4, "callIntrusionComplete" },
  {   5, "callIntrusionEnd" },
  { 0, NULL }
};

static const per_choice_t h450_11_CIStatusInformation_choice[] = {
  {   0, &hf_h450_11_callIntrusionImpending, ASN1_EXTENSION_ROOT    , dissect_h450_11_NULL },
  {   1, &hf_h450_11_callIntruded, ASN1_EXTENSION_ROOT    , dissect_h450_11_NULL },
  {   2, &hf_h450_11_callIsolated, ASN1_EXTENSION_ROOT    , dissect_h450_11_NULL },
  {   3, &hf_h450_11_callForceReleased, ASN1_EXTENSION_ROOT    , dissect_h450_11_NULL },
  {   4, &hf_h450_11_callIntrusionComplete, ASN1_EXTENSION_ROOT    , dissect_h450_11_NULL },
  {   5, &hf_h450_11_callIntrusionEnd, ASN1_EXTENSION_ROOT    , dissect_h450_11_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_11_CIStatusInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_11_CIStatusInformation, h450_11_CIStatusInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t h450_11_CIRequestRes_sequence[] = {
  { &hf_h450_11_ciStatusInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_11_CIStatusInformation },
  { &hf_h450_11_cIRequestRes_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIRequestRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIRequestRes, h450_11_CIRequestRes_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIGetCIPLOptArg_sequence[] = {
  { &hf_h450_11_cIGetCIPLOptArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIGetCIPLOptArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIGetCIPLOptArg, h450_11_CIGetCIPLOptArg_sequence);

  return offset;
}


static const value_string h450_11_CIProtectionLevel_vals[] = {
  {   0, "lowProtection" },
  {   1, "mediumProtection" },
  {   2, "highProtection" },
  {   3, "fullProtection" },
  { 0, NULL }
};


static int
dissect_h450_11_CIProtectionLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h450_11_CIGetCIPLRes_sequence[] = {
  { &hf_h450_11_ciProtectionLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_11_CIProtectionLevel },
  { &hf_h450_11_silentMonitoringPermitted, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_NULL },
  { &hf_h450_11_cIGetCIPLRes_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIGetCIPLRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIGetCIPLRes, h450_11_CIGetCIPLRes_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIIsOptArg_sequence[] = {
  { &hf_h450_11_cIIsOptArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIIsOptArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIIsOptArg, h450_11_CIIsOptArg_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIIsOptRes_sequence[] = {
  { &hf_h450_11_cIIsOptRes_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIIsOptRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIIsOptRes, h450_11_CIIsOptRes_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIFrcRelArg_sequence[] = {
  { &hf_h450_11_ciCapabilityLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_11_CICapabilityLevel },
  { &hf_h450_11_cIFrcRelArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIFrcRelArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIFrcRelArg, h450_11_CIFrcRelArg_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIFrcRelOptRes_sequence[] = {
  { &hf_h450_11_cIFrcRelOptRes_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIFrcRelOptRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIFrcRelOptRes, h450_11_CIFrcRelOptRes_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIWobOptArg_sequence[] = {
  { &hf_h450_11_cIWobOptArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIWobOptArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIWobOptArg, h450_11_CIWobOptArg_sequence);

  return offset;
}


static const per_sequence_t h450_11_CIWobOptRes_sequence[] = {
  { &hf_h450_11_cIWobOptRes_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CIWobOptRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CIWobOptRes, h450_11_CIWobOptRes_sequence);

  return offset;
}


static const per_sequence_t h450_11_CISilentArg_sequence[] = {
  { &hf_h450_11_ciCapabilityLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_11_CICapabilityLevel },
  { &hf_h450_11_specificCall, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h225_CallIdentifier },
  { &hf_h450_11_cISilentArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CISilentArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CISilentArg, h450_11_CISilentArg_sequence);

  return offset;
}


static const per_sequence_t h450_11_CISilentOptRes_sequence[] = {
  { &hf_h450_11_cISilentOptRes_resultExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CISilentOptRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CISilentOptRes, h450_11_CISilentOptRes_sequence);

  return offset;
}


static const per_sequence_t h450_11_CINotificationArg_sequence[] = {
  { &hf_h450_11_ciStatusInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h450_11_CIStatusInformation },
  { &hf_h450_11_cINotificationArg_argumentExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_11_CINotificationArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_11_CINotificationArg, h450_11_CINotificationArg_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_11_CIRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIRequestArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIRequestArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIRequestRes(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIRequestRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIGetCIPLOptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIGetCIPLOptArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIGetCIPLOptArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIGetCIPLRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIGetCIPLRes(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIGetCIPLRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIIsOptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIIsOptArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIIsOptArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIIsOptRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIIsOptRes(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIIsOptRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIFrcRelArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIFrcRelArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIFrcRelArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIFrcRelOptRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIFrcRelOptRes(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIFrcRelOptRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIWobOptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIWobOptArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIWobOptArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CIWobOptRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CIWobOptRes(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CIWobOptRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CISilentArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CISilentArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CISilentArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CISilentOptRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CISilentOptRes(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CISilentOptRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_11_CINotificationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_11_CINotificationArg(tvb, offset, &asn1_ctx, tree, hf_h450_11_h450_11_CINotificationArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/* --- Module Common-Information-Operations --- --- ---                       */



static int
dissect_h450_12_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t h450_12_FeatureList_sequence[] = {
  { &hf_h450_12_ssCFreRoutingSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCTreRoutingSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCCBSPossible, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCCNRPossible, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCOSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCIForcedReleaseSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCIIsolationSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCIWaitOnBusySupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCISilentMonitoringSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCIConferenceSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCHFarHoldSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssMWICallbackSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCPCallParkSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_12_FeatureList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_12_FeatureList, h450_12_FeatureList_sequence);

  return offset;
}


static const value_string h450_12_PartyCategory_vals[] = {
  {   0, "unknown" },
  {   1, "extension" },
  {   2, "attendant" },
  {   3, "emergExt" },
  { 0, NULL }
};


static int
dissect_h450_12_PartyCategory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_h450_12_SSCIProtectionLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t h450_12_FeatureValues_sequence[] = {
  { &hf_h450_12_partyCategory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_PartyCategory },
  { &hf_h450_12_ssCIprotectionLevel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_SSCIProtectionLevel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_12_FeatureValues(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_12_FeatureValues, h450_12_FeatureValues_sequence);

  return offset;
}


static const per_sequence_t h450_12_FeatureControl_sequence[] = {
  { &hf_h450_12_ssCHDoNotHold, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCTDoNotTransfer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssMWICallbackCall, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { &hf_h450_12_ssCISilentMonitorPermitted, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_12_FeatureControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_12_FeatureControl, h450_12_FeatureControl_sequence);

  return offset;
}


static const per_sequence_t h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { &hf_h450_12_cmnArg_extension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_4_MixedExtension },
};

static int
dissect_h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension, h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255, FALSE);

  return offset;
}


static const per_sequence_t h450_12_CmnArg_sequence[] = {
  { &hf_h450_12_featureList , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_FeatureList },
  { &hf_h450_12_featureValues, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_FeatureValues },
  { &hf_h450_12_featureControl, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_FeatureControl },
  { &hf_h450_12_cmnArg_extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_12_CmnArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_12_CmnArg, h450_12_CmnArg_sequence);

  return offset;
}


static const per_sequence_t h450_12_DummyArg_sequence[] = {
  { &hf_h450_12_extensionArg, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_12_DummyArg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_12_DummyArg, h450_12_DummyArg_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_h450_12_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_12_DummyArg(tvb, offset, &asn1_ctx, tree, hf_h450_12_h450_12_DummyArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_h450_12_CmnArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h450_12_CmnArg(tvb, offset, &asn1_ctx, tree, hf_h450_12_h450_12_CmnArg_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-h450-fn.c ---*/
#line 74 "../../asn1/h450/packet-h450-template.c"

typedef struct _h450_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} h450_op_t;

static const h450_op_t h450_op_tab[] = {

/*--- Included file: packet-h450-table11.c ---*/
#line 1 "../../asn1/h450/packet-h450-table11.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

/* Unknown or empty loop list OPERATION */

/* --- Module Call-Transfer-Operations --- --- ---                            */

  /* callTransferIdentify     */ {   7, dissect_h450_2_DummyArg_PDU, dissect_h450_2_CTIdentifyRes_PDU },
  /* callTransferAbandon      */ {   8, dissect_h450_2_DummyArg_PDU, NULL },
  /* callTransferInitiate     */ {   9, dissect_h450_2_CTInitiateArg_PDU, dissect_h450_2_DummyRes_PDU },
  /* callTransferSetup        */ {  10, dissect_h450_2_CTSetupArg_PDU, dissect_h450_2_DummyRes_PDU },
  /* callTransferUpdate       */ {  13, dissect_h450_2_CTUpdateArg_PDU, NULL },
  /* subaddressTransfer       */ {  14, dissect_h450_2_SubaddressTransferArg_PDU, NULL },
  /* callTransferComplete     */ {  12, dissect_h450_2_CTCompleteArg_PDU, NULL },
  /* callTransferActive       */ {  11, dissect_h450_2_CTActiveArg_PDU, NULL },

/* --- Module Call-Diversion-Operations --- --- ---                           */

  /* activateDiversionQ       */ {  15, dissect_h450_3_ARG_activateDiversionQ_PDU, dissect_h450_3_RES_activateDiversionQ_PDU },
  /* deactivateDiversionQ     */ {  16, dissect_h450_3_ARG_deactivateDiversionQ_PDU, dissect_h450_3_RES_deactivateDiversionQ_PDU },
  /* interrogateDiversionQ    */ {  17, dissect_h450_3_ARG_interrogateDiversionQ_PDU, dissect_h450_3_IntResultList_PDU },
  /* checkRestriction         */ {  18, dissect_h450_3_ARG_checkRestriction_PDU, dissect_h450_3_RES_checkRestriction_PDU },
  /* callRerouting            */ {  19, dissect_h450_3_ARG_callRerouting_PDU, dissect_h450_3_RES_callRerouting_PDU },
  /* divertingLegInformation1 */ {  20, dissect_h450_3_ARG_divertingLegInformation1_PDU, NULL },
  /* divertingLegInformation2 */ {  21, dissect_h450_3_ARG_divertingLegInformation2_PDU, NULL },
  /* divertingLegInformation3 */ {  22, dissect_h450_3_ARG_divertingLegInformation3_PDU, NULL },
  /* divertingLegInformation4 */ { 100, dissect_h450_3_ARG_divertingLegInformation4_PDU, NULL },
  /* cfnrDivertedLegFailed    */ {  23, dissect_h450_3_ARG_cfnrDivertedLegFailed_PDU, NULL },

/* --- Module Call-Hold-Operations --- --- ---                                */

  /* holdNotific              */ { 101, dissect_h450_4_HoldNotificArg_PDU, NULL },
  /* retrieveNotific          */ { 102, dissect_h450_4_RetrieveNotificArg_PDU, NULL },
  /* remoteHold               */ { 103, dissect_h450_4_RemoteHoldArg_PDU, dissect_h450_4_RemoteHoldRes_PDU },
  /* remoteRetrieve           */ { 104, dissect_h450_4_RemoteRetrieveArg_PDU, dissect_h450_4_RemoteRetrieveRes_PDU },

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

  /* cpRequest                */ { 106, dissect_h450_5_CpRequestArg_PDU, dissect_h450_5_CpRequestRes_PDU },
  /* cpSetup                  */ { 107, dissect_h450_5_CpSetupArg_PDU, dissect_h450_5_CpSetupRes_PDU },
  /* groupIndicationOn        */ { 108, dissect_h450_5_GroupIndicationOnArg_PDU, dissect_h450_5_GroupIndicationOnRes_PDU },
  /* groupIndicationOff       */ { 109, dissect_h450_5_GroupIndicationOffArg_PDU, dissect_h450_5_GroupIndicationOffRes_PDU },
  /* pickrequ                 */ { 110, dissect_h450_5_PickrequArg_PDU, dissect_h450_5_PickrequRes_PDU },
  /* pickup                   */ { 111, dissect_h450_5_PickupArg_PDU, dissect_h450_5_PickupRes_PDU },
  /* pickExe                  */ { 112, dissect_h450_5_PickExeArg_PDU, dissect_h450_5_PickExeRes_PDU },
  /* cpNotify                 */ { 113, dissect_h450_5_CpNotifyArg_PDU, NULL },
  /* cpickupNotify            */ { 114, dissect_h450_5_CpickupNotifyArg_PDU, NULL },

/* --- Module Call-Waiting-Operations --- --- ---                             */

  /* callWaiting              */ { 105, dissect_h450_6_CallWaitingArg_PDU, NULL },

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

  /* mwiActivate              */ {  80, dissect_h450_7_MWIActivateArg_PDU, dissect_h450_7_DummyRes_PDU },
  /* mwiDeactivate            */ {  81, dissect_h450_7_MWIDeactivateArg_PDU, dissect_h450_7_DummyRes_PDU },
  /* mwiInterrogate           */ {  82, dissect_h450_7_MWIInterrogateArg_PDU, dissect_h450_7_MWIInterrogateRes_PDU },

/* --- Module Name-Operations --- --- ---                                     */

  /* callingName              */ {   0, dissect_h450_8_ARG_callingName_PDU, NULL },
  /* alertingName             */ {   1, dissect_h450_8_ARG_alertingName_PDU, NULL },
  /* connectedName            */ {   2, dissect_h450_8_ARG_connectedName_PDU, NULL },
  /* busyName                 */ {   3, dissect_h450_8_ARG_busyName_PDU, NULL },

/* --- Module Call-Completion-Operations --- --- ---                          */

  /* ccbsRequest              */ {  40, dissect_h450_9_CcRequestArg_PDU, dissect_h450_9_CcRequestRes_PDU },
  /* ccnrRequest              */ {  27, dissect_h450_9_CcRequestArg_PDU, dissect_h450_9_CcRequestRes_PDU },
  /* ccCancel                 */ {  28, dissect_h450_9_CcArg_PDU, NULL },
  /* ccExecPossible           */ {  29, dissect_h450_9_CcArg_PDU, NULL },
  /* ccRingout                */ {  31, dissect_h450_9_CcShortArg_PDU, NULL },
  /* ccSuspend                */ {  32, dissect_h450_9_CcShortArg_PDU, NULL },
  /* ccResume                 */ {  33, dissect_h450_9_CcArg_PDU, NULL },

/* --- Module Call-Offer-Operations --- --- ---                               */

  /* callOfferRequest         */ {  34, dissect_h450_10_CoReqOptArg_PDU, NULL },
  /* remoteUserAlerting       */ { 115, dissect_h450_10_RUAlertOptArg_PDU, NULL },
  /* cfbOverride              */ {  49, dissect_h450_10_CfbOvrOptArg_PDU, NULL },

/* --- Module Call-Intrusion-Operations --- --- ---                           */

  /* callIntrusionRequest     */ {  43, dissect_h450_11_CIRequestArg_PDU, dissect_h450_11_CIRequestRes_PDU },
  /* callIntrusionGetCIPL     */ {  44, dissect_h450_11_CIGetCIPLOptArg_PDU, dissect_h450_11_CIGetCIPLRes_PDU },
  /* callIntrusionIsolate     */ {  45, dissect_h450_11_CIIsOptArg_PDU, dissect_h450_11_CIIsOptRes_PDU },
  /* callIntrusionForcedRelease */ {  46, dissect_h450_11_CIFrcRelArg_PDU, dissect_h450_11_CIFrcRelOptRes_PDU },
  /* callIntrusionWOBRequest  */ {  47, dissect_h450_11_CIWobOptArg_PDU, dissect_h450_11_CIWobOptRes_PDU },
  /* callIntrusionSilentMonitor */ { 116, dissect_h450_11_CISilentArg_PDU, dissect_h450_11_CISilentOptRes_PDU },
  /* callIntrusionNotification */ { 117, dissect_h450_11_CINotificationArg_PDU, NULL },

/* --- Module Common-Information-Operations --- --- ---                       */

  /* cmnRequest               */ {  84, dissect_h450_12_DummyArg_PDU, dissect_h450_12_CmnArg_PDU },
  /* cmnInform                */ {  85, dissect_h450_12_CmnArg_PDU, NULL },

/*--- End of included file: packet-h450-table11.c ---*/
#line 83 "../../asn1/h450/packet-h450-template.c"
};

typedef struct _h450_err_t {
  gint32 errcode;
  new_dissector_t err_pdu;
} h450_err_t;

static const h450_err_t h450_err_tab[] = {

/*--- Included file: packet-h450-table21.c ---*/
#line 1 "../../asn1/h450/packet-h450-table21.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

  /* userNotSubscribed        */ {    0, NULL },
  /* rejectedByNetwork        */ {    1, NULL },
  /* rejectedByUser           */ {    2, NULL },
  /* notAvailable             */ {    3, NULL },
  /* insufficientInformation  */ {    5, NULL },
  /* invalidServedUserNumber  */ {    6, NULL },
  /* invalidCallState         */ {    7, NULL },
  /* basicServiceNotProvided  */ {    8, NULL },
  /* notIncomingCall          */ {    9, NULL },
  /* supplementaryServiceInteractionNotAllowed */ {   10, NULL },
  /* resourceUnavailable      */ {   11, NULL },
  /* callFailure              */ {   25, NULL },
  /* proceduralError          */ {   43, NULL },

/* --- Module Call-Transfer-Operations --- --- ---                            */

  /* unspecified              */ { 1008, dissect_h450_2_PAR_unspecified_PDU },
  /* invalidReroutingNumber   */ { 1004, NULL },
  /* unrecognizedCallIdentity */ { 1005, NULL },
  /* establishmentFailure     */ { 1006, NULL },

/* --- Module Call-Diversion-Operations --- --- ---                           */

  /* invalidDivertedNumber    */ {   12, NULL },
  /* specialServiceNumber     */ {   14, NULL },
  /* diversionToServedUserNumber */ {   15, NULL },
  /* numberOfDiversionsExceeded */ {   24, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* notAuthorized            */ { 1007, NULL },
  /* unspecified              */ { 1008, dissect_h450_3_PAR_unspecified_PDU },

/* --- Module Call-Hold-Operations --- --- ---                                */

  /* undefined                */ { 2002, dissect_h450_4_PAR_undefined_PDU },

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

  /* callPickupIdInvalid      */ { 2000, NULL },
  /* callAlreadyPickedUp      */ { 2001, NULL },
  /* undefined                */ { 2002, dissect_h450_5_PAR_undefined_PDU },

/* --- Module Call-Waiting-Operations --- --- ---                             */

/* Unknown or empty loop list ERROR */

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

  /* undefined                */ { 2002, dissect_h450_7_PAR_undefined_PDU },
  /* invalidMsgCentreId       */ { 1018, NULL },
  /* notActivated             */ {   31, NULL },

/* --- Module Name-Operations --- --- ---                                     */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Completion-Operations --- --- ---                          */

  /* shortTermRejection       */ { 1010, NULL },
  /* longTermRejection        */ { 1011, NULL },
  /* remoteUserBusyAgain      */ { 1012, NULL },
  /* failureToMatch           */ { 1013, NULL },

/* --- Module Call-Offer-Operations --- --- ---                               */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Intrusion-Operations --- --- ---                           */

  /* notBusy                  */ { 1009, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* notAuthorized            */ { 1007, NULL },

/* --- Module Common-Information-Operations --- --- ---                       */

/* Unknown or empty loop list ERROR */

/*--- End of included file: packet-h450-table21.c ---*/
#line 92 "../../asn1/h450/packet-h450-template.c"
};

static const h450_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(h450_op_tab) - 1; i >= 0; i--)
    if (h450_op_tab[i].opcode == opcode)
      return &h450_op_tab[i];
  return NULL;
}

static const h450_err_t *get_err(gint32 errcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(h450_err_tab) - 1; i >= 0; i--)
    if (h450_err_tab[i].errcode == errcode)
      return &h450_err_tab[i];
  return NULL;
}

/*--- dissect_h450_arg ------------------------------------------------------*/
static int
dissect_h450_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_item *hidden_item;
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode;
  const h450_op_t *op_ptr;
  const gchar *p;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  hidden_item = proto_tree_add_uint(tree, hf_h450_operation, tvb, 0, 0, opcode);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  p = try_val_to_str(opcode, VALS(h450_str_operation));
  if (p) {
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->arg_pdu && (tvb_length_remaining(tvb, offset) > 0))
    offset = op_ptr->arg_pdu(tvb, pinfo, tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (H.450)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_h450_res ------------------------------------------------------*/
static int
dissect_h450_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_item *hidden_item;
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode;
  const h450_op_t *op_ptr;
  const gchar *p;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 2)  /* returnResult */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  hidden_item = proto_tree_add_uint(tree, hf_h450_operation, tvb, 0, 0, opcode);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  p = try_val_to_str(opcode, VALS(h450_str_operation));
  if (p) {
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->res_pdu && (tvb_length_remaining(tvb, offset) > 0))
    offset = op_ptr->res_pdu(tvb, pinfo, tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (H.450)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_h450_err ------------------------------------------------------*/
static int
dissect_h450_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_item *hidden_item;
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 errcode;
  const h450_err_t *err_ptr;
  const gchar *p;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 3)  /* returnError */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  errcode = rctx->d.code_local;
  err_ptr = get_err(errcode);
  if (!err_ptr)
    return offset;

  hidden_item = proto_tree_add_uint(tree, hf_h450_error, tvb, 0, 0, errcode);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  p = try_val_to_str(errcode, VALS(h450_str_error));
  if (p) {
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu && (tvb_length_remaining(tvb, offset) > 0))
    offset = err_ptr->err_pdu(tvb, pinfo, tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(tree, tvb, offset, -1, "UNSUPPORTED ERROR TYPE (H.450)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- proto_register_h450 -------------------------------------------*/
void proto_register_h450(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_h450_operation, { "Operation", "h450.operation",
                           FT_UINT8, BASE_DEC, VALS(h450_str_operation), 0x0,
                           NULL, HFILL }},
    { &hf_h450_error,     { "Error", "h450.error",
                           FT_UINT8, BASE_DEC, VALS(h450_str_error), 0x0,
                           NULL, HFILL }},

/*--- Included file: packet-h450-hfarr.c ---*/
#line 1 "../../asn1/h450/packet-h450-hfarr.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

    { &hf_h450_h450_H4501SupplementaryService_PDU,
      { "H4501SupplementaryService", "h450.H4501SupplementaryService_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_networkFacilityExtension,
      { "networkFacilityExtension", "h450.networkFacilityExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_interpretationApdu,
      { "interpretationApdu", "h450.interpretationApdu",
        FT_UINT32, BASE_DEC, VALS(h450_InterpretationApdu_vals), 0,
        NULL, HFILL }},
    { &hf_h450_serviceApdu,
      { "serviceApdu", "h450.serviceApdu",
        FT_UINT32, BASE_DEC, VALS(h450_ServiceApdus_vals), 0,
        "ServiceApdus", HFILL }},
    { &hf_h450_sourceEntity,
      { "sourceEntity", "h450.sourceEntity",
        FT_UINT32, BASE_DEC, VALS(h450_EntityType_vals), 0,
        "EntityType", HFILL }},
    { &hf_h450_sourceEntityAddress,
      { "sourceEntityAddress", "h450.sourceEntityAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AddressInformation", HFILL }},
    { &hf_h450_destinationEntity,
      { "destinationEntity", "h450.destinationEntity",
        FT_UINT32, BASE_DEC, VALS(h450_EntityType_vals), 0,
        "EntityType", HFILL }},
    { &hf_h450_destinationEntityAddress,
      { "destinationEntityAddress", "h450.destinationEntityAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AddressInformation", HFILL }},
    { &hf_h450_endpoint,
      { "endpoint", "h450.endpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_anyEntity,
      { "anyEntity", "h450.anyEntity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_discardAnyUnrecognizedInvokePdu,
      { "discardAnyUnrecognizedInvokePdu", "h450.discardAnyUnrecognizedInvokePdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_clearCallIfAnyInvokePduNotRecognized,
      { "clearCallIfAnyInvokePduNotRecognized", "h450.clearCallIfAnyInvokePduNotRecognized_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_rejectAnyUnrecognizedInvokePdu,
      { "rejectAnyUnrecognizedInvokePdu", "h450.rejectAnyUnrecognizedInvokePdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_rosApdus,
      { "rosApdus", "h450.rosApdus",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_rosApdus_item,
      { "rosApdus item", "h450.rosApdus_item",
        FT_UINT32, BASE_DEC, VALS(h450_ros_ROS_vals), 0,
        NULL, HFILL }},
    { &hf_h450_destinationAddress,
      { "destinationAddress", "h450.destinationAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AliasAddress", HFILL }},
    { &hf_h450_destinationAddress_item,
      { "AliasAddress", "h450.AliasAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h450_remoteExtensionAddress,
      { "remoteExtensionAddress", "h450.remoteExtensionAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AliasAddress", HFILL }},
    { &hf_h450_destinationAddressPresentationIndicator,
      { "destinationAddressPresentationIndicator", "h450.destinationAddressPresentationIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_PresentationIndicator_vals), 0,
        "PresentationIndicator", HFILL }},
    { &hf_h450_destinationAddressScreeningIndicator,
      { "destinationAddressScreeningIndicator", "h450.destinationAddressScreeningIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_ScreeningIndicator_vals), 0,
        "ScreeningIndicator", HFILL }},
    { &hf_h450_remoteExtensionAddressPresentationIndicator,
      { "remoteExtensionAddressPresentationIndicator", "h450.remoteExtensionAddressPresentationIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_PresentationIndicator_vals), 0,
        "PresentationIndicator", HFILL }},
    { &hf_h450_remoteExtensionAddressScreeningIndicator,
      { "remoteExtensionAddressScreeningIndicator", "h450.remoteExtensionAddressScreeningIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_ScreeningIndicator_vals), 0,
        "ScreeningIndicator", HFILL }},
    { &hf_h450_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "h450.userSpecifiedSubaddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_nsapSubaddress,
      { "nsapSubaddress", "h450.nsapSubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_subaddressInformation,
      { "subaddressInformation", "h450.subaddressInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_oddCountIndicator,
      { "oddCountIndicator", "h450.oddCountIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h450_extensionId,
      { "extensionId", "h450.extensionId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h450_extensionArgument,
      { "extensionArgument", "h450.extensionArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Transfer-Operations --- --- ---                            */

    { &hf_h450_2_h450_2_DummyArg_PDU,
      { "DummyArg", "h450.2.DummyArg",
        FT_UINT32, BASE_DEC, VALS(h450_2_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_CTIdentifyRes_PDU,
      { "CTIdentifyRes", "h450.2.CTIdentifyRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_CTInitiateArg_PDU,
      { "CTInitiateArg", "h450.2.CTInitiateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_DummyRes_PDU,
      { "DummyRes", "h450.2.DummyRes",
        FT_UINT32, BASE_DEC, VALS(h450_2_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_CTSetupArg_PDU,
      { "CTSetupArg", "h450.2.CTSetupArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_CTUpdateArg_PDU,
      { "CTUpdateArg", "h450.2.CTUpdateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_SubaddressTransferArg_PDU,
      { "SubaddressTransferArg", "h450.2.SubaddressTransferArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_CTCompleteArg_PDU,
      { "CTCompleteArg", "h450.2.CTCompleteArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_CTActiveArg_PDU,
      { "CTActiveArg", "h450.2.CTActiveArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_h450_2_PAR_unspecified_PDU,
      { "PAR-unspecified", "h450.2.PAR_unspecified",
        FT_UINT32, BASE_DEC, VALS(h450_2_PAR_unspecified_vals), 0,
        NULL, HFILL }},
    { &hf_h450_2_extensionSeq,
      { "extensionSeq", "h450.2.extensionSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_nonStandardData,
      { "nonStandardData", "h450.2.nonStandardData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h450_2_callIdentity,
      { "callIdentity", "h450.2.callIdentity",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_reroutingNumber,
      { "reroutingNumber", "h450.2.reroutingNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_2_cTInitiateArg_argumentExtension,
      { "argumentExtension", "h450.2.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_cTInitiateArg_argumentExtension_vals), 0,
        "T_cTInitiateArg_argumentExtension", HFILL }},
    { &hf_h450_2_transferringNumber,
      { "transferringNumber", "h450.2.transferringNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_2_cTSetupArg_argumentExtension,
      { "argumentExtension", "h450.2.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_cTSetupArg_argumentExtension_vals), 0,
        "T_cTSetupArg_argumentExtension", HFILL }},
    { &hf_h450_2_resultExtension,
      { "resultExtension", "h450.2.resultExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_resultExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_2_redirectionNumber,
      { "redirectionNumber", "h450.2.redirectionNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_2_redirectionInfo,
      { "redirectionInfo", "h450.2.redirectionInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_2_basicCallInfoElements,
      { "basicCallInfoElements", "h450.2.basicCallInfoElements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "H225InformationElement", HFILL }},
    { &hf_h450_2_cTUpdateArg_argumentExtension,
      { "argumentExtension", "h450.2.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_cTUpdateArg_argumentExtension_vals), 0,
        "T_cTUpdateArg_argumentExtension", HFILL }},
    { &hf_h450_2_redirectionSubaddress,
      { "redirectionSubaddress", "h450.2.redirectionSubaddress",
        FT_UINT32, BASE_DEC, VALS(h450_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_h450_2_subaddressTransferArg_argumentExtension,
      { "argumentExtension", "h450.2.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_subaddressTransferArg_argumentExtension_vals), 0,
        "T_subaddressTransferArg_argumentExtension", HFILL }},
    { &hf_h450_2_endDesignation,
      { "endDesignation", "h450.2.endDesignation",
        FT_UINT32, BASE_DEC, VALS(h450_2_EndDesignation_vals), 0,
        NULL, HFILL }},
    { &hf_h450_2_callStatus,
      { "callStatus", "h450.2.callStatus",
        FT_UINT32, BASE_DEC, VALS(h450_2_CallStatus_vals), 0,
        NULL, HFILL }},
    { &hf_h450_2_cTCompleteArg_argumentExtension,
      { "argumentExtension", "h450.2.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_cTCompleteArg_argumentExtension_vals), 0,
        "T_cTCompleteArg_argumentExtension", HFILL }},
    { &hf_h450_2_connectedAddress,
      { "connectedAddress", "h450.2.connectedAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_2_connectedInfo,
      { "connectedInfo", "h450.2.connectedInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_2_cTActiveArg_argumentExtension,
      { "argumentExtension", "h450.2.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_2_T_cTActiveArg_argumentExtension_vals), 0,
        "T_cTActiveArg_argumentExtension", HFILL }},
    { &hf_h450_2_ExtensionSeq_item,
      { "Extension", "h450.2.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_unspecified_extension,
      { "extension", "h450.2.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_2_nonStandard,
      { "nonStandard", "h450.2.nonStandard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},

/* --- Module Call-Diversion-Operations --- --- ---                           */

    { &hf_h450_3_h450_3_ARG_activateDiversionQ_PDU,
      { "ARG-activateDiversionQ", "h450.3.ARG_activateDiversionQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_RES_activateDiversionQ_PDU,
      { "RES-activateDiversionQ", "h450.3.RES_activateDiversionQ",
        FT_UINT32, BASE_DEC, VALS(h450_3_RES_activateDiversionQ_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_deactivateDiversionQ_PDU,
      { "ARG-deactivateDiversionQ", "h450.3.ARG_deactivateDiversionQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_RES_deactivateDiversionQ_PDU,
      { "RES-deactivateDiversionQ", "h450.3.RES_deactivateDiversionQ",
        FT_UINT32, BASE_DEC, VALS(h450_3_RES_deactivateDiversionQ_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_interrogateDiversionQ_PDU,
      { "ARG-interrogateDiversionQ", "h450.3.ARG_interrogateDiversionQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_IntResultList_PDU,
      { "IntResultList", "h450.3.IntResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_checkRestriction_PDU,
      { "ARG-checkRestriction", "h450.3.ARG_checkRestriction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_RES_checkRestriction_PDU,
      { "RES-checkRestriction", "h450.3.RES_checkRestriction",
        FT_UINT32, BASE_DEC, VALS(h450_3_RES_checkRestriction_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_callRerouting_PDU,
      { "ARG-callRerouting", "h450.3.ARG_callRerouting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_RES_callRerouting_PDU,
      { "RES-callRerouting", "h450.3.RES_callRerouting",
        FT_UINT32, BASE_DEC, VALS(h450_3_RES_callRerouting_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_divertingLegInformation1_PDU,
      { "ARG-divertingLegInformation1", "h450.3.ARG_divertingLegInformation1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_divertingLegInformation2_PDU,
      { "ARG-divertingLegInformation2", "h450.3.ARG_divertingLegInformation2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_divertingLegInformation3_PDU,
      { "ARG-divertingLegInformation3", "h450.3.ARG_divertingLegInformation3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_divertingLegInformation4_PDU,
      { "ARG-divertingLegInformation4", "h450.3.ARG_divertingLegInformation4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_ARG_cfnrDivertedLegFailed_PDU,
      { "ARG-cfnrDivertedLegFailed", "h450.3.ARG_cfnrDivertedLegFailed",
        FT_UINT32, BASE_DEC, VALS(h450_3_ARG_cfnrDivertedLegFailed_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_h450_3_PAR_unspecified_PDU,
      { "PAR-unspecified", "h450.3.PAR_unspecified",
        FT_UINT32, BASE_DEC, VALS(h450_3_PAR_unspecified_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_procedure,
      { "procedure", "h450.3.procedure",
        FT_UINT32, BASE_DEC, VALS(h450_3_Procedure_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_basicService,
      { "basicService", "h450.3.basicService",
        FT_UINT32, BASE_DEC, VALS(h450_3_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_divertedToAddress,
      { "divertedToAddress", "h450.3.divertedToAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_servedUserNr,
      { "servedUserNr", "h450.3.servedUserNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_activatingUserNr,
      { "activatingUserNr", "h450.3.activatingUserNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_activateDiversionQArg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_ActivateDiversionQArg_extension_vals), 0,
        "ActivateDiversionQArg_extension", HFILL }},
    { &hf_h450_3_extensionSeq,
      { "extensionSeq", "h450.3.extensionSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_nonStandardData,
      { "nonStandardData", "h450.3.nonStandardData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h450_3_deactivatingUserNr,
      { "deactivatingUserNr", "h450.3.deactivatingUserNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_deactivateDiversionQArg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_DeactivateDiversionQArg_extension_vals), 0,
        "DeactivateDiversionQArg_extension", HFILL }},
    { &hf_h450_3_interrogatingUserNr,
      { "interrogatingUserNr", "h450.3.interrogatingUserNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_interrogateDiversionQ_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_InterrogateDiversionQ_extension_vals), 0,
        "InterrogateDiversionQ_extension", HFILL }},
    { &hf_h450_3_divertedToNr,
      { "divertedToNr", "h450.3.divertedToNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_checkRestrictionArg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_CheckRestrictionArg_extension_vals), 0,
        "CheckRestrictionArg_extension", HFILL }},
    { &hf_h450_3_reroutingReason,
      { "reroutingReason", "h450.3.reroutingReason",
        FT_UINT32, BASE_DEC, VALS(h450_3_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_h450_3_originalReroutingReason,
      { "originalReroutingReason", "h450.3.originalReroutingReason",
        FT_UINT32, BASE_DEC, VALS(h450_3_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_h450_3_calledAddress,
      { "calledAddress", "h450.3.calledAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_diversionCounter,
      { "diversionCounter", "h450.3.diversionCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15", HFILL }},
    { &hf_h450_3_h225InfoElement,
      { "h225InfoElement", "h450.3.h225InfoElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "H225InformationElement", HFILL }},
    { &hf_h450_3_lastReroutingNr,
      { "lastReroutingNr", "h450.3.lastReroutingNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_subscriptionOption,
      { "subscriptionOption", "h450.3.subscriptionOption",
        FT_UINT32, BASE_DEC, VALS(h450_3_SubscriptionOption_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_callingPartySubaddress,
      { "callingPartySubaddress", "h450.3.callingPartySubaddress",
        FT_UINT32, BASE_DEC, VALS(h450_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_h450_3_callingNumber,
      { "callingNumber", "h450.3.callingNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_callingInfo,
      { "callingInfo", "h450.3.callingInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_3_originalCalledNr,
      { "originalCalledNr", "h450.3.originalCalledNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_redirectingInfo,
      { "redirectingInfo", "h450.3.redirectingInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_3_originalCalledInfo,
      { "originalCalledInfo", "h450.3.originalCalledInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_3_callReroutingArg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_CallReroutingArg_extension_vals), 0,
        "CallReroutingArg_extension", HFILL }},
    { &hf_h450_3_diversionReason,
      { "diversionReason", "h450.3.diversionReason",
        FT_UINT32, BASE_DEC, VALS(h450_3_DiversionReason_vals), 0,
        NULL, HFILL }},
    { &hf_h450_3_nominatedNr,
      { "nominatedNr", "h450.3.nominatedNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_nominatedInfo,
      { "nominatedInfo", "h450.3.nominatedInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_3_redirectingNr,
      { "redirectingNr", "h450.3.redirectingNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_divertingLegInformation1Arg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_DivertingLegInformation1Arg_extension_vals), 0,
        "DivertingLegInformation1Arg_extension", HFILL }},
    { &hf_h450_3_originalDiversionReason,
      { "originalDiversionReason", "h450.3.originalDiversionReason",
        FT_UINT32, BASE_DEC, VALS(h450_3_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_h450_3_divertingNr,
      { "divertingNr", "h450.3.divertingNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_divertingLegInformation2Arg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_DivertingLegInformation2Arg_extension_vals), 0,
        "DivertingLegInformation2Arg_extension", HFILL }},
    { &hf_h450_3_presentationAllowedIndicator,
      { "presentationAllowedIndicator", "h450.3.presentationAllowedIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_redirectionNr,
      { "redirectionNr", "h450.3.redirectionNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_redirectionInfo,
      { "redirectionInfo", "h450.3.redirectionInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString_SIZE_1_128", HFILL }},
    { &hf_h450_3_divertingLegInformation3Arg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_DivertingLegInformation3Arg_extension_vals), 0,
        "DivertingLegInformation3Arg_extension", HFILL }},
    { &hf_h450_3_callingNr,
      { "callingNr", "h450.3.callingNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_3_divertingLegInformation4Arg_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_DivertingLegInformation4Arg_extension_vals), 0,
        "DivertingLegInformation4Arg_extension", HFILL }},
    { &hf_h450_3_IntResultList_item,
      { "IntResult", "h450.3.IntResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_remoteEnabled,
      { "remoteEnabled", "h450.3.remoteEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h450_3_intResult_extension,
      { "extension", "h450.3.extension",
        FT_UINT32, BASE_DEC, VALS(h450_3_IntResult_extension_vals), 0,
        "IntResult_extension", HFILL }},
    { &hf_h450_3_unspecified_extension,
      { "extension", "h450.3.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_3_nonStandard,
      { "nonStandard", "h450.3.nonStandard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h450_3_ExtensionSeq_item,
      { "Extension", "h450.3.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Hold-Operations --- --- ---                                */

    { &hf_h450_4_h450_4_HoldNotificArg_PDU,
      { "HoldNotificArg", "h450.4.HoldNotificArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_h450_4_RetrieveNotificArg_PDU,
      { "RetrieveNotificArg", "h450.4.RetrieveNotificArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_h450_4_RemoteHoldArg_PDU,
      { "RemoteHoldArg", "h450.4.RemoteHoldArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_h450_4_RemoteHoldRes_PDU,
      { "RemoteHoldRes", "h450.4.RemoteHoldRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_h450_4_RemoteRetrieveArg_PDU,
      { "RemoteRetrieveArg", "h450.4.RemoteRetrieveArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_h450_4_RemoteRetrieveRes_PDU,
      { "RemoteRetrieveRes", "h450.4.RemoteRetrieveRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_h450_4_PAR_undefined_PDU,
      { "PAR-undefined", "h450.4.PAR_undefined",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_holdNotificArg_extensionArg,
      { "extensionArg", "h450.4.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_4_holdNotificArg_extensionArg_item,
      { "MixedExtension", "h450.4.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_4_retrieveNotificArg_extensionArg,
      { "extensionArg", "h450.4.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_4_retrieveNotificArg_extensionArg_item,
      { "MixedExtension", "h450.4.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_4_remoteHoldArg_extensionArg,
      { "extensionArg", "h450.4.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_4_remoteHoldArg_extensionArg_item,
      { "MixedExtension", "h450.4.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_4_extensionRes,
      { "extensionRes", "h450.4.extensionRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_4_extensionRes_item,
      { "MixedExtension", "h450.4.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_4_remoteRetrieveArg_extensionArg,
      { "extensionArg", "h450.4.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_4_remoteRetrieveArg_extensionArg_item,
      { "MixedExtension", "h450.4.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_4_mixedExtension_extension,
      { "extension", "h450.4.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_4_nonStandardData,
      { "nonStandardData", "h450.4.nonStandardData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h450_4_PAR_undefined_item,
      { "MixedExtension", "h450.4.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

    { &hf_h450_5_h450_5_CpRequestArg_PDU,
      { "CpRequestArg", "h450.5.CpRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_CpRequestRes_PDU,
      { "CpRequestRes", "h450.5.CpRequestRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_CpSetupArg_PDU,
      { "CpSetupArg", "h450.5.CpSetupArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_CpSetupRes_PDU,
      { "CpSetupRes", "h450.5.CpSetupRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_GroupIndicationOnArg_PDU,
      { "GroupIndicationOnArg", "h450.5.GroupIndicationOnArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_GroupIndicationOnRes_PDU,
      { "GroupIndicationOnRes", "h450.5.GroupIndicationOnRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_GroupIndicationOffArg_PDU,
      { "GroupIndicationOffArg", "h450.5.GroupIndicationOffArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_GroupIndicationOffRes_PDU,
      { "GroupIndicationOffRes", "h450.5.GroupIndicationOffRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PickrequArg_PDU,
      { "PickrequArg", "h450.5.PickrequArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PickrequRes_PDU,
      { "PickrequRes", "h450.5.PickrequRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PickupArg_PDU,
      { "PickupArg", "h450.5.PickupArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PickupRes_PDU,
      { "PickupRes", "h450.5.PickupRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PickExeArg_PDU,
      { "PickExeArg", "h450.5.PickExeArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PickExeRes_PDU,
      { "PickExeRes", "h450.5.PickExeRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_CpNotifyArg_PDU,
      { "CpNotifyArg", "h450.5.CpNotifyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_CpickupNotifyArg_PDU,
      { "CpickupNotifyArg", "h450.5.CpickupNotifyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_h450_5_PAR_undefined_PDU,
      { "PAR-undefined", "h450.5.PAR_undefined",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_parkingNumber,
      { "parkingNumber", "h450.5.parkingNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_parkedNumber,
      { "parkedNumber", "h450.5.parkedNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_parkedToNumber,
      { "parkedToNumber", "h450.5.parkedToNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_parkedToPosition,
      { "parkedToPosition", "h450.5.parkedToPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_5_cpRequestArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_cpRequestArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_parkCondition,
      { "parkCondition", "h450.5.parkCondition",
        FT_UINT32, BASE_DEC, VALS(h450_5_ParkCondition_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_extensionRes,
      { "extensionRes", "h450.5.extensionRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_extensionRes_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_cpSetupArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_cpSetupArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_callPickupId,
      { "callPickupId", "h450.5.callPickupId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentifier", HFILL }},
    { &hf_h450_5_groupMemberUserNr,
      { "groupMemberUserNr", "h450.5.groupMemberUserNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_retrieveCallType,
      { "retrieveCallType", "h450.5.retrieveCallType",
        FT_UINT32, BASE_DEC, VALS(h450_5_CallType_vals), 0,
        "CallType", HFILL }},
    { &hf_h450_5_partyToRetrieve,
      { "partyToRetrieve", "h450.5.partyToRetrieve_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_retrieveAddress,
      { "retrieveAddress", "h450.5.retrieveAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_parkPosition,
      { "parkPosition", "h450.5.parkPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ParkedToPosition", HFILL }},
    { &hf_h450_5_groupIndicationOnArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_groupIndicationOnArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_groupIndicationOffArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_groupIndicationOffArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_picking_upNumber,
      { "picking-upNumber", "h450.5.picking_upNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_5_pickrequArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_pickrequArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_pickupArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_pickupArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_pickExeArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_pickExeArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_cpNotifyArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_cpNotifyArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_cpickupNotifyArg_extensionArg,
      { "extensionArg", "h450.5.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_5_cpickupNotifyArg_extensionArg_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_5_PAR_undefined_item,
      { "MixedExtension", "h450.5.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},

/* --- Module Call-Waiting-Operations --- --- ---                             */

    { &hf_h450_6_h450_6_CallWaitingArg_PDU,
      { "CallWaitingArg", "h450.6.CallWaitingArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_6_nbOfAddWaitingCalls,
      { "nbOfAddWaitingCalls", "h450.6.nbOfAddWaitingCalls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h450_6_callWaitingArg_extensionArg,
      { "extensionArg", "h450.6.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_6_callWaitingArg_extensionArg_item,
      { "MixedExtension", "h450.6.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

    { &hf_h450_7_h450_7_MWIActivateArg_PDU,
      { "MWIActivateArg", "h450.7.MWIActivateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_h450_7_DummyRes_PDU,
      { "DummyRes", "h450.7.DummyRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_h450_7_MWIDeactivateArg_PDU,
      { "MWIDeactivateArg", "h450.7.MWIDeactivateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_h450_7_MWIInterrogateArg_PDU,
      { "MWIInterrogateArg", "h450.7.MWIInterrogateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_h450_7_MWIInterrogateRes_PDU,
      { "MWIInterrogateRes", "h450.7.MWIInterrogateRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_h450_7_PAR_undefined_PDU,
      { "PAR-undefined", "h450.7.PAR_undefined",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_servedUserNr,
      { "servedUserNr", "h450.7.servedUserNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_7_basicService,
      { "basicService", "h450.7.basicService",
        FT_UINT32, BASE_DEC, VALS(h450_7_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_msgCentreId,
      { "msgCentreId", "h450.7.msgCentreId",
        FT_UINT32, BASE_DEC, VALS(h450_7_MsgCentreId_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_nbOfMessages,
      { "nbOfMessages", "h450.7.nbOfMessages",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_originatingNr,
      { "originatingNr", "h450.7.originatingNr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_7_timestamp,
      { "timestamp", "h450.7.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_priority,
      { "priority", "h450.7.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_h450_7_mWIActivateArg_extensionArg,
      { "extensionArg", "h450.7.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_7_mWIActivateArg_extensionArg_item,
      { "MixedExtension", "h450.7.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_DummyRes_item,
      { "MixedExtension", "h450.7.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_callbackReq,
      { "callbackReq", "h450.7.callbackReq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h450_7_mWIDeactivateArg_extensionArg,
      { "extensionArg", "h450.7.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_7_mWIDeactivateArg_extensionArg_item,
      { "MixedExtension", "h450.7.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_mWIInterrogateArg_extensionArg,
      { "extensionArg", "h450.7.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_7_mWIInterrogateArg_extensionArg_item,
      { "MixedExtension", "h450.7.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_MWIInterrogateRes_item,
      { "MWIInterrogateResElt", "h450.7.MWIInterrogateResElt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_7_mWIInterrogateResElt_extensionArg,
      { "extensionArg", "h450.7.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_7_mWIInterrogateResElt_extensionArg_item,
      { "MixedExtension", "h450.7.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_7_integer,
      { "integer", "h450.7.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h450_7_partyNumber,
      { "partyNumber", "h450.7.partyNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_7_numericString,
      { "numericString", "h450.7.numericString",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_1_10", HFILL }},
    { &hf_h450_7_PAR_undefined_item,
      { "MixedExtension", "h450.7.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},

/* --- Module Name-Operations --- --- ---                                     */

    { &hf_h450_8_h450_8_ARG_callingName_PDU,
      { "ARG-callingName", "h450.8.ARG_callingName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_h450_8_ARG_alertingName_PDU,
      { "ARG-alertingName", "h450.8.ARG_alertingName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_h450_8_ARG_connectedName_PDU,
      { "ARG-connectedName", "h450.8.ARG_connectedName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_h450_8_ARG_busyName_PDU,
      { "ARG-busyName", "h450.8.ARG_busyName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_name,
      { "name", "h450.8.name",
        FT_UINT32, BASE_DEC, VALS(h450_8_Name_vals), 0,
        NULL, HFILL }},
    { &hf_h450_8_extensionArg,
      { "extensionArg", "h450.8.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_8_extensionArg_item,
      { "MixedExtension", "h450.8.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_8_namePresentationAllowed,
      { "namePresentationAllowed", "h450.8.namePresentationAllowed",
        FT_UINT32, BASE_DEC, VALS(h450_8_NamePresentationAllowed_vals), 0,
        NULL, HFILL }},
    { &hf_h450_8_namePresentationRestricted,
      { "namePresentationRestricted", "h450.8.namePresentationRestricted",
        FT_UINT32, BASE_DEC, VALS(h450_8_NamePresentationRestricted_vals), 0,
        NULL, HFILL }},
    { &hf_h450_8_nameNotAvailable,
      { "nameNotAvailable", "h450.8.nameNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_simpleName,
      { "simpleName", "h450.8.simpleName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_extendedName,
      { "extendedName", "h450.8.extendedName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_8_restrictedNull,
      { "restrictedNull", "h450.8.restrictedNull_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Completion-Operations --- --- ---                          */

    { &hf_h450_9_h450_9_CcRequestArg_PDU,
      { "CcRequestArg", "h450.9.CcRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_9_h450_9_CcRequestRes_PDU,
      { "CcRequestRes", "h450.9.CcRequestRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_9_h450_9_CcArg_PDU,
      { "CcArg", "h450.9.CcArg",
        FT_UINT32, BASE_DEC, VALS(h450_9_CcArg_vals), 0,
        NULL, HFILL }},
    { &hf_h450_9_h450_9_CcShortArg_PDU,
      { "CcShortArg", "h450.9.CcShortArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_9_numberA,
      { "numberA", "h450.9.numberA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_9_numberB,
      { "numberB", "h450.9.numberB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointAddress", HFILL }},
    { &hf_h450_9_ccIdentifier,
      { "ccIdentifier", "h450.9.ccIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentifier", HFILL }},
    { &hf_h450_9_service,
      { "service", "h450.9.service",
        FT_UINT32, BASE_DEC, VALS(h450_7_BasicService_vals), 0,
        "BasicService", HFILL }},
    { &hf_h450_9_can_retain_service,
      { "can-retain-service", "h450.9.can_retain_service",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h450_9_retain_sig_connection,
      { "retain-sig-connection", "h450.9.retain_sig_connection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h450_9_ccRequestArg_extension,
      { "extension", "h450.9.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_9_ccRequestArg_extension_item,
      { "MixedExtension", "h450.9.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_9_retain_service,
      { "retain-service", "h450.9.retain_service",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h450_9_ccRequestRes_extension,
      { "extension", "h450.9.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_9_ccRequestRes_extension_item,
      { "MixedExtension", "h450.9.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_9_shortArg,
      { "shortArg", "h450.9.shortArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CcShortArg", HFILL }},
    { &hf_h450_9_longArg,
      { "longArg", "h450.9.longArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CcLongArg", HFILL }},
    { &hf_h450_9_ccShortArg_extension,
      { "extension", "h450.9.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_9_ccShortArg_extension_item,
      { "MixedExtension", "h450.9.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_9_ccLongArg_extension,
      { "extension", "h450.9.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_9_ccLongArg_extension_item,
      { "MixedExtension", "h450.9.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},

/* --- Module Call-Offer-Operations --- --- ---                               */

    { &hf_h450_10_h450_10_CoReqOptArg_PDU,
      { "CoReqOptArg", "h450.10.CoReqOptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_10_h450_10_RUAlertOptArg_PDU,
      { "RUAlertOptArg", "h450.10.RUAlertOptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_10_h450_10_CfbOvrOptArg_PDU,
      { "CfbOvrOptArg", "h450.10.CfbOvrOptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_10_coReqOptArg_extension,
      { "extension", "h450.10.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_10_coReqOptArg_extension_item,
      { "MixedExtension", "h450.10.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_10_rUAlertOptArg_extension,
      { "extension", "h450.10.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_10_rUAlertOptArg_extension_item,
      { "MixedExtension", "h450.10.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_10_cfbOvrOptArg_extension,
      { "extension", "h450.10.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_10_cfbOvrOptArg_extension_item,
      { "MixedExtension", "h450.10.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},

/* --- Module Call-Intrusion-Operations --- --- ---                           */

    { &hf_h450_11_h450_11_CIRequestArg_PDU,
      { "CIRequestArg", "h450.11.CIRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIRequestRes_PDU,
      { "CIRequestRes", "h450.11.CIRequestRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIGetCIPLOptArg_PDU,
      { "CIGetCIPLOptArg", "h450.11.CIGetCIPLOptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIGetCIPLRes_PDU,
      { "CIGetCIPLRes", "h450.11.CIGetCIPLRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIIsOptArg_PDU,
      { "CIIsOptArg", "h450.11.CIIsOptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIIsOptRes_PDU,
      { "CIIsOptRes", "h450.11.CIIsOptRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIFrcRelArg_PDU,
      { "CIFrcRelArg", "h450.11.CIFrcRelArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIFrcRelOptRes_PDU,
      { "CIFrcRelOptRes", "h450.11.CIFrcRelOptRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIWobOptArg_PDU,
      { "CIWobOptArg", "h450.11.CIWobOptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CIWobOptRes_PDU,
      { "CIWobOptRes", "h450.11.CIWobOptRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CISilentArg_PDU,
      { "CISilentArg", "h450.11.CISilentArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CISilentOptRes_PDU,
      { "CISilentOptRes", "h450.11.CISilentOptRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_h450_11_CINotificationArg_PDU,
      { "CINotificationArg", "h450.11.CINotificationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_ciCapabilityLevel,
      { "ciCapabilityLevel", "h450.11.ciCapabilityLevel",
        FT_UINT32, BASE_DEC, VALS(h450_11_CICapabilityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIRequestArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIRequestArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_ciStatusInformation,
      { "ciStatusInformation", "h450.11.ciStatusInformation",
        FT_UINT32, BASE_DEC, VALS(h450_11_CIStatusInformation_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIRequestRes_resultExtension,
      { "resultExtension", "h450.11.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIRequestRes_resultExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIGetCIPLOptArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIGetCIPLOptArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_ciProtectionLevel,
      { "ciProtectionLevel", "h450.11.ciProtectionLevel",
        FT_UINT32, BASE_DEC, VALS(h450_11_CIProtectionLevel_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_silentMonitoringPermitted,
      { "silentMonitoringPermitted", "h450.11.silentMonitoringPermitted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_cIGetCIPLRes_resultExtension,
      { "resultExtension", "h450.11.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIGetCIPLRes_resultExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIIsOptArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIIsOptArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIIsOptRes_resultExtension,
      { "resultExtension", "h450.11.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIIsOptRes_resultExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIFrcRelArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIFrcRelArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIFrcRelOptRes_resultExtension,
      { "resultExtension", "h450.11.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIFrcRelOptRes_resultExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIWobOptArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIWobOptArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cIWobOptRes_resultExtension,
      { "resultExtension", "h450.11.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cIWobOptRes_resultExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_specificCall,
      { "specificCall", "h450.11.specificCall_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentifier", HFILL }},
    { &hf_h450_11_cISilentArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cISilentArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cISilentOptRes_resultExtension,
      { "resultExtension", "h450.11.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cISilentOptRes_resultExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_cINotificationArg_argumentExtension,
      { "argumentExtension", "h450.11.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_11_cINotificationArg_argumentExtension_item,
      { "MixedExtension", "h450.11.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_11_callIntrusionImpending,
      { "callIntrusionImpending", "h450.11.callIntrusionImpending_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_callIntruded,
      { "callIntruded", "h450.11.callIntruded_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_callIsolated,
      { "callIsolated", "h450.11.callIsolated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_callForceReleased,
      { "callForceReleased", "h450.11.callForceReleased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_callIntrusionComplete,
      { "callIntrusionComplete", "h450.11.callIntrusionComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_11_callIntrusionEnd,
      { "callIntrusionEnd", "h450.11.callIntrusionEnd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Common-Information-Operations --- --- ---                       */

    { &hf_h450_12_h450_12_DummyArg_PDU,
      { "DummyArg", "h450.12.DummyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_h450_12_CmnArg_PDU,
      { "CmnArg", "h450.12.CmnArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_featureList,
      { "featureList", "h450.12.featureList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_featureValues,
      { "featureValues", "h450.12.featureValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_featureControl,
      { "featureControl", "h450.12.featureControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_cmnArg_extension,
      { "extension", "h450.12.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_12_cmnArg_extension_item,
      { "MixedExtension", "h450.12.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_12_extensionArg,
      { "extensionArg", "h450.12.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_255_OF_MixedExtension", HFILL }},
    { &hf_h450_12_extensionArg_item,
      { "MixedExtension", "h450.12.MixedExtension",
        FT_UINT32, BASE_DEC, VALS(h450_4_MixedExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCFreRoutingSupported,
      { "ssCFreRoutingSupported", "h450.12.ssCFreRoutingSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCTreRoutingSupported,
      { "ssCTreRoutingSupported", "h450.12.ssCTreRoutingSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCCBSPossible,
      { "ssCCBSPossible", "h450.12.ssCCBSPossible_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCCNRPossible,
      { "ssCCNRPossible", "h450.12.ssCCNRPossible_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCOSupported,
      { "ssCOSupported", "h450.12.ssCOSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCIForcedReleaseSupported,
      { "ssCIForcedReleaseSupported", "h450.12.ssCIForcedReleaseSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCIIsolationSupported,
      { "ssCIIsolationSupported", "h450.12.ssCIIsolationSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCIWaitOnBusySupported,
      { "ssCIWaitOnBusySupported", "h450.12.ssCIWaitOnBusySupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCISilentMonitoringSupported,
      { "ssCISilentMonitoringSupported", "h450.12.ssCISilentMonitoringSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCIConferenceSupported,
      { "ssCIConferenceSupported", "h450.12.ssCIConferenceSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCHFarHoldSupported,
      { "ssCHFarHoldSupported", "h450.12.ssCHFarHoldSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssMWICallbackSupported,
      { "ssMWICallbackSupported", "h450.12.ssMWICallbackSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCPCallParkSupported,
      { "ssCPCallParkSupported", "h450.12.ssCPCallParkSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_partyCategory,
      { "partyCategory", "h450.12.partyCategory",
        FT_UINT32, BASE_DEC, VALS(h450_12_PartyCategory_vals), 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCIprotectionLevel,
      { "ssCIprotectionLevel", "h450.12.ssCIprotectionLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCHDoNotHold,
      { "ssCHDoNotHold", "h450.12.ssCHDoNotHold_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCTDoNotTransfer,
      { "ssCTDoNotTransfer", "h450.12.ssCTDoNotTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssMWICallbackCall,
      { "ssMWICallbackCall", "h450.12.ssMWICallbackCall_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_12_ssCISilentMonitorPermitted,
      { "ssCISilentMonitorPermitted", "h450.12.ssCISilentMonitorPermitted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-h450-hfarr.c ---*/
#line 261 "../../asn1/h450/packet-h450-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-h450-ettarr.c ---*/
#line 1 "../../asn1/h450/packet-h450-ettarr.c"

/* --- Modules H4501-Supplementary-ServiceAPDU-Structure Addressing-Data-Elements H225-generic-parameters-definition Manufacturer-specific-service-extension-definition H4501-General-Error-List --- --- --- */

    &ett_h450_H4501SupplementaryService,
    &ett_h450_NetworkFacilityExtension,
    &ett_h450_EntityType,
    &ett_h450_InterpretationApdu,
    &ett_h450_ServiceApdus,
    &ett_h450_T_rosApdus,
    &ett_h450_EndpointAddress,
    &ett_h450_SEQUENCE_OF_AliasAddress,
    &ett_h450_PartySubaddress,
    &ett_h450_UserSpecifiedSubaddress,
    &ett_h450_Extension,

/* --- Module Call-Transfer-Operations --- --- ---                            */

    &ett_h450_2_DummyArg,
    &ett_h450_2_DummyRes,
    &ett_h450_2_CTInitiateArg,
    &ett_h450_2_T_cTInitiateArg_argumentExtension,
    &ett_h450_2_CTSetupArg,
    &ett_h450_2_T_cTSetupArg_argumentExtension,
    &ett_h450_2_CTIdentifyRes,
    &ett_h450_2_T_resultExtension,
    &ett_h450_2_CTUpdateArg,
    &ett_h450_2_T_cTUpdateArg_argumentExtension,
    &ett_h450_2_SubaddressTransferArg,
    &ett_h450_2_T_subaddressTransferArg_argumentExtension,
    &ett_h450_2_CTCompleteArg,
    &ett_h450_2_T_cTCompleteArg_argumentExtension,
    &ett_h450_2_CTActiveArg,
    &ett_h450_2_T_cTActiveArg_argumentExtension,
    &ett_h450_2_ExtensionSeq,
    &ett_h450_2_PAR_unspecified,

/* --- Module Call-Diversion-Operations --- --- ---                           */

    &ett_h450_3_ARG_activateDiversionQ,
    &ett_h450_3_ActivateDiversionQArg_extension,
    &ett_h450_3_RES_activateDiversionQ,
    &ett_h450_3_ARG_deactivateDiversionQ,
    &ett_h450_3_DeactivateDiversionQArg_extension,
    &ett_h450_3_RES_deactivateDiversionQ,
    &ett_h450_3_ARG_interrogateDiversionQ,
    &ett_h450_3_InterrogateDiversionQ_extension,
    &ett_h450_3_ARG_checkRestriction,
    &ett_h450_3_CheckRestrictionArg_extension,
    &ett_h450_3_RES_checkRestriction,
    &ett_h450_3_ARG_callRerouting,
    &ett_h450_3_CallReroutingArg_extension,
    &ett_h450_3_RES_callRerouting,
    &ett_h450_3_ARG_divertingLegInformation1,
    &ett_h450_3_DivertingLegInformation1Arg_extension,
    &ett_h450_3_ARG_divertingLegInformation2,
    &ett_h450_3_DivertingLegInformation2Arg_extension,
    &ett_h450_3_ARG_divertingLegInformation3,
    &ett_h450_3_DivertingLegInformation3Arg_extension,
    &ett_h450_3_ARG_divertingLegInformation4,
    &ett_h450_3_DivertingLegInformation4Arg_extension,
    &ett_h450_3_ARG_cfnrDivertedLegFailed,
    &ett_h450_3_IntResultList,
    &ett_h450_3_IntResult,
    &ett_h450_3_IntResult_extension,
    &ett_h450_3_PAR_unspecified,
    &ett_h450_3_ExtensionSeq,

/* --- Module Call-Hold-Operations --- --- ---                                */

    &ett_h450_4_HoldNotificArg,
    &ett_h450_4_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_4_RetrieveNotificArg,
    &ett_h450_4_RemoteHoldArg,
    &ett_h450_4_RemoteHoldRes,
    &ett_h450_4_RemoteRetrieveArg,
    &ett_h450_4_RemoteRetrieveRes,
    &ett_h450_4_MixedExtension,
    &ett_h450_4_PAR_undefined,

/* --- Module Call-Park-Pickup-Operations --- --- ---                         */

    &ett_h450_5_CpRequestArg,
    &ett_h450_5_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_5_CpRequestRes,
    &ett_h450_5_CpSetupArg,
    &ett_h450_5_CpSetupRes,
    &ett_h450_5_GroupIndicationOnArg,
    &ett_h450_5_GroupIndicationOnRes,
    &ett_h450_5_GroupIndicationOffArg,
    &ett_h450_5_GroupIndicationOffRes,
    &ett_h450_5_PickrequArg,
    &ett_h450_5_PickrequRes,
    &ett_h450_5_PickupArg,
    &ett_h450_5_PickupRes,
    &ett_h450_5_PickExeArg,
    &ett_h450_5_PickExeRes,
    &ett_h450_5_CpNotifyArg,
    &ett_h450_5_CpickupNotifyArg,
    &ett_h450_5_PAR_undefined,

/* --- Module Call-Waiting-Operations --- --- ---                             */

    &ett_h450_6_CallWaitingArg,
    &ett_h450_6_SEQUENCE_SIZE_0_255_OF_MixedExtension,

/* --- Module Message-Waiting-Indication-Operations --- --- ---               */

    &ett_h450_7_MWIActivateArg,
    &ett_h450_7_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_7_DummyRes,
    &ett_h450_7_MWIDeactivateArg,
    &ett_h450_7_MWIInterrogateArg,
    &ett_h450_7_MWIInterrogateRes,
    &ett_h450_7_MWIInterrogateResElt,
    &ett_h450_7_MsgCentreId,
    &ett_h450_7_PAR_undefined,

/* --- Module Name-Operations --- --- ---                                     */

    &ett_h450_8_ARG_callingName,
    &ett_h450_8_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_8_ARG_alertingName,
    &ett_h450_8_ARG_connectedName,
    &ett_h450_8_ARG_busyName,
    &ett_h450_8_Name,
    &ett_h450_8_NamePresentationAllowed,
    &ett_h450_8_NamePresentationRestricted,

/* --- Module Call-Completion-Operations --- --- ---                          */

    &ett_h450_9_CcRequestArg,
    &ett_h450_9_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_9_CcRequestRes,
    &ett_h450_9_CcArg,
    &ett_h450_9_CcShortArg,
    &ett_h450_9_CcLongArg,

/* --- Module Call-Offer-Operations --- --- ---                               */

    &ett_h450_10_CoReqOptArg,
    &ett_h450_10_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_10_RUAlertOptArg,
    &ett_h450_10_CfbOvrOptArg,

/* --- Module Call-Intrusion-Operations --- --- ---                           */

    &ett_h450_11_CIRequestArg,
    &ett_h450_11_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_11_CIRequestRes,
    &ett_h450_11_CIGetCIPLOptArg,
    &ett_h450_11_CIGetCIPLRes,
    &ett_h450_11_CIIsOptArg,
    &ett_h450_11_CIIsOptRes,
    &ett_h450_11_CIFrcRelArg,
    &ett_h450_11_CIFrcRelOptRes,
    &ett_h450_11_CIWobOptArg,
    &ett_h450_11_CIWobOptRes,
    &ett_h450_11_CISilentArg,
    &ett_h450_11_CISilentOptRes,
    &ett_h450_11_CINotificationArg,
    &ett_h450_11_CIStatusInformation,

/* --- Module Common-Information-Operations --- --- ---                       */

    &ett_h450_12_CmnArg,
    &ett_h450_12_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_12_DummyArg,
    &ett_h450_12_FeatureList,
    &ett_h450_12_FeatureValues,
    &ett_h450_12_FeatureControl,

/*--- End of included file: packet-h450-ettarr.c ---*/
#line 266 "../../asn1/h450/packet-h450-template.c"
  };


  /* Register protocol */
  proto_h450 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("h4501", dissect_h450_H4501SupplementaryService_PDU, proto_h450);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h450, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rose_ctx_init(&h450_rose_ctx);

  /* Register dissector tables */
  h450_rose_ctx.arg_global_dissector_table = register_dissector_table("h450.ros.global.arg", "H.450 Operation Argument (global opcode)", FT_STRING, BASE_NONE);
  h450_rose_ctx.res_global_dissector_table = register_dissector_table("h450.ros.global.res", "H.450 Operation Result (global opcode)", FT_STRING, BASE_NONE);
  h450_rose_ctx.arg_local_dissector_table = register_dissector_table("h450.ros.local.arg", "H.450 Operation Argument (local opcode)", FT_UINT32, BASE_HEX);
  h450_rose_ctx.res_local_dissector_table = register_dissector_table("h450.ros.local.res", "H.450 Operation Result (local opcode)", FT_UINT32, BASE_HEX);
  h450_rose_ctx.err_global_dissector_table = register_dissector_table("h450.ros.global.err", "H.450 Error (global opcode)", FT_STRING, BASE_NONE);
  h450_rose_ctx.err_local_dissector_table = register_dissector_table("h450.ros.local.err", "H.450 Error (local opcode)", FT_UINT32, BASE_HEX);

}


/*--- proto_reg_handoff_h450 ---------------------------------------*/
void
proto_reg_handoff_h450(void)
{
  int i;
  dissector_handle_t h450_arg_handle;
  dissector_handle_t h450_res_handle;
  dissector_handle_t h450_err_handle;

  h450_arg_handle = new_create_dissector_handle(dissect_h450_arg, proto_h450);
  h450_res_handle = new_create_dissector_handle(dissect_h450_res, proto_h450);
  for (i=0; i<(int)array_length(h450_op_tab); i++) {
    dissector_add_uint("h450.ros.local.arg", h450_op_tab[i].opcode, h450_arg_handle);
    dissector_add_uint("h450.ros.local.res", h450_op_tab[i].opcode, h450_res_handle);
  }
  h450_err_handle = new_create_dissector_handle(dissect_h450_err, proto_h450);
  for (i=0; i<(int)array_length(h450_err_tab); i++) {
    dissector_add_uint("h450.ros.local.err", h450_err_tab[i].errcode, h450_err_handle);
  }

}
