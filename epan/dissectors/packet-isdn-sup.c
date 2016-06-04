/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-isdn-sup.c                                                          */
/* asn2wrs.py -b -p isdn-sup -c ./isdn-sup.cnf -s ./packet-isdn-sup-template -D . -O ../.. Addressing-Data-Elements.asn Basic-Service-Elements.asn Embedded-Q931-Types.asn General-Errors.asn Advice-of-Charge-Operations.asn Closed-User-Group-Service-Operations.asn Conference-Add-On-Operations.asn Diversion-Operations.asn MCID-Operations.asn User-To-User-Signalling-Operations.asn Freephone-Operations.asn MLPP-Operations-And-Errors.asn */

/* Input file: packet-isdn-sup-template.c */

#line 1 "./asn1/isdn-sup/packet-isdn-sup-template.c"
/* packet-isdn-sup-template.c
 * Routines for ETSI Integrated Services Digital Network (ISDN)
 * supplementary services
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI 300 374
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-ber.h"

#define PNAME  "ISDN supplementary services"
#define PSNAME "ISDN_SUP"
#define PFNAME "isdn_sup"

void proto_register_isdn_sup(void);
void proto_reg_handoff_isdn_sup(void);


/*--- Included file: packet-isdn-sup-val.h ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-val.h"
#define fPHOID                         "0.4.0.210.1"

/*--- End of included file: packet-isdn-sup-val.h ---*/
#line 41 "./asn1/isdn-sup/packet-isdn-sup-template.c"

/* Initialize the protocol and registered fields */
static int proto_isdn_sup = -1;
static int hf_isdn_sup_operation = -1;
static int hf_isdn_sup_error = -1;

/* Global variables */

#if 0
/* ROSE context */
static rose_ctx_t isdn_sup_rose_ctx;
#endif

typedef struct _isdn_sup_op_t {
  gint32 opcode;
  dissector_t arg_pdu;
  dissector_t res_pdu;
} isdn_sup_op_t;

typedef struct _isdn_global_sup_op_t {
  const char*  oid;
  dissector_t arg_pdu;
  dissector_t res_pdu;
} isdn_sup_global_op_t;


typedef struct isdn_sup_err_t {
  gint32 errcode;
  dissector_t err_pdu;
} isdn_sup_err_t;

static const value_string isdn_sup_str_operation[] = {

/*--- Included file: packet-isdn-sup-table10.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-table10.c"
  {   1, "userUserService" },
  {   2, "cUGcall" },
  {   3, "mCIDRequest" },
  {   7, "activationDiversion" },
  {   8, "deactivationDiversion" },
  {   9, "activationStatusNotificationDiv" },
  {  10, "deactivationStatusNotificationDiv" },
  {  11, "interrogationDiversion" },
  {  12, "diversionInformation" },
  {  13, "callDeflection" },
  {  14, "callRerouteing" },
  {  15, "divertingLegInformation2" },
  {  17, "interrogateServedUserNumbers" },
  {  18, "divertingLegInformation1" },
  {  19, "divertingLegInformation3" },
  {  24, "mLPPLFBQuery" },
  {  25, "mLPPCallRequest" },
  {  26, "mLPPCallPreemption" },
  {  30, "chargingRequest" },
  {  31, "aOCSCurrency" },
  {  32, "aOCSSpecialArr" },
  {  33, "aOCDCurrency" },
  {  34, "aOCDChargingUnit" },
  {  35, "aOCECurrency" },
  {  36, "aOCEChargingUnit" },
  {  40, "beginCONF" },
  {  41, "addCONF" },
  {  42, "splitCONF" },
  {  43, "dropCONF" },
  {  44, "isolateCONF" },
  {  45, "reattachCONF" },
  {  46, "partyDISC" },

/*--- End of included file: packet-isdn-sup-table10.c ---*/
#line 74 "./asn1/isdn-sup/packet-isdn-sup-template.c"
  {   0, NULL}
};


static const value_string isdn_sup_str_error[] = {

/*--- Included file: packet-isdn-sup-table20.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-table20.c"
  {    0, "notSubscribed" },
  {    3, "notAvailable" },
  {    4, "notImplemented" },
  {    6, "invalidServedUserNr" },
  {    7, "invalidCallState" },
  {    8, "basicServiceNotProvided" },
  {    9, "notIncomingCall" },
  {   10, "supplementaryServiceInteractionNotAllowed" },
  {   11, "resourceUnavailable" },
  {   26, "noChargingInfoAvailable" },
  {   16, "invalidOrUnregisteredCUGIndex" },
  {   17, "requestedBasicServiceViolatesCUGConstraints" },
  {   18, "outgoingCallsBarredWithinCUG" },
  {   19, "incomingCallsBarredWithinCUG" },
  {   20, "userNotMemberOfCUG" },
  {   21, "inconsistencyInDesignatedFacilityAndSubscriberClass" },
  {   28, "illConferenceId" },
  {   29, "illPartyId" },
  {   30, "numberOfPartiesExceeded" },
  {   31, "notActive" },
  {   32, "notAllowed" },
  {   12, "invalidDivertedToNr" },
  {   14, "specialServiceNr" },
  {   15, "diversionToServedUserNr" },
  {   23, "incomingCallAccepted" },
  {   24, "numberOfDiversionsExceeded" },
  {   46, "notActivated" },
  {   48, "requestAlreadyAccepted" },
  {    1, "rejectedByTheNetwork" },
  {    2, "rejectedByTheUser" },
  {   44, "unauthorizedPrecedenceLevel" },

/*--- End of included file: packet-isdn-sup-table20.c ---*/
#line 80 "./asn1/isdn-sup/packet-isdn-sup-template.c"
  {   0, NULL}
};

static int hf_isdn_sup = -1;


/*--- Included file: packet-isdn-sup-hf.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-hf.c"
static int hf_isdn_sup_ChargingRequestArg_PDU = -1;  /* ChargingRequestArg */
static int hf_isdn_sup_ChargingRequestRes_PDU = -1;  /* ChargingRequestRes */
static int hf_isdn_sup_AOCSCurrencyArg_PDU = -1;  /* AOCSCurrencyArg */
static int hf_isdn_sup_AOCSSpecialArrArg_PDU = -1;  /* AOCSSpecialArrArg */
static int hf_isdn_sup_AOCDCurrencyArg_PDU = -1;  /* AOCDCurrencyArg */
static int hf_isdn_sup_AOCDChargingUnitArg_PDU = -1;  /* AOCDChargingUnitArg */
static int hf_isdn_sup_AOCECurrencyArg_PDU = -1;  /* AOCECurrencyArg */
static int hf_isdn_sup_AOCEChargingUnitArg_PDU = -1;  /* AOCEChargingUnitArg */
static int hf_isdn_sup_CUGcallArg_PDU = -1;       /* CUGcallArg */
static int hf_isdn_sup_BeginCONFArg_PDU = -1;     /* BeginCONFArg */
static int hf_isdn_sup_BeginCONFRes_PDU = -1;     /* BeginCONFRes */
static int hf_isdn_sup_AddCONFArg_PDU = -1;       /* AddCONFArg */
static int hf_isdn_sup_AddCONFRes_PDU = -1;       /* AddCONFRes */
static int hf_isdn_sup_SplitCONFArg_PDU = -1;     /* SplitCONFArg */
static int hf_isdn_sup_DropCONFArg_PDU = -1;      /* DropCONFArg */
static int hf_isdn_sup_IsolateCONFArg_PDU = -1;   /* IsolateCONFArg */
static int hf_isdn_sup_ReattachCONFArg_PDU = -1;  /* ReattachCONFArg */
static int hf_isdn_sup_PartyDISCArg_PDU = -1;     /* PartyDISCArg */
static int hf_isdn_sup_ActivationDiversionArg_PDU = -1;  /* ActivationDiversionArg */
static int hf_isdn_sup_DeactivationDiversionArg_PDU = -1;  /* DeactivationDiversionArg */
static int hf_isdn_sup_ActivationStatusNotificationDivArg_PDU = -1;  /* ActivationStatusNotificationDivArg */
static int hf_isdn_sup_DeactivationStatusNotificationDivArg_PDU = -1;  /* DeactivationStatusNotificationDivArg */
static int hf_isdn_sup_InterrogationDiversionArg_PDU = -1;  /* InterrogationDiversionArg */
static int hf_isdn_sup_InterrogationDiversionRes_PDU = -1;  /* InterrogationDiversionRes */
static int hf_isdn_sup_InterrogateServedUserNumbersRes_PDU = -1;  /* InterrogateServedUserNumbersRes */
static int hf_isdn_sup_DiversionInformationArg_PDU = -1;  /* DiversionInformationArg */
static int hf_isdn_sup_CallDeflectionArg_PDU = -1;  /* CallDeflectionArg */
static int hf_isdn_sup_CallRerouteingArg_PDU = -1;  /* CallRerouteingArg */
static int hf_isdn_sup_DivertingLegInformation1Arg_PDU = -1;  /* DivertingLegInformation1Arg */
static int hf_isdn_sup_DivertingLegInformation2Arg_PDU = -1;  /* DivertingLegInformation2Arg */
static int hf_isdn_sup_DivertingLegInformation3Arg_PDU = -1;  /* DivertingLegInformation3Arg */
static int hf_isdn_sup_UserUserServiceArg_PDU = -1;  /* UserUserServiceArg */
static int hf_isdn_sup_CalledFreephoneNrArg_PDU = -1;  /* CalledFreephoneNrArg */
static int hf_isdn_sup_Monitor_T_FPHArg_PDU = -1;  /* Monitor_T_FPHArg */
static int hf_isdn_sup_Free_T_FPHArg_PDU = -1;    /* Free_T_FPHArg */
static int hf_isdn_sup_Call_T_FPHArg_PDU = -1;    /* Call_T_FPHArg */
static int hf_isdn_sup_MLPPLFBArg_PDU = -1;       /* MLPPLFBArg */
static int hf_isdn_sup_MLPPLFBResp_PDU = -1;      /* MLPPLFBResp */
static int hf_isdn_sup_MLPPParams_PDU = -1;       /* MLPPParams */
static int hf_isdn_sup_StatusRequest_PDU = -1;    /* StatusRequest */
static int hf_isdn_sup_PreemptParams_PDU = -1;    /* PreemptParams */
static int hf_isdn_sup_presentationallowedaddressscreened = -1;  /* AddressScreened */
static int hf_isdn_sup_presentationRestricted = -1;  /* NULL */
static int hf_isdn_sup_numberNotAvailableDueToInterworking = -1;  /* NULL */
static int hf_isdn_sup_presentationrestrictedaddressscreened = -1;  /* AddressScreened */
static int hf_isdn_sup_presentationAllowedAddress = -1;  /* Address */
static int hf_isdn_sup_presentationRestrictedAddress = -1;  /* Address */
static int hf_isdn_sup_presentationallowednumberscreened = -1;  /* NumberScreened */
static int hf_isdn_sup_presentationrestrictednumberscreened = -1;  /* NumberScreened */
static int hf_isdn_sup_presentationAllowedNumber = -1;  /* PartyNumber */
static int hf_isdn_sup_presentationRestrictedNumber = -1;  /* PartyNumber */
static int hf_isdn_sup_partyNumber = -1;          /* PartyNumber */
static int hf_isdn_sup_screeningIndicator = -1;   /* ScreeningIndicator */
static int hf_isdn_sup_partySubaddress = -1;      /* PartySubaddress */
static int hf_isdn_sup_unknownPartyNumber = -1;   /* NumberDigits */
static int hf_isdn_sup_publicPartyNumber = -1;    /* PublicPartyNumber */
static int hf_isdn_sup_nsapEncodedNumber = -1;    /* NsapEncodedNumber */
static int hf_isdn_sup_dataPartyNumber = -1;      /* NumberDigits */
static int hf_isdn_sup_telexPartyNumber = -1;     /* NumberDigits */
static int hf_isdn_sup_privatePartyNumber = -1;   /* PrivatePartyNumber */
static int hf_isdn_sup_nationalStandardPartyNumber = -1;  /* NumberDigits */
static int hf_isdn_sup_publicTypeOfNumber = -1;   /* PublicTypeOfNumber */
static int hf_isdn_sup_publicNumberDigits = -1;   /* NumberDigits */
static int hf_isdn_sup_privateTypeOfNumber = -1;  /* PrivateTypeOfNumber */
static int hf_isdn_sup_privateNumberDigits = -1;  /* NumberDigits */
static int hf_isdn_sup_userSpecifiedSubaddress = -1;  /* UserSpecifiedSubaddress */
static int hf_isdn_sup_nSAPSubaddress = -1;       /* NSAPSubaddress */
static int hf_isdn_sup_subaddressInformation = -1;  /* SubaddressInformation */
static int hf_isdn_sup_oddCountIndicator = -1;    /* BOOLEAN */
static int hf_isdn_sup_aOCSCurrencyInfoList = -1;  /* AOCSCurrencyInfoList */
static int hf_isdn_sup_aOCSSpecialArrInfo = -1;   /* AOCSSpecialArrInfo */
static int hf_isdn_sup_chargingInfoFollows = -1;  /* NULL */
static int hf_isdn_sup_chargeNotAvailable = -1;   /* NULL */
static int hf_isdn_sup_aOCDCurrencyInfo = -1;     /* AOCDCurrencyInfo */
static int hf_isdn_sup_aOCDChargingUnitInfo = -1;  /* AOCDChargingUnitInfo */
static int hf_isdn_sup_aOCECurrencyInfo = -1;     /* AOCECurrencyInfo */
static int hf_isdn_sup_aOCEChargingUnitInfo = -1;  /* AOCEChargingUnitInfo */
static int hf_isdn_sup_AOCSCurrencyInfoList_item = -1;  /* AOCSCurrencyInfo */
static int hf_isdn_sup_chargedItem = -1;          /* ChargedItem */
static int hf_isdn_sup_chargingtype = -1;         /* T_chargingtype */
static int hf_isdn_sup_aocschargingtypespecificCurrency = -1;  /* AOCSChargingTypeSpecificCurrency */
static int hf_isdn_sup_durationCurrency = -1;     /* DurationCurrency */
static int hf_isdn_sup_flatRateCurrency = -1;     /* FlatRateCurrency */
static int hf_isdn_sup_volumeRateCurrency = -1;   /* VolumeRateCurrency */
static int hf_isdn_sup_specialChargingCode = -1;  /* SpecialChargingCode */
static int hf_isdn_sup_freeOfCharge = -1;         /* NULL */
static int hf_isdn_sup_currencyInfoNotAvailable = -1;  /* NULL */
static int hf_isdn_sup_dCurrency = -1;            /* Currency */
static int hf_isdn_sup_dAmount = -1;              /* Amount */
static int hf_isdn_sup_dChargingType = -1;        /* ChargingType */
static int hf_isdn_sup_dTime = -1;                /* Time */
static int hf_isdn_sup_dGranularity = -1;         /* Time */
static int hf_isdn_sup_fRCurrency = -1;           /* Currency */
static int hf_isdn_sup_fRAmount = -1;             /* Amount */
static int hf_isdn_sup_vRCurrency = -1;           /* Currency */
static int hf_isdn_sup_vRAmount = -1;             /* Amount */
static int hf_isdn_sup_vRVolumeUnit = -1;         /* VolumeUnit */
static int hf_isdn_sup_aocdspecificCurrency = -1;  /* AOCDSpecificCurrency */
static int hf_isdn_sup_recordedCurrency = -1;     /* RecordedCurrency */
static int hf_isdn_sup_typeOfChargingInfo = -1;   /* TypeOfChargingInfo */
static int hf_isdn_sup_aOCDBillingId = -1;        /* AOCDBillingId */
static int hf_isdn_sup_aocdspecificchargingunits = -1;  /* AOCDSpecificChargingUnits */
static int hf_isdn_sup_recordedUnitsList = -1;    /* RecordedUnitsList */
static int hf_isdn_sup_rCurrency = -1;            /* Currency */
static int hf_isdn_sup_rAmount = -1;              /* Amount */
static int hf_isdn_sup_RecordedUnitsList_item = -1;  /* RecordedUnits */
static int hf_isdn_sup_recoredunitscc = -1;       /* RecoredUnitsCc */
static int hf_isdn_sup_recordedNumberOfUnits = -1;  /* NumberOfUnits */
static int hf_isdn_sup_notAvailable = -1;         /* NULL */
static int hf_isdn_sup_recordedTypeOfUnits = -1;  /* TypeOfUnit */
static int hf_isdn_sup_aocecurrencycc = -1;       /* AOCECurrencyCc */
static int hf_isdn_sup_aoceccspecificCurrency = -1;  /* AOCECcSpecificCurrency */
static int hf_isdn_sup_aOCEBillingId = -1;        /* AOCEBillingId */
static int hf_isdn_sup_chargingAssociation = -1;  /* ChargingAssociation */
static int hf_isdn_sup_aocechargingunitcc = -1;   /* AOCEChargingUnitCc */
static int hf_isdn_sup_aoceccspecificchargingunits = -1;  /* AOCECcSpecificChargingUnits */
static int hf_isdn_sup_currencyAmount = -1;       /* CurrencyAmount */
static int hf_isdn_sup_multiplier = -1;           /* Multiplier */
static int hf_isdn_sup_lengthOfTimeUnit = -1;     /* LengthOfTimeUnit */
static int hf_isdn_sup_scale = -1;                /* Scale */
static int hf_isdn_sup_chargeNumber = -1;         /* PartyNumber */
static int hf_isdn_sup_chargeIdentifier = -1;     /* ChargeIdentifier */
static int hf_isdn_sup_oARequested = -1;          /* OARequested */
static int hf_isdn_sup_cUGIndex = -1;             /* CUGIndex */
static int hf_isdn_sup_conferenceId = -1;         /* ConferenceId */
static int hf_isdn_sup_partyId = -1;              /* PartyId */
static int hf_isdn_sup_procedure = -1;            /* Procedure */
static int hf_isdn_sup_basicService = -1;         /* BasicService */
static int hf_isdn_sup_forwardedToAddress = -1;   /* Address */
static int hf_isdn_sup_servedUserNr = -1;         /* ServedUserNr */
static int hf_isdn_sup_noReplyTimer = -1;         /* NoReplyTimer */
static int hf_isdn_sup_forwardedToAddresss = -1;  /* Address */
static int hf_isdn_sup_diversionReason = -1;      /* DiversionReason */
static int hf_isdn_sup_servedUserSubaddress = -1;  /* PartySubaddress */
static int hf_isdn_sup_callingAddress = -1;       /* PresentedAddressScreened */
static int hf_isdn_sup_originalCalledNr = -1;     /* PresentedNumberUnscreened */
static int hf_isdn_sup_lastDivertingNr = -1;      /* PresentedNumberUnscreened */
static int hf_isdn_sup_lastDivertingReason = -1;  /* DiversionReason */
static int hf_isdn_sup_userInfo = -1;             /* Q931InformationElement */
static int hf_isdn_sup_deflectionAddress = -1;    /* Address */
static int hf_isdn_sup_presentationAllowedDivertedToUser = -1;  /* PresentationAllowedIndicator */
static int hf_isdn_sup_rerouteingReason = -1;     /* DiversionReason */
static int hf_isdn_sup_calledAddress = -1;        /* Address */
static int hf_isdn_sup_rerouteingCounter = -1;    /* DiversionCounter */
static int hf_isdn_sup_q931InfoElement = -1;      /* Q931InformationElement */
static int hf_isdn_sup_lastRerouteingNr = -1;     /* PresentedNumberUnscreened */
static int hf_isdn_sup_subscriptionOption = -1;   /* SubscriptionOption */
static int hf_isdn_sup_callingPartySubaddress = -1;  /* PartySubaddress */
static int hf_isdn_sup_divertedToNumber = -1;     /* PresentedNumberUnscreened */
static int hf_isdn_sup_diversionCounter = -1;     /* DiversionCounter */
static int hf_isdn_sup_divertingNr = -1;          /* PresentedNumberUnscreened */
static int hf_isdn_sup_IntResultList_item = -1;   /* IntResult */
static int hf_isdn_sup_individualNumber = -1;     /* PartyNumber */
static int hf_isdn_sup_allNumbers = -1;           /* NULL */
static int hf_isdn_sup_ServedUserNumberList_item = -1;  /* PartyNumber */
static int hf_isdn_sup_service = -1;              /* Service */
static int hf_isdn_sup_preferred = -1;            /* Preferred */
static int hf_isdn_sup_servedUserDestination = -1;  /* PartyNumber */
static int hf_isdn_sup_queueIdentity = -1;        /* QueueIdentity */
static int hf_isdn_sup_fPHReference = -1;         /* FPHReference */
static int hf_isdn_sup_calledFreephoneNr = -1;    /* CalledFreephoneNr */
static int hf_isdn_sup_mlppParams = -1;           /* MLPPParams */
static int hf_isdn_sup_ieArg = -1;                /* IEArg */
static int hf_isdn_sup_precLevel = -1;            /* PrecLevel */
static int hf_isdn_sup_lfbIndictn = -1;           /* LFBIndictn */
static int hf_isdn_sup_mlppSvcDomn = -1;          /* MLPPSvcDomn */
static int hf_isdn_sup_statusQuery = -1;          /* StatusQuery */
static int hf_isdn_sup_location = -1;             /* Location */

/*--- End of included file: packet-isdn-sup-hf.c ---*/
#line 86 "./asn1/isdn-sup/packet-isdn-sup-template.c"


/* Initialize the subtree pointers */
static gint ett_isdn_sup = -1;


/*--- Included file: packet-isdn-sup-ett.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-ett.c"
static gint ett_isdn_sup_PresentedAddressScreened = -1;
static gint ett_isdn_sup_PresentedAddressUnscreened = -1;
static gint ett_isdn_sup_PresentedNumberScreened = -1;
static gint ett_isdn_sup_PresentedNumberUnscreened = -1;
static gint ett_isdn_sup_AddressScreened = -1;
static gint ett_isdn_sup_NumberScreened = -1;
static gint ett_isdn_sup_Address = -1;
static gint ett_isdn_sup_PartyNumber = -1;
static gint ett_isdn_sup_PublicPartyNumber = -1;
static gint ett_isdn_sup_PrivatePartyNumber = -1;
static gint ett_isdn_sup_PartySubaddress = -1;
static gint ett_isdn_sup_UserSpecifiedSubaddress = -1;
static gint ett_isdn_sup_ChargingRequestRes = -1;
static gint ett_isdn_sup_AOCSCurrencyArg = -1;
static gint ett_isdn_sup_AOCSSpecialArrArg = -1;
static gint ett_isdn_sup_AOCDCurrencyArg = -1;
static gint ett_isdn_sup_AOCDChargingUnitArg = -1;
static gint ett_isdn_sup_AOCECurrencyArg = -1;
static gint ett_isdn_sup_AOCEChargingUnitArg = -1;
static gint ett_isdn_sup_AOCSCurrencyInfoList = -1;
static gint ett_isdn_sup_AOCSCurrencyInfo = -1;
static gint ett_isdn_sup_T_chargingtype = -1;
static gint ett_isdn_sup_AOCSChargingTypeSpecificCurrency = -1;
static gint ett_isdn_sup_DurationCurrency = -1;
static gint ett_isdn_sup_FlatRateCurrency = -1;
static gint ett_isdn_sup_VolumeRateCurrency = -1;
static gint ett_isdn_sup_AOCDCurrencyInfo = -1;
static gint ett_isdn_sup_AOCDSpecificCurrency = -1;
static gint ett_isdn_sup_AOCDChargingUnitInfo = -1;
static gint ett_isdn_sup_AOCDSpecificChargingUnits = -1;
static gint ett_isdn_sup_RecordedCurrency = -1;
static gint ett_isdn_sup_RecordedUnitsList = -1;
static gint ett_isdn_sup_RecordedUnits = -1;
static gint ett_isdn_sup_RecoredUnitsCc = -1;
static gint ett_isdn_sup_AOCECurrencyInfo = -1;
static gint ett_isdn_sup_AOCECurrencyCc = -1;
static gint ett_isdn_sup_AOCECcSpecificCurrency = -1;
static gint ett_isdn_sup_AOCEChargingUnitInfo = -1;
static gint ett_isdn_sup_AOCEChargingUnitCc = -1;
static gint ett_isdn_sup_AOCECcSpecificChargingUnits = -1;
static gint ett_isdn_sup_Amount = -1;
static gint ett_isdn_sup_Time = -1;
static gint ett_isdn_sup_ChargingAssociation = -1;
static gint ett_isdn_sup_CUGcallArg = -1;
static gint ett_isdn_sup_BeginCONFRes = -1;
static gint ett_isdn_sup_SplitCONFArg = -1;
static gint ett_isdn_sup_ActivationDiversionArg = -1;
static gint ett_isdn_sup_DeactivationDiversionArg = -1;
static gint ett_isdn_sup_ActivationStatusNotificationDivArg = -1;
static gint ett_isdn_sup_DeactivationStatusNotificationDivArg = -1;
static gint ett_isdn_sup_InterrogationDiversionArg = -1;
static gint ett_isdn_sup_DiversionInformationArg = -1;
static gint ett_isdn_sup_CallDeflectionArg = -1;
static gint ett_isdn_sup_CallRerouteingArg = -1;
static gint ett_isdn_sup_DivertingLegInformation1Arg = -1;
static gint ett_isdn_sup_DivertingLegInformation2Arg = -1;
static gint ett_isdn_sup_IntResultList = -1;
static gint ett_isdn_sup_IntResult = -1;
static gint ett_isdn_sup_ServedUserNr = -1;
static gint ett_isdn_sup_ServedUserNumberList = -1;
static gint ett_isdn_sup_UserUserServiceArg = -1;
static gint ett_isdn_sup_Monitor_T_FPHArg = -1;
static gint ett_isdn_sup_Free_T_FPHArg = -1;
static gint ett_isdn_sup_Call_T_FPHArg = -1;
static gint ett_isdn_sup_MLPPLFBArg = -1;
static gint ett_isdn_sup_MLPPParams = -1;
static gint ett_isdn_sup_MLPPLFBResp = -1;

/*--- End of included file: packet-isdn-sup-ett.c ---*/
#line 92 "./asn1/isdn-sup/packet-isdn-sup-template.c"

/* static expert_field ei_isdn_sup_unsupported_arg_type = EI_INIT; */
static expert_field ei_isdn_sup_unsupported_result_type = EI_INIT;
static expert_field ei_isdn_sup_unsupported_error_type = EI_INIT;

/* Preference settings default */

/* Global variables */


/*--- Included file: packet-isdn-sup-fn.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-fn.c"


static int
dissect_isdn_sup_NumberDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string isdn_sup_PublicTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "internationalNumber" },
  {   2, "nationalNumber" },
  {   3, "networkSpecificNumber" },
  {   4, "subscriberNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_isdn_sup_PublicTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PublicPartyNumber_sequence[] = {
  { &hf_isdn_sup_publicTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PublicTypeOfNumber },
  { &hf_isdn_sup_publicNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PublicPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PublicPartyNumber_sequence, hf_index, ett_isdn_sup_PublicPartyNumber);

  return offset;
}



static int
dissect_isdn_sup_NsapEncodedNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string isdn_sup_PrivateTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "level2RegionalNumber" },
  {   2, "level1RegionalNumber" },
  {   3, "pTNSpecificNumber" },
  {   4, "localNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_isdn_sup_PrivateTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PrivatePartyNumber_sequence[] = {
  { &hf_isdn_sup_privateTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PrivateTypeOfNumber },
  { &hf_isdn_sup_privateNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PrivatePartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivatePartyNumber_sequence, hf_index, ett_isdn_sup_PrivatePartyNumber);

  return offset;
}


static const value_string isdn_sup_PartyNumber_vals[] = {
  {   0, "unknownPartyNumber" },
  {   1, "publicPartyNumber" },
  {   2, "nsapEncodedNumber" },
  {   3, "dataPartyNumber" },
  {   4, "telexPartyNumber" },
  {   5, "privatePartyNumber" },
  {   8, "nationalStandardPartyNumber" },
  { 0, NULL }
};

static const ber_choice_t PartyNumber_choice[] = {
  {   0, &hf_isdn_sup_unknownPartyNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  {   1, &hf_isdn_sup_publicPartyNumber, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_PublicPartyNumber },
  {   2, &hf_isdn_sup_nsapEncodedNumber, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NsapEncodedNumber },
  {   3, &hf_isdn_sup_dataPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  {   4, &hf_isdn_sup_telexPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  {   5, &hf_isdn_sup_privatePartyNumber, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_isdn_sup_PrivatePartyNumber },
  {   8, &hf_isdn_sup_nationalStandardPartyNumber, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartyNumber_choice, hf_index, ett_isdn_sup_PartyNumber,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_ScreeningIndicator_vals[] = {
  {   0, "userProvidedNotScreened" },
  {   1, "userProvidedVerifiedAndPassed" },
  {   2, "userProvidedVerifiedAndFailed" },
  {   3, "networkProvided" },
  { 0, NULL }
};


static int
dissect_isdn_sup_ScreeningIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_SubaddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_isdn_sup_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { &hf_isdn_sup_subaddressInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_SubaddressInformation },
  { &hf_isdn_sup_oddCountIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_UserSpecifiedSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserSpecifiedSubaddress_sequence, hf_index, ett_isdn_sup_UserSpecifiedSubaddress);

  return offset;
}



static int
dissect_isdn_sup_NSAPSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string isdn_sup_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nSAPSubaddress" },
  { 0, NULL }
};

static const ber_choice_t PartySubaddress_choice[] = {
  {   0, &hf_isdn_sup_userSpecifiedSubaddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_UserSpecifiedSubaddress },
  {   1, &hf_isdn_sup_nSAPSubaddress, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NSAPSubaddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartySubaddress_choice, hf_index, ett_isdn_sup_PartySubaddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddressScreened_sequence[] = {
  { &hf_isdn_sup_partyNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
  { &hf_isdn_sup_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_ScreeningIndicator },
  { &hf_isdn_sup_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressScreened_sequence, hf_index, ett_isdn_sup_AddressScreened);

  return offset;
}



static int
dissect_isdn_sup_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string isdn_sup_PresentedAddressScreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const ber_choice_t PresentedAddressScreened_choice[] = {
  {   0, &hf_isdn_sup_presentationallowedaddressscreened, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_isdn_sup_AddressScreened },
  {   1, &hf_isdn_sup_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   2, &hf_isdn_sup_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   3, &hf_isdn_sup_presentationrestrictedaddressscreened, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_AddressScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedAddressScreened_choice, hf_index, ett_isdn_sup_PresentedAddressScreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t Address_sequence[] = {
  { &hf_isdn_sup_partyNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
  { &hf_isdn_sup_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Address_sequence, hf_index, ett_isdn_sup_Address);

  return offset;
}





static const value_string isdn_sup_PresentedNumberUnscreened_vals[] = {
  {   0, "presentationAllowedNumber" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedNumber" },
  { 0, NULL }
};

static const ber_choice_t PresentedNumberUnscreened_choice[] = {
  {   0, &hf_isdn_sup_presentationAllowedNumber, BER_CLASS_CON, 0, 0, dissect_isdn_sup_PartyNumber },
  {   1, &hf_isdn_sup_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   2, &hf_isdn_sup_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   3, &hf_isdn_sup_presentationRestrictedNumber, BER_CLASS_CON, 3, 0, dissect_isdn_sup_PartyNumber },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedNumberUnscreened_choice, hf_index, ett_isdn_sup_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string isdn_sup_BasicService_vals[] = {
  {   0, "allServices" },
  {   1, "speech" },
  {   2, "unrestrictedDigitalInformation" },
  {   3, "audio3k1Hz" },
  {   4, "unrestrictedDigitalInformationWithTonesAndAnnouncements" },
  {   5, "multirate" },
  {  32, "telephony3k1Hz" },
  {  33, "teletex" },
  {  34, "telefaxGroup4Class1" },
  {  35, "videotexSyntaxBased" },
  {  36, "videotelephony" },
  {  37, "telefaxGroup2-3" },
  {  38, "telephony7kHz" },
  {  39, "euroFileTransfer" },
  {  40, "fileTransferAndAccessManagement" },
  {  41, "videoconference" },
  {  42, "audioGraphicConference" },
  { 0, NULL }
};


static int
dissect_isdn_sup_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_isdn_sup_Q931InformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_isdn_sup_OCTET_STRING);

  return offset;
}


static const value_string isdn_sup_ChargingCase_vals[] = {
  {   0, "chargingInformationAtCallSetup" },
  {   1, "chargingDuringACall" },
  {   2, "chargingAtTheEndOfACall" },
  { 0, NULL }
};


static int
dissect_isdn_sup_ChargingCase(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_ChargingRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_ChargingCase(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string isdn_sup_ChargedItem_vals[] = {
  {   0, "basicCommunication" },
  {   1, "callAttempt" },
  {   2, "callSetup" },
  {   3, "userToUserInfo" },
  {   4, "operationOfSupplementaryServ" },
  { 0, NULL }
};


static int
dissect_isdn_sup_ChargedItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_Currency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_isdn_sup_CurrencyAmount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_Multiplier_vals[] = {
  {   0, "oneThousandth" },
  {   1, "oneHundredth" },
  {   2, "oneTenth" },
  {   3, "one" },
  {   4, "ten" },
  {   5, "hundred" },
  {   6, "thousand" },
  { 0, NULL }
};


static int
dissect_isdn_sup_Multiplier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Amount_sequence[] = {
  { &hf_isdn_sup_currencyAmount, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_CurrencyAmount },
  { &hf_isdn_sup_multiplier , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Multiplier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Amount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Amount_sequence, hf_index, ett_isdn_sup_Amount);

  return offset;
}


static const value_string isdn_sup_ChargingType_vals[] = {
  {   0, "continuousCharging" },
  {   1, "stepFunction" },
  { 0, NULL }
};


static int
dissect_isdn_sup_ChargingType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_LengthOfTimeUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_Scale_vals[] = {
  {   0, "oneHundredthSecond" },
  {   1, "oneTenthSecond" },
  {   2, "oneSecond" },
  {   3, "tenSeconds" },
  {   4, "oneMinute" },
  {   5, "oneHour" },
  {   6, "twentyFourHours" },
  { 0, NULL }
};


static int
dissect_isdn_sup_Scale(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Time_sequence[] = {
  { &hf_isdn_sup_lengthOfTimeUnit, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_LengthOfTimeUnit },
  { &hf_isdn_sup_scale      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Scale },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Time_sequence, hf_index, ett_isdn_sup_Time);

  return offset;
}


static const ber_sequence_t DurationCurrency_sequence[] = {
  { &hf_isdn_sup_dCurrency  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Currency },
  { &hf_isdn_sup_dAmount    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Amount },
  { &hf_isdn_sup_dChargingType, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_ChargingType },
  { &hf_isdn_sup_dTime      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Time },
  { &hf_isdn_sup_dGranularity, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_isdn_sup_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DurationCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DurationCurrency_sequence, hf_index, ett_isdn_sup_DurationCurrency);

  return offset;
}


static const ber_sequence_t FlatRateCurrency_sequence[] = {
  { &hf_isdn_sup_fRCurrency , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Currency },
  { &hf_isdn_sup_fRAmount   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Amount },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_FlatRateCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FlatRateCurrency_sequence, hf_index, ett_isdn_sup_FlatRateCurrency);

  return offset;
}


static const value_string isdn_sup_VolumeUnit_vals[] = {
  {   0, "octet" },
  {   1, "segment" },
  {   2, "message" },
  { 0, NULL }
};


static int
dissect_isdn_sup_VolumeUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t VolumeRateCurrency_sequence[] = {
  { &hf_isdn_sup_vRCurrency , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Currency },
  { &hf_isdn_sup_vRAmount   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Amount },
  { &hf_isdn_sup_vRVolumeUnit, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_VolumeUnit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_VolumeRateCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VolumeRateCurrency_sequence, hf_index, ett_isdn_sup_VolumeRateCurrency);

  return offset;
}


static const value_string isdn_sup_AOCSChargingTypeSpecificCurrency_vals[] = {
  {   1, "durationCurrency" },
  {   2, "flatRateCurrency" },
  {   3, "volumeRateCurrency" },
  { 0, NULL }
};

static const ber_choice_t AOCSChargingTypeSpecificCurrency_choice[] = {
  {   1, &hf_isdn_sup_durationCurrency, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_DurationCurrency },
  {   2, &hf_isdn_sup_flatRateCurrency, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_FlatRateCurrency },
  {   3, &hf_isdn_sup_volumeRateCurrency, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_VolumeRateCurrency },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCSChargingTypeSpecificCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCSChargingTypeSpecificCurrency_choice, hf_index, ett_isdn_sup_AOCSChargingTypeSpecificCurrency,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_SpecialChargingCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_T_chargingtype_vals[] = {
  {   0, "specificCurrency" },
  {   1, "specialChargingCode" },
  {   2, "freeOfCharge" },
  {   3, "currencyInfoNotAvailable" },
  { 0, NULL }
};

static const ber_choice_t T_chargingtype_choice[] = {
  {   0, &hf_isdn_sup_aocschargingtypespecificCurrency, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCSChargingTypeSpecificCurrency },
  {   1, &hf_isdn_sup_specialChargingCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_SpecialChargingCode },
  {   2, &hf_isdn_sup_freeOfCharge, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   3, &hf_isdn_sup_currencyInfoNotAvailable, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_T_chargingtype(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_chargingtype_choice, hf_index, ett_isdn_sup_T_chargingtype,
                                 NULL);

  return offset;
}


static const ber_sequence_t AOCSCurrencyInfo_sequence[] = {
  { &hf_isdn_sup_chargedItem, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_ChargedItem },
  { &hf_isdn_sup_chargingtype, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_T_chargingtype },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCSCurrencyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCSCurrencyInfo_sequence, hf_index, ett_isdn_sup_AOCSCurrencyInfo);

  return offset;
}


static const ber_sequence_t AOCSCurrencyInfoList_sequence_of[1] = {
  { &hf_isdn_sup_AOCSCurrencyInfoList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCSCurrencyInfo },
};

static int
dissect_isdn_sup_AOCSCurrencyInfoList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AOCSCurrencyInfoList_sequence_of, hf_index, ett_isdn_sup_AOCSCurrencyInfoList);

  return offset;
}



static int
dissect_isdn_sup_AOCSSpecialArrInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_ChargingRequestRes_vals[] = {
  {   0, "aOCSCurrencyInfoList" },
  {   1, "aOCSSpecialArrInfo" },
  {   2, "chargingInfoFollows" },
  { 0, NULL }
};

static const ber_choice_t ChargingRequestRes_choice[] = {
  {   0, &hf_isdn_sup_aOCSCurrencyInfoList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCSCurrencyInfoList },
  {   1, &hf_isdn_sup_aOCSSpecialArrInfo, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCSSpecialArrInfo },
  {   2, &hf_isdn_sup_chargingInfoFollows, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ChargingRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChargingRequestRes_choice, hf_index, ett_isdn_sup_ChargingRequestRes,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_AOCSCurrencyArg_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aOCSCurrencyInfoList" },
  { 0, NULL }
};

static const ber_choice_t AOCSCurrencyArg_choice[] = {
  {   0, &hf_isdn_sup_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  {   1, &hf_isdn_sup_aOCSCurrencyInfoList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCSCurrencyInfoList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCSCurrencyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCSCurrencyArg_choice, hf_index, ett_isdn_sup_AOCSCurrencyArg,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_AOCSSpecialArrArg_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aOCSSpecialArrInfo" },
  { 0, NULL }
};

static const ber_choice_t AOCSSpecialArrArg_choice[] = {
  {   0, &hf_isdn_sup_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  {   1, &hf_isdn_sup_aOCSSpecialArrInfo, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCSSpecialArrInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCSSpecialArrArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCSSpecialArrArg_choice, hf_index, ett_isdn_sup_AOCSSpecialArrArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t RecordedCurrency_sequence[] = {
  { &hf_isdn_sup_rCurrency  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Currency },
  { &hf_isdn_sup_rAmount    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Amount },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_RecordedCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecordedCurrency_sequence, hf_index, ett_isdn_sup_RecordedCurrency);

  return offset;
}


static const value_string isdn_sup_TypeOfChargingInfo_vals[] = {
  {   0, "subTotal" },
  {   1, "total" },
  { 0, NULL }
};


static int
dissect_isdn_sup_TypeOfChargingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string isdn_sup_AOCDBillingId_vals[] = {
  {   0, "normalCharging" },
  {   1, "reverseCharging" },
  {   2, "creditCardCharging" },
  { 0, NULL }
};


static int
dissect_isdn_sup_AOCDBillingId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AOCDSpecificCurrency_sequence[] = {
  { &hf_isdn_sup_recordedCurrency, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_RecordedCurrency },
  { &hf_isdn_sup_typeOfChargingInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_TypeOfChargingInfo },
  { &hf_isdn_sup_aOCDBillingId, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_isdn_sup_AOCDBillingId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCDSpecificCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCDSpecificCurrency_sequence, hf_index, ett_isdn_sup_AOCDSpecificCurrency);

  return offset;
}


static const value_string isdn_sup_AOCDCurrencyInfo_vals[] = {
  {   0, "specificCurrency" },
  {   1, "freeOfCharge" },
  { 0, NULL }
};

static const ber_choice_t AOCDCurrencyInfo_choice[] = {
  {   0, &hf_isdn_sup_aocdspecificCurrency, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCDSpecificCurrency },
  {   1, &hf_isdn_sup_freeOfCharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCDCurrencyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCDCurrencyInfo_choice, hf_index, ett_isdn_sup_AOCDCurrencyInfo,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_AOCDCurrencyArg_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aOCDCurrencyInfo" },
  { 0, NULL }
};

static const ber_choice_t AOCDCurrencyArg_choice[] = {
  {   0, &hf_isdn_sup_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  {   1, &hf_isdn_sup_aOCDCurrencyInfo, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCDCurrencyInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCDCurrencyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCDCurrencyArg_choice, hf_index, ett_isdn_sup_AOCDCurrencyArg,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_NumberOfUnits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_RecoredUnitsCc_vals[] = {
  {   0, "recordedNumberOfUnits" },
  {   1, "notAvailable" },
  { 0, NULL }
};

static const ber_choice_t RecoredUnitsCc_choice[] = {
  {   0, &hf_isdn_sup_recordedNumberOfUnits, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NumberOfUnits },
  {   1, &hf_isdn_sup_notAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_RecoredUnitsCc(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RecoredUnitsCc_choice, hf_index, ett_isdn_sup_RecoredUnitsCc,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_TypeOfUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RecordedUnits_sequence[] = {
  { &hf_isdn_sup_recoredunitscc, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_RecoredUnitsCc },
  { &hf_isdn_sup_recordedTypeOfUnits, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_TypeOfUnit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_RecordedUnits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecordedUnits_sequence, hf_index, ett_isdn_sup_RecordedUnits);

  return offset;
}


static const ber_sequence_t RecordedUnitsList_sequence_of[1] = {
  { &hf_isdn_sup_RecordedUnitsList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_RecordedUnits },
};

static int
dissect_isdn_sup_RecordedUnitsList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RecordedUnitsList_sequence_of, hf_index, ett_isdn_sup_RecordedUnitsList);

  return offset;
}


static const ber_sequence_t AOCDSpecificChargingUnits_sequence[] = {
  { &hf_isdn_sup_recordedUnitsList, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_RecordedUnitsList },
  { &hf_isdn_sup_typeOfChargingInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_TypeOfChargingInfo },
  { &hf_isdn_sup_aOCDBillingId, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_isdn_sup_AOCDBillingId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCDSpecificChargingUnits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCDSpecificChargingUnits_sequence, hf_index, ett_isdn_sup_AOCDSpecificChargingUnits);

  return offset;
}


static const value_string isdn_sup_AOCDChargingUnitInfo_vals[] = {
  {   0, "specificChargingUnits" },
  {   1, "freeOfCharge" },
  { 0, NULL }
};

static const ber_choice_t AOCDChargingUnitInfo_choice[] = {
  {   0, &hf_isdn_sup_aocdspecificchargingunits, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCDSpecificChargingUnits },
  {   1, &hf_isdn_sup_freeOfCharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCDChargingUnitInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCDChargingUnitInfo_choice, hf_index, ett_isdn_sup_AOCDChargingUnitInfo,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_AOCDChargingUnitArg_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aOCDChargingUnitInfo" },
  { 0, NULL }
};

static const ber_choice_t AOCDChargingUnitArg_choice[] = {
  {   0, &hf_isdn_sup_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  {   1, &hf_isdn_sup_aOCDChargingUnitInfo, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCDChargingUnitInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCDChargingUnitArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCDChargingUnitArg_choice, hf_index, ett_isdn_sup_AOCDChargingUnitArg,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_AOCEBillingId_vals[] = {
  {   0, "normalCharging" },
  {   1, "reverseCharging" },
  {   2, "creditCardCharging" },
  {   3, "callForwardingUnconditional" },
  {   4, "callForwardingBusy" },
  {   5, "callForwardingNoReply" },
  {   6, "callDeflection" },
  {   7, "callTransfer" },
  { 0, NULL }
};


static int
dissect_isdn_sup_AOCEBillingId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AOCECcSpecificCurrency_sequence[] = {
  { &hf_isdn_sup_recordedCurrency, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_RecordedCurrency },
  { &hf_isdn_sup_aOCEBillingId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_isdn_sup_AOCEBillingId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCECcSpecificCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCECcSpecificCurrency_sequence, hf_index, ett_isdn_sup_AOCECcSpecificCurrency);

  return offset;
}


static const value_string isdn_sup_AOCECurrencyCc_vals[] = {
  {   0, "specificCurrency" },
  {   1, "freeOfCharge" },
  { 0, NULL }
};

static const ber_choice_t AOCECurrencyCc_choice[] = {
  {   0, &hf_isdn_sup_aoceccspecificCurrency, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCECcSpecificCurrency },
  {   1, &hf_isdn_sup_freeOfCharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCECurrencyCc(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCECurrencyCc_choice, hf_index, ett_isdn_sup_AOCECurrencyCc,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_ChargeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_ChargingAssociation_vals[] = {
  {   0, "chargeNumber" },
  {   1, "chargeIdentifier" },
  { 0, NULL }
};

static const ber_choice_t ChargingAssociation_choice[] = {
  {   0, &hf_isdn_sup_chargeNumber, BER_CLASS_CON, 0, 0, dissect_isdn_sup_PartyNumber },
  {   1, &hf_isdn_sup_chargeIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_ChargeIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ChargingAssociation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChargingAssociation_choice, hf_index, ett_isdn_sup_ChargingAssociation,
                                 NULL);

  return offset;
}


static const ber_sequence_t AOCECurrencyInfo_sequence[] = {
  { &hf_isdn_sup_aocecurrencycc, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_AOCECurrencyCc },
  { &hf_isdn_sup_chargingAssociation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ChargingAssociation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCECurrencyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCECurrencyInfo_sequence, hf_index, ett_isdn_sup_AOCECurrencyInfo);

  return offset;
}


static const value_string isdn_sup_AOCECurrencyArg_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aOCECurrencyInfo" },
  { 0, NULL }
};

static const ber_choice_t AOCECurrencyArg_choice[] = {
  {   0, &hf_isdn_sup_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  {   1, &hf_isdn_sup_aOCECurrencyInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCECurrencyInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCECurrencyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCECurrencyArg_choice, hf_index, ett_isdn_sup_AOCECurrencyArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t AOCECcSpecificChargingUnits_sequence[] = {
  { &hf_isdn_sup_recordedUnitsList, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_RecordedUnitsList },
  { &hf_isdn_sup_aOCEBillingId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_isdn_sup_AOCEBillingId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCECcSpecificChargingUnits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCECcSpecificChargingUnits_sequence, hf_index, ett_isdn_sup_AOCECcSpecificChargingUnits);

  return offset;
}


static const value_string isdn_sup_AOCEChargingUnitCc_vals[] = {
  {   0, "specificChargingUnits" },
  {   1, "freeOfCharge" },
  { 0, NULL }
};

static const ber_choice_t AOCEChargingUnitCc_choice[] = {
  {   0, &hf_isdn_sup_aoceccspecificchargingunits, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCECcSpecificChargingUnits },
  {   1, &hf_isdn_sup_freeOfCharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCEChargingUnitCc(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCEChargingUnitCc_choice, hf_index, ett_isdn_sup_AOCEChargingUnitCc,
                                 NULL);

  return offset;
}


static const ber_sequence_t AOCEChargingUnitInfo_sequence[] = {
  { &hf_isdn_sup_aocechargingunitcc, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_AOCEChargingUnitCc },
  { &hf_isdn_sup_chargingAssociation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ChargingAssociation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCEChargingUnitInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCEChargingUnitInfo_sequence, hf_index, ett_isdn_sup_AOCEChargingUnitInfo);

  return offset;
}


static const value_string isdn_sup_AOCEChargingUnitArg_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aOCEChargingUnitInfo" },
  { 0, NULL }
};

static const ber_choice_t AOCEChargingUnitArg_choice[] = {
  {   0, &hf_isdn_sup_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  {   1, &hf_isdn_sup_aOCEChargingUnitInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_AOCEChargingUnitInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AOCEChargingUnitArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AOCEChargingUnitArg_choice, hf_index, ett_isdn_sup_AOCEChargingUnitArg,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_OARequested(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 1, TRUE, dissect_isdn_sup_BOOLEAN);

  return offset;
}



static int
dissect_isdn_sup_INTEGER_0_32767(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_isdn_sup_CUGIndex(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, TRUE, dissect_isdn_sup_INTEGER_0_32767);

  return offset;
}


static const ber_sequence_t CUGcallArg_sequence[] = {
  { &hf_isdn_sup_oARequested, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_OARequested },
  { &hf_isdn_sup_cUGIndex   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_CUGIndex },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_CUGcallArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CUGcallArg_sequence, hf_index, ett_isdn_sup_CUGcallArg);

  return offset;
}



static int
dissect_isdn_sup_ConfSize(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_isdn_sup_BeginCONFArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_ConfSize(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_ConferenceId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_isdn_sup_PartyId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BeginCONFRes_sequence[] = {
  { &hf_isdn_sup_conferenceId, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_ConferenceId },
  { &hf_isdn_sup_partyId    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PartyId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_BeginCONFRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BeginCONFRes_sequence, hf_index, ett_isdn_sup_BeginCONFRes);

  return offset;
}



static int
dissect_isdn_sup_AddCONFArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_ConferenceId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_AddCONFRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PartyId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SplitCONFArg_sequence[] = {
  { &hf_isdn_sup_conferenceId, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_ConferenceId },
  { &hf_isdn_sup_partyId    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PartyId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_SplitCONFArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SplitCONFArg_sequence, hf_index, ett_isdn_sup_SplitCONFArg);

  return offset;
}



static int
dissect_isdn_sup_DropCONFArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PartyId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_IsolateCONFArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PartyId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_ReattachCONFArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PartyId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_PartyDISCArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PartyId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string isdn_sup_Procedure_vals[] = {
  {   0, "cfu" },
  {   1, "cfb" },
  {   2, "cfnr" },
  { 0, NULL }
};


static int
dissect_isdn_sup_Procedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string isdn_sup_ServedUserNr_vals[] = {
  {   0, "individualNumber" },
  {   1, "allNumbers" },
  { 0, NULL }
};

static const ber_choice_t ServedUserNr_choice[] = {
  {   0, &hf_isdn_sup_individualNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PartyNumber },
  {   1, &hf_isdn_sup_allNumbers , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ServedUserNr(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ServedUserNr_choice, hf_index, ett_isdn_sup_ServedUserNr,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_NoReplyTimer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ActivationDiversionArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_forwardedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { &hf_isdn_sup_noReplyTimer, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NoReplyTimer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ActivationDiversionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivationDiversionArg_sequence, hf_index, ett_isdn_sup_ActivationDiversionArg);

  return offset;
}


static const ber_sequence_t DeactivationDiversionArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DeactivationDiversionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeactivationDiversionArg_sequence, hf_index, ett_isdn_sup_DeactivationDiversionArg);

  return offset;
}


static const ber_sequence_t ActivationStatusNotificationDivArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_forwardedToAddresss, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ActivationStatusNotificationDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivationStatusNotificationDivArg_sequence, hf_index, ett_isdn_sup_ActivationStatusNotificationDivArg);

  return offset;
}


static const ber_sequence_t DeactivationStatusNotificationDivArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DeactivationStatusNotificationDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeactivationStatusNotificationDivArg_sequence, hf_index, ett_isdn_sup_DeactivationStatusNotificationDivArg);

  return offset;
}


static const ber_sequence_t InterrogationDiversionArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_InterrogationDiversionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InterrogationDiversionArg_sequence, hf_index, ett_isdn_sup_InterrogationDiversionArg);

  return offset;
}


static const ber_sequence_t IntResult_sequence[] = {
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_forwardedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_IntResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntResult_sequence, hf_index, ett_isdn_sup_IntResult);

  return offset;
}


static const ber_sequence_t IntResultList_set_of[1] = {
  { &hf_isdn_sup_IntResultList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_IntResult },
};

static int
dissect_isdn_sup_IntResultList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 IntResultList_set_of, hf_index, ett_isdn_sup_IntResultList);

  return offset;
}



static int
dissect_isdn_sup_InterrogationDiversionRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_IntResultList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ServedUserNumberList_set_of[1] = {
  { &hf_isdn_sup_ServedUserNumberList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
};

static int
dissect_isdn_sup_ServedUserNumberList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ServedUserNumberList_set_of, hf_index, ett_isdn_sup_ServedUserNumberList);

  return offset;
}



static int
dissect_isdn_sup_InterrogateServedUserNumbersRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_ServedUserNumberList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string isdn_sup_DiversionReason_vals[] = {
  {   0, "unknown" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfnr" },
  {   4, "cdAlerting" },
  {   5, "cdImmediate" },
  { 0, NULL }
};


static int
dissect_isdn_sup_DiversionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DiversionInformationArg_sequence[] = {
  { &hf_isdn_sup_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserSubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { &hf_isdn_sup_callingAddress, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedAddressScreened },
  { &hf_isdn_sup_originalCalledNr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_lastDivertingNr, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_lastDivertingReason, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_userInfo   , BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Q931InformationElement },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DiversionInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DiversionInformationArg_sequence, hf_index, ett_isdn_sup_DiversionInformationArg);

  return offset;
}


static const ber_sequence_t CallDeflectionArg_sequence[] = {
  { &hf_isdn_sup_deflectionAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_presentationAllowedDivertedToUser, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PresentationAllowedIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_CallDeflectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallDeflectionArg_sequence, hf_index, ett_isdn_sup_CallDeflectionArg);

  return offset;
}



static int
dissect_isdn_sup_DiversionCounter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_isdn_sup_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CallRerouteingArg_sequence[] = {
  { &hf_isdn_sup_rerouteingReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_calledAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_rerouteingCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionCounter },
  { &hf_isdn_sup_q931InfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Q931InformationElement },
  { &hf_isdn_sup_lastRerouteingNr, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_subscriptionOption, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_isdn_sup_SubscriptionOption },
  { &hf_isdn_sup_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_CallRerouteingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallRerouteingArg_sequence, hf_index, ett_isdn_sup_CallRerouteingArg);

  return offset;
}


static const ber_sequence_t DivertingLegInformation1Arg_sequence[] = {
  { &hf_isdn_sup_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_subscriptionOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_SubscriptionOption },
  { &hf_isdn_sup_divertedToNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DivertingLegInformation1Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DivertingLegInformation1Arg_sequence, hf_index, ett_isdn_sup_DivertingLegInformation1Arg);

  return offset;
}


static const ber_sequence_t DivertingLegInformation2Arg_sequence[] = {
  { &hf_isdn_sup_diversionCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionCounter },
  { &hf_isdn_sup_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_divertingNr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_originalCalledNr, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DivertingLegInformation2Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DivertingLegInformation2Arg_sequence, hf_index, ett_isdn_sup_DivertingLegInformation2Arg);

  return offset;
}



static int
dissect_isdn_sup_DivertingLegInformation3Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PresentationAllowedIndicator(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string isdn_sup_Service_vals[] = {
  {   1, "service1" },
  {   2, "service2" },
  {   3, "service3" },
  { 0, NULL }
};


static int
dissect_isdn_sup_Service(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_isdn_sup_Preferred(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserUserServiceArg_sequence[] = {
  { &hf_isdn_sup_service    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Service },
  { &hf_isdn_sup_preferred  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_Preferred },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_UserUserServiceArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserUserServiceArg_sequence, hf_index, ett_isdn_sup_UserUserServiceArg);

  return offset;
}



static int
dissect_isdn_sup_CalledFreephoneNr(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PartyNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_CalledFreephoneNrArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_CalledFreephoneNr(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_isdn_sup_QueueIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Monitor_T_FPHArg_sequence[] = {
  { &hf_isdn_sup_q931InfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Q931InformationElement },
  { &hf_isdn_sup_servedUserDestination, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
  { &hf_isdn_sup_queueIdentity, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_QueueIdentity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Monitor_T_FPHArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Monitor_T_FPHArg_sequence, hf_index, ett_isdn_sup_Monitor_T_FPHArg);

  return offset;
}



static int
dissect_isdn_sup_FPHReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Free_T_FPHArg_sequence[] = {
  { &hf_isdn_sup_servedUserDestination, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
  { &hf_isdn_sup_fPHReference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_FPHReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Free_T_FPHArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Free_T_FPHArg_sequence, hf_index, ett_isdn_sup_Free_T_FPHArg);

  return offset;
}


static const ber_sequence_t Call_T_FPHArg_sequence[] = {
  { &hf_isdn_sup_fPHReference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_FPHReference },
  { &hf_isdn_sup_calledFreephoneNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_CalledFreephoneNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Call_T_FPHArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Call_T_FPHArg_sequence, hf_index, ett_isdn_sup_Call_T_FPHArg);

  return offset;
}


static const value_string isdn_sup_PrecLevel_vals[] = {
  {   0, "flashOverride" },
  {   1, "flash" },
  {   2, "immediate" },
  {   3, "priority" },
  {   4, "routine" },
  { 0, NULL }
};


static int
dissect_isdn_sup_PrecLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string isdn_sup_LFBIndictn_vals[] = {
  {   0, "ifbAllowed" },
  {   1, "ifbNotAllowed" },
  {   2, "pathReserved" },
  { 0, NULL }
};


static int
dissect_isdn_sup_LFBIndictn(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_MLPPSvcDomn(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t MLPPParams_sequence[] = {
  { &hf_isdn_sup_precLevel  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PrecLevel },
  { &hf_isdn_sup_lfbIndictn , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_LFBIndictn },
  { &hf_isdn_sup_mlppSvcDomn, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_MLPPSvcDomn },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_MLPPParams(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MLPPParams_sequence, hf_index, ett_isdn_sup_MLPPParams);

  return offset;
}



static int
dissect_isdn_sup_IEArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_Q931InformationElement(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MLPPLFBArg_sequence[] = {
  { &hf_isdn_sup_mlppParams , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_MLPPParams },
  { &hf_isdn_sup_ieArg      , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_IEArg },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_MLPPLFBArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MLPPLFBArg_sequence, hf_index, ett_isdn_sup_MLPPLFBArg);

  return offset;
}


static const value_string isdn_sup_StatusQuery_vals[] = {
  {   1, "success" },
  {   2, "failure" },
  {   3, "bearerCapabilityNotAuthorized" },
  {   4, "bearerCapabilityNotlmplemented" },
  {   5, "bearerCapabilityNotAvailable" },
  {   6, "pathReservationDenied" },
  { 0, NULL }
};


static int
dissect_isdn_sup_StatusQuery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_Location(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_Q931InformationElement(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MLPPLFBResp_sequence[] = {
  { &hf_isdn_sup_statusQuery, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_StatusQuery },
  { &hf_isdn_sup_location   , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Location },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_MLPPLFBResp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MLPPLFBResp_sequence, hf_index, ett_isdn_sup_MLPPLFBResp);

  return offset;
}


static const value_string isdn_sup_StatusRequest_vals[] = {
  {   1, "successCalledUserMLPPSubscriber" },
  {   2, "successCalledUserNotMLPPSubscriber" },
  {   3, "failureCaseA" },
  {   4, "failureCaseB" },
  { 0, NULL }
};


static int
dissect_isdn_sup_StatusRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string isdn_sup_PreemptParams_vals[] = {
  {   1, "circuitReservedForReuse" },
  {   2, "circuitNotReservedForReuse" },
  { 0, NULL }
};


static int
dissect_isdn_sup_PreemptParams(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ChargingRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ChargingRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ChargingRequestArg_PDU);
  return offset;
}
static int dissect_ChargingRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ChargingRequestRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ChargingRequestRes_PDU);
  return offset;
}
static int dissect_AOCSCurrencyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AOCSCurrencyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AOCSCurrencyArg_PDU);
  return offset;
}
static int dissect_AOCSSpecialArrArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AOCSSpecialArrArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AOCSSpecialArrArg_PDU);
  return offset;
}
static int dissect_AOCDCurrencyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AOCDCurrencyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AOCDCurrencyArg_PDU);
  return offset;
}
static int dissect_AOCDChargingUnitArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AOCDChargingUnitArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AOCDChargingUnitArg_PDU);
  return offset;
}
static int dissect_AOCECurrencyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AOCECurrencyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AOCECurrencyArg_PDU);
  return offset;
}
static int dissect_AOCEChargingUnitArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AOCEChargingUnitArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AOCEChargingUnitArg_PDU);
  return offset;
}
static int dissect_CUGcallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_CUGcallArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_CUGcallArg_PDU);
  return offset;
}
static int dissect_BeginCONFArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_BeginCONFArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_BeginCONFArg_PDU);
  return offset;
}
static int dissect_BeginCONFRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_BeginCONFRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_BeginCONFRes_PDU);
  return offset;
}
static int dissect_AddCONFArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AddCONFArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AddCONFArg_PDU);
  return offset;
}
static int dissect_AddCONFRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_AddCONFRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_AddCONFRes_PDU);
  return offset;
}
static int dissect_SplitCONFArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_SplitCONFArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_SplitCONFArg_PDU);
  return offset;
}
static int dissect_DropCONFArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DropCONFArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DropCONFArg_PDU);
  return offset;
}
static int dissect_IsolateCONFArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_IsolateCONFArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_IsolateCONFArg_PDU);
  return offset;
}
static int dissect_ReattachCONFArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ReattachCONFArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ReattachCONFArg_PDU);
  return offset;
}
static int dissect_PartyDISCArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_PartyDISCArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_PartyDISCArg_PDU);
  return offset;
}
static int dissect_ActivationDiversionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ActivationDiversionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ActivationDiversionArg_PDU);
  return offset;
}
static int dissect_DeactivationDiversionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DeactivationDiversionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DeactivationDiversionArg_PDU);
  return offset;
}
static int dissect_ActivationStatusNotificationDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ActivationStatusNotificationDivArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ActivationStatusNotificationDivArg_PDU);
  return offset;
}
static int dissect_DeactivationStatusNotificationDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DeactivationStatusNotificationDivArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DeactivationStatusNotificationDivArg_PDU);
  return offset;
}
static int dissect_InterrogationDiversionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_InterrogationDiversionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_InterrogationDiversionArg_PDU);
  return offset;
}
static int dissect_InterrogationDiversionRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_InterrogationDiversionRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_InterrogationDiversionRes_PDU);
  return offset;
}
static int dissect_InterrogateServedUserNumbersRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_InterrogateServedUserNumbersRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_InterrogateServedUserNumbersRes_PDU);
  return offset;
}
static int dissect_DiversionInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DiversionInformationArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DiversionInformationArg_PDU);
  return offset;
}
static int dissect_CallDeflectionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_CallDeflectionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_CallDeflectionArg_PDU);
  return offset;
}
static int dissect_CallRerouteingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_CallRerouteingArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_CallRerouteingArg_PDU);
  return offset;
}
static int dissect_DivertingLegInformation1Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DivertingLegInformation1Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DivertingLegInformation1Arg_PDU);
  return offset;
}
static int dissect_DivertingLegInformation2Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DivertingLegInformation2Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DivertingLegInformation2Arg_PDU);
  return offset;
}
static int dissect_DivertingLegInformation3Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DivertingLegInformation3Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DivertingLegInformation3Arg_PDU);
  return offset;
}
static int dissect_UserUserServiceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_UserUserServiceArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_UserUserServiceArg_PDU);
  return offset;
}
static int dissect_CalledFreephoneNrArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_CalledFreephoneNrArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_CalledFreephoneNrArg_PDU);
  return offset;
}
static int dissect_Monitor_T_FPHArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_Monitor_T_FPHArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_Monitor_T_FPHArg_PDU);
  return offset;
}
static int dissect_Free_T_FPHArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_Free_T_FPHArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_Free_T_FPHArg_PDU);
  return offset;
}
static int dissect_Call_T_FPHArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_Call_T_FPHArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_Call_T_FPHArg_PDU);
  return offset;
}
static int dissect_MLPPLFBArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_MLPPLFBArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_MLPPLFBArg_PDU);
  return offset;
}
static int dissect_MLPPLFBResp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_MLPPLFBResp(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_MLPPLFBResp_PDU);
  return offset;
}
static int dissect_MLPPParams_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_MLPPParams(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_MLPPParams_PDU);
  return offset;
}
static int dissect_StatusRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_StatusRequest(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_StatusRequest_PDU);
  return offset;
}
static int dissect_PreemptParams_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_PreemptParams(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_PreemptParams_PDU);
  return offset;
}


/*--- End of included file: packet-isdn-sup-fn.c ---*/
#line 102 "./asn1/isdn-sup/packet-isdn-sup-template.c"

static const isdn_sup_op_t isdn_sup_op_tab[] = {

/*--- Included file: packet-isdn-sup-table11.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-table11.c"
  /* chargingRequest          */ {  30, dissect_ChargingRequestArg_PDU, dissect_ChargingRequestRes_PDU },
  /* aOCSCurrency             */ {  31, dissect_AOCSCurrencyArg_PDU, NULL },
  /* aOCSSpecialArr           */ {  32, dissect_AOCSSpecialArrArg_PDU, NULL },
  /* aOCDCurrency             */ {  33, dissect_AOCDCurrencyArg_PDU, NULL },
  /* aOCDChargingUnit         */ {  34, dissect_AOCDChargingUnitArg_PDU, NULL },
  /* aOCECurrency             */ {  35, dissect_AOCECurrencyArg_PDU, NULL },
  /* aOCEChargingUnit         */ {  36, dissect_AOCEChargingUnitArg_PDU, NULL },
  /* cUGcall                  */ {   2, dissect_CUGcallArg_PDU, NULL },
  /* beginCONF                */ {  40, dissect_BeginCONFArg_PDU, dissect_BeginCONFRes_PDU },
  /* addCONF                  */ {  41, dissect_AddCONFArg_PDU, dissect_AddCONFRes_PDU },
  /* splitCONF                */ {  42, dissect_SplitCONFArg_PDU, NULL },
  /* dropCONF                 */ {  43, dissect_DropCONFArg_PDU, NULL },
  /* isolateCONF              */ {  44, dissect_IsolateCONFArg_PDU, NULL },
  /* reattachCONF             */ {  45, dissect_ReattachCONFArg_PDU, NULL },
  /* partyDISC                */ {  46, dissect_PartyDISCArg_PDU, NULL },
  /* activationDiversion      */ {   7, dissect_ActivationDiversionArg_PDU, NULL },
  /* deactivationDiversion    */ {   8, dissect_DeactivationDiversionArg_PDU, NULL },
  /* activationStatusNotificationDiv */ {   9, dissect_ActivationStatusNotificationDivArg_PDU, NULL },
  /* deactivationStatusNotificationDiv */ {  10, dissect_DeactivationStatusNotificationDivArg_PDU, NULL },
  /* interrogationDiversion   */ {  11, dissect_InterrogationDiversionArg_PDU, dissect_InterrogationDiversionRes_PDU },
  /* interrogateServedUserNumbers */ {  17, NULL, dissect_InterrogateServedUserNumbersRes_PDU },
  /* diversionInformation     */ {  12, dissect_DiversionInformationArg_PDU, NULL },
  /* callDeflection           */ {  13, dissect_CallDeflectionArg_PDU, NULL },
  /* callRerouteing           */ {  14, dissect_CallRerouteingArg_PDU, NULL },
  /* divertingLegInformation1 */ {  18, dissect_DivertingLegInformation1Arg_PDU, NULL },
  /* divertingLegInformation2 */ {  15, dissect_DivertingLegInformation2Arg_PDU, NULL },
  /* divertingLegInformation3 */ {  19, dissect_DivertingLegInformation3Arg_PDU, NULL },
  /* mCIDRequest              */ {   3, NULL, NULL },
  /* userUserService          */ {   1, dissect_UserUserServiceArg_PDU, NULL },
  /* mLPPLFBQuery             */ {  24, dissect_MLPPLFBArg_PDU, dissect_MLPPLFBResp_PDU },
  /* mLPPCallRequest          */ {  25, dissect_MLPPParams_PDU, dissect_StatusRequest_PDU },
  /* mLPPCallPreemption       */ {  26, dissect_PreemptParams_PDU, NULL },

/*--- End of included file: packet-isdn-sup-table11.c ---*/
#line 105 "./asn1/isdn-sup/packet-isdn-sup-template.c"
};


static const isdn_sup_global_op_t isdn_sup_global_op_tab[] = {


/*--- Included file: packet-isdn-sup-table31.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-table31.c"
  /* callFPH                  */ { fPHOID".1", dissect_CalledFreephoneNrArg_PDU, NULL },
  /* monitor-T-FPH            */ { fPHOID".2", dissect_Monitor_T_FPHArg_PDU, NULL },
  /* free-T-FPH               */ { fPHOID".3", dissect_Free_T_FPHArg_PDU, NULL },
  /* call-T-FPH               */ { fPHOID".4", dissect_Call_T_FPHArg_PDU, NULL },

/*--- End of included file: packet-isdn-sup-table31.c ---*/
#line 111 "./asn1/isdn-sup/packet-isdn-sup-template.c"
};

static const isdn_sup_err_t isdn_sup_err_tab[] = {

/*--- Included file: packet-isdn-sup-table21.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-table21.c"
  /* notSubscribed            */ {    0, NULL },
  /* notAvailable             */ {    3, NULL },
  /* notImplemented           */ {    4, NULL },
  /* invalidServedUserNr      */ {    6, NULL },
  /* invalidCallState         */ {    7, NULL },
  /* basicServiceNotProvided  */ {    8, NULL },
  /* notIncomingCall          */ {    9, NULL },
  /* supplementaryServiceInteractionNotAllowed */ {   10, NULL },
  /* resourceUnavailable      */ {   11, NULL },
  /* noChargingInfoAvailable  */ {   26, NULL },
  /* invalidOrUnregisteredCUGIndex */ {   16, NULL },
  /* requestedBasicServiceViolatesCUGConstraints */ {   17, NULL },
  /* outgoingCallsBarredWithinCUG */ {   18, NULL },
  /* incomingCallsBarredWithinCUG */ {   19, NULL },
  /* userNotMemberOfCUG       */ {   20, NULL },
  /* inconsistencyInDesignatedFacilityAndSubscriberClass */ {   21, NULL },
  /* illConferenceId          */ {   28, NULL },
  /* illPartyId               */ {   29, NULL },
  /* numberOfPartiesExceeded  */ {   30, NULL },
  /* notActive                */ {   31, NULL },
  /* notAllowed               */ {   32, NULL },
  /* invalidDivertedToNr      */ {   12, NULL },
  /* specialServiceNr         */ {   14, NULL },
  /* diversionToServedUserNr  */ {   15, NULL },
  /* incomingCallAccepted     */ {   23, NULL },
  /* numberOfDiversionsExceeded */ {   24, NULL },
  /* notActivated             */ {   46, NULL },
  /* requestAlreadyAccepted   */ {   48, NULL },
  /* rejectedByTheNetwork     */ {    1, NULL },
  /* rejectedByTheUser        */ {    2, NULL },
  /* unauthorizedPrecedenceLevel */ {   44, NULL },

/*--- End of included file: packet-isdn-sup-table21.c ---*/
#line 115 "./asn1/isdn-sup/packet-isdn-sup-template.c"
};


static const isdn_sup_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(isdn_sup_op_tab) - 1; i >= 0; i--)
    if (isdn_sup_op_tab[i].opcode == opcode)
      return &isdn_sup_op_tab[i];
  return NULL;
}

static const isdn_sup_err_t *get_err(gint32 errcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(isdn_sup_err_tab) - 1; i >= 0; i--)
    if (isdn_sup_err_tab[i].errcode == errcode)
      return &isdn_sup_err_tab[i];
  return NULL;
}

/*--- dissect_isdn_sup_arg ------------------------------------------------------*/
static int
dissect_isdn_sup_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code == 0) {  /* local */
    opcode = rctx->d.code_local;
  } else {
    return offset;
  }
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, -1, ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_expert(tree, pinfo, &ei_isdn_sup_unsupported_error_type, tvb, offset, -1);
      offset += tvb_reported_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_isdn_sup_res -------------------------------------------------------*/
static int
dissect_isdn_sup_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  gint offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

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

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, -1, ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_expert(tree, pinfo, &ei_isdn_sup_unsupported_result_type, tvb, offset, -1);
      offset += tvb_reported_length_remaining(tvb, offset);
    }

  return offset;
}


/*--- dissect_isdn_sup_err ------------------------------------------------------*/
static int
dissect_isdn_sup_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 errcode;
  const isdn_sup_err_t *err_ptr;
  const gchar *p;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

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

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, -1, ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_error, tvb, 0, 0, errcode);
  p = try_val_to_str(errcode, VALS(isdn_sup_str_error));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu)
    offset = err_ptr->err_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_expert(tree, pinfo, &ei_isdn_sup_unsupported_error_type, tvb, offset, -1);
      offset += tvb_reported_length_remaining(tvb, offset);
    }

  return offset;
}


/*--- proto_reg_handoff_isdn_sup ---------------------------------------*/

void proto_reg_handoff_isdn_sup(void) {
  int i;
#if 0
  dissector_handle_t q931_handle;
#endif
  dissector_handle_t isdn_sup_arg_handle;
  dissector_handle_t isdn_sup_res_handle;
  dissector_handle_t isdn_sup_err_handle;

#if 0
  q931_handle = find_dissector("q931");
#endif

  isdn_sup_arg_handle = create_dissector_handle(dissect_isdn_sup_arg, proto_isdn_sup);
  isdn_sup_res_handle = create_dissector_handle(dissect_isdn_sup_res, proto_isdn_sup);
  for (i=0; i<(int)array_length(isdn_sup_op_tab); i++) {
    dissector_add_uint("q932.ros.etsi.local.arg", isdn_sup_op_tab[i].opcode, isdn_sup_arg_handle);
    dissector_add_uint("q932.ros.etsi.local.res", isdn_sup_op_tab[i].opcode, isdn_sup_res_handle);
  }

  for (i=0; i<(int)array_length(isdn_sup_global_op_tab); i++) {
	  if(isdn_sup_global_op_tab->arg_pdu)
		  dissector_add_string("q932.ros.global.arg", isdn_sup_global_op_tab[i].oid, create_dissector_handle(isdn_sup_global_op_tab[i].arg_pdu, proto_isdn_sup));
	  if(isdn_sup_global_op_tab->res_pdu)
		  dissector_add_string("q932.ros.global.res", isdn_sup_global_op_tab[i].oid, create_dissector_handle(isdn_sup_global_op_tab[i].res_pdu, proto_isdn_sup));
  }

  isdn_sup_err_handle = create_dissector_handle(dissect_isdn_sup_err, proto_isdn_sup);

  for (i=0; i<(int)array_length(isdn_sup_err_tab); i++) {
    dissector_add_uint("q932.ros.etsi.local.err", isdn_sup_err_tab[i].errcode, isdn_sup_err_handle);
  }


}

void proto_register_isdn_sup(void) {

	/* List of fields */
  static hf_register_info hf[] = {
    { &hf_isdn_sup,
      { "isdn_sup", "isdn_sup.1",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
	},
    { &hf_isdn_sup_operation,
	  { "Operation", "isdn_sup.operation",
        FT_UINT8, BASE_DEC, VALS(isdn_sup_str_operation), 0x0,
        NULL, HFILL }
	},
    { &hf_isdn_sup_error,
	  { "Error", "isdn_sup.error",
        FT_UINT8, BASE_DEC, VALS(isdn_sup_str_error), 0x0,
        NULL, HFILL }
	},


/*--- Included file: packet-isdn-sup-hfarr.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-hfarr.c"
    { &hf_isdn_sup_ChargingRequestArg_PDU,
      { "ChargingRequestArg", "isdn-sup.ChargingRequestArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ChargingCase_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ChargingRequestRes_PDU,
      { "ChargingRequestRes", "isdn-sup.ChargingRequestRes",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ChargingRequestRes_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCSCurrencyArg_PDU,
      { "AOCSCurrencyArg", "isdn-sup.AOCSCurrencyArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCSCurrencyArg_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCSSpecialArrArg_PDU,
      { "AOCSSpecialArrArg", "isdn-sup.AOCSSpecialArrArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCSSpecialArrArg_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCDCurrencyArg_PDU,
      { "AOCDCurrencyArg", "isdn-sup.AOCDCurrencyArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCDCurrencyArg_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCDChargingUnitArg_PDU,
      { "AOCDChargingUnitArg", "isdn-sup.AOCDChargingUnitArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCDChargingUnitArg_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCECurrencyArg_PDU,
      { "AOCECurrencyArg", "isdn-sup.AOCECurrencyArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCECurrencyArg_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCEChargingUnitArg_PDU,
      { "AOCEChargingUnitArg", "isdn-sup.AOCEChargingUnitArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCEChargingUnitArg_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_CUGcallArg_PDU,
      { "CUGcallArg", "isdn-sup.CUGcallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_BeginCONFArg_PDU,
      { "BeginCONFArg", "isdn-sup.BeginCONFArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_BeginCONFRes_PDU,
      { "BeginCONFRes", "isdn-sup.BeginCONFRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AddCONFArg_PDU,
      { "AddCONFArg", "isdn-sup.AddCONFArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AddCONFRes_PDU,
      { "AddCONFRes", "isdn-sup.AddCONFRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_SplitCONFArg_PDU,
      { "SplitCONFArg", "isdn-sup.SplitCONFArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DropCONFArg_PDU,
      { "DropCONFArg", "isdn-sup.DropCONFArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_IsolateCONFArg_PDU,
      { "IsolateCONFArg", "isdn-sup.IsolateCONFArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ReattachCONFArg_PDU,
      { "ReattachCONFArg", "isdn-sup.ReattachCONFArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_PartyDISCArg_PDU,
      { "PartyDISCArg", "isdn-sup.PartyDISCArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ActivationDiversionArg_PDU,
      { "ActivationDiversionArg", "isdn-sup.ActivationDiversionArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DeactivationDiversionArg_PDU,
      { "DeactivationDiversionArg", "isdn-sup.DeactivationDiversionArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ActivationStatusNotificationDivArg_PDU,
      { "ActivationStatusNotificationDivArg", "isdn-sup.ActivationStatusNotificationDivArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DeactivationStatusNotificationDivArg_PDU,
      { "DeactivationStatusNotificationDivArg", "isdn-sup.DeactivationStatusNotificationDivArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_InterrogationDiversionArg_PDU,
      { "InterrogationDiversionArg", "isdn-sup.InterrogationDiversionArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_InterrogationDiversionRes_PDU,
      { "InterrogationDiversionRes", "isdn-sup.InterrogationDiversionRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_InterrogateServedUserNumbersRes_PDU,
      { "InterrogateServedUserNumbersRes", "isdn-sup.InterrogateServedUserNumbersRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DiversionInformationArg_PDU,
      { "DiversionInformationArg", "isdn-sup.DiversionInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_CallDeflectionArg_PDU,
      { "CallDeflectionArg", "isdn-sup.CallDeflectionArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_CallRerouteingArg_PDU,
      { "CallRerouteingArg", "isdn-sup.CallRerouteingArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DivertingLegInformation1Arg_PDU,
      { "DivertingLegInformation1Arg", "isdn-sup.DivertingLegInformation1Arg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DivertingLegInformation2Arg_PDU,
      { "DivertingLegInformation2Arg", "isdn-sup.DivertingLegInformation2Arg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DivertingLegInformation3Arg_PDU,
      { "DivertingLegInformation3Arg", "isdn-sup.DivertingLegInformation3Arg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_UserUserServiceArg_PDU,
      { "UserUserServiceArg", "isdn-sup.UserUserServiceArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_CalledFreephoneNrArg_PDU,
      { "CalledFreephoneNrArg", "isdn-sup.CalledFreephoneNrArg",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_Monitor_T_FPHArg_PDU,
      { "Monitor-T-FPHArg", "isdn-sup.Monitor_T_FPHArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_Free_T_FPHArg_PDU,
      { "Free-T-FPHArg", "isdn-sup.Free_T_FPHArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_Call_T_FPHArg_PDU,
      { "Call-T-FPHArg", "isdn-sup.Call_T_FPHArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_MLPPLFBArg_PDU,
      { "MLPPLFBArg", "isdn-sup.MLPPLFBArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_MLPPLFBResp_PDU,
      { "MLPPLFBResp", "isdn-sup.MLPPLFBResp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_MLPPParams_PDU,
      { "MLPPParams", "isdn-sup.MLPPParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_StatusRequest_PDU,
      { "StatusRequest", "isdn-sup.StatusRequest",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_StatusRequest_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_PreemptParams_PDU,
      { "PreemptParams", "isdn-sup.PreemptParams",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PreemptParams_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_presentationallowedaddressscreened,
      { "presentationAllowedAddress", "isdn-sup.presentationAllowedAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_isdn_sup_presentationRestricted,
      { "presentationRestricted", "isdn-sup.presentationRestricted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_numberNotAvailableDueToInterworking,
      { "numberNotAvailableDueToInterworking", "isdn-sup.numberNotAvailableDueToInterworking_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_presentationrestrictedaddressscreened,
      { "presentationRestrictedAddress", "isdn-sup.presentationRestrictedAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_isdn_sup_presentationAllowedAddress,
      { "presentationAllowedAddress", "isdn-sup.presentationAllowedAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "isdn-sup.presentationRestrictedAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_presentationallowednumberscreened,
      { "presentationAllowedNumber", "isdn-sup.presentationAllowedNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_isdn_sup_presentationrestrictednumberscreened,
      { "presentationRestrictedNumber", "isdn-sup.presentationRestrictedNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_isdn_sup_presentationAllowedNumber,
      { "presentationAllowedNumber", "isdn-sup.presentationAllowedNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_presentationRestrictedNumber,
      { "presentationRestrictedNumber", "isdn-sup.presentationRestrictedNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_partyNumber,
      { "partyNumber", "isdn-sup.partyNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_screeningIndicator,
      { "screeningIndicator", "isdn-sup.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ScreeningIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_partySubaddress,
      { "partySubaddress", "isdn-sup.partySubaddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartySubaddress_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_unknownPartyNumber,
      { "unknownPartyNumber", "isdn-sup.unknownPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_publicPartyNumber,
      { "publicPartyNumber", "isdn-sup.publicPartyNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_nsapEncodedNumber,
      { "nsapEncodedNumber", "isdn-sup.nsapEncodedNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_dataPartyNumber,
      { "dataPartyNumber", "isdn-sup.dataPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_telexPartyNumber,
      { "telexPartyNumber", "isdn-sup.telexPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_privatePartyNumber,
      { "privatePartyNumber", "isdn-sup.privatePartyNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_nationalStandardPartyNumber,
      { "nationalStandardPartyNumber", "isdn-sup.nationalStandardPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_publicTypeOfNumber,
      { "publicTypeOfNumber", "isdn-sup.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PublicTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_publicNumberDigits,
      { "publicNumberDigits", "isdn-sup.publicNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_privateTypeOfNumber,
      { "privateTypeOfNumber", "isdn-sup.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PrivateTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_privateNumberDigits,
      { "privateNumberDigits", "isdn-sup.privateNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "isdn-sup.userSpecifiedSubaddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_nSAPSubaddress,
      { "nSAPSubaddress", "isdn-sup.nSAPSubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_subaddressInformation,
      { "subaddressInformation", "isdn-sup.subaddressInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_oddCountIndicator,
      { "oddCountIndicator", "isdn-sup.oddCountIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_isdn_sup_aOCSCurrencyInfoList,
      { "aOCSCurrencyInfoList", "isdn-sup.aOCSCurrencyInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aOCSSpecialArrInfo,
      { "aOCSSpecialArrInfo", "isdn-sup.aOCSSpecialArrInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_chargingInfoFollows,
      { "chargingInfoFollows", "isdn-sup.chargingInfoFollows_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_chargeNotAvailable,
      { "chargeNotAvailable", "isdn-sup.chargeNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aOCDCurrencyInfo,
      { "aOCDCurrencyInfo", "isdn-sup.aOCDCurrencyInfo",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCDCurrencyInfo_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aOCDChargingUnitInfo,
      { "aOCDChargingUnitInfo", "isdn-sup.aOCDChargingUnitInfo",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCDChargingUnitInfo_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aOCECurrencyInfo,
      { "aOCECurrencyInfo", "isdn-sup.aOCECurrencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aOCEChargingUnitInfo,
      { "aOCEChargingUnitInfo", "isdn-sup.aOCEChargingUnitInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_AOCSCurrencyInfoList_item,
      { "AOCSCurrencyInfo", "isdn-sup.AOCSCurrencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_chargedItem,
      { "chargedItem", "isdn-sup.chargedItem",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ChargedItem_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_chargingtype,
      { "chargingtype", "isdn-sup.chargingtype",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_T_chargingtype_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aocschargingtypespecificCurrency,
      { "specificCurrency", "isdn-sup.specificCurrency",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCSChargingTypeSpecificCurrency_vals), 0,
        "AOCSChargingTypeSpecificCurrency", HFILL }},
    { &hf_isdn_sup_durationCurrency,
      { "durationCurrency", "isdn-sup.durationCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_flatRateCurrency,
      { "flatRateCurrency", "isdn-sup.flatRateCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_volumeRateCurrency,
      { "volumeRateCurrency", "isdn-sup.volumeRateCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_specialChargingCode,
      { "specialChargingCode", "isdn-sup.specialChargingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_freeOfCharge,
      { "freeOfCharge", "isdn-sup.freeOfCharge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_currencyInfoNotAvailable,
      { "currencyInfoNotAvailable", "isdn-sup.currencyInfoNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_dCurrency,
      { "dCurrency", "isdn-sup.dCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_isdn_sup_dAmount,
      { "dAmount", "isdn-sup.dAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_isdn_sup_dChargingType,
      { "dChargingType", "isdn-sup.dChargingType",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ChargingType_vals), 0,
        "ChargingType", HFILL }},
    { &hf_isdn_sup_dTime,
      { "dTime", "isdn-sup.dTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_isdn_sup_dGranularity,
      { "dGranularity", "isdn-sup.dGranularity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_isdn_sup_fRCurrency,
      { "fRCurrency", "isdn-sup.fRCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_isdn_sup_fRAmount,
      { "fRAmount", "isdn-sup.fRAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_isdn_sup_vRCurrency,
      { "vRCurrency", "isdn-sup.vRCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_isdn_sup_vRAmount,
      { "vRAmount", "isdn-sup.vRAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_isdn_sup_vRVolumeUnit,
      { "vRVolumeUnit", "isdn-sup.vRVolumeUnit",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_VolumeUnit_vals), 0,
        "VolumeUnit", HFILL }},
    { &hf_isdn_sup_aocdspecificCurrency,
      { "specificCurrency", "isdn-sup.specificCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AOCDSpecificCurrency", HFILL }},
    { &hf_isdn_sup_recordedCurrency,
      { "recordedCurrency", "isdn-sup.recordedCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_typeOfChargingInfo,
      { "typeOfChargingInfo", "isdn-sup.typeOfChargingInfo",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_TypeOfChargingInfo_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aOCDBillingId,
      { "aOCDBillingId", "isdn-sup.aOCDBillingId",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCDBillingId_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aocdspecificchargingunits,
      { "specificChargingUnits", "isdn-sup.specificChargingUnits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AOCDSpecificChargingUnits", HFILL }},
    { &hf_isdn_sup_recordedUnitsList,
      { "recordedUnitsList", "isdn-sup.recordedUnitsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_rCurrency,
      { "rCurrency", "isdn-sup.rCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_isdn_sup_rAmount,
      { "rAmount", "isdn-sup.rAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_isdn_sup_RecordedUnitsList_item,
      { "RecordedUnits", "isdn-sup.RecordedUnits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_recoredunitscc,
      { "cc", "isdn-sup.cc",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_RecoredUnitsCc_vals), 0,
        "RecoredUnitsCc", HFILL }},
    { &hf_isdn_sup_recordedNumberOfUnits,
      { "recordedNumberOfUnits", "isdn-sup.recordedNumberOfUnits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NumberOfUnits", HFILL }},
    { &hf_isdn_sup_notAvailable,
      { "notAvailable", "isdn-sup.notAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_recordedTypeOfUnits,
      { "recordedTypeOfUnits", "isdn-sup.recordedTypeOfUnits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TypeOfUnit", HFILL }},
    { &hf_isdn_sup_aocecurrencycc,
      { "cc", "isdn-sup.cc",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCECurrencyCc_vals), 0,
        "AOCECurrencyCc", HFILL }},
    { &hf_isdn_sup_aoceccspecificCurrency,
      { "specificCurrency", "isdn-sup.specificCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AOCECcSpecificCurrency", HFILL }},
    { &hf_isdn_sup_aOCEBillingId,
      { "aOCEBillingId", "isdn-sup.aOCEBillingId",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCEBillingId_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_chargingAssociation,
      { "chargingAssociation", "isdn-sup.chargingAssociation",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ChargingAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_aocechargingunitcc,
      { "cc", "isdn-sup.cc",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_AOCEChargingUnitCc_vals), 0,
        "AOCEChargingUnitCc", HFILL }},
    { &hf_isdn_sup_aoceccspecificchargingunits,
      { "specificChargingUnits", "isdn-sup.specificChargingUnits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AOCECcSpecificChargingUnits", HFILL }},
    { &hf_isdn_sup_currencyAmount,
      { "currencyAmount", "isdn-sup.currencyAmount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_multiplier,
      { "multiplier", "isdn-sup.multiplier",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_Multiplier_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_lengthOfTimeUnit,
      { "lengthOfTimeUnit", "isdn-sup.lengthOfTimeUnit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_scale,
      { "scale", "isdn-sup.scale",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_Scale_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_chargeNumber,
      { "chargeNumber", "isdn-sup.chargeNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_chargeIdentifier,
      { "chargeIdentifier", "isdn-sup.chargeIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_oARequested,
      { "oARequested", "isdn-sup.oARequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_cUGIndex,
      { "cUGIndex", "isdn-sup.cUGIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_conferenceId,
      { "conferenceId", "isdn-sup.conferenceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_partyId,
      { "partyId", "isdn-sup.partyId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_procedure,
      { "procedure", "isdn-sup.procedure",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_Procedure_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_basicService,
      { "basicService", "isdn-sup.basicService",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_forwardedToAddress,
      { "forwardedToAddress", "isdn-sup.forwardedToAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_servedUserNr,
      { "servedUserNr", "isdn-sup.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ServedUserNr_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_noReplyTimer,
      { "noReplyTimer", "isdn-sup.noReplyTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_forwardedToAddresss,
      { "forwardedToAddresss", "isdn-sup.forwardedToAddresss_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_diversionReason,
      { "diversionReason", "isdn-sup.diversionReason",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_DiversionReason_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_servedUserSubaddress,
      { "servedUserSubaddress", "isdn-sup.servedUserSubaddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_isdn_sup_callingAddress,
      { "callingAddress", "isdn-sup.callingAddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedAddressScreened_vals), 0,
        "PresentedAddressScreened", HFILL }},
    { &hf_isdn_sup_originalCalledNr,
      { "originalCalledNr", "isdn-sup.originalCalledNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_lastDivertingNr,
      { "lastDivertingNr", "isdn-sup.lastDivertingNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_lastDivertingReason,
      { "lastDivertingReason", "isdn-sup.lastDivertingReason",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_isdn_sup_userInfo,
      { "userInfo", "isdn-sup.userInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Q931InformationElement", HFILL }},
    { &hf_isdn_sup_deflectionAddress,
      { "deflectionAddress", "isdn-sup.deflectionAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_presentationAllowedDivertedToUser,
      { "presentationAllowedDivertedToUser", "isdn-sup.presentationAllowedDivertedToUser",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PresentationAllowedIndicator", HFILL }},
    { &hf_isdn_sup_rerouteingReason,
      { "rerouteingReason", "isdn-sup.rerouteingReason",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_isdn_sup_calledAddress,
      { "calledAddress", "isdn-sup.calledAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_rerouteingCounter,
      { "rerouteingCounter", "isdn-sup.rerouteingCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DiversionCounter", HFILL }},
    { &hf_isdn_sup_q931InfoElement,
      { "q931InfoElement", "isdn-sup.q931InfoElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Q931InformationElement", HFILL }},
    { &hf_isdn_sup_lastRerouteingNr,
      { "lastRerouteingNr", "isdn-sup.lastRerouteingNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_subscriptionOption,
      { "subscriptionOption", "isdn-sup.subscriptionOption",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_SubscriptionOption_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_callingPartySubaddress,
      { "callingPartySubaddress", "isdn-sup.callingPartySubaddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_isdn_sup_divertedToNumber,
      { "divertedToNumber", "isdn-sup.divertedToNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_diversionCounter,
      { "diversionCounter", "isdn-sup.diversionCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_divertingNr,
      { "divertingNr", "isdn-sup.divertingNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_IntResultList_item,
      { "IntResult", "isdn-sup.IntResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_individualNumber,
      { "individualNumber", "isdn-sup.individualNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_allNumbers,
      { "allNumbers", "isdn-sup.allNumbers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ServedUserNumberList_item,
      { "PartyNumber", "isdn-sup.PartyNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_service,
      { "service", "isdn-sup.service",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_Service_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_preferred,
      { "preferred", "isdn-sup.preferred",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_servedUserDestination,
      { "servedUserDestination", "isdn-sup.servedUserDestination",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_queueIdentity,
      { "queueIdentity", "isdn-sup.queueIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_fPHReference,
      { "fPHReference", "isdn-sup.fPHReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_calledFreephoneNr,
      { "calledFreephoneNr", "isdn-sup.calledFreephoneNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_mlppParams,
      { "mlppParams", "isdn-sup.mlppParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ieArg,
      { "ieArg", "isdn-sup.ieArg",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_precLevel,
      { "precLevel", "isdn-sup.precLevel",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PrecLevel_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_lfbIndictn,
      { "lfbIndictn", "isdn-sup.lfbIndictn",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_LFBIndictn_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_mlppSvcDomn,
      { "mlppSvcDomn", "isdn-sup.mlppSvcDomn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_statusQuery,
      { "statusQuery", "isdn-sup.statusQuery",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_StatusQuery_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_location,
      { "location", "isdn-sup.location",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-isdn-sup-hfarr.c ---*/
#line 348 "./asn1/isdn-sup/packet-isdn-sup-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_isdn_sup,


/*--- Included file: packet-isdn-sup-ettarr.c ---*/
#line 1 "./asn1/isdn-sup/packet-isdn-sup-ettarr.c"
    &ett_isdn_sup_PresentedAddressScreened,
    &ett_isdn_sup_PresentedAddressUnscreened,
    &ett_isdn_sup_PresentedNumberScreened,
    &ett_isdn_sup_PresentedNumberUnscreened,
    &ett_isdn_sup_AddressScreened,
    &ett_isdn_sup_NumberScreened,
    &ett_isdn_sup_Address,
    &ett_isdn_sup_PartyNumber,
    &ett_isdn_sup_PublicPartyNumber,
    &ett_isdn_sup_PrivatePartyNumber,
    &ett_isdn_sup_PartySubaddress,
    &ett_isdn_sup_UserSpecifiedSubaddress,
    &ett_isdn_sup_ChargingRequestRes,
    &ett_isdn_sup_AOCSCurrencyArg,
    &ett_isdn_sup_AOCSSpecialArrArg,
    &ett_isdn_sup_AOCDCurrencyArg,
    &ett_isdn_sup_AOCDChargingUnitArg,
    &ett_isdn_sup_AOCECurrencyArg,
    &ett_isdn_sup_AOCEChargingUnitArg,
    &ett_isdn_sup_AOCSCurrencyInfoList,
    &ett_isdn_sup_AOCSCurrencyInfo,
    &ett_isdn_sup_T_chargingtype,
    &ett_isdn_sup_AOCSChargingTypeSpecificCurrency,
    &ett_isdn_sup_DurationCurrency,
    &ett_isdn_sup_FlatRateCurrency,
    &ett_isdn_sup_VolumeRateCurrency,
    &ett_isdn_sup_AOCDCurrencyInfo,
    &ett_isdn_sup_AOCDSpecificCurrency,
    &ett_isdn_sup_AOCDChargingUnitInfo,
    &ett_isdn_sup_AOCDSpecificChargingUnits,
    &ett_isdn_sup_RecordedCurrency,
    &ett_isdn_sup_RecordedUnitsList,
    &ett_isdn_sup_RecordedUnits,
    &ett_isdn_sup_RecoredUnitsCc,
    &ett_isdn_sup_AOCECurrencyInfo,
    &ett_isdn_sup_AOCECurrencyCc,
    &ett_isdn_sup_AOCECcSpecificCurrency,
    &ett_isdn_sup_AOCEChargingUnitInfo,
    &ett_isdn_sup_AOCEChargingUnitCc,
    &ett_isdn_sup_AOCECcSpecificChargingUnits,
    &ett_isdn_sup_Amount,
    &ett_isdn_sup_Time,
    &ett_isdn_sup_ChargingAssociation,
    &ett_isdn_sup_CUGcallArg,
    &ett_isdn_sup_BeginCONFRes,
    &ett_isdn_sup_SplitCONFArg,
    &ett_isdn_sup_ActivationDiversionArg,
    &ett_isdn_sup_DeactivationDiversionArg,
    &ett_isdn_sup_ActivationStatusNotificationDivArg,
    &ett_isdn_sup_DeactivationStatusNotificationDivArg,
    &ett_isdn_sup_InterrogationDiversionArg,
    &ett_isdn_sup_DiversionInformationArg,
    &ett_isdn_sup_CallDeflectionArg,
    &ett_isdn_sup_CallRerouteingArg,
    &ett_isdn_sup_DivertingLegInformation1Arg,
    &ett_isdn_sup_DivertingLegInformation2Arg,
    &ett_isdn_sup_IntResultList,
    &ett_isdn_sup_IntResult,
    &ett_isdn_sup_ServedUserNr,
    &ett_isdn_sup_ServedUserNumberList,
    &ett_isdn_sup_UserUserServiceArg,
    &ett_isdn_sup_Monitor_T_FPHArg,
    &ett_isdn_sup_Free_T_FPHArg,
    &ett_isdn_sup_Call_T_FPHArg,
    &ett_isdn_sup_MLPPLFBArg,
    &ett_isdn_sup_MLPPParams,
    &ett_isdn_sup_MLPPLFBResp,

/*--- End of included file: packet-isdn-sup-ettarr.c ---*/
#line 355 "./asn1/isdn-sup/packet-isdn-sup-template.c"
  };

  static ei_register_info ei[] = {
#if 0
    { &ei_isdn_sup_unsupported_arg_type, { "isdn_sup.unsupported.arg_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED ARGUMENT TYPE (ETSI sup)", EXPFILL }},
#endif
    { &ei_isdn_sup_unsupported_result_type, { "isdn_sup.unsupported.result_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED RESULT TYPE (ETSI sup)", EXPFILL }},
    { &ei_isdn_sup_unsupported_error_type, { "isdn_sup.unsupported.error_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED ERROR TYPE (ETSI sup)", EXPFILL }},
  };

  expert_module_t* expert_isdn_sup;

  /* Register protocol */
  proto_isdn_sup = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_isdn_sup, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_isdn_sup = expert_register_protocol(proto_isdn_sup);
  expert_register_field_array(expert_isdn_sup, ei, array_length(ei));
}
