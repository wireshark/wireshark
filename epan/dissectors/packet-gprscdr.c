/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-gprscdr.c                                                           */
/* ../../tools/asn2wrs.py -b -p gprscdr -c ./gprscdr.cnf -s ./packet-gprscdr-template -D . -O ../../epan/dissectors GenericChargingDataTypesV641.asn GPRSChargingDataTypesV641.asn */

/* Input file: packet-gprscdr-template.c */

#line 1 "../../asn1/gprscdr/packet-gprscdr-template.c"
/* packet-gprscdr-template.c
 * Copyright 2011 , Anders Broman <anders.broman [AT] ericsson.com>
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
 * References: 3GPP TS 32.298
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-gsm_map.h"
#include "packet-e212.h"
#include "packet-gprscdr.h"

#define PNAME  "GPRS CDR"
#define PSNAME "GPRSCDR"
#define PFNAME "gprscdr"

/* Define the GPRS CDR proto */
static int proto_gprscdr = -1;


/*--- Included file: packet-gprscdr-hf.c ---*/
#line 1 "../../asn1/gprscdr/packet-gprscdr-hf.c"
static int hf_gprscdr_gprscdr_GPRSCallEventRecord_PDU = -1;  /* GPRSCallEventRecord */
static int hf_gprscdr_gsm0408Cause = -1;          /* INTEGER */
static int hf_gprscdr_gsm0902MapErrorValue = -1;  /* INTEGER */
static int hf_gprscdr_itu_tQ767Cause = -1;        /* INTEGER */
static int hf_gprscdr_networkSpecificCause = -1;  /* ManagementExtension */
static int hf_gprscdr_manufacturerSpecificCause = -1;  /* ManagementExtension */
static int hf_gprscdr_positionMethodFailureCause = -1;  /* PositionMethodFailure_Diagnostic */
static int hf_gprscdr_unauthorizedLCSClientCause = -1;  /* UnauthorizedLCSClient_Diagnostic */
static int hf_gprscdr_iPBinaryAddress = -1;       /* IPBinaryAddress */
static int hf_gprscdr_iPTextRepresentedAddress = -1;  /* IPTextRepresentedAddress */
static int hf_gprscdr_iPBinV4Address = -1;        /* OCTET_STRING_SIZE_4 */
static int hf_gprscdr_iPBinV6Address = -1;        /* OCTET_STRING_SIZE_16 */
static int hf_gprscdr_iPTextV4Address = -1;       /* IA5String_SIZE_7_15 */
static int hf_gprscdr_iPTextV6Address = -1;       /* IA5String_SIZE_15_45 */
static int hf_gprscdr_ManagementExtensions_item = -1;  /* ManagementExtension */
static int hf_gprscdr_identifier = -1;            /* OBJECT_IDENTIFIER */
static int hf_gprscdr_significance = -1;          /* BOOLEAN */
static int hf_gprscdr_information = -1;           /* T_information */
static int hf_gprscdr_sgsnPDPRecord = -1;         /* SGSNPDPRecord */
static int hf_gprscdr_ggsnPDPRecord = -1;         /* GGSNPDPRecord */
static int hf_gprscdr_sgsnMMRecord = -1;          /* SGSNMMRecord */
static int hf_gprscdr_sgsnSMORecord = -1;         /* SGSNSMORecord */
static int hf_gprscdr_sgsnSMTRecord = -1;         /* SGSNSMTRecord */
static int hf_gprscdr_egsnPDPRecord = -1;         /* EGSNPDPRecord */
static int hf_gprscdr_recordType = -1;            /* CallEventRecordType */
static int hf_gprscdr_networkInitiation = -1;     /* NetworkInitiatedPDPContext */
static int hf_gprscdr_servedIMSI = -1;            /* IMSI */
static int hf_gprscdr_ggsnAddress = -1;           /* GSNAddress */
static int hf_gprscdr_chargingID = -1;            /* ChargingID */
static int hf_gprscdr_sgsnAddress = -1;           /* SEQUENCE_OF_GSNAddress */
static int hf_gprscdr_sgsnAddress_item = -1;      /* GSNAddress */
static int hf_gprscdr_accessPointNameNI = -1;     /* AccessPointNameNI */
static int hf_gprscdr_pdpType = -1;               /* PDPType */
static int hf_gprscdr_servedPDPAddress = -1;      /* PDPAddress */
static int hf_gprscdr_dynamicAddressFlag = -1;    /* DynamicAddressFlag */
static int hf_gprscdr_listOfTrafficVolumes = -1;  /* SEQUENCE_OF_ChangeOfCharCondition */
static int hf_gprscdr_listOfTrafficVolumes_item = -1;  /* ChangeOfCharCondition */
static int hf_gprscdr_recordOpeningTime = -1;     /* TimeStamp */
static int hf_gprscdr_duration = -1;              /* CallDuration */
static int hf_gprscdr_causeForRecClosing = -1;    /* CauseForRecClosing */
static int hf_gprscdr_diagnostics = -1;           /* Diagnostics */
static int hf_gprscdr_recordSequenceNumber = -1;  /* INTEGER */
static int hf_gprscdr_nodeID = -1;                /* NodeID */
static int hf_gprscdr_recordExtensions = -1;      /* ManagementExtensions */
static int hf_gprscdr_localSequenceNumber = -1;   /* LocalSequenceNumber */
static int hf_gprscdr_apnSelectionMode = -1;      /* APNSelectionMode */
static int hf_gprscdr_servedMSISDN = -1;          /* MSISDN */
static int hf_gprscdr_chargingCharacteristics = -1;  /* ChargingCharacteristics */
static int hf_gprscdr_chChSelectionMode = -1;     /* ChChSelectionMode */
static int hf_gprscdr_iMSsignalingContext = -1;   /* NULL */
static int hf_gprscdr_externalChargingID = -1;    /* OCTET_STRING */
static int hf_gprscdr_sgsnPLMNIdentifier = -1;    /* PLMN_Id */
static int hf_gprscdr_servedIMEISV = -1;          /* IMEI */
static int hf_gprscdr_rATType = -1;               /* RATType */
static int hf_gprscdr_mSTimeZone = -1;            /* MSTimeZone */
static int hf_gprscdr_userLocationInformation = -1;  /* OCTET_STRING */
static int hf_gprscdr_cAMELChargingInformation = -1;  /* OCTET_STRING */
static int hf_gprscdr_pSFurnishChargingInformation = -1;  /* PSFurnishChargingInformation */
static int hf_gprscdr_listOfServiceData = -1;     /* SEQUENCE_OF_ChangeOfServiceCondition */
static int hf_gprscdr_listOfServiceData_item = -1;  /* ChangeOfServiceCondition */
static int hf_gprscdr_servedIMEI = -1;            /* IMEI */
static int hf_gprscdr_sgsnAddress_01 = -1;        /* GSNAddress */
static int hf_gprscdr_msNetworkCapability = -1;   /* MSNetworkCapability */
static int hf_gprscdr_routingArea = -1;           /* RoutingAreaCode */
static int hf_gprscdr_locationAreaCode = -1;      /* LocationAreaCode */
static int hf_gprscdr_cellIdentifier = -1;        /* CellId */
static int hf_gprscdr_changeLocation = -1;        /* SEQUENCE_OF_ChangeLocation */
static int hf_gprscdr_changeLocation_item = -1;   /* ChangeLocation */
static int hf_gprscdr_sgsnChange = -1;            /* SGSNChange */
static int hf_gprscdr_cAMELInformationMM = -1;    /* CAMELInformationMM */
static int hf_gprscdr_ggsnAddressUsed = -1;       /* GSNAddress */
static int hf_gprscdr_accessPointNameOI = -1;     /* AccessPointNameOI */
static int hf_gprscdr_cAMELInformationPDP = -1;   /* CAMELInformationPDP */
static int hf_gprscdr_rNCUnsentDownlinkVolume = -1;  /* DataVolumeGPRS */
static int hf_gprscdr_serviceCentre = -1;         /* AddressString */
static int hf_gprscdr_recordingEntity = -1;       /* RecordingEntity */
static int hf_gprscdr_locationArea = -1;          /* LocationAreaCode */
static int hf_gprscdr_messageReference = -1;      /* MessageReference */
static int hf_gprscdr_eventTimeStamp = -1;        /* TimeStamp */
static int hf_gprscdr_smsResult = -1;             /* SMSResult */
static int hf_gprscdr_destinationNumber = -1;     /* SmsTpDestinationNumber */
static int hf_gprscdr_cAMELInformationSMS = -1;   /* CAMELInformationSMS */
static int hf_gprscdr_sCFAddress = -1;            /* SCFAddress */
static int hf_gprscdr_serviceKey = -1;            /* ServiceKey */
static int hf_gprscdr_defaultTransactionHandling = -1;  /* DefaultGPRS_Handling */
static int hf_gprscdr_numberOfDPEncountered = -1;  /* NumberOfDPEncountered */
static int hf_gprscdr_levelOfCAMELService = -1;   /* LevelOfCAMELService */
static int hf_gprscdr_freeFormatData = -1;        /* FreeFormatData */
static int hf_gprscdr_fFDAppendIndicator = -1;    /* FFDAppendIndicator */
static int hf_gprscdr_cAMELAccessPointNameNI = -1;  /* CAMELAccessPointNameNI */
static int hf_gprscdr_cAMELAccessPointNameOI = -1;  /* CAMELAccessPointNameOI */
static int hf_gprscdr_defaultSMSHandling = -1;    /* DefaultSMS_Handling */
static int hf_gprscdr_cAMELCallingPartyNumber = -1;  /* CallingNumber */
static int hf_gprscdr_cAMELDestinationSubscriberNumber = -1;  /* SmsTpDestinationNumber */
static int hf_gprscdr_cAMELSMSCAddress = -1;      /* AddressString */
static int hf_gprscdr_smsReferenceNumber = -1;    /* CallReferenceNumber */
static int hf_gprscdr_qosRequested = -1;          /* QoSInformation */
static int hf_gprscdr_qosNegotiated = -1;         /* QoSInformation */
static int hf_gprscdr_dataVolumeGPRSUplink = -1;  /* DataVolumeGPRS */
static int hf_gprscdr_dataVolumeGPRSDownlink = -1;  /* DataVolumeGPRS */
static int hf_gprscdr_changeCondition = -1;       /* ChangeCondition */
static int hf_gprscdr_changeTime = -1;            /* TimeStamp */
static int hf_gprscdr_ratingGroup = -1;           /* RatingGroupId */
static int hf_gprscdr_chargingRuleBaseName = -1;  /* ChargingRuleBaseName */
static int hf_gprscdr_resultCode = -1;            /* ResultCode */
static int hf_gprscdr_timeOfFirstUsage = -1;      /* TimeStamp */
static int hf_gprscdr_timeOfLastUsage = -1;       /* TimeStamp */
static int hf_gprscdr_timeUsage = -1;             /* CallDuration */
static int hf_gprscdr_serviceConditionChange = -1;  /* ServiceConditionChange */
static int hf_gprscdr_qoSInformationNeg = -1;     /* QoSInformation */
static int hf_gprscdr_sgsn_Address = -1;          /* GSNAddress */
static int hf_gprscdr_sGSNPLMNIdentifier = -1;    /* PLMN_Id */
static int hf_gprscdr_datavolumeFBCUplink = -1;   /* DataVolumeGPRS */
static int hf_gprscdr_datavolumeFBCDownlink = -1;  /* DataVolumeGPRS */
static int hf_gprscdr_timeOfReport = -1;          /* TimeStamp */
static int hf_gprscdr_failureHandlingContinue = -1;  /* FailureHandlingContinue */
static int hf_gprscdr_serviceIdentifier = -1;     /* ServiceIdentifier */
static int hf_gprscdr_routingAreaCode = -1;       /* RoutingAreaCode */
static int hf_gprscdr_cellId = -1;                /* CellId */
static int hf_gprscdr_iPAddress = -1;             /* IPAddress */
static int hf_gprscdr_eTSIAddress = -1;           /* ETSIAddress */
static int hf_gprscdr_pSFreeFormatData = -1;      /* FreeFormatData */
static int hf_gprscdr_pSFFDAppendIndicator = -1;  /* FFDAppendIndicator */
/* named bits */
static int hf_gprscdr_LevelOfCAMELService_basic = -1;
static int hf_gprscdr_LevelOfCAMELService_callDurationSupervision = -1;
static int hf_gprscdr_LevelOfCAMELService_onlineCharging = -1;
static int hf_gprscdr_ServiceConditionChange_qoSChange = -1;
static int hf_gprscdr_ServiceConditionChange_sGSNChange = -1;
static int hf_gprscdr_ServiceConditionChange_sGSNPLMNIDChange = -1;
static int hf_gprscdr_ServiceConditionChange_tariffTimeSwitch = -1;
static int hf_gprscdr_ServiceConditionChange_pDPContextRelease = -1;
static int hf_gprscdr_ServiceConditionChange_rATChange = -1;
static int hf_gprscdr_ServiceConditionChange_serviceIdledOut = -1;
static int hf_gprscdr_ServiceConditionChange_qCTExpiry = -1;
static int hf_gprscdr_ServiceConditionChange_configurationChange = -1;
static int hf_gprscdr_ServiceConditionChange_serviceStop = -1;
static int hf_gprscdr_ServiceConditionChange_timeThresholdReached = -1;
static int hf_gprscdr_ServiceConditionChange_volumeThresholdReached = -1;
static int hf_gprscdr_ServiceConditionChange_timeExhausted = -1;
static int hf_gprscdr_ServiceConditionChange_volumeExhausted = -1;
static int hf_gprscdr_ServiceConditionChange_timeout = -1;
static int hf_gprscdr_ServiceConditionChange_returnRequested = -1;
static int hf_gprscdr_ServiceConditionChange_reauthorisationRequest = -1;
static int hf_gprscdr_ServiceConditionChange_continueOngoingSession = -1;
static int hf_gprscdr_ServiceConditionChange_retryAndTerminateOngoingSession = -1;
static int hf_gprscdr_ServiceConditionChange_terminateOngoingSession = -1;

/*--- End of included file: packet-gprscdr-hf.c ---*/
#line 47 "../../asn1/gprscdr/packet-gprscdr-template.c"

static int ett_gprscdr = -1;
static int ett_gprscdr_timestamp = -1;
static int ett_gprscdr_plmn_id = -1;

/*--- Included file: packet-gprscdr-ett.c ---*/
#line 1 "../../asn1/gprscdr/packet-gprscdr-ett.c"
static gint ett_gprscdr_Diagnostics = -1;
static gint ett_gprscdr_IPAddress = -1;
static gint ett_gprscdr_IPBinaryAddress = -1;
static gint ett_gprscdr_IPTextRepresentedAddress = -1;
static gint ett_gprscdr_LevelOfCAMELService = -1;
static gint ett_gprscdr_ManagementExtensions = -1;
static gint ett_gprscdr_ManagementExtension = -1;
static gint ett_gprscdr_GPRSCallEventRecord = -1;
static gint ett_gprscdr_GGSNPDPRecord = -1;
static gint ett_gprscdr_SEQUENCE_OF_GSNAddress = -1;
static gint ett_gprscdr_SEQUENCE_OF_ChangeOfCharCondition = -1;
static gint ett_gprscdr_EGSNPDPRecord = -1;
static gint ett_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition = -1;
static gint ett_gprscdr_SGSNMMRecord = -1;
static gint ett_gprscdr_SEQUENCE_OF_ChangeLocation = -1;
static gint ett_gprscdr_SGSNPDPRecord = -1;
static gint ett_gprscdr_SGSNSMORecord = -1;
static gint ett_gprscdr_SGSNSMTRecord = -1;
static gint ett_gprscdr_CAMELInformationMM = -1;
static gint ett_gprscdr_CAMELInformationPDP = -1;
static gint ett_gprscdr_CAMELInformationSMS = -1;
static gint ett_gprscdr_ChangeOfCharCondition = -1;
static gint ett_gprscdr_ChangeOfServiceCondition = -1;
static gint ett_gprscdr_ChangeLocation = -1;
static gint ett_gprscdr_PDPAddress = -1;
static gint ett_gprscdr_PSFurnishChargingInformation = -1;
static gint ett_gprscdr_ServiceConditionChange = -1;

/*--- End of included file: packet-gprscdr-ett.c ---*/
#line 52 "../../asn1/gprscdr/packet-gprscdr-template.c"

static const value_string gprscdr_daylight_saving_time_vals[] = {
    {0, "No adjustment"},
    {1, "+1 hour adjustment for Daylight Saving Time"},
    {2, "+2 hours adjustment for Daylight Saving Time"},
    {3, "Reserved"},
    {0, NULL}
};


/*--- Included file: packet-gprscdr-fn.c ---*/
#line 1 "../../asn1/gprscdr/packet-gprscdr-fn.c"


static int
dissect_gprscdr_BCDDirectoryNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_CallDuration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gprscdr_CallEventRecordType_vals[] = {
  {   0, "moCallRecord" },
  {   1, "mtCallRecord" },
  {   2, "roamingRecord" },
  {   3, "incGatewayRecord" },
  {   4, "outGatewayRecord" },
  {   5, "transitCallRecord" },
  {   6, "moSMSRecord" },
  {   7, "mtSMSRecord" },
  {   8, "moSMSIWRecord" },
  {   9, "mtSMSGWRecord" },
  {  10, "ssActionRecord" },
  {  11, "hlrIntRecord" },
  {  12, "locUpdateHLRRecord" },
  {  13, "locUpdateVLRRecord" },
  {  14, "commonEquipRecord" },
  {  15, "moTraceRecord" },
  {  16, "mtTraceRecord" },
  {  17, "termCAMELRecord" },
  {  18, "sgsnPDPRecord" },
  {  19, "ggsnPDPRecord" },
  {  20, "sgsnMMRecord" },
  {  21, "sgsnSMORecord" },
  {  22, "sgsnSMTRecord" },
  {  23, "mtLCSRecord" },
  {  24, "moLCSRecord" },
  {  25, "niLCSRecord" },
  {  26, "sgsnMtLCSRecord" },
  {  27, "sgsnMoLCSRecord" },
  {  28, "sgsnNiLCSRecord" },
  {  29, "mmO1SRecord" },
  {  30, "mmO4FRqRecord" },
  {  31, "mmO4FRsRecord" },
  {  32, "mmO4DRecord" },
  {  33, "mmO1DRecord" },
  {  34, "mmO4RRecord" },
  {  35, "mmO1RRecord" },
  {  36, "mmOMDRecord" },
  {  37, "mmR4FRecord" },
  {  38, "mmR1NRqRecord" },
  {  39, "mmR1NRsRecord" },
  {  40, "mmR1RtRecord" },
  {  42, "mmR1AFRecord" },
  {  43, "mmR4DRqRecord" },
  {  44, "mmR4DRsRecord" },
  {  45, "mmR1RRRecord" },
  {  46, "mmR4RRqRecord" },
  {  47, "mmR4RRsRecord" },
  {  48, "mmRMDRecord" },
  {  49, "mmFRecord" },
  {  50, "mmBx1SRecord" },
  {  51, "mmBx1VRecord" },
  {  52, "mmBx1URecord" },
  {  53, "mmBx1DRecord" },
  {  54, "mM7SRecord" },
  {  55, "mM7DRqRecord" },
  {  56, "mM7DRsRecord" },
  {  57, "mM7CRecord" },
  {  58, "mM7RRecord" },
  {  59, "mM7DRRqRecord" },
  {  60, "mM7DRRsRecord" },
  {  61, "mM7RRqRecord" },
  {  62, "mM7RRsRecord" },
  {  63, "s-CSCFRecord" },
  {  64, "p-CSCFRecord" },
  {  65, "i-CSCFRecord" },
  {  66, "mRFCRecord" },
  {  67, "mGCFRecord" },
  {  68, "bGCFRecord" },
  {  69, "aSRecord" },
  {  70, "egsnPDPRecord" },
  {  71, "lCSGMORecord" },
  {  72, "lCSRGMTRecord" },
  {  73, "lCSHGMTRecord" },
  {  74, "lCSVGMTRecord" },
  {  75, "lCSGNIRecord" },
  {  76, "sgsnMBMSRecord" },
  {  77, "ggsnMBMSRecord" },
  {  78, "subBMSCRecord" },
  {  79, "contentBMSCRecord" },
  {  80, "pPFRecord" },
  {  81, "cPFRecord" },
  { 0, NULL }
};


static int
dissect_gprscdr_CallEventRecordType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_CallingNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_BCDDirectoryNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_CellId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_T_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 45 "../../asn1/gprscdr/gprscdr.cnf"

   proto_tree_add_text(tree, tvb, offset, -1, "Not dissected");
   


  return offset;
}


static const ber_sequence_t ManagementExtension_sequence[] = {
  { &hf_gprscdr_identifier  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gprscdr_OBJECT_IDENTIFIER },
  { &hf_gprscdr_significance, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_BOOLEAN },
  { &hf_gprscdr_information , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_T_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ManagementExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ManagementExtension_sequence, hf_index, ett_gprscdr_ManagementExtension);

  return offset;
}


static const value_string gprscdr_Diagnostics_vals[] = {
  {   0, "gsm0408Cause" },
  {   1, "gsm0902MapErrorValue" },
  {   2, "itu-tQ767Cause" },
  {   3, "networkSpecificCause" },
  {   4, "manufacturerSpecificCause" },
  {   5, "positionMethodFailureCause" },
  {   6, "unauthorizedLCSClientCause" },
  { 0, NULL }
};

static const ber_choice_t Diagnostics_choice[] = {
  {   0, &hf_gprscdr_gsm0408Cause, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  {   1, &hf_gprscdr_gsm0902MapErrorValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  {   2, &hf_gprscdr_itu_tQ767Cause, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  {   3, &hf_gprscdr_networkSpecificCause, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtension },
  {   4, &hf_gprscdr_manufacturerSpecificCause, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtension },
  {   5, &hf_gprscdr_positionMethodFailureCause, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gsm_map_er_PositionMethodFailure_Diagnostic },
  {   6, &hf_gprscdr_unauthorizedLCSClientCause, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gsm_map_er_UnauthorizedLCSClient_Diagnostic },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_Diagnostics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Diagnostics_choice, hf_index, ett_gprscdr_Diagnostics,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_OCTET_STRING_SIZE_4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_OCTET_STRING_SIZE_16(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_IPBinaryAddress_vals[] = {
  {   0, "iPBinV4Address" },
  {   1, "iPBinV6Address" },
  { 0, NULL }
};

static const ber_choice_t IPBinaryAddress_choice[] = {
  {   0, &hf_gprscdr_iPBinV4Address, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING_SIZE_4 },
  {   1, &hf_gprscdr_iPBinV6Address, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING_SIZE_16 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPBinaryAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPBinaryAddress_choice, hf_index, ett_gprscdr_IPBinaryAddress,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_IA5String_SIZE_7_15(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_IA5String_SIZE_15_45(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gprscdr_IPTextRepresentedAddress_vals[] = {
  {   2, "iPTextV4Address" },
  {   3, "iPTextV6Address" },
  { 0, NULL }
};

static const ber_choice_t IPTextRepresentedAddress_choice[] = {
  {   2, &hf_gprscdr_iPTextV4Address, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_IA5String_SIZE_7_15 },
  {   3, &hf_gprscdr_iPTextV6Address, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_IA5String_SIZE_15_45 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPTextRepresentedAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPTextRepresentedAddress_choice, hf_index, ett_gprscdr_IPTextRepresentedAddress,
                                 NULL);

  return offset;
}


static const value_string gprscdr_IPAddress_vals[] = {
  { -1/*choice*/, "iPBinaryAddress" },
  { -1/*choice*/, "iPTextRepresentedAddress" },
  { 0, NULL }
};

static const ber_choice_t IPAddress_choice[] = {
  { -1/*choice*/, &hf_gprscdr_iPBinaryAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gprscdr_IPBinaryAddress },
  { -1/*choice*/, &hf_gprscdr_iPTextRepresentedAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gprscdr_IPTextRepresentedAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPAddress_choice, hf_index, ett_gprscdr_IPAddress,
                                 NULL);

  return offset;
}


static const asn_namedbit LevelOfCAMELService_bits[] = {
  {  0, &hf_gprscdr_LevelOfCAMELService_basic, -1, -1, "basic", NULL },
  {  1, &hf_gprscdr_LevelOfCAMELService_callDurationSupervision, -1, -1, "callDurationSupervision", NULL },
  {  2, &hf_gprscdr_LevelOfCAMELService_onlineCharging, -1, -1, "onlineCharging", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gprscdr_LevelOfCAMELService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    LevelOfCAMELService_bits, hf_index, ett_gprscdr_LevelOfCAMELService,
                                    NULL);

  return offset;
}



static int
dissect_gprscdr_LocalSequenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_LocationAreaCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ManagementExtensions_set_of[1] = {
  { &hf_gprscdr_ManagementExtensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ManagementExtension },
};

static int
dissect_gprscdr_ManagementExtensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ManagementExtensions_set_of, hf_index, ett_gprscdr_ManagementExtensions);

  return offset;
}



static int
dissect_gprscdr_MessageReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_MSISDN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_ISDN_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_MSTimeZone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 88 "../../asn1/gprscdr/gprscdr.cnf"
/*
 *
 * 1.Octet: Time Zone and 2. Octet: Daylight saving time, see TS 29.060 [75]
 */
 tvbuff_t	*parameter_tvb;
 guint8 data, data2;
 char sign;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

	data = tvb_get_guint8(parameter_tvb, 0);
	sign = (data & 0x08) ? '-' : '+';
	data = (data >> 4) + (data & 0x07) * 10;

	data2 = tvb_get_guint8(tvb, 1) & 0x3;
	
	proto_item_append_text(actx->created_item, " (GMT %c %d hours %d minutes %s)", 
			sign, 
			data / 4, 
			data % 4 * 15,
			val_to_str_const(data2, gprscdr_daylight_saving_time_vals, "Unknown")
			);
			


  return offset;
}



static int
dissect_gprscdr_RecordingEntity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_SMSResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_Diagnostics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_SmsTpDestinationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_TimeStamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 49 "../../asn1/gprscdr/gprscdr.cnf"
/*
 *
 * The contents of this field are a compact form of the UTCTime format
 * containing local time plus an offset to universal time. Binary coded
 * decimal encoding is employed for the digits to reduce the storage and
 * transmission overhead
 * e.g. YYMMDDhhmmssShhmm
 * where
 * YY 	= 	Year 00 to 99		BCD encoded
 * MM 	= 	Month 01 to 12 		BCD encoded
 * DD	=	Day 01 to 31		BCD encoded
 * hh	=	hour 00 to 23		BCD encoded
 * mm	=	minute 00 to 59		BCD encoded
 * ss	=	second 00 to 59		BCD encoded
 * S	=	Sign 0 = "+", "-"	ASCII encoded
 * hh	=	hour 00 to 23		BCD encoded
 * mm	=	minute 00 to 59		BCD encoded
 */

 tvbuff_t	*parameter_tvb;
 
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 proto_item_append_text(actx->created_item, " (UTC %x-%x-%x %x:%x:%x %s%x:%x)",
			tvb_get_guint8(parameter_tvb,0),             /* Year */
			tvb_get_guint8(parameter_tvb,1),             /* Month */
			tvb_get_guint8(parameter_tvb,2),             /* Day */
			tvb_get_guint8(parameter_tvb,3),             /* Hour */
			tvb_get_guint8(parameter_tvb,4),             /* Minute */
			tvb_get_guint8(parameter_tvb,5),             /* Second */
			tvb_get_ephemeral_string(parameter_tvb,6,1), /* Sign */
			tvb_get_guint8(parameter_tvb,7),             /* Hour */
			tvb_get_guint8(parameter_tvb,8)             /* Minute */
			);
 


  return offset;
}



static int
dissect_gprscdr_NetworkInitiatedPDPContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_GSNAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_IPAddress(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_MSNetworkCapability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_RoutingAreaCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_ChargingID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_AccessPointNameNI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_PDPType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_ETSIAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string gprscdr_PDPAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "eTSIAddress" },
  { 0, NULL }
};

static const ber_choice_t PDPAddress_choice[] = {
  {   0, &hf_gprscdr_iPAddress   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_IPAddress },
  {   1, &hf_gprscdr_eTSIAddress , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_ETSIAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PDPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PDPAddress_choice, hf_index, ett_gprscdr_PDPAddress,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_QoSInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_DataVolumeGPRS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gprscdr_ChangeCondition_vals[] = {
  {   0, "qoSChange" },
  {   1, "tariffTime" },
  {   2, "recordClosure" },
  {   3, "failureHandlingContinueOngoing" },
  {   4, "failureHandlingRetryandTerminateOngoing" },
  {   5, "failureHandlingTerminateOngoing" },
  { 0, NULL }
};


static int
dissect_gprscdr_ChangeCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ChangeOfCharCondition_sequence[] = {
  { &hf_gprscdr_qosRequested, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_qosNegotiated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_dataVolumeGPRSUplink, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_dataVolumeGPRSDownlink, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_changeCondition, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChangeCondition },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfCharCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfCharCondition_sequence, hf_index, ett_gprscdr_ChangeOfCharCondition);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfCharCondition_sequence_of[1] = {
  { &hf_gprscdr_listOfTrafficVolumes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfCharCondition },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfCharCondition_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfCharCondition);

  return offset;
}



static int
dissect_gprscdr_SGSNChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string gprscdr_CauseForRecClosing_vals[] = {
  {   0, "normalRelease" },
  {   4, "abnormalRelease" },
  {   5, "cAMELInitCallRelease" },
  {  16, "volumeLimit" },
  {  17, "timeLimit" },
  {  18, "sGSNChange" },
  {  19, "maxChangeCond" },
  {  20, "managementIntervention" },
  {  21, "intraSGSNIntersystemChange" },
  {  22, "rATChange" },
  {  23, "mSTimeZoneChange" },
  {  52, "unauthorizedRequestingNetwork" },
  {  53, "unauthorizedLCSClient" },
  {  54, "positionMethodFailure" },
  {  58, "unknownOrUnreachableLCSClient" },
  {  59, "listofDownstreamNodeChange" },
  { 0, NULL }
};


static int
dissect_gprscdr_CauseForRecClosing(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_NodeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gprscdr_APNSelectionMode_vals[] = {
  {   0, "mSorNetworkProvidedSubscriptionVerified" },
  {   1, "mSProvidedSubscriptionNotVerified" },
  {   2, "networkProvidedSubscriptionNotVerified" },
  { 0, NULL }
};


static int
dissect_gprscdr_APNSelectionMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_AccessPointNameOI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_ChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_RATType_vals[] = {
  {   0, "reserved" },
  {   1, "utran" },
  {   2, "geran" },
  {   3, "wlan" },
  {   4, "gan" },
  {   5, "hspa-evolution" },
  { 0, NULL }
};


static int
dissect_gprscdr_RATType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_SCFAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_CAMELAccessPointNameNI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_AccessPointNameNI(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_CAMELAccessPointNameOI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_AccessPointNameOI(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_NumberOfDPEncountered(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_FreeFormatData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_FFDAppendIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CAMELInformationPDP_set[] = {
  { &hf_gprscdr_sCFAddress  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCFAddress },
  { &hf_gprscdr_serviceKey  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_ServiceKey },
  { &hf_gprscdr_defaultTransactionHandling, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_DefaultGPRS_Handling },
  { &hf_gprscdr_cAMELAccessPointNameNI, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELAccessPointNameNI },
  { &hf_gprscdr_cAMELAccessPointNameOI, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELAccessPointNameOI },
  { &hf_gprscdr_numberOfDPEncountered, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NumberOfDPEncountered },
  { &hf_gprscdr_levelOfCAMELService, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LevelOfCAMELService },
  { &hf_gprscdr_freeFormatData, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_fFDAppendIndicator, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FFDAppendIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_CAMELInformationPDP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CAMELInformationPDP_set, hf_index, ett_gprscdr_CAMELInformationPDP);

  return offset;
}


static const value_string gprscdr_ChChSelectionMode_vals[] = {
  {   0, "sGSNSupplied" },
  {   1, "subscriptionSpecific" },
  {   2, "aPNSpecific" },
  {   3, "homeDefault" },
  {   4, "roamingDefault" },
  {   5, "visitingDefault" },
  { 0, NULL }
};


static int
dissect_gprscdr_ChChSelectionMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_DynamicAddressFlag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SGSNPDPRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_ggsnAddressUsed, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_sgsnChange  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNChange },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_accessPointNameOI, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameOI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_cAMELInformationPDP, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationPDP },
  { &hf_gprscdr_rNCUnsentDownlinkVolume, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNPDPRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNPDPRecord_set, hf_index, ett_gprscdr_SGSNPDPRecord);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_GSNAddress_sequence_of[1] = {
  { &hf_gprscdr_sgsnAddress_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
};

static int
dissect_gprscdr_SEQUENCE_OF_GSNAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_GSNAddress_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_GSNAddress);

  return offset;
}



static int
dissect_gprscdr_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_gprscdr_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_PLMN_Id(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 115 "../../asn1/gprscdr/gprscdr.cnf"
 tvbuff_t	*parameter_tvb;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
	   
 subtree = proto_item_add_subtree(actx->created_item, ett_gprscdr_plmn_id);	   
 dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, TRUE);
 


  return offset;
}


static const ber_sequence_t GGSNPDPRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_sgsnAddress , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_externalChargingID, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_servedIMEISV, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_GGSNPDPRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              GGSNPDPRecord_set, hf_index, ett_gprscdr_GGSNPDPRecord);

  return offset;
}


static const ber_sequence_t ChangeLocation_sequence[] = {
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingAreaCode, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellId      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeLocation_sequence, hf_index, ett_gprscdr_ChangeLocation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeLocation_sequence_of[1] = {
  { &hf_gprscdr_changeLocation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeLocation },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeLocation_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeLocation);

  return offset;
}


static const ber_sequence_t CAMELInformationMM_set[] = {
  { &hf_gprscdr_sCFAddress  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCFAddress },
  { &hf_gprscdr_serviceKey  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_ServiceKey },
  { &hf_gprscdr_defaultTransactionHandling, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_DefaultGPRS_Handling },
  { &hf_gprscdr_numberOfDPEncountered, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NumberOfDPEncountered },
  { &hf_gprscdr_levelOfCAMELService, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LevelOfCAMELService },
  { &hf_gprscdr_freeFormatData, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_fFDAppendIndicator, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FFDAppendIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_CAMELInformationMM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CAMELInformationMM_set, hf_index, ett_gprscdr_CAMELInformationMM);

  return offset;
}


static const ber_sequence_t SGSNMMRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_changeLocation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeLocation },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_sgsnChange  , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNChange },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_cAMELInformationMM, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationMM },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNMMRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNMMRecord_set, hf_index, ett_gprscdr_SGSNMMRecord);

  return offset;
}


static const ber_sequence_t CAMELInformationSMS_set[] = {
  { &hf_gprscdr_sCFAddress  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCFAddress },
  { &hf_gprscdr_serviceKey  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_ServiceKey },
  { &hf_gprscdr_defaultSMSHandling, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_DefaultSMS_Handling },
  { &hf_gprscdr_cAMELCallingPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallingNumber },
  { &hf_gprscdr_cAMELDestinationSubscriberNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SmsTpDestinationNumber },
  { &hf_gprscdr_cAMELSMSCAddress, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_freeFormatData, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_smsReferenceNumber, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ch_CallReferenceNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_CAMELInformationSMS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CAMELInformationSMS_set, hf_index, ett_gprscdr_CAMELInformationSMS);

  return offset;
}


static const ber_sequence_t SGSNSMORecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_serviceCentre, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_locationArea, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_messageReference, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_MessageReference },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_smsResult   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_SMSResult },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_destinationNumber, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SmsTpDestinationNumber },
  { &hf_gprscdr_cAMELInformationSMS, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationSMS },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNSMORecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNSMORecord_set, hf_index, ett_gprscdr_SGSNSMORecord);

  return offset;
}


static const ber_sequence_t SGSNSMTRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_serviceCentre, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_locationArea, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_smsResult   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_SMSResult },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_cAMELInformationSMS, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationSMS },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNSMTRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNSMTRecord_set, hf_index, ett_gprscdr_SGSNSMTRecord);

  return offset;
}


static const ber_sequence_t PSFurnishChargingInformation_sequence[] = {
  { &hf_gprscdr_pSFreeFormatData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_pSFFDAppendIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FFDAppendIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PSFurnishChargingInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PSFurnishChargingInformation_sequence, hf_index, ett_gprscdr_PSFurnishChargingInformation);

  return offset;
}



static int
dissect_gprscdr_RatingGroupId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_ChargingRuleBaseName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_ResultCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const asn_namedbit ServiceConditionChange_bits[] = {
  {  0, &hf_gprscdr_ServiceConditionChange_qoSChange, -1, -1, "qoSChange", NULL },
  {  1, &hf_gprscdr_ServiceConditionChange_sGSNChange, -1, -1, "sGSNChange", NULL },
  {  2, &hf_gprscdr_ServiceConditionChange_sGSNPLMNIDChange, -1, -1, "sGSNPLMNIDChange", NULL },
  {  3, &hf_gprscdr_ServiceConditionChange_tariffTimeSwitch, -1, -1, "tariffTimeSwitch", NULL },
  {  4, &hf_gprscdr_ServiceConditionChange_pDPContextRelease, -1, -1, "pDPContextRelease", NULL },
  {  5, &hf_gprscdr_ServiceConditionChange_rATChange, -1, -1, "rATChange", NULL },
  {  6, &hf_gprscdr_ServiceConditionChange_serviceIdledOut, -1, -1, "serviceIdledOut", NULL },
  {  7, &hf_gprscdr_ServiceConditionChange_qCTExpiry, -1, -1, "qCTExpiry", NULL },
  {  8, &hf_gprscdr_ServiceConditionChange_configurationChange, -1, -1, "configurationChange", NULL },
  {  9, &hf_gprscdr_ServiceConditionChange_serviceStop, -1, -1, "serviceStop", NULL },
  { 10, &hf_gprscdr_ServiceConditionChange_timeThresholdReached, -1, -1, "timeThresholdReached", NULL },
  { 11, &hf_gprscdr_ServiceConditionChange_volumeThresholdReached, -1, -1, "volumeThresholdReached", NULL },
  { 13, &hf_gprscdr_ServiceConditionChange_timeExhausted, -1, -1, "timeExhausted", NULL },
  { 14, &hf_gprscdr_ServiceConditionChange_volumeExhausted, -1, -1, "volumeExhausted", NULL },
  { 15, &hf_gprscdr_ServiceConditionChange_timeout, -1, -1, "timeout", NULL },
  { 16, &hf_gprscdr_ServiceConditionChange_returnRequested, -1, -1, "returnRequested", NULL },
  { 17, &hf_gprscdr_ServiceConditionChange_reauthorisationRequest, -1, -1, "reauthorisationRequest", NULL },
  { 18, &hf_gprscdr_ServiceConditionChange_continueOngoingSession, -1, -1, "continueOngoingSession", NULL },
  { 19, &hf_gprscdr_ServiceConditionChange_retryAndTerminateOngoingSession, -1, -1, "retryAndTerminateOngoingSession", NULL },
  { 20, &hf_gprscdr_ServiceConditionChange_terminateOngoingSession, -1, -1, "terminateOngoingSession", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gprscdr_ServiceConditionChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceConditionChange_bits, hf_index, ett_gprscdr_ServiceConditionChange,
                                    NULL);

  return offset;
}



static int
dissect_gprscdr_FailureHandlingContinue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_ServiceIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ChangeOfServiceCondition_sequence[] = {
  { &hf_gprscdr_ratingGroup , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RatingGroupId },
  { &hf_gprscdr_chargingRuleBaseName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingRuleBaseName },
  { &hf_gprscdr_resultCode  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ResultCode },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_timeOfFirstUsage, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeOfLastUsage, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeUsage   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_serviceConditionChange, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceConditionChange },
  { &hf_gprscdr_qoSInformationNeg, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_sgsn_Address, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_sGSNPLMNIdentifier, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_datavolumeFBCUplink, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_datavolumeFBCDownlink, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_timeOfReport, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_failureHandlingContinue, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FailureHandlingContinue },
  { &hf_gprscdr_serviceIdentifier, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceIdentifier },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfServiceCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfServiceCondition_sequence, hf_index, ett_gprscdr_ChangeOfServiceCondition);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfServiceCondition_sequence_of[1] = {
  { &hf_gprscdr_listOfServiceData_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfServiceCondition },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfServiceCondition_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition);

  return offset;
}


static const ber_sequence_t EGSNPDPRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_sgsnAddress , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_externalChargingID, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_servedIMEISV, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_listOfServiceData, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EGSNPDPRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EGSNPDPRecord_set, hf_index, ett_gprscdr_EGSNPDPRecord);

  return offset;
}


const value_string gprscdr_GPRSCallEventRecord_vals[] = {
  {  20, "sgsnPDPRecord" },
  {  21, "ggsnPDPRecord" },
  {  22, "sgsnMMRecord" },
  {  23, "sgsnSMORecord" },
  {  24, "sgsnSMTRecord" },
  {  28, "egsnPDPRecord" },
  { 0, NULL }
};

static const ber_choice_t GPRSCallEventRecord_choice[] = {
  {  20, &hf_gprscdr_sgsnPDPRecord, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNPDPRecord },
  {  21, &hf_gprscdr_ggsnPDPRecord, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_gprscdr_GGSNPDPRecord },
  {  22, &hf_gprscdr_sgsnMMRecord, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNMMRecord },
  {  23, &hf_gprscdr_sgsnSMORecord, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNSMORecord },
  {  24, &hf_gprscdr_sgsnSMTRecord, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNSMTRecord },
  {  28, &hf_gprscdr_egsnPDPRecord, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_gprscdr_EGSNPDPRecord },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_gprscdr_GPRSCallEventRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPRSCallEventRecord_choice, hf_index, ett_gprscdr_GPRSCallEventRecord,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_RatingGroup(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}

/*--- PDUs ---*/

int dissect_gprscdr_GPRSCallEventRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_gprscdr_GPRSCallEventRecord(FALSE, tvb, offset, &asn1_ctx, tree, hf_gprscdr_gprscdr_GPRSCallEventRecord_PDU);
  return offset;
}


/*--- End of included file: packet-gprscdr-fn.c ---*/
#line 62 "../../asn1/gprscdr/packet-gprscdr-template.c"



/* Register all the bits needed with the filtering engine */
void
proto_register_gprscdr(void)
{
  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-gprscdr-hfarr.c ---*/
#line 1 "../../asn1/gprscdr/packet-gprscdr-hfarr.c"
    { &hf_gprscdr_gprscdr_GPRSCallEventRecord_PDU,
      { "GPRSCallEventRecord", "gprscdr.GPRSCallEventRecord",
        FT_UINT32, BASE_DEC, VALS(gprscdr_GPRSCallEventRecord_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_gsm0408Cause,
      { "gsm0408Cause", "gprscdr.gsm0408Cause",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_gsm0902MapErrorValue,
      { "gsm0902MapErrorValue", "gprscdr.gsm0902MapErrorValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_itu_tQ767Cause,
      { "itu-tQ767Cause", "gprscdr.itu_tQ767Cause",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_networkSpecificCause,
      { "networkSpecificCause", "gprscdr.networkSpecificCause",
        FT_NONE, BASE_NONE, NULL, 0,
        "ManagementExtension", HFILL }},
    { &hf_gprscdr_manufacturerSpecificCause,
      { "manufacturerSpecificCause", "gprscdr.manufacturerSpecificCause",
        FT_NONE, BASE_NONE, NULL, 0,
        "ManagementExtension", HFILL }},
    { &hf_gprscdr_positionMethodFailureCause,
      { "positionMethodFailureCause", "gprscdr.positionMethodFailureCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_er_PositionMethodFailure_Diagnostic_vals), 0,
        "PositionMethodFailure_Diagnostic", HFILL }},
    { &hf_gprscdr_unauthorizedLCSClientCause,
      { "unauthorizedLCSClientCause", "gprscdr.unauthorizedLCSClientCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_er_UnauthorizedLCSClient_Diagnostic_vals), 0,
        "UnauthorizedLCSClient_Diagnostic", HFILL }},
    { &hf_gprscdr_iPBinaryAddress,
      { "iPBinaryAddress", "gprscdr.iPBinaryAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPBinaryAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPTextRepresentedAddress,
      { "iPTextRepresentedAddress", "gprscdr.iPTextRepresentedAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPTextRepresentedAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPBinV4Address,
      { "iPBinV4Address", "gprscdr.iPBinV4Address",
        FT_IPv4, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_gprscdr_iPBinV6Address,
      { "iPBinV6Address", "gprscdr.iPBinV6Address",
        FT_IPv6, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_gprscdr_iPTextV4Address,
      { "iPTextV4Address", "gprscdr.iPTextV4Address",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_7_15", HFILL }},
    { &hf_gprscdr_iPTextV6Address,
      { "iPTextV6Address", "gprscdr.iPTextV6Address",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_15_45", HFILL }},
    { &hf_gprscdr_ManagementExtensions_item,
      { "ManagementExtension", "gprscdr.ManagementExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_identifier,
      { "identifier", "gprscdr.identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_gprscdr_significance,
      { "significance", "gprscdr.significance",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_gprscdr_information,
      { "information", "gprscdr.information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnPDPRecord,
      { "sgsnPDPRecord", "gprscdr.sgsnPDPRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_ggsnPDPRecord,
      { "ggsnPDPRecord", "gprscdr.ggsnPDPRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnMMRecord,
      { "sgsnMMRecord", "gprscdr.sgsnMMRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnSMORecord,
      { "sgsnSMORecord", "gprscdr.sgsnSMORecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnSMTRecord,
      { "sgsnSMTRecord", "gprscdr.sgsnSMTRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_egsnPDPRecord,
      { "egsnPDPRecord", "gprscdr.egsnPDPRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordType,
      { "recordType", "gprscdr.recordType",
        FT_INT32, BASE_DEC, VALS(gprscdr_CallEventRecordType_vals), 0,
        "CallEventRecordType", HFILL }},
    { &hf_gprscdr_networkInitiation,
      { "networkInitiation", "gprscdr.networkInitiation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "NetworkInitiatedPDPContext", HFILL }},
    { &hf_gprscdr_servedIMSI,
      { "servedIMSI", "gprscdr.servedIMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IMSI", HFILL }},
    { &hf_gprscdr_ggsnAddress,
      { "ggsnAddress", "gprscdr.ggsnAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_chargingID,
      { "chargingID", "gprscdr.chargingID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnAddress,
      { "sgsnAddress", "gprscdr.sgsnAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GSNAddress", HFILL }},
    { &hf_gprscdr_sgsnAddress_item,
      { "GSNAddress", "gprscdr.GSNAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_accessPointNameNI,
      { "accessPointNameNI", "gprscdr.accessPointNameNI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pdpType,
      { "pdpType", "gprscdr.pdpType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedPDPAddress,
      { "servedPDPAddress", "gprscdr.servedPDPAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_dynamicAddressFlag,
      { "dynamicAddressFlag", "gprscdr.dynamicAddressFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes,
      { "listOfTrafficVolumes", "gprscdr.listOfTrafficVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfCharCondition", HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes_item,
      { "ChangeOfCharCondition", "gprscdr.ChangeOfCharCondition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordOpeningTime,
      { "recordOpeningTime", "gprscdr.recordOpeningTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_duration,
      { "duration", "gprscdr.duration",
        FT_INT32, BASE_DEC, NULL, 0,
        "CallDuration", HFILL }},
    { &hf_gprscdr_causeForRecClosing,
      { "causeForRecClosing", "gprscdr.causeForRecClosing",
        FT_INT32, BASE_DEC, VALS(gprscdr_CauseForRecClosing_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_diagnostics,
      { "diagnostics", "gprscdr.diagnostics",
        FT_UINT32, BASE_DEC, VALS(gprscdr_Diagnostics_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordSequenceNumber,
      { "recordSequenceNumber", "gprscdr.recordSequenceNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_nodeID,
      { "nodeID", "gprscdr.nodeID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordExtensions,
      { "recordExtensions", "gprscdr.recordExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ManagementExtensions", HFILL }},
    { &hf_gprscdr_localSequenceNumber,
      { "localSequenceNumber", "gprscdr.localSequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_apnSelectionMode,
      { "apnSelectionMode", "gprscdr.apnSelectionMode",
        FT_UINT32, BASE_DEC, VALS(gprscdr_APNSelectionMode_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedMSISDN,
      { "servedMSISDN", "gprscdr.servedMSISDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MSISDN", HFILL }},
    { &hf_gprscdr_chargingCharacteristics,
      { "chargingCharacteristics", "gprscdr.chargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_chChSelectionMode,
      { "chChSelectionMode", "gprscdr.chChSelectionMode",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ChChSelectionMode_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_iMSsignalingContext,
      { "iMSsignalingContext", "gprscdr.iMSsignalingContext",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_externalChargingID,
      { "externalChargingID", "gprscdr.externalChargingID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_sgsnPLMNIdentifier,
      { "sgsnPLMNIdentifier", "gprscdr.sgsnPLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_servedIMEISV,
      { "servedIMEISV", "gprscdr.servedIMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IMEI", HFILL }},
    { &hf_gprscdr_rATType,
      { "rATType", "gprscdr.rATType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_RATType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_mSTimeZone,
      { "mSTimeZone", "gprscdr.mSTimeZone",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_cAMELChargingInformation,
      { "cAMELChargingInformation", "gprscdr.cAMELChargingInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_pSFurnishChargingInformation,
      { "pSFurnishChargingInformation", "gprscdr.pSFurnishChargingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listOfServiceData,
      { "listOfServiceData", "gprscdr.listOfServiceData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfServiceCondition", HFILL }},
    { &hf_gprscdr_listOfServiceData_item,
      { "ChangeOfServiceCondition", "gprscdr.ChangeOfServiceCondition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedIMEI,
      { "servedIMEI", "gprscdr.servedIMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IMEI", HFILL }},
    { &hf_gprscdr_sgsnAddress_01,
      { "sgsnAddress", "gprscdr.sgsnAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_msNetworkCapability,
      { "msNetworkCapability", "gprscdr.msNetworkCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_routingArea,
      { "routingArea", "gprscdr.routingArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RoutingAreaCode", HFILL }},
    { &hf_gprscdr_locationAreaCode,
      { "locationAreaCode", "gprscdr.locationAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cellIdentifier,
      { "cellIdentifier", "gprscdr.cellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellId", HFILL }},
    { &hf_gprscdr_changeLocation,
      { "changeLocation", "gprscdr.changeLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeLocation", HFILL }},
    { &hf_gprscdr_changeLocation_item,
      { "ChangeLocation", "gprscdr.ChangeLocation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnChange,
      { "sgsnChange", "gprscdr.sgsnChange",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELInformationMM,
      { "cAMELInformationMM", "gprscdr.cAMELInformationMM",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_ggsnAddressUsed,
      { "ggsnAddressUsed", "gprscdr.ggsnAddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_accessPointNameOI,
      { "accessPointNameOI", "gprscdr.accessPointNameOI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELInformationPDP,
      { "cAMELInformationPDP", "gprscdr.cAMELInformationPDP",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_rNCUnsentDownlinkVolume,
      { "rNCUnsentDownlinkVolume", "gprscdr.rNCUnsentDownlinkVolume",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_serviceCentre,
      { "serviceCentre", "gprscdr.serviceCentre",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AddressString", HFILL }},
    { &hf_gprscdr_recordingEntity,
      { "recordingEntity", "gprscdr.recordingEntity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_locationArea,
      { "locationArea", "gprscdr.locationArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LocationAreaCode", HFILL }},
    { &hf_gprscdr_messageReference,
      { "messageReference", "gprscdr.messageReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_eventTimeStamp,
      { "eventTimeStamp", "gprscdr.eventTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_smsResult,
      { "smsResult", "gprscdr.smsResult",
        FT_UINT32, BASE_DEC, VALS(gprscdr_Diagnostics_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_destinationNumber,
      { "destinationNumber", "gprscdr.destinationNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SmsTpDestinationNumber", HFILL }},
    { &hf_gprscdr_cAMELInformationSMS,
      { "cAMELInformationSMS", "gprscdr.cAMELInformationSMS",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sCFAddress,
      { "sCFAddress", "gprscdr.sCFAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_serviceKey,
      { "serviceKey", "gprscdr.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_defaultTransactionHandling,
      { "defaultTransactionHandling", "gprscdr.defaultTransactionHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ms_DefaultGPRS_Handling_vals), 0,
        "DefaultGPRS_Handling", HFILL }},
    { &hf_gprscdr_numberOfDPEncountered,
      { "numberOfDPEncountered", "gprscdr.numberOfDPEncountered",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_levelOfCAMELService,
      { "levelOfCAMELService", "gprscdr.levelOfCAMELService",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_freeFormatData,
      { "freeFormatData", "gprscdr.freeFormatData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_fFDAppendIndicator,
      { "fFDAppendIndicator", "gprscdr.fFDAppendIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELAccessPointNameNI,
      { "cAMELAccessPointNameNI", "gprscdr.cAMELAccessPointNameNI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELAccessPointNameOI,
      { "cAMELAccessPointNameOI", "gprscdr.cAMELAccessPointNameOI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_defaultSMSHandling,
      { "defaultSMSHandling", "gprscdr.defaultSMSHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ms_DefaultSMS_Handling_vals), 0,
        "DefaultSMS_Handling", HFILL }},
    { &hf_gprscdr_cAMELCallingPartyNumber,
      { "cAMELCallingPartyNumber", "gprscdr.cAMELCallingPartyNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CallingNumber", HFILL }},
    { &hf_gprscdr_cAMELDestinationSubscriberNumber,
      { "cAMELDestinationSubscriberNumber", "gprscdr.cAMELDestinationSubscriberNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SmsTpDestinationNumber", HFILL }},
    { &hf_gprscdr_cAMELSMSCAddress,
      { "cAMELSMSCAddress", "gprscdr.cAMELSMSCAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AddressString", HFILL }},
    { &hf_gprscdr_smsReferenceNumber,
      { "smsReferenceNumber", "gprscdr.smsReferenceNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CallReferenceNumber", HFILL }},
    { &hf_gprscdr_qosRequested,
      { "qosRequested", "gprscdr.qosRequested",
        FT_BYTES, BASE_NONE, NULL, 0,
        "QoSInformation", HFILL }},
    { &hf_gprscdr_qosNegotiated,
      { "qosNegotiated", "gprscdr.qosNegotiated",
        FT_BYTES, BASE_NONE, NULL, 0,
        "QoSInformation", HFILL }},
    { &hf_gprscdr_dataVolumeGPRSUplink,
      { "dataVolumeGPRSUplink", "gprscdr.dataVolumeGPRSUplink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_dataVolumeGPRSDownlink,
      { "dataVolumeGPRSDownlink", "gprscdr.dataVolumeGPRSDownlink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_changeCondition,
      { "changeCondition", "gprscdr.changeCondition",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ChangeCondition_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_changeTime,
      { "changeTime", "gprscdr.changeTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_ratingGroup,
      { "ratingGroup", "gprscdr.ratingGroup",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RatingGroupId", HFILL }},
    { &hf_gprscdr_chargingRuleBaseName,
      { "chargingRuleBaseName", "gprscdr.chargingRuleBaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_resultCode,
      { "resultCode", "gprscdr.resultCode",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_timeOfFirstUsage,
      { "timeOfFirstUsage", "gprscdr.timeOfFirstUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_timeOfLastUsage,
      { "timeOfLastUsage", "gprscdr.timeOfLastUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_timeUsage,
      { "timeUsage", "gprscdr.timeUsage",
        FT_INT32, BASE_DEC, NULL, 0,
        "CallDuration", HFILL }},
    { &hf_gprscdr_serviceConditionChange,
      { "serviceConditionChange", "gprscdr.serviceConditionChange",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_qoSInformationNeg,
      { "qoSInformationNeg", "gprscdr.qoSInformationNeg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "QoSInformation", HFILL }},
    { &hf_gprscdr_sgsn_Address,
      { "sgsn-Address", "gprscdr.sgsn_Address",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_sGSNPLMNIdentifier,
      { "sGSNPLMNIdentifier", "gprscdr.sGSNPLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_datavolumeFBCUplink,
      { "datavolumeFBCUplink", "gprscdr.datavolumeFBCUplink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_datavolumeFBCDownlink,
      { "datavolumeFBCDownlink", "gprscdr.datavolumeFBCDownlink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_timeOfReport,
      { "timeOfReport", "gprscdr.timeOfReport",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_failureHandlingContinue,
      { "failureHandlingContinue", "gprscdr.failureHandlingContinue",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_serviceIdentifier,
      { "serviceIdentifier", "gprscdr.serviceIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_routingAreaCode,
      { "routingAreaCode", "gprscdr.routingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cellId,
      { "cellId", "gprscdr.cellId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPAddress,
      { "iPAddress", "gprscdr.iPAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_eTSIAddress,
      { "eTSIAddress", "gprscdr.eTSIAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pSFreeFormatData,
      { "pSFreeFormatData", "gprscdr.pSFreeFormatData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FreeFormatData", HFILL }},
    { &hf_gprscdr_pSFFDAppendIndicator,
      { "pSFFDAppendIndicator", "gprscdr.pSFFDAppendIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "FFDAppendIndicator", HFILL }},
    { &hf_gprscdr_LevelOfCAMELService_basic,
      { "basic", "gprscdr.basic",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_LevelOfCAMELService_callDurationSupervision,
      { "callDurationSupervision", "gprscdr.callDurationSupervision",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_LevelOfCAMELService_onlineCharging,
      { "onlineCharging", "gprscdr.onlineCharging",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_qoSChange,
      { "qoSChange", "gprscdr.qoSChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_sGSNChange,
      { "sGSNChange", "gprscdr.sGSNChange",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_sGSNPLMNIDChange,
      { "sGSNPLMNIDChange", "gprscdr.sGSNPLMNIDChange",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_tariffTimeSwitch,
      { "tariffTimeSwitch", "gprscdr.tariffTimeSwitch",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_pDPContextRelease,
      { "pDPContextRelease", "gprscdr.pDPContextRelease",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_rATChange,
      { "rATChange", "gprscdr.rATChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_serviceIdledOut,
      { "serviceIdledOut", "gprscdr.serviceIdledOut",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_qCTExpiry,
      { "qCTExpiry", "gprscdr.qCTExpiry",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_configurationChange,
      { "configurationChange", "gprscdr.configurationChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_serviceStop,
      { "serviceStop", "gprscdr.serviceStop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_timeThresholdReached,
      { "timeThresholdReached", "gprscdr.timeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_volumeThresholdReached,
      { "volumeThresholdReached", "gprscdr.volumeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_timeExhausted,
      { "timeExhausted", "gprscdr.timeExhausted",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_volumeExhausted,
      { "volumeExhausted", "gprscdr.volumeExhausted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_timeout,
      { "timeout", "gprscdr.timeout",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_returnRequested,
      { "returnRequested", "gprscdr.returnRequested",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_reauthorisationRequest,
      { "reauthorisationRequest", "gprscdr.reauthorisationRequest",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_continueOngoingSession,
      { "continueOngoingSession", "gprscdr.continueOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_retryAndTerminateOngoingSession,
      { "retryAndTerminateOngoingSession", "gprscdr.retryAndTerminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_terminateOngoingSession,
      { "terminateOngoingSession", "gprscdr.terminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},

/*--- End of included file: packet-gprscdr-hfarr.c ---*/
#line 72 "../../asn1/gprscdr/packet-gprscdr-template.c"
  };

  /* List of subtrees */
    static gint *ett[] = {
    &ett_gprscdr,
	&ett_gprscdr_timestamp,
	&ett_gprscdr_plmn_id,

/*--- Included file: packet-gprscdr-ettarr.c ---*/
#line 1 "../../asn1/gprscdr/packet-gprscdr-ettarr.c"
    &ett_gprscdr_Diagnostics,
    &ett_gprscdr_IPAddress,
    &ett_gprscdr_IPBinaryAddress,
    &ett_gprscdr_IPTextRepresentedAddress,
    &ett_gprscdr_LevelOfCAMELService,
    &ett_gprscdr_ManagementExtensions,
    &ett_gprscdr_ManagementExtension,
    &ett_gprscdr_GPRSCallEventRecord,
    &ett_gprscdr_GGSNPDPRecord,
    &ett_gprscdr_SEQUENCE_OF_GSNAddress,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfCharCondition,
    &ett_gprscdr_EGSNPDPRecord,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition,
    &ett_gprscdr_SGSNMMRecord,
    &ett_gprscdr_SEQUENCE_OF_ChangeLocation,
    &ett_gprscdr_SGSNPDPRecord,
    &ett_gprscdr_SGSNSMORecord,
    &ett_gprscdr_SGSNSMTRecord,
    &ett_gprscdr_CAMELInformationMM,
    &ett_gprscdr_CAMELInformationPDP,
    &ett_gprscdr_CAMELInformationSMS,
    &ett_gprscdr_ChangeOfCharCondition,
    &ett_gprscdr_ChangeOfServiceCondition,
    &ett_gprscdr_ChangeLocation,
    &ett_gprscdr_PDPAddress,
    &ett_gprscdr_PSFurnishChargingInformation,
    &ett_gprscdr_ServiceConditionChange,

/*--- End of included file: packet-gprscdr-ettarr.c ---*/
#line 80 "../../asn1/gprscdr/packet-gprscdr-template.c"
        };

  proto_gprscdr = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_gprscdr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routine */

