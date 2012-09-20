/* packet-slowprotocols.c
 * Routines for EtherType (0x8809) Slow Protocols disassembly.
 *
 * $Id$
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2005 Dominique Bastien <dbastien@accedian.com>
 * Copyright 2009 Artem Tamazov <artem.tamazov@telllabs.com>
 * Copyright 2010 Roberto Morro <roberto.morro[AT]tilab.com>
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/llcsaps.h>
#include <epan/ppptypes.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>

/* General declarations */

#define SLOW_PROTO_SUBTYPE              0

#define LACP_SUBTYPE                    0x1
#define MARKER_SUBTYPE                  0x2
#define OAM_SUBTYPE                     0x3
#define OSSP_SUBTYPE                    0xa /* IEEE 802.3 Annex 57A*/


/* Offsets of fields within a LACPDU */

#define LACPDU_VERSION_NUMBER            1

#define LACPDU_ACTOR_TYPE                2
#define LACPDU_ACTOR_INFO_LEN            3
#define LACPDU_ACTOR_SYS_PRIORITY        4
#define LACPDU_ACTOR_SYSTEM              6
#define LACPDU_ACTOR_KEY                12
#define LACPDU_ACTOR_PORT_PRIORITY      14
#define LACPDU_ACTOR_PORT               16
#define LACPDU_ACTOR_STATE              18
#define LACPDU_ACTOR_RESERVED           19

#define LACPDU_PARTNER_TYPE             22
#define LACPDU_PARTNER_INFO_LEN         23
#define LACPDU_PARTNER_SYS_PRIORITY     24
#define LACPDU_PARTNER_SYSTEM           26
#define LACPDU_PARTNER_KEY              32
#define LACPDU_PARTNER_PORT_PRIORITY    34
#define LACPDU_PARTNER_PORT             36
#define LACPDU_PARTNER_STATE            38
#define LACPDU_PARTNER_RESERVED         39

#define LACPDU_COLL_TYPE                42
#define LACPDU_COLL_INFO_LEN            43
#define LACPDU_COLL_MAX_DELAY           44
#define LACPDU_COLL_RESERVED            46

#define LACPDU_TERM_TYPE                58
#define LACPDU_TERM_LEN                 59
#define LACPDU_TERM_RESERVED            60

/* Actor and Partner Flag bits */
#define LACPDU_FLAGS_ACTIVITY           0x01
#define LACPDU_FLAGS_TIMEOUT            0x02
#define LACPDU_FLAGS_AGGREGATION        0x04
#define LACPDU_FLAGS_SYNC               0x08
#define LACPDU_FLAGS_COLLECTING         0x10
#define LACPDU_FLAGS_DISTRIB            0x20
#define LACPDU_FLAGS_DEFAULTED          0x40
#define LACPDU_FLAGS_EXPIRED            0x80


/* MARKER TLVs subtype */
#define MARKERPDU_END_MARKER            0x0
#define MARKERPDU_MARKER_INFO           0x1
#define MARKERPDU_MARKER_RESPONSE       0x2


/* Offsets of fields within a OAMPDU */
#define OAMPDU_FLAGS                    1
#define OAMPDU_CODE                     3

#define OAMPDU_HEADER_SIZE              4

/* OAMPDU Flag bits */
#define OAMPDU_FLAGS_LINK_FAULT         0x01
#define OAMPDU_FLAGS_DYING_GASP         0x02
#define OAMPDU_FLAGS_CRITICAL_EVENT     0x04
#define OAMPDU_FLAGS_LOCAL_EVAL         0x08
#define OAMPDU_FLAGS_LOCAL_STABLE       0x10
#define OAMPDU_FLAGS_REMOTE_EVAL        0x20
#define OAMPDU_FLAGS_REMOTE_STABLE      0x40

/* OAMPDU Code */
#define OAMPDU_INFORMATION              0x0
#define OAMPDU_EVENT_NOTIFICATION       0x1
#define OAMPDU_VAR_REQUEST              0x2
#define OAMPDU_VAR_RESPONSE             0x3
#define OAMPDU_LOOPBACK_CTRL            0x4
#define OAMPDU_VENDOR_SPECIFIC          0xFE

/* Information Type */
#define OAMPDU_INFO_TYPE_ENDMARKER      0x0
#define OAMPDU_INFO_TYPE_LOCAL          0x1
#define OAMPDU_INFO_TYPE_REMOTE         0x2
#define OAMPDU_INFO_TYPE_ORG            0xFE

/* Size of fields within a OAMPDU Information */
#define OAMPDU_INFO_TYPE_SZ             1
#define OAMPDU_INFO_LENGTH_SZ           1
#define OAMPDU_INFO_VERSION_SZ          1
#define OAMPDU_INFO_REVISION_SZ         2
#define OAMPDU_INFO_STATE_SZ            1
#define OAMPDU_INFO_OAM_CONFIG_SZ       1
#define OAMPDU_INFO_OAMPDU_CONFIG_SZ    2
#define OAMPDU_INFO_OUI_SZ              3
#define OAMPDU_INFO_VENDOR_SPECIFIC_SZ  4

/* OAM configuration bits */

#define OAMPDU_INFO_CONFIG_MODE         0x01
#define OAMPDU_INFO_CONFIG_UNI          0x02
#define OAMPDU_INFO_CONFIG_LPBK         0x04
#define OAMPDU_INFO_CONFIG_EVENT        0x08
#define OAMPDU_INFO_CONFIG_VAR          0x10

/* Event Type */
#define OAMPDU_EVENT_TYPE_END           0x0
#define OAMPDU_EVENT_TYPE_ESPE          0x1
#define OAMPDU_EVENT_TYPE_EFE           0x2
#define OAMPDU_EVENT_TYPE_EFPE          0x3
#define OAMPDU_EVENT_TYPE_EFSSE         0x4
#define OAMPDU_EVENT_TYPE_OSE           0xFE

/* Size of fields within a OAMPDU Event notification */
#define OAMPDU_EVENT_SEQUENCE_SZ        2
#define OAMPDU_EVENT_TYPE_SZ            1
#define OAMPDU_EVENT_LENGTH_SZ          1
#define OAMPDU_EVENT_TIMESTAMP_SZ       2

/* Size of fields within a OAMPDU ESPE: Errored Symbol Period Event TLV */
#define OAMPDU_ESPE_WINDOW_SZ           8
#define OAMPDU_ESPE_THRESHOLD_SZ        8
#define OAMPDU_ESPE_ERRORS_SZ           8
#define OAMPDU_ESPE_ERR_TOTAL_SZ        8
#define OAMPDU_ESPE_TOTAL_SZ            4

/* Size of fields within a OAMPDU EFE: Errored Frame Event TLV */
#define OAMPDU_EFE_WINDOW_SZ            2
#define OAMPDU_EFE_THRESHOLD_SZ         4
#define OAMPDU_EFE_ERRORS_SZ            4
#define OAMPDU_EFE_ERR_TOTAL_SZ         8
#define OAMPDU_EFE_TOTAL_SZ             4

/* Size of fields within a OAMPDU EFPE: Errored Frame Period Event TLV */
#define OAMPDU_EFPE_WINDOW_SZ           4
#define OAMPDU_EFPE_THRESHOLD_SZ        4
#define OAMPDU_EFPE_ERRORS_SZ           4
#define OAMPDU_EFPE_ERR_TOTAL_SZ        8
#define OAMPDU_EFPE_TOTAL_SZ            4

/* Size of fields within a OAMPDU EFSSE: Errored Frame Seconds Summary Event TLV */
#define OAMPDU_EFSSE_WINDOW_SZ          2
#define OAMPDU_EFSSE_THRESHOLD_SZ       2
#define OAMPDU_EFSSE_ERRORS_SZ          2
#define OAMPDU_EFSSE_ERR_TOTAL_SZ       4
#define OAMPDU_EFSSE_TOTAL_SZ           4

/* Variable Branch Type */
#define OAMPDU_VARS_OBJECT              0x3
#define OAMPDU_VARS_PACKAGE             0x4
#define OAMPDU_VARS_BINDING             0x6
#define OAMPDU_VARS_ATTRIBUTE           0x7

/* OAMPDU Loopback Control bits */
#define OAMPDU_LPBK_ENABLE              0x01
#define OAMPDU_LPBK_DISABLE             0x02


static const value_string subtype_vals[] = {
    { LACP_SUBTYPE   , "LACP" },
    { MARKER_SUBTYPE , "Marker Protocol" },
    { OAM_SUBTYPE    , "OAM" },
    { OSSP_SUBTYPE   , "Organization Specific Slow Protocol" },
    { 0, NULL }
};

static const value_string marker_vals[] = {
    { 1, "Marker Information" },
    { 2, "Marker Response Information" },
    { 0, NULL }
};

/* see IEEE802.3, table 57-4 */
static const value_string code_vals[] = {
    { 0    , "Information" },
    { 1    , "Event Notification" },
    { 2    , "Variable Request" },
    { 3    , "Variable Response" },
    { 4    , "Loopback Control"},
    { 0xFE , "Organization Specific" },
    { 0, NULL }
};

/* see IEEE802.3, table 57-6 */
static const value_string info_type_vals[] = {
    { 0    , "End of TLV marker" },
    { 1    , "Local Information TLV" },
    { 2    , "Remote Information TLV" },
    { 0xFE , "Organization Specific Information TLV" },
    { 0, NULL }
};

/* see IEEE802.3, table 57-12 */
static const value_string event_type_vals[] = {
    { 0    , "End of TLV marker" },
    { 1    , "Errored Symbol Period Event" },
    { 2    , "Errored Frame Event" },
    { 3    , "Errored Frame Period Event" },
    { 4    , "Errored Frame Seconds Summary Event" },
    { 0xFE , "Organization Specific Event TLV" },
    { 0, NULL }
};


/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-define. Only the
 * managedObjectClass(3) is put in the branch and the leaf is one of the
 * following value:
 */
static const value_string object_vals[] = {
    {  1, "macObjectClass" },
    {  2, "phyObjectClass"},
    {  3, "repeaterObjectClass"},
    {  4, "groupObjectClass"},
    {  5, "repeaterPortObjectClass"},
    {  6, "mauObjectClass"},
    {  7, "autoNegObjectClass"},
    {  8, "macControlObjectClass"},
    {  9, "macControlFunctionObjectClass"},
    { 10, "oAggregator"},
    { 11, "oAggregationPort"},
    { 12, "oAggPortStats"},
    { 13, "oAggPortDebugInformation" },
    { 15, "pseObjectClass"},
    { 17, "midSpanObjectClass"},
    { 18, "midSpanGroupObjectClass"},
    { 19, "ompObjectClass"},
    { 20, "oamObjectClass" },
    { 21, "mpcpObjectClass" },
    { 24, "pafObjectClass" },
    { 25, "pmeObjectClass"},
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * package(4) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string package_vals[] = {
    {  1, "macMandatoryPkg" },
    {  2, "macRecommendedPkg" },
    {  3, "macOptionalPkg" },
    {  4, "macarrayPkg" },
    {  5, "macExcessiveDeferralPkg" },
    {  6, "phyRecommendedPkg" },
    {  7, "phyMultiplePhyPkg" },
    {  8, "phy100MbpsMonitor" },
    {  9, "repeaterPerfMonitorPkg"},
    { 10, "portPerfMonitorPkg"},
    { 11, "portAddrTrackPkg"},
    { 12, "port100MbpsMonitor"},
    { 13, "mauControlPkg"},
    { 14, "mediaLossTrackingPkg"},
    { 15, "broadbandMAUPkg"},
    { 16, "mau100MbpsMonitor"},
    { 17, "macControlRecommendedPkg" },
    { 18, "portBurst"},
    { 19, "pAggregatorMandatory"},
    { 20, "pAggregatorRecommended"},
    { 21, "pAggregatorOptional"},
    { 22, "pAggregationPortMandatory"},
    { 23, "pAggPortStats"},
    { 24, "pAggPortDebugInformation"},

    { 27, "pseRecommendedPkg"},

    { 30, "fecMonitor"},
    { 35, "pcsMonitor"},
    { 37, "oMPError"},
    { 38, "pafAggregation"},
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * nameBinding(6) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string binding_vals[] = {
    { 26, "repeaterPortName"},
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * attribute(7) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string attribute_vals[] = {
    {   1, "aMACID" },
    {   2, "aFramesTransmittedOK" },
    {   3, "aSingleCollisionFrames" },
    {   4, "aMultipleCollisionFrames" },
    {   5, "aFramesReceivedOK" },
    {   6, "aFrameCheckSequenceErrors" },
    {   7, "aAlignmentErrors" },
    {   8, "aOctetsTransmittedOK" },
    {   9, "aFramesWithDeferredXmissions" },
    {  10, "aLateCollisions" },
    {  11, "aFramesAbortedDueToXSColls" },
    {  12, "aFramesLostDueToIntMACXmitError" },
    {  13, "aCarrierSenseErrors" },
    {  14, "aOctetsReceivedOK" },
    {  15, "aFramesLostDueToIntMACRcvError" },
    {  16, "aPromiscuousStatus" },
    {  17, "aReadMulticastAddressList" },
    {  18, "aMulticastFramesXmittedOK" },
    {  19, "aBroadcastFramesXmittedOK" },
    {  20, "aFramesWithExcessiveDeferral" },
    {  21, "aMulticastFramesReceivedOK" },
    {  22, "aBroadcastFramesReceivedOK" },
    {  23, "aInRangeLengthErrors" },
    {  24, "aOutOfRangeLengthField" },
    {  25, "aFrameTooLongErrors" },
    {  26, "aMACEnableStatus" },
    {  27, "aTransmitEnableStatus" },
    {  28, "aMulticastReceiveStatus" },
    {  29, "aReadWriteMACAddress" },
    {  30, "aCollisionFrames" },
    {  31, "aPHYID" },
    {  32, "aPHYType" },
    {  33, "aPHYTypeList" },
    {  34, "aSQETestErrors" },
    {  35, "aSymbolErrorDuringCarrier" },
    {  36, "aMIIDetect" },
    {  37, "aPHYAdminState" },
    {  38, "aRepeaterID" },
    {  39, "aRepeaterType" },
    {  40, "aRepeaterGroupCapacity" },
    {  41, "aGroupMap" },
    {  42, "aRepeaterHealthState" },
    {  43, "aRepeaterHealthText" },
    {  44, "aRepeaterHealthData" },
    {  45, "aTransmitCollisions" }, /* XXX: was: 44 */
    {  46, "aGroupID" },
    {  47, "aGroupPortCapacity" },
    {  48, "aPortMap" },
    {  49, "aPortID" },
    {  50, "aPortAdminState" },
    {  51, "aAutoPartitionState" },
    {  52, "aReadableFrames" },
    {  53, "aReadableOctets" },
    {  54, "aFrameCheckSequenceErrors" },
    {  55, "aAlignmentErrors" },
    {  56, "aFramesTooLong" },
    {  57, "aShortEvents" },
    {  58, "aRunts" },
    {  59, "aCollisions" },
    {  60, "aLateEvents" },
    {  61, "aVeryLongEvents" },
    {  62, "aDataRateMismatches" },
    {  63, "aAutoPartitions" },
    {  64, "aIsolates" },
    {  65, "aSymbolErrorDuringPacket" },
    {  66, "aLastSourceAddress" },
    {  67, "aSourceAddressChanges" },
    {  68, "aMAUID" },
    {  69, "aMAUType" },
    {  70, "aMAUTypeList" },
    {  71, "aMediaAvailable" },
    {  72, "aLoseMediaCounter" },
    {  73, "aJabber" },
    {  74, "aMAUAdminState" },
    {  75, "aBbMAUXmitRcvSplitType" },
    {  76, "aBroadbandFrequencies" },
    {  77, "aFalseCarriers" },
    {  78, "aAutoNegID" },
    {  79, "aAutoNegAdminState" },
    {  80, "aAutoNegRemoteSignaling" },
    {  81, "aAutoNegAutoConfig" },
    {  82, "aAutoNegLocalTechnologyAbility" },
    {  83, "aAutoNegAdvertisedTechnologyAbility" },
    {  84, "aAutoNegReceivedTechnologyAbility" },
    {  85, "aAutoNegLocalSelectorAbility" },
    {  86, "aAutoNegAdvertisedSelectorAbility" },
    {  87, "aAutoNegReceivedSelectorAbility" },

    {  89, "aMACCapabilities" },
    {  90, "aDuplexStatus" },
    {  91, "aIdleErrorCount"},
    {  92, "aMACControlID" },
    {  93, "aMACControlFunctionsSupported" },
    {  94, "aMACControlFramesTransmitted" },
    {  95, "aMACControlFramesReceived" },
    {  96, "aUnsupportedOpcodesReceived" },
    {  97, "aPAUSELinkDelayAllowance" },
    {  98, "aPAUSEMACCtrlFramesTransmitted" },
    {  99, "aPAUSEMACCtrlFramesReceived" },
    { 100, "aBursts" },
    { 101, "aAggID" },
    { 102, "aAggDescription" },
    { 103, "aAggName" },
    { 104, "aAggActorSystemID" },
    { 105, "aAggActorSystemPriority" },
    { 106, "aAggAggregateOrIndividual" },
    { 107, "aAggActorAdminKey" },
    { 108, "aAggActorOperKey" },
    { 109, "aAggMACAddress" },
    { 110, "aAggPartnerSystemID" },
    { 111, "aAggPartnerSystemPriority" },
    { 112, "aAggPartnerOperKey" },
    { 113, "aAggAdminState" },
    { 114, "aAggOperState" },
    { 115, "aAggTimeOfLastOperChange" },
    { 116, "aAggDataRate" },
    { 117, "aAggOctetsTxOK" },
    { 118, "aAggOctetsRxOK" },
    { 119, "aAggFramesTxOK" },
    { 120, "aAggFramesRxOK" },
    { 121, "aAggMulticastFramesTxOK" },
    { 122, "aAggMulticastFramesRxOK" },
    { 123, "aAggBroadcastFramesTxOK" },
    { 124, "aAggBroadcastFramesRxOK" },
    { 125, "aAggFramesDiscardedOnTx" },
    { 126, "aAggFramesDiscardedOnRx" },
    { 127, "aAggFramesWithTxErrors" },
    { 128, "aAggFramesWithRxErrors" },
    { 129, "aAggUnknownProtocolFrames" },
    { 130, "aAggLinkUpDownNotificationEnable" },
    { 131, "aAggPortList" },
    { 132, "aAggCollectorMaxDelay" },
    { 133, "aAggPortID" },
    { 134, "aAggPortActorSystemPriority" },
    { 135, "aAggPortActorSystemID" },
    { 136, "aAggPortActorAdminKey" },
    { 137, "aAggPortActorOperKey" },
    { 138, "aAggPortPartnerAdminSystemPriority" },
    { 139, "aAggPortPartnerOperSystemPriority" },
    { 140, "aAggPortPartnerAdminSystemID" },
    { 141, "aAggPortPartnerOperSystemID" },
    { 142, "aAggPortPartnerAdminKey" },
    { 143, "aAggPortPartnerOperKey" },
    { 144, "aAggPortSelectedAggID" },
    { 145, "aAggPortAttachedAggID" },
    { 146, "aAggPortActorPort" },
    { 147, "aAggPortActorPortPriority" },
    { 148, "aAggPortPartnerAdminPort" },
    { 149, "aAggPortPartnerOperPort" },
    { 150, "aAggPortPartnerAdminPortPriority" },
    { 151, "aAggPortPartnerOperPortPriority" },
    { 152, "aAggPortActorAdminState" },
    { 153, "aAggPortActorOperState" },
    { 154, "aAggPortPartnerAdminState" },
    { 155, "aAggPortPartnerOperState" },
    { 156, "aAggPortAggregateOrIndividual" },
    { 157, "aAggPortStatsID" },
    { 158, "aAggPortStatsLACPDUsRx" },
    { 159, "aAggPortStatsMarkerPDUsRx" },
    { 160, "aAggPortStatsMarkerResponsePDUsRx" },
    { 161, "aAggPortStatsUnknownRx" },
    { 162, "aAggPortStatsIllegalRx" },
    { 163, "aAggPortStatsLACPDUsTx" },
    { 164, "aAggPortStatsMarkerPDUsTx" },
    { 165, "aAggPortStatsMarkerResponsePDUsTx" },
    { 166, "aAggPortDebugInformationID" },
    { 167, "aAggPortDebugRxState" },
    { 168, "aAggPortDebugLastRxTime" },
    { 169, "aAggPortDebugMuxState" },
    { 170, "aAggPortDebugMuxReason" },
    { 171, "aAggPortDebugActorChurnState" },
    { 172, "aAggPortDebugPartnerChurnState" },
    { 173, "aAggPortDebugActorChurnCount" },
    { 174, "aAggPortDebugPartnerChurnCount" },
    { 175, "aAggPortDebugActorSyncTransitionCount" },
    { 176, "aAggPortDebugPartnerSyncTransitionCount" },
    { 177, "aAggPortDebugActorChangeCount" },
    { 178, "aAggPortDebugPartnerChangeCount" },


    { 236, "aOAMID" },
    { 237, "aOAMAdminState" },
    { 238, "aOAMMode" },
    { 239, "aOAMRemoteMACAddress" },
    { 240, "aOAMRemoteConfiguration" },
    { 241, "aOAMRemotePDUConfiguration" },
    { 242, "aOAMLocalFlagsField" },
    { 243, "aOAMRemoteFlagsField" },
    { 244, "aOAMRemoteRevision" },
    { 245, "aOAMRemoteState" },
    { 246, "aOAMRemoteVendorOUI" },
    { 247, "aOAMRemoteVendorSpecificInfo" },

    { 250, "aOAMUnsupportedCodesRx" },
    { 251, "aOAMInformationTx" },
    { 252, "aOAMInformationRx" },

    { 254, "aOAMUniqueEventNotificationRx" },
    { 255, "aOAMDuplicateEventNotificationRx" },
    { 256, "aOAMLoopbackControlTx" },
    { 257, "aOAMLoopbackControlRx" },
    { 258, "aOAMVariableRequestTx" },
    { 259, "aOAMVariableRequestRx" },
    { 260, "aOAMVariableResponseTx" },
    { 261, "aOAMVariableResponseRx" },
    { 262, "aOAMOrganizationSpecificTx" },
    { 263, "aOAMOrganizationSpecificRx" },
    { 264, "aOAMLocalErrSymPeriodConfig" },
    { 265, "aOAMLocalErrSymPeriodEvent" },
    { 266, "aOAMLocalErrFrameConfig" },
    { 267, "aOAMLocalErrFrameEvent" },
    { 268, "aOAMLocalErrFramePeriodConfig" },
    { 269, "aOAMLocalErrFramePeriodEvent" },
    { 270, "aOAMLocalErrFrameSecsSummaryConfig" },
    { 271, "aOAMLocalErrFrameSecsSummaryEvent" },
    { 272, "aOAMRemoteErrSymPeriodEvent" },
    { 273, "aOAMRemoteErrFrameEvent" },
    { 274, "aOAMRemoteErrFramePeriodEvent" },
    { 275, "aOAMRemoteErrFrameSecsSummaryEvent" },
    { 276, "aFramesLostDueToOAMError" },

    { 333, "aOAMDiscoveryState"},
    { 334, "aOAMLocalConfiguration"},
    { 335, "aOAMLocalPDUConfiguration"},
    { 336, "aOAMLocalRevision"},
    { 337, "aOAMLocalState"},
    { 338, "aOAMUnsupportedCodesTx" },
    { 339, "aOAMUniqueEventNotificationTx" },
    { 340, "aOAMDuplicateEventNotificationTx" },
    { 0, NULL }
};
static value_string_ext attribute_vals_ext = VALUE_STRING_EXT_INIT(attribute_vals);

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * package(4) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string indication_vals[] = {
    { 0x01, "Variable Container(s) exceeded OAMPDU data field" },

    { 0x20, "Attribute->Unable to return due to an undetermined error" },
    { 0x21, "Attribute->Unable to return because it is not supported" },
    { 0x22, "Attribute->May have been corrupted due to reset" },
    { 0x23, "Attribute->Unable to return due to a hardware failure" },
    { 0x24, "Attribute->Experience an overflow error" },

    { 0x40, "Object->End of object indication" },
    { 0x41, "Object->Unable to return due to an undetermined error" },
    { 0x42, "Object->Unable to return because it is not supported" },
    { 0x43, "Object->May have been corrupted due to reset" },
    { 0x44, "Object->Unable to return due to a hardware failure" },

    { 0x60, "Package->End of package indication" },
    { 0x61, "Package->Unable to return due to an undetermined error" },
    { 0x62, "Package->Unable to return because it is not supported" },
    { 0x63, "Package->May have been corrupted due to reset" },
    { 0x64, "Package->Unable to return due to a hardware failure" },
    { 0, NULL }
};

static const value_string status_vals[] _U_ = {
    { 0x00, "Unsatisfied, can't complete" },
    { 0x01, "Discovery in process" },
    { 0x02, "Satisfied, Discovery complete" },
    { 0x10, "Satisfied, Discovery complete" },
    { 0x20, "Discovery in process" },
    { 0x40, "Satisfied, Discovery complete" },
    { 0x50, "BUG Satisfied, Discovery complete" },
    { 0x80, "Discovery in process" },

    { 0, NULL }
};

static const value_string branch_vals[] = {
    { 3, "Object" },
    { 4, "Package" },
    { 6, "nameBinding" },
    { 7, "Attribute" },
    { 0, NULL }
};

static const value_string parser_vals[] = {
    { 0, "Forward non-OAMPDUs to higher sublayer" },
    { 1, "Loopback non-OAMPDUs to the lower sublayer" },
    { 2, "Discarding non-OAMPDUs" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const true_false_string mux = {
    "Discard non-OAMPDUs",
    "Forward non-OAMPDUs to lower sublayer"
};

static const true_false_string oam_mode = {
    "DTE configured in Active mode",
    "DTE configured in Passive mode"
};

static const true_false_string oam_uni = {
    "DTE is capable of sending OAMPDUs when rcv path is down",
    "DTE is not capable of sending OAMPDUs when rcv path is down"
};

static const true_false_string oam_lpbk = {
    "DTE is capable of OAM remote loopback mode",
    "DTE is not capable of OAM remote loopback mode"
};

static const true_false_string oam_event = {
    "DTE supports interpreting Link Events",
    "DTE does not support interpreting Link Events"
};

static const true_false_string oam_var = {
    "DTE supports sending Variable Response",
    "DTE does not support sending Variable Response"
};

/*
 * ESMC
 */
#define ITU_OUI_0                   0x00
#define ITU_OUI_1                   0x19
#define ITU_OUI_2                   0xa7
#define OUI_SIZE                       3
#define ESMC_ITU_SUBTYPE          0x0001
#define ESMC_VERSION_1              0x01
#define ESMC_QL_TLV_TYPE            0x01
#define ESMC_QL_TLV_LENGTH          0x04
#define ESMC_TIMESTAMP_TLV_TYPE     0x02
#define ESMC_TIMESTAMP_TLV_LENGTH   0x08

static const value_string esmc_event_flag_vals[] = {
    { 0, "Information ESMC PDU" },
    { 1, "Time-critical Event ESMC PDU" },
    { 0, NULL }
};

static const value_string esmc_tlv_type_vals[] = {
    { 1, "Quality Level" },
    { 2, "Timestamp" },
    { 0, NULL }
};

static const value_string esmc_timestamp_valid_flag_vals[] = {
    { 0, "Not set. Do not use Timestamp value even if Timestamp TLV present" },
    { 1, "Set. Timestamp TLV Present" },
    { 0, NULL }
};

/* G.781 5.5.1.1 Option I SDH (same in G.707) */
static const value_string esmc_quality_level_opt_1_vals[] = {
    {  2,   "QL-PRC, Primary reference clock (G.811)" },
    {  4,   "QL-SSU-A, Type I or V SSU clock (G.812), 'transit node clock'" },
    {  8,   "QL-SSU-B, Type VI SSU clock (G.812), 'local node clock'" },
    { 11,   "QL-SEC, SEC clock (G.813, Option I) or QL-EEC1 (G.8262)" },
    { 15,   "QL-DNU, 'Do Not Use'" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_1_vals_short[] = {
    {  2,   "QL-PRC" },
    {  4,   "QL-SSU-A" },
    {  8,   "QL-SSU-B" },
    { 11,   "QL-SEC" },
    { 15,   "QL-DNU" },
    { 0, NULL }
};

#if 0 /*not used yet*/
/* G.781 5.5.1.2 Option II SDH synchronization networking */
static const value_string esmc_quality_level_opt_2_vals[] = {
    {  0,   "QL-STU, unknown - signal does not carry the QL message of the source" },
    {  1,   "QL-PRS, PRS clock (G.811) / ST1, Stratum 1 Traceable" },
    {  4,   "QL-TNC, Transit Node Clock (G.812, Type V)" },
    {  7,   "QL-ST2, Stratum 2 clock (G.812, Type II)" },
    { 10,   "QL-ST3, Stratum 3 clock (G.812, Type IV) or QL-EEC2 (G.8262)" },
    { 12,   "QL-SMC, SONET self timed clock (G.813, Option II) / SMC 20 ppm Clock Traceable" },
    { 13,   "QL-ST3E, Stratum 3E clock (G.812, Type III)" },
    { 14,   "QL-PROV, provisionable by the network operator / Reserved for Network Synchronization" },
    { 15,   "QL-DUS, shall not be used for synchronization" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_2_short[] = {
    {  0,   "QL-STU" },
    {  1,   "QL-PRS" },
    {  4,   "QL-TNC" },
    {  7,   "QL-ST2" },
    { 10,   "QL-ST3" },
    { 12,   "QL-SMC" },
    { 13,   "QL-ST3E" },
    { 14,   "QL-PROV" },
    { 15,   "QL-DUS" },
    { 0, NULL }
};
#endif

static const value_string esmc_quality_level_invalid_vals[] = {
    {  0,   "QL-INV0" },
    {  1,   "QL-INV1" },
    {  2,   "QL-INV2" },
    {  3,   "QL-INV3" },
    {  4,   "QL-INV4" },
    {  5,   "QL-INV5" },
    {  6,   "QL-INV6" },
    {  7,   "QL-INV7" },
    {  8,   "QL-INV8" },
    {  9,   "QL-INV9" },
    { 10,   "QL-INV10" },
    { 11,   "QL-INV11" },
    { 12,   "QL-INV12" },
    { 13,   "QL-INV13" },
    { 14,   "QL-INV14" },
    { 15,   "QL-INV15" },
    { 0, NULL }
};

/* Initialise the protocol and registered fields */
static int proto_slow = -1;

static int hf_slow_subtype = -1;

static int hf_lacpdu_version_number = -1;
static int hf_lacpdu_actor_type = -1;
static int hf_lacpdu_actor_info_len = -1;
static int hf_lacpdu_actor_sys_priority = -1;
static int hf_lacpdu_actor_sys = -1;
static int hf_lacpdu_actor_key = -1;
static int hf_lacpdu_actor_port_priority = -1;
static int hf_lacpdu_actor_port = -1;
static int hf_lacpdu_actor_state = -1;
static int hf_lacpdu_flags_a_activity = -1;
static int hf_lacpdu_flags_a_timeout = -1;
static int hf_lacpdu_flags_a_aggregation = -1;
static int hf_lacpdu_flags_a_sync = -1;
static int hf_lacpdu_flags_a_collecting = -1;
static int hf_lacpdu_flags_a_distrib = -1;
static int hf_lacpdu_flags_a_defaulted = -1;
static int hf_lacpdu_flags_a_expired = -1;
static int hf_lacpdu_actor_reserved = -1;

static int hf_lacpdu_partner_type = -1;
static int hf_lacpdu_partner_info_len = -1;
static int hf_lacpdu_partner_sys_priority = -1;
static int hf_lacpdu_partner_sys = -1;
static int hf_lacpdu_partner_key = -1;
static int hf_lacpdu_partner_port_priority = -1;
static int hf_lacpdu_partner_port = -1;
static int hf_lacpdu_partner_state = -1;
static int hf_lacpdu_flags_p_activity = -1;
static int hf_lacpdu_flags_p_timeout = -1;
static int hf_lacpdu_flags_p_aggregation = -1;
static int hf_lacpdu_flags_p_sync = -1;
static int hf_lacpdu_flags_p_collecting = -1;
static int hf_lacpdu_flags_p_distrib = -1;
static int hf_lacpdu_flags_p_defaulted = -1;
static int hf_lacpdu_flags_p_expired = -1;
static int hf_lacpdu_partner_reserved = -1;

static int hf_lacpdu_coll_type = -1;
static int hf_lacpdu_coll_info_len = -1;
static int hf_lacpdu_coll_max_delay = -1;
static int hf_lacpdu_coll_reserved = -1;

static int hf_lacpdu_term_type = -1;
static int hf_lacpdu_term_len = -1;
static int hf_lacpdu_term_reserved = -1;

/* ESMC */
static int hf_ossp_oui = -1;
static int hf_itu_subtype = -1;
static int hf_esmc_version = -1;
static int hf_esmc_event_flag = -1;
static int hf_esmc_timestamp_valid_flag = -1;
static int hf_esmc_reserved_32 = -1;
static int hf_esmc_tlv = -1;
static int hf_esmc_tlv_type = -1;
static int hf_esmc_tlv_length = -1;
static int hf_esmc_tlv_ql_unused = -1;
static int hf_esmc_tlv_ts_reserved = -1;
static int hf_esmc_quality_level_opt_1 = -1;
#if 0 /*not used yet*/
static int hf_esmc_quality_level_opt_2 = -1;
#endif
static int hf_esmc_quality_level_invalid = -1;
static int hf_esmc_timestamp = -1;
static int hf_esmc_padding = -1;

/*
 * The Timestamp TLV and Timestamp Valid Flag fields
 * are proposed in WD56 document for G.8264.
 * WD56 is not accepted at this moment (June 2009).
 *
 * The following variable controls dissection of Timestamp fields.
 * Implementation is not fully complete yet -- in this version
 * Timestamp dissection is always enabled.
 *
 * I expect that when WD56 proposal for G.8264 will be accepted,
 * ESMC Version would be used to control Timestamp dissection.
 * In this case this variable will be eliminated (replaced).
 *
 * Until that, a preference which controls Timestamp
 * dissection may be added, if such need arise.
 * At the moment this is not practical as nobody needs this.
 */
static gboolean pref_decode_esmc_timestamp = TRUE;

/* MARKER */
static int hf_marker_version_number = -1;
static int hf_marker_tlv_type = -1;
static int hf_marker_tlv_length = -1;
static int hf_marker_req_port = -1;
static int hf_marker_req_system = -1;
static int hf_marker_req_trans_id = -1;

/* OAM */
static int hf_oampdu_flags = -1;
static int hf_oampdu_flags_link_fault = -1;
static int hf_oampdu_flags_dying_gasp = -1;
static int hf_oampdu_flags_critical_event = -1;
static int hf_oampdu_flags_local_evaluating = -1;
static int hf_oampdu_flags_local_stable = -1;
static int hf_oampdu_flags_remote_evaluating = -1;
static int hf_oampdu_flags_remote_stable = -1;
static int hf_oampdu_code = -1;

static int hf_oampdu_info_type = -1;
static int hf_oampdu_info_len = -1;
static int hf_oampdu_info_version = -1;
static int hf_oampdu_info_revision = -1;
static int hf_oampdu_info_state = -1;
static int hf_oampdu_info_oamConfig = -1;
static int hf_oampdu_info_oampduConfig = -1;
static int hf_oampdu_info_oui = -1;
static int hf_oampdu_info_vendor = -1;

static int hf_oampdu_info_state_parser = -1;
static int hf_oampdu_info_state_mux = -1;

static int hf_oampdu_info_oamConfig_mode = -1;
static int hf_oampdu_info_oamConfig_uni = -1;
static int hf_oampdu_info_oamConfig_lpbk = -1;
static int hf_oampdu_info_oamConfig_event = -1;
static int hf_oampdu_info_oamConfig_var = -1;

static int hf_oampdu_event_type = -1;
static int hf_oampdu_event_sequence = -1;
static int hf_oampdu_event_length = -1;
static int hf_oampdu_event_timeStamp = -1;

static int hf_oampdu_event_espeWindow = -1;
static int hf_oampdu_event_espeThreshold = -1;
static int hf_oampdu_event_espeErrors = -1;
static int hf_oampdu_event_espeTotalErrors = -1;
static int hf_oampdu_event_espeTotalEvents = -1;

static int hf_oampdu_event_efeWindow = -1;
static int hf_oampdu_event_efeThreshold = -1;
static int hf_oampdu_event_efeErrors = -1;
static int hf_oampdu_event_efeTotalErrors = -1;
static int hf_oampdu_event_efeTotalEvents = -1;

static int hf_oampdu_event_efpeWindow = -1;
static int hf_oampdu_event_efpeThreshold = -1;
static int hf_oampdu_event_efpeErrors = -1;
static int hf_oampdu_event_efpeTotalErrors = -1;
static int hf_oampdu_event_efpeTotalEvents = -1;

static int hf_oampdu_event_efsseWindow = -1;
static int hf_oampdu_event_efsseThreshold = -1;
static int hf_oampdu_event_efsseErrors = -1;
static int hf_oampdu_event_efsseTotalErrors = -1;
static int hf_oampdu_event_efsseTotalEvents = -1;

static int hf_oampdu_variable_branch = -1;
static int hf_oampdu_variable_object = -1;
static int hf_oampdu_variable_package = -1;
static int hf_oampdu_variable_binding = -1;
static int hf_oampdu_variable_attribute = -1;
static int hf_oampdu_variable_width = -1;
static int hf_oampdu_variable_indication = -1;
static int hf_oampdu_variable_value = -1;

static int hf_oampdu_lpbk = -1;
static int hf_oampdu_lpbk_enable = -1;
static int hf_oampdu_lpbk_disable = -1;


/* Initialise the subtree pointers */

static gint ett_pdu = -1;

static gint ett_lacpdu = -1;
static gint ett_lacpdu_a_flags = -1;
static gint ett_lacpdu_p_flags = -1;

static gint ett_marker = -1;
static gint ett_esmc = -1;

static gint ett_oampdu = -1;
static gint ett_oampdu_flags = -1;

static gint ett_oampdu_local_info = -1;
static gint ett_oampdu_local_info_state = -1;
static gint ett_oampdu_local_info_config = -1;
static gint ett_oampdu_remote_info = -1;
static gint ett_oampdu_remote_info_state = -1;
static gint ett_oampdu_remote_info_config = -1;
static gint ett_oampdu_org_info = -1;

static gint ett_oampdu_event_espe = -1;
static gint ett_oampdu_event_efe = -1;
static gint ett_oampdu_event_efpe = -1;
static gint ett_oampdu_event_efsse = -1;
static gint ett_oampdu_event_ose = -1;

static gint ett_oampdu_lpbk_ctrl = -1;

static gint ett_ossppdu = -1;
static gint ett_itu_ossp = -1;

static const char initial_sep[] = " (";
static const char cont_sep[] = ", ";

static dissector_handle_t dh_data;

#define APPEND_BOOLEAN_FLAG(flag, item, string) \
    if(flag){                                   \
        if(item)                                          \
            proto_item_append_text(item, string, sep);    \
        sep = cont_sep;                                   \
    }


#define APPEND_OUI_NAME(item, string, tvb, offset) \
    if(item){                              \
        string = tvb_get_manuf_name(tvb, offset);          \
        proto_item_append_text(item, " (");                \
        proto_item_append_text(item, "%s", string);        \
        proto_item_append_text(item, ")");                 \
    }

static void
dissect_lacp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_marker_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ossp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_oampdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_oampdu_information(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_event_notification(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_variable_request(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_variable_response(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_loopback_control(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_vendor_specific(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_esmc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *treex);

static void
dissect_itu_ossp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*
 * Name: dissect_slow_protocols
 *
 * Description:
 *    This function is used to dissect the slow protocols defined in IEEE802.3
 *    CSMA/CD. The current slow protocols subtypes are define in ANNEX 43B of
 *    the 802.3 document. In case of an unsupported slow protocol, we only
 *    fill the protocol and info columns.
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values:
 *    None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for OAM slow protocol (defined in clause 57).
 *      + add support for Marker slow protocol (defined in clause 43).
 *    Artem Tamazov (artem.tamazov@telllabs.com)
 *      + add support for ESMC (Ethernet Synchronization Messaging Channel),
 *        (defined in G.8264/Y.1364 clause 11).
 */
static void
dissect_slow_protocols(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8      subtype;
    proto_tree *pdu_tree;
    proto_item *pdu_item;

    subtype = tvb_get_guint8(tvb, 0);

    switch (subtype)
    {
        case LACP_SUBTYPE:
            dissect_lacp_pdu(tvb, pinfo, tree);
            break;
        case MARKER_SUBTYPE:
            dissect_marker_pdu(tvb, pinfo, tree);
            break;
        case OAM_SUBTYPE:
            dissect_oampdu(tvb, pinfo, tree);
            break;
        case OSSP_SUBTYPE:
            dissect_ossp_pdu(tvb, pinfo, tree);
            break;
        default:
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Slow Protocols");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Subtype = %u.", subtype);

            if (tree)
            {
                pdu_item = proto_tree_add_item(tree, proto_slow, tvb,
                        0, -1, ENC_NA);
                pdu_tree = proto_item_add_subtree(pdu_item, ett_pdu);

                /* Subtype */
                proto_tree_add_item(pdu_tree, hf_slow_subtype, tvb,
                        0, 1, ENC_BIG_ENDIAN);
            }

            break;
        }
    }
}

/*
 * Name: dissect_lacp_pdu
 *
 * Description:
 *    This function is used to dissect the Link Aggregation Control Protocol
 *    slow protocols defined in IEEE802.3 clause 43.3.
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 */
static void
dissect_lacp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16 raw_word;
    guint8  raw_octet;

    guint8  flags;

    proto_tree *lacpdu_tree;
    proto_item *lacpdu_item;
    proto_tree *actor_flags_tree;
    proto_item *actor_flags_item;
    proto_tree *partner_flags_tree;
    proto_item *partner_flags_item;

    const char *sep;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LACP");
    col_set_str(pinfo->cinfo, COL_INFO, "Link Aggregation Control Protocol");

    if (tree)
    {
        /* Add LACP Heading */
        lacpdu_item = proto_tree_add_protocol_format(tree, proto_slow, tvb,
                0, -1, "Link Aggregation Control Protocol");
        lacpdu_tree = proto_item_add_subtree(lacpdu_item, ett_lacpdu);

        /* Subtype */
        proto_tree_add_item(lacpdu_tree, hf_slow_subtype, tvb,
                0, 1, ENC_BIG_ENDIAN);

        /* Version Number */
        raw_octet = tvb_get_guint8(tvb, LACPDU_VERSION_NUMBER);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_version_number, tvb,
                LACPDU_VERSION_NUMBER, 1, raw_octet);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Version %d.  ", raw_octet);

        /* Actor Type */
        raw_octet = tvb_get_guint8(tvb, LACPDU_ACTOR_TYPE);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_type, tvb,
                LACPDU_ACTOR_TYPE, 1, raw_octet);

        /* Actor Info Length */
        raw_octet = tvb_get_guint8(tvb, LACPDU_ACTOR_INFO_LEN);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_info_len, tvb,
                LACPDU_ACTOR_INFO_LEN, 1, raw_octet);

        /* Actor System Priority */

        raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_SYS_PRIORITY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_sys_priority, tvb,
                LACPDU_ACTOR_SYS_PRIORITY, 2, raw_word);
        /* Actor System */

        proto_tree_add_item(lacpdu_tree, hf_lacpdu_actor_sys, tvb,
                LACPDU_ACTOR_SYSTEM, 6, ENC_NA);

        /* Actor Key */

        raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_KEY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_key, tvb,
                LACPDU_ACTOR_KEY, 2, raw_word);

        /* Actor Port Priority */

        raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_PORT_PRIORITY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_port_priority, tvb,
                LACPDU_ACTOR_PORT_PRIORITY, 2, raw_word);

        /* Actor Port */

        raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_PORT);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_port, tvb,
                LACPDU_ACTOR_PORT, 2, raw_word);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Actor Port = %d ", raw_word);

        /* Actor State */

        flags = tvb_get_guint8(tvb, LACPDU_ACTOR_STATE);
        actor_flags_item = proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_state, tvb,
                LACPDU_ACTOR_STATE, 1, flags);
        actor_flags_tree = proto_item_add_subtree(actor_flags_item, ett_lacpdu_a_flags);

        sep = initial_sep;

        /* Activity Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_ACTIVITY, actor_flags_item,
                "%sActivity");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_activity, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        /* Timeout Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_TIMEOUT, actor_flags_item,
                "%sTimeout");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_timeout, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        /* Aggregation Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_AGGREGATION, actor_flags_item,
                "%sAggregation");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_aggregation, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        /* Synchronization Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_SYNC, actor_flags_item,
                "%sSynchronization");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_sync, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        /* Collecting Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_COLLECTING, actor_flags_item,
                "%sCollecting");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_collecting, tvb,
                LACPDU_ACTOR_STATE, 1, flags);


        /* Distributing Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DISTRIB, actor_flags_item,
                "%sDistributing");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_distrib, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        /* Defaulted Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DEFAULTED, actor_flags_item,
                "%sDefaulted");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_defaulted, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        /* Expired Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_EXPIRED, actor_flags_item,
                "%sExpired");
        proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_expired, tvb,
                LACPDU_ACTOR_STATE, 1, flags);

        if (sep != initial_sep)
        {
            /* We put something in; put in the terminating ")" */
            proto_item_append_text(actor_flags_item, ")");
        }

        /* Actor Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacpdu_actor_reserved, tvb,
                LACPDU_ACTOR_RESERVED, 3, ENC_NA);


        /* Partner Type */
        raw_octet = tvb_get_guint8(tvb, LACPDU_PARTNER_TYPE);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_type, tvb,
                LACPDU_PARTNER_TYPE, 1, raw_octet);

        /* Partner Info Length */
        raw_octet = tvb_get_guint8(tvb, LACPDU_PARTNER_INFO_LEN);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_info_len, tvb,
                LACPDU_PARTNER_INFO_LEN, 1, raw_octet);

        /* Partner System Priority */

        raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_SYS_PRIORITY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_sys_priority, tvb,
                LACPDU_PARTNER_SYS_PRIORITY, 2, raw_word);

        /* Partner System */

        proto_tree_add_item(lacpdu_tree, hf_lacpdu_partner_sys, tvb,
                LACPDU_PARTNER_SYSTEM, 6, ENC_NA);

        /* Partner Key */

        raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_KEY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_key, tvb,
                LACPDU_PARTNER_KEY, 2, raw_word);

        /* Partner Port Priority */

        raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_PORT_PRIORITY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_port_priority, tvb,
                LACPDU_PARTNER_PORT_PRIORITY, 2, raw_word);

        /* Partner Port */

        raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_PORT);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_port, tvb,
                LACPDU_PARTNER_PORT, 2, raw_word);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Partner Port = %d ", raw_word);

        /* Partner State */

        flags = tvb_get_guint8(tvb, LACPDU_PARTNER_STATE);
        partner_flags_item = proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_state, tvb,
                LACPDU_PARTNER_STATE, 1, flags);
        partner_flags_tree = proto_item_add_subtree(partner_flags_item, ett_lacpdu_p_flags);

        sep = initial_sep;

        /* Activity Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_ACTIVITY, partner_flags_item,
                "%sActivity");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_activity, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        /* Timeout Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_TIMEOUT, partner_flags_item,
                "%sTimeout");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_timeout, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        /* Aggregation Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_AGGREGATION, partner_flags_item,
                "%sAggregation");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_aggregation, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        /* Synchronization Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_SYNC, partner_flags_item,
                "%sSynchronization");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_sync, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        /* Collecting Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_COLLECTING, partner_flags_item,
                "%sCollecting");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_collecting, tvb,
                LACPDU_PARTNER_STATE, 1, flags);


        /* Distributing Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DISTRIB, partner_flags_item,
                "%sDistributing");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_distrib, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        /* Defaulted Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DEFAULTED, partner_flags_item,
                "%sDefaulted");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_defaulted, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        /* Expired Flag */

        APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_EXPIRED, partner_flags_item,
                "%sExpired");
        proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_expired, tvb,
                LACPDU_PARTNER_STATE, 1, flags);

        if (sep != initial_sep)
        {
            /* We put something in; put in the terminating ")" */
            proto_item_append_text(partner_flags_item, ")");
        }

        /* Partner Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacpdu_partner_reserved, tvb,
                LACPDU_PARTNER_RESERVED, 3, ENC_NA);


        /* Collector Type */
        raw_octet = tvb_get_guint8(tvb, LACPDU_COLL_TYPE);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_coll_type, tvb,
                LACPDU_COLL_TYPE, 1, raw_octet);

        /* Collector Info Length */
        raw_octet = tvb_get_guint8(tvb, LACPDU_COLL_INFO_LEN);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_coll_info_len, tvb,
                LACPDU_COLL_INFO_LEN, 1, raw_octet);

        /* Collector Max Delay */

        raw_word = tvb_get_ntohs(tvb, LACPDU_COLL_MAX_DELAY);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_coll_max_delay, tvb,
                LACPDU_COLL_MAX_DELAY, 2, raw_word);

        /* Collector Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacpdu_coll_reserved, tvb,
                LACPDU_COLL_RESERVED, 12, ENC_NA);

        /* Terminator Type */
        raw_octet = tvb_get_guint8(tvb, LACPDU_TERM_TYPE);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_term_type, tvb,
                LACPDU_TERM_TYPE, 1, raw_octet);

        /* Terminator Info Length */
        raw_octet = tvb_get_guint8(tvb, LACPDU_TERM_LEN);
        proto_tree_add_uint(lacpdu_tree, hf_lacpdu_term_len, tvb,
                LACPDU_TERM_LEN, 1, raw_octet);

        /* Terminator Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacpdu_term_reserved, tvb,
                LACPDU_TERM_RESERVED, 50, ENC_NA);
    }
}

/*
 * Name: dissect_marker_pdu
 *
 * Description:
 *    This function is used to dissect the Link Aggregation Marker Protocol
 *    slow protocols defined in IEEE802.3 clause 43.5 (The PDUs are defined
 *    in section 43.5.3.2). The TLV types are 0x01 for a marker TLV and 0x02
 *    for a marker response. A value of 0x00 indicates an end of message.
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for MARKER and MARKER Response PDUs.
 */
static void
dissect_marker_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8  raw_octet;
    guint16 raw_word;
    guint32 dword;
    guint32 offset;

    proto_tree *marker_tree;
    proto_item *marker_item;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MARKER");
    col_set_str(pinfo->cinfo, COL_INFO, "Marker Protocol");

    if (tree)
    {
        marker_item = proto_tree_add_protocol_format(tree, proto_slow, tvb,
                            0, -1, "Marker Protocol");
        marker_tree = proto_item_add_subtree(marker_item, ett_marker);

        /* Subtype */
        proto_tree_add_item(marker_tree, hf_slow_subtype, tvb,
                0, 1, ENC_BIG_ENDIAN);

        offset = 1;

        /* Version Number */
        raw_octet = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(marker_tree, hf_marker_version_number, tvb,
                offset, 1, raw_octet);

        offset += 1;

        while (1)
        {
            /* TLV Type */
            raw_octet = tvb_get_guint8(tvb, offset);

            if (raw_octet==0) break;

            proto_tree_add_uint(marker_tree, hf_marker_tlv_type, tvb,
                    offset, 1, raw_octet);

            offset += 1;

            /* TLV Length */
            raw_octet = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(marker_tree, hf_marker_tlv_length, tvb,
                    offset, 1, raw_octet);
            offset += 1;

            /* Requester Port */
            raw_word = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(marker_tree, hf_marker_req_port, tvb,
                    offset, 2, raw_word);
            offset += 2;

            /* Requester System */
            proto_tree_add_item(marker_tree, hf_marker_req_system, tvb,
                    offset, 6, ENC_NA);
            offset += 6;

            /* Requester Transaction ID */
            dword = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(marker_tree, hf_marker_req_trans_id, tvb,
                    offset, 4, dword);
            offset += 2;

            /* Pad to align */
            offset += 2;
        }
    }
}

/*
 * Name: dissect_ossp_pdu
 *
 * Description:
 *    This function is used to dissect the Organization Specific Slow
 *    Protocol defined in IEEE 802.3 Annex 57B. Currently only the ESMC
 *    slow protocol as defined in ITU-T G.8264 is implemented
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Roberto Morro (roberto.morro[AT]tilab.com)
 */
static void
dissect_ossp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint          offset = 0;
    const gchar  *str;
    proto_item   *oui_item, *ossp_item;
    proto_tree   *ossp_tree;
    tvbuff_t     *ossp_tvb;
    const guint8  itu_oui[] = {ITU_OUI_0, ITU_OUI_1, ITU_OUI_2};

    /* OUI of the organization defining the protocol */
    str = tvb_get_manuf_name(tvb, offset+1);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSSP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "OUI: %s", str);

    ossp_item = proto_tree_add_protocol_format(tree, proto_slow, tvb, 0, -1,
                                               "Organization Specific Slow Protocol");
    ossp_tree = proto_item_add_subtree(ossp_item, ett_ossppdu);

    /* Slow Protocol Subtype */
    proto_tree_add_item(ossp_tree, hf_slow_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    oui_item = proto_tree_add_item(ossp_tree, hf_ossp_oui,
                                    tvb, offset, OUI_SIZE, ENC_NA);
    proto_item_append_text(oui_item, " (%s)", str);
    offset += 3;

    ossp_tvb = tvb_new_subset_remaining(tvb, offset);
    if (tvb_memeql(tvb, 1, itu_oui, OUI_SIZE) == 0)
    {
       dissect_itu_ossp(ossp_tvb, pinfo, ossp_tree);
    }
/*    new Organization Specific Slow Protocols go hereafter */
#if 0
    else if (tvb_memeql(tvb, 1, xxx_oui, OUI_SIZE) == 0)
    {
        dissect_xxx_ossp(ossp_tvb, pinfo, ossp_tree);
    }
    else if (tvb_memeql(tvb, 1, yyy_oui, OUI_SIZE) == 0)
    {
        dissect_yyy_ossp(ossp_tvb, pinfo, ossp_tree);
    }
#endif
    else
    {
        proto_item_append_text(oui_item, " (Unknown OSSP organization)");
    }
}


/*
 * Name: dissect_itu_ossp
 *
 * Description:
 *    This function is used to dissect the ITU-T OSSP (Organization Specific
 *    Slow Protocol). Currently only the Ethernet Synchronization
 *    Messaging Channel (ESMC) slow protocol as defined in ITU-T G.8264
 *    is implemented
 *
 * Input Arguments:
 *    tvb:     buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo:   structure associated with the rcv packet (see packet_info.h).
 *    tree:    the protocol tree associated with the rcv packet (see proto.h).
 *    subtype: the protocol subtype (according to IEEE802.3 annex 57B)
 *
 * Return Values: None
 *
 * Notes:
 *    Roberto Morro (roberto.morro[AT]tilab.com)
 */

static void
dissect_itu_ossp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16     subtype;
    proto_tree *itu_ossp_tree, *ti;

    /* ITU-T OSSP Subtype */
    subtype = tvb_get_ntohs(tvb, 0);
    ti = proto_tree_add_item(tree, hf_itu_subtype, tvb, 0, 2, ENC_BIG_ENDIAN);

    itu_ossp_tree = proto_item_add_subtree(ti, ett_itu_ossp);

    switch (subtype)
    {
        case ESMC_ITU_SUBTYPE:
            dissect_esmc_pdu(tvb, pinfo, itu_ossp_tree);
            break;

/*  Other ITU-T defined slow protocols go hereafter */
#if 0
        case XXXX_ITU_SUBTYPE:
            dissect_xxxx_pdu(tvb, pinfo, itu_ossp_tree);
            break;
#endif
        default:
            proto_item_append_text(itu_ossp_tree, " (Unknown)");
    }
}
/*
 * Description:
 *    This function is used to dissect ESMC PDU defined G.8264/Y.1364 clause 11.3.1.1.
 *
 *    Added: TimeStamp TLV as per WD56 proposal for G.8264,
 *    "TLVs for ESMC and Querying Capability".
 */
static void
dissect_esmc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *treex)
{
    gint     offset    = 2; /*starting from ESMC Version */
    gboolean event_flag;
    gboolean malformed = FALSE;
    gint     ql        = -1; /*negative means unknown:*/
    gboolean timestamp_valid_flag = FALSE; /*set if timestamp valid*/
    gint32   timestamp = -1; /*nanoseconds*/

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESMC");

    proto_item_append_text(treex, ": ESMC");
    {
        proto_tree *tree_a;
        tree_a = proto_item_add_subtree(treex, ett_esmc);

        { /* version */
            proto_item *item_b;
            item_b = proto_tree_add_item(tree_a, hf_esmc_version, tvb, offset, 1, ENC_BIG_ENDIAN);
            if ((tvb_get_guint8(tvb, offset) >> 4) != ESMC_VERSION_1)
            {
                malformed = TRUE;
                expert_add_info_format(pinfo, item_b, PI_MALFORMED, PI_ERROR
                        ,"Version must be 0x%.1x claim compliance with Version 1 of this protocol"
                        ,ESMC_VERSION_1);
            }
            /*stay at the same octet in tvb*/
        }
        { /* event flag */
            event_flag = ((tvb_get_guint8(tvb, offset) & 0x08) != 0);
            proto_tree_add_item(tree_a, hf_esmc_event_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*stay at the same octet in tvb*/
        }
        if (pref_decode_esmc_timestamp)
        { /* timestamp valid flag */
            timestamp_valid_flag = ((tvb_get_guint8(tvb, offset) & 0x04) != 0);
            proto_tree_add_item(tree_a, hf_esmc_timestamp_valid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*stay at the same octet in tvb*/
        }
        { /* reserved bits */
            proto_item *item_b;
            guint32 reserved;
            reserved = tvb_get_ntohl(tvb, offset)
                        & (pref_decode_esmc_timestamp ? 0x3ffffff : 0x7ffffff);
            item_b = proto_tree_add_uint_format_value(tree_a, hf_esmc_reserved_32, tvb, offset, 4
                                                    , reserved, "0x%.7x", reserved);
            if (reserved != 0x0)
            {
                malformed = TRUE;
                expert_add_info_format(pinfo, item_b, PI_MALFORMED, PI_WARN
                        ,"Reserved bits must be set to all zero on transmitter");
            }
            offset += 4;
        }
        proto_item_append_text(treex, ", Event:%s", event_flag ?
                               "Time-critical" : "Information");

        /*
         * Quality Level TLV is mandatory at fixed location.
         */
        {
            proto_item *item_b;
            guint8 type;
            item_b = proto_tree_add_item(tree_a, hf_esmc_tlv, tvb, offset, 4, ENC_NA);
            {
                proto_tree *tree_b;
                tree_b = proto_item_add_subtree(item_b, ett_esmc);
                {
                    proto_item *item_c;
                    guint16 length;
                    guint8 unused;

                    /* type */
                    type = tvb_get_guint8(tvb, offset);
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (type != ESMC_QL_TLV_TYPE)
                    {
                        malformed = TRUE;
                        expert_add_info_format(pinfo, item_c, PI_MALFORMED, PI_ERROR
                                ,"TLV Type must be == 0x%.2x (QL) because QL TLV must be first in the ESMC PDU"
                                ,ESMC_QL_TLV_TYPE);
                        expert_add_info_format(pinfo, item_c, PI_UNDECODED, PI_NOTE
                                ,"Let's decode as if this is QL TLV");
                    }
                    offset += 1;

                    /* length */
                    length = tvb_get_ntohs(tvb, offset);
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    if (length != ESMC_QL_TLV_LENGTH)
                    {
                        malformed = TRUE;
                        expert_add_info_format(pinfo, item_c, PI_MALFORMED, PI_ERROR
                                ,"QL TLV Length must be == 0x%.4x", ESMC_QL_TLV_LENGTH);
                        expert_add_info_format(pinfo, item_c, PI_UNDECODED, PI_NOTE
                                ,"Let's decode this TLV as if Length has valid value");
                    }
                    offset += 2;

                    /* value */
                    unused = tvb_get_guint8(tvb, offset); /*as temp var*/
                    ql = unused & 0x0f;
                    unused &= 0xf0;
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ql_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (unused != 0x00)
                    {
                        malformed = TRUE;
                        expert_add_info_format(pinfo, item_c, PI_MALFORMED, PI_WARN
                                ,"Unused bits of TLV must be all zeroes");
                    }
                    if (NULL != match_strval(ql, esmc_quality_level_opt_1_vals))
                    {
                        proto_tree_add_item(tree_b, hf_esmc_quality_level_opt_1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    else
                    {
                        item_c = proto_tree_add_item(tree_b, hf_esmc_quality_level_invalid, tvb, offset, 1, ENC_BIG_ENDIAN);
                        expert_add_info_format(pinfo, item_c, PI_UNDECODED, PI_WARN
                                ,"Invalid SSM message, unknown QL code");
                    }
                    offset += 1;
                }
            }
            proto_item_append_text(item_b, ", %s"
                , val_to_str(ql, esmc_quality_level_opt_1_vals_short, "QL-INV%d"));
        }
        proto_item_append_text(treex, ", %s"
            , val_to_str(ql, esmc_quality_level_opt_1_vals_short, "QL-INV%d"));

        if (pref_decode_esmc_timestamp)
        {
            /*
             * Timestamp TLV is optional at fixed location.
             * Decode it if Timestamp Valid flag is set,
             * or if type of next TLV is 0x02.
             */
            guint8 type;
            type = tvb_get_guint8(tvb, offset);

            if (timestamp_valid_flag || type == ESMC_TIMESTAMP_TLV_TYPE)
            {
                proto_item *item_b;
                item_b = proto_tree_add_item(tree_a, hf_esmc_tlv, tvb, offset, 8, ENC_NA);
                {
                    proto_tree *tree_b;
                    tree_b = proto_item_add_subtree(item_b, ett_esmc);
                    {
                        proto_item *item_c;
                        guint16 length;
                        guint8 reserved;

                        /* type */
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (type != ESMC_TIMESTAMP_TLV_TYPE)
                        {
                            malformed = TRUE;
                            expert_add_info_format(pinfo, item_c, PI_MALFORMED, PI_ERROR
                                    ,"TLV Type must be == 0x%.2x (Timestamp) because Timestamp Valid Flag is set"
                                    ,ESMC_TIMESTAMP_TLV_TYPE);
                            expert_add_info_format(pinfo, item_c, PI_UNDECODED, PI_NOTE
                                    ,"Let's decode as if this is Timestamp TLV");
                        }
                        offset += 1;

                        /* length */
                        length = tvb_get_ntohs(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                        if (length != ESMC_TIMESTAMP_TLV_LENGTH)
                        {
                            malformed = TRUE;
                            expert_add_info_format(pinfo, item_c, PI_MALFORMED, PI_ERROR
                                    ,"Timestamp TLV Length must be == 0x%.4x"
                                    ,ESMC_TIMESTAMP_TLV_LENGTH);
                            expert_add_info_format(pinfo, item_c, PI_UNDECODED, PI_NOTE
                                    ,"Let's decode this TLV as if Length has valid value");
                        }
                        offset += 2;

                        /* value */
                        timestamp = (gint32)tvb_get_ntohl(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
                        if (!timestamp_valid_flag) proto_item_append_text(item_c, " [invalid]");
                        offset += 4;

                        /* reserved */
                        reserved = tvb_get_guint8(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ts_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (reserved != 0x0)
                        {
                            expert_add_info_format(pinfo, item_c, PI_UNDECODED, PI_WARN
                                    ,"Reserved bits must be set to all zero");
                        }
                        offset += 1;
                    }
                }
                proto_item_append_text(item_b, ", Timestamp: %d ns", timestamp);
                if (!timestamp_valid_flag) proto_item_append_text(item_b, " [invalid]");
            }
        }
        if (timestamp_valid_flag)
        {
            proto_item_append_text(treex, ", Timestamp:%d", timestamp);
        }
    }

    { /* padding */
        gint padding_size;
        padding_size = tvb_length_remaining(tvb, offset);
        if (0 != padding_size)
        {
            proto_tree* tree_a;
            tree_a = proto_item_add_subtree(treex, ett_esmc);
            {
                proto_item* item_b;
                tvbuff_t* tvb_next;
                tvb_next = tvb_new_subset(tvb, offset, padding_size, -1);
                item_b = proto_tree_add_item(tree_a, hf_esmc_padding, tvb_next, 0, -1, ENC_NA);
                proto_item_append_text(item_b, ", %d %s%s", padding_size
                , "octet", plurality(padding_size,"","s"));
                {
                    proto_tree* tree_b;
                    tree_b = proto_item_add_subtree(item_b, ett_esmc);
                    call_dissector(dh_data, tvb_next, pinfo, tree_b);
                }
            }
        }
    }

    col_clear(pinfo->cinfo, COL_INFO);
    /* append summary info */
    col_append_fstr(pinfo->cinfo, COL_INFO, "Event:%s", event_flag ?
                    "Time-critical" : "Information");
    if (ql >= 0)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s"
        , val_to_str(ql, esmc_quality_level_opt_1_vals_short, "QL-INVALID-%d"));
    }
    if (timestamp_valid_flag)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", TS:%d", timestamp);
    }
    if (malformed)
    {
        col_append_str(pinfo->cinfo, COL_INFO, ", Malformed PDU");
    }
}

/*
 * Name: dissect_oampdu
 *
 * Description:
 *    This function is used to dissect the Operation, Administration, and
 *    Maintenance slow protocol defined in IEEE802.3 clause 57 (The OAMPDUs
 *    common part is defined in section 57.4).
 *
 *    Only the 6 folowing codes are currently defined in the 2004 version of this
 *    protocol:

 *       OAMPDU_INFORMATION:        0x0
 *       OAMPDU_EVENT_NOTIFICATION: 0x1
 *       OAMPDU_VAR_REQUEST:        0x2
 *       OAMPDU_VAR_RESPONSE:       0x3
 *       OAMPDU_LOOPBACK_CTRL:      0x4
 *       OAMPDU_VENDOR_SPECIFIC:    0xFE
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8    oampdu_code;
    guint16   flags,state;
    guint32   i;

    proto_tree *oampdu_tree;
    proto_item *oampdu_item;
    proto_tree *flags_tree;
    proto_item *flags_item;

    const char *sep = initial_sep;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OAM");

    oampdu_code = tvb_get_guint8(tvb, OAMPDU_CODE);

    switch (oampdu_code)
    {
        case OAMPDU_INFORMATION:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Information");
            break;
        case OAMPDU_EVENT_NOTIFICATION:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Event Notification");
            break;
        case OAMPDU_VAR_REQUEST:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Variable Request");
            break;
        case OAMPDU_VAR_RESPONSE:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Variable Response");
            break;
        case OAMPDU_LOOPBACK_CTRL:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Loopback Control");
            break;
        case OAMPDU_VENDOR_SPECIFIC:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU: Organization Specific");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "OAMPDU reserved");
            break;
    }


    if (tree)
    {
        /* Add OAM Heading */
        oampdu_item = proto_tree_add_protocol_format(tree, proto_slow, tvb,
                0, -1, "OAM Protocol");
        oampdu_tree = proto_item_add_subtree(oampdu_item, ett_oampdu);

        /* Subtype */
        proto_tree_add_item(oampdu_tree, hf_slow_subtype, tvb,
                0, 1, ENC_BIG_ENDIAN);

        /* Flags field */
        flags = tvb_get_ntohs(tvb, OAMPDU_FLAGS);
        flags_item = proto_tree_add_uint(oampdu_tree, hf_oampdu_flags, tvb,
                OAMPDU_FLAGS, 2, flags);
        flags_tree = proto_item_add_subtree(flags_item, ett_oampdu_flags);

        /*
         * In this section we add keywords for the bit set on the Flags's line.
         * We also add all the bit inside the subtree.
         */
        APPEND_BOOLEAN_FLAG(flags & OAMPDU_FLAGS_LINK_FAULT, flags_item,
                "%sLink Fault");
        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_link_fault,
                tvb, OAMPDU_FLAGS, 1, flags);

        APPEND_BOOLEAN_FLAG(flags & OAMPDU_FLAGS_DYING_GASP, flags_item,
                "%sDying Gasp");
        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_dying_gasp,
                tvb, OAMPDU_FLAGS, 1, flags);

        APPEND_BOOLEAN_FLAG(flags & OAMPDU_FLAGS_CRITICAL_EVENT, flags_item,
                "%sCriticalEvent");
        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_critical_event,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_local_evaluating,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_local_stable,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_remote_evaluating,
                tvb, OAMPDU_FLAGS, 1, flags);

        proto_tree_add_boolean(flags_tree, hf_oampdu_flags_remote_stable,
                tvb, OAMPDU_FLAGS, 1, flags);

        if (sep != cont_sep)
            proto_item_append_text(flags_item, " (");
        else
            proto_item_append_text(flags_item, ", ");

        for(i=0;i<2;i++)
        {
            if (i==0)
            {
                proto_item_append_text(flags_item, "local: ");
                state = (flags&(OAMPDU_FLAGS_LOCAL_EVAL|OAMPDU_FLAGS_LOCAL_STABLE));
                state = state>>3;
            }
            else
            {
                proto_item_append_text(flags_item, "remote: ");
                state = (flags&(OAMPDU_FLAGS_REMOTE_EVAL|OAMPDU_FLAGS_REMOTE_STABLE));
                state = state>>5;
            }

            switch (state)
            {
                case 0:
                    proto_item_append_text(flags_item, "Unsatisfied");
                    break;
                case 1:
                    proto_item_append_text(flags_item, "Discovery in process");
                    break;
                case 2:
                    proto_item_append_text(flags_item, "Discovery complete");
                    break;
                default:
                    proto_item_append_text(flags_item, "Reserved");
                    break;
            }

            if (i==0)
                proto_item_append_text(flags_item, ", ");

        }

        proto_item_append_text(flags_item, ")");

        /* OAMPDU code */
        oampdu_code = tvb_get_guint8(tvb, OAMPDU_CODE);
        proto_tree_add_uint(oampdu_tree, hf_oampdu_code, tvb,
                OAMPDU_CODE, 1, oampdu_code);

        switch (oampdu_code)
        {
            case OAMPDU_INFORMATION:
                dissect_oampdu_information(tvb, oampdu_tree);
                break;
            case OAMPDU_EVENT_NOTIFICATION:
                dissect_oampdu_event_notification(tvb, oampdu_tree);
                break;
            case OAMPDU_VAR_REQUEST:
                dissect_oampdu_variable_request(tvb, oampdu_tree);
                break;
            case OAMPDU_VAR_RESPONSE:
                dissect_oampdu_variable_response(tvb, oampdu_tree);
                break;
            case OAMPDU_LOOPBACK_CTRL:
                dissect_oampdu_loopback_control(tvb, oampdu_tree);
                break;
            case OAMPDU_VENDOR_SPECIFIC:
                dissect_oampdu_vendor_specific(tvb, oampdu_tree);
            default:
                break;
        }
    }
}

/*
 * Name: dissect_oampdu_information
 *
 * Description:
 *    This function is used to dissect the Information TLVs defined in IEEE802.3
 *    section 57.5.2.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_information(tvbuff_t *tvb, proto_tree *tree)
{
    guint16   raw_word;
    guint8    raw_octet;
    guint8    info_type;
    guint32   offset;
    guint16   bytes;

    const guint8 *ptr;

    proto_tree *info_tree;
    proto_item *info_item;
    proto_tree *state_tree;
    proto_item *state_item;
    proto_tree *cfg_tree;
    proto_item *cfg_item;
    proto_item *oui_item;
    proto_item *item;


    offset = OAMPDU_HEADER_SIZE;

    while (1)
    {
        bytes = tvb_length_remaining(tvb, offset);
        if (bytes < 1) break;

        info_type = tvb_get_guint8(tvb, offset);

        if (info_type == OAMPDU_INFO_TYPE_ENDMARKER) break;

        info_item = proto_tree_add_uint(tree, hf_oampdu_info_type, tvb,
                                        offset, 1, info_type);

        switch (info_type)
        {
            case OAMPDU_INFO_TYPE_LOCAL:
                info_tree = proto_item_add_subtree(info_item, ett_oampdu_local_info);
                break;
            case OAMPDU_INFO_TYPE_REMOTE:
                info_tree = proto_item_add_subtree(info_item, ett_oampdu_remote_info);
                break;
            case OAMPDU_INFO_TYPE_ORG:
                info_tree = proto_item_add_subtree(info_item, ett_oampdu_org_info);
                break;
            default:
                info_tree = NULL;
                break;
        }

        offset += OAMPDU_INFO_TYPE_SZ;

        if ((info_type==OAMPDU_INFO_TYPE_LOCAL)||(info_type==OAMPDU_INFO_TYPE_REMOTE))
        {
            raw_octet = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(info_tree, hf_oampdu_info_len,
                                tvb, offset, 1, raw_octet);

            offset += OAMPDU_INFO_LENGTH_SZ;

            raw_octet = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(info_tree, hf_oampdu_info_version,
                                tvb, offset, 1, raw_octet);

            offset += OAMPDU_INFO_VERSION_SZ;

            raw_word = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(info_tree, hf_oampdu_info_revision,
                                tvb, offset, 2, raw_word);

            offset += OAMPDU_INFO_REVISION_SZ;

            /* Build OAM State field field */
            raw_octet = tvb_get_guint8(tvb, offset);
            state_item = proto_tree_add_uint(info_tree, hf_oampdu_info_state,
                                             tvb, offset, 1, raw_octet);

            if (raw_octet == OAMPDU_INFO_TYPE_LOCAL)
                state_tree = proto_item_add_subtree(state_item, ett_oampdu_local_info_state);
            else
                state_tree = proto_item_add_subtree(state_item, ett_oampdu_remote_info_state);

            proto_tree_add_uint(state_tree, hf_oampdu_info_state_parser,
                                tvb, offset, 1, raw_octet);

            proto_tree_add_boolean(state_tree, hf_oampdu_info_state_mux,
                                   tvb, offset, 1, raw_octet);

            offset += OAMPDU_INFO_STATE_SZ;

            /* Build OAM configuration field */
            raw_octet = tvb_get_guint8(tvb, offset);
            cfg_item = proto_tree_add_uint(info_tree, hf_oampdu_info_oamConfig,
                                           tvb, offset, 1, raw_octet);

            if (raw_octet == OAMPDU_INFO_TYPE_LOCAL)
                cfg_tree = proto_item_add_subtree(cfg_item, ett_oampdu_local_info_config);
            else
                cfg_tree = proto_item_add_subtree(cfg_item, ett_oampdu_remote_info_config);

            proto_tree_add_boolean(cfg_tree, hf_oampdu_info_oamConfig_mode,
                                   tvb, offset, 1, raw_octet);

            proto_tree_add_boolean(cfg_tree, hf_oampdu_info_oamConfig_uni,
                                   tvb, offset, 1, raw_octet);

            proto_tree_add_boolean(cfg_tree, hf_oampdu_info_oamConfig_lpbk,
                                   tvb, offset, 1, raw_octet);

            proto_tree_add_boolean(cfg_tree, hf_oampdu_info_oamConfig_event,
                                   tvb, offset, 1, raw_octet);

            proto_tree_add_boolean(cfg_tree, hf_oampdu_info_oamConfig_var,
                                   tvb, offset, 1, raw_octet);

            offset += OAMPDU_INFO_OAM_CONFIG_SZ;

            raw_word = tvb_get_ntohs(tvb, offset);
            item = proto_tree_add_uint(info_tree, hf_oampdu_info_oampduConfig,
                                       tvb, offset, 2, raw_word);

            proto_item_append_text(item, " (bytes)");

            offset += OAMPDU_INFO_OAMPDU_CONFIG_SZ;

            oui_item = proto_tree_add_item(info_tree, hf_oampdu_info_oui,
                                           tvb, offset, 3, ENC_NA);

            APPEND_OUI_NAME(oui_item, ptr, tvb, offset);

            offset += OAMPDU_INFO_OUI_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_vendor,
                                tvb, offset, 4, ENC_NA);

            offset += OAMPDU_INFO_VENDOR_SPECIFIC_SZ;
        }
        else if (info_type == OAMPDU_INFO_TYPE_ORG)
        {
            /* see IEEE802.3, section 57.5.2.3 for more details */
            raw_octet = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(info_tree, hf_oampdu_info_len,
                                tvb, offset, 1, raw_octet);

            offset += OAMPDU_INFO_LENGTH_SZ;

            oui_item = proto_tree_add_item(info_tree, hf_oampdu_info_oui,
                                            tvb, offset, 3, ENC_NA);

            APPEND_OUI_NAME(oui_item, ptr, tvb, offset);

            offset += OAMPDU_INFO_OUI_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_vendor,
                                tvb, offset, raw_octet-5, ENC_NA);

            offset += raw_octet-5;

        }
        else
        {
            /* If it's a unknown type jump over */
            raw_octet = tvb_get_guint8(tvb, offset);
            offset += raw_octet;
        }
    }
}

/*
 * Name: dissect_oampdu_event_notification
 *
 * Description:
 *    This function is used to dissect the Event Notification TLVs defined in
 *    IEEE802.3 section 57.5.3.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_event_notification(tvbuff_t *tvb, proto_tree *tree)
{
    guint8    raw_octet;
    guint16   raw_word;
    guint32   dword;
    guint64   big;

    guint8    event_type;
    guint32   offset;
    guint16   bytes;

    proto_tree *event_tree;
    proto_item *event_item;

    offset = OAMPDU_HEADER_SIZE;

    /* Display the sequence number before displaying the TLVs */
    raw_word = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_oampdu_event_sequence,
            tvb, offset, 2, raw_word);

    offset += OAMPDU_EVENT_SEQUENCE_SZ;

    while (1)
    {
        bytes = tvb_length_remaining(tvb, offset);
        if (bytes < 1) break;

        event_type = tvb_get_guint8(tvb, offset);

        if (event_type == 0) break;

        event_item = proto_tree_add_uint(tree, hf_oampdu_event_type,
                            tvb, offset, 1, event_type);

        offset += OAMPDU_EVENT_TYPE_SZ;

        switch (event_type)
        {
            case OAMPDU_EVENT_TYPE_END:
                break;
            case OAMPDU_EVENT_TYPE_ESPE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_espe);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeWindow,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_WINDOW_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeThreshold,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_THRESHOLD_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_ERRORS_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeTotalErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_espeTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_ESPE_TOTAL_SZ;
                break;
            }
            case OAMPDU_EVENT_TYPE_EFE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_efe);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeWindow,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EFE_WINDOW_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeThreshold,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFE_THRESHOLD_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeErrors,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFE_ERRORS_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_efeTotalErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_EFE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFE_TOTAL_SZ;

                break;
            }
            case OAMPDU_EVENT_TYPE_EFPE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_efpe);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeWindow,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_WINDOW_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeThreshold,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_THRESHOLD_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeErrors,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_ERRORS_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_efpeTotalErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_EFPE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_TOTAL_SZ;

                break;
            }
            case OAMPDU_EVENT_TYPE_EFSSE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_efsse);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseWindow,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EFSSE_WINDOW_SZ;

                dword = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseThreshold,
                        tvb, offset, 2, dword);

                offset += OAMPDU_EFSSE_THRESHOLD_SZ;

                dword = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseErrors,
                        tvb, offset, 2, dword);

                offset += OAMPDU_EFSSE_ERRORS_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseTotalErrors,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFSSE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFSSE_TOTAL_SZ;

                break;
            }
            case OAMPDU_EVENT_TYPE_OSE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_ose);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                offset += (raw_octet-2);
                break;
            }
            default:
              break;
        }
    }
}

/*
 * Name: dissect_oampdu_variable_request
 *
 * Description:
 *    This function is used to dissect the Variable Request TLVs defined in
 *    IEEE802.3 section 57.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_variable_request(tvbuff_t *tvb, proto_tree *tree)
{
    guint16   raw_word;
    guint8    raw_octet;
    guint32   offset;


    offset = OAMPDU_HEADER_SIZE;

    while (1)
    {
        raw_octet = tvb_get_guint8(tvb, offset);

        if (raw_octet == 0) break;

        proto_tree_add_uint(tree, hf_oampdu_variable_branch,
                tvb,offset, 1, raw_octet);

        offset+=1;

        switch (raw_octet)
        {
            case OAMPDU_VARS_OBJECT:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_object,
                        tvb, offset, 2, raw_word);
                break;
            }
            case OAMPDU_VARS_PACKAGE:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_package,
                        tvb, offset, 2, raw_word);
                break;
            }
            case OAMPDU_VARS_BINDING:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_binding,
                        tvb, offset, 2, raw_word);
                break;
            }
            case OAMPDU_VARS_ATTRIBUTE:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_attribute,
                        tvb, offset, 2, raw_word);
                break;
            }
            default:
                break;
        }

        offset+=2;
    }
}

/*
 * Name: dissect_oampdu_variable_response
 *
 * Description:
 *    This function is used to dissect the Variable Response TLVs defined in
 *    IEEE802.3 section 57.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_variable_response(tvbuff_t *tvb, proto_tree *tree)
{
    guint16   raw_word;
    guint8    raw_octet;
    guint32   offset;


    offset = OAMPDU_HEADER_SIZE;

    while (1)
    {
        raw_octet = tvb_get_guint8(tvb, offset);

        if (raw_octet == 0) break;

        proto_tree_add_uint(tree, hf_oampdu_variable_branch,
                            tvb,offset, 1, raw_octet);

        offset+=1;

        switch (raw_octet)
        {
            case OAMPDU_VARS_OBJECT:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_object,
                                    tvb, offset, 2, raw_word);
                break;
            }
            case OAMPDU_VARS_PACKAGE:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_package,
                                    tvb, offset, 2, raw_word);
                break;
            }
            case OAMPDU_VARS_BINDING:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_binding,
                                    tvb, offset, 2, raw_word);
                break;
            }
            case OAMPDU_VARS_ATTRIBUTE:
            {
                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_oampdu_variable_attribute,
                                    tvb, offset, 2, raw_word);
                break;
            }
            default:
                break;
        }

        offset+=2;

        raw_octet = tvb_get_guint8(tvb, offset);

        if (raw_octet >= 0x80)
        {
            /* Variable Indication */
            proto_tree_add_uint(tree, hf_oampdu_variable_indication,
                                tvb,offset, 1, (raw_octet&0x7F));

            offset+=1;
        }
        else
        {
            /* Special case for 128 bytes container */
            if (raw_octet == 0) raw_octet = 128;

            proto_tree_add_uint(tree, hf_oampdu_variable_width,
                                tvb,offset, 1, raw_octet);

            offset+=1;

            proto_tree_add_item(tree, hf_oampdu_variable_value,
                                 tvb, offset, raw_octet, ENC_NA);

            offset+=raw_octet;
        }
    }
}

/*
 * Name: dissect_oampdu_loopback_control
 *
 * Description:
 *    This function is used to dissect the Variable Request TLVs defined in
 *    IEEE802.3 section 57.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_loopback_control(tvbuff_t *tvb, proto_tree *tree)
{
    guint8    ctrl;
    guint32   offset;
    guint16   bytes;

    proto_tree *ctrl_tree;
    proto_item *ctrl_item;

    const char *sep;

    offset = OAMPDU_HEADER_SIZE;

    bytes = tvb_length_remaining(tvb, offset);

    if (bytes >= 1)
    {
        ctrl = tvb_get_guint8(tvb, offset);

        ctrl_item = proto_tree_add_uint(tree, hf_oampdu_lpbk,
                            tvb, offset, 1, ctrl);

        ctrl_tree = proto_item_add_subtree(ctrl_item, ett_oampdu_lpbk_ctrl);

        sep = initial_sep;

        APPEND_BOOLEAN_FLAG(ctrl & OAMPDU_LPBK_ENABLE, ctrl_item,
                "%sEnable Remote Loopack");
        proto_tree_add_boolean(ctrl_tree, hf_oampdu_lpbk_enable,
                tvb, offset, 1, ctrl);

        APPEND_BOOLEAN_FLAG(ctrl & OAMPDU_LPBK_DISABLE, ctrl_item,
                "%sDisable Remote Loopback");
        proto_tree_add_boolean(ctrl_tree, hf_oampdu_lpbk_disable,
                tvb, offset, 1, ctrl);

        if (sep != initial_sep)
            proto_item_append_text(ctrl_item, ")");
    }
}

/*
 * Name: dissect_oampdu_vendor_specific
 *
 * Description:
 *    This function is used to dissect the Vendor Specific TLV defined in
 *    IEEE802.3 section 57.4.3.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_vendor_specific(tvbuff_t *tvb, proto_tree *tree)
{
    guint32   offset;
    guint16   bytes;

    const guint8 *ptr;

    proto_item *oui_item;


    offset = OAMPDU_HEADER_SIZE;

    bytes = tvb_length_remaining(tvb, offset);

    if (bytes >= 3)
    {
        oui_item = proto_tree_add_item(tree, hf_oampdu_info_oui,
                                        tvb, offset, 3, ENC_NA);

        APPEND_OUI_NAME(oui_item, ptr, tvb, offset);
    }
}


/* Register the protocol with Wireshark */
void
proto_register_slow_protocols(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {

/*
 * Generic slow protocol portion
 */
        { &hf_slow_subtype,
          { "Slow Protocols subtype",    "slow.subtype",
            FT_UINT8,    BASE_HEX,    VALS(subtype_vals),    0x0,
            "Identifies the LACP version", HFILL }},

/*
 *  LACP portion
 */
        { &hf_lacpdu_version_number,
          { "LACP Version Number",    "slow.lacp.version",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "Identifies the LACP version", HFILL }},

        { &hf_lacpdu_actor_type,
          { "Actor Information",    "slow.lacp.actorInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Actor", HFILL }},

        { &hf_lacpdu_actor_info_len,
          { "Actor Information Length",            "slow.lacp.actorInfoLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Actor TLV", HFILL }},

        { &hf_lacpdu_actor_sys_priority,
          { "Actor System Priority",  "slow.lacp.actorSysPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to this System by management or admin", HFILL }},

        { &hf_lacpdu_actor_sys,
          { "Actor System",            "slow.lacp.actorSystem",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "The Actor's System ID encoded as a MAC address", HFILL }},

        { &hf_lacpdu_actor_key,
          { "Actor Key",            "slow.lacp.actorKey",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The operational Key value assigned to the port by the Actor", HFILL }},

        { &hf_lacpdu_actor_port_priority,
          { "Actor Port Priority",            "slow.lacp.actorPortPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to the port by the Actor (via Management or Admin)", HFILL }},

        { &hf_lacpdu_actor_port,
          { "Actor Port",            "slow.lacp.actorPort",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The port number assigned to the port by the Actor (via Management or Admin)", HFILL }},

        { &hf_lacpdu_actor_state,
          { "Actor State",            "slow.lacp.actorState",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The Actor's state variables for the port, encoded as bits within a single octet", HFILL }},

        { &hf_lacpdu_flags_a_activity,
          { "LACP Activity",        "slow.lacp.actorState.activity",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_ACTIVITY,
            "Activity control value for this link. Active = 1, Passive = 0", HFILL }},

        { &hf_lacpdu_flags_a_timeout,
          { "LACP Timeout",        "slow.lacp.actorState.timeout",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_TIMEOUT,
            "Timeout control value for this link. Short Timeout = 1, Long Timeout = 0", HFILL }},

        { &hf_lacpdu_flags_a_aggregation,
          { "Aggregation",        "slow.lacp.actorState.aggregation",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_AGGREGATION,
            "Aggregatable = 1, Individual = 0", HFILL }},

        { &hf_lacpdu_flags_a_sync,
          { "Synchronization",        "slow.lacp.actorState.synchronization",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_SYNC,
            "In Sync = 1, Out of Sync = 0", HFILL }},

        { &hf_lacpdu_flags_a_collecting,
          { "Collecting",        "slow.lacp.actorState.collecting",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_COLLECTING,
            "Collection of incoming frames is: Enabled = 1, Disabled = 0", HFILL }},

        { &hf_lacpdu_flags_a_distrib,
          { "Distributing",        "slow.lacp.actorState.distributing",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DISTRIB,
            "Distribution of outgoing frames is: Enabled = 1, Disabled = 0", HFILL }},

        { &hf_lacpdu_flags_a_defaulted,
          { "Defaulted",        "slow.lacp.actorState.defaulted",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DEFAULTED,
            "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},

        { &hf_lacpdu_flags_a_expired,
          { "Expired",        "slow.lacp.actorState.expired",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_EXPIRED,
            "1 = Actor Rx machine is EXPIRED, 0 = is NOT EXPIRED", HFILL }},

        { &hf_lacpdu_actor_reserved,
          { "Reserved",        "slow.lacp.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacpdu_partner_type,
          { "Partner Information",    "slow.lacp.partnerInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Partner", HFILL }},

        { &hf_lacpdu_partner_info_len,
          { "Partner Information Length",            "slow.lacp.partnerInfoLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Partner TLV", HFILL }},

        { &hf_lacpdu_partner_sys_priority,
          { "Partner System Priority",  "slow.lacp.partnerSysPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to the Partner System by management or admin", HFILL }},

        { &hf_lacpdu_partner_sys,
          { "Partner System",            "slow.lacp.partnerSystem",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "The Partner's System ID encoded as a MAC address", HFILL }},

        { &hf_lacpdu_partner_key,
          { "Partner Key",            "slow.lacp.partnerKey",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The operational Key value assigned to the port associated with this link by the Partner", HFILL }},

        { &hf_lacpdu_partner_port_priority,
          { "Partner Port Priority",            "slow.lacp.partnerPortPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to the port by the Partner (via Management or Admin)", HFILL }},

        { &hf_lacpdu_partner_port,
          { "Partner Port",            "slow.lacp.partnerPort",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The port number associated with this link assigned to the port by the Partner (via Management or Admin)", HFILL }},

        { &hf_lacpdu_partner_state,
          { "Partner State",            "slow.lacp.partnerState",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The Partner's state variables for the port, encoded as bits within a single octet", HFILL }},

        { &hf_lacpdu_flags_p_activity,
          { "LACP Activity",        "slow.lacp.partnerState.activity",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_ACTIVITY,
            "Activity control value for this link. Active = 1, Passive = 0", HFILL }},

        { &hf_lacpdu_flags_p_timeout,
          { "LACP Timeout",        "slow.lacp.partnerState.timeout",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_TIMEOUT,
            "Timeout control value for this link. Short Timeout = 1, Long Timeout = 0", HFILL }},

        { &hf_lacpdu_flags_p_aggregation,
          { "Aggregation",        "slow.lacp.partnerState.aggregation",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_AGGREGATION,
            "Aggregatable = 1, Individual = 0", HFILL }},

        { &hf_lacpdu_flags_p_sync,
          { "Synchronization",        "slow.lacp.partnerState.synchronization",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_SYNC,
            "In Sync = 1, Out of Sync = 0", HFILL }},

        { &hf_lacpdu_flags_p_collecting,
          { "Collecting",        "slow.lacp.partnerState.collecting",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_COLLECTING,
            "Collection of incoming frames is: Enabled = 1, Disabled = 0", HFILL }},

        { &hf_lacpdu_flags_p_distrib,
          { "Distributing",        "slow.lacp.partnerState.distributing",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DISTRIB,
            "Distribution of outgoing frames is: Enabled = 1, Disabled = 0", HFILL }},

        { &hf_lacpdu_flags_p_defaulted,
          { "Defaulted",        "slow.lacp.partnerState.defaulted",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DEFAULTED,
            "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},

        { &hf_lacpdu_flags_p_expired,
          { "Expired",        "slow.lacp.partnerState.expired",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_EXPIRED,
            "1 = Actor Rx machine is EXPIRED, 0 = is NOT EXPIRED", HFILL }},

        { &hf_lacpdu_partner_reserved,
          { "Reserved",        "slow.lacp.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacpdu_coll_type,
          { "Collector Information",    "slow.lacp.collectorInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Collector", HFILL }},

        { &hf_lacpdu_coll_info_len,
          { "Collector Information Length",            "slow.lacp.collectorInfoLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Collector TLV", HFILL }},

        { &hf_lacpdu_coll_max_delay,
          { "Collector Max Delay",  "slow.lacp.collectorMaxDelay",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The max delay of the station tx'ing the LACPDU (in tens of usecs)", HFILL }},

        { &hf_lacpdu_coll_reserved,
          { "Reserved",        "slow.lacp.coll_reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacpdu_term_type,
          { "Terminator Information",    "slow.lacp.termInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Terminator", HFILL }},

        { &hf_lacpdu_term_len,
          { "Terminator Length",            "slow.lacp.termLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Terminator TLV", HFILL }},

        { &hf_lacpdu_term_reserved,
          { "Reserved",        "slow.lacp.term_reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},


/*
 *  MARKER portion
 */

        { &hf_marker_version_number,
          { "Version Number",    "slow.marker.version",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "Identifies the Marker version", HFILL }},

        { &hf_marker_tlv_type,
          { "TLV Type",    "slow.marker.tlvType",
            FT_UINT8,    BASE_HEX,    VALS(marker_vals),    0x0,
            "Marker TLV type", HFILL }},

        { &hf_marker_tlv_length,
          { "TLV Length",            "slow.marker.tlvLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Actor TLV", HFILL }},

        { &hf_marker_req_port,
          { "Requester Port",  "slow.marker.requesterPort",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The Requester Port", HFILL }},

        { &hf_marker_req_system,
          { "Requester System",  "slow.marker.requesterSystem",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "The Requester System ID encoded as a MAC address", HFILL }},

        { &hf_marker_req_trans_id,
          { "Requester Transaction ID",  "slow.marker.requesterTransId",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "The Requester Transaction ID", HFILL }},

/*
 *  ESMC portion
 */

        { &hf_ossp_oui,
          { "OUI",    "slow.ossp.oui",
            FT_BYTES,     BASE_NONE,    NULL,    0,
            "IEEE assigned Organizationally Unique Identifier", HFILL }},

        { &hf_itu_subtype,
          { "ITU-T OSSP Subtype",    "slow.ossp.itu.subtype",
            FT_UINT16,    BASE_HEX,    NULL,    0,
            "Subtype assigned by the ITU-T", HFILL }},

        { &hf_esmc_version,
          { "Version",    "slow.esmc.version",
            FT_UINT8,     BASE_HEX,    NULL,    0xf0,
            "This field indicates the version of ITU-T SG15 Q13 OSSP frame format", HFILL }},

        { &hf_esmc_event_flag,
          { "Event Flag",    "slow.esmc.event_flag",
            FT_UINT8,    BASE_HEX,    VALS(esmc_event_flag_vals),    0x08,
            "This bit distinguishes the critical, time sensitive behaviour of the"
            " ESMC Event PDU from the ESMC Information PDU", HFILL }},

        { &hf_esmc_timestamp_valid_flag,
          { "Timestamp Valid Flag",    "slow.esmc.timestamp_valid_flag",
            FT_UINT8,    BASE_HEX,    VALS(esmc_timestamp_valid_flag_vals),    0x04,
            "Indicates validity (i.e. presence) of the Timestamp TLV", HFILL }},

        { &hf_esmc_reserved_32,
          { "Reserved",    "slow.esmc.reserved",
            FT_UINT32,    BASE_HEX,    NULL,    0,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_tlv,
          { "ESMC TLV",    "slow.esmc.tlv",
            FT_NONE,     BASE_NONE,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_type,
          { "TLV Type",    "slow.esmc.tlv_type",
            FT_UINT8,    BASE_HEX,    VALS(esmc_tlv_type_vals),    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_length,
          { "TLV Length",    "slow.esmc.tlv_length",
            FT_UINT16,    BASE_HEX,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_ql_unused,
          { "Unused",    "slow.esmc.tlv_ql_unused",
            FT_UINT8,     BASE_HEX,    NULL,    0xf0,
            "This field is not used in QL TLV", HFILL }},

        { &hf_esmc_quality_level_opt_1,
          { "SSM Code",    "slow.esmc.ql",
            FT_UINT8,    BASE_HEX,    VALS(esmc_quality_level_opt_1_vals),    0x0f,
            "Quality Level information", HFILL }},

#if 0 /*not used yet*/
        { &hf_esmc_quality_level_opt_2,
          { "SSM Code",    "slow.esmc.ql",
            FT_UINT8,    BASE_HEX,    VALS(esmc_quality_level_opt_2_vals),    0x0f,
            "Quality Level information", HFILL }},
#endif

        { &hf_esmc_quality_level_invalid,
          { "SSM Code",    "slow.esmc.ql",
            FT_UINT8,    BASE_HEX,    VALS(esmc_quality_level_invalid_vals),    0x0f,
            "Quality Level information", HFILL }},

        { &hf_esmc_timestamp,
          { "Timestamp (ns)",    "slow.esmc.timestamp",
            FT_INT32,    BASE_DEC,    NULL,    0,
            "Timestamp according to the \"whole nanoseconds\" part of the IEEE 1588 originTimestamp", HFILL }},

        { &hf_esmc_tlv_ts_reserved,
          { "Reserved",    "slow.esmc.tlv_ts_reserved",
            FT_UINT8,     BASE_HEX,    NULL,    0,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_padding,
          { "Padding",    "slow.esmc.padding",
            FT_BYTES,     BASE_NONE,    NULL,    0x0,
            "This field contains necessary padding to achieve the minimum frame size of 64 bytes at least", HFILL }},

/*
 *  OAMPDU portion
 */
        { &hf_oampdu_flags,
          { "Flags",    "slow.oam.flags",
            FT_UINT16,    BASE_HEX,    NULL,    0x0,
            "The Flags Field", HFILL }},

        { &hf_oampdu_flags_link_fault,
          { "Link Fault",        "slow.oam.flags.linkFault",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_LINK_FAULT,
            "The PHY detected a fault in the receive direction. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_dying_gasp,
          { "Dying Gasp",        "slow.oam.flags.dyingGasp",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_DYING_GASP,
            "An unrecoverable local failure occured. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_critical_event,
          { "Critical Event",        "slow.oam.flags.criticalEvent",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_CRITICAL_EVENT,
            "A critical event has occurred. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_local_evaluating,
          { "Local Evaluating",        "slow.oam.flags.localEvaluating",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_LOCAL_EVAL,
            "Local DTE Discovery process in progress. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_local_stable,
          { "Local Stable",        "slow.oam.flags.localStable",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_LOCAL_STABLE,
            "Local DTE is Stable. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_remote_evaluating,
          { "Remote Evaluating",        "slow.oam.flags.remoteEvaluating",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_REMOTE_EVAL,
            "Remote DTE Discovery process in progress. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_remote_stable,
          { "Remote Stable",        "slow.oam.flags.remoteStable",
            FT_BOOLEAN,    8,        TFS(&tfs_true_false),    OAMPDU_FLAGS_REMOTE_STABLE,
            "Remote DTE is Stable. True = 1, False = 0", HFILL }},

        { &hf_oampdu_code,
          { "OAMPDU code",    "slow.oam.code",
            FT_UINT8,    BASE_HEX,    VALS(code_vals),    0x0,
            "Identifies the TLVs code", HFILL }},

        { &hf_oampdu_info_type,
          { "Type",    "slow.oam.info.type",
            FT_UINT8,    BASE_HEX,    VALS(info_type_vals),    0x0,
            "Identifies the TLV type", HFILL }},

        { &hf_oampdu_info_len,
          { "TLV Length",    "slow.oam.info.length",
            FT_UINT8,    BASE_DEC,    NULL,    0x0,
            "Identifies the TLVs type", HFILL }},

        { &hf_oampdu_info_version,
          { "TLV Version",    "slow.oam.info.version",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "Identifies the TLVs version", HFILL }},

        { &hf_oampdu_info_revision,
          { "TLV Revision",    "slow.oam.info.revision",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Identifies the TLVs revision", HFILL }},

        { &hf_oampdu_info_state,
          { "OAM DTE States",    "slow.oam.info.state",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "OAM DTE State of the Mux and the Parser", HFILL }},

        { &hf_oampdu_info_state_parser,
          { "Parser Action",        "slow.oam.info.state.parser",
            FT_UINT8,    BASE_HEX,    VALS(parser_vals),    0x03,
            NULL, HFILL }},

        { &hf_oampdu_info_state_mux,
          { "Muxiplexer Action",        "slow.oam.info.state.muxiplexer",
            FT_BOOLEAN,    8,        TFS(&mux),    0x04,
            NULL, HFILL }},

        { &hf_oampdu_info_oamConfig,
          { "OAM Configuration",    "slow.oam.info.oamConfig",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_mode,
          { "OAM Mode",        "slow.oam.info.oamConfig.mode",
            FT_BOOLEAN,    8,        TFS(&oam_mode),    OAMPDU_INFO_CONFIG_MODE,
            NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_uni,
          { "Unidirectional support",        "slow.oam.flags.dyingGasp",
            FT_BOOLEAN,    8,        TFS(&oam_uni),    OAMPDU_INFO_CONFIG_UNI,
            NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_lpbk,
          { "Loopback support",        "slow.oam.flags.criticalEvent",
            FT_BOOLEAN,    8,        TFS(&oam_lpbk),    OAMPDU_INFO_CONFIG_LPBK,
            NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_event,
          { "Link Events support",        "slow.oam.flags.localEvaluating",
            FT_BOOLEAN,    8,        TFS(&oam_event),    OAMPDU_INFO_CONFIG_EVENT,
            NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_var,
          { "Variable Retrieval",        "slow.oam.flags.localStable",
            FT_BOOLEAN,    8,        TFS(&oam_var),    OAMPDU_INFO_CONFIG_VAR,
            "Variable Retrieval support", HFILL }},

        { &hf_oampdu_info_oampduConfig,
          { "Max OAMPDU Size",    "slow.oam.info.oampduConfig",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "OAMPDU Configuration", HFILL }},

        { &hf_oampdu_info_oui,
          { "Organizationally Unique Identifier", "slow.oam.info.oui",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_oampdu_info_vendor,
          { "Vendor Specific Information", "slow.oam.info.vendor",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        /*
         * Event notification definitions
         */
        { &hf_oampdu_event_sequence,
          { "Sequence Number",    "slow.oam.event.sequence",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Identifies the Event Notification TLVs", HFILL }},

        { &hf_oampdu_event_type,
          { "Event Type",    "slow.oam.event.type",
            FT_UINT8,    BASE_HEX,    VALS(event_type_vals),    0x0,
            "Identifies the TLV type", HFILL }},

        { &hf_oampdu_event_length,
          { "Event Length",    "slow.oam.event.length",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "This field indicates the length in octets of the TLV-tuple", HFILL }},

        { &hf_oampdu_event_timeStamp,
          { "Event Timestamp (100ms)",    "slow.oam.event.timestamp",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Event Time Stamp in term of 100 ms intervals", HFILL }},

        /* Errored Symbol Period Event TLV */
        { &hf_oampdu_event_espeWindow,
          { "Errored Symbol Window",    "slow.oam.event.espeWindow",
            FT_UINT64,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in the period", HFILL }},

        { &hf_oampdu_event_espeThreshold,
          { "Errored Symbol Threshold",    "slow.oam.event.espeThreshold",
            FT_UINT64,    BASE_DEC,    NULL,    0x0,
            "Number of symbols required to generate the Event", HFILL }},

        { &hf_oampdu_event_espeErrors,
          { "Errored Symbols",    "slow.oam.event.espeErrors",
            FT_UINT64,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_espeTotalErrors,
          { "Error Running Total",    "slow.oam.event.espeTotalErrors",
            FT_UINT64,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_espeTotalEvents,
          { "Event Running Total",    "slow.oam.event.espeTotalEvents",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Total Event generated since reset of the sublayer", HFILL }},

        /* Errored Frame Event TLV */
        { &hf_oampdu_event_efeWindow,
          { "Errored Frame Window",    "slow.oam.event.efeWindow",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in the period", HFILL }},

        { &hf_oampdu_event_efeThreshold,
          { "Errored Frame Threshold",    "slow.oam.event.efeThreshold",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Number of frames required to generate the Event", HFILL }},

        { &hf_oampdu_event_efeErrors,
          { "Errored Frames",    "slow.oam.event.efeErrors",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_efeTotalErrors,
          { "Error Running Total",    "slow.oam.event.efeTotalErrors",
            FT_UINT64,    BASE_DEC,    NULL,    0x0,
            "Number of frames in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_efeTotalEvents,
          { "Event Running Total",    "slow.oam.event.efeTotalEvents",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Total Event generated since reset of the sublayer", HFILL }},

        /* Errored Frame Period Event TLV */
        { &hf_oampdu_event_efpeWindow,
          { "Errored Frame Window",    "slow.oam.event.efpeWindow",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Number of frame in error during the period", HFILL }},

        { &hf_oampdu_event_efpeThreshold,
          { "Errored Frame Threshold",    "slow.oam.event.efpeThreshold",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Number of frames required to generate the Event", HFILL }},

        { &hf_oampdu_event_efpeErrors,
          { "Errored Frames",    "slow.oam.event.efeErrors",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_efpeTotalErrors,
          { "Error Running Total",    "slow.oam.event.efpeTotalErrors",
            FT_UINT64,    BASE_DEC,    NULL,    0x0,
            "Number of frames in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_efpeTotalEvents,
          { "Event Running Total",    "slow.oam.event.efpeTotalEvents",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Total Event generated since reset of the sublayer", HFILL }},

        /* Errored Frame Second Summary Event TLV */
        { &hf_oampdu_event_efsseWindow,
          { "Errored Frame Window",    "slow.oam.event.efsseWindow",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Number of frame in error during the period", HFILL }},

        { &hf_oampdu_event_efsseThreshold,
          { "Errored Frame Threshold",    "slow.oam.event.efsseThreshold",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Number of frames required to generate the Event", HFILL }},

        { &hf_oampdu_event_efsseErrors,
          { "Errored Frames",    "slow.oam.event.efeErrors",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_efsseTotalErrors,
          { "Error Running Total",    "slow.oam.event.efsseTotalErrors",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Number of frames in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_efsseTotalEvents,
          { "Event Running Total",    "slow.oam.event.efsseTotalEvents",
            FT_UINT32,    BASE_DEC,    NULL,    0x0,
            "Total Event generated since reset of the sublayer", HFILL }},

        /* Variable request and response definitions*/
        { &hf_oampdu_variable_branch,
          { "Branch",    "slow.oam.variable.branch",
            FT_UINT8,    BASE_HEX,    VALS(branch_vals),    0x0,
            "Variable Branch, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_object,
          { "Leaf",    "slow.oam.variable.object",
            FT_UINT16,    BASE_HEX,    VALS(object_vals),    0x0,
            "Object, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_package,
          { "Leaf",    "slow.oam.variable.package",
            FT_UINT16,    BASE_HEX,    VALS(package_vals),    0x0,
            "Package, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_binding,
          { "Leaf",    "slow.oam.variable.binding",
            FT_UINT16,    BASE_HEX,    VALS(binding_vals),    0x0,
            "Binding, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_attribute,
          { "Leaf",    "slow.oam.variable.attribute",
            FT_UINT16,    BASE_HEX|BASE_EXT_STRING,  &attribute_vals_ext,   0x0,
            "Attribute, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_width,
          { "Variable Width",    "slow.oam.variable.width",
            FT_UINT8,    BASE_DEC,    NULL,    0x0,
            "Width", HFILL }},

        { &hf_oampdu_variable_indication,
          { "Variable indication",    "slow.oam.variable.indication",
            FT_UINT8,    BASE_HEX,    VALS(indication_vals),    0x0,
            NULL, HFILL }},

        { &hf_oampdu_variable_value,
          { "Variable Value",    "slow.oam.variable.value",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            "Value", HFILL }},

        /* Loopback Control definitions*/
        { &hf_oampdu_lpbk,
          { "Commands", "slow.oam.lpbk.commands",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The List of Loopback Commands", HFILL }},

        { &hf_oampdu_lpbk_enable,
          { "Enable Remote Loopback", "slow.oam.lpbk.commands.enable",
            FT_BOOLEAN,    8,        NULL,    OAMPDU_LPBK_ENABLE,
            "Enable Remote Loopback Command", HFILL }},

        { &hf_oampdu_lpbk_disable,
          { "Disable Remote Loopback", "slow.oam.lpbk.commands.disable",
            FT_BOOLEAN,    8,        NULL,    OAMPDU_LPBK_DISABLE,
            "Disable Remote Loopback Command", HFILL }}
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_pdu,
        &ett_lacpdu,
        &ett_lacpdu_a_flags,
        &ett_lacpdu_p_flags,
        &ett_marker,
        &ett_esmc,
        &ett_oampdu,
        &ett_oampdu_flags,
        &ett_oampdu_local_info,
        &ett_oampdu_local_info_state,
        &ett_oampdu_local_info_config,
        &ett_oampdu_remote_info,
        &ett_oampdu_remote_info_state,
        &ett_oampdu_remote_info_config,
        &ett_oampdu_org_info,
        &ett_oampdu_event_espe,
        &ett_oampdu_event_efe,
        &ett_oampdu_event_efpe,
        &ett_oampdu_event_efsse,
        &ett_oampdu_event_ose,
        &ett_oampdu_lpbk_ctrl,
        &ett_ossppdu,
        &ett_itu_ossp

    };

    /* Register the protocol name and description */

    proto_slow = proto_register_protocol("Slow Protocols", "802.3 Slow protocols", "slow");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_slow, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_slow_protocols(void)
{
    dissector_handle_t slow_protocols_handle;

    slow_protocols_handle = create_dissector_handle(dissect_slow_protocols, proto_slow);
    dissector_add_uint("ethertype", ETHERTYPE_SLOW_PROTOCOLS, slow_protocols_handle);
    dh_data = find_dissector("data");
}
