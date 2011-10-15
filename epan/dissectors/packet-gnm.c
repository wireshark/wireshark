/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-gnm.c                                                               */
/* ../../tools/asn2wrs.py -b -p gnm -c ./gnm.cnf -s ./packet-gnm-template -D . -O ../../epan/dissectors GNM.asn */

/* Input file: packet-gnm-template.c */

#line 1 "../../asn1/gnm/packet-gnm-template.c"
/* packet-gnm.c
 * Routines for GENERIC NETWORK INFORMATION MODEL Data dissection
 *
 * Copyright 2005 , Anders Broman <anders.broman [AT] ericsson.com>
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
 *
 * References:
 * ITU-T recommendatiom M.3100
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-cmip.h"
#include "packet-gnm.h"

#define PNAME  "ITU M.3100 Generic Network Information Model"
#define PSNAME "GNM"
#define PFNAME "gnm"

/* Initialize the protocol and registered fields */
static int proto_gnm = -1;


/*--- Included file: packet-gnm-hf.c ---*/
#line 1 "../../asn1/gnm/packet-gnm-hf.c"
static int hf_gnm_SupportedTOClasses_PDU = -1;    /* SupportedTOClasses */
static int hf_gnm_AcceptableCircuitPackTypeList_PDU = -1;  /* AcceptableCircuitPackTypeList */
static int hf_gnm_AlarmSeverityAssignmentList_PDU = -1;  /* AlarmSeverityAssignmentList */
static int hf_gnm_AlarmStatus_PDU = -1;           /* AlarmStatus */
static int hf_gnm_Boolean_PDU = -1;               /* Boolean */
static int hf_gnm_ChannelNumber_PDU = -1;         /* ChannelNumber */
static int hf_gnm_CharacteristicInformation_PDU = -1;  /* CharacteristicInformation */
static int hf_gnm_CircuitDirectionality_PDU = -1;  /* CircuitDirectionality */
static int hf_gnm_CircuitPackType_PDU = -1;       /* CircuitPackType */
static int hf_gnm_ConnectInformation_PDU = -1;    /* ConnectInformation */
static int hf_gnm_ConnectivityPointer_PDU = -1;   /* ConnectivityPointer */
static int hf_gnm_Count_PDU = -1;                 /* Count */
static int hf_gnm_CrossConnectionName_PDU = -1;   /* CrossConnectionName */
static int hf_gnm_CrossConnectionObjectPointer_PDU = -1;  /* CrossConnectionObjectPointer */
static int hf_gnm_CurrentProblemList_PDU = -1;    /* CurrentProblemList */
static int hf_gnm_Directionality_PDU = -1;        /* Directionality */
static int hf_gnm_DisconnectResult_PDU = -1;      /* DisconnectResult */
static int hf_gnm_DownstreamConnectivityPointer_PDU = -1;  /* DownstreamConnectivityPointer */
static int hf_gnm_ExternalTime_PDU = -1;          /* ExternalTime */
static int hf_gnm_EquipmentHolderAddress_PDU = -1;  /* EquipmentHolderAddress */
static int hf_gnm_EquipmentHolderType_PDU = -1;   /* EquipmentHolderType */
static int hf_gnm_HolderStatus_PDU = -1;          /* HolderStatus */
static int hf_gnm_InformationTransferCapabilities_PDU = -1;  /* InformationTransferCapabilities */
static int hf_gnm_ListOfCharacteristicInformation_PDU = -1;  /* ListOfCharacteristicInformation */
static int hf_gnm_NameType_PDU = -1;              /* NameType */
static int hf_gnm_NumberOfCircuits_PDU = -1;      /* NumberOfCircuits */
static int hf_gnm_ObjectList_PDU = -1;            /* ObjectList */
static int hf_gnm_Pointer_PDU = -1;               /* Pointer */
static int hf_gnm_PointerOrNull_PDU = -1;         /* PointerOrNull */
static int hf_gnm_RelatedObjectInstance_PDU = -1;  /* RelatedObjectInstance */
static int hf_gnm_Replaceable_PDU = -1;           /* Replaceable */
static int hf_gnm_SequenceOfObjectInstance_PDU = -1;  /* SequenceOfObjectInstance */
static int hf_gnm_SerialNumber_PDU = -1;          /* SerialNumber */
static int hf_gnm_SignallingCapabilities_PDU = -1;  /* SignallingCapabilities */
static int hf_gnm_SignalType_PDU = -1;            /* SignalType */
static int hf_gnm_SubordinateCircuitPackSoftwareLoad_PDU = -1;  /* SubordinateCircuitPackSoftwareLoad */
static int hf_gnm_SupportableClientList_PDU = -1;  /* SupportableClientList */
static int hf_gnm_SystemTimingSource_PDU = -1;    /* SystemTimingSource */
static int hf_gnm_TpsInGtpList_PDU = -1;          /* TpsInGtpList */
static int hf_gnm_TransmissionCharacteristics_PDU = -1;  /* TransmissionCharacteristics */
static int hf_gnm_UserLabel_PDU = -1;             /* UserLabel */
static int hf_gnm_VendorName_PDU = -1;            /* VendorName */
static int hf_gnm_Version_PDU = -1;               /* Version */
static int hf_gnm_MappingList_item = -1;          /* PayloadLevel */
static int hf_gnm_objectClass = -1;               /* OBJECT_IDENTIFIER */
static int hf_gnm_characteristicInformation = -1;  /* CharacteristicInformation */
static int hf_gnm_SupportedTOClasses_item = -1;   /* OBJECT_IDENTIFIER */
static int hf_gnm_AcceptableCircuitPackTypeList_item = -1;  /* PrintableString */
static int hf_gnm_mpCrossConnection = -1;         /* ObjectInstance */
static int hf_gnm_legs = -1;                      /* SET_OF_ToTermSpecifier */
static int hf_gnm_legs_item = -1;                 /* ToTermSpecifier */
static int hf_gnm_problem = -1;                   /* ProbableCause */
static int hf_gnm_severityAssignedServiceAffecting = -1;  /* AlarmSeverityCode */
static int hf_gnm_severityAssignedNonServiceAffecting = -1;  /* AlarmSeverityCode */
static int hf_gnm_severityAssignedServiceIndependent = -1;  /* AlarmSeverityCode */
static int hf_gnm_AlarmSeverityAssignmentList_item = -1;  /* AlarmSeverityAssignment */
static int hf_gnm_characteristicInfoType = -1;    /* CharacteristicInformation */
static int hf_gnm_bundlingFactor = -1;            /* INTEGER */
static int hf_gnm_pointToPoint = -1;              /* PointToPoint */
static int hf_gnm_pointToMultipoint = -1;         /* PointToMultipoint */
static int hf_gnm_ConnectInformation_item = -1;   /* ConnectInformation_item */
static int hf_gnm_itemType = -1;                  /* T_itemType */
static int hf_gnm_unidirectional = -1;            /* ConnectionType */
static int hf_gnm_bidirectional = -1;             /* ConnectionTypeBi */
static int hf_gnm_addleg = -1;                    /* AddLeg */
static int hf_gnm_administrativeState = -1;       /* AdministrativeState */
static int hf_gnm_namedCrossConnection = -1;      /* NamedCrossConnection */
static int hf_gnm_userLabel = -1;                 /* UserLabel */
static int hf_gnm_redline = -1;                   /* Boolean */
static int hf_gnm_additionalInfo = -1;            /* AdditionalInformation */
static int hf_gnm_none = -1;                      /* NULL */
static int hf_gnm_single = -1;                    /* ObjectInstance */
static int hf_gnm_concatenated = -1;              /* SEQUENCE_OF_ObjectInstance */
static int hf_gnm_concatenated_item = -1;         /* ObjectInstance */
static int hf_gnm_explicitPToP = -1;              /* ExplicitPtoP */
static int hf_gnm_ptoTpPool = -1;                 /* PtoTPPool */
static int hf_gnm_explicitPtoMP = -1;             /* ExplicitPtoMP */
static int hf_gnm_ptoMPools = -1;                 /* PtoMPools */
static int hf_gnm_notConnected = -1;              /* ObjectInstance */
static int hf_gnm_connected = -1;                 /* ObjectInstance */
static int hf_gnm_multipleConnections = -1;       /* MultipleConnections */
static int hf_gnm_alarmStatus = -1;               /* AlarmStatus */
static int hf_gnm_CurrentProblemList_item = -1;   /* CurrentProblem */
static int hf_gnm_DisconnectResult_item = -1;     /* DisconnectResult_item */
static int hf_gnm_failed = -1;                    /* Failed */
static int hf_gnm_disconnected = -1;              /* ObjectInstance */
static int hf_gnm_broadcast = -1;                 /* SET_OF_ObjectInstance */
static int hf_gnm_broadcast_item = -1;            /* ObjectInstance */
static int hf_gnm_broadcastConcatenated = -1;     /* T_broadcastConcatenated */
static int hf_gnm_broadcastConcatenated_item = -1;  /* SEQUENCE_OF_ObjectInstance */
static int hf_gnm__item_item = -1;                /* ObjectInstance */
static int hf_gnm_fromTp = -1;                    /* ExplicitTP */
static int hf_gnm_toTPs = -1;                     /* SET_OF_ExplicitTP */
static int hf_gnm_toTPs_item = -1;                /* ExplicitTP */
static int hf_gnm_toTp = -1;                      /* ExplicitTP */
static int hf_gnm_oneTPorGTP = -1;                /* ObjectInstance */
static int hf_gnm_listofTPs = -1;                 /* SEQUENCE_OF_ObjectInstance */
static int hf_gnm_listofTPs_item = -1;            /* ObjectInstance */
static int hf_gnm_EquipmentHolderAddress_item = -1;  /* PrintableString */
static int hf_gnm_logicalProblem = -1;            /* LogicalProblem */
static int hf_gnm_resourceProblem = -1;           /* ResourceProblem */
static int hf_gnm_holderEmpty = -1;               /* NULL */
static int hf_gnm_inTheAcceptableList = -1;       /* CircuitPackType */
static int hf_gnm_notInTheAcceptableList = -1;    /* CircuitPackType */
static int hf_gnm_unknownType = -1;               /* NULL */
static int hf_gnm_ListOfCharacteristicInformation_item = -1;  /* CharacteristicInformation */
static int hf_gnm_problemCause = -1;              /* ProblemCause */
static int hf_gnm_incorrectInstances = -1;        /* SET_OF_ObjectInstance */
static int hf_gnm_incorrectInstances_item = -1;   /* ObjectInstance */
static int hf_gnm_MultipleConnections_item = -1;  /* MultipleConnections_item */
static int hf_gnm_downstreamNotConnected = -1;    /* ObjectInstance */
static int hf_gnm_downstreamConnected = -1;       /* ObjectInstance */
static int hf_gnm_upstreamNotConnected = -1;      /* ObjectInstance */
static int hf_gnm_upstreamConnected = -1;         /* ObjectInstance */
static int hf_gnm_redline_01 = -1;                /* BOOLEAN */
static int hf_gnm_name = -1;                      /* CrossConnectionName */
static int hf_gnm_numericName = -1;               /* INTEGER */
static int hf_gnm_pString = -1;                   /* GraphicString */
static int hf_gnm_ObjectList_item = -1;           /* ObjectInstance */
static int hf_gnm_diverse = -1;                   /* T_diverse */
static int hf_gnm_downstream = -1;                /* SignalRateAndMappingList */
static int hf_gnm_upStream = -1;                  /* SignalRateAndMappingList */
static int hf_gnm_uniform = -1;                   /* SignalRateAndMappingList */
static int hf_gnm_pointer = -1;                   /* ObjectInstance */
static int hf_gnm_null = -1;                      /* NULL */
static int hf_gnm_fromTp_01 = -1;                 /* ObjectInstance */
static int hf_gnm_toTp_01 = -1;                   /* ObjectInstance */
static int hf_gnm_xCon = -1;                      /* ObjectInstance */
static int hf_gnm_toTps = -1;                     /* T_toTps */
static int hf_gnm_toTps_item = -1;                /* T_toTps_item */
static int hf_gnm_tp = -1;                        /* ObjectInstance */
static int hf_gnm_xConnection = -1;               /* ObjectInstance */
static int hf_gnm_mpXCon = -1;                    /* ObjectInstance */
static int hf_gnm_unknown = -1;                   /* NULL */
static int hf_gnm_integerValue = -1;              /* INTEGER */
static int hf_gnm_toTPPools = -1;                 /* ToTPPools */
static int hf_gnm_toTpPool = -1;                  /* ObjectInstance */
static int hf_gnm_notAvailable = -1;              /* NULL */
static int hf_gnm_relatedObject = -1;             /* ObjectInstance */
static int hf_gnm_SequenceOfObjectInstance_item = -1;  /* ObjectInstance */
static int hf_gnm_SignalRateAndMappingList_item = -1;  /* SignalRateAndMappingList_item */
static int hf_gnm_signalRate = -1;                /* SignalRate */
static int hf_gnm_mappingList = -1;               /* MappingList */
static int hf_gnm_wavelength = -1;                /* WaveLength */
static int hf_gnm_simple = -1;                    /* CharacteristicInformation */
static int hf_gnm_bundle = -1;                    /* Bundle */
static int hf_gnm_complex = -1;                   /* SEQUENCE_OF_Bundle */
static int hf_gnm_complex_item = -1;              /* Bundle */
static int hf_gnm_notApplicable = -1;             /* NULL */
static int hf_gnm_softwareInstances = -1;         /* SEQUENCE_OF_ObjectInstance */
static int hf_gnm_softwareInstances_item = -1;    /* ObjectInstance */
static int hf_gnm_softwareIdentifiers = -1;       /* T_softwareIdentifiers */
static int hf_gnm_softwareIdentifiers_item = -1;  /* PrintableString */
static int hf_gnm_SupportableClientList_item = -1;  /* ObjectClass */
static int hf_gnm_sourceType = -1;                /* T_sourceType */
static int hf_gnm_sourceID = -1;                  /* ObjectInstance */
static int hf_gnm_primaryTimingSource = -1;       /* SystemTiming */
static int hf_gnm_secondaryTimingSource = -1;     /* SystemTiming */
static int hf_gnm_toTpOrGTP = -1;                 /* ExplicitTP */
static int hf_gnm_toPool = -1;                    /* ObjectInstance */
static int hf_gnm_ToTPPools_item = -1;            /* ToTPPools_item */
static int hf_gnm_tpPoolId = -1;                  /* ObjectInstance */
static int hf_gnm_numberOfTPs = -1;               /* INTEGER */
static int hf_gnm_TpsInGtpList_item = -1;         /* ObjectInstance */
/* named bits */
static int hf_gnm_TransmissionCharacteristics_satellite = -1;
static int hf_gnm_TransmissionCharacteristics_dCME = -1;
static int hf_gnm_TransmissionCharacteristics_echoControl = -1;

/*--- End of included file: packet-gnm-hf.c ---*/
#line 50 "../../asn1/gnm/packet-gnm-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-gnm-ett.c ---*/
#line 1 "../../asn1/gnm/packet-gnm-ett.c"
static gint ett_gnm_MappingList = -1;
static gint ett_gnm_SignalRate = -1;
static gint ett_gnm_SupportedTOClasses = -1;
static gint ett_gnm_AcceptableCircuitPackTypeList = -1;
static gint ett_gnm_AddLeg = -1;
static gint ett_gnm_SET_OF_ToTermSpecifier = -1;
static gint ett_gnm_AlarmSeverityAssignment = -1;
static gint ett_gnm_AlarmSeverityAssignmentList = -1;
static gint ett_gnm_Bundle = -1;
static gint ett_gnm_Connected = -1;
static gint ett_gnm_ConnectInformation = -1;
static gint ett_gnm_ConnectInformation_item = -1;
static gint ett_gnm_T_itemType = -1;
static gint ett_gnm_ConnectivityPointer = -1;
static gint ett_gnm_SEQUENCE_OF_ObjectInstance = -1;
static gint ett_gnm_ConnectionType = -1;
static gint ett_gnm_ConnectionTypeBi = -1;
static gint ett_gnm_CrossConnectionObjectPointer = -1;
static gint ett_gnm_CurrentProblem = -1;
static gint ett_gnm_CurrentProblemList = -1;
static gint ett_gnm_DisconnectResult = -1;
static gint ett_gnm_DisconnectResult_item = -1;
static gint ett_gnm_DownstreamConnectivityPointer = -1;
static gint ett_gnm_SET_OF_ObjectInstance = -1;
static gint ett_gnm_T_broadcastConcatenated = -1;
static gint ett_gnm_ExplicitPtoMP = -1;
static gint ett_gnm_SET_OF_ExplicitTP = -1;
static gint ett_gnm_ExplicitPtoP = -1;
static gint ett_gnm_ExplicitTP = -1;
static gint ett_gnm_EquipmentHolderAddress = -1;
static gint ett_gnm_Failed = -1;
static gint ett_gnm_HolderStatus = -1;
static gint ett_gnm_ListOfCharacteristicInformation = -1;
static gint ett_gnm_LogicalProblem = -1;
static gint ett_gnm_MultipleConnections = -1;
static gint ett_gnm_MultipleConnections_item = -1;
static gint ett_gnm_NamedCrossConnection = -1;
static gint ett_gnm_NameType = -1;
static gint ett_gnm_ObjectList = -1;
static gint ett_gnm_PhysicalPortSignalRateAndMappingList = -1;
static gint ett_gnm_T_diverse = -1;
static gint ett_gnm_PointerOrNull = -1;
static gint ett_gnm_PointToPoint = -1;
static gint ett_gnm_PointToMultipoint = -1;
static gint ett_gnm_T_toTps = -1;
static gint ett_gnm_T_toTps_item = -1;
static gint ett_gnm_ProblemCause = -1;
static gint ett_gnm_PtoMPools = -1;
static gint ett_gnm_PtoTPPool = -1;
static gint ett_gnm_RelatedObjectInstance = -1;
static gint ett_gnm_ResourceProblem = -1;
static gint ett_gnm_SequenceOfObjectInstance = -1;
static gint ett_gnm_SignalRateAndMappingList = -1;
static gint ett_gnm_SignalRateAndMappingList_item = -1;
static gint ett_gnm_SignalType = -1;
static gint ett_gnm_SEQUENCE_OF_Bundle = -1;
static gint ett_gnm_SubordinateCircuitPackSoftwareLoad = -1;
static gint ett_gnm_T_softwareIdentifiers = -1;
static gint ett_gnm_SupportableClientList = -1;
static gint ett_gnm_SystemTiming = -1;
static gint ett_gnm_SystemTimingSource = -1;
static gint ett_gnm_ToTermSpecifier = -1;
static gint ett_gnm_ToTPPools = -1;
static gint ett_gnm_ToTPPools_item = -1;
static gint ett_gnm_TpsInGtpList = -1;
static gint ett_gnm_TransmissionCharacteristics = -1;

/*--- End of included file: packet-gnm-ett.c ---*/
#line 53 "../../asn1/gnm/packet-gnm-template.c"


/*--- Included file: packet-gnm-fn.c ---*/
#line 1 "../../asn1/gnm/packet-gnm-fn.c"


static int
dissect_gnm_CharacteristicInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gnm_PayloadLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gnm_CharacteristicInformation(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t MappingList_sequence_of[1] = {
  { &hf_gnm_MappingList_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gnm_PayloadLevel },
};

static int
dissect_gnm_MappingList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MappingList_sequence_of, hf_index, ett_gnm_MappingList);

  return offset;
}



static int
dissect_gnm_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string gnm_SignalRate_vals[] = {
  {   0, "objectClass" },
  {   1, "characteristicInformation" },
  { 0, NULL }
};

static const ber_choice_t SignalRate_choice[] = {
  {   0, &hf_gnm_objectClass     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_OBJECT_IDENTIFIER },
  {   1, &hf_gnm_characteristicInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_CharacteristicInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_SignalRate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SignalRate_choice, hf_index, ett_gnm_SignalRate,
                                 NULL);

  return offset;
}


static const ber_sequence_t SupportedTOClasses_set_of[1] = {
  { &hf_gnm_SupportedTOClasses_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gnm_OBJECT_IDENTIFIER },
};

static int
dissect_gnm_SupportedTOClasses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SupportedTOClasses_set_of, hf_index, ett_gnm_SupportedTOClasses);

  return offset;
}



static int
dissect_gnm_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t AcceptableCircuitPackTypeList_set_of[1] = {
  { &hf_gnm_AcceptableCircuitPackTypeList_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_gnm_PrintableString },
};

static int
dissect_gnm_AcceptableCircuitPackTypeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AcceptableCircuitPackTypeList_set_of, hf_index, ett_gnm_AcceptableCircuitPackTypeList);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ObjectInstance_sequence_of[1] = {
  { &hf_gnm_concatenated_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_gnm_SEQUENCE_OF_ObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ObjectInstance_sequence_of, hf_index, ett_gnm_SEQUENCE_OF_ObjectInstance);

  return offset;
}


static const value_string gnm_ExplicitTP_vals[] = {
  {   0, "oneTPorGTP" },
  {   1, "listofTPs" },
  { 0, NULL }
};

static const ber_choice_t ExplicitTP_choice[] = {
  {   0, &hf_gnm_oneTPorGTP      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  {   1, &hf_gnm_listofTPs       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_SEQUENCE_OF_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ExplicitTP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ExplicitTP_choice, hf_index, ett_gnm_ExplicitTP,
                                 NULL);

  return offset;
}


static const value_string gnm_ToTermSpecifier_vals[] = {
  {   0, "toTpOrGTP" },
  {   1, "toPool" },
  { 0, NULL }
};

static const ber_choice_t ToTermSpecifier_choice[] = {
  {   0, &hf_gnm_toTpOrGTP       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_ExplicitTP },
  {   1, &hf_gnm_toPool          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ToTermSpecifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ToTermSpecifier_choice, hf_index, ett_gnm_ToTermSpecifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ToTermSpecifier_set_of[1] = {
  { &hf_gnm_legs_item       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ToTermSpecifier },
};

static int
dissect_gnm_SET_OF_ToTermSpecifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ToTermSpecifier_set_of, hf_index, ett_gnm_SET_OF_ToTermSpecifier);

  return offset;
}


static const ber_sequence_t AddLeg_sequence[] = {
  { &hf_gnm_mpCrossConnection, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { &hf_gnm_legs            , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_SET_OF_ToTermSpecifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_AddLeg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddLeg_sequence, hf_index, ett_gnm_AddLeg);

  return offset;
}


static const value_string gnm_AlarmSeverityCode_vals[] = {
  {   0, "non-alarmed" },
  {   1, "minor" },
  {   2, "major" },
  {   3, "critical" },
  {   4, "warning" },
  { 0, NULL }
};


static int
dissect_gnm_AlarmSeverityCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AlarmSeverityAssignment_sequence[] = {
  { &hf_gnm_problem         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ProbableCause },
  { &hf_gnm_severityAssignedServiceAffecting, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gnm_AlarmSeverityCode },
  { &hf_gnm_severityAssignedNonServiceAffecting, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gnm_AlarmSeverityCode },
  { &hf_gnm_severityAssignedServiceIndependent, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gnm_AlarmSeverityCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_AlarmSeverityAssignment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlarmSeverityAssignment_sequence, hf_index, ett_gnm_AlarmSeverityAssignment);

  return offset;
}


static const ber_sequence_t AlarmSeverityAssignmentList_set_of[1] = {
  { &hf_gnm_AlarmSeverityAssignmentList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_AlarmSeverityAssignment },
};

static int
dissect_gnm_AlarmSeverityAssignmentList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AlarmSeverityAssignmentList_set_of, hf_index, ett_gnm_AlarmSeverityAssignmentList);

  return offset;
}


static const value_string gnm_AlarmStatus_vals[] = {
  {   0, "cleared" },
  {   1, "activeReportable-Indeterminate" },
  {   2, "activeReportable-Warning" },
  {   3, "activeReportable-Minor" },
  {   4, "activeReportable-Major" },
  {   5, "activeReportable-Critical" },
  {   6, "activePending" },
  { 0, NULL }
};


static int
dissect_gnm_AlarmStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gnm_Boolean(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gnm_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Bundle_sequence[] = {
  { &hf_gnm_characteristicInfoType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gnm_CharacteristicInformation },
  { &hf_gnm_bundlingFactor  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gnm_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_Bundle(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Bundle_sequence, hf_index, ett_gnm_Bundle);

  return offset;
}



static int
dissect_gnm_ChannelNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gnm_CircuitDirectionality_vals[] = {
  {   0, "onewayOut" },
  {   1, "onewayIn" },
  {   2, "twoway" },
  { 0, NULL }
};


static int
dissect_gnm_CircuitDirectionality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gnm_CircuitPackType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PointToPoint_sequence[] = {
  { &hf_gnm_fromTp_01       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { &hf_gnm_toTp_01         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { &hf_gnm_xCon            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_PointToPoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PointToPoint_sequence, hf_index, ett_gnm_PointToPoint);

  return offset;
}


static const ber_sequence_t T_toTps_item_sequence[] = {
  { &hf_gnm_tp              , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { &hf_gnm_xConnection     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_T_toTps_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_toTps_item_sequence, hf_index, ett_gnm_T_toTps_item);

  return offset;
}


static const ber_sequence_t T_toTps_set_of[1] = {
  { &hf_gnm_toTps_item      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_T_toTps_item },
};

static int
dissect_gnm_T_toTps(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_toTps_set_of, hf_index, ett_gnm_T_toTps);

  return offset;
}


static const ber_sequence_t PointToMultipoint_sequence[] = {
  { &hf_gnm_fromTp_01       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { &hf_gnm_toTps           , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_T_toTps },
  { &hf_gnm_mpXCon          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_PointToMultipoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PointToMultipoint_sequence, hf_index, ett_gnm_PointToMultipoint);

  return offset;
}


static const value_string gnm_Connected_vals[] = {
  {   0, "pointToPoint" },
  {   1, "pointToMultipoint" },
  { 0, NULL }
};

static const ber_choice_t Connected_choice[] = {
  {   0, &hf_gnm_pointToPoint    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_PointToPoint },
  {   1, &hf_gnm_pointToMultipoint, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_PointToMultipoint },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_Connected(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Connected_choice, hf_index, ett_gnm_Connected,
                                 NULL);

  return offset;
}


static const ber_sequence_t ExplicitPtoP_sequence[] = {
  { &hf_gnm_fromTp          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ExplicitTP },
  { &hf_gnm_toTp            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ExplicitTP },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ExplicitPtoP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExplicitPtoP_sequence, hf_index, ett_gnm_ExplicitPtoP);

  return offset;
}


static const ber_sequence_t PtoTPPool_sequence[] = {
  { &hf_gnm_fromTp          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ExplicitTP },
  { &hf_gnm_toTpPool        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_PtoTPPool(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PtoTPPool_sequence, hf_index, ett_gnm_PtoTPPool);

  return offset;
}


static const ber_sequence_t SET_OF_ExplicitTP_set_of[1] = {
  { &hf_gnm_toTPs_item      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ExplicitTP },
};

static int
dissect_gnm_SET_OF_ExplicitTP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ExplicitTP_set_of, hf_index, ett_gnm_SET_OF_ExplicitTP);

  return offset;
}


static const ber_sequence_t ExplicitPtoMP_sequence[] = {
  { &hf_gnm_fromTp          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ExplicitTP },
  { &hf_gnm_toTPs           , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_SET_OF_ExplicitTP },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ExplicitPtoMP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExplicitPtoMP_sequence, hf_index, ett_gnm_ExplicitPtoMP);

  return offset;
}


static const ber_sequence_t ToTPPools_item_sequence[] = {
  { &hf_gnm_tpPoolId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { &hf_gnm_numberOfTPs     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gnm_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ToTPPools_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ToTPPools_item_sequence, hf_index, ett_gnm_ToTPPools_item);

  return offset;
}


static const ber_sequence_t ToTPPools_set_of[1] = {
  { &hf_gnm_ToTPPools_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_ToTPPools_item },
};

static int
dissect_gnm_ToTPPools(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ToTPPools_set_of, hf_index, ett_gnm_ToTPPools);

  return offset;
}


static const ber_sequence_t PtoMPools_sequence[] = {
  { &hf_gnm_fromTp          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ExplicitTP },
  { &hf_gnm_toTPPools       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_ToTPPools },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_PtoMPools(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PtoMPools_sequence, hf_index, ett_gnm_PtoMPools);

  return offset;
}


static const value_string gnm_ConnectionType_vals[] = {
  {   0, "explicitPToP" },
  {   1, "ptoTpPool" },
  {   2, "explicitPtoMP" },
  {   3, "ptoMPools" },
  { 0, NULL }
};

static const ber_choice_t ConnectionType_choice[] = {
  {   0, &hf_gnm_explicitPToP    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_ExplicitPtoP },
  {   1, &hf_gnm_ptoTpPool       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_PtoTPPool },
  {   2, &hf_gnm_explicitPtoMP   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gnm_ExplicitPtoMP },
  {   3, &hf_gnm_ptoMPools       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gnm_PtoMPools },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectionType_choice, hf_index, ett_gnm_ConnectionType,
                                 NULL);

  return offset;
}


static const value_string gnm_ConnectionTypeBi_vals[] = {
  {   0, "explicitPToP" },
  {   1, "ptoTpPool" },
  { 0, NULL }
};

static const ber_choice_t ConnectionTypeBi_choice[] = {
  {   0, &hf_gnm_explicitPToP    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_ExplicitPtoP },
  {   1, &hf_gnm_ptoTpPool       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_PtoTPPool },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectionTypeBi(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectionTypeBi_choice, hf_index, ett_gnm_ConnectionTypeBi,
                                 NULL);

  return offset;
}


static const value_string gnm_T_itemType_vals[] = {
  {   0, "unidirectional" },
  {   1, "bidirectional" },
  {   2, "addleg" },
  { 0, NULL }
};

static const ber_choice_t T_itemType_choice[] = {
  {   0, &hf_gnm_unidirectional  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_ConnectionType },
  {   1, &hf_gnm_bidirectional   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_ConnectionTypeBi },
  {   2, &hf_gnm_addleg          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gnm_AddLeg },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_T_itemType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_itemType_choice, hf_index, ett_gnm_T_itemType,
                                 NULL);

  return offset;
}



static int
dissect_gnm_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gnm_CrossConnectionName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t NamedCrossConnection_sequence[] = {
  { &hf_gnm_redline_01      , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_gnm_BOOLEAN },
  { &hf_gnm_name            , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_gnm_CrossConnectionName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_NamedCrossConnection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NamedCrossConnection_sequence, hf_index, ett_gnm_NamedCrossConnection);

  return offset;
}



static int
dissect_gnm_UserLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t ConnectInformation_item_sequence[] = {
  { &hf_gnm_itemType        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_T_itemType },
  { &hf_gnm_administrativeState, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_AdministrativeState },
  { &hf_gnm_namedCrossConnection, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gnm_NamedCrossConnection },
  { &hf_gnm_userLabel       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gnm_UserLabel },
  { &hf_gnm_redline         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gnm_Boolean },
  { &hf_gnm_additionalInfo  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_AdditionalInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectInformation_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectInformation_item_sequence, hf_index, ett_gnm_ConnectInformation_item);

  return offset;
}


static const ber_sequence_t ConnectInformation_sequence_of[1] = {
  { &hf_gnm_ConnectInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_ConnectInformation_item },
};

static int
dissect_gnm_ConnectInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ConnectInformation_sequence_of, hf_index, ett_gnm_ConnectInformation);

  return offset;
}



static int
dissect_gnm_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string gnm_ConnectivityPointer_vals[] = {
  {   0, "none" },
  {   1, "single" },
  {   2, "concatenated" },
  { 0, NULL }
};

static const ber_choice_t ConnectivityPointer_choice[] = {
  {   0, &hf_gnm_none            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_single          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  {   2, &hf_gnm_concatenated    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_SEQUENCE_OF_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectivityPointer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectivityPointer_choice, hf_index, ett_gnm_ConnectivityPointer,
                                 NULL);

  return offset;
}



static int
dissect_gnm_Count(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gnm_MultipleConnections_item_vals[] = {
  {   0, "downstreamNotConnected" },
  {   1, "downstreamConnected" },
  {   2, "upstreamNotConnected" },
  {   3, "upstreamConnected" },
  { 0, NULL }
};

static const ber_choice_t MultipleConnections_item_choice[] = {
  {   0, &hf_gnm_downstreamNotConnected, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  {   1, &hf_gnm_downstreamConnected, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  {   2, &hf_gnm_upstreamNotConnected, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  {   3, &hf_gnm_upstreamConnected, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_MultipleConnections_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MultipleConnections_item_choice, hf_index, ett_gnm_MultipleConnections_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t MultipleConnections_set_of[1] = {
  { &hf_gnm_MultipleConnections_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_MultipleConnections_item },
};

static int
dissect_gnm_MultipleConnections(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MultipleConnections_set_of, hf_index, ett_gnm_MultipleConnections);

  return offset;
}


static const value_string gnm_CrossConnectionObjectPointer_vals[] = {
  {   0, "notConnected" },
  {   1, "connected" },
  {   2, "multipleConnections" },
  { 0, NULL }
};

static const ber_choice_t CrossConnectionObjectPointer_choice[] = {
  {   0, &hf_gnm_notConnected    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  {   1, &hf_gnm_connected       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  {   2, &hf_gnm_multipleConnections, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_MultipleConnections },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_CrossConnectionObjectPointer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CrossConnectionObjectPointer_choice, hf_index, ett_gnm_CrossConnectionObjectPointer,
                                 NULL);

  return offset;
}


static const ber_sequence_t CurrentProblem_sequence[] = {
  { &hf_gnm_problem         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_ProbableCause },
  { &hf_gnm_alarmStatus     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_AlarmStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_CurrentProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CurrentProblem_sequence, hf_index, ett_gnm_CurrentProblem);

  return offset;
}


static const ber_sequence_t CurrentProblemList_set_of[1] = {
  { &hf_gnm_CurrentProblemList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_CurrentProblem },
};

static int
dissect_gnm_CurrentProblemList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CurrentProblemList_set_of, hf_index, ett_gnm_CurrentProblemList);

  return offset;
}


static const value_string gnm_Directionality_vals[] = {
  {   0, "unidirectional" },
  {   1, "bidirectional" },
  { 0, NULL }
};


static int
dissect_gnm_Directionality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gnm_ProblemCause_vals[] = {
  {   0, "unknown" },
  {   1, "integerValue" },
  { 0, NULL }
};

static const ber_choice_t ProblemCause_choice[] = {
  {   0, &hf_gnm_unknown         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_integerValue    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gnm_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ProblemCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProblemCause_choice, hf_index, ett_gnm_ProblemCause,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ObjectInstance_set_of[1] = {
  { &hf_gnm_broadcast_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_gnm_SET_OF_ObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ObjectInstance_set_of, hf_index, ett_gnm_SET_OF_ObjectInstance);

  return offset;
}


static const ber_sequence_t LogicalProblem_sequence[] = {
  { &hf_gnm_problemCause    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_ProblemCause },
  { &hf_gnm_incorrectInstances, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gnm_SET_OF_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_LogicalProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LogicalProblem_sequence, hf_index, ett_gnm_LogicalProblem);

  return offset;
}


static const value_string gnm_ResourceProblem_vals[] = {
  {   0, "unknown" },
  {   1, "integerValue" },
  { 0, NULL }
};

static const ber_choice_t ResourceProblem_choice[] = {
  {   0, &hf_gnm_unknown         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_integerValue    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gnm_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_ResourceProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ResourceProblem_choice, hf_index, ett_gnm_ResourceProblem,
                                 NULL);

  return offset;
}


static const value_string gnm_Failed_vals[] = {
  {   0, "logicalProblem" },
  {   1, "resourceProblem" },
  { 0, NULL }
};

static const ber_choice_t Failed_choice[] = {
  {   0, &hf_gnm_logicalProblem  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_LogicalProblem },
  {   1, &hf_gnm_resourceProblem , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gnm_ResourceProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_Failed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Failed_choice, hf_index, ett_gnm_Failed,
                                 NULL);

  return offset;
}


static const value_string gnm_DisconnectResult_item_vals[] = {
  { -1/*choice*/, "failed" },
  { -1/*choice*/, "disconnected" },
  { 0, NULL }
};

static const ber_choice_t DisconnectResult_item_choice[] = {
  { -1/*choice*/, &hf_gnm_failed          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gnm_Failed },
  { -1/*choice*/, &hf_gnm_disconnected    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_DisconnectResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DisconnectResult_item_choice, hf_index, ett_gnm_DisconnectResult_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t DisconnectResult_sequence_of[1] = {
  { &hf_gnm_DisconnectResult_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_DisconnectResult_item },
};

static int
dissect_gnm_DisconnectResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DisconnectResult_sequence_of, hf_index, ett_gnm_DisconnectResult);

  return offset;
}


static const ber_sequence_t T_broadcastConcatenated_set_of[1] = {
  { &hf_gnm_broadcastConcatenated_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_SEQUENCE_OF_ObjectInstance },
};

static int
dissect_gnm_T_broadcastConcatenated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_broadcastConcatenated_set_of, hf_index, ett_gnm_T_broadcastConcatenated);

  return offset;
}


static const value_string gnm_DownstreamConnectivityPointer_vals[] = {
  {   0, "none" },
  {   1, "single" },
  {   2, "concatenated" },
  {   3, "broadcast" },
  {   4, "broadcastConcatenated" },
  { 0, NULL }
};

static const ber_choice_t DownstreamConnectivityPointer_choice[] = {
  {   0, &hf_gnm_none            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_single          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  {   2, &hf_gnm_concatenated    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_SEQUENCE_OF_ObjectInstance },
  {   3, &hf_gnm_broadcast       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_SET_OF_ObjectInstance },
  {   4, &hf_gnm_broadcastConcatenated, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_T_broadcastConcatenated },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_DownstreamConnectivityPointer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DownstreamConnectivityPointer_choice, hf_index, ett_gnm_DownstreamConnectivityPointer,
                                 NULL);

  return offset;
}



static int
dissect_gnm_ExternalTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t EquipmentHolderAddress_sequence_of[1] = {
  { &hf_gnm_EquipmentHolderAddress_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_gnm_PrintableString },
};

static int
dissect_gnm_EquipmentHolderAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EquipmentHolderAddress_sequence_of, hf_index, ett_gnm_EquipmentHolderAddress);

  return offset;
}



static int
dissect_gnm_EquipmentHolderType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gnm_HolderStatus_vals[] = {
  {   0, "holderEmpty" },
  {   1, "inTheAcceptableList" },
  {   2, "notInTheAcceptableList" },
  {   3, "unknownType" },
  { 0, NULL }
};

static const ber_choice_t HolderStatus_choice[] = {
  {   0, &hf_gnm_holderEmpty     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_inTheAcceptableList, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_CircuitPackType },
  {   2, &hf_gnm_notInTheAcceptableList, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gnm_CircuitPackType },
  {   3, &hf_gnm_unknownType     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gnm_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_HolderStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HolderStatus_choice, hf_index, ett_gnm_HolderStatus,
                                 NULL);

  return offset;
}


static const value_string gnm_InformationTransferCapabilities_vals[] = {
  {   0, "speech" },
  {   1, "audio3pt1" },
  {   2, "audio7" },
  {   3, "audioComb" },
  {   4, "digitalRestricted56" },
  {   5, "digitalUnrestricted64" },
  { 0, NULL }
};


static int
dissect_gnm_InformationTransferCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ListOfCharacteristicInformation_set_of[1] = {
  { &hf_gnm_ListOfCharacteristicInformation_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gnm_CharacteristicInformation },
};

static int
dissect_gnm_ListOfCharacteristicInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ListOfCharacteristicInformation_set_of, hf_index, ett_gnm_ListOfCharacteristicInformation);

  return offset;
}



static int
dissect_gnm_GraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gnm_NameType_vals[] = {
  {   0, "numericName" },
  {   1, "pString" },
  { 0, NULL }
};

static const ber_choice_t NameType_choice[] = {
  {   0, &hf_gnm_numericName     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gnm_INTEGER },
  {   1, &hf_gnm_pString         , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_gnm_GraphicString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_NameType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NameType_choice, hf_index, ett_gnm_NameType,
                                 NULL);

  return offset;
}



static int
dissect_gnm_NumberOfCircuits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ObjectList_set_of[1] = {
  { &hf_gnm_ObjectList_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_gnm_ObjectList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ObjectList_set_of, hf_index, ett_gnm_ObjectList);

  return offset;
}



static int
dissect_gnm_WaveLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SignalRateAndMappingList_item_sequence[] = {
  { &hf_gnm_signalRate      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gnm_SignalRate },
  { &hf_gnm_mappingList     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gnm_MappingList },
  { &hf_gnm_wavelength      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gnm_WaveLength },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_SignalRateAndMappingList_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SignalRateAndMappingList_item_sequence, hf_index, ett_gnm_SignalRateAndMappingList_item);

  return offset;
}


static const ber_sequence_t SignalRateAndMappingList_set_of[1] = {
  { &hf_gnm_SignalRateAndMappingList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_SignalRateAndMappingList_item },
};

static int
dissect_gnm_SignalRateAndMappingList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SignalRateAndMappingList_set_of, hf_index, ett_gnm_SignalRateAndMappingList);

  return offset;
}


static const ber_sequence_t T_diverse_sequence[] = {
  { &hf_gnm_downstream      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_SignalRateAndMappingList },
  { &hf_gnm_upStream        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_SignalRateAndMappingList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_T_diverse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_diverse_sequence, hf_index, ett_gnm_T_diverse);

  return offset;
}


static const value_string gnm_PhysicalPortSignalRateAndMappingList_vals[] = {
  {   0, "diverse" },
  {   1, "uniform" },
  { 0, NULL }
};

static const ber_choice_t PhysicalPortSignalRateAndMappingList_choice[] = {
  {   0, &hf_gnm_diverse         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_T_diverse },
  {   1, &hf_gnm_uniform         , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_gnm_SignalRateAndMappingList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_PhysicalPortSignalRateAndMappingList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PhysicalPortSignalRateAndMappingList_choice, hf_index, ett_gnm_PhysicalPortSignalRateAndMappingList,
                                 NULL);

  return offset;
}



static int
dissect_gnm_Pointer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_ObjectInstance(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string gnm_PointerOrNull_vals[] = {
  {   0, "pointer" },
  {   1, "null" },
  { 0, NULL }
};

static const ber_choice_t PointerOrNull_choice[] = {
  {   0, &hf_gnm_pointer         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  {   1, &hf_gnm_null            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_PointerOrNull(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PointerOrNull_choice, hf_index, ett_gnm_PointerOrNull,
                                 NULL);

  return offset;
}


static const value_string gnm_RelatedObjectInstance_vals[] = {
  {   0, "notAvailable" },
  {   1, "relatedObject" },
  { 0, NULL }
};

static const ber_choice_t RelatedObjectInstance_choice[] = {
  {   0, &hf_gnm_notAvailable    , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_relatedObject   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_RelatedObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RelatedObjectInstance_choice, hf_index, ett_gnm_RelatedObjectInstance,
                                 NULL);

  return offset;
}


static const value_string gnm_Replaceable_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  {   2, "notapplicable" },
  { 0, NULL }
};


static int
dissect_gnm_Replaceable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SequenceOfObjectInstance_sequence_of[1] = {
  { &hf_gnm_SequenceOfObjectInstance_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_gnm_SequenceOfObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SequenceOfObjectInstance_sequence_of, hf_index, ett_gnm_SequenceOfObjectInstance);

  return offset;
}



static int
dissect_gnm_SerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gnm_SignallingCapabilities_vals[] = {
  {   0, "isup" },
  {   1, "isup92" },
  {   2, "itu-tNo5" },
  {   3, "r2" },
  {   4, "itu-tNo6" },
  {   5, "tup" },
  { 0, NULL }
};


static int
dissect_gnm_SignallingCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Bundle_sequence_of[1] = {
  { &hf_gnm_complex_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_Bundle },
};

static int
dissect_gnm_SEQUENCE_OF_Bundle(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Bundle_sequence_of, hf_index, ett_gnm_SEQUENCE_OF_Bundle);

  return offset;
}


static const value_string gnm_SignalType_vals[] = {
  {   0, "simple" },
  {   1, "bundle" },
  {   2, "complex" },
  { 0, NULL }
};

static const ber_choice_t SignalType_choice[] = {
  {   0, &hf_gnm_simple          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gnm_CharacteristicInformation },
  {   1, &hf_gnm_bundle          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_Bundle },
  {   2, &hf_gnm_complex         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_SEQUENCE_OF_Bundle },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_SignalType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SignalType_choice, hf_index, ett_gnm_SignalType,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_softwareIdentifiers_sequence_of[1] = {
  { &hf_gnm_softwareIdentifiers_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_gnm_PrintableString },
};

static int
dissect_gnm_T_softwareIdentifiers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_softwareIdentifiers_sequence_of, hf_index, ett_gnm_T_softwareIdentifiers);

  return offset;
}


static const value_string gnm_SubordinateCircuitPackSoftwareLoad_vals[] = {
  {   0, "notApplicable" },
  {   1, "softwareInstances" },
  {   2, "softwareIdentifiers" },
  { 0, NULL }
};

static const ber_choice_t SubordinateCircuitPackSoftwareLoad_choice[] = {
  {   0, &hf_gnm_notApplicable   , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_gnm_NULL },
  {   1, &hf_gnm_softwareInstances, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gnm_SEQUENCE_OF_ObjectInstance },
  {   2, &hf_gnm_softwareIdentifiers, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gnm_T_softwareIdentifiers },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_SubordinateCircuitPackSoftwareLoad(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SubordinateCircuitPackSoftwareLoad_choice, hf_index, ett_gnm_SubordinateCircuitPackSoftwareLoad,
                                 NULL);

  return offset;
}


static const ber_sequence_t SupportableClientList_set_of[1] = {
  { &hf_gnm_SupportableClientList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectClass },
};

static int
dissect_gnm_SupportableClientList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SupportableClientList_set_of, hf_index, ett_gnm_SupportableClientList);

  return offset;
}


static const value_string gnm_T_sourceType_vals[] = {
  {   0, "internalTimingSource" },
  {   1, "remoteTimingSource" },
  {   2, "slavedTimingTerminationSignal" },
  { 0, NULL }
};


static int
dissect_gnm_T_sourceType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SystemTiming_sequence[] = {
  { &hf_gnm_sourceType      , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_gnm_T_sourceType },
  { &hf_gnm_sourceID        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_SystemTiming(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SystemTiming_sequence, hf_index, ett_gnm_SystemTiming);

  return offset;
}


static const ber_sequence_t SystemTimingSource_sequence[] = {
  { &hf_gnm_primaryTimingSource, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gnm_SystemTiming },
  { &hf_gnm_secondaryTimingSource, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gnm_SystemTiming },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gnm_SystemTimingSource(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SystemTimingSource_sequence, hf_index, ett_gnm_SystemTimingSource);

  return offset;
}


static const ber_sequence_t TpsInGtpList_sequence_of[1] = {
  { &hf_gnm_TpsInGtpList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_gnm_TpsInGtpList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TpsInGtpList_sequence_of, hf_index, ett_gnm_TpsInGtpList);

  return offset;
}


static const asn_namedbit TransmissionCharacteristics_bits[] = {
  {  0, &hf_gnm_TransmissionCharacteristics_satellite, -1, -1, "satellite", NULL },
  {  1, &hf_gnm_TransmissionCharacteristics_dCME, -1, -1, "dCME", NULL },
  {  2, &hf_gnm_TransmissionCharacteristics_echoControl, -1, -1, "echoControl", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gnm_TransmissionCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    TransmissionCharacteristics_bits, hf_index, ett_gnm_TransmissionCharacteristics,
                                    NULL);

  return offset;
}



static int
dissect_gnm_VendorName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gnm_Version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_SupportedTOClasses_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SupportedTOClasses(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SupportedTOClasses_PDU);
}
static void dissect_AcceptableCircuitPackTypeList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_AcceptableCircuitPackTypeList(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_AcceptableCircuitPackTypeList_PDU);
}
static void dissect_AlarmSeverityAssignmentList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_AlarmSeverityAssignmentList(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_AlarmSeverityAssignmentList_PDU);
}
static void dissect_AlarmStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_AlarmStatus(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_AlarmStatus_PDU);
}
static void dissect_Boolean_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_Boolean(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_Boolean_PDU);
}
static void dissect_ChannelNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_ChannelNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_ChannelNumber_PDU);
}
static void dissect_CharacteristicInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_CharacteristicInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_CharacteristicInformation_PDU);
}
static void dissect_CircuitDirectionality_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_CircuitDirectionality(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_CircuitDirectionality_PDU);
}
static void dissect_CircuitPackType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_CircuitPackType(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_CircuitPackType_PDU);
}
static void dissect_ConnectInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_ConnectInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_ConnectInformation_PDU);
}
static void dissect_ConnectivityPointer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_ConnectivityPointer(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_ConnectivityPointer_PDU);
}
static void dissect_Count_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_Count(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_Count_PDU);
}
static void dissect_CrossConnectionName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_CrossConnectionName(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_CrossConnectionName_PDU);
}
static void dissect_CrossConnectionObjectPointer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_CrossConnectionObjectPointer(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_CrossConnectionObjectPointer_PDU);
}
static void dissect_CurrentProblemList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_CurrentProblemList(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_CurrentProblemList_PDU);
}
static void dissect_Directionality_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_Directionality(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_Directionality_PDU);
}
static void dissect_DisconnectResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_DisconnectResult(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_DisconnectResult_PDU);
}
static void dissect_DownstreamConnectivityPointer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_DownstreamConnectivityPointer(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_DownstreamConnectivityPointer_PDU);
}
static void dissect_ExternalTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_ExternalTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_ExternalTime_PDU);
}
static void dissect_EquipmentHolderAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_EquipmentHolderAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_EquipmentHolderAddress_PDU);
}
static void dissect_EquipmentHolderType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_EquipmentHolderType(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_EquipmentHolderType_PDU);
}
static void dissect_HolderStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_HolderStatus(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_HolderStatus_PDU);
}
static void dissect_InformationTransferCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_InformationTransferCapabilities(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_InformationTransferCapabilities_PDU);
}
static void dissect_ListOfCharacteristicInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_ListOfCharacteristicInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_ListOfCharacteristicInformation_PDU);
}
static void dissect_NameType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_NameType(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_NameType_PDU);
}
static void dissect_NumberOfCircuits_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_NumberOfCircuits(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_NumberOfCircuits_PDU);
}
static void dissect_ObjectList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_ObjectList(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_ObjectList_PDU);
}
static void dissect_Pointer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_Pointer(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_Pointer_PDU);
}
static void dissect_PointerOrNull_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_PointerOrNull(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_PointerOrNull_PDU);
}
static void dissect_RelatedObjectInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_RelatedObjectInstance(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_RelatedObjectInstance_PDU);
}
static void dissect_Replaceable_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_Replaceable(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_Replaceable_PDU);
}
static void dissect_SequenceOfObjectInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SequenceOfObjectInstance(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SequenceOfObjectInstance_PDU);
}
static void dissect_SerialNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SerialNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SerialNumber_PDU);
}
static void dissect_SignallingCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SignallingCapabilities(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SignallingCapabilities_PDU);
}
static void dissect_SignalType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SignalType(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SignalType_PDU);
}
static void dissect_SubordinateCircuitPackSoftwareLoad_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SubordinateCircuitPackSoftwareLoad(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SubordinateCircuitPackSoftwareLoad_PDU);
}
static void dissect_SupportableClientList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SupportableClientList(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SupportableClientList_PDU);
}
static void dissect_SystemTimingSource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_SystemTimingSource(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_SystemTimingSource_PDU);
}
static void dissect_TpsInGtpList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_TpsInGtpList(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_TpsInGtpList_PDU);
}
static void dissect_TransmissionCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_TransmissionCharacteristics(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_TransmissionCharacteristics_PDU);
}
static void dissect_UserLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_UserLabel(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_UserLabel_PDU);
}
static void dissect_VendorName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_VendorName(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_VendorName_PDU);
}
static void dissect_Version_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_gnm_Version(FALSE, tvb, 0, &asn1_ctx, tree, hf_gnm_Version_PDU);
}


/*--- End of included file: packet-gnm-fn.c ---*/
#line 55 "../../asn1/gnm/packet-gnm-template.c"



static void
dissect_gnm_attribute_ObjectInstance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	dissect_cmip_ObjectInstance(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);

}

void
dissect_gnm(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_)
{
  /* Dymmy function */
}

/*--- proto_register_gnm -------------------------------------------*/
void proto_register_gnm(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-gnm-hfarr.c ---*/
#line 1 "../../asn1/gnm/packet-gnm-hfarr.c"
    { &hf_gnm_SupportedTOClasses_PDU,
      { "SupportedTOClasses", "gnm.SupportedTOClasses",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_AcceptableCircuitPackTypeList_PDU,
      { "AcceptableCircuitPackTypeList", "gnm.AcceptableCircuitPackTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_AlarmSeverityAssignmentList_PDU,
      { "AlarmSeverityAssignmentList", "gnm.AlarmSeverityAssignmentList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_AlarmStatus_PDU,
      { "AlarmStatus", "gnm.AlarmStatus",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmStatus_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_Boolean_PDU,
      { "Boolean", "gnm.Boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ChannelNumber_PDU,
      { "ChannelNumber", "gnm.ChannelNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_CharacteristicInformation_PDU,
      { "CharacteristicInformation", "gnm.CharacteristicInformation",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_CircuitDirectionality_PDU,
      { "CircuitDirectionality", "gnm.CircuitDirectionality",
        FT_UINT32, BASE_DEC, VALS(gnm_CircuitDirectionality_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_CircuitPackType_PDU,
      { "CircuitPackType", "gnm.CircuitPackType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ConnectInformation_PDU,
      { "ConnectInformation", "gnm.ConnectInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ConnectivityPointer_PDU,
      { "ConnectivityPointer", "gnm.ConnectivityPointer",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectivityPointer_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_Count_PDU,
      { "Count", "gnm.Count",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_CrossConnectionName_PDU,
      { "CrossConnectionName", "gnm.CrossConnectionName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_CrossConnectionObjectPointer_PDU,
      { "CrossConnectionObjectPointer", "gnm.CrossConnectionObjectPointer",
        FT_UINT32, BASE_DEC, VALS(gnm_CrossConnectionObjectPointer_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_CurrentProblemList_PDU,
      { "CurrentProblemList", "gnm.CurrentProblemList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_Directionality_PDU,
      { "Directionality", "gnm.Directionality",
        FT_UINT32, BASE_DEC, VALS(gnm_Directionality_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_DisconnectResult_PDU,
      { "DisconnectResult", "gnm.DisconnectResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_DownstreamConnectivityPointer_PDU,
      { "DownstreamConnectivityPointer", "gnm.DownstreamConnectivityPointer",
        FT_UINT32, BASE_DEC, VALS(gnm_DownstreamConnectivityPointer_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_ExternalTime_PDU,
      { "ExternalTime", "gnm.ExternalTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_EquipmentHolderAddress_PDU,
      { "EquipmentHolderAddress", "gnm.EquipmentHolderAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_EquipmentHolderType_PDU,
      { "EquipmentHolderType", "gnm.EquipmentHolderType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_HolderStatus_PDU,
      { "HolderStatus", "gnm.HolderStatus",
        FT_UINT32, BASE_DEC, VALS(gnm_HolderStatus_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_InformationTransferCapabilities_PDU,
      { "InformationTransferCapabilities", "gnm.InformationTransferCapabilities",
        FT_UINT32, BASE_DEC, VALS(gnm_InformationTransferCapabilities_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_ListOfCharacteristicInformation_PDU,
      { "ListOfCharacteristicInformation", "gnm.ListOfCharacteristicInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_NameType_PDU,
      { "NameType", "gnm.NameType",
        FT_UINT32, BASE_DEC, VALS(gnm_NameType_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_NumberOfCircuits_PDU,
      { "NumberOfCircuits", "gnm.NumberOfCircuits",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ObjectList_PDU,
      { "ObjectList", "gnm.ObjectList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_Pointer_PDU,
      { "Pointer", "gnm.Pointer",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_PointerOrNull_PDU,
      { "PointerOrNull", "gnm.PointerOrNull",
        FT_UINT32, BASE_DEC, VALS(gnm_PointerOrNull_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_RelatedObjectInstance_PDU,
      { "RelatedObjectInstance", "gnm.RelatedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(gnm_RelatedObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_Replaceable_PDU,
      { "Replaceable", "gnm.Replaceable",
        FT_UINT32, BASE_DEC, VALS(gnm_Replaceable_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_SequenceOfObjectInstance_PDU,
      { "SequenceOfObjectInstance", "gnm.SequenceOfObjectInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_SerialNumber_PDU,
      { "SerialNumber", "gnm.SerialNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_SignallingCapabilities_PDU,
      { "SignallingCapabilities", "gnm.SignallingCapabilities",
        FT_UINT32, BASE_DEC, VALS(gnm_SignallingCapabilities_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_SignalType_PDU,
      { "SignalType", "gnm.SignalType",
        FT_UINT32, BASE_DEC, VALS(gnm_SignalType_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_SubordinateCircuitPackSoftwareLoad_PDU,
      { "SubordinateCircuitPackSoftwareLoad", "gnm.SubordinateCircuitPackSoftwareLoad",
        FT_UINT32, BASE_DEC, VALS(gnm_SubordinateCircuitPackSoftwareLoad_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_SupportableClientList_PDU,
      { "SupportableClientList", "gnm.SupportableClientList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_SystemTimingSource_PDU,
      { "SystemTimingSource", "gnm.SystemTimingSource",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_TpsInGtpList_PDU,
      { "TpsInGtpList", "gnm.TpsInGtpList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_TransmissionCharacteristics_PDU,
      { "TransmissionCharacteristics", "gnm.TransmissionCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_UserLabel_PDU,
      { "UserLabel", "gnm.UserLabel",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_VendorName_PDU,
      { "VendorName", "gnm.VendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_Version_PDU,
      { "Version", "gnm.Version",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_MappingList_item,
      { "PayloadLevel", "gnm.PayloadLevel",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_objectClass,
      { "objectClass", "gnm.objectClass",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_gnm_characteristicInformation,
      { "characteristicInformation", "gnm.characteristicInformation",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_SupportedTOClasses_item,
      { "SupportedTOClasses item", "gnm.SupportedTOClasses_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_gnm_AcceptableCircuitPackTypeList_item,
      { "AcceptableCircuitPackTypeList item", "gnm.AcceptableCircuitPackTypeList_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_gnm_mpCrossConnection,
      { "mpCrossConnection", "gnm.mpCrossConnection",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_legs,
      { "legs", "gnm.legs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ToTermSpecifier", HFILL }},
    { &hf_gnm_legs_item,
      { "ToTermSpecifier", "gnm.ToTermSpecifier",
        FT_UINT32, BASE_DEC, VALS(gnm_ToTermSpecifier_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_problem,
      { "problem", "gnm.problem",
        FT_UINT32, BASE_DEC, VALS(cmip_ProbableCause_vals), 0,
        "ProbableCause", HFILL }},
    { &hf_gnm_severityAssignedServiceAffecting,
      { "severityAssignedServiceAffecting", "gnm.severityAssignedServiceAffecting",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmSeverityCode_vals), 0,
        "AlarmSeverityCode", HFILL }},
    { &hf_gnm_severityAssignedNonServiceAffecting,
      { "severityAssignedNonServiceAffecting", "gnm.severityAssignedNonServiceAffecting",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmSeverityCode_vals), 0,
        "AlarmSeverityCode", HFILL }},
    { &hf_gnm_severityAssignedServiceIndependent,
      { "severityAssignedServiceIndependent", "gnm.severityAssignedServiceIndependent",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmSeverityCode_vals), 0,
        "AlarmSeverityCode", HFILL }},
    { &hf_gnm_AlarmSeverityAssignmentList_item,
      { "AlarmSeverityAssignment", "gnm.AlarmSeverityAssignment",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_characteristicInfoType,
      { "characteristicInfoType", "gnm.characteristicInfoType",
        FT_OID, BASE_NONE, NULL, 0,
        "CharacteristicInformation", HFILL }},
    { &hf_gnm_bundlingFactor,
      { "bundlingFactor", "gnm.bundlingFactor",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gnm_pointToPoint,
      { "pointToPoint", "gnm.pointToPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_pointToMultipoint,
      { "pointToMultipoint", "gnm.pointToMultipoint",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ConnectInformation_item,
      { "ConnectInformation item", "gnm.ConnectInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_itemType,
      { "itemType", "gnm.itemType",
        FT_UINT32, BASE_DEC, VALS(gnm_T_itemType_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_unidirectional,
      { "unidirectional", "gnm.unidirectional",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectionType_vals), 0,
        "ConnectionType", HFILL }},
    { &hf_gnm_bidirectional,
      { "bidirectional", "gnm.bidirectional",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectionTypeBi_vals), 0,
        "ConnectionTypeBi", HFILL }},
    { &hf_gnm_addleg,
      { "addleg", "gnm.addleg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_administrativeState,
      { "administrativeState", "gnm.administrativeState",
        FT_UINT32, BASE_DEC, VALS(cmip_AdministrativeState_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_namedCrossConnection,
      { "namedCrossConnection", "gnm.namedCrossConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_userLabel,
      { "userLabel", "gnm.userLabel",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_redline,
      { "redline", "gnm.redline",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "Boolean", HFILL }},
    { &hf_gnm_additionalInfo,
      { "additionalInfo", "gnm.additionalInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdditionalInformation", HFILL }},
    { &hf_gnm_none,
      { "none", "gnm.none",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_single,
      { "single", "gnm.single",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_concatenated,
      { "concatenated", "gnm.concatenated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectInstance", HFILL }},
    { &hf_gnm_concatenated_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_explicitPToP,
      { "explicitPToP", "gnm.explicitPToP",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ptoTpPool,
      { "ptoTpPool", "gnm.ptoTpPool",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_explicitPtoMP,
      { "explicitPtoMP", "gnm.explicitPtoMP",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ptoMPools,
      { "ptoMPools", "gnm.ptoMPools",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_notConnected,
      { "notConnected", "gnm.notConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_connected,
      { "connected", "gnm.connected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_multipleConnections,
      { "multipleConnections", "gnm.multipleConnections",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_alarmStatus,
      { "alarmStatus", "gnm.alarmStatus",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmStatus_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_CurrentProblemList_item,
      { "CurrentProblem", "gnm.CurrentProblem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_DisconnectResult_item,
      { "DisconnectResult item", "gnm.DisconnectResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_DisconnectResult_item_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_failed,
      { "failed", "gnm.failed",
        FT_UINT32, BASE_DEC, VALS(gnm_Failed_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_disconnected,
      { "disconnected", "gnm.disconnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_broadcast,
      { "broadcast", "gnm.broadcast",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ObjectInstance", HFILL }},
    { &hf_gnm_broadcast_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_broadcastConcatenated,
      { "broadcastConcatenated", "gnm.broadcastConcatenated",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_broadcastConcatenated_item,
      { "broadcastConcatenated item", "gnm.broadcastConcatenated_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectInstance", HFILL }},
    { &hf_gnm__item_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_fromTp,
      { "fromTp", "gnm.fromTp",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "ExplicitTP", HFILL }},
    { &hf_gnm_toTPs,
      { "toTPs", "gnm.toTPs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ExplicitTP", HFILL }},
    { &hf_gnm_toTPs_item,
      { "ExplicitTP", "gnm.ExplicitTP",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_toTp,
      { "toTp", "gnm.toTp",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "ExplicitTP", HFILL }},
    { &hf_gnm_oneTPorGTP,
      { "oneTPorGTP", "gnm.oneTPorGTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_listofTPs,
      { "listofTPs", "gnm.listofTPs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectInstance", HFILL }},
    { &hf_gnm_listofTPs_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_EquipmentHolderAddress_item,
      { "EquipmentHolderAddress item", "gnm.EquipmentHolderAddress_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_gnm_logicalProblem,
      { "logicalProblem", "gnm.logicalProblem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_resourceProblem,
      { "resourceProblem", "gnm.resourceProblem",
        FT_UINT32, BASE_DEC, VALS(gnm_ResourceProblem_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_holderEmpty,
      { "holderEmpty", "gnm.holderEmpty",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_inTheAcceptableList,
      { "inTheAcceptableList", "gnm.inTheAcceptableList",
        FT_STRING, BASE_NONE, NULL, 0,
        "CircuitPackType", HFILL }},
    { &hf_gnm_notInTheAcceptableList,
      { "notInTheAcceptableList", "gnm.notInTheAcceptableList",
        FT_STRING, BASE_NONE, NULL, 0,
        "CircuitPackType", HFILL }},
    { &hf_gnm_unknownType,
      { "unknownType", "gnm.unknownType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_ListOfCharacteristicInformation_item,
      { "CharacteristicInformation", "gnm.CharacteristicInformation",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_problemCause,
      { "problemCause", "gnm.problemCause",
        FT_UINT32, BASE_DEC, VALS(gnm_ProblemCause_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_incorrectInstances,
      { "incorrectInstances", "gnm.incorrectInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ObjectInstance", HFILL }},
    { &hf_gnm_incorrectInstances_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_MultipleConnections_item,
      { "MultipleConnections item", "gnm.MultipleConnections_item",
        FT_UINT32, BASE_DEC, VALS(gnm_MultipleConnections_item_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_downstreamNotConnected,
      { "downstreamNotConnected", "gnm.downstreamNotConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_downstreamConnected,
      { "downstreamConnected", "gnm.downstreamConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_upstreamNotConnected,
      { "upstreamNotConnected", "gnm.upstreamNotConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_upstreamConnected,
      { "upstreamConnected", "gnm.upstreamConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_redline_01,
      { "redline", "gnm.redline",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_gnm_name,
      { "name", "gnm.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "CrossConnectionName", HFILL }},
    { &hf_gnm_numericName,
      { "numericName", "gnm.numericName",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gnm_pString,
      { "pString", "gnm.pString",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_gnm_ObjectList_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_diverse,
      { "diverse", "gnm.diverse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_downstream,
      { "downstream", "gnm.downstream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalRateAndMappingList", HFILL }},
    { &hf_gnm_upStream,
      { "upStream", "gnm.upStream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalRateAndMappingList", HFILL }},
    { &hf_gnm_uniform,
      { "uniform", "gnm.uniform",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalRateAndMappingList", HFILL }},
    { &hf_gnm_pointer,
      { "pointer", "gnm.pointer",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_null,
      { "null", "gnm.null",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_fromTp_01,
      { "fromTp", "gnm.fromTp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_toTp_01,
      { "toTp", "gnm.toTp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_xCon,
      { "xCon", "gnm.xCon",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_toTps,
      { "toTps", "gnm.toTps",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_toTps_item,
      { "toTps item", "gnm.toTps_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_tp,
      { "tp", "gnm.tp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_xConnection,
      { "xConnection", "gnm.xConnection",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_mpXCon,
      { "mpXCon", "gnm.mpXCon",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_unknown,
      { "unknown", "gnm.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_integerValue,
      { "integerValue", "gnm.integerValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gnm_toTPPools,
      { "toTPPools", "gnm.toTPPools",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_toTpPool,
      { "toTpPool", "gnm.toTpPool",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_notAvailable,
      { "notAvailable", "gnm.notAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_relatedObject,
      { "relatedObject", "gnm.relatedObject",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_SequenceOfObjectInstance_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_SignalRateAndMappingList_item,
      { "SignalRateAndMappingList item", "gnm.SignalRateAndMappingList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_signalRate,
      { "signalRate", "gnm.signalRate",
        FT_UINT32, BASE_DEC, VALS(gnm_SignalRate_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_mappingList,
      { "mappingList", "gnm.mappingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_wavelength,
      { "wavelength", "gnm.wavelength",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_simple,
      { "simple", "gnm.simple",
        FT_OID, BASE_NONE, NULL, 0,
        "CharacteristicInformation", HFILL }},
    { &hf_gnm_bundle,
      { "bundle", "gnm.bundle",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_complex,
      { "complex", "gnm.complex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Bundle", HFILL }},
    { &hf_gnm_complex_item,
      { "Bundle", "gnm.Bundle",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_notApplicable,
      { "notApplicable", "gnm.notApplicable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_softwareInstances,
      { "softwareInstances", "gnm.softwareInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectInstance", HFILL }},
    { &hf_gnm_softwareInstances_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_softwareIdentifiers,
      { "softwareIdentifiers", "gnm.softwareIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_softwareIdentifiers_item,
      { "softwareIdentifiers item", "gnm.softwareIdentifiers_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_gnm_SupportableClientList_item,
      { "ObjectClass", "gnm.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_sourceType,
      { "sourceType", "gnm.sourceType",
        FT_UINT32, BASE_DEC, VALS(gnm_T_sourceType_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_sourceID,
      { "sourceID", "gnm.sourceID",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_primaryTimingSource,
      { "primaryTimingSource", "gnm.primaryTimingSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemTiming", HFILL }},
    { &hf_gnm_secondaryTimingSource,
      { "secondaryTimingSource", "gnm.secondaryTimingSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemTiming", HFILL }},
    { &hf_gnm_toTpOrGTP,
      { "toTpOrGTP", "gnm.toTpOrGTP",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "ExplicitTP", HFILL }},
    { &hf_gnm_toPool,
      { "toPool", "gnm.toPool",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_ToTPPools_item,
      { "ToTPPools item", "gnm.ToTPPools_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gnm_tpPoolId,
      { "tpPoolId", "gnm.tpPoolId",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_gnm_numberOfTPs,
      { "numberOfTPs", "gnm.numberOfTPs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gnm_TpsInGtpList_item,
      { "ObjectInstance", "gnm.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_gnm_TransmissionCharacteristics_satellite,
      { "satellite", "gnm.satellite",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gnm_TransmissionCharacteristics_dCME,
      { "dCME", "gnm.dCME",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gnm_TransmissionCharacteristics_echoControl,
      { "echoControl", "gnm.echoControl",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

/*--- End of included file: packet-gnm-hfarr.c ---*/
#line 82 "../../asn1/gnm/packet-gnm-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-gnm-ettarr.c ---*/
#line 1 "../../asn1/gnm/packet-gnm-ettarr.c"
    &ett_gnm_MappingList,
    &ett_gnm_SignalRate,
    &ett_gnm_SupportedTOClasses,
    &ett_gnm_AcceptableCircuitPackTypeList,
    &ett_gnm_AddLeg,
    &ett_gnm_SET_OF_ToTermSpecifier,
    &ett_gnm_AlarmSeverityAssignment,
    &ett_gnm_AlarmSeverityAssignmentList,
    &ett_gnm_Bundle,
    &ett_gnm_Connected,
    &ett_gnm_ConnectInformation,
    &ett_gnm_ConnectInformation_item,
    &ett_gnm_T_itemType,
    &ett_gnm_ConnectivityPointer,
    &ett_gnm_SEQUENCE_OF_ObjectInstance,
    &ett_gnm_ConnectionType,
    &ett_gnm_ConnectionTypeBi,
    &ett_gnm_CrossConnectionObjectPointer,
    &ett_gnm_CurrentProblem,
    &ett_gnm_CurrentProblemList,
    &ett_gnm_DisconnectResult,
    &ett_gnm_DisconnectResult_item,
    &ett_gnm_DownstreamConnectivityPointer,
    &ett_gnm_SET_OF_ObjectInstance,
    &ett_gnm_T_broadcastConcatenated,
    &ett_gnm_ExplicitPtoMP,
    &ett_gnm_SET_OF_ExplicitTP,
    &ett_gnm_ExplicitPtoP,
    &ett_gnm_ExplicitTP,
    &ett_gnm_EquipmentHolderAddress,
    &ett_gnm_Failed,
    &ett_gnm_HolderStatus,
    &ett_gnm_ListOfCharacteristicInformation,
    &ett_gnm_LogicalProblem,
    &ett_gnm_MultipleConnections,
    &ett_gnm_MultipleConnections_item,
    &ett_gnm_NamedCrossConnection,
    &ett_gnm_NameType,
    &ett_gnm_ObjectList,
    &ett_gnm_PhysicalPortSignalRateAndMappingList,
    &ett_gnm_T_diverse,
    &ett_gnm_PointerOrNull,
    &ett_gnm_PointToPoint,
    &ett_gnm_PointToMultipoint,
    &ett_gnm_T_toTps,
    &ett_gnm_T_toTps_item,
    &ett_gnm_ProblemCause,
    &ett_gnm_PtoMPools,
    &ett_gnm_PtoTPPool,
    &ett_gnm_RelatedObjectInstance,
    &ett_gnm_ResourceProblem,
    &ett_gnm_SequenceOfObjectInstance,
    &ett_gnm_SignalRateAndMappingList,
    &ett_gnm_SignalRateAndMappingList_item,
    &ett_gnm_SignalType,
    &ett_gnm_SEQUENCE_OF_Bundle,
    &ett_gnm_SubordinateCircuitPackSoftwareLoad,
    &ett_gnm_T_softwareIdentifiers,
    &ett_gnm_SupportableClientList,
    &ett_gnm_SystemTiming,
    &ett_gnm_SystemTimingSource,
    &ett_gnm_ToTermSpecifier,
    &ett_gnm_ToTPPools,
    &ett_gnm_ToTPPools_item,
    &ett_gnm_TpsInGtpList,
    &ett_gnm_TransmissionCharacteristics,

/*--- End of included file: packet-gnm-ettarr.c ---*/
#line 87 "../../asn1/gnm/packet-gnm-template.c"
  };

  /* Register protocol */
  proto_gnm = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("gnm", dissect_gnm, proto_gnm);
  /* Register fields and subtrees */
  proto_register_field_array(proto_gnm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_gnm ---------------------------------------*/
void proto_reg_handoff_gnm(void) {

/*--- Included file: packet-gnm-dis-tab.c ---*/
#line 1 "../../asn1/gnm/packet-gnm-dis-tab.c"
  register_ber_oid_dissector("0.0.13.3100.0.7.1", dissect_RelatedObjectInstance_PDU, proto_gnm, "a-TPInstance(1)");
  register_ber_oid_dissector("0.0.13.3100.0.7.2", dissect_ObjectList_PDU, proto_gnm, "affectedObjectList(2)");
  register_ber_oid_dissector("0.0.13.3100.0.7.3", dissect_AlarmSeverityAssignmentList_PDU, proto_gnm, "alarmSeverityAssignmentList(3)");
  register_ber_oid_dissector("0.0.13.3100.0.7.4", dissect_NameType_PDU, proto_gnm, "alarmSeverityAssignmentProfileId(4)");
  register_ber_oid_dissector("0.0.13.3100.0.7.5", dissect_PointerOrNull_PDU, proto_gnm, "alarmSeverityAssignmentProfilePointer(5)");
  register_ber_oid_dissector("0.0.13.3100.0.7.6", dissect_AlarmStatus_PDU, proto_gnm, "alarmStatus(6)");
  register_ber_oid_dissector("0.0.13.3100.0.7.7", dissect_ChannelNumber_PDU, proto_gnm, "channelNumber(7)");
  register_ber_oid_dissector("0.0.13.3100.0.7.8", dissect_CharacteristicInformation_PDU, proto_gnm, "characteristicInformation(8)");
  register_ber_oid_dissector("0.0.13.3100.0.7.11", dissect_Count_PDU, proto_gnm, "connectedTpCount(11)");
  register_ber_oid_dissector("0.0.13.3100.0.7.12", dissect_NameType_PDU, proto_gnm, "connectionId(12)");
  register_ber_oid_dissector("0.0.13.3100.0.7.13", dissect_NameType_PDU, proto_gnm, "cTPId(13)");
  register_ber_oid_dissector("0.0.13.3100.0.7.14", dissect_NameType_PDU, proto_gnm, "crossConnectionId(14)");
  register_ber_oid_dissector("0.0.13.3100.0.7.15", dissect_CrossConnectionName_PDU, proto_gnm, "crossConnectionName(15)");
  register_ber_oid_dissector("0.0.13.3100.0.7.16", dissect_CrossConnectionObjectPointer_PDU, proto_gnm, "crossConnectionObjectPointer(16)");
  register_ber_oid_dissector("0.0.13.3100.0.7.17", dissect_CurrentProblemList_PDU, proto_gnm, "currentProblemList(17)");
  register_ber_oid_dissector("0.0.13.3100.0.7.18", dissect_Directionality_PDU, proto_gnm, "directionality(18)");
  register_ber_oid_dissector("0.0.13.3100.0.7.19", dissect_DownstreamConnectivityPointer_PDU, proto_gnm, "downstreamConnectivityPointer(19)");
  register_ber_oid_dissector("0.0.13.3100.0.7.20", dissect_NameType_PDU, proto_gnm, "equipmentId(20)");
  register_ber_oid_dissector("0.0.13.3100.0.7.21", dissect_ExternalTime_PDU, proto_gnm, "externalTime(21)");
  register_ber_oid_dissector("0.0.13.3100.0.7.22", dissect_NameType_PDU, proto_gnm, "fabricId(22)");
  register_ber_oid_dissector("0.0.13.3100.0.7.23", dissect_PointerOrNull_PDU, proto_gnm, "fromTermination(23)");
  register_ber_oid_dissector("0.0.13.3100.0.7.24", dissect_NameType_PDU, proto_gnm, "gtpId(24)");
  register_ber_oid_dissector("0.0.13.3100.0.7.25", dissect_Count_PDU, proto_gnm, "idleTpCount(25)");
  register_ber_oid_dissector("0.0.13.3100.0.7.26", dissect_ListOfCharacteristicInformation_PDU, proto_gnm, "listOfCharacteristicInfo(26)");
  register_ber_oid_dissector("0.0.13.3100.0.7.27", dissect_Replaceable_PDU, proto_gnm, "locationName(27)");
  register_ber_oid_dissector("0.0.13.3100.0.7.28", dissect_NameType_PDU, proto_gnm, "managedElementId(28)");
  register_ber_oid_dissector("0.0.13.3100.0.7.29", dissect_NameType_PDU, proto_gnm, "mpCrossConnectionId(29)");
  register_ber_oid_dissector("0.0.13.3100.0.7.30", dissect_NameType_PDU, proto_gnm, "networkId(30)");
  register_ber_oid_dissector("0.0.13.3100.0.7.32", dissect_Boolean_PDU, proto_gnm, "protected(32)");
  register_ber_oid_dissector("0.0.13.3100.0.7.33", dissect_Boolean_PDU, proto_gnm, "redline(33)");
  register_ber_oid_dissector("0.0.13.3100.0.7.34", dissect_Replaceable_PDU, proto_gnm, "replaceable(34)");
  register_ber_oid_dissector("0.0.13.3100.0.7.35", dissect_SequenceOfObjectInstance_PDU, proto_gnm, "serverConnectionList(35)");
  register_ber_oid_dissector("0.0.13.3100.0.7.36", dissect_ObjectList_PDU, proto_gnm, "serverTrailList(36)");
  register_ber_oid_dissector("0.0.13.3100.0.7.37", dissect_SignalType_PDU, proto_gnm, "signalType(37)");
  register_ber_oid_dissector("0.0.13.3100.0.7.38", dissect_NameType_PDU, proto_gnm, "softwareId(38)");
  register_ber_oid_dissector("0.0.13.3100.0.7.39", dissect_SupportableClientList_PDU, proto_gnm, "supportableClientList(39)");
  register_ber_oid_dissector("0.0.13.3100.0.7.40", dissect_ObjectList_PDU, proto_gnm, "supportedByObjectList(40)");
  register_ber_oid_dissector("0.0.13.3100.0.7.41", dissect_SystemTimingSource_PDU, proto_gnm, "systemTimingSource(41)");
  register_ber_oid_dissector("0.0.13.3100.0.7.42", dissect_Count_PDU, proto_gnm, "totalTpCount(42)");
  register_ber_oid_dissector("0.0.13.3100.0.7.43", dissect_Pointer_PDU, proto_gnm, "toTermination(43)");
  register_ber_oid_dissector("0.0.13.3100.0.7.44", dissect_NameType_PDU, proto_gnm, "tpPoolId(44)");
  register_ber_oid_dissector("0.0.13.3100.0.7.45", dissect_TpsInGtpList_PDU, proto_gnm, "tpsInGtpList(45)");
  register_ber_oid_dissector("0.0.13.3100.0.7.47", dissect_NameType_PDU, proto_gnm, "trailId(47)");
  register_ber_oid_dissector("0.0.13.3100.0.7.48", dissect_NameType_PDU, proto_gnm, "tTPId(48)");
  register_ber_oid_dissector("0.0.13.3100.0.7.49", dissect_ConnectivityPointer_PDU, proto_gnm, "upstreamConnectivityPointer(49)");
  register_ber_oid_dissector("0.0.13.3100.0.7.50", dissect_UserLabel_PDU, proto_gnm, "userLabel(50)");
  register_ber_oid_dissector("0.0.13.3100.0.7.51", dissect_VendorName_PDU, proto_gnm, "vendorName(51)");
  register_ber_oid_dissector("0.0.13.3100.0.7.52", dissect_Version_PDU, proto_gnm, "version(52)");
  register_ber_oid_dissector("0.0.13.3100.0.7.53", dissect_ObjectList_PDU, proto_gnm, "clientConnectionList(53)");
  register_ber_oid_dissector("0.0.13.3100.0.7.54", dissect_CircuitPackType_PDU, proto_gnm, "circuitPackType(54)");
  register_ber_oid_dissector("0.0.13.3100.0.7.55", dissect_RelatedObjectInstance_PDU, proto_gnm, "z-TPInstance(55)");
  register_ber_oid_dissector("0.0.13.3100.0.7.56", dissect_EquipmentHolderAddress_PDU, proto_gnm, "equipmentHolderAddress(56)");
  register_ber_oid_dissector("0.0.13.3100.0.7.57", dissect_EquipmentHolderType_PDU, proto_gnm, "equipmentHolderType(57)");
  register_ber_oid_dissector("0.0.13.3100.0.7.58", dissect_AcceptableCircuitPackTypeList_PDU, proto_gnm, "acceptableCircuitPackTypeList(58)");
  register_ber_oid_dissector("0.0.13.3100.0.7.59", dissect_HolderStatus_PDU, proto_gnm, "holderStatus(59)");
  register_ber_oid_dissector("0.0.13.3100.0.7.60", dissect_SubordinateCircuitPackSoftwareLoad_PDU, proto_gnm, "subordinateCircuitPackSoftwareLoad(60)");
  register_ber_oid_dissector("0.0.13.3100.0.7.61", dissect_NameType_PDU, proto_gnm, "circuitEndPointSubgroupId(61)");
  register_ber_oid_dissector("0.0.13.3100.0.7.62", dissect_NumberOfCircuits_PDU, proto_gnm, "numberOfCircuits(62)");
  register_ber_oid_dissector("0.0.13.3100.0.7.63", dissect_UserLabel_PDU, proto_gnm, "labelOfFarEndExchange(63)");
  register_ber_oid_dissector("0.0.13.3100.0.7.64", dissect_SignallingCapabilities_PDU, proto_gnm, "signallingCapabilities(64)");
  register_ber_oid_dissector("0.0.13.3100.0.7.65", dissect_InformationTransferCapabilities_PDU, proto_gnm, "informationTransferCapabilities(65)");
  register_ber_oid_dissector("0.0.13.3100.0.7.66", dissect_CircuitDirectionality_PDU, proto_gnm, "circuitDirectionality(66)");
  register_ber_oid_dissector("0.0.13.3100.0.7.67", dissect_TransmissionCharacteristics_PDU, proto_gnm, "transmissionCharacteristics(67)");
  register_ber_oid_dissector("0.0.13.3100.0.7.68", dissect_NameType_PDU, proto_gnm, "managedElementComplexId(68)");
  register_ber_oid_dissector("0.0.13.3100.0.7.69", dissect_SerialNumber_PDU, proto_gnm, "serialNumber(69)");
  register_ber_oid_dissector("0.0.13.3100.0.9.4", dissect_ConnectInformation_PDU, proto_gnm, "connect(4)");
  register_ber_oid_dissector("0.0.13.3100.0.9.5", dissect_DisconnectResult_PDU, proto_gnm, "disconnect(5)");
  register_ber_oid_dissector("2.9.2.12.7.7", dissect_SupportedTOClasses_PDU, proto_gnm, "supportedTOClasses(7)");


/*--- End of included file: packet-gnm-dis-tab.c ---*/
#line 102 "../../asn1/gnm/packet-gnm-template.c"
	/* Wrapper to call CMIP */
	register_ber_oid_dissector("0.0.13.3100.0.7.9", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientConnection(9)");
	register_ber_oid_dissector("0.0.13.3100.0.7.10", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientTrail(10)");
	register_ber_oid_dissector("0.0.13.3100.0.7.31", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");
	register_ber_oid_dissector("0.0.13.3100.0.7.46", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");

}
