/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-gnm.c                                                             */
/* ../../tools/asn2eth.py -X -b -e -p gnm -c gnm.cnf -s packet-gnm-template GNM.asn */

/* Input file: packet-gnm-template.c */

/* packet-gnm.c
 * Routines for GENERIC NETWORK INFORMATION MODEL Data dissection
 *
 * Copyright 2005 , Anders Broman <anders.broman [AT] ericsson.com>
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>
#include "packet-cmip.h"
#include "packet-ber.h"
#include "packet-gnm.h"

#define PNAME  "ITU M.3100 Generic Network Information Model"
#define PSNAME "GNM"
#define PFNAME "gnm"

/* Initialize the protocol and registered fields */
int proto_gnm = -1;

static int hf_gnm_AdministrativeState = -1;

/*--- Included file: packet-gnm-hf.c ---*/

static int hf_gnm_AdministrativeState_PDU = -1;   /* AdministrativeState */
static int hf_gnm_ControlStatus_PDU = -1;         /* ControlStatus */
static int hf_gnm_Packages_PDU = -1;              /* Packages */
static int hf_gnm_SupportedTOClasses_PDU = -1;    /* SupportedTOClasses */
static int hf_gnm_AcceptableCircuitPackTypeList_PDU = -1;  /* AcceptableCircuitPackTypeList */
static int hf_gnm_AlarmSeverityAssignmentList_PDU = -1;  /* AlarmSeverityAssignmentList */
static int hf_gnm_AlarmStatus_PDU = -1;           /* AlarmStatus */
static int hf_gnm_Boolean_PDU = -1;               /* Boolean */
static int hf_gnm_ChannelNumber_PDU = -1;         /* ChannelNumber */
static int hf_gnm_CharacteristicInformation_PDU = -1;  /* CharacteristicInformation */
static int hf_gnm_CircuitDirectionality_PDU = -1;  /* CircuitDirectionality */
static int hf_gnm_CircuitPackType_PDU = -1;       /* CircuitPackType */
static int hf_gnm_ConnectivityPointer_PDU = -1;   /* ConnectivityPointer */
static int hf_gnm_Count_PDU = -1;                 /* Count */
static int hf_gnm_CrossConnectionName_PDU = -1;   /* CrossConnectionName */
static int hf_gnm_CrossConnectionObjectPointer_PDU = -1;  /* CrossConnectionObjectPointer */
static int hf_gnm_CurrentProblemList_PDU = -1;    /* CurrentProblemList */
static int hf_gnm_Directionality_PDU = -1;        /* Directionality */
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
static int hf_gnm_globalValue = -1;               /* OBJECT_IDENTIFIER */
static int hf_gnm_localValue = -1;                /* INTEGER */
static int hf_gnm_AvailabilityStatus_item = -1;   /* AvailabilityStatus_item */
static int hf_gnm_AttributeList_item = -1;        /* Attribute */
static int hf_gnm_AdditionalInformation_item = -1;  /* ManagementExtension */
static int hf_gnm_ControlStatus_item = -1;        /* ControlStatus_item */
static int hf_gnm_identifier = -1;                /* OBJECT_IDENTIFIER */
static int hf_gnm_significance = -1;              /* BOOLEAN */
static int hf_gnm_information = -1;               /* T_information */
static int hf_gnm_MappingList_item = -1;          /* PayloadLevel */
static int hf_gnm_Packages_item = -1;             /* OBJECT_IDENTIFIER */
static int hf_gnm_objectClass = -1;               /* OBJECT_IDENTIFIER */
static int hf_gnm_characteristicInformation = -1;  /* CharacteristicInformation */
static int hf_gnm_SupportedTOClasses_item = -1;   /* OBJECT_IDENTIFIER */
static int hf_gnm_AcceptableCircuitPackTypeList_item = -1;  /* PrintableString */
static int hf_gnm_gtp = -1;                       /* ObjectInstance */
static int hf_gnm_tpsAdded = -1;                  /* SEQUENCE_OF_ObjectInstance */
static int hf_gnm_tpsAdded_item = -1;             /* ObjectInstance */
static int hf_gnm_mpCrossConnection = -1;         /* ObjectInstance */
static int hf_gnm_legs = -1;                      /* SET_OF_ToTermSpecifier */
static int hf_gnm_legs_item = -1;                 /* ToTermSpecifier */
static int hf_gnm_AddTpsToGtpInformation_item = -1;  /* AddTpsToGtpInformation_item */
static int hf_gnm_tpsAdded1 = -1;                 /* SEQUENCE_OF_TerminationPointInformation */
static int hf_gnm_tpsAdded_item1 = -1;            /* TerminationPointInformation */
static int hf_gnm_AddTpsToGtpResult_item = -1;    /* AddTpsToGtpResult_item */
static int hf_gnm_failed = -1;                    /* Failed */
static int hf_gnm_addedTps = -1;                  /* AddedTps */
static int hf_gnm_AddTpsToTpPoolInformation_item = -1;  /* AddTpsToTpPoolInformation_item */
static int hf_gnm_tps = -1;                       /* SET_OF_TerminationPointInformation */
static int hf_gnm_tps_item = -1;                  /* TerminationPointInformation */
static int hf_gnm_toTpPool = -1;                  /* ObjectInstance */
static int hf_gnm_AddTpsToTpPoolResult_item = -1;  /* AddTpsToTpPoolResult_item */
static int hf_gnm_tpsAddedToTpPool = -1;          /* TpsAddedToTpPool */
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
static int hf_gnm_ConnectResult_item = -1;        /* ConnectResult_item */
static int hf_gnm_connected = -1;                 /* Connected */
static int hf_gnm_explicitPToP = -1;              /* ExplicitPtoP */
static int hf_gnm_ptoTpPool = -1;                 /* PtoTPPool */
static int hf_gnm_explicitPtoMP = -1;             /* ExplicitPtoMP */
static int hf_gnm_ptoMPools = -1;                 /* PtoMPools */
static int hf_gnm_notConnected = -1;              /* ObjectInstance */
static int hf_gnm_connected1 = -1;                /* ObjectInstance */
static int hf_gnm_multipleConnections = -1;       /* MultipleConnections */
static int hf_gnm_alarmStatus = -1;               /* AlarmStatus */
static int hf_gnm_CurrentProblemList_item = -1;   /* CurrentProblem */
static int hf_gnm_DisconnectInformation_item = -1;  /* ObjectInstance */
static int hf_gnm_DisconnectResult_item = -1;     /* DisconnectResult_item */
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
static int hf_gnm_GeneralError_item = -1;         /* GeneralError_item */
static int hf_gnm_cause = -1;                     /* GeneralErrorCause */
static int hf_gnm_details = -1;                   /* GraphicString */
static int hf_gnm_relatedObjects = -1;            /* SET_OF_ObjectInstance */
static int hf_gnm_relatedObjects_item = -1;       /* ObjectInstance */
static int hf_gnm_attributeList = -1;             /* AttributeList */
static int hf_gnm_holderEmpty = -1;               /* NULL */
static int hf_gnm_inTheAcceptableList = -1;       /* CircuitPackType */
static int hf_gnm_notInTheAcceptableList = -1;    /* CircuitPackType */
static int hf_gnm_unknownType = -1;               /* NULL */
static int hf_gnm_connection = -1;                /* ObjectInstance */
static int hf_gnm_unchangedTP = -1;               /* ObjectInstance */
static int hf_gnm_newTP = -1;                     /* ObjectInstance */
static int hf_gnm_pass = -1;                      /* Connected */
static int hf_gnm_ListOfCharacteristicInformation_item = -1;  /* CharacteristicInformation */
static int hf_gnm_ListOfTPs_item = -1;            /* ObjectInstance */
static int hf_gnm_problemCause = -1;              /* ProblemCause */
static int hf_gnm_incorrectInstances = -1;        /* SET_OF_ObjectInstance */
static int hf_gnm_incorrectInstances_item = -1;   /* ObjectInstance */
static int hf_gnm_MultipleConnections_item = -1;  /* MultipleConnections_item */
static int hf_gnm_downstreamNotConnected = -1;    /* ObjectInstance */
static int hf_gnm_downstreamConnected = -1;       /* ObjectInstance */
static int hf_gnm_upstreamNotConnected = -1;      /* ObjectInstance */
static int hf_gnm_upstreamConnected = -1;         /* ObjectInstance */
static int hf_gnm_redline1 = -1;                  /* BOOLEAN */
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
static int hf_gnm_fromTp1 = -1;                   /* ObjectInstance */
static int hf_gnm_toTp1 = -1;                     /* ObjectInstance */
static int hf_gnm_xCon = -1;                      /* ObjectInstance */
static int hf_gnm_toTps = -1;                     /* T_toTps */
static int hf_gnm_toTps_item = -1;                /* T_toTps_item */
static int hf_gnm_tp = -1;                        /* ObjectInstance */
static int hf_gnm_xConnection = -1;               /* ObjectInstance */
static int hf_gnm_mpXCon = -1;                    /* ObjectInstance */
static int hf_gnm_unknown = -1;                   /* NULL */
static int hf_gnm_integerValue = -1;              /* INTEGER */
static int hf_gnm_toTPPools = -1;                 /* ToTPPools */
static int hf_gnm_notAvailable = -1;              /* NULL */
static int hf_gnm_relatedObject = -1;             /* ObjectInstance */
static int hf_gnm_RemoveTpsFromGtpInformation_item = -1;  /* RemoveTpsFromGtpInformation_item */
static int hf_gnm_fromGtp = -1;                   /* ObjectInstance */
static int hf_gnm_tps1 = -1;                      /* SET_OF_ObjectInstance */
static int hf_gnm_tps_item1 = -1;                 /* ObjectInstance */
static int hf_gnm_RemoveTpsFromGtpResult_item = -1;  /* RemoveTpsFromGtpResult_item */
static int hf_gnm_removed = -1;                   /* RemoveTpsResultInformation */
static int hf_gnm_RemoveTpsFromTpPoolInformation_item = -1;  /* RemoveTpsFromTpPoolInformation_item */
static int hf_gnm_fromTpPool = -1;                /* ObjectInstance */
static int hf_gnm_RemoveTpsFromTpPoolResult_item = -1;  /* RemoveTpsFromTpPoolResult_item */
static int hf_gnm_deletedTpPoolOrGTP = -1;        /* ObjectInstance */
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
static int hf_gnm_SwitchOverInformation_item = -1;  /* IndividualSwitchOver */
static int hf_gnm_SwitchOverResult_item = -1;     /* IndividualResult */
static int hf_gnm_tPOrGTP = -1;                   /* ObjectInstance */
static int hf_gnm_sourceTP = -1;                  /* ObjectInstance */
static int hf_gnm_sinkTP = -1;                    /* ObjectInstance */
static int hf_gnm_toTpOrGTP = -1;                 /* ExplicitTP */
static int hf_gnm_toPool = -1;                    /* ObjectInstance */
static int hf_gnm_ToTPPools_item = -1;            /* ToTPPools_item */
static int hf_gnm_tpPoolId = -1;                  /* ObjectInstance */
static int hf_gnm_numberOfTPs = -1;               /* INTEGER */
static int hf_gnm_tpPool = -1;                    /* ObjectInstance */
static int hf_gnm_TpsInGtpList_item = -1;         /* ObjectInstance */
/* named bits */
static int hf_gnm_TransmissionCharacteristics_satellite = -1;
static int hf_gnm_TransmissionCharacteristics_dCME = -1;
static int hf_gnm_TransmissionCharacteristics_echoControl = -1;

/*--- End of included file: packet-gnm-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-gnm-ett.c ---*/

static gint ett_gnm_ProbableCause = -1;
static gint ett_gnm_AvailabilityStatus = -1;
static gint ett_gnm_AttributeList = -1;
static gint ett_gnm_AdditionalInformation = -1;
static gint ett_gnm_ControlStatus = -1;
static gint ett_gnm_ManagementExtension = -1;
static gint ett_gnm_MappingList = -1;
static gint ett_gnm_Packages = -1;
static gint ett_gnm_SignalRate = -1;
static gint ett_gnm_SupportedTOClasses = -1;
static gint ett_gnm_AcceptableCircuitPackTypeList = -1;
static gint ett_gnm_AddedTps = -1;
static gint ett_gnm_SEQUENCE_OF_ObjectInstance = -1;
static gint ett_gnm_AddLeg = -1;
static gint ett_gnm_SET_OF_ToTermSpecifier = -1;
static gint ett_gnm_AddTpsToGtpInformation = -1;
static gint ett_gnm_AddTpsToGtpInformation_item = -1;
static gint ett_gnm_SEQUENCE_OF_TerminationPointInformation = -1;
static gint ett_gnm_AddTpsToGtpResult = -1;
static gint ett_gnm_AddTpsToGtpResult_item = -1;
static gint ett_gnm_AddTpsToTpPoolInformation = -1;
static gint ett_gnm_AddTpsToTpPoolInformation_item = -1;
static gint ett_gnm_SET_OF_TerminationPointInformation = -1;
static gint ett_gnm_AddTpsToTpPoolResult = -1;
static gint ett_gnm_AddTpsToTpPoolResult_item = -1;
static gint ett_gnm_AlarmSeverityAssignment = -1;
static gint ett_gnm_AlarmSeverityAssignmentList = -1;
static gint ett_gnm_Bundle = -1;
static gint ett_gnm_Connected = -1;
static gint ett_gnm_ConnectInformation = -1;
static gint ett_gnm_ConnectInformation_item = -1;
static gint ett_gnm_T_itemType = -1;
static gint ett_gnm_ConnectivityPointer = -1;
static gint ett_gnm_ConnectResult = -1;
static gint ett_gnm_ConnectResult_item = -1;
static gint ett_gnm_ConnectionType = -1;
static gint ett_gnm_ConnectionTypeBi = -1;
static gint ett_gnm_CrossConnectionObjectPointer = -1;
static gint ett_gnm_CurrentProblem = -1;
static gint ett_gnm_CurrentProblemList = -1;
static gint ett_gnm_DisconnectInformation = -1;
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
static gint ett_gnm_GeneralError = -1;
static gint ett_gnm_GeneralError_item = -1;
static gint ett_gnm_GeneralErrorCause = -1;
static gint ett_gnm_HolderStatus = -1;
static gint ett_gnm_IndividualSwitchOver = -1;
static gint ett_gnm_IndividualResult = -1;
static gint ett_gnm_ListOfCharacteristicInformation = -1;
static gint ett_gnm_ListOfTPs = -1;
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
static gint ett_gnm_RemoveTpsFromGtpInformation = -1;
static gint ett_gnm_RemoveTpsFromGtpInformation_item = -1;
static gint ett_gnm_RemoveTpsFromGtpResult = -1;
static gint ett_gnm_RemoveTpsFromGtpResult_item = -1;
static gint ett_gnm_RemoveTpsFromTpPoolInformation = -1;
static gint ett_gnm_RemoveTpsFromTpPoolInformation_item = -1;
static gint ett_gnm_RemoveTpsFromTpPoolResult = -1;
static gint ett_gnm_RemoveTpsFromTpPoolResult_item = -1;
static gint ett_gnm_RemoveTpsResultInformation = -1;
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
static gint ett_gnm_SwitchOverInformation = -1;
static gint ett_gnm_SwitchOverResult = -1;
static gint ett_gnm_TerminationPointInformation = -1;
static gint ett_gnm_ToTermSpecifier = -1;
static gint ett_gnm_ToTPPools = -1;
static gint ett_gnm_ToTPPools_item = -1;
static gint ett_gnm_TpsAddedToTpPool = -1;
static gint ett_gnm_TpsInGtpList = -1;
static gint ett_gnm_TransmissionCharacteristics = -1;

/*--- End of included file: packet-gnm-ett.c ---*/



/*--- Included file: packet-gnm-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_AttributeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(FALSE, tvb, offset, pinfo, tree, hf_gnm_AttributeList_item);
}
static int dissect_gtp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_gtp);
}
static int dissect_tpsAdded_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tpsAdded_item);
}
static int dissect_mpCrossConnection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_mpCrossConnection);
}
static int dissect_toTpPool(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTpPool);
}
static int dissect_single(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_single);
}
static int dissect_concatenated_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_concatenated_item);
}
static int dissect_notConnected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_notConnected);
}
static int dissect_connected1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_connected1);
}
static int dissect_DisconnectInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_DisconnectInformation_item);
}
static int dissect_disconnected(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_disconnected);
}
static int dissect_broadcast_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_broadcast_item);
}
static int dissect__item_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm__item_item);
}
static int dissect_oneTPorGTP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_oneTPorGTP);
}
static int dissect_listofTPs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_listofTPs_item);
}
static int dissect_relatedObjects_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_relatedObjects_item);
}
static int dissect_connection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_connection);
}
static int dissect_unchangedTP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_unchangedTP);
}
static int dissect_newTP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_newTP);
}
static int dissect_ListOfTPs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_ListOfTPs_item);
}
static int dissect_incorrectInstances_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_incorrectInstances_item);
}
static int dissect_downstreamNotConnected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_downstreamNotConnected);
}
static int dissect_downstreamConnected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_downstreamConnected);
}
static int dissect_upstreamNotConnected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_upstreamNotConnected);
}
static int dissect_upstreamConnected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_upstreamConnected);
}
static int dissect_ObjectList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_ObjectList_item);
}
static int dissect_pointer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_pointer);
}
static int dissect_fromTp1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_fromTp1);
}
static int dissect_toTp1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTp1);
}
static int dissect_xCon(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_xCon);
}
static int dissect_tp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tp);
}
static int dissect_xConnection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_xConnection);
}
static int dissect_mpXCon(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_mpXCon);
}
static int dissect_relatedObject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_relatedObject);
}
static int dissect_fromGtp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_fromGtp);
}
static int dissect_tps_item1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tps_item1);
}
static int dissect_fromTpPool(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_fromTpPool);
}
static int dissect_deletedTpPoolOrGTP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_deletedTpPoolOrGTP);
}
static int dissect_SequenceOfObjectInstance_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_SequenceOfObjectInstance_item);
}
static int dissect_softwareInstances_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_softwareInstances_item);
}
static int dissect_SupportableClientList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectClass(FALSE, tvb, offset, pinfo, tree, hf_gnm_SupportableClientList_item);
}
static int dissect_sourceID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_sourceID);
}
static int dissect_tPOrGTP_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_tPOrGTP);
}
static int dissect_sourceTP_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_sourceTP);
}
static int dissect_sinkTP_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_sinkTP);
}
static int dissect_toPool_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_toPool);
}
static int dissect_tpPoolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tpPoolId);
}
static int dissect_tpPool(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tpPool);
}
static int dissect_TpsInGtpList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_TpsInGtpList_item);
}



static int
dissect_gnm_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_globalValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gnm_globalValue);
}
static int dissect_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gnm_identifier);
}
static int dissect_Packages_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gnm_Packages_item);
}
static int dissect_objectClass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_gnm_objectClass);
}
static int dissect_SupportedTOClasses_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gnm_SupportedTOClasses_item);
}



static int
dissect_gnm_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_localValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_gnm_localValue);
}
static int dissect_bundlingFactor(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_gnm_bundlingFactor);
}
static int dissect_numericName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_gnm_numericName);
}
static int dissect_integerValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_gnm_integerValue);
}
static int dissect_numberOfTPs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_gnm_numberOfTPs);
}


static const value_string gnm_ProbableCause_vals[] = {
  {   0, "globalValue" },
  {   1, "localValue" },
  { 0, NULL }
};

static const ber_choice_t ProbableCause_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ProbableCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ProbableCause_choice, hf_index, ett_gnm_ProbableCause,
                                 NULL);

  return offset;
}
static int dissect_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ProbableCause(FALSE, tvb, offset, pinfo, tree, hf_gnm_problem);
}
static int dissect_problem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ProbableCause(TRUE, tvb, offset, pinfo, tree, hf_gnm_problem);
}


static const value_string gnm_AdministrativeState_vals[] = {
  {   0, "locked" },
  {   1, "unlocked" },
  {   2, "shuttingDown" },
  { 0, NULL }
};


static int
dissect_gnm_AdministrativeState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_administrativeState(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AdministrativeState(FALSE, tvb, offset, pinfo, tree, hf_gnm_administrativeState);
}


static const value_string gnm_AvailabilityStatus_item_vals[] = {
  {   0, "inTest" },
  {   1, "failed" },
  {   2, "powerOff" },
  {   3, "offLine" },
  {   4, "offDuty" },
  {   5, "dependency" },
  {   6, "degraded" },
  {   7, "notInstalled" },
  {   8, "logFull" },
  { 0, NULL }
};


static int
dissect_gnm_AvailabilityStatus_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_AvailabilityStatus_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AvailabilityStatus_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_AvailabilityStatus_item);
}


static const ber_sequence_t AvailabilityStatus_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_AvailabilityStatus_item },
};

static int
dissect_gnm_AvailabilityStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 AvailabilityStatus_set_of, hf_index, ett_gnm_AvailabilityStatus);

  return offset;
}


static const ber_sequence_t AttributeList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AttributeList_item },
};

static int
dissect_gnm_AttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 AttributeList_set_of, hf_index, ett_gnm_AttributeList);

  return offset;
}
static int dissect_attributeList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AttributeList(TRUE, tvb, offset, pinfo, tree, hf_gnm_attributeList);
}



static int
dissect_gnm_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_significance_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_gnm_significance);
}
static int dissect_redline1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_gnm_redline1);
}



static int
dissect_gnm_T_information(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
/* FIX ME */


  return offset;
}
static int dissect_information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_information(TRUE, tvb, offset, pinfo, tree, hf_gnm_information);
}


static const ber_sequence_t ManagementExtension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_identifier },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_significance_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_information_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_ManagementExtension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ManagementExtension_sequence, hf_index, ett_gnm_ManagementExtension);

  return offset;
}
static int dissect_AdditionalInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ManagementExtension(FALSE, tvb, offset, pinfo, tree, hf_gnm_AdditionalInformation_item);
}


static const ber_sequence_t AdditionalInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AdditionalInformation_item },
};

static int
dissect_gnm_AdditionalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 AdditionalInformation_set_of, hf_index, ett_gnm_AdditionalInformation);

  return offset;
}
static int dissect_additionalInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AdditionalInformation(TRUE, tvb, offset, pinfo, tree, hf_gnm_additionalInfo);
}


static const value_string gnm_ControlStatus_item_vals[] = {
  {   0, "subjectToTest" },
  {   1, "partOfServicesLocked" },
  {   2, "reservedForTest" },
  {   3, "suspended" },
  { 0, NULL }
};


static int
dissect_gnm_ControlStatus_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ControlStatus_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ControlStatus_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_ControlStatus_item);
}


static const ber_sequence_t ControlStatus_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ControlStatus_item },
};

static int
dissect_gnm_ControlStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ControlStatus_set_of, hf_index, ett_gnm_ControlStatus);

  return offset;
}



static int
dissect_gnm_CharacteristicInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_characteristicInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CharacteristicInformation(TRUE, tvb, offset, pinfo, tree, hf_gnm_characteristicInformation);
}
static int dissect_characteristicInfoType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CharacteristicInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_characteristicInfoType);
}
static int dissect_ListOfCharacteristicInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CharacteristicInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_ListOfCharacteristicInformation_item);
}
static int dissect_simple(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CharacteristicInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_simple);
}



static int
dissect_gnm_PayloadLevel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gnm_CharacteristicInformation(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_MappingList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PayloadLevel(FALSE, tvb, offset, pinfo, tree, hf_gnm_MappingList_item);
}


static const ber_sequence_t MappingList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_MappingList_item },
};

static int
dissect_gnm_MappingList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MappingList_sequence_of, hf_index, ett_gnm_MappingList);

  return offset;
}
static int dissect_mappingList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_MappingList(FALSE, tvb, offset, pinfo, tree, hf_gnm_mappingList);
}


static const ber_sequence_t Packages_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_Packages_item },
};

static int
dissect_gnm_Packages(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 Packages_set_of, hf_index, ett_gnm_Packages);

  return offset;
}


static const value_string gnm_SignalRate_vals[] = {
  {   0, "objectClass" },
  {   1, "characteristicInformation" },
  { 0, NULL }
};

static const ber_choice_t SignalRate_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_objectClass_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_characteristicInformation_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_SignalRate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SignalRate_choice, hf_index, ett_gnm_SignalRate,
                                 NULL);

  return offset;
}
static int dissect_signalRate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SignalRate(FALSE, tvb, offset, pinfo, tree, hf_gnm_signalRate);
}


static const ber_sequence_t SupportedTOClasses_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_SupportedTOClasses_item },
};

static int
dissect_gnm_SupportedTOClasses(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SupportedTOClasses_set_of, hf_index, ett_gnm_SupportedTOClasses);

  return offset;
}



static int
dissect_gnm_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_AcceptableCircuitPackTypeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_gnm_AcceptableCircuitPackTypeList_item);
}
static int dissect_EquipmentHolderAddress_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_gnm_EquipmentHolderAddress_item);
}
static int dissect_softwareIdentifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_gnm_softwareIdentifiers_item);
}


static const ber_sequence_t AcceptableCircuitPackTypeList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_AcceptableCircuitPackTypeList_item },
};

static int
dissect_gnm_AcceptableCircuitPackTypeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 AcceptableCircuitPackTypeList_set_of, hf_index, ett_gnm_AcceptableCircuitPackTypeList);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ObjectInstance_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_tpsAdded_item },
};

static int
dissect_gnm_SEQUENCE_OF_ObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ObjectInstance_sequence_of, hf_index, ett_gnm_SEQUENCE_OF_ObjectInstance);

  return offset;
}
static int dissect_tpsAdded(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tpsAdded);
}
static int dissect_concatenated(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_concatenated);
}
static int dissect_broadcastConcatenated_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_broadcastConcatenated_item);
}
static int dissect_listofTPs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_listofTPs);
}
static int dissect_softwareInstances_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_softwareInstances);
}


static const ber_sequence_t AddedTps_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gtp },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tpsAdded },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_AddedTps(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddedTps_sequence, hf_index, ett_gnm_AddedTps);

  return offset;
}
static int dissect_addedTps_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AddedTps(TRUE, tvb, offset, pinfo, tree, hf_gnm_addedTps);
}


static const value_string gnm_ExplicitTP_vals[] = {
  {   0, "oneTPorGTP" },
  {   1, "listofTPs" },
  { 0, NULL }
};

static const ber_choice_t ExplicitTP_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_oneTPorGTP },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listofTPs },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ExplicitTP(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ExplicitTP_choice, hf_index, ett_gnm_ExplicitTP,
                                 NULL);

  return offset;
}
static int dissect_fromTp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ExplicitTP(FALSE, tvb, offset, pinfo, tree, hf_gnm_fromTp);
}
static int dissect_toTPs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ExplicitTP(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTPs_item);
}
static int dissect_toTp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ExplicitTP(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTp);
}
static int dissect_toTpOrGTP_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ExplicitTP(TRUE, tvb, offset, pinfo, tree, hf_gnm_toTpOrGTP);
}


static const value_string gnm_ToTermSpecifier_vals[] = {
  {   0, "toTpOrGTP" },
  {   1, "toPool" },
  { 0, NULL }
};

static const ber_choice_t ToTermSpecifier_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_toTpOrGTP_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_toPool_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ToTermSpecifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ToTermSpecifier_choice, hf_index, ett_gnm_ToTermSpecifier,
                                 NULL);

  return offset;
}
static int dissect_legs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ToTermSpecifier(FALSE, tvb, offset, pinfo, tree, hf_gnm_legs_item);
}


static const ber_sequence_t SET_OF_ToTermSpecifier_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_legs_item },
};

static int
dissect_gnm_SET_OF_ToTermSpecifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ToTermSpecifier_set_of, hf_index, ett_gnm_SET_OF_ToTermSpecifier);

  return offset;
}
static int dissect_legs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_ToTermSpecifier(FALSE, tvb, offset, pinfo, tree, hf_gnm_legs);
}


static const ber_sequence_t AddLeg_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_mpCrossConnection },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_legs },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_AddLeg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddLeg_sequence, hf_index, ett_gnm_AddLeg);

  return offset;
}
static int dissect_addleg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AddLeg(TRUE, tvb, offset, pinfo, tree, hf_gnm_addleg);
}


static const value_string gnm_TerminationPointInformation_vals[] = {
  {   0, "tPOrGTP" },
  {   1, "sourceTP" },
  {   2, "sinkTP" },
  { 0, NULL }
};

static const ber_choice_t TerminationPointInformation_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_tPOrGTP_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_sourceTP_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_sinkTP_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_TerminationPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TerminationPointInformation_choice, hf_index, ett_gnm_TerminationPointInformation,
                                 NULL);

  return offset;
}
static int dissect_tpsAdded_item1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_TerminationPointInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_tpsAdded_item1);
}
static int dissect_tps_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_TerminationPointInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_tps_item);
}


static const ber_sequence_t SEQUENCE_OF_TerminationPointInformation_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tpsAdded_item1 },
};

static int
dissect_gnm_SEQUENCE_OF_TerminationPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_TerminationPointInformation_sequence_of, hf_index, ett_gnm_SEQUENCE_OF_TerminationPointInformation);

  return offset;
}
static int dissect_tpsAdded1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_TerminationPointInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_tpsAdded1);
}


static const ber_sequence_t AddTpsToGtpInformation_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tpsAdded1 },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gtp },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_AddTpsToGtpInformation_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddTpsToGtpInformation_item_sequence, hf_index, ett_gnm_AddTpsToGtpInformation_item);

  return offset;
}
static int dissect_AddTpsToGtpInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AddTpsToGtpInformation_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_AddTpsToGtpInformation_item);
}


static const ber_sequence_t AddTpsToGtpInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AddTpsToGtpInformation_item },
};

static int
dissect_gnm_AddTpsToGtpInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AddTpsToGtpInformation_sequence_of, hf_index, ett_gnm_AddTpsToGtpInformation);

  return offset;
}



static int
dissect_gnm_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_none(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(FALSE, tvb, offset, pinfo, tree, hf_gnm_none);
}
static int dissect_holderEmpty_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(TRUE, tvb, offset, pinfo, tree, hf_gnm_holderEmpty);
}
static int dissect_unknownType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(TRUE, tvb, offset, pinfo, tree, hf_gnm_unknownType);
}
static int dissect_null(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(FALSE, tvb, offset, pinfo, tree, hf_gnm_null);
}
static int dissect_unknown(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(FALSE, tvb, offset, pinfo, tree, hf_gnm_unknown);
}
static int dissect_notAvailable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(FALSE, tvb, offset, pinfo, tree, hf_gnm_notAvailable);
}
static int dissect_notApplicable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NULL(FALSE, tvb, offset, pinfo, tree, hf_gnm_notApplicable);
}


static const value_string gnm_ProblemCause_vals[] = {
  {   0, "unknown" },
  {   1, "integerValue" },
  { 0, NULL }
};

static const ber_choice_t ProblemCause_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_unknown },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_integerValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ProblemCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ProblemCause_choice, hf_index, ett_gnm_ProblemCause,
                                 NULL);

  return offset;
}
static int dissect_problemCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ProblemCause(FALSE, tvb, offset, pinfo, tree, hf_gnm_problemCause);
}


static const ber_sequence_t SET_OF_ObjectInstance_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_broadcast_item },
};

static int
dissect_gnm_SET_OF_ObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ObjectInstance_set_of, hf_index, ett_gnm_SET_OF_ObjectInstance);

  return offset;
}
static int dissect_broadcast(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_broadcast);
}
static int dissect_relatedObjects_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_ObjectInstance(TRUE, tvb, offset, pinfo, tree, hf_gnm_relatedObjects);
}
static int dissect_incorrectInstances(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_incorrectInstances);
}
static int dissect_tps1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_gnm_tps1);
}


static const ber_sequence_t LogicalProblem_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_problemCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_incorrectInstances },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_LogicalProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LogicalProblem_sequence, hf_index, ett_gnm_LogicalProblem);

  return offset;
}
static int dissect_logicalProblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_LogicalProblem(FALSE, tvb, offset, pinfo, tree, hf_gnm_logicalProblem);
}


static const value_string gnm_ResourceProblem_vals[] = {
  {   0, "unknown" },
  {   1, "integerValue" },
  { 0, NULL }
};

static const ber_choice_t ResourceProblem_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_unknown },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_integerValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ResourceProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ResourceProblem_choice, hf_index, ett_gnm_ResourceProblem,
                                 NULL);

  return offset;
}
static int dissect_resourceProblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ResourceProblem(FALSE, tvb, offset, pinfo, tree, hf_gnm_resourceProblem);
}


static const value_string gnm_Failed_vals[] = {
  {   0, "logicalProblem" },
  {   1, "resourceProblem" },
  { 0, NULL }
};

static const ber_choice_t Failed_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_logicalProblem },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_resourceProblem },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_Failed(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Failed_choice, hf_index, ett_gnm_Failed,
                                 NULL);

  return offset;
}
static int dissect_failed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Failed(FALSE, tvb, offset, pinfo, tree, hf_gnm_failed);
}
static int dissect_failed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Failed(TRUE, tvb, offset, pinfo, tree, hf_gnm_failed);
}


static const value_string gnm_AddTpsToGtpResult_item_vals[] = {
  {   0, "failed" },
  {   1, "addedTps" },
  { 0, NULL }
};

static const ber_choice_t AddTpsToGtpResult_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_failed_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_addedTps_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_AddTpsToGtpResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AddTpsToGtpResult_item_choice, hf_index, ett_gnm_AddTpsToGtpResult_item,
                                 NULL);

  return offset;
}
static int dissect_AddTpsToGtpResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AddTpsToGtpResult_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_AddTpsToGtpResult_item);
}


static const ber_sequence_t AddTpsToGtpResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_AddTpsToGtpResult_item },
};

static int
dissect_gnm_AddTpsToGtpResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AddTpsToGtpResult_sequence_of, hf_index, ett_gnm_AddTpsToGtpResult);

  return offset;
}


static const ber_sequence_t SET_OF_TerminationPointInformation_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tps_item },
};

static int
dissect_gnm_SET_OF_TerminationPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_TerminationPointInformation_set_of, hf_index, ett_gnm_SET_OF_TerminationPointInformation);

  return offset;
}
static int dissect_tps(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_TerminationPointInformation(FALSE, tvb, offset, pinfo, tree, hf_gnm_tps);
}


static const ber_sequence_t AddTpsToTpPoolInformation_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_tps },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_toTpPool },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_AddTpsToTpPoolInformation_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddTpsToTpPoolInformation_item_sequence, hf_index, ett_gnm_AddTpsToTpPoolInformation_item);

  return offset;
}
static int dissect_AddTpsToTpPoolInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AddTpsToTpPoolInformation_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_AddTpsToTpPoolInformation_item);
}


static const ber_sequence_t AddTpsToTpPoolInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AddTpsToTpPoolInformation_item },
};

static int
dissect_gnm_AddTpsToTpPoolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AddTpsToTpPoolInformation_sequence_of, hf_index, ett_gnm_AddTpsToTpPoolInformation);

  return offset;
}


static const ber_sequence_t TpsAddedToTpPool_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_tpPool },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_tps1 },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_TpsAddedToTpPool(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TpsAddedToTpPool_sequence, hf_index, ett_gnm_TpsAddedToTpPool);

  return offset;
}
static int dissect_tpsAddedToTpPool_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_TpsAddedToTpPool(TRUE, tvb, offset, pinfo, tree, hf_gnm_tpsAddedToTpPool);
}


static const value_string gnm_AddTpsToTpPoolResult_item_vals[] = {
  {   0, "failed" },
  {   1, "tpsAddedToTpPool" },
  { 0, NULL }
};

static const ber_choice_t AddTpsToTpPoolResult_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_failed_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_tpsAddedToTpPool_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_AddTpsToTpPoolResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AddTpsToTpPoolResult_item_choice, hf_index, ett_gnm_AddTpsToTpPoolResult_item,
                                 NULL);

  return offset;
}
static int dissect_AddTpsToTpPoolResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AddTpsToTpPoolResult_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_AddTpsToTpPoolResult_item);
}


static const ber_sequence_t AddTpsToTpPoolResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_AddTpsToTpPoolResult_item },
};

static int
dissect_gnm_AddTpsToTpPoolResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AddTpsToTpPoolResult_sequence_of, hf_index, ett_gnm_AddTpsToTpPoolResult);

  return offset;
}



static int
dissect_gnm_AlarmEffectOnServiceParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

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
dissect_gnm_AlarmSeverityCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_severityAssignedServiceAffecting_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AlarmSeverityCode(TRUE, tvb, offset, pinfo, tree, hf_gnm_severityAssignedServiceAffecting);
}
static int dissect_severityAssignedNonServiceAffecting_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AlarmSeverityCode(TRUE, tvb, offset, pinfo, tree, hf_gnm_severityAssignedNonServiceAffecting);
}
static int dissect_severityAssignedServiceIndependent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AlarmSeverityCode(TRUE, tvb, offset, pinfo, tree, hf_gnm_severityAssignedServiceIndependent);
}


static const ber_sequence_t AlarmSeverityAssignment_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_problem },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severityAssignedServiceAffecting_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severityAssignedNonServiceAffecting_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severityAssignedServiceIndependent_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_AlarmSeverityAssignment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlarmSeverityAssignment_sequence, hf_index, ett_gnm_AlarmSeverityAssignment);

  return offset;
}
static int dissect_AlarmSeverityAssignmentList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AlarmSeverityAssignment(FALSE, tvb, offset, pinfo, tree, hf_gnm_AlarmSeverityAssignmentList_item);
}


static const ber_sequence_t AlarmSeverityAssignmentList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AlarmSeverityAssignmentList_item },
};

static int
dissect_gnm_AlarmSeverityAssignmentList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_gnm_AlarmStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_alarmStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_AlarmStatus(TRUE, tvb, offset, pinfo, tree, hf_gnm_alarmStatus);
}



static int
dissect_gnm_Boolean(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_redline_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Boolean(TRUE, tvb, offset, pinfo, tree, hf_gnm_redline);
}


static const ber_sequence_t Bundle_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_characteristicInfoType },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_bundlingFactor },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_Bundle(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Bundle_sequence, hf_index, ett_gnm_Bundle);

  return offset;
}
static int dissect_bundle(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Bundle(FALSE, tvb, offset, pinfo, tree, hf_gnm_bundle);
}
static int dissect_complex_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Bundle(FALSE, tvb, offset, pinfo, tree, hf_gnm_complex_item);
}



static int
dissect_gnm_ChannelNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
dissect_gnm_CircuitDirectionality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gnm_CircuitPackAvailabilityStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gnm_AvailabilityStatus(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_gnm_CircuitPackType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_inTheAcceptableList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CircuitPackType(TRUE, tvb, offset, pinfo, tree, hf_gnm_inTheAcceptableList);
}
static int dissect_notInTheAcceptableList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CircuitPackType(TRUE, tvb, offset, pinfo, tree, hf_gnm_notInTheAcceptableList);
}


static const ber_sequence_t PointToPoint_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_fromTp1 },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_toTp1 },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_xCon },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_PointToPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PointToPoint_sequence, hf_index, ett_gnm_PointToPoint);

  return offset;
}
static int dissect_pointToPoint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PointToPoint(TRUE, tvb, offset, pinfo, tree, hf_gnm_pointToPoint);
}


static const ber_sequence_t T_toTps_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_tp },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_xConnection },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_T_toTps_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_toTps_item_sequence, hf_index, ett_gnm_T_toTps_item);

  return offset;
}
static int dissect_toTps_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_toTps_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTps_item);
}


static const ber_sequence_t T_toTps_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_toTps_item },
};

static int
dissect_gnm_T_toTps(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_toTps_set_of, hf_index, ett_gnm_T_toTps);

  return offset;
}
static int dissect_toTps(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_toTps(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTps);
}


static const ber_sequence_t PointToMultipoint_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_fromTp1 },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_toTps },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_mpXCon },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_PointToMultipoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PointToMultipoint_sequence, hf_index, ett_gnm_PointToMultipoint);

  return offset;
}
static int dissect_pointToMultipoint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PointToMultipoint(TRUE, tvb, offset, pinfo, tree, hf_gnm_pointToMultipoint);
}


static const value_string gnm_Connected_vals[] = {
  {   0, "pointToPoint" },
  {   1, "pointToMultipoint" },
  { 0, NULL }
};

static const ber_choice_t Connected_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_pointToPoint_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_pointToMultipoint_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_Connected(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Connected_choice, hf_index, ett_gnm_Connected,
                                 NULL);

  return offset;
}
static int dissect_connected(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Connected(FALSE, tvb, offset, pinfo, tree, hf_gnm_connected);
}
static int dissect_pass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_Connected(TRUE, tvb, offset, pinfo, tree, hf_gnm_pass);
}


static const ber_sequence_t ExplicitPtoP_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_fromTp },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_toTp },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_ExplicitPtoP(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExplicitPtoP_sequence, hf_index, ett_gnm_ExplicitPtoP);

  return offset;
}
static int dissect_explicitPToP_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ExplicitPtoP(TRUE, tvb, offset, pinfo, tree, hf_gnm_explicitPToP);
}


static const ber_sequence_t PtoTPPool_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_fromTp },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_toTpPool },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_PtoTPPool(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PtoTPPool_sequence, hf_index, ett_gnm_PtoTPPool);

  return offset;
}
static int dissect_ptoTpPool_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PtoTPPool(TRUE, tvb, offset, pinfo, tree, hf_gnm_ptoTpPool);
}


static const ber_sequence_t SET_OF_ExplicitTP_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_toTPs_item },
};

static int
dissect_gnm_SET_OF_ExplicitTP(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ExplicitTP_set_of, hf_index, ett_gnm_SET_OF_ExplicitTP);

  return offset;
}
static int dissect_toTPs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SET_OF_ExplicitTP(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTPs);
}


static const ber_sequence_t ExplicitPtoMP_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_fromTp },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_toTPs },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_ExplicitPtoMP(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExplicitPtoMP_sequence, hf_index, ett_gnm_ExplicitPtoMP);

  return offset;
}
static int dissect_explicitPtoMP_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ExplicitPtoMP(TRUE, tvb, offset, pinfo, tree, hf_gnm_explicitPtoMP);
}


static const ber_sequence_t ToTPPools_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_tpPoolId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_numberOfTPs },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_ToTPPools_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ToTPPools_item_sequence, hf_index, ett_gnm_ToTPPools_item);

  return offset;
}
static int dissect_ToTPPools_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ToTPPools_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_ToTPPools_item);
}


static const ber_sequence_t ToTPPools_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ToTPPools_item },
};

static int
dissect_gnm_ToTPPools(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ToTPPools_set_of, hf_index, ett_gnm_ToTPPools);

  return offset;
}
static int dissect_toTPPools(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ToTPPools(FALSE, tvb, offset, pinfo, tree, hf_gnm_toTPPools);
}


static const ber_sequence_t PtoMPools_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_fromTp },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_toTPPools },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_PtoMPools(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PtoMPools_sequence, hf_index, ett_gnm_PtoMPools);

  return offset;
}
static int dissect_ptoMPools_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_PtoMPools(TRUE, tvb, offset, pinfo, tree, hf_gnm_ptoMPools);
}


static const value_string gnm_ConnectionType_vals[] = {
  {   0, "explicitPToP" },
  {   1, "ptoTpPool" },
  {   2, "explicitPtoMP" },
  {   3, "ptoMPools" },
  { 0, NULL }
};

static const ber_choice_t ConnectionType_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_explicitPToP_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_ptoTpPool_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_explicitPtoMP_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_ptoMPools_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectionType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConnectionType_choice, hf_index, ett_gnm_ConnectionType,
                                 NULL);

  return offset;
}
static int dissect_unidirectional_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ConnectionType(TRUE, tvb, offset, pinfo, tree, hf_gnm_unidirectional);
}


static const value_string gnm_ConnectionTypeBi_vals[] = {
  {   0, "explicitPToP" },
  {   1, "ptoTpPool" },
  { 0, NULL }
};

static const ber_choice_t ConnectionTypeBi_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_explicitPToP_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_ptoTpPool_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectionTypeBi(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConnectionTypeBi_choice, hf_index, ett_gnm_ConnectionTypeBi,
                                 NULL);

  return offset;
}
static int dissect_bidirectional_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ConnectionTypeBi(TRUE, tvb, offset, pinfo, tree, hf_gnm_bidirectional);
}


static const value_string gnm_T_itemType_vals[] = {
  {   0, "unidirectional" },
  {   1, "bidirectional" },
  {   2, "addleg" },
  { 0, NULL }
};

static const ber_choice_t T_itemType_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_unidirectional_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_bidirectional_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_addleg_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_T_itemType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_itemType_choice, hf_index, ett_gnm_T_itemType,
                                 NULL);

  return offset;
}
static int dissect_itemType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_itemType(FALSE, tvb, offset, pinfo, tree, hf_gnm_itemType);
}



static int
dissect_gnm_CrossConnectionName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CrossConnectionName(FALSE, tvb, offset, pinfo, tree, hf_gnm_name);
}


static const ber_sequence_t NamedCrossConnection_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_redline1 },
  { BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_name },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_NamedCrossConnection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NamedCrossConnection_sequence, hf_index, ett_gnm_NamedCrossConnection);

  return offset;
}
static int dissect_namedCrossConnection_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_NamedCrossConnection(TRUE, tvb, offset, pinfo, tree, hf_gnm_namedCrossConnection);
}



static int
dissect_gnm_UserLabel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_userLabel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_UserLabel(TRUE, tvb, offset, pinfo, tree, hf_gnm_userLabel);
}


static const ber_sequence_t ConnectInformation_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_itemType },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_administrativeState },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_namedCrossConnection_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userLabel_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redline_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalInfo_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectInformation_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ConnectInformation_item_sequence, hf_index, ett_gnm_ConnectInformation_item);

  return offset;
}
static int dissect_ConnectInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ConnectInformation_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_ConnectInformation_item);
}


static const ber_sequence_t ConnectInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ConnectInformation_item },
};

static int
dissect_gnm_ConnectInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ConnectInformation_sequence_of, hf_index, ett_gnm_ConnectInformation);

  return offset;
}



static int
dissect_gnm_ConnectorType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gnm_ConnectivityPointer_vals[] = {
  {   0, "none" },
  {   1, "single" },
  {   2, "concatenated" },
  { 0, NULL }
};

static const ber_choice_t ConnectivityPointer_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_none },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_single },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_concatenated },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectivityPointer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConnectivityPointer_choice, hf_index, ett_gnm_ConnectivityPointer,
                                 NULL);

  return offset;
}


static const value_string gnm_ConnectResult_item_vals[] = {
  { -1/*choice*/, "failed" },
  { -1/*choice*/, "connected" },
  { 0, NULL }
};

static const ber_choice_t ConnectResult_item_choice[] = {
  { -1/*choice*/, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_failed },
  { -1/*choice*/, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_connected },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_ConnectResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConnectResult_item_choice, hf_index, ett_gnm_ConnectResult_item,
                                 NULL);

  return offset;
}
static int dissect_ConnectResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_ConnectResult_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_ConnectResult_item);
}


static const ber_sequence_t ConnectResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ConnectResult_item },
};

static int
dissect_gnm_ConnectResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ConnectResult_sequence_of, hf_index, ett_gnm_ConnectResult);

  return offset;
}



static int
dissect_gnm_Count(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gnm_CreateError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
  {   0, BER_CLASS_CON, 0, 0, dissect_downstreamNotConnected_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_downstreamConnected_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_upstreamNotConnected_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_upstreamConnected_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_MultipleConnections_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MultipleConnections_item_choice, hf_index, ett_gnm_MultipleConnections_item,
                                 NULL);

  return offset;
}
static int dissect_MultipleConnections_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_MultipleConnections_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_MultipleConnections_item);
}


static const ber_sequence_t MultipleConnections_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_MultipleConnections_item },
};

static int
dissect_gnm_MultipleConnections(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 MultipleConnections_set_of, hf_index, ett_gnm_MultipleConnections);

  return offset;
}
static int dissect_multipleConnections(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_MultipleConnections(FALSE, tvb, offset, pinfo, tree, hf_gnm_multipleConnections);
}


static const value_string gnm_CrossConnectionObjectPointer_vals[] = {
  {   0, "notConnected" },
  {   1, "connected" },
  {   2, "multipleConnections" },
  { 0, NULL }
};

static const ber_choice_t CrossConnectionObjectPointer_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_notConnected_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_connected1_impl },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_multipleConnections },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_CrossConnectionObjectPointer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CrossConnectionObjectPointer_choice, hf_index, ett_gnm_CrossConnectionObjectPointer,
                                 NULL);

  return offset;
}



static int
dissect_gnm_CTPUpstreamPointer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gnm_ConnectivityPointer(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_broadcastConcatenated_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_broadcastConcatenated_item },
};

static int
dissect_gnm_T_broadcastConcatenated(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_broadcastConcatenated_set_of, hf_index, ett_gnm_T_broadcastConcatenated);

  return offset;
}
static int dissect_broadcastConcatenated_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_broadcastConcatenated(TRUE, tvb, offset, pinfo, tree, hf_gnm_broadcastConcatenated);
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
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_none },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_single },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_concatenated },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_broadcast },
  {   4, BER_CLASS_CON, 1, 0, dissect_broadcastConcatenated_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_DownstreamConnectivityPointer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DownstreamConnectivityPointer_choice, hf_index, ett_gnm_DownstreamConnectivityPointer,
                                 NULL);

  return offset;
}



static int
dissect_gnm_CTPDownstreamPointer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gnm_DownstreamConnectivityPointer(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t CurrentProblem_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_problem_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_alarmStatus_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_CurrentProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CurrentProblem_sequence, hf_index, ett_gnm_CurrentProblem);

  return offset;
}
static int dissect_CurrentProblemList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_CurrentProblem(FALSE, tvb, offset, pinfo, tree, hf_gnm_CurrentProblemList_item);
}


static const ber_sequence_t CurrentProblemList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CurrentProblemList_item },
};

static int
dissect_gnm_CurrentProblemList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 CurrentProblemList_set_of, hf_index, ett_gnm_CurrentProblemList);

  return offset;
}


static const value_string gnm_Directionality_vals[] = {
  {   0, "unidirectional" },
  {   1, "bidirectional" },
  { 0, NULL }
};


static int
dissect_gnm_Directionality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DisconnectInformation_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_DisconnectInformation_item },
};

static int
dissect_gnm_DisconnectInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DisconnectInformation_sequence_of, hf_index, ett_gnm_DisconnectInformation);

  return offset;
}


static const value_string gnm_DisconnectResult_item_vals[] = {
  { -1/*choice*/, "failed" },
  { -1/*choice*/, "disconnected" },
  { 0, NULL }
};

static const ber_choice_t DisconnectResult_item_choice[] = {
  { -1/*choice*/, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_failed },
  { -1/*choice*/, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_disconnected },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_DisconnectResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DisconnectResult_item_choice, hf_index, ett_gnm_DisconnectResult_item,
                                 NULL);

  return offset;
}
static int dissect_DisconnectResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_DisconnectResult_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_DisconnectResult_item);
}


static const ber_sequence_t DisconnectResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_DisconnectResult_item },
};

static int
dissect_gnm_DisconnectResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DisconnectResult_sequence_of, hf_index, ett_gnm_DisconnectResult);

  return offset;
}



static int
dissect_gnm_ExternalTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t EquipmentHolderAddress_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_EquipmentHolderAddress_item },
};

static int
dissect_gnm_EquipmentHolderAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      EquipmentHolderAddress_sequence_of, hf_index, ett_gnm_EquipmentHolderAddress);

  return offset;
}



static int
dissect_gnm_EquipmentHolderType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gnm_GeneralErrorCause_vals[] = {
  {   0, "globalValue" },
  {   1, "localValue" },
  { 0, NULL }
};

static const ber_choice_t GeneralErrorCause_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_GeneralErrorCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GeneralErrorCause_choice, hf_index, ett_gnm_GeneralErrorCause,
                                 NULL);

  return offset;
}
static int dissect_cause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_GeneralErrorCause(FALSE, tvb, offset, pinfo, tree, hf_gnm_cause);
}



static int
dissect_gnm_GraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_details(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_GraphicString(FALSE, tvb, offset, pinfo, tree, hf_gnm_details);
}
static int dissect_pString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_GraphicString(FALSE, tvb, offset, pinfo, tree, hf_gnm_pString);
}


static const ber_sequence_t GeneralError_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cause },
  { BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_details },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_relatedObjects_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributeList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_GeneralError_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GeneralError_item_sequence, hf_index, ett_gnm_GeneralError_item);

  return offset;
}
static int dissect_GeneralError_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_GeneralError_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_GeneralError_item);
}


static const ber_sequence_t GeneralError_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GeneralError_item },
};

static int
dissect_gnm_GeneralError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      GeneralError_sequence_of, hf_index, ett_gnm_GeneralError);

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
  {   0, BER_CLASS_CON, 0, 0, dissect_holderEmpty_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_inTheAcceptableList_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_notInTheAcceptableList_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_unknownType_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_HolderStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 HolderStatus_choice, hf_index, ett_gnm_HolderStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t IndividualSwitchOver_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_connection },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_unchangedTP },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_newTP },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_IndividualSwitchOver(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IndividualSwitchOver_sequence, hf_index, ett_gnm_IndividualSwitchOver);

  return offset;
}
static int dissect_SwitchOverInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_IndividualSwitchOver(FALSE, tvb, offset, pinfo, tree, hf_gnm_SwitchOverInformation_item);
}


static const value_string gnm_IndividualResult_vals[] = {
  {   0, "failed" },
  {   1, "pass" },
  { 0, NULL }
};

static const ber_choice_t IndividualResult_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_failed_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_pass_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_IndividualResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 IndividualResult_choice, hf_index, ett_gnm_IndividualResult,
                                 NULL);

  return offset;
}
static int dissect_SwitchOverResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_IndividualResult(FALSE, tvb, offset, pinfo, tree, hf_gnm_SwitchOverResult_item);
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
dissect_gnm_InformationTransferCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ListOfCharacteristicInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ListOfCharacteristicInformation_item },
};

static int
dissect_gnm_ListOfCharacteristicInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ListOfCharacteristicInformation_set_of, hf_index, ett_gnm_ListOfCharacteristicInformation);

  return offset;
}


static const ber_sequence_t ListOfTPs_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ListOfTPs_item },
};

static int
dissect_gnm_ListOfTPs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ListOfTPs_set_of, hf_index, ett_gnm_ListOfTPs);

  return offset;
}



static int
dissect_gnm_LocationName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gnm_NameType_vals[] = {
  {   0, "numericName" },
  {   1, "pString" },
  { 0, NULL }
};

static const ber_choice_t NameType_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_numericName },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_pString },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_NameType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NameType_choice, hf_index, ett_gnm_NameType,
                                 NULL);

  return offset;
}



static int
dissect_gnm_NumberOfCircuits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ObjectList_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ObjectList_item },
};

static int
dissect_gnm_ObjectList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ObjectList_set_of, hf_index, ett_gnm_ObjectList);

  return offset;
}



static int
dissect_gnm_WaveLength(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_wavelength(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_WaveLength(FALSE, tvb, offset, pinfo, tree, hf_gnm_wavelength);
}


static const ber_sequence_t SignalRateAndMappingList_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_signalRate },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_mappingList },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_wavelength },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_SignalRateAndMappingList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SignalRateAndMappingList_item_sequence, hf_index, ett_gnm_SignalRateAndMappingList_item);

  return offset;
}
static int dissect_SignalRateAndMappingList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SignalRateAndMappingList_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_SignalRateAndMappingList_item);
}


static const ber_sequence_t SignalRateAndMappingList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SignalRateAndMappingList_item },
};

static int
dissect_gnm_SignalRateAndMappingList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SignalRateAndMappingList_set_of, hf_index, ett_gnm_SignalRateAndMappingList);

  return offset;
}
static int dissect_downstream(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SignalRateAndMappingList(FALSE, tvb, offset, pinfo, tree, hf_gnm_downstream);
}
static int dissect_upStream(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SignalRateAndMappingList(FALSE, tvb, offset, pinfo, tree, hf_gnm_upStream);
}
static int dissect_uniform(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SignalRateAndMappingList(FALSE, tvb, offset, pinfo, tree, hf_gnm_uniform);
}


static const ber_sequence_t T_diverse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_downstream },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_upStream },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_T_diverse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_diverse_sequence, hf_index, ett_gnm_T_diverse);

  return offset;
}
static int dissect_diverse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_diverse(FALSE, tvb, offset, pinfo, tree, hf_gnm_diverse);
}


static const value_string gnm_PhysicalPortSignalRateAndMappingList_vals[] = {
  {   0, "diverse" },
  {   1, "uniform" },
  { 0, NULL }
};

static const ber_choice_t PhysicalPortSignalRateAndMappingList_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_diverse },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_uniform },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_PhysicalPortSignalRateAndMappingList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PhysicalPortSignalRateAndMappingList_choice, hf_index, ett_gnm_PhysicalPortSignalRateAndMappingList,
                                 NULL);

  return offset;
}



static int
dissect_gnm_Pointer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cmip_ObjectInstance(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string gnm_PointerOrNull_vals[] = {
  {   0, "pointer" },
  {   1, "null" },
  { 0, NULL }
};

static const ber_choice_t PointerOrNull_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pointer },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_PointerOrNull(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PointerOrNull_choice, hf_index, ett_gnm_PointerOrNull,
                                 NULL);

  return offset;
}



static int
dissect_gnm_PortNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gnm_Reach(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gnm_RelatedObjectInstance_vals[] = {
  {   0, "notAvailable" },
  {   1, "relatedObject" },
  { 0, NULL }
};

static const ber_choice_t RelatedObjectInstance_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_notAvailable },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_relatedObject },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_RelatedObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RelatedObjectInstance_choice, hf_index, ett_gnm_RelatedObjectInstance,
                                 NULL);

  return offset;
}


static const ber_sequence_t RemoveTpsFromGtpInformation_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_fromGtp },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_tps1 },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_RemoveTpsFromGtpInformation_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RemoveTpsFromGtpInformation_item_sequence, hf_index, ett_gnm_RemoveTpsFromGtpInformation_item);

  return offset;
}
static int dissect_RemoveTpsFromGtpInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_RemoveTpsFromGtpInformation_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_RemoveTpsFromGtpInformation_item);
}


static const ber_sequence_t RemoveTpsFromGtpInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RemoveTpsFromGtpInformation_item },
};

static int
dissect_gnm_RemoveTpsFromGtpInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RemoveTpsFromGtpInformation_sequence_of, hf_index, ett_gnm_RemoveTpsFromGtpInformation);

  return offset;
}


static const ber_sequence_t RemoveTpsResultInformation_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_deletedTpPoolOrGTP },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_tps1 },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_RemoveTpsResultInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RemoveTpsResultInformation_sequence, hf_index, ett_gnm_RemoveTpsResultInformation);

  return offset;
}
static int dissect_removed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_RemoveTpsResultInformation(TRUE, tvb, offset, pinfo, tree, hf_gnm_removed);
}


static const value_string gnm_RemoveTpsFromGtpResult_item_vals[] = {
  {   0, "failed" },
  {   1, "removed" },
  { 0, NULL }
};

static const ber_choice_t RemoveTpsFromGtpResult_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_failed_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_removed_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_RemoveTpsFromGtpResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RemoveTpsFromGtpResult_item_choice, hf_index, ett_gnm_RemoveTpsFromGtpResult_item,
                                 NULL);

  return offset;
}
static int dissect_RemoveTpsFromGtpResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_RemoveTpsFromGtpResult_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_RemoveTpsFromGtpResult_item);
}


static const ber_sequence_t RemoveTpsFromGtpResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_RemoveTpsFromGtpResult_item },
};

static int
dissect_gnm_RemoveTpsFromGtpResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RemoveTpsFromGtpResult_sequence_of, hf_index, ett_gnm_RemoveTpsFromGtpResult);

  return offset;
}


static const ber_sequence_t RemoveTpsFromTpPoolInformation_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_fromTpPool },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_tps1 },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_RemoveTpsFromTpPoolInformation_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RemoveTpsFromTpPoolInformation_item_sequence, hf_index, ett_gnm_RemoveTpsFromTpPoolInformation_item);

  return offset;
}
static int dissect_RemoveTpsFromTpPoolInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_RemoveTpsFromTpPoolInformation_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_RemoveTpsFromTpPoolInformation_item);
}


static const ber_sequence_t RemoveTpsFromTpPoolInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RemoveTpsFromTpPoolInformation_item },
};

static int
dissect_gnm_RemoveTpsFromTpPoolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RemoveTpsFromTpPoolInformation_sequence_of, hf_index, ett_gnm_RemoveTpsFromTpPoolInformation);

  return offset;
}


static const value_string gnm_RemoveTpsFromTpPoolResult_item_vals[] = {
  {   0, "failed" },
  {   1, "removed" },
  { 0, NULL }
};

static const ber_choice_t RemoveTpsFromTpPoolResult_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_failed_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_removed_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_RemoveTpsFromTpPoolResult_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RemoveTpsFromTpPoolResult_item_choice, hf_index, ett_gnm_RemoveTpsFromTpPoolResult_item,
                                 NULL);

  return offset;
}
static int dissect_RemoveTpsFromTpPoolResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_RemoveTpsFromTpPoolResult_item(FALSE, tvb, offset, pinfo, tree, hf_gnm_RemoveTpsFromTpPoolResult_item);
}


static const ber_sequence_t RemoveTpsFromTpPoolResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_RemoveTpsFromTpPoolResult_item },
};

static int
dissect_gnm_RemoveTpsFromTpPoolResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RemoveTpsFromTpPoolResult_sequence_of, hf_index, ett_gnm_RemoveTpsFromTpPoolResult);

  return offset;
}


static const value_string gnm_Replaceable_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  {   2, "notapplicable" },
  { 0, NULL }
};


static int
dissect_gnm_Replaceable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SequenceOfObjectInstance_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_SequenceOfObjectInstance_item },
};

static int
dissect_gnm_SequenceOfObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SequenceOfObjectInstance_sequence_of, hf_index, ett_gnm_SequenceOfObjectInstance);

  return offset;
}



static int
dissect_gnm_SerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
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
dissect_gnm_SignallingCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Bundle_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_complex_item },
};

static int
dissect_gnm_SEQUENCE_OF_Bundle(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Bundle_sequence_of, hf_index, ett_gnm_SEQUENCE_OF_Bundle);

  return offset;
}
static int dissect_complex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SEQUENCE_OF_Bundle(TRUE, tvb, offset, pinfo, tree, hf_gnm_complex);
}


static const value_string gnm_SignalType_vals[] = {
  {   0, "simple" },
  {   1, "bundle" },
  {   2, "complex" },
  { 0, NULL }
};

static const ber_choice_t SignalType_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_simple },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bundle },
  {   2, BER_CLASS_CON, 0, 0, dissect_complex_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_SignalType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SignalType_choice, hf_index, ett_gnm_SignalType,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_softwareIdentifiers_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_softwareIdentifiers_item },
};

static int
dissect_gnm_T_softwareIdentifiers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_softwareIdentifiers_sequence_of, hf_index, ett_gnm_T_softwareIdentifiers);

  return offset;
}
static int dissect_softwareIdentifiers_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_softwareIdentifiers(TRUE, tvb, offset, pinfo, tree, hf_gnm_softwareIdentifiers);
}


static const value_string gnm_SubordinateCircuitPackSoftwareLoad_vals[] = {
  {   0, "notApplicable" },
  {   1, "softwareInstances" },
  {   2, "softwareIdentifiers" },
  { 0, NULL }
};

static const ber_choice_t SubordinateCircuitPackSoftwareLoad_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_notApplicable },
  {   1, BER_CLASS_CON, 0, 0, dissect_softwareInstances_impl },
  {   2, BER_CLASS_CON, 1, 0, dissect_softwareIdentifiers_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gnm_SubordinateCircuitPackSoftwareLoad(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SubordinateCircuitPackSoftwareLoad_choice, hf_index, ett_gnm_SubordinateCircuitPackSoftwareLoad,
                                 NULL);

  return offset;
}


static const ber_sequence_t SupportableClientList_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_SupportableClientList_item },
};

static int
dissect_gnm_SupportableClientList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_gnm_T_sourceType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sourceType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_T_sourceType(FALSE, tvb, offset, pinfo, tree, hf_gnm_sourceType);
}


static const ber_sequence_t SystemTiming_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_sourceType },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sourceID },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_SystemTiming(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SystemTiming_sequence, hf_index, ett_gnm_SystemTiming);

  return offset;
}
static int dissect_primaryTimingSource(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SystemTiming(FALSE, tvb, offset, pinfo, tree, hf_gnm_primaryTimingSource);
}
static int dissect_secondaryTimingSource(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gnm_SystemTiming(FALSE, tvb, offset, pinfo, tree, hf_gnm_secondaryTimingSource);
}


static const ber_sequence_t SystemTimingSource_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_primaryTimingSource },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_secondaryTimingSource },
  { 0, 0, 0, NULL }
};

static int
dissect_gnm_SystemTimingSource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SystemTimingSource_sequence, hf_index, ett_gnm_SystemTimingSource);

  return offset;
}


static const ber_sequence_t SwitchOverInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SwitchOverInformation_item },
};

static int
dissect_gnm_SwitchOverInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SwitchOverInformation_sequence_of, hf_index, ett_gnm_SwitchOverInformation);

  return offset;
}


static const ber_sequence_t SwitchOverResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_SwitchOverResult_item },
};

static int
dissect_gnm_SwitchOverResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SwitchOverResult_sequence_of, hf_index, ett_gnm_SwitchOverResult);

  return offset;
}


static const ber_sequence_t TpsInGtpList_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_TpsInGtpList_item },
};

static int
dissect_gnm_TpsInGtpList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_gnm_TransmissionCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    TransmissionCharacteristics_bits, hf_index, ett_gnm_TransmissionCharacteristics,
                                    NULL);

  return offset;
}



static int
dissect_gnm_TypeText(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gnm_VendorName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gnm_Version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AdministrativeState_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_AdministrativeState(FALSE, tvb, 0, pinfo, tree, hf_gnm_AdministrativeState_PDU);
}
static void dissect_ControlStatus_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_ControlStatus(FALSE, tvb, 0, pinfo, tree, hf_gnm_ControlStatus_PDU);
}
static void dissect_Packages_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Packages(FALSE, tvb, 0, pinfo, tree, hf_gnm_Packages_PDU);
}
static void dissect_SupportedTOClasses_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SupportedTOClasses(FALSE, tvb, 0, pinfo, tree, hf_gnm_SupportedTOClasses_PDU);
}
static void dissect_AcceptableCircuitPackTypeList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_AcceptableCircuitPackTypeList(FALSE, tvb, 0, pinfo, tree, hf_gnm_AcceptableCircuitPackTypeList_PDU);
}
static void dissect_AlarmSeverityAssignmentList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_AlarmSeverityAssignmentList(FALSE, tvb, 0, pinfo, tree, hf_gnm_AlarmSeverityAssignmentList_PDU);
}
static void dissect_AlarmStatus_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_AlarmStatus(FALSE, tvb, 0, pinfo, tree, hf_gnm_AlarmStatus_PDU);
}
static void dissect_Boolean_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Boolean(FALSE, tvb, 0, pinfo, tree, hf_gnm_Boolean_PDU);
}
static void dissect_ChannelNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_ChannelNumber(FALSE, tvb, 0, pinfo, tree, hf_gnm_ChannelNumber_PDU);
}
static void dissect_CharacteristicInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_CharacteristicInformation(FALSE, tvb, 0, pinfo, tree, hf_gnm_CharacteristicInformation_PDU);
}
static void dissect_CircuitDirectionality_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_CircuitDirectionality(FALSE, tvb, 0, pinfo, tree, hf_gnm_CircuitDirectionality_PDU);
}
static void dissect_CircuitPackType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_CircuitPackType(FALSE, tvb, 0, pinfo, tree, hf_gnm_CircuitPackType_PDU);
}
static void dissect_ConnectivityPointer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_ConnectivityPointer(FALSE, tvb, 0, pinfo, tree, hf_gnm_ConnectivityPointer_PDU);
}
static void dissect_Count_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Count(FALSE, tvb, 0, pinfo, tree, hf_gnm_Count_PDU);
}
static void dissect_CrossConnectionName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_CrossConnectionName(FALSE, tvb, 0, pinfo, tree, hf_gnm_CrossConnectionName_PDU);
}
static void dissect_CrossConnectionObjectPointer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_CrossConnectionObjectPointer(FALSE, tvb, 0, pinfo, tree, hf_gnm_CrossConnectionObjectPointer_PDU);
}
static void dissect_CurrentProblemList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_CurrentProblemList(FALSE, tvb, 0, pinfo, tree, hf_gnm_CurrentProblemList_PDU);
}
static void dissect_Directionality_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Directionality(FALSE, tvb, 0, pinfo, tree, hf_gnm_Directionality_PDU);
}
static void dissect_DownstreamConnectivityPointer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_DownstreamConnectivityPointer(FALSE, tvb, 0, pinfo, tree, hf_gnm_DownstreamConnectivityPointer_PDU);
}
static void dissect_ExternalTime_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_ExternalTime(FALSE, tvb, 0, pinfo, tree, hf_gnm_ExternalTime_PDU);
}
static void dissect_EquipmentHolderAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_EquipmentHolderAddress(FALSE, tvb, 0, pinfo, tree, hf_gnm_EquipmentHolderAddress_PDU);
}
static void dissect_EquipmentHolderType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_EquipmentHolderType(FALSE, tvb, 0, pinfo, tree, hf_gnm_EquipmentHolderType_PDU);
}
static void dissect_HolderStatus_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_HolderStatus(FALSE, tvb, 0, pinfo, tree, hf_gnm_HolderStatus_PDU);
}
static void dissect_InformationTransferCapabilities_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_InformationTransferCapabilities(FALSE, tvb, 0, pinfo, tree, hf_gnm_InformationTransferCapabilities_PDU);
}
static void dissect_ListOfCharacteristicInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_ListOfCharacteristicInformation(FALSE, tvb, 0, pinfo, tree, hf_gnm_ListOfCharacteristicInformation_PDU);
}
static void dissect_NameType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_NameType(FALSE, tvb, 0, pinfo, tree, hf_gnm_NameType_PDU);
}
static void dissect_NumberOfCircuits_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_NumberOfCircuits(FALSE, tvb, 0, pinfo, tree, hf_gnm_NumberOfCircuits_PDU);
}
static void dissect_ObjectList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_ObjectList(FALSE, tvb, 0, pinfo, tree, hf_gnm_ObjectList_PDU);
}
static void dissect_Pointer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Pointer(FALSE, tvb, 0, pinfo, tree, hf_gnm_Pointer_PDU);
}
static void dissect_PointerOrNull_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_PointerOrNull(FALSE, tvb, 0, pinfo, tree, hf_gnm_PointerOrNull_PDU);
}
static void dissect_RelatedObjectInstance_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_RelatedObjectInstance(FALSE, tvb, 0, pinfo, tree, hf_gnm_RelatedObjectInstance_PDU);
}
static void dissect_Replaceable_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Replaceable(FALSE, tvb, 0, pinfo, tree, hf_gnm_Replaceable_PDU);
}
static void dissect_SequenceOfObjectInstance_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SequenceOfObjectInstance(FALSE, tvb, 0, pinfo, tree, hf_gnm_SequenceOfObjectInstance_PDU);
}
static void dissect_SerialNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SerialNumber(FALSE, tvb, 0, pinfo, tree, hf_gnm_SerialNumber_PDU);
}
static void dissect_SignallingCapabilities_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SignallingCapabilities(FALSE, tvb, 0, pinfo, tree, hf_gnm_SignallingCapabilities_PDU);
}
static void dissect_SignalType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SignalType(FALSE, tvb, 0, pinfo, tree, hf_gnm_SignalType_PDU);
}
static void dissect_SubordinateCircuitPackSoftwareLoad_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SubordinateCircuitPackSoftwareLoad(FALSE, tvb, 0, pinfo, tree, hf_gnm_SubordinateCircuitPackSoftwareLoad_PDU);
}
static void dissect_SupportableClientList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SupportableClientList(FALSE, tvb, 0, pinfo, tree, hf_gnm_SupportableClientList_PDU);
}
static void dissect_SystemTimingSource_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_SystemTimingSource(FALSE, tvb, 0, pinfo, tree, hf_gnm_SystemTimingSource_PDU);
}
static void dissect_TpsInGtpList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_TpsInGtpList(FALSE, tvb, 0, pinfo, tree, hf_gnm_TpsInGtpList_PDU);
}
static void dissect_TransmissionCharacteristics_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_TransmissionCharacteristics(FALSE, tvb, 0, pinfo, tree, hf_gnm_TransmissionCharacteristics_PDU);
}
static void dissect_UserLabel_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_UserLabel(FALSE, tvb, 0, pinfo, tree, hf_gnm_UserLabel_PDU);
}
static void dissect_VendorName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_VendorName(FALSE, tvb, 0, pinfo, tree, hf_gnm_VendorName_PDU);
}
static void dissect_Version_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gnm_Version(FALSE, tvb, 0, pinfo, tree, hf_gnm_Version_PDU);
}


/*--- End of included file: packet-gnm-fn.c ---*/




static void
dissect_gnm_attribute_ObjectInstance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_ObjectInstance(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

void
dissect_gnm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  /* Dymmy function */
}

/*--- proto_register_gnm -------------------------------------------*/
void proto_register_gnm(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gnm_AdministrativeState,
      { "AdministrativeState", "gnm.AdministrativeState",
        FT_UINT32, BASE_DEC, VALS(gnm_AdministrativeState_vals), 0,
        "", HFILL }},


/*--- Included file: packet-gnm-hfarr.c ---*/

    { &hf_gnm_AdministrativeState_PDU,
      { "AdministrativeState", "gnm.AdministrativeState",
        FT_UINT32, BASE_DEC, VALS(gnm_AdministrativeState_vals), 0,
        "AdministrativeState", HFILL }},
    { &hf_gnm_ControlStatus_PDU,
      { "ControlStatus", "gnm.ControlStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ControlStatus", HFILL }},
    { &hf_gnm_Packages_PDU,
      { "Packages", "gnm.Packages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Packages", HFILL }},
    { &hf_gnm_SupportedTOClasses_PDU,
      { "SupportedTOClasses", "gnm.SupportedTOClasses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SupportedTOClasses", HFILL }},
    { &hf_gnm_AcceptableCircuitPackTypeList_PDU,
      { "AcceptableCircuitPackTypeList", "gnm.AcceptableCircuitPackTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcceptableCircuitPackTypeList", HFILL }},
    { &hf_gnm_AlarmSeverityAssignmentList_PDU,
      { "AlarmSeverityAssignmentList", "gnm.AlarmSeverityAssignmentList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlarmSeverityAssignmentList", HFILL }},
    { &hf_gnm_AlarmStatus_PDU,
      { "AlarmStatus", "gnm.AlarmStatus",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmStatus_vals), 0,
        "AlarmStatus", HFILL }},
    { &hf_gnm_Boolean_PDU,
      { "Boolean", "gnm.Boolean",
        FT_BOOLEAN, 8, NULL, 0,
        "Boolean", HFILL }},
    { &hf_gnm_ChannelNumber_PDU,
      { "ChannelNumber", "gnm.ChannelNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "ChannelNumber", HFILL }},
    { &hf_gnm_CharacteristicInformation_PDU,
      { "CharacteristicInformation", "gnm.CharacteristicInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "CharacteristicInformation", HFILL }},
    { &hf_gnm_CircuitDirectionality_PDU,
      { "CircuitDirectionality", "gnm.CircuitDirectionality",
        FT_UINT32, BASE_DEC, VALS(gnm_CircuitDirectionality_vals), 0,
        "CircuitDirectionality", HFILL }},
    { &hf_gnm_CircuitPackType_PDU,
      { "CircuitPackType", "gnm.CircuitPackType",
        FT_STRING, BASE_NONE, NULL, 0,
        "CircuitPackType", HFILL }},
    { &hf_gnm_ConnectivityPointer_PDU,
      { "ConnectivityPointer", "gnm.ConnectivityPointer",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectivityPointer_vals), 0,
        "ConnectivityPointer", HFILL }},
    { &hf_gnm_Count_PDU,
      { "Count", "gnm.Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "Count", HFILL }},
    { &hf_gnm_CrossConnectionName_PDU,
      { "CrossConnectionName", "gnm.CrossConnectionName",
        FT_STRING, BASE_NONE, NULL, 0,
        "CrossConnectionName", HFILL }},
    { &hf_gnm_CrossConnectionObjectPointer_PDU,
      { "CrossConnectionObjectPointer", "gnm.CrossConnectionObjectPointer",
        FT_UINT32, BASE_DEC, VALS(gnm_CrossConnectionObjectPointer_vals), 0,
        "CrossConnectionObjectPointer", HFILL }},
    { &hf_gnm_CurrentProblemList_PDU,
      { "CurrentProblemList", "gnm.CurrentProblemList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CurrentProblemList", HFILL }},
    { &hf_gnm_Directionality_PDU,
      { "Directionality", "gnm.Directionality",
        FT_UINT32, BASE_DEC, VALS(gnm_Directionality_vals), 0,
        "Directionality", HFILL }},
    { &hf_gnm_DownstreamConnectivityPointer_PDU,
      { "DownstreamConnectivityPointer", "gnm.DownstreamConnectivityPointer",
        FT_UINT32, BASE_DEC, VALS(gnm_DownstreamConnectivityPointer_vals), 0,
        "DownstreamConnectivityPointer", HFILL }},
    { &hf_gnm_ExternalTime_PDU,
      { "ExternalTime", "gnm.ExternalTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExternalTime", HFILL }},
    { &hf_gnm_EquipmentHolderAddress_PDU,
      { "EquipmentHolderAddress", "gnm.EquipmentHolderAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EquipmentHolderAddress", HFILL }},
    { &hf_gnm_EquipmentHolderType_PDU,
      { "EquipmentHolderType", "gnm.EquipmentHolderType",
        FT_STRING, BASE_NONE, NULL, 0,
        "EquipmentHolderType", HFILL }},
    { &hf_gnm_HolderStatus_PDU,
      { "HolderStatus", "gnm.HolderStatus",
        FT_UINT32, BASE_DEC, VALS(gnm_HolderStatus_vals), 0,
        "HolderStatus", HFILL }},
    { &hf_gnm_InformationTransferCapabilities_PDU,
      { "InformationTransferCapabilities", "gnm.InformationTransferCapabilities",
        FT_UINT32, BASE_DEC, VALS(gnm_InformationTransferCapabilities_vals), 0,
        "InformationTransferCapabilities", HFILL }},
    { &hf_gnm_ListOfCharacteristicInformation_PDU,
      { "ListOfCharacteristicInformation", "gnm.ListOfCharacteristicInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListOfCharacteristicInformation", HFILL }},
    { &hf_gnm_NameType_PDU,
      { "NameType", "gnm.NameType",
        FT_UINT32, BASE_DEC, VALS(gnm_NameType_vals), 0,
        "NameType", HFILL }},
    { &hf_gnm_NumberOfCircuits_PDU,
      { "NumberOfCircuits", "gnm.NumberOfCircuits",
        FT_INT32, BASE_DEC, NULL, 0,
        "NumberOfCircuits", HFILL }},
    { &hf_gnm_ObjectList_PDU,
      { "ObjectList", "gnm.ObjectList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ObjectList", HFILL }},
    { &hf_gnm_Pointer_PDU,
      { "Pointer", "gnm.Pointer",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "Pointer", HFILL }},
    { &hf_gnm_PointerOrNull_PDU,
      { "PointerOrNull", "gnm.PointerOrNull",
        FT_UINT32, BASE_DEC, VALS(gnm_PointerOrNull_vals), 0,
        "PointerOrNull", HFILL }},
    { &hf_gnm_RelatedObjectInstance_PDU,
      { "RelatedObjectInstance", "gnm.RelatedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(gnm_RelatedObjectInstance_vals), 0,
        "RelatedObjectInstance", HFILL }},
    { &hf_gnm_Replaceable_PDU,
      { "Replaceable", "gnm.Replaceable",
        FT_UINT32, BASE_DEC, VALS(gnm_Replaceable_vals), 0,
        "Replaceable", HFILL }},
    { &hf_gnm_SequenceOfObjectInstance_PDU,
      { "SequenceOfObjectInstance", "gnm.SequenceOfObjectInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfObjectInstance", HFILL }},
    { &hf_gnm_SerialNumber_PDU,
      { "SerialNumber", "gnm.SerialNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "SerialNumber", HFILL }},
    { &hf_gnm_SignallingCapabilities_PDU,
      { "SignallingCapabilities", "gnm.SignallingCapabilities",
        FT_UINT32, BASE_DEC, VALS(gnm_SignallingCapabilities_vals), 0,
        "SignallingCapabilities", HFILL }},
    { &hf_gnm_SignalType_PDU,
      { "SignalType", "gnm.SignalType",
        FT_UINT32, BASE_DEC, VALS(gnm_SignalType_vals), 0,
        "SignalType", HFILL }},
    { &hf_gnm_SubordinateCircuitPackSoftwareLoad_PDU,
      { "SubordinateCircuitPackSoftwareLoad", "gnm.SubordinateCircuitPackSoftwareLoad",
        FT_UINT32, BASE_DEC, VALS(gnm_SubordinateCircuitPackSoftwareLoad_vals), 0,
        "SubordinateCircuitPackSoftwareLoad", HFILL }},
    { &hf_gnm_SupportableClientList_PDU,
      { "SupportableClientList", "gnm.SupportableClientList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SupportableClientList", HFILL }},
    { &hf_gnm_SystemTimingSource_PDU,
      { "SystemTimingSource", "gnm.SystemTimingSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemTimingSource", HFILL }},
    { &hf_gnm_TpsInGtpList_PDU,
      { "TpsInGtpList", "gnm.TpsInGtpList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TpsInGtpList", HFILL }},
    { &hf_gnm_TransmissionCharacteristics_PDU,
      { "TransmissionCharacteristics", "gnm.TransmissionCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TransmissionCharacteristics", HFILL }},
    { &hf_gnm_UserLabel_PDU,
      { "UserLabel", "gnm.UserLabel",
        FT_STRING, BASE_NONE, NULL, 0,
        "UserLabel", HFILL }},
    { &hf_gnm_VendorName_PDU,
      { "VendorName", "gnm.VendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VendorName", HFILL }},
    { &hf_gnm_Version_PDU,
      { "Version", "gnm.Version",
        FT_STRING, BASE_NONE, NULL, 0,
        "Version", HFILL }},
    { &hf_gnm_globalValue,
      { "globalValue", "gnm.globalValue",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gnm_localValue,
      { "localValue", "gnm.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gnm_AvailabilityStatus_item,
      { "Item", "gnm.AvailabilityStatus_item",
        FT_INT32, BASE_DEC, VALS(gnm_AvailabilityStatus_item_vals), 0,
        "AvailabilityStatus/_item", HFILL }},
    { &hf_gnm_AttributeList_item,
      { "Item", "gnm.AttributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeList/_item", HFILL }},
    { &hf_gnm_AdditionalInformation_item,
      { "Item", "gnm.AdditionalInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdditionalInformation/_item", HFILL }},
    { &hf_gnm_ControlStatus_item,
      { "Item", "gnm.ControlStatus_item",
        FT_INT32, BASE_DEC, VALS(gnm_ControlStatus_item_vals), 0,
        "ControlStatus/_item", HFILL }},
    { &hf_gnm_identifier,
      { "identifier", "gnm.identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "ManagementExtension/identifier", HFILL }},
    { &hf_gnm_significance,
      { "significance", "gnm.significance",
        FT_BOOLEAN, 8, NULL, 0,
        "ManagementExtension/significance", HFILL }},
    { &hf_gnm_information,
      { "information", "gnm.information",
        FT_NONE, BASE_NONE, NULL, 0,
        "ManagementExtension/information", HFILL }},
    { &hf_gnm_MappingList_item,
      { "Item", "gnm.MappingList_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "MappingList/_item", HFILL }},
    { &hf_gnm_Packages_item,
      { "Item", "gnm.Packages_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "Packages/_item", HFILL }},
    { &hf_gnm_objectClass,
      { "objectClass", "gnm.objectClass",
        FT_STRING, BASE_NONE, NULL, 0,
        "SignalRate/objectClass", HFILL }},
    { &hf_gnm_characteristicInformation,
      { "characteristicInformation", "gnm.characteristicInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "SignalRate/characteristicInformation", HFILL }},
    { &hf_gnm_SupportedTOClasses_item,
      { "Item", "gnm.SupportedTOClasses_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "SupportedTOClasses/_item", HFILL }},
    { &hf_gnm_AcceptableCircuitPackTypeList_item,
      { "Item", "gnm.AcceptableCircuitPackTypeList_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "AcceptableCircuitPackTypeList/_item", HFILL }},
    { &hf_gnm_gtp,
      { "gtp", "gnm.gtp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_gnm_tpsAdded,
      { "tpsAdded", "gnm.tpsAdded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddedTps/tpsAdded", HFILL }},
    { &hf_gnm_tpsAdded_item,
      { "Item", "gnm.tpsAdded_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "AddedTps/tpsAdded/_item", HFILL }},
    { &hf_gnm_mpCrossConnection,
      { "mpCrossConnection", "gnm.mpCrossConnection",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "AddLeg/mpCrossConnection", HFILL }},
    { &hf_gnm_legs,
      { "legs", "gnm.legs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddLeg/legs", HFILL }},
    { &hf_gnm_legs_item,
      { "Item", "gnm.legs_item",
        FT_UINT32, BASE_DEC, VALS(gnm_ToTermSpecifier_vals), 0,
        "AddLeg/legs/_item", HFILL }},
    { &hf_gnm_AddTpsToGtpInformation_item,
      { "Item", "gnm.AddTpsToGtpInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddTpsToGtpInformation/_item", HFILL }},
    { &hf_gnm_tpsAdded1,
      { "tpsAdded", "gnm.tpsAdded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddTpsToGtpInformation/_item/tpsAdded", HFILL }},
    { &hf_gnm_tpsAdded_item1,
      { "Item", "gnm.tpsAdded_item",
        FT_UINT32, BASE_DEC, VALS(gnm_TerminationPointInformation_vals), 0,
        "AddTpsToGtpInformation/_item/tpsAdded/_item", HFILL }},
    { &hf_gnm_AddTpsToGtpResult_item,
      { "Item", "gnm.AddTpsToGtpResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_AddTpsToGtpResult_item_vals), 0,
        "AddTpsToGtpResult/_item", HFILL }},
    { &hf_gnm_failed,
      { "failed", "gnm.failed",
        FT_UINT32, BASE_DEC, VALS(gnm_Failed_vals), 0,
        "", HFILL }},
    { &hf_gnm_addedTps,
      { "addedTps", "gnm.addedTps",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddTpsToGtpResult/_item/addedTps", HFILL }},
    { &hf_gnm_AddTpsToTpPoolInformation_item,
      { "Item", "gnm.AddTpsToTpPoolInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddTpsToTpPoolInformation/_item", HFILL }},
    { &hf_gnm_tps,
      { "tps", "gnm.tps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddTpsToTpPoolInformation/_item/tps", HFILL }},
    { &hf_gnm_tps_item,
      { "Item", "gnm.tps_item",
        FT_UINT32, BASE_DEC, VALS(gnm_TerminationPointInformation_vals), 0,
        "AddTpsToTpPoolInformation/_item/tps/_item", HFILL }},
    { &hf_gnm_toTpPool,
      { "toTpPool", "gnm.toTpPool",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_gnm_AddTpsToTpPoolResult_item,
      { "Item", "gnm.AddTpsToTpPoolResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_AddTpsToTpPoolResult_item_vals), 0,
        "AddTpsToTpPoolResult/_item", HFILL }},
    { &hf_gnm_tpsAddedToTpPool,
      { "tpsAddedToTpPool", "gnm.tpsAddedToTpPool",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddTpsToTpPoolResult/_item/tpsAddedToTpPool", HFILL }},
    { &hf_gnm_problem,
      { "problem", "gnm.problem",
        FT_UINT32, BASE_DEC, VALS(gnm_ProbableCause_vals), 0,
        "", HFILL }},
    { &hf_gnm_severityAssignedServiceAffecting,
      { "severityAssignedServiceAffecting", "gnm.severityAssignedServiceAffecting",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmSeverityCode_vals), 0,
        "AlarmSeverityAssignment/severityAssignedServiceAffecting", HFILL }},
    { &hf_gnm_severityAssignedNonServiceAffecting,
      { "severityAssignedNonServiceAffecting", "gnm.severityAssignedNonServiceAffecting",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmSeverityCode_vals), 0,
        "AlarmSeverityAssignment/severityAssignedNonServiceAffecting", HFILL }},
    { &hf_gnm_severityAssignedServiceIndependent,
      { "severityAssignedServiceIndependent", "gnm.severityAssignedServiceIndependent",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmSeverityCode_vals), 0,
        "AlarmSeverityAssignment/severityAssignedServiceIndependent", HFILL }},
    { &hf_gnm_AlarmSeverityAssignmentList_item,
      { "Item", "gnm.AlarmSeverityAssignmentList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlarmSeverityAssignmentList/_item", HFILL }},
    { &hf_gnm_characteristicInfoType,
      { "characteristicInfoType", "gnm.characteristicInfoType",
        FT_STRING, BASE_NONE, NULL, 0,
        "Bundle/characteristicInfoType", HFILL }},
    { &hf_gnm_bundlingFactor,
      { "bundlingFactor", "gnm.bundlingFactor",
        FT_INT32, BASE_DEC, NULL, 0,
        "Bundle/bundlingFactor", HFILL }},
    { &hf_gnm_pointToPoint,
      { "pointToPoint", "gnm.pointToPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "Connected/pointToPoint", HFILL }},
    { &hf_gnm_pointToMultipoint,
      { "pointToMultipoint", "gnm.pointToMultipoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "Connected/pointToMultipoint", HFILL }},
    { &hf_gnm_ConnectInformation_item,
      { "Item", "gnm.ConnectInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectInformation/_item", HFILL }},
    { &hf_gnm_itemType,
      { "itemType", "gnm.itemType",
        FT_UINT32, BASE_DEC, VALS(gnm_T_itemType_vals), 0,
        "ConnectInformation/_item/itemType", HFILL }},
    { &hf_gnm_unidirectional,
      { "unidirectional", "gnm.unidirectional",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectionType_vals), 0,
        "ConnectInformation/_item/itemType/unidirectional", HFILL }},
    { &hf_gnm_bidirectional,
      { "bidirectional", "gnm.bidirectional",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectionTypeBi_vals), 0,
        "ConnectInformation/_item/itemType/bidirectional", HFILL }},
    { &hf_gnm_addleg,
      { "addleg", "gnm.addleg",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectInformation/_item/itemType/addleg", HFILL }},
    { &hf_gnm_administrativeState,
      { "administrativeState", "gnm.administrativeState",
        FT_UINT32, BASE_DEC, VALS(gnm_AdministrativeState_vals), 0,
        "ConnectInformation/_item/administrativeState", HFILL }},
    { &hf_gnm_namedCrossConnection,
      { "namedCrossConnection", "gnm.namedCrossConnection",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectInformation/_item/namedCrossConnection", HFILL }},
    { &hf_gnm_userLabel,
      { "userLabel", "gnm.userLabel",
        FT_STRING, BASE_NONE, NULL, 0,
        "ConnectInformation/_item/userLabel", HFILL }},
    { &hf_gnm_redline,
      { "redline", "gnm.redline",
        FT_BOOLEAN, 8, NULL, 0,
        "ConnectInformation/_item/redline", HFILL }},
    { &hf_gnm_additionalInfo,
      { "additionalInfo", "gnm.additionalInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ConnectInformation/_item/additionalInfo", HFILL }},
    { &hf_gnm_none,
      { "none", "gnm.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gnm_single,
      { "single", "gnm.single",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_gnm_concatenated,
      { "concatenated", "gnm.concatenated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gnm_concatenated_item,
      { "Item", "gnm.concatenated_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_gnm_ConnectResult_item,
      { "Item", "gnm.ConnectResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_ConnectResult_item_vals), 0,
        "ConnectResult/_item", HFILL }},
    { &hf_gnm_connected,
      { "connected", "gnm.connected",
        FT_UINT32, BASE_DEC, VALS(gnm_Connected_vals), 0,
        "ConnectResult/_item/connected", HFILL }},
    { &hf_gnm_explicitPToP,
      { "explicitPToP", "gnm.explicitPToP",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gnm_ptoTpPool,
      { "ptoTpPool", "gnm.ptoTpPool",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gnm_explicitPtoMP,
      { "explicitPtoMP", "gnm.explicitPtoMP",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectionType/explicitPtoMP", HFILL }},
    { &hf_gnm_ptoMPools,
      { "ptoMPools", "gnm.ptoMPools",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectionType/ptoMPools", HFILL }},
    { &hf_gnm_notConnected,
      { "notConnected", "gnm.notConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "CrossConnectionObjectPointer/notConnected", HFILL }},
    { &hf_gnm_connected1,
      { "connected", "gnm.connected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "CrossConnectionObjectPointer/connected", HFILL }},
    { &hf_gnm_multipleConnections,
      { "multipleConnections", "gnm.multipleConnections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CrossConnectionObjectPointer/multipleConnections", HFILL }},
    { &hf_gnm_alarmStatus,
      { "alarmStatus", "gnm.alarmStatus",
        FT_UINT32, BASE_DEC, VALS(gnm_AlarmStatus_vals), 0,
        "CurrentProblem/alarmStatus", HFILL }},
    { &hf_gnm_CurrentProblemList_item,
      { "Item", "gnm.CurrentProblemList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CurrentProblemList/_item", HFILL }},
    { &hf_gnm_DisconnectInformation_item,
      { "Item", "gnm.DisconnectInformation_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "DisconnectInformation/_item", HFILL }},
    { &hf_gnm_DisconnectResult_item,
      { "Item", "gnm.DisconnectResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_DisconnectResult_item_vals), 0,
        "DisconnectResult/_item", HFILL }},
    { &hf_gnm_disconnected,
      { "disconnected", "gnm.disconnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "DisconnectResult/_item/disconnected", HFILL }},
    { &hf_gnm_broadcast,
      { "broadcast", "gnm.broadcast",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DownstreamConnectivityPointer/broadcast", HFILL }},
    { &hf_gnm_broadcast_item,
      { "Item", "gnm.broadcast_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "DownstreamConnectivityPointer/broadcast/_item", HFILL }},
    { &hf_gnm_broadcastConcatenated,
      { "broadcastConcatenated", "gnm.broadcastConcatenated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DownstreamConnectivityPointer/broadcastConcatenated", HFILL }},
    { &hf_gnm_broadcastConcatenated_item,
      { "Item", "gnm.broadcastConcatenated_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DownstreamConnectivityPointer/broadcastConcatenated/_item", HFILL }},
    { &hf_gnm__item_item,
      { "Item", "gnm._item_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "DownstreamConnectivityPointer/broadcastConcatenated/_item/_item", HFILL }},
    { &hf_gnm_fromTp,
      { "fromTp", "gnm.fromTp",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "", HFILL }},
    { &hf_gnm_toTPs,
      { "toTPs", "gnm.toTPs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExplicitPtoMP/toTPs", HFILL }},
    { &hf_gnm_toTPs_item,
      { "Item", "gnm.toTPs_item",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "ExplicitPtoMP/toTPs/_item", HFILL }},
    { &hf_gnm_toTp,
      { "toTp", "gnm.toTp",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "ExplicitPtoP/toTp", HFILL }},
    { &hf_gnm_oneTPorGTP,
      { "oneTPorGTP", "gnm.oneTPorGTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ExplicitTP/oneTPorGTP", HFILL }},
    { &hf_gnm_listofTPs,
      { "listofTPs", "gnm.listofTPs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExplicitTP/listofTPs", HFILL }},
    { &hf_gnm_listofTPs_item,
      { "Item", "gnm.listofTPs_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ExplicitTP/listofTPs/_item", HFILL }},
    { &hf_gnm_EquipmentHolderAddress_item,
      { "Item", "gnm.EquipmentHolderAddress_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "EquipmentHolderAddress/_item", HFILL }},
    { &hf_gnm_logicalProblem,
      { "logicalProblem", "gnm.logicalProblem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Failed/logicalProblem", HFILL }},
    { &hf_gnm_resourceProblem,
      { "resourceProblem", "gnm.resourceProblem",
        FT_UINT32, BASE_DEC, VALS(gnm_ResourceProblem_vals), 0,
        "Failed/resourceProblem", HFILL }},
    { &hf_gnm_GeneralError_item,
      { "Item", "gnm.GeneralError_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeneralError/_item", HFILL }},
    { &hf_gnm_cause,
      { "cause", "gnm.cause",
        FT_UINT32, BASE_DEC, VALS(gnm_GeneralErrorCause_vals), 0,
        "GeneralError/_item/cause", HFILL }},
    { &hf_gnm_details,
      { "details", "gnm.details",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralError/_item/details", HFILL }},
    { &hf_gnm_relatedObjects,
      { "relatedObjects", "gnm.relatedObjects",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralError/_item/relatedObjects", HFILL }},
    { &hf_gnm_relatedObjects_item,
      { "Item", "gnm.relatedObjects_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "GeneralError/_item/relatedObjects/_item", HFILL }},
    { &hf_gnm_attributeList,
      { "attributeList", "gnm.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralError/_item/attributeList", HFILL }},
    { &hf_gnm_holderEmpty,
      { "holderEmpty", "gnm.holderEmpty",
        FT_NONE, BASE_NONE, NULL, 0,
        "HolderStatus/holderEmpty", HFILL }},
    { &hf_gnm_inTheAcceptableList,
      { "inTheAcceptableList", "gnm.inTheAcceptableList",
        FT_STRING, BASE_NONE, NULL, 0,
        "HolderStatus/inTheAcceptableList", HFILL }},
    { &hf_gnm_notInTheAcceptableList,
      { "notInTheAcceptableList", "gnm.notInTheAcceptableList",
        FT_STRING, BASE_NONE, NULL, 0,
        "HolderStatus/notInTheAcceptableList", HFILL }},
    { &hf_gnm_unknownType,
      { "unknownType", "gnm.unknownType",
        FT_NONE, BASE_NONE, NULL, 0,
        "HolderStatus/unknownType", HFILL }},
    { &hf_gnm_connection,
      { "connection", "gnm.connection",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "IndividualSwitchOver/connection", HFILL }},
    { &hf_gnm_unchangedTP,
      { "unchangedTP", "gnm.unchangedTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "IndividualSwitchOver/unchangedTP", HFILL }},
    { &hf_gnm_newTP,
      { "newTP", "gnm.newTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "IndividualSwitchOver/newTP", HFILL }},
    { &hf_gnm_pass,
      { "pass", "gnm.pass",
        FT_UINT32, BASE_DEC, VALS(gnm_Connected_vals), 0,
        "IndividualResult/pass", HFILL }},
    { &hf_gnm_ListOfCharacteristicInformation_item,
      { "Item", "gnm.ListOfCharacteristicInformation_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "ListOfCharacteristicInformation/_item", HFILL }},
    { &hf_gnm_ListOfTPs_item,
      { "Item", "gnm.ListOfTPs_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ListOfTPs/_item", HFILL }},
    { &hf_gnm_problemCause,
      { "problemCause", "gnm.problemCause",
        FT_UINT32, BASE_DEC, VALS(gnm_ProblemCause_vals), 0,
        "LogicalProblem/problemCause", HFILL }},
    { &hf_gnm_incorrectInstances,
      { "incorrectInstances", "gnm.incorrectInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalProblem/incorrectInstances", HFILL }},
    { &hf_gnm_incorrectInstances_item,
      { "Item", "gnm.incorrectInstances_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "LogicalProblem/incorrectInstances/_item", HFILL }},
    { &hf_gnm_MultipleConnections_item,
      { "Item", "gnm.MultipleConnections_item",
        FT_UINT32, BASE_DEC, VALS(gnm_MultipleConnections_item_vals), 0,
        "MultipleConnections/_item", HFILL }},
    { &hf_gnm_downstreamNotConnected,
      { "downstreamNotConnected", "gnm.downstreamNotConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "MultipleConnections/_item/downstreamNotConnected", HFILL }},
    { &hf_gnm_downstreamConnected,
      { "downstreamConnected", "gnm.downstreamConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "MultipleConnections/_item/downstreamConnected", HFILL }},
    { &hf_gnm_upstreamNotConnected,
      { "upstreamNotConnected", "gnm.upstreamNotConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "MultipleConnections/_item/upstreamNotConnected", HFILL }},
    { &hf_gnm_upstreamConnected,
      { "upstreamConnected", "gnm.upstreamConnected",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "MultipleConnections/_item/upstreamConnected", HFILL }},
    { &hf_gnm_redline1,
      { "redline", "gnm.redline",
        FT_BOOLEAN, 8, NULL, 0,
        "NamedCrossConnection/redline", HFILL }},
    { &hf_gnm_name,
      { "name", "gnm.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "NamedCrossConnection/name", HFILL }},
    { &hf_gnm_numericName,
      { "numericName", "gnm.numericName",
        FT_INT32, BASE_DEC, NULL, 0,
        "NameType/numericName", HFILL }},
    { &hf_gnm_pString,
      { "pString", "gnm.pString",
        FT_STRING, BASE_NONE, NULL, 0,
        "NameType/pString", HFILL }},
    { &hf_gnm_ObjectList_item,
      { "Item", "gnm.ObjectList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectList/_item", HFILL }},
    { &hf_gnm_diverse,
      { "diverse", "gnm.diverse",
        FT_NONE, BASE_NONE, NULL, 0,
        "PhysicalPortSignalRateAndMappingList/diverse", HFILL }},
    { &hf_gnm_downstream,
      { "downstream", "gnm.downstream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysicalPortSignalRateAndMappingList/diverse/downstream", HFILL }},
    { &hf_gnm_upStream,
      { "upStream", "gnm.upStream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysicalPortSignalRateAndMappingList/diverse/upStream", HFILL }},
    { &hf_gnm_uniform,
      { "uniform", "gnm.uniform",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysicalPortSignalRateAndMappingList/uniform", HFILL }},
    { &hf_gnm_pointer,
      { "pointer", "gnm.pointer",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "PointerOrNull/pointer", HFILL }},
    { &hf_gnm_null,
      { "null", "gnm.null",
        FT_NONE, BASE_NONE, NULL, 0,
        "PointerOrNull/null", HFILL }},
    { &hf_gnm_fromTp1,
      { "fromTp", "gnm.fromTp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_gnm_toTp1,
      { "toTp", "gnm.toTp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "PointToPoint/toTp", HFILL }},
    { &hf_gnm_xCon,
      { "xCon", "gnm.xCon",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "PointToPoint/xCon", HFILL }},
    { &hf_gnm_toTps,
      { "toTps", "gnm.toTps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PointToMultipoint/toTps", HFILL }},
    { &hf_gnm_toTps_item,
      { "Item", "gnm.toTps_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PointToMultipoint/toTps/_item", HFILL }},
    { &hf_gnm_tp,
      { "tp", "gnm.tp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "PointToMultipoint/toTps/_item/tp", HFILL }},
    { &hf_gnm_xConnection,
      { "xConnection", "gnm.xConnection",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "PointToMultipoint/toTps/_item/xConnection", HFILL }},
    { &hf_gnm_mpXCon,
      { "mpXCon", "gnm.mpXCon",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "PointToMultipoint/mpXCon", HFILL }},
    { &hf_gnm_unknown,
      { "unknown", "gnm.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gnm_integerValue,
      { "integerValue", "gnm.integerValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gnm_toTPPools,
      { "toTPPools", "gnm.toTPPools",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PtoMPools/toTPPools", HFILL }},
    { &hf_gnm_notAvailable,
      { "notAvailable", "gnm.notAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelatedObjectInstance/notAvailable", HFILL }},
    { &hf_gnm_relatedObject,
      { "relatedObject", "gnm.relatedObject",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "RelatedObjectInstance/relatedObject", HFILL }},
    { &hf_gnm_RemoveTpsFromGtpInformation_item,
      { "Item", "gnm.RemoveTpsFromGtpInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveTpsFromGtpInformation/_item", HFILL }},
    { &hf_gnm_fromGtp,
      { "fromGtp", "gnm.fromGtp",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "RemoveTpsFromGtpInformation/_item/fromGtp", HFILL }},
    { &hf_gnm_tps1,
      { "tps", "gnm.tps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gnm_tps_item1,
      { "Item", "gnm.tps_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_gnm_RemoveTpsFromGtpResult_item,
      { "Item", "gnm.RemoveTpsFromGtpResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_RemoveTpsFromGtpResult_item_vals), 0,
        "RemoveTpsFromGtpResult/_item", HFILL }},
    { &hf_gnm_removed,
      { "removed", "gnm.removed",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gnm_RemoveTpsFromTpPoolInformation_item,
      { "Item", "gnm.RemoveTpsFromTpPoolInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveTpsFromTpPoolInformation/_item", HFILL }},
    { &hf_gnm_fromTpPool,
      { "fromTpPool", "gnm.fromTpPool",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "RemoveTpsFromTpPoolInformation/_item/fromTpPool", HFILL }},
    { &hf_gnm_RemoveTpsFromTpPoolResult_item,
      { "Item", "gnm.RemoveTpsFromTpPoolResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_RemoveTpsFromTpPoolResult_item_vals), 0,
        "RemoveTpsFromTpPoolResult/_item", HFILL }},
    { &hf_gnm_deletedTpPoolOrGTP,
      { "deletedTpPoolOrGTP", "gnm.deletedTpPoolOrGTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "RemoveTpsResultInformation/deletedTpPoolOrGTP", HFILL }},
    { &hf_gnm_SequenceOfObjectInstance_item,
      { "Item", "gnm.SequenceOfObjectInstance_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "SequenceOfObjectInstance/_item", HFILL }},
    { &hf_gnm_SignalRateAndMappingList_item,
      { "Item", "gnm.SignalRateAndMappingList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalRateAndMappingList/_item", HFILL }},
    { &hf_gnm_signalRate,
      { "signalRate", "gnm.signalRate",
        FT_UINT32, BASE_DEC, VALS(gnm_SignalRate_vals), 0,
        "SignalRateAndMappingList/_item/signalRate", HFILL }},
    { &hf_gnm_mappingList,
      { "mappingList", "gnm.mappingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalRateAndMappingList/_item/mappingList", HFILL }},
    { &hf_gnm_wavelength,
      { "wavelength", "gnm.wavelength",
        FT_INT32, BASE_DEC, NULL, 0,
        "SignalRateAndMappingList/_item/wavelength", HFILL }},
    { &hf_gnm_simple,
      { "simple", "gnm.simple",
        FT_STRING, BASE_NONE, NULL, 0,
        "SignalType/simple", HFILL }},
    { &hf_gnm_bundle,
      { "bundle", "gnm.bundle",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalType/bundle", HFILL }},
    { &hf_gnm_complex,
      { "complex", "gnm.complex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalType/complex", HFILL }},
    { &hf_gnm_complex_item,
      { "Item", "gnm.complex_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalType/complex/_item", HFILL }},
    { &hf_gnm_notApplicable,
      { "notApplicable", "gnm.notApplicable",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubordinateCircuitPackSoftwareLoad/notApplicable", HFILL }},
    { &hf_gnm_softwareInstances,
      { "softwareInstances", "gnm.softwareInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubordinateCircuitPackSoftwareLoad/softwareInstances", HFILL }},
    { &hf_gnm_softwareInstances_item,
      { "Item", "gnm.softwareInstances_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "SubordinateCircuitPackSoftwareLoad/softwareInstances/_item", HFILL }},
    { &hf_gnm_softwareIdentifiers,
      { "softwareIdentifiers", "gnm.softwareIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubordinateCircuitPackSoftwareLoad/softwareIdentifiers", HFILL }},
    { &hf_gnm_softwareIdentifiers_item,
      { "Item", "gnm.softwareIdentifiers_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubordinateCircuitPackSoftwareLoad/softwareIdentifiers/_item", HFILL }},
    { &hf_gnm_SupportableClientList_item,
      { "Item", "gnm.SupportableClientList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "SupportableClientList/_item", HFILL }},
    { &hf_gnm_sourceType,
      { "sourceType", "gnm.sourceType",
        FT_UINT32, BASE_DEC, VALS(gnm_T_sourceType_vals), 0,
        "SystemTiming/sourceType", HFILL }},
    { &hf_gnm_sourceID,
      { "sourceID", "gnm.sourceID",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "SystemTiming/sourceID", HFILL }},
    { &hf_gnm_primaryTimingSource,
      { "primaryTimingSource", "gnm.primaryTimingSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemTimingSource/primaryTimingSource", HFILL }},
    { &hf_gnm_secondaryTimingSource,
      { "secondaryTimingSource", "gnm.secondaryTimingSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemTimingSource/secondaryTimingSource", HFILL }},
    { &hf_gnm_SwitchOverInformation_item,
      { "Item", "gnm.SwitchOverInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SwitchOverInformation/_item", HFILL }},
    { &hf_gnm_SwitchOverResult_item,
      { "Item", "gnm.SwitchOverResult_item",
        FT_UINT32, BASE_DEC, VALS(gnm_IndividualResult_vals), 0,
        "SwitchOverResult/_item", HFILL }},
    { &hf_gnm_tPOrGTP,
      { "tPOrGTP", "gnm.tPOrGTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "TerminationPointInformation/tPOrGTP", HFILL }},
    { &hf_gnm_sourceTP,
      { "sourceTP", "gnm.sourceTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "TerminationPointInformation/sourceTP", HFILL }},
    { &hf_gnm_sinkTP,
      { "sinkTP", "gnm.sinkTP",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "TerminationPointInformation/sinkTP", HFILL }},
    { &hf_gnm_toTpOrGTP,
      { "toTpOrGTP", "gnm.toTpOrGTP",
        FT_UINT32, BASE_DEC, VALS(gnm_ExplicitTP_vals), 0,
        "ToTermSpecifier/toTpOrGTP", HFILL }},
    { &hf_gnm_toPool,
      { "toPool", "gnm.toPool",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ToTermSpecifier/toPool", HFILL }},
    { &hf_gnm_ToTPPools_item,
      { "Item", "gnm.ToTPPools_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToTPPools/_item", HFILL }},
    { &hf_gnm_tpPoolId,
      { "tpPoolId", "gnm.tpPoolId",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ToTPPools/_item/tpPoolId", HFILL }},
    { &hf_gnm_numberOfTPs,
      { "numberOfTPs", "gnm.numberOfTPs",
        FT_INT32, BASE_DEC, NULL, 0,
        "ToTPPools/_item/numberOfTPs", HFILL }},
    { &hf_gnm_tpPool,
      { "tpPool", "gnm.tpPool",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "TpsAddedToTpPool/tpPool", HFILL }},
    { &hf_gnm_TpsInGtpList_item,
      { "Item", "gnm.TpsInGtpList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "TpsInGtpList/_item", HFILL }},
    { &hf_gnm_TransmissionCharacteristics_satellite,
      { "satellite", "gnm.satellite",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gnm_TransmissionCharacteristics_dCME,
      { "dCME", "gnm.dCME",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gnm_TransmissionCharacteristics_echoControl,
      { "echoControl", "gnm.echoControl",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-gnm-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-gnm-ettarr.c ---*/

    &ett_gnm_ProbableCause,
    &ett_gnm_AvailabilityStatus,
    &ett_gnm_AttributeList,
    &ett_gnm_AdditionalInformation,
    &ett_gnm_ControlStatus,
    &ett_gnm_ManagementExtension,
    &ett_gnm_MappingList,
    &ett_gnm_Packages,
    &ett_gnm_SignalRate,
    &ett_gnm_SupportedTOClasses,
    &ett_gnm_AcceptableCircuitPackTypeList,
    &ett_gnm_AddedTps,
    &ett_gnm_SEQUENCE_OF_ObjectInstance,
    &ett_gnm_AddLeg,
    &ett_gnm_SET_OF_ToTermSpecifier,
    &ett_gnm_AddTpsToGtpInformation,
    &ett_gnm_AddTpsToGtpInformation_item,
    &ett_gnm_SEQUENCE_OF_TerminationPointInformation,
    &ett_gnm_AddTpsToGtpResult,
    &ett_gnm_AddTpsToGtpResult_item,
    &ett_gnm_AddTpsToTpPoolInformation,
    &ett_gnm_AddTpsToTpPoolInformation_item,
    &ett_gnm_SET_OF_TerminationPointInformation,
    &ett_gnm_AddTpsToTpPoolResult,
    &ett_gnm_AddTpsToTpPoolResult_item,
    &ett_gnm_AlarmSeverityAssignment,
    &ett_gnm_AlarmSeverityAssignmentList,
    &ett_gnm_Bundle,
    &ett_gnm_Connected,
    &ett_gnm_ConnectInformation,
    &ett_gnm_ConnectInformation_item,
    &ett_gnm_T_itemType,
    &ett_gnm_ConnectivityPointer,
    &ett_gnm_ConnectResult,
    &ett_gnm_ConnectResult_item,
    &ett_gnm_ConnectionType,
    &ett_gnm_ConnectionTypeBi,
    &ett_gnm_CrossConnectionObjectPointer,
    &ett_gnm_CurrentProblem,
    &ett_gnm_CurrentProblemList,
    &ett_gnm_DisconnectInformation,
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
    &ett_gnm_GeneralError,
    &ett_gnm_GeneralError_item,
    &ett_gnm_GeneralErrorCause,
    &ett_gnm_HolderStatus,
    &ett_gnm_IndividualSwitchOver,
    &ett_gnm_IndividualResult,
    &ett_gnm_ListOfCharacteristicInformation,
    &ett_gnm_ListOfTPs,
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
    &ett_gnm_RemoveTpsFromGtpInformation,
    &ett_gnm_RemoveTpsFromGtpInformation_item,
    &ett_gnm_RemoveTpsFromGtpResult,
    &ett_gnm_RemoveTpsFromGtpResult_item,
    &ett_gnm_RemoveTpsFromTpPoolInformation,
    &ett_gnm_RemoveTpsFromTpPoolInformation_item,
    &ett_gnm_RemoveTpsFromTpPoolResult,
    &ett_gnm_RemoveTpsFromTpPoolResult_item,
    &ett_gnm_RemoveTpsResultInformation,
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
    &ett_gnm_SwitchOverInformation,
    &ett_gnm_SwitchOverResult,
    &ett_gnm_TerminationPointInformation,
    &ett_gnm_ToTermSpecifier,
    &ett_gnm_ToTPPools,
    &ett_gnm_ToTPPools_item,
    &ett_gnm_TpsAddedToTpPool,
    &ett_gnm_TpsInGtpList,
    &ett_gnm_TransmissionCharacteristics,

/*--- End of included file: packet-gnm-ettarr.c ---*/

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
  register_ber_oid_dissector("2.9.3.2.7.31", dissect_AdministrativeState_PDU, proto_gnm, "administrativeState(31)");
  register_ber_oid_dissector("2.9.3.2.7.34", dissect_ControlStatus_PDU, proto_gnm, "controlStatus(34)");
  register_ber_oid_dissector("2.9.3.2.7.66", dissect_Packages_PDU, proto_gnm, "packages(66)");
  register_ber_oid_dissector("2.9.2.12.7.7", dissect_SupportedTOClasses_PDU, proto_gnm, "supportedTOClasses(7)");


/*--- End of included file: packet-gnm-dis-tab.c ---*/

	register_ber_oid_dissector("0.0.13.3100.0.7.9", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientConnection(9)");
	register_ber_oid_dissector("0.0.13.3100.0.7.10", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientTrail(10)");
	register_ber_oid_dissector("0.0.13.3100.0.7.31", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");
	register_ber_oid_dissector("0.0.13.3100.0.7.46", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");

}
