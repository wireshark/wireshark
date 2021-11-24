/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lix2.c                                                              */
/* asn2wrs.py -b -p lix2 -c ./lix2.cnf -s ./packet-lix2-template -D . -O ../.. lix2.asn */

/* Input file: packet-lix2-template.c */

#line 1 "./asn1/lix2/packet-lix2-template.c"
/* packet-lix2-template.c
 * Routines for Lawful Interception X2 xIRI event dissection
 *
 * See 3GPP TS33.128.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/asn1.h>

#include "packet-ber.h"

#define PNAME  "X2 xIRI payload"
#define PSNAME "xIRI"
#define PFNAME "xiri"

void proto_reg_handoff_lix2(void);
void proto_register_lix2(void);

/* Initialize the protocol and registered fields */
static int proto_lix2 = -1;
static dissector_handle_t lix2_handle = NULL;



/*--- Included file: packet-lix2-hf.c ---*/
#line 1 "./asn1/lix2/packet-lix2-hf.c"
static int hf_lix2_XIRIPayload_PDU = -1;          /* XIRIPayload */
static int hf_lix2_xIRIPayloadOID = -1;           /* RELATIVE_OID */
static int hf_lix2_event = -1;                    /* XIRIEvent */
static int hf_lix2_registration = -1;             /* AMFRegistration */
static int hf_lix2_deregistration = -1;           /* AMFDeregistration */
static int hf_lix2_locationUpdate = -1;           /* AMFLocationUpdate */
static int hf_lix2_startOfInterceptionWithRegisteredUE = -1;  /* AMFStartOfInterceptionWithRegisteredUE */
static int hf_lix2_unsuccessfulAMProcedure = -1;  /* AMFUnsuccessfulProcedure */
static int hf_lix2_pDUSessionEstablishment = -1;  /* SMFPDUSessionEstablishment */
static int hf_lix2_pDUSessionModification = -1;   /* SMFPDUSessionModification */
static int hf_lix2_pDUSessionRelease = -1;        /* SMFPDUSessionRelease */
static int hf_lix2_startOfInterceptionWithEstablishedPDUSession = -1;  /* SMFStartOfInterceptionWithEstablishedPDUSession */
static int hf_lix2_unsuccessfulSMProcedure = -1;  /* SMFUnsuccessfulProcedure */
static int hf_lix2_servingSystemMessage = -1;     /* UDMServingSystemMessage */
static int hf_lix2_sMSMessage = -1;               /* SMSMessage */
static int hf_lix2_lALSReport = -1;               /* LALSReport */
static int hf_lix2_pDHeaderReport = -1;           /* PDHeaderReport */
static int hf_lix2_pDSummaryReport = -1;          /* PDSummaryReport */
static int hf_lix2_mMSSend = -1;                  /* MMSSend */
static int hf_lix2_mMSSendByNonLocalTarget = -1;  /* MMSSendByNonLocalTarget */
static int hf_lix2_mMSNotification = -1;          /* MMSNotification */
static int hf_lix2_mMSSendToNonLocalTarget = -1;  /* MMSSendToNonLocalTarget */
static int hf_lix2_mMSNotificationResponse = -1;  /* MMSNotificationResponse */
static int hf_lix2_mMSRetrieval = -1;             /* MMSRetrieval */
static int hf_lix2_mMSDeliveryAck = -1;           /* MMSDeliveryAck */
static int hf_lix2_mMSForward = -1;               /* MMSForward */
static int hf_lix2_mMSDeleteFromRelay = -1;       /* MMSDeleteFromRelay */
static int hf_lix2_mMSDeliveryReport = -1;        /* MMSDeliveryReport */
static int hf_lix2_mMSDeliveryReportNonLocalTarget = -1;  /* MMSDeliveryReportNonLocalTarget */
static int hf_lix2_mMSReadReport = -1;            /* MMSReadReport */
static int hf_lix2_mMSReadReportNonLocalTarget = -1;  /* MMSReadReportNonLocalTarget */
static int hf_lix2_mMSCancel = -1;                /* MMSCancel */
static int hf_lix2_mMSMBoxStore = -1;             /* MMSMBoxStore */
static int hf_lix2_mMSMBoxUpload = -1;            /* MMSMBoxUpload */
static int hf_lix2_mMSMBoxDelete = -1;            /* MMSMBoxDelete */
static int hf_lix2_mMSMBoxViewRequest = -1;       /* MMSMBoxViewRequest */
static int hf_lix2_mMSMBoxViewResponse = -1;      /* MMSMBoxViewResponse */
static int hf_lix2_pTCRegistration = -1;          /* PTCRegistration */
static int hf_lix2_pTCSessionInitiation = -1;     /* PTCSessionInitiation */
static int hf_lix2_pTCSessionAbandon = -1;        /* PTCSessionAbandon */
static int hf_lix2_pTCSessionStart = -1;          /* PTCSessionStart */
static int hf_lix2_pTCSessionEnd = -1;            /* PTCSessionEnd */
static int hf_lix2_pTCStartOfInterception = -1;   /* PTCStartOfInterception */
static int hf_lix2_pTCPreEstablishedSession = -1;  /* PTCPreEstablishedSession */
static int hf_lix2_pTCInstantPersonalAlert = -1;  /* PTCInstantPersonalAlert */
static int hf_lix2_pTCPartyJoin = -1;             /* PTCPartyJoin */
static int hf_lix2_pTCPartyDrop = -1;             /* PTCPartyDrop */
static int hf_lix2_pTCPartyHold = -1;             /* PTCPartyHold */
static int hf_lix2_pTCMediaModification = -1;     /* PTCMediaModification */
static int hf_lix2_pTCGroupAdvertisement = -1;    /* PTCGroupAdvertisement */
static int hf_lix2_pTCFloorControl = -1;          /* PTCFloorControl */
static int hf_lix2_pTCTargetPresence = -1;        /* PTCTargetPresence */
static int hf_lix2_pTCParticipantPresence = -1;   /* PTCParticipantPresence */
static int hf_lix2_pTCListManagement = -1;        /* PTCListManagement */
static int hf_lix2_pTCAccessPolicy = -1;          /* PTCAccessPolicy */
static int hf_lix2_subscriberRecordChangeMessage = -1;  /* UDMSubscriberRecordChangeMessage */
static int hf_lix2_cancelLocationMessage = -1;    /* UDMCancelLocationMessage */
static int hf_lix2_sMSReport = -1;                /* SMSReport */
static int hf_lix2_sMFMAPDUSessionEstablishment = -1;  /* SMFMAPDUSessionEstablishment */
static int hf_lix2_sMFMAPDUSessionModification = -1;  /* SMFMAPDUSessionModification */
static int hf_lix2_sMFMAPDUSessionRelease = -1;   /* SMFMAPDUSessionRelease */
static int hf_lix2_startOfInterceptionWithEstablishedMAPDUSession = -1;  /* SMFStartOfInterceptionWithEstablishedMAPDUSession */
static int hf_lix2_unsuccessfulMASMProcedure = -1;  /* SMFMAUnsuccessfulProcedure */
static int hf_lix2_aMFIdentifierAssocation = -1;  /* AMFIdentifierAssocation */
static int hf_lix2_mMEIdentifierAssocation = -1;  /* MMEIdentifierAssocation */
static int hf_lix2_sMFPDUtoMAPDUSessionModification = -1;  /* SMFPDUtoMAPDUSessionModification */
static int hf_lix2_nEFPDUSessionEstablishment = -1;  /* NEFPDUSessionEstablishment */
static int hf_lix2_nEFPDUSessionModification = -1;  /* NEFPDUSessionModification */
static int hf_lix2_nEFPDUSessionRelease = -1;     /* NEFPDUSessionRelease */
static int hf_lix2_nEFUnsuccessfulProcedure = -1;  /* NEFUnsuccessfulProcedure */
static int hf_lix2_nEFStartOfInterceptionWithEstablishedPDUSession = -1;  /* NEFStartOfInterceptionWithEstablishedPDUSession */
static int hf_lix2_nEFdeviceTrigger = -1;         /* NEFDeviceTrigger */
static int hf_lix2_nEFdeviceTriggerReplace = -1;  /* NEFDeviceTriggerReplace */
static int hf_lix2_nEFdeviceTriggerCancellation = -1;  /* NEFDeviceTriggerCancellation */
static int hf_lix2_nEFdeviceTriggerReportNotify = -1;  /* NEFDeviceTriggerReportNotify */
static int hf_lix2_nEFMSISDNLessMOSMS = -1;       /* NEFMSISDNLessMOSMS */
static int hf_lix2_nEFExpectedUEBehaviourUpdate = -1;  /* NEFExpectedUEBehaviourUpdate */
static int hf_lix2_sCEFPDNConnectionEstablishment = -1;  /* SCEFPDNConnectionEstablishment */
static int hf_lix2_sCEFPDNConnectionUpdate = -1;  /* SCEFPDNConnectionUpdate */
static int hf_lix2_sCEFPDNConnectionRelease = -1;  /* SCEFPDNConnectionRelease */
static int hf_lix2_sCEFUnsuccessfulProcedure = -1;  /* SCEFUnsuccessfulProcedure */
static int hf_lix2_sCEFStartOfInterceptionWithEstablishedPDNConnection = -1;  /* SCEFStartOfInterceptionWithEstablishedPDNConnection */
static int hf_lix2_sCEFdeviceTrigger = -1;        /* SCEFDeviceTrigger */
static int hf_lix2_sCEFdeviceTriggerReplace = -1;  /* SCEFDeviceTriggerReplace */
static int hf_lix2_sCEFdeviceTriggerCancellation = -1;  /* SCEFDeviceTriggerCancellation */
static int hf_lix2_sCEFdeviceTriggerReportNotify = -1;  /* SCEFDeviceTriggerReportNotify */
static int hf_lix2_sCEFMSISDNLessMOSMS = -1;      /* SCEFMSISDNLessMOSMS */
static int hf_lix2_sCEFCommunicationPatternUpdate = -1;  /* SCEFCommunicationPatternUpdate */
static int hf_lix2_mMEAttach = -1;                /* MMEAttach */
static int hf_lix2_mMEDetach = -1;                /* MMEDetach */
static int hf_lix2_mMELocationUpdate = -1;        /* MMELocationUpdate */
static int hf_lix2_mMEStartOfInterceptionWithEPSAttachedUE = -1;  /* MMEStartOfInterceptionWithEPSAttachedUE */
static int hf_lix2_mMEUnsuccessfulProcedure = -1;  /* MMEUnsuccessfulProcedure */
static int hf_lix2_iRIPayloadOID = -1;            /* RELATIVE_OID */
static int hf_lix2_event_01 = -1;                 /* IRIEvent */
static int hf_lix2_targetIdentifiers = -1;        /* SEQUENCE_OF_IRITargetIdentifier */
static int hf_lix2_targetIdentifiers_item = -1;   /* IRITargetIdentifier */
static int hf_lix2_unsuccessfulRegistrationProcedure = -1;  /* AMFUnsuccessfulProcedure */
static int hf_lix2_unsuccessfulSessionProcedure = -1;  /* SMFUnsuccessfulProcedure */
static int hf_lix2_mDFCellSiteReport = -1;        /* MDFCellSiteReport */
static int hf_lix2_identifier = -1;               /* TargetIdentifier */
static int hf_lix2_provenance = -1;               /* TargetIdentifierProvenance */
static int hf_lix2_cCPayloadOID = -1;             /* RELATIVE_OID */
static int hf_lix2_pDU = -1;                      /* CCPDU */
static int hf_lix2_uPFCCPDU = -1;                 /* UPFCCPDU */
static int hf_lix2_extendedUPFCCPDU = -1;         /* ExtendedUPFCCPDU */
static int hf_lix2_mMSCCPDU = -1;                 /* MMSCCPDU */
static int hf_lix2_nIDDCCPDU = -1;                /* NIDDCCPDU */
static int hf_lix2_lINotificationPayloadOID = -1;  /* RELATIVE_OID */
static int hf_lix2_notification = -1;             /* LINotificationMessage */
static int hf_lix2_lINotification = -1;           /* LINotification */
static int hf_lix2_sUPI = -1;                     /* SUPI */
static int hf_lix2_gPSI = -1;                     /* GPSI */
static int hf_lix2_pDUSessionID = -1;             /* PDUSessionID */
static int hf_lix2_sNSSAI = -1;                   /* SNSSAI */
static int hf_lix2_nEFID = -1;                    /* NEFID */
static int hf_lix2_dNN = -1;                      /* DNN */
static int hf_lix2_rDSSupport = -1;               /* RDSSupport */
static int hf_lix2_sMFID = -1;                    /* SMFID */
static int hf_lix2_aFID = -1;                     /* AFID */
static int hf_lix2_initiator = -1;                /* Initiator */
static int hf_lix2_rDSSourcePortNumber = -1;      /* RDSPortNumber */
static int hf_lix2_rDSDestinationPortNumber = -1;  /* RDSPortNumber */
static int hf_lix2_applicationID = -1;            /* ApplicationID */
static int hf_lix2_rDSAction = -1;                /* RDSAction */
static int hf_lix2_serializationFormat = -1;      /* SerializationFormat */
static int hf_lix2_timeOfFirstPacket = -1;        /* Timestamp */
static int hf_lix2_timeOfLastPacket = -1;         /* Timestamp */
static int hf_lix2_uplinkVolume = -1;             /* INTEGER */
static int hf_lix2_downlinkVolume = -1;           /* INTEGER */
static int hf_lix2_releaseCause = -1;             /* NEFReleaseCause */
static int hf_lix2_failureCause = -1;             /* NEFFailureCause */
static int hf_lix2_triggerId = -1;                /* TriggerID */
static int hf_lix2_triggerPayload = -1;           /* TriggerPayload */
static int hf_lix2_validityPeriod = -1;           /* INTEGER */
static int hf_lix2_priorityDT = -1;               /* PriorityDT */
static int hf_lix2_sourcePortId = -1;             /* PortNumber */
static int hf_lix2_destinationPortId = -1;        /* PortNumber */
static int hf_lix2_deviceTriggerDeliveryResult = -1;  /* DeviceTriggerDeliveryResult */
static int hf_lix2_terminatingSMSParty = -1;      /* AFID */
static int hf_lix2_sMS = -1;                      /* SMSTPDUData */
static int hf_lix2_sourcePort = -1;               /* PortNumber */
static int hf_lix2_destinationPort = -1;          /* PortNumber */
static int hf_lix2_expectedUEMovingTrajectory = -1;  /* SEQUENCE_OF_UMTLocationArea5G */
static int hf_lix2_expectedUEMovingTrajectory_item = -1;  /* UMTLocationArea5G */
static int hf_lix2_stationaryIndication = -1;     /* StationaryIndication */
static int hf_lix2_communicationDurationTime = -1;  /* INTEGER */
static int hf_lix2_periodicTime = -1;             /* INTEGER */
static int hf_lix2_scheduledCommunicationTime = -1;  /* ScheduledCommunicationTime */
static int hf_lix2_scheduledCommunicationType = -1;  /* ScheduledCommunicationType */
static int hf_lix2_batteryIndication = -1;        /* BatteryIndication */
static int hf_lix2_trafficProfile = -1;           /* TrafficProfile */
static int hf_lix2_expectedTimeAndDayOfWeekInTrajectory = -1;  /* SEQUENCE_OF_UMTLocationArea5G */
static int hf_lix2_expectedTimeAndDayOfWeekInTrajectory_item = -1;  /* UMTLocationArea5G */
static int hf_lix2_validityTime = -1;             /* Timestamp */
static int hf_lix2_days = -1;                     /* SEQUENCE_OF_Daytime */
static int hf_lix2_days_item = -1;                /* Daytime */
static int hf_lix2_timeOfDay = -1;                /* Daytime */
static int hf_lix2_durationSec = -1;              /* INTEGER */
static int hf_lix2_location = -1;                 /* NRLocation */
static int hf_lix2_daysOfWeek = -1;               /* Day */
static int hf_lix2_timeOfDayStart = -1;           /* Timestamp */
static int hf_lix2_timeOfDayEnd = -1;             /* Timestamp */
static int hf_lix2_iMSI = -1;                     /* IMSI */
static int hf_lix2_mSISDN = -1;                   /* MSISDN */
static int hf_lix2_externalIdentifier = -1;       /* NAI */
static int hf_lix2_iMEI = -1;                     /* IMEI */
static int hf_lix2_ePSBearerID = -1;              /* EPSBearerID */
static int hf_lix2_sCEFID = -1;                   /* SCEFID */
static int hf_lix2_aPN = -1;                      /* APN */
static int hf_lix2_sCSASID = -1;                  /* SCSASID */
static int hf_lix2_releaseCause_01 = -1;          /* SCEFReleaseCause */
static int hf_lix2_failureCause_01 = -1;          /* SCEFFailureCause */
static int hf_lix2_externalIdentifie = -1;        /* NAI */
static int hf_lix2_terminatingSMSParty_01 = -1;   /* SCSASID */
static int hf_lix2_periodicCommunicationIndicator = -1;  /* PeriodicCommunicationIndicator */
static int hf_lix2_registrationType = -1;         /* AMFRegistrationType */
static int hf_lix2_registrationResult = -1;       /* AMFRegistrationResult */
static int hf_lix2_slice = -1;                    /* Slice */
static int hf_lix2_sUCI = -1;                     /* SUCI */
static int hf_lix2_pEI = -1;                      /* PEI */
static int hf_lix2_gUTI = -1;                     /* FiveGGUTI */
static int hf_lix2_location_01 = -1;              /* Location */
static int hf_lix2_non3GPPAccessEndpoint = -1;    /* UEEndpointAddress */
static int hf_lix2_fiveGSTAIList = -1;            /* TAIList */
static int hf_lix2_sMSOverNasIndicator = -1;      /* SMSOverNASIndicator */
static int hf_lix2_oldGUTI = -1;                  /* EPS5GGUTI */
static int hf_lix2_eMM5GRegStatus = -1;           /* EMM5GMMStatus */
static int hf_lix2_deregistrationDirection = -1;  /* AMFDirection */
static int hf_lix2_accessType = -1;               /* AccessType */
static int hf_lix2_cause = -1;                    /* FiveGMMCause */
static int hf_lix2_switchOffIndicator = -1;       /* SwitchOffIndicator */
static int hf_lix2_reRegRequiredIndicator = -1;   /* ReRegRequiredIndicator */
static int hf_lix2_sMSOverNASIndicator = -1;      /* SMSOverNASIndicator */
static int hf_lix2_timeOfRegistration = -1;       /* Timestamp */
static int hf_lix2_failedProcedureType = -1;      /* AMFFailedProcedureType */
static int hf_lix2_failureCause_02 = -1;          /* AMFFailureCause */
static int hf_lix2_requestedSlice = -1;           /* NSSAI */
static int hf_lix2_aMFRegionID = -1;              /* AMFRegionID */
static int hf_lix2_aMFSetID = -1;                 /* AMFSetID */
static int hf_lix2_aMFPointer = -1;               /* AMFPointer */
static int hf_lix2_fiveGMMCause = -1;             /* FiveGMMCause */
static int hf_lix2_fiveGSMCause = -1;             /* FiveGSMCause */
static int hf_lix2_sUPIUnauthenticated = -1;      /* SUPIUnauthenticatedIndication */
static int hf_lix2_gTPTunnelID = -1;              /* FTEID */
static int hf_lix2_pDUSessionType = -1;           /* PDUSessionType */
static int hf_lix2_uEEndpoint = -1;               /* SEQUENCE_OF_UEEndpointAddress */
static int hf_lix2_uEEndpoint_item = -1;          /* UEEndpointAddress */
static int hf_lix2_aMFID = -1;                    /* AMFID */
static int hf_lix2_hSMFURI = -1;                  /* HSMFURI */
static int hf_lix2_requestType = -1;              /* FiveGSMRequestType */
static int hf_lix2_rATType = -1;                  /* RATType */
static int hf_lix2_sMPDUDNRequest = -1;           /* SMPDUDNRequest */
static int hf_lix2_uEEPSPDNConnection = -1;       /* UEEPSPDNConnection */
static int hf_lix2_cause_01 = -1;                 /* SMFErrorCodes */
static int hf_lix2_timeOfSessionEstablishment = -1;  /* Timestamp */
static int hf_lix2_failedProcedureType_01 = -1;   /* SMFFailedProcedureType */
static int hf_lix2_failureCause_03 = -1;          /* FiveGSMCause */
static int hf_lix2_requestIndication = -1;        /* RequestIndication */
static int hf_lix2_aTSSSContainer = -1;           /* ATSSSContainer */
static int hf_lix2_accessInfo = -1;               /* SEQUENCE_OF_AccessInfo */
static int hf_lix2_accessInfo_item = -1;          /* AccessInfo */
static int hf_lix2_servingNetwork = -1;           /* SMFServingNetwork */
static int hf_lix2_oldPDUSessionID = -1;          /* PDUSessionID */
static int hf_lix2_mAUpgradeIndication = -1;      /* SMFMAUpgradeIndication */
static int hf_lix2_ePSPDNCnxInfo = -1;            /* SMFEPSPDNCnxInfo */
static int hf_lix2_mAAcceptedIndication = -1;     /* SMFMAAcceptedIndication */
static int hf_lix2_pLMNID = -1;                   /* PLMNID */
static int hf_lix2_nID = -1;                      /* NID */
static int hf_lix2_establishmentStatus = -1;      /* EstablishmentStatus */
static int hf_lix2_aNTypeToReactivate = -1;       /* AccessType */
static int hf_lix2_payload = -1;                  /* UPFCCPDUPayload */
static int hf_lix2_qFI = -1;                      /* QFI */
static int hf_lix2_uPFIPCC = -1;                  /* OCTET_STRING */
static int hf_lix2_uPFEthernetCC = -1;            /* OCTET_STRING */
static int hf_lix2_uPFUnstructuredCC = -1;        /* OCTET_STRING */
static int hf_lix2_gUAMI = -1;                    /* GUAMI */
static int hf_lix2_gUMMEI = -1;                   /* GUMMEI */
static int hf_lix2_servingSystemMethod = -1;      /* UDMServingSystemMethod */
static int hf_lix2_serviceID = -1;                /* ServiceID */
static int hf_lix2_oldPEI = -1;                   /* PEI */
static int hf_lix2_oldSUPI = -1;                  /* SUPI */
static int hf_lix2_oldGPSI = -1;                  /* GPSI */
static int hf_lix2_oldserviceID = -1;             /* ServiceID */
static int hf_lix2_subscriberRecordChangeMethod = -1;  /* UDMSubscriberRecordChangeMethod */
static int hf_lix2_cancelLocationMethod = -1;     /* UDMCancelLocationMethod */
static int hf_lix2_nSSAI = -1;                    /* NSSAI */
static int hf_lix2_cAGID = -1;                    /* SEQUENCE_OF_CAGID */
static int hf_lix2_cAGID_item = -1;               /* CAGID */
static int hf_lix2_originatingSMSParty = -1;      /* SMSParty */
static int hf_lix2_terminatingSMSParty_02 = -1;   /* SMSParty */
static int hf_lix2_direction = -1;                /* Direction */
static int hf_lix2_linkTransferStatus = -1;       /* SMSTransferStatus */
static int hf_lix2_otherMessage = -1;             /* SMSOtherMessageIndication */
static int hf_lix2_peerNFAddress = -1;            /* SMSNFAddress */
static int hf_lix2_peerNFType = -1;               /* SMSNFType */
static int hf_lix2_sMSTPDUData = -1;              /* SMSTPDUData */
static int hf_lix2_messageType = -1;              /* SMSMessageType */
static int hf_lix2_rPMessageReference = -1;       /* SMSRPMessageReference */
static int hf_lix2_sMSAddress = -1;               /* SMSAddress */
static int hf_lix2_iPAddress = -1;                /* IPAddress */
static int hf_lix2_e164Number = -1;               /* E164Number */
static int hf_lix2_sMSTPDU = -1;                  /* SMSTPDU */
static int hf_lix2_truncatedSMSTPDU = -1;         /* TruncatedSMSTPDU */
static int hf_lix2_transactionID = -1;            /* UTF8String */
static int hf_lix2_version = -1;                  /* MMSVersion */
static int hf_lix2_dateTime = -1;                 /* Timestamp */
static int hf_lix2_originatingMMSParty = -1;      /* MMSParty */
static int hf_lix2_terminatingMMSParty = -1;      /* SEQUENCE_OF_MMSParty */
static int hf_lix2_terminatingMMSParty_item = -1;  /* MMSParty */
static int hf_lix2_cCRecipients = -1;             /* SEQUENCE_OF_MMSParty */
static int hf_lix2_cCRecipients_item = -1;        /* MMSParty */
static int hf_lix2_bCCRecipients = -1;            /* SEQUENCE_OF_MMSParty */
static int hf_lix2_bCCRecipients_item = -1;       /* MMSParty */
static int hf_lix2_direction_01 = -1;             /* MMSDirection */
static int hf_lix2_subject = -1;                  /* MMSSubject */
static int hf_lix2_messageClass = -1;             /* MMSMessageClass */
static int hf_lix2_expiry = -1;                   /* MMSExpiry */
static int hf_lix2_desiredDeliveryTime = -1;      /* Timestamp */
static int hf_lix2_priority = -1;                 /* MMSPriority */
static int hf_lix2_senderVisibility = -1;         /* BOOLEAN */
static int hf_lix2_deliveryReport = -1;           /* BOOLEAN */
static int hf_lix2_readReport = -1;               /* BOOLEAN */
static int hf_lix2_store = -1;                    /* BOOLEAN */
static int hf_lix2_state = -1;                    /* MMState */
static int hf_lix2_flags = -1;                    /* MMFlags */
static int hf_lix2_replyCharging = -1;            /* MMSReplyCharging */
static int hf_lix2_applicID = -1;                 /* UTF8String */
static int hf_lix2_replyApplicID = -1;            /* UTF8String */
static int hf_lix2_auxApplicInfo = -1;            /* UTF8String */
static int hf_lix2_contentClass = -1;             /* MMSContentClass */
static int hf_lix2_dRMContent = -1;               /* BOOLEAN */
static int hf_lix2_adaptationAllowed = -1;        /* MMSAdaptation */
static int hf_lix2_contentType = -1;              /* MMSContentType */
static int hf_lix2_responseStatus = -1;           /* MMSResponseStatus */
static int hf_lix2_responseStatusText = -1;       /* UTF8String */
static int hf_lix2_messageID = -1;                /* UTF8String */
static int hf_lix2_forwardCount = -1;             /* INTEGER */
static int hf_lix2_previouslySentBy = -1;         /* MMSPreviouslySentBy */
static int hf_lix2_prevSentByDateTime = -1;       /* Timestamp */
static int hf_lix2_deliveryReportRequested = -1;  /* BOOLEAN */
static int hf_lix2_stored = -1;                   /* BOOLEAN */
static int hf_lix2_messageSize = -1;              /* INTEGER */
static int hf_lix2_status = -1;                   /* MMStatus */
static int hf_lix2_reportAllowed = -1;            /* BOOLEAN */
static int hf_lix2_retrieveStatus = -1;           /* MMSRetrieveStatus */
static int hf_lix2_retrieveStatusText = -1;       /* UTF8String */
static int hf_lix2_replaceID = -1;                /* UTF8String */
static int hf_lix2_contentType_01 = -1;           /* UTF8String */
static int hf_lix2_deliveryReportAllowed = -1;    /* BOOLEAN */
static int hf_lix2_contentLocationReq = -1;       /* UTF8String */
static int hf_lix2_contentLocationConf = -1;      /* UTF8String */
static int hf_lix2_storeStatus = -1;              /* MMSStoreStatus */
static int hf_lix2_storeStatusText = -1;          /* UTF8String */
static int hf_lix2_contentLocationReq_01 = -1;    /* T_contentLocationReq */
static int hf_lix2_contentLocationReq_item = -1;  /* UTF8String */
static int hf_lix2_contentLocationConf_01 = -1;   /* T_contentLocationConf */
static int hf_lix2_contentLocationConf_item = -1;  /* UTF8String */
static int hf_lix2_deleteResponseStatus = -1;     /* MMSDeleteResponseStatus */
static int hf_lix2_deleteResponseText = -1;       /* T_deleteResponseText */
static int hf_lix2_deleteResponseText_item = -1;  /* UTF8String */
static int hf_lix2_contentLocation = -1;          /* UTF8String */
static int hf_lix2_mMessages = -1;                /* SEQUENCE_OF_MMBoxDescription */
static int hf_lix2_mMessages_item = -1;           /* MMBoxDescription */
static int hf_lix2_contentLocationReq_02 = -1;    /* T_contentLocationReq_01 */
static int hf_lix2_contentLocationConf_02 = -1;   /* T_contentLocationConf_01 */
static int hf_lix2_responseStatus_01 = -1;        /* MMSDeleteResponseStatus */
static int hf_lix2_mMSDateTime = -1;              /* Timestamp */
static int hf_lix2_forwardToOriginator = -1;      /* BOOLEAN */
static int hf_lix2_statusExtension = -1;          /* MMStatusExtension */
static int hf_lix2_statusText = -1;               /* MMStatusText */
static int hf_lix2_originatingMMSParty_01 = -1;   /* SEQUENCE_OF_MMSParty */
static int hf_lix2_originatingMMSParty_item = -1;  /* MMSParty */
static int hf_lix2_readStatus = -1;               /* MMSReadStatus */
static int hf_lix2_readStatusText = -1;           /* MMSReadStatusText */
static int hf_lix2_cancelID = -1;                 /* UTF8String */
static int hf_lix2_state_01 = -1;                 /* SEQUENCE_OF_MMState */
static int hf_lix2_state_item = -1;               /* MMState */
static int hf_lix2_flags_01 = -1;                 /* SEQUENCE_OF_MMFlags */
static int hf_lix2_flags_item = -1;               /* MMFlags */
static int hf_lix2_start = -1;                    /* INTEGER */
static int hf_lix2_limit = -1;                    /* INTEGER */
static int hf_lix2_attributes = -1;               /* T_attributes */
static int hf_lix2_attributes_item = -1;          /* UTF8String */
static int hf_lix2_totals = -1;                   /* INTEGER */
static int hf_lix2_quotas = -1;                   /* MMSQuota */
static int hf_lix2_attributes_01 = -1;            /* T_attributes_01 */
static int hf_lix2_mMSTotals = -1;                /* BOOLEAN */
static int hf_lix2_mMSQuotas = -1;                /* BOOLEAN */
static int hf_lix2_deliveryTime = -1;             /* Timestamp */
static int hf_lix2_previouslySentByDateTime = -1;  /* Timestamp */
static int hf_lix2_mMSContent = -1;               /* OCTET_STRING */
static int hf_lix2_allowed = -1;                  /* BOOLEAN */
static int hf_lix2_overriden = -1;                /* BOOLEAN */
static int hf_lix2_reference = -1;                /* UTF8String */
static int hf_lix2_parameter = -1;                /* UTF8String */
static int hf_lix2_value = -1;                    /* UTF8String */
static int hf_lix2_expiryPeriod = -1;             /* INTEGER */
static int hf_lix2_periodFormat = -1;             /* MMSPeriodFormat */
static int hf_lix2_length = -1;                   /* INTEGER */
static int hf_lix2_flag = -1;                     /* MMStateFlag */
static int hf_lix2_flagString = -1;               /* UTF8String */
static int hf_lix2_mMSPartyIDs = -1;              /* SEQUENCE_OF_MMSPartyID */
static int hf_lix2_mMSPartyIDs_item = -1;         /* MMSPartyID */
static int hf_lix2_nonLocalID = -1;               /* NonLocalID */
static int hf_lix2_emailAddress = -1;             /* EmailAddress */
static int hf_lix2_iMPU = -1;                     /* IMPU */
static int hf_lix2_iMPI = -1;                     /* IMPI */
static int hf_lix2_previouslySentByParty = -1;    /* MMSParty */
static int hf_lix2_sequenceNumber = -1;           /* INTEGER */
static int hf_lix2_previousSendDateTime = -1;     /* Timestamp */
static int hf_lix2_MMSPreviouslySentBy_item = -1;  /* MMSPreviouslySent */
static int hf_lix2_quota = -1;                    /* INTEGER */
static int hf_lix2_quotaUnit = -1;                /* MMSQuotaUnit */
static int hf_lix2_majorVersion = -1;             /* INTEGER */
static int hf_lix2_minorVersion = -1;             /* INTEGER */
static int hf_lix2_pTCTargetInformation = -1;     /* PTCTargetInformation */
static int hf_lix2_pTCServerURI = -1;             /* UTF8String */
static int hf_lix2_pTCRegistrationRequest = -1;   /* PTCRegistrationRequest */
static int hf_lix2_pTCRegistrationOutcome = -1;   /* PTCRegistrationOutcome */
static int hf_lix2_pTCDirection = -1;             /* Direction */
static int hf_lix2_pTCSessionInfo = -1;           /* PTCSessionInfo */
static int hf_lix2_pTCOriginatingID = -1;         /* PTCTargetInformation */
static int hf_lix2_pTCParticipants = -1;          /* SEQUENCE_OF_PTCTargetInformation */
static int hf_lix2_pTCParticipants_item = -1;     /* PTCTargetInformation */
static int hf_lix2_pTCParticipantPresenceStatus = -1;  /* MultipleParticipantPresenceStatus */
static int hf_lix2_pTCBearerCapability = -1;      /* UTF8String */
static int hf_lix2_pTCHost = -1;                  /* PTCTargetInformation */
static int hf_lix2_pTCAbandonCause = -1;          /* INTEGER */
static int hf_lix2_pTCSessionEndCause = -1;       /* PTCSessionEndCause */
static int hf_lix2_preEstSessionID = -1;          /* PTCSessionInfo */
static int hf_lix2_pTCMediaStreamAvail = -1;      /* BOOLEAN */
static int hf_lix2_rTPSetting = -1;               /* RTPSetting */
static int hf_lix2_pTCMediaCapability = -1;       /* UTF8String */
static int hf_lix2_pTCPreEstSessionID = -1;       /* PTCSessionInfo */
static int hf_lix2_pTCPreEstStatus = -1;          /* PTCPreEstStatus */
static int hf_lix2_pTCFailureCode = -1;           /* PTCFailureCode */
static int hf_lix2_pTCIPAPartyID = -1;            /* PTCTargetInformation */
static int hf_lix2_pTCIPADirection = -1;          /* Direction */
static int hf_lix2_pTCPartyDrop_01 = -1;          /* PTCTargetInformation */
static int hf_lix2_pTCParticipantPresenceStatus_01 = -1;  /* PTCParticipantPresenceStatus */
static int hf_lix2_pTCHoldID = -1;                /* SEQUENCE_OF_PTCTargetInformation */
static int hf_lix2_pTCHoldID_item = -1;           /* PTCTargetInformation */
static int hf_lix2_pTCHoldRetrieveInd = -1;       /* BOOLEAN */
static int hf_lix2_pTCIDList = -1;                /* SEQUENCE_OF_PTCTargetInformation */
static int hf_lix2_pTCIDList_item = -1;           /* PTCTargetInformation */
static int hf_lix2_pTCGroupAuthRule = -1;         /* PTCGroupAuthRule */
static int hf_lix2_pTCGroupAdSender = -1;         /* PTCTargetInformation */
static int hf_lix2_pTCGroupNickname = -1;         /* UTF8String */
static int hf_lix2_pTCSessioninfo = -1;           /* PTCSessionInfo */
static int hf_lix2_pTCFloorActivity = -1;         /* SEQUENCE_OF_PTCFloorActivity */
static int hf_lix2_pTCFloorActivity_item = -1;    /* PTCFloorActivity */
static int hf_lix2_pTCFloorSpeakerID = -1;        /* PTCTargetInformation */
static int hf_lix2_pTCMaxTBTime = -1;             /* INTEGER */
static int hf_lix2_pTCQueuedFloorControl = -1;    /* BOOLEAN */
static int hf_lix2_pTCQueuedPosition = -1;        /* INTEGER */
static int hf_lix2_pTCTalkBurstPriority = -1;     /* PTCTBPriorityLevel */
static int hf_lix2_pTCTalkBurstReason = -1;       /* PTCTBReasonCode */
static int hf_lix2_pTCTargetPresenceStatus = -1;  /* PTCParticipantPresenceStatus */
static int hf_lix2_pTCListManagementType = -1;    /* PTCListManagementType */
static int hf_lix2_pTCListManagementAction = -1;  /* PTCListManagementAction */
static int hf_lix2_pTCListManagementFailure = -1;  /* PTCListManagementFailure */
static int hf_lix2_pTCContactID = -1;             /* PTCTargetInformation */
static int hf_lix2_pTCIDList_01 = -1;             /* SEQUENCE_OF_PTCIDList */
static int hf_lix2_pTCIDList_item_01 = -1;        /* PTCIDList */
static int hf_lix2_pTCAccessPolicyType = -1;      /* PTCAccessPolicyType */
static int hf_lix2_pTCUserAccessPolicy = -1;      /* PTCUserAccessPolicy */
static int hf_lix2_pTCAccessPolicyFailure = -1;   /* PTCAccessPolicyFailure */
static int hf_lix2_identifiers = -1;              /* SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers */
static int hf_lix2_identifiers_item = -1;         /* PTCIdentifiers */
static int hf_lix2_mCPTTID = -1;                  /* UTF8String */
static int hf_lix2_instanceIdentifierURN = -1;    /* UTF8String */
static int hf_lix2_pTCChatGroupID = -1;           /* PTCChatGroupID */
static int hf_lix2_pTCSessionURI = -1;            /* UTF8String */
static int hf_lix2_pTCSessionType = -1;           /* PTCSessionType */
static int hf_lix2_MultipleParticipantPresenceStatus_item = -1;  /* PTCParticipantPresenceStatus */
static int hf_lix2_presenceID = -1;               /* PTCTargetInformation */
static int hf_lix2_presenceType = -1;             /* PTCPresenceType */
static int hf_lix2_presenceStatus = -1;           /* BOOLEAN */
static int hf_lix2_portNumber = -1;               /* PortNumber */
static int hf_lix2_pTCPartyID = -1;               /* PTCTargetInformation */
static int hf_lix2_groupIdentity = -1;            /* UTF8String */
static int hf_lix2_sourceIPAddress = -1;          /* IPAddress */
static int hf_lix2_destinationIPAddress = -1;     /* IPAddress */
static int hf_lix2_nextLayerProtocol = -1;        /* NextLayerProtocol */
static int hf_lix2_iPv6flowLabel = -1;            /* IPv6FlowLabel */
static int hf_lix2_packetSize = -1;               /* INTEGER */
static int hf_lix2_pDSRSummaryTrigger = -1;       /* PDSRSummaryTrigger */
static int hf_lix2_firstPacketTimestamp = -1;     /* Timestamp */
static int hf_lix2_lastPacketTimestamp = -1;      /* Timestamp */
static int hf_lix2_packetCount = -1;              /* INTEGER */
static int hf_lix2_byteCount = -1;                /* INTEGER */
static int hf_lix2_gUTI_01 = -1;                  /* GUTI */
static int hf_lix2_tAIList = -1;                  /* TAIList */
static int hf_lix2_attachType = -1;               /* EPSAttachType */
static int hf_lix2_attachResult = -1;             /* EPSAttachResult */
static int hf_lix2_ePSTAIList = -1;               /* TAIList */
static int hf_lix2_sMSServiceStatus = -1;         /* EPSSMSServiceStatus */
static int hf_lix2_oldGUTI_01 = -1;               /* GUTI */
static int hf_lix2_detachDirection = -1;          /* MMEDirection */
static int hf_lix2_detachType = -1;               /* EPSDetachType */
static int hf_lix2_cause_02 = -1;                 /* EMMCause */
static int hf_lix2_failedProcedureType_02 = -1;   /* MMEFailedProcedureType */
static int hf_lix2_failureCause_04 = -1;          /* MMEFailureCause */
static int hf_lix2_eMMCause = -1;                 /* EMMCause */
static int hf_lix2_eSMCause = -1;                 /* ESMCause */
static int hf_lix2_notificationType = -1;         /* LINotificationType */
static int hf_lix2_appliedTargetID = -1;          /* TargetIdentifier */
static int hf_lix2_appliedDeliveryInformation = -1;  /* SEQUENCE_OF_LIAppliedDeliveryInformation */
static int hf_lix2_appliedDeliveryInformation_item = -1;  /* LIAppliedDeliveryInformation */
static int hf_lix2_appliedStartTime = -1;         /* Timestamp */
static int hf_lix2_appliedEndTime = -1;           /* Timestamp */
static int hf_lix2_hI2DeliveryIPAddress = -1;     /* IPAddress */
static int hf_lix2_hI2DeliveryPortNumber = -1;    /* PortNumber */
static int hf_lix2_hI3DeliveryIPAddress = -1;     /* IPAddress */
static int hf_lix2_hI3DeliveryPortNumber = -1;    /* PortNumber */
static int hf_lix2_MDFCellSiteReport_item = -1;   /* CellInformation */
static int hf_lix2_eMMRegStatus = -1;             /* EMMRegStatus */
static int hf_lix2_fiveGMMStatus = -1;            /* FiveGMMStatus */
static int hf_lix2_fiveGGUTI = -1;                /* FiveGGUTI */
static int hf_lix2_mCC = -1;                      /* MCC */
static int hf_lix2_mNC = -1;                      /* MNC */
static int hf_lix2_fiveGTMSI = -1;                /* FiveGTMSI */
static int hf_lix2_tEID = -1;                     /* INTEGER_0_4294967295 */
static int hf_lix2_iPv4Address = -1;              /* IPv4Address */
static int hf_lix2_iPv6Address = -1;              /* IPv6Address */
static int hf_lix2_nAI = -1;                      /* NAI */
static int hf_lix2_mMEID = -1;                    /* MMEID */
static int hf_lix2_mMEGroupID = -1;               /* MMEGroupID */
static int hf_lix2_mMECode = -1;                  /* MMECode */
static int hf_lix2_mTMSI = -1;                    /* TMSI */
static int hf_lix2_sIPURI = -1;                   /* SIPURI */
static int hf_lix2_tELURI = -1;                   /* TELURI */
static int hf_lix2_mMEGI = -1;                    /* MMEGI */
static int hf_lix2_mMEC = -1;                     /* MMEC */
static int hf_lix2_NSSAI_item = -1;               /* SNSSAI */
static int hf_lix2_iMEISV = -1;                   /* IMEISV */
static int hf_lix2_RejectedNSSAI_item = -1;       /* RejectedSNSSAI */
static int hf_lix2_causeValue = -1;               /* RejectedSliceCauseValue */
static int hf_lix2_allowedNSSAI = -1;             /* NSSAI */
static int hf_lix2_configuredNSSAI = -1;          /* NSSAI */
static int hf_lix2_rejectedNSSAI = -1;            /* RejectedNSSAI */
static int hf_lix2_sliceServiceType = -1;         /* INTEGER_0_255 */
static int hf_lix2_sliceDifferentiator = -1;      /* OCTET_STRING_SIZE_3 */
static int hf_lix2_routingIndicator = -1;         /* RoutingIndicator */
static int hf_lix2_protectionSchemeID = -1;       /* ProtectionSchemeID */
static int hf_lix2_homeNetworkPublicKeyID = -1;   /* HomeNetworkPublicKeyID */
static int hf_lix2_schemeOutput = -1;             /* SchemeOutput */
static int hf_lix2_ethernetAddress = -1;          /* MACAddress */
static int hf_lix2_locationInfo = -1;             /* LocationInfo */
static int hf_lix2_positioningInfo = -1;          /* PositioningInfo */
static int hf_lix2_locationPresenceReport = -1;   /* LocationPresenceReport */
static int hf_lix2_ePSLocationInfo = -1;          /* EPSLocationInfo */
static int hf_lix2_geographicalCoordinates = -1;  /* GeographicalCoordinates */
static int hf_lix2_azimuth = -1;                  /* INTEGER_0_359 */
static int hf_lix2_operatorSpecificInformation = -1;  /* UTF8String */
static int hf_lix2_userLocation = -1;             /* UserLocation */
static int hf_lix2_currentLoc = -1;               /* BOOLEAN */
static int hf_lix2_geoInfo = -1;                  /* GeographicArea */
static int hf_lix2_timeZone = -1;                 /* TimeZone */
static int hf_lix2_additionalCellIDs = -1;        /* SEQUENCE_OF_CellInformation */
static int hf_lix2_additionalCellIDs_item = -1;   /* CellInformation */
static int hf_lix2_eUTRALocation = -1;            /* EUTRALocation */
static int hf_lix2_nRLocation = -1;               /* NRLocation */
static int hf_lix2_n3GALocation = -1;             /* N3GALocation */
static int hf_lix2_tAI = -1;                      /* TAI */
static int hf_lix2_eCGI = -1;                     /* ECGI */
static int hf_lix2_ageOfLocationInfo = -1;        /* INTEGER */
static int hf_lix2_uELocationTimestamp = -1;      /* Timestamp */
static int hf_lix2_geographicalInformation = -1;  /* UTF8String */
static int hf_lix2_geodeticInformation = -1;      /* UTF8String */
static int hf_lix2_globalNGENbID = -1;            /* GlobalRANNodeID */
static int hf_lix2_cellSiteInformation = -1;      /* CellSiteInformation */
static int hf_lix2_globalENbID = -1;              /* GlobalRANNodeID */
static int hf_lix2_nCGI = -1;                     /* NCGI */
static int hf_lix2_globalGNbID = -1;              /* GlobalRANNodeID */
static int hf_lix2_n3IWFID = -1;                  /* N3IWFIDNGAP */
static int hf_lix2_uEIPAddr = -1;                 /* IPAddr */
static int hf_lix2_portNumber_01 = -1;            /* INTEGER */
static int hf_lix2_tNAPID = -1;                   /* TNAPID */
static int hf_lix2_tWAPID = -1;                   /* TWAPID */
static int hf_lix2_hFCNodeID = -1;                /* HFCNodeID */
static int hf_lix2_gLI = -1;                      /* GLI */
static int hf_lix2_w5GBANLineType = -1;           /* W5GBANLineType */
static int hf_lix2_gCI = -1;                      /* GCI */
static int hf_lix2_iPv4Addr = -1;                 /* IPv4Address */
static int hf_lix2_iPv6Addr = -1;                 /* IPv6Address */
static int hf_lix2_aNNodeID = -1;                 /* ANNodeID */
static int hf_lix2_n3IWFID_01 = -1;               /* N3IWFIDSBI */
static int hf_lix2_gNbID = -1;                    /* GNbID */
static int hf_lix2_nGENbID = -1;                  /* NGENbID */
static int hf_lix2_eNbID = -1;                    /* ENbID */
static int hf_lix2_wAGFID = -1;                   /* WAGFID */
static int hf_lix2_tNGFID = -1;                   /* TNGFID */
static int hf_lix2_tAC = -1;                      /* TAC */
static int hf_lix2_lAI = -1;                      /* LAI */
static int hf_lix2_cellID = -1;                   /* CellID */
static int hf_lix2_lAC = -1;                      /* LAC */
static int hf_lix2_sAC = -1;                      /* SAC */
static int hf_lix2_eUTRACellID = -1;              /* EUTRACellID */
static int hf_lix2_TAIList_item = -1;             /* TAI */
static int hf_lix2_nRCellID = -1;                 /* NRCellID */
static int hf_lix2_rANCGI = -1;                   /* RANCGI */
static int hf_lix2_cellSiteinformation = -1;      /* CellSiteInformation */
static int hf_lix2_timeOfLocation = -1;           /* Timestamp */
static int hf_lix2_sSID = -1;                     /* SSID */
static int hf_lix2_bSSID = -1;                    /* BSSID */
static int hf_lix2_civicAddress = -1;             /* CivicAddressBytes */
static int hf_lix2_macroNGENbID = -1;             /* BIT_STRING_SIZE_20 */
static int hf_lix2_shortMacroNGENbID = -1;        /* BIT_STRING_SIZE_18 */
static int hf_lix2_longMacroNGENbID = -1;         /* BIT_STRING_SIZE_21 */
static int hf_lix2_macroENbID = -1;               /* BIT_STRING_SIZE_20 */
static int hf_lix2_homeENbID = -1;                /* BIT_STRING_SIZE_28 */
static int hf_lix2_shortMacroENbID = -1;          /* BIT_STRING_SIZE_18 */
static int hf_lix2_longMacroENbID = -1;           /* BIT_STRING_SIZE_21 */
static int hf_lix2_positionInfo = -1;             /* LocationData */
static int hf_lix2_rawMLPResponse = -1;           /* RawMLPResponse */
static int hf_lix2_mLPPositionData = -1;          /* UTF8String */
static int hf_lix2_mLPErrorCode = -1;             /* INTEGER_1_699 */
static int hf_lix2_locationEstimate = -1;         /* GeographicArea */
static int hf_lix2_accuracyFulfilmentIndicator = -1;  /* AccuracyFulfilmentIndicator */
static int hf_lix2_ageOfLocationEstimate = -1;    /* AgeOfLocationEstimate */
static int hf_lix2_velocityEstimate = -1;         /* VelocityEstimate */
static int hf_lix2_civicAddress_01 = -1;          /* CivicAddress */
static int hf_lix2_positioningDataList = -1;      /* SET_OF_PositioningMethodAndUsage */
static int hf_lix2_positioningDataList_item = -1;  /* PositioningMethodAndUsage */
static int hf_lix2_gNSSPositioningDataList = -1;  /* SET_OF_GNSSPositioningMethodAndUsage */
static int hf_lix2_gNSSPositioningDataList_item = -1;  /* GNSSPositioningMethodAndUsage */
static int hf_lix2_altitude = -1;                 /* Altitude */
static int hf_lix2_barometricPressure = -1;       /* BarometricPressure */
static int hf_lix2_locationData = -1;             /* LocationData */
static int hf_lix2_cGI = -1;                      /* CGI */
static int hf_lix2_sAI = -1;                      /* SAI */
static int hf_lix2_eSMLCCellInfo = -1;            /* ESMLCCellInfo */
static int hf_lix2_cellPortionID = -1;            /* CellPortionID */
static int hf_lix2_type = -1;                     /* AMFEventType */
static int hf_lix2_timestamp = -1;                /* Timestamp */
static int hf_lix2_areaList = -1;                 /* SET_OF_AMFEventArea */
static int hf_lix2_areaList_item = -1;            /* AMFEventArea */
static int hf_lix2_accessTypes = -1;              /* SET_OF_AccessType */
static int hf_lix2_accessTypes_item = -1;         /* AccessType */
static int hf_lix2_rMInfoList = -1;               /* SET_OF_RMInfo */
static int hf_lix2_rMInfoList_item = -1;          /* RMInfo */
static int hf_lix2_cMInfoList = -1;               /* SET_OF_CMInfo */
static int hf_lix2_cMInfoList_item = -1;          /* CMInfo */
static int hf_lix2_reachability = -1;             /* UEReachability */
static int hf_lix2_location_02 = -1;              /* UserLocation */
static int hf_lix2_presenceInfo = -1;             /* PresenceInfo */
static int hf_lix2_lADNInfo = -1;                 /* LADNInfo */
static int hf_lix2_presenceState = -1;            /* PresenceState */
static int hf_lix2_trackingAreaList = -1;         /* SET_OF_TAI */
static int hf_lix2_trackingAreaList_item = -1;    /* TAI */
static int hf_lix2_eCGIList = -1;                 /* SET_OF_ECGI */
static int hf_lix2_eCGIList_item = -1;            /* ECGI */
static int hf_lix2_nCGIList = -1;                 /* SET_OF_NCGI */
static int hf_lix2_nCGIList_item = -1;            /* NCGI */
static int hf_lix2_globalRANNodeIDList = -1;      /* SET_OF_GlobalRANNodeID */
static int hf_lix2_globalRANNodeIDList_item = -1;  /* GlobalRANNodeID */
static int hf_lix2_globalENbIDList = -1;          /* SET_OF_GlobalRANNodeID */
static int hf_lix2_globalENbIDList_item = -1;     /* GlobalRANNodeID */
static int hf_lix2_lADN = -1;                     /* UTF8String */
static int hf_lix2_presence = -1;                 /* PresenceState */
static int hf_lix2_rMState = -1;                  /* RMState */
static int hf_lix2_cMState = -1;                  /* CMState */
static int hf_lix2_point = -1;                    /* Point */
static int hf_lix2_pointUncertaintyCircle = -1;   /* PointUncertaintyCircle */
static int hf_lix2_pointUncertaintyEllipse = -1;  /* PointUncertaintyEllipse */
static int hf_lix2_polygon = -1;                  /* Polygon */
static int hf_lix2_pointAltitude = -1;            /* PointAltitude */
static int hf_lix2_pointAltitudeUncertainty = -1;  /* PointAltitudeUncertainty */
static int hf_lix2_ellipsoidArc = -1;             /* EllipsoidArc */
static int hf_lix2_horVelocity = -1;              /* HorizontalVelocity */
static int hf_lix2_horWithVertVelocity = -1;      /* HorizontalWithVerticalVelocity */
static int hf_lix2_horVelocityWithUncertainty = -1;  /* HorizontalVelocityWithUncertainty */
static int hf_lix2_horWithVertVelocityAndUncertainty = -1;  /* HorizontalWithVerticalVelocityAndUncertainty */
static int hf_lix2_country = -1;                  /* UTF8String */
static int hf_lix2_a1 = -1;                       /* UTF8String */
static int hf_lix2_a2 = -1;                       /* UTF8String */
static int hf_lix2_a3 = -1;                       /* UTF8String */
static int hf_lix2_a4 = -1;                       /* UTF8String */
static int hf_lix2_a5 = -1;                       /* UTF8String */
static int hf_lix2_a6 = -1;                       /* UTF8String */
static int hf_lix2_prd = -1;                      /* UTF8String */
static int hf_lix2_pod = -1;                      /* UTF8String */
static int hf_lix2_sts = -1;                      /* UTF8String */
static int hf_lix2_hno = -1;                      /* UTF8String */
static int hf_lix2_hns = -1;                      /* UTF8String */
static int hf_lix2_lmk = -1;                      /* UTF8String */
static int hf_lix2_loc = -1;                      /* UTF8String */
static int hf_lix2_nam = -1;                      /* UTF8String */
static int hf_lix2_pc = -1;                       /* UTF8String */
static int hf_lix2_bld = -1;                      /* UTF8String */
static int hf_lix2_unit = -1;                     /* UTF8String */
static int hf_lix2_flr = -1;                      /* UTF8String */
static int hf_lix2_room = -1;                     /* UTF8String */
static int hf_lix2_plc = -1;                      /* UTF8String */
static int hf_lix2_pcn = -1;                      /* UTF8String */
static int hf_lix2_pobox = -1;                    /* UTF8String */
static int hf_lix2_addcode = -1;                  /* UTF8String */
static int hf_lix2_seat = -1;                     /* UTF8String */
static int hf_lix2_rd = -1;                       /* UTF8String */
static int hf_lix2_rdsec = -1;                    /* UTF8String */
static int hf_lix2_rdbr = -1;                     /* UTF8String */
static int hf_lix2_rdsubbr = -1;                  /* UTF8String */
static int hf_lix2_prm = -1;                      /* UTF8String */
static int hf_lix2_pom = -1;                      /* UTF8String */
static int hf_lix2_method = -1;                   /* PositioningMethod */
static int hf_lix2_mode = -1;                     /* PositioningMode */
static int hf_lix2_usage = -1;                    /* Usage */
static int hf_lix2_methodCode = -1;               /* MethodCode */
static int hf_lix2_gNSS = -1;                     /* GNSSID */
static int hf_lix2_uncertainty = -1;              /* Uncertainty */
static int hf_lix2_uncertainty_01 = -1;           /* UncertaintyEllipse */
static int hf_lix2_confidence = -1;               /* Confidence */
static int hf_lix2_pointList = -1;                /* SET_SIZE_3_15_OF_GeographicalCoordinates */
static int hf_lix2_pointList_item = -1;           /* GeographicalCoordinates */
static int hf_lix2_point_01 = -1;                 /* GeographicalCoordinates */
static int hf_lix2_uncertaintyEllipse = -1;       /* UncertaintyEllipse */
static int hf_lix2_uncertaintyAltitude = -1;      /* Uncertainty */
static int hf_lix2_innerRadius = -1;              /* InnerRadius */
static int hf_lix2_uncertaintyRadius = -1;        /* Uncertainty */
static int hf_lix2_offsetAngle = -1;              /* Angle */
static int hf_lix2_includedAngle = -1;            /* Angle */
static int hf_lix2_latitude = -1;                 /* UTF8String */
static int hf_lix2_longitude = -1;                /* UTF8String */
static int hf_lix2_mapDatumInformation = -1;      /* OGCURN */
static int hf_lix2_semiMajor = -1;                /* Uncertainty */
static int hf_lix2_semiMinor = -1;                /* Uncertainty */
static int hf_lix2_orientationMajor = -1;         /* Orientation */
static int hf_lix2_hSpeed = -1;                   /* HorizontalSpeed */
static int hf_lix2_bearing = -1;                  /* Angle */
static int hf_lix2_vSpeed = -1;                   /* VerticalSpeed */
static int hf_lix2_vDirection = -1;               /* VerticalDirection */
static int hf_lix2_uncertainty_02 = -1;           /* SpeedUncertainty */
static int hf_lix2_hUncertainty = -1;             /* SpeedUncertainty */
static int hf_lix2_vUncertainty = -1;             /* SpeedUncertainty */

/*--- End of included file: packet-lix2-hf.c ---*/
#line 34 "./asn1/lix2/packet-lix2-template.c"


/*--- Included file: packet-lix2-ett.c ---*/
#line 1 "./asn1/lix2/packet-lix2-ett.c"
static gint ett_lix2_XIRIPayload = -1;
static gint ett_lix2_XIRIEvent = -1;
static gint ett_lix2_IRIPayload = -1;
static gint ett_lix2_SEQUENCE_OF_IRITargetIdentifier = -1;
static gint ett_lix2_IRIEvent = -1;
static gint ett_lix2_IRITargetIdentifier = -1;
static gint ett_lix2_CCPayload = -1;
static gint ett_lix2_CCPDU = -1;
static gint ett_lix2_LINotificationPayload = -1;
static gint ett_lix2_LINotificationMessage = -1;
static gint ett_lix2_NEFPDUSessionEstablishment = -1;
static gint ett_lix2_NEFPDUSessionModification = -1;
static gint ett_lix2_NEFPDUSessionRelease = -1;
static gint ett_lix2_NEFUnsuccessfulProcedure = -1;
static gint ett_lix2_NEFStartOfInterceptionWithEstablishedPDUSession = -1;
static gint ett_lix2_NEFDeviceTrigger = -1;
static gint ett_lix2_NEFDeviceTriggerReplace = -1;
static gint ett_lix2_NEFDeviceTriggerCancellation = -1;
static gint ett_lix2_NEFDeviceTriggerReportNotify = -1;
static gint ett_lix2_NEFMSISDNLessMOSMS = -1;
static gint ett_lix2_NEFExpectedUEBehaviourUpdate = -1;
static gint ett_lix2_SEQUENCE_OF_UMTLocationArea5G = -1;
static gint ett_lix2_ScheduledCommunicationTime = -1;
static gint ett_lix2_SEQUENCE_OF_Daytime = -1;
static gint ett_lix2_UMTLocationArea5G = -1;
static gint ett_lix2_Daytime = -1;
static gint ett_lix2_SCEFPDNConnectionEstablishment = -1;
static gint ett_lix2_SCEFPDNConnectionUpdate = -1;
static gint ett_lix2_SCEFPDNConnectionRelease = -1;
static gint ett_lix2_SCEFUnsuccessfulProcedure = -1;
static gint ett_lix2_SCEFStartOfInterceptionWithEstablishedPDNConnection = -1;
static gint ett_lix2_SCEFDeviceTrigger = -1;
static gint ett_lix2_SCEFDeviceTriggerReplace = -1;
static gint ett_lix2_SCEFDeviceTriggerCancellation = -1;
static gint ett_lix2_SCEFDeviceTriggerReportNotify = -1;
static gint ett_lix2_SCEFMSISDNLessMOSMS = -1;
static gint ett_lix2_SCEFCommunicationPatternUpdate = -1;
static gint ett_lix2_AMFRegistration = -1;
static gint ett_lix2_AMFDeregistration = -1;
static gint ett_lix2_AMFLocationUpdate = -1;
static gint ett_lix2_AMFStartOfInterceptionWithRegisteredUE = -1;
static gint ett_lix2_AMFUnsuccessfulProcedure = -1;
static gint ett_lix2_AMFID = -1;
static gint ett_lix2_AMFFailureCause = -1;
static gint ett_lix2_SMFPDUSessionEstablishment = -1;
static gint ett_lix2_SEQUENCE_OF_UEEndpointAddress = -1;
static gint ett_lix2_SMFPDUSessionModification = -1;
static gint ett_lix2_SMFPDUSessionRelease = -1;
static gint ett_lix2_SMFStartOfInterceptionWithEstablishedPDUSession = -1;
static gint ett_lix2_SMFUnsuccessfulProcedure = -1;
static gint ett_lix2_SMFPDUtoMAPDUSessionModification = -1;
static gint ett_lix2_SMFMAPDUSessionEstablishment = -1;
static gint ett_lix2_SEQUENCE_OF_AccessInfo = -1;
static gint ett_lix2_SMFMAPDUSessionModification = -1;
static gint ett_lix2_SMFMAPDUSessionRelease = -1;
static gint ett_lix2_SMFStartOfInterceptionWithEstablishedMAPDUSession = -1;
static gint ett_lix2_SMFMAUnsuccessfulProcedure = -1;
static gint ett_lix2_SMFServingNetwork = -1;
static gint ett_lix2_AccessInfo = -1;
static gint ett_lix2_ExtendedUPFCCPDU = -1;
static gint ett_lix2_UPFCCPDUPayload = -1;
static gint ett_lix2_UDMServingSystemMessage = -1;
static gint ett_lix2_UDMSubscriberRecordChangeMessage = -1;
static gint ett_lix2_UDMCancelLocationMessage = -1;
static gint ett_lix2_ServiceID = -1;
static gint ett_lix2_SEQUENCE_OF_CAGID = -1;
static gint ett_lix2_SMSMessage = -1;
static gint ett_lix2_SMSReport = -1;
static gint ett_lix2_SMSParty = -1;
static gint ett_lix2_SMSNFAddress = -1;
static gint ett_lix2_SMSTPDUData = -1;
static gint ett_lix2_MMSSend = -1;
static gint ett_lix2_SEQUENCE_OF_MMSParty = -1;
static gint ett_lix2_MMSSendByNonLocalTarget = -1;
static gint ett_lix2_MMSNotification = -1;
static gint ett_lix2_MMSSendToNonLocalTarget = -1;
static gint ett_lix2_MMSNotificationResponse = -1;
static gint ett_lix2_MMSRetrieval = -1;
static gint ett_lix2_MMSDeliveryAck = -1;
static gint ett_lix2_MMSForward = -1;
static gint ett_lix2_MMSDeleteFromRelay = -1;
static gint ett_lix2_T_contentLocationReq = -1;
static gint ett_lix2_T_contentLocationConf = -1;
static gint ett_lix2_T_deleteResponseText = -1;
static gint ett_lix2_MMSMBoxStore = -1;
static gint ett_lix2_MMSMBoxUpload = -1;
static gint ett_lix2_SEQUENCE_OF_MMBoxDescription = -1;
static gint ett_lix2_MMSMBoxDelete = -1;
static gint ett_lix2_T_contentLocationReq_01 = -1;
static gint ett_lix2_T_contentLocationConf_01 = -1;
static gint ett_lix2_MMSDeliveryReport = -1;
static gint ett_lix2_MMSDeliveryReportNonLocalTarget = -1;
static gint ett_lix2_MMSReadReport = -1;
static gint ett_lix2_MMSReadReportNonLocalTarget = -1;
static gint ett_lix2_MMSCancel = -1;
static gint ett_lix2_MMSMBoxViewRequest = -1;
static gint ett_lix2_SEQUENCE_OF_MMState = -1;
static gint ett_lix2_SEQUENCE_OF_MMFlags = -1;
static gint ett_lix2_T_attributes = -1;
static gint ett_lix2_MMSMBoxViewResponse = -1;
static gint ett_lix2_T_attributes_01 = -1;
static gint ett_lix2_MMBoxDescription = -1;
static gint ett_lix2_MMSCCPDU = -1;
static gint ett_lix2_MMSAdaptation = -1;
static gint ett_lix2_MMSElementDescriptor = -1;
static gint ett_lix2_MMSExpiry = -1;
static gint ett_lix2_MMFlags = -1;
static gint ett_lix2_MMSParty = -1;
static gint ett_lix2_SEQUENCE_OF_MMSPartyID = -1;
static gint ett_lix2_MMSPartyID = -1;
static gint ett_lix2_MMSPreviouslySent = -1;
static gint ett_lix2_MMSPreviouslySentBy = -1;
static gint ett_lix2_MMSQuota = -1;
static gint ett_lix2_MMSVersion = -1;
static gint ett_lix2_PTCRegistration = -1;
static gint ett_lix2_PTCSessionInitiation = -1;
static gint ett_lix2_SEQUENCE_OF_PTCTargetInformation = -1;
static gint ett_lix2_PTCSessionAbandon = -1;
static gint ett_lix2_PTCSessionStart = -1;
static gint ett_lix2_PTCSessionEnd = -1;
static gint ett_lix2_PTCStartOfInterception = -1;
static gint ett_lix2_PTCPreEstablishedSession = -1;
static gint ett_lix2_PTCInstantPersonalAlert = -1;
static gint ett_lix2_PTCPartyJoin = -1;
static gint ett_lix2_PTCPartyDrop = -1;
static gint ett_lix2_PTCPartyHold = -1;
static gint ett_lix2_PTCMediaModification = -1;
static gint ett_lix2_PTCGroupAdvertisement = -1;
static gint ett_lix2_PTCFloorControl = -1;
static gint ett_lix2_SEQUENCE_OF_PTCFloorActivity = -1;
static gint ett_lix2_PTCTargetPresence = -1;
static gint ett_lix2_PTCParticipantPresence = -1;
static gint ett_lix2_PTCListManagement = -1;
static gint ett_lix2_SEQUENCE_OF_PTCIDList = -1;
static gint ett_lix2_PTCAccessPolicy = -1;
static gint ett_lix2_PTCTargetInformation = -1;
static gint ett_lix2_SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers = -1;
static gint ett_lix2_PTCIdentifiers = -1;
static gint ett_lix2_PTCSessionInfo = -1;
static gint ett_lix2_MultipleParticipantPresenceStatus = -1;
static gint ett_lix2_PTCParticipantPresenceStatus = -1;
static gint ett_lix2_RTPSetting = -1;
static gint ett_lix2_PTCIDList = -1;
static gint ett_lix2_PTCChatGroupID = -1;
static gint ett_lix2_LALSReport = -1;
static gint ett_lix2_PDHeaderReport = -1;
static gint ett_lix2_PDSummaryReport = -1;
static gint ett_lix2_AMFIdentifierAssocation = -1;
static gint ett_lix2_MMEIdentifierAssocation = -1;
static gint ett_lix2_MMEAttach = -1;
static gint ett_lix2_MMEDetach = -1;
static gint ett_lix2_MMELocationUpdate = -1;
static gint ett_lix2_MMEStartOfInterceptionWithEPSAttachedUE = -1;
static gint ett_lix2_MMEUnsuccessfulProcedure = -1;
static gint ett_lix2_MMEFailureCause = -1;
static gint ett_lix2_LINotification = -1;
static gint ett_lix2_SEQUENCE_OF_LIAppliedDeliveryInformation = -1;
static gint ett_lix2_LIAppliedDeliveryInformation = -1;
static gint ett_lix2_MDFCellSiteReport = -1;
static gint ett_lix2_EMM5GMMStatus = -1;
static gint ett_lix2_EPS5GGUTI = -1;
static gint ett_lix2_FiveGGUTI = -1;
static gint ett_lix2_FTEID = -1;
static gint ett_lix2_GPSI = -1;
static gint ett_lix2_GUAMI = -1;
static gint ett_lix2_GUMMEI = -1;
static gint ett_lix2_GUTI = -1;
static gint ett_lix2_IMPU = -1;
static gint ett_lix2_IPAddress = -1;
static gint ett_lix2_MMEID = -1;
static gint ett_lix2_NSSAI = -1;
static gint ett_lix2_PLMNID = -1;
static gint ett_lix2_PEI = -1;
static gint ett_lix2_RejectedNSSAI = -1;
static gint ett_lix2_RejectedSNSSAI = -1;
static gint ett_lix2_Slice = -1;
static gint ett_lix2_SNSSAI = -1;
static gint ett_lix2_SUCI = -1;
static gint ett_lix2_SUPI = -1;
static gint ett_lix2_TargetIdentifier = -1;
static gint ett_lix2_UEEndpointAddress = -1;
static gint ett_lix2_Location = -1;
static gint ett_lix2_CellSiteInformation = -1;
static gint ett_lix2_LocationInfo = -1;
static gint ett_lix2_SEQUENCE_OF_CellInformation = -1;
static gint ett_lix2_UserLocation = -1;
static gint ett_lix2_EUTRALocation = -1;
static gint ett_lix2_NRLocation = -1;
static gint ett_lix2_N3GALocation = -1;
static gint ett_lix2_IPAddr = -1;
static gint ett_lix2_GlobalRANNodeID = -1;
static gint ett_lix2_ANNodeID = -1;
static gint ett_lix2_TAI = -1;
static gint ett_lix2_CGI = -1;
static gint ett_lix2_LAI = -1;
static gint ett_lix2_SAI = -1;
static gint ett_lix2_ECGI = -1;
static gint ett_lix2_TAIList = -1;
static gint ett_lix2_NCGI = -1;
static gint ett_lix2_RANCGI = -1;
static gint ett_lix2_CellInformation = -1;
static gint ett_lix2_TNAPID = -1;
static gint ett_lix2_TWAPID = -1;
static gint ett_lix2_NGENbID = -1;
static gint ett_lix2_ENbID = -1;
static gint ett_lix2_PositioningInfo = -1;
static gint ett_lix2_RawMLPResponse = -1;
static gint ett_lix2_LocationData = -1;
static gint ett_lix2_SET_OF_PositioningMethodAndUsage = -1;
static gint ett_lix2_SET_OF_GNSSPositioningMethodAndUsage = -1;
static gint ett_lix2_EPSLocationInfo = -1;
static gint ett_lix2_ESMLCCellInfo = -1;
static gint ett_lix2_LocationPresenceReport = -1;
static gint ett_lix2_SET_OF_AMFEventArea = -1;
static gint ett_lix2_SET_OF_AccessType = -1;
static gint ett_lix2_SET_OF_RMInfo = -1;
static gint ett_lix2_SET_OF_CMInfo = -1;
static gint ett_lix2_AMFEventArea = -1;
static gint ett_lix2_PresenceInfo = -1;
static gint ett_lix2_SET_OF_TAI = -1;
static gint ett_lix2_SET_OF_ECGI = -1;
static gint ett_lix2_SET_OF_NCGI = -1;
static gint ett_lix2_SET_OF_GlobalRANNodeID = -1;
static gint ett_lix2_LADNInfo = -1;
static gint ett_lix2_RMInfo = -1;
static gint ett_lix2_CMInfo = -1;
static gint ett_lix2_GeographicArea = -1;
static gint ett_lix2_VelocityEstimate = -1;
static gint ett_lix2_CivicAddress = -1;
static gint ett_lix2_PositioningMethodAndUsage = -1;
static gint ett_lix2_GNSSPositioningMethodAndUsage = -1;
static gint ett_lix2_Point = -1;
static gint ett_lix2_PointUncertaintyCircle = -1;
static gint ett_lix2_PointUncertaintyEllipse = -1;
static gint ett_lix2_Polygon = -1;
static gint ett_lix2_SET_SIZE_3_15_OF_GeographicalCoordinates = -1;
static gint ett_lix2_PointAltitude = -1;
static gint ett_lix2_PointAltitudeUncertainty = -1;
static gint ett_lix2_EllipsoidArc = -1;
static gint ett_lix2_GeographicalCoordinates = -1;
static gint ett_lix2_UncertaintyEllipse = -1;
static gint ett_lix2_HorizontalVelocity = -1;
static gint ett_lix2_HorizontalWithVerticalVelocity = -1;
static gint ett_lix2_HorizontalVelocityWithUncertainty = -1;
static gint ett_lix2_HorizontalWithVerticalVelocityAndUncertainty = -1;

/*--- End of included file: packet-lix2-ett.c ---*/
#line 36 "./asn1/lix2/packet-lix2-template.c"


/*--- Included file: packet-lix2-fn.c ---*/
#line 1 "./asn1/lix2/packet-lix2-fn.c"


static int
dissect_lix2_RELATIVE_OID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_relative_oid(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string lix2_AMFRegistrationType_vals[] = {
  {   1, "initial" },
  {   2, "mobility" },
  {   3, "periodic" },
  {   4, "emergency" },
  { 0, NULL }
};


static int
dissect_lix2_AMFRegistrationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_AMFRegistrationResult_vals[] = {
  {   1, "threeGPPAccess" },
  {   2, "nonThreeGPPAccess" },
  {   3, "threeGPPAndNonThreeGPPAccess" },
  { 0, NULL }
};


static int
dissect_lix2_AMFRegistrationResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_OCTET_STRING_SIZE_3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SNSSAI_sequence[] = {
  { &hf_lix2_sliceServiceType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER_0_255 },
  { &hf_lix2_sliceDifferentiator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_OCTET_STRING_SIZE_3 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SNSSAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SNSSAI_sequence, hf_index, ett_lix2_SNSSAI);

  return offset;
}


static const ber_sequence_t NSSAI_sequence_of[1] = {
  { &hf_lix2_NSSAI_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_SNSSAI },
};

static int
dissect_lix2_NSSAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      NSSAI_sequence_of, hf_index, ett_lix2_NSSAI);

  return offset;
}



static int
dissect_lix2_RejectedSliceCauseValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RejectedSNSSAI_sequence[] = {
  { &hf_lix2_causeValue     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_RejectedSliceCauseValue },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_RejectedSNSSAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RejectedSNSSAI_sequence, hf_index, ett_lix2_RejectedSNSSAI);

  return offset;
}


static const ber_sequence_t RejectedNSSAI_sequence_of[1] = {
  { &hf_lix2_RejectedNSSAI_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_RejectedSNSSAI },
};

static int
dissect_lix2_RejectedNSSAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RejectedNSSAI_sequence_of, hf_index, ett_lix2_RejectedNSSAI);

  return offset;
}


static const ber_sequence_t Slice_sequence[] = {
  { &hf_lix2_allowedNSSAI   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NSSAI },
  { &hf_lix2_configuredNSSAI, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NSSAI },
  { &hf_lix2_rejectedNSSAI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RejectedNSSAI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_Slice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Slice_sequence, hf_index, ett_lix2_Slice);

  return offset;
}



static int
dissect_lix2_IMSI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_NAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_SUPI_vals[] = {
  {   1, "iMSI" },
  {   2, "nAI" },
  { 0, NULL }
};

static const ber_choice_t SUPI_choice[] = {
  {   1, &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  {   2, &hf_lix2_nAI            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SUPI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SUPI_choice, hf_index, ett_lix2_SUPI,
                                 NULL);

  return offset;
}



static int
dissect_lix2_MCC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_MNC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_RoutingIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_ProtectionSchemeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_HomeNetworkPublicKeyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_SchemeOutput(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SUCI_sequence[] = {
  { &hf_lix2_mCC            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MCC },
  { &hf_lix2_mNC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MNC },
  { &hf_lix2_routingIndicator, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_RoutingIndicator },
  { &hf_lix2_protectionSchemeID, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_ProtectionSchemeID },
  { &hf_lix2_homeNetworkPublicKeyID, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_HomeNetworkPublicKeyID },
  { &hf_lix2_schemeOutput   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SchemeOutput },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SUCI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SUCI_sequence, hf_index, ett_lix2_SUCI);

  return offset;
}



static int
dissect_lix2_IMEI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_IMEISV(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_PEI_vals[] = {
  {   1, "iMEI" },
  {   2, "iMEISV" },
  { 0, NULL }
};

static const ber_choice_t PEI_choice[] = {
  {   1, &hf_lix2_iMEI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  {   2, &hf_lix2_iMEISV         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_IMEISV },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PEI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PEI_choice, hf_index, ett_lix2_PEI,
                                 NULL);

  return offset;
}



static int
dissect_lix2_MSISDN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_GPSI_vals[] = {
  {   1, "mSISDN" },
  {   2, "nAI" },
  { 0, NULL }
};

static const ber_choice_t GPSI_choice[] = {
  {   1, &hf_lix2_mSISDN         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  {   2, &hf_lix2_nAI            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GPSI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPSI_choice, hf_index, ett_lix2_GPSI,
                                 NULL);

  return offset;
}



static int
dissect_lix2_AMFRegionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_AMFSetID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_AMFPointer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_FiveGTMSI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t FiveGGUTI_sequence[] = {
  { &hf_lix2_mCC            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MCC },
  { &hf_lix2_mNC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MNC },
  { &hf_lix2_aMFRegionID    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegionID },
  { &hf_lix2_aMFSetID       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_AMFSetID },
  { &hf_lix2_aMFPointer     , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_AMFPointer },
  { &hf_lix2_fiveGTMSI      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGTMSI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_FiveGGUTI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FiveGGUTI_sequence, hf_index, ett_lix2_FiveGGUTI);

  return offset;
}


static const ber_sequence_t PLMNID_sequence[] = {
  { &hf_lix2_mCC            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MCC },
  { &hf_lix2_mNC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MNC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PLMNID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PLMNID_sequence, hf_index, ett_lix2_PLMNID);

  return offset;
}



static int
dissect_lix2_TAC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_NID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t TAI_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_tAC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_TAC },
  { &hf_lix2_nID            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_TAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TAI_sequence, hf_index, ett_lix2_TAI);

  return offset;
}



static int
dissect_lix2_EUTRACellID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t ECGI_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_eUTRACellID    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_EUTRACellID },
  { &hf_lix2_nID            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ECGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ECGI_sequence, hf_index, ett_lix2_ECGI);

  return offset;
}



static int
dissect_lix2_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_Timestamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_lix2_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_N3IWFIDSBI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_GNbID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_lix2_BIT_STRING_SIZE_20(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_lix2_BIT_STRING_SIZE_18(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_lix2_BIT_STRING_SIZE_21(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const value_string lix2_NGENbID_vals[] = {
  {   1, "macroNGENbID" },
  {   2, "shortMacroNGENbID" },
  {   3, "longMacroNGENbID" },
  { 0, NULL }
};

static const ber_choice_t NGENbID_choice[] = {
  {   1, &hf_lix2_macroNGENbID   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_20 },
  {   2, &hf_lix2_shortMacroNGENbID, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_18 },
  {   3, &hf_lix2_longMacroNGENbID, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NGENbID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NGENbID_choice, hf_index, ett_lix2_NGENbID,
                                 NULL);

  return offset;
}



static int
dissect_lix2_BIT_STRING_SIZE_28(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const value_string lix2_ENbID_vals[] = {
  {   1, "macroENbID" },
  {   2, "homeENbID" },
  {   3, "shortMacroENbID" },
  {   4, "longMacroENbID" },
  { 0, NULL }
};

static const ber_choice_t ENbID_choice[] = {
  {   1, &hf_lix2_macroENbID     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_20 },
  {   2, &hf_lix2_homeENbID      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_28 },
  {   3, &hf_lix2_shortMacroENbID, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_18 },
  {   4, &hf_lix2_longMacroENbID , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ENbID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ENbID_choice, hf_index, ett_lix2_ENbID,
                                 NULL);

  return offset;
}



static int
dissect_lix2_WAGFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_TNGFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_ANNodeID_vals[] = {
  {   1, "n3IWFID" },
  {   2, "gNbID" },
  {   3, "nGENbID" },
  {   4, "eNbID" },
  {   5, "wAGFID" },
  {   6, "tNGFID" },
  { 0, NULL }
};

static const ber_choice_t ANNodeID_choice[] = {
  {   1, &hf_lix2_n3IWFID_01     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_N3IWFIDSBI },
  {   2, &hf_lix2_gNbID          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_GNbID },
  {   3, &hf_lix2_nGENbID        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_NGENbID },
  {   4, &hf_lix2_eNbID          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_ENbID },
  {   5, &hf_lix2_wAGFID         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_WAGFID },
  {   6, &hf_lix2_tNGFID         , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_TNGFID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ANNodeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ANNodeID_choice, hf_index, ett_lix2_ANNodeID,
                                 NULL);

  return offset;
}


static const ber_sequence_t GlobalRANNodeID_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_aNNodeID       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_ANNodeID },
  { &hf_lix2_nID            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GlobalRANNodeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GlobalRANNodeID_sequence, hf_index, ett_lix2_GlobalRANNodeID);

  return offset;
}



static int
dissect_lix2_OGCURN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_lix2_latitude       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_longitude      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_mapDatumInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_OGCURN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GeographicalCoordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GeographicalCoordinates_sequence, hf_index, ett_lix2_GeographicalCoordinates);

  return offset;
}



static int
dissect_lix2_INTEGER_0_359(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CellSiteInformation_sequence[] = {
  { &hf_lix2_geographicalCoordinates, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { &hf_lix2_azimuth        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER_0_359 },
  { &hf_lix2_operatorSpecificInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CellSiteInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CellSiteInformation_sequence, hf_index, ett_lix2_CellSiteInformation);

  return offset;
}


static const ber_sequence_t EUTRALocation_sequence[] = {
  { &hf_lix2_tAI            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_TAI },
  { &hf_lix2_eCGI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_ECGI },
  { &hf_lix2_ageOfLocationInfo, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_uELocationTimestamp, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_geographicalInformation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_geodeticInformation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_globalNGENbID  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GlobalRANNodeID },
  { &hf_lix2_cellSiteInformation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CellSiteInformation },
  { &hf_lix2_globalENbID    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GlobalRANNodeID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_EUTRALocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EUTRALocation_sequence, hf_index, ett_lix2_EUTRALocation);

  return offset;
}



static int
dissect_lix2_NRCellID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t NCGI_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_nRCellID       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_NRCellID },
  { &hf_lix2_nID            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NCGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NCGI_sequence, hf_index, ett_lix2_NCGI);

  return offset;
}


static const ber_sequence_t NRLocation_sequence[] = {
  { &hf_lix2_tAI            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_TAI },
  { &hf_lix2_nCGI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_NCGI },
  { &hf_lix2_ageOfLocationInfo, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_uELocationTimestamp, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_geographicalInformation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_geodeticInformation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_globalGNbID    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GlobalRANNodeID },
  { &hf_lix2_cellSiteInformation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CellSiteInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NRLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NRLocation_sequence, hf_index, ett_lix2_NRLocation);

  return offset;
}



static int
dissect_lix2_N3IWFIDNGAP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_lix2_IPv4Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_IPv6Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t IPAddr_sequence[] = {
  { &hf_lix2_iPv4Addr       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPv4Address },
  { &hf_lix2_iPv6Addr       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPv6Address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_IPAddr(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPAddr_sequence, hf_index, ett_lix2_IPAddr);

  return offset;
}



static int
dissect_lix2_SSID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_BSSID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_CivicAddressBytes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TNAPID_sequence[] = {
  { &hf_lix2_sSID           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SSID },
  { &hf_lix2_bSSID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BSSID },
  { &hf_lix2_civicAddress   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CivicAddressBytes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_TNAPID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TNAPID_sequence, hf_index, ett_lix2_TNAPID);

  return offset;
}


static const ber_sequence_t TWAPID_sequence[] = {
  { &hf_lix2_sSID           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SSID },
  { &hf_lix2_bSSID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BSSID },
  { &hf_lix2_civicAddress   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CivicAddressBytes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_TWAPID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TWAPID_sequence, hf_index, ett_lix2_TWAPID);

  return offset;
}



static int
dissect_lix2_HFCNodeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_GLI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_W5GBANLineType_vals[] = {
  {   1, "dSL" },
  {   2, "pON" },
  { 0, NULL }
};


static int
dissect_lix2_W5GBANLineType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_GCI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t N3GALocation_sequence[] = {
  { &hf_lix2_tAI            , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAI },
  { &hf_lix2_n3IWFID        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_N3IWFIDNGAP },
  { &hf_lix2_uEIPAddr       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPAddr },
  { &hf_lix2_portNumber_01  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_tNAPID         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TNAPID },
  { &hf_lix2_tWAPID         , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TWAPID },
  { &hf_lix2_hFCNodeID      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HFCNodeID },
  { &hf_lix2_gLI            , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GLI },
  { &hf_lix2_w5GBANLineType , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_W5GBANLineType },
  { &hf_lix2_gCI            , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GCI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_N3GALocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   N3GALocation_sequence, hf_index, ett_lix2_N3GALocation);

  return offset;
}


static const ber_sequence_t UserLocation_sequence[] = {
  { &hf_lix2_eUTRALocation  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EUTRALocation },
  { &hf_lix2_nRLocation     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NRLocation },
  { &hf_lix2_n3GALocation   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_N3GALocation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UserLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserLocation_sequence, hf_index, ett_lix2_UserLocation);

  return offset;
}



static int
dissect_lix2_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t Point_sequence[] = {
  { &hf_lix2_geographicalCoordinates, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_Point(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Point_sequence, hf_index, ett_lix2_Point);

  return offset;
}



static int
dissect_lix2_Uncertainty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PointUncertaintyCircle_sequence[] = {
  { &hf_lix2_geographicalCoordinates, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { &hf_lix2_uncertainty    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Uncertainty },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PointUncertaintyCircle(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PointUncertaintyCircle_sequence, hf_index, ett_lix2_PointUncertaintyCircle);

  return offset;
}



static int
dissect_lix2_Orientation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t UncertaintyEllipse_sequence[] = {
  { &hf_lix2_semiMajor      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_Uncertainty },
  { &hf_lix2_semiMinor      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Uncertainty },
  { &hf_lix2_orientationMajor, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Orientation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UncertaintyEllipse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UncertaintyEllipse_sequence, hf_index, ett_lix2_UncertaintyEllipse);

  return offset;
}



static int
dissect_lix2_Confidence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PointUncertaintyEllipse_sequence[] = {
  { &hf_lix2_geographicalCoordinates, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { &hf_lix2_uncertainty_01 , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UncertaintyEllipse },
  { &hf_lix2_confidence     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Confidence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PointUncertaintyEllipse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PointUncertaintyEllipse_sequence, hf_index, ett_lix2_PointUncertaintyEllipse);

  return offset;
}


static const ber_sequence_t SET_SIZE_3_15_OF_GeographicalCoordinates_set_of[1] = {
  { &hf_lix2_pointList_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_GeographicalCoordinates },
};

static int
dissect_lix2_SET_SIZE_3_15_OF_GeographicalCoordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_3_15_OF_GeographicalCoordinates_set_of, hf_index, ett_lix2_SET_SIZE_3_15_OF_GeographicalCoordinates);

  return offset;
}


static const ber_sequence_t Polygon_sequence[] = {
  { &hf_lix2_pointList      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SET_SIZE_3_15_OF_GeographicalCoordinates },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_Polygon(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Polygon_sequence, hf_index, ett_lix2_Polygon);

  return offset;
}



static int
dissect_lix2_Altitude(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PointAltitude_sequence[] = {
  { &hf_lix2_point_01       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { &hf_lix2_altitude       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Altitude },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PointAltitude(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PointAltitude_sequence, hf_index, ett_lix2_PointAltitude);

  return offset;
}


static const ber_sequence_t PointAltitudeUncertainty_sequence[] = {
  { &hf_lix2_point_01       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { &hf_lix2_altitude       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Altitude },
  { &hf_lix2_uncertaintyEllipse, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UncertaintyEllipse },
  { &hf_lix2_uncertaintyAltitude, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Uncertainty },
  { &hf_lix2_confidence     , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_Confidence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PointAltitudeUncertainty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PointAltitudeUncertainty_sequence, hf_index, ett_lix2_PointAltitudeUncertainty);

  return offset;
}



static int
dissect_lix2_InnerRadius(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_Angle(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EllipsoidArc_sequence[] = {
  { &hf_lix2_point_01       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GeographicalCoordinates },
  { &hf_lix2_innerRadius    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_InnerRadius },
  { &hf_lix2_uncertaintyRadius, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Uncertainty },
  { &hf_lix2_offsetAngle    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Angle },
  { &hf_lix2_includedAngle  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_Angle },
  { &hf_lix2_confidence     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_Confidence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_EllipsoidArc(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EllipsoidArc_sequence, hf_index, ett_lix2_EllipsoidArc);

  return offset;
}


static const value_string lix2_GeographicArea_vals[] = {
  {   1, "point" },
  {   2, "pointUncertaintyCircle" },
  {   3, "pointUncertaintyEllipse" },
  {   4, "polygon" },
  {   5, "pointAltitude" },
  {   6, "pointAltitudeUncertainty" },
  {   7, "ellipsoidArc" },
  { 0, NULL }
};

static const ber_choice_t GeographicArea_choice[] = {
  {   1, &hf_lix2_point          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_Point },
  {   2, &hf_lix2_pointUncertaintyCircle, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PointUncertaintyCircle },
  {   3, &hf_lix2_pointUncertaintyEllipse, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PointUncertaintyEllipse },
  {   4, &hf_lix2_polygon        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Polygon },
  {   5, &hf_lix2_pointAltitude  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PointAltitude },
  {   6, &hf_lix2_pointAltitudeUncertainty, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_PointAltitudeUncertainty },
  {   7, &hf_lix2_ellipsoidArc   , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_EllipsoidArc },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GeographicArea(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GeographicArea_choice, hf_index, ett_lix2_GeographicArea,
                                 NULL);

  return offset;
}


static const value_string lix2_RATType_vals[] = {
  {   1, "nR" },
  {   2, "eUTRA" },
  {   3, "wLAN" },
  {   4, "virtual" },
  {   5, "nBIOT" },
  {   6, "wireline" },
  {   7, "wirelineCable" },
  {   8, "wirelineBBF" },
  {   9, "lTEM" },
  {  10, "nRU" },
  {  11, "eUTRAU" },
  {  12, "trustedN3GA" },
  {  13, "trustedWLAN" },
  {  14, "uTRA" },
  {  15, "gERA" },
  { 0, NULL }
};


static int
dissect_lix2_RATType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_TimeZone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_RANCGI_vals[] = {
  {   1, "eCGI" },
  {   2, "nCGI" },
  { 0, NULL }
};

static const ber_choice_t RANCGI_choice[] = {
  {   1, &hf_lix2_eCGI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_ECGI },
  {   2, &hf_lix2_nCGI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_NCGI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_RANCGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RANCGI_choice, hf_index, ett_lix2_RANCGI,
                                 NULL);

  return offset;
}


static const ber_sequence_t CellInformation_sequence[] = {
  { &hf_lix2_rANCGI         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_RANCGI },
  { &hf_lix2_cellSiteinformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CellSiteInformation },
  { &hf_lix2_timeOfLocation , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CellInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CellInformation_sequence, hf_index, ett_lix2_CellInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CellInformation_sequence_of[1] = {
  { &hf_lix2_additionalCellIDs_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_CellInformation },
};

static int
dissect_lix2_SEQUENCE_OF_CellInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CellInformation_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_CellInformation);

  return offset;
}


static const ber_sequence_t LocationInfo_sequence[] = {
  { &hf_lix2_userLocation   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UserLocation },
  { &hf_lix2_currentLoc     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_geoInfo        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GeographicArea },
  { &hf_lix2_rATType        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_timeZone       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TimeZone },
  { &hf_lix2_additionalCellIDs, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_CellInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LocationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocationInfo_sequence, hf_index, ett_lix2_LocationInfo);

  return offset;
}


static const value_string lix2_AccuracyFulfilmentIndicator_vals[] = {
  {   1, "requestedAccuracyFulfilled" },
  {   2, "requestedAccuracyNotFulfilled" },
  { 0, NULL }
};


static int
dissect_lix2_AccuracyFulfilmentIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_AgeOfLocationEstimate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_HorizontalSpeed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t HorizontalVelocity_sequence[] = {
  { &hf_lix2_hSpeed         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalSpeed },
  { &hf_lix2_bearing        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Angle },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_HorizontalVelocity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HorizontalVelocity_sequence, hf_index, ett_lix2_HorizontalVelocity);

  return offset;
}



static int
dissect_lix2_VerticalSpeed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_VerticalDirection_vals[] = {
  {   1, "upward" },
  {   2, "downward" },
  { 0, NULL }
};


static int
dissect_lix2_VerticalDirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t HorizontalWithVerticalVelocity_sequence[] = {
  { &hf_lix2_hSpeed         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalSpeed },
  { &hf_lix2_bearing        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Angle },
  { &hf_lix2_vSpeed         , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_VerticalSpeed },
  { &hf_lix2_vDirection     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_VerticalDirection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_HorizontalWithVerticalVelocity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HorizontalWithVerticalVelocity_sequence, hf_index, ett_lix2_HorizontalWithVerticalVelocity);

  return offset;
}



static int
dissect_lix2_SpeedUncertainty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t HorizontalVelocityWithUncertainty_sequence[] = {
  { &hf_lix2_hSpeed         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalSpeed },
  { &hf_lix2_bearing        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Angle },
  { &hf_lix2_uncertainty_02 , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SpeedUncertainty },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_HorizontalVelocityWithUncertainty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HorizontalVelocityWithUncertainty_sequence, hf_index, ett_lix2_HorizontalVelocityWithUncertainty);

  return offset;
}


static const ber_sequence_t HorizontalWithVerticalVelocityAndUncertainty_sequence[] = {
  { &hf_lix2_hSpeed         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalSpeed },
  { &hf_lix2_bearing        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Angle },
  { &hf_lix2_vSpeed         , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_VerticalSpeed },
  { &hf_lix2_vDirection     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_VerticalDirection },
  { &hf_lix2_hUncertainty   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_SpeedUncertainty },
  { &hf_lix2_vUncertainty   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SpeedUncertainty },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_HorizontalWithVerticalVelocityAndUncertainty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HorizontalWithVerticalVelocityAndUncertainty_sequence, hf_index, ett_lix2_HorizontalWithVerticalVelocityAndUncertainty);

  return offset;
}


static const value_string lix2_VelocityEstimate_vals[] = {
  {   1, "horVelocity" },
  {   2, "horWithVertVelocity" },
  {   3, "horVelocityWithUncertainty" },
  {   4, "horWithVertVelocityAndUncertainty" },
  { 0, NULL }
};

static const ber_choice_t VelocityEstimate_choice[] = {
  {   1, &hf_lix2_horVelocity    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalVelocity },
  {   2, &hf_lix2_horWithVertVelocity, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalWithVerticalVelocity },
  {   3, &hf_lix2_horVelocityWithUncertainty, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalVelocityWithUncertainty },
  {   4, &hf_lix2_horWithVertVelocityAndUncertainty, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_HorizontalWithVerticalVelocityAndUncertainty },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_VelocityEstimate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 VelocityEstimate_choice, hf_index, ett_lix2_VelocityEstimate,
                                 NULL);

  return offset;
}


static const ber_sequence_t CivicAddress_sequence[] = {
  { &hf_lix2_country        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_a1             , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_a2             , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_a3             , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_a4             , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_a5             , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_a6             , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_prd            , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pod            , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_sts            , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_hno            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_hns            , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_lmk            , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_loc            , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_nam            , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pc             , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_bld            , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_unit           , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_flr            , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_room           , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_plc            , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pcn            , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pobox          , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_addcode        , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_seat           , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_rd             , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_rdsec          , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_rdbr           , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_rdsubbr        , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_prm            , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pom            , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CivicAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CivicAddress_sequence, hf_index, ett_lix2_CivicAddress);

  return offset;
}


static const value_string lix2_PositioningMethod_vals[] = {
  {   1, "cellID" },
  {   2, "eCID" },
  {   3, "oTDOA" },
  {   4, "barometricPressure" },
  {   5, "wLAN" },
  {   6, "bluetooth" },
  {   7, "mBS" },
  {   8, "motionSensor" },
  {   9, "dLTDOA" },
  {  10, "dLAOD" },
  {  11, "multiRTT" },
  {  12, "nRECID" },
  {  13, "uLTDOA" },
  {  14, "uLAOA" },
  {  15, "networkSpecific" },
  { 0, NULL }
};


static int
dissect_lix2_PositioningMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PositioningMode_vals[] = {
  {   1, "uEBased" },
  {   2, "uEAssisted" },
  {   3, "conventional" },
  { 0, NULL }
};


static int
dissect_lix2_PositioningMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_Usage_vals[] = {
  {   1, "unsuccess" },
  {   2, "successResultsNotUsed" },
  {   3, "successResultsUsedToVerifyLocation" },
  {   4, "successResultsUsedToGenerateLocation" },
  {   5, "successMethodNotDetermined" },
  { 0, NULL }
};


static int
dissect_lix2_Usage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_MethodCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PositioningMethodAndUsage_sequence[] = {
  { &hf_lix2_method         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PositioningMethod },
  { &hf_lix2_mode           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PositioningMode },
  { &hf_lix2_usage          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Usage },
  { &hf_lix2_methodCode     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MethodCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PositioningMethodAndUsage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PositioningMethodAndUsage_sequence, hf_index, ett_lix2_PositioningMethodAndUsage);

  return offset;
}


static const ber_sequence_t SET_OF_PositioningMethodAndUsage_set_of[1] = {
  { &hf_lix2_positioningDataList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_PositioningMethodAndUsage },
};

static int
dissect_lix2_SET_OF_PositioningMethodAndUsage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_PositioningMethodAndUsage_set_of, hf_index, ett_lix2_SET_OF_PositioningMethodAndUsage);

  return offset;
}


static const value_string lix2_GNSSID_vals[] = {
  {   1, "gPS" },
  {   2, "galileo" },
  {   3, "sBAS" },
  {   4, "modernizedGPS" },
  {   5, "qZSS" },
  {   6, "gLONASS" },
  {   7, "bDS" },
  {   8, "nAVIC" },
  { 0, NULL }
};


static int
dissect_lix2_GNSSID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t GNSSPositioningMethodAndUsage_sequence[] = {
  { &hf_lix2_mode           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PositioningMode },
  { &hf_lix2_gNSS           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_GNSSID },
  { &hf_lix2_usage          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Usage },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GNSSPositioningMethodAndUsage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GNSSPositioningMethodAndUsage_sequence, hf_index, ett_lix2_GNSSPositioningMethodAndUsage);

  return offset;
}


static const ber_sequence_t SET_OF_GNSSPositioningMethodAndUsage_set_of[1] = {
  { &hf_lix2_gNSSPositioningDataList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_GNSSPositioningMethodAndUsage },
};

static int
dissect_lix2_SET_OF_GNSSPositioningMethodAndUsage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_GNSSPositioningMethodAndUsage_set_of, hf_index, ett_lix2_SET_OF_GNSSPositioningMethodAndUsage);

  return offset;
}



static int
dissect_lix2_BarometricPressure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t LocationData_sequence[] = {
  { &hf_lix2_locationEstimate, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GeographicArea },
  { &hf_lix2_accuracyFulfilmentIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccuracyFulfilmentIndicator },
  { &hf_lix2_ageOfLocationEstimate, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AgeOfLocationEstimate },
  { &hf_lix2_velocityEstimate, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_VelocityEstimate },
  { &hf_lix2_civicAddress_01, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CivicAddress },
  { &hf_lix2_positioningDataList, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_PositioningMethodAndUsage },
  { &hf_lix2_gNSSPositioningDataList, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_GNSSPositioningMethodAndUsage },
  { &hf_lix2_eCGI           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ECGI },
  { &hf_lix2_nCGI           , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NCGI },
  { &hf_lix2_altitude       , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Altitude },
  { &hf_lix2_barometricPressure, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BarometricPressure },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LocationData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocationData_sequence, hf_index, ett_lix2_LocationData);

  return offset;
}



static int
dissect_lix2_INTEGER_1_699(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string lix2_RawMLPResponse_vals[] = {
  {   1, "mLPPositionData" },
  {   2, "mLPErrorCode" },
  { 0, NULL }
};

static const ber_choice_t RawMLPResponse_choice[] = {
  {   1, &hf_lix2_mLPPositionData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  {   2, &hf_lix2_mLPErrorCode   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER_1_699 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_RawMLPResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RawMLPResponse_choice, hf_index, ett_lix2_RawMLPResponse,
                                 NULL);

  return offset;
}


static const ber_sequence_t PositioningInfo_sequence[] = {
  { &hf_lix2_positionInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_LocationData },
  { &hf_lix2_rawMLPResponse , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_RawMLPResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PositioningInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PositioningInfo_sequence, hf_index, ett_lix2_PositioningInfo);

  return offset;
}


static const value_string lix2_AMFEventType_vals[] = {
  {   1, "locationReport" },
  {   2, "presenceInAOIReport" },
  { 0, NULL }
};


static int
dissect_lix2_AMFEventType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PresenceState_vals[] = {
  {   1, "inArea" },
  {   2, "outOfArea" },
  {   3, "unknown" },
  {   4, "inactive" },
  { 0, NULL }
};


static int
dissect_lix2_PresenceState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SET_OF_TAI_set_of[1] = {
  { &hf_lix2_trackingAreaList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_TAI },
};

static int
dissect_lix2_SET_OF_TAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_TAI_set_of, hf_index, ett_lix2_SET_OF_TAI);

  return offset;
}


static const ber_sequence_t SET_OF_ECGI_set_of[1] = {
  { &hf_lix2_eCGIList_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_ECGI },
};

static int
dissect_lix2_SET_OF_ECGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ECGI_set_of, hf_index, ett_lix2_SET_OF_ECGI);

  return offset;
}


static const ber_sequence_t SET_OF_NCGI_set_of[1] = {
  { &hf_lix2_nCGIList_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_NCGI },
};

static int
dissect_lix2_SET_OF_NCGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_NCGI_set_of, hf_index, ett_lix2_SET_OF_NCGI);

  return offset;
}


static const ber_sequence_t SET_OF_GlobalRANNodeID_set_of[1] = {
  { &hf_lix2_globalRANNodeIDList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_GlobalRANNodeID },
};

static int
dissect_lix2_SET_OF_GlobalRANNodeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_GlobalRANNodeID_set_of, hf_index, ett_lix2_SET_OF_GlobalRANNodeID);

  return offset;
}


static const ber_sequence_t PresenceInfo_sequence[] = {
  { &hf_lix2_presenceState  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PresenceState },
  { &hf_lix2_trackingAreaList, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_TAI },
  { &hf_lix2_eCGIList       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_ECGI },
  { &hf_lix2_nCGIList       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_NCGI },
  { &hf_lix2_globalRANNodeIDList, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_GlobalRANNodeID },
  { &hf_lix2_globalENbIDList, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_GlobalRANNodeID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PresenceInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PresenceInfo_sequence, hf_index, ett_lix2_PresenceInfo);

  return offset;
}


static const ber_sequence_t LADNInfo_sequence[] = {
  { &hf_lix2_lADN           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_presence       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PresenceState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LADNInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LADNInfo_sequence, hf_index, ett_lix2_LADNInfo);

  return offset;
}


static const ber_sequence_t AMFEventArea_sequence[] = {
  { &hf_lix2_presenceInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PresenceInfo },
  { &hf_lix2_lADNInfo       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_LADNInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFEventArea(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFEventArea_sequence, hf_index, ett_lix2_AMFEventArea);

  return offset;
}


static const ber_sequence_t SET_OF_AMFEventArea_set_of[1] = {
  { &hf_lix2_areaList_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_AMFEventArea },
};

static int
dissect_lix2_SET_OF_AMFEventArea(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AMFEventArea_set_of, hf_index, ett_lix2_SET_OF_AMFEventArea);

  return offset;
}


static const value_string lix2_AccessType_vals[] = {
  {   1, "threeGPPAccess" },
  {   2, "nonThreeGPPAccess" },
  {   3, "threeGPPandNonThreeGPPAccess" },
  { 0, NULL }
};


static int
dissect_lix2_AccessType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AccessType_set_of[1] = {
  { &hf_lix2_accessTypes_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_lix2_AccessType },
};

static int
dissect_lix2_SET_OF_AccessType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AccessType_set_of, hf_index, ett_lix2_SET_OF_AccessType);

  return offset;
}


static const value_string lix2_RMState_vals[] = {
  {   1, "registered" },
  {   2, "deregistered" },
  { 0, NULL }
};


static int
dissect_lix2_RMState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t RMInfo_sequence[] = {
  { &hf_lix2_rMState        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_RMState },
  { &hf_lix2_accessType     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_RMInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RMInfo_sequence, hf_index, ett_lix2_RMInfo);

  return offset;
}


static const ber_sequence_t SET_OF_RMInfo_set_of[1] = {
  { &hf_lix2_rMInfoList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_RMInfo },
};

static int
dissect_lix2_SET_OF_RMInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_RMInfo_set_of, hf_index, ett_lix2_SET_OF_RMInfo);

  return offset;
}


static const value_string lix2_CMState_vals[] = {
  {   1, "idle" },
  {   2, "connected" },
  { 0, NULL }
};


static int
dissect_lix2_CMState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CMInfo_sequence[] = {
  { &hf_lix2_cMState        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_CMState },
  { &hf_lix2_accessType     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CMInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CMInfo_sequence, hf_index, ett_lix2_CMInfo);

  return offset;
}


static const ber_sequence_t SET_OF_CMInfo_set_of[1] = {
  { &hf_lix2_cMInfoList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_CMInfo },
};

static int
dissect_lix2_SET_OF_CMInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_CMInfo_set_of, hf_index, ett_lix2_SET_OF_CMInfo);

  return offset;
}


static const value_string lix2_UEReachability_vals[] = {
  {   1, "unreachable" },
  {   2, "reachable" },
  {   3, "regulatoryOnly" },
  { 0, NULL }
};


static int
dissect_lix2_UEReachability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t LocationPresenceReport_sequence[] = {
  { &hf_lix2_type           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFEventType },
  { &hf_lix2_timestamp      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_areaList       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_AMFEventArea },
  { &hf_lix2_timeZone       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TimeZone },
  { &hf_lix2_accessTypes    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_AccessType },
  { &hf_lix2_rMInfoList     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_RMInfo },
  { &hf_lix2_cMInfoList     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SET_OF_CMInfo },
  { &hf_lix2_reachability   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UEReachability },
  { &hf_lix2_location_02    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UserLocation },
  { &hf_lix2_additionalCellIDs, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_CellInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LocationPresenceReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocationPresenceReport_sequence, hf_index, ett_lix2_LocationPresenceReport);

  return offset;
}



static int
dissect_lix2_LAC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t LAI_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_lAC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_LAC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LAI_sequence, hf_index, ett_lix2_LAI);

  return offset;
}



static int
dissect_lix2_CellID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CGI_sequence[] = {
  { &hf_lix2_lAI            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_LAI },
  { &hf_lix2_cellID         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_CellID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CGI_sequence, hf_index, ett_lix2_CGI);

  return offset;
}



static int
dissect_lix2_SAC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SAI_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_lAC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_LAC },
  { &hf_lix2_sAC            , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SAC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SAI_sequence, hf_index, ett_lix2_SAI);

  return offset;
}



static int
dissect_lix2_CellPortionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ESMLCCellInfo_sequence[] = {
  { &hf_lix2_eCGI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_ECGI },
  { &hf_lix2_cellPortionID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_CellPortionID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ESMLCCellInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ESMLCCellInfo_sequence, hf_index, ett_lix2_ESMLCCellInfo);

  return offset;
}


static const ber_sequence_t EPSLocationInfo_sequence[] = {
  { &hf_lix2_locationData   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_LocationData },
  { &hf_lix2_cGI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_CGI },
  { &hf_lix2_sAI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SAI },
  { &hf_lix2_eSMLCCellInfo  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ESMLCCellInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_EPSLocationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPSLocationInfo_sequence, hf_index, ett_lix2_EPSLocationInfo);

  return offset;
}


static const ber_sequence_t Location_sequence[] = {
  { &hf_lix2_locationInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_LocationInfo },
  { &hf_lix2_positioningInfo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PositioningInfo },
  { &hf_lix2_locationPresenceReport, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_LocationPresenceReport },
  { &hf_lix2_ePSLocationInfo, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EPSLocationInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_Location(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Location_sequence, hf_index, ett_lix2_Location);

  return offset;
}



static int
dissect_lix2_MACAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_UEEndpointAddress_vals[] = {
  {   1, "iPv4Address" },
  {   2, "iPv6Address" },
  {   3, "ethernetAddress" },
  { 0, NULL }
};

static const ber_choice_t UEEndpointAddress_choice[] = {
  {   1, &hf_lix2_iPv4Address    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IPv4Address },
  {   2, &hf_lix2_iPv6Address    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_IPv6Address },
  {   3, &hf_lix2_ethernetAddress, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MACAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UEEndpointAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UEEndpointAddress_choice, hf_index, ett_lix2_UEEndpointAddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t TAIList_sequence_of[1] = {
  { &hf_lix2_TAIList_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_TAI },
};

static int
dissect_lix2_TAIList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TAIList_sequence_of, hf_index, ett_lix2_TAIList);

  return offset;
}


static const value_string lix2_SMSOverNASIndicator_vals[] = {
  {   1, "sMSOverNASNotAllowed" },
  {   2, "sMSOverNASAllowed" },
  { 0, NULL }
};


static int
dissect_lix2_SMSOverNASIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_MMEGroupID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_MMECode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_TMSI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t GUTI_sequence[] = {
  { &hf_lix2_mCC            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MCC },
  { &hf_lix2_mNC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MNC },
  { &hf_lix2_mMEGroupID     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMEGroupID },
  { &hf_lix2_mMECode        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMECode },
  { &hf_lix2_mTMSI          , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_TMSI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GUTI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GUTI_sequence, hf_index, ett_lix2_GUTI);

  return offset;
}


static const value_string lix2_EPS5GGUTI_vals[] = {
  {   1, "gUTI" },
  {   2, "fiveGGUTI" },
  { 0, NULL }
};

static const ber_choice_t EPS5GGUTI_choice[] = {
  {   1, &hf_lix2_gUTI_01        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  {   2, &hf_lix2_fiveGGUTI      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_EPS5GGUTI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EPS5GGUTI_choice, hf_index, ett_lix2_EPS5GGUTI,
                                 NULL);

  return offset;
}


static const value_string lix2_EMMRegStatus_vals[] = {
  {   1, "uEEMMRegistered" },
  {   2, "uENotEMMRegistered" },
  { 0, NULL }
};


static int
dissect_lix2_EMMRegStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_FiveGMMStatus_vals[] = {
  {   1, "uE5GMMRegistered" },
  {   2, "uENot5GMMRegistered" },
  { 0, NULL }
};


static int
dissect_lix2_FiveGMMStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t EMM5GMMStatus_sequence[] = {
  { &hf_lix2_eMMRegStatus   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EMMRegStatus },
  { &hf_lix2_fiveGMMStatus  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGMMStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_EMM5GMMStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EMM5GMMStatus_sequence, hf_index, ett_lix2_EMM5GMMStatus);

  return offset;
}


static const ber_sequence_t AMFRegistration_sequence[] = {
  { &hf_lix2_registrationType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegistrationType },
  { &hf_lix2_registrationResult, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegistrationResult },
  { &hf_lix2_slice          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Slice },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUCI           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUCI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUTI           , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_fiveGSTAIList  , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAIList },
  { &hf_lix2_sMSOverNasIndicator, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSOverNASIndicator },
  { &hf_lix2_oldGUTI        , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_EPS5GGUTI },
  { &hf_lix2_eMM5GRegStatus , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EMM5GMMStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFRegistration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFRegistration_sequence, hf_index, ett_lix2_AMFRegistration);

  return offset;
}


static const value_string lix2_AMFDirection_vals[] = {
  {   1, "networkInitiated" },
  {   2, "uEInitiated" },
  { 0, NULL }
};


static int
dissect_lix2_AMFDirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_FiveGMMCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string lix2_SwitchOffIndicator_vals[] = {
  {   1, "normalDetach" },
  {   2, "switchOff" },
  { 0, NULL }
};


static int
dissect_lix2_SwitchOffIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_ReRegRequiredIndicator_vals[] = {
  {   1, "reRegistrationRequired" },
  {   2, "reRegistrationNotRequired" },
  { 0, NULL }
};


static int
dissect_lix2_ReRegRequiredIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AMFDeregistration_sequence[] = {
  { &hf_lix2_deregistrationDirection, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFDirection },
  { &hf_lix2_accessType     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUCI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUCI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUTI           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { &hf_lix2_cause          , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGMMCause },
  { &hf_lix2_location_01    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_switchOffIndicator, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SwitchOffIndicator },
  { &hf_lix2_reRegRequiredIndicator, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ReRegRequiredIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFDeregistration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFDeregistration_sequence, hf_index, ett_lix2_AMFDeregistration);

  return offset;
}


static const ber_sequence_t AMFLocationUpdate_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUCI           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUCI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUTI           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_sMSOverNASIndicator, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSOverNASIndicator },
  { &hf_lix2_oldGUTI        , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_EPS5GGUTI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFLocationUpdate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFLocationUpdate_sequence, hf_index, ett_lix2_AMFLocationUpdate);

  return offset;
}


static const ber_sequence_t AMFStartOfInterceptionWithRegisteredUE_sequence[] = {
  { &hf_lix2_registrationResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegistrationResult },
  { &hf_lix2_registrationType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegistrationType },
  { &hf_lix2_slice          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Slice },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUCI           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUCI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUTI           , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_timeOfRegistration, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_fiveGSTAIList  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAIList },
  { &hf_lix2_sMSOverNASIndicator, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSOverNASIndicator },
  { &hf_lix2_oldGUTI        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_EPS5GGUTI },
  { &hf_lix2_eMM5GRegStatus , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EMM5GMMStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFStartOfInterceptionWithRegisteredUE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFStartOfInterceptionWithRegisteredUE_sequence, hf_index, ett_lix2_AMFStartOfInterceptionWithRegisteredUE);

  return offset;
}


static const value_string lix2_AMFFailedProcedureType_vals[] = {
  {   1, "registration" },
  {   2, "sMS" },
  {   3, "pDUSessionEstablishment" },
  { 0, NULL }
};


static int
dissect_lix2_AMFFailedProcedureType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_FiveGSMCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string lix2_AMFFailureCause_vals[] = {
  {   1, "fiveGMMCause" },
  {   2, "fiveGSMCause" },
  { 0, NULL }
};

static const ber_choice_t AMFFailureCause_choice[] = {
  {   1, &hf_lix2_fiveGMMCause   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGMMCause },
  {   2, &hf_lix2_fiveGSMCause   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMCause },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AMFFailureCause_choice, hf_index, ett_lix2_AMFFailureCause,
                                 NULL);

  return offset;
}


static const ber_sequence_t AMFUnsuccessfulProcedure_sequence[] = {
  { &hf_lix2_failedProcedureType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFFailedProcedureType },
  { &hf_lix2_failureCause_02, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_AMFFailureCause },
  { &hf_lix2_requestedSlice , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NSSAI },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUCI           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUCI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUTI           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFUnsuccessfulProcedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFUnsuccessfulProcedure_sequence, hf_index, ett_lix2_AMFUnsuccessfulProcedure);

  return offset;
}



static int
dissect_lix2_SUPIUnauthenticatedIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_lix2_PDUSessionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_INTEGER_0_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t FTEID_sequence[] = {
  { &hf_lix2_tEID           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER_0_4294967295 },
  { &hf_lix2_iPv4Address    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPv4Address },
  { &hf_lix2_iPv6Address    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPv6Address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_FTEID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FTEID_sequence, hf_index, ett_lix2_FTEID);

  return offset;
}


static const value_string lix2_PDUSessionType_vals[] = {
  {   1, "iPv4" },
  {   2, "iPv6" },
  {   3, "iPv4v6" },
  {   4, "unstructured" },
  {   5, "ethernet" },
  { 0, NULL }
};


static int
dissect_lix2_PDUSessionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_UEEndpointAddress_sequence_of[1] = {
  { &hf_lix2_uEEndpoint_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
};

static int
dissect_lix2_SEQUENCE_OF_UEEndpointAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_UEEndpointAddress_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_UEEndpointAddress);

  return offset;
}



static int
dissect_lix2_DNN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t AMFID_sequence[] = {
  { &hf_lix2_aMFRegionID    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegionID },
  { &hf_lix2_aMFSetID       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AMFSetID },
  { &hf_lix2_aMFPointer     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_AMFPointer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFID_sequence, hf_index, ett_lix2_AMFID);

  return offset;
}



static int
dissect_lix2_HSMFURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_FiveGSMRequestType_vals[] = {
  {   1, "initialRequest" },
  {   2, "existingPDUSession" },
  {   3, "initialEmergencyRequest" },
  {   4, "existingEmergencyPDUSession" },
  {   5, "modificationRequest" },
  {   6, "reserved" },
  {   7, "mAPDURequest" },
  { 0, NULL }
};


static int
dissect_lix2_FiveGSMRequestType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_SMPDUDNRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_UEEPSPDNConnection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SMFPDUSessionEstablishment_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_gTPTunnelID    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_FTEID },
  { &hf_lix2_pDUSessionType , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionType },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_uEEndpoint     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UEEndpointAddress },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_dNN            , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_aMFID          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_hSMFURI        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HSMFURI },
  { &hf_lix2_requestType    , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_accessType     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_rATType        , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_sMPDUDNRequest , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMPDUDNRequest },
  { &hf_lix2_uEEPSPDNConnection, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UEEPSPDNConnection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFPDUSessionEstablishment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFPDUSessionEstablishment_sequence, hf_index, ett_lix2_SMFPDUSessionEstablishment);

  return offset;
}


static const ber_sequence_t SMFPDUSessionModification_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_requestType    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_accessType     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_rATType        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFPDUSessionModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFPDUSessionModification_sequence, hf_index, ett_lix2_SMFPDUSessionModification);

  return offset;
}



static int
dissect_lix2_SMFErrorCodes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SMFPDUSessionRelease_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_timeOfFirstPacket, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_timeOfLastPacket, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_uplinkVolume   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_downlinkVolume , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_location_01    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_cause_01       , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFErrorCodes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFPDUSessionRelease(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFPDUSessionRelease_sequence, hf_index, ett_lix2_SMFPDUSessionRelease);

  return offset;
}


static const ber_sequence_t SMFStartOfInterceptionWithEstablishedPDUSession_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_gTPTunnelID    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_FTEID },
  { &hf_lix2_pDUSessionType , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionType },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_uEEndpoint     , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UEEndpointAddress },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_dNN            , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_aMFID          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_hSMFURI        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HSMFURI },
  { &hf_lix2_requestType    , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_accessType     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_rATType        , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_sMPDUDNRequest , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMPDUDNRequest },
  { &hf_lix2_timeOfSessionEstablishment, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFStartOfInterceptionWithEstablishedPDUSession(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFStartOfInterceptionWithEstablishedPDUSession_sequence, hf_index, ett_lix2_SMFStartOfInterceptionWithEstablishedPDUSession);

  return offset;
}


static const value_string lix2_SMFFailedProcedureType_vals[] = {
  {   1, "pDUSessionEstablishment" },
  {   2, "pDUSessionModification" },
  {   3, "pDUSessionRelease" },
  { 0, NULL }
};


static int
dissect_lix2_SMFFailedProcedureType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_Initiator_vals[] = {
  {   1, "uE" },
  {   2, "network" },
  {   3, "unknown" },
  { 0, NULL }
};


static int
dissect_lix2_Initiator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SMFUnsuccessfulProcedure_sequence[] = {
  { &hf_lix2_failedProcedureType_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SMFFailedProcedureType },
  { &hf_lix2_failureCause_03, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMCause },
  { &hf_lix2_initiator      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Initiator },
  { &hf_lix2_requestedSlice , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NSSAI },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_uEEndpoint     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UEEndpointAddress },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_dNN            , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_aMFID          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_hSMFURI        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HSMFURI },
  { &hf_lix2_requestType    , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_accessType     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_rATType        , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_sMPDUDNRequest , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMPDUDNRequest },
  { &hf_lix2_location_01    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFUnsuccessfulProcedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFUnsuccessfulProcedure_sequence, hf_index, ett_lix2_SMFUnsuccessfulProcedure);

  return offset;
}


static const ber_sequence_t GUAMI_sequence[] = {
  { &hf_lix2_aMFID          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GUAMI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GUAMI_sequence, hf_index, ett_lix2_GUAMI);

  return offset;
}



static int
dissect_lix2_MMEGI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_MMEC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t MMEID_sequence[] = {
  { &hf_lix2_mMEGI          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMEGI },
  { &hf_lix2_mMEC           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMEC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMEID_sequence, hf_index, ett_lix2_MMEID);

  return offset;
}


static const ber_sequence_t GUMMEI_sequence[] = {
  { &hf_lix2_mMEID          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMEID },
  { &hf_lix2_mCC            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MCC },
  { &hf_lix2_mNC            , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MNC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_GUMMEI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GUMMEI_sequence, hf_index, ett_lix2_GUMMEI);

  return offset;
}


static const value_string lix2_UDMServingSystemMethod_vals[] = {
  {   0, "amf3GPPAccessRegistration" },
  {   1, "amfNon3GPPAccessRegistration" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_lix2_UDMServingSystemMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_CAGID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CAGID_sequence_of[1] = {
  { &hf_lix2_cAGID_item     , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_CAGID },
};

static int
dissect_lix2_SEQUENCE_OF_CAGID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CAGID_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_CAGID);

  return offset;
}


static const ber_sequence_t ServiceID_sequence[] = {
  { &hf_lix2_nSSAI          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NSSAI },
  { &hf_lix2_cAGID          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_CAGID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ServiceID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceID_sequence, hf_index, ett_lix2_ServiceID);

  return offset;
}


static const ber_sequence_t UDMServingSystemMessage_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUAMI          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUAMI },
  { &hf_lix2_gUMMEI         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUMMEI },
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_servingSystemMethod, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_UDMServingSystemMethod },
  { &hf_lix2_serviceID      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ServiceID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UDMServingSystemMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UDMServingSystemMessage_sequence, hf_index, ett_lix2_UDMServingSystemMessage);

  return offset;
}



static int
dissect_lix2_SMSAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SMSParty_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_sMSAddress     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMSParty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMSParty_sequence, hf_index, ett_lix2_SMSParty);

  return offset;
}


static const value_string lix2_Direction_vals[] = {
  {   1, "fromTarget" },
  {   2, "toTarget" },
  { 0, NULL }
};


static int
dissect_lix2_Direction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_SMSTransferStatus_vals[] = {
  {   1, "transferSucceeded" },
  {   2, "transferFailed" },
  {   3, "undefined" },
  { 0, NULL }
};


static int
dissect_lix2_SMSTransferStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_SMSOtherMessageIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string lix2_IPAddress_vals[] = {
  {   1, "iPv4Address" },
  {   2, "iPv6Address" },
  { 0, NULL }
};

static const ber_choice_t IPAddress_choice[] = {
  {   1, &hf_lix2_iPv4Address    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IPv4Address },
  {   2, &hf_lix2_iPv6Address    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_IPv6Address },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_IPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPAddress_choice, hf_index, ett_lix2_IPAddress,
                                 NULL);

  return offset;
}



static int
dissect_lix2_E164Number(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_SMSNFAddress_vals[] = {
  {   1, "iPAddress" },
  {   2, "e164Number" },
  { 0, NULL }
};

static const ber_choice_t SMSNFAddress_choice[] = {
  {   1, &hf_lix2_iPAddress      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IPAddress },
  {   2, &hf_lix2_e164Number     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_E164Number },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMSNFAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SMSNFAddress_choice, hf_index, ett_lix2_SMSNFAddress,
                                 NULL);

  return offset;
}


static const value_string lix2_SMSNFType_vals[] = {
  {   1, "sMSGMSC" },
  {   2, "iWMSC" },
  {   3, "sMSRouter" },
  { 0, NULL }
};


static int
dissect_lix2_SMSNFType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_SMSTPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_TruncatedSMSTPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_SMSTPDUData_vals[] = {
  {   1, "sMSTPDU" },
  {   2, "truncatedSMSTPDU" },
  { 0, NULL }
};

static const ber_choice_t SMSTPDUData_choice[] = {
  {   1, &hf_lix2_sMSTPDU        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SMSTPDU },
  {   2, &hf_lix2_truncatedSMSTPDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_TruncatedSMSTPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMSTPDUData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SMSTPDUData_choice, hf_index, ett_lix2_SMSTPDUData,
                                 NULL);

  return offset;
}


static const value_string lix2_SMSMessageType_vals[] = {
  {   1, "deliver" },
  {   2, "deliverReportAck" },
  {   3, "deliverReportError" },
  {   4, "statusReport" },
  {   5, "command" },
  {   6, "submit" },
  {   7, "submitReportAck" },
  {   8, "submitReportError" },
  {   9, "reserved" },
  { 0, NULL }
};


static int
dissect_lix2_SMSMessageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_SMSRPMessageReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SMSMessage_sequence[] = {
  { &hf_lix2_originatingSMSParty, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SMSParty },
  { &hf_lix2_terminatingSMSParty_02, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_SMSParty },
  { &hf_lix2_direction      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_linkTransferStatus, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SMSTransferStatus },
  { &hf_lix2_otherMessage   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSOtherMessageIndication },
  { &hf_lix2_location_01    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_peerNFAddress  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SMSNFAddress },
  { &hf_lix2_peerNFType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSNFType },
  { &hf_lix2_sMSTPDUData    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SMSTPDUData },
  { &hf_lix2_messageType    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSMessageType },
  { &hf_lix2_rPMessageReference, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMSRPMessageReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMSMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMSMessage_sequence, hf_index, ett_lix2_SMSMessage);

  return offset;
}



static int
dissect_lix2_SIPURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_TELURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_IMPU_vals[] = {
  {   1, "sIPURI" },
  {   2, "tELURI" },
  { 0, NULL }
};

static const ber_choice_t IMPU_choice[] = {
  {   1, &hf_lix2_sIPURI         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SIPURI },
  {   2, &hf_lix2_tELURI         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_TELURI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_IMPU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IMPU_choice, hf_index, ett_lix2_IMPU,
                                 NULL);

  return offset;
}


static const ber_sequence_t LALSReport_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_iMPU           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IMPU },
  { &hf_lix2_iMSI           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LALSReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LALSReport_sequence, hf_index, ett_lix2_LALSReport);

  return offset;
}



static int
dissect_lix2_PortNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_NextLayerProtocol(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_IPv6FlowLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PDHeaderReport_sequence[] = {
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_sourceIPAddress, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_sourcePort     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationIPAddress, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_destinationPort, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_nextLayerProtocol, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_NextLayerProtocol },
  { &hf_lix2_iPv6flowLabel  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPv6FlowLabel },
  { &hf_lix2_direction      , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_packetSize     , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PDHeaderReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDHeaderReport_sequence, hf_index, ett_lix2_PDHeaderReport);

  return offset;
}


static const value_string lix2_PDSRSummaryTrigger_vals[] = {
  {   1, "timerExpiry" },
  {   2, "packetCount" },
  {   3, "byteCount" },
  {   4, "startOfFlow" },
  {   5, "endOfFlow" },
  { 0, NULL }
};


static int
dissect_lix2_PDSRSummaryTrigger(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PDSummaryReport_sequence[] = {
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_sourceIPAddress, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_sourcePort     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationIPAddress, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_destinationPort, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_nextLayerProtocol, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_NextLayerProtocol },
  { &hf_lix2_iPv6flowLabel  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IPv6FlowLabel },
  { &hf_lix2_direction      , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pDSRSummaryTrigger, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_PDSRSummaryTrigger },
  { &hf_lix2_firstPacketTimestamp, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_lastPacketTimestamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_packetCount    , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_byteCount      , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PDSummaryReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDSummaryReport_sequence, hf_index, ett_lix2_PDSummaryReport);

  return offset;
}


static const ber_sequence_t MMSVersion_sequence[] = {
  { &hf_lix2_majorVersion   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_minorVersion   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSVersion_sequence, hf_index, ett_lix2_MMSVersion);

  return offset;
}



static int
dissect_lix2_EmailAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_IMPI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_lix2_NAI(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string lix2_MMSPartyID_vals[] = {
  {   1, "e164Number" },
  {   2, "emailAddress" },
  {   3, "iMSI" },
  {   4, "iMPU" },
  {   5, "iMPI" },
  {   6, "sUPI" },
  {   7, "gPSI" },
  { 0, NULL }
};

static const ber_choice_t MMSPartyID_choice[] = {
  {   1, &hf_lix2_e164Number     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_E164Number },
  {   2, &hf_lix2_emailAddress   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_EmailAddress },
  {   3, &hf_lix2_iMSI           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  {   4, &hf_lix2_iMPU           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_IMPU },
  {   5, &hf_lix2_iMPI           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_IMPI },
  {   6, &hf_lix2_sUPI           , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SUPI },
  {   7, &hf_lix2_gPSI           , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_GPSI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSPartyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MMSPartyID_choice, hf_index, ett_lix2_MMSPartyID,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MMSPartyID_sequence_of[1] = {
  { &hf_lix2_mMSPartyIDs_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_MMSPartyID },
};

static int
dissect_lix2_SEQUENCE_OF_MMSPartyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MMSPartyID_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_MMSPartyID);

  return offset;
}


static const value_string lix2_NonLocalID_vals[] = {
  {   1, "local" },
  {   2, "nonLocal" },
  { 0, NULL }
};


static int
dissect_lix2_NonLocalID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSParty_sequence[] = {
  { &hf_lix2_mMSPartyIDs    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSPartyID },
  { &hf_lix2_nonLocalID     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_NonLocalID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSParty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSParty_sequence, hf_index, ett_lix2_MMSParty);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MMSParty_sequence_of[1] = {
  { &hf_lix2_terminatingMMSParty_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_MMSParty },
};

static int
dissect_lix2_SEQUENCE_OF_MMSParty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MMSParty_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_MMSParty);

  return offset;
}


static const value_string lix2_MMSDirection_vals[] = {
  {   0, "fromTarget" },
  {   1, "toTarget" },
  { 0, NULL }
};


static int
dissect_lix2_MMSDirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_MMSSubject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_MMSMessageClass_vals[] = {
  {   1, "personal" },
  {   2, "advertisement" },
  {   3, "informational" },
  {   4, "auto" },
  { 0, NULL }
};


static int
dissect_lix2_MMSMessageClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_MMSPeriodFormat_vals[] = {
  {   1, "absolute" },
  {   2, "relative" },
  { 0, NULL }
};


static int
dissect_lix2_MMSPeriodFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSExpiry_sequence[] = {
  { &hf_lix2_expiryPeriod   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_periodFormat   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSPeriodFormat },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSExpiry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSExpiry_sequence, hf_index, ett_lix2_MMSExpiry);

  return offset;
}


static const value_string lix2_MMSPriority_vals[] = {
  {   1, "low" },
  {   2, "normal" },
  {   3, "high" },
  { 0, NULL }
};


static int
dissect_lix2_MMSPriority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_MMState_vals[] = {
  {   1, "draft" },
  {   2, "sent" },
  {   3, "new" },
  {   4, "retrieved" },
  {   5, "forwarded" },
  { 0, NULL }
};


static int
dissect_lix2_MMState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_MMStateFlag_vals[] = {
  {   1, "add" },
  {   2, "remove" },
  {   3, "filter" },
  { 0, NULL }
};


static int
dissect_lix2_MMStateFlag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMFlags_sequence[] = {
  { &hf_lix2_length         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_flag           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMStateFlag },
  { &hf_lix2_flagString     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMFlags_sequence, hf_index, ett_lix2_MMFlags);

  return offset;
}


static const value_string lix2_MMSReplyCharging_vals[] = {
  {   0, "requested" },
  {   1, "requestedTextOnly" },
  {   2, "accepted" },
  {   3, "acceptedTextOnly" },
  { 0, NULL }
};


static int
dissect_lix2_MMSReplyCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_MMSContentClass_vals[] = {
  {   1, "text" },
  {   2, "imageBasic" },
  {   3, "imageRich" },
  {   4, "videoBasic" },
  {   5, "videoRich" },
  {   6, "megaPixel" },
  {   7, "contentBasic" },
  {   8, "contentRich" },
  { 0, NULL }
};


static int
dissect_lix2_MMSContentClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSAdaptation_sequence[] = {
  { &hf_lix2_allowed        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_overriden      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSAdaptation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSAdaptation_sequence, hf_index, ett_lix2_MMSAdaptation);

  return offset;
}



static int
dissect_lix2_MMSContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lix2_MMSResponseStatus_vals[] = {
  {   1, "ok" },
  {   2, "errorUnspecified" },
  {   3, "errorServiceDenied" },
  {   4, "errorMessageFormatCorrupt" },
  {   5, "errorSendingAddressUnresolved" },
  {   6, "errorMessageNotFound" },
  {   7, "errorNetworkProblem" },
  {   8, "errorContentNotAccepted" },
  {   9, "errorUnsupportedMessage" },
  {  10, "errorTransientFailure" },
  {  11, "errorTransientSendingAddressUnresolved" },
  {  12, "errorTransientMessageNotFound" },
  {  13, "errorTransientNetworkProblem" },
  {  14, "errorTransientPartialSuccess" },
  {  15, "errorPermanentFailure" },
  {  16, "errorPermanentServiceDenied" },
  {  17, "errorPermanentMessageFormatCorrupt" },
  {  18, "errorPermanentSendingAddressUnresolved" },
  {  19, "errorPermanentMessageNotFound" },
  {  20, "errorPermanentContentNotAccepted" },
  {  21, "errorPermanentReplyChargingLimitationsNotMet" },
  {  22, "errorPermanentReplyChargingRequestNotAccepted" },
  {  23, "errorPermanentReplyChargingForwardingDenied" },
  {  24, "errorPermanentReplyChargingNotSupported" },
  {  25, "errorPermanentAddressHidingNotSupported" },
  {  26, "errorPermanentLackOfPrepaid" },
  { 0, NULL }
};


static int
dissect_lix2_MMSResponseStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSSend_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_dateTime       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_cCRecipients   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_bCCRecipients  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_subject        , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSSubject },
  { &hf_lix2_messageClass   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSMessageClass },
  { &hf_lix2_expiry         , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_MMSExpiry },
  { &hf_lix2_desiredDeliveryTime, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_priority       , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPriority },
  { &hf_lix2_senderVisibility, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_deliveryReport , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_readReport     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_store          , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_state          , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMState },
  { &hf_lix2_flags          , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMFlags },
  { &hf_lix2_replyCharging  , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSReplyCharging },
  { &hf_lix2_applicID       , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentClass   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentClass },
  { &hf_lix2_dRMContent     , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_adaptationAllowed, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSAdaptation },
  { &hf_lix2_contentType    , BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentType },
  { &hf_lix2_responseStatus , BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_lix2_MMSResponseStatus },
  { &hf_lix2_responseStatusText, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_messageID      , BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSSend(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSSend_sequence, hf_index, ett_lix2_MMSSend);

  return offset;
}


static const ber_sequence_t MMSPreviouslySent_sequence[] = {
  { &hf_lix2_previouslySentByParty, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_sequenceNumber , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_previousSendDateTime, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSPreviouslySent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSPreviouslySent_sequence, hf_index, ett_lix2_MMSPreviouslySent);

  return offset;
}


static const ber_sequence_t MMSPreviouslySentBy_sequence_of[1] = {
  { &hf_lix2_MMSPreviouslySentBy_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_MMSPreviouslySent },
};

static int
dissect_lix2_MMSPreviouslySentBy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MMSPreviouslySentBy_sequence_of, hf_index, ett_lix2_MMSPreviouslySentBy);

  return offset;
}


static const ber_sequence_t MMSSendByNonLocalTarget_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_transactionID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_messageID      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_contentType    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentType },
  { &hf_lix2_messageClass   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSMessageClass },
  { &hf_lix2_dateTime       , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_expiry         , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSExpiry },
  { &hf_lix2_deliveryReport , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_priority       , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPriority },
  { &hf_lix2_senderVisibility, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_readReport     , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_subject        , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSSubject },
  { &hf_lix2_forwardCount   , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_previouslySentBy, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPreviouslySentBy },
  { &hf_lix2_prevSentByDateTime, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_applicID       , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentClass   , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentClass },
  { &hf_lix2_dRMContent     , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_adaptationAllowed, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSAdaptation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSSendByNonLocalTarget(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSSendByNonLocalTarget_sequence, hf_index, ett_lix2_MMSSendByNonLocalTarget);

  return offset;
}


static const ber_sequence_t MMSNotification_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_subject        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSSubject },
  { &hf_lix2_deliveryReportRequested, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_stored         , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_messageClass   , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMessageClass },
  { &hf_lix2_priority       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPriority },
  { &hf_lix2_messageSize    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_expiry         , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_MMSExpiry },
  { &hf_lix2_replyCharging  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSReplyCharging },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSNotification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSNotification_sequence, hf_index, ett_lix2_MMSNotification);

  return offset;
}


static const ber_sequence_t MMSSendToNonLocalTarget_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_transactionID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_messageID      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_contentType    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentType },
  { &hf_lix2_messageClass   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSMessageClass },
  { &hf_lix2_dateTime       , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_expiry         , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSExpiry },
  { &hf_lix2_deliveryReport , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_priority       , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPriority },
  { &hf_lix2_senderVisibility, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_readReport     , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_subject        , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSSubject },
  { &hf_lix2_forwardCount   , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_previouslySentBy, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPreviouslySentBy },
  { &hf_lix2_prevSentByDateTime, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_applicID       , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentClass   , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentClass },
  { &hf_lix2_dRMContent     , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_adaptationAllowed, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSAdaptation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSSendToNonLocalTarget(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSSendToNonLocalTarget_sequence, hf_index, ett_lix2_MMSSendToNonLocalTarget);

  return offset;
}


static const value_string lix2_MMStatus_vals[] = {
  {   1, "expired" },
  {   2, "retrieved" },
  {   3, "rejected" },
  {   4, "deferred" },
  {   5, "unrecognized" },
  {   6, "indeterminate" },
  {   7, "forwarded" },
  {   8, "unreachable" },
  { 0, NULL }
};


static int
dissect_lix2_MMStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSNotificationResponse_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_status         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMStatus },
  { &hf_lix2_reportAllowed  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSNotificationResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSNotificationResponse_sequence, hf_index, ett_lix2_MMSNotificationResponse);

  return offset;
}


static const value_string lix2_MMSRetrieveStatus_vals[] = {
  {   1, "success" },
  {   2, "errorTransientFailure" },
  {   3, "errorTransientMessageNotFound" },
  {   4, "errorTransientNetworkProblem" },
  {   5, "errorPermanentFailure" },
  {   6, "errorPermanentServiceDenied" },
  {   7, "errorPermanentMessageNotFound" },
  {   8, "errorPermanentContentUnsupported" },
  { 0, NULL }
};


static int
dissect_lix2_MMSRetrieveStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSRetrieval_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_messageID      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_dateTime       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_previouslySentBy, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPreviouslySentBy },
  { &hf_lix2_prevSentByDateTime, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_cCRecipients   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_subject        , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSSubject },
  { &hf_lix2_state          , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMState },
  { &hf_lix2_flags          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMFlags },
  { &hf_lix2_messageClass   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSMessageClass },
  { &hf_lix2_priority       , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_lix2_MMSPriority },
  { &hf_lix2_deliveryReport , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_readReport     , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_replyCharging  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSReplyCharging },
  { &hf_lix2_retrieveStatus , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSRetrieveStatus },
  { &hf_lix2_retrieveStatusText, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_applicID       , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentClass   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSContentClass },
  { &hf_lix2_dRMContent     , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_replaceID      , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentType_01 , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSRetrieval(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSRetrieval_sequence, hf_index, ett_lix2_MMSRetrieval);

  return offset;
}


static const ber_sequence_t MMSDeliveryAck_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_reportAllowed  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_status         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMStatus },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSDeliveryAck(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSDeliveryAck_sequence, hf_index, ett_lix2_MMSDeliveryAck);

  return offset;
}


static const value_string lix2_MMSStoreStatus_vals[] = {
  {   1, "success" },
  {   2, "errorTransientFailure" },
  {   3, "errorTransientNetworkProblem" },
  {   4, "errorPermanentFailure" },
  {   5, "errorPermanentServiceDenied" },
  {   6, "errorPermanentMessageFormatCorrupt" },
  {   7, "errorPermanentMessageNotFound" },
  {   8, "errorMMBoxFull" },
  { 0, NULL }
};


static int
dissect_lix2_MMSStoreStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSForward_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_dateTime       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_cCRecipients   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_bCCRecipients  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_expiry         , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSExpiry },
  { &hf_lix2_desiredDeliveryTime, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_deliveryReportAllowed, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_deliveryReport , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_store          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_state          , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMState },
  { &hf_lix2_flags          , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMFlags },
  { &hf_lix2_contentLocationReq, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyCharging  , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSReplyCharging },
  { &hf_lix2_responseStatus , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_lix2_MMSResponseStatus },
  { &hf_lix2_responseStatusText, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_messageID      , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentLocationConf, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_storeStatus    , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSStoreStatus },
  { &hf_lix2_storeStatusText, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSForward(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSForward_sequence, hf_index, ett_lix2_MMSForward);

  return offset;
}


static const ber_sequence_t T_contentLocationReq_sequence_of[1] = {
  { &hf_lix2_contentLocationReq_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_contentLocationReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_contentLocationReq_sequence_of, hf_index, ett_lix2_T_contentLocationReq);

  return offset;
}


static const ber_sequence_t T_contentLocationConf_sequence_of[1] = {
  { &hf_lix2_contentLocationConf_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_contentLocationConf(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_contentLocationConf_sequence_of, hf_index, ett_lix2_T_contentLocationConf);

  return offset;
}


static const value_string lix2_MMSDeleteResponseStatus_vals[] = {
  {   1, "ok" },
  {   2, "errorUnspecified" },
  {   3, "errorServiceDenied" },
  {   4, "errorMessageFormatCorrupt" },
  {   5, "errorSendingAddressUnresolved" },
  {   6, "errorMessageNotFound" },
  {   7, "errorNetworkProblem" },
  {   8, "errorContentNotAccepted" },
  {   9, "errorUnsupportedMessage" },
  {  10, "errorTransientFailure" },
  {  11, "errorTransientSendingAddressUnresolved" },
  {  12, "errorTransientMessageNotFound" },
  {  13, "errorTransientNetworkProblem" },
  {  14, "errorTransientPartialSuccess" },
  {  15, "errorPermanentFailure" },
  {  16, "errorPermanentServiceDenied" },
  {  17, "errorPermanentMessageFormatCorrupt" },
  {  18, "errorPermanentSendingAddressUnresolved" },
  {  19, "errorPermanentMessageNotFound" },
  {  20, "errorPermanentContentNotAccepted" },
  {  21, "errorPermanentReplyChargingLimitationsNotMet" },
  {  22, "errorPermanentReplyChargingRequestNotAccepted" },
  {  23, "errorPermanentReplyChargingForwardingDenied" },
  {  24, "errorPermanentReplyChargingNotSupported" },
  {  25, "errorPermanentAddressHidingNotSupported" },
  {  26, "errorPermanentLackOfPrepaid" },
  { 0, NULL }
};


static int
dissect_lix2_MMSDeleteResponseStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_deleteResponseText_sequence_of[1] = {
  { &hf_lix2_deleteResponseText_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_deleteResponseText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_deleteResponseText_sequence_of, hf_index, ett_lix2_T_deleteResponseText);

  return offset;
}


static const ber_sequence_t MMSDeleteFromRelay_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_contentLocationReq_01, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_T_contentLocationReq },
  { &hf_lix2_contentLocationConf_01, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_T_contentLocationConf },
  { &hf_lix2_deleteResponseStatus, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeleteResponseStatus },
  { &hf_lix2_deleteResponseText, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_T_deleteResponseText },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSDeleteFromRelay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSDeleteFromRelay_sequence, hf_index, ett_lix2_MMSDeleteFromRelay);

  return offset;
}


static const ber_sequence_t MMSDeliveryReport_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_messageID      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_mMSDateTime    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_responseStatus , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSResponseStatus },
  { &hf_lix2_responseStatusText, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_applicID       , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSDeliveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSDeliveryReport_sequence, hf_index, ett_lix2_MMSDeliveryReport);

  return offset;
}


static const value_string lix2_MMStatusExtension_vals[] = {
  {   0, "rejectionByMMSRecipient" },
  {   1, "rejectionByOtherRS" },
  { 0, NULL }
};


static int
dissect_lix2_MMStatusExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_MMStatusText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t MMSDeliveryReportNonLocalTarget_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_transactionID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_messageID      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_mMSDateTime    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_forwardToOriginator, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_status         , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_MMStatus },
  { &hf_lix2_statusExtension, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_MMStatusExtension },
  { &hf_lix2_statusText     , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_MMStatusText },
  { &hf_lix2_applicID       , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSDeliveryReportNonLocalTarget(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSDeliveryReportNonLocalTarget_sequence, hf_index, ett_lix2_MMSDeliveryReportNonLocalTarget);

  return offset;
}


static const value_string lix2_MMSReadStatus_vals[] = {
  {   1, "read" },
  {   2, "deletedWithoutBeingRead" },
  { 0, NULL }
};


static int
dissect_lix2_MMSReadStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSReadReport_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_messageID      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_originatingMMSParty_01, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_mMSDateTime    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_readStatus     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadStatus },
  { &hf_lix2_applicID       , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSReadReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSReadReport_sequence, hf_index, ett_lix2_MMSReadReport);

  return offset;
}



static int
dissect_lix2_MMSReadStatusText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t MMSReadReportNonLocalTarget_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_transactionID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_originatingMMSParty_01, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_messageID      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_mMSDateTime    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_readStatus     , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadStatus },
  { &hf_lix2_readStatusText , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadStatusText },
  { &hf_lix2_applicID       , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_replyApplicID  , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_auxApplicInfo  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSReadReportNonLocalTarget(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSReadReportNonLocalTarget_sequence, hf_index, ett_lix2_MMSReadReportNonLocalTarget);

  return offset;
}


static const ber_sequence_t MMSCancel_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_cancelID       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSCancel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSCancel_sequence, hf_index, ett_lix2_MMSCancel);

  return offset;
}


static const ber_sequence_t MMSMBoxStore_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_contentLocationReq, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_state          , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMState },
  { &hf_lix2_flags          , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMFlags },
  { &hf_lix2_contentLocationConf, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_storeStatus    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_MMSStoreStatus },
  { &hf_lix2_storeStatusText, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSMBoxStore(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSMBoxStore_sequence, hf_index, ett_lix2_MMSMBoxStore);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MMFlags_sequence_of[1] = {
  { &hf_lix2_flags_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_MMFlags },
};

static int
dissect_lix2_SEQUENCE_OF_MMFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MMFlags_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_MMFlags);

  return offset;
}


static const ber_sequence_t MMBoxDescription_sequence[] = {
  { &hf_lix2_contentLocation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_messageID      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_state          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMState },
  { &hf_lix2_flags_01       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMFlags },
  { &hf_lix2_dateTime       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_originatingMMSParty, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSParty },
  { &hf_lix2_terminatingMMSParty, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_cCRecipients   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_bCCRecipients  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMSParty },
  { &hf_lix2_messageClass   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSMessageClass },
  { &hf_lix2_subject        , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSSubject },
  { &hf_lix2_priority       , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPriority },
  { &hf_lix2_deliveryTime   , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_readReport     , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_messageSize    , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_replyCharging  , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSReplyCharging },
  { &hf_lix2_previouslySentBy, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSPreviouslySentBy },
  { &hf_lix2_previouslySentByDateTime, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_contentType_01 , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMBoxDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMBoxDescription_sequence, hf_index, ett_lix2_MMBoxDescription);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MMBoxDescription_sequence_of[1] = {
  { &hf_lix2_mMessages_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_MMBoxDescription },
};

static int
dissect_lix2_SEQUENCE_OF_MMBoxDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MMBoxDescription_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_MMBoxDescription);

  return offset;
}


static const ber_sequence_t MMSMBoxUpload_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_state          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMState },
  { &hf_lix2_flags          , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMFlags },
  { &hf_lix2_contentType_01 , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_contentLocation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_storeStatus    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_MMSStoreStatus },
  { &hf_lix2_storeStatusText, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_mMessages      , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMBoxDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSMBoxUpload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSMBoxUpload_sequence, hf_index, ett_lix2_MMSMBoxUpload);

  return offset;
}


static const ber_sequence_t T_contentLocationReq_01_sequence_of[1] = {
  { &hf_lix2_contentLocationReq_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_contentLocationReq_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_contentLocationReq_01_sequence_of, hf_index, ett_lix2_T_contentLocationReq_01);

  return offset;
}


static const ber_sequence_t T_contentLocationConf_01_sequence_of[1] = {
  { &hf_lix2_contentLocationConf_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_contentLocationConf_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_contentLocationConf_01_sequence_of, hf_index, ett_lix2_T_contentLocationConf_01);

  return offset;
}


static const ber_sequence_t MMSMBoxDelete_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_direction_01   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDirection },
  { &hf_lix2_contentLocationReq_02, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_T_contentLocationReq_01 },
  { &hf_lix2_contentLocationConf_02, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_T_contentLocationConf_01 },
  { &hf_lix2_responseStatus_01, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeleteResponseStatus },
  { &hf_lix2_responseStatusText, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSMBoxDelete(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSMBoxDelete_sequence, hf_index, ett_lix2_MMSMBoxDelete);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_MMState_sequence_of[1] = {
  { &hf_lix2_state_item     , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_lix2_MMState },
};

static int
dissect_lix2_SEQUENCE_OF_MMState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_MMState_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_MMState);

  return offset;
}


static const ber_sequence_t T_attributes_sequence_of[1] = {
  { &hf_lix2_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_attributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_attributes_sequence_of, hf_index, ett_lix2_T_attributes);

  return offset;
}


static const value_string lix2_MMSQuotaUnit_vals[] = {
  {   1, "numMessages" },
  {   2, "bytes" },
  { 0, NULL }
};


static int
dissect_lix2_MMSQuotaUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSQuota_sequence[] = {
  { &hf_lix2_quota          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_quotaUnit      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSQuotaUnit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSQuota(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSQuota_sequence, hf_index, ett_lix2_MMSQuota);

  return offset;
}


static const ber_sequence_t MMSMBoxViewRequest_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_contentLocation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_state_01       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMState },
  { &hf_lix2_flags_01       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMFlags },
  { &hf_lix2_start          , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_limit          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_attributes     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_T_attributes },
  { &hf_lix2_totals         , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_quotas         , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MMSQuota },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSMBoxViewRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSMBoxViewRequest_sequence, hf_index, ett_lix2_MMSMBoxViewRequest);

  return offset;
}


static const ber_sequence_t T_attributes_01_sequence_of[1] = {
  { &hf_lix2_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_lix2_UTF8String },
};

static int
dissect_lix2_T_attributes_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_attributes_01_sequence_of, hf_index, ett_lix2_T_attributes_01);

  return offset;
}


static const ber_sequence_t MMSMBoxViewResponse_sequence[] = {
  { &hf_lix2_transactionID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_version        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_contentLocation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_state_01       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMState },
  { &hf_lix2_flags_01       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMFlags },
  { &hf_lix2_start          , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_limit          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_attributes_01  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_T_attributes_01 },
  { &hf_lix2_mMSTotals      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_mMSQuotas      , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_mMessages      , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_MMBoxDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSMBoxViewResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSMBoxViewResponse_sequence, hf_index, ett_lix2_MMSMBoxViewResponse);

  return offset;
}


static const ber_sequence_t PTCChatGroupID_sequence[] = {
  { &hf_lix2_groupIdentity  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCChatGroupID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCChatGroupID_sequence, hf_index, ett_lix2_PTCChatGroupID);

  return offset;
}


static const value_string lix2_PTCIdentifiers_vals[] = {
  {   1, "mCPTTID" },
  {   2, "instanceIdentifierURN" },
  {   3, "pTCChatGroupID" },
  {   4, "iMPU" },
  {   5, "iMPI" },
  { 0, NULL }
};

static const ber_choice_t PTCIdentifiers_choice[] = {
  {   1, &hf_lix2_mCPTTID        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  {   2, &hf_lix2_instanceIdentifierURN, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  {   3, &hf_lix2_pTCChatGroupID , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCChatGroupID },
  {   4, &hf_lix2_iMPU           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_IMPU },
  {   5, &hf_lix2_iMPI           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_IMPI },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCIdentifiers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PTCIdentifiers_choice, hf_index, ett_lix2_PTCIdentifiers,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers_sequence_of[1] = {
  { &hf_lix2_identifiers_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PTCIdentifiers },
};

static int
dissect_lix2_SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers_sequence_of, hf_index, ett_lix2_SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers);

  return offset;
}


static const ber_sequence_t PTCTargetInformation_sequence[] = {
  { &hf_lix2_identifiers    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCTargetInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCTargetInformation_sequence, hf_index, ett_lix2_PTCTargetInformation);

  return offset;
}


static const value_string lix2_PTCRegistrationRequest_vals[] = {
  {   1, "register" },
  {   2, "reRegister" },
  {   3, "deRegister" },
  { 0, NULL }
};


static int
dissect_lix2_PTCRegistrationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCRegistrationOutcome_vals[] = {
  {   1, "success" },
  {   2, "failure" },
  { 0, NULL }
};


static int
dissect_lix2_PTCRegistrationOutcome(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCRegistration_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCServerURI   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCRegistrationRequest, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCRegistrationRequest },
  { &hf_lix2_pTCRegistrationOutcome, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PTCRegistrationOutcome },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCRegistration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCRegistration_sequence, hf_index, ett_lix2_PTCRegistration);

  return offset;
}


static const value_string lix2_PTCSessionType_vals[] = {
  {   1, "ondemand" },
  {   2, "preEstablished" },
  {   3, "adhoc" },
  {   4, "prearranged" },
  {   5, "groupSession" },
  { 0, NULL }
};


static int
dissect_lix2_PTCSessionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCSessionInfo_sequence[] = {
  { &hf_lix2_pTCSessionURI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCSessionType , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCSessionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCSessionInfo_sequence, hf_index, ett_lix2_PTCSessionInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PTCTargetInformation_sequence_of[1] = {
  { &hf_lix2_pTCParticipants_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_PTCTargetInformation },
};

static int
dissect_lix2_SEQUENCE_OF_PTCTargetInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PTCTargetInformation_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_PTCTargetInformation);

  return offset;
}


static const value_string lix2_PTCPresenceType_vals[] = {
  {   1, "pTCClient" },
  {   2, "pTCGroup" },
  { 0, NULL }
};


static int
dissect_lix2_PTCPresenceType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCParticipantPresenceStatus_sequence[] = {
  { &hf_lix2_presenceID     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_presenceType   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPresenceType },
  { &hf_lix2_presenceStatus , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCParticipantPresenceStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCParticipantPresenceStatus_sequence, hf_index, ett_lix2_PTCParticipantPresenceStatus);

  return offset;
}


static const ber_sequence_t MultipleParticipantPresenceStatus_sequence_of[1] = {
  { &hf_lix2_MultipleParticipantPresenceStatus_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_PTCParticipantPresenceStatus },
};

static int
dissect_lix2_MultipleParticipantPresenceStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MultipleParticipantPresenceStatus_sequence_of, hf_index, ett_lix2_MultipleParticipantPresenceStatus);

  return offset;
}


static const ber_sequence_t PTCSessionInitiation_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCServerURI   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCOriginatingID, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCParticipants, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCParticipantPresenceStatus, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MultipleParticipantPresenceStatus },
  { &hf_lix2_location_01    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_pTCBearerCapability, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCHost        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCSessionInitiation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCSessionInitiation_sequence, hf_index, ett_lix2_PTCSessionInitiation);

  return offset;
}


static const ber_sequence_t PTCSessionAbandon_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_location_01    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_pTCAbandonCause, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCSessionAbandon(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCSessionAbandon_sequence, hf_index, ett_lix2_PTCSessionAbandon);

  return offset;
}


static const ber_sequence_t PTCSessionStart_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCServerURI   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCOriginatingID, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCParticipants, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCParticipantPresenceStatus, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MultipleParticipantPresenceStatus },
  { &hf_lix2_location_01    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_pTCHost        , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCBearerCapability, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCSessionStart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCSessionStart_sequence, hf_index, ett_lix2_PTCSessionStart);

  return offset;
}


static const value_string lix2_PTCSessionEndCause_vals[] = {
  {   1, "initiaterLeavesSession" },
  {   2, "definedParticipantLeaves" },
  {   3, "numberOfParticipants" },
  {   4, "sessionTimerExpired" },
  {   5, "pTCSpeechInactive" },
  {   6, "allMediaTypesInactive" },
  { 0, NULL }
};


static int
dissect_lix2_PTCSessionEndCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCSessionEnd_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCServerURI   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCParticipants, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_location_01    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_pTCSessionEndCause, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionEndCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCSessionEnd(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCSessionEnd_sequence, hf_index, ett_lix2_PTCSessionEnd);

  return offset;
}


static const ber_sequence_t PTCStartOfInterception_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_preEstSessionID, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCOriginatingID, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCHost        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCParticipants, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCMediaStreamAvail, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_pTCBearerCapability, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCStartOfInterception(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCStartOfInterception_sequence, hf_index, ett_lix2_PTCStartOfInterception);

  return offset;
}


static const ber_sequence_t RTPSetting_sequence[] = {
  { &hf_lix2_iPAddress      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_portNumber     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_RTPSetting(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RTPSetting_sequence, hf_index, ett_lix2_RTPSetting);

  return offset;
}


static const value_string lix2_PTCPreEstStatus_vals[] = {
  {   1, "established" },
  {   2, "modified" },
  {   3, "released" },
  { 0, NULL }
};


static int
dissect_lix2_PTCPreEstStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCFailureCode_vals[] = {
  {   1, "sessionCannotBeEstablished" },
  {   2, "sessionCannotBeModified" },
  { 0, NULL }
};


static int
dissect_lix2_PTCFailureCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCPreEstablishedSession_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCServerURI   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_rTPSetting     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_RTPSetting },
  { &hf_lix2_pTCMediaCapability, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_pTCPreEstSessionID, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCPreEstStatus, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPreEstStatus },
  { &hf_lix2_pTCMediaStreamAvail, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_location_01    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_pTCFailureCode , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCFailureCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCPreEstablishedSession(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCPreEstablishedSession_sequence, hf_index, ett_lix2_PTCPreEstablishedSession);

  return offset;
}


static const ber_sequence_t PTCInstantPersonalAlert_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCIPAPartyID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCIPADirection, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCInstantPersonalAlert(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCInstantPersonalAlert_sequence, hf_index, ett_lix2_PTCInstantPersonalAlert);

  return offset;
}


static const ber_sequence_t PTCPartyJoin_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCParticipants, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCParticipantPresenceStatus, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MultipleParticipantPresenceStatus },
  { &hf_lix2_pTCMediaStreamAvail, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_pTCBearerCapability, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCPartyJoin(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCPartyJoin_sequence, hf_index, ett_lix2_PTCPartyJoin);

  return offset;
}


static const ber_sequence_t PTCPartyDrop_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCPartyDrop_01, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCParticipantPresenceStatus_01, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCParticipantPresenceStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCPartyDrop(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCPartyDrop_sequence, hf_index, ett_lix2_PTCPartyDrop);

  return offset;
}


static const ber_sequence_t PTCPartyHold_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCParticipants, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCHoldID      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCHoldRetrieveInd, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCPartyHold(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCPartyHold_sequence, hf_index, ett_lix2_PTCPartyHold);

  return offset;
}


static const ber_sequence_t PTCMediaModification_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCSessionInfo , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCMediaStreamAvail, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_pTCBearerCapability, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCMediaModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCMediaModification_sequence, hf_index, ett_lix2_PTCMediaModification);

  return offset;
}


static const value_string lix2_PTCGroupAuthRule_vals[] = {
  {   1, "allowInitiatingPTCSession" },
  {   2, "blockInitiatingPTCSession" },
  {   3, "allowJoiningPTCSession" },
  {   4, "blockJoiningPTCSession" },
  {   5, "allowAddParticipants" },
  {   6, "blockAddParticipants" },
  {   7, "allowSubscriptionPTCSessionState" },
  {   8, "blockSubscriptionPTCSessionState" },
  {   9, "allowAnonymity" },
  {  10, "forbidAnonymity" },
  { 0, NULL }
};


static int
dissect_lix2_PTCGroupAuthRule(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCGroupAdvertisement_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCIDList      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCTargetInformation },
  { &hf_lix2_pTCGroupAuthRule, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCGroupAuthRule },
  { &hf_lix2_pTCGroupAdSender, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCGroupNickname, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCGroupAdvertisement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCGroupAdvertisement_sequence, hf_index, ett_lix2_PTCGroupAdvertisement);

  return offset;
}


static const value_string lix2_PTCFloorActivity_vals[] = {
  {   1, "tBCPRequest" },
  {   2, "tBCPGranted" },
  {   3, "tBCPDeny" },
  {   4, "tBCPIdle" },
  {   5, "tBCPTaken" },
  {   6, "tBCPRevoke" },
  {   7, "tBCPQueued" },
  {   8, "tBCPRelease" },
  { 0, NULL }
};


static int
dissect_lix2_PTCFloorActivity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PTCFloorActivity_sequence_of[1] = {
  { &hf_lix2_pTCFloorActivity_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_lix2_PTCFloorActivity },
};

static int
dissect_lix2_SEQUENCE_OF_PTCFloorActivity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PTCFloorActivity_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_PTCFloorActivity);

  return offset;
}


static const value_string lix2_PTCTBPriorityLevel_vals[] = {
  {   1, "preEmptive" },
  {   2, "highPriority" },
  {   3, "normalPriority" },
  {   4, "listenOnly" },
  { 0, NULL }
};


static int
dissect_lix2_PTCTBPriorityLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCTBReasonCode_vals[] = {
  {   1, "noQueuingAllowed" },
  {   2, "oneParticipantSession" },
  {   3, "listenOnly" },
  {   4, "exceededMaxDuration" },
  {   5, "tBPrevented" },
  { 0, NULL }
};


static int
dissect_lix2_PTCTBReasonCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCFloorControl_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCSessioninfo , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInfo },
  { &hf_lix2_pTCFloorActivity, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCFloorActivity },
  { &hf_lix2_pTCFloorSpeakerID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCMaxTBTime   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_pTCQueuedFloorControl, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BOOLEAN },
  { &hf_lix2_pTCQueuedPosition, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_pTCTalkBurstPriority, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTBPriorityLevel },
  { &hf_lix2_pTCTalkBurstReason, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTBReasonCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCFloorControl(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCFloorControl_sequence, hf_index, ett_lix2_PTCFloorControl);

  return offset;
}


static const ber_sequence_t PTCTargetPresence_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCTargetPresenceStatus, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PTCParticipantPresenceStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCTargetPresence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCTargetPresence_sequence, hf_index, ett_lix2_PTCTargetPresence);

  return offset;
}


static const ber_sequence_t PTCParticipantPresence_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCParticipantPresenceStatus_01, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PTCParticipantPresenceStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCParticipantPresence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCParticipantPresence_sequence, hf_index, ett_lix2_PTCParticipantPresence);

  return offset;
}


static const value_string lix2_PTCListManagementType_vals[] = {
  {   1, "contactListManagementAttempt" },
  {   2, "groupListManagementAttempt" },
  {   3, "contactListManagementResult" },
  {   4, "groupListManagementResult" },
  {   5, "requestUnsuccessful" },
  { 0, NULL }
};


static int
dissect_lix2_PTCListManagementType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCListManagementAction_vals[] = {
  {   1, "create" },
  {   2, "modify" },
  {   3, "retrieve" },
  {   4, "delete" },
  {   5, "notify" },
  { 0, NULL }
};


static int
dissect_lix2_PTCListManagementAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCListManagementFailure_vals[] = {
  {   1, "requestUnsuccessful" },
  {   2, "requestUnknown" },
  { 0, NULL }
};


static int
dissect_lix2_PTCListManagementFailure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCIDList_sequence[] = {
  { &hf_lix2_pTCPartyID     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCChatGroupID , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_PTCChatGroupID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCIDList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCIDList_sequence, hf_index, ett_lix2_PTCIDList);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PTCIDList_sequence_of[1] = {
  { &hf_lix2_pTCIDList_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_PTCIDList },
};

static int
dissect_lix2_SEQUENCE_OF_PTCIDList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PTCIDList_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_PTCIDList);

  return offset;
}


static const ber_sequence_t PTCListManagement_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCListManagementType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCListManagementType },
  { &hf_lix2_pTCListManagementAction, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCListManagementAction },
  { &hf_lix2_pTCListManagementFailure, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCListManagementFailure },
  { &hf_lix2_pTCContactID   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCIDList_01   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_PTCIDList },
  { &hf_lix2_pTCHost        , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCListManagement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCListManagement_sequence, hf_index, ett_lix2_PTCListManagement);

  return offset;
}


static const value_string lix2_PTCAccessPolicyType_vals[] = {
  {   1, "pTCUserAccessPolicyAttempt" },
  {   2, "groupAuthorizationRulesAttempt" },
  {   3, "pTCUserAccessPolicyQuery" },
  {   4, "groupAuthorizationRulesQuery" },
  {   5, "pTCUserAccessPolicyResult" },
  {   6, "groupAuthorizationRulesResult" },
  {   7, "requestUnsuccessful" },
  { 0, NULL }
};


static int
dissect_lix2_PTCAccessPolicyType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCUserAccessPolicy_vals[] = {
  {   1, "allowIncomingPTCSessionRequest" },
  {   2, "blockIncomingPTCSessionRequest" },
  {   3, "allowAutoAnswerMode" },
  {   4, "allowOverrideManualAnswerMode" },
  { 0, NULL }
};


static int
dissect_lix2_PTCUserAccessPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_PTCAccessPolicyFailure_vals[] = {
  {   1, "requestUnsuccessful" },
  {   2, "requestUnknown" },
  { 0, NULL }
};


static int
dissect_lix2_PTCAccessPolicyFailure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PTCAccessPolicy_sequence[] = {
  { &hf_lix2_pTCTargetInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCDirection   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_Direction },
  { &hf_lix2_pTCAccessPolicyType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCAccessPolicyType },
  { &hf_lix2_pTCUserAccessPolicy, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCUserAccessPolicy },
  { &hf_lix2_pTCGroupAuthRule, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCGroupAuthRule },
  { &hf_lix2_pTCContactID   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetInformation },
  { &hf_lix2_pTCAccessPolicyFailure, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PTCAccessPolicyFailure },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_PTCAccessPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCAccessPolicy_sequence, hf_index, ett_lix2_PTCAccessPolicy);

  return offset;
}


static const value_string lix2_UDMSubscriberRecordChangeMethod_vals[] = {
  {   1, "pEIChange" },
  {   2, "sUPIChange" },
  {   3, "gPSIChange" },
  {   4, "uEDeprovisioning" },
  {   5, "unknown" },
  {   6, "serviceIDChange" },
  { 0, NULL }
};


static int
dissect_lix2_UDMSubscriberRecordChangeMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t UDMSubscriberRecordChangeMessage_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_oldPEI         , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_oldSUPI        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_oldGPSI        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_oldserviceID   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ServiceID },
  { &hf_lix2_subscriberRecordChangeMethod, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_UDMSubscriberRecordChangeMethod },
  { &hf_lix2_serviceID      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ServiceID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UDMSubscriberRecordChangeMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UDMSubscriberRecordChangeMessage_sequence, hf_index, ett_lix2_UDMSubscriberRecordChangeMessage);

  return offset;
}


static const value_string lix2_UDMCancelLocationMethod_vals[] = {
  {   1, "aMF3GPPAccessDeregistration" },
  {   2, "aMFNon3GPPAccessDeregistration" },
  {   3, "uDMDeregistration" },
  {   4, "unknown" },
  { 0, NULL }
};


static int
dissect_lix2_UDMCancelLocationMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t UDMCancelLocationMessage_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUAMI          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUAMI },
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_cancelLocationMethod, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_UDMCancelLocationMethod },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UDMCancelLocationMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UDMCancelLocationMessage_sequence, hf_index, ett_lix2_UDMCancelLocationMessage);

  return offset;
}


static const ber_sequence_t SMSReport_sequence[] = {
  { &hf_lix2_location_01    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_sMSTPDUData    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SMSTPDUData },
  { &hf_lix2_messageType    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SMSMessageType },
  { &hf_lix2_rPMessageReference, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SMSRPMessageReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMSReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMSReport_sequence, hf_index, ett_lix2_SMSReport);

  return offset;
}


static const value_string lix2_EstablishmentStatus_vals[] = {
  {   0, "established" },
  {   1, "released" },
  { 0, NULL }
};


static int
dissect_lix2_EstablishmentStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AccessInfo_sequence[] = {
  { &hf_lix2_accessType     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_rATType        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_gTPTunnelID    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_FTEID },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_establishmentStatus, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_EstablishmentStatus },
  { &hf_lix2_aNTypeToReactivate, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AccessInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessInfo_sequence, hf_index, ett_lix2_AccessInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AccessInfo_sequence_of[1] = {
  { &hf_lix2_accessInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_AccessInfo },
};

static int
dissect_lix2_SEQUENCE_OF_AccessInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AccessInfo_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_AccessInfo);

  return offset;
}


static const ber_sequence_t SMFServingNetwork_sequence[] = {
  { &hf_lix2_pLMNID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_PLMNID },
  { &hf_lix2_nID            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFServingNetwork(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFServingNetwork_sequence, hf_index, ett_lix2_SMFServingNetwork);

  return offset;
}



static int
dissect_lix2_SMFMAUpgradeIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_lix2_SMFEPSPDNCnxInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_SMFMAAcceptedIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_lix2_ATSSSContainer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SMFMAPDUSessionEstablishment_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_pDUSessionType , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionType },
  { &hf_lix2_accessInfo     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_AccessInfo },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_uEEndpoint     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_dNN            , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_aMFID          , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_hSMFURI        , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HSMFURI },
  { &hf_lix2_requestType    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_sMPDUDNRequest , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMPDUDNRequest },
  { &hf_lix2_servingNetwork , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_lix2_SMFServingNetwork },
  { &hf_lix2_oldPDUSessionID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_mAUpgradeIndication, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAUpgradeIndication },
  { &hf_lix2_ePSPDNCnxInfo  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFEPSPDNCnxInfo },
  { &hf_lix2_mAAcceptedIndication, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAAcceptedIndication },
  { &hf_lix2_aTSSSContainer , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ATSSSContainer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFMAPDUSessionEstablishment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFMAPDUSessionEstablishment_sequence, hf_index, ett_lix2_SMFMAPDUSessionEstablishment);

  return offset;
}


static const ber_sequence_t SMFMAPDUSessionModification_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_accessInfo     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_AccessInfo },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_requestType    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_servingNetwork , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_SMFServingNetwork },
  { &hf_lix2_oldPDUSessionID, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_mAUpgradeIndication, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAUpgradeIndication },
  { &hf_lix2_ePSPDNCnxInfo  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFEPSPDNCnxInfo },
  { &hf_lix2_mAAcceptedIndication, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAAcceptedIndication },
  { &hf_lix2_aTSSSContainer , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ATSSSContainer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFMAPDUSessionModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFMAPDUSessionModification_sequence, hf_index, ett_lix2_SMFMAPDUSessionModification);

  return offset;
}


static const ber_sequence_t SMFMAPDUSessionRelease_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_timeOfFirstPacket, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_timeOfLastPacket, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_uplinkVolume   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_downlinkVolume , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_location_01    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_cause_01       , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFErrorCodes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFMAPDUSessionRelease(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFMAPDUSessionRelease_sequence, hf_index, ett_lix2_SMFMAPDUSessionRelease);

  return offset;
}


static const ber_sequence_t SMFStartOfInterceptionWithEstablishedMAPDUSession_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_pDUSessionType , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionType },
  { &hf_lix2_accessInfo     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_AccessInfo },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_uEEndpoint     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_dNN            , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_aMFID          , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_hSMFURI        , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HSMFURI },
  { &hf_lix2_requestType    , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_sMPDUDNRequest , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMPDUDNRequest },
  { &hf_lix2_servingNetwork , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_lix2_SMFServingNetwork },
  { &hf_lix2_oldPDUSessionID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_mAUpgradeIndication, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAUpgradeIndication },
  { &hf_lix2_ePSPDNCnxInfo  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMFEPSPDNCnxInfo },
  { &hf_lix2_mAAcceptedIndication, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAAcceptedIndication },
  { &hf_lix2_aTSSSContainer , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ATSSSContainer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFStartOfInterceptionWithEstablishedMAPDUSession(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFStartOfInterceptionWithEstablishedMAPDUSession_sequence, hf_index, ett_lix2_SMFStartOfInterceptionWithEstablishedMAPDUSession);

  return offset;
}


static const ber_sequence_t SMFMAUnsuccessfulProcedure_sequence[] = {
  { &hf_lix2_failedProcedureType_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SMFFailedProcedureType },
  { &hf_lix2_failureCause_03, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMCause },
  { &hf_lix2_requestedSlice , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NSSAI },
  { &hf_lix2_initiator      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Initiator },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_accessInfo     , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_AccessInfo },
  { &hf_lix2_uEEndpoint     , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_dNN            , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_aMFID          , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AMFID },
  { &hf_lix2_hSMFURI        , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_HSMFURI },
  { &hf_lix2_requestType    , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_sMPDUDNRequest , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SMPDUDNRequest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFMAUnsuccessfulProcedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFMAUnsuccessfulProcedure_sequence, hf_index, ett_lix2_SMFMAUnsuccessfulProcedure);

  return offset;
}


static const ber_sequence_t AMFIdentifierAssocation_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUCI           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUCI },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_gUTI           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGGUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_fiveGSTAIList  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAIList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_AMFIdentifierAssocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMFIdentifierAssocation_sequence, hf_index, ett_lix2_AMFIdentifierAssocation);

  return offset;
}


static const ber_sequence_t MMEIdentifierAssocation_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_gUTI_01        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_tAIList        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAIList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEIdentifierAssocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMEIdentifierAssocation_sequence, hf_index, ett_lix2_MMEIdentifierAssocation);

  return offset;
}


static const value_string lix2_RequestIndication_vals[] = {
  {   0, "uEREQPDUSESMOD" },
  {   1, "uEREQPDUSESREL" },
  {   2, "pDUSESMOB" },
  {   3, "nWREQPDUSESAUTH" },
  {   4, "nWREQPDUSESMOD" },
  {   5, "nWREQPDUSESREL" },
  {   6, "eBIASSIGNMENTREQ" },
  {   7, "rELDUETO5GANREQUEST" },
  { 0, NULL }
};


static int
dissect_lix2_RequestIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SMFPDUtoMAPDUSessionModification_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_sUPIUnauthenticated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SUPIUnauthenticatedIndication },
  { &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_PEI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_non3GPPAccessEndpoint, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UEEndpointAddress },
  { &hf_lix2_location_01    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_requestType    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_FiveGSMRequestType },
  { &hf_lix2_accessType     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AccessType },
  { &hf_lix2_rATType        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RATType },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_requestIndication, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_lix2_RequestIndication },
  { &hf_lix2_aTSSSContainer , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_lix2_ATSSSContainer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SMFPDUtoMAPDUSessionModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMFPDUtoMAPDUSessionModification_sequence, hf_index, ett_lix2_SMFPDUtoMAPDUSessionModification);

  return offset;
}



static int
dissect_lix2_NEFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_RDSSupport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_lix2_SMFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_AFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t NEFPDUSessionEstablishment_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_nEFID          , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_NEFID },
  { &hf_lix2_dNN            , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_rDSSupport     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_RDSSupport },
  { &hf_lix2_sMFID          , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_SMFID },
  { &hf_lix2_aFID           , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFPDUSessionEstablishment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFPDUSessionEstablishment_sequence, hf_index, ett_lix2_NEFPDUSessionEstablishment);

  return offset;
}



static int
dissect_lix2_RDSPortNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_ApplicationID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_RDSAction_vals[] = {
  {   1, "reservePort" },
  {   2, "releasePort" },
  { 0, NULL }
};


static int
dissect_lix2_RDSAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_SerializationFormat_vals[] = {
  {   1, "xml" },
  {   2, "json" },
  {   3, "cbor" },
  { 0, NULL }
};


static int
dissect_lix2_SerializationFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NEFPDUSessionModification_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_initiator      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Initiator },
  { &hf_lix2_rDSSourcePortNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSPortNumber },
  { &hf_lix2_rDSDestinationPortNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSPortNumber },
  { &hf_lix2_applicationID  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ApplicationID },
  { &hf_lix2_aFID           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { &hf_lix2_rDSAction      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSAction },
  { &hf_lix2_serializationFormat, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SerializationFormat },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFPDUSessionModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFPDUSessionModification_sequence, hf_index, ett_lix2_NEFPDUSessionModification);

  return offset;
}


static const value_string lix2_NEFReleaseCause_vals[] = {
  {   1, "sMFRelease" },
  {   2, "dNRelease" },
  {   3, "uDMRelease" },
  {   4, "cHFRelease" },
  {   5, "localConfigurationPolicy" },
  {   6, "unknownCause" },
  { 0, NULL }
};


static int
dissect_lix2_NEFReleaseCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NEFPDUSessionRelease_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_timeOfFirstPacket, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_timeOfLastPacket, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_uplinkVolume   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_downlinkVolume , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_releaseCause   , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_NEFReleaseCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFPDUSessionRelease(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFPDUSessionRelease_sequence, hf_index, ett_lix2_NEFPDUSessionRelease);

  return offset;
}


static const value_string lix2_NEFFailureCause_vals[] = {
  {   1, "userUnknown" },
  {   2, "niddConfigurationNotAvailable" },
  {   3, "contextNotFound" },
  {   4, "portNotFree" },
  {   5, "portNotAssociatedWithSpecifiedApplication" },
  { 0, NULL }
};


static int
dissect_lix2_NEFFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NEFUnsuccessfulProcedure_sequence[] = {
  { &hf_lix2_failureCause   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_NEFFailureCause },
  { &hf_lix2_sUPI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_dNN            , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_rDSDestinationPortNumber, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_RDSPortNumber },
  { &hf_lix2_applicationID  , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_ApplicationID },
  { &hf_lix2_aFID           , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFUnsuccessfulProcedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFUnsuccessfulProcedure_sequence, hf_index, ett_lix2_NEFUnsuccessfulProcedure);

  return offset;
}


static const ber_sequence_t NEFStartOfInterceptionWithEstablishedPDUSession_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_pDUSessionID   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PDUSessionID },
  { &hf_lix2_dNN            , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_DNN },
  { &hf_lix2_sNSSAI         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_SNSSAI },
  { &hf_lix2_nEFID          , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_NEFID },
  { &hf_lix2_rDSSupport     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_RDSSupport },
  { &hf_lix2_sMFID          , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_SMFID },
  { &hf_lix2_aFID           , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFStartOfInterceptionWithEstablishedPDUSession(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFStartOfInterceptionWithEstablishedPDUSession_sequence, hf_index, ett_lix2_NEFStartOfInterceptionWithEstablishedPDUSession);

  return offset;
}



static int
dissect_lix2_TriggerID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_TriggerPayload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_PriorityDT_vals[] = {
  {   1, "noPriority" },
  {   2, "priority" },
  { 0, NULL }
};


static int
dissect_lix2_PriorityDT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NEFDeviceTrigger_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { &hf_lix2_aFID           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { &hf_lix2_triggerPayload , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TriggerPayload },
  { &hf_lix2_validityPeriod , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_priorityDT     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PriorityDT },
  { &hf_lix2_sourcePortId   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationPortId, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFDeviceTrigger(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFDeviceTrigger_sequence, hf_index, ett_lix2_NEFDeviceTrigger);

  return offset;
}


static const ber_sequence_t NEFDeviceTriggerReplace_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { &hf_lix2_aFID           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { &hf_lix2_triggerPayload , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TriggerPayload },
  { &hf_lix2_validityPeriod , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_priorityDT     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PriorityDT },
  { &hf_lix2_sourcePortId   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationPortId, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFDeviceTriggerReplace(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFDeviceTriggerReplace_sequence, hf_index, ett_lix2_NEFDeviceTriggerReplace);

  return offset;
}


static const ber_sequence_t NEFDeviceTriggerCancellation_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFDeviceTriggerCancellation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFDeviceTriggerCancellation_sequence, hf_index, ett_lix2_NEFDeviceTriggerCancellation);

  return offset;
}


static const value_string lix2_DeviceTriggerDeliveryResult_vals[] = {
  {   1, "success" },
  {   2, "unknown" },
  {   3, "failure" },
  {   4, "triggered" },
  {   5, "expired" },
  {   6, "unconfirmed" },
  {   7, "replaced" },
  {   8, "terminate" },
  { 0, NULL }
};


static int
dissect_lix2_DeviceTriggerDeliveryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NEFDeviceTriggerReportNotify_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { &hf_lix2_deviceTriggerDeliveryResult, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_DeviceTriggerDeliveryResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFDeviceTriggerReportNotify(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFDeviceTriggerReportNotify_sequence, hf_index, ett_lix2_NEFDeviceTriggerReportNotify);

  return offset;
}


static const ber_sequence_t NEFMSISDNLessMOSMS_sequence[] = {
  { &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SUPI },
  { &hf_lix2_gPSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_terminatingSMSParty, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { &hf_lix2_sMS            , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SMSTPDUData },
  { &hf_lix2_sourcePort     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationPort, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFMSISDNLessMOSMS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFMSISDNLessMOSMS_sequence, hf_index, ett_lix2_NEFMSISDNLessMOSMS);

  return offset;
}


static const value_string lix2_Day_vals[] = {
  {   1, "monday" },
  {   2, "tuesday" },
  {   3, "wednesday" },
  {   4, "thursday" },
  {   5, "friday" },
  {   6, "saturday" },
  {   7, "sunday" },
  { 0, NULL }
};


static int
dissect_lix2_Day(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Daytime_sequence[] = {
  { &hf_lix2_daysOfWeek     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Day },
  { &hf_lix2_timeOfDayStart , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_timeOfDayEnd   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_Daytime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Daytime_sequence, hf_index, ett_lix2_Daytime);

  return offset;
}


static const ber_sequence_t UMTLocationArea5G_sequence[] = {
  { &hf_lix2_timeOfDay      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_Daytime },
  { &hf_lix2_durationSec    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_location       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_NRLocation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UMTLocationArea5G(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UMTLocationArea5G_sequence, hf_index, ett_lix2_UMTLocationArea5G);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_UMTLocationArea5G_sequence_of[1] = {
  { &hf_lix2_expectedUEMovingTrajectory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_UMTLocationArea5G },
};

static int
dissect_lix2_SEQUENCE_OF_UMTLocationArea5G(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_UMTLocationArea5G_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_UMTLocationArea5G);

  return offset;
}


static const value_string lix2_StationaryIndication_vals[] = {
  {   1, "stationary" },
  {   2, "mobile" },
  { 0, NULL }
};


static int
dissect_lix2_StationaryIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Daytime_sequence_of[1] = {
  { &hf_lix2_days_item      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_Daytime },
};

static int
dissect_lix2_SEQUENCE_OF_Daytime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Daytime_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_Daytime);

  return offset;
}


static const ber_sequence_t ScheduledCommunicationTime_sequence[] = {
  { &hf_lix2_days           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_Daytime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ScheduledCommunicationTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScheduledCommunicationTime_sequence, hf_index, ett_lix2_ScheduledCommunicationTime);

  return offset;
}


static const value_string lix2_ScheduledCommunicationType_vals[] = {
  {   1, "downlinkOnly" },
  {   2, "uplinkOnly" },
  {   3, "bidirectional" },
  { 0, NULL }
};


static int
dissect_lix2_ScheduledCommunicationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_BatteryIndication_vals[] = {
  {   1, "batteryRecharge" },
  {   2, "batteryReplace" },
  {   3, "batteryNoRecharge" },
  {   4, "batteryNoReplace" },
  {   5, "noBattery" },
  { 0, NULL }
};


static int
dissect_lix2_BatteryIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_TrafficProfile_vals[] = {
  {   1, "singleTransUL" },
  {   2, "singleTransDL" },
  {   3, "dualTransULFirst" },
  {   4, "dualTransDLFirst" },
  {   5, "multiTrans" },
  { 0, NULL }
};


static int
dissect_lix2_TrafficProfile(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NEFExpectedUEBehaviourUpdate_sequence[] = {
  { &hf_lix2_gPSI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_GPSI },
  { &hf_lix2_expectedUEMovingTrajectory, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UMTLocationArea5G },
  { &hf_lix2_stationaryIndication, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_StationaryIndication },
  { &hf_lix2_communicationDurationTime, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_periodicTime   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_scheduledCommunicationTime, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ScheduledCommunicationTime },
  { &hf_lix2_scheduledCommunicationType, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ScheduledCommunicationType },
  { &hf_lix2_batteryIndication, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BatteryIndication },
  { &hf_lix2_trafficProfile , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TrafficProfile },
  { &hf_lix2_expectedTimeAndDayOfWeekInTrajectory, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UMTLocationArea5G },
  { &hf_lix2_aFID           , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_AFID },
  { &hf_lix2_validityTime   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_NEFExpectedUEBehaviourUpdate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NEFExpectedUEBehaviourUpdate_sequence, hf_index, ett_lix2_NEFExpectedUEBehaviourUpdate);

  return offset;
}



static int
dissect_lix2_EPSBearerID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_lix2_SCEFID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_APN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_lix2_SCSASID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SCEFPDNConnectionEstablishment_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_ePSBearerID    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_EPSBearerID },
  { &hf_lix2_sCEFID         , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFID },
  { &hf_lix2_aPN            , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_APN },
  { &hf_lix2_rDSSupport     , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_RDSSupport },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFPDNConnectionEstablishment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFPDNConnectionEstablishment_sequence, hf_index, ett_lix2_SCEFPDNConnectionEstablishment);

  return offset;
}


static const ber_sequence_t SCEFPDNConnectionUpdate_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_initiator      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_Initiator },
  { &hf_lix2_rDSSourcePortNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSPortNumber },
  { &hf_lix2_rDSDestinationPortNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSPortNumber },
  { &hf_lix2_applicationID  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ApplicationID },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { &hf_lix2_rDSAction      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSAction },
  { &hf_lix2_serializationFormat, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SerializationFormat },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFPDNConnectionUpdate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFPDNConnectionUpdate_sequence, hf_index, ett_lix2_SCEFPDNConnectionUpdate);

  return offset;
}


static const value_string lix2_SCEFReleaseCause_vals[] = {
  {   1, "mMERelease" },
  {   2, "dNRelease" },
  {   3, "hSSRelease" },
  {   4, "localConfigurationPolicy" },
  {   5, "unknownCause" },
  { 0, NULL }
};


static int
dissect_lix2_SCEFReleaseCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SCEFPDNConnectionRelease_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_ePSBearerID    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_EPSBearerID },
  { &hf_lix2_timeOfFirstPacket, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_timeOfLastPacket, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_uplinkVolume   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_downlinkVolume , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_releaseCause_01, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFReleaseCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFPDNConnectionRelease(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFPDNConnectionRelease_sequence, hf_index, ett_lix2_SCEFPDNConnectionRelease);

  return offset;
}


static const value_string lix2_SCEFFailureCause_vals[] = {
  {   1, "userUnknown" },
  {   2, "niddConfigurationNotAvailable" },
  {   3, "invalidEPSBearer" },
  {   4, "operationNotAllowed" },
  {   5, "portNotFree" },
  {   6, "portNotAssociatedWithSpecifiedApplication" },
  { 0, NULL }
};


static int
dissect_lix2_SCEFFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SCEFUnsuccessfulProcedure_sequence[] = {
  { &hf_lix2_failureCause_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFFailureCause },
  { &hf_lix2_iMSI           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_ePSBearerID    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_EPSBearerID },
  { &hf_lix2_aPN            , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_APN },
  { &hf_lix2_rDSDestinationPortNumber, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_RDSPortNumber },
  { &hf_lix2_applicationID  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ApplicationID },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFUnsuccessfulProcedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFUnsuccessfulProcedure_sequence, hf_index, ett_lix2_SCEFUnsuccessfulProcedure);

  return offset;
}


static const ber_sequence_t SCEFStartOfInterceptionWithEstablishedPDNConnection_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_ePSBearerID    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_EPSBearerID },
  { &hf_lix2_sCEFID         , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFID },
  { &hf_lix2_aPN            , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_APN },
  { &hf_lix2_rDSSupport     , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_RDSSupport },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFStartOfInterceptionWithEstablishedPDNConnection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFStartOfInterceptionWithEstablishedPDNConnection_sequence, hf_index, ett_lix2_SCEFStartOfInterceptionWithEstablishedPDNConnection);

  return offset;
}


static const ber_sequence_t SCEFDeviceTrigger_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { &hf_lix2_triggerPayload , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TriggerPayload },
  { &hf_lix2_validityPeriod , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_priorityDT     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PriorityDT },
  { &hf_lix2_sourcePortId   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationPortId, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFDeviceTrigger(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFDeviceTrigger_sequence, hf_index, ett_lix2_SCEFDeviceTrigger);

  return offset;
}


static const ber_sequence_t SCEFDeviceTriggerReplace_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { &hf_lix2_triggerPayload , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TriggerPayload },
  { &hf_lix2_validityPeriod , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_priorityDT     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PriorityDT },
  { &hf_lix2_sourcePortId   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationPortId, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFDeviceTriggerReplace(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFDeviceTriggerReplace_sequence, hf_index, ett_lix2_SCEFDeviceTriggerReplace);

  return offset;
}


static const ber_sequence_t SCEFDeviceTriggerCancellation_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFDeviceTriggerCancellation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFDeviceTriggerCancellation_sequence, hf_index, ett_lix2_SCEFDeviceTriggerCancellation);

  return offset;
}


static const ber_sequence_t SCEFDeviceTriggerReportNotify_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_triggerId      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_TriggerID },
  { &hf_lix2_deviceTriggerDeliveryResult, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_DeviceTriggerDeliveryResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFDeviceTriggerReportNotify(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFDeviceTriggerReportNotify_sequence, hf_index, ett_lix2_SCEFDeviceTriggerReportNotify);

  return offset;
}


static const ber_sequence_t SCEFMSISDNLessMOSMS_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifie, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_terminatingSMSParty_01, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { &hf_lix2_sMS            , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_SMSTPDUData },
  { &hf_lix2_sourcePort     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_destinationPort, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFMSISDNLessMOSMS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFMSISDNLessMOSMS_sequence, hf_index, ett_lix2_SCEFMSISDNLessMOSMS);

  return offset;
}


static const value_string lix2_PeriodicCommunicationIndicator_vals[] = {
  {   1, "periodic" },
  {   2, "nonPeriodic" },
  { 0, NULL }
};


static int
dissect_lix2_PeriodicCommunicationIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SCEFCommunicationPatternUpdate_sequence[] = {
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_externalIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  { &hf_lix2_periodicCommunicationIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PeriodicCommunicationIndicator },
  { &hf_lix2_communicationDurationTime, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_periodicTime   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_INTEGER },
  { &hf_lix2_scheduledCommunicationTime, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ScheduledCommunicationTime },
  { &hf_lix2_scheduledCommunicationType, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_ScheduledCommunicationType },
  { &hf_lix2_stationaryIndication, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_StationaryIndication },
  { &hf_lix2_batteryIndication, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_BatteryIndication },
  { &hf_lix2_trafficProfile , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TrafficProfile },
  { &hf_lix2_expectedUEMovingTrajectory, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_UMTLocationArea5G },
  { &hf_lix2_sCSASID        , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_lix2_SCSASID },
  { &hf_lix2_validityTime   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_SCEFCommunicationPatternUpdate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SCEFCommunicationPatternUpdate_sequence, hf_index, ett_lix2_SCEFCommunicationPatternUpdate);

  return offset;
}


static const value_string lix2_EPSAttachType_vals[] = {
  {   1, "ePSAttach" },
  {   2, "combinedEPSIMSIAttach" },
  {   3, "ePSRLOSAttach" },
  {   4, "ePSEmergencyAttach" },
  {   5, "reserved" },
  { 0, NULL }
};


static int
dissect_lix2_EPSAttachType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_EPSAttachResult_vals[] = {
  {   1, "ePSOnly" },
  {   2, "combinedEPSIMSI" },
  { 0, NULL }
};


static int
dissect_lix2_EPSAttachResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_EPSSMSServiceStatus_vals[] = {
  {   1, "sMSServicesNotAvailable" },
  {   2, "sMSServicesNotAvailableInThisPLMN" },
  {   3, "networkFailure" },
  {   4, "congestion" },
  { 0, NULL }
};


static int
dissect_lix2_EPSSMSServiceStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMEAttach_sequence[] = {
  { &hf_lix2_attachType     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_EPSAttachType },
  { &hf_lix2_attachResult   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_EPSAttachResult },
  { &hf_lix2_iMSI           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_gUTI_01        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_ePSTAIList     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAIList },
  { &hf_lix2_sMSServiceStatus, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EPSSMSServiceStatus },
  { &hf_lix2_oldGUTI_01     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_eMM5GRegStatus , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EMM5GMMStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEAttach(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMEAttach_sequence, hf_index, ett_lix2_MMEAttach);

  return offset;
}


static const value_string lix2_MMEDirection_vals[] = {
  {   1, "networkInitiated" },
  {   2, "uEInitiated" },
  { 0, NULL }
};


static int
dissect_lix2_MMEDirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string lix2_EPSDetachType_vals[] = {
  {   1, "ePSDetach" },
  {   2, "iMSIDetach" },
  {   3, "combinedEPSIMSIDetach" },
  {   4, "reAttachRequired" },
  {   5, "reAttachNotRequired" },
  {   6, "reserved" },
  { 0, NULL }
};


static int
dissect_lix2_EPSDetachType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_EMMCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MMEDetach_sequence[] = {
  { &hf_lix2_detachDirection, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMEDirection },
  { &hf_lix2_detachType     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_EPSDetachType },
  { &hf_lix2_iMSI           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_gUTI_01        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_cause_02       , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EMMCause },
  { &hf_lix2_location_01    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_switchOffIndicator, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SwitchOffIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEDetach(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMEDetach_sequence, hf_index, ett_lix2_MMEDetach);

  return offset;
}


static const ber_sequence_t MMELocationUpdate_sequence[] = {
  { &hf_lix2_iMSI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_gUTI_01        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_oldGUTI_01     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_sMSServiceStatus, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EPSSMSServiceStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMELocationUpdate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMELocationUpdate_sequence, hf_index, ett_lix2_MMELocationUpdate);

  return offset;
}


static const ber_sequence_t MMEStartOfInterceptionWithEPSAttachedUE_sequence[] = {
  { &hf_lix2_attachType     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_EPSAttachType },
  { &hf_lix2_attachResult   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_EPSAttachResult },
  { &hf_lix2_iMSI           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_gUTI_01        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { &hf_lix2_ePSTAIList     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TAIList },
  { &hf_lix2_sMSServiceStatus, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EPSSMSServiceStatus },
  { &hf_lix2_eMM5GRegStatus , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_EMM5GMMStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEStartOfInterceptionWithEPSAttachedUE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMEStartOfInterceptionWithEPSAttachedUE_sequence, hf_index, ett_lix2_MMEStartOfInterceptionWithEPSAttachedUE);

  return offset;
}


static const value_string lix2_MMEFailedProcedureType_vals[] = {
  {   1, "attachReject" },
  {   2, "authenticationReject" },
  {   3, "securityModeReject" },
  {   4, "serviceReject" },
  {   5, "trackingAreaUpdateReject" },
  {   6, "activateDedicatedEPSBearerContextReject" },
  {   7, "activateDefaultEPSBearerContextReject" },
  {   8, "bearerResourceAllocationReject" },
  {   9, "bearerResourceModificationReject" },
  {  10, "modifyEPSBearerContectReject" },
  {  11, "pDNConnectivityReject" },
  {  12, "pDNDisconnectReject" },
  { 0, NULL }
};


static int
dissect_lix2_MMEFailedProcedureType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_lix2_ESMCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string lix2_MMEFailureCause_vals[] = {
  {   1, "eMMCause" },
  {   2, "eSMCause" },
  { 0, NULL }
};

static const ber_choice_t MMEFailureCause_choice[] = {
  {   1, &hf_lix2_eMMCause       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_EMMCause },
  {   2, &hf_lix2_eSMCause       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_ESMCause },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MMEFailureCause_choice, hf_index, ett_lix2_MMEFailureCause,
                                 NULL);

  return offset;
}


static const ber_sequence_t MMEUnsuccessfulProcedure_sequence[] = {
  { &hf_lix2_failedProcedureType_02, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMEFailedProcedureType },
  { &hf_lix2_failureCause_04, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_MMEFailureCause },
  { &hf_lix2_iMSI           , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  { &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  { &hf_lix2_mSISDN         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  { &hf_lix2_gUTI_01        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_GUTI },
  { &hf_lix2_location_01    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Location },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMEUnsuccessfulProcedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMEUnsuccessfulProcedure_sequence, hf_index, ett_lix2_MMEUnsuccessfulProcedure);

  return offset;
}


static const value_string lix2_XIRIEvent_vals[] = {
  {   1, "registration" },
  {   2, "deregistration" },
  {   3, "locationUpdate" },
  {   4, "startOfInterceptionWithRegisteredUE" },
  {   5, "unsuccessfulAMProcedure" },
  {   6, "pDUSessionEstablishment" },
  {   7, "pDUSessionModification" },
  {   8, "pDUSessionRelease" },
  {   9, "startOfInterceptionWithEstablishedPDUSession" },
  {  10, "unsuccessfulSMProcedure" },
  {  11, "servingSystemMessage" },
  {  12, "sMSMessage" },
  {  13, "lALSReport" },
  {  14, "pDHeaderReport" },
  {  15, "pDSummaryReport" },
  {  17, "mMSSend" },
  {  18, "mMSSendByNonLocalTarget" },
  {  19, "mMSNotification" },
  {  20, "mMSSendToNonLocalTarget" },
  {  21, "mMSNotificationResponse" },
  {  22, "mMSRetrieval" },
  {  23, "mMSDeliveryAck" },
  {  24, "mMSForward" },
  {  25, "mMSDeleteFromRelay" },
  {  26, "mMSDeliveryReport" },
  {  27, "mMSDeliveryReportNonLocalTarget" },
  {  28, "mMSReadReport" },
  {  29, "mMSReadReportNonLocalTarget" },
  {  30, "mMSCancel" },
  {  31, "mMSMBoxStore" },
  {  32, "mMSMBoxUpload" },
  {  33, "mMSMBoxDelete" },
  {  34, "mMSMBoxViewRequest" },
  {  35, "mMSMBoxViewResponse" },
  {  36, "pTCRegistration" },
  {  37, "pTCSessionInitiation" },
  {  38, "pTCSessionAbandon" },
  {  39, "pTCSessionStart" },
  {  40, "pTCSessionEnd" },
  {  41, "pTCStartOfInterception" },
  {  42, "pTCPreEstablishedSession" },
  {  43, "pTCInstantPersonalAlert" },
  {  44, "pTCPartyJoin" },
  {  45, "pTCPartyDrop" },
  {  46, "pTCPartyHold" },
  {  47, "pTCMediaModification" },
  {  48, "pTCGroupAdvertisement" },
  {  49, "pTCFloorControl" },
  {  50, "pTCTargetPresence" },
  {  51, "pTCParticipantPresence" },
  {  52, "pTCListManagement" },
  {  53, "pTCAccessPolicy" },
  {  54, "subscriberRecordChangeMessage" },
  {  55, "cancelLocationMessage" },
  {  56, "sMSReport" },
  {  57, "sMFMAPDUSessionEstablishment" },
  {  58, "sMFMAPDUSessionModification" },
  {  59, "sMFMAPDUSessionRelease" },
  {  60, "startOfInterceptionWithEstablishedMAPDUSession" },
  {  61, "unsuccessfulMASMProcedure" },
  {  62, "aMFIdentifierAssocation" },
  {  63, "mMEIdentifierAssocation" },
  {  64, "sMFPDUtoMAPDUSessionModification" },
  {  65, "nEFPDUSessionEstablishment" },
  {  66, "nEFPDUSessionModification" },
  {  67, "nEFPDUSessionRelease" },
  {  68, "nEFUnsuccessfulProcedure" },
  {  69, "nEFStartOfInterceptionWithEstablishedPDUSession" },
  {  70, "nEFdeviceTrigger" },
  {  71, "nEFdeviceTriggerReplace" },
  {  72, "nEFdeviceTriggerCancellation" },
  {  73, "nEFdeviceTriggerReportNotify" },
  {  74, "nEFMSISDNLessMOSMS" },
  {  75, "nEFExpectedUEBehaviourUpdate" },
  {  76, "sCEFPDNConnectionEstablishment" },
  {  77, "sCEFPDNConnectionUpdate" },
  {  78, "sCEFPDNConnectionRelease" },
  {  79, "sCEFUnsuccessfulProcedure" },
  {  80, "sCEFStartOfInterceptionWithEstablishedPDNConnection" },
  {  81, "sCEFdeviceTrigger" },
  {  82, "sCEFdeviceTriggerReplace" },
  {  83, "sCEFdeviceTriggerCancellation" },
  {  84, "sCEFdeviceTriggerReportNotify" },
  {  85, "sCEFMSISDNLessMOSMS" },
  {  86, "sCEFCommunicationPatternUpdate" },
  {  87, "mMEAttach" },
  {  88, "mMEDetach" },
  {  89, "mMELocationUpdate" },
  {  90, "mMEStartOfInterceptionWithEPSAttachedUE" },
  {  91, "mMEUnsuccessfulProcedure" },
  { 0, NULL }
};

static const ber_choice_t XIRIEvent_choice[] = {
  {   1, &hf_lix2_registration   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegistration },
  {   2, &hf_lix2_deregistration , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AMFDeregistration },
  {   3, &hf_lix2_locationUpdate , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_AMFLocationUpdate },
  {   4, &hf_lix2_startOfInterceptionWithRegisteredUE, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_AMFStartOfInterceptionWithRegisteredUE },
  {   5, &hf_lix2_unsuccessfulAMProcedure, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_AMFUnsuccessfulProcedure },
  {   6, &hf_lix2_pDUSessionEstablishment, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUSessionEstablishment },
  {   7, &hf_lix2_pDUSessionModification, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUSessionModification },
  {   8, &hf_lix2_pDUSessionRelease, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUSessionRelease },
  {   9, &hf_lix2_startOfInterceptionWithEstablishedPDUSession, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SMFStartOfInterceptionWithEstablishedPDUSession },
  {  10, &hf_lix2_unsuccessfulSMProcedure, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_SMFUnsuccessfulProcedure },
  {  11, &hf_lix2_servingSystemMessage, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_UDMServingSystemMessage },
  {  12, &hf_lix2_sMSMessage     , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_lix2_SMSMessage },
  {  13, &hf_lix2_lALSReport     , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_lix2_LALSReport },
  {  14, &hf_lix2_pDHeaderReport , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_lix2_PDHeaderReport },
  {  15, &hf_lix2_pDSummaryReport, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_lix2_PDSummaryReport },
  {  17, &hf_lix2_mMSSend        , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_lix2_MMSSend },
  {  18, &hf_lix2_mMSSendByNonLocalTarget, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_lix2_MMSSendByNonLocalTarget },
  {  19, &hf_lix2_mMSNotification, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_lix2_MMSNotification },
  {  20, &hf_lix2_mMSSendToNonLocalTarget, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_lix2_MMSSendToNonLocalTarget },
  {  21, &hf_lix2_mMSNotificationResponse, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_lix2_MMSNotificationResponse },
  {  22, &hf_lix2_mMSRetrieval   , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_lix2_MMSRetrieval },
  {  23, &hf_lix2_mMSDeliveryAck , BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeliveryAck },
  {  24, &hf_lix2_mMSForward     , BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_lix2_MMSForward },
  {  25, &hf_lix2_mMSDeleteFromRelay, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeleteFromRelay },
  {  26, &hf_lix2_mMSDeliveryReport, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeliveryReport },
  {  27, &hf_lix2_mMSDeliveryReportNonLocalTarget, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeliveryReportNonLocalTarget },
  {  28, &hf_lix2_mMSReadReport  , BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadReport },
  {  29, &hf_lix2_mMSReadReportNonLocalTarget, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadReportNonLocalTarget },
  {  30, &hf_lix2_mMSCancel      , BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_lix2_MMSCancel },
  {  31, &hf_lix2_mMSMBoxStore   , BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxStore },
  {  32, &hf_lix2_mMSMBoxUpload  , BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxUpload },
  {  33, &hf_lix2_mMSMBoxDelete  , BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxDelete },
  {  34, &hf_lix2_mMSMBoxViewRequest, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxViewRequest },
  {  35, &hf_lix2_mMSMBoxViewResponse, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxViewResponse },
  {  36, &hf_lix2_pTCRegistration, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_lix2_PTCRegistration },
  {  37, &hf_lix2_pTCSessionInitiation, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInitiation },
  {  38, &hf_lix2_pTCSessionAbandon, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionAbandon },
  {  39, &hf_lix2_pTCSessionStart, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionStart },
  {  40, &hf_lix2_pTCSessionEnd  , BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionEnd },
  {  41, &hf_lix2_pTCStartOfInterception, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_lix2_PTCStartOfInterception },
  {  42, &hf_lix2_pTCPreEstablishedSession, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPreEstablishedSession },
  {  43, &hf_lix2_pTCInstantPersonalAlert, BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_lix2_PTCInstantPersonalAlert },
  {  44, &hf_lix2_pTCPartyJoin   , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPartyJoin },
  {  45, &hf_lix2_pTCPartyDrop   , BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPartyDrop },
  {  46, &hf_lix2_pTCPartyHold   , BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPartyHold },
  {  47, &hf_lix2_pTCMediaModification, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_lix2_PTCMediaModification },
  {  48, &hf_lix2_pTCGroupAdvertisement, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_lix2_PTCGroupAdvertisement },
  {  49, &hf_lix2_pTCFloorControl, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_lix2_PTCFloorControl },
  {  50, &hf_lix2_pTCTargetPresence, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetPresence },
  {  51, &hf_lix2_pTCParticipantPresence, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_lix2_PTCParticipantPresence },
  {  52, &hf_lix2_pTCListManagement, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_lix2_PTCListManagement },
  {  53, &hf_lix2_pTCAccessPolicy, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_lix2_PTCAccessPolicy },
  {  54, &hf_lix2_subscriberRecordChangeMessage, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_lix2_UDMSubscriberRecordChangeMessage },
  {  55, &hf_lix2_cancelLocationMessage, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_lix2_UDMCancelLocationMessage },
  {  56, &hf_lix2_sMSReport      , BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_lix2_SMSReport },
  {  57, &hf_lix2_sMFMAPDUSessionEstablishment, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAPDUSessionEstablishment },
  {  58, &hf_lix2_sMFMAPDUSessionModification, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAPDUSessionModification },
  {  59, &hf_lix2_sMFMAPDUSessionRelease, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAPDUSessionRelease },
  {  60, &hf_lix2_startOfInterceptionWithEstablishedMAPDUSession, BER_CLASS_CON, 60, BER_FLAGS_IMPLTAG, dissect_lix2_SMFStartOfInterceptionWithEstablishedMAPDUSession },
  {  61, &hf_lix2_unsuccessfulMASMProcedure, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAUnsuccessfulProcedure },
  {  62, &hf_lix2_aMFIdentifierAssocation, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_lix2_AMFIdentifierAssocation },
  {  63, &hf_lix2_mMEIdentifierAssocation, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_lix2_MMEIdentifierAssocation },
  {  64, &hf_lix2_sMFPDUtoMAPDUSessionModification, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUtoMAPDUSessionModification },
  {  65, &hf_lix2_nEFPDUSessionEstablishment, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_lix2_NEFPDUSessionEstablishment },
  {  66, &hf_lix2_nEFPDUSessionModification, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_lix2_NEFPDUSessionModification },
  {  67, &hf_lix2_nEFPDUSessionRelease, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_lix2_NEFPDUSessionRelease },
  {  68, &hf_lix2_nEFUnsuccessfulProcedure, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_lix2_NEFUnsuccessfulProcedure },
  {  69, &hf_lix2_nEFStartOfInterceptionWithEstablishedPDUSession, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_lix2_NEFStartOfInterceptionWithEstablishedPDUSession },
  {  70, &hf_lix2_nEFdeviceTrigger, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTrigger },
  {  71, &hf_lix2_nEFdeviceTriggerReplace, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTriggerReplace },
  {  72, &hf_lix2_nEFdeviceTriggerCancellation, BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTriggerCancellation },
  {  73, &hf_lix2_nEFdeviceTriggerReportNotify, BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTriggerReportNotify },
  {  74, &hf_lix2_nEFMSISDNLessMOSMS, BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_lix2_NEFMSISDNLessMOSMS },
  {  75, &hf_lix2_nEFExpectedUEBehaviourUpdate, BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_lix2_NEFExpectedUEBehaviourUpdate },
  {  76, &hf_lix2_sCEFPDNConnectionEstablishment, BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFPDNConnectionEstablishment },
  {  77, &hf_lix2_sCEFPDNConnectionUpdate, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFPDNConnectionUpdate },
  {  78, &hf_lix2_sCEFPDNConnectionRelease, BER_CLASS_CON, 78, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFPDNConnectionRelease },
  {  79, &hf_lix2_sCEFUnsuccessfulProcedure, BER_CLASS_CON, 79, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFUnsuccessfulProcedure },
  {  80, &hf_lix2_sCEFStartOfInterceptionWithEstablishedPDNConnection, BER_CLASS_CON, 80, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFStartOfInterceptionWithEstablishedPDNConnection },
  {  81, &hf_lix2_sCEFdeviceTrigger, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTrigger },
  {  82, &hf_lix2_sCEFdeviceTriggerReplace, BER_CLASS_CON, 82, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTriggerReplace },
  {  83, &hf_lix2_sCEFdeviceTriggerCancellation, BER_CLASS_CON, 83, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTriggerCancellation },
  {  84, &hf_lix2_sCEFdeviceTriggerReportNotify, BER_CLASS_CON, 84, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTriggerReportNotify },
  {  85, &hf_lix2_sCEFMSISDNLessMOSMS, BER_CLASS_CON, 85, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFMSISDNLessMOSMS },
  {  86, &hf_lix2_sCEFCommunicationPatternUpdate, BER_CLASS_CON, 86, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFCommunicationPatternUpdate },
  {  87, &hf_lix2_mMEAttach      , BER_CLASS_CON, 87, BER_FLAGS_IMPLTAG, dissect_lix2_MMEAttach },
  {  88, &hf_lix2_mMEDetach      , BER_CLASS_CON, 88, BER_FLAGS_IMPLTAG, dissect_lix2_MMEDetach },
  {  89, &hf_lix2_mMELocationUpdate, BER_CLASS_CON, 89, BER_FLAGS_IMPLTAG, dissect_lix2_MMELocationUpdate },
  {  90, &hf_lix2_mMEStartOfInterceptionWithEPSAttachedUE, BER_CLASS_CON, 90, BER_FLAGS_IMPLTAG, dissect_lix2_MMEStartOfInterceptionWithEPSAttachedUE },
  {  91, &hf_lix2_mMEUnsuccessfulProcedure, BER_CLASS_CON, 91, BER_FLAGS_IMPLTAG, dissect_lix2_MMEUnsuccessfulProcedure },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_XIRIEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 XIRIEvent_choice, hf_index, ett_lix2_XIRIEvent,
                                 NULL);

  return offset;
}


static const ber_sequence_t XIRIPayload_sequence[] = {
  { &hf_lix2_xIRIPayloadOID , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_RELATIVE_OID },
  { &hf_lix2_event          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_XIRIEvent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_XIRIPayload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   XIRIPayload_sequence, hf_index, ett_lix2_XIRIPayload);

  return offset;
}


static const ber_sequence_t MDFCellSiteReport_sequence_of[1] = {
  { &hf_lix2_MDFCellSiteReport_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_CellInformation },
};

static int
dissect_lix2_MDFCellSiteReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MDFCellSiteReport_sequence_of, hf_index, ett_lix2_MDFCellSiteReport);

  return offset;
}


static const value_string lix2_IRIEvent_vals[] = {
  {   1, "registration" },
  {   2, "deregistration" },
  {   3, "locationUpdate" },
  {   4, "startOfInterceptionWithRegisteredUE" },
  {   5, "unsuccessfulRegistrationProcedure" },
  {   6, "pDUSessionEstablishment" },
  {   7, "pDUSessionModification" },
  {   8, "pDUSessionRelease" },
  {   9, "startOfInterceptionWithEstablishedPDUSession" },
  {  10, "unsuccessfulSessionProcedure" },
  {  11, "servingSystemMessage" },
  {  12, "sMSMessage" },
  {  13, "lALSReport" },
  {  14, "pDHeaderReport" },
  {  15, "pDSummaryReport" },
  {  16, "mDFCellSiteReport" },
  {  17, "mMSSend" },
  {  18, "mMSSendByNonLocalTarget" },
  {  19, "mMSNotification" },
  {  20, "mMSSendToNonLocalTarget" },
  {  21, "mMSNotificationResponse" },
  {  22, "mMSRetrieval" },
  {  23, "mMSDeliveryAck" },
  {  24, "mMSForward" },
  {  25, "mMSDeleteFromRelay" },
  {  26, "mMSDeliveryReport" },
  {  27, "mMSDeliveryReportNonLocalTarget" },
  {  28, "mMSReadReport" },
  {  29, "mMSReadReportNonLocalTarget" },
  {  30, "mMSCancel" },
  {  31, "mMSMBoxStore" },
  {  32, "mMSMBoxUpload" },
  {  33, "mMSMBoxDelete" },
  {  34, "mMSMBoxViewRequest" },
  {  35, "mMSMBoxViewResponse" },
  {  36, "pTCRegistration" },
  {  37, "pTCSessionInitiation" },
  {  38, "pTCSessionAbandon" },
  {  39, "pTCSessionStart" },
  {  40, "pTCSessionEnd" },
  {  41, "pTCStartOfInterception" },
  {  42, "pTCPreEstablishedSession" },
  {  43, "pTCInstantPersonalAlert" },
  {  44, "pTCPartyJoin" },
  {  45, "pTCPartyDrop" },
  {  46, "pTCPartyHold" },
  {  47, "pTCMediaModification" },
  {  48, "pTCGroupAdvertisement" },
  {  49, "pTCFloorControl" },
  {  50, "pTCTargetPresence" },
  {  51, "pTCParticipantPresence" },
  {  52, "pTCListManagement" },
  {  53, "pTCAccessPolicy" },
  {  54, "subscriberRecordChangeMessage" },
  {  55, "cancelLocationMessage" },
  {  56, "sMSReport" },
  {  57, "sMFMAPDUSessionEstablishment" },
  {  58, "sMFMAPDUSessionModification" },
  {  59, "sMFMAPDUSessionRelease" },
  {  60, "startOfInterceptionWithEstablishedMAPDUSession" },
  {  61, "unsuccessfulMASMProcedure" },
  {  62, "aMFIdentifierAssocation" },
  {  63, "mMEIdentifierAssocation" },
  {  64, "sMFPDUtoMAPDUSessionModification" },
  {  65, "nEFPDUSessionEstablishment" },
  {  66, "nEFPDUSessionModification" },
  {  67, "nEFPDUSessionRelease" },
  {  68, "nEFUnsuccessfulProcedure" },
  {  69, "nEFStartOfInterceptionWithEstablishedPDUSession" },
  {  70, "nEFdeviceTrigger" },
  {  71, "nEFdeviceTriggerReplace" },
  {  72, "nEFdeviceTriggerCancellation" },
  {  73, "nEFdeviceTriggerReportNotify" },
  {  74, "nEFMSISDNLessMOSMS" },
  {  75, "nEFExpectedUEBehaviourUpdate" },
  {  76, "sCEFPDNConnectionEstablishment" },
  {  77, "sCEFPDNConnectionUpdate" },
  {  78, "sCEFPDNConnectionRelease" },
  {  79, "sCEFUnsuccessfulProcedure" },
  {  80, "sCEFStartOfInterceptionWithEstablishedPDNConnection" },
  {  81, "sCEFdeviceTrigger" },
  {  82, "sCEFdeviceTriggerReplace" },
  {  83, "sCEFdeviceTriggerCancellation" },
  {  84, "sCEFdeviceTriggerReportNotify" },
  {  85, "sCEFMSISDNLessMOSMS" },
  {  86, "sCEFCommunicationPatternUpdate" },
  {  87, "mMEAttach" },
  {  88, "mMEDetach" },
  {  89, "mMELocationUpdate" },
  {  90, "mMEStartOfInterceptionWithEPSAttachedUE" },
  {  91, "mMEUnsuccessfulProcedure" },
  { 0, NULL }
};

static const ber_choice_t IRIEvent_choice[] = {
  {   1, &hf_lix2_registration   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_AMFRegistration },
  {   2, &hf_lix2_deregistration , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_AMFDeregistration },
  {   3, &hf_lix2_locationUpdate , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_AMFLocationUpdate },
  {   4, &hf_lix2_startOfInterceptionWithRegisteredUE, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_AMFStartOfInterceptionWithRegisteredUE },
  {   5, &hf_lix2_unsuccessfulRegistrationProcedure, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_AMFUnsuccessfulProcedure },
  {   6, &hf_lix2_pDUSessionEstablishment, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUSessionEstablishment },
  {   7, &hf_lix2_pDUSessionModification, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUSessionModification },
  {   8, &hf_lix2_pDUSessionRelease, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUSessionRelease },
  {   9, &hf_lix2_startOfInterceptionWithEstablishedPDUSession, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_SMFStartOfInterceptionWithEstablishedPDUSession },
  {  10, &hf_lix2_unsuccessfulSessionProcedure, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_SMFUnsuccessfulProcedure },
  {  11, &hf_lix2_servingSystemMessage, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_lix2_UDMServingSystemMessage },
  {  12, &hf_lix2_sMSMessage     , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_lix2_SMSMessage },
  {  13, &hf_lix2_lALSReport     , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_lix2_LALSReport },
  {  14, &hf_lix2_pDHeaderReport , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_lix2_PDHeaderReport },
  {  15, &hf_lix2_pDSummaryReport, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_lix2_PDSummaryReport },
  {  16, &hf_lix2_mDFCellSiteReport, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_lix2_MDFCellSiteReport },
  {  17, &hf_lix2_mMSSend        , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_lix2_MMSSend },
  {  18, &hf_lix2_mMSSendByNonLocalTarget, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_lix2_MMSSendByNonLocalTarget },
  {  19, &hf_lix2_mMSNotification, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_lix2_MMSNotification },
  {  20, &hf_lix2_mMSSendToNonLocalTarget, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_lix2_MMSSendToNonLocalTarget },
  {  21, &hf_lix2_mMSNotificationResponse, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_lix2_MMSNotificationResponse },
  {  22, &hf_lix2_mMSRetrieval   , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_lix2_MMSRetrieval },
  {  23, &hf_lix2_mMSDeliveryAck , BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeliveryAck },
  {  24, &hf_lix2_mMSForward     , BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_lix2_MMSForward },
  {  25, &hf_lix2_mMSDeleteFromRelay, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeleteFromRelay },
  {  26, &hf_lix2_mMSDeliveryReport, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeliveryReport },
  {  27, &hf_lix2_mMSDeliveryReportNonLocalTarget, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_lix2_MMSDeliveryReportNonLocalTarget },
  {  28, &hf_lix2_mMSReadReport  , BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadReport },
  {  29, &hf_lix2_mMSReadReportNonLocalTarget, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_lix2_MMSReadReportNonLocalTarget },
  {  30, &hf_lix2_mMSCancel      , BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_lix2_MMSCancel },
  {  31, &hf_lix2_mMSMBoxStore   , BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxStore },
  {  32, &hf_lix2_mMSMBoxUpload  , BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxUpload },
  {  33, &hf_lix2_mMSMBoxDelete  , BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxDelete },
  {  34, &hf_lix2_mMSMBoxViewRequest, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxViewRequest },
  {  35, &hf_lix2_mMSMBoxViewResponse, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_lix2_MMSMBoxViewResponse },
  {  36, &hf_lix2_pTCRegistration, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_lix2_PTCRegistration },
  {  37, &hf_lix2_pTCSessionInitiation, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionInitiation },
  {  38, &hf_lix2_pTCSessionAbandon, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionAbandon },
  {  39, &hf_lix2_pTCSessionStart, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionStart },
  {  40, &hf_lix2_pTCSessionEnd  , BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_lix2_PTCSessionEnd },
  {  41, &hf_lix2_pTCStartOfInterception, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_lix2_PTCStartOfInterception },
  {  42, &hf_lix2_pTCPreEstablishedSession, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPreEstablishedSession },
  {  43, &hf_lix2_pTCInstantPersonalAlert, BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_lix2_PTCInstantPersonalAlert },
  {  44, &hf_lix2_pTCPartyJoin   , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPartyJoin },
  {  45, &hf_lix2_pTCPartyDrop   , BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPartyDrop },
  {  46, &hf_lix2_pTCPartyHold   , BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_lix2_PTCPartyHold },
  {  47, &hf_lix2_pTCMediaModification, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_lix2_PTCMediaModification },
  {  48, &hf_lix2_pTCGroupAdvertisement, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_lix2_PTCGroupAdvertisement },
  {  49, &hf_lix2_pTCFloorControl, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_lix2_PTCFloorControl },
  {  50, &hf_lix2_pTCTargetPresence, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_lix2_PTCTargetPresence },
  {  51, &hf_lix2_pTCParticipantPresence, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_lix2_PTCParticipantPresence },
  {  52, &hf_lix2_pTCListManagement, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_lix2_PTCListManagement },
  {  53, &hf_lix2_pTCAccessPolicy, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_lix2_PTCAccessPolicy },
  {  54, &hf_lix2_subscriberRecordChangeMessage, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_lix2_UDMSubscriberRecordChangeMessage },
  {  55, &hf_lix2_cancelLocationMessage, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_lix2_UDMCancelLocationMessage },
  {  56, &hf_lix2_sMSReport      , BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_lix2_SMSReport },
  {  57, &hf_lix2_sMFMAPDUSessionEstablishment, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAPDUSessionEstablishment },
  {  58, &hf_lix2_sMFMAPDUSessionModification, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAPDUSessionModification },
  {  59, &hf_lix2_sMFMAPDUSessionRelease, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAPDUSessionRelease },
  {  60, &hf_lix2_startOfInterceptionWithEstablishedMAPDUSession, BER_CLASS_CON, 60, BER_FLAGS_IMPLTAG, dissect_lix2_SMFStartOfInterceptionWithEstablishedMAPDUSession },
  {  61, &hf_lix2_unsuccessfulMASMProcedure, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_lix2_SMFMAUnsuccessfulProcedure },
  {  62, &hf_lix2_aMFIdentifierAssocation, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_lix2_AMFIdentifierAssocation },
  {  63, &hf_lix2_mMEIdentifierAssocation, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_lix2_MMEIdentifierAssocation },
  {  64, &hf_lix2_sMFPDUtoMAPDUSessionModification, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_lix2_SMFPDUtoMAPDUSessionModification },
  {  65, &hf_lix2_nEFPDUSessionEstablishment, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_lix2_NEFPDUSessionEstablishment },
  {  66, &hf_lix2_nEFPDUSessionModification, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_lix2_NEFPDUSessionModification },
  {  67, &hf_lix2_nEFPDUSessionRelease, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_lix2_NEFPDUSessionRelease },
  {  68, &hf_lix2_nEFUnsuccessfulProcedure, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_lix2_NEFUnsuccessfulProcedure },
  {  69, &hf_lix2_nEFStartOfInterceptionWithEstablishedPDUSession, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_lix2_NEFStartOfInterceptionWithEstablishedPDUSession },
  {  70, &hf_lix2_nEFdeviceTrigger, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTrigger },
  {  71, &hf_lix2_nEFdeviceTriggerReplace, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTriggerReplace },
  {  72, &hf_lix2_nEFdeviceTriggerCancellation, BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTriggerCancellation },
  {  73, &hf_lix2_nEFdeviceTriggerReportNotify, BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_lix2_NEFDeviceTriggerReportNotify },
  {  74, &hf_lix2_nEFMSISDNLessMOSMS, BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_lix2_NEFMSISDNLessMOSMS },
  {  75, &hf_lix2_nEFExpectedUEBehaviourUpdate, BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_lix2_NEFExpectedUEBehaviourUpdate },
  {  76, &hf_lix2_sCEFPDNConnectionEstablishment, BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFPDNConnectionEstablishment },
  {  77, &hf_lix2_sCEFPDNConnectionUpdate, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFPDNConnectionUpdate },
  {  78, &hf_lix2_sCEFPDNConnectionRelease, BER_CLASS_CON, 78, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFPDNConnectionRelease },
  {  79, &hf_lix2_sCEFUnsuccessfulProcedure, BER_CLASS_CON, 79, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFUnsuccessfulProcedure },
  {  80, &hf_lix2_sCEFStartOfInterceptionWithEstablishedPDNConnection, BER_CLASS_CON, 80, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFStartOfInterceptionWithEstablishedPDNConnection },
  {  81, &hf_lix2_sCEFdeviceTrigger, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTrigger },
  {  82, &hf_lix2_sCEFdeviceTriggerReplace, BER_CLASS_CON, 82, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTriggerReplace },
  {  83, &hf_lix2_sCEFdeviceTriggerCancellation, BER_CLASS_CON, 83, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTriggerCancellation },
  {  84, &hf_lix2_sCEFdeviceTriggerReportNotify, BER_CLASS_CON, 84, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFDeviceTriggerReportNotify },
  {  85, &hf_lix2_sCEFMSISDNLessMOSMS, BER_CLASS_CON, 85, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFMSISDNLessMOSMS },
  {  86, &hf_lix2_sCEFCommunicationPatternUpdate, BER_CLASS_CON, 86, BER_FLAGS_IMPLTAG, dissect_lix2_SCEFCommunicationPatternUpdate },
  {  87, &hf_lix2_mMEAttach      , BER_CLASS_CON, 87, BER_FLAGS_IMPLTAG, dissect_lix2_MMEAttach },
  {  88, &hf_lix2_mMEDetach      , BER_CLASS_CON, 88, BER_FLAGS_IMPLTAG, dissect_lix2_MMEDetach },
  {  89, &hf_lix2_mMELocationUpdate, BER_CLASS_CON, 89, BER_FLAGS_IMPLTAG, dissect_lix2_MMELocationUpdate },
  {  90, &hf_lix2_mMEStartOfInterceptionWithEPSAttachedUE, BER_CLASS_CON, 90, BER_FLAGS_IMPLTAG, dissect_lix2_MMEStartOfInterceptionWithEPSAttachedUE },
  {  91, &hf_lix2_mMEUnsuccessfulProcedure, BER_CLASS_CON, 91, BER_FLAGS_IMPLTAG, dissect_lix2_MMEUnsuccessfulProcedure },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_IRIEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IRIEvent_choice, hf_index, ett_lix2_IRIEvent,
                                 NULL);

  return offset;
}


static const value_string lix2_TargetIdentifier_vals[] = {
  {   1, "sUPI" },
  {   2, "iMSI" },
  {   3, "pEI" },
  {   4, "iMEI" },
  {   5, "gPSI" },
  {   6, "mSISDN" },
  {   7, "nAI" },
  {   8, "iPv4Address" },
  {   9, "iPv6Address" },
  {  10, "ethernetAddress" },
  { 0, NULL }
};

static const ber_choice_t TargetIdentifier_choice[] = {
  {   1, &hf_lix2_sUPI           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_SUPI },
  {   2, &hf_lix2_iMSI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_IMSI },
  {   3, &hf_lix2_pEI            , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_PEI },
  {   4, &hf_lix2_iMEI           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_IMEI },
  {   5, &hf_lix2_gPSI           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lix2_GPSI },
  {   6, &hf_lix2_mSISDN         , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lix2_MSISDN },
  {   7, &hf_lix2_nAI            , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_lix2_NAI },
  {   8, &hf_lix2_iPv4Address    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_lix2_IPv4Address },
  {   9, &hf_lix2_iPv6Address    , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lix2_IPv6Address },
  {  10, &hf_lix2_ethernetAddress, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_lix2_MACAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_TargetIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TargetIdentifier_choice, hf_index, ett_lix2_TargetIdentifier,
                                 NULL);

  return offset;
}


static const value_string lix2_TargetIdentifierProvenance_vals[] = {
  {   1, "lEAProvided" },
  {   2, "observed" },
  {   3, "matchedOn" },
  {   4, "other" },
  { 0, NULL }
};


static int
dissect_lix2_TargetIdentifierProvenance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t IRITargetIdentifier_sequence[] = {
  { &hf_lix2_identifier     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_TargetIdentifier },
  { &hf_lix2_provenance     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_TargetIdentifierProvenance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_IRITargetIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRITargetIdentifier_sequence, hf_index, ett_lix2_IRITargetIdentifier);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_IRITargetIdentifier_sequence_of[1] = {
  { &hf_lix2_targetIdentifiers_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_IRITargetIdentifier },
};

static int
dissect_lix2_SEQUENCE_OF_IRITargetIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_IRITargetIdentifier_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_IRITargetIdentifier);

  return offset;
}


static const ber_sequence_t IRIPayload_sequence[] = {
  { &hf_lix2_iRIPayloadOID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_RELATIVE_OID },
  { &hf_lix2_event_01       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IRIEvent },
  { &hf_lix2_targetIdentifiers, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_IRITargetIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_IRIPayload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRIPayload_sequence, hf_index, ett_lix2_IRIPayload);

  return offset;
}



static int
dissect_lix2_UPFCCPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_lix2_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_UPFCCPDUPayload_vals[] = {
  {   1, "uPFIPCC" },
  {   2, "uPFEthernetCC" },
  {   3, "uPFUnstructuredCC" },
  { 0, NULL }
};

static const ber_choice_t UPFCCPDUPayload_choice[] = {
  {   1, &hf_lix2_uPFIPCC        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_OCTET_STRING },
  {   2, &hf_lix2_uPFEthernetCC  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_OCTET_STRING },
  {   3, &hf_lix2_uPFUnstructuredCC, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_UPFCCPDUPayload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UPFCCPDUPayload_choice, hf_index, ett_lix2_UPFCCPDUPayload,
                                 NULL);

  return offset;
}



static int
dissect_lix2_QFI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ExtendedUPFCCPDU_sequence[] = {
  { &hf_lix2_payload        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_UPFCCPDUPayload },
  { &hf_lix2_qFI            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_QFI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_ExtendedUPFCCPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedUPFCCPDU_sequence, hf_index, ett_lix2_ExtendedUPFCCPDU);

  return offset;
}


static const ber_sequence_t MMSCCPDU_sequence[] = {
  { &hf_lix2_version        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_MMSVersion },
  { &hf_lix2_transactionID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_mMSContent     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSCCPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSCCPDU_sequence, hf_index, ett_lix2_MMSCCPDU);

  return offset;
}



static int
dissect_lix2_NIDDCCPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string lix2_CCPDU_vals[] = {
  {   1, "uPFCCPDU" },
  {   2, "extendedUPFCCPDU" },
  {   3, "mMSCCPDU" },
  {   4, "nIDDCCPDU" },
  { 0, NULL }
};

static const ber_choice_t CCPDU_choice[] = {
  {   1, &hf_lix2_uPFCCPDU       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UPFCCPDU },
  {   2, &hf_lix2_extendedUPFCCPDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lix2_ExtendedUPFCCPDU },
  {   3, &hf_lix2_mMSCCPDU       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lix2_MMSCCPDU },
  {   4, &hf_lix2_nIDDCCPDU      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lix2_NIDDCCPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CCPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CCPDU_choice, hf_index, ett_lix2_CCPDU,
                                 NULL);

  return offset;
}


static const ber_sequence_t CCPayload_sequence[] = {
  { &hf_lix2_cCPayloadOID   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_RELATIVE_OID },
  { &hf_lix2_pDU            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_CCPDU },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_CCPayload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCPayload_sequence, hf_index, ett_lix2_CCPayload);

  return offset;
}


static const value_string lix2_LINotificationType_vals[] = {
  {   1, "activation" },
  {   2, "deactivation" },
  {   3, "modification" },
  { 0, NULL }
};


static int
dissect_lix2_LINotificationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t LIAppliedDeliveryInformation_sequence[] = {
  { &hf_lix2_hI2DeliveryIPAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_hI2DeliveryPortNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { &hf_lix2_hI3DeliveryIPAddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_IPAddress },
  { &hf_lix2_hI3DeliveryPortNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_PortNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LIAppliedDeliveryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LIAppliedDeliveryInformation_sequence, hf_index, ett_lix2_LIAppliedDeliveryInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LIAppliedDeliveryInformation_sequence_of[1] = {
  { &hf_lix2_appliedDeliveryInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lix2_LIAppliedDeliveryInformation },
};

static int
dissect_lix2_SEQUENCE_OF_LIAppliedDeliveryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LIAppliedDeliveryInformation_sequence_of, hf_index, ett_lix2_SEQUENCE_OF_LIAppliedDeliveryInformation);

  return offset;
}


static const ber_sequence_t LINotification_sequence[] = {
  { &hf_lix2_notificationType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_LINotificationType },
  { &hf_lix2_appliedTargetID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_TargetIdentifier },
  { &hf_lix2_appliedDeliveryInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_SEQUENCE_OF_LIAppliedDeliveryInformation },
  { &hf_lix2_appliedStartTime, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { &hf_lix2_appliedEndTime , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LINotification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LINotification_sequence, hf_index, ett_lix2_LINotification);

  return offset;
}


static const value_string lix2_LINotificationMessage_vals[] = {
  {   1, "lINotification" },
  { 0, NULL }
};

static const ber_choice_t LINotificationMessage_choice[] = {
  {   1, &hf_lix2_lINotification , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_LINotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LINotificationMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LINotificationMessage_choice, hf_index, ett_lix2_LINotificationMessage,
                                 NULL);

  return offset;
}


static const ber_sequence_t LINotificationPayload_sequence[] = {
  { &hf_lix2_lINotificationPayloadOID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_RELATIVE_OID },
  { &hf_lix2_notification   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lix2_LINotificationMessage },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_LINotificationPayload(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LINotificationPayload_sequence, hf_index, ett_lix2_LINotificationPayload);

  return offset;
}


static const value_string lix2_MMSCancelStatus_vals[] = {
  {   1, "cancelRequestSuccessfullyReceived" },
  {   2, "cancelRequestCorrupted" },
  { 0, NULL }
};


static int
dissect_lix2_MMSCancelStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MMSElementDescriptor_sequence[] = {
  { &hf_lix2_reference      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_parameter      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { &hf_lix2_value          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lix2_MMSElementDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MMSElementDescriptor_sequence, hf_index, ett_lix2_MMSElementDescriptor);

  return offset;
}

/*--- PDUs ---*/

static int dissect_XIRIPayload_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_lix2_XIRIPayload(FALSE, tvb, offset, &asn1_ctx, tree, hf_lix2_XIRIPayload_PDU);
  return offset;
}


/*--- End of included file: packet-lix2-fn.c ---*/
#line 38 "./asn1/lix2/packet-lix2-template.c"

/*--- proto_register_lix2 -------------------------------------------*/
void proto_register_lix2(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-lix2-hfarr.c ---*/
#line 1 "./asn1/lix2/packet-lix2-hfarr.c"
    { &hf_lix2_XIRIPayload_PDU,
      { "XIRIPayload", "lix2.XIRIPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_xIRIPayloadOID,
      { "xIRIPayloadOID", "lix2.xIRIPayloadOID",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_lix2_event,
      { "event", "lix2.event",
        FT_UINT32, BASE_DEC, VALS(lix2_XIRIEvent_vals), 0,
        "XIRIEvent", HFILL }},
    { &hf_lix2_registration,
      { "registration", "lix2.registration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AMFRegistration", HFILL }},
    { &hf_lix2_deregistration,
      { "deregistration", "lix2.deregistration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AMFDeregistration", HFILL }},
    { &hf_lix2_locationUpdate,
      { "locationUpdate", "lix2.locationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AMFLocationUpdate", HFILL }},
    { &hf_lix2_startOfInterceptionWithRegisteredUE,
      { "startOfInterceptionWithRegisteredUE", "lix2.startOfInterceptionWithRegisteredUE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AMFStartOfInterceptionWithRegisteredUE", HFILL }},
    { &hf_lix2_unsuccessfulAMProcedure,
      { "unsuccessfulAMProcedure", "lix2.unsuccessfulAMProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AMFUnsuccessfulProcedure", HFILL }},
    { &hf_lix2_pDUSessionEstablishment,
      { "pDUSessionEstablishment", "lix2.pDUSessionEstablishment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFPDUSessionEstablishment", HFILL }},
    { &hf_lix2_pDUSessionModification,
      { "pDUSessionModification", "lix2.pDUSessionModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFPDUSessionModification", HFILL }},
    { &hf_lix2_pDUSessionRelease,
      { "pDUSessionRelease", "lix2.pDUSessionRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFPDUSessionRelease", HFILL }},
    { &hf_lix2_startOfInterceptionWithEstablishedPDUSession,
      { "startOfInterceptionWithEstablishedPDUSession", "lix2.startOfInterceptionWithEstablishedPDUSession_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFStartOfInterceptionWithEstablishedPDUSession", HFILL }},
    { &hf_lix2_unsuccessfulSMProcedure,
      { "unsuccessfulSMProcedure", "lix2.unsuccessfulSMProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFUnsuccessfulProcedure", HFILL }},
    { &hf_lix2_servingSystemMessage,
      { "servingSystemMessage", "lix2.servingSystemMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UDMServingSystemMessage", HFILL }},
    { &hf_lix2_sMSMessage,
      { "sMSMessage", "lix2.sMSMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_lALSReport,
      { "lALSReport", "lix2.lALSReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pDHeaderReport,
      { "pDHeaderReport", "lix2.pDHeaderReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pDSummaryReport,
      { "pDSummaryReport", "lix2.pDSummaryReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSSend,
      { "mMSSend", "lix2.mMSSend_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSSendByNonLocalTarget,
      { "mMSSendByNonLocalTarget", "lix2.mMSSendByNonLocalTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSNotification,
      { "mMSNotification", "lix2.mMSNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSSendToNonLocalTarget,
      { "mMSSendToNonLocalTarget", "lix2.mMSSendToNonLocalTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSNotificationResponse,
      { "mMSNotificationResponse", "lix2.mMSNotificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSRetrieval,
      { "mMSRetrieval", "lix2.mMSRetrieval_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSDeliveryAck,
      { "mMSDeliveryAck", "lix2.mMSDeliveryAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSForward,
      { "mMSForward", "lix2.mMSForward_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSDeleteFromRelay,
      { "mMSDeleteFromRelay", "lix2.mMSDeleteFromRelay_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSDeliveryReport,
      { "mMSDeliveryReport", "lix2.mMSDeliveryReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSDeliveryReportNonLocalTarget,
      { "mMSDeliveryReportNonLocalTarget", "lix2.mMSDeliveryReportNonLocalTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSReadReport,
      { "mMSReadReport", "lix2.mMSReadReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSReadReportNonLocalTarget,
      { "mMSReadReportNonLocalTarget", "lix2.mMSReadReportNonLocalTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSCancel,
      { "mMSCancel", "lix2.mMSCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSMBoxStore,
      { "mMSMBoxStore", "lix2.mMSMBoxStore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSMBoxUpload,
      { "mMSMBoxUpload", "lix2.mMSMBoxUpload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSMBoxDelete,
      { "mMSMBoxDelete", "lix2.mMSMBoxDelete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSMBoxViewRequest,
      { "mMSMBoxViewRequest", "lix2.mMSMBoxViewRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSMBoxViewResponse,
      { "mMSMBoxViewResponse", "lix2.mMSMBoxViewResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCRegistration,
      { "pTCRegistration", "lix2.pTCRegistration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCSessionInitiation,
      { "pTCSessionInitiation", "lix2.pTCSessionInitiation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCSessionAbandon,
      { "pTCSessionAbandon", "lix2.pTCSessionAbandon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCSessionStart,
      { "pTCSessionStart", "lix2.pTCSessionStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCSessionEnd,
      { "pTCSessionEnd", "lix2.pTCSessionEnd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCStartOfInterception,
      { "pTCStartOfInterception", "lix2.pTCStartOfInterception_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCPreEstablishedSession,
      { "pTCPreEstablishedSession", "lix2.pTCPreEstablishedSession_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCInstantPersonalAlert,
      { "pTCInstantPersonalAlert", "lix2.pTCInstantPersonalAlert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCPartyJoin,
      { "pTCPartyJoin", "lix2.pTCPartyJoin_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCPartyDrop,
      { "pTCPartyDrop", "lix2.pTCPartyDrop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCPartyHold,
      { "pTCPartyHold", "lix2.pTCPartyHold_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCMediaModification,
      { "pTCMediaModification", "lix2.pTCMediaModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCGroupAdvertisement,
      { "pTCGroupAdvertisement", "lix2.pTCGroupAdvertisement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCFloorControl,
      { "pTCFloorControl", "lix2.pTCFloorControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCTargetPresence,
      { "pTCTargetPresence", "lix2.pTCTargetPresence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCParticipantPresence,
      { "pTCParticipantPresence", "lix2.pTCParticipantPresence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCListManagement,
      { "pTCListManagement", "lix2.pTCListManagement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCAccessPolicy,
      { "pTCAccessPolicy", "lix2.pTCAccessPolicy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_subscriberRecordChangeMessage,
      { "subscriberRecordChangeMessage", "lix2.subscriberRecordChangeMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UDMSubscriberRecordChangeMessage", HFILL }},
    { &hf_lix2_cancelLocationMessage,
      { "cancelLocationMessage", "lix2.cancelLocationMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UDMCancelLocationMessage", HFILL }},
    { &hf_lix2_sMSReport,
      { "sMSReport", "lix2.sMSReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sMFMAPDUSessionEstablishment,
      { "sMFMAPDUSessionEstablishment", "lix2.sMFMAPDUSessionEstablishment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sMFMAPDUSessionModification,
      { "sMFMAPDUSessionModification", "lix2.sMFMAPDUSessionModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sMFMAPDUSessionRelease,
      { "sMFMAPDUSessionRelease", "lix2.sMFMAPDUSessionRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_startOfInterceptionWithEstablishedMAPDUSession,
      { "startOfInterceptionWithEstablishedMAPDUSession", "lix2.startOfInterceptionWithEstablishedMAPDUSession_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFStartOfInterceptionWithEstablishedMAPDUSession", HFILL }},
    { &hf_lix2_unsuccessfulMASMProcedure,
      { "unsuccessfulMASMProcedure", "lix2.unsuccessfulMASMProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFMAUnsuccessfulProcedure", HFILL }},
    { &hf_lix2_aMFIdentifierAssocation,
      { "aMFIdentifierAssocation", "lix2.aMFIdentifierAssocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEIdentifierAssocation,
      { "mMEIdentifierAssocation", "lix2.mMEIdentifierAssocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sMFPDUtoMAPDUSessionModification,
      { "sMFPDUtoMAPDUSessionModification", "lix2.sMFPDUtoMAPDUSessionModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFPDUSessionEstablishment,
      { "nEFPDUSessionEstablishment", "lix2.nEFPDUSessionEstablishment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFPDUSessionModification,
      { "nEFPDUSessionModification", "lix2.nEFPDUSessionModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFPDUSessionRelease,
      { "nEFPDUSessionRelease", "lix2.nEFPDUSessionRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFUnsuccessfulProcedure,
      { "nEFUnsuccessfulProcedure", "lix2.nEFUnsuccessfulProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFStartOfInterceptionWithEstablishedPDUSession,
      { "nEFStartOfInterceptionWithEstablishedPDUSession", "lix2.nEFStartOfInterceptionWithEstablishedPDUSession_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFdeviceTrigger,
      { "nEFdeviceTrigger", "lix2.nEFdeviceTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFdeviceTriggerReplace,
      { "nEFdeviceTriggerReplace", "lix2.nEFdeviceTriggerReplace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFdeviceTriggerCancellation,
      { "nEFdeviceTriggerCancellation", "lix2.nEFdeviceTriggerCancellation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFdeviceTriggerReportNotify,
      { "nEFdeviceTriggerReportNotify", "lix2.nEFdeviceTriggerReportNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFMSISDNLessMOSMS,
      { "nEFMSISDNLessMOSMS", "lix2.nEFMSISDNLessMOSMS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFExpectedUEBehaviourUpdate,
      { "nEFExpectedUEBehaviourUpdate", "lix2.nEFExpectedUEBehaviourUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFPDNConnectionEstablishment,
      { "sCEFPDNConnectionEstablishment", "lix2.sCEFPDNConnectionEstablishment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFPDNConnectionUpdate,
      { "sCEFPDNConnectionUpdate", "lix2.sCEFPDNConnectionUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFPDNConnectionRelease,
      { "sCEFPDNConnectionRelease", "lix2.sCEFPDNConnectionRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFUnsuccessfulProcedure,
      { "sCEFUnsuccessfulProcedure", "lix2.sCEFUnsuccessfulProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFStartOfInterceptionWithEstablishedPDNConnection,
      { "sCEFStartOfInterceptionWithEstablishedPDNConnection", "lix2.sCEFStartOfInterceptionWithEstablishedPDNConnection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFdeviceTrigger,
      { "sCEFdeviceTrigger", "lix2.sCEFdeviceTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFdeviceTriggerReplace,
      { "sCEFdeviceTriggerReplace", "lix2.sCEFdeviceTriggerReplace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFdeviceTriggerCancellation,
      { "sCEFdeviceTriggerCancellation", "lix2.sCEFdeviceTriggerCancellation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFdeviceTriggerReportNotify,
      { "sCEFdeviceTriggerReportNotify", "lix2.sCEFdeviceTriggerReportNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFMSISDNLessMOSMS,
      { "sCEFMSISDNLessMOSMS", "lix2.sCEFMSISDNLessMOSMS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFCommunicationPatternUpdate,
      { "sCEFCommunicationPatternUpdate", "lix2.sCEFCommunicationPatternUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEAttach,
      { "mMEAttach", "lix2.mMEAttach_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEDetach,
      { "mMEDetach", "lix2.mMEDetach_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMELocationUpdate,
      { "mMELocationUpdate", "lix2.mMELocationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEStartOfInterceptionWithEPSAttachedUE,
      { "mMEStartOfInterceptionWithEPSAttachedUE", "lix2.mMEStartOfInterceptionWithEPSAttachedUE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEUnsuccessfulProcedure,
      { "mMEUnsuccessfulProcedure", "lix2.mMEUnsuccessfulProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iRIPayloadOID,
      { "iRIPayloadOID", "lix2.iRIPayloadOID",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_lix2_event_01,
      { "event", "lix2.event",
        FT_UINT32, BASE_DEC, VALS(lix2_IRIEvent_vals), 0,
        "IRIEvent", HFILL }},
    { &hf_lix2_targetIdentifiers,
      { "targetIdentifiers", "lix2.targetIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_IRITargetIdentifier", HFILL }},
    { &hf_lix2_targetIdentifiers_item,
      { "IRITargetIdentifier", "lix2.IRITargetIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_unsuccessfulRegistrationProcedure,
      { "unsuccessfulRegistrationProcedure", "lix2.unsuccessfulRegistrationProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AMFUnsuccessfulProcedure", HFILL }},
    { &hf_lix2_unsuccessfulSessionProcedure,
      { "unsuccessfulSessionProcedure", "lix2.unsuccessfulSessionProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFUnsuccessfulProcedure", HFILL }},
    { &hf_lix2_mDFCellSiteReport,
      { "mDFCellSiteReport", "lix2.mDFCellSiteReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_identifier,
      { "identifier", "lix2.identifier",
        FT_UINT32, BASE_DEC, VALS(lix2_TargetIdentifier_vals), 0,
        "TargetIdentifier", HFILL }},
    { &hf_lix2_provenance,
      { "provenance", "lix2.provenance",
        FT_UINT32, BASE_DEC, VALS(lix2_TargetIdentifierProvenance_vals), 0,
        "TargetIdentifierProvenance", HFILL }},
    { &hf_lix2_cCPayloadOID,
      { "cCPayloadOID", "lix2.cCPayloadOID",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_lix2_pDU,
      { "pDU", "lix2.pDU",
        FT_UINT32, BASE_DEC, VALS(lix2_CCPDU_vals), 0,
        "CCPDU", HFILL }},
    { &hf_lix2_uPFCCPDU,
      { "uPFCCPDU", "lix2.uPFCCPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_extendedUPFCCPDU,
      { "extendedUPFCCPDU", "lix2.extendedUPFCCPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMSCCPDU,
      { "mMSCCPDU", "lix2.mMSCCPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nIDDCCPDU,
      { "nIDDCCPDU", "lix2.nIDDCCPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_lINotificationPayloadOID,
      { "lINotificationPayloadOID", "lix2.lINotificationPayloadOID",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_lix2_notification,
      { "notification", "lix2.notification",
        FT_UINT32, BASE_DEC, VALS(lix2_LINotificationMessage_vals), 0,
        "LINotificationMessage", HFILL }},
    { &hf_lix2_lINotification,
      { "lINotification", "lix2.lINotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sUPI,
      { "sUPI", "lix2.sUPI",
        FT_UINT32, BASE_DEC, VALS(lix2_SUPI_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_gPSI,
      { "gPSI", "lix2.gPSI",
        FT_UINT32, BASE_DEC, VALS(lix2_GPSI_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pDUSessionID,
      { "pDUSessionID", "lix2.pDUSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sNSSAI,
      { "sNSSAI", "lix2.sNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nEFID,
      { "nEFID", "lix2.nEFID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_dNN,
      { "dNN", "lix2.dNN",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_rDSSupport,
      { "rDSSupport", "lix2.rDSSupport",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sMFID,
      { "sMFID", "lix2.sMFID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_aFID,
      { "aFID", "lix2.aFID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_initiator,
      { "initiator", "lix2.initiator",
        FT_UINT32, BASE_DEC, VALS(lix2_Initiator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_rDSSourcePortNumber,
      { "rDSSourcePortNumber", "lix2.rDSSourcePortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDSPortNumber", HFILL }},
    { &hf_lix2_rDSDestinationPortNumber,
      { "rDSDestinationPortNumber", "lix2.rDSDestinationPortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDSPortNumber", HFILL }},
    { &hf_lix2_applicationID,
      { "applicationID", "lix2.applicationID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_rDSAction,
      { "rDSAction", "lix2.rDSAction",
        FT_UINT32, BASE_DEC, VALS(lix2_RDSAction_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_serializationFormat,
      { "serializationFormat", "lix2.serializationFormat",
        FT_UINT32, BASE_DEC, VALS(lix2_SerializationFormat_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_timeOfFirstPacket,
      { "timeOfFirstPacket", "lix2.timeOfFirstPacket",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_timeOfLastPacket,
      { "timeOfLastPacket", "lix2.timeOfLastPacket",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_uplinkVolume,
      { "uplinkVolume", "lix2.uplinkVolume",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_downlinkVolume,
      { "downlinkVolume", "lix2.downlinkVolume",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_releaseCause,
      { "releaseCause", "lix2.releaseCause",
        FT_UINT32, BASE_DEC, VALS(lix2_NEFReleaseCause_vals), 0,
        "NEFReleaseCause", HFILL }},
    { &hf_lix2_failureCause,
      { "failureCause", "lix2.failureCause",
        FT_UINT32, BASE_DEC, VALS(lix2_NEFFailureCause_vals), 0,
        "NEFFailureCause", HFILL }},
    { &hf_lix2_triggerId,
      { "triggerId", "lix2.triggerId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_triggerPayload,
      { "triggerPayload", "lix2.triggerPayload",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_validityPeriod,
      { "validityPeriod", "lix2.validityPeriod",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_priorityDT,
      { "priorityDT", "lix2.priorityDT",
        FT_UINT32, BASE_DEC, VALS(lix2_PriorityDT_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_sourcePortId,
      { "sourcePortId", "lix2.sourcePortId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PortNumber", HFILL }},
    { &hf_lix2_destinationPortId,
      { "destinationPortId", "lix2.destinationPortId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PortNumber", HFILL }},
    { &hf_lix2_deviceTriggerDeliveryResult,
      { "deviceTriggerDeliveryResult", "lix2.deviceTriggerDeliveryResult",
        FT_UINT32, BASE_DEC, VALS(lix2_DeviceTriggerDeliveryResult_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_terminatingSMSParty,
      { "terminatingSMSParty", "lix2.terminatingSMSParty",
        FT_STRING, BASE_NONE, NULL, 0,
        "AFID", HFILL }},
    { &hf_lix2_sMS,
      { "sMS", "lix2.sMS",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSTPDUData_vals), 0,
        "SMSTPDUData", HFILL }},
    { &hf_lix2_sourcePort,
      { "sourcePort", "lix2.sourcePort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PortNumber", HFILL }},
    { &hf_lix2_destinationPort,
      { "destinationPort", "lix2.destinationPort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PortNumber", HFILL }},
    { &hf_lix2_expectedUEMovingTrajectory,
      { "expectedUEMovingTrajectory", "lix2.expectedUEMovingTrajectory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UMTLocationArea5G", HFILL }},
    { &hf_lix2_expectedUEMovingTrajectory_item,
      { "UMTLocationArea5G", "lix2.UMTLocationArea5G_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_stationaryIndication,
      { "stationaryIndication", "lix2.stationaryIndication",
        FT_UINT32, BASE_DEC, VALS(lix2_StationaryIndication_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_communicationDurationTime,
      { "communicationDurationTime", "lix2.communicationDurationTime",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_periodicTime,
      { "periodicTime", "lix2.periodicTime",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_scheduledCommunicationTime,
      { "scheduledCommunicationTime", "lix2.scheduledCommunicationTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_scheduledCommunicationType,
      { "scheduledCommunicationType", "lix2.scheduledCommunicationType",
        FT_UINT32, BASE_DEC, VALS(lix2_ScheduledCommunicationType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_batteryIndication,
      { "batteryIndication", "lix2.batteryIndication",
        FT_UINT32, BASE_DEC, VALS(lix2_BatteryIndication_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_trafficProfile,
      { "trafficProfile", "lix2.trafficProfile",
        FT_UINT32, BASE_DEC, VALS(lix2_TrafficProfile_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_expectedTimeAndDayOfWeekInTrajectory,
      { "expectedTimeAndDayOfWeekInTrajectory", "lix2.expectedTimeAndDayOfWeekInTrajectory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UMTLocationArea5G", HFILL }},
    { &hf_lix2_expectedTimeAndDayOfWeekInTrajectory_item,
      { "UMTLocationArea5G", "lix2.UMTLocationArea5G_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_validityTime,
      { "validityTime", "lix2.validityTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_days,
      { "days", "lix2.days",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Daytime", HFILL }},
    { &hf_lix2_days_item,
      { "Daytime", "lix2.Daytime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_timeOfDay,
      { "timeOfDay", "lix2.timeOfDay_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Daytime", HFILL }},
    { &hf_lix2_durationSec,
      { "durationSec", "lix2.durationSec",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_location,
      { "location", "lix2.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRLocation", HFILL }},
    { &hf_lix2_daysOfWeek,
      { "daysOfWeek", "lix2.daysOfWeek",
        FT_UINT32, BASE_DEC, VALS(lix2_Day_vals), 0,
        "Day", HFILL }},
    { &hf_lix2_timeOfDayStart,
      { "timeOfDayStart", "lix2.timeOfDayStart",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_timeOfDayEnd,
      { "timeOfDayEnd", "lix2.timeOfDayEnd",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_iMSI,
      { "iMSI", "lix2.iMSI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mSISDN,
      { "mSISDN", "lix2.mSISDN",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_externalIdentifier,
      { "externalIdentifier", "lix2.externalIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "NAI", HFILL }},
    { &hf_lix2_iMEI,
      { "iMEI", "lix2.iMEI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_ePSBearerID,
      { "ePSBearerID", "lix2.ePSBearerID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCEFID,
      { "sCEFID", "lix2.sCEFID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_aPN,
      { "aPN", "lix2.aPN",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sCSASID,
      { "sCSASID", "lix2.sCSASID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_releaseCause_01,
      { "releaseCause", "lix2.releaseCause",
        FT_UINT32, BASE_DEC, VALS(lix2_SCEFReleaseCause_vals), 0,
        "SCEFReleaseCause", HFILL }},
    { &hf_lix2_failureCause_01,
      { "failureCause", "lix2.failureCause",
        FT_UINT32, BASE_DEC, VALS(lix2_SCEFFailureCause_vals), 0,
        "SCEFFailureCause", HFILL }},
    { &hf_lix2_externalIdentifie,
      { "externalIdentifie", "lix2.externalIdentifie",
        FT_STRING, BASE_NONE, NULL, 0,
        "NAI", HFILL }},
    { &hf_lix2_terminatingSMSParty_01,
      { "terminatingSMSParty", "lix2.terminatingSMSParty",
        FT_STRING, BASE_NONE, NULL, 0,
        "SCSASID", HFILL }},
    { &hf_lix2_periodicCommunicationIndicator,
      { "periodicCommunicationIndicator", "lix2.periodicCommunicationIndicator",
        FT_UINT32, BASE_DEC, VALS(lix2_PeriodicCommunicationIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_registrationType,
      { "registrationType", "lix2.registrationType",
        FT_UINT32, BASE_DEC, VALS(lix2_AMFRegistrationType_vals), 0,
        "AMFRegistrationType", HFILL }},
    { &hf_lix2_registrationResult,
      { "registrationResult", "lix2.registrationResult",
        FT_UINT32, BASE_DEC, VALS(lix2_AMFRegistrationResult_vals), 0,
        "AMFRegistrationResult", HFILL }},
    { &hf_lix2_slice,
      { "slice", "lix2.slice_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sUCI,
      { "sUCI", "lix2.sUCI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pEI,
      { "pEI", "lix2.pEI",
        FT_UINT32, BASE_DEC, VALS(lix2_PEI_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_gUTI,
      { "gUTI", "lix2.gUTI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FiveGGUTI", HFILL }},
    { &hf_lix2_location_01,
      { "location", "lix2.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_non3GPPAccessEndpoint,
      { "non3GPPAccessEndpoint", "lix2.non3GPPAccessEndpoint",
        FT_UINT32, BASE_DEC, VALS(lix2_UEEndpointAddress_vals), 0,
        "UEEndpointAddress", HFILL }},
    { &hf_lix2_fiveGSTAIList,
      { "fiveGSTAIList", "lix2.fiveGSTAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TAIList", HFILL }},
    { &hf_lix2_sMSOverNasIndicator,
      { "sMSOverNasIndicator", "lix2.sMSOverNasIndicator",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSOverNASIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_oldGUTI,
      { "oldGUTI", "lix2.oldGUTI",
        FT_UINT32, BASE_DEC, VALS(lix2_EPS5GGUTI_vals), 0,
        "EPS5GGUTI", HFILL }},
    { &hf_lix2_eMM5GRegStatus,
      { "eMM5GRegStatus", "lix2.eMM5GRegStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EMM5GMMStatus", HFILL }},
    { &hf_lix2_deregistrationDirection,
      { "deregistrationDirection", "lix2.deregistrationDirection",
        FT_UINT32, BASE_DEC, VALS(lix2_AMFDirection_vals), 0,
        "AMFDirection", HFILL }},
    { &hf_lix2_accessType,
      { "accessType", "lix2.accessType",
        FT_UINT32, BASE_DEC, VALS(lix2_AccessType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_cause,
      { "cause", "lix2.cause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FiveGMMCause", HFILL }},
    { &hf_lix2_switchOffIndicator,
      { "switchOffIndicator", "lix2.switchOffIndicator",
        FT_UINT32, BASE_DEC, VALS(lix2_SwitchOffIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_reRegRequiredIndicator,
      { "reRegRequiredIndicator", "lix2.reRegRequiredIndicator",
        FT_UINT32, BASE_DEC, VALS(lix2_ReRegRequiredIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_sMSOverNASIndicator,
      { "sMSOverNASIndicator", "lix2.sMSOverNASIndicator",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSOverNASIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_timeOfRegistration,
      { "timeOfRegistration", "lix2.timeOfRegistration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_failedProcedureType,
      { "failedProcedureType", "lix2.failedProcedureType",
        FT_UINT32, BASE_DEC, VALS(lix2_AMFFailedProcedureType_vals), 0,
        "AMFFailedProcedureType", HFILL }},
    { &hf_lix2_failureCause_02,
      { "failureCause", "lix2.failureCause",
        FT_UINT32, BASE_DEC, VALS(lix2_AMFFailureCause_vals), 0,
        "AMFFailureCause", HFILL }},
    { &hf_lix2_requestedSlice,
      { "requestedSlice", "lix2.requestedSlice",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NSSAI", HFILL }},
    { &hf_lix2_aMFRegionID,
      { "aMFRegionID", "lix2.aMFRegionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_aMFSetID,
      { "aMFSetID", "lix2.aMFSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_aMFPointer,
      { "aMFPointer", "lix2.aMFPointer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_fiveGMMCause,
      { "fiveGMMCause", "lix2.fiveGMMCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_fiveGSMCause,
      { "fiveGSMCause", "lix2.fiveGSMCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sUPIUnauthenticated,
      { "sUPIUnauthenticated", "lix2.sUPIUnauthenticated",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "SUPIUnauthenticatedIndication", HFILL }},
    { &hf_lix2_gTPTunnelID,
      { "gTPTunnelID", "lix2.gTPTunnelID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FTEID", HFILL }},
    { &hf_lix2_pDUSessionType,
      { "pDUSessionType", "lix2.pDUSessionType",
        FT_UINT32, BASE_DEC, VALS(lix2_PDUSessionType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_uEEndpoint,
      { "uEEndpoint", "lix2.uEEndpoint",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UEEndpointAddress", HFILL }},
    { &hf_lix2_uEEndpoint_item,
      { "UEEndpointAddress", "lix2.UEEndpointAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_UEEndpointAddress_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_aMFID,
      { "aMFID", "lix2.aMFID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_hSMFURI,
      { "hSMFURI", "lix2.hSMFURI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_requestType,
      { "requestType", "lix2.requestType",
        FT_UINT32, BASE_DEC, VALS(lix2_FiveGSMRequestType_vals), 0,
        "FiveGSMRequestType", HFILL }},
    { &hf_lix2_rATType,
      { "rATType", "lix2.rATType",
        FT_UINT32, BASE_DEC, VALS(lix2_RATType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_sMPDUDNRequest,
      { "sMPDUDNRequest", "lix2.sMPDUDNRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_uEEPSPDNConnection,
      { "uEEPSPDNConnection", "lix2.uEEPSPDNConnection",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cause_01,
      { "cause", "lix2.cause",
        FT_STRING, BASE_NONE, NULL, 0,
        "SMFErrorCodes", HFILL }},
    { &hf_lix2_timeOfSessionEstablishment,
      { "timeOfSessionEstablishment", "lix2.timeOfSessionEstablishment",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_failedProcedureType_01,
      { "failedProcedureType", "lix2.failedProcedureType",
        FT_UINT32, BASE_DEC, VALS(lix2_SMFFailedProcedureType_vals), 0,
        "SMFFailedProcedureType", HFILL }},
    { &hf_lix2_failureCause_03,
      { "failureCause", "lix2.failureCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FiveGSMCause", HFILL }},
    { &hf_lix2_requestIndication,
      { "requestIndication", "lix2.requestIndication",
        FT_UINT32, BASE_DEC, VALS(lix2_RequestIndication_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_aTSSSContainer,
      { "aTSSSContainer", "lix2.aTSSSContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_accessInfo,
      { "accessInfo", "lix2.accessInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AccessInfo", HFILL }},
    { &hf_lix2_accessInfo_item,
      { "AccessInfo", "lix2.AccessInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_servingNetwork,
      { "servingNetwork", "lix2.servingNetwork_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMFServingNetwork", HFILL }},
    { &hf_lix2_oldPDUSessionID,
      { "oldPDUSessionID", "lix2.oldPDUSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionID", HFILL }},
    { &hf_lix2_mAUpgradeIndication,
      { "mAUpgradeIndication", "lix2.mAUpgradeIndication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "SMFMAUpgradeIndication", HFILL }},
    { &hf_lix2_ePSPDNCnxInfo,
      { "ePSPDNCnxInfo", "lix2.ePSPDNCnxInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "SMFEPSPDNCnxInfo", HFILL }},
    { &hf_lix2_mAAcceptedIndication,
      { "mAAcceptedIndication", "lix2.mAAcceptedIndication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "SMFMAAcceptedIndication", HFILL }},
    { &hf_lix2_pLMNID,
      { "pLMNID", "lix2.pLMNID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nID,
      { "nID", "lix2.nID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_establishmentStatus,
      { "establishmentStatus", "lix2.establishmentStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_EstablishmentStatus_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_aNTypeToReactivate,
      { "aNTypeToReactivate", "lix2.aNTypeToReactivate",
        FT_UINT32, BASE_DEC, VALS(lix2_AccessType_vals), 0,
        "AccessType", HFILL }},
    { &hf_lix2_payload,
      { "payload", "lix2.payload",
        FT_UINT32, BASE_DEC, VALS(lix2_UPFCCPDUPayload_vals), 0,
        "UPFCCPDUPayload", HFILL }},
    { &hf_lix2_qFI,
      { "qFI", "lix2.qFI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_uPFIPCC,
      { "uPFIPCC", "lix2.uPFIPCC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_lix2_uPFEthernetCC,
      { "uPFEthernetCC", "lix2.uPFEthernetCC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_lix2_uPFUnstructuredCC,
      { "uPFUnstructuredCC", "lix2.uPFUnstructuredCC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_lix2_gUAMI,
      { "gUAMI", "lix2.gUAMI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_gUMMEI,
      { "gUMMEI", "lix2.gUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_servingSystemMethod,
      { "servingSystemMethod", "lix2.servingSystemMethod",
        FT_UINT32, BASE_DEC, VALS(lix2_UDMServingSystemMethod_vals), 0,
        "UDMServingSystemMethod", HFILL }},
    { &hf_lix2_serviceID,
      { "serviceID", "lix2.serviceID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_oldPEI,
      { "oldPEI", "lix2.oldPEI",
        FT_UINT32, BASE_DEC, VALS(lix2_PEI_vals), 0,
        "PEI", HFILL }},
    { &hf_lix2_oldSUPI,
      { "oldSUPI", "lix2.oldSUPI",
        FT_UINT32, BASE_DEC, VALS(lix2_SUPI_vals), 0,
        "SUPI", HFILL }},
    { &hf_lix2_oldGPSI,
      { "oldGPSI", "lix2.oldGPSI",
        FT_UINT32, BASE_DEC, VALS(lix2_GPSI_vals), 0,
        "GPSI", HFILL }},
    { &hf_lix2_oldserviceID,
      { "oldserviceID", "lix2.oldserviceID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceID", HFILL }},
    { &hf_lix2_subscriberRecordChangeMethod,
      { "subscriberRecordChangeMethod", "lix2.subscriberRecordChangeMethod",
        FT_UINT32, BASE_DEC, VALS(lix2_UDMSubscriberRecordChangeMethod_vals), 0,
        "UDMSubscriberRecordChangeMethod", HFILL }},
    { &hf_lix2_cancelLocationMethod,
      { "cancelLocationMethod", "lix2.cancelLocationMethod",
        FT_UINT32, BASE_DEC, VALS(lix2_UDMCancelLocationMethod_vals), 0,
        "UDMCancelLocationMethod", HFILL }},
    { &hf_lix2_nSSAI,
      { "nSSAI", "lix2.nSSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cAGID,
      { "cAGID", "lix2.cAGID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CAGID", HFILL }},
    { &hf_lix2_cAGID_item,
      { "CAGID", "lix2.CAGID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_originatingSMSParty,
      { "originatingSMSParty", "lix2.originatingSMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMSParty", HFILL }},
    { &hf_lix2_terminatingSMSParty_02,
      { "terminatingSMSParty", "lix2.terminatingSMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMSParty", HFILL }},
    { &hf_lix2_direction,
      { "direction", "lix2.direction",
        FT_UINT32, BASE_DEC, VALS(lix2_Direction_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_linkTransferStatus,
      { "linkTransferStatus", "lix2.linkTransferStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSTransferStatus_vals), 0,
        "SMSTransferStatus", HFILL }},
    { &hf_lix2_otherMessage,
      { "otherMessage", "lix2.otherMessage",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "SMSOtherMessageIndication", HFILL }},
    { &hf_lix2_peerNFAddress,
      { "peerNFAddress", "lix2.peerNFAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSNFAddress_vals), 0,
        "SMSNFAddress", HFILL }},
    { &hf_lix2_peerNFType,
      { "peerNFType", "lix2.peerNFType",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSNFType_vals), 0,
        "SMSNFType", HFILL }},
    { &hf_lix2_sMSTPDUData,
      { "sMSTPDUData", "lix2.sMSTPDUData",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSTPDUData_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_messageType,
      { "messageType", "lix2.messageType",
        FT_UINT32, BASE_DEC, VALS(lix2_SMSMessageType_vals), 0,
        "SMSMessageType", HFILL }},
    { &hf_lix2_rPMessageReference,
      { "rPMessageReference", "lix2.rPMessageReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SMSRPMessageReference", HFILL }},
    { &hf_lix2_sMSAddress,
      { "sMSAddress", "lix2.sMSAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iPAddress,
      { "iPAddress", "lix2.iPAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_e164Number,
      { "e164Number", "lix2.e164Number",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sMSTPDU,
      { "sMSTPDU", "lix2.sMSTPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_truncatedSMSTPDU,
      { "truncatedSMSTPDU", "lix2.truncatedSMSTPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_transactionID,
      { "transactionID", "lix2.transactionID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_version,
      { "version", "lix2.version_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMSVersion", HFILL }},
    { &hf_lix2_dateTime,
      { "dateTime", "lix2.dateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_originatingMMSParty,
      { "originatingMMSParty", "lix2.originatingMMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMSParty", HFILL }},
    { &hf_lix2_terminatingMMSParty,
      { "terminatingMMSParty", "lix2.terminatingMMSParty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMSParty", HFILL }},
    { &hf_lix2_terminatingMMSParty_item,
      { "MMSParty", "lix2.MMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cCRecipients,
      { "cCRecipients", "lix2.cCRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMSParty", HFILL }},
    { &hf_lix2_cCRecipients_item,
      { "MMSParty", "lix2.MMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_bCCRecipients,
      { "bCCRecipients", "lix2.bCCRecipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMSParty", HFILL }},
    { &hf_lix2_bCCRecipients_item,
      { "MMSParty", "lix2.MMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_direction_01,
      { "direction", "lix2.direction",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSDirection_vals), 0,
        "MMSDirection", HFILL }},
    { &hf_lix2_subject,
      { "subject", "lix2.subject",
        FT_STRING, BASE_NONE, NULL, 0,
        "MMSSubject", HFILL }},
    { &hf_lix2_messageClass,
      { "messageClass", "lix2.messageClass",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSMessageClass_vals), 0,
        "MMSMessageClass", HFILL }},
    { &hf_lix2_expiry,
      { "expiry", "lix2.expiry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMSExpiry", HFILL }},
    { &hf_lix2_desiredDeliveryTime,
      { "desiredDeliveryTime", "lix2.desiredDeliveryTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_priority,
      { "priority", "lix2.priority",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSPriority_vals), 0,
        "MMSPriority", HFILL }},
    { &hf_lix2_senderVisibility,
      { "senderVisibility", "lix2.senderVisibility",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_deliveryReport,
      { "deliveryReport", "lix2.deliveryReport",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_readReport,
      { "readReport", "lix2.readReport",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_store,
      { "store", "lix2.store",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_state,
      { "state", "lix2.state",
        FT_UINT32, BASE_DEC, VALS(lix2_MMState_vals), 0,
        "MMState", HFILL }},
    { &hf_lix2_flags,
      { "flags", "lix2.flags_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMFlags", HFILL }},
    { &hf_lix2_replyCharging,
      { "replyCharging", "lix2.replyCharging",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSReplyCharging_vals), 0,
        "MMSReplyCharging", HFILL }},
    { &hf_lix2_applicID,
      { "applicID", "lix2.applicID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_replyApplicID,
      { "replyApplicID", "lix2.replyApplicID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_auxApplicInfo,
      { "auxApplicInfo", "lix2.auxApplicInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_contentClass,
      { "contentClass", "lix2.contentClass",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSContentClass_vals), 0,
        "MMSContentClass", HFILL }},
    { &hf_lix2_dRMContent,
      { "dRMContent", "lix2.dRMContent",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_adaptationAllowed,
      { "adaptationAllowed", "lix2.adaptationAllowed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMSAdaptation", HFILL }},
    { &hf_lix2_contentType,
      { "contentType", "lix2.contentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "MMSContentType", HFILL }},
    { &hf_lix2_responseStatus,
      { "responseStatus", "lix2.responseStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSResponseStatus_vals), 0,
        "MMSResponseStatus", HFILL }},
    { &hf_lix2_responseStatusText,
      { "responseStatusText", "lix2.responseStatusText",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_messageID,
      { "messageID", "lix2.messageID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_forwardCount,
      { "forwardCount", "lix2.forwardCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_previouslySentBy,
      { "previouslySentBy", "lix2.previouslySentBy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MMSPreviouslySentBy", HFILL }},
    { &hf_lix2_prevSentByDateTime,
      { "prevSentByDateTime", "lix2.prevSentByDateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_deliveryReportRequested,
      { "deliveryReportRequested", "lix2.deliveryReportRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_stored,
      { "stored", "lix2.stored",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_messageSize,
      { "messageSize", "lix2.messageSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_status,
      { "status", "lix2.status",
        FT_UINT32, BASE_DEC, VALS(lix2_MMStatus_vals), 0,
        "MMStatus", HFILL }},
    { &hf_lix2_reportAllowed,
      { "reportAllowed", "lix2.reportAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_retrieveStatus,
      { "retrieveStatus", "lix2.retrieveStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSRetrieveStatus_vals), 0,
        "MMSRetrieveStatus", HFILL }},
    { &hf_lix2_retrieveStatusText,
      { "retrieveStatusText", "lix2.retrieveStatusText",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_replaceID,
      { "replaceID", "lix2.replaceID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_contentType_01,
      { "contentType", "lix2.contentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_deliveryReportAllowed,
      { "deliveryReportAllowed", "lix2.deliveryReportAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_contentLocationReq,
      { "contentLocationReq", "lix2.contentLocationReq",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_contentLocationConf,
      { "contentLocationConf", "lix2.contentLocationConf",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_storeStatus,
      { "storeStatus", "lix2.storeStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSStoreStatus_vals), 0,
        "MMSStoreStatus", HFILL }},
    { &hf_lix2_storeStatusText,
      { "storeStatusText", "lix2.storeStatusText",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_contentLocationReq_01,
      { "contentLocationReq", "lix2.contentLocationReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_contentLocationReq_item,
      { "contentLocationReq item", "lix2.contentLocationReq_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_contentLocationConf_01,
      { "contentLocationConf", "lix2.contentLocationConf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_contentLocationConf_item,
      { "contentLocationConf item", "lix2.contentLocationConf_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_deleteResponseStatus,
      { "deleteResponseStatus", "lix2.deleteResponseStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSDeleteResponseStatus_vals), 0,
        "MMSDeleteResponseStatus", HFILL }},
    { &hf_lix2_deleteResponseText,
      { "deleteResponseText", "lix2.deleteResponseText",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_deleteResponseText_item,
      { "deleteResponseText item", "lix2.deleteResponseText_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_contentLocation,
      { "contentLocation", "lix2.contentLocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_mMessages,
      { "mMessages", "lix2.mMessages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMBoxDescription", HFILL }},
    { &hf_lix2_mMessages_item,
      { "MMBoxDescription", "lix2.MMBoxDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_contentLocationReq_02,
      { "contentLocationReq", "lix2.contentLocationReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_contentLocationReq_01", HFILL }},
    { &hf_lix2_contentLocationConf_02,
      { "contentLocationConf", "lix2.contentLocationConf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_contentLocationConf_01", HFILL }},
    { &hf_lix2_responseStatus_01,
      { "responseStatus", "lix2.responseStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSDeleteResponseStatus_vals), 0,
        "MMSDeleteResponseStatus", HFILL }},
    { &hf_lix2_mMSDateTime,
      { "mMSDateTime", "lix2.mMSDateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_forwardToOriginator,
      { "forwardToOriginator", "lix2.forwardToOriginator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_statusExtension,
      { "statusExtension", "lix2.statusExtension",
        FT_UINT32, BASE_DEC, VALS(lix2_MMStatusExtension_vals), 0,
        "MMStatusExtension", HFILL }},
    { &hf_lix2_statusText,
      { "statusText", "lix2.statusText",
        FT_STRING, BASE_NONE, NULL, 0,
        "MMStatusText", HFILL }},
    { &hf_lix2_originatingMMSParty_01,
      { "originatingMMSParty", "lix2.originatingMMSParty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMSParty", HFILL }},
    { &hf_lix2_originatingMMSParty_item,
      { "MMSParty", "lix2.MMSParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_readStatus,
      { "readStatus", "lix2.readStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSReadStatus_vals), 0,
        "MMSReadStatus", HFILL }},
    { &hf_lix2_readStatusText,
      { "readStatusText", "lix2.readStatusText",
        FT_STRING, BASE_NONE, NULL, 0,
        "MMSReadStatusText", HFILL }},
    { &hf_lix2_cancelID,
      { "cancelID", "lix2.cancelID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_state_01,
      { "state", "lix2.state",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMState", HFILL }},
    { &hf_lix2_state_item,
      { "MMState", "lix2.MMState",
        FT_UINT32, BASE_DEC, VALS(lix2_MMState_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_flags_01,
      { "flags", "lix2.flags",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMFlags", HFILL }},
    { &hf_lix2_flags_item,
      { "MMFlags", "lix2.MMFlags_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_start,
      { "start", "lix2.start",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_limit,
      { "limit", "lix2.limit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_attributes,
      { "attributes", "lix2.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_attributes_item,
      { "attributes item", "lix2.attributes_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_totals,
      { "totals", "lix2.totals",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_quotas,
      { "quotas", "lix2.quotas_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMSQuota", HFILL }},
    { &hf_lix2_attributes_01,
      { "attributes", "lix2.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_attributes_01", HFILL }},
    { &hf_lix2_mMSTotals,
      { "mMSTotals", "lix2.mMSTotals",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_mMSQuotas,
      { "mMSQuotas", "lix2.mMSQuotas",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_deliveryTime,
      { "deliveryTime", "lix2.deliveryTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_previouslySentByDateTime,
      { "previouslySentByDateTime", "lix2.previouslySentByDateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_mMSContent,
      { "mMSContent", "lix2.mMSContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_lix2_allowed,
      { "allowed", "lix2.allowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_overriden,
      { "overriden", "lix2.overriden",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_reference,
      { "reference", "lix2.reference",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_parameter,
      { "parameter", "lix2.parameter",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_value,
      { "value", "lix2.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_expiryPeriod,
      { "expiryPeriod", "lix2.expiryPeriod",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_periodFormat,
      { "periodFormat", "lix2.periodFormat",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSPeriodFormat_vals), 0,
        "MMSPeriodFormat", HFILL }},
    { &hf_lix2_length,
      { "length", "lix2.length",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_flag,
      { "flag", "lix2.flag",
        FT_UINT32, BASE_DEC, VALS(lix2_MMStateFlag_vals), 0,
        "MMStateFlag", HFILL }},
    { &hf_lix2_flagString,
      { "flagString", "lix2.flagString",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_mMSPartyIDs,
      { "mMSPartyIDs", "lix2.mMSPartyIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MMSPartyID", HFILL }},
    { &hf_lix2_mMSPartyIDs_item,
      { "MMSPartyID", "lix2.MMSPartyID",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSPartyID_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_nonLocalID,
      { "nonLocalID", "lix2.nonLocalID",
        FT_UINT32, BASE_DEC, VALS(lix2_NonLocalID_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_emailAddress,
      { "emailAddress", "lix2.emailAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iMPU,
      { "iMPU", "lix2.iMPU",
        FT_UINT32, BASE_DEC, VALS(lix2_IMPU_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_iMPI,
      { "iMPI", "lix2.iMPI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_previouslySentByParty,
      { "previouslySentByParty", "lix2.previouslySentByParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MMSParty", HFILL }},
    { &hf_lix2_sequenceNumber,
      { "sequenceNumber", "lix2.sequenceNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_previousSendDateTime,
      { "previousSendDateTime", "lix2.previousSendDateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_MMSPreviouslySentBy_item,
      { "MMSPreviouslySent", "lix2.MMSPreviouslySent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_quota,
      { "quota", "lix2.quota",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_quotaUnit,
      { "quotaUnit", "lix2.quotaUnit",
        FT_UINT32, BASE_DEC, VALS(lix2_MMSQuotaUnit_vals), 0,
        "MMSQuotaUnit", HFILL }},
    { &hf_lix2_majorVersion,
      { "majorVersion", "lix2.majorVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_minorVersion,
      { "minorVersion", "lix2.minorVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_pTCTargetInformation,
      { "pTCTargetInformation", "lix2.pTCTargetInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCServerURI,
      { "pTCServerURI", "lix2.pTCServerURI",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pTCRegistrationRequest,
      { "pTCRegistrationRequest", "lix2.pTCRegistrationRequest",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCRegistrationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCRegistrationOutcome,
      { "pTCRegistrationOutcome", "lix2.pTCRegistrationOutcome",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCRegistrationOutcome_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCDirection,
      { "pTCDirection", "lix2.pTCDirection",
        FT_UINT32, BASE_DEC, VALS(lix2_Direction_vals), 0,
        "Direction", HFILL }},
    { &hf_lix2_pTCSessionInfo,
      { "pTCSessionInfo", "lix2.pTCSessionInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCOriginatingID,
      { "pTCOriginatingID", "lix2.pTCOriginatingID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCParticipants,
      { "pTCParticipants", "lix2.pTCParticipants",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCParticipants_item,
      { "PTCTargetInformation", "lix2.PTCTargetInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCParticipantPresenceStatus,
      { "pTCParticipantPresenceStatus", "lix2.pTCParticipantPresenceStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MultipleParticipantPresenceStatus", HFILL }},
    { &hf_lix2_pTCBearerCapability,
      { "pTCBearerCapability", "lix2.pTCBearerCapability",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pTCHost,
      { "pTCHost", "lix2.pTCHost_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCAbandonCause,
      { "pTCAbandonCause", "lix2.pTCAbandonCause",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_pTCSessionEndCause,
      { "pTCSessionEndCause", "lix2.pTCSessionEndCause",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCSessionEndCause_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_preEstSessionID,
      { "preEstSessionID", "lix2.preEstSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCSessionInfo", HFILL }},
    { &hf_lix2_pTCMediaStreamAvail,
      { "pTCMediaStreamAvail", "lix2.pTCMediaStreamAvail",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_rTPSetting,
      { "rTPSetting", "lix2.rTPSetting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCMediaCapability,
      { "pTCMediaCapability", "lix2.pTCMediaCapability",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pTCPreEstSessionID,
      { "pTCPreEstSessionID", "lix2.pTCPreEstSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCSessionInfo", HFILL }},
    { &hf_lix2_pTCPreEstStatus,
      { "pTCPreEstStatus", "lix2.pTCPreEstStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCPreEstStatus_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCFailureCode,
      { "pTCFailureCode", "lix2.pTCFailureCode",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCFailureCode_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCIPAPartyID,
      { "pTCIPAPartyID", "lix2.pTCIPAPartyID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCIPADirection,
      { "pTCIPADirection", "lix2.pTCIPADirection",
        FT_UINT32, BASE_DEC, VALS(lix2_Direction_vals), 0,
        "Direction", HFILL }},
    { &hf_lix2_pTCPartyDrop_01,
      { "pTCPartyDrop", "lix2.pTCPartyDrop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCParticipantPresenceStatus_01,
      { "pTCParticipantPresenceStatus", "lix2.pTCParticipantPresenceStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCHoldID,
      { "pTCHoldID", "lix2.pTCHoldID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCHoldID_item,
      { "PTCTargetInformation", "lix2.PTCTargetInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCHoldRetrieveInd,
      { "pTCHoldRetrieveInd", "lix2.pTCHoldRetrieveInd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_pTCIDList,
      { "pTCIDList", "lix2.pTCIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCIDList_item,
      { "PTCTargetInformation", "lix2.PTCTargetInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCGroupAuthRule,
      { "pTCGroupAuthRule", "lix2.pTCGroupAuthRule",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCGroupAuthRule_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCGroupAdSender,
      { "pTCGroupAdSender", "lix2.pTCGroupAdSender_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCGroupNickname,
      { "pTCGroupNickname", "lix2.pTCGroupNickname",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pTCSessioninfo,
      { "pTCSessioninfo", "lix2.pTCSessioninfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCFloorActivity,
      { "pTCFloorActivity", "lix2.pTCFloorActivity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PTCFloorActivity", HFILL }},
    { &hf_lix2_pTCFloorActivity_item,
      { "PTCFloorActivity", "lix2.PTCFloorActivity",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCFloorActivity_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCFloorSpeakerID,
      { "pTCFloorSpeakerID", "lix2.pTCFloorSpeakerID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCMaxTBTime,
      { "pTCMaxTBTime", "lix2.pTCMaxTBTime",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_pTCQueuedFloorControl,
      { "pTCQueuedFloorControl", "lix2.pTCQueuedFloorControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_pTCQueuedPosition,
      { "pTCQueuedPosition", "lix2.pTCQueuedPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_pTCTalkBurstPriority,
      { "pTCTalkBurstPriority", "lix2.pTCTalkBurstPriority",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCTBPriorityLevel_vals), 0,
        "PTCTBPriorityLevel", HFILL }},
    { &hf_lix2_pTCTalkBurstReason,
      { "pTCTalkBurstReason", "lix2.pTCTalkBurstReason",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCTBReasonCode_vals), 0,
        "PTCTBReasonCode", HFILL }},
    { &hf_lix2_pTCTargetPresenceStatus,
      { "pTCTargetPresenceStatus", "lix2.pTCTargetPresenceStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCParticipantPresenceStatus", HFILL }},
    { &hf_lix2_pTCListManagementType,
      { "pTCListManagementType", "lix2.pTCListManagementType",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCListManagementType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCListManagementAction,
      { "pTCListManagementAction", "lix2.pTCListManagementAction",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCListManagementAction_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCListManagementFailure,
      { "pTCListManagementFailure", "lix2.pTCListManagementFailure",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCListManagementFailure_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCContactID,
      { "pTCContactID", "lix2.pTCContactID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_pTCIDList_01,
      { "pTCIDList", "lix2.pTCIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PTCIDList", HFILL }},
    { &hf_lix2_pTCIDList_item_01,
      { "PTCIDList", "lix2.PTCIDList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCAccessPolicyType,
      { "pTCAccessPolicyType", "lix2.pTCAccessPolicyType",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCAccessPolicyType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCUserAccessPolicy,
      { "pTCUserAccessPolicy", "lix2.pTCUserAccessPolicy",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCUserAccessPolicy_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_pTCAccessPolicyFailure,
      { "pTCAccessPolicyFailure", "lix2.pTCAccessPolicyFailure",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCAccessPolicyFailure_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_identifiers,
      { "identifiers", "lix2.identifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers", HFILL }},
    { &hf_lix2_identifiers_item,
      { "PTCIdentifiers", "lix2.PTCIdentifiers",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCIdentifiers_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_mCPTTID,
      { "mCPTTID", "lix2.mCPTTID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_instanceIdentifierURN,
      { "instanceIdentifierURN", "lix2.instanceIdentifierURN",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pTCChatGroupID,
      { "pTCChatGroupID", "lix2.pTCChatGroupID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCSessionURI,
      { "pTCSessionURI", "lix2.pTCSessionURI",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pTCSessionType,
      { "pTCSessionType", "lix2.pTCSessionType",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCSessionType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_MultipleParticipantPresenceStatus_item,
      { "PTCParticipantPresenceStatus", "lix2.PTCParticipantPresenceStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_presenceID,
      { "presenceID", "lix2.presenceID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_presenceType,
      { "presenceType", "lix2.presenceType",
        FT_UINT32, BASE_DEC, VALS(lix2_PTCPresenceType_vals), 0,
        "PTCPresenceType", HFILL }},
    { &hf_lix2_presenceStatus,
      { "presenceStatus", "lix2.presenceStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_portNumber,
      { "portNumber", "lix2.portNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pTCPartyID,
      { "pTCPartyID", "lix2.pTCPartyID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCTargetInformation", HFILL }},
    { &hf_lix2_groupIdentity,
      { "groupIdentity", "lix2.groupIdentity",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_sourceIPAddress,
      { "sourceIPAddress", "lix2.sourceIPAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_IPAddress_vals), 0,
        "IPAddress", HFILL }},
    { &hf_lix2_destinationIPAddress,
      { "destinationIPAddress", "lix2.destinationIPAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_IPAddress_vals), 0,
        "IPAddress", HFILL }},
    { &hf_lix2_nextLayerProtocol,
      { "nextLayerProtocol", "lix2.nextLayerProtocol",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iPv6flowLabel,
      { "iPv6flowLabel", "lix2.iPv6flowLabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_packetSize,
      { "packetSize", "lix2.packetSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_pDSRSummaryTrigger,
      { "pDSRSummaryTrigger", "lix2.pDSRSummaryTrigger",
        FT_UINT32, BASE_DEC, VALS(lix2_PDSRSummaryTrigger_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_firstPacketTimestamp,
      { "firstPacketTimestamp", "lix2.firstPacketTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_lastPacketTimestamp,
      { "lastPacketTimestamp", "lix2.lastPacketTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_packetCount,
      { "packetCount", "lix2.packetCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_byteCount,
      { "byteCount", "lix2.byteCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_gUTI_01,
      { "gUTI", "lix2.gUTI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tAIList,
      { "tAIList", "lix2.tAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_attachType,
      { "attachType", "lix2.attachType",
        FT_UINT32, BASE_DEC, VALS(lix2_EPSAttachType_vals), 0,
        "EPSAttachType", HFILL }},
    { &hf_lix2_attachResult,
      { "attachResult", "lix2.attachResult",
        FT_UINT32, BASE_DEC, VALS(lix2_EPSAttachResult_vals), 0,
        "EPSAttachResult", HFILL }},
    { &hf_lix2_ePSTAIList,
      { "ePSTAIList", "lix2.ePSTAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TAIList", HFILL }},
    { &hf_lix2_sMSServiceStatus,
      { "sMSServiceStatus", "lix2.sMSServiceStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_EPSSMSServiceStatus_vals), 0,
        "EPSSMSServiceStatus", HFILL }},
    { &hf_lix2_oldGUTI_01,
      { "oldGUTI", "lix2.oldGUTI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GUTI", HFILL }},
    { &hf_lix2_detachDirection,
      { "detachDirection", "lix2.detachDirection",
        FT_UINT32, BASE_DEC, VALS(lix2_MMEDirection_vals), 0,
        "MMEDirection", HFILL }},
    { &hf_lix2_detachType,
      { "detachType", "lix2.detachType",
        FT_UINT32, BASE_DEC, VALS(lix2_EPSDetachType_vals), 0,
        "EPSDetachType", HFILL }},
    { &hf_lix2_cause_02,
      { "cause", "lix2.cause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EMMCause", HFILL }},
    { &hf_lix2_failedProcedureType_02,
      { "failedProcedureType", "lix2.failedProcedureType",
        FT_UINT32, BASE_DEC, VALS(lix2_MMEFailedProcedureType_vals), 0,
        "MMEFailedProcedureType", HFILL }},
    { &hf_lix2_failureCause_04,
      { "failureCause", "lix2.failureCause",
        FT_UINT32, BASE_DEC, VALS(lix2_MMEFailureCause_vals), 0,
        "MMEFailureCause", HFILL }},
    { &hf_lix2_eMMCause,
      { "eMMCause", "lix2.eMMCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eSMCause,
      { "eSMCause", "lix2.eSMCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_notificationType,
      { "notificationType", "lix2.notificationType",
        FT_UINT32, BASE_DEC, VALS(lix2_LINotificationType_vals), 0,
        "LINotificationType", HFILL }},
    { &hf_lix2_appliedTargetID,
      { "appliedTargetID", "lix2.appliedTargetID",
        FT_UINT32, BASE_DEC, VALS(lix2_TargetIdentifier_vals), 0,
        "TargetIdentifier", HFILL }},
    { &hf_lix2_appliedDeliveryInformation,
      { "appliedDeliveryInformation", "lix2.appliedDeliveryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_LIAppliedDeliveryInformation", HFILL }},
    { &hf_lix2_appliedDeliveryInformation_item,
      { "LIAppliedDeliveryInformation", "lix2.LIAppliedDeliveryInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_appliedStartTime,
      { "appliedStartTime", "lix2.appliedStartTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_appliedEndTime,
      { "appliedEndTime", "lix2.appliedEndTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_hI2DeliveryIPAddress,
      { "hI2DeliveryIPAddress", "lix2.hI2DeliveryIPAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_IPAddress_vals), 0,
        "IPAddress", HFILL }},
    { &hf_lix2_hI2DeliveryPortNumber,
      { "hI2DeliveryPortNumber", "lix2.hI2DeliveryPortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PortNumber", HFILL }},
    { &hf_lix2_hI3DeliveryIPAddress,
      { "hI3DeliveryIPAddress", "lix2.hI3DeliveryIPAddress",
        FT_UINT32, BASE_DEC, VALS(lix2_IPAddress_vals), 0,
        "IPAddress", HFILL }},
    { &hf_lix2_hI3DeliveryPortNumber,
      { "hI3DeliveryPortNumber", "lix2.hI3DeliveryPortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PortNumber", HFILL }},
    { &hf_lix2_MDFCellSiteReport_item,
      { "CellInformation", "lix2.CellInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eMMRegStatus,
      { "eMMRegStatus", "lix2.eMMRegStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_EMMRegStatus_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_fiveGMMStatus,
      { "fiveGMMStatus", "lix2.fiveGMMStatus",
        FT_UINT32, BASE_DEC, VALS(lix2_FiveGMMStatus_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_fiveGGUTI,
      { "fiveGGUTI", "lix2.fiveGGUTI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mCC,
      { "mCC", "lix2.mCC",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mNC,
      { "mNC", "lix2.mNC",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_fiveGTMSI,
      { "fiveGTMSI", "lix2.fiveGTMSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tEID,
      { "tEID", "lix2.tEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_lix2_iPv4Address,
      { "iPv4Address", "lix2.iPv4Address",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iPv6Address,
      { "iPv6Address", "lix2.iPv6Address",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nAI,
      { "nAI", "lix2.nAI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEID,
      { "mMEID", "lix2.mMEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEGroupID,
      { "mMEGroupID", "lix2.mMEGroupID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMECode,
      { "mMECode", "lix2.mMECode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mTMSI,
      { "mTMSI", "lix2.mTMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TMSI", HFILL }},
    { &hf_lix2_sIPURI,
      { "sIPURI", "lix2.sIPURI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tELURI,
      { "tELURI", "lix2.tELURI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEGI,
      { "mMEGI", "lix2.mMEGI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_mMEC,
      { "mMEC", "lix2.mMEC",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_NSSAI_item,
      { "SNSSAI", "lix2.SNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iMEISV,
      { "iMEISV", "lix2.iMEISV",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_RejectedNSSAI_item,
      { "RejectedSNSSAI", "lix2.RejectedSNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_causeValue,
      { "causeValue", "lix2.causeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RejectedSliceCauseValue", HFILL }},
    { &hf_lix2_allowedNSSAI,
      { "allowedNSSAI", "lix2.allowedNSSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NSSAI", HFILL }},
    { &hf_lix2_configuredNSSAI,
      { "configuredNSSAI", "lix2.configuredNSSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NSSAI", HFILL }},
    { &hf_lix2_rejectedNSSAI,
      { "rejectedNSSAI", "lix2.rejectedNSSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sliceServiceType,
      { "sliceServiceType", "lix2.sliceServiceType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_lix2_sliceDifferentiator,
      { "sliceDifferentiator", "lix2.sliceDifferentiator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_lix2_routingIndicator,
      { "routingIndicator", "lix2.routingIndicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_protectionSchemeID,
      { "protectionSchemeID", "lix2.protectionSchemeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_homeNetworkPublicKeyID,
      { "homeNetworkPublicKeyID", "lix2.homeNetworkPublicKeyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_schemeOutput,
      { "schemeOutput", "lix2.schemeOutput",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_ethernetAddress,
      { "ethernetAddress", "lix2.ethernetAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MACAddress", HFILL }},
    { &hf_lix2_locationInfo,
      { "locationInfo", "lix2.locationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_positioningInfo,
      { "positioningInfo", "lix2.positioningInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_locationPresenceReport,
      { "locationPresenceReport", "lix2.locationPresenceReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_ePSLocationInfo,
      { "ePSLocationInfo", "lix2.ePSLocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_geographicalCoordinates,
      { "geographicalCoordinates", "lix2.geographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_azimuth,
      { "azimuth", "lix2.azimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_lix2_operatorSpecificInformation,
      { "operatorSpecificInformation", "lix2.operatorSpecificInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_userLocation,
      { "userLocation", "lix2.userLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_currentLoc,
      { "currentLoc", "lix2.currentLoc",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lix2_geoInfo,
      { "geoInfo", "lix2.geoInfo",
        FT_UINT32, BASE_DEC, VALS(lix2_GeographicArea_vals), 0,
        "GeographicArea", HFILL }},
    { &hf_lix2_timeZone,
      { "timeZone", "lix2.timeZone",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_additionalCellIDs,
      { "additionalCellIDs", "lix2.additionalCellIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CellInformation", HFILL }},
    { &hf_lix2_additionalCellIDs_item,
      { "CellInformation", "lix2.CellInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eUTRALocation,
      { "eUTRALocation", "lix2.eUTRALocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nRLocation,
      { "nRLocation", "lix2.nRLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_n3GALocation,
      { "n3GALocation", "lix2.n3GALocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tAI,
      { "tAI", "lix2.tAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eCGI,
      { "eCGI", "lix2.eCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_ageOfLocationInfo,
      { "ageOfLocationInfo", "lix2.ageOfLocationInfo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_uELocationTimestamp,
      { "uELocationTimestamp", "lix2.uELocationTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_geographicalInformation,
      { "geographicalInformation", "lix2.geographicalInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_geodeticInformation,
      { "geodeticInformation", "lix2.geodeticInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_globalNGENbID,
      { "globalNGENbID", "lix2.globalNGENbID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalRANNodeID", HFILL }},
    { &hf_lix2_cellSiteInformation,
      { "cellSiteInformation", "lix2.cellSiteInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_globalENbID,
      { "globalENbID", "lix2.globalENbID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalRANNodeID", HFILL }},
    { &hf_lix2_nCGI,
      { "nCGI", "lix2.nCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_globalGNbID,
      { "globalGNbID", "lix2.globalGNbID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalRANNodeID", HFILL }},
    { &hf_lix2_n3IWFID,
      { "n3IWFID", "lix2.n3IWFID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "N3IWFIDNGAP", HFILL }},
    { &hf_lix2_uEIPAddr,
      { "uEIPAddr", "lix2.uEIPAddr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddr", HFILL }},
    { &hf_lix2_portNumber_01,
      { "portNumber", "lix2.portNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lix2_tNAPID,
      { "tNAPID", "lix2.tNAPID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tWAPID,
      { "tWAPID", "lix2.tWAPID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_hFCNodeID,
      { "hFCNodeID", "lix2.hFCNodeID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_gLI,
      { "gLI", "lix2.gLI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_w5GBANLineType,
      { "w5GBANLineType", "lix2.w5GBANLineType",
        FT_UINT32, BASE_DEC, VALS(lix2_W5GBANLineType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_gCI,
      { "gCI", "lix2.gCI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_iPv4Addr,
      { "iPv4Addr", "lix2.iPv4Addr",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IPv4Address", HFILL }},
    { &hf_lix2_iPv6Addr,
      { "iPv6Addr", "lix2.iPv6Addr",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IPv6Address", HFILL }},
    { &hf_lix2_aNNodeID,
      { "aNNodeID", "lix2.aNNodeID",
        FT_UINT32, BASE_DEC, VALS(lix2_ANNodeID_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_n3IWFID_01,
      { "n3IWFID", "lix2.n3IWFID",
        FT_STRING, BASE_NONE, NULL, 0,
        "N3IWFIDSBI", HFILL }},
    { &hf_lix2_gNbID,
      { "gNbID", "lix2.gNbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nGENbID,
      { "nGENbID", "lix2.nGENbID",
        FT_UINT32, BASE_DEC, VALS(lix2_NGENbID_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_eNbID,
      { "eNbID", "lix2.eNbID",
        FT_UINT32, BASE_DEC, VALS(lix2_ENbID_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_wAGFID,
      { "wAGFID", "lix2.wAGFID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tNGFID,
      { "tNGFID", "lix2.tNGFID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_tAC,
      { "tAC", "lix2.tAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_lAI,
      { "lAI", "lix2.lAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cellID,
      { "cellID", "lix2.cellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_lAC,
      { "lAC", "lix2.lAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sAC,
      { "sAC", "lix2.sAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eUTRACellID,
      { "eUTRACellID", "lix2.eUTRACellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_TAIList_item,
      { "TAI", "lix2.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nRCellID,
      { "nRCellID", "lix2.nRCellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_rANCGI,
      { "rANCGI", "lix2.rANCGI",
        FT_UINT32, BASE_DEC, VALS(lix2_RANCGI_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_cellSiteinformation,
      { "cellSiteinformation", "lix2.cellSiteinformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_timeOfLocation,
      { "timeOfLocation", "lix2.timeOfLocation",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "Timestamp", HFILL }},
    { &hf_lix2_sSID,
      { "sSID", "lix2.sSID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_bSSID,
      { "bSSID", "lix2.bSSID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_civicAddress,
      { "civicAddress", "lix2.civicAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CivicAddressBytes", HFILL }},
    { &hf_lix2_macroNGENbID,
      { "macroNGENbID", "lix2.macroNGENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_lix2_shortMacroNGENbID,
      { "shortMacroNGENbID", "lix2.shortMacroNGENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_lix2_longMacroNGENbID,
      { "longMacroNGENbID", "lix2.longMacroNGENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_lix2_macroENbID,
      { "macroENbID", "lix2.macroENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_lix2_homeENbID,
      { "homeENbID", "lix2.homeENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_lix2_shortMacroENbID,
      { "shortMacroENbID", "lix2.shortMacroENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_lix2_longMacroENbID,
      { "longMacroENbID", "lix2.longMacroENbID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_lix2_positionInfo,
      { "positionInfo", "lix2.positionInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationData", HFILL }},
    { &hf_lix2_rawMLPResponse,
      { "rawMLPResponse", "lix2.rawMLPResponse",
        FT_UINT32, BASE_DEC, VALS(lix2_RawMLPResponse_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_mLPPositionData,
      { "mLPPositionData", "lix2.mLPPositionData",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_mLPErrorCode,
      { "mLPErrorCode", "lix2.mLPErrorCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_699", HFILL }},
    { &hf_lix2_locationEstimate,
      { "locationEstimate", "lix2.locationEstimate",
        FT_UINT32, BASE_DEC, VALS(lix2_GeographicArea_vals), 0,
        "GeographicArea", HFILL }},
    { &hf_lix2_accuracyFulfilmentIndicator,
      { "accuracyFulfilmentIndicator", "lix2.accuracyFulfilmentIndicator",
        FT_UINT32, BASE_DEC, VALS(lix2_AccuracyFulfilmentIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_ageOfLocationEstimate,
      { "ageOfLocationEstimate", "lix2.ageOfLocationEstimate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_velocityEstimate,
      { "velocityEstimate", "lix2.velocityEstimate",
        FT_UINT32, BASE_DEC, VALS(lix2_VelocityEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_civicAddress_01,
      { "civicAddress", "lix2.civicAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_positioningDataList,
      { "positioningDataList", "lix2.positioningDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_PositioningMethodAndUsage", HFILL }},
    { &hf_lix2_positioningDataList_item,
      { "PositioningMethodAndUsage", "lix2.PositioningMethodAndUsage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_gNSSPositioningDataList,
      { "gNSSPositioningDataList", "lix2.gNSSPositioningDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_GNSSPositioningMethodAndUsage", HFILL }},
    { &hf_lix2_gNSSPositioningDataList_item,
      { "GNSSPositioningMethodAndUsage", "lix2.GNSSPositioningMethodAndUsage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_altitude,
      { "altitude", "lix2.altitude",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_barometricPressure,
      { "barometricPressure", "lix2.barometricPressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_locationData,
      { "locationData", "lix2.locationData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cGI,
      { "cGI", "lix2.cGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_sAI,
      { "sAI", "lix2.sAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eSMLCCellInfo,
      { "eSMLCCellInfo", "lix2.eSMLCCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cellPortionID,
      { "cellPortionID", "lix2.cellPortionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_type,
      { "type", "lix2.type",
        FT_UINT32, BASE_DEC, VALS(lix2_AMFEventType_vals), 0,
        "AMFEventType", HFILL }},
    { &hf_lix2_timestamp,
      { "timestamp", "lix2.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_areaList,
      { "areaList", "lix2.areaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AMFEventArea", HFILL }},
    { &hf_lix2_areaList_item,
      { "AMFEventArea", "lix2.AMFEventArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_accessTypes,
      { "accessTypes", "lix2.accessTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AccessType", HFILL }},
    { &hf_lix2_accessTypes_item,
      { "AccessType", "lix2.AccessType",
        FT_UINT32, BASE_DEC, VALS(lix2_AccessType_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_rMInfoList,
      { "rMInfoList", "lix2.rMInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_RMInfo", HFILL }},
    { &hf_lix2_rMInfoList_item,
      { "RMInfo", "lix2.RMInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_cMInfoList,
      { "cMInfoList", "lix2.cMInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_CMInfo", HFILL }},
    { &hf_lix2_cMInfoList_item,
      { "CMInfo", "lix2.CMInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_reachability,
      { "reachability", "lix2.reachability",
        FT_UINT32, BASE_DEC, VALS(lix2_UEReachability_vals), 0,
        "UEReachability", HFILL }},
    { &hf_lix2_location_02,
      { "location", "lix2.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserLocation", HFILL }},
    { &hf_lix2_presenceInfo,
      { "presenceInfo", "lix2.presenceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_lADNInfo,
      { "lADNInfo", "lix2.lADNInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_presenceState,
      { "presenceState", "lix2.presenceState",
        FT_UINT32, BASE_DEC, VALS(lix2_PresenceState_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_trackingAreaList,
      { "trackingAreaList", "lix2.trackingAreaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TAI", HFILL }},
    { &hf_lix2_trackingAreaList_item,
      { "TAI", "lix2.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_eCGIList,
      { "eCGIList", "lix2.eCGIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ECGI", HFILL }},
    { &hf_lix2_eCGIList_item,
      { "ECGI", "lix2.ECGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_nCGIList,
      { "nCGIList", "lix2.nCGIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_NCGI", HFILL }},
    { &hf_lix2_nCGIList_item,
      { "NCGI", "lix2.NCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_globalRANNodeIDList,
      { "globalRANNodeIDList", "lix2.globalRANNodeIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_GlobalRANNodeID", HFILL }},
    { &hf_lix2_globalRANNodeIDList_item,
      { "GlobalRANNodeID", "lix2.GlobalRANNodeID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_globalENbIDList,
      { "globalENbIDList", "lix2.globalENbIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_GlobalRANNodeID", HFILL }},
    { &hf_lix2_globalENbIDList_item,
      { "GlobalRANNodeID", "lix2.GlobalRANNodeID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_lADN,
      { "lADN", "lix2.lADN",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_presence,
      { "presence", "lix2.presence",
        FT_UINT32, BASE_DEC, VALS(lix2_PresenceState_vals), 0,
        "PresenceState", HFILL }},
    { &hf_lix2_rMState,
      { "rMState", "lix2.rMState",
        FT_UINT32, BASE_DEC, VALS(lix2_RMState_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_cMState,
      { "cMState", "lix2.cMState",
        FT_UINT32, BASE_DEC, VALS(lix2_CMState_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_point,
      { "point", "lix2.point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pointUncertaintyCircle,
      { "pointUncertaintyCircle", "lix2.pointUncertaintyCircle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pointUncertaintyEllipse,
      { "pointUncertaintyEllipse", "lix2.pointUncertaintyEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_polygon,
      { "polygon", "lix2.polygon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pointAltitude,
      { "pointAltitude", "lix2.pointAltitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pointAltitudeUncertainty,
      { "pointAltitudeUncertainty", "lix2.pointAltitudeUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_ellipsoidArc,
      { "ellipsoidArc", "lix2.ellipsoidArc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_horVelocity,
      { "horVelocity", "lix2.horVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HorizontalVelocity", HFILL }},
    { &hf_lix2_horWithVertVelocity,
      { "horWithVertVelocity", "lix2.horWithVertVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HorizontalWithVerticalVelocity", HFILL }},
    { &hf_lix2_horVelocityWithUncertainty,
      { "horVelocityWithUncertainty", "lix2.horVelocityWithUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HorizontalVelocityWithUncertainty", HFILL }},
    { &hf_lix2_horWithVertVelocityAndUncertainty,
      { "horWithVertVelocityAndUncertainty", "lix2.horWithVertVelocityAndUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HorizontalWithVerticalVelocityAndUncertainty", HFILL }},
    { &hf_lix2_country,
      { "country", "lix2.country",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_a1,
      { "a1", "lix2.a1",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_a2,
      { "a2", "lix2.a2",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_a3,
      { "a3", "lix2.a3",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_a4,
      { "a4", "lix2.a4",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_a5,
      { "a5", "lix2.a5",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_a6,
      { "a6", "lix2.a6",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_prd,
      { "prd", "lix2.prd",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pod,
      { "pod", "lix2.pod",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_sts,
      { "sts", "lix2.sts",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_hno,
      { "hno", "lix2.hno",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_hns,
      { "hns", "lix2.hns",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_lmk,
      { "lmk", "lix2.lmk",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_loc,
      { "loc", "lix2.loc",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_nam,
      { "nam", "lix2.nam",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pc,
      { "pc", "lix2.pc",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_bld,
      { "bld", "lix2.bld",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_unit,
      { "unit", "lix2.unit",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_flr,
      { "flr", "lix2.flr",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_room,
      { "room", "lix2.room",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_plc,
      { "plc", "lix2.plc",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pcn,
      { "pcn", "lix2.pcn",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pobox,
      { "pobox", "lix2.pobox",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_addcode,
      { "addcode", "lix2.addcode",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_seat,
      { "seat", "lix2.seat",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_rd,
      { "rd", "lix2.rd",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_rdsec,
      { "rdsec", "lix2.rdsec",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_rdbr,
      { "rdbr", "lix2.rdbr",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_rdsubbr,
      { "rdsubbr", "lix2.rdsubbr",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_prm,
      { "prm", "lix2.prm",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_pom,
      { "pom", "lix2.pom",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_method,
      { "method", "lix2.method",
        FT_UINT32, BASE_DEC, VALS(lix2_PositioningMethod_vals), 0,
        "PositioningMethod", HFILL }},
    { &hf_lix2_mode,
      { "mode", "lix2.mode",
        FT_UINT32, BASE_DEC, VALS(lix2_PositioningMode_vals), 0,
        "PositioningMode", HFILL }},
    { &hf_lix2_usage,
      { "usage", "lix2.usage",
        FT_UINT32, BASE_DEC, VALS(lix2_Usage_vals), 0,
        NULL, HFILL }},
    { &hf_lix2_methodCode,
      { "methodCode", "lix2.methodCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_gNSS,
      { "gNSS", "lix2.gNSS",
        FT_UINT32, BASE_DEC, VALS(lix2_GNSSID_vals), 0,
        "GNSSID", HFILL }},
    { &hf_lix2_uncertainty,
      { "uncertainty", "lix2.uncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_uncertainty_01,
      { "uncertainty", "lix2.uncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UncertaintyEllipse", HFILL }},
    { &hf_lix2_confidence,
      { "confidence", "lix2.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_pointList,
      { "pointList", "lix2.pointList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_3_15_OF_GeographicalCoordinates", HFILL }},
    { &hf_lix2_pointList_item,
      { "GeographicalCoordinates", "lix2.GeographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_point_01,
      { "point", "lix2.point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalCoordinates", HFILL }},
    { &hf_lix2_uncertaintyEllipse,
      { "uncertaintyEllipse", "lix2.uncertaintyEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_uncertaintyAltitude,
      { "uncertaintyAltitude", "lix2.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty", HFILL }},
    { &hf_lix2_innerRadius,
      { "innerRadius", "lix2.innerRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lix2_uncertaintyRadius,
      { "uncertaintyRadius", "lix2.uncertaintyRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty", HFILL }},
    { &hf_lix2_offsetAngle,
      { "offsetAngle", "lix2.offsetAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_lix2_includedAngle,
      { "includedAngle", "lix2.includedAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_lix2_latitude,
      { "latitude", "lix2.latitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_longitude,
      { "longitude", "lix2.longitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_lix2_mapDatumInformation,
      { "mapDatumInformation", "lix2.mapDatumInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "OGCURN", HFILL }},
    { &hf_lix2_semiMajor,
      { "semiMajor", "lix2.semiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty", HFILL }},
    { &hf_lix2_semiMinor,
      { "semiMinor", "lix2.semiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty", HFILL }},
    { &hf_lix2_orientationMajor,
      { "orientationMajor", "lix2.orientationMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Orientation", HFILL }},
    { &hf_lix2_hSpeed,
      { "hSpeed", "lix2.hSpeed",
        FT_STRING, BASE_NONE, NULL, 0,
        "HorizontalSpeed", HFILL }},
    { &hf_lix2_bearing,
      { "bearing", "lix2.bearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_lix2_vSpeed,
      { "vSpeed", "lix2.vSpeed",
        FT_STRING, BASE_NONE, NULL, 0,
        "VerticalSpeed", HFILL }},
    { &hf_lix2_vDirection,
      { "vDirection", "lix2.vDirection",
        FT_UINT32, BASE_DEC, VALS(lix2_VerticalDirection_vals), 0,
        "VerticalDirection", HFILL }},
    { &hf_lix2_uncertainty_02,
      { "uncertainty", "lix2.uncertainty",
        FT_STRING, BASE_NONE, NULL, 0,
        "SpeedUncertainty", HFILL }},
    { &hf_lix2_hUncertainty,
      { "hUncertainty", "lix2.hUncertainty",
        FT_STRING, BASE_NONE, NULL, 0,
        "SpeedUncertainty", HFILL }},
    { &hf_lix2_vUncertainty,
      { "vUncertainty", "lix2.vUncertainty",
        FT_STRING, BASE_NONE, NULL, 0,
        "SpeedUncertainty", HFILL }},

/*--- End of included file: packet-lix2-hfarr.c ---*/
#line 45 "./asn1/lix2/packet-lix2-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-lix2-ettarr.c ---*/
#line 1 "./asn1/lix2/packet-lix2-ettarr.c"
    &ett_lix2_XIRIPayload,
    &ett_lix2_XIRIEvent,
    &ett_lix2_IRIPayload,
    &ett_lix2_SEQUENCE_OF_IRITargetIdentifier,
    &ett_lix2_IRIEvent,
    &ett_lix2_IRITargetIdentifier,
    &ett_lix2_CCPayload,
    &ett_lix2_CCPDU,
    &ett_lix2_LINotificationPayload,
    &ett_lix2_LINotificationMessage,
    &ett_lix2_NEFPDUSessionEstablishment,
    &ett_lix2_NEFPDUSessionModification,
    &ett_lix2_NEFPDUSessionRelease,
    &ett_lix2_NEFUnsuccessfulProcedure,
    &ett_lix2_NEFStartOfInterceptionWithEstablishedPDUSession,
    &ett_lix2_NEFDeviceTrigger,
    &ett_lix2_NEFDeviceTriggerReplace,
    &ett_lix2_NEFDeviceTriggerCancellation,
    &ett_lix2_NEFDeviceTriggerReportNotify,
    &ett_lix2_NEFMSISDNLessMOSMS,
    &ett_lix2_NEFExpectedUEBehaviourUpdate,
    &ett_lix2_SEQUENCE_OF_UMTLocationArea5G,
    &ett_lix2_ScheduledCommunicationTime,
    &ett_lix2_SEQUENCE_OF_Daytime,
    &ett_lix2_UMTLocationArea5G,
    &ett_lix2_Daytime,
    &ett_lix2_SCEFPDNConnectionEstablishment,
    &ett_lix2_SCEFPDNConnectionUpdate,
    &ett_lix2_SCEFPDNConnectionRelease,
    &ett_lix2_SCEFUnsuccessfulProcedure,
    &ett_lix2_SCEFStartOfInterceptionWithEstablishedPDNConnection,
    &ett_lix2_SCEFDeviceTrigger,
    &ett_lix2_SCEFDeviceTriggerReplace,
    &ett_lix2_SCEFDeviceTriggerCancellation,
    &ett_lix2_SCEFDeviceTriggerReportNotify,
    &ett_lix2_SCEFMSISDNLessMOSMS,
    &ett_lix2_SCEFCommunicationPatternUpdate,
    &ett_lix2_AMFRegistration,
    &ett_lix2_AMFDeregistration,
    &ett_lix2_AMFLocationUpdate,
    &ett_lix2_AMFStartOfInterceptionWithRegisteredUE,
    &ett_lix2_AMFUnsuccessfulProcedure,
    &ett_lix2_AMFID,
    &ett_lix2_AMFFailureCause,
    &ett_lix2_SMFPDUSessionEstablishment,
    &ett_lix2_SEQUENCE_OF_UEEndpointAddress,
    &ett_lix2_SMFPDUSessionModification,
    &ett_lix2_SMFPDUSessionRelease,
    &ett_lix2_SMFStartOfInterceptionWithEstablishedPDUSession,
    &ett_lix2_SMFUnsuccessfulProcedure,
    &ett_lix2_SMFPDUtoMAPDUSessionModification,
    &ett_lix2_SMFMAPDUSessionEstablishment,
    &ett_lix2_SEQUENCE_OF_AccessInfo,
    &ett_lix2_SMFMAPDUSessionModification,
    &ett_lix2_SMFMAPDUSessionRelease,
    &ett_lix2_SMFStartOfInterceptionWithEstablishedMAPDUSession,
    &ett_lix2_SMFMAUnsuccessfulProcedure,
    &ett_lix2_SMFServingNetwork,
    &ett_lix2_AccessInfo,
    &ett_lix2_ExtendedUPFCCPDU,
    &ett_lix2_UPFCCPDUPayload,
    &ett_lix2_UDMServingSystemMessage,
    &ett_lix2_UDMSubscriberRecordChangeMessage,
    &ett_lix2_UDMCancelLocationMessage,
    &ett_lix2_ServiceID,
    &ett_lix2_SEQUENCE_OF_CAGID,
    &ett_lix2_SMSMessage,
    &ett_lix2_SMSReport,
    &ett_lix2_SMSParty,
    &ett_lix2_SMSNFAddress,
    &ett_lix2_SMSTPDUData,
    &ett_lix2_MMSSend,
    &ett_lix2_SEQUENCE_OF_MMSParty,
    &ett_lix2_MMSSendByNonLocalTarget,
    &ett_lix2_MMSNotification,
    &ett_lix2_MMSSendToNonLocalTarget,
    &ett_lix2_MMSNotificationResponse,
    &ett_lix2_MMSRetrieval,
    &ett_lix2_MMSDeliveryAck,
    &ett_lix2_MMSForward,
    &ett_lix2_MMSDeleteFromRelay,
    &ett_lix2_T_contentLocationReq,
    &ett_lix2_T_contentLocationConf,
    &ett_lix2_T_deleteResponseText,
    &ett_lix2_MMSMBoxStore,
    &ett_lix2_MMSMBoxUpload,
    &ett_lix2_SEQUENCE_OF_MMBoxDescription,
    &ett_lix2_MMSMBoxDelete,
    &ett_lix2_T_contentLocationReq_01,
    &ett_lix2_T_contentLocationConf_01,
    &ett_lix2_MMSDeliveryReport,
    &ett_lix2_MMSDeliveryReportNonLocalTarget,
    &ett_lix2_MMSReadReport,
    &ett_lix2_MMSReadReportNonLocalTarget,
    &ett_lix2_MMSCancel,
    &ett_lix2_MMSMBoxViewRequest,
    &ett_lix2_SEQUENCE_OF_MMState,
    &ett_lix2_SEQUENCE_OF_MMFlags,
    &ett_lix2_T_attributes,
    &ett_lix2_MMSMBoxViewResponse,
    &ett_lix2_T_attributes_01,
    &ett_lix2_MMBoxDescription,
    &ett_lix2_MMSCCPDU,
    &ett_lix2_MMSAdaptation,
    &ett_lix2_MMSElementDescriptor,
    &ett_lix2_MMSExpiry,
    &ett_lix2_MMFlags,
    &ett_lix2_MMSParty,
    &ett_lix2_SEQUENCE_OF_MMSPartyID,
    &ett_lix2_MMSPartyID,
    &ett_lix2_MMSPreviouslySent,
    &ett_lix2_MMSPreviouslySentBy,
    &ett_lix2_MMSQuota,
    &ett_lix2_MMSVersion,
    &ett_lix2_PTCRegistration,
    &ett_lix2_PTCSessionInitiation,
    &ett_lix2_SEQUENCE_OF_PTCTargetInformation,
    &ett_lix2_PTCSessionAbandon,
    &ett_lix2_PTCSessionStart,
    &ett_lix2_PTCSessionEnd,
    &ett_lix2_PTCStartOfInterception,
    &ett_lix2_PTCPreEstablishedSession,
    &ett_lix2_PTCInstantPersonalAlert,
    &ett_lix2_PTCPartyJoin,
    &ett_lix2_PTCPartyDrop,
    &ett_lix2_PTCPartyHold,
    &ett_lix2_PTCMediaModification,
    &ett_lix2_PTCGroupAdvertisement,
    &ett_lix2_PTCFloorControl,
    &ett_lix2_SEQUENCE_OF_PTCFloorActivity,
    &ett_lix2_PTCTargetPresence,
    &ett_lix2_PTCParticipantPresence,
    &ett_lix2_PTCListManagement,
    &ett_lix2_SEQUENCE_OF_PTCIDList,
    &ett_lix2_PTCAccessPolicy,
    &ett_lix2_PTCTargetInformation,
    &ett_lix2_SEQUENCE_SIZE_1_MAX_OF_PTCIdentifiers,
    &ett_lix2_PTCIdentifiers,
    &ett_lix2_PTCSessionInfo,
    &ett_lix2_MultipleParticipantPresenceStatus,
    &ett_lix2_PTCParticipantPresenceStatus,
    &ett_lix2_RTPSetting,
    &ett_lix2_PTCIDList,
    &ett_lix2_PTCChatGroupID,
    &ett_lix2_LALSReport,
    &ett_lix2_PDHeaderReport,
    &ett_lix2_PDSummaryReport,
    &ett_lix2_AMFIdentifierAssocation,
    &ett_lix2_MMEIdentifierAssocation,
    &ett_lix2_MMEAttach,
    &ett_lix2_MMEDetach,
    &ett_lix2_MMELocationUpdate,
    &ett_lix2_MMEStartOfInterceptionWithEPSAttachedUE,
    &ett_lix2_MMEUnsuccessfulProcedure,
    &ett_lix2_MMEFailureCause,
    &ett_lix2_LINotification,
    &ett_lix2_SEQUENCE_OF_LIAppliedDeliveryInformation,
    &ett_lix2_LIAppliedDeliveryInformation,
    &ett_lix2_MDFCellSiteReport,
    &ett_lix2_EMM5GMMStatus,
    &ett_lix2_EPS5GGUTI,
    &ett_lix2_FiveGGUTI,
    &ett_lix2_FTEID,
    &ett_lix2_GPSI,
    &ett_lix2_GUAMI,
    &ett_lix2_GUMMEI,
    &ett_lix2_GUTI,
    &ett_lix2_IMPU,
    &ett_lix2_IPAddress,
    &ett_lix2_MMEID,
    &ett_lix2_NSSAI,
    &ett_lix2_PLMNID,
    &ett_lix2_PEI,
    &ett_lix2_RejectedNSSAI,
    &ett_lix2_RejectedSNSSAI,
    &ett_lix2_Slice,
    &ett_lix2_SNSSAI,
    &ett_lix2_SUCI,
    &ett_lix2_SUPI,
    &ett_lix2_TargetIdentifier,
    &ett_lix2_UEEndpointAddress,
    &ett_lix2_Location,
    &ett_lix2_CellSiteInformation,
    &ett_lix2_LocationInfo,
    &ett_lix2_SEQUENCE_OF_CellInformation,
    &ett_lix2_UserLocation,
    &ett_lix2_EUTRALocation,
    &ett_lix2_NRLocation,
    &ett_lix2_N3GALocation,
    &ett_lix2_IPAddr,
    &ett_lix2_GlobalRANNodeID,
    &ett_lix2_ANNodeID,
    &ett_lix2_TAI,
    &ett_lix2_CGI,
    &ett_lix2_LAI,
    &ett_lix2_SAI,
    &ett_lix2_ECGI,
    &ett_lix2_TAIList,
    &ett_lix2_NCGI,
    &ett_lix2_RANCGI,
    &ett_lix2_CellInformation,
    &ett_lix2_TNAPID,
    &ett_lix2_TWAPID,
    &ett_lix2_NGENbID,
    &ett_lix2_ENbID,
    &ett_lix2_PositioningInfo,
    &ett_lix2_RawMLPResponse,
    &ett_lix2_LocationData,
    &ett_lix2_SET_OF_PositioningMethodAndUsage,
    &ett_lix2_SET_OF_GNSSPositioningMethodAndUsage,
    &ett_lix2_EPSLocationInfo,
    &ett_lix2_ESMLCCellInfo,
    &ett_lix2_LocationPresenceReport,
    &ett_lix2_SET_OF_AMFEventArea,
    &ett_lix2_SET_OF_AccessType,
    &ett_lix2_SET_OF_RMInfo,
    &ett_lix2_SET_OF_CMInfo,
    &ett_lix2_AMFEventArea,
    &ett_lix2_PresenceInfo,
    &ett_lix2_SET_OF_TAI,
    &ett_lix2_SET_OF_ECGI,
    &ett_lix2_SET_OF_NCGI,
    &ett_lix2_SET_OF_GlobalRANNodeID,
    &ett_lix2_LADNInfo,
    &ett_lix2_RMInfo,
    &ett_lix2_CMInfo,
    &ett_lix2_GeographicArea,
    &ett_lix2_VelocityEstimate,
    &ett_lix2_CivicAddress,
    &ett_lix2_PositioningMethodAndUsage,
    &ett_lix2_GNSSPositioningMethodAndUsage,
    &ett_lix2_Point,
    &ett_lix2_PointUncertaintyCircle,
    &ett_lix2_PointUncertaintyEllipse,
    &ett_lix2_Polygon,
    &ett_lix2_SET_SIZE_3_15_OF_GeographicalCoordinates,
    &ett_lix2_PointAltitude,
    &ett_lix2_PointAltitudeUncertainty,
    &ett_lix2_EllipsoidArc,
    &ett_lix2_GeographicalCoordinates,
    &ett_lix2_UncertaintyEllipse,
    &ett_lix2_HorizontalVelocity,
    &ett_lix2_HorizontalWithVerticalVelocity,
    &ett_lix2_HorizontalVelocityWithUncertainty,
    &ett_lix2_HorizontalWithVerticalVelocityAndUncertainty,

/*--- End of included file: packet-lix2-ettarr.c ---*/
#line 50 "./asn1/lix2/packet-lix2-template.c"
  };

  /* Register protocol */
  proto_lix2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lix2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  lix2_handle = register_dissector("xiri", dissect_XIRIPayload_PDU, proto_lix2);

  /* Get rid of unused code warnings */
  (void)&dissect_lix2_MMSElementDescriptor;
  (void)&dissect_lix2_MMSCancelStatus;
  (void)&lix2_MMSCancelStatus_vals;
  (void)&dissect_lix2_LINotificationPayload;
  (void)&dissect_lix2_CCPayload;
  (void)&dissect_lix2_IRIPayload;
  (void)&hf_lix2_bCCRecipients_item;
  (void)&hf_lix2_cCRecipients_item;
  (void)&hf_lix2_expectedTimeAndDayOfWeekInTrajectory_item;
  (void)&hf_lix2_globalENbIDList_item;
  (void)&hf_lix2_originatingMMSParty_item;
  (void)&hf_lix2_pTCHoldID_item;
  (void)&hf_lix2_pTCIDList_item;
}
